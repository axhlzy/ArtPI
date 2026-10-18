//
// agent_java_registerclass.cpp - Frida-style Java.registerClass() on top of
// runtime DEX generation (PI::DexGen) + InMemoryDexClassLoader (PI::DexLoader).
//
// Design
// ------
// * Every JS-implemented method is declared ACC_NATIVE in the generated DEX.
//   There is therefore no smali assembler in the loop: a method body is a
//   single native entry point, which ART resolves through RegisterNatives.
// * Each registered method gets a unique, runtime-generated ARM64 stub that
//   loads its slot id into x16 and branches to artpi_native_thunk_entry
//   (native_thunk_arm64.S). The stub spills the argument register file and
//   calls ArtpiNativeDispatch(), which marshals args to JS and the JS return
//   value back into x0/d0.
// * `NewObject` / static calls / reflection all reuse the existing JRef layer;
//   FindClassWithFallback() consults PI::DexLoader's generated-class registry,
//   so __native_jcall("<generated.Class>", "method", ...) just works.
//

#include "agent_java_registerclass.h"
#include "agent_dex_writer.h"
#include "dex/pi_dex_writer.h"

#include "agent_java_ref.h"
#include "dex/pi_dex_gen.h"
#include "dex/pi_dex_loader.h"
#include "../../include/ArtPI.h"

#include "frida-gum.h"

#include <android/log.h>
#include <sys/mman.h>
#include <unistd.h>

#include <cstring>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

#define REGCLS_TAG "ArtPI-RegClass"

namespace artpi { namespace agent {

// ===========================================================================
// 1. Per-method native thunks
// ===========================================================================
namespace {

// Mirrors the stack frame built by native_thunk_arm64.S.
struct ArtpiNativeFrame {
    uint64_t x[8];        // x0..x7 (x0 = JNIEnv*, x1 = jobject/jclass)
    uint64_t d[8];        // raw bits of d0..d7
    uint64_t caller_sp;   // original SP (first stack-passed argument)
};

constexpr int kMaxThunks = 512;
constexpr size_t kThunkStride = 32;

void* g_thunks[kMaxThunks] = {nullptr};
int g_thunkUsed = 0;
std::mutex g_thunkMutex;
std::once_flag g_thunkInit;
bool g_thunksReady = false;

extern "C" void artpi_native_thunk_entry();

bool BuildNativeThunks() {
    gum_init_embedded();

    long pageSizeValue = sysconf(_SC_PAGESIZE);
    const size_t pageSize = pageSizeValue > 0 ? static_cast<size_t>(pageSizeValue) : 4096;
    const size_t needed = static_cast<size_t>(kMaxThunks) * kThunkStride;
    const size_t allocSize = (needed + pageSize - 1) & ~(pageSize - 1);

    GumAddressSpec spec = {};
    spec.near_address = reinterpret_cast<void*>(artpi_native_thunk_entry);
    spec.max_distance = 64 * 1024 * 1024;

    void* mem = gum_memory_allocate_near(&spec, allocSize, pageSize, GUM_PAGE_RWX);
    if (mem == nullptr) {
        mem = gum_memory_allocate(nullptr, allocSize, pageSize, GUM_PAGE_RWX);
    }
    if (mem == nullptr) {
        __android_log_print(ANDROID_LOG_ERROR, REGCLS_TAG,
                            "failed to allocate %u bytes for native thunks",
                            static_cast<unsigned>(allocSize));
        return false;
    }

    GumArm64Writer writer;
    gum_arm64_writer_init(&writer, mem);
    bool ok = true;

    for (int i = 0; i < kMaxThunks; ++i) {
        void* slot = gum_arm64_writer_cur(&writer);
        if (!gum_arm64_writer_put_ldr_reg_u64(&writer, ARM64_REG_X16,
                                              static_cast<guint64>(i))) {
            ok = false;
            break;
        }
        if (!gum_arm64_writer_put_b_imm(&writer,
                reinterpret_cast<GumAddress>(artpi_native_thunk_entry))) {
            if (!gum_arm64_writer_put_ldr_reg_address(
                    &writer, ARM64_REG_X17,
                    reinterpret_cast<GumAddress>(artpi_native_thunk_entry)) ||
                !gum_arm64_writer_put_br_reg(&writer, ARM64_REG_X17)) {
                ok = false;
                break;
            }
        }
        g_thunks[i] = slot;
    }

    if (ok && gum_arm64_writer_offset(&writer) > needed) ok = false;
    if (ok && !gum_arm64_writer_flush(&writer)) ok = false;
    gum_arm64_writer_clear(&writer);

    if (!ok) {
        for (int i = 0; i < kMaxThunks; ++i) g_thunks[i] = nullptr;
        gum_memory_free(mem, allocSize);
        __android_log_print(ANDROID_LOG_ERROR, REGCLS_TAG, "native thunk generation failed");
        return false;
    }

    __android_log_print(ANDROID_LOG_INFO, REGCLS_TAG,
                        "native thunks at %p (%d slots)", mem, kMaxThunks);
    return true;
}

// Returns a unique stub pointer; *slot receives its dispatch id.
void* AcquireThunk(int* slot) {
    std::lock_guard<std::mutex> lk(g_thunkMutex);
    std::call_once(g_thunkInit, []() { g_thunksReady = BuildNativeThunks(); });
    if (!g_thunksReady) return nullptr;
    if (g_thunkUsed >= kMaxThunks) return nullptr;
    *slot = g_thunkUsed;
    return g_thunks[g_thunkUsed++];
}

}  // namespace

// ===========================================================================
// 2. Slot -> JS implementation table + dispatcher
// ===========================================================================
namespace {

struct NativeBinding {
    std::string className;              // dotted
    std::string methodName;
    std::string signature;
    std::string retType;                // descriptor
    std::vector<std::string> argTypes;  // descriptors
    JSValue impl = JS_UNDEFINED;
};

std::map<int, NativeBinding> g_bindings;
std::mutex g_bindingsMutex;

std::string DescriptorToTypeName(const std::string& desc) {
    if (desc.empty()) return "java.lang.Object";
    switch (desc[0]) {
        case 'V': return "void";
        case 'Z': return "boolean";
        case 'B': return "byte";
        case 'S': return "short";
        case 'C': return "char";
        case 'I': return "int";
        case 'J': return "long";
        case 'F': return "float";
        case 'D': return "double";
        default: break;
    }
    if (desc[0] == 'L' && desc.back() == ';') {
        std::string n = desc.substr(1, desc.size() - 2);
        for (char& c : n) {
            if (c == '/') c = '.';
        }
        return n;
    }
    return desc;  // arrays: leave as descriptor (JRef path)
}

}  // namespace

extern "C" void ArtpiNativeDispatch(int slot, ArtpiNativeFrame* frame) {
    if (frame == nullptr) return;

    JNIEnv* env = reinterpret_cast<JNIEnv*>(static_cast<uintptr_t>(frame->x[0]));
    if (env == nullptr) return;

    // Every early return below must produce a null/zero result: the thunk
    // reloads x0/d0 from the frame, and x0 currently holds JNIEnv*.
    frame->x[0] = 0;
    frame->d[0] = 0;

    NativeBinding binding;
    {
        std::lock_guard<std::mutex> lk(g_bindingsMutex);
        auto it = g_bindings.find(slot);
        if (it == g_bindings.end()) {
            __android_log_print(ANDROID_LOG_ERROR, REGCLS_TAG,
                                "dispatch: unknown slot %d", slot);
            return;
        }
        binding = it->second;
    }

    if (JS_IsUndefined(binding.impl) || g_ctx == nullptr) return;

    // Reentrancy rule (same as the hook callbacks): if this thread is already
    // inside a JS eval it owns g_jsMutex, so calling JS directly is safe and
    // taking the lock would deadlock.
    const bool reentrant = t_jsReentrancyDepth > 0;
    std::unique_lock<std::mutex> jsLock(g_jsMutex, std::defer_lock);
    if (!reentrant) jsLock.lock();

    JSContext* ctx = g_ctx;

    const size_t argCount = binding.argTypes.size();
    std::vector<JSValue> jsArgs(argCount, JS_UNDEFINED);

    size_t xi = 2;  // x0 = env, x1 = thiz/clazz
    size_t di = 0;
    bool overflow = false;

    for (size_t i = 0; i < argCount; ++i) {
        const std::string& d = binding.argTypes[i];
        const char c = d.empty() ? 'I' : d[0];
        switch (c) {
            case 'L':
            case '[': {
                if (xi >= 8) { overflow = true; break; }
                auto o = reinterpret_cast<jobject>(static_cast<uintptr_t>(frame->x[xi++]));
                jsArgs[i] = JavaObjectToJsValue(ctx, env, o);
            } break;
            case 'J': {
                if (xi >= 8) { overflow = true; break; }
                jsArgs[i] = JS_NewBigInt64(ctx, static_cast<int64_t>(frame->x[xi++]));
            } break;
            case 'Z': {
                if (xi >= 8) { overflow = true; break; }
                jsArgs[i] = JS_NewBool(ctx, frame->x[xi++] != 0);
            } break;
            case 'F': {
                if (di >= 8) { overflow = true; break; }
                uint32_t bits = static_cast<uint32_t>(frame->d[di++]);
                float f = 0.0f;
                std::memcpy(&f, &bits, sizeof(f));
                jsArgs[i] = JS_NewFloat64(ctx, static_cast<double>(f));
            } break;
            case 'D': {
                if (di >= 8) { overflow = true; break; }
                double v = 0.0;
                std::memcpy(&v, &frame->d[di++], sizeof(v));
                jsArgs[i] = JS_NewFloat64(ctx, v);
            } break;
            default: {  // I / B / C / S
                if (xi >= 8) { overflow = true; break; }
                jsArgs[i] = JS_NewInt32(ctx, static_cast<int32_t>(frame->x[xi++]));
            } break;
        }
        if (overflow) break;
    }

    if (overflow) {
        for (JSValue& v : jsArgs) JS_FreeValue(ctx, v);
        jclass iae = env->FindClass("java/lang/IllegalArgumentException");
        if (iae != nullptr) {
            env->ThrowNew(iae, "ArtPI: too many arguments for JS native method");
            env->DeleteLocalRef(iae);
        }
        return;
    }

    JSValue ret = JS_Call(ctx, binding.impl, JS_UNDEFINED,
                          static_cast<int>(jsArgs.size()),
                          jsArgs.empty() ? nullptr : jsArgs.data());
    for (JSValue& v : jsArgs) JS_FreeValue(ctx, v);

    if (JS_IsException(ret)) {
        JSValue exc = JS_GetException(ctx);
        const char* msg = JS_ToCString(ctx, exc);
        std::string text = msg != nullptr ? msg : "JS exception";
        if (msg) JS_FreeCString(ctx, msg);
        JS_FreeValue(ctx, exc);
        JS_FreeValue(ctx, ret);

        __android_log_print(ANDROID_LOG_ERROR, REGCLS_TAG,
                            "%s.%s threw: %s", binding.className.c_str(),
                            binding.methodName.c_str(), text.c_str());
        jclass rt = env->FindClass("java/lang/RuntimeException");
        if (rt != nullptr) {
            env->ThrowNew(rt, text.c_str());
            env->DeleteLocalRef(rt);
        }
        frame->x[0] = 0;
        return;
    }

    const std::string& rt = binding.retType;
    const char rc = rt.empty() ? 'V' : rt[0];
    switch (rc) {
        case 'V':
            frame->x[0] = 0;
            break;
        case 'Z':
            frame->x[0] = JS_ToBool(ctx, ret) ? 1 : 0;
            break;
        case 'B':
        case 'C':
        case 'S':
        case 'I': {
            int32_t v = 0;
            JS_ToInt32(ctx, &v, ret);
            frame->x[0] = static_cast<uint32_t>(v);
        } break;
        case 'J': {
            int64_t v = 0;
            if (JS_IsBigInt(ctx, ret)) JS_ToBigInt64(ctx, &v, ret);
            else JS_ToInt64(ctx, &v, ret);
            frame->x[0] = static_cast<uint64_t>(v);
        } break;
        case 'F': {
            double v = 0.0;
            JS_ToFloat64(ctx, &v, ret);
            float f = static_cast<float>(v);
            uint32_t bits = 0;
            std::memcpy(&bits, &f, sizeof(bits));
            frame->d[0] = bits;
        } break;
        case 'D': {
            double v = 0.0;
            JS_ToFloat64(ctx, &v, ret);
            uint64_t bits = 0;
            std::memcpy(&bits, &v, sizeof(bits));
            frame->d[0] = bits;
        } break;
        case 'L':
        case '[': {
            jobject o = JsValueToJavaObject(env, ctx, ret, DescriptorToTypeName(rt));
            if (o == nullptr && !JS_IsNull(ret) && !JS_IsUndefined(ret)) {
                // JsValueToJavaObject() only understands String / boxed
                // primitives / JRef - a plain JS array or object would silently
                // become null, which is very confusing from Java's side.
                jclass rt2 = env->FindClass("java/lang/RuntimeException");
                if (rt2 != nullptr) {
                    std::string msg = "ArtPI: cannot convert JS value to " + rt +
                                      " (return a JRef for arrays / objects)";
                    env->ThrowNew(rt2, msg.c_str());
                    env->DeleteLocalRef(rt2);
                }
                frame->x[0] = 0;
                break;
            }
            frame->x[0] = static_cast<uint64_t>(reinterpret_cast<uintptr_t>(o));
        } break;
        default:
            frame->x[0] = 0;
            break;
    }

    JS_FreeValue(ctx, ret);
}

// ===========================================================================
// 3. Registered classes (handles exposed to JS)
// ===========================================================================
namespace {

struct RegisteredClass {
    std::string name;            // dotted
    jobject loader = nullptr;    // global ref (app loader when injected)
    jobject isolated = nullptr;  // global ref (private loader, element source)
    jclass cls = nullptr;        // global ref
    bool injected = false;
    std::vector<int> slots;
};

std::map<int, RegisteredClass> g_registered;
std::mutex g_regMutex;
int g_nextHandle = 1;

RegisteredClass* FindRegistered(int handle) {
    auto it = g_registered.find(handle);
    return it == g_registered.end() ? nullptr : &it->second;
}

// A DEX loaded through Java.loadDex() (not tied to a single class).
struct LoadedDexHandle {
    std::string name;
    jobject loader = nullptr;    // global ref
    jobject isolated = nullptr;  // global ref
    bool injected = false;
};

std::map<int, LoadedDexHandle> g_loadedDexes;
int g_nextDexHandle = 1;

LoadedDexHandle* FindLoadedDex(int handle) {
    auto it = g_loadedDexes.find(handle);
    return it == g_loadedDexes.end() ? nullptr : &it->second;
}

// Deletes the (global) loader refs without ever releasing the same reference
// twice. When a dex could not be spliced into the app loader, LoadedDex::loader
// and LoadedDex::isolated refer to the same ClassLoader.
void DeleteLoaderRefs(JNIEnv* env, jobject loader, jobject isolated) {
    if (env == nullptr) return;
    if (isolated == loader) isolated = nullptr;
    if (loader != nullptr) env->DeleteGlobalRef(loader);
    if (isolated != nullptr) env->DeleteGlobalRef(isolated);
}

// --- reflection helpers ----------------------------------------------------
struct MethodInfo {
    std::string name;
    std::string signature;
    std::string ret_type;
    std::vector<std::string> arg_types;
    bool is_static = false;
    bool is_abstract = false;
};

bool MethodToInfo(JNIEnv* env, jobject method, MethodInfo* out) {
    jclass methodCls = env->FindClass("java/lang/reflect/Method");
    if (methodCls == nullptr) {
        if (env->ExceptionCheck()) env->ExceptionClear();
        return false;
    }

    jmethodID mName = env->GetMethodID(methodCls, "getName", "()Ljava/lang/String;");
    jmethodID mParams = env->GetMethodID(methodCls, "getParameterTypes", "()[Ljava/lang/Class;");
    jmethodID mRet = env->GetMethodID(methodCls, "getReturnType", "()Ljava/lang/Class;");
    jmethodID mMod = env->GetMethodID(methodCls, "getModifiers", "()I");
    if (env->ExceptionCheck()) env->ExceptionClear();
    if (mName == nullptr || mParams == nullptr || mRet == nullptr) {
        env->DeleteLocalRef(methodCls);
        return false;
    }

    auto jn = static_cast<jstring>(env->CallObjectMethod(method, mName));
    if (jn != nullptr) {
        const char* c = env->GetStringUTFChars(jn, nullptr);
        if (c) {
            out->name = c;
            env->ReleaseStringUTFChars(jn, c);
        }
        env->DeleteLocalRef(jn);
    }

    std::string sig = "(";
    auto params = static_cast<jobjectArray>(env->CallObjectMethod(method, mParams));
    if (params != nullptr) {
        jsize n = env->GetArrayLength(params);
        for (jsize i = 0; i < n; ++i) {
            auto pc = static_cast<jclass>(env->GetObjectArrayElement(params, i));
            if (pc == nullptr) continue;
            std::string pn = JavaClassName(env, pc);
            std::string pd = TypeNameToDescriptor(pn);
            out->arg_types.push_back(pd);
            sig += pd;
            env->DeleteLocalRef(pc);
        }
        env->DeleteLocalRef(params);
    }
    sig += ")";

    auto rc = static_cast<jclass>(env->CallObjectMethod(method, mRet));
    std::string retName = "void";
    if (rc != nullptr) {
        retName = JavaClassName(env, rc);
        env->DeleteLocalRef(rc);
    }
    out->ret_type = TypeNameToDescriptor(retName);
    sig += out->ret_type;
    out->signature = sig;

    int mods = mMod != nullptr ? env->CallIntMethod(method, mMod) : 0;
    out->is_static = (mods & 0x0008) != 0;
    out->is_abstract = (mods & 0x0400) != 0;

    if (env->ExceptionCheck()) env->ExceptionClear();
    env->DeleteLocalRef(methodCls);
    return !out->name.empty();
}

// Collects `Class.getMethods()` of `cls` into `out`.
bool CollectMethods(JNIEnv* env, jclass cls, std::vector<MethodInfo>* out) {
    jclass classCls = env->FindClass("java/lang/Class");
    if (classCls == nullptr) {
        if (env->ExceptionCheck()) env->ExceptionClear();
        return false;
    }
    jmethodID gm = env->GetMethodID(classCls, "getMethods", "()[Ljava/lang/reflect/Method;");
    if (gm == nullptr) {
        if (env->ExceptionCheck()) env->ExceptionClear();
        env->DeleteLocalRef(classCls);
        return false;
    }

    auto methods = static_cast<jobjectArray>(env->CallObjectMethod(cls, gm));
    env->DeleteLocalRef(classCls);
    if (env->ExceptionCheck()) {
        env->ExceptionClear();
        return false;
    }
    if (methods == nullptr) return false;

    jsize n = env->GetArrayLength(methods);
    for (jsize i = 0; i < n; ++i) {
        jobject m = env->GetObjectArrayElement(methods, i);
        if (m == nullptr) continue;
        MethodInfo info;
        if (MethodToInfo(env, m, &info)) out->push_back(std::move(info));
        env->DeleteLocalRef(m);
    }
    env->DeleteLocalRef(methods);
    return true;
}

// Infers the signature of a short-form method (`foo(a, b) { ... }`) by looking
// for a same-named method in the declared interfaces / superclass chain.
bool InferSignature(JNIEnv* env,
                    const std::string& methodName,
                    const std::string& superclass,
                    const std::vector<std::string>& interfaces,
                    std::string* signature,
                    std::string* ret_type,
                    std::vector<std::string>* arg_types,
                    bool* is_static,
                    std::string* error) {
    MethodInfo firstMatch;
    bool found = false;
    bool ambiguous = false;

    auto scan = [&](const std::string& className) {
        jclass cls = FindClassWithFallback(env, className);
        if (cls == nullptr) return;
        std::vector<MethodInfo> methods;
        CollectMethods(env, cls, &methods);
        env->DeleteLocalRef(cls);

        for (const auto& m : methods) {
            if (m.name != methodName) continue;
            if (!found) {
                firstMatch = m;
                found = true;
            } else if (firstMatch.signature != m.signature) {
                ambiguous = true;
            }
        }
    };

    for (const auto& iface : interfaces) scan(iface);
    if (!ambiguous) scan(superclass);

    if (!found) {
        if (error) {
            *error = "cannot infer the signature of '" + methodName +
                     "' (declare returnType/argumentTypes explicitly)";
        }
        return false;
    }
    if (ambiguous) {
        if (error) {
            *error = "ambiguous overloads for '" + methodName +
                     "'; declare returnType/argumentTypes explicitly";
        }
        return false;
    }

    *signature = firstMatch.signature;
    *ret_type = firstMatch.ret_type;
    *arg_types = firstMatch.arg_types;
    *is_static = firstMatch.is_static;
    return true;
}

// --- JS helpers ------------------------------------------------------------
bool GetStringProp(JSContext* ctx, JSValueConst obj, const char* key, std::string* out) {
    JSValue v = JS_GetPropertyStr(ctx, obj, key);
    bool ok = false;
    if (JS_IsString(v)) {
        const char* s = JS_ToCString(ctx, v);
        if (s) {
            *out = s;
            JS_FreeCString(ctx, s);
            ok = true;
        }
    }
    JS_FreeValue(ctx, v);
    return ok;
}

bool GetBoolProp(JSContext* ctx, JSValueConst obj, const char* key, bool fallback) {
    JSValue v = JS_GetPropertyStr(ctx, obj, key);
    bool result = fallback;
    if (!JS_IsUndefined(v) && !JS_IsNull(v)) result = JS_ToBool(ctx, v) != 0;
    JS_FreeValue(ctx, v);
    return result;
}

// Returns a JSValue in `*out` (owned by the caller) or JS_UNDEFINED.
void GetValueProp(JSContext* ctx, JSValueConst obj, const char* key, JSValue* out) {
    *out = JS_GetPropertyStr(ctx, obj, key);
}

// Reads a JS array of strings. Returns false when the property is absent.
bool GetStringArrayProp(JSContext* ctx, JSValueConst obj, const char* key,
                        std::vector<std::string>* out) {
    JSValue v = JS_GetPropertyStr(ctx, obj, key);
    if (!JS_IsArray(ctx, v)) {
        JS_FreeValue(ctx, v);
        return false;
    }
    JSValue lenVal = JS_GetPropertyStr(ctx, v, "length");
    int64_t len = 0;
    JS_ToInt64(ctx, &len, lenVal);
    JS_FreeValue(ctx, lenVal);
    for (int64_t i = 0; i < len; ++i) {
        JSValue e = JS_GetPropertyUint32(ctx, v, static_cast<uint32_t>(i));
        if (JS_IsString(e)) {
            const char* s = JS_ToCString(ctx, e);
            if (s) {
                out->push_back(s);
                JS_FreeCString(ctx, s);
            }
        }
        JS_FreeValue(ctx, e);
    }
    JS_FreeValue(ctx, v);
    return true;
}

// Accepts both Java type names ("int", "java.lang.String") and DEX type
// descriptors ("I", "Ljava/lang/String;", "[B") and returns a descriptor.
std::string NormalizeTypeName(const std::string& t) {
    if (t.empty()) return "V";
    if (t[0] == '[') {
        std::string d = t;
        for (char& c : d) {
            if (c == '.') c = '/';
        }
        return d;
    }
    if (t.size() >= 3 && t[0] == 'L' && t.back() == ';') return t;
    if (t.size() == 1 && std::strchr("VZBCSIJFD", t[0]) != nullptr) return t;
    return TypeNameToDescriptor(t);
}

bool ParseSignatureLocal(const std::string& sig,
                         std::string* ret,
                         std::vector<std::string>* args) {
    return PI::DexGen::ParseSignature(sig, ret, args);
}

}  // namespace

// ===========================================================================
// 4. Java.registerClass(spec)
// ===========================================================================
static JSValue JsRegisterClass(JSContext* ctx, JSValueConst /*this_val*/,
                               int argc, JSValueConst* argv) {
    if (argc < 1 || !JS_IsObject(argv[0])) {
        return JS_ThrowTypeError(ctx, "Java.registerClass({ name, methods, ... })");
    }
    JNIEnv* env = GetEnv();
    if (env == nullptr) {
        return JS_ThrowTypeError(ctx, "Java.registerClass: no JNIEnv");
    }

    JSValueConst spec = argv[0];

    std::string className;
    if (!GetStringProp(ctx, spec, "name", &className) || className.empty()) {
        return JS_ThrowTypeError(ctx, "Java.registerClass: 'name' is required");
    }
    if (className.find('.') == std::string::npos) {
        return JS_ThrowTypeError(ctx,
            "Java.registerClass: 'name' must be fully qualified (e.g. com.foo.Bar)");
    }

    std::string superclass = "java.lang.Object";
    GetStringProp(ctx, spec, "superclass", &superclass);

    std::vector<std::string> interfaces;
    GetStringArrayProp(ctx, spec, "implements", &interfaces);

    // ---- methods ---------------------------------------------------------
    std::vector<PI::DexGen::MethodSpec> dexMethods;
    struct PendingNative {
        std::string name;
        std::string signature;
        std::string retType;
        std::vector<std::string> argTypes;
        JSValue impl = JS_UNDEFINED;
    };
    std::vector<PendingNative> pending;
    bool hasNoArgConstructor = false;
    bool hasAnyConstructor = false;

    JSValue methodsObj = JS_GetPropertyStr(ctx, spec, "methods");
    if (JS_IsObject(methodsObj)) {
        JSPropertyEnum* table = nullptr;
        uint32_t count = 0;
        if (JS_GetOwnPropertyNames(ctx, &table, &count, methodsObj,
                                   JS_GPN_STRING_MASK | JS_GPN_ENUM_ONLY) == 0) {
            for (uint32_t i = 0; i < count; ++i) {
                const char* rawName = JS_AtomToCString(ctx, table[i].atom);
                std::string rawKey = rawName ? rawName : "";
                if (rawName) JS_FreeCString(ctx, rawName);
                JS_FreeAtom(ctx, table[i].atom);
                table[i].atom = JS_ATOM_NULL;

                if (rawKey.empty()) continue;

                std::string methodName = rawKey;
                // Support inline signature in method name: e.g. "myMethod(I)V"
                std::string signature, retType;
                std::vector<std::string> argTypes;
                size_t lparen = methodName.find('(');
                if (lparen != std::string::npos) {
                    signature = methodName.substr(lparen);
                    methodName = methodName.substr(0, lparen);
                }

                JSValue def = JS_GetPropertyStr(ctx, methodsObj, rawKey.c_str());

                bool isStatic = false;
                JSValue impl = JS_UNDEFINED;

                bool isExplicitBytecode = false;
                if (JS_IsFunction(ctx, def)) {
                    impl = JS_DupValue(ctx, def);
                    if (signature.empty()) {
                        std::string err;
                        if (!InferSignature(env, methodName, superclass, interfaces,
                                            &signature, &retType, &argTypes,
                                            &isStatic, &err)) {
                            JS_FreeValue(ctx, def);
                            JS_FreeValue(ctx, impl);
                            JS_FreeValue(ctx, methodsObj);
                            js_free(ctx, table);
                            return JS_ThrowTypeError(ctx, "%s", err.c_str());
                        }
                    }
                } else if (GetDexWriterInstance(ctx, def) != nullptr || JS_IsString(def)) {
                    impl = JS_DupValue(ctx, def);
                    if (signature.empty()) {
                        std::string err;
                        if (!InferSignature(env, methodName, superclass, interfaces,
                                            &signature, &retType, &argTypes,
                                            &isStatic, &err)) {
                            JS_FreeValue(ctx, def);
                            JS_FreeValue(ctx, impl);
                            JS_FreeValue(ctx, methodsObj);
                            js_free(ctx, table);
                            return JS_ThrowTypeError(ctx, "%s", err.c_str());
                        }
                    }
                } else if (JS_IsObject(def)) {
                    std::string explicitSig;
                    if (GetStringProp(ctx, def, "signature", &explicitSig)) {
                        signature = explicitSig;
                    } else if (signature.empty()) {
                        std::string retName;
                        if (!GetStringProp(ctx, def, "returnType", &retName)) {
                            retName = "void";
                        }
                        retType = NormalizeTypeName(retName);

                        std::vector<std::string> argNames;
                        GetStringArrayProp(ctx, def, "argumentTypes", &argNames);

                        signature = "(";
                        for (const auto& a : argNames) {
                            std::string d = NormalizeTypeName(a);
                            argTypes.push_back(d);
                            signature += d;
                        }
                        signature += ")" + retType;
                    }
                    isStatic = GetBoolProp(ctx, def, "static", isStatic);
                    GetValueProp(ctx, def, "implementation", &impl);
                    if (JS_IsUndefined(impl)) {
                        JS_FreeValue(ctx, impl);
                        GetValueProp(ctx, def, "bytecode", &impl);
                        if (!JS_IsUndefined(impl)) {
                            isExplicitBytecode = true;
                        }
                    }
                } else {
                    JS_FreeValue(ctx, def);
                    continue;
                }

                if (signature.empty() || !PI::DexGen::ValidateSignature(signature, nullptr)) {
                    JS_FreeValue(ctx, def);
                    JS_FreeValue(ctx, impl);
                    JS_FreeValue(ctx, methodsObj);
                    js_free(ctx, table);
                    return JS_ThrowTypeError(ctx, "invalid signature for %s.%s: %s",
                                             className.c_str(), methodName.c_str(),
                                             signature.c_str());
                }
                if (retType.empty() || argTypes.empty()) {
                    // signature-only form: derive ret/args from it
                    std::string parsedRet;
                    std::vector<std::string> parsedArgs;
                    if (ParseSignatureLocal(signature, &parsedRet, &parsedArgs)) {
                        if (retType.empty()) retType = parsedRet;
                        if (argTypes.empty()) argTypes = parsedArgs;
                    }
                }

                bool isConstructor = (methodName == "<init>");
                if (isConstructor) {
                    hasAnyConstructor = true;
                    if (signature == "()V") {
                        hasNoArgConstructor = true;
                    }
                }
                PI::DexGen::MethodSpec dexMethod;
                dexMethod.name = methodName;
                dexMethod.signature = signature;
                dexMethod.is_static = isStatic;
                dexMethod.is_constructor = isConstructor;
                dexMethod.access_flags = PI::DexGen::ACC_PUBLIC | PI::DexGen::ACC_NATIVE;
                if (isConstructor) dexMethod.access_flags |= PI::DexGen::ACC_CONSTRUCTOR;
                if (isStatic) dexMethod.access_flags |= PI::DexGen::ACC_STATIC;

                std::shared_ptr<PI::DexWriter::Writer> bytecodeWriter = nullptr;
                uint16_t expectedIns = PI::DexGen::CalculateInsWords(argTypes, isStatic);

                // 1. Check if impl is already a DexWriter instance
                if (PI::DexWriter::Writer* existing = GetDexWriterInstance(ctx, impl)) {
                    bytecodeWriter = std::make_shared<PI::DexWriter::Writer>(*existing);
                    uint16_t curIns = bytecodeWriter->GetIns();
                    uint16_t curRegs = bytecodeWriter->GetRegisters();
                    uint16_t curOuts = bytecodeWriter->GetOuts();
                    if (curIns != expectedIns || curRegs < expectedIns) {
                        uint16_t newRegs = std::max<uint16_t>(curRegs, expectedIns + 2);
                        bytecodeWriter->SetRegisters(newRegs, expectedIns, curOuts);
                    }
                } else if (JS_IsString(impl)) {
                    // 2. Smali string shorthand (Option B)
                    const char* smaliStr = JS_ToCString(ctx, impl);
                    if (smaliStr) {
                        bytecodeWriter = std::make_shared<PI::DexWriter::Writer>();
                        uint16_t totalRegs = std::max<uint16_t>(expectedIns + 2, 4);
                        bytecodeWriter->SetRegisters(totalRegs, expectedIns, 4);

                        std::string err;
                        if (!bytecodeWriter->EmitSmali(smaliStr, &err)) {
                            JS_FreeCString(ctx, smaliStr);
                            JS_FreeValue(ctx, impl);
                            JS_FreeValue(ctx, def);
                            js_free(ctx, table);
                            JS_FreeValue(ctx, methodsObj);
                            for (auto& p : pending) JS_FreeValue(ctx, p.impl);
                            return JS_ThrowTypeError(ctx, "Smali error in %s: %s", methodName.c_str(), err.c_str());
                        }
                        JS_FreeCString(ctx, smaliStr);
                    }
                } else if (JS_IsFunction(ctx, impl)) {
                    // 3. Bytecode builder function (explicit bytecode: fn, or fn.$emit = true, or fn.bytecode = true)
                    bool isBytecodeBuilder = isExplicitBytecode;
                    if (!isBytecodeBuilder) {
                        JSValue emitProp = JS_GetPropertyStr(ctx, impl, "$emit");
                        if (JS_ToBool(ctx, emitProp)) isBytecodeBuilder = true;
                        JS_FreeValue(ctx, emitProp);
                        if (!isBytecodeBuilder) {
                            JSValue bcProp = JS_GetPropertyStr(ctx, impl, "bytecode");
                            if (JS_ToBool(ctx, bcProp)) isBytecodeBuilder = true;
                            JS_FreeValue(ctx, bcProp);
                        }
                    }

                    if (isBytecodeBuilder) {
                        auto probeWriter = std::make_shared<PI::DexWriter::Writer>();
                        uint16_t totalRegs = std::max<uint16_t>(expectedIns + 2, 4);
                        probeWriter->SetRegisters(totalRegs, expectedIns, 4);

                        JSValue writerObj = CreateDexWriterObject(ctx, probeWriter);
                        JSValue res = JS_Call(ctx, impl, JS_UNDEFINED, 1, &writerObj);
                        JS_FreeValue(ctx, writerObj);
                        if (JS_IsException(res)) {
                            JS_FreeValue(ctx, impl);
                            JS_FreeValue(ctx, def);
                            js_free(ctx, table);
                            JS_FreeValue(ctx, methodsObj);
                            for (auto& p : pending) JS_FreeValue(ctx, p.impl);
                            return res;
                        }
                        JS_FreeValue(ctx, res);

                        if (probeWriter->GetBytecodeInstructionCount() == 0) {
                            JS_FreeValue(ctx, impl);
                            JS_FreeValue(ctx, def);
                            js_free(ctx, table);
                            JS_FreeValue(ctx, methodsObj);
                            for (auto& p : pending) JS_FreeValue(ctx, p.impl);
                            return JS_ThrowTypeError(ctx, "bytecode builder for method %s emitted no instructions",
                                                     methodName.c_str());
                        }
                        bytecodeWriter = probeWriter;
                    }
                }

                if (bytecodeWriter != nullptr) {
                    dexMethod.writer = bytecodeWriter;
                    dexMethod.access_flags &= ~PI::DexGen::ACC_NATIVE;
                    JS_FreeValue(ctx, impl);
                } else if (JS_IsFunction(ctx, impl)) {
                    PendingNative pn;
                    pn.name = methodName;
                    pn.signature = signature;
                    pn.retType = retType;
                    pn.argTypes = argTypes;
                    pn.impl = impl;  // ownership transferred
                    pending.push_back(std::move(pn));
                } else {
                    JS_FreeValue(ctx, impl);
                }

                dexMethods.push_back(std::move(dexMethod));

                JS_FreeValue(ctx, def);
            }
            js_free(ctx, table);
        }
    }
    JS_FreeValue(ctx, methodsObj);

    if (!hasNoArgConstructor) {
        bool superHasDefaultCtor = false;
        jclass sc = FindClassWithFallback(env, superclass);
        if (sc != nullptr) {
            jmethodID mid = env->GetMethodID(sc, "<init>", "()V");
            if (env->ExceptionCheck()) {
                env->ExceptionClear();
            }
            if (mid != nullptr) {
                superHasDefaultCtor = true;
            }
            env->DeleteLocalRef(sc);
        }

        if (superHasDefaultCtor) {
            PI::DexGen::MethodSpec ctorMethod;
            ctorMethod.name = "<init>";
            ctorMethod.signature = "()V";
            ctorMethod.is_static = false;
            ctorMethod.is_constructor = true;
            ctorMethod.access_flags = PI::DexGen::ACC_PUBLIC | PI::DexGen::ACC_CONSTRUCTOR;

            auto ctorWriter = std::make_shared<PI::DexWriter::Writer>();
            ctorWriter->SetRegisters(1, 1, 0); // p0 = this
            std::string superInit = PI::DexWriter::NormalizeType(superclass) + "-><init>()V";
            ctorWriter->PutInvokeDirect(superInit, {0});
            ctorWriter->PutReturnVoid();

            ctorMethod.writer = ctorWriter;
            dexMethods.push_back(std::move(ctorMethod));
        } else if (!hasAnyConstructor) {
            for (auto& p : pending) JS_FreeValue(ctx, p.impl);
            return JS_ThrowTypeError(ctx,
                "Java.registerClass: superclass '%s' does not have a no-argument constructor; an explicit '<init>' method must be provided",
                superclass.c_str());
        }
    }

    if (dexMethods.empty()) {
        for (auto& p : pending) JS_FreeValue(ctx, p.impl);
        return JS_ThrowTypeError(ctx,
            "Java.registerClass: 'methods' must declare at least one method");
    }

    // ---- fields ----------------------------------------------------------
    std::vector<PI::DexGen::FieldSpec> dexFields;
    JSValue fieldsObj = JS_GetPropertyStr(ctx, spec, "fields");
    if (JS_IsObject(fieldsObj)) {
        JSPropertyEnum* table = nullptr;
        uint32_t count = 0;
        if (JS_GetOwnPropertyNames(ctx, &table, &count, fieldsObj,
                                   JS_GPN_STRING_MASK | JS_GPN_ENUM_ONLY) == 0) {
            for (uint32_t i = 0; i < count; ++i) {
                const char* rawName = JS_AtomToCString(ctx, table[i].atom);
                std::string fieldName = rawName ? rawName : "";
                if (rawName) JS_FreeCString(ctx, rawName);
                JS_FreeAtom(ctx, table[i].atom);
                table[i].atom = JS_ATOM_NULL;

                JSValue def = JS_GetPropertyStr(ctx, fieldsObj, fieldName.c_str());
                if (JS_IsString(def)) {
                    const char* s = JS_ToCString(ctx, def);
                    if (s) {
                        PI::DexGen::FieldSpec fs;
                        fs.name = fieldName;
                        fs.type = NormalizeTypeName(s);
                        fs.access_flags = PI::DexGen::ACC_PUBLIC; // instance field
                        dexFields.push_back(std::move(fs));
                        JS_FreeCString(ctx, s);
                    }
                } else if (JS_IsObject(def)) {
                    std::string typeName;
                    GetStringProp(ctx, def, "type", &typeName);
                    if (!typeName.empty()) {
                        PI::DexGen::FieldSpec fs;
                        fs.name = fieldName;
                        fs.type = NormalizeTypeName(typeName);

                        bool isStatic = true;
                        JSValue statVal = JS_GetPropertyStr(ctx, def, "static");
                        if (JS_IsBool(statVal)) isStatic = (JS_ToBool(ctx, statVal) != 0);
                        JS_FreeValue(ctx, statVal);

                        fs.access_flags = PI::DexGen::ACC_PUBLIC;
                        if (isStatic) fs.access_flags |= PI::DexGen::ACC_STATIC;

                        const std::string& d = fs.type;
                        JSValue value = JS_GetPropertyStr(ctx, def, "value");
                        if (d == "Z") {
                            fs.kind = PI::DexGen::FieldSpec::Kind::Bool;
                            fs.bool_value = JS_ToBool(ctx, value) != 0;
                        } else if (d == "J") {
                            fs.kind = PI::DexGen::FieldSpec::Kind::Long;
                            int64_t v = 0;
                            if (JS_IsBigInt(ctx, value)) JS_ToBigInt64(ctx, &v, value);
                            else JS_ToInt64(ctx, &v, value);
                            fs.long_value = v;
                        } else if (d == "Ljava/lang/String;") {
                            fs.kind = PI::DexGen::FieldSpec::Kind::String;
                            const char* s = JS_ToCString(ctx, value);
                            fs.string_value = s ? s : "";
                            if (s) JS_FreeCString(ctx, s);
                        } else if (d == "I" || d == "S" || d == "B" || d == "C") {
                            fs.kind = PI::DexGen::FieldSpec::Kind::Int;
                            int32_t v = 0;
                            JS_ToInt32(ctx, &v, value);
                            fs.long_value = v;
                        }
                        JS_FreeValue(ctx, value);
                        dexFields.push_back(std::move(fs));
                    }
                }
                JS_FreeValue(ctx, def);
            }
            js_free(ctx, table);
        }
    }
    JS_FreeValue(ctx, fieldsObj);

    // ---- generate + load -------------------------------------------------
    PI::DexGen::ClassSpec classSpec;
    classSpec.name = className;
    classSpec.superclass = superclass;
    classSpec.interfaces = interfaces;
    classSpec.methods = std::move(dexMethods);
    classSpec.fields = std::move(dexFields);

    std::vector<PI::DexGen::ClassSpec> specs;
    specs.push_back(std::move(classSpec));

    std::vector<uint8_t> image;
    std::string error;
    if (!PI::DexGen::BuildDex(specs, &image, &error)) {
        for (auto& p : pending) JS_FreeValue(ctx, p.impl);
        return JS_ThrowTypeError(ctx, "dex generation failed: %s", error.c_str());
    }

    PI::DexLoader::LoadOptions loadOptions;
    loadOptions.inject_into_app_loader = true;   // make the class app-visible
    loadOptions.prepend = false;

    PI::DexLoader::LoadedDex loaded;
    if (!PI::DexLoader::LoadDex(env, image, className, GetAppClassLoader(env),
                                loadOptions, &loaded, &error)) {
        for (auto& p : pending) JS_FreeValue(ctx, p.impl);
        return JS_ThrowTypeError(ctx, "class loader failed: %s", error.c_str());
    }
    jobject loader = loaded.loader;

    jclass cls = PI::DexLoader::LoadClass(env, loader, className, &error);
    if (cls == nullptr) {
        DeleteLoaderRefs(env, loader, loaded.isolated);
        for (auto& p : pending) JS_FreeValue(ctx, p.impl);
        return JS_ThrowTypeError(ctx, "loadClass failed: %s", error.c_str());
    }

    // Fail fast with a readable message instead of a later AbstractMethodError
    // when an implemented interface / abstract superclass method was not
    // declared in the spec.
    {
        std::vector<MethodInfo> declared;
        CollectMethods(env, cls, &declared);
        std::string missing;
        for (const auto& m : declared) {
            if (!m.is_abstract) continue;
            missing += "\n  " + m.name + m.signature;
        }
        if (!missing.empty()) {
            PI::DexLoader::UnregisterGeneratedClass(env, className);
            env->DeleteGlobalRef(cls);
            DeleteLoaderRefs(env, loader, loaded.isolated);
            for (auto& p : pending) JS_FreeValue(ctx, p.impl);
            return JS_ThrowTypeError(
                ctx, "%s has unimplemented abstract method(s):%s\n"
                     "declare them in `methods` (native stub or implementation).",
                className.c_str(), missing.c_str());
        }
    }

    // ---- RegisterNatives ------------------------------------------------
    std::vector<std::string> nameStore;
    std::vector<std::string> sigStore;
    std::vector<JNINativeMethod> natives;
    std::vector<int> slots;
    nameStore.reserve(pending.size());
    sigStore.reserve(pending.size());

    bool failed = false;
    for (auto& p : pending) {
        int slot = -1;
        void* thunk = AcquireThunk(&slot);
        if (thunk == nullptr) {
            error = "out of native thunk slots";
            failed = true;
            break;
        }

        NativeBinding binding;
        binding.className = className;
        binding.methodName = p.name;
        binding.signature = p.signature;
        binding.retType = p.retType;
        binding.argTypes = p.argTypes;
        binding.impl = p.impl;
        {
            std::lock_guard<std::mutex> lk(g_bindingsMutex);
            g_bindings[slot] = std::move(binding);
        }
        slots.push_back(slot);

        nameStore.push_back(p.name);
        sigStore.push_back(p.signature);
        JNINativeMethod nm;
        nm.name = const_cast<char*>(nameStore.back().c_str());
        nm.signature = const_cast<char*>(sigStore.back().c_str());
        nm.fnPtr = thunk;
        natives.push_back(nm);
    }

    if (!failed && !natives.empty()) {
        if (env->RegisterNatives(cls, natives.data(),
                                 static_cast<jint>(natives.size())) != 0 ||
            env->ExceptionCheck()) {
            if (env->ExceptionCheck()) {
                LogAndClearJavaException(env, "RegisterNatives");
            }
            error = "RegisterNatives failed";
            failed = true;
        }
    }

    if (failed) {
        for (size_t i = 0; i < pending.size(); ++i) {
            if (i >= slots.size()) JS_FreeValue(ctx, pending[i].impl);
        }
        {
            std::lock_guard<std::mutex> lk(g_bindingsMutex);
            for (int slot : slots) g_bindings.erase(slot);
        }
        PI::DexLoader::UnregisterGeneratedClass(env, className);
        env->DeleteGlobalRef(cls);
        DeleteLoaderRefs(env, loader, loaded.isolated);
        return JS_ThrowTypeError(ctx, "Java.registerClass failed: %s", error.c_str());
    }

    // Warm the reflection cache so __native_jcall / JRef proxies can call the
    // generated class immediately (and on the hook path).
    PrepareClassMembers(env, cls);

    int handle;
    {
        std::lock_guard<std::mutex> lk(g_regMutex);
        handle = g_nextHandle++;
        RegisteredClass rc;
        rc.name = className;
        rc.loader = loader;                    // global ref ownership transferred
        rc.isolated = loaded.isolated;         // global ref ownership transferred
        rc.cls = cls;                          // global ref ownership transferred
        rc.injected = loaded.injected;
        rc.slots = slots;
        g_registered[handle] = std::move(rc);
    }

    __android_log_print(ANDROID_LOG_INFO, REGCLS_TAG,
                        "registered %s (%zu native method(s), loader=%p, injected=%d)",
                        className.c_str(), natives.size(), loader, loaded.injected ? 1 : 0);

    // ---- build the JS wrapper -------------------------------------------
    JSValue global = JS_GetGlobalObject(ctx);
    JSValue maker = JS_GetPropertyStr(ctx, global, "__makeRegisteredClass");
    JS_FreeValue(ctx, global);

    JSValue result = JS_UNDEFINED;
    if (JS_IsFunction(ctx, maker)) {
        JSValue staticNames = JS_NewArray(ctx);
        uint32_t n = 0;
        for (const auto& m : specs[0].methods) {
            if (m.is_static) {
                JS_SetPropertyUint32(ctx, staticNames, n++, JS_NewString(ctx, m.name.c_str()));
            }
        }
        JSValue args[4] = {
            JS_NewInt32(ctx, handle),
            JS_NewString(ctx, className.c_str()),
            staticNames,
            JS_NewBool(ctx, loaded.injected ? 1 : 0),
        };
        result = JS_Call(ctx, maker, JS_UNDEFINED, 4, args);
        for (JSValue& v : args) JS_FreeValue(ctx, v);
    }
    JS_FreeValue(ctx, maker);
    return result;
}

// ===========================================================================
// 5. __native_reg* helpers
// ===========================================================================
static JSValue JsRegNew(JSContext* ctx, JSValueConst /*this_val*/,
                        int argc, JSValueConst* argv) {
    if (argc < 1) return JS_ThrowTypeError(ctx, "$new(): missing handle");
    JNIEnv* env = GetEnv();
    if (env == nullptr) return JS_ThrowTypeError(ctx, "$new(): no JNIEnv");

    int handle = 0;
    JS_ToInt32(ctx, &handle, argv[0]);

    jclass cls = nullptr;
    {
        std::lock_guard<std::mutex> lk(g_regMutex);
        RegisteredClass* rc = FindRegistered(handle);
        if (rc == nullptr || rc->cls == nullptr) {
            return JS_ThrowTypeError(ctx, "$new(): unknown class handle");
        }
        cls = rc->cls;
    }

    const int argCount = argc - 1;

    // No-arg constructor fast path (the common case for generated classes).
    if (argCount == 0) {
        jmethodID ctor = env->GetMethodID(cls, "<init>", "()V");
        if (ctor == nullptr || env->ExceptionCheck()) {
            if (env->ExceptionCheck()) env->ExceptionClear();
            return JS_ThrowTypeError(ctx, "$new(): no default constructor");
        }
        jobject obj = env->NewObject(cls, ctor);
        if (env->ExceptionCheck()) {
            LogAndClearJavaException(env, "newObject");
            return JS_ThrowTypeError(ctx, "$new(): construction failed");
        }
        JSValue out = JavaObjectToJsValue(ctx, env, obj);
        if (obj) env->DeleteLocalRef(obj);
        return out;
    }

    // Arity-matched constructor via reflection.
    jclass classCls = env->FindClass("java/lang/Class");
    jmethodID getCtors = classCls != nullptr
        ? env->GetMethodID(classCls, "getDeclaredConstructors",
                           "()[Ljava/lang/reflect/Constructor;")
        : nullptr;
    if (env->ExceptionCheck()) env->ExceptionClear();
    if (getCtors == nullptr) {
        if (classCls) env->DeleteLocalRef(classCls);
        return JS_ThrowTypeError(ctx, "$new(): reflection unavailable");
    }

    auto ctors = static_cast<jobjectArray>(env->CallObjectMethod(cls, getCtors));
    env->DeleteLocalRef(classCls);
    if (env->ExceptionCheck() || ctors == nullptr) {
        if (env->ExceptionCheck()) env->ExceptionClear();
        return JS_ThrowTypeError(ctx, "$new(): cannot enumerate constructors");
    }

    jclass ctorCls = env->FindClass("java/lang/reflect/Constructor");
    jmethodID getParams = ctorCls != nullptr
        ? env->GetMethodID(ctorCls, "getParameterTypes", "()[Ljava/lang/Class;")
        : nullptr;
    if (env->ExceptionCheck()) env->ExceptionClear();
    if (ctorCls) env->DeleteLocalRef(ctorCls);

    jsize total = env->GetArrayLength(ctors);
    for (jsize i = 0; i < total; ++i) {
        jobject ctorObj = env->GetObjectArrayElement(ctors, i);
        if (ctorObj == nullptr) continue;

        auto params = getParams != nullptr
            ? static_cast<jobjectArray>(env->CallObjectMethod(ctorObj, getParams))
            : nullptr;
        if (env->ExceptionCheck()) env->ExceptionClear();
        if (params == nullptr) {
            env->DeleteLocalRef(ctorObj);
            continue;
        }

        jsize pn = env->GetArrayLength(params);
        if (pn != argCount) {
            env->DeleteLocalRef(params);
            env->DeleteLocalRef(ctorObj);
            continue;
        }

        std::vector<std::string> argTypes;
        std::string sig = "(";
        for (jsize p = 0; p < pn; ++p) {
            auto pc = static_cast<jclass>(env->GetObjectArrayElement(params, p));
            if (pc == nullptr) continue;
            std::string d = TypeNameToDescriptor(JavaClassName(env, pc));
            argTypes.push_back(d);
            sig += d;
            env->DeleteLocalRef(pc);
        }
        sig += ")V";
        env->DeleteLocalRef(params);
        env->DeleteLocalRef(ctorObj);

        jmethodID mid = env->GetMethodID(cls, "<init>", sig.c_str());
        if (env->ExceptionCheck()) env->ExceptionClear();
        if (mid == nullptr) continue;

        std::vector<jvalue> jargs(argTypes.size());
        std::vector<jobject> locals;
        for (size_t a = 0; a < argTypes.size(); ++a) {
            const std::string& d = argTypes[a];
            JSValueConst v = argv[1 + a];
            switch (d.empty() ? 'I' : d[0]) {
                case 'Z': jargs[a].z = JS_ToBool(ctx, v) ? JNI_TRUE : JNI_FALSE; break;
                case 'B': { int32_t t = 0; JS_ToInt32(ctx, &t, v); jargs[a].b = (jbyte) t; } break;
                case 'S': { int32_t t = 0; JS_ToInt32(ctx, &t, v); jargs[a].s = (jshort) t; } break;
                case 'C': { int32_t t = 0; JS_ToInt32(ctx, &t, v); jargs[a].c = (jchar) t; } break;
                case 'I': { int32_t t = 0; JS_ToInt32(ctx, &t, v); jargs[a].i = t; } break;
                case 'J': {
                    int64_t t = 0;
                    if (JS_IsBigInt(ctx, v)) JS_ToBigInt64(ctx, &t, v);
                    else JS_ToInt64(ctx, &t, v);
                    jargs[a].j = t;
                } break;
                case 'F': { double t = 0; JS_ToFloat64(ctx, &t, v); jargs[a].f = (jfloat) t; } break;
                case 'D': { double t = 0; JS_ToFloat64(ctx, &t, v); jargs[a].d = t; } break;
                default: {
                    jobject o = JsValueToJavaObject(env, ctx, v, DescriptorToTypeName(d));
                    if (o == nullptr && !JS_IsNull(v) && !JS_IsUndefined(v)) {
                        for (jobject lo : locals) env->DeleteLocalRef(lo);
                        env->DeleteLocalRef(ctors);
                        return JS_ThrowTypeError(ctx,
                            "$new(): cannot convert argument #%zu to %s "
                            "(arrays / non-String objects must be a JRef)",
                            a, d.c_str());
                    }
                    jargs[a].l = o;
                    if (o) locals.push_back(o);
                } break;
            }
        }

        jobject obj = env->NewObjectA(cls, mid, jargs.data());
        for (jobject o : locals) env->DeleteLocalRef(o);

        if (env->ExceptionCheck()) {
            LogAndClearJavaException(env, "newObject(args)");
            env->DeleteLocalRef(ctors);
            return JS_ThrowTypeError(ctx, "$new(): construction failed");
        }

        env->DeleteLocalRef(ctors);
        JSValue out = JavaObjectToJsValue(ctx, env, obj);
        if (obj) env->DeleteLocalRef(obj);
        return out;
    }

    env->DeleteLocalRef(ctors);
    return JS_ThrowTypeError(ctx, "$new(): no constructor accepts %d argument(s)", argCount);
}

static JSValue JsRegDispose(JSContext* ctx, JSValueConst /*this_val*/,
                            int argc, JSValueConst* argv) {
    if (argc < 1) return JS_FALSE;
    int handle = 0;
    JS_ToInt32(ctx, &handle, argv[0]);

    std::vector<int> slots;
    std::string name;
    jclass cls = nullptr;
    jobject loader = nullptr;
    jobject isolated = nullptr;
    {
        std::lock_guard<std::mutex> lk(g_regMutex);
        RegisteredClass* rc = FindRegistered(handle);
        if (rc == nullptr) return JS_FALSE;
        slots = rc->slots;
        name = rc->name;
        cls = rc->cls;
        loader = rc->loader;
        isolated = rc->isolated;
        g_registered.erase(handle);
    }

    JNIEnv* env = GetEnv();
    if (env != nullptr && cls != nullptr) {
        env->UnregisterNatives(cls);
        if (env->ExceptionCheck()) env->ExceptionClear();
    }
    {
        std::lock_guard<std::mutex> lk(g_bindingsMutex);
        for (int slot : slots) {
            auto it = g_bindings.find(slot);
            if (it != g_bindings.end()) {
                // The JS function value is intentionally not freed: the QuickJS
                // runtime owns it, and freeing it here could race with an eval
                // holding g_jsMutex.
                g_bindings.erase(it);
            }
        }
    }
    PI::DexLoader::UnregisterGeneratedClass(env, name);
    if (env != nullptr && cls != nullptr) env->DeleteGlobalRef(cls);
    DeleteLoaderRefs(env, loader, isolated);
    return JS_TRUE;
}

static JSValue JsRegMethod(JSContext* ctx, JSValueConst /*this_val*/,
                           int argc, JSValueConst* argv) {
    if (argc < 3) return JS_ThrowTypeError(ctx, "$method(name, signature)");
    JNIEnv* env = GetEnv();
    if (env == nullptr) return JS_ThrowTypeError(ctx, "no JNIEnv");

    int handle = 0;
    JS_ToInt32(ctx, &handle, argv[0]);

    const char* nameC = JS_ToCString(ctx, argv[1]);
    const char* sigC = JS_ToCString(ctx, argv[2]);
    std::string name = nameC ? nameC : "";
    std::string sig = sigC ? sigC : "";
    if (nameC) JS_FreeCString(ctx, nameC);
    if (sigC) JS_FreeCString(ctx, sigC);

    jclass cls = nullptr;
    {
        std::lock_guard<std::mutex> lk(g_regMutex);
        RegisteredClass* rc = FindRegistered(handle);
        if (rc == nullptr) return JS_ThrowTypeError(ctx, "$method(): unknown handle");
        cls = rc->cls;
    }

    PI::Method m = PI::resolve(env, cls, name, sig);
    if (!m.isValid()) {
        return JS_ThrowTypeError(ctx, "$method(): %s%s not found", name.c_str(), sig.c_str());
    }
    return JS_NewBigInt64(ctx, static_cast<int64_t>(
        reinterpret_cast<uintptr_t>(m.getArtMethod())));
}

static JSValue JsRegLoader(JSContext* ctx, JSValueConst /*this_val*/,
                           int argc, JSValueConst* argv) {
    if (argc < 1) return JS_NULL;
    JNIEnv* env = GetEnv();
    if (env == nullptr) return JS_NULL;

    int handle = 0;
    JS_ToInt32(ctx, &handle, argv[0]);

    jobject loader = nullptr;
    {
        std::lock_guard<std::mutex> lk(g_regMutex);
        RegisteredClass* rc = FindRegistered(handle);
        if (rc == nullptr || rc->loader == nullptr) return JS_NULL;
        loader = rc->loader;
    }
    return JavaObjectToJsValue(ctx, env, loader);
}

// Debug knob for the DEX loading strategy:
//   __native_dexdisk(0)  normal (InMemoryDexClassLoader when available)
//   __native_dexdisk(1)  force the DexClassLoader disk fallback
//   __native_dexdisk(2)  pretend InMemoryDexClassLoader is missing (API<26)
static JSValue JsForceDisk(JSContext* ctx, JSValueConst /*this_val*/,
                           int argc, JSValueConst* argv) {
    int mode = 0;
    if (argc >= 1) JS_ToInt32(ctx, &mode, argv[0]);
    PI::DexLoader::SetForceDisk(mode == 1);
    PI::DexLoader::SetSimulateNoInMemory(mode == 2);
    return JS_NewInt32(ctx, mode);
}

static JSValue JsRegClasses(JSContext* ctx, JSValueConst /*this_val*/,
                            int /*argc*/, JSValueConst* /*argv*/) {
    JSValue arr = JS_NewArray(ctx);
    uint32_t i = 0;
    std::lock_guard<std::mutex> lk(g_regMutex);
    for (const auto& entry : g_registered) {
        JS_SetPropertyUint32(ctx, arr, i++, JS_NewString(ctx, entry.second.name.c_str()));
    }
    return arr;
}

// ===========================================================================
// 5b. Java.loadDex(source, { inject, prepend, name })
// ===========================================================================
static bool ReadDexFileBytes(const std::string& path, std::vector<uint8_t>* out,
                             std::string* error) {
    FILE* fp = std::fopen(path.c_str(), "rb");
    if (fp == nullptr) {
        if (error) *error = "cannot open " + path + " (" + std::strerror(errno) + ")";
        return false;
    }
    std::fseek(fp, 0, SEEK_END);
    long size = std::ftell(fp);
    std::fseek(fp, 0, SEEK_SET);
    if (size <= 0) {
        std::fclose(fp);
        if (error) *error = "empty file: " + path;
        return false;
    }
    out->resize(static_cast<size_t>(size));
    size_t got = std::fread(out->data(), 1, out->size(), fp);
    std::fclose(fp);
    if (got != out->size()) {
        if (error) *error = "short read on " + path;
        return false;
    }
    return true;
}

static bool JsValueToDexBytes(JSContext* ctx, JNIEnv* env, JSValueConst v,
                              std::vector<uint8_t>* out, std::string* error) {
    if (JS_IsString(v)) {
        const char* p = JS_ToCString(ctx, v);
        std::string path = p ? p : "";
        if (p) JS_FreeCString(ctx, p);
        return ReadDexFileBytes(path, out, error);
    }

    if (JS_IsArray(ctx, v)) {
        JSValue lenVal = JS_GetPropertyStr(ctx, v, "length");
        int64_t len = 0;
        JS_ToInt64(ctx, &len, lenVal);
        JS_FreeValue(ctx, lenVal);
        if (len <= 0) {
            if (error) *error = "empty byte array";
            return false;
        }
        out->resize(static_cast<size_t>(len));
        for (int64_t i = 0; i < len; ++i) {
            JSValue e = JS_GetPropertyUint32(ctx, v, static_cast<uint32_t>(i));
            int32_t b = 0;
            JS_ToInt32(ctx, &b, e);
            JS_FreeValue(ctx, e);
            (*out)[static_cast<size_t>(i)] = static_cast<uint8_t>(b);
        }
        return true;
    }

    // JRef to a byte[]
    int h = ExtractJRefHandle(ctx, v);
    jobject obj = h >= 0 ? GetJRef(h) : nullptr;
    if (obj != nullptr && env != nullptr) {
        jclass byteArrayCls = env->FindClass("[B");
        if (byteArrayCls != nullptr) {
            bool isBytes = env->IsInstanceOf(obj, byteArrayCls) == JNI_TRUE;
            env->DeleteLocalRef(byteArrayCls);
            if (isBytes) {
                auto arr = static_cast<jbyteArray>(obj);
                jsize n = env->GetArrayLength(arr);
                out->resize(static_cast<size_t>(n));
                env->GetByteArrayRegion(arr, 0, n,
                                        reinterpret_cast<jbyte*>(out->data()));
                return !env->ExceptionCheck();
            }
        } else if (env->ExceptionCheck()) {
            env->ExceptionClear();
        }
    }

    if (error) *error = "source must be a .dex path, a number[] or a byte[] JRef";
    return false;
}

static JSValue JsLoadDex(JSContext* ctx, JSValueConst /*this_val*/,
                         int argc, JSValueConst* argv) {
    if (argc < 1) {
        return JS_ThrowTypeError(ctx, "Java.loadDex(pathOrBytes, {inject, prepend, name})");
    }
    JNIEnv* env = GetEnv();
    if (env == nullptr) return JS_ThrowTypeError(ctx, "Java.loadDex: no JNIEnv");

    std::vector<uint8_t> image;
    std::string error;
    if (!JsValueToDexBytes(ctx, env, argv[0], &image, &error)) {
        return JS_ThrowTypeError(ctx, "Java.loadDex: %s", error.c_str());
    }
    // Sanity check: standard / compact dex magic.
    if (image.size() < 8 || std::memcmp(image.data(), "dex\n", 4) != 0) {
        if (image.size() < 8 || std::memcmp(image.data(), "cdex", 4) != 0) {
            return JS_ThrowTypeError(ctx,
                "Java.loadDex: not a .dex image (bad magic, %zu bytes)", image.size());
        }
    }

    bool inject = true;
    bool prepend = false;
    std::string name;
    if (argc >= 2 && JS_IsObject(argv[1])) {
        JSValueConst opt = argv[1];
        inject = GetBoolProp(ctx, opt, "inject", true);
        prepend = GetBoolProp(ctx, opt, "prepend", false);
        GetStringProp(ctx, opt, "name", &name);
    }
    if (name.empty()) name = "external.dex";

    PI::DexLoader::LoadOptions loadOptions;
    loadOptions.inject_into_app_loader = inject;
    loadOptions.prepend = prepend;

    PI::DexLoader::LoadedDex loaded;
    if (!PI::DexLoader::LoadDex(env, image, name, GetAppClassLoader(env),
                                loadOptions, &loaded, &error)) {
        return JS_ThrowTypeError(ctx, "Java.loadDex: %s", error.c_str());
    }

    int handle;
    {
        std::lock_guard<std::mutex> lk(g_regMutex);
        handle = g_nextDexHandle++;
        LoadedDexHandle h;
        h.name = name;
        h.loader = loaded.loader;
        h.isolated = loaded.isolated;
        h.injected = loaded.injected;
        g_loadedDexes[handle] = std::move(h);
    }

    __android_log_print(ANDROID_LOG_INFO, REGCLS_TAG,
                        "loadDex %s (%zu bytes, injected=%d)",
                        name.c_str(), image.size(), loaded.injected ? 1 : 0);

    JSValue global = JS_GetGlobalObject(ctx);
    JSValue maker = JS_GetPropertyStr(ctx, global, "__makeDexLoader");
    JS_FreeValue(ctx, global);

    JSValue result = JS_UNDEFINED;
    if (JS_IsFunction(ctx, maker)) {
        JSValue args[3] = {
            JS_NewInt32(ctx, handle),
            JS_NewString(ctx, name.c_str()),
            JS_NewBool(ctx, loaded.injected ? 1 : 0),
        };
        result = JS_Call(ctx, maker, JS_UNDEFINED, 3, args);
        for (JSValue& v : args) JS_FreeValue(ctx, v);
    }
    JS_FreeValue(ctx, maker);
    return result;
}

static JSValue JsDexLoadClass(JSContext* ctx, JSValueConst /*this_val*/,
                              int argc, JSValueConst* argv) {
    if (argc < 2) return JS_ThrowTypeError(ctx, "$loadClass(name)");
    JNIEnv* env = GetEnv();
    if (env == nullptr) return JS_ThrowTypeError(ctx, "no JNIEnv");

    int handle = 0;
    JS_ToInt32(ctx, &handle, argv[0]);

    const char* nameC = JS_ToCString(ctx, argv[1]);
    std::string name = nameC ? nameC : "";
    if (nameC) JS_FreeCString(ctx, nameC);
    if (name.empty()) return JS_ThrowTypeError(ctx, "$loadClass(name)");

    jobject loader = nullptr;
    {
        std::lock_guard<std::mutex> lk(g_regMutex);
        LoadedDexHandle* h = FindLoadedDex(handle);
        if (h == nullptr) return JS_ThrowTypeError(ctx, "$loadClass(): unknown handle");
        loader = h->loader;
    }

    std::string error;
    jclass cls = PI::DexLoader::LoadClass(env, loader, name, &error);
    if (cls == nullptr) {
        return JS_ThrowTypeError(ctx, "$loadClass('%s'): %s", name.c_str(), error.c_str());
    }
    PrepareClassMembers(env, cls);
    JSValue out = JavaObjectToJsValue(ctx, env, cls);
    env->DeleteGlobalRef(cls);   // LoadClass() returns a caller-owned global ref
    return out;
}

static JSValue JsDexLoaderObj(JSContext* ctx, JSValueConst /*this_val*/,
                              int argc, JSValueConst* argv) {
    if (argc < 1) return JS_NULL;
    JNIEnv* env = GetEnv();
    if (env == nullptr) return JS_NULL;
    int handle = 0;
    JS_ToInt32(ctx, &handle, argv[0]);

    jobject loader = nullptr;
    {
        std::lock_guard<std::mutex> lk(g_regMutex);
        LoadedDexHandle* h = FindLoadedDex(handle);
        if (h == nullptr) return JS_NULL;
        loader = h->loader;
    }
    return JavaObjectToJsValue(ctx, env, loader);
}

static JSValue JsDexDispose(JSContext* ctx, JSValueConst /*this_val*/,
                            int argc, JSValueConst* argv) {
    if (argc < 1) return JS_FALSE;
    int handle = 0;
    JS_ToInt32(ctx, &handle, argv[0]);

    jobject loader = nullptr;
    jobject isolated = nullptr;
    {
        std::lock_guard<std::mutex> lk(g_regMutex);
        auto it = g_loadedDexes.find(handle);
        if (it == g_loadedDexes.end()) return JS_FALSE;
        loader = it->second.loader;
        isolated = it->second.isolated;
        g_loadedDexes.erase(it);
    }
    JNIEnv* env = GetEnv();
    DeleteLoaderRefs(env, loader, isolated);
    return JS_TRUE;
}

static JSValue JsLoadedDexes(JSContext* ctx, JSValueConst /*this_val*/,
                             int /*argc*/, JSValueConst* /*argv*/) {
    JSValue arr = JS_NewArray(ctx);
    uint32_t i = 0;
    std::lock_guard<std::mutex> lk(g_regMutex);
    for (const auto& entry : g_loadedDexes) {
        JSValue o = JS_NewObject(ctx);
        JS_SetPropertyStr(ctx, o, "name", JS_NewString(ctx, entry.second.name.c_str()));
        JS_SetPropertyStr(ctx, o, "injected", JS_NewBool(ctx, entry.second.injected ? 1 : 0));
        JS_SetPropertyUint32(ctx, arr, i++, o);
    }
    return arr;
}

// ===========================================================================
// 6. Registration
// ===========================================================================
void RegisterJavaRegisterClassApis(JSContext* ctx, JSValue global, JSValue java) {
    JS_SetPropertyStr(ctx, java, "registerClass",
                      JS_NewCFunction(ctx, JsRegisterClass, "registerClass", 1));
    JS_SetPropertyStr(ctx, java, "registeredClasses",
                      JS_NewCFunction(ctx, JsRegClasses, "registeredClasses", 0));
    JS_SetPropertyStr(ctx, global, "registerClass",
                      JS_NewCFunction(ctx, JsRegisterClass, "registerClass", 1));

    JS_SetPropertyStr(ctx, global, "__native_regnew",
                      JS_NewCFunction(ctx, JsRegNew, "__native_regnew", 1));
    JS_SetPropertyStr(ctx, global, "__native_regdispose",
                      JS_NewCFunction(ctx, JsRegDispose, "__native_regdispose", 1));
    JS_SetPropertyStr(ctx, global, "__native_regmethod",
                      JS_NewCFunction(ctx, JsRegMethod, "__native_regmethod", 3));
    JS_SetPropertyStr(ctx, global, "__native_regloader",
                      JS_NewCFunction(ctx, JsRegLoader, "__native_regloader", 1));
    JS_SetPropertyStr(ctx, global, "__native_dexdisk",
                      JS_NewCFunction(ctx, JsForceDisk, "__native_dexdisk", 1));

    // ---- Java.loadDex ---------------------------------------------------
    JS_SetPropertyStr(ctx, java, "loadDex",
                      JS_NewCFunction(ctx, JsLoadDex, "loadDex", 2));
    JS_SetPropertyStr(ctx, java, "loadedDexes",
                      JS_NewCFunction(ctx, JsLoadedDexes, "loadedDexes", 0));
    JS_SetPropertyStr(ctx, global, "loadDex",
                      JS_NewCFunction(ctx, JsLoadDex, "loadDex", 2));
    JS_SetPropertyStr(ctx, global, "__native_dexloadclass",
                      JS_NewCFunction(ctx, JsDexLoadClass, "__native_dexloadclass", 2));
    JS_SetPropertyStr(ctx, global, "__native_dexloader",
                      JS_NewCFunction(ctx, JsDexLoaderObj, "__native_dexloader", 1));
    JS_SetPropertyStr(ctx, global, "__native_dexdispose",
                      JS_NewCFunction(ctx, JsDexDispose, "__native_dexdispose", 1));

    static const char* kBoot =
        "(function(){"
        "  if (globalThis.__makeRegisteredClass) return;"
        "  globalThis.__makeRegisteredClass = function(handle, className, staticNames, injected){"
        "    var isStatic = {};"
        "    for (var i = 0; i < staticNames.length; i++) isStatic[staticNames[i]] = true;"
        "    var target = {};"
        "    return new Proxy(target, {"
        "      get: function(t, p){"
        "        if (p === '$handle') return handle;"
        "        if (p === '$className') return className;"
        "        if (p === '$injected') return !!injected;"
        "        if (p === '$new') return function(){ return __native_regnew.apply(null, [handle].concat([].slice.call(arguments))); };"
        "        if (p === '$dispose') return function(){ return __native_regdispose(handle); };"
        "        if (p === '$method') return function(n, s){ return __native_regmethod(handle, n, s); };"
        "        if (p === '$loader') return __native_regloader(handle);"
        "        if (p === '$methods') return Object.keys(isStatic);"
        "        if (p === 'toString' || p === 'valueOf') return function(){ return '[JavaClass ' + className + ']'; };"
        "        if (typeof p === 'string' && p.charCodeAt(0) !== 95) {"
        "          if (p === 'then' || p === 'toJSON' || p === 'inspect') return t[p];"
        "          return function(){"
        "            return __native_jcall.apply(null, [className, p].concat([].slice.call(arguments)));"
        "          };"
        "        }"
        "        return t[p];"
        "      }"
        "    });"
        "  };"
        "  globalThis.__makeDexLoader = function(handle, name, injected){"
        "    return new Proxy({}, {"
        "      get: function(t, p){"
        "        if (p === '$handle') return handle;"
        "        if (p === '$name') return name;"
        "        if (p === '$injected') return !!injected;"
        "        if (p === 'loadClass' || p === '$loadClass') return function(n){ return __native_dexloadclass(handle, n); };"
        "        if (p === '$loader') return __native_dexloader(handle);"
        "        if (p === '$dispose') return function(){ return __native_dexdispose(handle); };"
        "        return t[p];"
        "      }"
        "    });"
        "  };"
        "})();";

    JSValue boot = JS_Eval(ctx, kBoot, strlen(kBoot), "<registerclass_boot>",
                           JS_EVAL_TYPE_GLOBAL);
    if (JS_IsException(boot)) {
        JSValue exc = JS_GetException(ctx);
        const char* err = JS_ToCString(ctx, exc);
        __android_log_print(ANDROID_LOG_ERROR, REGCLS_TAG,
                            "bootstrap failed: %s", err ? err : "?");
        if (err) JS_FreeCString(ctx, err);
        JS_FreeValue(ctx, exc);
    }
    JS_FreeValue(ctx, boot);
}

}} // namespace artpi::agent
