//
// Created for Pine Native - Pure C/C++ ART Hook Engine
//

#include "pine_native.h"
#include "android.h"
#include "art/art_method.h"
#include "art/thread.h"
#include "trampoline/trampoline_installer.h"
#include "utils/log.h"
#include "utils/scoped_local_ref.h"
#include "dex/pi_smali.h"
#include <sys/system_properties.h>
#include <atomic>
#include <mutex>
#include <unordered_map>
#include <unordered_set>
#include <functional>
#include <inttypes.h>
#include <algorithm>
#include <sstream>
#include <unwind.h>
#include <dlfcn.h>
#include <cstdio>

using namespace pine;

static std::atomic<bool> g_pine_native_initialized{false};
static JavaVM* g_jvm = nullptr;

namespace pine_native {

JNIEnv* GetCurrentJNIEnv() {
    if (!g_jvm) return nullptr;
    JNIEnv* env = nullptr;
    if (g_jvm->GetEnv(reinterpret_cast<void**>(&env), JNI_VERSION_1_6) == JNI_OK) {
        return env;
    }
    if (g_jvm->AttachCurrentThread(&env, nullptr) == JNI_OK) {
        return env;
    }
    return nullptr;
}

} // namespace pine_native

static int GetAndroidSdkVersion(JNIEnv* env) {
    char sdk_version_str[PROP_VALUE_MAX] = {0};
    if (__system_property_get("ro.build.version.sdk", sdk_version_str) > 0) {
        int version = atoi(sdk_version_str);
        if (version > 0) return version;
    }

    // JNI fallback
    if (env) {
        jclass versionClass = env->FindClass("android/os/Build$VERSION");
        if (versionClass) {
            jfieldID sdkIntField = env->GetStaticFieldID(versionClass, "SDK_INT", "I");
            if (sdkIntField) {
                int sdk = env->GetStaticIntField(versionClass, sdkIntField);
                env->DeleteLocalRef(versionClass);
                return sdk;
            }
            env->DeleteLocalRef(versionClass);
        }
        if (env->ExceptionCheck()) {
            env->ExceptionClear();
        }
    }
    return 30; // Default fallback to Android 11 (R)
}

bool PineNative_Init(JNIEnv* env) {
    if (env && !g_jvm) {
        env->GetJavaVM(&g_jvm);
    }

    if (g_pine_native_initialized.load(std::memory_order_acquire)) {
        return true;
    }

    if (!env) {
        LOGE("PineNative_Init failed: JNIEnv is null");
        return false;
    }

    int sdk_version = GetAndroidSdkVersion(env);
    LOGI("PineNative_Init: Detected Android SDK Level = %d", sdk_version);

    // Initialize Android runtime symbol resolution & Trampolines
    Android::Init(env, sdk_version, false, false);
    TrampolineInstaller::GetOrInitDefault();

    // Initialize ArtMethod member offsets without loading any Java Ruler class
    art::ArtMethod::InitMembersNative(env);

    g_pine_native_initialized.store(true, std::memory_order_release);
    LOGI("PineNative_Init successfully initialized!");
    return true;
}

bool PineNative_IsInitialized(void) {
    return g_pine_native_initialized.load(std::memory_order_acquire);
}

bool PineNative_Hook(JNIEnv* env, jclass clazz, const char* methodName, const char* signature,
                     bool isStatic, PineNativeCallback callback, void** out_backup) {
    if (!PineNative_IsInitialized()) {
        if (!PineNative_Init(env)) {
            LOGE("PineNative_Hook failed: initialization error");
            return false;
        }
    }

    if (!env || !clazz || !methodName || !signature || !callback) {
        LOGE("PineNative_Hook: Invalid parameters");
        return false;
    }

    art::ArtMethod* target = art::ArtMethod::Require(env, clazz, methodName, signature, isStatic);
    if (!target) {
        LOGE("PineNative_Hook: Failed to find target method %s%s", methodName, signature);
        return false;
    }

    TrampolineInstaller* installer = TrampolineInstaller::GetDefault();
    if (!installer) {
        LOGE("PineNative_Hook: TrampolineInstaller is null");
        return false;
    }

    void* backup = nullptr;
    if (!installer->IsReplacementOnly() && !installer->CannotSafeInlineHook(target)) {
        LOGI("PineNative_Hook: Installing native inline hook on %s%s", methodName, signature);
        backup = installer->InstallNativeInlineTrampoline(target, reinterpret_cast<void*>(callback), false);
    }

    if (!backup) {
        LOGW("PineNative_Hook: Inline hook failed or unsupported, falling back to replacement trampoline");
        backup = installer->InstallNativeReplacementTrampoline(target, reinterpret_cast<void*>(callback));
    }

    if (backup && out_backup) {
        *out_backup = backup;
    }

    return backup != nullptr;
}

bool PineNative_HookMethod(JNIEnv* env, jclass clazz, jmethodID methodId,
                           bool isStatic, PineNativeCallback callback, void** out_backup) {
    if (!PineNative_IsInitialized()) {
        if (!PineNative_Init(env)) return false;
    }

    if (!methodId || !callback) return false;

    art::ArtMethod* target = nullptr;
    if (Android::version >= Android::kR && (reinterpret_cast<uintptr_t>(methodId) & 1)) {
        ScopedLocalRef javaMethod(env, env->ToReflectedMethod(clazz, methodId, static_cast<jboolean>(isStatic)));
        target = art::ArtMethod::GetArtMethodForR(env, javaMethod.Get());
    } else {
        target = reinterpret_cast<art::ArtMethod*>(methodId);
    }

    if (!target) {
        LOGE("PineNative_HookMethod: Invalid ArtMethod pointer");
        return false;
    }

    TrampolineInstaller* installer = TrampolineInstaller::GetDefault();
    void* backup = nullptr;
    if (!installer->IsReplacementOnly() && !installer->CannotSafeInlineHook(target)) {
        backup = installer->InstallNativeInlineTrampoline(target, reinterpret_cast<void*>(callback), false);
    }
    if (!backup) {
        backup = installer->InstallNativeReplacementTrampoline(target, reinterpret_cast<void*>(callback));
    }

    if (backup && out_backup) {
        *out_backup = backup;
    }

    return backup != nullptr;
}

bool PineNative_HookReplace(JNIEnv* env, jclass clazz, const char* methodName, const char* signature,
                            bool isStatic, PineNativeReplacement replacement, void** out_backup) {
    if (!PineNative_IsInitialized()) {
        if (!PineNative_Init(env)) return false;
    }

    if (!env || !clazz || !methodName || !signature || !replacement) return false;

    art::ArtMethod* target = art::ArtMethod::Require(env, clazz, methodName, signature, isStatic);
    if (!target) {
        LOGE("PineNative_HookReplace: Method %s%s not found", methodName, signature);
        return false;
    }

    TrampolineInstaller* installer = TrampolineInstaller::GetDefault();
    void* backup = installer->InstallNativeDirectReplacement(target, reinterpret_cast<void*>(replacement));

    if (backup && out_backup) {
        *out_backup = backup;
    }

    return backup != nullptr;
}

jobject PineNative_ToJObject(JNIEnv* env, void* art_obj) {
    if (!env || !art_obj) return nullptr;
    art::Thread* thread = art::Thread::Current(env);
    if (!thread) {
        LOGE("PineNative_ToJObject: Failed to get current art::Thread");
        return nullptr;
    }
    return thread->AddLocalRef(env, reinterpret_cast<Object*>(art_obj));
}

void* PineNative_ToArtObject(JNIEnv* env, jobject j_obj) {
    if (!env || !j_obj) return nullptr;
    art::Thread* thread = art::Thread::Current(env);
    if (!thread) {
        LOGE("PineNative_ToArtObject: Failed to get current art::Thread");
        return nullptr;
    }
    return thread->DecodeJObject(j_obj);
}

static PineObservedObjectCallback g_observedObjectCb = nullptr;

void PineNative_SetObservedObjectCallback(PineObservedObjectCallback cb) {
    g_observedObjectCb = cb;
}

void PineNative_NotifyObservedObject(JNIEnv* env, uint64_t raw, jobject obj) {
    if (g_observedObjectCb && env && obj && raw) {
        g_observedObjectCb(env, raw, obj);
    }
}

static std::mutex g_lambda_mutex;
static std::unordered_map<void*, std::function<void(void*, PineNativeContext*, void*)>> g_lambda_hooks;

static void LambdaHookDispatcher(void* target, PineNativeContext* ctx, void* origin) {
    std::function<void(void*, PineNativeContext*, void*)> fn;
    {
        std::lock_guard<std::mutex> lock(g_lambda_mutex);
        auto it = g_lambda_hooks.find(target);
        if (it != g_lambda_hooks.end()) {
            fn = it->second;
        }
    }
    if (fn) {
        fn(target, ctx, origin);
    }
}

namespace pine_native {

bool PineNative_HookLambda(JNIEnv* env, jclass clazz, const char* methodName, const char* signature,
                           bool isStatic, const std::function<void(void*, PineNativeContext*, void*)>& fn,
                           void** out_backup) {
    if (!env || !clazz || !methodName || !signature) return false;
    art::ArtMethod* target = art::ArtMethod::Require(env, clazz, methodName, signature, isStatic);
    if (!target) {
        LOGE("PineNative_HookLambda: Target method %s%s not found", methodName, signature);
        return false;
    }

    {
        std::lock_guard<std::mutex> lock(g_lambda_mutex);
        g_lambda_hooks[target] = fn;
    }

    return PineNative_Hook(env, clazz, methodName, signature, isStatic, LambdaHookDispatcher, out_backup);
}

// Human-readable class name (dotted, e.g. "com.example.Foo") for log/frame use.
static std::string ClassNameOf(JNIEnv* env, jclass clazz) {
    if (!env || !clazz) return "";
    jclass classCls = env->FindClass("java/lang/Class");
    if (!classCls) { if (env->ExceptionCheck()) env->ExceptionClear(); return ""; }
    jmethodID getName = env->GetMethodID(classCls, "getName", "()Ljava/lang/String;");
    std::string n;
    if (getName) {
        auto jn = static_cast<jstring>(env->CallObjectMethod(clazz, getName));
        if (jn) {
            const char* c = env->GetStringUTFChars(jn, nullptr);
            if (c) { n = c; env->ReleaseStringUTFChars(jn, c); }
            env->DeleteLocalRef(jn);
        }
    }
    if (env->ExceptionCheck()) env->ExceptionClear();
    env->DeleteLocalRef(classCls);
    return n;
}

static std::vector<std::string> ParseJavaArgTypes(const std::string& sig) {
    std::vector<std::string> types;
    auto start = sig.find('(');
    auto end = sig.find(')');
    if (start == std::string::npos || end == std::string::npos || end <= start) return types;
    for (size_t i = start + 1; i < end; ++i) {
        size_t type_start = i;
        while (i < end && sig[i] == '[') {
            i++;
        }
        if (i < end && sig[i] == 'L') {
            size_t semi = sig.find(';', i);
            if (semi != std::string::npos && semi < end) {
                i = semi;
            }
        }
        types.push_back(sig.substr(type_start, i - type_start + 1));
    }
    return types;
}

// --- ArgProxy Implementations ---
bool ArgProxy::isObject() const {
    if (index_ < 0) return true;
    return frame_ ? frame_->isArgObject(index_) : false;
}

ArgProxy::operator jobject() const {
    if (index_ < 0) return frame_->getThisObject();
    return frame_->getArg(index_);
}

ArgProxy::operator jstring() const {
    if (index_ < 0) return reinterpret_cast<jstring>(frame_->getThisObject());
    return reinterpret_cast<jstring>(frame_->getArg(index_));
}

ArgProxy::operator jclass() const {
    if (index_ < 0) return reinterpret_cast<jclass>(frame_->getThisObject());
    return reinterpret_cast<jclass>(frame_->getArg(index_));
}

ArgProxy::operator int() const {
    if (index_ < 0) return 0;
    return static_cast<int>(frame_->getArgRaw(index_));
}

ArgProxy::operator jlong() const {
    if (index_ < 0) return 0;
    return static_cast<jlong>(frame_->getArgRaw(index_));
}

ArgProxy::operator bool() const {
    if (index_ < 0) return frame_->getThisObject() != nullptr;
    return static_cast<bool>(frame_->getArgRaw(index_));
}

ArgProxy::operator double() const {
    if (index_ >= 0 && index_ < 8) return frame_->ctx->d[index_];
    return 0.0;
}

ArgProxy::operator float() const {
    if (index_ >= 0 && index_ < 8) return static_cast<float>(frame_->ctx->d[index_]);
    return 0.0f;
}

ArgProxy::operator void*() const {
    if (index_ < 0) return reinterpret_cast<void*>(frame_->getThisObject());
    return reinterpret_cast<void*>(frame_->getArgRaw(index_));
}

ArgProxy::operator std::string() const {
    return as_string();
}

ArgProxy& ArgProxy::operator=(jobject obj) {
    if (index_ >= 0) frame_->setArg(index_, obj);
    return *this;
}

ArgProxy& ArgProxy::operator=(int val) {
    if (index_ >= 0) frame_->setArgRaw(index_, static_cast<uint64_t>(val));
    return *this;
}

ArgProxy& ArgProxy::operator=(jlong val) {
    if (index_ >= 0) frame_->setArgRaw(index_, static_cast<uint64_t>(val));
    return *this;
}

ArgProxy& ArgProxy::operator=(bool val) {
    if (index_ >= 0) frame_->setArgRaw(index_, val ? 1 : 0);
    return *this;
}

ArgProxy& ArgProxy::operator=(double val) {
    if (index_ >= 0 && index_ < 8) frame_->ctx->d[index_] = val;
    return *this;
}

ArgProxy& ArgProxy::operator=(float val) {
    if (index_ >= 0 && index_ < 8) frame_->ctx->d[index_] = static_cast<double>(val);
    return *this;
}

ArgProxy& ArgProxy::operator=(void* val) {
    if (index_ >= 0) frame_->setArgRaw(index_, reinterpret_cast<uint64_t>(val));
    return *this;
}

ArgProxy& ArgProxy::operator=(const char* str) {
    if (index_ >= 0 && frame_->getEnv() && str) {
        jstring js = frame_->getEnv()->NewStringUTF(str);
        frame_->setArg(index_, js);
    }
    return *this;
}

ArgProxy& ArgProxy::operator=(const std::string& str) {
    return *this = str.c_str();
}

std::string ArgProxy::as_string() const {
    if (index_ < 0) {
        jobject thiz = frame_->getThisObject();
        char buf[64];
        snprintf(buf, sizeof(buf), "instance@%p", thiz);
        return std::string(buf);
    }
    return frame_->getArgString(index_);
}

jobject ArgProxy::as_jobject() const {
    if (index_ < 0) return frame_->getThisObject();
    return frame_->getArg(index_);
}

template<typename T>
T ArgProxy::as() const {
    if constexpr (std::is_same_v<T, std::string>) {
        return as_string();
    } else if (index_ < 0) {
        if constexpr (std::is_pointer_v<T>) {
            return reinterpret_cast<T>(frame_->getThisObject());
        } else {
            return static_cast<T>(0);
        }
    } else if constexpr (std::is_pointer_v<T>) {
        return reinterpret_cast<T>(frame_->getArgRaw(index_));
    } else {
        return static_cast<T>(frame_->getArgRaw(index_));
    }
}

// Explicit template instantiations
template std::string ArgProxy::as<std::string>() const;
template int ArgProxy::as<int>() const;
template jlong ArgProxy::as<jlong>() const;
template bool ArgProxy::as<bool>() const;
template void* ArgProxy::as<void*>() const;

ArgProxy ArgsAccessor::operator[](int index) const {
    if (index < 0 || index >= frame_->getArgCount()) {
        LOGE("ArgsAccessor: Argument index %d out of bounds (count %d)", index, frame_->getArgCount());
    }
    return ArgProxy(frame_, index);
}

ArgProxy CallFrame::operator[](size_t index) {
    if (index >= static_cast<size_t>(arg_count)) {
        LOGE("CallFrame[]: Argument index %zu out of range! Method %s has %d arguments (slots 0..%d)",
             index, method_name.c_str(), arg_count, arg_count > 0 ? (arg_count - 1) : 0);
    }
    return ArgProxy(this, static_cast<int>(index));
}

const ArgProxy CallFrame::operator[](size_t index) const {
    return const_cast<CallFrame*>(this)->operator[](index);
}

// --- CallFrame Implementations ---

CallFrame::CallFrame(JNIEnv* env, void* target, PineNativeContext* ctx, void* origin,
                     bool isStatic, const std::string& methodName, const std::string& sig,
                     const std::string& className)
    : env(env), target_method(target), ctx(ctx), origin_entry(origin),
      is_static(isStatic), method_name(methodName), signature(sig),
      class_name(className), arg_count(0), return_type('V'), clazz(nullptr), mid(nullptr),
      has_custom_result(false), original_invoked(false), original_result_raw(0), thiz(this, -1), args(this) {
    arg_types = ParseJavaArgTypes(sig);
    arg_count = static_cast<int>(arg_types.size());
    auto r_pos = sig.find(')');
    if (r_pos != std::string::npos && r_pos + 1 < sig.size()) {
        return_type = sig[r_pos + 1];
    }
}

bool CallFrame::isArgObject(int index) const {
    if (index < 0 || index >= static_cast<int>(arg_types.size())) return false;
    char first = arg_types[index][0];
    return first == 'L' || first == '[';
}

std::string CallFrame::getMethodToString() const {
    return class_name.empty() ? (method_name + signature) : (class_name + "." + method_name + signature);
}

jobject CallFrame::getThisObject() const {
    if (is_static || !env) return nullptr;
    return PineNative_ToJObject(env, reinterpret_cast<void*>(ctx->r[1]));
}

jobject CallFrame::getArg(int index) const {
    if (!env || index < 0 || index >= arg_count) return nullptr;
    if (!isArgObject(index)) return nullptr;
    size_t reg_idx = is_static ? (1 + index) : (2 + index);
    void* art_obj = nullptr;
    if (reg_idx <= 7) {
        art_obj = reinterpret_cast<void*>(ctx->r[reg_idx]);
    } else {
        size_t stack_idx = reg_idx - 8;
        uint64_t* sp_ptr = reinterpret_cast<uint64_t*>(ctx->sp);
        art_obj = reinterpret_cast<void*>(sp_ptr[stack_idx]);
    }
    return PineNative_ToJObject(env, art_obj);
}

void CallFrame::setArg(int index, jobject arg) {
    if (!env || index < 0 || index >= arg_count) return;
    void* art_obj = PineNative_ToArtObject(env, arg);
    setArgRaw(index, reinterpret_cast<uintptr_t>(art_obj));
}

uint64_t CallFrame::getArgRaw(int index) const {
    if (index < 0 || index >= arg_count) return 0;
    // Floating point args are passed in the d register file (d0..d7), indexed by
    // argument position (same convention as ArgProxy).
    if (index < static_cast<int>(arg_types.size())) {
        char t = arg_types[index].empty() ? 'I' : arg_types[index][0];
        if (t == 'F' || t == 'D') {
            if (index < 8) {
                uint64_t raw;
                double dv = ctx->d[index];
                std::memcpy(&raw, &dv, sizeof(raw));
                return raw;
            }
        }
    }
    size_t reg_idx = is_static ? (1 + index) : (2 + index);
    if (reg_idx <= 7) {
        return ctx->r[reg_idx];
    } else {
        size_t stack_idx = reg_idx - 8;
        uint64_t* sp_ptr = reinterpret_cast<uint64_t*>(ctx->sp);
        return sp_ptr[stack_idx];
    }
}

void CallFrame::setArgRaw(int index, uint64_t val) {
    if (index < 0 || index >= arg_count) return;
    if (index < static_cast<int>(arg_types.size())) {
        char t = arg_types[index].empty() ? 'I' : arg_types[index][0];
        if (t == 'F' || t == 'D') {
            if (index < 8) {
                double dv;
                std::memcpy(&dv, &val, sizeof(dv));
                ctx->d[index] = dv;
                return;
            }
        }
    }
    size_t reg_idx = is_static ? (1 + index) : (2 + index);
    if (reg_idx <= 7) {
        ctx->r[reg_idx] = val;
    } else {
        size_t stack_idx = reg_idx - 8;
        uint64_t* sp_ptr = reinterpret_cast<uint64_t*>(ctx->sp);
        sp_ptr[stack_idx] = val;
    }
}

namespace {
// "Lkotlin/jvm/functions/Function1;" -> "Function1"; primitives pass through.
std::string ShortTypeName(const std::string& d) {
    if (d.empty()) return "";
    std::string s = d;
    if (s[0] == 'L' && s.size() > 1 && s.back() == ';') s = s.substr(1, s.size() - 2);
    size_t slash = s.rfind('/');
    if (slash != std::string::npos) s = s.substr(slash + 1);
    return s;
}

// True if the bytes form valid UTF-8 without control/surrogate/PUA/halfwidth
// codepoints (i.e. it reads as normal text, including CJK/emoji).
bool LooksLikeText(const std::string& s) {
    size_t i = 0, n = s.size();
    while (i < n) {
        unsigned char c = static_cast<unsigned char>(s[i]);
        uint32_t cp; int len;
        if (c < 0x80) { cp = c; len = 1; }
        else if ((c & 0xE0) == 0xC0) { cp = c & 0x1F; len = 2; }
        else if ((c & 0xF0) == 0xE0) { cp = c & 0x0F; len = 3; }
        else if ((c & 0xF8) == 0xF0) { cp = c & 0x07; len = 4; }
        else return false;
        if (i + len > n) return false;
        for (int k = 1; k < len; k++) {
            if ((static_cast<unsigned char>(s[i + k]) & 0xC0) != 0x80) return false;
            cp = (cp << 6) | (static_cast<unsigned char>(s[i + k]) & 0x3F);
        }
        if (cp < 0x20 || cp == 0x7F) return false;              // C0 controls
        if (cp >= 0x80 && cp <= 0x9F) return false;             // C1 controls
        if (cp >= 0xD800 && cp <= 0xDFFF) return false;         // surrogates
        if (cp >= 0xE000 && cp <= 0xF8FF) return false;         // private use
        if (cp >= 0xFF80 && cp <= 0xFFFF) return false;         // halfwidth/specials
        i += len;
    }
    return true;
}

// Binary-ish Java strings (arbitrary bytes decoded as String) show as mojibake;
// escape them so the log is deterministic/readable. Normal text passes through.
std::string SanitizeForLog(const std::string& s) {
    if (s.empty() || LooksLikeText(s)) return s;
    std::string out;
    out.reserve(s.size() * 2);
    for (unsigned char c : s) {
        if (c >= 0x20 && c < 0x7F) {
            out += static_cast<char>(c);
        } else {
            char b[8];
            snprintf(b, sizeof(b), "\\x%02x", c);
            out += b;
        }
    }
    return out;
}

// Render an array: byte[] as hex, int/short/char[] as a short list, others as
// "elem[len]". Pure JNI array ops (safe on the hook path).
std::string FormatArrayValue(JNIEnv* env, jobject arr, const std::string& desc) {
    if (!env || !arr) return "null";
    jarray a = reinterpret_cast<jarray>(arr);
    jsize len = env->GetArrayLength(a);
    if (env->ExceptionCheck()) { env->ExceptionClear(); return "array"; }
    std::string elem = (desc.size() > 1) ? desc.substr(1) : std::string();
    char head[64];

    if (elem == "B") {
        const int kMax = 96;
        int n = len < kMax ? len : kMax;
        std::vector<jbyte> buf(n);
        env->GetByteArrayRegion(reinterpret_cast<jbyteArray>(arr), 0, n, buf.data());
        if (env->ExceptionCheck()) env->ExceptionClear();
        std::string hex;
        hex.reserve(static_cast<size_t>(n) * 2);
        for (int i = 0; i < n; i++) {
            char t[4];
            snprintf(t, sizeof(t), "%02x", static_cast<unsigned char>(buf[i]));
            hex += t;
        }
        snprintf(head, sizeof(head), "byte[%d] ", static_cast<int>(len));
        return std::string(head) + hex + (len > n ? "..." : "");
    }
    if (elem == "I" || elem == "S" || elem == "C") {
        const int kMax = 24;
        int n = len < kMax ? len : kMax;
        std::vector<jint> buf(n);
        env->GetIntArrayRegion(reinterpret_cast<jintArray>(arr), 0, n, buf.data());
        if (env->ExceptionCheck()) env->ExceptionClear();
        std::string s;
        for (int i = 0; i < n; i++) { if (i) s += ','; s += std::to_string(buf[i]); }
        const char* tn = (elem == "I") ? "int" : (elem == "S") ? "short" : "char";
        snprintf(head, sizeof(head), "%s[%d] ", tn, static_cast<int>(len));
        return std::string(head) + s + (len > n ? ",..." : "");
    }

    std::string et = elem;
    if (!et.empty() && et[0] == 'L' && et.back() == ';') {
        et = et.substr(1, et.size() - 2);
        size_t slash = et.rfind('/');
        if (slash != std::string::npos) et = et.substr(slash + 1);
    }
    snprintf(head, sizeof(head), "%s[%d]", et.empty() ? "array" : et.c_str(), static_cast<int>(len));
    return head;
}

// Render an object arg/return purely natively: TypeDesc@0xaddr.
// No obj.toString() here — it would enter Java (and possibly a hooked method)
// on the hook/interpreter path.
std::string FormatObjectValue(JNIEnv* env, jobject obj, uint64_t raw, const std::string& typeDesc) {
    if (env && obj && raw) {
        PineNative_NotifyObservedObject(env, raw, obj);
    }
    if (!raw) return "null";
    std::string tn = ShortTypeName(typeDesc);
    char buf[160];
    snprintf(buf, sizeof(buf), "%s@0x%llx", tn.empty() ? "obj" : tn.c_str(),
             static_cast<unsigned long long>(raw));
    return std::string(buf);
}
} // namespace

std::string CallFrame::getArgString(int index) const {
    if (!env || index < 0 || index >= arg_count) return "";
    if (index < static_cast<int>(arg_types.size())) {
        const std::string& type = arg_types[index];
        if (type == "Ljava/lang/String;") {
            jobject obj = getArg(index);
            if (!obj) return "null";
            jstring jstr = reinterpret_cast<jstring>(obj);
            const char* c_str = env->GetStringUTFChars(jstr, nullptr);
            if (!c_str) {
                if (env->ExceptionCheck()) env->ExceptionClear();
                return "";
            }
            std::string s(c_str);
            env->ReleaseStringUTFChars(jstr, c_str);
            return SanitizeForLog(s);
        }
        if (type == "I" || type == "S" || type == "B") {
            return std::to_string(static_cast<int>(getArgRaw(index)));
        }
        if (type == "Z") {
            return getArgRaw(index) ? "true" : "false";
        }
        if (type == "J") {
            return std::to_string(static_cast<int64_t>(getArgRaw(index)));
        }
        if (type == "C") {
            char c = static_cast<char>(getArgRaw(index));
            return std::string(1, c);
        }
        if (type == "D" || type == "F") {
            double dv = (index < 8) ? ctx->d[index] : 0.0;
            char buf[48];
            snprintf(buf, sizeof(buf), "%g", dv);
            return std::string(buf);
        }
    }
    if (isArgObject(index)) {
        jobject obj = getArg(index);
        uint64_t raw = getArgRaw(index);
        if (!raw && obj && env) {
            void* artObj = PineNative_ToArtObject(env, obj);
            if (artObj) raw = reinterpret_cast<uintptr_t>(artObj);
        }
        std::string td = (index < static_cast<int>(arg_types.size())) ? arg_types[index] : "";
        if (!td.empty() && td[0] == '[') return FormatArrayValue(env, obj, td);
        return FormatObjectValue(env, obj, raw, td);
    }
    char buf[64];
    snprintf(buf, sizeof(buf), "0x%" PRIx64, getArgRaw(index));
    return std::string(buf);
}

jobject CallFrame::getResult() const {
    if (!env || (!original_invoked && !has_custom_result)) return nullptr;
    auto r_pos = signature.find(')');
    if (r_pos != std::string::npos && r_pos + 1 < signature.length()) {
        char ret_type = signature[r_pos + 1];
        if (ret_type == 'V') return nullptr;
        if (ret_type == 'L' || ret_type == '[') {
            return PineNative_ToJObject(env, reinterpret_cast<void*>(ctx->r[0]));
        }
    }
    return reinterpret_cast<jobject>(ctx->r[0]);
}

std::string CallFrame::getResultString() const {
    if (!original_invoked && !has_custom_result) {
        return "<not returned yet>";
    }
    if (!env) return "";
    auto r_pos = signature.find(')');
    if (r_pos != std::string::npos && signature.substr(r_pos + 1) == "Ljava/lang/String;") {
        jobject res = getResult();
        if (!res) return "null";
        const char* c_str = env->GetStringUTFChars(reinterpret_cast<jstring>(res), nullptr);
        if (c_str) {
            std::string s(c_str);
            env->ReleaseStringUTFChars(reinterpret_cast<jstring>(res), c_str);
            return SanitizeForLog(s);
        }
        if (env->ExceptionCheck()) env->ExceptionClear();
    }
    if (r_pos != std::string::npos && signature[r_pos + 1] == 'I') {
        return std::to_string(static_cast<int>(ctx->r[0]));
    }
    if (r_pos != std::string::npos && signature[r_pos + 1] == 'Z') {
        return ctx->r[0] ? "true" : "false";
    }
    if (r_pos != std::string::npos &&
        (signature[r_pos + 1] == 'D' || signature[r_pos + 1] == 'F')) {
        char buf[48];
        snprintf(buf, sizeof(buf), "%g", ctx->d[0]);
        return std::string(buf);
    }
    if (r_pos != std::string::npos && signature[r_pos + 1] == 'V') {
        return "void";
    }
    if (r_pos != std::string::npos) {
        char rt = signature[r_pos + 1];
        if (rt == 'L' || rt == '[') {
            uint64_t raw = ctx->r[0];
            if (!raw) return "null";
            jobject res = getResult();
            std::string rtDesc = signature.substr(r_pos + 1);
            if (!rtDesc.empty() && rtDesc[0] == '[') return FormatArrayValue(env, res, rtDesc);
            return FormatObjectValue(env, res, raw, rtDesc);
        }
    }
    char buf[64];
    snprintf(buf, sizeof(buf), "0x%" PRIx64, ctx->r[0]);
    return std::string(buf);
}

void CallFrame::setResult(jobject result) {
    if (env && result) {
        ctx->r[0] = reinterpret_cast<uintptr_t>(PineNative_ToArtObject(env, result));
    } else {
        ctx->r[0] = reinterpret_cast<uintptr_t>(result);
    }
    has_custom_result = true;
}

void CallFrame::setResult(const char* str) {
    if (env && str) {
        jstring js = env->NewStringUTF(str);
        setResult(static_cast<jobject>(js));
    }
}

void CallFrame::setResult(const std::string& str) {
    setResult(str.c_str());
}

jobject CallFrame::invokeOriginalInternal() {
    if (!origin_entry) return nullptr;
    if (original_invoked) return getResult();

    auto target = reinterpret_cast<art::ArtMethod*>(target_method);
    void* cur_entry = target->GetEntryPointFromCompiledCode();

    if (mid && clazz && env) {
        jvalue jargs[16];
        for (int i = 0; i < arg_count && i < 16; ++i) {
            if (isArgObject(i)) {
                jargs[i].l = getArg(i);
            } else if (i < static_cast<int>(arg_types.size())) {
                char t = arg_types[i][0];
                if (t == 'I' || t == 'S' || t == 'B' || t == 'C') jargs[i].i = static_cast<jint>(getArgRaw(i));
                else if (t == 'Z') jargs[i].z = static_cast<jboolean>(getArgRaw(i));
                else if (t == 'J') jargs[i].j = static_cast<jlong>(getArgRaw(i));
                else if (t == 'F') jargs[i].f = static_cast<jfloat>(ctx->d[i]);
                else if (t == 'D') jargs[i].d = ctx->d[i];
                else jargs[i].j = static_cast<jlong>(getArgRaw(i));
            } else {
                jargs[i].j = static_cast<jlong>(getArgRaw(i));
            }
        }

        // Temporarily restore original entrypoint to avoid recursive hook invocation
        target->SetEntryPointFromCompiledCode(origin_entry);

        jobject res_obj = nullptr;
        if (is_static) {
            switch (return_type) {
                case 'V':
                    env->CallStaticVoidMethodA(clazz, mid, jargs);
                    break;
                case 'I': case 'S': case 'B': case 'C': {
                    jint r = env->CallStaticIntMethodA(clazz, mid, jargs);
                    ctx->r[0] = static_cast<uint64_t>(r);
                    break;
                }
                case 'Z': {
                    jboolean r = env->CallStaticBooleanMethodA(clazz, mid, jargs);
                    ctx->r[0] = r ? 1 : 0;
                    break;
                }
                case 'J': {
                    jlong r = env->CallStaticLongMethodA(clazz, mid, jargs);
                    ctx->r[0] = static_cast<uint64_t>(r);
                    break;
                }
                case 'F': {
                    jfloat r = env->CallStaticFloatMethodA(clazz, mid, jargs);
                    ctx->d[0] = static_cast<double>(r);
                    break;
                }
                case 'D': {
                    jdouble r = env->CallStaticDoubleMethodA(clazz, mid, jargs);
                    ctx->d[0] = r;
                    break;
                }
                default: {
                    res_obj = env->CallStaticObjectMethodA(clazz, mid, jargs);
                    if (res_obj) {
                        ctx->r[0] = reinterpret_cast<uintptr_t>(PineNative_ToArtObject(env, res_obj));
                    } else {
                        ctx->r[0] = 0;
                    }
                    break;
                }
            }
        } else {
            jobject thiz = getThisObject();
            switch (return_type) {
                case 'V':
                    env->CallNonvirtualVoidMethodA(thiz, clazz, mid, jargs);
                    break;
                case 'I': case 'S': case 'B': case 'C': {
                    jint r = env->CallNonvirtualIntMethodA(thiz, clazz, mid, jargs);
                    ctx->r[0] = static_cast<uint64_t>(r);
                    break;
                }
                case 'Z': {
                    jboolean r = env->CallNonvirtualBooleanMethodA(thiz, clazz, mid, jargs);
                    ctx->r[0] = r ? 1 : 0;
                    break;
                }
                case 'J': {
                    jlong r = env->CallNonvirtualLongMethodA(thiz, clazz, mid, jargs);
                    ctx->r[0] = static_cast<uint64_t>(r);
                    break;
                }
                case 'F': {
                    jfloat r = env->CallNonvirtualFloatMethodA(thiz, clazz, mid, jargs);
                    ctx->d[0] = static_cast<double>(r);
                    break;
                }
                case 'D': {
                    jdouble r = env->CallNonvirtualDoubleMethodA(thiz, clazz, mid, jargs);
                    ctx->d[0] = r;
                    break;
                }
                default: {
                    res_obj = env->CallNonvirtualObjectMethodA(thiz, clazz, mid, jargs);
                    if (res_obj) {
                        ctx->r[0] = reinterpret_cast<uintptr_t>(PineNative_ToArtObject(env, res_obj));
                    } else {
                        ctx->r[0] = 0;
                    }
                    break;
                }
            }
        }

        if (env->ExceptionCheck()) {
            LOGW("invokeOriginal: Exception occurred during original method execution");
        }

        // Restore bridge entry point
        target->SetEntryPointFromCompiledCode(cur_entry);

        original_invoked = true;
        return res_obj ? res_obj : getResult();
    } else {
        using ArtOriginCall = uint64_t (*)(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
        auto fn = reinterpret_cast<ArtOriginCall>(origin_entry);
        original_result_raw = fn(ctx->r[0], ctx->r[1], ctx->r[2], ctx->r[3], ctx->r[4], ctx->r[5], ctx->r[6], ctx->r[7]);
        ctx->r[0] = original_result_raw;
        original_invoked = true;
        return getResult();
    }
}

std::string CallFrame::toString() const {
    return getMethodToString();
}

std::string CallFrame::toValueString() const {
    std::stringstream ss;
    ss << "CallFrame { method=" << getMethodToString() << ", this=";
    if (is_static) {
        ss << "static";
    } else {
        jobject thiz_obj = getThisObject();
        char buf[32];
        snprintf(buf, sizeof(buf), "%p", thiz_obj);
        ss << (thiz_obj ? buf : "null");
    }
    ss << ", args=[";
    for (int i = 0; i < arg_count; ++i) {
        ss << "[" << i << "]='" << getArgString(i) << "'";
        if (i != arg_count - 1) ss << ", ";
    }
    ss << "], ret=>['" << getResultString() << "'] }";
    return ss.str();
}

namespace {

struct NativeBacktrace {
    char* buf;
    size_t cap;
    size_t len;
    int depth;
    int maxDepth;
};

_Unwind_Reason_Code NativeBacktraceCb(struct _Unwind_Context* ctx, void* arg) {
    auto* st = static_cast<NativeBacktrace*>(arg);
    if (st->depth >= st->maxDepth || st->len + 128 >= st->cap) {
        return _URC_END_OF_STACK;
    }
    uintptr_t pc = _Unwind_GetIP(ctx);
    if (pc) {
        Dl_info info;
        int n;
        if (dladdr(reinterpret_cast<void*>(pc), &info) && info.dli_sname) {
            n = snprintf(st->buf + st->len, st->cap - st->len, "  #%02d %p %s (%s)\n",
                         st->depth, reinterpret_cast<void*>(pc), info.dli_sname,
                         info.dli_fname ? info.dli_fname : "?");
        } else {
            n = snprintf(st->buf + st->len, st->cap - st->len, "  #%02d %p\n",
                         st->depth, reinterpret_cast<void*>(pc));
        }
        if (n > 0) st->len += static_cast<size_t>(n);
    }
    st->depth++;
    return _URC_NO_REASON;
}

} // namespace

std::string CallFrame::getJavaStackTrace() const {
    // A real Java stack trace cannot be obtained here: this runs inside a raw
    // hook trampoline where ART's managed stack has no valid frame, so both
    // env->FindClass() and new Throwable()/fillInStackTrace() walk the managed
    // stack (StackVisitor::WalkStack) and SIGSEGV. Emit a native backtrace
    // instead, which is safe and still shows the hook dispatch path.
    char buf[4096];
    buf[0] = '\0';
    NativeBacktrace st{buf, sizeof(buf), 0, 0, 32};
    _Unwind_Backtrace(NativeBacktraceCb, &st);
    return std::string(buf, st.len);
}

void CallFrame::printJavaStackTrace(const char* tag) const {
    std::string trace = getJavaStackTrace();
    if (!trace.empty()) {
        __android_log_print(ANDROID_LOG_INFO, tag ? tag : "PineStackTrace",
                            "=== Java StackTrace for %s ===\n%s",
                            getMethodToString().c_str(), trace.c_str());
    }
}

void CallFrame::showSmali(int max_instructions, const char* tag) const {
    if (target_method) {
        PI::showSmali(reinterpret_cast<pine::art::ArtMethod*>(target_method), max_instructions, tag);
    }
}

std::string CallFrame::dumpSmali(int max_instructions) const {
    if (target_method) {
        return PI::dumpSmali(reinterpret_cast<pine::art::ArtMethod*>(target_method), max_instructions);
    }
    return "[Pine] CallFrame::dumpSmali: target ArtMethod is null\n";
}

// --- MethodHookDispatcher & High-Level APIs ---

struct MethodHookEntry {
    std::string class_name;
    std::string method_name;
    std::string signature;
    bool is_static;
    int arg_count;
    std::vector<std::string> arg_types;
    char return_type;
    jclass clazz;
    jmethodID mid;
    HookCallback on_enter;
    HookCallback on_leave;
};

static std::mutex g_method_hook_mutex;
static std::unordered_map<void*, MethodHookEntry> g_method_hooks;
static thread_local std::unordered_set<void*> tl_active_hooks;

static void MethodHookDispatcher(void* target, PineNativeContext* ctx, void* origin) {
    if (tl_active_hooks.find(target) != tl_active_hooks.end()) {
        // Recursion detected on this thread for this method! Directly invoke origin/backup.
        if (origin) {
            using ArtOriginCall = uint64_t (*)(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
            auto fn = reinterpret_cast<ArtOriginCall>(origin);
            ctx->r[0] = fn(ctx->r[0], ctx->r[1], ctx->r[2], ctx->r[3], ctx->r[4], ctx->r[5], ctx->r[6], ctx->r[7]);
        }
        return;
    }

    MethodHookEntry entry;
    {
        std::lock_guard<std::mutex> lock(g_method_hook_mutex);
        auto it = g_method_hooks.find(target);
        if (it == g_method_hooks.end()) return;
        entry = it->second;
    }

    JNIEnv* env = GetCurrentJNIEnv();
    if (!env) {
        LOGE("MethodHookDispatcher: Failed to get current JNIEnv");
        return;
    }

    tl_active_hooks.insert(target);
    struct RecursionGuard {
        void* t;
        ~RecursionGuard() { tl_active_hooks.erase(t); }
    } guard{target};

    CallFrame frame(env, target, ctx, origin, entry.is_static, entry.method_name, entry.signature, entry.class_name);
    frame.arg_types = entry.arg_types;
    frame.arg_count = entry.arg_count;
    frame.return_type = entry.return_type;
    frame.clazz = entry.clazz;
    frame.mid = entry.mid;

    // 1. onEnter
    if (entry.on_enter) {
        entry.on_enter(env, frame);
    }

    // 2. invoke original if not already invoked by user in onEnter and not custom result
    if (!frame.has_custom_result && !frame.original_invoked && origin) {
        frame.callOriginal();
    }

    // 3. onLeave
    if (entry.on_leave) {
        entry.on_leave(env, frame);
    }
}


jclass Pine_FindClass(JNIEnv* env, const std::string& className, jobject classLoader) {
    if (!env || className.empty()) return nullptr;
    std::string slashName = className;
    std::replace(slashName.begin(), slashName.end(), '.', '/');

    jclass localClass = env->FindClass(slashName.c_str());
    if (localClass) return localClass;
    if (env->ExceptionCheck()) env->ExceptionClear();

    // Try classLoader if available
    if (classLoader) {
        std::string dotName = className;
        std::replace(dotName.begin(), dotName.end(), '/', '.');
        jclass clClass = env->GetObjectClass(classLoader);
        jmethodID loadClassMid = env->GetMethodID(clClass, "loadClass", "(Ljava/lang/String;)Ljava/lang/Class;");
        jstring jname = env->NewStringUTF(dotName.c_str());
        jclass found = reinterpret_cast<jclass>(env->CallObjectMethod(classLoader, loadClassMid, jname));
        env->DeleteLocalRef(jname);
        env->DeleteLocalRef(clClass);
        if (env->ExceptionCheck()) env->ExceptionClear();
        if (found) return found;
    }

    // Try ActivityThread.currentApplication().getClassLoader()
    jclass activityThreadClass = env->FindClass("android/app/ActivityThread");
    if (activityThreadClass) {
        jmethodID currentAppMid = env->GetStaticMethodID(activityThreadClass, "currentApplication", "()Landroid/app/Application;");
        if (currentAppMid) {
            jobject app = env->CallStaticObjectMethod(activityThreadClass, currentAppMid);
            if (app) {
                jclass appClass = env->GetObjectClass(app);
                jmethodID getClMid = env->GetMethodID(appClass, "getClassLoader", "()Ljava/lang/ClassLoader;");
                if (getClMid) {
                    jobject appCl = env->CallObjectMethod(app, getClMid);
                    if (appCl) {
                        std::string dotName = className;
                        std::replace(dotName.begin(), dotName.end(), '/', '.');
                        jclass clClass = env->GetObjectClass(appCl);
                        jmethodID loadClassMid = env->GetMethodID(clClass, "loadClass", "(Ljava/lang/String;)Ljava/lang/Class;");
                        jstring jname = env->NewStringUTF(dotName.c_str());
                        jclass found = reinterpret_cast<jclass>(env->CallObjectMethod(appCl, loadClassMid, jname));
                        env->DeleteLocalRef(jname);
                        env->DeleteLocalRef(clClass);
                        env->DeleteLocalRef(appCl);
                        env->DeleteLocalRef(appClass);
                        env->DeleteLocalRef(app);
                        env->DeleteLocalRef(activityThreadClass);
                        if (env->ExceptionCheck()) env->ExceptionClear();
                        if (found) return found;
                    }
                }
                env->DeleteLocalRef(app);
            }
        }
        env->DeleteLocalRef(activityThreadClass);
    }
    if (env->ExceptionCheck()) env->ExceptionClear();
    return nullptr;
}

bool PineInit(JavaVM* vm, [[maybe_unused]] void* reserved, JNIEnv* env) {
    if (vm) g_jvm = vm;
    if (!env && vm) {
        vm->GetEnv(reinterpret_cast<void**>(&env), JNI_VERSION_1_6);
    }
    return PineNative_Init(env);
}

bool registerMethodHookEx(JNIEnv* env, jclass clazz, const std::string& methodName, const std::string& methodSig,
                          const HookCallback& callback, void** out_backup) {
    if (!PineNative_IsInitialized()) {
        if (!PineNative_Init(env)) return false;
    }
    if (!env || !clazz) return false;

    // Instance method lookup
    jmethodID mid = env->GetMethodID(clazz, methodName.c_str(), methodSig.c_str());
    if (!mid) {
        if (env->ExceptionCheck()) env->ExceptionClear();
        LOGE("registerMethodHook: Instance method %s%s not found (for static methods, use registerStaticMethodHook)", methodName.c_str(), methodSig.c_str());
        return false;
    }

    art::ArtMethod* target = art::ArtMethod::Require(env, clazz, methodName.c_str(), methodSig.c_str(), false);
    if (!target) {
        LOGE("registerMethodHook: ArtMethod %s%s not found", methodName.c_str(), methodSig.c_str());
        return false;
    }

    MethodHookEntry entry;
    entry.method_name = methodName;
    entry.signature = methodSig;
    entry.class_name = ClassNameOf(env, clazz);
    entry.is_static = false;
    entry.arg_types = ParseJavaArgTypes(methodSig);
    entry.arg_count = static_cast<int>(entry.arg_types.size());
    entry.return_type = 'V';
    auto rpos = methodSig.rfind(')');
    if (rpos != std::string::npos && rpos + 1 < methodSig.length()) {
        entry.return_type = methodSig[rpos + 1];
    }
    entry.clazz = (jclass)env->NewGlobalRef(clazz);
    entry.mid = mid;
    entry.on_enter = callback;
    entry.on_leave = nullptr;

    {
        std::lock_guard<std::mutex> lock(g_method_hook_mutex);
        g_method_hooks[target] = entry;
    }

    return PineNative_Hook(env, clazz, methodName.c_str(), methodSig.c_str(), false, MethodHookDispatcher, out_backup);
}

bool registerMethodHook(JNIEnv* env, jclass clazz, const std::string& methodName, const std::string& methodSig,
                        const HookCallback& callback) {
    return registerMethodHookEx(env, clazz, methodName, methodSig, callback, nullptr);
}

bool registerMethodHook(const std::string& className, const std::string& methodName, const std::string& methodSig,
                        const HookCallback& callback) {
    JNIEnv* env = GetCurrentJNIEnv();
    if (!env) {
        LOGE("registerMethodHook: JNIEnv is null");
        return false;
    }
    jclass clazz = Pine_FindClass(env, className, nullptr);
    if (!clazz) {
        LOGE("registerMethodHook: Class %s not found", className.c_str());
        return false;
    }
    bool res = registerMethodHook(env, clazz, methodName, methodSig, callback);
    env->DeleteLocalRef(clazz);
    return res;
}

bool registerMethodHook(jclass clazz, const std::string& methodName, const std::string& methodSig,
                        const HookCallback& callback) {
    JNIEnv* env = GetCurrentJNIEnv();
    return registerMethodHook(env, clazz, methodName, methodSig, callback);
}

bool registerStaticMethodHookEx(JNIEnv* env, jclass clazz, const std::string& methodName, const std::string& methodSig,
                                const HookCallback& callback, void** out_backup) {
    if (!PineNative_IsInitialized()) {
        if (!PineNative_Init(env)) return false;
    }
    if (!env || !clazz) return false;

    // Static method lookup
    jmethodID mid = env->GetStaticMethodID(clazz, methodName.c_str(), methodSig.c_str());
    if (!mid) {
        if (env->ExceptionCheck()) env->ExceptionClear();
        LOGE("registerStaticMethodHook: Static method %s%s not found", methodName.c_str(), methodSig.c_str());
        return false;
    }

    art::ArtMethod* target = art::ArtMethod::Require(env, clazz, methodName.c_str(), methodSig.c_str(), true);
    if (!target) {
        LOGE("registerStaticMethodHook: ArtMethod %s%s not found", methodName.c_str(), methodSig.c_str());
        return false;
    }

    MethodHookEntry entry;
    entry.method_name = methodName;
    entry.signature = methodSig;
    entry.class_name = ClassNameOf(env, clazz);
    entry.is_static = true;
    entry.arg_types = ParseJavaArgTypes(methodSig);
    entry.arg_count = static_cast<int>(entry.arg_types.size());
    entry.return_type = 'V';
    auto rpos = methodSig.rfind(')');
    if (rpos != std::string::npos && rpos + 1 < methodSig.length()) {
        entry.return_type = methodSig[rpos + 1];
    }
    entry.clazz = (jclass)env->NewGlobalRef(clazz);
    entry.mid = mid;
    entry.on_enter = callback;
    entry.on_leave = nullptr;

    {
        std::lock_guard<std::mutex> lock(g_method_hook_mutex);
        g_method_hooks[target] = entry;
    }

    return PineNative_Hook(env, clazz, methodName.c_str(), methodSig.c_str(), true, MethodHookDispatcher, out_backup);
}

bool registerStaticMethodHook(JNIEnv* env, jclass clazz, const std::string& methodName, const std::string& methodSig,
                              const HookCallback& callback) {
    return registerStaticMethodHookEx(env, clazz, methodName, methodSig, callback, nullptr);
}

bool registerArtMethodHookDirect(JNIEnv* env, art::ArtMethod* target,
                                 const std::string& className,
                                 const std::string& methodName,
                                 const std::string& methodSig,
                                 bool isStatic, jclass clazz, jmethodID mid,
                                 const HookCallback& callback, void** out_backup) {
    if (!target) return false;
    if (!PineNative_IsInitialized()) {
        if (!PineNative_Init(env)) return false;
    }
    TrampolineInstaller* installer = TrampolineInstaller::GetDefault();
    if (!installer) {
        LOGE("registerArtMethodHookDirect: TrampolineInstaller is null");
        return false;
    }

    MethodHookEntry entry;
    entry.method_name = methodName.empty() ? "unknown" : methodName;
    entry.signature = methodSig;
    entry.class_name = className;
    entry.is_static = isStatic;
    entry.arg_types = ParseJavaArgTypes(methodSig);
    entry.arg_count = static_cast<int>(entry.arg_types.size());
    entry.return_type = 'V';
    auto rpos = methodSig.rfind(')');
    if (rpos != std::string::npos && rpos + 1 < methodSig.length()) {
        entry.return_type = methodSig[rpos + 1];
    }
    entry.clazz = (clazz && env) ? (jclass)env->NewGlobalRef(clazz) : nullptr;
    entry.mid = mid;
    entry.on_enter = callback;
    entry.on_leave = nullptr;

    {
        std::lock_guard<std::mutex> lock(g_method_hook_mutex);
        g_method_hooks[target] = entry;
    }

    void* backup = nullptr;
    if (!installer->IsReplacementOnly() && !installer->CannotSafeInlineHook(target)) {
        LOGI("registerArtMethodHookDirect: Installing native inline hook on %p (%s.%s)",
             target, className.c_str(), methodName.c_str());
        backup = installer->InstallNativeInlineTrampoline(target, reinterpret_cast<void*>(MethodHookDispatcher), false);
    }
    if (!backup) {
        LOGI("registerArtMethodHookDirect: Installing replacement trampoline on %p (%s.%s)",
             target, className.c_str(), methodName.c_str());
        backup = installer->InstallNativeReplacementTrampoline(target, reinterpret_cast<void*>(MethodHookDispatcher));
    }

    if (backup && out_backup) {
        *out_backup = backup;
    }
    return backup != nullptr;
}

bool unregisterMethodHook(art::ArtMethod* target) {
    if (!target) return false;
    std::lock_guard<std::mutex> lock(g_method_hook_mutex);
    auto it = g_method_hooks.find(target);
    if (it != g_method_hooks.end()) {
        if (it->second.clazz) {
            JNIEnv* env = GetCurrentJNIEnv();
            if (env) env->DeleteGlobalRef(it->second.clazz);
        }
        g_method_hooks.erase(it);
        LOGI("Pine::unregisterMethodHook: Removed hook registration for %p", target);
        return true;
    }
    return false;
}

bool registerStaticMethodHook(const std::string& className, const std::string& methodName, const std::string& methodSig,
                              const HookCallback& callback) {
    JNIEnv* env = GetCurrentJNIEnv();
    if (!env) {
        LOGE("registerStaticMethodHook: JNIEnv is null");
        return false;
    }
    jclass clazz = Pine_FindClass(env, className, nullptr);
    if (!clazz) {
        LOGE("registerStaticMethodHook: Class %s not found", className.c_str());
        return false;
    }
    bool res = registerStaticMethodHook(env, clazz, methodName, methodSig, callback);
    env->DeleteLocalRef(clazz);
    return res;
}

bool registerStaticMethodHook(jclass clazz, const std::string& methodName, const std::string& methodSig,
                              const HookCallback& callback) {
    JNIEnv* env = GetCurrentJNIEnv();
    return registerStaticMethodHook(env, clazz, methodName, methodSig, callback);
}

bool registerClassHook(JNIEnv* env, jclass clazz,
                       const HookCallback& onEnter,
                       const HookCallback& onLeave,
                       const std::vector<std::string>& ignoreMethods) {
    if (!PineNative_IsInitialized()) {
        if (!PineNative_Init(env)) return false;
    }
    if (!env || !clazz) return false;

    jclass classClazz = env->FindClass("java/lang/Class");
    if (!classClazz) return false;
    jmethodID getDeclaredMethodsMid = env->GetMethodID(classClazz, "getDeclaredMethods", "()[Ljava/lang/reflect/Method;");
    jobjectArray methodsArray = reinterpret_cast<jobjectArray>(env->CallObjectMethod(clazz, getDeclaredMethodsMid));
    env->DeleteLocalRef(classClazz);
    if (!methodsArray) return false;

    jclass methodClazz = env->FindClass("java/lang/reflect/Method");
    jmethodID getNameMid = env->GetMethodID(methodClazz, "getName", "()Ljava/lang/String;");
    jmethodID getModifiersMid = env->GetMethodID(methodClazz, "getModifiers", "()I");
    jclass modifierClazz = env->FindClass("java/lang/reflect/Modifier");
    jmethodID isAbstractMid = env->GetStaticMethodID(modifierClazz, "isAbstract", "(I)Z");

    jsize len = env->GetArrayLength(methodsArray);
    for (jsize i = 0; i < len; ++i) {
        jobject methodObj = env->GetObjectArrayElement(methodsArray, i);
        if (!methodObj) continue;

        jint mod = env->CallIntMethod(methodObj, getModifiersMid);
        if (env->CallStaticBooleanMethod(modifierClazz, isAbstractMid, mod)) {
            env->DeleteLocalRef(methodObj);
            continue;
        }

        jstring nameJStr = reinterpret_cast<jstring>(env->CallObjectMethod(methodObj, getNameMid));
        const char* c_name = env->GetStringUTFChars(nameJStr, nullptr);
        std::string mName = c_name ? c_name : "";
        if (c_name) env->ReleaseStringUTFChars(nameJStr, c_name);
        env->DeleteLocalRef(nameJStr);

        bool shouldIgnore = false;
        for (const auto& ign : ignoreMethods) {
            if (mName == ign) {
                shouldIgnore = true;
                break;
            }
        }
        if (shouldIgnore) {
            env->DeleteLocalRef(methodObj);
            continue;
        }

        art::ArtMethod* target = nullptr;
        if (Android::version >= Android::kR) {
            target = art::ArtMethod::GetArtMethodForR(env, methodObj);
        } else {
            jmethodID mid = env->FromReflectedMethod(methodObj);
            target = reinterpret_cast<art::ArtMethod*>(mid);
        }

        if (target) {
            MethodHookEntry entry;
            entry.method_name = mName;
            entry.signature = "";
            entry.is_static = (mod & 0x0008) != 0;
            entry.arg_count = 8;
            entry.on_enter = onEnter;
            entry.on_leave = onLeave;

            {
                std::lock_guard<std::mutex> lock(g_method_hook_mutex);
                g_method_hooks[target] = entry;
            }

            TrampolineInstaller* installer = TrampolineInstaller::GetDefault();
            if (!installer->IsReplacementOnly() && !installer->CannotSafeInlineHook(target)) {
                installer->InstallNativeInlineTrampoline(target, reinterpret_cast<void*>(MethodHookDispatcher), false);
            } else {
                installer->InstallNativeReplacementTrampoline(target, reinterpret_cast<void*>(MethodHookDispatcher));
            }
        }

        env->DeleteLocalRef(methodObj);
    }

    env->DeleteLocalRef(modifierClazz);
    env->DeleteLocalRef(methodClazz);
    env->DeleteLocalRef(methodsArray);
    return true;
}

bool registerClassHook(const std::string& className, jobject classLoader,
                       const HookCallback& onEnter,
                       const HookCallback& onLeave,
                       const std::vector<std::string>& ignoreMethods) {
    JNIEnv* env = GetCurrentJNIEnv();
    if (!env) return false;
    jclass clazz = Pine_FindClass(env, className, classLoader);
    if (!clazz) return false;
    bool res = registerClassHook(env, clazz, onEnter, onLeave, ignoreMethods);
    env->DeleteLocalRef(clazz);
    return res;
}

} // namespace pine_native
