//
// agent_invoke.cpp - Dual-path Java method invocation (ART/JNI vs nmmvm)
//

#include "agent_invoke.h"

#include "agent_java_ref.h"
#include "../../include/ArtPI.h"
#include "art/art_method.h"
#include "sandbox/pi_interp_executor.h"
#include "sandbox/pi_interp_tracer.h"

#include <string>
#include <vector>

namespace artpi { namespace agent {

namespace {

// "I" -> "int", "Ljava/lang/String;" -> "java.lang.String" (for
// JsValueToJavaObject, which boxes primitives by type name).
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
    return desc;  // arrays keep the descriptor form (JRef path)
}

bool SplitSignature(const std::string& sig,
                    std::vector<std::string>* params,
                    std::string* ret) {
    params->clear();
    if (sig.size() < 3 || sig[0] != '(') return false;
    size_t i = 1;
    while (i < sig.size() && sig[i] != ')') {
        size_t start = i;
        while (i < sig.size() && sig[i] == '[') ++i;
        if (i >= sig.size()) return false;
        if (sig[i] == 'L') {
            size_t semi = sig.find(';', i);
            if (semi == std::string::npos) return false;
            i = semi + 1;
        } else {
            ++i;
        }
        params->push_back(sig.substr(start, i - start));
    }
    if (i >= sig.size() || sig[i] != ')') return false;
    ++i;
    if (i >= sig.size()) return false;
    size_t rstart = i;
    while (i < sig.size() && sig[i] == '[') ++i;
    if (i >= sig.size()) return false;
    if (sig[i] == 'L') {
        size_t semi = sig.find(';', i);
        if (semi == std::string::npos) return false;
        i = semi + 1;
    } else {
        ++i;
    }
    if (i != sig.size()) return false;
    *ret = sig.substr(rstart);
    return true;
}

JSValue JvalueToJs(JSContext* ctx, JNIEnv* env, char retChar, const jvalue& rv) {
    switch (retChar) {
        case 'V': return JS_UNDEFINED;
        case 'Z': return JS_NewBool(ctx, rv.z != 0);
        case 'B': return JS_NewInt32(ctx, rv.b);
        case 'S': return JS_NewInt32(ctx, rv.s);
        case 'C': return JS_NewInt32(ctx, rv.c);
        case 'I': return JS_NewInt32(ctx, rv.i);
        case 'J': return JS_NewBigInt64(ctx, rv.j);
        case 'F': return JS_NewFloat64(ctx, static_cast<double>(rv.f));
        case 'D': return JS_NewFloat64(ctx, rv.d);
        case 'L':
        case '[': {
            JSValue out = JavaObjectToJsValue(ctx, env, rv.l);
            if (rv.l != nullptr) env->DeleteLocalRef(rv.l);
            return out;
        }
        default:
            return JS_UNDEFINED;
    }
}

struct ArgPack {
    std::vector<jvalue> values;
    std::vector<jobject> locals;   // object args we created (delete after use)

    ~ArgPack() = default;

    void Release(JNIEnv* env) {
        if (env == nullptr) return;
        for (jobject o : locals) env->DeleteLocalRef(o);
        locals.clear();
    }
};

bool PackArgs(JNIEnv* env, JSContext* ctx,
              const std::vector<std::string>& params,
              JSValueConst* argv, int argc, int firstArg,
              ArgPack* pack, std::string* error) {
    pack->values.assign(params.size(), jvalue{});
    for (size_t i = 0; i < params.size(); ++i) {
        if (firstArg + static_cast<int>(i) >= argc) {
            *error = "missing argument #" + std::to_string(i) + " (" + params[i] + ")";
            return false;
        }
        JSValueConst v = argv[firstArg + i];
        switch (params[i].empty() ? 'I' : params[i][0]) {
            case 'Z': pack->values[i].z = JS_ToBool(ctx, v) ? JNI_TRUE : JNI_FALSE; break;
            case 'B': { int32_t t = 0; JS_ToInt32(ctx, &t, v); pack->values[i].b = (jbyte) t; } break;
            case 'S': { int32_t t = 0; JS_ToInt32(ctx, &t, v); pack->values[i].s = (jshort) t; } break;
            case 'C': { int32_t t = 0; JS_ToInt32(ctx, &t, v); pack->values[i].c = (jchar) t; } break;
            case 'I': { int32_t t = 0; JS_ToInt32(ctx, &t, v); pack->values[i].i = t; } break;
            case 'J': {
                int64_t t = 0;
                if (JS_IsBigInt(ctx, v)) JS_ToBigInt64(ctx, &t, v);
                else JS_ToInt64(ctx, &t, v);
                pack->values[i].j = t;
            } break;
            case 'F': { double t = 0; JS_ToFloat64(ctx, &t, v); pack->values[i].f = (jfloat) t; } break;
            case 'D': { double t = 0; JS_ToFloat64(ctx, &t, v); pack->values[i].d = t; } break;
            default: {
                jobject o = JsValueToJavaObject(env, ctx, v, DescriptorToTypeName(params[i]));
                if (o == nullptr && !JS_IsNull(v) && !JS_IsUndefined(v)) {
                    *error = "cannot convert argument #" + std::to_string(i) + " to " +
                             params[i] + " (arrays / non-String objects must be passed as JRef)";
                    return false;
                }
                pack->values[i].l = o;
                if (o != nullptr) pack->locals.push_back(o);
            } break;
        }
    }
    return true;
}

// ART/JNI invocation. `receiver` is ignored for static methods.
bool InvokeJni(JNIEnv* env, jmethodID mid, jclass clazz, bool isStatic,
               jobject receiver, std::vector<jvalue>& args, char retChar,
               jvalue* out, std::string* error) {
    if (mid == nullptr) {
        *error = "jmethodID unavailable";
        return false;
    }
    if (!isStatic && receiver == nullptr) {
        *error = "instance method requires a receiver (use .bind(obj))";
        return false;
    }
    jvalue* a = args.empty() ? nullptr : args.data();

    if (isStatic) {
        jclass c = clazz;
        if (c == nullptr) {
            *error = "declaring class unavailable";
            return false;
        }
        switch (retChar) {
            case 'V': env->CallStaticVoidMethodA(c, mid, a); break;
            case 'Z': out->z = env->CallStaticBooleanMethodA(c, mid, a); break;
            case 'B': out->b = env->CallStaticByteMethodA(c, mid, a); break;
            case 'S': out->s = env->CallStaticShortMethodA(c, mid, a); break;
            case 'C': out->c = env->CallStaticCharMethodA(c, mid, a); break;
            case 'I': out->i = env->CallStaticIntMethodA(c, mid, a); break;
            case 'J': out->j = env->CallStaticLongMethodA(c, mid, a); break;
            case 'F': out->f = env->CallStaticFloatMethodA(c, mid, a); break;
            case 'D': out->d = env->CallStaticDoubleMethodA(c, mid, a); break;
            default:  out->l = env->CallStaticObjectMethodA(c, mid, a); break;
        }
    } else {
        switch (retChar) {
            case 'V': env->CallVoidMethodA(receiver, mid, a); break;
            case 'Z': out->z = env->CallBooleanMethodA(receiver, mid, a); break;
            case 'B': out->b = env->CallByteMethodA(receiver, mid, a); break;
            case 'S': out->s = env->CallShortMethodA(receiver, mid, a); break;
            case 'C': out->c = env->CallCharMethodA(receiver, mid, a); break;
            case 'I': out->i = env->CallIntMethodA(receiver, mid, a); break;
            case 'J': out->j = env->CallLongMethodA(receiver, mid, a); break;
            case 'F': out->f = env->CallFloatMethodA(receiver, mid, a); break;
            case 'D': out->d = env->CallDoubleMethodA(receiver, mid, a); break;
            default:  out->l = env->CallObjectMethodA(receiver, mid, a); break;
        }
    }

    if (env->ExceptionCheck()) {
        LogAndClearJavaException(env, "invoke(jni)");
        *error = "Java exception thrown by the method";
        return false;
    }
    return true;
}

const char* RunStatusName(PI::Interp::RunResult::Status s) {
    switch (s) {
        case PI::Interp::RunResult::OK: return "OK";
        case PI::Interp::RunResult::NO_CODE: return "NO_CODE (native/abstract)";
        case PI::Interp::RunResult::RESOLVE_FAIL: return "RESOLVE_FAIL";
        case PI::Interp::RunResult::UNSUPPORTED: return "UNSUPPORTED opcode";
        case PI::Interp::RunResult::PACK_FAIL: return "PACK_FAIL";
        case PI::Interp::RunResult::ABORTED: return "ABORTED";
        default: return "ERROR";
    }
}

}  // namespace

// __native_invoke(artMethod, mode, receiverOrNull, ...args)
static JSValue JsInvoke(JSContext* ctx, JSValueConst /*this_val*/,
                        int argc, JSValueConst* argv) {
    if (argc < 2) {
        return JS_ThrowTypeError(ctx,
            "invoke(artMethod, 'jni'|'interp', receiverOrNull, ...args)");
    }
    JNIEnv* env = GetEnv();
    if (env == nullptr) return JS_ThrowTypeError(ctx, "invoke: no JNIEnv");

    const int64_t artPtr = ParsePtr(ctx, argv[0]);
    if (artPtr == 0) return JS_ThrowTypeError(ctx, "invoke: invalid ArtMethod pointer");

    const char* modeC = JS_ToCString(ctx, argv[1]);
    std::string mode = modeC ? modeC : "";
    if (modeC) JS_FreeCString(ctx, modeC);

    jobject receiver = nullptr;
    if (argc >= 3 && !JS_IsNull(argv[2]) && !JS_IsUndefined(argv[2])) {
        int h = ExtractJRefHandle(ctx, argv[2]);
        receiver = h >= 0 ? GetJRef(h) : nullptr;
        if (receiver == nullptr) {
            return JS_ThrowTypeError(ctx, "invoke: receiver must be a JRef/null");
        }
    }

    auto* art = reinterpret_cast<ArtMethod*>(artPtr);
    PI::Method meta = PI::resolve(art);
    if (!meta.isValid()) return JS_ThrowTypeError(ctx, "invoke: cannot resolve ArtMethod");

    const std::string sig = meta.getSignature();
    std::vector<std::string> params;
    std::string ret;
    if (!SplitSignature(sig, &params, &ret)) {
        return JS_ThrowTypeError(ctx, "invoke: unsupported signature %s", sig.c_str());
    }
    if (argc - 3 < static_cast<int>(params.size())) {
        return JS_ThrowTypeError(ctx, "invoke: %s needs %zu arg(s), got %d",
                                 sig.c_str(), params.size(), argc - 3);
    }

    ArgPack pack;
    std::string error;
    if (!PackArgs(env, ctx, params, argv, argc, 3, &pack, &error)) {
        pack.Release(env);
        return JS_ThrowTypeError(ctx, "invoke: %s", error.c_str());
    }

    const char retChar = ret.empty() ? 'V' : ret[0];

    if (mode == "jni" || mode == "native" || mode == "art") {
        PI::Method jm = PI::resolve(env, meta.getDeclaringClassName(),
                                    meta.getName(), sig);
        if (!jm.isValid()) {
            pack.Release(env);
            return JS_ThrowTypeError(ctx, "invoke: cannot resolve %s.%s%s",
                                     meta.getDeclaringClassName().c_str(),
                                     meta.getName().c_str(), sig.c_str());
        }
        jvalue rv{};
        bool ok = InvokeJni(env, jm.getMethodId(), jm.getDeclaringClass(),
                            jm.isStatic(), receiver, pack.values, retChar,
                            &rv, &error);
        pack.Release(env);
        if (!ok) return JS_ThrowTypeError(ctx, "invoke(jni): %s", error.c_str());
        return JvalueToJs(ctx, env, retChar, rv);
    }

    if (mode == "interp" || mode == "nmmvm" || mode == "vm") {
        if (meta.isNative()) {
            pack.Release(env);
            return JS_ThrowTypeError(ctx,
                "invoke(interp): %s.%s is native (no bytecode); use 'jni'",
                meta.getDeclaringClassName().c_str(), meta.getName().c_str());
        }
        if (!meta.isStatic() && receiver == nullptr) {
            pack.Release(env);
            return JS_ThrowTypeError(ctx,
                "invoke(interp): instance method requires a receiver (use .bind(obj))");
        }
        std::string shorty;
        if (!PI::Interp::shortyFromSignature(sig, shorty)) {
            pack.Release(env);
            return JS_ThrowTypeError(ctx, "invoke(interp): bad signature %s", sig.c_str());
        }

        PI::Interp::RunResult res = PI::Interp::runMethod(
            env, art, meta.isStatic() ? nullptr : receiver,
            pack.values.empty() ? nullptr : pack.values.data(), shorty.c_str());
        pack.Release(env);

        if (res.status != PI::Interp::RunResult::OK) {
            return JS_ThrowTypeError(ctx, "invoke(interp): %s failed: %s",
                                     meta.getName().c_str(), RunStatusName(res.status));
        }
        if (res.exceptionPending) {
            if (env->ExceptionCheck()) {
                LogAndClearJavaException(env, "invoke(interp)");
            }
            return JS_ThrowTypeError(ctx, "invoke(interp): Java exception from %s",
                                     meta.getName().c_str());
        }

        jvalue rv{};
        if (res.isVoid) return JS_UNDEFINED;
        if (res.isObject) rv.l = res.objectResult;
        else rv = res.value;
        return JvalueToJs(ctx, env, retChar, rv);
    }

    pack.Release(env);
    return JS_ThrowTypeError(ctx,
        "invoke: unknown mode '%s' (use 'jni' or 'interp')", mode.c_str());
}

void RegisterJavaInvokeApis(JSContext* ctx, JSValue global, JSValue java) {
    JS_SetPropertyStr(ctx, java, "invoke",
                      JS_NewCFunction(ctx, JsInvoke, "invoke", 3));
    JS_SetPropertyStr(ctx, global, "__native_invoke",
                      JS_NewCFunction(ctx, JsInvoke, "__native_invoke", 3));
}

}} // namespace artpi::agent
