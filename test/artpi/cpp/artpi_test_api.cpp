//
// artpi_test_api.cpp - ArtPI.h public-API surface coverage
//
// Native methods backing com.artpi.test.ApiCoverage. Covers the API not touched
// by the functional suite: all resolve() overloads, Method/HookHandle getters,
// ArgProxy + ArgsAccessor, frame-level invokeInterpreted/invokeTrace/
// invokeInterpretedWith(opts), InvokeVerdict::StepIn, Callbacks
// (onInsn/onInvoke/onInvokePost/onException), Options/FilterOptions, InvokeEvent
// OO helpers, Interp free helpers, xDL, Native engine, Pine alias.
//
#include "artpi_test_common.h"

#include <cstdio>
#include <cstring>

using namespace artpi_test;

extern "C" {

// ---- resolve(): all overloads ---------------------------------------------
JNIEXPORT jintArray JNICALL
Java_com_artpi_test_NativeTest_apiResolveOverloads(JNIEnv* env, jclass, jclass clz, jobject reflectedMethod,
                                                   jstring clsName, jstring name, jstring sig) {
    std::string cls = ToSlash(JStr(env, clsName));
    std::string nm = JStr(env, name);
    std::string sg = JStr(env, sig);

    jint r[6] = {0, 0, 0, 0, 0, 0};
    r[0] = PI::resolve(env, clz, nm, sg).isValid() ? 1 : 0;      // (env, jclass, ...)
    r[1] = PI::resolve(env, cls, nm, sg).isValid() ? 1 : 0;      // (env, className, ...)
    r[2] = PI::resolve(clz, nm, sg).isValid() ? 1 : 0;           // (jclass, ...)
    r[3] = PI::resolve(cls, nm, sg).isValid() ? 1 : 0;           // (className, ...)
    r[4] = PI::resolve(env, reflectedMethod).isValid() ? 1 : 0;  // (env, reflected Method)
    PI::Method m = PI::resolve(env, clz, nm, sg);
    r[5] = PI::resolve(m.getArtMethod()).isValid() ? 1 : 0;      // (ArtMethod*)

    jintArray arr = env->NewIntArray(6);
    env->SetIntArrayRegion(arr, 0, 6, r);
    return arr;
}

// ---- Method information getters -------------------------------------------
JNIEXPORT jstring JNICALL
Java_com_artpi_test_NativeTest_apiMethodMeta(JNIEnv* env, jclass, jstring c, jstring n, jstring s) {
    PI::Method m = Resolve(env, c, n, s);
    char buf[512];
    snprintf(buf, sizeof(buf),
             "valid=%d bool=%d name=%s sig=%s cls=%s static=%d native=%d compiled=%d id=%d decl=%d flags=0x%x "
             "toString=%s dumpCode=%zu dumpNative=%zu dumpSmali=%zu",
             m.isValid() ? 1 : 0, m ? 1 : 0, m.getName().c_str(), m.getSignature().c_str(),
             m.getDeclaringClassName().c_str(), m.isStatic() ? 1 : 0, m.isNative() ? 1 : 0,
             m.isCompiled() ? 1 : 0, m.getMethodId() ? 1 : 0, m.getDeclaringClass() ? 1 : 0,
             m.getAccessFlags(), m.toString().c_str(),
             m.dumpCode().size(), m.dumpNative().size(), m.dumpSmali().size());
    return env->NewStringUTF(buf);
}

// ---- HookHandle getters / lifecycle ---------------------------------------
JNIEXPORT jstring JNICALL
Java_com_artpi_test_NativeTest_apiHandleMeta(JNIEnv* env, jclass, jstring c, jstring n, jstring s, jint value) {
    PI::Method m = Resolve(env, c, n, s);
    const int v = value;
    PI::HookHandle h = m.hook([v](JNIEnv*, PI::CallFrame& f) { f.setResult((int) v); });
    char buf[320];
    snprintf(buf, sizeof(buf), "valid=%d bool=%d hooked=%d backup=%d art=%d",
             h.isValid() ? 1 : 0, h ? 1 : 0, h.isHooked() ? 1 : 0,
             h.getBackup() ? 1 : 0, h.getArtMethod() ? 1 : 0);
    std::string before(buf);
    h.unhook();
    snprintf(buf, sizeof(buf), "|afterValid=%d afterHooked=%d", h.isValid() ? 1 : 0, h.isHooked() ? 1 : 0);
    return env->NewStringUTF((before + buf).c_str());
}

// ---- ArgProxy / ArgsAccessor / CallFrame meta (inside a hook) -------------
JNIEXPORT jint JNICALL
Java_com_artpi_test_NativeTest_apiArgProxyInt(JNIEnv* env, jclass, jstring c, jstring n, jstring s) {
    PI::Method m = Resolve(env, c, n, s);
    if (!m.isValid()) return -1;
    PI::HookHandle h = m.hook([](JNIEnv*, PI::CallFrame& f) {
        int a = (int) f[0];                       // ArgProxy -> int
        int b = f[1].as<int>();                   // ArgProxy::as<int>
        int a2 = f.args[1];                       // ArgsAccessor[] -> ArgProxy -> int
        bool isInst = f.args[0].isThis();
        int idx0 = f[0].getIndex();
        bool obj0 = f[0].isObject();
        f[0] = 7;                                 // ArgProxy::operator=(int)
        uint64_t raw1 = f.getArgRaw(1);           // CallFrame::getArgRaw
        f.setArgRaw(1, 9);                        // CallFrame::setArgRaw
        if (a == 2 && b == 3 && a2 == 3 && idx0 == 0 && !obj0 && !isInst && raw1 == 3) {
            f.setResult((int) (10000 + b * 100));
        } else {
            f.setResult((int) -7);
        }
        f.resetResult();                          // exercise resetResult
        f.setResult((int) f.getArgRaw(1));        // now args[1] == 9
    });
    return Store(std::move(h));
}

JNIEXPORT jint JNICALL
Java_com_artpi_test_NativeTest_apiArgProxyString(JNIEnv* env, jclass, jstring c, jstring n, jstring s) {
    PI::Method m = Resolve(env, c, n, s);
    if (!m.isValid()) return -1;
    PI::HookHandle h = m.hook([](JNIEnv*, PI::CallFrame& f) {
        std::string a0 = f[0];                    // ArgProxy -> std::string
        std::string a0b = f.args[0].as_string();
        jobject o = f.getArg(0);
        f[0] = std::string("Z");                  // ArgProxy::operator=(std::string)
        f.setResult(std::string("R:") + a0 + "/" + a0b + (o ? "" : "!"));
    });
    return Store(std::move(h));
}

// ---- frame-level invokeInterpreted / custom args --------------------------
JNIEXPORT jint JNICALL
Java_com_artpi_test_NativeTest_apiFrameInterpret(JNIEnv* env, jclass, jstring c, jstring n, jstring s,
                                                 jint mode, jint a, jint b) {
    PI::Method m = Resolve(env, c, n, s);
    if (!m.isValid()) return -1;
    const int md = mode, aa = a, bb = b;
    PI::HookHandle h = m.hook([md, aa, bb](JNIEnv*, PI::CallFrame& f) {
        if (md == 0) {
            f.setResult(f.invokeInterpreted<int>());                    // replay with current args
        } else {
            f.setResult(f.invokeInterpreted<int>(aa, bb));              // replay with custom args
        }
    });
    return Store(std::move(h));
}

// ---- frame-level invokeTrace(preset) --------------------------------------
JNIEXPORT jint JNICALL
Java_com_artpi_test_NativeTest_apiFrameTrace(JNIEnv* env, jclass, jstring c, jstring n, jstring s, jint preset) {
    PI::Method m = Resolve(env, c, n, s);
    if (!m.isValid()) return -1;
    const int p = preset;
    PI::HookHandle h = m.hook([p](JNIEnv*, PI::CallFrame& f) {
        auto pre = (PI::Trace::TracePreset) p;
        f.setResult(f.invokeTrace<int>(pre));
    });
    return Store(std::move(h));
}

// ---- invokeInterpretedWith(cbs, Options) + StepIn -------------------------
JNIEXPORT jint JNICALL
Java_com_artpi_test_NativeTest_apiInterpretWithOptions(JNIEnv* env, jclass, jstring c, jstring n, jstring s,
                                                       jint x, jint maxInsn, jboolean stepIn) {
    PI::Method m = Resolve(env, c, n, s);
    if (!m.isValid()) return -1;

    std::string shorty;
    if (!PI::Interp::shortyFromSignature(m.getSignature(), shorty)) return -2;

    jvalue args[1];
    std::memset(args, 0, sizeof(args));
    args[0].i = x;

    PI::Interp::Callbacks cbs;
    cbs.onInvoke = [stepIn](const PI::Interp::InvokeEvent& e, jvalue* mockRet) -> PI::Interp::InvokeVerdict {
        (void) mockRet;
        if (e.methodName == "check") {
            return stepIn ? PI::Interp::InvokeVerdict::StepIn     // recurse into Java bytecode
                          : PI::Interp::InvokeVerdict::JniDirect;
        }
        return PI::Interp::InvokeVerdict::JniDirect;
    };
    PI::Interp::Options opts;
    opts.max_instructions = maxInsn;
    opts.step_in_enabled = stepIn;
    opts.max_depth = 4;

    PI::Interp::RunResult r = PI::Interp::runMethodInternal(
            env, m.getArtMethod(), nullptr, args, shorty.c_str(), &cbs, &opts, nullptr, 0, "guarded");
    if (r.status != PI::Interp::RunResult::OK) return -(100 + (int) r.status);
    return r.value.i;
}

// ---- Callbacks: onInsn / onInvokePost / onException / InvokeEvent OO ------
JNIEXPORT jstring JNICALL
Java_com_artpi_test_NativeTest_apiEventCounts(JNIEnv* env, jclass, jstring c, jstring n, jstring s, jint x) {
    PI::Method m = Resolve(env, c, n, s);
    if (!m.isValid()) return env->NewStringUTF("resolve=0");

    std::string shorty;
    if (!PI::Interp::shortyFromSignature(m.getSignature(), shorty)) return env->NewStringUTF("shorty=0");

    jvalue args[1];
    std::memset(args, 0, sizeof(args));
    args[0].i = x;

    int insn = 0, pre = 0, post = 0, exc = 0;
    char fmt[256] = {0};
    PI::Interp::Callbacks cbs;
    cbs.onInsn = [&insn](const PI::Interp::InsnEvent& e) {
        (void) e;
        insn++;
        return true;
    };
    cbs.onInvoke = [&pre, &fmt](const PI::Interp::InvokeEvent& e, jvalue*) -> PI::Interp::InvokeVerdict {
        pre++;
        if (pre == 1) {
            std::string mn = e.formatMethod();
            std::string ar = e.formatArgs();
            uint64_t raw = e.getArgRaw(0);
            std::string s0 = e.getArgString(0);
            snprintf(fmt, sizeof(fmt), "first=%s args=%s raw=%llu s0=%s cls=%s native=%d argc=%d",
                     mn.c_str(), ar.c_str(), (unsigned long long) raw, s0.c_str(),
                     e.className.c_str(), (int) e.isNative, e.argc);
        }
        return PI::Interp::InvokeVerdict::JniDirect;
    };
    cbs.onInvokePost = [&post](const PI::Interp::InvokeEvent& e, const jvalue* ret, bool hasExc) {
        (void) e;
        (void) ret;
        (void) hasExc;
        post++;
    };
    cbs.onException = [&exc](const PI::Interp::ExceptionEvent& e) {
        (void) e;
        exc++;
    };

    PI::Interp::RunResult r = PI::Interp::runMethodInternal(
            env, m.getArtMethod(), nullptr, args, shorty.c_str(), &cbs, nullptr, nullptr, 0, "guarded");

    char buf[768];
    snprintf(buf, sizeof(buf), "status=%d insn=%d pre=%d post=%d exc=%d | %s",
             (int) r.status, insn, pre, post, exc, fmt);
    return env->NewStringUTF(buf);
}

// ---- onException on a throwing method -------------------------------------
JNIEXPORT jstring JNICALL
Java_com_artpi_test_NativeTest_apiExceptionEvent(JNIEnv* env, jclass, jstring c, jstring n, jstring s) {
    PI::Method m = Resolve(env, c, n, s);
    if (!m.isValid()) return env->NewStringUTF("resolve=0");

    std::string shorty;
    if (!PI::Interp::shortyFromSignature(m.getSignature(), shorty)) return env->NewStringUTF("shorty=0");

    int exc = 0;
    int catchPc = -999;
    PI::Interp::Callbacks cbs;
    cbs.onException = [&exc, &catchPc](const PI::Interp::ExceptionEvent& e) {
        exc++;
        catchPc = e.catchPc;
    };

    PI::Interp::RunResult r = PI::Interp::runMethodInternal(
            env, m.getArtMethod(), nullptr, nullptr, shorty.c_str(), &cbs, nullptr, nullptr, 0, "boom");
    if (env->ExceptionCheck()) env->ExceptionClear();

    char buf[160];
    snprintf(buf, sizeof(buf), "status=%d exc=%d catchPc=%d pend=%d",
             (int) r.status, exc, catchPc, (int) r.exceptionPending);
    return env->NewStringUTF(buf);
}

// ---- Interp free helpers --------------------------------------------------
JNIEXPORT jstring JNICALL
Java_com_artpi_test_NativeTest_apiInterpHelpers(JNIEnv* env, jclass) {
    bool sysJava = PI::Interp::isSystemDescriptor("Ljava/lang/String;");
    bool sysAndroid = PI::Interp::isSystemDescriptor("Landroid/view/View;");
    bool sysApp = PI::Interp::isSystemDescriptor("Lcom/artpi/test/Target;");

    jvalue args[2];
    std::memset(args, 0, sizeof(args));
    args[0].i = 1;
    args[1].i = 2;
    std::string fa = PI::Interp::formatInvokeArgs(env, "(II)I", args, 2);

    jvalue ret;
    std::memset(&ret, 0, sizeof(ret));
    ret.i = 42;
    std::string fr = PI::Interp::formatReturnValue(env, "(II)I", ret);

    bool interpretingNull = PI::Interp::isInterpretingOnCurrentThread(nullptr);

    PI::Interp::setTraceEnabled(true);
    bool trOn = PI::Interp::isTraceEnabled();
    PI::Interp::setTraceEnabled(false);
    bool trOff = PI::Interp::isTraceEnabled();

    char buf[256];
    snprintf(buf, sizeof(buf), "sysJava=%d sysAndroid=%d sysApp=%d args=%s ret=%s interpNull=%d trOn=%d trOff=%d",
             (int) sysJava, (int) sysAndroid, (int) sysApp, fa.c_str(), fr.c_str(),
             (int) interpretingNull, (int) trOn, (int) trOff);
    return env->NewStringUTF(buf);
}

// ---- FilterOptions --------------------------------------------------------
JNIEXPORT jint JNICALL
Java_com_artpi_test_NativeTest_apiFilterOptions(JNIEnv* env, jclass, jstring c, jstring n, jstring s, jint x) {
    PI::Method m = Resolve(env, c, n, s);
    if (!m.isValid()) return -1;
    std::string shorty;
    if (!PI::Interp::shortyFromSignature(m.getSignature(), shorty)) return -2;
    jvalue args[1];
    std::memset(args, 0, sizeof(args));
    args[0].i = x;

    PI::Interp::FilterOptions filter;
    filter.filter_system_classes = true;
    filter.whitelist_pkgs.push_back("Lcom/artpi/");
    filter.blacklist_pkgs.push_back("Lcom/blocked/");

    PI::Interp::RunResult r = PI::Interp::runMethodInternal(
            env, m.getArtMethod(), nullptr, args, shorty.c_str(), nullptr, nullptr, &filter, 0, "guarded");
    if (r.status != PI::Interp::RunResult::OK) return -(100 + (int) r.status);
    return r.value.i;
}

// ---- PI-level dump / resolveNativeMethod ----------------------------------
JNIEXPORT jstring JNICALL
Java_com_artpi_test_NativeTest_apiPiLevel(JNIEnv* env, jclass, jstring c, jstring n, jstring s) {
    PI::Method m = Resolve(env, c, n, s);
    if (!m.isValid()) return env->NewStringUTF("resolve=0");
    ArtMethod* am = m.getArtMethod();
    size_t s1 = PI::dumpSmali(am).size();
    size_t s2 = PI::dumpCode(am).size();
    size_t s3 = PI::dumpNative(am).size();
    void* nat = PI::resolveNativeMethod(am, env);
    char buf[160];
    snprintf(buf, sizeof(buf), "dumpSmali=%zu dumpCode=%zu dumpNative=%zu nativePtr=%d",
             s1, s2, s3, nat ? 1 : 0);
    return env->NewStringUTF(buf);
}

// ---- xDL dynamic linker ---------------------------------------------------
JNIEXPORT jstring JNICALL
Java_com_artpi_test_NativeTest_apiXdl(JNIEnv* env, jclass) {
    void* h = xdl_open("libc.so", XDL_DEFAULT);
    size_t sz = 0;
    void* sym = h ? xdl_sym(h, "malloc", &sz) : nullptr;
    void* dsym = h ? xdl_dsym(h, "malloc", nullptr) : nullptr;

    xdl_info_t info;
    std::memset(&info, 0, sizeof(info));
    void* cache = nullptr;
    int addrOk = 0;
    if (sym) {
        addrOk = (xdl_addr(sym, &info, &cache) != 0) ? 1 : 0;
    }
    if (cache) xdl_addr_clean(&cache);

    char buf[256];
    snprintf(buf, sizeof(buf), "open=%d sym=%d dsym=%d addr=%d name=%s",
             h ? 1 : 0, sym ? 1 : 0, dsym ? 1 : 0, addrOk, info.dli_sname ? info.dli_sname : "?");
    if (h) xdl_close(h);
    return env->NewStringUTF(buf);
}

// ---- Native engine + Pine alias -------------------------------------------
JNIEXPORT jboolean JNICALL
Java_com_artpi_test_NativeTest_apiNativeEngine(JNIEnv* env, jclass) {
    PI::Native::initNativeEngine(env);
    return PI::Native::isNativeEngineInitialized() ? JNI_TRUE : JNI_FALSE;
}

JNIEXPORT jboolean JNICALL
Java_com_artpi_test_NativeTest_apiPineAlias(JNIEnv* env, jclass) {
    return Pine::PineInit(nullptr, nullptr, env) ? JNI_TRUE : JNI_FALSE;
}

} // extern "C"
