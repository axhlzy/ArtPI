//
// artpi_test_core.cpp - ArtPI functional tests (hook / interpreter / sandbox)
//
// Native methods backing com.artpi.test.Main. One JNI entry per capability so
// the Java runner can assert behavior. Built with -fno-exceptions -fno-rtti.
//
#include "artpi_test_common.h"

#include <cstdio>
#include <cstring>

using namespace artpi_test;

extern "C" {

// ---- init ------------------------------------------------------------------
JNIEXPORT jboolean JNICALL
Java_com_artpi_test_NativeTest_nativeInit(JNIEnv* env, jclass) {
    bool ok = PI::init(env);
    LOGI("PI::init -> %d", (int) ok);
    return ok ? JNI_TRUE : JNI_FALSE;
}

JNIEXPORT jboolean JNICALL
Java_com_artpi_test_NativeTest_isInitialized(JNIEnv*, jclass) {
    return PI::isInitialized() ? JNI_TRUE : JNI_FALSE;
}

// ---- resolve / method info -------------------------------------------------
JNIEXPORT jstring JNICALL
Java_com_artpi_test_NativeTest_methodInfo(JNIEnv* env, jclass, jstring c, jstring n, jstring s) {
    PI::Method m = Resolve(env, c, n, s);
    char buf[320];
    snprintf(buf, sizeof(buf), "valid=%d static=%d native=%d clazz=%s name=%s sig=%s art=%p",
             m.isValid() ? 1 : 0, m.isStatic() ? 1 : 0, m.isNative() ? 1 : 0,
             m.getDeclaringClassName().c_str(), m.getName().c_str(),
             m.getSignature().c_str(), (void*) m.getArtMethod());
    return env->NewStringUTF(buf);
}

JNIEXPORT jstring JNICALL
Java_com_artpi_test_NativeTest_dumpSmali(JNIEnv* env, jclass, jstring c, jstring n, jstring s, jint maxInsn) {
    PI::Method m = Resolve(env, c, n, s);
    if (!m.isValid()) return env->NewStringUTF("[!] resolve failed");
    return env->NewStringUTF(m.dumpSmali(maxInsn).c_str());
}

// ---- hook: replace return value entirely (int) -----------------------------
JNIEXPORT jint JNICALL
Java_com_artpi_test_NativeTest_hookRewriteReturn(JNIEnv* env, jclass, jstring c, jstring n, jstring s, jint value) {
    PI::Method m = Resolve(env, c, n, s);
    if (!m.isValid()) return -1;
    const int v = value;
    PI::HookHandle h = m.hook([v](JNIEnv*, PI::CallFrame& frame) {
        frame.setResult((int) v);
    });
    int id = Store(std::move(h));
    LOGI("hookRewriteReturn -> id=%d", id);
    return id;
}

// ---- hook: call original, then add delta -----------------------------------
JNIEXPORT jint JNICALL
Java_com_artpi_test_NativeTest_hookCallOriginalPlus(JNIEnv* env, jclass, jstring c, jstring n, jstring s, jint delta) {
    PI::Method m = Resolve(env, c, n, s);
    if (!m.isValid()) return -1;
    const int d = delta;
    PI::HookHandle h = m.hook([d](JNIEnv*, PI::CallFrame& frame) {
        int orig = frame.invokeOriginal<int>();
        frame.setResult((int) (orig + d));
    });
    return Store(std::move(h));
}

// ---- hook: mutate arg0 then call original ----------------------------------
JNIEXPORT jint JNICALL
Java_com_artpi_test_NativeTest_hookMutateArg0(JNIEnv* env, jclass, jstring c, jstring n, jstring s,
                                              jint newArg0, jint extra) {
    PI::Method m = Resolve(env, c, n, s);
    if (!m.isValid()) return -1;
    const int a0 = newArg0;
    const int ex = extra;
    PI::HookHandle h = m.hook([a0, ex](JNIEnv*, PI::CallFrame& frame) {
        if (frame.getArgCount() < 2) { frame.setResult((int) -999); return; }
        int arg1 = frame.getArg<int>(1);
        int orig = frame.invokeOriginal<int>((int) a0, arg1);
        frame.setResult((int) (orig + ex));
    });
    return Store(std::move(h));
}

// ---- hook: long arithmetic --------------------------------------------------
JNIEXPORT jint JNICALL
Java_com_artpi_test_NativeTest_hookLongAdd(JNIEnv* env, jclass, jstring c, jstring n, jstring s, jlong delta) {
    PI::Method m = Resolve(env, c, n, s);
    if (!m.isValid()) return -1;
    const jlong d = delta;
    PI::HookHandle h = m.hook([d](JNIEnv*, PI::CallFrame& frame) {
        jlong orig = frame.invokeOriginal<jlong>();
        frame.setResult((jlong) (orig + d));
    });
    return Store(std::move(h));
}

// ---- hook: boolean negation -------------------------------------------------
JNIEXPORT jint JNICALL
Java_com_artpi_test_NativeTest_hookBoolNot(JNIEnv* env, jclass, jstring c, jstring n, jstring s) {
    PI::Method m = Resolve(env, c, n, s);
    if (!m.isValid()) return -1;
    PI::HookHandle h = m.hook([](JNIEnv*, PI::CallFrame& frame) {
        jboolean orig = frame.invokeOriginal<jboolean>();
        frame.setResult((bool) (orig == JNI_FALSE));
    });
    return Store(std::move(h));
}

// ---- hook: double scaling ---------------------------------------------------
JNIEXPORT jint JNICALL
Java_com_artpi_test_NativeTest_hookDoubleScale(JNIEnv* env, jclass, jstring c, jstring n, jstring s, jdouble factor) {
    PI::Method m = Resolve(env, c, n, s);
    if (!m.isValid()) return -1;
    const double f = factor;
    PI::HookHandle h = m.hook([f](JNIEnv*, PI::CallFrame& frame) {
        double orig = frame.invokeOriginal<double>();
        frame.setResult((double) (orig * f));
    });
    return Store(std::move(h));
}

// ---- hook: string return (arg read + rewrite) ------------------------------
JNIEXPORT jint JNICALL
Java_com_artpi_test_NativeTest_hookStringPrefix(JNIEnv* env, jclass, jstring c, jstring n, jstring s, jstring prefix) {
    PI::Method m = Resolve(env, c, n, s);
    if (!m.isValid()) return -1;
    const std::string pre = JStr(env, prefix);
    PI::HookHandle h = m.hook([pre](JNIEnv*, PI::CallFrame& frame) {
        std::string a0 = frame.getArgString(0);
        frame.setResult(pre + a0);
    });
    return Store(std::move(h));
}

// ---- hook: instance method, verify `this` present ---------------------------
JNIEXPORT jint JNICALL
Java_com_artpi_test_NativeTest_hookInstanceMul(JNIEnv* env, jclass, jstring c, jstring n, jstring s) {
    PI::Method m = Resolve(env, c, n, s);
    if (!m.isValid()) return -1;
    PI::HookHandle h = m.hook([](JNIEnv*, PI::CallFrame& frame) {
        bool hasThis = (frame.getThisObject() != nullptr);
        int orig = frame.invokeOriginal<int>();
        frame.setResult((int) (hasThis ? orig : -12345));
    });
    return Store(std::move(h));
}

// ---- hook lifecycle ---------------------------------------------------------
JNIEXPORT jboolean JNICALL
Java_com_artpi_test_NativeTest_unhook(JNIEnv*, jclass, jint id) {
    return Unhook(id) ? JNI_TRUE : JNI_FALSE;
}

JNIEXPORT jint JNICALL
Java_com_artpi_test_NativeTest_unhookAll(JNIEnv*, jclass) {
    return UnhookAll();
}

JNIEXPORT jint JNICALL
Java_com_artpi_test_NativeTest_countHandles(JNIEnv*, jclass) {
    return CountHandles();
}

// ---- interpreter: replay method body on nmmvm -------------------------------
JNIEXPORT jint JNICALL
Java_com_artpi_test_NativeTest_interpretInt2(JNIEnv* env, jclass, jstring c, jstring n, jstring s,
                                             jint a, jint b) {
    PI::Method m = Resolve(env, c, n, s);
    if (!m.isValid()) return -1;

    std::string shorty;
    if (!PI::Interp::shortyFromSignature(m.getSignature(), shorty)) return -2;

    jvalue args[2];
    std::memset(args, 0, sizeof(args));
    args[0].i = a;
    args[1].i = b;

    PI::Interp::RunResult r = PI::Interp::runMethod(env, m.getArtMethod(), nullptr, args, shorty.c_str());
    LOGI("interpret %s status=%d exceptionPending=%d", m.getName().c_str(), (int) r.status,
         (int) r.exceptionPending);
    if (r.status != PI::Interp::RunResult::OK) return -(100 + (int) r.status);
    return r.value.i;
}

// ---- sandbox: run `guarded` on the interpreter with Helper.check Mocked -----
JNIEXPORT jint JNICALL
Java_com_artpi_test_NativeTest_interpretWithMockCheck(JNIEnv* env, jclass, jstring c, jstring n,
                                                      jstring s, jint x) {
    PI::Method m = Resolve(env, c, n, s);
    if (!m.isValid()) return -1;

    std::string shorty;
    if (!PI::Interp::shortyFromSignature(m.getSignature(), shorty)) return -2;

    jvalue args[1];
    std::memset(args, 0, sizeof(args));
    args[0].i = x;

    PI::Interp::Callbacks cbs;
    cbs.onInvoke = [](const PI::Interp::InvokeEvent& e, jvalue* mockRet) -> PI::Interp::InvokeVerdict {
        if (e.methodName == "check") {
            return e.mock(mockRet, true);
        }
        return PI::Interp::InvokeVerdict::JniDirect;
    };

    PI::Interp::RunResult r = PI::Interp::runMethodInternal(
            env, m.getArtMethod(), nullptr, args, shorty.c_str(), &cbs, nullptr, nullptr, 0, "guarded");
    if (r.status != PI::Interp::RunResult::OK) return -(100 + (int) r.status);
    return r.value.i;
}

// ---- trace: one-line method tracing ----------------------------------------
JNIEXPORT jint JNICALL
Java_com_artpi_test_NativeTest_traceOn(JNIEnv* env, jclass, jstring c, jstring n, jstring s, jstring tag) {
    PI::Method m = Resolve(env, c, n, s);
    if (!m.isValid()) return -1;
    std::string t = JStr(env, tag);
    PI::HookHandle h = m.trace(t.c_str());
    return Store(std::move(h));
}

} // extern "C"
