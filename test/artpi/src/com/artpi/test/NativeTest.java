package com.artpi.test;

/** Native entry points implemented by libartpi_test.so (see test/cpp/artpi_test.cpp). */
public class NativeTest {

    /** PI::init(env) — must be called before anything else. */
    public static native boolean nativeInit();

    public static native boolean isInitialized();

    /** "valid=.. static=.. native=.. clazz=.. name=.. sig=.. art=.." */
    public static native String methodInfo(String cls, String name, String sig);

    /** Full Smali disassembly (maxInsn < 0 = all). */
    public static native String dumpSmali(String cls, String name, String sig, int maxInsn);

    // ---- hooking ----------------------------------------------------------
    public static native int hookRewriteReturn(String cls, String name, String sig, int value);

    public static native int hookCallOriginalPlus(String cls, String name, String sig, int delta);

    public static native int hookMutateArg0(String cls, String name, String sig, int newArg0, int extra);

    public static native int hookLongAdd(String cls, String name, String sig, long delta);

    public static native int hookBoolNot(String cls, String name, String sig);

    public static native int hookDoubleScale(String cls, String name, String sig, double factor);

    public static native int hookStringPrefix(String cls, String name, String sig, String prefix);

    public static native int hookInstanceMul(String cls, String name, String sig);

    public static native int traceOn(String cls, String name, String sig, String tag);

    public static native boolean unhook(int id);

    public static native int unhookAll();

    public static native int countHandles();

    // ---- interpreter ------------------------------------------------------
    public static native int interpretInt2(String cls, String name, String sig, int a, int b);

    /** Interpret `guarded` with Helper.check() Mocked to true. */
    public static native int interpretWithMockCheck(String cls, String name, String sig, int x);

    // ==== ArtPI.h public-API surface coverage ==============================
    public static native int[] apiResolveOverloads(Class<?> cls, java.lang.reflect.Method reflected,
                                                   String clsName, String name, String sig);

    public static native String apiMethodMeta(String cls, String name, String sig);

    public static native String apiHandleMeta(String cls, String name, String sig, int value);

    public static native int apiArgProxyInt(String cls, String name, String sig);

    public static native int apiArgProxyString(String cls, String name, String sig);

    public static native int apiFrameInterpret(String cls, String name, String sig, int mode, int a, int b);

    public static native int apiFrameTrace(String cls, String name, String sig, int preset);

    public static native int apiInterpretWithOptions(String cls, String name, String sig, int x, int maxInsn,
                                                     boolean stepIn);

    public static native String apiEventCounts(String cls, String name, String sig, int x);

    public static native String apiExceptionEvent(String cls, String name, String sig);

    public static native String apiInterpHelpers();

    public static native int apiFilterOptions(String cls, String name, String sig, int x);

    public static native String apiPiLevel(String cls, String name, String sig);

    public static native String apiXdl();

    public static native boolean apiNativeEngine();

    public static native boolean apiPineAlias();
}
