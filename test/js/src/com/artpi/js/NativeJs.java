package com.artpi.js;

/** Native driver implemented by libartpi_js_test.so (see js/cpp/js_test.cpp). */
public class NativeJs {

    /** dlopen libartpi_agent.so and initialise its QuickJS runtime. */
    public static native boolean loadAgent();

    /** Evaluate a JS snippet, returning the result (or "[Exception] ..."). */
    public static native String eval(String script);

    /** Drain the agent's captured log ring (hook entry / arg / result lines). */
    public static native String takeLog();

    /** Address of a known 256-byte native buffer (for Memory.hexdump tests). */
    public static native long bufferAddress();

    /** Byte value at buffer()[i], for cross-checking hexdump. */
    public static native long bufferByte(int i);

    /** Calls the exported C function artpi_test_native_add (nhook target). */
    public static native int callNativeAdd(int a, int b);

    /** Address of artpi_test_native_add (for nhook-by-address). */
    public static native long nativeAddAddress();
}
