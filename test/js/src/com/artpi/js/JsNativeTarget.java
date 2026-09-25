package com.artpi.js;

/**
 * JNI target for unified-trace tests: {@code nadd} is statically registered
 * (implemented in test/js/cpp/js_test.cpp) and acts as the JNI boundary that
 * FULL_STACK_NATIVE should step into via QBDI.
 */
public class JsNativeTarget {

    public static native int nadd(int a, int b);
}
