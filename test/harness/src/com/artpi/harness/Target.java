package com.artpi.harness;

/** Java targets exercised by the harness ticker loop. Hook/trace these. */
public class Target {

    /** Simple binary op (hook arg/return editing). */
    public static int add(int a, int b) {
        return a + b;
    }

    /** String op (object arg / return). */
    public static String greet(String name) {
        return "hello, " + name;
    }

    /** JNI boundary crossing (for traceunified: Java -> native via QBDI). */
    public static int callNative(int a, int b) {
        return Native.nativeAdd(a, b);
    }

    /**
     * Call chain with two levels, so call-tree / StepIn tracing has something
     * to recurse into. Driven by the ticker with a changing argument.
     */
    public static int step(int i) {
        int a = innerA(i);
        int b = innerB(i + 1);
        return a + b;
    }

    private static int innerA(int x) {
        return x * 2;
    }

    private static int innerB(int x) {
        return x + 3;
    }
}
