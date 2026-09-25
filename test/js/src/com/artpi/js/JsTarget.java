package com.artpi.js;

/** Target class referenced from JS (findclass/findmethod/dumpsmali bindings). */
public class JsTarget {

    public static int add(int a, int b) {
        return a + b;
    }

    public static String greet(String name) {
        return "hi " + name;
    }

    public int mul(int a, int b) {
        return a * b;
    }

    /** Value holder with public fields, for JS JRef field read/write tests. */
    public static class Box {
        public int value;
        public String label;

        public Box(int v, String l) {
            this.value = v;
            this.label = l;
        }

        public int doubled() {
            return value * 2;
        }

        public int addTo(int x) {
            return value + x;
        }
    }

    /** Consumes a Box; JS can read/modify b.value / b.label via JRef. */
    public static int useBox(Box b) {
        return b.value;
    }

    /** Returns an int[]; JS can index the JRef-wrapped result. */
    public static int[] makeInts(int n) {
        int[] a = new int[n];
        for (int i = 0; i < n; i++) a[i] = i * i;
        return a;
    }

    /** Consumes an int[]; JS can read/write elements via JRef. */
    public static int sumInts(int[] a) {
        int s = 0;
        for (int v : a) s += v;
        return s;
    }

    /** Calls a JNI native method — the JNI boundary for unified-trace tests. */
    public static int callNative(int a, int b) {
        return JsNativeTarget.nadd(a, b);
    }

    /** Calls a system method (java.lang.String.length) — for excludeSystem trace tests. */
    public static int strLen(String s) {
        return s.length();
    }
}
