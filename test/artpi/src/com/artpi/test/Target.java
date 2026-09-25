package com.artpi.test;

/**
 * Simple target with a few arithmetic / string / instance methods for hooking.
 * Kept small so the Smali dump stays readable.
 */
public class Target {

    // ---- static, primitive ------------------------------------------------
    public static int add(int a, int b) {
        return a + b;
    }

    public static long ladd(long a, long b) {
        return a + b;
    }

    public static boolean isPositive(int x) {
        return x > 0;
    }

    public static double half(double x) {
        return x / 2.0;
    }

    // ---- static, object ---------------------------------------------------
    public static String greet(String name) {
        return "hello " + name;
    }

    // ---- static, calls a nested method (sandbox Mock target) --------------
    public static int guarded(int x) {
        if (Helper.check(x)) {
            return 100;
        }
        return -1;
    }

    // ---- a slightly bigger body so dumpSmali has something to show --------
    public static int fibonacci(int n) {
        if (n < 0) {
            return -1;
        }
        int[] f = new int[n + 1];
        f[0] = 0;
        if (n > 0) {
            f[1] = 1;
        }
        for (int i = 2; i <= n; i++) {
            f[i] = f[i - 1] + f[i - 2];
        }
        return f[n];
    }

    // ---- instance methods -------------------------------------------------
    public int mul(int a, int b) {
        return a * b;
    }

    public String tag(String s) {
        return "T:" + s;
    }

    // ---- extra targets for API-surface tests -----------------------------
    /** Calls a nested static method (StepIn / invoke-event coverage). */
    public static int nested(int x) {
        return Helper.twice(x);
    }

    /** Throws, for onException coverage. */
    public static void boom() {
        throw new IllegalStateException("boom");
    }
}
