package com.artpi.test;

/**
 * ArtPI functional test runner.
 *
 * Launched by app_process:
 *   CLASSPATH=/data/local/tmp/artpi_test/classes.dex \
 *   ARTPI_TEST_LIB=/data/local/tmp/artpi_test/libartpi_test.so \
 *   app_process /system/bin com.artpi.test.Main
 *
 * Exit code: 0 = all passed, 1 = failures.
 */
public class Main {

    private static int passed = 0;
    private static int failed = 0;
    private static int skipped = 0;
    private static final java.util.List<String> failedNames = new java.util.ArrayList<String>();
    private static final java.util.List<String> skippedNames = new java.util.ArrayList<String>();
    private static final boolean STRICT = isSet("ARTPI_STRICT");

    public static void main(String[] args) {
        banner("ArtPI Functional Test (app_process)");
        System.out.println("[Java] PID      = " + pid());
        System.out.println("[Java] vm.name  = " + System.getProperty("java.vm.name"));
        System.out.println("[Java] os.arch  = " + System.getProperty("os.arch"));
        System.out.flush();

        String lib = System.getenv("ARTPI_TEST_LIB");
        if (lib == null || lib.isEmpty()) {
            lib = "/data/local/tmp/artpi_test/libartpi_test.so";
        }

        if (isSet("ARTPI_WAIT")) {
            System.out.print("[Java] >>> Press Enter to start ... ");
            System.out.flush();
            try { System.in.read(); } catch (Throwable ignored) { }
            System.out.println();
        }

        try {
            System.load(lib);
            System.out.println("[Java] System.load(" + lib + ") -> OK");
        } catch (Throwable t) {
            System.out.println("[Java] System.load FAILED: " + t);
            t.printStackTrace();
            System.exit(2);
            return;
        }

        // ---- 1. init ------------------------------------------------------
        expectTrue("init", NativeTest.nativeInit());
        expectTrue("isInitialized", NativeTest.isInitialized());

        // ---- 2. resolve / method info -------------------------------------
        String infoStatic = NativeTest.methodInfo("com.artpi.test.Target", "add", "(II)I");
        System.out.println("[Java] methodInfo(add) = " + infoStatic);
        check("resolve.static", infoStatic.contains("valid=1") && infoStatic.contains("static=1"));

        String infoInst = NativeTest.methodInfo("com.artpi.test.Target", "mul", "(II)I");
        System.out.println("[Java] methodInfo(mul) = " + infoInst);
        check("resolve.instance", infoInst.contains("valid=1") && infoInst.contains("static=0"));

        String infoBad = NativeTest.methodInfo("com.artpi.test.Target", "nope", "(II)I");
        check("resolve.missing", infoBad.contains("valid=0"));

        // ---- 3. dumpSmali --------------------------------------------------
        String smali = NativeTest.dumpSmali("com.artpi.test.Target", "fibonacci", "(I)I", -1);
        int smaliLines = smali.split("\n").length;
        System.out.println("[Java] dumpSmali(fibonacci) lines = " + smaliLines);
        check("dumpSmali.nonEmpty", smaliLines > 3);
        check("dumpSmali.hasOpcode", smali.contains("add-int") || smali.contains("if-") || smali.contains("aget"));

        // ---- 4. hook: rewrite return, then unhook --------------------------
        int hRew = NativeTest.hookRewriteReturn("com.artpi.test.Target", "add", "(II)I", 777);
        expectTrue("hook.rewrite.installed", hRew > 0);
        expectEq("hook.rewrite.active", Target.add(2, 3), 777);
        expectTrue("hook.rewrite.unhook", NativeTest.unhook(hRew));
        expectEq("hook.rewrite.restored", Target.add(2, 3), 5);

        // ---- 5. hook: call original + delta --------------------------------
        int hPlus = NativeTest.hookCallOriginalPlus("com.artpi.test.Target", "add", "(II)I", 100);
        expectTrue("hook.delta.installed", hPlus > 0);
        expectEq("hook.delta.active", Target.add(2, 3), 105);
        NativeTest.unhook(hPlus);
        expectEq("hook.delta.restored", Target.add(2, 3), 5);

        // ---- 6. hook: mutate arg0 ------------------------------------------
        int hMut = NativeTest.hookMutateArg0("com.artpi.test.Target", "add", "(II)I", 10, 1);
        expectTrue("hook.mutate.installed", hMut > 0);
        expectEq("hook.mutate.active", Target.add(2, 3), 14);   // (10+3)+1
        NativeTest.unhook(hMut);
        expectEq("hook.mutate.restored", Target.add(2, 3), 5);

        // ---- 7. hook: long --------------------------------------------------
        int hL = NativeTest.hookLongAdd("com.artpi.test.Target", "ladd", "(JJ)J", 1000L);
        expectTrue("hook.long.installed", hL > 0);
        expectEq("hook.long.active", Target.ladd(1L, 2L), 1003L);
        NativeTest.unhook(hL);
        expectEq("hook.long.restored", Target.ladd(1L, 2L), 3L);

        // ---- 8. hook: boolean ----------------------------------------------
        int hB = NativeTest.hookBoolNot("com.artpi.test.Target", "isPositive", "(I)Z");
        expectTrue("hook.bool.installed", hB > 0);
        expectEq("hook.bool.true2false", Target.isPositive(5), false);
        expectEq("hook.bool.false2true", Target.isPositive(-1), true);
        NativeTest.unhook(hB);
        expectEq("hook.bool.restored", Target.isPositive(5), true);

        // ---- 9. hook: double -------------------------------------------------
        int hD = NativeTest.hookDoubleScale("com.artpi.test.Target", "half", "(D)D", 4.0);
        expectTrue("hook.double.installed", hD > 0);
        expectEq("hook.double.active", Target.half(10.0), 20.0);
        NativeTest.unhook(hD);
        expectEq("hook.double.restored", Target.half(10.0), 5.0);

        // ---- 10. hook: String return ----------------------------------------
        int hS = NativeTest.hookStringPrefix("com.artpi.test.Target", "greet",
                "(Ljava/lang/String;)Ljava/lang/String;", "HOOK:");
        expectTrue("hook.string.installed", hS > 0);
        expectEq("hook.string.active", Target.greet("bob"), "HOOK:bob");
        NativeTest.unhook(hS);
        expectEq("hook.string.restored", Target.greet("bob"), "hello bob");

        // ---- 11. hook: instance method (this) -------------------------------
        int hI = NativeTest.hookInstanceMul("com.artpi.test.Target", "mul", "(II)I");
        expectTrue("hook.instance.installed", hI > 0);
        expectEq("hook.instance.active", new Target().mul(6, 7), 42);
        NativeTest.unhook(hI);
        expectEq("hook.instance.restored", new Target().mul(6, 7), 42);

        // ---- 12. interpreter: replay add() on nmmvm -------------------------
        expectEq("interpret.add", NativeTest.interpretInt2(
                "com.artpi.test.Target", "add", "(II)I", 20, 22), 42);
        expectEq("interpret.fibonacci", NativeTest.interpretInt2(
                "com.artpi.test.Target", "fibonacci", "(I)I", 10, 0), 55);

        // ---- 13. interpreter + sandbox Mock (independent of the hook engine)
        // `guarded(-5)`: original -> -1 (check false); with Helper.check() Mocked -> 100
        expectEq("sandbox.mock", NativeTest.interpretWithMockCheck(
                "com.artpi.test.Target", "guarded", "(I)I", -5), 100);
        expectEq("sandbox.noMock", NativeTest.interpretInt2(
                "com.artpi.test.Target", "guarded", "(I)I", -5, 0), -1);

        // ---- 13b. inline-hook path must intercept too -----------------------
        int hG = NativeTest.hookRewriteReturn("com.artpi.test.Target", "guarded", "(I)I", 555);
        expectTrue("inlineHook.installed", hG > 0);
        expectEq("inlineHook.intercept", Target.guarded(-5), 555);
        NativeTest.unhook(hG);
        expectEq("inlineHook.restored", Target.guarded(-5), -1);

        // ---- 14. trace (install + fire + unhook) ----------------------------
        int hT = NativeTest.traceOn("com.artpi.test.Target", "add", "(II)I", "ArtPI_Test");
        expectTrue("trace.installed", hT > 0);
        int traced = Target.add(4, 5);
        expectEq("trace.math", traced, 9);
        NativeTest.unhook(hT);

        // ---- 15. bulk unhook -------------------------------------------------
        NativeTest.hookRewriteReturn("com.artpi.test.Target", "add", "(II)I", 1);
        NativeTest.hookRewriteReturn("com.artpi.test.Target", "ladd", "(JJ)J", 2);
        expectEq("handles.count", NativeTest.countHandles(), 2);
        expectEq("unhookAll.count", NativeTest.unhookAll(), 2);
        expectEq("handles.cleared", NativeTest.countHandles(), 0);
        expectEq("post.bulkAdd", Target.add(2, 3), 5);

        // ---- 16. ArtPI.h API-surface coverage (separate runner) -------------
        int[] api = ApiCoverage.run();
        passed += api[0];
        failed += api[1];
        if (api[1] > 0) failedNames.addAll(ApiCoverage.failures());

        String summary = "Result: " + passed + " passed, " + failed + " failed, " + skipped + " skipped";
        banner(summary);
        if (failed > 0) {
            System.out.println("[Java] FAILED CASES:");
            for (Object n : failedNames) System.out.println("[Java]   - " + n);
        }
        if (skipped > 0) {
            System.out.println("[Java] KNOWN-ISSUE CASES (skipped; set ARTPI_STRICT=1 to fail):");
            for (Object n : skippedNames) System.out.println("[Java]   - " + n);
        }
        System.out.flush();
        System.exit(failed == 0 ? 0 : 1);
    }

    // ------------------------------------------------------------------ utils

    private static void banner(String s) {
        System.out.println("==========================================================");
        System.out.println("[Java] " + s);
        System.out.println("==========================================================");
    }

    private static boolean isSet(String k) {
        String v = System.getenv(k);
        return v != null && !v.isEmpty() && !"0".equals(v);
    }

    private static void check(String name, boolean ok) {
        if (ok) {
            passed++;
            System.out.println("[Java]   PASS  " + name);
        } else {
            failed++;
            failedNames.add(name);
            System.out.println("[Java]   FAIL  " + name);
        }
        System.out.flush();
    }

    private static void expectTrue(String name, boolean v) {
        check(name, v);
    }

    /** A check whose failure is a documented framework limitation.
     *  Counts as SKIP unless ARTPI_STRICT=1 (then it counts as FAIL). */
    private static void known(String name, boolean ok, String note) {
        if (ok) {
            passed++;
            System.out.println("[Java]   PASS  " + name);
        } else if (STRICT) {
            failed++;
            failedNames.add(name);
            System.out.println("[Java]   FAIL  " + name + "  (" + note + ")");
        } else {
            skipped++;
            skippedNames.add(name);
            System.out.println("[Java]   SKIP  " + name + "  (known: " + note + ")");
        }
        System.out.flush();
    }

    private static void expectEq(String name, long actual, long expected) {
        boolean ok = (actual == expected);
        System.out.println("[Java]         " + name + ": " + actual + (ok ? " (ok)" : " != " + expected));
        check(name, ok);
    }

    private static void expectEq(String name, boolean actual, boolean expected) {
        boolean ok = (actual == expected);
        System.out.println("[Java]         " + name + ": " + actual + (ok ? " (ok)" : " != " + expected));
        check(name, ok);
    }

    private static void expectEq(String name, double actual, double expected) {
        boolean ok = (Math.abs(actual - expected) < 1e-9);
        System.out.println("[Java]         " + name + ": " + actual + (ok ? " (ok)" : " != " + expected));
        check(name, ok);
    }

    private static void expectEq(String name, Object actual, Object expected) {
        boolean ok = (actual == null) ? (expected == null) : actual.equals(expected);
        System.out.println("[Java]         " + name + ": " + actual + (ok ? " (ok)" : " != " + expected));
        check(name, ok);
    }

    private static String pid() {
        try {
            String p = new java.io.File("/proc/self").getCanonicalPath();
            int i = p.lastIndexOf('/');
            return (i >= 0) ? p.substring(i + 1) : p;
        } catch (Throwable t) {
            return "unknown";
        }
    }
}
