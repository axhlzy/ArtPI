package com.artpi.test;

/**
 * ArtPI.h public-API surface coverage. Invoked from {@link Main} after the
 * functional tests; contributes its own pass/fail counts.
 *
 * Covers the API not exercised by Main: all resolve() overloads, Method /
 * HookHandle getters, ArgProxy + ArgsAccessor, frame-level invokeInterpreted /
 * invokeTrace / invokeInterpretedWith(opts), InvokeVerdict.StepIn, Callbacks
 * (onInsn/onInvoke/onInvokePost/onException), Options / FilterOptions,
 * InvokeEvent OO helpers, Interp free helpers, xDL, Native engine, Pine alias.
 */
public class ApiCoverage {

    private static int pass = 0;
    private static int fail = 0;
    private static final java.util.List<String> failures = new java.util.ArrayList<String>();

    private static final String C = "com.artpi.test.Target";

    public static int[] run() {
        banner("ArtPI.h API-surface coverage");

        resolveOverloads();
        methodMeta();
        handleMeta();
        argProxyInt();
        argProxyString();
        frameInterpret();
        frameTrace();
        interpretWithOptions();
        eventCounts();
        exceptionEvent();
        interpHelpers();
        filterOptions();
        piLevel();
        xdl();
        nativeEngine();
        pineAlias();

        return new int[]{pass, fail};
    }

    // ------------------------------------------------------------------ cases

    private static void resolveOverloads() {
        try {
            java.lang.reflect.Method rm = Target.class.getDeclaredMethod("add", int.class, int.class);
            int[] r = NativeTest.apiResolveOverloads(Target.class, rm, C, "add", "(II)I");
            String s = java.util.Arrays.toString(r);
            System.out.println("[Java][API] resolveOverloads = " + s);
            // (env,jclass) (env,className) (jclass) (className) (reflected) (ArtMethod*)
            boolean ok = r.length == 6 && r[0] == 1 && r[1] == 1 && r[2] == 1 && r[3] == 1 && r[4] == 1 && r[5] == 1;
            check("resolve.overloads.all", ok, s);
        } catch (Throwable t) {
            check("resolve.overloads.all", false, String.valueOf(t));
        }
    }

    private static void methodMeta() {
        String m = NativeTest.apiMethodMeta(C, "add", "(II)I");
        System.out.println("[Java][API] methodMeta = " + m);
        boolean ok = m.contains("valid=1") && m.contains("bool=1") && m.contains("static=1")
                && m.contains("native=0") && m.contains("id=1") && m.contains("decl=1")
                && !m.contains("flags=0x0") && m.contains("toString=com.artpi.test.Target.add(II)I")
                && !m.contains("dumpSmali=0");
        check("method.meta", ok, m);

        String n = NativeTest.apiMethodMeta(C, "boom", "()V");
        System.out.println("[Java][API] methodMeta(boom) = " + n);
        check("method.meta.void", n.contains("valid=1") && n.contains("static=1"), n);
    }

    private static void handleMeta() {
        String m = NativeTest.apiHandleMeta(C, "add", "(II)I", 4242);
        System.out.println("[Java][API] handleMeta = " + m);
        // isValid() means "handle was created OK" (target+backup bound); it stays
        // true after unhook(). isHooked() reflects the live state and must clear.
        boolean ok = m.contains("valid=1") && m.contains("bool=1") && m.contains("hooked=1")
                && m.contains("backup=1") && m.contains("art=1")
                && m.contains("afterValid=1") && m.contains("afterHooked=0");
        check("handle.meta", ok, m);
        // hook was unhooked internally -> original behavior restored
        check("handle.meta.restored", Target.add(2, 3) == 5, "add(2,3)=" + Target.add(2, 3));
    }

    private static void argProxyInt() {
        int id = NativeTest.apiArgProxyInt(C, "add", "(II)I");
        check("argproxy.int.installed", id > 0, "id=" + id);
        if (id <= 0) return;
        // hook: validates ArgProxy/ArgsAccessor reads, then sets args[1]=9 -> returns 9
        int v = Target.add(2, 3);
        check("argproxy.int.readWrite", v == 9, "add(2,3)=" + v + " want 9");
        NativeTest.unhook(id);
        check("argproxy.int.restored", Target.add(2, 3) == 5, "add(2,3)=" + Target.add(2, 3));
    }

    private static void argProxyString() {
        int id = NativeTest.apiArgProxyString(C, "greet", "(Ljava/lang/String;)Ljava/lang/String;");
        check("argproxy.string.installed", id > 0, "id=" + id);
        if (id <= 0) return;
        String v = Target.greet("b");
        // "R:" + a0 + "/" + a0b + (obj != null ? "" : "!")  -> "R:b/b"
        check("argproxy.string.readWrite", "R:b/b".equals(v), "greet(b)=" + v);
        NativeTest.unhook(id);
        check("argproxy.string.restored", "hello b".equals(Target.greet("b")), Target.greet("b"));
    }

    private static void frameInterpret() {
        // mode 0: replay with current args
        int id0 = NativeTest.apiFrameInterpret(C, "add", "(II)I", 0, 0, 0);
        check("frame.interpret.installed", id0 > 0, "id=" + id0);
        if (id0 > 0) {
            check("frame.interpret.currentArgs", Target.add(2, 3) == 5, "add(2,3)=" + Target.add(2, 3));
            NativeTest.unhook(id0);
        }
        // mode 1: replay with custom args (100, 200) -> 300
        int id1 = NativeTest.apiFrameInterpret(C, "add", "(II)I", 1, 100, 200);
        if (id1 > 0) {
            check("frame.interpret.customArgs", Target.add(2, 3) == 300, "add(2,3)=" + Target.add(2, 3));
            NativeTest.unhook(id1);
        } else {
            check("frame.interpret.customArgs", false, "id=" + id1);
        }
    }

    private static void frameTrace() {
        int id0 = NativeTest.apiFrameTrace(C, "add", "(II)I", 0);   // METHOD_ONLY
        if (id0 > 0) {
            check("frame.trace.methodOnly", Target.add(4, 5) == 9, "=" + Target.add(4, 5));
            NativeTest.unhook(id0);
        } else {
            check("frame.trace.methodOnly", false, "id=" + id0);
        }
        int id1 = NativeTest.apiFrameTrace(C, "add", "(II)I", 1);   // INSTRUCTION_DIFF
        if (id1 > 0) {
            check("frame.trace.instructionDiff", Target.add(4, 5) == 9, "=" + Target.add(4, 5));
            NativeTest.unhook(id1);
        } else {
            check("frame.trace.instructionDiff", false, "id=" + id1);
        }
    }

    private static void interpretWithOptions() {
        // stepIn=false, unlimited budget: guarded(5) -> 100
        int a = NativeTest.apiInterpretWithOptions(C, "guarded", "(I)I", 5, -1, false);
        check("interp.opts.direct", a == 100, "=" + a);
        // stepIn=true: recurse into Helper.check bytecode -> still 100
        int b = NativeTest.apiInterpretWithOptions(C, "guarded", "(I)I", 5, -1, true);
        check("interp.opts.stepIn", b == 100, "=" + b);
        // instruction budget exhausted -> negative error marker
        int c = NativeTest.apiInterpretWithOptions(C, "guarded", "(I)I", 5, 1, false);
        check("interp.opts.budgetAbort", c < 0, "=" + c);
    }

    private static void eventCounts() {
        String s = NativeTest.apiEventCounts(C, "guarded", "(I)I", 5);
        System.out.println("[Java][API] eventCounts = " + s);
        boolean ok = s.contains("status=0") && s.contains("exc=0") && s.contains("first=")
                && !s.contains("insn=0") && !s.contains("pre=0") && !s.contains("post=0");
        check("callbacks.events", ok, s);
    }

    private static void exceptionEvent() {
        String s = NativeTest.apiExceptionEvent(C, "boom", "()V");
        System.out.println("[Java][API] exceptionEvent = " + s);
        boolean ok = s.contains("exc=1") && s.contains("catchPc=-1");
        check("callbacks.exception", ok, s);
    }

    private static void interpHelpers() {
        String s = NativeTest.apiInterpHelpers();
        System.out.println("[Java][API] interpHelpers = " + s);
        boolean ok = s.contains("sysJava=1") && s.contains("sysAndroid=1") && s.contains("sysApp=0")
                && s.contains("ret=42") && s.contains("interpNull=0")
                && s.contains("trOn=1") && s.contains("trOff=0");
        check("interp.helpers", ok, s);
    }

    private static void filterOptions() {
        int v = NativeTest.apiFilterOptions(C, "guarded", "(I)I", 5);
        check("interp.filterOptions", v == 100, "=" + v);
    }

    private static void piLevel() {
        String s = NativeTest.apiPiLevel(C, "add", "(II)I");
        System.out.println("[Java][API] piLevel = " + s);
        boolean ok = !s.contains("dumpSmali=0") && !s.contains("dumpCode=0") && s.contains("nativePtr=0");
        check("pi.level.dump", ok, s);
    }

    private static void xdl() {
        String s = NativeTest.apiXdl();
        System.out.println("[Java][API] xdl = " + s);
        boolean ok = s.contains("open=1") && s.contains("sym=1") && s.contains("dsym=1") && s.contains("addr=1");
        check("xdl.linkers", ok, s);
    }

    private static void nativeEngine() {
        boolean ok = NativeTest.apiNativeEngine();
        check("native.engine.init", ok, "isNativeEngineInitialized=" + ok);
    }

    private static void pineAlias() {
        boolean ok = NativeTest.apiPineAlias();
        check("pine.alias.init", ok, "PineInit=" + ok);
    }

    // ------------------------------------------------------------------ utils

    private static void banner(String s) {
        System.out.println("==========================================================");
        System.out.println("[Java] " + s);
        System.out.println("==========================================================");
    }

    private static void check(String name, boolean ok, String detail) {
        if (ok) {
            pass++;
            System.out.println("[Java][API]   PASS  " + name);
        } else {
            fail++;
            failures.add(name);
            System.out.println("[Java][API]   FAIL  " + name + "  (" + detail + ")");
        }
        System.out.flush();
    }

    public static java.util.List<String> failures() {
        return failures;
    }
}
