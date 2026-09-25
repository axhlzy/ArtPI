package com.artpi.js;

/**
 * Suite 2 runner: ArtPI QuickJS binding tests.
 *
 * Launched by app_process:
 *   CLASSPATH=.../classes.dex app_process /system/bin com.artpi.js.JsMain
 *
 * Loads libartpi_agent.so (its ctor boots PI + QuickJS + the TCP server) and
 * drives the JS runtime through NativeJs.eval(), asserting results.
 *
 * Exit code: 0 all passed, 1 otherwise.
 */
public class JsMain {

    private static int passed = 0;
    private static int failed = 0;
    private static final java.util.List<String> failures = new java.util.ArrayList<String>();

    private static final String T = "com.artpi.js.JsTarget";
    private static final String M_ADD = "var t = findclass('" + T + "'); var m = findmethod(t, 'add', '(II)I'); ";

    public static void main(String[] args) {
        banner("ArtPI Suite 2 - QuickJS bindings");

        String lib = System.getenv("ARTPI_TEST_LIB");
        if (lib == null || lib.isEmpty()) {
            lib = "/data/local/tmp/artpi_js_test/libartpi_js_test.so";
        }
        try {
            System.load(lib);
            System.out.println("[Java] System.load(" + lib + ") -> OK");
        } catch (Throwable t) {
            System.out.println("[Java] System.load FAILED: " + t);
            System.exit(2);
            return;
        }

        if (!NativeJs.loadAgent()) {
            System.out.println("[Java] loadAgent failed (is libartpi_agent.so pushed?)");
            System.exit(2);
            return;
        }
        System.out.println("[Java] agent loaded, QuickJS runtime ready");

        runtimeBasics();
        namespaces();
        javaBindings();
        memoryBindings();
        jsHook();
        jsHookResultAndMutate();
        instanceObjectFields();
        jrefMethodsArrays();
        jrefMethodCalls();
        nativeHook();
        traceOptions();
        traceUnified();
        breakpoints();
        hookLogging();
        debugTraceNativeSurface();

        banner("Result: " + passed + " passed, " + failed + " failed");
        if (failed > 0) {
            System.out.println("[Java] FAILED CASES:");
            for (Object n : failures) System.out.println("[Java]   - " + n);
        }
        System.out.flush();
        System.exit(failed == 0 ? 0 : 1);
    }

    // ------------------------------------------------------------------ groups

    private static void runtimeBasics() {
        eq("js.arith", ev("1 + 1"), "2");
        eq("js.string", ev("\"a\" + \"b\""), "ab");
        eq("js.bigint", ev("(9007199254740993n + 1n).toString()"), "9007199254740994");
        eq("js.bool", ev("1 === 1"), "true");
        eq("js.null", ev("null"), "null");
        eq("js.undefined", ev("void 0"), "undefined");
        eq("js.closure", ev("(function(n){ return n * 3; })(7)"), "21");
        eq("js.array", ev("[1,2,3].map(function(x){return x*x;}).join(',')"), "1,4,9");
        eq("js.console", ev("console.log('hi from js'); 1"), "1");
        eq("js.exception", ev("throw new Error('x')").startsWith("[Exception]"), true);
    }

    private static final String[] GLOBAL_FNS = {
            "findclass", "findmethod", "methodtoart", "dumpsmali", "jhook", "unhook", "unhookall", "nhook",
            "prepare",
            "findmodule", "findsymbol", "findModule", "findSymbol", "dumpnative", "dumpNative", "nunhookall",
            "traceunified", "tracejava", "tracenative",
            // Debug: flat aliases are brkj/brkn/s/n/c/r (+ helpers)
            "brkj", "brkn", "s", "n", "c", "r", "bt", "inspect", "po",
            "getreg", "setreg", "dumpRegs", "thread", "bpunhookall",
            "hexdump", "readmem", "writemem", "readstring", "readu32", "writeU32"
    };

    private static void namespaces() {
        eq("ns.objects", ev(
                "['Java','Native','Memory','Trace','Debug'].every(function(k){return typeof globalThis[k]==='object';})"),
                "true");
        eq("ns.lowerAliases", ev(
                "['debug','memory','trace'].every(function(k){return typeof globalThis[k]==='object';})"),
                "true");
        // diagnostic: list which expected globals are missing (printed, not asserted)
        StringBuilder list = new StringBuilder("[");
        for (int i = 0; i < GLOBAL_FNS.length; i++) {
            if (i > 0) list.append(',');
            list.append("'").append(GLOBAL_FNS[i]).append("'");
        }
        list.append("]");
        String missing = ev(list + ".filter(function(k){return typeof globalThis[k]!=='function';}).join(',')");
        System.out.println("[Java] ns.globals missing = [" + missing + "]");
        eq("ns.globals", ev(list + ".every(function(k){return typeof globalThis[k]==='function';})"), "true");
        eq("ns.debugFns", ev(
                "['breakJava','breakNative','continue','step','next','return','bt','inspect','getreg','setreg','dumpRegs','thread']"
              + ".every(function(k){return typeof Debug[k]==='function';})"),
                "true");
        eq("ns.regsProxy", ev("typeof regs === 'object' && typeof regs.get === 'function'"), "true");
        eq("ns.javaFns", ev(
                "['findClass','findMethod','listMethods','methodToArt','dumpSmali','dumpCode','hook','unhook','unhookAll']"
              + ".every(function(k){return typeof Java[k]==='function';})"),
                "true");
        eq("ns.nativeFns", ev("typeof Native.findModule==='function' && typeof Native.findSymbol==='function' && typeof Native.dumpNative==='function' && typeof Native.hook==='function'"),
                "true");
        eq("ns.memoryFns", ev(
                "['hexdump','readByteArray','writeByteArray','readCString','readU32','writeU32']"
              + ".every(function(k){return typeof Memory[k]==='function';})"),
                "true");
    }

    private static void javaBindings() {
        eq("findclass.type", ev("typeof findclass('java.lang.String')"), "bigint");
        eq("findclass.ok", ev("String(findclass('java.lang.String')).length > 1"), "true");
        eq("findclass.missing", ev("findclass('no.such.Clazz') === null"), "true");
        eq("findmethod.ok", ev(M_ADD + "String(m).length > 0"), "true");
        eq("findmethod.missing", ev("var t=findclass('" + T + "'); findmethod(t,'nope','()V') === null"), "true");
        eq("methodtoart.roundtrip", ev(M_ADD + "methodtoart(m) === m"), "true");
        eq("dumpsmali.opcode", ev(M_ADD + "dumpsmali(m, 64).indexOf('add-int') >= 0"), "true");
        eq("listMethods.contains", ev("Java.listMethods(findclass('" + T + "')).indexOf('add') >= 0"), "true");
        // app_process has no Application -> class-loader enumeration may return null; smoke-test only
        eq("enumloaders.noThrow", ev("typeof enumloaders() === 'string' || enumloaders() === null"), "true");
    }

    private static void memoryBindings() {
        long addr = NativeJs.bufferAddress();
        System.out.println("[Java] bufferAddress = 0x" + Long.toHexString(addr));
        String a = addr + "n";
        String a4 = (addr + 4) + "n";
        String a16 = (addr + 16) + "n";

        eq("hexdump.bytes", ev("hexdump(" + a + ", 16).indexOf('00 01 02 03 04 05 06 07') >= 0"), "true");
        eq("readu32.le", ev("readu32(" + a + ")"), "50462976");                 // 0x03020100
        eq("readmem.byteLength", ev("readmem(" + a + ", 4).byteLength"), "4");
        eq("writeu32.roundtrip",
                ev("writeU32(" + a4 + ", 287454020); readu32(" + a4 + ")"), "287454020"); // 0x11223344
        eq("writemem.cstring",
                ev("writemem(" + a16 + ", '41 42 43 00'); readstring(" + a16 + ")"), "ABC");
    }

    private static void jsHook() {
        // install: callback increments a global each time JsTarget.add() runs
        String res = ev("globalThis.__hits = 0; " + M_ADD
                + "jhook(m, function(o){ globalThis.__hits++; });");
        System.out.println("[Java] jhook -> " + res);
        eq("jhook.installed", res.startsWith("Hook installed"), true);

        int r = JsTarget.add(2, 3);
        eq("jhook.originalStillRuns", r == 5, true);
        eq("jhook.callbackFired", ev("String(globalThis.__hits)"), "1");

        String un = ev("unhookall()");
        System.out.println("[Java] unhookall -> " + un);
        eq("jhook.unhooked", un.startsWith("Unhooked"), true);
        eq("jhook.restored", JsTarget.add(2, 3) == 5, true);
        eq("jhook.noExtraHits", ev("String(globalThis.__hits)"), "1");
    }

    // --- JS hook can override the result / mutate args (not just observe) -----
    private static void jsHookResultAndMutate() {
        // setResult: JS decides the return value; original is skipped
        String r1 = ev(M_ADD + "jhook(m, function(o){ o.setResult(999); });");
        eq("jhook.setResult.installed", r1.startsWith("Hook installed"), true);
        eq("jhook.setResult.value", JsTarget.add(2, 3) == 999, true);
        eq("jhook.setResult.unhook", ev("unhookall()").startsWith("Unhooked"), true);
        eq("jhook.setResult.restored", JsTarget.add(2, 3) == 5, true);

        // mutate args: no setResult -> original runs with modified args (10 + 3)
        String r2 = ev(M_ADD + "jhook(m, function(o){ o.args[0] = 10; });");
        eq("jhook.mutateArg.installed", r2.startsWith("Hook installed"), true);
        eq("jhook.mutateArg.value", JsTarget.add(2, 3) == 13, true);
        ev("unhookall()");
        eq("jhook.mutateArg.restored", JsTarget.add(2, 3) == 5, true);

        // String arg read + String result rewrite
        String sm = "var t = findclass('" + T + "'); var m = findmethod(t, 'greet', "
                + "'(Ljava/lang/String;)Ljava/lang/String;'); ";
        String r3 = ev(sm + "jhook(m, function(o){ o.setResult('X' + o.args[0]); });");
        eq("jhook.string.installed", r3.startsWith("Hook installed"), true);
        eq("jhook.string.value", JsTarget.greet("b"), "Xb");
        ev("unhookall()");
        eq("jhook.string.restored", JsTarget.greet("b"), "hi b");
    }

    // --- instance object args: obj.field read/write via JRef ---------------
    private static final String M_BOX =
            "var t = findclass('com.artpi.js.JsTarget'); "
          + "var m = findmethod(t, 'useBox', '(Lcom/artpi/js/JsTarget$Box;)I'); ";

    private static void instanceObjectFields() {
        NativeJs.takeLog();   // clear

        // read field: o.args[0].value
        String r1 = ev(M_BOX + "jhook(m, function(o){ o.setResult(o.args[0].value + 1000); });");
        eq("jref.installed", r1.startsWith("Hook installed"), true);
        eq("jref.readField", JsTarget.useBox(new JsTarget.Box(7, "hi")) == 1007, true);
        ev("unhookall()");

        // write field (no setResult): original runs with mutated field -> 42
        String r2 = ev(M_BOX + "jhook(m, function(o){ o.args[0].value = 42; });");
        eq("jref.setField.installed", r2.startsWith("Hook installed"), true);
        JsTarget.Box box = new JsTarget.Box(7, "hi");
        eq("jref.setField.value", JsTarget.useBox(box) == 42, true);
        eq("jref.setField.inPlace", box.value == 42, true);
        ev("unhookall()");

        // read String field: o.args[0].label -> report the JS type we received
        String r3 = ev(M_BOX + "jhook(m, function(o){ var v = o.args[0].label; "
                + "o.setResult(typeof v === 'string' ? 1 : (v === undefined ? 2 : (typeof v === 'object' ? 3 : 4))); });");
        eq("jref.readStringField.installed", r3.startsWith("Hook installed"), true);
        int code = JsTarget.useBox(new JsTarget.Box(7, "hi"));
        System.out.println("[Java] jref.labelTypeCode = " + code + " (1=string 2=undefined 3=object 4=other)");
        eq("jref.readStringField", code == 1, true);
        ev("unhookall()");

        // nested: o.args[0].toString() present
        String r4 = ev(M_BOX + "jhook(m, function(o){ "
                + "o.setResult(typeof o.args[0].toString === 'function' ? 1 : 0); });");
        eq("jref.toString.installed", r4.startsWith("Hook installed"), true);
        int tsCode = JsTarget.useBox(new JsTarget.Box(7, "hi"));
        System.out.println("[Java] jref.toStringCode = " + tsCode);
        eq("jref.toString", tsCode == 1, true);
        ev("unhookall()");
    }

    // --- hook logs: entry / arg modified / return modified -----------------
    // --- native hook (nhook) with onEnter/onLeave, setArg/setRet -------------
    // --- JRef: field access (arrays covered via JRef array proxy) -----------
    private static void jrefMethodsArrays() {
        // NOTE: object *method* invocation is intentionally not exposed yet —
        // resolving methods needs Class.getDeclaredMethods(), whose hidden-API
        // caller lookup walks the (frameless) hook stack and crashes. Only
        // fields + array elements are supported on the JRef hook path.

        // int[] arg: read length + elements
        String am = "var __at = findclass('com.artpi.js.JsTarget'); var __am = findmethod(__at, 'sumInts', '([I)I'); ";
        String r3 = ev(am + "jhook(__am, function(o){ var a = o.args[0]; "
                + "o.setResult(a.length * 1000 + a[0] * 10 + a[2]); });");
        eq("jref.array.read.installed", r3.startsWith("Hook installed"), true);
        eq("jref.array.read.value", JsTarget.sumInts(new int[]{0, 1, 4}) == 3004, true);   // len=3,a0=0,a2=4
        ev("unhookall()");

        // int[] arg: write element (original runs with modified array)
        String r4 = ev(am + "jhook(__am, function(o){ o.args[0][0] = 100; });");
        eq("jref.array.write.installed", r4.startsWith("Hook installed"), true);
        eq("jref.array.write.value", JsTarget.sumInts(new int[]{0, 1, 4}) == 105, true);    // 100+1+4
        ev("unhookall()");

        // object array element read/write (String[] arg)
        // (Box field access already covered by instanceObjectFields())
    }

    // --- JRef method calls (requires Java.prepare at eval time) --------------
    private static void jrefMethodCalls() {
        String prep = ev("prepare(findclass('com.artpi.js.JsTarget'))");
        System.out.println("[Java] prepare(JsTarget) = " + prep);
        eq("jref.prepare.class", prep.contains("prepared") && !prep.contains("not found"), true);
        String prepB = ev("prepare(findclass('com.artpi.js.JsTarget$Box'))");
        System.out.println("[Java] prepare(Box) = " + prepB);
        eq("jref.prepare.box", prepB.contains("prepared") && !prepB.contains("not found"), true);

        // no-arg instance method: o.args[0].doubled()
        String r1 = ev(M_BOX + "jhook(m, function(o){ o.setResult(o.args[0].doubled()); });");
        eq("jref.callMethod.installed", r1.startsWith("Hook installed"), true);
        eq("jref.callMethod.value", JsTarget.useBox(new JsTarget.Box(7, "hi")) == 14, true);
        ev("unhookall()");

        // method with args: o.args[0].addTo(5)
        String r2 = ev(M_BOX + "jhook(m, function(o){ o.setResult(o.args[0].addTo(5)); });");
        eq("jref.callMethod.args.installed", r2.startsWith("Hook installed"), true);
        eq("jref.callMethod.args.value", JsTarget.useBox(new JsTarget.Box(7, "hi")) == 12, true);
        ev("unhookall()");

        // prepared field path (cache) still works — encode pieces for diagnosis
        String r3 = ev(M_BOX + "jhook(m, function(o){ "
                + "o.setResult(o.args[0].value * 100 + o.args[0].label.length); });");
        eq("jref.preparedField.installed", r3.startsWith("Hook installed"), true);
        NativeJs.takeLog();
        int pf = JsTarget.useBox(new JsTarget.Box(7, "hi"));
        System.out.println("[Java] jref.preparedField raw = " + pf + " (expect 702)");
        System.out.println("[Java] preparedField log:\n" + NativeJs.takeLog());
        eq("jref.preparedField.value", pf == 702, true);  // 7*100 + 2
        ev("unhookall()");
    }

    private static void nativeHook() {
        final String SYM = "'libartpi_js_test.so!artpi_test_native_add'";

        // onEnter modifies arg0; onLeave counts + reads the return value
        String r = ev("globalThis.__nhE = 0; globalThis.__nhL = 0; "
                + "nhook(" + SYM + ", {"
                + "  onEnter: function(o){ globalThis.__nhE++; o.setArg(0, 100); },"
                + "  onLeave: function(o){ globalThis.__nhL++; globalThis.__nhRet = String(o.ret); }"
                + "});");
        eq("nhook.installed", r.startsWith("Native hook installed"), true);
        eq("nhook.setArg", NativeJs.callNativeAdd(1, 2) == 102, true);   // 100 + 2
        eq("nhook.onEnterCount", ev("String(__nhE)"), "1");
        eq("nhook.onLeaveCount", ev("String(__nhL)"), "1");
        eq("nhook.retRead", ev("String(__nhRet)"), "102");
        eq("nhook.unhookAll", ev("nunhookall()").startsWith("Unhooked"), true);
        eq("nhook.restored", NativeJs.callNativeAdd(1, 2) == 3, true);

        // onLeave overrides the return value
        String r2 = ev("nhook(" + SYM + ", { onLeave: function(o){ o.setRet(777); } });");
        eq("nhook.setRet.installed", r2.startsWith("Native hook installed"), true);
        eq("nhook.setRet", NativeJs.callNativeAdd(1, 2) == 777, true);
        ev("nunhookall()");
        eq("nhook.setRet.restored", NativeJs.callNativeAdd(1, 2) == 3, true);

        // by raw address
        long addr = NativeJs.nativeAddAddress();
        String r3 = ev("nhook(" + addr + "n, { onEnter: function(o){ globalThis.__nhAddr = (globalThis.__nhAddr||0)+1; } });");
        eq("nhook.byAddr.installed", r3.startsWith("Native hook installed"), true);
        NativeJs.callNativeAdd(1, 1);
        eq("nhook.byAddr.fired", ev("String(__nhAddr)"), "1");
        ev("nunhookall()");
    }

    // --- Trace.* honors opt / TraceOption (callbacks, mode, filters) ---------
    private static void traceOptions() {
        // tracejava: onEnter/onLeave callbacks + handle.stop()
        String r = ev("globalThis.__te = 0; globalThis.__tl = 0; globalThis.__tr = ''; " + M_ADD
                + "globalThis.__h = tracejava(m, { onEnter: function(e){ globalThis.__te++; globalThis.__tsym = e.symbol; }, "
                + "onLeave: function(e){ globalThis.__tl++; globalThis.__tr = e.ret; } }); 'ok'");
        eq("trace.java.installed", r, "ok");
        JsTarget.add(2, 3);
        eq("trace.java.onEnter", ev("String(__te)"), "1");
        eq("trace.java.onLeave", ev("String(__tl)"), "1");
        eq("trace.java.ret", ev("String(__tr)"), "5");
        eq("trace.java.symbol", ev("(globalThis.__tsym||'').indexOf('add') >= 0 ? 'true':'false'"), "true");
        eq("trace.java.stop", ev("__h.stop()"), "Trace stopped");
        JsTarget.add(2, 3);
        eq("trace.java.stoppedNoMore", ev("String(__te)"), "1");

        // tracejava INSN_STEP -> onInsn fires per instruction
        String r2 = ev("globalThis.__insn = 0; " + M_ADD
                + "globalThis.__h2 = tracejava(m, { mode:'INSN_STEP', excludeSystem:false, "
                + "onInsn: function(e){ globalThis.__insn++; return true; } }); 'ok'");
        eq("trace.java.insnStep.installed", r2, "ok");
        JsTarget.add(1, 1);
        eq("trace.java.insnStep.counted", ev("String(__insn !== 0)"), "true");
        ev("__h2.stop()");

        // excludeSystem: tracing java.lang.String.length is filtered by default
        // (use non-colliding var names — `c`/`s`/`n`/`r` are global aliases!)
        String sm = "var __sc = findclass('java.lang.String'); var __lm = findmethod(__sc, 'length', '()I'); ";
        String r3 = ev("globalThis.__se = 0; " + sm
                + "globalThis.__h3 = tracejava(__lm, { onEnter: function(e){ globalThis.__se++; } }); 'ok'");
        eq("trace.java.systemHook.installed", r3, "ok");
        eq("trace.java.strLen", JsTarget.strLen("hello") == 5, true);
        eq("trace.java.excludeSystem", ev("String(__se)"), "0");
        ev("__h3.stop()");

        String r4 = ev("globalThis.__se2 = 0; " + sm
                + "globalThis.__h4 = tracejava(__lm, { excludeSystem:false, onEnter: function(e){ globalThis.__se2++; } }); 'ok'");
        eq("trace.java.includeSystem.installed", r4, "ok");
        JsTarget.strLen("hi");
        eq("trace.java.includeSystem", ev("String(__se2)"), "1");
        ev("__h4.stop()");

        // tracenative: onEnter/onLeave callbacks
        long addr = NativeJs.nativeAddAddress();
        String rn = ev("globalThis.__ne = 0; globalThis.__nl = 0; "
                + "globalThis.__hn = tracenative(" + addr + "n, { excludeSystem:false, "
                + "includeNative:'libartpi_js_test', onEnter: function(e){ globalThis.__ne++; }, "
                + "onLeave: function(e){ globalThis.__nl++; } }); 'ok'");
        eq("trace.native.installed", rn, "ok");
        NativeJs.callNativeAdd(1, 2);
        eq("trace.native.onEnter", ev("String(__ne)"), "1");
        eq("trace.native.onLeave", ev("String(__nl)"), "1");
        ev("__hn.stop()");

        // tracenative: includeNative mismatch -> callback filtered
        String rf = ev("globalThis.__me = 0; "
                + "globalThis.__hf = tracenative(" + addr + "n, { includeNative:'libdoesnotexist', "
                + "onEnter: function(e){ globalThis.__me++; } }); 'ok'");
        eq("trace.native.filter.installed", rf, "ok");
        NativeJs.callNativeAdd(1, 2);
        eq("trace.native.includeNativeFilter", ev("String(__me)"), "0");
        ev("__hf.stop()");
    }

    // --- breakpoints: cross-thread pause/resume + cond gate -------------------
    private static boolean waitPaused(int timeoutMs) {
        long end = System.currentTimeMillis() + timeoutMs;
        while (System.currentTimeMillis() < end) {
            // while paused, inspect() does not report "no thread paused"
            if (!ev("inspect('v0')").startsWith("[*] No thread paused")) return true;
            try { Thread.sleep(15); } catch (InterruptedException e) { }
        }
        return false;
    }

    private static boolean waitNonZero(String var, int timeoutMs) {
        long end = System.currentTimeMillis() + timeoutMs;
        while (System.currentTimeMillis() < end) {
            if (!"0".equals(ev("String(" + var + ")"))) return true;
            try { Thread.sleep(15); } catch (InterruptedException e) { }
        }
        return false;
    }

    // --- traceunified: real Java <-> Native (QBDI) handoff -------------------
    private static void traceUnified() {
        // Warm JNI resolution + interpreter class cache.
        eq("unified.warmup", JsTarget.callNative(1, 2) == 3, true);
        ev("prepare(findclass('com.artpi.js.JsTarget'))");
        ev("prepare(findclass('com.artpi.js.JsNativeTarget'))");

        String m = "var __ut = findclass('com.artpi.js.JsTarget'); "
                + "var __um = findmethod(__ut, 'callNative', '(II)I'); ";
        String r = ev("globalThis.__lines = ''; " + m
                + "globalThis.__uh = traceunified(__um, { onInsn: function(e){ globalThis.__lines += e.text + '\\n'; } }); 'ok'");
        eq("unified.installed", r, "ok");

        int v = JsTarget.callNative(4, 5);
        System.out.println("[Java] unified.callNative(4,5) raw = " + v + " (expect 9)");
        eq("unified.result", v == 9, true);

        String lines = ev("globalThis.__lines");
        System.out.println("[Java] unified lines:\n" + lines);
        eq("unified.hasJavaLine", lines.contains("callNative"), true);
        eq("unified.hasNativeLine", lines.contains("[Native JNI]") || lines.contains("[ARM64]"), true);

        eq("unified.stop", ev("__uh.stop()"), "Trace stopped");
        eq("unified.restored", JsTarget.callNative(1, 1) == 2, true);
    }

    private static void breakpoints() {
        final long addr = NativeJs.nativeAddAddress();

        // (1) brkn: pause at native entry, resume from the controlling thread
        String r = ev("globalThis.__bph = 0; globalThis.__bp = brkn(" + addr + "n, "
                + "function(e){ globalThis.__bph++; return true; }); typeof __bp");
        eq("bp.brkn.installed", r, "string");
        final int[] out1 = {0};
        Thread t1 = new Thread(new Runnable() { public void run() { out1[0] = NativeJs.callNativeAdd(1, 2); } });
        t1.start();
        eq("bp.brkn.paused", waitPaused(3000), true);
        eq("bp.brkn.condFired", ev("String(__bph)"), "1");
        eq("bp.brkn.continue", ev("c()").startsWith("Continuing"), true);
        try { t1.join(3000); } catch (InterruptedException e) { }
        eq("bp.brkn.result", out1[0] == 3, true);
        ev("bpunhookall()");

        // (2) brkn with cond=false: cond evaluated, but never pauses
        ev("globalThis.__bpc = 0; brkn(" + addr + "n, function(e){ globalThis.__bpc++; return false; });");
        final int[] out2 = {0};
        Thread t2 = new Thread(new Runnable() { public void run() { out2[0] = NativeJs.callNativeAdd(1, 2); } });
        t2.start();
        eq("bp.cond.evaluated", waitNonZero("__bpc", 3000), true);
        eq("bp.cond.falseNoPause", ev("inspect('v0')").startsWith("[*] No thread paused"), true);
        try { t2.join(3000); } catch (InterruptedException e) { }
        eq("bp.cond.falseResult", out2[0] == 3, true);
        ev("bpunhookall()");

        // (3) brkj: Java breakpoint with cond; single-step then continue
        String rm = "var __t = findclass('com.artpi.js.JsTarget'); var __m = findmethod(__t, 'add', '(II)I'); ";
        String r3 = ev("globalThis.__jbp = 0; " + rm
                + "globalThis.__jb = brkj(__m, function(e){ globalThis.__jbp++; return true; }); typeof __jb");
        eq("bp.brkj.installed", r3, "string");
        final int[] out3 = {0};
        Thread t3 = new Thread(new Runnable() { public void run() { out3[0] = JsTarget.add(2, 3); } });
        t3.start();
        eq("bp.brkj.paused", waitPaused(3000), true);
        eq("bp.brkj.condFired", ev("String(__jbp)"), "1");
        ev("c()");                                   // continue to completion
        try { t3.join(3000); } catch (InterruptedException e) { }
        eq("bp.brkj.result", out3[0] == 5, true);
        ev("bpunhookall()");
        eq("bp.brkj.restored", JsTarget.add(2, 3) == 5, true);
    }

    private static void hookLogging() {
        NativeJs.takeLog();   // clear

        String r = ev(M_ADD + "jhook(m, function(o){ o.setResult(4242); });");
        eq("logh.result.installed", r.startsWith("Hook installed"), true);
        JsTarget.add(2, 3);
        String log1 = NativeJs.takeLog();
        System.out.println("[Java] hook log (setResult):\n" + log1);
        eq("logh.entry", log1.contains("[hook]") && log1.contains("JsTarget.add"), true);
        eq("logh.resultModified", log1.contains("return MODIFIED"), true);
        eq("logh.resultValue", log1.contains("4242"), true);
        ev("unhookall()");

        // arg modification is logged
        NativeJs.takeLog();
        ev(M_ADD + "jhook(m, function(o){ o.args[0] = 77; });");
        JsTarget.add(2, 3);
        String log2 = NativeJs.takeLog();
        System.out.println("[Java] hook log (arg):\n" + log2);
        eq("logh.argModified", log2.contains("arg[0] MODIFIED"), true);
        eq("logh.originalReturn", log2.contains("original return"), true);
        ev("unhookall()");
    }

    private static void debugTraceNativeSurface() {        eq("debug.brk", ev("typeof brkj==='function' && typeof brkn==='function'"), "true");
        eq("debug.step", ev("typeof s==='function' && typeof n==='function' && typeof c==='function' && typeof r==='function'"), "true");
        eq("debug.namespace", ev("typeof Debug.breakJava==='function' && typeof Debug.step==='function' && typeof Debug.continue==='function'"), "true");
        eq("trace.unified", ev("typeof traceunified==='function' && typeof tracejava==='function' && typeof tracenative==='function'"), "true");
        eq("native.namespace", ev("typeof nhook==='function' && typeof Native.findModule==='function' && typeof Native.findSymbol==='function'"), "true");
        eq("native.findModule.libart", ev("String(Native.findModule('libart.so')).length > 0"), "true");
    }

    // ------------------------------------------------------------------ utils

    private static String ev(String script) {
        return NativeJs.eval(script);
    }

    private static void banner(String s) {
        System.out.println("==========================================================");
        System.out.println("[Java] " + s);
        System.out.println("==========================================================");
    }

    private static void eq(String name, Object actual, Object expected) {
        boolean ok = (actual == null) ? (expected == null) : actual.equals(expected);
        System.out.println("[Java]   " + (ok ? "PASS" : "FAIL") + "  " + name
                + (ok ? "" : "  (got=" + actual + " want=" + expected + ")"));
        if (ok) passed++; else { failed++; failures.add(name); }
        System.out.flush();
    }
}
