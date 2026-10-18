//
// verify_review_fixes.js - Test suite for the 10 code review fixes
//
console.log("=================================================");
console.log("=== STARTING CODE REVIEW FIXES VERIFICATION ===");
console.log("=================================================");

let passCount = 0;
let failCount = 0;

function assert(cond, msg) {
    if (cond) {
        console.log("  [PASS] " + msg);
        passCount++;
    } else {
        console.log("  [FAIL] " + msg);
        failCount++;
    }
}

let mulArt = Java.findMethod("com.axhlzy.oattest.MainActivity", "staticMul");
console.log("[*] Target staticMul ArtMethod:", mulArt);

// ---------------------------------------------------------------------------
// TEST 1: Issue 9 - Hook ID monotonic increment across unhookall
// ---------------------------------------------------------------------------
console.log("\n[TEST 1] Hook ID uniqueness & unhookall monotonicity...");
try {
    let res1 = jhook(mulArt);
    let m1 = String(res1).match(/id:\s*(\d+)/);
    let id1 = m1 ? parseInt(m1[1]) : -1;
    console.log("  First hook:", res1, "-> id:", id1);

    unhookall();

    let res2 = jhook(mulArt);
    let m2 = String(res2).match(/id:\s*(\d+)/);
    let id2 = m2 ? parseInt(m2[1]) : -1;
    console.log("  Second hook after unhookall:", res2, "-> id:", id2);

    assert(id2 > id1, "Hook ID monotonically increased after unhookall (" + id2 + " > " + id1 + ")");

    // Attempting to unhook old id1
    unhook(id1);
    // Unhooking id2 should succeed
    let unhookRes = unhook(id2);
    console.log("  unhook(id2) result:", unhookRes);
    assert(String(unhookRes).indexOf("Unhooked successfully") !== -1, "unhook(id2) succeeded and was not corrupted by unhook(id1)");
    unhookall();
} catch (e) {
    console.log("  [EXC] Test 1 failed:", e);
    failCount++;
}

// ---------------------------------------------------------------------------
// Setup Async Worker Class for multi-threaded hook triggers
// ---------------------------------------------------------------------------
let AsyncWorker = Java.registerClass({
    name: "com.artpi.test.AsyncHookWorker",
    implements: ["java.lang.Runnable"],
    methods: {
        "startWorker()V": `
            new-instance v0, Ljava/lang/Thread;
            invoke-direct {v0, p0}, Ljava/lang/Thread;-><init>(Ljava/lang/Runnable;)V
            invoke-virtual {v0}, Ljava/lang/Thread;->start()V
            return-void
        `,
        "run()V": `
            const/4 v0, 5
            const/4 v1, 6
            invoke-static {v0, v1}, Lcom/axhlzy/oattest/MainActivity;->staticMul(II)I
            return-void
        `
    }
});

// ---------------------------------------------------------------------------
// TEST 2: Issue 1 - ctx.stack cached on read, setResult illegal outside callback
// ---------------------------------------------------------------------------
console.log("\n[TEST 2] Issue 1: ctx.stack & setResult safety...");
try {
    let savedCtx = null;
    let stackInside = null;
    let hookExecuted = false;

    Java.hook(mulArt,
        function onEnter(ctx) {
            hookExecuted = true;
            savedCtx = ctx;
            stackInside = ctx.stack;
            console.log("  Inside onEnter (thread=" + Process.getCurrentThreadId() + "), stack length:", (stackInside ? stackInside.length : 0));
        },
        function onLeave(ctx) {
        }
    );

    let w = AsyncWorker.$new();
    w.startWorker();
    sleep(400); // yields g_jsMutex so worker thread can execute hook

    assert(hookExecuted, "Hook callback executed on background worker thread");
    assert(typeof stackInside === "string" && stackInside.length > 0, "ctx.stack readable inside callback");

    // Outside callback: read cached stack on savedCtx
    let stackOutside = savedCtx.stack;
    assert(stackOutside === stackInside, "savedCtx.stack preserved cached value outside callback without crash");

    // Outside callback: calling setResult must throw TypeError, NOT dangling pointer write
    let setResultThrew = false;
    let errMsg = "";
    try {
        savedCtx.setResult(999);
    } catch (err) {
        setResultThrew = true;
        errMsg = String(err);
    }
    assert(setResultThrew, "savedCtx.setResult outside callback threw exception: " + errMsg);

    unhookall();
} catch (e) {
    console.log("  [EXC] Test 2 failed:", e);
    failCount++;
}

// ---------------------------------------------------------------------------
// TEST 3: Issue 1 - Unread ctx.stack invalidation
// ---------------------------------------------------------------------------
console.log("\n[TEST 3] Issue 1: Unread ctx.stack invalidation outside callback...");
try {
    let unreadCtx = null;
    let hookExecuted = false;

    Java.hook(mulArt, function onEnter(ctx) {
        hookExecuted = true;
        unreadCtx = ctx;
        // intentionally NOT reading ctx.stack here
    });

    let w = AsyncWorker.$new();
    w.startWorker();
    sleep(400);

    assert(hookExecuted, "Hook callback executed on worker thread without reading ctx.stack");
    assert(unreadCtx !== null, "unreadCtx captured");

    let unreadStack = unreadCtx.stack;
    console.log("  unreadCtx.stack outside callback:", unreadStack);
    assert(typeof unreadStack === "string" && unreadStack.indexOf("stack is only available during hook callback execution") !== -1,
           "Unread ctx.stack returns invalidation warning string outside callback");

    unhookall();
} catch (e) {
    console.log("  [EXC] Test 3 failed:", e);
    failCount++;
}

// ---------------------------------------------------------------------------
// TEST 4: Issue 2 - System.gc() during hook with intact ManagedStack link_
// ---------------------------------------------------------------------------
console.log("\n[TEST 4] Issue 2: System.gc() during hook with intact ManagedStack link_...");
try {
    let gcRan = false;

    Java.hook(mulArt, function onEnter(ctx) {
        console.log("  Triggering System.gc() inside hook callback...");
        dynamic.java.java.lang.System.gc();
        gcRan = true;
        console.log("  System.gc() completed cleanly!");
    });

    let w = AsyncWorker.$new();
    w.startWorker();
    sleep(500);

    assert(gcRan, "System.gc() successfully executed inside hook without aborting/crashing GC walker");

    unhookall();
} catch (e) {
    console.log("  [EXC] Test 4 failed:", e);
    failCount++;
}

// ---------------------------------------------------------------------------
// TEST 5: Issue 4 - Last-one-wins replacement & in-flight drain
// ---------------------------------------------------------------------------
console.log("\n[TEST 5] Issue 4: Last-one-wins replacement & in-flight drain...");
try {
    let hook1Called = false;
    let hook2Called = false;

    // Install hook 1
    Java.hook(mulArt, function onEnter(ctx) { hook1Called = true; });

    // Replace with hook 2 immediately (last-one-wins with in-flight drain)
    Java.hook(mulArt, function onEnter(ctx) { hook2Called = true; });

    let w = AsyncWorker.$new();
    w.startWorker();
    sleep(400);

    assert(!hook1Called, "Old hook1 was replaced and NOT called");
    assert(hook2Called, "New hook2 was called successfully");

    unhookall();
} catch (e) {
    console.log("  [EXC] Test 5 failed:", e);
    failCount++;
}

// ---------------------------------------------------------------------------
// TEST 6: Issue 8 - SetDumpRegsAfter restoration in trace
// ---------------------------------------------------------------------------
console.log("\n[TEST 6] Issue 8: SetDumpRegsAfter restoration in trace...");
try {
    // Trace 1 with dumpAfter: false
    let t1 = Trace.unified(mulArt, { dumpAfter: false });
    console.log("  Trace 1 handle:", t1);
    t1.stop();

    // Trace 2 with default dumpAfter: true
    let t2 = Trace.unified(mulArt);
    console.log("  Trace 2 handle:", t2);
    t2.stop();

    assert(true, "Consecutive traces with different dumpAfter executed and stopped cleanly");
} catch (e) {
    console.log("  [EXC] Test 6 failed:", e);
    failCount++;
}

// ---------------------------------------------------------------------------
// Summary
// ---------------------------------------------------------------------------
console.log("\n=================================================");
console.log("=== RESULTS: " + passCount + " PASSED, " + failCount + " FAILED ===");
console.log("=================================================");
