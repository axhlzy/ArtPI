//
// artpi_dexwriter_test.js - Test suite for DexWriter & Java.registerClass pure Dalvik bytecode
//

console.log("[*] ====== Starting DexWriter & Java.registerClass Test ======");

// 1. Verify DexWriter existence and static helpers
if (typeof DexWriter !== 'function' || typeof Java.DexWriter !== 'function') {
    throw new Error("DexWriter is not registered in global or Java scope!");
}
if (typeof DexWriter.build !== 'function' || typeof DexWriter.smali !== 'function') {
    throw new Error("DexWriter.build or DexWriter.smali is missing!");
}
console.log("[+] DexWriter is available with .build and .smali static builders!");

// 2. Register a hybrid class containing:
//    - Pure Dalvik bytecode via DexWriter.build(w => ...)
//    - Pure Dalvik bytecode via object { bytecode: function(w) ... }
//    - Pure Dalvik bytecode via Option B (Smali text shorthand)
//    - Pure Dalvik bytecode via Option B (DexWriter.smali(...))
//    - Native JS callback (traditional ACC_NATIVE) with args (must NOT be called at reg time)
let nativeCallCount = 0;

let TestCls = Java.registerClass({
    name: "com.artpi.test.BytecodePlugin",
    methods: {
        // Option A1: DexWriter.build(w => ...) fluent API
        "testBranch(I)I": DexWriter.build(function(w) {
            // registers: 3, ins: 2 (p0=this(v1), p1=flag(v2))
            w.setRegisters(3, 2, 0);
            let lblZero = w.makeLabel();
            let lblEnd = w.makeLabel();

            w.putIfEqz(2, lblZero);     // if p1 == 0 goto lblZero
            w.putConst(0, 777);         // v0 = 777
            w.putGoto(lblEnd);

            w.putLabel(lblZero);
            w.putConst(0, 999);         // v0 = 999

            w.putLabel(lblEnd);
            w.putReturn(0);             // return v0
        }),

        // Option A2: Object form with explicit bytecode function
        "getAnswer()I": {
            bytecode: function(w) {
                w.setRegisters(2, 1, 0); // p0=this(v1), v0=local
                w.putConst4(0, 42);
                w.putReturn(0);
            }
        },

        // Option B1: Direct Smali string shorthand
        "getSmaliConst()I": `
            const/16 v0, 0x1337
            return v0
        `,

        // Option B2: DexWriter.smali(...) explicit builder
        "getGreeting()Ljava/lang/String;": DexWriter.smali(`
            const-string v0, "Hello from Pure Dalvik Bytecode!"
            return-object v0
        `),

        // Option B3: Smali with multi-way branching (if-ge, if-eq)
        "compare(II)I": `
            if-ge p1, p2, :greater_or_equal
            const/4 v0, -1
            return v0
            :greater_or_equal
            if-eq p1, p2, :equal
            const/4 v0, 1
            return v0
            :equal
            const/4 v0, 0
            return v0
        `,

        // Option B4: Static method with Smali
        "staticAdd(II)I": {
            static: true,
            bytecode: `
                add-int v0, p0, p1
                return v0
            `
        },

        // Option B5: Static method with DexWriter.smali("static (II)I", ...)
        "staticSub(II)I": {
            static: true,
            bytecode: DexWriter.smali("static (II)I", `
                sub-int v0, p0, p1
                return v0
            `)
        },

        // Option B6: Backward branch / while-loop test (computes sum 1..N)
        "sumLoop(I)I": `
            const/4 v0, 0
            const/4 v1, 1
            :loop_head
            if-gtz p1, :loop_body
            return v0
            :loop_body
            add-int v0, v0, p1
            sub-int p1, p1, v1
            goto :loop_head
        `,

        // Option A3: Fluent API binary math ops
        "mathFluent(II)I": DexWriter.build(function(w) {
            w.setRegisters(5, 3, 0); // v0,v1: locals, p0: this(v2), p1: a(v3), p2: b(v4)
            w.putAddInt(0, 3, 4);    // v0 = a + b
            w.putMulInt(1, 3, 4);    // v1 = a * b
            w.putSubInt(0, 1, 0);    // v0 = (a * b) - (a + b)
            w.putReturn(0);
        }),

        // Option B7: Method with wide (long) parameter to test calculateInsWords
        "wideParam(J)I": DexWriter.smali(`(J)I`, `
            const/4 v0, 42
            return v0
        `),

        // Traditional Native callback with arguments:
        // Must NOT be executed during Java.registerClass!
        "addNative(II)I": function(a, b) {
            nativeCallCount++;
            return a + b;
        }
    }
});

console.log("[+] Class registered successfully:", TestCls);

// Verify native callback was NOT called during registration
if (nativeCallCount !== 0) {
    throw new Error("Native callback was prematurely called during registerClass! Count: " + nativeCallCount);
}
console.log("[+] Confirmed: JS native methods were NOT executed during registration.");

// 3. Instantiate the class
let instance = TestCls.$new();
console.log("[+] Instance created:", instance);

// 4. Test method execution
let ans = instance.getAnswer();
console.log("[*] getAnswer() =", ans);
if (ans !== 42) throw new Error("Expected 42, got " + ans);

let smaliVal = instance.getSmaliConst();
console.log("[*] getSmaliConst() =", smaliVal);
if (smaliVal !== 0x1337) throw new Error("Expected 0x1337 (4919), got " + smaliVal);

let greeting = instance.getGreeting();
console.log("[*] getGreeting() =", greeting);
if (greeting !== "Hello from Pure Dalvik Bytecode!") {
    throw new Error("Greeting mismatch: " + greeting);
}

let branchTrue = instance.testBranch(1);
console.log("[*] testBranch(1) =", branchTrue);
if (branchTrue !== 777) throw new Error("Expected 777, got " + branchTrue);

let branchFalse = instance.testBranch(0);
console.log("[*] testBranch(0) =", branchFalse);
if (branchFalse !== 999) throw new Error("Expected 999, got " + branchFalse);

let cmpLess = instance.compare(3, 10);
let cmpEq = instance.compare(10, 10);
let cmpGreater = instance.compare(20, 10);
console.log("[*] compare: 3 vs 10 =", cmpLess, ", 10 vs 10 =", cmpEq, ", 20 vs 10 =", cmpGreater);
if (cmpLess !== -1 || cmpEq !== 0 || cmpGreater !== 1) {
    throw new Error("Comparison branch failed: " + cmpLess + ", " + cmpEq + ", " + cmpGreater);
}

let sumStatic = TestCls.staticAdd(15, 27);
console.log("[*] staticAdd(15, 27) =", sumStatic);
if (sumStatic !== 42) throw new Error("Expected 42, got " + sumStatic);

let subStatic = TestCls.staticSub(100, 30);
console.log("[*] staticSub(100, 30) =", subStatic);
if (subStatic !== 70) throw new Error("Expected 70, got " + subStatic);

let loopSum = instance.sumLoop(10);
console.log("[*] sumLoop(10) =", loopSum);
if (loopSum !== 55) throw new Error("Expected 55 (sum of 1..10), got " + loopSum);

// mathFluent(10, 5) => (10 * 5) - (10 + 5) = 50 - 15 = 35
let mathVal = instance.mathFluent(10, 5);
console.log("[*] mathFluent(10, 5) =", mathVal);
if (mathVal !== 35) throw new Error("Expected 35, got " + mathVal);

let wideVal = instance.wideParam(1234567890123n);
console.log("[*] wideParam(1234567890123n) =", wideVal);
if (wideVal !== 42) throw new Error("Expected 42, got " + wideVal);

let nativeSum = instance.addNative(100, 200);
console.log("[*] addNative(100, 200) =", nativeSum);
if (nativeSum !== 300 || nativeCallCount !== 1) {
    throw new Error("Native add failed: sum=" + nativeSum + ", count=" + nativeCallCount);
}

// 5. Test explicit constructor alongside default no-arg constructor
let CtorCls = Java.registerClass({
    name: "com.artpi.test.CustomCtorCls",
    methods: {
        "<init>(I)V": `
            invoke-direct {p0}, Ljava/lang/Object;-><init>()V
            return-void
        `,
        "ping()I": `
            const/4 v0, 88
            return v0
        `
    }
});
let ctorInst = CtorCls.$new();
let pingVal = ctorInst.ping();
console.log("[*] CustomCtorCls.$new().ping() =", pingVal);
if (pingVal !== 88) throw new Error("Expected 88 from CustomCtorCls, got " + pingVal);

// 6. Test error validation suite (none should crash/abort the process!)

// Test 6.1: Unresolved label
let caughtErr = false;
try {
    Java.registerClass({
        name: "com.artpi.test.BadLabel",
        methods: { "fail()V": DexWriter.smali("goto :missing") }
    });
} catch (e) {
    caughtErr = true;
    console.log("[*] Caught expected unresolved label error cleanly:", e.message);
}
if (!caughtErr) throw new Error("Unresolved label did not throw error!");

// Test 6.2: Empty bytecode writer
caughtErr = false;
try {
    Java.registerClass({
        name: "com.artpi.test.EmptyWriter",
        methods: { "fail()V": new DexWriter() }
    });
} catch (e) {
    caughtErr = true;
    console.log("[*] Caught expected empty writer error cleanly:", e.message);
}
if (!caughtErr) throw new Error("Empty writer did not throw error!");

// Test 6.3: Method without terminal return/throw
caughtErr = false;
try {
    Java.registerClass({
        name: "com.artpi.test.MissingReturn",
        methods: { "fail()V": DexWriter.smali("const/4 v0, 0") }
    });
} catch (e) {
    caughtErr = true;
    console.log("[*] Caught expected missing return error cleanly:", e.message);
}
if (!caughtErr) throw new Error("Missing return did not throw error!");

// Test 6.4: Register index out of bounds
caughtErr = false;
try {
    Java.registerClass({
        name: "com.artpi.test.BadReg",
        methods: { "fail()V": DexWriter.smali("return v10") } // default regs is 4, v10 >= 4
    });
} catch (e) {
    caughtErr = true;
    console.log("[*] Caught expected register bounds error cleanly:", e.message);
}
if (!caughtErr) throw new Error("Register bounds check did not throw error!");

// Test 6.5: Invoke with >5 registers rejected cleanly
caughtErr = false;
try {
    Java.registerClass({
        name: "com.artpi.test.TooManyArgs",
        methods: {
            "fail()V": DexWriter.smali(`
                invoke-static {v0, v1, v2, v3, v4, v5}, Ljava/lang/Math;->min(II)I
                return-void
            `)
        }
    });
} catch (e) {
    caughtErr = true;
    console.log("[*] Caught expected >5 args invoke error cleanly:", e.message);
    if (!e.message.includes("invoke register list exceeds DEX limit of 5")) {
        throw new Error("Error message did not include detailed reason: " + e.message);
    }
}
if (!caughtErr) throw new Error("Invoke >5 regs did not throw error!");

// Test 6.6: Invalid signature in DexWriter.smali throws TypeError cleanly
caughtErr = false;
try {
    DexWriter.smali("not_a_valid_signature", "return-void");
} catch (e) {
    caughtErr = true;
    console.log("[*] Caught expected invalid signature error cleanly:", e.message);
}
if (!caughtErr) throw new Error("Invalid signature did not throw error!");

// Test 6.7: Consecutive failure test (verifies error state recovery and ensures
// trap environment / slicer state resets cleanly across repeated failures).
// Note: "return v99" is intercepted early by the pre-assembly register bounds
// validation check before reaching Slicer; RunGuarded longjmp trap serves as the safety net.
for (let i = 0; i < 3; i++) {
    let loopCaught = false;
    try {
        Java.registerClass({
            name: "com.artpi.test.ConsecutiveFail" + i,
            methods: { "fail()V": DexWriter.smali("return v99") }
        });
    } catch (e) {
        loopCaught = true;
    }
    if (!loopCaught) throw new Error("Consecutive failure " + i + " did not throw error!");
}
console.log("[+] Consecutive failure tests passed cleanly, state recovered cleanly!");

// Test 6.8: Verify valid registration still works perfectly after consecutive errors
let RecoveryCls = Java.registerClass({
    name: "com.artpi.test.RecoveryCls",
    methods: {
        "ok()I": `
            const/4 v0, 100
            return v0
        `
    }
});
let recInst = RecoveryCls.$new();
if (recInst.ok() !== 100) throw new Error("RecoveryCls failed after consecutive errors!");
console.log("[+] Post-failure recovery registration and invocation verified!");

console.log("[+] ====== ALL DEXWRITER TESTS PASSED SUCCESSFULLY! ======");
