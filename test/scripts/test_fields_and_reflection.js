// =========================================================================
// ArtPI Test: Static & Instance Fields + Reflection in Java.registerClass
// Note:
//   - Tests 1-3 test registered fields & bytecode access (universal).
//   - Tests 4-5 test interop with the local sample app (com.axhlzy.oattest.MainActivity).
//     When running against another target package, adapt or skip Tests 4 & 5.
// =========================================================================
console.log("[*] ====== Testing Fields & Reflection in Java.registerClass ======");

let TestFieldCls = Java.registerClass({
    name: "com.artpi.demo.InvokerBridgeV2",
    fields: {
        // Static field with literal initial value
        "staticGreeting": { type: "java.lang.String", value: "Hello from Registered Field!", static: true },
        // Static integer field
        "magicNumber": { type: "int", value: 9999, static: true },
        // Instance field (integer)
        "counter": { type: "int", static: false }
    },
    methods: {
        // 1. Read static field via Smali sget-object
        "getStaticGreeting()Ljava/lang/String;": `
            sget-object v0, Lcom/artpi/demo/InvokerBridgeV2;->staticGreeting:Ljava/lang/String;
            return-object v0
        `,

        // 2. Read and modify static field via Smali sget / sput
        "addMagic(I)I": `
            sget v0, Lcom/artpi/demo/InvokerBridgeV2;->magicNumber:I
            add-int v0, v0, p1
            sput v0, Lcom/artpi/demo/InvokerBridgeV2;->magicNumber:I
            return v0
        `,

        // 3. Write and read instance field via Smali iput / iget
        "setAndGetCounter(I)I": `
            iput p1, p0, Lcom/artpi/demo/InvokerBridgeV2;->counter:I
            iget v0, p0, Lcom/artpi/demo/InvokerBridgeV2;->counter:I
            return v0
        `,

        // 4. Call target app's existing method directly via Smali invoke-static
        "callAppStaticMul(II)I": `
            invoke-static {p1, p2}, Lcom/axhlzy/oattest/MainActivity;->staticMul(II)I
            move-result v0
            return v0
        `,

        // 5. Call target app's existing method via Java Reflection in Smali
        "callAppViaReflection(Ljava/lang/Object;)Ljava/lang/String;": `
            # Class.forName("com.axhlzy.oattest.MainActivity")
            const-string v0, "com.axhlzy.oattest.MainActivity"
            invoke-static {v0}, Ljava/lang/Class;->forName(Ljava/lang/String;)Ljava/lang/Class;
            move-result-object v0

            # getMethod("stringFromJNI", null)
            const-string v1, "stringFromJNI"
            const/4 v2, 0
            invoke-virtual {v0, v1, v2}, Ljava/lang/Class;->getMethod(Ljava/lang/String;[Ljava/lang/Class;)Ljava/lang/reflect/Method;
            move-result-object v1

            # method.invoke(targetInstance, null)
            invoke-virtual {v1, p1, v2}, Ljava/lang/reflect/Method;->invoke(Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;
            move-result-object v0

            check-cast v0, Ljava/lang/String;
            return-object v0
        `
    }
});

console.log("[+] TestFieldCls registered successfully:", TestFieldCls);

let inst = TestFieldCls.$new();
console.log("[+] Instance created:", inst);

// Test 1: Static greeting
let greeting = inst.getStaticGreeting();
console.log("[*] getStaticGreeting() =", greeting);
if (greeting !== "Hello from Registered Field!") throw new Error("Unexpected static field value!");

// Test 2: Static integer calculation
let initialMag = inst.addMagic(0);
let mag1 = inst.addMagic(1);
console.log("[*] initialMag =", initialMag, "addMagic(1) =", mag1);
if (mag1 !== initialMag + 1) throw new Error("Unexpected static field update!");

let mag2 = inst.addMagic(50);
console.log("[*] addMagic(50) =", mag2);
if (mag2 !== mag1 + 50) throw new Error("Unexpected static field update 2!");

// Test 3: Instance field
let c1 = inst.setAndGetCounter(77);
console.log("[*] setAndGetCounter(77) =", c1);
if (c1 !== 77) throw new Error("Unexpected instance field value!");

let inst2 = TestFieldCls.$new();
let c2 = inst2.setAndGetCounter(999);
console.log("[*] inst2 counter =", c2, "inst1 counter still =", inst.setAndGetCounter(77));
if (c2 !== 999) throw new Error("Instance fields isolated check failed!");

// Test 4: Direct call to app's MainActivity.staticMul(6, 7)
let mulDirect = inst.callAppStaticMul(6, 7);
console.log("[*] callAppStaticMul(6, 7) [Direct App Call] =", mulDirect);
if (mulDirect !== 172171) throw new Error("callAppStaticMul failed! Got: " + mulDirect);

// Test 5: Reflection call to app's MainActivity.stringFromJNI()
let targetAct = null;
Java.choose("com.axhlzy.oattest.MainActivity", {
    onMatch: function(instance) {
        targetAct = instance;
        return "stop";
    }
});
console.log("[*] Java.choose targetAct:", targetAct);
if (targetAct) {
    let strReflect = inst.callAppViaReflection(targetAct);
    console.log("[*] callAppViaReflection(targetAct) [Java Reflection Call] =", strReflect);
    if (typeof strReflect !== 'string' || strReflect.length === 0) throw new Error("callAppViaReflection failed!");
}

console.log("[+] ====== ALL FIELDS & REFLECTION TESTS PASSED PERFECTLY! ======");
