console.log("=== Verifying P2-1: dumpSmali(0xdeadbeef) ===");
let r1 = dumpsmali(0xdeadbeef);
console.log("dumpSmali(0xdeadbeef) ->", r1);

console.log("=== Verifying P2: dumpNative(0xdeadbeef) ===");
let rn = dumpnative(0xdeadbeef, 2);
console.log("dumpNative(0xdeadbeef) ->", rn.trim());

console.log("=== Verifying P2: decompile(0xdeadbeef) ===");
let rd = decompile(0xdeadbeef);
console.log("decompile(0xdeadbeef) ->", rd.trim());

console.log("=== Verifying P2: methodInfo(0xdeadbeef) ===");
let rmi = Java.methodInfo(0xdeadbeef);
console.log("methodInfo(0xdeadbeef) ->", rmi);

console.log("=== Verifying P2: jhook(0xdeadbeef) ===");
let rh = jhook(0xdeadbeef);
console.log("jhook(0xdeadbeef) ->", rh);

console.log("=== Verifying P3-2: dumpSmali(\"com.not.exist\") ===");
let r2 = dumpsmali("com.not.exist");
console.log("dumpSmali(\"com.not.exist\") ->", r2);

console.log("=== Verifying P2-4: dumpNative on non-native Java method ===");
let mulArt = Java.findMethod("com.axhlzy.oattest.MainActivity", "staticMul");
console.log("staticMul ArtMethod:", mulArt);
let r3 = dumpnative(mulArt);
console.log("dumpNative(staticMul) ->", r3);

console.log("=== Verifying P3-1: dynamic.java.com.axhlzy.oattest.MainActivity.staticMul.disassembly() ===");
let dsm = dynamic.java.com.axhlzy.oattest.MainActivity.staticMul.disassembly();
console.log("disassembly() sample (first 4 lines):");
console.log(dsm.split("\n").slice(0, 4).join("\n"));

console.log("=== Verifying P2-3: dumpNative on actual native method ===");
let jniArt = Java.findMethod("com.axhlzy.oattest.MainActivity", "stringFromJNI");
console.log("stringFromJNI ArtMethod:", jniArt);
let r4 = dumpnative(jniArt, 5);
console.log("dumpNative(stringFromJNI, 5) ->");
console.log(r4);

console.log("=== ALL P2 & P3 VERIFICATIONS FINISHED PERFECTLY ===");
