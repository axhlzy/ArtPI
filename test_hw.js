console.log("[test] Starting HWBreakpoint test on stringFromJNI...");

var sym = Process.findSymbol("liboattest.so", "Java_com_axhlzy_oattest_MainActivity_stringFromJNI");
console.log("[test] Symbol Java_com_axhlzy_oattest_MainActivity_stringFromJNI -> " + sym);

var hitCount = 0;
var bp = HWBreakpoint.attach("liboattest.so!Java_com_axhlzy_oattest_MainActivity_stringFromJNI", {
    onEnter: function(ctx) {
        hitCount++;
        console.log("\n==============================================");
        console.log("[+] [HWBreakpoint HIT #" + hitCount + "] stringFromJNI entered!");
        console.log("[+] PC: 0x" + ctx.pc.toString(16));
        console.log("[+] SP: 0x" + ctx.sp.toString(16));
        console.log("[+] LR: 0x" + ctx.lr.toString(16));
        console.log("[+] Thread ID: " + ctx.threadId);
        console.log("[+] Slot: " + ctx.slot);
        console.log("[+] JNIEnv (x0): 0x" + ctx.x0.toString(16));
        console.log("[+] jobject (x1): 0x" + ctx.x1.toString(16));
        console.log("==============================================\n");
    }
});

console.log("[test] HWBreakpoint attached! id=" + bp.id + ", slot=" + bp.slot);
console.log("[test] HWBreakpoint list: " + JSON.stringify(HWBreakpoint.list()));
