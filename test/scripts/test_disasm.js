let addr = findSymbol("libc.so", "open") || findSymbol("libart.so", "JNI_CreateJavaVM");
console.log("[*] addr =", addr);
if (addr) {
    let out = disassembly(addr, 6);
    console.log("[+] disassembly(addr, 6):\n" + out);
}
