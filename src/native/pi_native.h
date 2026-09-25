//
// pi_native.h - Runtime Native ARM64 Disassembler, Symbol Resolver & CFG Flow
//
#ifndef PI_NATIVE_H
#define PI_NATIVE_H

#include "pi_common.h"
#include <cstdint>
#include <string>

namespace PI {

/**
 * Dump native ARM64 machine instructions for a native ArtMethod or raw code address.
 * Includes leftmost CFG jump graph and symbol resolution via xDL and Frida-Gum.
 *
 * @param native_pc The native machine code entry address.
 * @param max_instructions Maximum number of instructions to disassemble (-1 for automatic boundary).
 * @param method Optional associated ArtMethod for full signature display.
 * @return Formatted multi-line ARM64 disassembly string with CFG arrows.
 */
std::string dumpNative(const void* native_pc, int max_instructions, ArtMethod* method, uintptr_t highlight_pc);
std::string dumpNative(ArtMethod* method, int max_instructions);

/**
 * Attempt to bind an unbound native ArtMethod (whose entry is art_jni_dlsym_lookup_stub).
 * Uses two-stage resolution:
 *   Stage 1: JNI symbol synthesis + loaded ELF module scan (zero risk).
 *   Stage 2: Safe reflection invocation with dummy args & Unsafe dummy receiver (fallback).
 *
 * @param method The native ArtMethod to bind.
 * @param env Optional JNIEnv pointer.
 * @return The resolved native function address, or nullptr if unresolved.
 */
void* resolveNativeMethod(ArtMethod* method, JNIEnv* env);

/**
 * Resolve "ret package.Class.method(params)" for any ArtMethod via libart PrettyMethod.
 * Returns empty string if the symbol is unavailable.
 */
std::string getPrettyMethodSignature(ArtMethod* method);

/**
 * Checks if entry is art_jni_dlsym_lookup_stub.
 */
bool isDlsymLookupStub(void* entry);

/**
 * Resolves a native code address to "; <module!symbol+offset>" or "; <module+offset>".
 */
std::string resolveAddressSymbol(uintptr_t addr);

/**
 * Demangle an Itanium C++ symbol name (e.g. "_Z34...").
 */
std::string demangle(const char* mangled);
std::string demangle(const std::string& mangled);

} // namespace PI

#endif // PI_NATIVE_H
