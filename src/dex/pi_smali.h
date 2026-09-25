//
// pi_smali.h - Runtime Dalvik Smali disassembler for ArtMethod
//

#ifndef PI_SMALI_H
#define PI_SMALI_H

#include "pi_common.h"
#include "../native/pi_native.h"

namespace PI {

/**
 * Dump the Smali bytecode instructions of the specified ArtMethod as a formatted string.
 * @param method The target ArtMethod.
 * @param max_instructions Maximum number of instructions to disassemble (-1 for all).
 * @return Formatted multi-line Smali bytecode representation.
 */
std::string dumpSmali(ArtMethod* method, int max_instructions);
std::string dumpSmali(ArtMethod* method, int max_instructions, int highlight_pc);

/**
 * Format ONLY the single instruction located at bytecode offset `pc` (in 16-bit
 * code units), in the same style as a dumpSmali line, e.g.:
 *   "[0x0002] 2071 91a3 0004  |  invoke-static {v4, v0}, void ..."
 * Returns "" if the method has no code body or `pc` is out of range.
 * Cheap enough to call per-instruction from a tracer (does NOT walk the whole method).
 */
std::string dumpSmaliInsn(ArtMethod* method, uint32_t pc);

/**
 * Unified code dumper: dispatches to dumpNative if method is native, else dumpSmali.
 */
std::string dumpCode(ArtMethod* method, int max_instructions);

/**
 * Format a single instruction in the same style as dumpSmali lines:
 *   "0x0029 021a 00a2 |  const-string v2, \"ZZZ\" // string@162"
 * Falls back to opcode-name/op_0xNN when libdexfile symbols are unavailable.
 * @param insn        pointer at the instruction (16-bit code units)
 * @param artDexFile  the art::DexFile* backing `insn` (for operand resolution)
 */
std::string formatSingleInstruction(const uint16_t* insn, const void* artDexFile);

/**
 * dalvik instruction length table (256 entries, in 16-bit code units).
 */
const uint8_t* instructionSizeTable();

/**
 * Print the Smali bytecode instructions of the specified ArtMethod to Android Logcat.
 * @param method The target ArtMethod.
 * @param max_instructions Maximum number of instructions to disassemble (-1 for all).
 * @param tag Android logcat tag (defaults to "PI_SMALI").
 */
void showSmali(ArtMethod* method, int max_instructions = -1, const char* tag = "PI_SMALI");

} // namespace PI

#endif // PI_SMALI_H
