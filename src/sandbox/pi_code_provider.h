//
// pi_code_provider.h - L1 CodeProvider
//
// Builds a nmmvm `vmCode` from a runtime ArtMethod:
//   - parses the in-memory code_item (StandardDex + CompactDex, same layout
//     knowledge as pi_smali.cpp)
//   - repacks the tries/handler section into the layout expected by
//     nmmvm's vm/DexCatch.h ({u2 triesSize, u2 unused, TryItem[], handlers})
//   - allocates the register file (regptr_t = u64 per slot) and object flags
//
// The InterpCode object owns every pointer inside vmCode and must outlive
// the vmInterpret() call that consumes it.
//

#ifndef PI_CODE_PROVIDER_H
#define PI_CODE_PROVIDER_H

#include "pi_common.h"
#include "dex/pi_dex_resolver.h"

// nmmvm public ABI (vmInterpret / vmCode / vmResolver)
#include "vm.h"

namespace PI {

struct InterpCode {
    vmCode code{};

    std::vector<regptr_t>  regs;       // register file, 1 x u64 per slot
    std::vector<uint8_t>   regFlags;   // 1 = slot holds a jobject local ref
    std::vector<uint8_t>   triesBuf;   // repacked TryCatchHandler block
    std::vector<uint16_t>  insnsBuf;   // CompactDex: aligned copy of insns

    const uint16_t* insnsPtr = nullptr;  // zero-copy (StandardDex) or insnsBuf
    const uint8_t*  triesPtr = nullptr;  // points into triesBuf

    uint16_t registersSize = 0;
    uint16_t insSize       = 0;
    uint16_t outsSize      = 0;
    uint32_t insnsCount    = 0;
    bool     hasTries      = false;
    bool     isCompactDex  = false;
};

// Parse the code_item of a non-native / non-abstract method.
// Registers are NOT packed here (see pi_smali_runner.cpp for arg packing).
// Returns false (and logs) when the method has no interpretable body.
bool buildVmCode(JNIEnv* env, ArtMethod* method, const DexResolver& dex,
                 InterpCode& out);

} // namespace PI

#endif // PI_CODE_PROVIDER_H
