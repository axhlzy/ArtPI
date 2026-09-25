//
// pi_code_provider.cpp - L1 CodeProvider implementation
//

#include "pi_code_provider.h"
#include "art/art_method.h"
#include <cstring>
#include <algorithm>

namespace PI {

// ============================================================================
// encoded_catch_handler_list walker: returns the byte length of the list
// starting at `p`. Layout (dex spec):
//   uleb128  size  (number of handlers)
//   encoded_catch_handler[size]:
//     sleb128  size  (positive = typed handlers only,
//                     negative = typed handlers + catch-all)
//     encoded_type_addr_pair[abs(size)]:
//       uleb128 type_idx
//       uleb128 address
//     if size <= 0: uleb128 catch_all_addr
// ============================================================================
static size_t measureCatchHandlerList(const uint8_t* p) {
    const uint8_t* start = p;
    auto readUleb = [](const uint8_t** ptr) -> uint32_t {
        uint32_t result = 0; int shift = 0;
        do {
            uint8_t b = *(*ptr)++;
            result |= static_cast<uint32_t>(b & 0x7F) << shift;
            if ((b & 0x80) == 0) break;
            shift += 7;
        } while (shift < 35);
        return result;
    };
    auto readSleb = [](const uint8_t** ptr) -> int32_t {
        int32_t result = 0; int shift = 0; uint8_t b;
        do {
            b = *(*ptr)++;
            result |= static_cast<int32_t>(b & 0x7F) << shift;
            shift += 7;
        } while ((b & 0x80) != 0);
        if (shift < 32 && (b & 0x40) != 0) result |= -(1 << shift);
        return result;
    };

    uint32_t handlers = readUleb(&p);
    if (handlers > 0x10000u) return 0;  // sanity
    for (uint32_t i = 0; i < handlers; i++) {
        int32_t count = readSleb(&p);
        uint32_t n = static_cast<uint32_t>(count < 0 ? -count : count);
        if (n > 0x10000u) return 0;
        for (uint32_t j = 0; j < n; j++) {
            readUleb(&p);  // type_idx
            readUleb(&p);  // address
        }
        if (count <= 0) readUleb(&p);  // catch_all_addr
    }
    return static_cast<size_t>(p - start);
}

// ============================================================================
// StandardDex code_item layout (all offsets in bytes from code_item):
//   +0  u2 registers_size
//   +2  u2 ins_size
//   +4  u2 outs_size
//   +6  u2 tries_size
//   +8  u4 debug_info_off
//   +12 u4 insns_size (in 16-bit code units)
//   +16 u2 insns[insns_size]
//       (2 bytes padding if insns_size is odd, to keep 4-byte alignment)
//       try_item[tries_size]   each: u4 start_addr, u2 insn_count, u2 handler_off
//       encoded_catch_handler_list
// ============================================================================
static bool buildStandardCodeItem(const uint8_t* ci, InterpCode& out) {
    out.registersSize = *reinterpret_cast<const uint16_t*>(ci + 0);
    out.insSize       = *reinterpret_cast<const uint16_t*>(ci + 2);
    out.outsSize      = *reinterpret_cast<const uint16_t*>(ci + 4);
    uint16_t triesSize = *reinterpret_cast<const uint16_t*>(ci + 6);
    out.insnsCount    = *reinterpret_cast<const uint32_t*>(ci + 12);
    const uint16_t* insns = reinterpret_cast<const uint16_t*>(ci + 16);

    if (out.insnsCount == 0 || out.registersSize == 0) return false;
    out.insnsPtr = insns;
    out.insnsBuf.clear();  // zero-copy for StandardDex

    if (triesSize == 0) {
        out.hasTries = false;
        out.triesPtr = nullptr;
        return true;
    }

    // tries start: right after insns, 4-byte aligned (2-byte padding when
    // insns_size is odd). NOTE: there is NO extra size field here — the
    // try_item[] array starts directly (tries_size comes from the
    // code_item header at +6), followed by encoded_catch_handler_list.
    uintptr_t triesAddr = reinterpret_cast<uintptr_t>(insns) +
                          static_cast<uintptr_t>(out.insnsCount) * 2u;
    triesAddr = (triesAddr + 3u) & ~static_cast<uintptr_t>(3u);
    const uint8_t* tryItems = reinterpret_cast<const uint8_t*>(triesAddr);

    const uint8_t* handlerList = tryItems + static_cast<size_t>(triesSize) * 8u;
    size_t handlerBytes = measureCatchHandlerList(handlerList);
    if (handlerBytes == 0) {
        PI_LOGW("CodeProvider: failed to measure catch handler list, dropping tries");
        out.hasTries = false;
        out.triesPtr = nullptr;
        return true;
    }

    // Repack into nmmvm layout: {u2 triesSize, u2 unused, TryItem[], handlers}
    out.triesBuf.resize(4u + static_cast<size_t>(triesSize) * 8u + handlerBytes);
    uint8_t* dst = out.triesBuf.data();
    *reinterpret_cast<uint16_t*>(dst + 0) = triesSize;
    *reinterpret_cast<uint16_t*>(dst + 2) = 0;  // padding
    std::memcpy(dst + 4, tryItems, static_cast<size_t>(triesSize) * 8u);
    std::memcpy(dst + 4u + static_cast<size_t>(triesSize) * 8u, handlerList, handlerBytes);

    out.hasTries = true;
    out.triesPtr = out.triesBuf.data();
    return true;
}

// ============================================================================
// CompactDex code_item layout (art/libdexfile/dex/compact_dex_file.h):
//   +0  u2 fields: registers_size [15:12] | ins_size [11:8] | outs_size [7:4]
//                  | preheader_size [3:0]
//   +2  u2 insns_count_and_flags: count = value >> 5
//   +4  u2 insns[insns_count]  (may not be 4-byte aligned -> copy)
//
// CompactDex stores tries after insns, but the exact alignment / preheader
// handling is version dependent; until that is fully verified we drop the
// exception table for CompactDex (the interpreter still runs, exceptions
// simply propagate to the caller instead of matching in-method handlers).
// ============================================================================
static bool buildCompactCodeItem(const uint8_t* ci, InterpCode& out) {
    uint16_t fields = *reinterpret_cast<const uint16_t*>(ci + 0);
    uint16_t insnsCountAndFlags = *reinterpret_cast<const uint16_t*>(ci + 2);
    out.registersSize = (fields >> 12) & 0xF;
    out.insSize       = (fields >> 8) & 0xF;
    out.outsSize      = (fields >> 4) & 0xF;
    out.insnsCount    = insnsCountAndFlags >> 5;

    if (out.insnsCount == 0 || out.registersSize == 0) return false;

    out.insnsBuf.assign(out.insnsCount, 0);
    std::memcpy(out.insnsBuf.data(), ci + 4,
                static_cast<size_t>(out.insnsCount) * 2u);
    out.insnsPtr = out.insnsBuf.data();

    out.hasTries = false;
    out.triesPtr = nullptr;
    PI_LOGD("CodeProvider: CompactDex code_item, tries dropped (registers=%u ins=%u insns=%u)",
            out.registersSize, out.insSize, out.insnsCount);
    return true;
}

bool buildVmCode(JNIEnv* env, ArtMethod* method, const DexResolver& dex,
                 InterpCode& out) {
    (void) env;
    // manual reset: vmCode holds const members -> no assignable InterpCode
    out.regs.clear();
    out.regFlags.clear();
    out.triesBuf.clear();
    out.insnsBuf.clear();
    out.insnsPtr = nullptr;
    out.triesPtr = nullptr;
    out.registersSize = 0;
    out.insSize = 0;
    out.outsSize = 0;
    out.insnsCount = 0;
    out.hasTries = false;
    out.isCompactDex = false;
    out.isCompactDex = dex.isCompactDex();

    if (method == nullptr) {
        PI_LOGE("CodeProvider: method is null");
        return false;
    }
    if (method->IsNative()) {
        PI_LOGE("CodeProvider: method is native, no bytecode");
        return false;
    }
    if (method->HasAccessFlags(0x0400)) {  // ACC_ABSTRACT
        PI_LOGE("CodeProvider: method is abstract, no bytecode");
        return false;
    }

    // code_item lives in entry_point_from_jni_ for non-native methods
    // (Android 10+: raw pointer, bit0 = quickened flag). Same trick as pi_smali.cpp.
    void* dataPtr = method->GetEntryPointFromJni();
    const uint8_t* codeItem =
        reinterpret_cast<const uint8_t*>(reinterpret_cast<uintptr_t>(dataPtr) & ~1ULL);
    if (codeItem == nullptr) {
        PI_LOGE("CodeProvider: code_item is null");
        return false;
    }

    bool ok = out.isCompactDex ? buildCompactCodeItem(codeItem, out)
                               : buildStandardCodeItem(codeItem, out);
    if (!ok) {
        PI_LOGE("CodeProvider: failed to parse %s code_item at %p",
                out.isCompactDex ? "CompactDex" : "StandardDex", codeItem);
        return false;
    }

    // register file (u64 per slot, matching nmmvm regptr_t)
    out.regs.assign(out.registersSize, 0);
    out.regFlags.assign(out.registersSize, 0);

    // assemble the final vmCode (members are const -> aggregate init via
    // placement-new over the existing trivial object)
    new (&out.code) vmCode{
        .insns         = out.insnsPtr,
        .insnsSize     = out.insnsCount,
        .regs          = out.regs.data(),
        .reg_flags     = out.regFlags.data(),
        .triesHandlers = out.hasTries ? out.triesPtr : nullptr,
    };
    return true;
}

} // namespace PI
