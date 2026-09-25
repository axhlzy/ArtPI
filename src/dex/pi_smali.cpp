//
// pi_smali.cpp - Runtime Dalvik Smali disassembler implementation
//

#include "pi_smali.h"
#include "../native/pi_native.h"
#include "art/art_method.h"
#include "utils/elf_image.h"
#include "xdl.h"
#include <cstring>
#include <sstream>
#include <iomanip>
#include <mutex>
#include <cxxabi.h>
#include <map>
#include <algorithm>
#include <vector>

namespace PI {

static const uint8_t kInstructionSizes[256] = {
    1, 1, 2, 3, 1, 2, 3, 1, 2, 3, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 2, 3, 2, 2, 3, 5, 2, 2, 3, 2, 1, 1, 2,
    2, 1, 2, 2, 3, 3, 3, 1, 1, 2, 3, 3, 3, 2, 2, 2,
    2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 1, 1,
    1, 1, 1, 1, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
    2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
    2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 3, 3,
    3, 3, 3, 1, 3, 3, 3, 3, 3, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
    2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
    2, 2, 2, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 4, 4, 3, 3, 2, 2,
};

#include "frida-gum.h"
#include <vector>

// Typedef for art::Instruction::DumpString(const DexFile*) const
typedef std::string (*DumpStringFn)(const void* insn, const void* dex_file);
typedef std::string (*PrettyMethodFn)(void* insn, bool with_sig);

static DumpStringFn g_dump_string_fn = nullptr;
static const char* const* g_instruction_names = nullptr;
static PrettyMethodFn g_pretty_method_fn = nullptr;
static bool g_symbols_initialized = false;
static std::mutex g_init_mutex;

static void EnsureSymbolsInitialized() {
    if (g_symbols_initialized) return;
    std::lock_guard<std::mutex> lock(g_init_mutex);
    if (g_symbols_initialized) return;

    // 1. Primary: Use xDL to open libdexfile.so (bypasses Android 7+ namespace restrictions)
    void* handle = xdl_open("libdexfile.so", XDL_DEFAULT);
    if (!handle) {
        handle = xdl_open("/apex/com.android.art/lib64/libdexfile.so", XDL_DEFAULT);
    }
    if (!handle) {
        handle = xdl_open("/apex/com.android.art/lib/libdexfile.so", XDL_DEFAULT);
    }
    if (handle) {
        g_dump_string_fn = reinterpret_cast<DumpStringFn>(
            xdl_sym(handle, "_ZNK3art11Instruction10DumpStringEPKNS_7DexFileE", nullptr)
        );
        g_instruction_names = reinterpret_cast<const char* const*>(
            xdl_sym(handle, "_ZN3art11Instruction17kInstructionNamesE", nullptr)
        );
        xdl_close(handle);
    }

    // 2. Fallback to ElfImage if xDL didn't find them
    if (!g_dump_string_fn || !g_instruction_names) {
        pine::ElfImage dexfile_elf("libdexfile.so", false, false);
        if (dexfile_elf.IsOpened()) {
            if (!g_dump_string_fn) {
                g_dump_string_fn = reinterpret_cast<DumpStringFn>(
                    dexfile_elf.GetSymbolAddress("_ZNK3art11Instruction10DumpStringEPKNS_7DexFileE", false)
                );
            }
            if (!g_instruction_names) {
                g_instruction_names = reinterpret_cast<const char* const*>(
                    dexfile_elf.GetSymbolAddress("_ZN3art11Instruction17kInstructionNamesE", false)
                );
            }
        }
    }

    // 3. Resolve PrettyMethod from libart.so
    void* h_art = xdl_open("libart.so", XDL_DEFAULT);
    if (!h_art) h_art = xdl_open("/apex/com.android.art/lib64/libart.so", XDL_DEFAULT);
    if (!h_art) h_art = xdl_open("/apex/com.android.art/lib/libart.so", XDL_DEFAULT);
    if (!h_art) h_art = xdl_open("/system/lib64/libart.so", XDL_DEFAULT);
    if (h_art) {
        g_pretty_method_fn = reinterpret_cast<PrettyMethodFn>(
            xdl_sym(h_art, "_ZN3art9ArtMethod12PrettyMethodEPS0_b", nullptr)
        );
        if (!g_pretty_method_fn) {
            g_pretty_method_fn = reinterpret_cast<PrettyMethodFn>(
                xdl_sym(h_art, "_ZN3art9ArtMethod12PrettyMethodEb", nullptr)
            );
        }
        xdl_close(h_art);
    }

    if (!g_pretty_method_fn) {
        pine::ElfImage art_elf("libart.so", false, false);
        if (art_elf.IsOpened()) {
            g_pretty_method_fn = reinterpret_cast<PrettyMethodFn>(
                art_elf.GetSymbolAddress("_ZN3art9ArtMethod12PrettyMethodEPS0_b", false)
            );
            if (!g_pretty_method_fn) {
                g_pretty_method_fn = reinterpret_cast<PrettyMethodFn>(
                    art_elf.GetSymbolAddress("_ZN3art9ArtMethod12PrettyMethodEb", false)
                );
            }
        }
    }

    PI_LOGI("PI Smali disassembler init: DumpString=%p, kInstructionNames=%p, PrettyMethod=%p",
            reinterpret_cast<void*>(g_dump_string_fn),
            reinterpret_cast<const void*>(g_instruction_names),
            reinterpret_cast<void*>(g_pretty_method_fn));

    g_symbols_initialized = true;
}

static std::string PrettyAccessFlags(uint32_t flags) {
    std::string s;
    auto append = [&](const char* name) {
        if (!s.empty()) s += " ";
        s += name;
    };

    if (flags & 0x0001) append("public");
    if (flags & 0x0002) append("private");
    if (flags & 0x0004) append("protected");
    if (flags & 0x0008) append("static");
    if (flags & 0x0010) append("final");
    if (flags & 0x0020) append("synchronized");
    if (flags & 0x0040) append("bridge");
    if (flags & 0x0080) append("varargs");
    if (flags & 0x0100) append("native");
    if (flags & 0x0200) append("interface");
    if (flags & 0x0400) append("abstract");
    if (flags & 0x0800) append("strictfp");
    if (flags & 0x1000) append("synthetic");
    if (flags & 0x00010000) append("constructor");
    if (flags & 0x00020000) append("declared-synchronized");

    return s.empty() ? "package-private" : s;
}

static std::string GetMethodFullName(ArtMethod* method, uint32_t flags) {
    std::string pretty;
    if (g_pretty_method_fn) {
        pretty = g_pretty_method_fn(method, true);
    }
    std::string access = PrettyAccessFlags(flags);
    if (pretty.empty()) {
        char buf[64];
        snprintf(buf, sizeof(buf), "Method@%p", method);
        return access.empty() ? buf : (access + " " + buf);
    }
    return access.empty() ? pretty : (access + " " + pretty);
}

std::string dumpSmali(ArtMethod* method, int max_instructions) {
    return dumpSmali(method, max_instructions, -1);
}

std::string dumpSmali(ArtMethod* method, int max_instructions, int highlight_pc) {
    if (!method) {
        return "[PI Smali] Error: ArtMethod is null\n";
    }

    EnsureSymbolsInitialized();

    std::ostringstream ss;
    ss << "======================================================================\n";
    uint32_t flags = method->GetAccessFlags();
    ss << "  " << GetMethodFullName(method, flags) << "\n";
    ss << "  ArtMethod=" << reinterpret_cast<void*>(method)
       << " | AccessFlags: 0x" << std::hex << flags << std::dec
       << " (" << PrettyAccessFlags(flags) << ")\n";

    if (method->IsNative()) {
        ss << "  [!] Method is Native (JNI). Machine code is in native library, no Dex Smali bytecode.\n";
        ss << "      Hint: Use dumpCode(...) or dumpNative(...) to disassemble native ARM64 instructions.\n";
        ss << "======================================================================\n";
        return ss.str();
    }
    if (method->HasAccessFlags(0x0400)) {
        ss << "  [!] Method is Abstract (no code body).\n";
        ss << "======================================================================\n";
        return ss.str();
    }

    // Step 1: mirror::Class*
    uint32_t klass_ref = method->GetDeclaringClass();
    if (!klass_ref) {
        ss << "  [!] Error: Declaring Class is null\n";
        ss << "======================================================================\n";
        return ss.str();
    }
    void* klass = reinterpret_cast<void*>(static_cast<uintptr_t>(klass_ref));

    // Step 2: mirror::DexCache* (Class + 0x10)
    uint32_t dex_cache_ref = *reinterpret_cast<uint32_t*>(static_cast<uint8_t*>(klass) + 0x10);
    if (!dex_cache_ref) {
        ss << "  [!] Error: DexCache is null\n";
        ss << "======================================================================\n";
        return ss.str();
    }
    void* dex_cache = reinterpret_cast<void*>(static_cast<uintptr_t>(dex_cache_ref));

    // Step 3: art::DexFile* (DexCache + 0x10)
    const void* dex_file = *reinterpret_cast<const void* const*>(static_cast<const uint8_t*>(dex_cache) + 0x10);
    if (!dex_file) {
        ss << "  [!] Error: DexFile is null\n";
        ss << "======================================================================\n";
        return ss.str();
    }

    // DexFile layout
    const uint8_t* dex_begin = *reinterpret_cast<const uint8_t* const*>(static_cast<const uint8_t*>(dex_file) + 0x08);
    size_t dex_size = *reinterpret_cast<const size_t*>(static_cast<const uint8_t*>(dex_file) + 0x10);
    const uint8_t* dex_data_begin = *reinterpret_cast<const uint8_t* const*>(static_cast<const uint8_t*>(dex_file) + 0x18);
    bool is_compact = (dex_begin && std::memcmp(dex_begin, "cdex", 4) == 0);

    // If dex_size is 0, read from DEX / CompactDex Header at offset 0x20 (uint32_t file_size_)
    const uint8_t* header_base = dex_data_begin ? dex_data_begin : dex_begin;
    if (header_base) {
        if (std::memcmp(header_base, "dex\n", 4) == 0 || std::memcmp(header_base, "cdex", 4) == 0) {
            uint32_t header_file_size = *reinterpret_cast<const uint32_t*>(header_base + 0x20);
            if (header_file_size > 0 && (dex_size == 0 || dex_size < header_file_size)) {
                dex_size = header_file_size;
            }
        }
    }

    ss << "  DEX: " << dex_file << " (" << (is_compact ? "CompactDex" : "StandardDex")
       << ") | DataBegin: " << reinterpret_cast<const void*>(dex_data_begin)
       << " | Size: " << dex_size << " bytes\n";

    // Step 4: CodeItem
    // In Android 10+, for non-native methods, data_ directly points to CodeItem (& ~1)
    void* data_ptr = method->GetEntryPointFromJni();
    const uint8_t* code_item = reinterpret_cast<const uint8_t*>(reinterpret_cast<uintptr_t>(data_ptr) & ~1ULL);

    if (!code_item) {
        ss << "  [!] Error: CodeItem pointer is null\n";
        ss << "======================================================================\n";
        return ss.str();
    }

    ss << "  CodeItem: " << reinterpret_cast<const void*>(code_item) << "\n";

    uint32_t insns_count = 0;
    const uint16_t* insns = nullptr;
    uint16_t registers_size = 0;
    uint16_t ins_size = 0;
    uint16_t outs_size = 0;

    if (is_compact) {
        // CompactDex layout
        uint16_t fields = *reinterpret_cast<const uint16_t*>(code_item);
        uint16_t insns_count_and_flags = *reinterpret_cast<const uint16_t*>(code_item + 2);
        registers_size = (fields >> 12) & 0xF;
        ins_size = (fields >> 8) & 0xF;
        outs_size = (fields >> 4) & 0xF;
        insns_count = insns_count_and_flags >> 5;
        insns = reinterpret_cast<const uint16_t*>(code_item + 4);
    } else {
        // StandardDex layout
        registers_size = *reinterpret_cast<const uint16_t*>(code_item + 0);
        ins_size = *reinterpret_cast<const uint16_t*>(code_item + 2);
        outs_size = *reinterpret_cast<const uint16_t*>(code_item + 4);
        insns_count = *reinterpret_cast<const uint32_t*>(code_item + 12);
        insns = reinterpret_cast<const uint16_t*>(code_item + 16);
    }

    ss << "  .registers " << registers_size << "  # ins=" << ins_size << ", outs=" << outs_size
       << ", insns_code_units=" << insns_count << "\n";
    ss << "----------------------------------------------------------------------\n";

    struct SmaliLine {
        uint32_t offset = 0;
        std::string text;
    };
    std::vector<SmaliLine> lines;
    uint32_t offset = 0;
    int hi_idx = -1;

    while (offset < insns_count) {
        const uint16_t* cur_insn = insns + offset;
        uint8_t opcode = (*cur_insn) & 0xFF;

        size_t insn_size = 1;
        if (*cur_insn == 0x0100) {
            insn_size = 4 + (cur_insn[1] * 2);
        } else if (*cur_insn == 0x0200) {
            insn_size = 2 + (cur_insn[1] * 4);
        } else if (*cur_insn == 0x0300) {
            uint16_t elem_width = cur_insn[1];
            uint32_t elem_count = *reinterpret_cast<const uint32_t*>(cur_insn + 2);
            insn_size = 4 + (elem_width * elem_count + 1) / 2;
        } else {
            insn_size = kInstructionSizes[opcode];
        }
        if (insn_size == 0 || insn_size > 500 || offset + insn_size > insns_count) {
            insn_size = 1;
        }

        std::string smali_str;
        if (g_dump_string_fn) {
            smali_str = g_dump_string_fn(cur_insn, dex_file);
        }
        if (smali_str.empty() && g_instruction_names) {
            smali_str = g_instruction_names[opcode] ? g_instruction_names[opcode] : "unknown_op";
        }
        if (smali_str.empty()) {
            char op_buf[32];
            snprintf(op_buf, sizeof(op_buf), "op_0x%02x", opcode);
            smali_str = op_buf;
        }

        const bool is_cur = (highlight_pc >= 0 && (int)offset == highlight_pc);
        const char* mark = is_cur ? " -> " : "    ";
        char line_buf[128];
        if (insn_size == 1) {
            snprintf(line_buf, sizeof(line_buf), "%s[0x%04x] %04x            |  ", mark, offset, cur_insn[0]);
        } else if (insn_size == 2) {
            snprintf(line_buf, sizeof(line_buf), "%s[0x%04x] %04x %04x       |  ", mark, offset, cur_insn[0], cur_insn[1]);
        } else if (insn_size == 3) {
            snprintf(line_buf, sizeof(line_buf), "%s[0x%04x] %04x %04x %04x  |  ", mark, offset, cur_insn[0], cur_insn[1], cur_insn[2]);
        } else {
            snprintf(line_buf, sizeof(line_buf), "%s[0x%04x] %04x %04x..     |  ", mark, offset, cur_insn[0], cur_insn[1]);
        }

        if (is_cur) hi_idx = static_cast<int>(lines.size());
        SmaliLine sl;
        sl.offset = offset;
        sl.text = std::string(line_buf) + smali_str;
        lines.push_back(std::move(sl));

        offset += insn_size;
    }

    const bool windowed = highlight_pc >= 0;
    const int listing_window = windowed
        ? ((max_instructions > 0) ? max_instructions : 21)
        : ((max_instructions > 0) ? max_instructions : static_cast<int>(lines.size()));
    int win_begin = 0;
    int win_end = static_cast<int>(lines.size());
    if (windowed && hi_idx < 0 && !lines.empty()) {
        for (int i = 0; i < win_end; i++) {
            if (static_cast<int>(lines[static_cast<size_t>(i)].offset) >= highlight_pc) {
                hi_idx = i;
                break;
            }
        }
        if (hi_idx < 0) hi_idx = win_end - 1;
    }
    if (!windowed && max_instructions > 0 && win_end > max_instructions) {
        win_end = max_instructions;
    } else if (windowed && win_end > listing_window && hi_idx >= 0) {
        const int total = static_cast<int>(lines.size());
        const int win = listing_window;
        int before = win / 2;
        win_begin = (hi_idx > before) ? (hi_idx - before) : 0;
        win_end = win_begin + win;
        if (win_end > total) {
            win_end = total;
            win_begin = (total > win) ? (total - win) : 0;
        }
    }
    if (win_begin > 0) {
        ss << "    ... (" << win_begin << " earlier instructions)\n";
    }
    for (int i = win_begin; i < win_end; i++) {
        ss << lines[static_cast<size_t>(i)].text << "\n";
    }
    if (win_end < static_cast<int>(lines.size())) {
        ss << "    ... (" << (static_cast<int>(lines.size()) - win_end) << " more instructions)\n";
    }

    ss << "======================================================================\n";
    return ss.str();
}

std::string dumpSmaliInsn(ArtMethod* method, uint32_t pc) {
    if (!method) return "";
    if (method->IsNative() || method->HasAccessFlags(0x0400)) return "";

    uint32_t klass_ref = method->GetDeclaringClass();
    if (!klass_ref) return "";
    void* klass = reinterpret_cast<void*>(static_cast<uintptr_t>(klass_ref));
    uint32_t dex_cache_ref = *reinterpret_cast<uint32_t*>(static_cast<uint8_t*>(klass) + 0x10);
    if (!dex_cache_ref) return "";
    void* dex_cache = reinterpret_cast<void*>(static_cast<uintptr_t>(dex_cache_ref));
    const void* dex_file = *reinterpret_cast<const void* const*>(static_cast<const uint8_t*>(dex_cache) + 0x10);
    if (!dex_file) return "";
    const uint8_t* dex_begin = *reinterpret_cast<const uint8_t* const*>(static_cast<const uint8_t*>(dex_file) + 0x08);
    bool is_compact = (dex_begin && std::memcmp(dex_begin, "cdex", 4) == 0);

    void* data_ptr = method->GetEntryPointFromJni();
    const uint8_t* code_item = reinterpret_cast<const uint8_t*>(reinterpret_cast<uintptr_t>(data_ptr) & ~1ULL);
    if (!code_item) return "";

    uint32_t insns_count = 0;
    const uint16_t* insns = nullptr;
    if (is_compact) {
        uint16_t insns_count_and_flags = *reinterpret_cast<const uint16_t*>(code_item + 2);
        insns_count = insns_count_and_flags >> 5;
        insns = reinterpret_cast<const uint16_t*>(code_item + 4);
    } else {
        insns_count = *reinterpret_cast<const uint32_t*>(code_item + 12);
        insns = reinterpret_cast<const uint16_t*>(code_item + 16);
    }
    if (pc >= insns_count) return "";

    const uint16_t* cur = insns + pc;
    uint8_t opcode = (*cur) & 0xFF;
    size_t size = 1;
    if (*cur == 0x0100) {
        size = 4 + (cur[1] * 2);
    } else if (*cur == 0x0200) {
        size = 2 + (cur[1] * 4);
    } else if (*cur == 0x0300) {
        uint32_t elem_count = *reinterpret_cast<const uint32_t*>(cur + 2);
        size = 4 + (cur[1] * elem_count + 1) / 2;
    } else {
        size = kInstructionSizes[opcode];
    }
    if (size == 0 || size > 500) size = 1;
    (void) size;

    // formatSingleInstruction already yields "<words> |  <smali>"; just prefix the offset.
    char off_buf[16];
    snprintf(off_buf, sizeof(off_buf), "[0x%04x] ", pc);
    return std::string(off_buf) + formatSingleInstruction(cur, dex_file);
}

void showSmali(ArtMethod* method, int max_instructions, const char* tag) {
    std::string smali = dumpSmali(method, max_instructions);
    // Split lines and log each line to avoid Android Logcat 4096-byte truncation
    std::istringstream stream(smali);
    std::string line;
    const char* log_tag = tag ? tag : "PI_SMALI";
    while (std::getline(stream, line)) {
        PI::Logger::log(PI::LogLevel::INFO, log_tag, "%s", line.c_str());
    }
}

std::string dumpCode(ArtMethod* method, int max_instructions) {
    if (!method) {
        return "[PI] Error: ArtMethod is null\n";
    }
    if (method->IsNative()) {
        return dumpNative(method, max_instructions);
    } else {
        return dumpSmali(method, max_instructions);
    }
}

// ============================================================================
// Single-instruction formatting (trace support)
// ============================================================================
const uint8_t* instructionSizeTable() {
    return kInstructionSizes;
}

std::string formatSingleInstruction(const uint16_t* insn, const void* artDexFile) {
    if (insn == nullptr) return "(null)";
    EnsureSymbolsInitialized();

    uint8_t opcode = (*insn) & 0xFF;

    // instruction length (same payload handling as dumpSmali)
    size_t insn_size = 1;
    if (*insn == 0x0100) {
        insn_size = 4 + (insn[1] * 2);
    } else if (*insn == 0x0200) {
        insn_size = 2 + (insn[1] * 4);
    } else if (*insn == 0x0300) {
        uint32_t elem_count = *reinterpret_cast<const uint32_t*>(insn + 2);
        insn_size = 4 + (insn[1] * elem_count + 1) / 2;
    } else {
        insn_size = kInstructionSizes[opcode];
    }
    if (insn_size == 0 || insn_size > 500) insn_size = 1;

    // hex code units prefix (column-aligned: instruction field is 14 chars: xxxx xxxx xxxx)
    char line_buf[128];
    if (insn_size == 1) {
        snprintf(line_buf, sizeof(line_buf), "%04x           |  ", insn[0]);
    } else if (insn_size == 2) {
        snprintf(line_buf, sizeof(line_buf), "%04x %04x      |  ", insn[0], insn[1]);
    } else if (insn_size == 3) {
        snprintf(line_buf, sizeof(line_buf), "%04x %04x %04x |  ", insn[0], insn[1], insn[2]);
    } else {
        snprintf(line_buf, sizeof(line_buf), "%04x %04x..    |  ", insn[0], insn[1]);
    }

    std::string smali_str;
    if (g_dump_string_fn) {
        smali_str = g_dump_string_fn(insn, artDexFile);
    }
    if (smali_str.empty() && g_instruction_names) {
        smali_str = g_instruction_names[opcode] ? g_instruction_names[opcode] : "unknown_op";
    }
    if (smali_str.empty()) {
        char op_buf[32];
        snprintf(op_buf, sizeof(op_buf), "op_0x%02x", opcode);
        smali_str = op_buf;
    }

    return std::string(line_buf) + smali_str;
}

} // namespace PI
