//
// pi_native.cpp - Runtime Native ARM64 Disassembler, Symbol Resolver & CFG Flow
//
#include "pi_native.h"
#include "art/art_method.h"
#include "xdl.h"
#include "frida-gum.h"
#include "pine_native.h"
#include <link.h>
#include <dlfcn.h>

#include <cstring>
#include <sstream>
#include <iomanip>
#include <mutex>
#include <cxxabi.h>
#include <map>
#include <algorithm>
#include <vector>

namespace PI {

namespace {

static bool IsDlsymLookupStub(void* entry) {
    static void* stub = []() -> void* {
        void* h = xdl_open("libart.so", XDL_DEFAULT);
        if (!h) return nullptr;
        void* s = xdl_sym(h, "art_jni_dlsym_lookup_stub", nullptr);
        if (!s) s = xdl_sym(h, "art_jni_dlsym_lookup_stub_jit", nullptr);
        xdl_close(h);
        return s;
    }();
    return stub != nullptr && entry == stub;
}

} // namespace

bool isDlsymLookupStub(void* entry) {
    return IsDlsymLookupStub(entry);
}

namespace {

static std::string PrettyAccessFlags(uint32_t flags) {
    std::string s;
    if (flags & 0x0001) s += "public ";
    if (flags & 0x0002) s += "private ";
    if (flags & 0x0004) s += "protected ";
    if (flags & 0x0008) s += "static ";
    if (flags & 0x0010) s += "final ";
    if (flags & 0x0020) s += "synchronized ";
    if (flags & 0x0100) s += "native ";
    if (flags & 0x0400) s += "abstract ";
    if (flags & 0x1000) s += "synthetic ";
    if (!s.empty() && s.back() == ' ') s.pop_back();
    return s;
}

typedef std::string (*PrettyMethodFn)(void* insn, bool with_sig);
static PrettyMethodFn g_pretty_method_fn = nullptr;
static bool g_symbols_initialized = false;

static void EnsureSymbolsInitialized() {
    if (g_symbols_initialized) return;
    g_symbols_initialized = true;
    void* art_h = xdl_open("libart.so", XDL_DEFAULT);
    if (!art_h) art_h = xdl_open("libart.so", XDL_TRY_FORCE_LOAD);
    if (art_h) {
        g_pretty_method_fn = reinterpret_cast<PrettyMethodFn>(
            xdl_sym(art_h, "_ZN3art9ArtMethod12PrettyMethodEb", nullptr));
        if (!g_pretty_method_fn) {
            g_pretty_method_fn = reinterpret_cast<PrettyMethodFn>(
                xdl_dsym(art_h, "_ZN3art9ArtMethod12PrettyMethodEb", nullptr));
        }
        xdl_close(art_h);
    }
}

static std::string GetMethodFullName(ArtMethod* method, uint32_t flags) {
    EnsureSymbolsInitialized();
    std::string sig;
    if (g_pretty_method_fn && method) {
        sig = g_pretty_method_fn(method, true);
    }
    std::string prefix = PrettyAccessFlags(flags);
    if (!prefix.empty()) {
        if (!sig.empty()) {
            return prefix + " " + sig;
        }
        return prefix;
    }
    return sig.empty() ? "(native method)" : sig;
}

struct NativeInsn {
    uint64_t addr = 0;
    uint8_t bytes[4] = {0};
    std::string mnemonic;
    std::string op_str;
    bool is_branch = false;
    bool is_call = false;
    uintptr_t target_addr = 0;
};

static std::string Demangle(const char* mangled) {
    if (!mangled || !*mangled) return "";
    int status = 0;
    char* demangled = abi::__cxa_demangle(mangled, nullptr, nullptr, &status);
    if (status == 0 && demangled) {
        std::string res(demangled);
        free(demangled);
        return res;
    }
    return mangled;
}

static std::string ResolveSymbol(uintptr_t addr, void** xdl_cache, uintptr_t func_start, uintptr_t func_end) {
    if (addr < 0x1000) return "";

    // 1. Resolve via xDL
    xdl_info_t info{};
    xdl_addr(reinterpret_cast<void*>(addr), &info, xdl_cache);

    std::string mod_name;
    if (info.dli_fname) {
        const char* slash = strrchr(info.dli_fname, '/');
        mod_name = slash ? (slash + 1) : info.dli_fname;
    }

    std::string sym_name;
    uintptr_t sym_base = reinterpret_cast<uintptr_t>(info.dli_saddr);
    if (info.dli_sname && *info.dli_sname) {
        sym_name = info.dli_sname;
    }

    // 2. Fallback: libc dladdr
    if (sym_name.empty()) {
        Dl_info dlinfo{};
        if (dladdr(reinterpret_cast<void*>(addr), &dlinfo)) {
            if (dlinfo.dli_sname && *dlinfo.dli_sname) {
                sym_name = dlinfo.dli_sname;
                if (!sym_base) sym_base = reinterpret_cast<uintptr_t>(dlinfo.dli_saddr);
            }
            if (mod_name.empty() && dlinfo.dli_fname) {
                const char* slash = strrchr(dlinfo.dli_fname, '/');
                mod_name = slash ? (slash + 1) : dlinfo.dli_fname;
            }
        }
    }

    if (!sym_name.empty()) {
        sym_name = Demangle(sym_name.c_str());
        std::ostringstream ss;
        ss << "; <";
        if (!mod_name.empty()) {
            ss << mod_name << "!" << sym_name;
            if (sym_base > 0 && addr > sym_base) {
                ss << "+0x" << std::hex << (addr - sym_base) << std::dec;
            }
        } else {
            ss << sym_name;
            if (sym_base > 0 && addr > sym_base) {
                ss << "+0x" << std::hex << (addr - sym_base) << std::dec;
            }
        }
        ss << ">";
        return ss.str();
    }

    // 3. If no symbol found and target is within current function, show intra-function loc offset
    if (func_start > 0 && func_end > func_start && addr >= func_start && addr < func_end) {
        char buf[64];
        snprintf(buf, sizeof(buf), "; <loc_0x%llx (+0x%x)>",
                 static_cast<unsigned long long>(addr),
                 static_cast<unsigned int>(addr - func_start));
        return buf;
    }

    // 4. Module base relative offset
    if (!mod_name.empty() && info.dli_fbase) {
        uintptr_t fbase = reinterpret_cast<uintptr_t>(info.dli_fbase);
        std::ostringstream ss;
        ss << "; <" << mod_name << "+0x" << std::hex << (addr - fbase) << std::dec << ">";
        return ss.str();
    }

    return "";
}

struct NativeWindowState {
    uintptr_t func_start = 0;
    size_t win_begin = 0;
};
static thread_local NativeWindowState t_nativeWinState;

} // namespace

std::string getPrettyMethodSignature(ArtMethod* method) {
    if (!method) return "";
    EnsureSymbolsInitialized();
    if (!g_pretty_method_fn) return "";
    return g_pretty_method_fn(method, true);
}

std::string dumpNative(const void* native_pc, int max_instructions, ArtMethod* method, uintptr_t highlight_pc) {
    uintptr_t pc = reinterpret_cast<uintptr_t>(native_pc);
    if (pc < 0x1000) {
        return "[PI Native] Error: Native code pointer is null or invalid (below 0x1000)\n";
    }
    if (highlight_pc < 0x1000) highlight_pc = 0;

    EnsureSymbolsInitialized();

    // 1. Resolve shared object & symbol via xdl_addr (current PC, so callees refresh)
    xdl_info_t info{};
    void* cache = nullptr;
    xdl_addr(const_cast<void*>(native_pc), &info, &cache);

    const char* so_name = info.dli_fname ? info.dli_fname : "unknown";
    uintptr_t fbase = reinterpret_cast<uintptr_t>(info.dli_fbase);
    uintptr_t rel_offset = (fbase > 0 && pc >= fbase) ? (pc - fbase) : 0;
    const char* sym_name = (info.dli_sname && *info.dli_sname) ? info.dli_sname : "";
    uintptr_t sym_addr = reinterpret_cast<uintptr_t>(info.dli_saddr);
    size_t sym_size = info.dli_ssize;

    uintptr_t func_start = pc;
    if (sym_addr != 0 && pc >= sym_addr) {
        bool in_sym = (sym_size > 0)
            ? (pc < sym_addr + sym_size)
            : ((pc - sym_addr) < 0x10000);
        if (in_sym) func_start = sym_addr;
    }
    size_t known_size = (sym_size > 0 && sym_size < 0x80000) ? sym_size : 0;
    const bool windowed = highlight_pc >= 0x1000;
    const int listing_window = windowed
        ? ((max_instructions > 0) ? max_instructions : 21)
        : ((max_instructions > 0) ? max_instructions : 256);

    // 3. Initialize Capstone ARM64 disassembler & Frida-Gum
    static std::once_flag s_cs_init_flag;
    std::call_once(s_cs_init_flag, []() {
        cs_arch_register_arm64();
        gum_init_embedded();
    });

    csh cs_handle = 0;
    cs_err err = cs_open(CS_ARCH_ARM64, CS_MODE_ARM, &cs_handle);
    if (err != CS_ERR_OK) {
        xdl_addr_clean(&cache);
        char errBuf[128];
        snprintf(errBuf, sizeof(errBuf), "[PI Native] Error: Failed to initialize ARM64 disassembler engine: %s (code %d)\n", cs_strerror(err), (int)err);
        return errBuf;
    }
    cs_option(cs_handle, CS_OPT_DETAIL, CS_OPT_ON);

    int max_limit = listing_window;
    uintptr_t dump_start = func_start;
    if (windowed) {
        uintptr_t center = (highlight_pc >= 0x1000) ? highlight_pc : pc;
        uintptr_t before = static_cast<uintptr_t>(listing_window / 2) * 4u;
        dump_start = (center > before) ? (center - before) : 0;
        dump_start &= ~3ull;
        if (center >= func_start && dump_start < func_start) {
            dump_start = func_start;
        }
        max_limit = listing_window + 4;
    }
    std::vector<NativeInsn> insns_list;
    uintptr_t cur_pc = dump_start;
    uintptr_t max_forward_target = dump_start;

    while (insns_list.size() < static_cast<size_t>(max_limit)) {
        const uint8_t* code_bytes = reinterpret_cast<const uint8_t*>(cur_pc);
        cs_insn* insn = nullptr;
        size_t count = cs_disasm(cs_handle, code_bytes, 4, cur_pc, 1, &insn);
        if (count == 0 || !insn) {
            break;
        }

        NativeInsn item;
        item.addr = cur_pc;
        std::memcpy(item.bytes, insn->bytes, 4);
        item.mnemonic = insn->mnemonic;
        item.op_str = insn->op_str;

        if (insn->detail) {
            auto& arm64 = insn->detail->arm64;
            switch (insn->id) {
                case ARM64_INS_B:
                case ARM64_INS_BC:
                    if (arm64.op_count >= 1 && arm64.operands[0].type == ARM64_OP_IMM) {
                        item.target_addr = static_cast<uintptr_t>(arm64.operands[0].imm);
                        item.is_branch = true;
                    }
                    break;
                case ARM64_INS_CBZ:
                case ARM64_INS_CBNZ:
                    if (arm64.op_count >= 2 && arm64.operands[1].type == ARM64_OP_IMM) {
                        item.target_addr = static_cast<uintptr_t>(arm64.operands[1].imm);
                        item.is_branch = true;
                    }
                    break;
                case ARM64_INS_TBZ:
                case ARM64_INS_TBNZ:
                    if (arm64.op_count >= 3 && arm64.operands[2].type == ARM64_OP_IMM) {
                        item.target_addr = static_cast<uintptr_t>(arm64.operands[2].imm);
                        item.is_branch = true;
                    }
                    break;
                case ARM64_INS_BL:
                    if (arm64.op_count >= 1 && arm64.operands[0].type == ARM64_OP_IMM) {
                        item.target_addr = static_cast<uintptr_t>(arm64.operands[0].imm);
                        item.is_call = true;
                    }
                    break;
                case ARM64_INS_ADR:
                case ARM64_INS_ADRP:
                case ARM64_INS_LDR:
                case ARM64_INS_LDRSW:
                    if (arm64.op_count >= 2 && arm64.operands[1].type == ARM64_OP_IMM) {
                        item.target_addr = static_cast<uintptr_t>(arm64.operands[1].imm);
                    }
                    break;
                default:
                    break;
            }
        }

        insns_list.push_back(item);

        if (item.is_branch && item.target_addr > cur_pc &&
            item.target_addr < static_cast<uintptr_t>(func_start + 0x20000)) {
            if (item.target_addr > max_forward_target) {
                max_forward_target = item.target_addr;
            }
        }

        bool is_ret = (insn->id == ARM64_INS_RET);
        bool is_tail_branch = (insn->id == ARM64_INS_B && insn->detail &&
                               insn->detail->arm64.op_count == 1 &&
                               insn->detail->arm64.operands[0].type == ARM64_OP_IMM &&
                               (insn->detail->arm64.operands[0].imm < static_cast<int64_t>(func_start) ||
                                insn->detail->arm64.operands[0].imm > static_cast<int64_t>(func_start + 0x10000)));

        cs_free(insn, count);

        cur_pc += 4;

        if (!windowed) {
            if (known_size > 0 && (cur_pc - func_start) >= known_size) {
                break;
            }
            if (known_size == 0 && (is_ret || is_tail_branch) && cur_pc >= max_forward_target) {
                const uint32_t* next_word = reinterpret_cast<const uint32_t*>(cur_pc);
                uint32_t w = *next_word;
                if (w == 0 || w == 0xd503201f /* nop */ || w == 0xd503233f /* paciasp */ ||
                    (w & 0xffc003e0) == 0xa98003e0 /* stp */) {
                    break;
                }
                if (is_ret) {
                    break;
                }
            }
        }
    }

    cs_close(&cs_handle);

    size_t total_bytes = insns_list.size() * 4;

    // 4. Construct intra-function CFG jump table & assign lanes
    struct JumpInfo {
        size_t src_idx = 0;
        size_t dst_idx = 0;
        uintptr_t src_addr = 0;
        uintptr_t dst_addr = 0;
        bool is_forward = true;
        int lane = -1;
    };

    std::map<uintptr_t, size_t> addr_to_idx;
    for (size_t idx = 0; idx < insns_list.size(); ++idx) {
        addr_to_idx[insns_list[idx].addr] = idx;
    }

    std::vector<JumpInfo> jumps;
    for (size_t idx = 0; idx < insns_list.size(); ++idx) {
        const auto& item = insns_list[idx];
        if (item.is_branch && item.target_addr != 0) {
            auto it = addr_to_idx.find(item.target_addr);
            if (it != addr_to_idx.end()) {
                JumpInfo j;
                j.src_idx = idx;
                j.dst_idx = it->second;
                j.src_addr = item.addr;
                j.dst_addr = item.target_addr;
                j.is_forward = (j.dst_idx > j.src_idx);
                jumps.push_back(j);
            }
        }
    }

    // Sort jumps by span descending (outer enclosing jumps take lower lane numbers)
    std::vector<size_t> sorted_jump_indices(jumps.size());
    for (size_t k = 0; k < jumps.size(); ++k) sorted_jump_indices[k] = k;
    std::sort(sorted_jump_indices.begin(), sorted_jump_indices.end(), [&](size_t a, size_t b) {
        size_t span_a = (jumps[a].dst_idx > jumps[a].src_idx) ? (jumps[a].dst_idx - jumps[a].src_idx) : (jumps[a].src_idx - jumps[a].dst_idx);
        size_t span_b = (jumps[b].dst_idx > jumps[b].src_idx) ? (jumps[b].dst_idx - jumps[b].src_idx) : (jumps[b].src_idx - jumps[b].dst_idx);
        if (span_a != span_b) return span_a > span_b;
        return jumps[a].src_idx < jumps[b].src_idx;
    });

    const int max_lanes_limit = 4;
    int num_lanes = 0;

    for (size_t s_idx : sorted_jump_indices) {
        auto& j = jumps[s_idx];
        size_t top = std::min(j.src_idx, j.dst_idx);
        size_t bot = std::max(j.src_idx, j.dst_idx);

        int chosen_lane = 0;
        while (chosen_lane < max_lanes_limit) {
            bool conflict = false;
            for (const auto& other : jumps) {
                if (other.lane == chosen_lane) {
                    size_t o_top = std::min(other.src_idx, other.dst_idx);
                    size_t o_bot = std::max(other.src_idx, other.dst_idx);
                    if (std::max(top, o_top) <= std::min(bot, o_bot)) {
                        conflict = true;
                        break;
                    }
                }
            }
            if (!conflict) break;
            chosen_lane++;
        }

        if (chosen_lane < max_lanes_limit) {
            j.lane = chosen_lane;
            if (chosen_lane + 1 > num_lanes) {
                num_lanes = chosen_lane + 1;
            }
        }
    }

    std::ostringstream ss;
    ss << "======================================================================\n";
    if (method) {
        uint32_t flags = method->GetAccessFlags();
        ss << "  " << GetMethodFullName(method, flags) << "\n";
        ss << "  ArtMethod=" << reinterpret_cast<void*>(method)
           << " | AccessFlags: 0x" << std::hex << flags << std::dec
           << " (" << PrettyAccessFlags(flags) << ")\n";
    } else if (sym_name && *sym_name) {
        ss << "  " << sym_name << "\n";
    }

    const char* slash = strrchr(so_name, '/');
    const char* short_so = slash ? (slash + 1) : so_name;

    ss << "  Native Entry: 0x" << std::hex << pc << std::dec;
    if (fbase > 0) {
        ss << " [" << short_so << " + 0x" << std::hex << rel_offset << std::dec << "]";
    }
    if (sym_name && *sym_name) {
        ss << " (" << sym_name << ")";
    }
    ss << "\n";

    if (IsDlsymLookupStub(const_cast<void*>(native_pc))) {
        ss << "  [!] Native method is not yet bound (entry points to art_jni_dlsym_lookup_stub)\n";
    }

    size_t win_begin = 0;
    size_t win_end = insns_list.size();
    size_t hi_idx = static_cast<size_t>(-1);
    if (windowed && !insns_list.empty()) {
        for (size_t i = 0; i < insns_list.size(); ++i) {
            if (insns_list[i].addr == highlight_pc) { hi_idx = i; break; }
        }
        if (hi_idx == static_cast<size_t>(-1)) {
            for (size_t i = 0; i < insns_list.size(); ++i) {
                if (insns_list[i].addr + 4 > highlight_pc) { hi_idx = i; break; }
            }
            if (hi_idx == static_cast<size_t>(-1)) hi_idx = insns_list.size() - 1;
        }
        const size_t win = static_cast<size_t>(listing_window);
        const size_t total = insns_list.size();
        if (total > win) {
            // Retain window start if still in same function
            if (t_nativeWinState.func_start == func_start && t_nativeWinState.win_begin < total) {
                win_begin = t_nativeWinState.win_begin;
            } else {
                win_begin = (hi_idx > win / 3) ? (hi_idx - win / 3) : 0;
            }

            const size_t margin = 3;
            // Only scroll window when arrow approaches the bottom or top boundary
            if (hi_idx >= win_begin + win - margin) {
                win_begin = (hi_idx + margin >= win) ? (hi_idx + margin - win + 1) : 0;
            } else if (hi_idx < win_begin + margin) {
                win_begin = (hi_idx >= margin) ? (hi_idx - margin) : 0;
            }

            if (win_begin + win > total) {
                win_begin = (total > win) ? (total - win) : 0;
            }
            win_end = win_begin + win;
            t_nativeWinState.func_start = func_start;
            t_nativeWinState.win_begin = win_begin;
        }
    }

    ss << "  Size: " << total_bytes << " bytes (" << insns_list.size() << " instructions)";
    if (windowed && (win_begin > 0 || win_end < insns_list.size())) {
        ss << "  showing [" << win_begin << ".." << (win_end ? win_end - 1 : 0) << "]";
    }
    ss << "\n";
    ss << "----------------------------------------------------------------------\n";
    if (win_begin > 0) {
        ss << "    ... (" << win_begin << " earlier instructions)\n";
    }

    // Box drawing characters: UP=1, DOWN=2, LEFT=4, RIGHT=8
    static const char* kBoxMap[16] = {
        "  ", // 0: none
        "│ ", // 1: UP
        "│ ", // 2: DOWN
        "│ ", // 3: UP | DOWN
        "──", // 4: LEFT
        "┘ ", // 5: UP | LEFT
        "┐ ", // 6: DOWN | LEFT
        "┤ ", // 7: UP | DOWN | LEFT
        "──", // 8: RIGHT
        "└─", // 9: UP | RIGHT
        "┌─", // 10: DOWN | RIGHT
        "├─", // 11: UP | DOWN | RIGHT
        "──", // 12: LEFT | RIGHT
        "┴─", // 13: UP | LEFT | RIGHT
        "┬─", // 14: DOWN | LEFT | RIGHT
        "┼─"  // 15: UP | DOWN | LEFT | RIGHT
    };

    for (size_t i = win_begin; i < win_end; ++i) {
        const auto& item = insns_list[i];
        const bool is_cur = windowed && (item.addr == highlight_pc || i == hi_idx);

        std::string row_graph;
        if (num_lanes > 0) {
            bool pass_horiz = false;
            bool is_any_dst = false;

            for (int l = 0; l < num_lanes; ++l) {
                bool has_up = false, has_down = false, is_src = false, is_dst = false;
                for (const auto& j : jumps) {
                    if (j.lane != l) continue;
                    size_t top = std::min(j.src_idx, j.dst_idx);
                    size_t bot = std::max(j.src_idx, j.dst_idx);
                    if (i > top && i <= bot) has_up = true;
                    if (i >= top && i < bot) has_down = true;
                    if (i == j.src_idx) is_src = true;
                    if (i == j.dst_idx) is_dst = true;
                }
                if (is_dst) is_any_dst = true;

                bool left_in = pass_horiz;
                if (is_src || is_dst) pass_horiz = true;
                bool right_out = pass_horiz;

                int mask = 0;
                if (has_up) mask |= 1;
                if (has_down) mask |= 2;
                if (left_in) mask |= 4;
                if (right_out) mask |= 8;

                row_graph += kBoxMap[mask];
            }

            if (pass_horiz) {
                if (is_any_dst) {
                    row_graph += "─> ";
                } else {
                    row_graph += "── ";
                }
            } else {
                row_graph += "   ";
            }
        } else {
            row_graph = "";
        }

        char off_str[32];
        if (item.addr >= func_start) {
            snprintf(off_str, sizeof(off_str), "[0x%04x]", static_cast<unsigned int>(item.addr - func_start));
        } else {
            snprintf(off_str, sizeof(off_str), "[-0x%02x]", static_cast<unsigned int>(func_start - item.addr));
        }

        char line_prefix[160];
        snprintf(line_prefix, sizeof(line_prefix), "%s%s%-8s 0x%-10llx  %02x %02x %02x %02x  |  ",
                 is_cur ? " -> " : "    ",
                 row_graph.c_str(),
                 off_str,
                 static_cast<unsigned long long>(item.addr),
                 item.bytes[0], item.bytes[1], item.bytes[2], item.bytes[3]);

        char disasm_buf[128];
        snprintf(disasm_buf, sizeof(disasm_buf), "%-8s %s", item.mnemonic.c_str(), item.op_str.c_str());
        std::string disasm_str = disasm_buf;

        std::string sym_comment = ResolveSymbol(item.target_addr, &cache, func_start, func_start + total_bytes);

        ss << line_prefix << disasm_str;
        if (!sym_comment.empty()) {
            if (disasm_str.length() < 34) {
                ss << std::string(34 - disasm_str.length(), ' ');
            } else {
                ss << "  ";
            }
            ss << sym_comment;
        }
        ss << "\n";
    }
    if (win_end < insns_list.size()) {
        ss << "    ... (" << (insns_list.size() - win_end) << " more instructions)\n";
    }

    xdl_addr_clean(&cache);
    ss << "======================================================================\n";
    return ss.str();
}

static std::string JniMangle(const std::string& str) {
    std::string out;
    out.reserve(str.size() * 2);
    for (char c : str) {
        if (c == '/' || c == '.') {
            out.push_back('_');
        } else if (c == '_') {
            out += "_1";
        } else if (c == ';') {
            out += "_2";
        } else if (c == '[') {
            out += "_3";
        } else {
            out.push_back(c);
        }
    }
    return out;
}

struct JniScanCtx {
    const char* sym_name;
    void* found_addr = nullptr;
    std::string found_lib;
};

void* resolveNativeMethod(ArtMethod* method, JNIEnv* env) {
    if (!method || !method->IsNative()) return nullptr;
    void* entry = method->GetEntryPointFromJni();
    if (entry && !IsDlsymLookupStub(entry)) {
        return entry; // Already bound!
    }

    EnsureSymbolsInitialized();
    std::string full_sig;
    if (g_pretty_method_fn) {
        full_sig = g_pretty_method_fn(method, true);
    }
    if (full_sig.empty()) return nullptr;

    std::string class_name, method_name;
    size_t paren = full_sig.find('(');
    if (paren != std::string::npos) {
        size_t dot = full_sig.rfind('.', paren);
        if (dot != std::string::npos) {
            method_name = full_sig.substr(dot + 1, paren - (dot + 1));
            size_t space = full_sig.rfind(' ', dot);
            if (space != std::string::npos) {
                class_name = full_sig.substr(space + 1, dot - (space + 1));
            }
        }
    }

    // =========================================================================
    // Strategy 1: Safe JNI Symbol Synthesis & Loaded ELF Module Scanning (0 Risk)
    // =========================================================================
    if (!class_name.empty() && !method_name.empty()) {
        std::string short_sym = "Java_" + JniMangle(class_name) + "_" + JniMangle(method_name);

        JniScanCtx sctx{short_sym.c_str(), nullptr, ""};
        dl_iterate_phdr([](struct dl_phdr_info* info, size_t, void* data) -> int {
            auto* ctx = reinterpret_cast<JniScanCtx*>(data);
            if (!info->dlpi_name || !info->dlpi_name[0]) return 0;
            const char* p = info->dlpi_name;
            if (strstr(p, "/system/") || strstr(p, "/apex/") || strstr(p, "libart.so")) return 0;

            void* h = xdl_open(info->dlpi_name, XDL_DEFAULT);
            if (!h) h = xdl_open(info->dlpi_name, XDL_TRY_FORCE_LOAD);
            if (h) {
                void* sym = xdl_sym(h, ctx->sym_name, nullptr);
                if (!sym) sym = xdl_dsym(h, ctx->sym_name, nullptr);
                xdl_close(h);
                if (sym) {
                    ctx->found_addr = sym;
                    ctx->found_lib = info->dlpi_name;
                    return 1;
                }
            }
            return 0;
        }, &sctx);

        if (sctx.found_addr != nullptr) {
            PI_LOGI("[PI Native] Stage 1 (Symbol Scan): Bound %s -> %s!%s (%p)",
                    full_sig.c_str(), sctx.found_lib.c_str(), short_sym.c_str(), sctx.found_addr);
            method->SetEntryPointFromJni(sctx.found_addr);
            return sctx.found_addr;
        }
    }

    // =========================================================================
    // Strategy 2: Guarded Reflection Invocation (Try-Catch + Dummy Instance/Args)
    // =========================================================================
    if (!env) {
        env = Pine::GetCurrentJNIEnv();
    }
    if (env && !class_name.empty()) {
        std::string slash_class = class_name;
        for (char& c : slash_class) if (c == '.') c = '/';
        jclass localCls = env->FindClass(slash_class.c_str());
        if (env->ExceptionCheck()) {
            env->ExceptionClear();
            localCls = nullptr;
        }

        if (!localCls) {
            jclass atCls = env->FindClass("android/app/ActivityThread");
            if (env->ExceptionCheck()) env->ExceptionClear();
            if (atCls) {
                jmethodID curAppMid = env->GetStaticMethodID(atCls, "currentApplication", "()Landroid/app/Application;");
                if (env->ExceptionCheck()) env->ExceptionClear();
                if (curAppMid) {
                    jobject app = env->CallStaticObjectMethod(atCls, curAppMid);
                    if (env->ExceptionCheck()) env->ExceptionClear();
                    if (app) {
                        jclass appCls = env->GetObjectClass(app);
                        jmethodID getClMid = env->GetMethodID(appCls, "getClassLoader", "()Ljava/lang/ClassLoader;");
                        if (env->ExceptionCheck()) env->ExceptionClear();
                        if (getClMid) {
                            jobject cl = env->CallObjectMethod(app, getClMid);
                            if (env->ExceptionCheck()) env->ExceptionClear();
                            if (cl) {
                                jclass clCls = env->GetObjectClass(cl);
                                jmethodID loadClsMid = env->GetMethodID(clCls, "loadClass", "(Ljava/lang/String;)Ljava/lang/Class;");
                                if (env->ExceptionCheck()) env->ExceptionClear();
                                if (loadClsMid) {
                                    jstring jname = env->NewStringUTF(class_name.c_str());
                                    localCls = (jclass)env->CallObjectMethod(cl, loadClsMid, jname);
                                    if (env->ExceptionCheck()) env->ExceptionClear();
                                    env->DeleteLocalRef(jname);
                                }
                                env->DeleteLocalRef(clCls);
                                env->DeleteLocalRef(cl);
                            }
                        }
                        env->DeleteLocalRef(appCls);
                        env->DeleteLocalRef(app);
                    }
                }
                env->DeleteLocalRef(atCls);
            }
        }

        if (localCls) {
            jclass classCls = env->FindClass("java/lang/Class");
            if (env->ExceptionCheck()) env->ExceptionClear();
            if (classCls) {
                jmethodID getDeclaredMethods = env->GetMethodID(classCls, "getDeclaredMethods", "()[Ljava/lang/reflect/Method;");
                if (env->ExceptionCheck()) env->ExceptionClear();
                if (getDeclaredMethods) {
                    auto methodsArr = (jobjectArray)env->CallObjectMethod(localCls, getDeclaredMethods);
                    if (env->ExceptionCheck()) env->ExceptionClear();
                    if (methodsArr) {
                        jsize len = env->GetArrayLength(methodsArr);
                        jobject targetMethodObj = nullptr;

                        jclass methodCls = env->FindClass("java/lang/reflect/Method");
                        if (env->ExceptionCheck()) env->ExceptionClear();
                        jmethodID getNameMid = methodCls ? env->GetMethodID(methodCls, "getName", "()Ljava/lang/String;") : nullptr;
                        if (env->ExceptionCheck()) env->ExceptionClear();

                        for (jsize i = 0; i < len; ++i) {
                            jobject m = env->GetObjectArrayElement(methodsArr, i);
                            if (!m) continue;
                            if (getNameMid) {
                                jstring jmn = (jstring)env->CallObjectMethod(m, getNameMid);
                                if (env->ExceptionCheck()) env->ExceptionClear();
                                if (jmn) {
                                    const char* s = env->GetStringUTFChars(jmn, nullptr);
                                    if (s) {
                                        if (method_name == s) {
                                            targetMethodObj = m;
                                            env->ReleaseStringUTFChars(jmn, s);
                                            env->DeleteLocalRef(jmn);
                                            break;
                                        }
                                        env->ReleaseStringUTFChars(jmn, s);
                                    }
                                    env->DeleteLocalRef(jmn);
                                }
                            }
                            env->DeleteLocalRef(m);
                        }

                        if (targetMethodObj && methodCls) {
                            // Set accessible
                            jclass accCls = env->FindClass("java/lang/reflect/AccessibleObject");
                            if (env->ExceptionCheck()) env->ExceptionClear();
                            if (accCls) {
                                jmethodID setAcc = env->GetMethodID(accCls, "setAccessible", "(Z)V");
                                if (env->ExceptionCheck()) env->ExceptionClear();
                                if (setAcc) {
                                    env->CallVoidMethod(targetMethodObj, setAcc, JNI_TRUE);
                                    if (env->ExceptionCheck()) env->ExceptionClear();
                                }
                                env->DeleteLocalRef(accCls);
                            }

                            // Prepare dummy arguments
                            jmethodID getParamTypesMid = env->GetMethodID(methodCls, "getParameterTypes", "()[Ljava/lang/Class;");
                            if (env->ExceptionCheck()) env->ExceptionClear();
                            auto paramTypes = (jobjectArray)env->CallObjectMethod(targetMethodObj, getParamTypesMid);
                            if (env->ExceptionCheck()) env->ExceptionClear();

                            jsize paramCount = paramTypes ? env->GetArrayLength(paramTypes) : 0;
                            jclass objCls = env->FindClass("java/lang/Object");
                            if (env->ExceptionCheck()) env->ExceptionClear();
                            jobjectArray argsArr = objCls ? env->NewObjectArray(paramCount, objCls, nullptr) : nullptr;

                            for (jsize p = 0; p < paramCount; ++p) {
                                jobject pType = env->GetObjectArrayElement(paramTypes, p);
                                if (!pType) continue;

                                jclass typeCls = env->GetObjectClass(pType);
                                jmethodID isPrimMid = env->GetMethodID(typeCls, "isPrimitive", "()Z");
                                jmethodID typeNameMid = env->GetMethodID(typeCls, "getName", "()Ljava/lang/String;");
                                jboolean isPrim = env->CallBooleanMethod(pType, isPrimMid);
                                if (env->ExceptionCheck()) env->ExceptionClear();

                                if (isPrim && argsArr) {
                                    jstring pName = (jstring)env->CallObjectMethod(pType, typeNameMid);
                                    if (env->ExceptionCheck()) env->ExceptionClear();
                                    if (pName) {
                                        const char* pn = env->GetStringUTFChars(pName, nullptr);
                                        if (pn) {
                                            if (strcmp(pn, "int") == 0 || strcmp(pn, "byte") == 0 || strcmp(pn, "short") == 0) {
                                                jclass intCls = env->FindClass("java/lang/Integer");
                                                jmethodID valOf = intCls ? env->GetStaticMethodID(intCls, "valueOf", "(I)Ljava/lang/Integer;") : nullptr;
                                                if (valOf) {
                                                    jobject boxed = env->CallStaticObjectMethod(intCls, valOf, 0);
                                                    if (boxed) { env->SetObjectArrayElement(argsArr, p, boxed); env->DeleteLocalRef(boxed); }
                                                }
                                                if (intCls) env->DeleteLocalRef(intCls);
                                            } else if (strcmp(pn, "boolean") == 0) {
                                                jclass boolCls = env->FindClass("java/lang/Boolean");
                                                jmethodID valOf = boolCls ? env->GetStaticMethodID(boolCls, "valueOf", "(Z)Ljava/lang/Boolean;") : nullptr;
                                                if (valOf) {
                                                    jobject boxed = env->CallStaticObjectMethod(boolCls, valOf, JNI_FALSE);
                                                    if (boxed) { env->SetObjectArrayElement(argsArr, p, boxed); env->DeleteLocalRef(boxed); }
                                                }
                                                if (boolCls) env->DeleteLocalRef(boolCls);
                                            } else if (strcmp(pn, "long") == 0) {
                                                jclass longCls = env->FindClass("java/lang/Long");
                                                jmethodID valOf = longCls ? env->GetStaticMethodID(longCls, "valueOf", "(J)Ljava/lang/Long;") : nullptr;
                                                if (valOf) {
                                                    jobject boxed = env->CallStaticObjectMethod(longCls, valOf, (jlong)0);
                                                    if (boxed) { env->SetObjectArrayElement(argsArr, p, boxed); env->DeleteLocalRef(boxed); }
                                                }
                                                if (longCls) env->DeleteLocalRef(longCls);
                                            }
                                            env->ReleaseStringUTFChars(pName, pn);
                                        }
                                        env->DeleteLocalRef(pName);
                                    }
                                }
                                env->DeleteLocalRef(typeCls);
                                env->DeleteLocalRef(pType);
                            }
                            if (paramTypes) env->DeleteLocalRef(paramTypes);

                            // Prepare receiver instance (null if static, Unsafe allocateInstance if virtual)
                            jobject receiver = nullptr;
                            if (!method->IsStatic()) {
                                jclass unsafeCls = env->FindClass("sun/misc/Unsafe");
                                if (env->ExceptionCheck()) env->ExceptionClear();
                                if (unsafeCls) {
                                    jfieldID theUnsafe = env->GetStaticFieldID(unsafeCls, "theUnsafe", "Lsun/misc/Unsafe;");
                                    if (env->ExceptionCheck()) env->ExceptionClear();
                                    if (theUnsafe) {
                                        jobject uObj = env->GetStaticObjectField(unsafeCls, theUnsafe);
                                        if (env->ExceptionCheck()) env->ExceptionClear();
                                        jmethodID allocMid = uObj ? env->GetMethodID(unsafeCls, "allocateInstance", "(Ljava/lang/Class;)Ljava/lang/Object;") : nullptr;
                                        if (env->ExceptionCheck()) env->ExceptionClear();
                                        if (allocMid) {
                                            receiver = env->CallObjectMethod(uObj, allocMid, localCls);
                                            if (env->ExceptionCheck()) env->ExceptionClear();
                                        }
                                        if (uObj) env->DeleteLocalRef(uObj);
                                    }
                                    env->DeleteLocalRef(unsafeCls);
                                }
                            }

                            // Invoke method under try-catch
                            jmethodID invokeMid = env->GetMethodID(methodCls, "invoke", "(Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;");
                            if (env->ExceptionCheck()) env->ExceptionClear();
                            if (invokeMid) {
                                env->CallObjectMethod(targetMethodObj, invokeMid, receiver, argsArr);
                                if (env->ExceptionCheck()) {
                                    env->ExceptionClear();
                                }
                            }

                            if (receiver) env->DeleteLocalRef(receiver);
                            if (argsArr) env->DeleteLocalRef(argsArr);
                            if (objCls) env->DeleteLocalRef(objCls);
                            env->DeleteLocalRef(targetMethodObj);
                        }
                        if (methodCls) env->DeleteLocalRef(methodCls);
                        env->DeleteLocalRef(methodsArr);
                    }
                }
                env->DeleteLocalRef(classCls);
            }
            env->DeleteLocalRef(localCls);
        }

        void* resolved = method->GetEntryPointFromJni();
        if (resolved && !IsDlsymLookupStub(resolved)) {
            PI_LOGI("[PI Native] Stage 2 (Reflection Invoke): Bound %s -> %p", full_sig.c_str(), resolved);
            return resolved;
        }
    }

    return nullptr;
}

std::string dumpNative(ArtMethod* method, int max_instructions) {
    if (!method) {
        return "[PI Native] Error: ArtMethod is null\n";
    }
    void* entry = method->GetEntryPointFromJni();
    if (!entry) {
        return "[PI Native] Error: ArtMethod entry_point_from_jni_ is null\n";
    }

    // If entry points to lazy binding stub, automatically resolve it!
    if (IsDlsymLookupStub(entry)) {
        void* resolved = resolveNativeMethod(method, nullptr);
        if (resolved) {
            entry = resolved;
        }
    }

    return dumpNative(entry, max_instructions, method, 0);
}

std::string resolveAddressSymbol(uintptr_t addr) {
    void* cache = nullptr;
    std::string s = ResolveSymbol(addr, &cache, 0, 0);
    if (cache) xdl_addr_clean(&cache);
    return s;
}

std::string demangle(const char* mangled) {
    return Demangle(mangled);
}

std::string demangle(const std::string& mangled) {
    return Demangle(mangled.c_str());
}

} // namespace PI
