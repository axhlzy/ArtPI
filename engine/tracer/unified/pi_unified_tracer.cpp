//
// pi_unified_tracer.cpp - Unified Full-Stack Tracer implementation
//

#include "pi_unified_tracer.h"
#include "../../native/hooker/pi_gum_hooker.h"
#include "../../native/hooker/pi_jni_sniffer.h"
#include "../../native/qbdi/pi_qbdi_engine.h"
#include "QBDI/State.h"
#include "core/pi_logger.h"
#include "xdl.h"
#include <atomic>
#include <cstdio>
#include <cstring>
#include <mutex>
#include <string>
#include <vector>

#ifndef ARTPI_EXPORT
#define ARTPI_EXPORT __attribute__((visibility("default")))
#endif

namespace PI {

namespace Native {

static std::atomic<bool> g_native_engine_inited{false};
static std::mutex g_native_engine_mutex;

ARTPI_EXPORT bool initNativeEngine(JNIEnv* env) {
    std::lock_guard<std::mutex> lock(g_native_engine_mutex);
    if (!GumHooker::init()) {
        PI::Logger::log(PI::LogLevel::ERROR, "PI_UnifiedTracer", "initNativeEngine: GumHooker::init() failed");
        return false;
    }
    if (env != nullptr) {
        RegisterNativesSniffer::start(env);
    }
    g_native_engine_inited.store(true, std::memory_order_release);
    return true;
}

ARTPI_EXPORT bool isNativeEngineInitialized() {
    return g_native_engine_inited.load(std::memory_order_acquire) && GumHooker::isInitialized();
}

} // namespace Native

namespace Trace {

static thread_local int t_unified_depth = 0;

int UnifiedCallDepth::get() { return t_unified_depth; }
void UnifiedCallDepth::set(int depth) { t_unified_depth = depth; }
void UnifiedCallDepth::push() { t_unified_depth++; }
void UnifiedCallDepth::pop() { if (t_unified_depth > 0) t_unified_depth--; }

namespace {

struct NativeSubFrame {
    uintptr_t targetAddr;
    std::string symName;
};

static thread_local std::vector<NativeSubFrame> t_subcall_stack;

static std::string resolveNativeSymbol(uintptr_t addr) {
    xdl_info_t info = {};
    void* cache = nullptr;
    std::string result;
    if (xdl_addr(reinterpret_cast<void*>(addr), &info, &cache) && info.dli_fname != nullptr) {
        const char* p = info.dli_fname;
        const char* base = p;
        for (; *p; p++) if (*p == '/') base = p + 1;
        char buf[256];
        if (info.dli_sname != nullptr) {
            snprintf(buf, sizeof(buf), "%s!%s (0x%lx)", base, info.dli_sname, (unsigned long) addr);
        } else {
            snprintf(buf, sizeof(buf), "%s+0x%lx (0x%lx)", base,
                     (unsigned long)((uintptr_t) addr - (uintptr_t) info.dli_fbase),
                     (unsigned long) addr);
        }
        result = buf;
    } else {
        char buf[64];
        snprintf(buf, sizeof(buf), "0x%lx", (unsigned long) addr);
        result = buf;
    }
    if (cache != nullptr) xdl_addr_clean(&cache);
    return result;
}

static uintptr_t parseTargetFromDisasm(uintptr_t pc, const char* disasm) {
    if (disasm == nullptr) return 0;
    // Look for "#0x..." or "0x..." in the disassembly
    const char* p = std::strstr(disasm, "#0x");
    if (p == nullptr) p = std::strstr(disasm, "0x");
    if (p != nullptr) {
        if (*p == '#') p++;
        uintptr_t val = static_cast<uintptr_t>(std::strtoull(p, nullptr, 16));
        if (val < 0x100000000ULL) {
            val = pc + val;
        }
        return val;
    }
    return 0;
}

static const char* getSyscallName(uint64_t nr) {
    switch (nr) {
        case 63:  return "sys_read";
        case 64:  return "sys_write";
        case 78:  return "sys_readlinkat";
        case 93:  return "sys_exit";
        case 94:  return "sys_exit_group";
        case 96:  return "sys_set_tid_address";
        case 98:  return "sys_futex";
        case 113: return "sys_clock_gettime";
        case 134: return "sys_sigaction";
        case 135: return "sys_rt_sigprocmask";
        case 172: return "sys_getpid";
        case 178: return "sys_gettid";
        case 215: return "sys_munmap";
        case 220: return "sys_clone";
        case 222: return "sys_mmap";
        case 226: return "sys_mprotect";
        case 260: return "sys_wait4";
        default:  return "unknown_syscall";
    }
}

static thread_local bool t_last_was_svc = false;
static thread_local std::string t_last_svc_name;

static std::string makeTreePrefix(int depth) {
    std::string prefix;
    prefix.reserve(static_cast<size_t>((depth + 1) * 4));
    for (int i = 0; i <= depth; i++) {
        prefix += "│   ";
    }
    return prefix;
}

static std::string makeBranchPrefix(int depth, bool isEntry) {
    if (depth <= 0) {
        return isEntry ? "┌── " : "└── ";
    }
    std::string prefix;
    prefix.reserve(static_cast<size_t>((depth + 1) * 4));
    for (int i = 0; i < depth; i++) {
        prefix += "│   ";
    }
    prefix += isEntry ? "├── " : "└── ";
    return prefix;
}

} // namespace

void setupFullStackNativeCallbacks(int baseDepth) {
    UnifiedCallDepth::set(baseDepth);
    t_subcall_stack.clear();
    t_last_was_svc = false;
    t_last_svc_name.clear();

    Native::QBDIEngine* engine = Native::QBDIEngine::current();
    if (engine == nullptr) return;

    engine->setInstructionCallback([](uintptr_t pc, const char* mnemonic,
                                      const char* disasm, int depth, void* rawGpr) -> int {
        (void) depth;
        int base = UnifiedCallDepth::get();
        int subDepth = static_cast<int>(t_subcall_stack.size());
        const QBDI::GPRState* gpr = static_cast<const QBDI::GPRState*>(rawGpr);

        std::string treePfx = makeTreePrefix(base + subDepth);

        if (t_last_was_svc && gpr != nullptr) {
            PI::Logger::log(PI::LogLevel::TRACE, "PI_CallTree",
                            "%s│   [Syscall Return] %s -> x0=0x%lx (%ld)",
                            treePfx.c_str(), t_last_svc_name.c_str(),
                            (unsigned long) gpr->x0, (long) gpr->x0);
            t_last_was_svc = false;
        }

        bool isCall = false;
        bool isRet = false;
        if (mnemonic != nullptr) {
            if (std::strcmp(mnemonic, "bl") == 0 || std::strcmp(mnemonic, "blr") == 0 ||
                std::strcmp(mnemonic, "BL") == 0 || std::strcmp(mnemonic, "BLR") == 0) {
                isCall = true;
            } else if (std::strcmp(mnemonic, "ret") == 0 || std::strcmp(mnemonic, "RET") == 0) {
                isRet = true;
            }
        }

        // Log the ARM64 instruction aligned with tree hierarchy
        PI::Logger::log(PI::LogLevel::TRACE, "PI_CallTree",
                        "%s0x%lx: %s",
                        treePfx.c_str(), (unsigned long) pc, disasm ? disasm : "");

        if (mnemonic != nullptr && gpr != nullptr) {
            std::string m(mnemonic);
            for (auto& c : m) c = std::tolower(c);
            if (m == "svc") {
                uint64_t nr = gpr->x8;
                const char* scName = getSyscallName(nr);
                t_last_was_svc = true;
                t_last_svc_name = scName;
                if (nr == 98) { // sys_futex
                    int op = (int) (gpr->x1 & 0x7f);
                    const char* opName = (op == 0) ? "FUTEX_WAIT" : (op == 1) ? "FUTEX_WAKE" : "FUTEX_OTHER";
                    bool isPriv = (gpr->x1 & 128) != 0;
                    PI::Logger::log(PI::LogLevel::TRACE, "PI_CallTree",
                                    "%s│   [Syscall] svc #0 nr=%lu (sys_futex %s%s) uaddr=0x%lx val=%ld timeout=0x%lx",
                                    treePfx.c_str(), (unsigned long) nr, opName,
                                    isPriv ? "_PRIVATE" : "", (unsigned long) gpr->x0,
                                    (long) gpr->x2, (unsigned long) gpr->x3);
                } else {
                    PI::Logger::log(PI::LogLevel::TRACE, "PI_CallTree",
                                    "%s│   [Syscall] svc #0 nr=%lu (%s) x0=0x%lx x1=0x%lx x2=0x%lx",
                                    treePfx.c_str(), (unsigned long) nr, scName,
                                    (unsigned long) gpr->x0, (unsigned long) gpr->x1, (unsigned long) gpr->x2);
                }
            } else if (m.find("ldaxr") != std::string::npos || m.find("ldxr") != std::string::npos) {
                PI::Logger::log(PI::LogLevel::TRACE, "PI_CallTree",
                                "%s│   [ARM64 Atomics] %s: Acquired exclusive monitor",
                                treePfx.c_str(), mnemonic);
            } else if (m.find("stlxr") != std::string::npos || m.find("stxr") != std::string::npos) {
                unsigned long mon = (unsigned long) gpr->localMonitor.enable;
                PI::Logger::log(PI::LogLevel::TRACE, "PI_CallTree",
                                "%s│   [ARM64 Atomics] %s: Store-conditional (localMonitor.enable=%lu%s)",
                                treePfx.c_str(), mnemonic, mon, (mon == 0) ? " -> LOST/WILL FAIL" : "");
            } else if (m.find("cas") != std::string::npos) {
                PI::Logger::log(PI::LogLevel::TRACE, "PI_CallTree",
                                "%s│   [ARM64 Atomics] %s: Hardware LSE atomic CAS (monitor-independent)",
                                treePfx.c_str(), mnemonic);
            }
        }

        if (isRet) {
            if (!t_subcall_stack.empty()) {
                auto top = t_subcall_stack.back();
                t_subcall_stack.pop_back();
                std::string branchPfx = makeBranchPrefix(base + static_cast<int>(t_subcall_stack.size()) + 1, false);
                PI::Logger::log(PI::LogLevel::TRACE, "PI_CallTree",
                                "%s[Native Sub] %s",
                                branchPfx.c_str(), top.symName.c_str());
            }
        } else if (isCall) {
            uintptr_t target = parseTargetFromDisasm(pc, disasm);
            std::string sym = target != 0 ? resolveNativeSymbol(target) : std::string(disasm ? disasm : "unknown");
            std::string branchPfx = makeBranchPrefix(base + subDepth + 1, true);
            PI::Logger::log(PI::LogLevel::TRACE, "PI_CallTree",
                            "%s[Native Sub] %s",
                            branchPfx.c_str(), sym.c_str());
            t_subcall_stack.push_back({target, sym});
        }

        return 0; // CONTINUE
    });

    engine->setMemoryAccessCallback([](uintptr_t insnPc, uintptr_t addr, size_t size,
                                       bool isWrite, uint64_t val) {
        (void) insnPc;
        int base = UnifiedCallDepth::get();
        int subDepth = static_cast<int>(t_subcall_stack.size());
        std::string memPfx = makeTreePrefix(base + subDepth) + "│   ";

        if (isWrite) {
            PI::Logger::log(PI::LogLevel::TRACE, "PI_CallTree",
                            "%s[mem] 0x%lx <- 0x%lx (%zu bytes)",
                            memPfx.c_str(), (unsigned long) addr, (unsigned long) val, size);
        } else {
            PI::Logger::log(PI::LogLevel::TRACE, "PI_CallTree",
                            "%s[mem] 0x%lx -> 0x%lx (%zu bytes)",
                            memPfx.c_str(), (unsigned long) addr, (unsigned long) val, size);
        }
    });
}

void cleanupFullStackNativeCallbacks() {
    t_subcall_stack.clear();
}

}} // namespace PI::Trace
