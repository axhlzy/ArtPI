//
// agent_hw_hook.h - QuickJS Bindings for Hardware Breakpoints & Watchpoints
//
#pragma once

#include "agent_common.h"
#include "native/hooker/pi_hw_hook.h"
#include <string>
#include <vector>

namespace artpi { namespace agent {

struct HwHookInfo {
    uint32_t id;
    std::string type;       // "BREAKPOINT", "WATCHPOINT", "GUM_INLINE_FALLBACK"
    int slot;               // 0..3 or -1
    uintptr_t address;
    std::string tag;
    size_t threads;
    size_t size;            // for watchpoint
    std::string condition;  // "r", "w", "rw"
};

struct HwSlotStatus {
    bool bp_slots[PI::Native::kMaxHwSlots];
    bool wp_slots[PI::Native::kMaxHwSlots];
    int bp_capacity;
    int wp_capacity;
};

void RegisterHwHookApis(JSContext* ctx, JSValue global);
size_t HwHookDetachAll();
bool SetupDlopenHwMonitor(const std::string& stopLib, bool libLog, bool constructors = false);

// Retry arming live threads that were missed (e.g. the gated main thread was
// still ptraced by the injector during the early-boot attach).
size_t HwHookRearmMissingThreads();

// True when at least one active hardware session has armed the process main
// thread (tid == pid). Used by the agent's boot auto-resume.
bool HwHookMainThreadArmed();

// Query the kernel for the real comparator counts (bounded wait; safe to call
// from a background thread after the early-boot critical path).
void HwHookRefreshCapacity();

// Query all active hardware hooks (including Gum inline fallback hooks)
std::vector<HwHookInfo> HwHookListAll();
HwSlotStatus HwHookGetSlotStatus();

}} // namespace artpi::agent
