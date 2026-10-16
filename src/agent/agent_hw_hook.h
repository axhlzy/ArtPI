//
// agent_hw_hook.h - QuickJS Bindings for Hardware Breakpoints & Watchpoints
//
#pragma once

#include "agent_common.h"
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
    bool bp_slots[4];
    bool wp_slots[4];
};

void RegisterHwHookApis(JSContext* ctx, JSValue global);
size_t HwHookDetachAll();
bool SetupDlopenHwMonitor(const std::string& stopLib, bool libLog);

// Query all active hardware hooks (including Gum inline fallback hooks)
std::vector<HwHookInfo> HwHookListAll();
HwSlotStatus HwHookGetSlotStatus();

}} // namespace artpi::agent
