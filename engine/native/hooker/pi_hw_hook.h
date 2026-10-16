//
// pi_hw_hook.h - Hardware Breakpoint & Watchpoint Engine (Frida-Gum based)
// High-level abstraction for hardware-assisted debugging and pseudo-hooking.
//
#ifndef PI_HW_HOOK_H
#define PI_HW_HOOK_H

#include <cstdint>
#include <cstddef>
#include <functional>
#include <string>
#include <vector>
#include <memory>
#include <mutex>
#include <set>
#include <sys/types.h>

namespace PI { namespace Native {

enum class HwHookType {
    BREAKPOINT, // Execution breakpoint (instruction PC)
    WATCHPOINT  // Memory data watchpoint (read/write access)
};

enum class HwWatchCondition {
    READ = 1,
    WRITE = 2,
    READ_WRITE = 3
};

struct HwCpuContext {
    uint64_t pc = 0;
    uint64_t sp = 0;
    uint64_t lr = 0;
    uint64_t fp = 0;
    uint64_t nzcv = 0;
    uint64_t x[29] = {0}; // x0 .. x28
    pid_t thread_id = 0;
    int slot = -1;

    // Memory info (for watchpoints)
    uint64_t memory_address = 0;
    int memory_operation = 0; // 1 = read, 2 = write

    // Raw Gum pointer for low-level access or writeback
    void* raw_gum_context = nullptr;

    uint64_t getArg(int index) const {
        if (index >= 0 && index < 8) return x[index];
        return 0;
    }
    void setArg(int index, uint64_t val) {
        if (index >= 0 && index < 8) x[index] = val;
    }
    void setRet(uint64_t val) {
        x[0] = val;
    }
};

using HwHookCallback = std::function<void(HwCpuContext& ctx)>;

struct HwHookConfig {
    HwHookType type = HwHookType::BREAKPOINT;
    uintptr_t address = 0;
    size_t size = 4; // for watchpoint: 1, 2, 4, 8 bytes
    HwWatchCondition condition = HwWatchCondition::WRITE;
    pid_t thread_id = 0; // 0 = all threads
    int slot = -1; // -1 = auto-assign (0..3)
    bool once = false; // if true, automatically unsets on first hit
    std::string tag;
    HwHookCallback on_hit;
};

struct HwHookSession {
    uint32_t id = 0;
    HwHookConfig config;
    int assigned_slot = -1;
    bool active = false;
    std::set<pid_t> armed_threads;

    // Step-over state for non-once breakpoints
    int step_over_slot = -1;
    uintptr_t step_over_pc = 0;
    pid_t stepping_thread = 0;
};

class HwHookManager {
public:
    static HwHookManager& instance();

    bool init();
    bool isInitialized() const;

    // Attach hardware breakpoint (execution)
    uint32_t attachBreakpoint(uintptr_t address, const HwHookCallback& onHit,
                              int slot = -1, pid_t thread_id = 0, bool once = false,
                              const std::string& tag = "");

    // Attach hardware watchpoint (data read/write)
    uint32_t attachWatchpoint(uintptr_t address, size_t size, HwWatchCondition condition,
                              const HwHookCallback& onHit, int slot = -1,
                              pid_t thread_id = 0, bool once = false,
                              const std::string& tag = "");

    // Unified attach
    uint32_t attach(const HwHookConfig& config);

    // Detach by session ID
    bool detach(uint32_t id);

    // Detach all active hardware hooks
    size_t detachAll();

    // Query active sessions
    std::vector<HwHookSession> listSessions() const;
    bool isSessionActive(uint32_t id) const;

    // Internal exception dispatcher called by GumExceptor
    static int HandleException(void* details, void* user_data);

private:
    HwHookManager();
    ~HwHookManager();

    int allocateSlot(HwHookType type, int requested_slot);
    void freeSlot(HwHookType type, int slot);

    bool armOnThread(HwHookSession& session, pid_t tid);
    bool disarmOnThread(HwHookSession& session, pid_t tid);

    mutable std::mutex mutex_;
    bool initialized_ = false;
    uint32_t next_id_ = 1;

    // Max 4 slots for breakpoint (0..3), max 4 slots for watchpoint (0..3)
    bool bp_slots_[4] = {false, false, false, false};
    bool wp_slots_[4] = {false, false, false, false};

    std::vector<std::shared_ptr<HwHookSession>> sessions_;
    void* exceptor_ = nullptr;
};

}} // namespace PI::Native

#endif // PI_HW_HOOK_H
