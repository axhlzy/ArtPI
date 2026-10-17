//
// pi_hw_hook.cpp - Hardware Breakpoint & Watchpoint Engine (Frida-Gum based)
//
#include "pi_hw_hook.h"
#include "frida-gum.h"

#include <android/log.h>
#include <cstring>
#include <algorithm>
#include <cerrno>
#include <csignal>

#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/uio.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <sched.h>
#include <dirent.h>
#include <unistd.h>
#include <elf.h>
#include <asm/ptrace.h>
#include <cstdlib>

#ifndef PTRACE_GETREGSET
#define PTRACE_GETREGSET 0x4204
#endif
#ifndef NT_ARM_HW_BREAK
#define NT_ARM_HW_BREAK 0x402
#endif
#ifndef NT_ARM_HW_WATCH
#define NT_ARM_HW_WATCH 0x403
#endif

#define HW_LOGI(...) __android_log_print(ANDROID_LOG_INFO,  "PI_HwHook", __VA_ARGS__)
#define HW_LOGW(...) __android_log_print(ANDROID_LOG_WARN,  "PI_HwHook", __VA_ARGS__)
#define HW_LOGE(...) __android_log_print(ANDROID_LOG_ERROR, "PI_HwHook", __VA_ARGS__)

namespace PI { namespace Native {

namespace {

static gboolean OnGumException(GumExceptionDetails* details, gpointer user_data) {
    if (!details) return FALSE;
    int res = HwHookManager::HandleException(details, user_data);
    return (res != 0) ? TRUE : FALSE;
}

// Enumerate /proc/self/task directly instead of gum_process_enumerate_threads.
// Gum parses each thread's "status" file and dereferences the strstr() result
// without a NULL check; hardened/packed apps (libDexHelper etc.) can make that
// file unreadable or non-standard, which crashes inside Gum. We only need the
// TIDs here, so a plain readdir is both safer and much cheaper.
static void EnumerateThreadIds(std::vector<pid_t>& out) {
    DIR* dir = opendir("/proc/self/task");
    if (!dir) return;

    struct dirent* entry;
    while ((entry = readdir(dir)) != nullptr) {
        const char* name = entry->d_name;
        if (name[0] == '.') continue;
        char* end = nullptr;
        long tid = strtol(name, &end, 10);
        if (end != nullptr && *end == '\0' && tid > 0) {
            out.push_back(static_cast<pid_t>(tid));
        }
    }
    closedir(dir);
}

// Read the true comparator count from the kernel instead of probing with
// Gum. On arm64 the NT_ARM_HW_BREAK / NT_ARM_HW_WATCH regset starts with
// `dbg_info = (debug_arch << 8) | num_slots`; Gum itself uses that low byte to
// size its PTRACE_SETREGSET transfer, so writing slot indices beyond it is
// silently dropped (which is why probing with gum_thread_set_hardware_* always
// "succeeds" up to 16). We query it from a short-lived traced child: a thread
// cannot ptrace a sibling of the same thread group.
static int HwSlotCountChild(void*) {
    ptrace(PTRACE_TRACEME, 0, nullptr, nullptr);
    kill(getpid(), SIGSTOP);
    _exit(0);
    return 0;
}

static int ReadHwSlotCount(bool watch) {
    // clone(SIGCHLD) instead of fork(): hardened/packed runtimes (libDexHelper
    // etc.) install pthread_atfork handlers that can deadlock, while clone()
    // bypasses them and still gives us a separately traced child process.
    constexpr size_t kStackSize = 64 * 1024;
    void* stack = mmap(nullptr, kStackSize, PROT_READ | PROT_WRITE,
                       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (stack == MAP_FAILED) return -1;

    uintptr_t top = reinterpret_cast<uintptr_t>(stack) + kStackSize;
    top &= ~static_cast<uintptr_t>(15);

    pid_t child = clone(HwSlotCountChild, reinterpret_cast<void*>(top),
                        SIGCHLD, nullptr);
    if (child < 0) {
        munmap(stack, kStackSize);
        return -1;
    }

    // Bounded wait: never block the agent if the child cannot stop.
    int status = 0;
    bool stopped = false;
    for (int i = 0; i < 200; i++) {
        pid_t r = waitpid(child, &status, WNOHANG);
        if (r == child) {
            stopped = WIFSTOPPED(status);
            break;
        }
        if (r < 0 && errno != EINTR) break;
        usleep(1000);
    }
    if (!stopped) {
        kill(child, SIGKILL);
        waitpid(child, &status, 0);
        munmap(stack, kStackSize);
        return -1;
    }

    struct user_hwdebug_state state;
    memset(&state, 0, sizeof(state));
    struct iovec iov;
    iov.iov_base = &state;
    iov.iov_len = sizeof(state);

    int note = watch ? NT_ARM_HW_WATCH : NT_ARM_HW_BREAK;
    int count = -1;
    if (ptrace(PTRACE_GETREGSET, child, (void*) (uintptr_t) note, &iov) == 0) {
        count = static_cast<int>(state.dbg_info & 0xffu);
    }

    ptrace(PTRACE_DETACH, child, nullptr, nullptr);
    waitpid(child, &status, 0);
    munmap(stack, kStackSize);
    return count;
}

} // namespace

HwHookManager::HwHookManager() = default;

HwHookManager::~HwHookManager() {
    detachAll();
    if (exceptor_) {
        gum_exceptor_remove(reinterpret_cast<GumExceptor*>(exceptor_), OnGumException, this);
        exceptor_ = nullptr;
    }
}

HwHookManager& HwHookManager::instance() {
    static HwHookManager s_inst;
    return s_inst;
}

bool HwHookManager::init() {
    std::lock_guard<std::recursive_mutex> lk(mutex_);
    if (initialized_) return true;

    gum_init_embedded();

    GumExceptor* ex = gum_exceptor_obtain();
    if (!ex) {
        HW_LOGE("gum_exceptor_obtain() returned null");
        return false;
    }

    exceptor_ = ex;
    gum_exceptor_add(ex, OnGumException, this);

    // Do NOT fork here: init() sits on the early-boot critical path and
    // hardened apps (libDexHelper etc.) can make fork/waitpid hang forever.
    // Start with the common default; refreshCapacity() queries the real
    // kernel value later (interactive/exhaustion path, with a bounded wait).
    bp_capacity_ = 4;
    wp_capacity_ = 4;

    initialized_ = true;
    HW_LOGI("HwHookManager initialized (default %d BP + %d WP slots; lazy kernel query), "
            "GumExceptor installed",
            bp_capacity_, wp_capacity_);
    return true;
}

bool HwHookManager::isInitialized() const {
    std::lock_guard<std::recursive_mutex> lk(mutex_);
    return initialized_;
}

int HwHookManager::breakpointCapacity() const {
    std::lock_guard<std::recursive_mutex> lk(mutex_);
    return bp_capacity_;
}

int HwHookManager::watchpointCapacity() const {
    std::lock_guard<std::recursive_mutex> lk(mutex_);
    return wp_capacity_;
}

void HwHookManager::refreshCapacity() {
    // Query the kernel OUTSIDE the manager lock: in hardened apps fork/waitpid
    // can block, and HandleException (signal handler) must never be starved.
    int bp = ReadHwSlotCount(false);
    int wp = ReadHwSlotCount(true);

    std::lock_guard<std::recursive_mutex> lk(mutex_);
    if (!initialized_) return;

    int old_bp = bp_capacity_;
    int old_wp = wp_capacity_;
    if (bp > 0) bp_capacity_ = bp;
    if (wp > 0) wp_capacity_ = wp;
    if (bp_capacity_ > kMaxHwSlots) bp_capacity_ = kMaxHwSlots;
    if (wp_capacity_ > kMaxHwSlots) wp_capacity_ = kMaxHwSlots;

    if (bp_capacity_ != old_bp || wp_capacity_ != old_wp) {
        HW_LOGI("refreshCapacity: %d breakpoint slot(s), %d watchpoint slot(s)",
                bp_capacity_, wp_capacity_);
    }
}

int HwHookManager::allocateSlot(HwHookType type, int requested_slot) {
    bool* slots = (type == HwHookType::BREAKPOINT) ? bp_slots_ : wp_slots_;
    int capacity = (type == HwHookType::BREAKPOINT) ? bp_capacity_ : wp_capacity_;
    if (requested_slot >= 0) {
        if (requested_slot < capacity && !slots[requested_slot]) {
            slots[requested_slot] = true;
            return requested_slot;
        }
        return -1; // Requested slot already in use or out of range
    }
    for (int i = 0; i < capacity; i++) {
        if (!slots[i]) {
            slots[i] = true;
            return i;
        }
    }
    return -1; // Exhausted
}

void HwHookManager::freeSlot(HwHookType type, int slot) {
    if (slot >= 0 && slot < kMaxHwSlots) {
        bool* slots = (type == HwHookType::BREAKPOINT) ? bp_slots_ : wp_slots_;
        slots[slot] = false;
    }
}

bool HwHookManager::armOnThread(HwHookSession& session, pid_t tid) {
    GError* error = nullptr;
    gboolean ok = FALSE;

    if (session.config.type == HwHookType::BREAKPOINT) {
        ok = gum_thread_set_hardware_breakpoint(static_cast<GumThreadId>(tid),
                                                session.assigned_slot,
                                                reinterpret_cast<GumAddress>(session.config.address),
                                                &error);
    } else {
        int condVal = 0;
        if ((int)session.config.condition & (int)HwWatchCondition::READ) condVal |= GUM_WATCH_READ;
        if ((int)session.config.condition & (int)HwWatchCondition::WRITE) condVal |= GUM_WATCH_WRITE;
        ok = gum_thread_set_hardware_watchpoint(static_cast<GumThreadId>(tid),
                                                session.assigned_slot,
                                                reinterpret_cast<GumAddress>(session.config.address),
                                                session.config.size,
                                                static_cast<GumWatchConditions>(condVal),
                                                &error);
    }

    if (ok) {
        session.armed_threads.insert(tid);
        return true;
    }

    if (error) {
        HW_LOGW("armOnThread(tid=%d, slot=%d) failed: %s", tid, session.assigned_slot, error->message);
        g_error_free(error);
    }
    return false;
}

bool HwHookManager::disarmOnThread(HwHookSession& session, pid_t tid) {
    GError* error = nullptr;
    gboolean ok = FALSE;

    if (session.config.type == HwHookType::BREAKPOINT) {
        ok = gum_thread_unset_hardware_breakpoint(static_cast<GumThreadId>(tid),
                                                  session.assigned_slot,
                                                  &error);
    } else {
        ok = gum_thread_unset_hardware_watchpoint(static_cast<GumThreadId>(tid),
                                                  session.assigned_slot,
                                                  &error);
    }

    session.armed_threads.erase(tid);
    if (error) g_error_free(error);
    return ok != FALSE;
}

uint32_t HwHookManager::attachBreakpoint(uintptr_t address, const HwHookCallback& onHit,
                                        int slot, pid_t thread_id, bool once,
                                        const std::string& tag) {
    HwHookConfig cfg;
    cfg.type = HwHookType::BREAKPOINT;
    cfg.address = address;
    cfg.on_hit = onHit;
    cfg.slot = slot;
    cfg.thread_id = thread_id;
    cfg.once = once;
    cfg.tag = tag;
    return attach(cfg);
}

uint32_t HwHookManager::attachWatchpoint(uintptr_t address, size_t size, HwWatchCondition condition,
                                        const HwHookCallback& onHit, int slot,
                                        pid_t thread_id, bool once,
                                        const std::string& tag) {
    HwHookConfig cfg;
    cfg.type = HwHookType::WATCHPOINT;
    cfg.address = address;
    cfg.size = size;
    cfg.condition = condition;
    cfg.on_hit = onHit;
    cfg.slot = slot;
    cfg.thread_id = thread_id;
    cfg.once = once;
    cfg.tag = tag;
    return attach(cfg);
}

uint32_t HwHookManager::attach(const HwHookConfig& config) {
    if (!init()) return 0;
    if (config.address == 0 || !config.on_hit) return 0;

    std::lock_guard<std::recursive_mutex> lk(mutex_);

    for (auto& s : sessions_) {
        if (s->active && s->config.address == config.address && s->config.type == config.type) {
            HW_LOGW("attach: session #%u already active on addr=0x%lx, reusing slot %d",
                    s->id, (unsigned long)config.address, s->assigned_slot);
            s->config.on_hit = config.on_hit;
            if (!config.tag.empty()) s->config.tag = config.tag;
            return s->id;
        }
    }

    int slot = allocateSlot(config.type, config.slot);
    if (slot < 0) {
        HW_LOGE("attach failed: no free hardware debug slot (type=%d, requested=%d)",
                (int)config.type, config.slot);
        return 0;
    }

    auto session = std::make_shared<HwHookSession>();
    session->id = next_id_++;
    session->config = config;
    session->assigned_slot = slot;
    session->active = true;

    if (config.thread_id > 0) {
        if (!armOnThread(*session, config.thread_id)) {
            freeSlot(config.type, slot);
            return 0;
        }
    } else {
        std::vector<pid_t> tids;
        EnumerateThreadIds(tids);
        int success_count = 0;
        for (pid_t tid : tids) {
            if (armOnThread(*session, tid)) {
                success_count++;
            }
        }
        if (success_count == 0 && !tids.empty()) {
            freeSlot(config.type, slot);
            return 0;
        }
    }

    sessions_.push_back(session);
    HW_LOGI("HwHookSession #%u attached: type=%s, addr=0x%lx, slot=%d, threads=%zu",
            session->id,
            (config.type == HwHookType::BREAKPOINT) ? "BREAKPOINT" : "WATCHPOINT",
            (unsigned long)config.address,
            slot,
            session->armed_threads.size());

    return session->id;
}

bool HwHookManager::detach(uint32_t id) {
    std::lock_guard<std::recursive_mutex> lk(mutex_);
    for (auto it = sessions_.begin(); it != sessions_.end(); ++it) {
        auto& s = *it;
        if (s->id == id) {
            // Clean up any pending step-over breakpoint
            if (s->step_over_slot >= 0 && s->stepping_thread > 0) {
                gum_thread_unset_hardware_breakpoint(s->stepping_thread, s->step_over_slot, nullptr);
                bp_slots_[s->step_over_slot] = false;
            }

            // Disarm on all armed threads
            for (pid_t tid : s->armed_threads) {
                if (s->config.type == HwHookType::BREAKPOINT) {
                    gum_thread_unset_hardware_breakpoint(tid, s->assigned_slot, nullptr);
                } else {
                    gum_thread_unset_hardware_watchpoint(tid, s->assigned_slot, nullptr);
                }
            }
            freeSlot(s->config.type, s->assigned_slot);
            s->active = false;
            sessions_.erase(it);
            HW_LOGI("HwHookSession #%u detached", id);
            return true;
        }
    }
    return false;
}

size_t HwHookManager::detachAll() {
    std::lock_guard<std::recursive_mutex> lk(mutex_);
    size_t count = 0;
    for (auto& s : sessions_) {
        if (s->step_over_slot >= 0 && s->stepping_thread > 0) {
            gum_thread_unset_hardware_breakpoint(s->stepping_thread, s->step_over_slot, nullptr);
            bp_slots_[s->step_over_slot] = false;
        }
        for (pid_t tid : s->armed_threads) {
            if (s->config.type == HwHookType::BREAKPOINT) {
                gum_thread_unset_hardware_breakpoint(tid, s->assigned_slot, nullptr);
            } else {
                gum_thread_unset_hardware_watchpoint(tid, s->assigned_slot, nullptr);
            }
        }
        freeSlot(s->config.type, s->assigned_slot);
        s->active = false;
        count++;
    }
    sessions_.clear();
    std::fill(std::begin(bp_slots_), std::end(bp_slots_), false);
    std::fill(std::begin(wp_slots_), std::end(wp_slots_), false);
    HW_LOGI("detachAll: detached %zu active hardware hooks", count);
    return count;
}

std::vector<HwHookSession> HwHookManager::listSessions() const {
    std::lock_guard<std::recursive_mutex> lk(mutex_);
    std::vector<HwHookSession> list;
    for (auto& s : sessions_) {
        list.push_back(*s);
    }
    return list;
}

bool HwHookManager::isSessionActive(uint32_t id) const {
    std::lock_guard<std::recursive_mutex> lk(mutex_);
    for (auto& s : sessions_) {
        if (s->id == id && s->active) return true;
    }
    return false;
}

void HwHookManager::getSlotStatus(bool out_bp[kMaxHwSlots],
                                  bool out_wp[kMaxHwSlots],
                                  int* out_bp_capacity,
                                  int* out_wp_capacity) const {
    std::lock_guard<std::recursive_mutex> lk(mutex_);
    for (int i = 0; i < kMaxHwSlots; i++) {
        if (out_bp) out_bp[i] = bp_slots_[i];
        if (out_wp) out_wp[i] = wp_slots_[i];
    }
    if (out_bp_capacity) *out_bp_capacity = bp_capacity_;
    if (out_wp_capacity) *out_wp_capacity = wp_capacity_;
}

size_t HwHookManager::rearmMissingThreads() {
    std::lock_guard<std::recursive_mutex> lk(mutex_);
    if (!initialized_) return 0;

    std::vector<pid_t> tids;
    EnumerateThreadIds(tids);

    size_t armed = 0;
    for (auto& s : sessions_) {
        if (!s->active) continue;
        for (pid_t tid : tids) {
            if (s->config.thread_id > 0 && s->config.thread_id != tid) continue;
            if (s->armed_threads.count(tid)) continue;
            if (armOnThread(*s, tid)) armed++;
        }
    }
    if (armed) {
        HW_LOGI("rearmMissingThreads: armed %zu (session,thread) pair(s)", armed);
    }
    return armed;
}

int HwHookManager::HandleException(void* raw_details, void* /*user_data*/) {
    auto* details = reinterpret_cast<GumExceptionDetails*>(raw_details);
    auto& mgr = HwHookManager::instance();
    std::unique_lock<std::recursive_mutex> lk(mgr.mutex_);

    pid_t tid = static_cast<pid_t>(details->thread_id);
    uintptr_t fault_addr = reinterpret_cast<uintptr_t>(details->address);
    uintptr_t pc_addr = 0;
#if defined(__aarch64__)
    pc_addr = static_cast<uintptr_t>(details->context.pc);
#endif

    // 1. Check if this is a step-over hit on a stepping thread
    for (auto& session : mgr.sessions_) {
        if (!session->active) continue;
        if (session->stepping_thread == tid && (session->step_over_pc == fault_addr || session->step_over_pc == pc_addr)) {
            // Disarm step-over slot
            gum_thread_unset_hardware_breakpoint(tid, session->step_over_slot, nullptr);
            mgr.bp_slots_[session->step_over_slot] = false;

            // Re-arm original slot
            if (session->config.type == HwHookType::BREAKPOINT) {
                gum_thread_set_hardware_breakpoint(tid, session->assigned_slot,
                    reinterpret_cast<GumAddress>(session->config.address), nullptr);
            } else {
                int condVal = 0;
                if ((int)session->config.condition & (int)HwWatchCondition::READ) condVal |= GUM_WATCH_READ;
                if ((int)session->config.condition & (int)HwWatchCondition::WRITE) condVal |= GUM_WATCH_WRITE;
                gum_thread_set_hardware_watchpoint(tid, session->assigned_slot,
                    reinterpret_cast<GumAddress>(session->config.address),
                    session->config.size, static_cast<GumWatchConditions>(condVal), nullptr);
            }

            session->step_over_slot = -1;
            session->step_over_pc = 0;
            session->stepping_thread = 0;
            return 1; // Handled step-over event!
        }
    }

    // 2. Check if this matches an active HW hook
    std::shared_ptr<HwHookSession> matched_session = nullptr;
    for (auto& session : mgr.sessions_) {
        if (!session->active) continue;

        if (session->config.type == HwHookType::BREAKPOINT) {
            if (fault_addr == session->config.address || pc_addr == session->config.address) {
                matched_session = session;
                break;
            }
        } else if (session->config.type == HwHookType::WATCHPOINT) {
            uintptr_t mem_addr = reinterpret_cast<uintptr_t>(details->memory.address);
            if (mem_addr >= session->config.address &&
                mem_addr < session->config.address + session->config.size) {
                matched_session = session;
                break;
            }
        }
    }

    if (!matched_session) {
        return 0; // Not our exception
    }

    if (matched_session->config.type == HwHookType::BREAKPOINT) {
        HW_LOGI("[HWBreakpoint] hit: addr=0x%lx (tid=%d, slot=%d)",
                (unsigned long)(fault_addr ? fault_addr : pc_addr), tid, matched_session->assigned_slot);
    } else {
        HW_LOGI("[HWWatchpoint] hit: addr=0x%lx, mem=0x%lx (tid=%d, slot=%d)",
                (unsigned long)(fault_addr ? fault_addr : pc_addr),
                (unsigned long)details->memory.address, tid, matched_session->assigned_slot);
    }

    // 3. Construct HwCpuContext
    HwCpuContext ctx;
    ctx.thread_id = tid;
    ctx.slot = matched_session->assigned_slot;
    ctx.raw_gum_context = &details->context;

#if defined(__aarch64__)
    ctx.pc = details->context.pc;
    ctx.sp = details->context.sp;
    ctx.lr = details->context.lr;
    ctx.fp = details->context.fp;
    ctx.nzcv = details->context.nzcv;
    std::memcpy(ctx.x, details->context.x, sizeof(ctx.x));
#endif

    if (matched_session->config.type == HwHookType::WATCHPOINT) {
        ctx.memory_address = reinterpret_cast<uint64_t>(details->memory.address);
        ctx.memory_operation = (details->memory.operation == GUM_MEMOP_READ) ? 1 : 2;
    }

    // 4. Invoke user callback WITHOUT the manager lock: callbacks may block for
    //    a long time (e.g. --stop-lib parks the thread) and may re-enter
    //    attach()/detach(), which would otherwise deadlock against resume().
    lk.unlock();
    if (matched_session->config.on_hit) {
        matched_session->config.on_hit(ctx);
    }
    lk.lock();

    if (!matched_session->active) {
        return 1; // session was detached by the callback
    }

    // Write back modified registers
#if defined(__aarch64__)
    details->context.pc = ctx.pc;
    details->context.sp = ctx.sp;
    details->context.lr = ctx.lr;
    details->context.fp = ctx.fp;
    std::memcpy(details->context.x, ctx.x, sizeof(ctx.x));
#endif

    // 5. Handle resuming execution
    if (matched_session->config.once) {
        // One-shot: disarm and deactivate
        mgr.disarmOnThread(*matched_session, tid);
        if (matched_session->config.thread_id == 0) {
            for (auto t : matched_session->armed_threads) {
                if (t != tid) mgr.disarmOnThread(*matched_session, t);
            }
        }
        matched_session->active = false;
        mgr.freeSlot(matched_session->config.type, matched_session->assigned_slot);
        return 1;
    }

    // Recurring: Step-over handling to avoid infinite loop
    if (matched_session->config.type == HwHookType::BREAKPOINT) {
        gum_thread_unset_hardware_breakpoint(tid, matched_session->assigned_slot, nullptr);

        int step_slot = -1;
        for (int i = 0; i < mgr.bp_capacity_; i++) {
            if (!mgr.bp_slots_[i] && i != matched_session->assigned_slot) {
                step_slot = i;
                break;
            }
        }

        if (step_slot >= 0) {
            uintptr_t next_pc = fault_addr + 4;
#if defined(__aarch64__)
            if (fault_addr >= 0x1000) {
                uint32_t insn = *reinterpret_cast<const uint32_t*>(fault_addr);
                // RET (d65f03c0)
                if ((insn & 0xfffffc1f) == 0xd65f0000) {
                    next_pc = static_cast<uintptr_t>(details->context.lr);
                }
                // B / BL (000101xx or 100101xx)
                else if ((insn & 0x7c000000) == 0x14000000) {
                    int32_t imm26 = static_cast<int32_t>(insn & 0x03ffffff);
                    if (imm26 & 0x02000000) imm26 |= 0xfc000000;
                    next_pc = fault_addr + (imm26 << 2);
                }
                // BR / BLR
                else if ((insn & 0xfffffc1f) == 0xd61f0000 || (insn & 0xfffffc1f) == 0xd63f0000) {
                    int rn = (insn >> 5) & 0x1f;
                    if (rn < 29) next_pc = static_cast<uintptr_t>(details->context.x[rn]);
                    else if (rn == 29) next_pc = static_cast<uintptr_t>(details->context.fp);
                    else if (rn == 30) next_pc = static_cast<uintptr_t>(details->context.lr);
                }
            }
#endif
            mgr.bp_slots_[step_slot] = true;
            matched_session->step_over_slot = step_slot;
            matched_session->step_over_pc = next_pc;
            matched_session->stepping_thread = tid;
            gum_thread_set_hardware_breakpoint(tid, step_slot, reinterpret_cast<GumAddress>(next_pc), nullptr);
        } else {
            matched_session->active = false;
            mgr.freeSlot(matched_session->config.type, matched_session->assigned_slot);
        }
        return 1;
    } else {
        // Watchpoint step-over
        gum_thread_unset_hardware_watchpoint(tid, matched_session->assigned_slot, nullptr);
        int step_slot = -1;
        for (int i = 0; i < mgr.bp_capacity_; i++) {
            if (!mgr.bp_slots_[i]) { step_slot = i; break; }
        }
        if (step_slot >= 0) {
            uintptr_t next_pc = fault_addr + 4;
            mgr.bp_slots_[step_slot] = true;
            matched_session->step_over_slot = step_slot;
            matched_session->step_over_pc = next_pc;
            matched_session->stepping_thread = tid;
            gum_thread_set_hardware_breakpoint(tid, step_slot, reinterpret_cast<GumAddress>(next_pc), nullptr);
        } else {
            matched_session->active = false;
            mgr.freeSlot(matched_session->config.type, matched_session->assigned_slot);
        }
        return 1;
    }
}

}} // namespace PI::Native
