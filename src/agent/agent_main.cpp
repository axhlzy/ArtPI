//
// agent_main.cpp - libartpi_agent.so entry point
// Spawns Agent thread on injection, initializes PI & QuickJS, binds NetServer
//
#include "agent_net.h"
#include "agent_js.h"
#include "agent_common.h"
#include "agent_hw_hook.h"
#include "../../include/ArtPI.h"

#include <pthread.h>
#include <unistd.h>
#include <cstdio>
#include <fcntl.h>
#include <linux/futex.h>
#include <sys/syscall.h>
#include <dlfcn.h>
#include <android/log.h>

#define AG_LOGI(...) __android_log_print(ANDROID_LOG_INFO,  "ArtPI", __VA_ARGS__)
#define AG_LOGE(...) __android_log_print(ANDROID_LOG_ERROR, "ArtPI", __VA_ARGS__)

extern "C" {

struct ArtPIGateState {
    uint64_t regs[31];          // offset 0..240
    uint64_t sp;                // offset 248
    uint64_t pc;                // offset 256
    uint64_t pstate;            // offset 264
    volatile int32_t paused;    // offset 272 (1 = paused, 0 = resumed)
    int32_t  pad;
};

__attribute__((visibility("default"), used))
ArtPIGateState artpi_gate_state = {};



__attribute__((visibility("default"), used))
ArtPIGateState* ArtPIGateWait() {
    AG_LOGI("ArtPIGateWait: main thread (tid=%d) paused at PC=0x%llx, waiting for resume()...",
            gettid(), (unsigned long long) artpi_gate_state.pc);
    while (__atomic_load_n(&artpi_gate_state.paused, __ATOMIC_ACQUIRE) != 0) {
        syscall(__NR_futex, const_cast<int32_t*>(&artpi_gate_state.paused),
                FUTEX_WAIT, 1, nullptr, nullptr, 0);
    }
    AG_LOGI("ArtPIGateWait: main thread (tid=%d) resumed -> jumping to PC=0x%llx",
            gettid(), (unsigned long long) artpi_gate_state.pc);
    return &artpi_gate_state;
}

__attribute__((visibility("default"), used))
void artpi_gate_trampoline();

} // extern "C"

__asm__(
    ".text\n"
    ".align 4\n"
    ".global artpi_gate_trampoline\n"
    ".type artpi_gate_trampoline, %function\n"
    "artpi_gate_trampoline:\n"
    "sub sp, sp, #512\n"
    "stp q0,  q1,  [sp, #0]\n"
    "stp q2,  q3,  [sp, #32]\n"
    "stp q4,  q5,  [sp, #64]\n"
    "stp q6,  q7,  [sp, #96]\n"
    "stp q8,  q9,  [sp, #128]\n"
    "stp q10, q11, [sp, #160]\n"
    "stp q12, q13, [sp, #192]\n"
    "stp q14, q15, [sp, #224]\n"
    "stp q16, q17, [sp, #256]\n"
    "stp q18, q19, [sp, #288]\n"
    "stp q20, q21, [sp, #320]\n"
    "stp q22, q23, [sp, #352]\n"
    "stp q24, q25, [sp, #384]\n"
    "stp q26, q27, [sp, #416]\n"
    "stp q28, q29, [sp, #448]\n"
    "stp q30, q31, [sp, #480]\n"

    "bl ArtPIGateWait\n"
    "mov x16, x0\n"

    "ldp q0,  q1,  [sp, #0]\n"
    "ldp q2,  q3,  [sp, #32]\n"
    "ldp q4,  q5,  [sp, #64]\n"
    "ldp q6,  q7,  [sp, #96]\n"
    "ldp q8,  q9,  [sp, #128]\n"
    "ldp q10, q11, [sp, #160]\n"
    "ldp q12, q13, [sp, #192]\n"
    "ldp q14, q15, [sp, #224]\n"
    "ldp q16, q17, [sp, #256]\n"
    "ldp q18, q19, [sp, #288]\n"
    "ldp q20, q21, [sp, #320]\n"
    "ldp q22, q23, [sp, #352]\n"
    "ldp q24, q25, [sp, #384]\n"
    "ldp q26, q27, [sp, #416]\n"
    "ldp q28, q29, [sp, #448]\n"
    "ldp q30, q31, [sp, #480]\n"
    "add sp, sp, #512\n"

    "ldr  x17, [x16, #264]\n"
    "msr  nzcv, x17\n"
    "ldr  x17, [x16, #248]\n"
    "mov  sp, x17\n"

    "ldp x0,  x1,  [x16, #0]\n"
    "ldp x2,  x3,  [x16, #16]\n"
    "ldp x4,  x5,  [x16, #32]\n"
    "ldp x6,  x7,  [x16, #48]\n"
    "ldp x8,  x9,  [x16, #64]\n"
    "ldp x10, x11, [x16, #80]\n"
    "ldp x12, x13, [x16, #96]\n"
    "ldp x14, x15, [x16, #112]\n"
    "ldp x18, x19, [x16, #144]\n"
    "ldp x20, x21, [x16, #160]\n"
    "ldp x22, x23, [x16, #176]\n"
    "ldp x24, x25, [x16, #192]\n"
    "ldp x26, x27, [x16, #208]\n"
    "ldp x28, x29, [x16, #224]\n"
    "ldr x30,      [x16, #240]\n"
    "ldr x17,      [x16, #256]\n"
    "ldr x16,      [x16, #128]\n"
    "br  x17\n"
);

namespace artpi { namespace agent {

bool ArtPIIsProcessPaused() {
    return __atomic_load_n(&artpi_gate_state.paused, __ATOMIC_ACQUIRE) != 0;
}

uint64_t ArtPIGetGatePc() {
    return artpi_gate_state.pc;
}

bool ArtPIResumeProcess() {
    int32_t expected = 1;
    if (__atomic_compare_exchange_n(&artpi_gate_state.paused, &expected, 0,
                                    false, __ATOMIC_RELEASE, __ATOMIC_RELAXED)) {
        syscall(__NR_futex, const_cast<int32_t*>(&artpi_gate_state.paused),
                FUTEX_WAKE, 0x7fffffff, nullptr, nullptr, 0);
        return true;
    }
    return false;
}

void ArtPIPauseCurrentThread(uint64_t pc) {
    artpi_gate_state.pc = pc;
    __atomic_store_n(&artpi_gate_state.paused, 1, __ATOMIC_RELEASE);
    ArtPIGateWait();
}

}} // namespace artpi::agent

namespace {

[[maybe_unused]] JavaVM* FindJavaVM() {
    typedef jint (*JNI_GetCreatedJavaVMs_t)(JavaVM**, jsize, jsize*);
    void* handle = xdl_open("libart.so", XDL_DEFAULT);
    if (!handle) handle = xdl_open("libdvm.so", XDL_DEFAULT);
    if (!handle) return nullptr;

    auto getVms = reinterpret_cast<JNI_GetCreatedJavaVMs_t>(xdl_sym(handle, "JNI_GetCreatedJavaVMs", nullptr));
    if (!getVms) {
        xdl_close(handle);
        return nullptr;
    }

    JavaVM* vms[2] = {nullptr};
    jsize num = 0;
    if (getVms(vms, 2, &num) == JNI_OK && num > 0) {
        xdl_close(handle);
        return vms[0];
    }
    xdl_close(handle);
    return nullptr;
}

artpi::msgpack::Value HandleClientCommand(const artpi::msgpack::Value& req) {
    artpi::msgpack::Value resp = artpi::msgpack::Value::makeMap();
    int64_t seq = req.getInt("seq", 0);
    resp.set("t", artpi::msgpack::Value(2)); // 2 = RESP
    resp.set("seq", artpi::msgpack::Value(seq));

    std::string cmd = req.getString("cmd");
    if (cmd == "ping") {
        resp.set("ok", artpi::msgpack::Value(true));
        artpi::msgpack::Value data = artpi::msgpack::Value::makeMap();
        data.set("pong", artpi::msgpack::Value("artpi_agent"));
        data.set("pid", artpi::msgpack::Value(static_cast<int64_t>(getpid())));
        
        char path[64];
        snprintf(path, sizeof(path), "/proc/%d/cmdline", getpid());
        char cmdline[256] = {0};
        int fd = open(path, O_RDONLY | O_CLOEXEC);
        if (fd >= 0) {
            read(fd, cmdline, sizeof(cmdline) - 1);
            close(fd);
        }
        data.set("pkg", artpi::msgpack::Value(cmdline));
        resp.set("data", data);
    } else if (cmd == "eval") {
        const artpi::msgpack::Value* args = req.get("args");
        std::string script = args ? args->getString("script") : "";
        std::string result = artpi::agent::EvalJs(script);
        resp.set("ok", artpi::msgpack::Value(true));
        artpi::msgpack::Value data = artpi::msgpack::Value::makeMap();
        data.set("result", artpi::msgpack::Value(result));
        resp.set("data", data);
    } else {
        resp.set("ok", artpi::msgpack::Value(false));
        resp.set("err", artpi::msgpack::Value("unknown command: " + cmd));
    }
    return resp;
}

void* AgentThreadEntry(void*) {
    AG_LOGI("AgentThreadEntry: start (tid=%d)", gettid());

    // 0. Auto-arm boot dlopen monitor if requested before any app libraries load
    bool bootAutoResume = false;
    {
        char cmdline[256] = {0};
        int fdCmd = open("/proc/self/cmdline", O_RDONLY | O_CLOEXEC);
        if (fdCmd >= 0) {
            read(fdCmd, cmdline, sizeof(cmdline) - 1);
            close(fdCmd);
        }
        std::string pkg(cmdline);
        std::vector<std::string> tryPaths;
        if (!pkg.empty()) {
            tryPaths.push_back("/data/data/" + pkg + "/artpi_boot.cfg");
            tryPaths.push_back("/data/user/0/" + pkg + "/artpi_boot.cfg");
        }
        tryPaths.push_back("/data/local/tmp/artpi_boot.cfg");

        for (const auto& path : tryPaths) {
            int fd = open(path.c_str(), O_RDONLY | O_CLOEXEC);
            if (fd >= 0) {
                char buf[512] = {0};
                ssize_t n = read(fd, buf, sizeof(buf) - 1);
                close(fd);
                unlink(path.c_str());
                if (n > 0) {
                    std::string c(buf);
                    bool libLog = (c.find("libLog=1") != std::string::npos);
                    bootAutoResume = (c.find("autoResume=1") != std::string::npos);
                    std::string stopLib;
                    size_t p = c.find("stopLib=");
                    if (p != std::string::npos) {
                        size_t end = c.find('\n', p);
                        stopLib = c.substr(p + 8, (end == std::string::npos) ? std::string::npos : (end - (p + 8)));
                    }
                    if (libLog || !stopLib.empty()) {
                        AG_LOGI("AgentThreadEntry: Early boot dlopen monitor armed from %s (stopLib='%s', libLog=%d)",
                                path.c_str(), stopLib.c_str(), libLog ? 1 : 0);
                        artpi::agent::SetupDlopenHwMonitor(stopLib, libLog);
                    }
                }
                break;
            }
        }
    }

    // 1. Start Agent NetServer (MessagePack over TCP / AF_UNIX) immediately
    //    so the injector can discover and connect to endpoint without any delay!
    AG_LOGI("AgentThreadEntry: StartServer ...");
    bool srvOk = artpi::agent::StartServer(HandleClientCommand);
    for (int i = 0; i < 60; ++i) {
        const char* u = artpi::agent::GetUnixSocketName();
        if (artpi::agent::GetServerPort() > 0 || (u && *u)) break;
        usleep(5 * 1000);
    }
    const char* unixName = artpi::agent::GetUnixSocketName();
    AG_LOGI("AgentThreadEntry: StartServer -> %d, tcp_port=%d, unix=%s",
            srvOk ? 1 : 0, artpi::agent::GetServerPort(), unixName ? unixName : "(none)");

    // The injector may still hold the main thread under ptrace while the early
    // boot dlopen monitor is armed (notably with -S auto-gate). Retry in the
    // background so skipped threads get their hooks once the injector detaches
    // (and newly created threads get covered too). If the boot cfg requested
    // autoResume, release the gated main thread as soon as it is armed (with a
    // timeout fallback so a broken cfg can never leave the app frozen).
    {
        void* (*rearm_fn)(void*) = [](void* user) -> void* {
            bool autoResume = (user != nullptr);
            for (int i = 0; i < 20; ++i) {
                usleep(100 * 1000);
                size_t n = artpi::agent::HwHookRearmMissingThreads();
                if (n) AG_LOGI("background rearm: armed %zu missed thread(s)", n);

                if (autoResume) {
                    bool armed = artpi::agent::HwHookMainThreadArmed();
                    if (armed || i >= 15) {
                        bool resumed = artpi::agent::ArtPIResumeProcess();
                        AG_LOGI("background auto-resume: armed=%d resumed=%d",
                                armed ? 1 : 0, resumed ? 1 : 0);
                        autoResume = false;
                    }
                }
            }
            return nullptr;
        };
        pthread_t rearmThread;
        void* rearmArg = bootAutoResume ? reinterpret_cast<void*>(1) : nullptr;
        if (pthread_create(&rearmThread, nullptr, rearm_fn, rearmArg) == 0) {
            pthread_detach(rearmThread);
        }
    }

    // 2. Initialize QuickJS Runtime & Bindings
    AG_LOGI("AgentThreadEntry: InitJs ...");
    bool jsOk = artpi::agent::InitJs(nullptr);
    AG_LOGI("AgentThreadEntry: InitJs -> %d", jsOk ? 1 : 0);

    return nullptr;
}

__attribute__((constructor))
void ArtPiAgentCtor() {
    AG_LOGI("ArtPiAgentCtor: constructor entered");
    pthread_t th;
    int rc = pthread_create(&th, nullptr, AgentThreadEntry, nullptr);
    AG_LOGI("ArtPiAgentCtor: pthread_create rc=%d tid=%lu", rc, (unsigned long) th);
    if (rc == 0) pthread_detach(th);

}

} // namespace
