//
// agent_main.cpp - libartpi_agent.so entry point
// Spawns Agent thread on injection, initializes PI & QuickJS, binds NetServer
//
#include "agent_net.h"
#include "agent_js.h"
#include "../../include/ArtPI.h"

#include <pthread.h>
#include <unistd.h>
#include <cstdio>
#include <fcntl.h>
#include <android/log.h>

#define AG_LOGI(...) __android_log_print(ANDROID_LOG_INFO,  "ArtPI", __VA_ARGS__)
#define AG_LOGE(...) __android_log_print(ANDROID_LOG_ERROR, "ArtPI", __VA_ARGS__)

namespace {

JavaVM* FindJavaVM() {
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
    // 1. Wait a moment for caller dlopen completion
    usleep(200 * 1000);

    // 2. Resolve JavaVM & JNIEnv
    JavaVM* vm = FindJavaVM();
    AG_LOGI("AgentThreadEntry: FindJavaVM -> %p", (void*) vm);
    JNIEnv* env = nullptr;
    if (vm) {
        vm->AttachCurrentThread(&env, nullptr);
    }
    AG_LOGI("AgentThreadEntry: AttachCurrentThread -> %p", (void*) env);

    if (env) {
        // 3. Initialize Core ArtPI (from libartpi_static.a)
        AG_LOGI("AgentThreadEntry: PI::init ...");
        PI::init(env);
        AG_LOGI("AgentThreadEntry: PI::init done");
    }

    // 4. Initialize QuickJS Runtime & Bindings
    AG_LOGI("AgentThreadEntry: InitJs ...");
    bool jsOk = artpi::agent::InitJs(env);
    AG_LOGI("AgentThreadEntry: InitJs -> %d", jsOk ? 1 : 0);

    // 5. Start Agent NetServer (MessagePack over TCP)
    AG_LOGI("AgentThreadEntry: StartServer ...");
    bool srvOk = artpi::agent::StartServer(HandleClientCommand);
    usleep(300 * 1000);   // let ServerWorker bind before reporting
    const char* unixName = artpi::agent::GetUnixSocketName();
    AG_LOGI("AgentThreadEntry: StartServer -> %d, tcp_port=%d, unix=%s",
            srvOk ? 1 : 0, artpi::agent::GetServerPort(), unixName ? unixName : "(none)");

    if (vm) {
        vm->DetachCurrentThread();
    }

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
