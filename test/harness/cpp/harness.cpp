//
// harness.cpp - ArtPI trace/hook playground driver (app_process based).
//
// Loads libartpi_agent.so in-process (its ctor boots PI + QuickJS + the net
// server), so the agent REPL can be attached from the host via adb forward (or
// via `artpi-cli -P <pid>` which will discover and reuse the live agent).
//
// Java side (com.artpi.harness.Harness) runs a background "ticker" that calls
// Target.step(i) repeatedly, giving hooks/tracers a steady stream of calls to
// observe without driving a real app UI.
//
#include <jni.h>
#include <android/log.h>
#include <dlfcn.h>

#include <cstring>
#include <string>

#define TAG "ArtPI_Harness"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, TAG, __VA_ARGS__)

namespace {

void* g_agent = nullptr;
int (*g_jsInit)(JNIEnv*) = nullptr;
const char* (*g_jsEval)(const char*) = nullptr;
int (*g_listenPort)() = nullptr;
const char* (*g_unixName)() = nullptr;

std::string JStr(JNIEnv* env, jstring s) {
    if (!s) return "";
    const char* c = env->GetStringUTFChars(s, nullptr);
    std::string r = c ? c : "";
    if (c) env->ReleaseStringUTFChars(s, c);
    return r;
}

bool LoadAgent(JNIEnv* env) {
    if (g_agent) return true;

    const char* candidates[] = {
        "/data/local/tmp/artpi_harness/libartpi_agent.so",   // default push location
        "libartpi_agent.so",                                 // LD_LIBRARY_PATH
        nullptr
    };
    const char* picked = nullptr;
    for (int i = 0; candidates[i]; i++) {
        g_agent = dlopen(candidates[i], RTLD_NOW | RTLD_GLOBAL);
        if (g_agent) { picked = candidates[i]; break; }
    }
    if (!g_agent) {
        LOGE("dlopen libartpi_agent.so failed: %s", dlerror());
        return false;
    }
    LOGI("loaded agent: %s", picked);

    g_jsInit = reinterpret_cast<int (*)(JNIEnv*)>(dlsym(g_agent, "artpi_agent_js_init"));
    g_jsEval = reinterpret_cast<const char* (*)(const char*)>(dlsym(g_agent, "artpi_agent_js_eval"));
    g_listenPort = reinterpret_cast<int (*)()>(dlsym(g_agent, "artpi_agent_listen_port"));
    g_unixName = reinterpret_cast<const char* (*)()>(dlsym(g_agent, "artpi_agent_unix_name"));
    if (!g_jsInit || !g_jsEval) {
        LOGE("dlsym artpi_agent_js_init/eval failed: %s", dlerror());
        return false;
    }
    g_jsInit(env);
    return true;
}

} // namespace

// A plain exported C function that can be nhook'd / QBDI-traced, plus a JNI
// wrapper (Native.nativeAdd) for the Java-visible JNI boundary.
extern "C" __attribute__((visibility("default"), noinline)) int artpi_harness_native_add(int a, int b) {
    return a + b;
}

extern "C" {

JNIEXPORT jboolean JNICALL
Java_com_artpi_harness_Harness_load(JNIEnv* env, jclass) {
    return LoadAgent(env) ? JNI_TRUE : JNI_FALSE;
}

JNIEXPORT jstring JNICALL
Java_com_artpi_harness_Harness_eval(JNIEnv* env, jclass, jstring script) {
    std::string s = JStr(env, script);
    const char* r = g_jsEval ? g_jsEval(s.c_str()) : "[!] agent not loaded";
    return env->NewStringUTF(r ? r : "");
}

JNIEXPORT jint JNICALL
Java_com_artpi_harness_Harness_listenPort(JNIEnv*, jclass) {
    return g_listenPort ? g_listenPort() : -1;
}

JNIEXPORT jstring JNICALL
Java_com_artpi_harness_Harness_unixName(JNIEnv* env, jclass) {
    const char* n = g_unixName ? g_unixName() : nullptr;
    return env->NewStringUTF(n ? n : "");
}

JNIEXPORT jint JNICALL
Java_com_artpi_harness_Native_nativeAdd(JNIEnv*, jclass, jint a, jint b) {
    return static_cast<jint>(artpi_harness_native_add(static_cast<int>(a), static_cast<int>(b)));
}

} // extern "C"
