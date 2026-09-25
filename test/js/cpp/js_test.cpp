//
// js_test.cpp - Suite 2 driver: exercise the agent's QuickJS bindings.
//
// Loads libartpi_agent.so (its ctor boots PI + QuickJS + the TCP server, then
// we call the exported artpi_agent_js_eval / artpi_agent_js_init entry points)
// and drives JS snippets from Java, returning the eval result string.
//
#include <jni.h>
#include <android/log.h>
#include <dlfcn.h>

#include <cstdint>
#include <cstring>
#include <string>

#define TEST_LOG_TAG "ArtPI_JsTest"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, TEST_LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, TEST_LOG_TAG, __VA_ARGS__)

namespace {

void* g_agent = nullptr;
int (*g_jsInit)(JNIEnv*) = nullptr;
const char* (*g_jsEval)(const char*) = nullptr;
const char* (*g_takeLog)() = nullptr;

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
        "/data/local/tmp/artpi_js_test/libartpi_agent.so",   // default push location
        "libartpi_agent.so",                                  // LD_LIBRARY_PATH
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
    g_takeLog = reinterpret_cast<const char* (*)()>(dlsym(g_agent, "artpi_agent_take_log"));
    if (!g_jsInit || !g_jsEval) {
        LOGE("dlsym artpi_agent_js_init/eval failed: %s", dlerror());
        return false;
    }
    g_jsInit(env);
    return true;
}

// A page-aligned buffer with known contents, so JS Memory.hexdump() has a
// safe, deterministic address to read.
alignas(64) uint8_t g_buf[256];

} // namespace

// A plain exported C function we can nhook, plus a JNI wrapper to call it.
extern "C" __attribute__((visibility("default"), noinline)) int artpi_test_native_add(int a, int b) {
    return a + b;
}

extern "C" {

JNIEXPORT jint JNICALL
Java_com_artpi_js_NativeJs_callNativeAdd(JNIEnv*, jclass, jint a, jint b) {
    return (jint) artpi_test_native_add((int) a, (int) b);
}

JNIEXPORT jlong JNICALL
Java_com_artpi_js_NativeJs_nativeAddAddress(JNIEnv*, jclass) {
    return (jlong) reinterpret_cast<uintptr_t>(&artpi_test_native_add);
}

// Static-registered JNI method used as the JNI boundary in unified-trace tests.
JNIEXPORT jint JNICALL
Java_com_artpi_js_JsNativeTarget_nadd(JNIEnv*, jclass, jint a, jint b) {
    return a + b;
}

JNIEXPORT jboolean JNICALL
Java_com_artpi_js_NativeJs_loadAgent(JNIEnv* env, jclass) {
    memset(g_buf, 0, sizeof(g_buf));
    for (int i = 0; i < 64; i++) g_buf[i] = (uint8_t) i;   // 00 01 02 ... 3f
    return LoadAgent(env) ? JNI_TRUE : JNI_FALSE;
}

JNIEXPORT jstring JNICALL
Java_com_artpi_js_NativeJs_eval(JNIEnv* env, jclass, jstring script) {
    if (!LoadAgent(env)) return env->NewStringUTF("[!] agent not loaded");
    std::string s = JStr(env, script);
    const char* r = g_jsEval(s.c_str());
    return env->NewStringUTF(r ? r : "");
}

// Drain the agent's captured log ring (returned as text).
JNIEXPORT jstring JNICALL
Java_com_artpi_js_NativeJs_takeLog(JNIEnv* env, jclass) {
    if (!LoadAgent(env) || !g_takeLog) return env->NewStringUTF("");
    const char* r = g_takeLog();
    return env->NewStringUTF(r ? r : "");
}

JNIEXPORT jlong JNICALL
Java_com_artpi_js_NativeJs_bufferAddress(JNIEnv*, jclass) {
    return (jlong) reinterpret_cast<uintptr_t>(g_buf);
}

JNIEXPORT jlong JNICALL
Java_com_artpi_js_NativeJs_bufferByte(JNIEnv*, jclass, jint i) {
    if (i < 0 || i >= (jint) sizeof(g_buf)) return -1;
    return (jlong) g_buf[i];
}

} // extern "C"
