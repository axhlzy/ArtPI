//
// pi_jni_sniffer.cpp - RegisterNatives 动态注册嗅探实现
//

#include "pi_jni_sniffer.h"
#include "pi_native_hook.h"
#include "xdl.h"
#include <android/log.h>
#include <map>
#include <mutex>
#include <cstring>

#define SN_LOGI(...) __android_log_print(ANDROID_LOG_INFO, "PI_Sniffer", __VA_ARGS__)
#define SN_LOGW(...) __android_log_print(ANDROID_LOG_WARN, "PI_Sniffer", __VA_ARGS__)

namespace PI { namespace Native {

namespace {

std::mutex g_mutex;
std::map<std::string, NativeMethodBinding> g_bindings;   // key: cls|name|sig
void* g_hook_cookie = nullptr;
bool g_started = false;

// libart 内部符号: art::JNI<false>::RegisterNatives
constexpr const char* kRegisterNativesSymbol =
    "_ZN3art3JNIILb0EE15RegisterNativesEP7_JNIEnvP7_jclassPK15JNINativeMethodi";
constexpr const char* kArtModule = "libart.so";

static std::string normalizeClass(std::string c) {
    if (c.size() >= 2 && c.front() == 'L' && c.back() == ';') {
        c = c.substr(1, c.size() - 2);
    }
    for (auto& ch : c) {
        if (ch == '.') ch = '/';
    }
    return c;
}

std::string makeKey(const std::string& c, const std::string& n, const std::string& s) {
    return normalizeClass(c) + "|" + n + "|" + s;
}

// jclass -> "com/example/Security" (via Class.getName + '.'->'/')
std::string classNameOf(JNIEnv* env, jclass clazz) {
    if (env == nullptr || clazz == nullptr) return "";
    jclass cls = env->GetObjectClass(clazz);
    if (cls == nullptr) return "";
    jmethodID mid = env->GetMethodID(cls, "getName", "()Ljava/lang/String;");
    env->DeleteLocalRef(cls);
    if (mid == nullptr) return "";
    auto name = (jstring) env->CallObjectMethod(clazz, mid);
    if (env->ExceptionCheck()) { env->ExceptionClear(); return ""; }
    std::string out;
    if (name != nullptr) {
        const char* utf = env->GetStringUTFChars(name, nullptr);
        if (utf != nullptr) { out = utf; env->ReleaseStringUTFChars(name, utf); }
        env->DeleteLocalRef(name);
    }
    for (auto& ch : out) if (ch == '.') ch = '/';
    return out;
}

void resolveModule(void* fnPtr, NativeMethodBinding& b) {
    xdl_info_t info = {};
    void* cache = nullptr;
    if (xdl_addr(fnPtr, &info, &cache) && info.dli_fname != nullptr) {
        const char* p = info.dli_fname;
        const char* base = p;
        for (; *p; p++) if (*p == '/') base = p + 1;
        b.moduleName = base;
        b.moduleOffset = (uintptr_t) fnPtr - (uintptr_t) info.dli_fbase;
    } else {
        b.moduleName = "<unknown>";
        b.moduleOffset = (uintptr_t) fnPtr;
    }
    if (cache != nullptr) xdl_addr_clean(&cache);
}

// ---------------------------------------------------------------------------
// RegisterNatives onEnter: 捕获 (env, clazz, methods, count)
// ---------------------------------------------------------------------------
void onRegisterNatives(HookContext& ctx) {
    auto* env = reinterpret_cast<JNIEnv*>(ctx.nthArgument(0));
    auto* clazz = reinterpret_cast<jclass>(ctx.nthArgument(1));
    auto* methods = reinterpret_cast<const JNINativeMethod*>(ctx.nthArgument(2));
    auto count = reinterpret_cast<intptr_t>(ctx.nthArgument(3));
    if (env == nullptr || clazz == nullptr || methods == nullptr || count <= 0) return;

    std::string cls = classNameOf(env, clazz);
    if (cls.empty()) return;

    std::lock_guard<std::mutex> lock(g_mutex);
    for (int i = 0; i < count; i++) {
        const JNINativeMethod& m = methods[i];
        if (m.name == nullptr || m.signature == nullptr || m.fnPtr == nullptr) continue;
        NativeMethodBinding b;
        b.className = cls;
        b.methodName = m.name;
        b.signature = m.signature;
        b.fnPtr = m.fnPtr;
        resolveModule(m.fnPtr, b);
        g_bindings[makeKey(b.className, b.methodName, b.signature)] = b;
        SN_LOGI("captured: %s.%s%s -> %s+%#lx [%s]",
                b.className.c_str(), b.methodName.c_str(), b.signature.c_str(),
                b.moduleName.c_str(), (unsigned long) b.moduleOffset,
                "dynamic-registered");
    }
}

} // namespace

// ============================================================================
// RegisterNativesSniffer
// ============================================================================
bool RegisterNativesSniffer::start(JNIEnv* env) {
    std::lock_guard<std::mutex> lock(g_mutex);
    if (g_started) return true;

    // 优先通过 JNIEnv 虚表函数地址 hook (精准且与混淆/符号剥离无关)
    void* target = nullptr;
    if (env != nullptr && env->functions != nullptr) {
        target = reinterpret_cast<void*>(env->functions->RegisterNatives);
        SN_LOGI("Attempting hook on env->functions->RegisterNatives = %p", target);
        g_hook_cookie = NativeHookManager::instance().hook(
            target,
            [](HookContext& ctx) { onRegisterNatives(ctx); },
            nullptr);
    }

    if (g_hook_cookie == nullptr) {
        // Fallback: 通过 NativeHookManager 按 libart 内部符号 hook
        g_hook_cookie = NativeHookManager::instance().hook(
            kArtModule, kRegisterNativesSymbol,
            [](HookContext& ctx) { onRegisterNatives(ctx); },
            nullptr);
    }

    if (g_hook_cookie == nullptr) {
        SN_LOGW("RegisterNatives hook failed (target=%p, symbol: %s)", target, kRegisterNativesSymbol);
        return false;
    }
    g_started = true;
    SN_LOGI("RegisterNatives sniffer started successfully");
    return true;
}

void RegisterNativesSniffer::stop() {
    std::lock_guard<std::mutex> lock(g_mutex);
    if (g_hook_cookie != nullptr) {
        NativeHookManager::instance().unhook(g_hook_cookie);
        g_hook_cookie = nullptr;
    }
    g_started = false;
}

bool RegisterNativesSniffer::isStarted() {
    std::lock_guard<std::mutex> lock(g_mutex);
    return g_started;
}

void* RegisterNativesSniffer::findBinding(const std::string& className,
                                          const std::string& methodName,
                                          const std::string& signature) {
    std::lock_guard<std::mutex> lock(g_mutex);
    auto it = g_bindings.find(makeKey(className, methodName, signature));
    return it == g_bindings.end() ? nullptr : it->second.fnPtr;
}

bool RegisterNativesSniffer::isRegisteredNative(void* fnPtr,
                                                NativeMethodBinding* outInfo) {
    if (fnPtr == nullptr) return false;
    std::lock_guard<std::mutex> lock(g_mutex);
    for (auto& kv : g_bindings) {
        if (kv.second.fnPtr == fnPtr) {
            if (outInfo != nullptr) *outInfo = kv.second;
            return true;
        }
    }
    return false;
}

}} // namespace PI::Native
