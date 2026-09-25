//
// pi_jni_bridge.cpp - Java <-> Native 跨层交接桥实现
//

#include "pi_jni_bridge.h"
#include "pi_unified_tracer.h"
#include "../../native/hooker/pi_native_hook.h"
#include "../../native/hooker/pi_jni_sniffer.h"
#include "../../native/qbdi/pi_qbdi_engine.h"
#include "../../native/hooker/pi_gum_hooker.h"
#include "art/art_method.h"
#include "xdl.h"
#include <android/log.h>
#include <cstring>

#define JB_LOGI(...) __android_log_print(ANDROID_LOG_INFO, "PI_Bridge", __VA_ARGS__)
#define JB_LOGW(...) __android_log_print(ANDROID_LOG_WARN, "PI_Bridge", __VA_ARGS__)

namespace PI { namespace Trace {

namespace {

// ---------------------------------------------------------------------------
// 描述符 "Lcom/foo/Bar;" -> JNI "com/foo/Bar" (FindClass 形式)
// ---------------------------------------------------------------------------
[[maybe_unused]] static std::string descriptorToJni(const std::string& desc) {
    if (desc.size() > 2 && desc[0] == 'L' && desc.back() == ';') {
        return desc.substr(1, desc.size() - 2);
    }
    return desc;
}

// ---------------------------------------------------------------------------
// dlsym 预热桩识别: entry == art_jni_dlsym_lookup_stub
// ---------------------------------------------------------------------------
bool isDlsymLookupStub(void* entry) {
    static void* stub = []() -> void* {
        void* h = xdl_open("libart.so", XDL_DEFAULT);
        if (h == nullptr) return nullptr;
        void* s = xdl_sym(h, "art_jni_dlsym_lookup_stub", nullptr);
        if (s == nullptr) s = xdl_sym(h, "art_jni_dlsym_lookup_stub_jit", nullptr);
        xdl_close(h);
        return s;
    }();
    return stub != nullptr && entry == stub;
}

// ---------------------------------------------------------------------------
// shorty -> 参数 AAPCS 打包 (X0..X7 / D0..D7)
//   isStatic, isCritical 决定 X0/X1 的占用
// ---------------------------------------------------------------------------
bool packArgs(const char* shorty, JNIEnv* env, jobject receiver,
              jclass staticClazz, int argc, const jvalue* args,
              uint64_t* x, double* d, bool isCritical, bool isStatic) {
    for (int i = 0; i < 8; i++) x[i] = 0;
    for (int i = 0; i < 8; i++) d[i] = 0;

    int xi = 0, di = 0;
    if (!isCritical) {
        x[xi++] = reinterpret_cast<uint64_t>(env);          // X0 = JNIEnv*
        x[xi++] = reinterpret_cast<uint64_t>(
            isStatic ? static_cast<void*>(staticClazz)
                     : static_cast<void*>(receiver));       // X1 = thiz/clazz
    }
    // shorty[0] 是返回类型; 参数从 shorty[1] 起
    for (int i = 1; shorty[i] != '\0' && i <= argc; i++) {
        char t = shorty[i];
        const jvalue& v = args[i - 1];
        if (t == 'D' || t == 'F') {
            if (di >= 8) return false;                       // 栈参暂不支持 → 降级
            if (t == 'F') {
                float f = v.f;
                uint32_t bits; std::memcpy(&bits, &f, 4);
                std::memcpy(&d[di], &bits, 4);               // 低 32 位
            } else {
                d[di] = v.d;
            }
            di++;
        } else {
            if (xi >= 8) return false;
            if (t == 'J') x[xi] = static_cast<uint64_t>(v.j);
            else if (t == 'L') x[xi] = reinterpret_cast<uint64_t>(v.l);
            else x[xi] = static_cast<uint32_t>(v.i);         // I/S/B/C/Z
            xi++;
        }
    }
    return true;
}

} // namespace

// ============================================================================
// resolveNativeTarget: 嗅探表 → entry_point → dlsym 桩判定
// ============================================================================
bool JniNativeBridge::resolveNativeTarget(
        JNIEnv* env, pine::art::ArtMethod* am,
        const std::string& className, const std::string& methodName,
        const std::string& signature, void** outFuncAddr) {
    (void) env;
    if (am == nullptr || outFuncAddr == nullptr) return false;

    // 1. 嗅探表优先 (动态注册, dlsym 必死场景的唯一解)
    void* fn = Native::RegisterNativesSniffer::findBinding(className, methodName, signature);
    if (fn != nullptr) {
        PI::Native::QBDIEngine::current()->addInstrumentedModuleFromAddr((uintptr_t) fn);
        *outFuncAddr = fn;
        return true;
    }

    // 2. entry_point_from_jni (静态注册 / 已解析)
    void* entry = am->GetEntryPointFromJni();
    if (entry == nullptr) return false;

    // 3. dlsym 查找桩: 需要一次 JniDirect 预热让 ART 解析真实地址
    if (isDlsymLookupStub(entry)) return false;

    // 4. 业务 SO 白名单自动圈定
    PI::Native::QBDIEngine::current()->addInstrumentedModuleFromAddr((uintptr_t) entry);
    *outFuncAddr = entry;
    return true;
}

// ============================================================================
// dispatchToNative: Java 实参 → AAPCS64 → QBDI 执行 → jvalue
// ============================================================================
jvalue JniNativeBridge::dispatchToNative(
        JNIEnv* env, pine::art::ArtMethod* am, jobject receiver,
        int argc, const jvalue* args, const char* shorty,
        int currentDepth, ITracerListener* listener,
        bool* dispatched,
        void* targetFunc) {
    jvalue ret{};
    ret.j = 0;
    if (dispatched != nullptr) *dispatched = false;
    if (am == nullptr || shorty == nullptr || shorty[0] == '\0') return ret;

    bool isStatic = am->IsStatic();
    // NOTE: flag-based critical-native detection is unreliable — on several ART
    // versions kAccCriticalNative (0x00200000) collides with runtime-internal
    // access flags (kAccPreCompiled / kAccCompileDontBother), so ordinary JNI
    // methods get misclassified and their JNIEnv*/jclass arguments are dropped
    // (args shift -> wrong result). Critical natives carry no JNIEnv and cannot
    // be dispatched through this bridge anyway, so always pack env+thiz.
    bool isCritical = false;

    // 1. 解析真实入口
    void* fn = targetFunc;
    if (fn == nullptr) {
        void* entry = am->GetEntryPointFromJni();
        if (entry == nullptr || isDlsymLookupStub(entry)) {
            return ret;                              // 预热穿透
        }
        fn = entry;
    }
    PI::Native::QBDIEngine::current()->addInstrumentedModuleFromAddr((uintptr_t) fn);

    // 2. 静态方法需要 jclass
    jclass staticClazz = nullptr;
    if (isStatic && !isCritical) {
        staticClazz = reinterpret_cast<jclass>(receiver);
        receiver = nullptr;
    }

    // 3. AAPCS 打包
    uint64_t x[8];
    double d[8];
    if (!packArgs(shorty, env, receiver, staticClazz, argc, args, x, d, isCritical, isStatic)) {
        JB_LOGW("dispatchToNative: arg overflow (argc=%d), fallback JNI", argc);
        return ret;
    }

    // 4. QBDI 执行
    PI::Trace::UnifiedCallDepth::set(currentDepth);
    PI::Native::QBDIEngine* engine = PI::Native::QBDIEngine::current();
    engine->setInstructionBudget(2'000'000);   // 熔断: 200 万指令
    PI::Native::NativeRunResult rr = engine->run(fn, std::vector<uint64_t>(x, x + 8),
                                     std::vector<double>(d, d + 8));
    if (listener != nullptr) {
        PI::Trace::CallEvent ev{};
        ev.layer = PI::Trace::Layer::NATIVE_ARM64;
        ev.callee_target = reinterpret_cast<uint64_t>(fn);
        ev.is_cross_bridge = true;
        ev.argc = argc;
        for (int i = 0; i < argc && i < 8; i++) ev.args[i] = x[i];
        ev.return_value = rr.gprResult;
        listener->onReturn(ev);
    }

    // 5. 异常仲裁: 有异常 → 废弃 Native 返回值, 让异常链向外冒泡
    if (env->ExceptionCheck()) {
        JB_LOGW("dispatchToNative: exception pending after native run");
        if (dispatched != nullptr) *dispatched = true;
        return ret;   // 零值 + 异常挂起
    }
    if (rr.status != PI::Native::NativeRunResult::OK) return ret;

    // 6. 返回值还原 (按 shorty[0])
    switch (shorty[0]) {
        case 'V': ret.j = 0; break;
        case 'J': ret.j = static_cast<jlong>(rr.gprResult); break;
        case 'D': std::memcpy(&ret.d, &rr.fprResult, 8); break;
        case 'F': {
            float f;
            uint32_t bits = static_cast<uint32_t>(rr.gprResult & 0xffffffffu);
            std::memcpy(&f, &bits, 4);
            ret.f = f;
            break;
        }
        case 'L': ret.l = reinterpret_cast<jobject>(rr.gprResult); break;
        default:  ret.i = static_cast<jint>(rr.gprResult); break;   // I/S/B/C/Z
    }
    if (dispatched != nullptr) *dispatched = true;
    JB_LOGI("dispatchToNative: %p OK (%llu insns) -> shorty=%c",
            fn, (unsigned long long) rr.instructionsExecuted, shorty[0]);
    return ret;
}

}} // namespace PI::Trace
