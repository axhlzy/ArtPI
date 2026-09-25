//
// pi_jni_bridge.h - §3.4 Java <-> Native 跨层交接桥
//
// 入口判定状态机 + AAPCS64 调用规约适配 + 异常仲裁。
// 线程状态协同: StateAndFlags 位布局因 ART 版本而异, 为避免位级硬编码
// 引发 GC 崩溃, 本实现沿用 Pine inline-hook 替身函数的运行模型
// (线程保持 kRunnable, 依赖目标函数内部的 JNI 边界自然挂起点),
// 并在 QBDI 指令回调中保留可插拔的挂起检查钩子。
//

#ifndef PI_JNI_BRIDGE_H
#define PI_JNI_BRIDGE_H

#include <jni.h>
#include <string>

namespace pine { namespace art { class ArtMethod; } }

namespace PI { namespace Trace {
    class ITracerListener;
} }

namespace PI { namespace Trace {

class JniNativeBridge {
public:
    // 检查并解析目标 Native 方法的可执行真实入口。
    // 返回 true = 可进入 QBDI 执行 (outFuncAddr 有效);
    // 返回 false = 需走 JniDirect 预热穿透 (如 art_jni_dlsym_lookup_stub)。
    static bool resolveNativeTarget(
        JNIEnv* env, pine::art::ArtMethod* am,
        const std::string& className, const std::string& methodName,
        const std::string& signature, void** outFuncAddr);

    // 将 Java 参数打包 (AAPCS64) 并路由至 QBDIEngine 执行,
    // 结果按 shorty[0] 还原为 jvalue。
    // 失败时返回零值 jvalue, 并置 *dispatched = false (调用方降级 JNI 直调)。
    static jvalue dispatchToNative(
        JNIEnv* env, pine::art::ArtMethod* am, jobject receiver,
        int argc, const jvalue* args, const char* shorty,
        int currentDepth, ITracerListener* listener,
        bool* dispatched = nullptr,
        void* targetFunc = nullptr);
};

}} // namespace PI::Trace

#endif // PI_JNI_BRIDGE_H
