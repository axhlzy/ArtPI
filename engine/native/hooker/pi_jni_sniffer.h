//
// pi_jni_sniffer.h - §3.2 动态注册主动嗅探器
//
// 拦截 libart 的 art::JNI::RegisterNatives, 将全进程的 JNI 动态注册
// (类/方法/签名/C函数地址) 自动捕获到全局映射表, 解决商业 SO 混淆下
// dlsym 必死的问题。
//

#ifndef PI_JNI_SNIFFER_H
#define PI_JNI_SNIFFER_H

#include <jni.h>
#include <string>

namespace PI { namespace Native {

struct NativeMethodBinding {
    std::string className;        // 例如 "com/example/Security"
    std::string methodName;       // 例如 "verifySign"
    std::string signature;        // 例如 "(Ljava/lang/String;)Z"
    void*       fnPtr = nullptr;  // 目标真实 C 函数内存地址
    std::string moduleName;       // 所属 SO 模块名 (xdl_addr 解析)
    uintptr_t   moduleOffset = 0; // 相对 SO 基地址的偏移
};

class RegisterNativesSniffer {
public:
    // 安装 RegisterNatives 拦截 (内部走 NativeHookManager)
    static bool start(JNIEnv* env);
    static void stop();
    static bool isStarted();

    // 查找真实 C 函数指针; 未注册/未捕获返回 nullptr
    static void* findBinding(const std::string& className,
                             const std::string& methodName,
                             const std::string& signature);

    // 查询函数地址是否属于已知 JNI 注册函数
    static bool isRegisteredNative(void* fnPtr,
                                   NativeMethodBinding* outInfo = nullptr);
};

}} // namespace PI::Native

#endif // PI_JNI_SNIFFER_H
