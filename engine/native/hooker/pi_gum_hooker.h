//
// pi_gum_hooker.h - §3.1 Native Hook 适配层 (libgum 后端)
//
// 两层结构:
//   1. GumHooker        —— 规范契约 (§3.1): gum 专用 API, 回调暴露
//                          GumInvocationContext*, 支持监听/替换两种模式;
//   2. GumHookBackend   —— PI::Native::INativeHookBackend 的 gum 适配器,
//                          回调以后端无关的 HookContext 呈现, 注册进
//                          NativeHookManager (后端可替换为 libdobby 等)。
//

#ifndef PI_GUM_HOOKER_H
#define PI_GUM_HOOKER_H

#include "pi_native_hook.h"
#include <string>

typedef struct _GumInvocationContext GumInvocationContext;

namespace PI { namespace Native {

// ============================================================================
// §3.1 规范契约: gum 专用封装
// ============================================================================
class GumHooker {
public:
    static bool init();
    static bool isInitialized();

    // 1. 按内存地址 Hook (监听模式)
    static NativeHookHandle hook(
        void* targetAddr,
        std::function<void(GumInvocationContext* ctx)> onEnter,
        std::function<void(GumInvocationContext* ctx)> onLeave = nullptr);

    // 2. 按 SO 模块 + 符号名 Hook (结合 xDL, 支持非导出符号)
    static NativeHookHandle hook(
        const char* moduleName, const char* symbolName,
        std::function<void(GumInvocationContext* ctx)> onEnter,
        std::function<void(GumInvocationContext* ctx)> onLeave = nullptr);

    // 3. 替换模式 (Replace): outOriginal 带回原函数入口
    static NativeHookHandle replace(
        void* targetAddr, void* replacementFunc, void** outOriginal = nullptr);
};

// ============================================================================
// GumHookBackend: 后端抽象适配器 (注册进 NativeHookManager)
// ============================================================================
class GumHookBackend : public INativeHookBackend {
public:
    const char* name() const override { return "gum"; }
    bool init() override;
    bool isInitialized() const override;
    bool attach(void* target, const NativeHookCallback& onEnter,
                const NativeHookCallback& onLeave, void** outHandle) override;
    bool detach(void* handle) override;
    bool replace(void* target, void* replacement, void** outOriginal) override;
    void* findSymbol(const char* module, const char* symbol) override;
};

}} // namespace PI::Native

#endif // PI_GUM_HOOKER_H
