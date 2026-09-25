//
// pi_native_hook.h - Native Hook 抽象管理层 (后端可替换: gum / dobby / ...)
//
// 设计契约:
//   1. HookContext 与 GumInvocationContext 能力【1:1 全量镜像】—— 参数/返回值
//      读写、返回地址、线程 id、深度、listener/replacement 数据、CPU 上下文,
//      另提供 raw() 逃生舱直达后端原始上下文 (100% 后端能力可用);
//   2. 回调统一为 std::function (lambda), 用户代码零 gum 类型依赖;
//   3. INativeHookBackend 为后端契约, 新框架 (如 libdobby) 只需实现并
//      registerBackend 即可整体替换, 上层零改动。
//

#ifndef PI_NATIVE_HOOK_H
#define PI_NATIVE_HOOK_H

#include <jni.h>
#include <cstdint>
#include <cstring>
#include <functional>
#include <string>
#include <vector>

#if defined(__GNUC__) || defined(__clang__)
#define PI_NATIVE_EXPORT __attribute__((visibility("default")))
#else
#define PI_NATIVE_EXPORT
#endif

namespace PI { namespace Native {

// ============================================================================
// 后端无关调用上下文 —— 与 GumInvocationContext 能力 1:1 对齐
// ============================================================================
class HookContext {
public:
    virtual ~HookContext() = default;

    // ---- 参数 / 返回值 (gum: get/replace_nth_argument, get/replace_return_value)
    virtual void* nthArgument(int index) const = 0;
    virtual void replaceNthArgument(int index, void* value) = 0;
    virtual void* returnValue() const = 0;
    virtual void replaceReturnValue(void* value) = 0;

    // ---- 调用元信息
    virtual void* returnAddress() const = 0;   // gum: get_return_address
    virtual unsigned int threadId() const = 0; // gum: get_thread_id
    virtual unsigned int depth() const = 0;    // gum: get_depth

    // ---- listener / replacement 数据槽
    virtual void* listenerThreadData(size_t requiredSize) const = 0;
    virtual void* listenerFunctionData() const = 0;
    virtual void* listenerInvocationData(size_t requiredSize) const = 0;
    virtual void* replacementData() const = 0;

    // ---- CPU 上下文 (gum: GumCpuContext*, 可读写全部寄存器)
    virtual void* cpuContext() const = 0;

    // ---- 后端原始上下文逃生舱 (gum: GumInvocationContext*, 100% 能力)
    virtual void* raw() const = 0;

    // ---- 便捷封装 (基于上述原语) ----
    template<typename T>
    T argAs(int index) const {
        void* p = nthArgument(index);
        if (p == nullptr) return T{};
        return *reinterpret_cast<const T*>(p);
    }
    template<typename T>
    void setArgAs(int index, T value) {
        T v = value;
        replaceNthArgument(index, *reinterpret_cast<void**>(&v));
    }

private:
    static constexpr uint64_t zero_ = 0;
};

// lambda 回调签名 (onEnter / onLeave 共用)
using NativeHookCallback = std::function<void(HookContext& ctx)>;

// ============================================================================
// 后端契约: libgum / libdobby / ... 各实现一份, 经 NativeHookManager 注册
// ============================================================================
class INativeHookBackend {
public:
    virtual ~INativeHookBackend() = default;

    virtual const char* name() const = 0;

    virtual bool init() = 0;
    virtual bool isInitialized() const = 0;

    virtual bool attach(void* target,
                        const NativeHookCallback& onEnter,
                        const NativeHookCallback& onLeave,
                        void** outHandle) = 0;
    virtual bool detach(void* handle) = 0;

    virtual bool replace(void* target, void* replacement,
                         void** outOriginal) = 0;

    virtual void* findSymbol(const char* module, const char* symbol) = 0;
};

// ============================================================================
// 管理门面: 后端注册表 + 统一 hook/replace/unhook
// ============================================================================
class PI_NATIVE_EXPORT NativeHookManager {
public:
    static NativeHookManager& instance();

    static void registerBackend(INativeHookBackend* backend, bool makeDefault = false);
    bool init(const char* backendName = nullptr);
    bool isInitialized() const;
    INativeHookBackend* backend(const char* name = nullptr) const;

    // ---- 高层 lambda API ----
    static void* hook(void* target,
               const NativeHookCallback& onEnter,
               const NativeHookCallback& onLeave = nullptr);
    static void* hook(const char* module, const char* symbol,
               const NativeHookCallback& onEnter,
               const NativeHookCallback& onLeave = nullptr);
    static void* replace(void* target, void* replacement, void** outOriginal = nullptr);
    static bool unhook(void* handle);

// Impl 需被 cpp 侧的静态方法访问 (singleton 惯例) — public (singleton 惯例)
    struct Impl;
    Impl* impl_ = nullptr;
};

// ============================================================================
// RAII 句柄: 析构 / 显式 unhook 自动走管理门面
// 实现 cookie 语义: cookie = 后端会话指针, 由后端 attach 产出
// (NativeHookManager::hook 系列的返回值)。
// ============================================================================
class PI_NATIVE_EXPORT NativeHookHandle {
public:
    NativeHookHandle();
    ~NativeHookHandle();
    NativeHookHandle(NativeHookHandle&& other) noexcept;
    NativeHookHandle& operator=(NativeHookHandle&& other) noexcept;
    NativeHookHandle(const NativeHookHandle&) = delete;
    NativeHookHandle& operator=(const NativeHookHandle&) = delete;

    bool isValid() const;
    explicit operator bool() const { return isValid(); }
    bool unhook();
    void* getBackup() const;

    // 内部构造入口 (NativeHookManager / GumHooker 使用)
    static NativeHookHandle fromCookie(void* cookie) {
        NativeHookHandle h;
        h.cookie_ = cookie;
        return h;
    }

private:
    void* cookie_ = nullptr;
};

}} // namespace PI::Native

#endif // PI_NATIVE_HOOK_H
