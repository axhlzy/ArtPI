//
// pi_interp_tracer.h - PI::Interp callback layer on top of nmmvm's VmTracer
//
// Brings the "sandbox" control plane described in
// OPTIMIZATION_AND_ARCHITECTURE_V2.md §3/§4/§8:
//   - per-instruction callbacks (may abort the run)
//   - invoke interception with three verdicts:
//       JniDirect : let ART execute the callee (system step-over / native)
//       StepIn    : recursively interpret the callee in-process (no hook!)
//       Mock      : forge the return value, skip the callee entirely
//   - scope filtering (system classes are black-boxed by default)
//
#ifndef PI_INTERP_TRACER_H
#define PI_INTERP_TRACER_H

#include "pi_common.h"
#include "dex/pi_dex_resolver.h"

#include <functional>
#include <string>
#include <vector>

namespace PI {
    namespace Trace { class ITracerListener; }
}

namespace PI { namespace Interp {

// §9 InvokeEvent OO 方法使用的底层分派 (签名感知装箱; 实现在 tracer.cpp)
namespace detail {
enum class DetailArgKind { INT, FP, OBJECT };
void setArgValue(JNIEnv* env, const std::string& signature, int index,
                 jvalue& slot, DetailArgKind kind, uint64_t raw);
void mockValue(const std::string& signature, jvalue& slot,
               DetailArgKind kind, uint64_t raw);
}

enum class InvokeVerdict {
    JniDirect = 0,   // 原生 JNI 调用 (后续可在此对接 Dobby / QBDI)
    StepIn    = 1,   // 原地递归单步步入子方法进行纯解释执行
    Mock      = 2,   // 跳过方法调用，直接填充 mockRet (函数打桩)
};

struct InsnEvent {
    JNIEnv*     env;
    void*       artMethod;        // 当前帧的 ArtMethod*（经 user 会话传递，可为 null）
    const char* methodName;       // 当前帧方法名（会话缓存，可为 null）
    int         depth;
    uint32_t    pc;
    uint16_t    inst;
    uint64_t    insns_executed;
    uint64_t* regs = nullptr;
    uint8_t*  regFlags = nullptr;
    uint32_t  regsSize = 0;
};

struct InvokeEvent {
    JNIEnv*     env;
    std::string className;        // "Ljava/lang/String;" 描述符
    std::string methodName;
    std::string signature;        // JNI 签名 "(...)..."
    bool        isStatic;
    bool        isNative;         // 目标是否为 JNI native 方法
    void*       artMethod = nullptr;
    jobject     receiver;         // 非 static 时有效
    int         argc;
    // onInvoke(Pre):  指向解释器实参数组【活指针】—— 此处修改立即生效,
    //                 对 JniDirect 与 StepIn 两条路径均有效 (篡改实参能力)
    // onInvokePost:   指向 Pre 时刻的【快照】—— 只读语义
    jvalue*     args;
    int         depth;            // 解释递归深度

    // =========================================================================
    // §9 面向对象的高层易用方法 (彻底废弃手动 4 参数工具函数)
    // =========================================================================
    // 仅参数列表字符串: `(1.44e+08)` / `("abc", 7)`
    std::string formatArgs() const;
    // 完整调用串 (点分类名): `com.example.app.bizHelper(10, "CT")`
    std::string formatMethod() const;
    // 返回值/异常串: `-> 28` / `-> "hello"` / `-> <exception: NullPointerException>`
    std::string formatResult(const jvalue* ret, bool hasException) const;
    std::string toString() const { return formatMethod(); }

    // =========================================================================
    // 类 CallFrame 的易用参数访问 (屏蔽 jvalue union; 按签名类型自动分派)
    // =========================================================================
    uint64_t    getArgRaw(int index) const;
    std::string getArgString(int index) const;

    // 修改入参: 支持整型/浮点/bool/jobject/const char*, 按声明类型装箱
    // (回调以 const& 接收事件, 但底层 args 缓冲可变 — 因此这里 const + const_cast)
    template<typename T>
    void setArg(int index, T val) const {
        if (index < 0 || index >= argc || args == nullptr) return;
        auto& slot = const_cast<jvalue&>(args[index]);
        using D = std::decay_t<T>;
        if constexpr (std::is_same_v<D, const char*> || std::is_same_v<D, char*>) {
            jstring s = env ? env->NewStringUTF(val) : nullptr;
            detail::setArgValue(env, signature, index, slot, detail::DetailArgKind::OBJECT, (uint64_t)(uintptr_t)s);
        } else if constexpr (std::is_same_v<D, jobject> || std::is_same_v<D, jstring> ||
                             std::is_same_v<D, jclass>) {
            detail::setArgValue(env, signature, index, slot, detail::DetailArgKind::OBJECT, (uint64_t)(uintptr_t)val);
        } else if constexpr (std::is_same_v<D, bool>) {
            detail::setArgValue(env, signature, index, slot, detail::DetailArgKind::INT, val ? 1 : 0);
        } else if constexpr (std::is_floating_point_v<D>) {
            double dv = static_cast<double>(val);
            uint64_t raw;
            std::memcpy(&raw, &dv, 8);
            detail::setArgValue(env, signature, index, slot, detail::DetailArgKind::FP, raw);
        } else if constexpr (std::is_pointer_v<D>) {
            detail::setArgValue(env, signature, index, slot, detail::DetailArgKind::OBJECT, (uint64_t)(uintptr_t)val);
        } else {
            detail::setArgValue(env, signature, index, slot, detail::DetailArgKind::INT,
                                static_cast<uint64_t>(static_cast<long long>(val)));
        }
    }

    // =========================================================================
    // 一行代码完成 Mock 打桩 (按返回类型自动装箱)
    // =========================================================================
    template<typename T>
    InvokeVerdict mock(jvalue* mockRet, T val) const {
        if (mockRet == nullptr) return InvokeVerdict::Mock;
        using D = std::decay_t<T>;
        if constexpr (std::is_same_v<D, bool>) {
            mockRet->z = val ? JNI_TRUE : JNI_FALSE;
        } else if constexpr (std::is_same_v<D, jobject> || std::is_same_v<D, jstring> ||
                             std::is_same_v<D, jclass> || std::is_pointer_v<D>) {
            mockRet->l = reinterpret_cast<jobject>(val);
        } else if constexpr (std::is_floating_point_v<D>) {
            double dv = static_cast<double>(val);
            uint64_t raw;
            std::memcpy(&raw, &dv, 8);
            detail::mockValue(signature, *mockRet, detail::DetailArgKind::FP, raw);
        } else {
            detail::mockValue(signature, *mockRet, detail::DetailArgKind::INT,
                              static_cast<uint64_t>(static_cast<long long>(val)));
        }
        return InvokeVerdict::Mock;
    }
};

struct Options {
    int64_t max_instructions = -1;   // 单次会话指令预算（防死循环），<0 不限
    bool    step_in_enabled  = false;
    int     max_depth        = 8;    // StepIn 递归深度上限
    bool    log_instructions = false; // §6: INSTRUCTION_DIFF 预设的指令日志通道
    bool    enable_native_step_in = false;   // NATIVE SPEC: Native 方法步入 QBDI
    bool    safe_handoff = false;    // bail at first system-call / allocation, let
                                     // the caller run the method natively instead
                                     // (avoids GC/stack-walk over nmmvm frames)
    Trace::ITracerListener* unified_listener = nullptr; // 跨层统一监听器
};

struct FilterOptions {
    bool filter_system_classes = true;       // 默认开启系统类黑盒透传
    std::vector<std::string> whitelist_pkgs; // 仅追踪的业务包描述符前缀 (如 "Lcom/example/")
    std::vector<std::string> blacklist_pkgs; // 额外黑名单包描述符前缀
};

// Android / Java 核心系统类判定 (描述符前缀)
inline bool isSystemDescriptor(const std::string& desc) {
    return desc.rfind("Ljava/", 0) == 0 ||
           desc.rfind("Ljavax/", 0) == 0 ||
           desc.rfind("Landroid/", 0) == 0 ||
           desc.rfind("Landroidx/", 0) == 0 ||
           desc.rfind("Lkotlin/", 0) == 0 ||
           desc.rfind("Ldalvik/", 0) == 0 ||
           desc.rfind("Llibcore/", 0) == 0 ||
           desc.rfind("Lsun/", 0) == 0 ||
           desc.rfind("Lorg/apache/harmony/", 0) == 0;
}

// ============================================================================
// 类型感知的值渲染 (复用 PI_VMTrace 的对象渲染: 纯 native, 无 Java 调用)
//   formatInvokeArgs  : 按签名逐参渲染  -> `(1.44e+08)` / `("abc", 7)`
//   formatReturnValue : 按签名渲染返回值 -> `2` / `"hello"` / `28`
//   对象走 native 类描述符 Type@addr; 数组 native 格式化; J/D/F 按数值; Z 输出 true/false
// ============================================================================
std::string formatInvokeArgs(JNIEnv* env, const std::string& signature,
                             const jvalue* args, int argc);
std::string formatReturnValue(JNIEnv* env, const std::string& signature,
                              const jvalue& ret);

// Pure-native object rendering (no Class.getName / toString / Arrays.toString):
// `Lcom/foo/Bar;` -> `Lcom/foo/Bar;@0x..`, arrays formatted via Get*ArrayRegion.
std::string FormatObjectNative(JNIEnv* env, jobject obj);

struct ExceptionEvent {
    JNIEnv*     env;
    std::string className;        // 当前帧所属类（顶层帧暂为空）
    std::string methodName;       // 当前帧方法名（顶层帧暂为空）
    int         depth;            // 解释递归深度
    jthrowable  exception;        // 抛出的异常对象 (JNI local ref)
    uint32_t    throwPc;          // 抛出点字节码偏移
    int         catchPc;          // 命中的 handler 偏移; -1 = 无人捕获(向调用方传播)
};

struct Callbacks {
    // 每条指令执行前触发；返回 false 主动中止整个解释会话
    std::function<bool(const InsnEvent&)> onInsn;

    // 调用子方法前触发：Java 方法可 StepIn / JniDirect；Native 方法可 Mock
    std::function<InvokeVerdict(const InvokeEvent&, jvalue* mockRet)> onInvoke;

    // 子方法返回（JNI 原生返回 / StepIn 返回 / Mock 三种路径均触发），
    // InvokeEvent 携带完整实参（args 为拷贝）
    std::function<void(const InvokeEvent&, const jvalue* ret, bool hasException)> onInvokePost;

    // 异常抛出事件（catchPc=-1 表示未捕获）
    std::function<void(const ExceptionEvent&)> onException;
};

// 当前线程是否正在解释执行给定 ArtMethod（防重入探测）
bool isInterpretingOnCurrentThread(void* artMethod);

struct InterpStackFrame {
    void* artMethod = nullptr;
    uint32_t dexPc = 0;
    int depth = 0;
};
std::vector<InterpStackFrame> getInterpCallStack();

struct ManagedStackSnapshot {
    void* thread = nullptr;
    uint64_t topQuickFrame = 0;
    uint64_t link = 0;
    uint64_t topShadowFrame = 0;
    size_t managedStackOffset = 0;
};
bool getManagedStackSnapshot(ManagedStackSnapshot& out);

// Class-ref cache used by the interpreter to resolve referenced classes WITHOUT
// env->FindClass() (which walks the managed stack and crashes inside a hook
// trampoline). Warm it at eval time via RegisterClassRef (e.g. from Java.prepare);
// the interpreter falls back to FindClass only when a descriptor is not cached.
void RegisterClassRef(JNIEnv* env, const char* jniName, jclass cls);

// Register the app ClassLoader used as a hook-path-safe fallback for class
// resolution (ClassLoader.loadClass runs as a managed frame). Call from InitJs.
void RegisterAppClassLoader(JNIEnv* env, jobject loader);

// Cache-first class lookup (returns a GLOBAL ref; do not DeleteLocalRef).
// Falls back to env->FindClass only when the name is not cached.
jclass FindClassRefCached(JNIEnv* env, const char* jniName);

// ---------------------------------------------------------------------------
// logcat per-instruction trace ("PI_VMTrace" lines; see pi_interp_tracer.cpp)
// ---------------------------------------------------------------------------
class TraceGuard {
public:
    TraceGuard(JNIEnv* env, const void* artDexFile, const uint16_t* insnsBase,
               uint32_t regsSize, const void* dexResolver = nullptr,
               const char* label = nullptr, bool force = false);
    ~TraceGuard();
    TraceGuard(const TraceGuard&) = delete;
    TraceGuard& operator=(const TraceGuard&) = delete;

private:
    struct State;
    State* state_ = nullptr;
    bool active_ = false;
};

void setTraceEnabled(bool on);
bool isTraceEnabled();

// internal wiring used by pi_interp_executor.cpp (opaque void* on purpose:
// the nmmvm VmFrameCtx/vmCode types stay private to the engine)
namespace detail {

// §9 InvokeEvent 方法用的底层分派 (签名感知装箱)
// NOTE: DetailArgKind / setArgValue / mockValue 已前置于文件顶部
char paramTypeChar(const std::string& signature, int index);
char returnTypeChar(const std::string& signature);

bool hasActiveCallbacks(const Callbacks* cbs);
void* makeSession(JNIEnv* env, const void* dexResolver, const Callbacks* cbs,
                  const Options* opts, const FilterOptions* filter, int depth,
                  void* frameArtMethod);
bool sessionAborted(void* session);
// True when the run bailed specifically to hand execution back to the real
// method (safe_handoff hit a system call / allocation).
bool sessionHandoff(void* session);
void destroySession(void* session);
void* makeFrameCtx(void* session, const void* code, int depth);
void pushFrame(void* frameCtx, void* artMethod);
void popFrame();
void destroyFrameCtx(void* frameCtx);
void setSessionListener(void* session, Trace::ITracerListener* listener);
} // namespace detail

}} // namespace PI::Interp

#endif // PI_INTERP_TRACER_H
