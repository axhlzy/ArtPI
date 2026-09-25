//
// ArtPI.h - Art Process Inspector (ArtPI)
// High-Performance Native Toolkit for Android ART Runtime Introspection & Manipulation
//
// Features:
//   1. Resolve: Dynamic ArtMethod pointer resolution (by Class+Name+Sig, JNI reflected Method, or direct pointer)
//   2. Smali Disassembly: Memory Dex parsing & real-time Smali disassembling (via libdexfile)
//   3. Method Hook: Il2cppHooker-style ergonomics (frame[0], frame.callOriginal(), frame.setResult())
//   4. Method Trace: One-line automatic method entry/exit/backtrace monitoring
//   5. xDL Linker: Built-in linker namespace bypass for Android 7.0+ (open system libs & resolve hidden symbols)
//
// Usage:
//   #include "ArtPI.h"
//
//   // 1. Resolve and dump Smali bytecode
//   PI::resolve(env, clazz, "testMethod", "(Ljava/lang/String;)Ljava/lang/String;").showSmali();
//
//   // 2. Resolve and hook method
//   auto handle = PI::resolve(env, clazz, "testAdd", "(II)I")
//       .hook([](JNIEnv* env, PI::CallFrame& frame) {
//           int a = frame[0];
//           int b = frame[1];
//           frame.callOriginal();
//           frame.setResult(30888);
//       });
//
//   // 3. Unhook at any time
//   handle.unhook();
//
//   // 4. One-line method tracing
//   auto trace_handle = PI::resolve(env, clazz, "testAdd", "(II)I").trace("MyTraceTag");
//

#ifndef ART_PI_H
#define ART_PI_H

#include <jni.h>
#include <string>
#include <vector>
#include <memory>
#include <functional>
#include <cstdint>
#include <cstring>
#include <sstream>
#include <type_traits>

#if defined(__GNUC__) || defined(__clang__)
#define ARTPI_EXPORT __attribute__((visibility("default")))
#else
#define ARTPI_EXPORT
#endif

// ======================================================================
// Built-in xDL Dynamic Linker (Bypass Android 7.0+ Linker Restrictions)
// ======================================================================
#ifndef _XDL_H_
#define _XDL_H_ 1

#ifdef __cplusplus
extern "C" {
#endif

#define XDL_DEFAULT           0x00
#define XDL_TRY_FORCE_LOAD    0x01
#define XDL_ALWAYS_FORCE_LOAD 0x02
#define XDL_DI_DLINFO         1

typedef struct {
    const char* dli_fname;
    void*       dli_fbase;
    const char* dli_sname;
    void*       dli_saddr;
    // Must match external/xdl exactly — xdl_addr() writes all 7 fields; a
    // reduced struct would overflow the caller's stack.
    size_t      dli_ssize;
    const void* dlpi_phdr;
    size_t      dlpi_phnum;
} xdl_info_t;

ARTPI_EXPORT void* xdl_open(const char* filename, int flags);
ARTPI_EXPORT void* xdl_sym(void* handle, const char* symbol, size_t* symbol_size);
ARTPI_EXPORT void* xdl_dsym(void* handle, const char* symbol, size_t* symbol_size);
ARTPI_EXPORT int   xdl_addr(void* addr, xdl_info_t* info, void** cache);
ARTPI_EXPORT void  xdl_addr_clean(void** cache);
ARTPI_EXPORT void* xdl_close(void* handle);
ARTPI_EXPORT int   xdl_iterate_phdr(int (*callback)(struct dl_phdr_info *, size_t, void *), void *data, int flags);

#ifdef __cplusplus
}
#endif

#endif // _XDL_H_

// Forward declaration of internal ART structure
namespace pine { namespace art { class ArtMethod; } }
using ArtMethod = pine::art::ArtMethod;

namespace PI {
    class Method;
    class HookHandle;
    namespace Interp {
        struct Callbacks;   // defined in src/sandbox/pi_interp_tracer.h
        struct Options;     // defined in src/sandbox/pi_interp_tracer.h
    }
    namespace Native {
        // NATIVE SPEC 门面: gum + RegisterNatives 嗅探 + QBDI 引擎一键初始化
        ARTPI_EXPORT bool initNativeEngine(JNIEnv* env);
        ARTPI_EXPORT bool isNativeEngineInitialized();
    }
    namespace Trace {
        // §7.2 【高层用户端】一行代码开箱即用的预设模式
        enum class TracePreset {
            METHOD_ONLY,        // 体验 1: 只看方法调用树 (自动 StepOver 系统类, 极轻量)
            INSTRUCTION_DIFF,   // 体验 2: 逐行打印 Smali 指令与寄存器变化 (算法逆向/脱壳)
            FULL_STACK_NATIVE,  // 体验 3: 跨 JNI 边界穿透 Native (QBDI/Dobby 桥接预留中)
        };
    }
}

// Native register context. Layout MUST match engine/pine/pine_native.h and the
// assembly produced context in engine/trampoline/arch/arm64.S
// (pine_native_bridge_trampoline): r[0..30] @0, sp @248, d0..d7 @256.
struct PineNativeContext {
    uint64_t r[31];
    uint64_t sp;
    double   d[8];
};

namespace pine_native {

class CallFrame;
class ArgProxy;
class ArgsAccessor;

// ----------------------------------------------------------------------
// ArgProxy: Provides seamless [] operator indexing for CallFrame
// ----------------------------------------------------------------------
class ARTPI_EXPORT ArgProxy {
private:
    CallFrame* frame_;
    int index_;             // -1: thisObject, >= 0: method argument index

public:
    ArgProxy(CallFrame* frame, int index) : frame_(frame), index_(index) {}

    bool isThis() const { return index_ < 0; }
    int getIndex() const { return index_; }
    bool isObject() const;

    bool operator==(std::nullptr_t) const { return static_cast<jobject>(*this) == nullptr; }
    bool operator!=(std::nullptr_t) const { return static_cast<jobject>(*this) != nullptr; }

    operator jobject() const;
    operator jstring() const;
    operator jclass() const;
    operator int() const;
    operator jlong() const;
    operator bool() const;
    operator double() const;
    operator float() const;
    operator void*() const;
    operator std::string() const;

    ArgProxy& operator=(jobject obj);
    inline ArgProxy& operator=(jstring str) { return *this = static_cast<jobject>(str); }
    ArgProxy& operator=(int val);
    ArgProxy& operator=(jlong val);
    ArgProxy& operator=(bool val);
    ArgProxy& operator=(double val);
    ArgProxy& operator=(float val);
    ArgProxy& operator=(void* val);
    ArgProxy& operator=(const char* str);
    ArgProxy& operator=(const std::string& str);

    std::string as_string() const;
    jobject as_jobject() const;
    jstring as_jstring() const { return static_cast<jstring>(*this); }
    template<typename T> T as() const;
};

class ARTPI_EXPORT ArgsAccessor {
private:
    CallFrame* frame_;
public:
    explicit ArgsAccessor(CallFrame* frame) : frame_(frame) {}
    ArgProxy operator[](int index) const;
};

// ----------------------------------------------------------------------
// CallFrame: Encapsulates method call context, arguments, return value
// ----------------------------------------------------------------------
class ARTPI_EXPORT CallFrame {
public:
    JNIEnv* env;
    void* target_method;
    PineNativeContext* ctx;
    void* origin_entry;
    bool is_static;
    std::string method_name;
    std::string signature;
    std::string class_name;
    int arg_count;
    std::vector<std::string> arg_types;
    char return_type;
    jclass clazz;
    jmethodID mid;
    bool has_custom_result;
    bool original_invoked;
    uint64_t original_result_raw;

    ArgProxy thiz;
    ArgsAccessor args;

    CallFrame(JNIEnv* env, void* target, PineNativeContext* ctx, void* origin,
              bool isStatic, const std::string& methodName, const std::string& sig,
              const std::string& className = "");

    bool isArgObject(int index) const;
    JNIEnv* getEnv() const { return env; }

    ArgProxy operator[](size_t index);
    const ArgProxy operator[](size_t index) const;

    std::string getMethodToString() const;
    const std::string& getMethodName() const { return method_name; }
    const std::string& getMethodSig() const { return signature; }
    bool isStatic() const { return is_static; }

    jobject getThisObject() const;
    jobject getThis() const { return getThisObject(); }
    jobject thisObject() const { return getThisObject(); }

    int getArgCount() const { return arg_count; }
    jobject getArg(int index) const;
    template<typename T>
    T getArg(int index) const {
        if constexpr (std::is_same_v<T, jobject> || std::is_same_v<T, jstring> || std::is_same_v<T, jclass>) {
            return reinterpret_cast<T>(getArg(index));
        } else if constexpr (std::is_floating_point_v<T>) {
            // Floating point args live in the d register file (see ArgProxy)
            return static_cast<T>(ctx->d[index]);
        } else if constexpr (std::is_pointer_v<T>) {
            return reinterpret_cast<T>(getArgRaw(index));
        } else {
            return static_cast<T>(getArgRaw(index));
        }
    }
    void setArg(int index, jobject arg);
    inline void setArg(int index, jstring str) { setArg(index, static_cast<jobject>(str)); }
    uint64_t getArgRaw(int index) const;
    void setArgRaw(int index, uint64_t val);
    std::string getArgString(int index) const;

    jobject getResult() const;
    std::string getResultString() const;
    template<typename T> T getResult() const {
        if constexpr (std::is_floating_point_v<T>) {
            return static_cast<T>(ctx->d[0]);   // FP return lives in d0
        } else if constexpr (std::is_pointer_v<T>) {
            return reinterpret_cast<T>(ctx->r[0]);
        } else {
            return static_cast<T>(ctx->r[0]);
        }
    }
    void setResult(jobject result);
    inline void setResult(jstring str) { setResult(static_cast<jobject>(str)); }
    void setResult(const char* str);
    void setResult(const std::string& str);
    template<typename T>
    std::enable_if_t<!std::is_convertible_v<T, jobject>> setResult(T val) {
        if constexpr (std::is_floating_point_v<T>) {
            ctx->d[0] = static_cast<double>(val);   // FP return lives in d0
        } else if constexpr (std::is_pointer_v<T>) {
            ctx->r[0] = reinterpret_cast<uint64_t>(val);
        } else {
            ctx->r[0] = static_cast<uint64_t>(val);
        }
        has_custom_result = true;
    }
    void resetResult() { has_custom_result = false; }
    bool hasResult() const { return has_custom_result; }

    // =========================================================================
    // 1. 原生机器码执行：支持无参调用或传入自定义实参篡改后调用
    // =========================================================================
    template<typename Ret = jobject, typename... Args>
    Ret invokeOriginal(Args&&... custom_args) {
        if constexpr (sizeof...(custom_args) > 0) {
            SetArgsHelper<0>(std::forward<Args>(custom_args)...);
        }
        invokeOriginalInternal();
        if constexpr (std::is_same_v<Ret, jobject> || std::is_same_v<Ret, jstring>) {
            return reinterpret_cast<Ret>(getResult());
        } else if constexpr (std::is_same_v<Ret, void>) {
            return;
        } else {
            return getResult<Ret>();
        }
    }

    // =========================================================================
    // 2. Dalvik VM 解释执行：参数与返回值规则同 invokeOriginal 保持 1:1 镜像！
    //    在内嵌 NMM-VM 解释器中重放原方法体（不触 trampoline、不给被调方加 hook）。
    //    方法体抛出的 Java 异常会挂在 env 上随 hook 回调返回自然传播。
    // =========================================================================
    template<typename Ret = jobject, typename... Args>
    Ret invokeInterpreted(Args&&... custom_args) {
        if constexpr (sizeof...(custom_args) > 0) {
            SetArgsHelper<0>(std::forward<Args>(custom_args)...);
        }
        invokeInterpreterInternal(nullptr, nullptr);
        if constexpr (std::is_same_v<Ret, jobject> || std::is_same_v<Ret, jstring>) {
            return reinterpret_cast<Ret>(getResult());
        } else if constexpr (std::is_same_v<Ret, void>) {
            return;
        } else {
            return getResult<Ret>();
        }
    }

    // =========================================================================
    // 3. 开箱即用 Trace 执行：指定预设模式 (只看方法树/单步指令/全栈)，同时可传业务实参
    // =========================================================================
    template<typename Ret = jobject, typename... Args>
    Ret invokeTrace(PI::Trace::TracePreset preset = PI::Trace::TracePreset::METHOD_ONLY,
                    Args&&... custom_args) {
        if constexpr (sizeof...(custom_args) > 0) {
            SetArgsHelper<0>(std::forward<Args>(custom_args)...);
        }
        invokeTraceInternal(preset);
        if constexpr (std::is_same_v<Ret, jobject> || std::is_same_v<Ret, jstring>) {
            return reinterpret_cast<Ret>(getResult());
        } else if constexpr (std::is_same_v<Ret, void>) {
            return;
        } else {
            return getResult<Ret>();
        }
    }

    // =========================================================================
    // 4. 高级沙箱/定制控制执行（方案 A）：注入 Callbacks / StepIn / Mock 策略，同时可传业务实参
    // =========================================================================
    template<typename Ret = jobject, typename... Args>
    Ret invokeInterpretedWith(const PI::Interp::Callbacks& cbs, Args&&... custom_args) {
        if constexpr (sizeof...(custom_args) > 0) {
            SetArgsHelper<0>(std::forward<Args>(custom_args)...);
        }
        invokeInterpreterInternal(&cbs, nullptr);
        if constexpr (std::is_same_v<Ret, jobject> || std::is_same_v<Ret, jstring>) {
            return reinterpret_cast<Ret>(getResult());
        } else if constexpr (std::is_same_v<Ret, void>) {
            return;
        } else {
            return getResult<Ret>();
        }
    }

    template<typename Ret = jobject, typename... Args>
    Ret invokeInterpretedWith(const PI::Interp::Callbacks& cbs, const PI::Interp::Options& opts,
                              Args&&... custom_args) {
        if constexpr (sizeof...(custom_args) > 0) {
            SetArgsHelper<0>(std::forward<Args>(custom_args)...);
        }
        invokeInterpreterInternal(&cbs, &opts);
        if constexpr (std::is_same_v<Ret, jobject> || std::is_same_v<Ret, jstring>) {
            return reinterpret_cast<Ret>(getResult());
        } else if constexpr (std::is_same_v<Ret, void>) {
            return;
        } else {
            return getResult<Ret>();
        }
    }

    std::string toString() const;
    std::string toValueString() const;
    std::string getJavaStackTrace() const;
    void printJavaStackTrace(const char* tag = "ArtPI") const;
    void showSmali(int max_instructions = -1, const char* tag = "ArtPI") const;
    std::string dumpSmali(int max_instructions = -1) const;

private:
    jobject invokeOriginalInternal();

    // backend of invokeInterpreted / invokeInterpretedWith (implemented in
    // src/sandbox/pi_interp_executor.cpp); stores the result into this frame
    jvalue invokeInterpreterInternal(const PI::Interp::Callbacks* cbs,
                                     const PI::Interp::Options* opts);
    // backend of invokeTrace(preset) (preset -> 内建 Callbacks/Options)
    jvalue invokeTraceInternal(PI::Trace::TracePreset preset);

    template<size_t Index>
    void SetArgsHelper() {}

    template<size_t Index, typename First, typename... Rest>
    void SetArgsHelper(First&& first, Rest&&... rest) {
        if (Index < static_cast<size_t>(arg_count)) {
            if constexpr (std::is_same_v<std::decay_t<First>, ArgProxy>) {
                if (first.isObject()) {
                    setArg(Index, first.as_jobject());
                } else {
                    setArgRaw(Index, static_cast<uint64_t>(static_cast<jlong>(first)));
                }
            } else if constexpr (std::is_convertible_v<First, jobject>) {
                setArg(Index, static_cast<jobject>(first));
            } else if constexpr (std::is_same_v<std::decay_t<First>, const char*> || std::is_same_v<std::decay_t<First>, std::string>) {
                setArg(Index, env ? env->NewStringUTF(std::string(first).c_str()) : nullptr);
            } else if constexpr (std::is_integral_v<std::decay_t<First>>) {
                setArgRaw(Index, static_cast<uint64_t>(first));
            } else if constexpr (std::is_floating_point_v<std::decay_t<First>>) {
                double dv = static_cast<double>(first);
                uint64_t raw;
                std::memcpy(&raw, &dv, sizeof(raw));
                setArgRaw(Index, raw);
            } else {
                setArgRaw(Index, reinterpret_cast<uint64_t>(first));
            }
        }
        SetArgsHelper<Index + 1>(std::forward<Rest>(rest)...);
    }
};

} // namespace pine_native

// ======================================================================
// PI Framework Main Namespace
// ======================================================================
namespace PI {

using CallFrame = ::pine_native::CallFrame;
using ArgProxy = ::pine_native::ArgProxy;
using ArgsAccessor = ::pine_native::ArgsAccessor;

class Method;
class HookHandle;

using HookCallback = std::function<void(JNIEnv*, CallFrame&)>;

// ----------------------------------------------------------------------
// HookHandle: Manages active hook and supports handle.unhook()
// ----------------------------------------------------------------------
class ARTPI_EXPORT HookHandle {
public:
    HookHandle();
    ~HookHandle();

    HookHandle(const HookHandle&) = default;
    HookHandle& operator=(const HookHandle&) = default;
    HookHandle(HookHandle&&) noexcept = default;
    HookHandle& operator=(HookHandle&&) noexcept = default;

    bool isValid() const;
    explicit operator bool() const { return isValid(); }
    bool isHooked() const;
    bool unhook();
    void* getBackup() const;
    ArtMethod* getArtMethod() const;

    struct Impl;
    explicit HookHandle(std::shared_ptr<Impl> impl);

private:
    friend class Method;
    std::shared_ptr<Impl> impl_;
};

// ----------------------------------------------------------------------
// Method: ArtMethod wrapper with showSmali(), hook(), trace()
// ----------------------------------------------------------------------
class ARTPI_EXPORT Method {
public:
    Method();
    Method(JNIEnv* env, jclass clazz, jmethodID mid, ArtMethod* artMethod,
           const std::string& name, const std::string& sig, bool isStatic);

    bool isValid() const { return artMethod_ != nullptr; }
    explicit operator bool() const { return isValid(); }

    // 1. Hooking: returns HookHandle supporting handle.unhook()
    HookHandle hook(const HookCallback& callback) const;

    // 2. Smali disassembling: parses memory CodeItem and prints via libdexfile
    void showSmali(int max_instructions = -1, const char* tag = "ArtPI") const;
    std::string dumpSmali(int max_instructions = -1) const;
    std::string dumpNative(int max_instructions = -1) const;
    std::string dumpCode(int max_instructions = -1) const;

    // 3. Method Tracing: automatic logging of arguments, backtrace, and return value
    HookHandle trace(const char* tag = "ArtPI_Trace") const;

    // 4. Information getters
    ArtMethod* getArtMethod() const { return artMethod_; }
    jmethodID getMethodId() const { return mid_; }
    jclass getDeclaringClass() const;
    const std::string& getName() const { return name_; }
    const std::string& getSignature() const { return sig_; }
    std::string getDeclaringClassName() const;
    bool isStatic() const { return isStatic_; }
    bool isNative() const;
    bool isCompiled() const;
    uint32_t getAccessFlags() const;
    std::string toString() const;

private:
    JNIEnv* env_ = nullptr;
    std::shared_ptr<_jobject> clazz_ref_;
    jmethodID mid_ = nullptr;
    ArtMethod* artMethod_ = nullptr;
    std::string name_;
    std::string sig_;
    bool isStatic_ = false;
};

// ----------------------------------------------------------------------
// Global Functions: PI::init, PI::isInitialized, PI::resolve
// ----------------------------------------------------------------------
ARTPI_EXPORT bool init(JNIEnv* env = nullptr);
ARTPI_EXPORT bool isInitialized();

ARTPI_EXPORT Method resolve(JNIEnv* env, jclass clazz, const std::string& methodName, const std::string& methodSig);
ARTPI_EXPORT Method resolve(JNIEnv* env, const std::string& className, const std::string& methodName, const std::string& methodSig);
ARTPI_EXPORT Method resolve(jclass clazz, const std::string& methodName, const std::string& methodSig);
ARTPI_EXPORT Method resolve(const std::string& className, const std::string& methodName, const std::string& methodSig);
ARTPI_EXPORT Method resolve(JNIEnv* env, jobject reflectedMethod);
ARTPI_EXPORT Method resolve(ArtMethod* artMethod);

ARTPI_EXPORT std::string dumpSmali(ArtMethod* method, int max_instructions = -1);
// Format only the single instruction at bytecode offset `pc` (16-bit code units).
ARTPI_EXPORT std::string dumpSmaliInsn(ArtMethod* method, uint32_t pc);
ARTPI_EXPORT std::string dumpNative(ArtMethod* method, int max_instructions = -1);
ARTPI_EXPORT std::string dumpNative(const void* native_pc, int max_instructions = -1, ArtMethod* method = nullptr, uintptr_t highlight_pc = 0);
ARTPI_EXPORT std::string dumpCode(ArtMethod* method, int max_instructions = -1);
ARTPI_EXPORT void* resolveNativeMethod(ArtMethod* method, JNIEnv* env = nullptr);

} // namespace PI

// Compatibility aliases for Pine namespace
namespace Pine {
    using CallFrame = ::PI::CallFrame;
    using HookCallback = ::PI::HookCallback;
    using ArgProxy = ::PI::ArgProxy;
    inline bool PineInit(JavaVM* vm, void* reserved = nullptr, JNIEnv* env = nullptr) {
        return ::PI::init(env);
    }
}

// DexResolver + embedded NMM-VM (nmmp nmmvm) interpreter
#include "../src/dex/pi_dex_resolver.h"
#include "../src/sandbox/pi_interp_executor.h"

#endif // ART_PI_H

