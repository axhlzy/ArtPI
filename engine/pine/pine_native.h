#ifndef PINE_NATIVE_H
#define PINE_NATIVE_H

#include <jni.h>
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
#include <functional>
#include <string>
#include <vector>
#include <sstream>
#include <type_traits>
#include <string_view>
#endif

#if defined(__GNUC__) || defined(__clang__)
#define PINE_EXPORT __attribute__((visibility("default")))
#else
#define PINE_EXPORT
#endif

#ifdef __cplusplus
namespace pine::art {
    class ArtMethod;
}
extern "C" {
#endif

/**
 * Convert an ART raw object pointer (e.g. from PineNativeContext registers)
 * into a valid JNI jobject local reference.
 */
PINE_EXPORT jobject PineNative_ToJObject(JNIEnv* env, void* art_obj);

/**
 * Convert a JNI jobject into an ART raw object pointer (e.g. for returning via
 * PineNativeContext or passing into ART methods).
 */
PINE_EXPORT void* PineNative_ToArtObject(JNIEnv* env, jobject j_obj);

typedef void (*PineObservedObjectCallback)(JNIEnv* env, uint64_t raw, jobject obj);
PINE_EXPORT void PineNative_SetObservedObjectCallback(PineObservedObjectCallback cb);
PINE_EXPORT void PineNative_NotifyObservedObject(JNIEnv* env, uint64_t raw, jobject obj);

/**
 * Initialize Pine Native.
 * Call this in JNI_OnLoad. Does NOT require loading any DEX or calling any Java code!
 */
PINE_EXPORT bool PineNative_Init(JNIEnv* env);

/**
 * Check if Pine Native is initialized.
 */
PINE_EXPORT bool PineNative_IsInitialized(void);

#ifdef __cplusplus
} // extern "C"
#endif

// 当 Java 调用该方法时，CPU 跳转进入 pine_native_bridge_trampoline：
//
//   FUNCTION(pine_native_bridge_trampoline)
//       // 1. 在栈上申请 320 字节（248字节通用寄存器 + 8字节SP + 64字节浮点寄存器）
//       sub sp, sp, #320
//
//       // 2. 保存通用寄存器：AAPCS64 调用约定中，x0是ArtMethod/返回值，x1~x7是Java入参
//       stp x0, x1, [sp, #0]
//       stp x2, x3, [sp, #16]
//       ...
//       stp x28, x29, [sp, #224]
//       str x30, [sp, #240]        // 保存返回地址 LR
//
//       add x9, sp, #320
//       str x9, [sp, #248]        // 保存原始 SP
//
//       // 3. 保存浮点寄存器 d0 ~ d7 (double/float 参数和返回值)
//       stp d0, d1, [sp, #256]
//       ...
//       stp d6, d7, [sp, #304]
//
//       // 4. 调用 C++ 回调函数！
//       // 此时栈顶 SP 上的内存布局与 struct PineNativeContext 一致
//       ldr x0, [sp, #0]          // arg 0 = target ArtMethod*
//       mov x1, sp                // arg 1 = PineNativeContext* (直接把栈顶指针当上下文)
//       LDVAR(x2, pine_native_bridge_trampoline_origin_entry) // arg 2 = 备份的原函数入口
//       LDVAR(x17, pine_native_bridge_trampoline_callback)    // callback = MethodHookDispatcher
//       blr x17                   // 跳转执行 C++ 逻辑
// CPU general-purpose and floating-point registers on ARM64
typedef struct PineNativeContext {
    uint64_t r[31]; // x0 ~ x30 (x0: ArtMethod*, x1~x7: args/this, x29: FP, x30: LR)
    uint64_t sp;    // original stack pointer
    double   d[8];  // d0 ~ d7 (FP/SIMD floating point args & returns)

#ifdef __cplusplus
    // --- Low-level C++ Convenience Member Methods ---
    template<typename T = void*>
    inline T GetThis() const {
        return reinterpret_cast<T>(r[1]);
    }

    template<typename T>
    inline T GetArg(size_t index) const {
        return reinterpret_cast<T>(r[index]);
    }

    template<typename T>
    inline void SetArg(size_t index, T val) {
        r[index] = reinterpret_cast<uint64_t>(val);
    }

    template<typename T = void*>
    inline T GetResult() const {
        return reinterpret_cast<T>(r[0]);
    }

    template<typename T>
    inline void SetResult(T val) {
        r[0] = reinterpret_cast<uint64_t>(val);
    }

    inline jobject GetArgJObject(JNIEnv* env, size_t index) const {
        return PineNative_ToJObject(env, reinterpret_cast<void*>(r[index]));
    }

    inline void SetResultJObject(JNIEnv* env, jobject j_obj) {
        r[0] = reinterpret_cast<uintptr_t>(PineNative_ToArtObject(env, j_obj));
    }
#endif
} PineNativeContext;

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Interceptor callback type:
 * @param target_method ArtMethod* pointer of the hooked method
 * @param ctx Register context. You can read arguments (ctx->r[1]..), modify them, or write return value (ctx->r[0])
 * @param origin_entry Function pointer to call original method directly
 */
typedef void (*PineNativeCallback)(void* target_method, PineNativeContext* ctx, void* origin_entry);

/**
 * Direct replacement function pointer (standard AAPCS64 calling convention):
 * void* replacement(void* artMethod, void* thiz, ...)
 */
typedef void* PineNativeReplacement;

PINE_EXPORT bool PineNative_Hook(JNIEnv* env, jclass clazz, const char* methodName, const char* signature,
                                 bool isStatic, PineNativeCallback callback, void** out_backup);

PINE_EXPORT bool PineNative_HookMethod(JNIEnv* env, jclass clazz, jmethodID methodId,
                                       bool isStatic, PineNativeCallback callback, void** out_backup);

PINE_EXPORT bool PineNative_HookReplace(JNIEnv* env, jclass clazz, const char* methodName, const char* signature,
                                        bool isStatic, PineNativeReplacement replacement, void** out_backup);

#ifdef __cplusplus
} // extern "C"

namespace pine_native {

    class CallFrame;
    class ArgProxy;

    // ArgProxy provides seamless [] operator indexing for CallFrame
    class ArgProxy {
    private:
        CallFrame* frame_;
        int index_;             // -1: thisObject, >= 0: method argument index

    public:
        ArgProxy(CallFrame* frame, int index) : frame_(frame), index_(index) {}

        bool isThis() const { return index_ < 0; }
        int getIndex() const { return index_; }
        bool isObject() const;

        // Equality checks with nullptr
        bool operator==(std::nullptr_t) const {
            return static_cast<jobject>(*this) == nullptr;
        }
        bool operator!=(std::nullptr_t) const {
            return static_cast<jobject>(*this) != nullptr;
        }

        // Implicit type conversions
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

        // Assignment operators
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

        // Helper methods
        std::string as_string() const;
        jobject as_jobject() const;
        jstring as_jstring() const { return static_cast<jstring>(*this); }
        template<typename T> T as() const;
    };

    class ArgsAccessor {
    private:
        CallFrame* frame_;
    public:
        explicit ArgsAccessor(CallFrame* frame) : frame_(frame) {}
        ArgProxy operator[](int index) const;
    };

    /**
     * CallFrame: Encapsulates method call context, arguments, return value, and original invocation.
     * Matches the elegant API design of Pine / Il2cppHooker.
     */
    class CallFrame {
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

        // [] operator overload on CallFrame:
        // [0] -> 1st Java arg (arg 0)
        // [1] -> 2nd Java arg (arg 1)
        // [index] -> (index)-th Java arg
        // NOTE: For instance methods, use frame.thiz (or frame.getThis()) to access the instance object!
        ArgProxy operator[](size_t index);
        const ArgProxy operator[](size_t index) const;

        // Method info
        std::string getMethodToString() const;
        const std::string& getMethodName() const { return method_name; }
        const std::string& getMethodSig() const { return signature; }
        bool isStatic() const { return is_static; }

        // thisObject
        jobject getThisObject() const;
        jobject getThis() const { return getThisObject(); }
        jobject thisObject() const { return getThisObject(); }

        // Arguments
        int getArgCount() const { return arg_count; }
        jobject getArg(int index) const;
        template<typename T>
        T getArg(int index) const {
            if constexpr (std::is_same_v<T, jobject> || std::is_same_v<T, jstring> || std::is_same_v<T, jclass>) {
                return reinterpret_cast<T>(getArg(index));
            } else if constexpr (std::is_floating_point_v<T>) {
                return static_cast<T>(ctx->d[index]);   // FP args live in d0..d7
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

        // Return value
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
        void resetResult() {
            has_custom_result = false;
        }
        bool hasResult() const { return has_custom_result; }

        // Execute original method with optional explicit arguments, returning typed Ret
        template<typename Ret = jobject, typename... Args>
        Ret callOriginal(Args&&... custom_args) {
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

        // String representation (matching Il2cppHooker)
        std::string toString() const;
        std::string toValueString() const;

        // Java Stack Trace / Backtrace helper
        std::string getJavaStackTrace() const;
        void printJavaStackTrace(const char* tag = "PineStackTrace") const;

        // Smali Disassembly helpers
        void showSmali(int max_instructions = -1, const char* tag = "PI_SMALI") const;
        std::string dumpSmali(int max_instructions = -1) const;

    private:
        jobject invokeOriginalInternal();

    private:
        template<size_t Index>
        void SetArgsHelper() {}

        template<size_t Index, typename First, typename... Rest>
        void SetArgsHelper(First&& first, Rest&&... rest) {
            if (Index < static_cast<size_t>(arg_count)) {
                if constexpr (std::is_same_v<std::decay_t<First>, ArgProxy>) {
                    if (first.isObject()) {
                        jobject obj = first.as_jobject();
                        setArg(Index, obj);
                    } else {
                        uint64_t raw = static_cast<uint64_t>(static_cast<jlong>(first));
                        setArgRaw(Index, raw);
                    }
                } else if constexpr (std::is_convertible_v<First, jobject>) {
                    jobject obj = static_cast<jobject>(first);
                    setArg(Index, obj);
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

    using HookCallback = std::function<void(JNIEnv*, CallFrame&)>;
    static auto NOP_FUNC = [](JNIEnv*, CallFrame&) {};

    // Initialization (Il2cppHooker style)
    PINE_EXPORT bool PineInit(JavaVM* vm, void* reserved, JNIEnv* env);
    inline bool Init(JNIEnv* env) { return PineNative_Init(env); }
    inline bool IsInitialized() { return PineNative_IsInitialized(); }
    PINE_EXPORT JNIEnv* GetCurrentJNIEnv();
    PINE_EXPORT jclass Pine_FindClass(JNIEnv* env, const std::string& className, jobject classLoader = nullptr);

    // Instance Method Hook APIs (specifically for non-static methods)
    PINE_EXPORT bool registerMethodHook(const std::string& className, const std::string& methodName, const std::string& methodSig,
                                        const HookCallback& callback);

    PINE_EXPORT bool registerMethodHook(jclass clazz, const std::string& methodName, const std::string& methodSig,
                                        const HookCallback& callback);

    PINE_EXPORT bool registerMethodHook(JNIEnv* env, jclass clazz, const std::string& methodName, const std::string& methodSig,
                                        const HookCallback& callback);

    PINE_EXPORT bool registerMethodHookEx(JNIEnv* env, jclass clazz, const std::string& methodName, const std::string& methodSig,
                                          const HookCallback& callback, void** out_backup = nullptr);

    // Static Method Hook APIs (specifically for static methods)
    PINE_EXPORT bool registerStaticMethodHook(const std::string& className, const std::string& methodName, const std::string& methodSig,
                                              const HookCallback& callback);

    PINE_EXPORT bool registerStaticMethodHook(jclass clazz, const std::string& methodName, const std::string& methodSig,
                                              const HookCallback& callback);

    PINE_EXPORT bool registerStaticMethodHook(JNIEnv* env, jclass clazz, const std::string& methodName, const std::string& methodSig,
                                              const HookCallback& callback);

    PINE_EXPORT bool registerStaticMethodHookEx(JNIEnv* env, jclass clazz, const std::string& methodName, const std::string& methodSig,
                                                const HookCallback& callback, void** out_backup = nullptr);

    // Direct ArtMethod pointer hook (bypasses reflection resolution requirements)
    PINE_EXPORT bool registerArtMethodHookDirect(JNIEnv* env, pine::art::ArtMethod* target,
                                                 const std::string& className,
                                                 const std::string& methodName,
                                                 const std::string& methodSig,
                                                 bool isStatic, jclass clazz, jmethodID mid,
                                                 const HookCallback& callback,
                                                 void** out_backup = nullptr);

    // Unhook / unregister API
    PINE_EXPORT bool unregisterMethodHook(pine::art::ArtMethod* target);

    PINE_EXPORT bool registerClassHook(const std::string& className, jobject classLoader = nullptr,
                                       const HookCallback& onEnter = NOP_FUNC,
                                       const HookCallback& onLeave = NOP_FUNC,
                                       const std::vector<std::string>& ignoreMethods = {});

    PINE_EXPORT bool registerClassHook(JNIEnv* env, jclass clazz,
                                       const HookCallback& onEnter = NOP_FUNC,
                                       const HookCallback& onLeave = NOP_FUNC,
                                       const std::vector<std::string>& ignoreMethods = {});

    // Hook Lambda dispatcher
    PINE_EXPORT bool PineNative_HookLambda(JNIEnv* env, jclass clazz, const char* methodName, const char* signature,
                                           bool isStatic, const std::function<void(void*, PineNativeContext*, void*)>& fn,
                                           void** out_backup = nullptr);

    // Unified Hook supporting function pointer, stateless lambda, and capturing lambda / std::function
    template<typename Func>
    inline bool Hook(JNIEnv* env, jclass clazz, const char* methodName, const char* signature,
                     bool isStatic, Func&& callback, void** out_backup = nullptr) {
        if constexpr (std::is_convertible_v<Func, PineNativeCallback>) {
            return PineNative_Hook(env, clazz, methodName, signature, isStatic, static_cast<PineNativeCallback>(callback), out_backup);
        } else if constexpr (std::is_invocable_v<Func, JNIEnv*, CallFrame*>) {
            return registerMethodHook(env, clazz, methodName, signature, std::forward<Func>(callback), NOP_FUNC);
        } else if constexpr (std::is_invocable_v<Func, CallFrame*>) {
            return registerMethodHook(env, clazz, methodName, signature, [cb = std::forward<Func>(callback)](JNIEnv*, CallFrame* f) { cb(f); }, NOP_FUNC);
        } else {
            return PineNative_HookLambda(env, clazz, methodName, signature, isStatic,
                                         std::function<void(void*, PineNativeContext*, void*)>(std::forward<Func>(callback)), out_backup);
        }
    }

    inline bool HookMethod(JNIEnv* env, jclass clazz, jmethodID methodId,
                           bool isStatic, PineNativeCallback callback, void** out_backup = nullptr) {
        return PineNative_HookMethod(env, clazz, methodId, isStatic, callback, out_backup);
    }

    // Direct Replacement Hook with stateless lambda or function pointer
    template<typename Func>
    inline bool HookReplace(JNIEnv* env, jclass clazz, const char* methodName, const char* signature,
                            bool isStatic, Func&& func, void** out_backup = nullptr) {
        if constexpr (std::is_pointer_v<std::decay_t<Func>>) {
            return PineNative_HookReplace(env, clazz, methodName, signature, isStatic, reinterpret_cast<void*>(func), out_backup);
        } else {
            return PineNative_HookReplace(env, clazz, methodName, signature, isStatic, reinterpret_cast<void*>(+func), out_backup);
        }
    }

    inline jobject ToJObject(JNIEnv* env, void* art_obj) {
        return PineNative_ToJObject(env, art_obj);
    }

    inline void* ToArtObject(JNIEnv* env, jobject j_obj) {
        return PineNative_ToArtObject(env, j_obj);
    }
}

// Alias for Pine:: exactly matching Il2cppHooker style!
namespace Pine = pine_native;

#endif // __cplusplus

#endif // PINE_NATIVE_H
