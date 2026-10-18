//
// agent_binder.h - Production-grade C++20 Template Metaprogramming Dispatcher for QuickJS
//
#pragma once

#include "agent_common.h"
#include <tuple>
#include <type_traits>
#include <string>
#include <string_view>
#include <vector>
#include <optional>
#include <functional>
#include <utility>
#include <sstream>

namespace artpi { namespace agent {

// ============================================================================
// 1. Type Traits (C++ <-> QuickJS Value Conversion)
// ============================================================================

template <typename T, typename Enable = void>
struct JsTraits;

// --- Boolean ---
template <>
struct JsTraits<bool> {
    static constexpr const char* name = "boolean";
    static bool from_js(JSContext* ctx, JSValueConst v) {
        return JS_ToBool(ctx, v) > 0;
    }
    static JSValue to_js(JSContext* ctx, bool val) {
        return JS_NewBool(ctx, val);
    }
};

// --- Small & 32-bit Integers ---
template <typename T>
struct JsTraits<T, std::enable_if_t<std::is_integral_v<T> && sizeof(T) <= 4 && std::is_signed_v<T> && !std::is_same_v<T, bool>>> {
    static constexpr const char* name = "int32";
    static T from_js(JSContext* ctx, JSValueConst v) {
        int32_t val = 0;
        JS_ToInt32(ctx, &val, v);
        return static_cast<T>(val);
    }
    static JSValue to_js(JSContext* ctx, T val) {
        return JS_NewInt32(ctx, static_cast<int32_t>(val));
    }
};

template <typename T>
struct JsTraits<T, std::enable_if_t<std::is_integral_v<T> && sizeof(T) <= 4 && std::is_unsigned_v<T> && !std::is_same_v<T, bool>>> {
    static constexpr const char* name = "uint32";
    static T from_js(JSContext* ctx, JSValueConst v) {
        uint32_t val = 0;
        JS_ToUint32(ctx, &val, v);
        return static_cast<T>(val);
    }
    static JSValue to_js(JSContext* ctx, T val) {
        return JS_NewUint32(ctx, static_cast<uint32_t>(val));
    }
};

// --- 64-bit Integers (Transparently supports Number, BigInt & Hex Strings) ---
template <typename T>
struct JsTraits<T, std::enable_if_t<std::is_integral_v<T> && sizeof(T) == 8 && std::is_signed_v<T>>> {
    static constexpr const char* name = "int64";
    static T from_js(JSContext* ctx, JSValueConst v) {
        return static_cast<T>(ParsePtr(ctx, v));
    }
    static JSValue to_js(JSContext* ctx, T val) {
        return JS_NewBigInt64(ctx, static_cast<int64_t>(val));
    }
};

template <typename T>
struct JsTraits<T, std::enable_if_t<std::is_integral_v<T> && sizeof(T) == 8 && std::is_unsigned_v<T>>> {
    static constexpr const char* name = "uint64";
    static T from_js(JSContext* ctx, JSValueConst v) {
        return static_cast<T>(ParsePtr(ctx, v));
    }
    static JSValue to_js(JSContext* ctx, T val) {
        return NewBigIntOrInt(ctx, static_cast<uint64_t>(val));
    }
};

// --- Floating Point ---
template <>
struct JsTraits<float> {
    static constexpr const char* name = "float";
    static float from_js(JSContext* ctx, JSValueConst v) {
        double val = 0;
        JS_ToFloat64(ctx, &val, v);
        return static_cast<float>(val);
    }
    static JSValue to_js(JSContext* ctx, float val) {
        return JS_NewFloat64(ctx, static_cast<double>(val));
    }
};

template <>
struct JsTraits<double> {
    static constexpr const char* name = "double";
    static double from_js(JSContext* ctx, JSValueConst v) {
        double val = 0;
        JS_ToFloat64(ctx, &val, v);
        return val;
    }
    static JSValue to_js(JSContext* ctx, double val) {
        return JS_NewFloat64(ctx, val);
    }
};

// --- Strings ---
template <>
struct JsTraits<std::string> {
    static constexpr const char* name = "string";
    static std::string from_js(JSContext* ctx, JSValueConst v) {
        const char* s = JS_ToCString(ctx, v);
        std::string str = s ? s : "";
        if (s) JS_FreeCString(ctx, s);
        return str;
    }
    static JSValue to_js(JSContext* ctx, const std::string& val) {
        return JS_NewString(ctx, val.c_str());
    }
};

template <>
struct JsTraits<std::string_view> {
    static constexpr const char* name = "string";
    static JSValue to_js(JSContext* ctx, std::string_view val) {
        return JS_NewStringLen(ctx, val.data(), val.size());
    }
};

template <>
struct JsTraits<const char*> {
    static constexpr const char* name = "string";
    static JSValue to_js(JSContext* ctx, const char* val) {
        return val ? JS_NewString(ctx, val) : JS_NULL;
    }
};

// --- Raw Pointers ---
template <typename T>
struct JsTraits<T*, std::enable_if_t<!std::is_same_v<T, char> && !std::is_same_v<T, const char>>> {
    static constexpr const char* name = "pointer";
    static T* from_js(JSContext* ctx, JSValueConst v) {
        return reinterpret_cast<T*>(ParsePtr(ctx, v));
    }
    static JSValue to_js(JSContext* ctx, T* val) {
        return NewBigIntOrInt(ctx, reinterpret_cast<uintptr_t>(val));
    }
};

// --- JSValue direct passthrough ---
template <>
struct JsTraits<JSValue> {
    static constexpr const char* name = "any";
    static JSValue from_js(JSContext* /*ctx*/, JSValueConst v) {
        return v;
    }
    static JSValue to_js(JSContext* /*ctx*/, JSValue val) {
        return val;
    }
};

// --- std::optional<T> ---
template <typename T>
struct JsTraits<std::optional<T>> {
    static constexpr const char* name = "optional";
    static std::optional<T> from_js(JSContext* ctx, JSValueConst v) {
        if (JS_IsNull(v) || JS_IsUndefined(v)) return std::nullopt;
        return JsTraits<T>::from_js(ctx, v);
    }
    static JSValue to_js(JSContext* ctx, const std::optional<T>& val) {
        if (!val.has_value()) return JS_NULL;
        return JsTraits<T>::to_js(ctx, *val);
    }
};

// --- std::vector<T> ---
template <typename T>
struct JsTraits<std::vector<T>> {
    static constexpr const char* name = "Array";
    static std::vector<T> from_js(JSContext* ctx, JSValueConst v) {
        std::vector<T> result;
        if (!JS_IsArray(ctx, v)) return result;
        int64_t len = 0;
        JSValue lenVal = JS_GetPropertyStr(ctx, v, "length");
        JS_ToInt64(ctx, &len, lenVal);
        JS_FreeValue(ctx, lenVal);
        result.reserve(static_cast<size_t>(len));
        for (int64_t i = 0; i < len; ++i) {
            JSValue elem = JS_GetPropertyUint32(ctx, v, static_cast<uint32_t>(i));
            result.push_back(JsTraits<T>::from_js(ctx, elem));
            JS_FreeValue(ctx, elem);
        }
        return result;
    }
    static JSValue to_js(JSContext* ctx, const std::vector<T>& val) {
        JSValue arr = JS_NewArray(ctx);
        for (uint32_t i = 0; i < val.size(); ++i) {
            JS_SetPropertyUint32(ctx, arr, i, JsTraits<T>::to_js(ctx, val[i]));
        }
        return arr;
    }
};

// ============================================================================
// 2. Scoped Argument Extractor (RAII for string lifetimes)
// ============================================================================

template <typename T>
struct ArgHolder {
    using CleanT = std::decay_t<T>;
    CleanT value;
    ArgHolder(JSContext* ctx, JSValueConst v) : value(JsTraits<CleanT>::from_js(ctx, v)) {}
    decltype(auto) get() { return value; }
};

template <>
struct ArgHolder<const char*> {
    const char* str = nullptr;
    JSContext* ctx = nullptr;
    ArgHolder(JSContext* c, JSValueConst v) : ctx(c) {
        str = JS_ToCString(ctx, v);
    }
    ~ArgHolder() {
        if (str) JS_FreeCString(ctx, str);
    }
    const char* get() const { return str ? str : ""; }
};

template <>
struct ArgHolder<std::string_view> {
    const char* str = nullptr;
    size_t len = 0;
    JSContext* ctx = nullptr;
    ArgHolder(JSContext* c, JSValueConst v) : ctx(c) {
        str = JS_ToCStringLen(ctx, &len, v);
    }
    ~ArgHolder() {
        if (str) JS_FreeCString(ctx, str);
    }
    std::string_view get() const { return str ? std::string_view(str, len) : std::string_view(); }
};

// ============================================================================
// 3. Function Signature Deduction (FunctionTraits)
// ============================================================================

template <typename T>
struct FunctionTraits;

// Free function
template <typename Ret, typename... Args>
struct FunctionTraits<Ret(*)(Args...)> {
    using ReturnType = Ret;
    using ArgsTuple = std::tuple<std::decay_t<Args>...>;
    static constexpr size_t arity = sizeof...(Args);
};

// Functor / Lambda
template <typename F>
struct FunctionTraits : FunctionTraits<decltype(&F::operator())> {};

// Const member function (lambdas)
template <typename Class, typename Ret, typename... Args>
struct FunctionTraits<Ret(Class::*)(Args...) const> {
    using ReturnType = Ret;
    using ArgsTuple = std::tuple<std::decay_t<Args>...>;
    static constexpr size_t arity = sizeof...(Args);
};

// Non-const member function
template <typename Class, typename Ret, typename... Args>
struct FunctionTraits<Ret(Class::*)(Args...)> {
    using ReturnType = Ret;
    using ArgsTuple = std::tuple<std::decay_t<Args>...>;
    static constexpr size_t arity = sizeof...(Args);
};

// ============================================================================
// 4. Safe Dispatch Invoker
// ============================================================================

template <typename Func, size_t... Is>
inline JSValue DispatchCall(JSContext* ctx, Func&& func, int argc, JSValueConst* argv, std::index_sequence<Is...>) {
    using Traits = FunctionTraits<std::decay_t<Func>>;
    using Ret = typename Traits::ReturnType;
    constexpr size_t numArgs = sizeof...(Is);

    if (argc < static_cast<int>(numArgs)) {
        return JS_ThrowTypeError(ctx, "Function requires at least %zu argument(s), got %d", numArgs, argc);
    }

#if defined(__cpp_exceptions) || defined(__EXCEPTIONS) || defined(_CPPUNWIND)
    try {
#endif
        std::tuple<ArgHolder<std::tuple_element_t<Is, typename Traits::ArgsTuple>>...> holders{
            ArgHolder<std::tuple_element_t<Is, typename Traits::ArgsTuple>>(ctx, argv[Is])...
        };

        if constexpr (std::is_void_v<Ret>) {
            func(std::get<Is>(holders).get()...);
            return JS_UNDEFINED;
        } else {
            auto result = func(std::get<Is>(holders).get()...);
            return JsTraits<Ret>::to_js(ctx, result);
        }
#if defined(__cpp_exceptions) || defined(__EXCEPTIONS) || defined(_CPPUNWIND)
    } catch (const std::exception& e) {
        return JS_ThrowInternalError(ctx, "C++ exception: %s", e.what());
    } catch (...) {
        return JS_ThrowInternalError(ctx, "Unknown C++ exception occurred");
    }
#endif
}

// ============================================================================
// 5. GC-Managed Lambda / Closure Holder
// ============================================================================

struct IBinderHolder {
    virtual ~IBinderHolder() = default;
    virtual JSValue invoke(JSContext* ctx, int argc, JSValueConst* argv) = 0;
};

template <typename Func>
struct BinderHolderImpl : public IBinderHolder {
    Func func;
    explicit BinderHolderImpl(Func&& f) : func(std::forward<Func>(f)) {}
    JSValue invoke(JSContext* ctx, int argc, JSValueConst* argv) override {
        return DispatchCall(ctx, func, argc, argv, std::make_index_sequence<FunctionTraits<Func>::arity>{});
    }
};

inline JSClassID g_binderHolderClassId = 0;

inline void BinderHolderFinalizer(JSRuntime* /*rt*/, JSValue val) {
    auto* holder = reinterpret_cast<IBinderHolder*>(JS_GetOpaque(val, g_binderHolderClassId));
    delete holder;
}

inline void EnsureBinderClassRegistered(JSContext* ctx) {
    if (g_binderHolderClassId == 0) {
        static std::mutex s_mutex;
        std::lock_guard<std::mutex> lk(s_mutex);
        if (g_binderHolderClassId == 0) {
            JSRuntime* rt = JS_GetRuntime(ctx);
            JS_NewClassID(rt, &g_binderHolderClassId);
            JSClassDef def = {};
            def.class_name = "ArtPI_BinderHolder";
            def.finalizer = BinderHolderFinalizer;
            JS_NewClass(rt, g_binderHolderClassId, &def);
        }
    }
}

inline JSValue BinderHolderCallback(JSContext* ctx, JSValueConst /*this_val*/, int argc, JSValueConst* argv, int /*magic*/, JSValue* func_data) {
    auto* holder = reinterpret_cast<IBinderHolder*>(JS_GetOpaque(func_data[0], g_binderHolderClassId));
    if (!holder) {
        return JS_ThrowInternalError(ctx, "Invalid binder closure holder");
    }
    return holder->invoke(ctx, argc, argv);
}

// Compile-time static invoker for zero-allocation free function pointers
template <auto Func>
struct StaticFunctionInvoker {
    using Traits = FunctionTraits<decltype(Func)>;
    static JSValue Callback(JSContext* ctx, JSValueConst /*this_val*/, int argc, JSValueConst* argv) {
        return DispatchCall(ctx, Func, argc, argv, std::make_index_sequence<Traits::arity>{});
    }
};

// ============================================================================
// 6. JsBinder Fluent Interface
// ============================================================================

class JsBinder {
public:
    explicit JsBinder(JSContext* ctx) : ctx_(ctx) {
        EnsureBinderClassRegistered(ctx_);
    }

    // 1. Compile-Time Non-Type Function Pointer Binding (Zero Heap Allocation, Fastest)
    // Usage: binder.bind<&MyFunction>(target, "myFunc", {"myfunc"});
    template <auto Func>
    JsBinder& bind(JSValue target, const char* name,
                   const std::vector<std::string>& aliases = {}) {
        using Traits = FunctionTraits<decltype(Func)>;
        constexpr int arity = static_cast<int>(Traits::arity);

        JSValue cfunc = JS_NewCFunction(ctx_, StaticFunctionInvoker<Func>::Callback, name, arity);
        JS_SetPropertyStr(ctx_, target, name, JS_DupValue(ctx_, cfunc));
        for (const auto& alias : aliases) {
            JS_SetPropertyStr(ctx_, target, alias.c_str(), JS_DupValue(ctx_, cfunc));
        }
        JS_FreeValue(ctx_, cfunc);
        return *this;
    }

    // 2. Runtime Free Function Pointer Binding
    // Usage: binder.bind(target, "myFunc", &MyFunction, {"myfunc"});
    template <typename Ret, typename... Args>
    JsBinder& bind(JSValue target, const char* name, Ret(*func)(Args...),
                   const std::vector<std::string>& aliases = {}) {
        return bind(target, name, [func](Args... args) -> Ret {
            if constexpr (std::is_void_v<Ret>) {
                func(std::forward<Args>(args)...);
            } else {
                return func(std::forward<Args>(args)...);
            }
        }, aliases);
    }

    // 3. Lambda / Functor / Closure Binding (GC-Managed Lifetime)
    // Usage: binder.bind(target, "myFunc", [](int a, const std::string& b) { ... });
    template <typename Lambda, typename = std::enable_if_t<!std::is_pointer_v<std::decay_t<Lambda>>>>
    JsBinder& bind(JSValue target, const char* name, Lambda&& lambda,
                   const std::vector<std::string>& aliases = {}) {
        using FuncType = std::decay_t<Lambda>;
        constexpr int arity = static_cast<int>(FunctionTraits<FuncType>::arity);

        // Allocate polymorphic holder
        IBinderHolder* holder = new BinderHolderImpl<FuncType>(std::forward<Lambda>(lambda));

        // Create a GC-managed QuickJS object
        JSValue data = JS_NewObjectClass(ctx_, g_binderHolderClassId);
        JS_SetOpaque(data, holder);

        JSValue cfunc = JS_NewCFunctionData(ctx_, BinderHolderCallback, arity, 0, 1, &data);
        JS_FreeValue(ctx_, data);

        JS_SetPropertyStr(ctx_, target, name, JS_DupValue(ctx_, cfunc));
        for (const auto& alias : aliases) {
            JS_SetPropertyStr(ctx_, target, alias.c_str(), JS_DupValue(ctx_, cfunc));
        }
        JS_FreeValue(ctx_, cfunc);
        return *this;
    }

private:
    JSContext* ctx_;
};

}} // namespace artpi::agent
