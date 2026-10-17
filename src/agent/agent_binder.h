//
// agent_binder.h - Modern C++20 Template Metaprogramming Dispatcher for QuickJS
//
#pragma once

#include "agent_common.h"
#include <tuple>
#include <type_traits>
#include <string>
#include <string_view>
#include <vector>
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
    static bool from_js(JSContext* /*ctx*/, JSValueConst v) {
        return JS_ToBool(nullptr, v) > 0;
    }
    static JSValue to_js(JSContext* ctx, bool val) {
        return JS_NewBool(ctx, val);
    }
};

// --- 32-bit Integers ---
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

// --- 64-bit Integers ---
template <typename T>
struct JsTraits<T, std::enable_if_t<std::is_integral_v<T> && sizeof(T) == 8 && std::is_signed_v<T>>> {
    static constexpr const char* name = "int64";
    static T from_js(JSContext* ctx, JSValueConst v) {
        int64_t val = 0;
        if (JS_IsBigInt(ctx, v)) {
            JS_ToBigInt64(ctx, &val, v);
        } else {
            JS_ToInt64(ctx, &val, v);
        }
        return static_cast<T>(val);
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
    static std::string from_js(JSContext* ctx, JSValueConst v) {
        return JsTraits<std::string>::from_js(ctx, v);
    }
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
// 2. Function Signature Deduction (FunctionTraits)
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
// 3. Dispatch Invoker & Dispatcher
// ============================================================================

template <typename Func, size_t... Is>
inline JSValue DispatchCall(JSContext* ctx, Func&& func, int argc, JSValueConst* argv, std::index_sequence<Is...>) {
    using Traits = FunctionTraits<std::decay_t<Func>>;
    using Ret = typename Traits::ReturnType;
    constexpr size_t numArgs = sizeof...(Is);

    if (argc < static_cast<int>(numArgs)) {
        return JS_ThrowTypeError(ctx, "Function requires at least %zu argument(s), got %d", numArgs, argc);
    }

    if constexpr (std::is_void_v<Ret>) {
        func(JsTraits<std::tuple_element_t<Is, typename Traits::ArgsTuple>>::from_js(ctx, argv[Is])...);
        return JS_UNDEFINED;
    } else {
        auto result = func(JsTraits<std::tuple_element_t<Is, typename Traits::ArgsTuple>>::from_js(ctx, argv[Is])...);
        return JsTraits<Ret>::to_js(ctx, result);
    }
}

// Wrapper for stateless function pointers / closures
template <typename Func>
struct NativeFunctionHolder {
    static JSValue Callback(JSContext* ctx, JSValueConst /*this_val*/, int argc, JSValueConst* argv, int /*magic*/, JSValue* func_data) {
        void* ptr = JS_GetOpaque(func_data[0], 0);
        if (!ptr) return JS_ThrowInternalError(ctx, "Invalid native function holder");
        auto* fn = reinterpret_cast<Func*>(ptr);
        return DispatchCall(ctx, *fn, argc, argv, std::make_index_sequence<FunctionTraits<Func>::arity>{});
    }
};

// Specialized for plain function pointers without heap allocation
template <typename Ret, typename... Args>
struct PlainFunctionHolder {
    using FuncPtr = Ret(*)(Args...);
    static JSValue Callback(JSContext* ctx, JSValueConst /*this_val*/, int argc, JSValueConst* argv, int magic) {
        auto fn = reinterpret_cast<FuncPtr>(static_cast<uintptr_t>(magic));
        return DispatchCall(ctx, fn, argc, argv, std::make_index_sequence<sizeof...(Args)>{});
    }
};

// ============================================================================
// 4. JsBinder Fluent Interface
// ============================================================================

class JsBinder {
public:
    explicit JsBinder(JSContext* ctx) : ctx_(ctx) {}

    // Bind a plain C++ free function pointer
    template <typename Ret, typename... Args>
    JsBinder& bind(JSValue target, const char* name, Ret(*func)(Args...),
                   const std::vector<std::string>& aliases = {}) {
        constexpr int arity = static_cast<int>(sizeof...(Args));
        
        // Wrap as QuickJS CFunctionData
        auto* fnPtr = new auto(func);
        JSValue data = JS_NewObject(ctx_);
        JS_SetOpaque(data, fnPtr);

        JSValue cfunc = JS_NewCFunctionData(ctx_,
            NativeFunctionHolder<Ret(*)(Args...)>::Callback,
            arity, 0, 1, &data);
        JS_FreeValue(ctx_, data);

        JS_SetPropertyStr(ctx_, target, name, JS_DupValue(ctx_, cfunc));
        for (const auto& alias : aliases) {
            JS_SetPropertyStr(ctx_, target, alias.c_str(), JS_DupValue(ctx_, cfunc));
        }
        JS_FreeValue(ctx_, cfunc);
        return *this;
    }

    // Bind a lambda or std::function
    template <typename Lambda, typename = std::enable_if_t<!std::is_pointer_v<std::decay_t<Lambda>>>>
    JsBinder& bind(JSValue target, const char* name, Lambda&& lambda,
                   const std::vector<std::string>& aliases = {}) {
        using FuncType = std::decay_t<Lambda>;
        constexpr int arity = static_cast<int>(FunctionTraits<FuncType>::arity);

        auto* holder = new FuncType(std::forward<Lambda>(lambda));
        JSValue data = JS_NewObject(ctx_);
        JS_SetOpaque(data, holder);

        JSValue cfunc = JS_NewCFunctionData(ctx_,
            NativeFunctionHolder<FuncType>::Callback,
            arity, 0, 1, &data);
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
