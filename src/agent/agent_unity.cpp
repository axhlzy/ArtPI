//
// agent_unity.cpp - UnityResolve.hpp bridge + QuickJS bindings (dynamic.unity)
//
// This is the ONLY translation unit that includes UnityResolve.hpp.  The rest
// of the agent is built with -fno-exceptions/-fno-rtti; UnityResolve::Invoke
// uses try/catch, so this file is compiled with -fexceptions (see CMakeLists).
//
#include "agent_unity.h"
#include "agent_common.h"
#include "agent_native.h"
#include "agent_net.h"
#include "native/hooker/pi_gum_hooker.h"
#include "frida-gum.h"

#include "UnityResolve.hpp"

#include <android/log.h>
#include <dlfcn.h>
#include <sys/stat.h>

#include <algorithm>
#include <cctype>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <cerrno>
#include <ctime>
#include <fstream>
#include <functional>
#include <memory>
#include <mutex>
#include <new>
#include <sstream>
#include <string>
#include <unordered_map>
#include <vector>

#ifndef RTLD_NOLOAD
#define RTLD_NOLOAD 0x4
#endif

#define UN_LOGI(...) __android_log_print(ANDROID_LOG_INFO,  "ArtPI_Unity", __VA_ARGS__)
#define UN_LOGW(...) __android_log_print(ANDROID_LOG_WARN,  "ArtPI_Unity", __VA_ARGS__)
#define UN_LOGE(...) __android_log_print(ANDROID_LOG_ERROR, "ArtPI_Unity", __VA_ARGS__)

// Consumed by the vendored UnityResolve.hpp xDL resolver (see its ANDROID_MODE
// patch). g_libil2cppPath keeps the string alive for the process lifetime.
extern "C" const char* g_artpi_unity_libil2cpp_path = nullptr;

namespace artpi { namespace agent {

namespace {

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------
enum class UnityState { Uninitialized, Ready, Failed };

std::mutex g_unityMutex;
UnityState g_unityState = UnityState::Uninitialized;
std::string g_unityError;
std::string g_unityLibDirHint;
std::string g_libil2cppPath;
const auto g_unityAgentLoadedAt = std::chrono::steady_clock::now();
thread_local bool t_unityAttached = false;

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------
static std::string ArgString(JSContext* ctx, JSValueConst v) {
    const char* s = JS_ToCString(ctx, v);
    std::string out = s ? s : "";
    if (s) JS_FreeCString(ctx, s);
    return out;
}

static void* ArgPtr(JSContext* ctx, JSValueConst v) {
    return reinterpret_cast<void*>(static_cast<uintptr_t>(ParsePtr(ctx, v)));
}

static int64_t ToI64(JSContext* ctx, JSValueConst v) {
    int64_t out = 0;
    if (JS_IsBigInt(ctx, v)) {
        JS_ToBigInt64(ctx, &out, v);
    } else {
        JS_ToInt64(ctx, &out, v);
    }
    return out;
}

static uint64_t ToU64(JSContext* ctx, JSValueConst v) {
    return static_cast<uint64_t>(ToI64(ctx, v));
}

static double ToF64(JSContext* ctx, JSValueConst v) {
    double out = 0;
    JS_ToFloat64(ctx, &out, v);
    return out;
}

static JSValue PtrToJs(JSContext* ctx, const void* p) {
    return NewBigIntOrInt(ctx, static_cast<uint64_t>(reinterpret_cast<uintptr_t>(p)));
}

static void* ThisPtr(JSContext* ctx, JSValueConst this_val) {
    JSValue p = JS_GetPropertyStr(ctx, this_val, "__ptr");
    int64_t v = ParsePtr(ctx, p);
    JS_FreeValue(ctx, p);
    return reinterpret_cast<void*>(static_cast<uintptr_t>(v));
}

static std::vector<std::string> ArgStringArray(JSContext* ctx, JSValueConst v) {
    std::vector<std::string> out;
    if (!JS_IsObject(v)) return out;

    JSValue lenVal = JS_GetPropertyStr(ctx, v, "length");
    uint32_t len = 0;
    if (JS_IsNumber(lenVal)) JS_ToUint32(ctx, &len, lenVal);
    JS_FreeValue(ctx, lenVal);

    for (uint32_t i = 0; i < len; ++i) {
        JSValue item = JS_GetPropertyUint32(ctx, v, i);
        if (!JS_IsUndefined(item)) out.push_back(ArgString(ctx, item));
        JS_FreeValue(ctx, item);
    }
    return out;
}

static bool IsVoidType(const UnityResolve::Type* t) {
    return t && t->name == "System.Void";
}

static size_t RawSize(const UnityResolve::Type* t) {
    if (!t || t->size <= 0) return sizeof(void*);
    size_t s = static_cast<size_t>(t->size);
    return s < sizeof(void*) ? sizeof(void*) : s;
}

static bool IsValueTypeName(const std::string& n) {
    static const char* kValueTypes[] = {
        "System.Boolean", "System.Byte", "System.SByte", "System.Char",
        "System.Int16", "System.UInt16", "System.Int32", "System.UInt32",
        "System.Int64", "System.UInt64", "System.Single", "System.Double",
        "System.IntPtr", "System.UIntPtr", "System.Decimal",
        "UnityEngine.Vector2", "UnityEngine.Vector3", "UnityEngine.Vector4",
        "UnityEngine.Quaternion", "UnityEngine.Color", "UnityEngine.Color32",
        "UnityEngine.Rect", "UnityEngine.Bounds",
    };
    for (const char* s : kValueTypes) if (n == s) return true;
    return false;
}

// ---------------------------------------------------------------------------
// Value marshalling
// ---------------------------------------------------------------------------
// UnityResolve::UnityType::String::ToString() converts m_firstChar[32] as a
// null-terminated wide string; long paths (>32 chars) over-read and throw
// std::range_error across the C callback boundary (SIGABRT). Decode exactly
// m_stringLength UTF-16 code units instead (Il2CppString layout: length@0x10,
// chars@0x14 on 64-bit IL2CPP).
static std::string UnityStringToUtf8(UnityResolve::UnityType::String* s) {
    if (!s) return "";
    uintptr_t base = reinterpret_cast<uintptr_t>(s);
    int32_t len = *reinterpret_cast<const int32_t*>(base + 0x10);
    if (len <= 0 || len > (1 << 20)) return "";

    const char16_t* chars = reinterpret_cast<const char16_t*>(base + 0x14);
    std::string out;
    out.reserve(static_cast<size_t>(len) * 3);

    for (int32_t i = 0; i < len; ++i) {
        uint32_t cp = chars[i];
        if (cp >= 0xD800 && cp <= 0xDBFF) {
            if (i + 1 < len) {
                uint32_t lo = chars[i + 1];
                if (lo >= 0xDC00 && lo <= 0xDFFF) {
                    cp = 0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00);
                    ++i;
                } else {
                    cp = 0xFFFD;
                }
            } else {
                cp = 0xFFFD;
            }
        } else if (cp >= 0xDC00 && cp <= 0xDFFF) {
            cp = 0xFFFD; // lone low surrogate
        }

        if (cp < 0x80) {
            out.push_back(static_cast<char>(cp));
        } else if (cp < 0x800) {
            out.push_back(static_cast<char>(0xC0 | (cp >> 6)));
            out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
        } else if (cp < 0x10000) {
            out.push_back(static_cast<char>(0xE0 | (cp >> 12)));
            out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
            out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
        } else {
            out.push_back(static_cast<char>(0xF0 | (cp >> 18)));
            out.push_back(static_cast<char>(0x80 | ((cp >> 12) & 0x3F)));
            out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
            out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
        }
    }
    return out;
}

static JSValue ReadValue(JSContext* ctx, const UnityResolve::Type* type, const void* addr) {
    if (!type || !addr) return JS_UNDEFINED;
    const std::string& n = type->name;

    if (n == "System.Boolean") return JS_NewBool(ctx, *reinterpret_cast<const bool*>(addr));
    if (n == "System.Byte")    return JS_NewInt32(ctx, *reinterpret_cast<const uint8_t*>(addr));
    if (n == "System.SByte")   return JS_NewInt32(ctx, *reinterpret_cast<const int8_t*>(addr));
    if (n == "System.Char")    return JS_NewInt32(ctx, *reinterpret_cast<const uint16_t*>(addr));
    if (n == "System.Int16")   return JS_NewInt32(ctx, *reinterpret_cast<const int16_t*>(addr));
    if (n == "System.UInt16")  return JS_NewInt32(ctx, *reinterpret_cast<const uint16_t*>(addr));
    if (n == "System.Int32")   return JS_NewInt32(ctx, *reinterpret_cast<const int32_t*>(addr));
    if (n == "System.UInt32")  return JS_NewUint32(ctx, *reinterpret_cast<const uint32_t*>(addr));
    if (n == "System.Int64")   return NewBigIntOrInt(ctx, static_cast<uint64_t>(*reinterpret_cast<const int64_t*>(addr)));
    if (n == "System.UInt64")  return NewBigIntOrInt(ctx, *reinterpret_cast<const uint64_t*>(addr));
    if (n == "System.IntPtr")  return PtrToJs(ctx, reinterpret_cast<const void*>(*reinterpret_cast<const uintptr_t*>(addr)));
    if (n == "System.UIntPtr") return PtrToJs(ctx, reinterpret_cast<const void*>(*reinterpret_cast<const uintptr_t*>(addr)));
    if (n == "System.Single")  return JS_NewFloat64(ctx, *reinterpret_cast<const float*>(addr));
    if (n == "System.Double")  return JS_NewFloat64(ctx, *reinterpret_cast<const double*>(addr));
    if (n == "System.String") {
        auto* s = *reinterpret_cast<UnityResolve::UnityType::String* const*>(addr);
        return JS_NewString(ctx, UnityStringToUtf8(s).c_str());
    }
    if (n == "UnityEngine.Vector2") {
        float v[2]; std::memcpy(v, addr, sizeof(v));
        JSValue o = JS_NewObject(ctx);
        JS_SetPropertyStr(ctx, o, "x", JS_NewFloat64(ctx, v[0]));
        JS_SetPropertyStr(ctx, o, "y", JS_NewFloat64(ctx, v[1]));
        return o;
    }
    if (n == "UnityEngine.Vector3") {
        float v[3]; std::memcpy(v, addr, sizeof(v));
        JSValue o = JS_NewObject(ctx);
        JS_SetPropertyStr(ctx, o, "x", JS_NewFloat64(ctx, v[0]));
        JS_SetPropertyStr(ctx, o, "y", JS_NewFloat64(ctx, v[1]));
        JS_SetPropertyStr(ctx, o, "z", JS_NewFloat64(ctx, v[2]));
        return o;
    }
    if (n == "UnityEngine.Vector4" || n == "UnityEngine.Quaternion") {
        float v[4]; std::memcpy(v, addr, sizeof(v));
        JSValue o = JS_NewObject(ctx);
        JS_SetPropertyStr(ctx, o, "x", JS_NewFloat64(ctx, v[0]));
        JS_SetPropertyStr(ctx, o, "y", JS_NewFloat64(ctx, v[1]));
        JS_SetPropertyStr(ctx, o, "z", JS_NewFloat64(ctx, v[2]));
        JS_SetPropertyStr(ctx, o, "w", JS_NewFloat64(ctx, v[3]));
        return o;
    }
    if (n == "UnityEngine.Color") {
        float v[4]; std::memcpy(v, addr, sizeof(v));
        JSValue o = JS_NewObject(ctx);
        JS_SetPropertyStr(ctx, o, "r", JS_NewFloat64(ctx, v[0]));
        JS_SetPropertyStr(ctx, o, "g", JS_NewFloat64(ctx, v[1]));
        JS_SetPropertyStr(ctx, o, "b", JS_NewFloat64(ctx, v[2]));
        JS_SetPropertyStr(ctx, o, "a", JS_NewFloat64(ctx, v[3]));
        return o;
    }

    // Reference types / unknown 8-byte values: treat the slot as a pointer.
    if (type->size == 8 || !IsValueTypeName(n)) {
        return PtrToJs(ctx, *reinterpret_cast<void* const*>(addr));
    }
    return JS_UNDEFINED;
}

static bool WriteValue(JSContext* ctx, const UnityResolve::Type* type, void* addr, JSValueConst v) {
    if (!type || !addr) return false;
    const std::string& n = type->name;

    if (n == "System.Boolean") { *reinterpret_cast<bool*>(addr) = JS_ToBool(ctx, v) != 0; return true; }
    if (n == "System.Byte")    { *reinterpret_cast<uint8_t*>(addr)  = static_cast<uint8_t>(ToI64(ctx, v)); return true; }
    if (n == "System.SByte")   { *reinterpret_cast<int8_t*>(addr)   = static_cast<int8_t>(ToI64(ctx, v)); return true; }
    if (n == "System.Char")    { *reinterpret_cast<uint16_t*>(addr) = static_cast<uint16_t>(ToI64(ctx, v)); return true; }
    if (n == "System.Int16")   { *reinterpret_cast<int16_t*>(addr)  = static_cast<int16_t>(ToI64(ctx, v)); return true; }
    if (n == "System.UInt16")  { *reinterpret_cast<uint16_t*>(addr) = static_cast<uint16_t>(ToI64(ctx, v)); return true; }
    if (n == "System.Int32")   { *reinterpret_cast<int32_t*>(addr)  = static_cast<int32_t>(ToI64(ctx, v)); return true; }
    if (n == "System.UInt32")  { *reinterpret_cast<uint32_t*>(addr) = static_cast<uint32_t>(ToU64(ctx, v)); return true; }
    if (n == "System.Int64")   { *reinterpret_cast<int64_t*>(addr)  = ToI64(ctx, v); return true; }
    if (n == "System.UInt64")  { *reinterpret_cast<uint64_t*>(addr) = ToU64(ctx, v); return true; }
    if (n == "System.IntPtr")  { *reinterpret_cast<uintptr_t*>(addr) = static_cast<uintptr_t>(ToI64(ctx, v)); return true; }
    if (n == "System.UIntPtr") { *reinterpret_cast<uintptr_t*>(addr) = static_cast<uintptr_t>(ToU64(ctx, v)); return true; }
    if (n == "System.Single")  { *reinterpret_cast<float*>(addr)  = static_cast<float>(ToF64(ctx, v)); return true; }
    if (n == "System.Double")  { *reinterpret_cast<double*>(addr) = ToF64(ctx, v); return true; }
    if (n == "System.String") {
        auto* s = UnityResolve::UnityType::String::New(ArgString(ctx, v));
        *reinterpret_cast<UnityResolve::UnityType::String**>(addr) = s;
        return true;
    }
    if (n == "UnityEngine.Vector2") {
        float out[2] = {0};
        if (JS_IsObject(v)) {
            JSValue x = JS_GetPropertyStr(ctx, v, "x"); JSValue y = JS_GetPropertyStr(ctx, v, "y");
            out[0] = static_cast<float>(ToF64(ctx, x));
            out[1] = static_cast<float>(ToF64(ctx, y));
            JS_FreeValue(ctx, x); JS_FreeValue(ctx, y);
        }
        std::memcpy(addr, out, sizeof(out));
        return true;
    }
    if (n == "UnityEngine.Vector3") {
        float out[3] = {0};
        if (JS_IsObject(v)) {
            JSValue x = JS_GetPropertyStr(ctx, v, "x"); JSValue y = JS_GetPropertyStr(ctx, v, "y");
            JSValue z = JS_GetPropertyStr(ctx, v, "z");
            out[0] = static_cast<float>(ToF64(ctx, x));
            out[1] = static_cast<float>(ToF64(ctx, y));
            out[2] = static_cast<float>(ToF64(ctx, z));
            JS_FreeValue(ctx, x); JS_FreeValue(ctx, y); JS_FreeValue(ctx, z);
        }
        std::memcpy(addr, out, sizeof(out));
        return true;
    }
    if (n == "UnityEngine.Vector4" || n == "UnityEngine.Quaternion") {
        float out[4] = {0};
        if (JS_IsObject(v)) {
            JSValue x = JS_GetPropertyStr(ctx, v, "x"); JSValue y = JS_GetPropertyStr(ctx, v, "y");
            JSValue z = JS_GetPropertyStr(ctx, v, "z"); JSValue w = JS_GetPropertyStr(ctx, v, "w");
            out[0] = static_cast<float>(ToF64(ctx, x));
            out[1] = static_cast<float>(ToF64(ctx, y));
            out[2] = static_cast<float>(ToF64(ctx, z));
            out[3] = static_cast<float>(ToF64(ctx, w));
            JS_FreeValue(ctx, x); JS_FreeValue(ctx, y); JS_FreeValue(ctx, z); JS_FreeValue(ctx, w);
        }
        std::memcpy(addr, out, sizeof(out));
        return true;
    }
    if (n == "UnityEngine.Color") {
        float out[4] = {0};
        if (JS_IsObject(v)) {
            JSValue r = JS_GetPropertyStr(ctx, v, "r"); JSValue g = JS_GetPropertyStr(ctx, v, "g");
            JSValue b = JS_GetPropertyStr(ctx, v, "b"); JSValue a = JS_GetPropertyStr(ctx, v, "a");
            out[0] = static_cast<float>(ToF64(ctx, r));
            out[1] = static_cast<float>(ToF64(ctx, g));
            out[2] = static_cast<float>(ToF64(ctx, b));
            out[3] = static_cast<float>(ToF64(ctx, a));
            JS_FreeValue(ctx, r); JS_FreeValue(ctx, g); JS_FreeValue(ctx, b); JS_FreeValue(ctx, a);
        }
        std::memcpy(addr, out, sizeof(out));
        return true;
    }

    // Reference types / pointers.
    *reinterpret_cast<void**>(addr) = ArgPtr(ctx, v);
    return true;
}

// ---------------------------------------------------------------------------
// Initialisation
// ---------------------------------------------------------------------------
static bool FindLibil2cpp(std::string& path, uintptr_t& base) {
    auto mods = EnumerateAllLoadedModules();
    for (const auto& m : mods) {
        if (m.name == "libil2cpp.so") {
            path = m.path;
            base = m.base;
            return true;
        }
    }
    for (const auto& m : mods) {
        if (m.name.find("libil2cpp") != std::string::npos) {
            path = m.path;
            base = m.base;
            return true;
        }
    }
    return false;
}

// Caller must hold g_unityMutex.
static bool EnsureInitLocked(std::string* err) {
    if (g_unityState == UnityState::Ready) return true;
    if (g_unityState == UnityState::Failed) {
        if (err) *err = g_unityError;
        return false;
    }

    std::string path;
    uintptr_t base = 0;
    if (!FindLibil2cpp(path, base)) {
        if (err) *err = "libil2cpp.so is not loaded yet";
        return false; // keep retryable
    }

    // The vendored header resolves il2cpp_* via xDL (dlsym crashes on newer
    // Android). Keep the path string alive for the process lifetime.
    g_libil2cppPath = path;
    g_artpi_unity_libil2cpp_path = g_libil2cppPath.c_str();

    void* handle = dlopen(path.c_str(), RTLD_NOW | RTLD_NOLOAD);
    if (!handle) handle = dlopen("libil2cpp.so", RTLD_NOW | RTLD_NOLOAD);
    if (!handle) handle = dlopen(path.c_str(), RTLD_NOW);
    if (!handle) handle = dlopen("libil2cpp.so", RTLD_NOW);
    if (!handle) {
        g_unityState = UnityState::Failed;
        g_unityError = "dlopen(libil2cpp.so) failed";
        UN_LOGE("%s", g_unityError.c_str());
        if (err) *err = g_unityError;
        return false;
    }

    UN_LOGI("initializing UnityResolve (libil2cpp base=0x%lx, path=%s)",
            static_cast<unsigned long>(base), path.c_str());

    // libil2cpp.so can be mapped before IL2CPP has created its domain and
    // assemblies. UnityResolve::Init immediately calls il2cpp_domain_get(),
    // attaches the current thread, and enumerates assemblies; probing those
    // IL2CPP exports directly here is not safe during loader/startup (and can
    // itself fault on some Unity builds). Defer using only process/module
    // state, which is safe before the runtime is initialized.
    const auto elapsed = std::chrono::steady_clock::now() - g_unityAgentLoadedAt;
    if (elapsed < std::chrono::seconds(4)) {
        if (err) *err = "Unity runtime is still starting; retry shortly";
        return false; // retryable; do not poison g_unityState
    }

    try {
        UnityResolve::Init(handle, UnityResolve::Mode::Il2Cpp);
        t_unityAttached = true; // Init() calls il2cpp_thread_attach on this thread
    } catch (const std::exception& e) {
        g_unityState = UnityState::Failed;
        g_unityError = std::string("UnityResolve::Init exception: ") + e.what();
        UN_LOGE("%s", g_unityError.c_str());
        if (err) *err = g_unityError;
        return false;
    } catch (...) {
        g_unityState = UnityState::Failed;
        g_unityError = "UnityResolve::Init unknown exception";
        UN_LOGE("%s", g_unityError.c_str());
        if (err) *err = g_unityError;
        return false;
    }

    if (UnityResolve::assembly.empty()) {
        g_unityState = UnityState::Failed;
        g_unityError = "UnityResolve: no assemblies found (not IL2CPP / metadata encrypted?)";
        UN_LOGE("%s", g_unityError.c_str());
        if (err) *err = g_unityError;
        return false;
    }

    g_unityState = UnityState::Ready;
    g_unityError.clear();
    UN_LOGI("UnityResolve ready: %zu assemblies", UnityResolve::assembly.size());
    return true;
}

// Caller must hold g_unityMutex and EnsureInitLocked()==true.
static void EnsureThreadAttached() {
    if (!t_unityAttached && g_unityState == UnityState::Ready) {
        UnityResolve::ThreadAttach();
        t_unityAttached = true;
    }
}

// ---------------------------------------------------------------------------
// Field / method operations (caller holds g_unityMutex)
// ---------------------------------------------------------------------------
static JSValue ReadField(JSContext* ctx, UnityResolve::Field* f, void* obj) {
    if (!f || !f->type) return JS_UNDEFINED;
    if (f->static_field) {
        size_t sz = RawSize(f->type);
        std::vector<uint8_t> buf(sz, 0);
        UnityResolve::Invoke<void>("il2cpp_field_static_get_value", (void*)f->address, (void*)buf.data());
        return ReadValue(ctx, f->type, buf.data());
    }
    if (!obj) return JS_ThrowTypeError(ctx, "field.get(): instance pointer is required");
    return ReadValue(ctx, f->type, reinterpret_cast<uint8_t*>(obj) + f->offset);
}

static bool WriteField(JSContext* ctx, UnityResolve::Field* f, void* obj, JSValueConst v) {
    if (!f || !f->type) return false;
    if (f->static_field) {
        size_t sz = RawSize(f->type);
        std::vector<uint8_t> buf(sz, 0);
        if (!WriteValue(ctx, f->type, buf.data(), v)) return false;
        UnityResolve::Invoke<void>("il2cpp_field_static_set_value", (void*)f->address, (void*)buf.data());
        return true;
    }
    if (!obj) return false;
    return WriteValue(ctx, f->type, reinterpret_cast<uint8_t*>(obj) + f->offset, v);
}

static JSValue InvokeMethod(JSContext* ctx, UnityResolve::Method* m, void* obj,
                            int argc, JSValueConst* argv) {
    if (!m) return JS_ThrowTypeError(ctx, "invalid method");
    if (argc < static_cast<int>(m->args.size())) {
        return JS_ThrowTypeError(ctx, "method %s expects %zu argument(s), got %d",
                                 m->name.c_str(), m->args.size(), argc);
    }

    std::vector<std::vector<uint8_t>> storage(m->args.size());
    std::vector<void*> params(m->args.size());

    for (size_t i = 0; i < m->args.size(); ++i) {
        auto* t = m->args[i]->pType;
        size_t sz = RawSize(t);
        storage[i].assign(sz, 0);
        if (!WriteValue(ctx, t, storage[i].data(), argv[i])) {
            return JS_ThrowTypeError(ctx, "cannot convert argument %zu of %s", i, m->name.c_str());
        }
        params[i] = storage[i].data();
    }

    void* result = UnityResolve::Invoke<void*>(
        "il2cpp_runtime_invoke", (void*)m->address, obj,
        (void*)(params.empty() ? nullptr : params.data()), (void*)nullptr);

    if (IsVoidType(m->return_type)) return JS_UNDEFINED;
    if (!result) return JS_NULL;

    if (m->return_type && IsValueTypeName(m->return_type->name)) {
        void* unboxed = UnityResolve::Invoke<void*>("il2cpp_object_unbox", result);
        return ReadValue(ctx, m->return_type, unboxed);
    }
    return ReadValue(ctx, m->return_type, &result);
}

static std::vector<void*> FindObjectsOfType(UnityResolve::Class* cls) {
    std::vector<void*> out;
    auto* core = UnityResolve::Get("UnityEngine.CoreModule.dll");
    if (!core) return out;
    auto* objectClass = core->Get("Object");
    if (!objectClass) return out;
    auto* method = objectClass->Get<UnityResolve::Method>("FindObjectsOfType", { "System.Type" });
    if (!method) return out;
    void* typeObj = cls->GetType();
    if (!typeObj) return out;
    auto* arr = method->Invoke<UnityResolve::UnityType::Array<void*>*>(typeObj);
    if (arr) out = arr->ToVector();
    return out;
}

// ---------------------------------------------------------------------------
// Readable display for wrappers (EvalJs falls back to toString()).
// Follows Il2CppHookScripts (il2cppM.ts): access modifier + short type names,
// parameter names, and MethodInfo -> function (RVA) addresses.
// ---------------------------------------------------------------------------
static std::string UnityTypeName(const UnityResolve::Type* t) {
    return (t && !t->name.empty()) ? t->name : "?";
}

// Matches Il2CppHookScripts' getMethodDesFromMethodInfo(): generic types keep
// their full name, plain types use the last namespace segment.
static std::string UnityShortTypeName(const std::string& n) {
    if (n.find('>') != std::string::npos) return n;
    size_t dot = n.rfind('.');
    return dot == std::string::npos ? n : n.substr(dot + 1);
}

// Matches Il2CppHookScripts' getMethodModifier().
static std::string UnityMethodModifier(int32_t flags) {
    std::string out;
    switch (flags & 0x0007) { // MemberAccessMask
    case 0x0001: out += "private "; break;
    case 0x0006: out += "public "; break;
    case 0x0004: out += "protected "; break;
    case 0x0003: // Assembly
    case 0x0002: // FamANDAssem
        out += "internal "; break;
    case 0x0005: // FamORAssem
        out += "protected internal "; break;
    default: break;
    }
    if (flags & 0x0010) out += "static ";
    if (flags & 0x0400) { // Abstract
        out += "abstract ";
        if ((flags & 0x0100) == 0x0000) out += "override ";
    } else if (flags & 0x0020) { // Final
        if ((flags & 0x0100) == 0x0000) out += "sealed override ";
    } else if (flags & 0x0040) { // Virtual
        if ((flags & 0x0100) == 0x0100) out += "virtual ";
        else out += "override ";
    }
    if (flags & 0x2000) out += "extern ";
    return out;
}

static std::string HexStr(uintptr_t v) {
    char buf[32];
    snprintf(buf, sizeof(buf), "0x%lx", (unsigned long) v);
    return buf;
}

static std::string BaseName(const char* path) {
    if (!path || !*path) return "?";
    const char* slash = strrchr(path, '/');
    return slash ? std::string(slash + 1) : std::string(path);
}

static UnityResolve::Assembly* FindAssemblyForClass(UnityResolve::Class* cls) {
    if (!cls) return nullptr;
    for (auto* a : UnityResolve::assembly) {
        for (auto* c : a->classes) {
            if (c == cls) return a;
        }
    }
    return nullptr;
}

static std::string UnityClassFullName(UnityResolve::Class* c) {
    if (!c) return "?";
    return c->namespaze.empty() ? c->name : (c->namespaze + "." + c->name);
}

static UnityResolve::Class* FindClassByAddress(void* address) {
    if (!address) return nullptr;
    for (auto* a : UnityResolve::assembly) {
        for (auto* c : a->classes) {
            if (c->address == address) return c;
        }
    }
    return nullptr;
}

// Case-insensitive wildcard match: '*' matches any run, '?' one character.
// A pattern without wildcards is treated as a case-insensitive substring.
static bool UnityWildcardMatch(const std::string& pattern, const std::string& text,
                               bool exactWhenNoWildcard = false) {
    if (pattern.empty()) return true;
    if (pattern.find('*') == std::string::npos && pattern.find('?') == std::string::npos) {
        if (exactWhenNoWildcard) {
            if (pattern.size() != text.size()) return false;
            for (size_t i = 0; i < text.size(); ++i) {
                if (std::tolower((unsigned char)pattern[i]) !=
                    std::tolower((unsigned char)text[i])) return false;
            }
            return true;
        }
        return std::search(text.begin(), text.end(), pattern.begin(), pattern.end(),
                           [](char a, char b) {
                               return std::tolower((unsigned char)a) ==
                                      std::tolower((unsigned char)b);
                           }) != text.end();
    }

    const char* p = pattern.c_str();
    const char* t = text.c_str();
    const char* star = nullptr;
    const char* backtrack = nullptr;
    while (*t) {
        if (*p == '?' ||
            (*p && std::tolower((unsigned char)*p) == std::tolower((unsigned char)*t))) {
            ++p;
            ++t;
        } else if (*p == '*') {
            star = p++;
            backtrack = t;
        } else if (star) {
            p = star + 1;
            t = ++backtrack;
        } else {
            return false;
        }
    }
    while (*p == '*') ++p;
    return *p == '\0';
}

static UnityResolve::Class* FindClassByName(const std::string& name) {
    if (name.empty()) return nullptr;
    for (auto* a : UnityResolve::assembly) {
        if (auto* c = a->Get(name)) return c;
    }
    return nullptr;
}

// Object/class helpers that also work for inflated generic classes
// (List<T>, Dictionary<K,V>, ...) which UnityResolve's static class table
// does not contain.  These use the IL2CPP runtime class of the live object.
static void* UnityObjectClassOf(void* obj) {
    if (!obj) return nullptr;
    return UnityResolve::Invoke<void*>("il2cpp_object_get_class", obj);
}

static void* UnityClassFieldByName(void* klass, const char* name) {
    if (!klass || !name) return nullptr;
    for (int guard = 0; klass && guard < 32; ++guard) {
        if (void* f = UnityResolve::Invoke<void*>(
                "il2cpp_class_get_field_from_name", klass, name)) {
            return f;
        }
        klass = UnityResolve::Invoke<void*>("il2cpp_class_get_parent", klass);
    }
    return nullptr;
}

static int32_t UnityFieldOffsetOf(void* field) {
    return field ? UnityResolve::Invoke<int32_t>("il2cpp_field_get_offset", field) : -1;
}

static void* UnityClassMethodByName(void* klass, const char* name) {
    if (!klass || !name) return nullptr;
    return UnityResolve::Invoke<void*>(
        "il2cpp_class_get_method_from_name", klass, name, -1);
}

static std::string UnityClassRuntimeName(void* klass) {
    if (!klass) return "?";
    const char* name = UnityResolve::Invoke<const char*>("il2cpp_class_get_name", klass);
    const char* ns = UnityResolve::Invoke<const char*>(
        "il2cpp_class_get_namespace", klass);
    if (!name || !*name) return "?";
    return (ns && *ns) ? (std::string(ns) + "." + name) : std::string(name);
}

static std::string UnityObjectRuntimeName(void* obj) {
    return obj ? UnityClassRuntimeName(UnityObjectClassOf(obj)) : "null";
}

static void* ReadPtrAt(void* obj, int32_t offset) {
    if (!obj || offset < 0) return nullptr;
    return *reinterpret_cast<void**>(reinterpret_cast<uint8_t*>(obj) + offset);
}

struct UnityMethodOwner {
    UnityResolve::Method* method = nullptr;
    UnityResolve::Class* klass = nullptr;
    UnityResolve::Assembly* assembly = nullptr;
};

static UnityMethodOwner FindMethodByInfoOrFunction(void* methodInfo, void* function) {
    UnityMethodOwner out;
    for (auto* a : UnityResolve::assembly) {
        for (auto* c : a->classes) {
            for (auto* m : c->methods) {
                if (methodInfo && reinterpret_cast<void*>(m->address) == methodInfo) {
                    out = { m, c, a };
                    return out;
                }
                if (!methodInfo && function && reinterpret_cast<void*>(m->function) == function) {
                    out = { m, c, a };
                    return out;
                }
            }
        }
    }
    return out;
}

static std::string UnityMethodOwnerName(const UnityMethodOwner& owner) {
    if (!owner.method) return "?";
    std::string asmName = owner.assembly ? owner.assembly->name : std::string("?");
    if (asmName.size() > 4 && asmName.compare(asmName.size() - 4, 4, ".dll") == 0) {
        asmName.resize(asmName.size() - 4);
    }
    return asmName + "." + UnityClassFullName(owner.klass) + "." + owner.method->name;
}

static std::string UnityRvaAtModule(void* function, bool* ok = nullptr) {
    if (!function) {
        if (ok) *ok = false;
        return "?";
    }
    Dl_info di{};
    if (dladdr(function, &di) && di.dli_fbase) {
        uintptr_t rva = reinterpret_cast<uintptr_t>(function) -
                        reinterpret_cast<uintptr_t>(di.dli_fbase);
        if (ok) *ok = true;
        return HexStr(rva) + "@" + BaseName(di.dli_fname);
    }
    if (ok) *ok = false;
    return HexStr(reinterpret_cast<uintptr_t>(function));
}

static std::string InvokeStringMethod(UnityResolve::Class* cls, const char* name, void* obj) {
    if (!cls) return "";
    auto* m = cls->Get<UnityResolve::Method>(name);
    if (!m || !m->function) return "";
    auto* s = m->Invoke<UnityResolve::UnityType::String*>(obj);
    return s ? UnityStringToUtf8(s) : "";
}

static int32_t InvokeIntMethod(UnityResolve::Class* cls, const char* name, void* obj) {
    if (!cls) return 0;
    auto* m = cls->Get<UnityResolve::Method>(name);
    if (!m || !m->function) return 0;
    return m->Invoke<int32_t>(obj);
}

static void* InvokePtrMethod(UnityResolve::Class* cls, const char* name, void* obj) {
    if (!cls) return nullptr;
    auto* m = cls->Get<UnityResolve::Method>(name);
    if (!m || !m->function) return nullptr;
    return m->Invoke<void*>(obj);
}

static std::string TimeNow() {
    time_t now = time(nullptr);
    struct tm tmv{};
    localtime_r(&now, &tmv);
    char buf[16];
    strftime(buf, sizeof(buf), "%H:%M:%S", &tmv);
    return buf;
}

static std::string UnityFieldModifier(int32_t flags) {
    std::string out;
    switch (flags & 0x0007) {
    case 0x0001: out += "private "; break;
    case 0x0006: out += "public "; break;
    case 0x0004: out += "protected "; break;
    case 0x0003: out += "internal "; break;
    case 0x0005: out += "protected internal "; break;
    case 0x0002: out += "private protected "; break;
    default: break;
    }
    if (flags & 0x0010) out += "static ";
    if (flags & 0x0020) out += "readonly ";
    if (flags & 0x0040) out += "const ";
    return out;
}

// Concise field line for class listings.
static std::string UnityFieldLine(UnityResolve::Field* f) {
    if (!f) return "[Field null]";
    char buf[512];
    snprintf(buf, sizeof(buf), "%s%s %s @ 0x%x",
             f->static_field ? "static " : "",
             UnityShortTypeName(UnityTypeName(f->type)).c_str(),
             f->name.c_str(),
             f->offset);
    return buf;
}

// Concise signature: modifier + short return + name(params with names).
static std::string UnityMethodSignature(UnityResolve::Method* m) {
    if (!m) return "?";
    std::string out = UnityMethodModifier(m->flags);
    out += UnityShortTypeName(UnityTypeName(m->return_type));
    out += " " + m->name + "(";
    for (size_t i = 0; i < m->args.size(); ++i) {
        if (i) out += ", ";
        auto* a = m->args[i];
        out += UnityShortTypeName(UnityTypeName(a ? a->pType : nullptr));
        if (a && !a->name.empty()) out += " " + a->name;
    }
    out += ")";
    return out;
}

// MethodInfo -> function (RVA in its owning module).
static std::string UnityMethodSummary(UnityResolve::Method* m) {
    if (!m) return "[Method null]";
    std::string mod = "?";
    uintptr_t rva = 0;
    if (m->function) {
        Dl_info di{};
        if (dladdr(reinterpret_cast<void*>(m->function), &di) && di.dli_fbase) {
            rva = reinterpret_cast<uintptr_t>(m->function) -
                  reinterpret_cast<uintptr_t>(di.dli_fbase);
            mod = BaseName(di.dli_fname);
        }
    }

    std::string out = HexStr(reinterpret_cast<uintptr_t>(m->address));
    out += " ---> ";
    out += m->function ? HexStr(reinterpret_cast<uintptr_t>(m->function)) : "null";
    out += " (";
    out += m->function ? (HexStr(rva) + "@" + mod) : std::string("rva ?");
    out += ") | ";
    out += UnityMethodSignature(m);
    return out;
}

// Detailed field display (field wrapper toString).
static std::string UnityFieldText(UnityResolve::Field* f) {
    if (!f) return "[Field null]";
    UnityResolve::Class* c = f->klass;
    UnityResolve::Assembly* a = FindAssemblyForClass(c);

    std::string out;
    out += "namespace: " + (c && !c->namespaze.empty() ? c->namespaze : std::string("(global)")) + "\n";
    out += "assembly:  " + (a ? a->name : "?") + "\n";
    out += "class:     " + (c ? UnityClassFullName(c) : std::string("?")) + "\n";
    out += "field:     " + UnityFieldLine(f) + "\n";
    out += "  type:    " + UnityTypeName(f->type) +
           " (short " + UnityShortTypeName(UnityTypeName(f->type)) + ")\n";
    out += "  offset:  " + HexStr(static_cast<uintptr_t>(f->offset)) + "\n";
    out += "  static:  " + std::string(f->static_field ? "true" : "false");
    return out;
}

// Detailed method display (method wrapper toString).
static std::string UnityMethodText(UnityResolve::Method* m) {
    if (!m) return "[Method null]";
    UnityResolve::Class* c = m->klass;
    UnityResolve::Assembly* a = FindAssemblyForClass(c);

    std::string mod = "?";
    uintptr_t rva = 0;
    bool hasRva = false;
    if (m->function) {
        Dl_info di{};
        if (dladdr(reinterpret_cast<void*>(m->function), &di) && di.dli_fbase) {
            rva = reinterpret_cast<uintptr_t>(m->function) -
                  reinterpret_cast<uintptr_t>(di.dli_fbase);
            mod = BaseName(di.dli_fname);
            hasRva = true;
        }
    }

    std::string out;
    out += "namespace: " + (c && !c->namespaze.empty() ? c->namespaze : std::string("(global)")) + "\n";
    out += "assembly:  " + (a ? a->name : "?") + "\n";
    out += "class:     " + (c ? UnityClassFullName(c) : std::string("?")) + "\n";
    out += "method:    " + UnityMethodSignature(m) + "\n";
    out += "  methodInfo:  " + HexStr(reinterpret_cast<uintptr_t>(m->address)) + "\n";
    out += "  function:    " + (m->function ? HexStr(reinterpret_cast<uintptr_t>(m->function)) : std::string("null")) + "\n";
    out += "  module:      " + mod + "\n";
    out += "  rva:         " + (hasRva ? HexStr(rva) : std::string("?")) + "\n";
    out += "  return:      " + UnityTypeName(m->return_type) +
           " (short " + UnityShortTypeName(UnityTypeName(m->return_type)) + ")\n";
    out += "  parameters (" + std::to_string(m->args.size()) + "):";
    for (size_t i = 0; i < m->args.size(); ++i) {
        auto* arg = m->args[i];
        out += "\n    [" + std::to_string(i) + "] " +
               UnityShortTypeName(UnityTypeName(arg ? arg->pType : nullptr));
        if (arg && !arg->name.empty()) out += " " + arg->name;
        out += "  (" + UnityTypeName(arg ? arg->pType : nullptr) + ")";
    }
    return out;
}

// Detailed class display (class wrapper toString).
static std::string UnityClassText(UnityResolve::Class* c) {
    if (!c) return "[Class null]";
    UnityResolve::Assembly* a = FindAssemblyForClass(c);
    constexpr size_t kMaxShow = 50;

    std::string out;
    out += "namespace: " + (c->namespaze.empty() ? std::string("(global)") : c->namespaze) + "\n";
    out += "assembly:  " + (a ? a->name : "?") + "\n";
    out += "class:     " + c->name;
    if (!c->parent.empty()) out += " : " + c->parent;
    out += " @ " + HexStr(reinterpret_cast<uintptr_t>(c->address)) + "\n";

    out += "fields (" + std::to_string(c->fields.size()) + "):";
    for (size_t i = 0; i < c->fields.size() && i < kMaxShow; ++i) {
        out += "\n  [" + std::to_string(i) + "] " + UnityFieldLine(c->fields[i]);
    }
    if (c->fields.size() > kMaxShow) {
        out += "\n  ... (+" + std::to_string(c->fields.size() - kMaxShow) + " more)";
    }

    out += "\nmethods (" + std::to_string(c->methods.size()) + "):";
    for (size_t i = 0; i < c->methods.size() && i < kMaxShow; ++i) {
        out += "\n  [" + std::to_string(i) + "] " + UnityMethodSummary(c->methods[i]);
    }
    if (c->methods.size() > kMaxShow) {
        out += "\n  ... (+" + std::to_string(c->methods.size() - kMaxShow) + " more)";
    }
    return out;
}

// Detailed assembly display (assembly wrapper toString).
static std::string UnityAssemblyText(UnityResolve::Assembly* a) {
    if (!a) return "[Assembly null]";
    std::string out;
    out += "assembly: " + a->name + "\n";
    out += "file:     " + a->file + "\n";
    out += "address:  " + HexStr(reinterpret_cast<uintptr_t>(a->address)) + "\n";
    out += "classes:  " + std::to_string(a->classes.size());
    return out;
}

// Il2CppHookScripts style GameObject inspector used by HookSetActive /
// HookOnPointerClick / showGameObject.
static std::string FormatGameObject(void* goPtr) {
    if (!goPtr) return "[GameObject null]";
    auto* core = UnityResolve::Get("UnityEngine.CoreModule.dll");
    if (!core) return "[!] UnityEngine.CoreModule.dll missing";
    auto* goCls = core->Get("GameObject");
    auto* objCls = core->Get("Object");
    auto* trCls = core->Get("Transform");

    std::string name = InvokeStringMethod(objCls, "get_name", goPtr);
    int32_t layer = InvokeIntMethod(goCls, "get_layer", goPtr);
    void* tr = InvokePtrMethod(goCls, "get_transform", goPtr);

    std::string hierarchy;
    void* cur = tr;
    int guard = 0;
    while (cur && guard++ < 32) {
        std::string n = InvokeStringMethod(objCls, "get_name", cur);
        if (!hierarchy.empty()) hierarchy += " <--- ";
        hierarchy += (n.empty() ? std::string("(unnamed)") : n) +
                     "(" + HexStr(reinterpret_cast<uintptr_t>(cur)) + ")";
        cur = InvokePtrMethod(trCls, "get_parent", cur);
    }

    std::string out;
    out += "--------- GameObject ---------\n";
    out += "gameObj         --->    " + HexStr(reinterpret_cast<uintptr_t>(goPtr)) + "\n";
    out += "getName         --->    " + (name.empty() ? std::string("(unnamed)") : name) + "\n";
    out += "getLayer        --->    " + std::to_string(layer) + "\n";
    out += "getTransform    --->    " + (tr ? HexStr(reinterpret_cast<uintptr_t>(tr)) : std::string("null")) + "\n";
    out += "hierarchy       --->    " + (hierarchy.empty() ? std::string("(none)") : hierarchy);
    return out;
}

static void* ComponentGameObject(void* component) {
    if (!component) return nullptr;
    auto* core = UnityResolve::Get("UnityEngine.CoreModule.dll");
    if (!core) return nullptr;
    return InvokePtrMethod(core->Get("Component"), "get_gameObject", component);
}

static JSValue JsUnityWrapperToString(JSContext* ctx, JSValueConst this_val, int, JSValueConst*) {
    JSValue kindVal = JS_GetPropertyStr(ctx, this_val, "__unity_kind");
    std::string kind = ArgString(ctx, kindVal);
    JS_FreeValue(ctx, kindVal);
    void* ptr = ThisPtr(ctx, this_val);

    std::string text;
    if (kind == "assembly") {
        text = UnityAssemblyText(reinterpret_cast<UnityResolve::Assembly*>(ptr));
    } else if (kind == "class") {
        text = UnityClassText(reinterpret_cast<UnityResolve::Class*>(ptr));
    } else if (kind == "field") {
        text = UnityFieldText(reinterpret_cast<UnityResolve::Field*>(ptr));
    } else if (kind == "method") {
        text = UnityMethodText(reinterpret_cast<UnityResolve::Method*>(ptr));
    } else {
        text = "[UnityObject]";
    }
    return JS_NewString(ctx, text.c_str());
}

// ---------------------------------------------------------------------------
// JS wrappers (assemblies / classes / fields / methods)
// ---------------------------------------------------------------------------
static JSValue MakeFieldObject(JSContext* ctx, UnityResolve::Field* f);

static JSValue JsFieldGet(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
    std::lock_guard<std::mutex> lk(g_unityMutex);
    std::string err;
    if (!EnsureInitLocked(&err)) return JS_ThrowInternalError(ctx, "UnityResolve: %s", err.c_str());
    EnsureThreadAttached();

    auto* f = reinterpret_cast<UnityResolve::Field*>(ThisPtr(ctx, this_val));
    void* obj = argc >= 1 ? ArgPtr(ctx, argv[0]) : nullptr;
    return ReadField(ctx, f, obj);
}

static JSValue JsFieldSet(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
    std::lock_guard<std::mutex> lk(g_unityMutex);
    std::string err;
    if (!EnsureInitLocked(&err)) return JS_ThrowInternalError(ctx, "UnityResolve: %s", err.c_str());
    EnsureThreadAttached();

    auto* f = reinterpret_cast<UnityResolve::Field*>(ThisPtr(ctx, this_val));
    if (argc < 2) return JS_ThrowTypeError(ctx, "field.set(instance, value)");
    void* obj = ArgPtr(ctx, argv[0]);
    if (!WriteField(ctx, f, obj, argv[1])) return JS_ThrowTypeError(ctx, "field.set() failed");
    return JS_TRUE;
}

static JSValue JsFieldGetStatic(JSContext* ctx, JSValueConst this_val, int, JSValueConst*) {
    std::lock_guard<std::mutex> lk(g_unityMutex);
    std::string err;
    if (!EnsureInitLocked(&err)) return JS_ThrowInternalError(ctx, "UnityResolve: %s", err.c_str());
    EnsureThreadAttached();
    auto* f = reinterpret_cast<UnityResolve::Field*>(ThisPtr(ctx, this_val));
    return ReadField(ctx, f, nullptr);
}

static JSValue JsFieldSetStatic(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
    std::lock_guard<std::mutex> lk(g_unityMutex);
    std::string err;
    if (!EnsureInitLocked(&err)) return JS_ThrowInternalError(ctx, "UnityResolve: %s", err.c_str());
    EnsureThreadAttached();
    auto* f = reinterpret_cast<UnityResolve::Field*>(ThisPtr(ctx, this_val));
    if (argc < 1) return JS_ThrowTypeError(ctx, "field.setStatic(value)");
    if (!WriteField(ctx, f, nullptr, argv[0])) return JS_ThrowTypeError(ctx, "field.setStatic() failed");
    return JS_TRUE;
}

static JSValue MakeFieldObject(JSContext* ctx, UnityResolve::Field* f) {
    if (!f) return JS_NULL;
    JSValue o = JS_NewObject(ctx);
    JS_SetPropertyStr(ctx, o, "__ptr", PtrToJs(ctx, f));
    JS_SetPropertyStr(ctx, o, "__unity_kind", JS_NewString(ctx, "field"));
    JS_SetPropertyStr(ctx, o, "toString", JS_NewCFunction(ctx, JsUnityWrapperToString, "toString", 0));
    JS_SetPropertyStr(ctx, o, "name", JS_NewString(ctx, f->name.c_str()));
    JS_SetPropertyStr(ctx, o, "offset", JS_NewInt32(ctx, f->offset));
    JS_SetPropertyStr(ctx, o, "type", JS_NewString(ctx, f->type ? f->type->name.c_str() : "?"));
    JS_SetPropertyStr(ctx, o, "static", JS_NewBool(ctx, f->static_field));
    JS_SetPropertyStr(ctx, o, "get", JS_NewCFunction(ctx, JsFieldGet, "get", 1));
    JS_SetPropertyStr(ctx, o, "set", JS_NewCFunction(ctx, JsFieldSet, "set", 2));
    JS_SetPropertyStr(ctx, o, "getStatic", JS_NewCFunction(ctx, JsFieldGetStatic, "getStatic", 0));
    JS_SetPropertyStr(ctx, o, "setStatic", JS_NewCFunction(ctx, JsFieldSetStatic, "setStatic", 1));
    return o;
}

static JSValue JsMethodInvoke(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
    std::lock_guard<std::mutex> lk(g_unityMutex);
    std::string err;
    if (!EnsureInitLocked(&err)) return JS_ThrowInternalError(ctx, "UnityResolve: %s", err.c_str());
    EnsureThreadAttached();

    auto* m = reinterpret_cast<UnityResolve::Method*>(ThisPtr(ctx, this_val));
    if (!m) return JS_ThrowTypeError(ctx, "invalid method");

    void* obj = nullptr;
    int first = 0;
    if (!m->static_function) {
        if (argc < 1) return JS_ThrowTypeError(ctx, "instance method %s requires instance as first argument", m->name.c_str());
        obj = ArgPtr(ctx, argv[0]);
        first = 1;
    }
    return InvokeMethod(ctx, m, obj, argc - first, argv + first);
}

static JSValue MakeMethodObject(JSContext* ctx, UnityResolve::Method* m) {
    if (!m) return JS_NULL;
    JSValue o = JS_NewObject(ctx);
    JS_SetPropertyStr(ctx, o, "__ptr", PtrToJs(ctx, m));
    JS_SetPropertyStr(ctx, o, "__unity_kind", JS_NewString(ctx, "method"));
    JS_SetPropertyStr(ctx, o, "toString", JS_NewCFunction(ctx, JsUnityWrapperToString, "toString", 0));
    JS_SetPropertyStr(ctx, o, "name", JS_NewString(ctx, m->name.c_str()));
    // MethodInfo* (what mi()/b() expect), not the UnityResolve wrapper pointer.
    JS_SetPropertyStr(ctx, o, "methodInfo", PtrToJs(ctx, m->address));
    JS_SetPropertyStr(ctx, o, "address", PtrToJs(ctx, m->function));
    JS_SetPropertyStr(ctx, o, "static", JS_NewBool(ctx, m->static_function));
    JS_SetPropertyStr(ctx, o, "ret", JS_NewString(ctx, m->return_type ? m->return_type->name.c_str() : "?"));
    JSValue args = JS_NewArray(ctx);
    for (size_t i = 0; i < m->args.size(); ++i) {
        JS_SetPropertyUint32(ctx, args, static_cast<uint32_t>(i),
                             JS_NewString(ctx, m->args[i]->pType ? m->args[i]->pType->name.c_str() : "?"));
    }
    JS_SetPropertyStr(ctx, o, "args", args);
    JS_SetPropertyStr(ctx, o, "invoke", JS_NewCFunction(ctx, JsMethodInvoke, "invoke", 0));
    return o;
}

static JSValue MakeClassObject(JSContext* ctx, UnityResolve::Class* c);

// Custom array toString so `cls.fields()` / `cls.methods()` print a compact,
// aligned list instead of nested multi-line wrapper dumps.
static JSValue JsUnityFieldArrayToString(JSContext* ctx, JSValueConst this_val, int, JSValueConst*) {
    int64_t len = 0;
    JSValue lenVal = JS_GetPropertyStr(ctx, this_val, "length");
    JS_ToInt64(ctx, &len, lenVal);
    JS_FreeValue(ctx, lenVal);

    std::string out = "fields (" + std::to_string(len) + "):";
    for (int64_t i = 0; i < len; ++i) {
        JSValue elem = JS_GetPropertyUint32(ctx, this_val, static_cast<uint32_t>(i));
        JSValue p = JS_GetPropertyStr(ctx, elem, "__ptr");
        auto* f = reinterpret_cast<UnityResolve::Field*>(
            static_cast<uintptr_t>(ParsePtr(ctx, p)));
        JS_FreeValue(ctx, p);
        JS_FreeValue(ctx, elem);
        out += "\n  [" + std::to_string(i) + "] " + UnityFieldLine(f);
    }
    return JS_NewString(ctx, out.c_str());
}

static JSValue JsUnityMethodArrayToString(JSContext* ctx, JSValueConst this_val, int, JSValueConst*) {
    int64_t len = 0;
    JSValue lenVal = JS_GetPropertyStr(ctx, this_val, "length");
    JS_ToInt64(ctx, &len, lenVal);
    JS_FreeValue(ctx, lenVal);

    std::string out = "methods (" + std::to_string(len) + "):";
    for (int64_t i = 0; i < len; ++i) {
        JSValue elem = JS_GetPropertyUint32(ctx, this_val, static_cast<uint32_t>(i));
        JSValue p = JS_GetPropertyStr(ctx, elem, "__ptr");
        auto* m = reinterpret_cast<UnityResolve::Method*>(
            static_cast<uintptr_t>(ParsePtr(ctx, p)));
        JS_FreeValue(ctx, p);
        JS_FreeValue(ctx, elem);
        out += "\n  [" + std::to_string(i) + "] " + UnityMethodSummary(m);
    }
    return JS_NewString(ctx, out.c_str());
}

static JSValue JsClassFields(JSContext* ctx, JSValueConst this_val, int, JSValueConst*) {
    std::lock_guard<std::mutex> lk(g_unityMutex);
    auto* c = reinterpret_cast<UnityResolve::Class*>(ThisPtr(ctx, this_val));
    JSValue arr = JS_NewArray(ctx);
    if (!c) return arr;
    for (size_t i = 0; i < c->fields.size(); ++i) {
        JS_SetPropertyUint32(ctx, arr, static_cast<uint32_t>(i), MakeFieldObject(ctx, c->fields[i]));
    }
    JS_SetPropertyStr(ctx, arr, "toString",
                      JS_NewCFunction(ctx, JsUnityFieldArrayToString, "toString", 0));
    return arr;
}

static JSValue JsClassMethods(JSContext* ctx, JSValueConst this_val, int, JSValueConst*) {
    std::lock_guard<std::mutex> lk(g_unityMutex);
    auto* c = reinterpret_cast<UnityResolve::Class*>(ThisPtr(ctx, this_val));
    JSValue arr = JS_NewArray(ctx);
    if (!c) return arr;
    for (size_t i = 0; i < c->methods.size(); ++i) {
        JS_SetPropertyUint32(ctx, arr, static_cast<uint32_t>(i), MakeMethodObject(ctx, c->methods[i]));
    }
    JS_SetPropertyStr(ctx, arr, "toString",
                      JS_NewCFunction(ctx, JsUnityMethodArrayToString, "toString", 0));
    return arr;
}

static JSValue JsClassField(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
    std::lock_guard<std::mutex> lk(g_unityMutex);
    auto* c = reinterpret_cast<UnityResolve::Class*>(ThisPtr(ctx, this_val));
    if (!c || argc < 1) return JS_NULL;
    return MakeFieldObject(ctx, c->Get<UnityResolve::Field>(ArgString(ctx, argv[0])));
}

static JSValue JsClassMethod(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
    std::lock_guard<std::mutex> lk(g_unityMutex);
    auto* c = reinterpret_cast<UnityResolve::Class*>(ThisPtr(ctx, this_val));
    if (!c || argc < 1) return JS_NULL;
    std::vector<std::string> types;
    if (argc >= 2) types = ArgStringArray(ctx, argv[1]);
    return MakeMethodObject(ctx, c->Get<UnityResolve::Method>(ArgString(ctx, argv[0]), types));
}

static JSValue JsClassNew(JSContext* ctx, JSValueConst this_val, int, JSValueConst*) {
    std::lock_guard<std::mutex> lk(g_unityMutex);
    std::string err;
    if (!EnsureInitLocked(&err)) return JS_ThrowInternalError(ctx, "UnityResolve: %s", err.c_str());
    EnsureThreadAttached();
    auto* c = reinterpret_cast<UnityResolve::Class*>(ThisPtr(ctx, this_val));
    if (!c) return JS_NULL;
    void* obj = UnityResolve::Invoke<void*, void*>("il2cpp_object_new", c->address);
    return PtrToJs(ctx, obj);
}

static JSValue JsClassType(JSContext* ctx, JSValueConst this_val, int, JSValueConst*) {
    std::lock_guard<std::mutex> lk(g_unityMutex);
    std::string err;
    if (!EnsureInitLocked(&err)) return JS_ThrowInternalError(ctx, "UnityResolve: %s", err.c_str());
    EnsureThreadAttached();
    auto* c = reinterpret_cast<UnityResolve::Class*>(ThisPtr(ctx, this_val));
    if (!c) return JS_NULL;
    return PtrToJs(ctx, c->GetType());
}

static JSValue JsClassFindObjects(JSContext* ctx, JSValueConst this_val, int, JSValueConst*) {
    std::lock_guard<std::mutex> lk(g_unityMutex);
    std::string err;
    if (!EnsureInitLocked(&err)) return JS_ThrowInternalError(ctx, "UnityResolve: %s", err.c_str());
    EnsureThreadAttached();
    auto* c = reinterpret_cast<UnityResolve::Class*>(ThisPtr(ctx, this_val));
    JSValue arr = JS_NewArray(ctx);
    if (!c) return arr;
    auto objects = FindObjectsOfType(c);
    for (size_t i = 0; i < objects.size(); ++i) {
        JS_SetPropertyUint32(ctx, arr, static_cast<uint32_t>(i), PtrToJs(ctx, objects[i]));
    }
    return arr;
}

static JSValue JsUnityM(JSContext* ctx, JSValueConst, int argc, JSValueConst* argv);

static JSValue MakeClassObject(JSContext* ctx, UnityResolve::Class* c) {
    if (!c) return JS_NULL;
    JSValue o = JS_NewObject(ctx);
    JS_SetPropertyStr(ctx, o, "__ptr", PtrToJs(ctx, c));
    JS_SetPropertyStr(ctx, o, "__unity_kind", JS_NewString(ctx, "class"));
    JS_SetPropertyStr(ctx, o, "toString", JS_NewCFunction(ctx, JsUnityWrapperToString, "toString", 0));
    JS_SetPropertyStr(ctx, o, "name", JS_NewString(ctx, c->name.c_str()));
    JS_SetPropertyStr(ctx, o, "namespace", JS_NewString(ctx, c->namespaze.c_str()));
    JS_SetPropertyStr(ctx, o, "parent", JS_NewString(ctx, c->parent.c_str()));
    JS_SetPropertyStr(ctx, o, "address", PtrToJs(ctx, c->address));
    JS_SetPropertyStr(ctx, o, "fields", JS_NewCFunction(ctx, JsClassFields, "fields", 0));
    JS_SetPropertyStr(ctx, o, "methods", JS_NewCFunction(ctx, JsClassMethods, "methods", 0));
    JS_SetPropertyStr(ctx, o, "m", JS_NewCFunction(ctx, JsUnityM, "m", 3));
    JS_SetPropertyStr(ctx, o, "field", JS_NewCFunction(ctx, JsClassField, "field", 1));
    JS_SetPropertyStr(ctx, o, "method", JS_NewCFunction(ctx, JsClassMethod, "method", 2));
    JS_SetPropertyStr(ctx, o, "new", JS_NewCFunction(ctx, JsClassNew, "new", 0));
    JS_SetPropertyStr(ctx, o, "type", JS_NewCFunction(ctx, JsClassType, "type", 0));
    JS_SetPropertyStr(ctx, o, "findObjects", JS_NewCFunction(ctx, JsClassFindObjects, "findObjects", 0));
    return o;
}

static JSValue MakeAssemblyObject(JSContext* ctx, UnityResolve::Assembly* a);

static JSValue JsAssemblyClasses(JSContext* ctx, JSValueConst this_val, int, JSValueConst*) {
    std::lock_guard<std::mutex> lk(g_unityMutex);
    auto* a = reinterpret_cast<UnityResolve::Assembly*>(ThisPtr(ctx, this_val));
    JSValue arr = JS_NewArray(ctx);
    if (!a) return arr;
    for (size_t i = 0; i < a->classes.size(); ++i) {
        JS_SetPropertyUint32(ctx, arr, static_cast<uint32_t>(i),
                             JS_NewString(ctx, a->classes[i]->name.c_str()));
    }
    return arr;
}

static JSValue JsAssemblyClass(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
    std::lock_guard<std::mutex> lk(g_unityMutex);
    auto* a = reinterpret_cast<UnityResolve::Assembly*>(ThisPtr(ctx, this_val));
    if (!a || argc < 1) return JS_NULL;
    std::string ns = argc >= 2 ? ArgString(ctx, argv[1]) : "*";
    std::string parent = argc >= 3 ? ArgString(ctx, argv[2]) : "*";
    return MakeClassObject(ctx, a->Get(ArgString(ctx, argv[0]), ns, parent));
}

static JSValue MakeAssemblyObject(JSContext* ctx, UnityResolve::Assembly* a) {
    if (!a) return JS_NULL;
    JSValue o = JS_NewObject(ctx);
    JS_SetPropertyStr(ctx, o, "__ptr", PtrToJs(ctx, a));
    JS_SetPropertyStr(ctx, o, "__unity_kind", JS_NewString(ctx, "assembly"));
    JS_SetPropertyStr(ctx, o, "toString", JS_NewCFunction(ctx, JsUnityWrapperToString, "toString", 0));
    JS_SetPropertyStr(ctx, o, "name", JS_NewString(ctx, a->name.c_str()));
    JS_SetPropertyStr(ctx, o, "file", JS_NewString(ctx, a->file.c_str()));
    JS_SetPropertyStr(ctx, o, "classes", JS_NewCFunction(ctx, JsAssemblyClasses, "classes", 0));
    JS_SetPropertyStr(ctx, o, "class", JS_NewCFunction(ctx, JsAssemblyClass, "class", 3));
    JS_SetPropertyStr(ctx, o, "get", JS_NewCFunction(ctx, JsAssemblyClass, "get", 3));
    return o;
}

// ---------------------------------------------------------------------------
// Root API
// ---------------------------------------------------------------------------
static JSValue JsUnityInit(JSContext* ctx, JSValueConst, int, JSValueConst*) {
    std::lock_guard<std::mutex> lk(g_unityMutex);
    std::string err;
    if (!EnsureInitLocked(&err)) return JS_NewString(ctx, (std::string("[!] ") + err).c_str());
    char buf[160];
    snprintf(buf, sizeof(buf), "[+] UnityResolve ready: %zu assemblies", UnityResolve::assembly.size());
    return JS_NewString(ctx, buf);
}

static JSValue JsUnityAvailable(JSContext* ctx, JSValueConst, int, JSValueConst*) {
    std::lock_guard<std::mutex> lk(g_unityMutex);
    std::string err;
    return JS_NewBool(ctx, EnsureInitLocked(&err));
}

static JSValue JsUnityAssemblies(JSContext* ctx, JSValueConst, int, JSValueConst*) {
    std::lock_guard<std::mutex> lk(g_unityMutex);
    std::string err;
    if (!EnsureInitLocked(&err)) return JS_ThrowInternalError(ctx, "UnityResolve: %s", err.c_str());
    JSValue arr = JS_NewArray(ctx);
    for (size_t i = 0; i < UnityResolve::assembly.size(); ++i) {
        JS_SetPropertyUint32(ctx, arr, static_cast<uint32_t>(i),
                             JS_NewString(ctx, UnityResolve::assembly[i]->name.c_str()));
    }
    return arr;
}

static JSValue JsUnityAssembly(JSContext* ctx, JSValueConst, int argc, JSValueConst* argv) {
    std::lock_guard<std::mutex> lk(g_unityMutex);
    std::string err;
    if (!EnsureInitLocked(&err)) return JS_ThrowInternalError(ctx, "UnityResolve: %s", err.c_str());
    if (argc < 1) return JS_NULL;
    return MakeAssemblyObject(ctx, UnityResolve::Get(ArgString(ctx, argv[0])));
}

static JSValue JsUnityClass(JSContext* ctx, JSValueConst, int argc, JSValueConst* argv) {
    std::lock_guard<std::mutex> lk(g_unityMutex);
    std::string err;
    if (!EnsureInitLocked(&err)) return JS_ThrowInternalError(ctx, "UnityResolve: %s", err.c_str());
    if (argc < 2) return JS_ThrowTypeError(ctx, "unity.class(assembly, class, [namespace])");
    auto* a = UnityResolve::Get(ArgString(ctx, argv[0]));
    if (!a) return JS_NULL;
    std::string ns = argc >= 3 ? ArgString(ctx, argv[2]) : "*";
    return MakeClassObject(ctx, a->Get(ArgString(ctx, argv[1]), ns));
}

// ---------------------------------------------------------------------------
// dynamic.unity.findclass / findmethods: full-tree scans with wildcards.
// Kept under dynamic.unity only (no globals) to avoid clashes with the Java
// findclass/findMethods helpers.
// ---------------------------------------------------------------------------
struct UnityFindOptions {
    std::string assembly;
    std::string classFilter;
    std::string nsFilter;
    bool exact = false;
    bool includeAbstract = true;
    int limit = 200;
};

static UnityFindOptions ParseFindOptions(JSContext* ctx, JSValueConst v) {
    UnityFindOptions o;
    if (JS_IsObject(v)) {
        JSValue x = JS_GetPropertyStr(ctx, v, "assembly");
        if (JS_IsString(x)) o.assembly = ArgString(ctx, x);
        JS_FreeValue(ctx, x);

        x = JS_GetPropertyStr(ctx, v, "class");
        if (JS_IsString(x)) o.classFilter = ArgString(ctx, x);
        JS_FreeValue(ctx, x);

        x = JS_GetPropertyStr(ctx, v, "namespace");
        if (JS_IsString(x)) o.nsFilter = ArgString(ctx, x);
        JS_FreeValue(ctx, x);

        x = JS_GetPropertyStr(ctx, v, "exact");
        if (!JS_IsUndefined(x)) o.exact = JS_ToBool(ctx, x) != 0;
        JS_FreeValue(ctx, x);

        x = JS_GetPropertyStr(ctx, v, "includeAbstract");
        if (!JS_IsUndefined(x)) o.includeAbstract = JS_ToBool(ctx, x) != 0;
        JS_FreeValue(ctx, x);

        x = JS_GetPropertyStr(ctx, v, "limit");
        if (JS_IsNumber(x)) JS_ToInt32(ctx, &o.limit, x);
        JS_FreeValue(ctx, x);

        if (o.limit < 1) o.limit = 1;
        if (o.limit > 1000) o.limit = 1000;
        return o;
    }
    if (JS_IsString(v)) o.assembly = ArgString(ctx, v);
    if (o.limit < 1) o.limit = 1;
    if (o.limit > 1000) o.limit = 1000;
    return o;
}

static JSValue JsUnityClassArrayToString(JSContext* ctx, JSValueConst this_val, int, JSValueConst*) {
    int64_t len = 0;
    JSValue lenVal = JS_GetPropertyStr(ctx, this_val, "length");
    JS_ToInt64(ctx, &len, lenVal);
    JS_FreeValue(ctx, lenVal);

    std::string out = "classes (" + std::to_string(len) + "):";
    for (int64_t i = 0; i < len; ++i) {
        JSValue elem = JS_GetPropertyUint32(ctx, this_val, static_cast<uint32_t>(i));
        JSValue p = JS_GetPropertyStr(ctx, elem, "__ptr");
        auto* c = reinterpret_cast<UnityResolve::Class*>(
            static_cast<uintptr_t>(ParsePtr(ctx, p)));
        JS_FreeValue(ctx, p);
        JS_FreeValue(ctx, elem);
        if (!c) continue;
        std::string full = c->namespaze.empty() ? c->name : (c->namespaze + "." + c->name);
        out += "\n  [" + std::to_string(i) + "] " + full + " @ " +
               HexStr(reinterpret_cast<uintptr_t>(c->address)) +
               " | F:" + std::to_string(c->fields.size()) +
               " M:" + std::to_string(c->methods.size());
    }
    return JS_NewString(ctx, out.c_str());
}

static JSValue JsUnityFindClass(JSContext* ctx, JSValueConst, int argc, JSValueConst* argv) {
    if (argc < 1) return JS_ThrowTypeError(ctx, "unity.findclass(pattern, [options])");
    std::string pattern = ArgString(ctx, argv[0]);
    if (pattern.empty()) pattern = "*";
    UnityFindOptions opt = argc >= 2 ? ParseFindOptions(ctx, argv[1]) : UnityFindOptions{};

    std::lock_guard<std::mutex> lk(g_unityMutex);
    std::string err;
    if (!EnsureInitLocked(&err)) return JS_ThrowInternalError(ctx, "UnityResolve: %s", err.c_str());

    JSValue arr = JS_NewArray(ctx);
    uint32_t index = 0;
    for (auto* a : UnityResolve::assembly) {
        if (index >= static_cast<uint32_t>(opt.limit)) break;
        if (!opt.assembly.empty() && !UnityWildcardMatch(opt.assembly, a->name)) continue;
        for (auto* c : a->classes) {
            if (index >= static_cast<uint32_t>(opt.limit)) break;
            std::string full = c->namespaze.empty() ? c->name : (c->namespaze + "." + c->name);
            if (!opt.nsFilter.empty() && !UnityWildcardMatch(opt.nsFilter, c->namespaze)) continue;
            if (!UnityWildcardMatch(pattern, c->name, opt.exact) &&
                !UnityWildcardMatch(pattern, full, opt.exact)) {
                continue;
            }
            JS_SetPropertyUint32(ctx, arr, index++, MakeClassObject(ctx, c));
        }
    }
    JS_SetPropertyStr(ctx, arr, "toString",
                      JS_NewCFunction(ctx, JsUnityClassArrayToString, "toString", 0));
    return arr;
}

static JSValue JsUnityFindMethods(JSContext* ctx, JSValueConst, int argc, JSValueConst* argv) {
    if (argc < 1) return JS_ThrowTypeError(ctx, "unity.findmethods(pattern, [options])");
    std::string pattern = ArgString(ctx, argv[0]);
    if (pattern.empty()) pattern = "*";
    UnityFindOptions opt = argc >= 2 ? ParseFindOptions(ctx, argv[1]) : UnityFindOptions{};

    std::lock_guard<std::mutex> lk(g_unityMutex);
    std::string err;
    if (!EnsureInitLocked(&err)) return JS_ThrowInternalError(ctx, "UnityResolve: %s", err.c_str());

    JSValue arr = JS_NewArray(ctx);
    uint32_t index = 0;
    for (auto* a : UnityResolve::assembly) {
        if (index >= static_cast<uint32_t>(opt.limit)) break;
        if (!opt.assembly.empty() && !UnityWildcardMatch(opt.assembly, a->name)) continue;
        for (auto* c : a->classes) {
            if (index >= static_cast<uint32_t>(opt.limit)) break;
            std::string full = c->namespaze.empty() ? c->name : (c->namespaze + "." + c->name);
            if (!opt.nsFilter.empty() && !UnityWildcardMatch(opt.nsFilter, c->namespaze)) continue;
            if (!opt.classFilter.empty() &&
                !UnityWildcardMatch(opt.classFilter, c->name) &&
                !UnityWildcardMatch(opt.classFilter, full)) {
                continue;
            }
            for (auto* m : c->methods) {
                if (index >= static_cast<uint32_t>(opt.limit)) break;
                if (!opt.includeAbstract && (m->flags & 0x0400)) continue;
                if (!UnityWildcardMatch(pattern, m->name, opt.exact)) continue;
                JS_SetPropertyUint32(ctx, arr, index++, MakeMethodObject(ctx, m));
            }
        }
    }
    JS_SetPropertyStr(ctx, arr, "toString",
                      JS_NewCFunction(ctx, JsUnityMethodArrayToString, "toString", 0));
    return arr;
}

// dynamic.unity.m(target, [sort], [detailed]) - TS `m()` / showMethods port.
static UnityResolve::Class* ResolveClassArg(JSContext* ctx, JSValueConst v) {
    if (JS_IsObject(v)) {
        JSValue kindVal = JS_GetPropertyStr(ctx, v, "__unity_kind");
        std::string kind = ArgString(ctx, kindVal);
        JS_FreeValue(ctx, kindVal);
        if (kind == "class") return reinterpret_cast<UnityResolve::Class*>(ThisPtr(ctx, v));
        if (kind == "method") {
            auto* m = reinterpret_cast<UnityResolve::Method*>(ThisPtr(ctx, v));
            return m ? m->klass : nullptr;
        }
        return nullptr;
    }
    if (JS_IsString(v)) {
        std::string name = ArgString(ctx, v);
        if (name.rfind("0x", 0) == 0 || name.rfind("0X", 0) == 0) {
            return reinterpret_cast<UnityResolve::Class*>(
                static_cast<uintptr_t>(ParsePtr(ctx, v)));
        }
        if (auto* c = FindClassByName(name)) return c;
        // Wildcards: first match wins.
        for (auto* a : UnityResolve::assembly) {
            for (auto* c : a->classes) {
                std::string full = c->namespaze.empty() ? c->name : (c->namespaze + "." + c->name);
                if (UnityWildcardMatch(name, c->name) || UnityWildcardMatch(name, full)) return c;
            }
        }
        return nullptr;
    }
    uintptr_t p = static_cast<uintptr_t>(ParsePtr(ctx, v));
    return p ? reinterpret_cast<UnityResolve::Class*>(p) : nullptr;
}

static JSValue JsUnityM(JSContext* ctx, JSValueConst, int argc, JSValueConst* argv) {
    if (argc < 1) return JS_ThrowTypeError(ctx, "unity.m(classOrName, [sort], [detailed])");

    int sortMode = 0; // 0=access 1=address 2=name 3=argsCount
    bool detailed = false;
    if (argc >= 2) {
        if (JS_IsBool(argv[1])) {
            detailed = JS_ToBool(ctx, argv[1]) != 0;
        } else if (JS_IsNumber(argv[1])) {
            JS_ToInt32(ctx, &sortMode, argv[1]);
        } else if (JS_IsString(argv[1])) {
            std::string s = ArgString(ctx, argv[1]);
            if (s == "address" || s == "addr") sortMode = 1;
            else if (s == "name") sortMode = 2;
            else if (s == "args" || s == "argc") sortMode = 3;
            else if (s == "detailed") detailed = true;
        }
    }
    if (argc >= 3) detailed = JS_ToBool(ctx, argv[2]) != 0;

    std::lock_guard<std::mutex> lk(g_unityMutex);
    std::string err;
    if (!EnsureInitLocked(&err)) return JS_ThrowInternalError(ctx, "UnityResolve: %s", err.c_str());
    EnsureThreadAttached();

    auto* cls = ResolveClassArg(ctx, argv[0]);
    if (!cls) return JS_NewString(ctx, "[!] m(): class not found");

    std::vector<UnityResolve::Method*> methods = cls->methods;
    switch (sortMode) {
    case 1:
        std::sort(methods.begin(), methods.end(),
                  [](UnityResolve::Method* a, UnityResolve::Method* b) {
                      return reinterpret_cast<uintptr_t>(a->function) <
                             reinterpret_cast<uintptr_t>(b->function);
                  });
        break;
    case 2:
        std::sort(methods.begin(), methods.end(),
                  [](UnityResolve::Method* a, UnityResolve::Method* b) {
                      return a->name < b->name;
                  });
        break;
    case 3:
        std::sort(methods.begin(), methods.end(),
                  [](UnityResolve::Method* a, UnityResolve::Method* b) {
                      return a->args.size() < b->args.size();
                  });
        break;
    default:
        std::stable_sort(methods.begin(), methods.end(),
                         [](UnityResolve::Method* a, UnityResolve::Method* b) {
                             return UnityMethodModifier(a->flags) > UnityMethodModifier(b->flags);
                         });
        break;
    }

    std::string out = "-----------------------------------------------------\n";
    out += "| Found " + std::to_string(methods.size()) + " Methods  in class: " +
           UnityClassFullName(cls) + " @ " + HexStr(reinterpret_cast<uintptr_t>(cls->address)) +
           " |\n";
    out += "-----------------------------------------------------";

    if (detailed) {
        for (auto* m : methods) {
            out += "\n\n[*] " + HexStr(reinterpret_cast<uintptr_t>(m->address)) + " ---> " +
                   (m->function ? HexStr(reinterpret_cast<uintptr_t>(m->function)) : std::string("0x0")) +
                   " ---> " + UnityRvaAtModule(reinterpret_cast<void*>(m->function));
            out += "\n\t" + UnityMethodSignature(m);
            if (m->return_type) {
                out += "\n\t\t---> retval\t" +
                       HexStr(reinterpret_cast<uintptr_t>(m->return_type->address)) +
                       "  <-  " + UnityTypeName(m->return_type);
            }
            for (size_t i = 0; i < m->args.size(); ++i) {
                auto* p = m->args[i];
                auto* t = p ? p->pType : nullptr;
                out += "\n\t\t---> args[" + std::to_string(i) + "]\t" +
                       HexStr(t ? reinterpret_cast<uintptr_t>(t->address) : 0) +
                       "  <-  " + UnityTypeName(t);
                if (p && !p->name.empty()) out += " " + p->name;
            }
        }
    } else {
        std::vector<UnityResolve::Method*> withFn;
        std::vector<UnityResolve::Method*> noFn;
        for (auto* m : methods) (m->function ? withFn : noFn).push_back(m);
        for (auto* m : withFn) {
            out += "\n[*] " + HexStr(reinterpret_cast<uintptr_t>(m->address)) + " ---> " +
                   HexStr(reinterpret_cast<uintptr_t>(m->function)) + " ---> " +
                   UnityRvaAtModule(reinterpret_cast<void*>(m->function)) +
                   "\t|  " + UnityMethodSignature(m);
        }
        for (auto* m : noFn) {
            out += "\n[*] " + HexStr(reinterpret_cast<uintptr_t>(m->address)) +
                   "\t|  " + UnityMethodSignature(m);
        }
    }
    return JS_NewString(ctx, out.c_str());
}

static std::string CurrentPackageName() {
    char buf[256] = {0};
    FILE* fp = fopen("/proc/self/cmdline", "rb");
    if (!fp) return "";
    size_t n = fread(buf, 1, sizeof(buf) - 1, fp);
    fclose(fp);
    std::string s(buf, n);
    size_t nul = s.find('\0');
    if (nul != std::string::npos) s = s.substr(0, nul);
    size_t colon = s.find(':');
    if (colon != std::string::npos) s = s.substr(0, colon);
    return s;
}

// The agent runs as the app UID, so /data/local/tmp is usually not writable.
// Default to the app's own files directory.
static std::string DefaultUnityDumpDir() {
    std::string pkg = CurrentPackageName();
    if (!pkg.empty()) return "/data/user/0/" + pkg + "/files/unity";
    return "/data/local/tmp/unity";
}

static std::string DumpLocked(const std::string& dir) {
    if (mkdir(dir.c_str(), 0777) != 0 && errno != EEXIST) {
        char e[320];
        snprintf(e, sizeof(e), "[!] cannot create %s: %s", dir.c_str(), strerror(errno));
        return e;
    }
    std::string path = dir + "/dump.cs";
    std::ofstream io(path, std::ios::out | std::ios::trunc);
    if (!io) return "[!] cannot open " + path;

    size_t nAsm = 0, nCls = 0, nMeth = 0;
    for (auto* a : UnityResolve::assembly) {
        ++nAsm;
        io << "// Assembly: " << a->name << " (" << a->file << ")\n";
        for (auto* c : a->classes) {
            ++nCls;
            io << "namespace " << c->namespaze << " {\n";
            io << "  class " << c->name;
            if (!c->parent.empty()) io << " : " << c->parent;
            io << " {\n";
            for (auto* f : c->fields) {
                io << "    " << (f->static_field ? "static " : "")
                   << (f->type ? f->type->name : "?") << " " << f->name
                   << "; // offset 0x" << std::hex << f->offset << std::dec << "\n";
            }
            io << "\n";
            for (auto* m : c->methods) {
                ++nMeth;
                io << "    " << (m->static_function ? "static " : "")
                   << (m->return_type ? m->return_type->name : "?") << " " << m->name << "(";
                for (size_t i = 0; i < m->args.size(); ++i) {
                    if (i) io << ", ";
                    io << (m->args[i]->pType ? m->args[i]->pType->name : "?");
                }
                io << "); // 0x" << std::hex << reinterpret_cast<uintptr_t>(m->function) << std::dec << "\n";
            }
            io << "  }\n}\n";
        }
    }
    io.close();

    char buf[256];
    snprintf(buf, sizeof(buf), "[+] dumped %zu assemblies, %zu classes, %zu methods -> %s",
             nAsm, nCls, nMeth, path.c_str());
    return buf;
}

static JSValue JsUnityDump(JSContext* ctx, JSValueConst, int argc, JSValueConst* argv) {
    std::lock_guard<std::mutex> lk(g_unityMutex);
    std::string err;
    if (!EnsureInitLocked(&err)) return JS_ThrowInternalError(ctx, "UnityResolve: %s", err.c_str());
    std::string dir = (argc >= 1 && JS_IsString(argv[0])) ? ArgString(ctx, argv[0]) : std::string();
    if (dir.empty()) dir = DefaultUnityDumpDir();
    return JS_NewString(ctx, DumpLocked(dir).c_str());
}

static JSValue JsUnityThreadAttach(JSContext* ctx, JSValueConst, int, JSValueConst*) {
    std::lock_guard<std::mutex> lk(g_unityMutex);
    std::string err;
    if (!EnsureInitLocked(&err)) return JS_ThrowInternalError(ctx, "UnityResolve: %s", err.c_str());
    if (!t_unityAttached) {
        UnityResolve::ThreadAttach();
        t_unityAttached = true;
    }
    return JS_TRUE;
}

static JSValue JsUnityThreadDetach(JSContext* ctx, JSValueConst, int, JSValueConst*) {
    std::lock_guard<std::mutex> lk(g_unityMutex);
    if (!t_unityAttached) return JS_TRUE;
    UnityResolve::ThreadDetach();
    t_unityAttached = false;
    return JS_TRUE;
}

static JSValue JsUnityString(JSContext* ctx, JSValueConst, int argc, JSValueConst* argv) {
    std::lock_guard<std::mutex> lk(g_unityMutex);
    std::string err;
    if (!EnsureInitLocked(&err)) return JS_ThrowInternalError(ctx, "UnityResolve: %s", err.c_str());
    EnsureThreadAttached();
    if (argc < 1) return JS_NULL;
    return PtrToJs(ctx, UnityResolve::UnityType::String::New(ArgString(ctx, argv[0])));
}

static JSValue JsUnityToString(JSContext* ctx, JSValueConst, int argc, JSValueConst* argv) {
    std::lock_guard<std::mutex> lk(g_unityMutex);
    if (argc < 1) return JS_NULL;
    auto* s = reinterpret_cast<UnityResolve::UnityType::String*>(ArgPtr(ctx, argv[0]));
    return JS_NewString(ctx, UnityStringToUtf8(s).c_str());
}

// Completion provider for dynamic.unity wrappers. The CLI's generic
// __getCompletions(expr) evaluates the expression and asks this helper for the
// dynamic member list (assemblies / classes / fields+methods).
static JSValue JsUnityCompletions(JSContext* ctx, JSValueConst, int argc, JSValueConst* argv) {
    JSValue arr = JS_NewArray(ctx);
    if (argc < 2) return arr;

    std::string kind = ArgString(ctx, argv[0]);
    void* ptr = ArgPtr(ctx, argv[1]);

    uint32_t idx = 0;
    auto add = [&](const std::string& s) {
        JS_SetPropertyUint32(ctx, arr, idx++, JS_NewString(ctx, s.c_str()));
    };

    std::lock_guard<std::mutex> lk(g_unityMutex);
    if (kind == "root") {
        for (const char* h : {"init()", "available()", "isAvailable()", "assemblies()",
                              "assembly(", "class(", "findclass(", "findmethods(",
                              "m(", "dump(", "string(", "toString(",
                              "threadAttach()", "threadDetach()", "help()",
                              "mi(", "b(", "lfs(", "showGameObject(",
                              "button(", "buttons()", "B_Button(",
                              "HookSetActive()", "HookOnPointerClick()",
                              "hooks.", "il2cpp."}) {
            add(h);
        }
        std::string err;
        if (EnsureInitLocked(&err)) {
            for (auto* a : UnityResolve::assembly) {
                add(std::string("assembly(\"") + a->name + "\")");
            }
        }
    } else if (kind == "il2cpp") {
        LoadedModuleInfo mod;
        if (FindLoadedModule("libil2cpp.so", mod) ||
            FindLoadedModule("libil2cpp", mod)) {
            EnumerateModuleSymbols(mod, [&](const char* name, uintptr_t) -> bool {
                add(name);
                return idx < 20000;
            });
        }
    } else if (kind == "assembly") {
        auto* a = reinterpret_cast<UnityResolve::Assembly*>(ptr);
        if (a) {
            for (const char* h : {"name", "file", "classes()", "class(", "get("}) add(h);
            for (auto* c : a->classes) {
                add(std::string("class(\"") + c->name + "\")");
            }
        }
    } else if (kind == "class") {
        auto* c = reinterpret_cast<UnityResolve::Class*>(ptr);
        if (c) {
            for (const char* h : {"name", "namespace", "parent", "address",
                                  "fields()", "methods()", "m()", "field(", "method(",
                                  "new()", "type()", "findObjects()"}) {
                add(h);
            }
            for (auto* f : c->fields) {
                add(std::string("field(\"") + f->name + "\")");
            }
            for (auto* m : c->methods) {
                add(std::string("method(\"") + m->name + "\")");
            }
        }
    }
    return arr;
}

static JSValue JsUnityHelp(JSContext* ctx, JSValueConst, int, JSValueConst*) {
    static const char* kHelp =
        "dynamic.unity (UnityResolve.hpp)\n"
        "  unity.init() / available() / assemblies()\n"
        "  unity.assembly(name)            -> {name, file, classes(), class(name, [ns])}\n"
        "  unity.class(asm, name, [ns])    -> {name, namespace, parent, fields(), methods(), field(), method(), new(), findObjects(), type()}\n"
        "  field.get(inst) / set(inst,v) / getStatic() / setStatic(v)\n"
        "  method.invoke(inst, ...args)    // static methods: invoke(...args)\n"
        "  unity.string(s) / toString(ptr)\n"
        "  unity.dump(path) / threadAttach() / threadDetach()\n"
        "  unity.mi(methodInfoPtr) / mi(methodInfoPtr)  // Assembly>Image>Class>Method hierarchy\n"
        "  unity.hooks.BF('Show', { maxCalls: 10, accurate: false, allImg: true, limit: 200, assembly: '' })\n"
        "  unity.hooks.BFA('ExactName') / hooks.list() / hooks.unhookAll()\n"
        "  unity.b(methodInfoPtr)                 // detailed single-method breakpoint (args + ret)\n"
        "  unity.m(classOrName, [sort], [detailed]) // list methods (TS m()/showMethods)\n"
        "  unity.findclass(pattern, [options])    // wildcard class scan ('*'/'?')\n"
        "  unity.findmethods(pattern, [options])  // wildcard method scan\n"
        "  unity.lfs(instancePtr)                 // list fields + values (class if a Class* is passed)\n"
        "  unity.showGameObject(gameObjectPtr)    // name / layer / transform / hierarchy\n"
        "  unity.HookSetActive()                  // GameObject.SetActive + GameObject info (deduped)\n"
        "  unity.HookOnPointerClick()             // Button.OnPointerClick + GameObject info\n"
        "  unity.B_Button()                       // hook clicks + dump onClick MethodInfo/listeners\n"
        "  unity.button(buttonPtr) / unity.buttons()\n"
        "  unity.il2cpp.<symbol>                  // NativeBox for any libil2cpp.so export\n"
        "  unity.il2cpp.                          // Tab: all exported il2cpp symbols\n"
        "Notes: lazy-init; requires libil2cpp.so to be loaded; invokes via il2cpp_runtime_invoke.\n"
        "D()/detach() also detaches every Unity hook.";
    return JS_NewString(ctx, kHelp);
}

// ---------------------------------------------------------------------------
// mi(): MethodInfo -> Assembly / Image / Class / Method hierarchy.
// Mirrors Il2CppHookScripts' `mi(0x...)` display.
// ---------------------------------------------------------------------------
static JSValue JsUnityMi(JSContext* ctx, JSValueConst, int argc, JSValueConst* argv) {
    if (argc < 1) return JS_ThrowTypeError(ctx, "mi(methodInfoPtr)");
    uintptr_t target = reinterpret_cast<uintptr_t>(ArgPtr(ctx, argv[0]));
    if (!target) return JS_ThrowTypeError(ctx, "mi(): invalid MethodInfo pointer");

    std::lock_guard<std::mutex> lk(g_unityMutex);
    std::string err;
    if (!EnsureInitLocked(&err)) return JS_ThrowInternalError(ctx, "UnityResolve: %s", err.c_str());

    UnityResolve::Method* method = nullptr;
    UnityResolve::Class* klass = nullptr;
    UnityResolve::Assembly* owner = nullptr;
    for (auto* a : UnityResolve::assembly) {
        for (auto* c : a->classes) {
            for (auto* m : c->methods) {
                if (reinterpret_cast<uintptr_t>(m->address) == target) {
                    method = m;
                    klass = c;
                    owner = a;
                    break;
                }
            }
            if (method) break;
        }
        if (method) break;
    }
    if (!method) {
        return JS_NewString(ctx, (std::string("[!] MethodInfo not found: ") + HexStr(target)).c_str());
    }

    std::string asmName = owner ? owner->name : "?";
    if (asmName.size() > 4 && asmName.compare(asmName.size() - 4, 4, ".dll") == 0) {
        asmName.resize(asmName.size() - 4);
    }
    uintptr_t asmAddr = owner ? reinterpret_cast<uintptr_t>(owner->address) : 0;
    std::string asmFile = owner ? owner->file : "?";

    uintptr_t rva = 0;
    if (method->function) {
        Dl_info di{};
        if (dladdr(reinterpret_cast<void*>(method->function), &di) && di.dli_fbase) {
            rva = reinterpret_cast<uintptr_t>(method->function) -
                  reinterpret_cast<uintptr_t>(di.dli_fbase);
        }
    }

    std::string out;
    out += "[-]" + asmName + " @ " + HexStr(asmAddr) + "\n";
    out += "  [-]" + asmFile + " @ " + HexStr(asmAddr) +
           " | C:" + std::to_string(owner ? owner->classes.size() : 0) + "\n";
    out += "    [-]" + (klass ? klass->name : std::string("?")) +
           " @ " + HexStr(klass ? reinterpret_cast<uintptr_t>(klass->address) : 0) +
           " | M:" + std::to_string(klass ? klass->methods.size() : 0) +
           " | F:" + std::to_string(klass ? klass->fields.size() : 0) +
           " | N:" + (klass ? klass->namespaze : std::string("")) + "\n";
    out += "      [-]" + UnityMethodSignature(method) +
           " @ MI: " + HexStr(reinterpret_cast<uintptr_t>(method->address)) +
           " & MP: " + (method->function ? HexStr(reinterpret_cast<uintptr_t>(method->function)) : std::string("null")) +
           " & RP: " + (method->function ? HexStr(rva) : std::string("?"));
    return JS_NewString(ctx, out.c_str());
}

// ---------------------------------------------------------------------------
// dynamic.unity.hooks.BF(): batch inline hooks by method name (TS BF port).
// ---------------------------------------------------------------------------
struct BfHookRecord {
    UnityResolve::Method* method = nullptr;
    UnityResolve::Class* klass = nullptr;
    PI::Native::NativeHookHandle handle;
    std::string signature;
    std::string class_name;
    int max_calls = 10;
    int calls = 0;
    bool detailed = false;
};

struct BfInvocation {
    std::string* text = nullptr;
    bool show = false;
};

static std::mutex g_bfMutex;
static std::vector<std::shared_ptr<BfHookRecord>> g_bfHooks;

static std::string BfFormatFloat(float f) {
    char b[48];
    snprintf(b, sizeof(b), "%g", f);
    return b;
}

static std::string BfFormatDouble(double d) {
    char b[64];
    snprintf(b, sizeof(b), "%g", d);
    return b;
}

static std::string BfTruncate(std::string s, size_t maxLen = 64) {
    for (char& c : s) {
        if (c == '\n' || c == '\r' || c == '\t') c = ' ';
    }
    if (s.size() > maxLen) s = s.substr(0, maxLen) + "...";
    return s;
}

static std::string BfFormatArg(const UnityResolve::Type* t, GumCpuContext* cpu,
                               int& gpr, int& fpr) {
    if (!t) return "?";
    const std::string n = t->name;

    auto hfa = [&](int count) -> std::string {
        std::string s = "(";
        for (int k = 0; k < count; ++k) {
            if (k) s += ", ";
            s += BfFormatFloat((cpu && fpr + k < 32) ? cpu->v[fpr + k].s : 0.0f);
        }
        s += ")";
        fpr += count;
        return s;
    };

    if (n == "System.Single") {
        float v = (cpu && fpr < 32) ? cpu->v[fpr].s : 0.0f;
        fpr++;
        return BfFormatFloat(v);
    }
    if (n == "System.Double") {
        double v = (cpu && fpr < 32) ? cpu->v[fpr].d : 0.0;
        fpr++;
        return BfFormatDouble(v);
    }
    if (n == "UnityEngine.Vector2") return hfa(2);
    if (n == "UnityEngine.Vector3") return hfa(3);
    if (n == "UnityEngine.Vector4" || n == "UnityEngine.Quaternion" || n == "UnityEngine.Color") {
        return hfa(4);
    }

    uint64_t raw = (cpu && gpr < 8) ? cpu->x[gpr] : 0;
    gpr++;

    if (n == "System.Boolean") return (raw & 1) ? "true" : "false";
    if (n == "System.String") {
        if (raw < 0x1000) return "\"\"";
        auto* s = reinterpret_cast<UnityResolve::UnityType::String*>(static_cast<uintptr_t>(raw));
        return "\"" + BfTruncate(UnityStringToUtf8(s)) + "\"";
    }
    if (n == "System.Int64" || n == "System.UInt64" ||
        n == "System.IntPtr" || n == "System.UIntPtr") {
        return std::to_string(static_cast<long long>(raw));
    }
    if (t->size > 0 && t->size <= 4) {
        return std::to_string(static_cast<int>(static_cast<intptr_t>(raw)));
    }
    if (n.rfind("System.", 0) == 0) {
        return std::to_string(static_cast<int>(static_cast<intptr_t>(raw)));
    }
    return HexStr(static_cast<uintptr_t>(raw));
}

static std::string BfFormatReturn(const UnityResolve::Type* t, GumCpuContext* cpu,
                                  uint64_t raw) {
    if (!t || t->name == "System.Void") return "";
    const std::string n = t->name;

    if (n == "System.Single") return BfFormatFloat(cpu ? cpu->v[0].s : 0.0f);
    if (n == "System.Double") return BfFormatDouble(cpu ? cpu->v[0].d : 0.0);
    if (n == "UnityEngine.Vector2" || n == "UnityEngine.Vector3" ||
        n == "UnityEngine.Vector4" || n == "UnityEngine.Quaternion" ||
        n == "UnityEngine.Color") {
        int count = (n == "UnityEngine.Vector2") ? 2 : (n == "UnityEngine.Vector3") ? 3 : 4;
        std::string s = "(";
        for (int k = 0; k < count; ++k) {
            if (k) s += ", ";
            s += BfFormatFloat(cpu ? cpu->v[k].s : 0.0f);
        }
        s += ")";
        return s;
    }
    if (n == "System.Boolean") return (raw & 1) ? "true" : "false";
    if (n == "System.String") {
        if (raw < 0x1000) return "\"\"";
        auto* s = reinterpret_cast<UnityResolve::UnityType::String*>(static_cast<uintptr_t>(raw));
        return "\"" + BfTruncate(UnityStringToUtf8(s)) + "\"";
    }
    if (t->size > 0 && t->size <= 4) {
        return std::to_string(static_cast<int>(static_cast<intptr_t>(raw)));
    }
    if (n.rfind("System.", 0) == 0) {
        return std::to_string(static_cast<int>(static_cast<intptr_t>(raw)));
    }
    return HexStr(static_cast<uintptr_t>(raw));
}

static void BfOnEnter(const std::shared_ptr<BfHookRecord>& rec, GumInvocationContext* ictx) {
    auto* data = static_cast<BfInvocation*>(
        gum_invocation_context_get_listener_invocation_data(ictx, sizeof(BfInvocation)));
    if (!data) return;
    data->text = nullptr;
    data->show = false;

    int calls = 0;
    {
        std::lock_guard<std::mutex> lk(g_bfMutex);
        calls = ++rec->calls;
    }
    if (calls > rec->max_calls) return;
    data->show = true;

    GumCpuContext* cpu = ictx->cpu_context;
    int gpr = (rec->method && rec->method->static_function) ? 0 : 1;
    int fpr = 0;

    if (rec->detailed) {
        uintptr_t mi = reinterpret_cast<uintptr_t>(rec->method ? rec->method->address : nullptr);
        uintptr_t mp = reinterpret_cast<uintptr_t>(rec->method ? rec->method->function : nullptr);
        uintptr_t rp = 0;
        if (mp) {
            Dl_info di{};
            if (dladdr(reinterpret_cast<void*>(mp), &di) && di.dli_fbase) {
                rp = mp - reinterpret_cast<uintptr_t>(di.dli_fbase);
            }
        }

        std::string line;
        line += rec->class_name + " | " + rec->signature +
                "    [ " + HexStr(mi) + " -> " + HexStr(mp) + " -> " + HexStr(rp) +
                " ] | " + TimeNow() + "\n";
        line += "-------------------------------------------------------\n";
        if (rec->method && !rec->method->static_function) {
            line += "  inst  |   " + HexStr(cpu ? static_cast<uintptr_t>(cpu->x[0]) : 0) +
                    "    [ " + rec->class_name + " ] ( " +
                    HexStr(rec->klass ? reinterpret_cast<uintptr_t>(rec->klass->address) : 0) + " )\n";
        }
        if (rec->method) {
            for (size_t i = 0; i < rec->method->args.size(); ++i) {
                auto* arg = rec->method->args[i];
                auto* t = arg ? arg->pType : nullptr;
                line += "  arg" + std::to_string(i) + "  |   " +
                        BfFormatArg(t, cpu, gpr, fpr) +
                        "    " + UnityTypeName(t) +
                        " ( " + HexStr(t ? reinterpret_cast<uintptr_t>(t->address) : 0) + " )";
                if (arg && !arg->name.empty()) line += "  // " + arg->name;
                line += "\n";
            }
        }
        data->text = new std::string(std::move(line));
        return;
    }

    std::string line = rec->class_name + "::" +
                       (rec->method ? rec->method->name : std::string("?")) + "(";
    bool first = true;

    if (rec->method && !rec->method->static_function) {
        line += "this=" + HexStr(cpu ? static_cast<uintptr_t>(cpu->x[0]) : 0);
        first = false;
    }
    if (rec->method) {
        for (size_t i = 0; i < rec->method->args.size(); ++i) {
            if (!first) line += ", ";
            first = false;
            line += BfFormatArg(rec->method->args[i] ? rec->method->args[i]->pType : nullptr,
                                cpu, gpr, fpr);
        }
    }
    line += ")";
    data->text = new std::string(std::move(line));
}

static void BfOnLeave(const std::shared_ptr<BfHookRecord>& rec, GumInvocationContext* ictx) {
    auto* data = static_cast<BfInvocation*>(
        gum_invocation_context_get_listener_invocation_data(ictx, sizeof(BfInvocation)));
    if (!data) return;

    if (data->show && data->text) {
        const void* ret = gum_invocation_context_get_return_value(ictx);
        uint64_t raw = static_cast<uint64_t>(reinterpret_cast<uintptr_t>(ret));
        auto* rt = rec->method ? rec->method->return_type : nullptr;
        if (rec->detailed) {
            std::string out = *data->text;
            out += "  ret   |   " + HexStr(static_cast<uintptr_t>(raw)) +
                   "    " + UnityTypeName(rt) +
                   " ( " + HexStr(rt ? reinterpret_cast<uintptr_t>(rt->address) : 0) + " )";
            std::string retResolved = BfFormatReturn(rt, ictx->cpu_context, raw);
            if (!retResolved.empty()) out += "  ->  " + retResolved;
            out += "\n-------------------------------------------------------";
            BroadcastLog("hook", out);
            __android_log_print(ANDROID_LOG_INFO, "ArtPI_Unity", "%s", out.c_str());
        } else {
            std::string retStr = BfFormatReturn(rt, ictx->cpu_context, raw);
            std::string line = "[BP] " + *data->text;
            if (!retStr.empty()) line += " -> " + retStr;
            BroadcastLog("hook", line);
            __android_log_print(ANDROID_LOG_INFO, "ArtPI_Unity", "%s", line.c_str());
        }
    }
    delete data->text;
    data->text = nullptr;
    data->show = false;
}

static void BfClearLocked() {
    for (auto& r : g_bfHooks) {
        if (r->handle.isValid()) r->handle.unhook();
    }
    g_bfHooks.clear();
}

static bool BfHookOne(UnityResolve::Method* method, UnityResolve::Class* klass,
                      int maxCalls, bool detailed) {
    if (!method || !method->function) return false;

    auto rec = std::make_shared<BfHookRecord>();
    rec->method = method;
    rec->klass = klass;
    rec->signature = UnityMethodSignature(method);
    rec->class_name = UnityClassFullName(klass);
    rec->max_calls = maxCalls;
    rec->detailed = detailed;

    auto handle = PI::Native::GumHooker::hook(
        reinterpret_cast<void*>(method->function),
        [rec](GumInvocationContext* ictx) { BfOnEnter(rec, ictx); },
        [rec](GumInvocationContext* ictx) { BfOnLeave(rec, ictx); });
    if (!handle.isValid()) {
        BroadcastLog("hook", "[!] add BP failed | " + UnityMethodSummary(method));
        return false;
    }
    rec->handle = std::move(handle);
    {
        std::lock_guard<std::mutex> lk(g_bfMutex);
        g_bfHooks.push_back(rec);
    }
    BroadcastLog("hook", "[+] add BP ( method ) |  " + UnityMethodSummary(method));
    return true;
}

static JSValue JsUnityBFImpl(JSContext* ctx, const std::string& filter, int maxCalls, int limit,
                             bool accurate, bool allImg, const std::string& assemblyFilter) {
    {
        std::lock_guard<std::mutex> lk(g_bfMutex);
        BfClearLocked();
    }

    std::lock_guard<std::mutex> lk(g_unityMutex);
    std::string err;
    if (!EnsureInitLocked(&err)) return JS_ThrowInternalError(ctx, "UnityResolve: %s", err.c_str());

    struct Candidate {
        UnityResolve::Method* method;
        UnityResolve::Class* klass;
    };
    std::vector<Candidate> candidates;

    for (auto* a : UnityResolve::assembly) {
        if (!allImg && a->name != "Assembly-CSharp.dll") continue;
        if (!assemblyFilter.empty() && a->name.find(assemblyFilter) == std::string::npos) continue;
        for (auto* c : a->classes) {
            for (auto* m : c->methods) {
                if (!m->function) continue;
                if (m->flags & 0x0400) continue; // abstract
                bool match = accurate ? (m->name == filter)
                                      : (m->name.find(filter) != std::string::npos);
                if (!match) continue;
                candidates.push_back({ m, c });
                if (candidates.size() >= static_cast<size_t>(limit)) break;
            }
            if (candidates.size() >= static_cast<size_t>(limit)) break;
        }
        if (candidates.size() >= static_cast<size_t>(limit)) break;
    }

    size_t hooked = 0;
    size_t failed = 0;
    for (auto& cand : candidates) {
        if (BfHookOne(cand.method, cand.klass, maxCalls, false)) {
            ++hooked;
        } else {
            ++failed;
        }
    }

    char buf[320];
    snprintf(buf, sizeof(buf),
             "[+] BF(\"%s\"): %zu method(s) hooked, %zu failed (maxCalls=%d, limit=%d)",
             filter.c_str(), hooked, failed, maxCalls, limit);
    return JS_NewString(ctx, buf);
}

static JSValue JsUnityBF(JSContext* ctx, JSValueConst, int argc, JSValueConst* argv) {
    if (argc < 1) return JS_ThrowTypeError(ctx, "hooks.BF(filter, [options])");
    std::string filter = ArgString(ctx, argv[0]);
    int maxCalls = 10;
    int limit = 200;
    bool accurate = false;
    bool allImg = true;
    std::string assemblyFilter;

    if (argc >= 2) {
        if (JS_IsObject(argv[1])) {
            JSValue v = JS_GetPropertyStr(ctx, argv[1], "maxCalls");
            if (JS_IsNumber(v)) JS_ToInt32(ctx, &maxCalls, v);
            JS_FreeValue(ctx, v);

            v = JS_GetPropertyStr(ctx, argv[1], "limit");
            if (JS_IsNumber(v)) JS_ToInt32(ctx, &limit, v);
            JS_FreeValue(ctx, v);

            v = JS_GetPropertyStr(ctx, argv[1], "accurate");
            if (!JS_IsUndefined(v)) accurate = JS_ToBool(ctx, v) != 0;
            JS_FreeValue(ctx, v);

            v = JS_GetPropertyStr(ctx, argv[1], "allImg");
            if (!JS_IsUndefined(v)) allImg = JS_ToBool(ctx, v) != 0;
            JS_FreeValue(ctx, v);

            v = JS_GetPropertyStr(ctx, argv[1], "assembly");
            if (JS_IsString(v)) assemblyFilter = ArgString(ctx, v);
            JS_FreeValue(ctx, v);
        } else {
            allImg = JS_ToBool(ctx, argv[1]) != 0;
            if (argc >= 3) accurate = JS_ToBool(ctx, argv[2]) != 0;
        }
    }

    if (maxCalls < 1) maxCalls = 1;
    if (maxCalls > 100000) maxCalls = 100000;
    if (limit < 1) limit = 1;
    if (limit > 1000) limit = 1000;
    return JsUnityBFImpl(ctx, filter, maxCalls, limit, accurate, allImg, assemblyFilter);
}

static JSValue JsUnityBFA(JSContext* ctx, JSValueConst, int argc, JSValueConst* argv) {
    if (argc < 1) return JS_ThrowTypeError(ctx, "hooks.BFA(filter)");
    return JsUnityBFImpl(ctx, ArgString(ctx, argv[0]), 10, 200, true, true, "");
}

static JSValue JsUnityHooksList(JSContext* ctx, JSValueConst, int, JSValueConst*) {
    std::lock_guard<std::mutex> lk(g_bfMutex);
    std::string out = "BF hooks (" + std::to_string(g_bfHooks.size()) + "):";
    for (size_t i = 0; i < g_bfHooks.size(); ++i) {
        auto& r = g_bfHooks[i];
        out += "\n  [" + std::to_string(i) + "] calls=" + std::to_string(r->calls) +
               "/" + std::to_string(r->max_calls) + " | " + UnityMethodSummary(r->method);
    }
    return JS_NewString(ctx, out.c_str());
}

static JSValue JsUnityHooksUnhookAll(JSContext* ctx, JSValueConst, int, JSValueConst*) {
    size_t n = UnityDetachAll();
    char buf[96];
    snprintf(buf, sizeof(buf), "Detached %zu Unity hook(s)", n);
    return JS_NewString(ctx, buf);
}

// ---------------------------------------------------------------------------
// b(methodInfoPtr): detailed single-method breakpoint (TS b()).
// ---------------------------------------------------------------------------
static JSValue JsUnityB(JSContext* ctx, JSValueConst, int argc, JSValueConst* argv) {
    if (argc < 1) return JS_ThrowTypeError(ctx, "b(methodInfoPtr, [maxCalls])");
    uintptr_t target = reinterpret_cast<uintptr_t>(ArgPtr(ctx, argv[0]));
    int maxCalls = 10;
    if (argc >= 2 && JS_IsNumber(argv[1])) {
        JS_ToInt32(ctx, &maxCalls, argv[1]);
    }
    if (maxCalls < 1) maxCalls = 1;
    if (maxCalls > 100000) maxCalls = 100000;

    std::lock_guard<std::mutex> lk(g_unityMutex);
    std::string err;
    if (!EnsureInitLocked(&err)) return JS_ThrowInternalError(ctx, "UnityResolve: %s", err.c_str());

    UnityResolve::Method* method = nullptr;
    UnityResolve::Class* klass = nullptr;
    for (auto* a : UnityResolve::assembly) {
        for (auto* c : a->classes) {
            for (auto* m : c->methods) {
                if (reinterpret_cast<uintptr_t>(m->address) == target) {
                    method = m;
                    klass = c;
                    break;
                }
            }
            if (method) break;
        }
        if (method) break;
    }
    if (!method) {
        return JS_NewString(ctx, (std::string("[!] MethodInfo not found: ") + HexStr(target)).c_str());
    }
    if (!BfHookOne(method, klass, maxCalls, true)) {
        return JS_NewString(ctx, "[!] b(): failed to attach");
    }
    return JS_NewString(ctx, ("[+] b(): " + UnityMethodSignature(method)).c_str());
}

// ---------------------------------------------------------------------------
// showGameObject(ptr)
// ---------------------------------------------------------------------------
static JSValue JsUnityShowGameObject(JSContext* ctx, JSValueConst, int argc, JSValueConst* argv) {
    if (argc < 1) return JS_ThrowTypeError(ctx, "showGameObject(gameObjectPtr)");
    void* go = ArgPtr(ctx, argv[0]);
    std::lock_guard<std::mutex> lk(g_unityMutex);
    std::string err;
    if (!EnsureInitLocked(&err)) return JS_ThrowInternalError(ctx, "UnityResolve: %s", err.c_str());
    EnsureThreadAttached();
    return JS_NewString(ctx, FormatGameObject(go).c_str());
}

// ---------------------------------------------------------------------------
// HookSetActive(): GameObject.SetActive(bool) + GameObject info, deduped.
// ---------------------------------------------------------------------------
struct SetActiveSeen {
    int count = 0;
    bool last = false;
};

static std::mutex g_setActiveMutex;
static PI::Native::NativeHookHandle g_setActiveHook;
static std::unordered_map<uintptr_t, SetActiveSeen> g_setActiveSeen;
static int g_setActiveLogs = 0;

static void SetActiveOnEnter(UnityResolve::Method* m, GumInvocationContext* ictx) {
    GumCpuContext* cpu = ictx->cpu_context;
    void* go = reinterpret_cast<void*>(static_cast<uintptr_t>(cpu ? cpu->x[0] : 0));
    bool value = cpu && ((cpu->x[1] & 1) != 0);

    {
        std::lock_guard<std::mutex> lk(g_setActiveMutex);
        if (g_setActiveLogs >= 50) return;
        auto& st = g_setActiveSeen[reinterpret_cast<uintptr_t>(go)];
        if (st.count > 0 && st.last == value) return; // same object + same state
        st.count++;
        st.last = value;
        g_setActiveLogs++;
    }

    uintptr_t lr = cpu ? static_cast<uintptr_t>(cpu->lr) : 0;
    uintptr_t rva = 0;
    std::string mod = "?";
    if (lr) {
        Dl_info di{};
        if (dladdr(reinterpret_cast<void*>(lr), &di) && di.dli_fbase) {
            rva = lr - reinterpret_cast<uintptr_t>(di.dli_fbase);
            mod = BaseName(di.dli_fname);
        }
    }

    std::string ret = UnityShortTypeName(UnityTypeName(m ? m->return_type : nullptr));
    if (ret == "Void") ret = "void";

    std::string line;
    line += "---------------------------------------------------------------\n";
    line += UnityMethodModifier(m ? m->flags : 0) + ret + " SetActive( " +
            (value ? "true" : "false") + " );  LR:" + HexStr(rva) + "|" + mod + "\n";
    line += FormatGameObject(go);
    BroadcastLog("hook", line);
    __android_log_print(ANDROID_LOG_INFO, "ArtPI_Unity", "%s", line.c_str());
}

static JSValue JsUnityHookSetActive(JSContext* ctx, JSValueConst, int, JSValueConst*) {
    std::lock_guard<std::mutex> lk(g_unityMutex);
    std::string err;
    if (!EnsureInitLocked(&err)) return JS_ThrowInternalError(ctx, "UnityResolve: %s", err.c_str());
    EnsureThreadAttached();

    auto* core = UnityResolve::Get("UnityEngine.CoreModule.dll");
    auto* goCls = core ? core->Get("GameObject") : nullptr;
    auto* m = goCls ? goCls->Get<UnityResolve::Method>("SetActive") : nullptr;
    if (!m || !m->function) return JS_NewString(ctx, "[!] GameObject.SetActive not found");

    {
        std::lock_guard<std::mutex> blk(g_setActiveMutex);
        if (g_setActiveHook.isValid()) g_setActiveHook.unhook();
        g_setActiveSeen.clear();
        g_setActiveLogs = 0;
    }
    g_setActiveHook = PI::Native::GumHooker::hook(
        reinterpret_cast<void*>(m->function),
        [m](GumInvocationContext* ictx) { SetActiveOnEnter(m, ictx); });
    if (!g_setActiveHook.isValid()) return JS_NewString(ctx, "[!] HookSetActive: failed to attach");

    uintptr_t rva = 0;
    Dl_info di{};
    if (dladdr(reinterpret_cast<void*>(m->function), &di) && di.dli_fbase) {
        rva = reinterpret_cast<uintptr_t>(m->function) - reinterpret_cast<uintptr_t>(di.dli_fbase);
    }
    char buf[160];
    snprintf(buf, sizeof(buf), "Enabled Hook GameObject.SetActive at 0x%lx (0x%lx)",
             (unsigned long) reinterpret_cast<uintptr_t>(m->function), (unsigned long) rva);
    return JS_NewString(ctx, buf);
}

// ---------------------------------------------------------------------------
// HookOnPointerClick(): UnityEngine.UI.Button.OnPointerClick + GameObject info.
// ---------------------------------------------------------------------------
static std::mutex g_onClickMutex;
static PI::Native::NativeHookHandle g_onClickHook;
static int g_onClickCalls = 0;
static int g_onClickMax = 50;

static void OnPointerClickOnEnter(UnityResolve::Method* m, GumInvocationContext* ictx) {
    {
        std::lock_guard<std::mutex> lk(g_onClickMutex);
        if (++g_onClickCalls > g_onClickMax) return;
    }
    GumCpuContext* cpu = ictx->cpu_context;
    void* button = reinterpret_cast<void*>(static_cast<uintptr_t>(cpu ? cpu->x[0] : 0));
    void* event = reinterpret_cast<void*>(static_cast<uintptr_t>(cpu ? cpu->x[1] : 0));
    void* go = ComponentGameObject(button);

    std::string line;
    line += "--------------------------------------\n";
    line += "public void Button::OnPointerClick( " + HexStr(reinterpret_cast<uintptr_t>(button)) +
            " , " + HexStr(reinterpret_cast<uintptr_t>(event)) + " )\n";
    line += FormatGameObject(go);
    BroadcastLog("hook", line);
    __android_log_print(ANDROID_LOG_INFO, "ArtPI_Unity", "%s", line.c_str());
    (void) m;
}

static JSValue JsUnityHookOnPointerClick(JSContext* ctx, JSValueConst, int, JSValueConst*) {
    std::lock_guard<std::mutex> lk(g_unityMutex);
    std::string err;
    if (!EnsureInitLocked(&err)) return JS_ThrowInternalError(ctx, "UnityResolve: %s", err.c_str());
    EnsureThreadAttached();

    auto* ui = UnityResolve::Get("UnityEngine.UI.dll");
    auto* buttonCls = ui ? ui->Get("Button") : nullptr;
    auto* m = buttonCls ? buttonCls->Get<UnityResolve::Method>("OnPointerClick") : nullptr;
    if (!m || !m->function) return JS_NewString(ctx, "[!] UnityEngine.UI.Button.OnPointerClick not found");

    {
        std::lock_guard<std::mutex> blk(g_onClickMutex);
        if (g_onClickHook.isValid()) g_onClickHook.unhook();
        g_onClickCalls = 0;
    }
    g_onClickHook = PI::Native::GumHooker::hook(
        reinterpret_cast<void*>(m->function),
        [m](GumInvocationContext* ictx) { OnPointerClickOnEnter(m, ictx); });
    if (!g_onClickHook.isValid()) return JS_NewString(ctx, "[!] HookOnPointerClick: failed to attach");

    uintptr_t rva = 0;
    Dl_info di{};
    if (dladdr(reinterpret_cast<void*>(m->function), &di) && di.dli_fbase) {
        rva = reinterpret_cast<uintptr_t>(m->function) - reinterpret_cast<uintptr_t>(di.dli_fbase);
    }
    char buf[160];
    snprintf(buf, sizeof(buf), "Enable Hook Button OnPointerClick at 0x%lx(0x%lx)",
             (unsigned long) reinterpret_cast<uintptr_t>(m->function), (unsigned long) rva);
    return JS_NewString(ctx, buf);
}

// ---------------------------------------------------------------------------
// B_Button(): hook Button.OnPointerClick (+ UIButton.OnClick) and print the
// clicked button, GameObject and its onClick listener methods.
// Mirrors Il2CppHookScripts' OnButtonClick().
// ---------------------------------------------------------------------------
static void AppendButtonListeners(void* button, std::string& out);
static void AppendEventDelegateList(void* list, std::string& out);

static std::mutex g_bButtonMutex;
static PI::Native::NativeHookHandle g_bButtonHook;
static PI::Native::NativeHookHandle g_bButtonNguiHook;
static int g_bButtonCalls = 0;
static int g_bButtonMax = 50;

static bool BButtonShouldLog() {
    std::lock_guard<std::mutex> lk(g_bButtonMutex);
    if (g_bButtonCalls >= g_bButtonMax) return false;
    ++g_bButtonCalls;
    return true;
}

static void BButtonEmit(const std::string& out) {
    BroadcastLog("hook", out);
    __android_log_print(ANDROID_LOG_INFO, "ArtPI_Unity", "%s", out.c_str());
}

static void BButtonOnPointerClick(UnityResolve::Method* m, GumInvocationContext* ictx) {
    if (!BButtonShouldLog()) return;
    GumCpuContext* cpu = ictx->cpu_context;
    void* button = reinterpret_cast<void*>(static_cast<uintptr_t>(cpu ? cpu->x[0] : 0));
    void* event = reinterpret_cast<void*>(static_cast<uintptr_t>(cpu ? cpu->x[1] : 0));

    void* go = ComponentGameObject(button);
    auto* core = UnityResolve::Get("UnityEngine.CoreModule.dll");
    auto* objCls = core ? core->Get("Object") : nullptr;
    auto* goCls = core ? core->Get("GameObject") : nullptr;
    std::string name = InvokeStringMethod(objCls, "get_name", go);
    void* tr = InvokePtrMethod(goCls, "get_transform", go);

    std::string out;
    out += "--------------------------------------\n";
    out += "public void Button::OnPointerClick( " +
           HexStr(reinterpret_cast<uintptr_t>(button)) + " , " +
           HexStr(reinterpret_cast<uintptr_t>(event)) + " )\n";
    if (m) out += "  hook: " + UnityMethodSummary(m) + "\n";
    out += "[*] " + HexStr(reinterpret_cast<uintptr_t>(button)) + " ---> " +
           (name.empty() ? std::string("(unnamed)") : name) +
           " { G:" + HexStr(reinterpret_cast<uintptr_t>(go)) +
           " | T:" + HexStr(reinterpret_cast<uintptr_t>(tr)) + " }";
    AppendButtonListeners(button, out);
    BButtonEmit(out);
}

static void BButtonOnNguiClick(UnityResolve::Method* m, GumInvocationContext* ictx) {
    if (!BButtonShouldLog()) return;
    GumCpuContext* cpu = ictx->cpu_context;
    void* instance = reinterpret_cast<void*>(static_cast<uintptr_t>(cpu ? cpu->x[0] : 0));
    if (!instance) return;

    void* go = ComponentGameObject(instance);
    auto* core = UnityResolve::Get("UnityEngine.CoreModule.dll");
    auto* objCls = core ? core->Get("Object") : nullptr;
    auto* goCls = core ? core->Get("GameObject") : nullptr;
    std::string name = InvokeStringMethod(objCls, "get_name", go);
    void* tr = InvokePtrMethod(goCls, "get_transform", go);

    void* cls = UnityObjectClassOf(instance);
    int32_t onClickOffset = UnityFieldOffsetOf(
        UnityClassFieldByName(cls, "onClick"));

    std::string out;
    out += "--------------------------------------\n";
    out += "public void UIButton::OnClick( " +
           HexStr(reinterpret_cast<uintptr_t>(instance)) + " )\n";
    if (m) out += "  hook: " + UnityMethodSummary(m) + "\n";
    out += "[*] " + HexStr(reinterpret_cast<uintptr_t>(instance)) + " ---> " +
           (name.empty() ? std::string("(unnamed)") : name) +
           " { G:" + HexStr(reinterpret_cast<uintptr_t>(go)) +
           " | T:" + HexStr(reinterpret_cast<uintptr_t>(tr)) + " }";
    AppendEventDelegateList(ReadPtrAt(instance, onClickOffset), out);
    BButtonEmit(out);
}

static JSValue JsUnityBButton(JSContext* ctx, JSValueConst, int argc, JSValueConst* argv) {
    std::lock_guard<std::mutex> lk(g_unityMutex);
    std::string err;
    if (!EnsureInitLocked(&err)) return JS_ThrowInternalError(ctx, "UnityResolve: %s", err.c_str());
    EnsureThreadAttached();

    void* customTarget = nullptr;
    UnityResolve::Method* customMethod = nullptr;
    UnityResolve::Class* customClass = nullptr;
    if (argc >= 1) {
        customTarget = ArgPtr(ctx, argv[0]);
    }

    auto* ui = UnityResolve::Get("UnityEngine.UI.dll");
    auto* buttonCls = ui ? ui->Get("Button") : nullptr;
    auto* method = buttonCls ? buttonCls->Get<UnityResolve::Method>("OnPointerClick") : nullptr;
    if (!method || !method->function) {
        return JS_NewString(ctx, "[!] UnityEngine.UI.Button.OnPointerClick not found");
    }

    if (customTarget) {
        // Accept either a MethodInfo* (preferred) or a native function address.
        for (auto* a : UnityResolve::assembly) {
            for (auto* c : a->classes) {
                for (auto* m : c->methods) {
                    if (reinterpret_cast<void*>(m->address) == customTarget ||
                        reinterpret_cast<void*>(m->function) == customTarget) {
                        customMethod = m;
                        customClass = c;
                        break;
                    }
                }
                if (customMethod) break;
            }
            if (customMethod) break;
        }
        if (customMethod) {
            method = customMethod;
            buttonCls = customClass;
        } else {
            // Raw function address: hook it, but the listener dump uses x0 as Button*.
            method = nullptr;
        }
    }

    {
        std::lock_guard<std::mutex> blk(g_bButtonMutex);
        if (g_bButtonHook.isValid()) g_bButtonHook.unhook();
        if (g_bButtonNguiHook.isValid()) g_bButtonNguiHook.unhook();
        g_bButtonCalls = 0;
    }

    void* target = nullptr;
    if (customMethod && customMethod->function) {
        target = reinterpret_cast<void*>(customMethod->function);
    } else if (customTarget) {
        target = customTarget;
    } else if (method) {
        target = reinterpret_cast<void*>(method->function);
    }
    if (!target) return JS_NewString(ctx, "[!] B_Button: invalid target");

    g_bButtonHook = PI::Native::GumHooker::hook(
        target, [method](GumInvocationContext* ictx) { BButtonOnPointerClick(method, ictx); });
    if (!g_bButtonHook.isValid()) return JS_NewString(ctx, "[!] B_Button: failed to attach");

    std::string out = "Enabled Hook Button OnPointerClick at " +
                      HexStr(reinterpret_cast<uintptr_t>(target)) +
                      "(" + UnityRvaAtModule(target) + ")";
    if (method) {
        out += "\n  MethodInfo: " +
               HexStr(reinterpret_cast<uintptr_t>(method->address)) +
               " | " + UnityMethodSummary(method);
    }

    if (!customTarget) {
        auto* asmCs = UnityResolve::Get("Assembly-CSharp.dll");
        auto* nguiCls = asmCs ? asmCs->Get("UIButton") : nullptr;
        auto* nguiOnClick = nguiCls ? nguiCls->Get<UnityResolve::Method>("OnClick") : nullptr;
        if (nguiOnClick && nguiOnClick->function) {
            g_bButtonNguiHook = PI::Native::GumHooker::hook(
                reinterpret_cast<void*>(nguiOnClick->function),
                [nguiOnClick](GumInvocationContext* ictx) {
                    BButtonOnNguiClick(nguiOnClick, ictx);
                });
            if (g_bButtonNguiHook.isValid()) {
                out += "\nEnabled Hook UIButton OnClick at " +
                       HexStr(reinterpret_cast<uintptr_t>(nguiOnClick->function)) +
                       "(" + UnityRvaAtModule(reinterpret_cast<void*>(nguiOnClick->function)) + ")";
            }
        }
    }
    return JS_NewString(ctx, out.c_str());
}

// ---------------------------------------------------------------------------
// lfs(ptr): list fields of an instance (or static fields of a class).
// ---------------------------------------------------------------------------
static JSValue JsUnityLfs(JSContext* ctx, JSValueConst, int argc, JSValueConst* argv) {
    if (argc < 1) return JS_ThrowTypeError(ctx, "lfs(instanceOrClassPtr)");
    uintptr_t target = reinterpret_cast<uintptr_t>(ArgPtr(ctx, argv[0]));
    if (target < 0x1000) return JS_ThrowTypeError(ctx, "lfs(): invalid pointer");

    std::lock_guard<std::mutex> lk(g_unityMutex);
    std::string err;
    if (!EnsureInitLocked(&err)) return JS_ThrowInternalError(ctx, "UnityResolve: %s", err.c_str());
    EnsureThreadAttached();

    void* maybeKlass = *reinterpret_cast<void**>(target);
    UnityResolve::Class* cls = FindClassByAddress(maybeKlass);
    bool isInstance = cls != nullptr;
    if (!cls) cls = FindClassByAddress(reinterpret_cast<void*>(target));
    if (!cls) {
        return JS_NewString(ctx, (std::string("[!] class not found for ") + HexStr(target)).c_str());
    }

    std::string out = "Found " + std::to_string(cls->fields.size()) +
                      " fields in class: " + UnityClassFullName(cls) +
                      " (" + HexStr(reinterpret_cast<uintptr_t>(cls->address)) + ")\n";
    out += "--------------------------------------------------\n";

    static constexpr size_t kMaxFields = 200;
    for (size_t i = 0; i < cls->fields.size() && i < kMaxFields; ++i) {
        auto* f = cls->fields[i];
        if (!f) continue;
        int32_t flags = UnityResolve::Invoke<int32_t>(
            "il2cpp_field_get_flags", reinterpret_cast<void*>(f->address));
        std::string modifier = UnityFieldModifier(flags);
        std::string typeName = UnityShortTypeName(UnityTypeName(f->type));
        uintptr_t typeAddr = f->type ? reinterpret_cast<uintptr_t>(f->type->address) : 0;

        out += "[" + std::to_string(i) + "]\t" + HexStr(static_cast<uintptr_t>(f->offset)) +
               " " + modifier + typeName + " (" + HexStr(typeAddr) + ")\t" + f->name + "\n";

        std::string addrStr = "(static)";
        std::string rawHex = "-";
        std::string resolved = "-";

        if (isInstance && !f->static_field && f->offset >= 0) {
            uintptr_t addr = target + static_cast<uintptr_t>(f->offset);
            addrStr = HexStr(addr);
            const std::string& tn = f->type ? f->type->name : std::string("?");
            if (tn == "System.String") {
                void* p = *reinterpret_cast<void**>(addr);
                rawHex = HexStr(reinterpret_cast<uintptr_t>(p));
                resolved = "\"" + BfTruncate(UnityStringToUtf8(
                    reinterpret_cast<UnityResolve::UnityType::String*>(p))) + "\"";
            } else if (f->type && f->type->size > 0 && f->type->size <= 4) {
                uint32_t v = *reinterpret_cast<uint32_t*>(addr);
                rawHex = HexStr(v);
                resolved = std::to_string(static_cast<int32_t>(v));
            } else {
                void* p = *reinterpret_cast<void**>(addr);
                rawHex = HexStr(reinterpret_cast<uintptr_t>(p));
                if (p) {
                    auto* pcls = FindClassByAddress(*reinterpret_cast<void**>(p));
                    resolved = pcls ? UnityClassFullName(pcls)
                                    : HexStr(reinterpret_cast<uintptr_t>(p));
                } else {
                    resolved = "null";
                }
            }
        } else if (f->static_field) {
            size_t sz = RawSize(f->type);
            std::vector<uint8_t> buf(sz, 0);
            UnityResolve::Invoke<void>("il2cpp_field_static_get_value",
                                       reinterpret_cast<void*>(f->address),
                                       reinterpret_cast<void*>(buf.data()));
            const std::string& tn = f->type ? f->type->name : std::string("?");
            if (tn == "System.String") {
                void* p = *reinterpret_cast<void**>(buf.data());
                rawHex = HexStr(reinterpret_cast<uintptr_t>(p));
                resolved = "\"" + BfTruncate(UnityStringToUtf8(
                    reinterpret_cast<UnityResolve::UnityType::String*>(p))) + "\"";
            } else if (f->type && f->type->size > 0 && f->type->size <= 4) {
                uint32_t v = *reinterpret_cast<uint32_t*>(buf.data());
                rawHex = HexStr(v);
                resolved = std::to_string(static_cast<int32_t>(v));
            } else {
                void* p = *reinterpret_cast<void**>(buf.data());
                rawHex = HexStr(reinterpret_cast<uintptr_t>(p));
                resolved = p ? HexStr(reinterpret_cast<uintptr_t>(p)) : "null";
            }
        }

        out += "        " + addrStr + "  --->  " + rawHex + "  --->  " + resolved + "\n\n";
    }
    if (cls->fields.size() > kMaxFields) {
        out += "... (+" + std::to_string(cls->fields.size() - kMaxFields) + " more)\n";
    }
    return JS_NewString(ctx, out.c_str());
}

// ---------------------------------------------------------------------------
// button(ptr) / buttons() / B_Button(): listener dump helpers.
// Mirrors Il2CppHookScripts' Button/export.ts:
//   Button.m_OnClick -> UnityEventBase.m_Calls (InvokableCallList)
//     -> m_ExecutingCalls / m_PersistentCalls / m_RuntimeCalls
//       -> InvokableCall.Delegate -> Delegate.method / method_ptr
// ---------------------------------------------------------------------------
struct UnityListInfo {
    void* list = nullptr;
    void* items = nullptr;
    int32_t size = 0;
};

static bool ReadUnityList(void* list, UnityListInfo& out) {
    out = {};
    if (!list) return false;

    // List<T> is an inflated generic class; its class pointer is not present in
    // UnityResolve's static class table. Resolve _size/_items through IL2CPP.
    void* klass = UnityObjectClassOf(list);
    void* sizeField = UnityClassFieldByName(klass, "_size");
    void* itemsField = UnityClassFieldByName(klass, "_items");
    int32_t sizeOffset = UnityFieldOffsetOf(sizeField);
    int32_t itemsOffset = UnityFieldOffsetOf(itemsField);
    if (sizeOffset < 0 || itemsOffset < 0) return false;

    int32_t size = *reinterpret_cast<int32_t*>(
        reinterpret_cast<uint8_t*>(list) + sizeOffset);
    if (size < 0 || size > 100000) return false;

    out.list = list;
    out.items = ReadPtrAt(list, itemsOffset);
    out.size = size;
    return true;
}

static void* UnityListAt(const UnityListInfo& info, int32_t index) {
    if (!info.items || index < 0 || index >= info.size) return nullptr;
    auto* arr = reinterpret_cast<UnityResolve::UnityType::Array<void*>*>(info.items);
    return arr->At(static_cast<unsigned int>(index));
}

static void AppendInvokableCallList(const char* label, void* list, std::string& out) {
    UnityListInfo info;
    if (!ReadUnityList(list, info)) return;

    out += "\n\t[+] " + std::string(label) + " ( " +
           HexStr(reinterpret_cast<uintptr_t>(list)) + " | " +
           std::to_string(info.size) + " )";
    if (info.size <= 0) return;

    int32_t show = info.size > 20 ? 20 : info.size;
    for (int32_t i = 0; i < show; ++i) {
        void* call = UnityListAt(info, i);
        if (!call) continue;

        void* callCls = UnityObjectClassOf(call);
        int32_t delegateOffset = UnityFieldOffsetOf(
            UnityClassFieldByName(callCls, "Delegate"));
        if (delegateOffset < 0) {
            delegateOffset = UnityFieldOffsetOf(
                UnityClassFieldByName(callCls, "delegate"));
        }
        void* delegate = ReadPtrAt(call, delegateOffset);
        if (!delegate) {
            out += "\n\t\t[" + std::to_string(i) + "] " +
                   HexStr(reinterpret_cast<uintptr_t>(call)) +
                   " -> (no delegate)";
            continue;
        }

        void* delCls = UnityObjectClassOf(delegate);
        void* methodInfo = ReadPtrAt(delegate,
            UnityFieldOffsetOf(UnityClassFieldByName(delCls, "method_info")));
        if (!methodInfo) {
            methodInfo = ReadPtrAt(delegate,
                UnityFieldOffsetOf(UnityClassFieldByName(delCls, "method")));
        }
        void* methodPtr = ReadPtrAt(delegate,
            UnityFieldOffsetOf(UnityClassFieldByName(delCls, "method_ptr")));
        void* target = ReadPtrAt(delegate,
            UnityFieldOffsetOf(UnityClassFieldByName(delCls, "m_target")));

        UnityMethodOwner owner = FindMethodByInfoOrFunction(methodInfo, methodPtr);
        std::string miStr = methodInfo
            ? HexStr(reinterpret_cast<uintptr_t>(methodInfo))
            : std::string("null");
        std::string fnStr = methodPtr
            ? UnityRvaAtModule(methodPtr)
            : std::string("null");

        out += "\n\t\t[" + std::to_string(i) + "] " +
               HexStr(reinterpret_cast<uintptr_t>(call)) + " -> " +
               HexStr(reinterpret_cast<uintptr_t>(delegate)) +
               "  (" + UnityObjectRuntimeName(delegate) + ")";
        if (owner.method) {
            out += "\n\t\t\tMethodInfo: " + miStr + " -> " + fnStr +
                   "\n\t\t\t" + UnityMethodOwnerName(owner) +
                   " | " + UnityMethodSignature(owner.method);
        } else {
            out += "\n\t\t\tMethodInfo: " + miStr + " -> " + fnStr;
        }
        if (target) {
            out += "\n\t\t\ttarget: " + HexStr(reinterpret_cast<uintptr_t>(target)) +
                   " (" + UnityObjectRuntimeName(target) + ")";
        }
    }
    if (info.size > show) {
        out += "\n\t\t... (+" + std::to_string(info.size - show) + " more)";
    }
}

// PersistentCallGroup.m_Calls: List<PersistentCall>.  PersistentCall stores the
// serialized target + method name even before Unity prepares runtime calls.
static void AppendPersistentCallGroup(void* group, std::string& out) {
    if (!group) return;
    void* groupCls = UnityObjectClassOf(group);
    int32_t listOffset = UnityFieldOffsetOf(
        UnityClassFieldByName(groupCls, "m_Calls"));
    void* list = ReadPtrAt(group, listOffset);

    UnityListInfo info;
    if (!ReadUnityList(list, info)) return;

    out += "\n\t[+] m_PersistentCalls.m_Calls ( " +
           HexStr(reinterpret_cast<uintptr_t>(list)) + " | " +
           std::to_string(info.size) + " )";
    if (info.size <= 0) return;

    int32_t show = info.size > 20 ? 20 : info.size;
    for (int32_t i = 0; i < show; ++i) {
        void* pc = UnityListAt(info, i);
        if (!pc) continue;
        void* pcCls = UnityObjectClassOf(pc);

        void* target = ReadPtrAt(pc,
            UnityFieldOffsetOf(UnityClassFieldByName(pcCls, "m_Target")));
        void* nameObj = ReadPtrAt(pc,
            UnityFieldOffsetOf(UnityClassFieldByName(pcCls, "m_MethodName")));
        void* typeNameObj = ReadPtrAt(pc,
            UnityFieldOffsetOf(UnityClassFieldByName(pcCls, "m_TargetAssemblyTypeName")));

        std::string methodName = UnityStringToUtf8(
            reinterpret_cast<UnityResolve::UnityType::String*>(nameObj));
        std::string typeName = UnityStringToUtf8(
            reinterpret_cast<UnityResolve::UnityType::String*>(typeNameObj));

        void* targetCls = UnityObjectClassOf(target);
        void* methodInfo = methodName.empty()
            ? nullptr : UnityClassMethodByName(targetCls, methodName.c_str());
        UnityMethodOwner owner = FindMethodByInfoOrFunction(methodInfo, nullptr);

        out += "\n\t\t[" + std::to_string(i) + "] target=" +
               HexStr(reinterpret_cast<uintptr_t>(target)) +
               " (" + UnityObjectRuntimeName(target) + ")";
        if (!typeName.empty()) out += " type=" + typeName;
        out += "\n\t\t\tmethodName: " +
               (methodName.empty() ? std::string("?") : methodName);
        if (methodInfo) {
            out += "\n\t\t\tMethodInfo: " +
                   HexStr(reinterpret_cast<uintptr_t>(methodInfo));
        }
        if (owner.method) {
            out += "\n\t\t\t" + UnityMethodOwnerName(owner) +
                   " | " + UnityMethodSignature(owner.method);
        }
    }
    if (info.size > show) {
        out += "\n\t\t... (+" + std::to_string(info.size - show) + " more)";
    }
}

static void AppendButtonListeners(void* button, std::string& out) {
    if (!button) return;
    void* buttonCls = UnityObjectClassOf(button);
    int32_t onClickOffset = UnityFieldOffsetOf(
        UnityClassFieldByName(buttonCls, "m_OnClick"));
    if (onClickOffset < 0) {
        onClickOffset = UnityFieldOffsetOf(
            UnityClassFieldByName(buttonCls, "onClick"));
    }
    void* event = ReadPtrAt(button, onClickOffset);
    if (!event) {
        out += "\n\t[+] m_OnClick -> null";
        return;
    }

    void* eventCls = UnityObjectClassOf(event);
    out += "\n\t[+] m_OnClick event " + HexStr(reinterpret_cast<uintptr_t>(event)) +
           " (" + UnityClassRuntimeName(eventCls) + ")";

    int32_t callsOffset = UnityFieldOffsetOf(
        UnityClassFieldByName(eventCls, "m_Calls"));
    void* calls = ReadPtrAt(event, callsOffset);
    if (!calls) {
        out += "\n\t[+] m_Calls -> null";
        return;
    }

    void* callsCls = UnityObjectClassOf(calls);
    out += "\n\t[+] m_Calls " + HexStr(reinterpret_cast<uintptr_t>(calls)) +
           " (" + UnityClassRuntimeName(callsCls) + ")";
    for (const char* name : {"m_ExecutingCalls", "m_PersistentCalls", "m_RuntimeCalls"}) {
        int32_t offset = UnityFieldOffsetOf(
            UnityClassFieldByName(callsCls, name));
        if (offset < 0) {
            out += "\n\t[+] " + std::string(name) + " (missing field)";
            continue;
        }
        AppendInvokableCallList(name, ReadPtrAt(calls, offset), out);
    }

    int32_t persistentOffset = UnityFieldOffsetOf(
        UnityClassFieldByName(eventCls, "m_PersistentCalls"));
    if (persistentOffset >= 0) {
        AppendPersistentCallGroup(ReadPtrAt(event, persistentOffset), out);
    }
}

// UIButton.OnClick -> onClick (List<EventDelegate>) -> mMethod (RuntimeMethodInfo)
// -> mhandle (MethodInfo*).  Used by B_Button for NGUI-style buttons.
static void AppendEventDelegateList(void* list, std::string& out) {
    UnityListInfo info;
    if (!ReadUnityList(list, info)) return;

    out += "\n\t[+] onClick ( " + HexStr(reinterpret_cast<uintptr_t>(list)) +
           " | " + std::to_string(info.size) + " )";
    if (info.size <= 0) return;

    int32_t show = info.size > 20 ? 20 : info.size;
    for (int32_t i = 0; i < show; ++i) {
        void* item = UnityListAt(info, i);
        if (!item) continue;
        void* cls = UnityObjectClassOf(item);
        int32_t mMethodOffset = UnityFieldOffsetOf(
            UnityClassFieldByName(cls, "mMethod"));
        void* runtimeMethod = ReadPtrAt(item, mMethodOffset);
        void* methodInfo = nullptr;
        if (runtimeMethod) {
            void* rmCls = UnityObjectClassOf(runtimeMethod);
            methodInfo = ReadPtrAt(runtimeMethod,
                UnityFieldOffsetOf(UnityClassFieldByName(rmCls, "mhandle")));
        }
        UnityMethodOwner owner = FindMethodByInfoOrFunction(methodInfo, nullptr);
        out += "\n\t\t[" + std::to_string(i) + "] " +
               HexStr(reinterpret_cast<uintptr_t>(item)) + " -> " +
               (methodInfo ? HexStr(reinterpret_cast<uintptr_t>(methodInfo))
                           : std::string("null"));
        if (owner.method) {
            out += "\n\t\t\t" + UnityMethodOwnerName(owner) +
                   " | " + UnityMethodSignature(owner.method);
        }
    }
    if (info.size > show) {
        out += "\n\t\t... (+" + std::to_string(info.size - show) + " more)";
    }
}

static std::string ButtonInfo(void* button) {
    if (!button) return "[!] button is null";
    void* go = ComponentGameObject(button);
    auto* core = UnityResolve::Get("UnityEngine.CoreModule.dll");
    auto* goCls = core ? core->Get("GameObject") : nullptr;
    auto* objCls = core ? core->Get("Object") : nullptr;

    std::string name = InvokeStringMethod(objCls, "get_name", go);
    void* tr = InvokePtrMethod(goCls, "get_transform", go);

    std::string out;
    out += "[*] " + HexStr(reinterpret_cast<uintptr_t>(button)) + " ---> " + name +
           " (UnityEngine.UI.Button) { G:" + HexStr(reinterpret_cast<uintptr_t>(go)) +
           " | T:" + HexStr(reinterpret_cast<uintptr_t>(tr)) + " }";
    AppendButtonListeners(button, out);
    return out;
}

static JSValue JsUnityButton(JSContext* ctx, JSValueConst, int argc, JSValueConst* argv) {
    if (argc < 1) return JS_ThrowTypeError(ctx, "button(buttonPtr)");
    void* button = ArgPtr(ctx, argv[0]);
    std::lock_guard<std::mutex> lk(g_unityMutex);
    std::string err;
    if (!EnsureInitLocked(&err)) return JS_ThrowInternalError(ctx, "UnityResolve: %s", err.c_str());
    EnsureThreadAttached();
    return JS_NewString(ctx, ButtonInfo(button).c_str());
}

static JSValue JsUnityButtons(JSContext* ctx, JSValueConst, int, JSValueConst*) {
    std::lock_guard<std::mutex> lk(g_unityMutex);
    std::string err;
    if (!EnsureInitLocked(&err)) return JS_ThrowInternalError(ctx, "UnityResolve: %s", err.c_str());
    EnsureThreadAttached();

    auto* ui = UnityResolve::Get("UnityEngine.UI.dll");
    auto* buttonCls = ui ? ui->Get("Button") : nullptr;
    if (!buttonCls) return JS_NewString(ctx, "[!] UnityEngine.UI.Button not found");

    auto objects = FindObjectsOfType(buttonCls);
    std::string out = "Buttons (" + std::to_string(objects.size()) + "):";
    size_t show = objects.size() > 20 ? 20 : objects.size();
    for (size_t i = 0; i < show; ++i) {
        out += "\n\n" + ButtonInfo(objects[i]);
    }
    if (objects.size() > show) {
        out += "\n... (+" + std::to_string(objects.size() - show) + " more)";
    }
    return JS_NewString(ctx, out.c_str());
}

} // namespace

size_t UnityDetachAll() {
    size_t n = 0;

    {
        std::lock_guard<std::mutex> lk(g_bfMutex);
        n += g_bfHooks.size();
        BfClearLocked();
    }
    {
        std::lock_guard<std::mutex> lk(g_setActiveMutex);
        if (g_setActiveHook.isValid()) {
            g_setActiveHook.unhook();
            ++n;
        }
        g_setActiveSeen.clear();
        g_setActiveLogs = 0;
    }
    {
        std::lock_guard<std::mutex> lk(g_onClickMutex);
        if (g_onClickHook.isValid()) {
            g_onClickHook.unhook();
            ++n;
        }
        g_onClickCalls = 0;
    }
    {
        std::lock_guard<std::mutex> lk(g_bButtonMutex);
        if (g_bButtonHook.isValid()) {
            g_bButtonHook.unhook();
            ++n;
        }
        if (g_bButtonNguiHook.isValid()) {
            g_bButtonNguiHook.unhook();
            ++n;
        }
        g_bButtonCalls = 0;
    }
    return n;
}

void UnitySetLibDirHint(const std::string& dir) {
    std::lock_guard<std::mutex> lk(g_unityMutex);
    g_unityLibDirHint = dir;
}

std::string UnityGetLibDirHint() {
    std::lock_guard<std::mutex> lk(g_unityMutex);
    return g_unityLibDirHint;
}

void RegisterUnityApis(JSContext* ctx, JSValue global) {
    JSValue root = JS_NewObject(ctx);
    JS_SetPropertyStr(ctx, root, "isAvailable", JS_NewCFunction(ctx, JsUnityAvailable, "isAvailable", 0));
    JS_SetPropertyStr(ctx, root, "available", JS_NewCFunction(ctx, JsUnityAvailable, "available", 0));
    JS_SetPropertyStr(ctx, root, "init", JS_NewCFunction(ctx, JsUnityInit, "init", 0));
    JS_SetPropertyStr(ctx, root, "assemblies", JS_NewCFunction(ctx, JsUnityAssemblies, "assemblies", 0));
    JS_SetPropertyStr(ctx, root, "assembly", JS_NewCFunction(ctx, JsUnityAssembly, "assembly", 1));
    JS_SetPropertyStr(ctx, root, "class", JS_NewCFunction(ctx, JsUnityClass, "class", 3));
    JS_SetPropertyStr(ctx, root, "findclass", JS_NewCFunction(ctx, JsUnityFindClass, "findclass", 2));
    JS_SetPropertyStr(ctx, root, "findmethods", JS_NewCFunction(ctx, JsUnityFindMethods, "findmethods", 2));
    JS_SetPropertyStr(ctx, root, "m", JS_NewCFunction(ctx, JsUnityM, "m", 3));
    JS_SetPropertyStr(ctx, root, "dump", JS_NewCFunction(ctx, JsUnityDump, "dump", 1));
    JS_SetPropertyStr(ctx, root, "threadAttach", JS_NewCFunction(ctx, JsUnityThreadAttach, "threadAttach", 0));
    JS_SetPropertyStr(ctx, root, "threadDetach", JS_NewCFunction(ctx, JsUnityThreadDetach, "threadDetach", 0));
    JS_SetPropertyStr(ctx, root, "string", JS_NewCFunction(ctx, JsUnityString, "string", 1));
    JS_SetPropertyStr(ctx, root, "toString", JS_NewCFunction(ctx, JsUnityToString, "toString", 1));
    JS_SetPropertyStr(ctx, root, "help", JS_NewCFunction(ctx, JsUnityHelp, "help", 0));
    JS_SetPropertyStr(ctx, root, "mi", JS_NewCFunction(ctx, JsUnityMi, "mi", 1));
    JS_SetPropertyStr(ctx, root, "b", JS_NewCFunction(ctx, JsUnityB, "b", 2));
    JS_SetPropertyStr(ctx, root, "lfs", JS_NewCFunction(ctx, JsUnityLfs, "lfs", 1));
    JS_SetPropertyStr(ctx, root, "showGameObject", JS_NewCFunction(ctx, JsUnityShowGameObject, "showGameObject", 1));
    JS_SetPropertyStr(ctx, root, "button", JS_NewCFunction(ctx, JsUnityButton, "button", 1));
    JS_SetPropertyStr(ctx, root, "buttons", JS_NewCFunction(ctx, JsUnityButtons, "buttons", 0));
    JS_SetPropertyStr(ctx, root, "B_Button", JS_NewCFunction(ctx, JsUnityBButton, "B_Button", 1));
    JS_SetPropertyStr(ctx, root, "HookSetActive", JS_NewCFunction(ctx, JsUnityHookSetActive, "HookSetActive", 0));
    JS_SetPropertyStr(ctx, root, "HookOnPointerClick", JS_NewCFunction(ctx, JsUnityHookOnPointerClick, "HookOnPointerClick", 0));

    JSValue hooks = JS_NewObject(ctx);
    JS_SetPropertyStr(ctx, hooks, "BF", JS_NewCFunction(ctx, JsUnityBF, "BF", 2));
    JS_SetPropertyStr(ctx, hooks, "BFA", JS_NewCFunction(ctx, JsUnityBFA, "BFA", 1));
    JS_SetPropertyStr(ctx, hooks, "b", JS_NewCFunction(ctx, JsUnityB, "b", 2));
    JS_SetPropertyStr(ctx, hooks, "list", JS_NewCFunction(ctx, JsUnityHooksList, "list", 0));
    JS_SetPropertyStr(ctx, hooks, "unhookAll", JS_NewCFunction(ctx, JsUnityHooksUnhookAll, "unhookAll", 0));
    JS_SetPropertyStr(ctx, root, "hooks", hooks);

    JS_SetPropertyStr(ctx, root, "__unity_kind", JS_NewString(ctx, "root"));
    JS_SetPropertyStr(ctx, global, "__NativeUnity", root);

    // Global aliases (kept only if not already defined by another subsystem).
    auto defineIfUndefined = [&](const char* name, JSValue fn) {
        JSValue existing = JS_GetPropertyStr(ctx, global, name);
        if (JS_IsUndefined(existing)) {
            JS_SetPropertyStr(ctx, global, name, fn);
        } else {
            JS_FreeValue(ctx, fn);
        }
        JS_FreeValue(ctx, existing);
    };
    defineIfUndefined("mi", JS_NewCFunction(ctx, JsUnityMi, "mi", 1));
    defineIfUndefined("BF", JS_NewCFunction(ctx, JsUnityBF, "BF", 2));
    defineIfUndefined("BFA", JS_NewCFunction(ctx, JsUnityBFA, "BFA", 1));
    defineIfUndefined("b", JS_NewCFunction(ctx, JsUnityB, "b", 2));
    defineIfUndefined("lfs", JS_NewCFunction(ctx, JsUnityLfs, "lfs", 1));
    defineIfUndefined("showGameObject", JS_NewCFunction(ctx, JsUnityShowGameObject, "showGameObject", 1));
    defineIfUndefined("button", JS_NewCFunction(ctx, JsUnityButton, "button", 1));
    defineIfUndefined("buttons", JS_NewCFunction(ctx, JsUnityButtons, "buttons", 0));
    defineIfUndefined("B_Button", JS_NewCFunction(ctx, JsUnityBButton, "B_Button", 1));
    defineIfUndefined("HookSetActive", JS_NewCFunction(ctx, JsUnityHookSetActive, "HookSetActive", 0));
    defineIfUndefined("HookOnPointerClick", JS_NewCFunction(ctx, JsUnityHookOnPointerClick, "HookOnPointerClick", 0));

    // Used by __getCompletions(expr) in agent_java_ref.cpp.
    JS_SetPropertyStr(ctx, global, "__native_unity_completions",
                      JS_NewCFunction(ctx, JsUnityCompletions, "__native_unity_completions", 2));
}

}} // namespace artpi::agent



