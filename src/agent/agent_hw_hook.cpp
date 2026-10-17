//
// agent_hw_hook.cpp - QuickJS Bindings for Hardware Breakpoints & Watchpoints
//
#include "agent_hw_hook.h"
#include "agent_common.h"
#include "agent_net.h"
#include "agent_qbdi.h"
#include "native/hooker/pi_hw_hook.h"
#include "native/hooker/pi_gum_hooker.h"
#include "native/qbdi/pi_qbdi_engine.h"
#include "frida-gum.h"
#include <unistd.h>
#include <elf.h>
#include <time.h>
#include <dlfcn.h>
#include "xdl.h"
#include <magic_enum/magic_enum.hpp>

#include <string>
#include <vector>
#include <memory>
#include <cstdio>
#include <cstring>
#include <cinttypes>
#include <android/log.h>

#define HW_LOGI(...) __android_log_print(ANDROID_LOG_INFO,  "PI_HwHook", __VA_ARGS__)
#define HW_LOGW(...) __android_log_print(ANDROID_LOG_WARN,  "PI_HwHook", __VA_ARGS__)
#define HW_LOGE(...) __android_log_print(ANDROID_LOG_ERROR, "PI_HwHook", __VA_ARGS__)

namespace artpi { namespace agent {

using namespace PI::Native;

namespace {

struct FallbackHookRecord {
    uint32_t id;
    uintptr_t address;
    std::string tag;
    PI::Native::NativeHookHandle handle;
};
static std::vector<FallbackHookRecord> g_fallbackHooks;
static std::mutex g_fallbackMutex;
static uint32_t g_nextFallbackId = 10000;
static bool g_dlopenMonitorActive = false;

static bool DetachSessionOrFallback(uint32_t id) {
    if (id < 10000) {
        return HwHookManager::instance().detach(id);
    }
    std::lock_guard<std::mutex> lk(g_fallbackMutex);
    for (auto it = g_fallbackHooks.begin(); it != g_fallbackHooks.end(); ++it) {
        if (it->id == id) {
            if (it->handle.isValid()) it->handle.unhook();
            g_fallbackHooks.erase(it);
            return true;
        }
    }
    return false;
}



// Helper to resolve address from various input forms:
// 1. (int/bigint/ptr)
// 2. ("0x1234")
// 3. ("module.so!symbol")
// 4. ("module.so", "symbol", ...)
static uintptr_t ResolveTarget(JSContext* ctx, int argc, JSValueConst* argv, int* out_opts_idx) {
    if (argc < 1) return 0;
    if (out_opts_idx) *out_opts_idx = 1;

    // Check ("module.so", "symbol", [options])
    if (argc >= 2 && JS_IsString(argv[0]) && JS_IsString(argv[1])) {
        const char* modStr = JS_ToCString(ctx, argv[0]);
        const char* symStr = JS_ToCString(ctx, argv[1]);
        uintptr_t addr = 0;
        if (modStr && symStr) {
            void* handle = xdl_open(modStr, XDL_DEFAULT);
            if (handle) {
                addr = reinterpret_cast<uintptr_t>(xdl_sym(handle, symStr, nullptr));
                if (!addr) {
                    addr = reinterpret_cast<uintptr_t>(xdl_dsym(handle, symStr, nullptr));
                }
                xdl_close(handle);
            }
        }
        if (modStr) JS_FreeCString(ctx, modStr);
        if (symStr) JS_FreeCString(ctx, symStr);
        if (out_opts_idx) *out_opts_idx = 2;
        return addr;
    }

    // Check single string argument
    if (JS_IsString(argv[0])) {
        const char* str = JS_ToCString(ctx, argv[0]);
        if (!str) return 0;
        std::string spec(str);
        JS_FreeCString(ctx, str);

        auto exPos = spec.find('!');
        if (exPos != std::string::npos) {
            std::string mod = spec.substr(0, exPos);
            std::string sym = spec.substr(exPos + 1);
            void* handle = xdl_open(mod.c_str(), XDL_DEFAULT);
            uintptr_t addr = 0;
            if (handle) {
                addr = reinterpret_cast<uintptr_t>(xdl_sym(handle, sym.c_str(), nullptr));
                if (!addr) {
                    addr = reinterpret_cast<uintptr_t>(xdl_dsym(handle, sym.c_str(), nullptr));
                }
                xdl_close(handle);
            }
            return addr;
        }

        // Try parsing hex string (e.g. "0x70123456")
        if (spec.size() > 2 && spec[0] == '0' && (spec[1] == 'x' || spec[1] == 'X')) {
            char* end = nullptr;
            return static_cast<uintptr_t>(strtoull(spec.c_str(), &end, 16));
        }

        // Fallback: search symbol across all loaded modules
        void* symAddr = dlsym(RTLD_DEFAULT, spec.c_str());
        return reinterpret_cast<uintptr_t>(symAddr);
    }

    // Numeric or BigInt address
    int64_t raw = ParsePtr(ctx, argv[0]);
    if (raw > 0) return static_cast<uintptr_t>(raw);
    return 0;
}

// Memory reader helpers exposed on context
static JSValue JsCtxReadCString(JSContext* ctx, JSValueConst /*this_val*/, int argc, JSValueConst* argv) {
    if (argc < 1) return JS_NULL;
    int64_t addr = ParsePtr(ctx, argv[0]);
    if (addr < 0x1000) return JS_NULL;
    const char* str = reinterpret_cast<const char*>(addr);
    char buf[512] = {0};
    size_t i = 0;
    while (i < sizeof(buf) - 1) {
        char c = str[i];
        if (c == '\0') break;
        buf[i++] = c;
    }
    return JS_NewString(ctx, buf);
}

static JSValue JsCtxReadU32(JSContext* ctx, JSValueConst /*this_val*/, int argc, JSValueConst* argv) {
    if (argc < 1) return JS_UNDEFINED;
    int64_t addr = ParsePtr(ctx, argv[0]);
    if (addr < 0x1000) return JS_UNDEFINED;
    uint32_t val = *reinterpret_cast<const uint32_t*>(addr);
    return JS_NewUint32(ctx, val);
}

static JSValue JsCtxReadU64(JSContext* ctx, JSValueConst /*this_val*/, int argc, JSValueConst* argv) {
    if (argc < 1) return JS_UNDEFINED;
    int64_t addr = ParsePtr(ctx, argv[0]);
    if (addr < 0x1000) return JS_UNDEFINED;
    uint64_t val = *reinterpret_cast<const uint64_t*>(addr);
    return NewBigIntOrInt(ctx, val);
}

// CFunctionData callback for ctx.setArg(i, val)
static JSValue JsHwSetArg(JSContext* ctx, JSValueConst, int argc, JSValueConst* argv, int, JSValue* func_data) {
    if (argc < 2) return JS_UNDEFINED;
    int64_t raw_ptr = 0;
    if (JS_IsBigInt(ctx, func_data[0])) JS_ToBigInt64(ctx, &raw_ptr, func_data[0]);
    else JS_ToInt64(ctx, &raw_ptr, func_data[0]);
    if (!raw_ptr) return JS_UNDEFINED;

    auto* hwctx = reinterpret_cast<HwCpuContext*>(raw_ptr);
    int32_t idx = 0;
    JS_ToInt32(ctx, &idx, argv[0]);
    int64_t val = 0;
    if (JS_IsBigInt(ctx, argv[1])) JS_ToBigInt64(ctx, &val, argv[1]);
    else JS_ToInt64(ctx, &val, argv[1]);

    hwctx->setArg(idx, static_cast<uint64_t>(val));
    return JS_UNDEFINED;
}

// CFunctionData callback for ctx.setRet(val)
static JSValue JsHwSetRet(JSContext* ctx, JSValueConst, int argc, JSValueConst* argv, int, JSValue* func_data) {
    if (argc < 1) return JS_UNDEFINED;
    int64_t raw_ptr = 0;
    if (JS_IsBigInt(ctx, func_data[0])) JS_ToBigInt64(ctx, &raw_ptr, func_data[0]);
    else JS_ToInt64(ctx, &raw_ptr, func_data[0]);
    if (!raw_ptr) return JS_UNDEFINED;

    auto* hwctx = reinterpret_cast<HwCpuContext*>(raw_ptr);
    int64_t val = 0;
    if (JS_IsBigInt(ctx, argv[0])) JS_ToBigInt64(ctx, &val, argv[0]);
    else JS_ToInt64(ctx, &val, argv[0]);

    hwctx->setRet(static_cast<uint64_t>(val));
    return JS_UNDEFINED;
}

// CFunctionData callback for ctx.setPc(val)
static JSValue JsHwSetPc(JSContext* ctx, JSValueConst, int argc, JSValueConst* argv, int, JSValue* func_data) {
    if (argc < 1) return JS_UNDEFINED;
    int64_t raw_ptr = 0;
    if (JS_IsBigInt(ctx, func_data[0])) JS_ToBigInt64(ctx, &raw_ptr, func_data[0]);
    else JS_ToInt64(ctx, &raw_ptr, func_data[0]);
    if (!raw_ptr) return JS_UNDEFINED;

    auto* hwctx = reinterpret_cast<HwCpuContext*>(raw_ptr);
    int64_t val = 0;
    if (JS_IsBigInt(ctx, argv[0])) JS_ToBigInt64(ctx, &val, argv[0]);
    else JS_ToInt64(ctx, &val, argv[0]);

    hwctx->pc = static_cast<uint64_t>(val);
    return JS_UNDEFINED;
}

// CFunctionData callback for ctx.setLr(val)
static JSValue JsHwSetLr(JSContext* ctx, JSValueConst, int argc, JSValueConst* argv, int, JSValue* func_data) {
    if (argc < 1) return JS_UNDEFINED;
    int64_t raw_ptr = 0;
    if (JS_IsBigInt(ctx, func_data[0])) JS_ToBigInt64(ctx, &raw_ptr, func_data[0]);
    else JS_ToInt64(ctx, &raw_ptr, func_data[0]);
    if (!raw_ptr) return JS_UNDEFINED;

    auto* hwctx = reinterpret_cast<HwCpuContext*>(raw_ptr);
    int64_t val = 0;
    if (JS_IsBigInt(ctx, argv[0])) JS_ToBigInt64(ctx, &val, argv[0]);
    else JS_ToInt64(ctx, &val, argv[0]);

    hwctx->lr = static_cast<uint64_t>(val);
    return JS_UNDEFINED;
}

// CFunctionData callback for ctx.skip([retVal])
static JSValue JsHwSkip(JSContext* ctx, JSValueConst, int argc, JSValueConst* argv, int, JSValue* func_data) {
    int64_t raw_ptr = 0;
    if (JS_IsBigInt(ctx, func_data[0])) JS_ToBigInt64(ctx, &raw_ptr, func_data[0]);
    else JS_ToInt64(ctx, &raw_ptr, func_data[0]);
    if (!raw_ptr) return JS_UNDEFINED;

    auto* hwctx = reinterpret_cast<HwCpuContext*>(raw_ptr);
    hwctx->pc = hwctx->lr;
    if (argc >= 1) {
        int64_t val = 0;
        if (JS_IsBigInt(ctx, argv[0])) JS_ToBigInt64(ctx, &val, argv[0]);
        else JS_ToInt64(ctx, &val, argv[0]);
        hwctx->setRet(static_cast<uint64_t>(val));
    }
    return JS_UNDEFINED;
}

static JSValue MakeHwContextObject(JSContext* ctx, HwCpuContext& hwctx, HwHookType type) {
    JSValue o = JS_NewObject(ctx);

    JS_SetPropertyStr(ctx, o, "pc", NewBigIntOrInt(ctx, hwctx.pc));
    JS_SetPropertyStr(ctx, o, "sp", NewBigIntOrInt(ctx, hwctx.sp));
    JS_SetPropertyStr(ctx, o, "lr", NewBigIntOrInt(ctx, hwctx.lr));
    JS_SetPropertyStr(ctx, o, "fp", NewBigIntOrInt(ctx, hwctx.fp));
    JS_SetPropertyStr(ctx, o, "threadId", JS_NewInt32(ctx, hwctx.thread_id));
    JS_SetPropertyStr(ctx, o, "slot", JS_NewInt32(ctx, hwctx.slot));

    // Register properties (x0 .. x28)
    JSValue args = JS_NewArray(ctx);
    for (int i = 0; i < 8; i++) {
        JS_SetPropertyUint32(ctx, args, static_cast<uint32_t>(i), NewBigIntOrInt(ctx, hwctx.x[i]));
    }
    JS_SetPropertyStr(ctx, o, "args", args);

    for (int i = 0; i <= 28; i++) {
        char regName[8];
        snprintf(regName, sizeof(regName), "x%d", i);
        JS_SetPropertyStr(ctx, o, regName, NewBigIntOrInt(ctx, hwctx.x[i]));
    }

    // Methods
    JSValue dataPtr = NewBigIntOrInt(ctx, reinterpret_cast<uintptr_t>(&hwctx));
    JSValue data[1] = { dataPtr };
    JS_SetPropertyStr(ctx, o, "setArg", JS_NewCFunctionData(ctx, JsHwSetArg, 2, 0, 1, data));
    JS_SetPropertyStr(ctx, o, "setRet", JS_NewCFunctionData(ctx, JsHwSetRet, 1, 0, 1, data));
    JS_SetPropertyStr(ctx, o, "setPc", JS_NewCFunctionData(ctx, JsHwSetPc, 1, 0, 1, data));
    JS_SetPropertyStr(ctx, o, "setLr", JS_NewCFunctionData(ctx, JsHwSetLr, 1, 0, 1, data));
    JS_SetPropertyStr(ctx, o, "skip", JS_NewCFunctionData(ctx, JsHwSkip, 1, 0, 1, data));
    JS_SetPropertyStr(ctx, o, "readCString", JS_NewCFunction(ctx, JsCtxReadCString, "readCString", 1));
    JS_SetPropertyStr(ctx, o, "readU32", JS_NewCFunction(ctx, JsCtxReadU32, "readU32", 1));
    JS_SetPropertyStr(ctx, o, "readU64", JS_NewCFunction(ctx, JsCtxReadU64, "readU64", 1));
    JS_FreeValue(ctx, dataPtr);

    if (type == HwHookType::WATCHPOINT) {
        JSValue mem = JS_NewObject(ctx);
        JS_SetPropertyStr(ctx, mem, "address", NewBigIntOrInt(ctx, hwctx.memory_address));
        JS_SetPropertyStr(ctx, mem, "operation", JS_NewString(ctx, (hwctx.memory_operation == 1) ? "read" : "write"));
        JS_SetPropertyStr(ctx, o, "memory", mem);
    }

    return o;
}

// CFunction callback for handle.detach()
static JSValue JsHwHandleDetach(JSContext* ctx, JSValueConst this_val, int /*argc*/, JSValueConst* /*argv*/) {
    JSValue idVal = JS_GetPropertyStr(ctx, this_val, "id");
    int32_t id = 0;
    if (JS_ToInt32(ctx, &id, idVal) == 0 && id > 0) {
        bool ok = DetachSessionOrFallback(static_cast<uint32_t>(id));
        JS_FreeValue(ctx, idVal);
        return JS_NewBool(ctx, ok);
    }
    JS_FreeValue(ctx, idVal);
    return JS_FALSE;
}

static JSValue CreateHandleObject(JSContext* ctx, uint32_t id, int slot, HwHookType type, uintptr_t address) {
    JSValue h = JS_NewObject(ctx);
    JS_SetPropertyStr(ctx, h, "id", JS_NewInt32(ctx, static_cast<int32_t>(id)));
    JS_SetPropertyStr(ctx, h, "slot", JS_NewInt32(ctx, slot));
    JS_SetPropertyStr(ctx, h, "type", JS_NewString(ctx, (type == HwHookType::BREAKPOINT) ? "breakpoint" : "watchpoint"));
    char hexBuf[32];
    snprintf(hexBuf, sizeof(hexBuf), "0x%" PRIxPTR, address);
    JS_SetPropertyStr(ctx, h, "address", JS_NewString(ctx, hexBuf));
    JS_SetPropertyStr(ctx, h, "detach", JS_NewCFunction(ctx, JsHwHandleDetach, "detach", 0));
    return h;
}

// HWBreakpoint.attach(target, [options | cb])
static uint32_t ArmBreakpointOrFallback(uintptr_t target, const std::string& tag, const HwHookCallback& cb);

static JSValue JsHwBreakpointAttach(JSContext* ctx, JSValueConst /*this_val*/, int argc, JSValueConst* argv) {
    if (argc < 1) {
        return JS_ThrowTypeError(ctx, "Usage: HWBreakpoint.attach(addressOrSymbol, { onEnter, [slot, threadId, once] })");
    }

    int optsIdx = 1;
    uintptr_t target = ResolveTarget(ctx, argc, argv, &optsIdx);
    if (!target) {
        return JS_ThrowTypeError(ctx, "[!] Failed to resolve hardware breakpoint target address");
    }

    JSValue jsCb = JS_UNDEFINED;
    int slot = -1;
    pid_t threadId = 0;
    bool once = false;

    if (argc > optsIdx) {
        JSValue opt = argv[optsIdx];
        if (JS_IsFunction(ctx, opt)) {
            jsCb = JS_DupValue(ctx, opt);
        } else if (JS_IsObject(opt)) {
            JSValue e = JS_GetPropertyStr(ctx, opt, "onEnter");
            if (JS_IsFunction(ctx, e)) {
                jsCb = e;
            } else {
                JS_FreeValue(ctx, e);
                JSValue h = JS_GetPropertyStr(ctx, opt, "onHit");
                if (JS_IsFunction(ctx, h)) jsCb = h; else JS_FreeValue(ctx, h);
            }

            JSValue sVal = JS_GetPropertyStr(ctx, opt, "slot");
            if (JS_IsNumber(sVal)) JS_ToInt32(ctx, &slot, sVal);
            JS_FreeValue(ctx, sVal);

            JSValue tVal = JS_GetPropertyStr(ctx, opt, "threadId");
            if (JS_IsNumber(tVal)) {
                int32_t t = 0; JS_ToInt32(ctx, &t, tVal);
                threadId = static_cast<pid_t>(t);
            }
            JS_FreeValue(ctx, tVal);

            JSValue oVal = JS_GetPropertyStr(ctx, opt, "once");
            if (!JS_IsUndefined(oVal)) once = JS_ToBool(ctx, oVal);
            JS_FreeValue(ctx, oVal);
        }
    }

    if (JS_IsUndefined(jsCb)) {
        return JS_ThrowTypeError(ctx, "[!] onEnter callback function is required");
    }

    std::string tag;
    char tbuf[32];
    snprintf(tbuf, sizeof(tbuf), "0x%lx", (unsigned long)target);
    tag = tbuf;

    auto cbGuard = std::shared_ptr<JSValue>(new JSValue(jsCb), [](JSValue* p) {
        if (p) {
            if (g_ctx && !JS_IsUndefined(*p)) JS_FreeValue(g_ctx, *p);
            delete p;
        }
    });

    HwHookConfig cfg;
    cfg.type = HwHookType::BREAKPOINT;
    cfg.address = target;
    cfg.slot = slot;
    cfg.thread_id = threadId;
    cfg.once = once;
    cfg.tag = tag;

    cfg.on_hit = [cbGuard](HwCpuContext& hwctx) {
        JSContext* jsctx = g_ctx;
        if (!jsctx || JS_IsUndefined(*cbGuard)) return;

        if (t_jsReentrancyDepth > 0) {
            char buf[128];
            snprintf(buf, sizeof(buf), "[HW BP] hit (reentrant) PC=0x%" PRIx64 " x0=0x%" PRIx64, hwctx.pc, hwctx.x[0]);
            BroadcastLog("hook", buf);
            return;
        }

        std::lock_guard<std::mutex> lk(g_jsMutex);
        JSValue ctxObj = MakeHwContextObject(jsctx, hwctx, HwHookType::BREAKPOINT);
        JSValue r = JS_Call(jsctx, *cbGuard, JS_UNDEFINED, 1, &ctxObj);
        if (JS_IsException(r)) {
            JSValue exc = JS_GetException(jsctx);
            const char* err = JS_ToCString(jsctx, exc);
            if (err) {
                BroadcastLog("console", std::string("[HWBreakpoint onEnter] ") + err);
                JS_FreeCString(jsctx, err);
            }
            JS_FreeValue(jsctx, exc);
        }
        JS_FreeValue(jsctx, r);
        JS_FreeValue(jsctx, ctxObj);
    };

    uint32_t id = HwHookManager::instance().attach(cfg);
    int assignedSlot = -1;
    if (id == 0) {
        id = ArmBreakpointOrFallback(target, tag, cfg.on_hit);
        if (id == 0) {
            return JS_ThrowInternalError(ctx, "[!] Failed to attach hardware breakpoint or fallback inline hook");
        }
        assignedSlot = -1;
    } else {
        for (const auto& s : HwHookManager::instance().listSessions()) {
            if (s.id == id) { assignedSlot = s.assigned_slot; break; }
        }
    }

    return CreateHandleObject(ctx, id, assignedSlot, HwHookType::BREAKPOINT, target);
}

// HWBreakpoint.detach(idOrHandle)
static JSValue JsHwBreakpointDetach(JSContext* ctx, JSValueConst /*this_val*/, int argc, JSValueConst* argv) {
    if (argc < 1) return JS_FALSE;
    int32_t id = 0;
    if (JS_IsObject(argv[0])) {
        JSValue idVal = JS_GetPropertyStr(ctx, argv[0], "id");
        JS_ToInt32(ctx, &id, idVal);
        JS_FreeValue(ctx, idVal);
    } else {
        JS_ToInt32(ctx, &id, argv[0]);
    }
    if (id <= 0) return JS_FALSE;
    bool ok = DetachSessionOrFallback(static_cast<uint32_t>(id));
    return JS_NewBool(ctx, ok);
}

// HWBreakpoint.detachAll()
static JSValue JsHwBreakpointDetachAll(JSContext* ctx, JSValueConst /*this_val*/, int /*argc*/, JSValueConst* /*argv*/) {
    size_t count = HwHookDetachAll();
    char buf[64];
    snprintf(buf, sizeof(buf), "Detached %zu hardware hook(s)", count);
    return JS_NewString(ctx, buf);
}

// HWBreakpoint.list()
static JSValue JsHwBreakpointList(JSContext* ctx, JSValueConst /*this_val*/, int /*argc*/, JSValueConst* /*argv*/) {
    JSValue arr = JS_NewArray(ctx);
    auto list = HwHookManager::instance().listSessions();
    uint32_t idx = 0;
    for (const auto& s : list) {
        JSValue item = JS_NewObject(ctx);
        JS_SetPropertyStr(ctx, item, "id", JS_NewInt32(ctx, static_cast<int32_t>(s.id)));
        JS_SetPropertyStr(ctx, item, "slot", JS_NewInt32(ctx, s.assigned_slot));
        JS_SetPropertyStr(ctx, item, "type", JS_NewString(ctx, (s.config.type == HwHookType::BREAKPOINT) ? "breakpoint" : "watchpoint"));
        char hexBuf[32];
        snprintf(hexBuf, sizeof(hexBuf), "0x%" PRIxPTR, s.config.address);
        JS_SetPropertyStr(ctx, item, "address", JS_NewString(ctx, hexBuf));
        JS_SetPropertyStr(ctx, item, "once", JS_NewBool(ctx, s.config.once));
        JS_SetPropertyStr(ctx, item, "threads", JS_NewInt32(ctx, static_cast<int32_t>(s.armed_threads.size())));
        JS_SetPropertyUint32(ctx, arr, idx++, item);
    }
    return arr;
}

// HWWatchpoint.attach(target, [options | cb])
static JSValue JsHwWatchpointAttach(JSContext* ctx, JSValueConst /*this_val*/, int argc, JSValueConst* argv) {
    if (argc < 1) {
        return JS_ThrowTypeError(ctx, "Usage: HWWatchpoint.attach(address, { onHit, [size: 4, conditions: 'w', slot, threadId, once] })");
    }

    int optsIdx = 1;
    uintptr_t target = ResolveTarget(ctx, argc, argv, &optsIdx);
    if (!target) {
        return JS_ThrowTypeError(ctx, "[!] Failed to resolve hardware watchpoint target address");
    }

    JSValue jsCb = JS_UNDEFINED;
    int slot = -1;
    pid_t threadId = 0;
    bool once = false;
    size_t size = 4;
    HwWatchCondition condition = HwWatchCondition::WRITE;

    if (argc > optsIdx) {
        JSValue opt = argv[optsIdx];
        if (JS_IsFunction(ctx, opt)) {
            jsCb = JS_DupValue(ctx, opt);
        } else if (JS_IsObject(opt)) {
            JSValue h = JS_GetPropertyStr(ctx, opt, "onHit");
            if (JS_IsFunction(ctx, h)) jsCb = h; else JS_FreeValue(ctx, h);

            JSValue sVal = JS_GetPropertyStr(ctx, opt, "size");
            if (JS_IsNumber(sVal)) {
                int32_t sz = 4; JS_ToInt32(ctx, &sz, sVal);
                if (sz == 1 || sz == 2 || sz == 4 || sz == 8) size = static_cast<size_t>(sz);
            }
            JS_FreeValue(ctx, sVal);

            JSValue cVal = JS_GetPropertyStr(ctx, opt, "conditions");
            if (JS_IsString(cVal)) {
                const char* cs = JS_ToCString(ctx, cVal);
                if (cs) {
                    std::string cstr = cs;
                    JS_FreeCString(ctx, cs);
                    std::string lower = cstr;
                    std::transform(lower.begin(), lower.end(), lower.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
                    if (lower == "r" || lower == "read") condition = HwWatchCondition::READ;
                    else if (lower == "w" || lower == "write") condition = HwWatchCondition::WRITE;
                    else if (lower == "rw" || lower == "read_write" || lower == "readwrite") condition = HwWatchCondition::READ_WRITE;
                    else {
                        auto parsed = magic_enum::enum_cast<HwWatchCondition>(cstr);
                        if (parsed.has_value()) {
                            condition = parsed.value();
                        } else {
                            JS_FreeValue(ctx, cVal);
                            JS_FreeValue(ctx, jsCb);
                            return JS_ThrowTypeError(ctx, "Unknown watch condition '%s'. Expected 'r'/'read', 'w'/'write', or 'rw'/'read_write'.", cstr.c_str());
                        }
                    }
                }
            }
            JS_FreeValue(ctx, cVal);

            JSValue slVal = JS_GetPropertyStr(ctx, opt, "slot");
            if (JS_IsNumber(slVal)) JS_ToInt32(ctx, &slot, slVal);
            JS_FreeValue(ctx, slVal);

            JSValue tVal = JS_GetPropertyStr(ctx, opt, "threadId");
            if (JS_IsNumber(tVal)) {
                int32_t t = 0; JS_ToInt32(ctx, &t, tVal);
                threadId = static_cast<pid_t>(t);
            }
            JS_FreeValue(ctx, tVal);

            JSValue oVal = JS_GetPropertyStr(ctx, opt, "once");
            if (!JS_IsUndefined(oVal)) once = JS_ToBool(ctx, oVal);
            JS_FreeValue(ctx, oVal);
        }
    }

    if (JS_IsUndefined(jsCb)) {
        return JS_ThrowTypeError(ctx, "[!] onHit callback function is required");
    }

    auto cbGuard = std::shared_ptr<JSValue>(new JSValue(jsCb), [](JSValue* p) {
        if (p) {
            if (g_ctx && !JS_IsUndefined(*p)) JS_FreeValue(g_ctx, *p);
            delete p;
        }
    });

    HwHookConfig cfg;
    cfg.type = HwHookType::WATCHPOINT;
    cfg.address = target;
    cfg.size = size;
    cfg.condition = condition;
    cfg.slot = slot;
    cfg.thread_id = threadId;
    cfg.once = once;

    cfg.on_hit = [cbGuard](HwCpuContext& hwctx) {
        JSContext* jsctx = g_ctx;
        if (!jsctx || JS_IsUndefined(*cbGuard)) return;

        if (t_jsReentrancyDepth > 0) {
            char buf[128];
            snprintf(buf, sizeof(buf), "[HW Watch] hit (reentrant) PC=0x%" PRIx64 " mem=0x%" PRIx64, hwctx.pc, hwctx.memory_address);
            BroadcastLog("hook", buf);
            return;
        }

        std::lock_guard<std::mutex> lk(g_jsMutex);
        JSValue ctxObj = MakeHwContextObject(jsctx, hwctx, HwHookType::WATCHPOINT);
        JSValue r = JS_Call(jsctx, *cbGuard, JS_UNDEFINED, 1, &ctxObj);
        if (JS_IsException(r)) {
            JSValue exc = JS_GetException(jsctx);
            const char* err = JS_ToCString(jsctx, exc);
            if (err) {
                BroadcastLog("console", std::string("[HWWatchpoint onHit] ") + err);
                JS_FreeCString(jsctx, err);
            }
            JS_FreeValue(jsctx, exc);
        }
        JS_FreeValue(jsctx, r);
        JS_FreeValue(jsctx, ctxObj);
    };

    uint32_t id = HwHookManager::instance().attach(cfg);
    if (id == 0) {
        return JS_ThrowInternalError(ctx, "[!] Failed to attach hardware watchpoint (slots exhausted or restricted)");
    }

    int assignedSlot = -1;
    for (const auto& s : HwHookManager::instance().listSessions()) {
        if (s.id == id) { assignedSlot = s.assigned_slot; break; }
    }

    return CreateHandleObject(ctx, id, assignedSlot, HwHookType::WATCHPOINT, target);
}

static uintptr_t ResolveDlopenExtAddress() {
    uintptr_t addr = 0;
    void* handle = xdl_open("libdl.so", XDL_DEFAULT);
    if (handle) {
        addr = reinterpret_cast<uintptr_t>(xdl_sym(handle, "android_dlopen_ext", nullptr));
        xdl_close(handle);
    }
    if (!addr) {
        void* p = dlsym(RTLD_DEFAULT, "android_dlopen_ext");
        addr = reinterpret_cast<uintptr_t>(p);
    }
    return addr;
}

static uintptr_t ResolveDlopenAddress() {
    uintptr_t addr = 0;
    void* handle = xdl_open("libdl.so", XDL_DEFAULT);
    if (handle) {
        addr = reinterpret_cast<uintptr_t>(xdl_sym(handle, "dlopen", nullptr));
        xdl_close(handle);
    }
    if (!addr) {
        void* p = dlsym(RTLD_DEFAULT, "dlopen");
        addr = reinterpret_cast<uintptr_t>(p);
    }
    return addr;
}

static inline uint64_t GetMonotonicTimeNs() {
    struct timespec ts{};
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return static_cast<uint64_t>(ts.tv_sec) * 1000000000ULL + static_cast<uint64_t>(ts.tv_nsec);
}

static uintptr_t ResolveCallConstructorsAddress() {
    uintptr_t addr = 0;
#if defined(__aarch64__) || defined(__x86_64__)
    const char* linker_name = "linker64";
#else
    const char* linker_name = "linker";
#endif
    void* handle = xdl_open(linker_name, XDL_DEFAULT);
    if (handle) {
        addr = reinterpret_cast<uintptr_t>(xdl_dsym(handle, "__dl__ZN6soinfo17call_constructorsEv", nullptr));
        if (!addr) {
            addr = reinterpret_cast<uintptr_t>(xdl_sym(handle, "__dl__ZN6soinfo17call_constructorsEv", nullptr));
        }
        if (!addr) {
            addr = reinterpret_cast<uintptr_t>(xdl_dsym(handle, "_ZN6soinfo17call_constructorsEv", nullptr));
        }
        if (!addr) {
            addr = reinterpret_cast<uintptr_t>(xdl_sym(handle, "_ZN6soinfo17call_constructorsEv", nullptr));
        }
        xdl_close(handle);
    }
    return addr;
}

static size_t DetectConstructorsCalledOffset(uintptr_t call_ctors_addr) {
    if (!call_ctors_addr || !gum_memory_is_readable(reinterpret_cast<const void*>(call_ctors_addr), 64)) {
        return sizeof(void*) == 8 ? 248 : 160;
    }
    const uint32_t* insns = reinterpret_cast<const uint32_t*>(call_ctors_addr);
    for (size_t i = 0; i < 16; i++) {
        uint32_t insn = insns[i];
        if ((insn & 0xffc00000) == 0x39400000) {
            uint32_t rn = (insn >> 5) & 0x1f;
            if (rn == 0) { // x0 is `this`
                size_t imm = (insn >> 10) & 0xfff;
                if (imm >= 0x80 && imm <= 0x300) {
                    return imm;
                }
            }
        }
    }
    return sizeof(void*) == 8 ? 248 : 160;
}

struct ExtractedConstructors {
    std::string soName;
    uintptr_t base = 0;
    std::vector<std::pair<uintptr_t, std::string>> ctors; // address, desc
};

static bool ExtractConstructorsFromSoinfo(uintptr_t soinfo_ptr, ExtractedConstructors& out) {
    if (soinfo_ptr < 0x1000) return false;
    if (!gum_memory_is_readable(reinterpret_cast<const void*>(soinfo_ptr), 0x50)) return false;

    // Scan pointer-sized slots of soinfo for a page-aligned base pointing to ELFMAG ("\x7fELF")
    uintptr_t base = 0;
    for (size_t off = 0; off <= 0x120; off += sizeof(void*)) {
        uintptr_t candidate = 0;
        if (!gum_memory_is_readable(reinterpret_cast<const void*>(soinfo_ptr + off), sizeof(void*))) {
            break;
        }
        std::memcpy(&candidate, reinterpret_cast<const void*>(soinfo_ptr + off), sizeof(void*));
        if (candidate >= 0x1000 && (candidate & 0xfff) == 0) {
            if (gum_memory_is_readable(reinterpret_cast<const void*>(candidate), 4)) {
                if (*reinterpret_cast<const uint32_t*>(candidate) == 0x464c457f) { // ELFMAG
                    base = candidate;
                    break;
                }
            }
        }
    }
    if (!base) return false;
    out.base = base;

    const ElfW(Ehdr)* ehdr = reinterpret_cast<const ElfW(Ehdr)*>(base);
    if (!gum_memory_is_readable(ehdr, sizeof(ElfW(Ehdr)))) return false;
    if (ehdr->e_phoff == 0 || ehdr->e_phnum == 0) return false;

    uintptr_t phdr_addr = base + ehdr->e_phoff;
    if (!gum_memory_is_readable(reinterpret_cast<const void*>(phdr_addr), sizeof(ElfW(Phdr)) * ehdr->e_phnum)) {
        return false;
    }
    const ElfW(Phdr)* phdr = reinterpret_cast<const ElfW(Phdr)*>(phdr_addr);

    // Compute load_bias (base - first PT_LOAD p_vaddr)
    uintptr_t load_bias = base;
    for (size_t i = 0; i < ehdr->e_phnum; i++) {
        if (phdr[i].p_type == PT_LOAD) {
            load_bias = base - phdr[i].p_vaddr;
            break;
        }
    }

    // Find PT_DYNAMIC
    const ElfW(Dyn)* dynamic = nullptr;
    for (size_t i = 0; i < ehdr->e_phnum; i++) {
        if (phdr[i].p_type == PT_DYNAMIC) {
            dynamic = reinterpret_cast<const ElfW(Dyn)*>(load_bias + phdr[i].p_vaddr);
            break;
        }
    }
    if (!dynamic || !gum_memory_is_readable(dynamic, sizeof(ElfW(Dyn)))) return false;

    uintptr_t strtab = 0;
    uintptr_t soname_idx = 0;
    uintptr_t init_func = 0;
    uintptr_t init_array = 0;
    size_t init_array_sz = 0;

    for (const ElfW(Dyn)* d = dynamic; ; d++) {
        if (!gum_memory_is_readable(d, sizeof(ElfW(Dyn)))) break;
        if (d->d_tag == DT_NULL) break;

        switch (d->d_tag) {
            case DT_STRTAB:
                strtab = (d->d_un.d_ptr < base) ? (load_bias + d->d_un.d_ptr) : d->d_un.d_ptr;
                break;
            case DT_SONAME:
                soname_idx = d->d_un.d_val;
                break;
            case DT_INIT:
                init_func = (d->d_un.d_ptr < base) ? (load_bias + d->d_un.d_ptr) : d->d_un.d_ptr;
                break;
            case DT_INIT_ARRAY:
                init_array = (d->d_un.d_ptr < base) ? (load_bias + d->d_un.d_ptr) : d->d_un.d_ptr;
                break;
            case DT_INIT_ARRAYSZ:
                init_array_sz = d->d_un.d_val;
                break;
        }
    }

    // Resolve SO Name
    if (strtab && soname_idx && gum_memory_is_readable(reinterpret_cast<const void*>(strtab + soname_idx), 1)) {
        out.soName = reinterpret_cast<const char*>(strtab + soname_idx);
    }
    if (out.soName.empty()) {
        Dl_info dli{};
        if (dladdr(reinterpret_cast<const void*>(base), &dli) && dli.dli_fname) {
            const char* slash = std::strrchr(dli.dli_fname, '/');
            out.soName = slash ? (slash + 1) : dli.dli_fname;
        }
    }
    if (out.soName.empty()) {
        char tmp[64];
        snprintf(tmp, sizeof(tmp), "lib@0x%" PRIxPTR, base);
        out.soName = tmp;
    }

    // Collect DT_INIT
    if (init_func && init_func != static_cast<uintptr_t>(-1)) {
        out.ctors.push_back({ init_func, "DT_INIT" });
    }

    // Collect DT_INIT_ARRAY
    if (init_array && init_array_sz > 0) {
        size_t count = init_array_sz / sizeof(void*);
        if (gum_memory_is_readable(reinterpret_cast<const void*>(init_array), init_array_sz)) {
            const uintptr_t* arr = reinterpret_cast<const uintptr_t*>(init_array);
            for (size_t i = 0; i < count; i++) {
                uintptr_t fn = arr[i];
                if (fn != 0 && fn != static_cast<uintptr_t>(-1)) {
                    char desc[64];
                    uintptr_t offset = (fn >= base) ? (fn - base) : fn;
                    snprintf(desc, sizeof(desc), "DT_INIT_ARRAY[%zu] (+0x%" PRIxPTR ")", i, offset);
                    out.ctors.push_back({ fn, desc });
                }
            }
        }
    }

    // Resolve constructor symbols via xdl_addr
    void* xdlCache = nullptr;
    for (auto& c : out.ctors) {
        xdl_info_t dli{};
        if (xdl_addr(reinterpret_cast<void*>(c.first), &dli, &xdlCache) != 0) {
            if (dli.dli_sname && dli.dli_sname[0] != '\0') {
                c.second += std::string(" (") + dli.dli_sname + ")";
            }
        }
    }
    if (xdlCache) {
        xdl_addr_clean(&xdlCache);
    }

    return true;
}

struct CtorRelaySession {
    std::string soName;
    uintptr_t base = 0;
    pid_t thread_id = 0;
    std::vector<std::pair<uintptr_t, std::string>> ctors;
    size_t current_index = 0;
    uintptr_t pending_ret_addr = 0;
    uint32_t active_hook_id = 0;
    uint64_t total_start_ns = 0;
    uint64_t step_start_ns = 0;
};

static std::vector<std::shared_ptr<CtorRelaySession>> g_ctorStack;
static std::mutex g_ctorMutex;
static JSValue g_onConstructorCb = JS_UNDEFINED;
static JSValue g_onCallConstructorsCb = JS_UNDEFINED;
static std::mutex g_ctorJsMutex;
static std::string g_qbdiCtorFilter;
static size_t g_qbdiMaxLog = 100;

static bool MatchesQbdiFilter(const std::string& soName, const std::string& desc,
                             size_t idx, uintptr_t funcAddr, uintptr_t base,
                             const std::string& filter) {
    if (filter.empty()) return false;
    if (filter == "*" || filter == "all" || filter == "ALL") return true;

    // 1. Check if filter has '@': "<libPart>@<offsetOrAddr>" or "@<offsetOrAddr>"
    size_t atPos = filter.find('@');
    if (atPos != std::string::npos) {
        std::string libPart = filter.substr(0, atPos);
        std::string targetPart = filter.substr(atPos + 1);

        if (!libPart.empty() && libPart != "*" && soName.find(libPart) == std::string::npos) {
            return false;
        }

        if (targetPart.empty() || targetPart == "*") return true;

        uintptr_t targetVal = std::strtoull(targetPart.c_str(), nullptr, 16);
        uintptr_t offset = (funcAddr >= base) ? (funcAddr - base) : funcAddr;

        if (offset == targetVal || funcAddr == targetVal) {
            return true;
        }

        char hexBuf[32];
        snprintf(hexBuf, sizeof(hexBuf), "%" PRIxPTR, targetVal);
        if (desc.find(hexBuf) != std::string::npos) {
            return true;
        }
        return false;
    }

    // 2. Check if filter has colon: "<libPart>:<ctorPart>"
    size_t colon = filter.find(':');
    if (colon != std::string::npos) {
        std::string libPart = filter.substr(0, colon);
        std::string ctorPart = filter.substr(colon + 1);

        if (!libPart.empty() && libPart != "*" && soName.find(libPart) == std::string::npos) {
            return false;
        }

        if (ctorPart.empty() || ctorPart == "*") return true;

        char* endPtr = nullptr;
        long num = std::strtol(ctorPart.c_str(), &endPtr, 0);
        if (endPtr && *endPtr == '\0') {
            return (static_cast<long>(idx) == num || static_cast<long>(idx + 1) == num);
        }

        return (desc.find(ctorPart) != std::string::npos);
    }

    if (soName.find(filter) != std::string::npos) {
        return true;
    }

    if (desc.find(filter) != std::string::npos) {
        return true;
    }

    return false;
}

static void ArmNextCtor(std::shared_ptr<CtorRelaySession> session);

static void ArmNextCtor(std::shared_ptr<CtorRelaySession> session) {
    if (!session) return;

    if (session->current_index < session->ctors.size()) {
        size_t idx = session->current_index;
        uintptr_t target_addr = session->ctors[idx].first & ~static_cast<uintptr_t>(1);
        std::string desc = session->ctors[idx].second;

        HwHookConfig cfg;
        cfg.type = HwHookType::BREAKPOINT;
        cfg.address = target_addr;
        cfg.thread_id = session->thread_id;
        cfg.once = true; // One shot! Automatically disarms on hit
        cfg.tag = session->soName + "!" + desc;

        cfg.on_hit = [session](HwCpuContext& hwctx) {
            session->active_hook_id = 0;
            uint64_t now_ns = GetMonotonicTimeNs();
            size_t idx = session->current_index;
            const std::string& currentDesc = session->ctors[idx].second;

            if (idx > 0 && session->step_start_ns > 0) {
                double prev_ms = static_cast<double>(now_ns - session->step_start_ns) / 1000000.0;
                char doneBuf[512];
                snprintf(doneBuf, sizeof(doneBuf),
                         "[%s] [%zu/%zu] <- %s finished in %.2f ms",
                         session->soName.c_str(), idx, session->ctors.size(),
                         session->ctors[idx - 1].second.c_str(), prev_ms);
                HW_LOGI("[constructors] %s", doneBuf);
                BroadcastLog("constructors", doneBuf);
            }

            session->step_start_ns = now_ns;

            char enterBuf[512];
            snprintf(enterBuf, sizeof(enterBuf),
                     "[%s] [%zu/%zu] -> calling %s @ 0x%" PRIx64,
                     session->soName.c_str(), idx + 1, session->ctors.size(),
                     currentDesc.c_str(), hwctx.pc);
            HW_LOGI("[constructors] %s", enterBuf);
            BroadcastLog("constructors", enterBuf);

            bool bypass = false;
            {
                std::lock_guard<std::mutex> lkCtor(g_ctorJsMutex);
                if (g_ctx && !JS_IsUndefined(g_onConstructorCb) && t_jsReentrancyDepth == 0) {
                    std::lock_guard<std::mutex> lk(g_jsMutex);
                    JSValue obj = JS_NewObject(g_ctx);
                    JS_SetPropertyStr(g_ctx, obj, "name", JS_NewString(g_ctx, session->soName.c_str()));
                    char hexBase[32], hexFunc[32];
                    snprintf(hexBase, sizeof(hexBase), "0x%" PRIxPTR, session->base);
                    snprintf(hexFunc, sizeof(hexFunc), "0x%" PRIx64, hwctx.pc);
                    JS_SetPropertyStr(g_ctx, obj, "base", JS_NewString(g_ctx, hexBase));
                    JS_SetPropertyStr(g_ctx, obj, "func", JS_NewString(g_ctx, hexFunc));
                    JS_SetPropertyStr(g_ctx, obj, "desc", JS_NewString(g_ctx, currentDesc.c_str()));
                    JS_SetPropertyStr(g_ctx, obj, "index", JS_NewInt32(g_ctx, static_cast<int32_t>(idx + 1)));
                    JS_SetPropertyStr(g_ctx, obj, "total", JS_NewInt32(g_ctx, static_cast<int32_t>(session->ctors.size())));
                    JS_SetPropertyStr(g_ctx, obj, "context", MakeHwContextObject(g_ctx, hwctx, HwHookType::BREAKPOINT));

                    JSValue r = JS_Call(g_ctx, g_onConstructorCb, JS_UNDEFINED, 1, &obj);
                    if (JS_IsBool(r) && !JS_ToBool(g_ctx, r)) {
                        bypass = true;
                    }
                    JS_FreeValue(g_ctx, r);
                    JS_FreeValue(g_ctx, obj);
                }
            }

            bool doQbdi = false;
            if (!bypass && !g_qbdiCtorFilter.empty() &&
                MatchesQbdiFilter(session->soName, currentDesc, idx, session->ctors[idx].first, session->base, g_qbdiCtorFilter)) {
                doQbdi = true;
            }

            if (doQbdi) {
                char hdrBuf[512];
                snprintf(hdrBuf, sizeof(hdrBuf),
                         "[%s] [QBDI TRACE] Emulating constructor %s @ 0x%" PRIx64 " (budget: 500000, maxLog: %s)",
                         session->soName.c_str(), currentDesc.c_str(), hwctx.pc,
                         g_qbdiMaxLog == 0 ? "unlimited" : std::to_string(g_qbdiMaxLog).c_str());
                HW_LOGI("[constructors] %s", hdrBuf);
                BroadcastLog("constructors", hdrBuf);
                BroadcastLog("trace", hdrBuf);

                auto* engine = PI::Native::QBDIEngine::current();
                engine->clearInstrumentedRanges();

                auto ranges = ResolveModuleRangesByName(session->soName);
                if (ranges.empty()) {
                    ranges = ResolveModuleRangesByAddr(static_cast<uintptr_t>(hwctx.pc));
                }
                if (ranges.empty()) {
                    engine->addInstrumentedRange(static_cast<uintptr_t>(hwctx.pc), static_cast<uintptr_t>(hwctx.pc) + (1u << 20));
                } else {
                    for (const auto& r : ranges) {
                        engine->addInstrumentedRange(r.first, r.second);
                    }
                }

                engine->setInstructionBudget(500000);

                struct PendingTraceLine {
                    uintptr_t pc = 0;
                    std::string text;
                    bool active = false;
                };
                auto pending = std::make_shared<PendingTraceLine>();

                size_t loggedInsns = 0;
                size_t maxLog = g_qbdiMaxLog;

                engine->setInstructionCallback([pending, maxLog, &loggedInsns](
                        uintptr_t pc, const char* mnem, const char* disasm, int /*depth*/, void* /*rawGpr*/) -> int {
                    if (maxLog == 0 || loggedInsns < maxLog) {
                        if (pending->active) {
                            HW_LOGI("%s", pending->text.c_str());
                            BroadcastLog("trace", pending->text);
                            pending->active = false;
                        }

                        char logLine[256];
                        snprintf(logLine, sizeof(logLine), "  [QBDI] 0x%" PRIxPTR ": %-8s %-28s",
                                 pc, mnem ? mnem : "", disasm ? disasm : "");
                        pending->pc = pc;
                        pending->text = logLine;
                        pending->active = true;

                        loggedInsns++;
                        if (maxLog > 0 && loggedInsns == maxLog) {
                            BroadcastLog("trace", "  [QBDI] ... (trace logging limit reached, continuing emulation. Use --log for full trace)");
                        }
                    }
                    return 0; // CONTINUE
                });

                engine->setPostInstructionCallback([pending](uintptr_t pc, void* preGpr, void* postGpr) {
                    if (pending->active && pending->pc == pc) {
                        std::string diff = FormatGprDiff(
                            reinterpret_cast<const QBDI::GPRState*>(preGpr),
                            reinterpret_cast<const QBDI::GPRState*>(postGpr));
                        std::string fullLine = pending->text;
                        if (!diff.empty()) {
                            fullLine += " ; " + diff;
                        }
                        HW_LOGI("%s", fullLine.c_str());
                        BroadcastLog("trace", fullLine);
                        pending->active = false;
                    }
                });

                std::vector<uint64_t> gprs;
                for (int i = 0; i < 8; i++) {
                    gprs.push_back(hwctx.x[i]);
                }
                std::vector<double> fprs;

                uint64_t qbdi_start_ns = GetMonotonicTimeNs();
                PI::Native::NativeRunResult rr = engine->run(reinterpret_cast<void*>(hwctx.pc), gprs, fprs);
                uint64_t qbdi_end_ns = GetMonotonicTimeNs();
                double qbdi_ms = static_cast<double>(qbdi_end_ns - qbdi_start_ns) / 1000000.0;

                if (pending->active) {
                    HW_LOGI("%s", pending->text.c_str());
                    BroadcastLog("trace", pending->text);
                    pending->active = false;
                }
                engine->clearCallbacks();

                const char* statusStr = "EXECUTION_ERROR";
                switch (rr.status) {
                    case PI::Native::NativeRunResult::OK: statusStr = "OK"; break;
                    case PI::Native::NativeRunResult::MAX_INSTRUCTIONS_REACHED: statusStr = "MAX_INSTRUCTIONS_REACHED"; break;
                    case PI::Native::NativeRunResult::CRASH_PROTECTED: statusStr = "CRASH_PROTECTED"; break;
                    default: statusStr = "EXECUTION_ERROR"; break;
                }

                char resBuf[512];
                snprintf(resBuf, sizeof(resBuf),
                         "[%s] [QBDI TRACE] %s finished: status=%s, insns=%" PRIu64 ", ret=0x%" PRIx64 ", time=%.2f ms",
                         session->soName.c_str(), currentDesc.c_str(), statusStr, rr.instructionsExecuted, rr.gprResult, qbdi_ms);
                HW_LOGI("[constructors] %s", resBuf);
                BroadcastLog("constructors", resBuf);
                BroadcastLog("trace", resBuf);

                bypass = true;
                hwctx.pc = hwctx.lr;
                hwctx.setRet(rr.gprResult);
            }

            if (bypass) {
                hwctx.pc = hwctx.lr;
            }

            session->current_index++;

            if (session->current_index < session->ctors.size()) {
                ArmNextCtor(session);
            } else {
                if (bypass) {
                    uint64_t end_ns = GetMonotonicTimeNs();
                    double last_ms = static_cast<double>(end_ns - session->step_start_ns) / 1000000.0;
                    double total_ms = static_cast<double>(end_ns - session->total_start_ns) / 1000000.0;
                    char finishBuf[512];
                    snprintf(finishBuf, sizeof(finishBuf),
                             "[%s] [%zu/%zu] <- %s finished in %.2f ms (all done, total: %.2f ms)",
                             session->soName.c_str(), session->ctors.size(), session->ctors.size(),
                             session->ctors.back().second.c_str(), last_ms, total_ms);
                    HW_LOGI("[constructors] %s", finishBuf);
                    BroadcastLog("constructors", finishBuf);

                    std::shared_ptr<CtorRelaySession> parentToResume = nullptr;
                    {
                        std::lock_guard<std::mutex> lk(g_ctorMutex);
                        if (!g_ctorStack.empty() && g_ctorStack.back() == session) {
                            g_ctorStack.pop_back();
                        }
                        if (!g_ctorStack.empty()) {
                            parentToResume = g_ctorStack.back();
                        }
                    }
                    if (parentToResume) {
                        ArmNextCtor(parentToResume);
                    }
                } else {
                    session->pending_ret_addr = static_cast<uintptr_t>(hwctx.lr) & ~static_cast<uintptr_t>(1);
                    ArmNextCtor(session);
                }
            }
        };

        uint32_t id = HwHookManager::instance().attach(cfg);
        session->active_hook_id = id;
        if (id == 0) {
            HW_LOGW("ArmNextCtor: failed to arm hardware breakpoint on %s (0x%" PRIxPTR ")",
                    cfg.tag.c_str(), target_addr);
        }
    } else if (session->pending_ret_addr >= 0x1000) {
        uintptr_t retAddr = session->pending_ret_addr;
        HwHookConfig retCfg;
        retCfg.type = HwHookType::BREAKPOINT;
        retCfg.address = retAddr;
        retCfg.thread_id = session->thread_id;
        retCfg.once = true;
        retCfg.tag = session->soName + "!ret";
        retCfg.on_hit = [session](HwCpuContext& /*retCtx*/) {
            session->active_hook_id = 0;
            uint64_t end_ns = GetMonotonicTimeNs();
            double last_ms = static_cast<double>(end_ns - session->step_start_ns) / 1000000.0;
            double total_ms = static_cast<double>(end_ns - session->total_start_ns) / 1000000.0;
            char finishBuf[512];
            snprintf(finishBuf, sizeof(finishBuf),
                     "[%s] [%zu/%zu] <- %s finished in %.2f ms (all done, total: %.2f ms)",
                     session->soName.c_str(), session->ctors.size(), session->ctors.size(),
                     session->ctors.back().second.c_str(), last_ms, total_ms);
            HW_LOGI("[constructors] %s", finishBuf);
            BroadcastLog("constructors", finishBuf);

            std::shared_ptr<CtorRelaySession> parentToResume = nullptr;
            {
                std::lock_guard<std::mutex> lk(g_ctorMutex);
                if (!g_ctorStack.empty() && g_ctorStack.back() == session) {
                    g_ctorStack.pop_back();
                }
                if (!g_ctorStack.empty()) {
                    parentToResume = g_ctorStack.back();
                }
            }
            if (parentToResume) {
                ArmNextCtor(parentToResume);
            }
        };
        session->active_hook_id = HwHookManager::instance().attach(retCfg);
        if (session->active_hook_id == 0) {
            HW_LOGW("ArmNextCtor: failed to arm return hook on 0x%" PRIxPTR " for %s",
                    retAddr, session->soName.c_str());
            std::shared_ptr<CtorRelaySession> parentToResume = nullptr;
            {
                std::lock_guard<std::mutex> lk(g_ctorMutex);
                if (!g_ctorStack.empty() && g_ctorStack.back() == session) {
                    g_ctorStack.pop_back();
                }
                if (!g_ctorStack.empty()) {
                    parentToResume = g_ctorStack.back();
                }
            }
            if (parentToResume) {
                ArmNextCtor(parentToResume);
            }
        }
    }
}

static void HandleCallConstructorsHit(HwCpuContext& hwctx) {
    uintptr_t soinfo_ptr = static_cast<uintptr_t>(hwctx.x[0]);
    if (soinfo_ptr < 0x1000) return;

    static size_t s_ctorsCalledOffset = DetectConstructorsCalledOffset(ResolveCallConstructorsAddress());
    if (s_ctorsCalledOffset > 0 && gum_memory_is_readable(reinterpret_cast<const void*>(soinfo_ptr + s_ctorsCalledOffset), 1)) {
        uint8_t called = *reinterpret_cast<const uint8_t*>(soinfo_ptr + s_ctorsCalledOffset);
        if (called != 0) {
            // Already initialized previously, Bionic will return early without calling constructors
            return;
        }
    }

    ExtractedConstructors ec;
    if (!ExtractConstructorsFromSoinfo(soinfo_ptr, ec)) {
        return;
    }

    // JS onCallConstructors callback
    {
        std::lock_guard<std::mutex> lkCtor(g_ctorJsMutex);
        if (g_ctx && !JS_IsUndefined(g_onCallConstructorsCb) && t_jsReentrancyDepth == 0) {
            std::lock_guard<std::mutex> lk(g_jsMutex);
            JSValue obj = JS_NewObject(g_ctx);
            char hexSoinfo[32], hexBase[32];
            snprintf(hexSoinfo, sizeof(hexSoinfo), "0x%" PRIxPTR, soinfo_ptr);
            snprintf(hexBase, sizeof(hexBase), "0x%" PRIxPTR, ec.base);
            JS_SetPropertyStr(g_ctx, obj, "soinfo", JS_NewString(g_ctx, hexSoinfo));
            JS_SetPropertyStr(g_ctx, obj, "name", JS_NewString(g_ctx, ec.soName.c_str()));
            JS_SetPropertyStr(g_ctx, obj, "base", JS_NewString(g_ctx, hexBase));
            JS_SetPropertyStr(g_ctx, obj, "context", MakeHwContextObject(g_ctx, hwctx, HwHookType::BREAKPOINT));

            JSValue arr = JS_NewArray(g_ctx);
            for (uint32_t i = 0; i < ec.ctors.size(); i++) {
                JSValue item = JS_NewObject(g_ctx);
                char hexCtor[32];
                snprintf(hexCtor, sizeof(hexCtor), "0x%" PRIxPTR, ec.ctors[i].first);
                JS_SetPropertyStr(g_ctx, item, "func", JS_NewString(g_ctx, hexCtor));
                JS_SetPropertyStr(g_ctx, item, "desc", JS_NewString(g_ctx, ec.ctors[i].second.c_str()));
                JS_SetPropertyUint32(g_ctx, arr, i, item);
            }
            JS_SetPropertyStr(g_ctx, obj, "constructors", arr);

            JSValue r = JS_Call(g_ctx, g_onCallConstructorsCb, JS_UNDEFINED, 1, &obj);
            bool bypass = false;
            if (JS_IsBool(r) && !JS_ToBool(g_ctx, r)) {
                bypass = true;
            }
            JS_FreeValue(g_ctx, r);
            JS_FreeValue(g_ctx, obj);
            if (bypass) {
                hwctx.pc = hwctx.lr;
                return;
            }
        }
    }

    if (ec.ctors.empty()) {
        char logBuf[512];
        snprintf(logBuf, sizeof(logBuf),
                 "[%s] (base=0x%" PRIxPTR ") calling constructors: 0 found",
                 ec.soName.c_str(), ec.base);
        HW_LOGI("[constructors] %s", logBuf);
        BroadcastLog("constructors", logBuf);
        return;
    }

    char logBuf[512];
    snprintf(logBuf, sizeof(logBuf),
             "[%s] (base=0x%" PRIxPTR ") calling constructors: %zu found",
             ec.soName.c_str(), ec.base, ec.ctors.size());
    HW_LOGI("[constructors] %s", logBuf);
    BroadcastLog("constructors", logBuf);

    auto session = std::make_shared<CtorRelaySession>();
    session->soName = ec.soName;
    session->base = ec.base;
    session->thread_id = hwctx.thread_id;
    session->ctors = std::move(ec.ctors);
    session->current_index = 0;
    session->total_start_ns = GetMonotonicTimeNs();
    session->step_start_ns = 0;
    session->active_hook_id = 0;

    {
        std::lock_guard<std::mutex> lk(g_ctorMutex);
        if (!g_ctorStack.empty()) {
            auto top = g_ctorStack.back();
            if (top && top->active_hook_id != 0) {
                HwHookManager::instance().detach(top->active_hook_id);
                top->active_hook_id = 0;
            }
        }
        g_ctorStack.push_back(session);
    }

    ArmNextCtor(session);
}

static uint32_t ArmBreakpointOrFallback(uintptr_t target, const std::string& tag, const HwHookCallback& cb) {
    HwHookConfig cfg;
    cfg.type = HwHookType::BREAKPOINT;
    cfg.address = target;
    cfg.slot = -1;
    cfg.thread_id = 0;
    cfg.once = false;
    cfg.tag = tag;
    cfg.on_hit = cb;

    uint32_t id = HwHookManager::instance().attach(cfg);
    if (id > 0) {
        HW_LOGI("[HWBreakpoint] Armed hardware breakpoint on %s at 0x%lx (id #%u)", tag.c_str(), (unsigned long)target, id);
        return id;
    }

    HW_LOGW("[HWBreakpoint] Hardware breakpoint unavailable for %s (0x%lx), falling back to Gum inline hook...",
            tag.c_str(), (unsigned long)target);
    BroadcastLog("console", std::string("[i] Hardware breakpoint unavailable for ") + tag + ", auto-falling back to Gum native inline hook...");

    if (!gum_memory_is_readable(reinterpret_cast<const void*>(target), 4)) {
        HW_LOGW("[HWBreakpoint] Target address 0x%lx is not mapped in memory, cannot apply Gum inline hook fallback",
                (unsigned long)target);
        BroadcastLog("console", "[!] Target address is not mapped in memory, cannot apply Gum inline hook fallback");
        return 0;
    }

    auto onEnter = [cb](GumInvocationContext* ictx) {
        GumCpuContext* cpu = ictx ? ictx->cpu_context : nullptr;
        HwCpuContext hwctx{};
        hwctx.thread_id = static_cast<pid_t>(gettid());
        hwctx.slot = -1;
        hwctx.raw_gum_context = cpu;
#if defined(__aarch64__)
        if (cpu) {
            hwctx.pc = cpu->pc;
            hwctx.sp = cpu->sp;
            hwctx.lr = cpu->lr;
            hwctx.fp = cpu->fp;
            std::memcpy(hwctx.x, cpu->x, sizeof(hwctx.x));
        }
#endif
        cb(hwctx);
    };

    PI::Native::NativeHookHandle handle = PI::Native::GumHooker::hook(reinterpret_cast<void*>(target), onEnter, nullptr);
    if (handle.isValid()) {
        std::lock_guard<std::mutex> lk(g_fallbackMutex);
        uint32_t fid = g_nextFallbackId++;
        g_fallbackHooks.push_back({ fid, target, tag + " (Gum Inline Fallback)", std::move(handle) });
        HW_LOGI("[HWBreakpoint] Armed Gum inline hook fallback for %s at 0x%lx (id #%u)", tag.c_str(), (unsigned long)target, fid);
        return fid;
    }
    return 0;
}

static std::string ExtractSoName(uint64_t addr) {
    if (addr < 0x1000) return "(null/main)";
    char buf[512] = {0};
    const char* str = reinterpret_cast<const char*>(addr);
    for (size_t i = 0; i < sizeof(buf) - 1; i++) {
        char c = str[i];
        if (c == '\0') break;
        buf[i] = c;
    }
    return buf;
}

static JSValue JsHwWatchDlopen(JSContext* ctx, JSValueConst /*this_val*/, int argc, JSValueConst* argv) {
    if (g_dlopenMonitorActive) {
        // The monitor may have been armed from the agent bootstrap while the
        // injector still held the main thread under ptrace, in which case that
        // thread was silently skipped. Retry now that the injector is gone.
        size_t rearmed = HwHookManager::instance().rearmMissingThreads();
        if (rearmed) {
            HW_LOGI("JsHwWatchDlopen: re-armed %zu previously missed thread(s)", rearmed);
        }
        uint32_t activeId = 1;
        int activeSlot = 0;
        for (const auto& s : HwHookManager::instance().listSessions()) {
            if (s.config.tag.find("dlopen") != std::string::npos) {
                activeId = s.id;
                activeSlot = s.assigned_slot;
                break;
            }
        }
        return CreateHandleObject(ctx, activeId, activeSlot, HwHookType::BREAKPOINT, ResolveDlopenAddress());
    }
    std::string stopLib;
    bool libLog = true;
    bool constructors = false;
    JSValue jsCbLoading = JS_UNDEFINED;
    JSValue jsCbLoaded = JS_UNDEFINED;

    if (argc >= 1) {
        if (JS_IsString(argv[0])) {
            const char* s = JS_ToCString(ctx, argv[0]);
            if (s) { stopLib = s; JS_FreeCString(ctx, s); }
        } else if (JS_IsObject(argv[0])) {
            JSValue sVal = JS_GetPropertyStr(ctx, argv[0], "stopLib");
            if (JS_IsString(sVal)) {
                const char* s = JS_ToCString(ctx, sVal);
                if (s) { stopLib = s; JS_FreeCString(ctx, s); }
            }
            JS_FreeValue(ctx, sVal);

            JSValue lVal = JS_GetPropertyStr(ctx, argv[0], "libLog");
            if (!JS_IsUndefined(lVal)) libLog = JS_ToBool(ctx, lVal);
            JS_FreeValue(ctx, lVal);

            JSValue ctVal = JS_GetPropertyStr(ctx, argv[0], "constructors");
            if (!JS_IsUndefined(ctVal)) constructors = JS_ToBool(ctx, ctVal);
            JS_FreeValue(ctx, ctVal);

            JSValue qVal = JS_GetPropertyStr(ctx, argv[0], "qbdi");
            if (JS_IsString(qVal)) {
                const char* s = JS_ToCString(ctx, qVal);
                if (s) { g_qbdiCtorFilter = s; JS_FreeCString(ctx, s); }
                constructors = true;
            }
            JS_FreeValue(ctx, qVal);

            JSValue tiVal = JS_GetPropertyStr(ctx, argv[0], "traceInit");
            if (JS_IsString(tiVal)) {
                const char* s = JS_ToCString(ctx, tiVal);
                if (s) { g_qbdiCtorFilter = s; JS_FreeCString(ctx, s); }
                constructors = true;
            }
            JS_FreeValue(ctx, tiVal);

            JSValue mlVal = JS_GetPropertyStr(ctx, argv[0], "maxLog");
            if (JS_IsNumber(mlVal)) {
                int64_t v = 0;
                JS_ToInt64(ctx, &v, mlVal);
                g_qbdiMaxLog = (v >= 0) ? static_cast<size_t>(v) : 0;
            }
            JS_FreeValue(ctx, mlVal);

            JSValue flVal = JS_GetPropertyStr(ctx, argv[0], "log");
            if (!JS_IsUndefined(flVal) && JS_ToBool(ctx, flVal)) {
                g_qbdiMaxLog = 0;
            }
            JS_FreeValue(ctx, flVal);

            JSValue flVal2 = JS_GetPropertyStr(ctx, argv[0], "fullLog");
            if (!JS_IsUndefined(flVal2) && JS_ToBool(ctx, flVal2)) {
                g_qbdiMaxLog = 0;
            }
            JS_FreeValue(ctx, flVal2);

            JSValue cVal = JS_GetPropertyStr(ctx, argv[0], "onLoading");
            if (JS_IsFunction(ctx, cVal)) jsCbLoading = cVal; else JS_FreeValue(ctx, cVal);

            JSValue dVal = JS_GetPropertyStr(ctx, argv[0], "onLoaded");
            if (JS_IsFunction(ctx, dVal)) jsCbLoaded = dVal; else JS_FreeValue(ctx, dVal);

            JSValue ctorVal = JS_GetPropertyStr(ctx, argv[0], "onConstructor");
            if (JS_IsFunction(ctx, ctorVal)) {
                constructors = true;
                std::lock_guard<std::mutex> lk(g_ctorJsMutex);
                if (g_ctx && !JS_IsUndefined(g_onConstructorCb)) JS_FreeValue(g_ctx, g_onConstructorCb);
                g_onConstructorCb = ctorVal;
            } else {
                JS_FreeValue(ctx, ctorVal);
            }

            JSValue callCtorsVal = JS_GetPropertyStr(ctx, argv[0], "onCallConstructors");
            if (JS_IsFunction(ctx, callCtorsVal)) {
                constructors = true;
                std::lock_guard<std::mutex> lk(g_ctorJsMutex);
                if (g_ctx && !JS_IsUndefined(g_onCallConstructorsCb)) JS_FreeValue(g_ctx, g_onCallConstructorsCb);
                g_onCallConstructorsCb = callCtorsVal;
            } else {
                JS_FreeValue(ctx, callCtorsVal);
            }
        }
        if (argc >= 2 && JS_IsFunction(ctx, argv[1])) {
            constructors = true;
            std::lock_guard<std::mutex> lk(g_ctorJsMutex);
            if (g_ctx && !JS_IsUndefined(g_onConstructorCb)) JS_FreeValue(g_ctx, g_onConstructorCb);
            g_onConstructorCb = JS_DupValue(ctx, argv[1]);
        }
    }

    uintptr_t targetExt = ResolveDlopenExtAddress();
    uintptr_t targetDl = ResolveDlopenAddress();
    if (!targetExt && !targetDl) {
        return JS_ThrowInternalError(ctx, "[!] Failed to resolve android_dlopen_ext / dlopen address");
    }

    auto cbLoadingGuard = std::shared_ptr<JSValue>(new JSValue(jsCbLoading), [](JSValue* p) {
        if (p) {
            if (g_ctx && !JS_IsUndefined(*p)) JS_FreeValue(g_ctx, *p);
            delete p;
        }
    });
    auto cbLoadedGuard = std::shared_ptr<JSValue>(new JSValue(jsCbLoaded), [](JSValue* p) {
        if (p) {
            if (g_ctx && !JS_IsUndefined(*p)) JS_FreeValue(g_ctx, *p);
            delete p;
        }
    });

    auto hitCb = [stopLib, libLog, cbLoadingGuard, cbLoadedGuard](HwCpuContext& hwctx) {
        std::string soPath = ExtractSoName(hwctx.x[0]);

        if (libLog) {
            char logBuf[512];
            snprintf(logBuf, sizeof(logBuf), "Loading SO: %s (caller=0x%" PRIx64 ")",
                     soPath.c_str(), hwctx.lr);
            HW_LOGI("%s", logBuf);
            BroadcastLog("dlopen", logBuf);
        }

        // JS onLoading callback
        JSContext* jsctx = g_ctx;
        if (jsctx && !JS_IsUndefined(*cbLoadingGuard) && t_jsReentrancyDepth == 0) {
            std::lock_guard<std::mutex> lk(g_jsMutex);
            JSValue args[2];
            args[0] = JS_NewString(jsctx, soPath.c_str());
            args[1] = MakeHwContextObject(jsctx, hwctx, HwHookType::BREAKPOINT);
            JSValue r = JS_Call(jsctx, *cbLoadingGuard, JS_UNDEFINED, 2, args);
            JS_FreeValue(jsctx, r);
            JS_FreeValue(jsctx, args[0]);
            JS_FreeValue(jsctx, args[1]);
        }

        // Arm temporary return breakpoint on caller LR to observe onLoaded
        if ((jsctx && !JS_IsUndefined(*cbLoadedGuard)) || !stopLib.empty()) {
            uintptr_t retAddr = static_cast<uintptr_t>(hwctx.lr);
            if (retAddr >= 0x1000) {
                HwHookConfig retCfg;
                retCfg.type = HwHookType::BREAKPOINT;
                retCfg.address = retAddr;
                retCfg.slot = -1;
                retCfg.thread_id = hwctx.thread_id;
                retCfg.once = true; // One-shot return hook
                retCfg.on_hit = [soPath, cbLoadedGuard](HwCpuContext& retCtx) {
                    uint64_t handle = retCtx.x[0];
                    char logBuf[512];
                    snprintf(logBuf, sizeof(logBuf), "Loaded SO: %s -> handle=0x%" PRIx64,
                             soPath.c_str(), handle);
                    HW_LOGI("%s", logBuf);
                    BroadcastLog("dlopen", logBuf);

                    JSContext* c = g_ctx;
                    if (c && !JS_IsUndefined(*cbLoadedGuard) && t_jsReentrancyDepth == 0) {
                        std::lock_guard<std::mutex> lk(g_jsMutex);
                        JSValue a[3];
                        a[0] = JS_NewString(c, soPath.c_str());
                        a[1] = NewBigIntOrInt(c, handle);
                        a[2] = MakeHwContextObject(c, retCtx, HwHookType::BREAKPOINT);
                        JSValue r = JS_Call(c, *cbLoadedGuard, JS_UNDEFINED, 3, a);
                        JS_FreeValue(c, r);
                        JS_FreeValue(c, a[0]);
                        JS_FreeValue(c, a[1]);
                        JS_FreeValue(c, a[2]);
                    }
                };
                HwHookManager::instance().attach(retCfg);
            }
        }

        // If matched stopLib, pause main thread right at dlopen entry
        if (!stopLib.empty() && soPath.find(stopLib) != std::string::npos) {
            char stopMsg[512];
            snprintf(stopMsg, sizeof(stopMsg),
                     "[+] [stop-lib] Target library '%s' intercepted at dlopen! Main thread PAUSED. (type 'resume' to continue)",
                     soPath.c_str());
            HW_LOGI("%s", stopMsg);
            BroadcastLog("dlopen", stopMsg);
            ArtPIPauseCurrentThread(hwctx.pc);
        }
    };

    uint32_t id1 = 0, id2 = 0;
    if (targetExt) {
        id1 = ArmBreakpointOrFallback(targetExt, "android_dlopen_ext", hitCb);
    }
    if (targetDl && targetDl != targetExt) {
        id2 = ArmBreakpointOrFallback(targetDl, "dlopen", hitCb);
    }

    if (constructors) {
        uintptr_t targetCtors = ResolveCallConstructorsAddress();
        if (targetCtors) {
            uint32_t cid = ArmBreakpointOrFallback(targetCtors, "call_constructors", HandleCallConstructorsHit);
            if (cid > 0) {
                HW_LOGI("JsHwWatchDlopen: armed soinfo::call_constructors hook (id #%u)", cid);
            }
        }
    }

    if (id1 == 0 && id2 == 0) {
        return JS_ThrowInternalError(ctx, "[!] Failed to attach hardware breakpoint or fallback on dlopen");
    }

    uint32_t primaryId = id1 ? id1 : id2;
    uintptr_t primaryAddr = id1 ? targetExt : targetDl;
    int assignedSlot = -1;
    for (const auto& s : HwHookManager::instance().listSessions()) {
        if (s.id == primaryId) { assignedSlot = s.assigned_slot; break; }
    }

    return CreateHandleObject(ctx, primaryId, assignedSlot, HwHookType::BREAKPOINT, primaryAddr);
}

} // namespace

void RegisterHwHookApis(JSContext* ctx, JSValue global) {
    // 0. Modern HW unified namespace (HW.attach & HW.watch)
    JSValue hw = JS_NewObject(ctx);
    JS_SetPropertyStr(ctx, hw, "attach", JS_NewCFunction(ctx, JsHwBreakpointAttach, "attach", 2));
    JS_SetPropertyStr(ctx, hw, "watch", JS_NewCFunction(ctx, JsHwWatchpointAttach, "watch", 2));
    JS_SetPropertyStr(ctx, hw, "detach", JS_NewCFunction(ctx, JsHwBreakpointDetach, "detach", 1));
    JS_SetPropertyStr(ctx, hw, "detachAll", JS_NewCFunction(ctx, JsHwBreakpointDetachAll, "detachAll", 0));
    JS_SetPropertyStr(ctx, hw, "list", JS_NewCFunction(ctx, JsHwBreakpointList, "list", 0));
    JS_SetPropertyStr(ctx, hw, "watchDlopen", JS_NewCFunction(ctx, JsHwWatchDlopen, "watchDlopen", 1));
    JS_SetPropertyStr(ctx, global, "HW", hw);

    // 1. HWBreakpoint class/namespace (backward compat)
    JSValue bp = JS_NewObject(ctx);
    JS_SetPropertyStr(ctx, bp, "attach", JS_NewCFunction(ctx, JsHwBreakpointAttach, "attach", 2));
    JS_SetPropertyStr(ctx, bp, "detach", JS_NewCFunction(ctx, JsHwBreakpointDetach, "detach", 1));
    JS_SetPropertyStr(ctx, bp, "detachAll", JS_NewCFunction(ctx, JsHwBreakpointDetachAll, "detachAll", 0));
    JS_SetPropertyStr(ctx, bp, "list", JS_NewCFunction(ctx, JsHwBreakpointList, "list", 0));
    JS_SetPropertyStr(ctx, global, "HWBreakpoint", bp);

    // 2. HWWatchpoint class/namespace (backward compat)
    JSValue wp = JS_NewObject(ctx);
    JS_SetPropertyStr(ctx, wp, "attach", JS_NewCFunction(ctx, JsHwWatchpointAttach, "attach", 2));
    JS_SetPropertyStr(ctx, wp, "detach", JS_NewCFunction(ctx, JsHwBreakpointDetach, "detach", 1));
    JS_SetPropertyStr(ctx, wp, "detachAll", JS_NewCFunction(ctx, JsHwBreakpointDetachAll, "detachAll", 0));
    JS_SetPropertyStr(ctx, wp, "list", JS_NewCFunction(ctx, JsHwBreakpointList, "list", 0));
    JS_SetPropertyStr(ctx, global, "HWWatchpoint", wp);

    // 3. Flat convenient aliases
    JS_SetPropertyStr(ctx, global, "hwhook", JS_NewCFunction(ctx, JsHwBreakpointAttach, "hwhook", 2));
    JS_SetPropertyStr(ctx, global, "hwwatch", JS_NewCFunction(ctx, JsHwWatchpointAttach, "hwwatch", 2));
    JS_SetPropertyStr(ctx, global, "hwunhook", JS_NewCFunction(ctx, JsHwBreakpointDetach, "hwunhook", 1));
    JS_SetPropertyStr(ctx, global, "hwunhookall", JS_NewCFunction(ctx, JsHwBreakpointDetachAll, "hwunhookall", 0));
}

size_t HwHookDetachAll() {
    size_t count = HwHookManager::instance().detachAll();
    {
        std::lock_guard<std::mutex> lk(g_ctorMutex);
        g_ctorStack.clear();
        g_qbdiCtorFilter.clear();
        g_qbdiMaxLog = 100;
    }
    {
        std::lock_guard<std::mutex> lk(g_ctorJsMutex);
        if (g_ctx) {
            if (!JS_IsUndefined(g_onConstructorCb)) {
                JS_FreeValue(g_ctx, g_onConstructorCb);
                g_onConstructorCb = JS_UNDEFINED;
            }
            if (!JS_IsUndefined(g_onCallConstructorsCb)) {
                JS_FreeValue(g_ctx, g_onCallConstructorsCb);
                g_onCallConstructorsCb = JS_UNDEFINED;
            }
        }
    }
    {
        std::lock_guard<std::mutex> lk(g_fallbackMutex);
        for (auto& f : g_fallbackHooks) {
            if (f.handle.isValid()) {
                f.handle.unhook();
                count++;
            }
        }
        g_fallbackHooks.clear();
    }
    return count;
}

std::vector<HwHookInfo> HwHookListAll() {
    std::vector<HwHookInfo> res;
    for (const auto& s : HwHookManager::instance().listSessions()) {
        auto tn = magic_enum::enum_name(s.config.type);
        std::string typeStr = tn.empty() ? (s.config.type == HwHookType::BREAKPOINT ? "BREAKPOINT" : "WATCHPOINT") : std::string(tn);
        std::string condStr = "";
        if (s.config.type == HwHookType::WATCHPOINT) {
            int cond = static_cast<int>(s.config.condition);
            if ((cond & 3) == 3) condStr = "rw";
            else if (cond & 1) condStr = "r";
            else if (cond & 2) condStr = "w";
        }
        res.push_back({
            s.id,
            typeStr,
            s.assigned_slot,
            s.config.address,
            s.config.tag,
            s.armed_threads.size(),
            s.config.size,
            condStr
        });
    }
    {
        std::lock_guard<std::mutex> lk(g_fallbackMutex);
        for (const auto& f : g_fallbackHooks) {
            if (f.handle.isValid()) {
                res.push_back({
                    f.id,
                    "GUM_INLINE_FALLBACK",
                    -1,
                    f.address,
                    f.tag,
                    0,
                    0,
                    ""
                });
            }
        }
    }
    return res;
}

HwSlotStatus HwHookGetSlotStatus() {
    HwSlotStatus st{};
    // Ensure the manager is initialized (so the capacity is known) as this
    // also serves the `L()` dashboard when no hardware hook is active yet.
    HwHookManager::instance().init();
    HwHookManager::instance().refreshCapacity();
    HwHookManager::instance().getSlotStatus(st.bp_slots, st.wp_slots,
                                            &st.bp_capacity, &st.wp_capacity);
    return st;
}

size_t HwHookRearmMissingThreads() {
    return HwHookManager::instance().rearmMissingThreads();
}

bool HwHookMainThreadArmed() {
    pid_t mainTid = getpid();
    for (const auto& s : HwHookManager::instance().listSessions()) {
        if (s.active && s.armed_threads.count(mainTid)) return true;
    }
    return false;
}

void HwHookRefreshCapacity() {
    HwHookManager::instance().refreshCapacity();
}

bool SetupDlopenHwMonitor(const std::string& stopLib, bool libLog, bool constructors, const std::string& qbdiFilter, size_t qbdiMaxLog) {
    if (!qbdiFilter.empty()) {
        g_qbdiCtorFilter = qbdiFilter;
        g_qbdiMaxLog = qbdiMaxLog;
        constructors = true;
    }
    if (g_dlopenMonitorActive) {
        // Early boot may have raced with the injector's ptrace attachment.
        HwHookManager::instance().rearmMissingThreads();
        return true;
    }
    uintptr_t targetExt = ResolveDlopenExtAddress();
    uintptr_t targetDl = ResolveDlopenAddress();
    if (!targetExt && !targetDl) {
        HW_LOGE("SetupDlopenHwMonitor: failed to resolve dlopen / android_dlopen_ext address");
        return false;
    }

    auto hitCb = [stopLib, libLog](HwCpuContext& hwctx) {
        std::string soPath = ExtractSoName(hwctx.x[0]);

        if (libLog) {
            char logBuf[512];
            snprintf(logBuf, sizeof(logBuf), "Loading SO: %s (caller=0x%" PRIx64 ")",
                     soPath.c_str(), hwctx.lr);
            HW_LOGI("%s", logBuf);
            BroadcastLog("dlopen", logBuf);
        }

        if (!stopLib.empty() && soPath.find(stopLib) != std::string::npos) {
            char stopMsg[512];
            snprintf(stopMsg, sizeof(stopMsg),
                     "[+] [stop-lib] Target library '%s' intercepted at dlopen! Main thread PAUSED. (type 'resume' to continue)",
                     soPath.c_str());
            HW_LOGI("%s", stopMsg);
            BroadcastLog("dlopen", stopMsg);
            ArtPIPauseCurrentThread(hwctx.pc);
        }
    };

    bool ok = false;
    if (targetExt) {
        uint32_t id1 = ArmBreakpointOrFallback(targetExt, "android_dlopen_ext", hitCb);
        if (id1 > 0) {
            HW_LOGI("SetupDlopenHwMonitor: armed android_dlopen_ext hook (id #%u, stopLib='%s', libLog=%d)",
                    id1, stopLib.c_str(), libLog ? 1 : 0);
            ok = true;
        }
    }
    if (targetDl && targetDl != targetExt) {
        uint32_t id2 = ArmBreakpointOrFallback(targetDl, "dlopen", hitCb);
        if (id2 > 0) {
            HW_LOGI("SetupDlopenHwMonitor: armed dlopen hook (id #%u, stopLib='%s', libLog=%d)",
                    id2, stopLib.c_str(), libLog ? 1 : 0);
            ok = true;
        }
    }

    if (constructors) {
        uintptr_t targetCtors = ResolveCallConstructorsAddress();
        if (targetCtors) {
            uint32_t cid = ArmBreakpointOrFallback(targetCtors, "call_constructors", HandleCallConstructorsHit);
            if (cid > 0) {
                HW_LOGI("SetupDlopenHwMonitor: armed soinfo::call_constructors hook (id #%u)", cid);
            }
        } else {
            HW_LOGW("SetupDlopenHwMonitor: could not resolve soinfo::call_constructors in linker");
        }
    }

    if (ok) g_dlopenMonitorActive = true;
    return ok;
}

}} // namespace artpi::agent
