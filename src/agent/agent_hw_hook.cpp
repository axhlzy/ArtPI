//
// agent_hw_hook.cpp - QuickJS Bindings for Hardware Breakpoints & Watchpoints
//
#include "agent_hw_hook.h"
#include "agent_common.h"
#include "agent_net.h"
#include "native/hooker/pi_hw_hook.h"
#include "native/hooker/pi_gum_hooker.h"
#include "frida-gum.h"
#include <unistd.h>
#include "xdl.h"

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
    size_t count = HwHookManager::instance().detachAll();
    char buf[64];
    snprintf(buf, sizeof(buf), "Detached %zu hardware breakpoint(s)", count);
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
                    if (strcmp(cs, "r") == 0) condition = HwWatchCondition::READ;
                    else if (strcmp(cs, "w") == 0) condition = HwWatchCondition::WRITE;
                    else if (strcmp(cs, "rw") == 0) condition = HwWatchCondition::READ_WRITE;
                    JS_FreeCString(ctx, cs);
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

            JSValue cVal = JS_GetPropertyStr(ctx, argv[0], "onLoading");
            if (JS_IsFunction(ctx, cVal)) jsCbLoading = cVal; else JS_FreeValue(ctx, cVal);

            JSValue dVal = JS_GetPropertyStr(ctx, argv[0], "onLoaded");
            if (JS_IsFunction(ctx, dVal)) jsCbLoaded = dVal; else JS_FreeValue(ctx, dVal);
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
        std::string typeStr = (s.config.type == HwHookType::BREAKPOINT) ? "BREAKPOINT" : "WATCHPOINT";
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

bool SetupDlopenHwMonitor(const std::string& stopLib, bool libLog) {
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
    if (ok) g_dlopenMonitorActive = true;
    return ok;
}

}} // namespace artpi::agent
