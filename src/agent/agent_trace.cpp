//
// agent_trace.cpp - Trace domain bindings for QuickJS (Unified, Java, Native)
//
// Honors the optional `opt` / `new TraceOption()` object:
//   mode          "CALL_TREE" (default) | "INSN_STEP"/"INSTRUCTION_DIFF"
//   excludeSystem  bool  (default true)  — drop java.*/android.* & /system,/apex,/vendor events
//   includeNative  string               — only deliver native events whose module matches
//   maxDepth       int                  — StepIn depth budget when INSN_STEP
//   onEnter/onLeave/onInsn              — JS callbacks (kept alive for the hook lifetime)
//
#include "agent_trace.h"
#include "agent_common.h"
#include "agent_java.h"
#include "agent_net.h"
#include "../../include/ArtPI.h"
#include "native/hooker/pi_gum_hooker.h"
#include "frida-gum.h"
#include "art/art_method.h"

#include <string>
#include <vector>
#include <cstdio>
#include <memory>
#include <mutex>
#include <sstream>
#include <cstring>

namespace artpi { namespace agent {

size_t TraceStopAll();   // defined after the anonymous namespace

namespace {

struct ActiveTraceSession {
    size_t id;
    bool is_active;
    std::string tag;
    PI::HookHandle java_handle;
    PI::Native::NativeHookHandle native_handle;
};

static std::vector<ActiveTraceSession> g_activeTraces;
static std::mutex g_traceMutex;

// ---------------------------------------------------------------------------
// Option parsing
// ---------------------------------------------------------------------------
struct TraceOpt {
    std::string mode = "CALL_TREE";
    bool excludeSystem = true;
    std::string includeNative;
    int maxDepth = 8;
    std::shared_ptr<JSValue> onEnter, onLeave, onInsn;
};

static std::shared_ptr<JSValue> GuardJsValue(JSValue v) {
    return std::shared_ptr<JSValue>(new JSValue(v), [](JSValue* p) {
        if (p) {
            if (g_ctx && !JS_IsUndefined(*p)) JS_FreeValue(g_ctx, *p);
            delete p;
        }
    });
}

static TraceOpt ParseTraceOpt(JSContext* ctx, JSValueConst opt) {
    TraceOpt o;
    if (!ctx || !JS_IsObject(opt)) return o;

    JSValue v = JS_GetPropertyStr(ctx, opt, "mode");
    if (JS_IsString(v)) { const char* s = JS_ToCString(ctx, v); if (s) { o.mode = s; JS_FreeCString(ctx, s); } }
    JS_FreeValue(ctx, v);

    v = JS_GetPropertyStr(ctx, opt, "excludeSystem");
    if (!JS_IsUndefined(v)) o.excludeSystem = (JS_ToBool(ctx, v) != 0);
    JS_FreeValue(ctx, v);

    v = JS_GetPropertyStr(ctx, opt, "includeNative");
    if (JS_IsString(v)) { const char* s = JS_ToCString(ctx, v); if (s) { o.includeNative = s; JS_FreeCString(ctx, s); } }
    JS_FreeValue(ctx, v);

    v = JS_GetPropertyStr(ctx, opt, "maxDepth");
    if (JS_IsNumber(v)) JS_ToInt32(ctx, &o.maxDepth, v);
    JS_FreeValue(ctx, v);

    v = JS_GetPropertyStr(ctx, opt, "onEnter");
    if (JS_IsFunction(ctx, v)) o.onEnter = GuardJsValue(v); else JS_FreeValue(ctx, v);
    v = JS_GetPropertyStr(ctx, opt, "onLeave");
    if (JS_IsFunction(ctx, v)) o.onLeave = GuardJsValue(v); else JS_FreeValue(ctx, v);
    v = JS_GetPropertyStr(ctx, opt, "onInsn");
    if (JS_IsFunction(ctx, v)) o.onInsn = GuardJsValue(v); else JS_FreeValue(ctx, v);

    return o;
}

// ---------------------------------------------------------------------------
// Filters
// ---------------------------------------------------------------------------
// Warm the interpreter's class-ref cache for `dotted` (eval-time, safe).
// The interpreted (hook-path) code resolves referenced classes via this cache;
// without it, resolveArtMethod falls back to env->FindClass and crashes inside
// the frameless trampoline. Auto-called for the traced method's declaring class.
static void WarmInterpClass(JNIEnv* env, const std::string& dotted) {
    if (!env || dotted.empty()) return;
    jclass cls = artpi::agent::FindClassWithFallback(env, dotted);
    if (env->ExceptionCheck()) env->ExceptionClear();
    if (!cls) return;
    std::string slash = dotted;
    for (char& c : slash) if (c == '.') c = '/';
    PI::Interp::RegisterClassRef(env, slash.c_str(), cls);
    env->DeleteLocalRef(cls);
}

static bool IsSystemJavaName(const std::string& n) {
    static const char* kSys[] = {"java.", "javax.", "android.", "androidx.", "kotlin.",
                                 "dalvik.", "libcore.", "sun.", "org.apache.harmony."};
    for (const char* p : kSys) {
        if (n.rfind(p, 0) == 0) return true;
    }
    return false;
}

static bool NativeModuleAllowed(uint64_t addr, const TraceOpt& opt, std::string* outPath) {
    xdl_info_t info;
    std::memset(&info, 0, sizeof(info));
    void* cache = nullptr;
    std::string path;
    if (xdl_addr(reinterpret_cast<void*>(addr), &info, &cache) != 0 && info.dli_fname) {
        path = info.dli_fname;
    }
    if (cache) xdl_addr_clean(&cache);
    if (outPath) *outPath = path;

    if (!opt.includeNative.empty() && path.find(opt.includeNative) == std::string::npos) return false;
    if (opt.excludeSystem && (path.rfind("/system/", 0) == 0 || path.rfind("/apex/", 0) == 0 ||
                              path.rfind("/vendor/", 0) == 0)) {
        return false;
    }
    return true;
}

// ---------------------------------------------------------------------------
// JS callback helpers
// ---------------------------------------------------------------------------
static void CallJsCb1(JSContext* ctx, const std::shared_ptr<JSValue>& cb, JSValueConst arg) {
    if (!ctx || !cb || JS_IsUndefined(*cb)) return;
    std::lock_guard<std::mutex> lk(g_jsMutex);
    JSValue r = JS_Call(ctx, *cb, JS_UNDEFINED, 1, &arg);
    if (JS_IsException(r)) {
        JSValue exc = JS_GetException(ctx);
        const char* e = JS_ToCString(ctx, exc);
        if (e) { BroadcastLog("console", std::string("[trace cb] ") + e); JS_FreeCString(ctx, e); }
        JS_FreeValue(ctx, exc);
    }
    JS_FreeValue(ctx, r);
}

static JSValue MakeJavaEvent(JSContext* ctx, const PI::CallFrame& frame, const std::string& symbol,
                             bool leave) {
    JSValue o = JS_NewObject(ctx);
    JS_SetPropertyStr(ctx, o, "layer", JS_NewString(ctx, "JAVA"));
    JS_SetPropertyStr(ctx, o, "symbol", JS_NewString(ctx, symbol.c_str()));
    JS_SetPropertyStr(ctx, o, "method", JS_NewString(ctx, frame.getMethodName().c_str()));
    JS_SetPropertyStr(ctx, o, "class", JS_NewString(ctx, frame.class_name.c_str()));
    JS_SetPropertyStr(ctx, o, "argc", JS_NewInt32(ctx, frame.getArgCount()));
    JSValue args = JS_NewArray(ctx);
    for (int i = 0; i < frame.getArgCount(); i++) {
        JS_SetPropertyUint32(ctx, args, (uint32_t) i, JS_NewBigInt64(ctx, (int64_t) frame.getArgRaw(i)));
    }
    JS_SetPropertyStr(ctx, o, "args", args);
    JS_SetPropertyStr(ctx, o, "str", JS_NewString(ctx, frame.toValueString().c_str()));
    if (leave) {
        JS_SetPropertyStr(ctx, o, "ret", JS_NewString(ctx, frame.getResultString().c_str()));
    }
    return o;
}

static JSValue MakeNativeEvent(JSContext* ctx, const std::string& symbol, uint64_t addr,
                               GumInvocationContext* g, bool leave) {
    JSValue o = JS_NewObject(ctx);
    JS_SetPropertyStr(ctx, o, "layer", JS_NewString(ctx, "NATIVE"));
    JS_SetPropertyStr(ctx, o, "symbol", JS_NewString(ctx, symbol.c_str()));
    JS_SetPropertyStr(ctx, o, "address", JS_NewBigInt64(ctx, (int64_t) addr));
    if (!leave) {
        JSValue args = JS_NewArray(ctx);
        for (int i = 0; i < 8; i++) {
            gpointer a = g ? gum_invocation_context_get_nth_argument(g, (guint) i) : nullptr;
            JS_SetPropertyUint32(ctx, args, (uint32_t) i, JS_NewBigInt64(ctx, (int64_t)(intptr_t) a));
        }
        JS_SetPropertyStr(ctx, o, "args", args);
    } else {
        gpointer rv = g ? gum_invocation_context_get_return_value(g) : nullptr;
        JS_SetPropertyStr(ctx, o, "ret", JS_NewBigInt64(ctx, (int64_t)(intptr_t) rv));
    }
    return o;
}

// TraceOption constructor
static JSValue JsTraceOptionConstructor(JSContext* ctx, JSValueConst new_target, int /*argc*/, JSValueConst* /*argv*/) {
    JSValue obj = JS_NewObjectClass(ctx, JS_GetClassID(new_target));
    if (JS_IsException(obj)) obj = JS_NewObject(ctx);

    JS_SetPropertyStr(ctx, obj, "mode", JS_NewString(ctx, "CALL_TREE"));
    JS_SetPropertyStr(ctx, obj, "includeNative", JS_NewString(ctx, ""));
    JS_SetPropertyStr(ctx, obj, "excludeSystem", JS_NewBool(ctx, true));
    JS_SetPropertyStr(ctx, obj, "maxDepth", JS_NewInt32(ctx, 8));
    JS_SetPropertyStr(ctx, obj, "onEnter", JS_NULL);
    JS_SetPropertyStr(ctx, obj, "onLeave", JS_NULL);
    JS_SetPropertyStr(ctx, obj, "onInsn", JS_NULL);

    return obj;
}

// Stop one trace by id. Returns true if it was active.
static bool StopTraceById(int32_t id) {
    std::lock_guard<std::mutex> lk(g_traceMutex);
    for (auto& s : g_activeTraces) {
        if (s.id == static_cast<size_t>(id) && s.is_active) {
            s.is_active = false;
            if (s.java_handle.isHooked()) s.java_handle.unhook();
            if (s.native_handle.isValid()) s.native_handle.unhook();
            return true;
        }
    }
    return false;
}

// Trace Handle stop() method
static JSValue JsTraceStop(JSContext* ctx, JSValueConst this_val, int /*argc*/, JSValueConst* /*argv*/) {
    JSValue idVal = JS_GetPropertyStr(ctx, this_val, "_id");
    int32_t id = -1;
    if (JS_IsNumber(idVal)) JS_ToInt32(ctx, &id, idVal);
    JS_FreeValue(ctx, idVal);

    if (id < 0) return JS_NewString(ctx, "[!] Invalid trace handle");
    return JS_NewString(ctx, StopTraceById(id) ? "Trace stopped" : "[*] Trace already stopped");
}

// untrace()      -> stop ALL traces
// untrace(id)    -> stop one trace by id
static JSValue JsUntrace(JSContext* ctx, JSValueConst /*this_val*/, int argc, JSValueConst* argv) {
    if (argc >= 1 && JS_IsNumber(argv[0])) {
        int32_t id = -1;
        JS_ToInt32(ctx, &id, argv[0]);
        if (id < 0) return JS_NewString(ctx, "[!] Invalid trace id");
        return JS_NewString(ctx, StopTraceById(id) ? "Trace stopped" : "[*] Trace already stopped");
    }
    size_t n = TraceStopAll();
    char buf[64];
    snprintf(buf, sizeof(buf), "Stopped %zu trace(s)", n);
    return JS_NewString(ctx, buf);
}

static JSValue JsTraceHandleToString(JSContext* ctx, JSValueConst this_val, int /*argc*/, JSValueConst* /*argv*/) {
    JSValue idV = JS_GetPropertyStr(ctx, this_val, "_id");
    int32_t id = -1;
    if (JS_IsNumber(idV)) JS_ToInt32(ctx, &id, idV);
    JS_FreeValue(ctx, idV);
    JSValue tV = JS_GetPropertyStr(ctx, this_val, "target");
    const char* t = JS_IsString(tV) ? JS_ToCString(ctx, tV) : nullptr;
    char buf[640];
    snprintf(buf, sizeof(buf), "[Trace %s (id=%d) — .stop() or untrace()]", t ? t : "?", (int) id);
    if (t) JS_FreeCString(ctx, t);
    JS_FreeValue(ctx, tV);
    return JS_NewString(ctx, buf);
}

static JSValue CreateTraceHandle(JSContext* ctx, size_t traceId, const std::string& desc) {
    JSValue handle = JS_NewObject(ctx);
    JS_SetPropertyStr(ctx, handle, "_id", JS_NewInt32(ctx, static_cast<int32_t>(traceId)));
    JS_SetPropertyStr(ctx, handle, "target", JS_NewString(ctx, desc.c_str()));
    JS_SetPropertyStr(ctx, handle, "stop", JS_NewCFunction(ctx, JsTraceStop, "stop", 0));
    JS_SetPropertyStr(ctx, handle, "toString", JS_NewCFunction(ctx, JsTraceHandleToString, "toString", 0));
    return handle;
}

static size_t RegisterSession(const std::string& desc, PI::HookHandle jh,
                              PI::Native::NativeHookHandle nh) {
    std::lock_guard<std::mutex> lk(g_traceMutex);
    size_t id = g_activeTraces.size();
    ActiveTraceSession session;
    session.id = id;
    session.is_active = true;
    session.tag = desc;
    session.java_handle = std::move(jh);
    session.native_handle = std::move(nh);
    g_activeTraces.push_back(std::move(session));
    return id;
}

// Stop any active trace already targeting the same method/symbol. Repeated
// .trace() calls must not stack multiple hooks on one ArtMethod (that corrupts
// the trampoline and crashes the target process).
static void StopExistingTrace(const std::string& desc, ArtMethod* am) {
    std::lock_guard<std::mutex> lk(g_traceMutex);
    for (auto& s : g_activeTraces) {
        if (!s.is_active) continue;
        bool same = (!desc.empty() && s.tag == desc);
        if (!same && am && s.java_handle.isHooked() &&
            reinterpret_cast<void*>(s.java_handle.getArtMethod()) == reinterpret_cast<void*>(am)) {
            same = true;
        }
        if (same) {
            s.is_active = false;
            if (s.java_handle.isHooked()) s.java_handle.unhook();
            if (s.native_handle.isValid()) s.native_handle.unhook();
        }
    }
    // Also drop a plain `jhook` on the same method (avoid hook+trace stacking).
    if (am) JavaUnhookMethod(reinterpret_cast<void*>(am));
}

// ---------------------------------------------------------------------------
// tracejava
// ---------------------------------------------------------------------------
static JSValue JsTraceJava(JSContext* ctx, JSValueConst /*this_val*/, int argc, JSValueConst* argv) {
    if (argc < 1) return JS_NewString(ctx, "Usage: tracejava(method, [opt])");
    int64_t ptr = ParsePtr(ctx, argv[0]);
    if (!ptr || ptr < 0x1000) return JS_NewString(ctx, "[!] Invalid method pointer");

    PI::Method m = PI::resolve(reinterpret_cast<ArtMethod*>(ptr));
    if (!m.isValid()) return JS_NewString(ctx, "[!] Cannot resolve ArtMethod");

    std::string desc = m.toString();
    std::string clsName = m.getDeclaringClassName();
    WarmInterpClass(GetEnv(), clsName);   // so INSN_STEP can resolve same-class calls
    bool sysCls = IsSystemJavaName(clsName);

    StopExistingTrace(desc, reinterpret_cast<ArtMethod*>(ptr));

    TraceOpt opt = ParseTraceOpt(ctx, argc >= 2 ? argv[1] : JS_UNDEFINED);
    bool insnStep = (opt.mode == "INSN_STEP" || opt.mode == "INSTRUCTION_DIFF");

    bool sysClsCopy = sysCls;
    std::string descCopy = desc;
    auto cbEnter = opt.onEnter, cbLeave = opt.onLeave, cbInsn = opt.onInsn;
    bool excludeSystem = opt.excludeSystem;
    int maxDepth = opt.maxDepth;

    PI::HookHandle hh = m.hook([descCopy, sysClsCopy, insnStep, excludeSystem, maxDepth,
                                cbEnter, cbLeave, cbInsn](JNIEnv*, PI::CallFrame& frame) {
        JSContext* jsctx = g_ctx;
        bool deliver = !(excludeSystem && sysClsCopy);

        if (deliver && jsctx) {
            JSValue ev = MakeJavaEvent(jsctx, frame, descCopy, false);
            CallJsCb1(jsctx, cbEnter, ev);
            JS_FreeValue(jsctx, ev);
        } else if (!jsctx) {
            BroadcastLog("trace", "[Trace::Java] entered " + descCopy);
        }

        if (insnStep && cbInsn) {
            auto insnCb = cbInsn;
            int budget = maxDepth > 0 ? maxDepth : 0;
            auto counter = std::make_shared<int>(0);
            PI::Interp::Callbacks cbs;
            cbs.onInsn = [insnCb, counter, budget](const PI::Interp::InsnEvent& e) -> bool {
                JSContext* c = g_ctx;
                if (!c) return true;
                (*counter)++;
                std::lock_guard<std::mutex> lk(g_jsMutex);
                JSValue o = JS_NewObject(c);
                JS_SetPropertyStr(c, o, "depth", JS_NewInt32(c, e.depth));
                JS_SetPropertyStr(c, o, "pc", JS_NewInt64(c, (int64_t) e.pc));
                JS_SetPropertyStr(c, o, "inst", JS_NewInt32(c, (int32_t) e.inst));
                JS_SetPropertyStr(c, o, "count", JS_NewInt64(c, (int64_t) e.insns_executed));
                // Rich per-instruction info: decoded Smali line + current vregs.
                if (e.artMethod) {
                    std::string smali = PI::dumpSmaliInsn(
                        reinterpret_cast<ArtMethod*>(e.artMethod), e.pc);
                    if (!smali.empty()) JS_SetPropertyStr(c, o, "smali", JS_NewString(c, smali.c_str()));
                }
                if (e.regs && e.regsSize) {
                    std::string rs;
                    char rb[48];
                    uint32_t rn = e.regsSize > 32 ? 32 : e.regsSize;
                    for (uint32_t i = 0; i < rn; i++) {
                        snprintf(rb, sizeof(rb), "v%u=0x%llx%s", i,
                                 (unsigned long long) e.regs[i],
                                 (e.regFlags && e.regFlags[i]) ? "(o) " : " ");
                        rs += rb;
                    }
                    JS_SetPropertyStr(c, o, "regs", JS_NewString(c, rs.c_str()));
                }
                JSValue r = JS_Call(c, *insnCb, JS_UNDEFINED, 1, &o);
                bool cont = true;
                if (JS_IsException(r)) { JS_FreeValue(c, JS_GetException(c)); }
                else if (JS_IsBool(r)) cont = (JS_ToBool(c, r) != 0);
                if (budget > 0 && *counter >= budget) cont = false;
                JS_FreeValue(c, r);
                JS_FreeValue(c, o);
                return cont;
            };
            frame.invokeInterpretedWith(cbs);
        } else {
            frame.invokeOriginal();
        }

        if (deliver && jsctx) {
            JSValue ev = MakeJavaEvent(jsctx, frame, descCopy, true);
            CallJsCb1(jsctx, cbLeave, ev);
            JS_FreeValue(jsctx, ev);
        }
    });

    if (!hh.isHooked()) return JS_NewString(ctx, "[!] Failed to install Java trace hook");
    size_t id = RegisterSession(desc, std::move(hh), PI::Native::NativeHookHandle());

    BroadcastLog("trace", "Started Java tracing: " + desc);
    return CreateTraceHandle(ctx, id, desc);
}

// ---------------------------------------------------------------------------
// tracenative
// ---------------------------------------------------------------------------
static JSValue JsTraceNative(JSContext* ctx, JSValueConst /*this_val*/, int argc, JSValueConst* argv) {
    if (argc < 1) return JS_NewString(ctx, "Usage: tracenative(address, [opt])");
    int64_t addr = ParsePtr(ctx, argv[0]);
    if (!addr || addr < 0x1000) return JS_NewString(ctx, "[!] Invalid native address");

    TraceOpt opt = ParseTraceOpt(ctx, argc >= 2 ? argv[1] : JS_UNDEFINED);
    if (!NativeModuleAllowed((uint64_t) addr, opt, nullptr) && !opt.onEnter && !opt.onLeave) {
        // Filtered and no callbacks -> nothing to do.
        return JS_NewString(ctx, "[*] target filtered out (excludeSystem/includeNative)");
    }

    void* target = reinterpret_cast<void*>(addr);
    char buf[64];
    snprintf(buf, sizeof(buf), "0x%llx", (unsigned long long) addr);
    std::string desc = buf;

    StopExistingTrace(desc, nullptr);

    auto cbEnter = opt.onEnter, cbLeave = opt.onLeave;
    bool excludeSystem = opt.excludeSystem;
    std::string includeNative = opt.includeNative;

    auto allowed = [addr, excludeSystem, includeNative]() {
        TraceOpt f;
        f.excludeSystem = excludeSystem;
        f.includeNative = includeNative;
        return NativeModuleAllowed((uint64_t) addr, f, nullptr);
    };

    auto onEnter = [desc, cbEnter, allowed](GumInvocationContext* g) {
        if (!allowed()) return;
        JSContext* jsctx = g_ctx;
        if (jsctx && cbEnter) {
            JSValue ev = MakeNativeEvent(jsctx, desc, 0, g, false);
            CallJsCb1(jsctx, cbEnter, ev);
            JS_FreeValue(jsctx, ev);
        } else {
            BroadcastLog("trace", "-> " + desc);
        }
    };
    std::function<void(GumInvocationContext*)> onLeave;
    if (cbLeave) {
        onLeave = [desc, cbLeave, allowed](GumInvocationContext* g) {
            if (!allowed()) return;
            JSContext* jsctx = g_ctx;
            if (!jsctx) return;
            JSValue ev = MakeNativeEvent(jsctx, desc, 0, g, true);
            CallJsCb1(jsctx, cbLeave, ev);
            JS_FreeValue(jsctx, ev);
        };
    }

    PI::Native::NativeHookHandle nh = PI::Native::GumHooker::hook(target, onEnter, onLeave);
    if (!nh.isValid()) return JS_NewString(ctx, "[!] Failed to attach native trace hook");

    size_t id = RegisterSession(desc, PI::HookHandle(), std::move(nh));
    BroadcastLog("trace", "Started Native tracing: " + desc);
    return CreateTraceHandle(ctx, id, desc);
}

// ---------------------------------------------------------------------------
// Unified (Java + Native) sink: forwards engine "PI_CallTree" lines to JS.
// ---------------------------------------------------------------------------
static void InstallUnifiedSink(JSContext* ctx, std::shared_ptr<JSValue> onLine) {
    PI::Logger::setLogSink([ctx, onLine](PI::LogLevel, const char* tag, const char* msg) {
        if (!tag || std::strcmp(tag, "PI_CallTree") != 0 || !msg) return;
        BroadcastLog("trace", std::string(msg));
        if (ctx && onLine && !JS_IsUndefined(*onLine)) {
            std::lock_guard<std::mutex> lk(g_jsMutex);
            JSValue o = JS_NewObject(ctx);
            JS_SetPropertyStr(ctx, o, "layer", JS_NewString(ctx, "UNIFIED"));
            JS_SetPropertyStr(ctx, o, "text", JS_NewString(ctx, msg));
            JSValue r = JS_Call(ctx, *onLine, JS_UNDEFINED, 1, &o);
            if (JS_IsException(r)) JS_FreeValue(ctx, JS_GetException(ctx));
            JS_FreeValue(ctx, r);
            JS_FreeValue(ctx, o);
        }
    });
}

// ---------------------------------------------------------------------------
// traceunified: real Java <-> Native (QBDI) handoff for a Java method.
// ---------------------------------------------------------------------------
static JSValue JsTraceUnified(JSContext* ctx, JSValueConst /*this_val*/, int argc, JSValueConst* argv) {
    if (argc < 1) {
        return JS_NewString(ctx, "Usage: traceunified(target, [opt])\nExamples:\n  traceunified(findMethod(\"com.example.App\", \"test\"))\n  traceunified(ptr, new TraceOption())");
    }

    int64_t ptr = ParsePtr(ctx, argv[0]);
    if (!ptr || ptr < 0x1000) return JS_NewString(ctx, "[!] Invalid target pointer");

    ArtMethod* art = reinterpret_cast<ArtMethod*>(ptr);
    PI::Method m = PI::resolve(art);

    // Native method (or raw native address): delegate to tracenative.
    if (!m.isValid() || m.isNative()) {
        if (m.isValid()) {
            void* entry = art->GetEntryPointFromJni();
            if (entry) {
                JSValue jEntry = JS_NewBigInt64(ctx, reinterpret_cast<int64_t>(entry));
                JSValueConst fwd[2] = { jEntry, argc >= 2 ? argv[1] : JS_UNDEFINED };
                JSValue ret = JsTraceNative(ctx, JS_UNDEFINED, argc >= 2 ? 2 : 1, fwd);
                JS_FreeValue(ctx, jEntry);
                return ret;
            }
        }
        return JsTraceNative(ctx, JS_UNDEFINED, argc, argv);
    }

    // Java method: interpret with FULL_STACK_NATIVE so JNI calls are stepped
    // into via QBDI and the engine emits unified "PI_CallTree" lines.
    TraceOpt opt = ParseTraceOpt(ctx, argc >= 2 ? argv[1] : JS_UNDEFINED);
    std::string desc = m.toString();
    WarmInterpClass(GetEnv(), m.getDeclaringClassName());   // resolve same-class calls on hook path
    auto cbEnter = opt.onEnter, cbLeave = opt.onLeave, cbLine = opt.onInsn;

    StopExistingTrace(desc, art);

    PI::HookHandle hh = m.hook([desc, cbEnter, cbLeave, cbLine](JNIEnv*, PI::CallFrame& frame) {
        JSContext* jsctx = g_ctx;
        if (jsctx && cbEnter) {
            JSValue ev = MakeJavaEvent(jsctx, frame, desc, false);
            CallJsCb1(jsctx, cbEnter, ev);
            JS_FreeValue(jsctx, ev);
        }
        InstallUnifiedSink(jsctx, cbLine);
        frame.invokeTrace<void>(PI::Trace::TracePreset::FULL_STACK_NATIVE);
        PI::Logger::setLogSink(nullptr);
        if (jsctx && cbLeave) {
            JSValue ev = MakeJavaEvent(jsctx, frame, desc, true);
            CallJsCb1(jsctx, cbLeave, ev);
            JS_FreeValue(jsctx, ev);
        }
    });

    if (!hh.isHooked()) return JS_NewString(ctx, "[!] Failed to install unified trace hook");
    size_t id = RegisterSession(desc, std::move(hh), PI::Native::NativeHookHandle());
    BroadcastLog("trace", "Started tracing: " + desc);
    return CreateTraceHandle(ctx, id, desc);
}

} // namespace

size_t TraceStopAll() {
    std::lock_guard<std::mutex> lk(g_traceMutex);
    size_t n = 0;
    for (auto& s : g_activeTraces) {
        if (s.is_active) {
            s.is_active = false;
            if (s.java_handle.isHooked()) s.java_handle.unhook();
            if (s.native_handle.isValid()) s.native_handle.unhook();
            n++;
        }
    }
    return n;
}

void RegisterTraceApis(JSContext* ctx, JSValue global, JSValue trace) {
    // TraceOption constructor
    JSValue optCtor = JS_NewCFunction2(ctx, JsTraceOptionConstructor, "TraceOption", 0, JS_CFUNC_constructor, 0);
    JS_SetPropertyStr(ctx, global, "TraceOption", JS_DupValue(ctx, optCtor));
    JS_SetPropertyStr(ctx, trace, "TraceOption", optCtor);

    // Trace namespace
    JS_SetPropertyStr(ctx, trace, "unified", JS_NewCFunction(ctx, JsTraceUnified, "unified", 2));
    JS_SetPropertyStr(ctx, trace, "java", JS_NewCFunction(ctx, JsTraceJava, "java", 2));
    JS_SetPropertyStr(ctx, trace, "native", JS_NewCFunction(ctx, JsTraceNative, "native", 2));
    JS_SetPropertyStr(ctx, trace, "untrace", JS_NewCFunction(ctx, JsUntrace, "untrace", 1));

    // Flat global aliases
    JS_SetPropertyStr(ctx, global, "traceunified", JS_NewCFunction(ctx, JsTraceUnified, "traceunified", 2));
    JS_SetPropertyStr(ctx, global, "tracejava", JS_NewCFunction(ctx, JsTraceJava, "tracejava", 2));
    JS_SetPropertyStr(ctx, global, "tracenative", JS_NewCFunction(ctx, JsTraceNative, "tracenative", 2));
    JS_SetPropertyStr(ctx, global, "untrace", JS_NewCFunction(ctx, JsUntrace, "untrace", 1));
}

}} // namespace artpi::agent
