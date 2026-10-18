//
// agent_trace.cpp - Trace domain bindings for QuickJS (Unified, Java, Native)
//
// Honors the optional `opt` / `new TraceOption()` object:
//   mode          "CALL_TREE" (default) | "INSN_STEP"/"INSTRUCTION_DIFF" |
//                 "FULL_STACK_NATIVE" (aliases: "native"/"insn"/"diff")
//   native/stepNative  bool  — shorthand for mode = "FULL_STACK_NATIVE"
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
#include "dex/pi_smali.h"
#include "native/hooker/pi_gum_hooker.h"
#include "frida-gum.h"
#include "art/art_method.h"

#include <string>
#include <vector>
#include <set>
#include <cctype>
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
static size_t g_nextTraceId = 0;
static std::mutex g_traceMutex;

// ---------------------------------------------------------------------------
// Option parsing
// ---------------------------------------------------------------------------
struct TraceOpt {
    std::string mode = "CALL_TREE";
    bool excludeSystem = true;
    std::string includeNative;
    int maxDepth = 8;
    bool dumpAfter = true;   // read register values AFTER the instruction (default)
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

// Accepts the canonical preset names plus a few short aliases:
//   "native" / "full" / "stepNative"  -> FULL_STACK_NATIVE
//   "insn"   / "instructions"         -> INSN_STEP
//   "diff"                            -> INSTRUCTION_DIFF
static std::string NormalizeTraceMode(std::string m) {
    for (char& c : m) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    if (m.empty() || m == "call_tree" || m == "tree" || m == "calls" ||
        m == "method" || m == "method_only") {
        return "CALL_TREE";
    }
    if (m == "insn" || m == "insns" || m == "insn_step" ||
        m == "instruction" || m == "instructions") {
        return "INSN_STEP";
    }
    if (m == "instruction_diff" || m == "insn_diff" || m == "diff") {
        return "INSTRUCTION_DIFF";
    }
    if (m == "native" || m == "full" || m == "fullstack" || m == "full_stack" ||
        m == "full_stack_native" || m == "step_native" || m == "stepnative") {
        return "FULL_STACK_NATIVE";
    }
    return m;
}

static TraceOpt ParseTraceOpt(JSContext* ctx, JSValueConst opt) {
    TraceOpt o;
    if (!ctx) return o;

    // String shorthand: m.trace("native") / m.trace("insn")
    if (JS_IsString(opt)) {
        const char* s = JS_ToCString(ctx, opt);
        if (s) {
            o.mode = NormalizeTraceMode(s);
            JS_FreeCString(ctx, s);
        }
        return o;
    }
    if (!JS_IsObject(opt)) return o;

    JSValue v = JS_GetPropertyStr(ctx, opt, "mode");
    if (JS_IsString(v)) { const char* s = JS_ToCString(ctx, v); if (s) { o.mode = NormalizeTraceMode(s); JS_FreeCString(ctx, s); } }
    JS_FreeValue(ctx, v);

    // `native: true` / `stepNative: true` is shorthand for FULL_STACK_NATIVE.
    for (const char* key : {"native", "stepNative"}) {
        v = JS_GetPropertyStr(ctx, opt, key);
        if (!JS_IsUndefined(v) && !JS_IsNull(v) && JS_ToBool(ctx, v) != 0) {
            o.mode = "FULL_STACK_NATIVE";
        }
        JS_FreeValue(ctx, v);
    }

    v = JS_GetPropertyStr(ctx, opt, "excludeSystem");
    if (!JS_IsUndefined(v)) o.excludeSystem = (JS_ToBool(ctx, v) != 0);
    JS_FreeValue(ctx, v);

    v = JS_GetPropertyStr(ctx, opt, "includeNative");
    if (JS_IsString(v)) { const char* s = JS_ToCString(ctx, v); if (s) { o.includeNative = s; JS_FreeCString(ctx, s); } }
    JS_FreeValue(ctx, v);

    v = JS_GetPropertyStr(ctx, opt, "maxDepth");
    if (JS_IsNumber(v)) JS_ToInt32(ctx, &o.maxDepth, v);
    JS_FreeValue(ctx, v);

    v = JS_GetPropertyStr(ctx, opt, "dumpAfter");
    if (!JS_IsUndefined(v)) o.dumpAfter = (JS_ToBool(ctx, v) != 0);
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

// Warm every class referenced by a method's code (field/method/type indices),
// so the interpreter resolves them from the cache without loadClass() on the
// frameless path. loadClass() fails for split-APK / default-package obfuscated
// classes (R8 emits bare "Lh84;" descriptors), which otherwise bails the run
// at the first iget-object/check-cast and truncates the call tree.
static void WarmMethodRefs(JNIEnv* env, ArtMethod* am) {
    if (!env || !am || am->IsNative()) return;

    const uint8_t* code_item = reinterpret_cast<const uint8_t*>(
        reinterpret_cast<uintptr_t>(am->GetEntryPointFromJni()) & ~1ULL);
    if (!code_item) return;

    PI::DexResolver dex;
    if (!dex.initFromMethod(am)) return;
    bool compact = dex.isCompactDex();

    uint32_t insns_size = 0;
    const uint16_t* insns = nullptr;
    if (compact) {
        uint16_t insns_count_and_flags = *reinterpret_cast<const uint16_t*>(code_item + 2);
        insns_size = insns_count_and_flags >> 5;
        if (insns_count_and_flags & (1u << 4)) {
            // kFlagPreHeaderInsnsSize: two 16-bit words precede code_item
            const uint16_t* preheader = reinterpret_cast<const uint16_t*>(code_item);
            --preheader;
            insns_size += static_cast<uint32_t>(*preheader);
            --preheader;
            insns_size += static_cast<uint32_t>(*preheader) << 16;
        }
        insns = reinterpret_cast<const uint16_t*>(code_item + 4);
    } else {
        insns_size = *reinterpret_cast<const uint32_t*>(code_item + 12);
        insns = reinterpret_cast<const uint16_t*>(code_item + 16);
    }
    if (!insns || insns_size == 0 || insns_size > 0x100000) return;

    const uint8_t* sizes = PI::instructionSizeTable();
    std::set<std::string> classes;

    // Best-effort static pre-warm: scans standard Dalvik opcodes (does not
    // decode quickened cdex opcodes such as iget-quick 0xe3).
    for (uint32_t i = 0; i < insns_size;) {
        const uint16_t* cur = insns + i;
        uint16_t w0 = cur[0];
        uint8_t op = static_cast<uint8_t>(w0 & 0xFF);

        std::string desc;
        if (i + 1 < insns_size) {
            if (op == 0x1c || op == 0x1f || op == 0x20 || op == 0x22 ||
                op == 0x23 || op == 0x24 || op == 0x25) {
                // type reference: const-class/check-cast/instance-of/new-instance/
                // new-array/filled-new-array (21c/22c/35c/3rc, index at insn[1])
                desc = dex.resolveType(cur[1]);
            } else if (op >= 0x52 && op <= 0x6d) {
                // field reference: iget/iput/sget/sput (22c, index at insn[1])
                PI::FieldRef fr = dex.resolveField(cur[1]);
                if (fr.isValid()) desc = fr.class_descriptor;
            } else if ((op >= 0x6e && op <= 0x72) || (op >= 0x74 && op <= 0x78)) {
                // method reference: invoke-* / invoke-*/range (35c/3rc, index at insn[1])
                PI::MethodRef mr = dex.resolveMethod(cur[1]);
                if (mr.isValid()) desc = mr.class_descriptor;
            }
        }

        if (desc.size() > 2 && desc[0] == 'L' && desc.back() == ';') {
            classes.insert(desc.substr(1, desc.size() - 2));    // slash name
        }

        uint32_t sz = 1;
        if (w0 == 0x0100 && i + 1 < insns_size) sz = 4 + cur[1] * 2;
        else if (w0 == 0x0200 && i + 1 < insns_size) sz = 2 + cur[1] * 4;
        else if (w0 == 0x0300 && i + 3 < insns_size) sz = 4 + (cur[1] * (*reinterpret_cast<const uint32_t*>(cur + 2)) + 1) / 2;
        else if (sizes != nullptr) sz = sizes[op];
        if (sz == 0) sz = 1;
        i += sz;
    }

    for (const std::string& slash : classes) {
        std::string dotted = slash;
        for (char& c : dotted) if (c == '/') c = '.';
        jclass cls = artpi::agent::FindClassWithFallback(env, dotted);
        if (env->ExceptionCheck()) env->ExceptionClear();
        if (!cls) continue;
        PI::Interp::RegisterClassRef(env, slash.c_str(), cls);
        env->DeleteLocalRef(cls);
    }
}

static bool IsSystemJavaName(const std::string& n) {
    static const char* kSys[] = {"java.", "javax.", "android.", "androidx.", "kotlin.",
                                 "kotlinx.", "org.jetbrains.", "dalvik.", "libcore.",
                                 "sun.", "org.apache.harmony."};
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
    JS_SetPropertyStr(ctx, obj, "native", JS_NewBool(ctx, false));
    JS_SetPropertyStr(ctx, obj, "stepNative", JS_NewBool(ctx, false));
    JS_SetPropertyStr(ctx, obj, "includeNative", JS_NewString(ctx, ""));
    JS_SetPropertyStr(ctx, obj, "excludeSystem", JS_NewBool(ctx, true));
    JS_SetPropertyStr(ctx, obj, "maxDepth", JS_NewInt32(ctx, 8));
    JS_SetPropertyStr(ctx, obj, "dumpAfter", JS_NewBool(ctx, true));
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
    snprintf(buf, sizeof(buf), "[Trace %s (id=%d)]", t ? t : "?", (int) id);
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
    // The REPL pretty-prints eval results; an empty dumpText suppresses the
    // `{ "_id": ..., "target": ... }` echo. The "[trace] Started ..." event is
    // the only output .trace() should produce.
    JS_SetPropertyStr(ctx, handle, "dumpText", JS_NewString(ctx, ""));
    return handle;
}

static size_t RegisterSession(const std::string& desc, PI::HookHandle jh,
                              PI::Native::NativeHookHandle nh) {
    std::lock_guard<std::mutex> lk(g_traceMutex);
    size_t id = g_nextTraceId++;
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
    if (am) {
        // Java-method target: release any existing hook/trace/breakpoint on the
        // same ArtMethod so the new trace installs cleanly (last-one-wins).
        int rel = AgentReleaseMethodInstrumentation(reinterpret_cast<void*>(am));
        if (rel) {
            BroadcastLog("console", std::string("[trace] replaced existing ") +
                                        FormatReleasedInstrumentation(rel) + " on " + desc);
        }
        return;
    }
    // Native target: stop + erase any active trace with the same tag/desc.
    std::lock_guard<std::mutex> lk(g_traceMutex);
    for (auto it = g_activeTraces.begin(); it != g_activeTraces.end();) {
        if (it->is_active && !desc.empty() && it->tag == desc) {
            it->is_active = false;
            if (it->java_handle.isHooked()) it->java_handle.unhook();
            if (it->native_handle.isValid()) it->native_handle.unhook();
            it = g_activeTraces.erase(it);
        } else {
            ++it;
        }
    }
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
    WarmMethodRefs(GetEnv(), m.getArtMethod());   // resolve the method's own referenced classes
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

    // Java method: interpret the body. Honor `mode`:
    //   CALL_TREE (default)        -> METHOD_ONLY (call tree, no per-insn log)
    //   INSN_STEP / INSTRUCTION_DIFF -> INSTRUCTION_DIFF (call tree + per-insn)
    //   FULL_STACK_NATIVE          -> cross-JNI native step-in (QBDI)
    TraceOpt opt = ParseTraceOpt(ctx, argc >= 2 ? argv[1] : JS_UNDEFINED);
    std::string desc = m.toString();
    WarmInterpClass(GetEnv(), m.getDeclaringClassName());   // resolve same-class calls on hook path
    WarmMethodRefs(GetEnv(), art);   // resolve the method's own referenced classes
    auto cbEnter = opt.onEnter, cbLeave = opt.onLeave, cbLine = opt.onInsn;

    PI::Trace::TracePreset preset = PI::Trace::TracePreset::METHOD_ONLY;
    if (opt.mode == "INSN_STEP" || opt.mode == "INSTRUCTION_DIFF") {
        preset = PI::Trace::TracePreset::INSTRUCTION_DIFF;
    } else if (opt.mode == "FULL_STACK_NATIVE") {
        preset = PI::Trace::TracePreset::FULL_STACK_NATIVE;
    }

    StopExistingTrace(desc, art);

    PI::HookHandle hh = m.hook([desc, cbEnter, cbLeave, cbLine, preset, dumpAfter = opt.dumpAfter](JNIEnv*, PI::CallFrame& frame) {
        JSContext* jsctx = g_ctx;
        if (jsctx && cbEnter) {
            JSValue ev = MakeJavaEvent(jsctx, frame, desc, false);
            CallJsCb1(jsctx, cbEnter, ev);
            JS_FreeValue(jsctx, ev);
        }
        PI::Interp::SetDumpRegsAfter(dumpAfter);
        InstallUnifiedSink(jsctx, cbLine);
        frame.invokeTrace<void>(preset);
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
    g_activeTraces.clear();
    g_nextTraceId = 0;
    return n;
}

std::vector<TraceInfo> TraceListAll() {
    std::lock_guard<std::mutex> lk(g_traceMutex);
    std::vector<TraceInfo> res;
    for (const auto& s : g_activeTraces) {
        if (s.is_active) {
            std::string mode = s.java_handle.isHooked() ? "Java" : (s.native_handle.isValid() ? "Native" : "Unified");
            res.push_back({ static_cast<int>(s.id), s.tag, mode });
        }
    }
    return res;
}

bool TraceStopByArtMethod(void* artMethod) {
    std::lock_guard<std::mutex> lk(g_traceMutex);
    bool done = false;
    for (auto it = g_activeTraces.begin(); it != g_activeTraces.end();) {
        bool match = artMethod && it->is_active && it->java_handle.isHooked() &&
                     reinterpret_cast<void*>(it->java_handle.getArtMethod()) == artMethod;
        if (match) {
            it->is_active = false;
            if (it->java_handle.isHooked()) it->java_handle.unhook();
            if (it->native_handle.isValid()) it->native_handle.unhook();
            it = g_activeTraces.erase(it);
            done = true;
        } else {
            ++it;
        }
    }
    return done;
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
