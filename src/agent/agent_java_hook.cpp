//
// agent_java_hook.cpp - ART method hooking, CallFrame marshalling & Unhook management
//
#include "agent_java_hook.h"
#include "agent_java_ref.h"
#include "agent_java_resolve.h"
#include "agent_common.h"
#include "agent_net.h"
#include "agent_debug.h"
#include "../../include/ArtPI.h"
#include "art/art_method.h"

#include <vector>
#include <string>
#include <mutex>
#include <unordered_set>
#include <algorithm>
#include <memory>
#include <sstream>
#include <cstring>
#include <cstdio>

extern "C" {
    void* PineNative_ToArtObject(JNIEnv* env, jobject j_obj);
}

namespace artpi { namespace agent {

static std::vector<PI::HookHandle> g_activeHooks;
static std::mutex g_hooksMutex;

static thread_local int t_hookCallDepth = 0;

static std::string FormatTreePrefix(int depth, bool isEntry) {
    if (depth <= 0) {
        return isEntry ? "┌── " : "└── ";
    }
    std::string prefix;
    prefix.reserve(static_cast<size_t>(depth * 4 + 8));
    for (int i = 0; i < depth; i++) {
        prefix += "│   ";
    }
    if (isEntry) {
        prefix += "├── ";
    } else {
        prefix += "└── ";
    }
    return prefix;
}

static std::string FormatJavaObject(JNIEnv* env, jobject obj) {
    if (!env || !obj) return "null";
    jclass cls = env->GetObjectClass(obj);
    std::string cname = cls ? SimplifyJavaType(JavaClassName(env, cls)) : "Object";
    if (cls) env->DeleteLocalRef(cls);
    void* artObj = PineNative_ToArtObject(env, obj);
    uint64_t addr = artObj ? reinterpret_cast<uintptr_t>(artObj) : reinterpret_cast<uintptr_t>(obj);
    DoRegisterObservedObject(env, addr, obj);
    char buf[128];
    snprintf(buf, sizeof(buf), "%s@0x%llx", cname.c_str(), (unsigned long long) addr);
    return buf;
}

static std::shared_ptr<JSValue> GuardJsHookCb(JSValue v) {
    return std::shared_ptr<JSValue>(new JSValue(v), [](JSValue* p) {
        if (p) {
            if (g_ctx && !JS_IsUndefined(*p)) JS_FreeValue(g_ctx, *p);
            delete p;
        }
    });
}

struct JsHookRet {
    bool set = false;
    JSValue val = JS_UNDEFINED;
};

static JSValue JsHookSetResultFn(JSContext* ctx, JSValueConst /*this_val*/, int argc, JSValueConst* argv,
                                 int /*magic*/, JSValue* func_data) {
    if (argc < 1) return JS_UNDEFINED;
    int64_t p = 0;
    if (JS_IsBigInt(ctx, func_data[0])) JS_ToBigInt64(ctx, &p, func_data[0]);
    else JS_ToInt64(ctx, &p, func_data[0]);
    auto* slot = reinterpret_cast<JsHookRet*>(static_cast<uintptr_t>(p));
    if (slot) {
        if (slot->set) JS_FreeValue(ctx, slot->val);
        slot->val = JS_DupValue(ctx, argv[0]);
        slot->set = true;
    }
    return JS_UNDEFINED;
}

static JSValue JsValueFromFrameArg(JSContext* ctx, PI::CallFrame& f, int i) {
    const std::string& t = (i < static_cast<int>(f.arg_types.size())) ? f.arg_types[i] : std::string("I");
    char k = t.empty() ? 'I' : t[0];
    uint64_t raw = f.getArgRaw(i);
    switch (k) {
        case 'I': case 'S': case 'B': case 'C': return JS_NewInt32(ctx, static_cast<int32_t>(raw));
        case 'Z': return JS_NewBool(ctx, raw ? 1 : 0);
        case 'J': { int64_t v; std::memcpy(&v, &raw, 8); return JS_NewBigInt64(ctx, v); }
        case 'F': case 'D': { double d; std::memcpy(&d, &raw, 8); return JS_NewFloat64(ctx, d); }
        case 'L': case '[':
            if (t == "Ljava/lang/String;") return JS_NewString(ctx, f.getArgString(i).c_str());
            return JavaObjectToJsValue(ctx, GetEnv(), f.getArg(i));
        default: return JS_NewInt32(ctx, static_cast<int32_t>(raw));
    }
}

static bool JsValueToFrameArg(JSContext* ctx, PI::CallFrame& f, int i, JSValueConst v) {
    const std::string& t = (i < static_cast<int>(f.arg_types.size())) ? f.arg_types[i] : std::string("I");
    char k = t.empty() ? 'I' : t[0];
    switch (k) {
        case 'I': case 'S': case 'B': case 'C': {
            int32_t iv = 0; JS_ToInt32(ctx, &iv, v);
            f.setArgRaw(i, static_cast<uint64_t>(static_cast<uint32_t>(iv)));
            return true;
        }
        case 'Z': { f.setArgRaw(i, JS_ToBool(ctx, v) ? 1 : 0); return true; }
        case 'J': {
            int64_t jv = 0;
            if (JS_IsBigInt(ctx, v)) JS_ToBigInt64(ctx, &jv, v); else JS_ToInt64(ctx, &jv, v);
            uint64_t raw; std::memcpy(&raw, &jv, 8);
            f.setArgRaw(i, raw);
            return true;
        }
        case 'F': case 'D': {
            double dv = 0; JS_ToFloat64(ctx, &dv, v);
            uint64_t raw; std::memcpy(&raw, &dv, 8);
            f.setArgRaw(i, raw);
            return true;
        }
        case 'L': case '[': {
            if (t == "Ljava/lang/String;" && JS_IsString(v)) {
                const char* s = JS_ToCString(ctx, v);
                if (s) {
                    JNIEnv* env = GetEnv();
                    jstring js = env ? env->NewStringUTF(s) : nullptr;
                    if (js) f.setArg(i, js);
                    JS_FreeCString(ctx, s);
                }
                return true;
            }
            return false;
        }
        default: return false;
    }
}

static bool JsValueToFrameResult(JSContext* ctx, PI::CallFrame& f, JSValueConst v) {
    switch (f.return_type) {
        case 'V': return true;
        case 'I': case 'S': case 'B': case 'C': { int32_t iv = 0; JS_ToInt32(ctx, &iv, v); f.setResult(static_cast<int>(iv)); return true; }
        case 'Z': { f.setResult((bool)(JS_ToBool(ctx, v) != 0)); return true; }
        case 'J': {
            int64_t jv = 0;
            if (JS_IsBigInt(ctx, v)) JS_ToBigInt64(ctx, &jv, v); else JS_ToInt64(ctx, &jv, v);
            f.setResult(reinterpret_cast<jlong>(jv));
            return true;
        }
        case 'F': case 'D': { double dv = 0; JS_ToFloat64(ctx, &dv, v); f.setResult((double) dv); return true; }
        case 'L': case '[': {
            if (JS_IsNull(v) || JS_IsUndefined(v)) { f.setResult((jobject) nullptr); return true; }
            if (JS_IsString(v)) {
                const char* s = JS_ToCString(ctx, v);
                f.setResult(std::string(s ? s : ""));
                if (s) JS_FreeCString(ctx, s);
                return true;
            }
            return false;
        }
        default: return false;
    }
}

static JSValue JsHookGetStackFn(JSContext* ctx, JSValueConst /*this_val*/,
                                int /*argc*/, JSValueConst* /*argv*/,
                                int /*magic*/, JSValue* func_data) {
    int64_t sp = ParsePtr(ctx, func_data[0]);
    if (!sp) return JS_NewString(ctx, "");
    std::string s = CaptureCallerStackFromSp(reinterpret_cast<void*>(static_cast<uintptr_t>(sp)));
    return JS_NewString(ctx, s.c_str());
}

static void AttachLazyStackGetter(JSContext* jsctx, JSValue obj, const PI::CallFrame& frame) {
    uintptr_t sp = (frame.ctx != nullptr) ? static_cast<uintptr_t>(frame.ctx->sp) : 0;
    JSValue spData[1] = { JS_NewBigInt64(jsctx, static_cast<int64_t>(sp)) };
    JSValue getter = JS_NewCFunctionData(jsctx, JsHookGetStackFn, 0, 0, 1, spData);
    JS_FreeValue(jsctx, spData[0]);
    JSAtom atom = JS_NewAtom(jsctx, "stack");
    JS_DefinePropertyGetSet(jsctx, obj, atom, getter, JS_UNDEFINED, JS_PROP_C_W_E);
    JS_FreeAtom(jsctx, atom);
}

static int InstallJavaMethodHook(JSContext* ctx, PI::Method& m,
                                 bool hasCb, bool twoCb,
                                 JSValueConst cbArg1, JSValueConst cbArg2) {
    if (!m.isValid()) return -1;

    {
        int rel = AgentReleaseMethodInstrumentation(reinterpret_cast<void*>(m.getArtMethod()));
        if (rel) {
            BroadcastLog("console", std::string("[hook] replaced existing ") +
                                        FormatReleasedInstrumentation(rel) +
                                        " on " + m.getDeclaringClassName() + "." + m.getName());
        }
    }

    PI::HookHandle handle;
    if (!twoCb && (!hasCb || !JS_IsFunction(ctx, cbArg1))) {
        handle = m.hook([](JNIEnv* cbEnv, PI::CallFrame& frame) {
            if (cbEnv) cbEnv->PushLocalFrame(32);

            int curDepth = t_hookCallDepth;
            t_hookCallDepth++;

            auto* am = reinterpret_cast<ArtMethod*>(frame.target_method);
            std::string mods = am ? FormatModifiers(am->GetAccessFlags()) : "";
            std::string mdesc = (mods.empty() ? "" : mods + " ") + frame.getMethodToString();

            std::string entry = mdesc + "(";
            bool hasArg = false;
            if (!frame.is_static) {
                jobject thiz = frame.getThisObject();
                if (thiz) {
                    entry += "this=" + FormatJavaObject(cbEnv, thiz);
                    hasArg = true;
                }
            }
            int n = frame.getArgCount();
            for (int i = 0; i < n; i++) {
                if (hasArg) entry += ", ";
                entry += "arg" + std::to_string(i) + "=" + frame.getArgString(i);
                hasArg = true;
            }
            entry += ")";

            BroadcastLog("hook", FormatTreePrefix(curDepth, true) + entry);

            struct DepthGuard {
                int& d;
                ~DepthGuard() { if (d > 0) d--; }
            } guard{t_hookCallDepth};

            frame.invokeOriginal();

            BroadcastLog("hook", FormatTreePrefix(curDepth, false)
                                 + frame.getMethodName() + "() = " + frame.getResultString());

            if (cbEnv) cbEnv->PopLocalFrame(nullptr);
        });
    } else if (twoCb) {
        auto onEnterGuard = JS_IsFunction(ctx, cbArg1)
            ? GuardJsHookCb(JS_DupValue(ctx, cbArg1))
            : nullptr;
        auto onLeaveGuard = GuardJsHookCb(JS_DupValue(ctx, cbArg2));
        handle = m.hook([onEnterGuard, onLeaveGuard](JNIEnv* cbEnv, PI::CallFrame& frame) {
            JSContext* jsctx = g_ctx;
            if (!jsctx) { frame.invokeOriginal(); return; }

            size_t jrefBase = GetJRefCount();
            if (cbEnv) cbEnv->PushLocalFrame(64);

            std::string entryLog = frame.class_name.empty()
                                       ? frame.getMethodName()
                                       : (frame.class_name + "." + frame.getMethodName());

            if (t_jsReentrancyDepth > 0) {
                std::string argdump;
                int an = frame.getArgCount();
                for (int i = 0; i < an; i++) {
                    argdump += " a" + std::to_string(i) + "=" + frame.getArgString(i);
                }
                BroadcastLog("debug", "[hook] " + entryLog + " (reentrant, JS cb skipped) args:" + argdump);
                frame.invokeOriginal();
                PopJRefsTo(cbEnv, jrefBase);
                if (cbEnv) cbEnv->PopLocalFrame(nullptr);
                return;
            }

            int n = frame.getArgCount();
            if (onEnterGuard) {
                std::lock_guard<std::mutex> lk(g_jsMutex);

                JSValue argsArr = JS_NewArray(jsctx);
                for (int i = 0; i < n; i++) {
                    JS_SetPropertyUint32(jsctx, argsArr, static_cast<uint32_t>(i),
                                         JsValueFromFrameArg(jsctx, frame, i));
                }

                JSValue obj = JS_NewObject(jsctx);
                JS_SetPropertyStr(jsctx, obj, "method", JS_NewString(jsctx, frame.getMethodName().c_str()));
                JS_SetPropertyStr(jsctx, obj, "class", JS_NewString(jsctx, frame.class_name.c_str()));
                JS_SetPropertyStr(jsctx, obj, "args", JS_DupValue(jsctx, argsArr));
                JS_SetPropertyStr(jsctx, obj, "argc", JS_NewInt32(jsctx, n));
                JS_SetPropertyStr(jsctx, obj, "thiz",
                                  frame.is_static ? JS_NULL
                                                  : JavaObjectToJsValue(jsctx, GetEnv(), frame.getThisObject()));
                AttachLazyStackGetter(jsctx, obj, frame);

                JSValue r1 = JS_Call(jsctx, *onEnterGuard, JS_UNDEFINED, 1, &obj);
                if (JS_IsException(r1)) {
                    JSValue exc = JS_GetException(jsctx);
                    const char* err = JS_ToCString(jsctx, exc);
                    if (err) { BroadcastLog("console", std::string("[hook callback] ") + err); JS_FreeCString(jsctx, err); }
                    JS_FreeValue(jsctx, exc);
                }
                JS_FreeValue(jsctx, r1);

                for (int i = 0; i < n; i++) {
                    JSValue v = JS_GetPropertyUint32(jsctx, argsArr, static_cast<uint32_t>(i));
                    JsValueToFrameArg(jsctx, frame, i, v);
                    JS_FreeValue(jsctx, v);
                }
                JS_FreeValue(jsctx, argsArr);
                JS_FreeValue(jsctx, obj);
            }

            frame.invokeOriginal();

            {
                std::lock_guard<std::mutex> lk(g_jsMutex);

                JsHookRet leaveRet;
                JSValue obj2 = JS_NewObject(jsctx);
                JS_SetPropertyStr(jsctx, obj2, "method", JS_NewString(jsctx, frame.getMethodName().c_str()));
                JS_SetPropertyStr(jsctx, obj2, "class", JS_NewString(jsctx, frame.class_name.c_str()));
                JS_SetPropertyStr(jsctx, obj2, "ret", JS_NewString(jsctx, frame.getResultString().c_str()));
                JS_SetPropertyStr(jsctx, obj2, "thiz",
                                  frame.is_static ? JS_NULL
                                                  : JavaObjectToJsValue(jsctx, GetEnv(), frame.getThisObject()));
                AttachLazyStackGetter(jsctx, obj2, frame);
                JSValue data[1] = { JS_NewBigInt64(jsctx, static_cast<int64_t>(reinterpret_cast<uintptr_t>(&leaveRet))) };
                JS_SetPropertyStr(jsctx, obj2, "setResult", JS_NewCFunctionData(jsctx, JsHookSetResultFn, 1, 0, 1, data));
                JS_FreeValue(jsctx, data[0]);

                JSValue r2 = JS_Call(jsctx, *onLeaveGuard, JS_UNDEFINED, 1, &obj2);
                if (JS_IsException(r2)) {
                    JSValue exc = JS_GetException(jsctx);
                    const char* err = JS_ToCString(jsctx, exc);
                    if (err) { BroadcastLog("console", std::string("[hook callback] ") + err); JS_FreeCString(jsctx, err); }
                    JS_FreeValue(jsctx, exc);
                }
                JS_FreeValue(jsctx, r2);

                if (leaveRet.set) {
                    JsValueToFrameResult(jsctx, frame, leaveRet.val);
                    const char* rv = JS_ToCString(jsctx, leaveRet.val);
                    BroadcastLog("debug", "[hook] " + entryLog + " -> return MODIFIED to "
                                              + (rv ? rv : "<null>"));
                    if (rv) JS_FreeCString(jsctx, rv);
                    JS_FreeValue(jsctx, leaveRet.val);
                }
                JS_FreeValue(jsctx, obj2);
            }

            PopJRefsTo(cbEnv, jrefBase);
            if (cbEnv) cbEnv->PopLocalFrame(nullptr);
        });
    } else {
        auto cbGuard = GuardJsHookCb(JS_DupValue(ctx, cbArg1));
        handle = m.hook([cbGuard](JNIEnv* cbEnv, PI::CallFrame& frame) {
            JSContext* jsctx = g_ctx;
            if (!jsctx) { frame.invokeOriginal(); return; }

            size_t jrefBase = GetJRefCount();
            if (cbEnv) cbEnv->PushLocalFrame(64);

            std::string entryLog = frame.class_name.empty()
                                       ? frame.getMethodName()
                                       : (frame.class_name + "." + frame.getMethodName());
            BroadcastLog("debug", "[hook] " + entryLog + " entered");

            bool overrideResult = false;
            if (t_jsReentrancyDepth > 0) {
                std::string argdump;
                int an = frame.getArgCount();
                for (int i = 0; i < an; i++) {
                    argdump += " a" + std::to_string(i) + "=" + frame.getArgString(i);
                }
                BroadcastLog("debug", "[hook] " + entryLog +
                             " (reentrant, JS cb skipped) args:" + argdump);
                frame.invokeOriginal();
                BroadcastLog("debug", "[hook] " + entryLog + " -> original return: " +
                                      frame.getResultString());
                PopJRefsTo(cbEnv, jrefBase);
                if (cbEnv) cbEnv->PopLocalFrame(nullptr);
                return;
            }
            {
                std::lock_guard<std::mutex> lk(g_jsMutex);

                int n = frame.getArgCount();
                JSValue argsArr = JS_NewArray(jsctx);
                for (int i = 0; i < n; i++) {
                    JS_SetPropertyUint32(jsctx, argsArr, static_cast<uint32_t>(i),
                                         JsValueFromFrameArg(jsctx, frame, i));
                }

                JsHookRet retSlot;
                JSValue obj = JS_NewObject(jsctx);
                JS_SetPropertyStr(jsctx, obj, "method", JS_NewString(jsctx, frame.getMethodName().c_str()));
                JS_SetPropertyStr(jsctx, obj, "class", JS_NewString(jsctx, frame.class_name.c_str()));
                JS_SetPropertyStr(jsctx, obj, "args", JS_DupValue(jsctx, argsArr));
                JS_SetPropertyStr(jsctx, obj, "argc", JS_NewInt32(jsctx, n));
                JS_SetPropertyStr(jsctx, obj, "thiz",
                                  frame.is_static ? JS_NULL
                                                  : JavaObjectToJsValue(jsctx, GetEnv(), frame.getThisObject()));

                AttachLazyStackGetter(jsctx, obj, frame);

                JSValue data[1] = { JS_NewBigInt64(jsctx, static_cast<int64_t>(reinterpret_cast<uintptr_t>(&retSlot))) };
                JS_SetPropertyStr(jsctx, obj, "setResult",
                                  JS_NewCFunctionData(jsctx, JsHookSetResultFn, 1, 0, 1, data));
                JS_FreeValue(jsctx, data[0]);

                JSValue callRet = JS_Call(jsctx, *cbGuard, JS_UNDEFINED, 1, &obj);
                if (JS_IsException(callRet)) {
                    JSValue exc = JS_GetException(jsctx);
                    const char* err = JS_ToCString(jsctx, exc);
                    if (err) {
                        BroadcastLog("console", std::string("[hook callback] ") + err);
                        JS_FreeCString(jsctx, err);
                    }
                    JS_FreeValue(jsctx, exc);
                }
                JS_FreeValue(jsctx, callRet);

                if (retSlot.set) {
                    JsValueToFrameResult(jsctx, frame, retSlot.val);
                    const char* rv = JS_ToCString(jsctx, retSlot.val);
                    BroadcastLog("debug", "[hook] " + entryLog + " -> return MODIFIED to "
                                          + (rv ? rv : "<null>"));
                    if (rv) JS_FreeCString(jsctx, rv);
                    JS_FreeValue(jsctx, retSlot.val);
                    retSlot.val = JS_UNDEFINED;
                    retSlot.set = false;
                    overrideResult = true;
                } else {
                    for (int i = 0; i < n; i++) {
                        JSValue v = JS_GetPropertyUint32(jsctx, argsArr, static_cast<uint32_t>(i));
                        uint64_t before = frame.getArgRaw(i);
                        JsValueToFrameArg(jsctx, frame, i, v);
                        uint64_t after = frame.getArgRaw(i);
                        if (before != after) {
                            const char* nv = JS_ToCString(jsctx, v);
                            char ib[256];
                            snprintf(ib, sizeof(ib), "[hook] %s arg[%d] MODIFIED:", entryLog.c_str(), i);
                            BroadcastLog("debug", std::string(ib) + " " + (nv ? nv : "<null>"));
                            if (nv) JS_FreeCString(jsctx, nv);
                        }
                        JS_FreeValue(jsctx, v);
                    }
                }

                JS_FreeValue(jsctx, argsArr);
                JS_FreeValue(jsctx, obj);
            }

            if (!overrideResult) {
                frame.invokeOriginal();
                BroadcastLog("debug", "[hook] " + entryLog + " -> original return: "
                                      + frame.getResultString());
            }

            PopJRefsTo(cbEnv, jrefBase);
            if (cbEnv) cbEnv->PopLocalFrame(nullptr);
        });
    }

    if (!handle.isHooked()) {
        return -1;
    }

    std::lock_guard<std::mutex> lk(g_hooksMutex);
    g_activeHooks.push_back(handle);
    return static_cast<int>(g_activeHooks.size() - 1);
}

static JSValue JsJavaHook(JSContext* ctx, JSValueConst /*this_val*/, int argc, JSValueConst* argv) {
    if (argc < 1) return JS_NewString(ctx, "Usage: jhook(artMethod, [onEnter], [onLeave], [className], [methodName], [sig])");
    int64_t ptr = ParsePtr(ctx, argv[0]);
    if (!ptr || ptr < 0x1000) return JS_NewString(ctx, "[!] Invalid method pointer");

    bool twoCb = (argc >= 3 && JS_IsFunction(ctx, argv[2]));
    int metaBase = twoCb ? 3 : 2;
    std::string optClass, optMethod, optSig;
    if (argc >= metaBase + 0 && JS_IsString(argv[metaBase + 0])) {
        const char* s = JS_ToCString(ctx, argv[metaBase + 0]);
        if (s) { optClass = s; JS_FreeCString(ctx, s); }
    }
    if (argc >= metaBase + 1 && JS_IsString(argv[metaBase + 1])) {
        const char* s = JS_ToCString(ctx, argv[metaBase + 1]);
        if (s) { optMethod = s; JS_FreeCString(ctx, s); }
    }
    if (argc >= metaBase + 2 && JS_IsString(argv[metaBase + 2])) {
        const char* s = JS_ToCString(ctx, argv[metaBase + 2]);
        if (s) { optSig = s; JS_FreeCString(ctx, s); }
    }

    PI::Method m;
    if (!optClass.empty() && !optMethod.empty() && !optSig.empty()) {
        JNIEnv* env = GetEnv();
        if (env) {
            jclass clazz = FindClassWithFallback(env, optClass);
            if (clazz) {
                m = PI::resolve(env, clazz, optMethod, optSig);
                env->DeleteLocalRef(clazz);
            }
        }
    }
    if (!m.isValid()) {
        m = PI::resolve(reinterpret_cast<ArtMethod*>(ptr));
    }
    if (!m.isValid() && ptr) {
        m = PI::Method(nullptr, nullptr, nullptr, reinterpret_cast<ArtMethod*>(ptr),
                       optMethod.empty() ? "ArtMethod" : optMethod, optSig,
                       reinterpret_cast<ArtMethod*>(ptr)->IsStatic());
    }
    if (!m.isValid()) return JS_NewString(ctx, "[!] Cannot resolve ArtMethod");

    bool hasCb = (argc >= 2 && JS_IsFunction(ctx, argv[1]));
    JSValueConst cb1 = (argc >= 2) ? argv[1] : JS_UNDEFINED;
    JSValueConst cb2 = (argc >= 3) ? argv[2] : JS_UNDEFINED;
    int hookId = InstallJavaMethodHook(ctx, m, hasCb, twoCb, cb1, cb2);
    if (hookId < 0) {
        return JS_NewString(ctx, "[!] Hook installation failed");
    }

    char resBuf[64];
    snprintf(resBuf, sizeof(resBuf), "Hook installed (id: %d)", hookId);
    return JS_NewString(ctx, resBuf);
}

static JSValue RunFindAndHook(JSContext* ctx, int argc, JSValueConst* argv, bool unlimited) {
    if (argc < 1) {
        return JS_NewString(ctx,
            "Usage:\n"
            "  findAndHook(keyword [, onEnter, onLeave, maxHooks])                 // match class OR method name (default maxHooks=50)\n"
            "  findAndHook(classPattern, methodPattern [, onEnter, onLeave, max])  // match class AND method pattern ('|' supported)\n"
            "  findAndHookAll(keyword [, onEnter, onLeave])                        // hook ALL matching methods without limit\n"
            "  findAndHookAll(classPattern, methodPattern [, onEnter, onLeave])\n"
            "Examples:\n"
            "  findAndHook(\"md5\")\n"
            "  findAndHook(\"md5\", 300)\n"
            "  findAndHookAll(\"md5\")\n"
            "  findAndHook(\"*encrypt*\", \"encrypt|decrypt\")");
    }

    JNIEnv* env = GetEnv();
    if (!env) return JS_NULL;

    int effArgc = argc;
    int maxHooks = unlimited ? 0x7fffffff : 50;
    if (!unlimited && effArgc >= 2 && JS_IsNumber(argv[effArgc - 1])) {
        int lim = 50;
        if (JS_ToInt32(ctx, &lim, argv[effArgc - 1]) == 0 && lim > 0) {
            maxHooks = lim;
        }
        effArgc--;
    }

    int64_t clsPtr = (!JS_IsString(argv[0]) && !JS_IsFunction(ctx, argv[0])) ? ParsePtr(ctx, argv[0]) : 0;
    std::string arg0Str;
    if (clsPtr == 0 && JS_IsString(argv[0])) {
        const char* s = JS_ToCString(ctx, argv[0]);
        if (s) { arg0Str = s; JS_FreeCString(ctx, s); }
    }
    if (clsPtr == 0 && arg0Str.empty()) {
        return JS_NewString(ctx, "[!] findAndHook: first argument must be a pattern string or class pointer");
    }

    bool hasSecondPattern = (effArgc >= 2 && JS_IsString(argv[1]));
    std::string classPattern;
    std::string methodPattern;
    bool singleKeywordMode = false;
    int cbBase = 1;

    if (hasSecondPattern) {
        const char* s = JS_ToCString(ctx, argv[1]);
        methodPattern = s ? s : "";
        if (s) JS_FreeCString(ctx, s);
        classPattern = arg0Str;
        singleKeywordMode = false;
        cbBase = 2;
    } else {
        cbBase = 1;
        if (clsPtr != 0) {
            methodPattern = "";
            singleKeywordMode = false;
        } else {
            bool hasMeta = (arg0Str.find('*') != std::string::npos ||
                            arg0Str.find('?') != std::string::npos ||
                            arg0Str.find('|') != std::string::npos);
            jclass exact = !hasMeta ? FindClassWithFallback(env, arg0Str) : nullptr;
            if (exact) {
                env->DeleteLocalRef(exact);
                classPattern = arg0Str;
                methodPattern = "";
                singleKeywordMode = false;
            } else {
                classPattern = arg0Str;
                methodPattern = arg0Str;
                singleKeywordMode = true;
            }
        }
    }

    bool hasCb = (effArgc > cbBase && JS_IsFunction(ctx, argv[cbBase]));
    bool twoCb = (effArgc > cbBase + 1 && JS_IsFunction(ctx, argv[cbBase + 1]));
    JSValueConst cb1 = (effArgc > cbBase) ? argv[cbBase] : JS_UNDEFINED;
    JSValueConst cb2 = (effArgc > cbBase + 1) ? argv[cbBase + 1] : JS_UNDEFINED;

    jclass classCls = env->FindClass("java/lang/Class");
    if (env->ExceptionCheck()) { env->ExceptionClear(); return JS_NULL; }
    jmethodID getDeclaredMethods = classCls ? env->GetMethodID(classCls, "getDeclaredMethods", "()[Ljava/lang/reflect/Method;") : nullptr;
    jclass methodCls = env->FindClass("java/lang/reflect/Method");
    if (env->ExceptionCheck()) { env->ExceptionClear(); methodCls = nullptr; }
    jmethodID methodToString = methodCls ? env->GetMethodID(methodCls, "toString", "()Ljava/lang/String;") : nullptr;
    jmethodID methodGetName = methodCls ? env->GetMethodID(methodCls, "getName", "()Ljava/lang/String;") : nullptr;
    if (env->ExceptionCheck()) env->ExceptionClear();

    std::unordered_set<void*> hookedArtMethods;
    std::ostringstream details;
    int hookedCount = 0;
    int skippedNativeOrAbstract = 0;
    int matchedClassCount = 0;

    auto hookMethodsInClass = [&](jclass targetCls, const std::string& cn) {
        if (!targetCls || !getDeclaredMethods || hookedCount >= maxHooks) return;
        auto methodsObj = (jobjectArray)env->CallObjectMethod(targetCls, getDeclaredMethods);
        if (env->ExceptionCheck()) { env->ExceptionClear(); return; }
        if (!methodsObj) return;

        bool classMatchesKeyword = singleKeywordMode && !cn.empty() && MatchPatternSubstr(cn, methodPattern);
        bool classHadMatch = false;
        jsize len = env->GetArrayLength(methodsObj);
        for (jsize i = 0; i < len && hookedCount < maxHooks; i++) {
            jobject mObj = env->GetObjectArrayElement(methodsObj, i);
            if (!mObj) continue;

            std::string nameStr;
            if (methodGetName) {
                auto jName = (jstring)env->CallObjectMethod(mObj, methodGetName);
                if (env->ExceptionCheck()) env->ExceptionClear();
                if (jName) {
                    const char* utf = env->GetStringUTFChars(jName, nullptr);
                    if (utf) { nameStr = utf; env->ReleaseStringUTFChars(jName, utf); }
                    env->DeleteLocalRef(jName);
                }
            }
            if (nameStr == "<clinit>" ||
                nameStr.rfind("$r8$lambda$", 0) == 0 ||
                nameStr.rfind("access$", 0) == 0 ||
                cn.find("$$ExternalSynthetic") != std::string::npos) {
                env->DeleteLocalRef(mObj);
                continue;
            }

            std::string desc = nameStr;
            if (methodToString) {
                auto jStr = (jstring)env->CallObjectMethod(mObj, methodToString);
                if (env->ExceptionCheck()) env->ExceptionClear();
                if (jStr) {
                    const char* utf = env->GetStringUTFChars(jStr, nullptr);
                    if (utf) { desc = utf; env->ReleaseStringUTFChars(jStr, utf); }
                    env->DeleteLocalRef(jStr);
                }
            }

            bool match = false;
            if (singleKeywordMode) {
                if (MatchPatternSubstr(nameStr, methodPattern)) {
                    match = true;
                } else if (classMatchesKeyword) {
                    // When only the class name matched the keyword (e.g. MD5Digest or MD5Util),
                    // only hook public/entry methods rather than private internal helpers
                    // like F/G/H/K/rotateLeft/char2Int/str2Bin.
                    PI::Method tmpM = PI::resolve(env, mObj);
                    uint32_t fl = tmpM.isValid() ? tmpM.getAccessFlags() : 0;
                    bool isPublic = (fl & 0x0001) != 0;
                    if (isPublic && nameStr.size() > 1) {
                        match = true;
                    }
                }
            } else if (methodPattern.empty() || methodPattern == "*") {
                match = true;
            } else if (methodPattern.find('(') != std::string::npos || methodPattern.find(' ') != std::string::npos) {
                match = MatchPatternSubstr(desc, methodPattern);
            } else {
                match = MatchPatternSubstr(nameStr, methodPattern);
            }

            if (match) {
                PI::Method pm = PI::resolve(env, mObj);
                if (pm.isValid() && pm.getArtMethod()) {
                    uint32_t flags = pm.getAccessFlags();
                    // Skip abstract (0x0400), native (0x0100), bridge (0x0040), and synthetic (0x1000) methods
                    if ((flags & 0x0400) != 0 || (flags & 0x0100) != 0 || (flags & 0x1040) != 0) {
                        skippedNativeOrAbstract++;
                    } else {
                        void* artPtr = reinterpret_cast<void*>(pm.getArtMethod());
                        if (hookedArtMethods.insert(artPtr).second) {
                            int hid = InstallJavaMethodHook(ctx, pm, hasCb, twoCb, cb1, cb2);
                            if (hid >= 0) {
                                hookedCount++;
                                classHadMatch = true;
                                char lineBuf[96];
                                snprintf(lineBuf, sizeof(lineBuf), "  [hook #%d] 0x%llx -> ",
                                         hid, (unsigned long long)reinterpret_cast<uintptr_t>(artPtr));
                                details << lineBuf << desc << "\n";
                            }
                        }
                    }
                }
            }
            env->DeleteLocalRef(mObj);
        }
        if (classHadMatch) matchedClassCount++;
        env->DeleteLocalRef(methodsObj);
    };

    if (clsPtr != 0) {
        hookMethodsInClass(reinterpret_cast<jclass>(clsPtr), "");
    } else {
        bool hasMeta = (classPattern.find('*') != std::string::npos ||
                        classPattern.find('?') != std::string::npos ||
                        classPattern.find('|') != std::string::npos);
        jclass exactCls = (!singleKeywordMode && !hasMeta) ? FindClassWithFallback(env, classPattern) : nullptr;
        if (exactCls) {
            hookMethodsInClass(exactCls, classPattern);
            env->DeleteLocalRef(exactCls);
        } else {
            std::vector<std::string> candidateClasses = FastScanCandidateClasses(env, classPattern, methodPattern, singleKeywordMode);
            for (const auto& cn : candidateClasses) {
                if (hookedCount >= maxHooks) break;
                jclass cls = FindClassWithFallback(env, cn);
                if (cls) {
                    hookMethodsInClass(cls, cn);
                    env->DeleteLocalRef(cls);
                }
            }
        }
    }

    if (classCls) env->DeleteLocalRef(classCls);
    if (methodCls) env->DeleteLocalRef(methodCls);

    const char* fnTag = unlimited ? "findAndHookAll" : "findAndHook";
    if (hookedCount == 0) {
        std::string msg = std::string("[!] ") + fnTag + ": no hookable methods matched ";
        msg += singleKeywordMode ? ("\"" + methodPattern + "\"")
                                 : ("class=\"" + classPattern + "\", method=\"" + methodPattern + "\"");
        if (skippedNativeOrAbstract > 0) {
            msg += " (skipped " + std::to_string(skippedNativeOrAbstract) + " abstract/native/synthetic)";
        }
        return JS_NewString(ctx, msg.c_str());
    }

    std::ostringstream out;
    out << "[*] " << fnTag << ": hooked " << hookedCount << " method(s) across " << matchedClassCount << " class(es)";
    if (skippedNativeOrAbstract > 0) {
        out << " (skipped " << skippedNativeOrAbstract << " abstract/native/synthetic)";
    }
    out << ":\n" << details.str();
    if (!unlimited && hookedCount >= maxHooks) {
        out << "[!] WARNING: Reached maxHooks limit (" << maxHooks
            << "). Some matching methods were not hooked!\n"
            << "    -> Use findAndHookAll(...) to hook all matching methods without limit, "
            << "or pass a larger maxHooks integer as the last argument (e.g. findAndHook(\""
            << (singleKeywordMode ? methodPattern : classPattern) << "\", " << (maxHooks * 5) << ")).\n";
    }
    std::string res = out.str();
    if (!res.empty() && res.back() == '\n') res.pop_back();
    return JS_NewString(ctx, res.c_str());
}

static JSValue JsFindAndHook(JSContext* ctx, JSValueConst /*this_val*/, int argc, JSValueConst* argv) {
    return RunFindAndHook(ctx, argc, argv, false);
}

static JSValue JsFindAndHookAll(JSContext* ctx, JSValueConst /*this_val*/, int argc, JSValueConst* argv) {
    return RunFindAndHook(ctx, argc, argv, true);
}

static JSValue JsJavaUnhook(JSContext* ctx, JSValueConst /*this_val*/, int argc, JSValueConst* argv) {
    if (argc < 1) return JS_NewString(ctx, "Usage: unhook(id)");
    int id = 0;
    JS_ToInt32(ctx, &id, argv[0]);

    std::lock_guard<std::mutex> lk(g_hooksMutex);
    if (id >= 0 && id < static_cast<int>(g_activeHooks.size())) {
        g_activeHooks[id].unhook();
        return JS_NewString(ctx, "Unhooked successfully");
    }
    return JS_NewString(ctx, "[!] Invalid hook id");
}

static JSValue JsJavaUnhookAll(JSContext* ctx, JSValueConst /*this_val*/, int /*argc*/, JSValueConst* /*argv*/) {
    size_t count = JavaUnhookAllCount();
    char resBuf[64];
    snprintf(resBuf, sizeof(resBuf), "Unhooked %zu methods", count);
    return JS_NewString(ctx, resBuf);
}

size_t JavaUnhookAllCount() {
    std::lock_guard<std::mutex> lk(g_hooksMutex);
    size_t count = 0;
    for (auto& h : g_activeHooks) {
        if (h.isHooked()) {
            h.unhook();
            count++;
        }
    }
    g_activeHooks.clear();
    return count;
}

bool JavaUnhookMethod(void* artMethod) {
    std::lock_guard<std::mutex> lk(g_hooksMutex);
    bool done = false;
    for (auto& h : g_activeHooks) {
        if (h.isHooked() && reinterpret_cast<void*>(h.getArtMethod()) == artMethod) {
            h.unhook();
            h = PI::HookHandle();
            done = true;
        }
    }
    return done;
}

void RegisterJavaHookApis(JSContext* ctx, JSValue global, JSValue java) {
    // Java namespace
    JS_SetPropertyStr(ctx, java, "hook", JS_NewCFunction(ctx, JsJavaHook, "hook", 2));
    JS_SetPropertyStr(ctx, java, "findAndHook", JS_NewCFunction(ctx, JsFindAndHook, "findAndHook", 3));
    JS_SetPropertyStr(ctx, java, "findandhook", JS_NewCFunction(ctx, JsFindAndHook, "findandhook", 3));
    JS_SetPropertyStr(ctx, java, "findAndHookAll", JS_NewCFunction(ctx, JsFindAndHookAll, "findAndHookAll", 3));
    JS_SetPropertyStr(ctx, java, "findandhookall", JS_NewCFunction(ctx, JsFindAndHookAll, "findandhookall", 3));
    JS_SetPropertyStr(ctx, java, "unhook", JS_NewCFunction(ctx, JsJavaUnhook, "unhook", 1));
    JS_SetPropertyStr(ctx, java, "unhookAll", JS_NewCFunction(ctx, JsJavaUnhookAll, "unhookAll", 0));

    // Flat global aliases
    JS_SetPropertyStr(ctx, global, "jhook", JS_NewCFunction(ctx, JsJavaHook, "jhook", 2));
    JS_SetPropertyStr(ctx, global, "findAndHook", JS_NewCFunction(ctx, JsFindAndHook, "findAndHook", 3));
    JS_SetPropertyStr(ctx, global, "findandhook", JS_NewCFunction(ctx, JsFindAndHook, "findandhook", 3));
    JS_SetPropertyStr(ctx, global, "findAndHookAll", JS_NewCFunction(ctx, JsFindAndHookAll, "findAndHookAll", 3));
    JS_SetPropertyStr(ctx, global, "findandhookall", JS_NewCFunction(ctx, JsFindAndHookAll, "findandhookall", 3));
    JS_SetPropertyStr(ctx, global, "unhook", JS_NewCFunction(ctx, JsJavaUnhook, "unhook", 1));
    JS_SetPropertyStr(ctx, global, "unhookall", JS_NewCFunction(ctx, JsJavaUnhookAll, "unhookall", 0));
}

}} // namespace artpi::agent
