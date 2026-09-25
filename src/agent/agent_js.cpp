//
// agent_js.cpp - QuickJS runtime container & dual-track API orchestration
//
#include "agent_js.h"
#include "agent_common.h"
#include "agent_java.h"
#include "agent_native.h"
#include "agent_memory.h"
#include "agent_trace.h"
#include "agent_debug.h"
#include "agent_dynamic.h"
#include "agent_net.h"
#include "sandbox/pi_interp_tracer.h"

#include <map>
#include <vector>
#include <algorithm>
#include <sstream>
#include <cstring>
#include <iomanip>

namespace artpi { namespace agent {

namespace {

static const std::map<std::string, std::string> kApiDocs = {
    {"findClass",
     "Usage: findClass(nameOrPattern)\n"
     "  - Exact name: returns class pointer (e.g. findClass(\"java.lang.String\"))\n"
     "  - Wildcard: lists matching classes (e.g. findClass(\"*String*\"), findClass(\"*Activity*\"))"},
    {"findclass", "Alias for findClass(nameOrPattern)"},

    {"findMethod",
     "Usage: findMethod(classOrName, methodName, [methodSig])\n"
     "  - Resolves method and returns actual ArtMethod* pointer.\n"
     "  - Examples:\n"
     "      findMethod(\"com.android.boot.MainActivity\", \"nativeWeatherRequest\", \"()Ljava/lang/String;\")\n"
     "      findMethod(cls, \"onCreate\")"},
    {"findmethod", "Alias for findMethod(classOrName, methodName, [methodSig])"},

    {"listMethods",
     "Usage: listMethods(classOrName)\n"
     "  - Lists all declared methods of a class with signatures and ArtMethod* pointers.\n"
     "  - Examples:\n"
     "      listMethods(\"com.android.boot.MainActivity\")\n"
     "      listMethods(findClass(\"com.android.boot.MainActivity\"))"},
    {"listmethods", "Alias for listMethods(classOrName)"},

    {"findMethods",
     "Usage: findMethods(classOrName[, methodPattern])  -- methodPattern defaults to \"\"\n"
     "  - With one class-name arg, lists all methods of that class (== second arg \"\").\n"
     "  - With a wildcard arg, searches methods across all classes.\n"
     "  - Examples:\n"
     "      findMethods(\"com.android.boot.MainActivity\")\n"
     "      findMethods(\"com.android.boot.MainActivity\", \"*Weather*\")\n"
     "      findMethods(cls, \"*Request*\")"},
    {"findmethods", "Alias for findMethods(classOrName[, methodPattern])"},

    {"dumpSmali",
     "Usage: dumpSmali(artMethodPtr, [maxInstructions])\n"
     "  - Disassembles DEX bytecode of method into Dalvik Smali format.\n"
     "  - Examples:\n"
     "      dumpSmali(m)\n"
     "      dumpSmali(0x71a23b40, 50)"},
    {"dumpsmali", "Alias for dumpSmali(artMethodPtr, [maxInstructions])"},

    {"dumpNative",
     "Usage: dumpNative(artMethodPtrOrNativeAddr, [maxInstructions])\n"
     "  - Disassembles native ARM64 machine instructions with CFG flow & symbol resolution.\n"
     "  - Examples:\n"
     "      dumpNative(0x7400031380)\n"
     "      dumpNative(0x759c123450, 40)"},
    {"dumpnative", "Alias for dumpNative(artMethodPtrOrNativeAddr, [maxInstructions])"},

    {"dumpCode",
     "Usage: dumpCode(artMethodPtrOrNativeAddr, [maxInstructions])\n"
     "  - Unified code disassembler: auto-dispatches to dumpNative or dumpSmali.\n"
     "  - Examples:\n"
     "      dumpCode(0x74000312e0)\n"
     "      dumpCode(m, 100)"},
    {"dumpcode", "Alias for dumpCode(artMethodPtrOrNativeAddr, [maxInstructions])"},

    {"methodToArt",
     "Usage: methodToArt(jmethodID)\n"
     "  - Resolves a jmethodID to its underlying ART ArtMethod* memory pointer."},
    {"methodtoart", "Alias for methodToArt(jmethodID)"},

    {"artToMethod",
     "Usage: artToMethod(artMethodPtr)\n"
     "  - Converts an ArtMethod* pointer to a callable jmethodID."},
    {"artmethodtojmethod", "Alias for artToMethod(artMethodPtr)"},

    {"enumloaders",
     "Usage: enumloaders()\n"
     "  - Lists all active ClassLoader instances in the target application process."},

    {"jhook",
     "Usage: jhook(artMethod, [callbackOrOpt])\n"
     "  - Installs an ART method hook."},
    {"choose",
     "Usage: choose(className, [callbacks])\n"
     "  - Scans active heap memory for live instances of the specified class (like Frida's Java.choose).\n"
     "  - Callback style: choose(\"com.example.Foo\", { onMatch: function(instance){}, onComplete: function(){} })\n"
     "  - Interactive style: choose(\"com.example.Foo\") -> lists matching instances"},

    {"findModule",
     "Usage: findModule(nameOrPattern)\n"
     "  - Finds an ELF shared library module and returns base address, size, and path."},
    {"findmodule", "Alias for findModule(nameOrPattern)"},

    {"findSymbol",
     "Usage: findSymbol(moduleName, symbolName)\n"
     "  - Locates export or dynamic symbol address in specified ELF module via xDL."},
    {"findsymbol", "Alias for findSymbol(moduleName, symbolName)"},

    {"nhook",
     "Usage: nhook(addressOrSymbol, [callbackOrOpt])\n"
     "  - Hooks a native function via Frida-Gum engine (supports 'lib.so!sym' or 0xaddr)."},

    {"traceunified",
     "Usage: traceunified(target, [opt])\n"
     "  - Full-stack unified tracer crossing Java Smali and Native machine code."},
    {"tracejava", "Usage: tracejava(method, [opt])\n  - Traces Java method execution flow."},
    {"tracenative", "Usage: tracenative(address, [opt])\n  - Traces native instruction execution flow."},

    {"brkj",
     "Usage: brkj(methodOrArtPtr, [condLambda])\n"
     "  - Sets in-process cooperative breakpoint at Java method."},
    {"brkn",
     "Usage: brkn(addressOrSymbol, [condLambda])\n"
     "  - Sets in-process cooperative breakpoint at native address."},
    {"s", "Usage: s()\n  - Step into (Java next Smali opcode / Native next instruction)."},
    {"n", "Usage: n()\n  - Step over (execute current call and stop at next instruction)."},
    {"c", "Usage: c()\n  - Continue execution at full speed."},
    {"r", "Usage: r()\n  - Finish current stack frame and break upon return."},

    {"hexdump",
     "Usage: hexdump(address, [length])\n"
     "  - Formats memory region into standard hex + ASCII representation."},
    {"readmem", "Usage: readmem(address, length)\n  - Reads bytes into an ArrayBuffer."},
    {"writemem", "Usage: writemem(address, bytesOrHex)\n  - Writes bytes directly to memory with mprotect."},
    {"readstring", "Usage: readstring(address)\n  - Reads null-terminated C string from memory."},
    {"readu32", "Usage: readu32(address)\n  - Reads 32-bit unsigned integer from address."},
    {"writeu32", "Usage: writeu32(address, value)\n  - Writes 32-bit unsigned integer to address with mprotect."},

    {"dynamic",
     "Usage: dynamic.java.<package>.<Class>.<method> | dynamic.native.<lib>.<symbol>\n"
     "  - Java chaining:\n"
     "      dynamic.java.com.android.boot.MainActivity.dumpCode() // dumps class\n"
     "      dynamic.java.com.android.boot.MainActivity.nativeWeatherRequest.dumpCode() // dumps method\n"
     "      dynamic.java.com.android.boot.MainActivity.nativeWeatherRequest.hook((orig, f) => { ... })\n"
     "  - Native chaining:\n"
     "      dynamic.native.libfk.Java_com_android_boot_MainActivity_nativeWeatherRequest.dumpCode()\n"
     "      dynamic.native.libfk.Java_com_android_boot_MainActivity_nativeWeatherRequest.hook((orig, ctx) => { ... })\n"
     "      dynamic.native.libfk.Java_com_android_boot_MainActivity_nativeWeatherRequest.address"},

    {"untrace", "Usage: untrace([id])\n  - Stops all active traces, or one by id. (handle.stop() also works.)"},
    {"D", "Usage: D()\n  - Detach everything: all Java hooks + native hooks + traces. (alias: detach)"},
    {"detach", "Alias for D(): detach all Java hooks + native hooks + traces."}
};

static JSValue JsDetachAll(JSContext* ctx, JSValueConst /*this_val*/, int /*argc*/, JSValueConst* /*argv*/) {
    size_t d = DebugDetachAll();
    size_t j = JavaUnhookAllCount();
    size_t n = NativeUnhookAllCount();
    size_t t = TraceStopAll();
    std::string msg = "Detached: " + std::to_string(j) + " java hook(s), "
                    + std::to_string(n) + " native hook(s), "
                    + std::to_string(t) + " trace(s), "
                    + std::to_string(d) + " debug breakpoint(s)";
    return JS_NewString(ctx, msg.c_str());
}

static void RegisterDualTrackApis(JSContext* ctx) {
    JSValue global = JS_GetGlobalObject(ctx);

    // 1. Create domain namespace objects
    JSValue java = JS_NewObject(ctx);
    JSValue native = JS_NewObject(ctx);
    JSValue memory = JS_NewObject(ctx);
    JSValue trace = JS_NewObject(ctx);
    JSValue debug = JS_NewObject(ctx);

    // 2. Register domain-specific and flat global APIs
    RegisterJavaApis(ctx, global, java);
    RegisterNativeApis(ctx, global, native);
    RegisterMemoryApis(ctx, global, memory);
    RegisterTraceApis(ctx, global, trace);
    RegisterDebugApis(ctx, global, debug);

    // 3. Mount domain namespaces on global
    JS_SetPropertyStr(ctx, global, "Java", java);
    JS_SetPropertyStr(ctx, global, "Native", native);
    JS_SetPropertyStr(ctx, global, "Memory", memory);
    JS_SetPropertyStr(ctx, global, "Trace", trace);
    JS_SetPropertyStr(ctx, global, "Debug", debug);
    // Lowercase aliases for convenience
    JS_SetPropertyStr(ctx, global, "debug", JS_DupValue(ctx, debug));
    JS_SetPropertyStr(ctx, global, "memory", JS_DupValue(ctx, memory));
    JS_SetPropertyStr(ctx, global, "trace", JS_DupValue(ctx, trace));

    // 4. Register dynamic proxy tree (dynamic.java & dynamic.native)
    RegisterDynamicApis(ctx);

    // 5. One-shot detach: Java hooks + native hooks + all traces
    JS_SetPropertyStr(ctx, global, "D", JS_NewCFunction(ctx, JsDetachAll, "D", 0));
    JS_SetPropertyStr(ctx, global, "detach", JS_NewCFunction(ctx, JsDetachAll, "detach", 0));

    // 6. Install console.log redirector
    InstallConsole(ctx);

    JS_FreeValue(ctx, global);
}

} // namespace

bool InitJs(JNIEnv* env) {
    std::lock_guard<std::mutex> lk(g_jsMutex);
    if (g_rt) return true;

    if (env) env->GetJavaVM(&g_jvm);

    g_rt = JS_NewRuntime();
    if (!g_rt) return false;

    // Disable stack size limit check across multi-threads on Android (prevents false stack overflows)
    JS_SetMaxStackSize(g_rt, 0);

    g_ctx = JS_NewContext(g_rt);
    if (!g_ctx) {
        JS_FreeRuntime(g_rt);
        g_rt = nullptr;
        return false;
    }

    RegisterDualTrackApis(g_ctx);
    // Cache classes used on the (frameless) hook path — see agent_java.cpp.
    if (env) artpi::agent::InitJRefClassCache(env);
    // Register the app ClassLoader so the interpreter can resolve referenced
    // classes safely (loadClass as a managed frame) during traced execution.
    // Fall back to the system / context class loader for app_process targets
    // that have no Application.
    if (env) {
        jobject loader = artpi::agent::GetAppClassLoader(env);
        if (!loader) {
            jclass clCls = env->FindClass("java/lang/ClassLoader");
            if (env->ExceptionCheck()) env->ExceptionClear();
            if (clCls) {
                jmethodID getSys = env->GetStaticMethodID(clCls, "getSystemClassLoader", "()Ljava/lang/ClassLoader;");
                if (env->ExceptionCheck()) env->ExceptionClear();
                if (getSys) {
                    loader = env->CallStaticObjectMethod(clCls, getSys);
                    if (env->ExceptionCheck()) { env->ExceptionClear(); loader = nullptr; }
                }
                env->DeleteLocalRef(clCls);
            }
        }
        if (!loader) {
            jclass thrCls = env->FindClass("java/lang/Thread");
            if (env->ExceptionCheck()) env->ExceptionClear();
            if (thrCls) {
                jmethodID cur = env->GetStaticMethodID(thrCls, "currentThread", "()Ljava/lang/Thread;");
                jmethodID getCtx = env->GetMethodID(thrCls, "getContextClassLoader", "()Ljava/lang/ClassLoader;");
                if (env->ExceptionCheck()) env->ExceptionClear();
                if (cur && getCtx) {
                    jobject th = env->CallStaticObjectMethod(thrCls, cur);
                    if (env->ExceptionCheck()) env->ExceptionClear();
                    if (th) { loader = env->CallObjectMethod(th, getCtx); if (env->ExceptionCheck()) { env->ExceptionClear(); loader = nullptr; } env->DeleteLocalRef(th); }
                }
                env->DeleteLocalRef(thrCls);
            }
        }
        if (loader) PI::Interp::RegisterAppClassLoader(env, loader);
    }
    return true;
}

std::string EvalJs(const std::string& script, const char* filename) {
    std::lock_guard<std::mutex> lk(g_jsMutex);
    if (!g_ctx) return "[!] QuickJS context not initialized";

    std::string trimmed = script;
    while (!trimmed.empty() && (trimmed.back() == ' ' || trimmed.back() == '\t' || trimmed.back() == '\n' || trimmed.back() == ';')) trimmed.pop_back();
    while (!trimmed.empty() && (trimmed.front() == ' ' || trimmed.front() == '\t')) trimmed.erase(trimmed.begin());

    JSValue val = JS_Eval(g_ctx, script.c_str(), script.size(), filename, JS_EVAL_TYPE_GLOBAL);
    std::string res;

    if (JS_IsException(val)) {
        JSValue exc = JS_GetException(g_ctx);
        const char* str = JS_ToCString(g_ctx, exc);
        res = "[Exception] ";
        res += str ? str : "unknown";
        if (str) JS_FreeCString(g_ctx, str);
        JS_FreeValue(g_ctx, exc);
    } else if (JS_IsFunction(g_ctx, val)) {
        bool handled = false;
        JSValue propName = JS_GetPropertyStr(g_ctx, val, "name");
        if (!JS_IsUndefined(propName)) {
            const char* fnName = JS_ToCString(g_ctx, propName);
            if (fnName) {
                auto it = kApiDocs.find(fnName);
                if (it != kApiDocs.end()) {
                    res = it->second;
                    handled = true;
                }
                JS_FreeCString(g_ctx, fnName);
            }
            JS_FreeValue(g_ctx, propName);
        }
        if (!handled) {
            auto it = kApiDocs.find(trimmed);
            if (it != kApiDocs.end()) {
                res = it->second;
                handled = true;
            }
        }
        if (!handled) {
            res = "[Function: " + (trimmed.empty() ? "anonymous" : trimmed) + "]";
        }
    } else if (JS_IsUndefined(val)) {
        res = "undefined";
    } else if (JS_IsNull(val)) {
        res = "null";
    } else if (JS_IsBool(val)) {
        res = JS_ToBool(g_ctx, val) ? "true" : "false";
    } else if (JS_IsBigInt(g_ctx, val)) {
        int64_t v = 0;
        JS_ToBigInt64(g_ctx, &v, val);
        char hexBuf[32];
        snprintf(hexBuf, sizeof(hexBuf), "0x%llx", static_cast<unsigned long long>(v));
        res = hexBuf;
    } else if (JS_IsArray(g_ctx, val)) {
        JSAtom atomToString = JS_NewAtom(g_ctx, "toString");
        bool hasOwnToString = (JS_GetOwnProperty(g_ctx, nullptr, val, atomToString) == 1);
        JS_FreeAtom(g_ctx, atomToString);

        if (hasOwnToString) {
            const char* str = JS_ToCString(g_ctx, val);
            res = str ? str : "";
            if (str) JS_FreeCString(g_ctx, str);
        } else {
            int64_t len = 0;
            JSValue lenVal = JS_GetPropertyStr(g_ctx, val, "length");
            JS_ToInt64(g_ctx, &len, lenVal);
            JS_FreeValue(g_ctx, lenVal);

            if (len == 0) {
                res = "[]";
            } else {
                std::vector<std::string> items;
                bool multiline = false;
                size_t totalLen = 0;
                int64_t maxShow = std::min<int64_t>(len, 100);
                for (int64_t i = 0; i < maxShow; i++) {
                    JSValue elem = JS_GetPropertyUint32(g_ctx, val, i);
                    std::string itemStr;
                    if (JS_IsString(elem)) {
                        const char* s = JS_ToCString(g_ctx, elem);
                        itemStr = std::string("\"") + (s ? s : "") + "\"";
                        if (s) JS_FreeCString(g_ctx, s);
                    } else if (JS_IsBigInt(g_ctx, elem)) {
                        int64_t bv = 0;
                        JS_ToBigInt64(g_ctx, &bv, elem);
                        char hbuf[32];
                        snprintf(hbuf, sizeof(hbuf), "0x%llx", (unsigned long long)bv);
                        itemStr = hbuf;
                    } else {
                        const char* s = JS_ToCString(g_ctx, elem);
                        itemStr = s ? s : "";
                        if (s) JS_FreeCString(g_ctx, s);
                    }
                    JS_FreeValue(g_ctx, elem);
                    if (itemStr.find('\n') != std::string::npos || itemStr.size() > 40) multiline = true;
                    totalLen += itemStr.size();
                    items.push_back(std::move(itemStr));
                }
                if (len > 5 || totalLen > 60) multiline = true;

                if (!multiline) {
                    res = "[ ";
                    for (size_t i = 0; i < items.size(); i++) {
                        if (i > 0) res += ", ";
                        res += items[i];
                    }
                    res += " ]";
                } else {
                    res = "[\n";
                    for (size_t i = 0; i < items.size(); i++) {
                        res += "  " + items[i];
                        if (i + 1 < items.size() || len > maxShow) res += ",";
                        res += "\n";
                    }
                    if (len > maxShow) {
                        res += "  ... and " + std::to_string(len - maxShow) + " more items\n";
                    }
                    res += "]";
                }
            }
        }
    } else {
        const char* str = JS_ToCString(g_ctx, val);
        res = str ? str : "";
        if (str) JS_FreeCString(g_ctx, str);
    }
    JS_FreeValue(g_ctx, val);
    return res;
}

void DestroyJs() {
    std::lock_guard<std::mutex> lk(g_jsMutex);
    if (g_ctx) {
        JS_FreeContext(g_ctx);
        g_ctx = nullptr;
    }
    if (g_rt) {
        JS_FreeRuntime(g_rt);
        g_rt = nullptr;
    }
}

}} // namespace artpi::agent

// ============================================================================
// Exported C entry points (used by the JS-binding test suite and embedders)
// ============================================================================
#if defined(__GNUC__) || defined(__clang__)
#define ARTPI_TEST_EXPORT __attribute__((visibility("default")))
#else
#define ARTPI_TEST_EXPORT
#endif

extern "C" ARTPI_TEST_EXPORT int artpi_agent_js_init(JNIEnv* env) {
    return artpi::agent::InitJs(env) ? 1 : 0;
}

extern "C" ARTPI_TEST_EXPORT const char* artpi_agent_js_eval(const char* script) {
    static thread_local std::string buf;
    buf = artpi::agent::EvalJs(script ? script : "");
    return buf.c_str();
}

