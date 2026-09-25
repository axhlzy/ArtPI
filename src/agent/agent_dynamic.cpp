//
// agent_dynamic.cpp - Dynamic Proxy-based chainable invocation API for Java & Native
//
#include "agent_dynamic.h"
#include "agent_common.h"
#include "agent_java.h"
#include "agent_native.h"
#include "agent_memory.h"
#include "../../include/ArtPI.h"
#include "frida-gum.h"

#include <link.h>
#include <vector>
#include <string>
#include <algorithm>
#include <sstream>
#include <mutex>

namespace artpi { namespace agent {

namespace {

// C-function helper: dynamic.__getCompletionData()
static JSValue JsGetCompletionData(JSContext* ctx, JSValueConst /*this_val*/, int /*argc*/, JSValueConst* /*argv*/) {
    JSValue root = JS_NewObject(ctx);

    // 1. Initial App Classes (keep payload fast & lightweight, < 300 entries)
    JNIEnv* env = GetEnv();
    std::vector<std::string> classes;
    if (env) {
        std::string pkg;
        FILE* fp = fopen("/proc/self/cmdline", "r");
        if (fp) {
            char buf[256] = {};
            if (fgets(buf, sizeof(buf), fp)) pkg = buf;
            fclose(fp);
        }
        if (!pkg.empty()) {
            classes = FindMatchingClassNames(env, pkg, 300);
        }
        if (classes.empty()) {
            classes = FindMatchingClassNames(env, "", 300);
        }
    }
    JSValue arrCls = JS_NewArray(ctx);
    for (size_t i = 0; i < classes.size(); i++) {
        JS_SetPropertyUint32(ctx, arrCls, static_cast<uint32_t>(i), JS_NewString(ctx, classes[i].c_str()));
    }
    JS_SetPropertyStr(ctx, root, "classes", arrCls);

    // 2. Loaded Modules across all namespaces & /proc/self/maps (app libs first!)
    std::vector<std::string> modules = CollectAllLoadedModules();
    JSValue arrMods = JS_NewArray(ctx);
    for (size_t i = 0; i < modules.size(); i++) {
        JS_SetPropertyUint32(ctx, arrMods, static_cast<uint32_t>(i), JS_NewString(ctx, modules[i].c_str()));
    }
    JS_SetPropertyStr(ctx, root, "modules", arrMods);

    return root;
}

// C-function helper: dynamic.__findMatchingClasses(prefix, limit)
static JSValue JsFindMatchingClasses(JSContext* ctx, JSValueConst /*this_val*/, int argc, JSValueConst* argv) {
    std::string prefix;
    if (argc >= 1) {
        const char* s = JS_ToCString(ctx, argv[0]);
        if (s) { prefix = s; JS_FreeCString(ctx, s); }
    }
    size_t limit = 40;
    if (argc >= 2) {
        uint32_t lim = 40;
        JS_ToUint32(ctx, &lim, argv[1]);
        if (lim > 0 && lim <= 200) limit = lim;
    }

    JNIEnv* env = GetEnv();
    std::vector<std::string> matches;
    if (env) {
        matches = FindMatchingClassNames(env, prefix, limit);
    }

    JSValue arr = JS_NewArray(ctx);
    for (size_t i = 0; i < matches.size(); i++) {
        JS_SetPropertyUint32(ctx, arr, static_cast<uint32_t>(i), JS_NewString(ctx, matches[i].c_str()));
    }
    return arr;
}

// C-function helper: dynamic.__getModuleSymbols(modName)
static JSValue JsGetModuleSymbols(JSContext* ctx, JSValueConst /*this_val*/, int argc, JSValueConst* argv) {
    if (argc < 1) return JS_NewArray(ctx);
    const char* modStr = JS_ToCString(ctx, argv[0]);
    if (!modStr) return JS_NewArray(ctx);
    std::string modName(modStr);
    JS_FreeCString(ctx, modStr);

    std::vector<std::string> symbols;
    LoadedModuleInfo mod;
    if (FindLoadedModule(modName, mod) ||
        (modName.size() > 3 && modName.substr(modName.size() - 3) == ".so" &&
         FindLoadedModule(modName.substr(0, modName.size() - 3), mod)) ||
        FindLoadedModule(modName + ".so", mod)) {
        EnumerateModuleSymbols(mod, [&](const char* name, uintptr_t /*addr*/) -> bool {
            symbols.push_back(name);
            return symbols.size() < 2000;
        });
    }

    JSValue arr = JS_NewArray(ctx);
    for (size_t i = 0; i < symbols.size(); i++) {
        JS_SetPropertyUint32(ctx, arr, static_cast<uint32_t>(i), JS_NewString(ctx, symbols[i].c_str()));
    }
    return arr;
}

// C-function helper: dynamic.__getClassMethods(className)
static JSValue JsGetClassMethods(JSContext* ctx, JSValueConst /*this_val*/, int argc, JSValueConst* argv) {
    JSValue arr = JS_NewArray(ctx);
    if (argc < 1) return arr;
    const char* clsStr = JS_ToCString(ctx, argv[0]);
    if (!clsStr) return arr;
    std::string className(clsStr);
    JS_FreeCString(ctx, clsStr);

    JNIEnv* env = GetEnv();
    if (!env) return arr;
    jclass targetCls = FindClassWithFallback(env, className);
    if (!targetCls) return arr;

    jclass classCls = env->FindClass("java/lang/Class");
    if (env->ExceptionCheck()) env->ExceptionClear();
    jmethodID getDeclaredMethods = classCls ? env->GetMethodID(classCls, "getDeclaredMethods", "()[Ljava/lang/reflect/Method;") : nullptr;
    if (env->ExceptionCheck()) env->ExceptionClear();
    if (!getDeclaredMethods) {
        if (classCls) env->DeleteLocalRef(classCls);
        env->DeleteLocalRef(targetCls);
        return arr;
    }

    auto methodsObj = (jobjectArray)env->CallObjectMethod(targetCls, getDeclaredMethods);
    if (env->ExceptionCheck()) env->ExceptionClear();
    jclass methodCls = env->FindClass("java/lang/reflect/Method");
    if (env->ExceptionCheck()) env->ExceptionClear();
    jmethodID methodGetName = methodCls ? env->GetMethodID(methodCls, "getName", "()Ljava/lang/String;") : nullptr;
    if (env->ExceptionCheck()) env->ExceptionClear();

    uint32_t idx = 0;
    if (methodsObj && methodGetName) {
        jsize len = env->GetArrayLength(methodsObj);
        for (jsize i = 0; i < len; i++) {
            jobject mObj = env->GetObjectArrayElement(methodsObj, i);
            if (!mObj) continue;
            auto jName = (jstring)env->CallObjectMethod(mObj, methodGetName);
            if (env->ExceptionCheck()) env->ExceptionClear();
            if (jName) {
                const char* utf = env->GetStringUTFChars(jName, nullptr);
                if (utf && utf[0]) {
                    JS_SetPropertyUint32(ctx, arr, idx++, JS_NewString(ctx, utf));
                }
                if (utf) env->ReleaseStringUTFChars(jName, utf);
                env->DeleteLocalRef(jName);
            }
            env->DeleteLocalRef(mObj);
        }
        env->DeleteLocalRef(methodsObj);
    }
    if (methodCls) env->DeleteLocalRef(methodCls);
    if (classCls) env->DeleteLocalRef(classCls);
    env->DeleteLocalRef(targetCls);
    return arr;
}

const char* kDynamicBootstrapJs = R"JS(
(function() {
    // =========================================================================
    // 1. Dynamic Java Class & Method Proxy
    // =========================================================================
    function makeClassBox(className) {
        let cls = Java.findClass(className);
        let methodCache = null;

        function getDeclaredMethods() {
            if (!methodCache) {
                methodCache = {};
                let text = Java.listMethods(cls);
                if (typeof text === 'string') {
                    let lines = text.split('\n');
                    for (let l of lines) {
                        let idx = l.indexOf('->');
                        if (idx !== -1) {
                            let part = l.substring(idx + 2).trim();
                            let pIdx = part.indexOf('(');
                            if (pIdx !== -1) {
                                let pre = part.substring(0, pIdx).trim();
                                let dot = pre.lastIndexOf('.');
                                if (dot !== -1) {
                                    let name = pre.substring(dot + 1);
                                    if (name) methodCache[name] = true;
                                }
                            }
                        }
                    }
                }
            }
            return methodCache;
        }

        // Parse `Java.listMethods(cls)` lines -> [{art: BigInt, desc}] so we hook the
        // exact ArtMethod (no name re-resolution) and can filter by modifiers.
        function listMethodEntries() {
            let out = [];
            let text = Java.listMethods(cls);
            if (typeof text !== 'string') return out;
            let lines = text.split('\n');
            for (let l of lines) {
                let arrow = l.indexOf('->');
                if (arrow === -1) continue;
                let before = l.substring(0, arrow);
                let mm = before.match(/0x[0-9a-fA-F]+/);
                if (!mm) continue;
                let art = BigInt(mm[0]);
                let desc = l.substring(arrow + 2).trim();
                if (art && art !== 0n) out.push({ art: art, desc: desc });
            }
            return out;
        }

        // Hook every declared method of this class; skip abstract/native (no body /
        // unsafe to hook). Overloaded methods are all distinct here (by ArtMethod).
        function hookAllMethods(cb) {
            let entries = listMethodEntries();
            let n = 0, skipped = 0;
            for (let i = 0; i < entries.length; i++) {
                let d = entries[i].desc;
                if (/\babstract\b/.test(d) || /\bnative\b/.test(d)) { skipped++; continue; }
                jhook(entries[i].art, cb);
                n++;
            }
            return `Hooked ${n} method(s) of ${className}` +
                   (skipped ? ` (skipped ${skipped} abstract/native)` : "");
        }

        function makeMethodBox(mName) {
            let art = Java.findMethod(className, mName);
            let info = (art && art !== 0n && typeof Java.methodInfo === 'function')
                ? Java.methodInfo(art) : null;
            let isNative = !!(info && info.isNative);
            let nativeEntry = (info && info.nativeEntry) ? info.nativeEntry : 0n;

            let mBox = {
                className: className,
                methodName: mName,
                // .artMethod: always the ArtMethod* (works for both smali & native)
                artMethod: art,
                isNative: isNative,
                // .address: native code entry for native methods, otherwise the
                //           ArtMethod* (i.e. the address to disassemble/trace).
                address: isNative ? nativeEntry : art,
                // .ptr: native function pointer, only meaningful for native methods.
                ptr: nativeEntry,
                dumpCode: function(maxInsns) {
                    return dumpcode(art, maxInsns !== undefined ? maxInsns : -1);
                },
                dumpSmali: function(maxInsns) {
                    return dumpsmali(art, maxInsns !== undefined ? maxInsns : -1);
                },
                dumpNative: function(maxInsns) {
                    return dumpnative(isNative && nativeEntry ? nativeEntry : art,
                                      maxInsns !== undefined ? maxInsns : -1);
                },
                disassembly: function() {
                    return Java.decompile(art);
                },
                decompile: function() {
                    return Java.decompile(art);
                },
                hook: function(cb) {
                    let sig = (info && info.signature) ? info.signature : "";
                    return jhook(art, cb, className, mName, sig);
                },
                trace: function(opt) {
                    if (isNative && nativeEntry && typeof tracenative === 'function') {
                        return tracenative(nativeEntry, opt);
                    }
                    if (typeof traceunified === 'function') return traceunified(art, opt);
                    return tracejava(art, opt);
                },
                "break": function(cond) {
                    let sig = (info && info.signature) ? info.signature : "";
                    return brkj(art, cond, className, mName, sig);
                },
                // Hook every method of the declaring class (first overload per name).
                hookallclassmethods: function(cb) {
                    return hookAllMethods(cb);
                },
                toString: function() {
                    let hex = art ? '0x' + art.toString(16) : 'null';
                    let kind = isNative ? "native" : "smali";
                    let mods = (info && info.modifiers) ? info.modifiers + ' ' : '';
                    return `[JavaMethod ${mods}${className}.${mName} (${kind}) ArtMethod=${hex}]`;
                }
            };
            return mBox;
        }

        let cBox = {
            $className: className,
            $class: cls,
            dumpCode: function(maxInsns) {
                let ms = getDeclaredMethods();
                let out = `=== DumpCode for ${className} ===\n`;
                for (let k in ms) {
                    out += makeMethodBox(k).dumpCode(maxInsns) + "\n";
                }
                return out;
            },
            dumpSmali: function(maxInsns) {
                return dumpsmali(cls, maxInsns !== undefined ? maxInsns : -1);
            },
            disassembly: function() {
                return Java.decompile(className);
            },
            decompile: function() {
                return Java.decompile(className);
            },
            listMethods: function() {
                return Java.listMethods(cls);
            },
            findMethods: function(pat) {
                return Java.findMethods(className, pat || "");
            },
            // Hook every declared method of this class (first overload per name).
            hookall: function(cb) {
                return hookAllMethods(cb);
            },
            // Search all live heap instances of this class (like Frida Java.choose)
            choose: function(callbacks) {
                return Java.choose(className, callbacks);
            },
            toString: function() {
                let hex = cls ? '0x' + cls.toString(16) : 'null';
                return `[JavaClass ${className} @ ${hex}]`;
            }
        };

        return new Proxy(cBox, {
            get(target, prop) {
                if (typeof prop !== 'string') return target[prop];
                if (prop in target) return target[prop];

                // If user accessed a method on the class
                let mb = makeMethodBox(prop);
                if (mb.artMethod && mb.artMethod !== 0n) return mb;

                // Support inner class chaining (e.g. MainActivity.Inner or MainActivity.$Inner)
                let innerProp = prop.startsWith("$") ? prop : ("$" + prop);
                let inner = className + innerProp;
                let innerCls = Java.findClass(inner);
                if (innerCls) return makeClassBox(inner);

                return mb;
            }
        });
    }

    function makeJavaPackage(path) {
        let pkgObj = {
            $path: path,
            toString: function() {
                return `[JavaPackage ${path || "<root>"}]`;
            }
        };
        return new Proxy(pkgObj, {
            get(target, prop) {
                if (typeof prop !== 'string') return target[prop];
                if (prop in target) return target[prop];
                let next = path ? (path + "." + prop) : prop;
                let cls = Java.findClass(next);
                if (cls) {
                    return makeClassBox(next);
                }
                return makeJavaPackage(next);
            }
        });
    }

    // =========================================================================
    // 2. Dynamic Native Module & Symbol Proxy (Boxed Address)
    // =========================================================================
    function makeNativeBox(modName, symName, addr) {
        let box = {
            module: modName,
            symbol: symName,
            address: addr,
            ptr: addr,
            hook: function(cb) {
                return nhook(addr, cb);
            },
            "break": function() {
                return brkn(addr);
            },
            dumpNative: function(maxInsns) {
                return dumpnative(addr, maxInsns !== undefined ? maxInsns : -1);
            },
            hexdump: function(len) {
                return hexdump(addr, len !== undefined ? len : 64);
            },
            readByteArray: function(len) {
                return readmem(addr, len);
            },
            readCString: function() {
                return readstring(addr);
            },
            readU32: function() {
                return readu32(addr);
            },
            writeU32: function(val) {
                return writeu32(addr, val);
            },
            toString: function() {
                let hex = addr ? '0x' + addr.toString(16) : 'null';
                return `[NativeBox ${modName}!${symName} @ ${hex}]`;
            }
        };
        return box;
    }

    function makeModuleProxy(modName) {
        let actual = modName;
        if (!actual.endsWith(".so")) actual += ".so";
        let mod = Native.findModule(actual);
        if (!mod) {
            mod = Native.findModule(modName);
            if (mod) actual = modName;
        }

        let mBox = {
            $name: actual,
            $mod: mod,
            findSymbol: function(sym) {
                return Native.findSymbol(actual, sym);
            },
            toString: function() {
                let baseHex = (mod && mod.base) ? '0x' + mod.base.toString(16) : 'null';
                return `[NativeModule ${actual} base=${baseHex}]`;
            }
        };

        let pxy;
        pxy = new Proxy(mBox, {
            get(target, prop) {
                if (typeof prop !== 'string') return target[prop];
                if (prop === "so") return pxy;
                if (prop in target) return target[prop];

                let addr = Native.findSymbol(actual, prop);
                if (!addr || addr === 0n) {
                    addr = Native.findSymbol(actual, "_" + prop);
                }
                return makeNativeBox(actual, prop, addr || 0n);
            }
        });
        return pxy;
    }

    let nativeRoot = new Proxy({}, {
        get(target, prop) {
            if (typeof prop !== 'string') return undefined;
            let m = prop;
            if (m.endsWith("_so")) {
                m = m.substring(0, m.length - 3) + ".so";
            }
            return makeModuleProxy(m);
        }
    });

    globalThis.dynamic = {
        java: makeJavaPackage(""),
        native: nativeRoot,
        __getCompletionData: function() {
            return __native_getCompletionData();
        },
        __findMatchingClasses: function(prefix, limit) {
            return __native_findMatchingClasses(prefix, limit);
        },
        __getModuleSymbols: function(mod) {
            return __native_getModuleSymbols(mod);
        },
        __getClassMethods: function(cls) {
            return __native_getClassMethods(cls);
        }
    };
})();
)JS";

} // namespace

void RegisterDynamicApis(JSContext* ctx) {
    JSValue global = JS_GetGlobalObject(ctx);

    // Register native helpers for completion and introspection
    JS_SetPropertyStr(ctx, global, "__native_getCompletionData",
                      JS_NewCFunction(ctx, JsGetCompletionData, "__native_getCompletionData", 0));
    JS_SetPropertyStr(ctx, global, "__native_findMatchingClasses",
                      JS_NewCFunction(ctx, JsFindMatchingClasses, "__native_findMatchingClasses", 2));
    JS_SetPropertyStr(ctx, global, "__native_getModuleSymbols",
                      JS_NewCFunction(ctx, JsGetModuleSymbols, "__native_getModuleSymbols", 1));
    JS_SetPropertyStr(ctx, global, "__native_getClassMethods",
                      JS_NewCFunction(ctx, JsGetClassMethods, "__native_getClassMethods", 1));

    // Evaluate dynamic bootstrap script to create globalThis.dynamic proxy tree
    JSValue res = JS_Eval(ctx, kDynamicBootstrapJs, strlen(kDynamicBootstrapJs), "<dynamic_bootstrap>", JS_EVAL_TYPE_GLOBAL);
    if (JS_IsException(res)) {
        JSValue exc = JS_GetException(ctx);
        const char* err = JS_ToCString(ctx, exc);
        PI_LOGE("RegisterDynamicApis: Failed to evaluate bootstrap JS: %s", err ? err : "unknown");
        if (err) JS_FreeCString(ctx, err);
        JS_FreeValue(ctx, exc);
    }
    JS_FreeValue(ctx, res);

    JS_FreeValue(ctx, global);
}

}} // namespace artpi::agent
