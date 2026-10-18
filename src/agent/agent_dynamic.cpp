//
// agent_dynamic.cpp - Dynamic Proxy-based chainable invocation API for Java & Native
//
#include "agent_dynamic.h"
#include "agent_common.h"
#include "agent_java.h"
#include "agent_native.h"
#include "agent_memory.h"
#include "agent_unity.h"
#include "../../include/ArtPI.h"
#include "frida-gum.h"

#include <link.h>
#include <vector>
#include <string>
#include <algorithm>
#include <sstream>
#include <mutex>
#include <cstdio>
#include <cstring>
#include <dlfcn.h>
#include <unistd.h>

#if defined(_WIN32)
#include <windows.h>
#endif

#ifndef RTLD_NOLOAD
#define RTLD_NOLOAD 0x4
#endif

namespace artpi { namespace agent {

namespace {

// C-function helper: dynamic.__getCompletionData()
static JSValue JsGetCompletionData(JSContext* ctx, JSValueConst /*this_val*/, int /*argc*/, JSValueConst* /*argv*/) {
    JSValue root = JS_NewObject(ctx);

    // 1. Initial App Classes (keep payload fast & lightweight, < 300 entries).
    //    Skip JNI enumeration while the main thread is paused in the startup gate.
    JNIEnv* env = ArtPIIsProcessPaused() ? nullptr : GetEnv();
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
    function createUnavailableDomain(name, reason) {
        let box = {
            $domain: name,
            $available: false,
            $reason: reason || "unavailable",
            isAvailable: function() { return false; },
            toString: function() { return `[DynamicDomain ${name}: unavailable - ${this.$reason}]`; }
        };
        return new Proxy(box, {
            get(target, prop) {
                if (typeof prop !== 'string') return target[prop];
                if (prop in target) return target[prop];
                return undefined;
            }
        });
    }

    function createDynamicRoot() {
        let root = {
            __domains: {},
            register: function(name, rootObj) {
                if (!name || !rootObj) return rootObj;
                this.__domains[name] = rootObj;
                this[name] = rootObj;
                return rootObj;
            },
            has: function(name) {
                return !!this.__domains[name];
            },
            domains: function() {
                return Object.keys(this.__domains).sort();
            },
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
        return root;
    }

    // =========================================================================
    // 1. Dynamic Java Class & Method Proxy
    // =========================================================================
    function makeClassBox(className) {
        // Java.findClass() returns a BigInt jclass on success, but a *string*
        // for wildcard listings and for the "[!] ... did you mean" suggestions.
        // Treating that string as a class is what made `listMethods()` report
        // "Class not found" on a mis-resolved dot chain.
        let found = Java.findClass(className);
        let cls = (typeof found === 'bigint') ? found : null;
        let resolveError = (typeof found === 'string') ? found : "";
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

        // Hook declared methods of this class; skip abstract/native (no body /
        // unsafe to hook). Supports optional methodPattern filter as first arg:
        //   cls.hookall()
        //   cls.hookall(onEnter [, onLeave])
        //   cls.hookall("encrypt|Header" [, onEnter, onLeave])
        function hookAllMethods(arg0, arg1, arg2) {
            if (!cls) {
                return resolveError || ("[!] Class not found: " + className);
            }
            if (typeof arg0 === 'string') {
                if (typeof Java.findAndHookAll === 'function') {
                    return Java.findAndHookAll(className, arg0, arg1, arg2);
                }
                if (typeof Java.findAndHook === 'function') {
                    return Java.findAndHook(className, arg0, arg1, arg2);
                }
            }
            let entries = listMethodEntries();
            let n = 0, skipped = 0;
            for (let i = 0; i < entries.length; i++) {
                let d = entries[i].desc;
                if (/\babstract\b/.test(d) || /\bnative\b/.test(d)) { skipped++; continue; }
                if (typeof arg1 === 'function') {
                    jhook(entries[i].art, arg0, arg1);
                } else {
                    jhook(entries[i].art, arg0);
                }
                n++;
            }
            return `Hooked ${n} method(s) of ${className}` +
                    (skipped ? ` (skipped ${skipped} abstract/native)` : "");
        }

        function formatPrettySignature(sig) {
            if (!sig || typeof sig !== 'string' || sig[0] !== '(') return { params: "", ret: "" };
            let closeIdx = sig.indexOf(')');
            if (closeIdx === -1) return { params: "", ret: "" };

            function parseType(s, pos) {
                let dim = 0;
                while (pos < s.length && s[pos] === '[') {
                    dim++;
                    pos++;
                }
                if (pos >= s.length) return { name: "unknown", next: pos };
                let ch = s[pos++];
                let base = "unknown";
                if (ch === 'Z') base = "boolean";
                else if (ch === 'B') base = "byte";
                else if (ch === 'C') base = "char";
                else if (ch === 'S') base = "short";
                else if (ch === 'I') base = "int";
                else if (ch === 'J') base = "long";
                else if (ch === 'F') base = "float";
                else if (ch === 'D') base = "double";
                else if (ch === 'V') base = "void";
                else if (ch === 'L') {
                    let semi = s.indexOf(';', pos);
                    if (semi === -1) {
                        base = s.substring(pos).replace(/\//g, '.');
                        pos = s.length;
                    } else {
                        base = s.substring(pos, semi).replace(/\//g, '.');
                        pos = semi + 1;
                    }
                }
                while (dim-- > 0) base += "[]";
                return { name: base, next: pos };
            }

            let params = [];
            let i = 1;
            while (i < closeIdx) {
                let res = parseType(sig, i);
                params.push(res.name);
                i = res.next;
            }
            let retRes = parseType(sig, closeIdx + 1);
            return { params: params.join(", "), ret: retRes.name };
        }

        // Build a method box from an already-resolved ArtMethod* + its metadata.
        // Shared by class-box property access and the global `jmethodBox`
        // (raw ArtMethod* -> dynamic-style box) entry point.
        function buildMethodBox(mName, art, info) {
            let isNative = !!(info && info.isNative);
            let nativeEntry = (info && info.nativeEntry) ? info.nativeEntry : 0n;

            let mFn = function(...args) {
                if (typeof __native_jcall === 'function') {
                    return __native_jcall(className, mName, ...args);
                }
                throw new Error("__native_jcall is not available");
            };

            // ---- dual-path invocation -------------------------------------
            // m(...)            : ART/JNI call (backwards compatible)
            // .invokeJni(...)   : explicit ART/JNI call
            // .invokeInterp(..) : run the bytecode on the embedded nmmvm
            // .bind(obj)        : receiver-bound view for instance methods
            mFn.invokeJni = function(...args) {
                return __native_invoke(art, 'jni', null, ...args);
            };
            mFn.callJni = mFn.invokeJni;
            mFn.invokeInterp = function(...args) {
                return __native_invoke(art, 'interp', null, ...args);
            };
            mFn.callInterp = mFn.invokeInterp;
            mFn.invoke = mFn.invokeInterp;   // NMMVM is the "instrumented" path
            mFn.nmmvm = mFn.invokeInterp;
            mFn.bind = function(thiz) {
                let bound = {
                    $thiz: thiz,
                    className: className,
                    methodName: mName,
                    artMethod: art,
                    signature: (info && info.signature) ? info.signature : "",
                    invokeJni: function(...args) { return __native_invoke(art, 'jni', thiz, ...args); },
                    invokeInterp: function(...args) { return __native_invoke(art, 'interp', thiz, ...args); },
                    call: function(...args) { return __native_invoke(art, 'jni', thiz, ...args); },
                    interp: function(...args) { return __native_invoke(art, 'interp', thiz, ...args); },
                    invoke: function(...args) { return __native_invoke(art, 'interp', thiz, ...args); },
                    callInterp: function(...args) { return __native_invoke(art, 'interp', thiz, ...args); },
                    nmmvm: function(...args) { return __native_invoke(art, 'interp', thiz, ...args); },
                    toString: function() { return "[JavaMethod bound " + className + "." + mName + "]"; }
                };
                return bound;
            };

            mFn.className = className;
            mFn.methodName = mName;
            // .artMethod: always the ArtMethod* (works for both smali & native)
            mFn.artMethod = art;
            mFn.isNative = isNative;
            // .address: native code entry for native methods, otherwise the
            //           ArtMethod* (i.e. the address to disassemble/trace).
            mFn.address = isNative ? nativeEntry : art;
            // .ptr: native function pointer, only meaningful for native methods.
            mFn.ptr = nativeEntry;
            mFn.signature = (info && info.signature) ? info.signature : "";

            mFn.dumpCode = function(maxInsns) {
                return dumpcode(art, maxInsns !== undefined ? maxInsns : -1);
            };
            mFn.dumpSmali = function(maxInsns) {
                return dumpsmali(art, maxInsns !== undefined ? maxInsns : -1);
            };
            mFn.dumpNative = function(maxInsns) {
                return dumpnative(isNative && nativeEntry ? nativeEntry : art,
                                  maxInsns !== undefined ? maxInsns : -1);
            };
            mFn.disassembly = function() {
                return Java.decompile(art);
            };
            mFn.decompile = function() {
                return Java.decompile(art);
            };
            // .hook(cb): single callback (Frida-style) — cb.setResult(v) overrides
            //            the return and skips the original method.
            // .hook(onEnter, onLeave): two-callback form — onEnter may inspect/mutate
            //            args, the original ALWAYS runs, then onLeave observes the
            //            result and may override it via onLeave.setResult(v).
            mFn.hook = function(onEnter, onLeave) {
                let sig = (info && info.signature) ? info.signature : "";
                if (typeof onLeave === 'function') {
                    return jhook(art, onEnter, onLeave, className, mName, sig);
                }
                return jhook(art, onEnter, className, mName, sig);
            };
            mFn.trace = function(opt) {
                if (isNative && nativeEntry && typeof tracenative === 'function') {
                    return tracenative(nativeEntry, opt);
                }
                if (typeof traceunified === 'function') return traceunified(art, opt);
                return tracejava(art, opt);
            };
            mFn["break"] = function(cond) {
                let sig = (info && info.signature) ? info.signature : "";
                return brkj(art, cond, className, mName, sig);
            };
            // Hook every method of the declaring class (first overload per name).
            mFn.hookallclassmethods = function(cb) {
                return hookAllMethods(cb);
            };
            mFn.toString = function() {
                let hex = art ? '0x' + art.toString(16) : 'null';
                let kind = isNative ? "native" : "smali";
                let mods = (info && info.modifiers) ? info.modifiers + ' ' : '';
                let sigObj = (info && info.signature) ? formatPrettySignature(info.signature) : { params: "", ret: "" };
                let retStr = (sigObj.ret && sigObj.ret !== "void" && mName !== "<init>") ? (sigObj.ret + ' ') : (sigObj.ret === "void" ? "void " : "");
                return `[JavaMethod ${mods}${retStr}${className}.${mName}(${sigObj.params}) (${kind}) ArtMethod=${hex}]`;
            };
            return mFn;
        }

        // Resolve by name (class-box access path) then delegate to buildMethodBox.
        function makeMethodBox(mName) {
            let art = Java.findMethod(className, mName);
            let info = (art && art !== 0n && typeof Java.methodInfo === 'function')
                ? Java.methodInfo(art) : null;
            return buildMethodBox(mName, art, info);
        }

        let cBox = {
            $className: className,
            $class: cls,
            // Build a box for an explicit ArtMethod* (used by global jmethodBox).
            $makeMethodBox: function(art, info) {
                return buildMethodBox((info && info.name) ? info.name : "", art, info);
            },
            dumpCode: function(maxInsns) {
                let ms = getDeclaredMethods();
                let out = `=== DumpCode for ${className} ===\n`;
                for (let k in ms) {
                    out += makeMethodBox(k).dumpCode(maxInsns) + "\n";
                }
                return out;
            },
            dumpSmali: function(maxInsns) {
                let ms = getDeclaredMethods();
                let out = `=== DumpSmali for ${className} ===\n`;
                for (let k in ms) {
                    out += makeMethodBox(k).dumpSmali(maxInsns) + "\n";
                }
                return out;
            },
            disassembly: function() {
                return Java.decompile(className);
            },
            decompile: function() {
                return Java.decompile(className);
            },
            listMethods: function() {
                if (!cls) {
                    return resolveError || ("[!] Class not found: " + className);
                }
                return Java.listMethods(cls);
            },
            findMethods: function(pat) {
                return Java.findMethods(className, pat || "");
            },
            // Hook every declared method of this class (or filter by pattern string).
            hookall: function(a, b, c) {
                return hookAllMethods(a, b, c);
            },
            hookAll: function(a, b, c) {
                return hookAllMethods(a, b, c);
            },
            findAndHook: function(pat, onEnter, onLeave) {
                return hookAllMethods(pat || "*", onEnter, onLeave);
            },
            findandhook: function(pat, onEnter, onLeave) {
                return hookAllMethods(pat || "*", onEnter, onLeave);
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
                if (typeof innerCls === 'bigint') return makeClassBox(inner);

                // Static field access on class
                if (typeof __native_jfget === 'function') {
                    let fv = __native_jfget(className, prop);
                    if (fv !== undefined) return fv;
                }

                return mb;
            },
            set(target, prop, value) {
                if (typeof prop !== 'string') { target[prop] = value; return true; }
                if (prop in target) { target[prop] = value; return true; }
                if (typeof __native_jfset === 'function') {
                    if (__native_jfset(className, prop, value)) return true;
                }
                target[prop] = value;
                return true;
            }
        });
    }

    function makeJavaRoot() {
        if (typeof Java === 'undefined' || !Java.findClass) {
            return createUnavailableDomain("java", "Java/ART runtime is not available in this process");
        }
        // The java root doubles as a package proxy; special-case a handful of
        // top-level helpers that would otherwise be shadowed by package lookup
        // (e.g. dynamic.java.dumpalldex()).
        let pkgRoot = makeJavaPackage("");
        let specials = {
            findAndHook: function(...args) {
                if (typeof Java.findAndHook !== 'function') throw new Error("Java.findAndHook is unavailable");
                return Java.findAndHook(...args);
            },
            findandhook: function(...args) {
                if (typeof Java.findAndHook !== 'function') throw new Error("Java.findAndHook is unavailable");
                return Java.findAndHook(...args);
            },
            findAndHookAll: function(...args) {
                if (typeof Java.findAndHookAll !== 'function') throw new Error("Java.findAndHookAll is unavailable");
                return Java.findAndHookAll(...args);
            },
            findandhookall: function(...args) {
                if (typeof Java.findAndHookAll !== 'function') throw new Error("Java.findAndHookAll is unavailable");
                return Java.findAndHookAll(...args);
            },
            dumpAllDex: function(dir) {
                if (typeof Java.dumpAllDex !== 'function') throw new Error("Java.dumpAllDex is unavailable");
                return Java.dumpAllDex(dir);
            },
            dumpalldex: function(dir) {
                if (typeof Java.dumpallDex !== 'function') throw new Error("Java.dumpAllDex is unavailable");
                return Java.dumpallDex(dir);
            },
            dumpDex: function(dir) {
                if (typeof Java.dumpDex !== 'function') throw new Error("Java.dumpAllDex is unavailable");
                return Java.dumpDex(dir);
            },
            $path: "",
            toString: function() { return "[JavaDomain]"; }
        };
        return new Proxy(specials, {
            get(target, prop) {
                if (typeof prop !== 'string') return target[prop];
                if (prop in target) return target[prop];
                return pkgRoot[prop];
            },
            set(target, prop, value) {
                if (typeof prop !== 'string') { target[prop] = value; return true; }
                if (prop in target) { target[prop] = value; return true; }
                pkgRoot[prop] = value;
                return true;
            }
        });
    }

    // Class-level API names. If one of these is accessed on a *package* chain,
    // the previous segment was meant to be a class: surface findClass()'s
    // "did you mean" message instead of silently building a bogus package.
    const CLASS_BOX_APIS = {
        hookall: 1, hookAll: 1, listMethods: 1, findMethods: 1, choose: 1,
        findAndHook: 1, findandhook: 1, dumpCode: 1, dumpSmali: 1,
        disassembly: 1, decompile: 1, hookallclassmethods: 1, $makeMethodBox: 1
    };

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
                if (path && CLASS_BOX_APIS[prop] === 1) {
                    let asCls = Java.findClass(path);
                    if (typeof asCls !== 'bigint') {
                        return function() {
                            return (typeof asCls === 'string')
                                ? asCls
                                : ("[!] Class not found: " + path);
                        };
                    }
                    return makeClassBox(path)[prop];
                }
                let next = path ? (path + "." + prop) : prop;
                let cls = Java.findClass(next);
                // Only a BigInt is a real jclass; strings are "did you mean"
                // suggestions and must NOT terminate the package chain.
                if (typeof cls === 'bigint') {
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
            invoke: function(...args) {
                return Native.invoke(addr, ...args);
            },
            call: function(...args) {
                return Native.invoke(addr, ...args);
            },
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
        return new Proxy(function(...args) {
            return Native.invoke(addr, ...args);
        }, {
            get(target, prop) {
                if (prop in box) return box[prop];
                return target[prop];
            },
            apply(target, thisArg, args) {
                return Native.invoke(addr, ...args);
            }
        });
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

    // =========================================================================
    // 3. Dynamic Unity & ObjC stubs
    // =========================================================================
    // dynamic.unity.il2cpp exposes every exported symbol of libil2cpp.so.
    // Property access returns a NativeBox (address/hook/dump helpers); tab
    // completion is served by __native_unity_completions('il2cpp').
    function makeUnityIl2cppRoot() {
        let box = {
            __unity_kind: "il2cpp",
            __ptr: 0,
            $name: "libil2cpp.so",
            findSymbol: function(name) {
                return Native.findSymbol("libil2cpp.so", name);
            },
            toString: function() { return "[UnityIL2CPP libil2cpp.so]"; }
        };
        return new Proxy(box, {
            get(target, prop) {
                if (typeof prop !== 'string') return target[prop];
                if (prop in target) return target[prop];
                // Never treat internal probes (__h/__ptr/...) as symbols; the
                // generic completion helper checks __h to detect Java refs.
                if (prop.charCodeAt(0) === 95) return undefined;
                let addr = Native.findSymbol("libil2cpp.so", prop);
                if (!addr) addr = Native.findSymbol("libil2cpp.so", "_" + prop);
                return makeNativeBox("libil2cpp.so", prop, addr || 0n);
            }
        });
    }

    function makeUnityMethodProxy(m, clsObj) {
        if (!m) return null;
        let fn = function(...args) {
            return m.invoke(...args);
        };
        fn.methodInfo = m.methodInfo;
        fn.address = m.address;
        fn.invoke = function(...args) { return m.invoke(...args); };
        fn.call = function(...args) { return m.invoke(...args); };
        fn.hook = function(cb) {
            if (m.address && m.address !== 0n) {
                return nhook(m.address, cb);
            }
            throw new Error("Method has no native function address to hook");
        };
        fn.b = function() {
            if (m.methodInfo && typeof dynamic.unity.b === 'function') {
                return dynamic.unity.b(m.methodInfo);
            }
            if (m.address && m.address !== 0n) return brkn(m.address);
            throw new Error("No address or methodInfo available for breakpoint");
        };
        fn.mi = function() {
            if (m.methodInfo && typeof dynamic.unity.mi === 'function') {
                return dynamic.unity.mi(m.methodInfo);
            }
            return m.toString();
        };
        fn.toString = function() { return m.toString(); };
        fn.__unity_kind = 'method';
        fn.__ptr = m.__ptr;
        return fn;
    }

    function makeClassProxy(clsObj) {
        if (!clsObj) return null;
        let pxy;
        pxy = new Proxy(clsObj, {
            get(target, prop) {
                if (typeof prop !== 'string') return target[prop];
                if (prop.charCodeAt(0) === 95 && prop.length > 1 && prop.charAt(1) === '_') {
                    return target[prop];
                }

                let mName = prop;
                if (mName === "_ctor" || mName === "$ctor" || mName === "ctor") {
                    mName = ".ctor";
                } else if (mName === "_cctor" || mName === "$cctor" || mName === "cctor") {
                    mName = ".cctor";
                }

                // Prefer exact Unity members over helper properties such as
                // name/address/type. No fuzzy fallback here: a typo must not
                // silently resolve to an unrelated method.
                if (typeof target.__lookup === 'function') {
                    let member = target.__lookup(mName);
                    if (member) {
                        if (member.__unity_kind === 'method') {
                            return makeUnityMethodProxy(member, target);
                        }
                        return member;
                    }
                }

                if (prop in target) return target[prop];
                return undefined;
            }
        });
        return pxy;
    }

    function makeAssemblyProxy(asmObj) {
        if (!asmObj) return null;
        let pxy;
        pxy = new Proxy(asmObj, {
            get(target, prop) {
                if (typeof prop !== 'string') return target[prop];
                if (prop.charCodeAt(0) === 95 && prop.length > 1 && prop.charAt(1) === '_') {
                    return target[prop];
                }

                // Exact class lookup first, so a class named "name"/"class" is
                // not shadowed by the helper properties on the assembly object.
                if (typeof target.__lookupClass === 'function') {
                    let cls = target.__lookupClass(prop);
                    if (!cls && prop.indexOf('_') >= 0) {
                        let dotted = prop.replace(/_/g, '.');
                        if (dotted !== prop) cls = target.__lookupClass(dotted);
                    }
                    if (!cls && prop.indexOf('_') >= 0) {
                        let slashed = prop.replace(/_/g, '/');
                        if (slashed !== prop) cls = target.__lookupClass(slashed);
                    }
                    if (!cls && prop.indexOf('_') >= 0) {
                        let dashed = prop.replace(/_/g, '-');
                        if (dashed !== prop) cls = target.__lookupClass(dashed);
                    }
                    if (cls) return makeClassProxy(cls);
                }

                if (prop in target) return target[prop];
                return undefined;
            }
        });
        return pxy;
    }

    function makeUnityAssemblyRootProxy(nativeAssemblyFn, root) {
        let fnWrapper = function(name) {
            let asm = nativeAssemblyFn(name);
            return asm ? makeAssemblyProxy(asm) : null;
        };

        function normalizeAsmName(name) {
            return name.toLowerCase().replace(/[-.]/g, '_');
        }

        function findAssembly(prop) {
            let asm = nativeAssemblyFn(prop);
            if (asm) return asm;
            asm = nativeAssemblyFn(prop + ".dll");
            if (asm) return asm;

            // Dot-chain identifiers cannot contain '.', so completions rewrite
            // both '-' and '.' to '_'. Try both interpretations here.
            let dashed = prop.replace(/_/g, '-');
            asm = nativeAssemblyFn(dashed);
            if (asm) return asm;
            asm = nativeAssemblyFn(dashed + ".dll");
            if (asm) return asm;

            let dotted = prop.replace(/_/g, '.');
            asm = nativeAssemblyFn(dotted);
            if (asm) return asm;
            asm = nativeAssemblyFn(dotted + ".dll");
            if (asm) return asm;

            try {
                let list = root.assemblies();
                let pNorm = normalizeAsmName(prop);
                for (let i = 0; i < list.length; i++) {
                    let aName = list[i];
                    let aStem = aName.endsWith('.dll') ? aName.slice(0, -4) : aName;
                    if (normalizeAsmName(aStem) === pNorm || normalizeAsmName(aName) === pNorm) {
                        return nativeAssemblyFn(aName);
                    }
                }
            } catch(e) {}
            return null;
        }

        let pxy;
        pxy = new Proxy(fnWrapper, {
            get(target, prop) {
                if (typeof prop !== 'string') return target[prop];
                if (prop === '__unity_kind') return 'assembly_root';
                if (prop === '__ptr') return 0;
                if (prop === 'toString') return function() { return "[UnityAssemblyRoot]"; };
                if (prop.charCodeAt(0) === 95 && prop.length > 1 && prop.charAt(1) === '_') {
                    return target[prop];
                }
                if (prop in target) return target[prop];

                let asm = findAssembly(prop);
                if (asm) {
                    return makeAssemblyProxy(asm);
                }
                return undefined;
            }
        });
        return pxy;
    }

    function makeUnityRoot() {
        let root = globalThis.__NativeUnity;
        if (!root) return createUnavailableDomain("unity", "UnityResolve bridge missing");
        root.$domain = "unity";
        root.$available = true;
        root.il2cpp = makeUnityIl2cppRoot();
        if (typeof root.assembly === 'function') {
            let nativeAssemblyFn = root.assembly.bind(root);
            root.assembly = makeUnityAssemblyRootProxy(nativeAssemblyFn, root);
        }
        // Compatibility aliases with the old placeholder API.
        root.findAssemblies = function() { try { return root.assemblies(); } catch (e) { return []; } };
        root.findClasses = function(a) { try { let asm = root.assembly(a); return asm ? asm.classes() : []; } catch (e) { return []; } };
        root.findMethods = function(a, c) { try { let asm = root.assembly(a); let cls = asm && asm.class(c); return cls ? cls.methods() : []; } catch (e) { return []; } };
        root.toString = function() { return "[UnityDomain: UnityResolve]"; };
        return root;
    }

    function makeObjcRoot() {
        let root = {
            $domain: "objc",
            $available: true,
            isAvailable: function() { return true; },
            findClasses: function() { return []; },
            findMethods: function() { return []; },
            toString: function() { return "[ObjCDomain available: empty implementation]"; }
        };
        return new Proxy(root, {
            get(target, prop) {
                if (typeof prop !== 'string') return target[prop];
                if (prop in target) return target[prop];
                return createUnavailableDomain("objc." + prop, "Objective-C runtime bridge is not implemented yet");
            }
        });
    }

    let dyn = createDynamicRoot();
    if (typeof __native_dynamicHasJava === 'function' && __native_dynamicHasJava()) {
        dyn.register("java", makeJavaRoot());
    }
    dyn.register("native", nativeRoot);
    if (typeof __native_dynamicHasUnity === 'function' && __native_dynamicHasUnity()) {
        dyn.register("unity", makeUnityRoot());
    }
    if (typeof __native_dynamicHasObjc === 'function' && __native_dynamicHasObjc()) {
        dyn.register("objc", makeObjcRoot());
    }
    globalThis.dynamic = dyn;

    // -------------------------------------------------------------------------
    // Raw ArtMethod* -> dynamic-style method box.
    //   let m = jmethodBox(findmethod("com.example.App", "onCreate"));
    //   m.hook(cb) / m.dumpSmali() / m.trace() / m.break() ...
    // -------------------------------------------------------------------------
    function makeJavaMethodBox(artPtr) {
        if (artPtr === undefined || artPtr === null) return null;
        let art;
        try {
            art = (typeof artPtr === 'bigint') ? artPtr : BigInt(artPtr);
        } catch (e) {
            return null;
        }
        if (art === 0n) return null;
        if (typeof Java === 'undefined' || typeof Java.methodInfo !== 'function') return null;
        let info = Java.methodInfo(art);
        if (!info || !info.className) return null;
        if (info.artMethod !== undefined && info.artMethod !== null) art = info.artMethod;
        let cb = makeClassBox(info.className);
        return cb.$makeMethodBox(art, info);
    }
    globalThis.__makeJavaMethodBox = makeJavaMethodBox;
    globalThis.jmethodBox = makeJavaMethodBox;
    globalThis.jmethodbox = makeJavaMethodBox;
    globalThis.methodBox = makeJavaMethodBox;
    globalThis.methodbox = makeJavaMethodBox;
    if (typeof Java === 'object' && Java) Java.methodBox = makeJavaMethodBox;
})();
)JS";

static bool HasLoadedModuleByName(const char* needle) {
    if (!needle || !needle[0]) return false;
    auto modules = CollectAllLoadedModules();
    for (const auto& name : modules) {
        if (name == needle) return true;
    }
    return false;
}

#if defined(__ANDROID__)
static std::string DynamicCurrentPackage() {
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

static bool FileExists(const std::string& path) {
    return access(path.c_str(), F_OK) == 0;
}

// True when the app ships a Unity runtime even if it has not been dlopen'd yet
// (important for -S: the agent runs before libil2cpp.so is mapped).  Derive the
// app's native lib dir from the mapped base.apk instead of globbing /data/app
// (glob is API 28+ and /data/app is not listable from the app UID).
static bool HasUnityLibraryOnDisk() {
    // Injector-provided hint from the boot cfg: <apk-dir>/lib/arm64.
    std::string hint = UnityGetLibDirHint();
    if (!hint.empty() &&
        (FileExists(hint + "/libil2cpp.so") || FileExists(hint + "/libunity.so"))) {
        return true;
    }

    auto mods = EnumerateAllLoadedModules();
    for (const auto& m : mods) {
        size_t apk = m.path.find("/base.apk");
        if (apk == std::string::npos) continue;
        size_t slash = m.path.rfind('/', apk);
        if (slash == std::string::npos) continue;
        std::string appDir = m.path.substr(0, slash); // .../<pkg>-<hash>

        static const char* kAbis[] = { "arm64", "arm", "x86_64", "x86" };
        for (const char* abi : kAbis) {
            std::string libDir = appDir + "/lib/" + abi;
            if (FileExists(libDir + "/libil2cpp.so") ||
                FileExists(libDir + "/libunity.so")) {
                return true;
            }
        }
    }

    // Some apps copy native libs into their data dir.
    std::string pkg = DynamicCurrentPackage();
    if (!pkg.empty()) {
        std::string dataDir = "/data/user/0/" + pkg + "/lib";
        if (FileExists(dataDir + "/libil2cpp.so") ||
            FileExists(dataDir + "/libunity.so")) {
            return true;
        }
    }
    return false;
}
#endif

static JSValue JsDynamicHasJava(JSContext* ctx, JSValueConst, int, JSValueConst*) {
#if defined(__ANDROID__)
    return JS_NewBool(ctx, true);
#else
    return JS_NewBool(ctx, false);
#endif
}

static JSValue JsDynamicHasUnity(JSContext* ctx, JSValueConst, int, JSValueConst*) {
#if defined(__ANDROID__)
    // libil2cpp.so/libunity.so: already mapped OR shipped by this app on disk.
    bool has = HasLoadedModuleByName("libil2cpp.so") ||
               HasLoadedModuleByName("libunity.so") ||
               HasUnityLibraryOnDisk() ||
               !UnityGetLibDirHint().empty();
    return JS_NewBool(ctx, has);
#elif defined(_WIN32)
    bool has = GetModuleHandleA("GameAssembly.dll") != nullptr ||
               GetModuleHandleA("UnityPlayer.dll") != nullptr;
    return JS_NewBool(ctx, has);
#elif defined(__APPLE__)
    // iOS: UnityFramework.framework; macOS: UnityPlayer.dylib / UnityPlayer.
    bool has = dlopen("UnityFramework.framework/UnityFramework", RTLD_NOLOAD) != nullptr ||
               dlopen("UnityFramework", RTLD_NOLOAD) != nullptr ||
               dlopen("UnityPlayer.dylib", RTLD_NOLOAD) != nullptr ||
               dlopen("UnityPlayer", RTLD_NOLOAD) != nullptr;
    return JS_NewBool(ctx, has);
#elif defined(__linux__)
    bool has = HasLoadedModuleByName("libil2cpp.so") ||
               HasLoadedModuleByName("libunity.so");
    return JS_NewBool(ctx, has);
#else
    return JS_NewBool(ctx, false);
#endif
}

static JSValue JsDynamicHasObjc(JSContext* ctx, JSValueConst, int, JSValueConst*) {
#if defined(__APPLE__)
    return JS_NewBool(ctx, true);
#else
    return JS_NewBool(ctx, false);
#endif
}

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
    JS_SetPropertyStr(ctx, global, "__native_dynamicHasJava",
                      JS_NewCFunction(ctx, JsDynamicHasJava, "__native_dynamicHasJava", 0));
    JS_SetPropertyStr(ctx, global, "__native_dynamicHasUnity",
                      JS_NewCFunction(ctx, JsDynamicHasUnity, "__native_dynamicHasUnity", 0));
    JS_SetPropertyStr(ctx, global, "__native_dynamicHasObjc",
                      JS_NewCFunction(ctx, JsDynamicHasObjc, "__native_dynamicHasObjc", 0));

    // UnityResolve bridge (globalThis.__NativeUnity), consumed by makeUnityRoot().
    RegisterUnityApis(ctx, global);

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
