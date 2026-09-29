//
// agent_java.cpp - Java / ART domain bindings for QuickJS
//
#include "agent_java.h"
#include "agent_common.h"
#include "agent_net.h"
#include "../../include/ArtPI.h"
#include "art/art_method.h"

#include "android.h"
#include <dlfcn.h>

extern "C" {
    jobject PineNative_ToJObject(JNIEnv* env, void* art_obj);
    void* PineNative_ToArtObject(JNIEnv* env, jobject j_obj);
    typedef void (*PineObservedObjectCallback)(JNIEnv* env, uint64_t raw, jobject obj);
    void PineNative_SetObservedObjectCallback(PineObservedObjectCallback cb);
    void PineNative_NotifyObservedObject(JNIEnv* env, uint64_t raw, jobject obj);
}

#include <sstream>
#include <vector>
#include <deque>
#include <string>
#include <mutex>
#include <map>
#include <algorithm>
#include <unordered_map>
#include <unordered_set>
#include <cstring>
#include <memory>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

namespace artpi { namespace agent {

// ---------------------------------------------------------------------------
// Cached class references.
//
// The hook callback runs inside a raw trampoline with no valid ART managed
// stack frame; calling env->FindClass() there walks the managed stack
// (StackVisitor::WalkStack) and SIGSEGVs (same failure mode as
// CallFrame::getJavaStackTrace). So every class used on the hook path is
// resolved ONCE here (init time, valid stack) and cached as a global ref.
// ---------------------------------------------------------------------------
static jclass g_c_Class = nullptr;
static jclass g_c_Field = nullptr;
static jclass g_c_Number = nullptr;
static jclass g_c_Boolean = nullptr;
static jclass g_c_Integer = nullptr;
static jclass g_c_Long = nullptr;
static jclass g_c_Short = nullptr;
static jclass g_c_Byte = nullptr;
static jclass g_c_Character = nullptr;
static jclass g_c_Float = nullptr;
static jclass g_c_Double = nullptr;
static jclass g_c_Throwable = nullptr;
static jclass g_c_Log = nullptr;
static jclass g_c_Method = nullptr;
static jclass g_c_Object = nullptr;

static jclass CacheClassGlobal(JNIEnv* env, const char* name) {
    jclass l = env->FindClass(name);
    if (env->ExceptionCheck()) env->ExceptionClear();
    if (!l) return nullptr;
    jclass g = static_cast<jclass>(env->NewGlobalRef(l));
    env->DeleteLocalRef(l);
    return g;
}

void InitJRefClassCache(JNIEnv* env) {
    if (!env || g_c_Class) return;
    g_c_Class     = CacheClassGlobal(env, "java/lang/Class");
    g_c_Field     = CacheClassGlobal(env, "java/lang/reflect/Field");
    g_c_Number    = CacheClassGlobal(env, "java/lang/Number");
    g_c_Boolean   = CacheClassGlobal(env, "java/lang/Boolean");
    g_c_Integer   = CacheClassGlobal(env, "java/lang/Integer");
    g_c_Long      = CacheClassGlobal(env, "java/lang/Long");
    g_c_Short     = CacheClassGlobal(env, "java/lang/Short");
    g_c_Byte      = CacheClassGlobal(env, "java/lang/Byte");
    g_c_Character = CacheClassGlobal(env, "java/lang/Character");
    g_c_Float     = CacheClassGlobal(env, "java/lang/Float");
    g_c_Double    = CacheClassGlobal(env, "java/lang/Double");
    g_c_Throwable = CacheClassGlobal(env, "java/lang/Throwable");
    g_c_Log       = CacheClassGlobal(env, "android/util/Log");
    g_c_Method    = CacheClassGlobal(env, "java/lang/reflect/Method");
    g_c_Object    = CacheClassGlobal(env, "java/lang/Object");
}

static jclass CachedWrapperClass(const char* slashName);

jclass AgentCachedClass(const char* slashName) {
    if (!slashName) return nullptr;
    if (!std::strcmp(slashName, "java/lang/Class"))     return g_c_Class;
    if (!std::strcmp(slashName, "java/lang/reflect/Field")) return g_c_Field;
    if (!std::strcmp(slashName, "java/lang/Throwable")) return g_c_Throwable;
    if (!std::strcmp(slashName, "android/util/Log"))   return g_c_Log;
    if (!std::strcmp(slashName, "java/lang/reflect/Method")) return g_c_Method;
    if (!std::strcmp(slashName, "java/lang/Object"))   return g_c_Object;
    return CachedWrapperClass(slashName);
}

static jclass CachedWrapperClass(const char* slashName) {
    if (!std::strcmp(slashName, "java/lang/Boolean"))   return g_c_Boolean;
    if (!std::strcmp(slashName, "java/lang/Integer"))   return g_c_Integer;
    if (!std::strcmp(slashName, "java/lang/Long"))      return g_c_Long;
    if (!std::strcmp(slashName, "java/lang/Short"))     return g_c_Short;
    if (!std::strcmp(slashName, "java/lang/Byte"))      return g_c_Byte;
    if (!std::strcmp(slashName, "java/lang/Character")) return g_c_Character;
    if (!std::strcmp(slashName, "java/lang/Float"))     return g_c_Float;
    if (!std::strcmp(slashName, "java/lang/Double"))    return g_c_Double;
    if (!std::strcmp(slashName, "java/lang/Number"))    return g_c_Number;
    return nullptr;
}

size_t JavaUnhookAllCount();   // defined after the anonymous namespace

// Java/ART access flags -> "public static final ..." (common subset).
static std::string FormatModifiers(uint32_t f) {
    std::string s;
    auto add = [&](const char* w) { if (!s.empty()) s += ' '; s += w; };
    if (f & 0x0001) add("public");
    if (f & 0x0002) add("private");
    if (f & 0x0004) add("protected");
    if (f & 0x0008) add("static");
    if (f & 0x0010) add("final");
    if (f & 0x0020) add("synchronized");
    if (f & 0x0040) add("bridge");
    if (f & 0x0080) add("varargs");
    if (f & 0x0100) add("native");
    if (f & 0x0400) add("abstract");
    if (f & 0x1000) add("synthetic");
    return s;
}

namespace {

static std::vector<PI::HookHandle> g_activeHooks;
static std::mutex g_hooksMutex;

static std::mutex g_classRefMutex;
static std::unordered_map<std::string, jclass> g_classRefCache;

static jclass GetOrCreateGlobalClassRef(JNIEnv* env, const std::string& className, jclass localCls) {
    std::lock_guard<std::mutex> lk(g_classRefMutex);
    auto it = g_classRefCache.find(className);
    if (it != g_classRefCache.end()) {
        if (localCls) env->DeleteLocalRef(localCls);
        return it->second;
    }
    if (!localCls) return nullptr;
    jclass gCls = reinterpret_cast<jclass>(env->NewGlobalRef(localCls));
    env->DeleteLocalRef(localCls);
    g_classRefCache[className] = gCls;
    return gCls;
}

static void InspectClassMethods(JNIEnv* env, jclass targetCls, const std::string& pattern,
                                std::ostringstream& ss, int& count, int maxCount = 50) {
    if (!targetCls) return;
    jclass classCls = env->FindClass("java/lang/Class");
    if (env->ExceptionCheck()) { env->ExceptionClear(); return; }

    jmethodID getDeclaredMethods = classCls ? env->GetMethodID(classCls, "getDeclaredMethods", "()[Ljava/lang/reflect/Method;") : nullptr;
    if (env->ExceptionCheck()) env->ExceptionClear();
    if (!getDeclaredMethods) {
        if (classCls) env->DeleteLocalRef(classCls);
        return;
    }

    auto methodsObj = (jobjectArray)env->CallObjectMethod(targetCls, getDeclaredMethods);
    if (env->ExceptionCheck()) {
        env->ExceptionClear();
        if (classCls) env->DeleteLocalRef(classCls);
        return;
    }

    jclass methodCls = env->FindClass("java/lang/reflect/Method");
    if (env->ExceptionCheck()) { env->ExceptionClear(); methodCls = nullptr; }
    jmethodID methodToString = methodCls ? env->GetMethodID(methodCls, "toString", "()Ljava/lang/String;") : nullptr;
    if (env->ExceptionCheck()) env->ExceptionClear();
    jmethodID methodGetName = methodCls ? env->GetMethodID(methodCls, "getName", "()Ljava/lang/String;") : nullptr;
    if (env->ExceptionCheck()) env->ExceptionClear();

    if (methodsObj) {
        jsize len = env->GetArrayLength(methodsObj);
        for (jsize i = 0; i < len; i++) {
            if (count >= maxCount) break;
            jobject mObj = env->GetObjectArrayElement(methodsObj, i);
            if (!mObj) continue;

            std::string nameStr;
            if (methodGetName) {
                auto jName = (jstring)env->CallObjectMethod(mObj, methodGetName);
                if (env->ExceptionCheck()) env->ExceptionClear();
                if (jName) {
                    const char* utf = env->GetStringUTFChars(jName, nullptr);
                    if (utf) {
                        nameStr = utf;
                        env->ReleaseStringUTFChars(jName, utf);
                    }
                    env->DeleteLocalRef(jName);
                }
            }

            std::string desc = nameStr;
            if (methodToString) {
                auto jStr = (jstring)env->CallObjectMethod(mObj, methodToString);
                if (env->ExceptionCheck()) env->ExceptionClear();
                if (jStr) {
                    const char* utf = env->GetStringUTFChars(jStr, nullptr);
                    if (utf) {
                        desc = utf;
                        env->ReleaseStringUTFChars(jStr, utf);
                    }
                    env->DeleteLocalRef(jStr);
                }
            }

            bool match = pattern.empty() || pattern == "*" || MatchWildcard(nameStr, pattern) || MatchWildcard(desc, pattern);
            if (match) {
                PI::Method pm = PI::resolve(env, mObj);
                void* art = pm.isValid() ? pm.getArtMethod() : nullptr;
                char artBuf[32];
                snprintf(artBuf, sizeof(artBuf), "0x%llx", (unsigned long long)reinterpret_cast<uintptr_t>(art));

                char linePrefix[64];
                snprintf(linePrefix, sizeof(linePrefix), "[%2d] %-14s -> ", count++, artBuf);
                ss << "  " << linePrefix << desc << "\n";
            }
            env->DeleteLocalRef(mObj);
        }
        env->DeleteLocalRef(methodsObj);
    }

    if (classCls) env->DeleteLocalRef(classCls);
    if (methodCls) env->DeleteLocalRef(methodCls);
}

JSValue JsFindClass(JSContext* ctx, JSValueConst /*this_val*/, int argc, JSValueConst* argv) {
    if (argc < 1) return JS_NewString(ctx, "Usage: findClass(classNamePattern, [limit])  -- limit default 50 for wildcard lists");
    const char* name = JS_ToCString(ctx, argv[0]);
    if (!name) return JS_NULL;

    int limit = 50;
    if (argc >= 2) JS_ToInt32(ctx, &limit, argv[1]);
    if (limit <= 0) limit = 50;
    if (limit > 5000) limit = 5000;

    JNIEnv* env = GetEnv();
    if (!env) {
        JS_FreeCString(ctx, name);
        return JS_NULL;
    }

    std::string pattern(name);
    JS_FreeCString(ctx, name);

    // If pattern has wildcards (* or ?), perform pattern matching
    if (pattern.find('*') != std::string::npos || pattern.find('?') != std::string::npos) {
        std::vector<std::string> allNames = EnumerateAppClassNames(env);
        static const std::vector<std::string> kSysClasses = {
            "java.lang.String", "java.lang.StringBuilder", "java.lang.StringBuffer",
            "java.lang.Thread", "java.lang.Class", "java.lang.Object",
            "android.app.Activity", "android.app.Application", "android.content.Context",
            "android.os.Bundle", "android.widget.TextView", "android.view.View"
        };
        for (const auto& sc : kSysClasses) allNames.push_back(sc);

        std::vector<std::string> matches;
        for (const auto& cn : allNames) {
            if (MatchWildcard(cn, pattern)) {
                if (std::find(matches.begin(), matches.end(), cn) == matches.end()) {
                    matches.push_back(cn);
                }
            }
        }

        if (matches.empty()) {
            return JS_NewString(ctx, ("[!] No classes matched: " + pattern).c_str());
        }

        if (matches.size() == 1) {
            const std::string& cn = matches[0];
            jclass cls = FindClassWithFallback(env, cn);
            uintptr_t ptrVal = 0;
            if (cls) {
                jclass gCls = GetOrCreateGlobalClassRef(env, cn, cls);
                ptrVal = reinterpret_cast<uintptr_t>(gCls);
            }
            char ptrBuf[32];
            snprintf(ptrBuf, sizeof(ptrBuf), "0x%llx", (unsigned long long)ptrVal);
            std::string res = std::string(ptrBuf) + " -> " + cn;
            return JS_NewString(ctx, res.c_str());
        }

        std::ostringstream ss;
        size_t shown = std::min<size_t>(matches.size(), static_cast<size_t>(limit));
        ss << "Matched " << matches.size() << " class(es)";
        if (matches.size() > shown) ss << " (showing " << shown << ", +" << (matches.size() - shown) << " more; pass a larger limit)";
        ss << ":\n";
        for (size_t i = 0; i < shown; i++) {
            const std::string& cn = matches[i];
            jclass cls = FindClassWithFallback(env, cn);
            uintptr_t ptrVal = 0;
            if (cls) {
                jclass gCls = GetOrCreateGlobalClassRef(env, cn, cls);
                ptrVal = reinterpret_cast<uintptr_t>(gCls);
            }
            char ptrBuf[32];
            snprintf(ptrBuf, sizeof(ptrBuf), "0x%llx", (unsigned long long)ptrVal);
            ss << "  [" << i << "] " << ptrBuf << " -> " << cn << "\n";
        }
        return JS_NewString(ctx, ss.str().c_str());
    }

    jclass localCls = FindClassWithFallback(env, pattern);
    if (!localCls) {
        return JS_NULL;
    }

    jclass gCls = GetOrCreateGlobalClassRef(env, pattern, localCls);
    return JS_NewBigInt64(ctx, reinterpret_cast<int64_t>(gCls));
}

JSValue JsFindMethod(JSContext* ctx, JSValueConst /*this_val*/, int argc, JSValueConst* argv) {
    if (argc < 2) return JS_NewString(ctx, "Usage: findMethod(classOrName, methodName, [methodSig])");
    JNIEnv* env = GetEnv();
    if (!env) return JS_NULL;

    jclass targetCls = nullptr;
    bool needDeleteCls = false;
    std::string methodName;
    std::string methodSig;

    int64_t parsedClsPtr = ParsePtr(ctx, argv[0]);
    if (parsedClsPtr != 0) {
        targetCls = reinterpret_cast<jclass>(parsedClsPtr);
    } else if (JS_IsString(argv[0])) {
        const char* clzStr = JS_ToCString(ctx, argv[0]);
        if (clzStr) {
            std::string cname(clzStr);
            JS_FreeCString(ctx, clzStr);
            targetCls = FindClassWithFallback(env, cname);
            needDeleteCls = true;
        }
    }

    if (!targetCls) return JS_NULL;

    const char* mName = JS_ToCString(ctx, argv[1]);
    if (mName) {
        methodName = mName;
        JS_FreeCString(ctx, mName);
    }

    if (argc >= 3 && JS_IsString(argv[2])) {
        const char* mSig = JS_ToCString(ctx, argv[2]);
        if (mSig) {
            methodSig = mSig;
            JS_FreeCString(ctx, mSig);
        }
    }

    PI::Method m;
    if (!methodSig.empty()) {
        m = PI::resolve(env, targetCls, methodName, methodSig);
    } else {
        // Find method by name via reflection (traversing superclasses when omitted)
        jclass classCls = env->FindClass("java/lang/Class");
        if (env->ExceptionCheck()) env->ExceptionClear();
        jmethodID getDeclaredMethods = classCls ? env->GetMethodID(classCls, "getDeclaredMethods", "()[Ljava/lang/reflect/Method;") : nullptr;
        jmethodID getSuperclass = classCls ? env->GetMethodID(classCls, "getSuperclass", "()Ljava/lang/Class;") : nullptr;
        if (env->ExceptionCheck()) env->ExceptionClear();
        jclass methodCls = env->FindClass("java/lang/reflect/Method");
        if (env->ExceptionCheck()) env->ExceptionClear();
        jmethodID methodGetName = methodCls ? env->GetMethodID(methodCls, "getName", "()Ljava/lang/String;") : nullptr;
        if (env->ExceptionCheck()) env->ExceptionClear();

        if (classCls && getDeclaredMethods && methodCls && methodGetName) {
            jclass curCls = targetCls;
            bool isCurrentClsAllocated = false;
            while (curCls && !m.isValid()) {
                auto methodsObj = (jobjectArray)env->CallObjectMethod(curCls, getDeclaredMethods);
                if (env->ExceptionCheck()) env->ExceptionClear();
                if (methodsObj) {
                    jsize len = env->GetArrayLength(methodsObj);
                    for (jsize i = 0; i < len; i++) {
                        jobject mObj = env->GetObjectArrayElement(methodsObj, i);
                        if (!mObj) continue;
                        auto jName = (jstring)env->CallObjectMethod(mObj, methodGetName);
                        if (env->ExceptionCheck()) env->ExceptionClear();
                        if (jName) {
                            const char* utf = env->GetStringUTFChars(jName, nullptr);
                            bool match = (utf && methodName == utf);
                            if (utf) env->ReleaseStringUTFChars(jName, utf);
                            env->DeleteLocalRef(jName);
                            if (match) {
                                m = PI::resolve(env, mObj);
                                env->DeleteLocalRef(mObj);
                                break;
                            }
                        }
                        env->DeleteLocalRef(mObj);
                    }
                    env->DeleteLocalRef(methodsObj);
                }
                if (m.isValid()) break;
                if (!getSuperclass) break;
                jclass nextCls = (jclass)env->CallObjectMethod(curCls, getSuperclass);
                if (env->ExceptionCheck()) { env->ExceptionClear(); break; }
                if (isCurrentClsAllocated) env->DeleteLocalRef(curCls);
                curCls = nextCls;
                isCurrentClsAllocated = true;
            }
            if (isCurrentClsAllocated && curCls) env->DeleteLocalRef(curCls);
        }
        if (methodCls) env->DeleteLocalRef(methodCls);
        if (classCls) env->DeleteLocalRef(classCls);
    }

    if (needDeleteCls) {
        env->DeleteLocalRef(targetCls);
    }

    if (!m.isValid()) return JS_NULL;

    // Return the TRUE ArtMethod* pointer in memory
    return JS_NewBigInt64(ctx, reinterpret_cast<int64_t>(m.getArtMethod()));
}

JSValue JsListMethods(JSContext* ctx, JSValueConst /*this_val*/, int argc, JSValueConst* argv) {
    if (argc < 1) return JS_NewString(ctx, "Usage: listMethods(classOrName)");
    JNIEnv* env = GetEnv();
    if (!env) return JS_NULL;

    jclass targetCls = nullptr;
    bool needDelete = false;

    int64_t clsPtr = ParsePtr(ctx, argv[0]);
    if (clsPtr != 0) {
        targetCls = reinterpret_cast<jclass>(clsPtr);
    } else if (JS_IsString(argv[0])) {
        const char* clzStr = JS_ToCString(ctx, argv[0]);
        if (clzStr) {
            std::string cname(clzStr);
            JS_FreeCString(ctx, clzStr);
            targetCls = FindClassWithFallback(env, cname);
            needDelete = true;
        }
    }

    if (!targetCls) {
        return JS_NewString(ctx, "[!] Class not found");
    }

    std::ostringstream ss;
    int count = 0;
    InspectClassMethods(env, targetCls, "", ss, count, 200);

    if (needDelete) env->DeleteLocalRef(targetCls);

    if (count == 0) {
        return JS_NewString(ctx, "[*] No declared methods found.");
    }
    return JS_NewString(ctx, ss.str().c_str());
}

JSValue JsFindMethods(JSContext* ctx, JSValueConst /*this_val*/, int argc, JSValueConst* argv) {
    if (argc < 1) return JS_NewString(ctx, "Usage: findMethods(classOrPattern[, methodPattern])  (methodPattern defaults to \"\")\nExamples:\n  findMethods(\"com.android.boot.MainActivity\")            // all methods of the class\n  findMethods(\"com.android.boot.MainActivity\", \"*Weather*\")\n  findMethods(\"*boot*\")                                     // wildcard: search methods across classes");
    JNIEnv* env = GetEnv();
    if (!env) return JS_NULL;

    std::ostringstream ss;
    int count = 0;

    if (argc == 1) {
        // 1) Pointer form: findMethods(clsPtr) -> all declared methods of the class.
        int64_t clsPtr = ParsePtr(ctx, argv[0]);
        if (clsPtr != 0) {
            InspectClassMethods(env, reinterpret_cast<jclass>(clsPtr), "", ss, count, 100);
            if (count == 0) return JS_NewString(ctx, "[*] No declared methods found.");
            return JS_NewString(ctx, ss.str().c_str());
        }

        if (!JS_IsString(argv[0])) {
            return JS_NewString(ctx, "Usage: findMethods(classOrPattern[, methodPattern])");
        }

        const char* pStr = JS_ToCString(ctx, argv[0]);
        if (!pStr) return JS_NULL;
        std::string arg0(pStr);
        JS_FreeCString(ctx, pStr);

        // 2) Class-name form: the second argument defaults to "" so that
        //    findMethods("com.foo.Bar") == findMethods("com.foo.Bar", "").
        //    FindClassWithFallback() returns nullptr for wildcard specs, which
        //    cleanly distinguishes an exact class name from a method pattern.
        jclass exactCls = FindClassWithFallback(env, arg0);
        if (exactCls) {
            InspectClassMethods(env, exactCls, "", ss, count, 100);
            env->DeleteLocalRef(exactCls);
            if (count == 0) return JS_NewString(ctx, "[*] No declared methods found.");
            return JS_NewString(ctx, ss.str().c_str());
        }

        // 3) Fallback: treat the single argument as a method pattern searched across all classes.
        std::vector<std::string> classNames = EnumerateAppClassNames(env);
        for (const auto& cn : classNames) {
            if (count >= 50) break;
            jclass cls = FindClassWithFallback(env, cn);
            if (cls) {
                InspectClassMethods(env, cls, arg0, ss, count, 50);
                env->DeleteLocalRef(cls);
            }
        }
        if (count == 0) {
            return JS_NewString(ctx, ("[!] No methods found matching: " + arg0).c_str());
        }
        return JS_NewString(ctx, ss.str().c_str());
    }

    const char* mPatStr = JS_ToCString(ctx, argv[1]);
    std::string methodPattern = mPatStr ? mPatStr : "";
    if (mPatStr) JS_FreeCString(ctx, mPatStr);

    int64_t clsPtr = ParsePtr(ctx, argv[0]);
    if (clsPtr != 0) {
        InspectClassMethods(env, reinterpret_cast<jclass>(clsPtr), methodPattern, ss, count, 100);
        if (count == 0) return JS_NewString(ctx, "[*] No matching methods found.");
        return JS_NewString(ctx, ss.str().c_str());
    }

    if (JS_IsString(argv[0])) {
        const char* clzStr = JS_ToCString(ctx, argv[0]);
        if (!clzStr) return JS_NULL;
        std::string classSpec(clzStr);
        JS_FreeCString(ctx, clzStr);

        if (classSpec.find('*') != std::string::npos || classSpec.find('?') != std::string::npos) {
            std::vector<std::string> allNames = EnumerateAppClassNames(env);
            for (const auto& cn : allNames) {
                if (count >= 50) break;
                if (MatchWildcard(cn, classSpec)) {
                    jclass cls = FindClassWithFallback(env, cn);
                    if (cls) {
                        InspectClassMethods(env, cls, methodPattern, ss, count, 50);
                        env->DeleteLocalRef(cls);
                    }
                }
            }
        } else {
            jclass cls = FindClassWithFallback(env, classSpec);
            if (cls) {
                InspectClassMethods(env, cls, methodPattern, ss, count, 100);
                env->DeleteLocalRef(cls);
            } else {
                return JS_NewString(ctx, ("[!] Class not found: " + classSpec).c_str());
            }
        }
    }

    if (count == 0) {
        return JS_NewString(ctx, "[*] No matching methods found.");
    }
    return JS_NewString(ctx, ss.str().c_str());
}

JSValue JsMethodToArt(JSContext* ctx, JSValueConst /*this_val*/, int argc, JSValueConst* argv) {
    if (argc < 1) return JS_NewString(ctx, "Usage: methodToArt(artMethodPtr)");
    int64_t mid = ParsePtr(ctx, argv[0]);
    if (!mid || mid < 0x10000) {
        return JS_NewString(ctx, "[!] Invalid ArtMethod pointer (null or address below 0x10000)");
    }

    ArtMethod* art = reinterpret_cast<ArtMethod*>(mid);
    return JS_NewBigInt64(ctx, reinterpret_cast<int64_t>(art));
}

JSValue JsArtToMethod(JSContext* ctx, JSValueConst /*this_val*/, int argc, JSValueConst* argv) {
    if (argc < 1) return JS_NewString(ctx, "Usage: artToMethod(artMethodPtr)");
    int64_t ptr = ParsePtr(ctx, argv[0]);
    if (!ptr || ptr < 0x1000) return JS_NULL;
    return JS_NewBigInt64(ctx, ptr);
}

// methodInfo(artMethodPtr) -> structured descriptor:
//   { artMethod, name, signature, className, isStatic, isNative, isCompiled,
//     nativeEntry }
// `nativeEntry` is the resolved JNI function pointer for native methods (null
// otherwise), i.e. what `.address` / `.ptr` mean on a dynamic method box.
JSValue JsMethodInfo(JSContext* ctx, JSValueConst /*this_val*/, int argc, JSValueConst* argv) {
    if (argc < 1) return JS_NewString(ctx, "Usage: methodInfo(artMethodPtr)");
    int64_t ptr = ParsePtr(ctx, argv[0]);
    if (!ptr || ptr < 0x1000) return JS_NULL;

    PI::Method m = PI::resolve(reinterpret_cast<ArtMethod*>(ptr));
    if (!m.isValid()) return JS_NULL;

    bool isNative = m.isNative();
    JSValue o = JS_NewObject(ctx);
    JS_SetPropertyStr(ctx, o, "artMethod", JS_NewBigInt64(ctx, ptr));
    JS_SetPropertyStr(ctx, o, "name", JS_NewString(ctx, m.getName().c_str()));
    JS_SetPropertyStr(ctx, o, "signature", JS_NewString(ctx, m.getSignature().c_str()));
    JS_SetPropertyStr(ctx, o, "className", JS_NewString(ctx, m.getDeclaringClassName().c_str()));
    JS_SetPropertyStr(ctx, o, "isStatic", JS_NewBool(ctx, m.isStatic()));
    JS_SetPropertyStr(ctx, o, "isNative", JS_NewBool(ctx, isNative));
    JS_SetPropertyStr(ctx, o, "isCompiled", JS_NewBool(ctx, m.isCompiled()));
    JS_SetPropertyStr(ctx, o, "modifiers", JS_NewString(ctx, FormatModifiers(m.getAccessFlags()).c_str()));

    void* nativeEntry = isNative ? PI::resolveNativeMethod(m.getArtMethod(), GetEnv()) : nullptr;
    JS_SetPropertyStr(ctx, o, "nativeEntry",
                      nativeEntry ? JS_NewBigInt64(ctx, static_cast<int64_t>(reinterpret_cast<uintptr_t>(nativeEntry)))
                                  : JS_NULL);
    return o;
}

JSValue JsEnumerateClassLoaders(JSContext* ctx, JSValueConst /*this_val*/, int /*argc*/, JSValueConst* /*argv*/) {
    JNIEnv* env = GetEnv();
    if (!env) return JS_NULL;
    jobject appCl = GetAppClassLoader(env);
    if (!appCl) return JS_NULL;

    jclass clClass = env->FindClass("java/lang/ClassLoader");
    if (env->ExceptionCheck()) { env->ExceptionClear(); return JS_NULL; }
    jmethodID getParentMid = env->GetMethodID(clClass, "getParent", "()Ljava/lang/ClassLoader;");
    jmethodID toStringMid = env->GetMethodID(clClass, "toString", "()Ljava/lang/String;");
    if (env->ExceptionCheck()) env->ExceptionClear();

    std::ostringstream ss;
    ss << "[ClassLoaders in current process]\n";

    jobject cur = env->NewLocalRef(appCl);
    int idx = 0;
    while (cur) {
        std::string desc = "ClassLoader";
        if (toStringMid) {
            jstring jstr = reinterpret_cast<jstring>(env->CallObjectMethod(cur, toStringMid));
            if (env->ExceptionCheck()) env->ExceptionClear();
            if (jstr) {
                const char* chars = env->GetStringUTFChars(jstr, nullptr);
                if (chars) { desc = chars; env->ReleaseStringUTFChars(jstr, chars); }
                env->DeleteLocalRef(jstr);
            }
        }
        char buf[64];
        snprintf(buf, sizeof(buf), "  [%d] ", idx++);
        ss << buf << desc << "\n";

        if (!getParentMid) break;
        jobject parent = env->CallObjectMethod(cur, getParentMid);
        if (env->ExceptionCheck()) { env->ExceptionClear(); parent = nullptr; }
        env->DeleteLocalRef(cur);
        cur = parent;
    }

    env->DeleteLocalRef(clClass);
    return JS_NewString(ctx, ss.str().c_str());
}

JSValue JsDumpSmali(JSContext* ctx, JSValueConst /*this_val*/, int argc, JSValueConst* argv) {
    if (argc < 1) return JS_NewString(ctx, "Usage: dumpSmali(artMethodPtrOrClass, [maxInstructions])");
    int maxInsn = -1;
    if (argc >= 2) JS_ToInt32(ctx, &maxInsn, argv[1]);

    JNIEnv* env = GetEnv();

    // 1. If string argument: class name
    if (JS_IsString(argv[0])) {
        const char* s = JS_ToCString(ctx, argv[0]);
        if (s) {
            std::string name = s;
            JS_FreeCString(ctx, s);
            if (env) {
                jclass cls = FindClassWithFallback(env, name);
                if (cls) {
                    jclass classCls = env->FindClass("java/lang/Class");
                    if (env->ExceptionCheck()) env->ExceptionClear();
                    jmethodID getDeclaredMethods = classCls ? env->GetMethodID(classCls, "getDeclaredMethods", "()[Ljava/lang/reflect/Method;") : nullptr;
                    if (classCls && getDeclaredMethods) {
                        auto mArr = (jobjectArray)env->CallObjectMethod(cls, getDeclaredMethods);
                        if (env->ExceptionCheck()) env->ExceptionClear();
                        if (mArr) {
                            jsize len = env->GetArrayLength(mArr);
                            std::ostringstream ss;
                            ss << "=== DumpSmali for " << name << " (" << len << " methods) ===\n\n";
                            for (jsize i = 0; i < len; ++i) {
                                jobject mObj = env->GetObjectArrayElement(mArr, i);
                                if (mObj) {
                                    PI::Method pm = PI::resolve(env, mObj);
                                    if (pm.isValid()) {
                                        ss << pm.dumpSmali(maxInsn) << "\n";
                                    }
                                    env->DeleteLocalRef(mObj);
                                }
                            }
                            env->DeleteLocalRef(mArr);
                            env->DeleteLocalRef(classCls);
                            env->DeleteLocalRef(cls);
                            return JS_NewString(ctx, ss.str().c_str());
                        }
                    }
                    if (classCls) env->DeleteLocalRef(classCls);
                    env->DeleteLocalRef(cls);
                }
            }
        }
    }

    int64_t ptr = ParsePtr(ctx, argv[0]);
    if (!ptr || ptr < 0x1000) {
        return JS_NewString(ctx, "[!] Invalid pointer (address is null or below 0x1000)");
    }

    // 2. Check if ptr is a jclass reference
    if (env && ptr > 0x1000) {
        jobject testObj = reinterpret_cast<jobject>(ptr);
        if (g_c_Class && env->IsInstanceOf(testObj, g_c_Class)) {
            jclass cls = reinterpret_cast<jclass>(testObj);
            jmethodID getDeclaredMethods = env->GetMethodID(g_c_Class, "getDeclaredMethods", "()[Ljava/lang/reflect/Method;");
            if (env->ExceptionCheck()) env->ExceptionClear();
            if (getDeclaredMethods) {
                auto mArr = (jobjectArray)env->CallObjectMethod(cls, getDeclaredMethods);
                if (env->ExceptionCheck()) env->ExceptionClear();
                if (mArr) {
                    jsize len = env->GetArrayLength(mArr);
                    std::ostringstream ss;
                    ss << "=== DumpSmali for Class (" << len << " methods) ===\n\n";
                    for (jsize i = 0; i < len; ++i) {
                        jobject mObj = env->GetObjectArrayElement(mArr, i);
                        if (mObj) {
                            PI::Method pm = PI::resolve(env, mObj);
                            if (pm.isValid()) {
                                ss << pm.dumpSmali(maxInsn) << "\n";
                            }
                            env->DeleteLocalRef(mObj);
                        }
                    }
                    env->DeleteLocalRef(mArr);
                    return JS_NewString(ctx, ss.str().c_str());
                }
            }
        }
    }

    // 3. Otherwise treat as ArtMethod*
    PI::Method m = PI::resolve(reinterpret_cast<ArtMethod*>(ptr));
    if (!m.isValid()) {
        return JS_NewString(ctx, "[!] Cannot resolve ArtMethod at given address");
    }

    std::string smali = m.dumpSmali(maxInsn);
    return JS_NewString(ctx, smali.c_str());
}

JSValue JsDumpCode(JSContext* ctx, JSValueConst /*this_val*/, int argc, JSValueConst* argv) {
    if (argc < 1) return JS_NewString(ctx, "Usage: dumpCode(artMethodPtrOrNativeAddr, [maxInstructions])");
    int64_t ptr = ParsePtr(ctx, argv[0]);
    if (!ptr || ptr < 0x1000) {
        return JS_NewString(ctx, "[!] Invalid pointer (address is null or below 0x1000)");
    }

    int maxInsn = -1;
    if (argc >= 2) JS_ToInt32(ctx, &maxInsn, argv[1]);

    // 1. If ptr is inside an ELF module (.so), it's definitely a raw native code pointer
    xdl_info_t info;
    void* cache = nullptr;
    if (xdl_addr(reinterpret_cast<void*>(ptr), &info, &cache) != 0) {
        xdl_addr_clean(&cache);
        std::string code = PI::dumpNative(reinterpret_cast<const void*>(ptr), maxInsn);
        return JS_NewString(ctx, code.c_str());
    }
    xdl_addr_clean(&cache);

    // 2. Otherwise treat as ArtMethod
    ArtMethod* art = reinterpret_cast<ArtMethod*>(ptr);
    PI::Method m = PI::resolve(art);
    if (m.isValid()) {
        std::string code = PI::dumpCode(art, maxInsn);
        return JS_NewString(ctx, code.c_str());
    }

    std::string code = PI::dumpNative(reinterpret_cast<const void*>(ptr), maxInsn);
    return JS_NewString(ctx, code.c_str());
}

static bool DumpDexFromArtMethod(ArtMethod* art, std::string& outDexPath) {
    if (!art) return false;
    uint32_t klass_ref = art->GetDeclaringClass();
    if (!klass_ref) return false;
    void* klass = reinterpret_cast<void*>(static_cast<uintptr_t>(klass_ref));

    uint32_t dex_cache_ref = *reinterpret_cast<uint32_t*>(static_cast<uint8_t*>(klass) + 0x10);
    if (!dex_cache_ref) return false;
    void* dex_cache = reinterpret_cast<void*>(static_cast<uintptr_t>(dex_cache_ref));

    const void* dex_file = *reinterpret_cast<const void* const*>(static_cast<const uint8_t*>(dex_cache) + 0x10);
    if (!dex_file) return false;

    const uint8_t* dex_begin = *reinterpret_cast<const uint8_t* const*>(static_cast<const uint8_t*>(dex_file) + 0x08);
    size_t dex_size = *reinterpret_cast<const size_t*>(static_cast<const uint8_t*>(dex_file) + 0x10);
    const uint8_t* dex_data_begin = *reinterpret_cast<const uint8_t* const*>(static_cast<const uint8_t*>(dex_file) + 0x18);
    if (!dex_data_begin) dex_data_begin = dex_begin;
    if (!dex_data_begin) return false;

    if (dex_size == 0 || dex_size > 0x10000000) {
        if (std::memcmp(dex_data_begin, "dex\n", 4) == 0 || std::memcmp(dex_data_begin, "cdex", 4) == 0) {
            dex_size = *reinterpret_cast<const uint32_t*>(dex_data_begin + 0x20);
        }
    }
    if (dex_size == 0 || dex_size > 0x10000000) return false;

    uint32_t checksum = 0;
    if (dex_size >= 16) {
        checksum = *reinterpret_cast<const uint32_t*>(dex_data_begin + 8);
    }

    mkdir("/data/local/tmp/jtmp", 0777);
    chmod("/data/local/tmp/jtmp", 0777);

    char buf[128];
    snprintf(buf, sizeof(buf), "/data/local/tmp/jtmp/dex_%zx_%08x.dex", dex_size, checksum);
    outDexPath = buf;

    struct stat st;
    if (stat(outDexPath.c_str(), &st) == 0 && (size_t)st.st_size == dex_size) {
        return true;
    }

    int fd = open(outDexPath.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0666);
    if (fd < 0) return false;
    size_t written = 0;
    while (written < dex_size) {
        ssize_t w = write(fd, dex_data_begin + written, dex_size - written);
        if (w <= 0) { close(fd); return false; }
        written += w;
    }
    close(fd);
    chmod(outDexPath.c_str(), 0666);
    return true;
}

static std::string DecompileSingleClass(const std::string& className, const std::string& dexPath, const std::string& methodName) {
    mkdir("/data/local/tmp/dalvik-cache", 0777);
    chmod("/data/local/tmp/dalvik-cache", 0777);
    mkdir("/data/local/tmp/jtmp", 0777);
    chmod("/data/local/tmp/jtmp", 0777);
    mkdir("/data/local/tmp/jout", 0777);
    chmod("/data/local/tmp/jout", 0777);
    chmod("/data/local/tmp/jadxcli.jar", 0666);
    chmod(dexPath.c_str(), 0666);

    std::string relPath = className;
    for (char& c : relPath) { if (c == '.') c = '/'; }
    std::string targetJava1 = "/data/local/tmp/jout/" + relPath + ".java";
    std::string targetJava2 = "/data/local/tmp/jout/sources/" + relPath + ".java";
    std::string targetJava3 = "/data/local/tmp/jout/decompiled.java";
    unlink(targetJava1.c_str());
    unlink(targetJava2.c_str());
    unlink(targetJava3.c_str());

    std::string cmd = "export ANDROID_DATA=/data/local/tmp; dalvikvm -Xmx256m -Djava.io.tmpdir=/data/local/tmp/jtmp -cp /data/local/tmp/jadxcli.jar jadx.cli.JadxCLI --no-res -ds /data/local/tmp/jout --single-class " + className + " --single-class-output " + targetJava3 + " " + dexPath + " >/dev/null 2>&1";
    int ret = system(cmd.c_str());
    (void)ret;

    FILE* fp = fopen(targetJava3.c_str(), "rb");
    if (!fp) fp = fopen(targetJava1.c_str(), "rb");
    if (!fp) fp = fopen(targetJava2.c_str(), "rb");
    if (!fp) {
        // Return empty so caller falls back gracefully
        return "";
    }
    fseek(fp, 0, SEEK_END);
    long sz = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    std::string javaCode(sz, '\0');
    fread(&javaCode[0], 1, sz, fp);
    fclose(fp);

    if (methodName.empty()) {
        return javaCode;
    }

    std::string needle = methodName + "(";
    size_t pos = javaCode.find(needle);
    if (pos == std::string::npos) {
        return "// [Note: Method '" + methodName + "' not found directly (may be inlined/synthetic/obfuscated). Full class source:]\n\n" + javaCode;
    }

    size_t lineStart = javaCode.rfind('\n', pos);
    lineStart = (lineStart == std::string::npos) ? 0 : lineStart + 1;

    // Scan backwards for preceding annotations and comments
    size_t scanPos = lineStart;
    while (scanPos > 0) {
        size_t prevLineEnd = scanPos - 1;
        size_t prevLineStart = javaCode.rfind('\n', prevLineEnd > 0 ? prevLineEnd - 1 : 0);
        prevLineStart = (prevLineStart == std::string::npos) ? 0 : prevLineStart + 1;
        std::string prevLine = javaCode.substr(prevLineStart, prevLineEnd - prevLineStart);
        size_t nonWs = prevLine.find_first_not_of(" \t\r\n");
        if (nonWs != std::string::npos) {
            std::string trimmed = prevLine.substr(nonWs);
            if (trimmed.rfind("@", 0) == 0 || trimmed.rfind("/*", 0) == 0 || trimmed.rfind("//", 0) == 0 || trimmed.rfind("*", 0) == 0) {
                scanPos = prevLineStart;
                lineStart = prevLineStart;
                continue;
            }
        }
        break;
    }

    // Check for native or abstract method (which ends with ';' and has NO '{')
    size_t semiColon = javaCode.find(';', pos);
    size_t braceOpen = javaCode.find('{', pos);
    if (semiColon != std::string::npos && (braceOpen == std::string::npos || semiColon < braceOpen)) {
        std::string methodCode = javaCode.substr(lineStart, semiColon - lineStart + 1);
        return "// Decompiled " + className + "." + methodName + " via JADX:\n" + methodCode;
    }

    if (braceOpen == std::string::npos) {
        return javaCode;
    }

    int braceCount = 1;
    size_t i = braceOpen + 1;
    for (; i < javaCode.size(); i++) {
        if (javaCode[i] == '{') braceCount++;
        else if (javaCode[i] == '}') {
            braceCount--;
            if (braceCount == 0) break;
        }
    }

    if (braceCount == 0 && i < javaCode.size()) {
        std::string methodCode = javaCode.substr(lineStart, i - lineStart + 1);
        return "// Decompiled " + className + "." + methodName + " via JADX:\n" + methodCode;
    }

    return javaCode;
}

JSValue JsDecompile(JSContext* ctx, JSValueConst /*this_val*/, int argc, JSValueConst* argv) {
    if (argc < 1) return JS_NewString(ctx, "Usage: decompile(classOrMethodNameOrArtMethod, [methodName])");
    JNIEnv* env = GetEnv();
    if (!env) return JS_NULL;

    std::string className;
    std::string methodName;
    ArtMethod* targetArt = nullptr;

    int64_t ptr = ParsePtr(ctx, argv[0]);
    if (ptr > 0x1000) {
        targetArt = reinterpret_cast<ArtMethod*>(ptr);
        PI::Method m = PI::resolve(targetArt);
        if (m.isValid()) {
            className = m.getDeclaringClassName();
            methodName = m.getName();
        }
    } else if (JS_IsString(argv[0])) {
        const char* s = JS_ToCString(ctx, argv[0]);
        if (s) {
            className = s;
            JS_FreeCString(ctx, s);
        }
    }

    if (argc >= 2 && JS_IsString(argv[1])) {
        const char* s = JS_ToCString(ctx, argv[1]);
        if (s) {
            methodName = s;
            JS_FreeCString(ctx, s);
        }
    }

    if (!targetArt && !className.empty()) {
        jclass cls = FindClassWithFallback(env, className);
        if (cls) {
            if (!methodName.empty()) {
                JSValue mVal = JsFindMethod(ctx, JS_UNDEFINED, 2, argv);
                int64_t mPtr = ParsePtr(ctx, mVal);
                JS_FreeValue(ctx, mVal);
                if (mPtr > 0x1000) targetArt = reinterpret_cast<ArtMethod*>(mPtr);
            }
            if (!targetArt) {
                jclass classCls = env->FindClass("java/lang/Class");
                if (env->ExceptionCheck()) env->ExceptionClear();
                jmethodID getDeclaredMethods = classCls ? env->GetMethodID(classCls, "getDeclaredMethods", "()[Ljava/lang/reflect/Method;") : nullptr;
                if (classCls && getDeclaredMethods) {
                    auto mArr = (jobjectArray)env->CallObjectMethod(cls, getDeclaredMethods);
                    if (env->ExceptionCheck()) env->ExceptionClear();
                    if (mArr && env->GetArrayLength(mArr) > 0) {
                        jobject mObj = env->GetObjectArrayElement(mArr, 0);
                        if (mObj) {
                            PI::Method pm = PI::resolve(env, mObj);
                            if (pm.isValid()) targetArt = pm.getArtMethod();
                            env->DeleteLocalRef(mObj);
                        }
                        env->DeleteLocalRef(mArr);
                    }
                    env->DeleteLocalRef(classCls);
                }
            }
            env->DeleteLocalRef(cls);
        }
    }

    if (!targetArt) {
        return JS_NewString(ctx, ("[!] Unable to resolve class or method: " + className).c_str());
    }

    bool jadxOk = (access("/data/local/tmp/jadxcli.jar", R_OK) == 0);
    std::string dexPath;
    if (jadxOk && DumpDexFromArtMethod(targetArt, dexPath)) {
        std::string res = DecompileSingleClass(className, dexPath, methodName);
        if (!res.empty()) {
            return JS_NewString(ctx, res.c_str());
        }
    }

    // Fallback: JADX not available or failed; provide full Class/Method disassembly
    if (!methodName.empty()) {
        PI::Method m = PI::resolve(targetArt);
        std::string smali = m.dumpSmali(-1);
        return JS_NewString(ctx, ("[*] JADX decompile unavailable; fallback to Smali disassembly:\n\n" + smali).c_str());
    }

    // Class-level fallback: reconstruct class structure with declarations and Smali
    std::ostringstream ss;
    ss << "// [*] JADX decompile unavailable; fallback to Smali/Class disassembly:\n";
    ss << "// Class: " << className << "\n\n";

    jclass cls = FindClassWithFallback(env, className);
    if (cls) {
        jclass classCls = env->FindClass("java/lang/Class");
        if (env->ExceptionCheck()) env->ExceptionClear();
        jmethodID getDeclaredMethods = classCls ? env->GetMethodID(classCls, "getDeclaredMethods", "()[Ljava/lang/reflect/Method;") : nullptr;
        if (classCls && getDeclaredMethods) {
            auto mArr = (jobjectArray)env->CallObjectMethod(cls, getDeclaredMethods);
            if (env->ExceptionCheck()) env->ExceptionClear();
            if (mArr) {
                jsize len = env->GetArrayLength(mArr);
                for (jsize i = 0; i < len; ++i) {
                    jobject mObj = env->GetObjectArrayElement(mArr, i);
                    if (mObj) {
                        PI::Method pm = PI::resolve(env, mObj);
                        if (pm.isValid()) {
                            ss << pm.dumpSmali(-1) << "\n";
                        }
                        env->DeleteLocalRef(mObj);
                    }
                }
                env->DeleteLocalRef(mArr);
            }
            env->DeleteLocalRef(classCls);
        }
        env->DeleteLocalRef(cls);
    }
    return JS_NewString(ctx, ss.str().c_str());
}

// ---------------------------------------------------------------------------
// Hook callback bridge: expose frame args + setResult to the JS callback.
// ---------------------------------------------------------------------------

// Forward decls (JRef defined below)
static JSValue CreateJRefValue(JSContext* ctx, int handle);
static JSValue JavaObjectToJsValue(JSContext* ctx, JNIEnv* env, jobject obj);

// Scratch slot for the JS->C++ return-value hand-off, alive for one callback.
struct JsHookRet {
    bool set = false;
    JSValue val = JS_UNDEFINED;
};

static JSValue JsHookSetResultFn(JSContext* ctx, JSValueConst, int argc, JSValueConst* argv,
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

// Expose frame arg i to JS (primitive / String; other objects -> null).
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
            // Non-String object: expose as a JRef field proxy (obj.field / obj.field = v)
            return JavaObjectToJsValue(ctx, GetEnv(), f.getArg(i));
        default: return JS_NewInt32(ctx, static_cast<int32_t>(raw));
    }
}

// Write a (possibly modified) JS value back into frame arg i.
// Only primitives and String are written; opaque objects are left untouched.
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
            return false;   // opaque object: don't clobber
        }
        default: return false;
    }
}

// Apply a JS-provided value as the hooked method's return value.
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

// ---------------------------------------------------------------------------
// JRef method invocation & array element access
// ---------------------------------------------------------------------------
static jobject GetJRef(int handle);
static std::string JavaClassName(JNIEnv* env, jclass cls);
static jobject JsValueToJavaObject(JNIEnv* env, JSContext* ctx, JSValueConst v, const std::string& tn);

// ===========================================================================
// Member cache: resolve fields/methods to jfieldID/jmethodID at eval time
// (where Java reflection is safe) so the hook path never calls reflection
// (Class.getDeclaredMethods/Fields walks the managed stack -> SIGSEGV).
// ===========================================================================
struct CachedField {
    jfieldID id = nullptr;
    char type = 'L';
    std::string typeName;
    bool isStatic = false;
};
struct CachedMethod {
    jmethodID id = nullptr;
    std::vector<std::string> params;   // type names
    std::string ret;                   // return type name
    bool isStatic = false;
};
struct ClassMembers {
    std::string name;
    std::map<std::string, CachedField> fields;
    std::map<std::string, std::vector<CachedMethod>> methods;
};
static std::map<std::string, ClassMembers> g_memberCache;
static std::mutex g_memberMutex;

static std::string TypeNameToDescriptor(const std::string& tn) {
    if (tn.empty()) return "Ljava/lang/Object;";
    if (tn[0] == '[') {                       // JVM array form e.g. [I / [Ljava.lang.String;
        std::string d = tn;
        for (char& c : d) if (c == '.') c = '/';
        return d;
    }
    if (tn.size() > 2 && tn.compare(tn.size() - 2, 2, "[]") == 0) {
        return "[" + TypeNameToDescriptor(tn.substr(0, tn.size() - 2));
    }
    if (tn == "int") return "I";
    if (tn == "long") return "J";
    if (tn == "boolean") return "Z";
    if (tn == "byte") return "B";
    if (tn == "char") return "C";
    if (tn == "short") return "S";
    if (tn == "float") return "F";
    if (tn == "double") return "D";
    if (tn == "void") return "V";
    std::string d = "L" + tn + ";";
    for (char& c : d) if (c == '.') c = '/';
    return d;
}

// Enumerate a class's members (and superclasses) and cache field/method IDs.
static int PrepareClassMembers(JNIEnv* env, jclass cls) {
    if (!env || !cls || !g_c_Class || !g_c_Field || !g_c_Method) return 0;
    std::string cname = JavaClassName(env, cls);
    if (cname.empty()) return 0;
    {
        std::lock_guard<std::mutex> lk(g_memberMutex);
        if (g_memberCache.count(cname)) return (int) g_memberCache[cname].fields.size();
    }

    // Java Modifier.STATIC is 0x0008
    auto modStatic = [](jint mod) -> bool {
        return (mod & 0x0008) != 0;
    };

    ClassMembers cm;
    cm.name = cname;

    jclass cur = (jclass) env->NewLocalRef(cls);
    while (cur != nullptr) {
        // ---- fields of cur ----
        jmethodID gdf = env->GetMethodID(g_c_Class, "getDeclaredFields", "()[Ljava/lang/reflect/Field;");
        auto fs = gdf ? (jobjectArray) env->CallObjectMethod(cur, gdf) : nullptr;
        if (env->ExceptionCheck()) { env->ExceptionClear(); fs = nullptr; }
        if (fs) {
            jmethodID fName = env->GetMethodID(g_c_Field, "getName", "()Ljava/lang/String;");
            jmethodID fType = env->GetMethodID(g_c_Field, "getType", "()Ljava/lang/Class;");
            jmethodID fMod = env->GetMethodID(g_c_Field, "getModifiers", "()I");
            jsize len = env->GetArrayLength(fs);
            for (jsize i = 0; i < len; i++) {
                jobject f = env->GetObjectArrayElement(fs, i);
                if (!f) continue;
                std::string fname, ftype;
                if (fName) { jstring j = (jstring) env->CallObjectMethod(f, fName); if (j) { const char* c = env->GetStringUTFChars(j, nullptr); if (c) { fname = c; env->ReleaseStringUTFChars(j, c);} env->DeleteLocalRef(j);} }
                if (fType) { jclass t = (jclass) env->CallObjectMethod(f, fType); if (t) { ftype = JavaClassName(env, t); env->DeleteLocalRef(t);} }
                bool isStatic = fMod ? modStatic(env->CallIntMethod(f, fMod)) : false;
                if (env->ExceptionCheck()) env->ExceptionClear();
                if (!fname.empty() && cm.fields.find(fname) == cm.fields.end()) {
                    std::string desc = TypeNameToDescriptor(ftype);
                    jfieldID id = isStatic ? env->GetStaticFieldID(cur, fname.c_str(), desc.c_str())
                                           : env->GetFieldID(cur, fname.c_str(), desc.c_str());
                    if (env->ExceptionCheck()) env->ExceptionClear();
                    if (id) {
                        CachedField cf; cf.id = id; cf.type = desc.empty() ? 'L' : desc[0];
                        cf.typeName = ftype; cf.isStatic = isStatic;
                        cm.fields[fname] = cf;
                    }
                }
                env->DeleteLocalRef(f);
            }
            env->DeleteLocalRef(fs);
        }

        // ---- methods of cur ----
        jmethodID gdm = env->GetMethodID(g_c_Class, "getDeclaredMethods", "()[Ljava/lang/reflect/Method;");
        auto ms = gdm ? (jobjectArray) env->CallObjectMethod(cur, gdm) : nullptr;
        if (env->ExceptionCheck()) { env->ExceptionClear(); ms = nullptr; }
        if (ms) {
            jmethodID mName = env->GetMethodID(g_c_Method, "getName", "()Ljava/lang/String;");
            jmethodID mParams = env->GetMethodID(g_c_Method, "getParameterTypes", "()[Ljava/lang/Class;");
            jmethodID mRet = env->GetMethodID(g_c_Method, "getReturnType", "()Ljava/lang/Class;");
            jmethodID mMod = env->GetMethodID(g_c_Method, "getModifiers", "()I");
            jsize len = env->GetArrayLength(ms);
            for (jsize i = 0; i < len; i++) {
                jobject m = env->GetObjectArrayElement(ms, i);
                if (!m) continue;
                std::string mname;
                if (mName) { jstring j = (jstring) env->CallObjectMethod(m, mName); if (j) { const char* c = env->GetStringUTFChars(j, nullptr); if (c) { mname = c; env->ReleaseStringUTFChars(j, c);} env->DeleteLocalRef(j);} }
                if (mname.empty()) { env->DeleteLocalRef(m); continue; }

                std::vector<std::string> ptypes;
                jobjectArray params = mParams ? (jobjectArray) env->CallObjectMethod(m, mParams) : nullptr;
                if (env->ExceptionCheck()) { env->ExceptionClear(); params = nullptr; }
                if (params) {
                    jsize np = env->GetArrayLength(params);
                    for (jsize k = 0; k < np; k++) {
                        jclass pt = (jclass) env->GetObjectArrayElement(params, k);
                        if (pt) { ptypes.push_back(JavaClassName(env, pt)); env->DeleteLocalRef(pt); }
                        else ptypes.push_back("java.lang.Object");
                    }
                    env->DeleteLocalRef(params);
                }
                std::string rtype;
                if (mRet) { jclass rt = (jclass) env->CallObjectMethod(m, mRet); if (rt) { rtype = JavaClassName(env, rt); env->DeleteLocalRef(rt);} }
                bool isStatic = mMod ? modStatic(env->CallIntMethod(m, mMod)) : false;
                if (env->ExceptionCheck()) env->ExceptionClear();

                std::string sig = "(";
                for (auto& p : ptypes) sig += TypeNameToDescriptor(p);
                sig += ")";
                sig += TypeNameToDescriptor(rtype.empty() ? "void" : rtype);
                jmethodID id = isStatic ? env->GetStaticMethodID(cur, mname.c_str(), sig.c_str())
                                        : env->GetMethodID(cur, mname.c_str(), sig.c_str());
                if (env->ExceptionCheck()) env->ExceptionClear();
                if (id) {
                    CachedMethod cme; cme.id = id; cme.params = ptypes;
                    cme.ret = rtype.empty() ? "void" : rtype; cme.isStatic = isStatic;
                    cm.methods[mname].push_back(cme);
                }
                env->DeleteLocalRef(m);
            }
            env->DeleteLocalRef(ms);
        }

        jclass parent = env->GetSuperclass(cur);
        env->DeleteLocalRef(cur);
        std::string parentName = parent ? JavaClassName(env, parent) : "";
        if (parentName.empty() || parentName == "java.lang.Object") {
            if (parent) env->DeleteLocalRef(parent);
            cur = nullptr;
        } else {
            cur = parent;
        }
    }


    int total = (int) (cm.fields.size() + cm.methods.size());
    {
        std::lock_guard<std::mutex> lk(g_memberMutex);
        g_memberCache[cname] = std::move(cm);
    }
    return total;
}

static const ClassMembers* LookupMembers(const std::string& cname) {
    std::lock_guard<std::mutex> lk(g_memberMutex);
    auto it = g_memberCache.find(cname);
    return it == g_memberCache.end() ? nullptr : &it->second;
}

// JS: prepare(classOrName) -> "prepared <n> members" (call at eval time)
static JSValue JsPrepare(JSContext* ctx, JSValueConst, int argc, JSValueConst* argv) {
    JNIEnv* env = GetEnv();
    if (!env || argc < 1) return JS_NewString(ctx, "Usage: prepare(classOrName)");
    jclass cls = nullptr;
    if (JS_IsString(argv[0])) {
        const char* s = JS_ToCString(ctx, argv[0]);
        if (s) { std::string n(s); for (char& c : n) if (c == '.') c = '/'; cls = env->FindClass(n.c_str()); JS_FreeCString(ctx, s); }
    } else {
        int64_t v = ParsePtr(ctx, argv[0]);
        if (v) cls = reinterpret_cast<jclass>(v);
    }
    if (env->ExceptionCheck()) { env->ExceptionClear(); cls = nullptr; }
    if (!cls) return JS_NewString(ctx, "[!] prepare: class not found");
    int n = PrepareClassMembers(env, cls);
    // Also warm the interpreter's class-ref cache (used to resolve referenced
    // classes on the hook path without env->FindClass).
    {
        std::string jni = JavaClassName(env, cls);
        for (char& c : jni) if (c == '.') c = '/';
        if (!jni.empty()) PI::Interp::RegisterClassRef(env, jni.c_str(), cls);
    }
    char buf[64];
    snprintf(buf, sizeof(buf), "prepared %d members for %s", n, JavaClassName(env, cls).c_str());
    return JS_NewString(ctx, buf);
}

static int ExtractJRefHandle(JSContext* ctx, JSValueConst val) {
    if (JS_IsNumber(val)) {
        int h = -1;
        JS_ToInt32(ctx, &h, val);
        return h;
    }
    if (JS_IsBigInt(ctx, val)) {
        int64_t v = -1;
        JS_ToBigInt64(ctx, &v, val);
        return static_cast<int>(v);
    }
    if (JS_IsObject(val)) {
        JSValue hh = JS_GetPropertyStr(ctx, val, "__h");
        int h = -1;
        if (JS_IsNumber(hh)) {
            JS_ToInt32(ctx, &h, hh);
        } else if (JS_IsBigInt(ctx, hh)) {
            int64_t v = -1;
            JS_ToBigInt64(ctx, &v, hh);
            h = static_cast<int>(v);
        }
        JS_FreeValue(ctx, hh);
        return h;
    }
    return -1;
}

static JSValue ReadCachedField(JSContext* ctx, JNIEnv* env, jobject obj, jclass cls, const CachedField& cf) {
    switch (cf.type) {
        case 'I': case 'S': case 'B': case 'C': return JS_NewInt32(ctx, cf.isStatic ? env->GetStaticIntField(cls, cf.id) : env->GetIntField(obj, cf.id));
        case 'Z': return JS_NewBool(ctx, cf.isStatic ? env->GetStaticBooleanField(cls, cf.id) : env->GetBooleanField(obj, cf.id));
        case 'J': return JS_NewBigInt64(ctx, cf.isStatic ? env->GetStaticLongField(cls, cf.id) : env->GetLongField(obj, cf.id));
        case 'F': return JS_NewFloat64(ctx, cf.isStatic ? env->GetStaticFloatField(cls, cf.id) : env->GetFloatField(obj, cf.id));
        case 'D': return JS_NewFloat64(ctx, cf.isStatic ? env->GetStaticDoubleField(cls, cf.id) : env->GetDoubleField(obj, cf.id));
        default: {
            jobject v = cf.isStatic ? env->GetStaticObjectField(cls, cf.id) : env->GetObjectField(obj, cf.id);
            JSValue ret = JavaObjectToJsValue(ctx, env, v);
            if (v) env->DeleteLocalRef(v);
            return ret;
        }
    }
}

static bool WriteCachedField(JSContext* ctx, JNIEnv* env, jobject obj, jclass cls,
                             const CachedField& cf, JSValueConst v) {
    switch (cf.type) {
        case 'I': case 'S': case 'B': case 'C': { int32_t i = 0; JS_ToInt32(ctx, &i, v); cf.isStatic ? (void) env->SetStaticIntField(cls, cf.id, i) : (void) env->SetIntField(obj, cf.id, i); break; }
        case 'Z': { jboolean b = JS_ToBool(ctx, v) ? JNI_TRUE : JNI_FALSE; cf.isStatic ? (void) env->SetStaticBooleanField(cls, cf.id, b) : (void) env->SetBooleanField(obj, cf.id, b); break; }
        case 'J': { int64_t jv = 0; if (JS_IsBigInt(ctx, v)) JS_ToBigInt64(ctx, &jv, v); else JS_ToInt64(ctx, &jv, v); cf.isStatic ? (void) env->SetStaticLongField(cls, cf.id, jv) : (void) env->SetLongField(obj, cf.id, jv); break; }
        case 'F': { double d = 0; JS_ToFloat64(ctx, &d, v); cf.isStatic ? (void) env->SetStaticFloatField(cls, cf.id, (jfloat) d) : (void) env->SetFloatField(obj, cf.id, (jfloat) d); break; }
        case 'D': { double d = 0; JS_ToFloat64(ctx, &d, v); cf.isStatic ? (void) env->SetStaticDoubleField(cls, cf.id, d) : (void) env->SetDoubleField(obj, cf.id, d); break; }
        default: { jobject o = JsValueToJavaObject(env, ctx, v, cf.typeName); cf.isStatic ? (void) env->SetStaticObjectField(cls, cf.id, o) : (void) env->SetObjectField(obj, cf.id, o); break; }
    }
    if (env->ExceptionCheck()) { env->ExceptionClear(); return false; }
    return true;
}

// JS: __native_jcall(handleOrClass, methodName, ...args) -> invoke via member cache
static JSValue JsJCall(JSContext* ctx, JSValueConst, int argc, JSValueConst* argv) {
    if (argc < 2) return JS_UNDEFINED;
    JNIEnv* env = GetEnv();
    if (!env) return JS_UNDEFINED;

    int h = ExtractJRefHandle(ctx, argv[0]);
    jobject obj = nullptr;
    jclass cls = nullptr;
    std::string cname;
    bool needDeleteCls = false;

    if (h >= 0) {
        obj = GetJRef(h);
        if (!obj) return JS_UNDEFINED;
        cls = env->GetObjectClass(obj);
        cname = JavaClassName(env, cls);
        needDeleteCls = true;
    } else if (JS_IsString(argv[0])) {
        const char* c = JS_ToCString(ctx, argv[0]);
        if (!c) return JS_UNDEFINED;
        cname = c;
        JS_FreeCString(ctx, c);
        cls = FindClassWithFallback(env, cname);
        needDeleteCls = true;
    } else {
        int64_t ptr = ParsePtr(ctx, argv[0]);
        if (ptr > 0x1000) {
            cls = reinterpret_cast<jclass>(ptr);
            cname = JavaClassName(env, cls);
        }
    }

    if (!cls) return JS_UNDEFINED;

    const char* nameC = JS_ToCString(ctx, argv[1]);
    if (!nameC) {
        if (needDeleteCls) env->DeleteLocalRef(cls);
        return JS_UNDEFINED;
    }
    std::string name = nameC;
    JS_FreeCString(ctx, nameC);

    int nargs = argc - 2;
    const ClassMembers* mem = LookupMembers(cname);
    if (!mem) {
        PrepareClassMembers(env, cls);
        mem = LookupMembers(cname);
    }
    const CachedMethod* chosen = nullptr;
    CachedMethod dynMethod;

    if (mem) {
        auto it = mem->methods.find(name);
        if (it != mem->methods.end()) {
            for (const auto& m : it->second) {
                if ((int) m.params.size() == nargs) {
                    if (obj || m.isStatic) { chosen = &m; break; }
                }
            }
            if (!chosen && !it->second.empty()) {
                for (const auto& m : it->second) {
                    if (obj || m.isStatic) { chosen = &m; break; }
                }
            }
        }
    }

    if (!chosen) {
        // Reflection fallback: iterate declared methods on cls and superclasses
        jclass cur = (jclass) env->NewLocalRef(cls);
        while (cur != nullptr && !chosen) {
            jmethodID gdm = env->GetMethodID(g_c_Class, "getDeclaredMethods", "()[Ljava/lang/reflect/Method;");
            auto ms = gdm ? (jobjectArray) env->CallObjectMethod(cur, gdm) : nullptr;
            if (env->ExceptionCheck()) { env->ExceptionClear(); ms = nullptr; }
            if (ms) {
                jmethodID mName = env->GetMethodID(g_c_Method, "getName", "()Ljava/lang/String;");
                jmethodID mParams = env->GetMethodID(g_c_Method, "getParameterTypes", "()[Ljava/lang/Class;");
                jmethodID mRet = env->GetMethodID(g_c_Method, "getReturnType", "()Ljava/lang/Class;");
                jmethodID mMod = env->GetMethodID(g_c_Method, "getModifiers", "()I");
                jsize len = env->GetArrayLength(ms);
                for (jsize i = 0; i < len; i++) {
                    jobject m = env->GetObjectArrayElement(ms, i);
                    if (!m) continue;
                    std::string mname;
                    if (mName) {
                        jstring j = (jstring) env->CallObjectMethod(m, mName);
                        if (j) {
                            const char* c = env->GetStringUTFChars(j, nullptr);
                            if (c) { mname = c; env->ReleaseStringUTFChars(j, c); }
                            env->DeleteLocalRef(j);
                        }
                    }
                    if (mname == name) {
                        jobjectArray params = mParams ? (jobjectArray) env->CallObjectMethod(m, mParams) : nullptr;
                        if (env->ExceptionCheck()) { env->ExceptionClear(); params = nullptr; }
                        jsize np = params ? env->GetArrayLength(params) : 0;
                        if (np == nargs) {
                            bool isStatic = false;
                            if (mMod) {
                                jint modVal = env->CallIntMethod(m, mMod);
                                if (env->ExceptionCheck()) env->ExceptionClear();
                                isStatic = (modVal & 0x0008) != 0;
                            }
                            if (obj || isStatic) {
                                dynMethod.params.clear();
                                for (jsize k = 0; k < np; k++) {
                                    jclass pt = (jclass) env->GetObjectArrayElement(params, k);
                                    if (pt) { dynMethod.params.push_back(JavaClassName(env, pt)); env->DeleteLocalRef(pt); }
                                    else dynMethod.params.push_back("java.lang.Object");
                                }
                                std::string rtype = "void";
                                if (mRet) {
                                    jclass rt = (jclass) env->CallObjectMethod(m, mRet);
                                    if (rt) { rtype = JavaClassName(env, rt); env->DeleteLocalRef(rt); }
                                }
                                dynMethod.ret = rtype;
                                dynMethod.isStatic = isStatic;
                                std::string sig = "(";
                                for (auto& p : dynMethod.params) sig += TypeNameToDescriptor(p);
                                sig += ")";
                                sig += TypeNameToDescriptor(rtype.empty() ? "void" : rtype);
                                dynMethod.id = isStatic ? env->GetStaticMethodID(cur, name.c_str(), sig.c_str())
                                                        : env->GetMethodID(cur, name.c_str(), sig.c_str());
                                if (env->ExceptionCheck()) env->ExceptionClear();
                                if (dynMethod.id) {
                                    chosen = &dynMethod;
                                }
                            }
                        }
                        if (params) env->DeleteLocalRef(params);
                    }
                    env->DeleteLocalRef(m);
                    if (chosen) break;
                }
                env->DeleteLocalRef(ms);
            }
            if (!chosen) {
                jclass parent = env->GetSuperclass(cur);
                env->DeleteLocalRef(cur);
                cur = parent;
            }
        }
        if (cur) env->DeleteLocalRef(cur);
    }

    if (!chosen) {
        if (needDeleteCls) env->DeleteLocalRef(cls);
        if (!obj) {
            return JS_ThrowTypeError(ctx, "Static method '%s' with %d argument(s) not found in class %s",
                                     name.c_str(), nargs, cname.c_str());
        }
        return JS_ThrowTypeError(ctx, "Method '%s' with %d argument(s) not found in class %s",
                                 name.c_str(), nargs, cname.c_str());
    }

    if (!obj && !chosen->isStatic) {
        if (needDeleteCls) env->DeleteLocalRef(cls);
        return JS_ThrowTypeError(ctx, "Cannot invoke non-static method '%s' without an instance (use getInstance() or choose() first)", name.c_str());
    }

    std::vector<jvalue> jargs(nargs);
    for (int k = 0; k < nargs; k++) {
        std::memset(&jargs[k], 0, sizeof(jvalue));
        const std::string& pt = chosen->params[k];
        std::string desc = TypeNameToDescriptor(pt);
        char tc = desc.empty() ? 'L' : desc[0];
        switch (tc) {
            case 'I': case 'S': case 'B': case 'C': { int32_t iv = 0; JS_ToInt32(ctx, &iv, argv[2 + k]); jargs[k].i = iv; break; }
            case 'Z': jargs[k].z = JS_ToBool(ctx, argv[2 + k]) ? JNI_TRUE : JNI_FALSE; break;
            case 'J': { int64_t jv = 0; if (JS_IsBigInt(ctx, argv[2 + k])) JS_ToBigInt64(ctx, &jv, argv[2 + k]); else JS_ToInt64(ctx, &jv, argv[2 + k]); jargs[k].j = jv; break; }
            case 'F': { double d = 0; JS_ToFloat64(ctx, &d, argv[2 + k]); jargs[k].f = (jfloat) d; break; }
            case 'D': { double d = 0; JS_ToFloat64(ctx, &d, argv[2 + k]); jargs[k].d = d; break; }
            default:  jargs[k].l = JsValueToJavaObject(env, ctx, argv[2 + k], pt); break;
        }
    }

    jvalue rv;
    std::memset(&rv, 0, sizeof(rv));
    char rc = TypeNameToDescriptor(chosen->ret)[0];
    bool st = chosen->isStatic;
    jvalue* ap = jargs.empty() ? nullptr : jargs.data();
    switch (rc) {
        case 'V': st ? env->CallStaticVoidMethodA(cls, chosen->id, ap) : (obj ? env->CallVoidMethodA(obj, chosen->id, ap) : (void)0); break;
        case 'I': case 'S': case 'B': case 'C': rv.i = st ? env->CallStaticIntMethodA(cls, chosen->id, ap) : (obj ? env->CallIntMethodA(obj, chosen->id, ap) : 0); break;
        case 'Z': rv.z = st ? env->CallStaticBooleanMethodA(cls, chosen->id, ap) : (obj ? env->CallBooleanMethodA(obj, chosen->id, ap) : JNI_FALSE); break;
        case 'J': rv.j = st ? env->CallStaticLongMethodA(cls, chosen->id, ap) : (obj ? env->CallLongMethodA(obj, chosen->id, ap) : 0); break;
        case 'F': rv.f = st ? env->CallStaticFloatMethodA(cls, chosen->id, ap) : (obj ? env->CallFloatMethodA(obj, chosen->id, ap) : 0.0f); break;
        case 'D': rv.d = st ? env->CallStaticDoubleMethodA(cls, chosen->id, ap) : (obj ? env->CallDoubleMethodA(obj, chosen->id, ap) : 0.0); break;
        default:  rv.l = st ? env->CallStaticObjectMethodA(cls, chosen->id, ap) : (obj ? env->CallObjectMethodA(obj, chosen->id, ap) : nullptr); break;
    }
    bool exc = env->ExceptionCheck() != 0;
    if (exc) env->ExceptionClear();
    if (needDeleteCls) env->DeleteLocalRef(cls);
    if (exc) return JS_UNDEFINED;

    switch (rc) {
        case 'V': return JS_UNDEFINED;
        case 'Z': return JS_NewBool(ctx, rv.z);
        case 'J': return JS_NewBigInt64(ctx, rv.j);
        case 'F': return JS_NewFloat64(ctx, (double) rv.f);
        case 'D': return JS_NewFloat64(ctx, rv.d);
        case 'I': case 'S': case 'B': case 'C': return JS_NewInt32(ctx, rv.i);
        default: {
            JSValue ret = JavaObjectToJsValue(ctx, env, rv.l);
            if (rv.l) env->DeleteLocalRef(rv.l);
            return ret;
        }
    }
}

// JS: __native_jarray_len(handle) -> length or -1 (not an array)
static JSValue JsJArrayLen(JSContext* ctx, JSValueConst, int argc, JSValueConst* argv) {
    if (argc < 1) return JS_NewInt32(ctx, -1);
    int h = 0; JS_ToInt32(ctx, &h, argv[0]);
    jobject obj = GetJRef(h);
    JNIEnv* env = GetEnv();
    if (!obj || !env) return JS_NewInt32(ctx, -1);
    jclass c = env->GetObjectClass(obj);
    std::string n = JavaClassName(env, c);
    if (c) env->DeleteLocalRef(c);
    if (n.empty() || n[0] != '[') return JS_NewInt32(ctx, -1);
    return JS_NewInt32(ctx, env->GetArrayLength((jarray) obj));
}

// JS: __native_jarray_get(handle, i)
static JSValue JsJArrayGet(JSContext* ctx, JSValueConst, int argc, JSValueConst* argv) {
    if (argc < 2) return JS_UNDEFINED;
    int h = 0; JS_ToInt32(ctx, &h, argv[0]);
    int32_t idx = 0; JS_ToInt32(ctx, &idx, argv[1]);
    jobject arr = GetJRef(h);
    JNIEnv* env = GetEnv();
    if (!arr || !env) return JS_UNDEFINED;
    jclass c = env->GetObjectClass(arr);
    std::string n = JavaClassName(env, c);
    if (c) env->DeleteLocalRef(c);
    if (n.size() < 2 || n[0] != '[') return JS_UNDEFINED;
    int len = env->GetArrayLength((jarray) arr);
    if (idx < 0 || idx >= len) return JS_UNDEFINED;

    char t = n[1];
    if (t == 'L' || t == '[') {
        jobject e = env->GetObjectArrayElement((jobjectArray) arr, idx);
        if (env->ExceptionCheck()) { env->ExceptionClear(); return JS_UNDEFINED; }
        return JavaObjectToJsValue(ctx, env, e);
    }
    jint iv; jlong jv; jboolean zv; jfloat fv; jdouble dv;
    switch (t) {
        case 'Z': env->GetBooleanArrayRegion((jbooleanArray) arr, idx, 1, &zv); return JS_NewBool(ctx, zv);
        case 'B': { jbyte b; env->GetByteArrayRegion((jbyteArray) arr, idx, 1, &b); return JS_NewInt32(ctx, b); }
        case 'C': { jchar ch; env->GetCharArrayRegion((jcharArray) arr, idx, 1, &ch); return JS_NewInt32(ctx, ch); }
        case 'S': { jshort s; env->GetShortArrayRegion((jshortArray) arr, idx, 1, &s); return JS_NewInt32(ctx, s); }
        case 'I': env->GetIntArrayRegion((jintArray) arr, idx, 1, &iv); return JS_NewInt32(ctx, iv);
        case 'J': env->GetLongArrayRegion((jlongArray) arr, idx, 1, &jv); return JS_NewBigInt64(ctx, jv);
        case 'F': env->GetFloatArrayRegion((jfloatArray) arr, idx, 1, &fv); return JS_NewFloat64(ctx, fv);
        case 'D': env->GetDoubleArrayRegion((jdoubleArray) arr, idx, 1, &dv); return JS_NewFloat64(ctx, dv);
        default: return JS_UNDEFINED;
    }
}

// JS: __native_jarray_set(handle, i, v) -> bool
static JSValue JsJArraySet(JSContext* ctx, JSValueConst, int argc, JSValueConst* argv) {
    if (argc < 3) return JS_FALSE;
    int h = 0; JS_ToInt32(ctx, &h, argv[0]);
    int32_t idx = 0; JS_ToInt32(ctx, &idx, argv[1]);
    jobject arr = GetJRef(h);
    JNIEnv* env = GetEnv();
    if (!arr || !env) return JS_FALSE;
    jclass c = env->GetObjectClass(arr);
    std::string n = JavaClassName(env, c);
    if (c) env->DeleteLocalRef(c);
    if (n.size() < 2 || n[0] != '[') return JS_FALSE;
    int len = env->GetArrayLength((jarray) arr);
    if (idx < 0 || idx >= len) return JS_FALSE;

    char t = n[1];
    if (t == 'L' || t == '[') {
        std::string tn = n.substr(1);
        jobject e = JsValueToJavaObject(env, ctx, argv[2], tn);
        env->SetObjectArrayElement((jobjectArray) arr, idx, e);
        if (env->ExceptionCheck()) { env->ExceptionClear(); return JS_FALSE; }
        return JS_TRUE;
    }
    int32_t iv = 0; int64_t jv = 0; double dv = 0;
    if (JS_IsBigInt(ctx, argv[2])) JS_ToBigInt64(ctx, &jv, argv[2]); else JS_ToInt64(ctx, &jv, argv[2]);
    JS_ToInt32(ctx, &iv, argv[2]);
    JS_ToFloat64(ctx, &dv, argv[2]);
    switch (t) {
        case 'Z': { jboolean zv = JS_ToBool(ctx, argv[2]) ? JNI_TRUE : JNI_FALSE; env->SetBooleanArrayRegion((jbooleanArray) arr, idx, 1, &zv); break; }
        case 'B': { jbyte b = (jbyte) iv; env->SetByteArrayRegion((jbyteArray) arr, idx, 1, &b); break; }
        case 'C': { jchar ch = (jchar) iv; env->SetCharArrayRegion((jcharArray) arr, idx, 1, &ch); break; }
        case 'S': { jshort s = (jshort) iv; env->SetShortArrayRegion((jshortArray) arr, idx, 1, &s); break; }
        case 'I': { jint v = iv; env->SetIntArrayRegion((jintArray) arr, idx, 1, &v); break; }
        case 'J': { jlong v = jv; env->SetLongArrayRegion((jlongArray) arr, idx, 1, &v); break; }
        case 'F': { jfloat v = (jfloat) dv; env->SetFloatArrayRegion((jfloatArray) arr, idx, 1, &v); break; }
        case 'D': { jdouble v = dv; env->SetDoubleArrayRegion((jdoubleArray) arr, idx, 1, &v); break; }
        default: return JS_FALSE;
    }
    if (env->ExceptionCheck()) { env->ExceptionClear(); return JS_FALSE; }
    return JS_TRUE;
}

// ---------------------------------------------------------------------------
// JRef: JS wrapper over a Java object supporting `obj.field` get/set.
// ---------------------------------------------------------------------------
struct JRefEntry {
    jobject obj = nullptr;
    bool isGlobal = false;
    uint64_t originalAddr = 0;
};
static std::mutex g_jrefMutex;
static std::vector<JRefEntry> g_jrefs;

static int AddJRef(JNIEnv* env, jobject o, uint64_t addr = 0, bool persistent = false) {
    if (!env || !o) return -1;
    std::lock_guard<std::mutex> lk(g_jrefMutex);
    if (addr != 0) {
        for (size_t i = 0; i < g_jrefs.size(); i++) {
            if (g_jrefs[i].originalAddr == addr && g_jrefs[i].obj) {
                if (!g_jrefs[i].isGlobal && persistent) {
                    jobject old = g_jrefs[i].obj;
                    g_jrefs[i].obj = env->NewGlobalRef(old);
                    g_jrefs[i].isGlobal = true;
                    env->DeleteLocalRef(old);
                }
                return static_cast<int>(i);
            }
        }
    }
    JRefEntry e;
    e.isGlobal = persistent;
    e.obj = persistent ? env->NewGlobalRef(o) : env->NewLocalRef(o);
    e.originalAddr = addr ? addr : reinterpret_cast<uintptr_t>(o);
    g_jrefs.push_back(e);
    return static_cast<int>(g_jrefs.size()) - 1;
}

static jobject GetJRef(int h) {
    std::lock_guard<std::mutex> lk(g_jrefMutex);
    if (h < 0 || h >= static_cast<int>(g_jrefs.size())) return nullptr;
    return g_jrefs[h].obj;
}

static uint64_t GetJRefAddr(int h) {
    std::lock_guard<std::mutex> lk(g_jrefMutex);
    if (h < 0 || h >= static_cast<int>(g_jrefs.size())) return 0;
    return g_jrefs[h].originalAddr;
}

static void PopJRefsTo(JNIEnv* env, size_t base) {
    std::lock_guard<std::mutex> lk(g_jrefMutex);
    while (g_jrefs.size() > base) {
        auto& e = g_jrefs.back();
        if (env && e.obj) {
            if (e.isGlobal) env->DeleteGlobalRef(e.obj);
            else env->DeleteLocalRef(e.obj);
        }
        g_jrefs.pop_back();
    }
}

// ---------------------------------------------------------------------------
// Observed objects ring buffer (records objects printed in trace/hook logs)
// ---------------------------------------------------------------------------
static std::mutex g_observedMutex;
static std::unordered_map<uint64_t, jobject> g_observedObjects;
static std::deque<std::pair<uint64_t, jobject>> g_observedQueue;
static const size_t kMaxObserved = 2048;
static void DoRegisterObservedObject(JNIEnv* env, uint64_t raw, jobject obj) {
    if (!env || !obj || !raw) return;
    std::lock_guard<std::mutex> lk(g_observedMutex);
    if (g_observedObjects.find(raw) != g_observedObjects.end()) return;

    jobject gref = env->NewGlobalRef(obj);
    if (!gref) {
        if (env->ExceptionCheck()) env->ExceptionClear();
        return;
    }
    g_observedObjects[raw] = gref;
    g_observedQueue.push_back({raw, gref});

    // Also decode art_obj if possible and map its raw heap address too!
    void* decoded = PineNative_ToArtObject(env, obj);
    if (decoded) {
        uint64_t heapAddr = reinterpret_cast<uintptr_t>(decoded);
        if (heapAddr && heapAddr != raw && g_observedObjects.find(heapAddr) == g_observedObjects.end()) {
            g_observedObjects[heapAddr] = gref;
        }
    }

    if (g_observedQueue.size() > kMaxObserved) {
        auto front = g_observedQueue.front();
        g_observedQueue.pop_front();
        g_observedObjects.erase(front.first);
        env->DeleteGlobalRef(front.second);
    }
}

static std::string JavaClassName(JNIEnv* env, jclass cls) {
    if (!cls || !g_c_Class) return "";
    jmethodID getName = env->GetMethodID(g_c_Class, "getName", "()Ljava/lang/String;");
    std::string n;
    if (getName) {
        auto jn = static_cast<jstring>(env->CallObjectMethod(cls, getName));
        if (jn) {
            const char* c = env->GetStringUTFChars(jn, nullptr);
            if (c) { n = c; env->ReleaseStringUTFChars(jn, c); }
            env->DeleteLocalRef(jn);
        }
    }
    if (env->ExceptionCheck()) env->ExceptionClear();
    return n;
}

static JSValue CreateJRefValue(JSContext* ctx, int handle) {
    if (handle < 0) return JS_NULL;
    JSValue global = JS_GetGlobalObject(ctx);
    JSValue fn = JS_GetPropertyStr(ctx, global, "__makeJRef");
    JSValue r = JS_NULL;
    if (JS_IsFunction(ctx, fn)) {
        JSValue a = JS_NewInt32(ctx, handle);
        r = JS_Call(ctx, fn, JS_UNDEFINED, 1, &a);
        JS_FreeValue(ctx, a);
    }
    JS_FreeValue(ctx, fn);
    JS_FreeValue(ctx, global);
    return r;
}

static JSValue JavaObjectToJsValue(JSContext* ctx, JNIEnv* env, jobject obj) {
    if (!env || !obj) return JS_NULL;
    jclass cls = env->GetObjectClass(obj);
    std::string n = JavaClassName(env, cls);

    auto callNum = [&](const char* cname, const char* mid, const char* sig) -> jdouble {
        jclass c = CachedWrapperClass(cname);
        if (!c) return 0;
        jmethodID m = env->GetMethodID(c, mid, sig);
        jdouble r = 0;
        if (m) {
            if (std::strcmp(sig, "()Z") == 0) r = env->CallBooleanMethod(obj, m) ? 1 : 0;
            else if (std::strcmp(sig, "()I") == 0) r = env->CallIntMethod(obj, m);
            else if (std::strcmp(sig, "()J") == 0) r = (jdouble) env->CallLongMethod(obj, m);
            else if (std::strcmp(sig, "()C") == 0) r = (jdouble) env->CallCharMethod(obj, m);
            else if (std::strcmp(sig, "()F") == 0) r = env->CallFloatMethod(obj, m);
            else if (std::strcmp(sig, "()D") == 0) r = env->CallDoubleMethod(obj, m);
        }
        if (env->ExceptionCheck()) env->ExceptionClear();
        return r;
    };

    JSValue r = JS_NULL;
    if (n == "java.lang.String") {
        const char* c = env->GetStringUTFChars(static_cast<jstring>(obj), nullptr);
        r = JS_NewString(ctx, c ? c : "");
        if (c) env->ReleaseStringUTFChars(static_cast<jstring>(obj), c);
    } else if (n == "java.lang.Boolean") {
        r = JS_NewBool(ctx, callNum("java/lang/Boolean", "booleanValue", "()Z") != 0);
    } else if (n == "java.lang.Integer" || n == "java.lang.Short" || n == "java.lang.Byte") {
        r = JS_NewInt32(ctx, (int32_t) callNum("java/lang/Number", "intValue", "()I"));
    } else if (n == "java.lang.Character") {
        r = JS_NewInt32(ctx, (int32_t) callNum("java/lang/Character", "charValue", "()C"));
    } else if (n == "java.lang.Long") {
        r = JS_NewBigInt64(ctx, (int64_t) callNum("java/lang/Long", "longValue", "()J"));
    } else if (n == "java.lang.Float" || n == "java.lang.Double") {
        r = JS_NewFloat64(ctx, callNum("java/lang/Number", "doubleValue", "()D"));
    } else {
        void* artObj = PineNative_ToArtObject(env, obj);
        uint64_t addr = artObj ? reinterpret_cast<uintptr_t>(artObj) : reinterpret_cast<uintptr_t>(obj);
        DoRegisterObservedObject(env, addr, obj);
        int handle = AddJRef(env, obj, addr, /*persistent=*/true);
        r = CreateJRefValue(ctx, handle);
    }

    if (cls) env->DeleteLocalRef(cls);
    return r;
}

// Convert a JS value to a (boxed) Java object for a target type name.
static jobject JsValueToJavaObject(JNIEnv* env, JSContext* ctx, JSValueConst v, const std::string& tn) {
    if (!env) return nullptr;
    if (JS_IsNull(v) || JS_IsUndefined(v)) return nullptr;

    if (tn == "java.lang.String" || tn == "Ljava/lang/String;") {
        const char* s = JS_ToCString(ctx, v);
        jstring j = s ? env->NewStringUTF(s) : nullptr;
        if (s) JS_FreeCString(ctx, s);
        return j;
    }
    auto box = [&](const char* cls, const char* sig, char kind) -> jobject {
        jclass c = CachedWrapperClass(cls);
        if (!c) return nullptr;
        jmethodID m = env->GetStaticMethodID(c, "valueOf", sig);
        jobject o = nullptr;
        if (m) {
            if (kind == 'Z') o = env->CallStaticObjectMethod(c, m, JS_ToBool(ctx, v) ? JNI_TRUE : JNI_FALSE);
            else if (kind == 'I') { int32_t i = 0; JS_ToInt32(ctx, &i, v); o = env->CallStaticObjectMethod(c, m, (jint) i); }
            else if (kind == 'J') { int64_t l = 0; if (JS_IsBigInt(ctx, v)) JS_ToBigInt64(ctx, &l, v); else JS_ToInt64(ctx, &l, v); o = env->CallStaticObjectMethod(c, m, (jlong) l); }
            else if (kind == 'C') { int32_t i = 0; JS_ToInt32(ctx, &i, v); o = env->CallStaticObjectMethod(c, m, (jchar) i); }
            else if (kind == 'F') { double d = 0; JS_ToFloat64(ctx, &d, v); o = env->CallStaticObjectMethod(c, m, (jfloat) d); }
            else if (kind == 'D') { double d = 0; JS_ToFloat64(ctx, &d, v); o = env->CallStaticObjectMethod(c, m, (jdouble) d); }
        }
        if (env->ExceptionCheck()) env->ExceptionClear();
        return o;
    };

    if (tn == "int" || tn == "java.lang.Integer") return box("java/lang/Integer", "(I)Ljava/lang/Integer;", 'I');
    if (tn == "long" || tn == "java.lang.Long") return box("java/lang/Long", "(J)Ljava/lang/Long;", 'J');
    if (tn == "boolean" || tn == "java.lang.Boolean") return box("java/lang/Boolean", "(Z)Ljava/lang/Boolean;", 'Z');
    if (tn == "short" || tn == "java.lang.Short") return box("java/lang/Short", "(S)Ljava/lang/Short;", 'I');
    if (tn == "byte" || tn == "java.lang.Byte") return box("java/lang/Byte", "(B)Ljava/lang/Byte;", 'I');
    if (tn == "char" || tn == "java.lang.Character") return box("java/lang/Character", "(C)Ljava/lang/Character;", 'C');
    if (tn == "float" || tn == "java.lang.Float") return box("java/lang/Float", "(F)Ljava/lang/Float;", 'F');
    if (tn == "double" || tn == "java.lang.Double") return box("java/lang/Double", "(D)Ljava/lang/Double;", 'D');

    // Fallback: treat as a nested JRef
    int h = ExtractJRefHandle(ctx, v);
    jobject inner = GetJRef(h);
    return inner ? env->NewLocalRef(inner) : nullptr;
}

// Method trampoline: obj.method(...) -> __native_jcall(handle, name, ...args)
static JSValue JsJMethodTrampoline(JSContext* ctx, JSValueConst, int argc, JSValueConst* argv,
                                   int /*magic*/, JSValue* func_data) {
    std::vector<JSValue> args;
    args.reserve(argc + 2);
    args.push_back(JS_DupValue(ctx, func_data[0]));
    args.push_back(JS_DupValue(ctx, func_data[1]));
    for (int i = 0; i < argc; i++) args.push_back(JS_DupValue(ctx, argv[i]));
    JSValue r = JsJCall(ctx, JS_UNDEFINED, (int) args.size(), args.data());
    for (auto& v : args) JS_FreeValue(ctx, v);
    return r;
}

static uint64_t ParseObjAddr(JSContext* ctx, JSValueConst val) {
    if (JS_IsBigInt(ctx, val)) {
        int64_t v = 0;
        JS_ToBigInt64(ctx, &v, val);
        return static_cast<uint64_t>(v);
    }
    if (JS_IsNumber(val)) {
        double d = 0;
        JS_ToFloat64(ctx, &d, val);
        return static_cast<uint64_t>(d);
    }
    if (JS_IsString(val)) {
        const char* s = JS_ToCString(ctx, val);
        if (!s) return 0;
        uint64_t addr = 0;
        std::string str(s);
        JS_FreeCString(ctx, s);
        size_t p = str.find_first_not_of(" \t\r\n\"'");
        if (p != std::string::npos) str = str.substr(p);
        size_t q = str.find_last_not_of(" \t\r\n\"'");
        if (q != std::string::npos) str = str.substr(0, q + 1);
        if (str.size() > 2 && (str[0] == '0' && (str[1] == 'x' || str[1] == 'X'))) {
            addr = std::strtoull(str.c_str() + 2, nullptr, 16);
        } else if (str.find_first_of("abcdefABCDEF") != std::string::npos) {
            addr = std::strtoull(str.c_str(), nullptr, 16);
        } else {
            addr = std::strtoull(str.c_str(), nullptr, 10);
        }
        return addr;
    }
    if (JS_IsObject(val)) {
        JSValue hh = JS_GetPropertyStr(ctx, val, "__h");
        if (JS_IsNumber(hh)) {
            int h = -1;
            JS_ToInt32(ctx, &h, hh);
            JS_FreeValue(ctx, hh);
            return GetJRefAddr(h);
        }
        JS_FreeValue(ctx, hh);
    }
    return 0;
}

static std::string SimplifyJavaType(std::string t) {
    if (t.empty()) return "void";
    if (t == "kotlin.Unit") return "void";

    int arrayDims = 0;
    while (!t.empty() && t[0] == '[') {
        arrayDims++;
        t = t.substr(1);
    }
    if (arrayDims > 0) {
        if (t == "Z") t = "boolean";
        else if (t == "B") t = "byte";
        else if (t == "C") t = "char";
        else if (t == "S") t = "short";
        else if (t == "I") t = "int";
        else if (t == "J") t = "long";
        else if (t == "F") t = "float";
        else if (t == "D") t = "double";
        else if (!t.empty() && t[0] == 'L' && t.back() == ';') {
            t = t.substr(1, t.size() - 2);
            std::replace(t.begin(), t.end(), '/', '.');
        }
    }

    if (t.rfind("java.lang.", 0) == 0) {
        t = t.substr(10);
    } else if (t.rfind("java.util.", 0) == 0) {
        t = t.substr(10);
    } else {
        int dotCount = 0;
        for (char c : t) if (c == '.') dotCount++;

        size_t dollar = t.find('$');
        std::string innerPart;
        std::string mainPart = t;
        if (dollar != std::string::npos) {
            innerPart = t.substr(dollar);
            std::replace(innerPart.begin(), innerPart.end(), '$', '.');
            mainPart = t.substr(0, dollar);
        }

        if (dotCount >= 2 || mainPart.rfind("android.", 0) == 0 ||
            mainPart.rfind("androidx.", 0) == 0 || mainPart.rfind("kotlin.", 0) == 0) {
            size_t lastDot = mainPart.rfind('.');
            if (lastDot != std::string::npos) {
                std::string base = mainPart.substr(lastDot + 1);
                if (!base.empty()) {
                    t = base + innerPart;
                }
            }
        } else if (!innerPart.empty()) {
            t = mainPart + innerPart;
        }
    }

    while (arrayDims-- > 0) {
        t += "[]";
    }
    return t;
}

static std::string FormatJavaModifiers(uint32_t f) {
    std::string s;
    auto add = [&](const char* w) { if (!s.empty()) s += ' '; s += w; };
    if (f & 0x0001) add("public");
    if (f & 0x0002) add("private");
    if (f & 0x0004) add("protected");
    if (f & 0x0008) add("static");
    if (f & 0x0010) add("final");
    if (f & 0x0020) add("synchronized");
    if (f & 0x0040) add("volatile");
    if (f & 0x0080) add("transient");
    if (f & 0x0100) add("native");
    if (f & 0x0400) add("abstract");
    return s;
}

static std::string FormatDumpValue(JNIEnv* env, jobject val, const std::string& typeName) {
    if (!val) return "null";
    if (typeName == "java.lang.String" || typeName == "Ljava/lang/String;") {
        const char* c = env->GetStringUTFChars(static_cast<jstring>(val), nullptr);
        std::string s = c ? ("\"" + std::string(c) + "\"") : "null";
        if (c) env->ReleaseStringUTFChars(static_cast<jstring>(val), c);
        return s;
    }
    if (typeName == "boolean" || typeName == "java.lang.Boolean") {
        jclass c = AgentCachedClass("java/lang/Boolean");
        jmethodID m = c ? env->GetMethodID(c, "booleanValue", "()Z") : nullptr;
        if (m) return env->CallBooleanMethod(val, m) ? "true" : "false";
    }
    if (typeName == "int" || typeName == "java.lang.Integer" || typeName == "short" || typeName == "byte") {
        jclass c = AgentCachedClass("java/lang/Number");
        jmethodID m = c ? env->GetMethodID(c, "intValue", "()I") : nullptr;
        if (m) return std::to_string(env->CallIntMethod(val, m));
    }
    if (typeName == "long" || typeName == "java.lang.Long") {
        jclass c = AgentCachedClass("java/lang/Long");
        jmethodID m = c ? env->GetMethodID(c, "longValue", "()J") : nullptr;
        if (m) return std::to_string(env->CallLongMethod(val, m)) + "L";
    }
    if (typeName == "float" || typeName == "double" || typeName == "java.lang.Float" || typeName == "java.lang.Double") {
        jclass c = AgentCachedClass("java/lang/Number");
        jmethodID m = c ? env->GetMethodID(c, "doubleValue", "()D") : nullptr;
        if (m) {
            char b[32]; snprintf(b, sizeof(b), "%g", env->CallDoubleMethod(val, m));
            return b;
        }
    }
    if (typeName == "char" || typeName == "java.lang.Character") {
        jclass c = AgentCachedClass("java/lang/Character");
        jmethodID m = c ? env->GetMethodID(c, "charValue", "()C") : nullptr;
        if (m) {
            jchar ch = env->CallCharMethod(val, m);
            return std::string("'") + (char)ch + "'";
        }
    }
    if (!typeName.empty() && typeName[0] == '[') {
        jsize len = env->GetArrayLength((jarray)val);
        if (env->ExceptionCheck()) { env->ExceptionClear(); return "[]"; }
        char abuf[64];
        snprintf(abuf, sizeof(abuf), "%s[%d]@0x%llx", SimplifyJavaType(typeName).c_str(), (int)len, (unsigned long long)reinterpret_cast<uintptr_t>(val));
        return abuf;
    }
    // Generic object: TypeName@0xaddr
    uint64_t vAddr = reinterpret_cast<uintptr_t>(val);
    DoRegisterObservedObject(env, vAddr, val);
    char buf[128];
    snprintf(buf, sizeof(buf), "%s@0x%llx", SimplifyJavaType(typeName).c_str(), (unsigned long long)vAddr);
    return buf;
}

static std::string DumpArtObject(JNIEnv* env, jobject obj, uint64_t addr) {
    if (!env || !obj) return "<null>";
    jclass cls = env->GetObjectClass(obj);
    if (!cls) {
        if (env->ExceptionCheck()) env->ExceptionClear();
        return "<invalid object>";
    }
    std::string className = JavaClassName(env, cls);
    if (!addr) addr = reinterpret_cast<uintptr_t>(obj);

    std::ostringstream ss;
    std::string simpleClassName = SimplifyJavaType(className);
    std::string extendsStr;

    jclass superClass = env->GetSuperclass(cls);
    if (superClass) {
        std::string sname = JavaClassName(env, superClass);
        if (!sname.empty() && sname != "java.lang.Object") {
            extendsStr = " extends " + SimplifyJavaType(sname);
        }
        env->DeleteLocalRef(superClass);
    }

    char headerBuf[256];
    snprintf(headerBuf, sizeof(headerBuf), "// %s @ 0x%llx\nclass %s%s {",
             className.c_str(), (unsigned long long) addr,
             simpleClassName.c_str(), extendsStr.c_str());
    ss << headerBuf << "\n";

    std::vector<std::string> instanceFields;
    std::vector<std::string> staticFields;
    std::vector<std::string> methodsList;
    std::unordered_set<std::string> seenInstanceFields;
    std::unordered_set<std::string> seenStaticFields;
    std::unordered_set<std::string> seenMethods;

    jclass cur = (jclass) env->NewLocalRef(cls);
    while (cur != nullptr) {
        // Scan fields
        jmethodID gdf = env->GetMethodID(g_c_Class, "getDeclaredFields", "()[Ljava/lang/reflect/Field;");
        auto fs = gdf ? (jobjectArray) env->CallObjectMethod(cur, gdf) : nullptr;
        if (env->ExceptionCheck()) { env->ExceptionClear(); fs = nullptr; }
        if (fs) {
            jmethodID fName = env->GetMethodID(g_c_Field, "getName", "()Ljava/lang/String;");
            jmethodID fType = env->GetMethodID(g_c_Field, "getType", "()Ljava/lang/Class;");
            jmethodID fMod = env->GetMethodID(g_c_Field, "getModifiers", "()I");
            jmethodID setAcc = env->GetMethodID(g_c_Field, "setAccessible", "(Z)V");
            jmethodID getVal = env->GetMethodID(g_c_Field, "get", "(Ljava/lang/Object;)Ljava/lang/Object;");

            jsize len = env->GetArrayLength(fs);
            for (jsize i = 0; i < len; i++) {
                jobject f = env->GetObjectArrayElement(fs, i);
                if (!f) continue;
                if (setAcc) {
                    env->CallVoidMethod(f, setAcc, JNI_TRUE);
                    if (env->ExceptionCheck()) env->ExceptionClear();
                }

                std::string fname, ftype;
                if (fName) {
                    jstring j = (jstring) env->CallObjectMethod(f, fName);
                    if (j) {
                        const char* c = env->GetStringUTFChars(j, nullptr);
                        if (c) { fname = c; env->ReleaseStringUTFChars(j, c); }
                        env->DeleteLocalRef(j);
                    }
                }
                if (fType) {
                    jclass t = (jclass) env->CallObjectMethod(f, fType);
                    if (t) { ftype = JavaClassName(env, t); env->DeleteLocalRef(t); }
                }
                int mod = fMod ? env->CallIntMethod(f, fMod) : 0;
                if (env->ExceptionCheck()) env->ExceptionClear();
                bool isStatic = (mod & 0x0008) != 0;

                if (isStatic) {
                    if (!seenStaticFields.insert(fname).second) {
                        env->DeleteLocalRef(f);
                        continue;
                    }
                } else {
                    if (!seenInstanceFields.insert(fname).second) {
                        env->DeleteLocalRef(f);
                        continue;
                    }
                }

                std::string valStr = "?";
                if (getVal) {
                    jobject v = env->CallObjectMethod(f, getVal, isStatic ? nullptr : obj);
                    if (env->ExceptionCheck()) {
                        env->ExceptionClear();
                        valStr = "<inaccessible>";
                    } else if (!v) {
                        valStr = "null";
                    } else {
                        valStr = FormatDumpValue(env, v, ftype);
                        env->DeleteLocalRef(v);
                    }
                }

                std::string modStr = FormatJavaModifiers(mod);
                if (!modStr.empty()) modStr += " ";
                std::string typeStr = SimplifyJavaType(ftype);
                std::string entry = "    " + modStr + typeStr + " " + fname + " = " + valStr + ";";

                if (isStatic) staticFields.push_back(entry);
                else instanceFields.push_back(entry);

                env->DeleteLocalRef(f);
            }
            env->DeleteLocalRef(fs);
        }

        // Scan methods
        jmethodID gdm = env->GetMethodID(g_c_Class, "getDeclaredMethods", "()[Ljava/lang/reflect/Method;");
        auto ms = gdm ? (jobjectArray) env->CallObjectMethod(cur, gdm) : nullptr;
        if (env->ExceptionCheck()) { env->ExceptionClear(); ms = nullptr; }
        if (ms) {
            jmethodID mName = env->GetMethodID(g_c_Method, "getName", "()Ljava/lang/String;");
            jmethodID mParams = env->GetMethodID(g_c_Method, "getParameterTypes", "()[Ljava/lang/Class;");
            jmethodID mRet = env->GetMethodID(g_c_Method, "getReturnType", "()Ljava/lang/Class;");
            jmethodID mMod = env->GetMethodID(g_c_Method, "getModifiers", "()I");

            jsize mlen = env->GetArrayLength(ms);
            for (jsize i = 0; i < mlen; i++) {
                jobject m = env->GetObjectArrayElement(ms, i);
                if (!m) continue;
                std::string mname, rtype;
                if (mName) {
                    jstring j = (jstring) env->CallObjectMethod(m, mName);
                    if (j) {
                        const char* c = env->GetStringUTFChars(j, nullptr);
                        if (c) { mname = c; env->ReleaseStringUTFChars(j, c); }
                        env->DeleteLocalRef(j);
                    }
                }
                if (mRet) {
                    jclass rt = (jclass) env->CallObjectMethod(m, mRet);
                    if (rt) { rtype = JavaClassName(env, rt); env->DeleteLocalRef(rt); }
                }
                int mod = mMod ? env->CallIntMethod(m, mMod) : 0;
                if (env->ExceptionCheck()) env->ExceptionClear();

                std::string paramsStr;
                if (mParams) {
                    auto pa = (jobjectArray) env->CallObjectMethod(m, mParams);
                    if (pa) {
                        jsize plen = env->GetArrayLength(pa);
                        for (jsize p = 0; p < plen; p++) {
                            if (p > 0) paramsStr += ", ";
                            jclass pt = (jclass) env->GetObjectArrayElement(pa, p);
                            if (pt) {
                                std::string ptName = JavaClassName(env, pt);
                                paramsStr += SimplifyJavaType(ptName) + " arg" + std::to_string(p);
                                env->DeleteLocalRef(pt);
                            }
                        }
                        env->DeleteLocalRef(pa);
                    }
                }

                std::string mSig = mname + "(" + paramsStr + ")";
                if (seenMethods.insert(mSig).second) {
                    std::string modStr = FormatJavaModifiers(mod);
                    if (!modStr.empty()) modStr += " ";
                    std::string retStr = SimplifyJavaType(rtype);
                    std::string mEntry = "    " + modStr + retStr + " " + mname + "(" + paramsStr + ");";
                    methodsList.push_back(mEntry);
                }
                env->DeleteLocalRef(m);
            }
            env->DeleteLocalRef(ms);
        }

        jclass parent = env->GetSuperclass(cur);
        env->DeleteLocalRef(cur);
        std::string parentName = parent ? JavaClassName(env, parent) : "";
        if (parentName.empty() || parentName == "java.lang.Object" || parentName.rfind("android.app.", 0) == 0) {
            if (parent) env->DeleteLocalRef(parent);
            cur = nullptr;
        } else {
            cur = parent;
        }
    }

    env->DeleteLocalRef(cls);

    if (!instanceFields.empty()) {
        ss << "    // --- Fields (" << instanceFields.size() << ") ---\n";
        for (const auto& f : instanceFields) ss << f << "\n";
        ss << "\n";
    }

    if (!staticFields.empty()) {
        ss << "    // --- Static Fields (" << staticFields.size() << ") ---\n";
        for (const auto& f : staticFields) ss << f << "\n";
        ss << "\n";
    }

    if (!methodsList.empty()) {
        ss << "    // --- Methods (" << methodsList.size() << ") ---\n";
        size_t showM = std::min(methodsList.size(), static_cast<size_t>(25));
        for (size_t i = 0; i < showM; i++) ss << methodsList[i] << "\n";
        if (methodsList.size() > showM) {
            ss << "    // ... (" << (methodsList.size() - showM) << " more methods, call .methods() to list all)\n";
        }
    }

    ss << "}";
    return ss.str();
}

static JSValue JsArtObject(JSContext* ctx, JSValueConst, int argc, JSValueConst* argv) {
    if (argc < 1) {
        JNIEnv* env = GetEnv();
        std::lock_guard<std::mutex> lk(g_observedMutex);
        if (g_observedObjects.empty()) {
            return JS_NewString(ctx, "No observed objects yet. Trigger a hook or trace to observe objects.");
        }
        std::ostringstream ss;
        ss << "// Observed Objects (" << g_observedObjects.size() << ")\n";
        for (const auto& pair : g_observedObjects) {
            std::string cname = "Object";
            if (env && pair.second) {
                jclass c = env->GetObjectClass(pair.second);
                if (c) {
                    cname = SimplifyJavaType(JavaClassName(env, c));
                    env->DeleteLocalRef(c);
                }
            }
            char buf[128];
            snprintf(buf, sizeof(buf), "  artobject(0x%llx) -> %s\n", (unsigned long long) pair.first, cname.c_str());
            ss << buf;
        }
        return JS_NewString(ctx, ss.str().c_str());
    }
    uint64_t addr = ParseObjAddr(ctx, argv[0]);
    if (!addr) return JS_NewString(ctx, "[!] Invalid address");

    JNIEnv* env = GetEnv();
    if (!env) return JS_NewString(ctx, "[!] JNIEnv not available");

    jobject targetObj = nullptr;

    // 1. Look up in observed objects registry
    {
        std::lock_guard<std::mutex> lk(g_observedMutex);
        auto it = g_observedObjects.find(addr);
        if (it != g_observedObjects.end() && it->second) {
            targetObj = it->second;
        }
    }

    // 2. Fallback: try decoding via PineNative
    if (!targetObj) {
        // Tagged JNI indirect ref check (low bits)
        if ((addr & 1) != 0) {
            void* decoded = PineNative_ToArtObject(env, reinterpret_cast<jobject>(addr));
            if (decoded) {
                targetObj = PineNative_ToJObject(env, decoded);
            }
        }
        // Direct mirror::Object* heap pointer check
        if (!targetObj && addr > 0x1000) {
            jobject ref = PineNative_ToJObject(env, reinterpret_cast<void*>(addr));
            if (ref) {
                jclass c = env->GetObjectClass(ref);
                if (c) {
                    env->DeleteLocalRef(c);
                    targetObj = ref;
                } else {
                    if (env->ExceptionCheck()) env->ExceptionClear();
                    env->DeleteLocalRef(ref);
                }
            }
        }
    }

    if (!targetObj) {
        char errBuf[128];
        snprintf(errBuf, sizeof(errBuf), "[!] Object at 0x%llx not found or inaccessible", (unsigned long long) addr);
        return JS_NewString(ctx, errBuf);
    }

    // Register into observed cache and add persistent JRef
    DoRegisterObservedObject(env, addr, targetObj);
    int handle = AddJRef(env, targetObj, addr, /*persistent=*/true);
    return CreateJRefValue(ctx, handle);
}

static JSValue JsJMethods(JSContext* ctx, JSValueConst, int argc, JSValueConst* argv) {
    if (argc < 1) return JS_UNDEFINED;
    int h = ExtractJRefHandle(ctx, argv[0]);
    jobject obj = GetJRef(h);
    JNIEnv* env = GetEnv();
    if (!obj || !env) return JS_UNDEFINED;

    jclass cls = env->GetObjectClass(obj);
    std::string cname = JavaClassName(env, cls);
    const ClassMembers* mem = LookupMembers(cname);
    if (!mem) {
        PrepareClassMembers(env, cls);
        mem = LookupMembers(cname);
    }

    JSValue arr = JS_NewArray(ctx);
    uint32_t idx = 0;
    if (mem) {
        for (const auto& pair : mem->methods) {
            for (const auto& m : pair.second) {
                std::string sig = pair.first + "(";
                for (size_t i = 0; i < m.params.size(); i++) {
                    if (i > 0) sig += ", ";
                    sig += m.params[i];
                }
                sig += ") -> " + m.ret;
                JS_SetPropertyUint32(ctx, arr, idx++, JS_NewString(ctx, sig.c_str()));
            }
        }
    }
    env->DeleteLocalRef(cls);
    return arr;
}

static JSValue JsJFields(JSContext* ctx, JSValueConst, int argc, JSValueConst* argv) {
    if (argc < 1) return JS_UNDEFINED;
    int h = ExtractJRefHandle(ctx, argv[0]);
    jobject obj = GetJRef(h);
    JNIEnv* env = GetEnv();
    if (!obj || !env) return JS_UNDEFINED;

    jclass cls = env->GetObjectClass(obj);
    std::string cname = JavaClassName(env, cls);
    const ClassMembers* mem = LookupMembers(cname);
    if (!mem) {
        PrepareClassMembers(env, cls);
        mem = LookupMembers(cname);
    }

    JSValue out = JS_NewObject(ctx);
    if (mem) {
        for (const auto& pair : mem->fields) {
            JSValue fval = ReadCachedField(ctx, env, obj, cls, pair.second);
            JS_SetPropertyStr(ctx, out, pair.first.c_str(), fval);
        }
    }
    env->DeleteLocalRef(cls);
    return out;
}

// JS: __native_jfget(handleOrClass, name): cached field value, a bound method
// callable (when the class was prepared), or a reflection fallback for fields.
static JSValue JsJFieldGet(JSContext* ctx, JSValueConst, int argc, JSValueConst* argv) {
    if (argc < 2) return JS_UNDEFINED;
    JNIEnv* env = GetEnv();
    if (!env) return JS_UNDEFINED;

    int h = ExtractJRefHandle(ctx, argv[0]);
    jobject obj = nullptr;
    jclass cls = nullptr;
    std::string cname;
    bool needDeleteCls = false;

    if (h >= 0) {
        obj = GetJRef(h);
        if (!obj) return JS_UNDEFINED;
        cls = env->GetObjectClass(obj);
        cname = JavaClassName(env, cls);
        needDeleteCls = true;
    } else if (JS_IsString(argv[0])) {
        const char* c = JS_ToCString(ctx, argv[0]);
        if (!c) return JS_UNDEFINED;
        cname = c;
        JS_FreeCString(ctx, c);
        cls = FindClassWithFallback(env, cname);
        needDeleteCls = true;
    } else {
        int64_t ptr = ParsePtr(ctx, argv[0]);
        if (ptr > 0x1000) {
            cls = reinterpret_cast<jclass>(ptr);
            cname = JavaClassName(env, cls);
        }
    }
    if (!cls) return JS_UNDEFINED;

    const char* name = JS_ToCString(ctx, argv[1]);
    if (!name) {
        if (needDeleteCls) env->DeleteLocalRef(cls);
        return JS_UNDEFINED;
    }

    const ClassMembers* mem = LookupMembers(cname);
    if (!mem) {
        PrepareClassMembers(env, cls);
        mem = LookupMembers(cname);
    }
    JSValue r = JS_UNDEFINED;
    if (mem) {
        auto fit = mem->fields.find(name);
        if (fit != mem->fields.end()) {
            if (obj || fit->second.isStatic) {
                r = ReadCachedField(ctx, env, obj, cls, fit->second);
            }
        } else if (mem->methods.count(name) && obj) {
            // Prepared method -> return a bound callable (obj.m(...)).
            JSValue data[2] = { JS_NewInt32(ctx, h), JS_NewString(ctx, name) };
            r = JS_NewCFunctionData(ctx, JsJMethodTrampoline, 0, 0, 2, data);
            JS_FreeValue(ctx, data[0]);
            JS_FreeValue(ctx, data[1]);
        }
    }
    if (JS_IsUndefined(r)) {
        // Fallback: search declared fields on cls and superclasses
        jclass cur = (jclass) env->NewLocalRef(cls);
        jstring fname = env->NewStringUTF(name);
        jobject field = nullptr;
        while (cur != nullptr && !field) {
            jmethodID gdf = env->GetMethodID(g_c_Class, "getDeclaredField", "(Ljava/lang/String;)Ljava/lang/reflect/Field;");
            if (gdf) {
                field = env->CallObjectMethod(cur, gdf, fname);
                if (env->ExceptionCheck()) { env->ExceptionClear(); field = nullptr; }
            }
            if (!field) {
                jclass parent = env->GetSuperclass(cur);
                env->DeleteLocalRef(cur);
                cur = parent;
            }
        }
        if (cur) env->DeleteLocalRef(cur);
        env->DeleteLocalRef(fname);

        if (field) {
            jmethodID setAcc = env->GetMethodID(g_c_Field, "setAccessible", "(Z)V");
            jmethodID get = env->GetMethodID(g_c_Field, "get", "(Ljava/lang/Object;)Ljava/lang/Object;");
            if (setAcc) { env->CallVoidMethod(field, setAcc, JNI_TRUE); if (env->ExceptionCheck()) env->ExceptionClear(); }
            if (get) {
                jobject val = env->CallObjectMethod(field, get, obj);
                if (env->ExceptionCheck()) env->ExceptionClear();
                r = JavaObjectToJsValue(ctx, env, val);
                if (val) env->DeleteLocalRef(val);
            }
            env->DeleteLocalRef(field);
        }
    }
    if (needDeleteCls) env->DeleteLocalRef(cls);
    JS_FreeCString(ctx, name);
    return r;
}

// JS: __native_jfset(handleOrClass, fieldName, value)
static JSValue JsJFieldSet(JSContext* ctx, JSValueConst, int argc, JSValueConst* argv) {
    if (argc < 3) return JS_FALSE;
    JNIEnv* env = GetEnv();
    if (!env) return JS_FALSE;

    int h = ExtractJRefHandle(ctx, argv[0]);
    jobject obj = nullptr;
    jclass cls = nullptr;
    std::string cname;
    bool needDeleteCls = false;

    if (h >= 0) {
        obj = GetJRef(h);
        if (!obj) return JS_FALSE;
        cls = env->GetObjectClass(obj);
        cname = JavaClassName(env, cls);
        needDeleteCls = true;
    } else if (JS_IsString(argv[0])) {
        const char* c = JS_ToCString(ctx, argv[0]);
        if (!c) return JS_FALSE;
        cname = c;
        JS_FreeCString(ctx, c);
        cls = FindClassWithFallback(env, cname);
        needDeleteCls = true;
    } else {
        int64_t ptr = ParsePtr(ctx, argv[0]);
        if (ptr > 0x1000) {
            cls = reinterpret_cast<jclass>(ptr);
            cname = JavaClassName(env, cls);
        }
    }
    if (!cls) return JS_FALSE;

    const char* name = JS_ToCString(ctx, argv[1]);
    if (!name) {
        if (needDeleteCls) env->DeleteLocalRef(cls);
        return JS_FALSE;
    }

    const ClassMembers* mem = LookupMembers(cname);
    if (!mem) {
        PrepareClassMembers(env, cls);
        mem = LookupMembers(cname);
    }
    bool ok = false;
    if (mem) {
        auto fit = mem->fields.find(name);
        if (fit != mem->fields.end()) {
            if (obj || fit->second.isStatic) {
                ok = WriteCachedField(ctx, env, obj, cls, fit->second, argv[2]);
            }
        }
    }
    if (!ok) {
        // Fallback: search declared fields on cls and superclasses
        jclass cur = (jclass) env->NewLocalRef(cls);
        jstring fname = env->NewStringUTF(name);
        jobject field = nullptr;
        while (cur != nullptr && !field) {
            jmethodID gdf = env->GetMethodID(g_c_Class, "getDeclaredField", "(Ljava/lang/String;)Ljava/lang/reflect/Field;");
            if (gdf) {
                field = env->CallObjectMethod(cur, gdf, fname);
                if (env->ExceptionCheck()) { env->ExceptionClear(); field = nullptr; }
            }
            if (!field) {
                jclass parent = env->GetSuperclass(cur);
                env->DeleteLocalRef(cur);
                cur = parent;
            }
        }
        if (cur) env->DeleteLocalRef(cur);
        env->DeleteLocalRef(fname);

        if (field) {
            jmethodID setAcc = env->GetMethodID(g_c_Field, "setAccessible", "(Z)V");
            jmethodID getType = env->GetMethodID(g_c_Field, "getType", "()Ljava/lang/Class;");
            jmethodID set = env->GetMethodID(g_c_Field, "set", "(Ljava/lang/Object;Ljava/lang/Object;)V");
            if (setAcc) { env->CallVoidMethod(field, setAcc, JNI_TRUE); if (env->ExceptionCheck()) env->ExceptionClear(); }
            if (getType && set) {
                jclass ftype = static_cast<jclass>(env->CallObjectMethod(field, getType));
                std::string tn = JavaClassName(env, ftype);
                jobject boxed = JsValueToJavaObject(env, ctx, argv[2], tn);
                env->CallVoidMethod(field, set, obj, boxed);
                if (env->ExceptionCheck()) env->ExceptionClear(); else ok = true;
                if (ftype) env->DeleteLocalRef(ftype);
                if (boxed) env->DeleteLocalRef(boxed);
            }
            env->DeleteLocalRef(field);
        }
    }
    if (needDeleteCls) env->DeleteLocalRef(cls);
    JS_FreeCString(ctx, name);
    return JS_NewBool(ctx, ok);
}

// JS: __native_jstr(handle) -> full DumpArtObject
static JSValue JsJRefStr(JSContext* ctx, JSValueConst, int argc, JSValueConst* argv) {
    if (argc < 1) return JS_UNDEFINED;
    int h = ExtractJRefHandle(ctx, argv[0]);
    jobject obj = GetJRef(h);
    JNIEnv* env = GetEnv();
    if (!obj || !env) return JS_NULL;
    uint64_t addr = GetJRefAddr(h);
    std::string dump = DumpArtObject(env, obj, addr);
    return JS_NewString(ctx, dump.c_str());
}

// JS: __native_jmembers(handle) -> array of string member names
static JSValue JsJMembers(JSContext* ctx, JSValueConst, int argc, JSValueConst* argv) {
    if (argc < 1) return JS_NewArray(ctx);
    int h = ExtractJRefHandle(ctx, argv[0]);
    jobject obj = GetJRef(h);
    JNIEnv* env = GetEnv();
    if (!obj || !env) return JS_NewArray(ctx);

    jclass cls = env->GetObjectClass(obj);
    std::string cname = JavaClassName(env, cls);
    const ClassMembers* mem = LookupMembers(cname);
    if (!mem) {
        PrepareClassMembers(env, cls);
        mem = LookupMembers(cname);
    }

    std::set<std::string> names;
    if (mem) {
        for (const auto& f : mem->fields) names.insert(f.first);
        for (const auto& m : mem->methods) names.insert(m.first);
    }
    names.insert("$dump");
    names.insert("$methods");
    names.insert("$fields");

    env->DeleteLocalRef(cls);

    JSValue arr = JS_NewArray(ctx);
    uint32_t idx = 0;
    for (const auto& n : names) {
        JS_SetPropertyUint32(ctx, arr, idx++, JS_NewString(ctx, n.c_str()));
    }
    return arr;
}

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

JSValue JsJavaHook(JSContext* ctx, JSValueConst /*this_val*/, int argc, JSValueConst* argv) {
    if (argc < 1) return JS_NewString(ctx, "Usage: jhook(artMethod, [callback], [className], [methodName], [sig])");
    int64_t ptr = ParsePtr(ctx, argv[0]);
    if (!ptr || ptr < 0x1000) return JS_NewString(ctx, "[!] Invalid method pointer");

    std::string optClass, optMethod, optSig;
    if (argc >= 3 && JS_IsString(argv[2])) {
        const char* s = JS_ToCString(ctx, argv[2]);
        if (s) { optClass = s; JS_FreeCString(ctx, s); }
    }
    if (argc >= 4 && JS_IsString(argv[3])) {
        const char* s = JS_ToCString(ctx, argv[3]);
        if (s) { optMethod = s; JS_FreeCString(ctx, s); }
    }
    if (argc >= 5 && JS_IsString(argv[4])) {
        const char* s = JS_ToCString(ctx, argv[4]);
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

    // Idempotent: re-hooking an ArtMethod that already has a live hook re-enters
    // the installed trampoline and crashes. Return the existing hook id instead.
    {
        std::lock_guard<std::mutex> lk(g_hooksMutex);
        for (size_t i = 0; i < g_activeHooks.size(); i++) {
            if (g_activeHooks[i].isHooked() &&
                reinterpret_cast<void*>(g_activeHooks[i].getArtMethod()) == reinterpret_cast<void*>(ptr)) {
                char resBuf[96];
                snprintf(resBuf, sizeof(resBuf), "Already hooked (id: %zu)", i);
                return JS_NewString(ctx, resBuf);
            }
        }
    }

    PI::HookHandle handle;
    if (argc < 2 || !JS_IsFunction(ctx, argv[1])) {
        // No callback -> default "call log" hook: Box-drawing call hierarchy with clear return packets.
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
    } else {
        // Keep the callback alive for the hook's lifetime; the deleter frees the
        // JSValue when the hook is removed (Pine destroys the std::function).
        auto cbGuard = std::make_shared<JSValue>(JS_DupValue(ctx, argv[1]));
        handle = m.hook([cbGuard](JNIEnv* cbEnv, PI::CallFrame& frame) {
            JSContext* jsctx = g_ctx;
            if (!jsctx) { frame.invokeOriginal(); return; }

            // JRef handles created during this callback are released at the end.
            size_t jrefBase;
            {
                std::lock_guard<std::mutex> lk(g_jrefMutex);
                jrefBase = g_jrefs.size();
            }
            if (cbEnv) cbEnv->PushLocalFrame(64);

            std::string entryLog = frame.class_name.empty()
                                       ? frame.getMethodName()
                                       : (frame.class_name + "." + frame.getMethodName());
            BroadcastLog("debug", "[hook] " + entryLog + " entered");

            bool overrideResult = false;
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
                    // JS decided the return value -> apply, skip original.
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
                    // Write back any mutated args (and log the changes).
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

            // Release JRef local refs created during this callback.
            PopJRefsTo(cbEnv, jrefBase);
            if (cbEnv) cbEnv->PopLocalFrame(nullptr);
        });
    }

    if (!handle.isHooked()) {
        return JS_NewString(ctx, "[!] Hook installation failed");
    }

    std::lock_guard<std::mutex> lk(g_hooksMutex);
    g_activeHooks.push_back(handle);
    size_t hookId = g_activeHooks.size() - 1;
    char resBuf[64];
    snprintf(resBuf, sizeof(resBuf), "Hook installed (id: %zu)", hookId);
    return JS_NewString(ctx, resBuf);
}

JSValue JsJavaUnhook(JSContext* ctx, JSValueConst /*this_val*/, int argc, JSValueConst* argv) {
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

JSValue JsJavaUnhookAll(JSContext* ctx, JSValueConst /*this_val*/, int /*argc*/, JSValueConst* /*argv*/) {
    size_t count = JavaUnhookAllCount();
    char resBuf[64];
    snprintf(resBuf, sizeof(resBuf), "Unhooked %zu methods", count);
    return JS_NewString(ctx, resBuf);
}

// ---------------------------------------------------------------------------
// Java.choose / choose(className, callbacksOrLimit) implementation
// Dual-engine: JVMTI iterate instances + Direct Heap Space Scanning fallback
// ---------------------------------------------------------------------------
typedef struct {
    uintptr_t start;
    uintptr_t end;
} HeapMemoryRange;

static std::vector<HeapMemoryRange> CollectDalvikHeapRanges() {
    std::vector<HeapMemoryRange> ranges;
    FILE* fp = fopen("/proc/self/maps", "r");
    if (!fp) return ranges;

    char line[512];
    while (fgets(line, sizeof(line), fp)) {
        if (strstr(line, "rw-p") &&
            (strstr(line, "[anon:dalvik-main space]") ||
             strstr(line, "[anon:dalvik-zygote space]") ||
             strstr(line, "[anon:dalvik-non moving space]") ||
             strstr(line, "[anon:dalvik-free list large object space]"))) {
            uintptr_t start = 0, end = 0;
            if (sscanf(line, "%lx-%lx", &start, &end) == 2 && start < end) {
                ranges.push_back({start, end});
            }
        }
    }
    fclose(fp);
    return ranges;
}

static std::vector<jobject> PerformHeapMemoryScan(JNIEnv* env, jclass targetCls, size_t maxCount) {
    std::vector<jobject> results;
    if (!env || !targetCls) return results;

    void* targetArtCls = PineNative_ToArtObject(env, targetCls);
    if (!targetArtCls) return results;

    auto ranges = CollectDalvikHeapRanges();
    if (ranges.empty()) return results;

    // Use Pine's Thread & SuspendVM infrastructure to protect GC while scanning
    pine::art::Thread* selfThread = pine::art::Thread::Current(env);
    alignas(16) char suspendCookie[128] = {};
    bool suspended = false;

    if (selfThread) {
        pine::Android::SuspendVM(suspendCookie, selfThread, "ArtPI-Choose");
        suspended = true;
    }

    const uint32_t targetKlassWord = static_cast<uint32_t>(reinterpret_cast<uintptr_t>(targetArtCls));

    for (const auto& r : ranges) {
        uintptr_t cur = (r.start + 7) & ~static_cast<uintptr_t>(7);
        uintptr_t end = r.end - 16; // ensure room for header

        while (cur < end) {
            uint32_t klassWord = *reinterpret_cast<const uint32_t*>(cur);
            if (klassWord == targetKlassWord) {
                // Potential match: check monitor word
                uint32_t monitorWord = *reinterpret_cast<const uint32_t*>(cur + 4);
                // If top bits indicate forwarding address, skip or resolve
                if ((monitorWord & (3u << 30)) != (3u << 30)) {
                    jobject lref = PineNative_ToJObject(env, reinterpret_cast<void*>(cur));
                    if (lref) {
                        jclass actualCls = env->GetObjectClass(lref);
                        if (actualCls) {
                            if (env->IsSameObject(actualCls, targetCls) || env->IsInstanceOf(lref, targetCls)) {
                                results.push_back(lref);
                            } else {
                                env->DeleteLocalRef(lref);
                            }
                            env->DeleteLocalRef(actualCls);
                        } else {
                            if (env->ExceptionCheck()) env->ExceptionClear();
                            env->DeleteLocalRef(lref);
                        }
                    }
                    if (results.size() >= maxCount) break;
                }
            }
            cur += 8; // ART heap objects are 8-byte aligned
        }
        if (results.size() >= maxCount) break;
    }

    if (suspended) {
        pine::Android::ResumeVM(suspendCookie);
    }

    return results;
}

static JSValue JsJavaChoose(JSContext* ctx, JSValueConst /*this_val*/, int argc, JSValueConst* argv) {
    if (argc < 1) {
        return JS_NewString(ctx, "Usage: Java.choose(className, { onMatch: function(instance){}, onComplete: function(){} })");
    }

    JNIEnv* env = GetEnv();
    if (!env) return JS_NewString(ctx, "[!] JNIEnv unavailable");

    std::string className;
    jclass targetCls = nullptr;
    bool needDeleteCls = false;

    if (JS_IsString(argv[0])) {
        const char* cstr = JS_ToCString(ctx, argv[0]);
        if (cstr) {
            className = cstr;
            JS_FreeCString(ctx, cstr);
            targetCls = FindClassWithFallback(env, className);
            needDeleteCls = true;
        }
    } else {
        int64_t ptr = ParsePtr(ctx, argv[0]);
        if (ptr != 0) {
            targetCls = reinterpret_cast<jclass>(ptr);
            className = JavaClassName(env, targetCls);
        }
    }

    if (!targetCls) {
        return JS_NewString(ctx, ("[!] Target class not found: " + className).c_str());
    }

    JSValue callbacks = (argc >= 2) ? argv[1] : JS_UNDEFINED;
    JSValue onMatch = JS_UNDEFINED;
    JSValue onComplete = JS_UNDEFINED;
    bool hasCallbacks = false;

    if (JS_IsObject(callbacks) && !JS_IsFunction(ctx, callbacks)) {
        onMatch = JS_GetPropertyStr(ctx, callbacks, "onMatch");
        onComplete = JS_GetPropertyStr(ctx, callbacks, "onComplete");
        hasCallbacks = JS_IsFunction(ctx, onMatch);
    } else if (JS_IsFunction(ctx, callbacks)) {
        onMatch = JS_DupValue(ctx, callbacks);
        hasCallbacks = true;
    }

    size_t limit = hasCallbacks ? 1000 : 50;

    std::vector<jobject> instances = PerformHeapMemoryScan(env, targetCls, limit);

    if (hasCallbacks) {
        size_t count = 0;
        for (jobject obj : instances) {
            void* artObj = PineNative_ToArtObject(env, obj);
            uint64_t addr = artObj ? reinterpret_cast<uintptr_t>(artObj) : reinterpret_cast<uintptr_t>(obj);
            DoRegisterObservedObject(env, addr, obj);
            int handle = AddJRef(env, obj, addr, /*persistent=*/true);
            JSValue jrefVal = CreateJRefValue(ctx, handle);

            JSValue ret = JS_Call(ctx, onMatch, JS_UNDEFINED, 1, &jrefVal);
            JS_FreeValue(ctx, jrefVal);

            count++;
            bool stop = false;
            if (JS_IsString(ret)) {
                const char* retStr = JS_ToCString(ctx, ret);
                if (retStr && strcmp(retStr, "stop") == 0) stop = true;
                if (retStr) JS_FreeCString(ctx, retStr);
            }
            JS_FreeValue(ctx, ret);
            if (stop) break;
        }

        if (JS_IsFunction(ctx, onComplete)) {
            JSValue compRet = JS_Call(ctx, onComplete, JS_UNDEFINED, 0, nullptr);
            JS_FreeValue(ctx, compRet);
        }
        if (JS_IsFunction(ctx, onMatch)) JS_FreeValue(ctx, onMatch);
        if (JS_IsFunction(ctx, onComplete)) JS_FreeValue(ctx, onComplete);

        for (jobject obj : instances) env->DeleteLocalRef(obj);
        if (needDeleteCls) env->DeleteLocalRef(targetCls);

        char buf[64];
        snprintf(buf, sizeof(buf), "[*] Scanned %zu instance(s)", count);
        return JS_NewString(ctx, buf);
    }

    // CLI Interactive Mode: return formatted string listing instances
    std::ostringstream ss;
    if (instances.empty()) {
        ss << "[*] No active instances found for class: " << className;
    } else {
        ss << "Found " << instances.size() << " instance(s) of " << className << ":\n";
        for (size_t i = 0; i < instances.size(); i++) {
            jobject obj = instances[i];
            void* artObj = PineNative_ToArtObject(env, obj);
            uint64_t addr = artObj ? reinterpret_cast<uintptr_t>(artObj) : reinterpret_cast<uintptr_t>(obj);
            DoRegisterObservedObject(env, addr, obj);
            AddJRef(env, obj, addr, /*persistent=*/true);

            char buf[128];
            snprintf(buf, sizeof(buf), "  [%2zu] %s@0x%llx\n", i, SimplifyJavaType(className).c_str(), (unsigned long long)addr);
            ss << buf;
            env->DeleteLocalRef(obj);
        }
    }

    if (needDeleteCls) env->DeleteLocalRef(targetCls);
    return JS_NewString(ctx, ss.str().c_str());
}

// ===========================================================================
// UI Hierarchy & Click Event Inspection
// ===========================================================================
static jobject GetWindowManagerViews(JNIEnv* env) {
    if (!env) return nullptr;
    jclass wmgCls = FindClassWithFallback(env, "android.view.WindowManagerGlobal");
    if (!wmgCls) return nullptr;
    jmethodID getInstanceMid = env->GetStaticMethodID(wmgCls, "getInstance", "()Landroid/view/WindowManagerGlobal;");
    if (env->ExceptionCheck()) { env->ExceptionClear(); getInstanceMid = nullptr; }
    if (!getInstanceMid) { env->DeleteLocalRef(wmgCls); return nullptr; }
    jobject wmg = env->CallStaticObjectMethod(wmgCls, getInstanceMid);
    if (env->ExceptionCheck()) { env->ExceptionClear(); wmg = nullptr; }
    if (!wmg) { env->DeleteLocalRef(wmgCls); return nullptr; }
    jfieldID mViewsFid = env->GetFieldID(wmgCls, "mViews", "Ljava/util/ArrayList;");
    if (env->ExceptionCheck()) { env->ExceptionClear(); mViewsFid = nullptr; }
    jobject mViews = mViewsFid ? env->GetObjectField(wmg, mViewsFid) : nullptr;
    if (env->ExceptionCheck()) { env->ExceptionClear(); mViews = nullptr; }
    env->DeleteLocalRef(wmg);
    env->DeleteLocalRef(wmgCls);
    return mViews;
}

struct ViewNode {
    jobject view = nullptr;
    std::string className;
    std::string simpleName;
    int32_t id = 0;
    std::string idName;
    std::string text;
    std::string contentDesc;
    int32_t left = 0, top = 0, right = 0, bottom = 0;
    int32_t width = 0, height = 0;
    int32_t cx = 0, cy = 0;
    int32_t visibility = 0;
    bool isClickable = false;
    bool isEnabled = true;
    std::string listenerClassName;
    uint64_t listenerArtMethod = 0;
    std::string longClickListenerClassName;
    uint64_t longClickListenerArtMethod = 0;
    int depth = 0;
    std::vector<ViewNode> children;
};

struct UiFilterOptions {
    std::string pattern;
    std::string text;
    std::string id;
    std::string className;
    bool clickableOnly = false;
    bool visibleOnly = false;
    int maxDepth = 1000;

    bool hasFilter() const {
        return !pattern.empty() || !text.empty() || !id.empty() || !className.empty() || clickableOnly || visibleOnly;
    }
};

static bool ContainsCaseInsensitive(const std::string& str, const std::string& sub) {
    if (sub.empty()) return true;
    auto it = std::search(str.begin(), str.end(), sub.begin(), sub.end(),
                          [](char a, char b) { return tolower(a) == tolower(b); });
    return it != str.end();
}

static bool NodeMatchesFilter(const ViewNode& node, const UiFilterOptions& opt) {
    if (opt.clickableOnly && !node.isClickable && node.listenerClassName.empty() && node.longClickListenerClassName.empty()) return false;
    if (opt.visibleOnly && node.visibility != 0) return false;

    if (!opt.text.empty() && !ContainsCaseInsensitive(node.text, opt.text)) return false;
    if (!opt.id.empty() && !ContainsCaseInsensitive(node.idName, opt.id)) return false;
    if (!opt.className.empty() && !ContainsCaseInsensitive(node.simpleName, opt.className) && !ContainsCaseInsensitive(node.className, opt.className)) return false;

    if (!opt.pattern.empty()) {
        if (ContainsCaseInsensitive(node.text, opt.pattern)) return true;
        if (ContainsCaseInsensitive(node.idName, opt.pattern)) return true;
        if (ContainsCaseInsensitive(node.simpleName, opt.pattern)) return true;
        if (ContainsCaseInsensitive(node.className, opt.pattern)) return true;
        if (ContainsCaseInsensitive(node.listenerClassName, opt.pattern)) return true;
        if (ContainsCaseInsensitive(node.longClickListenerClassName, opt.pattern)) return true;
        if (ContainsCaseInsensitive(node.contentDesc, opt.pattern)) return true;
        char idBuf[32];
        snprintf(idBuf, sizeof(idBuf), "0x%x", node.id);
        if (ContainsCaseInsensitive(idBuf, opt.pattern)) return true;
        return false;
    }
    return true;
}

static bool HasMatchingDescendant(const ViewNode& node, const UiFilterOptions& opt) {
    for (const auto& child : node.children) {
        if (NodeMatchesFilter(child, opt) || HasMatchingDescendant(child, opt)) {
            return true;
        }
    }
    return false;
}

static UiFilterOptions ParseUiFilterOptions(JSContext* ctx, int argc, JSValueConst* argv) {
    UiFilterOptions opt;
    if (argc <= 0 || JS_IsUndefined(argv[0]) || JS_IsNull(argv[0])) return opt;

    if (JS_IsString(argv[0])) {
        const char* p = JS_ToCString(ctx, argv[0]);
        if (p) { opt.pattern = p; JS_FreeCString(ctx, p); }
    } else if (JS_IsObject(argv[0])) {
        JSValue patVal = JS_GetPropertyStr(ctx, argv[0], "pattern");
        if (JS_IsString(patVal)) { const char* s = JS_ToCString(ctx, patVal); if (s) { opt.pattern = s; JS_FreeCString(ctx, s); } }
        JS_FreeValue(ctx, patVal);

        JSValue textVal = JS_GetPropertyStr(ctx, argv[0], "text");
        if (JS_IsString(textVal)) { const char* s = JS_ToCString(ctx, textVal); if (s) { opt.text = s; JS_FreeCString(ctx, s); } }
        JS_FreeValue(ctx, textVal);

        JSValue idVal = JS_GetPropertyStr(ctx, argv[0], "id");
        if (JS_IsString(idVal)) { const char* s = JS_ToCString(ctx, idVal); if (s) { opt.id = s; JS_FreeCString(ctx, s); } }
        JS_FreeValue(ctx, idVal);

        JSValue clsVal = JS_GetPropertyStr(ctx, argv[0], "className");
        if (JS_IsString(clsVal)) { const char* s = JS_ToCString(ctx, clsVal); if (s) { opt.className = s; JS_FreeCString(ctx, s); } }
        JS_FreeValue(ctx, clsVal);

        JSValue clkVal = JS_GetPropertyStr(ctx, argv[0], "clickable");
        if (JS_IsBool(clkVal)) opt.clickableOnly = JS_ToBool(ctx, clkVal);
        JS_FreeValue(ctx, clkVal);

        JSValue visVal = JS_GetPropertyStr(ctx, argv[0], "visible");
        if (JS_IsBool(visVal)) opt.visibleOnly = JS_ToBool(ctx, visVal);
        JS_FreeValue(ctx, visVal);

        JSValue depVal = JS_GetPropertyStr(ctx, argv[0], "maxDepth");
        if (JS_IsNumber(depVal)) JS_ToInt32(ctx, &opt.maxDepth, depVal);
        JS_FreeValue(ctx, depVal);
    }
    return opt;
}

static void TraverseViewTree(JNIEnv* env, jobject v, int depth, ViewNode& node,
                             jclass viewCls, jclass viewGroupCls, jclass textViewCls,
                             jclass resCls, jmethodID getIdMid, jmethodID getVisMid,
                             jmethodID isClickableMid, jmethodID isEnabledMid,
                             jmethodID getWidthMid, jmethodID getHeightMid,
                             jmethodID getLocMid, jmethodID getResMid, jmethodID getEntryNameMid,
                             jmethodID getContentDescMid, jfieldID mListenerInfoFid,
                             jclass liCls, jfieldID liOnClickFid, jfieldID liOnLongClickFid,
                             jmethodID getChildCountMid, jmethodID getChildAtMid,
                             jmethodID getTextMid, jmethodID csToStringMid,
                             jintArray locArr, bool keepViewRefs) {
    if (!env || !v) return;
    node.depth = depth;
    if (keepViewRefs) {
        node.view = env->NewLocalRef(v);
    }

    jclass cls = env->GetObjectClass(v);
    node.className = JavaClassName(env, cls);
    node.simpleName = SimplifyJavaType(node.className);
    env->DeleteLocalRef(cls);

    if (getIdMid) {
        node.id = env->CallIntMethod(v, getIdMid);
        if (env->ExceptionCheck()) env->ExceptionClear();
    }
    if (getVisMid) {
        node.visibility = env->CallIntMethod(v, getVisMid);
        if (env->ExceptionCheck()) env->ExceptionClear();
    }
    if (isClickableMid) {
        node.isClickable = env->CallBooleanMethod(v, isClickableMid) != 0;
        if (env->ExceptionCheck()) env->ExceptionClear();
    }
    if (isEnabledMid) {
        node.isEnabled = env->CallBooleanMethod(v, isEnabledMid) != 0;
        if (env->ExceptionCheck()) env->ExceptionClear();
    }
    if (getWidthMid) {
        node.width = env->CallIntMethod(v, getWidthMid);
        if (env->ExceptionCheck()) env->ExceptionClear();
    }
    if (getHeightMid) {
        node.height = env->CallIntMethod(v, getHeightMid);
        if (env->ExceptionCheck()) env->ExceptionClear();
    }
    if (getLocMid && locArr) {
        env->CallVoidMethod(v, getLocMid, locArr);
        if (env->ExceptionCheck()) env->ExceptionClear();
        jint locBuf[2] = {0, 0};
        env->GetIntArrayRegion(locArr, 0, 2, locBuf);
        node.left = locBuf[0];
        node.top = locBuf[1];
        node.right = node.left + node.width;
        node.bottom = node.top + node.height;
        node.cx = node.left + node.width / 2;
        node.cy = node.top + node.height / 2;
    }

    if (node.id > 0 && node.id != -1 && getResMid && getEntryNameMid) {
        jobject res = env->CallObjectMethod(v, getResMid);
        if (env->ExceptionCheck()) env->ExceptionClear();
        if (res) {
            jstring nameJ = (jstring) env->CallObjectMethod(res, getEntryNameMid, node.id);
            if (env->ExceptionCheck()) {
                env->ExceptionClear();
            } else if (nameJ) {
                const char* s = env->GetStringUTFChars(nameJ, nullptr);
                if (s) {
                    node.idName = std::string("id/") + s;
                    env->ReleaseStringUTFChars(nameJ, s);
                }
                env->DeleteLocalRef(nameJ);
            }
            env->DeleteLocalRef(res);
        }
    }

    if (textViewCls && env->IsInstanceOf(v, textViewCls) && getTextMid) {
        jobject cs = env->CallObjectMethod(v, getTextMid);
        if (env->ExceptionCheck()) env->ExceptionClear();
        if (cs) {
            if (csToStringMid) {
                jstring ts = (jstring) env->CallObjectMethod(cs, csToStringMid);
                if (env->ExceptionCheck()) env->ExceptionClear();
                if (ts) {
                    const char* s = env->GetStringUTFChars(ts, nullptr);
                    if (s) {
                        node.text = s;
                        env->ReleaseStringUTFChars(ts, s);
                    }
                    env->DeleteLocalRef(ts);
                }
            }
            env->DeleteLocalRef(cs);
        }
    }

    if (getContentDescMid) {
        jobject cd = env->CallObjectMethod(v, getContentDescMid);
        if (env->ExceptionCheck()) env->ExceptionClear();
        if (cd) {
            if (csToStringMid) {
                jstring ts = (jstring) env->CallObjectMethod(cd, csToStringMid);
                if (env->ExceptionCheck()) env->ExceptionClear();
                if (ts) {
                    const char* s = env->GetStringUTFChars(ts, nullptr);
                    if (s) {
                        node.contentDesc = s;
                        env->ReleaseStringUTFChars(ts, s);
                    }
                    env->DeleteLocalRef(ts);
                }
            }
            env->DeleteLocalRef(cd);
        }
    }

    if (mListenerInfoFid) {
        jobject li = env->GetObjectField(v, mListenerInfoFid);
        if (env->ExceptionCheck()) env->ExceptionClear();
        if (li) {
            if (liOnClickFid) {
                jobject l = env->GetObjectField(li, liOnClickFid);
                if (env->ExceptionCheck()) env->ExceptionClear();
                if (l) {
                    jclass lCls = env->GetObjectClass(l);
                    node.listenerClassName = JavaClassName(env, lCls);
                    PI::Method pm = PI::resolve(env, lCls, "onClick", "(Landroid/view/View;)V");
                    if (pm.isValid()) {
                        node.listenerArtMethod = reinterpret_cast<uintptr_t>(pm.getArtMethod());
                    }
                    env->DeleteLocalRef(lCls);
                    env->DeleteLocalRef(l);
                }
            }
            if (liOnLongClickFid) {
                jobject ll = env->GetObjectField(li, liOnLongClickFid);
                if (env->ExceptionCheck()) env->ExceptionClear();
                if (ll) {
                    jclass llCls = env->GetObjectClass(ll);
                    node.longClickListenerClassName = JavaClassName(env, llCls);
                    PI::Method pm = PI::resolve(env, llCls, "onLongClick", "(Landroid/view/View;)Z");
                    if (pm.isValid()) {
                        node.longClickListenerArtMethod = reinterpret_cast<uintptr_t>(pm.getArtMethod());
                    }
                    env->DeleteLocalRef(llCls);
                    env->DeleteLocalRef(ll);
                }
            }
            env->DeleteLocalRef(li);
        }
    }

    if (viewGroupCls && env->IsInstanceOf(v, viewGroupCls) && getChildCountMid && getChildAtMid) {
        int childCount = env->CallIntMethod(v, getChildCountMid);
        if (env->ExceptionCheck()) env->ExceptionClear();
        for (int i = 0; i < childCount; i++) {
            jobject child = env->CallObjectMethod(v, getChildAtMid, i);
            if (env->ExceptionCheck()) { env->ExceptionClear(); continue; }
            if (child) {
                ViewNode childNode;
                TraverseViewTree(env, child, depth + 1, childNode,
                                 viewCls, viewGroupCls, textViewCls, resCls,
                                 getIdMid, getVisMid, isClickableMid, isEnabledMid,
                                 getWidthMid, getHeightMid, getLocMid, getResMid, getEntryNameMid,
                                 getContentDescMid, mListenerInfoFid, liCls, liOnClickFid, liOnLongClickFid,
                                 getChildCountMid, getChildAtMid, getTextMid,
                                 csToStringMid, locArr, keepViewRefs);
                node.children.push_back(std::move(childNode));
                env->DeleteLocalRef(child);
            }
        }
    }
}

static void FormatViewTree(const ViewNode& v, const std::string& prefix, bool isLast,
                           std::ostringstream& ss, const UiFilterOptions& opt) {
    bool hasFilt = opt.hasFilter();
    bool selfMatch = NodeMatchesFilter(v, opt);
    bool childMatch = hasFilt && HasMatchingDescendant(v, opt);

    if (hasFilt && !selfMatch && !childMatch) return;

    std::string branch = prefix.empty() ? "" : (prefix + (isLast ? "└─ " : "├─ "));
    ss << branch << v.simpleName;
    if (!v.idName.empty()) {
        ss << " " << v.idName;
    } else if (v.id > 0) {
        char idBuf[32];
        snprintf(idBuf, sizeof(idBuf), " #0x%x", v.id);
        ss << idBuf;
    }
    if (!v.text.empty()) {
        std::string t = v.text;
        if (t.size() > 32) t = t.substr(0, 30) + "...";
        for (char& c : t) if (c == '\n' || c == '\r') c = ' ';
        ss << " \"" << t << "\"";
    }
    char boundsBuf[96];
    snprintf(boundsBuf, sizeof(boundsBuf), " [%d, %d, %d, %d] center=(%d, %d)",
             v.left, v.top, v.right, v.bottom, v.cx, v.cy);
    ss << boundsBuf;

    if (v.visibility != 0) {
        ss << (v.visibility == 4 ? " [INVISIBLE]" : " [GONE]");
    }
    if (v.isClickable || !v.listenerClassName.empty()) {
        ss << " [CLICKABLE]";
    }
    if (!v.isEnabled) {
        ss << " [DISABLED]";
    }
    if (!v.contentDesc.empty()) {
        ss << " desc=\"" << v.contentDesc << "\"";
    }
    if (hasFilt && selfMatch) {
        ss << " [★ MATCH]";
    }
    ss << "\n";

    if (!v.listenerClassName.empty()) {
        std::string nextPrefix = prefix.empty() ? "  " : (prefix + (isLast ? "    " : "│   "));
        ss << nextPrefix << "└─ ClickListener: " << v.listenerClassName;
        if (v.listenerArtMethod) {
            char artBuf[32];
            snprintf(artBuf, sizeof(artBuf), " (ArtMethod=0x%llx)", (unsigned long long) v.listenerArtMethod);
            ss << artBuf;
        }
        ss << "\n";
    }

    if (!v.longClickListenerClassName.empty()) {
        std::string nextPrefix = prefix.empty() ? "  " : (prefix + (isLast ? "    " : "│   "));
        ss << nextPrefix << "└─ LongClickListener: " << v.longClickListenerClassName;
        if (v.longClickListenerArtMethod) {
            char artBuf[32];
            snprintf(artBuf, sizeof(artBuf), " (ArtMethod=0x%llx)", (unsigned long long) v.longClickListenerArtMethod);
            ss << artBuf;
        }
        ss << "\n";
    }

    if (v.depth >= opt.maxDepth) return;

    std::vector<const ViewNode*> visibleChildren;
    for (const auto& child : v.children) {
        if (!hasFilt || NodeMatchesFilter(child, opt) || HasMatchingDescendant(child, opt)) {
            visibleChildren.push_back(&child);
        }
    }

    std::string childPrefix = prefix.empty() ? "  " : (prefix + (isLast ? "    " : "│   "));
    for (size_t i = 0; i < visibleChildren.size(); i++) {
        FormatViewTree(*visibleChildren[i], childPrefix, i + 1 == visibleChildren.size(), ss, opt);
    }
}

static bool DispatchTouchEventPair(JNIEnv* env, jobject decorView, float x, float y) {
    if (!env || !decorView) return false;
    jclass sysClockCls = env->FindClass("android/os/SystemClock");
    jmethodID uptimeMid = sysClockCls ? env->GetStaticMethodID(sysClockCls, "uptimeMillis", "()J") : nullptr;
    jlong now = uptimeMid ? env->CallStaticLongMethod(sysClockCls, uptimeMid) : 0;
    if (env->ExceptionCheck()) env->ExceptionClear();

    jclass motionEventCls = env->FindClass("android/view/MotionEvent");
    jmethodID obtainMid = motionEventCls ? env->GetStaticMethodID(motionEventCls, "obtain", "(JJIFFI)Landroid/view/MotionEvent;") : nullptr;
    if (env->ExceptionCheck()) env->ExceptionClear();
    if (!obtainMid) {
        if (motionEventCls) env->DeleteLocalRef(motionEventCls);
        if (sysClockCls) env->DeleteLocalRef(sysClockCls);
        return false;
    }

    jclass viewCls = env->FindClass("android/view/View");
    jmethodID dispatchMid = viewCls ? env->GetMethodID(viewCls, "dispatchTouchEvent", "(Landroid/view/MotionEvent;)Z") : nullptr;
    jmethodID recycleMid = motionEventCls ? env->GetMethodID(motionEventCls, "recycle", "()V") : nullptr;
    if (env->ExceptionCheck()) env->ExceptionClear();

    // ACTION_DOWN = 0
    jobject downEv = env->CallStaticObjectMethod(motionEventCls, obtainMid, now, now, 0, x, y, 0);
    if (env->ExceptionCheck()) env->ExceptionClear();
    if (downEv && dispatchMid) {
        env->CallBooleanMethod(decorView, dispatchMid, downEv);
        if (env->ExceptionCheck()) env->ExceptionClear();
        if (recycleMid) env->CallVoidMethod(downEv, recycleMid);
        env->DeleteLocalRef(downEv);
    }

    // ACTION_UP = 1 (40ms later)
    jobject upEv = env->CallStaticObjectMethod(motionEventCls, obtainMid, now, now + 40, 1, x, y, 0);
    if (env->ExceptionCheck()) env->ExceptionClear();
    if (upEv && dispatchMid) {
        env->CallBooleanMethod(decorView, dispatchMid, upEv);
        if (env->ExceptionCheck()) env->ExceptionClear();
        if (recycleMid) env->CallVoidMethod(upEv, recycleMid);
        env->DeleteLocalRef(upEv);
    }

    if (viewCls) env->DeleteLocalRef(viewCls);
    if (motionEventCls) env->DeleteLocalRef(motionEventCls);
    if (sysClockCls) env->DeleteLocalRef(sysClockCls);
    return true;
}

static bool DispatchTouchSequence(JNIEnv* env, jobject decorView,
                                  float x1, float y1, float x2, float y2, int durationMs) {
    if (!env || !decorView) return false;
    jclass sysClockCls = env->FindClass("android/os/SystemClock");
    jmethodID uptimeMid = sysClockCls ? env->GetStaticMethodID(sysClockCls, "uptimeMillis", "()J") : nullptr;
    jlong downTime = uptimeMid ? env->CallStaticLongMethod(sysClockCls, uptimeMid) : 0;
    if (env->ExceptionCheck()) env->ExceptionClear();

    jclass motionEventCls = env->FindClass("android/view/MotionEvent");
    jmethodID obtainMid = motionEventCls ? env->GetStaticMethodID(motionEventCls, "obtain", "(JJIFFI)Landroid/view/MotionEvent;") : nullptr;
    jclass viewCls = env->FindClass("android/view/View");
    jmethodID dispatchMid = viewCls ? env->GetMethodID(viewCls, "dispatchTouchEvent", "(Landroid/view/MotionEvent;)Z") : nullptr;
    jmethodID recycleMid = motionEventCls ? env->GetMethodID(motionEventCls, "recycle", "()V") : nullptr;

    if (!obtainMid || !dispatchMid) {
        if (viewCls) env->DeleteLocalRef(viewCls);
        if (motionEventCls) env->DeleteLocalRef(motionEventCls);
        if (sysClockCls) env->DeleteLocalRef(sysClockCls);
        return false;
    }

    // ACTION_DOWN = 0
    jobject downEv = env->CallStaticObjectMethod(motionEventCls, obtainMid, downTime, downTime, 0, x1, y1, 0);
    if (env->ExceptionCheck()) env->ExceptionClear();
    if (downEv) {
        env->CallBooleanMethod(decorView, dispatchMid, downEv);
        if (env->ExceptionCheck()) env->ExceptionClear();
        if (recycleMid) env->CallVoidMethod(downEv, recycleMid);
        env->DeleteLocalRef(downEv);
    }

    // Intermediate ACTION_MOVEs
    int steps = 10;
    int totalMs = durationMs > 0 ? durationMs : 250;
    int stepDelay = totalMs / steps;
    if (stepDelay < 5) stepDelay = 5;

    for (int i = 1; i <= steps; i++) {
        float factor = static_cast<float>(i) / static_cast<float>(steps);
        float curX = x1 + (x2 - x1) * factor;
        float curY = y1 + (y2 - y1) * factor;
        jlong curTime = downTime + i * stepDelay;
        // ACTION_MOVE = 2
        jobject moveEv = env->CallStaticObjectMethod(motionEventCls, obtainMid, downTime, curTime, 2, curX, curY, 0);
        if (env->ExceptionCheck()) env->ExceptionClear();
        if (moveEv) {
            env->CallBooleanMethod(decorView, dispatchMid, moveEv);
            if (env->ExceptionCheck()) env->ExceptionClear();
            if (recycleMid) env->CallVoidMethod(moveEv, recycleMid);
            env->DeleteLocalRef(moveEv);
        }
        usleep(stepDelay * 1000);
    }

    // ACTION_UP = 1
    jlong upTime = downTime + totalMs;
    jobject upEv = env->CallStaticObjectMethod(motionEventCls, obtainMid, downTime, upTime, 1, x2, y2, 0);
    if (env->ExceptionCheck()) env->ExceptionClear();
    if (upEv) {
        env->CallBooleanMethod(decorView, dispatchMid, upEv);
        if (env->ExceptionCheck()) env->ExceptionClear();
        if (recycleMid) env->CallVoidMethod(upEv, recycleMid);
        env->DeleteLocalRef(upEv);
    }

    if (viewCls) env->DeleteLocalRef(viewCls);
    if (motionEventCls) env->DeleteLocalRef(motionEventCls);
    if (sysClockCls) env->DeleteLocalRef(sysClockCls);
    return true;
}

static void FlattenViewNodes(JNIEnv* env, JSContext* ctx, const ViewNode& node,
                             const UiFilterOptions& opt, JSValue arr, uint32_t& idx) {
    if (NodeMatchesFilter(node, opt)) {
        JSValue item = JS_NewObject(ctx);
        if (node.view) {
            void* artObj = PineNative_ToArtObject(env, node.view);
            uint64_t addr = artObj ? reinterpret_cast<uintptr_t>(artObj) : reinterpret_cast<uintptr_t>(node.view);
            DoRegisterObservedObject(env, addr, node.view);
            int h = AddJRef(env, node.view, addr, /*persistent=*/true);
            JS_SetPropertyStr(ctx, item, "view", CreateJRefValue(ctx, h));
        } else {
            JS_SetPropertyStr(ctx, item, "view", JS_NULL);
        }
        JS_SetPropertyStr(ctx, item, "className", JS_NewString(ctx, node.className.c_str()));
        JS_SetPropertyStr(ctx, item, "simpleName", JS_NewString(ctx, node.simpleName.c_str()));
        JS_SetPropertyStr(ctx, item, "id", JS_NewInt32(ctx, node.id));
        JS_SetPropertyStr(ctx, item, "idName", JS_NewString(ctx, node.idName.c_str()));
        JS_SetPropertyStr(ctx, item, "text", JS_NewString(ctx, node.text.c_str()));
        JS_SetPropertyStr(ctx, item, "contentDesc", JS_NewString(ctx, node.contentDesc.c_str()));
        JS_SetPropertyStr(ctx, item, "clickable", JS_NewBool(ctx, node.isClickable || !node.listenerClassName.empty()));
        JS_SetPropertyStr(ctx, item, "enabled", JS_NewBool(ctx, node.isEnabled));
        JS_SetPropertyStr(ctx, item, "visibility", JS_NewInt32(ctx, node.visibility));

        JSValue b = JS_NewObject(ctx);
        JS_SetPropertyStr(ctx, b, "left", JS_NewInt32(ctx, node.left));
        JS_SetPropertyStr(ctx, b, "top", JS_NewInt32(ctx, node.top));
        JS_SetPropertyStr(ctx, b, "right", JS_NewInt32(ctx, node.right));
        JS_SetPropertyStr(ctx, b, "bottom", JS_NewInt32(ctx, node.bottom));
        JS_SetPropertyStr(ctx, b, "width", JS_NewInt32(ctx, node.width));
        JS_SetPropertyStr(ctx, b, "height", JS_NewInt32(ctx, node.height));
        JS_SetPropertyStr(ctx, b, "cx", JS_NewInt32(ctx, node.cx));
        JS_SetPropertyStr(ctx, b, "cy", JS_NewInt32(ctx, node.cy));
        JS_SetPropertyStr(ctx, item, "bounds", b);

        if (!node.listenerClassName.empty()) {
            JSValue l = JS_NewObject(ctx);
            JS_SetPropertyStr(ctx, l, "className", JS_NewString(ctx, node.listenerClassName.c_str()));
            if (node.listenerArtMethod) {
                JS_SetPropertyStr(ctx, l, "artMethod", JS_NewBigInt64(ctx, node.listenerArtMethod));
            }
            JS_SetPropertyStr(ctx, item, "clickListener", l);
        } else {
            JS_SetPropertyStr(ctx, item, "clickListener", JS_NULL);
        }

        if (!node.longClickListenerClassName.empty()) {
            JSValue ll = JS_NewObject(ctx);
            JS_SetPropertyStr(ctx, ll, "className", JS_NewString(ctx, node.longClickListenerClassName.c_str()));
            if (node.longClickListenerArtMethod) {
                JS_SetPropertyStr(ctx, ll, "artMethod", JS_NewBigInt64(ctx, node.longClickListenerArtMethod));
            }
            JS_SetPropertyStr(ctx, item, "longClickListener", ll);
        } else {
            JS_SetPropertyStr(ctx, item, "longClickListener", JS_NULL);
        }

        const char* kClickFn = "(function(){ return function(){ return UI.click(this); }; })()";
        JS_SetPropertyStr(ctx, item, "click", JS_Eval(ctx, kClickFn, strlen(kClickFn), "<click_fn>", JS_EVAL_TYPE_GLOBAL));

        const char* kLongClickFn = "(function(){ return function(){ return UI.longClick(this); }; })()";
        JS_SetPropertyStr(ctx, item, "longClick", JS_Eval(ctx, kLongClickFn, strlen(kLongClickFn), "<long_click_fn>", JS_EVAL_TYPE_GLOBAL));

        const char* kSetTextFn = "(function(){ return function(txt){ return UI.setText(this, txt); }; })()";
        JS_SetPropertyStr(ctx, item, "setText", JS_Eval(ctx, kSetTextFn, strlen(kSetTextFn), "<set_text_fn>", JS_EVAL_TYPE_GLOBAL));

        const char* kStrFn = "(function(){ return function(){ var idStr = this.idName ? (' ' + this.idName) : ''; var txt = this.text ? (' \"' + this.text + '\"') : ''; var clk = this.clickListener ? (' [Click: ' + this.clickListener.className + ']') : ''; return '[View ' + this.simpleName + idStr + txt + ' bounds=[' + this.bounds.left + ',' + this.bounds.top + ',' + this.bounds.right + ',' + this.bounds.bottom + ']' + clk + ']'; }; })()";
        JS_SetPropertyStr(ctx, item, "toString", JS_Eval(ctx, kStrFn, strlen(kStrFn), "<view_str_fn>", JS_EVAL_TYPE_GLOBAL));

        JS_SetPropertyUint32(ctx, arr, idx++, item);
    }

    for (const auto& child : node.children) {
        FlattenViewNodes(env, ctx, child, opt, arr, idx);
    }
}

static void FreeViewNodeTree(JNIEnv* env, ViewNode& node) {
    if (node.view) {
        env->DeleteLocalRef(node.view);
        node.view = nullptr;
    }
    for (auto& ch : node.children) {
        FreeViewNodeTree(env, ch);
    }
}

static jobject FindDeepestChildAt(JNIEnv* env, jobject parent, int x, int y,
                                  jclass viewCls, jclass viewGroupCls,
                                  jmethodID getVisMid, jmethodID getWidthMid,
                                  jmethodID getHeightMid, jmethodID getLocMid,
                                  jmethodID getChildCountMid, jmethodID getChildAtMid,
                                  jintArray locArr) {
    if (!env || !parent) return nullptr;
    if (getVisMid && env->CallIntMethod(parent, getVisMid) != 0) return nullptr;
    if (env->ExceptionCheck()) { env->ExceptionClear(); return nullptr; }

    env->CallVoidMethod(parent, getLocMid, locArr);
    if (env->ExceptionCheck()) { env->ExceptionClear(); return nullptr; }
    jint loc[2] = {0, 0};
    env->GetIntArrayRegion(locArr, 0, 2, loc);
    int w = env->CallIntMethod(parent, getWidthMid);
    int h = env->CallIntMethod(parent, getHeightMid);
    if (env->ExceptionCheck()) { env->ExceptionClear(); return nullptr; }

    if (x < loc[0] || x > loc[0] + w || y < loc[1] || y > loc[1] + h) {
        return nullptr;
    }

    if (viewGroupCls && env->IsInstanceOf(parent, viewGroupCls) && getChildCountMid && getChildAtMid) {
        int count = env->CallIntMethod(parent, getChildCountMid);
        if (env->ExceptionCheck()) { env->ExceptionClear(); count = 0; }
        for (int i = count - 1; i >= 0; i--) {
            jobject child = env->CallObjectMethod(parent, getChildAtMid, i);
            if (env->ExceptionCheck()) { env->ExceptionClear(); continue; }
            if (child) {
                jobject hit = FindDeepestChildAt(env, child, x, y, viewCls, viewGroupCls,
                                                getVisMid, getWidthMid, getHeightMid, getLocMid,
                                                getChildCountMid, getChildAtMid, locArr);
                if (hit) {
                    env->DeleteLocalRef(child);
                    return hit;
                }
                env->DeleteLocalRef(child);
            }
        }
    }
    return env->NewLocalRef(parent);
}

struct HitViewResult {
    jobject targetView = nullptr;   // LocalRef
    jobject decorView = nullptr;    // LocalRef
    std::string className;
    std::string simpleName;
    std::string idName;
    std::string text;
    int left = 0, top = 0, right = 0, bottom = 0;
    int cx = 0, cy = 0;
};

static bool FindHitViewAt(JNIEnv* env, int x, int y, HitViewResult& out) {
    jobject mViews = GetWindowManagerViews(env);
    if (!mViews) return false;

    jclass listCls = env->FindClass("java/util/List");
    jmethodID sizeMid = listCls ? env->GetMethodID(listCls, "size", "()I") : nullptr;
    jmethodID getMid = listCls ? env->GetMethodID(listCls, "get", "(I)Ljava/lang/Object;") : nullptr;
    int numRoots = (listCls && sizeMid) ? env->CallIntMethod(mViews, sizeMid) : 0;
    if (env->ExceptionCheck()) { env->ExceptionClear(); numRoots = 0; }

    jclass viewCls = env->FindClass("android/view/View");
    jclass viewGroupCls = env->FindClass("android/view/ViewGroup");
    jclass textViewCls = env->FindClass("android/widget/TextView");
    jclass resCls = env->FindClass("android/content/res/Resources");
    jclass charSeqCls = env->FindClass("java/lang/CharSequence");
    jclass liCls = env->FindClass("android/view/View$ListenerInfo");

    jmethodID getIdMid = viewCls ? env->GetMethodID(viewCls, "getId", "()I") : nullptr;
    jmethodID getVisMid = viewCls ? env->GetMethodID(viewCls, "getVisibility", "()I") : nullptr;
    jmethodID isClickableMid = viewCls ? env->GetMethodID(viewCls, "isClickable", "()Z") : nullptr;
    jmethodID getWidthMid = viewCls ? env->GetMethodID(viewCls, "getWidth", "()I") : nullptr;
    jmethodID getHeightMid = viewCls ? env->GetMethodID(viewCls, "getHeight", "()I") : nullptr;
    jmethodID getLocMid = viewCls ? env->GetMethodID(viewCls, "getLocationOnScreen", "([I)V") : nullptr;
    jmethodID getResMid = viewCls ? env->GetMethodID(viewCls, "getResources", "()Landroid/content/res/Resources;") : nullptr;
    jmethodID getEntryNameMid = resCls ? env->GetMethodID(resCls, "getResourceEntryName", "(I)Ljava/lang/String;") : nullptr;
    jmethodID getParentMid = viewCls ? env->GetMethodID(viewCls, "getParent", "()Landroid/view/ViewParent;") : nullptr;
    jfieldID mListenerInfoFid = viewCls ? env->GetFieldID(viewCls, "mListenerInfo", "Landroid/view/View$ListenerInfo;") : nullptr;
    jfieldID liOnClickFid = liCls ? env->GetFieldID(liCls, "mOnClickListener", "Landroid/view/View$OnClickListener;") : nullptr;

    jmethodID getChildCountMid = viewGroupCls ? env->GetMethodID(viewGroupCls, "getChildCount", "()I") : nullptr;
    jmethodID getChildAtMid = viewGroupCls ? env->GetMethodID(viewGroupCls, "getChildAt", "(I)Landroid/view/View;") : nullptr;
    jmethodID getTextMid = textViewCls ? env->GetMethodID(textViewCls, "getText", "()Ljava/lang/CharSequence;") : nullptr;
    jmethodID csToStringMid = charSeqCls ? env->GetMethodID(charSeqCls, "toString", "()Ljava/lang/String;") : nullptr;
    if (env->ExceptionCheck()) env->ExceptionClear();

    jintArray locArr = env->NewIntArray(2);
    bool found = false;

    // Search from top-most window (highest index) down to 0
    for (int i = numRoots - 1; i >= 0 && !found; i--) {
        jobject root = env->CallObjectMethod(mViews, getMid, i);
        if (env->ExceptionCheck()) { env->ExceptionClear(); continue; }
        if (!root) continue;

        jobject hit = FindDeepestChildAt(env, root, x, y, viewCls, viewGroupCls,
                                         getVisMid, getWidthMid, getHeightMid,
                                         getLocMid, getChildCountMid, getChildAtMid, locArr);
        if (hit) {
            found = true;
            out.decorView = env->NewLocalRef(root);

            // Walk up to find clickable parent if hit itself is not clickable
            jobject target = env->NewLocalRef(hit);
            jboolean clickable = env->CallBooleanMethod(target, isClickableMid);
            jobject li = mListenerInfoFid ? env->GetObjectField(target, mListenerInfoFid) : nullptr;
            jobject l = (li && liOnClickFid) ? env->GetObjectField(li, liOnClickFid) : nullptr;
            if (l) env->DeleteLocalRef(l);
            if (li) env->DeleteLocalRef(li);

            if (!clickable && !l && getParentMid) {
                jobject curr = env->NewLocalRef(target);
                while (curr) {
                    jobject parent = env->CallObjectMethod(curr, getParentMid);
                    if (env->ExceptionCheck()) { env->ExceptionClear(); break; }
                    if (parent && env->IsInstanceOf(parent, viewCls)) {
                        jboolean pClickable = env->CallBooleanMethod(parent, isClickableMid);
                        jobject pLi = mListenerInfoFid ? env->GetObjectField(parent, mListenerInfoFid) : nullptr;
                        jobject pL = (pLi && liOnClickFid) ? env->GetObjectField(pLi, liOnClickFid) : nullptr;
                        bool isTarget = (pClickable != 0) || (pL != nullptr);
                        if (pL) env->DeleteLocalRef(pL);
                        if (pLi) env->DeleteLocalRef(pLi);
                        if (isTarget) {
                            env->DeleteLocalRef(target);
                            target = parent;
                            env->DeleteLocalRef(curr);
                            break;
                        }
                        env->DeleteLocalRef(curr);
                        curr = parent;
                    } else {
                        if (parent) env->DeleteLocalRef(parent);
                        env->DeleteLocalRef(curr);
                        break;
                    }
                }
            }

            out.targetView = target;
            jclass tCls = env->GetObjectClass(target);
            out.className = JavaClassName(env, tCls);
            size_t lastDot = out.className.find_last_of('.');
            out.simpleName = (lastDot != std::string::npos) ? out.className.substr(lastDot + 1) : out.className;
            env->DeleteLocalRef(tCls);

            int tId = env->CallIntMethod(target, getIdMid);
            if (tId > 0 && tId != -1 && getResMid && getEntryNameMid) {
                jobject res = env->CallObjectMethod(target, getResMid);
                if (res) {
                    jstring nameJ = (jstring) env->CallObjectMethod(res, getEntryNameMid, tId);
                    if (nameJ) {
                        const char* s = env->GetStringUTFChars(nameJ, nullptr);
                        if (s) { out.idName = std::string("id/") + s; env->ReleaseStringUTFChars(nameJ, s); }
                        env->DeleteLocalRef(nameJ);
                    }
                    env->DeleteLocalRef(res);
                }
            }

            if (textViewCls && env->IsInstanceOf(target, textViewCls) && getTextMid) {
                jobject cs = env->CallObjectMethod(target, getTextMid);
                if (cs && csToStringMid) {
                    jstring ts = (jstring) env->CallObjectMethod(cs, csToStringMid);
                    if (ts) {
                        const char* s = env->GetStringUTFChars(ts, nullptr);
                        if (s) { out.text = s; env->ReleaseStringUTFChars(ts, s); }
                        env->DeleteLocalRef(ts);
                    }
                    env->DeleteLocalRef(cs);
                }
            }

            env->CallVoidMethod(target, getLocMid, locArr);
            jint locBuf[2] = {0, 0};
            env->GetIntArrayRegion(locArr, 0, 2, locBuf);
            int tw = env->CallIntMethod(target, getWidthMid);
            int th = env->CallIntMethod(target, getHeightMid);
            out.left = locBuf[0];
            out.top = locBuf[1];
            out.right = out.left + tw;
            out.bottom = out.top + th;
            out.cx = out.left + tw / 2;
            out.cy = out.top + th / 2;

            env->DeleteLocalRef(hit);
        }
        env->DeleteLocalRef(root);
    }

    if (locArr) env->DeleteLocalRef(locArr);
    if (liCls) env->DeleteLocalRef(liCls);
    if (charSeqCls) env->DeleteLocalRef(charSeqCls);
    if (resCls) env->DeleteLocalRef(resCls);
    if (textViewCls) env->DeleteLocalRef(textViewCls);
    if (viewGroupCls) env->DeleteLocalRef(viewGroupCls);
    if (viewCls) env->DeleteLocalRef(viewCls);
    if (listCls) env->DeleteLocalRef(listCls);
    env->DeleteLocalRef(mViews);

    return found;
}

static jobject GetCurrentActivity(JNIEnv* env) {
    jobject mViews = GetWindowManagerViews(env);
    if (!mViews) return nullptr;

    jclass listCls = env->FindClass("java/util/List");
    jmethodID sizeMid = listCls ? env->GetMethodID(listCls, "size", "()I") : nullptr;
    jmethodID getMid = listCls ? env->GetMethodID(listCls, "get", "(I)Ljava/lang/Object;") : nullptr;
    int numRoots = (listCls && sizeMid) ? env->CallIntMethod(mViews, sizeMid) : 0;
    if (env->ExceptionCheck()) { env->ExceptionClear(); numRoots = 0; }

    jclass viewCls = env->FindClass("android/view/View");
    jmethodID getContextMid = viewCls ? env->GetMethodID(viewCls, "getContext", "()Landroid/content/Context;") : nullptr;
    jclass activityCls = env->FindClass("android/app/Activity");
    jclass wrapperCls = env->FindClass("android/view/ContextThemeWrapper");
    jmethodID getBaseMid = wrapperCls ? env->GetMethodID(wrapperCls, "getBaseContext", "()Landroid/content/Context;") : nullptr;
    if (env->ExceptionCheck()) env->ExceptionClear();

    jobject resultAct = nullptr;
    for (int i = numRoots - 1; i >= 0 && !resultAct; i--) {
        jobject root = env->CallObjectMethod(mViews, getMid, i);
        if (env->ExceptionCheck()) { env->ExceptionClear(); continue; }
        if (!root) continue;
        if (getContextMid) {
            jobject ctx = env->CallObjectMethod(root, getContextMid);
            if (env->ExceptionCheck()) env->ExceptionClear();
            if (ctx) {
                if (activityCls && env->IsInstanceOf(ctx, activityCls)) {
                    resultAct = ctx;
                } else if (wrapperCls && env->IsInstanceOf(ctx, wrapperCls) && getBaseMid) {
                    jobject base = env->CallObjectMethod(ctx, getBaseMid);
                    if (env->ExceptionCheck()) env->ExceptionClear();
                    if (base && activityCls && env->IsInstanceOf(base, activityCls)) {
                        resultAct = base;
                    }
                    if (base && base != resultAct) env->DeleteLocalRef(base);
                }
                if (ctx != resultAct) env->DeleteLocalRef(ctx);
            }
        }
        env->DeleteLocalRef(root);
    }

    if (wrapperCls) env->DeleteLocalRef(wrapperCls);
    if (activityCls) env->DeleteLocalRef(activityCls);
    if (viewCls) env->DeleteLocalRef(viewCls);
    if (listCls) env->DeleteLocalRef(listCls);
    env->DeleteLocalRef(mViews);
    return resultAct;
}

static JSValue JsUiDumpViews(JSContext* ctx, JSValueConst, int argc, JSValueConst* argv) {
    JNIEnv* env = GetEnv();
    if (!env) return JS_UNDEFINED;

    UiFilterOptions opt = ParseUiFilterOptions(ctx, argc, argv);

    jobject mViews = GetWindowManagerViews(env);
    if (!mViews) return JS_NewString(ctx, "[-] Failed to obtain WindowManagerGlobal.mViews");

    jclass listCls = env->FindClass("java/util/List");
    jmethodID sizeMid = listCls ? env->GetMethodID(listCls, "size", "()I") : nullptr;
    jmethodID getMid = listCls ? env->GetMethodID(listCls, "get", "(I)Ljava/lang/Object;") : nullptr;
    int numRoots = (listCls && sizeMid) ? env->CallIntMethod(mViews, sizeMid) : 0;
    if (env->ExceptionCheck()) { env->ExceptionClear(); numRoots = 0; }

    jclass viewCls = env->FindClass("android/view/View");
    jclass viewGroupCls = env->FindClass("android/view/ViewGroup");
    jclass textViewCls = env->FindClass("android/widget/TextView");
    jclass resCls = env->FindClass("android/content/res/Resources");
    jclass charSeqCls = env->FindClass("java/lang/CharSequence");
    jclass liCls = env->FindClass("android/view/View$ListenerInfo");

    jmethodID getIdMid = viewCls ? env->GetMethodID(viewCls, "getId", "()I") : nullptr;
    jmethodID getVisMid = viewCls ? env->GetMethodID(viewCls, "getVisibility", "()I") : nullptr;
    jmethodID isClickableMid = viewCls ? env->GetMethodID(viewCls, "isClickable", "()Z") : nullptr;
    jmethodID isEnabledMid = viewCls ? env->GetMethodID(viewCls, "isEnabled", "()Z") : nullptr;
    jmethodID getWidthMid = viewCls ? env->GetMethodID(viewCls, "getWidth", "()I") : nullptr;
    jmethodID getHeightMid = viewCls ? env->GetMethodID(viewCls, "getHeight", "()I") : nullptr;
    jmethodID getLocMid = viewCls ? env->GetMethodID(viewCls, "getLocationOnScreen", "([I)V") : nullptr;
    jmethodID getResMid = viewCls ? env->GetMethodID(viewCls, "getResources", "()Landroid/content/res/Resources;") : nullptr;
    jmethodID getEntryNameMid = resCls ? env->GetMethodID(resCls, "getResourceEntryName", "(I)Ljava/lang/String;") : nullptr;
    jmethodID getContentDescMid = viewCls ? env->GetMethodID(viewCls, "getContentDescription", "()Ljava/lang/CharSequence;") : nullptr;
    jfieldID mListenerInfoFid = viewCls ? env->GetFieldID(viewCls, "mListenerInfo", "Landroid/view/View$ListenerInfo;") : nullptr;

    jmethodID getChildCountMid = viewGroupCls ? env->GetMethodID(viewGroupCls, "getChildCount", "()I") : nullptr;
    jmethodID getChildAtMid = viewGroupCls ? env->GetMethodID(viewGroupCls, "getChildAt", "(I)Landroid/view/View;") : nullptr;

    jmethodID getTextMid = textViewCls ? env->GetMethodID(textViewCls, "getText", "()Ljava/lang/CharSequence;") : nullptr;
    jmethodID csToStringMid = charSeqCls ? env->GetMethodID(charSeqCls, "toString", "()Ljava/lang/String;") : nullptr;
    jfieldID liOnClickFid = liCls ? env->GetFieldID(liCls, "mOnClickListener", "Landroid/view/View$OnClickListener;") : nullptr;
    jfieldID liOnLongClickFid = liCls ? env->GetFieldID(liCls, "mOnLongClickListener", "Landroid/view/View$OnLongClickListener;") : nullptr;
    if (env->ExceptionCheck()) env->ExceptionClear();

    jintArray locArr = env->NewIntArray(2);

    std::ostringstream ss;
    ss << "=== Active Window View Tree (" << numRoots << " window(s))";
    if (opt.hasFilter()) {
        ss << " [Filter: \"" << (opt.pattern.empty() ? (opt.text.empty() ? opt.id : opt.text) : opt.pattern) << "\"]";
    }
    ss << " ===\n";

    bool anyMatched = false;
    for (int i = 0; i < numRoots; i++) {
        jobject root = env->CallObjectMethod(mViews, getMid, i);
        if (env->ExceptionCheck()) { env->ExceptionClear(); continue; }
        if (!root) continue;

        ViewNode rootNode;
        TraverseViewTree(env, root, 0, rootNode,
                         viewCls, viewGroupCls, textViewCls, resCls,
                         getIdMid, getVisMid, isClickableMid, isEnabledMid,
                         getWidthMid, getHeightMid, getLocMid, getResMid, getEntryNameMid,
                         getContentDescMid, mListenerInfoFid, liCls, liOnClickFid, liOnLongClickFid,
                         getChildCountMid, getChildAtMid, getTextMid,
                         csToStringMid, locArr, false);

        if (!opt.hasFilter() || NodeMatchesFilter(rootNode, opt) || HasMatchingDescendant(rootNode, opt)) {
            anyMatched = true;
            ss << "[Window " << i << "] ";
            FormatViewTree(rootNode, "", true, ss, opt);
        }
        env->DeleteLocalRef(root);
    }

    if (locArr) env->DeleteLocalRef(locArr);
    if (liCls) env->DeleteLocalRef(liCls);
    if (charSeqCls) env->DeleteLocalRef(charSeqCls);
    if (resCls) env->DeleteLocalRef(resCls);
    if (textViewCls) env->DeleteLocalRef(textViewCls);
    if (viewGroupCls) env->DeleteLocalRef(viewGroupCls);
    if (viewCls) env->DeleteLocalRef(viewCls);
    if (listCls) env->DeleteLocalRef(listCls);
    env->DeleteLocalRef(mViews);

    if (opt.hasFilter() && !anyMatched) {
        std::string msg = "[-] No views found matching filter: \"" +
                          (opt.pattern.empty() ? (opt.text.empty() ? opt.id : opt.text) : opt.pattern) + "\"\n";
        return JS_NewString(ctx, msg.c_str());
    }

    return JS_NewString(ctx, ss.str().c_str());
}

static JSValue JsUiGetViews(JSContext* ctx, JSValueConst, int argc, JSValueConst* argv) {
    JNIEnv* env = GetEnv();
    if (!env) return JS_NewArray(ctx);

    UiFilterOptions opt = ParseUiFilterOptions(ctx, argc, argv);

    jobject mViews = GetWindowManagerViews(env);
    if (!mViews) return JS_NewArray(ctx);

    jclass listCls = env->FindClass("java/util/List");
    jmethodID sizeMid = listCls ? env->GetMethodID(listCls, "size", "()I") : nullptr;
    jmethodID getMid = listCls ? env->GetMethodID(listCls, "get", "(I)Ljava/lang/Object;") : nullptr;
    int numRoots = (listCls && sizeMid) ? env->CallIntMethod(mViews, sizeMid) : 0;
    if (env->ExceptionCheck()) { env->ExceptionClear(); numRoots = 0; }

    jclass viewCls = env->FindClass("android/view/View");
    jclass viewGroupCls = env->FindClass("android/view/ViewGroup");
    jclass textViewCls = env->FindClass("android/widget/TextView");
    jclass resCls = env->FindClass("android/content/res/Resources");
    jclass charSeqCls = env->FindClass("java/lang/CharSequence");
    jclass liCls = env->FindClass("android/view/View$ListenerInfo");

    jmethodID getIdMid = viewCls ? env->GetMethodID(viewCls, "getId", "()I") : nullptr;
    jmethodID getVisMid = viewCls ? env->GetMethodID(viewCls, "getVisibility", "()I") : nullptr;
    jmethodID isClickableMid = viewCls ? env->GetMethodID(viewCls, "isClickable", "()Z") : nullptr;
    jmethodID isEnabledMid = viewCls ? env->GetMethodID(viewCls, "isEnabled", "()Z") : nullptr;
    jmethodID getWidthMid = viewCls ? env->GetMethodID(viewCls, "getWidth", "()I") : nullptr;
    jmethodID getHeightMid = viewCls ? env->GetMethodID(viewCls, "getHeight", "()I") : nullptr;
    jmethodID getLocMid = viewCls ? env->GetMethodID(viewCls, "getLocationOnScreen", "([I)V") : nullptr;
    jmethodID getResMid = viewCls ? env->GetMethodID(viewCls, "getResources", "()Landroid/content/res/Resources;") : nullptr;
    jmethodID getEntryNameMid = resCls ? env->GetMethodID(resCls, "getResourceEntryName", "(I)Ljava/lang/String;") : nullptr;
    jmethodID getContentDescMid = viewCls ? env->GetMethodID(viewCls, "getContentDescription", "()Ljava/lang/CharSequence;") : nullptr;
    jfieldID mListenerInfoFid = viewCls ? env->GetFieldID(viewCls, "mListenerInfo", "Landroid/view/View$ListenerInfo;") : nullptr;

    jmethodID getChildCountMid = viewGroupCls ? env->GetMethodID(viewGroupCls, "getChildCount", "()I") : nullptr;
    jmethodID getChildAtMid = viewGroupCls ? env->GetMethodID(viewGroupCls, "getChildAt", "(I)Landroid/view/View;") : nullptr;

    jmethodID getTextMid = textViewCls ? env->GetMethodID(textViewCls, "getText", "()Ljava/lang/CharSequence;") : nullptr;
    jmethodID csToStringMid = charSeqCls ? env->GetMethodID(charSeqCls, "toString", "()Ljava/lang/String;") : nullptr;
    jfieldID liOnClickFid = liCls ? env->GetFieldID(liCls, "mOnClickListener", "Landroid/view/View$OnClickListener;") : nullptr;
    jfieldID liOnLongClickFid = liCls ? env->GetFieldID(liCls, "mOnLongClickListener", "Landroid/view/View$OnLongClickListener;") : nullptr;
    if (env->ExceptionCheck()) env->ExceptionClear();

    jintArray locArr = env->NewIntArray(2);
    JSValue arr = JS_NewArray(ctx);
    uint32_t outIdx = 0;

    for (int i = 0; i < numRoots; i++) {
        jobject root = env->CallObjectMethod(mViews, getMid, i);
        if (env->ExceptionCheck()) { env->ExceptionClear(); continue; }
        if (!root) continue;

        ViewNode rootNode;
        TraverseViewTree(env, root, 0, rootNode,
                         viewCls, viewGroupCls, textViewCls, resCls,
                         getIdMid, getVisMid, isClickableMid, isEnabledMid,
                         getWidthMid, getHeightMid, getLocMid, getResMid, getEntryNameMid,
                         getContentDescMid, mListenerInfoFid, liCls, liOnClickFid, liOnLongClickFid,
                         getChildCountMid, getChildAtMid, getTextMid,
                         csToStringMid, locArr, true);

        FlattenViewNodes(env, ctx, rootNode, opt, arr, outIdx);
        FreeViewNodeTree(env, rootNode);
        env->DeleteLocalRef(root);
    }

    if (locArr) env->DeleteLocalRef(locArr);
    if (liCls) env->DeleteLocalRef(liCls);
    if (charSeqCls) env->DeleteLocalRef(charSeqCls);
    if (resCls) env->DeleteLocalRef(resCls);
    if (textViewCls) env->DeleteLocalRef(textViewCls);
    if (viewGroupCls) env->DeleteLocalRef(viewGroupCls);
    if (viewCls) env->DeleteLocalRef(viewCls);
    if (listCls) env->DeleteLocalRef(listCls);
    env->DeleteLocalRef(mViews);

    return arr;
}

static JSValue JsUiClick(JSContext* ctx, JSValueConst, int argc, JSValueConst* argv) {
    if (argc < 1) return JS_NewString(ctx, "Usage: UI.click(x, y) | UI.click('textOrId') | UI.click(viewNode)");
    JNIEnv* env = GetEnv();
    if (!env) return JS_FALSE;

    // Case 1: Coordinate click UI.click(x, y)
    if (argc >= 2 && JS_IsNumber(argv[0]) && JS_IsNumber(argv[1])) {
        int x = 0, y = 0;
        JS_ToInt32(ctx, &x, argv[0]);
        JS_ToInt32(ctx, &y, argv[1]);

        HitViewResult hit;
        bool found = FindHitViewAt(env, x, y, hit);
        if (found) {
            bool touchDispatched = DispatchTouchEventPair(env, hit.decorView, static_cast<float>(x), static_cast<float>(y));

            jclass vCls = env->GetObjectClass(hit.targetView);
            jmethodID callOnClickMid = env->GetMethodID(vCls, "callOnClick", "()Z");
            jmethodID performClickMid = env->GetMethodID(vCls, "performClick", "()Z");
            if (env->ExceptionCheck()) env->ExceptionClear();

            jboolean clicked = JNI_FALSE;
            if (callOnClickMid) {
                clicked = env->CallBooleanMethod(hit.targetView, callOnClickMid);
                if (env->ExceptionCheck()) env->ExceptionClear();
            }
            if (!clicked && performClickMid) {
                clicked = env->CallBooleanMethod(hit.targetView, performClickMid);
                if (env->ExceptionCheck()) env->ExceptionClear();
            }
            env->DeleteLocalRef(vCls);
            env->DeleteLocalRef(hit.targetView);
            env->DeleteLocalRef(hit.decorView);

            char outBuf[256];
            std::string idPart = hit.idName.empty() ? "" : (" (" + hit.idName + ")");
            std::string txtPart = hit.text.empty() ? "" : (" \"" + hit.text + "\"");
            snprintf(outBuf, sizeof(outBuf),
                     "[+] Clicked %s%s%s at (%d, %d) [bounds: %d,%d,%d,%d | clickTriggered=%s, touchDispatched=%s]",
                     hit.simpleName.c_str(), idPart.c_str(), txtPart.c_str(), x, y,
                     hit.left, hit.top, hit.right, hit.bottom,
                     clicked ? "true" : "false", touchDispatched ? "true" : "false");
            return JS_NewString(ctx, outBuf);
        } else {
            jobject mViews = GetWindowManagerViews(env);
            if (mViews) {
                jclass listCls = env->FindClass("java/util/List");
                jmethodID sizeMid = listCls ? env->GetMethodID(listCls, "size", "()I") : nullptr;
                jmethodID getMid = listCls ? env->GetMethodID(listCls, "get", "(I)Ljava/lang/Object;") : nullptr;
                int count = (listCls && sizeMid) ? env->CallIntMethod(mViews, sizeMid) : 0;
                if (count > 0 && getMid) {
                    jobject topRoot = env->CallObjectMethod(mViews, getMid, count - 1);
                    if (topRoot) {
                        DispatchTouchEventPair(env, topRoot, static_cast<float>(x), static_cast<float>(y));
                        env->DeleteLocalRef(topRoot);
                    }
                }
                if (listCls) env->DeleteLocalRef(listCls);
                env->DeleteLocalRef(mViews);
            }
            char outBuf[128];
            snprintf(outBuf, sizeof(outBuf), "[+] Dispatched MotionEvent at (%d, %d) [no view hit]", x, y);
            return JS_NewString(ctx, outBuf);
        }
    }

    // Case 2: String pattern click UI.click("SIGTRAP") or UI.click("id/btn_test")
    if (argc == 1 && JS_IsString(argv[0])) {
        const char* pat = JS_ToCString(ctx, argv[0]);
        if (!pat) return JS_FALSE;
        std::string patternStr = pat;
        JS_FreeCString(ctx, pat);

        JSValue viewsArr = JsUiGetViews(ctx, JS_UNDEFINED, argc, argv);
        int len = 0;
        JSValue lenVal = JS_GetPropertyStr(ctx, viewsArr, "length");
        if (JS_IsNumber(lenVal)) JS_ToInt32(ctx, &len, lenVal);
        JS_FreeValue(ctx, lenVal);

        if (len <= 0) {
            JS_FreeValue(ctx, viewsArr);
            std::string err = "[-] No view found matching \"" + patternStr + "\" to click";
            return JS_NewString(ctx, err.c_str());
        }

        int targetIdx = 0;
        for (int i = 0; i < len; i++) {
            JSValue item = JS_GetPropertyUint32(ctx, viewsArr, i);
            JSValue clkVal = JS_GetPropertyStr(ctx, item, "clickable");
            bool isClk = JS_ToBool(ctx, clkVal);
            JS_FreeValue(ctx, clkVal);
            JS_FreeValue(ctx, item);
            if (isClk) { targetIdx = i; break; }
        }

        JSValue targetItem = JS_GetPropertyUint32(ctx, viewsArr, targetIdx);
        JS_FreeValue(ctx, viewsArr);

        JSValue clickFn = JS_GetPropertyStr(ctx, targetItem, "click");
        JSValue retVal = JS_UNDEFINED;
        if (JS_IsFunction(ctx, clickFn)) {
            retVal = JS_Call(ctx, clickFn, targetItem, 0, nullptr);
        }
        JS_FreeValue(ctx, clickFn);
        JS_FreeValue(ctx, targetItem);
        return retVal;
    }

    // Case 3: UI.click(viewNode) or UI.click(viewJRef)
    JSValue targetVal = argv[0];
    bool needFreeTarget = false;
    int cx = -1, cy = -1;
    if (JS_IsObject(targetVal)) {
        JSValue boundsVal = JS_GetPropertyStr(ctx, targetVal, "bounds");
        if (JS_IsObject(boundsVal)) {
            JSValue cxVal = JS_GetPropertyStr(ctx, boundsVal, "cx");
            JSValue cyVal = JS_GetPropertyStr(ctx, boundsVal, "cy");
            if (JS_IsNumber(cxVal)) JS_ToInt32(ctx, &cx, cxVal);
            if (JS_IsNumber(cyVal)) JS_ToInt32(ctx, &cy, cyVal);
            JS_FreeValue(ctx, cxVal);
            JS_FreeValue(ctx, cyVal);
        }
        JS_FreeValue(ctx, boundsVal);

        JSValue vVal = JS_GetPropertyStr(ctx, targetVal, "view");
        if (JS_IsObject(vVal)) {
            targetVal = vVal;
            needFreeTarget = true;
        } else {
            JS_FreeValue(ctx, vVal);
        }
    }

    int h = ExtractJRefHandle(ctx, targetVal);
    if (needFreeTarget) JS_FreeValue(ctx, targetVal);

    if (h < 0) {
        return JS_ThrowTypeError(ctx, "Argument must be coordinates (x, y), string pattern, or View object");
    }

    jobject obj = GetJRef(h);
    if (!obj) return JS_FALSE;

    if (cx >= 0 && cy >= 0) {
        HitViewResult hit;
        if (FindHitViewAt(env, cx, cy, hit)) {
            DispatchTouchEventPair(env, hit.decorView, static_cast<float>(cx), static_cast<float>(cy));
            if (hit.targetView) env->DeleteLocalRef(hit.targetView);
            if (hit.decorView) env->DeleteLocalRef(hit.decorView);
        }
    }

    jclass viewCls = env->GetObjectClass(obj);
    jmethodID callOnClickMid = env->GetMethodID(viewCls, "callOnClick", "()Z");
    jmethodID performClickMid = env->GetMethodID(viewCls, "performClick", "()Z");
    if (env->ExceptionCheck()) env->ExceptionClear();

    jboolean clicked = JNI_FALSE;
    if (callOnClickMid) {
        clicked = env->CallBooleanMethod(obj, callOnClickMid);
        if (env->ExceptionCheck()) env->ExceptionClear();
    }
    if (!clicked && performClickMid) {
        clicked = env->CallBooleanMethod(obj, performClickMid);
        if (env->ExceptionCheck()) env->ExceptionClear();
    }
    env->DeleteLocalRef(viewCls);

    return JS_NewBool(ctx, clicked != 0);
}

static JSValue JsUiLongClick(JSContext* ctx, JSValueConst, int argc, JSValueConst* argv) {
    if (argc < 1) return JS_NewString(ctx, "Usage: UI.longClick(view) | UI.longClick(x, y) | UI.longClick('text')");
    JNIEnv* env = GetEnv();
    if (!env) return JS_FALSE;

    if (argc >= 2 && JS_IsNumber(argv[0]) && JS_IsNumber(argv[1])) {
        int x = 0, y = 0;
        JS_ToInt32(ctx, &x, argv[0]);
        JS_ToInt32(ctx, &y, argv[1]);

        HitViewResult hit;
        if (FindHitViewAt(env, x, y, hit)) {
            jclass vCls = env->GetObjectClass(hit.targetView);
            jmethodID longClickMid = env->GetMethodID(vCls, "performLongClick", "()Z");
            if (env->ExceptionCheck()) env->ExceptionClear();
            jboolean done = longClickMid ? env->CallBooleanMethod(hit.targetView, longClickMid) : JNI_FALSE;
            if (env->ExceptionCheck()) env->ExceptionClear();
            env->DeleteLocalRef(vCls);
            env->DeleteLocalRef(hit.targetView);
            env->DeleteLocalRef(hit.decorView);

            char outBuf[128];
            snprintf(outBuf, sizeof(outBuf), "[+] LongClicked %s at (%d, %d) [result=%s]",
                     hit.simpleName.c_str(), x, y, done ? "true" : "false");
            return JS_NewString(ctx, outBuf);
        }
        return JS_NewString(ctx, "[-] No view found at coordinates for longClick");
    }

    if (argc == 1 && JS_IsString(argv[0])) {
        JSValue viewsArr = JsUiGetViews(ctx, JS_UNDEFINED, argc, argv);
        int len = 0;
        JSValue lenVal = JS_GetPropertyStr(ctx, viewsArr, "length");
        if (JS_IsNumber(lenVal)) JS_ToInt32(ctx, &len, lenVal);
        JS_FreeValue(ctx, lenVal);

        if (len <= 0) {
            JS_FreeValue(ctx, viewsArr);
            return JS_NewString(ctx, "[-] No view found matching pattern for longClick");
        }

        JSValue targetItem = JS_GetPropertyUint32(ctx, viewsArr, 0);
        JS_FreeValue(ctx, viewsArr);
        JSValue lclkFn = JS_GetPropertyStr(ctx, targetItem, "longClick");
        JSValue retVal = JS_UNDEFINED;
        if (JS_IsFunction(ctx, lclkFn)) {
            retVal = JS_Call(ctx, lclkFn, targetItem, 0, nullptr);
        }
        JS_FreeValue(ctx, lclkFn);
        JS_FreeValue(ctx, targetItem);
        return retVal;
    }

    JSValue targetVal = argv[0];
    bool needFreeTarget = false;
    if (JS_IsObject(targetVal)) {
        JSValue vVal = JS_GetPropertyStr(ctx, targetVal, "view");
        if (JS_IsObject(vVal)) { targetVal = vVal; needFreeTarget = true; }
        else { JS_FreeValue(ctx, vVal); }
    }

    int h = ExtractJRefHandle(ctx, targetVal);
    if (needFreeTarget) JS_FreeValue(ctx, targetVal);
    if (h < 0) return JS_ThrowTypeError(ctx, "Invalid View target for longClick");

    jobject obj = GetJRef(h);
    if (!obj) return JS_FALSE;

    jclass vCls = env->GetObjectClass(obj);
    jmethodID longClickMid = env->GetMethodID(vCls, "performLongClick", "()Z");
    if (env->ExceptionCheck()) env->ExceptionClear();
    jboolean done = longClickMid ? env->CallBooleanMethod(obj, longClickMid) : JNI_FALSE;
    if (env->ExceptionCheck()) env->ExceptionClear();
    env->DeleteLocalRef(vCls);
    return JS_NewBool(ctx, done != 0);
}

static JSValue JsUiSwipe(JSContext* ctx, JSValueConst, int argc, JSValueConst* argv) {
    if (argc < 4) return JS_NewString(ctx, "Usage: UI.swipe(x1, y1, x2, y2, [durationMs])");
    JNIEnv* env = GetEnv();
    if (!env) return JS_FALSE;

    int x1 = 0, y1 = 0, x2 = 0, y2 = 0, durationMs = 250;
    JS_ToInt32(ctx, &x1, argv[0]);
    JS_ToInt32(ctx, &y1, argv[1]);
    JS_ToInt32(ctx, &x2, argv[2]);
    JS_ToInt32(ctx, &y2, argv[3]);
    if (argc >= 5 && JS_IsNumber(argv[4])) JS_ToInt32(ctx, &durationMs, argv[4]);

    jobject mViews = GetWindowManagerViews(env);
    if (!mViews) return JS_NewString(ctx, "[-] Failed to obtain active window for swipe");

    jclass listCls = env->FindClass("java/util/List");
    jmethodID sizeMid = listCls ? env->GetMethodID(listCls, "size", "()I") : nullptr;
    jmethodID getMid = listCls ? env->GetMethodID(listCls, "get", "(I)Ljava/lang/Object;") : nullptr;
    int numRoots = (listCls && sizeMid) ? env->CallIntMethod(mViews, sizeMid) : 0;
    if (numRoots <= 0 || !getMid) {
        if (listCls) env->DeleteLocalRef(listCls);
        env->DeleteLocalRef(mViews);
        return JS_NewString(ctx, "[-] No active root view found for swipe");
    }

    jobject topRoot = env->CallObjectMethod(mViews, getMid, numRoots - 1);
    bool ok = false;
    if (topRoot) {
        ok = DispatchTouchSequence(env, topRoot, static_cast<float>(x1), static_cast<float>(y1),
                                   static_cast<float>(x2), static_cast<float>(y2), durationMs);
        env->DeleteLocalRef(topRoot);
    }

    if (listCls) env->DeleteLocalRef(listCls);
    env->DeleteLocalRef(mViews);

    char outBuf[128];
    snprintf(outBuf, sizeof(outBuf), "[+] Swiped (%d, %d) -> (%d, %d) over %dms [result=%s]",
             x1, y1, x2, y2, durationMs, ok ? "true" : "false");
    return JS_NewString(ctx, outBuf);
}

static JSValue JsUiSetText(JSContext* ctx, JSValueConst, int argc, JSValueConst* argv) {
    if (argc < 2) return JS_NewString(ctx, "Usage: UI.setText(viewOrSelector, 'newText')");
    JNIEnv* env = GetEnv();
    if (!env) return JS_FALSE;

    const char* textStr = JS_ToCString(ctx, argv[1]);
    if (!textStr) return JS_FALSE;
    std::string newText = textStr;
    JS_FreeCString(ctx, textStr);

    jobject targetView = nullptr;
    bool needDeleteTarget = false;

    if (JS_IsString(argv[0])) {
        JSValue viewsArr = JsUiGetViews(ctx, JS_UNDEFINED, 1, argv);
        int len = 0;
        JSValue lenVal = JS_GetPropertyStr(ctx, viewsArr, "length");
        if (JS_IsNumber(lenVal)) JS_ToInt32(ctx, &len, lenVal);
        JS_FreeValue(ctx, lenVal);
        if (len > 0) {
            JSValue item = JS_GetPropertyUint32(ctx, viewsArr, 0);
            JSValue vVal = JS_GetPropertyStr(ctx, item, "view");
            int h = ExtractJRefHandle(ctx, vVal);
            if (h >= 0) targetView = GetJRef(h);
            JS_FreeValue(ctx, vVal);
            JS_FreeValue(ctx, item);
        }
        JS_FreeValue(ctx, viewsArr);
    } else {
        JSValue targetVal = argv[0];
        bool needFreeTarget = false;
        if (JS_IsObject(targetVal)) {
            JSValue vVal = JS_GetPropertyStr(ctx, targetVal, "view");
            if (JS_IsObject(vVal)) { targetVal = vVal; needFreeTarget = true; }
            else { JS_FreeValue(ctx, vVal); }
        }
        int h = ExtractJRefHandle(ctx, targetVal);
        if (needFreeTarget) JS_FreeValue(ctx, targetVal);
        if (h >= 0) targetView = GetJRef(h);
    }

    if (!targetView) {
        return JS_NewString(ctx, "[-] No target view found to setText");
    }

    jclass textViewCls = env->FindClass("android/widget/TextView");
    if (!textViewCls || !env->IsInstanceOf(targetView, textViewCls)) {
        if (textViewCls) env->DeleteLocalRef(textViewCls);
        return JS_NewString(ctx, "[-] Target view is not an instance of TextView/EditText");
    }

    jmethodID setTextMid = env->GetMethodID(textViewCls, "setText", "(Ljava/lang/CharSequence;)V");
    if (setTextMid) {
        jstring js = env->NewStringUTF(newText.c_str());
        env->CallVoidMethod(targetView, setTextMid, js);
        if (env->ExceptionCheck()) env->ExceptionClear();
        env->DeleteLocalRef(js);
    }
    env->DeleteLocalRef(textViewCls);
    if (needDeleteTarget) env->DeleteLocalRef(targetView);

    return JS_NewString(ctx, "[+] setText completed");
}

static JSValue JsUiCurrentActivity(JSContext* ctx, JSValueConst, int, JSValueConst*) {
    JNIEnv* env = GetEnv();
    if (!env) return JS_NULL;

    jobject act = GetCurrentActivity(env);
    if (!act) return JS_NULL;

    void* artObj = PineNative_ToArtObject(env, act);
    uint64_t addr = artObj ? reinterpret_cast<uintptr_t>(artObj) : reinterpret_cast<uintptr_t>(act);
    DoRegisterObservedObject(env, addr, act);
    int h = AddJRef(env, act, addr, /*persistent=*/true);
    env->DeleteLocalRef(act);
    return CreateJRefValue(ctx, h);
}

static JSValue JsUiPressBack(JSContext* ctx, JSValueConst, int, JSValueConst*) {
    JNIEnv* env = GetEnv();
    if (!env) return JS_FALSE;

    jobject act = GetCurrentActivity(env);
    if (!act) return JS_NewString(ctx, "[-] No foreground Activity found to trigger back");

    jclass actCls = env->GetObjectClass(act);
    jmethodID backMid = env->GetMethodID(actCls, "onBackPressed", "()V");
    if (backMid) {
        env->CallVoidMethod(act, backMid);
        if (env->ExceptionCheck()) env->ExceptionClear();
    }
    std::string actName = JavaClassName(env, actCls);
    env->DeleteLocalRef(actCls);
    env->DeleteLocalRef(act);

    std::string msg = "[+] Triggered onBackPressed() on " + actName;
    return JS_NewString(ctx, msg.c_str());
}

static JSValue JsUiHelp(JSContext* ctx, JSValueConst, int, JSValueConst*) {
    const char* kHelp =
        "=== ArtPI UI Automation & Inspection APIs ===\n"
        "• UI.dump([filter])                 - Print formatted UI hierarchy tree (prunes non-matching nodes)\n"
        "• UI.find(patternOrObj)             - Search views by text, idName, className, clickable\n"
        "• UI.views([patternOrObj])          - Alias for UI.find()\n"
        "• UI.click(view | 'text' | x, y)    - Click a view, text label, or screen coordinates\n"
        "• UI.longClick(view | 'text' | x, y)- Long-press a view, text, or coordinates\n"
        "• UI.swipe(x1, y1, x2, y2, [ms])   - Smooth swipe gesture between two points\n"
        "• UI.setText(view | 'id', 'text')   - Set text on EditText or TextView\n"
        "• UI.currentActivity()              - Get current foreground Activity (JRef)\n"
        "• UI.pressBack()                    - Trigger Activity back button\n"
        "==============================================";
    return JS_NewString(ctx, kHelp);
}

} // namespace

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
            done = true;
        }
    }
    return done;
}

void RegisterObservedObject(JNIEnv* env, uint64_t raw, jobject obj) {
    DoRegisterObservedObject(env, raw, obj);
}

void RegisterJavaApis(JSContext* ctx, JSValue global, JSValue java) {
    PineNative_SetObservedObjectCallback(RegisterObservedObject);

    // Methods on Java namespace
    JS_SetPropertyStr(ctx, java, "findClass", JS_NewCFunction(ctx, JsFindClass, "findClass", 1));
    JS_SetPropertyStr(ctx, java, "findMethod", JS_NewCFunction(ctx, JsFindMethod, "findMethod", 3));
    JS_SetPropertyStr(ctx, java, "listMethods", JS_NewCFunction(ctx, JsListMethods, "listMethods", 1));
    JS_SetPropertyStr(ctx, java, "findMethods", JS_NewCFunction(ctx, JsFindMethods, "findMethods", 2));
    JS_SetPropertyStr(ctx, java, "methodToArt", JS_NewCFunction(ctx, JsMethodToArt, "methodToArt", 1));
    JS_SetPropertyStr(ctx, java, "artToMethod", JS_NewCFunction(ctx, JsArtToMethod, "artToMethod", 1));
    JS_SetPropertyStr(ctx, java, "methodInfo", JS_NewCFunction(ctx, JsMethodInfo, "methodInfo", 1));
    JS_SetPropertyStr(ctx, java, "enumerateClassLoaders", JS_NewCFunction(ctx, JsEnumerateClassLoaders, "enumerateClassLoaders", 0));
    JS_SetPropertyStr(ctx, java, "dumpSmali", JS_NewCFunction(ctx, JsDumpSmali, "dumpSmali", 2));
    JS_SetPropertyStr(ctx, java, "dumpCode", JS_NewCFunction(ctx, JsDumpCode, "dumpCode", 2));
    JS_SetPropertyStr(ctx, java, "decompile", JS_NewCFunction(ctx, JsDecompile, "decompile", 2));
    JS_SetPropertyStr(ctx, java, "disassembly", JS_NewCFunction(ctx, JsDecompile, "disassembly", 2));
    JS_SetPropertyStr(ctx, java, "choose", JS_NewCFunction(ctx, JsJavaChoose, "choose", 2));
    JS_SetPropertyStr(ctx, global, "choose", JS_NewCFunction(ctx, JsJavaChoose, "choose", 2));
    JS_SetPropertyStr(ctx, java, "hook", JS_NewCFunction(ctx, JsJavaHook, "hook", 2));
    JS_SetPropertyStr(ctx, java, "unhook", JS_NewCFunction(ctx, JsJavaUnhook, "unhook", 1));
    JS_SetPropertyStr(ctx, java, "unhookAll", JS_NewCFunction(ctx, JsJavaUnhookAll, "unhookAll", 0));
    JS_SetPropertyStr(ctx, java, "prepare", JS_NewCFunction(ctx, JsPrepare, "prepare", 1));
    JS_SetPropertyStr(ctx, java, "object", JS_NewCFunction(ctx, JsArtObject, "object", 1));

    // Flat global aliases
    JS_SetPropertyStr(ctx, global, "prepare", JS_NewCFunction(ctx, JsPrepare, "prepare", 1));
    JS_SetPropertyStr(ctx, global, "artobject", JS_NewCFunction(ctx, JsArtObject, "artobject", 1));
    JS_SetPropertyStr(ctx, global, "artobjects", JS_NewCFunction(ctx, JsArtObject, "artobjects", 1));
    JS_SetPropertyStr(ctx, global, "jobject", JS_NewCFunction(ctx, JsArtObject, "jobject", 1));
    JS_SetPropertyStr(ctx, global, "jobjects", JS_NewCFunction(ctx, JsArtObject, "jobjects", 1));
    JS_SetPropertyStr(ctx, global, "findClass", JS_NewCFunction(ctx, JsFindClass, "findClass", 1));
    JS_SetPropertyStr(ctx, global, "findclass", JS_NewCFunction(ctx, JsFindClass, "findclass", 1));
    JS_SetPropertyStr(ctx, global, "findMethod", JS_NewCFunction(ctx, JsFindMethod, "findMethod", 3));
    JS_SetPropertyStr(ctx, global, "findmethod", JS_NewCFunction(ctx, JsFindMethod, "findmethod", 3));
    JS_SetPropertyStr(ctx, global, "listMethods", JS_NewCFunction(ctx, JsListMethods, "listMethods", 1));
    JS_SetPropertyStr(ctx, global, "listmethods", JS_NewCFunction(ctx, JsListMethods, "listmethods", 1));
    JS_SetPropertyStr(ctx, global, "findMethods", JS_NewCFunction(ctx, JsFindMethods, "findMethods", 2));
    JS_SetPropertyStr(ctx, global, "findmethods", JS_NewCFunction(ctx, JsFindMethods, "findmethods", 2));
    JS_SetPropertyStr(ctx, global, "methodToArt", JS_NewCFunction(ctx, JsMethodToArt, "methodToArt", 1));
    JS_SetPropertyStr(ctx, global, "methodtoart", JS_NewCFunction(ctx, JsMethodToArt, "methodtoart", 1));
    JS_SetPropertyStr(ctx, global, "artToMethod", JS_NewCFunction(ctx, JsArtToMethod, "artToMethod", 1));
    JS_SetPropertyStr(ctx, global, "artmethodtojmethod", JS_NewCFunction(ctx, JsArtToMethod, "artmethodtojmethod", 1));
    JS_SetPropertyStr(ctx, global, "methodInfo", JS_NewCFunction(ctx, JsMethodInfo, "methodInfo", 1));
    JS_SetPropertyStr(ctx, global, "methodinfo", JS_NewCFunction(ctx, JsMethodInfo, "methodinfo", 1));
    JS_SetPropertyStr(ctx, global, "enumloaders", JS_NewCFunction(ctx, JsEnumerateClassLoaders, "enumloaders", 0));
    JS_SetPropertyStr(ctx, global, "dumpSmali", JS_NewCFunction(ctx, JsDumpSmali, "dumpSmali", 2));
    JS_SetPropertyStr(ctx, global, "dumpsmali", JS_NewCFunction(ctx, JsDumpSmali, "dumpsmali", 2));
    JS_SetPropertyStr(ctx, global, "dumpCode", JS_NewCFunction(ctx, JsDumpCode, "dumpCode", 2));
    JS_SetPropertyStr(ctx, global, "dumpcode", JS_NewCFunction(ctx, JsDumpCode, "dumpcode", 2));
    JS_SetPropertyStr(ctx, global, "decompile", JS_NewCFunction(ctx, JsDecompile, "decompile", 2));
    JS_SetPropertyStr(ctx, global, "disassembly", JS_NewCFunction(ctx, JsDecompile, "disassembly", 2));
    JS_SetPropertyStr(ctx, global, "jhook", JS_NewCFunction(ctx, JsJavaHook, "jhook", 2));
    JS_SetPropertyStr(ctx, global, "unhook", JS_NewCFunction(ctx, JsJavaUnhook, "unhook", 1));
    JS_SetPropertyStr(ctx, global, "unhookall", JS_NewCFunction(ctx, JsJavaUnhookAll, "unhookall", 0));

    // UI inspection & interaction APIs
    JSValue ui = JS_NewObject(ctx);
    JS_SetPropertyStr(ctx, ui, "dump", JS_NewCFunction(ctx, JsUiDumpViews, "dump", 1));
    JS_SetPropertyStr(ctx, ui, "views", JS_NewCFunction(ctx, JsUiGetViews, "views", 1));
    JS_SetPropertyStr(ctx, ui, "find", JS_NewCFunction(ctx, JsUiGetViews, "find", 1));
    JS_SetPropertyStr(ctx, ui, "click", JS_NewCFunction(ctx, JsUiClick, "click", 2));
    JS_SetPropertyStr(ctx, ui, "longClick", JS_NewCFunction(ctx, JsUiLongClick, "longClick", 2));
    JS_SetPropertyStr(ctx, ui, "swipe", JS_NewCFunction(ctx, JsUiSwipe, "swipe", 5));
    JS_SetPropertyStr(ctx, ui, "setText", JS_NewCFunction(ctx, JsUiSetText, "setText", 2));
    JS_SetPropertyStr(ctx, ui, "currentActivity", JS_NewCFunction(ctx, JsUiCurrentActivity, "currentActivity", 0));
    JS_SetPropertyStr(ctx, ui, "topActivity", JS_NewCFunction(ctx, JsUiCurrentActivity, "topActivity", 0));
    JS_SetPropertyStr(ctx, ui, "pressBack", JS_NewCFunction(ctx, JsUiPressBack, "pressBack", 0));
    JS_SetPropertyStr(ctx, ui, "help", JS_NewCFunction(ctx, JsUiHelp, "help", 0));

    JS_SetPropertyStr(ctx, global, "UI", ui);
    JS_SetPropertyStr(ctx, global, "ui", JS_DupValue(ctx, ui));
    JS_SetPropertyStr(ctx, global, "dumpViews", JS_NewCFunction(ctx, JsUiDumpViews, "dumpViews", 1));
    JS_SetPropertyStr(ctx, global, "dumpviews", JS_NewCFunction(ctx, JsUiDumpViews, "dumpviews", 1));
    JS_SetPropertyStr(ctx, global, "findViews", JS_NewCFunction(ctx, JsUiGetViews, "findViews", 1));
    JS_SetPropertyStr(ctx, global, "findviews", JS_NewCFunction(ctx, JsUiGetViews, "findviews", 1));
    JS_SetPropertyStr(ctx, global, "click", JS_NewCFunction(ctx, JsUiClick, "click", 2));
    JS_SetPropertyStr(ctx, global, "swipe", JS_NewCFunction(ctx, JsUiSwipe, "swipe", 5));
    JS_SetPropertyStr(ctx, global, "currentActivity", JS_NewCFunction(ctx, JsUiCurrentActivity, "currentActivity", 0));
    JS_SetPropertyStr(ctx, global, "pressBack", JS_NewCFunction(ctx, JsUiPressBack, "pressBack", 0));

    // JRef field proxy: obj.field / obj.field = v  (backed by reflection)
    JS_SetPropertyStr(ctx, global, "__native_jfget", JS_NewCFunction(ctx, JsJFieldGet, "__native_jfget", 2));
    JS_SetPropertyStr(ctx, global, "__native_jfset", JS_NewCFunction(ctx, JsJFieldSet, "__native_jfset", 3));
    JS_SetPropertyStr(ctx, global, "__native_jstr", JS_NewCFunction(ctx, JsJRefStr, "__native_jstr", 1));
    JS_SetPropertyStr(ctx, global, "__native_jdump", JS_NewCFunction(ctx, JsJRefStr, "__native_jdump", 1));
    JS_SetPropertyStr(ctx, global, "__native_jmethods", JS_NewCFunction(ctx, JsJMethods, "__native_jmethods", 1));
    JS_SetPropertyStr(ctx, global, "__native_jfields", JS_NewCFunction(ctx, JsJFields, "__native_jfields", 1));
    JS_SetPropertyStr(ctx, global, "__native_jcall", JS_NewCFunction(ctx, JsJCall, "__native_jcall", 2));
    JS_SetPropertyStr(ctx, global, "__native_jarrlen", JS_NewCFunction(ctx, JsJArrayLen, "__native_jarrlen", 1));
    JS_SetPropertyStr(ctx, global, "__native_jarrget", JS_NewCFunction(ctx, JsJArrayGet, "__native_jarrget", 2));
    JS_SetPropertyStr(ctx, global, "__native_jarrset", JS_NewCFunction(ctx, JsJArraySet, "__native_jarrset", 3));
    JS_SetPropertyStr(ctx, global, "__native_jmembers", JS_NewCFunction(ctx, JsJMembers, "__native_jmembers", 1));

    const char* kJRefBoot =
        "(function(){"
        "  globalThis.__makeJRef = function(h){"
        "    return new Proxy({ __h: h }, {"
        "      get(t, p) {"
        "        if (p === '__h') return h;"
        "        if (p === 'toString' || p === 'valueOf' || p === '$dump' || p === 'dump') return function(){ return __native_jdump(h); };"
        "        if (p === '$methods' || p === 'methods') return function(){ return __native_jmethods(h); };"
        "        if (p === '$fields' || p === 'fields') return function(){ return __native_jfields(h); };"
        "        if (p === '$call' || p === '$invoke') return function(m, ...a){ return __native_jcall(h, m, ...a); };"
        "        if (p === 'length') { var L = __native_jarrlen(h); if (L >= 0) return L; try { var sz = __native_jcall(h, 'size'); if (typeof sz === 'number') return sz; } catch(e){} }"
        "        if (typeof p === 'string' && /^\\d+$/.test(p)) {"
        "          var v = __native_jarrget(h, +p); if (v !== undefined) return v;"
        "          try { var item = __native_jcall(h, 'get', +p); if (item !== undefined) return item; } catch(e){}"
        "        }"
        "        if (p === Symbol.iterator) {"
        "          return function*(){"
        "            var L = __native_jarrlen(h);"
        "            if (L >= 0) { for (var i = 0; i < L; i++) yield __native_jarrget(h, i); return; }"
        "            try { var sz = __native_jcall(h, 'size'); if (typeof sz === 'number') { for (var i = 0; i < sz; i++) yield __native_jcall(h, 'get', i); } } catch(e){}"
        "          };"
        "        }"
        "        if (typeof p === 'string' && p.charCodeAt(0) !== 95) {"
        "          var fv = __native_jfget(h, p);"
        "          if (fv !== undefined) return fv;"
        "          return function(...args){ return __native_jcall(h, p, ...args); };"
        "        }"
        "        return t[p];"
        "      },"
        "      set(t, p, v) {"
        "        if (typeof p === 'string' && /^\\d+$/.test(p)) { if (__native_jarrset(h, +p, v)) return true; }"
        "        if (typeof p === 'string' && p.charCodeAt(0) !== 95) { __native_jfset(h, p, v); return true; }"
        "        t[p] = v; return true;"
        "      }"
        "    });"
        "  };"
        "  globalThis.__getCompletions = function(expr){"
        "    try {"
        "      var val = eval(expr);"
        "      if (val === null || val === undefined) return [];"
        "      if (typeof val === 'object' && val !== null && val.__h !== undefined) {"
        "        return __native_jmembers(val.__h);"
        "      }"
        "      var s = {};"
        "      for (var o = val; o !== null && o !== Object.prototype; o = Object.getPrototypeOf(o)) {"
        "        var props = Object.getOwnPropertyNames(o);"
        "        for (var i = 0; i < props.length; i++) {"
        "          if (props[i].charCodeAt(0) !== 95) s[props[i]] = true;"
        "        }"
        "      }"
        "      return Object.keys(s).sort();"
        "    } catch(e) {"
        "      return [];"
        "    }"
        "  };"
        "})();";
    JSValue jrefBoot = JS_Eval(ctx, kJRefBoot, strlen(kJRefBoot), "<jref_boot>", JS_EVAL_TYPE_GLOBAL);
    if (JS_IsException(jrefBoot)) {
        JSValue exc = JS_GetException(ctx);
        const char* e = JS_ToCString(ctx, exc);
        PI_LOGE("JRef bootstrap failed: %s", e ? e : "?");
        if (e) JS_FreeCString(ctx, e);
        JS_FreeValue(ctx, exc);
    }
    JS_FreeValue(ctx, jrefBoot);
}

}} // namespace artpi::agent
