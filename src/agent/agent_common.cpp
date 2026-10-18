//
// agent_common.cpp - Shared QuickJS helpers, JNI environment & utility functions
//
#include "agent_common.h"
#include "agent_net.h"
#include "agent_java.h"
#include "agent_trace.h"
#include "agent_debug.h"
#include "../../include/ArtPI.h"
#include "dex/pi_dex_loader.h"
#include <cstring>
#include <algorithm>
#include <vector>

namespace artpi { namespace agent {

JSRuntime* g_rt = nullptr;
JSContext* g_ctx = nullptr;
std::mutex g_jsMutex;
JavaVM* g_jvm = nullptr;
static bool g_piInited = false;

thread_local int t_jsReentrancyDepth = 0;

static jobject g_appClassLoader = nullptr;
static std::mutex g_clMutex;

static std::vector<std::string> g_cachedClassNames;
static std::mutex g_namesMutex;

static jobject GetCachedAppClassLoader() {
    std::lock_guard<std::mutex> lk(g_clMutex);
    return g_appClassLoader;
}

static jclass AgentInterpClassLookup(JNIEnv* env, const char* slashName) {
    if (env == nullptr || slashName == nullptr) return nullptr;
    std::string dotted = slashName;
    for (char& c : dotted) {
        if (c == '/') c = '.';
    }
    // The interpreter/hook path has no valid managed frame, so neither
    // env->FindClass() nor the lazy GetAppClassLoader() probe (it uses
    // FindClass internally) may run here. Registry + the loader cached at
    // InitJs are enough.
    return FindClassViaRegistryOrAppLoader(env, dotted, /*allow_lazy_loader=*/false);
}

void InstallInterpClassFallback() {
    PI::Interp::SetClassLookupFallback(&AgentInterpClassLookup);
}

JNIEnv* GetEnv() {
    if (!g_jvm) {
        static std::mutex g_jvmMutex;
        std::lock_guard<std::mutex> lk(g_jvmMutex);
        if (!g_jvm) {
            typedef jint (*JNI_GetCreatedJavaVMs_t)(JavaVM**, jsize, jsize*);
            void* handle = xdl_open("libart.so", XDL_DEFAULT);
            if (handle) {
                auto getVms = reinterpret_cast<JNI_GetCreatedJavaVMs_t>(
                    xdl_sym(handle, "JNI_GetCreatedJavaVMs", nullptr));
                JavaVM* vms[2] = {nullptr};
                jsize num = 0;
                if (getVms && getVms(vms, 2, &num) == JNI_OK && num > 0) {
                    g_jvm = vms[0];
                }
                xdl_close(handle);
            }
        }
        if (!g_jvm) return nullptr;
    }
    JNIEnv* env = nullptr;
    jint status = g_jvm->GetEnv(reinterpret_cast<void**>(&env), JNI_VERSION_1_6);
    if (status == JNI_EDETACHED) {
#if defined(__ANDROID__)
        g_jvm->AttachCurrentThread(&env, nullptr);
#else
        g_jvm->AttachCurrentThread(reinterpret_cast<void**>(&env), nullptr);
#endif
    }
    if (env) {
        static std::once_flag g_piOnce;
        std::call_once(g_piOnce, [env]() {
            g_piInited = true;
            PI::init(env);
            InitJRefClassCache(env);
        });
    }
    return env;
}

jobject GetAppClassLoader(JNIEnv* env) {
    std::lock_guard<std::mutex> lk(g_clMutex);
    if (g_appClassLoader) {
        return g_appClassLoader;
    }

    jclass activityThreadCls = env->FindClass("android/app/ActivityThread");
    if (env->ExceptionCheck()) {
        env->ExceptionClear();
        return nullptr;
    }

    jobject classLoader = nullptr;

    // 1. Try ActivityThread.currentApplication().getClassLoader()
    jmethodID currentAppMethod = env->GetStaticMethodID(activityThreadCls, "currentApplication", "()Landroid/app/Application;");
    if (env->ExceptionCheck()) env->ExceptionClear();

    if (currentAppMethod) {
        jobject appObj = env->CallStaticObjectMethod(activityThreadCls, currentAppMethod);
        if (env->ExceptionCheck()) env->ExceptionClear();
        if (appObj) {
            jclass contextCls = env->FindClass("android/content/Context");
            if (env->ExceptionCheck()) env->ExceptionClear();
            if (contextCls) {
                jmethodID getClMethod = env->GetMethodID(contextCls, "getClassLoader", "()Ljava/lang/ClassLoader;");
                if (env->ExceptionCheck()) env->ExceptionClear();
                if (getClMethod) {
                    classLoader = env->CallObjectMethod(appObj, getClMethod);
                    if (env->ExceptionCheck()) env->ExceptionClear();
                }
                env->DeleteLocalRef(contextCls);
            }
            env->DeleteLocalRef(appObj);
        }
    }

    // 2. Fallback: ActivityThread.currentActivityThread().mInitialApplication.getClassLoader()
    if (!classLoader) {
        jmethodID currentAtMethod = env->GetStaticMethodID(activityThreadCls, "currentActivityThread", "()Landroid/app/ActivityThread;");
        if (env->ExceptionCheck()) env->ExceptionClear();
        if (currentAtMethod) {
            jobject atObj = env->CallStaticObjectMethod(activityThreadCls, currentAtMethod);
            if (env->ExceptionCheck()) env->ExceptionClear();
            if (atObj) {
                jfieldID initialAppField = env->GetFieldID(activityThreadCls, "mInitialApplication", "Landroid/app/Application;");
                if (env->ExceptionCheck()) env->ExceptionClear();
                if (initialAppField) {
                    jobject initApp = env->GetObjectField(atObj, initialAppField);
                    if (env->ExceptionCheck()) env->ExceptionClear();
                    if (initApp) {
                        jclass contextCls = env->FindClass("android/content/Context");
                        if (env->ExceptionCheck()) env->ExceptionClear();
                        if (contextCls) {
                            jmethodID getClMethod = env->GetMethodID(contextCls, "getClassLoader", "()Ljava/lang/ClassLoader;");
                            if (env->ExceptionCheck()) env->ExceptionClear();
                            if (getClMethod) {
                                classLoader = env->CallObjectMethod(initApp, getClMethod);
                                if (env->ExceptionCheck()) env->ExceptionClear();
                            }
                            env->DeleteLocalRef(contextCls);
                        }
                        env->DeleteLocalRef(initApp);
                    }
                }

                // 3. Fallback: ActivityThread.mPackages (ArrayMap/HashMap of LoadedApk) -> LoadedApk.getClassLoader()
                if (!classLoader) {
                    jfieldID packagesField = env->GetFieldID(activityThreadCls, "mPackages", "Landroid/util/ArrayMap;");
                    if (env->ExceptionCheck()) {
                        env->ExceptionClear();
                        packagesField = env->GetFieldID(activityThreadCls, "mPackages", "Ljava/util/Map;");
                        if (env->ExceptionCheck()) env->ExceptionClear();
                    }
                    if (packagesField) {
                        jobject packagesMap = env->GetObjectField(atObj, packagesField);
                        if (env->ExceptionCheck()) env->ExceptionClear();
                        if (packagesMap) {
                            jclass mapCls = env->FindClass("java/util/Map");
                            if (env->ExceptionCheck()) env->ExceptionClear();
                            if (mapCls) {
                                jmethodID valuesMethod = env->GetMethodID(mapCls, "values", "()Ljava/util/Collection;");
                                if (env->ExceptionCheck()) env->ExceptionClear();
                                if (valuesMethod) {
                                    jobject col = env->CallObjectMethod(packagesMap, valuesMethod);
                                    if (env->ExceptionCheck()) env->ExceptionClear();
                                    if (col) {
                                        jclass colCls = env->FindClass("java/util/Collection");
                                        if (env->ExceptionCheck()) env->ExceptionClear();
                                        if (colCls) {
                                            jmethodID toArrayMethod = env->GetMethodID(colCls, "toArray", "()[Ljava/lang/Object;");
                                            if (env->ExceptionCheck()) env->ExceptionClear();
                                            if (toArrayMethod) {
                                                auto objArr = (jobjectArray)env->CallObjectMethod(col, toArrayMethod);
                                                if (env->ExceptionCheck()) env->ExceptionClear();
                                                if (objArr) {
                                                    jsize len = env->GetArrayLength(objArr);
                                                    jclass refCls = env->FindClass("java/lang/ref/WeakReference");
                                                    if (env->ExceptionCheck()) env->ExceptionClear();
                                                    jmethodID refGet = refCls ? env->GetMethodID(refCls, "get", "()Ljava/lang/Object;") : nullptr;
                                                    if (env->ExceptionCheck()) env->ExceptionClear();

                                                    for (jsize i = 0; i < len; i++) {
                                                        jobject item = env->GetObjectArrayElement(objArr, i);
                                                        if (!item) continue;
                                                        jobject loadedApk = item;
                                                        if (refGet && env->IsInstanceOf(item, refCls)) {
                                                            loadedApk = env->CallObjectMethod(item, refGet);
                                                            if (env->ExceptionCheck()) env->ExceptionClear();
                                                            env->DeleteLocalRef(item);
                                                            if (!loadedApk) continue;
                                                        }
                                                        jclass apkCls = env->GetObjectClass(loadedApk);
                                                        jmethodID getCl = env->GetMethodID(apkCls, "getClassLoader", "()Ljava/lang/ClassLoader;");
                                                        if (env->ExceptionCheck()) env->ExceptionClear();
                                                        if (getCl) {
                                                            classLoader = env->CallObjectMethod(loadedApk, getCl);
                                                            if (env->ExceptionCheck()) env->ExceptionClear();
                                                        }
                                                        env->DeleteLocalRef(apkCls);
                                                        env->DeleteLocalRef(loadedApk);
                                                        if (classLoader) break;
                                                    }
                                                    if (refCls) env->DeleteLocalRef(refCls);
                                                    env->DeleteLocalRef(objArr);
                                                }
                                            }
                                            env->DeleteLocalRef(colCls);
                                        }
                                        env->DeleteLocalRef(col);
                                    }
                                }
                                env->DeleteLocalRef(mapCls);
                            }
                            env->DeleteLocalRef(packagesMap);
                        }
                    }
                }
                env->DeleteLocalRef(atObj);
            }
        }
    }
    env->DeleteLocalRef(activityThreadCls);

    if (classLoader) {
        g_appClassLoader = env->NewGlobalRef(classLoader);
        env->DeleteLocalRef(classLoader);
        return g_appClassLoader;
    }
    return nullptr;
}

void LogAndClearJavaException(JNIEnv* env, const char* where) {
    if (env == nullptr || !env->ExceptionCheck()) return;

    // NOTE: never ExceptionDescribe() here - this may run on a frameless JNI
    // thread (hook trampoline / interpreter), where printing the trace can
    // abort ART. Throwable.toString() is safe.
    jthrowable ex = env->ExceptionOccurred();
    env->ExceptionClear();
    if (ex == nullptr) return;

    // Throwable.toString() is safe here; resolve the class from the exception
    // object itself (GetObjectClass) instead of env->FindClass(), which would
    // re-introduce the frameless-stack hazard.
    jclass thCls = env->GetObjectClass(ex);
    jmethodID toStr = thCls
        ? env->GetMethodID(thCls, "toString", "()Ljava/lang/String;")
        : nullptr;
    if (env->ExceptionCheck()) env->ExceptionClear();

    if (toStr != nullptr) {
        auto js = static_cast<jstring>(env->CallObjectMethod(ex, toStr));
        if (env->ExceptionCheck()) env->ExceptionClear();
        if (js != nullptr) {
            const char* msg = env->GetStringUTFChars(js, nullptr);
            if (msg != nullptr) {
                PI_LOGW("%s: %s", where != nullptr ? where : "Java exception", msg);
                env->ReleaseStringUTFChars(js, msg);
            }
            env->DeleteLocalRef(js);
        }
    }
    if (thCls) env->DeleteLocalRef(thCls);
    env->DeleteLocalRef(ex);
}

jclass FindClassViaRegistryOrAppLoader(JNIEnv* env, const std::string& className,
                                       bool allow_lazy_loader) {
    if (env == nullptr || className.empty()) return nullptr;
    if (className.find('*') != std::string::npos ||
        className.find('?') != std::string::npos) {
        return nullptr;
    }

    std::string slashName = className;
    std::string dotName = className;
    for (char& c : slashName) if (c == '.') c = '/';
    for (char& c : dotName) if (c == '/') c = '.';

    // 1. Classes synthesized at runtime live in their own ClassLoader and are
    //    invisible to env->FindClass / the app ClassLoader.
    if (jclass generated = PI::DexLoader::FindGeneratedClass(env, slashName)) {
        return static_cast<jclass>(env->NewLocalRef(generated));   // local ref
    }

    // 2. App ClassLoader.loadClass() (a managed Java frame, safe anywhere).
    jobject cl = allow_lazy_loader ? GetAppClassLoader(env) : GetCachedAppClassLoader();
    if (cl == nullptr) return nullptr;

    // Derive the ClassLoader class from the instance: no env->FindClass() here.
    jclass clCls = env->GetObjectClass(cl);
    if (clCls == nullptr) return nullptr;
    jmethodID loadClassMethod = env->GetMethodID(
        clCls, "loadClass", "(Ljava/lang/String;)Ljava/lang/Class;");
    if (env->ExceptionCheck() || loadClassMethod == nullptr) {
        if (env->ExceptionCheck()) env->ExceptionClear();
        env->DeleteLocalRef(clCls);
        return nullptr;
    }

    jstring jName = env->NewStringUTF(dotName.c_str());
    auto clsObj = (jclass)env->CallObjectMethod(cl, loadClassMethod, jName);
    if (env->ExceptionCheck()) {
        LogAndClearJavaException(env, ("FindClass('" + dotName + "')").c_str());
        clsObj = nullptr;
    }
    env->DeleteLocalRef(jName);
    env->DeleteLocalRef(clCls);
    return clsObj;
}

jclass FindClassWithFallback(JNIEnv* env, const std::string& className) {
    if (env == nullptr || className.empty()) return nullptr;
    if (className.find('*') != std::string::npos || className.find('?') != std::string::npos) {
        return nullptr;
    }

    std::string slashName = className;
    for (char& c : slashName) if (c == '.') c = '/';

    // 1. Try env->FindClass (works for boot/system classes)
    jclass localCls = env->FindClass(slashName.c_str());
    if (env->ExceptionCheck()) {
        env->ExceptionClear();
        localCls = nullptr;
    }
    if (localCls) return localCls;

    // 1b/2. Generated-class registry, then app ClassLoader.
    return FindClassViaRegistryOrAppLoader(env, className);
}


bool MatchWildcard(const std::string& str, const std::string& pattern) {
    size_t s = 0, p = 0, starIdx = std::string::npos, match = 0;
    while (s < str.size()) {
        if (p < pattern.size() && (pattern[p] == '?' || tolower(pattern[p]) == tolower(str[s]))) {
            s++;
            p++;
        } else if (p < pattern.size() && pattern[p] == '*') {
            starIdx = p;
            match = s;
            p++;
        } else if (starIdx != std::string::npos) {
            p = starIdx + 1;
            match++;
            s = match;
        } else {
            return false;
        }
    }
    while (p < pattern.size() && pattern[p] == '*') p++;
    return p == pattern.size();
}

std::vector<std::string> EnumerateAppClassNames(JNIEnv* env) {
    std::lock_guard<std::mutex> lk(g_namesMutex);
    if (!g_cachedClassNames.empty()) return g_cachedClassNames;

    jobject cl = GetAppClassLoader(env);
    if (!cl) return g_cachedClassNames;

    jclass baseCls = env->FindClass("dalvik/system/BaseDexClassLoader");
    if (!baseCls || env->ExceptionCheck()) { env->ExceptionClear(); return g_cachedClassNames; }

    jfieldID pathListField = env->GetFieldID(baseCls, "pathList", "Ldalvik/system/DexPathList;");
    if (!pathListField || env->ExceptionCheck()) { env->ExceptionClear(); env->DeleteLocalRef(baseCls); return g_cachedClassNames; }

    jobject pathList = env->GetObjectField(cl, pathListField);
    if (!pathList || env->ExceptionCheck()) { env->ExceptionClear(); env->DeleteLocalRef(baseCls); return g_cachedClassNames; }

    jclass dplCls = env->FindClass("dalvik/system/DexPathList");
    jfieldID dexElementsField = dplCls ? env->GetFieldID(dplCls, "dexElements", "[Ldalvik/system/DexPathList$Element;") : nullptr;
    if (env->ExceptionCheck()) env->ExceptionClear();

    if (dexElementsField) {
        auto dexElements = (jobjectArray)env->GetObjectField(pathList, dexElementsField);
        if (dexElements && !env->ExceptionCheck()) {
            jsize len = env->GetArrayLength(dexElements);
            jclass elemCls = env->FindClass("dalvik/system/DexPathList$Element");
            jfieldID dexFileField = elemCls ? env->GetFieldID(elemCls, "dexFile", "Ldalvik/system/DexFile;") : nullptr;
            jclass dexFileCls = env->FindClass("dalvik/system/DexFile");
            jmethodID entriesMid = dexFileCls ? env->GetMethodID(dexFileCls, "entries", "()Ljava/util/Enumeration;") : nullptr;
            jclass enumCls = env->FindClass("java/util/Enumeration");
            jmethodID hasMoreMid = enumCls ? env->GetMethodID(enumCls, "hasMoreElements", "()Z") : nullptr;
            jmethodID nextElemMid = enumCls ? env->GetMethodID(enumCls, "nextElement", "()Ljava/lang/Object;") : nullptr;

            if (dexFileField && entriesMid && hasMoreMid && nextElemMid) {
                for (jsize i = 0; i < len; i++) {
                    jobject elem = env->GetObjectArrayElement(dexElements, i);
                    if (!elem) continue;
                    jobject dexFile = env->GetObjectField(elem, dexFileField);
                    if (dexFile) {
                        jobject enumObj = env->CallObjectMethod(dexFile, entriesMid);
                        if (enumObj) {
                            while (env->CallBooleanMethod(enumObj, hasMoreMid)) {
                                auto strObj = (jstring)env->CallObjectMethod(enumObj, nextElemMid);
                                if (strObj) {
                                    const char* c = env->GetStringUTFChars(strObj, nullptr);
                                    if (c) {
                                        g_cachedClassNames.emplace_back(c);
                                        env->ReleaseStringUTFChars(strObj, c);
                                    }
                                    env->DeleteLocalRef(strObj);
                                }
                            }
                            env->DeleteLocalRef(enumObj);
                        }
                        env->DeleteLocalRef(dexFile);
                    }
                    env->DeleteLocalRef(elem);
                }
            }
            if (elemCls) env->DeleteLocalRef(elemCls);
            if (dexFileCls) env->DeleteLocalRef(dexFileCls);
            if (enumCls) env->DeleteLocalRef(enumCls);
            env->DeleteLocalRef(dexElements);
        }
    }
    if (dplCls) env->DeleteLocalRef(dplCls);
    env->DeleteLocalRef(pathList);
    env->DeleteLocalRef(baseCls);
    return g_cachedClassNames;
}

std::vector<std::string> FindMatchingClassNames(JNIEnv* env, const std::string& prefix, size_t limit) {
    EnumerateAppClassNames(env);
    std::lock_guard<std::mutex> lk(g_namesMutex);
    std::vector<std::string> results;
    std::string prefixLower = prefix;
    for (char& c : prefixLower) c = tolower(c);

    for (const auto& name : g_cachedClassNames) {
        if (prefix.empty()) {
            results.push_back(name);
        } else {
            std::string nameLower = name;
            for (char& c : nameLower) c = tolower(c);
            if (nameLower.rfind(prefixLower, 0) == 0) {
                results.push_back(name);
            }
        }
        if (results.size() >= limit) break;
    }
    return results;
}

int64_t ParsePtr(JSContext* ctx, JSValueConst val) {
    if (JS_IsBigInt(ctx, val)) {
        int64_t v = 0;
        JS_ToBigInt64(ctx, &v, val);
        return v;
    }
    if (JS_IsNumber(val)) {
        double d = 0;
        JS_ToFloat64(ctx, &d, val);
        return static_cast<int64_t>(d);
    }
    if (JS_IsString(val)) {
        const char* s = JS_ToCString(ctx, val);
        if (s) {
            int64_t v = 0;
            if (s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) {
                v = static_cast<int64_t>(strtoull(s, nullptr, 16));
            } else {
                v = static_cast<int64_t>(strtoull(s, nullptr, 10));
            }
            JS_FreeCString(ctx, s);
            return v;
        }
    }
    return 0;
}

JSValue NewBigIntOrInt(JSContext* ctx, uint64_t val) {
    return JS_NewBigUint64(ctx, val);
}

static JSValue JsConsoleLog(JSContext* ctx, JSValueConst /*this_val*/, int argc, JSValueConst* argv) {
    std::string out;
    for (int i = 0; i < argc; i++) {
        if (i > 0) out += " ";
        const char* str = JS_ToCString(ctx, argv[i]);
        if (str) {
            out += str;
            JS_FreeCString(ctx, str);
        }
    }
    BroadcastLog("console", out);
    return JS_UNDEFINED;
}

void InstallConsole(JSContext* ctx) {
    JSValue global = JS_GetGlobalObject(ctx);
    JSValue console = JS_NewObject(ctx);
    JS_SetPropertyStr(ctx, console, "log", JS_NewCFunction(ctx, JsConsoleLog, "log", 1));
    JS_SetPropertyStr(ctx, console, "info", JS_NewCFunction(ctx, JsConsoleLog, "info", 1));
    JS_SetPropertyStr(ctx, console, "warn", JS_NewCFunction(ctx, JsConsoleLog, "warn", 1));
    JS_SetPropertyStr(ctx, console, "error", JS_NewCFunction(ctx, JsConsoleLog, "error", 1));
    JS_SetPropertyStr(ctx, global, "console", console);
    JS_FreeValue(ctx, global);
}

int AgentReleaseMethodInstrumentation(void* artMethod) {
    if (!artMethod) return 0;
    int released = 0;
    if (JavaUnhookMethod(artMethod)) released |= 1;
    if (TraceStopByArtMethod(artMethod)) released |= 2;
    if (BreakpointClearByArtMethod(artMethod)) released |= 4;
    return released;
}

std::string FormatReleasedInstrumentation(int mask) {
    std::string what;
    if (mask & 1) what += "hook";
    if (mask & 2) what += (what.empty() ? "trace" : ", trace");
    if (mask & 4) what += (what.empty() ? "breakpoint" : ", breakpoint");
    return what;
}

}} // namespace artpi::agent
