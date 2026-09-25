//
// agent_common.cpp - Shared QuickJS helpers, JNI environment & utility functions
//
#include "agent_common.h"
#include "agent_net.h"
#include <cstring>
#include <algorithm>
#include <vector>

namespace artpi { namespace agent {

JSRuntime* g_rt = nullptr;
JSContext* g_ctx = nullptr;
std::mutex g_jsMutex;
JavaVM* g_jvm = nullptr;

static jobject g_appClassLoader = nullptr;
static std::mutex g_clMutex;

static std::vector<std::string> g_cachedClassNames;
static std::mutex g_namesMutex;

JNIEnv* GetEnv() {
    if (!g_jvm) return nullptr;
    JNIEnv* env = nullptr;
    jint status = g_jvm->GetEnv(reinterpret_cast<void**>(&env), JNI_VERSION_1_6);
    if (status == JNI_EDETACHED) {
#if defined(__ANDROID__)
        g_jvm->AttachCurrentThread(&env, nullptr);
#else
        g_jvm->AttachCurrentThread(reinterpret_cast<void**>(&env), nullptr);
#endif
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

jclass FindClassWithFallback(JNIEnv* env, const std::string& className) {
    if (className.empty()) return nullptr;
    if (className.find('*') != std::string::npos || className.find('?') != std::string::npos) {
        return nullptr;
    }

    std::string slashName = className;
    std::string dotName = className;
    for (char& c : slashName) if (c == '.') c = '/';
    for (char& c : dotName) if (c == '/') c = '.';

    // 1. Try env->FindClass (works for boot/system classes)
    jclass localCls = env->FindClass(slashName.c_str());
    if (env->ExceptionCheck()) {
        env->ExceptionClear();
        localCls = nullptr;
    }
    if (localCls) return localCls;

    // 2. Fallback: on-demand get App ClassLoader and use loadClass()
    jobject cl = GetAppClassLoader(env);
    if (cl) {
        jclass clCls = env->FindClass("java/lang/ClassLoader");
        if (env->ExceptionCheck()) {
            env->ExceptionClear();
            return nullptr;
        }
        jmethodID loadClassMethod = env->GetMethodID(clCls, "loadClass", "(Ljava/lang/String;)Ljava/lang/Class;");
        if (env->ExceptionCheck()) {
            env->ExceptionClear();
            env->DeleteLocalRef(clCls);
            return nullptr;
        }

        jstring jName = env->NewStringUTF(dotName.c_str());
        auto clsObj = (jclass)env->CallObjectMethod(cl, loadClassMethod, jName);
        if (env->ExceptionCheck()) {
            env->ExceptionClear();
            clsObj = nullptr;
        }
        env->DeleteLocalRef(jName);
        env->DeleteLocalRef(clCls);
        if (clsObj) return clsObj;
    }

    return nullptr;
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
    return JS_NewBigInt64(ctx, static_cast<int64_t>(val));
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

}} // namespace artpi::agent
