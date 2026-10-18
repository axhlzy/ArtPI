//
// agent_java_resolve.cpp - Class & Method resolution, classloader enumeration & metadata
//
#include "agent_java_resolve.h"
#include "agent_java_ref.h"
#include "agent_common.h"
#include "../../include/ArtPI.h"
#include "art/art_method.h"
#include "dex/pi_dex_resolver.h"
#include "dex/pi_dex_loader.h"
#include "levenshtein.h"

#include <sstream>
#include <vector>
#include <string>
#include <mutex>
#include <algorithm>
#include <unordered_map>
#include <unordered_set>
#include <cstring>
#include <sys/uio.h>
#include <sys/syscall.h>
#include <unistd.h>

namespace artpi { namespace agent {

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

std::string FormatModifiers(uint32_t f) {
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

bool MatchPatternSubstr(const std::string& str, const std::string& pattern) {
    if (pattern.empty() || pattern == "*") return true;
    size_t start = 0;
    while (start <= pattern.size()) {
        size_t bar = pattern.find('|', start);
        std::string term = (bar == std::string::npos)
                               ? pattern.substr(start)
                               : pattern.substr(start, bar - start);
        size_t first = term.find_first_not_of(" \t");
        if (first != std::string::npos) {
            size_t last = term.find_last_not_of(" \t");
            term = term.substr(first, last - first + 1);
        } else {
            term.clear();
        }
        if (!term.empty()) {
            if (term == "*") return true;
            if (term[0] == '=' && term.size() > 1) {
                if (MatchWildcard(str, term.substr(1))) return true;
            } else if (term.find('*') != std::string::npos || term.find('?') != std::string::npos) {
                if (MatchWildcard(str, term)) return true;
            } else {
                if (MatchWildcard(str, "*" + term + "*")) return true;
            }
        }
        if (bar == std::string::npos) break;
        start = bar + 1;
    }
    return false;
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

            bool match = false;
            if (pattern.empty() || pattern == "*") {
                match = true;
            } else if (pattern.find('(') != std::string::npos || pattern.find(' ') != std::string::npos) {
                match = MatchPatternSubstr(desc, pattern);
            } else {
                match = MatchPatternSubstr(nameStr, pattern);
            }
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

static std::string DescriptorToDotName(const char* desc) {
    if (!desc || desc[0] != 'L') return "";
    size_t len = std::strlen(desc);
    if (len <= 2 || desc[len - 1] != ';') return "";
    std::string out(desc + 1, len - 2);
    for (char& c : out) {
        if (c == '/') c = '.';
    }
    return out;
}

static std::vector<const void*> CollectAppNativeDexFiles(JNIEnv* env) {
    std::vector<const void*> result;
    if (!env) return result;
    jobject cl = GetAppClassLoader(env);
    if (!cl) return result;

    jclass baseCls = env->FindClass("dalvik/system/BaseDexClassLoader");
    if (env->ExceptionCheck()) { env->ExceptionClear(); baseCls = nullptr; }
    jfieldID pathListField = baseCls ? env->GetFieldID(baseCls, "pathList", "Ldalvik/system/DexPathList;") : nullptr;
    if (env->ExceptionCheck()) env->ExceptionClear();
    jobject pathList = pathListField ? env->GetObjectField(cl, pathListField) : nullptr;
    if (env->ExceptionCheck()) { env->ExceptionClear(); pathList = nullptr; }

    jclass dplCls = env->FindClass("dalvik/system/DexPathList");
    if (env->ExceptionCheck()) { env->ExceptionClear(); dplCls = nullptr; }
    jfieldID dexElementsField = dplCls ? env->GetFieldID(dplCls, "dexElements", "[Ldalvik/system/DexPathList$Element;") : nullptr;
    if (env->ExceptionCheck()) env->ExceptionClear();

    if (!pathList || !dexElementsField) {
        if (baseCls) env->DeleteLocalRef(baseCls);
        if (dplCls) env->DeleteLocalRef(dplCls);
        if (pathList) env->DeleteLocalRef(pathList);
        return result;
    }

    auto dexElements = (jobjectArray)env->GetObjectField(pathList, dexElementsField);
    if (env->ExceptionCheck()) { env->ExceptionClear(); dexElements = nullptr; }

    jclass elemCls = env->FindClass("dalvik/system/DexPathList$Element");
    if (env->ExceptionCheck()) { env->ExceptionClear(); elemCls = nullptr; }
    jfieldID dexFileField = elemCls ? env->GetFieldID(elemCls, "dexFile", "Ldalvik/system/DexFile;") : nullptr;
    if (env->ExceptionCheck()) env->ExceptionClear();

    jclass dexFileCls = env->FindClass("dalvik/system/DexFile");
    if (env->ExceptionCheck()) { env->ExceptionClear(); dexFileCls = nullptr; }
    jfieldID internalCookieField = dexFileCls ? env->GetFieldID(dexFileCls, "mInternalCookie", "Ljava/lang/Object;") : nullptr;
    if (env->ExceptionCheck()) env->ExceptionClear();
    jfieldID cookieField = dexFileCls ? env->GetFieldID(dexFileCls, "mCookie", "Ljava/lang/Object;") : nullptr;
    if (env->ExceptionCheck()) env->ExceptionClear();
    if (dexFileCls) env->DeleteLocalRef(dexFileCls);

    std::unordered_set<const void*> seen;
    auto collectCookie = [&](jobject df, jfieldID fid) {
        if (!fid) return;
        jobject cookie = env->GetObjectField(df, fid);
        if (env->ExceptionCheck()) { env->ExceptionClear(); cookie = nullptr; }
        if (!cookie) return;
        jclass ccls = env->GetObjectClass(cookie);
        if (env->ExceptionCheck()) { env->ExceptionClear(); ccls = nullptr; }
        if (ccls) {
            jclass classCls = AgentCachedClass("java/lang/Class");
            if (!classCls) classCls = env->FindClass("java/lang/Class");
            jmethodID gn = classCls ? env->GetMethodID(classCls, "getName", "()Ljava/lang/String;") : nullptr;
            if (env->ExceptionCheck()) env->ExceptionClear();
            jstring jn = gn ? (jstring)env->CallObjectMethod(ccls, gn) : nullptr;
            if (env->ExceptionCheck()) { env->ExceptionClear(); jn = nullptr; }
            bool isLongArr = false;
            if (jn) {
                const char* cs = env->GetStringUTFChars(jn, nullptr);
                if (cs && std::strcmp(cs, "[J") == 0) isLongArr = true;
                if (cs) env->ReleaseStringUTFChars(jn, cs);
                env->DeleteLocalRef(jn);
            }
            env->DeleteLocalRef(ccls);
            if (isLongArr) {
                jsize n = env->GetArrayLength(reinterpret_cast<jarray>(cookie));
                jlong* data = env->GetLongArrayElements(reinterpret_cast<jlongArray>(cookie), nullptr);
                if (data) {
                    for (jsize k = 0; k < n; ++k) {
                        const void* p = reinterpret_cast<const void*>(static_cast<uintptr_t>(data[k]));
                        if (p && reinterpret_cast<uintptr_t>(p) > 0x10000 && seen.insert(p).second) {
                            result.push_back(p);
                        }
                    }
                    env->ReleaseLongArrayElements(reinterpret_cast<jlongArray>(cookie), data, JNI_ABORT);
                }
            }
        }
        env->DeleteLocalRef(cookie);
    };

    if (dexElements && dexFileField) {
        jsize len = env->GetArrayLength(dexElements);
        for (jsize i = 0; i < len; ++i) {
            jobject elem = env->GetObjectArrayElement(dexElements, i);
            if (!elem) continue;
            jobject df = env->GetObjectField(elem, dexFileField);
            if (env->ExceptionCheck()) { env->ExceptionClear(); df = nullptr; }
            if (df) {
                collectCookie(df, internalCookieField);
                collectCookie(df, cookieField);
                env->DeleteLocalRef(df);
            }
            env->DeleteLocalRef(elem);
        }
    }

    if (dexElements) env->DeleteLocalRef(dexElements);
    if (elemCls) env->DeleteLocalRef(elemCls);
    if (dplCls) env->DeleteLocalRef(dplCls);
    if (baseCls) env->DeleteLocalRef(baseCls);
    env->DeleteLocalRef(pathList);
    return result;
}

std::vector<std::string> FastScanCandidateClasses(JNIEnv* env,
                                                  const std::string& classPattern,
                                                  const std::string& methodPattern,
                                                  bool singleKeywordMode) {
    std::vector<std::string> candidates;
    std::unordered_set<std::string> seenClasses;

    std::vector<const void*> dexPtrs = CollectAppNativeDexFiles(env);
    for (const void* dfp : dexPtrs) {
        struct iovec liov, riov;
        uint8_t fields[0x20];
        liov = { fields, sizeof(fields) };
        riov = { const_cast<void*>(dfp), sizeof(fields) };
        if (syscall(SYS_process_vm_readv, getpid(), &liov, 1, &riov, 1, 0) != sizeof(fields)) continue;
        const uint8_t* dex_begin = *reinterpret_cast<const uint8_t* const*>(fields + 0x08);
        if (!dex_begin) continue;
        uint8_t magic[8];
        liov = { magic, sizeof(magic) };
        riov = { const_cast<uint8_t*>(dex_begin), sizeof(magic) };
        if (syscall(SYS_process_vm_readv, getpid(), &liov, 1, &riov, 1, 0) != sizeof(magic)) continue;
        if (std::memcmp(magic, "dex\n", 4) != 0 && std::memcmp(magic, "cdex", 4) != 0) continue;

        PI::DexResolver resolver;
        if (!resolver.init(dfp)) continue;
        const auto* hdr = resolver.header();
        if (!hdr || !hdr->class_defs_size || !hdr->class_defs_off || !hdr->type_ids_size) continue;

        std::vector<uint8_t> state(hdr->type_ids_size, 0);
        size_t needMethodCheckCount = 0;

        const uint8_t* classDefsBase = dex_begin + hdr->class_defs_off;
        for (uint32_t i = 0; i < hdr->class_defs_size; ++i) {
            uint32_t class_idx = *reinterpret_cast<const uint32_t*>(classDefsBase + i * 32);
            if (class_idx >= hdr->type_ids_size) continue;
            const char* desc = resolver.typeUtf(class_idx);
            if (!desc) continue;
            std::string dotName = DescriptorToDotName(desc);
            if (dotName.empty() || dotName.find("$$ExternalSynthetic") != std::string::npos) continue;

            if (singleKeywordMode) {
                if (MatchPatternSubstr(dotName, methodPattern)) {
                    state[class_idx] = 2;
                    if (seenClasses.insert(dotName).second) candidates.push_back(dotName);
                } else {
                    state[class_idx] = 1;
                    needMethodCheckCount++;
                }
            } else {
                if (!MatchPatternSubstr(dotName, classPattern)) {
                    state[class_idx] = 0;
                } else if (methodPattern.empty() || methodPattern == "*") {
                    state[class_idx] = 2;
                    if (seenClasses.insert(dotName).second) candidates.push_back(dotName);
                } else {
                    state[class_idx] = 1;
                    needMethodCheckCount++;
                }
            }
        }

        if (needMethodCheckCount > 0 && hdr->method_ids_size && hdr->method_ids_off) {
            const auto* methodIds = reinterpret_cast<const PI::DexMethodId*>(dex_begin + hdr->method_ids_off);
            for (uint32_t m = 0; m < hdr->method_ids_size && needMethodCheckCount > 0; ++m) {
                uint16_t cidx = methodIds[m].class_idx;
                if (cidx >= hdr->type_ids_size || state[cidx] != 1) continue;
                const char* mname = resolver.resolveString(methodIds[m].name_idx);
                if (!mname || std::strncmp(mname, "$r8$lambda$", 11) == 0 || std::strncmp(mname, "access$", 7) == 0) {
                    continue;
                }
                if (MatchPatternSubstr(mname, methodPattern)) {
                    state[cidx] = 2;
                    needMethodCheckCount--;
                    const char* desc = resolver.typeUtf(cidx);
                    std::string dotName = DescriptorToDotName(desc);
                    if (!dotName.empty() && seenClasses.insert(dotName).second) {
                        candidates.push_back(dotName);
                    }
                }
            }
        }
    }

    if (dexPtrs.empty()) {
        std::vector<std::string> allNames = EnumerateAppClassNames(env);
        for (const auto& cn : allNames) {
            if (singleKeywordMode || MatchPatternSubstr(cn, classPattern)) {
                candidates.push_back(cn);
            }
        }
    }

    return candidates;
}

static JSValue JsFindClass(JSContext* ctx, JSValueConst /*this_val*/, int argc, JSValueConst* argv) {
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

    if (pattern.find('*') != std::string::npos || pattern.find('?') != std::string::npos) {
        std::vector<std::string> allNames = EnumerateAppClassNames(env);
        static const std::vector<std::string> kSysClasses = {
            "java.lang.String", "java.lang.StringBuilder", "java.lang.StringBuffer",
            "java.lang.Thread", "java.lang.Class", "java.lang.Object",
            "android.app.Activity", "android.app.Application", "android.content.Context",
            "android.os.Bundle", "android.widget.TextView", "android.view.View"
        };
        for (const auto& sc : kSysClasses) allNames.push_back(sc);
        // Generated classes (Java.registerClass) are not part of any app dex,
        // so they never show up in EnumerateAppClassNames().
        for (const auto& gc : PI::DexLoader::ListGeneratedClasses()) allNames.push_back(gc);

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

    // Generated classes (Java.registerClass) are only reachable through the
    // DexLoader registry. Also accept a *simple* name (`GenMem` -> the single
    // generated `com.foo.GenMem`), which is what people type in the REPL.
    if (!localCls && pattern.find('.') == std::string::npos) {
        std::string match;
        bool ambiguous = false;
        for (const auto& gc : PI::DexLoader::ListGeneratedClasses()) {
            if (gc.size() <= pattern.size()) continue;
            if (gc.compare(gc.size() - pattern.size(), pattern.size(), pattern) != 0) continue;
            if (gc[gc.size() - pattern.size() - 1] != '.') continue;
            if (!match.empty()) {
                ambiguous = true;
                break;
            }
            match = gc;
        }
        if (ambiguous) {
            return JS_NewString(ctx, ("[!] '" + pattern +
                "' is ambiguous; use the fully-qualified name").c_str());
        }
        if (!match.empty()) {
            jclass reg = PI::DexLoader::FindGeneratedClass(env, match);
            if (reg != nullptr) {
                localCls = static_cast<jclass>(env->NewLocalRef(reg));
                pattern = match;
            }
        }
    }

    if (!localCls) {
        auto appClasses = EnumerateAppClassNames(env);
        std::vector<std::pair<std::string, double>> ranked;
        for (const auto& cn : appClasses) {
            double sim = artpi::utils::LevenshteinSimilarity(pattern, cn);
            if (sim >= 0.55) {
                ranked.push_back({ cn, sim });
            }
        }
        if (!ranked.empty()) {
            std::sort(ranked.begin(), ranked.end(), [](const auto& a, const auto& b) {
                return a.second > b.second;
            });
            std::ostringstream ss;
            ss << "[!] Class '" << pattern << "' not found. Did you mean:\n";
            for (size_t i = 0; i < std::min<size_t>(ranked.size(), 3); ++i) {
                ss << "    -> " << ranked[i].first << " (" << static_cast<int>(ranked[i].second * 100) << "%)\n";
            }
            return JS_NewString(ctx, ss.str().c_str());
        }
        return JS_NULL;
    }

    jclass gCls = GetOrCreateGlobalClassRef(env, pattern, localCls);
    return JS_NewBigInt64(ctx, reinterpret_cast<int64_t>(gCls));
}

static JSValue JsFindMethod(JSContext* ctx, JSValueConst /*this_val*/, int argc, JSValueConst* argv) {
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
    return JS_NewBigInt64(ctx, reinterpret_cast<int64_t>(m.getArtMethod()));
}

static JSValue JsListMethods(JSContext* ctx, JSValueConst /*this_val*/, int argc, JSValueConst* argv) {
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

static JSValue JsFindMethods(JSContext* ctx, JSValueConst /*this_val*/, int argc, JSValueConst* argv) {
    if (argc < 1) return JS_NewString(ctx, "Usage: findMethods(classOrPattern[, methodPattern])  (methodPattern defaults to \"\")\nExamples:\n  findMethods(\"com.android.boot.MainActivity\")            // all methods of the class\n  findMethods(\"com.android.boot.MainActivity\", \"*Weather*\")\n  findMethods(\"md5\")                                        // search classes/methods containing 'md5'");
    JNIEnv* env = GetEnv();
    if (!env) return JS_NULL;

    std::ostringstream ss;
    int count = 0;

    if (argc == 1) {
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

        jclass exactCls = (arg0.find('|') == std::string::npos) ? FindClassWithFallback(env, arg0) : nullptr;
        if (exactCls) {
            InspectClassMethods(env, exactCls, "", ss, count, 100);
            env->DeleteLocalRef(exactCls);
            if (count == 0) return JS_NewString(ctx, "[*] No declared methods found.");
            return JS_NewString(ctx, ss.str().c_str());
        }

        std::vector<std::string> classNames = FastScanCandidateClasses(env, "", arg0, true);
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

        jclass exactCls = (classSpec.find('*') == std::string::npos &&
                           classSpec.find('?') == std::string::npos &&
                           classSpec.find('|') == std::string::npos)
                              ? FindClassWithFallback(env, classSpec)
                              : nullptr;
        if (exactCls) {
            InspectClassMethods(env, exactCls, methodPattern, ss, count, 100);
            env->DeleteLocalRef(exactCls);
        } else {
            std::vector<std::string> matchedClasses = FastScanCandidateClasses(env, classSpec, methodPattern, false);
            for (const auto& cn : matchedClasses) {
                if (count >= 50) break;
                jclass cls = FindClassWithFallback(env, cn);
                if (cls) {
                    InspectClassMethods(env, cls, methodPattern, ss, count, 50);
                    env->DeleteLocalRef(cls);
                }
            }
        }
    }

    if (count == 0) {
        return JS_NewString(ctx, "[*] No matching methods found.");
    }
    return JS_NewString(ctx, ss.str().c_str());
}

static JSValue JsMethodToArt(JSContext* ctx, JSValueConst /*this_val*/, int argc, JSValueConst* argv) {
    if (argc < 1) return JS_NewString(ctx, "Usage: methodToArt(artMethodPtr)");
    int64_t mid = ParsePtr(ctx, argv[0]);
    if (!mid || mid < 0x10000) {
        return JS_NewString(ctx, "[!] Invalid ArtMethod pointer (null or address below 0x10000)");
    }
    ArtMethod* art = reinterpret_cast<ArtMethod*>(mid);
    return JS_NewBigInt64(ctx, reinterpret_cast<int64_t>(art));
}

static JSValue JsArtToMethod(JSContext* ctx, JSValueConst /*this_val*/, int argc, JSValueConst* argv) {
    if (argc < 1) return JS_NewString(ctx, "Usage: artToMethod(artMethodPtr)");
    int64_t ptr = ParsePtr(ctx, argv[0]);
    if (!ptr || ptr < 0x1000) return JS_NULL;
    return JS_NewBigInt64(ctx, ptr);
}

static JSValue JsMethodInfo(JSContext* ctx, JSValueConst /*this_val*/, int argc, JSValueConst* argv) {
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

static JSValue JsEnumerateClassLoaders(JSContext* ctx, JSValueConst /*this_val*/, int /*argc*/, JSValueConst* /*argv*/) {
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

void RegisterJavaResolveApis(JSContext* ctx, JSValue global, JSValue java) {
    // Java namespace
    JS_SetPropertyStr(ctx, java, "findClass", JS_NewCFunction(ctx, JsFindClass, "findClass", 1));
    JS_SetPropertyStr(ctx, java, "findMethod", JS_NewCFunction(ctx, JsFindMethod, "findMethod", 3));
    JS_SetPropertyStr(ctx, java, "listMethods", JS_NewCFunction(ctx, JsListMethods, "listMethods", 1));
    JS_SetPropertyStr(ctx, java, "findMethods", JS_NewCFunction(ctx, JsFindMethods, "findMethods", 2));
    JS_SetPropertyStr(ctx, java, "methodToArt", JS_NewCFunction(ctx, JsMethodToArt, "methodToArt", 1));
    JS_SetPropertyStr(ctx, java, "artToMethod", JS_NewCFunction(ctx, JsArtToMethod, "artToMethod", 1));
    JS_SetPropertyStr(ctx, java, "methodInfo", JS_NewCFunction(ctx, JsMethodInfo, "methodInfo", 1));
    JS_SetPropertyStr(ctx, java, "enumerateClassLoaders", JS_NewCFunction(ctx, JsEnumerateClassLoaders, "enumerateClassLoaders", 0));

    // Flat global aliases
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
    JS_SetPropertyStr(ctx, global, "methodInfo", JS_NewCFunction(ctx, JsMethodInfo, "methodInfo", 1));
    JS_SetPropertyStr(ctx, global, "methodinfo", JS_NewCFunction(ctx, JsMethodInfo, "methodinfo", 1));
    JS_SetPropertyStr(ctx, global, "enumloaders", JS_NewCFunction(ctx, JsEnumerateClassLoaders, "enumloaders", 0));
}

}} // namespace artpi::agent
