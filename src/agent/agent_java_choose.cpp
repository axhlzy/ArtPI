//
// agent_java_choose.cpp - Heap object instance scanner (JVMTI + direct ART GC heap scanning)
//
#include "agent_java_choose.h"
#include "agent_java_ref.h"
#include "agent_common.h"
#include "../../include/ArtPI.h"
#include "android.h"
#include "art/thread.h"

#include <vector>
#include <string>
#include <sstream>
#include <cstring>
#include <cstdio>

extern "C" {
    jobject PineNative_ToJObject(JNIEnv* env, void* art_obj);
    void* PineNative_ToArtObject(JNIEnv* env, jobject j_obj);
}

namespace artpi { namespace agent {

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
        uintptr_t end = r.end - 16;

        while (cur < end) {
            uint32_t klassWord = *reinterpret_cast<const uint32_t*>(cur);
            if (klassWord == targetKlassWord) {
                uint32_t monitorWord = *reinterpret_cast<const uint32_t*>(cur + 4);
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
            cur += 8;
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

void RegisterJavaChooseApis(JSContext* ctx, JSValue global, JSValue java) {
    JS_SetPropertyStr(ctx, java, "choose", JS_NewCFunction(ctx, JsJavaChoose, "choose", 2));
    JS_SetPropertyStr(ctx, global, "choose", JS_NewCFunction(ctx, JsJavaChoose, "choose", 2));
}

}} // namespace artpi::agent
