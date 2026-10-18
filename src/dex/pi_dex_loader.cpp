//
// pi_dex_loader.cpp - Load a runtime-generated .dex image + class registry
//
// Primary path : dalvik.system.InMemoryDexClassLoader (API 26+)
// Fallback path: write to the app cache dir + dalvik.system.DexClassLoader
//                (API < 26, or ROMs where the in-memory loader is unusable)
//

#include "pi_dex_loader.h"

#include "pi_common.h"
#include "sandbox/pi_interp_tracer.h"

#include <atomic>
#include <cstdio>
#include <cstring>
#include <sys/stat.h>
#include <unistd.h>
#include <map>
#include <memory>
#include <mutex>

namespace PI {
namespace DexLoader {

namespace {

std::mutex g_lock;
std::map<std::string, jclass> g_classes;                  // slash name -> global ref
std::vector<std::unique_ptr<std::vector<uint8_t>>> g_images;  // keeps in-memory dex bytes alive
std::vector<std::string> g_diskFiles;                     // generated .dex paths (kept for the process)
int g_diskCounter = 0;
std::atomic<bool> g_forceDisk{false};
std::atomic<bool> g_simulateNoInMemory{false};

std::string ToSlash(const std::string& name) {
    std::string s = name;
    for (char& c : s) {
        if (c == '.') c = '/';
    }
    if (s.size() > 2 && s.front() == 'L' && s.back() == ';') {
        s = s.substr(1, s.size() - 2);
    }
    return s;
}

std::string ToDotted(const std::string& name) {
    std::string s = ToSlash(name);
    for (char& c : s) {
        if (c == '/') c = '.';
    }
    return s;
}

// ---------------------------------------------------------------------------
// JNI helpers
// ---------------------------------------------------------------------------
jmethodID FindMethod(JNIEnv* env, jclass cls, const char* name, const char* sig,
                     bool isStatic = false) {
    if (cls == nullptr) return nullptr;
    jmethodID mid = isStatic ? env->GetStaticMethodID(cls, name, sig)
                             : env->GetMethodID(cls, name, sig);
    if (env->ExceptionCheck()) env->ExceptionClear();
    return mid;
}

std::string CallStringMethod(JNIEnv* env, jobject obj, jmethodID mid) {
    if (obj == nullptr || mid == nullptr) return "";
    auto js = static_cast<jstring>(env->CallObjectMethod(obj, mid));
    if (env->ExceptionCheck()) {
        env->ExceptionClear();
        return "";
    }
    if (js == nullptr) return "";
    const char* c = env->GetStringUTFChars(js, nullptr);
    std::string out = c != nullptr ? c : "";
    if (c) env->ReleaseStringUTFChars(js, c);
    env->DeleteLocalRef(js);
    return out;
}

// Same contract as artpi::agent::LogAndClearJavaException(), duplicated here
// because this file belongs to the core libartpi (the agent helper lives in
// libartpi_agent, which links us, not the other way around).
void LogAndClearException(JNIEnv* env, const char* where) {
    if (env == nullptr || !env->ExceptionCheck()) return;
    jthrowable ex = env->ExceptionOccurred();
    env->ExceptionClear();
    if (ex == nullptr) return;

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
                PI_LOGW("DexLoader/%s: %s", where != nullptr ? where : "?", msg);
                env->ReleaseStringUTFChars(js, msg);
            }
            env->DeleteLocalRef(js);
        }
    }
    if (thCls) env->DeleteLocalRef(thCls);
    env->DeleteLocalRef(ex);
}


std::string GetAppCacheDir(JNIEnv* env) {
    jclass atCls = env->FindClass("android/app/ActivityThread");
    if (atCls == nullptr) {
        if (env->ExceptionCheck()) env->ExceptionClear();
        return "";
    }
    jmethodID currentApplication = FindMethod(
        env, atCls, "currentApplication", "()Landroid/app/Application;", true);
    jobject app = nullptr;
    if (currentApplication != nullptr) {
        app = env->CallStaticObjectMethod(atCls, currentApplication);
        if (env->ExceptionCheck()) {
            env->ExceptionClear();
            app = nullptr;
        }
    }
    env->DeleteLocalRef(atCls);
    if (app == nullptr) return "";

    jclass fileCls = env->FindClass("java/io/File");
    jmethodID getAbsolutePath = FindMethod(
        env, fileCls, "getAbsolutePath", "()Ljava/lang/String;");

    std::string dir;
    // getCodeCacheDir() (API 21+) is the canonical place for generated dex/odex.
    jclass ctxCls = env->FindClass("android/content/Context");
    const char* candidates[] = {"getCodeCacheDir", "getCacheDir"};
    for (const char* name : candidates) {
        jmethodID get = FindMethod(env, ctxCls, name, "()Ljava/io/File;");
        if (get == nullptr) continue;
        jobject file = env->CallObjectMethod(app, get);
        if (env->ExceptionCheck()) {
            env->ExceptionClear();
            file = nullptr;
        }
        if (file == nullptr) continue;
        dir = CallStringMethod(env, file, getAbsolutePath);
        env->DeleteLocalRef(file);
        if (!dir.empty()) break;
    }

    if (ctxCls) env->DeleteLocalRef(ctxCls);
    if (fileCls) env->DeleteLocalRef(fileCls);
    env->DeleteLocalRef(app);
    return dir;
}

bool WriteDexFile(const std::string& path, const std::vector<uint8_t>& image,
                  std::string* error) {
    FILE* fp = std::fopen(path.c_str(), "wb");
    if (fp == nullptr) {
        if (error) *error = "cannot create " + path;
        return false;
    }
    size_t written = std::fwrite(image.data(), 1, image.size(), fp);
    std::fclose(fp);
    if (written != image.size()) {
        std::remove(path.c_str());
        if (error) *error = "short write to " + path;
        return false;
    }
    // Make sure the dex is readable by the app process (we are already inside
    // it, but some cache dirs are created with restrictive modes).
    ::chmod(path.c_str(), 0644);
    return true;
}

// ---------------------------------------------------------------------------
// Path 1: InMemoryDexClassLoader (API 26+)
// ---------------------------------------------------------------------------
jobject CreateMemoryLoader(JNIEnv* env, const std::vector<uint8_t>& image,
                           jobject parent, std::string* error) {
    if (SimulateNoInMemory()) {
        if (error) *error = "InMemoryDexClassLoader unavailable (simulated API<26)";
        return nullptr;
    }

    jclass loaderCls = env->FindClass("dalvik/system/InMemoryDexClassLoader");
    if (loaderCls == nullptr) {
        if (env->ExceptionCheck()) env->ExceptionClear();
        if (error) *error = "InMemoryDexClassLoader unavailable";
        return nullptr;
    }

    jmethodID ctor = env->GetMethodID(loaderCls, "<init>",
                                      "(Ljava/nio/ByteBuffer;Ljava/lang/ClassLoader;)V");
    if (env->ExceptionCheck() || ctor == nullptr) {
        if (env->ExceptionCheck()) env->ExceptionClear();
        env->DeleteLocalRef(loaderCls);
        if (error) *error = "InMemoryDexClassLoader(ByteBuffer, ClassLoader) not found";
        return nullptr;
    }

    // The loader keeps a reference to the buffer contents and does NOT copy
    // them, so the image must live for the rest of the process.
    auto owned = std::make_unique<std::vector<uint8_t>>(image);
    jobject buffer = env->NewDirectByteBuffer(owned->data(), owned->size());
    if (buffer == nullptr) {
        if (env->ExceptionCheck()) env->ExceptionClear();
        env->DeleteLocalRef(loaderCls);
        if (error) *error = "NewDirectByteBuffer failed";
        return nullptr;
    }

    jobject loader = env->NewObject(loaderCls, ctor, buffer, parent);
    if (env->ExceptionCheck() || loader == nullptr) {
        LogAndClearException(env, "InMemoryDexClassLoader");
        env->DeleteLocalRef(buffer);
        env->DeleteLocalRef(loaderCls);
        if (error) *error = "InMemoryDexClassLoader construction failed (invalid dex?)";
        return nullptr;
    }

    jobject global = env->NewGlobalRef(loader);
    // Keep the buffer object alive too (defensive: some ART versions derive the
    // mapped region from the buffer object's identity).
    env->NewGlobalRef(buffer);
    {
        std::lock_guard<std::mutex> lk(g_lock);
        g_images.push_back(std::move(owned));
    }

    env->DeleteLocalRef(buffer);
    env->DeleteLocalRef(loaderCls);
    env->DeleteLocalRef(loader);
    return global;
}

// ---------------------------------------------------------------------------
// Path 2: DexClassLoader over a file in the app cache dir (API < 26)
// ---------------------------------------------------------------------------
jobject CreateDiskLoader(JNIEnv* env, const std::vector<uint8_t>& image,
                         jobject parent, const std::string& debug_name,
                         std::string* error) {
    std::string dir = GetAppCacheDir(env);
    if (dir.empty()) {
        // Last resort: usable when running as root/shell (app_process tests).
        dir = "/data/local/tmp";
    }

    int index = 0;
    {
        std::lock_guard<std::mutex> lk(g_lock);
        index = g_diskCounter++;
    }

    std::string safeName;
    for (char c : debug_name) {
        safeName += (c == '/' || c == '.' || c == '$') ? '_' : c;
    }
    char suffix[64];
    snprintf(suffix, sizeof(suffix), "-%d-%d.dex", getpid(), index);
    const std::string path = dir + "/artpi-" + safeName + suffix;

    if (!WriteDexFile(path, image, error)) return nullptr;

    jclass loaderCls = env->FindClass("dalvik/system/DexClassLoader");
    if (loaderCls == nullptr) {
        if (env->ExceptionCheck()) env->ExceptionClear();
        std::remove(path.c_str());
        if (error) *error = "DexClassLoader unavailable";
        return nullptr;
    }

    jmethodID ctor = env->GetMethodID(
        loaderCls, "<init>",
        "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/ClassLoader;)V");
    if (env->ExceptionCheck() || ctor == nullptr) {
        if (env->ExceptionCheck()) env->ExceptionClear();
        env->DeleteLocalRef(loaderCls);
        std::remove(path.c_str());
        if (error) *error = "DexClassLoader ctor not found";
        return nullptr;
    }

    jstring dexPath = env->NewStringUTF(path.c_str());
    jstring optimizedDir = env->NewStringUTF(dir.c_str());
    jobject loader = env->NewObject(loaderCls, ctor, dexPath, optimizedDir, nullptr, parent);
    env->DeleteLocalRef(dexPath);
    env->DeleteLocalRef(optimizedDir);
    env->DeleteLocalRef(loaderCls);

    if (env->ExceptionCheck() || loader == nullptr) {
        LogAndClearException(env, "DexClassLoader");
        std::remove(path.c_str());
        if (error) *error = "DexClassLoader construction failed for " + path;
        return nullptr;
    }

    jobject global = env->NewGlobalRef(loader);
    env->DeleteLocalRef(loader);
    {
        std::lock_guard<std::mutex> lk(g_lock);
        g_diskFiles.push_back(path);
    }

    PI_LOGI("DexLoader: disk fallback -> %s", path.c_str());
    return global;
}

// ---------------------------------------------------------------------------
// DexPathList splicing: make the loaded dex visible to the target ClassLoader
// ---------------------------------------------------------------------------
//
// BaseDexClassLoader.pathList (private final) -> DexPathList.dexElements
// (private final Element[]). Both are plain JNI field accesses (no hidden-API
// gate, which only guards java.lang.reflect). The element array is swapped with
// a merged copy; concurrent loadClass() calls that already hold the old array
// keep iterating it, which is safe.
//
// Writing a `final` field is best-effort: ART's release builds accept it, but
// some ROMs may silently ignore it, so every write is verified and retried.
struct PathListAccess {
    jfieldID pathListField = nullptr;     // BaseDexClassLoader.pathList
    jfieldID elementsField = nullptr;     // DexPathList.dexElements
    jobject pathList = nullptr;           // local ref
    jobjectArray elements = nullptr;      // local ref

    void Release(JNIEnv* env) {
        if (elements) env->DeleteLocalRef(elements);
        if (pathList) env->DeleteLocalRef(pathList);
        elements = nullptr;
        pathList = nullptr;
    }
};

bool ResolvePathList(JNIEnv* env, jobject loader, PathListAccess* out) {
    jclass baseCls = env->FindClass("dalvik/system/BaseDexClassLoader");
    if (baseCls == nullptr) {
        if (env->ExceptionCheck()) env->ExceptionClear();
        return false;
    }
    out->pathListField = env->GetFieldID(baseCls, "pathList", "Ldalvik/system/DexPathList;");
    if (env->ExceptionCheck()) env->ExceptionClear();
    env->DeleteLocalRef(baseCls);
    if (out->pathListField == nullptr) return false;

    out->pathList = env->GetObjectField(loader, out->pathListField);
    if (env->ExceptionCheck()) {
        env->ExceptionClear();
        out->pathList = nullptr;
    }
    if (out->pathList == nullptr) return false;

    jclass plCls = env->FindClass("dalvik/system/DexPathList");
    if (plCls == nullptr) {
        if (env->ExceptionCheck()) env->ExceptionClear();
        return false;
    }
    out->elementsField = env->GetFieldID(
        plCls, "dexElements", "[Ldalvik/system/DexPathList$Element;");
    if (env->ExceptionCheck()) env->ExceptionClear();
    env->DeleteLocalRef(plCls);
    if (out->elementsField == nullptr) return false;

    out->elements = static_cast<jobjectArray>(env->GetObjectField(out->pathList, out->elementsField));
    if (env->ExceptionCheck()) {
        env->ExceptionClear();
        out->elements = nullptr;
    }
    return out->elements != nullptr;
}

jobjectArray MergeElementArrays(JNIEnv* env, jobjectArray first, jobjectArray second) {
    jclass elementCls = env->FindClass("dalvik/system/DexPathList$Element");
    if (elementCls == nullptr) {
        if (env->ExceptionCheck()) env->ExceptionClear();
        return nullptr;
    }
    const jsize n1 = first != nullptr ? env->GetArrayLength(first) : 0;
    const jsize n2 = second != nullptr ? env->GetArrayLength(second) : 0;
    auto merged = env->NewObjectArray(n1 + n2, elementCls, nullptr);
    env->DeleteLocalRef(elementCls);
    if (merged == nullptr) {
        if (env->ExceptionCheck()) env->ExceptionClear();
        return nullptr;
    }

    jsize dst = 0;
    for (jsize i = 0; i < n1; ++i) {
        jobject e = env->GetObjectArrayElement(first, i);
        env->SetObjectArrayElement(merged, dst++, e);
        if (e) env->DeleteLocalRef(e);
    }
    for (jsize i = 0; i < n2; ++i) {
        jobject e = env->GetObjectArrayElement(second, i);
        env->SetObjectArrayElement(merged, dst++, e);
        if (e) env->DeleteLocalRef(e);
    }
    if (env->ExceptionCheck()) {
        env->ExceptionClear();
        env->DeleteLocalRef(merged);
        return nullptr;
    }
    return merged;
}

// Reflection fallback: Field.setAccessible(true); Field.set(pathList, merged)
bool SetElementsViaReflection(JNIEnv* env, jobject pathList, jobjectArray merged) {
    jclass classCls = env->FindClass("java/lang/Class");
    jclass fieldCls = env->FindClass("java/lang/reflect/Field");
    if (classCls == nullptr || fieldCls == nullptr) {
        if (env->ExceptionCheck()) env->ExceptionClear();
        if (classCls) env->DeleteLocalRef(classCls);
        if (fieldCls) env->DeleteLocalRef(fieldCls);
        return false;
    }

    jmethodID getDeclaredField = env->GetMethodID(
        classCls, "getDeclaredField", "(Ljava/lang/String;)Ljava/lang/reflect/Field;");
    jmethodID setAccessible = env->GetMethodID(fieldCls, "setAccessible", "(Z)V");
    jmethodID setField = env->GetMethodID(
        fieldCls, "set", "(Ljava/lang/Object;Ljava/lang/Object;)V");
    bool ok = false;

    if (getDeclaredField && setAccessible && setField) {
        jstring name = env->NewStringUTF("dexElements");
        jclass pathListCls = env->GetObjectClass(pathList);
        jobject field = pathListCls != nullptr
            ? env->CallObjectMethod(pathListCls, getDeclaredField, name)
            : nullptr;
        if (pathListCls != nullptr) env->DeleteLocalRef(pathListCls);
        if (env->ExceptionCheck()) env->ExceptionClear();
        if (field != nullptr) {
            env->CallVoidMethod(field, setAccessible, JNI_TRUE);
            if (!env->ExceptionCheck()) {
                env->CallVoidMethod(field, setField, pathList, merged);
            }
            if (env->ExceptionCheck()) env->ExceptionClear();
            else ok = true;
            env->DeleteLocalRef(field);
        }
        if (name) env->DeleteLocalRef(name);
    }
    if (env->ExceptionCheck()) env->ExceptionClear();
    env->DeleteLocalRef(classCls);
    env->DeleteLocalRef(fieldCls);
    return ok;
}

// Splices `sourceLoader`'s dex elements into `targetLoader`. Verified, retried.
bool InjectIntoLoader(JNIEnv* env, jobject sourceLoader, jobject targetLoader,
                      bool prepend, std::string* error) {
    if (sourceLoader == nullptr || targetLoader == nullptr) {
        if (error) *error = "missing loader";
        return false;
    }

    PathListAccess src;
    if (!ResolvePathList(env, sourceLoader, &src)) {
        src.Release(env);
        if (error) *error = "cannot read source DexPathList.dexElements";
        return false;
    }
    jobjectArray extra = static_cast<jobjectArray>(env->NewLocalRef(src.elements));
    src.Release(env);
    if (extra == nullptr) {
        if (error) *error = "empty source dex elements";
        return false;
    }
    const jsize extraCount = env->GetArrayLength(extra);

    bool injected = false;
    // Three attempts: plain JNI write -> reflection write -> JNI write again.
    for (int attempt = 0; attempt < 3 && !injected; ++attempt) {
        PathListAccess dst;
        if (!ResolvePathList(env, targetLoader, &dst)) {
            dst.Release(env);
            if (error) *error = "cannot read target DexPathList.dexElements";
            break;
        }
        const jsize baseCount = env->GetArrayLength(dst.elements);
        const jsize expected = baseCount + extraCount;

        jobjectArray merged = prepend ? MergeElementArrays(env, extra, dst.elements)
                                      : MergeElementArrays(env, dst.elements, extra);
        if (merged == nullptr) {
            dst.Release(env);
            if (error) *error = "element array merge failed";
            continue;
        }

        if (attempt == 1) {
            SetElementsViaReflection(env, dst.pathList, merged);
        } else {
            // Monitor(sync) the loader for the read-modify-write window.
            env->MonitorEnter(targetLoader);
            env->SetObjectField(dst.pathList, dst.elementsField, merged);
            if (env->ExceptionCheck()) env->ExceptionClear();
            env->MonitorExit(targetLoader);
            if (env->ExceptionCheck()) env->ExceptionClear();
        }

        // Verify: re-read the field and compare lengths.
        auto check = static_cast<jobjectArray>(env->GetObjectField(dst.pathList, dst.elementsField));
        if (env->ExceptionCheck()) env->ExceptionClear();
        if (check != nullptr) {
            injected = env->GetArrayLength(check) == expected;
            env->DeleteLocalRef(check);
        }

        env->DeleteLocalRef(merged);
        dst.Release(env);

        if (!injected && attempt < 2) {
            PI_LOGW("DexLoader: dexElements splice attempt %d failed, retrying", attempt + 1);
            usleep(20 * 1000);
        }
    }

    env->DeleteLocalRef(extra);

    if (!injected) {
        if (error) *error = "failed to splice dex elements into the target ClassLoader";
        return false;
    }
    PI_LOGI("DexLoader: spliced %d element(s) into %p (%s)",
            static_cast<int>(extraCount), targetLoader, prepend ? "prepend" : "append");
    return true;
}

}  // namespace

bool LoadDex(JNIEnv* env,
             const std::vector<uint8_t>& image,
             const std::string& debug_name,
             jobject parent,
             const LoadOptions& options,
             LoadedDex* out,
             std::string* error) {
    if (out == nullptr) return false;
    *out = {};
    if (env == nullptr || image.empty()) {
        if (error) *error = "empty dex image";
        return false;
    }

    jobject localParent = parent != nullptr ? env->NewLocalRef(parent) : nullptr;
    if (localParent == nullptr) {
        // Fall back to the system ClassLoader.
        jclass clCls = env->FindClass("java/lang/ClassLoader");
        if (clCls != nullptr) {
            jmethodID getSystem = env->GetStaticMethodID(
                clCls, "getSystemClassLoader", "()Ljava/lang/ClassLoader;");
            if (getSystem != nullptr) {
                localParent = env->CallStaticObjectMethod(clCls, getSystem);
                if (env->ExceptionCheck()) {
                    env->ExceptionClear();
                    localParent = nullptr;
                }
            } else if (env->ExceptionCheck()) {
                env->ExceptionClear();
            }
            env->DeleteLocalRef(clCls);
        } else if (env->ExceptionCheck()) {
            env->ExceptionClear();
        }
    }

    std::string memError;
    jobject loader = nullptr;
    bool used_memory = false;

    // Debug/verification knob: force the disk fallback even on API 26+.
    const bool forceDisk = ForceDisk() || getenv("ARTPI_DEX_DISK") != nullptr;
    if (forceDisk) {
        memError = "forced disk mode";
    } else {
        loader = CreateMemoryLoader(env, image, localParent, &memError);
        used_memory = loader != nullptr;
    }
    if (loader == nullptr) {
        PI_LOGW("DexLoader: in-memory load failed (%s), trying disk fallback", memError.c_str());
        // Clear anything a failed ART call may have thrown before retrying.
        if (env->ExceptionCheck()) env->ExceptionClear();
        std::string diskError;
        loader = CreateDiskLoader(env, image, localParent, debug_name, &diskError);
        if (loader == nullptr && error != nullptr) {
            *error = memError + " / " + diskError;
        }
    }

    if (loader == nullptr) {
        if (localParent != nullptr) env->DeleteLocalRef(localParent);
        return false;
    }

    out->isolated = loader;     // global ref, ownership moves to the caller
    // Keep `loader` a DISTINCT reference from `isolated` even when nothing gets
    // injected, so a caller that releases both can never double-delete.
    if (jobject alias = static_cast<jobject>(env->NewGlobalRef(loader))) {
        out->loader = alias;
    } else {
        // Out of global refs: share the single reference instead of leaking it.
        out->loader = loader;
        out->isolated = nullptr;
    }

    // Splice the dex into the app loader so `env->FindClass`, Class.forName and
    // the app's own code can resolve the classes (single Class object).
    //
    // A DexFile may only be registered with ONE class loader; in release builds
    // ART only warns when a second loader defines from it, but userdebug/eng
    // builds can abort. Memory-backed DexFiles (InMemoryDexClassLoader) are the
    // only path where splicing has been verified, so the file-backed fallback
    // always stays in its private loader.
    if (options.inject_into_app_loader && parent != nullptr && localParent != nullptr) {
        if (!used_memory) {
            PI_LOGW("DexLoader: disk-backed dex cannot be spliced into the app loader "
                    "(one DexFile / one ClassLoader; release ART only warns, "
                    "userdebug/eng may abort); classes stay in the private loader");
        } else {
            std::string injectError;
            if (InjectIntoLoader(env, loader, localParent, options.prepend, &injectError)) {
                jobject appLoaderRef = static_cast<jobject>(env->NewGlobalRef(localParent));
                if (appLoaderRef != nullptr) {
                    out->injected = true;
                    // Drop the alias created above; the app loader replaces it.
                    if (out->loader != nullptr) env->DeleteGlobalRef(out->loader);
                    out->loader = appLoaderRef;
                }
            } else {
                PI_LOGW("DexLoader: %s -> classes stay isolated in the private loader",
                        injectError.c_str());
            }
        }
    }

    if (localParent != nullptr) env->DeleteLocalRef(localParent);

    PI_LOGI("DexLoader: loaded %s (%zu bytes) -> loader %p (injected=%d)",
            debug_name.c_str(), image.size(), out->loader, out->injected ? 1 : 0);
    return true;
}


jclass LoadClass(JNIEnv* env, jobject loader, const std::string& name, std::string* error) {
    if (env == nullptr || loader == nullptr) {
        if (error) *error = "no class loader";
        return nullptr;
    }

    const std::string dotted = ToDotted(name);

    jclass clCls = env->FindClass("java/lang/ClassLoader");
    if (clCls == nullptr) {
        if (env->ExceptionCheck()) env->ExceptionClear();
        if (error) *error = "ClassLoader class unavailable";
        return nullptr;
    }
    jmethodID loadClass = env->GetMethodID(
        clCls, "loadClass", "(Ljava/lang/String;)Ljava/lang/Class;");
    if (loadClass == nullptr) {
        if (env->ExceptionCheck()) env->ExceptionClear();
        env->DeleteLocalRef(clCls);
        if (error) *error = "ClassLoader.loadClass unavailable";
        return nullptr;
    }

    jstring jname = env->NewStringUTF(dotted.c_str());
    auto local = static_cast<jclass>(env->CallObjectMethod(loader, loadClass, jname));
    env->DeleteLocalRef(jname);
    env->DeleteLocalRef(clCls);

    if (env->ExceptionCheck() || local == nullptr) {
        LogAndClearException(env, "loadClass");
        if (error) *error = "loadClass failed: " + dotted;
        return nullptr;
    }

    // The registry keeps its own global ref; the caller owns the one returned.
    RegisterGeneratedClass(env, dotted, local);
    jobject global = env->NewGlobalRef(local);
    env->DeleteLocalRef(local);
    return static_cast<jclass>(global);
}

void RegisterGeneratedClass(JNIEnv* env, const std::string& name, jclass cls) {
    if (cls == nullptr || env == nullptr) return;
    const std::string slash = ToSlash(name);

    // The registry owns its OWN global ref: callers keep ownership of the ref
    // they pass in (avoids double-delete / delete-local-of-global aborts).
    jclass stored = static_cast<jclass>(env->NewGlobalRef(cls));
    if (stored == nullptr) return;

    jclass previous = nullptr;
    {
        std::lock_guard<std::mutex> lk(g_lock);
        auto it = g_classes.find(slash);
        if (it != g_classes.end()) {
            if (it->second == stored) return;
            previous = it->second;
            it->second = stored;
        } else {
            g_classes[slash] = stored;
        }
    }
    if (previous != nullptr) env->DeleteGlobalRef(previous);

    // Make the interpreter able to resolve this class without FindClass()
    // (which walks the managed stack and is unsafe on hook trampolines).
    PI::Interp::RegisterClassRef(env, slash.c_str(), cls);
}

jclass FindGeneratedClass(JNIEnv* env, const std::string& name) {
    const std::string slash = ToSlash(name);
    std::lock_guard<std::mutex> lk(g_lock);
    auto it = g_classes.find(slash);
    if (it == g_classes.end()) return nullptr;
    (void) env;
    return it->second;
}

void UnregisterGeneratedClass(JNIEnv* env, const std::string& name) {
    const std::string slash = ToSlash(name);
    jclass cls = nullptr;
    {
        std::lock_guard<std::mutex> lk(g_lock);
        auto it = g_classes.find(slash);
        if (it == g_classes.end()) return;
        cls = it->second;
        g_classes.erase(it);
    }
    if (cls != nullptr && env != nullptr) env->DeleteGlobalRef(cls);
}

void SetForceDisk(bool on) { g_forceDisk.store(on); }
bool ForceDisk() { return g_forceDisk.load(); }
void SetSimulateNoInMemory(bool on) { g_simulateNoInMemory.store(on); }
bool SimulateNoInMemory() { return g_simulateNoInMemory.load(); }

std::vector<std::string> ListGeneratedClasses() {
    std::vector<std::string> out;
    std::lock_guard<std::mutex> lk(g_lock);
    out.reserve(g_classes.size());
    for (const auto& entry : g_classes) {
        std::string dotted = entry.first;
        for (char& c : dotted) {
            if (c == '/') c = '.';
        }
        out.push_back(dotted);
    }
    return out;
}

}  // namespace DexLoader
}  // namespace PI
