//
// pi_dex_loader.h - Load a runtime-generated / external .dex image
//
// Strategy:
//   1. Create a private loader over the image:
//        dalvik.system.InMemoryDexClassLoader (API 26+, direct ByteBuffer)
//        dalvik.system.DexClassLoader         (fallback: app code_cache dir)
//   2. (default) Splice that loader's DexPathList.Element[] into the app
//      (or caller supplied) PathClassLoader, so `env->FindClass` / Class.forName
//      / the app's own code can resolve the classes. The class is then DEFINED
//      by the app loader -> a single Class object, no cross-loader casts.
//
// Also owns the class registry: classes defined by an *isolated* loader (when
// splicing fails) are invisible to env->FindClass, so FindClassWithFallback()
// and the nmmvm class-ref cache consult this registry by name.
//

#ifndef PI_DEX_LOADER_H
#define PI_DEX_LOADER_H

#include <jni.h>
#include <cstdint>
#include <string>
#include <vector>

namespace PI {
namespace DexLoader {

struct LoadOptions {
    // Splice the dex elements into the app PathClassLoader (default on).
    bool inject_into_app_loader = true;
    // Put the new elements *before* the existing ones (app classes then lose
    // precedence on name conflicts; only useful for deliberate overrides).
    bool prepend = false;
};

struct LoadedDex {
    // Loader to call loadClass() on. When `injected` is true this is the app
    // loader, otherwise it is a *separate* global ref to `isolated` (so callers
    // may release both without double-deleting). global ref, caller owns.
    jobject loader = nullptr;
    // The private loader used as the DexPathList.Element source (keeps the
    // DexFile alive). global ref, caller owns.
    jobject isolated = nullptr;
    bool injected = false;
};

// Loads `image` (a complete StandardDex file).
// `parent` should be the app ClassLoader (generated classes may reference app
// types); pass nullptr to use the system ClassLoader.
// Returns false and fills `error` on failure.
bool LoadDex(JNIEnv* env,
             const std::vector<uint8_t>& image,
             const std::string& debug_name,
             jobject parent,
             const LoadOptions& options,
             LoadedDex* out,
             std::string* error);

// loader.loadClass(name) with dots or slashes. Returns a global reference and
// registers the class in the generated-class registry. nullptr on failure.
jclass LoadClass(JNIEnv* env, jobject loader, const std::string& name, std::string* error);

// Registers a generated class. The registry takes its OWN global ref (the
// caller keeps ownership of the reference it passes in). It also warms the
// interpreter class cache.
void RegisterGeneratedClass(JNIEnv* env, const std::string& name, jclass cls);

// Looks up a generated class by dotted / slash name. Returns a *global*
// reference (do not DeleteLocalRef) or nullptr.
jclass FindGeneratedClass(JNIEnv* env, const std::string& name);

// Drops the registry entry for `name` (deleting the global ref it owned).
void UnregisterGeneratedClass(JNIEnv* env, const std::string& name);

// Lists registered generated class names (dotted form).
std::vector<std::string> ListGeneratedClasses();

// Debug knob: force the DexClassLoader (disk) fallback even when
// InMemoryDexClassLoader is available. Exposed to JS as __native_dexdisk(1).
void SetForceDisk(bool on);
bool ForceDisk();

// Debug knob: pretend this ROM has no InMemoryDexClassLoader so the exact
// API<26 code path (class lookup fails -> disk fallback) is exercised.
void SetSimulateNoInMemory(bool on);
bool SimulateNoInMemory();

}  // namespace DexLoader
}  // namespace PI

#endif  // PI_DEX_LOADER_H
