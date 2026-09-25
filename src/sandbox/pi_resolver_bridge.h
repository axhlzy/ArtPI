//
// pi_resolver_bridge.h - L2 ResolverBridge
//
// Implements nmmvm's `vmResolver` (6 C callbacks, no user-data pointer) on
// top of PI::DexResolver, backed by per-dex caches:
//   - jmethodID / jfieldID  (valid for the process lifetime)
//   - jclass global refs    (per type_idx)
//   - jstring global refs   (interned via String.intern(), so bytecode
//                            `==` comparisons against literals keep Java
//                            semantics - see nmmp VmTest.constString notes)
//
// Concurrency:
//   - lazy per-slot resolution is guarded by a mutex (first resolve wins,
//     later reads are lock-free on a fully-resolved cache)
//   - the callbacks have no user-data, so the active bridge for the current
//     thread is kept on a thread_local stack (supports nesting: an
//     interpreted run that re-enters via JNI -> hook -> runMethod)
//
// Contract with the interpreter (vm/InterpC-portable.cpp):
//   every object returned by a callback must be a *fresh JNI local ref*;
//   the interpreter stores it in a register and DeleteLocalRef()s it when
//   that register is overwritten.
//

#ifndef PI_RESOLVER_BRIDGE_H
#define PI_RESOLVER_BRIDGE_H

#include "pi_common.h"
#include "dex/pi_dex_resolver.h"
#include "vm.h"
#include <mutex>

namespace PI {

class ResolverBridge {
public:
    ResolverBridge() = default;
    ~ResolverBridge();

    // `dex` must outlive this bridge (dex memory owned by the runtime).
    bool init(const DexResolver* dex);

    const vmResolver* nativeResolver() const { return &kResolver; }
    const DexResolver* dex() const { return dex_; }
    bool isInitialized() const { return initialized_; }

    // RAII: push/pop this bridge as the active one for the current thread.
    class ScopedActive {
    public:
        explicit ScopedActive(ResolverBridge* bridge);
        ~ScopedActive();
        ScopedActive(const ScopedActive&) = delete;
        ScopedActive& operator=(const ScopedActive&) = delete;
    private:
        bool pushed_ = false;
    };

private:
    friend struct BridgeAccess;

    const vmField*  resolveField(JNIEnv* env, u4 idx, bool isStatic);
    const vmMethod* resolveMethod(JNIEnv* env, u4 idx, bool isStatic);
    const char*     resolveTypeUtf(JNIEnv* env, u4 idx);
    jclass          resolveClass(JNIEnv* env, u4 idx);
    jclass          findClass(JNIEnv* env, const char* type);
    jstring         constantString(JNIEnv* env, u4 idx);

    jclass findClassByDescriptor(JNIEnv* env, const char* typeDesc);
    jstring internString(JNIEnv* env, const char* utf);

    const DexResolver* dex_ = nullptr;

    // Lazily filled; sized once in init() so storage never moves.
    std::vector<vmMethod>      methodCache_;
    std::vector<std::string>   shortyStorage_;   // stable storage for shorty
    std::vector<uint8_t>       methodResolved_;

    std::vector<vmField>       fieldCache_;
    std::vector<uint8_t>       fieldResolved_;

    std::vector<jclass>        classCache_;      // global refs
    std::vector<uint8_t>       classResolved_;

    std::vector<jstring>       stringCache_;     // global refs, interned
    std::vector<uint8_t>       stringResolved_;

    jmethodID internMid_ = nullptr;  // java/lang/String.intern()
    std::mutex mutex_;
    bool initialized_ = false;

    static const vmResolver kResolver;
};

// One-time interpreter runtime init (nmmvm GlobalCache: exception classes +
// primitive classes). Call once from PI::init().
bool interpRuntimeInit(JNIEnv* env);

} // namespace PI

#endif // PI_RESOLVER_BRIDGE_H
