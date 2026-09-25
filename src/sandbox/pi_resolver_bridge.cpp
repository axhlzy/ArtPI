//
// pi_resolver_bridge.cpp - L2 ResolverBridge implementation
//

#include "pi_resolver_bridge.h"
#include "pi_interp_tracer.h"   // PI::Interp::FindClassRefCached (hook-path safe lookup)
#include "GlobalCache.h"   // nmmvm GlobalCache (gVm, cacheInitial) via nmmvm/include
#include <cstring>

namespace PI {

// ============================================================================
// Active-bridge stack (thread_local)
// ============================================================================
namespace {
    std::vector<ResolverBridge*>& activeStack() {
        static thread_local std::vector<ResolverBridge*> stack;
        return stack;
    }

    ResolverBridge* currentBridge() {
        auto& s = activeStack();
        return s.empty() ? nullptr : s.back();
    }
}

ResolverBridge::ScopedActive::ScopedActive(ResolverBridge* bridge) {
    if (bridge != nullptr) {
        activeStack().push_back(bridge);
        pushed_ = true;
    }
}

ResolverBridge::ScopedActive::~ScopedActive() {
    if (pushed_) {
        auto& s = activeStack();
        if (!s.empty()) s.pop_back();
    }
}

// ============================================================================
// Helpers
// ============================================================================
namespace {

// "Lcom/foo/Bar;" -> "com/foo/Bar";  "[x" / primitives -> unchanged
void descriptorToJniName(const char* desc, std::string& out) {
    out.clear();
    if (desc == nullptr || desc[0] != 'L') {
        out = desc ? desc : "";
        return;
    }
    size_t len = strlen(desc);
    if (len >= 2) {
        out.assign(desc + 1, len - 2);
    }
}

} // namespace

// ============================================================================
// Lifecycle
// ============================================================================
ResolverBridge::~ResolverBridge() {
    // Global refs are leaked intentionally: the runtime dex may outlive us
    // and JNI global refs cannot be deleted without an env anyway.
}

bool ResolverBridge::init(const DexResolver* dex) {
    if (dex == nullptr || !dex->isValid()) {
        PI_LOGE("ResolverBridge::init: dex resolver invalid");
        return false;
    }
    dex_ = dex;
    const auto* header = dex_->header();

    methodCache_.resize(header->method_ids_size);
    shortyStorage_.resize(header->method_ids_size);
    methodResolved_.assign(header->method_ids_size, 0);

    fieldCache_.resize(header->field_ids_size);
    fieldResolved_.assign(header->field_ids_size, 0);

    classCache_.resize(header->type_ids_size);
    classResolved_.assign(header->type_ids_size, 0);

    stringCache_.resize(header->string_ids_size);
    stringResolved_.assign(header->string_ids_size, 0);

    initialized_ = true;
    return true;
}

// ============================================================================
// Callbacks
// ============================================================================
const vmMethod* ResolverBridge::resolveMethod(JNIEnv* env, u4 idx, bool isStatic) {
    if (!initialized_ || idx >= methodCache_.size()) return nullptr;

    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (!methodResolved_[idx]) {
            MethodRef ref = dex_->resolveMethod(idx);
            if (!ref.isValid()) return nullptr;

            jclass clazz = findClassByDescriptor(env, ref.class_descriptor.c_str());
            if (clazz == nullptr) return nullptr;

            jmethodID mid = isStatic
                ? env->GetStaticMethodID(clazz, ref.name.c_str(), ref.jni_signature.c_str())
                : env->GetMethodID(clazz, ref.name.c_str(), ref.jni_signature.c_str());
            env->DeleteLocalRef(clazz);
            if (mid == nullptr) return nullptr;

            shortyStorage_[idx] = ref.shorty;  // stable storage
            vmMethod& vm = methodCache_[idx];
            // real declaring-class type index: the interpreter re-resolves
            // this class for invoke-direct/super (CallNonvirtual*)
            vm.classIdx = static_cast<u2>(dex_->methodClassIdx(idx));
            vm.idx = idx;                      // tracer naming / StepIn
            vm.shorty = shortyStorage_[idx].c_str();
            vm.methodId = mid;
            methodResolved_[idx] = 1;
        }
    }
    return &methodCache_[idx];
}

const vmField* ResolverBridge::resolveField(JNIEnv* env, u4 idx, bool isStatic) {
    if (!initialized_ || idx >= fieldCache_.size()) return nullptr;

    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (!fieldResolved_[idx]) {
            FieldRef ref = dex_->resolveField(idx);
            if (!ref.isValid()) return nullptr;

            jclass clazz = findClassByDescriptor(env, ref.class_descriptor.c_str());
            if (clazz == nullptr) return nullptr;

            jfieldID fid = isStatic
                ? env->GetStaticFieldID(clazz, ref.name.c_str(), ref.type.c_str())
                : env->GetFieldID(clazz, ref.name.c_str(), ref.type.c_str());
            env->DeleteLocalRef(clazz);
            if (fid == nullptr) return nullptr;

            vmField& vf = fieldCache_[idx];
            // real declaring-class type index: sget/sput re-resolve it
            vf.classIdx = static_cast<u2>(dex_->fieldClassIdx(idx));
            vf.type = ref.type.empty() ? 'L' : ref.type[0];
            vf.fieldId = fid;
            fieldResolved_[idx] = 1;
        }
    }
    return &fieldCache_[idx];
}

const char* ResolverBridge::resolveTypeUtf(JNIEnv* /*env*/, u4 idx) {
    if (!initialized_) return nullptr;
    // Zero-copy: the descriptor lives in the dex image and is NUL-terminated.
    return dex_->typeUtf(idx);
}

jclass ResolverBridge::resolveClass(JNIEnv* env, u4 idx) {
    if (!initialized_ || idx >= classCache_.size()) return nullptr;

    jclass global = nullptr;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (!classResolved_[idx]) {
            std::string desc = dex_->resolveType(idx);
            if (desc.empty()) {
                classResolved_[idx] = 1;  // remember failure
            } else {
                jclass local = findClassByDescriptor(env, desc.c_str());
                if (local != nullptr) {
                    classCache_[idx] = (jclass) env->NewGlobalRef(local);
                    env->DeleteLocalRef(local);
                }
                classResolved_[idx] = 1;
            }
        }
        global = classCache_[idx];
    }
    // Always hand out a fresh local ref: the interpreter owns & deletes it.
    return global ? (jclass) env->NewLocalRef(global) : nullptr;
}

jclass ResolverBridge::findClass(JNIEnv* env, const char* type) {
    jclass c = findClassByDescriptor(env, type);
    // `type` is already a descriptor; result must be a fresh local ref, and
    // findClassByDescriptor already returns one.
    return c;
}

jstring ResolverBridge::constantString(JNIEnv* env, u4 idx) {
    if (!initialized_ || idx >= stringCache_.size()) return nullptr;

    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (!stringResolved_[idx]) {
            const char* utf = dex_->resolveString(idx);
            if (utf != nullptr) {
                jstring interned = internString(env, utf);
                if (interned != nullptr) {
                    stringCache_[idx] = (jstring) env->NewGlobalRef(interned);
                    env->DeleteLocalRef(interned);
                }
            }
            stringResolved_[idx] = 1;
        }
    }

    jstring global = stringCache_[idx];
    // Fresh local ref per call so the interpreter can DeleteLocalRef freely;
    // identity (==) is preserved because all refs alias the interned global.
    return global ? (jstring) env->NewLocalRef(global) : nullptr;
}

// ============================================================================
// Class / string helpers
// ============================================================================
jclass ResolverBridge::findClassByDescriptor(JNIEnv* env, const char* typeDesc) {
    if (typeDesc == nullptr || typeDesc[0] == '\0') return nullptr;

    // Primitive classes come from the nmmvm GlobalCache (initialized at init).
    switch (typeDesc[0]) {
        case 'Z': case 'B': case 'C': case 'S':
        case 'I': case 'J': case 'F': case 'D': {
            jclass g = ::getCacheClass(env, typeDesc);
            return g ? (jclass) env->NewLocalRef(g) : nullptr;
        }
        case 'V':
            return nullptr;
        default:
            break;
    }

    if (typeDesc[0] == '[') {
        // JNI FindClass accepts array descriptors verbatim.
        jclass g = PI::Interp::FindClassRefCached(env, typeDesc);
        return g ? (jclass) env->NewLocalRef(g) : nullptr;
    }

    std::string jniName;
    descriptorToJniName(typeDesc, jniName);
    jclass g = PI::Interp::FindClassRefCached(env, jniName.c_str());
    return g ? (jclass) env->NewLocalRef(g) : nullptr;
}

jstring ResolverBridge::internString(JNIEnv* env, const char* utf) {
    if (internMid_ == nullptr) {
        // Must NOT use env->FindClass() here: this runs on the interpreter/hook
        // path (frameless) where FindClass walks a bogus managed stack and aborts.
        jclass strClass = PI::Interp::FindClassRefCached(env, "java/lang/String");  // global ref, do not delete
        if (strClass == nullptr) return nullptr;
        internMid_ = env->GetMethodID(strClass, "intern", "()Ljava/lang/String;");
        if (internMid_ == nullptr && env->ExceptionCheck()) env->ExceptionClear();
    }

    jstring local = env->NewStringUTF(utf);
    if (local == nullptr) return nullptr;
    if (internMid_ == nullptr) return local;  // degraded: non-interned

    jstring interned = (jstring) env->CallObjectMethod(local, internMid_);
    env->DeleteLocalRef(local);
    return interned;
}

// ============================================================================
// C trampolines (vmResolver has no user-data pointer)
// ============================================================================
const vmResolver ResolverBridge::kResolver = {
    .dvmResolveField = [](JNIEnv* env, u4 idx, bool isStatic) -> const vmField* {
        ResolverBridge* b = currentBridge();
        return b ? b->resolveField(env, idx, isStatic) : nullptr;
    },
    .dvmResolveMethod = [](JNIEnv* env, u4 idx, bool isStatic) -> const vmMethod* {
        ResolverBridge* b = currentBridge();
        return b ? b->resolveMethod(env, idx, isStatic) : nullptr;
    },
    .dvmResolveTypeUtf = [](JNIEnv* env, u4 idx) -> const char* {
        ResolverBridge* b = currentBridge();
        return b ? b->resolveTypeUtf(env, idx) : nullptr;
    },
    .dvmResolveClass = [](JNIEnv* env, u4 idx) -> jclass {
        ResolverBridge* b = currentBridge();
        return b ? b->resolveClass(env, idx) : nullptr;
    },
    .dvmFindClass = [](JNIEnv* env, const char* type) -> jclass {
        ResolverBridge* b = currentBridge();
        return b ? b->findClass(env, type) : nullptr;
    },
    .dvmConstantString = [](JNIEnv* env, u4 idx) -> jstring {
        ResolverBridge* b = currentBridge();
        return b ? b->constantString(env, idx) : nullptr;
    },
};

// ============================================================================
// Runtime init
// ============================================================================
bool interpRuntimeInit(JNIEnv* env) {
    if (env == nullptr) return false;
    ::cacheInitial(env);  // nmmvm GlobalCache: primitive + exception classes
    return true;
}

} // namespace PI
