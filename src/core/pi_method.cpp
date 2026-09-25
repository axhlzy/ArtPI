//
// pi_method.cpp - Implementation of PI::Method wrapper
//

#include "pi_method.h"
#include "dex/pi_smali.h"
#include "art/art_method.h"
#include "trampoline/trampoline_installer.h"
#include "pine_native.h"
#include <cstring>

namespace PI {

Method::Method() = default;

Method::Method(JNIEnv* env, jclass clazz, jmethodID mid, ArtMethod* artMethod,
               const std::string& name, const std::string& sig, bool isStatic)
    : env_(env), mid_(mid), artMethod_(artMethod),
      name_(name), sig_(sig), isStatic_(isStatic) {
    if (clazz) {
        JNIEnv* e = env ? env : Pine::GetCurrentJNIEnv();
        if (e) {
            jobject gref = e->NewGlobalRef(clazz);
            if (gref) {
                clazz_ref_ = std::shared_ptr<_jobject>(gref, [](jobject ref) {
                    if (ref) {
                        JNIEnv* cur_env = Pine::GetCurrentJNIEnv();
                        if (cur_env) cur_env->DeleteGlobalRef(ref);
                    }
                });
            }
        }
    }
}

jclass Method::getDeclaringClass() const {
    return clazz_ref_ ? static_cast<jclass>(clazz_ref_.get()) : nullptr;
}

HookHandle Method::hook(const Pine::HookCallback& callback) const {
    if (!isValid()) {
        PI_LOGE("Method::hook: Invalid method (ArtMethod is null)");
        return HookHandle();
    }

    JNIEnv* env = env_ ? env_ : Pine::GetCurrentJNIEnv();
    if (!env) {
        PI_LOGE("Method::hook: JNIEnv is null");
        return HookHandle();
    }

    if (!PineNative_IsInitialized()) {
        if (!PineNative_Init(env)) {
            PI_LOGE("Method::hook: Failed to initialize Pine");
            return HookHandle();
        }
    }

    jclass clazz = getDeclaringClass();

    auto impl = std::make_shared<HookHandle::Impl>();
    impl->target = artMethod_;
    impl->orig_access_flags = artMethod_->GetAccessFlags();
    impl->orig_entry_point = artMethod_->GetEntryPointFromCompiledCode();
    impl->orig_interpreter_entry = artMethod_->GetEntryPointFromInterpreter();
    impl->clazz_ref = clazz_ref_;
    impl->global_clazz = clazz;

    // Determine inline vs replacement and save original bytes if inline
    pine::TrampolineInstaller* installer = pine::TrampolineInstaller::GetDefault();
    void* target_code_addr = artMethod_->GetCompiledCodeAddr();
    bool will_inline = installer && !installer->IsReplacementOnly() && !installer->CannotSafeInlineHook(artMethod_);
    impl->is_inline = will_inline;
    impl->target_code_addr = target_code_addr;

    if (will_inline && target_code_addr) {
        impl->orig_bytes_size = installer->GetDirectJumpTrampolineSize();
        if (impl->orig_bytes_size > sizeof(impl->orig_bytes)) {
            impl->orig_bytes_size = sizeof(impl->orig_bytes);
        }
        std::memcpy(impl->orig_bytes, target_code_addr, impl->orig_bytes_size);
    }

    // Call Pine registration with out_backup to capture the backup entry
    void* backup = nullptr;
    bool success = false;
    if (clazz && !name_.empty() && !sig_.empty()) {
        if (isStatic_) {
            success = Pine::registerStaticMethodHookEx(env, clazz, name_, sig_, callback, &backup);
        } else {
            success = Pine::registerMethodHookEx(env, clazz, name_, sig_, callback, &backup);
        }
    }
    if (!success) {
        // Direct ArtMethod hook fallback: bypasses JNI reflection method lookup
        success = Pine::registerArtMethodHookDirect(env, artMethod_, getDeclaringClassName(),
                                                    name_, sig_, isStatic_, clazz, mid_,
                                                    callback, &backup);
    }

    if (!success || !backup) {
        PI_LOGE("Method::hook: Hook installation failed for %s%s (ArtMethod=%p)",
                name_.c_str(), sig_.c_str(), artMethod_);
        return HookHandle();
    }

    impl->backup = backup;
    impl->is_hooked = true;

    PI_LOGI("Method::hook: Successfully hooked %s%s (backup=%p, is_inline=%d)",
            name_.c_str(), sig_.c_str(), backup, will_inline);

    return HookHandle(impl);
}

void Method::showSmali(int max_instructions, const char* tag) const {
    if (!artMethod_) {
        PI_LOGE("Method::showSmali: ArtMethod is null");
        return;
    }
    PI::showSmali(artMethod_, max_instructions, tag);
}

std::string Method::dumpSmali(int max_instructions) const {
    if (!artMethod_) {
        return "[PI] Method::dumpSmali: ArtMethod is null\n";
    }
    return PI::dumpSmali(artMethod_, max_instructions);
}

std::string Method::dumpNative(int max_instructions) const {
    if (!artMethod_) {
        return "[PI] Method::dumpNative: ArtMethod is null\n";
    }
    return PI::dumpNative(artMethod_, max_instructions);
}

std::string Method::dumpCode(int max_instructions) const {
    if (!artMethod_) {
        return "[PI] Method::dumpCode: ArtMethod is null\n";
    }
    return PI::dumpCode(artMethod_, max_instructions);
}

HookHandle Method::trace(const char* tag) const {
    const std::string log_tag = (tag && *tag) ? tag : "ArtPI_Trace";
    return hook([log_tag](JNIEnv* /*env*/, Pine::CallFrame& frame) {
        PI_LOGI("[%s Entry] %s", log_tag.c_str(), frame.toValueString().c_str());
        frame.printJavaStackTrace(log_tag.c_str());
        frame.callOriginal();
        PI_LOGI("[%s Exit] %s returned: %s", log_tag.c_str(),
                frame.getMethodName().c_str(), frame.getResultString().c_str());
    });
}

std::string Method::getDeclaringClassName() const {
    jclass clazz = getDeclaringClass();
    if (!clazz) return "";
    JNIEnv* env = env_ ? env_ : Pine::GetCurrentJNIEnv();
    if (env) {
        jclass clazzClass = env->GetObjectClass(clazz);
        if (clazzClass) {
            jmethodID getNameMid = env->GetMethodID(clazzClass, "getName", "()Ljava/lang/String;");
            if (getNameMid) {
                jstring name = reinterpret_cast<jstring>(env->CallObjectMethod(clazz, getNameMid));
                if (name) {
                    const char* chars = env->GetStringUTFChars(name, nullptr);
                    std::string str(chars ? chars : "");
                    if (chars) env->ReleaseStringUTFChars(name, chars);
                    env->DeleteLocalRef(name);
                    env->DeleteLocalRef(clazzClass);
                    return str;
                }
            }
            env->DeleteLocalRef(clazzClass);
        }
        if (env->ExceptionCheck()) env->ExceptionClear();
    }
    return "";
}

bool Method::isNative() const {
    return artMethod_ ? artMethod_->IsNative() : false;
}

bool Method::isCompiled() const {
    return artMethod_ ? artMethod_->IsCompiled() : false;
}

uint32_t Method::getAccessFlags() const {
    return artMethod_ ? artMethod_->GetAccessFlags() : 0;
}

std::string Method::toString() const {
    if (!artMethod_) return "Method(null)";
    std::string cl = getDeclaringClassName();
    if (!cl.empty()) {
        return cl + "." + name_ + sig_;
    }
    if (!name_.empty()) {
        return name_ + sig_;
    }
    char buf[64];
    snprintf(buf, sizeof(buf), "ArtMethod@%p", artMethod_);
    return std::string(buf);
}

} // namespace PI
