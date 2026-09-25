//
// pi_method.h - Method wrapper for ArtMethod in PI framework
//

#ifndef PI_METHOD_H
#define PI_METHOD_H

#include "pi_common.h"
#include "pi_hook_handle.h"
#include "pine_native.h"

namespace PI {

class Method {
public:
    Method();
    Method(JNIEnv* env, jclass clazz, jmethodID mid, ArtMethod* artMethod,
           const std::string& name, const std::string& sig, bool isStatic);

    bool isValid() const { return artMethod_ != nullptr; }
    explicit operator bool() const { return isValid(); }

    // 1. Hooking: returns HookHandle supporting handle.unhook()
    HookHandle hook(const Pine::HookCallback& callback) const;

    // 2. Code disassembling: Dalvik Smali or Native ARM64
    void showSmali(int max_instructions = -1, const char* tag = "ArtPI") const;
    std::string dumpSmali(int max_instructions = -1) const;
    std::string dumpNative(int max_instructions = -1) const;
    std::string dumpCode(int max_instructions = -1) const;

    // 3. Method Tracing: automatic logging of arguments, backtrace, and return value
    HookHandle trace(const char* tag = "ArtPI_Trace") const;

    // 3. Information getters
    ArtMethod* getArtMethod() const { return artMethod_; }
    jmethodID getMethodId() const { return mid_; }
    jclass getDeclaringClass() const;
    const std::string& getName() const { return name_; }
    const std::string& getSignature() const { return sig_; }
    std::string getDeclaringClassName() const;
    bool isStatic() const { return isStatic_; }
    bool isNative() const;
    bool isCompiled() const;
    uint32_t getAccessFlags() const;
    std::string toString() const;

private:
    JNIEnv* env_ = nullptr;
    std::shared_ptr<_jobject> clazz_ref_;
    jmethodID mid_ = nullptr;
    ArtMethod* artMethod_ = nullptr;
    std::string name_;
    std::string sig_;
    bool isStatic_ = false;
};

} // namespace PI

#endif // PI_METHOD_H
