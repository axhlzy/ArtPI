//
// pi.h - Modern high-level API for Pine Native (PI Framework)
//
// Usage:
//   PI::resolve(env, clazz, "testMethod", "(Ljava/lang/String;)V").showSmali();
//
//   auto handle = PI::resolve(env, clazz, "testMethod", "(Ljava/lang/String;)V")
//       .hook([](JNIEnv* env, Pine::CallFrame& frame) {
//           ...
//       });
//
//   handle.unhook();
//

#ifndef PI_H
#define PI_H

#include "pi_common.h"
#include "pi_method.h"
#include "pi_hook_handle.h"
#include "dex/pi_smali.h"

namespace PI {

/**
 * Initialize Pine and PI runtime.
 * Automatically called on first resolve() if not already initialized.
 */
bool init(JNIEnv* env = nullptr);
bool isInitialized();

/**
 * Resolve a method by JNIEnv, jclass, name and signature.
 * Automatically detects whether the method is static or virtual/instance.
 */
Method resolve(JNIEnv* env, jclass clazz, const std::string& methodName, const std::string& methodSig);

/**
 * Resolve a method by class name (e.g. "com/example/Test" or "com.example.Test"), name, and signature.
 */
Method resolve(JNIEnv* env, const std::string& className, const std::string& methodName, const std::string& methodSig);

/**
 * Resolve a method using current thread's JNIEnv.
 */
Method resolve(jclass clazz, const std::string& methodName, const std::string& methodSig);
Method resolve(const std::string& className, const std::string& methodName, const std::string& methodSig);

/**
 * Resolve a method from a java.lang.reflect.Method / Constructor jobject.
 */
Method resolve(JNIEnv* env, jobject reflectedMethod);

/**
 * Resolve an ArtMethod pointer directly into a Method wrapper.
 */
Method resolve(ArtMethod* artMethod);

} // namespace PI

#endif // PI_H
