//
// pi.cpp - High-level PI framework implementation
//

#include "pi.h"
#include "art/art_method.h"
#include "pine_native.h"
#include "native/pi_native.h"
#include "sandbox/pi_interp_executor.h"

namespace PI {

bool init(JNIEnv* env) {
    if (PineNative_IsInitialized()) return true;
    JNIEnv* current_env = env ? env : Pine::GetCurrentJNIEnv();
    if (!current_env) {
        PI_LOGE("PI::init: JNIEnv is null");
        return false;
    }
    if (!PineNative_Init(current_env)) {
        return false;
    }
    // interpreter runtime: primitive + exception class caches
    if (!Interp::init(current_env)) {
        PI_LOGE("PI::init: interpreter runtime init failed");
        return false;
    }
    return true;
}

bool isInitialized() {
    return PineNative_IsInitialized();
}

Method resolve(JNIEnv* env, jclass clazz, const std::string& methodName, const std::string& methodSig) {
    if (!env || !clazz) {
        PI_LOGE("PI::resolve: JNIEnv or jclass is null");
        return Method();
    }

    if (!PineNative_IsInitialized()) {
        if (!PineNative_Init(env)) {
            PI_LOGE("PI::resolve: Failed to initialize Pine");
            return Method();
        }
    }

    // 1. Try instance method first
    bool is_static = false;
    jmethodID mid = env->GetMethodID(clazz, methodName.c_str(), methodSig.c_str());
    if (!mid) {
        if (env->ExceptionCheck()) env->ExceptionClear();
        // 2. Try static method
        mid = env->GetStaticMethodID(clazz, methodName.c_str(), methodSig.c_str());
        if (mid) {
            is_static = true;
        }
    }

    if (!mid) {
        if (env->ExceptionCheck()) env->ExceptionClear();
        PI_LOGE("PI::resolve: Method %s%s not found in class", methodName.c_str(), methodSig.c_str());
        return Method();
    }

    // 3. Resolve underlying ArtMethod* pointer
    ArtMethod* target = ArtMethod::Require(env, clazz, methodName.c_str(), methodSig.c_str(), is_static);
    if (!target) {
        PI_LOGE("PI::resolve: ArtMethod %s%s resolution failed", methodName.c_str(), methodSig.c_str());
        return Method();
    }

    PI_LOGI("PI::resolve: Successfully resolved %s %s%s -> ArtMethod=%p",
            is_static ? "static" : "instance", methodName.c_str(), methodSig.c_str(), target);

    return Method(env, clazz, mid, target, methodName, methodSig, is_static);
}

Method resolve(JNIEnv* env, const std::string& className, const std::string& methodName, const std::string& methodSig) {
    if (!env) {
        PI_LOGE("PI::resolve: JNIEnv is null");
        return Method();
    }

    jclass clazz = Pine::Pine_FindClass(env, className, nullptr);
    if (!clazz) {
        PI_LOGE("PI::resolve: Class %s not found", className.c_str());
        return Method();
    }

    Method m = resolve(env, clazz, methodName, methodSig);
    env->DeleteLocalRef(clazz);
    return m;
}

Method resolve(jclass clazz, const std::string& methodName, const std::string& methodSig) {
    JNIEnv* env = Pine::GetCurrentJNIEnv();
    return resolve(env, clazz, methodName, methodSig);
}

Method resolve(const std::string& className, const std::string& methodName, const std::string& methodSig) {
    JNIEnv* env = Pine::GetCurrentJNIEnv();
    return resolve(env, className, methodName, methodSig);
}

static std::string ClassToJniType(JNIEnv* env, jclass typeCls) {
    if (!env || !typeCls) return "Ljava/lang/Object;";
    jclass clsCls = env->GetObjectClass(typeCls);
    jmethodID getName = clsCls ? env->GetMethodID(clsCls, "getName", "()Ljava/lang/String;") : nullptr;
    if (env->ExceptionCheck()) env->ExceptionClear();
    std::string n;
    if (getName) {
        jstring jn = (jstring)env->CallObjectMethod(typeCls, getName);
        if (env->ExceptionCheck()) env->ExceptionClear();
        if (jn) {
            const char* c = env->GetStringUTFChars(jn, nullptr);
            if (c) { n = c; env->ReleaseStringUTFChars(jn, c); }
            env->DeleteLocalRef(jn);
        }
    }
    if (clsCls) env->DeleteLocalRef(clsCls);
    if (n == "void") return "V";
    if (n == "boolean") return "Z";
    if (n == "byte") return "B";
    if (n == "char") return "C";
    if (n == "short") return "S";
    if (n == "int") return "I";
    if (n == "long") return "J";
    if (n == "float") return "F";
    if (n == "double") return "D";
    if (!n.empty() && n[0] == '[') {
        for (char& ch : n) if (ch == '.') ch = '/';
        return n;
    }
    for (char& ch : n) if (ch == '.') ch = '/';
    return "L" + n + ";";
}

static std::string ReflectedMethodJniSig(JNIEnv* env, jobject reflectedMethod) {
    if (!env || !reflectedMethod) return "";
    jclass methodClass = env->GetObjectClass(reflectedMethod);
    if (!methodClass) return "";
    jmethodID getRet = env->GetMethodID(methodClass, "getReturnType", "()Ljava/lang/Class;");
    jmethodID getParams = env->GetMethodID(methodClass, "getParameterTypes", "()[Ljava/lang/Class;");
    if (env->ExceptionCheck()) env->ExceptionClear();
    std::string sig = "(";
    if (getParams) {
        auto arr = (jobjectArray)env->CallObjectMethod(reflectedMethod, getParams);
        if (env->ExceptionCheck()) env->ExceptionClear();
        if (arr) {
            jsize n = env->GetArrayLength(arr);
            for (jsize i = 0; i < n; i++) {
                jclass t = (jclass)env->GetObjectArrayElement(arr, i);
                if (t) {
                    sig += ClassToJniType(env, t);
                    env->DeleteLocalRef(t);
                }
            }
            env->DeleteLocalRef(arr);
        }
    }
    sig += ")";
    if (getRet) {
        jclass ret = (jclass)env->CallObjectMethod(reflectedMethod, getRet);
        if (env->ExceptionCheck()) env->ExceptionClear();
        if (ret) {
            sig += ClassToJniType(env, ret);
            env->DeleteLocalRef(ret);
        } else {
            sig += "V";
        }
    } else {
        sig += "V";
    }
    env->DeleteLocalRef(methodClass);
    return sig;
}

Method resolve(JNIEnv* env, jobject reflectedMethod) {
    if (!env || !reflectedMethod) {
        PI_LOGE("PI::resolve: reflectedMethod is null");
        return Method();
    }

    if (!PineNative_IsInitialized()) {
        if (!PineNative_Init(env)) return Method();
    }

    ArtMethod* target = ArtMethod::FromReflectedMethod(env, reflectedMethod);
    if (!target) {
        PI_LOGE("PI::resolve: Failed to get ArtMethod from reflected object");
        return Method();
    }

    bool is_static = target->IsStatic();
    std::string name;
    jclass declaringClass = nullptr;
    jclass methodClass = env->GetObjectClass(reflectedMethod);
    if (methodClass) {
        jmethodID getDeclaringClassMid = env->GetMethodID(methodClass, "getDeclaringClass", "()Ljava/lang/Class;");
        if (getDeclaringClassMid) {
            declaringClass = reinterpret_cast<jclass>(env->CallObjectMethod(reflectedMethod, getDeclaringClassMid));
        }
        jmethodID getNameMid = env->GetMethodID(methodClass, "getName", "()Ljava/lang/String;");
        if (getNameMid) {
            jstring jname = reinterpret_cast<jstring>(env->CallObjectMethod(reflectedMethod, getNameMid));
            if (jname) {
                const char* chars = env->GetStringUTFChars(jname, nullptr);
                if (chars) {
                    name = chars;
                    env->ReleaseStringUTFChars(jname, chars);
                }
                env->DeleteLocalRef(jname);
            }
        }
        env->DeleteLocalRef(methodClass);
    }
    if (env->ExceptionCheck()) env->ExceptionClear();

    jmethodID mid = env->FromReflectedMethod(reflectedMethod);
    std::string jni_sig = ReflectedMethodJniSig(env, reflectedMethod);
    Method m(env, declaringClass, mid, target, name, jni_sig, is_static);
    if (declaringClass) env->DeleteLocalRef(declaringClass);
    return m;
}

Method resolve(ArtMethod* artMethod) {
    if (!artMethod) {
        return Method();
    }
    bool is_static = artMethod->IsStatic();

    // Recover declaring class & method identity by matching the ArtMethod pointer
    // against reflection metadata, so that hook() can register via Pine (needs clazz+name+sig).
    JNIEnv* env = Pine::GetCurrentJNIEnv();
    if (!env) {
        char buf[64];
        snprintf(buf, sizeof(buf), "ArtMethod@%p", artMethod);
        return Method(nullptr, nullptr, nullptr, artMethod, buf, "", is_static);
    }

    // 1. Get "ret package.Class.method(params)" via libart PrettyMethod
    std::string full_sig = getPrettyMethodSignature(artMethod);
    std::string class_name, method_name;
    if (!full_sig.empty()) {
        size_t paren = full_sig.find('(');
        if (paren != std::string::npos) {
            size_t dot = full_sig.rfind('.', paren);
            if (dot != std::string::npos) {
                method_name = full_sig.substr(dot + 1, paren - (dot + 1));
                size_t space = full_sig.rfind(' ', dot);
                if (space != std::string::npos) {
                    class_name = full_sig.substr(space + 1, dot - (space + 1));
                }
            }
        }
    }

    // 2. Load the class and match against its declared methods to build a full Method
    if (!class_name.empty() && !method_name.empty()) {
        jclass clazz = Pine::Pine_FindClass(env, class_name, nullptr);
        if (clazz) {
            jclass classCls = env->FindClass("java/lang/Class");
            if (env->ExceptionCheck()) env->ExceptionClear();

            // Check declared methods
            jmethodID gdm = classCls ? env->GetMethodID(classCls, "getDeclaredMethods", "()[Ljava/lang/reflect/Method;") : nullptr;
            if (env->ExceptionCheck()) env->ExceptionClear();
            if (classCls && gdm) {
                auto methodsArr = (jobjectArray)env->CallObjectMethod(clazz, gdm);
                if (env->ExceptionCheck()) env->ExceptionClear();
                if (methodsArr) {
                    jsize len = env->GetArrayLength(methodsArr);
                    for (jsize i = 0; i < len; i++) {
                        jobject mObj = env->GetObjectArrayElement(methodsArr, i);
                        if (!mObj) continue;
                        ArtMethod* cand = ArtMethod::FromReflectedMethod(env, mObj);
                        if (cand == artMethod) {
                            Method m = resolve(env, mObj);
                            if (m.isValid()) {
                                env->DeleteLocalRef(mObj);
                                env->DeleteLocalRef(methodsArr);
                                env->DeleteLocalRef(classCls);
                                env->DeleteLocalRef(clazz);
                                return m;
                            }
                        }
                        env->DeleteLocalRef(mObj);
                    }
                    env->DeleteLocalRef(methodsArr);
                }
            }

            // Check declared constructors if <init>
            if (method_name == "<init>") {
                jmethodID gdc = classCls ? env->GetMethodID(classCls, "getDeclaredConstructors", "()[Ljava/lang/reflect/Constructor;") : nullptr;
                if (env->ExceptionCheck()) env->ExceptionClear();
                if (classCls && gdc) {
                    auto ctorArr = (jobjectArray)env->CallObjectMethod(clazz, gdc);
                    if (env->ExceptionCheck()) env->ExceptionClear();
                    if (ctorArr) {
                        jsize len = env->GetArrayLength(ctorArr);
                        for (jsize i = 0; i < len; i++) {
                            jobject cObj = env->GetObjectArrayElement(ctorArr, i);
                            if (!cObj) continue;
                            ArtMethod* cand = ArtMethod::FromReflectedMethod(env, cObj);
                            if (cand == artMethod) {
                                Method m = resolve(env, cObj);
                                if (m.isValid()) {
                                    env->DeleteLocalRef(cObj);
                                    env->DeleteLocalRef(ctorArr);
                                    env->DeleteLocalRef(classCls);
                                    env->DeleteLocalRef(clazz);
                                    return m;
                                }
                            }
                            env->DeleteLocalRef(cObj);
                        }
                        env->DeleteLocalRef(ctorArr);
                    }
                }
            }

            if (classCls) env->DeleteLocalRef(classCls);
            // Even if exact reflected Method match failed, we have clazz!
            std::string sig;
            size_t p = full_sig.find('(');
            if (p != std::string::npos) sig = full_sig.substr(p);
            Method m(env, clazz, nullptr, artMethod, method_name, sig, is_static);
            env->DeleteLocalRef(clazz);
            return m;
        }
    }

    std::string mname = method_name.empty() ? "" : method_name;
    if (mname.empty()) {
        char buf[64];
        snprintf(buf, sizeof(buf), "ArtMethod@%p", artMethod);
        mname = buf;
    }
    return Method(nullptr, nullptr, nullptr, artMethod, mname, "", is_static);
}

} // namespace PI
