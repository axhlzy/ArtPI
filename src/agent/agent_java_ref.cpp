//
// agent_java_ref.cpp - JRef dynamic object proxy, class cache & reflection bridge
//
#include "agent_java_ref.h"
#include "agent_common.h"
#include "agent_net.h"
#include "../../include/ArtPI.h"

#include <sstream>
#include <vector>
#include <deque>
#include <string>
#include <mutex>
#include <map>
#include <set>
#include <algorithm>
#include <unordered_map>
#include <unordered_set>
#include <cctype>
#include <cstring>
#include <memory>

extern "C" {
    jobject PineNative_ToJObject(JNIEnv* env, void* art_obj);
    void* PineNative_ToArtObject(JNIEnv* env, jobject j_obj);
}

namespace artpi { namespace agent {

// ---------------------------------------------------------------------------
// Cached class references.
//
// The hook callback runs inside a raw trampoline with no valid ART managed
// stack frame; calling env->FindClass() there walks the managed stack
// (StackVisitor::WalkStack) and SIGSEGVs. So every class used on the hook
// path is resolved ONCE here (init time, valid stack) and cached as a global ref.
// ---------------------------------------------------------------------------
static jclass g_c_Class = nullptr;
static jclass g_c_Field = nullptr;
static jclass g_c_Number = nullptr;
static jclass g_c_Boolean = nullptr;
static jclass g_c_Integer = nullptr;
static jclass g_c_Long = nullptr;
static jclass g_c_Short = nullptr;
static jclass g_c_Byte = nullptr;
static jclass g_c_Character = nullptr;
static jclass g_c_Float = nullptr;
static jclass g_c_Double = nullptr;
static jclass g_c_Throwable = nullptr;
static jclass g_c_Log = nullptr;
static jclass g_c_Method = nullptr;
static jclass g_c_Object = nullptr;

static jclass CacheClassGlobal(JNIEnv* env, const char* name) {
    jclass l = env->FindClass(name);
    if (env->ExceptionCheck()) env->ExceptionClear();
    if (!l) return nullptr;
    jclass g = static_cast<jclass>(env->NewGlobalRef(l));
    env->DeleteLocalRef(l);
    return g;
}

void InitJRefClassCache(JNIEnv* env) {
    if (!env || g_c_Class) return;
    g_c_Class     = CacheClassGlobal(env, "java/lang/Class");
    g_c_Field     = CacheClassGlobal(env, "java/lang/reflect/Field");
    g_c_Number    = CacheClassGlobal(env, "java/lang/Number");
    g_c_Boolean   = CacheClassGlobal(env, "java/lang/Boolean");
    g_c_Integer   = CacheClassGlobal(env, "java/lang/Integer");
    g_c_Long      = CacheClassGlobal(env, "java/lang/Long");
    g_c_Short     = CacheClassGlobal(env, "java/lang/Short");
    g_c_Byte      = CacheClassGlobal(env, "java/lang/Byte");
    g_c_Character = CacheClassGlobal(env, "java/lang/Character");
    g_c_Float     = CacheClassGlobal(env, "java/lang/Float");
    g_c_Double    = CacheClassGlobal(env, "java/lang/Double");
    g_c_Throwable = CacheClassGlobal(env, "java/lang/Throwable");
    g_c_Log       = CacheClassGlobal(env, "android/util/Log");
    g_c_Method    = CacheClassGlobal(env, "java/lang/reflect/Method");
    g_c_Object    = CacheClassGlobal(env, "java/lang/Object");
}

jclass CachedWrapperClass(const char* slashName) {
    if (!slashName) return nullptr;
    if (!std::strcmp(slashName, "java/lang/Boolean"))   return g_c_Boolean;
    if (!std::strcmp(slashName, "java/lang/Integer"))   return g_c_Integer;
    if (!std::strcmp(slashName, "java/lang/Long"))      return g_c_Long;
    if (!std::strcmp(slashName, "java/lang/Short"))     return g_c_Short;
    if (!std::strcmp(slashName, "java/lang/Byte"))      return g_c_Byte;
    if (!std::strcmp(slashName, "java/lang/Character")) return g_c_Character;
    if (!std::strcmp(slashName, "java/lang/Float"))     return g_c_Float;
    if (!std::strcmp(slashName, "java/lang/Double"))    return g_c_Double;
    if (!std::strcmp(slashName, "java/lang/Number"))    return g_c_Number;
    return nullptr;
}

jclass AgentCachedClass(const char* slashName) {
    if (!slashName) return nullptr;
    if (!std::strcmp(slashName, "java/lang/Class"))          return g_c_Class;
    if (!std::strcmp(slashName, "java/lang/reflect/Field"))  return g_c_Field;
    if (!std::strcmp(slashName, "java/lang/Throwable"))      return g_c_Throwable;
    if (!std::strcmp(slashName, "android/util/Log"))        return g_c_Log;
    if (!std::strcmp(slashName, "java/lang/reflect/Method")) return g_c_Method;
    if (!std::strcmp(slashName, "java/lang/Object"))        return g_c_Object;
    return CachedWrapperClass(slashName);
}

// ---------------------------------------------------------------------------
// JRef Storage & Handle Management
// ---------------------------------------------------------------------------
struct JRefEntry {
    jobject obj = nullptr;
    bool isGlobal = false;
    uint64_t originalAddr = 0;
};
static std::mutex g_jrefMutex;
static std::vector<JRefEntry> g_jrefs;

int AddJRef(JNIEnv* env, jobject o, uint64_t addr, bool persistent) {
    if (!env || !o) return -1;
    std::lock_guard<std::mutex> lk(g_jrefMutex);
    if (addr != 0) {
        for (size_t i = 0; i < g_jrefs.size(); i++) {
            if (g_jrefs[i].originalAddr == addr && g_jrefs[i].obj) {
                if (!g_jrefs[i].isGlobal && persistent) {
                    jobject old = g_jrefs[i].obj;
                    g_jrefs[i].obj = env->NewGlobalRef(old);
                    g_jrefs[i].isGlobal = true;
                    env->DeleteLocalRef(old);
                }
                return static_cast<int>(i);
            }
        }
    }
    JRefEntry e;
    e.isGlobal = persistent;
    e.obj = persistent ? env->NewGlobalRef(o) : env->NewLocalRef(o);
    e.originalAddr = addr ? addr : reinterpret_cast<uintptr_t>(o);
    g_jrefs.push_back(e);
    return static_cast<int>(g_jrefs.size()) - 1;
}

jobject GetJRef(int h) {
    std::lock_guard<std::mutex> lk(g_jrefMutex);
    if (h < 0 || h >= static_cast<int>(g_jrefs.size())) return nullptr;
    return g_jrefs[h].obj;
}

uint64_t GetJRefAddr(int h) {
    std::lock_guard<std::mutex> lk(g_jrefMutex);
    if (h < 0 || h >= static_cast<int>(g_jrefs.size())) return 0;
    return g_jrefs[h].originalAddr;
}

size_t GetJRefCount() {
    std::lock_guard<std::mutex> lk(g_jrefMutex);
    return g_jrefs.size();
}

void PopJRefsTo(JNIEnv* env, size_t base) {
    std::lock_guard<std::mutex> lk(g_jrefMutex);
    while (g_jrefs.size() > base) {
        auto& e = g_jrefs.back();
        if (env && e.obj) {
            if (e.isGlobal) env->DeleteGlobalRef(e.obj);
            else env->DeleteLocalRef(e.obj);
        }
        g_jrefs.pop_back();
    }
}

int ExtractJRefHandle(JSContext* ctx, JSValueConst val) {
    if (JS_IsNumber(val)) {
        int h = -1;
        JS_ToInt32(ctx, &h, val);
        return h;
    }
    if (JS_IsBigInt(ctx, val)) {
        int64_t v = -1;
        JS_ToBigInt64(ctx, &v, val);
        return static_cast<int>(v);
    }
    if (JS_IsObject(val)) {
        JSValue hh = JS_GetPropertyStr(ctx, val, "__h");
        if (JS_IsNumber(hh)) {
            int h = -1;
            JS_ToInt32(ctx, &h, hh);
            JS_FreeValue(ctx, hh);
            return h;
        }
        JS_FreeValue(ctx, hh);
    }
    return -1;
}

JSValue CreateJRefValue(JSContext* ctx, int handle) {
    if (handle < 0) return JS_NULL;
    JSValue global = JS_GetGlobalObject(ctx);
    JSValue fn = JS_GetPropertyStr(ctx, global, "__makeJRef");
    JSValue r = JS_NULL;
    if (JS_IsFunction(ctx, fn)) {
        JSValue a = JS_NewInt32(ctx, handle);
        r = JS_Call(ctx, fn, JS_UNDEFINED, 1, &a);
        JS_FreeValue(ctx, a);
    }
    JS_FreeValue(ctx, fn);
    JS_FreeValue(ctx, global);
    return r;
}

// ---------------------------------------------------------------------------
// Observed objects ring buffer (records objects printed in trace/hook logs)
// ---------------------------------------------------------------------------
static std::mutex g_observedMutex;
static std::unordered_map<uint64_t, jobject> g_observedObjects;
static std::deque<std::pair<uint64_t, jobject>> g_observedQueue;

void DoRegisterObservedObject(JNIEnv* env, uint64_t raw, jobject obj) {
    if (!env || !raw || !obj) return;
    std::lock_guard<std::mutex> lk(g_observedMutex);
    auto it = g_observedObjects.find(raw);
    if (it != g_observedObjects.end()) return;

    jobject g = env->NewGlobalRef(obj);
    if (!g) return;

    if (g_observedQueue.size() >= 512) {
        auto old = g_observedQueue.front();
        g_observedQueue.pop_front();
        g_observedObjects.erase(old.first);
        env->DeleteGlobalRef(old.second);
    }

    g_observedObjects[raw] = g;
    g_observedQueue.push_back({raw, g});
}

void RegisterObservedObject(JNIEnv* env, uint64_t raw, jobject obj) {
    DoRegisterObservedObject(env, raw, obj);
}

// ---------------------------------------------------------------------------
// Class Reflection Member Cache
// ---------------------------------------------------------------------------
struct CachedField {
    jfieldID id = nullptr;
    char type = 'L';
    std::string typeName;
    bool isStatic = false;
};
struct CachedMethod {
    jmethodID id = nullptr;
    std::vector<std::string> params;   // type names
    std::string ret;                   // return type name
    bool isStatic = false;
};
struct ClassMembers {
    std::string name;
    std::map<std::string, CachedField> fields;
    std::map<std::string, std::vector<CachedMethod>> methods;
};
static std::map<std::string, ClassMembers> g_memberCache;
static std::mutex g_memberMutex;

static const ClassMembers* LookupMembers(const std::string& cname) {
    std::lock_guard<std::mutex> lk(g_memberMutex);
    auto it = g_memberCache.find(cname);
    return it == g_memberCache.end() ? nullptr : &it->second;
}

std::string JavaClassName(JNIEnv* env, jclass cls) {
    if (!cls || !g_c_Class) return "";
    jmethodID getName = env->GetMethodID(g_c_Class, "getName", "()Ljava/lang/String;");
    std::string n;
    if (getName) {
        auto jn = static_cast<jstring>(env->CallObjectMethod(cls, getName));
        if (jn) {
            const char* c = env->GetStringUTFChars(jn, nullptr);
            if (c) { n = c; env->ReleaseStringUTFChars(jn, c); }
            env->DeleteLocalRef(jn);
        }
    }
    if (env->ExceptionCheck()) env->ExceptionClear();
    return n;
}

static std::string TypeNameToDescriptor(const std::string& tn) {
    if (tn.empty()) return "Ljava/lang/Object;";
    if (tn[0] == '[') {
        std::string d = tn;
        for (char& c : d) if (c == '.') c = '/';
        return d;
    }
    if (tn.size() > 2 && tn.compare(tn.size() - 2, 2, "[]") == 0) {
        return "[" + TypeNameToDescriptor(tn.substr(0, tn.size() - 2));
    }
    if (tn == "int") return "I";
    if (tn == "long") return "J";
    if (tn == "boolean") return "Z";
    if (tn == "byte") return "B";
    if (tn == "char") return "C";
    if (tn == "short") return "S";
    if (tn == "float") return "F";
    if (tn == "double") return "D";
    if (tn == "void") return "V";
    std::string d = "L" + tn + ";";
    for (char& c : d) if (c == '.') c = '/';
    return d;
}

int PrepareClassMembers(JNIEnv* env, jclass cls) {
    if (!env || !cls || !g_c_Class || !g_c_Field || !g_c_Method) return 0;
    std::string cname = JavaClassName(env, cls);
    if (cname.empty()) return 0;
    {
        std::lock_guard<std::mutex> lk(g_memberMutex);
        if (g_memberCache.count(cname)) return (int) g_memberCache[cname].fields.size();
    }

    ClassMembers cm;
    cm.name = cname;

    jclass cur = static_cast<jclass>(env->NewLocalRef(cls));
    while (cur) {
        // Enumerate fields
        jmethodID gdf = env->GetMethodID(g_c_Class, "getDeclaredFields", "()[Ljava/lang/reflect/Field;");
        auto farr = gdf ? static_cast<jobjectArray>(env->CallObjectMethod(cur, gdf)) : nullptr;
        if (env->ExceptionCheck()) { env->ExceptionClear(); farr = nullptr; }
        if (farr) {
            jmethodID fName = env->GetMethodID(g_c_Field, "getName", "()Ljava/lang/String;");
            jmethodID fType = env->GetMethodID(g_c_Field, "getType", "()Ljava/lang/Class;");
            jmethodID fMod  = env->GetMethodID(g_c_Field, "getModifiers", "()I");
            jsize len = env->GetArrayLength(farr);
            for (jsize i = 0; i < len; ++i) {
                jobject f = env->GetObjectArrayElement(farr, i);
                if (!f) continue;
                std::string name;
                if (fName) {
                    auto jn = static_cast<jstring>(env->CallObjectMethod(f, fName));
                    if (jn) {
                        const char* c = env->GetStringUTFChars(jn, nullptr);
                        if (c) { name = c; env->ReleaseStringUTFChars(jn, c); }
                        env->DeleteLocalRef(jn);
                    }
                }
                std::string tname;
                char kind = 'L';
                if (fType) {
                    auto tc = static_cast<jclass>(env->CallObjectMethod(f, fType));
                    if (tc) {
                        tname = JavaClassName(env, tc);
                        if (tname == "int") kind = 'I';
                        else if (tname == "long") kind = 'J';
                        else if (tname == "boolean") kind = 'Z';
                        else if (tname == "byte") kind = 'B';
                        else if (tname == "char") kind = 'C';
                        else if (tname == "short") kind = 'S';
                        else if (tname == "float") kind = 'F';
                        else if (tname == "double") kind = 'D';
                        env->DeleteLocalRef(tc);
                    }
                }
                int mod = fMod ? env->CallIntMethod(f, fMod) : 0;
                if (env->ExceptionCheck()) env->ExceptionClear();
                bool isStatic = (mod & 0x0008) != 0;

                if (!name.empty() && !cm.fields.count(name)) {
                    std::string desc = TypeNameToDescriptor(tname);
                    jfieldID fid = isStatic ? env->GetStaticFieldID(cur, name.c_str(), desc.c_str())
                                            : env->GetFieldID(cur, name.c_str(), desc.c_str());
                    if (env->ExceptionCheck()) env->ExceptionClear();
                    if (fid) {
                        CachedField cf;
                        cf.id = fid;
                        cf.type = kind;
                        cf.typeName = tname;
                        cf.isStatic = isStatic;
                        cm.fields[name] = cf;
                    }
                }
                env->DeleteLocalRef(f);
            }
            env->DeleteLocalRef(farr);
        }

        // Enumerate methods
        jmethodID gdm = env->GetMethodID(g_c_Class, "getDeclaredMethods", "()[Ljava/lang/reflect/Method;");
        auto marr = gdm ? static_cast<jobjectArray>(env->CallObjectMethod(cur, gdm)) : nullptr;
        if (env->ExceptionCheck()) { env->ExceptionClear(); marr = nullptr; }
        if (marr) {
            jmethodID mName = env->GetMethodID(g_c_Method, "getName", "()Ljava/lang/String;");
            jmethodID mParams = env->GetMethodID(g_c_Method, "getParameterTypes", "()[Ljava/lang/Class;");
            jmethodID mRet = env->GetMethodID(g_c_Method, "getReturnType", "()Ljava/lang/Class;");
            jmethodID mMod = env->GetMethodID(g_c_Method, "getModifiers", "()I");
            jsize len = env->GetArrayLength(marr);
            for (jsize i = 0; i < len; ++i) {
                jobject m = env->GetObjectArrayElement(marr, i);
                if (!m) continue;
                std::string name;
                if (mName) {
                    auto jn = static_cast<jstring>(env->CallObjectMethod(m, mName));
                    if (jn) {
                        const char* c = env->GetStringUTFChars(jn, nullptr);
                        if (c) { name = c; env->ReleaseStringUTFChars(jn, c); }
                        env->DeleteLocalRef(jn);
                    }
                }
                std::vector<std::string> params;
                std::string sig = "(";
                if (mParams) {
                    auto pa = static_cast<jobjectArray>(env->CallObjectMethod(m, mParams));
                    if (pa) {
                        jsize plen = env->GetArrayLength(pa);
                        for (jsize p = 0; p < plen; ++p) {
                            auto pc = static_cast<jclass>(env->GetObjectArrayElement(pa, p));
                            if (pc) {
                                std::string pn = JavaClassName(env, pc);
                                params.push_back(pn);
                                sig += TypeNameToDescriptor(pn);
                                env->DeleteLocalRef(pc);
                            }
                        }
                        env->DeleteLocalRef(pa);
                    }
                }
                sig += ")";
                std::string retName = "void";
                if (mRet) {
                    auto rc = static_cast<jclass>(env->CallObjectMethod(m, mRet));
                    if (rc) {
                        retName = JavaClassName(env, rc);
                        env->DeleteLocalRef(rc);
                    }
                }
                sig += TypeNameToDescriptor(retName);
                int mod = mMod ? env->CallIntMethod(m, mMod) : 0;
                if (env->ExceptionCheck()) env->ExceptionClear();
                bool isStatic = (mod & 0x0008) != 0;

                if (!name.empty()) {
                    jmethodID mid = isStatic ? env->GetStaticMethodID(cur, name.c_str(), sig.c_str())
                                             : env->GetMethodID(cur, name.c_str(), sig.c_str());
                    if (env->ExceptionCheck()) env->ExceptionClear();
                    if (mid) {
                        CachedMethod cmeth;
                        cmeth.id = mid;
                        cmeth.params = params;
                        cmeth.ret = retName;
                        cmeth.isStatic = isStatic;
                        cm.methods[name].push_back(cmeth);
                    }
                }
                env->DeleteLocalRef(m);
            }
            env->DeleteLocalRef(marr);
        }

        jclass super = env->GetSuperclass(cur);
        env->DeleteLocalRef(cur);
        cur = super;
    }

    int count = static_cast<int>(cm.fields.size() + cm.methods.size());
    std::lock_guard<std::mutex> lk(g_memberMutex);
    g_memberCache[cname] = std::move(cm);
    return count;
}

// ---------------------------------------------------------------------------
// Type conversion & Object Dump Formatting
// ---------------------------------------------------------------------------
std::string SimplifyJavaType(std::string t) {
    if (t.empty()) return "void";
    if (t == "kotlin.Unit") return "void";

    int arrayDims = 0;
    while (!t.empty() && t[0] == '[') {
        arrayDims++;
        t = t.substr(1);
    }
    if (arrayDims > 0) {
        if (t == "Z") t = "boolean";
        else if (t == "B") t = "byte";
        else if (t == "C") t = "char";
        else if (t == "S") t = "short";
        else if (t == "I") t = "int";
        else if (t == "J") t = "long";
        else if (t == "F") t = "float";
        else if (t == "D") t = "double";
        else if (!t.empty() && t[0] == 'L' && t.back() == ';') {
            t = t.substr(1, t.size() - 2);
            std::replace(t.begin(), t.end(), '/', '.');
        }
    }

    if (t.rfind("java.lang.", 0) == 0) {
        t = t.substr(10);
    } else if (t.rfind("java.util.", 0) == 0) {
        t = t.substr(10);
    } else {
        int dotCount = 0;
        for (char c : t) if (c == '.') dotCount++;

        size_t dollar = t.find('$');
        std::string innerPart;
        std::string mainPart = t;
        if (dollar != std::string::npos) {
            innerPart = t.substr(dollar);
            std::replace(innerPart.begin(), innerPart.end(), '$', '.');
            mainPart = t.substr(0, dollar);
        }

        if (dotCount >= 2 || mainPart.rfind("android.", 0) == 0 ||
            mainPart.rfind("androidx.", 0) == 0 || mainPart.rfind("kotlin.", 0) == 0) {
            size_t lastDot = mainPart.rfind('.');
            if (lastDot != std::string::npos) {
                std::string base = mainPart.substr(lastDot + 1);
                if (!base.empty()) {
                    t = base + innerPart;
                }
            }
        } else if (!innerPart.empty()) {
            t = mainPart + innerPart;
        }
    }

    while (arrayDims-- > 0) {
        t += "[]";
    }
    return t;
}

static std::string FormatJavaModifiers(uint32_t f) {
    std::string s;
    auto add = [&](const char* w) { if (!s.empty()) s += ' '; s += w; };
    if (f & 0x0001) add("public");
    if (f & 0x0002) add("private");
    if (f & 0x0004) add("protected");
    if (f & 0x0008) add("static");
    if (f & 0x0010) add("final");
    if (f & 0x0020) add("synchronized");
    if (f & 0x0040) add("volatile");
    if (f & 0x0080) add("transient");
    if (f & 0x0100) add("native");
    if (f & 0x0400) add("abstract");
    return s;
}

static std::string FormatDumpValue(JNIEnv* env, jobject val, const std::string& typeName) {
    if (!val) return "null";
    if (typeName == "java.lang.String" || typeName == "Ljava/lang/String;") {
        const char* c = env->GetStringUTFChars(static_cast<jstring>(val), nullptr);
        std::string s = c ? ("\"" + std::string(c) + "\"") : "null";
        if (c) env->ReleaseStringUTFChars(static_cast<jstring>(val), c);
        return s;
    }
    if (typeName == "boolean" || typeName == "java.lang.Boolean") {
        jclass c = AgentCachedClass("java/lang/Boolean");
        jmethodID m = c ? env->GetMethodID(c, "booleanValue", "()Z") : nullptr;
        if (m) return env->CallBooleanMethod(val, m) ? "true" : "false";
    }
    if (typeName == "int" || typeName == "java.lang.Integer" || typeName == "short" || typeName == "byte") {
        jclass c = AgentCachedClass("java/lang/Number");
        jmethodID m = c ? env->GetMethodID(c, "intValue", "()I") : nullptr;
        if (m) return std::to_string(env->CallIntMethod(val, m));
    }
    if (typeName == "long" || typeName == "java.lang.Long") {
        jclass c = AgentCachedClass("java/lang/Long");
        jmethodID m = c ? env->GetMethodID(c, "longValue", "()J") : nullptr;
        if (m) return std::to_string(env->CallLongMethod(val, m)) + "L";
    }
    if (typeName == "float" || typeName == "double" || typeName == "java.lang.Float" || typeName == "java.lang.Double") {
        jclass c = AgentCachedClass("java/lang/Number");
        jmethodID m = c ? env->GetMethodID(c, "doubleValue", "()D") : nullptr;
        if (m) {
            char b[32]; snprintf(b, sizeof(b), "%g", env->CallDoubleMethod(val, m));
            return b;
        }
    }
    if (typeName == "char" || typeName == "java.lang.Character") {
        jclass c = AgentCachedClass("java/lang/Character");
        jmethodID m = c ? env->GetMethodID(c, "charValue", "()C") : nullptr;
        if (m) {
            jchar ch = env->CallCharMethod(val, m);
            return std::string("'") + (char)ch + "'";
        }
    }
    if (!typeName.empty() && typeName[0] == '[') {
        jsize len = env->GetArrayLength((jarray)val);
        if (env->ExceptionCheck()) { env->ExceptionClear(); return "[]"; }
        char abuf[64];
        snprintf(abuf, sizeof(abuf), "%s[%d]@0x%llx", SimplifyJavaType(typeName).c_str(), (int)len, (unsigned long long)reinterpret_cast<uintptr_t>(val));
        return abuf;
    }
    uint64_t vAddr = reinterpret_cast<uintptr_t>(val);
    DoRegisterObservedObject(env, vAddr, val);
    char buf[128];
    snprintf(buf, sizeof(buf), "%s@0x%llx", SimplifyJavaType(typeName).c_str(), (unsigned long long)vAddr);
    return buf;
}

static std::string DumpArtObject(JNIEnv* env, jobject obj, uint64_t addr) {
    if (!env || !obj) return "<null>";
    jclass cls = env->GetObjectClass(obj);
    if (!cls) {
        if (env->ExceptionCheck()) env->ExceptionClear();
        return "<invalid object>";
    }
    std::string className = JavaClassName(env, cls);
    if (!addr) addr = reinterpret_cast<uintptr_t>(obj);

    std::ostringstream ss;
    std::string simpleClassName = SimplifyJavaType(className);
    std::string extendsStr;

    jclass superClass = env->GetSuperclass(cls);
    if (superClass) {
        std::string sname = JavaClassName(env, superClass);
        if (!sname.empty() && sname != "java.lang.Object") {
            extendsStr = " extends " + SimplifyJavaType(sname);
        }
        env->DeleteLocalRef(superClass);
    }

    char headerBuf[256];
    snprintf(headerBuf, sizeof(headerBuf), "// %s @ 0x%llx\nclass %s%s {",
             className.c_str(), (unsigned long long) addr,
             simpleClassName.c_str(), extendsStr.c_str());
    ss << headerBuf << "\n";

    std::vector<std::string> instanceFields;
    std::vector<std::string> staticFields;
    std::vector<std::string> methodsList;
    std::unordered_set<std::string> seenInstanceFields;
    std::unordered_set<std::string> seenStaticFields;
    std::unordered_set<std::string> seenMethods;

    jclass cur = (jclass) env->NewLocalRef(cls);
    while (cur != nullptr) {
        // Scan fields
        jmethodID gdf = env->GetMethodID(g_c_Class, "getDeclaredFields", "()[Ljava/lang/reflect/Field;");
        auto fs = gdf ? (jobjectArray) env->CallObjectMethod(cur, gdf) : nullptr;
        if (env->ExceptionCheck()) { env->ExceptionClear(); fs = nullptr; }
        if (fs) {
            jmethodID fName = env->GetMethodID(g_c_Field, "getName", "()Ljava/lang/String;");
            jmethodID fType = env->GetMethodID(g_c_Field, "getType", "()Ljava/lang/Class;");
            jmethodID fMod = env->GetMethodID(g_c_Field, "getModifiers", "()I");
            jmethodID setAcc = env->GetMethodID(g_c_Field, "setAccessible", "(Z)V");
            jmethodID getVal = env->GetMethodID(g_c_Field, "get", "(Ljava/lang/Object;)Ljava/lang/Object;");

            jsize len = env->GetArrayLength(fs);
            for (jsize i = 0; i < len; i++) {
                jobject f = env->GetObjectArrayElement(fs, i);
                if (!f) continue;
                if (setAcc) {
                    env->CallVoidMethod(f, setAcc, JNI_TRUE);
                    if (env->ExceptionCheck()) env->ExceptionClear();
                }

                std::string fname, ftype;
                if (fName) {
                    jstring j = (jstring) env->CallObjectMethod(f, fName);
                    if (j) {
                        const char* c = env->GetStringUTFChars(j, nullptr);
                        if (c) { fname = c; env->ReleaseStringUTFChars(j, c); }
                        env->DeleteLocalRef(j);
                    }
                }
                if (fType) {
                    jclass t = (jclass) env->CallObjectMethod(f, fType);
                    if (t) { ftype = JavaClassName(env, t); env->DeleteLocalRef(t); }
                }
                int mod = fMod ? env->CallIntMethod(f, fMod) : 0;
                if (env->ExceptionCheck()) env->ExceptionClear();
                bool isStatic = (mod & 0x0008) != 0;

                if (isStatic) {
                    if (!seenStaticFields.insert(fname).second) {
                        env->DeleteLocalRef(f);
                        continue;
                    }
                } else {
                    if (!seenInstanceFields.insert(fname).second) {
                        env->DeleteLocalRef(f);
                        continue;
                    }
                }

                std::string valStr = "?";
                if (getVal) {
                    jobject v = env->CallObjectMethod(f, getVal, isStatic ? nullptr : obj);
                    if (env->ExceptionCheck()) {
                        env->ExceptionClear();
                        valStr = "<inaccessible>";
                    } else if (!v) {
                        valStr = "null";
                    } else {
                        valStr = FormatDumpValue(env, v, ftype);
                        env->DeleteLocalRef(v);
                    }
                }

                std::string modStr = FormatJavaModifiers(mod);
                if (!modStr.empty()) modStr += " ";
                std::string typeStr = SimplifyJavaType(ftype);
                std::string entry = "    " + modStr + typeStr + " " + fname + " = " + valStr + ";";

                if (isStatic) staticFields.push_back(entry);
                else instanceFields.push_back(entry);

                env->DeleteLocalRef(f);
            }
            env->DeleteLocalRef(fs);
        }

        // Scan methods
        jmethodID gdm = env->GetMethodID(g_c_Class, "getDeclaredMethods", "()[Ljava/lang/reflect/Method;");
        auto ms = gdm ? (jobjectArray) env->CallObjectMethod(cur, gdm) : nullptr;
        if (env->ExceptionCheck()) { env->ExceptionClear(); ms = nullptr; }
        if (ms) {
            jmethodID mName = env->GetMethodID(g_c_Method, "getName", "()Ljava/lang/String;");
            jmethodID mParams = env->GetMethodID(g_c_Method, "getParameterTypes", "()[Ljava/lang/Class;");
            jmethodID mRet = env->GetMethodID(g_c_Method, "getReturnType", "()Ljava/lang/Class;");
            jmethodID mMod = env->GetMethodID(g_c_Method, "getModifiers", "()I");

            jsize mlen = env->GetArrayLength(ms);
            for (jsize i = 0; i < mlen; i++) {
                jobject m = env->GetObjectArrayElement(ms, i);
                if (!m) continue;
                std::string mname, rtype;
                if (mName) {
                    jstring j = (jstring) env->CallObjectMethod(m, mName);
                    if (j) {
                        const char* c = env->GetStringUTFChars(j, nullptr);
                        if (c) { mname = c; env->ReleaseStringUTFChars(j, c); }
                        env->DeleteLocalRef(j);
                    }
                }
                if (mRet) {
                    jclass rt = (jclass) env->CallObjectMethod(m, mRet);
                    if (rt) { rtype = JavaClassName(env, rt); env->DeleteLocalRef(rt); }
                }
                int mod = mMod ? env->CallIntMethod(m, mMod) : 0;
                if (env->ExceptionCheck()) env->ExceptionClear();

                std::string paramsStr;
                if (mParams) {
                    auto pa = (jobjectArray) env->CallObjectMethod(m, mParams);
                    if (pa) {
                        jsize plen = env->GetArrayLength(pa);
                        for (jsize p = 0; p < plen; p++) {
                            if (p > 0) paramsStr += ", ";
                            jclass pt = (jclass) env->GetObjectArrayElement(pa, p);
                            if (pt) {
                                std::string ptName = JavaClassName(env, pt);
                                paramsStr += SimplifyJavaType(ptName) + " arg" + std::to_string(p);
                                env->DeleteLocalRef(pt);
                            }
                        }
                        env->DeleteLocalRef(pa);
                    }
                }

                std::string mSig = mname + "(" + paramsStr + ")";
                if (seenMethods.insert(mSig).second) {
                    std::string modStr = FormatJavaModifiers(mod);
                    if (!modStr.empty()) modStr += " ";
                    std::string retStr = SimplifyJavaType(rtype);
                    std::string mEntry = "    " + modStr + retStr + " " + mname + "(" + paramsStr + ");";
                    methodsList.push_back(mEntry);
                }
                env->DeleteLocalRef(m);
            }
            env->DeleteLocalRef(ms);
        }

        jclass parent = env->GetSuperclass(cur);
        env->DeleteLocalRef(cur);
        std::string parentName = parent ? JavaClassName(env, parent) : "";
        if (parentName.empty() || parentName == "java.lang.Object" || parentName.rfind("android.app.", 0) == 0) {
            if (parent) env->DeleteLocalRef(parent);
            cur = nullptr;
        } else {
            cur = parent;
        }
    }

    env->DeleteLocalRef(cls);

    if (!instanceFields.empty()) {
        ss << "    // --- Fields (" << instanceFields.size() << ") ---\n";
        for (const auto& f : instanceFields) ss << f << "\n";
        ss << "\n";
    }

    if (!staticFields.empty()) {
        ss << "    // --- Static Fields (" << staticFields.size() << ") ---\n";
        for (const auto& f : staticFields) ss << f << "\n";
        ss << "\n";
    }

    if (!methodsList.empty()) {
        ss << "    // --- Methods (" << methodsList.size() << ") ---\n";
        size_t showM = std::min(methodsList.size(), static_cast<size_t>(25));
        for (size_t i = 0; i < showM; i++) ss << methodsList[i] << "\n";
        if (methodsList.size() > showM) {
            ss << "    // ... (" << (methodsList.size() - showM) << " more methods, call .methods() to list all)\n";
        }
    }

    ss << "}";
    return ss.str();
}

// ---------------------------------------------------------------------------
// Conversion: Java Object <-> QuickJS Value
// ---------------------------------------------------------------------------
JSValue JavaObjectToJsValue(JSContext* ctx, JNIEnv* env, jobject obj) {
    if (!env || !obj) return JS_NULL;
    jclass cls = env->GetObjectClass(obj);
    if (!cls) {
        if (env->ExceptionCheck()) env->ExceptionClear();
        return JS_NULL;
    }
    std::string n = JavaClassName(env, cls);

    auto callNum = [&](const char* cname, const char* mname, const char* sig) -> double {
        jclass c = AgentCachedClass(cname);
        jmethodID m = c ? env->GetMethodID(c, mname, sig) : nullptr;
        double r = 0;
        if (m) {
            if (sig[strlen(sig) - 1] == 'Z') r = env->CallBooleanMethod(obj, m) ? 1.0 : 0.0;
            else if (sig[strlen(sig) - 1] == 'I') r = env->CallIntMethod(obj, m);
            else if (sig[strlen(sig) - 1] == 'J') r = static_cast<double>(env->CallLongMethod(obj, m));
            else if (sig[strlen(sig) - 1] == 'C') r = env->CallCharMethod(obj, m);
            else if (sig[strlen(sig) - 1] == 'D') r = env->CallDoubleMethod(obj, m);
        }
        if (env->ExceptionCheck()) env->ExceptionClear();
        return r;
    };

    JSValue r = JS_NULL;
    if (n == "java.lang.String") {
        const char* c = env->GetStringUTFChars(static_cast<jstring>(obj), nullptr);
        r = JS_NewString(ctx, c ? c : "");
        if (c) env->ReleaseStringUTFChars(static_cast<jstring>(obj), c);
    } else if (n == "java.lang.Boolean") {
        r = JS_NewBool(ctx, callNum("java/lang/Boolean", "booleanValue", "()Z") != 0);
    } else if (n == "java.lang.Integer" || n == "java.lang.Short" || n == "java.lang.Byte") {
        r = JS_NewInt32(ctx, (int32_t) callNum("java/lang/Number", "intValue", "()I"));
    } else if (n == "java.lang.Character") {
        r = JS_NewInt32(ctx, (int32_t) callNum("java/lang/Character", "charValue", "()C"));
    } else if (n == "java.lang.Long") {
        r = JS_NewBigInt64(ctx, (int64_t) callNum("java/lang/Long", "longValue", "()J"));
    } else if (n == "java.lang.Float" || n == "java.lang.Double") {
        r = JS_NewFloat64(ctx, callNum("java/lang/Number", "doubleValue", "()D"));
    } else {
        void* artObj = PineNative_ToArtObject(env, obj);
        uint64_t addr = artObj ? reinterpret_cast<uintptr_t>(artObj) : reinterpret_cast<uintptr_t>(obj);
        DoRegisterObservedObject(env, addr, obj);
        int handle = AddJRef(env, obj, addr, /*persistent=*/true);
        r = CreateJRefValue(ctx, handle);
    }

    if (cls) env->DeleteLocalRef(cls);
    return r;
}

jobject JsValueToJavaObject(JNIEnv* env, JSContext* ctx, JSValueConst v, const std::string& tn) {
    if (!env) return nullptr;
    if (JS_IsNull(v) || JS_IsUndefined(v)) return nullptr;

    if (tn == "java.lang.String" || tn == "Ljava/lang/String;") {
        const char* s = JS_ToCString(ctx, v);
        jstring j = s ? env->NewStringUTF(s) : nullptr;
        if (s) JS_FreeCString(ctx, s);
        return j;
    }
    auto box = [&](const char* cls, const char* sig, char kind) -> jobject {
        jclass c = CachedWrapperClass(cls);
        if (!c) return nullptr;
        jmethodID m = env->GetStaticMethodID(c, "valueOf", sig);
        jobject o = nullptr;
        if (m) {
            if (kind == 'Z') o = env->CallStaticObjectMethod(c, m, JS_ToBool(ctx, v) ? JNI_TRUE : JNI_FALSE);
            else if (kind == 'I') { int32_t i = 0; JS_ToInt32(ctx, &i, v); o = env->CallStaticObjectMethod(c, m, (jint) i); }
            else if (kind == 'J') { int64_t l = 0; if (JS_IsBigInt(ctx, v)) JS_ToBigInt64(ctx, &l, v); else JS_ToInt64(ctx, &l, v); o = env->CallStaticObjectMethod(c, m, (jlong) l); }
            else if (kind == 'C') { int32_t i = 0; JS_ToInt32(ctx, &i, v); o = env->CallStaticObjectMethod(c, m, (jchar) i); }
            else if (kind == 'F') { double d = 0; JS_ToFloat64(ctx, &d, v); o = env->CallStaticObjectMethod(c, m, (jfloat) d); }
            else if (kind == 'D') { double d = 0; JS_ToFloat64(ctx, &d, v); o = env->CallStaticObjectMethod(c, m, (jdouble) d); }
        }
        if (env->ExceptionCheck()) env->ExceptionClear();
        return o;
    };

    if (tn == "int" || tn == "java.lang.Integer") return box("java/lang/Integer", "(I)Ljava/lang/Integer;", 'I');
    if (tn == "long" || tn == "java.lang.Long") return box("java/lang/Long", "(J)Ljava/lang/Long;", 'J');
    if (tn == "boolean" || tn == "java.lang.Boolean") return box("java/lang/Boolean", "(Z)Ljava/lang/Boolean;", 'Z');
    if (tn == "short" || tn == "java.lang.Short") return box("java/lang/Short", "(S)Ljava/lang/Short;", 'I');
    if (tn == "byte" || tn == "java.lang.Byte") return box("java/lang/Byte", "(B)Ljava/lang/Byte;", 'I');
    if (tn == "char" || tn == "java.lang.Character") return box("java/lang/Character", "(C)Ljava/lang/Character;", 'C');
    if (tn == "float" || tn == "java.lang.Float") return box("java/lang/Float", "(F)Ljava/lang/Float;", 'F');
    if (tn == "double" || tn == "java.lang.Double") return box("java/lang/Double", "(D)Ljava/lang/Double;", 'D');

    int h = ExtractJRefHandle(ctx, v);
    jobject inner = GetJRef(h);
    return inner ? env->NewLocalRef(inner) : nullptr;
}

// ---------------------------------------------------------------------------
// JS Native Callbacks & Reflection Dispatch
// ---------------------------------------------------------------------------
JSValue JsPrepare(JSContext* ctx, JSValueConst /*this_val*/, int argc, JSValueConst* argv) {
    if (argc < 1) return JS_NewInt32(ctx, 0);
    JNIEnv* env = GetEnv();
    if (!env) return JS_NewInt32(ctx, 0);

    jclass cls = nullptr;
    bool needDelete = false;
    if (JS_IsString(argv[0])) {
        const char* s = JS_ToCString(ctx, argv[0]);
        if (!s) return JS_NewInt32(ctx, 0);
        cls = FindClassWithFallback(env, s);
        JS_FreeCString(ctx, s);
        needDelete = true;
    } else {
        int h = ExtractJRefHandle(ctx, argv[0]);
        jobject o = GetJRef(h);
        if (o) {
            cls = env->GetObjectClass(o);
            needDelete = true;
        }
    }
    int count = 0;
    if (cls) {
        count = PrepareClassMembers(env, cls);
        if (needDelete) env->DeleteLocalRef(cls);
    }
    return JS_NewInt32(ctx, count);
}

static JSValue JsJCall(JSContext* ctx, JSValueConst /*this_val*/, int argc, JSValueConst* argv) {
    if (argc < 2) return JS_UNDEFINED;
    JNIEnv* env = GetEnv();
    if (!env) return JS_UNDEFINED;

    int h = ExtractJRefHandle(ctx, argv[0]);
    jobject obj = nullptr;
    jclass cls = nullptr;
    std::string cname;
    bool needDeleteCls = false;

    if (h >= 0) {
        obj = GetJRef(h);
        if (!obj) return JS_UNDEFINED;
        cls = env->GetObjectClass(obj);
        cname = JavaClassName(env, cls);
        needDeleteCls = true;
    } else if (JS_IsString(argv[0])) {
        const char* cs = JS_ToCString(ctx, argv[0]);
        if (!cs) return JS_UNDEFINED;
        cname = cs;
        JS_FreeCString(ctx, cs);
        cls = FindClassWithFallback(env, cname);
        needDeleteCls = true;
    }
    if (!cls) return JS_UNDEFINED;

    const char* mnameC = JS_ToCString(ctx, argv[1]);
    if (!mnameC) {
        if (needDeleteCls) env->DeleteLocalRef(cls);
        return JS_UNDEFINED;
    }
    std::string mname = mnameC;
    JS_FreeCString(ctx, mnameC);

    const ClassMembers* mem = LookupMembers(cname);
    if (!mem) {
        PrepareClassMembers(env, cls);
        mem = LookupMembers(cname);
    }
    const CachedMethod* chosen = nullptr;
    CachedMethod dynMethod;

    if (mem) {
        auto it = mem->methods.find(mname);
        if (it != mem->methods.end()) {
            int argCount = argc - 2;
            for (const auto& cand : it->second) {
                if (static_cast<int>(cand.params.size()) == argCount) {
                    chosen = &cand;
                    break;
                }
            }
        }
    }

    if (!chosen) {
        // Fallback: reflect on Class.getMethods
        jmethodID gm = env->GetMethodID(g_c_Class, "getMethods", "()[Ljava/lang/reflect/Method;");
        auto ms = gm ? static_cast<jobjectArray>(env->CallObjectMethod(cls, gm)) : nullptr;
        if (env->ExceptionCheck()) { env->ExceptionClear(); ms = nullptr; }
        if (ms) {
            jmethodID fName = env->GetMethodID(g_c_Method, "getName", "()Ljava/lang/String;");
            jmethodID fParams = env->GetMethodID(g_c_Method, "getParameterTypes", "()[Ljava/lang/Class;");
            jmethodID fRet = env->GetMethodID(g_c_Method, "getReturnType", "()Ljava/lang/Class;");
            jmethodID fMod = env->GetMethodID(g_c_Method, "getModifiers", "()I");
            jsize len = env->GetArrayLength(ms);
            int argCount = argc - 2;
            for (jsize i = 0; i < len; ++i) {
                jobject m = env->GetObjectArrayElement(ms, i);
                if (!m) continue;
                std::string curName;
                if (fName) {
                    auto jn = static_cast<jstring>(env->CallObjectMethod(m, fName));
                    if (jn) {
                        const char* c = env->GetStringUTFChars(jn, nullptr);
                        if (c) { curName = c; env->ReleaseStringUTFChars(jn, c); }
                        env->DeleteLocalRef(jn);
                    }
                }
                if (curName == mname) {
                    std::vector<std::string> params;
                    std::string sig = "(";
                    if (fParams) {
                        auto pa = static_cast<jobjectArray>(env->CallObjectMethod(m, fParams));
                        if (pa) {
                            jsize plen = env->GetArrayLength(pa);
                            for (jsize p = 0; p < plen; ++p) {
                                auto pc = static_cast<jclass>(env->GetObjectArrayElement(pa, p));
                                if (pc) {
                                    std::string pn = JavaClassName(env, pc);
                                    params.push_back(pn);
                                    sig += TypeNameToDescriptor(pn);
                                    env->DeleteLocalRef(pc);
                                }
                            }
                            env->DeleteLocalRef(pa);
                        }
                    }
                    sig += ")";
                    std::string retName = "void";
                    if (fRet) {
                        auto rc = static_cast<jclass>(env->CallObjectMethod(m, fRet));
                        if (rc) {
                            retName = JavaClassName(env, rc);
                            env->DeleteLocalRef(rc);
                        }
                    }
                    sig += TypeNameToDescriptor(retName);
                    int mod = fMod ? env->CallIntMethod(m, fMod) : 0;
                    if (env->ExceptionCheck()) env->ExceptionClear();
                    bool isStatic = (mod & 0x0008) != 0;

                    if (static_cast<int>(params.size()) == argCount) {
                        jmethodID mid = isStatic ? env->GetStaticMethodID(cls, mname.c_str(), sig.c_str())
                                                 : env->GetMethodID(cls, mname.c_str(), sig.c_str());
                        if (env->ExceptionCheck()) env->ExceptionClear();
                        if (mid) {
                            dynMethod.id = mid;
                            dynMethod.params = params;
                            dynMethod.ret = retName;
                            dynMethod.isStatic = isStatic;
                            chosen = &dynMethod;
                            env->DeleteLocalRef(m);
                            break;
                        }
                    }
                }
                env->DeleteLocalRef(m);
            }
            env->DeleteLocalRef(ms);
        }
    }

    if (!chosen) {
        if (needDeleteCls) env->DeleteLocalRef(cls);
        return JS_ThrowTypeError(ctx, "Method '%s' not found or arg count mismatch on %s", mname.c_str(), cname.c_str());
    }

    std::vector<jvalue> jargs(chosen->params.size());
    std::vector<jobject> localRefsToDelete;
    for (size_t i = 0; i < chosen->params.size(); ++i) {
        const std::string& pt = chosen->params[i];
        JSValueConst val = argv[2 + i];
        if (pt == "int") { int32_t iv = 0; JS_ToInt32(ctx, &iv, val); jargs[i].i = iv; }
        else if (pt == "long") { int64_t lv = 0; if (JS_IsBigInt(ctx, val)) JS_ToBigInt64(ctx, &lv, val); else JS_ToInt64(ctx, &lv, val); jargs[i].j = lv; }
        else if (pt == "boolean") { jargs[i].z = JS_ToBool(ctx, val) ? JNI_TRUE : JNI_FALSE; }
        else if (pt == "byte") { int32_t iv = 0; JS_ToInt32(ctx, &iv, val); jargs[i].b = static_cast<jbyte>(iv); }
        else if (pt == "short") { int32_t iv = 0; JS_ToInt32(ctx, &iv, val); jargs[i].s = static_cast<jshort>(iv); }
        else if (pt == "char") { int32_t iv = 0; JS_ToInt32(ctx, &iv, val); jargs[i].c = static_cast<jchar>(iv); }
        else if (pt == "float") { double dv = 0; JS_ToFloat64(ctx, &dv, val); jargs[i].f = static_cast<jfloat>(dv); }
        else if (pt == "double") { double dv = 0; JS_ToFloat64(ctx, &dv, val); jargs[i].d = dv; }
        else {
            jobject jo = JsValueToJavaObject(env, ctx, val, pt);
            jargs[i].l = jo;
            if (jo) localRefsToDelete.push_back(jo);
        }
    }

    JSValue ret = JS_UNDEFINED;
    const std::string& rt = chosen->ret;
    if (chosen->isStatic) {
        if (rt == "void") { env->CallStaticVoidMethodA(cls, chosen->id, jargs.data()); }
        else if (rt == "int") { ret = JS_NewInt32(ctx, env->CallStaticIntMethodA(cls, chosen->id, jargs.data())); }
        else if (rt == "long") { ret = JS_NewBigInt64(ctx, env->CallStaticLongMethodA(cls, chosen->id, jargs.data())); }
        else if (rt == "boolean") { ret = JS_NewBool(ctx, env->CallStaticBooleanMethodA(cls, chosen->id, jargs.data())); }
        else if (rt == "byte") { ret = JS_NewInt32(ctx, env->CallStaticByteMethodA(cls, chosen->id, jargs.data())); }
        else if (rt == "short") { ret = JS_NewInt32(ctx, env->CallStaticShortMethodA(cls, chosen->id, jargs.data())); }
        else if (rt == "char") { ret = JS_NewInt32(ctx, env->CallStaticCharMethodA(cls, chosen->id, jargs.data())); }
        else if (rt == "float") { ret = JS_NewFloat64(ctx, env->CallStaticFloatMethodA(cls, chosen->id, jargs.data())); }
        else if (rt == "double") { ret = JS_NewFloat64(ctx, env->CallStaticDoubleMethodA(cls, chosen->id, jargs.data())); }
        else {
            jobject ro = env->CallStaticObjectMethodA(cls, chosen->id, jargs.data());
            ret = JavaObjectToJsValue(ctx, env, ro);
            if (ro) env->DeleteLocalRef(ro);
        }
    } else {
        if (rt == "void") { env->CallVoidMethodA(obj, chosen->id, jargs.data()); }
        else if (rt == "int") { ret = JS_NewInt32(ctx, env->CallIntMethodA(obj, chosen->id, jargs.data())); }
        else if (rt == "long") { ret = JS_NewBigInt64(ctx, env->CallLongMethodA(obj, chosen->id, jargs.data())); }
        else if (rt == "boolean") { ret = JS_NewBool(ctx, env->CallBooleanMethodA(obj, chosen->id, jargs.data())); }
        else if (rt == "byte") { ret = JS_NewInt32(ctx, env->CallByteMethodA(obj, chosen->id, jargs.data())); }
        else if (rt == "short") { ret = JS_NewInt32(ctx, env->CallShortMethodA(obj, chosen->id, jargs.data())); }
        else if (rt == "char") { ret = JS_NewInt32(ctx, env->CallCharMethodA(obj, chosen->id, jargs.data())); }
        else if (rt == "float") { ret = JS_NewFloat64(ctx, env->CallFloatMethodA(obj, chosen->id, jargs.data())); }
        else if (rt == "double") { ret = JS_NewFloat64(ctx, env->CallDoubleMethodA(obj, chosen->id, jargs.data())); }
        else {
            jobject ro = env->CallObjectMethodA(obj, chosen->id, jargs.data());
            ret = JavaObjectToJsValue(ctx, env, ro);
            if (ro) env->DeleteLocalRef(ro);
        }
    }

    for (jobject lr : localRefsToDelete) env->DeleteLocalRef(lr);
    if (needDeleteCls) env->DeleteLocalRef(cls);
    if (env->ExceptionCheck()) {
        jthrowable thr = env->ExceptionOccurred();
        env->ExceptionClear();
        std::string emsg = "Java exception occurred";
        if (thr) {
            jclass tcls = env->GetObjectClass(thr);
            if (tcls) {
                jmethodID tm = env->GetMethodID(tcls, "toString", "()Ljava/lang/String;");
                if (tm) {
                    auto jstr = static_cast<jstring>(env->CallObjectMethod(thr, tm));
                    if (jstr) {
                        const char* c = env->GetStringUTFChars(jstr, nullptr);
                        if (c) { emsg = c; env->ReleaseStringUTFChars(jstr, c); }
                        env->DeleteLocalRef(jstr);
                    }
                }
                env->DeleteLocalRef(tcls);
            }
            env->DeleteLocalRef(thr);
        }
        JS_FreeValue(ctx, ret);
        return JS_ThrowTypeError(ctx, "%s", emsg.c_str());
    }

    return ret;
}

static JSValue JsJArrayLen(JSContext* ctx, JSValueConst /*this_val*/, int argc, JSValueConst* argv) {
    if (argc < 1) return JS_NewInt32(ctx, -1);
    int h = ExtractJRefHandle(ctx, argv[0]);
    jobject obj = GetJRef(h);
    JNIEnv* env = GetEnv();
    if (!obj || !env) return JS_NewInt32(ctx, -1);
    jclass cls = env->GetObjectClass(obj);
    if (!cls) return JS_NewInt32(ctx, -1);
    std::string cname = JavaClassName(env, cls);
    env->DeleteLocalRef(cls);
    if (cname.empty() || cname[0] != '[') return JS_NewInt32(ctx, -1);
    jsize len = env->GetArrayLength(static_cast<jarray>(obj));
    if (env->ExceptionCheck()) { env->ExceptionClear(); return JS_NewInt32(ctx, -1); }
    return JS_NewInt32(ctx, len);
}

static JSValue JsJArrayGet(JSContext* ctx, JSValueConst /*this_val*/, int argc, JSValueConst* argv) {
    if (argc < 2) return JS_UNDEFINED;
    int h = ExtractJRefHandle(ctx, argv[0]);
    int idx = 0;
    JS_ToInt32(ctx, &idx, argv[1]);
    jobject obj = GetJRef(h);
    JNIEnv* env = GetEnv();
    if (!obj || !env || idx < 0) return JS_UNDEFINED;

    jclass cls = env->GetObjectClass(obj);
    if (!cls) return JS_UNDEFINED;
    std::string cname = JavaClassName(env, cls);
    env->DeleteLocalRef(cls);
    if (cname.empty() || cname[0] != '[') return JS_UNDEFINED;

    jsize len = env->GetArrayLength(static_cast<jarray>(obj));
    if (env->ExceptionCheck()) { env->ExceptionClear(); return JS_UNDEFINED; }
    if (idx >= len) return JS_UNDEFINED;

    char k = cname.size() > 1 ? cname[1] : 'L';
    if (k == 'I') { jint v = 0; env->GetIntArrayRegion(static_cast<jintArray>(obj), idx, 1, &v); return JS_NewInt32(ctx, v); }
    if (k == 'J') { jlong v = 0; env->GetLongArrayRegion(static_cast<jlongArray>(obj), idx, 1, &v); return JS_NewBigInt64(ctx, v); }
    if (k == 'Z') { jboolean v = 0; env->GetBooleanArrayRegion(static_cast<jbooleanArray>(obj), idx, 1, &v); return JS_NewBool(ctx, v); }
    if (k == 'B') { jbyte v = 0; env->GetByteArrayRegion(static_cast<jbyteArray>(obj), idx, 1, &v); return JS_NewInt32(ctx, v); }
    if (k == 'S') { jshort v = 0; env->GetShortArrayRegion(static_cast<jshortArray>(obj), idx, 1, &v); return JS_NewInt32(ctx, v); }
    if (k == 'C') { jchar v = 0; env->GetCharArrayRegion(static_cast<jcharArray>(obj), idx, 1, &v); return JS_NewInt32(ctx, v); }
    if (k == 'F') { jfloat v = 0; env->GetFloatArrayRegion(static_cast<jfloatArray>(obj), idx, 1, &v); return JS_NewFloat64(ctx, v); }
    if (k == 'D') { jdouble v = 0; env->GetDoubleArrayRegion(static_cast<jdoubleArray>(obj), idx, 1, &v); return JS_NewFloat64(ctx, v); }

    jobject elem = env->GetObjectArrayElement(static_cast<jobjectArray>(obj), idx);
    JSValue r = JavaObjectToJsValue(ctx, env, elem);
    if (elem) env->DeleteLocalRef(elem);
    return r;
}

static JSValue JsJArraySet(JSContext* ctx, JSValueConst /*this_val*/, int argc, JSValueConst* argv) {
    if (argc < 3) return JS_FALSE;
    int h = ExtractJRefHandle(ctx, argv[0]);
    int idx = 0;
    JS_ToInt32(ctx, &idx, argv[1]);
    jobject obj = GetJRef(h);
    JNIEnv* env = GetEnv();
    if (!obj || !env || idx < 0) return JS_FALSE;

    jclass cls = env->GetObjectClass(obj);
    if (!cls) return JS_FALSE;
    std::string cname = JavaClassName(env, cls);
    env->DeleteLocalRef(cls);
    if (cname.empty() || cname[0] != '[') return JS_FALSE;

    jsize len = env->GetArrayLength(static_cast<jarray>(obj));
    if (env->ExceptionCheck()) { env->ExceptionClear(); return JS_FALSE; }
    if (idx >= len) return JS_FALSE;

    char k = cname.size() > 1 ? cname[1] : 'L';
    if (k == 'I') { int32_t v = 0; JS_ToInt32(ctx, &v, argv[2]); jint jv = v; env->SetIntArrayRegion(static_cast<jintArray>(obj), idx, 1, &jv); return JS_TRUE; }
    if (k == 'J') { int64_t v = 0; if (JS_IsBigInt(ctx, argv[2])) JS_ToBigInt64(ctx, &v, argv[2]); else JS_ToInt64(ctx, &v, argv[2]); jlong jv = v; env->SetLongArrayRegion(static_cast<jlongArray>(obj), idx, 1, &jv); return JS_TRUE; }
    if (k == 'Z') { jboolean v = JS_ToBool(ctx, argv[2]) ? JNI_TRUE : JNI_FALSE; env->SetBooleanArrayRegion(static_cast<jbooleanArray>(obj), idx, 1, &v); return JS_TRUE; }
    if (k == 'B') { int32_t v = 0; JS_ToInt32(ctx, &v, argv[2]); jbyte jv = static_cast<jbyte>(v); env->SetByteArrayRegion(static_cast<jbyteArray>(obj), idx, 1, &jv); return JS_TRUE; }
    if (k == 'S') { int32_t v = 0; JS_ToInt32(ctx, &v, argv[2]); jshort jv = static_cast<jshort>(v); env->SetShortArrayRegion(static_cast<jshortArray>(obj), idx, 1, &jv); return JS_TRUE; }
    if (k == 'C') { int32_t v = 0; JS_ToInt32(ctx, &v, argv[2]); jchar jv = static_cast<jchar>(v); env->SetCharArrayRegion(static_cast<jcharArray>(obj), idx, 1, &jv); return JS_TRUE; }
    if (k == 'F') { double v = 0; JS_ToFloat64(ctx, &v, argv[2]); jfloat jv = static_cast<jfloat>(v); env->SetFloatArrayRegion(static_cast<jfloatArray>(obj), idx, 1, &jv); return JS_TRUE; }
    if (k == 'D') { double v = 0; JS_ToFloat64(ctx, &v, argv[2]); jdouble jv = v; env->SetDoubleArrayRegion(static_cast<jdoubleArray>(obj), idx, 1, &jv); return JS_TRUE; }

    std::string elemType = cname.substr(1);
    jobject elem = JsValueToJavaObject(env, ctx, argv[2], elemType);
    env->SetObjectArrayElement(static_cast<jobjectArray>(obj), idx, elem);
    if (elem) env->DeleteLocalRef(elem);
    return JS_TRUE;
}

JSValue JsArtObject(JSContext* ctx, JSValueConst /*this_val*/, int argc, JSValueConst* argv) {
    if (argc < 1) return JS_NULL;
    JNIEnv* env = GetEnv();
    if (!env) return JS_NULL;

    uint64_t addr = 0;
    if (JS_IsBigInt(ctx, argv[0])) {
        int64_t v = 0; JS_ToBigInt64(ctx, &v, argv[0]); addr = static_cast<uint64_t>(v);
    } else if (JS_IsNumber(argv[0])) {
        double d = 0; JS_ToFloat64(ctx, &d, argv[0]); addr = static_cast<uint64_t>(d);
    } else if (JS_IsString(argv[0])) {
        const char* s = JS_ToCString(ctx, argv[0]);
        if (s) {
            std::string str(s);
            JS_FreeCString(ctx, s);
            size_t p = str.find_first_not_of(" \t\r\n\"'");
            if (p != std::string::npos) str = str.substr(p);
            size_t q = str.find_last_not_of(" \t\r\n\"'");
            if (q != std::string::npos) str = str.substr(0, q + 1);
            if (str.size() > 2 && (str[0] == '0' && (str[1] == 'x' || str[1] == 'X'))) {
                addr = std::strtoull(str.c_str() + 2, nullptr, 16);
            } else if (str.find_first_of("abcdefABCDEF") != std::string::npos) {
                addr = std::strtoull(str.c_str(), nullptr, 16);
            } else {
                addr = std::strtoull(str.c_str(), nullptr, 10);
            }
        }
    } else if (JS_IsObject(argv[0])) {
        int h = ExtractJRefHandle(ctx, argv[0]);
        if (h >= 0) addr = GetJRefAddr(h);
    }

    if (!addr) return JS_NULL;

    jobject obj = nullptr;
    {
        std::lock_guard<std::mutex> lk(g_observedMutex);
        auto it = g_observedObjects.find(addr);
        if (it != g_observedObjects.end() && it->second) {
            obj = env->NewLocalRef(it->second);
        }
    }

    if (!obj) {
        obj = PineNative_ToJObject(env, reinterpret_cast<void*>(static_cast<uintptr_t>(addr)));
    }
    if (!obj) {
        obj = env->NewLocalRef(reinterpret_cast<jobject>(static_cast<uintptr_t>(addr)));
    }
    if (!obj) return JS_NULL;

    int handle = AddJRef(env, obj, addr, /*persistent=*/true);
    env->DeleteLocalRef(obj);
    return CreateJRefValue(ctx, handle);
}

static JSValue JsJMethods(JSContext* ctx, JSValueConst /*this_val*/, int argc, JSValueConst* argv) {
    if (argc < 1) return JS_UNDEFINED;
    int h = ExtractJRefHandle(ctx, argv[0]);
    jobject obj = GetJRef(h);
    JNIEnv* env = GetEnv();
    if (!obj || !env) return JS_UNDEFINED;

    jclass cls = env->GetObjectClass(obj);
    std::string cname = JavaClassName(env, cls);
    const ClassMembers* mem = LookupMembers(cname);
    if (!mem) {
        PrepareClassMembers(env, cls);
        mem = LookupMembers(cname);
    }

    JSValue arr = JS_NewArray(ctx);
    uint32_t idx = 0;
    if (mem) {
        for (const auto& pair : mem->methods) {
            for (const auto& m : pair.second) {
                std::string sig = (m.isStatic ? "static " : "") + m.ret + " " + pair.first + "(";
                for (size_t p = 0; p < m.params.size(); ++p) {
                    if (p > 0) sig += ", ";
                    sig += m.params[p];
                }
                sig += ")";
                JS_SetPropertyUint32(ctx, arr, idx++, JS_NewString(ctx, sig.c_str()));
            }
        }
    }
    env->DeleteLocalRef(cls);
    return arr;
}

static JSValue JsJFields(JSContext* ctx, JSValueConst /*this_val*/, int argc, JSValueConst* argv) {
    if (argc < 1) return JS_UNDEFINED;
    int h = ExtractJRefHandle(ctx, argv[0]);
    jobject obj = GetJRef(h);
    JNIEnv* env = GetEnv();
    if (!obj || !env) return JS_UNDEFINED;

    jclass cls = env->GetObjectClass(obj);
    std::string cname = JavaClassName(env, cls);
    const ClassMembers* mem = LookupMembers(cname);
    if (!mem) {
        PrepareClassMembers(env, cls);
        mem = LookupMembers(cname);
    }

    JSValue out = JS_NewObject(ctx);
    if (mem) {
        for (const auto& pair : mem->fields) {
            std::string desc = (pair.second.isStatic ? "static " : "") + pair.second.typeName;
            JS_SetPropertyStr(ctx, out, pair.first.c_str(), JS_NewString(ctx, desc.c_str()));
        }
    }
    env->DeleteLocalRef(cls);
    return out;
}

static JSValue JsJFieldGet(JSContext* ctx, JSValueConst /*this_val*/, int argc, JSValueConst* argv) {
    if (argc < 2) return JS_UNDEFINED;
    JNIEnv* env = GetEnv();
    if (!env) return JS_UNDEFINED;

    int h = ExtractJRefHandle(ctx, argv[0]);
    jobject obj = nullptr;
    jclass cls = nullptr;
    std::string cname;
    bool needDeleteCls = false;

    if (h >= 0) {
        obj = GetJRef(h);
        if (!obj) return JS_UNDEFINED;
        cls = env->GetObjectClass(obj);
        cname = JavaClassName(env, cls);
        needDeleteCls = true;
    } else if (JS_IsString(argv[0])) {
        const char* cs = JS_ToCString(ctx, argv[0]);
        if (!cs) return JS_UNDEFINED;
        cname = cs;
        JS_FreeCString(ctx, cs);
        cls = FindClassWithFallback(env, cname);
        needDeleteCls = true;
    }
    if (!cls) return JS_UNDEFINED;

    const char* fNameC = JS_ToCString(ctx, argv[1]);
    if (!fNameC) {
        if (needDeleteCls) env->DeleteLocalRef(cls);
        return JS_UNDEFINED;
    }
    std::string name = fNameC;
    JS_FreeCString(ctx, fNameC);

    const ClassMembers* mem = LookupMembers(cname);
    if (!mem) {
        PrepareClassMembers(env, cls);
        mem = LookupMembers(cname);
    }
    JSValue r = JS_UNDEFINED;
    if (mem) {
        auto fit = mem->fields.find(name);
        if (fit != mem->fields.end()) {
            const CachedField& f = fit->second;
            if (f.isStatic) {
                switch (f.type) {
                    case 'I': r = JS_NewInt32(ctx, env->GetStaticIntField(cls, f.id)); break;
                    case 'J': r = JS_NewBigInt64(ctx, env->GetStaticLongField(cls, f.id)); break;
                    case 'Z': r = JS_NewBool(ctx, env->GetStaticBooleanField(cls, f.id)); break;
                    case 'B': r = JS_NewInt32(ctx, env->GetStaticByteField(cls, f.id)); break;
                    case 'S': r = JS_NewInt32(ctx, env->GetStaticShortField(cls, f.id)); break;
                    case 'C': r = JS_NewInt32(ctx, env->GetStaticCharField(cls, f.id)); break;
                    case 'F': r = JS_NewFloat64(ctx, env->GetStaticFloatField(cls, f.id)); break;
                    case 'D': r = JS_NewFloat64(ctx, env->GetStaticDoubleField(cls, f.id)); break;
                    default: {
                        jobject o = env->GetStaticObjectField(cls, f.id);
                        r = JavaObjectToJsValue(ctx, env, o);
                        if (o) env->DeleteLocalRef(o);
                        break;
                    }
                }
            } else if (obj) {
                switch (f.type) {
                    case 'I': r = JS_NewInt32(ctx, env->GetIntField(obj, f.id)); break;
                    case 'J': r = JS_NewBigInt64(ctx, env->GetLongField(obj, f.id)); break;
                    case 'Z': r = JS_NewBool(ctx, env->GetBooleanField(obj, f.id)); break;
                    case 'B': r = JS_NewInt32(ctx, env->GetByteField(obj, f.id)); break;
                    case 'S': r = JS_NewInt32(ctx, env->GetShortField(obj, f.id)); break;
                    case 'C': r = JS_NewInt32(ctx, env->GetCharField(obj, f.id)); break;
                    case 'F': r = JS_NewFloat64(ctx, env->GetFloatField(obj, f.id)); break;
                    case 'D': r = JS_NewFloat64(ctx, env->GetDoubleField(obj, f.id)); break;
                    default: {
                        jobject o = env->GetObjectField(obj, f.id);
                        r = JavaObjectToJsValue(ctx, env, o);
                        if (o) env->DeleteLocalRef(o);
                        break;
                    }
                }
            }
        }
    }

    if (needDeleteCls) env->DeleteLocalRef(cls);
    if (env->ExceptionCheck()) env->ExceptionClear();
    return r;
}

static JSValue JsJFieldSet(JSContext* ctx, JSValueConst /*this_val*/, int argc, JSValueConst* argv) {
    if (argc < 3) return JS_FALSE;
    JNIEnv* env = GetEnv();
    if (!env) return JS_FALSE;

    int h = ExtractJRefHandle(ctx, argv[0]);
    jobject obj = nullptr;
    jclass cls = nullptr;
    std::string cname;
    bool needDeleteCls = false;

    if (h >= 0) {
        obj = GetJRef(h);
        if (!obj) return JS_FALSE;
        cls = env->GetObjectClass(obj);
        cname = JavaClassName(env, cls);
        needDeleteCls = true;
    } else if (JS_IsString(argv[0])) {
        const char* cs = JS_ToCString(ctx, argv[0]);
        if (!cs) return JS_FALSE;
        cname = cs;
        JS_FreeCString(ctx, cs);
        cls = FindClassWithFallback(env, cname);
        needDeleteCls = true;
    }
    if (!cls) return JS_FALSE;

    const char* fNameC = JS_ToCString(ctx, argv[1]);
    if (!fNameC) {
        if (needDeleteCls) env->DeleteLocalRef(cls);
        return JS_FALSE;
    }
    std::string name = fNameC;
    JS_FreeCString(ctx, fNameC);

    const ClassMembers* mem = LookupMembers(cname);
    if (!mem) {
        PrepareClassMembers(env, cls);
        mem = LookupMembers(cname);
    }
    bool ok = false;
    if (mem) {
        auto fit = mem->fields.find(name);
        if (fit != mem->fields.end()) {
            const CachedField& f = fit->second;
            JSValueConst val = argv[2];
            if (f.isStatic) {
                switch (f.type) {
                    case 'I': { int32_t v = 0; JS_ToInt32(ctx, &v, val); env->SetStaticIntField(cls, f.id, v); ok = true; break; }
                    case 'J': { int64_t v = 0; if (JS_IsBigInt(ctx, val)) JS_ToBigInt64(ctx, &v, val); else JS_ToInt64(ctx, &v, val); env->SetStaticLongField(cls, f.id, v); ok = true; break; }
                    case 'Z': { env->SetStaticBooleanField(cls, f.id, JS_ToBool(ctx, val) ? JNI_TRUE : JNI_FALSE); ok = true; break; }
                    case 'B': { int32_t v = 0; JS_ToInt32(ctx, &v, val); env->SetStaticByteField(cls, f.id, static_cast<jbyte>(v)); ok = true; break; }
                    case 'S': { int32_t v = 0; JS_ToInt32(ctx, &v, val); env->SetStaticShortField(cls, f.id, static_cast<jshort>(v)); ok = true; break; }
                    case 'C': { int32_t v = 0; JS_ToInt32(ctx, &v, val); env->SetStaticCharField(cls, f.id, static_cast<jchar>(v)); ok = true; break; }
                    case 'F': { double v = 0; JS_ToFloat64(ctx, &v, val); env->SetStaticFloatField(cls, f.id, static_cast<jfloat>(v)); ok = true; break; }
                    case 'D': { double v = 0; JS_ToFloat64(ctx, &v, val); env->SetStaticDoubleField(cls, f.id, v); ok = true; break; }
                    default: {
                        jobject o = JsValueToJavaObject(env, ctx, val, f.typeName);
                        env->SetStaticObjectField(cls, f.id, o);
                        if (o) env->DeleteLocalRef(o);
                        ok = true;
                        break;
                    }
                }
            } else if (obj) {
                switch (f.type) {
                    case 'I': { int32_t v = 0; JS_ToInt32(ctx, &v, val); env->SetIntField(obj, f.id, v); ok = true; break; }
                    case 'J': { int64_t v = 0; if (JS_IsBigInt(ctx, val)) JS_ToBigInt64(ctx, &v, val); else JS_ToInt64(ctx, &v, val); env->SetLongField(obj, f.id, v); ok = true; break; }
                    case 'Z': { env->SetBooleanField(obj, f.id, JS_ToBool(ctx, val) ? JNI_TRUE : JNI_FALSE); ok = true; break; }
                    case 'B': { int32_t v = 0; JS_ToInt32(ctx, &v, val); env->SetByteField(obj, f.id, static_cast<jbyte>(v)); ok = true; break; }
                    case 'S': { int32_t v = 0; JS_ToInt32(ctx, &v, val); env->SetShortField(obj, f.id, static_cast<jshort>(v)); ok = true; break; }
                    case 'C': { int32_t v = 0; JS_ToInt32(ctx, &v, val); env->SetCharField(obj, f.id, static_cast<jchar>(v)); ok = true; break; }
                    case 'F': { double v = 0; JS_ToFloat64(ctx, &v, val); env->SetFloatField(obj, f.id, static_cast<jfloat>(v)); ok = true; break; }
                    case 'D': { double v = 0; JS_ToFloat64(ctx, &v, val); env->SetDoubleField(obj, f.id, v); ok = true; break; }
                    default: {
                        jobject o = JsValueToJavaObject(env, ctx, val, f.typeName);
                        env->SetObjectField(obj, f.id, o);
                        if (o) env->DeleteLocalRef(o);
                        ok = true;
                        break;
                    }
                }
            }
        }
    }

    if (needDeleteCls) env->DeleteLocalRef(cls);
    if (env->ExceptionCheck()) env->ExceptionClear();
    return JS_NewBool(ctx, ok);
}

static JSValue JsJRefStr(JSContext* ctx, JSValueConst /*this_val*/, int argc, JSValueConst* argv) {
    if (argc < 1) return JS_UNDEFINED;
    int h = ExtractJRefHandle(ctx, argv[0]);
    jobject obj = GetJRef(h);
    JNIEnv* env = GetEnv();
    if (!obj || !env) return JS_NULL;
    uint64_t addr = GetJRefAddr(h);
    std::string dump = DumpArtObject(env, obj, addr);
    return JS_NewString(ctx, dump.c_str());
}

static JSValue JsJMembers(JSContext* ctx, JSValueConst /*this_val*/, int argc, JSValueConst* argv) {
    if (argc < 1) return JS_NewArray(ctx);
    int h = ExtractJRefHandle(ctx, argv[0]);
    jobject obj = GetJRef(h);
    JNIEnv* env = GetEnv();
    if (!obj || !env) return JS_NewArray(ctx);

    jclass cls = env->GetObjectClass(obj);
    std::string cname = JavaClassName(env, cls);
    const ClassMembers* mem = LookupMembers(cname);
    if (!mem) {
        PrepareClassMembers(env, cls);
        mem = LookupMembers(cname);
    }

    std::set<std::string> names;
    if (mem) {
        for (const auto& f : mem->fields) names.insert(f.first);
        for (const auto& m : mem->methods) names.insert(m.first);
    }
    env->DeleteLocalRef(cls);

    JSValue arr = JS_NewArray(ctx);
    uint32_t idx = 0;
    for (const auto& n : names) {
        JS_SetPropertyUint32(ctx, arr, idx++, JS_NewString(ctx, n.c_str()));
    }
    return arr;
}

// ---------------------------------------------------------------------------
// JRef API & Bootstrap Script Registration
// ---------------------------------------------------------------------------
void RegisterJavaRefApis(JSContext* ctx, JSValue global, JSValue java) {
    JS_SetPropertyStr(ctx, java, "prepare", JS_NewCFunction(ctx, JsPrepare, "prepare", 1));
    JS_SetPropertyStr(ctx, java, "object", JS_NewCFunction(ctx, JsArtObject, "object", 1));

    JS_SetPropertyStr(ctx, global, "prepare", JS_NewCFunction(ctx, JsPrepare, "prepare", 1));
    JS_SetPropertyStr(ctx, global, "artobject", JS_NewCFunction(ctx, JsArtObject, "artobject", 1));
    JS_SetPropertyStr(ctx, global, "artobjects", JS_NewCFunction(ctx, JsArtObject, "artobjects", 1));
    JS_SetPropertyStr(ctx, global, "jobject", JS_NewCFunction(ctx, JsArtObject, "jobject", 1));
    JS_SetPropertyStr(ctx, global, "jobjects", JS_NewCFunction(ctx, JsArtObject, "jobjects", 1));

    // Internal JRef native bridges
    JS_SetPropertyStr(ctx, global, "__native_jfget", JS_NewCFunction(ctx, JsJFieldGet, "__native_jfget", 2));
    JS_SetPropertyStr(ctx, global, "__native_jfset", JS_NewCFunction(ctx, JsJFieldSet, "__native_jfset", 3));
    JS_SetPropertyStr(ctx, global, "__native_jstr", JS_NewCFunction(ctx, JsJRefStr, "__native_jstr", 1));
    JS_SetPropertyStr(ctx, global, "__native_jdump", JS_NewCFunction(ctx, JsJRefStr, "__native_jdump", 1));
    JS_SetPropertyStr(ctx, global, "__native_jmethods", JS_NewCFunction(ctx, JsJMethods, "__native_jmethods", 1));
    JS_SetPropertyStr(ctx, global, "__native_jfields", JS_NewCFunction(ctx, JsJFields, "__native_jfields", 1));
    JS_SetPropertyStr(ctx, global, "__native_jcall", JS_NewCFunction(ctx, JsJCall, "__native_jcall", 2));
    JS_SetPropertyStr(ctx, global, "__native_jarrlen", JS_NewCFunction(ctx, JsJArrayLen, "__native_jarrlen", 1));
    JS_SetPropertyStr(ctx, global, "__native_jarrget", JS_NewCFunction(ctx, JsJArrayGet, "__native_jarrget", 2));
    JS_SetPropertyStr(ctx, global, "__native_jarrset", JS_NewCFunction(ctx, JsJArraySet, "__native_jarrset", 3));
    JS_SetPropertyStr(ctx, global, "__native_jmembers", JS_NewCFunction(ctx, JsJMembers, "__native_jmembers", 1));

    // Evaluate __makeJRef and __getCompletions bootstrap script
    const char* kJRefBoot =
        "(function(){"
        "  globalThis.__makeJRef = function(h){"
        "    return new Proxy({ __h: h }, {"
        "      get(t, p) {"
        "        if (p === '__h') return h;"
        "        if (p === 'toString' || p === 'valueOf' || p === '$dump' || p === 'dump') return function(){ return __native_jdump(h); };"
        "        if (p === '$methods' || p === 'methods') return function(){ return __native_jmethods(h); };"
        "        if (p === '$fields' || p === 'fields') return function(){ return __native_jfields(h); };"
        "        if (p === '$call' || p === '$invoke') return function(m, ...a){ return __native_jcall(h, m, ...a); };"
        "        if (p === 'length') { var L = __native_jarrlen(h); if (L >= 0) return L; try { var sz = __native_jcall(h, 'size'); if (typeof sz === 'number') return sz; } catch(e){} }"
        "        if (typeof p === 'string' && /^\\d+$/.test(p)) {"
        "          var v = __native_jarrget(h, +p); if (v !== undefined) return v;"
        "          try { var item = __native_jcall(h, 'get', +p); if (item !== undefined) return item; } catch(e){}"
        "        }"
        "        if (p === Symbol.iterator) {"
        "          return function*(){"
        "            var L = __native_jarrlen(h);"
        "            if (L >= 0) { for (var i = 0; i < L; i++) yield __native_jarrget(h, i); return; }"
        "            try { var sz = __native_jcall(h, 'size'); if (typeof sz === 'number') { for (var i = 0; i < sz; i++) yield __native_jcall(h, 'get', i); } } catch(e){}"
        "          };"
        "        }"
        "        if (typeof p === 'string' && p.charCodeAt(0) !== 95) {"
        "          var fv = __native_jfget(h, p);"
        "          if (fv !== undefined) return fv;"
        "          return function(...args){ return __native_jcall(h, p, ...args); };"
        "        }"
        "        return t[p];"
        "      },"
        "      set(t, p, v) {"
        "        if (typeof p === 'string' && /^\\d+$/.test(p)) { if (__native_jarrset(h, +p, v)) return true; }"
        "        if (typeof p === 'string' && p.charCodeAt(0) !== 95) { __native_jfset(h, p, v); return true; }"
        "        t[p] = v; return true;"
        "      }"
        "    });"
        "  };"
        "  globalThis.__getCompletions = function(expr){"
        "    try {"
        "      var val = eval(expr);"
        "      if (val === null || val === undefined) return [];"
        "      if (typeof val === 'object' && val !== null && val.__h !== undefined) {"
        "        return __native_jmembers(val.__h);"
        "      }"
        "      var s = {};"
        "      for (var o = val; o !== null && o !== Object.prototype; o = Object.getPrototypeOf(o)) {"
        "        var props = Object.getOwnPropertyNames(o);"
        "        for (var i = 0; i < props.length; i++) {"
        "          if (props[i].charCodeAt(0) !== 95) s[props[i]] = true;"
        "        }"
        "      }"
        "      return Object.keys(s).sort();"
        "    } catch(e) {"
        "      return [];"
        "    }"
        "  };"
        "})();";

    JSValue jrefBoot = JS_Eval(ctx, kJRefBoot, strlen(kJRefBoot), "<jref_boot>", JS_EVAL_TYPE_GLOBAL);
    if (JS_IsException(jrefBoot)) {
        JSValue exc = JS_GetException(ctx);
        const char* e = JS_ToCString(ctx, exc);
        PI_LOGE("JRef bootstrap failed: %s", e ? e : "?");
        if (e) JS_FreeCString(ctx, e);
        JS_FreeValue(ctx, exc);
    }
    JS_FreeValue(ctx, jrefBoot);
}

}} // namespace artpi::agent
