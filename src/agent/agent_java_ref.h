//
// agent_java_ref.h - JRef dynamic object proxy, class cache & reflection bridge
//
#pragma once

#include <jni.h>
#include <string>
#include <cstdint>

extern "C" {
#include "../../engine/qjs/quickjs/quickjs.h"
}

namespace artpi { namespace agent {

// Initialize class cache (must be called from a thread with a valid ART stack frame)
void InitJRefClassCache(JNIEnv* env);

// Query cached classes (guaranteed safe on frameless hook trampoline paths)
jclass AgentCachedClass(const char* slashName);
jclass CachedWrapperClass(const char* slashName);

// JRef Handle & Storage management
int AddJRef(JNIEnv* env, jobject o, uint64_t addr = 0, bool persistent = false);
jobject GetJRef(int h);
uint64_t GetJRefAddr(int h);
size_t GetJRefCount();
void PopJRefsTo(JNIEnv* env, size_t base);

// Handle extraction & JS Value wrap
int ExtractJRefHandle(JSContext* ctx, JSValueConst val);
JSValue CreateJRefValue(JSContext* ctx, int handle);

// Convert between Java jobject and JS Value (primitive unboxing or JRef proxy)
JSValue JavaObjectToJsValue(JSContext* ctx, JNIEnv* env, jobject obj);
jobject JsValueToJavaObject(JNIEnv* env, JSContext* ctx, JSValueConst v, const std::string& tn);

// Class inspection & member preparation
std::string JavaClassName(JNIEnv* env, jclass cls);
std::string SimplifyJavaType(std::string t);
int PrepareClassMembers(JNIEnv* env, jclass cls);

// Observed objects tracking (for raw pointer to jobject resolution)
void DoRegisterObservedObject(JNIEnv* env, uint64_t raw, jobject obj);
void RegisterObservedObject(JNIEnv* env, uint64_t raw, jobject obj);

// JS entry points exposed by JRef system
JSValue JsArtObject(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv);
JSValue JsPrepare(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv);

// Register JRef reflection APIs & __makeJRef bootstrap script
void RegisterJavaRefApis(JSContext* ctx, JSValue global, JSValue java);

}} // namespace artpi::agent
