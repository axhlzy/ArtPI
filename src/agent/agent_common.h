//
// agent_common.h - Shared QuickJS helpers, JNI environment & utility functions
//
#pragma once

#include <jni.h>
#include <string>
#include <vector>
#include <mutex>
#include <cstdint>

extern "C" {
#include "../../engine/qjs/quickjs/quickjs.h"
}

namespace artpi { namespace agent {

extern JSRuntime* g_rt;
extern JSContext* g_ctx;
extern std::mutex g_jsMutex;
extern JavaVM* g_jvm;

// JNI Thread Attaching Helper
JNIEnv* GetEnv();

// Application ClassLoader Discovery & Cache
jobject GetAppClassLoader(JNIEnv* env);
jclass FindClassWithFallback(JNIEnv* env, const std::string& className);
bool MatchWildcard(const std::string& str, const std::string& pattern);
std::vector<std::string> EnumerateAppClassNames(JNIEnv* env);
std::vector<std::string> FindMatchingClassNames(JNIEnv* env, const std::string& prefix, size_t limit = 50);

// QuickJS Value Extraction & Conversion
int64_t ParsePtr(JSContext* ctx, JSValueConst val);
JSValue NewBigIntOrInt(JSContext* ctx, uint64_t val);

// Cached class lookup (resolved once at init). Returns a GLOBAL ref that must
// NOT be DeleteLocalRef'd. Never calls FindClass, so it is safe on the hook
// path (frameless trampoline). Returns nullptr if not cached.
jclass AgentCachedClass(const char* slashName);

// Console Logging & Event Broadcaster
void InstallConsole(JSContext* ctx);

}} // namespace artpi::agent
