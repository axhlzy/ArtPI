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

// Thread-local reentrancy depth of the JS engine. >0 means the current thread is
// executing JS (inside EvalJs or a JS-triggered JNI call). Hook/trace callbacks that
// fire on such a thread MUST NOT try to run JS again: QuickJS is not reentrant and
// g_jsMutex is non-recursive, so it would deadlock (a very common footgun when you
// install a hook and then trigger the hooked method from the same `-e`/`-f` eval via
// __native_jcall). Guarded callbacks skip the JS invocation and just pass through.
extern thread_local int t_jsReentrancyDepth;

// JNI Thread Attaching Helper
JNIEnv* GetEnv();

// Application ClassLoader Discovery & Cache
jobject GetAppClassLoader(JNIEnv* env);
jclass FindClassWithFallback(JNIEnv* env, const std::string& className);

// Same as FindClassWithFallback minus env->FindClass(). Returns a LOCAL ref.
// env->FindClass() walks the managed stack, which is invalid on a frameless
// hook/interpreter thread, so this variant is the only safe one there. It still
// resolves: generated-class registry -> app ClassLoader.loadClass().
// `allow_lazy_loader=false` additionally forbids the lazy GetAppClassLoader()
// probe (which itself uses env->FindClass) and only uses an already cached one.
jclass FindClassViaRegistryOrAppLoader(JNIEnv* env, const std::string& className,
                                       bool allow_lazy_loader = true);

// Logs a pending Java exception with Throwable.toString() and clears it.
// Never uses ExceptionDescribe(): that is unsafe on frameless JNI threads.
void LogAndClearJavaException(JNIEnv* env, const char* where);
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

// Instrumentation ownership: one ArtMethod carries at most one Pine trampoline,
// so jhook / trace / breakpoint must never stack on the same method. Releases
// any existing instrumentation on `artMethod` so the next feature installs
// cleanly ("last one wins"; avoid replacing a hot method while another thread
// is executing inside its trampoline). Returns a bitmask of what was released:
// 1=hook, 2=trace, 4=breakpoint.
int AgentReleaseMethodInstrumentation(void* artMethod);
std::string FormatReleasedInstrumentation(int mask);

// Install the interpreter's class-lookup fallback (app loader + generated
// class registry). Call once from InitJs after the JS bindings are up.
void InstallInterpClassFallback();

// Early-startup main-thread pause gate (used by -W/--wait and --pause)
bool ArtPIIsProcessPaused();
uint64_t ArtPIGetGatePc();
bool ArtPIResumeProcess();
void ArtPIPauseCurrentThread(uint64_t pc);

}} // namespace artpi::agent
