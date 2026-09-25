//
// agent_java.h - Java / ART domain bindings for QuickJS
//
#pragma once

#include <jni.h>

extern "C" {
#include "../../engine/qjs/quickjs/quickjs.h"
}

namespace artpi { namespace agent {

void RegisterJavaApis(JSContext* ctx, JSValue global, JSValue java);

// Unhook every active Java hook; returns the number removed. (Used by `D()`.)
size_t JavaUnhookAllCount();

// Unhook any active `jhook` targeting the given ArtMethod* (void*). Used by the
// trace path so `.hook()` + `.trace()` on the same method don't stack hooks.
bool JavaUnhookMethod(void* artMethod);

// Resolve (once) the java.lang.* / reflection classes used by the JRef hook
// path. MUST be called at init time (valid ART stack): the hook callback runs
// in a frameless trampoline where env->FindClass() would crash.
void InitJRefClassCache(JNIEnv* env);

void RegisterObservedObject(JNIEnv* env, uint64_t raw, jobject obj);

}} // namespace artpi::agent
