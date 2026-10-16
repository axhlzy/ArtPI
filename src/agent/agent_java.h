//
// agent_java.h - Java / ART domain bindings facade for QuickJS
//
#pragma once

#include <jni.h>
#include <cstddef>
#include <cstdint>

extern "C" {
#include "../../engine/qjs/quickjs/quickjs.h"
}

namespace artpi { namespace agent {

// Initialize class cache & resolve reflection helper classes
void InitJRefClassCache(JNIEnv* env);

// Register observed object for pointer tracking
void RegisterObservedObject(JNIEnv* env, uint64_t raw, jobject obj);

// Unhook every active Java hook; returns count removed
size_t JavaUnhookAllCount();

// Unhook any active Java hook targeting specific ArtMethod*
bool JavaUnhookMethod(void* artMethod);

// Master registration function for all Java domain APIs
void RegisterJavaApis(JSContext* ctx, JSValue global, JSValue java);

}} // namespace artpi::agent
