//
// agent_invoke.h - Dual-path Java method invocation from JS
//
//   path "jni"    : normal ART invocation (JNI Call*MethodA, i.e. the system /
//                   reflection-style call)
//   path "interp" : the embedded nmmvm Dalvik interpreter (PI::Interp::runMethod)
//
// Both take an ArtMethod* (the same pointer produced by findmethod / MethodBox),
// so the same method can be exercised through both engines and compared.
//
#pragma once

#include "agent_common.h"

namespace artpi { namespace agent {

// Registers `Java.invoke(artMethod, mode, receiver, ...args)` + the internal
// `__native_invoke` used by MethodBox wrappers.
void RegisterJavaInvokeApis(JSContext* ctx, JSValue global, JSValue java);

}} // namespace artpi::agent
