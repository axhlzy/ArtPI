//
// agent_debug.h - Cooperative Debugger & Breakpoint domain bindings for QuickJS
//
#pragma once

#include <string>

extern "C" {
#include "../../engine/qjs/quickjs/quickjs.h"
}

namespace artpi { namespace agent {

void RegisterDebugApis(JSContext* ctx, JSValue global, JSValue debug);
size_t DebugDetachAll();

// Clear + erase any active Java breakpoint whose target is `artMethod`. Returns
// true if one was removed. (Used by the last-one-wins instrumentation coordinator.)
bool BreakpointClearByArtMethod(void* artMethod);

// Capture the Java caller chain from a hooked method's entry SP
// (PineNativeContext::sp), one "Class.method(sig)" line per caller. Pure native
// walk (no VM entry), so it is safe inside a hook trampoline. Backs the
// `ctx.stack` field of the dynamic.java / jmethodBox hook callback.
std::string CaptureCallerStackFromSp(void* callerSp);

}} // namespace artpi::agent
