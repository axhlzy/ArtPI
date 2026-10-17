//
// agent_unity.h - UnityResolve.hpp bridge for ARTool (dynamic.unity domain)
//
// The UnityResolve header is C++-heavy and uses try/catch, while the rest of
// the agent is compiled with -fno-exceptions/-fno-rtti.  Only agent_unity.cpp
// includes it (and is built with -fexceptions); everything else talks to the
// opaque QuickJS entry point below.
//
#pragma once

#include <string>

extern "C" {
#include "../../engine/qjs/quickjs/quickjs.h"
}

namespace artpi { namespace agent {

// Creates globalThis.__NativeUnity, consumed by the dynamic.unity bootstrap.
void RegisterUnityApis(JSContext* ctx, JSValue global);

// Optional hint from the injector's boot cfg (the app's lib/<abi> directory).
// Lets -S detection that the app ships libil2cpp.so/libunity.so before they are
// mapped into the process.
void UnitySetLibDirHint(const std::string& dir);
std::string UnityGetLibDirHint();

// Detach every Unity hook installed by this module (BF/b, HookSetActive,
// HookOnPointerClick, B_Button).  Safe to call when Unity is not initialized.
// Returns the number of detached hooks.  Consumed by the global D()/detach().
size_t UnityDetachAll();

}} // namespace artpi::agent
