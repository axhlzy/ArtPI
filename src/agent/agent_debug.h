//
// agent_debug.h - Cooperative Debugger & Breakpoint domain bindings for QuickJS
//
#pragma once

extern "C" {
#include "../../engine/qjs/quickjs/quickjs.h"
}

namespace artpi { namespace agent {

void RegisterDebugApis(JSContext* ctx, JSValue global, JSValue debug);
size_t DebugDetachAll();

}} // namespace artpi::agent
