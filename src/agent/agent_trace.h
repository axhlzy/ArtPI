//
// agent_trace.h - Trace domain bindings for QuickJS (Unified, Java, Native)
//
#pragma once

extern "C" {
#include "../../engine/qjs/quickjs/quickjs.h"
}

namespace artpi { namespace agent {

void RegisterTraceApis(JSContext* ctx, JSValue global, JSValue trace);

// Stop every active trace; returns the number stopped. (Used by `D()`.)
size_t TraceStopAll();

}} // namespace artpi::agent
