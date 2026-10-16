//
// agent_trace.h - Trace domain bindings for QuickJS (Unified, Java, Native)
//
#pragma once

#include <string>
#include <vector>

extern "C" {
#include "../../engine/qjs/quickjs/quickjs.h"
}

namespace artpi { namespace agent {

void RegisterTraceApis(JSContext* ctx, JSValue global, JSValue trace);

struct TraceInfo {
    int id;
    std::string target;
    std::string mode;
};

// Stop every active trace; returns the number stopped. (Used by `D()`.)
size_t TraceStopAll();

// Query all active traces
std::vector<TraceInfo> TraceListAll();

// Stop + erase any active trace whose Java target is `artMethod`. Returns true
// if one was removed. (Used by the last-one-wins instrumentation coordinator.)
bool TraceStopByArtMethod(void* artMethod);

}} // namespace artpi::agent
