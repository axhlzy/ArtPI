//
// agent_memory.h - Memory inspection & modification domain bindings for QuickJS
//
#pragma once

extern "C" {
#include "../../engine/qjs/quickjs/quickjs.h"
}

namespace artpi { namespace agent {

void RegisterMemoryApis(JSContext* ctx, JSValue global, JSValue memory);

}} // namespace artpi::agent
