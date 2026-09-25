//
// agent_dynamic.h - Dynamic Proxy-based chainable invocation API for Java & Native
//
#pragma once

extern "C" {
#include "../../engine/qjs/quickjs/quickjs.h"
}

namespace artpi { namespace agent {

void RegisterDynamicApis(JSContext* ctx);

}} // namespace artpi::agent
