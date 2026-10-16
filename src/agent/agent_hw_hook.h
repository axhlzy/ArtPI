//
// agent_hw_hook.h - QuickJS Bindings for Hardware Breakpoints & Watchpoints
//
#pragma once

#include "agent_common.h"

namespace artpi { namespace agent {

void RegisterHwHookApis(JSContext* ctx, JSValue global);
size_t HwHookDetachAll();

}} // namespace artpi::agent
