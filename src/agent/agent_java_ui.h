//
// agent_java_ui.h - Android View hierarchy inspection, hit-testing & UI interaction APIs
//
#pragma once

extern "C" {
#include "../../engine/qjs/quickjs/quickjs.h"
}

namespace artpi { namespace agent {

// Register UI automation and interaction APIs (UI.dump, UI.click, UI.swipe, etc.)
void RegisterJavaUiApis(JSContext* ctx, JSValue global);

}} // namespace artpi::agent
