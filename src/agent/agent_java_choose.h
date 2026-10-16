//
// agent_java_choose.h - Heap object instance scanner (JVMTI + direct ART GC heap scanning)
//
#pragma once

extern "C" {
#include "../../engine/qjs/quickjs/quickjs.h"
}

namespace artpi { namespace agent {

// Register Java choose APIs (Java.choose, choose)
void RegisterJavaChooseApis(JSContext* ctx, JSValue global, JSValue java);

}} // namespace artpi::agent
