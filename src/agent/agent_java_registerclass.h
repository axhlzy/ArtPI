//
// agent_java_registerclass.h - Frida-style Java.registerClass() for QuickJS
//
#pragma once

#include "agent_common.h"

namespace artpi { namespace agent {

// Registers `Java.registerClass(spec)` (+ global `registerClass`) and the
// internal __native_reg* helpers used by the JS-side class wrapper.
void RegisterJavaRegisterClassApis(JSContext* ctx, JSValue global, JSValue java);

}} // namespace artpi::agent
