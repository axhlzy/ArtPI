//
// agent_java_decompile.h - Smali disassembly, JADX runtime decompile & Dex memory export
//
#pragma once

extern "C" {
#include "../../engine/qjs/quickjs/quickjs.h"
}

namespace artpi { namespace agent {

// Register Java disassembly & decompile APIs (dumpSmali, dumpCode, decompile, dumpAllDex)
void RegisterJavaDecompileApis(JSContext* ctx, JSValue global, JSValue java);

}} // namespace artpi::agent
