#pragma once

#include "quickjs.h"

namespace artpi { namespace agent {

// Verifies code segment integrity of a loaded ELF module against its disk image.
// Transparently handles direct-APK mapping (extractNativeLibs="false"), APEX, and standalone SOs.
JSValue JsVerifyCodeIntegrity(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv);

}} // namespace artpi::agent
