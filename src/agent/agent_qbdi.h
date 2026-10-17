#pragma once

#include "quickjs.h"

namespace artpi { namespace agent {

void RegisterQbdiApis(JSContext* ctx, JSValue global);

}} // namespace artpi::agent
