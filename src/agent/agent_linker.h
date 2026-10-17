#pragma once

#include "quickjs.h"

namespace artpi { namespace agent {

void RegisterLinkerApis(JSContext* ctx, JSValue global);

}} // namespace artpi::agent
