#pragma once

#include "KittyUtils.h"
#include "KittyMemory.h"
#include "MemoryPatch.h"
#include "KittyScanner.h"
#include "KittyArm64.h"

using KittyMemory::ProcMap;
using KittyScanner::RegisterNativeFn;

#define HEX_STR(ptr, len) KittyUtils::HexDump<16, true>((void *)ptr, len).c_str()