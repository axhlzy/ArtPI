#pragma once

#include "quickjs.h"

#include <vector>
#include <string>
#include <cstdint>
#include <utility>

#include "QBDI/State.h"
#include <cstdio>
#include <cinttypes>

namespace artpi { namespace agent {

std::vector<std::pair<uintptr_t, uintptr_t>> ResolveModuleRangesByAddr(uintptr_t addr);
std::vector<std::pair<uintptr_t, uintptr_t>> ResolveModuleRangesByName(const std::string& name);

inline std::string FormatGprDiff(const QBDI::GPRState* pre, const QBDI::GPRState* post) {
    if (!pre || !post) return "";
    std::string diff;
    const uint64_t* preX = &pre->x0;
    const uint64_t* postX = &post->x0;

    for (int i = 0; i < 29; i++) {
        if (preX[i] != postX[i]) {
            char buf[64];
            snprintf(buf, sizeof(buf), "%sx%d=0x%" PRIx64, diff.empty() ? "" : ", ", i, postX[i]);
            diff += buf;
        }
    }
    if (pre->x29 != post->x29) {
        char buf[64];
        snprintf(buf, sizeof(buf), "%sfp=0x%" PRIx64, diff.empty() ? "" : ", ", post->x29);
        diff += buf;
    }
    if (pre->lr != post->lr) {
        char buf[64];
        snprintf(buf, sizeof(buf), "%slr=0x%" PRIx64, diff.empty() ? "" : ", ", post->lr);
        diff += buf;
    }
    if (pre->sp != post->sp) {
        char buf[64];
        snprintf(buf, sizeof(buf), "%ssp=0x%" PRIx64, diff.empty() ? "" : ", ", post->sp);
        diff += buf;
    }
    return diff;
}

void RegisterQbdiApis(JSContext* ctx, JSValue global);

}} // namespace artpi::agent
