//
// agent_jni.h - JNI Tracing (Vtable Hijack + Hardware Breakpoint) for ArtPI
//
#pragma once

#include "agent_common.h"
#include <cstdint>
#include <string>
#include <vector>

namespace artpi { namespace agent {

void RegisterJniApis(JSContext* ctx, JSValue global, JSValue jni);

struct JniHwInfo {
    uint32_t id = 0;
    std::string func_name;
    uintptr_t target_addr = 0;
};

struct JniStatusInfo {
    bool vtableTracing = false;
    std::string from;
    std::string only;
    std::string exclude;
    std::string className;
    std::string grep;
    std::vector<JniHwInfo> hwSessions;
};

JniStatusInfo JniGetStatusInfo();

// Programmatic control
bool JniStartTrace(const std::string& filterStr);
bool JniStopTrace();
bool JniIsTracing();

}} // namespace artpi::agent

// C-linkage entry points invoked from jni_trampoline_arm64.S
extern "C" {
    void ArtpiJniOnEnter(int slot_id, void* env, uint64_t* saved_regs, void* lr);
    void* ArtpiJniGetRealFunc(int slot_id);
    void ArtpiJniOnLeave(int slot_id, void* env, uint64_t retval, void* lr);
}
