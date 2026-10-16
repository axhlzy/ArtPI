//
// agent_java_hook.h - ART method hooking, CallFrame marshalling & Unhook management
//
#pragma once

#include <cstddef>
#include <string>
#include <vector>

extern "C" {
#include "../../engine/qjs/quickjs/quickjs.h"
}

namespace artpi { namespace agent {

struct JavaHookInfo {
    int id;
    std::string className;
    std::string methodName;
    std::string sig;
    uintptr_t artMethod;
};

// Unhook every active Java hook; returns count of removed hooks
size_t JavaUnhookAllCount();

// Unhook hook targeting specific ArtMethod (last-one-wins coordination)
bool JavaUnhookMethod(void* artMethod);

// Query all active Java hooks
std::vector<JavaHookInfo> JavaHookListAll();

// Register Java hook APIs (jhook, findAndHook, unhook, unhookAll)
void RegisterJavaHookApis(JSContext* ctx, JSValue global, JSValue java);

}} // namespace artpi::agent
