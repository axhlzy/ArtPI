//
// agent_native.h - Native / ELF / Gum domain bindings for QuickJS
//
#pragma once

#include <string>
#include <vector>
#include <functional>
#include <cstdint>

extern "C" {
#include "../../engine/qjs/quickjs/quickjs.h"
}

namespace artpi { namespace agent {

struct LoadedModuleInfo {
    std::string path;
    std::string name;
    uintptr_t base = 0;
};

void RegisterNativeApis(JSContext* ctx, JSValue global, JSValue native);

// Unhook every active native hook; returns the number removed. (Used by `D()`.)
size_t NativeUnhookAllCount();

// Module & Symbol enumeration across all Android namespaces & /proc/self/maps
std::vector<LoadedModuleInfo> EnumerateAllLoadedModules();
std::vector<std::string> CollectAllLoadedModules();
bool FindLoadedModule(const std::string& query, LoadedModuleInfo& out);
bool EnumerateModuleSymbols(const LoadedModuleInfo& mod,
                           const std::function<bool(const char* name, uintptr_t addr)>& cb);

}} // namespace artpi::agent
