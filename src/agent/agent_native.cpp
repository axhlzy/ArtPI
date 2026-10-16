//
// agent_native.cpp - Native / ELF / Gum domain bindings for QuickJS
//
#include "agent_native.h"
#include "agent_common.h"
#include "agent_net.h"
#include "../../include/ArtPI.h"
#include "native/pi_native.h"
#include "native/hooker/pi_gum_hooker.h"
#include "frida-gum.h"
#include <link.h>
#include <string>
#include <vector>
#include <mutex>
#include <memory>
#include <cstring>
#include <cstdio>
#include <functional>
#include <dlfcn.h>
#include <elf.h>
#include <dirent.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <algorithm>
#include <set>
#include <sstream>

namespace artpi { namespace agent {

static std::vector<PI::Native::NativeHookHandle> g_activeNativeHooks;
static std::mutex g_nativeHooksMutex;

struct ModuleMatchCtx {
    std::string pattern;
    JSValue result;
    JSContext* ctx;
};

static int FindModulePhdrCallback(struct dl_phdr_info* info, size_t /*size*/, void* data) {
    auto* matchCtx = reinterpret_cast<ModuleMatchCtx*>(data);
    if (!info || !info->dlpi_name) return 0;
    std::string path(info->dlpi_name);
    const char* slash = strrchr(info->dlpi_name, '/');
    std::string name = slash ? (slash + 1) : path;

    if (name == matchCtx->pattern || path == matchCtx->pattern ||
        MatchWildcard(name, matchCtx->pattern) || path.find(matchCtx->pattern) != std::string::npos) {
        JSValue obj = JS_NewObject(matchCtx->ctx);
        JS_SetPropertyStr(matchCtx->ctx, obj, "name", JS_NewString(matchCtx->ctx, name.c_str()));
        JS_SetPropertyStr(matchCtx->ctx, obj, "path", JS_NewString(matchCtx->ctx, path.c_str()));
        JS_SetPropertyStr(matchCtx->ctx, obj, "base", JS_NewBigInt64(matchCtx->ctx, static_cast<int64_t>(info->dlpi_addr)));

        size_t total_sz = 0;
        for (int i = 0; i < info->dlpi_phnum; i++) {
            if (info->dlpi_phdr[i].p_type == PT_LOAD) {
                total_sz += info->dlpi_phdr[i].p_memsz;
            }
        }
        JS_SetPropertyStr(matchCtx->ctx, obj, "size", JS_NewInt64(matchCtx->ctx, total_sz));
        matchCtx->result = obj;
        return 1;
    }
    return 0;
}

static JSValue MakeModuleObject(JSContext* ctx, const LoadedModuleInfo& mod);

JSValue JsFindModule(JSContext* ctx, JSValueConst /*this_val*/, int argc, JSValueConst* argv) {
    if (argc < 1) return JS_NewString(ctx, "Usage: findModule(nameOrPattern)");
    const char* str = JS_ToCString(ctx, argv[0]);
    if (!str) return JS_NULL;
    std::string query(str);
    JS_FreeCString(ctx, str);

    LoadedModuleInfo mod;
    if (FindLoadedModule(query, mod)) {
        return MakeModuleObject(ctx, mod);
    }

    ModuleMatchCtx mctx{query, JS_NULL, ctx};
    dl_iterate_phdr(FindModulePhdrCallback, &mctx);
    return mctx.result;
}

// Module-name filter for the symbol-matching helpers: accepts an exact
// basename, a full path, a wildcard, '|'-separated patterns, or empty / "*".
static bool ModuleNameMatchesSingle(const std::string& modField, const std::string& query) {
    if (query.empty() || query == "*") return true;
    if (modField == query) return true;
    const char* slash = strrchr(modField.c_str(), '/');
    std::string base = slash ? std::string(slash + 1) : modField;
    if (base == query) return true;
    if (modField.size() > 3 && modField.substr(modField.size() - 3) == ".so" &&
        modField.substr(0, modField.size() - 3) == query) return true;
    if (base.size() > 3 && base.substr(base.size() - 3) == ".so" &&
        base.substr(0, base.size() - 3) == query) return true;
    return MatchWildcard(base, query) || MatchWildcard(modField, query);
}

static bool ModuleNameMatches(const std::string& modField, const std::string& query) {
    if (query.empty() || query == "*") return true;
    size_t pos = 0;
    while (pos <= query.size()) {
        size_t bar = query.find('|', pos);
        std::string sub = (bar == std::string::npos) ? query.substr(pos) : query.substr(pos, bar - pos);
        if (!sub.empty() && ModuleNameMatchesSingle(modField, sub)) return true;
        if (bar == std::string::npos) break;
        pos = bar + 1;
    }
    return false;
}

// Locate all loaded modules across all Android linker namespaces and /proc/self/maps.
// App-specific libraries are sorted first for optimal REPL completion.
std::vector<LoadedModuleInfo> EnumerateAllLoadedModules() {
    std::vector<LoadedModuleInfo> modules;
    std::set<std::string> seenPaths;

    struct ModCollector {
        std::vector<LoadedModuleInfo>& modules;
        std::set<std::string>& seenPaths;

        void record(const char* pathStr, uintptr_t base) {
            if (!pathStr || !pathStr[0]) return;
            if (strstr(pathStr, "libartpi_agent.so")) return;

            std::string path(pathStr);
            while (!path.empty() && (path.back() == '\n' || path.back() == '\r' || path.back() == ' ')) {
                path.pop_back();
            }

            if (seenPaths.insert(path).second) {
                const char* slash = strrchr(path.c_str(), '/');
                std::string name = slash ? (slash + 1) : path;
                const char* exclam = strrchr(name.c_str(), '!');
                if (exclam) name = exclam + 1;
                slash = strrchr(name.c_str(), '/');
                if (slash) name = slash + 1;

                LoadedModuleInfo mod;
                mod.path = path;
                mod.name = name;
                mod.base = base;
                modules.push_back(std::move(mod));
            }
        }
    };
    ModCollector collector{modules, seenPaths};

    // 1. xdl_iterate_phdr (traverses linker namespaces via linker internals)
    xdl_iterate_phdr([](struct dl_phdr_info* info, size_t, void* data) -> int {
        auto* col = reinterpret_cast<ModCollector*>(data);
        if (info && info->dlpi_name && info->dlpi_name[0]) {
            col->record(info->dlpi_name, static_cast<uintptr_t>(info->dlpi_addr));
        }
        return 0;
    }, &collector, XDL_DEFAULT);

    // 2. Parse /proc/self/maps (guaranteed to find all mapped .so files, including app namespace)
    FILE* f = fopen("/proc/self/maps", "r");
    if (f) {
        char line[1024];
        while (fgets(line, sizeof(line), f)) {
            uintptr_t start = 0, end = 0, offset = 0;
            char perms[8] = {};
            char pathBuf[512] = {};
            int matched = sscanf(line, "%lx-%lx %4s %lx %*x:%*x %*d %511s",
                                 &start, &end, perms, &offset, pathBuf);
            if (matched >= 5 && pathBuf[0] == '/') {
                if (strstr(pathBuf, ".so") != nullptr) {
                    collector.record(pathBuf, start);
                }
            }
        }
        fclose(f);
    }

    // 3. dl_iterate_phdr (standard fallback)
    dl_iterate_phdr([](struct dl_phdr_info* info, size_t, void* data) -> int {
        auto* col = reinterpret_cast<ModCollector*>(data);
        if (info && info->dlpi_name && info->dlpi_name[0]) {
            col->record(info->dlpi_name, static_cast<uintptr_t>(info->dlpi_addr));
        }
        return 0;
    }, &collector);

    // Sort: App libraries first (alphabetical), then system/apex libraries
    auto isApp = [](const LoadedModuleInfo& m) -> bool {
        const std::string& p = m.path;
        if (p.rfind("/data/app/", 0) == 0 || p.rfind("/data/data/", 0) == 0 ||
            p.rfind("/data/user/", 0) == 0) return true;
        if (p.rfind("/system/", 0) != 0 && p.rfind("/apex/", 0) != 0 &&
            p.rfind("/vendor/", 0) != 0 && p.rfind("/product/", 0) != 0 &&
            p.rfind("/system_ext/", 0) != 0) return true;
        return false;
    };

    std::sort(modules.begin(), modules.end(), [&](const LoadedModuleInfo& a, const LoadedModuleInfo& b) {
        bool appA = isApp(a);
        bool appB = isApp(b);
        if (appA != appB) return appA > appB;
        return a.name < b.name;
    });

    return modules;
}

std::vector<std::string> CollectAllLoadedModules() {
    auto all = EnumerateAllLoadedModules();
    std::vector<std::string> names;
    std::set<std::string> seen;
    for (const auto& mod : all) {
        if (mod.name.empty() || mod.name[0] == '[') continue;
        if (mod.name.find(".odex") != std::string::npos || mod.name.find(".oat") != std::string::npos ||
            mod.name.find(".art") != std::string::npos || mod.name.find(".apk") != std::string::npos ||
            mod.name.find(".jar") != std::string::npos) continue;
        if (seen.insert(mod.name).second) {
            names.push_back(mod.name);
        }
    }
    return names;
}

bool FindLoadedModule(const std::string& query, LoadedModuleInfo& out) {
    auto all = EnumerateAllLoadedModules();
    for (const auto& mod : all) {
        if (ModuleNameMatches(mod.name, query) || ModuleNameMatches(mod.path, query)) {
            out = mod;
            return true;
        }
    }
    return false;
}

// Enumerate exported (.dynsym) symbols of a module by reading its ELF *file*
// (never the mapped image, which may contain unreadable / execute-only pages).
// Avoids frida-gum's module registry, which crashes on such mappings.
// `cb` returns false to stop early.
static bool PreadExact(int fd, void* buf, size_t len, off_t off) {
    size_t done = 0;
    while (done < len) {
        ssize_t r = pread(fd, static_cast<uint8_t*>(buf) + done, len - done,
                          off + static_cast<off_t>(done));
        if (r <= 0) return false;
        done += static_cast<size_t>(r);
    }
    return true;
}

bool EnumerateModuleSymbols(const LoadedModuleInfo& mod,
                           const std::function<bool(const char* name, uintptr_t addr)>& cb) {
    std::string filePath = mod.path;
    off_t fileBaseOffset = 0;

    size_t bang = mod.path.find("!/");
    if (bang != std::string::npos) {
        filePath = mod.path.substr(0, bang);
        FILE* mf = fopen("/proc/self/maps", "r");
        if (mf) {
            char mline[1024];
            while (fgets(mline, sizeof(mline), mf)) {
                uintptr_t start = 0, off = 0;
                if (sscanf(mline, "%lx-%*x %*s %lx", &start, &off) >= 2) {
                    if (start == mod.base) {
                        fileBaseOffset = static_cast<off_t>(off);
                        break;
                    }
                }
            }
            fclose(mf);
        }
    }

    int fd = open(filePath.c_str(), O_RDONLY | O_CLOEXEC);
    if (fd < 0) return false;

    Elf64_Ehdr ehdr;
    if (!PreadExact(fd, &ehdr, sizeof(ehdr), fileBaseOffset)) { close(fd); return false; }
    if (memcmp(ehdr.e_ident, ELFMAG, SELFMAG) != 0 || ehdr.e_ident[EI_CLASS] != ELFCLASS64 ||
        ehdr.e_shoff == 0 || ehdr.e_shentsize != sizeof(Elf64_Shdr) || ehdr.e_shnum == 0) {
        close(fd);
        return false;
    }

    std::vector<Elf64_Shdr> shdrs(ehdr.e_shnum);
    if (!PreadExact(fd, shdrs.data(), shdrs.size() * sizeof(Elf64_Shdr), fileBaseOffset + ehdr.e_shoff)) {
        close(fd);
        return false;
    }

    bool ok = false;
    for (int i = 0; i < ehdr.e_shnum; i++) {
        if (shdrs[i].sh_type != SHT_DYNSYM) continue;
        if (shdrs[i].sh_link >= ehdr.e_shnum) break;
        const Elf64_Shdr& dyn = shdrs[i];
        const Elf64_Shdr& str = shdrs[dyn.sh_link];
        if (dyn.sh_entsize != sizeof(Elf64_Sym) || dyn.sh_size == 0) break;
        if (dyn.sh_size > 64u * 1024 * 1024 || str.sh_size > 64u * 1024 * 1024) break;

        size_t nsyms = dyn.sh_size / sizeof(Elf64_Sym);
        std::vector<Elf64_Sym> syms(nsyms);
        std::vector<char> strs(str.sh_size);
        if (!PreadExact(fd, syms.data(), dyn.sh_size, fileBaseOffset + dyn.sh_offset)) break;
        if (!PreadExact(fd, strs.data(), str.sh_size, fileBaseOffset + str.sh_offset)) break;

        ok = true;
        for (size_t s = 0; s < nsyms; s++) {
            if (syms[s].st_value == 0 || syms[s].st_name == 0 || syms[s].st_name >= str.sh_size) continue;
            if (!cb(strs.data() + syms[s].st_name, mod.base + syms[s].st_value)) break;
        }
        break;
    }
    close(fd);
    return ok;
}

// First exported symbol matching `pattern` in `module` (wildcard allowed).
static uintptr_t FindFirstMatchingInModule(const std::string& module, const std::string& pattern) {
    LoadedModuleInfo mod;
    if (!FindLoadedModule(module, mod)) return 0;
    uintptr_t hit = 0;
    EnumerateModuleSymbols(mod, [&](const char* name, uintptr_t addr) -> bool {
        if (MatchWildcard(name, pattern)) { hit = addr; return false; }
        return true;
    });
    return hit;
}

JSValue JsFindSymbol(JSContext* ctx, JSValueConst /*this_val*/, int argc, JSValueConst* argv) {
    if (argc < 2) return JS_NewString(ctx, "Usage: findSymbol(moduleName, symbolName)");
    const char* modStr = JS_ToCString(ctx, argv[0]);
    const char* symStr = JS_ToCString(ctx, argv[1]);
    if (!modStr || !symStr) {
        if (modStr) JS_FreeCString(ctx, modStr);
        if (symStr) JS_FreeCString(ctx, symStr);
        return JS_NULL;
    }

    std::string module(modStr);
    std::string symbol(symStr);
    JS_FreeCString(ctx, modStr);
    JS_FreeCString(ctx, symStr);

    void* handle = xdl_open(module.c_str(), XDL_DEFAULT);
    if (!handle) handle = xdl_open(module.c_str(), XDL_TRY_FORCE_LOAD);

    void* addr = nullptr;
    if (handle) {
        size_t sz = 0;
        addr = xdl_sym(handle, symbol.c_str(), &sz);
        if (!addr) addr = xdl_dsym(handle, symbol.c_str(), &sz);
        xdl_close(handle);
    }

    if (addr) {
        return JS_NewBigInt64(ctx, reinterpret_cast<int64_t>(addr));
    }

    // Wildcard fallback: e.g. findSymbol("libfoo.so", "*Pattern*") resolves the
    // first gum-matching function whose module equals `module`. Use
    // findSymbolsMatching() to enumerate all hits.
    if (symbol.find('*') != std::string::npos || symbol.find('?') != std::string::npos) {
        uintptr_t hit = FindFirstMatchingInModule(module, symbol);
        if (hit) return JS_NewBigInt64(ctx, static_cast<int64_t>(hit));
    }
    return JS_NULL;
}

// ---------------------------------------------------------------------------
// DebugSymbol: gumjs-style symbol resolver built ONLY on xDL / dladdr.
// frida-gum's symbol util (gum_symbol_details_from_address etc.) is deliberately
// NOT used: it crashes (SEGV_ACCERR in gum_elf_module_load) on devices whose
// module map contains unreadable / execute-only mappings.
// ---------------------------------------------------------------------------
static uintptr_t LookupSymbolByName(const char* name) {
    // 1. Fast path: dlsym within RTLD_DEFAULT (the agent lives in the app ns).
    if (void* p = dlsym(RTLD_DEFAULT, name)) return reinterpret_cast<uintptr_t>(p);

    // 2. Scan all loaded modules via xDL across all namespaces
    auto all = EnumerateAllLoadedModules();
    for (const auto& mod : all) {
        void* h = xdl_open(mod.path.c_str(), XDL_DEFAULT);
        if (!h) h = xdl_open(mod.name.c_str(), XDL_DEFAULT);
        if (h) {
            void* s = xdl_sym(h, name, nullptr);
            if (!s) s = xdl_dsym(h, name, nullptr);
            xdl_close(h);
            if (s) return reinterpret_cast<uintptr_t>(s);
        }
    }
    return 0;
}

// Custom stringification so the REPL prints readable info instead of
// "[object Object]" (EvalJs ultimately calls JS_ToCString -> obj.toString()).
static JSValue JsDebugSymbolToString(JSContext* ctx, JSValueConst this_val, int /*argc*/, JSValueConst* /*argv*/) {
    JSValue addrV = JS_GetPropertyStr(ctx, this_val, "address");
    int64_t a = 0;
    if (JS_IsBigInt(ctx, addrV)) JS_ToBigInt64(ctx, &a, addrV);
    else JS_ToInt64(ctx, &a, addrV);
    JS_FreeValue(ctx, addrV);

    JSValue modV = JS_GetPropertyStr(ctx, this_val, "moduleName");
    JSValue nmV = JS_GetPropertyStr(ctx, this_val, "name");
    JSValue dnmV = JS_GetPropertyStr(ctx, this_val, "demangledName");
    const char* mod = JS_IsString(modV) ? JS_ToCString(ctx, modV) : nullptr;
    const char* nm = JS_IsString(nmV) ? JS_ToCString(ctx, nmV) : nullptr;
    const char* dnm = JS_IsString(dnmV) ? JS_ToCString(ctx, dnmV) : nullptr;

    char buf[1024];
    if (dnm && dnm[0] && nm && strcmp(dnm, nm) != 0) {
        snprintf(buf, sizeof(buf), "[DebugSymbol %s!%s (%s) @ 0x%llx]",
                 mod ? mod : "?", dnm, nm, static_cast<unsigned long long>(a));
    } else {
        snprintf(buf, sizeof(buf), "[DebugSymbol %s!%s @ 0x%llx]",
                 mod ? mod : "?", nm ? nm : "?", static_cast<unsigned long long>(a));
    }

    if (mod) JS_FreeCString(ctx, mod);
    if (nm) JS_FreeCString(ctx, nm);
    if (dnm) JS_FreeCString(ctx, dnm);
    JS_FreeValue(ctx, modV);
    JS_FreeValue(ctx, nmV);
    JS_FreeValue(ctx, dnmV);
    return JS_NewString(ctx, buf);
}

// JSON.stringify support: BigInt `address` would otherwise throw, so emit hex.
static JSValue JsDebugSymbolToJson(JSContext* ctx, JSValueConst this_val, int /*argc*/, JSValueConst* /*argv*/) {
    JSValue addrV = JS_GetPropertyStr(ctx, this_val, "address");
    int64_t a = 0;
    if (JS_IsBigInt(ctx, addrV)) JS_ToBigInt64(ctx, &a, addrV);
    else JS_ToInt64(ctx, &a, addrV);
    JS_FreeValue(ctx, addrV);

    char hex[32];
    snprintf(hex, sizeof(hex), "0x%llx", static_cast<unsigned long long>(a));

    JSValue o = JS_NewObject(ctx);
    JS_SetPropertyStr(ctx, o, "address", JS_NewString(ctx, hex));
    JS_SetPropertyStr(ctx, o, "moduleName", JS_GetPropertyStr(ctx, this_val, "moduleName"));
    JS_SetPropertyStr(ctx, o, "name", JS_GetPropertyStr(ctx, this_val, "name"));
    JS_SetPropertyStr(ctx, o, "demangledName", JS_GetPropertyStr(ctx, this_val, "demangledName"));
    JS_SetPropertyStr(ctx, o, "fileName", JS_GetPropertyStr(ctx, this_val, "fileName"));
    JS_SetPropertyStr(ctx, o, "lineNumber", JS_GetPropertyStr(ctx, this_val, "lineNumber"));
    JS_SetPropertyStr(ctx, o, "column", JS_GetPropertyStr(ctx, this_val, "column"));
    return o;
}

static JSValue MakeDebugSymbolObject(JSContext* ctx, uintptr_t address, const char* nameHint = nullptr, const char* modHint = nullptr) {
    uintptr_t outAddr = address;
    std::string modName = modHint ? modHint : "";
    std::string symName = nameHint ? nameHint : "";

    if (modName.empty() || symName.empty()) {
        xdl_info_t info;
        memset(&info, 0, sizeof(info));
        void* cache = nullptr;
        bool ok = xdl_addr(reinterpret_cast<void*>(address), &info, &cache) != 0;
        if (ok) {
            if (info.dli_saddr) outAddr = reinterpret_cast<uintptr_t>(info.dli_saddr);
            if (modName.empty() && info.dli_fname && info.dli_fname[0]) {
                const char* slash = strrchr(info.dli_fname, '/');
                modName = slash ? (slash + 1) : info.dli_fname;
            }
            if (symName.empty() && info.dli_sname && info.dli_sname[0]) {
                symName = info.dli_sname;
            }
        }
        xdl_addr_clean(&cache);
    }

    std::string demangled;
    if (!symName.empty()) {
        demangled = PI::demangle(symName.c_str());
    }

    JSValue o = JS_NewObject(ctx);
    JS_SetPropertyStr(ctx, o, "address", JS_NewBigInt64(ctx, static_cast<int64_t>(outAddr)));
    JS_SetPropertyStr(ctx, o, "moduleName", modName.empty() ? JS_NULL : JS_NewString(ctx, modName.c_str()));
    JS_SetPropertyStr(ctx, o, "name", symName.empty() ? JS_NULL : JS_NewString(ctx, symName.c_str()));
    if (!demangled.empty() && demangled != symName) {
        JS_SetPropertyStr(ctx, o, "demangledName", JS_NewString(ctx, demangled.c_str()));
    } else {
        JS_SetPropertyStr(ctx, o, "demangledName", JS_NULL);
    }
    JS_SetPropertyStr(ctx, o, "fileName", JS_NULL);
    JS_SetPropertyStr(ctx, o, "lineNumber", JS_NewInt32(ctx, 0));
    JS_SetPropertyStr(ctx, o, "column", JS_NewInt32(ctx, 0));
    JS_SetPropertyStr(ctx, o, "toString", JS_NewCFunction(ctx, JsDebugSymbolToString, "toString", 0));
    JS_SetPropertyStr(ctx, o, "toJSON", JS_NewCFunction(ctx, JsDebugSymbolToJson, "toJSON", 0));
    return o;
}

// Pretty table formatting for arrays of DebugSymbol objects
static JSValue JsDebugSymbolArrayToString(JSContext* ctx, JSValueConst this_val, int /*argc*/, JSValueConst* /*argv*/) {
    JSValue lenV = JS_GetPropertyStr(ctx, this_val, "length");
    int32_t len = 0;
    JS_ToInt32(ctx, &len, lenV);
    JS_FreeValue(ctx, lenV);

    if (len <= 0) {
        return JS_NewString(ctx, "[] (0 symbols found)");
    }

    std::ostringstream ss;
    ss << "[Symbol Search] " << len << " match" << (len > 1 ? "es" : "") << ":\n";

    const int kMaxDisplay = 60;
    int displayCount = std::min(len, kMaxDisplay);

    for (int i = 0; i < displayCount; i++) {
        JSValue item = JS_GetPropertyUint32(ctx, this_val, i);
        if (!JS_IsObject(item)) {
            JS_FreeValue(ctx, item);
            continue;
        }

        JSValue addrV = JS_GetPropertyStr(ctx, item, "address");
        int64_t addr = 0;
        if (JS_IsBigInt(ctx, addrV)) JS_ToBigInt64(ctx, &addr, addrV);
        else JS_ToInt64(ctx, &addr, addrV);
        JS_FreeValue(ctx, addrV);

        JSValue modV = JS_GetPropertyStr(ctx, item, "moduleName");
        JSValue nmV = JS_GetPropertyStr(ctx, item, "name");
        JSValue dnmV = JS_GetPropertyStr(ctx, item, "demangledName");
        const char* modStr = JS_IsString(modV) ? JS_ToCString(ctx, modV) : nullptr;
        const char* nmStr = JS_IsString(nmV) ? JS_ToCString(ctx, nmV) : nullptr;
        const char* dnmStr = JS_IsString(dnmV) ? JS_ToCString(ctx, dnmV) : nullptr;

        std::string mod = modStr ? modStr : "?";
        std::string nm = nmStr ? nmStr : "?";
        std::string dnm = dnmStr ? dnmStr : "";

        if (modStr) JS_FreeCString(ctx, modStr);
        if (nmStr) JS_FreeCString(ctx, nmStr);
        if (dnmStr) JS_FreeCString(ctx, dnmStr);
        JS_FreeValue(ctx, modV);
        JS_FreeValue(ctx, nmV);
        JS_FreeValue(ctx, dnmV);

        char header[128];
        snprintf(header, sizeof(header), "  #%-2d 0x%-12llx  %-24s  ",
                 i,
                 (unsigned long long)addr,
                 mod.length() > 24 ? (mod.substr(0, 21) + "...").c_str() : mod.c_str());
        ss << header;

        if (!dnm.empty() && dnm != nm) {
            ss << dnm << "\n";
            ss << std::string(48, ' ') << "(mangled: " << nm << ")\n";
        } else {
            ss << nm << "\n";
        }

        JS_FreeValue(ctx, item);
    }

    if (len > kMaxDisplay) {
        ss << "  ... and " << (len - kMaxDisplay) << " more symbols (total " << len << "). Refine search to narrow down.\n";
    }

    return JS_NewString(ctx, ss.str().c_str());
}

// Enumerate every symbol matching `pattern` that lives in `module`.
// Returns an array of DebugSymbol objects with pretty table formatting.
JSValue JsFindSymbolsMatching(JSContext* ctx, JSValueConst /*this_val*/, int argc, JSValueConst* argv) {
    if (argc < 2) return JS_NewString(ctx, "Usage: findSymbolsMatching(moduleName, symbolPattern)");
    const char* modStr = JS_ToCString(ctx, argv[0]);
    const char* patStr = JS_ToCString(ctx, argv[1]);
    if (!modStr || !patStr) {
        if (modStr) JS_FreeCString(ctx, modStr);
        if (patStr) JS_FreeCString(ctx, patStr);
        return JS_NULL;
    }
    std::string module(modStr);
    std::string pattern(patStr);
    JS_FreeCString(ctx, modStr);
    JS_FreeCString(ctx, patStr);

    LoadedModuleInfo mod;
    if (!FindLoadedModule(module, mod)) {
        return JS_NewString(ctx, ("[!] Module not loaded: " + module).c_str());
    }

    JSValue out = JS_NewArray(ctx);
    JS_SetPropertyStr(ctx, out, "toString", JS_NewCFunction(ctx, JsDebugSymbolArrayToString, "toString", 0));
    const uint32_t kMax = 2000;
    uint32_t idx = 0;
    bool wildcard = pattern.find('*') != std::string::npos || pattern.find('?') != std::string::npos;
    EnumerateModuleSymbols(mod, [&](const char* name, uintptr_t addr) -> bool {
        std::string demangled = PI::demangle(name);
        bool match = wildcard ? MatchWildcard(name, pattern) : pattern == name;
        if (!match && wildcard && !demangled.empty() && demangled != name) {
            match = MatchWildcard(demangled.c_str(), pattern);
        }
        if (!match) return true;

        JSValue symObj = MakeDebugSymbolObject(ctx, addr, name, mod.name.c_str());
        JS_SetPropertyUint32(ctx, out, idx++, symObj);
        return idx < kMax;
    });
    if (idx == 0) {
        JS_FreeValue(ctx, out);
        return JS_NewString(ctx, ("[!] No symbols in " + module + " matching: " + pattern).c_str());
    }
    return out;
}

JSValue JsDebugSymbolFromAddress(JSContext* ctx, JSValueConst /*this_val*/, int argc, JSValueConst* argv) {
    if (argc < 1) return JS_NewString(ctx, "Usage: DebugSymbol.fromAddress(address)");
    int64_t addr = ParsePtr(ctx, argv[0]);
    if (!addr) return JS_NULL;
    return MakeDebugSymbolObject(ctx, static_cast<uintptr_t>(addr));
}

JSValue JsDebugSymbolFromName(JSContext* ctx, JSValueConst /*this_val*/, int argc, JSValueConst* argv) {
    if (argc < 1) return JS_NewString(ctx, "Usage: DebugSymbol.fromName(name)");
    const char* name = JS_ToCString(ctx, argv[0]);
    if (!name) return JS_NULL;
    uintptr_t fn = LookupSymbolByName(name);
    JS_FreeCString(ctx, name);
    if (!fn) return JS_NULL;
    return MakeDebugSymbolObject(ctx, fn);
}

static JSValue JsDebugSymbolGetFunctionByName(JSContext* ctx, JSValueConst /*this_val*/, int argc, JSValueConst* argv) {
    if (argc < 1) return JS_NewString(ctx, "Usage: DebugSymbol.getFunctionByName(name)");
    const char* name = JS_ToCString(ctx, argv[0]);
    if (!name) return JS_NULL;
    uintptr_t fn = LookupSymbolByName(name);
    JS_FreeCString(ctx, name);
    if (!fn) return JS_NULL;
    return JS_NewBigInt64(ctx, static_cast<int64_t>(fn));
}

static JSValue JsDebugSymbolFindSymbolByName(JSContext* ctx, JSValueConst /*this_val*/, int argc, JSValueConst* argv) {
    if (argc < 1) return JS_NewString(ctx, "Usage: DebugSymbol.findSymbolByName(pattern, [moduleName])");
    const char* patStr = JS_ToCString(ctx, argv[0]);
    if (!patStr) return JS_NULL;
    std::string pattern(patStr);
    JS_FreeCString(ctx, patStr);

    std::string targetMod;
    if (argc >= 2 && !JS_IsNull(argv[1]) && !JS_IsUndefined(argv[1])) {
        const char* mStr = JS_ToCString(ctx, argv[1]);
        if (mStr) {
            targetMod = mStr;
            JS_FreeCString(ctx, mStr);
        }
    }

    JSValue out = JS_NewArray(ctx);
    JS_SetPropertyStr(ctx, out, "toString", JS_NewCFunction(ctx, JsDebugSymbolArrayToString, "toString", 0));

    uint32_t outIdx = 0;
    const uint32_t kMaxHits = 500;
    std::set<std::pair<uintptr_t, std::string>> seen;

    auto searchMod = [&](const LoadedModuleInfo& mod) {
        EnumerateModuleSymbols(mod, [&](const char* name, uintptr_t addr) -> bool {
            std::string demangled = PI::demangle(name);
            bool match = MatchWildcard(name, pattern);
            if (!match && !demangled.empty() && demangled != name) {
                match = MatchWildcard(demangled.c_str(), pattern);
            }
            if (!match) return true;

            if (seen.insert({addr, name}).second) {
                JSValue symObj = MakeDebugSymbolObject(ctx, addr, name, mod.name.c_str());
                JS_SetPropertyUint32(ctx, out, outIdx++, symObj);
            }
            return outIdx < kMaxHits;
        });
    };

    if (!targetMod.empty()) {
        LoadedModuleInfo mod;
        if (FindLoadedModule(targetMod, mod)) {
            searchMod(mod);
        }
    } else {
        auto all = EnumerateAllLoadedModules();
        for (const auto& mod : all) {
            searchMod(mod);
            if (outIdx >= kMaxHits) break;
        }
    }

    return out;
}

JSValue JsDumpNative(JSContext* ctx, JSValueConst /*this_val*/, int argc, JSValueConst* argv) {
    if (argc < 1) return JS_NewString(ctx, "Usage: dumpNative(artMethodPtrOrNativeAddr, [maxInstructions])");
    int64_t ptr = ParsePtr(ctx, argv[0]);
    if (!ptr || ptr < 0x1000) {
        return JS_NewString(ctx, "[!] Invalid pointer (address is null or below 0x1000)");
    }

    int maxInsn = -1;
    if (argc >= 2) JS_ToInt32(ctx, &maxInsn, argv[1]);

    // 1. If ptr is inside an ELF module (.so), it's definitely a raw native code pointer
    xdl_info_t info;
    void* cache = nullptr;
    if (xdl_addr(reinterpret_cast<void*>(ptr), &info, &cache) != 0) {
        xdl_addr_clean(&cache);
        std::string native_code = PI::dumpNative(reinterpret_cast<const void*>(ptr), maxInsn);
        return JS_NewString(ctx, native_code.c_str());
    }
    xdl_addr_clean(&cache);

    // 2. Try resolving as ArtMethod
    ArtMethod* art = reinterpret_cast<ArtMethod*>(ptr);
    PI::Method m = PI::resolve(art);
    if (m.isValid() && m.isNative()) {
        std::string native_code = m.dumpNative(maxInsn);
        return JS_NewString(ctx, native_code.c_str());
    }

    std::string native_code = PI::dumpNative(reinterpret_cast<const void*>(ptr), maxInsn);
    return JS_NewString(ctx, native_code.c_str());
}

// --- nhook callback bridge: expose args / ret + setArg / setRet -------------
static JSValue JsNativeSetArgFn(JSContext* ctx, JSValueConst, int argc, JSValueConst* argv,
                                int /*magic*/, JSValue* func_data) {
    if (argc < 2) return JS_UNDEFINED;
    int64_t g = 0;
    if (JS_IsBigInt(ctx, func_data[0])) JS_ToBigInt64(ctx, &g, func_data[0]); else JS_ToInt64(ctx, &g, func_data[0]);
    int32_t i = 0; JS_ToInt32(ctx, &i, argv[0]);
    int64_t v = 0;
    if (JS_IsBigInt(ctx, argv[1])) JS_ToBigInt64(ctx, &v, argv[1]); else JS_ToInt64(ctx, &v, argv[1]);
    if (g) {
        gum_invocation_context_replace_nth_argument(
                reinterpret_cast<GumInvocationContext*>(g), (guint) i, (gpointer)(intptr_t) v);
    }
    return JS_UNDEFINED;
}

static JSValue JsNativeSetRetFn(JSContext* ctx, JSValueConst, int argc, JSValueConst* argv,
                                int /*magic*/, JSValue* func_data) {
    if (argc < 1) return JS_UNDEFINED;
    int64_t g = 0;
    if (JS_IsBigInt(ctx, func_data[0])) JS_ToBigInt64(ctx, &g, func_data[0]); else JS_ToInt64(ctx, &g, func_data[0]);
    int64_t v = 0;
    if (JS_IsBigInt(ctx, argv[0])) JS_ToBigInt64(ctx, &v, argv[0]); else JS_ToInt64(ctx, &v, argv[0]);
    if (g) {
        gum_invocation_context_replace_return_value(
                reinterpret_cast<GumInvocationContext*>(g), (gpointer)(intptr_t) v);
    }
    return JS_UNDEFINED;
}

static JSValue MakeNativeHookCtx(JSContext* ctx, GumInvocationContext* g, uint64_t addr, bool isLeave) {
    JSValue o = JS_NewObject(ctx);
    JS_SetPropertyStr(ctx, o, "address", JS_NewBigInt64(ctx, (int64_t) addr));
    JSValue data[1] = { JS_NewBigInt64(ctx, (int64_t)(uintptr_t) g) };
    if (!isLeave) {
        JSValue args = JS_NewArray(ctx);
        for (int i = 0; i < 8; i++) {
            gpointer a = gum_invocation_context_get_nth_argument(g, (guint) i);
            JS_SetPropertyUint32(ctx, args, (uint32_t) i, JS_NewBigInt64(ctx, (int64_t)(intptr_t) a));
        }
        JS_SetPropertyStr(ctx, o, "args", args);
        JS_SetPropertyStr(ctx, o, "setArg",
                          JS_NewCFunctionData(ctx, JsNativeSetArgFn, 2, 0, 1, data));
    } else {
        gpointer rv = gum_invocation_context_get_return_value(g);
        JS_SetPropertyStr(ctx, o, "ret", JS_NewBigInt64(ctx, (int64_t)(intptr_t) rv));
        JS_SetPropertyStr(ctx, o, "setRet",
                          JS_NewCFunctionData(ctx, JsNativeSetRetFn, 1, 0, 1, data));
    }
    JS_FreeValue(ctx, data[0]);
    return o;
}

static JSValue JsNativeHook(JSContext* ctx, JSValueConst /*this_val*/, int argc, JSValueConst* argv) {
    if (argc < 1) return JS_NewString(ctx, "Usage: nhook(addressOrSymbol, cbOrOpt)");

    void* targetAddr = nullptr;
    std::string modName, symName;

    if (JS_IsString(argv[0])) {
        const char* str = JS_ToCString(ctx, argv[0]);
        if (str) {
            std::string spec(str);
            JS_FreeCString(ctx, str);
            auto exPos = spec.find('!');
            if (exPos != std::string::npos) {
                modName = spec.substr(0, exPos);
                symName = spec.substr(exPos + 1);
            }
        }
    } else {
        int64_t addr = ParsePtr(ctx, argv[0]);
        if (addr >= 0x1000) {
            targetAddr = reinterpret_cast<void*>(addr);
        }
    }

    // callback: function (onEnter) or { onEnter, onLeave }
    JSValue jsEnter = JS_UNDEFINED, jsLeave = JS_UNDEFINED;
    if (argc >= 2) {
        if (JS_IsFunction(ctx, argv[1])) {
            jsEnter = JS_DupValue(ctx, argv[1]);
        } else if (JS_IsObject(argv[1])) {
            JSValue e = JS_GetPropertyStr(ctx, argv[1], "onEnter");
            if (JS_IsFunction(ctx, e)) jsEnter = e; else JS_FreeValue(ctx, e);
            JSValue l = JS_GetPropertyStr(ctx, argv[1], "onLeave");
            if (JS_IsFunction(ctx, l)) jsLeave = l; else JS_FreeValue(ctx, l);
        }
    }

    // Keep callbacks alive for the hook's lifetime; freed when the handle is dropped.
    auto guard = [](JSValue v) {
        return std::shared_ptr<JSValue>(new JSValue(v), [](JSValue* p) {
            if (p) {
                if (g_ctx && !JS_IsUndefined(*p)) JS_FreeValue(g_ctx, *p);
                delete p;
            }
        });
    };
    auto cbEnter = guard(jsEnter);
    auto cbLeave = guard(jsLeave);

    uint64_t addrForLog = reinterpret_cast<uint64_t>(targetAddr);
    auto onEnter = [cbEnter, addrForLog](GumInvocationContext* g) {
        JSContext* jsctx = g_ctx;
        if (!jsctx || JS_IsUndefined(*cbEnter)) {
            BroadcastLog("hook", "[NativeHook] entered");
            return;
        }
        if (t_jsReentrancyDepth > 0) {
            // Fired on the JS eval thread -> running the callback would re-enter
            // QuickJS / deadlock on g_jsMutex. Log the raw register args instead.
            char rbuf[192];
            snprintf(rbuf, sizeof(rbuf),
                     "[NativeHook] entered (reentrant) x0=%llx x1=%llx x2=%llx x3=%llx x4=%llx x5=%llx",
                     (unsigned long long) gum_invocation_context_get_nth_argument(g, 0),
                     (unsigned long long) gum_invocation_context_get_nth_argument(g, 1),
                     (unsigned long long) gum_invocation_context_get_nth_argument(g, 2),
                     (unsigned long long) gum_invocation_context_get_nth_argument(g, 3),
                     (unsigned long long) gum_invocation_context_get_nth_argument(g, 4),
                     (unsigned long long) gum_invocation_context_get_nth_argument(g, 5));
            BroadcastLog("hook", rbuf);
            // Best-effort raw dump of each plausible pointer arg (used e.g. to capture
            // mbedtls rsa context / plaintext buffers). Guarded to avoid faulting.
            for (int ri = 0; ri < 6; ri++) {
                uintptr_t a = (uintptr_t) gum_invocation_context_get_nth_argument(g, ri);
                if (a > 0x1000000000ULL && a < 0x100000000000ULL) {
                    unsigned char tmp[160];
                    memcpy(tmp, (const void*) a, sizeof(tmp));
                    std::string hx;
                    char b[4];
                    for (int i = 0; i < (int) sizeof(tmp); i++) {
                        snprintf(b, sizeof(b), "%02x", tmp[i]);
                        hx += b;
                    }
                    BroadcastLog("hook", "[arg" + std::to_string(ri) + " mem] " + hx);
                }
            }
            return;
        }
        std::lock_guard<std::mutex> lk(g_jsMutex);
        JSValue o = MakeNativeHookCtx(jsctx, g, addrForLog, false);
        JSValue r = JS_Call(jsctx, *cbEnter, JS_UNDEFINED, 1, &o);
        if (JS_IsException(r)) {
            JSValue exc = JS_GetException(jsctx);
            const char* e = JS_ToCString(jsctx, exc);
            if (e) { BroadcastLog("console", std::string("[nhook onEnter] ") + e); JS_FreeCString(jsctx, e); }
            JS_FreeValue(jsctx, exc);
        }
        JS_FreeValue(jsctx, r);
        JS_FreeValue(jsctx, o);
    };
    std::function<void(GumInvocationContext*)> onLeave = nullptr;
    if (!JS_IsUndefined(*cbLeave)) {
        onLeave = [cbLeave, addrForLog](GumInvocationContext* g) {
            JSContext* jsctx = g_ctx;
            if (!jsctx) return;
            if (t_jsReentrancyDepth > 0) return;  // reentrant on JS thread: skip
            std::lock_guard<std::mutex> lk(g_jsMutex);
            JSValue o = MakeNativeHookCtx(jsctx, g, addrForLog, true);
            JSValue r = JS_Call(jsctx, *cbLeave, JS_UNDEFINED, 1, &o);
            if (JS_IsException(r)) {
                JSValue exc = JS_GetException(jsctx);
                const char* e = JS_ToCString(jsctx, exc);
                if (e) { BroadcastLog("console", std::string("[nhook onLeave] ") + e); JS_FreeCString(jsctx, e); }
                JS_FreeValue(jsctx, exc);
            }
            JS_FreeValue(jsctx, r);
            JS_FreeValue(jsctx, o);
        };
    }

    PI::Native::NativeHookHandle handle;
    if (targetAddr) {
        handle = PI::Native::GumHooker::hook(targetAddr, onEnter, onLeave);
    } else if (!modName.empty() && !symName.empty()) {
        handle = PI::Native::GumHooker::hook(modName.c_str(), symName.c_str(), onEnter, onLeave);
    } else {
        return JS_NewString(ctx, "[!] Invalid address or module!symbol specification");
    }

    if (!handle.isValid()) {
        return JS_NewString(ctx, "[!] Native hook installation failed");
    }

    std::lock_guard<std::mutex> lk(g_nativeHooksMutex);
    g_activeNativeHooks.push_back(std::move(handle));
    char buf[64];
    snprintf(buf, sizeof(buf), "Native hook installed (id: %zu)", g_activeNativeHooks.size() - 1);
    return JS_NewString(ctx, buf);
}

static JSValue JsNativeUnhookAll(JSContext* ctx, JSValueConst, int /*argc*/, JSValueConst* /*argv*/) {
    size_t n = NativeUnhookAllCount();
    char buf[64];
    snprintf(buf, sizeof(buf), "Unhooked %zu native hooks", n);
    return JS_NewString(ctx, buf);
}

size_t NativeUnhookAllCount() {
    std::lock_guard<std::mutex> lk(g_nativeHooksMutex);
    size_t n = 0;
    for (auto& h : g_activeNativeHooks) {
        if (h.isValid()) { h.unhook(); n++; }
    }
    g_activeNativeHooks.clear();
    return n;
}

// ===========================================================================
// Frida-style Process & Module namespace
// ===========================================================================

static size_t ComputeModuleMappedSize(const std::string& modPath, uintptr_t modBase) {
    FILE* f = fopen("/proc/self/maps", "r");
    if (!f) return 0;
    uintptr_t minStart = UINTPTR_MAX;
    uintptr_t maxEnd = 0;
    char line[1024];
    while (fgets(line, sizeof(line), f)) {
        uintptr_t start = 0, end = 0;
        if (sscanf(line, "%lx-%lx", &start, &end) != 2) continue;
        const char* p = strchr(line, '/');
        if (!p) continue;
        std::string lp(p);
        while (!lp.empty() && (lp.back() == '\n' || lp.back() == '\r' || lp.back() == ' ')) lp.pop_back();
        if (lp == modPath || (modBase != 0 && start == modBase)) {
            if (start < minStart) minStart = start;
            if (end > maxEnd) maxEnd = end;
        }
    }
    fclose(f);
    return (maxEnd > minStart) ? static_cast<size_t>(maxEnd - minStart) : 0;
}

static JSValue JsModuleToString(JSContext* ctx, JSValueConst this_val, int /*argc*/, JSValueConst* /*argv*/) {
    JSValue nameV = JS_GetPropertyStr(ctx, this_val, "name");
    JSValue baseV = JS_GetPropertyStr(ctx, this_val, "base");
    JSValue sizeV = JS_GetPropertyStr(ctx, this_val, "size");
    JSValue pathV = JS_GetPropertyStr(ctx, this_val, "path");
    const char* name = JS_IsString(nameV) ? JS_ToCString(ctx, nameV) : nullptr;
    const char* path = JS_IsString(pathV) ? JS_ToCString(ctx, pathV) : nullptr;
    int64_t base = ParsePtr(ctx, baseV);
    int64_t sz = 0;
    JS_ToInt64(ctx, &sz, sizeV);

    char buf[1024];
    snprintf(buf, sizeof(buf), "[Module %s @ 0x%llx (size=0x%llx, path=%s)]",
             name ? name : "?",
             static_cast<unsigned long long>(base),
             static_cast<unsigned long long>(sz),
             path ? path : "?");
    if (name) JS_FreeCString(ctx, name);
    if (path) JS_FreeCString(ctx, path);
    JS_FreeValue(ctx, nameV);
    JS_FreeValue(ctx, baseV);
    JS_FreeValue(ctx, sizeV);
    JS_FreeValue(ctx, pathV);
    return JS_NewString(ctx, buf);
}

static JSValue JsModuleFindSymbolByName(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
    if (argc < 1) return JS_NULL;
    JSValue pathV = JS_GetPropertyStr(ctx, this_val, "path");
    JSValue args[2] = { pathV, argv[0] };
    JSValue res = JsFindSymbol(ctx, JS_UNDEFINED, 2, args);
    JS_FreeValue(ctx, pathV);
    return res;
}

static JSValue JsModuleEnumerateSymbols(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
    JSValue pathV = JS_GetPropertyStr(ctx, this_val, "path");
    const char* p = JS_IsString(pathV) ? JS_ToCString(ctx, pathV) : nullptr;
    std::string modPath = p ? p : "";
    if (p) JS_FreeCString(ctx, p);
    JS_FreeValue(ctx, pathV);

    std::string pattern = "*";
    if (argc >= 1 && JS_IsString(argv[0])) {
        const char* s = JS_ToCString(ctx, argv[0]);
        if (s) { pattern = s; JS_FreeCString(ctx, s); }
    }

    LoadedModuleInfo mod;
    if (!FindLoadedModule(modPath, mod)) return JS_NewArray(ctx);

    JSValue arr = JS_NewArray(ctx);
    uint32_t idx = 0;
    EnumerateModuleSymbols(mod, [&](const char* name, uintptr_t addr) -> bool {
        if (pattern == "*" || MatchWildcard(name, pattern) || strstr(name, pattern.c_str()) != nullptr) {
            JSValue item = JS_NewObject(ctx);
            JS_SetPropertyStr(ctx, item, "name", JS_NewString(ctx, name));
            JS_SetPropertyStr(ctx, item, "address", JS_NewBigInt64(ctx, static_cast<int64_t>(addr)));
            JS_SetPropertyUint32(ctx, arr, idx++, item);
        }
        return idx < 2000;
    });
    return arr;
}

static JSValue MakeModuleObject(JSContext* ctx, const LoadedModuleInfo& mod) {
    JSValue obj = JS_NewObject(ctx);
    size_t sz = ComputeModuleMappedSize(mod.path, mod.base);
    JS_SetPropertyStr(ctx, obj, "name", JS_NewString(ctx, mod.name.c_str()));
    JS_SetPropertyStr(ctx, obj, "path", JS_NewString(ctx, mod.path.c_str()));
    JS_SetPropertyStr(ctx, obj, "base", JS_NewBigInt64(ctx, static_cast<int64_t>(mod.base)));
    JS_SetPropertyStr(ctx, obj, "size", JS_NewInt64(ctx, static_cast<int64_t>(sz)));
    JS_SetPropertyStr(ctx, obj, "findExportByName", JS_NewCFunction(ctx, JsModuleFindSymbolByName, "findExportByName", 1));
    JS_SetPropertyStr(ctx, obj, "findSymbolByName", JS_NewCFunction(ctx, JsModuleFindSymbolByName, "findSymbolByName", 1));
    JS_SetPropertyStr(ctx, obj, "findSymbol", JS_NewCFunction(ctx, JsModuleFindSymbolByName, "findSymbol", 1));
    JS_SetPropertyStr(ctx, obj, "enumerateSymbols", JS_NewCFunction(ctx, JsModuleEnumerateSymbols, "enumerateSymbols", 1));
    JS_SetPropertyStr(ctx, obj, "enumerateExports", JS_NewCFunction(ctx, JsModuleEnumerateSymbols, "enumerateExports", 1));
    JS_SetPropertyStr(ctx, obj, "toString", JS_NewCFunction(ctx, JsModuleToString, "toString", 0));
    return obj;
}

static JSValue JsProcessGetCurrentThreadId(JSContext* ctx, JSValueConst, int, JSValueConst*) {
    return JS_NewInt32(ctx, static_cast<int32_t>(gettid()));
}

static JSValue JsThreadToString(JSContext* ctx, JSValueConst this_val, int, JSValueConst*) {
    JSValue idV = JS_GetPropertyStr(ctx, this_val, "id");
    JSValue nmV = JS_GetPropertyStr(ctx, this_val, "name");
    JSValue stV = JS_GetPropertyStr(ctx, this_val, "state");
    int32_t tid = 0;
    JS_ToInt32(ctx, &tid, idV);
    const char* nm = JS_IsString(nmV) ? JS_ToCString(ctx, nmV) : nullptr;
    const char* st = JS_IsString(stV) ? JS_ToCString(ctx, stV) : nullptr;
    char buf[256];
    snprintf(buf, sizeof(buf), "[Thread id=%d name=\"%s\" state=%s]",
             tid, nm ? nm : "?", st ? st : "?");
    if (nm) JS_FreeCString(ctx, nm);
    if (st) JS_FreeCString(ctx, st);
    JS_FreeValue(ctx, idV);
    JS_FreeValue(ctx, nmV);
    JS_FreeValue(ctx, stV);
    return JS_NewString(ctx, buf);
}

static JSValue JsProcessEnumerateThreads(JSContext* ctx, JSValueConst, int, JSValueConst*) {
    JSValue arr = JS_NewArray(ctx);
    DIR* dir = opendir("/proc/self/task");
    if (!dir) return arr;

    uint32_t idx = 0;
    struct dirent* ent = nullptr;
    while ((ent = readdir(dir)) != nullptr) {
        if (ent->d_name[0] == '.') continue;
        long tid = strtol(ent->d_name, nullptr, 10);
        if (tid <= 0) continue;

        char commPath[64];
        snprintf(commPath, sizeof(commPath), "/proc/self/task/%ld/comm", tid);
        char comm[128] = {0};
        int fd = open(commPath, O_RDONLY | O_CLOEXEC);
        if (fd >= 0) {
            ssize_t n = read(fd, comm, sizeof(comm) - 1);
            close(fd);
            if (n > 0) comm[strcspn(comm, "\r\n")] = '\0';
        }

        char statusPath[64];
        snprintf(statusPath, sizeof(statusPath), "/proc/self/task/%ld/status", tid);
        std::string stateStr = "waiting";
        if (FILE* sf = fopen(statusPath, "r")) {
            char line[256];
            while (fgets(line, sizeof(line), sf)) {
                if (strncmp(line, "State:", 6) == 0) {
                    const char* p = line + 6;
                    while (*p == ' ' || *p == '\t') p++;
                    if (*p == 'R') stateStr = "running";
                    else if (*p == 'S') stateStr = "sleeping";
                    else if (*p == 'D') stateStr = "uninterruptible";
                    else if (*p == 'T' || *p == 't') stateStr = "stopped";
                    else if (*p == 'Z') stateStr = "zombie";
                    break;
                }
            }
            fclose(sf);
        }

        JSValue th = JS_NewObject(ctx);
        JS_SetPropertyStr(ctx, th, "id", JS_NewInt32(ctx, static_cast<int32_t>(tid)));
        JS_SetPropertyStr(ctx, th, "name", JS_NewString(ctx, comm));
        JS_SetPropertyStr(ctx, th, "state", JS_NewString(ctx, stateStr.c_str()));
        JS_SetPropertyStr(ctx, th, "toString", JS_NewCFunction(ctx, JsThreadToString, "toString", 0));
        JS_SetPropertyUint32(ctx, arr, idx++, th);
    }
    closedir(dir);
    return arr;
}

static JSValue JsProcessEnumerateModules(JSContext* ctx, JSValueConst, int argc, JSValueConst* argv) {
    std::string filter;
    if (argc >= 1 && JS_IsString(argv[0])) {
        const char* s = JS_ToCString(ctx, argv[0]);
        if (s) { filter = s; JS_FreeCString(ctx, s); }
    }
    auto all = EnumerateAllLoadedModules();
    JSValue arr = JS_NewArray(ctx);
    uint32_t idx = 0;
    for (const auto& mod : all) {
        if (!filter.empty() && !ModuleNameMatches(mod.name, filter) &&
            !ModuleNameMatches(mod.path, filter) &&
            mod.path.find(filter) == std::string::npos) {
            continue;
        }
        JS_SetPropertyUint32(ctx, arr, idx++, MakeModuleObject(ctx, mod));
    }
    return arr;
}

static JSValue JsProcessFindModuleByName(JSContext* ctx, JSValueConst, int argc, JSValueConst* argv) {
    if (argc < 1) return JS_NULL;
    const char* s = JS_ToCString(ctx, argv[0]);
    if (!s) return JS_NULL;
    std::string query(s);
    JS_FreeCString(ctx, s);

    LoadedModuleInfo mod;
    if (FindLoadedModule(query, mod)) {
        return MakeModuleObject(ctx, mod);
    }
    return JS_NULL;
}

static JSValue JsProcessFindModuleByAddress(JSContext* ctx, JSValueConst, int argc, JSValueConst* argv) {
    if (argc < 1) return JS_NULL;
    uintptr_t addr = static_cast<uintptr_t>(ParsePtr(ctx, argv[0]));
    if (addr < 0x1000) return JS_NULL;

    FILE* f = fopen("/proc/self/maps", "r");
    if (!f) return JS_NULL;
    char line[1024];
    std::string hitPath;
    while (fgets(line, sizeof(line), f)) {
        uintptr_t start = 0, end = 0;
        if (sscanf(line, "%lx-%lx", &start, &end) != 2) continue;
        if (addr >= start && addr < end) {
            const char* p = strchr(line, '/');
            if (p) {
                hitPath = p;
                while (!hitPath.empty() && (hitPath.back() == '\n' || hitPath.back() == '\r' || hitPath.back() == ' ')) {
                    hitPath.pop_back();
                }
            }
            break;
        }
    }
    fclose(f);

    if (!hitPath.empty()) {
        LoadedModuleInfo mod;
        if (FindLoadedModule(hitPath, mod)) {
            return MakeModuleObject(ctx, mod);
        }
    }
    return JS_NULL;
}

static JSValue JsProcessFindSymbol(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
    if (argc == 1 && JS_IsString(argv[0])) {
        const char* s = JS_ToCString(ctx, argv[0]);
        if (!s) return JS_NULL;
        std::string spec(s);
        JS_FreeCString(ctx, s);
        size_t bang = spec.find('!');
        if (bang != std::string::npos) {
            JSValue a0 = JS_NewString(ctx, spec.substr(0, bang).c_str());
            JSValue a1 = JS_NewString(ctx, spec.substr(bang + 1).c_str());
            JSValue args[2] = {a0, a1};
            JSValue r = JsFindSymbol(ctx, this_val, 2, args);
            JS_FreeValue(ctx, a0);
            JS_FreeValue(ctx, a1);
            return r;
        }
        uintptr_t addr = LookupSymbolByName(spec.c_str());
        return addr ? JS_NewBigInt64(ctx, static_cast<int64_t>(addr)) : JS_NULL;
    }
    if (argc >= 2 && (JS_IsNull(argv[0]) || JS_IsUndefined(argv[0]))) {
        const char* sym = JS_ToCString(ctx, argv[1]);
        if (!sym) return JS_NULL;
        uintptr_t addr = LookupSymbolByName(sym);
        JS_FreeCString(ctx, sym);
        return addr ? JS_NewBigInt64(ctx, static_cast<int64_t>(addr)) : JS_NULL;
    }
    return JsFindSymbol(ctx, this_val, argc, argv);
}

static JSValue JsProcessEnumerateRanges(JSContext* ctx, JSValueConst, int argc, JSValueConst* argv) {
    std::string wantProt;
    if (argc >= 1 && JS_IsString(argv[0])) {
        const char* s = JS_ToCString(ctx, argv[0]);
        if (s) { wantProt = s; JS_FreeCString(ctx, s); }
    }

    JSValue arr = JS_NewArray(ctx);
    FILE* f = fopen("/proc/self/maps", "r");
    if (!f) return arr;

    uint32_t idx = 0;
    char line[1024];
    while (fgets(line, sizeof(line), f)) {
        uintptr_t start = 0, end = 0, offset = 0;
        char perms[8] = {};
        if (sscanf(line, "%lx-%lx %4s %lx", &start, &end, perms, &offset) < 3) continue;
        std::string prot(perms, 3);
        if (!wantProt.empty()) {
            bool match = true;
            for (size_t i = 0; i < wantProt.size() && i < 3; ++i) {
                if (wantProt[i] != '-' && wantProt[i] != prot[i]) {
                    match = false;
                    break;
                }
            }
            if (!match) continue;
        }

        JSValue r = JS_NewObject(ctx);
        JS_SetPropertyStr(ctx, r, "base", JS_NewBigInt64(ctx, static_cast<int64_t>(start)));
        JS_SetPropertyStr(ctx, r, "size", JS_NewInt64(ctx, static_cast<int64_t>(end - start)));
        JS_SetPropertyStr(ctx, r, "protection", JS_NewString(ctx, prot.c_str()));

        const char* p = strchr(line, '/');
        if (p) {
            std::string path(p);
            while (!path.empty() && (path.back() == '\n' || path.back() == '\r' || path.back() == ' ')) path.pop_back();
            JSValue fileObj = JS_NewObject(ctx);
            JS_SetPropertyStr(ctx, fileObj, "path", JS_NewString(ctx, path.c_str()));
            JS_SetPropertyStr(ctx, fileObj, "offset", JS_NewInt64(ctx, static_cast<int64_t>(offset)));
            JS_SetPropertyStr(ctx, r, "file", fileObj);
        }
        JS_SetPropertyUint32(ctx, arr, idx++, r);
    }
    fclose(f);
    return arr;
}

// Process.onSoLoad disabled to prevent anti-tamper / anti-cheat detection

static JSValue JsProcessIsPaused(JSContext* ctx, JSValueConst, int, JSValueConst*) {
    return JS_NewBool(ctx, ArtPIIsProcessPaused());
}

static JSValue JsProcessResume(JSContext* ctx, JSValueConst, int, JSValueConst*) {
    uint64_t pc = ArtPIGetGatePc();
    if (ArtPIResumeProcess()) {
        char buf[128];
        snprintf(buf, sizeof(buf), "[+] Resumed main thread (PID %d) at PC=0x%llx",
                 (int) getpid(), (unsigned long long) pc);
        return JS_NewString(ctx, buf);
    }
    return JS_NewString(ctx, "[i] Process is not paused");
}


void RegisterNativeApis(JSContext* ctx, JSValue global, JSValue native) {
    // Native namespace
    JS_SetPropertyStr(ctx, native, "findModule", JS_NewCFunction(ctx, JsFindModule, "findModule", 1));
    JS_SetPropertyStr(ctx, native, "findSymbol", JS_NewCFunction(ctx, JsFindSymbol, "findSymbol", 2));
    JS_SetPropertyStr(ctx, native, "findSymbolsMatching", JS_NewCFunction(ctx, JsFindSymbolsMatching, "findSymbolsMatching", 2));
    JS_SetPropertyStr(ctx, native, "dumpNative", JS_NewCFunction(ctx, JsDumpNative, "dumpNative", 2));
    JS_SetPropertyStr(ctx, native, "hook", JS_NewCFunction(ctx, JsNativeHook, "hook", 2));
    JS_SetPropertyStr(ctx, native, "unhookAll", JS_NewCFunction(ctx, JsNativeUnhookAll, "unhookAll", 0));

    JSValue debugSymbol = JS_NewObject(ctx);
    JS_SetPropertyStr(ctx, debugSymbol, "fromAddress", JS_NewCFunction(ctx, JsDebugSymbolFromAddress, "fromAddress", 1));
    JS_SetPropertyStr(ctx, debugSymbol, "fromName", JS_NewCFunction(ctx, JsDebugSymbolFromName, "fromName", 1));
    JS_SetPropertyStr(ctx, debugSymbol, "getFunctionByName", JS_NewCFunction(ctx, JsDebugSymbolGetFunctionByName, "getFunctionByName", 1));
    JS_SetPropertyStr(ctx, debugSymbol, "findSymbolByName", JS_NewCFunction(ctx, JsDebugSymbolFindSymbolByName, "findSymbolByName", 2));
    JS_SetPropertyStr(ctx, debugSymbol, "findSymbolsByName", JS_NewCFunction(ctx, JsDebugSymbolFindSymbolByName, "findSymbolsByName", 2));
    JS_SetPropertyStr(ctx, native, "DebugSymbol", JS_DupValue(ctx, debugSymbol));
    JS_SetPropertyStr(ctx, global, "DebugSymbol", debugSymbol);

    // Frida-style Process namespace
    JSValue proc = JS_NewObject(ctx);
    JS_SetPropertyStr(ctx, proc, "id", JS_NewInt32(ctx, static_cast<int32_t>(getpid())));
    JS_SetPropertyStr(ctx, proc, "arch", JS_NewString(ctx, "arm64"));
    JS_SetPropertyStr(ctx, proc, "platform", JS_NewString(ctx, "linux"));
    JS_SetPropertyStr(ctx, proc, "pointerSize", JS_NewInt32(ctx, static_cast<int32_t>(sizeof(void*))));
    JS_SetPropertyStr(ctx, proc, "pageSize", JS_NewInt32(ctx, static_cast<int32_t>(getpagesize())));
    JS_SetPropertyStr(ctx, proc, "getCurrentThreadId", JS_NewCFunction(ctx, JsProcessGetCurrentThreadId, "getCurrentThreadId", 0));
    JS_SetPropertyStr(ctx, proc, "enumerateThreads", JS_NewCFunction(ctx, JsProcessEnumerateThreads, "enumerateThreads", 0));
    JS_SetPropertyStr(ctx, proc, "threads", JS_NewCFunction(ctx, JsProcessEnumerateThreads, "threads", 0));
    JS_SetPropertyStr(ctx, proc, "enumerateModules", JS_NewCFunction(ctx, JsProcessEnumerateModules, "enumerateModules", 1));
    JS_SetPropertyStr(ctx, proc, "modules", JS_NewCFunction(ctx, JsProcessEnumerateModules, "modules", 1));
    JS_SetPropertyStr(ctx, proc, "findModuleByName", JS_NewCFunction(ctx, JsProcessFindModuleByName, "findModuleByName", 1));
    JS_SetPropertyStr(ctx, proc, "getModuleByName", JS_NewCFunction(ctx, JsProcessFindModuleByName, "getModuleByName", 1));
    JS_SetPropertyStr(ctx, proc, "findModule", JS_NewCFunction(ctx, JsProcessFindModuleByName, "findModule", 1));
    JS_SetPropertyStr(ctx, proc, "findModuleByAddress", JS_NewCFunction(ctx, JsProcessFindModuleByAddress, "findModuleByAddress", 1));
    JS_SetPropertyStr(ctx, proc, "getModuleByAddress", JS_NewCFunction(ctx, JsProcessFindModuleByAddress, "getModuleByAddress", 1));
    JS_SetPropertyStr(ctx, proc, "findSymbol", JS_NewCFunction(ctx, JsProcessFindSymbol, "findSymbol", 2));
    JS_SetPropertyStr(ctx, proc, "findSymbolByName", JS_NewCFunction(ctx, JsProcessFindSymbol, "findSymbolByName", 2));
    JS_SetPropertyStr(ctx, proc, "findSymbolsMatching", JS_NewCFunction(ctx, JsFindSymbolsMatching, "findSymbolsMatching", 2));
    JS_SetPropertyStr(ctx, proc, "enumerateRanges", JS_NewCFunction(ctx, JsProcessEnumerateRanges, "enumerateRanges", 1));
    JS_SetPropertyStr(ctx, proc, "isPaused", JS_NewCFunction(ctx, JsProcessIsPaused, "isPaused", 0));
    JS_SetPropertyStr(ctx, proc, "resume", JS_NewCFunction(ctx, JsProcessResume, "resume", 0));
    JS_SetPropertyStr(ctx, global, "Process", proc);

    // Flat global aliases
    JS_SetPropertyStr(ctx, global, "findModule", JS_NewCFunction(ctx, JsFindModule, "findModule", 1));
    JS_SetPropertyStr(ctx, global, "findmodule", JS_NewCFunction(ctx, JsFindModule, "findmodule", 1));
    JS_SetPropertyStr(ctx, global, "findSymbol", JS_NewCFunction(ctx, JsFindSymbol, "findSymbol", 2));
    JS_SetPropertyStr(ctx, global, "findsymbol", JS_NewCFunction(ctx, JsFindSymbol, "findsymbol", 2));
    JS_SetPropertyStr(ctx, global, "findSymbolsMatching", JS_NewCFunction(ctx, JsFindSymbolsMatching, "findSymbolsMatching", 2));
    JS_SetPropertyStr(ctx, global, "findsymbolsmatching", JS_NewCFunction(ctx, JsFindSymbolsMatching, "findsymbolsmatching", 2));
    JS_SetPropertyStr(ctx, global, "dumpNative", JS_NewCFunction(ctx, JsDumpNative, "dumpNative", 2));
    JS_SetPropertyStr(ctx, global, "dumpnative", JS_NewCFunction(ctx, JsDumpNative, "dumpnative", 2));
    JS_SetPropertyStr(ctx, global, "nhook", JS_NewCFunction(ctx, JsNativeHook, "nhook", 2));
    JS_SetPropertyStr(ctx, global, "nunhookall", JS_NewCFunction(ctx, JsNativeUnhookAll, "nunhookall", 0));
    JS_SetPropertyStr(ctx, global, "resume", JS_NewCFunction(ctx, JsProcessResume, "resume", 0));
}

}} // namespace artpi::agent
