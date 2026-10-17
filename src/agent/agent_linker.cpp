#include "agent_linker.h"
#include "agent_common.h"
#include <link.h>
#include <dlfcn.h>
#include <cstdint>
#include <cinttypes>
#include <cstring>
#include <string>
#include <vector>
#include <sstream>
#include <iomanip>
#include "xdl.h"
#include "frida-gum.h"

namespace artpi { namespace agent {

namespace {

#if defined(__aarch64__) || defined(__x86_64__)
static const char* kLinkerName = "linker64";
#else
static const char* kLinkerName = "linker";
#endif

using FnGetSomain = void* (*)();
using FnGetSoname = const char* (*)(void*);
using FnFindContainingLib = void* (*)(const void*);
using FnLoaderDlopen = void* (*)(const char*, int, const void*);

static FnGetSomain g_fnGetSomain = nullptr;
static FnGetSoname g_fnGetSoname = nullptr;
static FnFindContainingLib g_fnFindContainingLib = nullptr;
static FnLoaderDlopen g_fnLoaderDlopen = nullptr;
static bool g_linkerSymbolsResolved = false;

static void ResolveLinkerSymbols() {
    if (g_linkerSymbolsResolved) return;
    g_linkerSymbolsResolved = true;

    void* handle = xdl_open(kLinkerName, XDL_DEFAULT);
    if (!handle) return;

    auto resolve = [handle](const char* sym1, const char* sym2) -> void* {
        void* p = xdl_dsym(handle, sym1, nullptr);
        if (!p) p = xdl_sym(handle, sym1, nullptr);
        if (!p && sym2) p = xdl_dsym(handle, sym2, nullptr);
        if (!p && sym2) p = xdl_sym(handle, sym2, nullptr);
        return p;
    };

    g_fnGetSomain = reinterpret_cast<FnGetSomain>(
        resolve("__dl__Z17solist_get_somainv", "_Z17solist_get_somainv"));
    g_fnGetSoname = reinterpret_cast<FnGetSoname>(
        resolve("__dl__ZNK6soinfo10get_sonameEv", "_ZNK6soinfo10get_sonameEv"));
    g_fnFindContainingLib = reinterpret_cast<FnFindContainingLib>(
        resolve("__dl__Z23find_containing_libraryPKv", "_Z23find_containing_libraryPKv"));
    g_fnLoaderDlopen = reinterpret_cast<FnLoaderDlopen>(
        resolve("__dl___loader_dlopen", "__loader_dlopen"));

    xdl_close(handle);
}

struct ParsedElfInfo {
    std::string soName;
    uintptr_t base = 0;
    size_t size = 0;
    uintptr_t load_bias = 0;
    const void* phdr = nullptr;
    size_t phnum = 0;
    const void* dynamic = nullptr;
    uintptr_t strtab = 0;
    uintptr_t symtab = 0;
    size_t syment_size = 0;
    size_t strtab_size = 0;
    std::vector<std::pair<uintptr_t, std::string>> ctors;
};

static bool ParseElfFromBase(uintptr_t base, ParsedElfInfo& out) {
    if (base < 0x1000) return false;
    if (!gum_memory_is_readable(reinterpret_cast<const void*>(base), sizeof(ElfW(Ehdr)))) {
        return false;
    }
    const ElfW(Ehdr)* ehdr = reinterpret_cast<const ElfW(Ehdr)*>(base);
    if (ehdr->e_ident[EI_MAG0] != ELFMAG0 || ehdr->e_ident[EI_MAG1] != ELFMAG1 ||
        ehdr->e_ident[EI_MAG2] != ELFMAG2 || ehdr->e_ident[EI_MAG3] != ELFMAG3) {
        return false;
    }
    if (ehdr->e_phoff == 0 || ehdr->e_phnum == 0) return false;

    uintptr_t phdr_addr = base + ehdr->e_phoff;
    if (!gum_memory_is_readable(reinterpret_cast<const void*>(phdr_addr), sizeof(ElfW(Phdr)) * ehdr->e_phnum)) {
        return false;
    }
    const ElfW(Phdr)* phdr = reinterpret_cast<const ElfW(Phdr)*>(phdr_addr);
    out.base = base;
    out.phdr = phdr;
    out.phnum = ehdr->e_phnum;

    uintptr_t load_bias = base;
    for (size_t i = 0; i < ehdr->e_phnum; i++) {
        if (phdr[i].p_type == PT_LOAD) {
            load_bias = base - phdr[i].p_vaddr;
            break;
        }
    }
    out.load_bias = load_bias;

    // Estimate size from PT_LOAD segments
    uintptr_t min_vaddr = ~0UL, max_vaddr = 0;
    for (size_t i = 0; i < ehdr->e_phnum; i++) {
        if (phdr[i].p_type == PT_LOAD) {
            if (phdr[i].p_vaddr < min_vaddr) min_vaddr = phdr[i].p_vaddr;
            if (phdr[i].p_vaddr + phdr[i].p_memsz > max_vaddr) max_vaddr = phdr[i].p_vaddr + phdr[i].p_memsz;
        }
    }
    if (max_vaddr > min_vaddr) out.size = max_vaddr - min_vaddr;

    const ElfW(Dyn)* dynamic = nullptr;
    for (size_t i = 0; i < ehdr->e_phnum; i++) {
        if (phdr[i].p_type == PT_DYNAMIC) {
            dynamic = reinterpret_cast<const ElfW(Dyn)*>(load_bias + phdr[i].p_vaddr);
            break;
        }
    }
    if (!dynamic || !gum_memory_is_readable(dynamic, sizeof(ElfW(Dyn)))) return true;
    out.dynamic = dynamic;

    uintptr_t soname_idx = 0;
    uintptr_t init_func = 0;
    uintptr_t init_array = 0;
    size_t init_array_sz = 0;

    for (const ElfW(Dyn)* d = dynamic; ; d++) {
        if (!gum_memory_is_readable(d, sizeof(ElfW(Dyn)))) break;
        if (d->d_tag == DT_NULL) break;
        switch (d->d_tag) {
            case DT_STRTAB:
                out.strtab = (d->d_un.d_ptr < base) ? (load_bias + d->d_un.d_ptr) : d->d_un.d_ptr;
                break;
            case DT_STRSZ:
                out.strtab_size = d->d_un.d_val;
                break;
            case DT_SYMTAB:
                out.symtab = (d->d_un.d_ptr < base) ? (load_bias + d->d_un.d_ptr) : d->d_un.d_ptr;
                break;
            case DT_SYMENT:
                out.syment_size = d->d_un.d_val;
                break;
            case DT_SONAME:
                soname_idx = d->d_un.d_val;
                break;
            case DT_INIT:
                init_func = (d->d_un.d_ptr < base) ? (load_bias + d->d_un.d_ptr) : d->d_un.d_ptr;
                break;
            case DT_INIT_ARRAY:
                init_array = (d->d_un.d_ptr < base) ? (load_bias + d->d_un.d_ptr) : d->d_un.d_ptr;
                break;
            case DT_INIT_ARRAYSZ:
                init_array_sz = d->d_un.d_val;
                break;
        }
    }

    if (out.strtab && soname_idx && gum_memory_is_readable(reinterpret_cast<const void*>(out.strtab + soname_idx), 1)) {
        out.soName = reinterpret_cast<const char*>(out.strtab + soname_idx);
    }
    if (out.soName.empty()) {
        Dl_info dli{};
        if (dladdr(reinterpret_cast<const void*>(base), &dli) && dli.dli_fname) {
            const char* slash = std::strrchr(dli.dli_fname, '/');
            out.soName = slash ? (slash + 1) : dli.dli_fname;
        }
    }

    if (init_func && init_func != static_cast<uintptr_t>(-1)) {
        out.ctors.push_back({ init_func, "DT_INIT" });
    }
    if (init_array && init_array_sz > 0) {
        size_t count = init_array_sz / sizeof(void*);
        if (gum_memory_is_readable(reinterpret_cast<const void*>(init_array), init_array_sz)) {
            const uintptr_t* arr = reinterpret_cast<const uintptr_t*>(init_array);
            for (size_t i = 0; i < count; i++) {
                uintptr_t fn = arr[i];
                if (fn != 0 && fn != static_cast<uintptr_t>(-1)) {
                    char desc[64];
                    uintptr_t offset = (fn >= base) ? (fn - base) : fn;
                    snprintf(desc, sizeof(desc), "DT_INIT_ARRAY[%zu] (+0x%" PRIxPTR ")", i, offset);
                    out.ctors.push_back({ fn, desc });
                }
            }
        }
    }
    return true;
}

static uintptr_t FindSoinfoBase(uintptr_t soinfo_ptr) {
    if (soinfo_ptr < 0x1000) return 0;
    if (!gum_memory_is_readable(reinterpret_cast<const void*>(soinfo_ptr), 0x50)) return 0;
    for (size_t off = 0; off <= 0x120; off += sizeof(void*)) {
        uintptr_t candidate = 0;
        if (!gum_memory_is_readable(reinterpret_cast<const void*>(soinfo_ptr + off), sizeof(void*))) break;
        std::memcpy(&candidate, reinterpret_cast<const void*>(soinfo_ptr + off), sizeof(void*));
        if (candidate >= 0x1000 && (candidate & 0xfff) == 0) {
            if (gum_memory_is_readable(reinterpret_cast<const void*>(candidate), 4)) {
                if (*reinterpret_cast<const uint32_t*>(candidate) == 0x464c457f) {
                    return candidate;
                }
            }
        }
    }
    return 0;
}

static uintptr_t FindSoinfoNext(uintptr_t soinfo_ptr, uintptr_t base) {
    if (soinfo_ptr < 0x1000) return 0;
    // In soinfo layout: `next` is a pointer slot following `dynamic`
    // We scan pointer slots after the base slot for another soinfo pointer
    size_t start_off = sizeof(void*) == 8 ? 0x28 : 0x14;
    for (size_t off = start_off; off <= start_off + 0x40; off += sizeof(void*)) {
        uintptr_t candidate = 0;
        if (!gum_memory_is_readable(reinterpret_cast<const void*>(soinfo_ptr + off), sizeof(void*))) break;
        std::memcpy(&candidate, reinterpret_cast<const void*>(soinfo_ptr + off), sizeof(void*));
        if (candidate >= 0x1000 && candidate != soinfo_ptr && candidate != base) {
            uintptr_t cand_base = FindSoinfoBase(candidate);
            if (cand_base != 0) {
                return candidate;
            }
        }
    }
    return 0;
}

static JSValue MakeSoinfoJsObject(JSContext* ctx, uintptr_t soinfo_ptr, uintptr_t explicit_base = 0) {
    uintptr_t base = explicit_base ? explicit_base : FindSoinfoBase(soinfo_ptr);
    ParsedElfInfo elf;
    if (base) {
        ParseElfFromBase(base, elf);
    }

    if (elf.soName.empty() && g_fnGetSoname && soinfo_ptr) {
        const char* name = g_fnGetSoname(reinterpret_cast<void*>(soinfo_ptr));
        if (name && name[0]) elf.soName = name;
    }
    if (elf.soName.empty() && base) {
        char buf[64];
        snprintf(buf, sizeof(buf), "lib@0x%" PRIxPTR, base);
        elf.soName = buf;
    }

    JSValue obj = JS_NewObject(ctx);
    char hex[32];

    snprintf(hex, sizeof(hex), "0x%" PRIxPTR, soinfo_ptr);
    JS_SetPropertyStr(ctx, obj, "ptr", JS_NewString(ctx, hex));
    JS_SetPropertyStr(ctx, obj, "name", JS_NewString(ctx, elf.soName.c_str()));
    JS_SetPropertyStr(ctx, obj, "soname", JS_NewString(ctx, elf.soName.c_str()));

    snprintf(hex, sizeof(hex), "0x%" PRIxPTR, base);
    JS_SetPropertyStr(ctx, obj, "base", JS_NewString(ctx, hex));
    JS_SetPropertyStr(ctx, obj, "size", JS_NewInt64(ctx, static_cast<int64_t>(elf.size)));

    snprintf(hex, sizeof(hex), "0x%" PRIxPTR, elf.load_bias);
    JS_SetPropertyStr(ctx, obj, "loadBias", JS_NewString(ctx, hex));

    snprintf(hex, sizeof(hex), "0x%" PRIxPTR, reinterpret_cast<uintptr_t>(elf.phdr));
    JS_SetPropertyStr(ctx, obj, "phdr", JS_NewString(ctx, hex));
    JS_SetPropertyStr(ctx, obj, "phnum", JS_NewInt32(ctx, static_cast<int32_t>(elf.phnum)));

    snprintf(hex, sizeof(hex), "0x%" PRIxPTR, reinterpret_cast<uintptr_t>(elf.dynamic));
    JS_SetPropertyStr(ctx, obj, "dynamic", JS_NewString(ctx, hex));

    uintptr_t next = FindSoinfoNext(soinfo_ptr, base);
    snprintf(hex, sizeof(hex), "0x%" PRIxPTR, next);
    JS_SetPropertyStr(ctx, obj, "next", JS_NewString(ctx, hex));

    // Constructors array
    JSValue ctorsArr = JS_NewArray(ctx);
    uint32_t cidx = 0;
    for (const auto& c : elf.ctors) {
        JSValue cObj = JS_NewObject(ctx);
        JS_SetPropertyStr(ctx, cObj, "desc", JS_NewString(ctx, c.second.c_str()));
        snprintf(hex, sizeof(hex), "0x%" PRIxPTR, c.first);
        JS_SetPropertyStr(ctx, cObj, "address", JS_NewString(ctx, hex));
        JS_SetPropertyStr(ctx, cObj, "func", JS_NewString(ctx, hex));
        uintptr_t offset = (c.first >= base) ? (c.first - base) : c.first;
        snprintf(hex, sizeof(hex), "0x%" PRIxPTR, offset);
        JS_SetPropertyStr(ctx, cObj, "offset", JS_NewString(ctx, hex));
        JS_SetPropertyStr(ctx, cObj, "type", JS_NewString(ctx, c.second.find("INIT_ARRAY") != std::string::npos ? "DT_INIT_ARRAY" : "DT_INIT"));
        JS_SetPropertyUint32(ctx, ctorsArr, cidx++, cObj);
    }
    JS_SetPropertyStr(ctx, obj, "constructors", ctorsArr);

    // dump() method
    std::string dumpStr;
    {
        std::ostringstream ss;
        ss << "[soinfo @ " << (void*)soinfo_ptr << "] " << elf.soName << "\n"
           << "  base     : 0x" << std::hex << base << " (size: 0x" << elf.size << ", bias: 0x" << elf.load_bias << ")\n"
           << "  phdr     : " << elf.phdr << " (phnum: " << std::dec << elf.phnum << ")\n"
           << "  dynamic  : " << elf.dynamic << "\n"
           << "  constructors: " << elf.ctors.size() << " found\n";
        for (size_t i = 0; i < elf.ctors.size(); i++) {
            ss << "    [" << i << "] " << elf.ctors[i].second << " @ 0x" << std::hex << elf.ctors[i].first << "\n";
        }
        dumpStr = ss.str();
    }
    JS_SetPropertyStr(ctx, obj, "dumpText", JS_NewString(ctx, dumpStr.c_str()));

    return obj;
}

// Linker.main() / linker.main()
static JSValue JsLinkerMain(JSContext* ctx, JSValueConst /*this_val*/, int /*argc*/, JSValueConst* /*argv*/) {
    ResolveLinkerSymbols();
    if (!g_fnGetSomain) {
        return JS_ThrowInternalError(ctx, "[!] Linker symbol solist_get_somain not available");
    }
    void* somain = g_fnGetSomain();
    if (!somain) {
        return JS_NULL;
    }
    return MakeSoinfoJsObject(ctx, reinterpret_cast<uintptr_t>(somain));
}

// Linker.list() / linker.list()
static JSValue JsLinkerList(JSContext* ctx, JSValueConst /*this_val*/, int /*argc*/, JSValueConst* /*argv*/) {
    ResolveLinkerSymbols();
    JSValue arr = JS_NewArray(ctx);
    uint32_t arrIdx = 0;

    std::vector<uintptr_t> visitedBases;

    // 1. Traverse via solist chain if available
    if (g_fnGetSomain) {
        uintptr_t curr = reinterpret_cast<uintptr_t>(g_fnGetSomain());
        int limit = 512;
        while (curr >= 0x1000 && limit-- > 0) {
            uintptr_t base = FindSoinfoBase(curr);
            if (base) {
                bool seen = false;
                for (auto b : visitedBases) { if (b == base) { seen = true; break; } }
                if (!seen) {
                    visitedBases.push_back(base);
                    JSValue obj = MakeSoinfoJsObject(ctx, curr, base);
                    JS_SetPropertyUint32(ctx, arr, arrIdx++, obj);
                }
            }
            uintptr_t next = FindSoinfoNext(curr, base);
            if (next == 0 || next == curr) break;
            curr = next;
        }
    }

    // 2. Supplement via dl_iterate_phdr to ensure 100% complete module coverage
    struct PhdrContext {
        std::vector<uintptr_t>* visited;
        JSContext* ctx;
        JSValue arr;
        uint32_t* arrIdx;
    } pctx{ &visitedBases, ctx, arr, &arrIdx };

    dl_iterate_phdr([](struct dl_phdr_info* info, size_t /*size*/, void* data) -> int {
        auto* p = static_cast<PhdrContext*>(data);
        uintptr_t base = static_cast<uintptr_t>(info->dlpi_addr);
        if (base >= 0x1000) {
            bool seen = false;
            for (auto b : *p->visited) { if (b == base) { seen = true; break; } }
            if (!seen) {
                p->visited->push_back(base);
                void* sinfo = nullptr;
                if (g_fnFindContainingLib) {
                    sinfo = g_fnFindContainingLib(reinterpret_cast<const void*>(base));
                }
                JSValue obj = MakeSoinfoJsObject(p->ctx, reinterpret_cast<uintptr_t>(sinfo), base);
                JS_SetPropertyUint32(p->ctx, p->arr, (*p->arrIdx)++, obj);
            }
        }
        return 0;
    }, &pctx);

    return arr;
}

// Linker.find(nameOrAddr) / linker.find(...)
static JSValue JsLinkerFind(JSContext* ctx, JSValueConst /*this_val*/, int argc, JSValueConst* argv) {
    if (argc < 1) {
        return JS_ThrowTypeError(ctx, "Usage: Linker.find(nameOrAddr)");
    }
    ResolveLinkerSymbols();

    uintptr_t targetAddr = 0;
    std::string targetName;

    if (JS_IsString(argv[0])) {
        const char* s = JS_ToCString(ctx, argv[0]);
        if (s) { targetName = s; JS_FreeCString(ctx, s); }
    } else {
        int64_t v = 0;
        JS_ToInt64(ctx, &v, argv[0]);
        targetAddr = static_cast<uintptr_t>(v);
    }

    // Lookup by address using find_containing_library
    if (targetAddr >= 0x1000 && g_fnFindContainingLib) {
        void* sinfo = g_fnFindContainingLib(reinterpret_cast<const void*>(targetAddr));
        if (sinfo) {
            return MakeSoinfoJsObject(ctx, reinterpret_cast<uintptr_t>(sinfo));
        }
    }

    // Lookup by name or address via iterating all modules
    JSValue list = JsLinkerList(ctx, JS_UNDEFINED, 0, nullptr);
    if (!JS_IsArray(ctx, list)) return JS_NULL;

    uint32_t len = 0;
    JSValue lenVal = JS_GetPropertyStr(ctx, list, "length");
    JS_ToUint32(ctx, &len, lenVal);
    JS_FreeValue(ctx, lenVal);

    JSValue match = JS_NULL;
    for (uint32_t i = 0; i < len; i++) {
        JSValue item = JS_GetPropertyUint32(ctx, list, i);
        if (JS_IsObject(item)) {
            if (!targetName.empty()) {
                JSValue nameVal = JS_GetPropertyStr(ctx, item, "name");
                const char* n = JS_ToCString(ctx, nameVal);
                if (n) {
                    if (std::string(n).find(targetName) != std::string::npos) {
                        match = JS_DupValue(ctx, item);
                    }
                    JS_FreeCString(ctx, n);
                }
                JS_FreeValue(ctx, nameVal);
            } else if (targetAddr >= 0x1000) {
                JSValue baseVal = JS_GetPropertyStr(ctx, item, "base");
                const char* bs = JS_ToCString(ctx, baseVal);
                uintptr_t b = bs ? std::strtoull(bs, nullptr, 0) : 0;
                if (bs) JS_FreeCString(ctx, bs);
                JS_FreeValue(ctx, baseVal);

                JSValue szVal = JS_GetPropertyStr(ctx, item, "size");
                int64_t sz = 0;
                JS_ToInt64(ctx, &sz, szVal);
                JS_FreeValue(ctx, szVal);

                if (b && targetAddr >= b && targetAddr < (b + static_cast<size_t>(sz))) {
                    match = JS_DupValue(ctx, item);
                }
            }
        }
        JS_FreeValue(ctx, item);
        if (!JS_IsNull(match)) break;
    }
    JS_FreeValue(ctx, list);
    return match;
}

// Linker.linkMap() / linker.linkMap()
static JSValue JsLinkerLinkMap(JSContext* ctx, JSValueConst /*this_val*/, int /*argc*/, JSValueConst* /*argv*/) {
    ResolveLinkerSymbols();
    JSValue arr = JS_NewArray(ctx);
    uint32_t idx = 0;

    // Traverse via dl_iterate_phdr to extract all loaded link map entries
    struct MapCtx {
        JSContext* ctx;
        JSValue arr;
        uint32_t* idx;
    } mctx{ ctx, arr, &idx };

    dl_iterate_phdr([](struct dl_phdr_info* info, size_t /*size*/, void* data) -> int {
        auto* p = static_cast<MapCtx*>(data);
        JSValue entry = JS_NewObject(p->ctx);
        char hex[32];
        snprintf(hex, sizeof(hex), "0x%" PRIxPTR, static_cast<uintptr_t>(info->dlpi_addr));
        JS_SetPropertyStr(p->ctx, entry, "addr", JS_NewString(p->ctx, hex));
        JS_SetPropertyStr(p->ctx, entry, "name", JS_NewString(p->ctx, info->dlpi_name ? info->dlpi_name : ""));
        JS_SetPropertyStr(p->ctx, entry, "phnum", JS_NewInt32(p->ctx, static_cast<int32_t>(info->dlpi_phnum)));
        JS_SetPropertyUint32(p->ctx, p->arr, (*p->idx)++, entry);
        return 0;
    }, &mctx);

    return arr;
}

// Linker.getConstructors(nameOrAddr) / linker.getConstructors(...)
static JSValue JsLinkerGetConstructors(JSContext* ctx, JSValueConst /*this_val*/, int argc, JSValueConst* argv) {
    if (argc < 1) {
        return JS_ThrowTypeError(ctx, "Usage: Linker.getConstructors(soNameOrAddr)");
    }
    JSValue info = JsLinkerFind(ctx, JS_UNDEFINED, argc, argv);
    if (JS_IsNull(info) || !JS_IsObject(info)) {
        return JS_NULL;
    }
    JSValue ctors = JS_GetPropertyStr(ctx, info, "constructors");
    JSValue res = JS_NewObject(ctx);
    JS_SetPropertyStr(ctx, res, "name", JS_GetPropertyStr(ctx, info, "name"));
    JS_SetPropertyStr(ctx, res, "base", JS_GetPropertyStr(ctx, info, "base"));
    JS_SetPropertyStr(ctx, res, "constructors", ctors);
    JS_FreeValue(ctx, info);
    return res;
}

// Linker.load(libName) / linker.load(...)
static JSValue JsLinkerLoad(JSContext* ctx, JSValueConst /*this_val*/, int argc, JSValueConst* argv) {
    if (argc < 1 || !JS_IsString(argv[0])) {
        return JS_ThrowTypeError(ctx, "Usage: Linker.load(libraryName)");
    }
    ResolveLinkerSymbols();

    const char* libName = JS_ToCString(ctx, argv[0]);
    if (!libName) return JS_NULL;

    void* handle = nullptr;
    if (g_fnLoaderDlopen) {
        void* artHandle = xdl_open("libart.so", XDL_DEFAULT);
        void* callerBase = artHandle;
        if (artHandle) {
            xdl_info_t dli;
            if (xdl_info(artHandle, XDL_DI_DLINFO, &dli) == 0) {
                callerBase = dli.dli_fbase;
            }
            xdl_close(artHandle);
        }
        handle = g_fnLoaderDlopen(libName, RTLD_NOW, callerBase);
    }
    if (!handle) {
        handle = xdl_open(libName, XDL_DEFAULT);
    }
    if (!handle) {
        handle = dlopen(libName, RTLD_NOW);
    }

    JS_FreeCString(ctx, libName);

    char hex[32];
    snprintf(hex, sizeof(hex), "0x%" PRIxPTR, reinterpret_cast<uintptr_t>(handle));
    return JS_NewString(ctx, hex);
}

// Linker.dump(target) / linker.dump(...)
static JSValue JsLinkerDump(JSContext* ctx, JSValueConst /*this_val*/, int argc, JSValueConst* argv) {
    if (argc < 1) {
        return JS_ThrowTypeError(ctx, "Usage: Linker.dump(soNameOrAddr)");
    }
    JSValue info = JsLinkerFind(ctx, JS_UNDEFINED, argc, argv);
    if (JS_IsNull(info) || !JS_IsObject(info)) {
        return JS_NewString(ctx, "[-] SO not found");
    }
    JSValue dt = JS_GetPropertyStr(ctx, info, "dumpText");
    JS_FreeValue(ctx, info);
    return dt;
}

static void PopulateLinkerObject(JSContext* ctx, JSValue obj) {
    JS_SetPropertyStr(ctx, obj, "main", JS_NewCFunction(ctx, JsLinkerMain, "main", 0));
    JS_SetPropertyStr(ctx, obj, "somain", JS_NewCFunction(ctx, JsLinkerMain, "somain", 0));
    JS_SetPropertyStr(ctx, obj, "list", JS_NewCFunction(ctx, JsLinkerList, "list", 0));
    JS_SetPropertyStr(ctx, obj, "modules", JS_NewCFunction(ctx, JsLinkerList, "modules", 0));
    JS_SetPropertyStr(ctx, obj, "find", JS_NewCFunction(ctx, JsLinkerFind, "find", 1));
    JS_SetPropertyStr(ctx, obj, "findSoinfo", JS_NewCFunction(ctx, JsLinkerFind, "findSoinfo", 1));
    JS_SetPropertyStr(ctx, obj, "linkMap", JS_NewCFunction(ctx, JsLinkerLinkMap, "linkMap", 0));
    JS_SetPropertyStr(ctx, obj, "getConstructors", JS_NewCFunction(ctx, JsLinkerGetConstructors, "getConstructors", 1));
    JS_SetPropertyStr(ctx, obj, "load", JS_NewCFunction(ctx, JsLinkerLoad, "load", 1));
    JS_SetPropertyStr(ctx, obj, "dump", JS_NewCFunction(ctx, JsLinkerDump, "dump", 1));
}

} // namespace

void RegisterLinkerApis(JSContext* ctx, JSValue global) {
    // 1. Linker (Uppercase L)
    JSValue linkerObj = JS_NewObject(ctx);
    PopulateLinkerObject(ctx, linkerObj);
    JS_SetPropertyStr(ctx, global, "Linker", JS_DupValue(ctx, linkerObj));

    // 2. linker (Lowercase l) - case insensitive requirement
    JS_SetPropertyStr(ctx, global, "linker", linkerObj);
}

}} // namespace artpi::agent
