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

struct ElfFuncEntry {
    uintptr_t func = 0;
    std::string tag;        // e.g. "DT_INIT", "DT_INIT_ARRAY[0] (+0x475bc)", "DT_FINI", etc.
    std::string type;       // "DT_INIT", "DT_INIT_ARRAY", "DT_PREINIT_ARRAY", "DT_FINI", "DT_FINI_ARRAY"
    std::string symbol;     // symbol name if resolved via xdl_addr, otherwise empty
    std::string desc;       // e.g. "DT_INIT (custom_dt_init)" or "DT_INIT"
    uintptr_t offset = 0;
};

struct ParsedElfInfo {
    std::string soName;
    uintptr_t base = 0;
    size_t size = 0;
    uintptr_t load_bias = 0;
    const void* phdr = nullptr;
    size_t phnum = 0;
    const void* dynamic = nullptr;
    uintptr_t strtab = 0;
    size_t strtab_size = 0;
    uintptr_t symtab = 0;
    size_t syment_size = 0;
    size_t symtab_count = 0;

    std::vector<std::string> needed;
    std::vector<ElfFuncEntry> ctors;
    std::vector<ElfFuncEntry> preinit;
    std::vector<ElfFuncEntry> dtors;
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
    std::vector<uintptr_t> needed_offsets;
    uintptr_t init_func = 0;
    uintptr_t init_array = 0;
    size_t init_array_sz = 0;
    uintptr_t preinit_array = 0;
    size_t preinit_array_sz = 0;
    uintptr_t fini_func = 0;
    uintptr_t fini_array = 0;
    size_t fini_array_sz = 0;

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
            case DT_NEEDED:
                needed_offsets.push_back(d->d_un.d_val);
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
            case DT_PREINIT_ARRAY:
                preinit_array = (d->d_un.d_ptr < base) ? (load_bias + d->d_un.d_ptr) : d->d_un.d_ptr;
                break;
            case DT_PREINIT_ARRAYSZ:
                preinit_array_sz = d->d_un.d_val;
                break;
            case DT_FINI:
                fini_func = (d->d_un.d_ptr < base) ? (load_bias + d->d_un.d_ptr) : d->d_un.d_ptr;
                break;
            case DT_FINI_ARRAY:
                fini_array = (d->d_un.d_ptr < base) ? (load_bias + d->d_un.d_ptr) : d->d_un.d_ptr;
                break;
            case DT_FINI_ARRAYSZ:
                fini_array_sz = d->d_un.d_val;
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

    // Resolve needed shared libraries
    for (uintptr_t off : needed_offsets) {
        if (out.strtab && (off < out.strtab_size || out.strtab_size == 0) &&
            gum_memory_is_readable(reinterpret_cast<const void*>(out.strtab + off), 1)) {
            out.needed.push_back(reinterpret_cast<const char*>(out.strtab + off));
        }
    }

    // Compute symtab count if possible
    if (out.symtab && out.syment_size > 0 && out.strtab > out.symtab) {
        out.symtab_count = (out.strtab - out.symtab) / out.syment_size;
    }

    // Collect DT_INIT
    if (init_func && init_func != static_cast<uintptr_t>(-1)) {
        ElfFuncEntry entry;
        entry.func = init_func;
        entry.offset = (init_func >= base) ? (init_func - base) : init_func;
        entry.type = "DT_INIT";
        entry.tag = "DT_INIT";
        out.ctors.push_back(entry);
    }

    // Collect DT_INIT_ARRAY
    if (init_array && init_array_sz > 0) {
        size_t count = init_array_sz / sizeof(void*);
        if (gum_memory_is_readable(reinterpret_cast<const void*>(init_array), init_array_sz)) {
            const uintptr_t* arr = reinterpret_cast<const uintptr_t*>(init_array);
            for (size_t i = 0; i < count; i++) {
                uintptr_t fn = arr[i];
                if (fn != 0 && fn != static_cast<uintptr_t>(-1)) {
                    ElfFuncEntry entry;
                    entry.func = fn;
                    entry.offset = (fn >= base) ? (fn - base) : fn;
                    entry.type = "DT_INIT_ARRAY";
                    char desc[64];
                    snprintf(desc, sizeof(desc), "DT_INIT_ARRAY[%zu] (+0x%" PRIxPTR ")", i, entry.offset);
                    entry.tag = desc;
                    out.ctors.push_back(entry);
                }
            }
        }
    }

    // Collect DT_PREINIT_ARRAY
    if (preinit_array && preinit_array_sz > 0) {
        size_t count = preinit_array_sz / sizeof(void*);
        if (gum_memory_is_readable(reinterpret_cast<const void*>(preinit_array), preinit_array_sz)) {
            const uintptr_t* arr = reinterpret_cast<const uintptr_t*>(preinit_array);
            for (size_t i = 0; i < count; i++) {
                uintptr_t fn = arr[i];
                if (fn != 0 && fn != static_cast<uintptr_t>(-1)) {
                    ElfFuncEntry entry;
                    entry.func = fn;
                    entry.offset = (fn >= base) ? (fn - base) : fn;
                    entry.type = "DT_PREINIT_ARRAY";
                    char desc[64];
                    snprintf(desc, sizeof(desc), "DT_PREINIT_ARRAY[%zu] (+0x%" PRIxPTR ")", i, entry.offset);
                    entry.tag = desc;
                    out.preinit.push_back(entry);
                }
            }
        }
    }

    // Collect DT_FINI
    if (fini_func && fini_func != static_cast<uintptr_t>(-1)) {
        ElfFuncEntry entry;
        entry.func = fini_func;
        entry.offset = (fini_func >= base) ? (fini_func - base) : fini_func;
        entry.type = "DT_FINI";
        entry.tag = "DT_FINI";
        out.dtors.push_back(entry);
    }

    // Collect DT_FINI_ARRAY
    if (fini_array && fini_array_sz > 0) {
        size_t count = fini_array_sz / sizeof(void*);
        if (gum_memory_is_readable(reinterpret_cast<const void*>(fini_array), fini_array_sz)) {
            const uintptr_t* arr = reinterpret_cast<const uintptr_t*>(fini_array);
            for (size_t i = 0; i < count; i++) {
                uintptr_t fn = arr[i];
                if (fn != 0 && fn != static_cast<uintptr_t>(-1)) {
                    ElfFuncEntry entry;
                    entry.func = fn;
                    entry.offset = (fn >= base) ? (fn - base) : fn;
                    entry.type = "DT_FINI_ARRAY";
                    char desc[64];
                    snprintf(desc, sizeof(desc), "DT_FINI_ARRAY[%zu] (+0x%" PRIxPTR ")", i, entry.offset);
                    entry.tag = desc;
                    out.dtors.push_back(entry);
                }
            }
        }
    }

    // Resolve symbols via xdl_addr
    void* xdlCache = nullptr;
    auto resolveAndFill = [&xdlCache](ElfFuncEntry& e) {
        if (e.func < 0x1000) return;
        xdl_info_t dli{};
        if (xdl_addr(reinterpret_cast<void*>(e.func), &dli, &xdlCache) != 0) {
            if (dli.dli_sname && dli.dli_sname[0] != '\0') {
                e.symbol = dli.dli_sname;
            }
        }
        if (!e.symbol.empty()) {
            e.desc = e.tag + " (" + e.symbol + ")";
        } else {
            e.desc = e.tag;
        }
    };

    for (auto& c : out.ctors) resolveAndFill(c);
    for (auto& p : out.preinit) resolveAndFill(p);
    for (auto& d : out.dtors) resolveAndFill(d);

    if (xdlCache) {
        xdl_addr_clean(&xdlCache);
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

    auto makeFuncListJsArray = [ctx](const std::vector<ElfFuncEntry>& list) -> JSValue {
        JSValue arr = JS_NewArray(ctx);
        uint32_t idx = 0;
        char hexBuf[32];
        for (const auto& item : list) {
            JSValue itemObj = JS_NewObject(ctx);
            JS_SetPropertyStr(ctx, itemObj, "desc", JS_NewString(ctx, item.desc.c_str()));
            JS_SetPropertyStr(ctx, itemObj, "tag", JS_NewString(ctx, item.tag.c_str()));
            JS_SetPropertyStr(ctx, itemObj, "type", JS_NewString(ctx, item.type.c_str()));
            JS_SetPropertyStr(ctx, itemObj, "symbol", JS_NewString(ctx, item.symbol.c_str()));
            snprintf(hexBuf, sizeof(hexBuf), "0x%" PRIxPTR, item.func);
            JS_SetPropertyStr(ctx, itemObj, "address", JS_NewString(ctx, hexBuf));
            JS_SetPropertyStr(ctx, itemObj, "func", JS_NewString(ctx, hexBuf));
            snprintf(hexBuf, sizeof(hexBuf), "0x%" PRIxPTR, item.offset);
            JS_SetPropertyStr(ctx, itemObj, "offset", JS_NewString(ctx, hexBuf));
            JS_SetPropertyUint32(ctx, arr, idx++, itemObj);
        }
        return arr;
    };

    JS_SetPropertyStr(ctx, obj, "constructors", makeFuncListJsArray(elf.ctors));
    JS_SetPropertyStr(ctx, obj, "destructors", makeFuncListJsArray(elf.dtors));
    if (!elf.preinit.empty()) {
        JS_SetPropertyStr(ctx, obj, "preinit", makeFuncListJsArray(elf.preinit));
    }

    // needed dependencies
    JSValue neededArr = JS_NewArray(ctx);
    for (uint32_t i = 0; i < elf.needed.size(); i++) {
        JS_SetPropertyUint32(ctx, neededArr, i, JS_NewString(ctx, elf.needed[i].c_str()));
    }
    JS_SetPropertyStr(ctx, obj, "needed", neededArr);
    JS_SetPropertyStr(ctx, obj, "dependencies", JS_DupValue(ctx, neededArr));

    if (elf.strtab) {
        snprintf(hex, sizeof(hex), "0x%" PRIxPTR, elf.strtab);
        JS_SetPropertyStr(ctx, obj, "strtab", JS_NewString(ctx, hex));
        JS_SetPropertyStr(ctx, obj, "strtabSize", JS_NewInt64(ctx, static_cast<int64_t>(elf.strtab_size)));
    }
    if (elf.symtab) {
        snprintf(hex, sizeof(hex), "0x%" PRIxPTR, elf.symtab);
        JS_SetPropertyStr(ctx, obj, "symtab", JS_NewString(ctx, hex));
        JS_SetPropertyStr(ctx, obj, "symentSize", JS_NewInt64(ctx, static_cast<int64_t>(elf.syment_size)));
        JS_SetPropertyStr(ctx, obj, "symtabCount", JS_NewInt64(ctx, static_cast<int64_t>(elf.symtab_count)));
    }

    // dump() method
    std::string dumpStr;
    {
        std::ostringstream ss;
        ss << "[soinfo @ " << (void*)soinfo_ptr << "] " << elf.soName << "\n"
           << "  base     : 0x" << std::hex << base << " (size: 0x" << elf.size << ", bias: 0x" << elf.load_bias << ")\n"
           << "  phdr     : " << elf.phdr << " (phnum: " << std::dec << elf.phnum << ")\n"
           << "  dynamic  : " << elf.dynamic << "\n";
        if (elf.strtab) {
            ss << "  strtab   : 0x" << std::hex << elf.strtab << " (size: 0x" << elf.strtab_size << ")\n";
        }
        if (elf.symtab) {
            ss << "  symtab   : 0x" << std::hex << elf.symtab;
            if (elf.symtab_count > 0) {
                ss << " (count: " << std::dec << elf.symtab_count << ", syment: " << elf.syment_size << ")";
            }
            ss << "\n";
        }
        if (!elf.needed.empty()) {
            ss << "  needed   : ";
            for (size_t i = 0; i < elf.needed.size(); i++) {
                if (i > 0) ss << ", ";
                ss << elf.needed[i];
            }
            ss << "\n";
        }
        if (!elf.preinit.empty()) {
            ss << "  preinit  : " << std::dec << elf.preinit.size() << " found\n";
            for (size_t i = 0; i < elf.preinit.size(); i++) {
                ss << "    [" << std::dec << i << "]\t" << elf.preinit[i].desc << " @ 0x" << std::hex << elf.preinit[i].func << "\n";
            }
        }
        ss << "  constructors: " << std::dec << elf.ctors.size() << " found\n";
        for (size_t i = 0; i < elf.ctors.size(); i++) {
            ss << "    [" << std::dec << i << "]\t" << elf.ctors[i].desc << " @ 0x" << std::hex << elf.ctors[i].func << "\n";
        }
        ss << "  destructors : " << std::dec << elf.dtors.size() << " found\n";
        for (size_t i = 0; i < elf.dtors.size(); i++) {
            ss << "    [" << std::dec << i << "]\t" << elf.dtors[i].desc << " @ 0x" << std::hex << elf.dtors[i].func << "\n";
        }
        dumpStr = ss.str();
    }
    JS_SetPropertyStr(ctx, obj, "dumpText", JS_NewString(ctx, dumpStr.c_str()));
    JS_SetPropertyStr(ctx, obj, "toString", JS_NewCFunction(ctx, [](JSContext* c, JSValueConst this_val, int, JSValueConst*) -> JSValue {
        return JS_GetPropertyStr(c, this_val, "dumpText");
    }, "toString", 0));

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

// Linker.getDestructors(nameOrAddr) / linker.getDestructors(...)
static JSValue JsLinkerGetDestructors(JSContext* ctx, JSValueConst /*this_val*/, int argc, JSValueConst* argv) {
    if (argc < 1) {
        return JS_ThrowTypeError(ctx, "Usage: Linker.getDestructors(soNameOrAddr)");
    }
    JSValue info = JsLinkerFind(ctx, JS_UNDEFINED, argc, argv);
    if (JS_IsNull(info) || !JS_IsObject(info)) {
        return JS_NULL;
    }
    JSValue dtors = JS_GetPropertyStr(ctx, info, "destructors");
    JSValue res = JS_NewObject(ctx);
    JS_SetPropertyStr(ctx, res, "name", JS_GetPropertyStr(ctx, info, "name"));
    JS_SetPropertyStr(ctx, res, "base", JS_GetPropertyStr(ctx, info, "base"));
    JS_SetPropertyStr(ctx, res, "destructors", dtors);
    JS_FreeValue(ctx, info);
    return res;
}

// Linker.symbols(nameOrAddr, maxCount) / linker.symbols(...)
static JSValue JsLinkerSymbols(JSContext* ctx, JSValueConst /*this_val*/, int argc, JSValueConst* argv) {
    if (argc < 1) {
        return JS_ThrowTypeError(ctx, "Usage: Linker.symbols(soNameOrAddr, [maxCount])");
    }
    JSValue info = JsLinkerFind(ctx, JS_UNDEFINED, 1, argv);
    if (JS_IsNull(info) || !JS_IsObject(info)) {
        return JS_NULL;
    }

    JSValue symtabVal = JS_GetPropertyStr(ctx, info, "symtab");
    const char* symtabStr = JS_ToCString(ctx, symtabVal);
    uintptr_t symtab = symtabStr ? std::strtoull(symtabStr, nullptr, 0) : 0;
    if (symtabStr) JS_FreeCString(ctx, symtabStr);
    JS_FreeValue(ctx, symtabVal);

    JSValue strtabVal = JS_GetPropertyStr(ctx, info, "strtab");
    const char* strtabStr = JS_ToCString(ctx, strtabVal);
    uintptr_t strtab = strtabStr ? std::strtoull(strtabStr, nullptr, 0) : 0;
    if (strtabStr) JS_FreeCString(ctx, strtabStr);
    JS_FreeValue(ctx, strtabVal);

    JSValue strtabSzVal = JS_GetPropertyStr(ctx, info, "strtabSize");
    int64_t strtabSize = 0;
    JS_ToInt64(ctx, &strtabSize, strtabSzVal);
    JS_FreeValue(ctx, strtabSzVal);

    JSValue symentSzVal = JS_GetPropertyStr(ctx, info, "symentSize");
    int64_t symentSize = sizeof(ElfW(Sym));
    if (JS_IsNumber(symentSzVal)) {
        JS_ToInt64(ctx, &symentSize, symentSzVal);
    }
    JS_FreeValue(ctx, symentSzVal);

    JSValue baseVal = JS_GetPropertyStr(ctx, info, "base");
    const char* baseStr = JS_ToCString(ctx, baseVal);
    uintptr_t base = baseStr ? std::strtoull(baseStr, nullptr, 0) : 0;
    if (baseStr) JS_FreeCString(ctx, baseStr);
    JS_FreeValue(ctx, baseVal);

    JS_FreeValue(ctx, info);

    if (!symtab || !strtab || symentSize <= 0) {
        return JS_NewArray(ctx);
    }

    size_t limit = 100;
    if (argc >= 2) {
        int32_t userLimit = 0;
        JS_ToInt32(ctx, &userLimit, argv[1]);
        if (userLimit > 0) limit = static_cast<size_t>(userLimit);
        else if (userLimit < 0) limit = 1000000;
    }

    size_t totalSymbols = (strtab > symtab) ? (strtab - symtab) / symentSize : 0;
    if (limit > totalSymbols && totalSymbols > 0) limit = totalSymbols;

    JSValue arr = JS_NewArray(ctx);
    const ElfW(Sym)* syms = reinterpret_cast<const ElfW(Sym)*>(symtab);
    char hex[32];

    for (size_t i = 0; i < limit; i++) {
        if (!gum_memory_is_readable(&syms[i], sizeof(ElfW(Sym)))) break;
        const ElfW(Sym)& s = syms[i];
        const char* name = "";
        if (s.st_name < static_cast<size_t>(strtabSize) &&
            gum_memory_is_readable(reinterpret_cast<const void*>(strtab + s.st_name), 1)) {
            name = reinterpret_cast<const char*>(strtab + s.st_name);
        }

        unsigned char bind = ELF_ST_BIND(s.st_info);
        unsigned char type = ELF_ST_TYPE(s.st_info);
        const char* bindStr = (bind == STB_LOCAL) ? "LOCAL" :
                              (bind == STB_GLOBAL) ? "GLOBAL" :
                              (bind == STB_WEAK) ? "WEAK" : "OTHER";
        const char* typeStr = (type == STT_NOTYPE) ? "NOTYPE" :
                              (type == STT_OBJECT) ? "OBJECT" :
                              (type == STT_FUNC) ? "FUNC" :
                              (type == STT_SECTION) ? "SECTION" :
                              (type == STT_FILE) ? "FILE" : "OTHER";

        JSValue item = JS_NewObject(ctx);
        JS_SetPropertyStr(ctx, item, "index", JS_NewInt32(ctx, static_cast<int32_t>(i)));
        JS_SetPropertyStr(ctx, item, "name", JS_NewString(ctx, name));
        snprintf(hex, sizeof(hex), "0x%" PRIxPTR, static_cast<uintptr_t>(s.st_value));
        JS_SetPropertyStr(ctx, item, "value", JS_NewString(ctx, hex));
        uintptr_t addr = s.st_value ? (base + s.st_value) : 0;
        snprintf(hex, sizeof(hex), "0x%" PRIxPTR, addr);
        JS_SetPropertyStr(ctx, item, "address", JS_NewString(ctx, hex));
        JS_SetPropertyStr(ctx, item, "size", JS_NewInt64(ctx, static_cast<int64_t>(s.st_size)));
        JS_SetPropertyStr(ctx, item, "bind", JS_NewString(ctx, bindStr));
        JS_SetPropertyStr(ctx, item, "type", JS_NewString(ctx, typeStr));

        JS_SetPropertyUint32(ctx, arr, static_cast<uint32_t>(i), item);
    }

    return arr;
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
    JS_SetPropertyStr(ctx, obj, "getDestructors", JS_NewCFunction(ctx, JsLinkerGetDestructors, "getDestructors", 1));
    JS_SetPropertyStr(ctx, obj, "symbols", JS_NewCFunction(ctx, JsLinkerSymbols, "symbols", 1));
    JS_SetPropertyStr(ctx, obj, "symtab", JS_NewCFunction(ctx, JsLinkerSymbols, "symtab", 1));
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
