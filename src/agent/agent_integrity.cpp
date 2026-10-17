#include "agent_integrity.h"
#include "agent_common.h"
#include "xdl.h"
#include "frida-gum.h"
#include "KittyInclude.h"
#include "../../engine/utils/pi_hash.h"

#include <vector>
#include <string>
#include <sstream>
#include <iomanip>
#include <cinttypes>
#include <cstring>
#include <cerrno>
#include <fcntl.h>
#include <unistd.h>
#include <link.h>
#include <sys/types.h>

namespace artpi { namespace agent {

struct PageDiffRecord {
    uintptr_t memAddr = 0;
    uint64_t fileOffset = 0;
    uint32_t diskCrc = 0;
    uint32_t memCrc = 0;
    size_t diffBytes = 0;
    size_t firstDiff = 0;
    std::vector<std::string> symbols;
};

struct IntegrityReport {
    std::string moduleName;
    std::string filePath;
    uintptr_t base = 0;
    size_t pageSize = 4096;
    size_t checkedPages = 0;
    size_t cleanPages = 0;
    bool isComplete = false;
    std::vector<PageDiffRecord> diffs;
    std::string error;

    std::string ToString() const {
        std::ostringstream ss;
        char hexBase[32];
        snprintf(hexBase, sizeof(hexBase), "0x%" PRIxPTR, base);
        ss << "[Code Integrity] Module: " << moduleName << " (Base: " << hexBase << ")\n";
        if (!error.empty()) {
            ss << "  Error       : " << error << "\n";
        }
        ss << "  File path   : " << filePath << "\n";
        size_t kbPerPage = pageSize / 1024;
        ss << "  Checked     : " << checkedPages << " executable page(s) (" << (checkedPages * kbPerPage) << " KB)\n";

        if (isComplete && (checkedPages > 0) && diffs.empty() && error.empty()) {
            ss << "  Status      : Clean (All executable code pages match disk image)\n";
        } else {
            if (!isComplete) {
                ss << "  Status      : INCOMPLETE / ERROR (" << diffs.size() << " diff(s) found before abort)\n";
            } else {
                ss << "  Status      : MISMATCH DETECTED (" << diffs.size() << " modified code page(s))\n";
            }
            if (!diffs.empty()) {
                ss << "  ----------------------------------------------------------------------\n";
                for (const auto& d : diffs) {
                    char pBuf[64], fBuf[64], dcBuf[32], mcBuf[32];
                    snprintf(pBuf, sizeof(pBuf), "0x%" PRIxPTR, d.memAddr);
                    snprintf(fBuf, sizeof(fBuf), "+0x%" PRIx64, d.fileOffset);
                    snprintf(dcBuf, sizeof(dcBuf), "0x%08x", d.diskCrc);
                    snprintf(mcBuf, sizeof(mcBuf), "0x%08x", d.memCrc);
                    ss << "  [!] Page @ " << pBuf << " (Offset: " << fBuf
                       << ", " << d.diffBytes << " byte(s) altered):\n";
                    ss << "      Disk CRC32 : " << dcBuf << " | Memory CRC32: " << mcBuf << "\n";
                    if (!d.symbols.empty()) {
                        ss << "      Symbols    : ";
                        for (size_t i = 0; i < d.symbols.size(); i++) {
                            if (i > 0) ss << ", ";
                            ss << d.symbols[i];
                        }
                        ss << "\n";
                    }
                }
                ss << "  ----------------------------------------------------------------------\n";
            }
        }
        return ss.str();
    }
};

static JSValue JsIntegrityReportToString(JSContext* ctx, JSValueConst this_val, int /*argc*/, JSValueConst* /*argv*/) {
    return JS_GetPropertyStr(ctx, this_val, "_summary");
}

struct ExecSegment {
    uintptr_t vaddrStart;
    uintptr_t vaddrEnd;
    uint64_t fileOffset;
    size_t memSize;
};

struct MatchModuleContext {
    std::string filter;
    uintptr_t filterAddr = 0;
    uintptr_t foundBase = 0;
    std::string foundName;
    std::vector<ExecSegment> execSegments;
};

JSValue JsVerifyCodeIntegrity(JSContext* ctx, JSValueConst /*this_val*/, int argc, JSValueConst* argv) {
    if (argc < 1) {
        return JS_ThrowTypeError(ctx, "Usage: verifyCodeIntegrity(soNameOrAddr)");
    }

    MatchModuleContext mctx;
    if (JS_IsString(argv[0])) {
        const char* s = JS_ToCString(ctx, argv[0]);
        if (s) {
            std::string strInput = s;
            JS_FreeCString(ctx, s);
            if (strInput.rfind("0x", 0) == 0 || strInput.rfind("0X", 0) == 0) {
                mctx.filterAddr = std::strtoull(strInput.c_str(), nullptr, 0);
            } else {
                mctx.filter = strInput;
            }
        }
    } else {
        mctx.filterAddr = static_cast<uintptr_t>(ParsePtr(ctx, argv[0]));
    }

    // Dynamic page size lookup
    long scPage = sysconf(_SC_PAGESIZE);
    size_t pageSize = (scPage > 0) ? static_cast<size_t>(scPage) : 4096;

    // Iterate loaded modules using dl_iterate_phdr
    dl_iterate_phdr([](struct dl_phdr_info* info, size_t, void* data) -> int {
        auto* mc = static_cast<MatchModuleContext*>(data);
        uintptr_t base = static_cast<uintptr_t>(info->dlpi_addr);
        if (base < 0x1000) return 0;

        bool matched = false;
        std::string modName;

        if (info->dlpi_name && info->dlpi_name[0]) {
            modName = info->dlpi_name;
        }

        // Match by address: check if filterAddr falls within this module's segments
        if (mc->filterAddr >= 0x1000) {
            if (mc->filterAddr == base) {
                matched = true;
            } else {
                for (size_t i = 0; i < info->dlpi_phnum; i++) {
                    const auto& ph = info->dlpi_phdr[i];
                    if (ph.p_type == PT_LOAD) {
                        uintptr_t segStart = base + ph.p_vaddr;
                        uintptr_t segEnd = segStart + ph.p_memsz;
                        if (mc->filterAddr >= segStart && mc->filterAddr < segEnd) {
                            matched = true;
                            break;
                        }
                    }
                }
            }
        } else if (!mc->filter.empty()) {
            // Match by module name or path
            if (!modName.empty()) {
                size_t slash = modName.rfind('/');
                std::string baseName = (slash != std::string::npos) ? modName.substr(slash + 1) : modName;
                if (modName == mc->filter || baseName == mc->filter) {
                    matched = true;
                } else if (modName.ends_with("/" + mc->filter) || modName.ends_with("!/" + mc->filter)) {
                    matched = true;
                }
            }

            // Also check DT_SONAME in ELF header if dlpi_name didn't match
            if (!matched && gum_memory_is_readable(reinterpret_cast<const void*>(base), sizeof(ElfW(Ehdr)))) {
                const auto* ehdr = reinterpret_cast<const ElfW(Ehdr)*>(base);
                if (ehdr->e_ident[0] == 0x7f && ehdr->e_ident[1] == 'E' &&
                    ehdr->e_ident[2] == 'L' && ehdr->e_ident[3] == 'F') {
                    for (size_t i = 0; i < info->dlpi_phnum; i++) {
                        const auto& ph = info->dlpi_phdr[i];
                        if (ph.p_type == PT_DYNAMIC) {
                            uintptr_t dynAddr = base + ph.p_vaddr;
                            const auto* dyn = reinterpret_cast<const ElfW(Dyn)*>(dynAddr);
                            uintptr_t strtab = 0;
                            uintptr_t sonameIdx = 0;
                            while (gum_memory_is_readable(dyn, sizeof(ElfW(Dyn))) && dyn->d_tag != DT_NULL) {
                                if (dyn->d_tag == DT_STRTAB) {
                                    strtab = (dyn->d_un.d_ptr < base) ? (base + dyn->d_un.d_ptr) : dyn->d_un.d_ptr;
                                } else if (dyn->d_tag == DT_SONAME) {
                                    sonameIdx = dyn->d_un.d_val;
                                }
                                dyn++;
                            }
                            if (strtab && sonameIdx && gum_memory_is_readable(reinterpret_cast<const void*>(strtab + sonameIdx), 1)) {
                                const char* soname = reinterpret_cast<const char*>(strtab + sonameIdx);
                                if (soname) {
                                    std::string sonameStr(soname);
                                    if (mc->filter == sonameStr) {
                                        matched = true;
                                        if (modName.empty()) modName = sonameStr;
                                    }
                                }
                            }
                            break;
                        }
                    }
                }
            }
        }

        if (matched) {
            mc->foundBase = base;
            mc->foundName = modName.empty() ? mc->filter : modName;
            mc->execSegments.clear();
            for (size_t i = 0; i < info->dlpi_phnum; i++) {
                const auto& ph = info->dlpi_phdr[i];
                if (ph.p_type == PT_LOAD && (ph.p_flags & PF_X)) {
                    ExecSegment seg;
                    seg.vaddrStart = base + ph.p_vaddr;
                    seg.vaddrEnd = seg.vaddrStart + ph.p_memsz;
                    seg.fileOffset = ph.p_offset;
                    seg.memSize = ph.p_memsz;
                    mc->execSegments.push_back(seg);
                }
            }
            return 1; // stop iteration
        }
        return 0;
    }, &mctx);

    if (mctx.foundBase == 0) {
        IntegrityReport rep;
        rep.moduleName = mctx.filter.empty() ? "unknown" : mctx.filter;
        rep.error = "Module not found in process memory mappings";
        rep.isComplete = false;

        JSValue o = JS_NewObject(ctx);
        JS_SetPropertyStr(ctx, o, "module", JS_NewString(ctx, rep.moduleName.c_str()));
        JS_SetPropertyStr(ctx, o, "isClean", JS_FALSE);
        JS_SetPropertyStr(ctx, o, "isComplete", JS_FALSE);
        JS_SetPropertyStr(ctx, o, "error", JS_NewString(ctx, rep.error.c_str()));
        JS_SetPropertyStr(ctx, o, "_summary", JS_NewString(ctx, rep.ToString().c_str()));
        JS_SetPropertyStr(ctx, o, "toString", JS_NewCFunction(ctx, JsIntegrityReportToString, "toString", 0));
        return o;
    }

    IntegrityReport rep;
    rep.base = mctx.foundBase;
    rep.moduleName = mctx.foundName;
    rep.pageSize = pageSize;

    if (mctx.execSegments.empty()) {
        rep.error = "No executable segments found in module program headers";
        rep.isComplete = false;

        JSValue o = JS_NewObject(ctx);
        JS_SetPropertyStr(ctx, o, "module", JS_NewString(ctx, rep.moduleName.c_str()));
        JS_SetPropertyStr(ctx, o, "isClean", JS_FALSE);
        JS_SetPropertyStr(ctx, o, "isComplete", JS_FALSE);
        JS_SetPropertyStr(ctx, o, "error", JS_NewString(ctx, rep.error.c_str()));
        JS_SetPropertyStr(ctx, o, "_summary", JS_NewString(ctx, rep.ToString().c_str()));
        JS_SetPropertyStr(ctx, o, "toString", JS_NewCFunction(ctx, JsIntegrityReportToString, "toString", 0));
        return o;
    }

    // Inspect base map to obtain underlying mapped file and base offset in file
    KittyMemory::ProcMap baseMap = KittyMemory::getAddressMap(reinterpret_cast<const void*>(mctx.foundBase));
    std::string mappedFilePath = baseMap.pathname;

    // Handle " (deleted)" suffix if present in /proc/self/maps
    const std::string deletedSuffix = " (deleted)";
    if (mappedFilePath.size() > deletedSuffix.size() &&
        mappedFilePath.compare(mappedFilePath.size() - deletedSuffix.size(), deletedSuffix.size(), deletedSuffix) == 0) {
        mappedFilePath = mappedFilePath.substr(0, mappedFilePath.size() - deletedSuffix.size());
    }

    rep.filePath = mappedFilePath;

    if (mappedFilePath.empty()) {
        rep.error = "Module base is not backed by a disk file (anonymous or memory-only module)";
        rep.isComplete = false;

        JSValue o = JS_NewObject(ctx);
        JS_SetPropertyStr(ctx, o, "module", JS_NewString(ctx, rep.moduleName.c_str()));
        JS_SetPropertyStr(ctx, o, "isClean", JS_FALSE);
        JS_SetPropertyStr(ctx, o, "isComplete", JS_FALSE);
        JS_SetPropertyStr(ctx, o, "error", JS_NewString(ctx, rep.error.c_str()));
        JS_SetPropertyStr(ctx, o, "_summary", JS_NewString(ctx, rep.ToString().c_str()));
        JS_SetPropertyStr(ctx, o, "toString", JS_NewCFunction(ctx, JsIntegrityReportToString, "toString", 0));
        return o;
    }

    int fd = open(mappedFilePath.c_str(), O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        fd = open(mappedFilePath.c_str(), O_RDONLY);
    }
    if (fd < 0) {
        rep.error = std::string("Failed to open disk file: ") + mappedFilePath + " (" + strerror(errno) + ")";
        rep.isComplete = false;

        JSValue o = JS_NewObject(ctx);
        JS_SetPropertyStr(ctx, o, "module", JS_NewString(ctx, rep.moduleName.c_str()));
        JS_SetPropertyStr(ctx, o, "isClean", JS_FALSE);
        JS_SetPropertyStr(ctx, o, "isComplete", JS_FALSE);
        JS_SetPropertyStr(ctx, o, "error", JS_NewString(ctx, rep.error.c_str()));
        JS_SetPropertyStr(ctx, o, "_summary", JS_NewString(ctx, rep.ToString().c_str()));
        JS_SetPropertyStr(ctx, o, "toString", JS_NewCFunction(ctx, JsIntegrityReportToString, "toString", 0));
        return o;
    }

    void* xdlCache = nullptr;
    std::vector<uint8_t> diskBuf(pageSize);
    std::vector<uint8_t> memBuf(pageSize);

    rep.isComplete = true;

    size_t expectedPages = 0;
    for (const auto& seg : mctx.execSegments) {
        uintptr_t pageStart = seg.vaddrStart & ~(pageSize - 1);
        uintptr_t pageEnd = (seg.vaddrEnd + pageSize - 1) & ~(pageSize - 1);
        expectedPages += (pageEnd - pageStart) / pageSize;
    }

    if (expectedPages == 0) {
        rep.error = "No executable code pages found in target module";
        rep.isComplete = false;
    }

    for (const auto& seg : mctx.execSegments) {
        // Page align the segment range
        uintptr_t pageStart = seg.vaddrStart & ~(pageSize - 1);
        uintptr_t pageEnd = (seg.vaddrEnd + pageSize - 1) & ~(pageSize - 1);
        size_t pageCount = (pageEnd - pageStart) / pageSize;

        // Query memory map for pageStart to obtain exact file offset (transparent for APK mapping)
        KittyMemory::ProcMap segMap = KittyMemory::getAddressMap(reinterpret_cast<const void*>(pageStart));
        uint64_t baseFileOff = segMap.isValid() ? segMap.offset : (baseMap.offset + seg.fileOffset);

        for (size_t p = 0; p < pageCount; p++) {
            uintptr_t memPageAddr = pageStart + p * pageSize;
            uint64_t fileOff = baseFileOff + p * pageSize;

            // Read disk bytes with EINTR retry loop
            ssize_t rd = 0;
            while (true) {
                rd = pread64(fd, diskBuf.data(), pageSize, static_cast<off64_t>(fileOff));
                if (rd < 0 && errno == EINTR) continue;
                break;
            }

            if (rd <= 0) {
                rep.error = "Disk read failed at file offset " + std::to_string(fileOff) + " (" + strerror(errno) + ")";
                rep.isComplete = false;
                break;
            }

            if (!gum_memory_is_readable(reinterpret_cast<const void*>(memPageAddr), static_cast<size_t>(rd))) {
                rep.error = "Memory page not readable at address 0x" + std::to_string(memPageAddr);
                rep.isComplete = false;
                break;
            }

            std::memcpy(memBuf.data(), reinterpret_cast<const void*>(memPageAddr), static_cast<size_t>(rd));
            rep.checkedPages++;

            if (std::memcmp(diskBuf.data(), memBuf.data(), static_cast<size_t>(rd)) == 0) {
                rep.cleanPages++;
            } else {
                PageDiffRecord diff;
                diff.memAddr = memPageAddr;
                diff.fileOffset = fileOff;
                diff.diskCrc = PI::Hash::Crc32(diskBuf.data(), static_cast<size_t>(rd));
                diff.memCrc = PI::Hash::Crc32(memBuf.data(), static_cast<size_t>(rd));

                bool foundFirst = false;
                for (ssize_t b = 0; b < rd; b++) {
                    if (diskBuf[b] != memBuf[b]) {
                        diff.diffBytes++;
                        if (!foundFirst) {
                            diff.firstDiff = static_cast<size_t>(b);
                            foundFirst = true;
                        }
                    }
                }

                // Resolve symbol inside this altered page using dli_fbase validation
                xdl_info_t dli{};
                if (xdl_addr(reinterpret_cast<void*>(memPageAddr + diff.firstDiff), &dli, &xdlCache) != 0) {
                    if (dli.dli_sname && dli.dli_sname[0] != '\0' && dli.dli_saddr && dli.dli_fbase) {
                        uintptr_t saddr = reinterpret_cast<uintptr_t>(dli.dli_saddr);
                        uintptr_t fbase = reinterpret_cast<uintptr_t>(dli.dli_fbase);
                        if (fbase == rep.base && saddr >= fbase) {
                            char symBuf[128];
                            snprintf(symBuf, sizeof(symBuf), "%s (+0x%" PRIxPTR ")",
                                     dli.dli_sname, saddr - fbase);
                            diff.symbols.push_back(symBuf);
                        }
                    }
                }

                rep.diffs.push_back(diff);
            }
        }

        if (!rep.isComplete) break;
    }

    close(fd);

    if (xdlCache) {
        xdl_addr_clean(&xdlCache);
    }

    if (rep.checkedPages < expectedPages) {
        rep.isComplete = false;
        if (rep.error.empty()) {
            rep.error = "Scan interrupted: checked " + std::to_string(rep.checkedPages) + " of " + std::to_string(expectedPages) + " expected pages";
        }
    }

    // Strict clean condition: scan must be 100% complete, checkedPages > 0, all pages match
    bool isClean = rep.isComplete && (rep.checkedPages > 0) && (rep.checkedPages == expectedPages) && rep.diffs.empty() && rep.error.empty();

    // Build JS Object
    JSValue obj = JS_NewObject(ctx);
    JS_SetPropertyStr(ctx, obj, "module", JS_NewString(ctx, rep.moduleName.c_str()));
    JS_SetPropertyStr(ctx, obj, "path", JS_NewString(ctx, rep.filePath.c_str()));
    char bStr[32];
    snprintf(bStr, sizeof(bStr), "0x%" PRIxPTR, rep.base);
    JS_SetPropertyStr(ctx, obj, "base", JS_NewString(ctx, bStr));
    JS_SetPropertyStr(ctx, obj, "pageSize", JS_NewInt64(ctx, static_cast<int64_t>(rep.pageSize)));
    JS_SetPropertyStr(ctx, obj, "totalPages", JS_NewInt64(ctx, static_cast<int64_t>(rep.checkedPages)));
    JS_SetPropertyStr(ctx, obj, "cleanPages", JS_NewInt64(ctx, static_cast<int64_t>(rep.cleanPages)));
    JS_SetPropertyStr(ctx, obj, "modifiedCount", JS_NewInt64(ctx, static_cast<int64_t>(rep.diffs.size())));
    JS_SetPropertyStr(ctx, obj, "isComplete", JS_NewBool(ctx, rep.isComplete));
    JS_SetPropertyStr(ctx, obj, "isClean", JS_NewBool(ctx, isClean));

    if (!rep.error.empty()) {
        JS_SetPropertyStr(ctx, obj, "error", JS_NewString(ctx, rep.error.c_str()));
    }

    JSValue diffArr = JS_NewArray(ctx);
    for (size_t i = 0; i < rep.diffs.size(); i++) {
        const auto& d = rep.diffs[i];
        JSValue dObj = JS_NewObject(ctx);
        char pStr[32], oStr[32], dcStr[32], mcStr[32];
        snprintf(pStr, sizeof(pStr), "0x%" PRIxPTR, d.memAddr);
        snprintf(oStr, sizeof(oStr), "+0x%" PRIx64, d.fileOffset);
        snprintf(dcStr, sizeof(dcStr), "0x%08x", d.diskCrc);
        snprintf(mcStr, sizeof(mcStr), "0x%08x", d.memCrc);
        JS_SetPropertyStr(ctx, dObj, "page", JS_NewString(ctx, pStr));
        JS_SetPropertyStr(ctx, dObj, "offset", JS_NewString(ctx, oStr));
        JS_SetPropertyStr(ctx, dObj, "diskCrc", JS_NewString(ctx, dcStr));
        JS_SetPropertyStr(ctx, dObj, "memCrc", JS_NewString(ctx, mcStr));
        JS_SetPropertyStr(ctx, dObj, "diffBytes", JS_NewInt64(ctx, static_cast<int64_t>(d.diffBytes)));
        JS_SetPropertyStr(ctx, dObj, "firstDiffOffset", JS_NewInt64(ctx, static_cast<int64_t>(d.firstDiff)));
        JSValue symArr = JS_NewArray(ctx);
        for (size_t s = 0; s < d.symbols.size(); s++) {
            JS_SetPropertyUint32(ctx, symArr, static_cast<uint32_t>(s), JS_NewString(ctx, d.symbols[s].c_str()));
        }
        JS_SetPropertyStr(ctx, dObj, "symbols", symArr);
        JS_SetPropertyUint32(ctx, diffArr, static_cast<uint32_t>(i), dObj);
    }
    JS_SetPropertyStr(ctx, obj, "modifiedPages", diffArr);
    JS_SetPropertyStr(ctx, obj, "diffs", JS_DupValue(ctx, diffArr));

    std::string summary = rep.ToString();
    JS_SetPropertyStr(ctx, obj, "_summary", JS_NewString(ctx, summary.c_str()));
    JS_SetPropertyStr(ctx, obj, "toString", JS_NewCFunction(ctx, JsIntegrityReportToString, "toString", 0));

    return obj;
}

}} // namespace artpi::agent
