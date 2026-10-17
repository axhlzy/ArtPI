#include "agent_memory.h"
#include "agent_common.h"
#include "../../include/ArtPI.h"
#include "art/art_method.h"
#include "KittyInclude.h"

#include <sstream>
#include <vector>
#include <string>
#include <cstring>
#include <sys/mman.h>
#include <unistd.h>
#include <iomanip>
#include <cctype>
#include <memory>
#include <mutex>
#include <algorithm>

namespace artpi { namespace agent {


namespace {

JSValue JsHexDump(JSContext* ctx, JSValueConst /*this_val*/, int argc, JSValueConst* argv) {
    if (argc < 1) return JS_NewString(ctx, "Usage: hexdump(address, [length])");
    int64_t addr = ParsePtr(ctx, argv[0]);
    if (!addr || addr < 0x1000) return JS_NewString(ctx, "[!] Invalid address");

    int len = 64;
    if (argc >= 2) JS_ToInt32(ctx, &len, argv[1]);
    if (len <= 0 || len > 4096) len = 64;

    const uint8_t* p = reinterpret_cast<const uint8_t*>(addr);
    std::ostringstream ss;
    char hex[4], asc[17];
    asc[16] = '\0';

    for (int i = 0; i < len; i += 16) {
        char header[32];
        snprintf(header, sizeof(header), "%016llx: ", (unsigned long long)(addr + i));
        ss << header;
        for (int j = 0; j < 16; j++) {
            if (i + j < len) {
                uint8_t b = p[i + j];
                snprintf(hex, sizeof(hex), "%02x ", b);
                asc[j] = (b >= 32 && b <= 126) ? static_cast<char>(b) : '.';
            } else {
                snprintf(hex, sizeof(hex), "   ");
                asc[j] = ' ';
            }
            ss << hex;
        }
        ss << " |" << asc << "|\n";
    }
    return JS_NewString(ctx, ss.str().c_str());
}

JSValue JsReadByteArray(JSContext* ctx, JSValueConst /*this_val*/, int argc, JSValueConst* argv) {
    if (argc < 2) return JS_NewString(ctx, "Usage: readmem(address, length)");
    int64_t addr = ParsePtr(ctx, argv[0]);
    int len = 0;
    JS_ToInt32(ctx, &len, argv[1]);
    if (!addr || len <= 0 || len > 65536) return JS_NULL;

    return JS_NewArrayBufferCopy(ctx, reinterpret_cast<const uint8_t*>(addr), len);
}

JSValue JsWriteByteArray(JSContext* ctx, JSValueConst /*this_val*/, int argc, JSValueConst* argv) {
    if (argc < 2) return JS_NewString(ctx, "Usage: writemem(address, arrayBufferOrHexString)");
    int64_t addr = ParsePtr(ctx, argv[0]);
    if (!addr || addr < 0x1000) return JS_NewString(ctx, "[!] Invalid address");

    size_t dataLen = 0;
    uint8_t* bytes = nullptr;
    std::vector<uint8_t> parsedHex;

    if (JS_IsString(argv[1])) {
        const char* hexStr = JS_ToCString(ctx, argv[1]);
        if (hexStr) {
            std::string s(hexStr);
            JS_FreeCString(ctx, hexStr);
            for (size_t i = 0; i + 1 < s.size();) {
                if (s[i] == ' ' || s[i] == '\t') { i++; continue; }
                char byteChars[3] = {s[i], s[i+1], '\0'};
                parsedHex.push_back(static_cast<uint8_t>(strtoul(byteChars, nullptr, 16)));
                i += 2;
            }
            bytes = parsedHex.data();
            dataLen = parsedHex.size();
        }
    } else {
        bytes = JS_GetArrayBuffer(ctx, &dataLen, argv[1]);
    }

    if (!bytes || dataLen == 0) {
        return JS_NewString(ctx, "[!] Invalid byte data");
    }

    uintptr_t page_start = static_cast<uintptr_t>(addr) & ~0xFFFULL;
    mprotect(reinterpret_cast<void*>(page_start), 4096 * 2, PROT_READ | PROT_WRITE | PROT_EXEC);
    std::memcpy(reinterpret_cast<void*>(addr), bytes, dataLen);
    return JS_NewString(ctx, "Memory written successfully");
}

JSValue JsReadCString(JSContext* ctx, JSValueConst /*this_val*/, int argc, JSValueConst* argv) {
    if (argc < 1) return JS_NewString(ctx, "Usage: readstring(address)");
    int64_t addr = ParsePtr(ctx, argv[0]);
    if (!addr || addr < 0x1000) return JS_NULL;

    const char* str = reinterpret_cast<const char*>(addr);
    return JS_NewString(ctx, str);
}

JSValue JsReadU32(JSContext* ctx, JSValueConst /*this_val*/, int argc, JSValueConst* argv) {
    if (argc < 1) return JS_NewString(ctx, "Usage: readu32(address)");
    int64_t addr = ParsePtr(ctx, argv[0]);
    if (!addr || addr < 0x1000) return JS_NULL;

    uint32_t val = *reinterpret_cast<const uint32_t*>(addr);
    return JS_NewInt64(ctx, val);
}

JSValue JsWriteU32(JSContext* ctx, JSValueConst /*this_val*/, int argc, JSValueConst* argv) {
    if (argc < 2) return JS_NewString(ctx, "Usage: writeu32(address, value)");
    int64_t addr = ParsePtr(ctx, argv[0]);
    if (!addr || addr < 0x1000) return JS_NewString(ctx, "[!] Invalid address");

    int64_t val = 0;
    if (JS_IsBigInt(ctx, argv[1])) {
        JS_ToBigInt64(ctx, &val, argv[1]);
    } else {
        JS_ToInt64(ctx, &val, argv[1]);
    }

    uintptr_t page_start = static_cast<uintptr_t>(addr) & ~0xFFFULL;
    mprotect(reinterpret_cast<void*>(page_start), 4096 * 2, PROT_READ | PROT_WRITE | PROT_EXEC);
    *reinterpret_cast<uint32_t*>(addr) = static_cast<uint32_t>(val);
    return JS_NewString(ctx, "u32 written successfully");
}

// ============================================================================
// KittyMemory: Pattern Scanning, Memory Patching, Maps & Dynamic Native Helpers
// ============================================================================

static bool ParsePattern(const std::string& pattern, std::vector<char>& outBytes, std::string& outMask) {
    outBytes.clear();
    outMask.clear();
    std::string s = pattern;
    for (char& c : s) if (c == ',') c = ' ';
    std::istringstream iss(s);
    std::string token;
    bool hasSpaces = (s.find(' ') != std::string::npos);
    if (hasSpaces) {
        while (iss >> token) {
            if (token == "?" || token == "??") {
                outBytes.push_back(0);
                outMask.push_back('?');
            } else if (token.size() == 2 && isxdigit(token[0]) && isxdigit(token[1])) {
                char byteVal = static_cast<char>(std::strtoul(token.c_str(), nullptr, 16));
                outBytes.push_back(byteVal);
                outMask.push_back('x');
            } else {
                return false;
            }
        }
    } else {
        if (s.size() % 2 != 0) return false;
        for (size_t i = 0; i < s.size(); i += 2) {
            std::string sub = s.substr(i, 2);
            if (sub == "??" || sub == "**") {
                outBytes.push_back(0);
                outMask.push_back('?');
            } else if (isxdigit(sub[0]) && isxdigit(sub[1])) {
                char byteVal = static_cast<char>(std::strtoul(sub.c_str(), nullptr, 16));
                outBytes.push_back(byteVal);
                outMask.push_back('x');
            } else {
                return false;
            }
        }
    }
    return !outBytes.empty() && outBytes.size() == outMask.size();
}

static std::string FormatAddressWithModule(uintptr_t addr) {
    ProcMap m = KittyMemory::getAddressMap(reinterpret_cast<void*>(addr));
    char buf[256];
    if (m.isValid() && !m.pathname.empty()) {
        const char* slash = strrchr(m.pathname.c_str(), '/');
        const char* modName = slash ? (slash + 1) : m.pathname.c_str();
        uintptr_t offset = addr - m.startAddress;
        snprintf(buf, sizeof(buf), "0x%llx  [%s + 0x%llx]",
                 (unsigned long long)addr, modName, (unsigned long long)offset);
    } else {
        snprintf(buf, sizeof(buf), "0x%llx", (unsigned long long)addr);
    }
    return buf;
}

static JSValue JsScanResultArrayToString(JSContext* ctx, JSValueConst this_val, int, JSValueConst*) {
    int64_t len = 0;
    JSValue lenVal = JS_GetPropertyStr(ctx, this_val, "length");
    JS_ToInt64(ctx, &len, lenVal);
    JS_FreeValue(ctx, lenVal);

    if (len == 0) return JS_NewString(ctx, "[*] Memory.scan: 0 matches found.");

    std::ostringstream ss;
    ss << "[+] Memory.scan found " << len << " match(es):\n";
    for (int64_t i = 0; i < len; ++i) {
        JSValue item = JS_GetPropertyUint32(ctx, this_val, static_cast<uint32_t>(i));
        const char* s = JS_ToCString(ctx, item);
        ss << "  [" << i << "] " << (s ? s : "?") << "\n";
        if (s) JS_FreeCString(ctx, s);
        JS_FreeValue(ctx, item);
    }
    return JS_NewString(ctx, ss.str().c_str());
}

static JSValue JsMemoryScan(JSContext* ctx, JSValueConst /*this_val*/, int argc, JSValueConst* argv) {
    if (argc < 2) return JS_ThrowTypeError(ctx, "Usage: Memory.scan(moduleOrAddr, [size], pattern, [maxResults])");

    std::vector<ProcMap> mapsToScan;
    std::string pattern;
    int maxResults = 50;

    if (JS_IsString(argv[0])) {
        const char* mStr = JS_ToCString(ctx, argv[0]);
        std::string modName = mStr ? mStr : "";
        if (mStr) JS_FreeCString(ctx, mStr);

        const char* pStr = JS_ToCString(ctx, argv[1]);
        pattern = pStr ? pStr : "";
        if (pStr) JS_FreeCString(ctx, pStr);

        if (argc >= 3) JS_ToInt32(ctx, &maxResults, argv[2]);
        if (maxResults <= 0) maxResults = 50;

        mapsToScan = KittyMemory::getMapsByName(modName);
        if (mapsToScan.empty()) {
            return JS_NewString(ctx, ("[!] No memory maps found for: " + modName).c_str());
        }
    } else {
        int64_t addr = ParsePtr(ctx, argv[0]);
        if (!addr || addr < 0x1000) return JS_ThrowTypeError(ctx, "Memory.scan: invalid address");

        if (argc >= 3 && JS_IsNumber(argv[1]) && JS_IsString(argv[2])) {
            int64_t scanLen = 0;
            JS_ToInt64(ctx, &scanLen, argv[1]);
            const char* pStr = JS_ToCString(ctx, argv[2]);
            pattern = pStr ? pStr : "";
            if (pStr) JS_FreeCString(ctx, pStr);

            if (argc >= 4) JS_ToInt32(ctx, &maxResults, argv[3]);
            if (maxResults <= 0) maxResults = 50;

            ProcMap customMap;
            customMap.startAddress = static_cast<unsigned long long>(addr);
            customMap.endAddress = static_cast<unsigned long long>(addr + scanLen);
            customMap.length = static_cast<size_t>(scanLen);
            customMap.readable = true;
            mapsToScan.push_back(customMap);
        } else {
            const char* pStr = JS_ToCString(ctx, argv[1]);
            pattern = pStr ? pStr : "";
            if (pStr) JS_FreeCString(ctx, pStr);

            if (argc >= 3) JS_ToInt32(ctx, &maxResults, argv[2]);
            if (maxResults <= 0) maxResults = 50;

            ProcMap m = KittyMemory::getAddressMap(reinterpret_cast<void*>(addr));
            if (!m.isValid()) {
                return JS_NewString(ctx, "[!] Address not found in any valid memory map.");
            }
            mapsToScan.push_back(m);
        }
    }

    std::vector<char> patternBytes;
    std::string patternMask;
    if (!ParsePattern(pattern, patternBytes, patternMask)) {
        return JS_ThrowTypeError(ctx, "Memory.scan: invalid pattern (expected hex like '1F 20 03 D5 ?? ?? 00 94')");
    }

    JSValue arr = JS_NewArray(ctx);
    uint32_t matchIdx = 0;

    for (const auto& m : mapsToScan) {
        if (!m.readable && !m.is_rx && !m.is_rw) continue;
        uintptr_t start = m.startAddress;
        uintptr_t end = m.endAddress;
        if (start >= end) continue;

        auto hits = KittyScanner::findBytesAll(start, end, patternBytes.data(), patternMask);
        for (uintptr_t hit : hits) {
            std::string desc = FormatAddressWithModule(hit);
            JS_SetPropertyUint32(ctx, arr, matchIdx++, JS_NewString(ctx, desc.c_str()));
            if (matchIdx >= static_cast<uint32_t>(maxResults)) break;
        }
        if (matchIdx >= static_cast<uint32_t>(maxResults)) break;
    }

    JS_SetPropertyStr(ctx, arr, "toString", JS_NewCFunction(ctx, JsScanResultArrayToString, "toString", 0));
    return arr;
}

static std::mutex g_patchesMutex;
static std::vector<std::shared_ptr<MemoryPatch>> g_activePatches;

static JSValue JsPatchModify(JSContext* ctx, JSValueConst this_val, int, JSValueConst*) {
    JSValue pVal = JS_GetPropertyStr(ctx, this_val, "__patch_ptr");
    auto* p = reinterpret_cast<MemoryPatch*>(static_cast<uintptr_t>(ParsePtr(ctx, pVal)));
    JS_FreeValue(ctx, pVal);
    if (!p) return JS_FALSE;
    bool ok = p->Modify();
    return JS_NewBool(ctx, ok);
}

static JSValue JsPatchRestore(JSContext* ctx, JSValueConst this_val, int, JSValueConst*) {
    JSValue pVal = JS_GetPropertyStr(ctx, this_val, "__patch_ptr");
    auto* p = reinterpret_cast<MemoryPatch*>(static_cast<uintptr_t>(ParsePtr(ctx, pVal)));
    JS_FreeValue(ctx, pVal);
    if (!p) return JS_FALSE;
    bool ok = p->Restore();
    return JS_NewBool(ctx, ok);
}

static JSValue JsPatchToString(JSContext* ctx, JSValueConst this_val, int, JSValueConst*) {
    JSValue pVal = JS_GetPropertyStr(ctx, this_val, "__patch_ptr");
    auto* p = reinterpret_cast<MemoryPatch*>(static_cast<uintptr_t>(ParsePtr(ctx, pVal)));
    JS_FreeValue(ctx, pVal);
    if (!p) return JS_NewString(ctx, "[MemoryPatch: null]");

    std::ostringstream ss;
    char hexAddr[32];
    snprintf(hexAddr, sizeof(hexAddr), "0x%llx", (unsigned long long)p->get_TargetAddress());
    ss << "[MemoryPatch @ " << hexAddr << " (" << p->get_PatchSize() << " bytes)]\n"
       << "  Original: " << p->get_OrigBytes() << "\n"
       << "  Patch:    " << p->get_PatchBytes() << "\n"
       << "  Current:  " << p->get_CurrBytes() << "\n"
       << "  Valid:    " << (p->isValid() ? "true" : "false");
    return JS_NewString(ctx, ss.str().c_str());
}

static JSValue MakePatchObject(JSContext* ctx, std::shared_ptr<MemoryPatch> patch) {
    if (!patch || !patch->isValid()) return JS_NULL;
    {
        std::lock_guard<std::mutex> lk(g_patchesMutex);
        g_activePatches.push_back(patch);
    }
    JSValue obj = JS_NewObject(ctx);
    JS_SetPropertyStr(ctx, obj, "__patch_ptr", NewBigIntOrInt(ctx, reinterpret_cast<uintptr_t>(patch.get())));
    char hexAddr[32];
    snprintf(hexAddr, sizeof(hexAddr), "0x%llx", (unsigned long long)patch->get_TargetAddress());
    JS_SetPropertyStr(ctx, obj, "address", JS_NewString(ctx, hexAddr));
    JS_SetPropertyStr(ctx, obj, "size", JS_NewInt32(ctx, static_cast<int32_t>(patch->get_PatchSize())));
    JS_SetPropertyStr(ctx, obj, "origBytes", JS_NewString(ctx, patch->get_OrigBytes().c_str()));
    JS_SetPropertyStr(ctx, obj, "patchBytes", JS_NewString(ctx, patch->get_PatchBytes().c_str()));
    JS_SetPropertyStr(ctx, obj, "currBytes", JS_NewString(ctx, patch->get_CurrBytes().c_str()));
    JS_SetPropertyStr(ctx, obj, "isValid", JS_NewBool(ctx, patch->isValid()));
    JS_SetPropertyStr(ctx, obj, "modify", JS_NewCFunction(ctx, JsPatchModify, "modify", 0));
    JS_SetPropertyStr(ctx, obj, "restore", JS_NewCFunction(ctx, JsPatchRestore, "restore", 0));
    JS_SetPropertyStr(ctx, obj, "toString", JS_NewCFunction(ctx, JsPatchToString, "toString", 0));
    return obj;
}

static JSValue JsMemoryPatch(JSContext* ctx, JSValueConst /*this_val*/, int argc, JSValueConst* argv) {
    if (argc < 2) return JS_ThrowTypeError(ctx, "Usage: Memory.patch(addressOrModule, [rvaOffset], hexString)");

    std::shared_ptr<MemoryPatch> p;
    if (JS_IsString(argv[0]) && argc >= 3 && JS_IsNumber(argv[1])) {
        const char* mStr = JS_ToCString(ctx, argv[0]);
        std::string modName = mStr ? mStr : "";
        if (mStr) JS_FreeCString(ctx, mStr);

        int64_t rva = 0;
        JS_ToInt64(ctx, &rva, argv[1]);

        const char* hStr = JS_ToCString(ctx, argv[2]);
        std::string hex = hStr ? hStr : "";
        if (hStr) JS_FreeCString(ctx, hStr);

        ProcMap baseMap = KittyMemory::getBaseMapOf(modName);
        if (!baseMap.isValid()) {
            return JS_ThrowInternalError(ctx, "Memory.patch: module %s not found", modName.c_str());
        }
        p = std::make_shared<MemoryPatch>(MemoryPatch::createWithHex(baseMap, static_cast<uintptr_t>(rva), hex));
    } else {
        int64_t addr = ParsePtr(ctx, argv[0]);
        if (!addr || addr < 0x1000) return JS_ThrowTypeError(ctx, "Memory.patch: invalid address");

        const char* hStr = JS_ToCString(ctx, argv[1]);
        std::string hex = hStr ? hStr : "";
        if (hStr) JS_FreeCString(ctx, hStr);

        p = std::make_shared<MemoryPatch>(MemoryPatch::createWithHex(static_cast<uintptr_t>(addr), hex));
    }

    if (!p || !p->isValid()) {
        return JS_ThrowInternalError(ctx, "Memory.patch: failed to create patch (check hex format or address protection)");
    }

    p->Modify();
    return MakePatchObject(ctx, p);
}

static JSValue JsMemoryRestoreAll(JSContext* ctx, JSValueConst, int, JSValueConst*) {
    std::lock_guard<std::mutex> lk(g_patchesMutex);
    size_t count = 0;
    for (auto& p : g_activePatches) {
        if (p && p->isValid()) {
            p->Restore();
            count++;
        }
    }
    g_activePatches.clear();
    char buf[64];
    snprintf(buf, sizeof(buf), "[+] Restored %zu active memory patch(es).", count);
    return JS_NewString(ctx, buf);
}

static JSValue JsMapsArrayToString(JSContext* ctx, JSValueConst this_val, int, JSValueConst*) {
    int64_t len = 0;
    JSValue lenVal = JS_GetPropertyStr(ctx, this_val, "length");
    JS_ToInt64(ctx, &len, lenVal);
    JS_FreeValue(ctx, lenVal);

    if (len == 0) return JS_NewString(ctx, "[]");

    std::ostringstream ss;
    char header[128];
    snprintf(header, sizeof(header), "  %-18s %-18s %-6s %-10s %s\n  %s\n",
             "Start", "End", "Perms", "Size", "Path",
             "--------------------------------------------------------------------------------");
    ss << header;

    for (int64_t i = 0; i < len; ++i) {
        JSValue item = JS_GetPropertyUint32(ctx, this_val, static_cast<uint32_t>(i));
        JSValue startV = JS_GetPropertyStr(ctx, item, "start");
        JSValue endV = JS_GetPropertyStr(ctx, item, "end");
        JSValue permsV = JS_GetPropertyStr(ctx, item, "perms");
        JSValue sizeV = JS_GetPropertyStr(ctx, item, "size");
        JSValue pathV = JS_GetPropertyStr(ctx, item, "path");

        const char* sStart = JS_ToCString(ctx, startV);
        const char* sEnd = JS_ToCString(ctx, endV);
        const char* sPerms = JS_ToCString(ctx, permsV);
        const char* sSize = JS_ToCString(ctx, sizeV);
        const char* sPath = JS_ToCString(ctx, pathV);

        char row[256];
        snprintf(row, sizeof(row), "  %-18s %-18s %-6s %-10s %s\n",
                 sStart ? sStart : "?", sEnd ? sEnd : "?",
                 sPerms ? sPerms : "?", sSize ? sSize : "?",
                 sPath ? sPath : "");
        ss << row;

        if (sStart) JS_FreeCString(ctx, sStart);
        if (sEnd) JS_FreeCString(ctx, sEnd);
        if (sPerms) JS_FreeCString(ctx, sPerms);
        if (sSize) JS_FreeCString(ctx, sSize);
        if (sPath) JS_FreeCString(ctx, sPath);

        JS_FreeValue(ctx, startV);
        JS_FreeValue(ctx, endV);
        JS_FreeValue(ctx, permsV);
        JS_FreeValue(ctx, sizeV);
        JS_FreeValue(ctx, pathV);
        JS_FreeValue(ctx, item);
    }
    return JS_NewString(ctx, ss.str().c_str());
}

static JSValue JsMemoryMaps(JSContext* ctx, JSValueConst /*this_val*/, int argc, JSValueConst* argv) {
    std::string filter;
    if (argc >= 1 && JS_IsString(argv[0])) {
        const char* s = JS_ToCString(ctx, argv[0]);
        if (s) { filter = s; JS_FreeCString(ctx, s); }
    }

    std::vector<ProcMap> maps = filter.empty() ? KittyMemory::getAllMaps() : KittyMemory::getMapsByName(filter);
    JSValue arr = JS_NewArray(ctx);
    for (size_t i = 0; i < maps.size(); ++i) {
        const auto& m = maps[i];
        JSValue o = JS_NewObject(ctx);
        char sBuf[32], eBuf[32], szBuf[32], pBuf[8];
        snprintf(sBuf, sizeof(sBuf), "0x%llx", (unsigned long long)m.startAddress);
        snprintf(eBuf, sizeof(eBuf), "0x%llx", (unsigned long long)m.endAddress);
        snprintf(szBuf, sizeof(szBuf), "0x%zx", m.length);
        snprintf(pBuf, sizeof(pBuf), "%c%c%c%c",
                 m.readable ? 'r' : '-',
                 m.writeable ? 'w' : '-',
                 m.executable ? 'x' : '-',
                 m.is_shared ? 's' : 'p');

        JS_SetPropertyStr(ctx, o, "start", JS_NewString(ctx, sBuf));
        JS_SetPropertyStr(ctx, o, "end", JS_NewString(ctx, eBuf));
        JS_SetPropertyStr(ctx, o, "size", JS_NewString(ctx, szBuf));
        JS_SetPropertyStr(ctx, o, "perms", JS_NewString(ctx, pBuf));
        JS_SetPropertyStr(ctx, o, "path", JS_NewString(ctx, m.pathname.c_str()));
        JS_SetPropertyUint32(ctx, arr, static_cast<uint32_t>(i), o);
    }
    JS_SetPropertyStr(ctx, arr, "toString", JS_NewCFunction(ctx, JsMapsArrayToString, "toString", 0));
    return arr;
}

static JSValue JsMemoryFindNative(JSContext* ctx, JSValueConst /*this_val*/, int argc, JSValueConst* argv) {
    if (argc < 1) return JS_ThrowTypeError(ctx, "Usage: Memory.findNative(methodName, [moduleName])");
    const char* nStr = JS_ToCString(ctx, argv[0]);
    std::string name = nStr ? nStr : "";
    if (nStr) JS_FreeCString(ctx, nStr);

    std::string modFilter;
    if (argc >= 2 && JS_IsString(argv[1])) {
        const char* mStr = JS_ToCString(ctx, argv[1]);
        if (mStr) { modFilter = mStr; JS_FreeCString(ctx, mStr); }
    }

    std::vector<ProcMap> maps = modFilter.empty() ? KittyMemory::getAllMaps() : KittyMemory::getMapsByName(modFilter);
    RegisterNativeFn fn = KittyScanner::findRegisterNativeFn(maps, name);
    if (!fn.isValid()) return JS_NULL;

    JSValue o = JS_NewObject(ctx);
    JS_SetPropertyStr(ctx, o, "name", JS_NewString(ctx, fn.name ? fn.name : ""));
    JS_SetPropertyStr(ctx, o, "sig", JS_NewString(ctx, fn.signature ? fn.signature : ""));
    char buf[32];
    snprintf(buf, sizeof(buf), "0x%llx", (unsigned long long)reinterpret_cast<uintptr_t>(fn.fnPtr));
    JS_SetPropertyStr(ctx, o, "fnPtr", JS_NewString(ctx, buf));
    return o;
}

static JSValue JsMemoryProtect(JSContext* ctx, JSValueConst /*this_val*/, int argc, JSValueConst* argv) {
    if (argc < 3) return JS_ThrowTypeError(ctx, "Usage: Memory.protect(address, length, protection)");
    int64_t addr = ParsePtr(ctx, argv[0]);
    int64_t len = 0;
    int prot = 0;
    JS_ToInt64(ctx, &len, argv[1]);
    JS_ToInt32(ctx, &prot, argv[2]);
    if (!addr || len <= 0) return JS_FALSE;
    int rc = KittyMemory::setAddressProtection(reinterpret_cast<void*>(addr), static_cast<size_t>(len), prot);
    return JS_NewBool(ctx, rc == 0);
}

} // namespace

void RegisterMemoryApis(JSContext* ctx, JSValue global, JSValue memory) {
    // Memory namespace
    JS_SetPropertyStr(ctx, memory, "hexdump", JS_NewCFunction(ctx, JsHexDump, "hexdump", 2));
    JS_SetPropertyStr(ctx, memory, "readByteArray", JS_NewCFunction(ctx, JsReadByteArray, "readByteArray", 2));
    JS_SetPropertyStr(ctx, memory, "writeByteArray", JS_NewCFunction(ctx, JsWriteByteArray, "writeByteArray", 2));
    JS_SetPropertyStr(ctx, memory, "readCString", JS_NewCFunction(ctx, JsReadCString, "readCString", 1));
    JS_SetPropertyStr(ctx, memory, "readU32", JS_NewCFunction(ctx, JsReadU32, "readU32", 1));
    JS_SetPropertyStr(ctx, memory, "writeU32", JS_NewCFunction(ctx, JsWriteU32, "writeU32", 2));
    JS_SetPropertyStr(ctx, memory, "scan", JS_NewCFunction(ctx, JsMemoryScan, "scan", 3));
    JS_SetPropertyStr(ctx, memory, "patch", JS_NewCFunction(ctx, JsMemoryPatch, "patch", 3));
    JS_SetPropertyStr(ctx, memory, "restoreAll", JS_NewCFunction(ctx, JsMemoryRestoreAll, "restoreAll", 0));
    JS_SetPropertyStr(ctx, memory, "maps", JS_NewCFunction(ctx, JsMemoryMaps, "maps", 1));
    JS_SetPropertyStr(ctx, memory, "findNative", JS_NewCFunction(ctx, JsMemoryFindNative, "findNative", 2));
    JS_SetPropertyStr(ctx, memory, "protect", JS_NewCFunction(ctx, JsMemoryProtect, "protect", 3));

    // Flat global aliases
    JS_SetPropertyStr(ctx, global, "hexdump", JS_NewCFunction(ctx, JsHexDump, "hexdump", 2));
    JS_SetPropertyStr(ctx, global, "readmem", JS_NewCFunction(ctx, JsReadByteArray, "readmem", 2));
    JS_SetPropertyStr(ctx, global, "readByteArray", JS_NewCFunction(ctx, JsReadByteArray, "readByteArray", 2));
    JS_SetPropertyStr(ctx, global, "writemem", JS_NewCFunction(ctx, JsWriteByteArray, "writemem", 2));
    JS_SetPropertyStr(ctx, global, "writeByteArray", JS_NewCFunction(ctx, JsWriteByteArray, "writeByteArray", 2));
    JS_SetPropertyStr(ctx, global, "readstring", JS_NewCFunction(ctx, JsReadCString, "readstring", 1));
    JS_SetPropertyStr(ctx, global, "readCString", JS_NewCFunction(ctx, JsReadCString, "readCString", 1));
    JS_SetPropertyStr(ctx, global, "readu32", JS_NewCFunction(ctx, JsReadU32, "readu32", 1));
    JS_SetPropertyStr(ctx, global, "readU32", JS_NewCFunction(ctx, JsReadU32, "readU32", 1));
    JS_SetPropertyStr(ctx, global, "writeu32", JS_NewCFunction(ctx, JsWriteU32, "writeu32", 2));
    JS_SetPropertyStr(ctx, global, "writeU32", JS_NewCFunction(ctx, JsWriteU32, "writeU32", 2));
    JS_SetPropertyStr(ctx, global, "scanmem", JS_NewCFunction(ctx, JsMemoryScan, "scanmem", 3));
    JS_SetPropertyStr(ctx, global, "patchmem", JS_NewCFunction(ctx, JsMemoryPatch, "patchmem", 3));
    JS_SetPropertyStr(ctx, global, "restoreall", JS_NewCFunction(ctx, JsMemoryRestoreAll, "restoreall", 0));
    JS_SetPropertyStr(ctx, global, "maps", JS_NewCFunction(ctx, JsMemoryMaps, "maps", 1));
    JS_SetPropertyStr(ctx, global, "findnative", JS_NewCFunction(ctx, JsMemoryFindNative, "findnative", 2));
}

}} // namespace artpi::agent

