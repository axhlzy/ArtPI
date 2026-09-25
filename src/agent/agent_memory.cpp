//
// agent_memory.cpp - Memory inspection & modification domain bindings for QuickJS
//
#include "agent_memory.h"
#include "agent_common.h"
#include "../../include/ArtPI.h"
#include "art/art_method.h"

#include <sstream>
#include <vector>
#include <string>
#include <cstring>
#include <sys/mman.h>
#include <unistd.h>

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

} // namespace

void RegisterMemoryApis(JSContext* ctx, JSValue global, JSValue memory) {
    // Memory namespace
    JS_SetPropertyStr(ctx, memory, "hexdump", JS_NewCFunction(ctx, JsHexDump, "hexdump", 2));
    JS_SetPropertyStr(ctx, memory, "readByteArray", JS_NewCFunction(ctx, JsReadByteArray, "readByteArray", 2));
    JS_SetPropertyStr(ctx, memory, "writeByteArray", JS_NewCFunction(ctx, JsWriteByteArray, "writeByteArray", 2));
    JS_SetPropertyStr(ctx, memory, "readCString", JS_NewCFunction(ctx, JsReadCString, "readCString", 1));
    JS_SetPropertyStr(ctx, memory, "readU32", JS_NewCFunction(ctx, JsReadU32, "readU32", 1));
    JS_SetPropertyStr(ctx, memory, "writeU32", JS_NewCFunction(ctx, JsWriteU32, "writeU32", 2));

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
}

}} // namespace artpi::agent
