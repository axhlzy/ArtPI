//
// agent_qbdi.cpp - QuickJS Bindings for QBDI Native Instruction Emulation & Tracing
//
#include "agent_qbdi.h"
#include "agent_common.h"
#include "agent_net.h"
#include "native/qbdi/pi_qbdi_engine.h"
#include "QBDI/State.h"

#include <xdl.h>
#include <dlfcn.h>
#include <cinttypes>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>
#include <memory>
#include <mutex>
#include <android/log.h>

#define AGENT_QBDI_LOGI(...) __android_log_print(ANDROID_LOG_INFO, "ArtPI_QBDI", __VA_ARGS__)
#define AGENT_QBDI_LOGW(...) __android_log_print(ANDROID_LOG_WARN, "ArtPI_QBDI", __VA_ARGS__)

namespace artpi { namespace agent {

namespace {

// Safely resolve executable ranges for the module enclosing `addr` from /proc/self/maps.
// Avoids SEGV_ACCERR on XOM (execute-only memory) segments.
static std::vector<std::pair<uintptr_t, uintptr_t>> ResolveModuleRangesByAddr(uintptr_t addr) {
    std::vector<std::pair<uintptr_t, uintptr_t>> ranges;
    FILE* f = fopen("/proc/self/maps", "r");
    if (!f) return ranges;

    char targetPath[512] = {};
    char line[1024];
    while (fgets(line, sizeof(line), f)) {
        uintptr_t start, end;
        char perms[8] = {};
        unsigned long long offset;
        int dev_major, dev_minor;
        unsigned long inode;
        char path[512] = {};
        int n = sscanf(line, "%lx-%lx %4s %llx %x:%x %lu %511[^\n]",
                       &start, &end, perms, &offset, &dev_major, &dev_minor, &inode, path);
        if (n >= 7 && addr >= start && addr < end) {
            char* p = path;
            while (*p == ' ' || *p == '\t') p++;
            if (*p) strncpy(targetPath, p, sizeof(targetPath) - 1);
            break;
        }
    }

    if (!targetPath[0]) { fclose(f); return ranges; }

    rewind(f);
    while (fgets(line, sizeof(line), f)) {
        uintptr_t start, end;
        char perms[8] = {};
        unsigned long long offset;
        int dev_major, dev_minor;
        unsigned long inode;
        char path[512] = {};
        int n = sscanf(line, "%lx-%lx %4s %llx %x:%x %lu %511[^\n]",
                       &start, &end, perms, &offset, &dev_major, &dev_minor, &inode, path);
        if (n >= 7) {
            char* p = path;
            while (*p == ' ' || *p == '\t') p++;
            if (*p && strcmp(p, targetPath) == 0 && perms[2] == 'x') {
                ranges.push_back({start, end});
            }
        }
    }
    fclose(f);
    return ranges;
}

// Safely resolve executable ranges for a module given its name or substring from /proc/self/maps.
static std::vector<std::pair<uintptr_t, uintptr_t>> ResolveModuleRangesByName(const std::string& name) {
    std::vector<std::pair<uintptr_t, uintptr_t>> ranges;
    FILE* f = fopen("/proc/self/maps", "r");
    if (!f) return ranges;

    char line[1024];
    while (fgets(line, sizeof(line), f)) {
        uintptr_t start, end;
        char perms[8] = {};
        unsigned long long offset;
        int dev_major, dev_minor;
        unsigned long inode;
        char path[512] = {};
        int n = sscanf(line, "%lx-%lx %4s %llx %x:%x %lu %511[^\n]",
                       &start, &end, perms, &offset, &dev_major, &dev_minor, &inode, path);
        if (n >= 7 && perms[2] == 'x') {
            char* p = path;
            while (*p == ' ' || *p == '\t') p++;
            if (*p && strstr(p, name.c_str()) != nullptr) {
                ranges.push_back({start, end});
            }
        }
    }
    fclose(f);
    return ranges;
}

static uintptr_t ParseTargetAddress(JSContext* ctx, JSValue val) {
    if (JS_IsBigInt(ctx, val)) {
        int64_t v = 0;
        JS_ToBigInt64(ctx, &v, val);
        return static_cast<uintptr_t>(v);
    }
    if (JS_IsNumber(val)) {
        int64_t v = 0;
        JS_ToInt64(ctx, &v, val);
        return static_cast<uintptr_t>(v);
    }
    if (JS_IsString(val)) {
        const char* s = JS_ToCString(ctx, val);
        if (!s) return 0;
        std::string str(s);
        JS_FreeCString(ctx, s);

        if (str.rfind("0x", 0) == 0 || str.rfind("0X", 0) == 0) {
            return static_cast<uintptr_t>(strtoull(str.c_str(), nullptr, 16));
        }

        // Module!Symbol notation: "libfoo.so!my_func"
        size_t bang = str.find('!');
        if (bang != std::string::npos) {
            std::string mod = str.substr(0, bang);
            std::string sym = str.substr(bang + 1);
            void* h = xdl_open(mod.c_str(), XDL_DEFAULT);
            if (!h) h = dlopen(mod.c_str(), RTLD_NOW);
            if (h) {
                void* symAddr = xdl_sym(h, sym.c_str(), nullptr);
                if (!symAddr) symAddr = dlsym(h, sym.c_str());
                if (symAddr) return reinterpret_cast<uintptr_t>(symAddr);
            }
        }

        // Global symbol lookup
        void* symAddr = xdl_sym(RTLD_DEFAULT, str.c_str(), nullptr);
        if (!symAddr) symAddr = dlsym(RTLD_DEFAULT, str.c_str());
        if (symAddr) return reinterpret_cast<uintptr_t>(symAddr);

        // Fallback: decimal or hex integer in string form
        return static_cast<uintptr_t>(strtoull(str.c_str(), nullptr, 0));
    }
    return 0;
}

// Convert GPRState to a rich JS object
static JSValue MakeGprObject(JSContext* ctx, uintptr_t pc, const char* mnem, const char* disasm, QBDI::GPRState* gpr) {
    JSValue obj = JS_NewObject(ctx);
    char hex[32];

    snprintf(hex, sizeof(hex), "0x%" PRIxPTR, pc);
    JS_SetPropertyStr(ctx, obj, "pc", JS_NewString(ctx, hex));
    JS_SetPropertyStr(ctx, obj, "mnemonic", JS_NewString(ctx, mnem ? mnem : ""));
    JS_SetPropertyStr(ctx, obj, "disasm", JS_NewString(ctx, disasm ? disasm : ""));

    if (gpr) {
        snprintf(hex, sizeof(hex), "0x%" PRIx64, static_cast<uint64_t>(gpr->sp));
        JS_SetPropertyStr(ctx, obj, "sp", JS_NewString(ctx, hex));
        snprintf(hex, sizeof(hex), "0x%" PRIx64, static_cast<uint64_t>(gpr->lr));
        JS_SetPropertyStr(ctx, obj, "lr", JS_NewString(ctx, hex));
        snprintf(hex, sizeof(hex), "0x%" PRIx64, static_cast<uint64_t>(gpr->x29));
        JS_SetPropertyStr(ctx, obj, "fp", JS_NewString(ctx, hex));

        for (int i = 0; i <= 28; i++) {
            char regName[8];
            snprintf(regName, sizeof(regName), "x%d", i);
            snprintf(hex, sizeof(hex), "0x%" PRIx64, static_cast<uint64_t>((&gpr->x0)[i]));
            JS_SetPropertyStr(ctx, obj, regName, JS_NewString(ctx, hex));
        }
    }
    return obj;
}

// QBDI.isAvailable() / qbdi.isAvailable()
static JSValue JsQbdiIsAvailable(JSContext* ctx, JSValueConst /*this_val*/, int /*argc*/, JSValueConst* /*argv*/) {
    return JS_TRUE;
}

// QBDI.addInstrumentedModule(moduleName)
static JSValue JsQbdiAddInstrumentedModule(JSContext* ctx, JSValueConst /*this_val*/, int argc, JSValueConst* argv) {
    if (argc < 1 || !JS_IsString(argv[0])) {
        return JS_ThrowTypeError(ctx, "Usage: QBDI.addInstrumentedModule(moduleName)");
    }
    const char* name = JS_ToCString(ctx, argv[0]);
    if (!name) return JS_FALSE;

    auto ranges = ResolveModuleRangesByName(name);
    JS_FreeCString(ctx, name);

    if (ranges.empty()) return JS_FALSE;
    auto* engine = PI::Native::QBDIEngine::current();
    for (auto& r : ranges) {
        engine->addInstrumentedRange(r.first, r.second);
    }
    return JS_TRUE;
}

// QBDI.addInstrumentedRange(start, end)
static JSValue JsQbdiAddInstrumentedRange(JSContext* ctx, JSValueConst /*this_val*/, int argc, JSValueConst* argv) {
    if (argc < 2) {
        return JS_ThrowTypeError(ctx, "Usage: QBDI.addInstrumentedRange(start, end)");
    }
    uintptr_t start = ParseTargetAddress(ctx, argv[0]);
    uintptr_t end = ParseTargetAddress(ctx, argv[1]);
    if (start == 0 || end <= start) {
        return JS_ThrowRangeError(ctx, "Invalid address range [0x%" PRIxPTR ", 0x%" PRIxPTR "]", start, end);
    }
    auto* engine = PI::Native::QBDIEngine::current();
    engine->addInstrumentedRange(start, end);
    return JS_TRUE;
}

// QBDI.clearInstrumentedRanges()
static JSValue JsQbdiClearInstrumentedRanges(JSContext* ctx, JSValueConst /*this_val*/, int /*argc*/, JSValueConst* /*argv*/) {
    auto* engine = PI::Native::QBDIEngine::current();
    engine->clearInstrumentedRanges();
    return JS_UNDEFINED;
}

// Internal helper to parse args array
static std::vector<uint64_t> ParseGprArgs(JSContext* ctx, JSValue argsVal) {
    std::vector<uint64_t> gprs;
    if (!JS_IsArray(ctx, argsVal)) return gprs;
    int64_t len = 0;
    JSValue lenVal = JS_GetPropertyStr(ctx, argsVal, "length");
    JS_ToInt64(ctx, &len, lenVal);
    JS_FreeValue(ctx, lenVal);

    for (int64_t i = 0; i < len && i < 8; i++) {
        JSValue el = JS_GetPropertyUint32(ctx, argsVal, static_cast<uint32_t>(i));
        gprs.push_back(ParseTargetAddress(ctx, el));
        JS_FreeValue(ctx, el);
    }
    return gprs;
}

// QBDI.run(target, [args], [options]) / qbdi.run(...)
static JSValue JsQbdiRun(JSContext* ctx, JSValueConst /*this_val*/, int argc, JSValueConst* argv) {
    if (argc < 1) {
        return JS_ThrowTypeError(ctx, "Usage: QBDI.run(funcAddressOrSymbol, [args], [options])");
    }

    uintptr_t target = ParseTargetAddress(ctx, argv[0]);
    if (target == 0) {
        return JS_ThrowTypeError(ctx, "Invalid target function address");
    }

    std::vector<uint64_t> gprs;
    std::vector<double> fprs;
    uint64_t budget = 500000;
    std::vector<std::string> modules;

    int optIndex = 1;
    if (argc >= 2 && JS_IsArray(ctx, argv[1])) {
        gprs = ParseGprArgs(ctx, argv[1]);
        optIndex = 2;
    }

    if (argc > optIndex && JS_IsObject(argv[optIndex])) {
        JSValue opt = argv[optIndex];

        JSValue argsVal = JS_GetPropertyStr(ctx, opt, "args");
        if (JS_IsArray(ctx, argsVal) && gprs.empty()) {
            gprs = ParseGprArgs(ctx, argsVal);
        }
        JS_FreeValue(ctx, argsVal);

        JSValue bVal = JS_GetPropertyStr(ctx, opt, "budget");
        if (!JS_IsUndefined(bVal)) {
            int64_t b = 0;
            JS_ToInt64(ctx, &b, bVal);
            if (b >= 0) budget = static_cast<uint64_t>(b);
        }
        JS_FreeValue(ctx, bVal);

        JSValue mVal = JS_GetPropertyStr(ctx, opt, "modules");
        if (JS_IsArray(ctx, mVal)) {
            int64_t mlen = 0;
            JSValue mLenVal = JS_GetPropertyStr(ctx, mVal, "length");
            JS_ToInt64(ctx, &mlen, mLenVal);
            JS_FreeValue(ctx, mLenVal);
            for (int64_t i = 0; i < mlen; i++) {
                JSValue item = JS_GetPropertyUint32(ctx, mVal, static_cast<uint32_t>(i));
                const char* s = JS_ToCString(ctx, item);
                if (s) { modules.push_back(s); JS_FreeCString(ctx, s); }
                JS_FreeValue(ctx, item);
            }
        }
        JS_FreeValue(ctx, mVal);
    }

    auto* engine = PI::Native::QBDIEngine::current();
    engine->clearInstrumentedRanges();

    if (!modules.empty()) {
        for (const auto& mod : modules) {
            auto ranges = ResolveModuleRangesByName(mod);
            for (auto& r : ranges) engine->addInstrumentedRange(r.first, r.second);
        }
    } else {
        auto ranges = ResolveModuleRangesByAddr(target);
        if (ranges.empty()) {
            engine->addInstrumentedRange(target, target + (1u << 20));
        } else {
            for (auto& r : ranges) engine->addInstrumentedRange(r.first, r.second);
        }
    }

    engine->setInstructionBudget(budget);
    PI::Native::NativeRunResult res = engine->run(reinterpret_cast<void*>(target), gprs, fprs);

    JSValue out = JS_NewObject(ctx);
    const char* statusStr = "EXECUTION_ERROR";
    switch (res.status) {
        case PI::Native::NativeRunResult::OK: statusStr = "OK"; break;
        case PI::Native::NativeRunResult::MAX_INSTRUCTIONS_REACHED: statusStr = "MAX_INSTRUCTIONS_REACHED"; break;
        case PI::Native::NativeRunResult::CRASH_PROTECTED: statusStr = "CRASH_PROTECTED"; break;
        default: statusStr = "EXECUTION_ERROR"; break;
    }

    char hex[32];
    snprintf(hex, sizeof(hex), "0x%" PRIx64, res.gprResult);

    JS_SetPropertyStr(ctx, out, "status", JS_NewString(ctx, statusStr));
    JS_SetPropertyStr(ctx, out, "result", JS_NewString(ctx, hex));
    JS_SetPropertyStr(ctx, out, "gprResult", JS_NewString(ctx, hex));
    JS_SetPropertyStr(ctx, out, "fprResult", JS_NewFloat64(ctx, res.fprResult));
    JS_SetPropertyStr(ctx, out, "instructionsExecuted", JS_NewInt64(ctx, static_cast<int64_t>(res.instructionsExecuted)));

    return out;
}

// QBDI.trace(target, [args], [options]) / qbdi.trace(...)
static JSValue JsQbdiTrace(JSContext* ctx, JSValueConst /*this_val*/, int argc, JSValueConst* argv) {
    if (argc < 1) {
        return JS_ThrowTypeError(ctx, "Usage: QBDI.trace(funcAddressOrSymbol, [args], [options])");
    }

    uintptr_t target = ParseTargetAddress(ctx, argv[0]);
    if (target == 0) {
        return JS_ThrowTypeError(ctx, "Invalid target function address");
    }

    std::vector<uint64_t> gprs;
    std::vector<double> fprs;
    uint64_t budget = 200000;
    bool enableLog = true;
    size_t maxLog = 100;
    std::vector<std::string> modules;

    JSValue jsInsnCb = JS_UNDEFINED;
    JSValue jsMemCb = JS_UNDEFINED;

    int optIndex = 1;
    if (argc >= 2 && JS_IsArray(ctx, argv[1])) {
        gprs = ParseGprArgs(ctx, argv[1]);
        optIndex = 2;
    }

    if (argc > optIndex && JS_IsObject(argv[optIndex])) {
        JSValue opt = argv[optIndex];

        JSValue argsVal = JS_GetPropertyStr(ctx, opt, "args");
        if (JS_IsArray(ctx, argsVal) && gprs.empty()) {
            gprs = ParseGprArgs(ctx, argsVal);
        }
        JS_FreeValue(ctx, argsVal);

        JSValue bVal = JS_GetPropertyStr(ctx, opt, "budget");
        if (!JS_IsUndefined(bVal)) {
            int64_t b = 0;
            JS_ToInt64(ctx, &b, bVal);
            if (b >= 0) budget = static_cast<uint64_t>(b);
        }
        JS_FreeValue(ctx, bVal);

        JSValue lVal = JS_GetPropertyStr(ctx, opt, "log");
        if (!JS_IsUndefined(lVal)) enableLog = JS_ToBool(ctx, lVal);
        JS_FreeValue(ctx, lVal);

        JSValue mlVal = JS_GetPropertyStr(ctx, opt, "maxLog");
        if (!JS_IsUndefined(mlVal)) {
            int64_t ml = 0;
            JS_ToInt64(ctx, &ml, mlVal);
            if (ml >= 0) maxLog = static_cast<size_t>(ml);
        }
        JS_FreeValue(ctx, mlVal);

        JSValue cb1 = JS_GetPropertyStr(ctx, opt, "onInstruction");
        if (JS_IsFunction(ctx, cb1)) jsInsnCb = cb1; else JS_FreeValue(ctx, cb1);

        JSValue cb2 = JS_GetPropertyStr(ctx, opt, "onMemory");
        if (JS_IsFunction(ctx, cb2)) jsMemCb = cb2; else JS_FreeValue(ctx, cb2);

        JSValue mVal = JS_GetPropertyStr(ctx, opt, "modules");
        if (JS_IsArray(ctx, mVal)) {
            int64_t mlen = 0;
            JSValue mLenVal = JS_GetPropertyStr(ctx, mVal, "length");
            JS_ToInt64(ctx, &mlen, mLenVal);
            JS_FreeValue(ctx, mLenVal);
            for (int64_t i = 0; i < mlen; i++) {
                JSValue item = JS_GetPropertyUint32(ctx, mVal, static_cast<uint32_t>(i));
                const char* s = JS_ToCString(ctx, item);
                if (s) { modules.push_back(s); JS_FreeCString(ctx, s); }
                JS_FreeValue(ctx, item);
            }
        }
        JS_FreeValue(ctx, mVal);
    }

    auto* engine = PI::Native::QBDIEngine::current();
    engine->clearInstrumentedRanges();

    if (!modules.empty()) {
        for (const auto& mod : modules) {
            auto ranges = ResolveModuleRangesByName(mod);
            for (auto& r : ranges) engine->addInstrumentedRange(r.first, r.second);
        }
    } else {
        auto ranges = ResolveModuleRangesByAddr(target);
        if (ranges.empty()) {
            engine->addInstrumentedRange(target, target + (1u << 20));
        } else {
            for (auto& r : ranges) engine->addInstrumentedRange(r.first, r.second);
        }
    }

    engine->setInstructionBudget(budget);

    auto insnGuard = std::shared_ptr<JSValue>(new JSValue(jsInsnCb), [ctx](JSValue* p) {
        if (p) {
            if (!JS_IsUndefined(*p)) JS_FreeValue(ctx, *p);
            delete p;
        }
    });

    auto memGuard = std::shared_ptr<JSValue>(new JSValue(jsMemCb), [ctx](JSValue* p) {
        if (p) {
            if (!JS_IsUndefined(*p)) JS_FreeValue(ctx, *p);
            delete p;
        }
    });

    size_t loggedInsns = 0;

    engine->setInstructionCallback([ctx, insnGuard, enableLog, maxLog, &loggedInsns](
            uintptr_t pc, const char* mnem, const char* disasm, int /*depth*/, void* rawGpr) -> int {
        if (enableLog && loggedInsns < maxLog) {
            char logLine[256];
            snprintf(logLine, sizeof(logLine), "[QBDI] 0x%" PRIxPTR ": %-8s %s",
                     pc, mnem ? mnem : "", disasm ? disasm : "");
            AGENT_QBDI_LOGI("%s", logLine);
            BroadcastLog("trace", logLine);
            loggedInsns++;
            if (loggedInsns == maxLog) {
                BroadcastLog("trace", "[QBDI] ... (trace logging limit reached)");
            }
        }

        if (!JS_IsUndefined(*insnGuard)) {
            bool needLock = (t_jsReentrancyDepth == 0);
            std::unique_lock<std::mutex> lk(g_jsMutex, std::defer_lock);
            if (needLock) lk.lock();

            auto* gpr = reinterpret_cast<QBDI::GPRState*>(rawGpr);
            JSValue gprObj = MakeGprObject(ctx, pc, mnem, disasm, gpr);
            JSValue args[5];
            args[0] = JS_NewBigInt64(ctx, static_cast<int64_t>(pc));
            args[1] = JS_NewString(ctx, mnem ? mnem : "");
            args[2] = JS_NewString(ctx, disasm ? disasm : "");
            args[3] = JS_NewInt32(ctx, 0);
            args[4] = gprObj;

            JSValue r = JS_Call(ctx, *insnGuard, JS_UNDEFINED, 5, args);
            bool stop = false;
            if (JS_IsBool(r) && !JS_ToBool(ctx, r)) {
                stop = true; // return false cancels execution
            } else if (JS_IsNumber(r)) {
                int32_t act = 0;
                JS_ToInt32(ctx, &act, r);
                if (act != 0) stop = true;
            }
            JS_FreeValue(ctx, r);
            for (int i = 0; i < 5; i++) JS_FreeValue(ctx, args[i]);

            if (stop) return 1; // STOP
        }
        return 0; // CONTINUE
    });

    if (!JS_IsUndefined(*memGuard)) {
        engine->setMemoryAccessCallback([ctx, memGuard](uintptr_t insnPc, uintptr_t addr, size_t size, bool isWrite, uint64_t val) {
            bool needLock = (t_jsReentrancyDepth == 0);
            std::unique_lock<std::mutex> lk(g_jsMutex, std::defer_lock);
            if (needLock) lk.lock();

            JSValue args[5];
            args[0] = JS_NewBigInt64(ctx, static_cast<int64_t>(insnPc));
            args[1] = JS_NewBigInt64(ctx, static_cast<int64_t>(addr));
            args[2] = JS_NewInt32(ctx, static_cast<int32_t>(size));
            args[3] = JS_NewBool(ctx, isWrite);
            args[4] = JS_NewBigInt64(ctx, static_cast<int64_t>(val));

            JSValue r = JS_Call(ctx, *memGuard, JS_UNDEFINED, 5, args);
            JS_FreeValue(ctx, r);
            for (int i = 0; i < 5; i++) JS_FreeValue(ctx, args[i]);
        });
    }

    PI::Native::NativeRunResult res = engine->run(reinterpret_cast<void*>(target), gprs, fprs);

    engine->clearCallbacks();

    JSValue out = JS_NewObject(ctx);
    const char* statusStr = "EXECUTION_ERROR";
    switch (res.status) {
        case PI::Native::NativeRunResult::OK: statusStr = "OK"; break;
        case PI::Native::NativeRunResult::MAX_INSTRUCTIONS_REACHED: statusStr = "MAX_INSTRUCTIONS_REACHED"; break;
        case PI::Native::NativeRunResult::CRASH_PROTECTED: statusStr = "CRASH_PROTECTED"; break;
        default: statusStr = "EXECUTION_ERROR"; break;
    }

    char hex[32];
    snprintf(hex, sizeof(hex), "0x%" PRIx64, res.gprResult);

    JS_SetPropertyStr(ctx, out, "status", JS_NewString(ctx, statusStr));
    JS_SetPropertyStr(ctx, out, "result", JS_NewString(ctx, hex));
    JS_SetPropertyStr(ctx, out, "gprResult", JS_NewString(ctx, hex));
    JS_SetPropertyStr(ctx, out, "fprResult", JS_NewFloat64(ctx, res.fprResult));
    JS_SetPropertyStr(ctx, out, "instructionsExecuted", JS_NewInt64(ctx, static_cast<int64_t>(res.instructionsExecuted)));

    return out;
}

static void PopulateQbdiObject(JSContext* ctx, JSValue obj) {
    JS_SetPropertyStr(ctx, obj, "isAvailable", JS_NewCFunction(ctx, JsQbdiIsAvailable, "isAvailable", 0));
    JS_SetPropertyStr(ctx, obj, "run", JS_NewCFunction(ctx, JsQbdiRun, "run", 3));
    JS_SetPropertyStr(ctx, obj, "trace", JS_NewCFunction(ctx, JsQbdiTrace, "trace", 3));
    JS_SetPropertyStr(ctx, obj, "addInstrumentedModule", JS_NewCFunction(ctx, JsQbdiAddInstrumentedModule, "addInstrumentedModule", 1));
    JS_SetPropertyStr(ctx, obj, "addInstrumentedRange", JS_NewCFunction(ctx, JsQbdiAddInstrumentedRange, "addInstrumentedRange", 2));
    JS_SetPropertyStr(ctx, obj, "clearInstrumentedRanges", JS_NewCFunction(ctx, JsQbdiClearInstrumentedRanges, "clearInstrumentedRanges", 0));
}

} // namespace

void RegisterQbdiApis(JSContext* ctx, JSValue global) {
    // 1. QBDI (Uppercase)
    JSValue qbdiObj = JS_NewObject(ctx);
    PopulateQbdiObject(ctx, qbdiObj);
    JS_SetPropertyStr(ctx, global, "QBDI", JS_DupValue(ctx, qbdiObj));

    // 2. qbdi (Lowercase) - case insensitive requirement
    JS_SetPropertyStr(ctx, global, "qbdi", qbdiObj);
}

}} // namespace artpi::agent
