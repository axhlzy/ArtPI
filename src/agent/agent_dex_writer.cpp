//
// agent_dex_writer.cpp - QuickJS bindings for DexWriter
//

#include "agent_dex_writer.h"
#include "dex/pi_dex_gen.h"
#include <algorithm>
#include <cstring>
#include <string>
#include <vector>

namespace artpi { namespace agent {

namespace {

JSClassID g_dexWriterClassId = 0;

struct DexWriterWrapper {
    std::shared_ptr<PI::DexWriter::Writer> writer;
};

void DexWriterFinalizer(JSRuntime* /*rt*/, JSValue val) {
    auto* wrap = static_cast<DexWriterWrapper*>(JS_GetOpaque(val, g_dexWriterClassId));
    delete wrap;
}

static JSClassDef kDexWriterClassDef = {
    "DexWriter",
    DexWriterFinalizer,
    nullptr, nullptr, nullptr
};

DexWriterWrapper* GetWrapper(JSContext* ctx, JSValueConst this_val) {
    return static_cast<DexWriterWrapper*>(JS_GetOpaque2(ctx, this_val, g_dexWriterClassId));
}

std::vector<uint32_t> ExtractRegs(JSContext* ctx, int argc, JSValueConst* argv, int startIndex) {
    std::vector<uint32_t> regs;
    if (startIndex >= argc) return regs;

    if (JS_IsArray(ctx, argv[startIndex])) {
        JSValue lenVal = JS_GetPropertyStr(ctx, argv[startIndex], "length");
        uint32_t len = 0;
        JS_ToUint32(ctx, &len, lenVal);
        JS_FreeValue(ctx, lenVal);

        for (uint32_t i = 0; i < len; ++i) {
            JSValue elem = JS_GetPropertyUint32(ctx, argv[startIndex], i);
            uint32_t r = 0;
            JS_ToUint32(ctx, &r, elem);
            JS_FreeValue(ctx, elem);
            regs.push_back(r);
        }
    } else {
        // Variadic arguments: putInvokeVirtual("...", 0, 1, 2)
        for (int i = startIndex; i < argc; ++i) {
            uint32_t r = 0;
            JS_ToUint32(ctx, &r, argv[i]);
            regs.push_back(r);
        }
    }
    return regs;
}

std::string GetCString(JSContext* ctx, JSValueConst val) {
    const char* c = JS_ToCString(ctx, val);
    std::string s = c ? c : "";
    if (c) JS_FreeCString(ctx, c);
    return s;
}

// ---------------------------------------------------------------------------
// JS Methods
// ---------------------------------------------------------------------------

static JSValue JsDexWriterCtor(JSContext* ctx, JSValueConst new_target, int argc, JSValueConst* argv) {
    auto writer = std::make_shared<PI::DexWriter::Writer>();
    if (argc >= 1 && JS_IsObject(argv[0])) {
        uint32_t total = 4, ins = 1, outs = 4;
        JSValue vTotal = JS_GetPropertyStr(ctx, argv[0], "registers");
        if (JS_IsNumber(vTotal)) JS_ToUint32(ctx, &total, vTotal);
        JS_FreeValue(ctx, vTotal);

        JSValue vIns = JS_GetPropertyStr(ctx, argv[0], "ins");
        if (JS_IsNumber(vIns)) JS_ToUint32(ctx, &ins, vIns);
        JS_FreeValue(ctx, vIns);

        JSValue vOuts = JS_GetPropertyStr(ctx, argv[0], "outs");
        if (JS_IsNumber(vOuts)) JS_ToUint32(ctx, &outs, vOuts);
        JS_FreeValue(ctx, vOuts);

        writer->SetRegisters(static_cast<uint16_t>(total),
                             static_cast<uint16_t>(ins),
                             static_cast<uint16_t>(outs));
    }

    JSValue obj = JS_NewObjectClass(ctx, g_dexWriterClassId);
    if (JS_IsException(obj)) return obj;

    auto* wrap = new DexWriterWrapper{std::move(writer)};
    JS_SetOpaque(obj, wrap);
    return obj;
}

static JSValue JsSetRegisters(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
    auto* wrap = GetWrapper(ctx, this_val);
    if (!wrap) return JS_EXCEPTION;
    uint32_t total = wrap->writer->GetRegisters();
    uint32_t ins = wrap->writer->GetIns();
    uint32_t outs = wrap->writer->GetOuts();
    if (argc >= 1 && !JS_IsUndefined(argv[0])) JS_ToUint32(ctx, &total, argv[0]);
    if (argc >= 2 && !JS_IsUndefined(argv[1])) JS_ToUint32(ctx, &ins, argv[1]);
    if (argc >= 3 && !JS_IsUndefined(argv[2])) JS_ToUint32(ctx, &outs, argv[2]);
    wrap->writer->SetRegisters(static_cast<uint16_t>(total),
                               static_cast<uint16_t>(ins),
                               static_cast<uint16_t>(outs));
    return JS_DupValue(ctx, this_val);
}

static JSValue JsMakeLabel(JSContext* ctx, JSValueConst this_val, int /*argc*/, JSValueConst* /*argv*/) {
    auto* wrap = GetWrapper(ctx, this_val);
    if (!wrap) return JS_EXCEPTION;
    return JS_NewInt32(ctx, wrap->writer->MakeLabel());
}

static JSValue JsPutLabel(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
    auto* wrap = GetWrapper(ctx, this_val);
    if (!wrap || argc < 1) return JS_EXCEPTION;
    int id = 0; JS_ToInt32(ctx, &id, argv[0]);
    wrap->writer->PutLabel(id);
    return JS_DupValue(ctx, this_val);
}

static JSValue JsPutGoto(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
    auto* wrap = GetWrapper(ctx, this_val);
    if (!wrap || argc < 1) return JS_EXCEPTION;
    int id = 0; JS_ToInt32(ctx, &id, argv[0]);
    wrap->writer->PutGoto(id);
    return JS_DupValue(ctx, this_val);
}

static JSValue JsPutIfEqz(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
    auto* wrap = GetWrapper(ctx, this_val);
    if (!wrap || argc < 2) return JS_EXCEPTION;
    uint32_t r = 0; int id = 0;
    JS_ToUint32(ctx, &r, argv[0]); JS_ToInt32(ctx, &id, argv[1]);
    wrap->writer->PutIfEqz(r, id);
    return JS_DupValue(ctx, this_val);
}

static JSValue JsPutIfNez(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
    auto* wrap = GetWrapper(ctx, this_val);
    if (!wrap || argc < 2) return JS_EXCEPTION;
    uint32_t r = 0; int id = 0;
    JS_ToUint32(ctx, &r, argv[0]); JS_ToInt32(ctx, &id, argv[1]);
    wrap->writer->PutIfNez(r, id);
    return JS_DupValue(ctx, this_val);
}

static JSValue JsPutIfLtz(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
    auto* wrap = GetWrapper(ctx, this_val);
    if (!wrap || argc < 2) return JS_EXCEPTION;
    uint32_t r = 0; int id = 0;
    JS_ToUint32(ctx, &r, argv[0]); JS_ToInt32(ctx, &id, argv[1]);
    wrap->writer->PutIfLtz(r, id);
    return JS_DupValue(ctx, this_val);
}

static JSValue JsPutIfGez(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
    auto* wrap = GetWrapper(ctx, this_val);
    if (!wrap || argc < 2) return JS_EXCEPTION;
    uint32_t r = 0; int id = 0;
    JS_ToUint32(ctx, &r, argv[0]); JS_ToInt32(ctx, &id, argv[1]);
    wrap->writer->PutIfGez(r, id);
    return JS_DupValue(ctx, this_val);
}

static JSValue JsPutIfGtz(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
    auto* wrap = GetWrapper(ctx, this_val);
    if (!wrap || argc < 2) return JS_EXCEPTION;
    uint32_t r = 0; int id = 0;
    JS_ToUint32(ctx, &r, argv[0]); JS_ToInt32(ctx, &id, argv[1]);
    wrap->writer->PutIfGtz(r, id);
    return JS_DupValue(ctx, this_val);
}

static JSValue JsPutIfLez(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
    auto* wrap = GetWrapper(ctx, this_val);
    if (!wrap || argc < 2) return JS_EXCEPTION;
    uint32_t r = 0; int id = 0;
    JS_ToUint32(ctx, &r, argv[0]); JS_ToInt32(ctx, &id, argv[1]);
    wrap->writer->PutIfLez(r, id);
    return JS_DupValue(ctx, this_val);
}

static JSValue JsPutIfEq(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
    auto* wrap = GetWrapper(ctx, this_val);
    if (!wrap || argc < 3) return JS_EXCEPTION;
    uint32_t r1 = 0, r2 = 0; int id = 0;
    JS_ToUint32(ctx, &r1, argv[0]); JS_ToUint32(ctx, &r2, argv[1]); JS_ToInt32(ctx, &id, argv[2]);
    wrap->writer->PutIfEq(r1, r2, id);
    return JS_DupValue(ctx, this_val);
}

static JSValue JsPutIfNe(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
    auto* wrap = GetWrapper(ctx, this_val);
    if (!wrap || argc < 3) return JS_EXCEPTION;
    uint32_t r1 = 0, r2 = 0; int id = 0;
    JS_ToUint32(ctx, &r1, argv[0]); JS_ToUint32(ctx, &r2, argv[1]); JS_ToInt32(ctx, &id, argv[2]);
    wrap->writer->PutIfNe(r1, r2, id);
    return JS_DupValue(ctx, this_val);
}

static JSValue JsPutIfLt(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
    auto* wrap = GetWrapper(ctx, this_val);
    if (!wrap || argc < 3) return JS_EXCEPTION;
    uint32_t r1 = 0, r2 = 0; int id = 0;
    JS_ToUint32(ctx, &r1, argv[0]); JS_ToUint32(ctx, &r2, argv[1]); JS_ToInt32(ctx, &id, argv[2]);
    wrap->writer->PutIfLt(r1, r2, id);
    return JS_DupValue(ctx, this_val);
}

static JSValue JsPutIfGe(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
    auto* wrap = GetWrapper(ctx, this_val);
    if (!wrap || argc < 3) return JS_EXCEPTION;
    uint32_t r1 = 0, r2 = 0; int id = 0;
    JS_ToUint32(ctx, &r1, argv[0]); JS_ToUint32(ctx, &r2, argv[1]); JS_ToInt32(ctx, &id, argv[2]);
    wrap->writer->PutIfGe(r1, r2, id);
    return JS_DupValue(ctx, this_val);
}

static JSValue JsPutIfGt(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
    auto* wrap = GetWrapper(ctx, this_val);
    if (!wrap || argc < 3) return JS_EXCEPTION;
    uint32_t r1 = 0, r2 = 0; int id = 0;
    JS_ToUint32(ctx, &r1, argv[0]); JS_ToUint32(ctx, &r2, argv[1]); JS_ToInt32(ctx, &id, argv[2]);
    wrap->writer->PutIfGt(r1, r2, id);
    return JS_DupValue(ctx, this_val);
}

static JSValue JsPutIfLe(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
    auto* wrap = GetWrapper(ctx, this_val);
    if (!wrap || argc < 3) return JS_EXCEPTION;
    uint32_t r1 = 0, r2 = 0; int id = 0;
    JS_ToUint32(ctx, &r1, argv[0]); JS_ToUint32(ctx, &r2, argv[1]); JS_ToInt32(ctx, &id, argv[2]);
    wrap->writer->PutIfLe(r1, r2, id);
    return JS_DupValue(ctx, this_val);
}

static JSValue JsPutConst4(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
    auto* wrap = GetWrapper(ctx, this_val);
    if (!wrap || argc < 2) return JS_EXCEPTION;
    uint32_t r = 0; int32_t val = 0;
    JS_ToUint32(ctx, &r, argv[0]); JS_ToInt32(ctx, &val, argv[1]);
    wrap->writer->PutConst4(r, val);
    return JS_DupValue(ctx, this_val);
}

static JSValue JsPutConst16(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
    auto* wrap = GetWrapper(ctx, this_val);
    if (!wrap || argc < 2) return JS_EXCEPTION;
    uint32_t r = 0; int32_t val = 0;
    JS_ToUint32(ctx, &r, argv[0]); JS_ToInt32(ctx, &val, argv[1]);
    wrap->writer->PutConst16(r, val);
    return JS_DupValue(ctx, this_val);
}

static JSValue JsPutConst(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
    auto* wrap = GetWrapper(ctx, this_val);
    if (!wrap || argc < 2) return JS_EXCEPTION;
    uint32_t r = 0; int32_t val = 0;
    JS_ToUint32(ctx, &r, argv[0]); JS_ToInt32(ctx, &val, argv[1]);
    wrap->writer->PutConst(r, val);
    return JS_DupValue(ctx, this_val);
}

static JSValue JsPutConstString(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
    auto* wrap = GetWrapper(ctx, this_val);
    if (!wrap || argc < 2) return JS_EXCEPTION;
    uint32_t r = 0; JS_ToUint32(ctx, &r, argv[0]);
    wrap->writer->PutConstString(r, GetCString(ctx, argv[1]));
    return JS_DupValue(ctx, this_val);
}

static JSValue JsPutConstClass(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
    auto* wrap = GetWrapper(ctx, this_val);
    if (!wrap || argc < 2) return JS_EXCEPTION;
    uint32_t r = 0; JS_ToUint32(ctx, &r, argv[0]);
    wrap->writer->PutConstClass(r, GetCString(ctx, argv[1]));
    return JS_DupValue(ctx, this_val);
}

static JSValue JsPutMove(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
    auto* wrap = GetWrapper(ctx, this_val);
    if (!wrap || argc < 2) return JS_EXCEPTION;
    uint32_t d = 0, s = 0;
    JS_ToUint32(ctx, &d, argv[0]); JS_ToUint32(ctx, &s, argv[1]);
    wrap->writer->PutMove(d, s);
    return JS_DupValue(ctx, this_val);
}

static JSValue JsPutMoveObject(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
    auto* wrap = GetWrapper(ctx, this_val);
    if (!wrap || argc < 2) return JS_EXCEPTION;
    uint32_t d = 0, s = 0;
    JS_ToUint32(ctx, &d, argv[0]); JS_ToUint32(ctx, &s, argv[1]);
    wrap->writer->PutMoveObject(d, s);
    return JS_DupValue(ctx, this_val);
}

static JSValue JsPutMoveResult(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
    auto* wrap = GetWrapper(ctx, this_val);
    if (!wrap || argc < 1) return JS_EXCEPTION;
    uint32_t d = 0; JS_ToUint32(ctx, &d, argv[0]);
    wrap->writer->PutMoveResult(d);
    return JS_DupValue(ctx, this_val);
}

static JSValue JsPutMoveResultObject(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
    auto* wrap = GetWrapper(ctx, this_val);
    if (!wrap || argc < 1) return JS_EXCEPTION;
    uint32_t d = 0; JS_ToUint32(ctx, &d, argv[0]);
    wrap->writer->PutMoveResultObject(d);
    return JS_DupValue(ctx, this_val);
}

static JSValue JsPutReturnVoid(JSContext* ctx, JSValueConst this_val, int /*argc*/, JSValueConst* /*argv*/) {
    auto* wrap = GetWrapper(ctx, this_val);
    if (!wrap) return JS_EXCEPTION;
    wrap->writer->PutReturnVoid();
    return JS_DupValue(ctx, this_val);
}

static JSValue JsPutReturn(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
    auto* wrap = GetWrapper(ctx, this_val);
    if (!wrap || argc < 1) return JS_EXCEPTION;
    uint32_t r = 0; JS_ToUint32(ctx, &r, argv[0]);
    wrap->writer->PutReturn(r);
    return JS_DupValue(ctx, this_val);
}

static JSValue JsPutReturnObject(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
    auto* wrap = GetWrapper(ctx, this_val);
    if (!wrap || argc < 1) return JS_EXCEPTION;
    uint32_t r = 0; JS_ToUint32(ctx, &r, argv[0]);
    wrap->writer->PutReturnObject(r);
    return JS_DupValue(ctx, this_val);
}

static JSValue JsPutInvokeVirtual(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
    auto* wrap = GetWrapper(ctx, this_val);
    if (!wrap || argc < 1) return JS_EXCEPTION;
    std::string sig = GetCString(ctx, argv[0]);
    std::vector<uint32_t> regs = ExtractRegs(ctx, argc, argv, 1);
    if (!wrap->writer->PutInvokeVirtual(sig, regs)) {
        return JS_ThrowTypeError(ctx, "malformed invoke signature: %s", sig.c_str());
    }
    return JS_DupValue(ctx, this_val);
}

static JSValue JsPutInvokeDirect(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
    auto* wrap = GetWrapper(ctx, this_val);
    if (!wrap || argc < 1) return JS_EXCEPTION;
    std::string sig = GetCString(ctx, argv[0]);
    std::vector<uint32_t> regs = ExtractRegs(ctx, argc, argv, 1);
    if (!wrap->writer->PutInvokeDirect(sig, regs)) {
        return JS_ThrowTypeError(ctx, "malformed invoke signature: %s", sig.c_str());
    }
    return JS_DupValue(ctx, this_val);
}

static JSValue JsPutInvokeStatic(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
    auto* wrap = GetWrapper(ctx, this_val);
    if (!wrap || argc < 1) return JS_EXCEPTION;
    std::string sig = GetCString(ctx, argv[0]);
    std::vector<uint32_t> regs = ExtractRegs(ctx, argc, argv, 1);
    if (!wrap->writer->PutInvokeStatic(sig, regs)) {
        return JS_ThrowTypeError(ctx, "malformed invoke signature: %s", sig.c_str());
    }
    return JS_DupValue(ctx, this_val);
}

static JSValue JsPutInvokeSuper(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
    auto* wrap = GetWrapper(ctx, this_val);
    if (!wrap || argc < 1) return JS_EXCEPTION;
    std::string sig = GetCString(ctx, argv[0]);
    std::vector<uint32_t> regs = ExtractRegs(ctx, argc, argv, 1);
    if (!wrap->writer->PutInvokeSuper(sig, regs)) {
        return JS_ThrowTypeError(ctx, "malformed invoke signature: %s", sig.c_str());
    }
    return JS_DupValue(ctx, this_val);
}

static JSValue JsPutInvokeInterface(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
    auto* wrap = GetWrapper(ctx, this_val);
    if (!wrap || argc < 1) return JS_EXCEPTION;
    std::string sig = GetCString(ctx, argv[0]);
    std::vector<uint32_t> regs = ExtractRegs(ctx, argc, argv, 1);
    if (!wrap->writer->PutInvokeInterface(sig, regs)) {
        return JS_ThrowTypeError(ctx, "malformed invoke signature: %s", sig.c_str());
    }
    return JS_DupValue(ctx, this_val);
}

static JSValue JsPutNewInstance(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
    auto* wrap = GetWrapper(ctx, this_val);
    if (!wrap || argc < 2) return JS_EXCEPTION;
    uint32_t r = 0; JS_ToUint32(ctx, &r, argv[0]);
    wrap->writer->PutNewInstance(r, GetCString(ctx, argv[1]));
    return JS_DupValue(ctx, this_val);
}

static JSValue JsPutCheckCast(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
    auto* wrap = GetWrapper(ctx, this_val);
    if (!wrap || argc < 2) return JS_EXCEPTION;
    uint32_t r = 0; JS_ToUint32(ctx, &r, argv[0]);
    wrap->writer->PutCheckCast(r, GetCString(ctx, argv[1]));
    return JS_DupValue(ctx, this_val);
}

static JSValue JsPutInstanceOf(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
    auto* wrap = GetWrapper(ctx, this_val);
    if (!wrap || argc < 3) return JS_EXCEPTION;
    uint32_t d = 0, o = 0;
    JS_ToUint32(ctx, &d, argv[0]); JS_ToUint32(ctx, &o, argv[1]);
    wrap->writer->PutInstanceOf(d, o, GetCString(ctx, argv[2]));
    return JS_DupValue(ctx, this_val);
}

static JSValue JsPutIget(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
    auto* wrap = GetWrapper(ctx, this_val);
    if (!wrap || argc < 3) return JS_EXCEPTION;
    uint32_t v = 0, o = 0;
    JS_ToUint32(ctx, &v, argv[0]); JS_ToUint32(ctx, &o, argv[1]);
    wrap->writer->PutIget(v, o, GetCString(ctx, argv[2]));
    return JS_DupValue(ctx, this_val);
}

static JSValue JsPutIput(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
    auto* wrap = GetWrapper(ctx, this_val);
    if (!wrap || argc < 3) return JS_EXCEPTION;
    uint32_t v = 0, o = 0;
    JS_ToUint32(ctx, &v, argv[0]); JS_ToUint32(ctx, &o, argv[1]);
    wrap->writer->PutIput(v, o, GetCString(ctx, argv[2]));
    return JS_DupValue(ctx, this_val);
}

static JSValue JsPutIgetObject(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
    auto* wrap = GetWrapper(ctx, this_val);
    if (!wrap || argc < 3) return JS_EXCEPTION;
    uint32_t v = 0, o = 0;
    JS_ToUint32(ctx, &v, argv[0]); JS_ToUint32(ctx, &o, argv[1]);
    wrap->writer->PutIgetObject(v, o, GetCString(ctx, argv[2]));
    return JS_DupValue(ctx, this_val);
}

static JSValue JsPutIputObject(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
    auto* wrap = GetWrapper(ctx, this_val);
    if (!wrap || argc < 3) return JS_EXCEPTION;
    uint32_t v = 0, o = 0;
    JS_ToUint32(ctx, &v, argv[0]); JS_ToUint32(ctx, &o, argv[1]);
    wrap->writer->PutIputObject(v, o, GetCString(ctx, argv[2]));
    return JS_DupValue(ctx, this_val);
}

static JSValue JsPutIgetBoolean(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
    auto* wrap = GetWrapper(ctx, this_val);
    if (!wrap || argc < 3) return JS_EXCEPTION;
    uint32_t v = 0, o = 0;
    JS_ToUint32(ctx, &v, argv[0]); JS_ToUint32(ctx, &o, argv[1]);
    wrap->writer->PutIgetBoolean(v, o, GetCString(ctx, argv[2]));
    return JS_DupValue(ctx, this_val);
}

static JSValue JsPutIputBoolean(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
    auto* wrap = GetWrapper(ctx, this_val);
    if (!wrap || argc < 3) return JS_EXCEPTION;
    uint32_t v = 0, o = 0;
    JS_ToUint32(ctx, &v, argv[0]); JS_ToUint32(ctx, &o, argv[1]);
    wrap->writer->PutIputBoolean(v, o, GetCString(ctx, argv[2]));
    return JS_DupValue(ctx, this_val);
}

static JSValue JsPutSget(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
    auto* wrap = GetWrapper(ctx, this_val);
    if (!wrap || argc < 2) return JS_EXCEPTION;
    uint32_t v = 0; JS_ToUint32(ctx, &v, argv[0]);
    wrap->writer->PutSget(v, GetCString(ctx, argv[1]));
    return JS_DupValue(ctx, this_val);
}

static JSValue JsPutSput(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
    auto* wrap = GetWrapper(ctx, this_val);
    if (!wrap || argc < 2) return JS_EXCEPTION;
    uint32_t v = 0; JS_ToUint32(ctx, &v, argv[0]);
    wrap->writer->PutSput(v, GetCString(ctx, argv[1]));
    return JS_DupValue(ctx, this_val);
}

static JSValue JsPutSgetObject(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
    auto* wrap = GetWrapper(ctx, this_val);
    if (!wrap || argc < 2) return JS_EXCEPTION;
    uint32_t v = 0; JS_ToUint32(ctx, &v, argv[0]);
    wrap->writer->PutSgetObject(v, GetCString(ctx, argv[1]));
    return JS_DupValue(ctx, this_val);
}

static JSValue JsPutSputObject(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
    auto* wrap = GetWrapper(ctx, this_val);
    if (!wrap || argc < 2) return JS_EXCEPTION;
    uint32_t v = 0; JS_ToUint32(ctx, &v, argv[0]);
    wrap->writer->PutSputObject(v, GetCString(ctx, argv[1]));
    return JS_DupValue(ctx, this_val);
}

static JSValue JsPutThrow(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
    auto* wrap = GetWrapper(ctx, this_val);
    if (!wrap || argc < 1) return JS_EXCEPTION;
    uint32_t r = 0; JS_ToUint32(ctx, &r, argv[0]);
    wrap->writer->PutThrow(r);
    return JS_DupValue(ctx, this_val);
}

static JSValue JsPutNop(JSContext* ctx, JSValueConst this_val, int /*argc*/, JSValueConst* /*argv*/) {
    auto* wrap = GetWrapper(ctx, this_val);
    if (!wrap) return JS_EXCEPTION;
    wrap->writer->PutNop();
    return JS_DupValue(ctx, this_val);
}

static JSValue JsPutBinaryOpInternal(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv, dex::Opcode op) {
    auto* wrap = GetWrapper(ctx, this_val);
    if (!wrap || argc < 3) return JS_EXCEPTION;
    uint32_t d = 0, s1 = 0, s2 = 0;
    JS_ToUint32(ctx, &d, argv[0]);
    JS_ToUint32(ctx, &s1, argv[1]);
    JS_ToUint32(ctx, &s2, argv[2]);
    wrap->writer->PutBinaryOp(op, d, s1, s2);
    return JS_DupValue(ctx, this_val);
}

static JSValue JsPutAddInt(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
    return JsPutBinaryOpInternal(ctx, this_val, argc, argv, dex::OP_ADD_INT);
}
static JSValue JsPutSubInt(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
    return JsPutBinaryOpInternal(ctx, this_val, argc, argv, dex::OP_SUB_INT);
}
static JSValue JsPutMulInt(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
    return JsPutBinaryOpInternal(ctx, this_val, argc, argv, dex::OP_MUL_INT);
}
static JSValue JsPutDivInt(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
    return JsPutBinaryOpInternal(ctx, this_val, argc, argv, dex::OP_DIV_INT);
}
static JSValue JsPutRemInt(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
    return JsPutBinaryOpInternal(ctx, this_val, argc, argv, dex::OP_REM_INT);
}
static JSValue JsPutAndInt(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
    return JsPutBinaryOpInternal(ctx, this_val, argc, argv, dex::OP_AND_INT);
}
static JSValue JsPutOrInt(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
    return JsPutBinaryOpInternal(ctx, this_val, argc, argv, dex::OP_OR_INT);
}
static JSValue JsPutXorInt(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
    return JsPutBinaryOpInternal(ctx, this_val, argc, argv, dex::OP_XOR_INT);
}
static JSValue JsPutShlInt(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
    return JsPutBinaryOpInternal(ctx, this_val, argc, argv, dex::OP_SHL_INT);
}
static JSValue JsPutShrInt(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
    return JsPutBinaryOpInternal(ctx, this_val, argc, argv, dex::OP_SHR_INT);
}
static JSValue JsPutUshrInt(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
    return JsPutBinaryOpInternal(ctx, this_val, argc, argv, dex::OP_USHR_INT);
}

// Smali parser method: writer.putSmali("...")
static JSValue JsEmitSmali(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
    auto* wrap = GetWrapper(ctx, this_val);
    if (!wrap || argc < 1) return JS_EXCEPTION;
    std::string smali = GetCString(ctx, argv[0]);
    std::string error;
    if (!wrap->writer->EmitSmali(smali, &error)) {
        return JS_ThrowTypeError(ctx, "%s", error.c_str());
    }
    return JS_DupValue(ctx, this_val);
}

// Static builder: DexWriter.smali([options/signature, ]smaliText)
static JSValue JsDexWriterSmaliStatic(JSContext* ctx, JSValueConst /*this_val*/, int argc, JSValueConst* argv) {
    if (argc < 1) return JS_ThrowTypeError(ctx, "DexWriter.smali([signature, ]smaliText)");

    uint16_t totalRegs = 4;
    uint16_t ins = 1;
    uint16_t outs = 4;
    std::string smali;

    if (argc == 1) {
        smali = GetCString(ctx, argv[0]);
    } else {
        // argc >= 2
        smali = GetCString(ctx, argv[1]);
        if (JS_IsNumber(argv[0])) {
            uint32_t insVal = 1;
            JS_ToUint32(ctx, &insVal, argv[0]);
            ins = static_cast<uint16_t>(insVal);
            totalRegs = std::max<uint16_t>(ins + 2, 4);
        } else if (JS_IsString(argv[0])) {
            std::string sig = GetCString(ctx, argv[0]);
            bool isStatic = false;
            size_t start = sig.find_first_not_of(" \t\r\n");
            if (start != std::string::npos) sig = sig.substr(start);
            if (sig.rfind("static ", 0) == 0) {
                isStatic = true;
                sig = sig.substr(7);
            } else if (sig.rfind("virtual ", 0) == 0) {
                isStatic = false;
                sig = sig.substr(8);
            } else if (sig.rfind("instance ", 0) == 0) {
                isStatic = false;
                sig = sig.substr(9);
            }
            start = sig.find_first_not_of(" \t\r\n");
            if (start != std::string::npos) sig = sig.substr(start);

            std::string ret;
            std::vector<std::string> params;
            if (!PI::DexGen::ParseSignature(sig, &ret, &params)) {
                return JS_ThrowTypeError(ctx, "invalid method signature for DexWriter.smali: '%s'", sig.c_str());
            }
            ins = PI::DexGen::CalculateInsWords(params, isStatic);
            totalRegs = std::max<uint16_t>(ins + 2, 4);
        } else if (JS_IsObject(argv[0])) {
            JSValue sigVal = JS_GetPropertyStr(ctx, argv[0], "signature");
            JSValue staticVal = JS_GetPropertyStr(ctx, argv[0], "static");
            JSValue regVal = JS_GetPropertyStr(ctx, argv[0], "registers");
            JSValue insVal = JS_GetPropertyStr(ctx, argv[0], "ins");
            JSValue outsVal = JS_GetPropertyStr(ctx, argv[0], "outs");

            bool isStatic = JS_ToBool(ctx, staticVal);
            if (JS_IsString(sigVal)) {
                std::string sig = GetCString(ctx, sigVal);
                std::string ret;
                std::vector<std::string> params;
                if (!PI::DexGen::ParseSignature(sig, &ret, &params)) {
                    JS_FreeValue(ctx, sigVal);
                    JS_FreeValue(ctx, staticVal);
                    JS_FreeValue(ctx, regVal);
                    JS_FreeValue(ctx, insVal);
                    JS_FreeValue(ctx, outsVal);
                    return JS_ThrowTypeError(ctx, "invalid method signature in DexWriter options: '%s'", sig.c_str());
                }
                ins = PI::DexGen::CalculateInsWords(params, isStatic);
                totalRegs = std::max<uint16_t>(ins + 2, 4);
            }
            if (JS_IsNumber(insVal)) {
                uint32_t val = 0;
                JS_ToUint32(ctx, &val, insVal);
                ins = static_cast<uint16_t>(val);
                totalRegs = std::max<uint16_t>(ins + 2, 4);
            }
            if (JS_IsNumber(regVal)) {
                uint32_t val = 0;
                JS_ToUint32(ctx, &val, regVal);
                totalRegs = static_cast<uint16_t>(val);
            }
            if (JS_IsNumber(outsVal)) {
                uint32_t val = 0;
                JS_ToUint32(ctx, &val, outsVal);
                outs = static_cast<uint16_t>(val);
            }
            JS_FreeValue(ctx, sigVal);
            JS_FreeValue(ctx, staticVal);
            JS_FreeValue(ctx, regVal);
            JS_FreeValue(ctx, insVal);
            JS_FreeValue(ctx, outsVal);
        }
    }

    auto writer = std::make_shared<PI::DexWriter::Writer>();
    writer->SetRegisters(totalRegs, ins, outs);
    std::string error;
    if (!writer->EmitSmali(smali, &error)) {
        return JS_ThrowTypeError(ctx, "%s", error.c_str());
    }

    JSValue obj = JS_NewObjectClass(ctx, g_dexWriterClassId);
    if (JS_IsException(obj)) return obj;

    auto* wrap = new DexWriterWrapper{std::move(writer)};
    JS_SetOpaque(obj, wrap);
    return obj;
}

// Static builder: DexWriter.build((writer) => { ... })
static JSValue JsDexWriterBuildStatic(JSContext* ctx, JSValueConst /*this_val*/, int argc, JSValueConst* argv) {
    if (argc < 1 || !JS_IsFunction(ctx, argv[0])) {
        return JS_ThrowTypeError(ctx, "DexWriter.build requires a function callback: (writer) => void");
    }

    auto writer = std::make_shared<PI::DexWriter::Writer>();
    JSValue obj = CreateDexWriterObject(ctx, writer);
    if (JS_IsException(obj)) return obj;

    JSValue fn = argv[0];
    JSValue res = JS_Call(ctx, fn, JS_UNDEFINED, 1, &obj);
    if (JS_IsException(res)) {
        JS_FreeValue(ctx, obj);
        return res;
    }
    JS_FreeValue(ctx, res);
    return obj;
}

static JSValue JsGetInstructionCount(JSContext* ctx, JSValueConst this_val) {
    auto* wrap = GetWrapper(ctx, this_val);
    if (!wrap) return JS_EXCEPTION;
    return JS_NewInt32(ctx, static_cast<int32_t>(wrap->writer->GetInstructionCount()));
}

static const JSCFunctionListEntry kDexWriterProtoEntries[] = {
    JS_CFUNC_DEF("setRegisters", 1, JsSetRegisters),
    JS_CFUNC_DEF("makeLabel", 0, JsMakeLabel),
    JS_CFUNC_DEF("putLabel", 1, JsPutLabel),
    JS_CFUNC_DEF("putGoto", 1, JsPutGoto),
    JS_CFUNC_DEF("putIfEqz", 2, JsPutIfEqz),
    JS_CFUNC_DEF("putIfNez", 2, JsPutIfNez),
    JS_CFUNC_DEF("putIfLtz", 2, JsPutIfLtz),
    JS_CFUNC_DEF("putIfGez", 2, JsPutIfGez),
    JS_CFUNC_DEF("putIfGtz", 2, JsPutIfGtz),
    JS_CFUNC_DEF("putIfLez", 2, JsPutIfLez),
    JS_CFUNC_DEF("putIfEq", 3, JsPutIfEq),
    JS_CFUNC_DEF("putIfNe", 3, JsPutIfNe),
    JS_CFUNC_DEF("putIfLt", 3, JsPutIfLt),
    JS_CFUNC_DEF("putIfGe", 3, JsPutIfGe),
    JS_CFUNC_DEF("putIfGt", 3, JsPutIfGt),
    JS_CFUNC_DEF("putIfLe", 3, JsPutIfLe),
    JS_CFUNC_DEF("putConst4", 2, JsPutConst4),
    JS_CFUNC_DEF("putConst16", 2, JsPutConst16),
    JS_CFUNC_DEF("putConst", 2, JsPutConst),
    JS_CFUNC_DEF("putConstString", 2, JsPutConstString),
    JS_CFUNC_DEF("putConstClass", 2, JsPutConstClass),
    JS_CFUNC_DEF("putMove", 2, JsPutMove),
    JS_CFUNC_DEF("putMoveObject", 2, JsPutMoveObject),
    JS_CFUNC_DEF("putMoveResult", 1, JsPutMoveResult),
    JS_CFUNC_DEF("putMoveResultObject", 1, JsPutMoveResultObject),
    JS_CFUNC_DEF("putReturnVoid", 0, JsPutReturnVoid),
    JS_CFUNC_DEF("putReturn", 1, JsPutReturn),
    JS_CFUNC_DEF("putReturnObject", 1, JsPutReturnObject),
    JS_CFUNC_DEF("putInvokeVirtual", 2, JsPutInvokeVirtual),
    JS_CFUNC_DEF("putInvokeDirect", 2, JsPutInvokeDirect),
    JS_CFUNC_DEF("putInvokeStatic", 2, JsPutInvokeStatic),
    JS_CFUNC_DEF("putInvokeSuper", 2, JsPutInvokeSuper),
    JS_CFUNC_DEF("putInvokeInterface", 2, JsPutInvokeInterface),
    JS_CFUNC_DEF("putNewInstance", 2, JsPutNewInstance),
    JS_CFUNC_DEF("putCheckCast", 2, JsPutCheckCast),
    JS_CFUNC_DEF("putInstanceOf", 3, JsPutInstanceOf),
    JS_CFUNC_DEF("putIget", 3, JsPutIget),
    JS_CFUNC_DEF("putIput", 3, JsPutIput),
    JS_CFUNC_DEF("putIgetObject", 3, JsPutIgetObject),
    JS_CFUNC_DEF("putIputObject", 3, JsPutIputObject),
    JS_CFUNC_DEF("putIgetBoolean", 3, JsPutIgetBoolean),
    JS_CFUNC_DEF("putIputBoolean", 3, JsPutIputBoolean),
    JS_CFUNC_DEF("putSget", 2, JsPutSget),
    JS_CFUNC_DEF("putSput", 2, JsPutSput),
    JS_CFUNC_DEF("putSgetObject", 2, JsPutSgetObject),
    JS_CFUNC_DEF("putSputObject", 2, JsPutSputObject),
    JS_CFUNC_DEF("putAddInt", 3, JsPutAddInt),
    JS_CFUNC_DEF("putSubInt", 3, JsPutSubInt),
    JS_CFUNC_DEF("putMulInt", 3, JsPutMulInt),
    JS_CFUNC_DEF("putDivInt", 3, JsPutDivInt),
    JS_CFUNC_DEF("putRemInt", 3, JsPutRemInt),
    JS_CFUNC_DEF("putAndInt", 3, JsPutAndInt),
    JS_CFUNC_DEF("putOrInt", 3, JsPutOrInt),
    JS_CFUNC_DEF("putXorInt", 3, JsPutXorInt),
    JS_CFUNC_DEF("putShlInt", 3, JsPutShlInt),
    JS_CFUNC_DEF("putShrInt", 3, JsPutShrInt),
    JS_CFUNC_DEF("putUshrInt", 3, JsPutUshrInt),
    JS_CFUNC_DEF("putThrow", 1, JsPutThrow),
    JS_CFUNC_DEF("putNop", 0, JsPutNop),
    JS_CFUNC_DEF("putSmali", 1, JsEmitSmali),
    JS_CFUNC_DEF("emitSmali", 1, JsEmitSmali),
    JS_CGETSET_DEF("instructionCount", JsGetInstructionCount, nullptr),
};

} // namespace

PI::DexWriter::Writer* GetDexWriterInstance(JSContext* /*ctx*/, JSValueConst val) {
    if (!JS_IsObject(val)) return nullptr;
    auto* wrap = static_cast<DexWriterWrapper*>(JS_GetOpaque(val, g_dexWriterClassId));
    if (wrap == nullptr || wrap->writer == nullptr) return nullptr;
    return wrap->writer.get();
}

JSValue CreateDexWriterObject(JSContext* ctx, std::shared_ptr<PI::DexWriter::Writer> writer) {
    if (!writer) return JS_NULL;
    JSValue obj = JS_NewObjectClass(ctx, g_dexWriterClassId);
    if (JS_IsException(obj)) return obj;
    auto* wrap = new DexWriterWrapper{std::move(writer)};
    JS_SetOpaque(obj, wrap);
    return obj;
}

void ResetDexWriterClassId() {
    g_dexWriterClassId = 0;
}

void RegisterDexWriterApis(JSContext* ctx, JSValue global, JSValue java) {
    JSRuntime* rt = JS_GetRuntime(ctx);
    if (g_dexWriterClassId == 0 || !JS_IsRegisteredClass(rt, g_dexWriterClassId)) {
        g_dexWriterClassId = 0;
        JS_NewClassID(rt, &g_dexWriterClassId);
        JS_NewClass(rt, g_dexWriterClassId, &kDexWriterClassDef);
    }

    JSValue proto = JS_NewObject(ctx);
    JS_SetPropertyFunctionList(ctx, proto, kDexWriterProtoEntries,
                               sizeof(kDexWriterProtoEntries) / sizeof(kDexWriterProtoEntries[0]));
    JS_SetClassProto(ctx, g_dexWriterClassId, proto);

    JSValue ctor = JS_NewCFunction2(ctx, JsDexWriterCtor, "DexWriter", 1, JS_CFUNC_constructor, 0);
    JS_SetConstructor(ctx, ctor, proto);

    // Static helper: DexWriter.smali("...")
    JS_SetPropertyStr(ctx, ctor, "smali",
                      JS_NewCFunction(ctx, JsDexWriterSmaliStatic, "smali", 1));

    // Static helper: DexWriter.build((w) => { ... })
    JS_SetPropertyStr(ctx, ctor, "build",
                      JS_NewCFunction(ctx, JsDexWriterBuildStatic, "build", 1));

    // Expose both as global `DexWriter` and `Java.DexWriter`
    JS_SetPropertyStr(ctx, global, "DexWriter", JS_DupValue(ctx, ctor));
    if (JS_IsObject(java)) {
        JS_SetPropertyStr(ctx, java, "DexWriter", JS_DupValue(ctx, ctor));
    }
    JS_FreeValue(ctx, ctor);
}

}} // namespace artpi::agent
