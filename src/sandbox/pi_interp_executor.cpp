//
// pi_interp_executor.cpp - interpreter main scheduler implementation
//
// Implements the sandbox guarantees from OPTIMIZATION_AND_ARCHITECTURE_V2.md
// §1 (AAPCS arg mapping), §2 (JNI local-ref frames), §5 (pre-scan + guards),
// §6 (invokeInterpreted API backend).
//

#include "pi_interp_executor.h"
#include "pi_code_provider.h"
#include "pi_resolver_bridge.h"
#include "pi_interp_tracer.h"
#include "dex/pi_smali.h"
#include "art/art_method.h"

#include <cstring>
#include <map>
#include <memory>
#include <mutex>
#include <vector>

// engine-side ART<->JNI handle converters (engine/pine/pine_native.h also
// pulls in the public ArtPI.h which we cannot include here - see below)
extern "C" jobject PineNative_ToJObject(JNIEnv* env, void* art_obj);
extern "C" void*    PineNative_ToArtObject(JNIEnv* env, jobject j_obj);

// CallFrame lives in the public header; we define the added member here.
#include "ArtPI.h"
#include "pi_unified_tracer.h"
#include "hooker/pi_jni_sniffer.h"
#include "art/thread.h"

// ============================================================================
// route-2': synthetic self-terminating "fake native frame"
// ----------------------------------------------------------------------------
// Pine's trampoline overwrites the hooked method's would-be frame with its
// PineNativeContext, and top_quick_frame_ (thread+0xa8) points there -> ART's
// GC walker reads it as an ArtMethod and SEGVs. For the duration of nmmvm we
// replace the thread's managed_stack_.top_quick_frame_ with our own buffer that
// looks like a *native* frame:
//   buf[0] = a private (kNative-marked) COPY of the ArtMethod, tagged -> header
//   == null; zeros everywhere else -> visit-refs are null, and
//   *(buf+frame_size)==0 so WalkStack terminates cleanly. The linked fragment
//   below is empty, so no caller frames are lost.
// The real ArtMethod is left untouched (runMethodInternal still interprets it).
// ManagedStack layout: {top_quick_frame_@0(bit0=tag), link_@8, top_shadow_frame_@0x10}.
namespace {
// Thread::managed_stack_ (tlsPtr_) byte offset. art::Thread is a pure C++ class
// with no stable ABI, so the offset varies by version/arch. Verified 0xa8 on
// Android 12/13 arm64; other versions use the known table below.
static size_t ManagedStackOffset() {
#if defined(__aarch64__)
    const int v = pine::Android::version;
    if (v >= pine::Android::kS) return 0xa8;   // Android 12..15
    if (v >= pine::Android::kQ) return 0xa0;   // Android 10..11
    if (v >= pine::Android::kO) return 0x98;   // Android 8..9
    return 0x90;                               // Android 7
#else
    return 0x58;                               // 32-bit baseline
#endif
}

struct FakeNativeFrame {
    unsigned long long buf[0x80];        // 0x400-byte scratch frame (zeroed)
    unsigned char mcopy[0x40];           // private copy of the ArtMethod
    unsigned char* thread = nullptr;
    unsigned long long savedQuick = 0;
    bool active = false;

    void enter(JNIEnv* env, pine::art::ArtMethod* m) {
        thread = reinterpret_cast<unsigned char*>(pine::art::Thread::Current(env));
        if (thread == nullptr || m == nullptr) return;
        for (auto& w : buf) w = 0ULL;
        std::memcpy(mcopy, m, sizeof(mcopy));
        *reinterpret_cast<uint32_t*>(mcopy + 4) |= 0x100u;   // AccessFlags::kNative
        buf[0] = reinterpret_cast<unsigned long long>(mcopy);
        auto* ms = reinterpret_cast<unsigned long long*>(thread + ManagedStackOffset());
        savedQuick = ms[0];
        ms[0] = reinterpret_cast<unsigned long long>(buf) | 1ULL;  // tagged native frame
        active = true;
        PI_LOGI("FAKEFRM enter target=%p copy=%p buf=%p old.quick=%p",
                (void*)m, (void*)mcopy, (void*)buf, (void*)savedQuick);
    }

    void leave() {
        if (!active) return;
        auto* ms = reinterpret_cast<unsigned long long*>(thread + ManagedStackOffset());
        ms[0] = savedQuick;
        active = false;
    }
};

// route-3: ManagedStack boundary (legal JNI-transition fragment).
// Pine's trampoline left a BOGUS head fragment (top_quick_frame_ -> PineNativeContext,
// which ART would read as an ArtMethod). We push an empty fragment that links to
// what the bogus head linked to, i.e. we SKIP the bogus frame and expose the real
// caller chain (the old head's link_ / shadow frame). While nmmvm runs, any JNI
// call pushes a legal fragment on top of ours; WalkStack then walks that, hits our
// empty fragment (top_quick_frame_==nullptr), and follows link_ to the real caller.
// ManagedStack {top_quick_frame_@0, link_@8, top_shadow_frame_@0x10} @ thread+tlsPtr.
struct ScopedManagedStackBoundary {
    unsigned char* thread = nullptr;
    unsigned long long saved[3] = {0, 0, 0};   // saved old (bogus) head, for restore
    bool active = false;
    int depth = 0;                             // re-entrancy telemetry (LIFO)
    inline static thread_local int s_depth = 0;
    inline static thread_local const ScopedManagedStackBoundary* s_current = nullptr;
    const ScopedManagedStackBoundary* prev = nullptr;

    explicit ScopedManagedStackBoundary(JNIEnv* env) { enter(env); }
    ~ScopedManagedStackBoundary() { leave(); }
    ScopedManagedStackBoundary(const ScopedManagedStackBoundary&) = delete;
    ScopedManagedStackBoundary& operator=(const ScopedManagedStackBoundary&) = delete;

    void enter(JNIEnv* env) {
        prev = s_current;
        s_current = this;
        thread = reinterpret_cast<unsigned char*>(pine::art::Thread::Current(env));
        if (thread == nullptr) return;
        auto* ms = reinterpret_cast<unsigned long long*>(thread + ManagedStackOffset());
        saved[0] = ms[0]; saved[1] = ms[1]; saved[2] = ms[2];
        // New top fragment: empty quick, keep the real shadow chain, and link to
        // the OLD head's link (skip the bogus Pine quick frame).
        ms[0] = 0;            // top_quick_frame_  = nullptr
        ms[2] = saved[2];     // top_shadow_frame_ = old shadow (usually nullptr)
        ms[1] = saved[1];     // link_ = old head's link -> real caller fragments
        active = true;
        depth = ++s_depth;
        PI_LOGI("MSBOUND enter depth=%d old={quick=%p link=%p shadow=%p}",
                depth, (void*)saved[0], (void*)saved[1], (void*)saved[2]);
    }

    void leave() {
        s_current = prev;
        if (!active || thread == nullptr) return;
        auto* ms = reinterpret_cast<unsigned long long*>(thread + ManagedStackOffset());
        ms[0] = saved[0]; ms[1] = saved[1]; ms[2] = saved[2];
        active = false;
        --s_depth;
    }
};
}  // namespace

namespace PI { namespace Interp {

bool getManagedStackSnapshot(ManagedStackSnapshot& out) {
    if (!ScopedManagedStackBoundary::s_current || !ScopedManagedStackBoundary::s_current->active) {
        return false;
    }
    const auto* b = ScopedManagedStackBoundary::s_current;
    out.thread = b->thread;
    out.topQuickFrame = b->saved[0];
    out.link = b->saved[1];
    out.topShadowFrame = b->saved[2];
    out.managedStackOffset = ManagedStackOffset();
    return true;
}

// ============================================================================
// shorty helpers
// ============================================================================
bool shortyFromSignature(const std::string& sig, std::string& out) {
    out.clear();
    size_t rparen = sig.find(')');
    if (sig.empty() || sig[0] != '(' || rparen == std::string::npos) return false;

    auto typeChar = [](char c) { return c == 'J' || c == 'D' ? c : 'I'; };

    // return type
    if (rparen + 1 >= sig.size()) return false;
    char ret = sig[rparen + 1];
    if (ret == 'L' || ret == '[') out += 'L';
    else out += ret;

    // parameters
    size_t i = 1;
    while (i < rparen) {
        char c = sig[i];
        if (c == '[') {
            // array: one 'L' shorty char regardless of element type
            out += 'L';
            while (i < rparen && sig[i] == '[') i++;
            if (i < rparen && sig[i] == 'L') {
                while (i < rparen && sig[i] != ';') i++;
            }
            i++;  // skip element char or ';'
            continue;
        }
        if (c == 'L') {
            out += 'L';
            while (i < rparen && sig[i] != ';') i++;
            i++;
            continue;
        }
        out += typeChar(c);
        i++;
    }
    return true;
}

// ============================================================================
// per-dex bridge registry (caches jmethodID/jfieldID/class/string globals)
// ============================================================================
namespace {

std::shared_ptr<ResolverBridge> acquireBridge(const DexResolver& dex) {
    static std::mutex regMutex;
    struct DexEntry {
        std::shared_ptr<DexResolver> resolver;   // keeps dex_ alive!
        std::shared_ptr<ResolverBridge> bridge;
    };
    static std::map<const void*, std::shared_ptr<DexEntry>> registry;

    const void* key = dex.getDexFile();
    std::lock_guard<std::mutex> lock(regMutex);
    auto it = registry.find(key);
    if (it != registry.end()) return it->second->bridge;

    // Keep a heap copy of the resolver: the bridge's lazy resolution
    // dereferences it long after this call's stack is gone. The entry owns
    // BOTH, otherwise the resolver would be freed here and the bridge's
    // dex_ pointer would dangle.
    auto entry = std::make_shared<DexEntry>();
    entry->resolver = std::make_shared<DexResolver>(dex);
    entry->bridge = std::make_shared<ResolverBridge>();
    if (!entry->bridge->init(entry->resolver.get())) return nullptr;
    registry[key] = entry;
    return entry->bridge;
}

// pack params (and receiver) into the tail registers of the frame
bool packRegisters(JNIEnv* env, InterpCode& ic, bool isStatic, jobject thisObj,
                   const jvalue* args, const char* shorty) {
    // compute expected slot usage and validate layout before writing
    int need = isStatic ? 0 : 1;
    for (const char* c = shorty + 1; *c; ++c) need += (*c == 'J' || *c == 'D') ? 2 : 1;
    if (need != ic.insSize) {
        PI_LOGE("SmaliRunner: shorty needs %d ins slots but code_item says %u",
                need, ic.insSize);
        return false;
    }
    if (ic.insSize > ic.registersSize) return false;

    int slot = ic.registersSize - ic.insSize;
    auto putSlot = [&](int s, regptr_t v, bool obj) {
        ic.regs[s] = v;
        ic.regFlags[s] = obj ? 1 : 0;
    };
    // The interpreter owns a local ref for every object slot (created inside
    // the caller's PushLocalFrame), so its DELETE_LOCAL_REF is valid.
    auto own = [&](jobject o) -> jobject { return (env && o) ? env->NewLocalRef(o) : nullptr; };

    if (!isStatic) putSlot(slot++, (regptr_t) own(thisObj), true);

    for (const char* c = shorty + 1; *c; ++c, ++args) {
        switch (*c) {
            case 'J':
                putSlot(slot, (regptr_t) (uint64_t) args->j, false);
                slot += 2;  // second wide slot stays zero
                break;
            case 'D': {
                regptr_t v;
                std::memcpy(&v, &args->d, 8);
                putSlot(slot, v, false);
                slot += 2;
                break;
            }
            case 'F': {
                uint32_t bits;
                std::memcpy(&bits, &args->f, 4);
                putSlot(slot, (regptr_t) bits, false);
                slot += 1;
                break;
            }
            case 'L':
                putSlot(slot, (regptr_t) own(args->l), true);
                slot += 1;
                break;
            default:  // I / S / B / C / Z
                putSlot(slot, (regptr_t) (uint32_t) args->i, false);
                slot += 1;
                break;
        }
    }
    return true;
}

void unpackResult(RunResult& r, const jvalue& rv, char retChar) {
    switch (retChar) {
        case 'V':
            r.isVoid = true;
            break;
        case 'J':
            r.isVoid = false; r.isWide = true;
            r.value.j = rv.j;
            break;
        case 'D':
            r.isVoid = false; r.isWide = true;
            std::memcpy(&r.value.d, &rv.d, 8);
            break;
        case 'F':
            r.isVoid = false;
            r.value.f = rv.f;
            break;
        case 'L': case '[':
            r.isVoid = false; r.isObject = true;
            r.objectResult = rv.l;
            break;
        default:  // I / S / B / C / Z
            r.isVoid = false;
            r.value.i = rv.i;
            break;
    }
}

// ===========================================================================
// §5: bytecode pre-scan — reject unsupported Dalvik opcodes before running
// ===========================================================================
bool prescanInsns(const uint16_t* insns, uint32_t size) {
    const uint8_t* sizes = PI::instructionSizeTable();
    if (insns == nullptr || sizes == nullptr) return false;

    uint32_t pc = 0;
    while (pc < size) {
        uint16_t u = insns[pc];
        uint8_t op = static_cast<uint8_t>(u & 0xFF);

        // payload pseudo-instructions (packed-switch / sparse-switch / array-data)
        if (op == 0x00 && u != 0x0000) {
            if (u == 0x0100) { pc += 4 + 2u * insns[pc + 1]; continue; }
            if (u == 0x0200) { pc += 2 + 4u * insns[pc + 1]; continue; }
            if (u == 0x0300) {
                uint32_t elemCount =
                    static_cast<uint32_t>(insns[pc + 2]) |
                    (static_cast<uint32_t>(insns[pc + 3]) << 16);
                pc += 4 + (elemCount * insns[pc + 1] + 1) / 2;
                continue;
            }
            return false;   // nop-nop-streams are not expected
        }

        // reject unimplemented opcodes (invoke-polymorphic/custom & beyond)
        if (op >= 0xE3) return false;

        uint8_t sz = sizes[op];
        if (sz == 0) return false;
        pc += sz;
        if (pc > size) return false;
    }
    return pc == size;
}

} // namespace

// ===========================================================================
// core session runner
// ===========================================================================
namespace {
    constexpr int kHardMaxDepth = 64;   // C-stack guard for StepIn recursion
}

RunResult runMethodInternal(JNIEnv* env, ArtMethod* method, jobject thisObj,
                            const jvalue* args, const char* shorty,
                            const Callbacks* cbs, const Options* opts,
                            const FilterOptions* filter, int depth,
                            const char* label) {
    RunResult result;

    if (env == nullptr || method == nullptr || shorty == nullptr || shorty[0] == '\0') {
        result.status = RunResult::ERROR;
        return result;
    }
    if (env->ExceptionCheck()) {
        // a pending exception would abort resolver JNI calls under CheckJNI
        result.status = RunResult::ERROR;
        result.exceptionPending = true;
        return result;
    }
    if (depth >= kHardMaxDepth) {
        PI_LOGE("InterpExecutor: hard depth limit %d reached", kHardMaxDepth);
        result.status = RunResult::ERROR;
        return result;
    }
    if (method->IsNative() || method->HasAccessFlags(0x0400)) {
        result.status = RunResult::NO_CODE;
        return result;
    }

    // L1: dex + code item
    DexResolver dex;
    if (!dex.initFromMethod(method)) {
        result.status = RunResult::RESOLVE_FAIL;
        return result;
    }

    InterpCode ic;
    if (!buildVmCode(env, method, dex, ic)) {
        result.status = RunResult::RESOLVE_FAIL;
        return result;
    }

    // §5: pre-scan — refuse to run methods with unsupported instructions
    if (!prescanInsns(ic.code.insns, ic.insnsCount)) {
        PI_LOGW("InterpExecutor: prescan rejected method (unsupported opcode)");
        result.status = RunResult::UNSUPPORTED;
        return result;
    }

    // §2: local-ref scoping — push BEFORE packing so the interpreter owns a
    // local ref for every object slot (this/args). Its per-register overwrite
    // DeleteLocalRef (DELETE_LOCAL_REF) is then valid; deleting borrowed refs
    // from the caller's local frame was the crash.
    if (env->PushLocalFrame(512) < 0) {
        result.status = RunResult::ERROR;   // OOM pending
        result.exceptionPending = true;
        return result;
    }

    // L3: pack args (owns a local ref for each object slot)
    if (!packRegisters(env, ic, method->IsStatic(), thisObj, args, shorty)) {
        env->PopLocalFrame(nullptr);
        result.status = RunResult::PACK_FAIL;
        return result;
    }

    // L2: resolver bridge (per-dex cache) as the thread's active bridge
    auto bridge = acquireBridge(dex);
    if (!bridge || !bridge->isInitialized()) {
        env->PopLocalFrame(nullptr);
        result.status = RunResult::RESOLVE_FAIL;
        return result;
    }

    // sandbox session wiring (§3/§4)
    bool withTracer = detail::hasActiveCallbacks(cbs);
    void* sess = nullptr;
    void* fctx = nullptr;
    if (withTracer) {
        sess = detail::makeSession(env, (const void*) bridge->dex(), cbs, opts, filter,
                                   depth, method);
        if (sess != nullptr && opts != nullptr) {
            detail::setSessionListener(sess, opts->unified_listener);
        }
        fctx = detail::makeFrameCtx(sess, (const void*) &ic.code, depth);
    }
    detail::pushFrame(fctx, method);

    ResolverBridge::ScopedActive active(bridge.get());

    // per-instruction logcat trace (only while enabled; reentrancy-safe)
    char labelBuf[72];
    if (label == nullptr || label[0] == '\0') {
        snprintf(labelBuf, sizeof(labelBuf), "ArtMethod@%p", (void*) method);
        label = labelBuf;
    }
    bool forceLog = (opts != nullptr && opts->log_instructions);
    TraceGuard traceGuard(env, dex.getDexFile(), ic.code.insns,
                          ic.registersSize, &dex, label, forceLog);

    jvalue rv = ::vmInterpret2(env, &ic.code, bridge->nativeResolver(),
                               static_cast<VmFrameCtx*>(fctx));

    bool hasExc = env->ExceptionCheck() != JNI_FALSE;

    // promote object returns out of the dying local frame
    jobject promoted = nullptr;
    if (!hasExc && (shorty[0] == 'L' || shorty[0] == '[')) {
        promoted = env->PopLocalFrame(rv.l);
        rv.l = promoted;
    } else {
        env->PopLocalFrame(nullptr);
    }

    detail::popFrame();
    bool aborted = detail::sessionAborted(sess);
    bool handoff = detail::sessionHandoff(sess);
    detail::destroyFrameCtx(fctx);
    detail::destroySession(sess);

    if (hasExc) {
        result.exceptionPending = true;  // uncaught inside the interpreter
    }
    result.status = aborted ? RunResult::ABORTED : RunResult::OK;
    result.handoff = handoff;
    unpackResult(result, rv, shorty[0]);
    return result;
}

RunResult runMethod(JNIEnv* env, ArtMethod* method, jobject thisObj,
                    const jvalue* args, const char* shorty) {
    return runMethodInternal(env, method, thisObj, args, shorty,
                             nullptr, nullptr, nullptr, 0);
}

// ===========================================================================
// runtime init + trace switch
// ===========================================================================
bool init(JNIEnv* env) {
    return interpRuntimeInit(env);
}

// ===========================================================================
// CallFrame integration (§1/§6): Dalvik VM execution of the hooked method
// ===========================================================================
namespace {

// ARM64 AAPCS mapping: x0 = ArtMethod*, x1 = this (instance) / arg0 (static);
// d0-d7 are allocated INDEPENDENTLY for float/double; spill goes to the stack.
struct ArgLoc {
    enum Kind { XReg, DReg, Stack } kind;
    int slot;
};

std::vector<ArgLoc> mapCallFrameArgs(const pine_native::CallFrame& frame) {
    std::vector<ArgLoc> locs;
    int xr = frame.is_static ? 1 : 2;
    int dr = 0;
    int st = 0;
    for (const auto& t : frame.arg_types) {
        char c = t.empty() ? 'I' : t[0];
        if (c == 'F' || c == 'D') {
            if (dr < 8) locs.push_back({ArgLoc::DReg, dr++});
            else        locs.push_back({ArgLoc::Stack, st++});
        } else {
            if (xr <= 7) locs.push_back({ArgLoc::XReg, xr++});
            else         locs.push_back({ArgLoc::Stack, st++});
        }
    }
    return locs;
}

uint64_t readArgRaw(const pine_native::CallFrame& f, const ArgLoc& l) {
    switch (l.kind) {
        case ArgLoc::XReg:
            return f.ctx->r[l.slot];
        case ArgLoc::DReg: {
            double d = f.ctx->d[l.slot];
            uint64_t u;
            std::memcpy(&u, &d, 8);
            return u;
        }
        case ArgLoc::Stack:
        default: {
            // The public ArtPI.h PineNativeContext lacks the trailing `sp`
            // field; the dispatcher-provided object is the full layout
            // (r[31], d[32], sp) - probe it with a prefix-compatible mirror.
            struct CtxWithSp { uint64_t r[31]; double d[32]; uint64_t sp; };
            const auto* full = reinterpret_cast<const CtxWithSp*>(f.ctx);
            return reinterpret_cast<const uint64_t*>(full->sp)[l.slot];
        }
    }
}

// one jvalue per parameter, locations resolved through AAPCS
std::vector<jvalue> collectCallFrameArgs(const pine_native::CallFrame& frame) {
    std::vector<ArgLoc> locs = mapCallFrameArgs(frame);
    std::vector<jvalue> out(static_cast<size_t>(frame.arg_count));
    for (int i = 0; i < frame.arg_count && i < static_cast<int>(locs.size()); i++) {
        jvalue jv{};
        jv.j = 0;
        const std::string& t = frame.arg_types[static_cast<size_t>(i)];
        char c = t.empty() ? 'I' : t[0];
        if (c == 'L' || c == '[') {
            // object args live as raw ART pointers in the context
            jv.l = PineNative_ToJObject(frame.env,
                                        reinterpret_cast<void*>(readArgRaw(frame, locs[static_cast<size_t>(i)])));
        } else {
            uint64_t raw = readArgRaw(frame, locs[static_cast<size_t>(i)]);
            switch (c) {
                case 'D': std::memcpy(&jv.d, &raw, 8); break;
                case 'F': {
                    uint32_t bits = static_cast<uint32_t>(raw & 0xffffffffu);
                    std::memcpy(&jv.f, &bits, 4);
                    break;
                }
                case 'J': jv.j = static_cast<jlong>(raw); break;
                case 'Z': jv.z = static_cast<jboolean>(raw); break;
                case 'C': jv.c = static_cast<jchar>(raw); break;
                case 'B': jv.b = static_cast<jbyte>(raw); break;
                case 'S': jv.s = static_cast<jshort>(raw); break;
                default:  jv.i = static_cast<jint>(raw); break;
            }
        }
        out[static_cast<size_t>(i)] = jv;
    }
    return out;
}

} // namespace

}} // namespace PI::Interp

// ============================================================================
// §6/§7.2: invokeTrace(preset) — 开箱即用预设模式
//   METHOD_ONLY       : 方法调用树 (业务方法递归展开, 系统类黑盒 Step-Over)
//   INSTRUCTION_DIFF  : 方法树 + 逐指令 PI_VMTrace 日志 (log_instructions)
//   FULL_STACK_NATIVE : [预留] QBDI/Dobby 桥接未接入, 暂退化为 METHOD_ONLY
// ============================================================================
namespace pine_native {

jvalue CallFrame::invokeTraceInternal(PI::Trace::TracePreset preset) {
    jvalue ret{};

    if (env == nullptr || target_method == nullptr) return ret;

    // route-3: cover the WHOLE hook body (arg formatting + nmmvm) with a legal
    // ManagedStack transition fragment, so any JNI call here walks safely.
    ScopedManagedStackBoundary msbound(env);

    std::string shorty;
    if (!PI::Interp::shortyFromSignature(signature, shorty)) {
        PI_LOGE("invokeTrace: cannot parse signature '%s'", signature.c_str());
        return ret;
    }

    // 预设 -> 内建策略
    PI::Interp::Callbacks cbs;
    PI::Interp::Options opts;
    opts.step_in_enabled = true;      // 业务方法递归展开
    opts.safe_handoff = false;        // default OFF (ManagedStack boundary handles the crash)
    opts.log_instructions = (preset == PI::Trace::TracePreset::INSTRUCTION_DIFF);
    if (preset == PI::Trace::TracePreset::FULL_STACK_NATIVE) {
        opts.step_in_enabled = true;
        opts.enable_native_step_in = true;   // NATIVE SPEC §4.3: Native 步入 QBDI
        opts.log_instructions = true;        // NATIVE SPEC §4.4: 逐指令 Smali/ARM64 追踪
        PI::Native::initNativeEngine(env);   // gum init + RegisterNatives 嗅探
        PI::Trace::setupFullStackNativeCallbacks(0);
    }

    auto FormatTraceTreePrefix = [](int depth, bool isEntry) -> std::string {
        if (depth <= 0) {
            return isEntry ? "┌── " : "└── ";
        }
        std::string prefix;
        prefix.reserve(static_cast<size_t>((depth + 1) * 4));
        for (int i = 0; i < depth; i++) {
            prefix += "│   ";
        }
        prefix += isEntry ? "├── " : "└── ";
        return prefix;
    };

    cbs.onInvoke = [preset, FormatTraceTreePrefix](const PI::Interp::InvokeEvent& e, jvalue*) {
        if (PI::Interp::isSystemDescriptor(e.className)) {
            return PI::Interp::InvokeVerdict::JniDirect;   // 系统层黑盒透传
        }
        PI::Trace::UnifiedCallDepth::set(e.depth + 1);

        if (e.isNative) {
            if (preset == PI::Trace::TracePreset::FULL_STACK_NATIVE) {
                PI::Native::NativeMethodBinding b;
                void* fn = PI::Native::RegisterNativesSniffer::findBinding(e.className, e.methodName, e.signature);
                std::string targetInfo;
                if (fn != nullptr && PI::Native::RegisterNativesSniffer::isRegisteredNative(fn, &b)) {
                    char buf[256];
                    snprintf(buf, sizeof(buf), "%s!%s (%p) [动态注册命中]",
                             b.moduleName.c_str(), b.methodName.c_str(), fn);
                    targetInfo = buf;
                } else {
                    targetInfo = e.formatMethod();
                }
                PI::Logger::log(PI::LogLevel::TRACE, "PI_CallTree", "%s[Native JNI] %s",
                                FormatTraceTreePrefix(e.depth + 1, true).c_str(), targetInfo.c_str());
                return PI::Interp::InvokeVerdict::StepIn;
            }
            return PI::Interp::InvokeVerdict::JniDirect;
        }
        PI::Logger::log(PI::LogLevel::TRACE, "PI_CallTree", "%s%s",
                        FormatTraceTreePrefix(e.depth + 1, true).c_str(), e.formatMethod().c_str());
        return PI::Interp::InvokeVerdict::StepIn;
    };
    cbs.onInvokePost = [preset, FormatTraceTreePrefix](const PI::Interp::InvokeEvent& e,
                                const jvalue* r, bool hasExc) {
        if (PI::Interp::isSystemDescriptor(e.className)) return;
        if (e.isNative) {
            if (preset == PI::Trace::TracePreset::FULL_STACK_NATIVE) {
                PI::Logger::log(PI::LogLevel::TRACE, "PI_CallTree", "%s[Native JNI] %s() = %s",
                                FormatTraceTreePrefix(e.depth + 1, false).c_str(), e.methodName.c_str(),
                                e.formatResult(r, hasExc).c_str());
            }
            PI::Trace::UnifiedCallDepth::set(e.depth);
            return;
        }
        PI::Logger::log(PI::LogLevel::TRACE, "PI_CallTree", "%s%s() = %s",
                        FormatTraceTreePrefix(e.depth + 1, false).c_str(), e.methodName.c_str(),
                        e.formatResult(r, hasExc).c_str());
        PI::Trace::UnifiedCallDepth::set(e.depth);
    };

    std::vector<jvalue> jargs = PI::Interp::collectCallFrameArgs(*this);
    if (static_cast<int>(jargs.size()) != arg_count) {
        PI_LOGE("invokeTrace: arg mapping failed for %s", getMethodToString().c_str());
        if (preset == PI::Trace::TracePreset::FULL_STACK_NATIVE) {
            PI::Trace::cleanupFullStackNativeCallbacks();
        }
        return ret;
    }

    auto am = reinterpret_cast<PI::ArtMethod*>(target_method);
    jobject thiz = is_static ? nullptr : getThisObject();

    std::string rootArgsStr = "(";
    bool hasArg = false;
    if (!is_static && thiz != nullptr) {
        rootArgsStr += "this=" + PI::Interp::FormatObjectNative(env, thiz);
        hasArg = true;
    }
    for (int i = 0; i < arg_count; i++) {
        if (hasArg) rootArgsStr += ", ";
        rootArgsStr += getArgString(i);
        hasArg = true;
    }
    rootArgsStr += ")";

    PI::Logger::log(PI::LogLevel::TRACE, "PI_CallTree", "┌── %s%s%s%s",
                    class_name.c_str(), class_name.empty() ? "" : ".",
                    method_name.c_str(), rootArgsStr.c_str());
    PI::Trace::UnifiedCallDepth::set(0);

    PI::Interp::RunResult res = PI::Interp::runMethodInternal(
            env, am, thiz, arg_count > 0 ? jargs.data() : nullptr, shorty.c_str(),
            &cbs, &opts, nullptr, 0, method_name.c_str());

    if (res.status == PI::Interp::RunResult::ABORTED && res.handoff) {
        // safe_handoff: the interpreter bailed at the first JNI/allocation
        // opcode. Run the real method natively (this also avoids the GC /
        // managed-stack-walk crash caused by nmmvm's non-ART frames).
        if (preset == PI::Trace::TracePreset::FULL_STACK_NATIVE) {
            PI::Trace::cleanupFullStackNativeCallbacks();
        }
        PI::Logger::log(PI::LogLevel::TRACE, "PI_CallTree",
                        "│   (handoff -> native) %s", getMethodToString().c_str());
        // Hand back to real native execution with the ORIGINAL managed-stack state
        // (release the boundary first; the RAII dtor then becomes a no-op).
        msbound.leave();
        invokeOriginalInternal();
        if (return_type == 'V') {
            /* void */
        } else if (shorty[0] == 'L' || shorty[0] == '[') {
            ret.l = reinterpret_cast<jobject>(ctx->r[0]);
        } else {
            ret.j = static_cast<jlong>(ctx->r[0]);
        }
        return ret;
    }

    std::string retStr;
    if (res.status == PI::Interp::RunResult::OK && !res.exceptionPending) {
        if (res.isVoid) retStr = "void";
        else if (res.isObject) {
            jobject o = res.objectResult;
            // pure-native rendering (no toString → no Java on the interp path)
            retStr = (o && env) ? PI::Interp::FormatObjectNative(env, o) : "null";
        } else {
            switch (return_type) {
                case 'J': retStr = std::to_string(res.value.j); break;
                case 'Z': retStr = res.value.z ? "true" : "false"; break;
                case 'F': retStr = std::to_string(res.value.f); break;
                case 'D': retStr = std::to_string(res.value.d); break;
                default:  retStr = std::to_string(res.value.i); break;
            }
        }
    } else {
        retStr = "<error>";
    }
    PI::Logger::log(PI::LogLevel::TRACE, "PI_CallTree", "└── %s%s%s() = %s",
                    class_name.c_str(), class_name.empty() ? "" : ".",
                    method_name.c_str(), retStr.c_str());
    PI::Trace::UnifiedCallDepth::set(0);

    if (preset == PI::Trace::TracePreset::FULL_STACK_NATIVE) {
        PI::Trace::cleanupFullStackNativeCallbacks();
    }

    if (res.status != PI::Interp::RunResult::OK) {
        PI_LOGE("invokeTrace: interpreter failed, status=%d (%s)",
                res.status, getMethodToString().c_str());
        return ret;
    }
    if (res.exceptionPending) return ret;

    if (res.isObject) {
        setResult(res.objectResult);
    } else if (!res.isVoid) {
        if (return_type == 'D') {
            std::memcpy(&ctx->r[0], &res.value.d, 8);
        } else if (return_type == 'F') {
            uint32_t bits;
            std::memcpy(&bits, &res.value.f, 4);
            ctx->r[0] = static_cast<uint64_t>(bits);
        } else {
            ctx->r[0] = static_cast<uint64_t>(res.value.j);
        }
        has_custom_result = true;
    } else {
        has_custom_result = true;
    }
    return ret;
}

} // namespace pine_native

// ============================================================================
// CallFrame integration: interpret the method body instead of calling it
// ============================================================================
namespace pine_native {

jvalue CallFrame::invokeInterpreterInternal(const PI::Interp::Callbacks* cbs,
                                            const PI::Interp::Options* opts) {
    jvalue ret{};

    if (env == nullptr || target_method == nullptr) return ret;

    // route-3: cover the whole hook body with a legal ManagedStack transition frame
    ScopedManagedStackBoundary msbound(env);

    // 1. shorty from the method signature
    std::string shorty;
    if (!PI::Interp::shortyFromSignature(signature, shorty)) {
        PI_LOGE("invokeInterpreted: cannot parse signature '%s'", signature.c_str());
        return ret;
    }

    // 2. jvalue args resolved through the AAPCS location map
    std::vector<jvalue> jargs = PI::Interp::collectCallFrameArgs(*this);
    if (static_cast<int>(jargs.size()) != arg_count) {
        PI_LOGE("invokeInterpreted: arg mapping failed for %s",
                getMethodToString().c_str());
        return ret;
    }

    // 3. run
    auto am = reinterpret_cast<PI::ArtMethod*>(target_method);
    jobject thiz = is_static ? nullptr : getThisObject();

    // route-3: (covered by the ScopedManagedStackBoundary at function entry)
    PI::Interp::RunResult res = PI::Interp::runMethodInternal(
            env, am, thiz, arg_count > 0 ? jargs.data() : nullptr, shorty.c_str(),
            cbs, opts, nullptr, 0);

    if (res.status != PI::Interp::RunResult::OK) {
        PI_LOGE("invokeInterpreted: interpreter failed, status=%d (%s)",
                res.status, getMethodToString().c_str());
        return ret;
    }

    // 4. propagate result (or leave a pending exception untouched)
    if (res.exceptionPending) {
        // Java exception is already pending on env; returning from the hook
        // callback lets Pine propagate it naturally.
        return ret;
    }

    if (res.isObject) {
        setResult(res.objectResult);
    } else if (!res.isVoid) {
        if (return_type == 'D') {
            std::memcpy(&ctx->r[0], &res.value.d, 8);
        } else if (return_type == 'F') {
            uint32_t bits;
            std::memcpy(&bits, &res.value.f, 4);
            ctx->r[0] = static_cast<uint64_t>(bits);
        } else {
            ctx->r[0] = static_cast<uint64_t>(res.value.j);  // I S B C Z J
        }
        has_custom_result = true;
    } else {
        has_custom_result = true;  // void
    }
    return ret;
}

} // namespace pine_native
