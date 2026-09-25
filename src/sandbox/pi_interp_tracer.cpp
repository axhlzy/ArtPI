//
// pi_interp_tracer.cpp - Callbacks/StepIn/Mock bridge over nmmvm VmTracer
//

#include "pi_interp_tracer.h"
#include "pi_interp_executor.h"
#include "../../native/hooker/pi_jni_sniffer.h"
#include "../../tracer/unified/pi_jni_bridge.h"
#include "../../tracer/unified/pi_unified_tracer.h"
#include "art/art_method.h"
#include "art/thread.h"
#include "dex/pi_smali.h"
#include "xdl.h"
#include "vm.h"
#include "VmTracer.h"
#include "pine_native.h"
#include <cstring>
#include <mutex>
#include <string>
#include <unordered_map>

namespace PI { namespace Interp {

// ============================================================================
// class-ref cache: the interpreter must resolve referenced classes WITHOUT
// env->FindClass() on the hook path (frameless -> StackVisitor::WalkStack
// SIGSEGV). Warm it at eval time via RegisterClassRef (e.g. Java.prepare);
// an app ClassLoader (loadClass runs as a managed frame -> hook-path safe) is
// used as the fallback, so trace/unified work without preparing every class.
// ============================================================================
static std::mutex g_clsCacheMutex;
static std::unordered_map<std::string, jclass> g_clsCache;
static jobject   g_appLoader = nullptr;     // global ref to the app ClassLoader
static jmethodID g_loadClassMid = nullptr;  // ClassLoader.loadClass(String)

void RegisterAppClassLoader(JNIEnv* env, jobject loader) {
    if (!env || !loader) return;
    std::lock_guard<std::mutex> lk(g_clsCacheMutex);
    if (g_appLoader) env->DeleteGlobalRef(g_appLoader);
    g_appLoader = env->NewGlobalRef(loader);
    if (!g_loadClassMid) {
        jclass clCls = env->FindClass("java/lang/ClassLoader");
        if (clCls) {
            g_loadClassMid = env->GetMethodID(clCls, "loadClass",
                                              "(Ljava/lang/String;)Ljava/lang/Class;");
            env->DeleteLocalRef(clCls);
        }
        if (env->ExceptionCheck()) env->ExceptionClear();
    }
}

// Non-zero while executing inside the interpreter / hook trampoline, where the
// managed stack has no valid frame and env->FindClass() aborts ART.
static thread_local int g_interpDepth = 0;

jclass FindClassRefCached(JNIEnv* env, const char* name) {
    if (!env || !name) return nullptr;
    {
        std::lock_guard<std::mutex> lk(g_clsCacheMutex);
        auto it = g_clsCache.find(name);
        if (it != g_clsCache.end()) return it->second;
    }

    // Prefer the app ClassLoader: loadClass() executes as a managed Java frame,
    // so it is safe even inside the frameless hook trampoline. env->FindClass()
    // instead walks the caller stack (StackVisitor::WalkStack) and crashes there.
    if (name[0] != '[') {
        jobject loader = nullptr;
        jmethodID lc = nullptr;
        {
            std::lock_guard<std::mutex> lk(g_clsCacheMutex);
            loader = g_appLoader;
            lc = g_loadClassMid;
        }
        if (loader && lc) {
            std::string dotted(name);
            for (char& c : dotted) if (c == '/') c = '.';
            jstring jn = env->NewStringUTF(dotted.c_str());
            jclass l = jn ? static_cast<jclass>(env->CallObjectMethod(loader, lc, jn)) : nullptr;
            if (env->ExceptionCheck()) { env->ExceptionClear(); l = nullptr; }
            if (jn) env->DeleteLocalRef(jn);
            if (l) {
                jclass g = static_cast<jclass>(env->NewGlobalRef(l));
                env->DeleteLocalRef(l);
                std::lock_guard<std::mutex> lk(g_clsCacheMutex);
                g_clsCache[name] = g;
                return g;
            }
        }
    }

    // On the interpreter/hook path the managed stack has no valid frame, so
    // env->FindClass() walks a bogus stack and aborts ART. Never call it there.
    if (g_interpDepth > 0) return nullptr;

    // Last resort (may be unsafe on the hook path; kept for eval-time callers).
    jclass l = env->FindClass(name);
    if (env->ExceptionCheck()) { env->ExceptionClear(); l = nullptr; }
    if (!l) return nullptr;
    jclass g = static_cast<jclass>(env->NewGlobalRef(l));
    env->DeleteLocalRef(l);
    {
        std::lock_guard<std::mutex> lk(g_clsCacheMutex);
        g_clsCache[name] = g;
    }
    return g;
}

void RegisterClassRef(JNIEnv* env, const char* jniName, jclass cls) {
    if (!env || !jniName || !cls) return;
    jclass g = static_cast<jclass>(env->NewGlobalRef(cls));
    std::lock_guard<std::mutex> lk(g_clsCacheMutex);
    g_clsCache[jniName] = g;
}

// ============================================================================
// per-thread interpreter frame bookkeeping (reentrancy guard + caller chain)
// ============================================================================
namespace {
    std::vector<void*>& interpStack() {
        static thread_local std::vector<void*> stack;
        return stack;
    }

    // chain of active VmFrameCtx on this thread (for caller linking)
    std::vector<VmFrameCtx*>& frameStack() {
        static thread_local std::vector<VmFrameCtx*> stack;
        return stack;
    }

    // find the ArtMethod* for a resolved method reference; nullptr on failure
    ArtMethod* resolveArtMethod(JNIEnv* env, const MethodRef& ref, bool isStatic) {
        if (ref.class_descriptor.empty() || ref.name.empty()) return nullptr;
        std::string jniName = ref.class_descriptor;
        if (jniName.size() > 2 && jniName[0] == 'L' && jniName.back() == ';') {
            jniName = jniName.substr(1, jniName.size() - 2);
        }
        jclass clazz = FindClassRefCached(env, jniName.c_str());   // global ref, do not delete
        if (clazz == nullptr) {
            if (env->ExceptionCheck()) env->ExceptionClear();
            return nullptr;
        }
        ArtMethod* am = ArtMethod::Require(env, clazz, ref.name.c_str(),
                                           ref.jni_signature.c_str(), isStatic);
        if (env->ExceptionCheck()) env->ExceptionClear();
        return am;
    }

    // scope filter (§8): system classes / blacklist / whitelist
    bool passScopeFilter(const FilterOptions* f, const std::string& desc) {
        if (f == nullptr) {
            // default policy: black-box system classes
            return !isSystemDescriptor(desc);
        }
        if (f->filter_system_classes && isSystemDescriptor(desc)) return false;
        for (const auto& b : f->blacklist_pkgs) {
            if (desc.rfind(b, 0) == 0) return false;
        }
        if (!f->whitelist_pkgs.empty()) {
            bool hit = false;
            for (const auto& w : f->whitelist_pkgs) {
                if (desc.rfind(w, 0) == 0) { hit = true; break; }
            }
            if (!hit) return false;
        }
        return true;
    }

    // ---------------------------------------------------------------------------
    // session handed to the C tracer through VmFrameCtx.user
    // ---------------------------------------------------------------------------
    bool isInvokeOpcode(uint8_t opcode);   // defined below

    struct Session {
        JNIEnv* env;
        const DexResolver* dex;
        const Callbacks* cbs;
        const Options* opts;
        const FilterOptions* filter;
        int depth;
        void* frameArtMethod;      // current frame's ArtMethod* (nullable)
        uint64_t budgetUsed;       // total instructions across the session
        bool aborted;              // set when the run was cut short
        bool handoffHit = false;   // aborted specifically for a safe hand-off
        Trace::ITracerListener* unifiedListener = nullptr;
    };

    // pending invoke records: filled at onInvokePre, consumed at
    // onInvokePost; thread-local because nested StepIn frames chain on the
    // same thread. Post 事件使用 Pre 时刻的 args 快照——解释器会在同帧内
    // 复用 args_tmp 缓冲，活指针在 Post 时可能已被嵌套调用覆盖。
    struct PendingCall {
        InvokeEvent ev;
        jvalue* argsSnapshot;   // new[] 分配, argc 个元素
    };
    std::vector<PendingCall>& pendingCalls() {
        static thread_local std::vector<PendingCall> stack;
        return stack;
    }

    void buildInvokeEventBase(InvokeEvent& ev, JNIEnv* env, const DexResolver* dex,
                              const vmMethod* m, int opcode, jobject receiver,
                              int argc, int depth, ArtMethod* am = nullptr) {
        MethodRef ref = dex->resolveMethod(m->idx);
        bool isStatic = (opcode == 0x71) || (opcode == 0x77);
        if (am == nullptr && ref.isValid()) {
            am = resolveArtMethod(env, ref, isStatic);
        }
        ev.env = env;
        ev.className = ref.class_descriptor;
        ev.methodName = ref.name;
        ev.signature = ref.jni_signature;
        ev.isStatic = isStatic;
        ev.isNative = (am == nullptr) || am->IsNative();
        ev.artMethod = am;
        ev.receiver = receiver;
        ev.argc = argc;
        ev.depth = depth;
    }

    // ---------------------------------------------------------------------------
    // C trampolines (installed into VmTracer)
    // ---------------------------------------------------------------------------
    int trOnInsn(VmFrameCtx* c) {
        Session* s = static_cast<Session*>(c->user);
        if (s == nullptr) return 0;
        s->budgetUsed++;
        if (s->opts != nullptr && s->opts->max_instructions >= 0 &&
            s->budgetUsed > static_cast<uint64_t>(s->opts->max_instructions)) {
            PI_LOGW("InterpTracer: instruction budget exhausted (%lld), aborting run",
                    (long long) s->opts->max_instructions);
            s->aborted = true;
            return 1;   // abort the run
        }
        // safe_handoff: bail before the interpreter does anything that can make
        // ART walk the managed stack while nmmvm frames are on it (which aborts):
        //   - heap allocation (new-instance/new-array/...): may trigger GC;
        //   - invoking a system-class method: the real JNI call may allocate/GC.
        // App-method invokes (StepIn) and pure ops are safe and stay interpreted.
        if (s->opts != nullptr && s->opts->safe_handoff) {
            uint8_t op = static_cast<uint8_t>(c->inst & 0xFF);
            bool risky = (op == 0x22 || op == 0x23 || op == 0x24 || op == 0x25);
            if (!risky && isInvokeOpcode(op) && s->dex != nullptr && c->code != nullptr) {
                uint32_t mi = c->code->insns[c->pc + 1];
                MethodRef ref = s->dex->resolveMethod(mi);
                if (ref.isValid() && isSystemDescriptor(ref.class_descriptor)) risky = true;
            }
            if (risky) {
                s->handoffHit = true;
                s->aborted = true;
                return 1;
            }
        }

        if (s->cbs == nullptr || !s->cbs->onInsn) return 0;
        InsnEvent ev{};
        ev.env = s->env;
        ev.artMethod = s->frameArtMethod;
        ev.methodName = nullptr;
        ev.depth = s->depth;
        ev.pc = c->pc;
        ev.inst = c->inst;
        ev.insns_executed = s->budgetUsed;
        ev.regs = const_cast<uint64_t*>(c->regs);
        ev.regFlags = const_cast<uint8_t*>(c->regFlags);
        ev.regsSize = 0;
        if (s->frameArtMethod) {
            auto* am = reinterpret_cast<ArtMethod*>(s->frameArtMethod);
            const uint8_t* code_item = reinterpret_cast<const uint8_t*>(
                reinterpret_cast<uintptr_t>(am->GetEntryPointFromJni()) & ~1ULL);
            if (code_item) ev.regsSize = *reinterpret_cast<const uint16_t*>(code_item);
        }
        if (ev.regsSize == 0 || ev.regsSize > 256) ev.regsSize = 16;
        bool cont = s->cbs->onInsn(ev);
        if (!cont) s->aborted = true;
        return cont ? 0 : 1;
    }

    int trOnInvokePre(VmFrameCtx* c, const vmMethod* m, int opcode,
                      jobject receiver, int argc, const jvalue* args,
                      jvalue* mockRet) {
        Session* s = static_cast<Session*>(c->user);
        if (s == nullptr || m == nullptr || s->dex == nullptr) return VM_INVOKE_JNI;

        MethodRef ref = s->dex->resolveMethod(m->idx);
        if (!ref.isValid()) return VM_INVOKE_JNI;

        bool isStatic = (opcode == 0x71) || (opcode == 0x77);
        ArtMethod* am = resolveArtMethod(s->env, ref, isStatic);
        bool isNative = (am == nullptr) || am->IsNative();

        // default scope policy: system classes step-over, business classes
        // may step-in when enabled
        bool scopeAllows = passScopeFilter(s->filter, ref.class_descriptor) &&
                           !isNative &&
                           s->opts != nullptr && s->opts->step_in_enabled &&
                           s->depth < s->opts->max_depth;

        if (s->cbs == nullptr || !s->cbs->onInvoke) {
            return scopeAllows ? VM_INVOKE_STEP_IN : VM_INVOKE_JNI;
        }

        InvokeEvent ev;
        buildInvokeEventBase(ev, s->env, s->dex, m, opcode, receiver, argc,
                             s->depth, am);
        ev.args = const_cast<jvalue*>(args);   // Pre: 活指针, 修改立即生效
        InvokeVerdict v = s->cbs->onInvoke(ev, mockRet);

        // register the pending call so onInvokePost can report the full
        // event (args / receiver) even though the C-level post callback
        // does not carry them; snapshot AFTER the callback so user-side
        // mutations are visible in post
        PendingCall rec{};
        rec.ev = ev;
        rec.ev.args = nullptr;
        if (argc > 0 && args != nullptr) {
            rec.argsSnapshot = new jvalue[static_cast<size_t>(argc)];
            std::memcpy(rec.argsSnapshot, args,
                        sizeof(jvalue) * static_cast<size_t>(argc));
        } else {
            rec.argsSnapshot = nullptr;
        }
        rec.ev.args = rec.argsSnapshot;
        pendingCalls().push_back(rec);

        if (v == InvokeVerdict::Mock) {
            return VM_INVOKE_MOCK;
        }

        // Native StepIn / QBDI only when explicitly enabled (smali debugger must not crash).
        if (v == InvokeVerdict::StepIn && isNative) {
            bool allowNative = s->opts && s->opts->enable_native_step_in;
            if (!allowNative) return VM_INVOKE_JNI;
            void* nativeTarget = nullptr;
            bool ready = Trace::JniNativeBridge::resolveNativeTarget(
                s->env, am, ref.class_descriptor, ref.name, ref.jni_signature,
                &nativeTarget);
            return ready ? VM_INVOKE_STEP_IN : VM_INVOKE_JNI;
        }

        if (v == InvokeVerdict::StepIn) {
            int maxDepth = (s->opts != nullptr) ? s->opts->max_depth : 8;
            if (!isNative && am != nullptr &&
                s->depth < maxDepth &&
                passScopeFilter(s->filter, ref.class_descriptor)) {
                return VM_INVOKE_STEP_IN;
            }
            return VM_INVOKE_JNI;
        }

        return VM_INVOKE_JNI;
    }

    int trStepIn(VmFrameCtx* c, const vmMethod* m, int opcode,
                 jobject receiver, int argc, const jvalue* args,
                 jvalue* outRet) {
        Session* s = static_cast<Session*>(c->user);
        if (s == nullptr || m == nullptr || s->dex == nullptr) return 1;

        MethodRef ref = s->dex->resolveMethod(m->idx);
        if (!ref.isValid()) return 1;
        bool isStatic = (opcode == 0x71) || (opcode == 0x77);
        ArtMethod* am = resolveArtMethod(s->env, ref, isStatic);
        if (am == nullptr || am->HasAccessFlags(0x0400)) return 1;
        int maxDepth = (s->opts != nullptr) ? s->opts->max_depth : 8;
        if (s->depth >= maxDepth) return 1;

        if (am->IsNative()) {
            if (!(s->opts && s->opts->enable_native_step_in)) return 1;
            void* nativeTarget = nullptr;
            Trace::JniNativeBridge::resolveNativeTarget(
                s->env, am, ref.class_descriptor, ref.name, ref.jni_signature, &nativeTarget);

            jobject recOrClazz = receiver;
            jclass foundClazz = nullptr;
            if (isStatic) {
                std::string jniName = ref.class_descriptor;
                if (jniName.size() > 2 && jniName[0] == 'L' && jniName.back() == ';') {
                    jniName = jniName.substr(1, jniName.size() - 2);
                }
                foundClazz = FindClassRefCached(s->env, jniName.c_str());   // global ref
                if (s->env->ExceptionCheck()) s->env->ExceptionClear();
                recOrClazz = foundClazz;
            }

            bool dispatched = false;
            *outRet = Trace::JniNativeBridge::dispatchToNative(
                s->env, am, recOrClazz, argc, args, m->shorty,
                s->depth + 1, s->opts ? s->opts->unified_listener : nullptr,
                &dispatched, nativeTarget);

            return dispatched ? 0 : 1;
        }

        // recurse into the sandbox executor (fresh frame, depth+1)
        RunResult r = runMethodInternal(s->env, am, receiver, args, m->shorty,
                                        s->cbs, s->opts, s->filter, s->depth + 1,
                                        ref.name.c_str());
        if (r.status == RunResult::ABORTED && r.handoff) {
            // propagate hand-off: abort the whole run so the root method is
            // executed natively instead (never issue JNI from nmmvm).
            s->handoffHit = true;
            s->aborted = true;
            return 2;
        }
        if (r.status != RunResult::OK || r.exceptionPending) return 1;

        if (r.isObject) {
            outRet->l = r.objectResult;
        } else {
            *outRet = r.value;
        }
        return 0;   // handled: the interpreter skips the JNI call
    }

    void trOnInvokePost(VmFrameCtx* c, const vmMethod* m, int opcode,
                        const jvalue* ret, jboolean excPending) {
        Session* s = static_cast<Session*>(c->user);
        if (s == nullptr || s->cbs == nullptr || !s->cbs->onInvokePost ||
            m == nullptr || s->dex == nullptr) {
            return;
        }
        auto& stack = pendingCalls();
        if (stack.empty()) return;
        PendingCall rec = stack.back();   // copy: nested calls may push more
        stack.pop_back();
        s->cbs->onInvokePost(rec.ev, ret, excPending == JNI_TRUE);
        delete[] rec.argsSnapshot;
    }

    void trOnException(VmFrameCtx* c, jthrowable exception, uint32_t throwPc,
                       int catchPc) {
        Session* s = static_cast<Session*>(c->user);
        if (s == nullptr || s->cbs == nullptr || !s->cbs->onException) return;
        ExceptionEvent ev{};
        ev.env = s->env;
        ev.depth = s->depth;
        ev.exception = exception;
        ev.throwPc = throwPc;
        ev.catchPc = catchPc;
        s->cbs->onException(ev);
    }

    const VmTracer kSessionTracer = {
        .user          = nullptr,
        .onInsn        = &trOnInsn,
        .onInvokePre   = &trOnInvokePre,
        .stepIn        = &trStepIn,
        .onInvokePost  = &trOnInvokePost,
        .onException   = &trOnException,
        .onFrameExit   = nullptr,
    };

} // namespace


// ============================================================================
// type-aware value rendering (shared by callbacks & log trace)
// ============================================================================
namespace {
// fwd: defined in the log-trace section below (same internal namespace)
std::string objectToString(JNIEnv* env, jobject obj);

// 解析签名: 参数类型字符 + 返回类型字符 (对象/数组统一归 'L')
void parseSigTypes(const std::string& sig, std::vector<char>& params, char& ret) {
    params.clear();
    ret = 'V';
    size_t rp = sig.find(')');
    if (sig.empty() || sig[0] != '(' || rp == std::string::npos) return;

    size_t i = 1;
    while (i < rp) {
        char c = sig[i];
        char kind;
        if (c == '[') {
            kind = 'L';
            while (i < rp && sig[i] == '[') i++;
            if (i < rp && sig[i] == 'L') { while (i < rp && sig[i] != ';') i++; }
            i++;
        } else if (c == 'L') {
            kind = 'L';
            while (i < rp && sig[i] != ';') i++;
            i++;
        } else {
            kind = c;
            i++;
        }
        params.push_back(kind);
    }
    char r = (rp + 1 < sig.size()) ? sig[rp + 1] : 'V';
    ret = (r == 'L' || r == '[') ? 'L' : r;
}

std::string formatValue(JNIEnv* env, char kind, const jvalue& v) {
    char buf[96];
    switch (kind) {
        case 'L':
            return "\"" + objectToString(env, v.l) + "\"";
        case 'Z':
            return v.z ? "true" : "false";
        case 'B':
            return std::to_string(static_cast<int>(v.b));
        case 'C': {
            snprintf(buf, sizeof(buf), "'%c'", v.c);
            return buf;
        }
        case 'S':
            return std::to_string(static_cast<int>(v.s));
        case 'I':
            return std::to_string(v.i);
        case 'J':
            snprintf(buf, sizeof(buf), "%lldL", (long long) v.j);
            return buf;
        case 'F':
            snprintf(buf, sizeof(buf), "%gf", v.f);
            return buf;
        case 'D':
            snprintf(buf, sizeof(buf), "%g", v.d);
            return buf;
        default:
            return "?";
    }
}
} // namespace

std::string formatInvokeArgs(JNIEnv* env, const std::string& signature,
                             const jvalue* args, int argc) {
    std::vector<char> kinds;
    char retKind;
    parseSigTypes(signature, kinds, retKind);
    std::string out = "(";
    for (int i = 0; i < argc && i < static_cast<int>(kinds.size()); i++) {
        if (i) out += ", ";
        out += (args != nullptr) ? formatValue(env, kinds[i], args[i]) : "?";
    }
    if (argc > static_cast<int>(kinds.size())) out += ",...";
    out += ")";
    return out;
}

std::string formatReturnValue(JNIEnv* env, const std::string& signature,
                              const jvalue& ret) {
    std::vector<char> kinds;
    char retKind;
    parseSigTypes(signature, kinds, retKind);
    if (retKind == 'V') return "void";
    return formatValue(env, retKind, ret);
}

std::string FormatObjectNative(JNIEnv* env, jobject obj) {
    return objectToString(env, obj);   // anon-namespace helper above
}

// ============================================================================
// session wiring (used by pi_interp_executor.cpp)
// ============================================================================
namespace detail {

bool hasActiveCallbacks(const Callbacks* cbs) {
    return cbs != nullptr &&
           (cbs->onInsn || cbs->onInvoke || cbs->onInvokePost || cbs->onException);
}

void* makeSession(JNIEnv* env, const void* dexResolver, const Callbacks* cbs,
                  const Options* opts, const FilterOptions* filter, int depth,
                  void* frameArtMethod) {
    static const Options kDefaultOpts{};   // used when caller passes nullptr
    auto* s = new Session{
        .env = env,
        .dex = static_cast<const DexResolver*>(dexResolver),
        .cbs = cbs,
        .opts = (opts != nullptr) ? opts : &kDefaultOpts,
        .filter = filter,
        .depth = depth,
        .frameArtMethod = frameArtMethod,
        .budgetUsed = 0,
        .aborted = false,
        .handoffHit = false,
    };
    return s;
}

bool sessionAborted(void* session) {
    return session != nullptr && static_cast<Session*>(session)->aborted;
}

bool sessionHandoff(void* session) {
    return session != nullptr && static_cast<Session*>(session)->handoffHit;
}

void setSessionListener(void* session, Trace::ITracerListener* listener) {
    if (session == nullptr) return;
    static_cast<Session*>(session)->unifiedListener = listener;
}

void destroySession(void* session) {
    delete static_cast<Session*>(session);
}

void* makeFrameCtx(void* session, const void* code, int depth) {
    // heap-allocated; released by destroyFrameCtx after the run
    VmFrameCtx* ctx = new VmFrameCtx{};
    ctx->user = session;
    ctx->code = static_cast<const vmCode*>(code);
    auto& fs = frameStack();
    ctx->caller = fs.empty() ? nullptr : fs.back();
    ctx->depth = depth;
    ctx->tracer = &kSessionTracer;
    return ctx;
}

void pushFrame(void* frameCtx, void* artMethod) {
    auto* ctx = static_cast<VmFrameCtx*>(frameCtx);
    frameStack().push_back(ctx);
    interpStack().push_back(artMethod);
    g_interpDepth++;
}

void popFrame() {
    if (!frameStack().empty()) frameStack().pop_back();
    if (!interpStack().empty()) interpStack().pop_back();
    if (g_interpDepth > 0) g_interpDepth--;
}

void destroyFrameCtx(void* frameCtx) {
    delete static_cast<VmFrameCtx*>(frameCtx);
}

} // namespace detail

// ============================================================================
// logcat per-instruction trace ("PI_VMTrace")
// format:
//   [0x0009]  206e 008f 0021  |  invoke-virtual ...  | regs: v1="..."  v2=5(0x5)
// regs line lists ALL registers referenced by the instruction (reads +
// writes, dedup, ascending), values BEFORE execution; objects render via the
// pure-native class descriptor (Class::GetDescriptor) + Get*ArrayRegion.
// ============================================================================
#include <algorithm>
#include <atomic>
#include <cstdio>

namespace {

std::atomic<bool> g_traceEnabled{false};

struct TraceContext {
    bool active = false;
    const void* artDexFile = nullptr;
    const uint16_t* insnsBase = nullptr;
    uint32_t regsSize = 0;
    uint32_t insnsTraced = 0;
    const DexResolver* dex = nullptr;   // for invoke shorty lookup
    char label[72] = {0};               // method label for section markers
};
thread_local TraceContext t_trace;

constexpr uint32_t kMaxInsnsPerRun = 4000;
constexpr size_t kMaxRegsPerLine = 10;
constexpr size_t kMaxToStringLen = 64;

struct RegRef {
    uint16_t reg;
    bool wide;
};

// dalvik opcode -> operand format
enum RegFmt : uint8_t {
    FMT_NONE, FMT_12x, FMT_11x, FMT_11n, FMT_21x, FMT_22x, FMT_22b, FMT_22r,
    FMT_23x, FMT_32x, FMT_35c, FMT_3rc,
};

const uint8_t kOpcodeFmt[256] = {
    /*00*/ FMT_NONE, FMT_12x, FMT_22x, FMT_32x, FMT_12x, FMT_22x, FMT_32x,
           FMT_12x, FMT_22x, FMT_32x, FMT_11x, FMT_11x, FMT_11x, FMT_11x,
           FMT_NONE, FMT_11x,
    /*10*/ FMT_11x, FMT_11x, FMT_11x, FMT_11n, FMT_21x, FMT_21x, FMT_21x,
           FMT_21x, FMT_21x, FMT_21x, FMT_21x, FMT_21x, FMT_21x, FMT_21x,
           FMT_21x, FMT_21x,
    /*20*/ FMT_22r, FMT_12x, FMT_21x, FMT_22r, FMT_35c, FMT_3rc, FMT_21x,
           FMT_11x, FMT_NONE, FMT_NONE, FMT_NONE, FMT_21x, FMT_21x,
    /*2d*/ FMT_23x, FMT_23x, FMT_23x, FMT_23x, FMT_23x,
    /*32*/ FMT_22r, FMT_22r, FMT_22r, FMT_22r, FMT_22r, FMT_22r,
    /*38*/ FMT_21x, FMT_21x, FMT_21x, FMT_21x, FMT_21x, FMT_21x,
    /*3e*/ FMT_NONE, FMT_NONE, FMT_NONE, FMT_NONE, FMT_NONE, FMT_NONE,
    /*44*/ FMT_23x, FMT_23x, FMT_23x, FMT_23x, FMT_23x, FMT_23x, FMT_23x,
           FMT_23x, FMT_23x, FMT_23x, FMT_23x, FMT_23x, FMT_23x, FMT_23x,
    /*52*/ FMT_22r, FMT_22r, FMT_22r, FMT_22r, FMT_22r, FMT_22r, FMT_22r,
           FMT_22r, FMT_22r, FMT_22r, FMT_22r, FMT_22r, FMT_22r, FMT_22r,
    /*60*/ FMT_21x, FMT_21x, FMT_21x, FMT_21x, FMT_21x, FMT_21x, FMT_21x,
           FMT_21x, FMT_21x, FMT_21x, FMT_21x, FMT_21x, FMT_21x, FMT_21x,
    /*6e*/ FMT_35c, FMT_35c, FMT_35c, FMT_35c, FMT_35c, FMT_NONE,
    /*74*/ FMT_3rc, FMT_3rc, FMT_3rc, FMT_3rc, FMT_3rc, FMT_NONE, FMT_NONE,
    /*7b*/ FMT_12x, FMT_12x, FMT_12x, FMT_12x, FMT_12x, FMT_12x, FMT_12x,
           FMT_12x, FMT_12x, FMT_12x, FMT_12x, FMT_12x, FMT_12x, FMT_12x,
           FMT_12x, FMT_12x, FMT_12x, FMT_12x, FMT_12x, FMT_12x, FMT_12x,
    /*90*/ FMT_23x, FMT_23x, FMT_23x, FMT_23x, FMT_23x, FMT_23x, FMT_23x,
           FMT_23x, FMT_23x, FMT_23x, FMT_23x, FMT_23x, FMT_23x, FMT_23x,
           FMT_23x, FMT_23x, FMT_23x, FMT_23x, FMT_23x, FMT_23x, FMT_23x,
           FMT_23x, FMT_23x, FMT_23x, FMT_23x, FMT_23x, FMT_23x, FMT_23x,
           FMT_23x, FMT_23x, FMT_23x, FMT_23x,
    /*b0*/ FMT_12x, FMT_12x, FMT_12x, FMT_12x, FMT_12x, FMT_12x, FMT_12x,
           FMT_12x, FMT_12x, FMT_12x, FMT_12x, FMT_12x, FMT_12x, FMT_12x,
           FMT_12x, FMT_12x, FMT_12x, FMT_12x, FMT_12x, FMT_12x, FMT_12x,
           FMT_12x, FMT_12x, FMT_12x, FMT_12x, FMT_12x, FMT_12x, FMT_12x,
           FMT_12x, FMT_12x, FMT_12x, FMT_12x,
    /*d0*/ FMT_22r, FMT_22r, FMT_22r, FMT_22r, FMT_22r, FMT_22r, FMT_22r,
           FMT_22r,
    /*d8*/ FMT_22b, FMT_22b, FMT_22b, FMT_22b, FMT_22b, FMT_22b, FMT_22b,
           FMT_22b, FMT_22b, FMT_22b, FMT_22b,
    /*e3*/ FMT_NONE, FMT_NONE, FMT_NONE, FMT_NONE, FMT_NONE, FMT_NONE,
           FMT_NONE, FMT_NONE, FMT_NONE, FMT_NONE, FMT_NONE, FMT_NONE,
           FMT_NONE, FMT_NONE, FMT_NONE, FMT_NONE, FMT_NONE, FMT_NONE,
           FMT_NONE, FMT_NONE, FMT_NONE, FMT_NONE, FMT_NONE,
    /*fa*/ FMT_35c, FMT_3rc, FMT_35c, FMT_3rc, FMT_21x, FMT_21x,
};

bool isWideValueOpcode(uint8_t opcode) {
    if (opcode >= 0x04 && opcode <= 0x06) return true;
    switch (opcode) {
        case 0x0b: case 0x10:
        case 0x16: case 0x17: case 0x18: case 0x19:
        case 0x45: case 0x4c: case 0x53: case 0x5a: case 0x61: case 0x65:
        case 0x7d: case 0x7e: case 0x86: case 0x8c:
            return true;
        default:
            return (opcode >= 0x9b && opcode <= 0x9f)
                || (opcode >= 0xbb && opcode <= 0xbf);
    }
}

bool isInvokeOpcode(uint8_t opcode) {
    return (opcode >= 0x6e && opcode <= 0x72)
        || (opcode >= 0x74 && opcode <= 0x78)
        || opcode == 0x24 || opcode == 0x25;
}

size_t collectUsedRegs(const uint16_t* insn, uint32_t regsSize,
                       uint16_t* out, size_t outCap) {
    uint8_t opcode = (*insn) & 0xFF;
    uint16_t tmp[8];
    size_t n = 0;

    switch (kOpcodeFmt[opcode]) {
        case FMT_12x:
            tmp[n++] = (insn[0] >> 8) & 0xF;
            tmp[n++] = (insn[0] >> 12) & 0xF;
            break;
        case FMT_11n:
            tmp[n++] = (insn[0] >> 8) & 0xF;
            break;
        case FMT_11x:
            tmp[n++] = (insn[0] >> 8) & 0xFF;
            break;
        case FMT_21x:
            tmp[n++] = (insn[0] >> 8) & 0xFF;
            break;
        case FMT_22x:
        case FMT_22b:
            tmp[n++] = (insn[0] >> 8) & 0xFF;
            tmp[n++] = insn[1] & 0xFF;
            break;
        case FMT_22r:
            tmp[n++] = (insn[0] >> 8) & 0xF;
            tmp[n++] = (insn[0] >> 12) & 0xF;
            break;
        case FMT_23x:
            tmp[n++] = (insn[0] >> 8) & 0xFF;
            tmp[n++] = insn[1] & 0xFF;
            tmp[n++] = (insn[1] >> 8) & 0xFF;
            break;
        case FMT_32x:
            tmp[n++] = insn[1];
            tmp[n++] = insn[2];
            break;
        case FMT_35c: {
            uint8_t count = (insn[0] >> 12) & 0xF;
            uint16_t regs5[5] = {
                static_cast<uint16_t>(insn[2] & 0xF),
                static_cast<uint16_t>((insn[2] >> 4) & 0xF),
                static_cast<uint16_t>((insn[2] >> 8) & 0xF),
                static_cast<uint16_t>((insn[2] >> 12) & 0xF),
                static_cast<uint16_t>((insn[0] >> 8) & 0xF),
            };
            for (int i = 0; i < count && i < 5; i++) tmp[n++] = regs5[i];
            break;
        }
        case FMT_3rc: {
            uint8_t count = (insn[0] >> 8) & 0xFF;
            uint16_t base = insn[2];
            for (int i = 0; i < count && n < 8; i++) tmp[n++] = base + i;
            break;
        }
        default:
            return 0;
    }

    std::sort(tmp, tmp + n);
    size_t m = 0;
    for (size_t i = 0; i < n; i++) {
        if (i > 0 && tmp[i] == tmp[i - 1]) continue;
        if (tmp[i] >= regsSize) continue;
        if (m >= outCap) break;
        out[m++] = tmp[i];
    }
    return m;
}

size_t collectInvokeRegs(const uint16_t* insn, uint8_t opcode, uint32_t regsSize,
                         const DexResolver* dex, RegRef* out, size_t outCap) {
    bool isRange = (opcode >= 0x74 && opcode <= 0x78) || opcode == 0x25;
    bool isStatic = (opcode == 0x71) || (opcode == 0x77);
    uint16_t methodIdx = insn[1];

    uint16_t slots[16];
    size_t slotCount = 0;
    if (isRange) {
        uint8_t count = (insn[0] >> 8) & 0xFF;
        uint16_t base = insn[2];
        for (int i = 0; i < count && slotCount < 16; i++)
            slots[slotCount++] = static_cast<uint16_t>(base + i);
    } else {
        uint8_t count = (insn[0] >> 12) & 0xF;
        uint16_t regs5[5] = {
            static_cast<uint16_t>(insn[2] & 0xF),
            static_cast<uint16_t>((insn[2] >> 4) & 0xF),
            static_cast<uint16_t>((insn[2] >> 8) & 0xF),
            static_cast<uint16_t>((insn[2] >> 12) & 0xF),
            static_cast<uint16_t>((insn[0] >> 8) & 0xF),
        };
        for (int i = 0; i < count && i < 5; i++) slots[slotCount++] = regs5[i];
    }

    const char* shorty = (dex != nullptr) ? dex->methodShorty(methodIdx) : nullptr;
    const char* p = (shorty != nullptr) ? shorty + 1 : nullptr;

    size_t n = 0;
    for (size_t i = 0; i < slotCount && n < outCap; i++) {
        if (slots[i] >= regsSize) continue;
        if (!isStatic && i == 0) {
            out[n++] = RegRef{slots[i], false};
            continue;
        }
        char c = (p != nullptr) ? *p : 0;
        if (c == 'J' || c == 'D') {
            out[n++] = RegRef{slots[i], true};
            if (p != nullptr && *p != '\0') p++;
            i++;   // wide param consumes 2 slots
            continue;
        }
        out[n++] = RegRef{slots[i], false};
        if (p != nullptr && *p != '\0') p++;
    }
    return n;
}

// ---- value rendering (PURE NATIVE) -----------------------------------------
// No Class.getName() / obj.toString() / Arrays.toString() on the interpreter
// hot path -> no Java frames entered, no safepoint/GC-during-JNI risk.
// Class descriptor comes from libart mirror::Class::GetDescriptor(std::string*)
// (xdl-resolved); arrays are formatted via Get*ArrayRegion.
typedef const char* (*ClassGetDescriptorFn)(const void*, std::string*);
static ClassGetDescriptorFn g_classGetDescriptor = nullptr;

static void ensureClassDescFn() {
    static std::once_flag flag;
    std::call_once(flag, []() {
        const char* sym =
            "_ZN3art6mirror5Class13GetDescriptorEPNSt3__112basic_stringIcNS2_11char_traitsIcEENS2_9allocatorIcEEEE";
        void* h = xdl_open("libart.so", XDL_DEFAULT);
        if (h == nullptr) h = xdl_open("/apex/com.android.art/lib64/libart.so", XDL_DEFAULT);
        if (h == nullptr) h = xdl_open("/apex/com.android.art/lib/libart.so", XDL_DEFAULT);
        if (h != nullptr) {
            g_classGetDescriptor = reinterpret_cast<ClassGetDescriptorFn>(xdl_sym(h, sym, nullptr));
            xdl_close(h);
        }
        if (g_classGetDescriptor == nullptr) {
            PI_LOGW("PI_VMTrace: Class::GetDescriptor unresolved -> class names unavailable");
        }
    });
}

// jclass == (indirect) JNI ref -> raw mirror::Class* -> descriptor string.
static std::string nativeClassDescriptor(JNIEnv* env, jclass cls) {
    std::string out;
    if (cls == nullptr) return out;
    ensureClassDescFn();
    if (g_classGetDescriptor == nullptr) return out;
    // JNI refs are indirect; MUST decode to the raw mirror::Class*. Never pass
    // the raw jclass handle to Class::GetDescriptor -> would read bogus memory.
    void* raw = nullptr;
    if (auto* th = pine::art::Thread::Current(env)) {
        raw = th->DecodeJObject(cls);
    }
    if (raw == nullptr) return out;
    // Returns the descriptor for reference classes; fills *out for arrays/primitives.
    const char* p = g_classGetDescriptor(raw, &out);
    if (p != nullptr && p[0] != '\0') return std::string(p);
    return out;
}

static std::string nativeFormatPrimitiveArray(JNIEnv* env, jarray arr, char e, jsize n, jsize m) {
    char buf[64];
    std::string out = "[";
    switch (e) {
        case 'B': { jbyte v[24];    env->GetByteArrayRegion((jbyteArray)arr, 0, m, v);
                    for (jsize i = 0; i < m; i++) { if (i) out += ", "; snprintf(buf, sizeof(buf), "%d", (int)v[i]); out += buf; } break; }
        case 'Z': { jboolean v[24]; env->GetBooleanArrayRegion((jbooleanArray)arr, 0, m, v);
                    for (jsize i = 0; i < m; i++) { if (i) out += ", "; out += (v[i] ? "true" : "false"); } break; }
        case 'C': { jchar v[24];    env->GetCharArrayRegion((jcharArray)arr, 0, m, v);
                    for (jsize i = 0; i < m; i++) {
                        if (i) out += ", ";
                        if (v[i] >= 0x20 && v[i] <= 0x7E) snprintf(buf, sizeof(buf), "'%c'", (char)v[i]);
                        else snprintf(buf, sizeof(buf), "\\u%04x", (unsigned)v[i]);
                        out += buf;
                    } break; }
        case 'S': { jshort v[24];   env->GetShortArrayRegion((jshortArray)arr, 0, m, v);
                    for (jsize i = 0; i < m; i++) { if (i) out += ", "; snprintf(buf, sizeof(buf), "%d", (int)v[i]); out += buf; } break; }
        case 'I': { jint v[24];     env->GetIntArrayRegion((jintArray)arr, 0, m, v);
                    for (jsize i = 0; i < m; i++) { if (i) out += ", "; snprintf(buf, sizeof(buf), "%d", (int)v[i]); out += buf; } break; }
        case 'J': { jlong v[24];    env->GetLongArrayRegion((jlongArray)arr, 0, m, v);
                    for (jsize i = 0; i < m; i++) { if (i) out += ", "; snprintf(buf, sizeof(buf), "%lld", (long long)v[i]); out += buf; } break; }
        case 'F': { jfloat v[24];   env->GetFloatArrayRegion((jfloatArray)arr, 0, m, v);
                    for (jsize i = 0; i < m; i++) { if (i) out += ", "; snprintf(buf, sizeof(buf), "%g", (double)v[i]); out += buf; } break; }
        case 'D': { jdouble v[24];  env->GetDoubleArrayRegion((jdoubleArray)arr, 0, m, v);
                    for (jsize i = 0; i < m; i++) { if (i) out += ", "; snprintf(buf, sizeof(buf), "%g", v[i]); out += buf; } break; }
        default:  out += "?"; break;
    }
    if (n > m) out += ", ...";
    out += "]";
    return out;
}

static std::string nativeFormatArray(JNIEnv* env, jobject arr, const char* desc) {
    if (desc == nullptr || desc[0] != '[') return "<not-array>";
    char e = desc[1];
    jsize n = env->GetArrayLength(reinterpret_cast<jarray>(arr));
    if (env->ExceptionCheck()) { env->ExceptionClear(); return "[?]"; }
    const jsize kMax = 24;
    jsize m = n < kMax ? n : kMax;
    if (e == 'L' || e == '[') {
        char buf[176];
        std::string out = "[";
        for (jsize i = 0; i < m; i++) {
            if (i) out += ", ";
            jobject el = env->GetObjectArrayElement(reinterpret_cast<jobjectArray>(arr), i);
            if (el == nullptr) { out += "null"; continue; }
            jclass ec = env->GetObjectClass(el);
            std::string ed = nativeClassDescriptor(env, ec);
            if (ec != nullptr) env->DeleteLocalRef(ec);
            snprintf(buf, sizeof(buf), "%s@%p", ed.empty() ? "Object" : ed.c_str(), (void*)el);
            out += buf;
            env->DeleteLocalRef(el);
        }
        if (n > m) out += ", ...";
        out += "]";
        return out;
    }
    return nativeFormatPrimitiveArray(env, reinterpret_cast<jarray>(arr), e, n, m);
}

struct ScopedJniFrame {
    JNIEnv* env;
    bool ok;
    explicit ScopedJniFrame(JNIEnv* e, int cap = 32) : env(e), ok(e && e->PushLocalFrame(cap) >= 0) {}
    ~ScopedJniFrame() {
        if (ok && env) env->PopLocalFrame(nullptr);
    }
};

std::string objectToString(JNIEnv* env, jobject obj) {
    if (obj == nullptr) return "null";
    if (env == nullptr || env->ExceptionCheck()) return "<pending-ex>";
    jclass cls = env->GetObjectClass(obj);   // JNI helper (reads obj->klass_); no Java call
    if (cls == nullptr) {
        if (env->ExceptionCheck()) env->ExceptionClear();
        return "<no-class>";
    }

    // ===== CRASH-REPRO TOGGLE =================================================
    // Set PI_REPRO_HOTPATH_JNI=1 to restore ONE Java call per object register
    // (the old Class.getName() behavior). nmmvm then enters Java on the hot path;
    // a GC checkpoint lands while ART's managed stack still points at Pine's
    // half-set-up frame -> WalkStack/ReferenceMapVisitor SEGV. Set to 0 for the
    // native (crash-free) path.
#ifndef PI_REPRO_HOTPATH_JNI
#define PI_REPRO_HOTPATH_JNI 0
#endif
#if PI_REPRO_HOTPATH_JNI
    {
        // REPRO variant A (minimal, reliably crashes): Class.getName() mid looked
        // up ON cls -> for array/non-Class-representable classes GetMethodID
        // throws NoSuchMethodError -> ART walks the stack -> hits Pine's
        // half-set-up frame -> StackVisitor::GetDexPc SEGV (fault 0x18).
        jmethodID nameMid = env->GetMethodID(cls, "getName", "()Ljava/lang/String;");
        if (nameMid != nullptr && !env->ExceptionCheck()) {
            jstring s = reinterpret_cast<jstring>(env->CallObjectMethod(cls, nameMid));
            if (!env->ExceptionCheck() && s != nullptr) {
                const char* utf = env->GetStringUTFChars(s, nullptr);
                std::string r = (utf != nullptr) ? utf : "";
                if (utf != nullptr) env->ReleaseStringUTFChars(s, utf);
                env->DeleteLocalRef(s);
                env->DeleteLocalRef(cls);
                return r;   // Java-rendered name on the hot path (old behavior)
            }
        }
        if (env->ExceptionCheck()) env->ExceptionClear();
    }
#endif
    // =========================================================================

    std::string desc = nativeClassDescriptor(env, cls);
    env->DeleteLocalRef(cls);
    if (env->ExceptionCheck()) env->ExceptionClear();
    if (desc.empty()) {
        char buf[64];
        snprintf(buf, sizeof(buf), "Object@%p", (void*)obj);
        return buf;
    }
    // String content is read natively (GetStringUTFChars: pure native memory read,
    // no Java frame) so URLs/keys/etc. stay visible in the trace. Returned raw
    // (unquoted) like the other object renderings; callers add the quotes.
    if (desc == "Ljava/lang/String;") {
        const char* utf = env->GetStringUTFChars(reinterpret_cast<jstring>(obj), nullptr);
        if (utf != nullptr) {
            std::string s = utf;
            env->ReleaseStringUTFChars(reinterpret_cast<jstring>(obj), utf);
            if (s.size() > kMaxToStringLen) { s.resize(kMaxToStringLen); s += "..."; }
            return s;
        }
        if (env->ExceptionCheck()) env->ExceptionClear();
        // fall through to Descriptor@addr on failure
    }
    if (desc[0] == '[') {
        std::string out = nativeFormatArray(env, obj, desc.c_str());
        if (out.size() > kMaxToStringLen) { out.resize(kMaxToStringLen); out += "..."; }
        return out;
    }
    std::string sname = desc;
    if (sname.size() > 2 && sname[0] == 'L' && sname.back() == ';') {
        size_t slash = sname.rfind('/');
        sname = (slash != std::string::npos) ? sname.substr(slash + 1, sname.size() - slash - 2)
                                             : sname.substr(1, sname.size() - 2);
    }
    char buf[192];
    snprintf(buf, sizeof(buf), "%s@%p", sname.c_str(), (void*)obj);
    if (obj) {
        PineNative_NotifyObservedObject(env, reinterpret_cast<uintptr_t>(obj), obj);
    }
    return buf;
}

std::string formatReg(JNIEnv* env, uint32_t idx, regptr_t value, uint8_t flag) {
    char buf[96];
    if (flag) {
        jobject obj = reinterpret_cast<jobject>(value);
        std::string s = objectToString(env, obj);
        snprintf(buf, sizeof(buf), "v%u=\"%s\"", idx, s.c_str());
    } else {
        auto asInt = static_cast<int32_t>(value);
        if (asInt > -1000000 && asInt < 1000000) {
            snprintf(buf, sizeof(buf), "v%u=%d(0x%llx)", idx, asInt,
                     (unsigned long long) value);
        } else {
            snprintf(buf, sizeof(buf), "v%u=0x%llx", idx,
                     (unsigned long long) value);
        }
    }
    return buf;
}

std::string formatWideReg(uint32_t idx, regptr_t value) {
    double d;
    std::memcpy(&d, &value, 8);
    char buf[96];
    if (std::isnan(d) || std::isinf(d)) {
        snprintf(buf, sizeof(buf), "v%u/v%u=0x%llx", idx, idx + 1,
                 (unsigned long long) value);
    } else {
        snprintf(buf, sizeof(buf), "v%u/v%u=lng:%lld|dbl:%g", idx, idx + 1,
                 (long long) (int64_t) value, d);
    }
    return buf;
}

void vmTraceHookImpl(JNIEnv* env, const vmCode* /*code*/, u4 pcOffset, u2 /*inst*/,
                     const regptr_t* regs, const u1* regFlags) {
    TraceContext& ctx = t_trace;
    if (!ctx.active || regs == nullptr || regFlags == nullptr ||
        ctx.insnsBase == nullptr) {
        return;
    }
    if (ctx.insnsTraced >= kMaxInsnsPerRun) {
        if (ctx.insnsTraced == kMaxInsnsPerRun) {
            PI::Logger::log(PI::LogLevel::WARN, "PI_VMTrace",
                            "=== trace limit %u reached, stopping ===",
                            kMaxInsnsPerRun);
            ctx.insnsTraced++;
        }
        return;
    }
    ctx.insnsTraced++;

    ScopedJniFrame jniFrame(env, 32);

    const uint16_t* insn = ctx.insnsBase + pcOffset;
    uint8_t opcode = (*insn) & 0xFF;

    std::string regsLine;
    if (isInvokeOpcode(opcode)) {
        RegRef refs[16];
        size_t n = collectInvokeRegs(insn, opcode, ctx.regsSize, ctx.dex,
                                     refs, 16);
        for (size_t i = 0; i < n; i++) {
            if (!regsLine.empty()) regsLine += "  ";
            uint16_t r = refs[i].reg;
            regsLine += refs[i].wide
                ? formatWideReg(r, regs[r])
                : formatReg(env, r, regs[r], regFlags[r]);
        }
    } else if (isWideValueOpcode(opcode)) {
        uint16_t regList[kMaxRegsPerLine];
        size_t regCount = collectUsedRegs(insn, ctx.regsSize, regList,
                                          kMaxRegsPerLine);
        for (size_t i = 0; i < regCount; i++) {
            if (!regsLine.empty()) regsLine += "  ";
            regsLine += formatWideReg(regList[i], regs[regList[i]]);
        }
    } else {
        uint16_t regList[kMaxRegsPerLine];
        size_t regCount = collectUsedRegs(insn, ctx.regsSize, regList,
                                          kMaxRegsPerLine);
        for (size_t i = 0; i < regCount; i++) {
            if (!regsLine.empty()) regsLine += "  ";
            uint16_t r = regList[i];
            regsLine += formatReg(env, r, regs[r], regFlags[r]);
        }
    }

    std::string text = ::PI::formatSingleInstruction(insn, ctx.artDexFile);

    int depth = Trace::UnifiedCallDepth::get();
    std::string prefix;
    prefix.reserve(static_cast<size_t>((depth + 1) * 4));
    for (int i = 0; i <= depth; i++) {
        prefix += "│   ";
    }

    if (regsLine.empty()) {
        PI::Logger::log(PI::LogLevel::TRACE, "PI_CallTree",
                        "%s0x%04x: %s",
                        prefix.c_str(), pcOffset, text.c_str());
    } else {
        // Default trace output includes the register snapshot for each step.
        PI::Logger::log(PI::LogLevel::TRACE, "PI_CallTree",
                        "%s0x%04x: %s   %s",
                        prefix.c_str(), pcOffset, text.c_str(), regsLine.c_str());
    }

    if (regsLine.empty()) {
        PI::Logger::log(PI::LogLevel::TRACE, "PI_VMTrace", "[0x%04x]  %s",
                            pcOffset, text.c_str());
    } else {
        PI::Logger::log(PI::LogLevel::TRACE, "PI_VMTrace",
                            "[0x%04x]  %s  | regs: %s",
                            pcOffset, text.c_str(), regsLine.c_str());
    }
}

} // namespace

// ============================================================================
// TraceGuard
// ============================================================================
struct TraceGuard::State {
    vmTraceHookFn savedHook;
    TraceContext savedCtx;
};

TraceGuard::TraceGuard(JNIEnv* env, const void* artDexFile,
                       const uint16_t* insnsBase, uint32_t regsSize,
                       const void* dexResolver, const char* label, bool force) {
    (void) env;
    if (!g_traceEnabled.load(std::memory_order_relaxed) && !force) return;

    state_ = new State();
    state_->savedHook = ::g_vmTraceHook;
    state_->savedCtx = std::move(t_trace);   // reentrancy: save outer run

    t_trace.artDexFile = artDexFile;
    t_trace.insnsBase = insnsBase;
    t_trace.regsSize = regsSize;
    t_trace.insnsTraced = 0;
    t_trace.dex = static_cast<const DexResolver*>(dexResolver);
    snprintf(t_trace.label, sizeof(t_trace.label), "%s",
             (label != nullptr && label[0] != '\0') ? label : "frame");
    t_trace.active = true;

    PI::Logger::log(PI::LogLevel::INFO, "PI_VMTrace",
                        "=== VMTrace start: %s (regs=%u) ===",
                        t_trace.label, regsSize);

    ::g_vmTraceHook = &vmTraceHookImpl;
    active_ = true;
}

TraceGuard::~TraceGuard() {
    if (!active_) return;
    PI::Logger::log(PI::LogLevel::INFO, "PI_VMTrace",
                        "=== VMTrace end (%u insns) ===", t_trace.insnsTraced);
    ::g_vmTraceHook = state_->savedHook;
    if (state_->savedCtx.active) {
        t_trace = std::move(state_->savedCtx);
    } else {
        t_trace = TraceContext{};
    }
    delete state_;
    active_ = false;
}

// ============================================================================
// §9 InvokeEvent 面向对象方法实现
// ============================================================================
namespace detail {

// 签名 -> 参数类型字符 (对象/数组归 'L'); 越界返回 'I'
char paramTypeChar(const std::string& signature, int index) {
    std::vector<char> kinds;
    char ret;
    parseSigTypes(signature, kinds, ret);
    if (index < 0 || index >= static_cast<int>(kinds.size())) return 'I';
    return kinds[index];
}

char returnTypeChar(const std::string& signature) {
    std::vector<char> kinds;
    char ret;
    parseSigTypes(signature, kinds, ret);
    return ret;
}

void setArgValue(JNIEnv* env, const std::string& signature, int index,
                 jvalue& slot, DetailArgKind kind, uint64_t raw) {
    char t = paramTypeChar(signature, index);
    if (kind == DetailArgKind::OBJECT) {
        slot.l = reinterpret_cast<jobject>(raw);          // L / [ / 其他引用
        return;
    }
    if (kind == DetailArgKind::FP) {
        if (t == 'F') { float f; std::memcpy(&f, &raw, 4); slot.f = f; }
        else        { std::memcpy(&slot.d, &raw, 8); }    // D (或未声明宽槽兜底)
        return;
    }
    // INT
    switch (t) {
        case 'J': slot.j = static_cast<jlong>((int64_t) raw); break;
        case 'Z': slot.z = static_cast<jboolean>(raw); break;
        case 'B': slot.b = static_cast<jbyte>(raw); break;
        case 'C': slot.c = static_cast<jchar>(raw); break;
        case 'S': slot.s = static_cast<jshort>(raw); break;
        default:  slot.i = static_cast<jint>((int32_t) raw); break;
    }
}

void mockValue(const std::string& signature, jvalue& slot,
               DetailArgKind kind, uint64_t raw) {
    char t = returnTypeChar(signature);
    if (t == 'V') t = 'I';   // void 方法 Mock 无意义, 兜底
    if (kind == DetailArgKind::OBJECT || t == 'L') {
        slot.l = reinterpret_cast<jobject>(raw);
        return;
    }
    if (kind == DetailArgKind::FP || t == 'D' || t == 'F') {
        if (t == 'F') { float f; std::memcpy(&f, &raw, 4); slot.f = f; }
        else        { std::memcpy(&slot.d, &raw, 8); }
        return;
    }
    switch (t) {
        case 'J': slot.j = static_cast<jlong>((int64_t) raw); break;
        case 'Z': slot.z = static_cast<jboolean>(raw); break;
        case 'B': slot.b = static_cast<jbyte>(raw); break;
        case 'C': slot.c = static_cast<jchar>(raw); break;
        case 'S': slot.s = static_cast<jshort>(raw); break;
        default:  slot.i = static_cast<jint>((int32_t) raw); break;
    }
}

} // namespace detail

std::string InvokeEvent::formatArgs() const {
    std::string out = "(";
    bool hasArg = false;
    if (!isStatic && receiver != nullptr) {
        out += "this=" + objectToString(env, receiver);
        hasArg = true;
    }
    std::vector<char> kinds;
    char retKind;
    parseSigTypes(signature, kinds, retKind);
    for (int i = 0; i < argc && i < static_cast<int>(kinds.size()); i++) {
        if (hasArg) out += ", ";
        out += (args != nullptr) ? formatValue(env, kinds[i], args[i]) : "?";
        hasArg = true;
    }
    if (argc > static_cast<int>(kinds.size())) out += ",...";
    out += ")";
    return out;
}

std::string InvokeEvent::formatMethod() const {
    // "Lcom/foo/Bar;.name(args)" -> "com.foo.Bar.name(args)"
    std::string cls = className;
    if (cls.size() > 2 && cls[0] == 'L' && cls.back() == ';') {
        cls = cls.substr(1, cls.size() - 2);
    }
    for (auto& ch : cls) if (ch == '/') ch = '.';
    return cls + "." + methodName + formatArgs();
}

std::string InvokeEvent::formatResult(const jvalue* ret, bool hasException) const {
    if (hasException) {
        std::string name = "exception";
        if (env != nullptr && env->ExceptionCheck()) {
            // Save the pending exception, clear it so JNI calls below are legal,
            // then re-throw so the business exception keeps propagating.
            jthrowable t = env->ExceptionOccurred();
            if (t != nullptr) {
                env->ExceptionClear();
                jclass cls = env->GetObjectClass(t);
                if (cls != nullptr) {
                    name = nativeClassDescriptor(env, cls);   // native, no Class.getName()
                    env->DeleteLocalRef(cls);
                }
                env->Throw(t);   // restore the original exception
                env->DeleteLocalRef(t);
            }
        }
        return "<exception: " + name + ">";
    }
    if (ret == nullptr) return "void";
    return formatReturnValue(env, signature, *ret);
}

uint64_t InvokeEvent::getArgRaw(int index) const {
    if (index < 0 || index >= argc || args == nullptr) return 0;
    return args[index].j;
}

std::string InvokeEvent::getArgString(int index) const {
    if (index < 0 || index >= argc || args == nullptr || env == nullptr) return "";
    char t = detail::paramTypeChar(signature, index);
    if (t == 'L') return objectToString(env, args[index].l);
    jvalue v = args[index];
    std::vector<char> kinds; char rk;
    parseSigTypes(signature, kinds, rk);
    if (t == 'D') return formatValue(env, 'D', v);
    if (t == 'F') return formatValue(env, 'F', v);
    return formatValue(env, t, v);
}

// ============================================================================
// §10 LogSink 已在 pi_logger.*; VMTrace 日志走 Logger (TRACE 通道)
// ============================================================================
bool isInterpretingOnCurrentThread(void* artMethod) {
    for (void* m : interpStack()) {
        if (m == artMethod) return true;
    }
    return false;
}

std::vector<InterpStackFrame> getInterpCallStack() {
    std::vector<InterpStackFrame> frames;
    auto& fs = frameStack();
    auto& is = interpStack();
    for (size_t i = 0; i < fs.size() && i < is.size(); i++) {
        if (fs[i] && is[i]) {
            frames.push_back({ is[i], fs[i]->pc, fs[i]->depth });
        }
    }
    return frames;
}

void setTraceEnabled(bool on) {
    g_traceEnabled.store(on, std::memory_order_relaxed);
}

bool isTraceEnabled() {
    return g_traceEnabled.load(std::memory_order_relaxed);
}

}} // namespace PI::Interp


