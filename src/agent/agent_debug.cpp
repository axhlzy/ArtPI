//
// agent_debug.cpp - Cooperative Debugger & Breakpoint domain bindings for QuickJS
//
#include "agent_debug.h"
#include "agent_common.h"
#include "agent_net.h"
#include "../../include/ArtPI.h"
#include "art/art_method.h"
#include "dex/pi_smali.h"
#include "sandbox/pi_interp_tracer.h"
#include "native/hooker/pi_gum_hooker.h"
#include "native/qbdi/pi_qbdi_engine.h"
#include "frida-gum.h"
#include "QBDI/State.h"

#include <string>
#include <vector>
#include <memory>
#include <mutex>
#include <condition_variable>
#include <sstream>
#include <iomanip>
#include <unistd.h>
#include <pthread.h>
#include <sys/prctl.h>
#include <sys/uio.h>
#include <sys/syscall.h>
#include <unwind.h>
#include <dlfcn.h>
#include <cstdio>
#include <dirent.h>
#include "native/pi_native.h"

namespace artpi { namespace agent {

namespace {

// Safely resolve all executable ranges for the module containing `addr`
// by parsing /proc/self/maps. Avoids gum_elf_module_load which crashes
// on execute-only memory mappings (SEGV_ACCERR).
static std::vector<std::pair<uintptr_t, uintptr_t>> ResolveModuleRanges(uintptr_t addr) {
    std::vector<std::pair<uintptr_t, uintptr_t>> ranges;
    FILE* f = fopen("/proc/self/maps", "r");
    if (!f) return ranges;

    // First pass: find the module path for the target address
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
            // Trim leading whitespace from path
            char* p = path;
            while (*p == ' ' || *p == '\t') p++;
            if (*p) strncpy(targetPath, p, sizeof(targetPath) - 1);
            break;
        }
    }

    if (!targetPath[0]) { fclose(f); return ranges; }

    // Second pass: collect all executable ranges for the same module
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

enum class DebugStepCommand {
    NONE = 0,
    STEP_IN = 1,
    STEP_OVER = 2,
    CONTINUE = 3,
    FINISH = 4
};

static std::mutex g_debugMutex;
static std::condition_variable g_debugCv;
static bool g_isThreadPaused = false;
static DebugStepCommand g_pendingCommand = DebugStepCommand::NONE;
static std::string g_pausedLocation;
thread_local DebugStepCommand t_runMode = DebugStepCommand::NONE;
thread_local int t_targetDepth = -1;

struct PausedRegs {
    bool isNative = false;
    void* rawGpr = nullptr;
    std::vector<std::string> regNames;
    std::vector<uint64_t> values;
    std::vector<uint8_t> flags;
    std::vector<std::string> decoded;
    std::string stackTrace;
    uint64_t* liveRegs = nullptr;
    uint8_t* liveFlags = nullptr;
    uint32_t pc = 0;
    int depth = 0;
    pid_t tid = 0;
    pid_t pid = 0;
    std::string threadName;
    std::string methodName;
    std::vector<jobject> pinned;
};
static PausedRegs g_pausedRegs;

static bool SafeReadMemory(void* dst, const void* src, size_t len) {
    if (!src || !dst || len == 0) return false;
    struct iovec local_iov = {dst, len};
    struct iovec remote_iov = {const_cast<void*>(src), len};
    ssize_t n = process_vm_readv(getpid(), &local_iov, 1, &remote_iov, 1, 0);
    return n == static_cast<ssize_t>(len);
}

static bool IsReasonableStackPointer(uintptr_t sp) {
    if (sp < 0x10000 || sp >= 0x800000000000ULL || (sp & 7) != 0) return false;
    uint64_t testWord = 0;
    return SafeReadMemory(&testWord, reinterpret_cast<const void*>(sp), sizeof(testWord));
}

static void ClearPinnedLocked() {
    if (g_pausedRegs.pinned.empty()) return;
    JNIEnv* env = GetEnv();
    if (!env) return;
    for (jobject o : g_pausedRegs.pinned) {
        if (o) env->DeleteGlobalRef(o);
    }
    g_pausedRegs.pinned.clear();
}

static std::string CurrentThreadName() {
    char name[64] = {0};
    prctl(PR_GET_NAME, name, 0, 0, 0);
    return name[0] ? std::string(name) : "<unnamed>";
}

static std::string DescribeJObject(JNIEnv* env, jobject obj) {
    if (!env) return "<no-env>";
    if (!obj) return "null";
    if (env->ExceptionCheck()) env->ExceptionClear();
    if (env->PushLocalFrame(16) < 0) return "<oom>";
    std::string out;
    jclass cls = env->GetObjectClass(obj);
    if (!cls) {
        if (env->ExceptionCheck()) env->ExceptionClear();
        env->PopLocalFrame(nullptr);
        return "<no-class>";
    }
    jclass classCls = AgentCachedClass("java/lang/Class");   // global ref, do not delete
    jmethodID getName = classCls ? env->GetMethodID(classCls, "getName", "()Ljava/lang/String;") : nullptr;
    if (env->ExceptionCheck()) env->ExceptionClear();
    std::string clsName;
    if (getName) {
        jstring jn = (jstring)env->CallObjectMethod(cls, getName);
        if (env->ExceptionCheck()) env->ExceptionClear();
        if (jn) {
            const char* c = env->GetStringUTFChars(jn, nullptr);
            if (c) { clsName = c; env->ReleaseStringUTFChars(jn, c); }
            env->DeleteLocalRef(jn);
        }
    }
    jmethodID toStr = env->GetMethodID(cls, "toString", "()Ljava/lang/String;");
    if (env->ExceptionCheck()) env->ExceptionClear();
    if (toStr) {
        jstring js = (jstring)env->CallObjectMethod(obj, toStr);
        if (env->ExceptionCheck()) {
            env->ExceptionClear();
            out = clsName.empty() ? "<toString-ex>" : (clsName + "{<toString-ex>}");
        } else if (js) {
            const char* c = env->GetStringUTFChars(js, nullptr);
            if (c) { out = c; env->ReleaseStringUTFChars(js, c); }
            env->DeleteLocalRef(js);
            if (out.size() > 120) { out.resize(117); out += "..."; }
        }
    } else {
        out = clsName.empty() ? "<obj>" : clsName;
    }
    env->PopLocalFrame(nullptr);
    return out;
}

static bool SafeRead(const void* src, void* dst, size_t len) {
    if (!src || !dst || len == 0) return false;
    struct iovec local_iov = { dst, len };
    struct iovec remote_iov = { const_cast<void*>(src), len };
    ssize_t n = syscall(SYS_process_vm_readv, getpid(), &local_iov, 1, &remote_iov, 1, 0);
    return n == static_cast<ssize_t>(len);
}

typedef int32_t (*GetLineNumFn)(void* art_method, uint32_t dex_pc);
static GetLineNumFn g_getLineNumFn = nullptr;
static bool g_lineNumResolved = false;

static int32_t ResolveLineNumber(void* art_method, uint32_t dex_pc) {
    if (!g_lineNumResolved) {
        g_lineNumResolved = true;
        void* art_h = xdl_open("libart.so", XDL_DEFAULT);
        if (!art_h) art_h = xdl_open("libart.so", XDL_TRY_FORCE_LOAD);
        if (art_h) {
            g_getLineNumFn = reinterpret_cast<GetLineNumFn>(
                xdl_sym(art_h, "_ZN3art9ArtMethod18GetLineNumFromDexPCEj", nullptr));
            if (!g_getLineNumFn) {
                g_getLineNumFn = reinterpret_cast<GetLineNumFn>(
                    xdl_dsym(art_h, "_ZN3art9ArtMethod18GetLineNumFromDexPCEj", nullptr));
            }
            xdl_close(art_h);
        }
    }
    if (g_getLineNumFn && art_method) {
        return g_getLineNumFn(art_method, dex_pc);
    }
    return -1;
}

static bool IsValidArtMethod(void* ptr) {
    if (!ptr) return false;
    uintptr_t addr = reinterpret_cast<uintptr_t>(ptr);
    if (addr < 0x10000 || (addr % alignof(void*)) != 0) return false;
    uint8_t probe[32];
    if (!SafeRead(ptr, probe, sizeof(probe))) return false;
    auto* am = reinterpret_cast<pine::art::ArtMethod*>(ptr);
    uint32_t decl_cls = am->GetDeclaringClass();
    if (decl_cls == 0) return false;
    return true;
}

// Crash-safe method pretty-printer. ART's PrettyMethod() dereferences the
// declaring class' DexCache and FATAL-aborts on a garbage ArtMethod*, which is
// easy to hit when unwinding a stack that contains Pine/trampoline synthetic
// frames. Only resolve via ART when the pointer actually lives in a mapped
// module; otherwise return the raw pointer annotated as untrusted.
static std::string SafePrettyMethod(void* m) {
    if (!m) return "<null>";
    uintptr_t a = reinterpret_cast<uintptr_t>(m);
    if (a < 0x1000 || (a & (alignof(void*) - 1)) != 0) {
        char b[32]; snprintf(b, sizeof(b), "%p", m); return b;
    }
    Dl_info di;
    if (!dladdr(m, &di) || !di.dli_fname) {
        char b[48]; snprintf(b, sizeof(b), "%p(heap?)", m); return b;
    }
    if (!IsValidArtMethod(m)) {
        char b[96]; snprintf(b, sizeof(b), "%p(%s invalid)", m, di.dli_fname); return b;
    }
    std::string s = PI::getPrettyMethodSignature(reinterpret_cast<ArtMethod*>(m));
    if (s.empty()) { char b[96]; snprintf(b, sizeof(b), "%p(%s)", m, di.dli_fname); return b; }
    return s;
}

struct ShadowFrameHeader {
    void* link;             // 0: ShadowFrame* link_
    void* method;           // 8: ArtMethod* method_
    void* result_register;  // 16
    void* dex_pc_ptr;       // 24
    void* dex_instructions; // 32
    void* lock_count_data;  // 40
    uint32_t num_vregs;     // 48 (const uint32_t number_of_vregs_)
    uint32_t dex_pc;        // 52
};

struct ManagedStackFragment {
    void* top_quick_frame;      // 0
    void* link;                 // 8
    void* top_shadow_frame;     // 16
};

struct JavaCallFrameInfo {
    void* artMethod;
    uint32_t dexPc;
};

static std::string CaptureNativeStack() {
    struct BtCtx { char* buf; size_t cap; size_t len; int depth; int max; };
    BtCtx st{nullptr, 0, 0, 0, 24};
    char buf[3072];
    st.buf = buf; st.cap = sizeof(buf); buf[0] = '\0';

    auto cb = +[](struct _Unwind_Context* ctx, void* arg) -> _Unwind_Reason_Code {
        auto* s = static_cast<BtCtx*>(arg);
        if (s->depth >= s->max || s->len + 128 >= s->cap) return _URC_END_OF_STACK;
        uintptr_t pc = _Unwind_GetIP(ctx);
        if (pc) {
            Dl_info info;
            int n;
            if (dladdr(reinterpret_cast<void*>(pc), &info) && info.dli_sname) {
                n = snprintf(s->buf + s->len, s->cap - s->len, "  #%02d %p %s (%s)\n",
                             s->depth, reinterpret_cast<void*>(pc), info.dli_sname,
                             info.dli_fname ? info.dli_fname : "?");
            } else {
                n = snprintf(s->buf + s->len, s->cap - s->len, "  #%02d %p\n",
                             s->depth, reinterpret_cast<void*>(pc));
            }
            if (n > 0) s->len += (size_t) n;
        }
        s->depth++;
        return _URC_NO_REASON;
    };
    _Unwind_Backtrace(cb, &st);
    return std::string(buf, st.len);
}

// ---------------------------------------------------------------------------
// Native ART quick-frame caller walk (route-3 boundary safe).
//
// When Pine hooks method M the trampoline stores the caller's SP in
// PineNativeContext::sp (== M's entry SP == caller K's frame base). ART keeps
// each quick frame's own ArtMethod* at its frame base (sp), and stepping to the
// caller means sp += frame_size(method). The frame size is decoded from the
// method's OatQuickMethodHeader CodeInfo. This walks memory only, never calling
// into the VM, so it is safe on the hook path (unlike StackVisitor::WalkStack,
// which FATAL-aborts on Pine's clobbered frame).
// ---------------------------------------------------------------------------
static constexpr uint32_t kCodeInfoVarintBits = 4;
static constexpr uint32_t kCodeInfoVarintMax = 11;
static constexpr uint32_t kArm64StackAlignment = 16;

static bool SafeReadU16(const void* src, uint16_t& out) {
    return SafeRead(src, &out, sizeof(out));
}
static bool SafeReadU32(const void* src, uint32_t& out) {
    return SafeRead(src, &out, sizeof(out));
}
static bool SafeReadPtr(const void* src, void*& out) {
    return SafeRead(src, &out, sizeof(out));
}

// Minimal port of art::BitMemoryReader::ReadInterleavedVarints (LSB-first bit
// order; values 0..11 inline, larger values carry their byte length).
static void DecodeCodeInfoHeader(const uint8_t* ci, uint32_t* out, size_t n) {
    size_t bit = 0;
    auto readBits = [&](size_t count) -> uint32_t {
        uint32_t v = 0;
        for (size_t i = 0; i < count; i++) {
            size_t bp = bit + i;
            uint32_t b = (ci[bp >> 3] >> (bp & 7)) & 1u;
            v |= b << i;
        }
        bit += count;
        return v;
    };
    uint64_t packed = 0;
    for (size_t i = 0; i < n; i++) {
        packed |= static_cast<uint64_t>(readBits(kCodeInfoVarintBits)) << (i * kCodeInfoVarintBits);
    }
    for (size_t i = 0; i < n; i++) {
        out[i] = static_cast<uint32_t>((packed >> (i * kCodeInfoVarintBits)) & 0xF);
    }
    for (size_t i = 0; i < n; i++) {
        if (out[i] > kCodeInfoVarintMax) {
            out[i] = readBits((out[i] - kCodeInfoVarintMax) * 8);
        }
    }
}

// Frame size (bytes) of an ArtMethod's quick frame, or 0 if unavailable.
static uint32_t ArtMethodFrameSize(void* methodPtr) {
    auto* am = reinterpret_cast<pine::art::ArtMethod*>(methodPtr);
    if (am == nullptr) return 0;

    if (am->IsCompiled()) {
        const int sdk = pine::Android::version;
        if (sdk < pine::Android::kR) return 0;
        void* entry = am->GetEntryPointFromCompiledCode();
        uintptr_t e = reinterpret_cast<uintptr_t>(entry);
        if (e < 0x10000) return 0;
        uint32_t code_info_offset = 0;
        if (sdk >= pine::Android::kS) {
            // Android 12+ (S+): PACKED(4) uint32_t data_ at e - 4.
            uint32_t data = 0;
            if (!SafeReadU32(reinterpret_cast<const void*>(e - 4), data)) return 0;
            if ((data & 0x40000000u) == 0) return 0;             // not optimized (no CodeInfo)
            code_info_offset = data & 0x3FFFFFFFu;
        } else {
            // Android 11 (R): vmap_table_offset_ at e - 8, code_size_ at e - 4.
            uint32_t vmap_off = 0, code_sz = 0;
            if (!SafeReadU32(reinterpret_cast<const void*>(e - 8), vmap_off) ||
                !SafeReadU32(reinterpret_cast<const void*>(e - 4), code_sz)) return 0;
            if ((code_sz & 0x7FFFFFFFu) == 0 || vmap_off == 0) return 0;
            code_info_offset = vmap_off;
        }
        if (code_info_offset == 0 || code_info_offset > 0x100000u) return 0;
        uint8_t ci[64];
        if (!SafeRead(reinterpret_cast<const void*>(e - code_info_offset), ci, sizeof(ci))) return 0;
        const size_t num_headers = (sdk >= pine::Android::kS) ? 7u : 6u;
        const size_t frame_idx   = (sdk >= pine::Android::kS) ? 2u : 1u;
        uint32_t hdr[7] = {0};
        DecodeCodeInfoHeader(ci, hdr, num_headers);
        uint32_t frame = hdr[frame_idx] * kArm64StackAlignment;  // packed_frame_size_ * alignment
        if (frame < kArm64StackAlignment || frame > 0x40000u || (frame & 0xFu) != 0) return 0;
        return frame;
    }

    // Not quick-compiled -> nterp (its frame is still a quick frame). Mirror
    // art::NterpGetFrameSize(arm64): entry(160) + 8*num_regs + 8 + 8 +
    // 4*out_regs + 8, rounded up to 16. For the switch interpreter there is no
    // quick frame at all, so the walk simply stops on the next invalid read.
    if (am->IsNative()) return 0;
    void* dp = am->GetEntryPointFromJni();                       // data_ == CodeItem* (& ~1)
    const uint8_t* ci = reinterpret_cast<const uint8_t*>(reinterpret_cast<uintptr_t>(dp) & ~1ULL);
    if (reinterpret_cast<uintptr_t>(ci) < 0x10000) return 0;

    PI::DexResolver dex;
    bool compact = dex.initFromMethod(am) && dex.isCompactDex();
    uint16_t num_regs = 0, out_regs = 0;
    if (compact) {
        uint16_t fields = 0, flags = 0;
        if (!SafeReadU16(ci + 0, fields) || !SafeReadU16(ci + 2, flags)) return 0;
        num_regs = (fields >> 12) & 0xFu;
        uint16_t ins_regs = (fields >> 8) & 0xFu;
        out_regs = (fields >> 4) & 0xFu;
        const uint16_t* preheader = reinterpret_cast<const uint16_t*>(ci);
        if (flags & (1u << 4)) preheader -= 2; // kFlagPreHeaderInsnsSize
        if (flags & (1u << 0)) {
            uint16_t ext = 0;
            if (!SafeReadU16(--preheader, ext)) return 0;
            num_regs += ext;
        }
        if (flags & (1u << 1)) {
            uint16_t ext = 0;
            if (!SafeReadU16(--preheader, ext)) return 0;
            ins_regs += ext;
        }
        if (flags & (1u << 2)) {
            uint16_t ext = 0;
            if (!SafeReadU16(--preheader, ext)) return 0;
            out_regs += ext;
        }
        // CompactDex stores (registers_size - ins_size) in fields[15:12].
        num_regs += ins_regs;
    } else {
        if (!SafeReadU16(ci + 0, num_regs) || !SafeReadU16(ci + 4, out_regs)) return 0;
    }
    size_t frame = 160 + 8 * num_regs + 8 + 8 + 4 * out_regs + 8;
    frame = (frame + 15u) & ~15u;
    if (frame < 160 || frame > 0x40000u) return 0;
    return static_cast<uint32_t>(frame);
}

// Walk the compiled/nterp quick-frame chain upward from `frameBase` (caller K's
// frame base). Appends one "Class.method(sig)" line per caller.
static void CaptureCallersViaNativeFrames(void* frameBase, std::vector<std::string>& out) {
    uintptr_t sp = reinterpret_cast<uintptr_t>(frameBase);
    if (sp < 0x1000) return;
    for (int i = 0; i < 128; i++) {
        void* m = nullptr;
        if (!SafeReadPtr(reinterpret_cast<const void*>(sp), m)) break;
        if (!IsValidArtMethod(m)) break;
        // Frames here are genuine quick frames (method pointer at frame base),
        // so resolving their names via ART is safe.
        std::string sig = PI::getPrettyMethodSignature(reinterpret_cast<ArtMethod*>(m));
        if (sig.empty()) {
            char b[32];
            snprintf(b, sizeof(b), "%p", m);
            sig = b;
        }
        out.push_back(std::move(sig));
        uint32_t f = ArtMethodFrameSize(m);
        if (f == 0) break;
        sp += f;
        if ((sp & 0xFu) != 0) break;
    }
}

static std::string CaptureJavaStack(ArtMethod* curMethod, const PI::Interp::InsnEvent& ev) {
    std::vector<JavaCallFrameInfo> frames;

    // 1. Current instruction frame (#00)
    void* topMethod = ev.artMethod ? ev.artMethod : reinterpret_cast<void*>(curMethod);
    if (topMethod) {
        frames.push_back({ topMethod, ev.pc });
    }

    // 2. Intermediate nmmvm interpreter frames (if depth > 0)
    std::vector<PI::Interp::InterpStackFrame> interpStack = PI::Interp::getInterpCallStack();
    if (interpStack.size() > 1) {
        for (int i = static_cast<int>(interpStack.size()) - 2; i >= 0; i--) {
            if (interpStack[i].artMethod) {
                frames.push_back({ interpStack[i].artMethod, interpStack[i].dexPc });
            }
        }
    }

    // #00 + interpreter frames are known-valid ArtMethods; name them directly.
    const size_t trustedCount = frames.size();

    // 3. ART caller frames (outside nmmvm). With the route-3 boundary active we
    //    walk the compiled quick-frame chain natively from the caller's frame
    //    base; otherwise fall back to the manual ShadowFrame / fragment walk.
    std::vector<std::string> callerLines;
    PI::Interp::ManagedStackSnapshot snap{};
    if (PI::Interp::getManagedStackSnapshot(snap)) {
        if (snap.callerFrameBase != nullptr) {
            CaptureCallersViaNativeFrames(snap.callerFrameBase, callerLines);
        }
        if (callerLines.empty()) {
        // Walk top_shadow_frame_
        void* sf = reinterpret_cast<void*>(snap.topShadowFrame);
        int sfCount = 0;
        while (sf != nullptr && sfCount < 64 && frames.size() < 128) {
            ShadowFrameHeader hdr{};
            if (!SafeRead(sf, &hdr, sizeof(hdr))) break;
            if (hdr.method != nullptr && IsValidArtMethod(hdr.method)) {
                if (frames.empty() || frames.back().artMethod != hdr.method) {
                    frames.push_back({ hdr.method, hdr.dex_pc });
                }
            }
            sf = hdr.link;
            sfCount++;
        }

        // Walk link_ (previous ManagedStack fragments)
        void* ms = reinterpret_cast<void*>(snap.link);
        int msCount = 0;
        while (ms != nullptr && msCount < 32 && frames.size() < 128) {
            ManagedStackFragment frag{};
            if (!SafeRead(ms, &frag, sizeof(frag))) break;

            if (frag.top_shadow_frame != nullptr) {
                void* cur_sf = frag.top_shadow_frame;
                int sfd = 0;
                while (cur_sf != nullptr && sfd < 64 && frames.size() < 128) {
                    ShadowFrameHeader hdr{};
                    if (!SafeRead(cur_sf, &hdr, sizeof(hdr))) break;
                    if (hdr.method != nullptr && IsValidArtMethod(hdr.method)) {
                        if (frames.empty() || frames.back().artMethod != hdr.method) {
                            frames.push_back({ hdr.method, hdr.dex_pc });
                        }
                    }
                    cur_sf = hdr.link;
                    sfd++;
                }
            }

            if (frag.top_quick_frame != nullptr) {
                uintptr_t qf = reinterpret_cast<uintptr_t>(frag.top_quick_frame) & ~1ULL;
                void* q_method = nullptr;
                if (SafeRead(reinterpret_cast<void*>(qf), &q_method, sizeof(q_method))) {
                    if (q_method != nullptr && IsValidArtMethod(q_method)) {
                        if (frames.empty() || frames.back().artMethod != q_method) {
                            frames.push_back({ q_method, 0 });
                        }
                    }
                }
            }

            ms = frag.link;
            msCount++;
        }
        }
    }

    if (frames.empty() && callerLines.empty()) {
        return CaptureNativeStack();
    }

    std::ostringstream ss;
    for (size_t i = 0; i < frames.size(); i++) {
        char buf[512];
        void* m = frames[i].artMethod;
        uint32_t pc = frames[i].dexPc;
        // Frames up to trustedCount (#00 + interpreter frames) are valid
        // ArtMethods -> name them directly. Walked caller frames may be garbage
        // (Pine synthetic frames), so resolve those defensively.
        bool knownValid = i < trustedCount;
        std::string sig = knownValid
            ? PI::getPrettyMethodSignature(reinterpret_cast<ArtMethod*>(m))
            : SafePrettyMethod(m);
        bool trusted = knownValid || (!sig.empty() && sig[0] != '0' &&
                       sig.find("(heap?)") == std::string::npos &&
                       sig.find("invalid)") == std::string::npos);
        int line = trusted ? ResolveLineNumber(m, pc) : -1;
        if (sig.empty()) sig = "<unknown method>";

        if (line > 0) {
            snprintf(buf, sizeof(buf), "  #%02zu %s [dex_pc=0x%x, line %d]\n",
                     i, sig.c_str(), pc, line);
        } else {
            snprintf(buf, sizeof(buf), "  #%02zu %s [dex_pc=0x%x]\n",
                     i, sig.c_str(), pc);
        }
        ss << buf;
    }
    // Native quick-frame caller chain (Class.method(sig) lines).
    for (size_t k = 0; k < callerLines.size(); k++) {
        char hdr[24];
        snprintf(hdr, sizeof(hdr), "  #%02zu ", frames.size() + k);
        ss << hdr << callerLines[k] << "\n";
    }
    return ss.str();
}

static std::string FormatSmaliStepView(ArtMethod* method, const PI::Interp::InsnEvent& ev) {
    PausedRegs snap;
    snap.isNative = false;
    snap.rawGpr = nullptr;
    snap.regNames.clear();
    uint32_t n = ev.regsSize;
    if (n == 0 || n > 64) n = 16;
    snap.liveRegs = ev.regs;
    snap.liveFlags = ev.regFlags;
    snap.pc = ev.pc;
    snap.depth = ev.depth;
    snap.tid = gettid();
    snap.pid = getpid();
    snap.threadName = CurrentThreadName();
    if (method) snap.methodName = PI::getPrettyMethodSignature(method);
    if (ev.regs) {
        snap.values.assign(ev.regs, ev.regs + n);
        if (ev.regFlags) snap.flags.assign(ev.regFlags, ev.regFlags + n);
        else snap.flags.assign(n, 0);
        snap.decoded.resize(n);
        for (uint32_t i = 0; i < n; i++) {
            if (snap.flags[i] && ev.env) {
                snap.decoded[i] = DescribeJObject(ev.env, reinterpret_cast<jobject>(snap.values[i]));
            }
        }
    }
    snap.stackTrace = CaptureJavaStack(method, ev);
    {
        std::lock_guard<std::mutex> lk(g_debugMutex);
        ClearPinnedLocked();
        g_pausedRegs = std::move(snap);
    }

    std::ostringstream ss;
    ss << PI::dumpSmali(method, -1, static_cast<int>(ev.pc));
    ss << "  regs";
    const PausedRegs& r = g_pausedRegs;
    if (r.values.empty()) {
        ss << " <unavailable>";
    } else {
        for (size_t i = 0; i < r.values.size(); i++) {
            char buf[32];
            snprintf(buf, sizeof(buf), "0x%llx", (unsigned long long)r.values[i]);
            ss << " v" << i << "=" << buf;
            if (i < r.flags.size() && r.flags[i]) {
                ss << "(obj";
                if (i < r.decoded.size() && !r.decoded[i].empty()) {
                    ss << " " << r.decoded[i];
                }
                ss << ")";
            }
        }
    }
    ss << "\n  pc=0x" << std::hex << ev.pc << std::dec
       << "  depth=" << ev.depth
       << "  tid=" << (int)gettid()
       << "  thread=" << CurrentThreadName()
       << "\n  [s]tep-in  [n]ext  [c]ontinue  [r]eturn  [bt]  [regs.vN / regs.set / inspect]\n";
    return ss.str();
}

struct BreakpointSession {
    size_t id;
    std::string location;
    bool is_active;
    PI::HookHandle java_handle;
    PI::Native::NativeHookHandle native_handle;
};

static std::vector<BreakpointSession> g_activeBreakpoints;
static size_t g_nextBpId = 0;
static std::mutex g_bpMutex;

static void OnBreakpointHit(const std::string& location) {
    std::unique_lock<std::mutex> lk(g_debugMutex);
    g_isThreadPaused = true;
    g_pausedLocation = location;
    g_pendingCommand = DebugStepCommand::NONE;

    BroadcastLog("debug", location);

    // Cooperative sleep: wait until CLI REPL user sends single-letter stepping command
    g_debugCv.wait(lk, []() {
        return g_pendingCommand != DebugStepCommand::NONE;
    });

    g_isThreadPaused = false;
    g_debugCv.notify_all();
}

static std::string FormatNativeStepView(ArtMethod* method, void* fn, uintptr_t pc,
                                        const char* mnem, const char* disasm, void* rawGpr) {
    std::ostringstream ss;
    void* entry = fn ? fn : reinterpret_cast<void*>(pc);
    ss << PI::dumpNative(entry, 21, method, pc);
    (void)mnem; (void)disasm;

    auto* gpr = reinterpret_cast<QBDI::GPRState*>(rawGpr);

    // Save snapshot to g_pausedRegs so REPL regs / getreg / setreg work in native mode!
    {
        std::lock_guard<std::mutex> lk(g_debugMutex);
        ClearPinnedLocked();
        PausedRegs snap;
        snap.isNative = true;
        snap.rawGpr = rawGpr;
        snap.tid = gettid();
        snap.pid = getpid();
        snap.pc = static_cast<uint32_t>(pc);
        snap.depth = 0;
        snap.threadName = CurrentThreadName();
        if (method) snap.methodName = PI::getPrettyMethodSignature(method);
        else snap.methodName = "";

        if (gpr) {
            snap.values.resize(33);
            snap.regNames.resize(33);
            for (int i = 0; i <= 28; i++) {
                char nm[8];
                snprintf(nm, sizeof(nm), "x%d", i);
                snap.regNames[i] = nm;
                snap.values[i] = (&gpr->x0)[i];
            }
            snap.regNames[29] = "fp"; snap.values[29] = gpr->x29;
            snap.regNames[30] = "lr"; snap.values[30] = gpr->lr;
            snap.regNames[31] = "sp"; snap.values[31] = gpr->sp;
            snap.regNames[32] = "pc"; snap.values[32] = gpr->pc;
        }
        g_pausedRegs = std::move(snap);
    }

    if (gpr) {
        auto fmtReg = [](const char* name, uint64_t val) -> std::string {
            char buf[48];
            snprintf(buf, sizeof(buf), "%s=0x%llx", name, (unsigned long long)val);
            return std::string(buf);
        };

        ss << "  regs\n";
        char b[200];
        snprintf(b, sizeof(b), "    %-23s %-23s %-23s %-23s\n",
                 fmtReg("x0", gpr->x0).c_str(), fmtReg("x1", gpr->x1).c_str(),
                 fmtReg("x2", gpr->x2).c_str(), fmtReg("x3", gpr->x3).c_str());
        ss << b;
        snprintf(b, sizeof(b), "    %-23s %-23s %-23s %-23s\n",
                 fmtReg("x4", gpr->x4).c_str(), fmtReg("x5", gpr->x5).c_str(),
                 fmtReg("x6", gpr->x6).c_str(), fmtReg("x7", gpr->x7).c_str());
        ss << b;
        snprintf(b, sizeof(b), "    %-23s %-23s %-23s %-23s\n",
                 fmtReg("x8", gpr->x8).c_str(), fmtReg("fp", gpr->x29).c_str(),
                 fmtReg("lr", gpr->lr).c_str(), fmtReg("sp", gpr->sp).c_str());
        ss << b;

        std::vector<std::string> extraItems;
        const uint64_t* x = &gpr->x0;
        for (int i = 9; i <= 28; i++) {
            if (x[i] != 0) {
                char nm[8];
                snprintf(nm, sizeof(nm), "x%d", i);
                extraItems.push_back(fmtReg(nm, x[i]));
            }
        }
        for (size_t i = 0; i < extraItems.size(); i += 4) {
            char eb[200];
            std::string c0 = extraItems[i];
            std::string c1 = (i + 1 < extraItems.size()) ? extraItems[i + 1] : "";
            std::string c2 = (i + 2 < extraItems.size()) ? extraItems[i + 2] : "";
            std::string c3 = (i + 3 < extraItems.size()) ? extraItems[i + 3] : "";
            snprintf(eb, sizeof(eb), "    %-23s %-23s %-23s %-23s\n",
                     c0.c_str(), c1.c_str(), c2.c_str(), c3.c_str());
            ss << eb;
        }

        // Stack view under regs if sp is reasonable
        if (IsReasonableStackPointer(gpr->sp)) {
            ss << "  stack (sp=0x" << std::hex << (unsigned long long)gpr->sp << std::dec << ")\n";
            for (int i = 0; i < 6; i++) {
                uintptr_t curAddr = gpr->sp + i * 8;
                uint64_t val = 0;
                if (!SafeReadMemory(&val, reinterpret_cast<const void*>(curAddr), sizeof(val))) break;
                std::string tag;
                if (curAddr == gpr->x29) tag += " (fp)";
                if (val == gpr->lr) tag += " (lr)";
                if (val == gpr->x29) tag += " (*fp)";

                std::string sym = PI::resolveAddressSymbol(static_cast<uintptr_t>(val));

                char sb[256];
                snprintf(sb, sizeof(sb), "    [sp+0x%02x] 0x%016llx%s%s%s\n",
                         i * 8, (unsigned long long)val, tag.c_str(),
                         sym.empty() ? "" : " ", sym.c_str());
                ss << sb;
            }
        }
    }

    char b[120];
    snprintf(b, sizeof(b), "  pc=0x%llx  tid=%d  thread=%s\n",
             (unsigned long long)pc, (int)gettid(), CurrentThreadName().c_str());
    ss << b;
    ss << "  [s]tep-in  [n]ext  [c]ontinue  [r]eturn  [bt]  [regs / stack / threads]\n";
    return ss.str();
}

static jvalue RunNativeStepped(const PI::Interp::InvokeEvent& ie) {
    jvalue ret{};
    ret.j = 0;
    if (!ie.env) return ret;
    std::string cn = ie.className;
    if (cn.size() > 2 && cn[0] == 'L' && cn.back() == ';') cn = cn.substr(1, cn.size() - 2);
    for (char& ch : cn) if (ch == '/') ch = '.';
    ArtMethod* am = reinterpret_cast<ArtMethod*>(ie.artMethod);
    if (!am) {
        PI::Method nm = PI::resolve(ie.env, cn, ie.methodName, ie.signature);
        if (nm.isValid()) am = nm.getArtMethod();
    }
    if (!am) return ret;
    void* fn = PI::resolveNativeMethod(am, ie.env);
    if (!fn) fn = am->GetEntryPointFromJni();
    if (!fn) return ret;

    jclass staticClazz = nullptr;
    if (ie.isStatic) {
        std::string slash = cn;
        for (char& ch : slash) if (ch == '.') ch = '/';
        staticClazz = ie.env->FindClass(slash.c_str());
        if (ie.env->ExceptionCheck()) { ie.env->ExceptionClear(); staticClazz = nullptr; }
    }
    std::vector<uint64_t> gprs;
    gprs.assign(8, 0);
    int xi = 0;
    gprs[xi++] = (uint64_t)(uintptr_t)ie.env;
    gprs[xi++] = (uint64_t)(uintptr_t)(ie.isStatic ? (void*)staticClazz : (void*)ie.receiver);
    const std::string& sig = ie.signature;
    size_t p = sig.find('(');
    size_t e = sig.find(')');
    int ai = 0;
    if (p != std::string::npos && e != std::string::npos) {
        for (size_t i = p + 1; i < e && ai < ie.argc && xi < 8; ) {
            char t = sig[i];
            if (t == 'L') {
                while (i < e && sig[i] != ';') i++;
                if (i < e) i++;
                gprs[xi++] = (uint64_t)(uintptr_t)ie.args[ai++].l;
            } else if (t == '[') {
                while (i < e && sig[i] == '[') i++;
                if (i < e && sig[i] == 'L') { while (i < e && sig[i] != ';') i++; if (i < e) i++; }
                else i++;
                gprs[xi++] = (uint64_t)(uintptr_t)ie.args[ai++].l;
            } else if (t == 'J') {
                i++;
                gprs[xi++] = (uint64_t)ie.args[ai++].j;
            } else if (t == 'D' || t == 'F') {
                i++;
                ai++;
            } else {
                i++;
                gprs[xi++] = (uint32_t)ie.args[ai++].i;
            }
        }
    }

    auto* engine = PI::Native::QBDIEngine::current();
    // Use safe /proc/self/maps resolution instead of QBDI's
    // addInstrumentedModuleFromAddr which internally calls gum_elf_module_load
    // and crashes on execute-only memory mappings (SEGV_ACCERR).
    engine->clearInstrumentedRanges();
    auto moduleRanges = ResolveModuleRanges((uintptr_t)fn);
    if (moduleRanges.empty()) {
        // Fallback: instrument a 1MB range starting at fn
        engine->addInstrumentedRange((uintptr_t)fn, (uintptr_t)fn + (1u << 20));
    } else {
        for (auto& r : moduleRanges) {
            engine->addInstrumentedRange(r.first, r.second);
        }
    }
    engine->setInstructionBudget(200000);
    t_runMode = DebugStepCommand::NONE;
    engine->setInstructionCallback(
        [am, fn](uintptr_t pc, const char* mnem, const char* disasm, int /*depth*/, void* gpr) -> int {
            if (t_runMode == DebugStepCommand::CONTINUE || t_runMode == DebugStepCommand::FINISH) {
                return 0;
            }
            std::string view = FormatNativeStepView(am, fn, pc, mnem, disasm, gpr);
            OnBreakpointHit(view);
            t_runMode = g_pendingCommand;
            return 0;
        });
    auto rr = engine->run(fn, gprs, {});
    engine->setInstructionCallback(std::function<int(uintptr_t, const char*, const char*, int, void*)>{});
    if (staticClazz) ie.env->DeleteLocalRef(staticClazz);

    char retCh = 'V';
    if (e != std::string::npos && e + 1 < sig.size()) retCh = sig[e + 1];
    if (retCh == 'L' || retCh == '[') ret.l = reinterpret_cast<jobject>(rr.gprResult);
    else if (retCh == 'J') ret.j = (jlong)rr.gprResult;
    else if (retCh == 'V') ret.j = 0;
    else ret.i = (jint)rr.gprResult;
    return ret;
}

// --- breakpoint condition (`cond` lambda) -----------------------------------
static std::shared_ptr<JSValue> GuardJs(JSValue v) {
    return std::shared_ptr<JSValue>(new JSValue(v), [](JSValue* p) {
        if (p) {
            if (g_ctx && !JS_IsUndefined(*p)) JS_FreeValue(g_ctx, *p);
            delete p;
        }
    });
}

// No cond (undefined) -> always true.
static bool EvalCond(const std::shared_ptr<JSValue>& cond, JSValueConst ev) {
    if (!cond || JS_IsUndefined(*cond)) return true;
    JSContext* c = g_ctx;
    if (!c) return true;
    // Reentrant on the JS eval thread: evaluating the condition would re-enter
    // QuickJS / deadlock, and pausing the JS thread would block the REPL. Skip it.
    if (t_jsReentrancyDepth > 0) return false;
    std::lock_guard<std::mutex> lk(g_jsMutex);
    JSValue r = JS_Call(c, *cond, JS_UNDEFINED, 1, &ev);
    bool ok = true;
    if (JS_IsException(r)) {
        JS_FreeValue(c, JS_GetException(c));
        ok = false;
    } else {
        ok = (JS_ToBool(c, r) != 0);
    }
    JS_FreeValue(c, r);
    return ok;
}

static JSValue MakeJavaCondEvent(JSContext* c, PI::CallFrame& f) {
    JSValue o = JS_NewObject(c);
    JS_SetPropertyStr(c, o, "method", JS_NewString(c, f.getMethodName().c_str()));
    JS_SetPropertyStr(c, o, "class", JS_NewString(c, f.class_name.c_str()));
    JS_SetPropertyStr(c, o, "argc", JS_NewInt32(c, f.getArgCount()));
    JSValue args = JS_NewArray(c);
    for (int i = 0; i < f.getArgCount(); i++) {
        JS_SetPropertyUint32(c, args, (uint32_t) i, JS_NewBigInt64(c, (int64_t) f.getArgRaw(i)));
    }
    JS_SetPropertyStr(c, o, "args", args);
    JS_SetPropertyStr(c, o, "str", JS_NewString(c, f.toValueString().c_str()));
    return o;
}

static JSValue MakeNativeCondEvent(JSContext* c, uint64_t addr, GumInvocationContext* g) {
    JSValue o = JS_NewObject(c);
    JS_SetPropertyStr(c, o, "address", JS_NewBigInt64(c, (int64_t) addr));
    JSValue args = JS_NewArray(c);
    for (int i = 0; i < 8; i++) {
        gpointer a = g ? gum_invocation_context_get_nth_argument(g, (guint) i) : nullptr;
        JS_SetPropertyUint32(c, args, (uint32_t) i, JS_NewBigInt64(c, (int64_t)(intptr_t) a));
    }
    JS_SetPropertyStr(c, o, "args", args);
    return o;
}

JSValue JsBreakJava(JSContext* ctx, JSValueConst /*this_val*/, int argc, JSValueConst* argv) {
    if (argc < 1) return JS_NewString(ctx, "Usage: brkj(methodOrArtPtr, [condLambda], [className], [methodName], [sig])");
    int64_t ptr = ParsePtr(ctx, argv[0]);
    if (!ptr || ptr < 0x1000) return JS_NewString(ctx, "[!] Invalid method pointer");

    std::string optClass, optMethod, optSig;
    if (argc >= 3 && JS_IsString(argv[2])) {
        const char* s = JS_ToCString(ctx, argv[2]);
        if (s) { optClass = s; JS_FreeCString(ctx, s); }
    }
    if (argc >= 4 && JS_IsString(argv[3])) {
        const char* s = JS_ToCString(ctx, argv[3]);
        if (s) { optMethod = s; JS_FreeCString(ctx, s); }
    }
    if (argc >= 5 && JS_IsString(argv[4])) {
        const char* s = JS_ToCString(ctx, argv[4]);
        if (s) { optSig = s; JS_FreeCString(ctx, s); }
    }

    PI::Method m;
    if (!optClass.empty() && !optMethod.empty() && !optSig.empty()) {
        JNIEnv* env = GetEnv();
        if (env) {
            jclass clazz = FindClassWithFallback(env, optClass);
            if (clazz) {
                m = PI::resolve(env, clazz, optMethod, optSig);
                env->DeleteLocalRef(clazz);
            }
        }
    }
    if (!m.isValid()) {
        m = PI::resolve(reinterpret_cast<ArtMethod*>(ptr));
    }
    if (!m.isValid() && ptr) {
        m = PI::Method(nullptr, nullptr, nullptr, reinterpret_cast<ArtMethod*>(ptr),
                       optMethod.empty() ? "ArtMethod" : optMethod, optSig,
                       reinterpret_cast<ArtMethod*>(ptr)->IsStatic());
    }
    if (!m.isValid()) return JS_NewString(ctx, "[!] Cannot resolve ArtMethod");

    // last-one-wins: drop any existing hook/trace/breakpoint on this ArtMethod
    // before arming a new breakpoint (a method carries only one trampoline).
    {
        int rel = AgentReleaseMethodInstrumentation(reinterpret_cast<void*>(m.getArtMethod()));
        if (rel) {
            BroadcastLog("console", std::string("[break] replaced existing ") +
                                        FormatReleasedInstrumentation(rel) + " on " + m.toString());
        }
    }

    std::string loc = m.toString();
    if (loc.empty()) loc = "ArtMethod";
    ArtMethod* art = m.getArtMethod();
    bool isNative = m.isNative();

    std::shared_ptr<JSValue> cond;
    if (argc >= 2 && JS_IsFunction(ctx, argv[1])) cond = GuardJs(JS_DupValue(ctx, argv[1]));

    PI::HookHandle hh = m.hook([loc, art, isNative, cond](JNIEnv* /*env*/, PI::CallFrame& frame) {
        // Condition gate: falsy -> skip the breakpoint entirely, run original.
        if (cond && !JS_IsUndefined(*cond)) {
            JSContext* c = g_ctx;
            bool proceed = true;
            if (c) {
                JSValue ev = MakeJavaCondEvent(c, frame);
                proceed = EvalCond(cond, ev);
                JS_FreeValue(c, ev);
            }
            if (!proceed) { frame.invokeOriginal(); return; }
        }
        if (!art || isNative) {
            OnBreakpointHit(loc + " " + frame.toValueString());
            frame.invokeOriginal();
            return;
        }
        t_runMode = DebugStepCommand::NONE;
        t_targetDepth = -1;
        PI::Interp::Callbacks cbs;
        cbs.onInsn = [art](const PI::Interp::InsnEvent& ev) -> bool {
            if (t_runMode == DebugStepCommand::CONTINUE) return true;
            if (t_runMode == DebugStepCommand::FINISH) {
                if (ev.depth > t_targetDepth) return true;
                t_runMode = DebugStepCommand::NONE;
            }
            ArtMethod* cur = ev.artMethod ? reinterpret_cast<ArtMethod*>(ev.artMethod) : art;
            std::string view = FormatSmaliStepView(cur, ev);
            OnBreakpointHit(view);
            t_runMode = g_pendingCommand;
            if (t_runMode == DebugStepCommand::FINISH) {
                t_targetDepth = (ev.depth > 0) ? (ev.depth - 1) : -1;
            }
            return true;
        };
        cbs.onInvoke = [](const PI::Interp::InvokeEvent& ie, jvalue* mockRet) {
            if (t_runMode != DebugStepCommand::STEP_IN) {
                return PI::Interp::InvokeVerdict::JniDirect;
            }
            t_runMode = DebugStepCommand::NONE;
            if (ie.isNative) {
                jvalue rv = RunNativeStepped(ie);
                if (mockRet) *mockRet = rv;
                return PI::Interp::InvokeVerdict::Mock;
            }
            return PI::Interp::InvokeVerdict::StepIn;
        };
        frame.invokeInterpretedWith(cbs);
        t_runMode = DebugStepCommand::NONE;
    });
    if (!hh.isHooked()) {
        return JS_NewString(ctx, "[!] Failed to set Java breakpoint");
    }
    BroadcastLog("debug", std::string("[Breakpoint] Armed (smali-step) at ") + loc + " — waiting for next call...");

    std::lock_guard<std::mutex> lk(g_bpMutex);
    size_t id = g_nextBpId++;
    BreakpointSession bp;
    bp.id = id;
    bp.location = loc;
    bp.is_active = true;
    bp.java_handle = hh;
    g_activeBreakpoints.push_back(std::move(bp));

    char resBuf[128];
    snprintf(resBuf, sizeof(resBuf), "Breakpoint %zu set at Java method: %s", id, loc.c_str());
    return JS_NewString(ctx, resBuf);
}

JSValue JsBreakNative(JSContext* ctx, JSValueConst /*this_val*/, int argc, JSValueConst* argv) {
    if (argc < 1) return JS_NewString(ctx, "Usage: brkn(addressOrSymbol, [condLambda])");
    int64_t addr = ParsePtr(ctx, argv[0]);
    if (!addr || addr < 0x1000) return JS_NewString(ctx, "[!] Invalid native address");

    char buf[64];
    snprintf(buf, sizeof(buf), "0x%llx", (unsigned long long)addr);
    std::string loc = buf;

    std::shared_ptr<JSValue> cond;
    if (argc >= 2 && JS_IsFunction(ctx, argv[1])) cond = GuardJs(JS_DupValue(ctx, argv[1]));

    void* target = reinterpret_cast<void*>(addr);
    PI::Native::NativeHookHandle nh = PI::Native::GumHooker::hook(target,
        [loc, addr, cond](GumInvocationContext* g) {
            if (cond && !JS_IsUndefined(*cond)) {
                JSContext* c = g_ctx;
                bool proceed = true;
                if (c) {
                    JSValue ev = MakeNativeCondEvent(c, (uint64_t) addr, g);
                    proceed = EvalCond(cond, ev);
                    JS_FreeValue(c, ev);
                }
                if (!proceed) return;
            }
            OnBreakpointHit(loc);
        });

    if (!nh.isValid()) {
        return JS_NewString(ctx, "[!] Failed to set Native breakpoint");
    }

    std::lock_guard<std::mutex> lk(g_bpMutex);
    size_t id = g_nextBpId++;
    BreakpointSession bp;
    bp.id = id;
    bp.location = loc;
    bp.is_active = true;
    bp.native_handle = std::move(nh);
    g_activeBreakpoints.push_back(std::move(bp));

    char resBuf[128];
    snprintf(resBuf, sizeof(resBuf), "Breakpoint %zu set at native address: %s", id, loc.c_str());
    return JS_NewString(ctx, resBuf);
}

JSValue JsContinue(JSContext* ctx, JSValueConst /*this_val*/, int /*argc*/, JSValueConst* /*argv*/) {
    std::lock_guard<std::mutex> lk(g_debugMutex);
    if (!g_isThreadPaused) return JS_NewString(ctx, "[*] No thread paused at breakpoint");
    g_pendingCommand = DebugStepCommand::CONTINUE;
    g_debugCv.notify_all();
    return JS_NewString(ctx, "Continuing execution...");
}

JSValue JsStep(JSContext* ctx, JSValueConst /*this_val*/, int /*argc*/, JSValueConst* /*argv*/) {
    std::lock_guard<std::mutex> lk(g_debugMutex);
    if (!g_isThreadPaused) return JS_NewString(ctx, "[*] No thread paused at breakpoint");
    g_pendingCommand = DebugStepCommand::STEP_IN;
    g_debugCv.notify_all();
    return JS_NewString(ctx, "Stepping in...");
}

JSValue JsNext(JSContext* ctx, JSValueConst /*this_val*/, int /*argc*/, JSValueConst* /*argv*/) {
    std::lock_guard<std::mutex> lk(g_debugMutex);
    if (!g_isThreadPaused) return JS_NewString(ctx, "[*] No thread paused at breakpoint");
    g_pendingCommand = DebugStepCommand::STEP_OVER;
    g_debugCv.notify_all();
    return JS_NewString(ctx, "Stepping over...");
}

JSValue JsReturn(JSContext* ctx, JSValueConst /*this_val*/, int /*argc*/, JSValueConst* /*argv*/) {
    std::lock_guard<std::mutex> lk(g_debugMutex);
    if (!g_isThreadPaused) return JS_NewString(ctx, "[*] No thread paused at breakpoint");
    // At the top-level smali frame (depth 0), "finish frame" has nothing to
    // unwind to, so it is equivalent to "continue to completion".
    if (g_pausedRegs.depth <= 0) {
        g_pendingCommand = DebugStepCommand::CONTINUE;
        g_debugCv.notify_all();
        return JS_NewString(ctx, "Continuing execution...");
    }
    g_pendingCommand = DebugStepCommand::FINISH;
    g_debugCv.notify_all();
    return JS_NewString(ctx, "Finishing frame...");
}

JSValue JsBt(JSContext* ctx, JSValueConst /*this_val*/, int /*argc*/, JSValueConst* /*argv*/) {
    std::lock_guard<std::mutex> lk(g_debugMutex);
    if (!g_isThreadPaused) return JS_NewString(ctx, "[*] No thread paused at breakpoint (bt is debug-only)");
    if (g_pausedRegs.stackTrace.empty()) return JS_NewString(ctx, "[*] No stack captured");
    return JS_NewString(ctx, g_pausedRegs.stackTrace.c_str());
}

JSValue JsInspect(JSContext* ctx, JSValueConst /*this_val*/, int argc, JSValueConst* argv) {
    if (argc < 1) return JS_NewString(ctx, "Usage: inspect(vN | ptr)  e.g. inspect(\"v1\") / inspect(1) / inspect(0x77aa...)");
    std::lock_guard<std::mutex> lk(g_debugMutex);
    if (!g_isThreadPaused) return JS_NewString(ctx, "[*] No thread paused at breakpoint (inspect is debug-only)");

    int regIdx = -1;
    uint64_t ptr = 0;
    if (JS_IsString(argv[0])) {
        const char* s = JS_ToCString(ctx, argv[0]);
        if (s) {
            if ((s[0] == 'v' || s[0] == 'V') && s[1] >= '0' && s[1] <= '9') {
                regIdx = atoi(s + 1);
            } else if (s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) {
                ptr = strtoull(s, nullptr, 16);
            } else {
                ptr = strtoull(s, nullptr, 0);
            }
            JS_FreeCString(ctx, s);
        }
    } else {
        int64_t v = ParsePtr(ctx, argv[0]);
        if (v >= 0 && v < 64 && (uint64_t)v < g_pausedRegs.values.size()) regIdx = (int)v;
        else ptr = (uint64_t)v;
    }

    auto formatOne = [](size_t i, const PausedRegs& r) {
        char buf[512];
        snprintf(buf, sizeof(buf), "v%zu=0x%llx%s%s", i,
                 (unsigned long long)(i < r.values.size() ? r.values[i] : 0),
                 (i < r.flags.size() && r.flags[i]) ? " (obj) " : " ",
                 (i < r.decoded.size()) ? r.decoded[i].c_str() : "");
        return std::string(buf);
    };

    if (regIdx >= 0) {
        if ((size_t)regIdx >= g_pausedRegs.values.size()) {
            return JS_NewString(ctx, "[!] register index out of range");
        }
        return JS_NewString(ctx, formatOne((size_t)regIdx, g_pausedRegs).c_str());
    }
    if (ptr != 0) {
        for (size_t i = 0; i < g_pausedRegs.values.size(); i++) {
            if (g_pausedRegs.values[i] == ptr) {
                return JS_NewString(ctx, formatOne(i, g_pausedRegs).c_str());
            }
        }
        char buf[128];
        snprintf(buf, sizeof(buf), "0x%llx (not in current vregs; decoded at pause only)", (unsigned long long)ptr);
        return JS_NewString(ctx, buf);
    }
    return JS_NewString(ctx, "[!] inspect: invalid argument");
}

static int ParseRegIndex(JSContext* ctx, JSValueConst val, size_t limit, const std::vector<std::string>& regNames) {
    if (JS_IsString(val)) {
        const char* s = JS_ToCString(ctx, val);
        if (!s) return -1;
        std::string str(s);
        JS_FreeCString(ctx, s);
        for (char& c : str) c = std::tolower(c);

        for (size_t i = 0; i < regNames.size(); i++) {
            if (str == regNames[i]) return static_cast<int>(i);
        }
        if (str[0] == 'v' && str.size() > 1 && isdigit(str[1])) {
            int idx = atoi(str.c_str() + 1);
            if (idx >= 0 && (size_t)idx < limit) return idx;
        }
        if (str[0] == 'x' && str.size() > 1 && isdigit(str[1])) {
            int idx = atoi(str.c_str() + 1);
            if (idx >= 0 && (size_t)idx < limit) return idx;
        }
        if (str == "fp" && limit > 29) return 29;
        if (str == "lr" && limit > 30) return 30;
        if (str == "sp" && limit > 31) return 31;
        if (str == "pc" && limit > 32) return 32;

        if (isdigit(str[0])) {
            int idx = atoi(str.c_str());
            if (idx >= 0 && (size_t)idx < limit) return idx;
        }
        return -1;
    }
    int64_t v = 0;
    if (JS_IsNumber(val) || JS_IsBigInt(ctx, val)) v = ParsePtr(ctx, val);
    if (v < 0 || (size_t)v >= limit) return -1;
    return (int)v;
}

JSValue JsGetReg(JSContext* ctx, JSValueConst /*this_val*/, int argc, JSValueConst* argv) {
    if (argc < 1) return JS_NewString(ctx, "Usage: getreg(vN|xN|fp|sp|pc)");
    std::lock_guard<std::mutex> lk(g_debugMutex);
    if (!g_isThreadPaused) return JS_NewString(ctx, "[*] No thread paused (getreg is debug-only)");
    int idx = ParseRegIndex(ctx, argv[0], g_pausedRegs.values.size(), g_pausedRegs.regNames);
    if (idx < 0) return JS_NewString(ctx, "[!] bad register");
    JSValue obj = JS_NewObject(ctx);
    std::string name;
    if (idx < (int)g_pausedRegs.regNames.size() && !g_pausedRegs.regNames[idx].empty()) {
        name = g_pausedRegs.regNames[idx];
    } else {
        name = "v" + std::to_string(idx);
    }
    JS_SetPropertyStr(ctx, obj, "name", JS_NewString(ctx, name.c_str()));
    JS_SetPropertyStr(ctx, obj, "index", JS_NewInt32(ctx, idx));
    JS_SetPropertyStr(ctx, obj, "value", NewBigIntOrInt(ctx, g_pausedRegs.values[idx]));
    JS_SetPropertyStr(ctx, obj, "isObj", JS_NewBool(ctx, idx < (int)g_pausedRegs.flags.size() && g_pausedRegs.flags[idx]));
    if (idx < (int)g_pausedRegs.decoded.size()) {
        JS_SetPropertyStr(ctx, obj, "str", JS_NewString(ctx, g_pausedRegs.decoded[idx].c_str()));
    }
    return obj;
}

JSValue JsSetReg(JSContext* ctx, JSValueConst /*this_val*/, int argc, JSValueConst* argv) {
    if (argc < 2) return JS_NewString(ctx, "Usage: setreg(reg, number|string)");
    std::lock_guard<std::mutex> lk(g_debugMutex);
    if (!g_isThreadPaused) return JS_NewString(ctx, "[*] No thread paused (setreg is debug-only)");
    int idx = ParseRegIndex(ctx, argv[0], g_pausedRegs.values.size(), g_pausedRegs.regNames);
    if (idx < 0) return JS_NewString(ctx, "[!] bad register");

    uint64_t newVal = 0;
    uint8_t isObj = 0;
    std::string decoded;
    if (JS_IsString(argv[1])) {
        const char* s = JS_ToCString(ctx, argv[1]);
        if (!s) return JS_NewString(ctx, "[!] bad string");
        JNIEnv* env = GetEnv();
        if (!env) {
            JS_FreeCString(ctx, s);
            return JS_NewString(ctx, "[!] no JNIEnv");
        }
        jstring js = env->NewStringUTF(s);
        jobject gref = js ? env->NewGlobalRef(js) : nullptr;
        if (js) env->DeleteLocalRef(js);
        if (!gref) {
            JS_FreeCString(ctx, s);
            return JS_NewString(ctx, "[!] NewGlobalRef failed");
        }
        g_pausedRegs.pinned.push_back(gref);
        newVal = (uint64_t)(uintptr_t)gref;
        isObj = 1;
        decoded = s;
        JS_FreeCString(ctx, s);
    } else {
        newVal = (uint64_t)ParsePtr(ctx, argv[1]);
        isObj = 0;
    }

    g_pausedRegs.values[idx] = newVal;
    if (idx < (int)g_pausedRegs.flags.size()) g_pausedRegs.flags[idx] = isObj;
    if (idx < (int)g_pausedRegs.decoded.size()) g_pausedRegs.decoded[idx] = decoded;
    if (g_pausedRegs.liveRegs) g_pausedRegs.liveRegs[idx] = newVal;
    if (g_pausedRegs.liveFlags) g_pausedRegs.liveFlags[idx] = isObj;

    if (g_pausedRegs.isNative && g_pausedRegs.rawGpr) {
        auto* gpr = reinterpret_cast<QBDI::GPRState*>(g_pausedRegs.rawGpr);
        if (idx <= 28) (&gpr->x0)[idx] = newVal;
        else if (idx == 29) gpr->x29 = newVal;
        else if (idx == 30) gpr->lr = newVal;
        else if (idx == 31) gpr->sp = newVal;
        else if (idx == 32) gpr->pc = newVal;
    }

    std::string name = (idx < (int)g_pausedRegs.regNames.size() && !g_pausedRegs.regNames[idx].empty())
                           ? g_pausedRegs.regNames[idx]
                           : ("v" + std::to_string(idx));
    char buf[160];
    snprintf(buf, sizeof(buf), "%s = 0x%llx%s%s", name.c_str(), (unsigned long long)newVal,
             isObj ? " (obj) " : " ", decoded.c_str());
    return JS_NewString(ctx, buf);
}

JSValue JsDumpRegs(JSContext* ctx, JSValueConst /*this_val*/, int /*argc*/, JSValueConst* /*argv*/) {
    std::lock_guard<std::mutex> lk(g_debugMutex);
    if (!g_isThreadPaused) return JS_NewString(ctx, "[*] No thread paused (regs is debug-only)");
    std::ostringstream ss;
    if (g_pausedRegs.isNative) {
        for (size_t i = 0; i < g_pausedRegs.values.size(); i++) {
            std::string nm = (i < g_pausedRegs.regNames.size()) ? g_pausedRegs.regNames[i] : ("r" + std::to_string(i));
            char buf[64];
            snprintf(buf, sizeof(buf), "    %-4s = 0x%llx\n", nm.c_str(), (unsigned long long)g_pausedRegs.values[i]);
            ss << buf;
        }
    } else {
        for (size_t i = 0; i < g_pausedRegs.values.size(); i++) {
            char buf[32];
            snprintf(buf, sizeof(buf), "v%zu=0x%llx", i, (unsigned long long)g_pausedRegs.values[i]);
            ss << buf;
            if (i < g_pausedRegs.flags.size() && g_pausedRegs.flags[i]) {
                ss << "(obj";
                if (i < g_pausedRegs.decoded.size() && !g_pausedRegs.decoded[i].empty())
                    ss << " " << g_pausedRegs.decoded[i];
                ss << ")";
            }
            ss << "\n";
        }
    }
    return JS_NewString(ctx, ss.str().c_str());
}

static JSValue JsStack(JSContext* ctx, JSValueConst, int argc, JSValueConst* argv) {
    std::lock_guard<std::mutex> lk(g_debugMutex);
    if (!g_isThreadPaused) return JS_NewString(ctx, "[*] No thread paused (stack is debug-only)");
    if (!g_pausedRegs.isNative || !g_pausedRegs.rawGpr) {
        return JS_NewString(ctx, "[*] Stack inspection is currently available for native breakpoints");
    }

    auto* gpr = reinterpret_cast<QBDI::GPRState*>(g_pausedRegs.rawGpr);
    int count = 16;
    if (argc >= 1) JS_ToInt32(ctx, &count, argv[0]);
    if (count <= 0) count = 16;
    if (count > 128) count = 128;

    int64_t off = 0;
    if (argc >= 2) off = ParsePtr(ctx, argv[1]);

    uintptr_t baseSp = static_cast<uintptr_t>(gpr->sp) + static_cast<uintptr_t>(off);
    if (!IsReasonableStackPointer(baseSp)) {
        return JS_NewString(ctx, "[!] Invalid or unreadable stack pointer");
    }

    std::ostringstream ss;
    ss << "=== Stack (sp=0x" << std::hex << (unsigned long long)gpr->sp
       << ", fp=0x" << (unsigned long long)gpr->x29 << std::dec << ") ===\n";

    for (int i = 0; i < count; i++) {
        uintptr_t curAddr = baseSp + i * 8;
        uint64_t val = 0;
        if (!SafeReadMemory(&val, reinterpret_cast<const void*>(curAddr), sizeof(val))) {
            ss << "    [sp+0x" << std::hex << (i * 8 + off) << "] <unreadable>\n" << std::dec;
            break;
        }

        std::string tag;
        if (curAddr == gpr->x29) tag += " (fp)";
        if (val == gpr->lr) tag += " (lr)";
        if (val == gpr->x29) tag += " (*fp)";

        std::string sym = PI::resolveAddressSymbol(static_cast<uintptr_t>(val));

        char b[256];
        snprintf(b, sizeof(b), "    [sp+0x%02x] 0x%016llx%s%s%s\n",
                 (unsigned int)(i * 8 + off),
                 (unsigned long long)val,
                 tag.c_str(),
                 sym.empty() ? "" : " ",
                 sym.c_str());
        ss << b;
    }
    return JS_NewString(ctx, ss.str().c_str());
}

static JSValue JsHexdump(JSContext* ctx, JSValueConst, int argc, JSValueConst* argv) {
    if (argc < 1) return JS_NewString(ctx, "Usage: hexdump(address, [size=64])");
    int64_t addr = ParsePtr(ctx, argv[0]);
    if (!addr || addr < 0x1000) return JS_NewString(ctx, "[!] Invalid address");
    int size = 64;
    if (argc >= 2) JS_ToInt32(ctx, &size, argv[1]);
    if (size <= 0) size = 64;
    if (size > 4096) size = 4096;

    std::vector<uint8_t> buf(size);
    if (!SafeReadMemory(buf.data(), reinterpret_cast<const void*>(addr), size)) {
        return JS_NewString(ctx, "[!] Memory unreadable at target address");
    }

    std::ostringstream ss;
    for (int i = 0; i < size; i += 16) {
        char prefix[64];
        snprintf(prefix, sizeof(prefix), "0x%010llx: ", (unsigned long long)(addr + i));
        ss << prefix;

        char hexPart[64] = {};
        char asciiPart[32] = {};
        int chunk = std::min(16, size - i);
        for (int j = 0; j < 16; j++) {
            if (j < chunk) {
                uint8_t byte = buf[i + j];
                snprintf(hexPart + strlen(hexPart), sizeof(hexPart) - strlen(hexPart), "%02x ", byte);
                asciiPart[j] = (byte >= 32 && byte <= 126) ? (char)byte : '.';
            } else {
                strcat(hexPart, "   ");
                asciiPart[j] = ' ';
            }
            if (j == 7) strcat(hexPart, " ");
        }
        asciiPart[16] = 0;
        ss << hexPart << " |" << asciiPart << "|\n";
    }
    return JS_NewString(ctx, ss.str().c_str());
}

static JSValue JsJavaThreads(JSContext* ctx, JSValueConst, int, JSValueConst*) {
    JNIEnv* env = GetEnv();
    if (!env) return JS_NewString(ctx, "[!] No JNIEnv available");

    jclass threadCls = env->FindClass("java/lang/Thread");
    if (!threadCls) { env->ExceptionClear(); return JS_NewString(ctx, "[!] Thread class not found"); }

    jmethodID getAllStackTracesMid = env->GetStaticMethodID(
        threadCls, "getAllStackTraces", "()Ljava/util/Map;");
    if (!getAllStackTracesMid) { env->ExceptionClear(); env->DeleteLocalRef(threadCls); return JS_NewString(ctx, "[!] getAllStackTraces not found"); }

    jobject traceMap = env->CallStaticObjectMethod(threadCls, getAllStackTracesMid);
    if (env->ExceptionCheck() || !traceMap) { env->ExceptionClear(); env->DeleteLocalRef(threadCls); return JS_NewString(ctx, "[!] Failed to get thread map"); }

    jclass mapCls = env->GetObjectClass(traceMap);
    jmethodID keySetMid = env->GetMethodID(mapCls, "keySet", "()Ljava/util/Set;");
    jobject keySet = env->CallObjectMethod(traceMap, keySetMid);

    jclass setCls = env->GetObjectClass(keySet);
    jmethodID toArrayMid = env->GetMethodID(setCls, "toArray", "()[Ljava/lang/Object;");
    auto threadArray = (jobjectArray)env->CallObjectMethod(keySet, toArrayMid);

    jmethodID getIdMid = env->GetMethodID(threadCls, "getId", "()J");
    jmethodID getNameMid = env->GetMethodID(threadCls, "getName", "()Ljava/lang/String;");
    jmethodID getStateMid = env->GetMethodID(threadCls, "getState", "()Ljava/lang/Thread$State;");
    jmethodID isDaemonMid = env->GetMethodID(threadCls, "isDaemon", "()Z");
    jmethodID getMapMid = env->GetMethodID(mapCls, "get", "(Ljava/lang/Object;)Ljava/lang/Object;");

    jsize count = threadArray ? env->GetArrayLength(threadArray) : 0;
    pid_t currentTid = gettid();

    std::ostringstream ss;
    ss << "=== Java Threads (" << count << ") ========================================\n";

    for (jsize i = 0; i < count; i++) {
        jobject th = env->GetObjectArrayElement(threadArray, i);
        if (!th) continue;

        jlong id = env->CallLongMethod(th, getIdMid);
        jstring jname = (jstring)env->CallObjectMethod(th, getNameMid);
        const char* nameStr = jname ? env->GetStringUTFChars(jname, nullptr) : "unknown";
        jobject stateObj = env->CallObjectMethod(th, getStateMid);
        std::string stateStr = "UNKNOWN";
        if (stateObj) {
            jclass stateCls = env->GetObjectClass(stateObj);
            jmethodID toStringMid = env->GetMethodID(stateCls, "toString", "()Ljava/lang/String;");
            jstring jState = (jstring)env->CallObjectMethod(stateObj, toStringMid);
            if (jState) {
                const char* st = env->GetStringUTFChars(jState, nullptr);
                if (st) { stateStr = st; env->ReleaseStringUTFChars(jState, st); }
                env->DeleteLocalRef(jState);
            }
            env->DeleteLocalRef(stateCls);
            env->DeleteLocalRef(stateObj);
        }
        jboolean isDaemon = env->CallBooleanMethod(th, isDaemonMid);

        std::string topFrame;
        auto framesArr = (jobjectArray)env->CallObjectMethod(traceMap, getMapMid, th);
        if (framesArr && env->GetArrayLength(framesArr) > 0) {
            jobject frame = env->GetObjectArrayElement(framesArr, 0);
            if (frame) {
                jclass frameCls = env->GetObjectClass(frame);
                jmethodID toStringMid = env->GetMethodID(frameCls, "toString", "()Ljava/lang/String;");
                jstring jf = (jstring)env->CallObjectMethod(frame, toStringMid);
                if (jf) {
                    const char* fStr = env->GetStringUTFChars(jf, nullptr);
                    if (fStr) { topFrame = fStr; env->ReleaseStringUTFChars(jf, fStr); }
                    env->DeleteLocalRef(jf);
                }
                env->DeleteLocalRef(frameCls);
                env->DeleteLocalRef(frame);
            }
            env->DeleteLocalRef(framesArr);
        }

        bool isCurrent = (g_isThreadPaused && g_pausedRegs.tid == (pid_t)id) || (currentTid == (pid_t)id);
        char line[512];
        snprintf(line, sizeof(line), " %c #%-5lld %-12s %-24s %s %s\n",
                 isCurrent ? '*' : ' ',
                 (long long)id,
                 stateStr.c_str(),
                 (std::string("\"") + nameStr + "\"").c_str(),
                 isDaemon ? "(daemon)" : "        ",
                 topFrame.empty() ? "" : (std::string("at ") + topFrame).c_str());
        ss << line;

        if (jname) { env->ReleaseStringUTFChars(jname, nameStr); env->DeleteLocalRef(jname); }
        env->DeleteLocalRef(th);
    }

    if (threadArray) env->DeleteLocalRef(threadArray);
    if (keySet) env->DeleteLocalRef(keySet);
    if (setCls) env->DeleteLocalRef(setCls);
    if (mapCls) env->DeleteLocalRef(mapCls);
    if (traceMap) env->DeleteLocalRef(traceMap);
    if (threadCls) env->DeleteLocalRef(threadCls);

    return JS_NewString(ctx, ss.str().c_str());
}

static JSValue JsNativeThreads(JSContext* ctx, JSValueConst, int, JSValueConst*) {
    DIR* d = opendir("/proc/self/task");
    if (!d) return JS_NewString(ctx, "[!] Failed to open /proc/self/task");

    struct ThreadItem {
        pid_t tid;
        std::string name;
        char state;
        uintptr_t pc;
        std::string loc;
    };
    std::vector<ThreadItem> list;

    struct dirent* de;
    while ((de = readdir(d)) != nullptr) {
        if (de->d_name[0] == '.') continue;
        pid_t tid = atoi(de->d_name);
        if (tid <= 0) continue;

        char path[128];
        snprintf(path, sizeof(path), "/proc/self/task/%d/comm", tid);
        std::string name = "unknown";
        FILE* f = fopen(path, "r");
        if (f) {
            char buf[64];
            if (fgets(buf, sizeof(buf), f)) {
                size_t len = strlen(buf);
                if (len > 0 && buf[len - 1] == '\n') buf[len - 1] = 0;
                name = buf;
            }
            fclose(f);
        }

        char state = '?';
        snprintf(path, sizeof(path), "/proc/self/task/%d/stat", tid);
        f = fopen(path, "r");
        if (f) {
            int t; char nbuf[64], s;
            if (fscanf(f, "%d (%63[^)]) %c", &t, nbuf, &s) == 3) {
                state = s;
            }
            fclose(f);
        }

        uintptr_t pc = 0;
        std::string loc;
        if (g_isThreadPaused && g_pausedRegs.tid == tid) {
            pc = g_pausedRegs.pc;
            loc = PI::resolveAddressSymbol(pc);
        }

        list.push_back({tid, name, state, pc, loc});
    }
    closedir(d);

    std::sort(list.begin(), list.end(), [](const ThreadItem& a, const ThreadItem& b) {
        return a.tid < b.tid;
    });

    std::ostringstream ss;
    ss << "=== Native Threads (" << list.size() << ") ====================================\n";
    for (const auto& item : list) {
        bool isCurrent = g_isThreadPaused && g_pausedRegs.tid == item.tid;
        char line[256];
        if (item.pc != 0) {
            snprintf(line, sizeof(line), " %c #%-5d [%c] %-20s pc=0x%llx %s\n",
                     isCurrent ? '*' : ' ', item.tid, item.state,
                     (std::string("\"") + item.name + "\"").c_str(),
                     (unsigned long long)item.pc, item.loc.c_str());
        } else {
            snprintf(line, sizeof(line), " %c #%-5d [%c] %-20s\n",
                     isCurrent ? '*' : ' ', item.tid, item.state,
                     (std::string("\"") + item.name + "\"").c_str());
        }
        ss << line;
    }
    return JS_NewString(ctx, ss.str().c_str());
}

static JSValue JsThreads(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
    if (g_isThreadPaused && g_pausedRegs.isNative) {
        return JsNativeThreads(ctx, this_val, argc, argv);
    }
    return JsJavaThreads(ctx, this_val, argc, argv);
}

JSValue JsThreadInfo(JSContext* ctx, JSValueConst /*this_val*/, int /*argc*/, JSValueConst* /*argv*/) {
    std::lock_guard<std::mutex> lk(g_debugMutex);
    if (!g_isThreadPaused) return JS_NewString(ctx, "[*] No thread paused (thread is debug-only)");
    JSValue obj = JS_NewObject(ctx);
    JS_SetPropertyStr(ctx, obj, "tid", JS_NewInt32(ctx, (int)g_pausedRegs.tid));
    JS_SetPropertyStr(ctx, obj, "pid", JS_NewInt32(ctx, (int)g_pausedRegs.pid));
    JS_SetPropertyStr(ctx, obj, "name", JS_NewString(ctx, g_pausedRegs.threadName.c_str()));
    JS_SetPropertyStr(ctx, obj, "pc", JS_NewInt32(ctx, (int)g_pausedRegs.pc));
    JS_SetPropertyStr(ctx, obj, "depth", JS_NewInt32(ctx, g_pausedRegs.depth));
    JS_SetPropertyStr(ctx, obj, "method", JS_NewString(ctx, g_pausedRegs.methodName.c_str()));
    JS_SetPropertyStr(ctx, obj, "stack", JS_NewString(ctx, g_pausedRegs.stackTrace.c_str()));
    return obj;
}

} // namespace

// Remove all armed breakpoints (Java + native) and resume paused thread if any.
size_t DebugDetachAll() {
    {
        std::lock_guard<std::mutex> lk(g_debugMutex);
        if (g_isThreadPaused) {
            g_pendingCommand = DebugStepCommand::CONTINUE;
            g_debugCv.notify_all();
        }
    }
    std::lock_guard<std::mutex> lk(g_bpMutex);
    size_t n = 0;
    for (auto& bp : g_activeBreakpoints) {
        if (!bp.is_active) continue;
        bp.is_active = false;
        if (bp.java_handle.isHooked()) bp.java_handle.unhook();
        if (bp.native_handle.isValid()) bp.native_handle.unhook();
        n++;
    }
    g_activeBreakpoints.clear();
    g_nextBpId = 0;
    return n;
}

bool BreakpointClearByArtMethod(void* artMethod) {
    std::lock_guard<std::mutex> lk(g_bpMutex);
    bool done = false;
    for (auto it = g_activeBreakpoints.begin(); it != g_activeBreakpoints.end();) {
        bool match = artMethod && it->is_active && it->java_handle.isHooked() &&
                     reinterpret_cast<void*>(it->java_handle.getArtMethod()) == artMethod;
        if (match) {
            // If a thread is currently paused at this breakpoint, resume it and
            // wait for it to leave the pause window before tearing down the trampoline.
            {
                std::unique_lock<std::mutex> dlk(g_debugMutex);
                if (g_isThreadPaused && g_pausedLocation == it->location) {
                    g_pendingCommand = DebugStepCommand::CONTINUE;
                    g_debugCv.notify_all();
                    g_debugCv.wait_for(dlk, std::chrono::milliseconds(200),
                                       []() { return !g_isThreadPaused; });
                }
            }
            it->is_active = false;
            if (it->java_handle.isHooked()) it->java_handle.unhook();
            if (it->native_handle.isValid()) it->native_handle.unhook();
            it = g_activeBreakpoints.erase(it);
            done = true;
        } else {
            ++it;
        }
    }
    return done;
}

JSValue JsDebugUnhookAll(JSContext* ctx, JSValueConst, int /*argc*/, JSValueConst* /*argv*/) {
    size_t n = DebugDetachAll();
    char buf[64];
    snprintf(buf, sizeof(buf), "Removed %zu breakpoints", n);
    return JS_NewString(ctx, buf);
}

void RegisterDebugApis(JSContext* ctx, JSValue global, JSValue debug) {    // Debug namespace
    JS_SetPropertyStr(ctx, debug, "breakJava", JS_NewCFunction(ctx, JsBreakJava, "breakJava", 2));
    JS_SetPropertyStr(ctx, debug, "breakNative", JS_NewCFunction(ctx, JsBreakNative, "breakNative", 2));
    JS_SetPropertyStr(ctx, debug, "continue", JS_NewCFunction(ctx, JsContinue, "continue", 0));
    JS_SetPropertyStr(ctx, debug, "step", JS_NewCFunction(ctx, JsStep, "step", 0));
    JS_SetPropertyStr(ctx, debug, "next", JS_NewCFunction(ctx, JsNext, "next", 0));
    JS_SetPropertyStr(ctx, debug, "return", JS_NewCFunction(ctx, JsReturn, "return", 0));
    JS_SetPropertyStr(ctx, debug, "bt", JS_NewCFunction(ctx, JsBt, "bt", 0));
    JS_SetPropertyStr(ctx, debug, "inspect", JS_NewCFunction(ctx, JsInspect, "inspect", 1));
    JS_SetPropertyStr(ctx, debug, "getreg", JS_NewCFunction(ctx, JsGetReg, "getreg", 1));
    JS_SetPropertyStr(ctx, debug, "setreg", JS_NewCFunction(ctx, JsSetReg, "setreg", 2));
    JS_SetPropertyStr(ctx, debug, "dumpRegs", JS_NewCFunction(ctx, JsDumpRegs, "dumpRegs", 0));
    JS_SetPropertyStr(ctx, debug, "thread", JS_NewCFunction(ctx, JsThreadInfo, "thread", 0));
    JS_SetPropertyStr(ctx, debug, "stack", JS_NewCFunction(ctx, JsStack, "stack", 2));
    JS_SetPropertyStr(ctx, debug, "hexdump", JS_NewCFunction(ctx, JsHexdump, "hexdump", 2));
    JS_SetPropertyStr(ctx, debug, "javathreads", JS_NewCFunction(ctx, JsJavaThreads, "javathreads", 0));
    JS_SetPropertyStr(ctx, debug, "nativethreads", JS_NewCFunction(ctx, JsNativeThreads, "nativethreads", 0));
    JS_SetPropertyStr(ctx, debug, "threads", JS_NewCFunction(ctx, JsThreads, "threads", 0));

    JS_SetPropertyStr(ctx, global, "brkj", JS_NewCFunction(ctx, JsBreakJava, "brkj", 2));
    JS_SetPropertyStr(ctx, global, "brkn", JS_NewCFunction(ctx, JsBreakNative, "brkn", 2));
    JS_SetPropertyStr(ctx, global, "bpunhookall", JS_NewCFunction(ctx, JsDebugUnhookAll, "bpunhookall", 0));
    JS_SetPropertyStr(ctx, debug, "unhookAll", JS_NewCFunction(ctx, JsDebugUnhookAll, "unhookAll", 0));
    JS_SetPropertyStr(ctx, global, "c", JS_NewCFunction(ctx, JsContinue, "c", 0));
    JS_SetPropertyStr(ctx, global, "s", JS_NewCFunction(ctx, JsStep, "s", 0));
    JS_SetPropertyStr(ctx, global, "n", JS_NewCFunction(ctx, JsNext, "n", 0));
    JS_SetPropertyStr(ctx, global, "r", JS_NewCFunction(ctx, JsReturn, "r", 0));
    JS_SetPropertyStr(ctx, global, "bt", JS_NewCFunction(ctx, JsBt, "bt", 0));
    JS_SetPropertyStr(ctx, global, "inspect", JS_NewCFunction(ctx, JsInspect, "inspect", 1));
    JS_SetPropertyStr(ctx, global, "po", JS_NewCFunction(ctx, JsInspect, "po", 1));
    JS_SetPropertyStr(ctx, global, "getreg", JS_NewCFunction(ctx, JsGetReg, "getreg", 1));
    JS_SetPropertyStr(ctx, global, "setreg", JS_NewCFunction(ctx, JsSetReg, "setreg", 2));
    JS_SetPropertyStr(ctx, global, "dumpRegs", JS_NewCFunction(ctx, JsDumpRegs, "dumpRegs", 0));
    JS_SetPropertyStr(ctx, global, "thread", JS_NewCFunction(ctx, JsThreadInfo, "thread", 0));
    JS_SetPropertyStr(ctx, global, "stack", JS_NewCFunction(ctx, JsStack, "stack", 2));
    JS_SetPropertyStr(ctx, global, "hexdump", JS_NewCFunction(ctx, JsHexdump, "hexdump", 2));
    JS_SetPropertyStr(ctx, global, "javathreads", JS_NewCFunction(ctx, JsJavaThreads, "javathreads", 0));
    JS_SetPropertyStr(ctx, global, "nativethreads", JS_NewCFunction(ctx, JsNativeThreads, "nativethreads", 0));
    JS_SetPropertyStr(ctx, global, "threads", JS_NewCFunction(ctx, JsThreads, "threads", 0));

    const char* kRegsProxy = R"JS(
(function(){
    globalThis.regs = new Proxy({
        get: getreg,
        set: setreg,
        dump: function(){ return dumpRegs ? dumpRegs() : getreg; }
    }, {
        get(t, p) {
            if (p in t) return t[p];
            if (typeof p === 'symbol') return undefined;
            let reg = getreg(p);
            if (reg && typeof reg === 'object' && 'value' in reg) {
                return reg.value;
            }
            return reg;
        },
        set(t, p, v) {
            if (typeof p === 'string') {
                setreg(p, v);
                return true;
            }
            t[p] = v;
            return true;
        }
    });
})();
)JS";
    JSValue r = JS_Eval(ctx, kRegsProxy, strlen(kRegsProxy), "<debug_regs>", JS_EVAL_TYPE_GLOBAL);
    JS_FreeValue(ctx, r);
}

// Capture the Java caller chain from a hooked method's entry SP
// (PineNativeContext::sp) using the native quick-frame walk. Exposed to the
// hook callback as `ctx.stack` so a plain hook can print the stack at entry
// without pausing the thread (and without ART's StackVisitor, which aborts on
// the trampoline's bogus frame).
std::string CaptureCallerStackFromSp(void* callerSp) {
    std::vector<std::string> lines;
    CaptureCallersViaNativeFrames(callerSp, lines);
    std::ostringstream ss;
    for (size_t i = 0; i < lines.size(); i++) {
        char hdr[16];
        snprintf(hdr, sizeof(hdr), "  #%02zu ", i);
        ss << hdr << lines[i] << "\n";
    }
    return ss.str();
}

}} // namespace artpi::agent
