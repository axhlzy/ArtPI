//
// agent_jni.cpp - JNI Tracing Engine (Vtable Hijacking & Hardware Breakpoints)
//
#include "agent_jni.h"
#include "agent_common.h"
#include "agent_net.h"
#include "agent_hw_hook.h"
#include "native/hooker/pi_hw_hook.h"
#include "native/pi_native.h"
#include "art/art_method.h"
#include "agent_java_ref.h"

#include <jni.h>
#include <dlfcn.h>
#include <sys/mman.h>
#include <sys/uio.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <unwind.h>
#include <android/log.h>
#include "xdl.h"

#include <string>
#include <vector>
#include <set>
#include <chrono>
#include <atomic>
#include <mutex>
#include <sstream>
#include <iomanip>
#include <regex>
#include <memory>
#include <cstring>
#include <cinttypes>
#include "frida-gum.h"

#define JNI_TAG "ArtPI-JNI"

namespace artpi { namespace agent {

constexpr int kNumJniSlots = 233;

#if defined(__aarch64__)
extern "C" void artpi_jni_common_entry();

// 32 bytes per slot: ldr x16, #8 (12) + b (4), or the indirect fallback
// ldr x16, #8 (12) + ldr x17, #8 (12) + br x17 (4) = 28 bytes.
constexpr size_t kTrampolineSlotSize = 32;
static void* g_jniTrampolineSlots[kNumJniSlots] = {nullptr};
static std::once_flag g_jniTrampolineInitOnce;
static std::once_flag g_gumInitOnce;
static bool g_jniTrampolinesReady = false;

static bool BuildJniTrampolines() {
    std::call_once(g_gumInitOnce, []() { gum_init_embedded(); });

    long pageSizeValue = sysconf(_SC_PAGESIZE);
    size_t pageSize = pageSizeValue > 0 ? static_cast<size_t>(pageSizeValue) : 4096;
    size_t needed = static_cast<size_t>(kNumJniSlots) * kTrampolineSlotSize;
    size_t allocSize = (needed + pageSize - 1) & ~(pageSize - 1);

    // Allocate executable memory near artpi_jni_common_entry using Gum.
    // Gum requires the allocation size to be page-aligned; a non-aligned
    // size (for example 233 * 16 = 3728) returns NULL on Android.
    GumAddressSpec spec = {};
    spec.near_address = reinterpret_cast<void*>(artpi_jni_common_entry);
    spec.max_distance = 64 * 1024 * 1024; // 64 MB (within ARM64 128MB branch range)

    void* mem = gum_memory_allocate_near(&spec, allocSize, pageSize, GUM_PAGE_RWX);
    if (!mem) {
        mem = gum_memory_allocate(nullptr, allocSize, pageSize, GUM_PAGE_RWX);
    }

    if (!mem) {
        __android_log_print(ANDROID_LOG_ERROR, JNI_TAG,
            "Failed to allocate %u bytes for dynamic JNI trampolines",
            static_cast<unsigned>(allocSize));
        return false;
    }

    GumArm64Writer writer;
    gum_arm64_writer_init(&writer, mem);
    bool ok = true;

    for (int i = 0; i < kNumJniSlots; ++i) {
        void* slotAddress = gum_arm64_writer_cur(&writer);
        // 1. x16 = slot_id
        if (!gum_arm64_writer_put_ldr_reg_u64(&writer, ARM64_REG_X16, static_cast<guint64>(i))) {
            ok = false;
            break;
        }
        // 2. b artpi_jni_common_entry
        if (!gum_arm64_writer_put_b_imm(&writer, reinterpret_cast<GumAddress>(artpi_jni_common_entry))) {
            // Fallback: indirect branch if out of direct range
            if (!gum_arm64_writer_put_ldr_reg_address(&writer, ARM64_REG_X17,
                    reinterpret_cast<GumAddress>(artpi_jni_common_entry)) ||
                !gum_arm64_writer_put_br_reg(&writer, ARM64_REG_X17)) {
                ok = false;
                break;
            }
        }
        g_jniTrampolineSlots[i] = slotAddress;
    }

    if (ok && gum_arm64_writer_offset(&writer) > needed) {
        ok = false;
    }
    if (ok && !gum_arm64_writer_flush(&writer)) {
        ok = false;
    }
    gum_arm64_writer_clear(&writer);

    if (!ok) {
        for (int i = 0; i < kNumJniSlots; ++i) g_jniTrampolineSlots[i] = nullptr;
        gum_memory_free(mem, allocSize);
        __android_log_print(ANDROID_LOG_ERROR, JNI_TAG,
            "Failed to generate dynamic JNI trampolines");
        return false;
    }

    __android_log_print(ANDROID_LOG_INFO, JNI_TAG,
        "Dynamic JNI trampolines generated via GumArm64Writer at %p (%d slots, %u bytes)",
        mem, kNumJniSlots, static_cast<unsigned>(allocSize));
    return true;
}

extern "C" void* artpi_jni_get_trampoline(int slot) {
    if (slot < 0 || slot >= kNumJniSlots) return nullptr;
    std::call_once(g_jniTrampolineInitOnce, []() {
        g_jniTrampolinesReady = BuildJniTrampolines();
    });
    return g_jniTrampolinesReady ? g_jniTrampolineSlots[slot] : nullptr;
}
#else
static void* artpi_jni_get_trampoline(int) { return nullptr; }
#endif

static const char* const kJniSlotNames[kNumJniSlots] = {
    "reserved0", "reserved1", "reserved2", "reserved3",
    "GetVersion", "DefineClass", "FindClass", "FromReflectedMethod",
    "FromReflectedField", "ToReflectedMethod", "GetSuperclass", "IsAssignableFrom",
    "ToReflectedField", "Throw", "ThrowNew", "ExceptionOccurred",
    "ExceptionDescribe", "ExceptionClear", "FatalError", "PushLocalFrame",
    "PopLocalFrame", "NewGlobalRef", "DeleteGlobalRef", "DeleteLocalRef",
    "IsSameObject", "NewLocalRef", "EnsureLocalCapacity", "AllocObject",
    "NewObject", "NewObjectV", "NewObjectA", "GetObjectClass",
    "IsInstanceOf", "GetMethodID", "CallObjectMethod", "CallObjectMethodV",
    "CallObjectMethodA", "CallBooleanMethod", "CallBooleanMethodV", "CallBooleanMethodA",
    "CallByteMethod", "CallByteMethodV", "CallByteMethodA", "CallCharMethod",
    "CallCharMethodV", "CallCharMethodA", "CallShortMethod", "CallShortMethodV",
    "CallShortMethodA", "CallIntMethod", "CallIntMethodV", "CallIntMethodA",
    "CallLongMethod", "CallLongMethodV", "CallLongMethodA", "CallFloatMethod",
    "CallFloatMethodV", "CallFloatMethodA", "CallDoubleMethod", "CallDoubleMethodV",
    "CallDoubleMethodA", "CallVoidMethod", "CallVoidMethodV", "CallVoidMethodA",
    "CallNonvirtualObjectMethod", "CallNonvirtualObjectMethodV", "CallNonvirtualObjectMethodA", "CallNonvirtualBooleanMethod",
    "CallNonvirtualBooleanMethodV", "CallNonvirtualBooleanMethodA", "CallNonvirtualByteMethod", "CallNonvirtualByteMethodV",
    "CallNonvirtualByteMethodA", "CallNonvirtualCharMethod", "CallNonvirtualCharMethodV", "CallNonvirtualCharMethodA",
    "CallNonvirtualShortMethod", "CallNonvirtualShortMethodV", "CallNonvirtualShortMethodA", "CallNonvirtualIntMethod",
    "CallNonvirtualIntMethodV", "CallNonvirtualIntMethodA", "CallNonvirtualLongMethod", "CallNonvirtualLongMethodV",
    "CallNonvirtualLongMethodA", "CallNonvirtualFloatMethod", "CallNonvirtualFloatMethodV", "CallNonvirtualFloatMethodA",
    "CallNonvirtualDoubleMethod", "CallNonvirtualDoubleMethodV", "CallNonvirtualDoubleMethodA", "CallNonvirtualVoidMethod",
    "CallNonvirtualVoidMethodV", "CallNonvirtualVoidMethodA", "GetFieldID", "GetObjectField",
    "GetBooleanField", "GetByteField", "GetCharField", "GetShortField",
    "GetIntField", "GetLongField", "GetFloatField", "GetDoubleField",
    "SetObjectField", "SetBooleanField", "SetByteField", "SetCharField",
    "SetShortField", "SetIntField", "SetLongField", "SetFloatField",
    "SetDoubleField", "GetStaticMethodID", "CallStaticObjectMethod", "CallStaticObjectMethodV",
    "CallStaticObjectMethodA", "CallStaticBooleanMethod", "CallStaticBooleanMethodV", "CallStaticBooleanMethodA",
    "CallStaticByteMethod", "CallStaticByteMethodV", "CallStaticByteMethodA", "CallStaticCharMethod",
    "CallStaticCharMethodV", "CallStaticCharMethodA", "CallStaticShortMethod", "CallStaticShortMethodV",
    "CallStaticShortMethodA", "CallStaticIntMethod", "CallStaticIntMethodV", "CallStaticIntMethodA",
    "CallStaticLongMethod", "CallStaticLongMethodV", "CallStaticLongMethodA", "CallStaticFloatMethod",
    "CallStaticFloatMethodV", "CallStaticFloatMethodA", "CallStaticDoubleMethod", "CallStaticDoubleMethodV",
    "CallStaticDoubleMethodA", "CallStaticVoidMethod", "CallStaticVoidMethodV", "CallStaticVoidMethodA",
    "GetStaticFieldID", "GetStaticObjectField", "GetStaticBooleanField", "GetStaticByteField",
    "GetStaticCharField", "GetStaticShortField", "GetStaticIntField", "GetStaticLongField",
    "GetStaticFloatField", "GetStaticDoubleField", "SetStaticObjectField", "SetStaticBooleanField",
    "SetStaticByteField", "SetStaticCharField", "SetStaticShortField", "SetStaticIntField",
    "SetStaticLongField", "SetStaticFloatField", "SetStaticDoubleField", "NewString",
    "GetStringLength", "GetStringChars", "ReleaseStringChars", "NewStringUTF",
    "GetStringUTFLength", "GetStringUTFChars", "ReleaseStringUTFChars", "GetArrayLength",
    "NewObjectArray", "GetObjectArrayElement", "SetObjectArrayElement", "NewBooleanArray",
    "NewByteArray", "NewCharArray", "NewShortArray", "NewIntArray",
    "NewLongArray", "NewFloatArray", "NewDoubleArray", "GetBooleanArrayElements",
    "GetByteArrayElements", "GetCharArrayElements", "GetShortArrayElements", "GetIntArrayElements",
    "GetLongArrayElements", "GetFloatArrayElements", "GetDoubleArrayElements", "ReleaseBooleanArrayElements",
    "ReleaseByteArrayElements", "ReleaseCharArrayElements", "ReleaseShortArrayElements", "ReleaseIntArrayElements",
    "ReleaseLongArrayElements", "ReleaseFloatArrayElements", "ReleaseDoubleArrayElements", "GetBooleanArrayRegion",
    "GetByteArrayRegion", "GetCharArrayRegion", "GetShortArrayRegion", "GetIntArrayRegion",
    "GetLongArrayRegion", "GetFloatArrayRegion", "GetDoubleArrayRegion", "SetBooleanArrayRegion",
    "SetByteArrayRegion", "SetCharArrayRegion", "SetShortArrayRegion", "SetIntArrayRegion",
    "SetLongArrayRegion", "SetFloatArrayRegion", "SetDoubleArrayRegion", "RegisterNatives",
    "UnregisterNatives", "MonitorEnter", "MonitorExit", "GetJavaVM",
    "GetStringRegion", "GetStringUTFRegion", "GetPrimitiveArrayCritical", "ReleasePrimitiveArrayCritical",
    "GetStringCritical", "ReleaseStringCritical", "NewWeakGlobalRef", "DeleteWeakGlobalRef",
    "ExceptionCheck", "NewDirectByteBuffer", "GetDirectBufferAddress", "GetDirectBufferCapacity",
    "GetObjectRefType"
};

static void* g_real_jni_table[kNumJniSlots] = {nullptr};
static void** g_hijacked_table = nullptr;
static bool g_backup_initialized = false;
static std::mutex g_vtableMutex;

static std::atomic<bool> g_vtableTracing{false};

// ---------------------------------------------------------------------------
// Filter Options
// ---------------------------------------------------------------------------
struct JniFilterConfig {
    std::string from;               // caller module substring (e.g. "liboattest.so")
    std::vector<std::string> only;  // only match these function names (or prefixes)
    std::vector<std::string> exclude;// exclude these function names
    std::string className;          // target class name filter
    std::string grep;               // rendered text substring filter
    bool stack = false;             // print caller stack trace
};

static JniFilterConfig g_filterConfig;
static std::mutex g_filterMutex;

static int FindSlotByName(const std::string& name) {
    for (int i = 0; i < kNumJniSlots; ++i) {
        if (name == kJniSlotNames[i]) return i;
    }
    return -1;
}

static std::string GetCallerModule(void* lr, uintptr_t* outOffset = nullptr) {
    if (!lr) return "unknown";
    Dl_info info;
    if (dladdr(lr, &info) && info.dli_fname) {
        const char* slash = strrchr(info.dli_fname, '/');
        std::string mod = slash ? slash + 1 : info.dli_fname;
        if (outOffset) {
            *outOffset = reinterpret_cast<uintptr_t>(lr) - reinterpret_cast<uintptr_t>(info.dli_fbase);
        }
        return mod;
    }
    return "0x" + std::to_string(reinterpret_cast<uintptr_t>(lr));
}

static std::string SafeReadCString(const void* ptr, size_t maxLen = 256) {
    if (!ptr || reinterpret_cast<uintptr_t>(ptr) < 0x1000) return "<null>";
    const char* p = reinterpret_cast<const char*>(ptr);
    std::string res;
    for (size_t i = 0; i < maxLen; ++i) {
        char c = p[i];
        if (c == 0) break;
        if (static_cast<unsigned char>(c) < 0x20 || static_cast<unsigned char>(c) > 0x7e) {
            c = '.';
        }
        res.push_back(c);
    }
    return res;
}

static bool SafeRead(const void* src, void* dst, size_t len) {
    if (!src || !dst || len == 0) return false;
    struct iovec local_iov = { dst, len };
    struct iovec remote_iov = { const_cast<void*>(src), len };
    ssize_t n = syscall(SYS_process_vm_readv, getpid(), &local_iov, 1, &remote_iov, 1, 0);
    return n == static_cast<ssize_t>(len);
}

static std::string CaptureJniCallStack(uintptr_t lr = 0, uintptr_t fp = 0) {
    struct BtCtx {
        uintptr_t pcs[32];
        int count = 0;
        int max = 20;
    } bt;

    auto cb = +[](struct _Unwind_Context* ctx, void* arg) -> _Unwind_Reason_Code {
        auto* s = static_cast<BtCtx*>(arg);
        if (s->count >= s->max) return _URC_END_OF_STACK;
        uintptr_t pc = _Unwind_GetIP(ctx);
        if (pc > 0x1000) {
            s->pcs[s->count++] = pc;
        }
        return _URC_NO_REASON;
    };
    _Unwind_Backtrace(cb, &bt);

    // If _Unwind_Backtrace captured <= 2 frames (often stops at signal trampoline),
    // walk ARM64 frame pointer chain using fp / lr
    if (bt.count <= 2 && (fp > 0x1000 || lr > 0x1000)) {
        bt.count = 0;
        if (lr > 0x1000) bt.pcs[bt.count++] = lr;
        uintptr_t cur_fp = fp;
        while (cur_fp > 0x1000 && (cur_fp & 0x7) == 0 && bt.count < bt.max) {
            uintptr_t next_fp = 0, next_lr = 0;
            if (!SafeRead(reinterpret_cast<const void*>(cur_fp), &next_fp, sizeof(next_fp))) break;
            if (!SafeRead(reinterpret_cast<const void*>(cur_fp + 8), &next_lr, sizeof(next_lr))) break;
            if (next_lr > 0x1000) {
                bt.pcs[bt.count++] = next_lr;
            }
            if (next_fp <= cur_fp || next_fp > cur_fp + 0x100000) break;
            cur_fp = next_fp;
        }
    }

    std::ostringstream ss;
    void* cache = nullptr;
    int frameIdx = 0;
    for (int i = 0; i < bt.count; i++) {
        uintptr_t pc = bt.pcs[i];
        xdl_info_t dli;
        memset(&dli, 0, sizeof(dli));
        if (xdl_addr(reinterpret_cast<void*>(pc), &dli, &cache) != 0) {
            const char* fname = dli.dli_fname ? dli.dli_fname : "?";
            const char* slash = strrchr(fname, '/');
            if (slash) fname = slash + 1;

            if (fname && strstr(fname, "libartpi_agent.so")) {
                continue;
            }

            uintptr_t fbase = reinterpret_cast<uintptr_t>(dli.dli_fbase);
            uintptr_t off = pc - fbase;
            char lineBuf[256];
            if (dli.dli_sname) {
                uintptr_t saddr = reinterpret_cast<uintptr_t>(dli.dli_saddr);
                snprintf(lineBuf, sizeof(lineBuf), "    #%02d 0x%lx %s!%s+0x%lx",
                         frameIdx++, (unsigned long)pc, fname, dli.dli_sname,
                         (unsigned long)(pc - saddr));
            } else {
                snprintf(lineBuf, sizeof(lineBuf), "    #%02d 0x%lx %s+0x%lx",
                         frameIdx++, (unsigned long)pc, fname, (unsigned long)off);
            }
            ss << lineBuf << "\n";
        } else {
            char lineBuf[64];
            snprintf(lineBuf, sizeof(lineBuf), "    #%02d 0x%lx\n", frameIdx++, (unsigned long)pc);
            ss << lineBuf;
        }
    }
    if (cache) xdl_addr_clean(&cache);
    return ss.str();
}

// ---------------------------------------------------------------------------
// Method & Field ID Resolution & JObject Inspection
// ---------------------------------------------------------------------------
static std::unordered_map<uintptr_t, std::string> g_methodIdNames;
static std::unordered_map<uintptr_t, std::string> g_fieldIdNames;
static std::unordered_map<uintptr_t, std::string> g_objectClassNames;
static std::unordered_map<uintptr_t, std::string> g_classNames;
static std::mutex g_idCacheMutex;

static thread_local bool t_insideJniTracer = false;

struct TracerGuard {
    bool& flag;
    bool active;
    TracerGuard(bool& f) : flag(f), active(!f) {
        if (active) flag = true;
    }
    ~TracerGuard() {
        if (active) flag = false;
    }
    bool isEngaged() const { return active; }
};

static std::string SafeResolveClass(JNIEnv* env, jclass clazz) {
    if (!clazz || reinterpret_cast<uintptr_t>(clazz) < 0x1000) {
        return "null";
    }
    uintptr_t rawAddr = reinterpret_cast<uintptr_t>(clazz);

    {
        std::lock_guard<std::mutex> lk(g_idCacheMutex);
        auto it = g_classNames.find(rawAddr);
        if (it != g_classNames.end()) {
            return "<class " + it->second + ">";
        }
    }

    if (!env || env->ExceptionCheck()) {
        char buf[32]; snprintf(buf, sizeof(buf), "0x%lx", (unsigned long)rawAddr);
        return buf;
    }

    std::string cname = JavaClassName(env, clazz);
    if (!cname.empty()) {
        {
            std::lock_guard<std::mutex> lk(g_idCacheMutex);
            g_classNames[rawAddr] = cname;
        }
        return "<class " + cname + ">";
    }
    char buf[32]; snprintf(buf, sizeof(buf), "0x%lx", (unsigned long)rawAddr);
    return buf;
}

static std::string SafeResolveJObject(JNIEnv* env, jobject obj) {
    if (!obj || reinterpret_cast<uintptr_t>(obj) < 0x1000) {
        return "null";
    }
    uintptr_t rawAddr = reinterpret_cast<uintptr_t>(obj);

    {
        std::lock_guard<std::mutex> lk(g_idCacheMutex);
        auto it = g_objectClassNames.find(rawAddr);
        if (it != g_objectClassNames.end()) {
            char buf[64];
            snprintf(buf, sizeof(buf), "<%s@0x%lx>", it->second.c_str(), (unsigned long)rawAddr);
            return buf;
        }
    }

    if (!env || env->ExceptionCheck()) {
        char buf[32]; snprintf(buf, sizeof(buf), "0x%lx", (unsigned long)rawAddr);
        return buf;
    }

    jclass cls = env->GetObjectClass(obj);
    if (!cls) {
        if (env->ExceptionCheck()) env->ExceptionClear();
        char buf[32]; snprintf(buf, sizeof(buf), "0x%lx", (unsigned long)rawAddr);
        return buf;
    }

    std::string cname = JavaClassName(env, cls);
    env->DeleteLocalRef(cls);
    if (cname.empty()) {
        char buf[32]; snprintf(buf, sizeof(buf), "0x%lx", (unsigned long)rawAddr);
        return buf;
    }

    // java.lang.String
    if (cname == "java.lang.String" || cname == "Ljava/lang/String;") {
        const char* c = env->GetStringUTFChars(static_cast<jstring>(obj), nullptr);
        std::string s;
        if (c) {
            s = "\"" + SafeReadCString(c, 64) + "\"";
            env->ReleaseStringUTFChars(static_cast<jstring>(obj), c);
        } else {
            if (env->ExceptionCheck()) env->ExceptionClear();
            s = "\"<string>\"";
        }
        return s;
    }

    // java.lang.Class
    if (cname == "java.lang.Class" || cname == "Ljava/lang/Class;") {
        std::string targetClsName = JavaClassName(env, static_cast<jclass>(obj));
        if (!targetClsName.empty()) {
            {
                std::lock_guard<std::mutex> lk(g_idCacheMutex);
                g_classNames[rawAddr] = targetClsName;
            }
            return "<class " + targetClsName + ">";
        }
        char buf[64]; snprintf(buf, sizeof(buf), "<class@0x%lx>", (unsigned long)rawAddr);
        return buf;
    }

    // Array: e.g. [I, [B, [Ljava/lang/String;
    if (!cname.empty() && cname[0] == '[') {
        jsize len = env->GetArrayLength(static_cast<jarray>(obj));
        if (env->ExceptionCheck()) env->ExceptionClear();
        char buf[64];
        snprintf(buf, sizeof(buf), "<%s[%d]@0x%lx>", SimplifyJavaType(cname).c_str(), (int)len, (unsigned long)rawAddr);
        return buf;
    }

    // General Java Object
    RegisterObservedObject(env, rawAddr, obj);
    std::string sname = SimplifyJavaType(cname);
    {
        std::lock_guard<std::mutex> lk(g_idCacheMutex);
        g_objectClassNames[rawAddr] = sname;
    }
    char buf[64];
    snprintf(buf, sizeof(buf), "<%s@0x%lx>", sname.c_str(), (unsigned long)rawAddr);
    return buf;
}

static std::string SafeResolveMethod(JNIEnv* env, jobject objOrCls, void* mid, bool isStatic) {
    if (!mid) return "<null-mid>";
    uintptr_t midVal = reinterpret_cast<uintptr_t>(mid);

    {
        std::lock_guard<std::mutex> lk(g_idCacheMutex);
        auto it = g_methodIdNames.find(midVal);
        if (it != g_methodIdNames.end()) {
            return it->second;
        }
    }

    // Direct ArtMethod* signature resolution (crash-safe, zero Java heap allocation)
    if (midVal >= 0x10000 && (midVal % alignof(void*)) == 0) {
        std::string s = PI::getPrettyMethodSignature(reinterpret_cast<PI::ArtMethod*>(mid));
        if (!s.empty()) {
            std::lock_guard<std::mutex> lk(g_idCacheMutex);
            g_methodIdNames[midVal] = s;
            return s;
        }
    }

    char buf[32];
    snprintf(buf, sizeof(buf), "0x%lx", (unsigned long)midVal);
    return buf;
}

static std::string SafeResolveField(JNIEnv* env, jobject objOrCls, void* fid, bool isStatic) {
    if (!fid) return "<null-fid>";
    uintptr_t fidVal = reinterpret_cast<uintptr_t>(fid);

    {
        std::lock_guard<std::mutex> lk(g_idCacheMutex);
        auto it = g_fieldIdNames.find(fidVal);
        if (it != g_fieldIdNames.end()) {
            return it->second;
        }
    }

    char buf[32];
    snprintf(buf, sizeof(buf), "0x%lx", (unsigned long)fidVal);
    return buf;
}

// ---------------------------------------------------------------------------
// Per-Thread Frame for Entry/Leave pairing
// ---------------------------------------------------------------------------
struct JniCallFrame {
    int slot_id;
    uint64_t start_ns;
    std::string call_desc;
    std::string caller_desc;
    bool matched;
    std::string pendingIdName;
    std::string stack_str;
};

static thread_local std::vector<JniCallFrame> t_callStack;

// ---------------------------------------------------------------------------
// JNI Vtable Hook Manager
// ---------------------------------------------------------------------------

static bool EnsureBackupTable(JNIEnv* env) {
    if (g_backup_initialized) return true;
    if (!env) return false;
    void** table = *reinterpret_cast<void***>(env);
    if (!table) return false;
    for (int i = 0; i < kNumJniSlots; ++i) {
        g_real_jni_table[i] = table[i];
    }
    g_backup_initialized = true;
    return true;
}

static bool InstallVtableHook(JNIEnv* env) {
#if !defined(__aarch64__)
    return false;
#endif
    std::lock_guard<std::mutex> lk(g_vtableMutex);
    if (g_vtableTracing.load()) return true;
    if (!env) return false;

    if (!EnsureBackupTable(env)) return false;

    void** table = *reinterpret_cast<void***>(env);
    if (!table) return false;

    // Build every stub before touching the live table. If any trampoline is
    // unavailable, leave the JNI table untouched and report failure.
    for (int i = 4; i < kNumJniSlots; ++i) {
        if (!artpi_jni_get_trampoline(i)) {
            __android_log_print(ANDROID_LOG_ERROR, JNI_TAG,
                "JNI vtable hook aborted: trampoline slot %d unavailable", i);
            return false;
        }
    }

    uintptr_t start = reinterpret_cast<uintptr_t>(table) & ~0xfffULL;
    uintptr_t end = (reinterpret_cast<uintptr_t>(table) + kNumJniSlots * sizeof(void*) + 0xfffULL) & ~0xfffULL;
    size_t len = end - start;

    if (mprotect(reinterpret_cast<void*>(start), len, PROT_READ | PROT_WRITE) != 0) {
        __android_log_print(ANDROID_LOG_ERROR, JNI_TAG, "mprotect RW failed on JNI table: %s", strerror(errno));
        return false;
    }

    // Overwrite slots 4..232 with our trampoline stubs (each 8 bytes)
    for (int i = 4; i < kNumJniSlots; ++i) {
        table[i] = artpi_jni_get_trampoline(i);
    }

    g_hijacked_table = table;
    g_vtableTracing.store(true);
    __android_log_print(ANDROID_LOG_INFO, JNI_TAG, "JNI Vtable hook successfully installed (%d slots)", kNumJniSlots - 4);
    return true;
}

static bool UninstallVtableHook() {
    std::lock_guard<std::mutex> lk(g_vtableMutex);
    if (!g_vtableTracing.load() || !g_hijacked_table) return true;

    uintptr_t start = reinterpret_cast<uintptr_t>(g_hijacked_table) & ~0xfffULL;
    uintptr_t end = (reinterpret_cast<uintptr_t>(g_hijacked_table) + kNumJniSlots * sizeof(void*) + 0xfffULL) & ~0xfffULL;
    size_t len = end - start;

    mprotect(reinterpret_cast<void*>(start), len, PROT_READ | PROT_WRITE);
    for (int i = 0; i < kNumJniSlots; ++i) {
        g_hijacked_table[i] = g_real_jni_table[i];
    }
    mprotect(reinterpret_cast<void*>(start), len, PROT_READ);

    g_hijacked_table = nullptr;
    g_vtableTracing.store(false);
    __android_log_print(ANDROID_LOG_INFO, JNI_TAG, "JNI Vtable hook successfully uninstalled. Original table restored.");
    return true;
}

// ---------------------------------------------------------------------------
// Parameter & Return value rendering
// ---------------------------------------------------------------------------

static std::string DescribeJniCall(int slot_id, JNIEnv* env, const uint64_t* args) {
    const char* name = (slot_id >= 0 && slot_id < kNumJniSlots) ? kJniSlotNames[slot_id] : "unknown";
    std::string sname = name;
    std::ostringstream ss;

    // Slot 215: RegisterNatives(env, clazz, methods, nMethods)
    if (slot_id == 215) {
        jclass clazz = reinterpret_cast<jclass>(args[1]);
        const JNINativeMethod* methods = reinterpret_cast<const JNINativeMethod*>(args[2]);
        jint nMethods = static_cast<jint>(args[3]);
        std::string clsStr = SafeResolveJObject(env, clazz);
        ss << "RegisterNatives(class=" << clsStr << ", n=" << std::dec << nMethods << ")";
        if (methods && nMethods > 0 && nMethods < 100) {
            for (int i = 0; i < nMethods; ++i) {
                const char* mname = methods[i].name ? methods[i].name : "<null>";
                const char* msig = methods[i].signature ? methods[i].signature : "<null>";
                void* fnPtr = methods[i].fnPtr;
                uintptr_t off = 0;
                std::string mod = GetCallerModule(fnPtr, &off);
                ss << "\n      #" << i << " " << mname << msig << " -> " << mod << "+0x" << std::hex << off << " (" << fnPtr << ")";
            }
        }
        return ss.str();
    }

    // Slot 6: FindClass(env, name)
    if (slot_id == 6) {
        ss << "FindClass(\"" << SafeReadCString(reinterpret_cast<const void*>(args[1])) << "\")";
        return ss.str();
    }

    // Slot 14: ThrowNew(env, clazz, msg)
    if (slot_id == 14) {
        ss << "ThrowNew(class=" << SafeResolveClass(env, reinterpret_cast<jclass>(args[1])) << ", \"" << SafeReadCString(reinterpret_cast<const void*>(args[2])) << "\")";
        return ss.str();
    }

    // Slot 17: ExceptionClear()
    if (slot_id == 17) {
        return "ExceptionClear()";
    }

    // Slot 228: ExceptionCheck()
    if (slot_id == 228) {
        return "ExceptionCheck()";
    }

    // Slot 31: GetObjectClass(env, obj)
    if (slot_id == 31) {
        ss << "GetObjectClass(obj=" << SafeResolveJObject(env, reinterpret_cast<jobject>(args[1])) << ")";
        return ss.str();
    }

    // Slot 32: IsInstanceOf(env, obj, clazz)
    if (slot_id == 32) {
        ss << "IsInstanceOf(obj=" << SafeResolveJObject(env, reinterpret_cast<jobject>(args[1]))
           << ", class=" << SafeResolveClass(env, reinterpret_cast<jclass>(args[2])) << ")";
        return ss.str();
    }

    // Slot 33: GetMethodID(env, clazz, name, sig)
    // Slot 113: GetStaticMethodID(env, clazz, name, sig)
    if (slot_id == 33 || slot_id == 113) {
        const char* prefix = (slot_id == 113) ? "GetStaticMethodID" : "GetMethodID";
        ss << prefix << "(class=" << SafeResolveClass(env, reinterpret_cast<jclass>(args[1])) << ", \""
           << SafeReadCString(reinterpret_cast<const void*>(args[2])) << "\", \""
           << SafeReadCString(reinterpret_cast<const void*>(args[3])) << "\")";
        return ss.str();
    }

    // Slot 94: GetFieldID, Slot 144: GetStaticFieldID
    if (slot_id == 94 || slot_id == 144) {
        const char* prefix = (slot_id == 144) ? "GetStaticFieldID" : "GetFieldID";
        ss << prefix << "(class=" << SafeResolveClass(env, reinterpret_cast<jclass>(args[1])) << ", \""
           << SafeReadCString(reinterpret_cast<const void*>(args[2])) << "\", \""
           << SafeReadCString(reinterpret_cast<const void*>(args[3])) << "\")";
        return ss.str();
    }

    // Reference management: NewLocalRef, NewGlobalRef, DeleteLocalRef, DeleteGlobalRef
    if (slot_id == 21 || slot_id == 25) {
        const char* p = (slot_id == 21) ? "NewGlobalRef" : "NewLocalRef";
        ss << p << "(obj=" << SafeResolveJObject(env, reinterpret_cast<jobject>(args[1])) << ")";
        return ss.str();
    }
    if (slot_id == 22 || slot_id == 23) {
        const char* p = (slot_id == 22) ? "DeleteGlobalRef" : "DeleteLocalRef";
        ss << p << "(obj=" << SafeResolveJObject(env, reinterpret_cast<jobject>(args[1])) << ")";
        return ss.str();
    }
    if (slot_id == 24) {
        ss << "IsSameObject(" << SafeResolveJObject(env, reinterpret_cast<jobject>(args[1])) << ", "
           << SafeResolveJObject(env, reinterpret_cast<jobject>(args[2])) << ")";
        return ss.str();
    }

    // Field Accessors: Get/Set<Type>Field
    if (sname.rfind("Get", 0) == 0 && sname.find("Field") != std::string::npos && slot_id != 94 && slot_id != 144) {
        bool isStatic = (sname.find("Static") != std::string::npos);
        jobject target = reinterpret_cast<jobject>(args[1]);
        void* fid = reinterpret_cast<void*>(args[2]);
        std::string fidStr = SafeResolveField(env, target, fid, isStatic);
        std::string targetDesc = isStatic ? SafeResolveClass(env, reinterpret_cast<jclass>(target))
                                          : SafeResolveJObject(env, target);
        ss << sname << "(" << (isStatic ? "class=" : "obj=") << targetDesc << ", fid=" << fidStr << ")";
        return ss.str();
    }
    if (sname.rfind("Set", 0) == 0 && sname.find("Field") != std::string::npos) {
        bool isStatic = (sname.find("Static") != std::string::npos);
        jobject target = reinterpret_cast<jobject>(args[1]);
        void* fid = reinterpret_cast<void*>(args[2]);
        std::string fidStr = SafeResolveField(env, target, fid, isStatic);
        std::string targetDesc = isStatic ? SafeResolveClass(env, reinterpret_cast<jclass>(target))
                                          : SafeResolveJObject(env, target);
        ss << sname << "(" << (isStatic ? "class=" : "obj=") << targetDesc << ", fid=" << fidStr;
        if (sname.find("ObjectField") != std::string::npos) {
            ss << ", val=" << SafeResolveJObject(env, reinterpret_cast<jobject>(args[3])) << ")";
        } else {
            ss << ", val=0x" << std::hex << args[3] << ")";
        }
        return ss.str();
    }

    // Slot 167: NewStringUTF(env, bytes)
    if (slot_id == 167) {
        ss << "NewStringUTF(\"" << SafeReadCString(reinterpret_cast<const void*>(args[1])) << "\")";
        return ss.str();
    }

    // Slot 169: GetStringUTFChars(env, string, isCopy)
    if (slot_id == 169) {
        ss << "GetStringUTFChars(str=" << SafeResolveJObject(env, reinterpret_cast<jobject>(args[1])) << ")";
        return ss.str();
    }

    // Slot 170: ReleaseStringUTFChars(env, string, chars)
    if (slot_id == 170) {
        ss << "ReleaseStringUTFChars(str=" << SafeResolveJObject(env, reinterpret_cast<jobject>(args[1])) << ", \"" << SafeReadCString(reinterpret_cast<const void*>(args[2])) << "\")";
        return ss.str();
    }

    // Arrays
    if (sname.rfind("New", 0) == 0 && sname.find("Array") != std::string::npos) {
        if (sname == "NewObjectArray") {
            ss << "NewObjectArray(len=" << std::dec << args[1] << ", class=" << SafeResolveClass(env, reinterpret_cast<jclass>(args[2])) << ")";
        } else {
            ss << sname << "(len=" << std::dec << args[1] << ")";
        }
        return ss.str();
    }
    if (sname.find("ArrayRegion") != std::string::npos) {
        ss << sname << "(arr=" << SafeResolveJObject(env, reinterpret_cast<jobject>(args[1])) << ", start=" << std::dec << args[2] << ", len=" << args[3] << ")";
        return ss.str();
    }
    if (sname == "GetObjectArrayElement") {
        ss << "GetObjectArrayElement(arr=" << SafeResolveJObject(env, reinterpret_cast<jobject>(args[1])) << ", index=" << std::dec << args[2] << ")";
        return ss.str();
    }
    if (sname == "SetObjectArrayElement") {
        ss << "SetObjectArrayElement(arr=" << SafeResolveJObject(env, reinterpret_cast<jobject>(args[1])) << ", index=" << std::dec << args[2]
           << ", val=" << SafeResolveJObject(env, reinterpret_cast<jobject>(args[3])) << ")";
        return ss.str();
    }

    // Call<Type>Method & CallStatic<Type>Method & CallNonvirtual<Type>Method
    if (sname.rfind("Call", 0) == 0 && sname.find("Method") != std::string::npos) {
        bool isStatic = (sname.find("Static") != std::string::npos);
        jobject target = reinterpret_cast<jobject>(args[1]);
        void* mid = reinterpret_cast<void*>(args[2]);
        std::string targetDesc = isStatic ? SafeResolveClass(env, reinterpret_cast<jclass>(target))
                                          : SafeResolveJObject(env, target);
        std::string midDesc = SafeResolveMethod(env, target, mid, isStatic);
        if (isStatic) {
            ss << sname << "(class=" << targetDesc << ", mid=" << midDesc << ")";
        } else {
            ss << sname << "(obj=" << targetDesc << ", mid=" << midDesc << ")";
        }
        return ss.str();
    }

    // Default generic format
    ss << name << "(a1=0x" << std::hex << args[1] << ", a2=0x" << args[2] << ", a3=0x" << args[3] << ")";
    return ss.str();
}

static std::string FormatReturnValue(int slot_id, uint64_t retval, JNIEnv* env) {
    const char* name = (slot_id >= 0 && slot_id < kNumJniSlots) ? kJniSlotNames[slot_id] : "";
    std::string sname = name;

    if (slot_id == 6) { // FindClass
        return SafeResolveClass(env, reinterpret_cast<jclass>(retval));
    }
    if (slot_id == 33 || slot_id == 113) { // GetMethodID, GetStaticMethodID
        std::lock_guard<std::mutex> lk(g_idCacheMutex);
        auto it = g_methodIdNames.find(retval);
        if (it != g_methodIdNames.end()) {
            return "mid:" + it->second;
        }
        char b[32]; snprintf(b, sizeof(b), "mid:0x%lx", (unsigned long)retval); return b;
    }
    if (slot_id == 94 || slot_id == 144) { // GetFieldID, GetStaticFieldID
        std::lock_guard<std::mutex> lk(g_idCacheMutex);
        auto it = g_fieldIdNames.find(retval);
        if (it != g_fieldIdNames.end()) {
            return "fid:" + it->second;
        }
        char b[32]; snprintf(b, sizeof(b), "jfieldID:0x%lx", (unsigned long)retval); return b;
    }
    if (slot_id == 167) { // NewStringUTF
        return SafeResolveJObject(env, reinterpret_cast<jobject>(retval));
    }
    if (slot_id == 169) { // GetStringUTFChars
        return "\"" + SafeReadCString(reinterpret_cast<const void*>(retval)) + "\"";
    }
    if (slot_id == 215) { // RegisterNatives
        return std::to_string(static_cast<int32_t>(retval));
    }
    if (slot_id == 228) { // ExceptionCheck
        return retval ? "true (exception pending)" : "false";
    }
    if (sname.find("Boolean") != std::string::npos) {
        return retval ? "true" : "false";
    }
    if (sname.find("Void") != std::string::npos) {
        return "void";
    }
    if (sname.find("IntMethod") != std::string::npos || sname == "GetIntField" || sname == "GetStaticIntField") {
        return std::to_string(static_cast<int32_t>(retval));
    }
    if (sname.find("LongMethod") != std::string::npos || sname == "GetLongField" || sname == "GetStaticLongField") {
        return std::to_string(static_cast<int64_t>(retval)) + "L";
    }
    if (sname.find("ShortMethod") != std::string::npos || sname == "GetShortField" || sname == "GetStaticShortField") {
        return std::to_string(static_cast<int16_t>(retval));
    }
    if (sname.find("ByteMethod") != std::string::npos || sname == "GetByteField" || sname == "GetStaticByteField") {
        return std::to_string(static_cast<int8_t>(retval));
    }
    if (sname.find("CharMethod") != std::string::npos || sname == "GetCharField" || sname == "GetStaticCharField") {
        char b[16]; snprintf(b, sizeof(b), "'%c'", static_cast<char>(retval)); return b;
    }
    if (sname.find("ObjectMethod") != std::string::npos || sname.rfind("New", 0) == 0 ||
        sname == "GetObjectField" || sname == "GetStaticObjectField" || sname == "GetObjectArrayElement") {
        if (retval == 0) return "null";
        return SafeResolveJObject(env, reinterpret_cast<jobject>(retval));
    }
    char b[32]; snprintf(b, sizeof(b), "0x%lx", (unsigned long)retval); return b;
}

static bool MatchFilters(const std::string& callerMod, const std::string& funcName, const std::string& desc) {
    std::lock_guard<std::mutex> lk(g_filterMutex);
    if (!g_filterConfig.from.empty()) {
        if (callerMod.find(g_filterConfig.from) == std::string::npos) return false;
    }
    if (!g_filterConfig.only.empty()) {
        bool ok = false;
        for (const auto& o : g_filterConfig.only) {
            if (funcName.find(o) != std::string::npos || desc.find(o) != std::string::npos) {
                ok = true; break;
            }
        }
        if (!ok) return false;
    }
    for (const auto& ex : g_filterConfig.exclude) {
        if (funcName.find(ex) != std::string::npos) return false;
    }
    if (!g_filterConfig.className.empty()) {
        if (desc.find(g_filterConfig.className) == std::string::npos) return false;
    }
    if (!g_filterConfig.grep.empty()) {
        if (desc.find(g_filterConfig.grep) == std::string::npos && callerMod.find(g_filterConfig.grep) == std::string::npos) return false;
    }
    return true;
}

// ---------------------------------------------------------------------------
// Hardware Breakpoint Support (jni.hwtrace)
// ---------------------------------------------------------------------------
struct JniHwSession {
    uint32_t id;
    int slot_id;
    std::string func_name;
    uintptr_t target_addr;
};

static std::vector<JniHwSession> g_hwSessions;
static std::mutex g_hwMutex;

}} // namespace artpi::agent

// ---------------------------------------------------------------------------
// C Entry Points from Assembly Trampoline
// ---------------------------------------------------------------------------

extern "C" void* ArtpiJniGetRealFunc(int slot_id) {
    if (slot_id >= 0 && slot_id < artpi::agent::kNumJniSlots) {
        return artpi::agent::g_real_jni_table[slot_id];
    }
    return nullptr;
}

extern "C" void ArtpiJniOnEnter(int slot_id, void* env, uint64_t* saved_regs, void* lr) {
    using namespace artpi::agent;
    if (t_insideJniTracer || !g_vtableTracing.load(std::memory_order_relaxed)) return;
    TracerGuard guard(t_insideJniTracer);

    JNIEnv* jniEnv = reinterpret_cast<JNIEnv*>(env);
    uintptr_t off = 0;
    std::string callerMod = GetCallerModule(lr, &off);
    const char* fname = (slot_id >= 0 && slot_id < kNumJniSlots) ? kJniSlotNames[slot_id] : "slot";
    std::string desc = DescribeJniCall(slot_id, jniEnv, saved_regs);

    bool matched = MatchFilters(callerMod, fname, desc);

    uint64_t now = std::chrono::duration_cast<std::chrono::nanoseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();

    char callerBuf[64];
    snprintf(callerBuf, sizeof(callerBuf), "%s+0x%lx", callerMod.c_str(), (unsigned long)off);

    std::string pendingIdName;
    if (slot_id == 33 || slot_id == 113) {
        std::string cname = SafeResolveJObject(jniEnv, reinterpret_cast<jobject>(saved_regs[1]));
        if (cname.rfind("<class ", 0) == 0 && cname.back() == '>') {
            cname = cname.substr(7, cname.size() - 8);
        }
        std::string mname = SafeReadCString(reinterpret_cast<const void*>(saved_regs[2]));
        std::string sig = SafeReadCString(reinterpret_cast<const void*>(saved_regs[3]));
        pendingIdName = (cname.empty() ? "" : SimplifyJavaType(cname) + ".") + mname + sig;
    } else if (slot_id == 94 || slot_id == 144) {
        std::string cname = SafeResolveJObject(jniEnv, reinterpret_cast<jobject>(saved_regs[1]));
        if (cname.rfind("<class ", 0) == 0 && cname.back() == '>') {
            cname = cname.substr(7, cname.size() - 8);
        }
        std::string fname_str = SafeReadCString(reinterpret_cast<const void*>(saved_regs[2]));
        std::string sig = SafeReadCString(reinterpret_cast<const void*>(saved_regs[3]));
        pendingIdName = (cname.empty() ? "" : SimplifyJavaType(cname) + ".") + fname_str + ":" + sig;
    }

    std::string stack_str;
    if (matched && g_filterConfig.stack) {
        stack_str = CaptureJniCallStack(reinterpret_cast<uintptr_t>(lr), 0);
    }

    t_callStack.push_back({slot_id, now, desc, callerBuf, matched, pendingIdName, stack_str});
}

extern "C" void ArtpiJniOnLeave(int slot_id, void* env, uint64_t retval, void* /*lr*/) {
    using namespace artpi::agent;
    if (t_insideJniTracer || !g_vtableTracing.load(std::memory_order_relaxed) || t_callStack.empty()) return;
    TracerGuard guard(t_insideJniTracer);

    JNIEnv* jniEnv = reinterpret_cast<JNIEnv*>(env);
    JniCallFrame fr = t_callStack.back();
    t_callStack.pop_back();

    // Cache method / field IDs if pending
    if ((slot_id == 33 || slot_id == 113) && retval != 0 && !fr.pendingIdName.empty()) {
        std::lock_guard<std::mutex> lk(g_idCacheMutex);
        g_methodIdNames[retval] = fr.pendingIdName;
    } else if ((slot_id == 94 || slot_id == 144) && retval != 0 && !fr.pendingIdName.empty()) {
        std::lock_guard<std::mutex> lk(g_idCacheMutex);
        g_fieldIdNames[retval] = fr.pendingIdName;
    }

    if (fr.matched) {
        uint64_t now = std::chrono::duration_cast<std::chrono::nanoseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count();
        double ms = (now - fr.start_ns) / 1e6;

        std::string retStr = FormatReturnValue(slot_id, retval, jniEnv);
        std::string ind(t_callStack.size() * 2, ' ');
        char timeBuf[32];
        snprintf(timeBuf, sizeof(timeBuf), " (%.3f ms)", ms);

        std::string line = "[JNI] " + ind + fr.call_desc + " = " + retStr + timeBuf + "  [" + fr.caller_desc + "]";
        if (!fr.stack_str.empty()) {
            line += "\n" + fr.stack_str;
            if (!line.empty() && line.back() == '\n') line.pop_back();
        }
        BroadcastLog("console", line);
        __android_log_print(ANDROID_LOG_INFO, JNI_TAG, "%s", line.c_str());
    }
}

// ---------------------------------------------------------------------------
// QuickJS REPL Bindings
// ---------------------------------------------------------------------------

namespace artpi { namespace agent {

bool JniStartTrace(const std::string& filterStr) {
    JNIEnv* env = GetEnv();
    if (!env) return false;

    {
        std::lock_guard<std::mutex> lk(g_filterMutex);
        g_filterConfig = JniFilterConfig();
        if (!filterStr.empty()) {
            if (filterStr.find(".so") != std::string::npos) {
                g_filterConfig.from = filterStr;
            } else if (filterStr.rfind("com.", 0) == 0 || filterStr.rfind("android.", 0) == 0) {
                g_filterConfig.className = filterStr;
            } else if (filterStr.front() == '/' && filterStr.back() == '/') {
                g_filterConfig.grep = filterStr.substr(1, filterStr.size() - 2);
            } else {
                g_filterConfig.only.push_back(filterStr);
            }
        }
    }

    return InstallVtableHook(env);
}

bool JniStopTrace() {
    return UninstallVtableHook();
}

bool JniIsTracing() {
    return g_vtableTracing.load();
}

// JNI.trace(filter)
static JSValue JsJniTrace(JSContext* ctx, JSValueConst /*this_val*/, int argc, JSValueConst* argv) {
    JNIEnv* env = GetEnv();
    if (!env) {
        return JS_ThrowInternalError(ctx, "[!] Failed to acquire JNIEnv in current process");
    }

    {
        std::lock_guard<std::mutex> lk(g_filterMutex);
        g_filterConfig = JniFilterConfig();

        if (argc >= 1) {
            JSValue arg = argv[0];
            if (JS_IsString(arg)) {
                const char* s = JS_ToCString(ctx, arg);
                if (s) {
                    std::string fstr = s;
                    JS_FreeCString(ctx, s);
                    if (fstr.find(".so") != std::string::npos) {
                        g_filterConfig.from = fstr;
                    } else if (fstr.rfind("com.", 0) == 0 || fstr.rfind("android.", 0) == 0) {
                        g_filterConfig.className = fstr;
                    } else if (fstr.front() == '/' && fstr.back() == '/' && fstr.size() > 2) {
                        g_filterConfig.grep = fstr.substr(1, fstr.size() - 2);
                    } else {
                        // support comma-separated list
                        std::istringstream iss(fstr);
                        std::string item;
                        while (std::getline(iss, item, ',')) {
                            while (!item.empty() && item.front() == ' ') item.erase(item.begin());
                            while (!item.empty() && item.back() == ' ') item.pop_back();
                            if (!item.empty()) {
                                if (item.front() == '!') {
                                    g_filterConfig.exclude.push_back(item.substr(1));
                                } else {
                                    g_filterConfig.only.push_back(item);
                                }
                            }
                        }
                    }
                }
            } else if (JS_IsObject(arg)) {
                JSValue fromVal = JS_GetPropertyStr(ctx, arg, "from");
                if (JS_IsString(fromVal)) {
                    const char* s = JS_ToCString(ctx, fromVal);
                    if (s) { g_filterConfig.from = s; JS_FreeCString(ctx, s); }
                }
                JS_FreeValue(ctx, fromVal);

                JSValue onlyVal = JS_GetPropertyStr(ctx, arg, "only");
                if (JS_IsString(onlyVal)) {
                    const char* s = JS_ToCString(ctx, onlyVal);
                    if (s) { g_filterConfig.only.push_back(s); JS_FreeCString(ctx, s); }
                }
                JS_FreeValue(ctx, onlyVal);

                JSValue exclVal = JS_GetPropertyStr(ctx, arg, "exclude");
                if (JS_IsString(exclVal)) {
                    const char* s = JS_ToCString(ctx, exclVal);
                    if (s) { g_filterConfig.exclude.push_back(s); JS_FreeCString(ctx, s); }
                }
                JS_FreeValue(ctx, exclVal);

                JSValue classVal = JS_GetPropertyStr(ctx, arg, "class");
                if (JS_IsString(classVal)) {
                    const char* s = JS_ToCString(ctx, classVal);
                    if (s) { g_filterConfig.className = s; JS_FreeCString(ctx, s); }
                }
                JS_FreeValue(ctx, classVal);

                JSValue grepVal = JS_GetPropertyStr(ctx, arg, "grep");
                if (JS_IsString(grepVal)) {
                    const char* s = JS_ToCString(ctx, grepVal);
                    if (s) { g_filterConfig.grep = s; JS_FreeCString(ctx, s); }
                }
                JS_FreeValue(ctx, grepVal);

                JSValue stackVal = JS_GetPropertyStr(ctx, arg, "stack");
                if (!JS_IsUndefined(stackVal)) {
                    g_filterConfig.stack = JS_ToBool(ctx, stackVal);
                }
                JS_FreeValue(ctx, stackVal);
            }
        }
    }

    if (!InstallVtableHook(env)) {
        return JS_ThrowInternalError(ctx, "[!] Failed to install JNI Vtable hook (check arch/mprotect)");
    }

    std::ostringstream msg;
    msg << "[*] JNI Vtable global trace started!\n"
        << "    From module : " << (g_filterConfig.from.empty() ? "<any>" : g_filterConfig.from) << "\n"
        << "    Only slots  : " << (g_filterConfig.only.empty() ? "<all>" : g_filterConfig.only[0]) << "\n"
        << "    Class filter: " << (g_filterConfig.className.empty() ? "<any>" : g_filterConfig.className) << "\n"
        << "    Type `jni.stop()` or `jnistop()` in REPL to restore original vtable.";
    BroadcastLog("console", msg.str());

    JSValue res = JS_NewObject(ctx);
    JS_SetPropertyStr(ctx, res, "status", JS_NewString(ctx, "active"));
    JS_SetPropertyStr(ctx, res, "stop", JS_NewCFunction(ctx, [](JSContext* c, JSValueConst, int, JSValueConst*) -> JSValue {
        UninstallVtableHook();
        BroadcastLog("console", "[*] JNI trace stopped. Original Vtable restored.");
        return JS_UNDEFINED;
    }, "stop", 0));
    return res;
}

// JNI.stop() / JNI.untrace()
static JSValue JsJniStop(JSContext* ctx, JSValueConst /*this_val*/, int /*argc*/, JSValueConst* /*argv*/) {
    UninstallVtableHook();
    std::string msg = "[*] JNI tracing stopped. Original JNINativeInterface table restored (100% clean).";
    BroadcastLog("console", msg);
    return JS_NewString(ctx, msg.c_str());
}

// Helper to resolve slot names for HW breakpoint arming
static std::vector<int> ResolveSlotsForHw(const std::string& name) {
    std::vector<int> slots;
    int baseSlot = FindSlotByName(name);
    if (baseSlot >= 0) {
        slots.push_back(baseSlot);
        // If user provided a base name that doesn't end with 'V' or 'A',
        // check if an equivalent 'V' variant exists (e.g. CallIntMethod -> CallIntMethodV).
        // In Android C++ NDK, calls like env->CallIntMethod(...) expand to CallIntMethodV.
        if (!name.empty() && name.back() != 'V' && name.back() != 'A') {
            std::string vName = name + "V";
            int vSlot = FindSlotByName(vName);
            if (vSlot >= 0) {
                slots.push_back(vSlot);
            }
        }
    }
    return slots;
}

// JNI.hwtrace(funcName, [optionsOrCallback])
static JSValue JsJniHwTrace(JSContext* ctx, JSValueConst /*this_val*/, int argc, JSValueConst* argv) {
    if (argc < 1) {
        return JS_ThrowTypeError(ctx, "Usage: JNI.hwtrace(funcName, [callbackOrOpts])\n"
                                      "Example: JNI.hwtrace(\"RegisterNatives\")\n"
                                      "         JNI.hwtrace(\"CallIntMethod\")\n"
                                      "         JNI.hwtrace(\"FindClass\", (ctx) => { ... })");
    }

    std::string funcName;
    bool optStack = false;
    JSValue userOnEnter = JS_UNDEFINED;
    JSValue userOnLeave = JS_UNDEFINED;

    if (JS_IsObject(argv[0])) {
        JSValue fnVal = JS_GetPropertyStr(ctx, argv[0], "func");
        if (!JS_IsString(fnVal)) {
            JS_FreeValue(ctx, fnVal);
            fnVal = JS_GetPropertyStr(ctx, argv[0], "name");
        }
        if (JS_IsString(fnVal)) {
            const char* s = JS_ToCString(ctx, fnVal);
            if (s) { funcName = s; JS_FreeCString(ctx, s); }
        }
        JS_FreeValue(ctx, fnVal);

        JSValue stVal = JS_GetPropertyStr(ctx, argv[0], "stack");
        if (!JS_IsUndefined(stVal)) optStack = JS_ToBool(ctx, stVal);
        JS_FreeValue(ctx, stVal);

        JSValue enterVal = JS_GetPropertyStr(ctx, argv[0], "onEnter");
        if (JS_IsFunction(ctx, enterVal)) userOnEnter = enterVal; else JS_FreeValue(ctx, enterVal);

        JSValue leaveVal = JS_GetPropertyStr(ctx, argv[0], "onLeave");
        if (JS_IsFunction(ctx, leaveVal)) userOnLeave = leaveVal; else JS_FreeValue(ctx, leaveVal);
    } else {
        const char* fnStr = JS_ToCString(ctx, argv[0]);
        if (!fnStr) return JS_ThrowTypeError(ctx, "funcName must be a string or config object");
        funcName = fnStr;
        JS_FreeCString(ctx, fnStr);
    }

    if (argc > 1) {
        if (JS_IsFunction(ctx, argv[1])) {
            userOnLeave = JS_DupValue(ctx, argv[1]);
        } else if (JS_IsObject(argv[1])) {
            JSValue stVal = JS_GetPropertyStr(ctx, argv[1], "stack");
            if (!JS_IsUndefined(stVal)) optStack = JS_ToBool(ctx, stVal);
            JS_FreeValue(ctx, stVal);

            JSValue enterVal = JS_GetPropertyStr(ctx, argv[1], "onEnter");
            if (JS_IsFunction(ctx, enterVal)) userOnEnter = enterVal; else JS_FreeValue(ctx, enterVal);

            JSValue leaveVal = JS_GetPropertyStr(ctx, argv[1], "onLeave");
            if (JS_IsFunction(ctx, leaveVal)) userOnLeave = leaveVal; else JS_FreeValue(ctx, leaveVal);
        }
    }

    std::vector<int> slotsToArm = ResolveSlotsForHw(funcName);
    if (slotsToArm.empty()) {
        std::string err = "[!] Unknown JNI function name: " + funcName + " (valid names: RegisterNatives, FindClass, NewStringUTF...)";
        return JS_ThrowTypeError(ctx, "%s", err.c_str());
    }

    JNIEnv* env = GetEnv();
    if (!env || !EnsureBackupTable(env)) {
        return JS_ThrowInternalError(ctx, "[!] Failed to get JNIEnv or read original function address");
    }

    auto enterGuard = std::shared_ptr<JSValue>(new JSValue(userOnEnter), [](JSValue* p) {
        if (p) {
            if (g_ctx && !JS_IsUndefined(*p)) JS_FreeValue(g_ctx, *p);
            delete p;
        }
    });

    auto leaveGuard = std::shared_ptr<JSValue>(new JSValue(userOnLeave), [](JSValue* p) {
        if (p) {
            if (g_ctx && !JS_IsUndefined(*p)) JS_FreeValue(g_ctx, *p);
            delete p;
        }
    });

    std::vector<uint32_t> armedIds;
    std::vector<uintptr_t> armedAddrs;

    for (int slot : slotsToArm) {
        std::string targetName = kJniSlotNames[slot];
        void* targetFunc = g_real_jni_table[slot];
        if (!targetFunc) continue;

        uintptr_t addr = reinterpret_cast<uintptr_t>(targetFunc);

        PI::Native::HwHookConfig cfg;
        cfg.type = PI::Native::HwHookType::BREAKPOINT;
        cfg.address = addr;
        cfg.tag = "JNI_" + targetName;

        cfg.on_hit = [targetName, slot, enterGuard, leaveGuard, optStack](PI::Native::HwCpuContext& hwctx) {
            if (t_insideJniTracer) return;
            TracerGuard guard(t_insideJniTracer);

            JNIEnv* curEnv = reinterpret_cast<JNIEnv*>(hwctx.x[0]);
            uintptr_t lr = static_cast<uintptr_t>(hwctx.lr);
            pid_t tid = hwctx.thread_id;
            uintptr_t off = 0;
            std::string callerMod = GetCallerModule(reinterpret_cast<void*>(lr), &off);

            char callerBuf[64];
            snprintf(callerBuf, sizeof(callerBuf), "%s+0x%lx", callerMod.c_str(), (unsigned long)off);

            std::string desc = DescribeJniCall(slot, curEnv, hwctx.x);
            uint64_t start_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(
                std::chrono::steady_clock::now().time_since_epoch()).count();

            std::string capturedStack;
            if (optStack || !JS_IsUndefined(*enterGuard) || !JS_IsUndefined(*leaveGuard)) {
                capturedStack = CaptureJniCallStack(hwctx.lr, hwctx.fp);
            }

            // User onEnter JS callback
            if (g_ctx && !JS_IsUndefined(*enterGuard)) {
                std::lock_guard<std::mutex> lk(g_jsMutex);
                JSValue ctxObj = JS_NewObject(g_ctx);
                JS_SetPropertyStr(g_ctx, ctxObj, "func", JS_NewString(g_ctx, targetName.c_str()));
                JS_SetPropertyStr(g_ctx, ctxObj, "caller", JS_NewString(g_ctx, callerBuf));
                JS_SetPropertyStr(g_ctx, ctxObj, "stack", JS_NewString(g_ctx, capturedStack.c_str()));
                JS_SetPropertyStr(g_ctx, ctxObj, "lr", JS_NewInt64(g_ctx, hwctx.lr));
                JS_SetPropertyStr(g_ctx, ctxObj, "sp", JS_NewInt64(g_ctx, hwctx.sp));
                JS_SetPropertyStr(g_ctx, ctxObj, "fp", JS_NewInt64(g_ctx, hwctx.fp));
                JSValue r = JS_Call(g_ctx, *enterGuard, JS_UNDEFINED, 1, &ctxObj);
                JS_FreeValue(g_ctx, ctxObj);
                if (JS_IsException(r)) {
                    JSValue exc = JS_GetException(g_ctx);
                    JS_FreeValue(g_ctx, exc);
                } else {
                    JS_FreeValue(g_ctx, r);
                }
            }

            // Cache pending method / field name for GetMethodID / GetFieldID if applicable
            std::string pendingIdName;
            if (slot == 33 || slot == 113) {
                std::string cname = SafeResolveJObject(curEnv, reinterpret_cast<jobject>(hwctx.x[1]));
                if (cname.rfind("<class ", 0) == 0 && cname.back() == '>') {
                    cname = cname.substr(7, cname.size() - 8);
                }
                std::string mname = SafeReadCString(reinterpret_cast<const void*>(hwctx.x[2]));
                std::string sig = SafeReadCString(reinterpret_cast<const void*>(hwctx.x[3]));
                pendingIdName = (cname.empty() ? "" : SimplifyJavaType(cname) + ".") + mname + sig;
            } else if (slot == 94 || slot == 144) {
                std::string cname = SafeResolveJObject(curEnv, reinterpret_cast<jobject>(hwctx.x[1]));
                if (cname.rfind("<class ", 0) == 0 && cname.back() == '>') {
                    cname = cname.substr(7, cname.size() - 8);
                }
                std::string fname_str = SafeReadCString(reinterpret_cast<const void*>(hwctx.x[2]));
                std::string sig = SafeReadCString(reinterpret_cast<const void*>(hwctx.x[3]));
                pendingIdName = (cname.empty() ? "" : SimplifyJavaType(cname) + ".") + fname_str + ":" + sig;
            }

            bool retArmed = false;
            if (lr > 0x1000) {
                PI::Native::HwHookConfig retCfg;
                retCfg.type = PI::Native::HwHookType::BREAKPOINT;
                retCfg.address = lr;
                retCfg.thread_id = tid;
                retCfg.once = true;
                retCfg.tag = "JNI_RET_" + targetName;

                std::string callerStr = callerBuf;
                retCfg.on_hit = [targetName, slot, desc, callerStr, start_ns, leaveGuard, curEnv, pendingIdName, optStack, capturedStack](PI::Native::HwCpuContext& retCtx) {
                    if (t_insideJniTracer) return;
                    TracerGuard retGuard(t_insideJniTracer);

                    uint64_t now = std::chrono::duration_cast<std::chrono::nanoseconds>(
                        std::chrono::steady_clock::now().time_since_epoch()).count();
                    double ms = (now - start_ns) / 1e6;

                    uint64_t retval = retCtx.x[0];
                    if ((slot == 33 || slot == 113) && retval != 0 && !pendingIdName.empty()) {
                        std::lock_guard<std::mutex> lk(g_idCacheMutex);
                        g_methodIdNames[retval] = pendingIdName;
                    } else if ((slot == 94 || slot == 144) && retval != 0 && !pendingIdName.empty()) {
                        std::lock_guard<std::mutex> lk(g_idCacheMutex);
                        g_fieldIdNames[retval] = pendingIdName;
                    }

                    std::string retStr = FormatReturnValue(slot, retval, curEnv);
                    char timeBuf[32];
                    snprintf(timeBuf, sizeof(timeBuf), " (%.3f ms)", ms);

                    std::string line = "[HW-JNI] " + desc + " = " + retStr + timeBuf + "  [" + callerStr + "]";
                    if (optStack && !capturedStack.empty()) {
                        line += "\n" + capturedStack;
                        if (!line.empty() && line.back() == '\n') line.pop_back();
                    }
                    BroadcastLog("console", line);
                    __android_log_print(ANDROID_LOG_INFO, JNI_TAG, "%s", line.c_str());

                    // JS callback on return
                    if (g_ctx && !JS_IsUndefined(*leaveGuard)) {
                        std::lock_guard<std::mutex> lk(g_jsMutex);
                        JSValue ctxObj = JS_NewObject(g_ctx);
                        JS_SetPropertyStr(g_ctx, ctxObj, "func", JS_NewString(g_ctx, targetName.c_str()));
                        JS_SetPropertyStr(g_ctx, ctxObj, "retval", JS_NewInt64(g_ctx, retval));
                        JS_SetPropertyStr(g_ctx, ctxObj, "retStr", JS_NewString(g_ctx, retStr.c_str()));
                        JS_SetPropertyStr(g_ctx, ctxObj, "caller", JS_NewString(g_ctx, callerStr.c_str()));
                        JS_SetPropertyStr(g_ctx, ctxObj, "duration_ms", JS_NewFloat64(g_ctx, ms));
                        JS_SetPropertyStr(g_ctx, ctxObj, "stack", JS_NewString(g_ctx, capturedStack.c_str()));
                        JSValue r = JS_Call(g_ctx, *leaveGuard, JS_UNDEFINED, 1, &ctxObj);
                        JS_FreeValue(g_ctx, ctxObj);
                        if (JS_IsException(r)) {
                            JSValue exc = JS_GetException(g_ctx);
                            JS_FreeValue(g_ctx, exc);
                        } else {
                            JS_FreeValue(g_ctx, r);
                        }
                    }
                };

                uint32_t retBpId = PI::Native::HwHookManager::instance().attach(retCfg);
                if (retBpId != 0) {
                    retArmed = true;
                }
            }

            if (!retArmed) {
                // Fallback: print entry immediately if return breakpoint couldn't be set
                std::string line = "[HW-JNI] " + desc + "  [" + callerBuf + "]";
                if (optStack && !capturedStack.empty()) {
                    line += "\n" + capturedStack;
                    if (!line.empty() && line.back() == '\n') line.pop_back();
                }
                BroadcastLog("console", line);
                __android_log_print(ANDROID_LOG_INFO, JNI_TAG, "%s", line.c_str());

                if (g_ctx && !JS_IsUndefined(*leaveGuard)) {
                    std::lock_guard<std::mutex> lk(g_jsMutex);
                    JSValue ctxObj = JS_NewObject(g_ctx);
                    JS_SetPropertyStr(g_ctx, ctxObj, "func", JS_NewString(g_ctx, targetName.c_str()));
                    JS_SetPropertyStr(g_ctx, ctxObj, "caller", JS_NewString(g_ctx, callerMod.c_str()));
                    JS_SetPropertyStr(g_ctx, ctxObj, "stack", JS_NewString(g_ctx, capturedStack.c_str()));
                    JSValue r = JS_Call(g_ctx, *leaveGuard, JS_UNDEFINED, 1, &ctxObj);
                    JS_FreeValue(g_ctx, ctxObj);
                    if (JS_IsException(r)) {
                        JSValue exc = JS_GetException(g_ctx);
                        JS_FreeValue(g_ctx, exc);
                    } else {
                        JS_FreeValue(g_ctx, r);
                    }
                }
            }
        };

        uint32_t bpId = PI::Native::HwHookManager::instance().attach(cfg);
        if (bpId != 0) {
            armedIds.push_back(bpId);
            armedAddrs.push_back(addr);
            {
                std::lock_guard<std::mutex> lk(g_hwMutex);
                g_hwSessions.push_back({bpId, slot, targetName, addr});
            }
            char msg[128];
            snprintf(msg, sizeof(msg), "[+] HW Breakpoint armed on JNI %s @ %p (ID: %u)", targetName.c_str(), (void*)addr, bpId);
            BroadcastLog("console", msg);
        }
    }

    if (armedIds.empty()) {
        return JS_ThrowInternalError(ctx, "[!] Failed to set hardware breakpoint on %s (slots exhausted?)", funcName.c_str());
    }

    JSValue res = JS_NewObject(ctx);
    JS_SetPropertyStr(ctx, res, "id", JS_NewInt32(ctx, armedIds[0]));
    JS_SetPropertyStr(ctx, res, "func", JS_NewString(ctx, funcName.c_str()));
    char abuf[32]; snprintf(abuf, sizeof(abuf), "0x%lx", (unsigned long)armedAddrs[0]);
    JS_SetPropertyStr(ctx, res, "address", JS_NewString(ctx, abuf));

    JSValue idsArr = JS_NewArray(ctx);
    for (size_t i = 0; i < armedIds.size(); ++i) {
        JS_SetPropertyUint32(ctx, idsArr, i, JS_NewInt32(ctx, armedIds[i]));
    }
    JS_SetPropertyStr(ctx, res, "ids", idsArr);

    JS_SetPropertyStr(ctx, res, "detach", JS_NewCFunction(ctx, [](JSContext* c, JSValueConst this_val, int, JSValueConst*) -> JSValue {
        JSValue idsVal = JS_GetPropertyStr(c, this_val, "ids");
        std::vector<uint32_t> toDetach;
        if (JS_IsArray(c, idsVal)) {
            int64_t len = 0;
            JSValue lenVal = JS_GetPropertyStr(c, idsVal, "length");
            JS_ToInt64(c, &len, lenVal);
            JS_FreeValue(c, lenVal);
            for (int64_t i = 0; i < len; ++i) {
                JSValue item = JS_GetPropertyUint32(c, idsVal, i);
                int32_t id = 0;
                JS_ToInt32(c, &id, item);
                JS_FreeValue(c, item);
                if (id > 0) toDetach.push_back(static_cast<uint32_t>(id));
            }
        } else {
            JSValue idVal = JS_GetPropertyStr(c, this_val, "id");
            int32_t id = 0;
            JS_ToInt32(c, &id, idVal);
            JS_FreeValue(c, idVal);
            if (id > 0) toDetach.push_back(static_cast<uint32_t>(id));
        }
        JS_FreeValue(c, idsVal);

        for (uint32_t id : toDetach) {
            PI::Native::HwHookManager::instance().detach(id);
            std::lock_guard<std::mutex> lk(g_hwMutex);
            g_hwSessions.erase(std::remove_if(g_hwSessions.begin(), g_hwSessions.end(),
                [id](const JniHwSession& s) { return s.id == id; }), g_hwSessions.end());
        }
        BroadcastLog("console", "[+] HW Breakpoint detached.");
        return JS_UNDEFINED;
    }, "detach", 0));
    return res;
}

// JNI.hwdetachAll() / JNI.hwstop()
static JSValue JsJniHwDetachAll(JSContext* ctx, JSValueConst /*this_val*/, int /*argc*/, JSValueConst* /*argv*/) {
    std::lock_guard<std::mutex> lk(g_hwMutex);
    size_t cnt = 0;
    for (const auto& s : g_hwSessions) {
        PI::Native::HwHookManager::instance().detach(s.id);
        cnt++;
    }
    g_hwSessions.clear();
    std::string msg = "[+] Detached " + std::to_string(cnt) + " JNI hardware breakpoint(s).";
    BroadcastLog("console", msg);
    return JS_NewString(ctx, msg.c_str());
}

// JNI.status()
static JSValue JsJniStatus(JSContext* ctx, JSValueConst /*this_val*/, int /*argc*/, JSValueConst* /*argv*/) {
    JSValue obj = JS_NewObject(ctx);
    JS_SetPropertyStr(ctx, obj, "vtableTracing", JS_NewBool(ctx, g_vtableTracing.load()));
    std::lock_guard<std::mutex> lk(g_hwMutex);
    JSValue arr = JS_NewArray(ctx);
    for (size_t i = 0; i < g_hwSessions.size(); ++i) {
        JSValue item = JS_NewObject(ctx);
        JS_SetPropertyStr(ctx, item, "id", JS_NewInt32(ctx, g_hwSessions[i].id));
        JS_SetPropertyStr(ctx, item, "func", JS_NewString(ctx, g_hwSessions[i].func_name.c_str()));
        char abuf[32]; snprintf(abuf, sizeof(abuf), "0x%lx", (unsigned long)g_hwSessions[i].target_addr);
        JS_SetPropertyStr(ctx, item, "address", JS_NewString(ctx, abuf));
        JS_SetPropertyUint32(ctx, arr, i, item);
    }
    JS_SetPropertyStr(ctx, obj, "hwBreakpoints", arr);
    return obj;
}

JniStatusInfo JniGetStatusInfo() {
    JniStatusInfo info;
    info.vtableTracing = g_vtableTracing.load(std::memory_order_relaxed);
    {
        std::lock_guard<std::mutex> lk(g_filterMutex);
        info.from = g_filterConfig.from;
        if (!g_filterConfig.only.empty()) {
            for (size_t i = 0; i < g_filterConfig.only.size(); ++i) {
                if (i > 0) info.only += ", ";
                info.only += g_filterConfig.only[i];
            }
        }
        if (!g_filterConfig.exclude.empty()) {
            for (size_t i = 0; i < g_filterConfig.exclude.size(); ++i) {
                if (i > 0) info.exclude += ", ";
                info.exclude += g_filterConfig.exclude[i];
            }
        }
        info.className = g_filterConfig.className;
        info.grep = g_filterConfig.grep;
    }
    {
        std::lock_guard<std::mutex> lk(g_hwMutex);
        for (const auto& s : g_hwSessions) {
            info.hwSessions.push_back({s.id, s.func_name, s.target_addr});
        }
    }
    return info;
}

void RegisterJniApis(JSContext* ctx, JSValue global, JSValue jni) {
    // 1. Mount on JNI / jni namespace
    JS_SetPropertyStr(ctx, jni, "trace", JS_NewCFunction(ctx, JsJniTrace, "trace", 1));
    JS_SetPropertyStr(ctx, jni, "stop", JS_NewCFunction(ctx, JsJniStop, "stop", 0));
    JS_SetPropertyStr(ctx, jni, "untrace", JS_NewCFunction(ctx, JsJniStop, "untrace", 0));
    JS_SetPropertyStr(ctx, jni, "hwtrace", JS_NewCFunction(ctx, JsJniHwTrace, "hwtrace", 2));
    JS_SetPropertyStr(ctx, jni, "hwstop", JS_NewCFunction(ctx, JsJniHwDetachAll, "hwstop", 0));
    JS_SetPropertyStr(ctx, jni, "hwdetachAll", JS_NewCFunction(ctx, JsJniHwDetachAll, "hwdetachAll", 0));
    JS_SetPropertyStr(ctx, jni, "status", JS_NewCFunction(ctx, JsJniStatus, "status", 0));

    // 2. Flat top-level convenience functions for inline REPL
    JS_SetPropertyStr(ctx, global, "jnitrace", JS_NewCFunction(ctx, JsJniTrace, "jnitrace", 1));
    JS_SetPropertyStr(ctx, global, "jnihw", JS_NewCFunction(ctx, JsJniHwTrace, "jnihw", 2));
    JS_SetPropertyStr(ctx, global, "jnistop", JS_NewCFunction(ctx, JsJniStop, "jnistop", 0));
    JS_SetPropertyStr(ctx, global, "jnihwstop", JS_NewCFunction(ctx, JsJniHwDetachAll, "jnihwstop", 0));
    JS_SetPropertyStr(ctx, global, "jnihwdetachAll", JS_NewCFunction(ctx, JsJniHwDetachAll, "jnihwdetachAll", 0));
}

}} // namespace artpi::agent
