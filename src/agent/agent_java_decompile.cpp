//
// agent_java_decompile.cpp - Smali disassembly, JADX runtime decompile & Dex memory export
//
#include "agent_java_decompile.h"
#include "agent_java_ref.h"
#include "agent_java.h"
#include "agent_common.h"
#include "../../include/ArtPI.h"
#include "art/art_method.h"

#include <sstream>
#include <vector>
#include <string>
#include <algorithm>
#include <unordered_set>
#include <cstring>
#include <cstdio>
#include <sys/stat.h>
#include <sys/uio.h>
#include <sys/syscall.h>
#include <fcntl.h>
#include <unistd.h>

namespace artpi { namespace agent {

// ---------------------------------------------------------------------------
// Dump Smali & Unified Code Disassembly
// ---------------------------------------------------------------------------
static std::string DumpMethodsOfClass(JNIEnv* env, jclass cls, const std::string& className, int maxInsn, bool smaliOnly) {
    if (!env || !cls) return "";
    jclass classCls = AgentCachedClass("java/lang/Class");
    if (!classCls) return "";
    jmethodID getDeclaredMethods = env->GetMethodID(classCls, "getDeclaredMethods", "()[Ljava/lang/reflect/Method;");
    if (env->ExceptionCheck()) { env->ExceptionClear(); return ""; }
    if (!getDeclaredMethods) return "";

    auto mArr = (jobjectArray)env->CallObjectMethod(cls, getDeclaredMethods);
    if (env->ExceptionCheck()) { env->ExceptionClear(); return ""; }
    if (!mArr) return "";

    jsize len = env->GetArrayLength(mArr);
    std::ostringstream ss;
    std::string tag = smaliOnly ? "DumpSmali" : "DumpCode";
    std::string title = className.empty() ? "Class" : className;
    ss << "=== " << tag << " for " << title << " (" << len << " methods) ===\n\n";
    for (jsize i = 0; i < len; ++i) {
        jobject mObj = env->GetObjectArrayElement(mArr, i);
        if (mObj) {
            PI::Method pm = PI::resolve(env, mObj);
            if (pm.isValid()) {
                if (smaliOnly) {
                    ss << pm.dumpSmali(maxInsn) << "\n";
                } else {
                    ss << pm.dumpCode(maxInsn) << "\n";
                }
            }
            env->DeleteLocalRef(mObj);
        }
    }
    env->DeleteLocalRef(mArr);
    return ss.str();
}

static JSValue JsDumpSmali(JSContext* ctx, JSValueConst /*this_val*/, int argc, JSValueConst* argv) {
    if (argc < 1) return JS_NewString(ctx, "Usage: dumpSmali(artMethodPtrOrClass, [maxInstructions])");
    int maxInsn = -1;
    if (argc >= 2) JS_ToInt32(ctx, &maxInsn, argv[1]);

    JNIEnv* env = GetEnv();
    int64_t ptr = 0;

    // 1. If JS Object: check $className or pointer fields
    if (JS_IsObject(argv[0])) {
        JSValue cn = JS_GetPropertyStr(ctx, argv[0], "$className");
        if (JS_IsString(cn)) {
            const char* cstr = JS_ToCString(ctx, cn);
            std::string className = cstr ? cstr : "";
            JS_FreeCString(ctx, cstr);
            JS_FreeValue(ctx, cn);
            if (!className.empty()) {
                if (env) {
                    jclass cls = FindClassWithFallback(env, className);
                    if (cls) {
                        std::string out = DumpMethodsOfClass(env, cls, className, maxInsn, true);
                        env->DeleteLocalRef(cls);
                        return JS_NewString(ctx, out.c_str());
                    }
                }
                return JS_NewString(ctx, ("[!] Class not found: " + className).c_str());
            }
        } else {
            JS_FreeValue(ctx, cn);
            JSValue artVal = JS_GetPropertyStr(ctx, argv[0], "artMethod");
            if (JS_IsUndefined(artVal) || JS_IsNull(artVal)) {
                artVal = JS_GetPropertyStr(ctx, argv[0], "address");
            }
            if (JS_IsUndefined(artVal) || JS_IsNull(artVal)) {
                artVal = JS_GetPropertyStr(ctx, argv[0], "ptr");
            }
            if (!JS_IsUndefined(artVal) && !JS_IsNull(artVal)) {
                ptr = ParsePtr(ctx, artVal);
            }
            JS_FreeValue(ctx, artVal);
        }
    }

    // 2. If String: either hex address or class name
    if (JS_IsString(argv[0])) {
        const char* s = JS_ToCString(ctx, argv[0]);
        if (s) {
            std::string strVal = s;
            JS_FreeCString(ctx, s);
            if (strVal.size() > 2 && strVal[0] == '0' && (strVal[1] == 'x' || strVal[1] == 'X')) {
                ptr = static_cast<int64_t>(strtoull(strVal.c_str(), nullptr, 16));
            } else {
                if (env) {
                    jclass cls = FindClassWithFallback(env, strVal);
                    if (cls) {
                        std::string out = DumpMethodsOfClass(env, cls, strVal, maxInsn, true);
                        env->DeleteLocalRef(cls);
                        return JS_NewString(ctx, out.c_str());
                    }
                }
                return JS_NewString(ctx, ("[!] Class not found: " + strVal).c_str());
            }
        }
    }

    if (!ptr) {
        ptr = ParsePtr(ctx, argv[0]);
    }
    if (!ptr || ptr < 0x1000) {
        return JS_NewString(ctx, "[!] Invalid pointer (address is null or below 0x1000)");
    }

    // Memory inspection gate: validate memory readability before any JNI / dereference
    std::string reason;
    MemoryTargetKind kind = InspectAddress(static_cast<uintptr_t>(ptr), &reason);
    if (kind == MemoryTargetKind::kInvalid) {
        return JS_NewString(ctx, ("[!] Invalid pointer: " + reason).c_str());
    }
    if (kind == MemoryTargetKind::kNativeCode) {
        return JS_NewString(ctx, "[!] Address points to native executable code, not an ArtMethod. Use dumpCode() or dumpNative().");
    }
    if (kind == MemoryTargetKind::kDexFile) {
        return JS_NewString(ctx, "[!] Address points to a DEX file buffer, not an ArtMethod.");
    }

    // Check if ptr is a known global jclass reference
    if (env && IsKnownGlobalClassRef(static_cast<uintptr_t>(ptr))) {
        jclass cls = reinterpret_cast<jclass>(ptr);
        std::string out = DumpMethodsOfClass(env, cls, "", maxInsn, true);
        return JS_NewString(ctx, out.c_str());
    }

    // Validate and dump ArtMethod
    if (kind == MemoryTargetKind::kArtMethod) {
        PI::Method m = PI::resolve(reinterpret_cast<ArtMethod*>(ptr));
        if (m.isValid()) {
            std::string smali = m.dumpSmali(maxInsn);
            return JS_NewString(ctx, smali.c_str());
        }
    }

    char hexBuf[32];
    snprintf(hexBuf, sizeof(hexBuf), "0x%llx", (unsigned long long)ptr);
    return JS_NewString(ctx, ("[!] Pointer " + std::string(hexBuf) + " is not an ArtMethod: " + reason).c_str());
}

static JSValue JsDumpCode(JSContext* ctx, JSValueConst /*this_val*/, int argc, JSValueConst* argv) {
    if (argc < 1) return JS_NewString(ctx, "Usage: dumpCode(artMethodPtrOrNativeAddrOrClass, [maxInstructions])");

    int maxInsn = -1;
    if (argc >= 2) JS_ToInt32(ctx, &maxInsn, argv[1]);

    JNIEnv* env = GetEnv();
    int64_t ptr = 0;

    // 1. If JS Object: check $className or pointer fields
    if (JS_IsObject(argv[0])) {
        JSValue cn = JS_GetPropertyStr(ctx, argv[0], "$className");
        if (JS_IsString(cn)) {
            const char* cstr = JS_ToCString(ctx, cn);
            std::string className = cstr ? cstr : "";
            JS_FreeCString(ctx, cstr);
            JS_FreeValue(ctx, cn);
            if (!className.empty()) {
                if (env) {
                    jclass cls = FindClassWithFallback(env, className);
                    if (cls) {
                        std::string out = DumpMethodsOfClass(env, cls, className, maxInsn, false);
                        env->DeleteLocalRef(cls);
                        return JS_NewString(ctx, out.c_str());
                    }
                }
                return JS_NewString(ctx, ("[!] Class not found: " + className).c_str());
            }
        } else {
            JS_FreeValue(ctx, cn);
            JSValue artVal = JS_GetPropertyStr(ctx, argv[0], "artMethod");
            if (JS_IsUndefined(artVal) || JS_IsNull(artVal)) {
                artVal = JS_GetPropertyStr(ctx, argv[0], "address");
            }
            if (JS_IsUndefined(artVal) || JS_IsNull(artVal)) {
                artVal = JS_GetPropertyStr(ctx, argv[0], "ptr");
            }
            if (!JS_IsUndefined(artVal) && !JS_IsNull(artVal)) {
                ptr = ParsePtr(ctx, artVal);
            }
            JS_FreeValue(ctx, artVal);
        }
    }

    // 2. If String: either hex address or class name
    if (JS_IsString(argv[0])) {
        const char* s = JS_ToCString(ctx, argv[0]);
        if (s) {
            std::string strVal = s;
            JS_FreeCString(ctx, s);
            if (strVal.size() > 2 && strVal[0] == '0' && (strVal[1] == 'x' || strVal[1] == 'X')) {
                ptr = static_cast<int64_t>(strtoull(strVal.c_str(), nullptr, 16));
            } else {
                if (env) {
                    jclass cls = FindClassWithFallback(env, strVal);
                    if (cls) {
                        std::string out = DumpMethodsOfClass(env, cls, strVal, maxInsn, false);
                        env->DeleteLocalRef(cls);
                        return JS_NewString(ctx, out.c_str());
                    }
                }
                return JS_NewString(ctx, ("[!] Class not found: " + strVal).c_str());
            }
        }
    }

    if (!ptr) {
        ptr = ParsePtr(ctx, argv[0]);
    }
    if (!ptr || ptr < 0x1000) {
        return JS_NewString(ctx, "[!] Invalid pointer (address is null or below 0x1000)");
    }

    std::string reason;
    MemoryTargetKind kind = InspectAddress(static_cast<uintptr_t>(ptr), &reason);
    if (kind == MemoryTargetKind::kInvalid) {
        return JS_NewString(ctx, ("[!] Invalid pointer: " + reason).c_str());
    }

    // Dimension: DEX memory buffer
    if (kind == MemoryTargetKind::kDexFile) {
        uint8_t magic[8] = {0};
        struct iovec liov = { magic, sizeof(magic) };
        struct iovec riov = { reinterpret_cast<void*>(ptr), sizeof(magic) };
        syscall(SYS_process_vm_readv, getpid(), &liov, 1, &riov, 1, 0);
        uint32_t file_size = 0;
        liov = { &file_size, sizeof(file_size) };
        riov = { reinterpret_cast<void*>(ptr + 0x20), sizeof(file_size) };
        syscall(SYS_process_vm_readv, getpid(), &liov, 1, &riov, 1, 0);

        std::ostringstream ss;
        ss << "=== DEX Memory Buffer at " << reinterpret_cast<void*>(ptr) << " ===\n";
        ss << "  Format: " << std::string(reinterpret_cast<const char*>(magic), 4) << "\n";
        ss << "  File Size: " << file_size << " bytes\n";
        return JS_NewString(ctx, ss.str().c_str());
    }

    // Check if ptr is a known global jclass reference
    if (env && IsKnownGlobalClassRef(static_cast<uintptr_t>(ptr))) {
        jclass cls = reinterpret_cast<jclass>(ptr);
        std::string out = DumpMethodsOfClass(env, cls, "", maxInsn, false);
        return JS_NewString(ctx, out.c_str());
    }

    // Dimension: Valid ArtMethod
    if (kind == MemoryTargetKind::kArtMethod) {
        ArtMethod* art = reinterpret_cast<ArtMethod*>(ptr);
        PI::Method m = PI::resolve(art);
        if (m.isValid()) {
            std::string code = PI::dumpCode(art, maxInsn);
            return JS_NewString(ctx, code.c_str());
        }
    }

    // Default fallback: Always Native ARM64 Disassembly!
    std::string code = PI::dumpNative(reinterpret_cast<const void*>(ptr), maxInsn);
    return JS_NewString(ctx, code.c_str());
}

// ---------------------------------------------------------------------------
// JADX In-Memory Single Class Decompile
// ---------------------------------------------------------------------------
static bool DumpDexFromArtMethod(ArtMethod* art, std::string& outDexPath) {
    if (!art) return false;
    uint32_t klass_ref = art->GetDeclaringClass();
    if (!klass_ref) return false;
    void* klass = reinterpret_cast<void*>(static_cast<uintptr_t>(klass_ref));

    uint32_t dex_cache_ref = *reinterpret_cast<uint32_t*>(static_cast<uint8_t*>(klass) + 0x10);
    if (!dex_cache_ref) return false;
    void* dex_cache = reinterpret_cast<void*>(static_cast<uintptr_t>(dex_cache_ref));

    const void* dex_file = *reinterpret_cast<const void* const*>(static_cast<const uint8_t*>(dex_cache) + 0x10);
    if (!dex_file) return false;

    const uint8_t* dex_begin = *reinterpret_cast<const uint8_t* const*>(static_cast<const uint8_t*>(dex_file) + 0x08);
    size_t dex_size = *reinterpret_cast<const size_t*>(static_cast<const uint8_t*>(dex_file) + 0x10);
    const uint8_t* dex_data_begin = *reinterpret_cast<const uint8_t* const*>(static_cast<const uint8_t*>(dex_file) + 0x18);
    if (!dex_data_begin) dex_data_begin = dex_begin;
    if (!dex_data_begin) return false;

    if (dex_size == 0 || dex_size > 0x10000000) {
        if (std::memcmp(dex_data_begin, "dex\n", 4) == 0 || std::memcmp(dex_data_begin, "cdex", 4) == 0) {
            dex_size = *reinterpret_cast<const uint32_t*>(dex_data_begin + 0x20);
        }
    }
    if (dex_size == 0 || dex_size > 0x10000000) return false;

    uint32_t checksum = 0;
    if (dex_size >= 16) {
        checksum = *reinterpret_cast<const uint32_t*>(dex_data_begin + 8);
    }

    mkdir("/data/local/tmp/jtmp", 0777);
    chmod("/data/local/tmp/jtmp", 0777);

    char buf[128];
    snprintf(buf, sizeof(buf), "/data/local/tmp/jtmp/dex_%zx_%08x.dex", dex_size, checksum);
    outDexPath = buf;

    struct stat st;
    if (stat(outDexPath.c_str(), &st) == 0 && (size_t)st.st_size == dex_size) {
        return true;
    }

    int fd = open(outDexPath.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0666);
    if (fd < 0) return false;
    size_t written = 0;
    while (written < dex_size) {
        ssize_t w = write(fd, dex_data_begin + written, dex_size - written);
        if (w <= 0) { close(fd); return false; }
        written += w;
    }
    close(fd);
    chmod(outDexPath.c_str(), 0666);
    return true;
}

static std::string DecompileSingleClass(const std::string& className, const std::string& dexPath, const std::string& methodName) {
    mkdir("/data/local/tmp/dalvik-cache", 0777);
    chmod("/data/local/tmp/dalvik-cache", 0777);
    mkdir("/data/local/tmp/jtmp", 0777);
    chmod("/data/local/tmp/jtmp", 0777);
    mkdir("/data/local/tmp/jout", 0777);
    chmod("/data/local/tmp/jout", 0777);
    chmod("/data/local/tmp/jadxcli.jar", 0666);
    chmod(dexPath.c_str(), 0666);

    std::string relPath = className;
    for (char& c : relPath) { if (c == '.') c = '/'; }
    std::string targetJava1 = "/data/local/tmp/jout/" + relPath + ".java";
    std::string targetJava2 = "/data/local/tmp/jout/sources/" + relPath + ".java";
    std::string targetJava3 = "/data/local/tmp/jout/decompiled.java";
    unlink(targetJava1.c_str());
    unlink(targetJava2.c_str());
    unlink(targetJava3.c_str());

    std::string cmd = "export ANDROID_DATA=/data/local/tmp; dalvikvm -Xmx256m -Djava.io.tmpdir=/data/local/tmp/jtmp -cp /data/local/tmp/jadxcli.jar jadx.cli.JadxCLI --no-res -ds /data/local/tmp/jout --single-class " + className + " --single-class-output " + targetJava3 + " " + dexPath + " >/dev/null 2>&1";
    int ret = system(cmd.c_str());
    (void)ret;

    FILE* fp = fopen(targetJava3.c_str(), "rb");
    if (!fp) fp = fopen(targetJava1.c_str(), "rb");
    if (!fp) fp = fopen(targetJava2.c_str(), "rb");
    if (!fp) return "";

    fseek(fp, 0, SEEK_END);
    long sz = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    std::string javaCode(sz, '\0');
    fread(&javaCode[0], 1, sz, fp);
    fclose(fp);

    if (methodName.empty()) {
        return javaCode;
    }

    std::string needle = methodName + "(";
    size_t pos = javaCode.find(needle);
    if (pos == std::string::npos) {
        return "// [Note: Method '" + methodName + "' not found directly (may be inlined/synthetic/obfuscated). Full class source:]\n\n" + javaCode;
    }

    size_t lineStart = javaCode.rfind('\n', pos);
    lineStart = (lineStart == std::string::npos) ? 0 : lineStart + 1;

    size_t scanPos = lineStart;
    while (scanPos > 0) {
        size_t prevLineEnd = scanPos - 1;
        size_t prevLineStart = javaCode.rfind('\n', prevLineEnd > 0 ? prevLineEnd - 1 : 0);
        prevLineStart = (prevLineStart == std::string::npos) ? 0 : prevLineStart + 1;
        std::string prevLine = javaCode.substr(prevLineStart, prevLineEnd - prevLineStart);
        size_t nonWs = prevLine.find_first_not_of(" \t\r\n");
        if (nonWs != std::string::npos) {
            std::string trimmed = prevLine.substr(nonWs);
            if (trimmed.rfind("@", 0) == 0 || trimmed.rfind("/*", 0) == 0 || trimmed.rfind("//", 0) == 0 || trimmed.rfind("*", 0) == 0) {
                scanPos = prevLineStart;
                lineStart = prevLineStart;
                continue;
            }
        }
        break;
    }

    size_t semiColon = javaCode.find(';', pos);
    size_t braceOpen = javaCode.find('{', pos);
    if (semiColon != std::string::npos && (braceOpen == std::string::npos || semiColon < braceOpen)) {
        std::string methodCode = javaCode.substr(lineStart, semiColon - lineStart + 1);
        return "// Decompiled " + className + "." + methodName + " via JADX:\n" + methodCode;
    }

    if (braceOpen == std::string::npos) return javaCode;

    int braceCount = 1;
    size_t i = braceOpen + 1;
    for (; i < javaCode.size(); i++) {
        if (javaCode[i] == '{') braceCount++;
        else if (javaCode[i] == '}') {
            braceCount--;
            if (braceCount == 0) break;
        }
    }

    if (braceCount == 0 && i < javaCode.size()) {
        std::string methodCode = javaCode.substr(lineStart, i - lineStart + 1);
        return "// Decompiled " + className + "." + methodName + " via JADX:\n" + methodCode;
    }

    return javaCode;
}

static JSValue JsDecompile(JSContext* ctx, JSValueConst /*this_val*/, int argc, JSValueConst* argv) {
    if (argc < 1) return JS_NewString(ctx, "Usage: decompile(classOrMethodNameOrArtMethod, [methodName])");
    JNIEnv* env = GetEnv();
    if (!env) return JS_NULL;

    std::string className;
    std::string methodName;
    ArtMethod* targetArt = nullptr;

    int64_t ptr = ParsePtr(ctx, argv[0]);
    if (ptr > 0x1000) {
        MemoryTargetKind kind = InspectAddress(static_cast<uintptr_t>(ptr));
        if (kind != MemoryTargetKind::kArtMethod) {
            // Pointer is not a validated ArtMethod; dispatch to disassembly rather than crashing JADX!
            return JsDumpCode(ctx, JS_UNDEFINED, argc, argv);
        }
        PI::Method m = PI::resolve(reinterpret_cast<ArtMethod*>(ptr));
        if (m.isValid()) {
            targetArt = m.getArtMethod();
            className = m.getDeclaringClassName();
            methodName = m.getName();
        } else {
            return JsDumpCode(ctx, JS_UNDEFINED, argc, argv);
        }
    } else if (JS_IsString(argv[0])) {
        const char* s = JS_ToCString(ctx, argv[0]);
        if (s) {
            className = s;
            JS_FreeCString(ctx, s);
        }
    }

    if (argc >= 2 && JS_IsString(argv[1])) {
        const char* s = JS_ToCString(ctx, argv[1]);
        if (s) {
            methodName = s;
            JS_FreeCString(ctx, s);
        }
    }

    if (!targetArt && !className.empty()) {
        jclass cls = FindClassWithFallback(env, className);
        if (cls) {
            if (!methodName.empty()) {
                JSValue mVal = JS_Call(ctx, JS_GetPropertyStr(ctx, JS_GetGlobalObject(ctx), "findMethod"), JS_UNDEFINED, 2, argv);
                int64_t mPtr = ParsePtr(ctx, mVal);
                JS_FreeValue(ctx, mVal);
                if (mPtr > 0x1000) targetArt = reinterpret_cast<ArtMethod*>(mPtr);
            }
            if (!targetArt) {
                jclass classCls = AgentCachedClass("java/lang/Class");
                jmethodID getDeclaredMethods = classCls ? env->GetMethodID(classCls, "getDeclaredMethods", "()[Ljava/lang/reflect/Method;") : nullptr;
                if (env->ExceptionCheck()) env->ExceptionClear();
                if (classCls && getDeclaredMethods) {
                    auto mArr = (jobjectArray)env->CallObjectMethod(cls, getDeclaredMethods);
                    if (env->ExceptionCheck()) env->ExceptionClear();
                    if (mArr && env->GetArrayLength(mArr) > 0) {
                        jobject mObj = env->GetObjectArrayElement(mArr, 0);
                        if (mObj) {
                            PI::Method pm = PI::resolve(env, mObj);
                            if (pm.isValid()) targetArt = pm.getArtMethod();
                            env->DeleteLocalRef(mObj);
                        }
                        env->DeleteLocalRef(mArr);
                    }
                }
            }
            env->DeleteLocalRef(cls);
        }
    }

    if (!targetArt) {
        return JS_NewString(ctx, ("[!] Unable to resolve class or method: " + className).c_str());
    }

    bool jadxOk = (access("/data/local/tmp/jadxcli.jar", R_OK) == 0);
    std::string dexPath;
    if (jadxOk && DumpDexFromArtMethod(targetArt, dexPath)) {
        std::string res = DecompileSingleClass(className, dexPath, methodName);
        if (!res.empty()) {
            return JS_NewString(ctx, res.c_str());
        }
    }

    if (!methodName.empty()) {
        PI::Method m = PI::resolve(targetArt);
        std::string smali = m.dumpSmali(-1);
        return JS_NewString(ctx, ("[*] JADX decompile unavailable; fallback to Smali disassembly:\n\n" + smali).c_str());
    }

    std::ostringstream ss;
    ss << "// [*] JADX decompile unavailable; fallback to Smali/Class disassembly:\n";
    ss << "// Class: " << className << "\n\n";

    jclass cls = FindClassWithFallback(env, className);
    if (cls) {
        ss << DumpMethodsOfClass(env, cls, className, -1, true);
        env->DeleteLocalRef(cls);
    }
    return JS_NewString(ctx, ss.str().c_str());
}

// ---------------------------------------------------------------------------
// Dump All Loaded DEX Files
// ---------------------------------------------------------------------------
static const char* kDumpDexDirName = "artpi_dex";

static uint32_t DexAdler32(const uint8_t* data, size_t len) {
    const uint32_t MOD = 65521;
    uint32_t a = 1, b = 0;
    for (size_t i = 0; i < len; ++i) {
        a += data[i];
        if (a >= MOD) a -= MOD;
        b += a;
        if (b >= MOD) b -= MOD;
    }
    return (b << 16) | a;
}

static bool SafeReadMem(void* dst, const void* src, size_t len) {
    if (!src || !dst || len == 0) return false;
    struct iovec local_iov = { dst, len };
    struct iovec remote_iov = { const_cast<void*>(src), len };
    ssize_t n = syscall(SYS_process_vm_readv, getpid(), &local_iov, 1, &remote_iov, 1, 0);
    return n == static_cast<ssize_t>(len);
}

static bool SafeDexMagic(const void* p, uint8_t outMagic[8]) {
    if (!SafeReadMem(outMagic, p, 8)) return false;
    return std::memcmp(outMagic, "dex\n", 4) == 0 || std::memcmp(outMagic, "cdex", 4) == 0;
}

static const void* DexFilePtrFromKlass(void* klass) {
    if (!klass) return nullptr;
    auto* k = static_cast<const uint8_t*>(klass);
    uint32_t dex_cache_ref = *reinterpret_cast<const uint32_t*>(k + 0x10);
    if (!dex_cache_ref) return nullptr;
    auto* dex_cache = reinterpret_cast<const uint8_t*>(static_cast<uintptr_t>(dex_cache_ref));
    return *reinterpret_cast<const void* const*>(dex_cache + 0x10);
}

static const uint8_t* DexMemoryFromArtDexFile(const void* dex_file, size_t& outSize) {
    outSize = 0;
    uint8_t fields[0x20];
    if (!SafeReadMem(fields, dex_file, sizeof(fields))) return nullptr;
    const uint8_t* dex_begin = *reinterpret_cast<const uint8_t* const*>(fields + 0x08);
    size_t         dex_size  = *reinterpret_cast<const size_t*>(fields + 0x10);
    const uint8_t* dex_data_begin = *reinterpret_cast<const uint8_t* const*>(fields + 0x18);
    if (!dex_data_begin) dex_data_begin = dex_begin;

    uint8_t magic[8];
    const uint8_t* base = nullptr;
    if (SafeDexMagic(dex_begin, magic)) base = dex_begin;
    else if (SafeDexMagic(dex_data_begin, magic)) base = dex_data_begin;
    if (!base) return nullptr;

    uint32_t header_file_size = 0;
    if (SafeReadMem(&header_file_size, base + 0x20, 4)
        && header_file_size >= 0x70 && header_file_size < 0x10000000) {
        dex_size = header_file_size;
    }
    if (dex_size < 0x70 || dex_size > 0x10000000) return nullptr;

    outSize = dex_size;
    return base;
}

static bool BuildRepairedDex(const uint8_t* base, size_t size, std::vector<uint8_t>& out,
                             bool& repaired, std::string& kind) {
    if (!base || size < 0x70) return false;
    out.assign(base, base + size);
    kind = (std::memcmp(out.data(), "cdex", 4) == 0) ? "CompactDex" : "StandardDex";

    uint32_t stored = *reinterpret_cast<const uint32_t*>(out.data() + 8);
    uint32_t calc = DexAdler32(out.data() + 12, out.size() - 12);
    repaired = (stored != calc);
    if (repaired) {
        *reinterpret_cast<uint32_t*>(out.data() + 8) = calc;
    }
    return true;
}

static void EnsureDirRecursive(const std::string& dir) {
    if (dir.empty()) return;
    std::string cur;
    cur.reserve(dir.size());
    for (size_t i = 0; i < dir.size(); ++i) {
        cur.push_back(dir[i]);
        if (dir[i] == '/' && cur.size() > 1) mkdir(cur.c_str(), 0777);
    }
    mkdir(dir.c_str(), 0777);
    chmod(dir.c_str(), 0777);
}

static bool WriteFileAll(const std::string& path, const std::vector<uint8_t>& data) {
    int fd = open(path.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0666);
    if (fd < 0) return false;
    size_t written = 0;
    while (written < data.size()) {
        ssize_t w = write(fd, data.data() + written, data.size() - written);
        if (w <= 0) { close(fd); return false; }
        written += static_cast<size_t>(w);
    }
    close(fd);
    chmod(path.c_str(), 0666);
    return true;
}

static std::string BaseNameOf(const std::string& p) {
    size_t s = p.find_last_of('/');
    return (s == std::string::npos) ? p : p.substr(s + 1);
}

static std::string SanitizeName(const std::string& in) {
    std::string out;
    out.reserve(in.size());
    for (char c : in) {
        if (isalnum(static_cast<unsigned char>(c)) || c == '.' || c == '_' || c == '-') out.push_back(c);
        else out.push_back('_');
    }
    return out.empty() ? std::string("classes") : out;
}

static std::string StripDexExt(std::string n) {
    for (const char* ext : {".dex", ".apk", ".jar", ".zip"}) {
        size_t l = std::strlen(ext);
        if (n.size() > l && n.compare(n.size() - l, l, ext) == 0) { n.resize(n.size() - l); break; }
    }
    return n;
}

static std::string ResolveAppFilesDir(JNIEnv* env) {
    jclass atCls = env->FindClass("android/app/ActivityThread");
    if (env->ExceptionCheck()) { env->ExceptionClear(); atCls = nullptr; }
    if (!atCls) return "";

    std::string result;
    jmethodID cam = env->GetStaticMethodID(atCls, "currentApplication", "()Landroid/app/Application;");
    if (env->ExceptionCheck()) env->ExceptionClear();
    jobject app = cam ? env->CallStaticObjectMethod(atCls, cam) : nullptr;
    if (env->ExceptionCheck()) { env->ExceptionClear(); app = nullptr; }
    if (app) {
        jclass ctxCls = env->FindClass("android/content/Context");
        if (env->ExceptionCheck()) { env->ExceptionClear(); ctxCls = nullptr; }
        jmethodID gfd = ctxCls ? env->GetMethodID(ctxCls, "getFilesDir", "()Ljava/io/File;") : nullptr;
        if (env->ExceptionCheck()) env->ExceptionClear();
        jobject file = gfd ? env->CallObjectMethod(app, gfd) : nullptr;
        if (env->ExceptionCheck()) { env->ExceptionClear(); file = nullptr; }
        if (file) {
            jclass fileCls = env->FindClass("java/io/File");
            if (env->ExceptionCheck()) { env->ExceptionClear(); fileCls = nullptr; }
            jmethodID gap = fileCls ? env->GetMethodID(fileCls, "getAbsolutePath", "()Ljava/lang/String;") : nullptr;
            if (env->ExceptionCheck()) env->ExceptionClear();
            auto js = gap ? (jstring)env->CallObjectMethod(file, gap) : nullptr;
            if (env->ExceptionCheck()) { env->ExceptionClear(); js = nullptr; }
            if (js) {
                const char* c = env->GetStringUTFChars(js, nullptr);
                if (c) { result = c; env->ReleaseStringUTFChars(js, c); }
                env->DeleteLocalRef(js);
            }
            if (fileCls) env->DeleteLocalRef(fileCls);
            env->DeleteLocalRef(file);
        }
        if (ctxCls) env->DeleteLocalRef(ctxCls);
        env->DeleteLocalRef(app);
    }
    env->DeleteLocalRef(atCls);
    return result;
}

static std::string PackageFromCmdline() {
    FILE* fp = fopen("/proc/self/cmdline", "rb");
    if (!fp) return "";
    char buf[256] = {0};
    size_t n = fread(buf, 1, sizeof(buf) - 1, fp);
    fclose(fp);
    if (n == 0) return "";
    std::string name(buf);
    size_t colon = name.find(':');
    if (colon != std::string::npos) name.resize(colon);
    return name;
}

static ArtMethod* FirstArtMethodOfClass(JNIEnv* env, jclass cls) {
    jclass classCls = AgentCachedClass("java/lang/Class");
    if (!classCls) return nullptr;

    struct Getter { const char* name; const char* sig; };
    const Getter getters[] = {
        { "getDeclaredMethods",      "()[Ljava/lang/reflect/Method;" },
        { "getDeclaredConstructors", "()[Ljava/lang/reflect/Constructor;" },
    };

    ArtMethod* found = nullptr;
    for (const auto& g : getters) {
        if (found) break;
        jmethodID mid = env->GetMethodID(classCls, g.name, g.sig);
        if (env->ExceptionCheck()) { env->ExceptionClear(); continue; }
        if (!mid) continue;
        auto arr = (jobjectArray)env->CallObjectMethod(cls, mid);
        if (env->ExceptionCheck()) { env->ExceptionClear(); continue; }
        if (!arr) continue;
        jsize n = env->GetArrayLength(arr);
        for (jsize i = 0; i < n && !found; ++i) {
            jobject mObj = env->GetObjectArrayElement(arr, i);
            if (mObj) {
                PI::Method pm = PI::resolve(env, mObj);
                env->DeleteLocalRef(mObj);
                if (pm.isValid()) found = pm.getArtMethod();
            }
        }
        env->DeleteLocalRef(arr);
    }

    return found;
}

static ArtMethod* FirstArtMethodOfDexFile(JNIEnv* env, jobject dexFile) {
    jclass dfCls = env->FindClass("dalvik/system/DexFile");
    if (env->ExceptionCheck()) { env->ExceptionClear(); dfCls = nullptr; }
    if (!dfCls) return nullptr;
    jmethodID entriesMid = env->GetMethodID(dfCls, "entries", "()Ljava/util/Enumeration;");
    if (env->ExceptionCheck()) env->ExceptionClear();
    env->DeleteLocalRef(dfCls);
    if (!entriesMid) return nullptr;

    jclass enumCls = env->FindClass("java/util/Enumeration");
    if (env->ExceptionCheck()) { env->ExceptionClear(); enumCls = nullptr; }
    jmethodID hasMore = enumCls ? env->GetMethodID(enumCls, "hasMoreElements", "()Z") : nullptr;
    jmethodID nextEl  = enumCls ? env->GetMethodID(enumCls, "nextElement", "()Ljava/lang/Object;") : nullptr;
    if (env->ExceptionCheck()) env->ExceptionClear();
    if (enumCls) env->DeleteLocalRef(enumCls);
    if (!hasMore || !nextEl) return nullptr;

    jobject en = env->CallObjectMethod(dexFile, entriesMid);
    if (env->ExceptionCheck()) { env->ExceptionClear(); en = nullptr; }

    ArtMethod* found = nullptr;
    int tried = 0;
    while (en && tried < 128 && !found) {
        jboolean more = env->CallBooleanMethod(en, hasMore);
        if (env->ExceptionCheck()) { env->ExceptionClear(); break; }
        if (!more) break;
        auto s = (jstring)env->CallObjectMethod(en, nextEl);
        if (env->ExceptionCheck()) { env->ExceptionClear(); s = nullptr; }
        if (s) {
            const char* c = env->GetStringUTFChars(s, nullptr);
            if (c) {
                jclass cls = FindClassWithFallback(env, std::string(c));
                env->ReleaseStringUTFChars(s, c);
                if (cls) {
                    found = FirstArtMethodOfClass(env, cls);
                    env->DeleteLocalRef(cls);
                }
            }
            env->DeleteLocalRef(s);
        }
        ++tried;
    }
    if (en) env->DeleteLocalRef(en);
    return found;
}

static void CollectDexPtrsFromField(JNIEnv* env, jobject dexFile, jfieldID fid,
                                    std::vector<const void*>& out) {
    if (!fid) return;
    jobject cookie = env->GetObjectField(dexFile, fid);
    if (env->ExceptionCheck()) { env->ExceptionClear(); cookie = nullptr; }
    if (!cookie) return;
    jclass ccls = env->GetObjectClass(cookie);
    std::string cn = ccls ? JavaClassName(env, ccls) : "";
    if (ccls) env->DeleteLocalRef(ccls);
    if (cn == "[J") {
        jsize n = env->GetArrayLength(reinterpret_cast<jarray>(cookie));
        jlong* data = env->GetLongArrayElements(reinterpret_cast<jlongArray>(cookie), nullptr);
        if (data) {
            for (jsize i = 0; i < n; ++i) {
                out.push_back(reinterpret_cast<const void*>(static_cast<uintptr_t>(data[i])));
            }
            env->ReleaseLongArrayElements(reinterpret_cast<jlongArray>(cookie), data, JNI_ABORT);
        }
    }
    env->DeleteLocalRef(cookie);
}

static JSValue JsDumpAllDex(JSContext* ctx, JSValueConst /*this_val*/, int argc, JSValueConst* argv) {
    JNIEnv* env = GetEnv();
    if (!env) return JS_NewString(ctx, "[!] dumpAllDex: no JNIEnv available");

    std::string dirArg;
    if (argc >= 1 && JS_IsString(argv[0])) {
        const char* s = JS_ToCString(ctx, argv[0]);
        if (s) { dirArg = s; JS_FreeCString(ctx, s); }
    }

    std::string outDir = dirArg;
    if (outDir.empty()) {
        std::string filesDir = ResolveAppFilesDir(env);
        if (!filesDir.empty()) {
            outDir = filesDir + "/" + kDumpDexDirName;
        } else {
            std::string pkg = PackageFromCmdline();
            outDir = pkg.empty() ? std::string("/data/local/tmp/") + kDumpDexDirName
                                 : "/data/data/" + pkg + "/files/" + kDumpDexDirName;
        }
    }
    EnsureDirRecursive(outDir);

    jobject cl = GetAppClassLoader(env);
    if (!cl) return JS_NewString(ctx, "[!] dumpAllDex: unable to locate application ClassLoader");

    jclass baseCls = env->FindClass("dalvik/system/BaseDexClassLoader");
    if (env->ExceptionCheck()) { env->ExceptionClear(); baseCls = nullptr; }
    jfieldID pathListField = baseCls ? env->GetFieldID(baseCls, "pathList", "Ldalvik/system/DexPathList;") : nullptr;
    if (env->ExceptionCheck()) env->ExceptionClear();
    jobject pathList = pathListField ? env->GetObjectField(cl, pathListField) : nullptr;
    if (env->ExceptionCheck()) { env->ExceptionClear(); pathList = nullptr; }

    jclass dplCls = env->FindClass("dalvik/system/DexPathList");
    if (env->ExceptionCheck()) { env->ExceptionClear(); dplCls = nullptr; }
    jfieldID dexElementsField = dplCls ? env->GetFieldID(dplCls, "dexElements", "[Ldalvik/system/DexPathList$Element;") : nullptr;
    if (env->ExceptionCheck()) env->ExceptionClear();

    if (!pathList || !dexElementsField) {
        if (baseCls) env->DeleteLocalRef(baseCls);
        if (dplCls) env->DeleteLocalRef(dplCls);
        if (pathList) env->DeleteLocalRef(pathList);
        return JS_NewString(ctx, "[!] dumpAllDex: DexPathList.dexElements unavailable");
    }

    auto dexElements = (jobjectArray)env->GetObjectField(pathList, dexElementsField);
    if (env->ExceptionCheck()) { env->ExceptionClear(); dexElements = nullptr; }

    jclass elemCls = env->FindClass("dalvik/system/DexPathList$Element");
    if (env->ExceptionCheck()) { env->ExceptionClear(); elemCls = nullptr; }
    jfieldID dexFileField = elemCls ? env->GetFieldID(elemCls, "dexFile", "Ldalvik/system/DexFile;") : nullptr;
    if (env->ExceptionCheck()) env->ExceptionClear();
    jfieldID pathField = elemCls ? env->GetFieldID(elemCls, "path", "Ljava/lang/String;") : nullptr;
    if (env->ExceptionCheck()) env->ExceptionClear();

    jclass dexFileCls = env->FindClass("dalvik/system/DexFile");
    if (env->ExceptionCheck()) { env->ExceptionClear(); dexFileCls = nullptr; }
    jfieldID internalCookieField = dexFileCls ? env->GetFieldID(dexFileCls, "mInternalCookie", "Ljava/lang/Object;") : nullptr;
    if (env->ExceptionCheck()) env->ExceptionClear();
    jfieldID cookieField = dexFileCls ? env->GetFieldID(dexFileCls, "mCookie", "Ljava/lang/Object;") : nullptr;
    if (env->ExceptionCheck()) env->ExceptionClear();
    if (dexFileCls) env->DeleteLocalRef(dexFileCls);

    std::unordered_set<uint64_t> seen;
    std::unordered_set<const void*> seenPtrs;
    std::ostringstream details;
    size_t index = 0, dumped = 0, repairedCount = 0, skipped = 0;

    if (dexElements && dexFileField) {
        jsize len = env->GetArrayLength(dexElements);
        for (jsize i = 0; i < len; ++i) {
            jobject elem = env->GetObjectArrayElement(dexElements, i);
            if (!elem) continue;

            std::string origName = "classes";
            if (pathField) {
                auto ps = (jstring)env->GetObjectField(elem, pathField);
                if (env->ExceptionCheck()) { env->ExceptionClear(); ps = nullptr; }
                if (ps) {
                    const char* c = env->GetStringUTFChars(ps, nullptr);
                    if (c) { origName = BaseNameOf(c); env->ReleaseStringUTFChars(ps, c); }
                    env->DeleteLocalRef(ps);
                }
            }

            jobject dexFile = env->GetObjectField(elem, dexFileField);
            if (env->ExceptionCheck()) { env->ExceptionClear(); dexFile = nullptr; }

            if (dexFile) {
                std::vector<const void*> dexPtrs;
                CollectDexPtrsFromField(env, dexFile, internalCookieField, dexPtrs);
                CollectDexPtrsFromField(env, dexFile, cookieField, dexPtrs);

                if (dexPtrs.empty()) {
                    ArtMethod* art = FirstArtMethodOfDexFile(env, dexFile);
                    if (art) {
                        uint32_t kr = art->GetDeclaringClass();
                        if (kr) {
                            const void* dfp = DexFilePtrFromKlass(reinterpret_cast<void*>(static_cast<uintptr_t>(kr)));
                            if (dfp) dexPtrs.push_back(dfp);
                        }
                    }
                }

                for (const void* dfp : dexPtrs) {
                    if (!dfp || !seenPtrs.insert(dfp).second) continue;
                    size_t size = 0;
                    const uint8_t* base = DexMemoryFromArtDexFile(dfp, size);
                    std::vector<uint8_t> buf;
                    bool repaired = false;
                    std::string kind;
                    if (!base || !BuildRepairedDex(base, size, buf, repaired, kind)) {
                        ++skipped;
                        continue;
                    }
                    uint32_t crc = *reinterpret_cast<const uint32_t*>(buf.data() + 8);
                    uint64_t key = (static_cast<uint64_t>(buf.size()) << 32) ^ crc;
                    if (!seen.insert(key).second) continue;
                    ++index;
                    char crcStr[16];
                    snprintf(crcStr, sizeof(crcStr), "%08x", crc);
                    char prefix[16];
                    snprintf(prefix, sizeof(prefix), "%04zu_", index);
                    std::string fname = std::string(prefix) + StripDexExt(SanitizeName(origName))
                                        + "_" + crcStr + ".dex";
                    std::string outPath = outDir + "/" + fname;
                    if (WriteFileAll(outPath, buf)) {
                        ++dumped;
                        if (repaired) ++repairedCount;
                        details << (repaired ? "  [fixed] " : "  [ok]    ") << fname
                                << "  " << buf.size() << " bytes  (" << kind << ")\n";
                    } else {
                        ++skipped;
                        details << "  [write-fail] " << outPath << "\n";
                    }
                }
                env->DeleteLocalRef(dexFile);
            } else {
                ++skipped;
            }
            env->DeleteLocalRef(elem);
        }
    }

    if (dexElements) env->DeleteLocalRef(dexElements);
    if (elemCls) env->DeleteLocalRef(elemCls);
    if (dplCls) env->DeleteLocalRef(dplCls);
    if (baseCls) env->DeleteLocalRef(baseCls);
    env->DeleteLocalRef(pathList);

    std::ostringstream out;
    out << "[*] dumpAllDex -> " << outDir << "\n";
    out << "    dumped=" << dumped << " (checksum repaired=" << repairedCount
        << ", skipped=" << skipped << ")\n";
    out << details.str();
    return JS_NewString(ctx, out.str().c_str());
}

void RegisterJavaDecompileApis(JSContext* ctx, JSValue global, JSValue java) {
    // Java namespace
    JS_SetPropertyStr(ctx, java, "dumpSmali", JS_NewCFunction(ctx, JsDumpSmali, "dumpSmali", 2));
    JS_SetPropertyStr(ctx, java, "dumpCode", JS_NewCFunction(ctx, JsDumpCode, "dumpCode", 2));
    JS_SetPropertyStr(ctx, java, "decompile", JS_NewCFunction(ctx, JsDecompile, "decompile", 2));
    JS_SetPropertyStr(ctx, java, "disassembly", JS_NewCFunction(ctx, JsDumpCode, "disassembly", 2));
    JS_SetPropertyStr(ctx, java, "dumpAllDex", JS_NewCFunction(ctx, JsDumpAllDex, "dumpAllDex", 1));
    JS_SetPropertyStr(ctx, java, "dumpalldex", JS_NewCFunction(ctx, JsDumpAllDex, "dumpalldex", 1));
    JS_SetPropertyStr(ctx, java, "dumpDex", JS_NewCFunction(ctx, JsDumpAllDex, "dumpDex", 1));

    // Flat global aliases
    JS_SetPropertyStr(ctx, global, "dumpSmali", JS_NewCFunction(ctx, JsDumpSmali, "dumpSmali", 2));
    JS_SetPropertyStr(ctx, global, "dumpsmali", JS_NewCFunction(ctx, JsDumpSmali, "dumpsmali", 2));
    JS_SetPropertyStr(ctx, global, "dumpCode", JS_NewCFunction(ctx, JsDumpCode, "dumpCode", 2));
    JS_SetPropertyStr(ctx, global, "dumpcode", JS_NewCFunction(ctx, JsDumpCode, "dumpcode", 2));
    JS_SetPropertyStr(ctx, global, "decompile", JS_NewCFunction(ctx, JsDecompile, "decompile", 2));
    JS_SetPropertyStr(ctx, global, "disassembly", JS_NewCFunction(ctx, JsDumpCode, "disassembly", 2));
    JS_SetPropertyStr(ctx, global, "disasm", JS_NewCFunction(ctx, JsDumpCode, "disasm", 2));
    JS_SetPropertyStr(ctx, global, "dumpAllDex", JS_NewCFunction(ctx, JsDumpAllDex, "dumpAllDex", 1));
    JS_SetPropertyStr(ctx, global, "dumpalldex", JS_NewCFunction(ctx, JsDumpAllDex, "dumpalldex", 1));
    JS_SetPropertyStr(ctx, global, "dumpdex", JS_NewCFunction(ctx, JsDumpAllDex, "dumpdex", 1));
}

}} // namespace artpi::agent
