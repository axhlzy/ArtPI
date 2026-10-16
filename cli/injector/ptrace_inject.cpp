#include "ptrace_inject.h"
#include "elf_util.h"

#include <cerrno>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#include <csignal>
#include <cstddef>
#include <cstdlib>
#include <fcntl.h>
#include <android/dlext.h>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef NT_PRSTATUS
#define NT_PRSTATUS 1
#endif

#ifndef RTLD_NOW
#define RTLD_NOW 2
#endif

#ifndef PTRACE_SEIZE
#define PTRACE_SEIZE 0x4206
#endif

#ifndef PTRACE_INTERRUPT
#define PTRACE_INTERRUPT 0x4207
#endif

#ifndef PTRACE_O_TRACESYSGOOD
#define PTRACE_O_TRACESYSGOOD 0x00000001
#endif

static_assert(offsetof(android_dlextinfo, flags) == 0x00, "unexpected android_dlextinfo.flags offset");
static_assert(offsetof(android_dlextinfo, library_fd) == 0x1c, "unexpected android_dlextinfo.library_fd offset");

extern "C" {
extern const uint8_t artpi_stage1_start[];
extern const uint8_t artpi_stage1_var_addr[];
extern const uint8_t artpi_stage1_end[];

extern const uint8_t artpi_stage2_start[];
extern const uint8_t artpi_stage2_dlopen_addr[];
extern const uint8_t artpi_stage2_caller_addr[];
extern const uint8_t artpi_stage2_malloc_addr[];
extern const uint8_t artpi_stage2_end[];
}

__asm__(
    ".text\n"
    ".align 4\n"
    ".global artpi_stage1_start\n"
    "artpi_stage1_start:\n"
    "0:\n"
    "ldr x16, 2f\n"
    "ldaxrb w17, [x16]\n"
    "cbnz w17, 0b\n"
    "mov w17, #1\n"
    "stlxrb w15, w17, [x16]\n"
    "cbnz w15, 0b\n"

    "sub sp, sp, #0x100\n"
    "stp x0, x1, [sp, #0x00]\n"
    "stp x2, x3, [sp, #0x10]\n"
    "stp x4, x5, [sp, #0x20]\n"
    "stp x6, x7, [sp, #0x30]\n"
    "stp x8, x9, [sp, #0x40]\n"
    "stp x10, x11, [sp, #0x50]\n"
    "stp x12, x13, [sp, #0x60]\n"
    "stp x14, x15, [sp, #0x70]\n"
    "stp x16, x17, [sp, #0x80]\n"
    "stp x18, x19, [sp, #0x90]\n"
    "stp x20, x21, [sp, #0xa0]\n"
    "stp x22, x23, [sp, #0xb0]\n"
    "stp x24, x25, [sp, #0xc0]\n"
    "stp x26, x27, [sp, #0xd0]\n"
    "stp x28, x29, [sp, #0xe0]\n"
    "str x30, [sp, #0xf0]\n"

    "mov x0, #0\n"
    "mov x1, #0x4000\n"
    "mov x2, #7\n"
    "mov x3, #0x22\n"
    "movn x4, #0\n"
    "mov x5, #0\n"
    "mov x8, #222\n"
    "svc #0\n"

    "adr x1, 1f\n"
    "ldp x2, x3, [x1]\n"
    "stp x2, x3, [x0]\n"
    "dc cvau, x0\n"
    "dsb ish\n"
    "ic ivau, x0\n"
    "dsb ish\n"
    "isb\n"

    "ldr x16, 2f\n"
    "orr x1, x0, #1\n"
    "stlr x1, [x16]\n"
    "br x0\n"

    ".align 3\n"
    "1:\n"
    "ldr w16, [x0, #0xf0]\n"
    "cbz w16, 1b\n"
    "isb\n"
    "b . + 0xf4\n"

    ".align 3\n"
    ".global artpi_stage1_var_addr\n"
    "artpi_stage1_var_addr:\n"
    "2:\n"
    ".quad 0\n"
    ".global artpi_stage1_end\n"
    "artpi_stage1_end:\n"

    ".align 4\n"
    ".global artpi_stage2_start\n"
    "artpi_stage2_start:\n"
    "mov x19, x0\n"
    "add x0, x19, #0x200\n"
    "mov x1, #2\n"
    "mov x2, #0\n"
    "ldr x3, 2f\n"
    "ldr x8, 1f\n"
    "blr x8\n"
    "cbnz x0, 4f\n"

    "mov x0, #-100\n"
    "add x1, x19, #0x200\n"
    "mov x2, #0x80000\n"
    "mov x3, #0\n"
    "mov x8, #56\n"
    "svc #0\n"
    "tbnz x0, #63, 4f\n"
    "mov w20, w0\n"
    "mov x1, #0x10\n"
    "str x1, [x19, #0x1c0]\n"
    "str w20, [x19, #0x1dc]\n"
    "add x0, x19, #0x200\n"
    "mov x1, #2\n"
    "add x2, x19, #0x1c0\n"
    "ldr x3, 2f\n"
    "ldr x8, 1f\n"
    "blr x8\n"
    "mov x21, x0\n"
    "mov w0, w20\n"
    "mov x8, #57\n"
    "svc #0\n"
    "mov x0, x21\n"

    "4:\n"
    "cmp x0, #0\n"
    "csetm x1, eq\n"
    "orr x0, x0, x1\n"
    "str x0, [x19, #0xf8]\n"
    "dmb ish\n"

    "ldr x16, 3f\n"
    "ldr x30, [sp, #0xf0]\n"
    "ldp x28, x29, [sp, #0xe0]\n"
    "ldp x26, x27, [sp, #0xd0]\n"
    "ldp x24, x25, [sp, #0xc0]\n"
    "ldp x22, x23, [sp, #0xb0]\n"
    "ldp x20, x21, [sp, #0xa0]\n"
    "ldp x18, x19, [sp, #0x90]\n"
    "ldp x14, x15, [sp, #0x70]\n"
    "ldp x12, x13, [sp, #0x60]\n"
    "ldp x10, x11, [sp, #0x50]\n"
    "ldp x8, x9, [sp, #0x40]\n"
    "ldp x6, x7, [sp, #0x30]\n"
    "ldp x4, x5, [sp, #0x20]\n"
    "ldp x2, x3, [sp, #0x10]\n"
    "ldp x0, x1, [sp, #0x00]\n"
    "add sp, sp, #0x100\n"
    "br x16\n"

    ".align 3\n"
    ".global artpi_stage2_dlopen_addr\n"
    "artpi_stage2_dlopen_addr:\n"
    "1: .quad 0\n"
    ".global artpi_stage2_caller_addr\n"
    "artpi_stage2_caller_addr:\n"
    "2: .quad 0\n"
    ".global artpi_stage2_malloc_addr\n"
    "artpi_stage2_malloc_addr:\n"
    "3: .quad 0\n"
    ".global artpi_stage2_end\n"
    "artpi_stage2_end:\n"
);

namespace {

    struct Arm64Regs {
        uint64_t regs[31];
        uint64_t sp;
        uint64_t pc;
        uint64_t pstate;
    };

    bool GetRegs(pid_t pid, Arm64Regs &r) {
        struct iovec iov{&r, sizeof(r)};
        return ptrace(PTRACE_GETREGSET, pid, (void *) (uintptr_t) NT_PRSTATUS, &iov) == 0;
    }

    bool SetRegs(pid_t pid, const Arm64Regs &r) {
        struct iovec iov{(void *) &r, sizeof(r)};
        return ptrace(PTRACE_SETREGSET, pid, (void *) (uintptr_t) NT_PRSTATUS, &iov) == 0;
    }

    bool WaitStop(pid_t pid, int timeoutMs, int *sigOut, std::string &err) {
        auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeoutMs);
        for (;;) {
            int status = 0;
            pid_t r = waitpid(pid, &status, WNOHANG);
            if (r == pid) {
                if (WIFSTOPPED(status)) {
                    *sigOut = WSTOPSIG(status);
                    return true;
                }
                if (WIFEXITED(status) || WIFSIGNALED(status)) {
                    err = "target died during remote call";
                    return false;
                }
            } else if (r < 0 && errno != EINTR) {
                err = std::string("waitpid: ") + strerror(errno);
                return false;
            }
            if (std::chrono::steady_clock::now() >= deadline) {
                err = "remote call timed out";
                return false;
            }
            usleep(500);
        }
    }

    bool RemoteCall(pid_t pid, uint64_t func, const uint64_t args[6], int nargs,
                    uint64_t &ret, std::string &err) {
        Arm64Regs saved{}, run{}, out{};
        if (!GetRegs(pid, saved)) { err = "GETREGSET failed"; return false; }
        // If the target thread was interrupted in the middle of a restartable syscall
        // (e.g. epoll_pwait -> -ERESTART_RESTARTBLOCK = -516), sanitize saved x0 to -EINTR (-4)
        // so that after SIGSEGV stop and SetRegs(saved), libc sees -EINTR instead of errno=516.
        int64_t sx0 = static_cast<int64_t>(saved.regs[0]);
        if (sx0 <= -512 && sx0 >= -516) {
            saved.regs[0] = static_cast<uint64_t>(-static_cast<int64_t>(EINTR));
        }
        run = saved;
        for (int i = 0; i < 6; i++) run.regs[i] = (i < nargs) ? args[i] : 0;
        run.regs[30] = 0;                        // LR sentinel
        run.sp = (saved.sp - 0x1000) & ~0xFull;  // scratch frame
        run.pc = func;
        if (!SetRegs(pid, run)) { err = "SETREGSET(arm) failed"; return false; }
        if (ptrace(PTRACE_CONT, pid, nullptr, nullptr) != 0) {
            err = std::string("PTRACE_CONT: ") + strerror(errno);
            SetRegs(pid, saved);
            return false;
        }
        int sig = 0;
        if (!WaitStop(pid, 30000, &sig, err)) {
            kill(pid, SIGSTOP);
            int st = 0;
            waitpid(pid, &st, 0);
            SetRegs(pid, saved);
            return false;
        }
        if (!GetRegs(pid, out)) { err = "GETREGSET(after call) failed"; SetRegs(pid, saved); return false; }
        ret = out.regs[0];
        if (sig != SIGSEGV || out.pc != 0) {
            char buf[128];
            snprintf(buf, sizeof(buf), "unexpected stop: sig=%d pc=0x%llx (expected SIGSEGV @ pc=0)",
                     sig, (unsigned long long) out.pc);
            err = buf;
            SetRegs(pid, saved);
            return false;
        }
        if (!SetRegs(pid, saved)) { err = "restore regs failed"; return false; }
        return true;
    }

    bool PokeBytes(pid_t pid, uint64_t addr, const void *data, size_t len) {
        size_t n8 = (len + 7) / 8;
        std::vector<uint64_t> buf(n8, 0);
        memcpy(buf.data(), data, len);
        for (size_t i = 0; i < n8; i++) {
            errno = 0;
            if (ptrace(PTRACE_POKEDATA, pid, (void *) (uintptr_t) (addr + i * 8),
                       (void *) (uintptr_t) buf[i]) != 0 && errno != 0)
                return false;
        }
        return true;
    }

    bool HasElfMagicAt(pid_t pid, uint64_t addr) {
        char memPath[64];
        snprintf(memPath, sizeof(memPath), "/proc/%d/mem", (int) pid);
        int fd = open(memPath, O_RDONLY | O_CLOEXEC);
        if (fd < 0) return false;
        uint8_t magic[4] = {0};
        ssize_t r = pread(fd, magic, sizeof(magic), (off_t) addr);
        close(fd);
        return r == 4 && magic[0] == 0x7f && magic[1] == 'E' && magic[2] == 'L' && magic[3] == 'F';
    }

    bool EndsWith(const std::string &str, const std::string &suffix) {
        return str.size() >= suffix.size() &&
               str.compare(str.size() - suffix.size(), suffix.size(), suffix) == 0;
    }

    // Generic caller module discovery:
    // Any ELF module inside /data/app/<pkg> will trigger Android linker's classloader namespace.
    bool FindCallerModule(pid_t pid, const char *apkDirPrefix, Module &out) {
        std::vector<Mapping> maps;
        if (!GetMappings(pid, maps)) return false;

        size_t plen = (apkDirPrefix && *apkDirPrefix) ? strlen(apkDirPrefix) : 0;

        // 1. If prefix provided, check modules/apks under apkDirPrefix first
        if (plen > 0) {
            for (const auto &mp : maps) {
                if (mp.path.compare(0, plen, apkDirPrefix) == 0 &&
                    (EndsWith(mp.path, ".apk") || EndsWith(mp.path, ".so"))) {
                    if (HasElfMagicAt(pid, mp.start)) {
                        out = Module{mp.start, mp.end, mp.path};
                        return true;
                    }
                }
            }
        }

        // 2. Generic scan: check any apk or native lib mapping with valid ELF header in /data/app
        for (const auto &mp : maps) {
            if (mp.path.rfind("/data/app/", 0) == 0 &&
                (EndsWith(mp.path, ".apk") || EndsWith(mp.path, ".so"))) {
                if (HasElfMagicAt(pid, mp.start)) {
                    out = Module{mp.start, mp.end, mp.path};
                    return true;
                }
            }
        }

        // 3. Last fallback: any mapped .so under /data/
        for (const auto &mp : maps) {
            if (mp.path.rfind("/data/", 0) == 0 && EndsWith(mp.path, ".so")) {
                if (HasElfMagicAt(pid, mp.start)) {
                    out = Module{mp.start, mp.end, mp.path};
                    return true;
                }
            }
        }

        return false;
    }

    bool RemoteReady(pid_t pid, const char *apkDirPrefix) {
        std::vector<Module> mods;
        if (!GetModules(pid, mods)) return false;
        if (!FindModuleByBasename(mods, "linker64")) return false;
        if (!FindModuleByBasename(mods, "libc.so")) return false;
        Module caller;
        return FindCallerModule(pid, apkDirPrefix, caller);
    }

} // namespace

bool IsLibraryMapped(pid_t pid, const char *basename) {
    std::vector<Module> mods;
    if (!GetModules(pid, mods)) return false;
    return FindModuleByBasename(mods, basename) != nullptr;
}

bool WaitForEarlyWindow(pid_t pid, const char *apkDirPrefix, int timeoutMs) {
    auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeoutMs);
    for (;;) {
        if (RemoteReady(pid, apkDirPrefix)) return true;
        if (std::chrono::steady_clock::now() >= deadline) return false;
        usleep(25 * 1000);
    }
}

bool InjectLibrary(pid_t pid, const char *soPath, const char *apkDirPrefix, std::string &err) {
    std::vector<Module> mods;
    const Module *linker = nullptr;
    const Module *libc = nullptr;
    for (int waitIter = 0; waitIter < 80; ++waitIter) {
        if (GetModules(pid, mods)) {
            linker = FindModuleByBasename(mods, "linker64");
            libc = FindModuleByBasename(mods, "libc.so");
            if (linker && libc) break;
        }
        usleep(10 * 1000);
    }
    if (!linker || !libc) {
        err = "linker64/libc.so not mapped in target (process too young?)";
        return false;
    }

    Module callerStorage;
    bool hasAppCaller = FindCallerModule(pid, apkDirPrefix, callerStorage);
    if (!hasAppCaller) {
        // During early --spawn, give the process up to ~350ms to map its APK/native lib;
        // if still absent (e.g. pure-Java app or pre-bindApplication), fall back to libc.so + library_fd.
        for (int i = 0; i < 70; ++i) {
            usleep(5 * 1000);
            if (FindCallerModule(pid, apkDirPrefix, callerStorage)) {
                hasAppCaller = true;
                break;
            }
        }
    }
    const Module *caller = hasAppCaller ? &callerStorage : libc;

    uint64_t offMmap = ElfSymbolOffset(libc->path.c_str(), {"mmap"});
    uint64_t offOpen = ElfSymbolOffset(libc->path.c_str(), {"open", "__open_2"});
    uint64_t offClose = ElfSymbolOffset(libc->path.c_str(), {"close"});
    uint64_t offDlopenExt = ElfSymbolOffset(linker->path.c_str(),
                                            {"__loader_android_dlopen_ext", "android_dlopen_ext"});
    if (!offMmap) { err = "symbol 'mmap' not found in " + libc->path; return false; }
    if (!offDlopenExt) { err = "symbol 'android_dlopen_ext' not found in " + linker->path; return false; }

    // Prefer PTRACE_SEIZE + PTRACE_INTERRUPT so ONLY the main thread is stopped;
    // sibling threads holding g_dl_mutex can finish instead of deadlocking dlopen.
    bool attached = false;
    if (ptrace(PTRACE_SEIZE, pid, nullptr, (void *) (uintptr_t) PTRACE_O_TRACESYSGOOD) == 0) {
        if (ptrace(PTRACE_INTERRUPT, pid, nullptr, nullptr) == 0) {
            attached = true;
        } else {
            ptrace(PTRACE_DETACH, pid, nullptr, nullptr);
        }
    }
    if (!attached) {
        if (ptrace(PTRACE_ATTACH, pid, nullptr, nullptr) != 0) {
            err = std::string("PTRACE_SEIZE/ATTACH: ") + strerror(errno);
            return false;
        }
        attached = true;
    }
    auto detach = [&]() {
        if (attached) {
            ptrace(PTRACE_DETACH, pid, nullptr, nullptr);
            attached = false;
        }
    };

    int sig = 0;
    if (!WaitStop(pid, 5000, &sig, err)) { detach(); return false; }

    // 1) remote scratch buffer: mmap(NULL, 16K, RW, PRIVATE|ANON, -1, 0)
    uint64_t args[6] = {0, 0x4000, PROT_READ | PROT_WRITE,
                        MAP_PRIVATE | MAP_ANONYMOUS, (uint64_t) -1, 0};
    uint64_t ret = 0;
    if (!RemoteCall(pid, libc->base + offMmap, args, 6, ret, err)) { detach(); return false; }
    if (ret == 0 || ret >= (uint64_t) -4095) {
        char buf[96];
        snprintf(buf, sizeof(buf), "remote mmap failed (ret=0x%llx)", (unsigned long long) ret);
        err = buf;
        detach();
        return false;
    }
    uint64_t remoteBuf = ret;

    // 2) write the library path into the scratch buffer
    size_t pathLen = strlen(soPath) + 1;
    if (pathLen > 0x1000 || !PokeBytes(pid, remoteBuf, soPath, pathLen)) {
        err = "failed to poke path into target";
        detach();
        return false;
    }

    // 3) __loader_android_dlopen_ext(path, RTLD_NOW, NULL, caller_addr)
    uint64_t span = caller->end - caller->base;
    uint64_t callerAddr = caller->base + (span > 0x2000 ? 0x1000 : span / 2);
    ret = 0;
    if (hasAppCaller) {
        args[0] = remoteBuf;
        args[1] = RTLD_NOW;
        args[2] = 0; // no extinfo: caller_addr selects the namespace
        args[3] = callerAddr;
        if (!RemoteCall(pid, linker->base + offDlopenExt, args, 4, ret, err)) { detach(); return false; }
    }

    // 4) Fallback: if caller had no app namespace yet or dlopen returned NULL,
    //    open the deployed .so inside the target and pass ANDROID_DLEXT_USE_LIBRARY_FD.
    if (ret == 0 && offOpen && offClose) {
        args[0] = remoteBuf;
        args[1] = O_RDONLY | O_CLOEXEC;
        args[2] = 0;
        uint64_t fdRet = (uint64_t) -1;
        if (RemoteCall(pid, libc->base + offOpen, args, 3, fdRet, err) &&
            static_cast<int64_t>(fdRet) >= 0) {
            android_dlextinfo extinfo{};
            extinfo.flags = ANDROID_DLEXT_USE_LIBRARY_FD;
            extinfo.library_fd = static_cast<int>(fdRet);
            uint64_t extAddr = remoteBuf + 0x1800;
            if (PokeBytes(pid, extAddr, &extinfo, sizeof(extinfo))) {
                args[0] = remoteBuf;
                args[1] = RTLD_NOW;
                args[2] = extAddr;
                args[3] = callerAddr;
                RemoteCall(pid, linker->base + offDlopenExt, args, 4, ret, err);
            }
            uint64_t closeArgs[6] = {fdRet, 0, 0, 0, 0, 0};
            uint64_t dummy = 0;
            std::string dummyErr;
            RemoteCall(pid, libc->base + offClose, closeArgs, 1, dummy, dummyErr);
        }
    }

    detach();

    if (ret == 0) {
        err = "remote dlopen returned NULL (check logcat for linker/selinux error)";
        return false;
    }
    char info[256];
    snprintf(info, sizeof(info), "dlopen handle=%p (caller=%s+0x%llx)",
             (void *) (uintptr_t) ret, caller->path.c_str(),
             (unsigned long long) (callerAddr - caller->base));
    err = info;
    return true;
}

bool InjectLibraryNoPtrace(pid_t pid, const char *soPath, const char *apkDirPrefix, std::string &err) {
    std::vector<Module> mods;
    if (!GetModules(pid, mods)) {
        err = "cannot read /proc/" + std::to_string(pid) + "/maps";
        return false;
    }
    const Module *linker = FindModuleByBasename(mods, "linker64");
    const Module *libc = FindModuleByBasename(mods, "libc.so");
    if (!linker || !libc) {
        err = "linker64/libc.so not mapped in target";
        return false;
    }

    Module callerStorage;
    const Module *caller = FindCallerModule(pid, apkDirPrefix, callerStorage) ? &callerStorage : libc;
    uint64_t span = caller->end - caller->base;
    uint64_t callerAddr = caller->base + (span > 0x2000 ? 0x1000 : span / 2);

    uint64_t offMalloc = ElfSymbolOffset(libc->path.c_str(), {"malloc"});
    uint64_t offVar    = ElfSymbolOffset(libc->path.c_str(), {"timezone", "daylight"});
    uint64_t offDlopenExt = ElfSymbolOffset(linker->path.c_str(),
                                            {"__loader_android_dlopen_ext", "android_dlopen_ext"});
    if (!offMalloc || !offVar || !offDlopenExt) {
        err = "cannot resolve malloc/timezone/android_dlopen_ext symbols";
        return false;
    }

    uint64_t remoteMalloc = libc->base + offMalloc;
    uint64_t remoteVar    = libc->base + offVar;
    uint64_t remoteDlopen = linker->base + offDlopenExt;

    char memPath[64];
    snprintf(memPath, sizeof(memPath), "/proc/%d/mem", static_cast<int>(pid));
    int memFd = open(memPath, O_RDWR | O_CLOEXEC);
    if (memFd < 0) {
        err = std::string("open ") + memPath + ": " + strerror(errno);
        return false;
    }
    auto closeMem = [&]() {
        if (memFd >= 0) { close(memFd); memFd = -1; }
    };

    // Build Stage 1 payload from assembly template
    size_t stage1Len = static_cast<size_t>(artpi_stage1_end - artpi_stage1_start);
    size_t varOff    = static_cast<size_t>(artpi_stage1_var_addr - artpi_stage1_start);
    std::vector<uint8_t> stage1(artpi_stage1_start, artpi_stage1_end);
    memcpy(stage1.data() + varOff, &remoteVar, sizeof(remoteVar));

    // Build Stage 2 payload from assembly template
    size_t stage2Len    = static_cast<size_t>(artpi_stage2_end - artpi_stage2_start);
    size_t dlopenOff    = static_cast<size_t>(artpi_stage2_dlopen_addr - artpi_stage2_start);
    size_t callerOff    = static_cast<size_t>(artpi_stage2_caller_addr - artpi_stage2_start);
    size_t mallocLitOff = static_cast<size_t>(artpi_stage2_malloc_addr - artpi_stage2_start);
    std::vector<uint8_t> stage2(artpi_stage2_start, artpi_stage2_end);
    memcpy(stage2.data() + dlopenOff, &remoteDlopen, sizeof(remoteDlopen));
    memcpy(stage2.data() + callerOff, &callerAddr, sizeof(callerAddr));
    memcpy(stage2.data() + mallocLitOff, &remoteMalloc, sizeof(remoteMalloc));

    // Backup original malloc bytes and timezone variable
    std::vector<uint8_t> origMalloc(stage1Len, 0);
    uint64_t origVar = 0;
    if (pread(memFd, origMalloc.data(), stage1Len, static_cast<off_t>(remoteMalloc)) != static_cast<ssize_t>(stage1Len) ||
        pread(memFd, &origVar, sizeof(origVar), static_cast<off_t>(remoteVar)) != sizeof(origVar)) {
        err = "failed to backup original bytes from /proc/pid/mem";
        closeMem();
        return false;
    }

    // Clear sync variable, then write Stage 1 (writing the first instruction LAST)
    uint64_t zero = 0;
    uint32_t selfJmp = 0x14000000; // ARM64 `b .`
    pwrite(memFd, &zero, sizeof(zero), static_cast<off_t>(remoteVar));
    pwrite(memFd, &selfJmp, sizeof(selfJmp), static_cast<off_t>(remoteMalloc));
    pwrite(memFd, stage1.data() + 4, stage1Len - 4, static_cast<off_t>(remoteMalloc + 4));
    pwrite(memFd, stage1.data(), 4, static_cast<off_t>(remoteMalloc));

    // Wait for any thread in target process to call malloc and allocate newMap
    uint64_t newMap = 0;
    auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(8000);
    bool nudged = false;
    while (std::chrono::steady_clock::now() < deadline) {
        uint64_t val = 0;
        if (pread(memFd, &val, sizeof(val), static_cast<off_t>(remoteVar)) == sizeof(val)) {
            if ((val & 1ULL) != 0 && (val & ~0xFFFULL) != 0 && (val & ~1ULL) < 0xfffffffffffff000ULL) {
                newMap = val & ~1ULL;
                break;
            }
        }
        if (!nudged) {
            nudged = true;
            // Send a harmless Binder/signal nudge in background so an idle app wakes a thread and calls malloc
            kill(pid, SIGURG);
        }
        usleep(5 * 1000);
    }

    // Always restore malloc and timezone immediately!
    pwrite(memFd, &selfJmp, sizeof(selfJmp), static_cast<off_t>(remoteMalloc));
    usleep(20 * 1000);
    pwrite(memFd, origMalloc.data() + 4, stage1Len - 4, static_cast<off_t>(remoteMalloc + 4));
    pwrite(memFd, &origVar, sizeof(origVar), static_cast<off_t>(remoteVar));
    pwrite(memFd, origMalloc.data(), 4, static_cast<off_t>(remoteMalloc));

    if (newMap == 0) {
        err = "no-ptrace stage1 timed out waiting for malloc trigger";
        closeMem();
        return false;
    }

    // Write Stage 2 to newMap + 0x100 and soPath to newMap + 0x200
    size_t pathLen = strlen(soPath) + 1;
    if (pwrite(memFd, stage2.data(), stage2Len, static_cast<off_t>(newMap + 0x100)) != static_cast<ssize_t>(stage2Len) ||
        pwrite(memFd, soPath, pathLen, static_cast<off_t>(newMap + 0x200)) != static_cast<ssize_t>(pathLen)) {
        err = "failed to write stage2 into newMap";
        closeMem();
        return false;
    }

    // Release the winner thread spinning on *(uint32_t*)(newMap + 0xf0)
    uint32_t readyFlag = 1;
    pwrite(memFd, &readyFlag, sizeof(readyFlag), static_cast<off_t>(newMap + 0xf0));

    // Poll *(uint64_t*)(newMap + 0xf8) for dlopen handle result
    uint64_t dlHandle = 0;
    auto dlDeadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(10000);
    while (std::chrono::steady_clock::now() < dlDeadline) {
        if (pread(memFd, &dlHandle, sizeof(dlHandle), static_cast<off_t>(newMap + 0xf8)) == sizeof(dlHandle) &&
            dlHandle != 0) {
            break;
        }
        usleep(10 * 1000);
    }
    closeMem();

    if (dlHandle == 0 || dlHandle == ~0ULL) {
        err = "no-ptrace dlopen returned NULL (or timed out)";
        return false;
    }

    char info[256];
    snprintf(info, sizeof(info), "no-ptrace dlopen handle=%p (newMap=0x%llx, caller=%s+0x%llx)",
             (void *) (uintptr_t) dlHandle, (unsigned long long) newMap,
             caller->path.c_str(), (unsigned long long) (callerAddr - caller->base));
    err = info;
    return true;
}

