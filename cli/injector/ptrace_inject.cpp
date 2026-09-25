#include "ptrace_inject.h"
#include "elf_util.h"

#include <cerrno>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#include <csignal>
#include <cstdlib>
#include <fcntl.h>
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
    if (!GetModules(pid, mods)) {
        err = "cannot read /proc/" + std::to_string(pid) + "/maps";
        return false;
    }
    const Module *linker = FindModuleByBasename(mods, "linker64");
    const Module *libc = FindModuleByBasename(mods, "libc.so");
    Module callerStorage;
    if (!linker || !libc) {
        err = "linker64/libc.so not mapped in target (process too young?)";
        return false;
    }
    if (!FindCallerModule(pid, apkDirPrefix, callerStorage)) {
        err = "no valid caller module (app apk or .so with ELF-base mapping in app namespace)";
        return false;
    }
    const Module *caller = &callerStorage;

    uint64_t offMmap = ElfSymbolOffset(libc->path.c_str(), {"mmap"});
    uint64_t offDlopenExt = ElfSymbolOffset(linker->path.c_str(),
                                            {"__loader_android_dlopen_ext", "android_dlopen_ext"});
    if (!offMmap) { err = "symbol 'mmap' not found in " + libc->path; return false; }
    if (!offDlopenExt) { err = "symbol 'android_dlopen_ext' not found in " + linker->path; return false; }

    if (getenv("ARTPI_DEBUG")) fprintf(stderr, "[dbg] libc base=0x%llx offMmap=0x%llx -> mmap@0x%llx\n",
            (unsigned long long) libc->base, (unsigned long long) offMmap,
            (unsigned long long) (libc->base + offMmap));
    if (getenv("ARTPI_DEBUG")) fprintf(stderr, "[dbg] linker base=0x%llx offDlopenExt=0x%llx -> dlopen@0x%llx\n",
            (unsigned long long) linker->base, (unsigned long long) offDlopenExt,
            (unsigned long long) (linker->base + offDlopenExt));
    if (getenv("ARTPI_DEBUG")) fprintf(stderr, "[dbg] caller=%s base=0x%llx end=0x%llx\n",
            caller->path.c_str(), (unsigned long long) caller->base, (unsigned long long) caller->end);

    if (ptrace(PTRACE_ATTACH, pid, nullptr, nullptr) != 0) {
        err = std::string("PTRACE_ATTACH: ") + strerror(errno);
        return false;
    }
    bool attached = true;
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
    if (getenv("ARTPI_DEBUG")) fprintf(stderr, "[dbg] step1: remote mmap...\n");
    if (!RemoteCall(pid, libc->base + offMmap, args, 6, ret, err)) { detach(); return false; }
    if (getenv("ARTPI_DEBUG")) fprintf(stderr, "[dbg] step1 ok: remoteBuf=0x%llx\n", (unsigned long long) ret);
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
    if (pathLen > 0x2000 || !PokeBytes(pid, remoteBuf, soPath, pathLen)) {
        err = "failed to poke path into target";
        detach();
        return false;
    }

    // 3) __loader_android_dlopen_ext(path, RTLD_NOW, NULL, caller_addr)
    uint64_t span = caller->end - caller->base;
    uint64_t callerAddr = caller->base + (span > 0x2000 ? 0x1000 : span / 2);
    args[0] = remoteBuf;
    args[1] = RTLD_NOW;
    args[2] = 0; // no extinfo: caller_addr selects the namespace
    args[3] = callerAddr;
    if (getenv("ARTPI_DEBUG")) fprintf(stderr, "[dbg] step2: android_dlopen_ext(path=0x%llx, RTLD_NOW, 0, caller=0x%llx)...\n",
            (unsigned long long) remoteBuf, (unsigned long long) callerAddr);
    if (!RemoteCall(pid, linker->base + offDlopenExt, args, 4, ret, err)) { detach(); return false; }
    if (getenv("ARTPI_DEBUG")) fprintf(stderr, "[dbg] step2 ok: dlopen handle=0x%llx\n", (unsigned long long) ret);
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
