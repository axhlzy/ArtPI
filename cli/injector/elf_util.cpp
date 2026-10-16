#include "elf_util.h"

#include <cstdio>
#include <cstring>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <elf.h>

// The kernel appends " (deleted)" to /proc/<pid>/maps for a mapping whose
// backing file was unlinked or replaced (e.g. our payload overwritten with
// O_TRUNC while the previous agent was still mapped). Strip it, otherwise
// basename matching (IsLibraryMapped) misses the live mapping and the injector
// re-deploys over a file that is still mapped.
static void StripDeletedSuffix(char *path) {
    static const char kSuffix[] = " (deleted)";
    const size_t slen = sizeof(kSuffix) - 1;
    size_t plen = strlen(path);
    if (plen >= slen && strcmp(path + plen - slen, kSuffix) == 0) {
        path[plen - slen] = '\0';
    }
}

bool GetModules(pid_t pid, std::vector<Module> &out) {
    out.clear();
    char mapsPath[64];
    snprintf(mapsPath, sizeof(mapsPath), "/proc/%d/maps", (int) pid);
    FILE *f = fopen(mapsPath, "r");
    if (!f) return false;
    char line[1024];
    while (fgets(line, sizeof(line), f)) {
        unsigned long long start = 0, end = 0;
        if (sscanf(line, "%llx-%llx", &start, &end) != 2) continue;
        char *p = strchr(line, '/');
        if (!p) continue; // anonymous / [vdso] style entries
        p[strcspn(p, "\r\n")] = 0;
        StripDeletedSuffix(p);
        bool merged = false;
        for (auto &m : out) {
            if (m.path == p) {
                if (start < m.base) m.base = start;
                if (end > m.end) m.end = end;
                merged = true;
                break;
            }
        }
        if (!merged) out.push_back(Module{start, end, p});
    }
    fclose(f);
    return true;
}

const Module *FindModuleByBasename(const std::vector<Module> &mods, const char *basename) {
    for (const auto &m : mods) {
        const char *bn = strrchr(m.path.c_str(), '/');
        bn = bn ? bn + 1 : m.path.c_str();
        if (strcmp(bn, basename) == 0) return &m;
    }
    return nullptr;
}

bool GetMappings(pid_t pid, std::vector<Mapping> &out) {
    out.clear();
    char mapsPath[64];
    snprintf(mapsPath, sizeof(mapsPath), "/proc/%d/maps", (int) pid);
    FILE *f = fopen(mapsPath, "r");
    if (!f) return false;
    char line[1024];
    while (fgets(line, sizeof(line), f)) {
        unsigned long long start = 0, end = 0;
        if (sscanf(line, "%llx-%llx", &start, &end) != 2) continue;
        char *p = strchr(line, '/');
        if (!p) continue;
        p[strcspn(p, "\r\n")] = 0;
        StripDeletedSuffix(p);
        out.push_back(Mapping{start, end, p});
    }
    fclose(f);
    return true;
}

uint64_t ElfSymbolOffset(const char *elfPath, std::initializer_list<const char *> names) {
    int fd = open(elfPath, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return 0;
    struct stat st{};
    if (fstat(fd, &st) != 0 || st.st_size < (off_t) sizeof(Elf64_Ehdr)) { close(fd); return 0; }
    std::vector<uint8_t> buf((size_t) st.st_size);
    ssize_t got = pread(fd, buf.data(), buf.size(), 0);
    close(fd);
    if (got != (ssize_t) buf.size()) return 0;

    const auto *ehdr = (const Elf64_Ehdr *) buf.data();
    if (memcmp(ehdr->e_ident, ELFMAG, SELFMAG) != 0 || ehdr->e_ident[EI_CLASS] != ELFCLASS64)
        return 0;
    if (ehdr->e_shoff == 0 || ehdr->e_shentsize != sizeof(Elf64_Shdr)) return 0;
    if (ehdr->e_shoff + (uint64_t) ehdr->e_shnum * ehdr->e_shentsize > buf.size()) return 0;

    const auto *shdrs = (const Elf64_Shdr *) (buf.data() + ehdr->e_shoff);
    for (int i = 0; i < ehdr->e_shnum; i++) {
        if (shdrs[i].sh_type != SHT_DYNSYM) continue;
        if (shdrs[i].sh_link >= (uint32_t) ehdr->e_shnum) continue;
        const Elf64_Shdr &strtab = shdrs[shdrs[i].sh_link];
        if (shdrs[i].sh_offset + shdrs[i].sh_size > buf.size()) continue;
        if (strtab.sh_offset + strtab.sh_size > buf.size()) continue;
        const auto *syms = (const Elf64_Sym *) (buf.data() + shdrs[i].sh_offset);
        size_t nsyms = shdrs[i].sh_size / sizeof(Elf64_Sym);
        const char *strs = (const char *) (buf.data() + strtab.sh_offset);
        for (const char *want : names) {
            for (size_t s = 0; s < nsyms; s++) {
                if (syms[s].st_value == 0 || syms[s].st_name == 0) continue;
                if (syms[s].st_name >= strtab.sh_size) continue;
                if (strcmp(strs + syms[s].st_name, want) == 0) return syms[s].st_value;
            }
        }
        break;
    }
    return 0;
}

#include <dirent.h>

pid_t FindPidByPackageName(const std::string& pkgName) {
    DIR* dir = opendir("/proc");
    if (!dir) return -1;

    struct dirent* ent = nullptr;
    while ((ent = readdir(dir)) != nullptr) {
        if (ent->d_type != DT_DIR) continue;
        char* endp = nullptr;
        long pid = strtol(ent->d_name, &endp, 10);
        if (*endp != '\0' || pid <= 0) continue;

        char path[64];
        snprintf(path, sizeof(path), "/proc/%ld/cmdline", pid);
        int fd = open(path, O_RDONLY | O_CLOEXEC);
        if (fd < 0) continue;

        char cmd[256] = {0};
        ssize_t n = read(fd, cmd, sizeof(cmd) - 1);
        close(fd);
        if (n <= 0) continue;

        if (pkgName == cmd) {
            closedir(dir);
            return static_cast<pid_t>(pid);
        }
    }
    closedir(dir);
    return -1;
}

bool FindTopActivityApp(pid_t& outPid, std::string& outPkg, std::string& outActivity) {
    outPid = -1;
    outPkg.clear();
    outActivity.clear();

    // 1. Fast path: `dumpsys activity top` prints activities from bottom to top;
    //    the last `  ACTIVITY <pkg>/<cls> <hash> pid=<pid>` line is the foreground top activity.
    if (FILE* fp = popen("dumpsys activity top 2>/dev/null", "r")) {
        char line[1024];
        while (fgets(line, sizeof(line), fp)) {
            const char* p = line;
            while (*p == ' ' || *p == '\t') p++;
            if (strncmp(p, "ACTIVITY ", 9) != 0) continue;
            p += 9;
            while (*p == ' ') p++;
            const char* compEnd = p;
            while (*compEnd && *compEnd != ' ' && *compEnd != '\t' && *compEnd != '\r' && *compEnd != '\n') {
                compEnd++;
            }
            std::string comp(p, static_cast<size_t>(compEnd - p));
            size_t slash = comp.find('/');
            if (slash == std::string::npos || slash == 0) continue;

            const char* pidPos = strstr(compEnd, "pid=");
            pid_t parsedPid = -1;
            if (pidPos) {
                long v = strtol(pidPos + 4, nullptr, 10);
                if (v > 0) parsedPid = static_cast<pid_t>(v);
            }
            outPkg = comp.substr(0, slash);
            outActivity = comp;
            outPid = parsedPid;
        }
        pclose(fp);
    }

    if (outPid <= 0 && !outPkg.empty()) {
        outPid = FindPidByPackageName(outPkg);
    }
    if (outPid > 0 && !outPkg.empty()) {
        return true;
    }

    // 2. Fallback: parse topResumedActivity / mResumedActivity from `dumpsys activity activities`
    if (FILE* fp = popen("dumpsys activity activities 2>/dev/null", "r")) {
        char line[1024];
        while (fgets(line, sizeof(line), fp)) {
            if (!strstr(line, "ResumedActivity")) continue;
            const char* slash = strchr(line, '/');
            if (!slash) continue;
            const char* pkgStart = slash;
            while (pkgStart > line && (isalnum(static_cast<unsigned char>(pkgStart[-1])) ||
                                       pkgStart[-1] == '.' || pkgStart[-1] == '_')) {
                pkgStart--;
            }
            const char* actEnd = slash + 1;
            while (*actEnd && !isspace(static_cast<unsigned char>(*actEnd)) && *actEnd != '}') {
                actEnd++;
            }
            if (pkgStart < slash && actEnd > slash + 1) {
                outPkg.assign(pkgStart, static_cast<size_t>(slash - pkgStart));
                outActivity.assign(pkgStart, static_cast<size_t>(actEnd - pkgStart));
                outPid = FindPidByPackageName(outPkg);
                if (outPid > 0) {
                    pclose(fp);
                    return true;
                }
            }
        }
        pclose(fp);
    }

    return outPid > 0 && !outPkg.empty();
}

pid_t GetTracerPid(pid_t pid) {
    char statusPath[64];
    snprintf(statusPath, sizeof(statusPath), "/proc/%d/status", static_cast<int>(pid));
    FILE* fp = fopen(statusPath, "r");
    if (!fp) return 0;
    char line[256];
    pid_t tracer = 0;
    while (fgets(line, sizeof(line), fp)) {
        if (strncmp(line, "TracerPid:", 10) == 0) {
            tracer = static_cast<pid_t>(strtol(line + 10, nullptr, 10));
            break;
        }
    }
    fclose(fp);
    return tracer;
}

bool IsAppSpecialized(pid_t pid) {
    char attrPath[64];
    snprintf(attrPath, sizeof(attrPath), "/proc/%d/attr/current", static_cast<int>(pid));
    int fd = open(attrPath, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return true; // SELinux disabled or inaccessible
    char buf[256] = {0};
    ssize_t n = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    if (n <= 0) return true;
    return strstr(buf, "zygote") == nullptr && strstr(buf, "usap") == nullptr;
}

#include <atomic>
#include <chrono>
#include <csignal>
#include <cstdlib>
#include <dlfcn.h>
#include <sched.h>
#include <thread>

namespace {

struct LoggerEntryHdr {
    uint16_t len;
    uint16_t hdr_size;
    int32_t pid;
    uint32_t tid;
    uint32_t sec;
    uint32_t nsec;
    uint32_t lid;
    uint32_t uid;
};

struct LogMsgBuf {
    union __attribute__((aligned(4))) {
        unsigned char buf[5 * 1024 + 1];
        LoggerEntryHdr entry;
    };
};

struct __attribute__((packed)) EventHeader {
    int32_t tag;
};

struct __attribute__((packed)) EventInt {
    int8_t type;
    int32_t data;
};

struct __attribute__((packed)) EventString {
    int8_t type;
    int32_t length;
    char data[];
};

struct __attribute__((packed)) EventList {
    int8_t type;
    int8_t element_count;
};

// 30014 am_proc_start (User|1|5),(PID|1|5),(UID|1|5),(Process Name|3),(Type|3),(Component|3)
struct __attribute__((packed)) EventAmProcStart {
    EventHeader tag;
    EventList list;
    EventInt user;
    EventInt pid;
    EventInt uid;
    EventString process_name;
};

static bool IsValidPkgName(const std::string& pkg) {
    if (pkg.empty()) return false;
    for (char c : pkg) {
        if (!(isalnum(static_cast<unsigned char>(c)) || c == '.' || c == '_')) return false;
    }
    return true;
}

static std::string ResolveLauncherComponent(const std::string& pkg) {
    std::string cmd = "cmd package resolve-activity --brief " + pkg + " 2>/dev/null";
    FILE* fp = popen(cmd.c_str(), "r");
    if (!fp) return "";
    char line[512];
    std::string lastLine;
    while (fgets(line, sizeof(line), fp)) {
        line[strcspn(line, "\r\n")] = '\0';
        if (strchr(line, '/') != nullptr && strncmp(line, pkg.c_str(), pkg.size()) == 0) {
            lastLine = line;
        }
    }
    pclose(fp);
    return lastLine;
}

static bool ForceStopAndWaitDead(const std::string& pkg) {
    if (!IsValidPkgName(pkg)) return false;
    std::string cmd = "am force-stop " + pkg + " >/dev/null 2>&1";
    system(cmd.c_str());
    for (int i = 0; i < 50; ++i) {
        pid_t p = FindPidByPackageName(pkg);
        if (p <= 0) return true;
        kill(p, SIGKILL);
        usleep(15 * 1000);
    }
    return FindPidByPackageName(pkg) <= 0;
}

static bool LaunchAppPackage(const std::string& pkg) {
    if (!IsValidPkgName(pkg)) return false;
    std::string comp = ResolveLauncherComponent(pkg);
    if (!comp.empty()) {
        std::string cmd = "am start -n " + comp + " >/dev/null 2>&1";
        if (system(cmd.c_str()) == 0) return true;
    }
    std::string monkeyCmd = "monkey -p " + pkg + " -c android.intent.category.LAUNCHER --pct-syskeys 0 --pct-anyevent 0 1 >/dev/null 2>&1";
    return system(monkeyCmd.c_str()) == 0;
}

} // namespace

bool SpawnAndWatchPackage(const std::string& pkgName, pid_t& outPid, std::string& err) {
    outPid = -1;
    if (!IsValidPkgName(pkgName)) {
        err = "invalid package name: " + pkgName;
        return false;
    }

    printf("[*] Force-stopping '%s'...\n", pkgName.c_str());
    ForceStopAndWaitDead(pkgName);

    std::atomic<pid_t> caughtPid{-1};
    std::atomic<bool> stopWatch{false};

    // Watcher 1: Android LOG_ID_EVENTS (tag 30014 = am_proc_start) via liblog.so
    std::thread eventThread([&]() {
        void* liblog = dlopen("liblog.so", RTLD_LAZY);
        if (!liblog) return;
        using alloc_fn = void* (*)(int, unsigned int, pid_t);
        using open_fn = void* (*)(void*, int);
        using read_fn = int (*)(void*, LogMsgBuf*);
        using free_fn = void (*)(void*);

        auto fnAlloc = reinterpret_cast<alloc_fn>(dlsym(liblog, "android_logger_list_alloc"));
        auto fnOpen  = reinterpret_cast<open_fn>(dlsym(liblog, "android_logger_open"));
        auto fnRead  = reinterpret_cast<read_fn>(dlsym(liblog, "android_logger_list_read"));
        auto fnFree  = reinterpret_cast<free_fn>(dlsym(liblog, "android_logger_list_free"));
        if (!fnAlloc || !fnOpen || !fnRead || !fnFree) return;

        // mode = ANDROID_LOG_NONBLOCK (0x00000800) so we can exit cleanly when stopWatch is set
        void* list = fnAlloc(0x00000800, 1, 0);
        if (!list) return;
        constexpr int kLogIdEvents = 2; // LOG_ID_EVENTS
        if (!fnOpen(list, kLogIdEvents)) {
            fnFree(list);
            return;
        }

        // Drain existing tail entry before monitoring
        LogMsgBuf msg{};
        fnRead(list, &msg);

        constexpr int32_t kAmProcStartTag = 30014;
        while (!stopWatch.load(std::memory_order_relaxed) && caughtPid.load(std::memory_order_relaxed) <= 0) {
            int r = fnRead(list, &msg);
            if (r <= 0) {
                usleep(1000);
                continue;
            }
            const auto* hdr = reinterpret_cast<const EventHeader*>(&msg.buf[msg.entry.hdr_size]);
            if (hdr->tag != kAmProcStartTag) continue;
            const auto* ev = reinterpret_cast<const EventAmProcStart*>(hdr);
            if (ev->process_name.length == static_cast<int32_t>(pkgName.size()) &&
                memcmp(ev->process_name.data, pkgName.data(), pkgName.size()) == 0 &&
                ev->pid.data > 0) {
                pid_t expected = -1;
                caughtPid.compare_exchange_strong(expected, static_cast<pid_t>(ev->pid.data));
                break;
            }
        }
        fnFree(list);
    });

    // Watcher 2: Fast /proc/<pid>/cmdline poll (1ms interval fallback)
    std::thread procThread([&]() {
        while (!stopWatch.load(std::memory_order_relaxed) && caughtPid.load(std::memory_order_relaxed) <= 0) {
            pid_t p = FindPidByPackageName(pkgName);
            if (p > 0) {
                pid_t expected = -1;
                caughtPid.compare_exchange_strong(expected, p);
                break;
            }
            usleep(1000);
        }
    });

    // Launch the app asynchronously after watchers are armed
    printf("[*] Launching '%s' and waiting for am_proc_start / zygote specialize...\n", pkgName.c_str());
    std::thread launchThread([&]() {
        usleep(15 * 1000);
        LaunchAppPackage(pkgName);
    });

    auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(10000);
    while (caughtPid.load(std::memory_order_relaxed) <= 0 &&
           std::chrono::steady_clock::now() < deadline) {
        usleep(500);
    }

    stopWatch.store(true, std::memory_order_relaxed);
    if (launchThread.joinable()) launchThread.join();
    if (eventThread.joinable()) eventThread.join();
    if (procThread.joinable()) procThread.join();

    pid_t pid = caughtPid.load();
    if (pid <= 0) {
        err = "timed out waiting for process '" + pkgName + "' to start";
        return false;
    }

    // Spin until the child process leaves the zygote/usap SELinux domain
    auto specDeadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(5000);
    while (!IsAppSpecialized(pid)) {
        if (kill(pid, 0) != 0) {
            err = "spawned process " + std::to_string(pid) + " exited before specialization";
            return false;
        }
        if (std::chrono::steady_clock::now() >= specDeadline) {
            break;
        }
        sched_yield();
    }

    outPid = pid;
    return true;
}



