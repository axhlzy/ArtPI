//
// main.cpp - artpi-cli standalone arm64 root executable
//
// Extracts libartpi.so payload, deploys it to target app's lib directory,
// and ptrace-injects it into target process via android_dlopen_ext.
//
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

#include <fcntl.h>
#include <sys/stat.h>
#include <sys/xattr.h>
#include <unistd.h>

#include "payload.h"
#include "ptrace_inject.h"
#include "elf_util.h"
#include "repl_client.h"

namespace {

    struct Options {
        int pid = 0;
        std::string pkgName;
        std::string waitName;
        std::string libPath;
        std::string evalScript;
        bool topActivity = false;
        bool spawnMode = false;
        bool pauseMainThread = false;
        bool noPtrace = false;
        bool serverMode = false;
    };

    void Usage(const char *argv0) {
        printf(
            "artpi-cli - Standalone root arm64 injector for libartpi_agent.so\n"
            "\n"
            "usage: %s [options]\n"
            "\n"
            "options:\n"
            "  -P, --pid <pid>      Target process PID\n"
            "  -k, --pkg <name>     Target package name (e.g. com.example.app)\n"
            "  -S, --spawn [<pkg>]  Force-stop, launch app, and inject at startup specialization\n"
            "  -W, --wait <name>    Wait for a new process matching <name> (e.g. dex2oat), inject & pause\n"
            "  --pause              Keep target main thread paused after injection until 'resume' is entered\n"
            "  -t, --top            Attach to the foreground (top Activity) app\n"
            "  --no-ptrace          Inject via /proc/<pid>/mem without ptrace (auto-enabled if TracerPid != 0)\n"
            "  -e, --eval <script>  Evaluate a JavaScript expression and exit\n"
            "  -f, --file <path>    Execute a JavaScript file and exit\n"
            "  --lib <path>         Use external libartpi_agent.so instead of embedded payload\n"
            "  --server             Server mode: inject and exit immediately after agent is listening\n"
            "                       (outputs ARTPI_AGENT_PORT=<port> or ARTPI_AGENT_UNIX=<name>)\n"
            "  -h, --help           Show this help\n",
            argv0);
    }

    // Emitted when the agent is up but not reachable over TCP — most often
    // because the target app lacks android.permission.INTERNET (AF_INET sockets
    // are gated on the AID_INET group), so the agent listens on an abstract
    // AF_UNIX socket instead.
    void PrintNoTcpHint(pid_t pid) {
        fprintf(stderr,
            "[i] No TCP agent port found.\n"
            "    If this app has no android.permission.INTERNET, the agent listens on\n"
            "    an abstract AF_UNIX socket @artpi_agent_%d. Connect from the host:\n"
            "      adb forward tcp:20700 localabstract:artpi_agent_%d\n"
            "      python cli/artpi_repl.py --port 20700\n",
            (int) pid, (int) pid);
    }

    // In --server mode, print a machine-readable locator plus a ready-to-run hint.
    void PrintServerMode(const artpi::injector::AgentEndpoint& ep) {
        if (ep.isUnix) {
            printf("ARTPI_AGENT_UNIX=%s\n", ep.unixName.c_str());
            printf("[i] host connection:  adb forward tcp:20700 localabstract:%s\n",
                   ep.unixName.c_str());
        } else {
            printf("ARTPI_AGENT_PORT=%d\n", ep.port);
        }
    }

    void HandleConnectedSession(const artpi::injector::AgentEndpoint& ep, const Options& opt) {
        if (opt.serverMode) {
            PrintServerMode(ep);
            printf("[+] Server mode: ArtPI Agent is active, exiting.\n");
            exit(0);
        }
        if (!opt.evalScript.empty()) {
            std::string result, err;
            if (artpi::injector::EvalScript(ep, opt.evalScript, result, err)) {
                if (!result.empty() && result != "undefined" && result != "[undefined]") {
                    printf("%s\n", result.c_str());
                }
                if (!opt.pauseMainThread) {
                    exit(0);
                }
            } else {
                fprintf(stderr, "[!] %s\n", err.c_str());
                if (!opt.pauseMainThread) {
                    exit(1);
                }
            }
        }
        if (opt.pauseMainThread) {
            printf("[*] Target main thread (PID %d) is PAUSED. Set your hooks, then type 'resume' to continue!\n",
                   opt.pid);
        }
        printf("[*] Attaching directly to interactive REPL session...\n");
        artpi::injector::RunInteractiveRepl(ep);
        exit(0);
    }

    [[maybe_unused]] bool MkdirP(const std::string &path, uid_t uid, gid_t gid) {
        std::string cur;
        size_t i = 0;
        while (i < path.size()) {
            size_t j = path.find('/', i + 1);
            cur = (j == std::string::npos) ? path : path.substr(0, j);
            if (mkdir(cur.c_str(), 0755) != 0 && errno != EEXIST) return false;
            chown(cur.c_str(), uid, gid);
            if (j == std::string::npos) break;
            i = j;
        }
        return true;
    }

    void ApplySelinux(const std::string &src, const std::string &dst,
                      const char *fallback = "u:object_r:apk_data_file:s0") {
        char ctx[256] = {0};
        ssize_t n = getxattr(src.c_str(), "security.selinux", ctx, sizeof(ctx) - 1);
        if (n <= 0) {
            strncpy(ctx, fallback, sizeof(ctx) - 1);
            n = (ssize_t) strlen(ctx);
        }
        setxattr(dst.c_str(), "security.selinux", ctx, (size_t) n, 0);
    }

    // Read the first NUL-terminated field of /proc/<pid>/cmdline.
    std::string ReadProcCmdline(pid_t pid) {
        std::string path = "/proc/" + std::to_string(pid) + "/cmdline";
        FILE *fp = fopen(path.c_str(), "rb");
        if (!fp) return "";
        char buf[256] = {0};
        size_t n = fread(buf, 1, sizeof(buf) - 1, fp);
        fclose(fp);
        std::string s(buf, n);
        size_t nul = s.find('\0');
        if (nul != std::string::npos) s = s.substr(0, nul);
        return s;
    }

    // Resolve the target app's private data dir: /data/user/<userId>/<pkg>.
    // This dir (unlike the apk's lib/ directory) is writable and is part of the
    // app linker namespace's permitted paths, so the agent can be dlopen'd from it.
    bool ResolveAppDataDir(pid_t pid, const std::string &pkgName,
                           std::string &outDataDir, std::string &err) {
        std::string pkg = pkgName;
        if (pkg.empty()) {
            pkg = ReadProcCmdline(pid);
            size_t colon = pkg.find(':');
            if (colon != std::string::npos) pkg = pkg.substr(0, colon);
        }
        if (pkg.empty()) {
            err = "cannot determine package name for pid " + std::to_string(pid);
            return false;
        }

        struct stat procSt{};
        unsigned long userId = 0;
        if (pid > 0 && stat(("/proc/" + std::to_string(pid)).c_str(), &procSt) == 0) {
            userId = (unsigned long) procSt.st_uid / 100000UL;
        }
        std::string dir = "/data/user/" + std::to_string(userId) + "/" + pkg;

        struct stat dirSt{};
        if (stat(dir.c_str(), &dirSt) != 0 || !S_ISDIR(dirSt.st_mode)) {
            err = "app data dir not found: " + dir;
            return false;
        }
        outDataDir = dir;
        return true;
    }

    bool FindAppLibDir(pid_t pid, const std::string &pkgName,
                       std::string &outLibDir, std::string &outApkPath) {
        std::vector<Mapping> maps;
        if (!GetMappings(pid, maps)) return false;

        auto accepts = [](const std::string &p, const std::string *pkg) -> bool {
            if (p.rfind("/data/app/", 0) != 0) return false;
            if (p.size() < 4 || p.compare(p.size() - 4, 4, ".apk") != 0) return false;
            // Prefer the target package's own directory; never pick a foreign app
            // (e.g. the WebView provider) when a package name is known.
            if (pkg && !pkg->empty()) {
                return p.find("/" + *pkg) != std::string::npos ||
                       p.find(*pkg + "-") != std::string::npos ||
                       p.find(*pkg + "/") != std::string::npos;
            }
            return true;
        };

        // 1) Target package's own apk (when a package name is known).
        // 2) Fallback: any app apk mapped in the target process.
        for (int pass = 0; pass < 2; pass++) {
            const std::string *pkg = (pass == 0) ? &pkgName : nullptr;
            if (pass == 0 && pkgName.empty()) continue;
            for (const auto &mp : maps) {
                if (!accepts(mp.path, pkg)) continue;
                outApkPath = mp.path;
                size_t slash = mp.path.rfind('/');
                if (slash != std::string::npos) {
                    outLibDir = mp.path.substr(0, slash) + "/lib/arm64";
                    return true;
                }
            }
        }
        return false;
    }

    // Write the payload into `deployDir` (which must already exist and be
    // writable). We do NOT create parent dirs here: chown'ing every path
    // component would clobber system dirs like /data, /data/user, /data/user/0.
    bool DeployPayload(const std::string &deployDir, const std::string &labelSrc,
                       const std::vector<uint8_t> &payload,
                       std::string &outPath, std::string &err) {
        struct stat dirSt{};
        if (stat(deployDir.c_str(), &dirSt) != 0) {
            err = "cannot stat " + deployDir + ": " + strerror(errno);
            return false;
        }
        if (!S_ISDIR(dirSt.st_mode)) {
            err = deployDir + " is not a directory";
            return false;
        }
        outPath = deployDir + "/libartpi_agent.so";
        int fd = open(outPath.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0755);
        if (fd < 0) { err = outPath + ": " + strerror(errno); return false; }
        size_t done = 0;
        while (done < payload.size()) {
            ssize_t w = write(fd, payload.data() + done, payload.size() - done);
            if (w < 0 && errno == EINTR) continue;
            if (w <= 0) { err = outPath + ": write failed: " + strerror(errno); close(fd); return false; }
            done += (size_t) w;
        }
        close(fd);
        chmod(outPath.c_str(), 0755);
        chown(outPath.c_str(), dirSt.st_uid, dirSt.st_gid);
        ApplySelinux(labelSrc, outPath);
        return true;
    }

    void EnsureJadxJarDeployed() {
        const char* targetPath = "/data/local/tmp/jadxcli.jar";
        struct stat st{};
        if (stat(targetPath, &st) == 0 && st.st_size > 1000000) {
            chmod(targetPath, 0666);
            return;
        }

        std::vector<uint8_t> jarData;
        std::string err;
        if (ExtractEmbeddedPayload(jarData, err, "PJADXJAR")) {
            int fd = open(targetPath, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0666);
            if (fd >= 0) {
                size_t done = 0;
                while (done < jarData.size()) {
                    ssize_t w = write(fd, jarData.data() + done, jarData.size() - done);
                    if (w <= 0) break;
                    done += (size_t)w;
                }
                close(fd);
                chmod(targetPath, 0666);
                printf("[+] Deployed embedded jadxcli.jar -> %s (%zu bytes)\n", targetPath, jarData.size());
            }
        }
    }

} // namespace

int main(int argc, char **argv) {
    EnsureJadxJarDeployed();
    Options opt;
    for (int i = 1; i < argc; i++) {
        std::string a = argv[i];
        auto needValue = [&](const char *name) -> const char * {
            if (i + 1 >= argc) { fprintf(stderr, "%s requires a value\n", name); exit(2); }
            return argv[++i];
        };
        if (a == "-h" || a == "--help") { Usage(argv[0]); return 0; }
        else if (a == "-P" || a == "--pid") opt.pid = atoi(needValue("-P/--pid"));
        else if (a == "-k" || a == "--pkg") opt.pkgName = needValue("-k/--pkg");
        else if (a == "-S" || a == "--spawn") {
            opt.spawnMode = true;
            if (i + 1 < argc && argv[i + 1][0] != '-') {
                opt.pkgName = argv[++i];
            }
        }
        else if (a == "-W" || a == "--wait") {
            opt.waitName = needValue("-W/--wait");
            opt.pauseMainThread = true;
        }
        else if (a == "--pause") opt.pauseMainThread = true;
        else if (a == "-t" || a == "--top") opt.topActivity = true;
        else if (a == "--no-ptrace") opt.noPtrace = true;
        else if (a == "-e" || a == "--eval") opt.evalScript = needValue("-e/--eval");
        else if (a == "-f" || a == "--file") {
            const char* path = needValue("-f/--file");
            FILE* fp = fopen(path, "rb");
            if (!fp) { fprintf(stderr, "cannot open file: %s\n", path); exit(2); }
            fseek(fp, 0, SEEK_END);
            long sz = ftell(fp);
            fseek(fp, 0, SEEK_SET);
            std::string content(sz, '\0');
            fread(&content[0], 1, sz, fp);
            fclose(fp);
            opt.evalScript = content;
        }
        else if (a == "--lib") opt.libPath = needValue("--lib");
        else if (a == "--server") opt.serverMode = true;
        else { fprintf(stderr, "unknown option: %s (try --help)\n", a.c_str()); return 2; }
    }

    if (getuid() != 0) {
        fprintf(stderr, "[!] must run as root (su -c '%s ...')\n", argv[0]);
        return 1;
    }

    if (opt.topActivity && opt.pid <= 0 && opt.pkgName.empty()) {
        pid_t topPid = -1;
        std::string topPkg, topAct;
        if (FindTopActivityApp(topPid, topPkg, topAct)) {
            opt.pid = topPid;
            opt.pkgName = topPkg;
            printf("[*] resolved top activity '%s' -> package '%s' (PID %d)\n",
                   topAct.c_str(), opt.pkgName.c_str(), opt.pid);
        } else {
            fprintf(stderr, "[!] cannot resolve foreground top activity app\n");
            return 1;
        }
    }

    std::vector<uint8_t> preExtractedPayload;
    std::string preDeployedSoPath;

    if (!opt.waitName.empty()) {
        std::string preErr;
        bool ok = opt.libPath.empty() ? ExtractEmbeddedPayload(preExtractedPayload, preErr, "PPAYLOAD")
                                      : ReadFileAll(opt.libPath, preExtractedPayload, preErr);
        if (!ok) {
            fprintf(stderr, "[!] payload extraction failed: %s\n", preErr.c_str());
            return 1;
        }
        std::string dataDir, dataErr;
        if (ResolveAppDataDir(0, opt.waitName, dataDir, dataErr)) {
            if (DeployPayload(dataDir, dataDir, preExtractedPayload, preDeployedSoPath, preErr)) {
                printf("[+] pre-deployed payload -> %s (%zu bytes)\n",
                       preDeployedSoPath.c_str(), preExtractedPayload.size());
            }
        } else {
            // Native process (e.g. dex2oat): pre-deploy to /data/app/libartpi_agent.so
            // (since u:r:dex2oat:s0 can search /data/app [apk_data_file], unlike /data/local/tmp [shell_data_file])
            // with system_lib_file SELinux label from /system/lib64/libc.so.
            if (DeployPayload("/data/app", "/system/lib64/libc.so",
                              preExtractedPayload, preDeployedSoPath, preErr) ||
                DeployPayload("/data/local/tmp", "/system/lib64/libc.so",
                              preExtractedPayload, preDeployedSoPath, preErr)) {
                printf("[+] pre-deployed payload -> %s (%zu bytes)\n",
                       preDeployedSoPath.c_str(), preExtractedPayload.size());
            }
        }

        pid_t waitedPid = -1;
        std::string matchedName, waitErr;
        if (!WaitForNewProcessByName(opt.waitName, waitedPid, matchedName, waitErr)) {
            fprintf(stderr, "[!] wait failed: %s\n", waitErr.c_str());
            return 1;
        }
        opt.pid = waitedPid;
        if (opt.pkgName.empty()) opt.pkgName = matchedName;
        printf("[+] caught new process '%s' -> PID %d\n", matchedName.c_str(), opt.pid);
    } else if (opt.spawnMode) {
        if (opt.pkgName.empty()) {
            fprintf(stderr, "[!] -S/--spawn requires a package name (-S <pkg> or -k <pkg>)\n");
            return 1;
        }
        // Pre-extract and pre-deploy libartpi_agent.so BEFORE spawning the app
        // so that zero time is wasted on XZ decompression/disk I/O after process birth!
        std::string preErr;
        bool ok = opt.libPath.empty() ? ExtractEmbeddedPayload(preExtractedPayload, preErr, "PPAYLOAD")
                                      : ReadFileAll(opt.libPath, preExtractedPayload, preErr);
        if (!ok) {
            fprintf(stderr, "[!] payload extraction failed: %s\n", preErr.c_str());
            return 1;
        }
        std::string dataDir, dataErr;
        if (ResolveAppDataDir(0, opt.pkgName, dataDir, dataErr)) {
            if (DeployPayload(dataDir, dataDir, preExtractedPayload, preDeployedSoPath, preErr)) {
                printf("[+] pre-deployed payload -> %s (%zu bytes)\n",
                       preDeployedSoPath.c_str(), preExtractedPayload.size());
            }
        }

        pid_t spawnedPid = -1;
        std::string spawnErr;
        if (!SpawnAndWatchPackage(opt.pkgName, spawnedPid, spawnErr)) {
            fprintf(stderr, "[!] spawn failed: %s\n", spawnErr.c_str());
            return 1;
        }
        opt.pid = spawnedPid;
        printf("[+] caught spawned package '%s' right after zygote specialize -> PID %d\n",
               opt.pkgName.c_str(), opt.pid);
    } else if (opt.pid <= 0 && !opt.pkgName.empty()) {
        pid_t resolved = FindPidByPackageName(opt.pkgName);
        if (resolved > 0) {
            opt.pid = resolved;
            printf("[*] resolved package '%s' -> PID %d\n", opt.pkgName.c_str(), opt.pid);
        } else {
            fprintf(stderr, "[!] cannot find running process for package '%s' (use -S to spawn it)\n", opt.pkgName.c_str());
            return 1;
        }
    }

    if (opt.pid <= 0) {
        Usage(argv[0]);
        return 1;
    }

    // 1. Check if an agent is already running for this target (AF_UNIX preferred,
    //    then TCP 20700..20800). If found, attach directly without re-injecting!
    int alivePid = 0;
    std::string alivePkg;
    artpi::injector::AgentEndpoint ep;
    if (!opt.spawnMode && artpi::injector::DiscoverAgent(opt.pid, opt.pkgName, 20700, 20800, ep, alivePid, alivePkg)) {
        printf("[*] Found active ArtPI Agent at %s (PID: %d, Package: %s)\n",
               artpi::injector::DescribeEndpoint(ep).c_str(), alivePid, alivePkg.c_str());
        HandleConnectedSession(ep, opt);
        return 0;
    }

    // 2. If libartpi_agent.so is ALREADY mapped in the target process (e.g. server starting up),
    // do NOT re-deploy (which truncates the running .so causing SIGBUS crash!)
    // and do NOT re-inject. Wait briefly and retry connecting!
    if (!opt.spawnMode && IsLibraryMapped(opt.pid, "libartpi_agent.so")) {
        printf("[*] libartpi_agent.so is mapped in PID %d, waiting for agent to come up...\n", opt.pid);
        for (int retry = 0; retry < 25; retry++) {
            usleep(200 * 1000);
            if (artpi::injector::DiscoverAgent(opt.pid, opt.pkgName, 20700, 20800, ep, alivePid, alivePkg)) {
                HandleConnectedSession(ep, opt);
                return 0;
            }
        }
        fprintf(stderr, "[!] libartpi_agent.so is mapped but no agent endpoint became reachable\n");
        PrintNoTcpHint(opt.pid);
        return 1;
    }

    std::vector<uint8_t> payload = std::move(preExtractedPayload);
    std::string err;
    if (payload.empty() && preDeployedSoPath.empty()) {
        bool ok = opt.libPath.empty() ? ExtractEmbeddedPayload(payload, err, "PPAYLOAD")
                                      : ReadFileAll(opt.libPath, payload, err);
        if (!ok) {
            fprintf(stderr, "[!] payload extraction failed: %s\n", err.c_str());
            return 1;
        }
        printf("[*] payload ready (%zu bytes)\n", payload.size());
    }

    // apkPath is used to pick the linker-namespace caller (base.apk mapping) when available.
    std::string libDir, apkPath;
    if (!opt.spawnMode) {
        FindAppLibDir(opt.pid, opt.pkgName, libDir, apkPath);
    }

    std::string deployedSoPath = preDeployedSoPath;
    bool deployed = !deployedSoPath.empty();
    if (!deployed) {
        std::string dataDir;
        std::string dataErr;
        if (ResolveAppDataDir(opt.pid, opt.pkgName, dataDir, dataErr)) {
            if (DeployPayload(dataDir, dataDir, payload, deployedSoPath, err)) {
                deployed = true;
            } else {
                fprintf(stderr, "[i] deploy to app data dir failed (%s), falling back to lib dir\n", err.c_str());
            }
        } else {
            fprintf(stderr, "[i] %s, falling back to lib dir\n", dataErr.c_str());
        }
        if (!deployed && !libDir.empty()) {
            if (DeployPayload(libDir, apkPath, payload, deployedSoPath, err)) {
                deployed = true;
            }
        }
        // Fallback for non-app native processes (e.g. dex2oat64): deploy to /data/app (or /data/local/tmp)
        if (!deployed) {
            if (DeployPayload("/data/app", "/system/lib64/libc.so", payload, deployedSoPath, err) ||
                DeployPayload("/data/local/tmp", "/system/lib64/libc.so", payload, deployedSoPath, err)) {
                deployed = true;
            } else {
                fprintf(stderr, "[!] deploy failed: %s\n", err.c_str());
                return 1;
            }
        }
        printf("[+] deployed payload -> %s\n", deployedSoPath.c_str());
    }



    size_t lastSlash = apkPath.rfind('/');
    std::string apkPrefix = (lastSlash != std::string::npos) ? apkPath.substr(0, lastSlash + 1) : "";

    pid_t tracerPid = GetTracerPid(opt.pid);
    bool useNoPtrace = opt.noPtrace;
    if (!useNoPtrace && tracerPid > 0) {
        printf("[!] Target PID %d is already traced (TracerPid=%d), auto-switching to --no-ptrace (/proc/mem) mode...\n",
               opt.pid, (int) tracerPid);
        useNoPtrace = true;
    }

    err.clear();
    bool injOk = false;
    if (useNoPtrace) {
        printf("[*] injecting libartpi_agent.so via /proc/%d/mem (no-ptrace) ...\n", opt.pid);
        injOk = InjectLibraryNoPtrace(opt.pid, deployedSoPath.c_str(), apkPrefix.c_str(), err);
    } else {
        printf("[*] injecting libartpi_agent.so via ptrace (SEIZE) into pid %d ...\n", opt.pid);
        injOk = InjectLibrary(opt.pid, deployedSoPath.c_str(), apkPrefix.c_str(), err, opt.pauseMainThread);
        if (!injOk && err.find("PTRACE_") != std::string::npos) {
            printf("[!] ptrace attach failed (%s), falling back to --no-ptrace (/proc/mem) mode...\n", err.c_str());
            err.clear();
            injOk = InjectLibraryNoPtrace(opt.pid, deployedSoPath.c_str(), apkPrefix.c_str(), err);
        }
    }

    if (!injOk) {
        fprintf(stderr, "[!] inject failed: %s\n", err.c_str());
        return 1;
    }

    printf("[+] injection successful: %s\n", err.c_str());

    // Connect to newly spawned Agent (AF_UNIX preferred, then TCP scan)
    printf("[*] waiting for agent endpoint...\n");
    bool found = false;
    for (int retry = 0; retry < 150; retry++) {
        usleep(30 * 1000);
        if (artpi::injector::DiscoverAgent(opt.pid, opt.pkgName, 20700, 20800, ep, alivePid, alivePkg)) {
            found = true;
            break;
        }
    }

    if (found) {
        HandleConnectedSession(ep, opt);
        return 0;
    } else {
        fprintf(stderr, "[!] agent was injected but no endpoint became reachable\n");
        PrintNoTcpHint(opt.pid);
        return 1;
    }
    return 0;
}
