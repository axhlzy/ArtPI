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
        std::string libPath;
        std::string evalScript;
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
                exit(0);
            } else {
                fprintf(stderr, "[!] %s\n", err.c_str());
                exit(1);
            }
        }
        printf("[*] Attaching directly to interactive REPL session...\n");
        artpi::injector::RunInteractiveRepl(ep);
        exit(0);
    }

    bool MkdirP(const std::string &path, uid_t uid, gid_t gid) {
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

    void ApplySelinux(const std::string &src, const std::string &dst) {
        char ctx[256] = {0};
        ssize_t n = getxattr(src.c_str(), "security.selinux", ctx, sizeof(ctx) - 1);
        if (n <= 0) {
            strncpy(ctx, "u:object_r:apk_data_file:s0", sizeof(ctx) - 1);
            n = (ssize_t) strlen(ctx);
        }
        setxattr(dst.c_str(), "security.selinux", ctx, (size_t) n, 0);
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

    bool DeployPayload(const std::string &libDir, const std::string &apkPath,
                       const std::vector<uint8_t> &payload,
                       std::string &outPath, std::string &err) {
        struct stat apkSt{};
        if (stat(apkPath.c_str(), &apkSt) != 0) {
            err = "cannot stat " + apkPath + ": " + strerror(errno);
            return false;
        }
        if (!MkdirP(libDir, apkSt.st_uid, apkSt.st_gid)) {
            err = "cannot create " + libDir + ": " + strerror(errno);
            return false;
        }
        outPath = libDir + "/libartpi_agent.so";
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
        chown(outPath.c_str(), apkSt.st_uid, apkSt.st_gid);
        ApplySelinux(apkPath, outPath);
        return true;
    }

    void EnsureJadxJarDeployed() {
        const char* targetPath = "/data/local/tmp/jadxcli.jar";
        struct stat st{};
        if (stat(targetPath, &st) == 0 && st.st_size > 1000000) {
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

    if (opt.pid <= 0 && !opt.pkgName.empty()) {
        pid_t resolved = FindPidByPackageName(opt.pkgName);
        if (resolved > 0) {
            opt.pid = resolved;
            printf("[*] resolved package '%s' -> PID %d\n", opt.pkgName.c_str(), opt.pid);
        } else {
            fprintf(stderr, "[!] cannot find running process for package '%s'\n", opt.pkgName.c_str());
            return 1;
        }
    }

    if (opt.pid <= 0) {
        Usage(argv[0]);
        return 1;
    }

    if (getuid() != 0) {
        fprintf(stderr, "[!] must run as root (su -c '%s ...')\n", argv[0]);
        return 1;
    }

    // 1. Check if an agent is already running for this target (AF_UNIX preferred,
    //    then TCP 20700..20800). If found, attach directly without re-injecting!
    int alivePid = 0;
    std::string alivePkg;
    artpi::injector::AgentEndpoint ep;
    if (artpi::injector::DiscoverAgent(opt.pid, opt.pkgName, 20700, 20800, ep, alivePid, alivePkg)) {
        printf("[*] Found active ArtPI Agent at %s (PID: %d, Package: %s)\n",
               artpi::injector::DescribeEndpoint(ep).c_str(), alivePid, alivePkg.c_str());
        HandleConnectedSession(ep, opt);
        return 0;
    }

    // 2. If libartpi_agent.so is ALREADY mapped in the target process (e.g. server starting up),
    // do NOT re-deploy (which truncates the running .so causing SIGBUS crash!)
    // and do NOT re-inject. Wait briefly and retry connecting!
    if (IsLibraryMapped(opt.pid, "libartpi_agent.so")) {
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

    std::vector<uint8_t> payload;
    std::string err;
    bool ok = opt.libPath.empty() ? ExtractEmbeddedPayload(payload, err, "PPAYLOAD")
                                  : ReadFileAll(opt.libPath, payload, err);
    if (!ok) {
        fprintf(stderr, "[!] payload extraction failed: %s\n", err.c_str());
        return 1;
    }
    printf("[*] payload ready (%zu bytes)\n", payload.size());

    std::string libDir, apkPath;
    if (!FindAppLibDir(opt.pid, opt.pkgName, libDir, apkPath)) {
        fprintf(stderr, "[!] cannot find app apk/lib mapping for pid %d\n", opt.pid);
        return 1;
    }

    std::string deployedSoPath;
    if (!DeployPayload(libDir, apkPath, payload, deployedSoPath, err)) {
        fprintf(stderr, "[!] deploy failed: %s\n", err.c_str());
        return 1;
    }
    printf("[+] deployed payload -> %s\n", deployedSoPath.c_str());

    printf("[*] injecting libartpi_agent.so via ptrace into pid %d ...\n", opt.pid);
    size_t lastSlash = apkPath.rfind('/');
    std::string apkPrefix = (lastSlash != std::string::npos) ? apkPath.substr(0, lastSlash + 1) : "";

    err.clear();
    if (!InjectLibrary(opt.pid, deployedSoPath.c_str(), apkPrefix.c_str(), err)) {
        fprintf(stderr, "[!] inject failed: %s\n", err.c_str());
        return 1;
    }

    printf("[+] injection successful: %s\n", err.c_str());

    // Connect to newly spawned Agent (AF_UNIX preferred, then TCP scan)
    printf("[*] waiting for agent endpoint...\n");
    bool found = false;
    for (int retry = 0; retry < 40; retry++) {
        usleep(150 * 1000);
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
