#include "agent_net.h"

#include <atomic>
#include <cstdio>
#include <cstring>
#include <mutex>
#include <thread>
#include <vector>
#include <algorithm>

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <fcntl.h>
#include <cstddef>
#include <android/log.h>

#define NET_LOGI(...) __android_log_print(ANDROID_LOG_INFO,  "ArtPI", __VA_ARGS__)
#define NET_LOGE(...) __android_log_print(ANDROID_LOG_ERROR, "ArtPI", __VA_ARGS__)

namespace artpi { namespace agent {

namespace {

constexpr int kPortRangeStart = 20700;
constexpr int kPortRangeEnd   = 20800;
constexpr uint32_t kMaxFrame  = 16u << 20;

struct ClientSession {
    int fd = -1;
    std::vector<uint8_t> rbuf;
};

std::mutex g_clientMutex;
std::vector<ClientSession> g_clients;
std::atomic<int> g_listenPort{-1};
std::string g_unixName;   // abstract-socket name when AF_INET is unavailable
std::atomic<bool> g_running{false};
std::thread g_serverThread;
MessageHandler g_handler;
thread_local int t_currentClientFd = -1;

// Log-capture ring (drained via artpi_agent_take_log).
std::mutex g_logMutex;
std::string g_logBuf;

bool SetNonBlocking(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0) return false;
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK) == 0;
}

bool SendAll(int fd, const void* data, size_t n) {
    const auto* p = static_cast<const uint8_t*>(data);
    while (n > 0) {
        ssize_t w = send(fd, p, n, MSG_NOSIGNAL);
        if (w < 0) {
            if (errno == EINTR) continue;
            return false;
        }
        if (w == 0) return false;
        p += w;
        n -= static_cast<size_t>(w);
    }
    return true;
}

bool SendFrame(int fd, const std::vector<uint8_t>& payload) {
    uint32_t lenBE = htonl(static_cast<uint32_t>(payload.size()));
    return SendAll(fd, &lenBE, 4) && SendAll(fd, payload.data(), payload.size());
}

void ServerWorker() {
    int listenFd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    int inetErrno = errno;
    int port = -1;

    if (listenFd >= 0) {
        int opt = 1;
        setsockopt(listenFd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
#ifdef SO_REUSEPORT
        setsockopt(listenFd, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt));
#endif
        for (int p = kPortRangeStart; p <= kPortRangeEnd; p++) {
            sockaddr_in sin{};
            sin.sin_family = AF_INET;
            sin.sin_port = htons(static_cast<uint16_t>(p));
            sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
            if (bind(listenFd, reinterpret_cast<sockaddr*>(&sin), sizeof(sin)) == 0) {
                port = p;
                break;
            }
        }
        if (port < 0 || listen(listenFd, 64) != 0) {
            inetErrno = errno;
            close(listenFd);
            listenFd = -1;
        }
    }

    if (listenFd >= 0) {
        g_listenPort.store(port);
        NET_LOGI("ServerWorker: TCP listening on 127.0.0.1:%d", port);
    } else {
        // AF_INET unavailable — typical when the target app has NO `INTERNET`
        // permission (Android gates AF_INET sockets on the AID_INET=3003 group),
        // or every port in the range is taken. Fall back to an *abstract* AF_UNIX
        // socket; reachable from the host via:
        //   adb forward tcp:<port> localabstract:<name>
        NET_LOGE("ServerWorker: TCP listen failed (errno=%d), falling back to AF_UNIX", inetErrno);
        listenFd = socket(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
        if (listenFd < 0) { NET_LOGE("ServerWorker: AF_UNIX socket failed errno=%d", errno); return; }
        sockaddr_un sun{};
        sun.sun_family = AF_UNIX;
        sun.sun_path[0] = '\0';   // abstract namespace
        int n = snprintf(sun.sun_path + 1, sizeof(sun.sun_path) - 1, "artpi_agent_%d", getpid());
        socklen_t len = static_cast<socklen_t>(offsetof(sockaddr_un, sun_path) + 1 + n);
        if (bind(listenFd, reinterpret_cast<sockaddr*>(&sun), len) != 0 || listen(listenFd, 64) != 0) {
            NET_LOGE("ServerWorker: AF_UNIX bind/listen failed errno=%d", errno);
            close(listenFd);
            return;
        }
        g_unixName.assign(sun.sun_path + 1, static_cast<size_t>(n));
        g_listenPort.store(-1);
        NET_LOGI("ServerWorker: AF_UNIX listening on @%s "
                 "(adb forward tcp:20700 localabstract:%s)", g_unixName.c_str(), g_unixName.c_str());
    }

    while (g_running.load()) {
        std::vector<pollfd> pfds;
        pfds.reserve(16);
        pfds.push_back(pollfd{listenFd, POLLIN, 0});

        {
            std::lock_guard<std::mutex> lk(g_clientMutex);
            for (const auto& c : g_clients) {
                if (c.fd >= 0) {
                    pfds.push_back(pollfd{c.fd, POLLIN, 0});
                }
            }
        }

        int r = poll(pfds.data(), pfds.size(), 100);
        if (r < 0) {
            if (errno == EINTR) continue;
            break;
        }

        // 1. Accept new incoming clients (stay non-blocking!)
        if (pfds[0].revents & POLLIN) {
            for (;;) {
                sockaddr_storage ss{};
                socklen_t slen = sizeof(ss);
                int nfd = accept4(listenFd, reinterpret_cast<sockaddr*>(&ss), &slen, SOCK_NONBLOCK | SOCK_CLOEXEC);
                if (nfd < 0) {
                    if (errno == EINTR) continue;
                    break;
                }
                int one = 1;
                setsockopt(nfd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
                SetNonBlocking(nfd);

                std::lock_guard<std::mutex> lk(g_clientMutex);
                ClientSession cs;
                cs.fd = nfd;
                cs.rbuf.reserve(64 * 1024);
                g_clients.push_back(std::move(cs));
            }
        }

        // 2. Read from active clients and parse complete requests
        struct RequestItem {
            int fd;
            msgpack::Value req;
        };
        std::vector<RequestItem> pendingRequests;
        std::vector<int> fdsToClose;

        {
            std::lock_guard<std::mutex> lk(g_clientMutex);
            for (size_t i = 1; i < pfds.size(); i++) {
                int cfd = pfds[i].fd;
                auto it = std::find_if(g_clients.begin(), g_clients.end(),
                                       [cfd](const ClientSession& s) { return s.fd == cfd; });
                if (it == g_clients.end()) continue;

                if (pfds[i].revents & (POLLERR | POLLNVAL)) {
                    fdsToClose.push_back(cfd);
                    it->fd = -1;
                    continue;
                }

                if (pfds[i].revents & POLLIN) {
                    bool closed = false;
                    for (;;) {
                        uint8_t buf[8192];
                        ssize_t n = recv(cfd, buf, sizeof(buf), 0);
                        if (n > 0) {
                            it->rbuf.insert(it->rbuf.end(), buf, buf + n);
                        } else if (n < 0) {
                            if (errno == EINTR) continue;
                            if (errno == EAGAIN || errno == EWOULDBLOCK) break;
                            closed = true;
                            break;
                        } else {
                            // n == 0: peer closed connection (EOF)
                            closed = true;
                            break;
                        }
                    }

                    // Extract all completed frames
                    auto& rbuf = it->rbuf;
                    while (rbuf.size() >= 4) {
                        uint32_t lenBE = 0;
                        std::memcpy(&lenBE, rbuf.data(), 4);
                        uint32_t frameLen = ntohl(lenBE);
                        if (frameLen > kMaxFrame) {
                            closed = true;
                            rbuf.clear();
                            break;
                        }
                        if (rbuf.size() < 4 + frameLen) break;

                        msgpack::Reader reader(rbuf.data() + 4, frameLen);
                        msgpack::Value req;
                        if (reader.readValue(req)) {
                            pendingRequests.push_back({cfd, std::move(req)});
                        }
                        rbuf.erase(rbuf.begin(), rbuf.begin() + 4 + frameLen);
                    }

                    if (closed) {
                        fdsToClose.push_back(cfd);
                        it->fd = -1;
                    }
                } else if (pfds[i].revents & POLLHUP) {
                    fdsToClose.push_back(cfd);
                    it->fd = -1;
                }
            }

            // Clean up marked sessions
            g_clients.erase(
                std::remove_if(g_clients.begin(), g_clients.end(),
                               [](const ClientSession& s) { return s.fd < 0; }),
                g_clients.end());
        }

        // Close sockets outside mutex
        for (int cfd : fdsToClose) {
            close(cfd);
        }

        // 3. Dispatch requests outside mutex to prevent deadlock with BroadcastLog / BroadcastEvent
        for (const auto& item : pendingRequests) {
            if (!g_handler) continue;
            SetCurrentClientFd(item.fd);
            msgpack::Value resp = g_handler(item.req);
            SetCurrentClientFd(-1);
            msgpack::Writer writer;
            writer.writeValue(resp);

            bool valid = false;
            {
                std::lock_guard<std::mutex> lk(g_clientMutex);
                for (const auto& c : g_clients) {
                    if (c.fd == item.fd) {
                        valid = true;
                        break;
                    }
                }
            }

            if (valid) {
                if (!SendFrame(item.fd, writer.buffer)) {
                    std::lock_guard<std::mutex> lk(g_clientMutex);
                    for (auto& c : g_clients) {
                        if (c.fd == item.fd) {
                            c.fd = -1;
                            break;
                        }
                    }
                    g_clients.erase(
                        std::remove_if(g_clients.begin(), g_clients.end(),
                                       [](const ClientSession& s) { return s.fd < 0; }),
                        g_clients.end());
                    close(item.fd);
                }
            }
        }
    }

    // Cleanup all clients on server stop
    {
        std::lock_guard<std::mutex> lk(g_clientMutex);
        for (auto& c : g_clients) {
            if (c.fd >= 0) close(c.fd);
        }
        g_clients.clear();
    }
    close(listenFd);
    g_listenPort.store(-1);
}

} // namespace

bool StartServer(MessageHandler handler) {
    if (g_running.exchange(true)) return true;
    g_handler = std::move(handler);
    g_serverThread = std::thread(ServerWorker);
    return true;
}

void BroadcastEvent(const std::string& channel, const msgpack::Value& data) {
    msgpack::Value frame = msgpack::Value::makeMap();
    frame.set("t", msgpack::Value(3)); // 3 = EVT
    frame.set("ch", msgpack::Value(channel));
    frame.set("data", data);

    msgpack::Writer writer;
    writer.writeValue(frame);

    int currFd = t_currentClientFd;
    if (currFd >= 0) {
        // Direct output exclusively to the invoking REPL client to prevent cross-talk
        bool valid = false;
        {
            std::lock_guard<std::mutex> lk(g_clientMutex);
            for (const auto& c : g_clients) {
                if (c.fd == currFd) {
                    valid = true;
                    break;
                }
            }
        }
        if (valid) {
            SendFrame(currFd, writer.buffer);
        }
        return;
    }

    // Background broadcast (hooks/tracers)
    std::vector<int> targetFds;
    {
        std::lock_guard<std::mutex> lk(g_clientMutex);
        for (const auto& c : g_clients) {
            if (c.fd >= 0) {
                targetFds.push_back(c.fd);
            }
        }
    }

    std::vector<int> failedFds;
    for (int fd : targetFds) {
        if (!SendFrame(fd, writer.buffer)) {
            failedFds.push_back(fd);
        }
    }

    if (!failedFds.empty()) {
        std::lock_guard<std::mutex> lk(g_clientMutex);
        for (int badFd : failedFds) {
            for (auto& c : g_clients) {
                if (c.fd == badFd) {
                    c.fd = -1;
                    break;
                }
            }
            close(badFd);
        }
        g_clients.erase(
            std::remove_if(g_clients.begin(), g_clients.end(),
                           [](const ClientSession& s) { return s.fd < 0; }),
            g_clients.end());
    }
}

void BroadcastLog(const char* channel, const std::string& text) {
    // Mirror every log/event line into a small ring buffer so embedders/tests can
    // read back what the agent emitted (see artpi_agent_take_log).
    {
        std::lock_guard<std::mutex> lk(g_logMutex);
        g_logBuf += '[';
        g_logBuf += (channel ? channel : "log");
        g_logBuf += "] ";
        g_logBuf += text;
        g_logBuf += '\n';
        if (g_logBuf.size() > 65536) g_logBuf.erase(0, 32768);
    }
    BroadcastEvent(channel ? channel : "log", msgpack::Value(text));
}

int GetCurrentClientFd() {
    return t_currentClientFd;
}

void SetCurrentClientFd(int fd) {
    t_currentClientFd = fd;
}

int GetActiveClientCount() {
    std::lock_guard<std::mutex> lk(g_clientMutex);
    return static_cast<int>(g_clients.size());
}

int GetServerPort() {
    return g_listenPort.load();
}

const char* GetUnixSocketName() {
    return g_unixName.empty() ? nullptr : g_unixName.c_str();
}

void StopServer() {
    if (!g_running.exchange(false)) return;
    if (g_serverThread.joinable()) {
        g_serverThread.join();
    }
}

// --- log capture ring (see BroadcastLog) ------------------------------------

}} // namespace artpi::agent

// Exported C entry: drain captured log lines (returns a thread-local buffer).
#if defined(__GNUC__) || defined(__clang__)
#define ARTPI_NET_EXPORT __attribute__((visibility("default")))
#else
#define ARTPI_NET_EXPORT
#endif
extern "C" ARTPI_NET_EXPORT const char* artpi_agent_take_log() {
    static thread_local std::string out;
    out.clear();
    {
        std::lock_guard<std::mutex> lk(artpi::agent::g_logMutex);
        out.swap(artpi::agent::g_logBuf);
    }
    return out.c_str();
}

// Exported C entry: abstract AF_UNIX socket name when AF_INET is unavailable
// (nullptr when the agent is serving over TCP).
extern "C" ARTPI_NET_EXPORT const char* artpi_agent_unix_name() {
    return artpi::agent::GetUnixSocketName();
}

// Exported C entry: bound TCP port (-1 when serving over AF_UNIX).
extern "C" ARTPI_NET_EXPORT int artpi_agent_listen_port() {
    return artpi::agent::GetServerPort();
}
