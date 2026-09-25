#include "payload.h"

#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

namespace {
    constexpr size_t kTrailer = 16; // magic(8) + size(8)
}

bool ReadFileAll(const std::string &path, std::vector<uint8_t> &out, std::string &err) {
    int fd = open(path.c_str(), O_RDONLY | O_CLOEXEC);
    if (fd < 0) { err = path + ": " + strerror(errno); return false; }
    struct stat st{};
    if (fstat(fd, &st) != 0) { err = path + ": fstat: " + strerror(errno); close(fd); return false; }
    out.resize((size_t) st.st_size);
    size_t done = 0;
    while (done < out.size()) {
        ssize_t r = read(fd, out.data() + done, out.size() - done);
        if (r < 0 && errno == EINTR) continue;
        if (r <= 0) { err = path + ": short read"; close(fd); return false; }
        done += (size_t) r;
    }
    close(fd);
    return true;
}

bool ExtractEmbeddedPayload(std::vector<uint8_t> &out, std::string &err, const char* magic) {
    int fd = open("/proc/self/exe", O_RDONLY | O_CLOEXEC);
    if (fd < 0) { err = std::string("/proc/self/exe: ") + strerror(errno); return false; }
    struct stat st{};
    if (fstat(fd, &st) != 0 || (size_t) st.st_size <= kTrailer) {
        err = "own exe too small";
        close(fd);
        return false;
    }

    off_t currentEnd = st.st_size;
    while (currentEnd >= (off_t)kTrailer) {
        uint8_t trailer[kTrailer];
        if (pread(fd, trailer, kTrailer, currentEnd - (off_t)kTrailer) != (ssize_t)kTrailer) {
            break;
        }

        uint64_t size = 0;
        for (int i = 0; i < 8; i++) size |= (uint64_t)trailer[8 + i] << (8 * i);

        if (size == 0 || size + kTrailer > (uint64_t)currentEnd) {
            break;
        }

        off_t payloadOff = currentEnd - (off_t)kTrailer - (off_t)size;

        if (memcmp(trailer, magic, 8) == 0) {
            out.resize((size_t)size);
            size_t done = 0;
            while (done < size) {
                ssize_t r = pread(fd, out.data() + done, size - done, payloadOff + (off_t)done);
                if (r <= 0) { err = "payload short read"; close(fd); return false; }
                done += (size_t)r;
            }
            close(fd);
            return true;
        }

        currentEnd = payloadOff;
    }

    close(fd);
    err = std::string("payload magic not found: ") + magic;
    return false;
}
