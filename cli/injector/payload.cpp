#include "payload.h"

#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include "xz.h"

namespace {
    constexpr size_t kTrailer = 16; // magic(8) + size(8)

    bool IsXzStream(const uint8_t *data, size_t size) {
        return size >= 6 &&
               data[0] == 0xFD &&
               data[1] == '7' &&
               data[2] == 'z' &&
               data[3] == 'X' &&
               data[4] == 'Z' &&
               data[5] == 0x00;
    }

    bool DecompressXz(const uint8_t *inData, size_t inSize, std::vector<uint8_t> &outData, std::string &err) {
        xz_crc32_init();
#ifdef XZ_USE_CRC64
        xz_crc64_init();
#endif
        struct xz_dec *s = xz_dec_init(XZ_DYNALLOC, 64U << 20);
        if (!s) {
            err = "xz_dec_init failed (memory allocation error)";
            return false;
        }

        struct xz_buf b{};
        b.in = inData;
        b.in_pos = 0;
        b.in_size = inSize;

        constexpr size_t kChunkSize = 256 * 1024;
        std::vector<uint8_t> chunk(kChunkSize);
        outData.clear();

        while (true) {
            b.out = chunk.data();
            b.out_pos = 0;
            b.out_size = chunk.size();

            enum xz_ret ret = xz_dec_catrun(s, &b, (b.in_pos == b.in_size));

            if (b.out_pos > 0) {
                outData.insert(outData.end(), chunk.data(), chunk.data() + b.out_pos);
            }

            if (ret == XZ_STREAM_END) {
                xz_dec_end(s);
                return true;
            }

            if (ret != XZ_OK && ret != XZ_UNSUPPORTED_CHECK) {
                xz_dec_end(s);
                err = "xz decompression failed with code " + std::to_string(ret);
                return false;
            }

            if (b.in_pos == b.in_size && b.out_pos == 0) {
                xz_dec_end(s);
                err = "xz stream truncated or corrupted";
                return false;
            }
        }
    }
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

    if (IsXzStream(out.data(), out.size())) {
        std::vector<uint8_t> decomp;
        if (!DecompressXz(out.data(), out.size(), decomp, err)) {
            return false;
        }
        out = std::move(decomp);
    }
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
            std::vector<uint8_t> rawPayload((size_t)size);
            size_t done = 0;
            while (done < size) {
                ssize_t r = pread(fd, rawPayload.data() + done, size - done, payloadOff + (off_t)done);
                if (r <= 0) { err = "payload short read"; close(fd); return false; }
                done += (size_t)r;
            }
            close(fd);

            if (IsXzStream(rawPayload.data(), rawPayload.size())) {
                return DecompressXz(rawPayload.data(), rawPayload.size(), out, err);
            }
            out = std::move(rawPayload);
            return true;
        }

        currentEnd = payloadOff;
    }

    close(fd);
    err = std::string("payload magic not found: ") + magic;
    return false;
}
