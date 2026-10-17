//
// pi_hash.cpp - ArtPI Hash & Integrity Suite Implementation
//
#include "pi_hash.h"
#include <cstring>
#include <cstdio>
#include <cctype>
#include <algorithm>

namespace PI { namespace Hash {

std::string ToHex(const uint8_t* data, size_t size, bool uppercase) {
    static const char* hexLower = "0123456789abcdef";
    static const char* hexUpper = "0123456789ABCDEF";
    const char* hex = uppercase ? hexUpper : hexLower;
    std::string s;
    s.resize(size * 2);
    for (size_t i = 0; i < size; i++) {
        s[i * 2]     = hex[(data[i] >> 4) & 0x0F];
        s[i * 2 + 1] = hex[data[i] & 0x0F];
    }
    return s;
}

// ============================================================================
// CRC32 & CRC32C (Compile-time constexpr tables - 100% thread safe, 0 race)
// ============================================================================
namespace {
template <uint32_t Poly>
struct CrcTable {
    uint32_t table[256]{};
    constexpr CrcTable() {
        for (uint32_t i = 0; i < 256; i++) {
            uint32_t c = i;
            for (int j = 0; j < 8; j++) {
                c = (c & 1) ? (Poly ^ (c >> 1)) : (c >> 1);
            }
            table[i] = c;
        }
    }
};

static constexpr CrcTable<0xEDB88320u> kCrc32Table;
static constexpr CrcTable<0x82F63B78u> kCrc32cTable;
} // namespace

uint32_t Crc32(const void* data, size_t size, uint32_t prev) {
    if (!data && size > 0) return 0;
    const uint8_t* p = reinterpret_cast<const uint8_t*>(data);
    uint32_t crc = ~prev;
    while (size--) {
        crc = kCrc32Table.table[(crc ^ *p++) & 0xFF] ^ (crc >> 8);
    }
    return ~crc;
}

uint32_t Crc32c(const void* data, size_t size, uint32_t prev) {
    if (!data && size > 0) return 0;
    const uint8_t* p = reinterpret_cast<const uint8_t*>(data);
    uint32_t crc = ~prev;
    while (size--) {
        crc = kCrc32cTable.table[(crc ^ *p++) & 0xFF] ^ (crc >> 8);
    }
    return ~crc;
}

// ============================================================================
// Adler-32 (RFC 1950 - standard DEX checksum)
// ============================================================================
uint32_t Adler32(const void* data, size_t size, uint32_t prev) {
    if (!data && size > 0) return 1;
    const uint8_t* buf = reinterpret_cast<const uint8_t*>(data);
    uint32_t a = prev & 0xffff;
    uint32_t b = (prev >> 16) & 0xffff;
    while (size > 0) {
        size_t tlen = size > 5552 ? 5552 : size;
        size -= tlen;
        while (tlen--) {
            a += *buf++;
            b += a;
        }
        a %= 65521;
        b %= 65521;
    }
    return (b << 16) | a;
}

// ============================================================================
// MD5 (RFC 1321)
// ============================================================================
namespace md5_impl {
    struct Context {
        uint32_t state[4];
        uint32_t count[2];
        uint8_t buffer[64];
    };

    static inline uint32_t F(uint32_t x, uint32_t y, uint32_t z) { return (x & y) | (~x & z); }
    static inline uint32_t G(uint32_t x, uint32_t y, uint32_t z) { return (x & z) | (y & ~z); }
    static inline uint32_t H(uint32_t x, uint32_t y, uint32_t z) { return x ^ y ^ z; }
    static inline uint32_t I(uint32_t x, uint32_t y, uint32_t z) { return y ^ (x | ~z); }
    static inline uint32_t RotL(uint32_t x, uint32_t n) { return (x << n) | (x >> (32 - n)); }

    static inline void FF(uint32_t& a, uint32_t b, uint32_t c, uint32_t d, uint32_t x, uint32_t s, uint32_t ac) {
        a = RotL(a + F(b, c, d) + x + ac, s) + b;
    }
    static inline void GG(uint32_t& a, uint32_t b, uint32_t c, uint32_t d, uint32_t x, uint32_t s, uint32_t ac) {
        a = RotL(a + G(b, c, d) + x + ac, s) + b;
    }
    static inline void HH(uint32_t& a, uint32_t b, uint32_t c, uint32_t d, uint32_t x, uint32_t s, uint32_t ac) {
        a = RotL(a + H(b, c, d) + x + ac, s) + b;
    }
    static inline void II(uint32_t& a, uint32_t b, uint32_t c, uint32_t d, uint32_t x, uint32_t s, uint32_t ac) {
        a = RotL(a + I(b, c, d) + x + ac, s) + b;
    }

    static void Transform(uint32_t state[4], const uint8_t block[64]) {
        uint32_t a = state[0], b = state[1], c = state[2], d = state[3], x[16];
        for (int i = 0, j = 0; i < 16; i++, j += 4) {
            x[i] = (static_cast<uint32_t>(block[j])) |
                   (static_cast<uint32_t>(block[j+1]) << 8) |
                   (static_cast<uint32_t>(block[j+2]) << 16) |
                   (static_cast<uint32_t>(block[j+3]) << 24);
        }

        FF(a, b, c, d, x[ 0], 7,  0xd76aa478); FF(d, a, b, c, x[ 1], 12, 0xe8c7b756);
        FF(c, d, a, b, x[ 2], 17, 0x242070db); FF(b, c, d, a, x[ 3], 22, 0xc1bdceee);
        FF(a, b, c, d, x[ 4], 7,  0xf57c0faf); FF(d, a, b, c, x[ 5], 12, 0x4787c62a);
        FF(c, d, a, b, x[ 6], 17, 0xa8304613); FF(b, c, d, a, x[ 7], 22, 0xfd469501);
        FF(a, b, c, d, x[ 8], 7,  0x698098d8); FF(d, a, b, c, x[ 9], 12, 0x8b44f7af);
        FF(c, d, a, b, x[10], 17, 0xffff5bb1); FF(b, c, d, a, x[11], 22, 0x895cd7be);
        FF(a, b, c, d, x[12], 7,  0x6b901122); FF(d, a, b, c, x[13], 12, 0xfd987193);
        FF(c, d, a, b, x[14], 17, 0xa679438e); FF(b, c, d, a, x[15], 22, 0x49b40821);

        GG(a, b, c, d, x[ 1], 5,  0xf61e2562); GG(d, a, b, c, x[ 6], 9,  0xc040b340);
        GG(c, d, a, b, x[11], 14, 0x265e5a51); GG(b, c, d, a, x[ 0], 20, 0xe9b6c7aa);
        GG(a, b, c, d, x[ 5], 5,  0xd62f105d); GG(d, a, b, c, x[10], 9,  0x02441453);
        GG(c, d, a, b, x[15], 14, 0xd8a1e681); GG(b, c, d, a, x[ 4], 20, 0xe7d3fbc8);
        GG(a, b, c, d, x[ 9], 5,  0x21e1cde6); GG(d, a, b, c, x[14], 9,  0xc33707d6);
        GG(c, d, a, b, x[ 3], 14, 0xf4d50d87); GG(b, c, d, a, x[ 8], 20, 0x455a14ed);
        GG(a, b, c, d, x[13], 5,  0xa9e3e905); GG(d, a, b, c, x[ 2], 9,  0xfcefa3f8);
        GG(c, d, a, b, x[ 7], 14, 0x676f02d9); GG(b, c, d, a, x[12], 20, 0x8d2a4c8a);

        HH(a, b, c, d, x[ 5], 4,  0xfffa3942); HH(d, a, b, c, x[ 8], 11, 0x8771f681);
        HH(c, d, a, b, x[11], 16, 0x6d9d6122); HH(b, c, d, a, x[14], 23, 0xfde5380c);
        HH(a, b, c, d, x[ 1], 4,  0xa4beea44); HH(d, a, b, c, x[ 4], 11, 0x4bdecfa9);
        HH(c, d, a, b, x[ 7], 16, 0xf6bb4b60); HH(b, c, d, a, x[10], 23, 0xbebfbc70);
        HH(a, b, c, d, x[13], 4,  0x289b7ec6); HH(d, a, b, c, x[ 0], 11, 0xeaa127fa);
        HH(c, d, a, b, x[ 3], 16, 0xd4ef3085); HH(b, c, d, a, x[ 6], 23, 0x04881d05);
        HH(a, b, c, d, x[ 9], 4,  0xd9d4d039); HH(d, a, b, c, x[12], 11, 0xe6db99e5);
        HH(c, d, a, b, x[15], 16, 0x1fa27cf8); HH(b, c, d, a, x[ 2], 23, 0xc4ac5665);

        II(a, b, c, d, x[ 0], 6,  0xf4292244); II(d, a, b, c, x[ 7], 10, 0x432aff97);
        II(c, d, a, b, x[14], 15, 0xab9423a7); II(b, c, d, a, x[ 5], 21, 0xfc93a039);
        II(a, b, c, d, x[12], 6,  0x655b59c3); II(d, a, b, c, x[ 3], 10, 0x8f0ccc92);
        II(c, d, a, b, x[10], 15, 0xffeff47d); II(b, c, d, a, x[ 1], 21, 0x85845dd1);
        II(a, b, c, d, x[ 8], 6,  0x6fa87e4f); II(d, a, b, c, x[15], 10, 0xfe2ce6e0);
        II(c, d, a, b, x[ 6], 15, 0xa3014314); II(b, c, d, a, x[13], 21, 0x4e0811a1);
        II(a, b, c, d, x[ 4], 6,  0xf7537e82); II(d, a, b, c, x[11], 10, 0xbd3af235);
        II(c, d, a, b, x[ 2], 15, 0x2ad7d2bb); II(b, c, d, a, x[ 9], 21, 0xeb86d391);

        state[0] += a; state[1] += b; state[2] += c; state[3] += d;
    }

    static void Init(Context& ctx) {
        ctx.count[0] = ctx.count[1] = 0;
        ctx.state[0] = 0x67452301; ctx.state[1] = 0xefcdab89;
        ctx.state[2] = 0x98badcfe; ctx.state[3] = 0x10325476;
    }

    static void Update(Context& ctx, const uint8_t* input, size_t inputLen) {
        size_t i = 0;
        uint32_t index = (ctx.count[0] >> 3) & 0x3F;
        uint64_t bitLen = static_cast<uint64_t>(inputLen) * 8;
        if ((ctx.count[0] += static_cast<uint32_t>(bitLen)) < static_cast<uint32_t>(bitLen))
            ctx.count[1]++;
        ctx.count[1] += static_cast<uint32_t>(static_cast<uint64_t>(inputLen) >> 29);

        size_t partLen = 64 - index;
        if (inputLen >= partLen) {
            memcpy(&ctx.buffer[index], input, partLen);
            Transform(ctx.state, ctx.buffer);
            for (i = partLen; i + 63 < inputLen; i += 64)
                Transform(ctx.state, &input[i]);
            index = 0;
        }
        memcpy(&ctx.buffer[index], &input[i], inputLen - i);
    }

    static void Final(Context& ctx, uint8_t digest[16]) {
        static const uint8_t PADDING[64] = { 0x80 };
        uint8_t bits[8];
        for (int i = 0; i < 4; i++) {
            bits[i] = static_cast<uint8_t>((ctx.count[0] >> (i * 8)) & 0xFF);
            bits[i + 4] = static_cast<uint8_t>((ctx.count[1] >> (i * 8)) & 0xFF);
        }
        uint32_t index = (ctx.count[0] >> 3) & 0x3F;
        uint32_t padLen = (index < 56) ? (56 - index) : (120 - index);
        Update(ctx, PADDING, padLen);
        Update(ctx, bits, 8);
        for (int i = 0; i < 4; i++) {
            digest[i * 4]     = static_cast<uint8_t>((ctx.state[i]) & 0xFF);
            digest[i * 4 + 1] = static_cast<uint8_t>((ctx.state[i] >> 8) & 0xFF);
            digest[i * 4 + 2] = static_cast<uint8_t>((ctx.state[i] >> 16) & 0xFF);
            digest[i * 4 + 3] = static_cast<uint8_t>((ctx.state[i] >> 24) & 0xFF);
        }
    }
} // namespace md5_impl

void Md5(const void* data, size_t size, uint8_t digest[16]) {
    md5_impl::Context ctx;
    md5_impl::Init(ctx);
    if (data && size > 0) {
        md5_impl::Update(ctx, reinterpret_cast<const uint8_t*>(data), size);
    }
    md5_impl::Final(ctx, digest);
}

std::string Md5Hex(const void* data, size_t size) {
    uint8_t digest[16];
    Md5(data, size, digest);
    return ToHex(digest, 16);
}

// ============================================================================
// SHA-1 (FIPS 180-1 - standard DEX signature)
// ============================================================================
namespace sha1_impl {
    struct Context {
        uint32_t state[5];
        uint32_t count[2];
        uint8_t buffer[64];
    };

    static inline uint32_t RotL(uint32_t x, uint32_t n) { return (x << n) | (x >> (32 - n)); }

    static void Transform(uint32_t state[5], const uint8_t buffer[64]) {
        uint32_t a = state[0], b = state[1], c = state[2], d = state[3], e = state[4], w[80];
        for (int t = 0; t < 16; t++) {
            w[t] = (static_cast<uint32_t>(buffer[t * 4]) << 24) |
                   (static_cast<uint32_t>(buffer[t * 4 + 1]) << 16) |
                   (static_cast<uint32_t>(buffer[t * 4 + 2]) << 8) |
                   (static_cast<uint32_t>(buffer[t * 4 + 3]));
        }
        for (int t = 16; t < 80; t++) {
            w[t] = RotL(w[t - 3] ^ w[t - 8] ^ w[t - 14] ^ w[t - 16], 1);
        }

        for (int t = 0; t < 20; t++) {
            uint32_t temp = RotL(a, 5) + ((b & c) | (~b & d)) + e + w[t] + 0x5A827999;
            e = d; d = c; c = RotL(b, 30); b = a; a = temp;
        }
        for (int t = 20; t < 40; t++) {
            uint32_t temp = RotL(a, 5) + (b ^ c ^ d) + e + w[t] + 0x6ED9EBA1;
            e = d; d = c; c = RotL(b, 30); b = a; a = temp;
        }
        for (int t = 40; t < 60; t++) {
            uint32_t temp = RotL(a, 5) + ((b & c) | (b & d) | (c & d)) + e + w[t] + 0x8F1BBCDC;
            e = d; d = c; c = RotL(b, 30); b = a; a = temp;
        }
        for (int t = 60; t < 80; t++) {
            uint32_t temp = RotL(a, 5) + (b ^ c ^ d) + e + w[t] + 0xCA62C1D6;
            e = d; d = c; c = RotL(b, 30); b = a; a = temp;
        }

        state[0] += a; state[1] += b; state[2] += c; state[3] += d; state[4] += e;
    }

    static void Init(Context& ctx) {
        ctx.state[0] = 0x67452301; ctx.state[1] = 0xEFCDAB89;
        ctx.state[2] = 0x98BADCFE; ctx.state[3] = 0x10325476; ctx.state[4] = 0xC3D2E1F0;
        ctx.count[0] = ctx.count[1] = 0;
    }

    static void Update(Context& ctx, const uint8_t* data, size_t len) {
        size_t i = 0, j = (ctx.count[0] >> 3) & 63;
        if ((ctx.count[0] += (static_cast<uint32_t>(len) << 3)) < (static_cast<uint32_t>(len) << 3))
            ctx.count[1]++;
        ctx.count[1] += static_cast<uint32_t>(len >> 29);

        if ((j + len) > 63) {
            memcpy(&ctx.buffer[j], data, (i = 64 - j));
            Transform(ctx.state, ctx.buffer);
            for (; i + 63 < len; i += 64) Transform(ctx.state, &data[i]);
            j = 0;
        }
        memcpy(&ctx.buffer[j], &data[i], len - i);
    }

    static void Final(Context& ctx, uint8_t digest[20]) {
        uint8_t finalcount[8];
        for (int i = 0; i < 8; i++) {
            finalcount[i] = static_cast<uint8_t>((ctx.count[(i >= 4 ? 0 : 1)] >> ((3 - (i & 3)) * 8)) & 255);
        }
        uint8_t c = 0x80;
        Update(ctx, &c, 1);
        while ((ctx.count[0] & 504) != 448) {
            c = 0x00;
            Update(ctx, &c, 1);
        }
        Update(ctx, finalcount, 8);
        for (int i = 0; i < 20; i++) {
            digest[i] = static_cast<uint8_t>((ctx.state[i >> 2] >> ((3 - (i & 3)) * 8)) & 255);
        }
    }
} // namespace sha1_impl

void Sha1(const void* data, size_t size, uint8_t digest[20]) {
    sha1_impl::Context ctx;
    sha1_impl::Init(ctx);
    if (data && size > 0) {
        sha1_impl::Update(ctx, reinterpret_cast<const uint8_t*>(data), size);
    }
    sha1_impl::Final(ctx, digest);
}

std::string Sha1Hex(const void* data, size_t size) {
    uint8_t digest[20];
    Sha1(data, size, digest);
    return ToHex(digest, 20);
}

// ============================================================================
// SHA-256 (FIPS 180-2)
// ============================================================================
namespace sha256_impl {
    struct Context {
        uint32_t state[8];
        uint64_t count;
        uint8_t buffer[64];
    };

    static inline uint32_t RotR(uint32_t x, uint32_t n) { return (x >> n) | (x << (32 - n)); }
    static inline uint32_t Ch(uint32_t x, uint32_t y, uint32_t z) { return (x & y) ^ (~x & z); }
    static inline uint32_t Maj(uint32_t x, uint32_t y, uint32_t z) { return (x & y) ^ (x & z) ^ (y & z); }
    static inline uint32_t Sigma0(uint32_t x) { return RotR(x, 2) ^ RotR(x, 13) ^ RotR(x, 22); }
    static inline uint32_t Sigma1(uint32_t x) { return RotR(x, 6) ^ RotR(x, 11) ^ RotR(x, 25); }
    static inline uint32_t Gamma0(uint32_t x) { return RotR(x, 7) ^ RotR(x, 18) ^ (x >> 3); }
    static inline uint32_t Gamma1(uint32_t x) { return RotR(x, 17) ^ RotR(x, 19) ^ (x >> 10); }

    static const uint32_t K[64] = {
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    };

    static void Transform(uint32_t state[8], const uint8_t buffer[64]) {
        uint32_t a = state[0], b = state[1], c = state[2], d = state[3];
        uint32_t e = state[4], f = state[5], g = state[6], h = state[7];
        uint32_t w[64];

        for (int i = 0; i < 16; i++) {
            w[i] = (static_cast<uint32_t>(buffer[i * 4]) << 24) |
                   (static_cast<uint32_t>(buffer[i * 4 + 1]) << 16) |
                   (static_cast<uint32_t>(buffer[i * 4 + 2]) << 8) |
                   (static_cast<uint32_t>(buffer[i * 4 + 3]));
        }
        for (int i = 16; i < 64; i++) {
            w[i] = Gamma1(w[i - 2]) + w[i - 7] + Gamma0(w[i - 15]) + w[i - 16];
        }

        for (int i = 0; i < 64; i++) {
            uint32_t t1 = h + Sigma1(e) + Ch(e, f, g) + K[i] + w[i];
            uint32_t t2 = Sigma0(a) + Maj(a, b, c);
            h = g; g = f; f = e; e = d + t1;
            d = c; c = b; b = a; a = t1 + t2;
        }

        state[0] += a; state[1] += b; state[2] += c; state[3] += d;
        state[4] += e; state[5] += f; state[6] += g; state[7] += h;
    }

    static void Init(Context& ctx) {
        ctx.state[0] = 0x6a09e667; ctx.state[1] = 0xbb67ae85;
        ctx.state[2] = 0x3c6ef372; ctx.state[3] = 0xa54ff53a;
        ctx.state[4] = 0x510e527f; ctx.state[5] = 0x9b05688c;
        ctx.state[6] = 0x1f83d9ab; ctx.state[7] = 0x5be0cd19;
        ctx.count = 0;
    }

    static void Update(Context& ctx, const uint8_t* data, size_t len) {
        size_t index = static_cast<size_t>(ctx.count & 63);
        ctx.count += len;
        size_t left = len;
        size_t offset = 0;

        if (index > 0) {
            size_t take = std::min(left, static_cast<size_t>(64 - index));
            memcpy(&ctx.buffer[index], &data[offset], take);
            index += take;
            offset += take;
            left -= take;
            if (index == 64) {
                Transform(ctx.state, ctx.buffer);
                index = 0;
            }
        }
        while (left >= 64) {
            Transform(ctx.state, &data[offset]);
            offset += 64;
            left -= 64;
        }
        if (left > 0) {
            memcpy(ctx.buffer, &data[offset], left);
        }
    }

    static void Final(Context& ctx, uint8_t digest[32]) {
        uint64_t totalBits = ctx.count * 8;
        uint8_t pad = 0x80;
        Update(ctx, &pad, 1);
        uint8_t zero = 0x00;
        while ((ctx.count & 63) != 56) {
            Update(ctx, &zero, 1);
        }
        uint8_t bits[8];
        for (int i = 0; i < 8; i++) {
            bits[i] = static_cast<uint8_t>((totalBits >> ((7 - i) * 8)) & 0xFF);
        }
        Update(ctx, bits, 8);
        for (int i = 0; i < 8; i++) {
            digest[i * 4]     = static_cast<uint8_t>((ctx.state[i] >> 24) & 0xFF);
            digest[i * 4 + 1] = static_cast<uint8_t>((ctx.state[i] >> 16) & 0xFF);
            digest[i * 4 + 2] = static_cast<uint8_t>((ctx.state[i] >> 8) & 0xFF);
            digest[i * 4 + 3] = static_cast<uint8_t>((ctx.state[i]) & 0xFF);
        }
    }
} // namespace sha256_impl

void Sha256(const void* data, size_t size, uint8_t digest[32]) {
    sha256_impl::Context ctx;
    sha256_impl::Init(ctx);
    if (data && size > 0) {
        sha256_impl::Update(ctx, reinterpret_cast<const uint8_t*>(data), size);
    }
    sha256_impl::Final(ctx, digest);
}

std::string Sha256Hex(const void* data, size_t size) {
    uint8_t digest[32];
    Sha256(data, size, digest);
    return ToHex(digest, 32);
}

// ============================================================================
// Unified Dispatch Helpers
// ============================================================================
std::string ComputeHex(Algorithm algo, const void* data, size_t size) {
    char buf[32];
    switch (algo) {
        case Algorithm::CRC32:
            snprintf(buf, sizeof(buf), "0x%08x", Crc32(data, size));
            return buf;
        case Algorithm::CRC32C:
            snprintf(buf, sizeof(buf), "0x%08x", Crc32c(data, size));
            return buf;
        case Algorithm::ADLER32:
            snprintf(buf, sizeof(buf), "0x%08x", Adler32(data, size));
            return buf;
        case Algorithm::MD5:
            return Md5Hex(data, size);
        case Algorithm::SHA1:
            return Sha1Hex(data, size);
        case Algorithm::SHA256:
            return Sha256Hex(data, size);
        default:
            return "";
    }
}

std::string ComputeHex(const std::string& algoName, const void* data, size_t size) {
    std::string s = algoName;
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
    });
    if (s == "crc32" || s == "crc") return ComputeHex(Algorithm::CRC32, data, size);
    if (s == "crc32c") return ComputeHex(Algorithm::CRC32C, data, size);
    if (s == "adler32" || s == "adler") return ComputeHex(Algorithm::ADLER32, data, size);
    if (s == "md5") return ComputeHex(Algorithm::MD5, data, size);
    if (s == "sha1" || s == "sha-1") return ComputeHex(Algorithm::SHA1, data, size);
    if (s == "sha256" || s == "sha-256") return ComputeHex(Algorithm::SHA256, data, size);
    return "";
}

}} // namespace PI::Hash
