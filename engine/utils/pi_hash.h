//
// pi_hash.h - ArtPI Hash & Integrity Suite
// Lightweight, zero-dependency hashing tools:
//   - CRC32 (IEEE 802.3 standard)
//   - CRC32C (Castagnoli)
//   - Adler-32 (DEX header checksum)
//   - MD5 (RFC 1321)
//   - SHA-1 (DEX header signature)
//   - SHA-256 (FIPS 180-2)
//
#ifndef PI_HASH_H
#define PI_HASH_H

#include <cstdint>
#include <cstddef>
#include <string>
#include <vector>

namespace PI { namespace Hash {

enum class Algorithm {
    CRC32,
    CRC32C,
    ADLER32,
    MD5,
    SHA1,
    SHA256
};

// 32-bit checksum calculations
uint32_t Crc32(const void* data, size_t size, uint32_t prev = 0);
uint32_t Crc32c(const void* data, size_t size, uint32_t prev = 0);
uint32_t Adler32(const void* data, size_t size, uint32_t prev = 1);

// Cryptographic / Message digest calculations
void Md5(const void* data, size_t size, uint8_t digest[16]);
std::string Md5Hex(const void* data, size_t size);

void Sha1(const void* data, size_t size, uint8_t digest[20]);
std::string Sha1Hex(const void* data, size_t size);

void Sha256(const void* data, size_t size, uint8_t digest[32]);
std::string Sha256Hex(const void* data, size_t size);

// Unified dispatch helpers
std::string ComputeHex(Algorithm algo, const void* data, size_t size);
std::string ComputeHex(const std::string& algoName, const void* data, size_t size);

// Byte array to hex string
std::string ToHex(const uint8_t* data, size_t size, bool uppercase = false);

}} // namespace PI::Hash

#endif // PI_HASH_H
