//
// pi_dex_resolver.h - DEX file index resolver (DexCache/DexFile based)
//
// Resolves DEX indices (method_idx, field_idx, type_idx, string_idx) into
// human-readable names and JNI-compatible descriptors. Supports both
// StandardDex and CompactDex (Android 10+) formats.
//

#ifndef PI_DEX_RESOLVER_H
#define PI_DEX_RESOLVER_H

#include "pi_common.h"
#include <cstdint>
#include <string>
#include <vector>

namespace PI {

// Resolved method reference
struct MethodRef {
    std::string class_descriptor;    // e.g. "Ljava/lang/String;"
    std::string name;                // e.g. "substring"
    std::string return_type;         // e.g. "Ljava/lang/String;"
    std::string shorty;              // e.g. "LII"
    std::vector<std::string> param_types; // e.g. {"I", "I"}
    std::string jni_signature;       // e.g. "(II)Ljava/lang/String;"

    bool isValid() const { return !name.empty(); }
};

// Resolved field reference
struct FieldRef {
    std::string class_descriptor;    // e.g. "Ljava/lang/String;"
    std::string name;                // e.g. "value"
    std::string type;                // e.g. "[C"

    bool isValid() const { return !name.empty(); }
};

// DEX file binary format structures (same layout for Standard and CompactDex headers)
struct DexFileHeader {
    uint8_t  magic[8];          // 0x00: "dex\n035\0" or "cdex001\0"
    uint32_t checksum;          // 0x08
    uint8_t  signature[20];     // 0x0C
    uint32_t file_size;         // 0x20
    uint32_t header_size;       // 0x24
    uint32_t endian_tag;        // 0x28
    uint32_t link_size;         // 0x2C
    uint32_t link_off;          // 0x30
    uint32_t map_off;           // 0x34
    uint32_t string_ids_size;   // 0x38
    uint32_t string_ids_off;    // 0x3C
    uint32_t type_ids_size;     // 0x40
    uint32_t type_ids_off;      // 0x44
    uint32_t proto_ids_size;    // 0x48
    uint32_t proto_ids_off;     // 0x4C
    uint32_t field_ids_size;    // 0x50
    uint32_t field_ids_off;     // 0x54
    uint32_t method_ids_size;   // 0x58
    uint32_t method_ids_off;    // 0x5C
    uint32_t class_defs_size;   // 0x60
    uint32_t class_defs_off;    // 0x64
    uint32_t data_size;         // 0x68
    uint32_t data_off;          // 0x6C
};

// DEX ID table entry formats
struct DexStringId   { uint32_t string_data_off; };
struct DexTypeId     { uint32_t descriptor_idx; };
struct DexProtoId    { uint32_t shorty_idx; uint32_t return_type_idx; uint32_t parameters_off; };
struct DexFieldId    { uint16_t class_idx; uint16_t type_idx; uint32_t name_idx; };
struct DexMethodId   { uint16_t class_idx; uint16_t proto_idx; uint32_t name_idx; };
struct DexTypeList   { uint32_t size; /* followed by size * uint16_t type_idx entries */ };

/**
 * DexResolver: Parses DEX file structures to resolve indices.
 *
 * Initialized from the art::DexFile* pointer obtained via:
 *   ArtMethod → DeclaringClass → DexCache → DexFile*
 *
 * All pointer offsets follow the layout used in pi_smali.cpp.
 */
class DexResolver {
public:
    DexResolver() = default;

    // Initialize from the art::DexFile* C++ object pointer
    bool init(const void* art_dex_file);

    // Initialize from an ArtMethod* (traverses Class→DexCache→DexFile)
    bool initFromMethod(ArtMethod* method);

    bool isValid() const { return dex_begin_ != nullptr && header_ != nullptr; }
    bool isCompactDex() const { return is_compact_; }

    // Raw header access (for consumers that need id-table sizes)
    const DexFileHeader* header() const { return header_; }

    // Zero-copy type descriptor: returns a NUL-terminated pointer that lives
    // inside the dex image (MUTF-8). nullptr on invalid type_idx.
    const char* typeUtf(uint32_t type_idx) const;

    // Raw class_idx of a method/field reference (needed by the interpreter:
    // invoke-direct re-resolves the declaring class via vmMethod.classIdx,
    // sget/sput via vmField.classIdx).
    uint32_t methodClassIdx(uint32_t method_idx) const;
    uint32_t fieldClassIdx(uint32_t field_idx) const;

    // Zero-copy proto shorty ("JDD" etc.: return char + param chars,
    // receiver NOT included). nullptr on invalid method_idx.
    const char* methodShorty(uint32_t method_idx) const;

    // === Index resolution ===
    const char* resolveString(uint32_t string_idx) const;
    std::string resolveType(uint32_t type_idx) const;
    MethodRef   resolveMethod(uint32_t method_idx) const;
    FieldRef    resolveField(uint32_t field_idx) const;

    // Build JNI-style method signature from proto_idx: "(param_types)return_type"
    std::string resolveProtoSignature(uint32_t proto_idx) const;

    // Get the raw DexFile pointer
    const void* getDexFile() const { return art_dex_file_; }

private:
    // Decode ULEB128 value at *ptr, advancing *ptr past the encoding
    static uint32_t decodeULEB128(const uint8_t** ptr);

    // Get the base pointer for data-relative offsets
    const uint8_t* dataBegin() const { return is_compact_ ? dex_data_begin_ : dex_begin_; }

    // Resolve proto parameters → vector of type descriptors
    std::vector<std::string> resolveProtoParams(uint32_t proto_idx) const;

    const void*    art_dex_file_ = nullptr;   // The art::DexFile C++ object
    const uint8_t* dex_begin_ = nullptr;      // DEX file bytes start
    const uint8_t* dex_data_begin_ = nullptr; // Data section start (CompactDex)
    size_t         dex_size_ = 0;
    bool           is_compact_ = false;

    // Parsed header (points into dex_begin_)
    const DexFileHeader* header_ = nullptr;

    // Pre-computed ID table pointers (all relative to dex_begin_)
    const DexStringId* string_ids_ = nullptr;
    const DexTypeId*   type_ids_   = nullptr;
    const DexProtoId*  proto_ids_  = nullptr;
    const DexFieldId*  field_ids_  = nullptr;
    const DexMethodId* method_ids_ = nullptr;
};

} // namespace PI

#endif // PI_DEX_RESOLVER_H
