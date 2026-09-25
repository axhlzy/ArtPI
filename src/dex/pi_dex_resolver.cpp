//
// pi_dex_resolver.cpp - DEX file index resolver implementation
//

#include "pi_dex_resolver.h"
#include "art/art_method.h"
#include <cstring>

namespace PI {

// ============================================================================
// ULEB128 decoder
// ============================================================================
uint32_t DexResolver::decodeULEB128(const uint8_t** ptr) {
    uint32_t result = 0;
    int shift = 0;
    const uint8_t* p = *ptr;
    do {
        uint8_t byte = *p++;
        result |= static_cast<uint32_t>(byte & 0x7F) << shift;
        if ((byte & 0x80) == 0) break;
        shift += 7;
    } while (shift < 35);
    *ptr = p;
    return result;
}

// ============================================================================
// Initialization
// ============================================================================
bool DexResolver::init(const void* art_dex_file) {
    if (!art_dex_file) {
        PI_LOGE("DexResolver::init: art_dex_file is null");
        return false;
    }

    art_dex_file_ = art_dex_file;

    // art::DexFile C++ object layout (same as pi_smali.cpp):
    //   offset 0x08: begin_     (const uint8_t*)
    //   offset 0x10: size_      (size_t)
    //   offset 0x18: data_begin_ (const uint8_t*)
    const auto* obj = static_cast<const uint8_t*>(art_dex_file);
    dex_begin_      = *reinterpret_cast<const uint8_t* const*>(obj + 0x08);
    dex_size_       = *reinterpret_cast<const size_t*>(obj + 0x10);
    dex_data_begin_ = *reinterpret_cast<const uint8_t* const*>(obj + 0x18);

    if (!dex_begin_) {
        PI_LOGE("DexResolver::init: dex_begin is null");
        return false;
    }

    // Detect CompactDex
    is_compact_ = (std::memcmp(dex_begin_, "cdex", 4) == 0);

    // For CompactDex, if data_begin is null, fall back to dex_begin
    if (is_compact_ && !dex_data_begin_) {
        PI_LOGW("DexResolver::init: CompactDex but data_begin is null, using dex_begin");
        dex_data_begin_ = dex_begin_;
    }

    // Read dex_size from header if it's zero in the DexFile object
    if (dex_size_ == 0) {
        const uint8_t* hdr_base = dex_data_begin_ ? dex_data_begin_ : dex_begin_;
        if (std::memcmp(hdr_base, "dex\n", 4) == 0 || std::memcmp(hdr_base, "cdex", 4) == 0) {
            dex_size_ = *reinterpret_cast<const uint32_t*>(hdr_base + 0x20);
        }
    }

    // Parse header (always at dex_begin)
    header_ = reinterpret_cast<const DexFileHeader*>(dex_begin_);

    // Set up ID table pointers (offsets in header are always relative to dex_begin)
    if (header_->string_ids_off && header_->string_ids_size)
        string_ids_ = reinterpret_cast<const DexStringId*>(dex_begin_ + header_->string_ids_off);
    if (header_->type_ids_off && header_->type_ids_size)
        type_ids_ = reinterpret_cast<const DexTypeId*>(dex_begin_ + header_->type_ids_off);
    if (header_->proto_ids_off && header_->proto_ids_size)
        proto_ids_ = reinterpret_cast<const DexProtoId*>(dex_begin_ + header_->proto_ids_off);
    if (header_->field_ids_off && header_->field_ids_size)
        field_ids_ = reinterpret_cast<const DexFieldId*>(dex_begin_ + header_->field_ids_off);
    if (header_->method_ids_off && header_->method_ids_size)
        method_ids_ = reinterpret_cast<const DexMethodId*>(dex_begin_ + header_->method_ids_off);

    PI_LOGI("DexResolver::init: %s | strings=%u types=%u protos=%u fields=%u methods=%u",
            is_compact_ ? "CompactDex" : "StandardDex",
            header_->string_ids_size, header_->type_ids_size,
            header_->proto_ids_size, header_->field_ids_size,
            header_->method_ids_size);

    return true;
}

bool DexResolver::initFromMethod(ArtMethod* method) {
    if (!method) return false;

    // ArtMethod → DeclaringClass (compressed ref, uint32_t at offset 0)
    uint32_t klass_ref = method->GetDeclaringClass();
    if (!klass_ref) {
        PI_LOGE("DexResolver::initFromMethod: declaring class is null");
        return false;
    }
    auto* klass = reinterpret_cast<const uint8_t*>(static_cast<uintptr_t>(klass_ref));

    // Class → DexCache (compressed ref at offset 0x10)
    uint32_t dex_cache_ref = *reinterpret_cast<const uint32_t*>(klass + 0x10);
    if (!dex_cache_ref) {
        PI_LOGE("DexResolver::initFromMethod: dex_cache is null");
        return false;
    }
    auto* dex_cache = reinterpret_cast<const uint8_t*>(static_cast<uintptr_t>(dex_cache_ref));

    // DexCache → DexFile* (pointer at offset 0x10)
    const void* dex_file = *reinterpret_cast<const void* const*>(dex_cache + 0x10);
    if (!dex_file) {
        PI_LOGE("DexResolver::initFromMethod: dex_file is null");
        return false;
    }

    return init(dex_file);
}

// ============================================================================
// String resolution
// ============================================================================
const char* DexResolver::resolveString(uint32_t string_idx) const {
    if (!string_ids_ || string_idx >= header_->string_ids_size) return nullptr;

    uint32_t data_off = string_ids_[string_idx].string_data_off;

    // String data offset is relative to dataBegin()
    const uint8_t* ptr = dataBegin() + data_off;

    // Skip ULEB128-encoded UTF-16 length
    decodeULEB128(&ptr);

    // ptr now points to MUTF-8 null-terminated string data
    return reinterpret_cast<const char*>(ptr);
}

// ============================================================================
// Type resolution
// ============================================================================
const char* DexResolver::typeUtf(uint32_t type_idx) const {
    if (!type_ids_ || type_idx >= header_->type_ids_size) return nullptr;
    uint32_t descriptor_idx = type_ids_[type_idx].descriptor_idx;
    return resolveString(descriptor_idx);  // direct pointer into dex image
}

uint32_t DexResolver::methodClassIdx(uint32_t method_idx) const {
    if (!method_ids_ || method_idx >= header_->method_ids_size) return 0;
    return method_ids_[method_idx].class_idx;
}

uint32_t DexResolver::fieldClassIdx(uint32_t field_idx) const {
    if (!field_ids_ || field_idx >= header_->field_ids_size) return 0;
    return field_ids_[field_idx].class_idx;
}

const char* DexResolver::methodShorty(uint32_t method_idx) const {
    if (!method_ids_ || method_idx >= header_->method_ids_size) return nullptr;
    uint32_t proto_idx = method_ids_[method_idx].proto_idx;
    if (!proto_ids_ || proto_idx >= header_->proto_ids_size) return nullptr;
    return resolveString(proto_ids_[proto_idx].shorty_idx);
}

std::string DexResolver::resolveType(uint32_t type_idx) const {
    if (!type_ids_ || type_idx >= header_->type_ids_size) return "";

    uint32_t descriptor_idx = type_ids_[type_idx].descriptor_idx;
    const char* str = resolveString(descriptor_idx);
    return str ? str : "";
}

// ============================================================================
// Proto resolution
// ============================================================================
std::vector<std::string> DexResolver::resolveProtoParams(uint32_t proto_idx) const {
    std::vector<std::string> params;
    if (!proto_ids_ || proto_idx >= header_->proto_ids_size) return params;

    uint32_t params_off = proto_ids_[proto_idx].parameters_off;
    if (params_off == 0) return params;  // No parameters

    // type_list is at dataBegin() + params_off
    const auto* type_list = reinterpret_cast<const DexTypeList*>(dataBegin() + params_off);
    const auto* type_items = reinterpret_cast<const uint16_t*>(
        reinterpret_cast<const uint8_t*>(type_list) + sizeof(uint32_t));

    for (uint32_t i = 0; i < type_list->size; i++) {
        params.push_back(resolveType(type_items[i]));
    }
    return params;
}

std::string DexResolver::resolveProtoSignature(uint32_t proto_idx) const {
    if (!proto_ids_ || proto_idx >= header_->proto_ids_size) return "";

    const auto& proto = proto_ids_[proto_idx];

    // Build "(param_types)return_type"
    std::string sig = "(";
    auto params = resolveProtoParams(proto_idx);
    for (const auto& p : params) {
        sig += p;
    }
    sig += ")";
    sig += resolveType(proto.return_type_idx);

    return sig;
}

// ============================================================================
// Method resolution
// ============================================================================
MethodRef DexResolver::resolveMethod(uint32_t method_idx) const {
    MethodRef ref;
    if (!method_ids_ || method_idx >= header_->method_ids_size) return ref;

    const auto& method = method_ids_[method_idx];
    ref.class_descriptor = resolveType(method.class_idx);
    const char* name = resolveString(method.name_idx);
    ref.name = name ? name : "";

    if (proto_ids_ && method.proto_idx < header_->proto_ids_size) {
        const auto& proto = proto_ids_[method.proto_idx];
        const char* shorty = resolveString(proto.shorty_idx);
        ref.shorty = shorty ? shorty : "";
        ref.return_type = resolveType(proto.return_type_idx);
        ref.param_types = resolveProtoParams(method.proto_idx);
        ref.jni_signature = resolveProtoSignature(method.proto_idx);
    }

    return ref;
}

// ============================================================================
// Field resolution
// ============================================================================
FieldRef DexResolver::resolveField(uint32_t field_idx) const {
    FieldRef ref;
    if (!field_ids_ || field_idx >= header_->field_ids_size) return ref;

    const auto& field = field_ids_[field_idx];
    ref.class_descriptor = resolveType(field.class_idx);
    ref.type = resolveType(field.type_idx);
    const char* name = resolveString(field.name_idx);
    ref.name = name ? name : "";

    return ref;
}

} // namespace PI
