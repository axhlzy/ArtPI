//
// pi_dex_gen.cpp - Runtime DEX generation via Dexter (slicer) IR
//

#include "pi_dex_gen.h"

#include "pi_common.h"
#include "utils/pi_hash.h"

#include "slicer/buffer.h"
#include "slicer/common.h"
#include "slicer/dex_format.h"
#include "slicer/dex_leb128.h"
#include "slicer/dex_ir.h"
#include "slicer/writer.h"

#include <cstdlib>
#include <cstring>
#include <map>
#include <memory>
#include <set>

namespace PI {
namespace DexGen {

namespace {

using namespace slicer;

// dex\n035\0 -- version 35 keeps the writer on the pre-v41 (container) layout,
// which is what every ART release understands.
constexpr char kDexMagic[8] = {'d', 'e', 'x', '\n', '0', '3', '5', '\0'};

class MallocAllocator : public dex::Writer::Allocator {
public:
    void* Allocate(size_t size) override { return std::malloc(size); }
    void Free(void* ptr) override { std::free(ptr); }
};

// ---------------------------------------------------------------------------
// MUTF-8 (Dalvik "string_data_item" payload)
// ---------------------------------------------------------------------------

// UTF-8 -> UTF-16 code units. Returns false on malformed input.
bool Utf8ToUtf16(const std::string& s, std::vector<uint16_t>* out) {
    out->clear();
    size_t i = 0;
    while (i < s.size()) {
        uint32_t cp = 0;
        uint8_t c = static_cast<uint8_t>(s[i]);
        size_t extra = 0;
        if (c < 0x80) { cp = c; extra = 0; }
        else if ((c & 0xE0) == 0xC0) { cp = c & 0x1F; extra = 1; }
        else if ((c & 0xF0) == 0xE0) { cp = c & 0x0F; extra = 2; }
        else if ((c & 0xF8) == 0xF0) { cp = c & 0x07; extra = 3; }
        else return false;

        if (i + extra >= s.size()) return false;
        for (size_t k = 1; k <= extra; ++k) {
            uint8_t cc = static_cast<uint8_t>(s[i + k]);
            if ((cc & 0xC0) != 0x80) return false;
            cp = (cp << 6) | (cc & 0x3F);
        }
        i += extra + 1;

        if (cp <= 0xFFFF) {
            out->push_back(static_cast<uint16_t>(cp));
        } else if (cp <= 0x10FFFF) {
            cp -= 0x10000;
            out->push_back(static_cast<uint16_t>(0xD800 + (cp >> 10)));
            out->push_back(static_cast<uint16_t>(0xDC00 + (cp & 0x3FF)));
        } else {
            return false;
        }
    }
    return true;
}

void AppendMutf8Unit(uint16_t unit, std::vector<uint8_t>* out) {
    if (unit != 0 && unit <= 0x7F) {
        out->push_back(static_cast<uint8_t>(unit));
    } else if (unit <= 0x7FF) {
        out->push_back(static_cast<uint8_t>(0xC0 | (unit >> 6)));
        out->push_back(static_cast<uint8_t>(0x80 | (unit & 0x3F)));
    } else {
        out->push_back(static_cast<uint8_t>(0xE0 | (unit >> 12)));
        out->push_back(static_cast<uint8_t>(0x80 | ((unit >> 6) & 0x3F)));
        out->push_back(static_cast<uint8_t>(0x80 | (unit & 0x3F)));
    }
}

// ---------------------------------------------------------------------------
// descriptor / signature helpers
// ---------------------------------------------------------------------------

bool IsPrimitiveChar(char c) {
    switch (c) {
        case 'V': case 'Z': case 'B': case 'S':
        case 'C': case 'I': case 'J': case 'F': case 'D':
            return true;
        default:
            return false;
    }
}

// Reads one type descriptor starting at `*i` (advanced past it).
bool ReadDescriptor(const std::string& s, size_t* i, std::string* out) {
    size_t p = *i;
    if (p >= s.size()) return false;

    size_t start = p;
    while (p < s.size() && s[p] == '[') ++p;
    if (p >= s.size()) return false;

    if (IsPrimitiveChar(s[p])) {
        if (p != start) return false;  // "[V" is not a valid type
        ++p;
    } else if (s[p] == 'L') {
        size_t semi = s.find(';', p);
        if (semi == std::string::npos || semi == p + 1) return false;
        p = semi + 1;
    } else {
        return false;
    }

    *out = s.substr(start, p - start);
    *i = p;
    return true;
}

bool ParseSignature(const std::string& sig,
                    std::string* ret,
                    std::vector<std::string>* params) {
    params->clear();
    if (sig.size() < 3 || sig[0] != '(') return false;

    size_t i = 1;
    while (i < sig.size() && sig[i] != ')') {
        std::string t;
        if (!ReadDescriptor(sig, &i, &t)) return false;
        params->push_back(t);
    }
    if (i >= sig.size() || sig[i] != ')') return false;
    ++i;
    if (!ReadDescriptor(sig, &i, ret)) return false;
    return i == sig.size();
}

}  // namespace

std::string ToDescriptor(const std::string& type) {
    if (type.empty()) return type;
    char c = type[0];
    if (c == 'L' && type.back() == ';') return type;   // already a descriptor
    if (c == '[') return type;                          // array descriptor
    if (type.size() == 1 && IsPrimitiveChar(c)) return type;

    std::string slash = type;
    for (char& ch : slash) {
        if (ch == '.') ch = '/';
    }
    return "L" + slash + ";";
}

bool ValidateSignature(const std::string& signature, std::string* error) {
    std::string ret;
    std::vector<std::string> params;
    if (!ParseSignature(signature, &ret, &params)) {
        if (error) *error = "malformed signature: " + signature;
        return false;
    }
    return true;
}

bool ValidateIdentifier(const std::string& name, std::string* error) {
    if (name.empty()) {
        if (error) *error = "empty identifier";
        return false;
    }
    for (unsigned char c : name) {
        bool ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                  (c >= '0' && c <= '9') || c == '_' || c == '$';
        // '<init>' / '<clinit>' are the only legal names containing brackets
        if (!ok) {
            if (name == "<init>" || name == "<clinit>") continue;
            if (error) {
                char buf[96];
                snprintf(buf, sizeof(buf), "illegal character 0x%02x in identifier '%s'",
                         c, name.c_str());
                *error = buf;
            }
            return false;
        }
    }
    return true;
}

namespace {

// ---------------------------------------------------------------------------
// ir::DexFile builder
// ---------------------------------------------------------------------------
class Builder {
public:
    Builder() : ir_(std::make_shared<ir::DexFile>()) {
        ir_->magic = slicer::MemView(kDexMagic, sizeof(kDexMagic));
    }

    ir::String* Str(const std::string& value) {
        auto it = strings_.find(value);
        if (it != strings_.end()) return it->second;

        auto* node = ir_->Alloc<ir::String>();

        // string_data_item: uleb128 utf16_size, MUTF-8 bytes, NUL
        std::vector<uint16_t> units;
        if (!Utf8ToUtf16(value, &units)) {
            // Fall back to a byte-wise copy: identifiers/descriptors are ASCII
            // in practice, and this keeps non-UTF8 input from aborting.
            units.clear();
            for (unsigned char c : value) units.push_back(c);
        }

        slicer::Buffer buf;
        buf.PushULeb128(static_cast<dex::u4>(units.size()));
        for (uint16_t u : units) {
            std::vector<uint8_t> enc;
            AppendMutf8Unit(u, &enc);
            for (uint8_t b : enc) buf.Push<uint8_t>(b);
        }
        buf.Push<uint8_t>(0);

        const uint8_t* data = buf.data();
        size_t size = buf.size();
        ir_->AttachBuffer(std::move(buf));
        node->data = slicer::MemView(data, size);

        strings_[value] = node;
        return node;
    }

    ir::Type* Type(const std::string& raw) {
        const std::string descriptor = ToDescriptor(raw);
        auto it = types_.find(descriptor);
        if (it != types_.end()) return it->second;

        auto* node = ir_->Alloc<ir::Type>();
        node->descriptor = Str(descriptor);
        node->class_def = nullptr;
        types_[descriptor] = node;
        return node;
    }

    ir::Proto* Proto(const std::string& signature) {
        auto it = protos_.find(signature);
        if (it != protos_.end()) return it->second;

        std::string ret;
        std::vector<std::string> params;
        if (!ParseSignature(signature, &ret, &params)) return nullptr;

        auto* proto = ir_->Alloc<ir::Proto>();
        proto->return_type = Type(ret);

        std::string shorty;
        shorty += dex::DescriptorToShorty(ToDescriptor(ret).c_str());
        if (!params.empty()) {
            proto->param_types = ir_->Alloc<ir::TypeList>();
            for (const auto& p : params) {
                std::string d = ToDescriptor(p);
                proto->param_types->types.push_back(Type(d));
                shorty += dex::DescriptorToShorty(d.c_str());
            }
        } else {
            proto->param_types = nullptr;
        }
        proto->shorty = Str(shorty);

        protos_[signature] = proto;
        return proto;
    }

    ir::MethodDecl* MethodDecl(ir::Type* parent,
                               const std::string& name,
                               ir::Proto* proto) {
        const std::string key = std::string(parent->descriptor->c_str()) + "->" +
                                name + proto->Signature();
        auto it = method_decls_.find(key);
        if (it != method_decls_.end()) return it->second;

        auto* decl = ir_->Alloc<ir::MethodDecl>();
        decl->name = Str(name);
        decl->prototype = proto;
        decl->parent = parent;
        method_decls_[key] = decl;
        return decl;
    }

    bool AddClass(const ClassSpec& spec, std::string* error) {
        const std::string desc = ToDescriptor(spec.name);
        if (classes_.count(desc)) {
            if (error) *error = "duplicate class: " + spec.name;
            return false;
        }

        auto* class_type = Type(desc);
        auto* cls = ir_->Alloc<ir::Class>();
        cls->type = class_type;
        cls->type->class_def = cls;
        // ACC_PUBLIC | ACC_SUPER: the standard shape for a plain Java class.
        cls->access_flags = ACC_PUBLIC | 0x0020u;

        const std::string super_desc = ToDescriptor(spec.superclass);
        cls->super_class = (super_desc == desc) ? nullptr : Type(super_desc);

        if (!spec.interfaces.empty()) {
            cls->interfaces = ir_->Alloc<ir::TypeList>();
            for (const auto& iface : spec.interfaces) {
                const std::string d = ToDescriptor(iface);
                if (d == desc) {
                    if (error) *error = "class implements itself: " + spec.name;
                    return false;
                }
                cls->interfaces->types.push_back(Type(d));
            }
        } else {
            cls->interfaces = nullptr;
        }

        cls->source_file = nullptr;
        cls->annotations = nullptr;
        cls->static_init = nullptr;

        for (const auto& f : spec.fields) {
            if (!ValidateIdentifier(f.name, error)) return false;
            auto* decl = ir_->Alloc<ir::FieldDecl>();
            decl->name = Str(f.name);
            decl->type = Type(f.type);
            decl->parent = class_type;

            // Pre-register every string the static_values may reference BEFORE
            // the first Normalize(): adding new strings afterwards would shift
            // string indexes and could reorder static_fields, desynchronizing
            // the encoded_array_item from class_data.
            if (f.kind == FieldSpec::Kind::String) Str(f.string_value);

            auto* encoded = ir_->Alloc<ir::EncodedField>();
            encoded->decl = decl;
            encoded->access_flags = f.access_flags;

            if (f.access_flags & ACC_STATIC) {
                cls->static_fields.push_back(encoded);
            } else {
                cls->instance_fields.push_back(encoded);
            }
            field_specs_[desc + "#" + f.name] = &f;
        }

        for (const auto& m : spec.methods) {
            if (!ValidateIdentifier(m.name, error)) return false;

            ir::Proto* proto = Proto(m.signature);
            if (proto == nullptr) {
                if (error) *error = "malformed signature for " + m.name + ": " + m.signature;
                return false;
            }

            auto* decl = MethodDecl(class_type, m.name, proto);
            auto* encoded = ir_->Alloc<ir::EncodedMethod>();
            encoded->decl = decl;
            encoded->code = nullptr;  // native method: no code_item
            encoded->access_flags = m.access_flags | ACC_NATIVE;

            const bool is_direct = m.is_static || m.is_constructor ||
                                   (m.access_flags & ACC_PRIVATE) != 0;
            if (is_direct) {
                cls->direct_methods.push_back(encoded);
            } else {
                cls->virtual_methods.push_back(encoded);
            }
        }

        classes_[desc] = cls;
        return true;
    }

    std::shared_ptr<ir::DexFile> Finish(std::string* error) {
        // First pass: assign stable indexes so we can emit static_values in the
        // exact order the writer will use (static_fields is sorted by index).
        ir_->Normalize();
        BuildStaticInits(error);
        return ir_;
    }

private:
    ir::EncodedValue* ValueFor(const FieldSpec& f) {
        auto* v = ir_->Alloc<ir::EncodedValue>();
        if (f.kind == FieldSpec::Kind::String) {
            v->type = dex::kEncodedString;
            v->u.string_value = Str(f.string_value);
            return v;
        }

        const std::string d = ToDescriptor(f.type);
        const char c = d.empty() ? 'I' : d[0];

        switch (f.kind) {
            case FieldSpec::Kind::Bool:
                v->type = dex::kEncodedBoolean;
                v->u.bool_value = f.bool_value;
                return v;
            case FieldSpec::Kind::Long:
                if (c == 'J') {
                    v->type = dex::kEncodedLong;
                    v->u.long_value = f.long_value;
                } else {
                    v->type = dex::kEncodedInt;
                    v->u.int_value = static_cast<int32_t>(f.long_value);
                }
                return v;
            case FieldSpec::Kind::Int:
                if (c == 'J') {
                    v->type = dex::kEncodedLong;
                    v->u.long_value = f.long_value;
                } else {
                    v->type = dex::kEncodedInt;
                    v->u.int_value = static_cast<int32_t>(f.long_value);
                }
                return v;
            case FieldSpec::Kind::None:
            default:
                break;
        }

        // No explicit value: emit the zero of the declared type.
        switch (c) {
            case 'L':
            case '[':
                v->type = dex::kEncodedNull;
                break;
            case 'J':
                v->type = dex::kEncodedLong;
                v->u.long_value = 0;
                break;
            case 'Z':
                v->type = dex::kEncodedBoolean;
                v->u.bool_value = false;
                break;
            default:
                v->type = dex::kEncodedInt;
                v->u.int_value = 0;
                break;
        }
        return v;
    }

    void BuildStaticInits(std::string* error) {
        for (auto& entry : classes_) {
            ir::Class* cls = entry.second;
            if (cls->static_fields.empty()) continue;

            auto* array = ir_->Alloc<ir::EncodedArray>();
            for (ir::EncodedField* field : cls->static_fields) {
                const std::string key =
                    entry.first + "#" + field->decl->name->c_str();
                auto it = field_specs_.find(key);
                if (it == field_specs_.end()) {
                    if (error) *error = "internal: missing field spec " + key;
                    continue;
                }
                array->values.push_back(ValueFor(*it->second));
            }
            cls->static_init = array;
        }
    }

    std::shared_ptr<ir::DexFile> ir_;
    std::map<std::string, ir::String*> strings_;
    std::map<std::string, ir::Type*> types_;
    std::map<std::string, ir::Proto*> protos_;
    std::map<std::string, ir::MethodDecl*> method_decls_;
    std::map<std::string, ir::Class*> classes_;
    std::map<std::string, const FieldSpec*> field_specs_;
};

}  // namespace

bool BuildDex(const std::vector<ClassSpec>& classes,
              std::vector<uint8_t>* out_image,
              std::string* error) {
    if (out_image == nullptr) return false;
    out_image->clear();
    if (classes.empty()) {
        if (error) *error = "no classes to generate";
        return false;
    }

    Builder builder;
    std::set<std::string> seen;
    for (const auto& spec : classes) {
        const std::string desc = ToDescriptor(spec.name);
        if (!seen.insert(desc).second) {
            if (error) *error = "duplicate class: " + spec.name;
            return false;
        }
        if (desc.size() < 3 || desc[0] != 'L' || desc.back() != ';') {
            if (error) *error = "invalid class name: " + spec.name;
            return false;
        }
        if (!builder.AddClass(spec, error)) return false;
    }

    auto ir = builder.Finish(error);
    if (ir == nullptr) {
        if (error) *error = "IR build failed";
        return false;
    }

    MallocAllocator allocator;
    dex::u1* image = nullptr;
    size_t image_size = 0;
    {
        dex::Writer writer(ir);
        image = writer.CreateImage(&allocator, &image_size);
    }
    if (image == nullptr || image_size < 0x70) {
        if (error) *error = "dex writer failed";
        return false;
    }

    // header.signature = SHA-1 over [32, file_size)
    uint8_t digest[20];
    PI::Hash::Sha1(image + 32, image_size - 32, digest);
    std::memcpy(image + 12, digest, sizeof(digest));

    // header.checksum = adler32 over [12, file_size)
    auto* header = reinterpret_cast<dex::Header*>(image);
    header->checksum = dex::ComputeChecksum(header);

    out_image->assign(image, image + image_size);
    allocator.Free(image);
    return true;
}

}  // namespace DexGen
}  // namespace PI
