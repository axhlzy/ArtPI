//
// pi_dex_gen.h - Runtime DEX generation (Dexter/slicer IR -> standalone .dex)
//
// Builds a *standalone* StandardDex image containing synthesized classes.
// The image is meant to be loaded with dalvik.system.InMemoryDexClassLoader
// (see pi_dex_loader.h).
//

#ifndef PI_DEX_GEN_H
#define PI_DEX_GEN_H

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

namespace PI {

namespace DexWriter {
class Writer;
}

namespace DexGen {

// DEX access flags (dex_format.h subset, kept local to avoid leaking headers)
constexpr uint32_t ACC_PUBLIC       = 0x0001;
constexpr uint32_t ACC_PRIVATE      = 0x0002;
constexpr uint32_t ACC_PROTECTED    = 0x0004;
constexpr uint32_t ACC_STATIC       = 0x0008;
constexpr uint32_t ACC_FINAL        = 0x0010;
constexpr uint32_t ACC_VOLATILE     = 0x0040;
constexpr uint32_t ACC_TRANSIENT    = 0x0080;
constexpr uint32_t ACC_NATIVE       = 0x0100;
constexpr uint32_t ACC_INTERFACE    = 0x0200;
constexpr uint32_t ACC_ABSTRACT     = 0x0400;
constexpr uint32_t ACC_SYNTHETIC    = 0x1000;
constexpr uint32_t ACC_CONSTRUCTOR  = 0x10000;

struct MethodSpec {
    std::string name;           // "onClick" / "<init>"
    std::string signature;      // "(ILjava/lang/String;)V"
    uint32_t    access_flags = ACC_PUBLIC | ACC_NATIVE;
    bool        is_static = false;
    bool        is_constructor = false;

    // If writer is non-null, method is assembled into pure Dalvik bytecode (non-native).
    // Note: writer must contain at least one instruction, otherwise BuildDex fails.
    std::shared_ptr<PI::DexWriter::Writer> writer = nullptr;
};

// Static field with a literal initial value (encoded_array_item static_values).
// `kind` decides which member of the union below is used.
struct FieldSpec {
    enum class Kind { None, Int, Long, Bool, String };

    std::string name;
    std::string type;           // descriptor, e.g. "Ljava/lang/String;" / "I"
    uint32_t    access_flags = ACC_PUBLIC | ACC_STATIC;
    Kind        kind = Kind::None;
    int64_t     long_value = 0;
    bool        bool_value = false;
    std::string string_value;
};

struct ClassSpec {
    std::string name;                                   // "com.foo.Bar" or descriptor
    std::string superclass = "java.lang.Object";        // dotted, slash or descriptor
    std::vector<std::string> interfaces;                // dotted, slash or descriptor
    std::vector<FieldSpec>  fields;
    std::vector<MethodSpec> methods;
};

// Converts "com.foo.Bar" / "com/foo/Bar" / "Lcom/foo/Bar;" / "I" / "[B"
// into a canonical DEX type descriptor.
std::string ToDescriptor(const std::string& type);

// Parses a method signature "(params)ret" into ret descriptor and params descriptor vector.
bool ParseSignature(const std::string& sig,
                    std::string* ret,
                    std::vector<std::string>* params);

// Calculates Dalvik ins words (accounting for 'this' if non-static and 2-word long/double).
uint16_t CalculateInsWords(const std::vector<std::string>& params, bool is_static);

// Validates a DEX method signature: "(" params ")" ret. Returns false on junk.
bool ValidateSignature(const std::string& signature, std::string* error);

// Validates a field/method/class name (DEX "SimpleName" / binary name rules).
bool ValidateIdentifier(const std::string& name, std::string* error);

// Builds a StandardDex image. On success `out_image` holds the complete file.
// Returns false and fills `error` on any problem.
bool BuildDex(const std::vector<ClassSpec>& classes,
              std::vector<uint8_t>* out_image,
              std::string* error);

}  // namespace DexGen
}  // namespace PI

#endif  // PI_DEX_GEN_H
