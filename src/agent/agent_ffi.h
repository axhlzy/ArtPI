//
// agent_ffi.h - Direct integration with Frida-Gum's bundled libffi
//
#pragma once

#include <cstdint>
#include <cstddef>
#include <vector>
#include <string>

extern "C" {

typedef struct _frida_ffi_type {
    size_t size;
    unsigned short alignment;
    unsigned short type;
    struct _frida_ffi_type **elements;
} frida_ffi_type;

typedef enum {
    FRIDA_FFI_OK = 0,
    FRIDA_FFI_BAD_TYPEDEF,
    FRIDA_FFI_BAD_ABI
} frida_ffi_status;

typedef enum {
    FRIDA_FFI_FIRST_ABI = 0,
    FRIDA_FFI_SYSV = 1,
    FRIDA_FFI_DEFAULT_ABI = FRIDA_FFI_SYSV,
} frida_ffi_abi;

// Struct layout with generous padding for architecture-specific fields (e.g. AArch64)
typedef struct {
    frida_ffi_abi abi;
    unsigned nargs;
    frida_ffi_type **arg_types;
    frida_ffi_type *rtype;
    unsigned bytes;
    unsigned flags;
    unsigned extra[16];
} frida_ffi_cif;

// Exported symbols inside libfrida-gum.a
extern frida_ffi_type _frida_ffi_type_void;
extern frida_ffi_type _frida_ffi_type_uint8;
extern frida_ffi_type _frida_ffi_type_sint8;
extern frida_ffi_type _frida_ffi_type_uint16;
extern frida_ffi_type _frida_ffi_type_sint16;
extern frida_ffi_type _frida_ffi_type_uint32;
extern frida_ffi_type _frida_ffi_type_sint32;
extern frida_ffi_type _frida_ffi_type_uint64;
extern frida_ffi_type _frida_ffi_type_sint64;
extern frida_ffi_type _frida_ffi_type_float;
extern frida_ffi_type _frida_ffi_type_double;
extern frida_ffi_type _frida_ffi_type_pointer;

frida_ffi_status _frida_ffi_prep_cif(frida_ffi_cif *cif, frida_ffi_abi abi, unsigned int nargs,
                                     frida_ffi_type *rtype, frida_ffi_type **atypes);
void _frida_ffi_call(frida_ffi_cif *cif, void (*fn)(void), void *rvalue, void **avalue);

} // extern "C"

namespace artpi { namespace agent {

inline frida_ffi_type* FfiResolveType(const std::string& name) {
    if (name == "void") return &_frida_ffi_type_void;
    if (name == "pointer" || name == "ptr" || name == "string" || name == "str") return &_frida_ffi_type_pointer;
    if (name == "int" || name == "int32" || name == "sint32") return &_frida_ffi_type_sint32;
    if (name == "uint" || name == "uint32") return &_frida_ffi_type_uint32;
    if (name == "int64" || name == "sint64" || name == "long") return &_frida_ffi_type_sint64;
    if (name == "uint64" || name == "ulong" || name == "size_t") return &_frida_ffi_type_uint64;
    if (name == "float") return &_frida_ffi_type_float;
    if (name == "double") return &_frida_ffi_type_double;
    if (name == "bool" || name == "boolean" || name == "uint8") return &_frida_ffi_type_uint8;
    if (name == "int8" || name == "sint8") return &_frida_ffi_type_sint8;
    if (name == "int16" || name == "sint16") return &_frida_ffi_type_sint16;
    if (name == "uint16") return &_frida_ffi_type_uint16;
    return &_frida_ffi_type_pointer;
}

}} // namespace artpi::agent
