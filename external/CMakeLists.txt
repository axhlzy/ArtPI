cmake_minimum_required(VERSION 3.10)
project(artpi_external LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

# ==============================================================================
# 1. xdl (eXtended Dynamic Linker)
# ==============================================================================
set(XDL_SOURCES
    xdl/xdl.c
    xdl/xdl_iterate.c
    xdl/xdl_linker.c
    xdl/xdl_lzma.c
    xdl/xdl_util.c
)
add_library(artpi_xdl STATIC ${XDL_SOURCES})
set_source_files_properties(${XDL_SOURCES} PROPERTIES COMPILE_FLAGS "-w")
target_include_directories(artpi_xdl PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/xdl/include
    ${CMAKE_CURRENT_SOURCE_DIR}/xdl
)

# ==============================================================================
# 2. xz-embedded (Lightweight LZMA2 decompressor for payloads)
# ==============================================================================
set(XZ_SOURCES
    xz-embedded/linux/lib/xz/xz_crc32.c
    xz-embedded/linux/lib/xz/xz_crc64.c
    xz-embedded/linux/lib/xz/xz_dec_stream.c
    xz-embedded/linux/lib/xz/xz_dec_lzma2.c
    xz-embedded/linux/lib/xz/xz_dec_bcj.c
)
add_library(artpi_xz STATIC ${XZ_SOURCES})
set_source_files_properties(${XZ_SOURCES} PROPERTIES
    COMPILE_FLAGS "-DXZ_USE_CRC64 -DXZ_DEC_ANY_CHECK -DXZ_DEC_CONCATENATED -DXZ_DEC_ARM64 -DXZ_DEC_X86 -DXZ_DEC_ARM -w"
)
target_include_directories(artpi_xz PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/xz-embedded/linux/include/linux
    ${CMAKE_CURRENT_SOURCE_DIR}/xz-embedded/userspace
)

# CLI alias for backwards compatibility
add_library(artpi_xz_cli ALIAS artpi_xz)

# ==============================================================================
# 3. KittyMemory (In-memory scanner, patcher, and map utility)
# ==============================================================================
set(KITTY_SOURCES
    KittyMemory/KittyArm64.cpp
    KittyMemory/KittyMemory.cpp
    KittyMemory/KittyScanner.cpp
    KittyMemory/KittyUtils.cpp
    KittyMemory/MemoryBackup.cpp
    KittyMemory/MemoryPatch.cpp
)
add_library(artpi_kittymemory STATIC ${KITTY_SOURCES})
set_source_files_properties(${KITTY_SOURCES} PROPERTIES COMPILE_FLAGS "-w")
target_include_directories(artpi_kittymemory PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/KittyMemory
)

# ==============================================================================
# 4. Prebuilt Static Libraries: frida-gum & QBDI
# ==============================================================================
add_library(artpi_frida_gum STATIC IMPORTED GLOBAL)
set_target_properties(artpi_frida_gum PROPERTIES
    IMPORTED_LOCATION "${CMAKE_CURRENT_SOURCE_DIR}/frida-gum/lib/${CMAKE_ANDROID_ARCH_ABI}/libfrida-gum.a"
    INTERFACE_INCLUDE_DIRECTORIES "${CMAKE_CURRENT_SOURCE_DIR}/frida-gum/include"
)

add_library(artpi_qbdi STATIC IMPORTED GLOBAL)
set_target_properties(artpi_qbdi PROPERTIES
    IMPORTED_LOCATION "${CMAKE_CURRENT_SOURCE_DIR}/qbdi/lib/${CMAKE_ANDROID_ARCH_ABI}/libQBDI.a"
    INTERFACE_INCLUDE_DIRECTORIES "${CMAKE_CURRENT_SOURCE_DIR}/qbdi/include"
)

# ==============================================================================
# 5. Header-Only Libraries
# ==============================================================================
add_library(artpi_magic_enum INTERFACE)
target_include_directories(artpi_magic_enum INTERFACE
    ${CMAKE_CURRENT_SOURCE_DIR}/magic_enum/include
)

add_library(artpi_unityresolve INTERFACE)
target_include_directories(artpi_unityresolve INTERFACE
    ${CMAKE_CURRENT_SOURCE_DIR}/unityresolve
)

add_library(artpi_levenshtein INTERFACE)
target_include_directories(artpi_levenshtein INTERFACE
    ${CMAKE_CURRENT_SOURCE_DIR}/levenshtein
)
