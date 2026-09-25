cmake_minimum_required(VERSION 3.10)
project(artpi_cli LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

set(XZ_EMBEDDED_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../../external/xz-embedded")
set(XZ_SOURCES
    ${XZ_EMBEDDED_DIR}/linux/lib/xz/xz_crc32.c
    ${XZ_EMBEDDED_DIR}/linux/lib/xz/xz_crc64.c
    ${XZ_EMBEDDED_DIR}/linux/lib/xz/xz_dec_stream.c
    ${XZ_EMBEDDED_DIR}/linux/lib/xz/xz_dec_lzma2.c
    ${XZ_EMBEDDED_DIR}/linux/lib/xz/xz_dec_bcj.c
)
set_source_files_properties(${XZ_SOURCES} PROPERTIES
    COMPILE_FLAGS "-DXZ_USE_CRC64 -DXZ_DEC_ANY_CHECK -DXZ_DEC_CONCATENATED -DXZ_DEC_ARM64 -DXZ_DEC_X86 -DXZ_DEC_ARM -w"
)

set(INJECTOR_SOURCES
    main.cpp
    ptrace_inject.cpp
    elf_util.cpp
    payload.cpp
    repl_client.cpp
    ${XZ_SOURCES}
)

add_executable(artpi-cli ${INJECTOR_SOURCES})

target_include_directories(artpi-cli PRIVATE
    .
    ../../engine/mpack
    ${XZ_EMBEDDED_DIR}/userspace
    ${XZ_EMBEDDED_DIR}/linux/include/linux
)

target_link_libraries(artpi-cli)

if (CMAKE_STRIP)
    add_custom_command(TARGET artpi-cli POST_BUILD
        COMMAND ${CMAKE_STRIP} --strip-unneeded $<TARGET_FILE:artpi-cli>
        COMMENT "Stripping symbols from artpi-cli"
    )
endif()

# NOTE: embedding libartpi_agent.so into the CLI binary (and writing the packed
# file to prebuild/) is done by Gradle (task ':cli') in pure JVM code, so no
# pack_payload.py / shell script is required. See cli/injector/build.gradle.
