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

# ==============================================================================
# 依赖关系对齐 Gradle:
#   :libartpi (artpi + artpi_static)  <-  :agent:build (artpi_agent)  <-  :cli:build
# Gradle 的 :cli 通过 :agent:build 间接依赖整个核心库, 这里用 add_dependencies
# 把同一条链补上, 否则在 CLion 里单独构建 artpi-cli 只会产出一个孤立的 CLI。
#
# 必须是 add_dependencies 而不是 target_link_libraries: CLI 并不链接 agent,
# libartpi_agent.so 是在构建完成后被作为 payload 内嵌进二进制的
# (见 cli/injector/build.gradle 的打包步骤与 payload.cpp 的 trailer 解析)。
# 这里只约定构建顺序, 不能真的去链接它。
# ==============================================================================
add_dependencies(artpi-cli artpi artpi_static artpi_agent)

if (CMAKE_STRIP)
    add_custom_command(TARGET artpi-cli POST_BUILD
        COMMAND ${CMAKE_STRIP} --strip-unneeded $<TARGET_FILE:artpi-cli>
        COMMENT "Stripping symbols from artpi-cli"
    )
endif()

# NOTE: embedding libartpi_agent.so into the CLI binary (and writing the packed
# file to prebuild/) is done by Gradle (task ':cli') in pure JVM code, so no
# pack_payload.py / shell script is required. See cli/injector/build.gradle.
