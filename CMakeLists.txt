cmake_minimum_required(VERSION 3.10)
project(artpi LANGUAGES C CXX ASM)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

set(COMMON_FLAGS "-Wall -Wextra -Wno-unused-parameter -Wno-macro-redefined -fvisibility=hidden -flto=thin")
set(CXX_ONLY_FLAGS "-fvisibility-inlines-hidden -fno-exceptions -fno-rtti")
set(LINKER_FLAGS "-fuse-ld=lld -flto=thin -ffixed-x18 -Wl,--hash-style=both -Wl,--unresolved-symbols=ignore-all")

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${COMMON_FLAGS}")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${COMMON_FLAGS} ${CXX_ONLY_FLAGS}")

# nmmvm interpreter: release builds strip dalvik asserts
set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} -DNDEBUG -g0")
set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -DNDEBUG -g0")

set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} ${LINKER_FLAGS}")
set(CMAKE_MODULE_LINKER_FLAGS "${CMAKE_MODULE_LINKER_FLAGS} ${LINKER_FLAGS}")
set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} ${LINKER_FLAGS}")

include_directories(
    include
    src
    engine
    engine/pine
    external/xz-embedded/linux/include/linux
    external/xz-embedded/userspace
    external/xdl/include
    external/xdl
    # nmmvm (nmmp) embedded dalvik interpreter
    engine/nmmvm
    engine/nmmvm/include
    # §NATIVE: libgum (Frida-Gum) / QBDI 引擎与跨层桥
    external/frida-gum/include
    external/qbdi/include
    engine/native
    engine/tracer/unified
)

set(XZ_EMBEDDED_SOURCE
        external/xz-embedded/linux/lib/xz/xz_crc32.c
        external/xz-embedded/linux/lib/xz/xz_dec_lzma2.c
        external/xz-embedded/linux/lib/xz/xz_dec_stream.c)

set(XDL_SOURCES
        external/xdl/xdl.c
        external/xdl/xdl_iterate.c
        external/xdl/xdl_linker.c
        external/xdl/xdl_lzma.c
        external/xdl/xdl_util.c)

set(ARTPI_SOURCES
        # Core ArtPI Framework (src/core)
        src/core/pi.cpp
        src/core/pi_logger.cpp
        src/core/pi_method.cpp
        src/core/pi_hook_handle.cpp

        # DEX parsing & disassembly (src/dex)
        src/dex/pi_smali.cpp
        src/dex/pi_dex_resolver.cpp

        # Native disassembly & symbol resolution (src/native)
        src/native/pi_native.cpp

        # Interpreter sandbox (src/sandbox)
        src/sandbox/pi_code_provider.cpp
        src/sandbox/pi_resolver_bridge.cpp
        src/sandbox/pi_interp_executor.cpp
        src/sandbox/pi_interp_tracer.cpp

        # Embedded NMM-VM interpreter (engine/nmmvm)
        engine/nmmvm/vm/DexCatch.cpp
        engine/nmmvm/vm/Exception.cpp
        engine/nmmvm/vm/GlobalCache.cpp
        engine/nmmvm/vm/Interp.cpp
        engine/nmmvm/vm/InterpC-portable.cpp
        engine/nmmvm/vm/JNIWrapper.c

        # Engine: Pine backend
        engine/pine/pine.cpp
        engine/pine/pine_native.cpp
        engine/pine/ruler.cpp
        engine/pine/android.cpp
        engine/pine/jni_bridge.cpp

        # Engine: ART Model
        engine/art/art_method.cpp
        engine/art/thread.cpp
        engine/art/jit.cpp

        # Engine: Trampoline
        engine/trampoline/trampoline_installer.cpp

        # Engine: Utilities
        engine/utils/memory.cpp
        engine/utils/scoped_memory_access_protection.cpp
        engine/utils/elf_image.cpp
        engine/utils/well_known_classes.cpp

        # External sub-tools
        ${XZ_EMBEDDED_SOURCE}
        ${XDL_SOURCES}

        # NATIVE: Native Hook 抽象层 + 动态注册嗅探器 (engine/native)
        engine/native/hooker/pi_gum_hooker.cpp
        engine/native/hooker/pi_jni_sniffer.cpp

        # NATIVE: QBDI 机器码 DBI 执行器
        engine/native/qbdi/pi_qbdi_engine.cpp

        # NATIVE: Java<->Native 跨层交接桥 (engine/tracer/unified)
        engine/tracer/unified/pi_unified_tracer.cpp
        engine/tracer/unified/pi_jni_bridge.cpp
)

# ==============================================================================
# 架构选择: 本工程 (含 nmmvm / gum / QBDI 依赖) 仅支持 arm64-v8a
# 其他架构分支保留注释
# ==============================================================================
if (CMAKE_ANDROID_ARCH_ABI STREQUAL "arm64-v8a")
    set(CMAKE_ASM_FLAGS "${CMAKE_ASM_FLAGS} -arch arm64")
    set(ARTPI_SOURCES
            ${ARTPI_SOURCES}
            engine/trampoline/arch/arm64.cpp
            engine/trampoline/arch/arm64.S)
# elseif(CMAKE_ANDROID_ARCH_ABI STREQUAL "armeabi-v7a")
#     ... (注释保留: thumb2 trampoline)
# elseif(CMAKE_ANDROID_ARCH_ABI STREQUAL "x86")
#     ... (注释保留: x86 trampoline)
else()
    message(FATAL_ERROR "Unsupported cpu abi ${CMAKE_ANDROID_ARCH_ABI} (V2 引擎仅支持 arm64-v8a)!")
endif()

set_source_files_properties(
    ${XZ_EMBEDDED_SOURCE}
    ${XDL_SOURCES}
    engine/nmmvm/vm/DexCatch.cpp
    engine/nmmvm/vm/Exception.cpp
    engine/nmmvm/vm/GlobalCache.cpp
    engine/nmmvm/vm/Interp.cpp
    engine/nmmvm/vm/InterpC-portable.cpp
    engine/nmmvm/vm/JNIWrapper.c
    PROPERTIES COMPILE_FLAGS "-w"
)

add_library(artpi SHARED ${ARTPI_SOURCES})
add_library(artpi_static STATIC ${ARTPI_SOURCES})

set_target_properties(artpi PROPERTIES OUTPUT_NAME "artpi")
set_target_properties(artpi_static PROPERTIES OUTPUT_NAME "artpi_static")

find_library(log-lib log)
find_package(cxx CONFIG)

# ==============================================================================
# NATIVE: 依赖库链接 —— 全部静态打包 (libfrida-gum.a + libQBDI.a)
# ==============================================================================
set(FRIDA_GUM_LIB "${CMAKE_CURRENT_SOURCE_DIR}/external/frida-gum/lib/${CMAKE_ANDROID_ARCH_ABI}/libfrida-gum.a")
set(QBDI_LIB      "${CMAKE_CURRENT_SOURCE_DIR}/external/qbdi/lib/${CMAKE_ANDROID_ARCH_ABI}/libQBDI.a")

if (TARGET cxx::cxx)
    target_link_libraries(artpi ${log-lib} cxx::cxx)
    target_link_libraries(artpi_static ${log-lib} cxx::cxx)
else()
    target_link_libraries(artpi ${log-lib})
    target_link_libraries(artpi_static ${log-lib})
endif()

foreach(_t artpi artpi_static)
    target_link_libraries(${_t} ${FRIDA_GUM_LIB} ${QBDI_LIB})
endforeach()

if (CMAKE_STRIP)
    add_custom_command(TARGET artpi POST_BUILD
        COMMAND ${CMAKE_STRIP} --strip-unneeded $<TARGET_FILE:artpi>
        COMMENT "Stripping symbols from libartpi.so"
    )
endif()

# NOTE: publishing libartpi.so / libartpi_static.a / ArtPI.h into prebuild/ is
# done by Gradle (task ':libartpi') so the whole build is driven from a single
# cross-platform entrypoint and needs no external packaging scripts.

# ==============================================================================
# 构建流水线与模块依赖关系:
# 1. 核心库构建:
#    - artpi (SHARED) + artpi_static (STATIC)
# 2. 注入代理库构建:
#    - artpi_agent (SHARED, 链接 artpi_static)
# 3. 独立注入器与命令行构建:
#    - artpi-cli (EXECUTABLE, 内嵌/部署 libartpi_agent.so, 支持交互式 REPL 与 --server 后台模式)
# 4. 功能测试 (app_process + JNI 包装):
#    - artpi_test (SHARED, 链接 artpi_static)
# ==============================================================================
add_subdirectory(src/agent)
add_subdirectory(cli/injector)
add_subdirectory(test)


