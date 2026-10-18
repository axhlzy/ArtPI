cmake_minimum_required(VERSION 3.10)
project(artpi LANGUAGES C CXX ASM)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

set(COMMON_FLAGS "-Wall -Wextra -Wno-unused-parameter -Wno-macro-redefined -fvisibility=hidden -flto=thin")
set(CXX_ONLY_FLAGS "-fvisibility-inlines-hidden -fno-exceptions -fno-rtti")
set(LINKER_FLAGS "-fuse-ld=lld -flto=thin -ffixed-x18 -Wl,--hash-style=both")

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
    engine/nmmvm
    engine/nmmvm/include
    engine/native
    engine/tracer/unified
)

add_subdirectory(external)

# Dexter (slicer) DEX manipulation library - required by src/dex/pi_dex_gen.cpp
# (runtime DEX generation for Java.registerClass). Must be added BEFORE the
# artpi targets so `slicer` exists when we link against it.
# NOTE: the old ARTPI_ENABLE_DEXTER cache variable is intentionally gone: it is
# a hard dependency now, and a stale OFF value in an existing build dir would
# silently break the link.
add_subdirectory(external/dexter)

set(ARTPI_SOURCES
        # Core ArtPI Framework (src/core)
        src/core/pi.cpp
        src/core/pi_logger.cpp
        src/core/pi_method.cpp
        src/core/pi_hook_handle.cpp

        # DEX parsing & disassembly (src/dex)
        src/dex/pi_smali.cpp
        src/dex/pi_dex_resolver.cpp
        src/dex/pi_dex_gen.cpp
        src/dex/pi_dex_loader.cpp
        src/dex/pi_dex_writer.cpp

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
        engine/utils/pi_hash.cpp

        # NATIVE: Native Hook 抽象层 + 动态注册嗅探器 + 硬件断点 (engine/native)
        engine/native/hooker/pi_gum_hooker.cpp
        engine/native/hooker/pi_jni_sniffer.cpp
        engine/native/hooker/pi_hw_hook.cpp

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
find_library(z-lib z)
find_package(cxx CONFIG)

if (TARGET cxx::cxx)
    target_link_libraries(artpi ${log-lib} ${z-lib} cxx::cxx)
    target_link_libraries(artpi_static ${log-lib} ${z-lib} cxx::cxx)
else()
    target_link_libraries(artpi ${log-lib} ${z-lib})
    target_link_libraries(artpi_static ${log-lib} ${z-lib})
endif()

foreach(_t artpi artpi_static)
    target_link_libraries(${_t}
        artpi_xdl
        artpi_xz
        artpi_frida_gum
        artpi_qbdi
        artpi_magic_enum
        # Dexter (slicer): static libs propagate PRIVATE deps as LINK_ONLY, so
        # libartpi_agent.so still resolves these symbols when it links artpi_static.
        slicer
    )
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
# 构建流水线与模块依赖关系 (与 Gradle 保持一致):
# 1. 核心库构建:
#    - artpi (SHARED) + artpi_static (STATIC)
# 2. 注入代理库构建:
#    - artpi_agent (SHARED, 链接 artpi_static)
# 3. 独立注入器与命令行构建:
#    - artpi-cli (EXECUTABLE, 内嵌/部署 libartpi_agent.so, 支持交互式 REPL 与 --server 后台模式)
# 4. 功能测试 (app_process + JNI 包装):
#    - artpi_test (SHARED, 链接 artpi_static)
#
# 目标依赖链:  artpi / artpi_static  <-  artpi_agent  <-  artpi-cli
# 与 Gradle 的 :libartpi <- :agent <- :cli 一一对应 (见 cli/injector/CMakeLists.txt),
# 这样在 CLion 里单独构建某个 target 时也会按整条链编译。
#
# 注意: 内嵌 payload (agent / jadxcli.jar) 的打包与 prebuild/ 的发布仍由 Gradle
add_subdirectory(src/agent)
add_subdirectory(cli/injector)
add_subdirectory(test)


