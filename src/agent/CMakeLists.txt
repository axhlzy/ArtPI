cmake_minimum_required(VERSION 3.10)
project(artpi_agent LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

# QuickJS C Sources
set(QUICKJS_SOURCES
    ../../engine/qjs/quickjs/quickjs.c
    ../../engine/qjs/quickjs/libregexp.c
    ../../engine/qjs/quickjs/libunicode.c
    ../../engine/qjs/quickjs/cutils.c
    ../../engine/qjs/quickjs/libbf.c
)
set_source_files_properties(${QUICKJS_SOURCES} PROPERTIES
    COMPILE_FLAGS "-D_GNU_SOURCE -DCONFIG_VERSION=\\\"2021-03-27\\\" -w")

# Agent Sources
set(AGENT_SOURCES
    agent_main.cpp
    agent_net.cpp
    agent_common.cpp
    agent_java.cpp
    agent_native.cpp
    agent_memory.cpp
    agent_trace.cpp
    agent_debug.cpp
    agent_dynamic.cpp
    agent_js.cpp
    ${QUICKJS_SOURCES}
)

add_library(artpi_agent SHARED ${AGENT_SOURCES})

target_include_directories(artpi_agent PRIVATE
    .
    ../../include
    ../../engine
    ../../engine/qjs/quickjs
    ../../engine/mpack
    ../../external/xdl/include
    ../../external/qbdi/include
    ../../engine/native
    ../../engine/native/qbdi
)

find_library(log-lib log)

# Link against the core static library libartpi_static.a + system libs
target_link_libraries(artpi_agent PRIVATE
    artpi_static
    ${log-lib}
    dl
)

set_target_properties(artpi_agent PROPERTIES OUTPUT_NAME "artpi_agent")

if (CMAKE_STRIP)
    add_custom_command(TARGET artpi_agent POST_BUILD
        COMMAND ${CMAKE_STRIP} --strip-unneeded $<TARGET_FILE:artpi_agent>
        COMMENT "Stripping symbols from libartpi_agent.so"
    )
endif()
