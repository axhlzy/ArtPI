cmake_minimum_required(VERSION 3.10)
project(artpi_cli LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

set(INJECTOR_SOURCES
    main.cpp
    ptrace_inject.cpp
    elf_util.cpp
    payload.cpp
    repl_client.cpp
)

add_executable(artpi-cli ${INJECTOR_SOURCES})

target_include_directories(artpi-cli PRIVATE
    .
    ../../engine/mpack
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
