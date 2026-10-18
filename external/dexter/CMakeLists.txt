cmake_minimum_required(VERSION 3.10)
project(dexter_slicer LANGUAGES CXX)

set(SLICER_DIR ${CMAKE_CURRENT_SOURCE_DIR}/slicer)

file(GLOB SLICER_SOURCES
    ${SLICER_DIR}/*.cc
)
list(FILTER SLICER_SOURCES EXCLUDE REGEX ".*_test\\.cc$")

add_library(slicer STATIC ${SLICER_SOURCES})

target_include_directories(slicer PUBLIC
    ${SLICER_DIR}/export
    ${SLICER_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}
)

target_compile_options(slicer PRIVATE
    -Wall
    -Wno-unused-parameter
    -Wno-shift-count-overflow
    -Wno-sign-compare
    -Wno-missing-field-initializers
)

# NOTE: do NOT force NDEBUG on writer.cc here. SLICER_EXTRA() is controlled by
# NDEBUG and it also declares a data member (ir::EncodedValue::original), so
# defining NDEBUG for a single translation unit would give writer.cc a different
# type layout than the rest of the program (ODR violation). ArtPI builds IR from
# scratch, so writer.cc skips the "re-encode == original bytes" cross-check when
# `original` is empty (see writer.cc, WriteEncodedValue()).

add_library(dexter::slicer ALIAS slicer)
