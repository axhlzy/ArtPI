# ==============================================================================
# Suite 1: ArtPI.h native API tests (loaded by app_process)
#   build/arm64-v8a/test/libartpi_test.so
# ==============================================================================
add_library(artpi_test SHARED
    artpi/cpp/artpi_test_common.cpp
    artpi/cpp/artpi_test_core.cpp
    artpi/cpp/artpi_test_api.cpp
)

target_include_directories(artpi_test PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/artpi/cpp
    ${CMAKE_SOURCE_DIR}/include
)

set_target_properties(artpi_test PROPERTIES OUTPUT_NAME "artpi_test")

find_library(log-lib log)

# artpi_static already exports its frida-gum / QBDI link interface
target_link_libraries(artpi_test PRIVATE
    artpi_static
    ${log-lib}
    dl
)

# ==============================================================================
# Suite 2: JS VM binding tests
#   dlopen's libartpi_agent.so at runtime -> no link against artpi_static needed
#   build/arm64-v8a/test/libartpi_js_test.so
# ==============================================================================
add_library(artpi_js_test SHARED
    js/cpp/js_test.cpp
)

target_include_directories(artpi_js_test PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/js/cpp
)

set_target_properties(artpi_js_test PROPERTIES OUTPUT_NAME "artpi_js_test")

target_link_libraries(artpi_js_test PRIVATE
    ${log-lib}
    dl
)

# ==============================================================================
# Playground: ArtPI trace/hook harness (loaded by app_process)
#   dlopen's libartpi_agent.so at runtime; runs a ticker loop over Target.*
#   build/arm64-v8a/test/libartpi_harness.so
# ==============================================================================
add_library(artpi_harness SHARED
    harness/cpp/harness.cpp
)

set_target_properties(artpi_harness PROPERTIES OUTPUT_NAME "artpi_harness")

target_link_libraries(artpi_harness PRIVATE
    ${log-lib}
    dl
)
