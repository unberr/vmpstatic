cmake_minimum_required(VERSION 3.16)
project(vmpstatic VERSION 1.2.0 LANGUAGES C CXX)

include(CTest)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

add_library(vmpstatic_core STATIC
    src/pe.cpp
    src/detect.cpp
    src/oep.cpp
    src/imports.cpp
    src/disasm.cpp
    src/vm.cpp
    src/packer.cpp
    src/lzma.cpp
    third_party/7zip_lzma/LzmaDec.c
    src/analysis.cpp
    src/report.cpp
)
target_include_directories(vmpstatic_core PUBLIC src PRIVATE third_party/7zip_lzma)

# Optional: accurate handler classification. Without Capstone the tool falls back to
# byte idioms and says so in the report.
find_path(CAPSTONE_INCLUDE_DIR capstone/capstone.h)
find_library(CAPSTONE_LIBRARY capstone)
if(CAPSTONE_INCLUDE_DIR AND CAPSTONE_LIBRARY)
    target_compile_definitions(vmpstatic_core PRIVATE VMPSTATIC_CAPSTONE=1)
    target_include_directories(vmpstatic_core PRIVATE ${CAPSTONE_INCLUDE_DIR})
    target_link_libraries(vmpstatic_core PUBLIC ${CAPSTONE_LIBRARY})
    message(STATUS "vmpstatic: Capstone found, handler classification enabled")
else()
    message(STATUS "vmpstatic: Capstone not found, using opcode patterns")
endif()

if(MSVC)
    target_compile_options(vmpstatic_core PRIVATE /W4)
else()
    target_compile_options(vmpstatic_core PRIVATE -Wall -Wextra)
endif()

add_executable(vmpstatic src/main.cpp)
target_link_libraries(vmpstatic PRIVATE vmpstatic_core)

if(BUILD_TESTING)
    add_executable(vmpstatic_tests tests/test_main.cpp)
    target_link_libraries(vmpstatic_tests PRIVATE vmpstatic_core)
    add_test(NAME vmpstatic_tests COMMAND vmpstatic_tests)
endif()
