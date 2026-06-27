cmake_minimum_required(VERSION 3.20)

# CMP0091: select MSVC runtime via CMAKE_MSVC_RUNTIME_LIBRARY rather
# than baking /MD into the compile flags. Lets callers pick.
cmake_policy(SET CMP0091 NEW)

project(mooring
    LANGUAGES   CXX
    VERSION     0.1.0
    DESCRIPTION "Process integrity and anti-injection detection toolkit"
)

# C++17 is enough; we don't reach for newer features and want to
# stay compatible with the toolchains shipped in long-term-support
# Visual Studio installs.
set(CMAKE_CXX_STANDARD          17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS        OFF)

# Default to Release if the caller didn't pick one. The Debug
# runtime adds a lot of overhead to STL iteration which matters in
# the export-walk loops; nobody wants to discover that the hard
# way.
if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "" FORCE)
endif()

if(NOT WIN32)
    message(FATAL_ERROR "mooring currently targets Windows only.")
endif()

option(MOORING_BUILD_EXAMPLES     "Build mooring example programs" ON)
option(MOORING_WARNINGS_AS_ERRORS "Treat warnings as errors"        OFF)

# ---------------------------------------------------------------------------
# Library
# ---------------------------------------------------------------------------

add_library(mooring STATIC
    src/core/result.cpp
    src/core/strings.cpp
    src/core/module_inventory.cpp
    src/core/pe_image.cpp
    src/detectors/inline_hook.cpp
    src/detectors/iat_hook.cpp
    src/detectors/thread_origin.cpp
    src/detectors/hidden_module.cpp
    src/detectors/hardware_breakpoint.cpp
)
add_library(mooring::mooring ALIAS mooring)

target_include_directories(mooring
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
)

target_compile_definitions(mooring
    PRIVATE
        WIN32_LEAN_AND_MEAN
        NOMINMAX
        _CRT_SECURE_NO_WARNINGS
)

# ntdll covers NtQueryInformationThread (thread_origin). Everything
# else we use is in the default Win32 link set.
target_link_libraries(mooring
    PUBLIC ntdll
)

if(MSVC)
    # /wd4324: "structure was padded due to alignment requirement"
    # — fires on CONTEXT in some SDK revisions, harmless.
    target_compile_options(mooring PRIVATE /W4 /permissive- /wd4324)
    if(MOORING_WARNINGS_AS_ERRORS)
        target_compile_options(mooring PRIVATE /WX)
    endif()
else()
    target_compile_options(mooring PRIVATE -Wall -Wextra -Wpedantic)
    if(MOORING_WARNINGS_AS_ERRORS)
        target_compile_options(mooring PRIVATE -Werror)
    endif()
endif()

# ---------------------------------------------------------------------------
# Examples
# ---------------------------------------------------------------------------

if(MOORING_BUILD_EXAMPLES)
    add_subdirectory(examples)
endif()

# ---------------------------------------------------------------------------
# Install
# ---------------------------------------------------------------------------

include(GNUInstallDirs)

install(TARGETS mooring
    EXPORT  mooringTargets
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
)
install(DIRECTORY include/ DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})

message(STATUS "mooring ${PROJECT_VERSION}: examples=${MOORING_BUILD_EXAMPLES}")
