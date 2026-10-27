# Copyright 2026 Perfect Soft
# SPDX-License-Identifier: Apache-2.0
# ts_analyze — MPEG-TS analyser (TR 101 290, PCR/PTS/IAT, SI).
#
# Standalone build. libdvbpsi comes either from the system (pkg-config
# libdvbpsi, -DTS_ANALYZE_SYSTEM_DVBPSI=ON) or, by default, from the upstream
# VideoLAN release tarball, fetched and checked by SHA-256 and compiled into a
# static library. -DTS_ANALYZE_STATIC=ON links a fully static binary (needs a
# static libc: musl, e.g. the Alpine container in Containerfile).
cmake_minimum_required(VERSION 3.20)
project(ts_analyze C CXX)

option(TS_ANALYZE_SYSTEM_DVBPSI "Use the system libdvbpsi (pkg-config)" OFF)
option(TS_ANALYZE_STATIC "Link a fully static executable" OFF)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_EXTENSIONS ON)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_EXTENSIONS ON)
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

if(TS_ANALYZE_SYSTEM_DVBPSI)
    find_package(PkgConfig REQUIRED)
    pkg_check_modules(DVBPSI REQUIRED IMPORTED_TARGET libdvbpsi>=1.3)
    add_library(ts_dvbpsi ALIAS PkgConfig::DVBPSI)
else()
    include(FetchContent)
    set(TS_ANALYZE_DVBPSI_URL
        "https://download.videolan.org/pub/libdvbpsi/1.3.3/libdvbpsi-1.3.3.tar.bz2"
        CACHE STRING "libdvbpsi release tarball")
    FetchContent_Declare(libdvbpsi
        URL "${TS_ANALYZE_DVBPSI_URL}"
        URL_HASH SHA256=02b5998bcf289cdfbd8757bedd5987e681309b0a25b3ffe6cebae599f7a00112
        DOWNLOAD_EXTRACT_TIMESTAMP ON)
    # Upstream has no CMakeLists.txt, so this only downloads and unpacks.
    FetchContent_MakeAvailable(libdvbpsi)

    # The upstream build is autotools; compile its sources directly. Its
    # public headers are included as <dvbpsi/xxx.h> (installed, flat layout),
    # so stage them flat into the build tree, plus the config.h the sources
    # expect from configure.
    set(_src "${libdvbpsi_SOURCE_DIR}/src")
    file(GLOB_RECURSE _dvbpsi_c CONFIGURE_DEPENDS ${_src}/*.c)
    file(GLOB_RECURSE _dvbpsi_h CONFIGURE_DEPENDS ${_src}/*.h)
    set(_inc "${CMAKE_BINARY_DIR}/dvbpsi-include")
    file(MAKE_DIRECTORY "${_inc}/dvbpsi")
    foreach(h ${_dvbpsi_h})
        get_filename_component(n "${h}" NAME)
        configure_file("${h}" "${_inc}/dvbpsi/${n}" COPYONLY)
    endforeach()
    file(WRITE "${CMAKE_BINARY_DIR}/dvbpsi-config/config.h"
        "#define HAVE_STDINT_H 1\n#define HAVE_INTTYPES_H 1\n"
        "#define HAVE_SYS_TYPES_H 1\n#define HAVE_ASPRINTF 1\n"
        "#define HAVE_VARIADIC_MACROS 1\n#define VERSION \"1.3.3\"\n")

    add_library(ts_dvbpsi STATIC ${_dvbpsi_c})
    target_include_directories(ts_dvbpsi
        PRIVATE "${CMAKE_BINARY_DIR}/dvbpsi-config"
        PUBLIC "${_inc}")
    target_compile_definitions(ts_dvbpsi PRIVATE _GNU_SOURCE)
    target_compile_options(ts_dvbpsi PRIVATE -w)
endif()

add_executable(ts_analyze src/main.cpp)
target_include_directories(ts_analyze PRIVATE include)
target_compile_options(ts_analyze PRIVATE -Wall -Wextra -Werror -Wcast-align
    -Wenum-compare -fmessage-length=0)
target_link_libraries(ts_analyze PRIVATE ts_dvbpsi)
if(TS_ANALYZE_STATIC)
    target_link_options(ts_analyze PRIVATE -static)
endif()
target_link_options(ts_analyze PRIVATE $<$<CONFIG:Release>:-s>)

install(TARGETS ts_analyze RUNTIME DESTINATION bin)

enable_testing()
add_test(NAME smoke
    COMMAND ${CMAKE_COMMAND} -DBIN=$<TARGET_FILE:ts_analyze>
            -DOUT=${CMAKE_BINARY_DIR}/smoke
            -P ${CMAKE_CURRENT_SOURCE_DIR}/tests/smoke.cmake)
add_test(NAME modes
    COMMAND ${CMAKE_COMMAND} -DBIN=$<TARGET_FILE:ts_analyze>
            -DOUT=${CMAKE_BINARY_DIR}/modes
            -P ${CMAKE_CURRENT_SOURCE_DIR}/tests/modes.cmake)
