cmake_minimum_required(VERSION 3.15)

set(BUILD_NUMBER CACHE STRING "The number of the current build.")

if ("${BUILD_NUMBER}" STREQUAL "")
	set(BUILD_NUMBER "0")
endif()

#
# Link MSVC runtime statically
# this should be revisited after installer migration to MSI
#
set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")

project("Ranz VPN"
  VERSION "0.1.${BUILD_NUMBER}"
  LANGUAGES C
)

set(TOP_DIRECTORY ${CMAKE_SOURCE_DIR})
set(BUILD_DIRECTORY ${CMAKE_BINARY_DIR})

# AddressSanitizer and libFuzzer builds (RANZ_ASAN, RANZ_FUZZ; both OFF by default)
include("${TOP_DIRECTORY}/cmake/RanzSanitizers.cmake")

# Source-based code coverage builds (RANZ_COVERAGE, OFF by default). After RanzSanitizers.cmake,
# whose options it reads.
include("${TOP_DIRECTORY}/cmake/RanzCoverage.cmake")

# The ranz_warnings target: /W3 and the warning flags that the project's own targets link PRIVATE
include("${TOP_DIRECTORY}/cmake/RanzWarnings.cmake")

# The hamcore files (src/bin/hamcore) as resources of the executables
include("${TOP_DIRECTORY}/cmake/RanzResources.cmake")

# Build options of the project's own code: C17 and the ranz_options target (Windows API level,
# per-configuration definitions). After RanzSanitizers.cmake, whose options it reads.
include("${TOP_DIRECTORY}/cmake/RanzOptions.cmake")

# ranz_add_executable(): each executable with its version resource, icon, manifest and options
include("${TOP_DIRECTORY}/cmake/RanzExecutable.cmake")

# The release-only hardened licence-gate binary ranzguard (SEC-4 #282, ADR-0036), x64 only and OFF by
# default; the clean internal and debug variant is the default build
option(RANZ_HARDENED "Build the release-only hardened licence-gate binary ranzguard (x64 only, ADR-0036)" OFF)

# Check that submodules are present only if source was downloaded with git
if(EXISTS "${TOP_DIRECTORY}/.git" AND NOT EXISTS "${TOP_DIRECTORY}/src/Mayaqua/3rdparty/liboqs/CMakeLists.txt")
    message (FATAL_ERROR "Submodules are not initialized. Run\n\tgit submodule update --init --recursive")
endif()

if(WIN32 AND VCPKG_TARGET_TRIPLET AND NOT DEFINED CMAKE_TOOLCHAIN_FILE)
  message (FATAL_ERROR "vcpkg not installed or integrated with Visual Studio. Install it and run\n\tvcpkg integrate install")
endif()

# Build time: one UTC stamp, so its parts cannot straddle a second rollover. string(TIMESTAMP) uses
# SOURCE_DATE_EPOCH when that is set, which makes the stamp reproducible. src/Cedar turns it into
# BuildInfo.h; the version resources (ver.rc) read DATE_YEAR.
string(TIMESTAMP BUILD_STAMP "%Y-%m-%d %H:%M:%S" UTC)
string(SUBSTRING "${BUILD_STAMP}" 0 4 DATE_YEAR)

message(STATUS "Build time (UTC): ${BUILD_STAMP}")

add_subdirectory(src)

# ranzguard is added here, not from src/, so it escapes the control-flow-guard and other linker flags
# that src/CMakeLists.txt sets (which would add a load-config import to its empty import table).
if(RANZ_HARDENED)
  if(NOT CMAKE_SIZEOF_VOID_P EQUAL 8)
    message(FATAL_ERROR "RANZ_HARDENED is the x64-only hardened variant (ADR-0036)")
  endif()
  add_subdirectory(src/guard)
endif()
