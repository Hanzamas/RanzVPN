cmake_minimum_required(VERSION 3.15)

set(BUILD_NUMBER CACHE STRING "The number of the current build.")

if ("${BUILD_NUMBER}" STREQUAL "")
	set(BUILD_NUMBER "0")
endif()

#
# Link MSVC runtime statically
# this should be revisited after installer migration to MSI
#
cmake_policy(SET CMP0091 NEW)
set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")

project("Ranz VPN"
  VERSION "0.1.${BUILD_NUMBER}"
  LANGUAGES C
)

set(CMAKE_C_STANDARD 99)

set(TOP_DIRECTORY ${CMAKE_SOURCE_DIR})
set(BUILD_DIRECTORY ${CMAKE_BINARY_DIR})

# AddressSanitizer and libFuzzer builds (RANZ_ASAN, RANZ_FUZZ; both OFF by default)
include("${TOP_DIRECTORY}/cmake/RanzSanitizers.cmake")

# We define a dedicated variable because CMAKE_BUILD_TYPE can have different
# configurations than "Debug" and "Release", such as "RelWithDebInfo".
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
  set(BUILD_TYPE "Debug")
else()
  set(BUILD_TYPE "Release")
endif()

# Check that submodules are present only if source was downloaded with git
if(EXISTS "${TOP_DIRECTORY}/.git" AND NOT EXISTS "${TOP_DIRECTORY}/src/libhamcore/CMakeLists.txt")
    message (FATAL_ERROR "Submodules are not initialized. Run\n\tgit submodule update --init --recursive")
endif()

if(WIN32 AND VCPKG_TARGET_TRIPLET AND NOT DEFINED CMAKE_TOOLCHAIN_FILE)
  message (FATAL_ERROR "vcpkg not installed or integrated with Visual Studio. Install it and run\n\tvcpkg integrate install")
endif()

# Date and time
string(TIMESTAMP DATE_DAY "%d" UTC)
string(TIMESTAMP DATE_MONTH "%m" UTC)
string(TIMESTAMP DATE_YEAR "%Y" UTC)
string(TIMESTAMP TIME_HOUR "%H" UTC)
string(TIMESTAMP TIME_MINUTE "%M" UTC)
string(TIMESTAMP TIME_SECOND "%S" UTC)

message(STATUS "Build date: ${DATE_DAY}/${DATE_MONTH}/${DATE_YEAR}")
message(STATUS "Build time: ${TIME_HOUR}:${TIME_MINUTE}:${TIME_SECOND}")

add_subdirectory(src)
