# RanzOptions.cmake
# Build options of the project's own code: the C standard and the INTERFACE target ranz_options,
# and ranz_core_options for the new core (at the end of this file).
#
# mayaqua links ranz_options PUBLIC (src/Mayaqua/CMakeLists.txt), so every target that builds on
# Mayaqua (cedar, ranz-node, vpntest and the fuzz targets) compiles with these options.
# The vendored targets (liboqs, oqs-provider) do not link Mayaqua and get none of them; they also
# set their own C standard.
#
# Windows API level: Windows 10 version 1607 and Windows Server 2016 (NTDDI_WIN10_RS1), the oldest
# systems Ranz VPN runs on (SUPPORTED_WINDOWS_LIST in MayaType.h). The SDK headers declare what this
# level has and hide what is newer. It is set here only: MayaType.h stops a translation unit that
# compiles below it with #error.
#
# Configuration: every configuration but Debug gives Malloc() a private Win32 heap and leaves DbgHelp
# out (no symbolized call stacks), Win32.c. Debug, and every AddressSanitizer build, allocates from
# the CRT heap. Debug also defines _DEBUG, through the debug CRT (/MTd, CMAKE_MSVC_RUNTIME_LIBRARY in
# the top-level CMakeLists.txt). The CI job "debug" compiles the Debug configuration.

if(NOT WIN32)
  message(FATAL_ERROR "Ranz VPN builds on Windows only")
endif()

# C17 (/std:c17 with clang-cl). CMake knows the C17 standard from version 3.21 on.
if(CMAKE_VERSION VERSION_LESS "3.21")
  message(FATAL_ERROR "Ranz VPN needs CMake 3.21 or later for C17 (this is CMake ${CMAKE_VERSION})")
endif()
set(CMAKE_C_STANDARD 17)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

add_library(ranz_options INTERFACE)

# Volatile loads and stores with acquire and release semantics (clang-cl maps /volatile:ms to
# -fms-volatile). x64 has this by default; ARM64 defaults to /volatile:iso, where a thread that sees a
# 'volatile bool' halt or cancel flag need not see the data written before it. The flags themselves
# go through FlagRead and FlagWrite (src/Mayaqua/Native.h); the CI step "Check /volatile:ms" checks
# the arm64 compile commands for it
target_compile_options(ranz_options INTERFACE "$<$<COMPILE_LANGUAGE:C,CXX>:/volatile:ms>")

target_compile_definitions(ranz_options INTERFACE
  WINVER=0x0A00
  _WIN32_WINNT=0x0A00
  NTDDI_VERSION=0x0A000002
  WIN32_LEAN_AND_MEAN
  # No deprecation warnings for the CRT functions that have _s variants (strcpy, sprintf, ...)
  _CRT_SECURE_NO_WARNINGS
  # Every configuration but Debug: no DbgHelp call stacks
  $<$<NOT:$<CONFIG:Debug>>:WIN32_NO_DEBUG_HELP_DLL>
)

if(RANZ_ASAN)
  # AddressSanitizer build (cmake/RanzSanitizers.cmake): AddressSanitizer must see every
  # allocation, so Malloc() keeps the CRT heap; Memory.c poisons the slack after each block
  target_compile_definitions(ranz_options INTERFACE RANZ_ASAN)
else()
  # Every configuration but Debug: Malloc() on a private Win32 heap
  target_compile_definitions(ranz_options INTERFACE $<$<NOT:$<CONFIG:Debug>>:WIN32_USE_HEAP_API_FOR_MEMORY>)
endif()

if(RANZ_FUZZ)
  # libFuzzer build (cmake/RanzSanitizers.cmake): AbortExitEx() calls abort() instead of _exit(1)
  # (Kernel.c), so that libFuzzer saves the input
  target_compile_definitions(ranz_options INTERFACE RANZ_FUZZING)
endif()

# ranz_core_options: the build options of the new core (src/Core) and of its test program
# (src/coretest), ADR-0022. The new core runs on Windows 11 and Windows Server 2022 and later, so
# its API level is that of Windows Server 2022 (NTDDI_WIN10_FE), the older of the two; ML-KEM
# (Windows 11 24H2) is looked up at run time. Of ranz_options it keeps /volatile:ms and
# WIN32_LEAN_AND_MEAN; the other definitions are Mayaqua's, and the new-core targets link neither
# Mayaqua nor ranz_options.
add_library(ranz_core_options INTERFACE)

target_compile_options(ranz_core_options INTERFACE "$<$<COMPILE_LANGUAGE:C,CXX>:/volatile:ms>")

target_compile_definitions(ranz_core_options INTERFACE
  WINVER=0x0A00
  _WIN32_WINNT=0x0A00
  NTDDI_VERSION=0x0A00000A
  WIN32_LEAN_AND_MEAN
)
