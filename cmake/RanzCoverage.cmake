# RanzCoverage.cmake
# Source-based code coverage (RANZ_COVERAGE) with clang-cl, for the coverage floor of ADR-0040 item 2:
# the CI job "coverage" builds coretest with it, runs the tests of the new core, and llvm-cov counts
# the lines of each module (.github/scripts/coverage-floor.py).
#
# The option defaults to OFF; with it OFF this file only declares it and returns, so the normal build
# is unchanged.
#
# Toolchain: clang-cl (Clang with the MSVC front end), x86 or x64, single-config generator. The
# .profraw files that the instrumented programs write are read by llvm-profdata and llvm-cov of the
# same LLVM release as the compiler. The coverage job picks a clang-cl whose bin directory has both
# and whose runtime directory has the profile runtime.
#
# CMake links MSVC-style targets by calling the linker (lld-link, or link.exe) directly, not through
# clang-cl, so the profile runtime that clang-cl would add in its own link step is named here, with
# the /INCLUDE of its registration symbol, as clang-cl does.
#
# References:
#   [CLANG-COV] https://clang.llvm.org/docs/SourceBasedCodeCoverage.html
#   [CLANG-DRV] https://github.com/llvm/llvm-project/blob/llvmorg-20.1.8/clang/lib/Driver/ToolChains/MSVC.cpp
#               (visualstudio::Linker::ConstructJob: -include:__llvm_profile_runtime and the profile runtime)

option(RANZ_COVERAGE "Build every C target with source-based code coverage (clang-cl only)" OFF)

if(NOT RANZ_COVERAGE)
  return()
endif()

if(RANZ_ASAN)
  message(FATAL_ERROR "RANZ_COVERAGE and RANZ_ASAN/RANZ_FUZZ are separate builds: turn one of them off")
endif()

if(NOT (WIN32 AND CMAKE_C_COMPILER_ID STREQUAL "Clang" AND CMAKE_C_COMPILER_FRONTEND_VARIANT STREQUAL "MSVC"))
  message(FATAL_ERROR "RANZ_COVERAGE needs clang-cl; the C compiler is "
    "${CMAKE_C_COMPILER_ID} (front end: ${CMAKE_C_COMPILER_FRONTEND_VARIANT})")
endif()

if(CMAKE_C_COMPILER_ARCHITECTURE_ID MATCHES "ARM" OR CMAKE_SYSTEM_PROCESSOR MATCHES "^(ARM64|arm64|aarch64)$")
  message(FATAL_ERROR "RANZ_COVERAGE: the coverage job builds x64; the profile runtime of arm64 is not looked up")
elseif(CMAKE_SIZEOF_VOID_P EQUAL 8)
  set(_ranz_cov_arch "x86_64")
else()
  set(_ranz_cov_arch "i386")
endif()

# Directory of Clang's runtime libraries: -print-runtime-dir, or the one the CI job found
# (<resource-dir>/lib/windows in official LLVM builds), as in RanzSanitizers.cmake
execute_process(
  COMMAND "${CMAKE_C_COMPILER}" -print-runtime-dir
  OUTPUT_VARIABLE _ranz_cov_rt_dir
  OUTPUT_STRIP_TRAILING_WHITESPACE
)
file(TO_CMAKE_PATH "${_ranz_cov_rt_dir}" _ranz_cov_rt_dir)
if(DEFINED ENV{RANZ_RT_DIR} AND IS_DIRECTORY "$ENV{RANZ_RT_DIR}")
  file(TO_CMAKE_PATH "$ENV{RANZ_RT_DIR}" _ranz_cov_rt_dir)
endif()

set(RANZ_PROFILE_LIB "")
foreach(candidate "clang_rt.profile-${_ranz_cov_arch}.lib" "clang_rt.profile.lib")
  if(NOT RANZ_PROFILE_LIB AND EXISTS "${_ranz_cov_rt_dir}/${candidate}")
    set(RANZ_PROFILE_LIB "${_ranz_cov_rt_dir}/${candidate}")
  endif()
endforeach()
if(NOT RANZ_PROFILE_LIB)
  message(FATAL_ERROR "RANZ_COVERAGE: no clang_rt.profile library for ${_ranz_cov_arch} in '${_ranz_cov_rt_dir}'")
endif()
message(STATUS "RANZ_COVERAGE: profile runtime ${RANZ_PROFILE_LIB}")

# Compiler: instrumentation and the coverage mapping ([CLANG-COV]); C and C++ only, so that resource
# and assembler sources keep their flags
add_compile_options("$<$<COMPILE_LANGUAGE:C,CXX>:-fprofile-instr-generate>" "$<$<COMPILE_LANGUAGE:C,CXX>:-fcoverage-mapping>")

# Linker: the profile runtime, and its registration symbol so that the runtime's object is linked
# and writes the profile at exit ([CLANG-DRV])
add_link_options("${RANZ_PROFILE_LIB}" "/INCLUDE:__llvm_profile_runtime")
