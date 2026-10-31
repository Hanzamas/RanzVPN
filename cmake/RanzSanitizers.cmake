# RanzSanitizers.cmake
# AddressSanitizer (RANZ_ASAN) and libFuzzer (RANZ_FUZZ) builds with clang-cl.
#
# Both options default to OFF. With both OFF this file only declares the options and
# returns, so the normal build is unchanged.
#
# Toolchain: clang-cl (Clang with the MSVC front end) of LLVM 20 or later, x86 or x64, static
# CRT (/MT, set by CMAKE_MSVC_RUNTIME_LIBRARY in the top-level CMakeLists.txt and matching the
# *-windows-static vcpkg triplets), RelWithDebInfo build type. ARM64 is rejected: Microsoft
# documents ASan on Windows for x86 and x64 only.
#
# CRT linkage: /MT stays. LLVM 20 and later have a single ASan runtime DLL for every CRT; with
# /MT the EXE links its import library plus a static thunk. LLVM 19 and earlier linked ASan
# statically with /MT, and that runtime never hooks HeapAlloc ([ASAN-WIN]): it is rejected.
# RANZ_ASAN builds allocate from the CRT heap (cmake/RanzOptions.cmake leaves
# WIN32_USE_HEAP_API_FOR_MEMORY undefined), so no ASAN_OPTIONS are needed.
# windows_hook_rtl_allocators=1 ([ASAN-FLAGS]) is not set: with it, vpntest did not start on the
# CI runner (0xC0000142, STATUS_DLL_INIT_FAILED).
#
# CMake links MSVC-style targets by calling the linker (lld-link, or link.exe) directly, not
# through clang-cl, so the sanitizer runtime libraries that clang-cl would add in its own link
# step are named here explicitly, exactly as clang-cl does for /MT.
#
# References (each flag below cites one of them):
#   [MS-ASAN]   https://learn.microsoft.com/en-us/cpp/sanitizers/asan
#   [MS-BUILD]  https://learn.microsoft.com/en-us/cpp/sanitizers/asan-building
#   [MS-RT]     https://learn.microsoft.com/en-us/cpp/sanitizers/asan-runtime
#   [MS-ISSUES] https://learn.microsoft.com/en-us/cpp/sanitizers/asan-known-issues
#   [MS-FSAN]   https://learn.microsoft.com/en-us/cpp/build/reference/fsanitize
#   [MS-INFER]  https://learn.microsoft.com/en-us/cpp/build/reference/inferasanlibs
#   [MS-WHOLE]  https://learn.microsoft.com/en-us/cpp/build/reference/wholearchive-include-all-library-object-files
#   [LIBFUZZER] https://llvm.org/docs/LibFuzzer.html
#   [CLANG-REF] https://clang.llvm.org/docs/ClangCommandLineReference.html
#   [CLANG-DRV] https://github.com/llvm/llvm-project/blob/llvmorg-20.1.8/clang/lib/Driver/ToolChains/MSVC.cpp
#               (visualstudio::Linker::ConstructJob: the libraries clang-cl links for ASan and libFuzzer)
#   [CLANG-SAN] https://github.com/llvm/llvm-project/blob/llvmorg-20.1.8/clang/lib/Driver/SanitizerArgs.cpp
#               (/MTd, /MDd and /LDd are rejected with -fsanitize=address)
#   [ASAN-WIN]  https://github.com/llvm/llvm-project/blob/llvmorg-19.1.7/compiler-rt/lib/asan/asan_malloc_win.cpp
#               (ReplaceSystemMalloc() hooks nothing unless ASAN_DYNAMIC) and the same file at llvmorg-20.1.8
#   [ASAN-FLAGS] https://github.com/llvm/llvm-project/blob/llvmorg-20.1.8/compiler-rt/lib/asan/asan_flags.inc

option(RANZ_ASAN "Build every C/C++ target with AddressSanitizer (clang-cl only)" OFF)
option(RANZ_FUZZ "Build the libFuzzer targets in src/fuzz (turns RANZ_ASAN on)" OFF)

if(RANZ_FUZZ AND NOT RANZ_ASAN)
  # [MS-FSAN] recommends ASan with libFuzzer; [LIBFUZZER]: libFuzzer on Windows without ASan is unsupported
  # A normal variable that shadows the cache entry: the cache keeps the user's own value, so a
  # later configure with -DRANZ_FUZZ=OFF turns ASan off again
  message(STATUS "RANZ_FUZZ=ON: turning RANZ_ASAN on")
  set(RANZ_ASAN ON)
endif()

if(NOT RANZ_ASAN)
  return()
endif()

if(NOT (WIN32 AND CMAKE_C_COMPILER_ID STREQUAL "Clang" AND CMAKE_C_COMPILER_FRONTEND_VARIANT STREQUAL "MSVC"))
  message(FATAL_ERROR "RANZ_ASAN/RANZ_FUZZ need clang-cl; the C compiler is "
    "${CMAKE_C_COMPILER_ID} (front end: ${CMAKE_C_COMPILER_FRONTEND_VARIANT})")
endif()

if(CMAKE_MSVC_RUNTIME_LIBRARY MATCHES "DLL")
  # The runtime libraries chosen below are the /MT ones ([MS-BUILD] /INFERASANLIBS table), and
  # [LIBFUZZER]: "Building fuzzers with the /MD (dynamic runtime library) compile option is unsupported."
  message(FATAL_ERROR "RANZ_ASAN/RANZ_FUZZ expect the static CRT (/MT); CMAKE_MSVC_RUNTIME_LIBRARY is ${CMAKE_MSVC_RUNTIME_LIBRARY}")
endif()

# RelWithDebInfo only. Debug selects /MTd (top-level CMakeLists.txt), which clang-cl rejects with
# ASan ([CLANG-SAN]). Release and MinSizeRel compile without debug information and link without
# /DEBUG, so ASan and libFuzzer stacks would have no symbols ([MS-ASAN]: "Debug information is
# required for optimal formatting of call stacks"; clang-cl links ASan and libFuzzer with -debug,
# [CLANG-DRV]). Multi-config generators can build Debug from the same configure, so they are
# rejected too.
get_property(_ranz_multi_config GLOBAL PROPERTY GENERATOR_IS_MULTI_CONFIG)
if(_ranz_multi_config OR NOT CMAKE_BUILD_TYPE STREQUAL "RelWithDebInfo")
  message(FATAL_ERROR "RANZ_ASAN/RANZ_FUZZ need a single-config generator (Ninja) and "
    "-DCMAKE_BUILD_TYPE=RelWithDebInfo (got '${CMAKE_BUILD_TYPE}'): clang-cl rejects /MTd (Debug) with "
    "-fsanitize=address, and Release or MinSizeRel stacks have no symbols")
endif()

# Architecture suffix of the compiler-rt libraries (Clang names: i386, x86_64)
if(CMAKE_C_COMPILER_ARCHITECTURE_ID MATCHES "ARM" OR CMAKE_SYSTEM_PROCESSOR MATCHES "^(ARM64|arm64|aarch64)$")
  # [MS-ASAN]: "Support is limited to x86 and x64 on Windows 10 and later."
  message(FATAL_ERROR "RANZ_ASAN/RANZ_FUZZ support x86 and x64 only (AddressSanitizer on Windows)")
elseif(CMAKE_SIZEOF_VOID_P EQUAL 8)
  set(RANZ_RT_ARCH "x86_64")
else()
  set(RANZ_RT_ARCH "i386")
endif()

# Directory of Clang's runtime libraries ([CLANG-REF] -print-runtime-dir)
execute_process(
  COMMAND "${CMAKE_C_COMPILER}" -print-runtime-dir
  OUTPUT_VARIABLE RANZ_RT_DIR
  OUTPUT_STRIP_TRAILING_WHITESPACE
  RESULT_VARIABLE _ranz_rc
)
file(TO_CMAKE_PATH "${RANZ_RT_DIR}" RANZ_RT_DIR)
# The CI job may have found the libraries elsewhere (<resource-dir>/lib/windows in official LLVM builds)
if(DEFINED ENV{RANZ_RT_DIR} AND IS_DIRECTORY "$ENV{RANZ_RT_DIR}")
  file(TO_CMAKE_PATH "$ENV{RANZ_RT_DIR}" RANZ_RT_DIR)
  set(_ranz_rc 0)
endif()
if(NOT _ranz_rc EQUAL 0 OR NOT IS_DIRECTORY "${RANZ_RT_DIR}")
  message(FATAL_ERROR "RANZ_ASAN: '${CMAKE_C_COMPILER} -print-runtime-dir' did not name a directory (got '${RANZ_RT_DIR}')")
endif()
message(STATUS "RANZ_ASAN: Clang runtime directory ${RANZ_RT_DIR}")

# Full path of a compiler-rt library, "clang_rt.<name>-<arch>.lib" (lib/windows layout) or
# "clang_rt.<name>.lib" (per-target runtime directory layout); empty when absent
function(ranz_rt_lib out name)
  set(${out} "" PARENT_SCOPE)
  foreach(candidate "clang_rt.${name}-${RANZ_RT_ARCH}.lib" "clang_rt.${name}.lib")
    if(EXISTS "${RANZ_RT_DIR}/${candidate}")
      set(${out} "${RANZ_RT_DIR}/${candidate}" PARENT_SCOPE)
      return()
    endif()
  endforeach()
endfunction()

ranz_rt_lib(_ranz_asan_dynamic asan_dynamic)
ranz_rt_lib(_ranz_asan_static_thunk asan_static_runtime_thunk)
ranz_rt_lib(_ranz_asan_static asan)
ranz_rt_lib(_ranz_asan_cxx asan_cxx)

if(_ranz_asan_dynamic AND _ranz_asan_static_thunk)
  # LLVM 20 and later (and MSVC since Visual Studio 2022 17.7): a single runtime DLL for every
  # CRT. With /MT, link the DLL's import library plus the static runtime thunk, the thunk with
  # /wholearchive ([MS-BUILD] /INFERASANLIBS table, [MS-RT] runtime table, [MS-WHOLE]).
  set(RANZ_ASAN_LIBS "${_ranz_asan_dynamic}" "/wholearchive:${_ranz_asan_static_thunk}")

  # [MS-RT]: "Even when statically linking, the ASan runtime DLL must be present at runtime".
  # Copy the DLL of this compiler next to the executables: the build directory (vpntest,
  # ranz-node, the fuzz targets).
  get_filename_component(_ranz_cc_dir "${CMAKE_C_COMPILER}" DIRECTORY)
  set(RANZ_ASAN_DLL "")
  foreach(candidate
      "${RANZ_RT_DIR}/clang_rt.asan_dynamic-${RANZ_RT_ARCH}.dll"
      "${RANZ_RT_DIR}/clang_rt.asan_dynamic.dll"
      "${_ranz_cc_dir}/clang_rt.asan_dynamic-${RANZ_RT_ARCH}.dll")
    if(NOT RANZ_ASAN_DLL AND EXISTS "${candidate}")
      set(RANZ_ASAN_DLL "${candidate}")
    endif()
  endforeach()
  if(NOT RANZ_ASAN_DLL)
    message(FATAL_ERROR "RANZ_ASAN: clang_rt.asan_dynamic DLL not found in ${RANZ_RT_DIR} or ${_ranz_cc_dir}")
  endif()
  file(COPY "${RANZ_ASAN_DLL}" DESTINATION "${CMAKE_BINARY_DIR}")
  message(STATUS "RANZ_ASAN: runtime DLL ${RANZ_ASAN_DLL}")
elseif(_ranz_asan_static AND _ranz_asan_cxx)
  # LLVM 19 and earlier with /MT: the static runtime ([MS-RT] "Previous versions" table) never
  # hooks HeapAlloc ([ASAN-WIN]), so every Mayaqua allocation would go unchecked
  message(FATAL_ERROR "RANZ_ASAN: ${RANZ_RT_DIR} has only the static ASan runtime of LLVM 19 or "
    "earlier, which does not check HeapAlloc (Mayaqua's allocator). Use clang-cl of LLVM 20 or later.")
else()
  message(FATAL_ERROR "RANZ_ASAN: no clang_rt.asan libraries for ${RANZ_RT_ARCH} in ${RANZ_RT_DIR}")
endif()

# Compiler: [MS-FSAN] /fsanitize=address, which clang-cl accepts with the same spelling.
# C and C++ only, so that resource and assembler sources keep their flags.
add_compile_options("$<$<COMPILE_LANGUAGE:C,CXX>:/fsanitize=address>")

# Test-only code in Mayaqua: the RANZ_ASAN macro poisons the slack after each Malloc() block
# (Memory.c). cmake/RanzOptions.cmake defines it for the project's own targets only.

# Linker: the runtime libraries above, on every EXE/DLL link (static libraries are not linked)
add_link_options(${RANZ_ASAN_LIBS})

# [MS-ISSUES]: "Incremental linking is unsupported, and should be disabled."
# [LIBFUZZER]: "Linking fuzzers with the /INCREMENTAL link option (or the /DEBUG option which
# implies it) is also unsupported." CMake puts "/debug /INCREMENTAL" in the RelWithDebInfo
# linker flags; keep /debug (PDBs give ASan symbolized stacks, [MS-ASAN]) and turn incremental
# linking off, as clang-cl does with -debug -incremental:no ([CLANG-DRV]).
foreach(_ranz_kind EXE SHARED MODULE)
  set(_ranz_var "CMAKE_${_ranz_kind}_LINKER_FLAGS_RELWITHDEBINFO")
  string(REPLACE "/INCREMENTAL:NO" "/INCREMENTAL" ${_ranz_var} "${${_ranz_var}}")
  string(REPLACE "/INCREMENTAL:YES" "/INCREMENTAL" ${_ranz_var} "${${_ranz_var}}")
  string(REPLACE "/INCREMENTAL" "/INCREMENTAL:NO" ${_ranz_var} "${${_ranz_var}}")
endforeach()

# link.exe would also add MSVC's own ASan libraries; clang-cl passes /INFERASANLIBS:NO to it
# for that reason ([CLANG-DRV], [MS-INFER]). lld-link does not infer libraries.
get_filename_component(_ranz_linker_name "${CMAKE_LINKER}" NAME)
string(TOLOWER "${_ranz_linker_name}" _ranz_linker_name)
if(_ranz_linker_name STREQUAL "link.exe")
  add_link_options(/INFERASANLIBS:NO)
endif()

if(RANZ_FUZZ)
  ranz_rt_lib(_ranz_fuzzer fuzzer)
  if(NOT _ranz_fuzzer)
    message(FATAL_ERROR "RANZ_FUZZ: clang_rt.fuzzer library for ${RANZ_RT_ARCH} not found in ${RANZ_RT_DIR}")
  endif()

  # [LIBFUZZER] "Fuzzer Usage": a large project that also compiles executables with their own
  # main() can request just the instrumentation without linking, -fsanitize=fuzzer-no-link.
  # Coverage instrumentation for Mayaqua, Cedar and the rest. Executables that do not link
  # libFuzzer (vpntest, ranz-node, ...) resolve the coverage callbacks to the default
  # implementations in the ASan runtime (sanitizer coverage interface).
  add_compile_options("$<$<COMPILE_LANGUAGE:C,CXX>:-fsanitize=fuzzer-no-link>")

  # Test-only code in Mayaqua: the RANZ_FUZZING macro makes AbortExitEx() call abort() instead of
  # _exit(1) (Kernel.c), so that libFuzzer saves the input ([LIBFUZZER]: a fuzz target "must not
  # exit() on any input"). cmake/RanzOptions.cmake defines it for the project's own targets only.

  # Link step of -fsanitize=fuzzer ([LIBFUZZER]: it "links in the libFuzzer's main()"), as
  # clang-cl does it: the libFuzzer library with /wholearchive ([CLANG-DRV], [MS-WHOLE]).
  # Used by src/fuzz/CMakeLists.txt.
  set(RANZ_FUZZER_LINK_OPTIONS "/wholearchive:${_ranz_fuzzer}")
  message(STATUS "RANZ_FUZZ: libFuzzer ${_ranz_fuzzer}")
endif()
