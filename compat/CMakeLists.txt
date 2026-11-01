# The build of ranz-compat (ADR-0037; SDN-L1, #207): the sidecar that serves stock SE-VPN clients, bridges and
# servers with the frozen Cedar of the slim fork and its OpenSSL. CORE-S8-3 (#577) deletes that code from this tree,
# so ranz-compat takes its Cedar from the branch frozen/cedar-se-vpn: from the commit of it that RANZ_FROZEN_CEDAR_SHA
# pins here (CORE-S8-2, #576). That commit is the head of integration of 2026-10-31 before CORE-S8-3: the Cedar and
# Mayaqua of the slim fork with every module of its SE-VPN server (listener, admin RPC, cascade, UDP Acceleration,
# local bridge), OpenSSL from vcpkg, and liboqs and oqs-provider from its submodules.
#
# The build is a project of its own, apart from the one of the root CMakeLists.txt. It configures the tree of that
# commit as its own top-level project (its CMakeLists.txt, vcpkg.json and submodules), with the compiler that the
# caller names and the vcpkg toolchain of VCPKG_ROOT, as its preset x64 does, and builds its cedar and mayaqua
# libraries. A configure with RANZ_FROZEN_CEDAR_DIR builds a checkout of that commit, which must be at the pinned sha;
# one without it clones the commit with its submodules. The CI job "ranz-compat (frozen Cedar)" of windows.yml builds
# it. The program ranz-compat itself, its main and its named pipe to the Node, comes with SDN-L1 (#207).
#
#   cmake -S compat -B build-compat -G Ninja -DCMAKE_C_COMPILER=clang-cl [-DRANZ_FROZEN_CEDAR_DIR=<checkout>]
#   cmake --build build-compat

cmake_minimum_required(VERSION 3.21)

project("Ranz VPN compat" LANGUAGES NONE)

# The commit of the frozen Cedar that ranz-compat builds from. A commit added to the branch later changes nothing here
# until this sha names it.
set(RANZ_FROZEN_CEDAR_BRANCH "frozen/cedar-se-vpn")
set(RANZ_FROZEN_CEDAR_SHA "b481a30539dd2baad9388ebca96c61d81811b782")
set(RANZ_FROZEN_CEDAR_REPOSITORY "https://github.com/Hanzamas/RanzVPN.git")

set(RANZ_FROZEN_CEDAR_DIR "" CACHE PATH "A checkout of RANZ_FROZEN_CEDAR_SHA with its submodules; empty to clone it")
set(RANZ_FROZEN_CEDAR_TRIPLET "x64-windows-static" CACHE STRING "The vcpkg triplet that the frozen tree builds with")

if(NOT CMAKE_C_COMPILER)
  message(FATAL_ERROR "ranz-compat: name the compiler of the frozen tree with CMAKE_C_COMPILER (clang-cl, as its presets do)")
endif()
if(NOT DEFINED ENV{VCPKG_ROOT})
  message(FATAL_ERROR "ranz-compat: VCPKG_ROOT names no vcpkg checkout, from which the frozen tree takes OpenSSL and cJSON")
endif()

# Forward slashes: the initial cache of the frozen tree is a CMake script, in which a backslash starts an escape
string(REPLACE "\\" "/" _ranz_compat_cc "${CMAKE_C_COMPILER}")
string(REPLACE "\\" "/" _ranz_compat_toolchain "$ENV{VCPKG_ROOT}/scripts/buildsystems/vcpkg.cmake")

if(RANZ_FROZEN_CEDAR_DIR)
  string(REPLACE "\\" "/" _ranz_compat_dir "${RANZ_FROZEN_CEDAR_DIR}")

  # A checkout of the caller is built only at the pinned commit
  execute_process(
    COMMAND git -C "${_ranz_compat_dir}" rev-parse HEAD
    OUTPUT_VARIABLE _ranz_compat_head
    OUTPUT_STRIP_TRAILING_WHITESPACE
    RESULT_VARIABLE _ranz_compat_result)
  if(NOT _ranz_compat_result EQUAL 0 OR NOT _ranz_compat_head STREQUAL RANZ_FROZEN_CEDAR_SHA)
    message(FATAL_ERROR "ranz-compat: ${_ranz_compat_dir} is at '${_ranz_compat_head}', not at ${RANZ_FROZEN_CEDAR_SHA} of ${RANZ_FROZEN_CEDAR_BRANCH}")
  endif()
  set(_ranz_compat_source SOURCE_DIR "${_ranz_compat_dir}")
else()
  set(_ranz_compat_source
    GIT_REPOSITORY "${RANZ_FROZEN_CEDAR_REPOSITORY}"
    GIT_TAG "${RANZ_FROZEN_CEDAR_SHA}"
    GIT_SUBMODULES_RECURSE ON)
endif()

message(STATUS "ranz-compat: the frozen Cedar of ${RANZ_FROZEN_CEDAR_BRANCH} at ${RANZ_FROZEN_CEDAR_SHA}")

include(ExternalProject)

# A short build directory: the object paths of the submodules of the frozen tree are long, and Ninja keeps under
# MAX_PATH
ExternalProject_Add(frozen_cedar
  ${_ranz_compat_source}
  BINARY_DIR "${CMAKE_BINARY_DIR}/frozen"
  CMAKE_CACHE_ARGS
    "-DCMAKE_BUILD_TYPE:STRING=RelWithDebInfo"
    "-DCMAKE_C_COMPILER:FILEPATH=${_ranz_compat_cc}"
    "-DCMAKE_TOOLCHAIN_FILE:FILEPATH=${_ranz_compat_toolchain}"
    "-DVCPKG_TARGET_TRIPLET:STRING=${RANZ_FROZEN_CEDAR_TRIPLET}"
  BUILD_COMMAND "${CMAKE_COMMAND}" --build <BINARY_DIR> --target cedar mayaqua
  INSTALL_COMMAND ""
  USES_TERMINAL_CONFIGURE ON
  USES_TERMINAL_BUILD ON)
