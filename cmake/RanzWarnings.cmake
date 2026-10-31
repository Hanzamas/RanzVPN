# RanzWarnings.cmake
# The INTERFACE target ranz_warnings: the compiler warnings of the project's own code.
#
# Every target of the project's own code links it PRIVATE: cedar and mayaqua, and every executable
# (ranz-node, vpntest and the fuzz targets) through ranz_add_executable
# (cmake/RanzExecutable.cmake):
#
#   target_link_libraries(<target> PRIVATE ranz_warnings)
#
# A new target gets the flags from that one line; no list of targets is kept anywhere. The vendored
# targets (liboqs, oqs-provider) do not link it, so they compile without them.
#
# What it carries:
#   - /W3 with every compiler (clang-cl maps it to -Wall)
#   - clang and clang-cl: -Werror=<family> for the families whose count is zero (RANZ_ERROR_FLAGS),
#     so that they cannot come back. The families that still have hits stay warnings: parentheses,
#     deprecated-declarations.
#     A read-only parameter of a Mayaqua helper is const (FND-158), which is what keeps
#     incompatible-pointer-types-discards-qualifiers and pointer-sign at zero.
#   - clang and clang-cl, unless RANZ_UNUSED_WARNINGS is OFF: the unused and unreachable code
#     warnings (spec #24, pass 0). CI's unused-code report step lists every warning of this family
#     as the compiler's view of dead file-local code. Pass 7 of the sweep made the kinds in
#     RANZ_UNUSED_ERROR_FLAGS errors: their report was empty. unused-variable and
#     unused-but-set-variable stay warnings: each local left in them is initialised by a function
#     call or assigned by executed statements, so deleting it would edit an executed statement,
#     which the sweep does not do.
#
# cl.exe gets /W3 only: the other flags are clang's.

option(RANZ_UNUSED_WARNINGS "Unused and unreachable code warnings for the project's own targets (clang or clang-cl; cl.exe ignores it)" ON)

set(RANZ_UNUSED_WARNING_FLAGS
  -Wunused-function
  -Wunused-variable
  -Wunused-but-set-variable
  -Wunused-label
  -Wunused-const-variable
  -Wunreachable-code
)

# The unused kinds whose report is empty fail the build (-Werror=<kind>)
set(RANZ_UNUSED_ERROR_FLAGS
  -Werror=unused-function
  -Werror=unused-label
  -Werror=unused-const-variable
  -Werror=unreachable-code
)

# The other families with zero hits in the baseline of FND-31 (the CI log of the x64 build).
# format: Format, FormatArgs, Print and Debug carry RANZ_PRINTF_FORMAT (Mayaqua/MayaType.h), so clang
# checks their arguments against the format string; the -Wformat report of the project's own targets
# was empty after FND-204.
set(RANZ_ERROR_FLAGS
  -Werror=implicit-function-declaration
  -Werror=int-conversion
  -Werror=return-type
  -Werror=incompatible-function-pointer-types
  -Werror=format
  -Werror=incompatible-pointer-types-discards-qualifiers
  -Werror=pointer-sign
)

add_library(ranz_warnings INTERFACE)

# The generator expression keeps the flags away from resource (.rc) and assembler sources, whose
# tools reject them.
target_compile_options(ranz_warnings INTERFACE "$<$<COMPILE_LANGUAGE:C,CXX>:/W3>")

if(CMAKE_C_COMPILER_ID STREQUAL "Clang")
  set(_ranz_flags ${RANZ_ERROR_FLAGS})
  if(RANZ_UNUSED_WARNINGS)
    list(APPEND _ranz_flags ${RANZ_UNUSED_WARNING_FLAGS} ${RANZ_UNUSED_ERROR_FLAGS})
  endif()
  foreach(_ranz_flag IN LISTS _ranz_flags)
    target_compile_options(ranz_warnings INTERFACE "$<$<COMPILE_LANGUAGE:C,CXX>:${_ranz_flag}>")
  endforeach()
  list(JOIN _ranz_flags " " _ranz_flags_text)
  message(STATUS "ranz_warnings: /W3 ${_ranz_flags_text}")
else()
  message(STATUS "ranz_warnings: /W3 (${CMAKE_C_COMPILER_ID}: the clang flags are not set)")
endif()
