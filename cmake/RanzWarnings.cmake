# RanzWarnings.cmake
# Unused-code warnings (RANZ_UNUSED_WARNINGS) for the project's own targets.
#
# The option defaults to OFF; with it OFF this file only declares the option and the function, so
# the normal build is unchanged. CI turns it on in the build_and_test jobs, and the unused-code
# report step lists every warning of this family as the compiler's view of dead file-local code
# (spec #24, pass 0). Pass 7 of the sweep made the kinds in RANZ_UNUSED_ERROR_FLAGS errors: their
# report was empty. unused-variable and unused-but-set-variable stay warnings: each local left in
# them is initialised by a function call or assigned by executed statements, so deleting it would
# edit an executed statement, which the sweep does not do.
#
# Only the project's own targets get the flags: Cedar and Mayaqua (src/CMakeLists.txt) and every
# executable (ranz_add_executable, cmake/RanzExecutable.cmake). Vendored third-party targets
# (liboqs, oqs-provider) do not.

option(RANZ_UNUSED_WARNINGS "Enable clang's unused and unreachable code warnings for the project's own targets (clang or clang-cl only)" OFF)

set(RANZ_UNUSED_WARNING_FLAGS
  -Wunused-function
  -Wunused-variable
  -Wunused-but-set-variable
  -Wunused-label
  -Wunused-const-variable
  -Wunreachable-code
)

# The kinds whose report is empty fail the build (-Werror=<kind>)
set(RANZ_UNUSED_ERROR_FLAGS
  -Werror=unused-function
  -Werror=unused-label
  -Werror=unused-const-variable
  -Werror=unreachable-code
)

if(RANZ_UNUSED_WARNINGS AND NOT CMAKE_C_COMPILER_ID STREQUAL "Clang")
  message(FATAL_ERROR "RANZ_UNUSED_WARNINGS needs clang or clang-cl; the C compiler is ${CMAKE_C_COMPILER_ID}")
endif()

# Adds the flags to the C and C++ sources of each target named in the arguments. The generator
# expression keeps them away from resource (.rc) and assembler sources, whose tools reject them.
function(ranz_unused_warnings)
  if(NOT RANZ_UNUSED_WARNINGS)
    return()
  endif()
  foreach(_ranz_target IN LISTS ARGN)
    foreach(_ranz_flag IN LISTS RANZ_UNUSED_WARNING_FLAGS RANZ_UNUSED_ERROR_FLAGS)
      target_compile_options(${_ranz_target} PRIVATE "$<$<COMPILE_LANGUAGE:C,CXX>:${_ranz_flag}>")
    endforeach()
  endforeach()
  list(JOIN RANZ_UNUSED_WARNING_FLAGS " " _ranz_flags)
  list(JOIN RANZ_UNUSED_ERROR_FLAGS " " _ranz_errors)
  list(JOIN ARGN ", " _ranz_targets)
  message(STATUS "RANZ_UNUSED_WARNINGS: ${_ranz_flags} ${_ranz_errors} for ${_ranz_targets}")
endfunction()
