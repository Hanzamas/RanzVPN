# libFuzzer targets, built only with RANZ_FUZZ=ON (see cmake/RanzSanitizers.cmake).
# Each target is one fuzz_<name>.c holding LLVMFuzzerTestOneInput(); fuzz_common.c holds
# LLVMFuzzerInitialize() and the helpers they share. Seeds: corpus/<target>/.
# Run them with run_fuzzers.ps1.
#
# Every fuzz_<name>.c of this directory but fuzz_common.c is a target, so a new target is a new file (with its seeds
# in corpus/ and their generator in seeds/, see make_seeds.py) and no list is edited here, in run_fuzzers.ps1 or in
# make_seeds.py. A target says what it needs in comment lines of its own source, each at the start of a line:
#   // fuzz-max-len: <bytes>     the -max_len that run_fuzzers.ps1 gives libFuzzer; required (the registry check of
#                                .github/scripts/fuzz-registry.py fails without it)
#   // fuzz-libs: <target>...    the libraries of the new core that the target links (src/Core/CMakeLists.txt); optional
#   // fuzz-reach: <function>    a function that the seeds must reach, which run_fuzzers.ps1 checks in the coverage of
#                                their replay; optional, one line for each; a line that names fuzz-reach in another
#                                form (no function, indented, a space before the colon, a /* */ comment) fails the
#                                run and the registry check, which also fails without the lines that REACH of
#                                fuzz-registry.py gives a target
file(GLOB RANZ_FUZZ_SOURCES RELATIVE "${CMAKE_CURRENT_SOURCE_DIR}" CONFIGURE_DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/fuzz_*.c")
list(REMOVE_ITEM RANZ_FUZZ_SOURCES "fuzz_common.c")

# Console executables without an icon or the hamcore resources (cmake/RanzExecutable.cmake)
foreach(fuzz_source IN LISTS RANZ_FUZZ_SOURCES)
  string(REGEX REPLACE "\\.c$" "" fuzz_target "${fuzz_source}")
  ranz_add_executable(${fuzz_target}
    DESCRIPTION "Fuzz Target ${fuzz_target}"
    SOURCES
      "${fuzz_source}"
      "fuzz_common.c"
      "fuzz_common.h"
    LINK_OPTIONS ${RANZ_FUZZER_LINK_OPTIONS}
  )

  file(STRINGS "${CMAKE_CURRENT_SOURCE_DIR}/${fuzz_source}" fuzz_libs_line REGEX "^// fuzz-libs:")
  if(fuzz_libs_line)
    string(REGEX REPLACE "^// fuzz-libs:" "" fuzz_libs "${fuzz_libs_line}")
    string(REPLACE "\r" "" fuzz_libs "${fuzz_libs}")
    separate_arguments(fuzz_libs)
    target_link_libraries(${fuzz_target} PRIVATE ${fuzz_libs})
  endif()
endforeach()
