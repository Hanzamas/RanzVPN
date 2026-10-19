# libFuzzer targets, built only with RANZ_FUZZ=ON (see cmake/RanzSanitizers.cmake).
# Each target is one fuzz_<name>.c holding LLVMFuzzerTestOneInput(); fuzz_common.c holds
# LLVMFuzzerInitialize() and the helpers they share. Seeds: corpus/<target>/.
# Run them with run_fuzzers.ps1.

set(RANZ_FUZZ_TARGETS
  fuzz_pack
  fuzz_cfg
  fuzz_tcpip
  fuzz_x509
  fuzz_http
  fuzz_login
)

foreach(fuzz_target IN LISTS RANZ_FUZZ_TARGETS)
  add_executable(${fuzz_target}
    "${fuzz_target}.c"
    "fuzz_common.c"
    "fuzz_common.h"

    "${TOP_DIRECTORY}/src/BuildFiles/Manifests/common.manifest"
  )

  set_target_properties(${fuzz_target}
    PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${BUILD_DIRECTORY}"
    PDB_OUTPUT_DIRECTORY "${BUILD_DIRECTORY}"
  )

  target_link_libraries(${fuzz_target} PRIVATE cedar)
  target_link_options(${fuzz_target} PRIVATE ${RANZ_FUZZER_LINK_OPTIONS})
endforeach()
