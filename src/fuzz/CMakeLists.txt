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
  fuzz_dhcp
  fuzz_net
  fuzz_stun
  fuzz_login
  fuzz_noise
)

# Console executables without an icon or the hamcore resources (cmake/RanzExecutable.cmake)
foreach(fuzz_target IN LISTS RANZ_FUZZ_TARGETS)
  ranz_add_executable(${fuzz_target}
    DESCRIPTION "Fuzz Target ${fuzz_target}"
    SOURCES
      "${fuzz_target}.c"
      "fuzz_common.c"
      "fuzz_common.h"
    LINK_OPTIONS ${RANZ_FUZZER_LINK_OPTIONS}
  )
endforeach()

# fuzz_noise: the session module of the new core (CORE-F2, #62) and the crypto module under it
target_link_libraries(fuzz_noise PRIVATE corenoise corecrypto)
