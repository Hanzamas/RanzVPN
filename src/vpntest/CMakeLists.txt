# vpntest (cmake/RanzExecutable.cmake): a console executable with the hamcore files as resources
#
# Every .c file of this directory is a source of vpntest, so a new test is a new file and this file does not change. The
# test registers itself with RANZ_TEST (testlist.h); "vpntest list" prints the registered tests and
# .github/scripts/vpntest.ps1 runs each of them. CONFIGURE_DEPENDS makes the build check the directory, so a file that
# was added or removed is picked up without a new configure.
file(GLOB RANZ_VPNTEST_SOURCES RELATIVE "${CMAKE_CURRENT_SOURCE_DIR}" CONFIGURE_DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/*.c")

ranz_add_executable(vpntest HAMCORE
  DESCRIPTION "Testing Utility"
  ICON "vpntest.ico"
  SOURCES
    ${RANZ_VPNTEST_SOURCES}
  # The session and crypto modules of the new core for nodelogin.c, the transport module for transporttest.c,
  # quictest.c and tlstest.c (the QUIC transport loads msquic.dll at run time, so no import library is linked), the VXLAN
  # module for vxlantest.c, the switch module for switchtest.c, the policy engine for policytest.c, the NAT simulator of
  # the core tests and the messages of the control stream for relaypathtest.c (CORE-S5-5, #411); netapi32: the local
  # account that stands for a domain account (NetUserAdd); the front door for sourcelimitstest.c
  LIBRARIES
    corefrontdoor
    coretransport
    corenoise
    corecrypto
    corevxlan
    coreswitch
    corepolicy
    natsim
    corecontrolpb
    "netapi32.lib"
  # The resources test (runtime.c) compares every hamcore file the executable serves with its source
  # file. A C-only definition, so the resource scripts of vpntest do not get the quoted path.
  C_DEFINITIONS
    "RANZ_HAMCORE_SOURCE_DIR=\"${TOP_DIRECTORY}/src/bin/hamcore\""
)

# The X.509 test (x509test.c) builds its certificates with the OpenSSL API itself, the crypto
# test (crypto.c) checks the DH groups against OpenSSL's own primes, and the default VRF tracer
# (sdntrace.c) runs the TLS of the control stream on it until the Schannel transport of CORE-S2-1
# (#69) does; Mayaqua no longer exports the OpenSSL include path, so these files get it
set_source_files_properties(x509test.c crypto.c sdntrace.c PROPERTIES INCLUDE_DIRECTORIES "${OPENSSL_INCLUDE_DIR}")

# The source group policy test (grouppolicytest.c, SDN-87 #386) starts the EVPN of a gateway node without its BGP sidecar,
# from the evpn object of a Bgp setting that cJSON parses, as NodeBgpStart does. Cedar does not export the include path of
# cJSON (vcpkg; the path that Cedar found from the header), so this file gets it; vpntest links cJSON through Cedar.
set_source_files_properties(grouppolicytest.c PROPERTIES INCLUDE_DIRECTORIES "${RANZ_CJSON_INCLUDE_DIR}")
