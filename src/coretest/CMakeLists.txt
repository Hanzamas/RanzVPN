# natsim: the NAT simulator of the core tests (natsim.c, natsim.h; CORE-S5-2, #78), a library of its own so that the peer
# tests of coretest and the relay path test of vpntest (src/vpntest/relaypathtest.c; CORE-S5-5, #411) run their worlds on
# the same one. It calls the peer module and nothing else; its users keep their own build options, so ranz_core_options
# stays PRIVATE, as for corepeer.
add_library(natsim STATIC natsim.c natsim.h)

target_include_directories(natsim PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}")

target_link_libraries(natsim PUBLIC corepeer)
target_link_libraries(natsim PRIVATE ranz_core_options ranz_warnings)

set_target_properties(natsim
  PROPERTIES
  ARCHIVE_OUTPUT_DIRECTORY "${BUILD_DIRECTORY}"
  LIBRARY_OUTPUT_DIRECTORY "${BUILD_DIRECTORY}"
  RUNTIME_OUTPUT_DIRECTORY "${BUILD_DIRECTORY}"
  COMPILE_PDB_NAME "natsim"
  COMPILE_PDB_OUTPUT_DIRECTORY "${BUILD_DIRECTORY}"
)

# coretest (cmake/RanzExecutable.cmake): the test program of the new core, which links the crypto,
# session, peer, transport and front door modules and the system libraries only (CORE: no cedar, no mayaqua, so
# no OpenSSL and no liboqs). The linker map is kept for the CI step "Core links no OpenSSL or liboqs".
ranz_add_executable(coretest CORE
  DESCRIPTION "New Core Testing Utility"
  ICON "../vpntest/vpntest.ico"
  SOURCES
    coretest.c coretest.h
    # Known-answer tests of the crypto module, CORE-F1 (#61)
    kat.c hybrid.c
    # The refusals of the crypto module, FIX-10 (#435)
    refusal.c
    # Certificate path and the Schannel handshake, CORE-F1 (#61)
    cert.c schannel.c
    # The session module: handshake, session, tunnel and the interop with flynn/noise, CORE-F2 (#62)
    noise.c session.c interop.c
    # Envelopes, the relay role and the relay-first bring-up on the NAT simulator (natsim), CORE-S5-2 (#78)
    envelope.c relay.c
    # ICE and the port mapping of home gateways, with the simulated gateway, CORE-S5-3 (#79)
    ice.c homegw.c
    # Port prediction and birthday punching for symmetric NAT on the NAT simulator, CORE-S5-4 (#266)
    punch.c
    # The peer sessions of the data datagrams on the NAT simulator, CORE-H2 (#399)
    peersession.c
    # The front door with the node and its owners as processes of their own, SDN-29 (#205)
    frontdoor.c
    # The msquic of the exporter of a QUIC connection, on an API table of the test, CORE-H5-R (#443)
    quicexporter.c
    # The fallback after a handshake: a server that refuses the handshake over QUIC, CORE-H5-R (#443)
    fallback.c
  LIBRARIES
    natsim
    corefrontdoor
    coretransport
    corenoise
    corepeer
    corecrypto
    "ws2_32.lib"
    "bcrypt.lib"
    "crypt32.lib"
    "Secur32.Lib"
    "iphlpapi.lib"
  LINK_OPTIONS
    "/MAP:${BUILD_DIRECTORY}/coretest.map"
)

# The msquic headers (src/Core/CMakeLists.txt) for the API table of quicexporter.c, which stands for msquic: the headers
# only, coretest loads no msquic.dll
target_include_directories(coretest PRIVATE "${RANZ_MSQUIC_INCLUDE_DIR}")
