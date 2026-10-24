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
    # Certificate path and the Schannel handshake, CORE-F1 (#61)
    cert.c schannel.c
    # The session module: handshake, session, tunnel and the interop with flynn/noise, CORE-F2 (#62)
    noise.c session.c interop.c
    # Envelopes, the relay role and the relay-first bring-up on the NAT simulator, CORE-S5-2 (#78)
    envelope.c relay.c natsim.c
    # ICE and the port mapping of home gateways, with the simulated gateway, CORE-S5-3 (#79)
    ice.c homegw.c
    # Port prediction and birthday punching for symmetric NAT on the NAT simulator, CORE-S5-4 (#266)
    punch.c
    # The front door with the node and its owners as processes of their own, SDN-29 (#205)
    frontdoor.c
  LIBRARIES
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
