# The new core (ADR-0022). Each of its modules is a static library of its own, so that a module
# links only what it uses; none links the slim fork (mayaqua, cedar), OpenSSL or liboqs.

# corecrypto: the crypto module (Crypto.h, Crypto*.c; CORE-F1, #61) on CNG, NCrypt and CryptoAPI
file(GLOB SOURCES_CORE_CRYPTO "Crypto*.c")
file(GLOB HEADERS_CORE_CRYPTO "Crypto*.h")

add_library(corecrypto STATIC ${SOURCES_CORE_CRYPTO} ${HEADERS_CORE_CRYPTO})

# The src root: a unit includes "Core/Crypto.h"
target_include_directories(corecrypto PUBLIC "${TOP_DIRECTORY}/src")

# The new core's build options (cmake/RanzOptions.cmake) and the warning flags
# (cmake/RanzWarnings.cmake) stay on the module. A program of the new core gets the options from
# ranz_add_executable(CORE); a program of the slim fork that links the module, vpntest for the
# node's Login (CORE-F2, #62), keeps the API level of ranz_options.
target_link_libraries(corecrypto PRIVATE ranz_core_options ranz_warnings)

# The only libraries the module calls
target_link_libraries(corecrypto
  PRIVATE
    "bcrypt.lib"
    "crypt32.lib"
    "ncrypt.lib"
)

set_target_properties(corecrypto
  PROPERTIES
  ARCHIVE_OUTPUT_DIRECTORY "${BUILD_DIRECTORY}"
  LIBRARY_OUTPUT_DIRECTORY "${BUILD_DIRECTORY}"
  RUNTIME_OUTPUT_DIRECTORY "${BUILD_DIRECTORY}"
  COMPILE_PDB_NAME "corecrypto"
  COMPILE_PDB_OUTPUT_DIRECTORY "${BUILD_DIRECTORY}"
)

# corenoise: the session module (Noise.h, Noise*.c; CORE-F2, #62), the Noise_IK handshake, the
# Noise session and the tunnel over the crypto module, which is all it links
file(GLOB SOURCES_CORE_NOISE "Noise*.c")
file(GLOB HEADERS_CORE_NOISE "Noise*.h")

add_library(corenoise STATIC ${SOURCES_CORE_NOISE} ${HEADERS_CORE_NOISE})

target_link_libraries(corenoise PUBLIC corecrypto)
target_link_libraries(corenoise PRIVATE ranz_core_options ranz_warnings)

set_target_properties(corenoise
  PROPERTIES
  ARCHIVE_OUTPUT_DIRECTORY "${BUILD_DIRECTORY}"
  LIBRARY_OUTPUT_DIRECTORY "${BUILD_DIRECTORY}"
  RUNTIME_OUTPUT_DIRECTORY "${BUILD_DIRECTORY}"
  COMPILE_PDB_NAME "corenoise"
  COMPILE_PDB_OUTPUT_DIRECTORY "${BUILD_DIRECTORY}"
)

# libjuice and libplum (3rdparty/CMakeLists.txt): ICE and the port mapping of the peer module
add_subdirectory(3rdparty)

# corepeer: the peer module (Peer.h, Peer*.c; CORE-S5-2, #78): the peer layer of a node, the relay role and the
# envelopes of binds and signals, on the crypto module and Winsock; ICE and the port mapping of home gateways
# (PeerIce.c, PeerPortMap.c; CORE-S5-3, #79) on libjuice and libplum, ICE on the socket of the layer (CORE-S5-6, #412),
# whose host addresses come from IP Helper; the peer sessions of its data datagrams
# (PeerSession.c; CORE-H2, #399) on the Noise_IK handshake of the session module. The Node module of Cedar links it too, so
# ranz_core_options and the libraries stay PRIVATE: a target that links corepeer keeps its own build options and
# gets the libraries for the link only.
file(GLOB SOURCES_CORE_PEER "Peer*.c")
file(GLOB HEADERS_CORE_PEER "Peer*.h")

add_library(corepeer STATIC ${SOURCES_CORE_PEER} ${HEADERS_CORE_PEER})

target_include_directories(corepeer PUBLIC "${TOP_DIRECTORY}/src")

target_link_libraries(corepeer PRIVATE ranz_core_options ranz_warnings)

# The only libraries the module calls
target_link_libraries(corepeer
  PRIVATE
    corenoise
    corecrypto
    libjuice
    libplum
    "ws2_32.lib"
    "iphlpapi.lib"
)

set_target_properties(corepeer
  PROPERTIES
  ARCHIVE_OUTPUT_DIRECTORY "${BUILD_DIRECTORY}"
  LIBRARY_OUTPUT_DIRECTORY "${BUILD_DIRECTORY}"
  RUNTIME_OUTPUT_DIRECTORY "${BUILD_DIRECTORY}"
  COMPILE_PDB_NAME "corepeer"
  COMPILE_PDB_OUTPUT_DIRECTORY "${BUILD_DIRECTORY}"
)

# coretransport: the transport module (Transport.h, Transport*.c; CORE-F4, #64): the transport interface, the
# session layer on it, the race of a client's fallback list and the in-process loopback transport, over the
# session module, which brings the crypto module. Its threads are those of the Windows thread pool.
file(GLOB SOURCES_CORE_TRANSPORT "Transport*.c")
file(GLOB HEADERS_CORE_TRANSPORT "Transport*.h")

add_library(coretransport STATIC ${SOURCES_CORE_TRANSPORT} ${HEADERS_CORE_TRANSPORT})

target_link_libraries(coretransport PUBLIC corenoise)
target_link_libraries(coretransport PRIVATE ranz_core_options ranz_warnings)

# The QUIC transport (TransportQuic.c, CORE-S1-1 #67) needs the msquic headers. It loads msquic.dll
# at run time through LoadLibrary and MsQuicOpenVersion, so it links no import library and a program
# that never dials or listens over QUIC needs no DLL. The official signed package (the Schannel
# build, pinned) is fetched in CI by .github/scripts/fetch-msquic.ps1, which sets RANZ_MSQUIC_DIR.
set(RANZ_MSQUIC_DIR "$ENV{RANZ_MSQUIC_DIR}" CACHE PATH "The msquic package directory that holds include/msquic.h")
find_path(RANZ_MSQUIC_INCLUDE_DIR "msquic.h" HINTS "${RANZ_MSQUIC_DIR}/include" "${RANZ_MSQUIC_DIR}")
if(NOT RANZ_MSQUIC_INCLUDE_DIR)
  message(FATAL_ERROR "msquic.h was not found. Set RANZ_MSQUIC_DIR to the msquic package directory (CORE-S1-1, #67); CI fetches the pinned signed package with .github/scripts/fetch-msquic.ps1.")
endif()
message(STATUS "coretransport: msquic headers at ${RANZ_MSQUIC_INCLUDE_DIR}")
target_include_directories(coretransport PRIVATE "${RANZ_MSQUIC_INCLUDE_DIR}")

# The TLS transport (TransportTls.c, CORE-S2-1 #69): Schannel through SSPI (secur32) over Winsock, and the
# machine's Schannel group list in the registry (advapi32). A program that links the module gets them for the link.
target_link_libraries(coretransport
  PRIVATE
    "secur32.lib"
    "ws2_32.lib"
    "advapi32.lib"
)

# The outbound path (TransportPath.c, SDN-61 #254): the system's proxy through WinHTTP, and the interface of the underlay
# by its alias or its index through IP Helper
target_link_libraries(coretransport
  PRIVATE
    "winhttp.lib"
    "iphlpapi.lib"
)

set_target_properties(coretransport
  PROPERTIES
  ARCHIVE_OUTPUT_DIRECTORY "${BUILD_DIRECTORY}"
  LIBRARY_OUTPUT_DIRECTORY "${BUILD_DIRECTORY}"
  RUNTIME_OUTPUT_DIRECTORY "${BUILD_DIRECTORY}"
  COMPILE_PDB_NAME "coretransport"
  COMPILE_PDB_OUTPUT_DIRECTORY "${BUILD_DIRECTORY}"
)

# corecontrol: the control module (Control.h, Control*.c; SDN-3, #179): the node's end of the control stream to the
# controller, with the DHCP responders of a state and their leases (ControlDhcp.c; SDN-43, #236) and the zones of
# overlay DNS of its VRFs (ControlDns.c; SDN-11, #187), over the transport
# module, with the messages that nanopb generates at build time from the one schema of
# the node and the controller, proto/ranz/control/v1/control.proto with its control.options (ADR-0027 decision 1).
# The generator is the one of the nanopb submodule (3rdparty/CMakeLists.txt); it needs Python with the protobuf
# package and protoc on the PATH, as the nanopb round trip of ranz.yml does (CI: .github/actions/nanopb). It
# builds its nanopb_pb2.py in the build tree, not in the submodule.
find_program(RANZ_PYTHON NAMES python python3 REQUIRED)
set(_ranz_proto "${TOP_DIRECTORY}/proto/ranz/control/v1")
set(_ranz_controlpb "${CMAKE_CURRENT_BINARY_DIR}/controlpb")
add_custom_command(
  OUTPUT "${_ranz_controlpb}/ranz/control/v1/control.pb.c" "${_ranz_controlpb}/ranz/control/v1/control.pb.h"
  COMMAND "${CMAKE_COMMAND}" -E make_directory "${_ranz_controlpb}/pb2"
  COMMAND "${CMAKE_COMMAND}" -E env "NANOPB_PB2_TEMP_DIR=${_ranz_controlpb}/pb2"
    "${RANZ_PYTHON}" "${CMAKE_CURRENT_SOURCE_DIR}/3rdparty/nanopb/generator/nanopb_generator.py"
    --error-on-unmatched -I proto -D "${_ranz_controlpb}" ranz/control/v1/control.proto
  WORKING_DIRECTORY "${TOP_DIRECTORY}"
  DEPENDS "${_ranz_proto}/control.proto" "${_ranz_proto}/control.options"
  COMMENT "nanopb: the messages of proto/ranz/control/v1/control.proto"
  VERBATIM
)

add_library(corecontrol STATIC
  Control.c
  Control.h
  # The delay before the stream opens again, which grows while the attempts fail (SDN-90, #395)
  ControlRetry.c
  ControlDhcp.c
  ControlDns.c
  ControlInternal.h
  # The Listener of a node in a desired state (SDN-45, #238)
  ControlListener.c
  # The TLS fingerprints of the certificate of the Controller in a desired state (SDN-92, #397)
  ControlPins.c
  "${_ranz_controlpb}/ranz/control/v1/control.pb.c"
  "${_ranz_controlpb}/ranz/control/v1/control.pb.h"
  # The policy of the VRFs in a desired state (SDN-8, #184)
  ControlPolicy.c
  ControlPolicy.h
  # The WireGuard Devices of a state and the counters of a gateway (SDN-80, #375)
  ControlDevice.c
  # The endpoints of a node and of its peers in a desired state (SDN-93, #410)
  ControlEndpoint.c
  # The kinds of the links of the VRFs and the tunnel endpoints in a desired state (SDN-76, #356)
  ControlLink.c
  # The security of the L2 Networks in a desired state (SDN-41, #234)
  ControlSecurity.c
  # The events of the node that the client reports (AUD1-DT-11, #459)
  ControlEvent.c
  # The source groups in a desired state and the counters of a node by tag mode (SDN-87, #386)
  ControlSourceGroup.c
  # The Relays of a desired state and the Signals of the peers on the control stream (CORE-S5-5, #411)
  ControlSignal.c
  # The hubs and the ECMP of the VRFs, the LAN subnets of a node and the gateways that are down in a desired state (SDN-19,
  # #195)
  ControlGateway.c
  # The BGP peering of a desired state and the report of the node, and the copy of a state that its peering keeps (SDN-77, #357)
  ControlPeering.c
  ControlCopy.c
  # The session profiles of a node and of its peers in a desired state (SDN-40, #233)
  ControlProfile.c
  # The VRFs whose internet exit a node is in a desired state (SDN-12, #188)
  ControlEgress.c
  # The Upgrades and the Fallbacks of the Paths of the peer agent that the client reports (CORE-S5-6, #412)
  ControlPath.c
  # The counters of the EVPN of a gateway that the client reports (SDN-25-R3, #571)
  ControlEvpn.c
  # The live operations of the Controller on the tables of the L2 Networks (SDN-50-N, #492)
  ControlOperation.c
  # The L3 Networks that split TCP in a desired state (CORE-P2-3, #94)
  ControlSplit.c
)

target_include_directories(corecontrol PRIVATE "${_ranz_controlpb}")
target_link_libraries(corecontrol PUBLIC coretransport)
target_link_libraries(corecontrol PRIVATE nanopb ranz_core_options ranz_warnings)

set_target_properties(corecontrol
  PROPERTIES
  ARCHIVE_OUTPUT_DIRECTORY "${BUILD_DIRECTORY}"
  LIBRARY_OUTPUT_DIRECTORY "${BUILD_DIRECTORY}"
  RUNTIME_OUTPUT_DIRECTORY "${BUILD_DIRECTORY}"
  COMPILE_PDB_NAME "corecontrol"
  COMPILE_PDB_OUTPUT_DIRECTORY "${BUILD_DIRECTORY}"
)

# corecontrolpb: the messages of the control stream for a test that stands in for the controller (the relay path test of
# vpntest, src/vpntest/relaypathtest.c; CORE-S5-5, #411): the headers that nanopb generates, with nanopb and corecontrol,
# whose build generates them
add_library(corecontrolpb INTERFACE)
target_include_directories(corecontrolpb INTERFACE "${_ranz_controlpb}")
target_link_libraries(corecontrolpb INTERFACE corecontrol nanopb)

# corevxlan: the VXLAN module (Vxlan.h, Vxlan*.c; SDN-62, #289): a frame encapsulated with its VNI towards one VTEP or
# each VTEP of a flood list, and decapsulated by VNI, on Winsock, which is all it links. It is written once for the
# Mirrors (SDN-23) and the EVPN gateway (SDN-25) of the Node module, so ranz_core_options and the library stay PRIVATE,
# as for corepeer.
file(GLOB SOURCES_CORE_VXLAN "Vxlan*.c")
file(GLOB HEADERS_CORE_VXLAN "Vxlan*.h")

add_library(corevxlan STATIC ${SOURCES_CORE_VXLAN} ${HEADERS_CORE_VXLAN})

target_include_directories(corevxlan PUBLIC "${TOP_DIRECTORY}/src")

target_link_libraries(corevxlan PRIVATE ranz_core_options ranz_warnings)

# The only library the module calls
target_link_libraries(corevxlan PRIVATE "ws2_32.lib")

set_target_properties(corevxlan
  PROPERTIES
  ARCHIVE_OUTPUT_DIRECTORY "${BUILD_DIRECTORY}"
  LIBRARY_OUTPUT_DIRECTORY "${BUILD_DIRECTORY}"
  RUNTIME_OUTPUT_DIRECTORY "${BUILD_DIRECTORY}"
  COMPILE_PDB_NAME "corevxlan"
  COMPILE_PDB_OUTPUT_DIRECTORY "${BUILD_DIRECTORY}"
)

# coreswitch: the switch module (Switch.h, Switch*.c; CORE-S4-1, #74): the VLAN-aware L2 switch of an L2 Network, the
# forwarding plane of the new core in place of the forwarding of the Hub and its hub-wide lock. It calls bcrypt for the
# random key of its MAC table, and the policy engine for the security of an L2 Network, and nothing else. The programs of
# the slim fork that link it (vpntest, the fuzz targets) keep their own build options, so ranz_core_options and the
# libraries stay PRIVATE, as for corepeer.
file(GLOB SOURCES_CORE_SWITCH "Switch*.c")
file(GLOB HEADERS_CORE_SWITCH "Switch*.h")

add_library(coreswitch STATIC ${SOURCES_CORE_SWITCH} ${HEADERS_CORE_SWITCH})

target_include_directories(coreswitch PUBLIC "${TOP_DIRECTORY}/src")

target_link_libraries(coreswitch PRIVATE ranz_core_options ranz_warnings)

# The only system library the module calls
target_link_libraries(coreswitch PRIVATE "bcrypt.lib")

# The security of an L2 Network (SwitchSecurity.c; SDN-41, #234) makes the policy engine the filter of a switch
target_link_libraries(coreswitch PRIVATE corepolicy)

set_target_properties(coreswitch
  PROPERTIES
  ARCHIVE_OUTPUT_DIRECTORY "${BUILD_DIRECTORY}"
  LIBRARY_OUTPUT_DIRECTORY "${BUILD_DIRECTORY}"
  RUNTIME_OUTPUT_DIRECTORY "${BUILD_DIRECTORY}"
  COMPILE_PDB_NAME "coreswitch"
  COMPILE_PDB_OUTPUT_DIRECTORY "${BUILD_DIRECTORY}"
)

# corepolicy: the policy engine (Policy.h, Policy*.c; CORE-S4-2, #75): the stateful, identity-based firewall of the
# Networks of a Node, with the isolation set of the fork, beside the switch module. It parses its JSON documents of rules
# with cJSON (vcpkg, MIT), as Cedar parses the pipe of the BGP sidecar: Windows has no JSON parser for C outside the
# Windows Runtime. It reads the addresses of the rules with Winsock's inet_pton and calls bcrypt for the random key of
# its conntrack tables. The programs of the slim fork that link it (vpntest, the fuzz targets) keep their own build
# options, so ranz_core_options and the libraries stay PRIVATE, as for coreswitch.
file(GLOB SOURCES_CORE_POLICY "Policy*.c")
file(GLOB HEADERS_CORE_POLICY "Policy*.h")

add_library(corepolicy STATIC ${SOURCES_CORE_POLICY} ${HEADERS_CORE_POLICY})

target_include_directories(corepolicy PUBLIC "${TOP_DIRECTORY}/src")

target_link_libraries(corepolicy PRIVATE ranz_core_options ranz_warnings)

# The include directory is found from the header, so the include line is <cjson/cJSON.h> whatever directory the
# package config exports (src/Cedar/CMakeLists.txt does the same)
find_package(cJSON CONFIG REQUIRED)
find_path(RANZ_CJSON_INCLUDE_DIR "cjson/cJSON.h" REQUIRED)
target_include_directories(corepolicy PRIVATE "${RANZ_CJSON_INCLUDE_DIR}")

# The only libraries the module calls
target_link_libraries(corepolicy
  PRIVATE
    cjson
    "bcrypt.lib"
    "ws2_32.lib"
)

set_target_properties(corepolicy
  PROPERTIES
  ARCHIVE_OUTPUT_DIRECTORY "${BUILD_DIRECTORY}"
  LIBRARY_OUTPUT_DIRECTORY "${BUILD_DIRECTORY}"
  RUNTIME_OUTPUT_DIRECTORY "${BUILD_DIRECTORY}"
  COMPILE_PDB_NAME "corepolicy"
  COMPILE_PDB_OUTPUT_DIRECTORY "${BUILD_DIRECTORY}"
)

# corefrontdoor: the front door (FrontDoor.h, FrontDoor*.c; SDN-29, #205; ADR-0035): the TCP listener of a node, on 443
# in a deployment, that peeks the first bytes of each connection, routes it by its ClientHello or its first bytes and
# hands the socket to its owner, in this process or in another through the owner's handoff pipe (WSADuplicateSocketW),
# and the owner's end of that pipe. It calls Winsock, and advapi32 for the security descriptor of a pipe, and nothing
# else. Its users keep their own build options, so ranz_core_options and the libraries stay PRIVATE, as for corepeer.
file(GLOB SOURCES_CORE_FRONT_DOOR "FrontDoor*.c")
file(GLOB HEADERS_CORE_FRONT_DOOR "FrontDoor*.h")

add_library(corefrontdoor STATIC ${SOURCES_CORE_FRONT_DOOR} ${HEADERS_CORE_FRONT_DOOR})

target_include_directories(corefrontdoor PUBLIC "${TOP_DIRECTORY}/src")

target_link_libraries(corefrontdoor PRIVATE ranz_core_options ranz_warnings)

# The only libraries the module calls
target_link_libraries(corefrontdoor
  PRIVATE
    "ws2_32.lib"
    "advapi32.lib"
)

set_target_properties(corefrontdoor
  PROPERTIES
  ARCHIVE_OUTPUT_DIRECTORY "${BUILD_DIRECTORY}"
  LIBRARY_OUTPUT_DIRECTORY "${BUILD_DIRECTORY}"
  RUNTIME_OUTPUT_DIRECTORY "${BUILD_DIRECTORY}"
  COMPILE_PDB_NAME "corefrontdoor"
  COMPILE_PDB_OUTPUT_DIRECTORY "${BUILD_DIRECTORY}"
)

# coresourcelimit: the limits for a source (SourceLimit.h, SourceLimit*.c; AUD1-DT-3, #451): the caps on the connections that
# have not finished their handshake, in all and for one source, and the rates of new connections and of handshake attempts
# of a source, which the front door and the QUIC transport of the Listener of a node each hold. It calls Winsock only for
# the types of an address and links nothing. Its users keep their own build options, so ranz_core_options stays PRIVATE.
file(GLOB SOURCES_CORE_SOURCE_LIMIT "SourceLimit*.c")
file(GLOB HEADERS_CORE_SOURCE_LIMIT "SourceLimit*.h")

add_library(coresourcelimit STATIC ${SOURCES_CORE_SOURCE_LIMIT} ${HEADERS_CORE_SOURCE_LIMIT})

target_include_directories(coresourcelimit PUBLIC "${TOP_DIRECTORY}/src")

target_link_libraries(coresourcelimit PRIVATE ranz_core_options ranz_warnings)

set_target_properties(coresourcelimit
  PROPERTIES
  ARCHIVE_OUTPUT_DIRECTORY "${BUILD_DIRECTORY}"
  LIBRARY_OUTPUT_DIRECTORY "${BUILD_DIRECTORY}"
  RUNTIME_OUTPUT_DIRECTORY "${BUILD_DIRECTORY}"
  COMPILE_PDB_NAME "coresourcelimit"
  COMPILE_PDB_OUTPUT_DIRECTORY "${BUILD_DIRECTORY}"
)

# The front door and the QUIC transport limit their sources with it
target_link_libraries(corefrontdoor PRIVATE coresourcelimit)
target_link_libraries(coretransport PRIVATE coresourcelimit)

# ranz_core_check_links(<target>...): stops the configure when one of the targets reaches,
# through any chain of linked targets, the slim fork (mayaqua, cedar), OpenSSL or liboqs, which
# the new core does not link (ADR-0022; CORE-F1, #61). src/CMakeLists.txt calls it once every
# target exists. The CI step "Core links no OpenSSL or liboqs" checks the linker map of coretest
# for the same.
function(ranz_core_check_links)
  foreach(_ranz_root IN LISTS ARGN)
    set(_ranz_seen "")
    set(_ranz_todo "${_ranz_root}")
    while(_ranz_todo)
      list(POP_FRONT _ranz_todo _ranz_target)
      if(_ranz_target IN_LIST _ranz_seen)
        continue()
      endif()
      list(APPEND _ranz_seen "${_ranz_target}")

      foreach(_ranz_property LINK_LIBRARIES INTERFACE_LINK_LIBRARIES)
        get_target_property(_ranz_libraries "${_ranz_target}" ${_ranz_property})
        if(NOT _ranz_libraries)
          continue()
        endif()

        foreach(_ranz_library IN LISTS _ranz_libraries)
          # A PRIVATE library of a static library is recorded as $<LINK_ONLY:name>
          string(REGEX REPLACE "^\\$<LINK_ONLY:(.+)>$" "\\1" _ranz_library "${_ranz_library}")
          if(_ranz_library MATCHES "^(mayaqua|cedar|oqs|oqsprovider)$" OR _ranz_library MATCHES "^OpenSSL::|openssl|libcrypto|libssl|liboqs")
            message(FATAL_ERROR "${_ranz_root} links ${_ranz_library} (through ${_ranz_target}): "
              "the new core links no OpenSSL, no liboqs and nothing of the slim fork")
          endif()
          if(TARGET "${_ranz_library}")
            list(APPEND _ranz_todo "${_ranz_library}")
          endif()
        endforeach()
      endforeach()
    endwhile()
    message(STATUS "${_ranz_root}: links no OpenSSL, no liboqs, no mayaqua or cedar")
  endforeach()
endfunction()
