# The two libraries of the peer module (src/Core/Peer*.c) that ADR-0015 names: libjuice for ICE and libplum for the
# port mapping of home gateways (CORE-S5-3, #79). Both are MPL-2.0 (ADR-0036) and are git submodules at a release
# tag. Each is built here as one static library from its sources, not with its own CMakeLists.txt, which would also
# build a DLL, its tests and an install tree; the lists follow the source lists of the tags, libjuice 1.7.4 and
# libplum 0.6.0. The project's warning flags and build options stay off both (ranz_warnings, ranz_core_options);
# CMAKE_MSVC_RUNTIME_LIBRARY (the static CRT) reaches them as every other target.

set(_ranz_juice "${CMAKE_CURRENT_SOURCE_DIR}/libjuice")
set(_ranz_plum "${CMAKE_CURRENT_SOURCE_DIR}/libplum")
set(_ranz_nanopb "${CMAKE_CURRENT_SOURCE_DIR}/nanopb")

if(NOT EXISTS "${_ranz_juice}/include/juice/juice.h" OR NOT EXISTS "${_ranz_plum}/include/plum/plum.h" OR NOT EXISTS "${_ranz_nanopb}/pb.h")
  message(FATAL_ERROR "The submodules of src/Core/3rdparty are not initialized. Run\n\tgit submodule update --init --recursive")
endif()

# libjuice: ICE (RFC 8445) with host and server reflexive candidates, connectivity checks, consent freshness
# (RFC 7675) as the keepalive of a direct path, and every ICE session of a node on one UDP socket (its mux mode).
# No STUN or TURN server (NO_SERVER), and its own SHA-1 and HMAC (USE_NETTLE=0).
add_library(libjuice STATIC
  "${_ranz_juice}/src/addr.c"
  "${_ranz_juice}/src/agent.c"
  "${_ranz_juice}/src/crc32.c"
  "${_ranz_juice}/src/const_time.c"
  "${_ranz_juice}/src/conn.c"
  "${_ranz_juice}/src/conn_poll.c"
  "${_ranz_juice}/src/conn_thread.c"
  "${_ranz_juice}/src/conn_mux.c"
  "${_ranz_juice}/src/base64.c"
  "${_ranz_juice}/src/hash.c"
  "${_ranz_juice}/src/hmac.c"
  "${_ranz_juice}/src/ice.c"
  "${_ranz_juice}/src/juice.c"
  "${_ranz_juice}/src/log.c"
  "${_ranz_juice}/src/random.c"
  "${_ranz_juice}/src/server.c"
  "${_ranz_juice}/src/stun.c"
  "${_ranz_juice}/src/timestamp.c"
  "${_ranz_juice}/src/tcp.c"
  "${_ranz_juice}/src/turn.c"
  "${_ranz_juice}/src/udp.c"
)

target_include_directories(libjuice
  PUBLIC
    "${_ranz_juice}/include"
  PRIVATE
    "${_ranz_juice}/include/juice"
    "${_ranz_juice}/src"
)

target_compile_definitions(libjuice
  PUBLIC
    JUICE_STATIC
  PRIVATE
    JUICE_EXPORTS
    USE_NETTLE=0
    NO_SERVER
    WIN32_LEAN_AND_MEAN
    NOMINMAX
    _CRT_SECURE_NO_WARNINGS
)

target_link_libraries(libjuice PRIVATE "ws2_32.lib" "bcrypt.lib")

# libplum: port mapping with PCP, NAT-PMP and UPnP IGD, on a client thread of its own.
#
# libjuice and libplum share the names of their address, UDP and clock helpers (addr_*, udp_*, current_timestamp),
# which would clash at the link of every program that has both; libplum's are renamed.
#
# xml_find_matching_child of libplum 0.6.0 (src/util.c) returns a pointer into a copy of the document that it has
# freed, and the UPnP code reads the control URL from there. plum-xml.c holds the same function without that use
# after free; util.c is built with its own one renamed out of the way, so that every caller gets the fixed one.
set(_ranz_plum_renames "")
foreach(_ranz_name
    addr_get_len addr_get_host addr_get_port addr_set_port addr_is_any addr_is_local addr_is_private addr_is_public
    addr_is_temp_inet6 addr_unmap_inet6_v4mapped addr_map_inet6_v4mapped addr_is_equal addr_to_string addr_set
    addr_set_binary addr_resolve addr_record_is_equal addr_record_to_string udp_create_socket udp_recvfrom
    udp_sendto udp_sendto_self udp_set_diffserv udp_get_port udp_get_bound_addr udp_get_local_addr
    current_timestamp)
  list(APPEND _ranz_plum_renames "${_ranz_name}=ranz_plum_${_ranz_name}")
endforeach()

add_library(libplum STATIC
  "${_ranz_plum}/src/addr.c"
  "${_ranz_plum}/src/client.c"
  "${_ranz_plum}/src/dummytls.c"
  "${_ranz_plum}/src/http.c"
  "${_ranz_plum}/src/log.c"
  "${_ranz_plum}/src/natpmp.c"
  "${_ranz_plum}/src/net.c"
  "${_ranz_plum}/src/noprotocol.c"
  "${_ranz_plum}/src/pcp.c"
  "${_ranz_plum}/src/plum.c"
  "${_ranz_plum}/src/random.c"
  "${_ranz_plum}/src/tcp.c"
  "${_ranz_plum}/src/timestamp.c"
  "${_ranz_plum}/src/udp.c"
  "${_ranz_plum}/src/upnp.c"
  "${_ranz_plum}/src/util.c"
  plum-xml.c
)

target_include_directories(libplum
  PUBLIC
    "${_ranz_plum}/include"
  PRIVATE
    "${_ranz_plum}/include/plum"
    "${_ranz_plum}/src"
)

target_compile_definitions(libplum
  PUBLIC
    PLUM_STATIC
  PRIVATE
    PLUM_EXPORTS
    WIN32_LEAN_AND_MEAN
    NOMINMAX
    _CRT_SECURE_NO_WARNINGS
    ${_ranz_plum_renames}
)

set_source_files_properties("${_ranz_plum}/src/util.c"
  PROPERTIES COMPILE_DEFINITIONS "xml_find_matching_child=ranz_plum_unused_xml_find_matching_child"
)

target_link_libraries(libplum PRIVATE "ws2_32.lib" "iphlpapi.lib" "bcrypt.lib")

# nanopb: the protobuf runtime of the C node's control stream (ADR-0022, ADR-0027; SDN-3, #179), zlib licence, a git
# submodule at the release tag nanopb-0.4.9.2, the one whose generator the nanopb round trip of ranz.yml runs.
# The messages of proto/ranz/control/v1/control.proto are generated at build time (src/Core/CMakeLists.txt). An
# Update of control.options is larger than 64 kB, so every user of nanopb gets PB_FIELD_32BIT.
add_library(nanopb STATIC
  "${_ranz_nanopb}/pb_common.c"
  "${_ranz_nanopb}/pb_decode.c"
  "${_ranz_nanopb}/pb_encode.c"
)

target_include_directories(nanopb PUBLIC "${_ranz_nanopb}")
target_compile_definitions(nanopb PUBLIC PB_FIELD_32BIT)

foreach(_ranz_target libjuice libplum nanopb)
  set_target_properties(${_ranz_target}
    PROPERTIES
    ARCHIVE_OUTPUT_DIRECTORY "${BUILD_DIRECTORY}"
    COMPILE_PDB_NAME "${_ranz_target}"
    COMPILE_PDB_OUTPUT_DIRECTORY "${BUILD_DIRECTORY}"
  )
endforeach()
