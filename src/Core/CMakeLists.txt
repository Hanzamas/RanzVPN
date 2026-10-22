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
# (PeerIce.c, PeerPortMap.c; CORE-S5-3, #79) on libjuice and libplum. The Node module of Cedar links it too, so
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
    corecrypto
    libjuice
    libplum
    "ws2_32.lib"
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

set_target_properties(coretransport
  PROPERTIES
  ARCHIVE_OUTPUT_DIRECTORY "${BUILD_DIRECTORY}"
  LIBRARY_OUTPUT_DIRECTORY "${BUILD_DIRECTORY}"
  RUNTIME_OUTPUT_DIRECTORY "${BUILD_DIRECTORY}"
  COMPILE_PDB_NAME "coretransport"
  COMPILE_PDB_OUTPUT_DIRECTORY "${BUILD_DIRECTORY}"
)

# corecontrol: the control module (Control.h, Control.c; SDN-3, #179): the node's end of the control stream to the
# controller, over the transport module, with the messages that nanopb generates at build time from the one schema of
# the node and the controller, proto/ranz/control/v1/control.proto with its control.options (ADR-0027 decision 1).
# The generator is the one of the nanopb submodule (3rdparty/CMakeLists.txt); it needs Python with the protobuf
# package and protoc on the PATH, as the nanopb round trip of controller.yml does (CI: .github/actions/nanopb). It
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
  "${_ranz_controlpb}/ranz/control/v1/control.pb.c"
  "${_ranz_controlpb}/ranz/control/v1/control.pb.h"
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
