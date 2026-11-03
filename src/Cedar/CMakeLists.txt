file(GLOB SOURCES_CEDAR "*.c")
file(GLOB HEADERS_CEDAR "*.h")

add_library(cedar STATIC ${SOURCES_CEDAR} ${HEADERS_CEDAR})

set_target_properties(cedar
  PROPERTIES
  ARCHIVE_OUTPUT_DIRECTORY "${BUILD_DIRECTORY}"
  LIBRARY_OUTPUT_DIRECTORY "${BUILD_DIRECTORY}"
  RUNTIME_OUTPUT_DIRECTORY "${BUILD_DIRECTORY}"
)

target_link_libraries(cedar PUBLIC mayaqua)

# The warning flags of the project's own code (cmake/RanzWarnings.cmake); PRIVATE: they stay on Cedar
target_link_libraries(cedar PRIVATE ranz_warnings)

set_target_properties(cedar
  PROPERTIES
  COMPILE_PDB_NAME "cedar"
  COMPILE_PDB_OUTPUT_DIRECTORY "${BUILD_DIRECTORY}"
)

# A Windows library sits on the target whose sources call it. setupapi.lib: SetupCopyOEMInfW and
# SetupUninstallOEMInf* (SeLowUser.c, Win32Com.c); ole32.lib and uuid.lib: CoCreateInstance and the
# INetCfg GUIDs (Win32Com.c), CoTaskMemFree and FOLDERID_ProgramData (Node.c); winsqlite3.lib: the
# SQLite of System32 (ConfigStore.c, ADR-0022); bcrypt.lib: BCryptDeriveKeyPBKDF2 and crypt32.lib:
# the certificate subject and thumbprint (ConfigStore.c);
# iphlpapi.lib: the learned routes of the BGP sidecar and ParseNetworkString (NodeBgp.c), which also
# takes the pipe name's nonce from bcrypt.lib, and the addresses, routes and address changes of the client role
# (NodeClient.c, NodeWintun.c); powrprof.lib: the suspend and resume events of the client role
target_link_libraries(cedar PRIVATE bcrypt.lib crypt32.lib iphlpapi.lib ole32.lib powrprof.lib setupapi.lib uuid.lib winsqlite3.lib)

# fwpuclnt.lib: the Windows Filtering Platform, whose filters keep two WireGuard Devices of a gateway apart
# (NodeWireGuardFilter.c; SDN-80, #375)
target_link_libraries(cedar PRIVATE fwpuclnt.lib)

# oleaut32.lib: the BSTRs and VARIANTs of the WMI calls through which the internet exit creates its NAT network of WinNAT
# (NodeEgressNat.c; SDN-12, #188), with the COM of ole32.lib above. The mprapi.dll of its RRAS NAT is loaded at run time.
target_link_libraries(cedar PRIVATE oleaut32.lib)

# The L2 adapter of the Node module (NodeL2*.c, NodeKmTest.c; CORE-S3-2, #72): newdev.lib for
# UpdateDriverForPlugAndPlayDevicesW, which installs the driver of a new KM-TEST Loopback Adapter, and ntdll.lib for
# NtCreateFile and NtDeviceIoControlFile, through which the header-only API of XDP for Windows drives the XDP driver
target_link_libraries(cedar PRIVATE newdev.lib ntdll.lib)

# The XDP for Windows SDK (Microsoft.XDP-for-Windows.Sdk, MIT) of the XDP backend of the L2 adapter: its headers, for
# NodeL2Xdp.c alone, with the header-only API of XDP_API_VERSION 3, so nothing of the package is linked or shipped (the
# runtime is the one that ranz install installs, ONE-3 #312). The package is pinned by its version and the SHA-512 that
# NuGet records for it, and downloaded at configure time into the build tree, as vcpkg fetches its ports; a configure
# without the network names an extracted package with RANZ_XDP_SDK_DIR instead.
set(RANZ_XDP_SDK_VERSION "1.4.0")
set(RANZ_XDP_SDK_SHA512 "bdc2ccdad3f2ea7fb0d66b66da10f5fc6348d1e3ab9e34adea736b9b7f70c377e5922fffa20085a8b39115b1d96457d98af1329f38ca0c9b41a3c63ec47ec633")
set(RANZ_XDP_SDK_DIR "$ENV{RANZ_XDP_SDK_DIR}" CACHE PATH "An extracted Microsoft.XDP-for-Windows.Sdk package; empty to download the pinned one")
set(_ranz_xdp_sdk "${RANZ_XDP_SDK_DIR}")
if(NOT _ranz_xdp_sdk)
  set(_ranz_xdp_sdk "${CMAKE_BINARY_DIR}/_deps/xdp-sdk-${RANZ_XDP_SDK_VERSION}")
  if(NOT EXISTS "${_ranz_xdp_sdk}/build/native/include/afxdp.h")
    set(_ranz_xdp_package "${CMAKE_BINARY_DIR}/_deps/xdp-sdk-${RANZ_XDP_SDK_VERSION}.zip")
    file(DOWNLOAD
      "https://api.nuget.org/v3-flatcontainer/microsoft.xdp-for-windows.sdk/${RANZ_XDP_SDK_VERSION}/microsoft.xdp-for-windows.sdk.${RANZ_XDP_SDK_VERSION}.nupkg"
      "${_ranz_xdp_package}"
      EXPECTED_HASH SHA512=${RANZ_XDP_SDK_SHA512}
      TLS_VERIFY ON
      STATUS _ranz_xdp_status)
    list(GET _ranz_xdp_status 0 _ranz_xdp_code)
    if(NOT _ranz_xdp_code EQUAL 0)
      message(FATAL_ERROR "The XDP SDK ${RANZ_XDP_SDK_VERSION} could not be downloaded (${_ranz_xdp_status}). Set RANZ_XDP_SDK_DIR to an extracted Microsoft.XDP-for-Windows.Sdk package instead.")
    endif()
    file(ARCHIVE_EXTRACT INPUT "${_ranz_xdp_package}" DESTINATION "${_ranz_xdp_sdk}" PATTERNS "build/native/include/*")
  endif()
endif()
if(NOT EXISTS "${_ranz_xdp_sdk}/build/native/include/afxdp.h")
  message(FATAL_ERROR "${_ranz_xdp_sdk} holds no build/native/include/afxdp.h of the XDP SDK (CORE-S3-2, #72)")
endif()
message(STATUS "cedar: XDP SDK ${RANZ_XDP_SDK_VERSION} headers at ${_ranz_xdp_sdk}/build/native/include")
set_source_files_properties(NodeL2Xdp.c
  PROPERTIES
    INCLUDE_DIRECTORIES "${_ranz_xdp_sdk}/build/native/include"
    COMPILE_DEFINITIONS "XDP_API_VERSION=3;XDP_INCLUDE_WINCOMMON"
)

# cJSON (vcpkg, MIT): the JSON messages of the pipe to the BGP sidecar ranz-bgp (NodeBgp.c, CORE-S7-1 #82).
# Windows has no JSON parser for C outside the Windows Runtime. The include directory is found from the
# header, so the include line is <cjson/cJSON.h> whatever directory the package config exports.
find_package(cJSON CONFIG REQUIRED)
find_path(RANZ_CJSON_INCLUDE_DIR "cjson/cJSON.h" REQUIRED)
target_include_directories(cedar PRIVATE "${RANZ_CJSON_INCLUDE_DIR}")
target_link_libraries(cedar PRIVATE cjson)

# The peer module of the new core (src/Core/CMakeLists.txt), which the relay role of the Node module runs
# (CORE-S5-2, #78). It keeps the build options of the new core to itself, so Cedar compiles with its own.
target_link_libraries(cedar PRIVATE corepeer)

# The policy engine of the new core, which judges the packets of the overlay of the Node module by the rules of their VRF
# (NodePolicy.c; SDN-8, #184). It keeps the build options of the new core to itself, as corepeer does.
target_link_libraries(cedar PRIVATE corepolicy)

# The control module of the new core, the control stream of the overlay of the Node module (NodeOverlay.c; SDN-3,
# #179), with the transport and session modules it runs on. Its nanopb messages stay inside it.
target_link_libraries(cedar PRIVATE corecontrol)

# The VXLAN module of the new core, which sends the copies of the Mirrors of the Node module to their sensors
# (NodeMirror.c; SDN-23, #199)
target_link_libraries(cedar PRIVATE corevxlan)

# The switch module of the new core, whose switch of an L2 Network the DHCP responder of the Node module joins as a
# member (NodeDhcp.c; SDN-43, #236). It keeps the build options of the new core to itself, as corepeer does.
target_link_libraries(cedar PRIVATE coreswitch)

# The front door of the new core, which the Listener of the Node module starts on the TCP port of its desired state and
# which hands each TLS connection to the node's TLS transport (NodeListener.c; SDN-45, #238). It keeps the build options
# of the new core to itself, as corepeer does.
target_link_libraries(cedar PRIVATE corefrontdoor)

# Build identity: version, build time and builder in one generated BuildInfo.h. Only the file that
# prints it includes it (Cedar.c), so a new stamp rebuilds that file and not the whole library.
# configure_file leaves the header alone when its content is the same.
option(RANZ_EMBED_BUILDER "Put the builder's user and host name in the build info string. Off by default: they differ per machine, so the build is not reproducible." OFF)

if(RANZ_EMBED_BUILDER)
  cmake_host_system_information(RESULT BUILDER_HOSTNAME QUERY HOSTNAME)
  set(BUILD_BUILDER_NAME "$ENV{USERNAME}")
  set(BUILD_BUILDER_PLACE "${BUILDER_HOSTNAME}")
endif()
if("${BUILD_BUILDER_NAME}" STREQUAL "")
  set(BUILD_BUILDER_NAME "Unknown")
endif()
if("${BUILD_BUILDER_PLACE}" STREQUAL "")
  set(BUILD_BUILDER_PLACE "Unknown")
endif()

# The stamp (year, month, day, hour, minute, second) without leading zeros, so C does not read
# 08 as an octal number.
string(REGEX MATCHALL "[0-9]+" BUILD_STAMP_PARTS "${BUILD_STAMP}")
set(BUILD_STAMP_INDEX 0)
foreach(BUILD_STAMP_FIELD YEAR MONTH DAY HOUR MINUTE SECOND)
  list(GET BUILD_STAMP_PARTS ${BUILD_STAMP_INDEX} BUILD_STAMP_PART)
  string(REGEX REPLACE "^0([0-9])" "\\1" BUILD_${BUILD_STAMP_FIELD} "${BUILD_STAMP_PART}")
  math(EXPR BUILD_STAMP_INDEX "${BUILD_STAMP_INDEX} + 1")
endforeach()

configure_file("${CMAKE_CURRENT_SOURCE_DIR}/BuildInfo.h.in" "${CMAKE_CURRENT_BINARY_DIR}/BuildInfo.h" @ONLY)
target_include_directories(cedar PRIVATE "${CMAKE_CURRENT_BINARY_DIR}")
