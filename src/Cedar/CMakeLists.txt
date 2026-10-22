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
# INetCfg GUIDs (Win32Com.c), CoTaskMemFree and FOLDERID_ProgramData (Node.c); winhttp.lib: the HTTP
# client of Protocol.c; winsqlite3.lib: the SQLite of System32 (ConfigStore.c, ADR-0022); bcrypt.lib:
# BCryptDeriveKeyPBKDF2 and crypt32.lib: the certificate subject and thumbprint (ConfigStore.c);
# iphlpapi.lib: the learned routes of the BGP sidecar and ParseNetworkString (NodeBgp.c), which also
# takes the pipe name's nonce from bcrypt.lib
target_link_libraries(cedar PRIVATE bcrypt.lib crypt32.lib iphlpapi.lib ole32.lib setupapi.lib uuid.lib winhttp.lib winsqlite3.lib)

# cJSON (vcpkg, MIT): the JSON messages of the pipe to the BGP sidecar ranz-bgp (NodeBgp.c, CORE-S7-1 #82).
# Windows has no JSON parser for C outside the Windows Runtime. The include directory is found from the
# header, so the include line is <cjson/cJSON.h> whatever directory the package config exports.
find_package(cJSON CONFIG REQUIRED)
find_path(RANZ_CJSON_INCLUDE_DIR "cjson/cJSON.h" REQUIRED)
target_include_directories(cedar PRIVATE "${RANZ_CJSON_INCLUDE_DIR}")
target_link_libraries(cedar PRIVATE cjson)

# Build identity: version, build time and builder in one generated BuildInfo.h. Only the files that
# print it include it (Cedar.c, Admin.c, Server.c, Command.c), so a new stamp rebuilds those four
# and not the whole library. configure_file leaves the header alone when its content is the same.
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
