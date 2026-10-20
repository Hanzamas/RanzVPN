set(COMPONENT_NAME "Server")
set(COMPONENT_INTERNAL_NAME "vpnserver")

add_executable(vpnserver WIN32
  "vpnserver.c"

  "${TOP_DIRECTORY}/src/BuildFiles/Manifests/common.manifest"
)

set_target_properties(vpnserver
  PROPERTIES
  PDB_OUTPUT_DIRECTORY "${BUILD_DIRECTORY}"
)

get_filename_component(COMPONENT_FILE_NAME vpnserver NAME)
set(COMPONENT_FILE_NAME "${COMPONENT_FILE_NAME}.exe")

configure_file("${TOP_DIRECTORY}/src/BuildFiles/VerScript/ver.rc" "${CMAKE_CURRENT_BINARY_DIR}/ver.rc")
target_sources(vpnserver PRIVATE "vpnserver.rc" "${CMAKE_CURRENT_BINARY_DIR}/ver.rc")

# The hamcore files, as resources (cmake/RanzResources.cmake)
ranz_hamcore_resources(vpnserver)

set_target_properties(vpnserver
  PROPERTIES
  ARCHIVE_OUTPUT_DIRECTORY "${BUILD_DIRECTORY}"
  LIBRARY_OUTPUT_DIRECTORY "${BUILD_DIRECTORY}"
  RUNTIME_OUTPUT_DIRECTORY "${BUILD_DIRECTORY}"
)

target_link_libraries(vpnserver PRIVATE cedar ranz_warnings)
