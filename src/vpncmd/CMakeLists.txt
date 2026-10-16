set(COMPONENT_NAME "Command Line Management Utility")
set(COMPONENT_INTERNAL_NAME "vpncmd")

add_executable(vpncmd vpncmd.c)

set_target_properties(vpncmd
  PROPERTIES
  ARCHIVE_OUTPUT_DIRECTORY "${BUILD_DIRECTORY}"
  LIBRARY_OUTPUT_DIRECTORY "${BUILD_DIRECTORY}"
  RUNTIME_OUTPUT_DIRECTORY "${BUILD_DIRECTORY}"
)

if(WIN32)
  set_target_properties(vpncmd
    PROPERTIES
    PDB_OUTPUT_DIRECTORY "${BUILD_DIRECTORY}"
  )

  get_filename_component(COMPONENT_FILE_NAME vpncmd NAME)
  set(COMPONENT_FILE_NAME "${COMPONENT_FILE_NAME}.exe")

  configure_file("${TOP_DIRECTORY}/src/BuildFiles/VerScript/ver.rc" "${CMAKE_CURRENT_BINARY_DIR}/ver.rc")

  target_sources(vpncmd PRIVATE
    "vpncmd.rc"
    "ver.rc"

    "${TOP_DIRECTORY}/src/BuildFiles/Manifests/common.manifest"
  )

  # The hamcore files, as resources (cmake/RanzResources.cmake)
  ranz_hamcore_resources(vpncmd)
endif()

target_link_libraries(vpncmd cedar)
