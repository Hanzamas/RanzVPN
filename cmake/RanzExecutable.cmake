# RanzExecutable.cmake
# ranz_add_executable(): every executable of the project (ranz-node, vpntest, coretest and the fuzz
# targets) is created by this one function.
#
# ranz_add_executable(<name> [WIN32] [HAMCORE] [CORE]
#   DESCRIPTION <text>          FileDescription and ProductName, after the project name
#   [ICON <file>]               the application icon, relative to the calling directory
#   SOURCES <file>...           the C sources and headers
#   [C_DEFINITIONS <def>...]    definitions for the C sources only, not for the resource scripts
#   [LINK_OPTIONS <option>...]  extra linker options
#   [LIBRARIES <library>...]    further libraries to link
# )
#
# Each executable gets:
# - the version resource and the icon, from the template src/BuildFiles/VerScript/ver.rc.in:
#   English (United States), language 0x0409
# - the manifest src/BuildFiles/Manifests/common.manifest
# - cedar, and through it mayaqua; ranz_options (cmake/RanzOptions.cmake). With CORE, a program of
#   the new core (src/coretest): ranz_core_options instead, and neither cedar nor mayaqua, so it
#   links only its LIBRARIES and the system libraries
# - the project's compiler warnings (ranz_warnings, cmake/RanzWarnings.cmake)
# - with HAMCORE, the hamcore files as resources (ranz_hamcore_resources, cmake/RanzResources.cmake)
# - its .exe and .pdb in the build directory
# WIN32 makes a Windows GUI subsystem executable, as add_executable(<name> WIN32 ...) does.

set(RANZ_VERSION_RESOURCE_TEMPLATE "${TOP_DIRECTORY}/src/BuildFiles/VerScript/ver.rc.in")
set(RANZ_EXECUTABLE_MANIFEST "${TOP_DIRECTORY}/src/BuildFiles/Manifests/common.manifest")

function(ranz_add_executable name)
  cmake_parse_arguments(PARSE_ARGV 1 _ranz "WIN32;HAMCORE;CORE" "DESCRIPTION;ICON" "SOURCES;C_DEFINITIONS;LINK_OPTIONS;LIBRARIES")
  if(_ranz_UNPARSED_ARGUMENTS)
    message(FATAL_ERROR "ranz_add_executable(${name}): unknown arguments: ${_ranz_UNPARSED_ARGUMENTS}")
  endif()
  if(NOT _ranz_DESCRIPTION OR NOT _ranz_SOURCES)
    message(FATAL_ERROR "ranz_add_executable(${name}): DESCRIPTION and SOURCES are required")
  endif()

  # The variables that ver.rc.in names, besides the project version and DATE_YEAR
  set(COMPONENT_NAME "${_ranz_DESCRIPTION}")
  set(COMPONENT_INTERNAL_NAME "${name}")
  set(COMPONENT_FILE_NAME "${name}.exe")
  set(RANZ_EXECUTABLE_ICON "")
  if(_ranz_ICON)
    set(_ranz_icon_path "${CMAKE_CURRENT_SOURCE_DIR}/${_ranz_ICON}")
    set(RANZ_EXECUTABLE_ICON "1 ICON \"${_ranz_icon_path}\"")
  endif()

  # One script per executable: the fuzz targets share a directory
  set(_ranz_rc_path "${CMAKE_CURRENT_BINARY_DIR}/${name}_ver.rc")
  configure_file("${RANZ_VERSION_RESOURCE_TEMPLATE}" "${_ranz_rc_path}")
  if(_ranz_ICON)
    # The resource compiler's dependency scan sees #include only, not the icon file
    set_source_files_properties("${_ranz_rc_path}" PROPERTIES OBJECT_DEPENDS "${_ranz_icon_path}")
  endif()

  set(_ranz_subsystem "")
  if(_ranz_WIN32)
    set(_ranz_subsystem WIN32)
  endif()
  add_executable(${name} ${_ranz_subsystem} ${_ranz_SOURCES} "${_ranz_rc_path}" "${RANZ_EXECUTABLE_MANIFEST}")

  set_target_properties(${name}
    PROPERTIES
    ARCHIVE_OUTPUT_DIRECTORY "${BUILD_DIRECTORY}"
    LIBRARY_OUTPUT_DIRECTORY "${BUILD_DIRECTORY}"
    RUNTIME_OUTPUT_DIRECTORY "${BUILD_DIRECTORY}"
    PDB_OUTPUT_DIRECTORY "${BUILD_DIRECTORY}"
  )

  if(_ranz_CORE)
    target_link_libraries(${name} PRIVATE ${_ranz_LIBRARIES} ranz_core_options ranz_warnings)
  else()
    target_link_libraries(${name} PRIVATE cedar ${_ranz_LIBRARIES} ranz_options ranz_warnings)
  endif()

  foreach(_ranz_definition IN LISTS _ranz_C_DEFINITIONS)
    target_compile_definitions(${name} PRIVATE "$<$<COMPILE_LANGUAGE:C>:${_ranz_definition}>")
  endforeach()

  if(_ranz_LINK_OPTIONS)
    target_link_options(${name} PRIVATE ${_ranz_LINK_OPTIONS})
  endif()

  if(_ranz_HAMCORE)
    ranz_hamcore_resources(${name})
  endif()
endfunction()
