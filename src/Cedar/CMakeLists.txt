file(GLOB SOURCES_CEDAR "*.c")
file(GLOB HEADERS_CEDAR "*.h")

if(WIN32)
  enable_language(CXX)
  file(GLOB SOURCES_CEDAR_CPP "*.cpp")
endif()

if(WIN32)
  add_library(cedar STATIC ${SOURCES_CEDAR} ${SOURCES_CEDAR_CPP} ${HEADERS_CEDAR})
endif()

if(MSVC)
  target_compile_options(cedar PRIVATE /EHsc)
elseif(CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
  if(CMAKE_CXX_COMPILER_FRONTEND_VARIANT STREQUAL "MSVC")
    target_compile_options(cedar PRIVATE /EHsc)
  else()
    target_compile_options(cedar PRIVATE -fexceptions)
  endif()
endif()
set_target_properties(cedar
  PROPERTIES
  ARCHIVE_OUTPUT_DIRECTORY "${BUILD_DIRECTORY}"
  LIBRARY_OUTPUT_DIRECTORY "${BUILD_DIRECTORY}"
  RUNTIME_OUTPUT_DIRECTORY "${BUILD_DIRECTORY}"
)

target_link_libraries(cedar PUBLIC mayaqua)

if(WIN32)
  set_target_properties(cedar
    PROPERTIES
    COMPILE_PDB_NAME "cedar"
    COMPILE_PDB_OUTPUT_DIRECTORY "${BUILD_DIRECTORY}"
  )

  target_link_libraries(cedar PRIVATE comctl32.lib urlmon.lib winhttp.lib)
endif()

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
