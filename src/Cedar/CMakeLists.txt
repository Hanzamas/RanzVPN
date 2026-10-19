file(GLOB SOURCES_CEDAR "*.c")
file(GLOB HEADERS_CEDAR "*.h")

enable_language(CXX)
file(GLOB SOURCES_CEDAR_CPP "*.cpp")

add_library(cedar STATIC ${SOURCES_CEDAR} ${SOURCES_CEDAR_CPP} ${HEADERS_CEDAR})

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

set_target_properties(cedar
  PROPERTIES
  COMPILE_PDB_NAME "cedar"
  COMPILE_PDB_OUTPUT_DIRECTORY "${BUILD_DIRECTORY}"
)

target_link_libraries(cedar PRIVATE comctl32.lib urlmon.lib winhttp.lib)

# Version
target_compile_definitions(cedar PRIVATE CEDAR_VERSION_MAJOR=${PROJECT_VERSION_MAJOR} CEDAR_VERSION_MINOR=${PROJECT_VERSION_MINOR} CEDAR_VERSION_BUILD=${PROJECT_VERSION_PATCH})

# Builder
target_compile_definitions(cedar PRIVATE BUILDER_NAME="$ENV{USERNAME}")

cmake_host_system_information(RESULT BUILDER_HOSTNAME QUERY HOSTNAME)

target_compile_definitions(cedar PRIVATE BUILD_PLACE="${BUILDER_HOSTNAME}")

# Remove leading 0 from date and time
string(REGEX REPLACE "^0([^ ]*)" "\\1" BUILD_DAY "${DATE_DAY}")
string(REGEX REPLACE "^0([^ ]*)" "\\1" BUILD_MONTH "${DATE_MONTH}")
string(REGEX REPLACE "^0([^ ]*)" "\\1" BUILD_YEAR "${DATE_YEAR}")
string(REGEX REPLACE "^0([^ ]*)" "\\1" BUILD_HOUR "${TIME_HOUR}")
string(REGEX REPLACE "^0([^ ]*)" "\\1" BUILD_MINUTE "${TIME_MINUTE}")
string(REGEX REPLACE "^0([^ ]*)" "\\1" BUILD_SECOND "${TIME_SECOND}")

target_compile_definitions(cedar PRIVATE BUILD_DATE_D=${BUILD_DAY} BUILD_DATE_M=${BUILD_MONTH} BUILD_DATE_Y=${BUILD_YEAR})
target_compile_definitions(cedar PRIVATE BUILD_DATE_HO=${BUILD_HOUR} BUILD_DATE_MI=${BUILD_MINUTE} BUILD_DATE_SE=${BUILD_SECOND})
