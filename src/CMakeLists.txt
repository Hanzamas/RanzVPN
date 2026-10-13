if(BUILD_TYPE STREQUAL "Debug")
  add_definitions(-D_DEBUG -DDEBUG)
else()
  add_definitions(-DNDEBUG -DVPN_SPEED)
endif()

if(CMAKE_SIZEOF_VOID_P EQUAL 8)
  add_definitions(-DCPU_64)
endif()

add_definitions(-D_REENTRANT -DREENTRANT -D_THREAD_SAFE -D_THREADSAFE -DTHREAD_SAFE -DTHREADSAFE -D_FILE_OFFSET_BITS=64)

# Add /src to the include paths
include_directories(.)

if(WIN32)
  if(IS_CROSS_COMPILATION MATCHES "arm64-on-x64")
    set(CMAKE_SYSTEM_PROCESSOR "arm64")
  else()
    message("Setting QSPECTRE")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} /Qspectre")
  endif()
  add_definitions(-DWIN32 -D_WINDOWS -DOS_WIN32 -D_CRT_SECURE_NO_WARNINGS)

  #
  # https://msrc-blog.microsoft.com/2020/08/17/control-flow-guard-for-clang-llvm-and-rust/
  #

  message("Setting CONTROL FLOW GUARD") 
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} /guard:cf")
  set(CMAKE_EXE_LINKER_FLAGS  "${CMAKE_EXE_LINKER_FLAGS} /guard:cf /DYNAMICBASE")

  message("Setting CETCOMPAT")
  set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} /CETCOMPAT")

endif()

# Cedar communication module
add_subdirectory(Cedar)

# Mayaqua kernel
add_subdirectory(Mayaqua)

# vpnserver
add_subdirectory(vpnserver)

# vpncmd
add_subdirectory(vpncmd)

# vpntest
add_subdirectory(vpntest)

# Unused-code warnings (RANZ_UNUSED_WARNINGS=ON, cmake/RanzWarnings.cmake): the project's own targets only
ranz_unused_warnings(cedar mayaqua vpnserver vpncmd vpntest)

# libFuzzer targets (RANZ_FUZZ=ON only)
if(RANZ_FUZZ)
  add_subdirectory(fuzz)
endif()

# libhamcore
add_subdirectory(libhamcore)

# hamcorebuilder utility
add_subdirectory(hamcorebuilder)

# hamcorebuilder runs during the build: ASan builds need the ASan runtime DLL next to it
if(RANZ_ASAN)
  ranz_copy_asan_dll(hamcorebuilder)
endif()

# hamcore.se2 archive file
add_custom_target(hamcore-archive-build
  ALL
  DEPENDS "${BUILD_DIRECTORY}/hamcore.se2"
)
if(IS_CROSS_COMPILATION MATCHES "arm64-on-x64")
    file(TO_CMAKE_PATH "${TOP_DIRECTORY}" TOP_DIRECTORY_NORM)
    set(X64_HAMCORE_BUILDER
      "${TOP_DIRECTORY_NORM}/out/build/x64-native/src/hamcorebuilder/hamcorebuilder.exe"
    )
    if(EXISTS "${X64_HAMCORE_BUILDER}")
      message(STATUS "file exist (from TOP_DIRECTORY)")
    endif()

  # support cross compile, when you compile ARM64 version on X64 Platform
  if(EXISTS "${X64_HAMCORE_BUILDER}")
    message("X64_HAMCORE_BUILDER found: ${X64_HAMCORE_BUILDER}")
  elseif(EXISTS("${TOP_DIRECTORY}/out/build/x64-native/src/hamcorebuilder/hamcorebuilder.exe"))
    set(X64_HAMCORE_BUILDER "${TOP_DIRECTORY}/out/build/x64-native/src/hamcorebuilder/hamcorebuilder.exe")
  else()
	message("${TOP_DIRECTORY}/out/build/x64-native/src/hamcorebuilder/hamcorebuilder.exe")
    message(FATAL_ERROR "X64_HAMCORE_BUILDER not found: ${X64_HAMCORE_BUILDER}, pls build x64-native version first")
  endif()
  message(STATUS "X64_HAMCORE_BUILDER = ${X64_HAMCORE_BUILDER}")

  add_custom_command(
    COMMENT "Building hamcore.se2 archive file..."
    COMMAND ${X64_HAMCORE_BUILDER} "hamcore.se2" "${TOP_DIRECTORY}/src/bin/hamcore"
    DEPENDS ${X64_HAMCORE_BUILDER} "${TOP_DIRECTORY}/src/bin/hamcore/"
    OUTPUT "${BUILD_DIRECTORY}/hamcore.se2"
    WORKING_DIRECTORY "${BUILD_DIRECTORY}"
    VERBATIM
  )

else()
  add_custom_command(
      COMMENT "Building hamcore.se2 archive file..."
      COMMAND hamcorebuilder "hamcore.se2" "${TOP_DIRECTORY}/src/bin/hamcore"
      DEPENDS hamcorebuilder "${TOP_DIRECTORY}/src/bin/hamcore/"
      OUTPUT "${BUILD_DIRECTORY}/hamcore.se2"
      WORKING_DIRECTORY "${BUILD_DIRECTORY}"
      VERBATIM
  )
endif()

