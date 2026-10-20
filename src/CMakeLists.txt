# The project's definitions and include path come from the targets, not from this directory:
# ranz_options (cmake/RanzOptions.cmake) and the src root that mayaqua exports
# (src/Mayaqua/CMakeLists.txt), so the vendored targets get neither

if(NOT CMAKE_SIZEOF_VOID_P EQUAL 8)
  message(FATAL_ERROR "Ranz VPN builds for x64 and arm64 only")
endif()

if(WIN32)
  if(CMAKE_C_COMPILER_ID STREQUAL "MSVC")
    # cl.exe only. clang-cl takes /Qspectre and ignores it with a warning, so it is not set for
    # clang-cl: docs/adr/0024-clang-cl-spectre.md
    message("Setting QSPECTRE")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} /Qspectre")
  else()
    message(STATUS "No /Qspectre with ${CMAKE_C_COMPILER_ID}: docs/adr/0024-clang-cl-spectre.md")
  endif()

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

# libFuzzer targets (RANZ_FUZZ=ON only)
if(RANZ_FUZZ)
  add_subdirectory(fuzz)
endif()
