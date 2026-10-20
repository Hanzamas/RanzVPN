# The project's definitions and include path come from the targets, not from this directory:
# ranz_options (cmake/RanzOptions.cmake) and the src root that mayaqua exports
# (src/Mayaqua/CMakeLists.txt), so the vendored targets get neither

if(NOT CMAKE_SIZEOF_VOID_P EQUAL 8)
  message(FATAL_ERROR "Ranz VPN builds for x64 and arm64 only")
endif()

if(WIN32)
  message("Setting QSPECTRE")
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} /Qspectre")

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

# Unused-code warnings (RANZ_UNUSED_WARNINGS=ON, cmake/RanzWarnings.cmake): the project's own targets
# only. The executables get them from ranz_add_executable (cmake/RanzExecutable.cmake).
ranz_unused_warnings(cedar mayaqua)

# libFuzzer targets (RANZ_FUZZ=ON only)
if(RANZ_FUZZ)
  add_subdirectory(fuzz)
endif()
