# The project's definitions and include path come from the targets, not from this directory:
# ranz_options (cmake/RanzOptions.cmake) and the src root that mayaqua exports
# (src/Mayaqua/CMakeLists.txt), so the vendored targets get neither

if(NOT WIN32)
  message(FATAL_ERROR "Ranz VPN builds on Windows only")
endif()

if(NOT CMAKE_SIZEOF_VOID_P EQUAL 8)
  message(FATAL_ERROR "Ranz VPN builds for x64 and arm64 only")
endif()

if(IS_CROSS_COMPILATION MATCHES "arm64-on-x64")
  set(CMAKE_SYSTEM_PROCESSOR "arm64")
else()
  message("Setting QSPECTRE")
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} /Qspectre")
endif()

#
# https://msrc-blog.microsoft.com/2020/08/17/control-flow-guard-for-clang-llvm-and-rust/
#

message("Setting CONTROL FLOW GUARD") 
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} /guard:cf")
set(CMAKE_EXE_LINKER_FLAGS  "${CMAKE_EXE_LINKER_FLAGS} /guard:cf /DYNAMICBASE")

message("Setting CETCOMPAT")
set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} /CETCOMPAT")

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
