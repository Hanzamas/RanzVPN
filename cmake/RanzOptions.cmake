# RanzOptions.cmake
# Build options of the project's own code: the INTERFACE target ranz_options.
#
# mayaqua links ranz_options PUBLIC (src/Mayaqua/CMakeLists.txt), so every target that builds on
# Mayaqua (cedar, vpnserver, vpncmd, vpntest and the fuzz targets) compiles with these options.
# The vendored targets (liboqs, oqs-provider) do not link Mayaqua and get none of them.
#
# Windows API level: Windows 10 version 1607 and Windows Server 2016 (NTDDI_WIN10_RS1), the oldest
# systems Ranz VPN runs on (SUPPORTED_WINDOWS_LIST in MayaType.h). The SDK headers declare what this
# level has and hide what is newer. It is set here only: MayaType.h stops a translation unit that
# compiles below it with #error.

add_library(ranz_options INTERFACE)

target_compile_definitions(ranz_options INTERFACE
  WINVER=0x0A00
  _WIN32_WINNT=0x0A00
  NTDDI_VERSION=0x0A000002
  WIN32_LEAN_AND_MEAN
)
