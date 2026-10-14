cmake_minimum_required(VERSION 3.20)
project(spbench C)

# Extracted Microsoft.XDP-for-Windows.Sdk nupkg (headers only from XDP_API_VERSION 3).
set(XDP_SDK "" CACHE PATH "Extracted Microsoft.XDP-for-Windows.Sdk package")
if(NOT EXISTS "${XDP_SDK}/build/native/include/afxdp.h")
  message(FATAL_ERROR "XDP_SDK does not contain build/native/include/afxdp.h: ${XDP_SDK}")
endif()

set(RANZ_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/../..")
set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded")

# SeLowCommon.h is the real kernel/user contract of the shipped SeLow driver.
add_executable(spbench spbench.c)
target_include_directories(spbench PRIVATE "${XDP_SDK}/build/native/include" "${RANZ_ROOT}/src/SeLow")
target_compile_definitions(spbench PRIVATE XDP_API_VERSION=3 XDP_INCLUDE_WINCOMMON _CRT_SECURE_NO_WARNINGS)
target_link_libraries(spbench PRIVATE ws2_32 iphlpapi ntdll)

# Same KM-TEST Loopback installer as the XDP spike.
add_executable(mkloop "${RANZ_ROOT}/spikes/xdp-loopback/mkloop.c")
target_compile_definitions(mkloop PRIVATE UNICODE _UNICODE)
target_link_libraries(mkloop PRIVATE setupapi newdev)
