cmake_minimum_required(VERSION 3.20)
project(xdpspike C)

# Extracted Microsoft.XDP-for-Windows.Sdk nupkg (headers only from XDP_API_VERSION 3).
set(XDP_SDK "" CACHE PATH "Extracted Microsoft.XDP-for-Windows.Sdk package")
if(NOT EXISTS "${XDP_SDK}/build/native/include/afxdp.h")
  message(FATAL_ERROR "XDP_SDK does not contain build/native/include/afxdp.h: ${XDP_SDK}")
endif()

# Static CRT: the Windows 10 test kit runs on machines without the VC++ redistributable.
set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded")

add_executable(xdpspike xdpspike.c)
target_include_directories(xdpspike PRIVATE "${XDP_SDK}/build/native/include")
target_compile_definitions(xdpspike PRIVATE XDP_API_VERSION=3 XDP_INCLUDE_WINCOMMON _CRT_SECURE_NO_WARNINGS)
target_link_libraries(xdpspike PRIVATE ws2_32 iphlpapi ntdll)

add_executable(mkloop mkloop.c)
target_compile_definitions(mkloop PRIVATE UNICODE _UNICODE)
target_link_libraries(mkloop PRIVATE setupapi newdev)
