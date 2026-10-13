cmake_minimum_required(VERSION 3.20)
project(xdpebpf C)

# Extracted Microsoft.XDP-for-Windows.Sdk nupkg (headers only from XDP_API_VERSION 3).
set(XDP_SDK "" CACHE PATH "Extracted Microsoft.XDP-for-Windows.Sdk package")
# Extracted eBPF-for-Windows.x64 nupkg (libbpf-style headers, ebpfapi.lib).
set(EBPF_SDK "" CACHE PATH "Extracted eBPF-for-Windows.x64 package")
if(NOT EXISTS "${XDP_SDK}/build/native/include/afxdp.h")
  message(FATAL_ERROR "XDP_SDK does not contain build/native/include/afxdp.h: ${XDP_SDK}")
endif()
if(NOT EXISTS "${EBPF_SDK}/build/native/include/bpf/libbpf.h")
  message(FATAL_ERROR "EBPF_SDK does not contain build/native/include/bpf/libbpf.h: ${EBPF_SDK}")
endif()

add_executable(xdpebpf xdpebpf.c)
target_include_directories(xdpebpf PRIVATE
  "${XDP_SDK}/build/native/include"
  "${EBPF_SDK}/build/native/include"
  "${EBPF_SDK}/build/native/include/uapi")
target_compile_definitions(xdpebpf PRIVATE XDP_API_VERSION=3 XDP_INCLUDE_WINCOMMON _CRT_SECURE_NO_WARNINGS)
target_link_libraries(xdpebpf PRIVATE ws2_32 iphlpapi ntdll "${EBPF_SDK}/build/native/lib/ebpfapi.lib")

add_executable(mkloop ../xdp-loopback/mkloop.c)
target_compile_definitions(mkloop PRIVATE UNICODE _UNICODE)
target_link_libraries(mkloop PRIVATE setupapi newdev)
