# How to build SoftEther VPN on Windows ARM64

This document describes how to build SoftEther VPN for Windows ARM64.


## Requirements


- Build host: Windows x64

- Target device: Windows 10 / Windows 11 ARM64


## Building 
 
    **Notes before building**: ARM64 builds are cross-compiled from an x64 Windows host. An existing x64-native build is required to generate hamcore.se2.
1. Follow [BUILD_WINDOWS.md](BUILD_WINDOWS.md##Building)

1. Build x64 (Native): From the build menu, select x64-on-x64. Complete the build successfully. This build is required to generate shared resources

1. Build ARM64 (Cross-Compiled): From the same build menu, select arm64-on-x64. 
Build the ARM64 version of SoftEther VPN.

# Summary

SoftEther VPN can be cross-compiled for Windows ARM64 on an x64 host
