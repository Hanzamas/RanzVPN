# How to build Ranz VPN on Windows ARM64

This document describes how to build Ranz VPN for Windows ARM64.


## Requirements


- Build host: Windows on ARM64 (CI builds natively on a windows-11-arm runner; there is no cross-compile preset)

- Target device: Windows 11 ARM64


## Building

The hamcore files are compiled into each executable as resources, so the ARM64 build needs no x64 build first.

1. Follow [BUILD_WINDOWS.md](BUILD_WINDOWS.md) up to the choice of the configuration.

1. Select the arm64 preset in Visual Studio, or in an ARM64 developer prompt run `cmake --preset arm64` and `cmake --build --preset arm64`.

The preset sets the arm64-windows-static vcpkg triplet. `src/Mayaqua/CMakeLists.txt` turns on `OQS_PERMIT_UNSUPPORTED_ARCHITECTURE` of liboqs for ARM64, so no extra configure flag is needed.
