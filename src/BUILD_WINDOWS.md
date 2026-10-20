How to build Ranz VPN on Windows
================================

The reference build is the GitHub Actions workflow
[`.github/workflows/windows.yml`](../.github/workflows/windows.yml): clang-cl, vcpkg (static triplets) and
Ninja, for x64 (`windows-latest`) and arm64 (`windows-11-arm`, built natively). The README's *Build*
section lists the same configure and build commands. Ranz VPN builds for 64-bit targets only.

## Requirements

- Visual Studio 2022 with **Desktop development with C++** and **C++ Clang Compiler for Windows**
- Git
- vcpkg, cloned to `C:\vcpkg` and bootstrapped (`bootstrap-vcpkg.bat`); Visual Studio's folder view
  also needs `vcpkg integrate install`

## Building

1. Clone with submodules (liboqs and oqs-provider):

   `git clone --recursive <repository>` or, in an existing clone, `git submodule update --init --recursive`

1. From a developer command prompt (`vcvars64.bat`, or `vcvarsarm64.bat` on an arm64 host):

   ```
   mkdir build
   cd build
   cmake -G "Ninja" -DCMAKE_TOOLCHAIN_FILE="C:\vcpkg\scripts\buildsystems\vcpkg.cmake" -DVCPKG_TARGET_TRIPLET=x64-windows-static -DCMAKE_BUILD_TYPE=RelWithDebInfo -DCMAKE_C_COMPILER=clang-cl ..
   cmake --build .
   ```

   Use `-DVCPKG_TARGET_TRIPLET=arm64-windows-static` on an arm64 host.

1. Visual Studio's *Open a local folder* uses `CMakeSettings.json`, which has one configuration, `x64-native`.

The executables (`vpnserver.exe`, `vpncmd.exe`, `vpntest.exe`) are written to the build directory. The
hamcore files are resources of each executable (`cmake/RanzResources.cmake`).

## Build number

`BUILD_NUMBER` is the third version component (0.1.N); CI passes the GitHub run number. Locally it
defaults to 0 (`-DBUILD_NUMBER=<n>`, or the `BuildNumber` environment in `CMakeSettings.json`).
