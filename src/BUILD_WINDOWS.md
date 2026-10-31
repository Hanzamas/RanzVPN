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

The OpenSSL and zlib versions come from the `builtin-baseline` commit in `vcpkg.json`, not from whatever
your vcpkg checkout holds, so CI and every developer build the same libraries. If the configure step
cannot find that commit, run `git pull` and `bootstrap-vcpkg.bat` in the vcpkg checkout. To take newer
library versions, move the baseline with `vcpkg x-update-baseline` and commit the changed `vcpkg.json`.

## Building

1. Clone with submodules (liboqs and oqs-provider; libjuice and libplum, the ICE and port mapping libraries of
   the new core):

   `git clone --recursive <repository>` or, in an existing clone, `git submodule update --init --recursive`

1. Set the environment variable `VCPKG_ROOT` to your vcpkg checkout (for example `C:\vcpkg`).

1. From a developer command prompt (`vcvars64.bat`, or `vcvarsarm64.bat` on an arm64 host):

   ```
   cmake --preset x64
   cmake --build --preset x64
   ```

   The presets are defined in `CMakePresets.json` and build in `build/`:

   - `x64`: x64 RelWithDebInfo, the configuration CI builds and tests
   - `arm64`: arm64 RelWithDebInfo, built on a Windows ARM64 host (no cross-compilation)
   - `asan`: x64 with AddressSanitizer and the libFuzzer targets (the fuzz-asan CI job)
   - `debug`, `debug-arm64`: Debug builds

1. Visual Studio's *Open a local folder* offers the same presets in the configuration dropdown.

The executables (`ranz-node.exe`, `vpntest.exe`, `coretest.exe`) are written to the build directory. The
hamcore files are resources of each executable (`cmake/RanzResources.cmake`).

## Build number

`BUILD_NUMBER` is the third version component (0.1.N); CI passes the GitHub run number. Locally it
defaults to 0 (`-DBUILD_NUMBER=<n>` on the configure command, or `BUILD_NUMBER` in a
`CMakeUserPresets.json` of your own). Delete the CMake cache after a change.
