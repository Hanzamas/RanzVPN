# Ranz VPN

Ranz VPN is a Windows-only slim fork of [SoftEther VPN](https://github.com/SoftEtherVPN/SoftEtherVPN), maintained by Hanzcodes. It keeps the native SE-VPN protocol (SSL-VPN over TCP, with UDP Acceleration) and removes everything else.

The version is `0.1.N`, where `N` is the number of the GitHub Actions run that built the binaries.

## What it is

- Headless executables: `vpnserver.exe` (the VPN server, also installable as a Windows service) and `vpncmd.exe` (command-line administration), plus `vpntest.exe` for self-tests. There is no GUI.
- Windows 10 and Windows Server 2016 or later, on x64 and arm64. x86 and other platforms are not supported.
- Default listeners are TCP 443 and 5555.
- Peers still see the SoftEther VPN 5.02 build 5187 version numbers and the `SE-VPN4-PROTOCOL` signature, so SE-VPN clients and servers keep working with it.
- The server reads `ranz_server.config` next to `vpnserver.exe`. Configuration files from SoftEther VPN (`vpn_server.config`) are not read or migrated.
- Settings in the Windows registry live under `Software\Hanzcodes\Ranz VPN`.

## Removed from SoftEther VPN

- Windows GUI applications (server manager, client manager, setup) and the GUI-only build targets
- JSON-RPC API, HTML5 web console, VPN Gate, and the JSON-RPC API clients, generator and samples under `developer_tools`
- The VPN Bridge (`vpnbridge`) executable
- OpenVPN, SSTP, L2TP/IPsec, EtherIP, IPsec/IKE, WireGuard (with libsodium and BLAKE2), PPP and the protocol dispatcher
- RADIUS authentication and the hub EAP client
- SecureNAT (virtual NAT, virtual DHCP and the native stack)
- The in-process IPC client module and in-process sockets
- Clustering and PKCS#11 smart-card authentication
- Cloud dependencies: VPN Azure, dynamic DNS, NAT traversal, R-UDP, the keep-alive server and the update check
- VPN over ICMP and VPN over DNS, which were built on R-UDP
- Windows 7 / Vista support, WinPcap bridging and the legacy driver packages

## Build

Ranz VPN is built only on GitHub Actions, by [`.github/workflows/windows.yml`](.github/workflows/windows.yml), with clang-cl, vcpkg and Ninja. Each run passes its run number to CMake as `BUILD_NUMBER`, runs the self-tests and uploads the executables, debug symbols and `hamcore.se2` as artifacts.

The configure step the workflow runs is:

```
cmake -G "Ninja" -DCMAKE_TOOLCHAIN_FILE="C:\vcpkg\scripts\buildsystems\vcpkg.cmake" -DVCPKG_TARGET_TRIPLET=x64-windows-static -DCMAKE_BUILD_TYPE=RelWithDebInfo -DBUILD_NUMBER=<run number> ..
cmake --build .
```

## License

Ranz VPN is proprietary software. Copyright (c) 2026 Hanzcodes. All rights reserved. See [LICENSE](LICENSE) for the terms.

Ranz VPN is derived from [SoftEther VPN](https://github.com/SoftEtherVPN/SoftEtherVPN).
Copyright (c) all contributors on SoftEther VPN project in GitHub.
Copyright (c) Daiyuu Nobori, SoftEther Project at University of Tsukuba, and SoftEther Corporation.

Third-party software included in Ranz VPN is licensed under its own terms; see [src/THIRD_PARTY.TXT](src/THIRD_PARTY.TXT).

SoftEther is a registered trademark of SoftEther Corporation. Ranz VPN is not affiliated with or endorsed by SoftEther Corporation or the SoftEther VPN Project.
