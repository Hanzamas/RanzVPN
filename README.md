# Ranz VPN

Ranz VPN is a Windows-only, lightweight VPN server maintained by Hanzcodes. It focuses strictly on the native SE-VPN protocol (SSL-VPN over TCP with UDP Acceleration) and strips out unrelated modules to keep the core small.

The version format is `0.1.N`, where `N` represents the GitHub Actions build run number.

## What it is

- Headless binaries: `vpnserver.exe` (runs directly or as a Windows service), `vpncmd.exe` (CLI administration tool), and `vpntest.exe` (diagnostics). No GUI is included.
- Platform support: Windows 10 and Windows Server 2016 or newer, on x64 and arm64 architectures. 32-bit (x86) and other operating systems are unsupported.
- Default listening ports: TCP 443 and TCP 5555.
- Client compatibility: Emits build version 5.02.5187 and the `SE-VPN4-PROTOCOL` signature, allowing existing SE-VPN clients and servers to connect without modification.
- Configuration: Loaded exclusively from `ranz_server.config` in the same directory as `vpnserver.exe`. Legacy configuration files (`vpn_server.config`) are ignored.
- Registry keys: Stored under `Software\Hanzcodes\Ranz VPN`.

## Design and exclusions

To reduce attack surface and resource usage, the following modules are excluded:

- Windows GUI applications (management consoles, client managers, setup wizards) and GUI build targets.
- Remote management APIs: JSON-RPC, HTML5 web consoles, public directory services, and tools under `developer_tools`.
- The standalone bridge utility (`vpnbridge`).
- Multi-protocol dispatchers and secondary tunnel protocols: OpenVPN, SSTP, L2TP/IPsec, EtherIP, IPsec/IKE, WireGuard (including libsodium and BLAKE2), and PPP.
- Enterprise auth add-ons: RADIUS authentication and hub EAP clients.
- SecureNAT components: virtual NAT, internal DHCP, and user-mode network stacks.
- In-process IPC client modules and in-process network sockets.
- Cluster nodes and PKCS#11 smart-card authentication.
- External cloud features: relay services, dynamic DNS, NAT traversal, R-UDP, keep-alive connections, and update check endpoints.
- Tunnels over ICMP and DNS.
- Legacy driver packages, WinPcap bridging, and support for Windows 7 or Vista.

## Build

Ranz VPN is built on GitHub Actions via [`.github/workflows/windows.yml`](.github/workflows/windows.yml) using clang-cl, vcpkg, and Ninja. The workflow supplies the current run number to CMake as `BUILD_NUMBER`, runs the diagnostic suite, and archives the compiled binaries, debug symbols, and `hamcore.se2`.

Build steps:

```
cmake -G "Ninja" -DCMAKE_TOOLCHAIN_FILE="C:\vcpkg\scripts\buildsystems\vcpkg.cmake" -DVCPKG_TARGET_TRIPLET=x64-windows-static -DCMAKE_BUILD_TYPE=RelWithDebInfo -DBUILD_NUMBER=<run number> ..
cmake --build .
```

## License

Ranz VPN is proprietary software. Copyright (c) 2026 Hanzcodes. All rights reserved. See [LICENSE](LICENSE) for terms.
```
