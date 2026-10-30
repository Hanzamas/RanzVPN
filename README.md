# Ranz VPN

Ranz VPN is a Windows-only, lightweight VPN server maintained by Hanzcodes. It focuses strictly on the native SE-VPN protocol (SSL-VPN over TCP with UDP Acceleration) and strips out unrelated modules to keep the core small.

The version format is `0.1.N`, where `N` represents the GitHub Actions build run number.

## What it is

- Headless binaries: `vpnserver.exe` (runs directly or as a Windows service), `ranz-node.exe` (the Node of the new core), and `vpntest.exe` (diagnostics). No GUI is included. `vpncmd.exe` was retired (CORE-S8-1, #84): the Controller's intent API, its web UI and the `ranz` command line replace it, and `ranz doctor`, `ranz test throughput` and `ranz cert` replace its tools.
- Platform support: Windows 10 and Windows Server 2016 or newer, on x64 and arm64 architectures. 32-bit (x86) and other operating systems are unsupported.
- Default listening port: TCP 443. A fresh configuration falls back to TCP 5555 when 443 cannot be bound at its first start, logs why, and keeps 5555 on later starts (ADR-0020). Listeners on any other TCP port can be added with `ListenerCreate`.
- Client compatibility: Emits build version 5.02.5187 and the `SE-VPN4-PROTOCOL` signature, so SE-VPN clients and servers can connect today because the legacy SE-VPN path is unchanged. This is not a guaranteed feature: in the final product, SE-VPN compatibility comes back through the `ranz-compat` sidecar (Legacy phase).
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

Ranz VPN is built on GitHub Actions via [`.github/workflows/windows.yml`](.github/workflows/windows.yml) using clang-cl, vcpkg, and Ninja. The workflow supplies the current run number to CMake as `BUILD_NUMBER`, runs the diagnostic suite, and archives the compiled binaries and debug symbols. The files of `src/bin/hamcore` are resources of each executable (`cmake/RanzResources.cmake`); there is no `hamcore.se2` archive.

Build steps:

```
set VCPKG_ROOT=C:\vcpkg
cmake --preset x64 -DBUILD_NUMBER=<run number>
cmake --build --preset x64
```

Run them in a Visual Studio developer prompt (clang-cl on the path). The presets of [`CMakePresets.json`](CMakePresets.json) are `x64`, `arm64`, `asan` (AddressSanitizer and libFuzzer, x64 only) and `debug`; CI runs each of its jobs through one of them and Visual Studio reads the same file. `vcpkg.json` pins the vcpkg ports tree with `builtin-baseline`, so OpenSSL and zlib are the same on every machine.

## License

Ranz VPN is proprietary software. Copyright (c) 2026 Hanzcodes. All rights reserved. See [LICENSE](LICENSE) for terms.
```
