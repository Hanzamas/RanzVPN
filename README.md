# Ranz VPN

Ranz VPN is a Windows-only VPN maintained by Hanzcodes. Its data plane is the Node of the new core (`ranz-node.exe`), driven by the Controller (`ranz controller`) through one `ranz.exe`. It started as a slimmed fork of SoftEther VPN; the fork's `vpnserver.exe` and `vpncmd.exe` are retired (CORE-S8-1, #84), and the fork's Hub, Account, Sam and logging live on inside the Node.

The version format is `0.1.N`, where `N` represents the GitHub Actions build run number.

## What it is

- Headless binaries: `ranz-node.exe` (the Node, the `ranzvpnserver` Windows service), `ranz.exe` (the Controller, the BGP sidecar, the tray and the command line), `vpntest.exe` and `coretest.exe` (tests). No GUI is included besides the web UI of the Controller.
- Retired with the slim fork (CORE-S8-1, #84): `vpnserver.exe` and its SE-VPN listener, whose sessions the Noise sessions of the Node over QUIC and TLS on 443 replace, and `vpncmd.exe`, whose administration the Controller's intent API, its web UI and the `ranz` command line replace, and whose tools `ranz doctor`, `ranz test throughput` and `ranz cert` replace. SE-VPN compatibility comes back only through the `ranz-compat` sidecar in the Legacy phase (ADR-0037).
- Platform support: Windows 11 and Windows Server 2022 or newer for the Node (ADR-0022), on x64 and arm64 architectures. 32-bit (x86) and other operating systems are unsupported.
- Configuration: the Node keeps its Configuration store `ranz_node.db` in `%ProgramData%\Hanzcodes\Ranz VPN`; the intent lives in the Controller.
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
