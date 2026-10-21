# ADR-0008: Replace SoftEther's self-written runtime with Windows and standard APIs where they exist

**Status:** Accepted as a principle (2026-10-13, Hilmi: "windows native total yang fast and furious"); individual rows are decided when the spec that touches them is written (Windows-native runtime #30, new core). Amended 2026-10-13: RIO is crossed out (Hilmi: "gas"). Amended 2026-10-20: the SecureNAT row becomes NAT in the data plane plus three egress tiers (SDN spec #176).

## Context

Mayaqua (about 85k to 95k lines) is a 2003-era portable runtime: its own allocator with canaries and tracking, LIST/QUEUE/HASH/BUF containers, ANSI and Unicode string libraries, sockets with its own TLS/UDP/R-UDP/NAT-T/ICMP/DNS tunnelling layer, config file format, PACK serialization, HTTP client and server, OpenSSL wrappers, service/registry/driver helpers. On a Windows-only product much of it duplicates what the OS provides, and the self-written parts are where the per-packet syscall and copy costs come from.

The principle agreed in the discussion: the data path stays ours (that is the product); everything else that Windows already provides should use the Windows API, with performance as the goal.

## Decision

| SoftEther component | Replacement | Why |
|---|---|---|
| sockets / UDP in `Network.c` | Winsock2 with **IOCP** (overlapped `WSARecvMsg`/`WSASendMsg`, a completion port per core group), `UDP_SEND_MSG_SIZE` (USO) and `UDP_RECV_MAX_COALESCED_SIZE` (URO); **RIO crossed out**: with USO/URO batching it adds little, and MsQuic's Windows datapath does not use it either | the NIC segments and coalesces, not the CPU |
| multi-TCP plus UDP Acceleration | **msquic** | its Windows datapath already uses IOCP, USO/URO, `WSASendMsg`/`WSARecvMsg` and CPU affinity, plus an optional XDP datapath (ADR-0018); do not write QUIC |
| `Encrypt.c` wrappers | CNG/bcrypt (AES-GCM, SHA-2, X25519, `BCryptGenRandom`), Schannel for TLS (ADR-0007) | one crypto stack, zero third-party crypto |
| own routing table code | IP Helper: `CreateIpForwardEntry2`, `NotifyRouteChange2`, `GetIpInterfaceEntry` | already partly used |
| SecureNAT (12k lines) | WinNAT (`New-NetNat`, kernel NAT in Windows 10+) *(replaced by the amendment of 2026-10-20 below: 1:1 NAT and SNAT in the node's data plane, internet egress in three tiers)* | built-in |
| host firewall / ACL | **WFP user-mode API** (`FwpmFilterAdd0`) or `INetFwPolicy2` | kernel-enforced filters defined from user mode, no driver |
| virtual DHCP | none; IPAM in the control plane | an overlay does not need DHCP |
| `HTTP.c` for admin / web UI | **http.sys** (HTTP Server API) with Schannel certificate binding | kernel HTTP listener, native |
| threads and locks (`Kernel.c`, `Object.c`) | SRWLOCK, `WaitOnAddress`, thread pool or per-core pinned workers | lighter than CRITICAL_SECTION |
| `Memory.c` allocator | HeapAlloc plus packet pools from `VirtualAlloc` (large pages) | no allocation on the data path |
| own log files | ETW (`TraceLogging`), Event Log, Prometheus metrics | Windows tooling can read them |
| `Internat.c` ANSI/Unicode pairs | UTF-8 internally, `MultiByteToWideChar` at the Win32 edge | one representation |
| `Cfg.c` format | YAML or JSON plus an API | declarative |
| own DNS | `DnsQueryEx` (async) | |
| PACK serialization | protobuf/gRPC for the control plane, a small binary header for data | standard |
| `hamcore.se2` and string tables | Windows resources or plain files, English strings plus JSON i18n | |
| own LIST/QUEUE/HASH/BUF | the language's standard library | |
| `Tick64`, own RNG, base64/hex | `QueryPerformanceCounter`, `BCryptGenRandom`, `CryptBinaryToString` | |
| own X.509 handling | Windows certificate store (`CertOpenStore`) plus CNG | |
| own keepalive / retry / reconnect | built into QUIC | |
| own SOCKS/HTTP proxy client | `WinHttpGetProxyForUrl` plus a small CONNECT | |
| `vpnsetup` installer | MSIX or winget | |
| update check | winget | |

What remains hand-written: the packet engine (Wintun to peer table to QUIC), framing and handshake, the policy match table on the data path, the control plane, the UI. Estimated 15k to 25k lines of new code rather than 150k.

## Consequences

- This table applies to the **new core**, not to the slim fork; the fork keeps Mayaqua as a reference and compatibility gateway.
- The crypto rows follow ADR-0007 (Schannel/CNG, Accepted); the adapter and routing rows follow ADR-0014 (dual-mode) rather than ADR-0004.
- The language for the new core (C with msquic and OpenSSL, or Rust with quinn/msquic bindings, wintun and aes-gcm crates) was discussed but not decided; Rust was called the natural pick for user-space performance with memory safety, C the faster start from the current code.

## Amendment 2026-10-20: SecureNAT is replaced by NAT in the data plane and three egress tiers, not by WinNAT

Maintainer decision, from the SDN spec #176 that Hilmi filed ("the SecureNAT row: WinNAT becomes the three egress tiers"). WinNAT cannot do what the SecureNAT row asked of it: it supports one NAT network per host (with more, it reports "unknown state"), no overlapping prefixes, needs Hyper-V, and its static mappings are TCP and UDP port forwards only (research of 2026-10-20). The SecureNAT row now reads:

- **1:1 NAT and SNAT per VRF are done in the node's data plane** (ADR-0025). They are own code, because no Windows NAT supports per-VRF tables with overlapping prefixes.
- **Internet egress uses the first of three Egress tiers that the host supports** (ADR-0025): (1) RRAS NAT on Windows Server, configured through the MprConfig API with the Wintun adapter as the private interface and reconciled after Windows updates; (2) WinNAT over one supernet of all remapped VRF prefixes, only where Hyper-V is present and no NetNat exists yet; (3) on every other host, a proxy that lets the Windows TCP/IP stack terminate the flow and re-dials with ordinary sockets (TCP, UDP, ICMP echo).
- **An existing NetNat on the host is never touched.**
- A WinDivert packet-driver module is opt-in only and ships only after it passes the gate in ADR-0025.
- The native-first rule still holds: tiers 1 and 2 are Windows kernel NAT, and tier 3 uses the Windows TCP/IP stack rather than one of our own (ADR-0014).
