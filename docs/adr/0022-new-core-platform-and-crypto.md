# ADR-0022: New-core platform, threading, crypto, adapters and the strangler plan

**Status:** Accepted (2026-10-13, from the grilling; "windows native total yang fast and furious", ADR-0008). This ADR consolidates the platform decisions for the new core and builds on ADR-0005 (transport), ADR-0006 (tiers), ADR-0007 (Schannel), ADR-0010 (routing), ADR-0018 (packet I/O) and ADR-0019 (VLAN and policy), each now Accepted. The security and anti-censorship design is ADR-0023.

## Context

ADR-0017 sequences the work: clean and stabilise the slim fork, build a harness, then build the new core as a strangler that reuses Hub, Account, Sam, Logging and Cfg and replaces the data path module by module, interop-tested against the pinned `main-oracle` releases. ADR-0008 established the principle of using Windows and standard APIs wherever they exist but left the language and several rows open. The grilling of 2026-10-13 settled the platform: minimum OS, language, threading, crypto, the config store, the client adapters, the control plane, the strangler order and the v1 scale target. Facts behind the decisions live in the grilling scratchpad: `facts-cng-schannel.md`, `facts-xdp.md`, `facts-signing.md`, `spike-xdp-result.md`, `spike-xdp-ebpf-result.md`, `perf-hotspots.md`.

## Decision

### Platform and language

- **Minimum OS: Windows 11 / Server 2022, x64 and arm64.** The slim fork keeps Windows 10 / Server 2016+. QUIC and TLS 1.3 in Schannel need Windows 11 / Server 2022 (ADR-0007), and XDP needs build 17763 or later. On arm64 there is no Windows Server 2025; arm64 targets are Windows 11 only.
- **Language: C17** (the same CMake, CI, harness, fuzz and ASan as the slim fork). The strangler reuses Hub, Account, Sam, Logging and Cfg **in-process, with no FFI**; msquic, Wintun, libjuice and libplum are C. Rust was considered and is the natural pick only if the strangler were dropped for a rewrite, which it is not.

### Threading

Per-core run-to-completion:

- msquic worker callbacks process **each datagram inline**: Noise decrypt, policy lookup, then hand the frame to the adapter ring.
- **One I/O thread per adapter queue** (the Wintun ring, or the single AF_XDP queue of a KM-TEST adapter).
- The MAC, route and policy tables are **read-mostly**: rebuilt and swapped atomically, never mutated under a per-frame lock.
- **No hub-wide forwarding lock.** The perf work (`perf-hotspots.md`, D2) shows today's hub serialises forwarding under the `MacHashTable` lock across `StorePacket` and the back-pressure sleeps; the new switch must not reproduce it.

### Crypto and TLS

- **Schannel TLS 1.3 and CNG only.** OpenSSL, liboqs and oqs-provider are **removed from the new core** (they stay in the slim fork).
- **AES-GCM only.** ChaCha20-Poly1305 is off by default in both Schannel and msquic (Schannel treats it as an admin-level, system-wide opt-in and msquic blocks it on the Schannel path).
- **Session layer: Noise_IK** with **X25519 via CNG** (`BCRYPT_ECDH_ALGORITHM` with `BCRYPT_ECC_CURVE_25519`), SHA-256, and **HKDF via CNG**. The CNG X25519 blob format and clamping are undocumented, so the implementation is tested against the RFC 7748 vectors on both x64 and arm64.
- **Node identity key in a CNG KSP** (TPM-backable), used for Noise static-key authentication.
- **Certificates via CryptoAPI:** ECDSA P-256 self-signed certificates, PFX import; ACME is a later addition, not core work for v1. Certificate keys live in a CNG KSP (`PKCS12_ALWAYS_CNG_KSP`) so TLS 1.3 server signatures (RSA-PSS / ECDSA) work.
- **Post-quantum** is a CNG ML-KEM hybrid with X25519, used where the OS provides it (Windows 11 24H2 / Server 2025 and later) in both TLS and Noise; it is otherwise a later addition, not a blocker.
- The transport-security layering (Noise inside TLS/QUIC), key separation and forward secrecy are specified in ADR-0023.

### Roles and SE-VPN compatibility

- **One node binary** with roles: `server`, `client` (cascade), `bridge`, `controller`, `relay`. There is **no separate client product**.
- The **legacy SE-VPN TCP listener is dropped once the new transport works**. SE-VPN interoperability is tested against the pinned `main-oracle` releases (ADR-0017), not an in-process legacy listener kept alive inside the new core.

### Configuration store

- **SQLite via `winsqlite3.dll`** (the copy in System32; no vendored library), introduced in the new core with a **one-time importer from `ranz_server.config`**. The old `Cfg` design has lock contention; SQLite replaces it rather than being ported.

### Client adapters and packet I/O

- **L3: Wintun** (default, Accepted in ADR-0009).
- **L2:** the Microsoft **KM-TEST Loopback Adapter** (ADR-0018 decision 4), a Hyper-V network, or a physical NIC (SeLow, Npcap, or XDP, per the ADR-0018 backend matrix).
- **Windows 11 client L2** is unproven: Microsoft documents and tests XDP only on Server. Run the XDP spike artifact by hand once in a Windows 11 VM; if it fails, the client L2 fallback is **tap-windows6**. A Ranz-built L2 driver stays crossed out (ADR-0018).
- **arm64 is L3 only** until a production-signed arm64 XDP runtime exists (today's arm64 runtimes are test-signed, which needs Secure Boot off and cannot ship).
- **XDP: ship on the XDP 1.4 rule API** (`XdpCreateProgram`, supported until 2028-01-29), which is the only XDP path that captures the frames the OS sends. The **eBPF path is rejected for now**: the `spike/xdp-ebpf` result (`spike-xdp-ebpf-result.md`) is conclusive that eBPF for Windows has no TX-inspect hook (every program attaches to `{L2, RX, INSPECT}`), and no production-signed eBPF runtime exists. Finish the eBPF spike in parallel and switch only when eBPF-for-Windows installs cleanly and is production-signed. **Re-verify the `xdp.sys` signature on a Server 2022 VM with Secure Boot on and test signing off before ADR-0018 decision 4 is treated as final.** XDP installs via a separate `Install-RanzXdp.ps1`, not bundled in the MSI for v1.
- **KM-TEST details:** a per-adapter locally administered MAC derived from the node id and the network id (so two adapters on one segment do not share a MAC); forward ARP, IGMP, LLMNR and NetBIOS chatter and rate-limit broadcast per VLAN; add broadcast, multicast and 802.1Q-tagged injection to the spike.
- **QUIC accelerated through the msquic XDP datapath** (ADR-0018 decision 2): **Accepted, default off, Server x64 only** — one flag, no Ranz AF_XDP code.
- **QTIP** (ADR-0018 decision 5): strangler step 7, default port **8443** (both TCP and UDP reserved, configurable), proven with a two-VM spike.
- **msquic distribution:** ship the official signed `msquic.dll` (Schannel build), pinned, for x64 and arm64.

### Control plane and routing

- A **`controller` role** in the node binary: one active per deployment plus a passive standby.
- **protobuf via nanopb (C)** on the Noise control stream; **no gRPC in the core**.
- **BGP via a Go sidecar `ranz-bgp`** that embeds GoBGP as a library (ADR-0010). The core talks to the sidecar over a **named pipe with JSON** (announce, withdraw, learned routes); the core installs learned routes into Windows through IP Helper. It is an optional MSI feature, built in CI (Go cross-compiled for x64 and arm64), and spiked on Windows when L3 networks land (strangler step 7). **No RRAS.**

### VLAN and policy engine (ADR-0019) v1

- Access / trunk / native VLAN with VLAN-aware MAC learning; per-VLAN broadcast limits and statistics.
- TCP / UDP / ICMP connection tracking.
- Identity rules (user, group, node tag, network, VLAN) with address groups, per-rule hit counters and a default action; import of the old access list.
- Deferred to later: QinQ, time-based rules, per-rule logging.
- **One engine for L2 and L3; WFP only protects the host.** Rules are JSON in the admin API (ADR-0021), ordered by priority, evaluated once per flow on ingress; established flows take a connection-tracking fast path; compiled tables are swapped atomically; the conntrack table is bounded per network with LRU eviction and configurable timeouts.

### Strangler order

Each step is interop-tested against the oracle (ADR-0017).

1. Noise session over CNG + an msquic listener, feeding L2 frames into the existing Session/Hub as a new connection type (the legacy listener untouched).
2. TLS/TCP 443 fallback on Schannel, on the same session layer.
3. The node `client` role (L2 on KM-TEST + XDP, L3 on Wintun), replacing Cascade/Link for new peers.
4. The new L2 switch with VLAN and the policy engine (ADR-0019), replacing Hub forwarding.
5. Control plane, `relay` role, ICE (libjuice) and port mapping (libplum).
6. L3 routed networks (IP Helper routes, WinNAT).
7. GoBGP sidecar, QTIP, the tier-3 mimicry sidecar (ADR-0023) and the CDN / WebSocket path.
8. Retire the legacy listener, vpncmd and OpenSSL, together with the slim fork.

**Before step 1**, do the perf work that the surviving hub needs: ticket #31 Q2 (IP table expiry) and the D2 back-pressure move. Skip D1 (flooding), because the new switch at step 4 replaces it.

### Enrollment, IPv6 and scale

- **Enrollment:** username/password checked by the existing Sam, plus Noise static-key pinning on first login (TOFU). Admin-issued one-time join tokens are a later addition.
- **IPv6:** full dual-stack in the new core (transport, adapters and policy).
- **v1 scale target (benchmark goal): 10,000 sessions per node and 10 Gbps.** Larger scale comes from many nodes plus the GoBGP sidecar, not from one bigger node.
- **Non-Windows clients** are served by a standard-protocol plugin transport in phase 2, out of v1.

## Consequences

- The new core ships **zero third-party crypto**: Schannel and CNG only, OpenSSL and liboqs gone. The slim fork is unaffected and keeps OpenSSL, liboqs and the X25519MLKEM768 TLS group for stock clients.
- Removing the hub-wide forwarding lock and moving to read-mostly tables is a correctness risk concentrated in the new switch (step 4); the harness frame tests and the benchmark are the net.
- Depending on the XDP rule API means tracking its deprecation: XDP 1.4 is pinned and supported to 2028-01-29, msquic's own datapath still uses the rule API, and SeLow on the loopback adapter stays the fallback behind the Local Bridge backend interface (ADR-0018). The eBPF path is re-checked on every XDP release.
- arm64 nodes run L3 only until Microsoft ships a production-signed arm64 XDP runtime, so an arm64 deployment that needs L2 has no virtual adapter yet.
- The control plane's own design (route advertisement, approval, health checks, ECMP, controller failover) still needs its own spec beyond this ADR; nanopb schemas and the named-pipe sidecar protocol are fixed here.
- The estimated size of the new core is 15k–25k lines of new code rather than ~150k, because the data path is the only hand-written part; everything the OS provides is called, not reimplemented (ADR-0008).

## Amendment 2026-10-14: native-first rule for the new core

Maintainer decision (Hilmi: "ya se rekomend mu lah ... fondasi 100% total"). Revised the same day (Hilmi: "fondasi bersih total dan clean total"): the slim fork ALSO completes its native migration, as #30 steps NAT-1 to NAT-6 (CNG for SHA-1/MD5/MD4/RC4/DES/RNG, the Windows Thread Pool API, PE resources instead of hamcore, strings on strsafe, charsets on the Win32 code-page functions, ETW and the Event Log), so the foundation the new core reuses is native too. zlib stays in the slim fork because compression is part of the legacy SE-VPN wire. The new core uses the Windows-native API from the start wherever one exists, a third-party library only where none exists, and own code only where neither exists:

- Native from the start: Windows Thread Pool API and timer queues (no own thread pool), resources embedded as PE resources via FindResource/LoadResource (no hamcore archive format), strsafe plus MultiByteToWideChar/WideCharToMultiByte for strings and charsets (no own string library or code-page tables), ETW TraceLogging for debug tracing and the Windows Event Log for service events, CNG, Schannel, IOCP, winsqlite3.
- Own code, because Windows has no equivalent: the small containers (list, queue, FIFO, buffer), the packet parser the policy engine needs, the legacy SHA-0 password verifier (only for accounts imported from ranz_server.config; new accounts use PBKDF2 via CNG). The Pack wire format is replaced by nanopb messages on the control stream.
- Dropped: payload compression (zlib), R-UDP, the own thread pool, the own string-table format.

## Amendment 2026-10-14: L2 backend per role

Maintainer decision (Hilmi: "ya setuju"). This replaces the tap-windows6 fallback above:

- Server, virtual L2 (KM-TEST loopback): XDP rule API (proven: TX inspect and RX inject).
- Server, bridge to a physical NIC: SeLow by default (proven, sets promiscuous itself); XDP plus Npcap as a performance option once CORE-S3-3 proves it on a physical NIC and on a Hyper-V network.
- Client (Windows 11, x64 or arm64): L3 through Wintun by default. When L2 is needed: SeLow on KM-TEST by default (signed, x64 and arm64, already shipped, no extra runtime); XDP on KM-TEST as an option if the manual Windows 11 test passes. tap-windows6 is no longer needed.
- Speed matters mainly on servers (10 Gbps target is roughly 0.8 Mpps at 1500 bytes); a client link rarely exceeds what SeLow carries. A CI benchmark of SeLow vs XDP on the same KM-TEST adapter gives the numbers.
