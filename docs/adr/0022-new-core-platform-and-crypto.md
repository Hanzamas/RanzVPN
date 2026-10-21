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

- msquic worker callbacks process **each datagram inline**: Noise decrypt, policy lookup, then hand the frame to the adapter ring. *(Since the 2026-10-15 single-encryption amendment: msquic has already decrypted the datagram; the callback does policy lookup and the hand-off only.)*
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
- The transport-security layering, key separation and forward secrecy are specified in ADR-0023 (since 2026-10-15: single encryption by QUIC/TLS, Noise for identity bound to the outer session).

### Roles and SE-VPN compatibility

- **One node binary** with roles: `server`, `client` (cascade), `bridge`, `controller`, `relay`. There is **no separate client product**.
- The **legacy SE-VPN TCP listener is dropped once the new transport works**. SE-VPN interoperability is tested against the pinned `main-oracle` releases (ADR-0017), not an in-process legacy listener kept alive inside the new core.

### Configuration store

- **SQLite via `winsqlite3.dll`** (the copy in System32; no vendored library), introduced in the new core with a **one-time importer from `ranz_server.config`**. The old `Cfg` design has lock contention; SQLite replaces it rather than being ported.

### Client adapters and packet I/O

- **L3: Wintun** (default, Accepted in ADR-0009).
- **L2:** the Microsoft **KM-TEST Loopback Adapter** (ADR-0018 decision 4), a Hyper-V network, or a physical NIC (SeLow, Npcap, or XDP, per the ADR-0018 backend matrix).
- **Windows 11 client L2** is unproven: Microsoft documents and tests XDP only on Server. Run the XDP spike artifact by hand once in a Windows 11 VM; if it fails, the client L2 fallback is **tap-windows6**. *(Superseded by the ADR-0002 amendment of 2026-10-21: no by-hand run; Server 2025 CI, run-time fallback to SeLow.)* A Ranz-built L2 driver stays crossed out (ADR-0018).
- **arm64 is L3 only** until a production-signed arm64 XDP runtime exists (today's arm64 runtimes are test-signed, which needs Secure Boot off and cannot ship).
- **XDP: ship on the XDP 1.4 rule API** (`XdpCreateProgram`, supported until 2028-01-29), which is the only XDP path that captures the frames the OS sends. The **eBPF path is rejected for now**: the `spike/xdp-ebpf` result (`spike-xdp-ebpf-result.md`) is conclusive that eBPF for Windows has no TX-inspect hook (every program attaches to `{L2, RX, INSPECT}`), and no production-signed eBPF runtime exists. Finish the eBPF spike in parallel and switch only when eBPF-for-Windows installs cleanly and is production-signed. **Re-verify the `xdp.sys` signature on a Server 2022 VM with Secure Boot on and test signing off before ADR-0018 decision 4 is treated as final.** XDP installs via a separate `Install-RanzXdp.ps1`, not bundled in the MSI for v1.
- **KM-TEST details:** a per-adapter locally administered MAC derived from the node id and the network id (so two adapters on one segment do not share a MAC); forward ARP, IGMP, LLMNR and NetBIOS chatter and rate-limit broadcast per VLAN; add broadcast, multicast and 802.1Q-tagged injection to the spike.
- **QUIC accelerated through the msquic XDP datapath** (ADR-0018 decision 2): **Accepted, default off, Server x64 only** — one flag, no Ranz AF_XDP code.
- **QTIP** (ADR-0018 decision 5): strangler step 7, default port **8443** (both TCP and UDP reserved, configurable), proven with a two-VM spike. *(Superseded by the ADR-0002 amendment of 2026-10-21: two node processes on one CI runner.)*
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

- **Enrollment:** username/password checked by the existing Sam, plus Noise static-key pinning on first login (TOFU). Admin-issued one-time join tokens are a later addition. *(Password hashing changed 2026-10-19, see the amendment below: PBKDF2-SHA256 via CNG, not Sam's SHA-0.)*
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
- Client (Windows 11, x64 or arm64): L3 through Wintun by default. When L2 is needed: SeLow on KM-TEST by default (signed, x64 and arm64, already shipped, no extra runtime); XDP on KM-TEST as an option if the manual Windows 11 test passes. tap-windows6 is no longer needed. *(Corrected in the amendment of 2026-10-21 below: SeLow ships for x64 only.)*
- Speed matters mainly on servers (10 Gbps target is roughly 0.8 Mpps at 1500 bytes); a client link rarely exceeds what SeLow carries. A CI benchmark of SeLow vs XDP on the same KM-TEST adapter gives the numbers.

## Amendment 2026-10-15: measured SeLow vs XDP, client default flips to XDP

CI benchmark on the same KM-TEST adapter (branch spike/selow-vs-xdp, Server 2022/2025, 1500 B): XDP TX capture 1.24-1.47 Mpps on about 1.1-1.4 cores, RX inject 337-445 kpps; SeLow TX capture 0.93-1.25 Mpps on 4 cores, RX inject about 70 kpps (WriteFile about 14 us per frame).
Maintainer decision (Hilmi: "(b) XDP default di x64"): this supersedes the client line of the 2026-10-14 amendment.
- Server: XDP is the default for virtual L2 AND for the physical-NIC bridge (XDP plus Npcap for promiscuous until xdp-for-windows #44); SeLow is not viable at 10 Gbit/s and stays only as a compatibility fallback.
- Client x64: XDP on KM-TEST is the default L2 backend (needs the XDP runtime; Microsoft does not yet support XDP on client SKUs, so the manual Windows 11 test gates it, superseded by the ADR-0002 amendment of 2026-10-21: run-time detection instead); SeLow on KM-TEST is the fallback when XDP is not installed or fails.
- Client arm64: SeLow on KM-TEST (no production-signed arm64 XDP runtime yet). *(Corrected in the amendment of 2026-10-21 below: there is no arm64 SeLow package.)*
- Known XDP risks to handle in CORE-S3-2: TX inspect with USO blocks senders instead of dropping when the consumer lags; unbinding ms_xdp can hang after heavy load; one unreproduced RX-inject stall followed by WSAENOBUFS. Mitigations: a dedicated drain thread per queue, bounded rings, health check plus reattach, unbind only after all sockets close with a timeout, a CI soak test, and upstream issues.

## Amendment 2026-10-15: multi-connection tunnels

Maintainer decision (Hilmi: "catat"). One QUIC connection is processed on one msquic worker, so a tunnel on one connection is capped by one core (estimated 3-8 Gbit/s on a modern server). To scale past that:
- A tunnel may span N transport connections (QUIC or TLS-443), negotiated in the session layer, each pinned to a different core. N is configurable with an automatic default from the core count and link speed; N = 1 stays the default for small links.
- Inner traffic is spread over the connections by a hash of the inner flow (5-tuple for IP, MAC pair plus EtherType for other L2), never per packet, so the packet order inside one inner flow is kept. One inner flow is therefore still limited to one connection.
- Each connection carries its own Noise transport keys derived from the session handshake, and rekeys on its own; losing one connection moves its flows to the others without tearing down the session. *(Superseded by the single-encryption amendment below: each connection is encrypted only by its own QUIC/TLS keys and bound to the session's Noise identity; the failover rule stays.)*
- Together with QUIC over the XDP datapath (ADR-0018 decision 2) and USO/URO, the design target is tens of Gbit/s per tunnel and 50-100 Gbit/s per server on 64 cores with 100G NICs (estimate, to be measured once CORE-S1 runs on real hardware).

## Amendment 2026-10-15: TCP-over-TCP meltdown on the TLS/TCP 443 path

Maintainer decision (Hilmi: "ya"). Tunnelling TCP inside the TCP-443 fallback causes retransmission amplification on lossy links; it cannot be removed while the outer transport is TCP.
1. Avoid it: QUIC over UDP stays the primary transport; TLS/TCP 443 is used only when UDP is blocked.
2. v1 mitigations on the TCP path: an active queue (CoDel-style) at the tunnel ingress drops inner packets whose queueing delay exceeds the target instead of buffering them, so inner TCP backs off early; multi-connection tunnels (previous amendment) confine a loss stall to the flows of one connection; the outer TCP uses BBR2 where Windows offers it (to verify on Windows 11 and Server 2022/2025), otherwise the system default.
3. Phase 2 option for L3 mode: TCP splitting. The client node terminates inner TCP flows with a user-mode TCP stack and sends only the byte stream through the tunnel, which removes the meltdown entirely; it applies to L3 TCP traffic only, not to L2 frames, and changes end-to-end ACK semantics, so it is opt-in.

## Amendment 2026-10-15: BBR congestion control in v1

Maintainer decision (Hilmi). msquic runs with its BBR congestion controller instead of CUBIC by default, because BBR keeps throughput on lossy links (public Wi-Fi, mobile, long international routes) where CUBIC backs off on every loss. CUBIC stays selectable per link. The CORE-S1 benchmark measures both on a lossy-link case.

## Amendment 2026-10-15: single encryption

Maintainer decision (Hilmi: "gaperlu ada enkripsi ganda, catat"); the full rule is in ADR-0023 (amendment 2026-10-15).
- Data is encrypted once, by msquic (QUIC) or Schannel (TLS 1.3), AES-GCM. The core does no per-packet crypto of its own on the QUIC and TLS-443 paths, which roughly halves the crypto cost per byte and brings per-core throughput close to WireGuard.
- Noise_IK (CNG X25519, KSP identity key) stays as the identity handshake on the first stream of each connection, bound to that connection through the TLS exporter where the stack exposes one (Schannel: `SECPKG_ATTR_KEYING_MATERIAL`). A mismatch closes the connection.
- Inner Noise data encryption remains only for the phase-2 CDN path.
- Spike in CORE-S1-1: check whether Schannel (with TLS 1.3) and msquic expose an RFC 8446 exporter to the application (no msquic exporter API is known yet). Where one does not, the binding falls back to `tls-server-end-point` (RFC 5929: the hash of the pinned server certificate, whose key is in a KSP) in the Noise prologue; data encryption stays single either way.

## Amendment 2026-10-19: no SoftEther compatibility, PBKDF2 passwords

Maintainer decisions (Hilmi: no stock SoftEther client, not even during the transition; "PBKDF2 CNG"). See the ADR-0011 amendment of the same date.
- **SE-VPN interoperability is no longer a requirement.** The strangler steps are no longer interop-tested against the SoftEther `main-oracle` releases for protocol compatibility; the harness goldens remain the behaviour seam. The legacy listener is still dropped in step 8, unchanged until then.
- **Password hashing in the new core: PBKDF2-SHA256 via CNG** (`BCryptDeriveKeyPBKDF2`), with a per-user random salt and an iteration count stored next to the hash, so it can be raised later. The password reaches the node inside the encrypted session (Noise/TLS), so the node verifies it directly against the PBKDF2 hash; no SHA-0 challenge-response. Sam's SHA-0 `HashedKey` is not carried into the new core. There are no deployed users, so nothing is migrated.
- **The one-time importer from `ranz_server.config` is optional:** no deployed configs exist, so it is needed only if development or test configs must be carried over. To be decided when CORE-F4 (#64) is picked up.

## Amendment 2026-10-19: L2 adapter throughput, no adapter bonding, XDP ring batching

Maintainer decision (Hilmi: "catat, batching optimal di ring XDP"). A KM-TEST loopback adapter has one queue, so the client L2 path is capped per adapter; the 2026-10-14 benchmark measured RX inject at 337-445 kpps (about 4-5 Gbit/s at 1500 B) and TX capture at 1.24-1.47 Mpps on CI runner VMs.
- **No adapter bonding.** Windows client SKUs have no native NIC teaming (LBFO is Server-only and deprecated), real bonding needs an own kernel driver (crossed out, ADR-0018), and spreading one L2 segment over several adapters in user mode gives several MACs/IPs per network, ARP and gateway confusion and Local Bridge loops.
- **Parallelism comes from the design instead:** one adapter per network/VLAN (a client in four networks has four KM-TEST adapters, four queues, no loop), multi-connection tunnels on the transport (amendment 2026-10-15), multi-queue physical NICs (RSS) or Hyper-V networks (VMQ/vRSS) on servers, and L3 mode (Wintun) for throughput-heavy single networks.
- **XDP ring batching is a required optimisation in CORE-S3:** reserve and submit descriptors in bulk (XskRingProducerReserve/Submit, XskRingConsumerReserve/Release with batches of tens to hundreds of frames), one XskNotifySocket poke or wait per batch instead of per frame, fill and completion rings recycled in bulk, rings and UMEM sized for bursts. Batch size is adaptive: flush at N frames or after a short timeout (tens of microseconds) so latency stays bounded at low load.
- **Measure on real hardware** (superseded by the ADR-0002 amendment of 2026-10-21: measured on CI runners as a regression number) in CORE-S3 (batch sizes 1/16/64/256; pps and CPU per core for TX capture and RX inject). Target: RX inject of at least 1 Mpps on one KM-TEST adapter. Revisit this amendment only if a single network on a client still needs more than one adapter can carry after batching.

## Amendment 2026-10-21: no arm64 SeLow package

Correction of fact (Hilmi: "ya gas"). The 2026-10-14 and 2026-10-15 amendments name SeLow as an arm64 client backend. The repository ships SeLow for x64 only (`src/bin/hamcore/DriverPackages/SeLow_Win10/x64`), and ADR-0009 and ADR-0013 record that there is no arm64 package and that SeLow cannot be rebuilt for arm64 without a driver-signing pipeline of our own.
- **Client arm64 is L3 only** (Wintun), as the Decision ("arm64 is L3 only") and the Consequences already state, until a production-signed arm64 XDP runtime exists. An arm64 client that needs L2 has no backend until then.
- **Client x64 is unchanged:** XDP on KM-TEST by default, SeLow on KM-TEST as the fallback.

