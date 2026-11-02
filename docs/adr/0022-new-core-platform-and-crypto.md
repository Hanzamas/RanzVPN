# ADR-0022: New-core platform, threading, crypto, adapters and the strangler plan

**Status:** Accepted (2026-10-13, from the grilling; "windows native total yang fast and furious", ADR-0008). This ADR consolidates the platform decisions for the new core and builds on ADR-0005 (transport), ADR-0006 (tiers), ADR-0007 (Schannel), ADR-0010 (routing), ADR-0018 (packet I/O) and ADR-0019 (VLAN and policy), each now Accepted. The security and anti-censorship design is ADR-0023. The SDN spec #176 amends the control plane, step 6, step 8 and the ports (amendment of 2026-10-20). Amended 2026-10-21: TCP splitting on the Windows TCP stack, the node identity key in the software KSP, server and controller keys in the CNG KSP with explicit Schannel key exchange groups.

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
- **Node identity key in a CNG KSP** (TPM-backable), used for Noise static-key authentication. *(Amended 2026-10-21 below: the software KSP, because the TPM provider has no curve25519.)*
- **Certificates via CryptoAPI:** ECDSA P-256 self-signed certificates, PFX import; ACME is a later addition, not core work for v1. Certificate keys live in a CNG KSP (`PKCS12_ALWAYS_CNG_KSP`) so TLS 1.3 server signatures (RSA-PSS / ECDSA) work. *(Amended 2026-10-21 below: server and controller keys always live in the CNG KSP, which closes the legacy-CSP question of #45.)*
- **Post-quantum** is a CNG ML-KEM hybrid with X25519, used where the OS provides it (Windows 11 24H2 / Server 2025 and later) in both TLS and Noise; it is otherwise a later addition, not a blocker. *(Amended 2026-10-21 below: Schannel's key exchange groups are set explicitly, X25519MLKEM768 first.)*
- The transport-security layering, key separation and forward secrecy are specified in ADR-0023 (since 2026-10-15: single encryption by QUIC/TLS, Noise for identity bound to the outer session).

### Roles and SE-VPN compatibility

- **One node binary** with roles: `server`, `client` (cascade), `bridge`, `controller`, `relay`. There is **no separate client product**. *(Since the amendment of 2026-10-20 below: the `controller` role leaves the node; the controller is the separate `ranz-controller` service, ADR-0026.)*
- The **legacy SE-VPN TCP listener is dropped once the new transport works**. SE-VPN interoperability is tested against the pinned `main-oracle` releases (ADR-0017), not an in-process legacy listener kept alive inside the new core. *(SE-VPN returns after v1 only in the separate `ranz-compat` sidecar, amendment of 2026-10-20 below.)*

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

- A **`controller` role** in the node binary: one active per deployment plus a passive standby. *(Superseded by the amendment of 2026-10-20 below: a separate Go service with rqlite, one member by default and 3 or 5 members for HA, ADR-0026.)*
- **protobuf via nanopb (C)** on the Noise control stream; **no gRPC in the core**.
- **BGP via a Go sidecar `ranz-bgp`** that embeds GoBGP as a library (ADR-0010). The core talks to the sidecar over a **named pipe with JSON** (announce, withdraw, learned routes); the core installs learned routes into Windows through IP Helper. It is an optional MSI feature, built in CI (Go cross-compiled for x64 and arm64), and spiked on Windows when L3 networks land (strangler step 7). **No RRAS.** *(Amended 2026-10-22: `ranz-bgp` becomes the subcommand `ranz bgp` of the one `ranz.exe`, not an optional MSI feature; ADR-0011 amendment, ONE-1.)*

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
6. L3 routed networks (IP Helper routes, WinNAT). *(Without WinNAT since the amendment of 2026-10-20 below: NAT in the data plane and three egress tiers.)*
7. GoBGP sidecar, QTIP, the tier-3 mimicry sidecar (ADR-0023) and the CDN / WebSocket path.
8. Retire the legacy listener, vpncmd and OpenSSL, together with the slim fork. *(They still leave the node; the frozen slim-fork Cedar lives on after v1 only as `ranz-compat`, amendment of 2026-10-20 below.)*

**Before step 1**, do the perf work that the surviving hub needs: ticket #31 Q2 (IP table expiry) and the D2 back-pressure move. Skip D1 (flooding), because the new switch at step 4 replaces it.

### Enrollment, IPv6 and scale

- **Enrollment:** username/password checked by the existing Sam, plus Noise static-key pinning on first login (TOFU). Admin-issued one-time join tokens are a later addition. *(Password hashing changed 2026-10-19, see the amendment below: PBKDF2-SHA256 via CNG, not Sam's SHA-0.)*
- **IPv6:** full dual-stack in the new core (transport, adapters and policy).
- **v1 scale target (benchmark goal): 10,000 sessions per node and 10 Gbps.** Larger scale comes from many nodes plus the GoBGP sidecar, not from one bigger node.
- **Non-Windows clients** are served by a standard-protocol plugin transport in phase 2, out of v1. *(Since 2026-10-20: other platforms join through the compat protocols of `ranz-compat` in the Legacy phase, ADR-0037.)*

## Consequences

- The new core ships **zero third-party crypto**: Schannel and CNG only, OpenSSL and liboqs gone. The slim fork is unaffected and keeps OpenSSL, liboqs and the X25519MLKEM768 TLS group for stock clients.
- Removing the hub-wide forwarding lock and moving to read-mostly tables is a correctness risk concentrated in the new switch (step 4); the harness frame tests and the benchmark are the net.
- Depending on the XDP rule API means tracking its deprecation: XDP 1.4 is pinned and supported to 2028-01-29, msquic's own datapath still uses the rule API, and SeLow on the loopback adapter stays the fallback behind the Local Bridge backend interface (ADR-0018). The eBPF path is re-checked on every XDP release.
- arm64 nodes run L3 only until Microsoft ships a production-signed arm64 XDP runtime, so an arm64 deployment that needs L2 has no virtual adapter yet.
- The control plane's own design (route advertisement, approval, health checks, ECMP, controller failover) still needs its own spec beyond this ADR; nanopb schemas and the named-pipe sidecar protocol are fixed here. *(Specified since 2026-10-20 by the SDN spec #176 in ADR-0025 to ADR-0027, except the approval step for advertised subnets, which #176 does not mention; since 2026-10-21 the `Gateway` resource is the approval, ADR-0010 amendment of that date.)*
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
3. Phase 2 option for L3 mode: TCP splitting. The client node terminates inner TCP flows with a user-mode TCP stack and sends only the byte stream through the tunnel, which removes the meltdown entirely; it applies to L3 TCP traffic only, not to L2 frames, and changes end-to-end ACK semantics, so it is opt-in. *(Amended 2026-10-21 below: the Windows TCP stack terminates the flows, reached through a WinDivert redirect to a local listener; no user-mode TCP stack.)*

## Amendment 2026-10-15: BBR congestion control in v1

Maintainer decision (Hilmi). msquic runs with its BBR congestion controller instead of CUBIC by default, because BBR keeps throughput on lossy links (public Wi-Fi, mobile, long international routes) where CUBIC backs off on every loss. CUBIC stays selectable per link. The CORE-S1 benchmark measures both on a lossy-link case.

## Amendment 2026-10-15: single encryption

Maintainer decision (Hilmi: "gaperlu ada enkripsi ganda, catat"); the full rule is in ADR-0023 (amendment 2026-10-15).
- Data is encrypted once, by msquic (QUIC) or Schannel (TLS 1.3), AES-GCM. The core does no per-packet crypto of its own on the QUIC and TLS-443 paths, which roughly halves the crypto cost per byte and brings per-core throughput close to WireGuard.
- Noise_IK (CNG X25519, KSP identity key) stays as the identity handshake on the first stream of each connection, bound to that connection through the TLS exporter where the stack exposes one (Schannel: `SECPKG_ATTR_KEYING_MATERIAL`). A mismatch closes the connection.
- Inner Noise data encryption remains only for the phase-2 CDN path.
- Spike in CORE-S1-1: check whether Schannel (with TLS 1.3) and msquic expose an RFC 8446 exporter to the application (no msquic exporter API is known yet). Where one does not, the binding falls back to `tls-server-end-point` (RFC 5929: the hash of the pinned server certificate, whose key is in a KSP) in the Noise prologue; data encryption stays single either way. *(Answered by the amendment of 2026-10-26 below: msquic 2.6 exports, and the QUIC path binds the exporter of its connection, CORE-H5.)*

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

## Amendment 2026-10-20: controller service with rqlite, step 6 without WinNAT, SE-VPN only through `ranz-compat`, the front door on 443

Maintainer decision, from the SDN spec #176 that Hilmi filed ("controller as a service with rqlite instead of an active and passive standby role; strangler step 6 without WinNAT; step 8 still retires the legacy SE-VPN listener from the node, and SE-VPN returns only in the Legacy phase as `ranz-compat`; the front door on 443"). #176 builds on strangler steps 5 to 7. It supersedes CORE-S5-1 (#77, the controller role with a passive standby) and CORE-S6-2 (#81, control-plane route distribution), and amends CORE-S6-1 (#80).
- **Controller.** The `controller` role leaves the node; the node roles are `server`, `client`, `bridge` and `relay` (ADR-0011 amendment of 2026-10-20). `ranz-controller` is a Go service on Windows or Linux with rqlite as a sidecar store: a single member by default, a 3 or 5 member Raft cluster for HA, and no passive standby (ADR-0026). nanopb on the Noise control stream stays the transport; it carries desired state by Generation, with deltas and acknowledgements (ADR-0027).
- **Configuration store.** The node keeps `winsqlite3` for its local state. The intent lives only in the controller.
- **Strangler step 6** builds L3 routed networks with IP Helper routes and without WinNAT: 1:1 NAT and SNAT per VRF in the node's data plane, and internet egress in three tiers (RRAS NAT on Server, WinNAT only where Hyper-V is present and no NetNat exists, a proxy on the Windows TCP/IP stack everywhere else; ADR-0025). CORE-S6-1 (#80) follows this instead of WinNAT.
- **Strangler step 8 still retires the legacy SE-VPN listener from the node.** SE-VPN returns only in the Legacy phase, after v1, as the separate `ranz-compat` sidecar: the frozen slim-fork Cedar with OpenSSL (ADR-0037). The node and the new protocol stay free of SE-VPN compatibility and of OpenSSL.
- **The front door on 443.** Publicly a node needs only TCP 443 and UDP 443. TCP 443 has one front door that peeks the first bytes with `MSG_PEEK`, routes by SNI and ALPN or by the first bytes, and hands each accepted socket to its owner process with `WSADuplicateSocketW`, proxying nothing after the handoff. UDP 443 stays QUIC only, owned by msquic (ADR-0035).
- **Policy engine.** The conntrack table bounded per network becomes a conntrack quota per VRF, with per-protocol timeouts in the intent (ADR-0029).
- **Scale.** The per-node target of 10,000 sessions and 10 Gbps stays. One controller cluster targets 10,000 nodes, 1,000 VRFs and 100,000 routes.

## Amendment 2026-10-21: TCP splitting on the Windows TCP stack

Maintainer decision (Hilmi: "ya ya ya semua"). Item 3 of the TCP-over-TCP amendment of 2026-10-15 stays a phase-2 option for L3 mode, without a user-mode TCP stack of our own.
- **The Windows TCP stack terminates the inner TCP flows.** Overlay TCP flows are redirected to a local listener with WinDivert, the same mechanism as egress tier 3 (ADR-0025), and only the byte stream goes through the tunnel. *(Made concrete by the amendment of 2026-11-01 below: the redirect is the rewrite in the node's own data path on its Wintun adapter that tier 3 uses, so no WinDivert driver is loaded.)*
- **It stays opt-in** and applies to L3 TCP traffic only, as before.
- **No own user-mode TCP stack is added**, so ADR-0014 holds. CORE-P2-3 (#94) is updated to match.

## Amendment 2026-10-21: the node identity key in the software KSP

Maintainer decision (Hilmi: "ya ya ya semua"). The node identity key stays in the software KSP (Microsoft Software Key Storage Provider). The TPM provider has no curve25519, and the Noise suite is X25519, so the key cannot be TPM-held as the crypto section's "TPM-backable" suggests. A TPM-held wrapping key for the identity key is an option after v1.

## Amendment 2026-10-21: server and controller keys in the CNG KSP, explicit Schannel key exchange groups

Maintainer decision (Hilmi: "ya ya ya semua"). CORE-S2-1 (#69) is updated to match.
- **Server and controller keys always live in the CNG KSP.** A PFX is imported into the KSP, never into a legacy CSP. The question of spec #45, whether Schannel TLS 1.3 falls back to 1.2 or fails when the server key sits in a legacy CSP, is therefore closed: the case does not arise.
- **Schannel's key exchange groups are set explicitly:** X25519MLKEM768 first, X25519 as the fallback, because Schannel does not pick the hybrid by default on builds 26100 and 26200.

## Amendment 2026-10-26: the QUIC path binds the exporter of its connection (CORE-H5)

CORE-H5 (#408), from finding F1 of the formal model (AUD-5, `docs/formal-model.md`). It answers the spike of the amendment of 2026-10-15 for msquic.
- **msquic 2.6 exports keying material:** `ConnectionExportKeyingMaterial` (API table, preview part of `msquic.h`), on Schannel through `SECPKG_ATTR_KEYING_MATERIAL`, as the TLS-443 path does. The QUIC path binds the Noise handshake to the exporter of its connection (`NOISE_EXPORTER_LABEL`, no context, 32 bytes; `TransportQuicExporter`), taken in the CONNECTED event while msquic holds the TLS state. The fallback to `tls-server-end-point`, which is the same for every connection to one certificate and so let a middlebox with the key of the certificate relay a session, is no longer used.
- **Data encryption stays single.** The other way that the ticket offered, an unbound QUIC session with its records under the Noise keys, was not needed. Cost of the exporter against the certificate binding on the vpntest harness (`quicbind`, 10000 records of 1400 bytes, best of 3, one CI run): x64 385.4 against 373.3 MB/s and 4.46 against 4.46 ms of CPU per MB, handshake 4.9 against 5.1 ms; arm64 215.0 against 101.2 MB/s and 8.93 against 11.16 ms of CPU per MB, handshake 7.5 against 7.1 ms. The records are the same, so the difference is the noise of a shared runner.
- **A node of the build before CORE-H5 is refused cleanly over QUIC,** both ways: the binding type in the prologue differs, so the handshake fails at message 1, with no session. Over TLS-443 the two still interoperate.
- **Follow-up CORE-H5-R (#443).** A client whose handshake fails on the stream that a race gave takes that transport out of the races of the server for `TRANSPORT_FALLBACK_HOLD` (5 min), so in a rolling upgrade the new node reaches the old one over TLS-443 at its next dial, and QUIC is tried again after the hold (`TransportFallback.c`); no version flag is needed. The exporter is read only from the pinned msquic minor (2.6, any patch), since the preview part of the API table may change with a minor; another minor is refused with a line of the node log, as is any side that has no exporter.

## Amendment 2026-11-01: TCP splitting built (CORE-P2-3)

CORE-P2-3 (#94) builds item 3 of the TCP-over-TCP amendment of 2026-10-15 as the amendment of 2026-10-21 decided it: the Windows TCP stack terminates the inner TCP flows, and no user-mode TCP stack is added, so ADR-0014 holds.
- **Off by default, per L3 Network.** `tcpSplit` of a Network resource turns it on; an L2 Network is refused, as it carries Ethernet frames, which no node terminates. Every node of the VRF gets it as `tcp_split` of the Network object of its state (`control.proto`). A node splits the TCP connections that its host opens from its address in such a Network, and opens to their real destination the ones that a peer sends from its address in one (`src/Cedar/NodeSplit.c`).
- **The redirect to the Windows TCP stack** is the rewrite of tier 3 of the egress (ADR-0025 decision 13, `NodeEgress.c`), in the node's own data path on the Wintun adapter of the VRF, which carries every packet of the host there. The SYN of the host's connection goes back into that adapter with the real destination as its source and the node's listener on its own address in the Network as its destination, so the host's TCP stack terminates the connection; every later segment of the connection takes the same way, and what the listener answers goes back to the application from the destination that it dialled. **No WinDivert driver is loaded:** the node needs no packet driver for packets that its own adapter carries. WinDivert stays the opt-in packet driver of ADR-0025 decision 14, with its gate, for traffic that crosses no Ranz adapter. This is what "with WinDivert, the same mechanism as egress tier 3" of the amendment of 2026-10-21 comes to, since tier 3 as SDN-12 built it rewrites in the data path and loads no driver.
- **Only the byte stream crosses the tunnel**, as control records of the Noise session of the peer: OPEN, ANSWER, DATA (16 KiB at most), WINDOW, FIN and RESET. Each direction of a flow has a window of 256 KiB that its receiver grants again as it writes the bytes to its socket, so a slow reader holds at most a window of a flow and never the session. The peer opens the connection with an ordinary socket only when its forwarding table routes the source to the sender and the destination to its host, the source is an address of the sender in a Network that splits TCP, the session profiles and the policy of the VRF allow a SYN between the two ends, a 1:1 NAT rule translates the destination as for a packet, and a destination of the default route alone is none that the egress refuses.
- **The end-to-end ACK changes:** an ACK that an application gets means that its node has the data, not that the far end has it, and the far end sees the connection come from the node at its end of the tunnel, which dials it. That is why the mode is opt-in. Connect, data, half-close, reset and timeout map to the far side: the host's SYN waits until the peer reached the destination, a refusal resets the host's connect, a destination that does not answer leaves it to time out, and a half-close and a reset of either end reach the other; a Noise session that closes resets the split connections of its peer.
- **Measured** on the lossy-link case of the vpntest harness (1% and 2% loss, 50 ms round trip, 10 Mbit/s, TLS-443; `vpntest lossylink`, deterministic): the inner goodput with splitting is 3477 kbit/s at 1% loss against 3159 with CoDel alone and 3055 plain, and 2730 at 2% loss against 2194 and 2161.
- **Every node of the VRF must run it.** A node of an older release would answer no split flow of its peers, so their split connections to it would time out. Each node reports the Capability `tcpSplit` (ADR-0033 amendment of 2026-11-02), and the Controller refuses a node that does not report it as a member of a VRF with a Network that splits TCP, before the apply.
- **Not in this step:** IPv6 connections and every other protocol take the packet path; the rate limits of a VRF and of the node (`NodeShape.c`) do not count a split connection, and those of a session profile count its SYN alone, not its byte stream.

