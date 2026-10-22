# Architecture discussion log (2026-10-10 to 2026-10-11)

This is the reasoning behind the ADRs in `docs/adr/`, written for someone who was not in the conversation. The discussion happened in Indonesian between Hilmi (maintainer) and the assistant while the slim-down tickets were being implemented; it is grouped by topic here, not in chronological order. Numbers marked **measured** come from commands run on the tree; numbers marked **estimate** are projections and should be treated as such.

## 1. Where the slim-down stands and what the numbers say

Starting point (measured on the clone of `Hanzamas/SoftEtherVPN` (renamed `Hanzamas/RanzVPN` on 2026-10-13) at `69c0aa69`):

| What | Lines |
|---|---|
| C source only, `src/Cedar/*.c` + `src/Mayaqua/*.c` | 289,866 |
| everything under `src/`, all extensions | 582,226 |
| whole repository, all text files (estimate derived from the above) | about 610,000 |

Index sizes (measured): CodeGraph 368 files, 19,596 nodes, 85,119 edges; graphify 13,875 nodes, 61,472 edges, 400 communities, largest community cohesion 0.02.

Per-ticket results (measured from the commits on branch `slim`, PR #22):

| Ticket | Commit | Files | Lines |
|---|---|---|---|
| #2 baseline, CI self-check | `07bda645`, `afd0ba3f`, `1860c7d5` | 7 | +140 |
| #3 Windows GUI removal | `fb235eb8` | 225 | +127 / -72,335 |
| #4 JSON-RPC, web console, VPN Gate stubs, devtools | `7e4a8d7b` | 111 | +10 / -103,472 |
| #5 vpnbridge | `c9792378` | 13 | +2 / -215 |
| #6 MsChapV2 module (prefactor) | `f23dfe55`, `9508e9c3` | 13 | +472 / -280 |
| #7 + #8 OpenVPN and SSTP | `025c8a24` | 26 | +2 / -5,671 |
| #9 IPsec family | `f011e0b2` | 33 | +12 / -17,518 |
| #10 WireGuard, libsodium, BLAKE2 | `9aa18703` | 22 | +11 / -1,982 |

C source only after the GUI ticket: 234,982 (measured). `git diff master..slim` after #9 was staged: 360 files, +759 / -181,973 text lines (measured); the GitHub PR page showed about 199,944 deletions at that point (Hilmi's number; it counts differently from `git diff --shortstat`).

Tree by area after #9 (measured, text files only, binaries excluded):

| Area | Lines |
|---|---|
| `src/Cedar` (.c, .h, .cpp) | 157,053 |
| `src/Mayaqua` | 84,848 |
| `src/bin/hamcore` | 127,499 (of which the nine `strtable_*.stb`: 66,537) |
| `src/See` + `src/SeeDll` + `src/Neo` | 22,824 |
| `src/Neo6` + `src/SeLow` | 6,024 |
| executables, tools, CI, iOS sample, developer_tools | about 7,000 |
| total | about 407,000 |

Other measured facts used in the discussion: the foreign protocol modules (`Proto_*.c/.h` without `Protocol.c`) were 23,579 lines; the Windows GUI files were 77,204 lines (`SM.c` 20,901, `CM.c` 12,667, `WinUi.c` 9,558, `SW.c` 6,317, ...); the Unix/Windows platform files were 27,410 lines; `OS_UNIX` appeared in 30 files (127 hits), `OS_WIN32` in 66 files (671 hits); `Str.c` went 5,090 to 3,058 and `Pack.c` 2,540 to 1,809 when the JSON code left; `Client.c` went 10,785 to 8,988 when the notify service left.

Projections (all **estimates**):

| Stage | C lines (.c only) | all text lines |
|---|---|---|
| now (after #10) | about 223,000 | about 405,000 |
| after the twenty tickets | about 168,000 | about 260,000 |
| after the safe cleanup catalogue (ADR-0003) | 135,000 to 145,000 (150,000 to 160,000 including headers) | about 235,000 |

The remaining 170k text lines to remove break down as: C about 51k (PPP and dispatcher, RADIUS, SecureNAT family 16k, cloud 5k, clustering, PKCS#11 with its `pkcs11*.h`, Unix platform 7k, cascading edits in Admin/Command/Server), legacy driver sources `See/`, `SeeDll/`, `Neo/` 23k, iOS sample and Unix CI/docs 2k, hamcore 68k (seven string tables 52k, pruning of the two kept tables, warning texts, driver `.inf` files), and the safe cleanup catalogue 25k.

Why the end result is still about 150k lines of C: line count is not logic. SoftEther's style (Allman braces, a four-to-five-line `// Validate arguments` block per function, blank lines, comments) makes 35 to 40 percent of lines non-statements; 160k lines are about 95k to 100k statements. The composition of what remains (estimate): vpncmd `Command.c` + `Console.c` 16.5k, `Admin.c` 10k, the protocol core (`Protocol`, `Connection`, `Session`, `Listener`, `Link`, `Hub`) 25k, `Server.c` + `Client.c` 15k, bridge/VLAN/L3/logging/UDP acceleration 13k, `Network.c` 13k, the rest of Mayaqua 35k, headers 20k, `WaterMark.c` 4.3k (a JPEG as a C array), WinPcap headers 3k. Going below that means cutting features (vpncmd to an essential subset, L3 switch, EtherLogger) or the behaviour-changing refactors that ADR-0002 forbids without a test harness.

## 2. Where the tangle ("benang kusut") really is

Hilmi's stated motivation for the whole exercise is to get a codebase he can understand. The diagnosis in the discussion was that the tangle is not duplication but structure:

1. A god header and god structs: every `.c` includes `Cedar.h`, which pulls in `CedarType.h` with about 500 typedefs; `SERVER`, `CEDAR`, `SESSION`, `CONNECTION`, `HUB` have hundreds of fields mutated from everywhere under scattered locks. graphify measured this as 400 communities with cohesion 0.02.
2. Files are bags, not modules: `Server.c` (11k) mixes config, caps, listeners, clustering and logging; `Protocol.c` (7k) mixes client connect and server accept; `Admin.c` (14k) mixes dispatch, 148 handlers and serializers; `Command.c` is 25k.
3. Implicit contracts in strings: PACK keys (`"hubname"`, `"client_build"`), config keys, string-table keys are literals spread across files; the wire contract is only discoverable by grep.
4. Manual lifecycle: hand reference counting, threads started anywhere, `Halt` flags polled.
5. Duplication (`Ex`/`Ex2`/... chains, ANSI/Unicode pairs, serializer boilerplate) is a symptom, not the disease.

Two ways out were described: (A) strangler in place, in C, step by step (measure with CodeGraph, dead-code sweep, make contracts explicit, split files, shrink headers, table-driven RPC/vpncmd, ANSI/Unicode unification last), or (B) rewrite the core around the protocol with SoftEther as the spec and test oracle. The limiting factor for A is verification, not effort: only the mechanical steps are safe without tests. Hilmi chose to keep only the mechanical steps (ADR-0002, ADR-0003) and to treat the modernised product as new code (ADR-0004 onward).

## 3. Performance ceiling of a user-space VPN on Windows

Constraints given by Hilmi: no kernel code of our own, no hardware offload assumed, but "maximise performance".

What actually bounds throughput (discussion, with commonly reported figures, **estimates**):

- Crypto is not the bottleneck: AES-GCM through OpenSSL EVP with AES-NI runs at 5 to 10 GB/s per core.
- The adapter boundary is: Wintun (shared-memory ring buffers, batched) reaches about 2 to 4 Gbps single flow in user space; SoftEther's Neo6 (batched IOCTL ring) about 1 to 2 Gbps; tap-windows6 (per-packet overlapped `ReadFile`) about 0.5 Gbps.
- Syscalls per packet are the other half: Winsock RIO (registered buffers, completion queues), UDP Segmentation Offload (`UDP_SEND_MSG_SIZE`) and Receive Offload (`UDP_RECV_MAX_COALESCED_SIZE`) let the NIC segment and coalesce; RSS gives multi-queue. "No driver of our own" is therefore not "no hardware help".
- Engine shape: one thread per core, run-to-completion, lock-free queues, packet pools with no allocation on the data path, no global lock like `Cedar->lock`.
- Optional: msquic's XDP-for-Windows datapath (a Microsoft-signed driver) for more than a million packets per second on servers.

Realistic ceiling: multi-Gbps aggregate per server on commodity CPUs, 2 to 4 Gbps single flow. That is comparable to WireGuard-NT (kernel) on aggregate and behind it on single flow. Above that is kernel territory, which is out of scope.

## 4. L2 versus L3, and the shape of the new system

The decision that determines everything else is L2 versus L3. The assistant's first recommendation (ADR-0004) was an L3-only core with L2 as an optional add-on: everything Hilmi asked for next (BGP, routing, firewall, hub-to-hub, hub-to-user, P2P, VLAN, scalability) is an L3 problem with standard tooling, and SoftEther's L2-everywhere design is its biggest "sin". Hilmi later rejected the premise, because L2 is the feature he values most (LAN gaming, broadcast, non-IP protocols). The outcome is **dual-mode networks** (ADR-0014, Accepted, see section 10): each virtual network is either L2 switched or L3 routed, one binary carries both backends. The rest of this section records the reasoning as it was made for the L3 path; it still applies to L3 routed networks.

The sketch (all Proposed): a single node binary (ADR-0011); data plane Wintun to a lock-free packet engine to QUIC/UDP with a TLS/TCP 443 fallback (ADR-0005); every participant is a node, direct P2P with STUN and hole punching, relay fallback (Tailscale/DERP model); a separate control-plane service for identity, membership, route and policy distribution (Headscale/Nebula style); BGP only at the edge via RRAS or GoBGP (ADR-0010); identity-based stateful L3/L4 policy in the data path plus WFP user-mode filters on the host; declarative YAML config plus a local API and web UI; ETW and Prometheus for observability.

P2P and relay were later settled in ADR-0015 (Accepted, 2026-10-11) after an external suggestion Hilmi pasted ("use libjuice/libnice/pion ICE, relay fallback mandatory, direct then port prediction then relay"). The assistant agreed on using an ICE library and a mandatory relay, and corrected two points: ICE handles cone NATs but is not port prediction, so symmetric NAT needs Ranz's own Tailscale-style port prediction and birthday-paradox punching on top of libjuice; Hilmi confirmed on 2026-10-21 that both are in scope from the start (an earlier draft had them deferred, then wrongly recorded as rejected); and a sequential order makes every new pair wait, so the design is relay-first with ICE upgrading the path in the background. The relay is Ranz's own stateless node role speaking the same session as the direct path (as the SoftEther hub already does), self-hostable on any node with a public address (VPS, home server with a mapped port, hub), not TURN; home-router port mapping uses libplum (PCP/NAT-PMP/UPnP); candidates are signed and exchanged through the control plane; one QUIC connection per path with the session layer switching between them.

Language was discussed but not decided: Rust (quinn or msquic bindings, `wintun`, `aes-gcm`, tokio; boringtun as proof) was called the natural pick, C the faster start from the current code, Go (Tailscale) convenient but slower per core.

The slim fork's role in that picture: a compatibility gateway for legacy SE-VPN clients during the transition, a test oracle, and a readable reference. "Best of the best" in this space is already defined by WireGuard-NT (performance), Tailscale (control plane, NAT traversal), Nebula (groups and firewall) and ZeroTier (L2 overlay); the niche is combining those ideas with Windows-native polish and a 443 fallback.

The two paths as they were compared before the dual-mode decision (the final design takes both, per network):

| | L2 switched network | L3 routed network |
|---|---|---|
| adapter | TAP: Neo6 or tap-windows6 (open), bridging via SeLow or Windows Network Bridge | Wintun |
| transport | QUIC datagrams carrying Ethernet frames, custom framing | QUIC datagrams carrying IP packets; MASQUE CONNECT-IP possible |
| routing | the segment is a subnet; routing/firewall/BGP sit on top | Windows IP stack + RRAS/GoBGP |
| estimated final code (as separate products) | about 110k lines | 50k to 60k lines (old auth/config reused + new transport) |

No combined size estimate for the dual-mode product was made.

## 5. Windows APIs instead of reinvented wheels

Hilmi's principle: wherever Windows already has an API, use it; the data path stays ours. The full mapping is ADR-0008. Items that cannot or should not be replaced: the raw-socket listener logic of `Network.c` and `HTTP.c` on the server side in the **slim fork** (the SE-VPN HTTPS encapsulation is the protocol and its PQ hybrid group only exists in OpenSSL there), `Str.c`/`Internat.c`/`Cfg.c`/`Pack.c` in the fork (thousands of call sites, and the config format must still load old files), and MS-RPC/ALPC for administration (it would tie the future web UI to Windows auth; the admin surface is the web UI's API). For the new core the TLS stack question was later settled in favour of Schannel (section 11).

## 6. Adapters and drivers

Hilmi asked why Neo6 and SeLow would not be used and what else exists. Summary (ADR-0009, ADR-0013): Neo6 is technically faster than tap-windows6 but is signed by SoftEther and not ours to modify; SeLow is an NDIS protocol driver for Local Bridge (this log first called it a filter; corrected in the 2026-10-13 amendment of ADR-0009), needed in the slim fork as long as Local Bridge is a kept feature. Under the earlier L3-only recommendation neither would have been needed by the new core; under the dual-mode decision (section 10) Wintun serves L3 networks, a TAP driver serves L2 networks (Neo6 versus tap-windows6 still open), and SeLow or the Windows Network Bridge does the bridging. Other options reviewed and rejected: the UWP VPN Platform (`VpnPlugIn`), RAS/RRAS built-in tunnels, Npcap, and any WFP callout or NDIS driver of our own. XDP-for-Windows is an optional accelerator through msquic.

At one point Hilmi wrote "gas" next to the sentence about keeping Neo6 for an optional L2 service; shortly after he proposed removing `vpnclient` entirely, which leaves Neo6 without a user in the slim fork (confirmed later, ticket #23). Neo6 stays a candidate for the new product's L2 backend; it can be taken back from upstream.

## 7. Transport, "SSL-VPN" and censorship circumvention

Clarifications that came up:

- msquic is QUIC over UDP only; the TCP 443 "SSL-VPN" path is a separate TLS/TCP listener with the same inner framing (ADR-0005). The capability "gets through 443 looking like HTTPS" survives; SoftEther's wire format does not, except as a legacy listener.
- Protocol mimicry of complex applications fails ("The Parrot is Dead"); what works is being the real protocol (HTTPS to a real site, a real HTTP/3 server, real WebRTC) and hiding data inside it. Three fingerprints must be right: ClientHello (JA3/JA4), certificate, length and timing patterns.
- "Looks like ordinary browsing to my own domain" is the Trojan/NaiveProxy model; "looks like access to Microsoft/Apple" is REALITY; "looks like HTTP/3" is Hysteria2/TUIC; "via CDN" is WebSocket/gRPC/XHTTP through Cloudflare.
- Cloudflare proxies only HTTP-shaped traffic (HTTPS, WebSocket, gRPC, HTTP/3), not raw TCP/UDP (that is the paid Spectrum product). The TCP leg is WebSocket inside HTTPS; the UDP leg is HTTP/3 to Cloudflare's anycast edge with XHTTP-style request splitting; the origin leg is best done with Cloudflare Tunnel so the server needs no inbound port and its IP stays hidden. Because the CDN terminates TLS, the end-to-end Noise-style session layer inside the transport is mandatory, which is why ADR-0005 makes it unconditional.
- Client-side DPI evasion for ISP-level blocking (ECH, ClientHello splitting, SNI omission, fake-TTL tricks, domain fronting) and their limits are in ADR-0006. ECH was first described as the proper fix for SNI-based blocking as practised in Indonesia (and a red flag in China/Russia); after the Schannel decision (section 11) ECH is sidecar-only.
- Licensing matters for "borrowing" from the Chinese ecosystem: Hysteria MIT, Xray-core MPL-2.0, sing-box (and therefore AnyTLS) GPLv3; GPL code cannot be merged into the Apache-2.0 fork, only run as a separate process.
- The assistant first argued that stealth requirements rule out Schannel (no ClientHello control, no ECH) and recommended OpenSSL 3.5; Hilmi later decided the opposite for tiers 1 and 2 (section 11): Schannel's fingerprint *is* the camouflage.

Corrections recorded on 2026-10-11, from an external analysis Hilmi pasted (right about the three-path transport design and the TCP-only origin leg, wrong about the JA3 direction):

- JA3/JA4 is the **client's** ClientHello fingerprint, observed by the censor on the client's network. Sending traffic through Cloudflare does not change the client's JA3; only the server side (anycast IP, certificate, JA3S) becomes Cloudflare's.
- Through the Cloudflare reverse proxy there is no end-to-end QUIC: the client-to-edge leg may be HTTP/3 only in HTTP-request form (XHTTP pattern); WebSocket at Cloudflare is HTTP/1.1 or HTTP/2 over TCP; edge-to-origin is TCP; raw UDP needs Spectrum (Enterprise).
- Cloudflare's "primarily HTML" terms clause was removed in 2023; heavy non-web traffic risks throttling or termination, it is not an automatic violation; Cloudflare Tunnel on the origin side is intended use.

Sources consulted for the circumvention landscape (web search on 2026-10-11; vendor blogs and secondary summaries, not measurement studies):

- [valebyte: REALITY vs Shadowsocks 2022 vs Hysteria2, which protocol to choose in 2026](https://valebyte.com/en/blog/reality-vs-shadowsocks-2022-vs-hysteria2-which-protocol-to-choose-in-2026/)
- [Lantern corpus: REALITY](https://corpus.lantern.io/defenses/reality/)
- [Lantern corpus: AnyTLS](https://corpus.lantern.io/defenses/anytls/)
- [Lantern corpus: AnyTLS padding scheme design](https://corpus.lantern.io/findings/2026-anon-anytls-anytls-sing-box-2026__anytls-tls-padding-scheme-design/)
- [sing-box documentation: AnyTLS inbound](https://sing-box.sagernet.org/configuration/inbound/anytls)
- [sing-box internals: AnyTLS](https://singbox-internals.hidandelion.com/protocols/anytls.html)
- [Surge manual: AnyTLS](https://manual.nssurge.com/policies/anytls.html)
- [lilting.ch: notes on networking from China](https://lilting.ch/en/tags/China)

Takeaways from those sources as quoted in the discussion: REALITY and Hysteria2 are the most-cited protocols still working from inside China in 2026; AnyTLS is rated not production-ready and mostly sing-box-only; Hysteria2's weaknesses are UDP blocking/throttling and its Brutal congestion control; nothing found measures block rates, so all of it is anecdotal.

## 8. Server that is also a client

Hilmi's own framing of the end state: "I am purely building a server that can also be a client". In SoftEther terms that already exists as cascade (`Link.c`). The consequence for the slim fork (remove `vpnclient`, keep cascade, ADR-0012) was first Proposed, briefly reported as withdrawn, and then confirmed by Hilmi: it is ticket #23 and amends the spec in issue #1. The consequence for the new product (one binary with roles and both data-path backends, ADR-0011) is Accepted as part of the dual-mode decision.

## 9. Open items at the time of writing

- Hilmi's confirmation of: the transport stack (ADR-0005), the extended safe-cleanup list (ADR-0003 items 5 to 13), the L2 client adapter (Neo6 versus tap-windows6, ADR-0009). The TLS stack is settled (ADR-0007, section 11).
- The language of the new core.
- The control plane design (own coordination service, MAC-to-node learning and group subscription for L2, BGP/EVPN at the edge) has no ADR yet.
- A size estimate for the dual-mode product.
- Whether a test harness (`vpntest` in-process server + client + golden outputs) is built before any behaviour-changing refactor is attempted; ADR-0002 makes it a precondition.

## 10. Correction after the first draft: L2 is first-class, dual-mode networks

After the ADRs above were first drafted, Hilmi overruled the L3-only recommendation: "yang gw suka itu L2-nya" (what he likes about SoftEther is the L2), and LAN gaming plus other broadcast and non-IP uses must keep working. The resulting decision (ADR-0014, Accepted):

- Each virtual network is either **L2 switched** or **L3 routed**; the type is chosen per network.
- L2 networks are ZeroTier-style virtual Ethernet: the control plane learns and distributes the MAC-to-node mapping; broadcast and multicast are delivered by group subscription rather than flooding every session as SoftEther's Virtual Hub does; the client adapter is a TAP device (Neo6 or tap-windows6, still open); bridging to a physical LAN uses SeLow (Accepted) or the Windows Network Bridge.
- L3 networks keep Wintun (Accepted) and the fastest data path; routing, firewall and BGP at the edge (ADR-0010) sit on top of both kinds of segment.
- One node binary carries both backends (ADR-0011, Accepted).
- Consequences for earlier ADRs: ADR-0004 is Superseded; ADR-0009 drops the "no SoftEther-signed drivers at all" line; ADR-0013 is Accepted for the new product as well; ADR-0005's session layer carries Ethernet frames or IP packets depending on the network type.
- The slim fork's L2 code (Virtual Hub switching, Local Bridge, cascade) is therefore a reference for the L2 backend, not disposable compatibility code; its specific sins (flooding, DHCP relay hacks, SecureNAT) are what the new backend must avoid.

## 11. Second correction: Schannel instead of OpenSSL in the new core

On 2026-10-11 Hilmi decided ("y catat") that the new core uses **Schannel** for the TLS/TCP 443 path and **msquic with the Schannel backend** for QUIC in censorship tiers 1 and 2, and that OpenSSL is dropped from the new core (ADR-0007, now Accepted; the slim fork keeps OpenSSL, liboqs and oqs-provider as before).

The reasoning that changed the earlier recommendation: the ClientHello of Schannel is identical to that of WinHTTP, Office, the Microsoft Store, Windows telemetry and thousands of other Windows applications, and msquic with Schannel is the QUIC stack behind Windows' own HTTP/3 and SMB over QUIC. The engine therefore blends in without any fingerprint engineering, and ships with zero third-party crypto. The earlier argument for OpenSSL (ECH and ClientHello control) only matters for tier 3, which is the sidecar's job anyway.

Consequences: minimum OS for the new core is Windows 11 / Server 2022 (QUIC in Schannel); no ECH in the core (accepted, since Indonesian SNI blocking is domain-list based and the product's domain is not listed); REALITY, ECH and uTLS-style tricks stay in the tier-3 sidecar; the crypto rows of ADR-0008 resolve to CNG; post-quantum hybrid key exchange is used where the OS provides it rather than through liboqs.
