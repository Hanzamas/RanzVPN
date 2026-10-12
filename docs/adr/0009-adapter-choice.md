# ADR-0009: Adapter choice: Wintun for L3 networks (Accepted), a TAP driver for L2 networks (Neo6 versus tap-windows6 still Proposed), SeLow for bridging (Accepted)

**Status:** Mixed, updated 2026-10-11 after ADR-0014. Wintun for L3 networks: Accepted. SeLow for Local Bridge / L2 bridging: Accepted (ADR-0013). The L2 client adapter, Neo6 or tap-windows6: Proposed, not yet chosen. The earlier reading "no SoftEther-signed drivers at all" is withdrawn: SeLow is SoftEther-signed and stays, and Neo6 remains a candidate.

## Context

SoftEther ships its own kernel drivers: Neo6 (NDIS 6 TAP adapter for the client, L2, batched IOCTL ring buffer) and SeLow (NDIS lightweight filter for Local Bridge capture/injection on the server). Both are signed by SoftEther Corporation; the fork cannot modify them without its own EV certificate and WHQL attestation, and accepts that they keep their SoftEther display names.

With dual-mode networks (ADR-0014) the product needs two adapter families: an L3 TUN adapter for routed networks and an L2 TAP adapter for switched networks, plus a way to bridge an L2 segment to a physical NIC. The question was which options exist on Windows for a user-space VPN with no kernel code of our own.

## Decision

| Option | Layer | Signed by | Verdict |
|---|---|---|---|
| **Wintun** | L3 | WireGuard LLC (WHQL) | **adapter for L3 routed networks** (Accepted); shared-memory ring buffers, batched, about 2 to 4 Gbps single flow in user space |
| **Neo6** | L2 | SoftEther | candidate for L2 switched networks (Proposed); batched IOCTL ring, about 1 to 2 Gbps; already driven by `VLanWin32.c` (1.4k lines) in the slim fork; not ours to modify or re-sign |
| **tap-windows6** | L2 | OpenVPN Inc | candidate for L2 switched networks (Proposed); per-packet overlapped `ReadFile`, about 0.5 Gbps; widely deployed, independent of SoftEther |
| **SeLow** | L2 filter | SoftEther | **bridging an L2 segment to a physical NIC** (Accepted, ADR-0013); Windows Network Bridge is the OS alternative when a TAP adapter is used instead |
| XDP-for-Windows | raw NIC | Microsoft | optional accelerator via msquic's XDP datapath for extreme packets-per-second on servers; one flag, not code |
| Windows Network Bridge / Hyper-V vSwitch | L2 kernel | Microsoft (OS) | alternative bridging path for TAP adapters |
| Windows VPN Platform (`VpnPlugIn`) | L3 | OS | no: UWP only, per-user, low throughput, client only |
| RAS/RRAS built-in tunnels (IKEv2, SSTP, L2TP) | L3 | OS | no: Microsoft's protocols, not ours |
| Npcap | raw L2 | Nmap | no: separate install and licensing |
| own WFP callout or NDIS filter driver | kernel | us | no: kernel code is out of scope |

Neo6 versus tap-windows6: Neo6 wins on throughput and is already integrated; tap-windows6 wins on ownership and ubiquity. Re-signing Neo6 ourselves (EV certificate plus WHQL attestation) was mentioned as possible but costly. The choice is open.

## Consequences

- No kernel code of our own; every kernel component is Microsoft's, OpenVPN's, WireGuard's or SoftEther's signed binary.
- The slim fork keeps the Neo6 packages and `VLanWin32.c` only while something in the fork uses them; with `vpnclient` removed (ADR-0012) they leave the fork, and the L2 backend of the new product takes Neo6 back from upstream or uses tap-windows6, depending on the open choice.
- SeLow, `SeLowUser.c`, `BridgeWin32.c` and the `SeLow_Win10` packages stay in the fork and are the reference for bridging in the new product.
