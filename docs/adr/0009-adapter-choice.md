# ADR-0009: Adapter choice: Wintun for L3 networks (Accepted), a TAP driver for L2 networks (Neo6 versus tap-windows6 still Proposed), SeLow for bridging (Accepted)

**Status:** Mixed, updated 2026-10-11 after ADR-0014. Wintun for L3 networks: Accepted. SeLow for Local Bridge / L2 bridging: Accepted (ADR-0013). The L2 client adapter, Neo6 or tap-windows6: Proposed, not yet chosen. The earlier reading "no SoftEther-signed drivers at all" is withdrawn: SeLow stays (its shipped binary is Microsoft-WHQL-signed, not SoftEther-signed; corrected in the 2026-10-13 amendment), and Neo6 remains a candidate.

## Context

SoftEther ships its own kernel drivers: Neo6 (NDIS 6 TAP adapter for the client, L2, batched IOCTL ring buffer) and SeLow (an NDIS **protocol** driver, Class `NetTrans`, for Local Bridge capture/injection on the server). Neo6 is signed by SoftEther Corporation; the SeLow package shipped in this repo is **Microsoft-WHQL-signed** (corrected in the 2026-10-13 amendment). The fork cannot modify either without breaking its signature, and accepts that they keep their SoftEther display names.

With dual-mode networks (ADR-0014) the product needs two adapter families: an L3 TUN adapter for routed networks and an L2 TAP adapter for switched networks, plus a way to bridge an L2 segment to a physical NIC. The question was which options exist on Windows for a user-space VPN with no kernel code of our own.

## Decision

| Option | Layer | Signed by | Verdict |
|---|---|---|---|
| **Wintun** | L3 | WireGuard LLC (WHQL) | **adapter for L3 routed networks** (Accepted); shared-memory ring buffers, batched, about 2 to 4 Gbps single flow in user space |
| **Neo6** | L2 | SoftEther | candidate for L2 switched networks (Proposed); batched IOCTL ring, about 1 to 2 Gbps; already driven by `VLanWin32.c` (1.4k lines) in the slim fork; not ours to modify or re-sign |
| **tap-windows6** | L2 | OpenVPN Inc | candidate for L2 switched networks (Proposed); per-packet overlapped `ReadFile`, about 0.5 Gbps; widely deployed, independent of SoftEther |
| **SeLow** | L2 protocol (NDIS `NetTrans`) | Microsoft (WHQL, see amendment) | **bridging an L2 segment to a physical NIC** (Accepted, ADR-0013); Windows Network Bridge is the OS alternative when a TAP adapter is used instead |
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

## Amendment 2026-10-13: SeLow driver type and signer corrected

From the 2026-10-13 grilling (`facts-signing.md` section 6, `prep-release.md` Q22), checked by local inspection of `src/bin/hamcore/DriverPackages/SeLow_Win10/x64/`:

- **SeLow is an NDIS *protocol* driver, not a lightweight filter.** Its INF has `Class = NetTrans`, `UpperRange noupper`, `LowerRange "ndis5,ndis4"`, and the code calls `NdisRegisterProtocolDriver` (`src/SeLow/SeLow.c`). Earlier text in this ADR calling it an "NDIS lightweight filter" / "L2 filter" is wrong and corrected above.
- **The shipped SeLow package is Microsoft-WHQL-signed, not SoftEther-signed.** `SeLow_x64.sys` and `SeLow_Win10_x64.cat` are signed by "Microsoft Windows Hardware Compatibility Publisher" (issuer: Microsoft Windows Third Party Component CA 2012; root: Microsoft Root Certificate Authority 2010), with a Microsoft Time-Stamp countersignature, and carry EKU `1.3.6.1.4.1.311.10.3.5` (Windows Hardware Driver Verification) with no `.5.1`, i.e. an HLK/WHQL dashboard signature rather than attestation. Only the pre-fork v4.19-era builds were SoftEther/GlobalSign-signed.
- **Consequence unchanged, reason corrected.** The package still cannot be modified: any byte change to the `.sys` or the `.inf` (including renaming the SoftEther display strings) breaks the catalog hash and voids Microsoft's signature. So the fork ships it byte-for-byte, x64 only, and needs no driver-signing account of its own. The "SoftEther" strings in the INF must stay to keep the signature valid.
- Open items (not decided here): the 2018 build's HVCI/Memory Integrity status is untested, and there is no x86 or arm64 SeLow package.
