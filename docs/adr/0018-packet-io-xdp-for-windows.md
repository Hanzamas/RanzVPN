# ADR-0018: Packet I/O and XDP for Windows

**Status:** Accepted (2026-10-13). Decisions 1, 3, 4 and 5 were Accepted in the first pass (Hilmi: "catat nih"; "mending ini KM TEST loopback"; the backend matrix and "y" to Npcap; "gas QTIP"); **decision 2 was accepted in the 2026-10-13 grilling** (default off, Server x64 only). See the amendment at the end.

## Context

XDP for Windows is a Microsoft open-source project: a kernel driver (`xdp.sys`) plus a header-only user-mode API. Packets from a NIC receive queue (per RSS queue) can be redirected, by an eBPF program, to AF_XDP sockets that bypass the Windows networking stack; AF_XDP sockets can also transmit raw frames. Facts checked on 2026-10-13 from the project's documentation: the latest official release is v1.4.0 (29 July 2026, supported until 29 January 2028); official releases are production-signed (test-signed prereleases need test signing with Secure Boot off); it is installed from the `Microsoft.XDP-for-Windows.Runtime` NuGet package; it is tested on Windows Server 2019 and 2022, x64 only; Microsoft has no plan to ship it as part of Windows. MsQuic already has an XDP datapath on Windows (setting `XdpEnabled`, off by default) and, since v2.6, can use XDP maps so that a privileged process installs the redirect rules and the MsQuic process only needs AF_XDP access.

The new core's transport is QUIC via MsQuic with a TLS/TCP 443 fallback and a Noise session layer (ADR-0005). The question was where, if anywhere, Ranz should use XDP directly instead of only through MsQuic.

## Decision

1. **The TLS/TCP 443 fallback stays on the Windows TCP stack** (Accepted). It is not moved onto XDP: that would require a complete TCP implementation in user mode, a project of its own, for a path that exists for reachability, not for speed.
2. **QUIC traffic gets XDP only through MsQuic** (Accepted 2026-10-13, default off, Server x64 only). Ranz carries its L2 and L3 packets in QUIC datagrams, so the MsQuic XDP datapath accelerates the main data path without Ranz code touching AF_XDP. XDP is an optional acceleration for server nodes on Windows Server x64; every node also runs on the normal datapath (Winsock with IOCP, USO/URO; **RIO is crossed out**, ADR-0008). A custom UDP transport on AF_XDP is not built while the transport is QUIC.
3. **Bridge backends, by attachment type** (Accepted 2026-10-13). The new core's Local Bridge has a backend interface; which backends apply depends on what the hub is attached to:
   - **Physical NIC (bridge to a LAN):** SeLow (default; prebuilt, bundled, works today); Npcap (optional; used only when the administrator installed it, never bundled, so no Npcap OEM licence is needed); XDP + Npcap (XDP carries the frames, Npcap only keeps the NIC in promiscuous mode, which XDP cannot set yet: xdp-for-windows issue #44). When issue #44 is resolved, XDP alone replaces the XDP + Npcap combination.
   - **Virtual (KM-TEST loopback adapter, the L2 adapter of decision 4):** XDP only, through its TX inspect and RX inject hooks; promiscuous mode is not needed there.
   Every XDP backend first passes a spike: foreign-MAC reception and transmission, coexistence with the host stack, and throughput measured against SeLow with the harness benchmark.
4. **L2 adapter = Microsoft KM-TEST Loopback Adapter** (Accepted 2026-10-13, Hilmi: "mending ini KM TEST loopback", "coret aja driver L2 sendiri"). Every L2 attachment that needs a virtual Ethernet card in Windows uses the inbox loopback adapter; Hilmi already runs SoftEther Local Bridge on a loopback adapter in production. In the new core Ranz attaches to it with XDP only (decision 3). A Ranz-built L2 driver is **crossed out**. In the current SoftEther-based code the loopback adapter keeps working through SeLow until the new core replaces it.

5. **QTIP for server-to-server links** (Accepted 2026-10-13, Hilmi: "gas QTIP"). MsQuic's QTIP sends QUIC packets with a TCP header instead of a UDP header over XDP; after the initial handshake it does not follow the TCP protocol. Ranz offers it as an opt-in mode, off by default, for links where both ends are Ranz server nodes running XDP (relay-to-relay, gateway-to-relay, cascades between servers), for networks and clouds that treat TCP better than UDP. It is not a replacement for the TLS/TCP 443 fallback of decision 1: stateful firewalls and DPI that check TCP behaviour may break it, and clients without XDP cannot use it. A QTIP-enabled listener reserves both the TCP and the UDP port of its address, and MsQuic does not allow a QTIP and a non-QTIP listener on the same port, so QTIP listeners get their own port.

Fact corrections (2026-10-13, from the repository's CI and releases): XDP for Windows is tested in CI on Windows Server 2022 and 2025 (x64, and arm64 on 2025) and a Windows prerelease image; Windows 10/11 client editions are not in its CI; the official v1.4.0 runtime package on NuGet is x64 only; its threat model lists Windows Firewall, WFP, TCP/UDP/ICMP/IP/ARP among the bypassed components for redirected packets (frames injected on the receive path still traverse the stack). The loopback design therefore needs a spike on Windows 10/11 x64 before it ships, and arm64 nodes have no L2 virtual adapter until an official arm64 runtime is published.

## Consequences

- No user-mode TCP stack is ever on the roadmap; the fallback's throughput is whatever the Windows TCP stack and Schannel deliver.
- Server deployments that want maximum throughput install the XDP runtime and enable it. Nodes that use an L2 network need the XDP runtime for the loopback adapter (decision 4); the transport never depends on it.
- Packets redirected to AF_XDP sockets are not seen by Windows Firewall/WFP; any XDP backend must apply its own filtering, and the documentation must say so.
- If the Local Bridge spike succeeds, Ranz stops depending on a frozen, third-party-signed driver binary (SeLow ships prebuilt and cannot be rebuilt or extended, e.g. to arm64, without a driver-signing pipeline of our own) on the server platforms XDP supports.

## Amendment 2026-10-13: decision 2 accepted, RIO crossed out, rule API now / eBPF later, signature re-check

The 2026-10-13 grilling (new-core round; `spike-xdp-result.md`, `spike-xdp-ebpf-result.md`, `facts-xdp.md`) settled the open points:

- **Decision 2 is Accepted:** QUIC acceleration through the MsQuic XDP datapath, **default off, Server x64 only** — one flag, no Ranz AF_XDP code.
- **RIO is crossed out** (ADR-0008): the normal datapath is Winsock with IOCP plus USO/URO. Decision 2's text above is corrected.
- **Ship on the XDP 1.4 rule API now; eBPF later.** The rule API (`XdpCreateProgram`) is the only XDP path that captures the frames the OS sends, and it is supported until 2028-01-29. The **eBPF path is rejected for now**: the `spike/xdp-ebpf` result is conclusive that eBPF for Windows has no TX-inspect hook (every program attaches to `{L2, RX, INSPECT}`, and KM-TEST does not loop TX back to RX), and there is **no production-signed eBPF for Windows runtime** (it needs test signing and Secure Boot off). Finish the eBPF spike in parallel and switch only when eBPF-for-Windows installs cleanly and is production-signed; re-run the spike on every XDP release.
- **Re-verify the `xdp.sys` signature before decision 4 is final.** The spike ran on hosted runners with test signing on; re-run it on a Server 2022 VM with **Secure Boot on and test signing off** to confirm the nuget.org `xdp.sys` is production-signed (not attestation-signed, which Server refuses) before the loopback design is treated as proven. `signtool verify /kp` already passes on the nuget.org 1.4.0 `xdp.sys`.
- **Install path:** a separate `Install-RanzXdp.ps1` (wrapping `xdp-setup.ps1`); the MSI does not bundle XDP for v1 (ADR-0022).
- **QTIP (decision 5) lands at strangler step 7** (ADR-0022), default port **8443** (both TCP and UDP reserved, configurable), proven with a two-VM spike. *(Superseded by the ADR-0002 amendment of 2026-10-21: two node processes on one CI runner.)*
- **KM-TEST details (decision 4):** per-adapter locally administered MAC from the node id and network id; forward ARP/IGMP/LLMNR/NetBIOS chatter and rate-limit broadcast per VLAN; add broadcast, multicast and 802.1Q-tagged injection to the spike.
