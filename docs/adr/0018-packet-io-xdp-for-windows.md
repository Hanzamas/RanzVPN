# ADR-0018: Packet I/O and XDP for Windows

**Status:** Partly accepted (2026-10-13). Decision 1 is Accepted (Hilmi: "catat nih"). Decisions 2 and 3 are Proposed and under discussion.

## Context

XDP for Windows is a Microsoft open-source project: a kernel driver (`xdp.sys`) plus a header-only user-mode API. Packets from a NIC receive queue (per RSS queue) can be redirected, by an eBPF program, to AF_XDP sockets that bypass the Windows networking stack; AF_XDP sockets can also transmit raw frames. Facts checked on 2026-10-13 from the project's documentation: the latest official release is v1.4.0 (29 July 2026, supported until 29 January 2028); official releases are production-signed (test-signed prereleases need test signing with Secure Boot off); it is installed from the `Microsoft.XDP-for-Windows.Runtime` NuGet package; it is tested on Windows Server 2019 and 2022, x64 only; Microsoft has no plan to ship it as part of Windows. MsQuic already has an XDP datapath on Windows (setting `XdpEnabled`, off by default) and, since v2.6, can use XDP maps so that a privileged process installs the redirect rules and the MsQuic process only needs AF_XDP access.

The new core's transport is QUIC via MsQuic with a TLS/TCP 443 fallback and a Noise session layer (ADR-0005). The question was where, if anywhere, Ranz should use XDP directly instead of only through MsQuic.

## Decision

1. **The TLS/TCP 443 fallback stays on the Windows TCP stack** (Accepted). It is not moved onto XDP: that would require a complete TCP implementation in user mode, a project of its own, for a path that exists for reachability, not for speed.
2. **QUIC traffic gets XDP only through MsQuic** (Proposed). Ranz carries its L2 and L3 packets in QUIC datagrams, so the MsQuic XDP datapath accelerates the main data path without Ranz code touching AF_XDP. XDP is an optional acceleration for server nodes on Windows Server 2019/2022 x64; every node also runs on the normal datapath (Winsock, RIO, USO/URO). A custom UDP transport on AF_XDP is not built while the transport is QUIC.
3. **Local Bridge gets a backend interface with two candidates** (Proposed): the prebuilt SeLow driver (current, ADR-0013) and an AF_XDP backend in user mode on top of the Microsoft-signed `xdp.sys`. The AF_XDP backend is adopted only after a spike proves, on a real NIC and on a Hyper-V NIC: receiving frames addressed to foreign MAC addresses (promiscuous reception), transmitting frames with foreign source MAC addresses, coexistence with the host's own traffic (or a documented dedicated-NIC requirement, as with SeLow today), and throughput against SeLow measured with the harness benchmark.

## Consequences

- No user-mode TCP stack is ever on the roadmap; the fallback's throughput is whatever the Windows TCP stack and Schannel deliver.
- Server deployments that want maximum throughput install the XDP runtime and enable it; clients and arm64 nodes never depend on it.
- Packets redirected to AF_XDP sockets are not seen by Windows Firewall/WFP; any XDP backend must apply its own filtering, and the documentation must say so.
- If the Local Bridge spike succeeds, Ranz stops depending on a frozen, third-party-signed driver binary (SeLow ships prebuilt and cannot be rebuilt or extended, e.g. to arm64, without a driver-signing pipeline of our own) on the server platforms XDP supports.
