# ADR-0025: VRF, 4via6 and NAT in the node's data plane

**Status:** Accepted (2026-10-20, from the SDN spec #176 that Hilmi filed; recorded by SDN-1, #177). Builds on ADR-0014 (L2 and L3 networks), ADR-0019 (policy engine) and ADR-0022 (per-core run-to-completion, read-mostly tables). Egress replaces the WinNAT rows of ADR-0008, ADR-0010, ADR-0013, ADR-0014 and ADR-0022 (amendments of 2026-10-20).

## Context

The new core (#45) gives Ranz networks, a VLAN-aware switch and a policy engine, but nothing splits the overlay into routing domains. Overlapping private ranges cannot coexist, although in practice every branch office sits on the same `192.168.1.0/24` that its ISP router hands out. A network engineer expects VRFs, 1:1 NAT for overlap, route leaking between domains and an internet exit per domain.

Windows gives none of this to applications (research of 2026-10-20, #176):

- **Routing compartments** exist in the kernel, but their create and assign APIs are documented as "Reserved for future use. Do not use", and Wintun cannot be placed in a compartment.
- **WinNAT** supports one NAT network per host (with more, it reports "unknown state"), no overlapping prefixes, needs Hyper-V, and its static mappings are TCP and UDP port forwards only.
- **RRAS NAT** still ships in Server 2025 and supports several private interfaces and 1:1 address mapping, on Server only.
- Other products: Tailscale and NetBird terminate egress flows in user space on Windows; ZeroTier and Netmaker have no Windows egress; OpenVPN uses RRAS NAT on Windows Server.

What Linux gets from the kernel (VRF, nftables NAT) therefore has to be built into the node.

## Decision

### VRF

1. **VRF is a first-class object.** It has a 32-bit id, a name, a random ULA /48 (RFC 4193), an MTU, a conntrack quota and timeouts, a topology (full mesh, or hub-and-spoke with a hub node) and route-target import and export lists. Routes, policy, DNS and addresses are always scoped to one VRF. Every Network (ADR-0014) belongs to exactly one VRF.
2. **One forwarding table per VRF in user space.** Each table is an immutable LPM table: DIR-24-8 for IPv4 and a trie for IPv6, in the style of DPDK's `rte_lpm`. For each Generation (ADR-0027) the node builds the new table beside the live one and swaps it in atomically, so forwarding never sees a half-built table. Readers take no lock; they rely on acquire and release semantics, which is why the build keeps `/volatile:ms`.
3. **One Wintun adapter per VRF that a host joins**, with a fixed requested GUID, never closed on a tunnel restart, so Windows network profiles, firewall rules and NAT bindings stay attached. Routes go into Windows through IP Helper. Windows routing compartments are not used.

### 4via6

4. **One /64 inside each VRF's ULA /48 is reserved for 4via6.** The original IPv4 address fills the last 32 bits (a /96 mapping). A host that joins two VRFs with overlapping IPv4 reaches the overlapping addresses through 4via6 by default, so `10.0.0.5` in VRF A and `10.0.0.5` in VRF B are two distinct IPv6 addresses on that host.

### NAT

5. **1:1 NAT is mandatory functionality**, a first-class rule in every VRF. **SNAT per VRF** is done in the node's data plane. Neither uses Windows NAT, so overlap and egress do not depend on its limits.
6. **Ranz never touches an existing Windows NAT network** (NetNat) on the host, so Hyper-V, container and lab setups keep working.

### Route leaking, Endpoints and topology

7. **VRFs are isolated by default.** Route leaking uses route-target import and export per VRF, as in MPLS L3VPN and EVPN. A shared-services VRF (DNS, AD, monitoring) can be imported by many VRFs without merging them.
8. **A leaked overlapping prefix requires 1:1 NAT**, so a leak never creates an ambiguous route. Policy applies to leaked traffic (ADR-0029): a leak is reachability, not a firewall bypass.
9. **A "connect VRF A and B" shortcut** in the UI and CLI makes a two-way leak one action instead of two route-target edits. Peering, transit gateways and global WAN constructs are not separate objects: route-target leaking, hub-and-spoke and gateway BGP (ADR-0032) cover them.
10. **An Endpoint publishes one IP address and port of a source VRF into a consumer VRF**, so a vendor or another department reaches only that service, even with overlapping ranges.
11. **Full mesh is the default topology; hub-and-spoke is an option per VRF.** The hub can force traffic through an inspection appliance (ADR-0029) or stop sites from talking directly.
12. **Gateway HA:** two or more gateways announce the same prefix; each node picks a healthy gateway from the controller's health data plus its own probes; ECMP across healthy gateways is optional.

### Egress tiers

13. A node that is an internet exit for a VRF uses the first Egress tier its host supports:
    1. **Windows Server: RRAS NAT**, configured by the node through the MprConfig API (`IP_NAT_INTERFACE_INFO`), with the Wintun adapter as the private interface. The node reconciles the RRAS configuration against desired state, so a reset by a Windows update heals.
    2. **Hyper-V present and no existing NetNat: WinNAT** over one supernet that holds every remapped VRF prefix. An existing NetNat is never touched; the node then uses tier 3.
    3. **Every other host: a proxy.** It rewrites the destination to a local listener on the Wintun address, lets the Windows TCP/IP stack terminate the flow and re-dials with ordinary sockets (TCP, UDP, ICMP echo). It is not a TCP/IP stack of its own, so ADR-0014 holds.
14. **A packet-driver module (WinDivert) is opt-in only**, enabled explicitly by an administrator, for true SNAT on hosts with no kernel NAT. It ships only after it is verified on Windows 11 with Memory Integrity on, with a valid signature, without Defender detection, and with arm64 supported or excluded.
15. **The node reports its Egress tier as a Capability** (ADR-0033).

### MTU, traffic control and multicast

16. **MTU per VRF from the controller, default 1280**, raised per VRF where the underlay allows. TCP MSS is clamped to the VRF MTU, so encapsulation, 4via6 and VXLAN never fragment by surprise.
17. **Token-bucket rate limits per node and per VRF. DSCP is carried through the tunnel unchanged.** Priority queues beyond that are after v1.
18. **Multicast inside a VRF is head-end replicated** to the members that policy allows, rate-limited. IGMP and MLD pruning is used if Windows sends membership reports on Wintun (to verify). Routed multicast (PIM) is after v1.
19. **The per-node target stays 10,000 sessions and 10 Gbit/s** (ADR-0022); the SDN layers must not slow the data path.

## Consequences

- Every SDN feature compiles down to the same three data-plane primitives: per-VRF tables, NAT and stateful policy. A new feature is a new compilation in the controller (ADR-0026), not a new engine in the node.
- The single Windows routing table only sees what a host can route without ambiguity. Overlap is handled by 4via6 on hosts and by EVPN at the edge (ADR-0032).
- The vpntest harness (seam 2 of #45, extended) feeds the data plane with a fake adapter in place of Wintun and checks golden output for per-VRF LPM and the atomic swap, overlapping VRFs, 4via6, 1:1 NAT, SNAT, MTU and MSS clamping, rate limits, DSCP and multicast. The VM CI job covers the real bindings: one Wintun adapter per VRF with a fixed GUID and the three Egress tiers.
- To verify during the work: RRAS NAT behaviour with a Wintun private interface, IGMP and MLD membership reports on Wintun, and the WinDivert gate.
- Tickets: SDN-4 (#180), SDN-5 (#181), SDN-6 (#182), SDN-7 (#183), SDN-12 (#188), SDN-19 (#195), SDN-20 (#196), SDN-22 (#198), SDN-24 (#200).
