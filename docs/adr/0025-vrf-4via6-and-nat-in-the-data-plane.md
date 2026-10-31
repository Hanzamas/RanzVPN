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
20. **Not in v1:** an L4 load balancer service.

## Consequences

- Every SDN feature compiles down to the same three data-plane primitives: per-VRF tables, NAT and stateful policy. A new feature is a new compilation in the controller (ADR-0026), not a new engine in the node.
- The single Windows routing table only sees what a host can route without ambiguity. Overlap is handled by 4via6 on hosts and by EVPN at the edge (ADR-0032).
- The vpntest harness (seam 2 of #45, extended) feeds the data plane with a fake adapter in place of Wintun and checks golden output for per-VRF LPM and the atomic swap, overlapping VRFs, 4via6, 1:1 NAT, SNAT, MTU and MSS clamping, rate limits, DSCP and multicast. The VM CI job covers the real bindings: one Wintun adapter per VRF with a fixed GUID and the three Egress tiers.
- To verify during the work: RRAS NAT behaviour with a Wintun private interface, IGMP and MLD membership reports on Wintun, and the WinDivert gate.
- Tickets: SDN-4 (#180), SDN-5 (#181), SDN-6 (#182), SDN-7 (#183), SDN-12 (#188), SDN-19 (#195), SDN-20 (#196), SDN-22 (#198), SDN-24 (#200).

## Amendment 2026-10-23: 4via6 and 1:1 NAT in the node's data plane (SDN-6)

Recorded by SDN-6 (#182), which builds on the forwarding tables of SDN-4 (#180) and the ULA of each VRF (SDN-3, #179). It makes decisions 4 and 5 concrete.

- **A 1:1 NAT rule is a resource.** A `NAT` resource of the Intent is one rule of a VRF, as a `Policy` is one rule of its policy: `vrf`; `node`, the member of the VRF that applies it; `inside`, the prefix as the host of that Node or the LAN behind it sees it; and `outside`, the prefix as the VRF sees it, of the same family and length. The outside prefix overlaps no pool, LAN subnet, 4via6 /64 or other outside prefix of the VRF, and the rules of one Node in one VRF do not overlap. A VRF or a Node that a rule names cannot be deleted. A Node applies at most 16 rules, its 4via6 counted: the control protocol carries 16.
- **4via6 compiles into the same primitive.** A Node in two VRFs whose IPv4 ranges overlap (the IPv4 pools of their Networks, their LAN subnets and the outside prefixes of their rules) gets the 4via6 of each such VRF as a rule from the /96 at the start of `<ula>:ffff::/64` (the 4via6 /64 of ADR-0028) inside to `0.0.0.0/0` outside. The IPv4 address fills the last 32 bits, so `10.0.0.5` of two VRFs is `<ula-a>:ffff::a00:5` and `<ula-b>:ffff::a00:5` on the host. In such a VRF the host reaches the IPv4 of the VRF through IPv6; a VRF that overlaps no other VRF of the Node keeps plain IPv4.
- **The control protocol** carries the rules that a node applies in `NodeConfig.nat`, and the outside prefixes of the rules of one family of a peer as `Peer.routes`. They are new fields, so no schema version changes: a node of an older release skips them.
- **In the node** (`src/Cedar/NodeNat.c`) the rules are built with the forwarding tables of their Generation and swapped in with them. The forwarding tables stay tables of the overlay: a packet of the host is translated, then checked; a packet of a peer is checked, then translated. Inside becomes outside on the way into the overlay and outside becomes inside on the way to the host, for the source, the destination and the addresses of the packet that an ICMP error quotes, with the IPv4 header, TCP, UDP and ICMPv6 checksums. The 4via6 translates the packet between IPv6 and IPv4 as SIIT does (RFC 7915) for TCP, UDP, ICMP Echo and the errors that a host needs (Destination Unreachable, Packet Too Big and Fragmentation Needed with the MTU of the other header, Time Exceeded, an unknown next header); it drops a fragment of IPv4, an IPv6 packet with an extension header and an ICMP message that has no counterpart. On the way into the overlay the 4via6 goes first and the other rules after it, on the way back the other way round, so a 1:1 NAT rule of IPv4 and the 4via6 of one VRF work together.
- **Next:** the overlapping leaks of SDN-7 (#183) compile into these rules; the Wintun adapter of a VRF (SDN-5, #181) carries its 4via6 /96 and the node's 4via6 address in it.

## Amendment 2026-10-24: route leaking with route targets (SDN-7)

Recorded by SDN-7 (#183), which builds on the forwarding tables of SDN-4 (#180) and the 1:1 NAT of SDN-6 (#182). It makes decisions 7 to 9 concrete.

- **A VRF lists the route targets that it imports and exports** (`importTargets` and `exportTargets` of the VRF resource), in the forms of the route target extended community of BGP: `ASN:NUMBER` or `IPV4:NUMBER`. The routes of a VRF leak into every other VRF that imports a route target that it exports. There is no route distinguisher, because every VRF has its own table on a Node.
- **What leaks** are the routes of the exporting VRF that lead to its members: the address of each member in each L3 Network of the VRF, as a host route, and the outside prefix of each 1:1 NAT rule of a member in it. An address that a 1:1 NAT rule of its Node holds as inside leaks only as the outside address of that rule.
- **An overlapping leak is refused (decision 8).** A leaked route that overlaps a prefix of the importing VRF (a pool of its Networks, a LAN subnet advertised in it, the outside prefix of one of its 1:1 NAT rules, or a route that another VRF leaks into it) refuses the apply, with an error that names both and the 1:1 NAT rule that resolves it.
- **The control protocol** carries a leaked route as a route of the Peer that it leads to, with `Route.peer_vrf_id`, the VRF of the peer that a packet on the route goes into. The members of the two VRFs of a leak are peers whether or not they share a VRF, so either can open the Noise session. It is a new field, so no schema version changes.
- **In the node** (`src/Cedar/NodeLeak.c`) each leaked route gets a next hop of its own, which carries that VRF, in the forwarding tables of its Generation, swapped in with them. A packet on it goes to the peer with the id of that VRF, and the peer delivers it in that VRF only when that VRF routes the source back to the sender. So a leak carries traffic only when it goes both ways, and the forwarding table, the 1:1 NAT rules and the policy of the destination VRF decide what passes (decision 8, ADR-0029 decision 6).
- **The shortcut (decision 9)** is `POST /api/v1/connect`, `ranz connect vrf A B` and the form of the VRFs page of the web UI: one revision with the two route-target edits. A VRF that exports none first exports `64512:<id>`, the first AS number for private use (RFC 6996) and its id.
- **Not yet:** the Policy resources reach the nodes with SDN-8 (#184), which compiles them into the engine of CORE-S4-2 (#75) on the same per-VRF path; the relay role forwards only between nodes that share a VRF, so two nodes that only a leak joins reach each other on a direct path; the client role does not put leaked routes into the routing table of Windows yet.

## Amendment 2026-10-30: the Egress tiers (SDN-12)

Recorded by SDN-12 (#188). It makes decisions 13 and 15 concrete.

- **An exit is named by its VRF.** The `egress` of a VRF resource names a member Node, the hub of a VRF of topology hub-and-spoke. The control protocol gives the exit the id of the VRF in `NodeConfig.egress_vrf_ids` and every other member the default route `0.0.0.0/0` of the VRF as a route of the Peer of the exit, one of the 16 routes that lead a Node to one peer; the exit needs an Egress tier among its Capabilities, which every node of this release reports. In the forwarding tables of the exit that default route leads to its host, and a packet of a peer that no other route of the VRF holds is the Egress's (`src/Cedar/NodeEgress.c`).
- **The tier is found on the host** (`src/Cedar/NodeCaps.c`): RRAS NAT on a Windows Server whose Routing and Remote Access runs (its service `RemoteAccess`) as a LAN router (its `RouterType` has LAN routing); WinNAT where Hyper-V (the service `vmms`) and WinNAT (the service `WinNat`) are present and no NAT network of WinNAT of another name exists; the proxy everywhere else. A node never installs RRAS or Hyper-V.
- **Tier 1** (`src/Cedar/NodeEgressNat.c`): the node adds the NAT routing protocol (`MS_IP_NAT`) to the IPv4 router of RRAS where it lacks it, makes the adapter of each VRF whose exit it is a private interface of the NAT and each interface that carries the egress a public one, a boundary with address and port translation (`IP_NAT_INTERFACE_INFO`, MS-RRASM 2.2.1.2.197), through MprConfig for the configuration and MprAdmin for the running router. `mprapi.dll` is loaded at run time, so a node of a client edition never imports it.
- **Tier 2**: the node creates the NAT network of WinNAT `RanzVPN-Egress` (an `MSFT_NetNat` of `ROOT\StandardCimv2`, as `New-NetNat` does) over the longest supernet that holds every IPv4 prefix of the VRFs whose exit it is; a supernet wider than a /8 takes the proxy. Decision 6 holds: a NAT network of another name is never touched, and one that appears while the node runs makes it fall back to the proxy.
- **Reconcile and fall back.** The Egress reconciles the NAT of Windows every 5 s and sets again what something else removed or changed (an operator, a reset of RRAS by a Windows update), and undoes what it configured once the node is the exit of no VRF, or stops. Until the NAT holds what the VRFs want, the Egress drops their traffic, which would leave the host untranslated. It falls back to the proxy for the rest of the run when the NAT cannot serve the VRFs (a VRF that overlaps another VRF of the node, whose host sees it through 4via6), when a NAT network of WinNAT of another program exists, and after three reconciles in a row that fail.
- **The strong host model.** Every interface of the host but the loopback that holds an IPv4 default route has Forwarding, WeakHostSend and WeakHostReceive on while the node is an exit, and gets back what it had after, so a reply that comes back on another interface than its request left by reaches the peer (maintainer decision of 2026-10-24).
- **Tests.** `vpntest egress` runs the proxy on every runner, `vpntest egressnat` the tier that the runner gives (WinNAT on the x64 and arm64 runners, which have Hyper-V, with the supernet of two VRFs) and the fallback beside a NAT network of another program, and `vpntest egressrras` RRAS NAT in the `egress (RRAS NAT)` job of `windows.yml`, which installs RRAS as a LAN router on Windows Server 2025 first.
