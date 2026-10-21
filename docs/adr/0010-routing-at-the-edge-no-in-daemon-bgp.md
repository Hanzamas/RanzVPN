# ADR-0010: Routing is the OS's job; overlay routes from the control plane, BGP at the edge via a GoBGP sidecar, no OSPF

**Status:** Accepted (2026-10-13; amended 2026-10-20: EVPN type-5 through `ranz-bgp`, VXLAN in the node, SDN spec #176; amended 2026-10-21: per-VRF forwarding inside the overlay, Windows IP forwarding only at a gateway's LAN edge, the `Gateway` resource is the approval). Hilmi accepted Windows IP forwarding in place of the Layer 3 switch ("accepted"), chose the GoBGP sidecar and control-plane overlay routes, wants both overlay routing and peering with customer routers, agreed that OSPF is not implemented, and asked to record it ("catat"). Originally Proposed as the assistant's answer to "static routing ganti ke BGP".

## Context

SoftEther offered an L3 switch (`Layer3.c`, static routes between hubs); it is removed by the scope cuts (spec #26, PR #25). Hilmi asked for routing between hubs and VLANs, dynamic routing, and his own OSPF/BGP, under the rule "jangan reinvent the wheel". Writing BGP or OSPF inside the daemon would be roughly ten to fifteen thousand lines each of network-facing parsers, months of work and interoperability testing; OSPF has no maintained implementation on Windows (Microsoft removed it from RRAS, BIRD and FRRouting are Linux/BSD only).

OSPF and BGP do different jobs: OSPF routes inside one organisation's network (every router knows the full topology); BGP routes between networks with explicit peers and rich filtering. Ranz's overlay is "another network" from a customer router's point of view, which is BGP's job; cloud VPN gateways (AWS, Azure, GCP) peer with customer routers over BGP for the same reason.

## Decision

1. **Routing between networks and VLANs is done by the Windows IP stack** on a gateway node. Each routed network (the successor of a Virtual Hub) or VLAN gets one Microsoft KM-TEST loopback adapter attached as an access port (ADR-0018, ADR-0019) and carries the gateway address of its subnet; IP forwarding is enabled on those adapters and the kernel routes between them. WinNAT (`New-NetNat`) provides NAT to the internet where needed. *(Replaced by the three egress tiers, amendment of 2026-10-20 below.)* Filtering between networks uses the Ranz policy engine at the gateway's ports (ADR-0019) and WFP rules at the forwarding layer. In the current SoftEther-based code the same setup works manually today: a Local Bridge from each hub to its own loopback adapter, plus `Set-NetIPInterface -Forwarding Enabled` or RRAS LAN routing. *(Amended 2026-10-21 below: inside the overlay, forwarding uses the node's per-VRF tables; Windows IP forwarding is used only at a gateway's LAN edge.)*
2. **Overlay routing is automatic, from the control plane** (ADR-0011): gateways advertise the subnets behind them; an administrator approves advertised subnets *(amended 2026-10-21 below: declaring the LAN prefixes in the `Gateway` resource is the approval)*; the control plane distributes routes to every node, health-checks gateways, fails over, and spreads load over several gateways (ECMP). Static routes exist only as administrator overrides distributed by the same mechanism. The daemon installs routes into Windows through IP Helper. No routing protocol runs between Ranz nodes.
3. **Edge routing with customer routers uses BGP through a GoBGP sidecar** (Apache-2.0, a separate process controlled by the daemon; see the 2026-10-13 amendment for the transport, which is a local named pipe with JSON, not gRPC). It announces overlay subnets to the customer's routers and learns theirs, with filters on both sides. GoBGP's route installation is Linux-only, so the daemon installs learned routes into Windows through IP Helper. RRAS BGP is not used.
4. **OSPF is not implemented.** Customers who run OSPF internally redistribute the BGP-learned Ranz routes into OSPF on their own routers (MikroTik, Cisco, Juniper and pfSense/FRR all can). Routers that speak neither protocol use static routes.
5. **Router-on-a-stick stays possible**: a VLAN trunk over Local Bridge to a physical NIC lets a customer's router route between Ranz networks.
6. L2 switched networks (ADR-0014) are subnets like any other from the router's point of view. EVPN remains the matching model if L2 segments are ever stretched between sites with BGP-speaking routers; noted, not decided. *(EVPN type-5 for IP prefixes per VRF is decided in the amendment of 2026-10-20 below; L2 stretch stays after v1.)*

## Consequences

- `Layer3.c` is gone (PR #25) and is not carried into the new core; kernel IP forwarding replaces it and is faster than routing in user mode. *(Inside the overlay, the node's per-VRF tables replace it; amendment of 2026-10-21 below.)*
- The number of loopback adapters on a gateway grows with the number of routed networks and VLANs; the bridge path to those adapters (SeLow today, XDP later) is the throughput limit, not the routing. *(Superseded for the overlay by the amendment of 2026-10-21 below.)*
- The control plane needs route advertisement, approval, health checks and ECMP; its design still needs its own ADR. *(Covered since 2026-10-20 by ADR-0025 to ADR-0027, except the approval step for advertised subnets, which #176 does not mention; since 2026-10-21 the `Gateway` resource is the approval, amendment below.)*
- The GoBGP sidecar adds a Go binary to gateway installations that peer with routers; nodes that do not peer never run it.

## Amendment 2026-10-13: GoBGP sidecar shape, RRAS BGP ruled out

The 2026-10-13 grilling fixed the sidecar and reaffirmed the routing decision (full detail in ADR-0022):

- **RRAS BGP is ruled out**, here and in ADR-0014 (which previously read "RRAS or GoBGP"). The GoBGP sidecar is the only edge-BGP path.
- The sidecar is a small Go program, **`ranz-bgp`, that embeds GoBGP as a library**. The C core talks to it over a **local named pipe with a few JSON messages** (announce, withdraw, learned routes) — **not gRPC**, correcting decision 3's "over its gRPC API". The core installs learned routes into Windows through IP Helper.
- Packaging: an **optional MSI feature**, built in CI (Go cross-compiled for x64 and arm64), spiked on Windows (BGP on TCP 179, no FIB) when L3 networks land at **strangler step 7** (ADR-0022).
- Overlay routing between Ranz nodes still uses the control plane (decision 2), not BGP; the `controller` role and its nanopb control stream are specified in ADR-0022. *(Since the amendment of 2026-10-20 below, the control plane is the separate `ranz-controller` service, ADR-0026.)*

## Amendment 2026-10-20: EVPN type-5 through `ranz-bgp`, VXLAN in the node

Maintainer decision, from the SDN spec #176 that Hilmi filed ("EVPN type-5 through `ranz-bgp`, VXLAN in the node"). The full edge design is ADR-0032; the VRFs it hands off are ADR-0025.

- **`ranz-bgp` gains EVPN type-5** (IP prefix routes per VRF). GoBGP stays a library inside it, and its named-pipe JSON contract with the node is extended for EVPN routes per VRF. RRAS BGP stays ruled out, and OSPF stays out (decision 4).
- **The gateway node does VXLAN encapsulation and decapsulation in user space**, because Windows has no VXLAN interface for applications. The same module carries Mirrors to a sensor (ADR-0029).
- **Overlap-safe handoff is EVPN only.** Overlapping prefixes never reach the single Windows routing table. VRF-lite (one VLAN per VRF) carries non-overlapping prefixes only: on Windows Server through LBFO team interfaces, on client SKUs one VRF per physical NIC.
- **Decision 6 is settled for L3:** EVPN is decided for IP prefixes per VRF (type-5). EVPN type-2 and L2 stretch over EVPN are after v1.
- **Decision 2 is now the controller's job:** route advertisement of LAN subnets behind gateways, health checks, gateway HA and optional ECMP are compiled by `ranz-controller` (ADR-0026) and delivered by Generation (ADR-0027). #176 does not mention the approval step for advertised subnets; LAN prefixes are part of the `Gateway` resource in the intent (ADR-0031). *(The approval is settled by the amendment of 2026-10-21 below.)*
- **Decision 1:** forwarding inside a VRF uses the node's per-VRF tables (ADR-0025). Its WinNAT sentence is replaced by the three egress tiers of the ADR-0008 amendment of 2026-10-20.

## Amendment 2026-10-21: per-VRF forwarding inside the overlay, the `Gateway` resource is the approval

Maintainer decisions (Hilmi: "ya ya ya semua").
- **Decision 1: inside the overlay, forwarding uses the node's per-VRF tables** (ADR-0025). Windows IP forwarding is used only at a gateway's LAN edge, through the VRF's adapter. Routing between the overlay's networks and VLANs no longer runs through loopback adapters and the Windows IP stack.
- **Decision 2: declaring LAN prefixes in the `Gateway` resource is the approval** (ADR-0031). Intent always goes through revisions, `ranz diff` and `ranz apply --confirm`, so a prefix is reviewed before it applies and can be rolled back. There is no separate approval step for advertised subnets.
