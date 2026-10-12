# ADR-0010: Routing is the OS's job; overlay routes from the control plane, BGP at the edge via a GoBGP sidecar, no OSPF

**Status:** Accepted (2026-10-13). Hilmi accepted Windows IP forwarding in place of the Layer 3 switch ("accepted"), chose the GoBGP sidecar and control-plane overlay routes, wants both overlay routing and peering with customer routers, agreed that OSPF is not implemented, and asked to record it ("catat"). Originally Proposed as the assistant's answer to "static routing ganti ke BGP".

## Context

SoftEther offered an L3 switch (`Layer3.c`, static routes between hubs); it is removed by the scope cuts (spec #26, PR #25). Hilmi asked for routing between hubs and VLANs, dynamic routing, and his own OSPF/BGP, under the rule "jangan reinvent the wheel". Writing BGP or OSPF inside the daemon would be roughly ten to fifteen thousand lines each of network-facing parsers, months of work and interoperability testing; OSPF has no maintained implementation on Windows (Microsoft removed it from RRAS, BIRD and FRRouting are Linux/BSD only).

OSPF and BGP do different jobs: OSPF routes inside one organisation's network (every router knows the full topology); BGP routes between networks with explicit peers and rich filtering. Ranz's overlay is "another network" from a customer router's point of view, which is BGP's job; cloud VPN gateways (AWS, Azure, GCP) peer with customer routers over BGP for the same reason.

## Decision

1. **Routing between networks and VLANs is done by the Windows IP stack** on a gateway node. Each routed network (the successor of a Virtual Hub) or VLAN gets one Microsoft KM-TEST loopback adapter attached as an access port (ADR-0018, ADR-0019) and carries the gateway address of its subnet; IP forwarding is enabled on those adapters and the kernel routes between them. WinNAT (`New-NetNat`) provides NAT to the internet where needed. Filtering between networks uses the Ranz policy engine at the gateway's ports (ADR-0019) and WFP rules at the forwarding layer. In the current SoftEther-based code the same setup works manually today: a Local Bridge from each hub to its own loopback adapter, plus `Set-NetIPInterface -Forwarding Enabled` or RRAS LAN routing.
2. **Overlay routing is automatic, from the control plane** (ADR-0011): gateways advertise the subnets behind them; an administrator approves advertised subnets; the control plane distributes routes to every node, health-checks gateways, fails over, and spreads load over several gateways (ECMP). Static routes exist only as administrator overrides distributed by the same mechanism. The daemon installs routes into Windows through IP Helper. No routing protocol runs between Ranz nodes.
3. **Edge routing with customer routers uses BGP through a GoBGP sidecar** (Apache-2.0, a separate process controlled by the daemon over its gRPC API). It announces overlay subnets to the customer's routers and learns theirs, with filters on both sides. GoBGP's route installation is Linux-only, so the daemon installs learned routes into Windows through IP Helper. RRAS BGP is not used.
4. **OSPF is not implemented.** Customers who run OSPF internally redistribute the BGP-learned Ranz routes into OSPF on their own routers (MikroTik, Cisco, Juniper and pfSense/FRR all can). Routers that speak neither protocol use static routes.
5. **Router-on-a-stick stays possible**: a VLAN trunk over Local Bridge to a physical NIC lets a customer's router route between Ranz networks.
6. L2 switched networks (ADR-0014) are subnets like any other from the router's point of view. EVPN remains the matching model if L2 segments are ever stretched between sites with BGP-speaking routers; noted, not decided.

## Consequences

- `Layer3.c` is gone (PR #25) and is not carried into the new core; kernel IP forwarding replaces it and is faster than routing in user mode.
- The number of loopback adapters on a gateway grows with the number of routed networks and VLANs; the bridge path to those adapters (SeLow today, XDP later) is the throughput limit, not the routing.
- The control plane needs route advertisement, approval, health checks and ECMP; its design still needs its own ADR.
- The GoBGP sidecar adds a Go binary to gateway installations that peer with routers; nodes that do not peer never run it.
