# ADR-0004: L3 core on Wintun, L2 as an optional service

**Status:** Superseded by ADR-0014 (2026-10-11). Recommended with "Saya sarankan ya"; Hilmi rejected the L2-as-optional premise ("yang gw suka itu L2-nya") and chose dual-mode networks with L2 first-class. The analysis below is kept because it still applies to L3 routed networks.

## Context

SoftEther is Layer 2 everywhere: the Virtual Hub is an Ethernet switch across the WAN, which brings MAC flooding, broadcast and ARP over the tunnel, DHCP relay hacks and SecureNAT, a 12k-line user-mode TCP/IP stack that fakes Layer 3. That design accounts for roughly 40% of the complexity that the slim-down is removing.

Everything the maintainer wants next (BGP, routing, firewall, hub-to-hub, hub-to-user, P2P, scalability) lives at Layer 3 and maps onto standard tooling there. The fastest user-space adapter on Windows, Wintun, is L3 only. The performance ceiling of a user-space VPN is set by the adapter boundary and syscalls per packet, not by crypto (see discussion log, "performance ceiling").

## Decision

- The new core is an **L3 overlay**: IP packets carried inside the transport (ADR-0005), **Wintun** as the adapter on every node.
- **L2 is an optional service on top of the L3 overlay**, in the way EVPN-VXLAN does it: an Ethernet segment with a VNI carried over the L3 underlay, MACs learned via the control plane. Only sites that need non-IP protocols or stretched broadcast domains enable it, using a TAP adapter (tap-windows6, or Neo6 while the slim fork still ships it) plus the Windows Network Bridge to reach a physical NIC.
- "VLAN" in the overlay means a segment/VNI plus policy; real 802.1Q tagging exists only inside the L2 service.

## Consequences

- The Virtual Hub switching code, SecureNAT, DHCP, ARP handling and the L2 bridge code are not carried into the new core; the slim fork keeps them only as a compatibility gateway and reference.
- BGP, firewall rules and routing become ordinary L3 problems (ADR-0010).
- Neither Neo6 nor SeLow is needed by the core (ADR-0009, ADR-0013).
- If this ADR is rejected in favour of staying L2, the adapter becomes tap-windows6 or Neo6, transport framing stays custom, and BGP becomes irrelevant; the estimated final code size is about 110k lines instead of 50k to 60k.
