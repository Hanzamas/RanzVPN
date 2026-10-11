# ADR-0010: Routing is the OS's job; BGP only at the edge via RRAS or GoBGP, never inside the VPN daemon

**Status:** Proposed (assistant's recommendation in answer to "static routing ganti ke BGP"; not confirmed).

## Context

SoftEther offers an L3 switch (`Layer3.c`, static routes between hubs) and cascade links for site-to-site. Hilmi asked for BGP, dynamic routing, firewall, hub-to-hub, hub-to-user, P2P and VLAN in the modernised product. A BGP implementation inside the daemon would be tens of thousands of lines and only makes sense for an L3 overlay with many sites exchanging prefixes dynamically.

## Decision

- Each node gets its route table from the control plane (ADR-0011); site gateways advertise their subnets; multiple gateways get ECMP with health checks.
- The VPN daemon provides an interface and installs routes through the Windows IP stack (IP Helper); it does **not** speak BGP.
- Where a site has real routers, a gateway node runs **RRAS BGP** (Windows Server, `Add-BgpRouter`) or **GoBGP** next to the daemon to import and export overlay routes. BGP is therefore an edge integration, not a core feature.
- L2 switched networks (ADR-0014) are subnets like any other from the router's point of view: the same routing, firewall and edge-BGP design applies on top of them. EVPN is the matching control-plane model if L2 segments are ever stretched between sites with BGP-speaking routers; this is noted, not decided.
- Policy/firewall: a stateful L3/L4 filter in the data path with identity-based rules (`group A to group B port 443`) distributed by the control plane; host-level rules through the WFP user-mode API (ADR-0008). "VLAN" in the overlay is a segment plus policy.

## Consequences

- `Layer3.c` is not carried into the new core; Windows IP forwarding replaces it.
- For two to five sites, static routes remain sufficient; BGP is only wired in where a customer's network already runs it.
- The control plane design (own coordination service in the Headscale/Nebula style, signed peer and route distribution) is implied here and in ADR-0011 but has no ADR of its own yet.
