# ADR-0014: Dual-mode virtual networks: L2 switched (first-class) and L3 routed, one node binary with both backends

**Status:** Accepted (2026-10-11, Hilmi: "yang gw suka itu L2-nya"; LAN gaming and other broadcast / non-IP uses must keep working). Supersedes ADR-0004.

## Context

ADR-0004 recommended an L3-only core with Wintun and treated L2 as an optional add-on. Hilmi rejected the premise: Layer 2 is the feature he values most in SoftEther (a virtual Ethernet segment across the internet: LAN discovery, broadcast, multicast, non-IP protocols, game LAN play). The performance argument for L3 (Wintun's ring buffers, no MAC learning) still holds for workloads that only need IP, and the routing/firewall/BGP goals still live at L3.

## Decision

- Every virtual network has a **type**, chosen per network:
  - **L2 switched network**: a virtual Ethernet segment, ZeroTier-style. The control plane learns and distributes the MAC-to-node mapping; unicast goes point to point; broadcast and multicast are delivered by **group subscription** (nodes subscribe to the groups they need) instead of flooding every session as SoftEther's Virtual Hub does. Client adapter: a TAP device (Neo6 or tap-windows6, ADR-0009). Bridging to a physical LAN: **SeLow** (ADR-0013) or the Windows Network Bridge.
  - **L3 routed network**: IP packets only, adapter **Wintun**, fastest path; the routing, firewall and edge-BGP design of ADR-0010 applies directly.
- **One node binary carries both backends** (ADR-0011); the network type selects the data path. A node can be a member of several networks of different types.
- L3 services (routing between segments, identity-based firewall, BGP at the edge via the GoBGP sidecar, ADR-0010) sit on top of L2 segments as well as on L3 networks: an L2 segment is a subnet like any other from the router's point of view.
- The transport (ADR-0005) carries Ethernet frames for L2 networks and IP packets for L3 networks inside the same session layer.

## Consequences

- ADR-0004 is Superseded; its performance analysis remains valid for L3 networks.
- The L2 data path must avoid SoftEther's sins explicitly: no flooding of unknown unicast across the WAN beyond a bounded learning window, no DHCP relay hacks (IPAM can still be control-plane driven for L2 networks), no user-mode TCP/IP stack (SecureNAT); NAT where needed is WinNAT.
- Both adapter families stay in the design: Wintun (Accepted for L3) and a TAP driver (Neo6 versus tap-windows6 still Proposed, ADR-0009). SeLow stays (Accepted).
- The slim fork's L2 code (Virtual Hub switching, Local Bridge, cascade) becomes the reference for the L2 backend rather than disposable compatibility code.
- Expected code size of the new core rises compared with the L3-only estimate (50k to 60k) because of the L2 backend, MAC learning and group delivery; no new figure was estimated in the discussion.

## Amendment 2026-10-13: edge BGP is the GoBGP sidecar only (no RRAS)

The 2026-10-13 grilling ruled out RRAS BGP. The decision point above originally read "BGP at the edge via RRAS or GoBGP"; the only edge-BGP path is the **GoBGP sidecar** (`ranz-bgp`, embedding GoBGP as a library, over a local named pipe with JSON), as decided in ADR-0010 and specified for the new core in ADR-0022. RRAS is not used for BGP.
