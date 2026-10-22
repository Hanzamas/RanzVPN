# ADR-0032: Edge handoff by EVPN type-5 with VXLAN in the node, and VRF-lite for non-overlapping prefixes

**Status:** Accepted (2026-10-20, from the SDN spec #176 that Hilmi filed; recorded by SDN-1, #177). Extends the edge BGP of ADR-0010 and the `ranz-bgp` sidecar of ADR-0022 (see the ADR-0010 amendment of 2026-10-20).

## Context

ADR-0010 puts edge routing on BGP through the `ranz-bgp` sidecar (GoBGP as a library, a local named pipe with JSON) and notes EVPN only as the model for stretched L2, not decided. With VRFs (ADR-0025) the overlay now carries routing domains with overlapping prefixes, and a data-centre engineer wants them handed into the fabric's VRFs. Two Windows facts shape how (research of 2026-10-20, #176):

- **Windows has no VXLAN interface for applications**, and a host has a single routing table, which cannot hold overlapping prefixes.
- **VLANs:** Windows 11 Home has one VLAN per NIC (the driver's VlanID). Several VLAN interfaces on one NIC need LBFO team interfaces (Windows Server) or Hyper-V host vNICs. Intel ANS is gone on Windows 11.

## Decision

1. **EVPN type-5 (IP prefix routes per VRF) through `ranz-bgp`.** The sidecar keeps GoBGP as a library; its named-pipe JSON contract with the node is extended for EVPN routes per VRF. A Ranz gateway peers EVPN type-5 with the fabric, so overlay VRFs and fabric VRFs exchange prefixes automatically.
2. **The gateway node does VXLAN encapsulation and decapsulation itself, in user space**, because Windows has no VXLAN interface for applications. A Windows Server gateway acts as a leaf-like VTEP for the overlay. The VXLAN module is shared with Mirrors (ADR-0029).
3. **Overlap-safe handoff is EVPN only.** Overlapping customer prefixes are handed off only through EVPN, so the single Windows routing table never sees them.
4. **VRF-lite (one VLAN per VRF on a trunk) is for non-overlapping prefixes**, for routers without EVPN. On Windows Server it uses LBFO team interfaces, with no Hyper-V needed. On client SKUs it is one VRF per physical NIC.
5. **Connections between organisations** with separate controllers use gateways with BGP or EVPN type-5, plus 1:1 NAT for overlap (ADR-0025). They need no new feature. Federation between controllers is after v1.
6. **Not in v1:** EVPN type-2 and L2 stretch over EVPN, routed multicast with PIM. **Not at all:** OSPF or RIP in the node, RRAS BGP (ADR-0010).
7. EVPN and BGP are Enterprise tier features, gated by the controller's licence check (ADR-0036).

## Consequences

- An intent that asks a client SKU for several VRF-lite VLANs on one NIC is refused before apply, naming the node and the missing Capability (ADR-0033).
- Interop is tested in the VM CI job with the two-VM pattern of the QTIP spike: EVPN type-5 against a reference BGP speaker (FRR) on a second VM, traffic through VXLAN, and two overlapping VRFs handed off without conflict. LBFO VLAN interfaces for VRF-lite are covered by the same job.
- EVPN lands last in the delivery order of #176.
- To verify during the work: Hyper-V host vNIC VLANs on Windows 11 Pro.
- Tickets: SDN-25 (#201), SDN-26 (#202).

## Amendment 2026-10-22: EVPN type-1, 2, 3 and 4 join type-5 (L2 stretch)

Hilmi ruled in chat on 2026-10-22, after a grilling round, that the full EVPN route set is in scope. This replaces decision 6's "Not in v1: EVPN type-2 and L2 stretch over EVPN". Delivery order: type-5 first (SDN-25, SDN-26), then type-2 and type-3 (L2 stretch without multihoming), then type-1 and type-4 (multihoming), all before the v1 release.

**Routes and the sidecar**
- `ranz-bgp` carries type-1, 2, 3, 4 and 5. GoBGP already has all five types, so no new library; its EVPN documentation marks them "very experimental", which the interop job below has to cover.
- The named-pipe JSON contract carries EVPN routes in batches of up to 500 routes per message. After the pipe reconnects the node sends a full resync, not a delta.

**Intent model**
- A new resource **`Stretch`** binds one Gateway to one Network (an L2 Network, ADR-0014). It holds the L2 VNI, the route targets, the ESI, the BUM rate limit, the MAC import limit, the stale timer and the `irb` flag. The admin fills them; the controller only validates (for example no VNI used twice on one gateway).
- The existing `EvpnPeer` (per gateway and per VRF, ADR-0031) holds the L3 VNI and the VRF route targets for type-5 and for IRB. The admin fills them too.
- A new Capability **`evpn`** in the Capabilities message (ADR-0033): a Windows Server node whose VXLAN module is present and whose Enterprise licence is valid. VXLAN itself stays a core capability on every SKU, because Mirrors need it (ADR-0029).
- An intent is refused before apply, naming the node and the Network (and the missing Capability where it applies), when: the node lacks `evpn`; a Network has more than one gateway with a `Stretch` and no ESI is configured; a Network has an active `Stretch` and also a node with the `bridge` role, unless that node is the stretch gateway itself.

**MAC distribution (L2 stretch)**
- The controller stays the source of truth for the MAC-to-node map (ADR-0014). The gateway announces type-2 for the MACs the controller knows on the Network, and it feeds type-2 routes learned from the fabric into the controller's map as "remote MAC, through this gateway", so overlay nodes unicast to the gateway without flooding.
- Type-2 carries MAC only and MAC plus IP (the IP is known to the controller), so the fabric can suppress ARP and ND.
- MAC mobility uses the RFC 7432 sequence number. A MAC counts as flapping after 5 moves within 180 seconds and is then held for 300 seconds. A locally known MAC wins over a remote claim unless the remote sequence number is higher. An announced MAC is withdrawn after 600 seconds unseen, the same age as the Cedar hub.
- At most 10,000 remote MACs are imported per Network (default; it matches the v1 session target). Further MACs are dropped and the controller gets an event.
- When the BGP session or `ranz-bgp` goes down, remote MACs stay in use as stale for 120 seconds (configurable per Gateway) and are then flushed. The MACs this gateway announced are withdrawn by the fabric at once.

**Flooding (corrects the first draft of this amendment)**
- Ingress replication to the type-3 flood list applies only on the fabric side, between the gateway and the fabric's VTEPs, because Windows has no multicast underlay. Inside the overlay, broadcast and multicast keep the group subscription of ADR-0014 with its per-VLAN limits (ADR-0019, ADR-0022).
- Each `Stretch` has a BUM rate limit, on by default. BPDUs from the fabric are dropped at the gateway and never enter the overlay.

**Multihoming and routing on the stretched Network**
- Two gateways of one Network can share an Ethernet segment (ESI) active-active through type-1 and type-4. The admin sets the ESI; the node runs designated-forwarder election (modulo, service carving of RFC 7432) and split horizon, because GoBGP only carries the routes. Preference-based DF election is after v1.
- IRB is symmetric (the L3 VNI of the VRF, type-2 with the router MAC) and opt-in per `Stretch`, off by default, because on a normal data-centre VLAN the fabric already owns the default gateway and two owners of one IP break ARP. An anycast gateway IP and MAC across gateways exists only for an ESI pair.

**Shared module, licence, operations**
- **One VXLAN module**, written once with VNI, decap and replication to several VTEPs from its first ticket. That foundation ticket comes before Mirrors (SDN-23) and SDN-26, and Mirrors use it with a single destination.
- **Tier.** EVPN stays an Enterprise tier feature behind the licence check (ADR-0036). Past the grace period the gateway stops announcing type-1 to 5 and closes the stretch forwarding; the BGP peering goes down and the overlay Networks keep working.
- **Events.** Flap held, MAC import limit reached, stale expiry, DF change and peering down are controller events, and `explain` (ADR-0031) points to one of them when it answers why a MAC is not forwarded.
- **Interop.** The VM CI job against FRR extends to a stretched L2 Network, a MAC move between the two sides, an ESI pair, and an IRB case.
- **Still out:** routed multicast with PIM, OSPF or RIP in the node, RRAS BGP.
- **Consequences.** The shared VXLAN module learns MACs on the fabric side and replicates flood traffic. Multihoming needs two gateways on the Network. New terms for CONTEXT.md: Stretch, ESI, L2 VNI, L3 VNI.
