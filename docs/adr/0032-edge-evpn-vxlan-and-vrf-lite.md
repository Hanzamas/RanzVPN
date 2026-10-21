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
