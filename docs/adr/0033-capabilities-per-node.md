# ADR-0033: Nodes report Capabilities and the controller refuses intent a node cannot honour

**Status:** Accepted (2026-10-20, from the SDN spec #176 that Hilmi filed; recorded by SDN-1, #177).

## Context

Ranz nodes run on very different Windows hosts: Home, Pro and Server SKUs, x64 and arm64, with or without Hyper-V, LBFO, SeLow or the XDP runtime. Several SDN features depend on them: the Egress tier (ADR-0025), VRF-lite VLANs (ADR-0032), the L2 backends (ADR-0022). An intent that silently half-applies on a host that cannot do it is the worst outcome, and a buyer must know in advance which features need Windows Server.

## Decision

1. **Each node reports its Capabilities to the controller:** SKU, architecture, Hyper-V, LBFO, SeLow, XDP and its Egress tier. *(Since 2026-10-21 also the fallback to 5555 when 443 is taken, ADR-0035 amendment of that date.)* They travel on the control stream (ADR-0027) and are part of the `Node` resource (ADR-0031).
2. **The controller validates intent against the Capabilities before an apply** and rejects what a node cannot honour, naming the node and the missing Capability, for example "node X is Home: multi-VLAN VRF-lite needs Windows Server". There is no silent partial apply.
3. **The UI shows which features each node supports**, so an administrator plans before applying.
4. **Every core feature works on every supported SKU and architecture:** overlay, VRF, NAT, policy, DNS, IPAM, Mirror and explain. Only gateway and edge features may require Windows Server.

## Consequences

- A new core feature must come with a path for every SKU and architecture; only gateway and edge features may list a Capability as a requirement. Egress is a gateway feature, and its tier 3 still runs on every host (ADR-0025), so any node can be an exit.
- Capability rejection is checked in the controller conformance seam (ADR-0026) with simulated nodes that report different Capabilities.
- The unified-management spec #224 adds device posture (OS version, BitLocker, Defender, firewall, domain membership), reported with the Capabilities (SDN-57, #250).
- Tickets: SDN-9 (#185).

## Amendment 2026-10-27: the Capability operations (SDN-50)

Recorded by SDN-50 (#243). `Capabilities.operations` (field 12) says that the node answers the `Operation` frame of its control stream: it reads and clears the MAC table and the IP table of its L2 Networks on the order of the Controller (ADR-0027 amendment of the same day). It is the Capability of a way of talking, not of a feature: no resource of the Intent needs it, `capability.Check` has no rule for it, and no apply is refused for the lack of it. Decision 4 holds, since a node that cannot answer forwards as well as one that can, and only an operator's view of its tables is missing. The Controller sends an Operation only to a node that reports it, because a node that does not know the frame ends its stream, and a call that asks every node of a Network gives the others the status `unsupported` (ADR-0031 amendment of the same day). The API form of the Capabilities has it as `operations`, and a node that reports nothing reports no `operations`.

## Amendment 2026-10-30: the Capability bgpPeering (SDN-77-R2)

Recorded by SDN-77-R2 (#532), from the review of SDN-77 (#357). `Capabilities.bgp_peering` (field 14; 13 is the `tags` of SDN-87, #386) says that the node runs the BGP peering of the standard mode (ADR-0010 amendment of 2026-10-29): its release has the peering, and `ranz.exe`, which holds the sidecar `ranz bgp` that the peering starts, is next to it. The peering is an edge feature, so `capability.Check` has a row for it: the `Vrf` object of a VRF whose peering is `bgp` needs it. The apply of an intent that makes a node that does not report it a member of such a VRF is refused with the message of decision 2, naming the node, the VRF and the Capability, and so is the Hello of a node that does not report it while its state has such a VRF. Reason: the check that SDN-76 added, `plainLinks`, passes for a node of the release before the peering. That node ignores the settings of the sidecar and starts none, and the Controller gives no route of the LAN subnets of the VRF, so it would lose every LAN route of the VRF and its own LAN subnets would be gone from every other node, with no error, which is the silent partial apply of decision 2. The API form of the Capabilities has it as `bgpPeering`, and a node that reports nothing reports no `bgpPeering`.

## Amendment 2026-10-31: the Capability evpn (SDN-63)

Recorded by SDN-63 (#290), the Stretch resource of the amendment of ADR-0032 of 2026-10-22. `Capabilities.evpn` (field 15; 13 and 14 are the fields of SDN-87, #386, and SDN-77-R2, #532) says that the node can be the gateway of a Stretch. The node reports it from its edition: a Windows Server does, on every architecture, since the VXLAN module runs on every node (as it does for `plainLinks`), and any other host, or one whose version cannot be read, does not. The licence is not part of it. The amendment of ADR-0032 describes the Capability as that of a Windows Server node whose Enterprise licence is valid, and the Controller checks that licence and not the node, since only the Controller holds the key (ADR-0036 decision 5). `capability.Check` has a row for it: a Stretch needs `evpn` at its gateway, and a node that is no gateway needs nothing. An apply that gives a Stretch to a gateway that does not report it is refused with the message of decision 2, naming the node, the Network and the Capability, and a gateway that has reported nothing yet is checked at its first Hello, which is refused the same way, with the reason `capability`. The API form of the Capabilities has it as `evpn`, and a node that reports nothing reports no `evpn`.
