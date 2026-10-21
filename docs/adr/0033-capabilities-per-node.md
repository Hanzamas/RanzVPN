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
