# ADR-0028: IPAM in the controller and overlay DNS per VRF

**Status:** Accepted (2026-10-20, from the SDN spec #176 that Hilmi filed; recorded by SDN-1, #177). Makes concrete the "virtual DHCP: none; IPAM in the control plane" row of ADR-0008.

## Context

The new core has no address management and no overlay DNS. SoftEther hands out addresses with the virtual DHCP server of SecureNAT, which ADR-0008 and ADR-0014 drop. With VRFs (ADR-0025) the same private range can exist in several routing domains, so addresses and names must be scoped per VRF, and a host must resolve overlay names without breaking its normal DNS.

## Decision

### IPAM

1. **IP addresses are allocated only by the controller** (ADR-0026). There is one source of truth and no DHCP inside the overlay.
2. **Pools are per VRF:** each Network has IPv4 and IPv6 pools, with reservations, and an event fires before a pool runs out (ADR-0030).
3. **Each VRF gets a random ULA /48** (RFC 4193), so IPv6 inside a VRF is unique by construction. One /64 of it is reserved for 4via6 (ADR-0025).
4. **LAN subnets behind a gateway are advertised as routes, not allocated**, so existing LANs keep their addresses.
5. **The first controller start creates an automatic pool** for VRF `default` (ADR-0034), so no one picks a subnet before the first connection.

### Overlay DNS

6. **A stub resolver in the node listens on each Wintun address.** NRPT rules (the Windows Name Resolution Policy Table) send only the overlay suffixes to it, so the host's normal DNS keeps working for everything else.
7. **One zone per VRF**, with records (`DnsRecord`) from the controller, so the same name can mean different hosts in different VRFs.
8. **Overlay DNS is on by default:** `fileserver.<suffix>` resolves from every node without setup (ADR-0034).
9. The answers the stub resolver sees also feed the FQDN rules of the policy engine (ADR-0029).

## Consequences

- The controller conformance seam (ADR-0026) covers IPAM and DNS records: the control messages a simulated node receives for an applied intent. The VM CI job covers the real NRPT binding.
- The unified-management spec #224 (2026-10-21) adds a DHCP responder for L2 Networks: when an L2 Network has no DHCP server on its bridged LAN, the node answers DHCP from the Network's IPAM pool (SDN-43, #236). The pool stays the controller's; the responder only hands out its addresses.
- Tickets: SDN-10 (#186), SDN-11 (#187).
