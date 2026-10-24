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

## Amendment 2026-10-23: IPv6 pools, reservations, gateway LAN subnets and the pool event (SDN-10)

Recorded by SDN-10 (#186), which builds on the IPv4 addresses of SDN-3 (#179). It makes decisions 2 to 4 concrete in the controller (`controller/internal/intent/ipam.go`, `address.go`).

- **IPv6 pools.** The IPv6 pool of a Network lies in the ULA /48 of its VRF, outside the /64 that 4via6 reserves (decision 3), which is the last /64 of the ULA, `<ula>:ffff::/64`, so the pools an operator carves from the start never meet it. A Node holds one address of each family in every L3 Network of its VRFs: the one it declares (`addresses` for IPv4, `ipv6Addresses` for IPv6), else the one it held, else the lowest free host address of the pool. The first address of a pool, and for IPv4 its last, are no host's, unless the pool holds no more than two. The pools of one VRF do not overlap, so an address names one holder; two VRFs may use the same range. A Node holds at most 16 addresses, the most that the control protocol carries.
- **Reservations.** A Network reserves prefixes of its pools, or single addresses (`reserved`). The allocation steps over them, a Node cannot declare one, and a Node that held an address that a Network now reserves gets another. A reserved address counts as in use for the pool event.
- **Gateway LAN subnets.** A gateway Node declares the LAN subnets behind it, by VRF (`lanSubnets`), and the controller reports each as a route via that Node (`GET /api/v1/ipam`, `ranz get ipam`). A LAN subnet is a route and never an allocation: no pool of its VRF may cover one, so no Node holds an address in one. Two gateways may advertise the same subnet (ADR-0025 decision 12). The route reaches the nodes with their per-VRF forwarding tables (SDN-4, #180), its first consumer; until then the control protocol does not carry it.
- **The pool event.** A change of the intent that takes a pool to the percentage of its host addresses in use that its Network sets (`poolThreshold`, 80 when it sets none) raises an `ipam-pool-near-exhaustion` Event in the transaction of the change (ADR-0030 decision 5). The condition arises once while the pool stays there, and again when the pool has fallen below its threshold and a later change takes it there once more. SDN-16 (#192) delivers the Event by webhook and as a metric.
- **No DHCP.** The controller conformance seam checks that the control protocol has no DHCP, and that a node simulator, which has no DHCP client and no data plane, holds its addresses from the Update alone. SDN-43 (#236) adds the DHCP responder for L2 Networks and changes that check for the objects it adds.

## Amendment 2026-10-24: the DHCP responder of an L2 Network (SDN-43)

Recorded by SDN-43 (#236), the consequence of the spec #224 above. Decision 1 stands for the overlay: no DHCP runs inside it, and the Nodes of an L3 Network hold their addresses from the controller alone. The responder serves the hosts of an L2 Network, the LAN that the Network is bridged to.

- **The intent.** A Network of mode L2 may carry a responder (`dhcp`): its mode, `off` (the default) or `pool`, the Node that answers DHCP for the Network, a Node of its VRF, the gateway and at most 4 DNS servers that the clients get, and the lease time (two hours when it sets none, 60 s to one year). The IPv4 pool is a /16 to a /30. The responder's own address, its server identifier, is a host address of the pool that the controller fills in like a Node address: the one it had while it stays free, else the lowest free one. No client gets the first or last address of the pool, a reservation, the gateway, a DNS server or the responder's own address. A Node that answers DHCP for a Network cannot be deleted.
- **The desired state.** Only the Node that answers DHCP gets the responder, in the Network object of its state (`Network.dhcp`), and only while the mode is `pool`: the other Nodes of the VRF get the Network without it, so a Node never answers DHCP for a Network whose object carries none.
- **The node.** The responder is a member of the switch of the Network (ADR-0019) with a locally administered MAC address that the node derives from its name and the Network's, the same at every start. Before it answers a client it sends a DHCPDISCOVER of its own and waits 2 s; it probes again every 5 minutes, and while a DHCP server of the LAN answered within 15 minutes it answers nobody, so a Network bridged to a LAN with DHCP keeps the LAN's server. It follows RFC 2131 for DISCOVER, REQUEST (selecting, init-reboot, renewing, rebinding), DECLINE, RELEASE and INFORM, and answers ARP for its own address.
- **Leases in IPAM.** The node reports the leases of each responder on its control stream (`Leases`), all of them after each Hello and whenever they change; the controller keeps each report in place of the one before and lists the leases that have not expired (`GET /api/v1/ipam/leases`, `ranz get leases`), also while the mode is off, as the clients hold them until then. The pool stays the controller's: the responder only hands out its addresses.
- **Capability.** An L2 Network needs XDP or SeLow on each Node of its VRF (ADR-0033); the responder adds no Capability of its own.
