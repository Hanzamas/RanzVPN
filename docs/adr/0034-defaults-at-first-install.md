# ADR-0034: A first install works like a mesh VPN with no configuration

**Status:** Accepted (2026-10-20, from the SDN spec #176 that Hilmi filed; recorded by SDN-1, #177).

## Context

Ranz v1 is a full SDN for network engineers (VRFs, NAT, route leaking, EVPN), but most installations are small: an SME owner with no network staff who wants servers and laptops connected the day the product is installed. The SDN features must not stand in the way of that simple case, and the simple case must not weaken the model (the policy engine stays default deny, ADR-0029).

## Decision

1. **The first controller start creates VRF `default`** with an automatic address pool (ADR-0028), full mesh topology, overlay DNS on, and the explicit starter rule "allow all inside VRF default" (ADR-0029).
2. **New nodes join `default`** and form a full mesh, so every node reaches every other node directly.
3. **More VRFs, overlapping ranges, NAT, route leaking, egress, Endpoints, Mirrors, hub-and-spoke and EVPN appear only when the intent asks for them.** The simple case feels as simple as a mesh VPN.
4. The other defaults that apply at first install:
   - a single controller with its embedded store (ADR-0026);
   - MTU 1280 per VRF with TCP MSS clamping (ADR-0025);
   - per-protocol conntrack timeouts with sane defaults (ADR-0029);
   - only TCP 443 and UDP 443 open to the internet, UDP 443 QUIC only (ADR-0035).

## Consequences

- The starter rule is an ordinary rule in the intent, visible through the API and named by `ranz explain` like any other rule.
- The default VRF tracer (SDN-3, #179) proves this path end to end: a fresh controller reports VRF `default` and the starter rule, and two harness nodes get addresses from the pool and exchange ICMP echo over the in-process loopback transport.
- Tickets: SDN-3 (#179).

## Amendment (AUD1-DT-6, #454)

The mesh is not changed: the control stream of the Nodes is not behind the admin source allowlist, and the starter rule stays. What the first install narrows is who may reach the API and the web UI of the Controller. `ranz install --controller` sets the admin source allowlist (SDN-39) to loopback and the subnets of the private interfaces of the host, or to the sources that `--admin-from` names, or leaves it empty with `--admin-from any`. The Controller applies the list at its first start only, and says in its log and in `ranz status` which sources are allowed and how to change them, and that the starter rule allows all traffic inside VRF `default` and how to narrow it (docs/first-test.md).
