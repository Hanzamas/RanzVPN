# ADR-0029: One stateful policy layer per VRF, compiled from tags, and Mirrors over VXLAN

**Status:** Accepted (2026-10-20, from the SDN spec #176 that Hilmi filed; recorded by SDN-1, #177). Uses the policy engine of ADR-0019 and ADR-0022 and scopes it to VRFs (ADR-0025).

## Context

ADR-0019 and ADR-0022 define a stateful, identity-based policy engine in the node: rules ordered by priority, one evaluation per flow on ingress, an established-flow fast path, compiled tables swapped atomically, and a conntrack table bounded per network. With VRFs, route leaking and a controller, the open points were: where rules come from, what the default is, how one VRF is kept from exhausting shared state, how domain names are matched, and how traffic reaches an IDS or a sensor without a built-in one.

## Decision

1. **One stateful policy layer, in the node, for all overlay traffic.** It is the ADR-0019/ADR-0022 engine, fed with rules that the controller compiles from tags. There is no separate stateless ACL layer, so there is one place to look when traffic is blocked. WFP still only protects the host (ADR-0022).
2. **Rules are written between tags, or FQDN sets, not IP addresses**, with protocol and port, priority and action, so rules follow identities when addresses change.
3. **Default deny with explicit allow rules.** The engine itself is default deny; the simple case of a first install works through an explicit starter rule, "allow all inside VRF default" (ADR-0034).
4. **Stateful enforcement:** one evaluation per flow on ingress and an established-flow fast path, so replies to allowed flows pass without mirror rules.
5. **The conntrack table has a quota per VRF**, so one busy or misbehaving VRF cannot exhaust the table for the others. Per-protocol conntrack timeouts are part of the VRF in the intent, with sane defaults.
6. **Policy applies to leaked traffic** (ADR-0025): a leak is reachability, not a firewall bypass.
7. **FQDN egress rules** (for example `*.microsoft.com`) are compiled into address sets from the answers that the node's own stub resolver sees (ADR-0028), so cloud services are allowed without chasing their IP ranges.
8. **Inline inspection uses an external appliance** (Suricata, pfSense, Fortinet) placed through hub-and-spoke (ADR-0025). Ranz builds no IDS, IPS or WAF of its own.
9. **A Mirror copies matching traffic to a sensor over VXLAN.** It has a source selector (tag, VRF or node), a filter (protocol or port), a sensor IP and a rate limit, so Zeek or Suricata see the traffic passively and a Mirror never eats the link. The VXLAN encapsulation module is the one the EVPN gateway uses (ADR-0032).

## Consequences

- ADR-0019 decision 3 allows "a default action per network (allow or deny)". Under this ADR the engine's default is always deny, and the allow case is the explicit starter rule. *(ADR-0019 is amended to match, amendment of 2026-10-21.)* The per-network conntrack bound of ADR-0022 becomes a quota per VRF.
- The vpntest harness (seam 2 of #45) checks policy from tags with conntrack, per-VRF conntrack quotas, FQDN rules and mirroring against golden output; the controller conformance seam (ADR-0026) checks the rules each simulated node receives.
- Tickets: SDN-8 (#184), SDN-21 (#197), SDN-23 (#199).
