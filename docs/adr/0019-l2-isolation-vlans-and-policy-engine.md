# ADR-0019: L2 isolation, full VLAN support and a stateful identity-based policy engine

**Status:** Accepted (2026-10-13, Hilmi: "gas", and "seting vlannya juga lengkap bisa kah"). Scope: the new core (ADR-0017 step 7). The current SoftEther-based code keeps its existing features unchanged until then.

## Context

The SoftEther-based code already isolates traffic in several ways: separate Virtual Hubs (separate broadcast domains, joined across servers by cascades), a per-user/group/cascade VLAN ID policy (802.1Q tag inserted on ingress and removed on egress, so a session only sees its VLAN), a configurable VLAN TPID (`VlanTypeId`, default 0x8100), VLAN-aware MAC learning (`NoManageVlanId` turns it off), the PrivacyFilter policy (sessions with it cannot reach each other, only sessions without it, like Wi-Fi client isolation), anti-spoofing policies (CheckMac, CheckIP, ArpDhcpOnly, DHCP filters, RA filter, MaxMac/MaxIP, NoBridge, NoRouting) and per-session protocol filters (FilterIPv4, FilterIPv6, FilterNonIP).

Its firewall is the per-hub access list: prioritised pass/discard rules matching source/destination IP and mask, protocol, port ranges, source/destination user or group, MAC and mask, the TCP established flag, plus delay/jitter/loss simulation and HTTP redirect; and a source-IP access control list for connecting to a hub. It is stateless apart from the TCP flag, has no per-rule counters or logging, no address groups, no time-based or domain-based rules, no VLAN criterion, and is scanned linearly per frame under the hub lock (spec #31). VLAN handling is a single VLAN per session: there are no trunk sessions with an allowed-VLAN list, no native VLAN, no per-VLAN limits, and the NIC "VLAN transparency" tool lost its only caller when the GUI was removed.

## Decision

1. **Isolation primitives stay first-class** in the new core: separate networks (the successor of Virtual Hubs), client isolation (the successor of PrivacyFilter) and the anti-spoofing set.
2. **Full VLAN support** in the L2 switch of the new core:
   - every member port (user session, cascade, bridge, loopback adapter) is an **access** port (one VLAN, untagged towards the member) or a **trunk** port (an allowed-VLAN list, plus an optional **native VLAN** for untagged frames);
   - VLAN membership is assigned from user, group or tag policy, and can be overridden per port;
   - VLAN-aware MAC learning, per-VLAN broadcast/multicast limits and per-VLAN statistics;
   - configurable TPID per network and optional QinQ (outer tag) for carrier-style setups;
   - VLAN is a match criterion in the policy engine;
   - VLAN state is visible in the CLI and status output, and the bridge backends pass tagged frames through (with NIC tag transparency configured where the driver needs it);
   - inter-VLAN routing is not done inside the daemon; it stays at the edge (ADR-0010).
3. **Stateful, identity-based policy engine** replacing the access list:
   - rules match identity (user, group, node tag, network, VLAN) as well as addresses, protocols and ports, with direction;
   - connection tracking for TCP, UDP and ICMP, so replies to allowed flows pass without mirror rules;
   - address groups, per-rule hit counters and optional per-rule logging, and time-based rules;
   - rules compiled into lookup tables per network and evaluated once per flow on ingress, not scanned linearly per frame;
   - a default action per network (allow or deny), and import of existing access-list rules for migration.
   Host firewalls (Windows Firewall on the loopback adapter) keep applying on top.

## Consequences

- The policy engine and the VLAN-aware switch are core components of the new-core spec; their verification uses the harness seam (frames between members of different VLANs and policies, golden outputs of the CLI).
- The current access list, VLAN policy and PrivacyFilter are not extended in the SoftEther-based code; the spec for the new core defines the migration of their configuration.
- Domain-based (L7) filtering is not part of this decision; it can be added to the policy engine later as a separate decision.
