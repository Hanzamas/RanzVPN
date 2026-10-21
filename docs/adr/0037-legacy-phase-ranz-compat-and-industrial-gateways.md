# ADR-0037: The Legacy phase: `ranz-compat` for SoftEther-line VPN protocols, and industrial gateways

**Status:** Accepted (2026-10-20, from the SDN spec #176 that Hilmi filed; recorded by SDN-1, #177). Phase: after v1. Amended in scope by the unified-management spec #224 (2026-10-21), noted below. Brings stock SoftEther peers back as a sidecar; see the ADR-0011 and ADR-0022 amendments.

## Context

The new core drops SE-VPN: the legacy listener leaves the node in strangler step 8 (ADR-0022), and the ADR-0011 amendment of 2026-10-19 removed compatibility with stock SoftEther clients. Ranz also has no node builds for non-Windows platforms. Yet existing SoftEther clients and bridges, phones and tablets with OpenVPN or WireGuard apps, the built-in L2TP/IPsec, SSTP and IKEv2 clients of every OS, MikroTik and Cisco routers, and industrial equipment that still speaks X.25, serial, Modbus, DNP3 or IEC 104 all need a way into a Ranz network. The slim fork's Cedar and the Apache-2.0 protocol modules of `main-oracle` already implement most of the VPN protocols, with OpenSSL. The new protocol must stay unchanged and free of third-party crypto (ADR-0022).

## Decision

### `ranz-compat`

1. **`ranz-compat` is a separate sidecar process: the frozen Cedar of the slim fork, with OpenSSL** as its own crypto library. The node and the new protocol stay unchanged.
2. **Stock SE-VPN clients, bridges and servers are served by `ranz-compat`; the node and the new protocol stay free of SE-VPN compatibility** (Hilmi, comment on #177, 2026-10-21). SE-VPN keeps its frozen wire format.
3. **Protocols:** OpenVPN, WireGuard, L2TP/IPsec (IKEv1), SSTP, EtherIP and L2TPv3, and RADIUS are ported back from the Apache-2.0 modules of `main-oracle`. IKEv2 is written new or provided by a strongSwan sidecar.
4. **Each compat session is a full member of a VRF:** it joins as a peer of the node through a local named-pipe link, gets an IPAM address (ADR-0028), tags from its user and group, overlay DNS, and shows up in `ranz explain` (ADR-0031).
5. **Reachable through the front door on TCP 443** (ADR-0035), and on an own port where a protocol needs one. A `CompatListener` resource (protocol, authentication source, target VRF) configures it.
6. **Order inside the phase:** SE-VPN compat; OpenVPN and WireGuard; L2TP/IPsec and SSTP; EtherIP, L2TPv3 and RADIUS.

### Industrial gateways

7. **A `legacy` role of the node, one module per protocol**, configured by a `LegacyGateway` resource (protocol type, LAN-side endpoint, X.121 prefixes or device addresses, target VRF).
8. **XOT first:** an own X.25 packet-layer subset with the RFC 1613 framing, X.121 addresses routed per VRF by the controller like prefixes, and X.25 virtual circuits translated to and from TCP connections (PAD with X.3, X.28 and X.29).
9. **Then:** serial devices over RFC 2217 (the Win32 COM API); Modbus RTU to Modbus TCP (libmodbus); DNP3 (opendnp3); IEC 60870-5-104 and IEC 61850 (a separate sidecar because of their GPL licence, or under a commercial licence, ADR-0036); an OPC UA and MQTT bridge (open62541); TN3270 (x3270). Industrial work runs in parallel with the compat protocols.
10. **Non-IP L2 protocols need no gateway:** an L2 Network carries non-IP EtherTypes (IPX, NetBEUI, AppleTalk, Profinet, GOOSE) unchanged.
11. **Other platforms join through the compat protocols.** There are no node builds for non-Windows platforms.

### Changes from #224 (2026-10-21)

12. **RADIUS moves from the Legacy phase to v1**; the compat protocols reuse the v1 RADIUS client (SDN-36, #230; SDN-L9, #215).
13. **`ranz-compat` also dials out as a cascade client to stock SoftEther servers**, joining that network to a Ranz VRF, so old and new networks connect during migration (SDN-L18, #255).

## Consequences

- The slim fork's Cedar is retired from the node in strangler step 8 (ADR-0022) and lives on only inside `ranz-compat`. Its defects found by the #224 inventory are fixed in the foundation because of that (#96).
- OpenSSL stays out of the node: `ranz-compat` links it, the node does not (SDN-L1, #207).
- Testing: SE-VPN compat against the pinned `main-oracle` releases (seam 1 of #45); standard clients (OpenVPN, WireGuard, the built-in Windows L2TP/IPsec and SSTP clients) in the VM CI job; industrial gateways against reference peers (an XOT peer, a libmodbus test server, an opendnp3 outstation).
- Tickets: SDN-L1 to SDN-L17 (#207 to #223) and SDN-L18 (#255).
