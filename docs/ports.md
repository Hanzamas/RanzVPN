# Ports and protocols

What an installation of the new core opens, uses and speaks, by plane. The decisions are in ADR-0020 (listener defaults), ADR-0035 (the front door), ADR-0015 (relay and peers), ADR-0022 and ADR-0026 (the Controller cluster). The Legacy protocols (SE-VPN compat, OpenVPN, WireGuard, L2TP, SSTP, IKEv2, EtherIP, L2TPv3, the industrial gateways) are postponed and are not listed.

Publicly a Node needs only **TCP 443 and UDP 443** open to the internet (ADR-0035). Everything else is optional, on the LAN side, outgoing only, or inside the host.

## Open to the internet

| Port | Protocol | Owner | Notes |
|---|---|---|---|
| TCP 443 | TLS | the front door of the Node (SDN-29) | One front door peeks the first bytes (`MSG_PEEK`), routes by SNI and ALPN, and hands the socket to its owner with `WSADuplicateSocketW`; nothing is proxied after the handoff. Owners: the new protocol over TLS (the Node), the web UI and the API of the Controller (the metrics are `/api/v1/metrics` on the same port), the control stream of the Nodes (ALPN `ranz-control/1`), and ACME and DoH where they are used. |
| UDP 443 | QUIC | msquic, in the Node | QUIC only, routed by ALPN inside one listener. Not shared with other protocols. |
| TCP 80 | HTTP | the HTTP listener | Off by default. It answers exactly two things: the redirect to HTTPS and ACME HTTP-01 (ADR-0020). Where HTTP.sys already holds port 80, for example under IIS, it registers through HTTP.sys URL reservations instead of binding the port itself. |
| TCP 5555 | TLS | the same owners as 443 | The fallback when 443 is taken by another program: the Controller and the Node log it and report it as a Capability (ADR-0035). |
| TCP 443, or the `listen` setting | TLS 1.3 (REALITY) | the sidecar `ranz mimic`, server role (CORE-P2-1) | Only on a Node that carries the mimicry transport for a network that fingerprints and probes (ADR-0023). It binds its own address, TCP 443 by default, and does not take its sockets from the front door yet, so on a Node whose front door holds 443 it needs an address of its own. A connection that is no Ranz client is spliced to the decoy site, and the ACME service that issues the certificate of an own decoy validates through this port (TLS-ALPN-01). |
| UDP, not a fixed number | Noise over UDP, ICE | the ICE socket of a Node | One UDP socket per Node carries all its ICE sessions to peers. A Node behind a home gateway asks it for a public port with PCP, NAT-PMP or UPnP. |
| UDP, set in the Node resource | the relay protocol | a Node with the relay Role | Only on a Node that runs a Relay. |

## On the LAN or fabric side only

| Port | Protocol | Owner | Notes |
|---|---|---|---|
| TCP 179 | BGP | the sidecar `ranz bgp` (GoBGP) | Peers with the operator's own routers. Started only when the `Bgp` setting names peers. |
| UDP 4789 | VXLAN | the VXLAN module of the Node (SDN-62) | Toward a fabric or a sensor. The Node is a VTEP. |
| UDP 6081, configurable | Geneve | the VXLAN module of the Node (SDN-71) | Toward a fabric, OVN or NSX that uses Geneve instead of VXLAN. The Node is a tunnel endpoint of Geneve. |
| UDP 67 and 68 | DHCP | the DHCP responder of the Node (SDN-43) | Only on an L2 Network whose responder is on, and only while no DHCP server of its bridged LAN answers. The responder is a member of the switch of the Network with a MAC address of its own and opens no socket of the host: it answers the clients' port 68 from port 67 and probes the LAN for a server from port 68. |
| 53 | DNS | overlay DNS (SDN-11, planned) | Inside the overlay and the NRPT rules of the host. |
| TCP 9821 | the traffic test | `ranz test throughput -listen`, started by hand (SDN-53) | Only while a test runs, on the address that it is given. `docs/first-test.md` uses it between two PCs. |

## Outgoing only

| Destination | Protocol | Used for |
|---|---|---|
| a STUN server, UDP 3478 by default | STUN | the reflexive address in ICE |
| the home gateway | PCP, NAT-PMP, UPnP IGD | the public port of the ICE socket (standard ports of those protocols; Ranz sets none) |
| the ACME CA | HTTPS | certificates (SDN-45, and the own decoy site of `ranz mimic`) |
| the site that a borrow decoy names (the host and port of its `dest`) | TCP | the mimicry sidecar splices a connection that is no Ranz client to it, so that a prober sees the real certificate of that site; the sidecar holds no key of it (CORE-P2-1) |
| the Hanzcodes activation service | HTTPS | online activation and the Enterprise key (SEC-6, SEC-7) |
| the operator's receivers, port in the URL | HTTPS webhook, OTLP over HTTP, IPFIX over UDP or TCP, syslog over UDP or TCP | events, metrics, flow records and audit export (SDN-16, SDN-49) |

## Inside the host and between Controller members

| Address | Protocol | Notes |
|---|---|---|
| `127.0.0.1:4001` | rqlite HTTP | The Controller's store. |
| `127.0.0.1:4002` | rqlite Raft | In a cluster of 3 or 5 members, `-rqlite-raft` must be an address that the other members reach (or `-rqlite-raft-adv` names one): open it between the members only. |
| `-api-listen`, `-control-listen`, `-http-listen` of `ranz controller` | HTTP or TLS | Development ports and the plain port 80; all off by default. |
| `127.0.0.1`, a port that the system gives (`decoy.listen`) | HTTPS | The own decoy site of `ranz mimic`, which only its REALITY listener reaches: the setting takes loopback addresses only. |
| named pipes | JSON lines, handoff messages and streams | The pipe of the BGP sidecar, the handoff pipes of the front door's owners, and the control pipe and the data pipes of the mimicry sidecar (JSON lines, then one pipe connection for each inner stream). Local, not network ports. |

## Firewall summary

- Open to the internet: TCP 443 and UDP 443. Add TCP 80 only when ACME HTTP-01 or the redirect is wanted.
- Between Controller cluster members: the Raft port, on a private network.
- On a Node that peers with a fabric or routers: TCP 179 and UDP 4789 (UDP 6081 for a fabric of Geneve) to those peers, on the LAN side.
- Nothing else needs to be open for incoming connections.

A new feature that needs a port adds a row to this page, and prefers an owner behind TCP 443 or UDP 443 over a port of its own.
