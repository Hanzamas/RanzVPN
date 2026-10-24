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
| UDP, not a fixed number | Noise over UDP, ICE | the ICE socket of a Node | One UDP socket per Node carries all its ICE sessions to peers. A Node behind a home gateway asks it for a public port with PCP, NAT-PMP or UPnP. |
| UDP, set in the Node resource | the relay protocol | a Node with the relay Role | Only on a Node that runs a Relay. |

## On the LAN or fabric side only

| Port | Protocol | Owner | Notes |
|---|---|---|---|
| TCP 179 | BGP | the sidecar `ranz bgp` (GoBGP) | Peers with the operator's own routers. Started only when the `Bgp` setting names peers. |
| UDP 4789 | VXLAN | the VXLAN module of the Node (SDN-62) | Toward a fabric or a sensor. The Node is a VTEP. |
| UDP 67 and 68 | DHCP | the DHCP responder of the Node (SDN-43, in progress) | Only on an L2 Network whose bridged LAN has no DHCP server. |
| 53 | DNS | overlay DNS (SDN-11, planned) | Inside the overlay and the NRPT rules of the host. |

## Outgoing only

| Destination | Protocol | Used for |
|---|---|---|
| a STUN server, UDP 3478 by default | STUN | the reflexive address in ICE |
| the home gateway | PCP, NAT-PMP, UPnP IGD | the public port of the ICE socket (standard ports of those protocols; Ranz sets none) |
| the ACME CA | HTTPS | certificates (SDN-45) |
| the Hanzcodes activation service | HTTPS | online activation and the Enterprise key (SEC-6, SEC-7) |
| the operator's receivers, port in the URL | HTTPS webhook, OTLP over HTTP, IPFIX over UDP or TCP, syslog over UDP or TCP | events, metrics, flow records and audit export (SDN-16, SDN-49) |

## Inside the host and between Controller members

| Address | Protocol | Notes |
|---|---|---|
| `127.0.0.1:4001` | rqlite HTTP | The Controller's store. |
| `127.0.0.1:4002` | rqlite Raft | In a cluster of 3 or 5 members, `-rqlite-raft` must be an address that the other members reach (or `-rqlite-raft-adv` names one): open it between the members only. |
| `-api-listen`, `-control-listen`, `-http-listen` of `ranz controller` | HTTP or TLS | Development ports and the plain port 80; all off by default. |
| named pipes | JSON lines and handoff messages | The pipe of the BGP sidecar and the handoff pipes of the front door's owners. Local, not network ports. |

## Firewall summary

- Open to the internet: TCP 443 and UDP 443. Add TCP 80 only when ACME HTTP-01 or the redirect is wanted.
- Between Controller cluster members: the Raft port, on a private network.
- On a Node that peers with a fabric or routers: TCP 179 and UDP 4789 to those peers, on the LAN side.
- Nothing else needs to be open for incoming connections.

A new feature that needs a port adds a row to this page, and prefers an owner behind TCP 443 or UDP 443 over a port of its own.
