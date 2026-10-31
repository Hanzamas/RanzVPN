# Ports and protocols

What an installation of the new core opens, uses and speaks, by plane. The decisions are in ADR-0020 (listener defaults), ADR-0035 (the front door), ADR-0015 (relay and peers), ADR-0022 and ADR-0026 (the Controller cluster). The Legacy protocols (SE-VPN compat, OpenVPN, L2TP, SSTP, IKEv2, EtherIP, L2TPv3, the industrial gateways) are postponed and are not listed. WireGuard is not one of them any more: the WireGuard Devices of a gateway Node (SDN-80, spec #374) took its place, and their port is listed.

Publicly a Node needs only **TCP 443 and UDP 443** open to the internet (ADR-0035); a gateway of WireGuard Devices needs its WireGuard port too, and a mimic server the TCP port of its `mimic` section, which is not the port of its front door, and with the Hysteria mode a UDP port of its own. Everything else is optional, on the LAN side, outgoing only, or inside the host.

## Open to the internet

| Port | Protocol | Owner | Notes |
|---|---|---|---|
| TCP 443 | TLS | the front door of the Node (SDN-29) | One front door peeks the first bytes (`MSG_PEEK`), routes by SNI and ALPN, and hands the socket to its owner with `WSADuplicateSocketW`; nothing is proxied after the handoff. Owners: the new protocol over TLS (the Node), the web UI and the API of the Controller (the metrics are `/api/v1/metrics` on the same port), the control stream of the Nodes (ALPN `ranz-control/1`), and ACME and DoH where they are used. The Listener resource of a Node (SDN-45) sets the port and the certificate, and a Node without one listens on neither port of its own. TLS 1.3 only for the new protocol and the control stream, TLS 1.2 and 1.3 for the web UI and the API. |
| UDP 443 | QUIC | msquic, in the Node | QUIC only, routed by ALPN inside one listener. Not shared with other protocols. The port of the Listener resource, with its certificate. |
| TCP 80 | HTTP | the HTTP listener | Off by default. It answers exactly two things: the redirect to HTTPS and ACME HTTP-01 (ADR-0020). Where HTTP.sys already holds port 80, for example under IIS, it registers through HTTP.sys URL reservations instead of binding the port itself. On a Node whose Listener takes its certificate from ACME, `ranz acme` answers the HTTP-01 challenge on the `httpPort` of the Listener (80 by default) while a run of it waits for the validation. |
| TCP 5555 | TLS | the same owners as 443 | The fallback when 443 is taken by another program: the Controller and the Node log it and report it as a Capability (ADR-0035). |
| TCP 443, or the `listen` field of the `MimicServer` setting, which an operator declares in the `mimic` section of the Listener resource of the Node (SDN-94) | TLS 1.3 (REALITY) | the sidecar `ranz mimic`, server role (CORE-P2-1), which the mimic transport of the Node starts when it listens (CORE-P2-6) | Only on a Node that carries the mimicry transport for a network that fingerprints and probes (ADR-0023). The sidecar listens on an address of its own, and the front door of the same Node is another listener, so the sidecar and the front door use different addresses: the `listen` of the `mimic` section is an IP address or none and a port from 1 to 65535, and the Controller refuses a section whose port is the TCP port of the front door of the same Listener. The front door does not hand the sidecar connections yet (handing them over by their server name is a ticket of its own), so on a Node whose front door holds 443 the sidecar takes another port, which is open to the internet beside TCP 443. The section holds the address, the server names, the decoy and the clock tolerance, and no key and no short id: the Node makes the key of its server, and the Controller makes the short id and gives each client its link. A connection that is no Ranz client is spliced to the decoy site, and the ACME service that issues the certificate of an own decoy validates through this port (TLS-ALPN-01). |
| UDP, the `listen` of the `hysteria` part of the `MimicServer` setting | QUIC and HTTP/3 (Hysteria 2) | the sidecar `ranz mimic`, server role, in its Hysteria mode (CORE-P2-4), beside its REALITY listener | Off by default: only on a mimic server whose setting has a `hysteria` part, for the links that lose so many packets that QUIC with BBR gets little through (ADR-0023 amendment of 2026-10-15). The address is required and is never UDP 443 of the Node, which the QUIC of its Listener (msquic) holds. The listener answers an ordinary HTTP/3 client as the own decoy site does, with its landing page and its certificate, and takes the streams of a client only when it presents one of the secrets of the setting; with the optional Salamander key no packet of the mode parses as QUIC. Brutal, the congestion control of the mode, takes an explicit rate for each link (the `brutal` rates of a link of the `MimicClient` setting; the link uses BBR without them) and sends at that rate whatever the link loses: it is unfair to the other traffic of the link, so give a link the rate that it carries and no more, and leave Brutal off on a link that others share. The `mimic` section of a Listener resource does not carry the mode yet. |
| TCP 8443 and UDP 8443, or the `QtipPort` setting | QTIP: QUIC with a TCP header instead of a UDP one, over XDP | msquic, in the Node, with the `Qtip` setting (CORE-S7-2, #83) | Off by default, and only on a server Node on Windows Server x64 with the XDP runtime, for the links to other server Nodes that run it (relay to relay, gateway to relay, a cascade between servers), on networks that treat TCP better than UDP. A QTIP listener reserves both the TCP and the UDP port of its address, and msquic does not let a QTIP and a non-QTIP listener share a port, so QTIP has a port of its own. From the network it takes plain QUIC on its UDP port as well; msquic takes the packets of a QTIP listener from XDP only, so a QUIC client on the same host does not reach it over the loopback. It does not replace TLS-443: a firewall or DPI that follows TCP may break it, and a peer without XDP cannot use it. The packets that XDP redirects bypass Windows Firewall and WFP (ADR-0018), so the rules for this port belong in front of the host. `ranz install` opens no rule for it. |
| UDP, not a fixed number | Noise over UDP, ICE | the ICE socket of a Node | One UDP socket per Node carries all its ICE sessions to peers. A Node behind a home gateway asks it for a public port with PCP, NAT-PMP or UPnP. |
| UDP, set in the Node resource | the relay protocol | a Node with the relay Role | Only on a Node that runs a Relay. |
| UDP 51820, or `wireguard.port` of the Node resource | WireGuard | the WireGuard interface of a gateway Node (WireGuardNT, SDN-80) | Only on a Node that is the gateway of a WireGuard Device, and only while it is one. The stock WireGuard clients of its Devices reach it there, at the DNS name `wireguard.endpoint` of the Node, which their configuration names. Not shared with UDP 443. Behind a NAT it needs a port forward by hand. |

## On the LAN or fabric side only

| Port | Protocol | Owner | Notes |
|---|---|---|---|
| TCP 179 | BGP | the sidecar `ranz bgp` (GoBGP) | Peers with the operator's own routers. Started only when the `Bgp` setting names peers. A second one peers with the other Nodes of each VRF of the Node whose peering is `bgp` in the standard mode (SDN-77): started only while the Node is a member of such a VRF, it listens on the address of the tunnel endpoint of the Node only and takes a session only from the address of a peer that the Controller named. |
| UDP 4789 | VXLAN | the VXLAN module of the Node (SDN-62) | Toward a fabric or a sensor. The Node is a VTEP. |
| UDP 6081, configurable | Geneve | the VXLAN module of the Node (SDN-71) | Toward a fabric, OVN or NSX that uses Geneve instead of VXLAN. The Node is a tunnel endpoint of Geneve. |
| UDP 67 and 68 | DHCP | the DHCP responder of the Node (SDN-43) | Only on an L2 Network whose responder is on, and only while no DHCP server of its bridged LAN answers. The responder is a member of the switch of the Network with a MAC address of its own and opens no socket of the host: it answers the clients' port 68 from port 67 and probes the LAN for a server from port 68. |
| 53 | DNS | overlay DNS (SDN-11, planned) | Inside the overlay and the NRPT rules of the host. |
| TCP 9821 | the traffic test | `ranz test throughput -listen`, started by hand (SDN-53) | Only while a test runs, on the address that it is given. `docs/first-test.md` uses it between two PCs. While it serves, the test lets its port in to itself in Windows Firewall, a rule of the group `Ranz VPN`, and removes the rule when it stops. |

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
| named pipes | JSON lines, handoff messages and streams | The pipe of each BGP sidecar, the handoff pipes of the front door's owners, and the control pipe and the data pipes of the mimicry sidecar (JSON lines, then one pipe connection for each inner stream). Local, not network ports. |

## Firewall summary

- Open to the internet: TCP 443 and UDP 443. Add TCP 80 only when ACME HTTP-01 or the redirect is wanted.
- Between Controller cluster members: the Raft port, on a private network.
- On a Node that peers with a fabric or routers: TCP 179 and UDP 4789 (UDP 6081 for a fabric of Geneve) to those peers, on the LAN side. On a Node of a VRF whose peering is `bgp` (SDN-77): TCP 179 between its tunnel endpoint and the ones of the other Nodes of the VRF, on the network that the operator trusts.
- On a gateway of WireGuard Devices: its WireGuard port, UDP 51820 unless the Node sets `wireguard.port`, open to the internet or forwarded to it by the NAT in front of it.
- On a mimic server (a Node whose Listener has a `mimic` section, SDN-94): the TCP port of that section, open to the internet or forwarded to it. It is the address of the sidecar, never the one of the front door, so a firewall that lets in TCP 443 for the front door does not open it. With the Hysteria mode (CORE-P2-4): the UDP port of the `listen` of its `hysteria` part as well, which is never UDP 443.
- On a server Node that runs QTIP (the `Qtip` setting): TCP 8443 and UDP 8443, or its `QtipPort`, to the other server Nodes that dial it.
- Nothing else needs to be open for incoming connections.

`ranz install` makes these rules in Windows Firewall itself, for the parts that it installs and nothing else (SDN-91): TCP 443 and UDP 443 for `ranz-node.exe`, and with `--controller` TCP 443 and 5555 for `ranz.exe`, the program of the Controller service, each in the Ranz folder under Program Files. They are inbound allow rules of every profile in the group `Ranz VPN` (`Get-NetFirewallRule -Group "Ranz VPN"` lists them). A second `ranz install` or an upgrade leaves the same rules: a rule that is there as it should be stays, and a rule of the group that no installed part needs goes. `ranz uninstall` removes every rule of the group. `ranz install` opens nothing else, so the WireGuard port of a gateway, the port of a `mimic` section, the UDP port of the Hysteria mode, TCP 80 and the ports of the LAN side stay the operator's, as does a firewall in front of the host.

A new feature that needs a port adds a row to this page, and prefers an owner behind TCP 443 or UDP 443 over a port of its own.
