# ADR-0035: The front door on TCP 443 hands sockets to their owners; UDP 443 stays QUIC only

**Status:** Accepted (2026-10-20, from the SDN spec #176 that Hilmi filed; recorded by SDN-1, #177). Builds on the transport of ADR-0005 and ADR-0022 and the listener defaults of ADR-0020.

## Context

A node should need one line in a firewall: TCP 443 and UDP 443 open to the internet, and it should work where only 443 is allowed. Several owners want TCP 443: the new protocol's TLS fallback (ADR-0005), the web UI and the API, ACME, DoH, and in the Legacy phase SE-VPN, SSTP and OpenVPN over TCP in `ranz-compat` (ADR-0037). UDP 443 carries QUIC, the 10 Gbit/s path, which must not pay for a demultiplexer. Proxying bytes between processes would cost the TCP owners a copy on every packet. SoftEther's own port sharing logic in `main-oracle` is prior art for telling the protocols apart on one port.

## Decision

1. **Publicly a node needs only TCP 443 and UDP 443.**
2. **TCP 443: one front door.** The node accepts the connection, peeks the first bytes with `MSG_PEEK` (nothing is consumed), and routes it:
   - TLS by SNI and ALPN: the new protocol's TLS fallback, the web UI and the API, ACME, DoH, and in the Legacy phase SE-VPN and SSTP in `ranz-compat`;
   - non-TLS signatures, for example OpenVPN over TCP, by their first bytes.
3. **The front door hands the accepted socket to its owner process with `WSADuplicateSocketW`.** No bytes are proxied after the handoff, so sharing the port costs nothing after it.
4. **UDP 443: QUIC only, owned by msquic**, routed by ALPN inside one listener. WireGuard and OpenVPN over UDP use their own ports by default. Sharing UDP 443 with them is an opt-in demultiplexer in front of msquic, at a lower QUIC throughput. OpenVPN can always use TCP 443.
5. **Off 443 by nature:** IKE and IPsec (UDP 500 and 4500, ESP), EtherIP, GRE and L2TPv3 over IP (IP protocols 97, 47 and 115), DHCP (UDP 67 and 68), DNS (53), DoT and DoQ (853), ICMP.
6. **Industrial device ports and RADIUS stay on the LAN side of a gateway:** Modbus 502, DNP3 20000, IEC 104 2404, XOT 1998. Across the internet they travel inside the overlay on 443.
7. **Underlay:** a node with both IPv4 and IPv6 underlay tries the paths in parallel, keeps the fastest, and switches when it fails.

## Consequences

- Each owner of a TCP 443 protocol is a separate process that receives duplicated sockets; the front door itself holds no protocol state after the handoff.
- The VM CI job covers the TCP 443 front door with socket handoff (seam 3 of #45). SE-VPN through the front door is tested against the pinned `main-oracle` releases in the Legacy phase (SDN-L2, #208).
- The unified-management spec #224 adds a `Listener` resource for ports and certificates (SDN-45, #238) and a front-door DoS guard (SDN-46, #239).
- Tickets: SDN-29 (#205), SDN-L2 (#208), SDN-L5 (#211).
