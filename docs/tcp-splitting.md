# TCP splitting

TCP splitting is an opt-in mode of an L3 Network (CORE-P2-3, ADR-0022 amendment of 2026-11-01). It removes the TCP-over-TCP meltdown on the TLS-443 fallback: when UDP is blocked, a node reaches its peer over TCP 443, and an application's TCP connection inside that tunnel retransmits into a stalled outer TCP whenever the network loses a segment. With splitting, the tunnel carries no inner TCP segment, only the byte stream of the connection.

## What changes for an application

**An ACK means that the client node has the data.** The Windows TCP stack of the host terminates the application's connection on the node of that host, which then carries the bytes to the peer that the destination routes to. The application gets its acknowledgements from its own node, at once, not from the far end. A program that takes an ACK, or a successful `send`, as proof that the far end received the bytes is wrong under splitting; only an answer of the far end proves it.

**The far end sees the connection come from the node at the other end of the tunnel**, which opens it with an ordinary socket: the address that the far end sees is that node's, not the application's address in the Network.

What still maps end to end:

- **Connect:** the application's SYN waits until the far node reached the destination, so a connect succeeds only once the far end took the connection.
- **Refused:** a destination that refuses the connection resets the application's connect (`WSAECONNREFUSED`, `ECONNREFUSED`).
- **Timeout:** a destination that does not answer leaves the application's connect to time out, as without splitting.
- **Half-close and reset:** a half-close (`shutdown`) of either end reaches the other end after the bytes before it, and a reset of either end resets the other one. A tunnel that goes down resets the split connections that it carried.

## Turning it on

It is off by default. Set `tcpSplit` on an L3 Network of the Intent:

```json
{"kind": "Network", "name": "branch-lan", "spec": {"vrf": "corp", "ipv4Pool": "10.20.0.0/24", "tcpSplit": true}}
```

An L2 Network is refused: it carries Ethernet frames, which no node terminates. Every Node of the VRF gets the setting. A node splits the IPv4 TCP connections that its host opens from its address in the Network to a peer that it reaches over a Noise session (QUIC or TLS-443), and opens the connections that a peer splits from its address in the Network to their real destination. Every other packet takes the normal packet path: UDP, ICMP, IPv6, a Network without the setting, and a peer on the datagram path. The Networks page of the web UI shows which Networks split TCP.

The policy of the VRF judges each split connection by its SYN, at both nodes, as it judges a connection without splitting. The rate limits of a VRF and of a session profile do not count the byte stream of a split connection.
