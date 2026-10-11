# ADR-0005: Transport stack: QUIC as primary, Trojan-style TLS/TCP fallback, Noise-style end-to-end session, CDN path, stealth sidecar

**Status:** Proposed. Hilmi asked "putuskan mana yang better"; this is the decision as made by the assistant. Hilmi moved on to the next topic without objecting and without explicit agreement.

## Context

SoftEther's "SSL-VPN" is a TLS stream with an HTTP-looking handshake (`POST /vpnsvc/connect.cgi` plus a watermark JPEG) followed by a custom framing, several TCP connections per session with a half-duplex trick, and a separate custom UDP Acceleration channel with its own key exchange. It is not real HTTP, it is trivially fingerprinted, and it reimplements what QUIC provides.

msquic implements QUIC over UDP only; it does not do TCP. Networks that block UDP exist (offices, some ISPs), so a TCP path is still required. CDNs such as Cloudflare proxy only HTTP-shaped traffic and terminate TLS at the edge.

## Decision

| Layer | Choice | Reason |
|---|---|---|
| Session (inside every transport) | Noise-IK style handshake (X25519 with hybrid ML-KEM), AEAD, data frames (Ethernet frames for L2 networks, IP packets for L3 networks, per ADR-0014) plus a control stream, keepalive | end-to-end encryption independent of the transport, needed because CDNs terminate TLS; 1-RTT |
| UDP | **QUIC via msquic** (OpenSSL backend), DATAGRAM frames for data, listener presented as a **real HTTP/3 server** with a real certificate (Hysteria2 model, BBR congestion control, not Brutal), optional port hopping | fastest, connection migration, 0-RTT |
| TCP | **TLS 1.3 on 443**, Trojan model: a real website behind it (http.sys), authentication in the first bytes after TLS, failed authentication is served the website; ECH on by default; optional ClientHello splitting on the client | gets through UDP-blocked networks; probers see an ordinary site |
| CDN | **WebSocket** over TLS for the TCP leg plus **Cloudflare Tunnel** at the origin; an XHTTP-style request-split transport for the HTTP/3 leg later | for when the server's IP is blocked |
| Tier-3 censorship | sidecar process running Xray or sing-box (REALITY, XHTTP, AnyTLS) in front of the core over loopback | those projects track the GFW weekly; the core does not |
| Client fallback order | QUIC, then TLS/TCP, then WebSocket/CDN, raced happy-eyeballs style | automatic |
| Legacy SE-VPN | separate listener in the slim fork during the transition only | not part of the new core |

Licensing: Hysteria is MIT, Xray-core is MPL-2.0 (file-level copyleft, may be linked or ported with attribution), **sing-box is GPLv3** and so is AnyTLS; sing-box code must stay a separate process and must not be copied into the Apache-2.0 fork.

## Consequences

- Dropped from SoftEther: multi-TCP connections and half-duplex, custom UDP Acceleration, cloud NAT-T, the watermark, PACK as the session wire format, R-UDP.
- Kept as ideas: getting through 443, looking like HTTPS, aggressive fallback.
- Double encryption (Noise inside TLS/QUIC) is accepted; with AES-NI its cost is negligible, and it is what makes the CDN path safe.
- The TLS stack must allow ECH and control over the ClientHello (ADR-0007).
- The censorship tiers and client-side DPI evasion options are detailed in ADR-0006.
