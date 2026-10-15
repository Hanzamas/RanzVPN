# ADR-0005: Transport stack: QUIC as primary, Trojan-style TLS/TCP fallback, Noise-style end-to-end session, CDN path, stealth sidecar

**Status:** Accepted (2026-10-13, in the grilling; see the amendment at the end). Originally Proposed: Hilmi asked "putuskan mana yang better", this was the decision as made by the assistant, which he moved past without objecting or explicitly agreeing; the 2026-10-13 grilling confirmed it and moved the concrete new-core parameters into ADR-0022 and ADR-0023.

## Context

SoftEther's "SSL-VPN" is a TLS stream with an HTTP-looking handshake (`POST /vpnsvc/connect.cgi` plus a watermark JPEG) followed by a custom framing, several TCP connections per session with a half-duplex trick, and a separate custom UDP Acceleration channel with its own key exchange. It is not real HTTP, it is trivially fingerprinted, and it reimplements what QUIC provides.

msquic implements QUIC over UDP only; it does not do TCP. Networks that block UDP exist (offices, some ISPs), so a TCP path is still required. CDNs such as Cloudflare proxy only HTTP-shaped traffic and terminate TLS at the edge.

## Decision

| Layer | Choice | Reason |
|---|---|---|
| Session (inside every transport) | Noise-IK style handshake (X25519 with hybrid ML-KEM), AEAD, data frames (Ethernet frames for L2 networks, IP packets for L3 networks, per ADR-0014) plus a control stream, keepalive | end-to-end encryption independent of the transport, needed because CDNs terminate TLS; 1-RTT |
| UDP | **QUIC via msquic** (Schannel backend, ADR-0007), DATAGRAM frames for data, listener presented as a **real HTTP/3 server** with a real certificate (Hysteria2 model, BBR congestion control, not Brutal), optional port hopping | fastest, connection migration, 0-RTT; same QUIC fingerprint as Windows' own HTTP/3 |
| TCP | **TLS 1.3 on 443 via Schannel** (ADR-0007), Trojan model: a real website behind it (http.sys), authentication in the first bytes after TLS, failed authentication is served the website; optional ClientHello splitting on the client; no ECH in the core (sidecar only) | gets through UDP-blocked networks; probers see an ordinary site; ClientHello identical to ordinary Windows applications |
| TLS library | **Schannel** for TLS/TCP, **msquic + Schannel** for QUIC; OpenSSL/liboqs stay in the slim fork only | zero third-party crypto, OS fingerprint for free (ADR-0007) |
| CDN | **WebSocket** over TLS for the TCP leg plus **Cloudflare Tunnel** at the origin; an XHTTP-style request-split transport for the HTTP/3 leg later | for when the server's IP is blocked |
| Tier-3 censorship | sidecar process running Xray or sing-box (REALITY, XHTTP, AnyTLS) in front of the core over loopback | those projects track the GFW weekly; the core does not |
| Client fallback order | QUIC, then TLS/TCP, then WebSocket/CDN, raced happy-eyeballs style | automatic |
| Legacy SE-VPN | separate listener in the slim fork during the transition only | not part of the new core |

Licensing: Hysteria is MIT, Xray-core is MPL-2.0 (file-level copyleft, may be linked or ported with attribution), **sing-box is GPLv3** and so is AnyTLS; sing-box code must stay a separate process and must not be copied into the Apache-2.0 fork.

## Consequences

- Dropped from SoftEther: multi-TCP connections and half-duplex, custom UDP Acceleration, cloud NAT-T, the watermark, PACK as the session wire format, R-UDP.
- Kept as ideas: getting through 443, looking like HTTPS, aggressive fallback.
- Double encryption (Noise inside TLS/QUIC) is accepted; with AES-NI its cost is negligible, and it is what makes the CDN path safe. *(Superseded 2026-10-15 by ADR-0023: data is encrypted once by QUIC/TLS with Noise as a bound identity handshake; inner Noise encryption only on the CDN path.)*
- ECH and ClientHello control are not provided by the core's TLS stack (ADR-0007); they belong to the tier-3 sidecar (ADR-0006). Minimum OS for the new core is Windows 11 / Server 2022.
- The CDN path does not change the client's JA3: the censor on the client's network still sees the core's (Schannel) ClientHello; only the server side (anycast IP, certificate, JA3S) becomes Cloudflare's (ADR-0006).
- The censorship tiers and client-side DPI evasion options are detailed in ADR-0006.

## Amendment 2026-10-13: Accepted; new-core parameters moved to ADR-0022/0023

The 2026-10-13 grilling accepted this transport design and fixed the details that were left open here:

- **Status is now Accepted.**
- **AES-GCM only; ChaCha20-Poly1305 is off by default** in both Schannel and msquic (ADR-0022). The "Hysteria2 model" QUIC listener and the Trojan-style TLS/TCP 443 fallback are unchanged.
- The **session layer** is Noise_IK with X25519, SHA-256 and HKDF via CNG, with a CNG ML-KEM hybrid where the OS provides it; the parameters now live in ADR-0022.
- **msquic ships as the official signed `msquic.dll`** (Schannel build), pinned, x64 and arm64 (ADR-0022).
- The **tier-3 "stealth sidecar"** row is now specified concretely as the **Go mimicry sidecar** (REALITY + uTLS first, full-proxy over a local named pipe) in ADR-0023; the Xray/sing-box option remains a valid separate-process choice under the same licence boundary.
- The **pluggable transport interface** (dial / listen / stream read-write) is defined now so later transports plug in (ADR-0023), even though v1 ships only QUIC and TLS-443.
- The CDN/WebSocket path and the tier-3 sidecar land at **strangler step 7** (ADR-0022).
