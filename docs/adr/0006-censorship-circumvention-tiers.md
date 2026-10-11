# ADR-0006: Censorship circumvention is a tiered edge feature, not part of the core

**Status:** Proposed (assistant's recommendation; Hilmi asked for the discussion and for the viral Chinese protocols to be looked up, and did not confirm a tier).

## Context

Hilmi asked whether stealth is needed and whether REALITY, Hysteria, AnyTLS and similar protocols should be adopted. The threat model differs by deployment: Indonesia mostly blocks by DNS and SNI with little deep inspection; corporate networks block UDP and allow 443 only; China, Iran and Russia use machine-learning DPI, active probing, entropy checks and QUIC throttling. The original SE-VPN wire format is not stealthy today.

What the Chinese ecosystem teaches (ideas, not code): REALITY borrows a big site's SNI and certificate and relays unauthenticated probers to the real site; Hysteria2 is a real HTTP/3 server with authentication over an HTTP/3 request; AnyTLS adds a flexible padding scheme against TLS-in-TLS length patterns and is not yet production-grade; XHTTP splits a stream into ordinary HTTP requests so it passes CDNs; Trojan and NaiveProxy serve a real website to anyone who fails authentication; Shadowsocks 2022 is reported as detected by ML DPI as of 2026. The "Parrot is Dead" principle applies: imitating a complex protocol (Zoom, FaceTime) fails; being the real protocol and hiding data inside it works.

## Decision

1. **Tier 1 (ISP-level DPI, Indonesia):** client-side options that are cheap to implement in the core's TLS/TCP path: ECH on by default (OpenSSL 3.5 client), ClientHello segmentation ("SNI split") as an option, SNI omission where the server is ours. Fake-TTL tricks are not implemented (fragile).
2. **Tier 2 (looks like ordinary HTTPS/HTTP3):** the Trojan-style TLS/TCP listener and the HTTP/3-camouflaged QUIC listener from ADR-0005, each with a real certificate and a real website or HTTP/3 service behind it. Three fingerprints must be right: the ClientHello (JA3/JA4), the certificate, and length/timing patterns.
3. **Tier 3 (GFW-class):** a sidecar process (Xray or sing-box) in front of the core over loopback, providing REALITY, XHTTP via CDN and AnyTLS. Not reimplemented in the core.
4. The core itself stays plain: QUIC plus TLS/TCP. Stealth lives at the edge and is configurable per deployment.
5. ECH is default on for Indonesian deployments and off for hostile ones, because the presence of ECH is itself a flag there (Russia blocked Cloudflare ECH in 2024).

## Consequences

- No promise of being undetectable; the design relies on several transports, fallbacks and IP rotation.
- Licensing as in ADR-0005: GPLv3 components only as separate processes.
- Choosing Tier 2 or 3 rules out Schannel as the TLS stack (ADR-0007).
- Sources consulted during the discussion are listed in the discussion log.
