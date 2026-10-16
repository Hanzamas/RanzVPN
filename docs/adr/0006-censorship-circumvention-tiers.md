# ADR-0006: Censorship circumvention is a tiered edge feature, not part of the core

**Status:** Accepted (2026-10-13, in the grilling; see the amendment at the end). Originally Proposed (assistant's recommendation; Hilmi asked for the discussion and for the viral Chinese protocols to be looked up, and did not confirm a tier); the 2026-10-13 grilling accepted the tiered design and fixed the threat model.

## Context

Hilmi asked whether stealth is needed and whether REALITY, Hysteria, AnyTLS and similar protocols should be adopted. The threat model differs by deployment: Indonesia mostly blocks by DNS and SNI with little deep inspection; corporate networks block UDP and allow 443 only; China, Iran and Russia use machine-learning DPI, active probing, entropy checks and QUIC throttling. The original SE-VPN wire format is not stealthy today.

What the Chinese ecosystem teaches (ideas, not code): REALITY borrows a big site's SNI and certificate and relays unauthenticated probers to the real site; Hysteria2 is a real HTTP/3 server with authentication over an HTTP/3 request; AnyTLS adds a flexible padding scheme against TLS-in-TLS length patterns and is not yet production-grade; XHTTP splits a stream into ordinary HTTP requests so it passes CDNs; Trojan and NaiveProxy serve a real website to anyone who fails authentication; Shadowsocks 2022 is reported as detected by ML DPI as of 2026. The "Parrot is Dead" principle applies: imitating a complex protocol (Zoom, FaceTime) fails; being the real protocol and hiding data inside it works.

## Decision

1. **Tier 1 (ISP-level DPI, Indonesia):** client-side options that are cheap to implement in the core's TLS/TCP path: ClientHello segmentation ("SNI split") as an option, SNI omission where the server is ours. ECH is **not** in the core (Schannel has no ECH, ADR-0007); accepted because Indonesian SNI blocking is domain-list based and the product's domain is not listed. Fake-TTL tricks are not implemented (fragile).
2. **Tier 2 (looks like ordinary HTTPS/HTTP3):** the Trojan-style TLS/TCP listener and the HTTP/3-camouflaged QUIC listener from ADR-0005, each with a real certificate and a real website or HTTP/3 service behind it. Three fingerprints must be right: the ClientHello (JA3/JA4), the certificate, and length/timing patterns.
3. **Tier 3 (GFW-class):** a sidecar process (Xray or sing-box) in front of the core over loopback, providing REALITY, XHTTP via CDN and AnyTLS. Not reimplemented in the core.
4. The core itself stays plain: QUIC plus TLS/TCP. Stealth lives at the edge and is configurable per deployment.
5. ECH, REALITY and uTLS-style fingerprint work live in the tier-3 sidecar only. In hostile networks the presence of ECH is itself a flag (Russia blocked Cloudflare ECH in 2024), so even there it is a per-deployment choice.
6. Tiers 1 and 2 rely on the core's TLS stack being **Schannel** (ADR-0007): the ClientHello and the QUIC fingerprint are those of ordinary Windows software, which is the camouflage.

## Correction recorded on 2026-10-11 (JA3 direction and Cloudflare facts)

An external analysis Hilmi pasted got the transport design and the Cloudflare origin leg right but the JA3 direction wrong. For the record:

- **JA3/JA4 is the fingerprint of the client's ClientHello.** The censor sits on the client's network and sees it there. Routing through Cloudflare does **not** change the client's JA3; what becomes Cloudflare's is the server side: the anycast IP, the certificate and the server-hello fingerprint (JA3S). Camouflage of the client therefore comes from the TLS stack in the client (Schannel, ADR-0007), not from the CDN.
- Through Cloudflare's reverse proxy ("orange cloud") there is **no end-to-end QUIC**: the client-to-edge leg may be HTTP/3 (QUIC) but only in HTTP-request form (the XHTTP pattern of POST uploads and streaming GET downloads); WebSocket at Cloudflare is HTTP/1.1 or HTTP/2 over TCP; the edge-to-origin leg is TCP. Raw UDP through Cloudflare needs Spectrum (Enterprise).
- Cloudflare's former "primarily HTML content" terms clause was removed in 2023. Heavy non-web traffic is not an automatic violation; the risk is throttling or termination for abuse-like volumes. Cloudflare Tunnel on the origin side is an intended use.

## Consequences

- No promise of being undetectable; the design relies on several transports, fallbacks and IP rotation.
- Licensing as in ADR-0005: GPLv3 components only as separate processes.
- Schannel is the core's TLS stack (ADR-0007); anything needing ClientHello control is sidecar-only.
- Sources consulted during the discussion are listed in the discussion log.

## Amendment 2026-10-13: Accepted, with the threat model and tier-3 sidecar fixed

The 2026-10-13 grilling accepted the tiered design and made it concrete (full detail in ADR-0023):

- **Status is now Accepted.**
- **Threat model split in two.** v1 defeats **commercial DPI that fingerprints VPN protocols** (traffic indistinguishable from ordinary HTTPS). **Nation-state resistance** (active probing, SNI blocking, ML classification, GFW-class) is **designed for now and fully enabled in phase 2**; v1 makes no claim against a GFW-class adversary.
- **Tier 3 is a Go mimicry sidecar.** Because native Schannel and msquic cannot shape a ClientHello and the mature libraries (uTLS, uQUIC, REALITY) are Go, the sidecar is a Go program: **REALITY (server) + uTLS (client) over TCP 443 first**, uQUIC later, a **full proxy** that forwards the inner stream to the core over a local named pipe. Browser fingerprint defaults to **Edge**, with Chrome and Firefox selectable per link; uTLS is pinned and bumped per browser release. This is ADR-0023; the Xray/sing-box option stays valid under the same separate-process licence boundary.
- **Active-probing resistance and two decoy modes** are added: (1) an own decoy landing page with a real ACME certificate (default, shared with the admin surface of ADR-0021), and (2) a borrow-a-big-site REALITY relay where probers are spliced to the real site and see its real certificate.
- **Tier 1 fragmentation** (ClientHello / SNI split across TCP segments) is a client toggle; **ChaCha20-Poly1305 stays off by default** (ADR-0022).
- The **pluggable transport interface** is defined now so mimicry, DoH, DoT and CDN transports plug in later (ADR-0023). Padding and CDN fronting are phase-2 options.
