# ADR-0023: Security model, anti-censorship, and the traffic-mimicry sidecar

**Status:** Accepted (2026-10-13, from the grilling). Refines the threat model and tier design of ADR-0006 and the transport of ADR-0005 for the new core (ADR-0022), and records the mimicry transport as a phase-2 Go sidecar. Facts behind the decisions: `facts-tls-mimicry.md`, `facts-cng-schannel.md`.

## Context

ADR-0005 chose a QUIC-primary transport with a Trojan-style TLS/TCP 443 fallback and a Noise session layer; ADR-0006 split censorship circumvention into tiers and put anything that needs ClientHello control into a tier-3 sidecar, because Schannel (ADR-0007) gives the core the fingerprint of ordinary Windows software but no control over the ClientHello shape, GREASE, extension order or ECH. The grilling fixed the concrete security properties of the new core, what v1 must defeat versus what is only designed-for now, and the exact shape of the mimicry sidecar once the research (`facts-tls-mimicry.md`) confirmed that the mature mimicry libraries (uTLS, uQUIC, REALITY) are Go and that native Schannel/msquic cannot shape a ClientHello.

## Decision

### Threat model

- **v1 defeats commercial DPI that fingerprints VPN protocols:** Ranz traffic is indistinguishable from ordinary HTTPS (the Schannel/msquic fingerprint of ADR-0007), so protocol-classification DPI has nothing to match.
- **Nation-state resistance** (active probing, SNI blocking, ML classification) is **designed for now and fully enabled in phase 2** through the mimicry sidecar below. v1 does not promise to defeat a GFW-class adversary.

### Core security properties

1. **Encryption layering: Noise inside, TLS/QUIC outside.** The inner stream stays Noise-encrypted even if the outer TLS is opened (by a CDN, a decrypting middlebox, or a prober that completes the TLS handshake). Double encryption is accepted; with AES-NI its cost is negligible and it is what makes the CDN path safe (ADR-0005).
2. **A pluggable transport interface is defined now** (dial / listen / stream read-write), even though v1 ships only QUIC and TLS-443. Later transports — mimicry, DoH, DoT, CDN — plug into it without touching the session layer.
3. **Secure by default.** A fresh install uses an encrypted transport (QUIC or TLS, with Noise inside), never plaintext, and refuses weak ciphers.
4. **Forward secrecy.** Ephemeral keys per session (Noise IK) plus periodic rekey for long-lived sessions.
5. **Key separation.** The Noise identity key lives in a CNG KSP (ADR-0022); the TLS certificate lives in the Windows certificate store; the mimicry sidecar's authentication keys are separate again. A compromise of one does not yield the others.

### The mimicry transport is a phase-2 Go sidecar

Native Schannel and msquic cannot shape a ClientHello, and the mature libraries that can (uTLS, uQUIC, REALITY) are Go. The rule is **native for the ordinary mode, a Go library sidecar for mimicry, because native cannot do it** — not a reimplementation of those libraries in C.

- **Data path: a full proxy.** The sidecar terminates the mimicry transport and forwards the inner stream to the core over a local named pipe. That is one localhost hop; the mimicry path is a fallback, not the hot path, so the extra hop is acceptable.
- **First transport: REALITY (server) + uTLS (client) over TCP 443.** uQUIC comes later.
- **ClientHello fingerprint: mimic a browser, default Edge** (the most natural fingerprint from a Windows box); Chrome and Firefox are selectable per link. uTLS is pinned and bumped per major browser release, with a CI reminder so the parrot does not go stale.
- **ClientHello / SNI fragmentation** into several TCP segments is a **client toggle** (useful against SNI-keyword DPI that does not reassemble the right layer).
- **QUIC disguised as HTTP/3** (ALPN `h3`, Chrome-like transport parameters) where msquic allows it. Exact QUIC-Initial shaping needs a patched msquic; that is a phase-2 detail, recorded, not promised for the first mimicry release.
- **Active-probing resistance (REALITY-style):** a connection that is not a valid Ranz handshake is forwarded to a real website, so a prober sees an ordinary site, not a VPN.
- **Decoy, two configurable modes:**
  1. **Own decoy landing page plus a real ACME certificate** (default). This is the same page the admin surface serves to non-allowlisted clients (ADR-0021).
  2. **Borrow-a-big-site relay (REALITY):** probers are spliced to the real site and see its real certificate; no private key is ever taken. Caveat recorded: a big-site SNI resolving to a random VPS IP is itself a signal, so the destination must be plausibly co-located.
- **Traffic-shape padding** (packet size and timing, against TLS-in-TLS length patterns) is an **option in phase 2**.
- **CDN fronting** (Cloudflare, WebSocket / HTTP2) is a **last-resort path in phase 2**, for when the server's IP is blocked.

## Consequences

- v1 is honest about its reach: indistinguishable-from-HTTPS against commercial DPI, with the GFW-class defences present in design and switched on in phase 2. There is no claim of being undetectable; the design leans on several transports, fallbacks and IP rotation (ADR-0006).
- GPLv3 and MPL components (REALITY is MPL-2.0; sing-box and AnyTLS are GPLv3) stay in a **separate process** and are not copied into the Apache-2.0 fork (ADR-0005). The named-pipe boundary to the Go sidecar is also the licence boundary.
- Keeping ClientHello control in the sidecar means the core's TLS stack stays Schannel-only (ADR-0007), with the OS fingerprint as the camouflage for tiers 1 and 2; only tier 3 pays the cost of the Go sidecar.
- The decoy page is shared between the admin access-control rule (ADR-0021) and the active-probing path, so a single real site (own page or borrowed) covers both.
- ECH remains out of the core (Schannel has no ECH) and a per-deployment sidecar choice, because in hostile networks the presence of ECH is itself a flag (ADR-0006, ADR-0007).
