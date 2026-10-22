# ADR-0015: NAT traversal, P2P and relay

**Status:** Accepted (2026-10-11, Hilmi: "gas masukin itu")

## Context

Every node must be able to reach every other node it is allowed to talk to (hub-to-user, hub-to-hub, P2P; ADR-0011, ADR-0014), most of them behind NAT. SoftEther solved this with its own NAT-T rendezvous service and R-UDP, both removed by the slim-down, and with the hub relaying every session.

An external suggestion Hilmi pasted said: do not write port prediction yourself, use libjuice or libnice (ICE) or pion/ice; relay fallback is mandatory; try direct first, then port prediction, then relay. The assistant agreed in principle and corrected two details: ICE is not port prediction (it does not solve symmetric NAT), and a sequential direct, then prediction, then relay order makes every new peer pair wait; relay-first with background upgrade is faster and simpler.

## Decision

1. **ICE via libjuice** (C, MIT, CMake, builds on Windows, the ICE agent used by libdatachannel): host and server-reflexive (STUN) candidates, connectivity checks, keepalives. Not libnice (GLib dependency, LGPL). pion/ice only if a Go sidecar exists for other reasons.
2. **ICE is not port prediction; both are in scope.** ICE (libjuice) handles cone NATs. For symmetric NAT (carrier-grade NAT, some offices) the node additionally runs its own **port prediction and birthday-paradox hole punching** in the Tailscale style, so symmetric-NAT peer pairs also get a direct path when the NAT behaviour allows it (Hilmi, 2026-10-21: "gw mau 2 ini"). This is Ranz code on top of libjuice's candidates, not deferred; the relay remains the fallback when it fails.
3. **Relay is mandatory, is Ranz's own, and is self-hosted.** A stateless `relay` role of the node binary speaks the same QUIC / TLS-443 session as the direct path, is policy-aware, and shares one code path with the direct path (this is what the SoftEther hub already does for every session). Any node with a public address can be a relay: a VPS, a home server with a mapped port, or a hub; the control plane lists the relays of a deployment and nodes pick by latency. TURN/coturn is optional for using third-party relay infrastructure, not the baseline: TURN is WebRTC-shaped (per-peer allocations, UDP-centric, short-term credentials).
4. **Relay-first, upgrade in the background.** A new peer pair comes up through the relay in one round trip; ICE runs in the background; traffic switches to the direct path once it is validated, and falls back to the relay automatically when the direct path dies. Not a sequential direct, then prediction, then relay wait.
5. **Port mapping on home gateways** via PCP, NAT-PMP and UPnP using libplum (same author as libjuice, MIT), as Tailscale's portmapper does, so nodes behind home routers obtain a public port without hole punching.
6. **Signalling:** ICE candidates are exchanged through the control plane and signed with the node keys; relays verify node identity and rate-limit.
7. **Path switching:** one QUIC connection per path (relay, direct); the Noise/session layer above them (ADR-0005) moves between paths. Do not rely on QUIC connection migration across the relay.

## Consequences

- New dependencies: libjuice and libplum (both MIT).
- A `relay` role in the node binary (ADR-0011), stateless, horizontally scalable.
- Control-plane messages for candidate exchange and relay assignment.
- Metrics on the direct-versus-relay ratio and on port-prediction success per deployment, for capacity planning and for tuning the prediction window.
- Port prediction and birthday-paradox punching are Ranz's own code (libjuice provides candidates and checks, not this); they need the control plane to coordinate timing between the two peers.
- STUN servers are needed for server-reflexive candidates; the optional `StunServer` setting from the slim-down spec (ticket #20) is the forerunner of this, and the control plane can point nodes at Ranz-operated or public STUN servers per deployment.

## Amendment 2026-10-21: libjuice and libplum are MPL-2.0, not MIT

Correction of fact (Hilmi: "ya ya ya semua"). Decision 1, decision 5 and the first consequence call libjuice and libplum MIT. Both are MPL-2.0, as the licence facts of 2026-10-21 in ADR-0036 record.
- **MPL-2.0 is file-level copyleft.** It is fine for the proprietary product as long as the library files we modify are published; Ranz's own files stay proprietary (ADR-0036 decision 6).
- **The libraries stay:** libjuice for ICE (decision 1) and libplum for port mapping (decision 5).
