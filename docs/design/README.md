# Design records

Architecture decision records live in `docs/adr/`; the reasoning behind them is in the discussion log here. Statuses: Accepted = Hilmi explicitly agreed; Proposed = recommended, not yet confirmed; Superseded = overridden by a later ADR; see each ADR's status line for nuances.

## Decision records

- [ADR-0001](../adr/0001-ranz-vpn-slim-down-scope.md) — Ranz VPN 0.1 slim-down scope: the spec is issue #1 (Accepted).
- [ADR-0002](../adr/0002-ci-only-verification-no-behaviour-changing-refactors.md) — CI is the only verification loop; no behaviour-changing refactors without a test harness (Accepted).
- [ADR-0003](../adr/0003-safe-cleanup-catalogue.md) — Catalogue of safe cleanups after the tickets (items 1, 3, 4 Accepted; the rest Proposed).
- [ADR-0004](../adr/0004-l3-core-with-wintun-l2-as-optional-service.md) — L3 core on Wintun, L2 as an optional service (Superseded by ADR-0014; analysis kept for L3 networks).
- [ADR-0005](../adr/0005-transport-stack-quic-tls-noise-cdn.md) — QUIC primary, Trojan-style TLS/TCP fallback, Noise-style session layer, CDN path, stealth sidecar (Proposed).
- [ADR-0006](../adr/0006-censorship-circumvention-tiers.md) — Censorship circumvention as a tiered edge feature (Proposed).
- [ADR-0007](../adr/0007-tls-stack-openssl-vs-schannel.md) — One TLS stack for the new core: Schannel and msquic+Schannel, OpenSSL dropped (Accepted; minimum OS Windows 11 / Server 2022).
- [ADR-0008](../adr/0008-windows-native-replacements.md) — Windows-native replacements for SoftEther's runtime (Proposed).
- [ADR-0009](../adr/0009-adapter-choice.md) — Adapters: Wintun for L3 (Accepted), TAP for L2 with Neo6 vs tap-windows6 open (Proposed), SeLow for bridging (Accepted).
- [ADR-0010](../adr/0010-routing-at-the-edge-no-in-daemon-bgp.md) — Routing by the OS, BGP only at the edge (Proposed).
- [ADR-0011](../adr/0011-single-node-binary-with-roles.md) — One node binary with roles and both data-path backends (Accepted with ADR-0014).
- [ADR-0012](../adr/0012-remove-vpnclient-from-slim-fork-keep-cascade.md) — Remove vpnclient from the slim fork, keep cascade (Accepted, ticket #23).
- [ADR-0013](../adr/0013-selow-stays-in-slim-fork-not-in-l3-core.md) — SeLow stays: Local Bridge in the fork, L2 bridging in the new product (Accepted).
- [ADR-0014](../adr/0014-dual-mode-networks-l2-first-class.md) — Dual-mode virtual networks, L2 switched first-class and L3 routed, one binary with both backends (Accepted).
- [ADR-0015](../adr/0015-nat-traversal-p2p-and-relay.md) — NAT traversal, P2P and relay: libjuice ICE, libplum port mapping, Ranz's own relay role, relay-first with background upgrade (Accepted).
- [ADR-0016](../adr/0016-windows-native-runtime-thin-inline-header.md) — Windows-native runtime for Mayaqua behind one thin inline header (`Lock(x)` stays readable), wrapper flip per primitive, semantics preserved, after the harness (Accepted).
- [ADR-0017](../adr/0017-roadmap-foundation-before-new-core.md) — Roadmap: slim-down, scope cuts, safe sweep, harness, table-driven RPC/vpncmd, structural refactor and Windows-native runtime, and only then the new core (Accepted).

## Discussion log

- [architecture-discussion.md](architecture-discussion.md) — the measured numbers, where the tangle is, the user-space performance ceiling, L2 versus L3 and the dual-mode correction, Windows-native replacements, adapters, transport and censorship landscape with sources, and the open items.
