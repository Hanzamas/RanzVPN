# ADR-0017: Roadmap: clean and stabilise the foundation before building the new core

**Status:** Accepted (2026-10-12). Hilmi: "core baru itu nanti ga sih fokus ini bersih bersih dan beres beres fondasi dl", and "gas" on the proposed order and seams.

## Context

The architecture discussion (ADR-0004 to ADR-0015) designed a new core: QUIC via msquic with a TLS/TCP 443 fallback and a Noise session layer, Schannel, Wintun for L3 and first-class L2, libjuice/libplum NAT traversal with an own relay, and one node binary with roles. In parallel the existing SoftEther code base is being slimmed (PR #22) and a safe cleanup sweep is specified (spec #24). The question was what comes first.

## Decision

The existing code base is cleaned and given a test harness before any new-core work starts. The order is:

1. Merge the slim-down, PR #22 (tickets #2 to #23).
2. Scope cuts that remove remaining unneeded features: the Layer 3 switch, and the WaterMark array moved from C source into hamcore.
3. The safe cleanup sweep, spec #24, with the one-time reformat as its last pass (ADR-0003 item 14).
4. The test harness in vpntest: in-process server driven through the admin RPC, vpncmd output against golden files, a cascade from the server to itself with frames passing between sessions, golden pack dumps per RPC structure, and lock/event/thread stress tests (ADR-0002 point 3).
5. Table-driven admin RPC and vpncmd marshalling (ADR-0002 as amended on 2026-10-12).
6. Structural refactor (god-file splits as pure moves, per-module API headers, ADR-0003 items 3 and 4) and the Windows-native runtime migration of Mayaqua (ADR-0016); these two may run in parallel because they touch different layers.
7. The new core, after its design has been stress-tested with a grilling session; it replaces the data path module by module (strangler), reusing Hub, Account, Sam, Logging and configuration.

Each step from 2 to 6 is its own spec; the harness is the single test seam for steps 5 and 6.

## Consequences

- The new core starts from a code base that is smaller, readable, and covered by golden outputs, so replacing the data path is verifiable.
- No new-core code lands before step 6 is done; prototypes, if any, live outside the main branch.
- The ADRs for the new core (0004 to 0015) remain the design reference and may be revised by the grilling session before step 7.
