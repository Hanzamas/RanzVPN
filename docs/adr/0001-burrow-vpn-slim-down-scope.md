# ADR-0001: Burrow VPN 0.1 slim-down scope

**Status:** Accepted (2026-10-10, Hilmi: "konfirmasi")

## Context

The fork started as a full copy of SoftEther VPN (about 290k lines of C in `src/Cedar` and `src/Mayaqua`, about 610k lines of text in the whole repository). The maintainer wants to build on the native SE-VPN protocol on Windows only and has no local toolchain; GitHub Actions is the only build and test loop.

The scope was settled in a grilling session and published as the spec issue [Hanzamas/SoftEtherVPN#1](https://github.com/Hanzamas/SoftEtherVPN/issues/1) with twenty tickets (#2 to #21) under it. This ADR only records that the spec exists and what it fixes; it does not repeat it.

## Decision

The spec in issue #1 is the authoritative scope for the slim-down phase. In one sentence: keep only the native SE-VPN protocol (with VPN over ICMP/DNS and UDP Acceleration), Windows 10 / Server 2016 and later on x64 and arm64, the headless executables, no cloud dependencies, no GUI, no JSON-RPC, no foreign protocols; add a standalone MS-CHAPv2 helper module and an optional STUN client; rename to Burrow VPN 0.1 by Hanzcodes; one branch, one commit per ticket, each kept green by the Windows workflow, one pull request ([#22](https://github.com/Hanzamas/SoftEtherVPN/pull/22)).

Removal means deletion, not stubbing. Error codes and auth-type constants are not renumbered.

## Consequences

- Every later architecture decision (ADR-0002 onward) assumes the slimmed tree as its starting point, not upstream SoftEther.
- Upstream merges are abandoned (hard fork); security fixes are cherry-picked by hand.
- The spec itself is amended through the issue tracker, not here. Scope changes decided later are recorded as separate ADRs and as tickets: removing `vpnclient` is ADR-0012 and ticket #23.
