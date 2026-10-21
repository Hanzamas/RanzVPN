# ADR-0001: Ranz VPN 0.1 slim-down scope

**Status:** Accepted (2026-10-10, Hilmi: "konfirmasi")

**Amended 2026-10-12:** the product name changed from Burrow VPN to Ranz VPN (Hilmi: "ganti ke ini Ranz VPN"). The rename is user-visible only, like the original one: executables, internal service names, hamcore.se2, the Cedar and Mayaqua modules and the SE-VPN wire signature are unchanged; the configuration file is ranz_server.config and the registry key Software\Hanzcodes\Ranz VPN.

## Context

The fork started as a full copy of SoftEther VPN (about 290k lines of C in `src/Cedar` and `src/Mayaqua`, about 610k lines of text in the whole repository). The maintainer wants to build on the native SE-VPN protocol on Windows only and has no local toolchain; GitHub Actions is the only build and test loop.

The scope was settled in a grilling session and published as the spec issue [Hanzamas/RanzVPN#1](https://github.com/Hanzamas/RanzVPN/issues/1) with twenty tickets (#2 to #21) under it. This ADR only records that the spec exists and what it fixes; it does not repeat it.

## Decision

The spec in issue #1 is the authoritative scope for the slim-down phase. In one sentence: keep only the native SE-VPN protocol (with VPN over ICMP/DNS and UDP Acceleration; ICMP/DNS later left with R-UDP, see the amendment of 2026-10-21 below), Windows 10 / Server 2016 and later on x64 and arm64, the headless executables, no cloud dependencies, no GUI, no JSON-RPC, no foreign protocols; add a standalone MS-CHAPv2 helper module and an optional STUN client; rename to Ranz VPN 0.1 by Hanzcodes; one branch, one commit per ticket, each kept green by the Windows workflow, one pull request ([#22](https://github.com/Hanzamas/RanzVPN/pull/22)).

Removal means deletion, not stubbing. Error codes and auth-type constants are not renumbered.

## Consequences

- Every later architecture decision (ADR-0002 onward) assumes the slimmed tree as its starting point, not upstream SoftEther.
- Upstream merges are abandoned (hard fork); security fixes are cherry-picked by hand.
- The spec itself is amended through the issue tracker, not here. Scope changes decided later are recorded as separate ADRs and as tickets: removing `vpnclient` is ADR-0012 and ticket #23.

## Amendment 2026-10-21: VPN over ICMP and DNS left with R-UDP

Correction of the scope sentence (Hilmi: "ya"). VPN over ICMP and VPN over DNS were listener modes of the R-UDP stack, so they left the slim fork with R-UDP in ticket #16, as ADR-0020 records. They come back in the new core as phase 2 transport plugins (DNS on port 53, DNS over TLS on 853, DNS over HTTPS and ICMP), after the QUIC and TLS transports are stable (ADR-0020, decision 8). The README's exclusion list is right.
