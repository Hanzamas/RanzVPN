# ADR-0002: CI is the only verification loop; no behaviour-changing refactors until a test harness exists

**Status:** Accepted (2026-10-11, Hilmi: "ubah kode berjalan itu coret aja ya, penting mah itu 1 3 4")

**Amended 2026-10-12:** Hilmi approved the table-driven RPC and vpncmd refactor ("RPC dan vpncmd table-driven setujui") on condition that it runs after the harness exists. Decision point 2 is amended accordingly; the other crossed-out items stay crossed out.

## Context

There is no local compiler. Every change is verified by the Windows GitHub Actions workflow: build on x64 and arm64 (x86 until the platform ticket drops it), the `vpntest` start/stop smoke test with the `NO MEMORY LEAKS` marker, the named `vpntest mschapv2` vector test, and `vpncmd /TOOLS /CMD Check`. A CI round trip costs 10 to 30 minutes. There are no unit tests, no integration tests and no golden-output tests of the RPC or vpncmd surface.

During the discussion a list of possible "fase 2" slimming steps was drawn up. Some of them are mechanical and are caught by the compiler and linker when wrong (deleting dead code, splitting files, tightening headers). Others change code that runs (making PACK/config/strtable keys explicit constants, table-driven RPC and vpncmd marshalling, unifying the ANSI/Unicode string APIs) and would only be caught by tests that do not exist.

## Decision

1. Until a real test harness exists, only **behaviour-preserving** work is allowed: changes whose failure mode is a compile or link error. Anything that alters the code path a running server or client takes is out of scope.
2. The behaviour-changing refactors discussed (explicit contract constants, ANSI/Unicode unification) are **crossed out** for now, not merely deferred. Table-driven RPC and vpncmd marshalling is **approved for after the harness** (amendment of 2026-10-12): it may start once the harness of point 3 records golden pack dumps for every RPC structure and golden output for every vpncmd command, and every change is diffed against them.
3. The first investment if those refactors are ever wanted is a harness in `vpntest`: in-process server plus client plus vpncmd, with recorded golden outputs to diff before and after each change.

## Consequences

- The slimming after the twenty tickets is limited to the catalogue in ADR-0003.
- With the amendment, the table-driven refactor becomes its own spec after the harness spec; see the roadmap in ADR-0017.
- The realistic floor for the C code with safe cleanup only is roughly 135k to 150k lines including headers (about 100k statements); see the discussion log for how that number was derived. Going lower requires scope cuts or the harness.
- Commits stay small and one-topic so a red CI run can be bisected by stepping back one commit.

## Amendment 2026-10-21: no manual or hardware verification in the new core

Maintainer decision (Hilmi: "tinggal cek kode yg udh pernah dibuat lah dan best practice di opensource, ngpaain susah susah, gw gaada arm64 gaadaa 10k node gaada hardware nic").

- Every acceptance criterion of the new core and the SDN platform is proven in CI. There is no by-hand spike, no physical NIC, no arm64 machine and no second host.
- What CI stands in for:
  - a second host: several node processes on one runner, each with its own KM-TEST loopback adapter, with the runner's own NIC as the physical side;
  - many nodes: the node simulator (SDN-2), up to the 10,000-node scale test (SDN-18);
  - NAT behaviour: the harness NAT simulator (CORE-S5-4);
  - a Windows 11 client: Windows Server 2025 runners. Microsoft does not support XDP on client SKUs, so the node detects at run time when XDP cannot bind and falls back to SeLow on x64; the client path does not wait for a by-hand run;
  - arm64: every pull request builds arm64; tests run on the `windows-11-arm` runner where the plan provides it, otherwise the x64 tests cover the architecture-neutral code.
- Where CI cannot reach (real NIC drivers, Hyper-V switches, absolute 10 and 100 Gbit/s numbers), the code follows an established open-source reference implementation and its documented practice (for example xdp-for-windows and its samples, msquic, Wintun, Npcap, Tailscale's NAT traversal, libjuice, libplum), and the pull request names the reference. Throughput is measured on CI runners as a regression number; the absolute targets stay estimates.
- This replaces the by-hand Windows 11 XDP spike and the two-VM QTIP spike (ADR-0018, ADR-0022), the "measure on real hardware" step of the ADR-0022 amendment of 2026-10-19, and the two-VM spikes of seam 3 of #45.
