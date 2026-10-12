# ADR-0003: Catalogue of safe (behaviour-preserving) cleanups

**Status:** Accepted (2026-10-11). Items 1, 3 and 4 were accepted first (Hilmi: "penting mah itu 1 3 4"). On 2026-10-11 Hilmi confirmed the extended list (items 5 to 13) as the "sapu aman" phase and it became the spec `Hanzamas/RanzVPN#24`, with two amendments: the comment item (10) now deletes most comments instead of rewriting them, and items 3 and 4 (file splits, per-module headers) are deferred to the harness phase so that the sweep stays pure deletion; the `static` half of item 4 stays in the sweep.

## Context

ADR-0002 restricts post-slim-down work to changes that the compiler and linker verify. This ADR lists what that work is, in the order it should run, so that later tickets can reference it. The numbering follows the discussion: 1, 3 and 4 were the original "safe" items; 2, 5 and 6 of the original list were the behaviour-changing ones that ADR-0002 crosses out.

## Decision

Run in this order, each as its own ticket, each verified by the existing CI:

1. **Dead function sweep** (Accepted). Use CodeGraph to list non-static functions with zero callers (excluding entry points), delete, run CI, repeat until stable; deleting one layer exposes the next. Expected 10k to 20k lines.
3. **Split god files by responsibility** (Accepted). Pure moves, no logic change: `Server.c` into config / listeners / caps; `Protocol.c` into client-connect and server-accept; `Admin.c` into dispatch plus one file per RPC area.
4. **Shrink the god header** (Accepted). `Cedar.h` includes only what is common; each module exposes its own API header; internals become `static`.
5. **Branches that never execute on the target** (Proposed): `IsNt() == false` (Win9x), `OPENSSL_VERSION_NUMBER < 0x10100000L` and LibreSSL paths, 32-bit branches of `CPU_64`, pre-Windows-10 OS-version branches, `OS_UNIX` (already a ticket). Removing them does not change behaviour on Windows 10+ x64/arm64 with OpenSSL 3.
6. **Silently dead code** (Proposed): `#if 0` blocks, commented-out code, struct fields never read, config keys loaded but never used, parameters never read, orphan `#define`s and string-table keys.
7. **Debug scaffolding** (Proposed): `KS_*` counters, `Tracking.c`, `Probe`, scattered `Debug()`. Exception: the malloc tracker that produces the `NO MEMORY LEAKS` marker stays until it is replaced by the CRT debug heap (`_CrtDumpMemoryLeaks`).
8. **Include hygiene** (Proposed): each `.c` includes only what it uses (CodeGraph can compute it); this is what makes the dependency graph honest after item 4.
9. **Byte-identical duplicates** (Proposed): merge function pairs whose bodies are identical (diff-verified). Flatten `Ex`/`Ex2`/... wrapper chains only with tooling plus CI, never by hand.
10. **Comments** (Accepted 2026-10-11, amended): delete comments rather than rewrite them. Keep the Apache license header on every file and comments that explain a reason, a wire or pack format, a magic number, a Windows API quirk or a security consideration; rewrite those in plain English. Delete per-function one-line headers, `// Validate arguments` markers, restatements of the next line, banners, stale TODOs and headers of deleted sections. Expected: about nine in ten comment lines go.
11. **Warnings as a tool** (Proposed): enable `-Wall -Wextra` under clang-cl in CI and fix only the mechanical subset (unused variables and parameters, unreachable code). Do not touch things like `while (err = ERR_get_error())` seen in the CI log; "fixing" them can change behaviour.
12. **Map for humans** (Proposed): `CONTEXT.md` plus ADRs generated from the CodeGraph dependency graph: about twelve modules, one sentence of contract each, who may call whom. Target: one-way dependencies for Admin, Command and Config; cycles among Hub, Session and Connection are the protocol core and are allowed.
13. **Metrics in CI** (Proposed): executable size and line counts per commit, so progress is visible and size regressions are caught.
14. **One-time reformat** (Accepted 2026-10-12, Hilmi: "y"): the very last pass of the sweep. A committed clang-format configuration (attached braces, tabs, no rewrapping, include sorting off) applied once to Cedar, Mayaqua and the program entry sources, in two commits: layout only, proven token-identical by a checker; then braces removed around single-statement bodies, proven by the same checker to delete only balanced brace pairs. CI pins the formatter and fails on drift. Motivation: at 46550173, 23% of the 171,640 lines in Cedar and Mayaqua are brace-only, 16% blank and 8% comments; only 53% carry code. Expected about 30k to 35k fewer lines with identical code.

## Consequences

- Order and tickets for the sweep are defined in spec `Hanzamas/RanzVPN#24`: CI steps (warnings-as-errors for unused code, size metrics) first, then dead functions, orphan declarations, dead branches, debug scaffolding, duplicates and forwarding wrappers, unconsumed config and pack keys, include hygiene and `static`, comments, string-table re-prune, module map, and the one-time reformat (item 14) last. Items 3 and 4 (file splits, per-module headers) run after the harness exists.
- Verification for every item above is the existing CI (build, smoke test, vector test, self-check).
- Expected result of the full catalogue: Mayaqua about 100k to 70k lines, Cedar about 70k to 50k lines; total C about 135k to 150k including headers. These are estimates.
- `WaterMark.c` (4.3k lines) is a JPEG stored as a C array; moving it to hamcore removes it from the code count with low risk but does touch the load path, so it is listed here only as a candidate.
