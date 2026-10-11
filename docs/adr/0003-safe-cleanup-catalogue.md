# ADR-0003: Catalogue of safe (behaviour-preserving) cleanups

**Status:** Partly accepted. Items 1, 3 and 4 are Accepted (Hilmi: "penting mah itu 1 3 4"). The extended list (items 5 to 12) was presented in answer to "dan apalagi?" and was not explicitly confirmed; treat those as Proposed.

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
10. **Comments** (Proposed): rewrite the machine-translated comments and the per-file headers per module. Zero risk, large readability gain.
11. **Warnings as a tool** (Proposed): enable `-Wall -Wextra` under clang-cl in CI and fix only the mechanical subset (unused variables and parameters, unreachable code). Do not touch things like `while (err = ERR_get_error())` seen in the CI log; "fixing" them can change behaviour.
12. **Map for humans** (Proposed): `CONTEXT.md` plus ADRs generated from the CodeGraph dependency graph: about twelve modules, one sentence of contract each, who may call whom. Target: one-way dependencies for Admin, Command and Config; cycles among Hub, Session and Connection are the protocol core and are allowed.
13. **Metrics in CI** (Proposed): executable size and line counts per commit, so progress is visible and size regressions are caught.

## Consequences

- Verification for every item above is the existing CI (build, smoke test, vector test, self-check).
- Expected result of the full catalogue: Mayaqua about 100k to 70k lines, Cedar about 70k to 50k lines; total C about 135k to 150k including headers. These are estimates.
- `WaterMark.c` (4.3k lines) is a JPEG stored as a C array; moving it to hamcore removes it from the code count with low risk but does touch the load path, so it is listed here only as a candidate.
