# ADR-0040: CI quality gates for the new core

**Status:** Accepted (2026-10-22, Hilmi: "Ya"). These gates start with the next wave of tickets; they are new-core gates and follow the CI-only verification rule of ADR-0002.

## Context

The new core parses attacker-reachable wire formats (the Noise handshake, the nanopb control stream, the config importer, the front-door classifier, DNS and the licence keys) and runs as a privileged service. ADR-0002 (amendment of 2026-10-21) makes CI the only verification loop, with no manual or hardware step. These gates make the quality bar a property CI enforces on every change, so a new parser cannot merge without a fuzzer, coverage cannot fall, and a regression in speed is caught as a number rather than noticed in the field.

## Decision

1. **A fuzz target per parser, before it merges.** Every new parser or wire-format handler ships with a fuzz target in the same change: the Noise handshake, `control.proto`, the config importer, the front-door classifier, DNS and the licence keys. The fuzzer is libFuzzer plus ASan for C, and `go test -fuzz` for Go.

2. **A per-module coverage floor checked in CI:** `llvm-cov` for C and `go cover` for Go. A change that drops a module below its floor fails CI.

3. **Static analysis in CI:** clang-tidy and MSVC `/analyze` with SAL for C; `staticcheck` and `govulncheck` for Go.

4. **Application Verifier runs in a CI job.** The native Windows tool (locks, handles, heap) covers what ThreadSanitizer would, because ThreadSanitizer is not available on Windows; `go test -race` stays for the Go code.

5. **A performance regression gate.** The harness micro-benchmarks and the controller scale test fail CI when they are slower than their recorded median by more than a set margin.

## Consequences

- A new parser cannot merge without its fuzzer, so the attacker-reachable formats are fuzzed from the first commit that adds them.
- The coverage floor is per module, so a large change cannot dilute one module's coverage behind a higher project-wide number.
- Application Verifier stands in for ThreadSanitizer on Windows; `go test -race` keeps race detection on the Go side.
- The performance gate compares against a recorded median with a margin, so the absolute throughput targets stay estimates (ADR-0002 amendment of 2026-10-21) while a regression still fails the build.

## Amendment 2026-10-24: the gates run in the full set, not on every pull request

Maintainer decision in chat. A CI cycle of a pull request took about 25 minutes and about 100 job-minutes, and a ticket needs two or three cycles. Every gate above still runs, in the **full set** of `windows.yml` and `ranz.yml` (the plan job, `ci-plan.yml`, chooses the set): on every push to `integration` and `master`, every night, on `workflow_dispatch`, on a pull request that carries the label `full-ci`, and on a pull request that changes `src/Core/Crypto*`, `src/Core/Noise*`, `src/SeLow` or the signing, install and MSI scripts (the MSI package, `.github/msi`, is built and installed only in the full set). Any other pull request runs the **fast set**: the format check, the move-only check, the fuzz target registry, the pins, `govulncheck` and SBOM job, `ranz` on Linux (with `go test -race`, the Go coverage floors, `go test -fuzz`, `staticcheck` and `govulncheck`) and on Windows x64, the x64 build with its `vpntest` and `coretest` tests and its performance gate, and the arm64 Debug build as a compile check.

- Decision 1 holds at merge: a new parser needs its fuzz target in the registry on the pull request, and the Go fuzz tests run there. The libFuzzer targets of the C code run under AddressSanitizer in the full set.
- For the C code, decisions 2 to 5 (the coverage floor, clang-tidy and MSVC `/analyze`, Application Verifier, the arm64 performance gate) run in the full set. A change that breaks one is found when it reaches `integration`, not before; the label `full-ci` runs them on the pull request.
- This also amends the arm64 line of the ADR-0002 amendment of 2026-10-21: every pull request still builds arm64 (the Debug configuration), and the arm64 tests run in the full set.

## Amendment 2026-10-30: the fuzz campaign and the nightly run (AUD-3)

Recorded by AUD-3 (#363). `fuzz.yml` runs every target of the registry for 15 minutes every night against a corpus that it stores, and for as long as it is told by hand (an hour for the campaign). A finding fails the run. The full set of `windows.yml` and `ranz.yml` keeps its 60 and 20 seconds for each target.
