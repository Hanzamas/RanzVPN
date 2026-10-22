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
