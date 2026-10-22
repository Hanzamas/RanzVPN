# ADR-0039: Security hardening baseline for every Windows binary

**Status:** Accepted (2026-10-22, Hilmi: "Ya"). This is the hardening baseline for the new core; it applies going forward and the slim fork is not retrofitted.

## Context

The new core ships proprietary Windows binaries (the Node, the Controller and the sidecars) to paying customers, on hosts the vendor does not control. A hardening baseline keeps exploit mitigations, least privilege and supply-chain integrity the same across every binary, and keeps them from regressing, by proving the shipped binary carries them in CI rather than trusting that a build flag survived. ADR-0020 (amendment of 2026-10-22) adds Authenticode signing and ADR-0036 (amendment of 2026-10-22) adds the self-integrity check and the activation model; this ADR is the rest of the per-binary hardening.

## Decision

1. **Exploit-mitigation compiler and linker flags on every binary:**
   - `/guard:cf` for Control Flow Guard (CFG).
   - `/CETCOMPAT` for shadow-stack (CET) hardware control-flow protection.
   - `/DYNAMICBASE` with `/HIGHENTROPYVA` for full, high-entropy ASLR.
   - `/NXCOMPAT` for DEP.
   - `/GS` for stack buffer-overrun checks.
   - `/sdl` for the additional security checks.

2. **Runtime process mitigations through `SetProcessMitigationPolicy`** where they do not break a needed feature: ACG (no dynamic code), only signed images may load, and strict handle checks. A mitigation that a required feature cannot run under is left off for that process and the reason is recorded.

3. **Least privilege:**
   - the Node and the Controller services run as a virtual service account (`NT SERVICE\...`), not LocalSystem.
   - the named pipes to `ranz-bgp` and the other sidecars carry a strict ACL.
   - DLLs load only from System32 (FIX-4).

4. **Supply chain:** pinned dependencies (a vcpkg baseline and `go.sum`), `govulncheck`, an SBOM, reproducible builds, and signed releases (ADR-0020).

5. **CI verifies the binary flags** with Microsoft BinSkim, or with `dumpbin /headers` and `dumpbin /loadconfig`, so a dropped mitigation fails the build.

## Consequences

- The gate is on the shipped artifact, not on the build script, so a flag that a toolchain change silently drops is caught.
- `/CETCOMPAT` and ACG constrain what a process may do at run time; a feature that needs dynamic code generation (for example a JIT) cannot run under ACG, so that mitigation is scoped per process rather than applied blanket.
- The virtual service accounts replace LocalSystem, so the data directory DACLs, the pipe ACLs and any registry access are set for those accounts, not for SYSTEM.
- The slim fork keeps its current build; this baseline is new-core only, so the two have different mitigation profiles until the fork is retired.
