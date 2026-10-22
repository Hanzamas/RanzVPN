# ADR-0036: Anti-debug and anti-RE obfuscation as a release-only build variant

**Status:** Accepted (2026-10-22, SEC-4 #282, under the new core #176). Amends ADR-0002 (CI-only verification) to allow a second build variant whose security properties are still proven in CI, not by hand. Builds on the key-separation property of ADR-0023 and the platform of ADR-0022.

## Context

The new core carries a licence gate and the key handling that protects the proprietary EULA and the paid tiers (#176). Those routines are the part of the product that an attacker wants to read and patch out. SoftEther's line shipped one binary with no protection; Ranz is sold, so the licence and key paths need anti-debug and anti-reverse-engineering (anti-RE) cover.

Three constraints shape the decision:

- **It must not trip the platform defences of a Windows VPN.** HVCI / Memory Integrity refuses executable pages that are also writable, and EDR heuristics flag self-modifying code, RWX allocations and any process that writes into `ntdll`. A protection that does any of those gets the whole product quarantined on the machines it is meant to run on.
- **A crash must stay debuggable in-house.** If every build fought the debugger, a field crash could not be analysed. The internal and debug builds have to be clean.
- **It must be provable in CI.** ADR-0002 made CI the only verification loop, and the SEC-4 acceptance criteria say every property is checked by a CI job, with no manual or hardware step (ADR-0002 amendment of 2026-10-21).

VMProtect is a paid tool and the only paid component in the build. Packing a whole VPN binary with it is exactly the kind of whole-binary virtualization that antivirus flags, so it cannot wrap the product.

## Decision

- **Two variants.** The clean variant (internal and debug) carries no anti-debug and no obfuscation, and is what CI builds and tests by default. The hardened variant is a release-only build, selected by the CMake option `RANZ_HARDENED`, that adds the anti-debug and anti-RE cover. The hardened variant is x64 only for v1; arm64 ships the clean build.

- **The hardened component is a focused binary, not the whole product.** The licence gate and key handling are built as a small, self-contained executable, `ranzguard`, that carries the full protection. The server and `vpncmd` are never packed or virtualized, so the product keeps an ordinary, EDR-friendly fingerprint.

- **Anti-debug is passive and release-only, and the response is degrade or deceive.** `ranzguard` reads the PEB `BeingDebugged` and `NtGlobalFlag`, asks `NtQueryInformationProcess` for `ProcessDebugPort`, `ProcessDebugFlags` and `ProcessDebugObjectHandle`, reads the debug registers for a hardware breakpoint, sets `NtSetInformationThread(ThreadHideFromDebugger)`, times a section with RDTSC and QPC, scans the entry bytes of its own protected routines for a `0xCC` software breakpoint, checks the parent process against a list of known debuggers, and runs a vectored-exception probe. On any detection it does not crash: the licence gate silently returns a locked result and key handling returns a wrong key, so the failure shows up later and far from the check.

- **Anti-RE without the platform-tripping tricks.** `ranzguard` resolves every Windows API at run time by hashing the export name (an empty import table), which also removes the obvious symbols a disassembler keys on; it keeps no RWX page, performs no self-modifying code, and never writes into `ntdll`. VMProtect virtualization is applied selectively, through `RANZ_VMP_BEGIN` / `RANZ_VMP_END` markers that wrap only the licence-gate and key-handling routines, never `main` and never the whole binary. The markers expand to the VMProtect SDK calls when the SDK is present at the release step and to nothing otherwise, so CI builds the variant without the paid tool.

## CI verification

All four acceptance criteria of #282 are CI jobs, no manual or hardware step:

- The clean variant is built and tested by the existing jobs; the `harden` job builds the hardened variant. The clean server binary is asserted to have an ordinary import table and no VMProtect marker section, so it carries no obfuscation.
- `harden-check.py` asserts that `ranzguard.exe` has an empty import table, no section that is both executable and writable, and no call that writes into `ntdll` or allocates an RWX page; and that the VMProtect markers appear only around the two protected routines.
- The `harden` self-test of `vpntest` runs `ranzguard.exe` once normally (it reports unlocked) and once as a debuggee through the Win32 debug API, and asserts the degrade-or-deceive response (it reports locked) with no crash.

## Consequences

- The release pipeline gains one build variant and one paid step (VMProtect on `ranzguard` only). Everything up to that step builds with the free toolchain, so CI covers the whole protection except the VMProtect pass itself, which only transforms already-marked routines.
- The protection is scoped to the licence and key paths. An attacker who strips `ranzguard` still has to defeat the server's own checks; the point is to raise the cost on the paid gate, not to make the product tamper-proof.
- arm64 has no hardened variant in v1. If the paid tiers need arm64 cover later, this ADR is the place to record the x64-only limit being lifted.
