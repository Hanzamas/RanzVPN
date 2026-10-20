# ADR-0024: Spectre mitigation under clang-cl

**Status:** Draft (2026-10-20, FND-31 of the foundation audit, #96). Needs the maintainer's decision on the open question below; until then the build does what the Decision section says.

## Context

`src/CMakeLists.txt` set `/Qspectre` for every Windows build except the arm64 cross build, and printed "Setting QSPECTRE". The flag is a `cl.exe` option. CI and the release build compile with clang-cl, which accepts `/Qspectre` and ignores it: the x64 CI log carried "argument unused during compilation: /Qspectre" once per compiled file (160 warnings). The message in the CMake output said the mitigation was on, and no CI or release binary had it.

clang has a Spectre variant 1 mitigation of its own, speculative load hardening (`-mspeculative-load-hardening`, reachable from clang-cl as `/clang:-mspeculative-load-hardening`). It is a different mechanism from `/Qspectre` (which inserts `lfence` barriers at the patterns it finds), it costs run time on every load, and nobody has measured it on the vpnserver data path.

## Decision

- `/Qspectre` is set only when the compiler is `cl.exe` (`CMAKE_C_COMPILER_ID` is `MSVC`). For clang-cl nothing is set, and the CMake output says so in one line that points here.
- No clang spelling is added until it is measured. The release binaries built with clang-cl carry no compiler Spectre mitigation, as they did not before; the CMake output now says that instead of claiming the opposite.
- Binaries are not changed by this decision: clang-cl ignored the flag.

## Open question

Does the server threat model need a compiler Spectre variant 1 mitigation? A Spectre attack usually needs attacker-controlled code on the same machine, and a dedicated VPN server runs none. If the maintainer wants the mitigation anyway, the next step is to build vpnserver with `/clang:-mspeculative-load-hardening`, measure the throughput cost with vpntest, and record the number here.

## Consequences

- The x64 and arm64 CI logs lose the 160 `/Qspectre` warnings. A local `cl.exe` build keeps `/Qspectre`.
- A clang-cl build that wants a Spectre mitigation has to ask for it explicitly; the decision to ship it is this ADR's to make.
