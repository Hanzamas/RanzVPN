# ADR-0013: SeLow stays: Local Bridge in the slim fork and L2 bridging in the new product

**Status:** Accepted (2026-10-11). The slim-fork part was already settled in the grilling session ("sisanya tetap", Local Bridge kept, SeLow package kept by the spec); the new-product part became Accepted with the dual-mode decision (ADR-0014), which makes L2 segments first-class and bridging to physical LANs a required feature.

## Context

SeLow is SoftEther's NDIS lightweight filter driver. The server uses it through `SeLowUser.c` and `BridgeWin32.c` to capture and inject Ethernet frames on a physical NIC for Local Bridge, which is the function that connects a virtual Ethernet segment to a real LAN segment. On Windows 10 it is the only bridging path the fork has (the WinPcap path goes away with Windows 7 support, ticket #18). The driver binary is signed by SoftEther and cannot be modified.

Hilmi asked whether SeLow is really no longer used. Under the earlier L3-only recommendation (ADR-0004, now superseded) it would not have been needed by the new core; under ADR-0014 it is.

## Decision

- **Slim fork:** SeLow stays. Local Bridge is a kept feature and SeLow implements it on Windows 10. Removing `vpnclient` (ADR-0012) does not affect this; SeLow is server-side.
- **New product:** SeLow (or the Windows Network Bridge when a TAP adapter is used) is the bridging path for L2 switched networks. L3 routed networks do not use it; a gateway routes IP between Wintun and the LAN with Windows IP forwarding and WinNAT where needed.

## Consequences

- `SeLowUser.c`, `BridgeWin32.c`, `Bridge.c` and the `SeLow_Win10` driver packages remain in the fork and are the reference for the L2 backend; `See/` and `SeeDll/` (WinPcap era) are removed by ticket #18 as planned.
- The SeLow protocol driver keeps its SoftEther name, as accepted in the spec.
- The new product therefore does depend on one SoftEther-signed binary unless the Windows Network Bridge path is chosen for every L2 deployment; this is recorded, not resolved.
