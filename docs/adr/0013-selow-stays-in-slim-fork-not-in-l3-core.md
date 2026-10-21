# ADR-0013: SeLow stays: Local Bridge in the slim fork and L2 bridging in the new product

**Status:** Accepted (2026-10-11). The slim-fork part was already settled in the grilling session ("sisanya tetap", Local Bridge kept, SeLow package kept by the spec); the new-product part became Accepted with the dual-mode decision (ADR-0014), which makes L2 segments first-class and bridging to physical LANs a required feature. Amended 2026-10-20: "WinNAT where needed" becomes the three egress tiers (SDN spec #176).

## Context

SeLow is an NDIS **protocol** driver (Class `NetTrans`; it calls `NdisRegisterProtocolDriver`), not a lightweight filter. The server uses it through `SeLowUser.c` and `BridgeWin32.c` to capture and inject Ethernet frames on a physical NIC for Local Bridge, which is the function that connects a virtual Ethernet segment to a real LAN segment. On Windows 10 it is the only bridging path the fork has (the WinPcap path goes away with Windows 7 support, ticket #18). The shipped driver binary is **Microsoft-WHQL-signed** (not SoftEther-signed) and cannot be modified without breaking that signature (corrected in the 2026-10-13 amendment).

Hilmi asked whether SeLow is really no longer used. Under the earlier L3-only recommendation (ADR-0004, now superseded) it would not have been needed by the new core; under ADR-0014 it is.

## Decision

- **Slim fork:** SeLow stays. Local Bridge is a kept feature and SeLow implements it on Windows 10. Removing `vpnclient` (ADR-0012) does not affect this; SeLow is server-side.
- **New product:** SeLow (or the Windows Network Bridge when a TAP adapter is used) is the bridging path for L2 switched networks. L3 routed networks do not use it; a gateway routes IP between Wintun and the LAN with Windows IP forwarding and WinNAT where needed. *("WinNAT where needed" is replaced by the three egress tiers, amendment of 2026-10-20 below.)*

## Consequences

- `SeLowUser.c`, `BridgeWin32.c`, `Bridge.c` and the `SeLow_Win10` driver packages remain in the fork and are the reference for the L2 backend; `See/` and `SeeDll/` (WinPcap era) are removed by ticket #18 as planned.
- The SeLow protocol driver keeps its SoftEther display strings, which it must to keep Microsoft's catalog signature valid.
- The new product therefore does depend on one third-party-signed binary (the Microsoft-WHQL-signed SeLow package) unless the Windows Network Bridge path is chosen for every L2 deployment; this is recorded, not resolved.

## Amendment 2026-10-13: SeLow driver type and signer corrected

From the 2026-10-13 grilling (`facts-signing.md` section 6, `prep-release.md` Q22), checked by local inspection of `src/bin/hamcore/DriverPackages/SeLow_Win10/x64/`. This ADR's original Context contained two factual errors, now fixed above:

- **Type.** SeLow is an NDIS **protocol** driver, not a lightweight filter: INF `Class = NetTrans`, `LowerRange "ndis5,ndis4"`, and `NdisRegisterProtocolDriver` in `src/SeLow/SeLow.c`.
- **Signer.** The shipped `SeLow_x64.sys` and `SeLow_Win10_x64.cat` are signed by **"Microsoft Windows Hardware Compatibility Publisher"** (an HLK/WHQL dashboard signature: EKU `1.3.6.1.4.1.311.10.3.5`, no `.5.1`), with a Microsoft Time-Stamp countersignature, x64 only. Only the pre-fork v4.19-era builds were SoftEther/GlobalSign-signed.
- **The decision stands; the dependency is on a Microsoft-signed binary, not a SoftEther-signed one.** It still cannot be rebuilt or extended (e.g. to arm64) without a driver-signing pipeline of our own, which is why XDP on the loopback adapter is the path away from it in the new core (ADR-0018). Open: the 2018 build's HVCI status is untested.

## Amendment 2026-10-20: "WinNAT where needed" becomes the three egress tiers

Maintainer decision, from the SDN spec #176 that Hilmi filed ("'WinNAT where needed' becomes the three egress tiers"). The SeLow decisions above are unchanged; only the NAT of an L3 gateway changes.
- **An L3 gateway that is an internet exit uses the first Egress tier its host supports** (ADR-0025, ADR-0008 amendment of 2026-10-20): RRAS NAT on Windows Server; WinNAT over one supernet where Hyper-V is present and no NetNat exists yet; otherwise a proxy on the Windows TCP/IP stack. An existing NetNat is never touched.
- **1:1 NAT and SNAT per VRF are done in the node's data plane**, not by Windows NAT.
- **SeLow is one of the Capabilities a node reports** (ADR-0033), so the controller knows which nodes can bridge an L2 Network to a physical LAN through it.
