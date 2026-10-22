# ADR-0036: Proprietary EULA with Personal, Business and Enterprise tiers, enforced by the controller

**Status:** Accepted (2026-10-20, from the SDN spec #176 that Hilmi filed; recorded by SDN-1, #177). Price points are out of scope; the tier structure is decided. Amended 2026-10-22: the protection, anti-tamper and activation model (Hilmi: "Ya", "yups").

## Context

Ranz is sold, but an individual must be able to run their own network for free, a business pays by the size of its network, an MSP serves many small customers, and an enterprise buys data-centre features with data-centre support. The code base mixes licences: the SoftEther-derived code is Apache 2.0, and the new core and the Legacy phase use MPL-2.0, LGPL and GPL components. Licence facts checked on 2026-10-21: libjuice and libplum are MPL-2.0 (their READMEs: "licensed under MPL 2.0"). ADR-0015 records both as MIT, which is wrong.

## Decision

1. **A proprietary EULA covers every Ranz component.**
2. **Tiers:**
   - **Personal:** free, non-commercial, all core features, a small node cap.
   - **Business:** per node per year; gateway and server nodes are priced above client nodes; volume pricing per managed node for MSPs.
   - **Enterprise:** adds EVPN and BGP (ADR-0032), controller high availability (ADR-0026) and priority support.
3. **A subscription turns into a perpetual fallback licence** for the version held, after 12 paid months.
4. **Security fixes for each major version for two years**, regardless of subscription, so no Ranz install stays unpatched.
5. **The controller verifies the licence key** (tier, node count, expiry, fallback version) and gates the Enterprise features. Tiers are enforced in that one place. *(Refined by the amendment of 2026-10-22 below: the controller still gates the Enterprise features and the tiers; online activation adds a vendor-server path that delivers the signed activation token and the Enterprise feature key.)*
6. **Third-party obligations:**
   - the SoftEther-derived code keeps its Apache 2.0 licence text and NOTICE;
   - MPL-2.0 dependencies (libjuice and others) publish only their own modified files;
   - LGPL modules are linked dynamically;
   - GPL libraries in the Legacy phase run only as separate sidecar processes, or under a commercial licence from their vendor (for example the IEC 60870-5-104 and IEC 61850 gateway, ADR-0037).

## Consequences

- The licence check is controller code; nodes never decide a tier themselves. Licence enforcement is tested in the controller conformance seam (ADR-0026). *(See the amendment of 2026-10-22 below: activation adds the Hanzcodes licensing server for the signed token and the Enterprise feature key; the controller still gates the tiers.)*
- The process boundary already used for GPL and MPL sidecars (ADR-0023) is also the boundary for the Legacy-phase GPL libraries.
- ADR-0015's "MIT" for libjuice and libplum needs a correction; it is recorded here and not amended by this ADR. *(Corrected by the ADR-0015 amendment of 2026-10-21.)*
- Tickets: SDN-30 (#206).

## Amendment 2026-10-22: protection, anti-tamper and activation model

Maintainer decision (Hilmi: "Ya", "yups"). This amendment records how the proprietary code is protected, how it resists cracking and reverse engineering, and how the Enterprise features and the initial activation are unlocked. The licence tiers, the EULA and the third-party obligations above are unchanged. Decision 5 is refined by point 7: the controller still gates the Enterprise features and the tiers, and activation adds a vendor-server path that delivers a signed token and the Enterprise feature key. The releases are Authenticode code-signed (ADR-0020 amendment of 2026-10-22).

1. **Protection is tiered by asset value.** The VPN tunnel and the core connectivity get zero DRM and are never gated on a licence or a server: availability comes first, and a live tunnel is never bricked. The licence and activation logic get strong protection. The Enterprise feature code gets the strongest.

2. **Anti-crack rests on cryptography and signing, not obfuscation:**
   - Ed25519 signed Licence keys, node-locked to the MachineGuid (the Machine identity, FIX-5).
   - Authenticode signing plus a self-integrity check at start: WinVerifyTrust and a hash of the `.text` section, with redundant and delayed checks.
   - symbol stripping: Go with `-trimpath` and `-ldflags "-s -w"`, a private PDB for the C code.
   - a per-customer watermark in each Licence key, and a revocation list distributed by update.

3. **Anti-debug is aggressive but passive and release-only.** It reads the PEB `BeingDebugged` and `NtGlobalFlag`, `NtQueryInformationProcess` (`ProcessDebugPort`, `ProcessDebugFlags`, `ProcessDebugObjectHandle`), a hardware-breakpoint check through the debug registers, `NtSetInformationThread(ThreadHideFromDebugger)`, RDTSC and QPC timing, a scan of its own `.text` for `0xCC`, a parent-process check, and exception-based checks. It avoids self-modifying code, RWX pages and patching ntdll, because those trip HVCI / Memory Integrity and EDR heuristics and cause false positives. Internal and debug builds are clean, so a crash can still be debugged.

4. **Anti-RE** is control-flow flattening and opaque predicates, string and constant encryption decrypted at use, dynamic API resolution (hash-based, an empty IAT), anti-disassembly, and VMProtect virtualization applied selectively to only the licence-gate and key-handling routines, never the whole binary, because whole-binary packing trips antivirus on a VPN product. VMProtect is the only paid component; everything else is native or free.

5. **Anti-VM is not used to refuse to run.** Customers legitimately run in VMs and in the cloud. Running in a VM is only recorded as a watermark in licence telemetry.

6. **The response to a detection is degrade or deceive, never an instant crash:** silently lock a feature, return wrong data, fail later and far from the check, or report to the server. A false positive must not brick a paying customer.

7. **Online activation and a server-delivered key, for the Enterprise features and the initial activation only** (option a, not a hard online gate). On install the Node or the Controller contacts the Hanzcodes licensing server with the Licence key and the machine fingerprint, and receives a signed, node-locked, time-limited activation token. A key that the server holds releases the Enterprise feature blob; that key lives in memory only. A periodic heartbeat re-validates with a grace period. Past the grace period the install degrades to the Licence in force or to Personal, but the core tunnel keeps working. There is an offline activation path, a signed request-response file exchanged by hand, for air-gapped and industrial customers, so that segment is never locked out.

8. **The Hanzcodes licensing and activation server is new vendor infrastructure:** an activation service with high availability, the vendor Ed25519 private key and the signing key in an HSM or a CNG KSP. It is built near release, not now. Until the vendor signing key is linked into release builds, no key verifies and every install runs Personal.
