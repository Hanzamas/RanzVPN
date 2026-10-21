# ADR-0036: Proprietary EULA with Personal, Business and Enterprise tiers, enforced by the controller

**Status:** Accepted (2026-10-20, from the SDN spec #176 that Hilmi filed; recorded by SDN-1, #177). Price points are out of scope; the tier structure is decided.

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
5. **The controller verifies the licence key** (tier, node count, expiry, fallback version) and gates the Enterprise features. Tiers are enforced in that one place.
6. **Third-party obligations:**
   - the SoftEther-derived code keeps its Apache 2.0 licence text and NOTICE;
   - MPL-2.0 dependencies (libjuice and others) publish only their own modified files;
   - LGPL modules are linked dynamically;
   - GPL libraries in the Legacy phase run only as separate sidecar processes, or under a commercial licence from their vendor (for example the IEC 60870-5-104 and IEC 61850 gateway, ADR-0037).

## Consequences

- The licence check is controller code; nodes never decide a tier themselves. Licence enforcement is tested in the controller conformance seam (ADR-0026).
- The process boundary already used for GPL and MPL sidecars (ADR-0023) is also the boundary for the Legacy-phase GPL libraries.
- ADR-0015's "MIT" for libjuice and libplum needs a correction; it is recorded here and not amended by this ADR.
- Tickets: SDN-30 (#206).
