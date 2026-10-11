# ADR-0007: One TLS stack: OpenSSL 3.5 (ECH, hybrid PQ) rather than Schannel

**Status:** Proposed. The discussion first framed it as "Windows 10 minimum with OpenSSL versus Windows 11 / Server 2025 minimum with Schannel and CNG"; the stealth requirements (ADR-0006) later settled the assistant's recommendation on OpenSSL. Hilmi has not chosen.

## Context

The slim fork already builds against OpenSSL 3 from vcpkg, with liboqs and oqs-provider for the hybrid X25519MLKEM768 TLS group. msquic can be built with either Schannel or OpenSSL. Schannel plus CNG would make the product free of third-party crypto, with TLS 1.3 and ML-KEM available on Windows 11 24H2 / Server 2025, but it gives no control over the ClientHello and no ECH, which rules out REALITY-style camouflage and Chrome fingerprint mimicry. BoringSSL would give a Chrome-identical ClientHello but has no stable API and would mean two TLS libraries alongside msquic.

## Decision

- Use **OpenSSL 3.5** everywhere: msquic backend, the TLS/TCP listener and client, ECH client support, X25519MLKEM768.
- Do not add BoringSSL; exact Chrome fingerprints are delegated to the Tier-3 sidecar (ADR-0006).
- Schannel/CNG remains the alternative if stealth is dropped from the requirements and Windows 11 / Server 2025 becomes the minimum.

## Consequences

- Minimum OS stays Windows 10 / Server 2016 as in the spec.
- liboqs and oqs-provider stay in the build (as the spec already says).
- The ClientHello produced by OpenSSL will not match Chrome's JA3/JA4 exactly; this is acceptable for Tier 1 and 2 networks and is the reason Tier 3 uses a sidecar.
