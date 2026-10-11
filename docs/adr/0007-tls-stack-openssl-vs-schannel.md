# ADR-0007: One TLS stack for the new core: Schannel (TLS/TCP 443) and msquic with the Schannel backend (QUIC); OpenSSL dropped from the new core

**Status:** Accepted (2026-10-11, Hilmi: "y catat"). Revised from the earlier Proposed recommendation of OpenSSL 3.5; the file name is kept for link stability.

## Context

The slim fork builds against OpenSSL 3 from vcpkg with liboqs and oqs-provider for the hybrid X25519MLKEM768 TLS group; that does not change. For the **new core** the question was which TLS stack to use for the TLS/TCP 443 path and as the msquic backend. The earlier recommendation (OpenSSL 3.5) rested on ECH and control over the ClientHello for censorship tiers 1 and 2 (ADR-0006).

Hilmi decided on Schannel after an external analysis he pasted on 2026-10-11, which was right about the three-path transport design and the Cloudflare origin leg but wrong about the direction of JA3 (see ADR-0006). The decisive argument: the ClientHello of Schannel is the ClientHello of WinHTTP, Office, the Microsoft Store, Windows telemetry and thousands of other Windows applications, and msquic with the Schannel backend is the QUIC stack of Windows' own HTTP/3 and SMB-over-QUIC. An engine built on them has the fingerprint of the operating system without any fingerprint engineering, and the product ships zero third-party crypto.

## Decision

- **TLS/TCP 443 path:** Schannel (SSPI / `InitializeSecurityContext` / `AcceptSecurityContext`).
- **QUIC path:** msquic built with the **Schannel** backend, for censorship tiers 1 and 2.
- **OpenSSL, liboqs and oqs-provider are not part of the new core.** They stay in the slim fork only.
- Crypto for the end-to-end session layer (ADR-0005) comes from CNG/bcrypt (X25519, AES-GCM, SHA-2, `BCryptGenRandom`); post-quantum hybrid key exchange is used where the OS provides it (ML-KEM in CNG/Schannel on Windows 11 24H2 / Server 2025 and later) and is otherwise a later addition, not a blocker.
- Tier-3 needs that require ClientHello control (REALITY, uTLS-style fingerprints, ECH) stay in the sidecar (ADR-0006).

## Consequences

- **Minimum OS for the new core becomes Windows 11 / Server 2022** (QUIC in Schannel). The slim fork keeps Windows 10 / Server 2016 as in the spec.
- **ECH is not available** in Schannel. Accepted, because SNI blocking as practised in Indonesia is domain-list based and the product's own domain is not on such lists; ECH remains a sidecar feature for hostile networks, where its presence is a flag anyway.
- The JA3/JA4 of the core equals that of ordinary Windows software, which is the intended camouflage for tiers 1 and 2; no uTLS, no BoringSSL, no two-library setup.
- The Windows-native replacement table (ADR-0008) resolves to the CNG column for crypto and certificate handling (`CertOpenStore`, CNG keys, Schannel credential binding, http.sys certificate binding for the admin UI).
- The discussion log records the earlier OpenSSL reasoning for completeness; the slim fork is unaffected by this ADR.
