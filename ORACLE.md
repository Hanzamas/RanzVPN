# main-oracle

This branch holds the original SoftEther VPN source exactly as it was when Ranz VPN forked it (upstream commit 69c0aa69, "Merge pull request #2312"). Ranz VPN uses it as a **test oracle**: the same input is given to the old code and to the new code, and the outputs are compared (ADR-0017, spec #27).

Rules:

- The source on this branch is never changed. Only the CI workflow differs from upstream: `.github/workflows/oracle.yml` builds Windows x64 and arm64, runs the upstream smoke test, and publishes the binaries as a pinned pre-release named `oracle-<sha8>`.
- Tests download a specific `oracle-<sha8>` release, never a moving build.
- The oracle covers everything upstream had, including the protocols removed from Ranz VPN (OpenVPN, SSTP, L2TP/IPsec, EtherIP, WireGuard), the Layer 3 switch, SecureNAT and vpnclient, so future protocol adapters and the new core can be compared against it.
- Do not deploy these binaries.
