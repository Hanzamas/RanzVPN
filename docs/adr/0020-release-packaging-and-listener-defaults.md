# ADR-0020: Release packaging and listener defaults for the current server

**Status:** Accepted (2026-10-13). Hilmi decided each point in the release grilling of 2026-10-13; his answer is quoted under each decision. Since the same day the repository is private and the product is proprietary (Hanzcodes), for personal use and as a portfolio piece (Hilmi: "buat ini portofolio pribadi dan penggunaan pribadi gw"). Amended 2026-10-22: releases are Authenticode code-signed (Hilmi: "Ya"); amended again 2026-10-22: the new product ships as one `ranz.exe` with a thin MSI.

## Context

So far the server has been installed by hand: copy the build output, then run the server's own install command, which registers a Windows service under the name inherited from SoftEther, `sevpnserverdev`. There was no installer, no release process, and no decision about which ports a fresh server opens.

A spike on the branch `spike/msi` (CI run 38351576122) built an MSI with WiX Toolset v5, for x64 and arm64, on the x64 runner. Its findings:

- The payload is the server executable and `hamcore.se2`, nothing else: the CRT and the Cedar and Mayaqua libraries are linked statically. Each MSI is about 3 MiB.
- On x64, a silent install starts the service, and a silent uninstall removes the service and both files. The arm64 MSI was built but never installed.
- The server writes its data next to its executable: the config file, its backups, and the server, security and packet logs. Windows Installer does not own these files, so uninstall leaves them in place.
- Uninstall also leaves the registry key `HKLM\SOFTWARE\Hanzcodes\Ranz VPN` and the Windows Firewall rule "Ranz VPN Server". The server adds that rule itself at start, by running a VBScript through cscript, and records a hash of the script under that registry key so that later starts skip it.
- Code signing has no cheap route for an individual in Indonesia. Azure Artifact Signing is not offered there, the free open-source signing programmes exclude proprietary code, and an OV or IV certificate costs about $200 to $500 a year.

Listener facts, from the current tree:

- A fresh server creates two listeners, TCP 443 and TCP 5555. Both carry the same traffic: SE-VPN sessions, the admin RPC and HTTP. Port 5555 is SoftEther's default port and serves only as a second port for machines where 443 is already taken, for example by IIS.
- Ports 992 and 1194 left the default list in the slim-down. VPN over ICMP and VPN over DNS left with the R-UDP stack (ticket #16), because both were R-UDP listener modes. That narrowed the scope sentence of ADR-0001, which still lists them as kept.

## Decision

1. **MSI built in CI, unsigned.** CI builds the MSI with WiX for x64 and arm64. Neither the executable nor the MSI is code-signed. A user who downloads it passes the SmartScreen warning by choosing "Run anyway". Hilmi: "MSI dibuat otomatis di CI, tanpa signing". *(Superseded by the amendment of 2026-10-22 below: the shipped executables and the MSI are Authenticode code-signed; CI signs with a self-signed certificate during development.)*
2. **Data stays next to the executable.** The config, its backups and the logs stay in the install directory under Program Files, where the server writes them today, so no code changes. The service runs as LocalSystem and can write there. ProgramData is used only by the new core. Hilmi: "(a) untuk sekarang. Service jalan sebagai SYSTEM jadi tetap bisa menulis di sana. ProgramData baru dipakai di core baru."
3. **Uninstall keeps config and logs.** Uninstall removes the binaries and the service, keeps the config, its backups and the logs, and removes the firewall rule "Ranz VPN Server" and the registry key `HKLM\SOFTWARE\Hanzcodes\Ranz VPN`. An upgrade or a reinstall starts from the existing configuration. Hilmi: "Upgrade dan install ulang tidak kehilangan konfigurasi."
4. **Service name `ranzvpnserver`.** The internal service name changes from `sevpnserverdev` to `ranzvpnserver`. The display name stays "Ranz VPN Server". The MSI and the server's own install command register the same name. On install, the MSI stops and deletes an existing `sevpnserverdev` service, so a machine that was set up by hand moves to the MSI without a manual step. Hilmi, correcting the proposed `RanzVPNServer`: "Ganti jadi ranzvpnserver. MSI otomatis mematikan dan menghapus service lama." _Supersedes part of ADR-0001's amendment of 2026-10-12, which kept internal service names unchanged; for the server's service, this decision replaces it._
5. **Releases come from tags.** Pushing a tag `v0.1.x` creates a GitHub Release in the private repository with three assets: the x64 MSI, the arm64 MSI and a zip. Hilmi: "Ada riwayat versi yang jelas, dan tinggal unduh."
6. **Default listener: TCP 443 only, with a fallback to 5555.** A fresh server, one with no config file yet, creates a single listener on TCP 443. If 443 is already in use at that first start, the server creates a listener on TCP 5555 instead and logs the fallback. Operators can still add any TCP listener, as today. Hilmi asked "klo bisa 443 semua knp tidak ??" and chose the variant with the fallback.
7. **Port 80: off by default, redirect and ACME only.** A fresh server does not listen on port 80. When an operator turns it on, port 80 serves exactly two things: a redirect from HTTP to HTTPS, and ACME HTTP-01 challenge responses, so that Let's Encrypt certificates can be added later. It never carries VPN sessions or the admin RPC. Hilmi: "catat deh 80 dibuat ini redircet http ke https dan acme http 01", then "(a) Mati secara default."
8. **DNS and ICMP transports wait for the new core.** VPN over DNS (port 53), DNS over TLS (port 853), DNS over HTTPS and VPN over ICMP are new-core transports for phase 2: they come as transport plugins after the QUIC and TLS transports are stable. The current server listens on neither 53 nor 853. Hilmi: "53 dan 853 nanti ini dah gw ingi nlgi over dns dan icmp dan dot dan doh", then "Fase 2 core baru, setelah transport QUIC/TLS stabil, sebagai plugin transport."

## Consequences

- Downloads show the SmartScreen warning. On Windows 11 machines that enforce Smart App Control, unsigned installers are blocked outright with no "Run anyway"; Smart App Control must be off there. Signing becomes a new decision if the product is ever distributed beyond personal use.
- Program Files lets local users read files by default, and the config holds the private key of the server certificate and the password hashes. Keeping the data next to the executable therefore means the MSI or the server must restrict access to the data files. The release spec decides how.
- The firewall rule allows the server executable, not a port, so the 5555 fallback and any added listener need no firewall change. The registry key holds the script hash that makes the server skip adding the rule, so the rule and the key must go together: removing only the rule would stop a reinstall from adding it again. Whether the MSI owns the rule or an uninstall step deletes it is left to the release spec. Today the rule depends on VBScript, which Microsoft is deprecating; without cscript the rule is never added.
- Deleting `sevpnserverdev` on install also deletes an upstream SoftEther VPN Developer Edition server on the same machine, because that edition uses the same service name. This matters only on a machine that also runs upstream SoftEther; the release spec may limit the delete to a service whose executable is a Ranz executable.
- The listener list is saved in the config, so existing servers keep 443 and 5555, and only fresh servers get the new default. The fallback happens once: a server that fell back to 5555 keeps it after 443 becomes free, until the operator adds a 443 listener. The spike's install test, which checks for both ports, changes with the code that applies this default.
- Port 80 needs a plain-HTTP responder that does not exist today; it lands with the ACME work. HTTP-01 validation reaches a server only on port 80, so a server whose inbound port 80 is blocked needs another ACME challenge type.
- Windows Installer orders upgrades by product version. The spike took the version from the CI run number, which counts per workflow. The release spec must take it from one counter that only grows, within the MSI limit of 65535 for the third field.
- Open items for the release spec: the arm64 MSI has never been installed; an upgrade from one version to the next has never been tested; the spike's MSI does not include vpncmd, so until the planned web admin exists, an MSI-installed server is administered with vpncmd from elsewhere.
- ADR-0008 names MSIX or winget as the installer for the new core; this ADR covers the current server only. While the repository is private, release assets need a signed-in download, so winget is not an option.

## Amendment 2026-10-22: releases are Authenticode code-signed

Maintainer decision (Hilmi: "Ya"). Decision 1, "MSI built in CI, unsigned", is superseded. The shipped executables and the MSI are signed with an Authenticode certificate, OV or EV. The certificate is bought near release, not now, because there is no release yet. During development, CI signs with a self-signed certificate, so the signing and the self-integrity path (ADR-0036 amendment of 2026-10-22) are exercised on every build.

- The release build signs every shipped executable and the MSI with the Authenticode certificate. A signed download no longer shows the SmartScreen "unknown publisher" warning, and an EV certificate also satisfies Smart App Control.
- Until the certificate is bought, CI signs with a self-signed certificate. That signature does not chain to a trusted root, so a self-signed build still shows SmartScreen, but the signing step and the self-integrity check that reads the signature run on every build.
- The self-integrity check at start (WinVerifyTrust plus a hash of the .text section) is specified in ADR-0036; it needs the binary to be signed, which is why CI signs even during development.

## Amendment 2026-10-22: the new product ships as one `ranz.exe` with a thin MSI

Maintainer decision (ADR-0011 amendment of the same date). This ADR still covers the current server, the slim-fork `vpnserver`, and decisions 1 to 8 stay for it until it is retired (CORE-S8-1, #84). The package of the new product differs:

- **The artifact is one signed `ranz.exe` per architecture**, which carries the Node and its drivers (ADR-0011 amendment). `ranz install` and `ranz uninstall` do what the MSI of the spike did: the files under Program Files with a restricted access list, the services, and the data directory kept on uninstall (decision 3). ONE-2 (#311).
- **The MSI is a thin wrapper** (ONE-5, #314). Its only payload is `ranz.exe` and its actions run `ranz install` and `ranz uninstall`, so Group Policy and Intune deploy the one file the usual way. CI builds it with the pinned WiX for x64 and arm64 and signs it like the executable.
- **Tag-driven releases** (decision 5) will publish the signed `ranz.exe` and the MSI per architecture instead of the three assets named there, and the zip falls away. No release is made before the product is complete.
- **Updates replace the one file** (SDN-59, #252), not an MSI.
- **Service names:** `ranzvpnserver` (decision 4) stays the name of the Node service; the Controller keeps its own service name.
