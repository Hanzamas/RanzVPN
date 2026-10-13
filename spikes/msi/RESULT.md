# Spike result: MSI for Ranz VPN Server (WiX Toolset v5)

Prototype for the release grilling, not a decision. Branch `spike/msi`.

Files:
- `spikes/msi/Package.wxs`: the package.
- `spikes/msi/test-msi.ps1`: the silent install and uninstall test.
- `.github/workflows/spike-msi.yml`: CI, runs on push to `spike/**`.

Passing run: https://github.com/Hanzamas/RanzVPN/actions/runs/38351576122 (3 attempts; the whole run takes about 3 minutes).

## What works

- **Build.** The `build` job copies the build steps of `windows.yml` for x64 (`windows-latest`) and arm64 (`windows-11-arm`). The `msi` job runs on the x64 runner and builds both MSIs with `wix build -arch x64|arm64`, using WiX 5.0.2 installed by `dotnet tool install --global wix --version 5.0.2`. WiX builds an arm64 MSI on an x64 host, so the arm64 runner does not need .NET or WiX.
- **Payload.** The MSI contains only `vpnserver.exe` and `hamcore.se2`. The CRT is linked statically, and cedar and mayaqua are static libraries, so there are no DLLs. vpnserver looks for `hamcore.se2` next to its exe (`InitHamcore` calls `GetExeDir`).
- **Install directory.** `C:\Program Files\Ranz VPN` (`ProgramFiles64Folder`, on both architectures).
- **Service.** The values match what `vpnserver /install` sets (`MsService`, `MsInstallServiceExW`, string table `SVC_SEVPNSERVERDEV_*`):
  - name `sevpnserverdev`, display name `Ranz VPN Server`, the same description;
  - own process, auto start, LocalSystem, error control normal;
  - command line `"C:\Program Files\Ranz VPN\vpnserver.exe" /service`.

  `ServiceControl` starts the service on install, stops it on install and uninstall, removes it on uninstall, and waits each time.
- **Version and upgrade.** The version is `0.1.<GITHUB_RUN_NUMBER>`, which is what CMake sets with `BUILD_NUMBER`. The upgrade code is fixed (`A670DB74-2C69-4A09-A841-D240248F4D29`) and `MajorUpgrade` is declared, with a downgrade error.
- **UI.** Only the basic UI of Windows Installer, with no WixUI dialog set and no license page. The MSI is not signed.
- **x64 test on the CI runner (admin):**
  - `msiexec /i /qn` exits with 0.
  - `sc query` shows the service RUNNING.
  - netstat shows vpnserver listening on TCP 443 and 5555, on IPv4 and IPv6. These are the default listeners (`SiInitListenerList`).
  - `msiexec /x /qn` exits with 0.
  - `sc query` then returns 1060, so the service is gone. The process is gone, and `vpnserver.exe` and `hamcore.se2` are removed.

## MSI size (run 3)

| | MSI | payload |
|---|---|---|
| x64 | 3,170,304 bytes (3.02 MiB) | vpnserver.exe 7,848,448 + hamcore.se2 474,202 |
| arm64 | 3,551,232 bytes (3.39 MiB) | vpnserver.exe 8,470,016 + hamcore.se2 474,202 |

## What uninstall leaves behind (config is KEPT)

vpnserver writes its data next to its exe (`GetDbDir` is the exe directory). The MSI does not own these files, so Windows Installer leaves them in place:

- **The install directory with the server's data.** `C:\Program Files\Ranz VPN` stays, with:
  - `ranz_server.config` and `lang.config`;
  - `backup.ranz_server.config\`;
  - `server_log\`, `security_log\` and `packet_log\`.
- **Registry.** `HKLM\SOFTWARE\Hanzcodes\Ranz VPN` stays, with the subkeys `Update Service Config` and `PacketiX VPN\FW ScriptHash`.
- **Firewall rule.** The Windows Firewall rule `Ranz VPN Server` stays. vpnserver adds it itself at start (`MsRegistWindowsFirewallEx` runs a VBScript through `cscript.exe`), and nothing removes it.

Keeping the config is what an upgrade needs. A "remove everything" option does not exist yet.

## Findings along the way

- `ServiceConfigFailureActions` with `restartService` fails the install with error 1939, because Windows Installer gets error 5 (access denied) when it sets the failure actions. The spike leaves the element out. vpnserver sets the same failure actions itself (restart three times after 10 s, reset after 1 day) on every service start (`MsServiceDispatcher` calls `MsUpdateServiceConfig`), and the test checks this with `sc qfailure`. If the MSI must own the failure actions, use `util:ServiceConfig` from the Util extension.
- The pwsh wrapper of GitHub Actions exits with the last native exit code. Without the final `exit 0`, the 1060 from `sc query` failed a passing test.

## Open

- **Signing.** Nothing is signed. `vpnserver.exe` must be signed before `wix build`, and the MSI after it. See `facts-signing.md`: Azure Artifact Signing is not available in Indonesia.
- **arm64 test.** The arm64 MSI is built but has never been installed. `test-msi.ps1` should run unchanged on `windows-11-arm`, after one more job that downloads the arm64 MSI.
- **Upgrade test.** Not done. To do: install version N, then N+1. Check that the old product is removed, the service restarts, and `ranz_server.config` is kept. Two constraints on the version:
  - `GITHUB_RUN_NUMBER` counts per workflow, so a release must use one counter, or a "new" MSI can carry a lower version.
  - The third field of an MSI version cannot exceed 65535.
- **Uninstall policy.** Decide which of these an uninstall should remove:
  - Config and logs: keep, purge, or ask.
  - The firewall rule: better owned by the MSI (`FirewallException` from the Firewall extension), so uninstall removes it.
  - The HKLM keys.

  Also, VBScript is a Windows feature on demand that Microsoft is deprecating. Without `cscript.exe`, the firewall rule is never added.
- **Data location.** Config and logs live in Program Files. Moving them to ProgramData is a code change (`GetDbDir`).
- **vpncmd.exe is not shipped.** vpnserver does not need it, but the server cannot be administered without it (or a remote vpncmd).
- **Existing service.** A machine that already ran `vpnserver /install` already has `sevpnserverdev`, and the MSI `ServiceInstall` would probably fail with error 1923. Not tested.
- **Names.** Manufacturer `Hanzcodes` is taken from `GC_REG_COMPANY_NAME`. The service name `sevpnserverdev` is inherited from SoftEther. Renaming it later breaks upgrades from systems registered with `vpnserver /install`.
