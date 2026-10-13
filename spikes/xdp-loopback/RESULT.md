# Spike result: XDP for Windows on a KM-TEST Loopback Adapter

Spike for the open risk in ADR-0018. Branch `spike/xdp-loopback`, never merged.
Workflow `.github/workflows/spike-xdp.yml`, code in `spikes/xdp-loopback/`.

## Answer

**PASS on both hosted x64 images.** XDP for Windows 1.4.0 in generic mode binds to the
Microsoft KM-TEST Loopback Adapter. Both halves of a TAP-like adapter work:

- **(a) TX inspect: PASS.** An AF_XDP RX socket on hook `{L2, TX, INSPECT}`, fed by an
  `XDP_MATCH_ALL -> REDIRECT` program, received every UDP datagram the OS sent out of the
  adapter. In phase 1 of run 38351131691, 27 of 28 (WS2022) and 28 of 29 (WS2025) datagrams were counted; the
  last one was sent after the phase-1 drain loop ended and was counted in phase 2. The socket
  also saw the OS's own chatter: NetBIOS broadcast on WS2022, and ARP, IGMP and LLMNR on
  WS2025. The frames are redirected
  (consumed), so they never reach `loop.sys`.
- **(b) RX inject: PASS.** An AF_XDP TX socket on hook `{L2, RX, INJECT}` (no program
  needed) injected IPv4/UDP frames with dst MAC = adapter MAC, src 10.99.0.2 and
  dst 10.99.0.1:5556. A plain Winsock UDP socket bound to 10.99.0.1:5556 received
  5 of 5. Under flood, every completed injection reached the socket.

| Image | OS build | Loopback created | XDP bound | TX inspect | RX inject |
|---|---|---|---|---|---|
| windows-2022 | Server 2022, 20348 | yes | yes (`ms_xdp` Enabled) | PASS | PASS |
| windows-2025 | Server 2025, 26100 | yes | yes (`ms_xdp` Enabled) | PASS | PASS |

Runs: 38351131691 and 38351393612 (both green, logs uploaded as `spike-xdp-<os>` artifacts).

## Packets per second (informational)

Single queue (KM-TEST has no RSS, so queue 0 only), 74 to 106 byte frames, busy-poll,
5 s per test, shared 4-vCPU hosted VMs. The numbers are noisy between runs.

| Image | Run | TX inspect (frames seen by XSK) | RX inject (delivered to UDP socket) |
|---|---|---|---|
| windows-2022 | 38351131691 | 620 kpps | 1,025 kpps |
| windows-2022 | 38351393612 | 347 kpps | 640 kpps |
| windows-2025 | 38351131691 | 566 kpps | 897 kpps |
| windows-2025 | 38351393612 | 325 kpps | 829 kpps |

TX inspect is bound by the sender, not by XDP: the XSK count equals the `sendto()` count
and `RxDropped` is 0. A single Winsock thread is the bottleneck. RX inject is bound by
TCPIP's receive path plus the one receiving thread, and no frames were lost.

## Install steps that worked on hosted runners

1. **XDP runtime.** The MSI is gone from v1.3 onward, so `msiexec` is not an option for
   1.4. Download `Microsoft.XDP-for-Windows.Runtime.x64` 1.4.0 from nuget.org
   (`https://www.nuget.org/api/v2/package/<id>/1.4.0`) and expand it as a zip. Then run
   `runtime\native\xdp-setup.ps1 -Install xdp`, which wraps
   `netcfg -l xdp.inf -c s -i ms_xdp` and `lodctr`. It takes 1 to 2 s, needs no reboot,
   and binds `ms_xdp` to every Ethernet adapter, including the KM-TEST one. The runner's
   own network was not disturbed.
2. **SDK.** `Microsoft.XDP-for-Windows.Sdk` 1.4.0 from nuget.org, headers only. Compile
   with `XDP_API_VERSION=3` and `XDP_INCLUDE_WINCOMMON`, and link `ntdll`. No `xdpapi.dll`
   is needed.
3. **KM-TEST Loopback Adapter.** `mkloop.c` does what `devcon install netloop.inf *MSLOOP`
   does: `SetupDiCreateDeviceInfo` + `DIF_REGISTERDEVICE` +
   `UpdateDriverForPlugAndPlayDevices(*MSLOOP, %windir%\inf\netloop.inf)`. `devcon.exe` is
   present on windows-2022 (WDK 10.0.26100) but **absent on windows-2025**, so the SetupAPI
   tool is the method that works on both. The adapter comes up `Up`/`Connected`, 802.3,
   MAC `02-00-4C-4F-4F-50`. That MAC is fixed and identical on every install.
4. **Address.** `New-NetIPAddress 10.99.0.1/24`. A permanent neighbor
   (10.99.0.2 -> 02-00-00-00-00-02) lets TCPIP transmit without ARP replies. The firewall
   was disabled so the injected UDP could reach the socket. A product needs a firewall rule
   instead.

## Signing

- `xdp.sys` and `xdp.cat` in the nuget.org 1.4.0 x64 runtime are signed by
  *Microsoft Windows Hardware Compatibility Publisher*, which chains through *Microsoft
  Windows Third Party Component CA 2012* to *Microsoft Root Certificate Authority 2010*.
  `signtool verify /kp` (kernel-mode production policy) passes with 0 errors on both images.
- Caveat: hosted runners boot with `testsigning Yes` and Secure Boot off, so a successful
  load on CI does not prove by itself that the driver loads with test signing off. The `/kp`
  verification is the evidence that test signing is **not** needed for x64 1.4.0.
- Not determined: whether the catalog is WHQL (HLK) or attestation signed. Both use the same
  signer name. Attestation-signed drivers are not accepted on Windows Server; Microsoft
  supports XDP on Server, which suggests WHQL. Unverified.
- ARM64 was not tested. nuget.org has no production-signed ARM64 runtime; the 1.4 ARM64
  builds are test-signed GitHub pre-releases. Test signing needs a reboot, which a hosted
  `windows-11-arm` job cannot survive.

## Windows 10

**Not covered by this spike.** GitHub has no hosted Windows 10 image. What is known:

- The INF section is `NTamd64.10.0...17763`, so it installs on Windows 10 1809 and later,
  including 21H2 and 22H2.
- The production signature passes kernel policy, and client SKUs accept both WHQL and
  attestation signatures.
- Microsoft documents and tests XDP only on Windows Server, so Windows 10 and 11 clients are
  unsupported territory.
- A manual run of this workflow's steps on a real Windows 10 22H2 box is still needed.

## Design notes for ADR-0018

- The TX-inspect program uses the built-in rule API (`XdpCreateProgram`, `XDP_RULE`). It
  works in 1.4 but is **deprecated and planned for removal**. The supported path is eBPF,
  which needs eBPF-for-Windows installed as well. RX inject needs no program.
- Injected frames used dst MAC = adapter MAC. Broadcast frames and frames to foreign MACs
  were not tested.
- TX inspect also captures all OS chatter on the adapter (ARP, IGMP, LLMNR, NetBIOS), so
  the VPN side must handle it or filter it.
- Every KM-TEST instance has the same MAC unless `NetworkAddress` is set.

## Fallback (SeLow / generic LWF on KM-TEST)

Not run. XDP passed, so the fallback was not needed. The XDP result itself shows that a
generic NDIS LWF (`ms_xdp`, FilterMediaTypes `ethernet`) binds to the KM-TEST Loopback
Adapter on Server 2022 and 2025.
