# Spike result: the eBPF path of XDP for Windows on a KM-TEST Loopback Adapter

Follow-up to `spikes/xdp-loopback` (ADR-0018). That spike passed with the deprecated
`XDP_RULE` API. This one asks whether the supported path (eBPF for Windows, the XDP eBPF
hook, and an XSKMAP redirect program) can do the same TX inspect. Branch `spike/xdp-ebpf`,
never merged. Workflow `.github/workflows/spike-xdp-ebpf.yml`, code in `spikes/xdp-ebpf/`.

## Answer

**FAIL for TX inspect, on both hosted x64 images. The result is conclusive.**

An eBPF program cannot see the frames that the OS sends out of the adapter. XDP for
Windows attaches every eBPF program to the `{L2, RX, INSPECT}` hook. The hook is
hard-coded in `EbpfProgramOnClientAttach` in `src/xdp/program.c` (release/1.4,
lines 1866-1868, and the same in `main` on 2026-10-08). `bpf_xdp_attach()` has no hook
argument, and no issue or pull request in xdp-for-windows proposes an eBPF TX hook. On
the KM-TEST adapter the RX path is empty, so the program never runs there.

The test checked everything around the question, so the FAIL is an answer and not a
broken setup:

| Check | windows-2022 (20348) | windows-2025 (26100) |
|---|---|---|
| eBPF 1.4.0 runtime installed (`ebpfcore` running) | PASS | PASS |
| `ranz_xsk.sys` built (clang + `Convert-BpfToNative`), verified, loaded | PASS | PASS |
| `bpf_prog_test_run_opts`: program runs in the kernel, `XDP_PASS` with an empty map, `XDP_REDIRECT` with an XSK in `xsk_map[0]` | PASS | PASS |
| `bpf_xdp_attach` on the KM-TEST adapter | PASS | PASS |
| **EBPF_TX_INSPECT**: XSK on `{L2, TX, INSPECT}` in `xsk_map`, OS sends UDP | **FAIL**: 28 sent, 0 seen, hook counter 0 | **FAIL**: 28 sent, 0 seen, hook counter 0 |
| eBPF on RX inspect sees the OS's own sends (does KM-TEST loop TX back to RX?) | NO | NO |
| eBPF on RX inspect sees frames injected on `{L2, RX, INJECT}` | NO (UDP socket got 5 of 5) | NO (5 of 5) |
| Host-NIC control: same program on the runner's NIC, empty map, fallback `XDP_PASS` | PASS, 89 RX frames in 3 s | PASS, 116 RX frames in 3 s |
| Deprecated `XDP_RULE` TX inspect while the eBPF program stays attached | PASS, 28 of 28 | PASS, 28 of 28 |
| RX inject (AF_XDP TX socket on `{L2, RX, INJECT}`, no program) | PASS, 5 of 5 | PASS, 5 of 5 |

Run 38379122204 (green, both images print `RESULT VERDICT ebpf_tx_inspect=FAIL
conclusive=yes`). Run 38377358705 had the same TX-inspect result without the two
controls. Logs are in the `spike-xdp-ebpf-<os>` artifacts.

Other findings:

- **KM-TEST does not loop sent frames back to its receive path.** So no RX-side
  workaround exists: an eBPF program on RX inspect never sees what the OS transmits.
- **Injected frames bypass RX inspect.** A redirect-all eBPF program on the adapter's RX
  hook does not steal frames that the VPN injects with `{L2, RX, INJECT}`.
- **eBPF and rules coexist on one interface when the hooks differ.** The docs say a
  program cannot mix eBPF and rules "on the same queue". An eBPF program on RX inspect
  and a rule program on TX inspect of the same adapter worked together.

## Signing: is a production-signed eBPF for Windows available?

**No.** The eBPF path runs only with test signing on (or a kernel debugger attached),
which needs Secure Boot off and a reboot. It cannot ship.

- `ebpf-for-windows.x64.1.4.0.msi` from the GitHub release is unsigned. `eBPFCore.sys`
  and `NetEbpfExt.sys` are signed with a WDK test certificate
  (`CN="WDKTestCert VssAdministrator,..."`), and `signtool verify /kp` fails ("terminated
  in a root"). `EbpfApi.dll` is unsigned.
- Every eBPF for Windows GitHub release is marked pre-release, up to v1.6.0
  (2026-09-18). `docs/ReleaseProcess.md`: "Pre-release binaries are test signed."
- A Microsoft maintainer wrote on 2026-05-04 (issue #5184) that there are currently no
  plans to release production-signed eBPF builds. Issue #274 ("Work out production signing
  pipeline") has been open since 2021.
- eBPF is not inbox on Windows Server 2022 or 2025: the services and files are absent
  before the MSI runs. XDP's own CI uses a Windows Server Insider image that ships eBPF
  inbox. No generally available Windows build with inbox eBPF was verified.
- The program itself is a kernel driver. `Convert-BpfToNative` test-signs `ranz_xsk.sys`
  with a WDK test certificate. In production the eBPF docs expect Microsoft's signing
  keys. An attestation signature from us would not be accepted on Windows Server.

`xdp.sys` 1.4.0 from nuget.org is still production-signed (`signtool /kp` passes), as in
the first spike.

## Install steps that worked on hosted runners (test signing on)

1. **eBPF runtime.** `msiexec /i ebpf-for-windows.x64.1.4.0.msi INSTALLFOLDER=C:\ebpf
   ADDLOCAL=eBPF_Runtime_Components /qn`. It takes 5 to 6 s and needs no reboot.
   `ebpfcore`, `netebpfext` and `ebpfsvc` run afterwards.
2. **XDP runtime.** `Microsoft.XDP-for-Windows.Runtime.x64` 1.4.0 from nuget.org, then
   `xdp-setup.ps1 -Install xdp` and `xdp-setup.ps1 -Install xdpebpf`. The second step sets
   `XdpEbpfEnabled=1` and runs `xdpbpfexport.exe`, which needs `ebpfapi.dll` on `PATH`.
   The MSI adds its folder to the machine `PATH`, but a running session does not see it.
3. **Program build.** Run `export_program_info.exe` and `xdpbpfexport.exe` to fill the
   eBPF store (HKLM). Then `clang -g -target bpf -O2 -c ranz_xsk.c` and
   `Convert-BpfToNative.ps1 -FileName ranz_xsk -Platform x64 -Configuration Release`.
   That runs bpf2c and the verifier, downloads a WDK NuGet package, builds a kernel
   driver and test-signs it. It takes about 90 s.
4. **Load and attach.** `bpf_object__open("ranz_xsk.sys")`, `bpf_object__load`,
   `bpf_map_update_elem(xsk_map, &queue, &xsk_handle)`, then
   `bpf_xdp_attach(ifindex, prog_fd, 0, NULL)`.

Pinned inputs (SHA-256 as downloaded in run 38379122204):

| Input | Version | SHA-256 |
|---|---|---|
| `Microsoft.XDP-for-Windows.Runtime.x64` (nuget.org) | 1.4.0 | `F78F091C3EDA1D17D2BF4F7E0DDC593FBEA1DAAC6A53CA69DE2F1854E8070D23` |
| `Microsoft.XDP-for-Windows.Sdk` (nuget.org) | 1.4.0 | `27332A319287FED2BB716C9C9F2B4B43CF56921421424437EEC87BBAE8ABE590` |
| `eBPF-for-Windows.x64` (nuget.org) | 1.4.0 | `C7F49881BEAEC4C7BC51CFCEDB98D6BEE730FF99E4B1120F45DE8C8E6E1894DA` |
| `ebpf-for-windows.x64.1.4.0.msi` (GitHub release) | 1.4.0 (`fc0e2f92`) | `22C2989DFDEBF7DBCE22602CA7605C36CB805F86E71146F1D63693AA3184894E` |

Not pinned: `Convert-BpfToNative` picks the WDK NuGet version for the installed Visual
Studio (10.0.26100.6584 with VS 2022 on windows-2022, 10.0.28000.1839 with VS 2026 on
windows-2025). clang is the runner image's LLVM.

## Packets per second (informational)

Single queue, 74 to 106 byte frames, busy-poll, 5 s per test, shared 4-vCPU hosted VMs.
The numbers are noisy between runs.

| Image | Run | Rule TX inspect (XSK frames) | eBPF TX inspect | RX inject (delivered to UDP socket) | eBPF program alone (test run) |
|---|---|---|---|---|---|
| windows-2022 | 38377358705 | 321 kpps | 0 (376 kpps sent) | 608 kpps | not measured |
| windows-2022 | 38379122204 | 450 kpps | 0 (541 kpps sent) | 638 kpps | 28 ns per frame |
| windows-2025 | 38377358705 | 534 kpps | 0 (565 kpps sent) | 1,357 kpps | not measured |
| windows-2025 | 38379122204 | 331 kpps | 0 (338 kpps sent) | 615 kpps | 25 ns per frame |

As in the first spike, rule TX inspect equals the `sendto()` rate, so one Winsock sender
thread is the bottleneck, not XDP. The test-run cost (25 to 28 ns, 1,000,000 repeats) is
the program alone, with no NIC and no XSK. It shows that an eBPF filter would not be the
bottleneck if it could be used.

## What the new core should use

1. **L2 adapter (KM-TEST): XDP 1.4.0 x64 without eBPF for Windows.**
   - TX inspect: the rules API. `XdpCreateProgram` with `XDP_MATCH_ALL ->
     REDIRECT` to an XSK on `{L2, TX, INSPECT}`. It is the only XDP path that captures the
     frames the OS sends.
   - RX inject: an AF_XDP TX socket on `{L2, RX, INJECT}`, no program.
   - The node installs only the production-signed `xdp.sys`. It needs no eBPF runtime,
     no program driver of its own, and no test signing.
2. **Do not depend on eBPF for Windows.** Its runtime is test-signed only, every program
   would be our own kernel driver to sign, and the hook cannot see TX anyway.
3. **Risk: the rules API is deprecated and "planned for removal".** Mitigations:
   - Pin XDP 1.4.0. It is supported until 29 January 2028.
   - Under XDP's release policy, a breaking API removal should need a new major version,
     and the last 1.x stays supported for 18 months after it ships. This is an inference
     from `docs/release.md`, not a promise.
   - `XdpCreateProgram` is still in `main` (2026-10-08). MsQuic's XDP datapath in `main`
     still uses it with QUIC flow rules. Removing it would break MsQuic (inference).
   - Keep packet I/O behind the Local Bridge backend interface (ADR-0018 decision 3), so
     SeLow on the loopback adapter stays the fallback.
   - Re-run this spike on every XDP release. Watch for an eBPF TX hook or the removal of
     the rules API.
4. **Physical-NIC backend (RX inspect): use the rules API too.** eBPF would work on RX
   (the host-NIC control shows that), but it is test-signed only.
5. **ADR-0018:** record that the eBPF path is rejected for now, with these reasons.

## Not covered

- Windows 10 and 11 clients, and ARM64. Same gaps as the first spike.
- eBPF for Windows later than 1.4.0. XDP release/1.4 builds against 1.4.0, and the TX
  limit is in `xdp.sys`, not in the eBPF runtime.
