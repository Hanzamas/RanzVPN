# Spike result: SeLow vs XDP on one KM-TEST Loopback Adapter

Branch `spike/selow-vs-xdp`, never merged. Workflow `.github/workflows/spike-selow-vs-xdp.yml`,
code in `spikes/selow-vs-xdp/`. Builds on `spikes/xdp-loopback/` (see its RESULT.md).

Data: run 38618207893 (both jobs green). Each image measured 120 tests: 2 backends x 2
directions x 3 frame sizes, 4 generator configurations, 5 runs of 5 s each. The health probe
passed after every test. Raw rows are in `results/windows-2022.csv` and
`results/windows-2025.csv`. All tables, including per-run values and CPU split, are in
`results/summary.md`, which `summarize.ps1` generates from the CSVs.

## Answer

- **SeLow installs and works on the hosted runners.** `netcfg -l SeLow_x64.inf -c p -i SeLow`
  (the same INetCfg install as `InstallNdisProtocolDriver`) took 2 to 3 s and exited 0.
  SeLow bound to the KM-TEST adapter on Server 2022 and 2025. Both directions work:
  - SeLow's promiscuous binding receives the frames TCPIP sends out of the adapter.
  - Frames that SeLow writes with dst MAC = adapter MAC reach a UDP socket.
- **TX capture (OS -> user mode):** at 1500 B, both backends exceed 0.8 Mpps, but only with
  the uncapped USO generator.
  - XDP: 1.24 to 1.47 Mpps on about 1.1 to 1.4 busy cores in total.
  - SeLow: 0.93 to 1.25 Mpps, and it uses all 4 vCPUs.
  - CPU per Mpps: XDP 0.75 to 1.1 cores, SeLow 3.2 to 4.3 cores.
- **RX inject (user mode -> OS):** this decides the comparison.
  - XDP delivers 337 to 465 kpps (4.0 to 5.3 Gbit/s at 1500 B).
  - SeLow delivers 69 to 71 kpps at every frame size, which is 0.83 Gbit/s at 1500 B.
  - SeLow is 5 to 7 times slower than XDP and costs 19 to 21.5 cores per Mpps. XDP costs
    3.5 to 6.9.

### Verdict: server role (10 Gbit/s, about 0.8 Mpps at 1500 B)

SeLow is not viable for the server role. Its RX inject path delivers about 70 kpps at every
frame size, about 1/12 of the target, and one writer thread stays 100 % busy. Its TX capture
reaches 0.93 to 1.25 Mpps at 1500 B only by using all 4 vCPUs, which leaves nothing for the
VPN transport. XDP is the only candidate. Its TX capture meets the target with headroom:
1.24 to 1.47 Mpps at 1500 B on about 1.1 to 1.4 cores. Its RX inject on one KM-TEST queue
stops at 337 to 445 kpps at 1500 B (4.0 to 5.3 Gbit/s), which is 42 to 56 % of the target.
The inject thread uses only 0.04 cores, so the limit is the single-queue XDP/TCPIP receive
path, not the user-mode writer. 10 Gbit/s needs more than one RX-inject queue or adapter, or
another host-delivery path. That was not tested here.

### Verdict: client role (1 Gbit/s link, about 83 kpps at 1500 B)

XDP covers the client role in both directions:
- TX capture: 140 to 224 kpps at 1500 B with the old single-thread `send()` generator, which
  is 1.7x or more headroom. With more sender threads it reaches 564 to 1,472 kpps.
- RX inject: 337 to 445 kpps at 1500 B, 4x or more headroom. At 83 kpps that is about 0.3 to
  0.6 cores (3.5 to 6.9 cores per Mpps).

SeLow covers TX capture: 266 to 274 kpps at 1500 B from a single sender thread, about 7.3 to
7.9 cores per Mpps, so about 0.6 cores at 83 kpps. SeLow falls short on RX inject: 69 to
70 kpps at 1500 B is 0.83 Gbit/s, about 16 % below line rate, and it costs about 1.3 to 1.5 cores.
The rate does not change with frame size, so the cost is per packet: about 14 us of
writer-thread CPU per frame inside `WriteFile`. On these 4-vCPU Azure VMs, SeLow cannot fill
a 1 Gbit/s downlink. A faster desktop CPU might close the gap; that is untested.

## Test setup

- **Same adapter, same VM.** Each job installs one KM-TEST Loopback Adapter (10.99.0.1/24,
  permanent neighbor 10.99.0.2 -> 02-00-00-00-00-02, firewall off). It measures SeLow first,
  before XDP is installed. Then it unbinds SeLow from the adapter, installs XDP 1.4.0 from
  nuget.org and measures XDP. Only one backend is in the data path at a time.
- **Frame size** is the L2 frame without FCS: 64, 512 or 1500 B. A 1500 B frame carries a
  1486 B IPv4 packet. Mbit/s = captured or delivered frames x frame length x 8.
- **TX capture** (frames the OS sends out of the adapter, read in user mode). The load
  generator is a Winsock UDP flood from 10.99.0.1 to 10.99.0.2:5555 with 3 configurations:
  - `sendto x1`: one thread, one `send()` per datagram. This is the first XDP spike's
    generator, kept as the baseline row.
  - `sendto x4`: one thread per logical CPU, pinned.
  - `uso x4`: one thread per logical CPU, pinned, with `UDP_SEND_MSG_SIZE` (USO). Each
    `send()` carries 256, 138 or 44 segments (64, 512 or 1500 B), and TCPIP segments them in
    software. KM-TEST reports no USO, LSO, checksum or RSS offload. USO was available on
    both images; no run fell back to plain `send()`.

  Readers:
  - XDP: an AF_XDP RX socket on `{L2, TX, INSPECT}` with a redirect-all program.
  - SeLow: `ReadFile` of 256-frame exchange buffers on `\\.\SELOW_A_{guid}`, waiting on the
    SeLow event when the buffer is empty.

  Both readers have a 4096-frame buffer: XSK rings of 4096 vs `SL_MAX_PACKET_QUEUED`. The
  capture thread runs at `THREAD_PRIORITY_HIGHEST`.
- **RX inject** (frames written in user mode that TCPIP receives). The same IPv4/UDP frames
  (dst MAC = adapter MAC, 10.99.0.2 -> 10.99.0.1:5556/5557) are written by one thread:
  - XDP: an AF_XDP TX socket on `{L2, RX, INJECT}`, ring 4096.
  - SeLow: `WriteFile` of 256-frame exchange buffers.

  Two UDP sockets with one thread each count what TCPIP delivers. "Accepted" means:
  - XDP: TX completions.
  - SeLow: frames written. SeLow drops silently above 4096 pending sends; this never
    happened, because delivered equals written.
- **Duplicates and reordering** are checked with a per-thread sequence number in every
  payload. Both backends had 0 in every test.
- **CPU** comes from cycle counters: `QueryIdleProcessorCycleTime` for the whole system, and
  `QueryThreadCycleTime` for the generator and capture threads. Tick-sampled thread times
  under-count threads that run in short bursts. `cpu_sys_ticks` (GetSystemTimes) is kept in
  the CSV as a cross-check. "Sys cores" is busy logical CPUs out of 4. "Cores per Mpps" =
  sys cores / (captured or delivered Mpps). Both numbers include the generator and the UDP
  sink. They are measured at saturation, so scaling them down to a lower rate is approximate.
- **Hardware.** The two images ran on different CPUs, so differences between the images
  are not caused by the OS alone:
  - windows-2022: Server 2022 build 20348, AMD EPYC 7763, 4 vCPU.
  - windows-2025: Server 2025 build 26100, Intel Xeon Platinum 8370C, 4 vCPU.
- A health probe (0.5 s of plain `send()`, no backend) runs after every test. It passed
  after all 240 measured tests.

## Results

All values are medians of 5 runs. Per-run values are listed in run order. kpps =
thousands of frames per second.

### TX capture, uncapped generator (USO, 4 pinned threads)

| Image | Frame B | Backend | Gen dgrams/s (k) | Captured kpps | Captured kpps, runs 1..5 | Mbit/s | Sys cores | Cores per Mpps | Gen CPU | Capture CPU |
|---|---|---|---|---|---|---|---|---|---|---|
| 2022 | 64 | XDP | 2,656 | **2,640** | 2,740 / 2,558 / 2,640 / 2,732 / 2,079 | 1,351 | 2.13 | 0.78 | 1.97 | 0.10 |
| 2022 | 64 | SeLow | 991 | **991** | 1,000 / 948 / 1,016 / 912 / 991 | 507 | 4.00 | 4.04 | 3.43 | 0.51 |
| 2022 | 512 | XDP | 2,112 | **2,106** | 2,471 / 2,039 / 2,130 / 2,106 / 1,866 | 8,625 | 1.11 | 0.56 | 1.01 | 0.07 |
| 2022 | 512 | SeLow | 1,359 | **1,359** | 1,182 / 1,402 / 1,372 / 1,253 / 1,359 | 5,567 | 4.00 | 2.94 | 3.08 | 0.87 |
| 2022 | 1500 | XDP | 1,473 | **1,472** | 1,783 / 1,320 / 1,713 / 1,308 / 1,472 | 17,664 | 1.10 | 0.75 | 1.00 | 0.07 |
| 2022 | 1500 | SeLow | 1,245 | **1,245** | 1,169 / 1,245 / 1,159 / 1,252 / 1,259 | 14,936 | 4.00 | 3.21 | 3.00 | 0.98 |
| 2025 | 64 | XDP | 1,733 | **1,679** | 1,722 / 1,734 / 1,679 / 1,465 / 1,458 | 860 | 2.43 | 1.64 | 1.18 | 0.06 |
| 2025 | 64 | SeLow | 792 | **792** | 676 / 788 / 792 / 855 / 851 | 406 | 4.00 | 5.05 | 3.28 | 0.58 |
| 2025 | 512 | XDP | 1,317 | **1,317** | 1,317 / 1,681 / 1,354 / 1,058 / 1,051 | 5,395 | 1.45 | 1.10 | 0.96 | 0.07 |
| 2025 | 512 | SeLow | 1,020 | **1,020** | 990 / 1,025 / 986 / 1,028 / 1,020 | 4,180 | 4.00 | 3.92 | 3.06 | 0.80 |
| 2025 | 1500 | XDP | 1,237 | **1,237** | 1,314 / 1,213 / 1,007 / 1,237 / 1,295 | 14,848 | 1.43 | 1.11 | 0.93 | 0.09 |
| 2025 | 1500 | SeLow | 925 | **925** | 925 / 924 / 943 / 931 / 907 | 11,105 | 4.00 | 4.32 | 2.89 | 0.96 |

Loss (generated minus captured) was under 0.5 %, except XDP at 64 B on 2025 (6.0 %, XSK
`RxDropped`).

### TX capture with plain `send()` (captured kpps; generated = captured, loss 0)

| Image | Frame B | XDP x1 (baseline) | SeLow x1 (baseline) | XDP x4 pinned | SeLow x4 pinned |
|---|---|---|---|---|---|
| 2022 | 64 | 238 | 296 | 763 | 603 |
| 2022 | 512 | 233 | 286 | 795 | 588 |
| 2022 | 1500 | 224 | 274 | 729 | 542 |
| 2025 | 64 | 150 | 281 | 527 | 493 |
| 2025 | 512 | 147 | 280 | 463 | 474 |
| 2025 | 1500 | 140 | 266 | 564 | 443 |

- The x1 baseline is bound by the generator: the sender thread is 1.00 core busy for both
  backends.
  - SeLow is faster here (266 to 296 vs 140 to 238 kpps), but its capture thread burns
    another full core.
  - Cores per Mpps at x1: SeLow 6.8 to 7.9, XDP 5.0 to 5.5 on 2022 and 15 to 17 on 2025.
    On 2025, about one more core was busy outside the bench threads during the XDP tests.
    It was not attributed to a process.
- x4 saturates all 4 vCPUs for both backends: 5.0 to 9.0 cores per Mpps.
- Neither backend reaches 0.8 Mpps at 1500 B with per-datagram `send()`. TCPIP's send path,
  not the backend, is the limit.

### RX inject (delivered to UDP sockets; accepted = delivered, loss 0 in every run)

| Image | Frame B | Backend | Delivered kpps | Delivered kpps, runs 1..5 | Mbit/s | Sys cores | Cores per Mpps | Inject CPU | Sink CPU |
|---|---|---|---|---|---|---|---|---|---|
| 2022 | 64 | XDP | **465** | 461 / 464 / 477 / 465 / 470 | 238 | 1.63 | 3.49 | 0.04 | 0.56 |
| 2022 | 64 | SeLow | **69** | 67 / 70 / 69 / 62 / 71 | 35 | 1.44 | 21.49 | 0.99 | 0.28 |
| 2022 | 512 | XDP | **455** | 447 / 454 / 459 / 458 / 455 | 1,864 | 1.64 | 3.59 | 0.04 | 0.56 |
| 2022 | 512 | SeLow | **70** | 70 / 70 / 70 / 70 / 71 | 287 | 1.33 | 19.04 | 1.00 | 0.29 |
| 2022 | 1500 | XDP | **445** | 439 / 444 / 451 / 446 / 445 | 5,338 | 1.67 | 3.75 | 0.04 | 0.59 |
| 2022 | 1500 | SeLow | **70** | 69 / 70 / 66 / 70 / 71 | 834 | 1.33 | 19.11 | 1.00 | 0.28 |
| 2025 | 64 | XDP | **401** | 411 / 417 / 401 / 375 / 362 | 205 | 1.99 | 4.95 | 0.04 | 0.65 |
| 2025 | 64 | SeLow | **71** | 71 / 70 / 70 / 71 / 72 | 36 | 1.48 | 21.10 | 0.99 | 0.30 |
| 2025 | 512 | XDP | **377** | 399 / 398 / 356 / 350 / 377 | 1,544 | 2.11 | 5.61 | 0.04 | 0.64 |
| 2025 | 512 | SeLow | **71** | 71 / 71 / 70 / 71 / 71 | 290 | 1.48 | 20.92 | 0.99 | 0.29 |
| 2025 | 1500 | XDP | **337** | 359 / 344 / 309 / 328 / 337 | 4,041 | 2.33 | 6.90 | 0.04 | 0.64 |
| 2025 | 1500 | SeLow | **69** | 68 / 70 / 69 / 69 / 71 | 832 | 1.47 | 21.18 | 0.99 | 0.28 |

- The SeLow writer thread is CPU-bound inside `WriteFile`, at 1.0 core. Each call moves 256
  frames, and the driver allocates and copies one NBL per frame. NDIS then loops each frame
  back to TCPIP in the writer's context.
- XDP's injector needs 0.04 cores. The work runs in XDP and TCPIP below the user-mode
  thread.
- Only one SeLow handle was tested. A second handle also receives a copy of every frame
  written (see `SlDeviceWriteProc`), so more writers do not scale for free.

## Install and signing (SeLow)

- Package: `src/bin/hamcore/DriverPackages/SeLow_Win10/x64`, driver 4.25.0.9658 (2018-02-04).
  The driver reports `SL_VER=48`, the same as `src/SeLow/SeLowCommon.h`, which spbench
  compiles against.
- Signatures:
  - `SeLow_Win10_x64.cat`: signed by *Microsoft Windows Hardware Compatibility Publisher*
    through *Microsoft Windows Third Party Component CA 2012* to *Microsoft Root Certificate
    Authority 2010*. The signing certificate expired 2018-11-01; the signature carries a
    Microsoft timestamp.
  - `SeLow_x64.sys`: embedded signature by SoftEther Corporation (Symantec, expired 2018,
    DigiCert timestamp).
  - `signtool verify /kp` (kernel-mode policy) on the catalog and the .sys: 0 errors on
    both images.
- Same caveat as the XDP spike: the runners boot with `testsigning Yes` and Secure Boot off.
  A successful load here does not prove that SeLow loads with test signing off. The `/kp`
  result is the evidence that it should. HVCI was not running (VBS status 2,
  SecurityServicesRunning 0), so HVCI compatibility of the 2018 driver is not proven.
- After `netcfg`, the SeLow service was not running, and `sc start SeLow` started it.
  SoftEther's `SuInitEx` does the same through `MsStartService`. It bound to all three
  adapters (`Get-NetAdapterBinding` shows `SeLow` enabled). The KM-TEST adapter showed up
  as `SELOW_A_{guid}` with name "MS NDIS 6.0 LoopBack Driver".
- `Disable-NetAdapterBinding ... -ComponentID SeLow` returned at once on both images.

## Findings and risks (XDP)

1. **The XDP generic TX-inspect path serializes USO senders.**
   - Symptoms: in every XDP USO test, 2 to 3 of the 4 sender threads were still blocked in
     `send()` 5 s after the stop flag (`gen_stuck` in the CSV). With 4 senders, only 1.0 to
     2.4 cores were busy.
   - Under SeLow, no sender ever blocked, and USO saturated all 4 vCPUs.
   - So XDP back-pressures the sender instead of dropping, and its single-queue TX-inspect
     ceiling is about 1.2 to 2.6 Mpps on 1 to 2.4 busy cores. The blocked senders cleared
     after the XSK closed: the next probe passed every time.
2. **Unbinding `ms_xdp` hangs after a heavy session.**
   - In the full run, `Disable-NetAdapterBinding -ComponentID ms_xdp` did not return within
     90 s on both images. It ran after all XDP tests and the diagnostic sequence.
   - In run 38528182565 the same call hung until the 45-minute step timeout.
   - A product that unbinds or uninstalls XDP at runtime should plan for a reboot. The cause
     is not isolated; the stuck USO sends in item 1 are the main suspect.
3. **One-off breakage of the adapter TX path (run 38528182565, both images).**
   - Sequence: XDP was installed while SeLow was still bound, and then SeLow was unbound.
     After the 64 B TX-inspect tests, which included USO with `RxDropped` > 0, an XDP RX
     inject at 64 B reported 14 to 22 M completions per second and delivered 0 frames.
   - After that, every `send()` on the adapter failed with WSAENOBUFS (10055) for the rest
     of the job. RX inject at 512 and 1500 B still worked.
   - Not reproduced in the full run, where XDP was installed after SeLow was unbound, and
     all RX ran before TX. The diagnostic sequence at the end of the full run was clean on
     both images: TX 64 B, then RX 64 B, then TX 1500 B USO, then RX 64 B and 1500 B. The
     trigger is not isolated.
4. TX inspect also redirects the OS's own frames (ARP, IGMP and others). The `other_ps`
   counter was 0 in these windows because only the generator was sending.

## Files

- `spbench.c`: both backends, the generators, the UDP sink, CPU accounting and the health
  probe (`-d probe`). It includes `src/SeLow/SeLowCommon.h`, the real SeLow kernel/user
  contract.
- `run.ps1`: CI runner with phases, health probes and timeouts. `summarize.ps1`: medians and
  tables.
- `results/`: CSVs of run 38618207893 and the generated `summary.md`.
- Earlier runs:
  - 38528182565: interleaved backends; failed with the findings in items 2 and 3.
  - 38616731670: 1 run x 2 s smoke test; clean.
