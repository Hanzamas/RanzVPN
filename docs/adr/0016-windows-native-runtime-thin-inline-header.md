# ADR-0016: Migrate the Mayaqua runtime to Windows-native primitives behind one thin inline header

**Status:** Accepted (2026-10-11). Hilmi chose the direction ("fokus ke ini migrasi ke windows native total") and the header shape ("sisain satu header inline tipis kayak Lock(x) biar kode tetap kebaca"). Execution waits for the test harness, per ADR-0002. Amended 2026-10-13: the migration stops after DNS and WinHTTP, CNG and Schannel move to the new core, and the memory tracker stays (see the amendment at the end).

## Context

Mayaqua is a portability layer from 2003: it re-implements threads, locks, events, counters, reference counts, tick counting, memory tracking, file I/O, DNS and crypto so that the same Cedar code ran on Windows and Unix. After the slim-down (PR #22) the only target is Windows 10 / Server 2016+ on x64 and arm64, so most of that layer wraps something Windows or the CRT already provides. About 65k lines of Mayaqua remain after the removal tickets. Hilmi wants the runtime moved to Windows-native APIs instead of deleting Mayaqua and Cedar, and wants the call sites to stay readable.

Facts that shape the migration, read from the tree at 46550173:

- `LOCK` is a heap-allocated `CRITICAL_SECTION` behind `LockInner`/`UnlockInner` (`Win32NewLock`, `Win32Lock`), so it is **recursive**. A `SRWLOCK` is not recursive and is therefore not a drop-in replacement.
- `EVENT` is an **auto-reset** kernel event (`CreateEvent(NULL, FALSE, FALSE, NULL)`) owned through a `REF` reference count.
- In `_DEBUG` builds `Lock(x)` is a block macro that records file, line and thread id; release builds call `LockInner` directly.
- The `NO MEMORY LEAKS` marker the CI smoke test greps for comes from Mayaqua's own tracker (`InternalMalloc`, `TrackNewObj`, printed in `Mayaqua.c`).
- Call-site counts in Cedar and Mayaqua `.c` files: `Free` 1323, `ZeroMalloc` 571, `Unlock` 342, `Lock` 283, `LockList` 268, `Tick64` 169, `Malloc` 152, `AddRef` 110, `NewList` 85, `NewLock` 71, `WaitThread` 53, `NewThread` 50, `Release` 40, `Wait`/`Set` 27 each, `NewEvent` 25.

## Decision

1. **Direction.** Replace Mayaqua's own implementations with Windows and CRT primitives wherever an equivalent exists. Mayaqua is not deleted; it shrinks to what Windows has no equivalent for.
2. **Header shape.** Keep one thin header of `static inline` functions with the existing Mayaqua names (`Lock(x)`, `Unlock(x)`, `Set(e)`, `Wait(e, ms)`, `Tick64()`, `ZeroMalloc(n)`, ...). Each function is one or two lines that call the Windows API directly: no dispatch table, no extra state, no logic beyond the call. Call sites keep reading as they do today. Block macros such as the current `_DEBUG` `Lock` are replaced by inline functions so that they behave as expressions and are visible to the debugger.
3. **Method: wrapper flip.** For each primitive: first swap the body of the existing Mayaqua function to the Windows API in one place and keep its name and signature; prove it with CI and the harness; then move it into the thin header as an inline function; then delete the old implementation and the `OS_DISPATCH_TABLE` entry. Call sites are never rewritten by hand in bulk.
4. **Semantics are preserved, not "upgraded".** A replacement must keep the observable semantics of the primitive it replaces:
   - `LOCK` stays recursive: `CRITICAL_SECTION` embedded in the struct (no separate heap allocation) is the default. A lock moves to `SRWLOCK` only after an audit proves it is never re-entered on the same thread, one lock at a time.
   - `EVENT` stays an auto-reset kernel event with its reference count.
   - `Tick64` stays monotonic and millisecond-based (`GetTickCount64` or QPC-derived), including across sleep and resume.
   - Threads keep `NewThread`/`WaitThread`/`ReleaseThread` reference-count semantics on top of `_beginthreadex` handles.
5. **Map.**

   | Mayaqua today | Windows-native target |
   |---|---|
   | Kernel/Object: `LOCK`, `COUNTER`, `REF`, `EVENT`, `THREAD` | `CRITICAL_SECTION` (embedded), `Interlocked*`, kernel event, `_beginthreadex` |
   | `Tick64` and time helpers | `GetTickCount64` / `QueryPerformanceCounter`, `GetSystemTimeAsFileTime` |
   | Memory tracker and `NO MEMORY LEAKS` | CRT debug heap (`_CrtSetDbgFlag`, `_CrtDumpMemoryLeaks`); the CI marker moves with it. **Withdrawn 2026-10-13: the tracker stays** (Mayaqua's `KS_*` counters and the marker are kept as-is; see the 2026-10-13 amendments). A separate test branch only trials the CRT debug heap against it. |
   | `FileIO`, `OS` dispatch table, `Win32.c` backend | direct `CreateFileW` family; the dispatch table disappears once it has a single backend |
   | DNS in `Network.c` | `GetAddrInfoW` / `GetAddrInfoExW` |
   | `Encrypt.c` on OpenSSL | CNG (`BCrypt*`, `NCrypt*`) and CryptoAPI for X.509, per ADR-0007. **Moved to the new core, 2026-10-13.** |
   | `HTTP.c` / `Wpc.c` | WinHTTP |
   | TLS in `Network.c` | Schannel, together with the new core (ADR-0005, ADR-0007) |

   Mayaqua keeps what Windows has no equivalent for: `LIST`/`QUEUE`/`FIFO`/`BUF` containers, the `Str` subset in use, `Pack` (RPC wire format), `Cfg` (config file format), `Table` (string tables), `TcpIp` packet parsing, and a tidied `Microsoft.c` (registry, services, drivers, firewall, which are already native).
6. **Order.** `Tick64` → `LOCK`/`COUNTER`/`REF` → `EVENT` → `THREAD` → memory tracker → `FileIO`/`OS` collapse → DNS → `Encrypt` to CNG → `HTTP` to WinHTTP → TLS to Schannel last, with the new core. Each step is its own ticket with its own CI run. Amended 2026-10-13: the memory tracker step and the `Encrypt` step leave this order, and the migration ends with WinHTTP; see the amendment at the end.
7. **Prerequisite.** None of this starts before the test harness of ADR-0002 exists: an in-process server plus cascade plus vpncmd run with golden outputs, plus a stress case that exercises lock re-entry, event waits and thread teardown. The safe cleanup sweep (spec #24) runs first because it removes code the migration would otherwise have to port.

## Consequences

- Expected size: Mayaqua from about 65k lines to about 25k to 30k; Cedar is unaffected by this ADR and shrinks through spec #24 and the new core.
- Call sites keep their current names, so the diff of each migration step is concentrated in Mayaqua and the thin header, which keeps review and bisection simple.
- OpenSSL leaves the dependency list at the `Encrypt` and TLS steps, which also removes the largest vcpkg build item from CI.
- The per-primitive semantic audit (re-entrancy of each `LOCK`, reset mode and waiters of each `EVENT`, ownership of each `THREAD`) is the first task of every migration ticket; it is not done in advance here.
- Risk is concentrated in silent semantic changes (deadlock from a non-recursive lock, lost wake-up from a reset-mode change, tick wrap or jump). Those are exactly what the harness stress case must catch, which is why the harness is a hard prerequisite.

## Amendment 2026-10-13: the migration stops at DNS and WinHTTP, and the memory tracker stays

Hilmi decided these points in the grilling of 2026-10-13.

1. **The runtime migration (spec #30) ends with DNS and WinHTTP.** Of the ten steps in decision 6, #30 keeps `Tick64`, `LOCK`/`COUNTER`/`REF`, `EVENT`, `THREAD`, the `FileIO`/`OS` collapse, DNS (step 7) and `HTTP` to WinHTTP (step 9). Step 5, the memory tracker, is dropped (point 3). Step 8, `Encrypt` to CNG, and step 10, TLS to Schannel, leave #30 (point 2).
2. **CNG and Schannel move to the new core; they are not dropped.** The new core uses CNG for crypto and Schannel for TLS from its start, as ADR-0007 and ADR-0008 require. The current code base keeps OpenSSL 3 until the new core replaces its data path. Two reasons. Schannel offers TLS 1.3 only on Windows 11 and Server 2022 or later, while the current code base targets Windows 10 and Server 2016 or later. And the old crypto and TLS paths are replaced by the new core anyway, so porting them now would do the work twice. Hilmi: "CNG dan Schannel dikerjakan langsung di core baru, supaya tidak kerja dua kali. #30 berhenti di langkah 7 dan 9", and "pentign cng dan schannel jangan didbuang".
3. **The memory tracker stays.** Mayaqua keeps its own tracker: the `KS_*` counters, the object tracking and the `NO MEMORY LEAKS` report that CI checks. The map row that moved it to the CRT debug heap is withdrawn. Reason: the CRT debug heap reports leaks only in debug builds, while CI builds and tests release builds, so the leak check would stop working; the tracker already works in release builds at no extra cost. Hilmi: "Sudah terbukti jalan, murah, dan bekerja di build release." The memory entries of the OS dispatch table, which step 5 would have deleted, become direct calls when step 6 deletes the table, like every other entry left at that point.
4. **Experiment: the CRT debug heap on a test branch.** A separate test branch carries an extra CI job that builds the Debug configuration and runs the tests with the CRT debug heap's leak report on, to compare it with the tracker. The job does not run on master and does not gate any pull request, and its CI minutes count against the private repository. Its result is input for a later decision about the tracker; it does not change point 3. Hilmi: "tambah job C1 debug khsuus gtur tapi ini hmmm branch sendiri buat tesitng".

Consequences of the amendment:

- OpenSSL, its vcpkg build and the in-tree liboqs and oqs-provider builds stay in the current code base and in CI. The consequence above that OpenSSL leaves at the `Encrypt` and TLS steps now happens with the new core.
- Besides the list in decision 5, Mayaqua keeps the memory tracker until a later decision retires it, and keeps `Encrypt` on OpenSSL and the TLS code in `Network.c` until the new core replaces them. The estimate of 25k to 30k lines is reached only then; `Encrypt` alone is about 5,400 lines today.
- Spec #30 needs the same amendment through the issue tracker: its memory, crypto and TLS user stories move to the new core or are withdrawn.

## Amendment 2026-10-13: #30 scope, the memory tracker, and CNG/Schannel deferred to the new core

The 2026-10-13 grilling fixed the scope of the Windows-native runtime migration (ticket #30) within the slim fork. The direction, header shape and wrapper-flip method of the original decision are unchanged; the step boundaries and three details are:

- **#30 stops at step 7 (DNS → `GetAddrInfoW`) and step 9 (HTTP client → WinHTTP).** Completed on branch `winnative` (PR #40): step 0/1 (`Tick64` plus `Native.h` setup), step 2 (`LOCK`/`COUNTER`/`REF`), step 3 (`EVENT`), step 4 (`THREAD`) and step 6 (`FileIO` plus the `OS` dispatch-table collapse); step 7 (DNS) and step 9 (HTTP) raced in parallel.
- **Step 5 (memory tracker) is not migrated.** Mayaqua's `KS_*` counters and the `NO MEMORY LEAKS` marker are **kept** (this reverses the original Map row, which moved the marker to the CRT debug heap). In addition, a **separate test branch** carries a Debug CI job that trials the CRT debug heap (`_CrtSetDbgFlag` / `_CrtDumpMemoryLeaks`); acceptance is that the debug-heap leak check agrees with the `KS_*` marker. The extra CI minutes are noted; the repo is private.
- **Steps 8 (`Encrypt` → CNG) and 10 (TLS → Schannel) move to the new core (ADR-0022); they are not dropped.** The new core is CNG and Schannel only.
- **Step 8, the part that is useful inside the slim fork while OpenSSL stays for TLS:** move only SHA-1, MD5, MD4, RC4, DES and the RNG to CNG, each with known-answer tests. X.509, RSA and DH stay on OpenSSL until TLS moves (step 10). The OpenSSL-engine client auth for cascades is dropped as a scope-cut ticket with its own golden diff. The legacy SE-VPN listener stays on OpenSSL until the slim fork retires.
