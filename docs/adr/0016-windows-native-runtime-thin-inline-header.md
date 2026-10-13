# ADR-0016: Migrate the Mayaqua runtime to Windows-native primitives behind one thin inline header

**Status:** Accepted (2026-10-11). Hilmi chose the direction ("fokus ke ini migrasi ke windows native total") and the header shape ("sisain satu header inline tipis kayak Lock(x) biar kode tetap kebaca"). Execution waits for the test harness, per ADR-0002.

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
   | Memory tracker and `NO MEMORY LEAKS` | **kept as-is** (Mayaqua's `KS_*` counters and the marker stay; corrected in the 2026-10-13 amendment) — a separate test branch only trials the CRT debug heap against it |
   | `FileIO`, `OS` dispatch table, `Win32.c` backend | direct `CreateFileW` family; the dispatch table disappears once it has a single backend |
   | DNS in `Network.c` | `GetAddrInfoW` / `GetAddrInfoExW` |
   | `Encrypt.c` on OpenSSL | CNG (`BCrypt*`, `NCrypt*`) and CryptoAPI for X.509, per ADR-0007 |
   | `HTTP.c` / `Wpc.c` | WinHTTP |
   | TLS in `Network.c` | Schannel, together with the new core (ADR-0005, ADR-0007) |

   Mayaqua keeps what Windows has no equivalent for: `LIST`/`QUEUE`/`FIFO`/`BUF` containers, the `Str` subset in use, `Pack` (RPC wire format), `Cfg` (config file format), `Table` (string tables), `TcpIp` packet parsing, and a tidied `Microsoft.c` (registry, services, drivers, firewall, which are already native).
6. **Order.** `Tick64` → `LOCK`/`COUNTER`/`REF` → `EVENT` → `THREAD` → memory tracker → `FileIO`/`OS` collapse → DNS → `Encrypt` to CNG → `HTTP` to WinHTTP → TLS to Schannel last, with the new core. Each step is its own ticket with its own CI run.
7. **Prerequisite.** None of this starts before the test harness of ADR-0002 exists: an in-process server plus cascade plus vpncmd run with golden outputs, plus a stress case that exercises lock re-entry, event waits and thread teardown. The safe cleanup sweep (spec #24) runs first because it removes code the migration would otherwise have to port.

## Consequences

- Expected size: Mayaqua from about 65k lines to about 25k to 30k; Cedar is unaffected by this ADR and shrinks through spec #24 and the new core.
- Call sites keep their current names, so the diff of each migration step is concentrated in Mayaqua and the thin header, which keeps review and bisection simple.
- OpenSSL leaves the dependency list at the `Encrypt` and TLS steps, which also removes the largest vcpkg build item from CI.
- The per-primitive semantic audit (re-entrancy of each `LOCK`, reset mode and waiters of each `EVENT`, ownership of each `THREAD`) is the first task of every migration ticket; it is not done in advance here.
- Risk is concentrated in silent semantic changes (deadlock from a non-recursive lock, lost wake-up from a reset-mode change, tick wrap or jump). Those are exactly what the harness stress case must catch, which is why the harness is a hard prerequisite.

## Amendment 2026-10-13: #30 scope, the memory tracker, and CNG/Schannel deferred to the new core

The 2026-10-13 grilling fixed the scope of the Windows-native runtime migration (ticket #30) within the slim fork. The direction, header shape and wrapper-flip method of the original decision are unchanged; the step boundaries and three details are:

- **#30 stops at step 7 (DNS → `GetAddrInfoW`) and step 9 (HTTP client → WinHTTP).** Completed on branch `winnative` (PR #40): step 0/1 (`Tick64` plus `Native.h` setup), step 2 (`LOCK`/`COUNTER`/`REF`), step 3 (`EVENT`), step 4 (`THREAD`) and step 6 (`FileIO` plus the `OS` dispatch-table collapse); step 7 (DNS) and step 9 (HTTP) raced in parallel.
- **Step 5 (memory tracker) is not migrated.** Mayaqua's `KS_*` counters and the `NO MEMORY LEAKS` marker are **kept** (this reverses the original Map row, which moved the marker to the CRT debug heap). In addition, a **separate test branch** carries a Debug CI job that trials the CRT debug heap (`_CrtSetDbgFlag` / `_CrtDumpMemoryLeaks`); acceptance is that the debug-heap leak check agrees with the `KS_*` marker. The extra CI minutes are noted; the repo is private.
- **Steps 8 (`Encrypt` → CNG) and 10 (TLS → Schannel) move to the new core (ADR-0022); they are not dropped.** The new core is CNG and Schannel only.
- **Step 8, the part that is useful inside the slim fork while OpenSSL stays for TLS:** move only SHA-1, MD5, MD4, RC4, DES and the RNG to CNG, each with known-answer tests. X.509, RSA and DH stay on OpenSSL until TLS moves (step 10). The OpenSSL-engine client auth for cascades is dropped as a scope-cut ticket with its own golden diff. The legacy SE-VPN listener stays on OpenSSL until the slim fork retires.
