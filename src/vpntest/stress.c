// stress.c
// Mayaqua runtime stress test ("stress" command of vpntest)
//
// Pins the runtime semantics that the Windows-native migration (ADR-0016) must keep:
// recursive LOCK, exact COUNTER/REF counts, auto-reset EVENT, THREAD lifetime,
// monotonic Tick64, LIST under LockList and CheckDeadLock.
// Every case runs under a watchdog, so a hang fails the test with a message instead
// of blocking CI. The watchdog ends with the last case. A failed run then arms an exit
// watchdog that terminates the process if teardown (FreeCedar/FreeMayaqua, after the final
// STRESS TEST line) has not ended within 20 s, because a broken runtime can hang the exit
// too (FreeThreading waits for every THREAD reference). This also applies to a failed run
// in the interactive prompt. A passing run leaves teardown unbounded, so the CI step that
// runs vpntest should still have its own timeout.
// The [PASS] and [STEP] lines contain no timings, thread ids or pointers, so the output
// of two passing builds can be compared line by line; the [FAIL] details include
// measured values (such as milliseconds) for diagnosis. "stress timing" adds one [TIME]
// line per case.

#include "Mayaqua/Kernel.h"
#include "Mayaqua/Memory.h"
#include "Mayaqua/Object.h"
#include "Mayaqua/Str.h"
#include "Mayaqua/Tick64.h"

#include <stdarg.h>
#include <stdio.h>

// Sizes and limits, kept modest so that the whole test stays well under 30 s on the arm64 runner
#define	STRESS_NUM_THREADS		8		// Worker threads in the LOCK and COUNTER/REF cases
#define	STRESS_LOCK_LOOPS		2500	// Locked increments per LOCK worker
#define	STRESS_COUNTER_LOOPS	500		// Inc/Inc/Dec + AddRef/Release rounds per COUNTER/REF worker
#define	STRESS_PINGPONG_ROUNDS	1000	// EVENT ping-pong rounds
#define	STRESS_CHURN_THREADS	100		// Threads in each THREAD churn phase
#define	STRESS_TICK_THREADS		4		// Tick64 sampling threads
#define	STRESS_TICK_SAMPLES		2000	// Tick64 samples per sampling thread
#define	STRESS_TICK_MAX_STEP	3000	// Largest plausible step between two Tick64 samples (ms)
#define	STRESS_TICK_SLEEP		250		// Sleep used to check that Tick64 advances (ms)
#define	STRESS_LIST_THREADS		4		// LIST worker threads
#define	STRESS_LIST_KEYS		400		// Keys owned by each LIST worker (even number)
#define	STRESS_WAIT_SHORT		50		// Wait that is expected to time out (ms)
#define	STRESS_WAIT_TIMEOUT		300		// Wait used to measure the timeout accuracy (ms)
#define	STRESS_WAIT_BOUND		1500	// Upper bound of a wait that is expected to succeed quickly, short so a failure prints before the watchdog (ms)
#define	STRESS_GATE_BOUND		3000	// Fail-safe bound of a gate that the case itself opens once it created every thread (ms)
#define	STRESS_ROUND_BOUND		1000	// Upper bound of one ping-pong wait, short so a lost wake-up fails before the watchdog (ms)
#define	STRESS_SETTLE			150		// Time given to a blocked thread to (wrongly) proceed (ms)
#define	STRESS_HELPER_DELAY		100		// Delay before a helper thread acts (ms)
#define	STRESS_DEADCHECK_TIMEOUT	2000	// Timeout given to CheckDeadLock (ms)
#define	STRESS_EXIT_BOUND		20000	// Time a failed run is given to exit before it is terminated (ms)

// What the EVENT helper thread does after its delay
#define	STRESS_HELPER_CANCEL	1		// Set the WaitEx cancel flag
#define	STRESS_HELPER_SET		2		// Set the event

// Run state shared by all cases
typedef struct STRESS_CTX
{
	char *CaseName;					// Name of the running case
	bool CaseFailed;				// A check of the running case failed
	UINT NumChecks;					// Checks run so far
	UINT NumFailed;					// Checks failed so far
	bool Timing;					// Print the elapsed time of each case
} STRESS_CTX;

// Last step started by the running case, reported by the watchdog
static char *volatile stress_step = "";

// Record the step the running case is in
static void StressStep(char *step)
{
	stress_step = step;
}

// Record one check: print [PASS], or [FAIL] with the formatted detail
static bool StressCheck(STRESS_CTX *ctx, bool ok, char *what, char *detail_fmt, ...)
{
	char detail[MAX_SIZE];
	va_list args;

	ctx->NumChecks++;

	if (ok)
	{
		Print("  [PASS] %s: %s\n", ctx->CaseName, what);
		return true;
	}

	va_start(args, detail_fmt);
	FormatArgs(detail, sizeof(detail), detail_fmt, args);
	va_end(args);

	Print("  [FAIL] %s: %s (%s)\n", ctx->CaseName, what, detail);

	ctx->NumFailed++;
	ctx->CaseFailed = true;

	return false;
}

// Watchdog of one case: a native thread that does not use the Mayaqua runtime under test
typedef struct STRESS_WATCHDOG
{
	HANDLE DoneEvent;				// Set when the case returns
	HANDLE Thread;					// Native watchdog thread
	char *CaseName;					// Name of the guarded case
	UINT BudgetMs;					// Time budget of the case
} STRESS_WATCHDOG;

// Watchdog thread: if the case overruns its budget, report it and terminate the process,
// because a stuck thread would otherwise hang the process at exit (FreeThreading)
static DWORD WINAPI StressWatchdogThread(LPVOID param)
{
	STRESS_WATCHDOG *w = (STRESS_WATCHDOG *)param;
	char msg[1024];
	DWORD written = 0;
	DWORD size;
	int len;

	if (WaitForSingleObject(w->DoneEvent, w->BudgetMs) != WAIT_TIMEOUT)
	{
		return 0;
	}

	len = snprintf(msg, sizeof(msg),
		"  [FAIL] %s: did not finish within its %u ms budget (last step: %s)\n"
		"STRESS TEST FAILED (watchdog terminated the process)\n",
		w->CaseName, w->BudgetMs, stress_step);
	if (len > 0)
	{
		size = (len >= (int)sizeof(msg)) ? (DWORD)(sizeof(msg) - 1) : (DWORD)len;
		WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), msg, size, &written, NULL);
	}

	TerminateProcess(GetCurrentProcess(), 1);

	return 0;
}

// Arm the watchdog for one case
static bool StressWatchdogStart(STRESS_WATCHDOG *w, char *case_name, UINT budget_ms)
{
	w->CaseName = case_name;
	w->BudgetMs = budget_ms;
	w->Thread = NULL;
	w->DoneEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
	if (w->DoneEvent == NULL)
	{
		return false;
	}

	w->Thread = CreateThread(NULL, 0, StressWatchdogThread, w, 0, NULL);
	if (w->Thread == NULL)
	{
		CloseHandle(w->DoneEvent);
		w->DoneEvent = NULL;
		return false;
	}

	return true;
}

// Disarm the watchdog after the case returned
static void StressWatchdogStop(STRESS_WATCHDOG *w)
{
	if (w->Thread == NULL)
	{
		return;
	}

	SetEvent(w->DoneEvent);
	WaitForSingleObject(w->Thread, INFINITE);

	CloseHandle(w->Thread);
	CloseHandle(w->DoneEvent);
	w->Thread = NULL;
	w->DoneEvent = NULL;
}

// Exit watchdog thread of a failed run: if the process is still alive after
// STRESS_EXIT_BOUND ms, report it and terminate the process. It uses no Mayaqua object,
// so a normal exit simply ends it together with the process.
static DWORD WINAPI StressExitWatchdogThread(LPVOID param)
{
	char msg[256];
	DWORD written = 0;
	int len;

	Sleep(STRESS_EXIT_BOUND);

	len = snprintf(msg, sizeof(msg), "STRESS TEST FAILED (process did not exit within %u s)\n",
		(UINT)(STRESS_EXIT_BOUND / 1000));
	if (len > 0 && len < (int)sizeof(msg))
	{
		WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), msg, (DWORD)len, &written, NULL);
	}

	TerminateProcess(GetCurrentProcess(), 1);

	return 0;
}

// Arm the exit watchdog after a failed run; it is never disarmed
static void StressExitWatchdogStart()
{
	HANDLE h = CreateThread(NULL, 0, StressExitWatchdogThread, NULL, 0, NULL);

	if (h != NULL)
	{
		CloseHandle(h);
	}
}

// Read a counter protected by a lock
static UINT StressGet(LOCK *lock, UINT *p)
{
	UINT ret;

	Lock(lock);
	{
		ret = *p;
	}
	Unlock(lock);

	return ret;
}

// Add to a counter protected by a lock
static void StressAdd(LOCK *lock, UINT *p, UINT n)
{
	Lock(lock);
	{
		*p += n;
	}
	Unlock(lock);
}

// Milliseconds since start on the Tick64 clock
static UINT StressElapsed(UINT64 start)
{
	UINT64 now = Tick64();

	if (now < start)
	{
		return 0;
	}

	return (UINT)(now - start);
}

// Poll a locked counter until it reaches value; false if timeout ms pass first
static bool StressWaitCount(LOCK *lock, UINT *p, UINT value, UINT timeout)
{
	UINT64 start = Tick64();

	while (StressGet(lock, p) < value)
	{
		if (StressElapsed(start) >= timeout)
		{
			return false;
		}

		SleepThread(1);
	}

	return true;
}

// Poll a flag until it becomes true; false if timeout ms pass first
static bool StressWaitFlag(volatile bool *flag, UINT timeout)
{
	UINT64 start = Tick64();

	while (*flag == false)
	{
		if (StressElapsed(start) >= timeout)
		{
			return false;
		}

		SleepThread(1);
	}

	return true;
}

// Wait for a thread and release it. A thread still running after timeout is waited for
// without limit, so that the watchdog reports the case instead of a hang at process exit.
static bool StressJoin(THREAD *t, UINT timeout)
{
	bool ret;

	if (t == NULL)
	{
		return false;
	}

	ret = WaitThread(t, timeout);
	if (ret == false)
	{
		WaitThread(t, INFINITE);
	}

	ReleaseThread(t);

	return ret;
}

//
// Case "lock": LOCK recursion and mutual exclusion
//

typedef struct STRESS_LOCK_DATA
{
	LOCK *Lock;						// LOCK under test
	volatile UINT Value;			// Plain counter protected only by Lock
	volatile bool Trying;			// Set by the probe thread just before it calls Lock
	volatile bool Acquired;			// Set by the probe thread once it holds Lock
} STRESS_LOCK_DATA;

// Lock the LOCK depth more times on the thread that already holds it, then unlock as often
static void StressLockNested(LOCK *lock, UINT depth)
{
	if (depth == 0)
	{
		return;
	}

	Lock(lock);
	{
		StressLockNested(lock, depth - 1);
	}
	Unlock(lock);
}

// Probe thread: acquire the LOCK once and record it
static void StressLockProbeThread(THREAD *t, void *param)
{
	STRESS_LOCK_DATA *d = (STRESS_LOCK_DATA *)param;

	if (t == NULL || d == NULL)
	{
		return;
	}

	d->Trying = true;

	Lock(d->Lock);
	{
		d->Acquired = true;
	}
	Unlock(d->Lock);
}

// Worker: increment the plain counter under the LOCK, re-entering the LOCK on odd rounds
static void StressLockWorkerThread(THREAD *t, void *param)
{
	STRESS_LOCK_DATA *d = (STRESS_LOCK_DATA *)param;

	if (t == NULL || d == NULL)
	{
		return;
	}

	for (UINT i = 0;i < STRESS_LOCK_LOOPS;i++)
	{
		Lock(d->Lock);
		{
			if ((i % 2) == 1)
			{
				Lock(d->Lock);
				{
					UINT v = d->Value;
					d->Value = v + 1;
				}
				Unlock(d->Lock);
			}
			else
			{
				UINT v = d->Value;
				d->Value = v + 1;
			}
		}
		Unlock(d->Lock);
	}
}

// LOCK case
static void StressCaseLock(STRESS_CTX *ctx)
{
	STRESS_LOCK_DATA d;
	THREAD *probe;
	THREAD *workers[STRESS_NUM_THREADS];
	UINT expected;
	bool trying, acquired_twice, acquired_once, joined;

	Zero(&d, sizeof(d));
	d.Lock = NewLock();

	// The owning thread re-enters the LOCK (a non-recursive lock deadlocks here)
	StressStep("lock: the owning thread re-enters the LOCK");
	Lock(d.Lock);
	{
		StressLockNested(d.Lock, 2);
	}
	Unlock(d.Lock);
	// Marker check that always passes: reaching it is the evidence, because a non-recursive
	// LOCK hangs above and the watchdog reports that step instead
	StressCheck(ctx, true, "nested Lock/Unlock (depth 3) on the owning thread returned",
		"not reached");

	// Another thread stays blocked until every Lock has been matched by an Unlock
	StressStep("lock: probe thread against a LOCK held twice");
	Lock(d.Lock);
	Lock(d.Lock);
	probe = NewThread(StressLockProbeThread, &d);
	// Sample only once the probe is about to call Lock, so a slow thread start cannot
	// make the two checks below pass without a blocked probe
	trying = StressWaitFlag(&d.Trying, STRESS_WAIT_BOUND);
	SleepThread(STRESS_SETTLE);
	acquired_twice = d.Acquired;
	Unlock(d.Lock);
	SleepThread(STRESS_SETTLE);
	acquired_once = d.Acquired;
	Unlock(d.Lock);
	StressCheck(ctx, trying && acquired_twice == false, "another thread cannot acquire a LOCK held twice",
		"probe reached Lock %s, acquired it %s", trying ? "yes" : "no", acquired_twice ? "yes" : "no");
	StressCheck(ctx, trying && acquired_once == false, "one Unlock of a twice-locked LOCK keeps it held",
		"probe reached Lock %s, acquired it after the first Unlock %s", trying ? "yes" : "no", acquired_once ? "yes" : "no");

	StressStep("lock: probe thread after the last Unlock");
	joined = StressJoin(probe, STRESS_WAIT_BOUND);
	StressCheck(ctx, joined && d.Acquired, "another thread acquires the LOCK after the last Unlock",
		"probe finished %s, acquired %s", joined ? "yes" : "no", d.Acquired ? "yes" : "no");

	// Workers increment a plain counter under the LOCK
	StressStep("lock: workers incrementing a counter under the LOCK");
	d.Value = 0;
	for (UINT i = 0;i < STRESS_NUM_THREADS;i++)
	{
		workers[i] = NewThread(StressLockWorkerThread, &d);
	}

	StressStep("lock: joining the counter workers");
	for (UINT i = 0;i < STRESS_NUM_THREADS;i++)
	{
		StressJoin(workers[i], INFINITE);
	}

	expected = STRESS_NUM_THREADS * STRESS_LOCK_LOOPS;
	StressCheck(ctx, d.Value == expected, "concurrent increments under Lock/Unlock (half of them nested) give an exact total",
		"total %u, expected %u", d.Value, expected);

	DeleteLock(d.Lock);
}

//
// Case "counter": COUNTER and REF under contention
//

// Object guarded by a REF, freed by whoever drops the last reference
typedef struct STRESS_OBJ
{
	REF *Ref;						// Reference counter of the object
} STRESS_OBJ;

typedef struct STRESS_COUNTER_DATA
{
	COUNTER *Counter;				// COUNTER under test
	STRESS_OBJ *Obj;				// Shared object: one reference per worker plus one for the case
	LOCK *StatLock;					// Protects the statistics below
	UINT BadReturns;				// Inc/Dec/AddRef/Release returned an impossible value
	UINT LastReleases;				// Release calls that returned 0 (the object was freed)
} STRESS_COUNTER_DATA;

// Drop one reference of the shared object and free it on the last one
static void StressReleaseObj(STRESS_COUNTER_DATA *d, STRESS_OBJ *o)
{
	if (Release(o->Ref) == 0)
	{
		Free(o);
		StressAdd(d->StatLock, &d->LastReleases, 1);
	}
}

// Worker: Inc/Inc/Dec on the COUNTER and AddRef/Release on the shared object
static void StressCounterWorkerThread(THREAD *t, void *param)
{
	STRESS_COUNTER_DATA *d = (STRESS_COUNTER_DATA *)param;
	STRESS_OBJ *o;
	UINT bad = 0;
	UINT max_count = STRESS_NUM_THREADS * (STRESS_COUNTER_LOOPS + 1);
	UINT max_ref = 1 + STRESS_NUM_THREADS * 2;

	if (t == NULL || d == NULL)
	{
		return;
	}

	o = d->Obj;

	for (UINT i = 0;i < STRESS_COUNTER_LOOPS;i++)
	{
		UINT a, b, c;

		// Inc, Inc, Dec: the share of this worker never drops below 1, so Dec never reaches 0
		a = Inc(d->Counter);
		b = Inc(d->Counter);
		c = Dec(d->Counter);
		if (a == 0 || a > max_count || b == 0 || b > max_count || c == 0 || c > max_count)
		{
			bad++;
		}

		// AddRef then Release: this worker still holds its own reference afterwards
		a = AddRef(o->Ref);
		b = Release(o->Ref);
		if (a < 2 || a > max_ref || b == 0 || b >= max_ref)
		{
			bad++;
		}
	}

	StressAdd(d->StatLock, &d->BadReturns, bad);

	// Drop the reference the case gave to this worker
	StressReleaseObj(d, o);
}

// Data of the floor phases of the COUNTER/REF case
typedef struct STRESS_FLOOR_DATA
{
	COUNTER *Counter;				// COUNTER under test, shared by every worker
	bool DecPhase;					// false: each worker calls Inc; true: each worker calls Dec twice as often
	LOCK *StatLock;					// Protects the statistics below
	UINT NumNonZero;				// Inc/Dec calls that returned a value other than 0
	UINT64 Sum;						// Sum of the values that Inc/Dec returned
	volatile bool Go;				// Opens the gate once the phase created every worker
} STRESS_FLOOR_DATA;

// Worker: call Inc STRESS_COUNTER_LOOPS times, or Dec twice as often, and sum up the return values
static void StressFloorWorkerThread(THREAD *t, void *param)
{
	STRESS_FLOOR_DATA *d = (STRESS_FLOOR_DATA *)param;
	UINT num, nonzero = 0;
	UINT64 sum = 0;

	if (t == NULL || d == NULL)
	{
		return;
	}

	num = d->DecPhase ? (STRESS_COUNTER_LOOPS * 2) : STRESS_COUNTER_LOOPS;

	// Start together with the other workers, so the Inc/Dec calls contend
	StressWaitFlag(&d->Go, STRESS_GATE_BOUND);

	for (UINT i = 0;i < num;i++)
	{
		UINT v = d->DecPhase ? Dec(d->Counter) : Inc(d->Counter);

		if (v != 0)
		{
			nonzero++;
			sum += v;
		}
	}

	Lock(d->StatLock);
	{
		d->NumNonZero += nonzero;
		d->Sum += sum;
	}
	Unlock(d->StatLock);
}

// Run one floor phase on STRESS_NUM_THREADS workers and wait for all of them
static void StressFloorPhase(STRESS_FLOOR_DATA *d, bool dec_phase)
{
	THREAD *workers[STRESS_NUM_THREADS];

	d->DecPhase = dec_phase;
	d->NumNonZero = 0;
	d->Sum = 0;
	d->Go = false;

	for (UINT i = 0;i < STRESS_NUM_THREADS;i++)
	{
		workers[i] = NewThread(StressFloorWorkerThread, d);
	}

	// Open the gate only after every worker exists
	d->Go = true;

	for (UINT i = 0;i < STRESS_NUM_THREADS;i++)
	{
		StressJoin(workers[i], INFINITE);
	}
}

// COUNTER/REF case
static void StressCaseCounter(STRESS_CTX *ctx)
{
	STRESS_COUNTER_DATA d;
	STRESS_FLOOR_DATA f;
	THREAD *workers[STRESS_NUM_THREADS];
	REF *ref;
	UINT a, b, c, total, bad, expected;
	UINT64 sum;

	// Return values of a REF on one thread
	StressStep("counter: REF return values");
	ref = NewRef();
	a = AddRef(ref);
	b = Release(ref);
	c = Release(ref);
	StressCheck(ctx, a == 2 && b == 1 && c == 0, "NewRef starts at 1, AddRef and Release return the new count",
		"AddRef %u, Release %u, Release %u", a, b, c);

	Zero(&d, sizeof(d));
	d.Counter = NewCounter();
	d.StatLock = NewLock();
	d.Obj = ZeroMalloc(sizeof(STRESS_OBJ));
	d.Obj->Ref = NewRef();

	// One reference per worker, dropped by the worker itself
	StressStep("counter: workers on a shared COUNTER and REF");
	for (UINT i = 0;i < STRESS_NUM_THREADS;i++)
	{
		AddRef(d.Obj->Ref);
	}
	for (UINT i = 0;i < STRESS_NUM_THREADS;i++)
	{
		workers[i] = NewThread(StressCounterWorkerThread, &d);
	}

	// The case drops its own reference while the workers run; d.Obj is not used after this
	StressReleaseObj(&d, d.Obj);

	StressStep("counter: joining the workers");
	for (UINT i = 0;i < STRESS_NUM_THREADS;i++)
	{
		StressJoin(workers[i], INFINITE);
	}

	total = Count(d.Counter);
	expected = STRESS_NUM_THREADS * STRESS_COUNTER_LOOPS;
	StressCheck(ctx, d.BadReturns == 0, "Inc, Dec, AddRef and Release return in-range values under contention",
		"%u impossible return values", d.BadReturns);
	StressCheck(ctx, total == expected, "concurrent Inc/Inc/Dec rounds leave an exact COUNTER value",
		"count %u, expected %u", total, expected);
	StressCheck(ctx, d.LastReleases == 1, "the shared object is freed exactly once, by the last Release",
		"%u Release calls returned 0", d.LastReleases);

	// Dec counts down one by one and saturates at 0. Only a correct count is drained,
	// so a corrupted (huge) count cannot keep the case busy until the watchdog fires.
	StressStep("counter: draining the COUNTER");
	if (total == expected)
	{
		bad = 0;
		for (UINT i = 0;i < total;i++)
		{
			if (Dec(d.Counter) != (total - 1 - i))
			{
				bad++;
			}
		}
		a = Dec(d.Counter);
		b = Count(d.Counter);
		StressCheck(ctx, bad == 0 && a == 0 && b == 0, "Dec counts down to 0 and saturates there",
			"%u wrong Dec results, Dec at zero returned %u, Count %u", bad, a, b);
	}
	else
	{
		StressCheck(ctx, false, "Dec counts down to 0 and saturates there",
			"skipped, count %u is wrong", total);
	}

	DeleteCounter(d.Counter);
	DeleteLock(d.StatLock);

	// Concurrent Inc from 0 returns every new value 1..n exactly once (n non-zero returns
	// that add up to n(n+1)/2) and leaves the COUNTER at n
	StressStep("counter: concurrent Inc from 0");
	Zero(&f, sizeof(f));
	f.Counter = NewCounter();
	f.StatLock = NewLock();
	expected = STRESS_NUM_THREADS * STRESS_COUNTER_LOOPS;
	StressFloorPhase(&f, false);
	sum = (UINT64)expected * (expected + 1) / 2;
	total = Count(f.Counter);
	StressCheck(ctx, f.NumNonZero == expected && f.Sum == sum && total == expected,
		"concurrent Inc returns every new value exactly once",
		"%u non-zero returns, sum %I64u, Count %u; expected %u, %I64u, %u", f.NumNonZero, f.Sum, total, expected, sum, expected);

	// Concurrent Dec, twice as many calls as the count: the floor at 0 holds under contention.
	// Every value n-1..1 is returned exactly once, every other call returns 0, and the COUNTER
	// ends at 0 instead of wrapping around.
	StressStep("counter: concurrent Dec past the floor");
	StressFloorPhase(&f, true);
	sum = (UINT64)(expected - 1) * expected / 2;
	total = Count(f.Counter);
	a = Dec(f.Counter);
	StressCheck(ctx, f.NumNonZero == (expected - 1) && f.Sum == sum && total == 0 && a == 0,
		"concurrent Dec past 0 returns every lower value exactly once and saturates at 0",
		"%u non-zero returns, sum %I64u, Count %u, next Dec %u; expected %u, %I64u, 0, 0", f.NumNonZero, f.Sum, total, a, expected - 1, sum);

	DeleteCounter(f.Counter);
	DeleteLock(f.StatLock);
}

//
// Case "event": auto-reset EVENT semantics
//

typedef struct STRESS_EVENT_DATA
{
	EVENT *Event;					// Event the waiters and WaitEx block on
	EVENT *Ping;					// Ping-pong: case to partner
	EVENT *Pong;					// Ping-pong: partner to case
	LOCK *StatLock;					// Protects the counters below
	UINT Ready;						// Waiters about to call Wait
	UINT Woken;						// Waits that returned true
	UINT TimedOut;					// Waits that returned false
	UINT PartnerRounds;				// Ping-pong rounds completed by the partner
	volatile bool Cancel;			// Cancel flag given to WaitEx
	UINT HelperMode;				// STRESS_HELPER_CANCEL or STRESS_HELPER_SET
} STRESS_EVENT_DATA;

// Waiter: one bounded Wait on the shared event
static void StressEventWaiterThread(THREAD *t, void *param)
{
	STRESS_EVENT_DATA *d = (STRESS_EVENT_DATA *)param;
	bool ret;

	if (t == NULL || d == NULL)
	{
		return;
	}

	StressAdd(d->StatLock, &d->Ready, 1);

	ret = Wait(d->Event, STRESS_WAIT_BOUND + 500);

	if (ret)
	{
		StressAdd(d->StatLock, &d->Woken, 1);
	}
	else
	{
		StressAdd(d->StatLock, &d->TimedOut, 1);
	}
}

// Ping-pong partner: answer every Ping with a Pong
static void StressEventPartnerThread(THREAD *t, void *param)
{
	STRESS_EVENT_DATA *d = (STRESS_EVENT_DATA *)param;
	UINT rounds = 0;

	if (t == NULL || d == NULL)
	{
		return;
	}

	for (UINT i = 0;i < STRESS_PINGPONG_ROUNDS;i++)
	{
		if (Wait(d->Ping, STRESS_ROUND_BOUND) == false)
		{
			break;
		}

		rounds++;
		Set(d->Pong);
	}

	StressAdd(d->StatLock, &d->PartnerRounds, rounds);
}

// Helper: after a short delay, set the cancel flag or the event
static void StressEventHelperThread(THREAD *t, void *param)
{
	STRESS_EVENT_DATA *d = (STRESS_EVENT_DATA *)param;

	if (t == NULL || d == NULL)
	{
		return;
	}

	SleepThread(STRESS_HELPER_DELAY);

	if (d->HelperMode == STRESS_HELPER_CANCEL)
	{
		d->Cancel = true;
	}
	else
	{
		Set(d->Event);
	}
}

// Raw thread: take the mutex and end without releasing it, which abandons the mutex
static DWORD WINAPI StressAbandonMutexThread(LPVOID param)
{
	WaitForSingleObject((HANDLE)param, INFINITE);

	return 0;
}

// One Wait on an EVENT whose handle is swapped for a raw handle; the EVENT gets its own handle back
static bool StressWaitOnHandle(EVENT *e, HANDLE h)
{
	void *own = e->pData;
	bool ret;

	e->pData = h;
	ret = Wait(e, STRESS_WAIT_BOUND);
	e->pData = own;

	return ret;
}

// Wait gives false only on a time-out or when the EVENT has no handle (spec #30 keeps this):
// a failed wait (WAIT_FAILED) and an abandoned wait (WAIT_ABANDONED) give true
static void StressEventWaitResult(STRESS_CTX *ctx)
{
	EVENT *e = NewEvent();
	HANDLE h = NULL;
	HANDLE mutex;
	bool failed = false, abandoned = false;
	bool ran_failed = false, ran_abandoned = false;

	// Failed wait: a duplicate of the event handle without SYNCHRONIZE access cannot be waited on
	if (DuplicateHandle(GetCurrentProcess(), (HANDLE)e->pData, GetCurrentProcess(), &h, EVENT_MODIFY_STATE, FALSE, 0))
	{
		ran_failed = true;
		failed = StressWaitOnHandle(e, h);
		CloseHandle(h);
	}

	// Abandoned wait: a raw thread takes a mutex and ends without releasing it. A Mayaqua
	// THREAD cannot abandon it, because its pool thread outlives the job
	mutex = CreateMutexW(NULL, FALSE, NULL);
	if (mutex != NULL)
	{
		h = CreateThread(NULL, 0, StressAbandonMutexThread, mutex, 0, NULL);
		if (h != NULL)
		{
			if (WaitForSingleObject(h, STRESS_WAIT_BOUND) == WAIT_OBJECT_0)
			{
				ran_abandoned = true;
				abandoned = StressWaitOnHandle(e, mutex);
				ReleaseMutex(mutex);
			}
			CloseHandle(h);
		}
		CloseHandle(mutex);
	}

	ReleaseEvent(e);

	StressCheck(ctx, failed && abandoned, "Wait returns true for a failed wait (WAIT_FAILED) and an abandoned wait (WAIT_ABANDONED)",
		"failed wait %s, abandoned wait %s",
		ran_failed ? (failed ? "true" : "false") : "not run",
		ran_abandoned ? (abandoned ? "true" : "false") : "not run");
}

// EVENT case
static void StressCaseEvent(STRESS_CTX *ctx)
{
	STRESS_EVENT_DATA d;
	THREAD *waiters[2];
	THREAD *partner;
	THREAD *helper;
	EVENT *e2;
	UINT64 start;
	UINT elapsed, rounds, woken, refs;
	bool r1, r2;

	Zero(&d, sizeof(d));
	d.Event = NewEvent();
	d.Ping = NewEvent();
	d.Pong = NewEvent();
	d.StatLock = NewLock();

	StressStep("event: initial state");
	r1 = Wait(d.Event, STRESS_WAIT_SHORT);
	StressCheck(ctx, r1 == false, "a new EVENT is not signaled", "Wait returned true");

	StressStep("event: one Set, two Waits");
	Set(d.Event);
	r1 = Wait(d.Event, STRESS_WAIT_BOUND);
	r2 = Wait(d.Event, STRESS_WAIT_SHORT);
	StressCheck(ctx, r1 && r2 == false, "one Set satisfies one Wait and the EVENT resets itself (auto-reset)",
		"first Wait %s, second Wait %s", r1 ? "true" : "false", r2 ? "true" : "false");

	StressStep("event: two Sets, two Waits");
	Set(d.Event);
	Set(d.Event);
	r1 = Wait(d.Event, STRESS_WAIT_BOUND);
	r2 = Wait(d.Event, STRESS_WAIT_SHORT);
	StressCheck(ctx, r1 && r2 == false, "two Sets before a Wait do not accumulate",
		"first Wait %s, second Wait %s", r1 ? "true" : "false", r2 ? "true" : "false");

	StressStep("event: Wait timeout accuracy");
	start = Tick64();
	r1 = Wait(d.Event, STRESS_WAIT_TIMEOUT);
	elapsed = StressElapsed(start);
	StressCheck(ctx, r1 == false && elapsed >= (STRESS_WAIT_TIMEOUT - 50) && elapsed <= (STRESS_WAIT_TIMEOUT + 2000),
		"Wait on an unset EVENT returns false after about its timeout",
		"returned %s after %u ms for a %u ms timeout", r1 ? "true" : "false", elapsed, STRESS_WAIT_TIMEOUT);

	// One Set wakes exactly one of two waiting threads (a manual-reset event wakes both)
	StressStep("event: one Set with two waiting threads");
	for (UINT i = 0;i < 2;i++)
	{
		waiters[i] = NewThread(StressEventWaiterThread, &d);
	}
	r1 = StressWaitCount(d.StatLock, &d.Ready, 2, STRESS_WAIT_BOUND);
	SleepThread(STRESS_WAIT_SHORT);
	Set(d.Event);
	r2 = StressWaitCount(d.StatLock, &d.Woken, 1, STRESS_WAIT_BOUND);
	SleepThread(STRESS_SETTLE);
	woken = StressGet(d.StatLock, &d.Woken);
	StressCheck(ctx, r1 && r2 && woken == 1, "one Set wakes exactly one of two waiting threads",
		"waiters ready %s, woken %u", r1 ? "yes" : "no", woken);

	Set(d.Event);
	StressStep("event: joining the waiting threads");
	for (UINT i = 0;i < 2;i++)
	{
		StressJoin(waiters[i], INFINITE);
	}
	StressCheck(ctx, d.Woken == 2 && d.TimedOut == 0, "a second Set wakes the remaining waiting thread",
		"woken %u, timed out %u", d.Woken, d.TimedOut);
	r1 = Wait(d.Event, STRESS_WAIT_SHORT);
	StressCheck(ctx, r1 == false, "no wake-up is left over once both waiting threads consumed theirs",
		"Wait returned true");

	// Ping-pong between two threads over two events
	StressStep("event: ping-pong between two threads");
	partner = NewThread(StressEventPartnerThread, &d);
	rounds = 0;
	for (UINT i = 0;i < STRESS_PINGPONG_ROUNDS;i++)
	{
		Set(d.Ping);
		if (Wait(d.Pong, STRESS_ROUND_BOUND) == false)
		{
			break;
		}
		rounds++;
	}

	StressStep("event: joining the ping-pong partner");
	StressJoin(partner, INFINITE);
	r1 = Wait(d.Ping, STRESS_WAIT_SHORT);
	r2 = Wait(d.Pong, STRESS_WAIT_SHORT);
	StressCheck(ctx, rounds == STRESS_PINGPONG_ROUNDS && d.PartnerRounds == STRESS_PINGPONG_ROUNDS && r1 == false && r2 == false,
		"ping-pong over two EVENTs completes every round without a lost or extra wake-up",
		"case %u, partner %u of %u rounds, stray ping %s, stray pong %s",
		rounds, d.PartnerRounds, STRESS_PINGPONG_ROUNDS, r1 ? "yes" : "no", r2 ? "yes" : "no");

	// WaitEx returns when its cancel flag is set
	StressStep("event: WaitEx with a cancel flag");
	d.Cancel = false;
	d.HelperMode = STRESS_HELPER_CANCEL;
	helper = NewThread(StressEventHelperThread, &d);
	start = Tick64();
	r1 = WaitEx(d.Event, STRESS_WAIT_BOUND, &d.Cancel);
	elapsed = StressElapsed(start);
	StressJoin(helper, INFINITE);
	StressCheck(ctx, r1 == false && elapsed < (STRESS_WAIT_BOUND - 500), "WaitEx returns false soon after its cancel flag is set",
		"returned %s after %u ms", r1 ? "true" : "false", elapsed);

	// WaitEx returns when another thread sets the event
	StressStep("event: WaitEx woken by Set");
	d.HelperMode = STRESS_HELPER_SET;
	helper = NewThread(StressEventHelperThread, &d);
	start = Tick64();
	r1 = WaitEx(d.Event, STRESS_WAIT_BOUND, NULL);
	elapsed = StressElapsed(start);
	StressJoin(helper, INFINITE);
	StressCheck(ctx, r1 && elapsed < (STRESS_WAIT_BOUND - 500), "WaitEx returns true when another thread sets the EVENT",
		"returned %s after %u ms", r1 ? "true" : "false", elapsed);

	// WaitEx times out
	StressStep("event: WaitEx timeout");
	start = Tick64();
	r1 = WaitEx(d.Event, STRESS_WAIT_TIMEOUT, NULL);
	elapsed = StressElapsed(start);
	StressCheck(ctx, r1 == false && elapsed >= (STRESS_WAIT_TIMEOUT - 50) && elapsed <= (STRESS_WAIT_TIMEOUT + 2000),
		"WaitEx on an unset EVENT returns false after about its timeout",
		"returned %s after %u ms for a %u ms timeout", r1 ? "true" : "false", elapsed, STRESS_WAIT_TIMEOUT);

	// The EVENT is owned through its REF
	// A wrongly freed EVENT has a closed handle, on which every Wait returns true (WAIT_FAILED):
	// the second Wait must time out to prove the EVENT is still a live auto-reset event
	StressStep("event: reference counting");
	e2 = NewEvent();
	refs = AddRef(e2->ref);
	ReleaseEvent(e2);
	Set(e2);
	r1 = Wait(e2, STRESS_WAIT_BOUND);
	r2 = Wait(e2, STRESS_WAIT_SHORT);
	ReleaseEvent(e2);
	StressCheck(ctx, refs == 2 && r1 && r2 == false, "an EVENT stays usable while a reference added with AddRef remains",
		"AddRef returned %u, Wait after Set %s, second Wait %s", refs, r1 ? "true" : "false", r2 ? "true" : "false");

	StressStep("event: Wait result of a failed and an abandoned wait");
	StressEventWaitResult(ctx);

	ReleaseEvent(d.Event);
	ReleaseEvent(d.Ping);
	ReleaseEvent(d.Pong);
	DeleteLock(d.StatLock);
}

//
// Case "thread": THREAD churn
//

typedef struct STRESS_THREAD_DATA
{
	LOCK *StatLock;					// Protects Ran
	UINT Ran;						// Thread procedures that ran to their end
	volatile bool Go;				// Releases the gated threads
} STRESS_THREAD_DATA;

// Short thread: count itself and end
static void StressChurnQuickThread(THREAD *t, void *param)
{
	STRESS_THREAD_DATA *d = (STRESS_THREAD_DATA *)param;

	if (t == NULL || d == NULL)
	{
		return;
	}

	StressAdd(d->StatLock, &d->Ran, 1);
}

// Gated thread: report its initialization, wait for the gate, count itself and end
static void StressChurnGatedThread(THREAD *t, void *param)
{
	STRESS_THREAD_DATA *d = (STRESS_THREAD_DATA *)param;

	if (t == NULL || d == NULL)
	{
		return;
	}

	NoticeThreadInit(t);

	StressWaitFlag(&d->Go, STRESS_GATE_BOUND);

	StressAdd(d->StatLock, &d->Ran, 1);
}

// Data shared with the threads that their creator releases while they run.
// Owned through Ref (one reference per thread plus one for the case) and freed by the
// last Release, so DeleteLock never races a thread that is still inside Unlock.
typedef struct STRESS_DETACH_DATA
{
	REF *Ref;						// References to this structure
	LOCK *StatLock;					// Protects the counters below
	UINT Ran;						// Thread procedures that passed the gate
	UINT BadParam;					// Procedures that read a wrong t->param after the release
	volatile bool Go;				// Opens the gate once the creator released every THREAD
} STRESS_DETACH_DATA;

// Drop one reference of the detach data and free it on the last one
static void StressReleaseDetach(STRESS_DETACH_DATA *d)
{
	if (Release(d->Ref) == 0)
	{
		DeleteLock(d->StatLock);
		Free(d);
	}
}

// Released thread: wait for the gate, which opens only after the creator called
// ReleaseThread on this THREAD, then use the THREAD, count itself and drop its reference
static void StressChurnReleasedThread(THREAD *t, void *param)
{
	STRESS_DETACH_DATA *d = (STRESS_DETACH_DATA *)param;

	if (t == NULL || d == NULL)
	{
		return;
	}

	StressWaitFlag(&d->Go, STRESS_GATE_BOUND);

	Lock(d->StatLock);
	{
		d->Ran++;

		// Deliberate dependency on the THREAD field param: a THREAD freed by its creator's
		// ReleaseThread can show a wrong value here. The THREAD step of ADR-0016 must keep
		// the field or update this line.
		if (t->param != param)
		{
			d->BadParam++;
		}
	}
	Unlock(d->StatLock);

	StressReleaseDetach(d);
}

// THREAD case
static void StressCaseThread(STRESS_CTX *ctx)
{
	STRESS_THREAD_DATA d;
	STRESS_DETACH_DATA *dd;
	THREAD *threads[STRESS_CHURN_THREADS];
	THREAD *probe;
	UINT joined, ran_early, ran, bad_param, refs_before, refs_after;
	bool all_ran, running, finished;

	Zero(&d, sizeof(d));
	d.StatLock = NewLock();

	// Threads that end before WaitThread is called
	StressStep("thread: creating short threads");
	for (UINT i = 0;i < STRESS_CHURN_THREADS;i++)
	{
		threads[i] = NewThread(StressChurnQuickThread, &d);
	}

	StressStep("thread: waiting until every short thread has run");
	all_ran = StressWaitCount(d.StatLock, &d.Ran, STRESS_CHURN_THREADS, STRESS_WAIT_BOUND);
	SleepThread(STRESS_WAIT_SHORT);

	StressStep("thread: joining threads that already ended");
	joined = 0;
	for (UINT i = 0;i < STRESS_CHURN_THREADS;i++)
	{
		if (StressJoin(threads[i], STRESS_WAIT_BOUND))
		{
			joined++;
		}
	}
	StressCheck(ctx, all_ran && joined == STRESS_CHURN_THREADS && d.Ran == STRESS_CHURN_THREADS,
		"WaitThread returns true for threads that ended before it was called",
		"ran %u, joined %u of %u", d.Ran, joined, STRESS_CHURN_THREADS);

	// Threads that are still running when WaitThread is called
	d.Ran = 0;
	d.Go = false;
	StressStep("thread: creating gated threads (NoticeThreadInit/WaitThreadInit)");
	for (UINT i = 0;i < STRESS_CHURN_THREADS;i++)
	{
		threads[i] = NewThread(StressChurnGatedThread, &d);
		WaitThreadInit(threads[i]);
	}

	running = (WaitThread(threads[0], 0) == false);
	ran_early = StressGet(d.StatLock, &d.Ran);
	StressCheck(ctx, running && ran_early == 0, "WaitThread with a zero timeout returns false while the thread runs",
		"WaitThread returned %s, %u threads passed the gate early", running ? "false" : "true", ran_early);

	d.Go = true;
	StressStep("thread: joining gated threads");
	joined = 0;
	for (UINT i = 0;i < STRESS_CHURN_THREADS;i++)
	{
		if (StressJoin(threads[i], STRESS_WAIT_BOUND))
		{
			joined++;
		}
	}
	StressCheck(ctx, joined == STRESS_CHURN_THREADS && d.Ran == STRESS_CHURN_THREADS,
		"WaitThread returns true for every thread that ends while it waits",
		"ran %u, joined %u of %u", d.Ran, joined, STRESS_CHURN_THREADS);

	// ReleaseThread drops exactly one reference. A ReleaseThread that keeps its reference
	// passes every other check, but the pool thread then waits for the last holder forever
	// and the process hangs at exit (FreeThreading), after the test output is complete.
	// The thread is held at its gate, so no other reference changes while counting.
	d.Ran = 0;
	d.Go = false;
	StressStep("thread: ReleaseThread drops one reference");
	probe = NewThread(StressChurnGatedThread, &d);
	WaitThreadInit(probe);
	refs_before = AddRef(probe->ref);
	ReleaseThread(probe);
	// Read the count through the public REF API only (AddRef returns the new count)
	refs_after = AddRef(probe->ref) - 1;
	Release(probe->ref);
	d.Go = true;
	finished = StressJoin(probe, STRESS_WAIT_BOUND);
	StressCheck(ctx, refs_after + 1 == refs_before && finished && d.Ran == 1,
		"ReleaseThread drops exactly one reference of a THREAD (a kept reference hangs the process at exit)",
		"AddRef returned %u, count after ReleaseThread %u, thread finished %s",
		refs_before, refs_after, finished ? "yes" : "no");

	// Threads that the creator releases while they still run, without WaitThread
	// (the NewThread then ReleaseThread pattern of Cedar). ReleaseThread must not wait
	// for the thread, and the THREAD must stay valid for its procedure until it ends.
	// A ReleaseThread that waits for the thread hangs here and the watchdog reports it.
	dd = ZeroMalloc(sizeof(STRESS_DETACH_DATA));
	dd->Ref = NewRef();
	dd->StatLock = NewLock();
	StressStep("thread: releasing gated threads while they run");
	for (UINT i = 0;i < STRESS_CHURN_THREADS;i++)
	{
		THREAD *t;

		AddRef(dd->Ref);
		t = NewThread(StressChurnReleasedThread, dd);
		ReleaseThread(t);
	}
	ran_early = StressGet(dd->StatLock, &dd->Ran);

	dd->Go = true;
	StressStep("thread: waiting for the released threads");
	all_ran = StressWaitCount(dd->StatLock, &dd->Ran, STRESS_CHURN_THREADS, STRESS_WAIT_BOUND);
	ran = StressGet(dd->StatLock, &dd->Ran);
	bad_param = StressGet(dd->StatLock, &dd->BadParam);
	StressCheck(ctx, ran_early == 0, "ReleaseThread on a running thread returns without waiting for it",
		"%u threads passed the gate before the last ReleaseThread", ran_early);
	StressCheck(ctx, all_ran && ran == STRESS_CHURN_THREADS && bad_param == 0,
		"threads released while they run still run to the end with a valid THREAD",
		"ran %u of %u, %u read a wrong t->param", ran, STRESS_CHURN_THREADS, bad_param);

	// The threads still holding a reference free the data when they end
	StressReleaseDetach(dd);

	DeleteLock(d.StatLock);
}

//
// Case "tick": Tick64 monotonicity and rate
//

typedef struct STRESS_TICK_DATA
{
	LOCK *Lock;						// Orders the shared samples and protects the fields below
	UINT64 SharedLast;				// Last value read under Lock by any thread
	UINT Backwards;					// Samples lower than the previous one
	UINT Jumps;						// Steps larger than STRESS_TICK_MAX_STEP
	UINT Zeros;						// Samples equal to 0
} STRESS_TICK_DATA;

// Sampler: read Tick64 in a loop, alone and under the shared LOCK
static void StressTickSamplerThread(THREAD *t, void *param)
{
	STRESS_TICK_DATA *d = (STRESS_TICK_DATA *)param;
	UINT64 last = 0;
	UINT backwards = 0, jumps = 0, zeros = 0;

	if (t == NULL || d == NULL)
	{
		return;
	}

	for (UINT i = 0;i < STRESS_TICK_SAMPLES;i++)
	{
		UINT64 now = Tick64();

		if (now == 0)
		{
			zeros++;
		}

		if (i != 0)
		{
			if (now < last)
			{
				backwards++;
			}
			else if ((now - last) > STRESS_TICK_MAX_STEP)
			{
				jumps++;
			}
		}

		last = now;

		if ((i % 16) == 0)
		{
			// Samples taken under one LOCK by all threads must not go backwards either
			Lock(d->Lock);
			{
				UINT64 shared = Tick64();

				if (shared < d->SharedLast)
				{
					d->Backwards++;
				}

				d->SharedLast = shared;
			}
			Unlock(d->Lock);
		}

		if ((i % 100) == 99)
		{
			SleepThread(1);
		}
	}

	Lock(d->Lock);
	{
		d->Backwards += backwards;
		d->Jumps += jumps;
		d->Zeros += zeros;
	}
	Unlock(d->Lock);
}

// Tick64 case
static void StressCaseTick(STRESS_CTX *ctx)
{
	STRESS_TICK_DATA d;
	THREAD *samplers[STRESS_TICK_THREADS];
	UINT64 first, t0, t1, advanced;

	Zero(&d, sizeof(d));
	d.Lock = NewLock();

	StressStep("tick: sampling threads");
	first = Tick64();
	for (UINT i = 0;i < STRESS_TICK_THREADS;i++)
	{
		samplers[i] = NewThread(StressTickSamplerThread, &d);
	}

	StressStep("tick: joining the sampling threads");
	for (UINT i = 0;i < STRESS_TICK_THREADS;i++)
	{
		StressJoin(samplers[i], INFINITE);
	}

	StressCheck(ctx, d.Zeros == 0 && first != 0, "Tick64 never returns 0",
		"%u zero samples", d.Zeros);
	StressCheck(ctx, d.Backwards == 0, "Tick64 never goes backwards, per thread and across threads ordered by a LOCK",
		"%u backward steps", d.Backwards);
	StressCheck(ctx, d.Jumps == 0, "Tick64 does not jump between samples (a false 32-bit wrap shows as a 2^32 ms step)",
		"%u steps over %u ms", d.Jumps, STRESS_TICK_MAX_STEP);

	// Tick64 advances by about the time slept
	StressStep("tick: Tick64 across a sleep");
	{
		UINT64 g0, g1, native;

		g0 = GetTickCount64();
		t0 = Tick64();
		SleepThread(STRESS_TICK_SLEEP);
		t1 = Tick64();
		g1 = GetTickCount64();

		advanced = (t1 >= t0) ? (t1 - t0) : 0;
		StressCheck(ctx, t1 >= t0 && advanced >= (STRESS_TICK_SLEEP - 50) && advanced <= (STRESS_TICK_SLEEP + 1750),
			"Tick64 advances by about the time slept",
			"advanced %u ms over a %u ms sleep", (UINT)advanced, STRESS_TICK_SLEEP);

		// The GetTickCount64 reads bracket the Tick64 reads: only clock granularity lets Tick64
		// measure more, and a preemption between two reads only lets GetTickCount64 measure more
		native = (g1 >= g0) ? (g1 - g0) : 0;
		StressCheck(ctx, t1 >= t0 && advanced <= (native + 100) && native <= (advanced + 300),
			"Tick64 and GetTickCount64 agree on the elapsed time",
			"Tick64 %u ms, GetTickCount64 %u ms", (UINT)advanced, (UINT)native);
	}

	DeleteLock(d.Lock);
}

//
// Case "list": LIST under LockList/UnlockList
//

typedef struct STRESS_ITEM
{
	UINT Key;						// Sort key
} STRESS_ITEM;

typedef struct STRESS_LIST_DATA
{
	LIST *List;						// LIST under test
	LOCK *StatLock;					// Protects the fields below
	UINT NextIndex;					// Hands each worker its own key range
	UINT Errors;					// Wrong Search or Delete results
} STRESS_LIST_DATA;

// Compare two STRESS_ITEM entries by key
static int StressCompareItem(void *p1, void *p2)
{
	STRESS_ITEM *a, *b;

	if (p1 == NULL || p2 == NULL)
	{
		return 0;
	}

	a = *(STRESS_ITEM **)p1;
	b = *(STRESS_ITEM **)p2;
	if (a == NULL || b == NULL)
	{
		return 0;
	}

	if (a->Key > b->Key)
	{
		return 1;
	}
	if (a->Key < b->Key)
	{
		return -1;
	}

	return 0;
}

// Search a key; the caller holds the list lock
static STRESS_ITEM *StressSearchKey(LIST *o, UINT key)
{
	STRESS_ITEM probe;

	probe.Key = key;

	return (STRESS_ITEM *)Search(o, &probe);
}

// Worker: add its keys while searching, then delete its odd keys
static void StressListWorkerThread(THREAD *t, void *param)
{
	STRESS_LIST_DATA *d = (STRESS_LIST_DATA *)param;
	UINT index, base, errors = 0;
	bool use_add;

	if (t == NULL || d == NULL)
	{
		return;
	}

	Lock(d->StatLock);
	{
		index = d->NextIndex++;
	}
	Unlock(d->StatLock);

	base = index * STRESS_LIST_KEYS;

	// Odd workers append with Add (which leaves the list unsorted), even workers use Insert
	use_add = ((index % 2) == 1);

	for (UINT j = 0;j < STRESS_LIST_KEYS;j++)
	{
		STRESS_ITEM *item = Malloc(sizeof(STRESS_ITEM));
		STRESS_ITEM *found;
		bool nested = ((j % 8) == 0);

		item->Key = base + j;

		LockList(d->List);
		{
			if (nested)
			{
				// Re-enter the list lock on the same thread
				LockList(d->List);
			}

			if (use_add)
			{
				Add(d->List, item);
			}
			else
			{
				Insert(d->List, item);
			}

			found = StressSearchKey(d->List, base + j / 2);
			if (found == NULL || found->Key != (base + j / 2))
			{
				errors++;
			}

			if (nested)
			{
				UnlockList(d->List);
			}
		}
		UnlockList(d->List);
	}

	for (UINT j = 1;j < STRESS_LIST_KEYS;j += 2)
	{
		STRESS_ITEM *found;
		STRESS_ITEM *again;
		bool deleted = false;

		LockList(d->List);
		{
			found = StressSearchKey(d->List, base + j);
			if (found != NULL)
			{
				deleted = Delete(d->List, found);
			}

			again = StressSearchKey(d->List, base + j);
		}
		UnlockList(d->List);

		if (found == NULL || found->Key != (base + j) || deleted == false || again != NULL)
		{
			errors++;
		}

		if (found != NULL && deleted)
		{
			Free(found);
		}
	}

	StressAdd(d->StatLock, &d->Errors, errors);
}

// LIST case
static void StressCaseList(STRESS_CTX *ctx)
{
	STRESS_LIST_DATA d;
	THREAD *workers[STRESS_LIST_THREADS];
	UINT num, wrong = 0;
	UINT half = STRESS_LIST_KEYS / 2;
	UINT expected_num = STRESS_LIST_THREADS * half;

	Zero(&d, sizeof(d));
	d.List = NewList(StressCompareItem);
	d.StatLock = NewLock();

	StressStep("list: workers adding, searching and deleting under LockList");
	for (UINT i = 0;i < STRESS_LIST_THREADS;i++)
	{
		workers[i] = NewThread(StressListWorkerThread, &d);
	}

	StressStep("list: joining the workers");
	for (UINT i = 0;i < STRESS_LIST_THREADS;i++)
	{
		StressJoin(workers[i], INFINITE);
	}

	StressCheck(ctx, d.Errors == 0, "concurrent Insert/Add/Search/Delete under LockList find and remove the right items",
		"%u wrong results", d.Errors);

	StressStep("list: checking the final contents");
	LockList(d.List);
	{
		Sort(d.List);
		num = LIST_NUM(d.List);

		for (UINT i = 0;i < num;i++)
		{
			STRESS_ITEM *item = LIST_DATA(d.List, i);
			UINT expected = (i / half) * STRESS_LIST_KEYS + (i % half) * 2;

			if (i >= expected_num || item->Key != expected)
			{
				wrong++;
			}
		}
	}
	UnlockList(d.List);

	StressCheck(ctx, num == expected_num && wrong == 0, "the LIST ends with exactly the even keys of every worker, in order",
		"%u items (expected %u), %u misplaced", num, expected_num, wrong);

	for (UINT i = 0;i < LIST_NUM(d.List);i++)
	{
		Free(LIST_DATA(d.List, i));
	}

	ReleaseList(d.List);
	DeleteLock(d.StatLock);
}

//
// Case "deadcheck": CheckDeadLock, only on locks that are or become free
// (CheckDeadLock aborts the process when its timeout expires, so it is never given a stuck lock)
//

typedef struct STRESS_DEADCHECK_DATA
{
	LOCK *Lock;						// LOCK given to CheckDeadLock
	volatile bool Holding;			// The holder thread owns Lock
} STRESS_DEADCHECK_DATA;

// Holder: take the LOCK twice, then give it back one level at a time
static void StressDeadCheckHolderThread(THREAD *t, void *param)
{
	STRESS_DEADCHECK_DATA *d = (STRESS_DEADCHECK_DATA *)param;

	if (t == NULL || d == NULL)
	{
		return;
	}

	Lock(d->Lock);
	Lock(d->Lock);
	d->Holding = true;

	SleepThread(STRESS_HELPER_DELAY);
	Unlock(d->Lock);

	SleepThread(STRESS_HELPER_DELAY);
	d->Holding = false;
	Unlock(d->Lock);
}

// CheckDeadLock case
static void StressCaseDeadCheck(STRESS_CTX *ctx)
{
	STRESS_DEADCHECK_DATA d;
	THREAD *holder;
	UINT64 start;
	UINT elapsed;
	bool ready, still_holding;

	Zero(&d, sizeof(d));
	d.Lock = NewLock();

	// On timeout CheckDeadLock calls AbortExitEx, whose message goes to the buffered CRT stdout
	// and is lost on a pipe. Print writes unbuffered, so the [STEP] line shows where the run died.
	StressStep("deadcheck: CheckDeadLock on a free LOCK");
	Print("  [STEP] deadcheck: CheckDeadLock on a free LOCK (aborts the process on timeout)\n");
	start = Tick64();
	CheckDeadLock(d.Lock, STRESS_DEADCHECK_TIMEOUT, "stress: free LOCK");
	elapsed = StressElapsed(start);
	StressCheck(ctx, elapsed < STRESS_DEADCHECK_TIMEOUT, "CheckDeadLock returns for a free LOCK",
		"returned after %u ms", elapsed);

	StressStep("deadcheck: CheckDeadLock on a LOCK another thread holds twice");
	holder = NewThread(StressDeadCheckHolderThread, &d);
	ready = StressWaitFlag(&d.Holding, STRESS_WAIT_BOUND);
	if (ready)
	{
		Print("  [STEP] deadcheck: CheckDeadLock on a LOCK held twice by another thread (aborts the process on timeout)\n");
		CheckDeadLock(d.Lock, STRESS_DEADCHECK_TIMEOUT, "stress: LOCK held twice by another thread");
	}
	still_holding = d.Holding;

	StressStep("deadcheck: joining the holder thread");
	StressJoin(holder, INFINITE);
	StressCheck(ctx, ready && still_holding == false, "CheckDeadLock waits for the last Unlock of a LOCK another thread holds twice",
		"holder ready %s, still holding when CheckDeadLock returned %s", ready ? "yes" : "no", still_holding ? "yes" : "no");

	DeleteLock(d.Lock);
}

//
// Case table and entry point
//

// Case procedure
typedef void (STRESS_CASE_PROC)(STRESS_CTX *ctx);

typedef struct STRESS_CASE
{
	char *Name;						// Name used on the command line and in the output
	STRESS_CASE_PROC *Proc;			// Case procedure
	UINT BudgetMs;					// Watchdog budget (the budgets add up to 30 s)
} STRESS_CASE;

// Cases in the order they run
static STRESS_CASE stress_cases[] =
{
	{"lock", StressCaseLock, 4000},
	{"counter", StressCaseCounter, 3000},
	{"event", StressCaseEvent, 7000},
	{"thread", StressCaseThread, 5000},
	{"tick", StressCaseTick, 4000},
	{"list", StressCaseList, 4000},
	{"deadcheck", StressCaseDeadCheck, 3000},
};

#define	STRESS_NUM_CASES	((UINT)(sizeof(stress_cases) / sizeof(stress_cases[0])))

// Mayaqua runtime stress test: stress [timing] [case ...]
void stress_test(UINT num, char **arg)
{
	STRESS_CTX ctx;
	bool selected[sizeof(stress_cases) / sizeof(stress_cases[0])];
	bool filter = false;
	bool bad_arg = false;
	char failed[MAX_SIZE];

	Zero(&ctx, sizeof(ctx));
	Zero(selected, sizeof(selected));
	failed[0] = 0;

	for (UINT i = 0;i < num;i++)
	{
		bool known = false;

		if (StrCmpi(arg[i], "timing") == 0)
		{
			ctx.Timing = true;
			continue;
		}

		for (UINT j = 0;j < STRESS_NUM_CASES;j++)
		{
			if (StrCmpi(arg[i], stress_cases[j].Name) == 0)
			{
				selected[j] = true;
				filter = true;
				known = true;
			}
		}

		if (known == false)
		{
			Print("Unknown stress case: %s\n", arg[i]);
			bad_arg = true;
		}
	}

	Print("Mayaqua runtime stress test (LOCK, COUNTER/REF, EVENT, THREAD, Tick64, LIST, CheckDeadLock)\n");

	if (bad_arg)
	{
		Print("Usage: stress [timing] [case ...]\nCases:");
		for (UINT j = 0;j < STRESS_NUM_CASES;j++)
		{
			Print(" %s", stress_cases[j].Name);
		}
		Print("\nSTRESS TEST FAILED (bad argument)\n");
		return;
	}

	for (UINT i = 0;i < STRESS_NUM_CASES;i++)
	{
		STRESS_CASE *c = &stress_cases[i];
		STRESS_WATCHDOG w;
		UINT64 start;
		UINT elapsed;

		if (filter && selected[i] == false)
		{
			continue;
		}

		ctx.CaseName = c->Name;
		ctx.CaseFailed = false;
		StressStep("starting the case");

		if (StressWatchdogStart(&w, c->Name, c->BudgetMs) == false)
		{
			StressCheck(&ctx, false, "the watchdog thread starts", "native thread creation failed");
		}
		else
		{
			start = Tick64();
			c->Proc(&ctx);
			elapsed = StressElapsed(start);

			StressWatchdogStop(&w);

			if (ctx.Timing)
			{
				Print("  [TIME] %s: %u ms\n", c->Name, elapsed);
			}
		}

		if (ctx.CaseFailed)
		{
			StrCat(failed, sizeof(failed), " ");
			StrCat(failed, sizeof(failed), c->Name);
		}
	}

	if (ctx.NumFailed == 0)
	{
		Print("STRESS TEST OK\n");
	}
	else
	{
		Print("STRESS TEST FAILED (%u of %u checks failed, in:%s)\n", ctx.NumFailed, ctx.NumChecks, failed);

		// A failed case can leave a THREAD reference behind that hangs the process exit
		StressExitWatchdogStart();
	}
}
