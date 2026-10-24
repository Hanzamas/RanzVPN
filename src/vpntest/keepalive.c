// keepalive.c
// Named keepalive span test of vpntest ("keepalive" command, SEC-4 #96)
//
// GenNextKeepAliveSpan() picks the time to the next keepalive of a TCP connection: a random value
// in [a / 5, a / 2) of the session timeout a. It computes rand() % (a / 2). A client, or a cascade
// Link of a server, takes the timeout from the welcome Pack of the server it connects to, which the
// client did not clamp, so a server that sent the timeout 0 or 1 made the span divide by zero and
// crashed the process (STATUS_INTEGER_DIVIDE_BY_ZERO). The test calls GenNextKeepAliveSpan() with
// the timeouts that a conformant server sends (TIMEOUT_MIN to TIMEOUT_MAX: the span is unchanged),
// then with 0, 1 and other values outside these bounds: the span must be the one of the timeout
// clamped to [TIMEOUT_MIN, TIMEOUT_MAX]. On the old code the timeout 0 divides by zero.
// The spans came from the CRT rand(), whose state is per thread and seeded only on the init thread,
// so every new thread drew the same sequence (FND-150). Two threads now draw their spans: the two
// sequences must differ. Prints "KEEPALIVE TEST OK" only when every check passes, and frees
// everything it allocates.

#include "testlist.h"

#include "Cedar/Cedar.h"
#include "Cedar/Connection.h"
#include "Cedar/Session.h"

#include "Mayaqua/Kernel.h"
#include "Mayaqua/Memory.h"
#include "Mayaqua/Str.h"

#include <stdarg.h>

#define	KEEPALIVE_TEST_DRAWS		64		// Spans drawn per timeout

// Run state of the test
typedef struct KEEPALIVE_TEST
{
	UINT NumChecks;						// Checks run so far
	UINT NumFailed;						// Checks failed so far
	CONNECTION *Connection;				// Connection of the spans; the test sets the timeout of its session
} KEEPALIVE_TEST;

// Record one check: print [PASS], or [FAIL] with the formatted detail
static void KeepAliveTestCheck(KEEPALIVE_TEST *t, bool ok, char *what, char *detail_fmt, ...)
{
	char detail[MAX_SIZE];
	va_list args;

	t->NumChecks++;

	if (ok)
	{
		Print("  [PASS] %s\n", what);
		return;
	}

	va_start(args, detail_fmt);
	FormatArgs(detail, sizeof(detail), detail_fmt, args);
	va_end(args);

	Print("  [FAIL] %s (%s)\n", what, detail);

	t->NumFailed++;
}

// Set the session timeout to timeout and draw KEEPALIVE_TEST_DRAWS spans: each one must lie in
// [expect / 5, expect / 2), the range of the timeout expect
static void KeepAliveTestTimeout(KEEPALIVE_TEST *t, UINT timeout, UINT expect, char *what)
{
	UINT lo = expect / 5;
	UINT hi = expect / 2;
	UINT num_bad = 0;
	UINT bad_span = 0;

	t->Connection->Session->Timeout = timeout;

	for (UINT i = 0;i < KEEPALIVE_TEST_DRAWS;i++)
	{
		UINT span = GenNextKeepAliveSpan(t->Connection);

		if (span < lo || span >= hi)
		{
			num_bad++;
			bad_span = span;
		}
	}

	KeepAliveTestCheck(t, num_bad == 0, what, "timeout %u: %u of %u spans outside [%u, %u), for example %u",
		timeout, num_bad, KEEPALIVE_TEST_DRAWS, lo, hi, bad_span);
}

// Spans one thread draws, at the timeout TIMEOUT_MAX
typedef struct KEEPALIVE_TEST_THREAD
{
	CONNECTION *Connection;				// Connection of the spans, own to the thread
	UINT Spans[KEEPALIVE_TEST_DRAWS];	// Spans drawn
} KEEPALIVE_TEST_THREAD;

static void KeepAliveTestThread(THREAD *thread, void *param)
{
	KEEPALIVE_TEST_THREAD *d = (KEEPALIVE_TEST_THREAD *)param;

	for (UINT i = 0;i < KEEPALIVE_TEST_DRAWS;i++)
	{
		d->Spans[i] = GenNextKeepAliveSpan(d->Connection);
	}
}

// Two new threads draw their spans: the sequences must differ (a per-thread CRT seed made them equal)
static void KeepAliveTestThreads(KEEPALIVE_TEST *t)
{
	KEEPALIVE_TEST_THREAD d[2];
	THREAD *th[2];

	Zero(d, sizeof(d));

	for (UINT i = 0;i < 2;i++)
	{
		d[i].Connection = ZeroMalloc(sizeof(CONNECTION));
		d[i].Connection->Session = ZeroMalloc(sizeof(SESSION));
		d[i].Connection->Session->Timeout = TIMEOUT_MAX;
	}

	for (UINT i = 0;i < 2;i++)
	{
		th[i] = NewThread(KeepAliveTestThread, &d[i]);
	}

	for (UINT i = 0;i < 2;i++)
	{
		WaitThread(th[i], INFINITE);
		ReleaseThread(th[i]);
	}

	KeepAliveTestCheck(t, Cmp(d[0].Spans, d[1].Spans, sizeof(d[0].Spans)) != 0,
		"two threads: different span sequences", "both threads drew the same %u spans", KEEPALIVE_TEST_DRAWS);

	for (UINT i = 0;i < 2;i++)
	{
		Free(d[i].Connection->Session);
		Free(d[i].Connection);
	}
}

// keepalive: the keepalive span of every session timeout, also of one that a server sends out of bounds
RANZ_TEST("keepalive", keepalive_test, "Keepalive span: a session timeout out of bounds, also 0 or 1 from a server, gives the span of the clamped timeout.");
void keepalive_test(UINT num, char **arg)
{
	KEEPALIVE_TEST t;

	Zero(&t, sizeof(t));

	Print("Keepalive span test (GenNextKeepAliveSpan)\n");

	t.Connection = ZeroMalloc(sizeof(CONNECTION));
	t.Connection->Session = ZeroMalloc(sizeof(SESSION));

	// The timeouts of a conformant server: the span is the one of the timeout itself
	KeepAliveTestTimeout(&t, TIMEOUT_MIN, TIMEOUT_MIN, "timeout TIMEOUT_MIN: span in [TIMEOUT_MIN / 5, TIMEOUT_MIN / 2)");
	KeepAliveTestTimeout(&t, TIMEOUT_DEFAULT, TIMEOUT_DEFAULT, "timeout TIMEOUT_DEFAULT: span in [TIMEOUT_DEFAULT / 5, TIMEOUT_DEFAULT / 2)");
	KeepAliveTestTimeout(&t, TIMEOUT_MAX, TIMEOUT_MAX, "timeout TIMEOUT_MAX: span in [TIMEOUT_MAX / 5, TIMEOUT_MAX / 2)");

	// Below the bounds: the span of TIMEOUT_MIN (the old code divided by zero at 0 and 1)
	KeepAliveTestTimeout(&t, 0, TIMEOUT_MIN, "timeout 0: span of TIMEOUT_MIN, no divide by zero");
	KeepAliveTestTimeout(&t, 1, TIMEOUT_MIN, "timeout 1: span of TIMEOUT_MIN, no divide by zero");
	KeepAliveTestTimeout(&t, 2, TIMEOUT_MIN, "timeout 2: span of TIMEOUT_MIN");
	KeepAliveTestTimeout(&t, TIMEOUT_MIN - 1, TIMEOUT_MIN, "timeout TIMEOUT_MIN - 1: span of TIMEOUT_MIN");

	// Above the bounds: the span of TIMEOUT_MAX
	KeepAliveTestTimeout(&t, TIMEOUT_MAX + 1, TIMEOUT_MAX, "timeout TIMEOUT_MAX + 1: span of TIMEOUT_MAX");
	KeepAliveTestTimeout(&t, 0xFFFFFFFF, TIMEOUT_MAX, "timeout 0xFFFFFFFF: span of TIMEOUT_MAX");

	// Spans of two threads: no shared CRT sequence
	KeepAliveTestThreads(&t);

	Free(t.Connection->Session);
	Free(t.Connection);

	if (t.NumFailed == 0)
	{
		Print("KEEPALIVE TEST OK\n");
	}
	else
	{
		Print("KEEPALIVE TEST FAILED (%u of %u checks failed)\n", t.NumFailed, t.NumChecks);
	}
}
