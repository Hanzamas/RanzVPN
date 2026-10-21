// Tick64.c
// 64-bit real-time clock program

#include "Tick64.h"

#include "Kernel.h"
#include "Memory.h"
#include "Str.h"

static TICK64 *tk64 = NULL;
static volatile LONG64 tick64_origin = 0;

// A performance-counter count in seconds; if the counter frequency cannot be read, the count is
// taken as milliseconds (the Tick64 fallback of HiResCounter)
static double HiResTimeSpan(UINT64 diff)
{
	LARGE_INTEGER t;
	UINT64 freq;

	if (QueryPerformanceFrequency(&t) == false)
	{
		freq = 1000ULL;
	}
	else
	{
		Copy(&freq, &t, sizeof(UINT64));
	}

	return (double)diff / (double)freq;
}

// The performance counter; Tick64 if the counter cannot be read
static UINT64 HiResCounter()
{
	LARGE_INTEGER t;
	UINT64 ret;

	if (QueryPerformanceCounter(&t) == false)
	{
		return Tick64();
	}

	Copy(&ret, &t, sizeof(UINT64));

	return ret;
}

UINT64 TickHighres64()
{
	return (UINT64)(HiResTimeSpan(HiResCounter()) * 1000.0f);

}

UINT64 TickHighresNano64()
{
	UINT64 ret = 0;

	ret = (UINT64)(HiResTimeSpan(HiResCounter()) * 1000000000.0f);

	return ret;
}

UINT64 Tick64ToTime64(UINT64 tick)
{
	UINT64 ret = 0;
	if (tick == 0)
	{
		return 0;
	}
	LockList(tk64->AdjustTime);
	{
		for (INT i = ((INT)LIST_NUM(tk64->AdjustTime) - 1); i >= 0; i--)
		{
			ADJUST_TIME *t = LIST_DATA(tk64->AdjustTime, i);
			if (t->Tick <= tick)
			{
				ret = t->Time + (tick - t->Tick);
				break;
			}
		}
	}
	UnlockList(tk64->AdjustTime);
	if (ret == 0)
	{
		ret++;
	}
	return ret;
}

UINT64 Tick64()
{
	if (tick64_origin == 0)
	{
		if (InterlockedCompareExchange64(&tick64_origin, (LONG64)GetTickCount64(), 0) == 0)
		{
			return 1;
		}
	}

	return GetTickCount64() - (UINT64)tick64_origin + 1;
}

// Clock check: record a correction when the system clock moved against the tick by a span or
// more, or went back, so that Tick64ToTime64 follows the clock. It runs under the list lock,
// so two checks never interleave.
static void Tick64CheckTime()
{
	LockList(tk64->AdjustTime);
	{
		UINT64 tick64 = Tick64();
		UINT64 now = SystemTime64();

		if (now < tk64->Time64 ||
			Diff64((now - tk64->Time64) + tk64->Tick64WithTime64, tick64) >= TICK64_SPAN_WIN32)
		{
			ADJUST_TIME *t = ZeroMalloc(sizeof(ADJUST_TIME));

			t->Tick = tick64;
			t->Time = now;
			Add(tk64->AdjustTime, t);

			// Bound the correction list on a system whose clock keeps skewing
			if (LIST_NUM(tk64->AdjustTime) > MAX_ADJUST_TIME)
			{
				ADJUST_TIME *t2 = LIST_DATA(tk64->AdjustTime, 1);

				Delete(tk64->AdjustTime, t2);

				Debug("NUM_ADJUST TIME: %u\n", LIST_NUM(tk64->AdjustTime));

				Free(t2);
			}

			tk64->Time64 = now;
			tk64->Tick64WithTime64 = tick64;
		}
	}
	UnlockList(tk64->AdjustTime);
}

// Timer callback (process thread pool), every TICK64_SPAN_WIN32 ms: the clock check runs at
// time-critical priority, so that its two clock reads stay close, and the pool thread gets
// its normal priority back
static void NTAPI Tick64TimerCallback(PTP_CALLBACK_INSTANCE instance, void *param, PTP_TIMER timer)
{
	SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_TIME_CRITICAL);

	Tick64CheckTime();

	SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_NORMAL);
}

UINT64 Diff64(UINT64 a, UINT64 b)
{
	if (a > b)
	{
		return a - b;
	}
	else
	{
		return b - a;
	}
}

void InitTick64()
{
	ULARGE_INTEGER span;
	FILETIME due;
	if (tk64 != NULL)
	{
		return;
	}

	tk64 = ZeroMalloc(sizeof(TICK64));
	tk64->AdjustTime = NewList(NULL);

	// The first correction, before this returns: the time at the current tick
	ADJUST_TIME *t = ZeroMalloc(sizeof(ADJUST_TIME));
	t->Tick = Tick64();
	t->Time = SystemTime64();
	tk64->Tick64WithTime64 = t->Tick;
	tk64->Time64 = t->Time;
	Add(tk64->AdjustTime, t);

	// Then the clock check every TICK64_SPAN_WIN32 ms, from one span on (a negative due time is relative)
	tk64->Timer = CreateThreadpoolTimer(Tick64TimerCallback, NULL, NULL);
	if (tk64->Timer == NULL)
	{
		AbortExitEx("Tick64 timer create failed.");
	}

	span.QuadPart = (ULONGLONG)(-((LONGLONG)TICK64_SPAN_WIN32 * 10000LL));
	due.dwLowDateTime = span.LowPart;
	due.dwHighDateTime = span.HighPart;
	SetThreadpoolTimer(tk64->Timer, &due, TICK64_SPAN_WIN32, 0);
}

void FreeTick64()
{
	if (tk64 == NULL)
	{
		return;
	}

	// Stop the clock check, and wait for a check that is still running
	SetThreadpoolTimer(tk64->Timer, NULL, 0, 0);
	WaitForThreadpoolTimerCallbacks(tk64->Timer, TRUE);
	CloseThreadpoolTimer(tk64->Timer);
	tk64->Timer = NULL;

	for (UINT i = 0;i < LIST_NUM(tk64->AdjustTime);i++)
	{
		ADJUST_TIME *t = LIST_DATA(tk64->AdjustTime, i);
		Free(t);
	}
	ReleaseList(tk64->AdjustTime);
	Free(tk64);
	tk64 = NULL;
}

