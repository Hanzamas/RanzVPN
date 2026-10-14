// Tick64.c
// 64-bit real-time clock program

#include "Tick64.h"

#include "Kernel.h"
#include "Memory.h"
#include "Microsoft.h"
#include "Object.h"
#include "Str.h"

static TICK64 *tk64 = NULL;
static EVENT *halt_tick_event = NULL;
static volatile LONG64 tick64_origin = 0;

UINT64 TickHighres64()
{
	return (UINT64)(MsGetHiResTimeSpan(MsGetHiResCounter()) * 1000.0f);

}

UINT64 TickHighresNano64(bool raw)
{
	UINT64 ret = 0;

	ret = (UINT64)(MsGetHiResTimeSpan(MsGetHiResCounter()) * 1000000000.0f);

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
		INT i;
		for (i = ((INT)LIST_NUM(tk64->AdjustTime) - 1); i >= 0; i--)
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

static void Tick64Thread(THREAD *thread, void *param)
{
	UINT n = 0;
	bool first = false;
	bool create_first_entry = true;
	UINT tick_span;
	if (thread == NULL)
	{
		return;
	}

	MsSetThreadPriorityRealtime();

	tick_span = TICK64_SPAN_WIN32;

	while (true)
	{
		UINT tick;
		UINT64 tick64;

		tick64 = Tick64();
		tick = (UINT)tick64;

		if (create_first_entry)
		{
			ADJUST_TIME *t = ZeroMalloc(sizeof(ADJUST_TIME));
			t->Tick = tick64;
			t->Time = SystemTime64();
			tk64->Tick64WithTime64 = tick64;
			tk64->Time64 = t->Time;
			Add(tk64->AdjustTime, t);

			NoticeThreadInit(thread);
			create_first_entry = false;
		}

		n += tick_span;
		if (n >= 1000 || first == false)
		{
			UINT64 now = SystemTime64();

			if (now < tk64->Time64 ||
				Diff64((now - tk64->Time64) + tk64->Tick64WithTime64, tick64) >= tick_span)
			{
				ADJUST_TIME *t = ZeroMalloc(sizeof(ADJUST_TIME));
				LockList(tk64->AdjustTime);
				{
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
				}
				UnlockList(tk64->AdjustTime);
				tk64->Time64 = now;
				tk64->Tick64WithTime64 = tick64;
			}
			first = true;
			n = 0;
		}

		if (tk64->Halt)
		{
			break;
		}

		Wait(halt_tick_event, tick_span);
	}
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
	if (tk64 != NULL)
	{
		return;
	}

	halt_tick_event = NewEvent();

	tk64 = ZeroMalloc(sizeof(TICK64));
	tk64->AdjustTime = NewList(NULL);

	tk64->Thread = NewThread(Tick64Thread, NULL);
	WaitThreadInit(tk64->Thread);
}

void FreeTick64()
{
	UINT i;
	if (tk64 == NULL)
	{
		return;
	}

	tk64->Halt = true;
	Set(halt_tick_event);
	WaitThread(tk64->Thread, INFINITE);
	ReleaseThread(tk64->Thread);

	for (i = 0;i < LIST_NUM(tk64->AdjustTime);i++)
	{
		ADJUST_TIME *t = LIST_DATA(tk64->AdjustTime, i);
		Free(t);
	}
	ReleaseList(tk64->AdjustTime);
	Free(tk64);
	tk64 = NULL;

	ReleaseEvent(halt_tick_event);
	halt_tick_event = NULL;
}

