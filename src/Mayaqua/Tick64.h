// Tick64.h
// Header of Tick64.c

#ifndef	TICK64_H
#define	TICK64_H

#include "MayaType.h"

#define	MAX_ADJUST_TIME				1024

struct ADJUST_TIME
{
	UINT64 Tick;
	UINT64 Time;
};

struct TICK64
{
	THREAD *Thread;
	UINT64 Time64;
	UINT64 Tick64WithTime64;
	volatile bool Halt;
	LIST *AdjustTime;
};

#define	TICK64_SPAN_WIN32	1000

void InitTick64();
void FreeTick64();
void Tick64Thread(THREAD *thread, void *param);
UINT64 Tick64();
UINT64 Diff64(UINT64 a, UINT64 b);
UINT64 Tick64ToTime64(UINT64 tick);
UINT64 TickToTime(UINT64 tick);
UINT64 TickHighres64();
UINT64 TickHighresNano64(bool raw);

#endif	// TICK64_H

