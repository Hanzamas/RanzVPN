// Tick64.h
// Header of Tick64.c

#ifndef TICK64_H
#define TICK64_H

#include "MayaType.h"

#define MAX_ADJUST_TIME 1024

struct ADJUST_TIME {
	UINT64 Tick;
	UINT64 Time;
};

struct TICK64 {
	PTP_TIMER Timer; // Thread pool timer that runs the clock check every TICK64_SPAN_WIN32 ms
	UINT64 Time64;
	UINT64 Tick64WithTime64;
	LIST *AdjustTime;
};

#define TICK64_SPAN_WIN32 1000

void InitTick64();
void FreeTick64();
UINT64 Tick64();
UINT64 Diff64(UINT64 a, UINT64 b);
UINT64 Tick64ToTime64(UINT64 tick);
UINT64 TickHighres64();
UINT64 TickHighresNano64();

#endif // TICK64_H

