// Native.h
// Thin header: static inline Mayaqua functions that call the Windows API directly
// Leaf header: it includes MayaType.h only, so any module header can include it

#ifndef	NATIVE_H
#define	NATIVE_H

#include "MayaType.h"

// Lock object: a recursive critical section embedded in the struct, one heap block
struct LOCK
{
	CRITICAL_SECTION CriticalSection;	// Recursive lock
	bool Ready;							// false once DeleteLock has started
};

// Counter object
struct COUNTER
{
	volatile UINT c;					// Changed only through the Interlocked functions
};

// Reference counter: the counter is embedded, so a REF is one heap block
struct REF
{
	COUNTER c;
};

// Out-of-line helpers called below (Object.c)
bool LockInner(LOCK *lock);
void UnlockInner(LOCK *lock);

// Raw lock (Object.c): the critical section behind LockInner/UnlockInner. It never touches
// the KS_ counters, because KS_INC itself takes such a lock
LOCK *NewRawLock();
bool RawLock(LOCK *lock);
void RawUnlock(LOCK *lock);
void DeleteRawLock(LOCK *lock);

// Thread ID of the calling thread
static inline UINT ThreadId()
{
	return GetCurrentThreadId();
}

// Give the rest of the time slice to another ready thread
static inline void YieldCpu()
{
	Sleep(0);
}

// Get the count value: 0 for NULL, otherwise an atomic read with a full barrier
static inline UINT Count(COUNTER *c)
{
	return (c == NULL) ? 0 : (UINT)InterlockedCompareExchange((volatile LONG *)&c->c, 0, 0);
}

// Cross-thread flag (a halt or cancel request that one thread sets and another polls): read with
// acquire and write with release semantics (ReadAcquire8 and WriteRelease8, winnt.h), so on ARM64
// the thread that sees the flag also sees everything written before it. The flags stay
// 'volatile bool'; read and write them only through these two functions
static inline bool FlagRead(volatile const bool *flag)
{
	return ReadAcquire8((CHAR const volatile *)flag) != 0;
}

static inline void FlagWrite(volatile bool *flag, bool value)
{
	WriteRelease8((CHAR volatile *)flag, value ? 1 : 0);
}

// Event object
struct EVENT
{
	REF *ref;
	void *pData;
};

// Set event: an unnamed auto-reset kernel event (NewEvent); no effect without the event or its handle
static inline void Set(EVENT *e)
{
	if (e != NULL && e->pData != NULL)
	{
		SetEvent((HANDLE)e->pData);
	}
}

#endif	// NATIVE_H
