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
#ifdef	_DEBUG
	char *FileName;
	UINT Line;
	UINT ThreadId;
#endif	// _DEBUG
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

// Get the count value: 0 for NULL, otherwise an atomic read with a full barrier
static inline UINT Count(COUNTER *c)
{
	return (c == NULL) ? 0 : (UINT)InterlockedCompareExchange((volatile LONG *)&c->c, 0, 0);
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
