// SoftEther VPN Source Code - Developer Edition Master Branch
// Mayaqua Kernel


// Object.h
// Header of Object.c

#ifndef	OBJECT_H
#define	OBJECT_H

#include "MayaType.h"
#include "Native.h"

// Constants
#define	OBJECT_ALLOC_FAIL_SLEEP_TIME		150
#define	OBJECT_ALLOC__MAX_RETRY				30

// Deadlock detection
struct DEADCHECK
{
	LOCK *Lock;
	UINT Timeout;
	bool Unlocked;
};


// Function prototype
LOCK *NewLock();
LOCK *NewLockMain();
void DeleteLock(LOCK *lock);
COUNTER *NewCounter();
void DeleteCounter(COUNTER *c);
UINT Inc(COUNTER *c);
UINT Dec(COUNTER *c);
UINT Release(REF *ref);
UINT AddRef(REF *ref);
REF *NewRef();
EVENT *NewEvent();
void ReleaseEvent(EVENT *e);
void CleanupEvent(EVENT *e);
bool Wait(EVENT *e, UINT timeout);
bool WaitEx(EVENT *e, UINT timeout, volatile bool *cancel);
void CheckDeadLock(LOCK *lock, UINT timeout, char *name);
void CheckDeadLockThread(THREAD *t, void *param);

#endif	// OBJECT_H

