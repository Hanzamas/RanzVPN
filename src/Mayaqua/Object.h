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


// Lock / Unlock: function-like macros, not inline functions. The Windows SDK
// header NTSecAPI.h declares a global Unlock and COM interfaces (objidl.h) have
// Lock/Unlock methods; a function-like macro expands only on Lock(...)/Unlock(...)
// at call sites that include this header, while an inline function named Unlock
// collides with the SDK. These macros live here (Object.h), not in the leaf
// Native.h that Kernel.h pulls into every unit, so they never reach the Windows
// COM/security headers of units that do not include Object.h (e.g. Win32Com.cpp).
#ifndef	_DEBUG

#define	Lock(lock)		LockInner((lock))
#define	Unlock(lock)	UnlockInner((lock))

#else	// _DEBUG

#define	Lock(lock)			\
	{						\
		LockInner(lock);	\
		if (lock != NULL) { lock->FileName = __FILE__; lock->Line = __LINE__; lock->ThreadId = ThreadId();}	\
	}

#define	Unlock(lock)		\
	{						\
		if (lock != NULL) { lock->FileName = NULL; lock->Line = 0; lock->ThreadId = 0;}	\
		UnlockInner(lock);	\
	}

#endif	// _DEBUG

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

