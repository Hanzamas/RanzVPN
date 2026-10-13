// SoftEther VPN Source Code - Developer Edition Master Branch
// Mayaqua Kernel


// Object.h
// Header of Object.c

#ifndef	OBJECT_H
#define	OBJECT_H

#include "MayaType.h"

#define	OBJECT_ALLOC_FAIL_SLEEP_TIME		150
#define	OBJECT_ALLOC__MAX_RETRY				30

struct LOCK
{
	void *pData;
	bool Ready;
#ifdef	_DEBUG
	char *FileName;
	UINT Line;
	UINT ThreadId;
#endif	// _DEBUG
};

struct COUNTER
{
	LOCK *lock;
	UINT c;
	bool Ready;
};

struct REF
{
	COUNTER *c;
};

struct EVENT
{
	REF *ref;
	void *pData;
};

struct DEADCHECK
{
	LOCK *Lock;
	UINT Timeout;
	bool Unlocked;
};

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

LOCK *NewLock();
LOCK *NewLockMain();
void DeleteLock(LOCK *lock);
COUNTER *NewCounter();
void UnlockInner(LOCK *lock);
bool LockInner(LOCK *lock);
void DeleteCounter(COUNTER *c);
UINT Count(COUNTER *c);
UINT Inc(COUNTER *c);
UINT Dec(COUNTER *c);
UINT Release(REF *ref);
UINT AddRef(REF *ref);
REF *NewRef();
EVENT *NewEvent();
void ReleaseEvent(EVENT *e);
void CleanupEvent(EVENT *e);
void Set(EVENT *e);
bool Wait(EVENT *e, UINT timeout);
bool WaitEx(EVENT *e, UINT timeout, volatile bool *cancel);
void CheckDeadLock(LOCK *lock, UINT timeout, char *name);
void CheckDeadLockThread(THREAD *t, void *param);

#endif	// OBJECT_H

