// Object.c
// Object management code

#include "Object.h"

#include "Mayaqua.h"
#include "Memory.h"
#include "Kernel.h"
#include "Str.h"
#include "Tick64.h"
#include "Tracking.h"
#include "Win32.h"

static void CheckDeadLockThread(THREAD *t, void *param)
{
	DEADCHECK *c = (DEADCHECK *)param;

	if (t == NULL || c == NULL)
	{
		return;
	}

	NoticeThreadInit(t);

	Lock(c->Lock);
	Unlock(c->Lock);
	c->Unlocked = true;
}

void CheckDeadLock(LOCK *lock, UINT timeout, char *name)
{
	DEADCHECK c;
	char msg[MAX_PATH];

	if (lock == NULL)
	{
		return;
	}
	if (name == NULL)
	{
		name = "Unknown";
	}

	Format(msg, sizeof(msg), "error: CheckDeadLock() Failed: %s\n", name);

	Zero(&c, sizeof(c));
	c.Lock = lock;
	c.Unlocked = false;

	THREAD *t = NewThread(CheckDeadLockThread, &c);
	WaitThreadInit(t);
	if (WaitThread(t, timeout) == false)
	{
		if (c.Unlocked == false)
		{
			AbortExitEx(msg);
		}
		else
		{
			WaitThread(t, INFINITE);
		}
	}

	ReleaseThread(t);
}

// Create a raw lock. One heap block from the raw OS allocator
LOCK *NewRawLock()
{
	// Memory allocation
	LOCK *lock = Win32MemoryAlloc(sizeof(LOCK));

	if (lock == NULL)
	{
		return NULL;
	}

	// Initialize the critical section
	InitializeCriticalSection(&lock->CriticalSection);
	lock->Ready = true;

	return lock;
}

bool RawLock(LOCK *lock)
{
	if (lock->Ready == false)
	{
		// State is invalid
		return false;
	}

	// Enter the critical section
	EnterCriticalSection(&lock->CriticalSection);

	return true;
}

void RawUnlock(LOCK *lock)
{
	if (lock->Ready == false)
	{
		// State is invalid
		return;
	}

	// Leave the critical section
	LeaveCriticalSection(&lock->CriticalSection);
}

void DeleteRawLock(LOCK *lock)
{
	// Reset the Ready flag safely
	EnterCriticalSection(&lock->CriticalSection);
	lock->Ready = false;
	LeaveCriticalSection(&lock->CriticalSection);

	// Delete the critical section
	DeleteCriticalSection(&lock->CriticalSection);

	// Memory release
	Win32MemoryFree(lock);
}

static LOCK *NewLockMain()
{
	LOCK *lock;
	UINT retry = 0;

	while (true)
	{
		if ((retry++) > OBJECT_ALLOC__MAX_RETRY)
		{
			AbortExitEx("error: NewRawLock() failed.\n\n");
		}
		lock = NewRawLock();
		if (lock != NULL)
		{
			break;
		}
		SleepThread(OBJECT_ALLOC_FAIL_SLEEP_TIME);
	}

	return lock;
}
LOCK *NewLock()
{
	LOCK *lock = NewLockMain();

	KS_INC(KS_NEWLOCK_COUNT);
	KS_INC(KS_CURRENT_LOCK_COUNT);

	return lock;
}

void DeleteLock(LOCK *lock)
{
	if (lock == NULL)
	{
		return;
	}

	KS_INC(KS_DELETELOCK_COUNT);
	KS_DEC(KS_CURRENT_LOCK_COUNT);

	DeleteRawLock(lock);
}

bool LockInner(LOCK *lock)
{
	if (lock == NULL)
	{
		return false;
	}

	KS_INC(KS_LOCK_COUNT);
	KS_INC(KS_CURRENT_LOCKED_COUNT);

	return RawLock(lock);
}

void UnlockInner(LOCK *lock)
{
	if (lock == NULL)
	{
		return;
	}

	KS_INC(KS_UNLOCK_COUNT);
	KS_DEC(KS_CURRENT_LOCKED_COUNT);

	RawUnlock(lock);
}

COUNTER *NewCounter()
{
	COUNTER *c = Malloc(sizeof(COUNTER));

	c->c = 0;

	KS_INC(KS_NEW_COUNTER_COUNT);

	return c;
}

void DeleteCounter(COUNTER *c)
{
	if (c == NULL)
	{
		return;
	}

	KS_INC(KS_DELETE_COUNTER_COUNT);
	KS_SUB(KS_CURRENT_COUNT, c->c);

	Free(c);
}

// Increment; returns the new value
UINT Inc(COUNTER *c)
{
	if (c == NULL)
	{
		return 0;
	}

	UINT ret = (UINT)InterlockedIncrement((volatile LONG *)&c->c);

	KS_INC(KS_INC_COUNT);
	KS_INC(KS_CURRENT_COUNT);

	return ret;
}

// Decrement; returns the new value. A COUNTER at 0 stays at 0 and returns 0.
UINT Dec(COUNTER *c)
{
	UINT old_value, ret;
	if (c == NULL)
	{
		return 0;
	}

	// Compare-exchange loop, so that the floor at 0 holds under contention
	while (true)
	{
		old_value = c->c;
		if (old_value == 0)
		{
			ret = 0;
			break;
		}

		ret = old_value - 1;
		if ((UINT)InterlockedCompareExchange((volatile LONG *)&c->c, (LONG)ret, (LONG)old_value) == old_value)
		{
			break;
		}
	}

	KS_INC(KS_DEC_COUNT);
	KS_DEC(KS_CURRENT_COUNT);

	return ret;
}

UINT Release(REF *ref)
{
	if (ref == NULL)
	{
		return 0;
	}

	KS_INC(KS_RELEASE_COUNT);
	KS_DEC(KS_CURRENT_REFED_COUNT);

	UINT c = Dec(&ref->c);
	if (c == 0)
	{
		KS_DEC(KS_CURRENT_REF_COUNT);
		KS_INC(KS_FREEREF_COUNT);

		Free(ref);
	}
	return c;
}

UINT AddRef(REF *ref)
{
	if (ref == NULL)
	{
		return 0;
	}

	UINT c = Inc(&ref->c);

	KS_INC(KS_ADDREF_COUNT);
	KS_INC(KS_CURRENT_REFED_COUNT);

	return c;
}

REF *NewRef()
{
	// Memory allocation: the counter is embedded, so this is the only heap block
	REF *ref = Malloc(sizeof(REF));

	// Initialization
	ref->c.c = 0;

	Inc(&ref->c);

	KS_INC(KS_NEWREF_COUNT);
	KS_INC(KS_CURRENT_REF_COUNT);
	KS_INC(KS_ADDREF_COUNT);
	KS_INC(KS_CURRENT_REFED_COUNT);

	return ref;
}

EVENT *NewEvent()
{
	EVENT *e = Malloc(sizeof(EVENT));

	e->ref = NewRef();

	// Creating an unnamed auto-reset event; a failed create leaves a NULL handle
	e->pData = CreateEvent(NULL, FALSE, FALSE, NULL);

	KS_INC(KS_NEWEVENT_COUNT);

	return e;
}

void ReleaseEvent(EVENT *e)
{
	if (e == NULL)
	{
		return;
	}

	if (Release(e->ref) == 0)
	{
		CleanupEvent(e);
	}
}

void CleanupEvent(EVENT *e)
{
	if (e == NULL)
	{
		return;
	}

	if (e->pData != NULL)
	{
		CloseHandle((HANDLE)e->pData);
	}

	Free(e);

	KS_INC(KS_FREEEVENT_COUNT);
}

bool Wait(EVENT *e, UINT timeout)
{
	if (e == NULL)
	{
		return false;
	}

	KS_INC(KS_WAIT_COUNT);

	if (e->pData == NULL)
	{
		return false;
	}

	// Only a time-out gives false: WAIT_FAILED and WAIT_ABANDONED give true
	return (WaitForSingleObject((HANDLE)e->pData, timeout) != WAIT_TIMEOUT);
}

bool WaitEx(EVENT *e, UINT timeout, volatile bool *cancel)
{
	bool dummy_bool = false;
	UINT64 giveup;
	if (cancel == NULL)
	{
		cancel = &dummy_bool;
	}

	UINT64 start = Tick64();

	if (timeout == INFINITE || timeout == 0x7FFFFFFF)
	{
		giveup = 0;
	}
	else
	{
		giveup = start + (UINT64)timeout;
	}

	while (true)
	{
		UINT64 now = Tick64();
		UINT interval_to_giveup = (UINT)(giveup - now);
		if (giveup == 0)
		{
			interval_to_giveup = INFINITE;
		}
		else
		{
			if (now >= giveup)
			{
				return false;
			}
		}

		interval_to_giveup = MIN(interval_to_giveup, 25);

		if (FlagRead(cancel))
		{
			return false;
		}

		if (e != NULL)
		{
			if (Wait(e, interval_to_giveup))
			{
				return true;
			}
		}
		else
		{
			SleepThread(interval_to_giveup);
		}
	}
}


