// Object.c
// Object management code

#include "Object.h"

#include "Mayaqua.h"
#include "Memory.h"
#include "Kernel.h"
#include "OS.h"
#include "Str.h"
#include "Tick64.h"
#include "Tracking.h"

void CheckDeadLockThread(THREAD *t, void *param)
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
	THREAD *t;
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
	c.Timeout = timeout;
	c.Unlocked = false;

	t = NewThread(CheckDeadLockThread, &c);
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

LOCK *NewLockMain()
{
	LOCK *lock;
	UINT retry = 0;

	while (true)
	{
		if ((retry++) > OBJECT_ALLOC__MAX_RETRY)
		{
			AbortExitEx("error: OSNewLock() failed.\n\n");
		}
		lock = OSNewLock();
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

	OSDeleteLock(lock);
}

bool LockInner(LOCK *lock)
{
	if (lock == NULL)
	{
		return false;
	}

	KS_INC(KS_LOCK_COUNT);
	KS_INC(KS_CURRENT_LOCKED_COUNT);

	return OSLock(lock);
}

void UnlockInner(LOCK *lock)
{
	if (lock == NULL)
	{
		return;
	}

	KS_INC(KS_UNLOCK_COUNT);
	KS_DEC(KS_CURRENT_LOCKED_COUNT);

	OSUnlock(lock);
}

COUNTER *NewCounter()
{
	COUNTER *c;

	c = Malloc(sizeof(COUNTER));

	c->Ready = true;
	c->c = 0;

	c->lock = NewLock();

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

	DeleteLock(c->lock);
	Free(c);
}

UINT Count(COUNTER *c)
{
	UINT ret;
	if (c == NULL)
	{
		return 0;
	}
	if (c->Ready == false)
	{
		return 0;
	}

	Lock(c->lock);
	{
		ret = c->c;
	}
	Unlock(c->lock);

	return ret;
}

UINT Inc(COUNTER *c)
{
	UINT ret;
	if (c == NULL)
	{
		return 0;
	}
	if (c->Ready == false)
	{
		return 0;
	}

	Lock(c->lock);
	{
		c->c++;
		ret = c->c;
	}
	Unlock(c->lock);

	KS_INC(KS_INC_COUNT);
	KS_INC(KS_CURRENT_COUNT);

	return ret;
}

UINT Dec(COUNTER *c)
{
	UINT ret;
	if (c == NULL)
	{
		return 0;
	}
	if (c->Ready == false)
	{
		return 0;
	}

	Lock(c->lock);
	{
		if (c->c != 0)
		{
			c->c--;
			ret = c->c;
		}
		else
		{
			ret = 0;
		}
	}
	Unlock(c->lock);

	KS_INC(KS_DEC_COUNT);
	KS_DEC(KS_CURRENT_COUNT);

	return ret;
}

UINT Release(REF *ref)
{
	UINT c;
	if (ref == NULL)
	{
		return 0;
	}

	KS_INC(KS_RELEASE_COUNT);
	KS_DEC(KS_CURRENT_REFED_COUNT);

	c = Dec(ref->c);
	if (c == 0)
	{
		KS_DEC(KS_CURRENT_REF_COUNT);
		KS_INC(KS_FREEREF_COUNT);

		DeleteCounter(ref->c);
		ref->c = 0;
		Free(ref);
	}
	return c;
}

UINT AddRef(REF *ref)
{
	UINT c;
	if (ref == NULL)
	{
		return 0;
	}

	c = Inc(ref->c);

	KS_INC(KS_ADDREF_COUNT);
	KS_INC(KS_CURRENT_REFED_COUNT);

	return c;
}

REF *NewRef()
{
	REF *ref;

	ref = Malloc(sizeof(REF));

	ref->c = NewCounter();

	Inc(ref->c);

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

	OSInitEvent(e);

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

	OSFreeEvent(e);

	Free(e);

	KS_INC(KS_FREEEVENT_COUNT);
}

void Set(EVENT *e)
{
	if (e == NULL)
	{
		return;
	}

	OSSetEvent(e);
}

bool Wait(EVENT *e, UINT timeout)
{
	if (e == NULL)
	{
		return false;
	}

	KS_INC(KS_WAIT_COUNT);

	return OSWaitEvent(e, timeout);
}

bool WaitEx(EVENT *e, UINT timeout, volatile bool *cancel)
{
	bool dummy_bool = false;
	UINT64 start, giveup;
	if (cancel == NULL)
	{
		cancel = &dummy_bool;
	}

	start = Tick64();

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

		if (*cancel)
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

