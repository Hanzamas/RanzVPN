// Kernel.c
// System service processing routine

#include "Kernel.h"

#include "Encrypt.h"
#include "Internat.h"
#include "Mayaqua.h"
#include "Memory.h"
#include "Microsoft.h"
#include "Object.h"
#include "Str.h"
#include "Table.h"
#include "Tracking.h"
#include "Win32.h"

#include <objbase.h>
#include <process.h>

#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifndef TM_YEAR_MAX
#define TM_YEAR_MAX         2106
#endif
#ifndef TM_MON_MAX
#define TM_MON_MAX          1
#endif
#ifndef TM_MDAY_MAX
#define TM_MDAY_MAX         7
#endif
#ifndef TM_HOUR_MAX
#define TM_HOUR_MAX         6
#endif
#ifndef TM_MIN_MAX
#define TM_MIN_MAX          28
#endif
#ifndef TM_SEC_MAX
#define TM_SEC_MAX          14
#endif

#define ADJUST_TM(tm_member, tm_carry, modulus) \
	if ((tm_member) < 0){ \
	tm_carry -= (1 - ((tm_member)+1) / (modulus)); \
	tm_member = (modulus-1) + (((tm_member)+1) % (modulus)); \
	} else if ((tm_member) >= (modulus)) { \
	tm_carry += (tm_member) / (modulus); \
	tm_member = (tm_member) % (modulus); \
	}
#define leap(y) (((y) % 4 == 0 && (y) % 100 != 0) || (y) % 400 == 0)
#define nleap(y) (((y) - 1969) / 4 - ((y) - 1901) / 100 + ((y) - 1601) / 400)
#define leapday(m, y) ((m) == 1 && leap (y))
#define monthlen(m, y) (ydays[(m)+1] - ydays[m] + leapday (m, y))
static int ydays[] =
{
	0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334, 365
};

static UINT cached_number_of_cpus = 0;


static wchar_t *default_locale_str =
L"- - $ : : $ Sun Mon Tue Wed Thu Fri Sat : : : $ (None)";


static LOCALE current_locale;

#define MONSPERYEAR 12
#define DAYSPERNYEAR 365
#define DAYSPERLYEAR 366
#define SECSPERMIN 60
#define SECSPERHOUR (60*60)
#define SECSPERDAY (24*60*60)
#define DAYSPERWEEK 7
#define TM_THURSDAY	4

#define TM_YEAR_BASE	1900

#define EPOCH_YEAR	1970
#define EPOCH_WDAY	TM_THURSDAY

#define isleap(y) (((y) % 4) == 0 && (((y) % 100) != 0 || ((y) % 400) == 0))

static const int	mon_lengths[2][MONSPERYEAR] = {
	{ 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 },
	{ 31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 }
};

static const int	year_lengths[2] = {
	DAYSPERNYEAR, DAYSPERLYEAR
};


/*
 * Taken from FreeBSD src / lib / libc / stdtime / localtime.c 1.43 revision.
 * localtime.c 7.78.
 * tzfile.h 1.8
 * adapted to be replacement gmtime_r.
 */
static void
c_timesub(timep, offset, tmp)
const time_64t * const			timep;
const long				offset;
struct tm * const		tmp;
{
	INT64			days;
	INT64			rem;
	INT64			y;
	int			yleap;
	const int *		ip;

	days = *timep / SECSPERDAY;
	rem = *timep % SECSPERDAY;
	rem += (offset);
	while (rem < 0) {
		rem += SECSPERDAY;
		--days;
	}
	while (rem >= SECSPERDAY) {
		rem -= SECSPERDAY;
		++days;
	}
	tmp->tm_hour = (int) (rem / SECSPERHOUR);
	rem = rem % SECSPERHOUR;
	tmp->tm_min = (int) (rem / SECSPERMIN);
	/*
	** A positive leap second requires a special
	** representation.  This uses "... ??:59:60" et seq.
	*/
	tmp->tm_sec = (int) (rem % SECSPERMIN) ;
	tmp->tm_wday = (int) ((EPOCH_WDAY + days) % DAYSPERWEEK);
	if (tmp->tm_wday < 0)
		tmp->tm_wday += DAYSPERWEEK;
	y = EPOCH_YEAR;
#define LEAPS_THRU_END_OF(y)	((y) / 4 - (y) / 100 + (y) / 400)
	while (days < 0 || days >= (long) year_lengths[yleap = isleap(y)]) {
		INT64	newy;

		newy = y + days / DAYSPERNYEAR;
		if (days < 0)
			--newy;
		days -= (newy - y) * DAYSPERNYEAR +
			LEAPS_THRU_END_OF(newy - 1) -
			LEAPS_THRU_END_OF(y - 1);
		y = newy;
	}
	tmp->tm_year = (int)(y - TM_YEAR_BASE);
	tmp->tm_yday = (int) days;
	ip = mon_lengths[yleap];
	for (tmp->tm_mon = 0; days >= (INT64) ip[tmp->tm_mon]; ++(tmp->tm_mon))
		days = days - (INT64) ip[tmp->tm_mon];
	tmp->tm_mday = (int) (days + 1);
	tmp->tm_isdst = 0;
}

static struct tm * c_gmtime_r(const time_64t* timep, struct tm *tm)
{
	c_timesub(timep, 0L, tm);
	return tm;
}

UINT GetNumberOfCpu()
{
	UINT ret = 0;

	if (cached_number_of_cpus == 0)
	{
		UINT i = 0;

		i = Win32GetNumberOfCpuInner();

		if (i == 0)
		{
			i = 8;
		}

		cached_number_of_cpus = i;
	}

	ret = cached_number_of_cpus;

	if (ret == 0)
	{
		ret = 1;
	}
	if (ret > 128)
	{
		ret = 128;
	}

	return ret;
}

void GetHomeDirW(wchar_t *path, UINT size)
{
	if (path == NULL)
	{
		return;
	}

	if (GetEnvW(L"HOME", path, size) == false)
	{
		wchar_t drive[MAX_SIZE];
		wchar_t hpath[MAX_SIZE];
		if (GetEnvW(L"HOMEDRIVE", drive, sizeof(drive)) &&
			GetEnvW(L"HOMEPATH", hpath, sizeof(hpath)))
		{
			UniFormat(path, size, L"%s%s", drive, hpath);
		}
		else
		{
			Win32GetCurrentDirW(path, size);
		}
	}
}

bool GetEnv(char *name, char *data, UINT size)
{
	char *ret;
	if (name == NULL || data == NULL)
	{
		return false;
	}

	StrCpy(data, size, "");

	ret = getenv(name);
	if (ret == NULL)
	{
		return false;
	}

	StrCpy(data, size, ret);

	return true;
}
bool GetEnvW(wchar_t *name, wchar_t *data, UINT size)
{
	wchar_t *ret;
	if (name == NULL || data == NULL)
	{
		return false;
	}

	UniStrCpy(data, size, L"");

	ret = _wgetenv(name);
	if (ret == NULL)
	{
		return false;
	}

	UniStrCpy(data, size, ret);

	return true;
}


void GetMemInfo(MEMINFO *info)
{
	OSGetMemInfo(info);
}

INSTANCE *NewSingleInstance(char *instance_name)
{
	return NewSingleInstanceEx(instance_name, false);
}
INSTANCE *NewSingleInstanceEx(char *instance_name, bool user_local)
{
	char name[MAX_SIZE];
	INSTANCE *ret;
	void *data;

	if (instance_name != NULL)
	{
		if (user_local == false)
		{
			HashInstanceName(name, sizeof(name), instance_name);
		}
		else
		{
			HashInstanceNameLocal(name, sizeof(name), instance_name);
		}

		data = OSNewSingleInstance(name);
	}
	else
	{
		data = OSNewSingleInstance(NULL);
	}

	if (data == NULL)
	{
		return NULL;
	}

	ret = ZeroMalloc(sizeof(INSTANCE));
	if (instance_name != NULL)
	{
		ret->Name = CopyStr(instance_name);
	}

	ret->pData = data;

	return ret;
}

void FreeSingleInstance(INSTANCE *inst)
{
	if (inst == NULL)
	{
		return;
	}

	OSFreeSingleInstance(inst->pData);

	if (inst->Name != NULL)
	{
		Free(inst->Name);
	}
	Free(inst);
}

void HashInstanceName(char *name, UINT size, char *instance_name)
{
	char tmp[MAX_SIZE];
	UCHAR hash[SHA1_SIZE];
	char key[11];
	if (name == NULL || instance_name == NULL)
	{
		return;
	}

	StrCpy(tmp, sizeof(tmp), instance_name);
	Trim(tmp);
	StrUpper(tmp);

	Sha0(hash, tmp, StrLen(tmp));
	BinToStr(key, sizeof(key), hash, 5);
	key[10] = 0;

	Format(name, size, "VPN-%s", key);

	StrCpy(tmp, sizeof(tmp), name);
	Format(name, size, "Global\\%s", tmp);
}
void HashInstanceNameLocal(char *name, UINT size, char *instance_name)
{
	char tmp[MAX_SIZE];
	UCHAR hash[SHA1_SIZE];
	char key[11];
	if (name == NULL || instance_name == NULL)
	{
		return;
	}

	StrCpy(tmp, sizeof(tmp), instance_name);
	Trim(tmp);
	StrUpper(tmp);

	Sha0(hash, tmp, StrLen(tmp));
	BinToStr(key, sizeof(key), hash, 5);
	key[10] = 0;

	Format(name, size, "VPN-%s", key);

	StrCpy(tmp, sizeof(tmp), name);
	Format(name, size, "Local\\%s", tmp);
}

bool Run(char *filename, char *arg, bool hide, bool wait)
{
	if (filename == NULL)
	{
		return false;
	}

	return OSRun(filename, arg, hide, wait);
}

void GetDateTimeStr64Uni(wchar_t *str, UINT size, UINT64 sec64)
{
	char tmp[MAX_SIZE];
	if (str == NULL)
	{
		return;
	}

	GetDateTimeStr64(tmp, sizeof(tmp), sec64);
	StrToUni(str, size, tmp);
}
void GetDateTimeStr64(char *str, UINT size, UINT64 sec64)
{
	SYSTEMTIME st;
	UINT64ToSystem(&st, sec64);
	GetDateTimeStr(str, size, &st);
}
void GetDateTimeStrMilli64(char *str, UINT size, UINT64 sec64)
{
	SYSTEMTIME st;
	UINT64ToSystem(&st, sec64);
	GetDateTimeStrMilli(str, size, &st);
}
void GetDateStr64(char *str, UINT size, UINT64 sec64)
{
	SYSTEMTIME st;
	if (sec64 == 0)
	{
		StrCpy(str, size, "(Unknown)");
		return;
	}
	UINT64ToSystem(&st, sec64);
	GetDateStr(str, size, &st);
}
void GetDateTimeStrEx64(wchar_t *str, UINT size, UINT64 sec64, LOCALE *locale)
{
	SYSTEMTIME st;
	if (locale == NULL)
	{
		locale = &current_locale;
	}
	if (sec64 == 0 || SystemToLocal64(sec64) == 0 || LocalToSystem64(sec64) == 0)
	{
		UniStrCpy(str, size, locale->Unknown);
		return;
	}
	UINT64ToSystem(&st, sec64);
	GetDateTimeStrEx(str, size, &st, locale);
}
void GetDateStrEx64(wchar_t *str, UINT size, UINT64 sec64, LOCALE *locale)
{
	SYSTEMTIME st;
	if (locale == NULL)
	{
		locale = &current_locale;
	}
	if (sec64 == 0 || SystemToLocal64(sec64) == 0 || LocalToSystem64(sec64) == 0)
	{
		UniStrCpy(str, size, locale->Unknown);
		return;
	}
	UINT64ToSystem(&st, sec64);
	GetDateStrEx(str, size, &st, locale);
}
void GetTimeStrMilli64(char *str, UINT size, UINT64 sec64)
{
	SYSTEMTIME st;
	if (sec64 == 0 || SystemToLocal64(sec64) == 0 || LocalToSystem64(sec64) == 0)
	{
		StrCpy(str, size, "(Unknown)");
		return;
	}
	UINT64ToSystem(&st, sec64);
	GetTimeStrMilli(str, size, &st);
}

static UINT64 SafeTime64(UINT64 sec64)
{
	return MAKESURE(sec64, 0, 4102243323123ULL);
}

// The THREAD jobs (NewThreadNamed) run on a private Windows thread pool. Every job joins the
// cleanup group, which FreeThreading waits on.
// The shutdown wait rests on an assumption: the Microsoft documentation of
// CloseThreadpoolCleanupGroupMembers names only work, wait and timer objects as members, and that
// a simple callback (TrySubmitThreadpoolCallback) joins the cleanup group of its environment is
// observed behaviour, not documented. The "NO MEMORY LEAKS" marker after the threadpool test of
// vpntest pins it: that test leaves a job running into the process exit.
#define	THREAD_POOL_MAX_THREADS		65535	// Upper bound of pool threads: the Windows default (500) is too low for a server

static PTP_POOL thread_pool = NULL;
static PTP_CLEANUP_GROUP thread_pool_cleanup = NULL;
static TP_CALLBACK_ENVIRON thread_pool_env;
static volatile LONG thread_pool_posted = 0;	// Jobs posted so far (only compared, so it may wrap)

void InitThreading()
{
	thread_pool = CreateThreadpool(NULL);
	thread_pool_cleanup = CreateThreadpoolCleanupGroup();
	if (thread_pool == NULL || thread_pool_cleanup == NULL)
	{
		printf("\n\n*** error: thread pool create failed.\n\n");
		AbortExit();
	}

	SetThreadpoolThreadMaximum(thread_pool, THREAD_POOL_MAX_THREADS);

	InitializeThreadpoolEnvironment(&thread_pool_env);
	SetThreadpoolCallbackPool(&thread_pool_env, thread_pool);
	SetThreadpoolCallbackCleanupGroup(&thread_pool_env, thread_pool_cleanup, NULL);

	// Jobs may run for a long time: the pool knows this before a callback starts, so several
	// NewThread calls at once do not wait for one another to start. This replaces a
	// CallbackMayRunLong call in each callback, which the pool refuses on such a callback.
	SetThreadpoolCallbackRunsLong(&thread_pool_env);
}

void FreeThreading()
{
	LONG posted;

	// Wait until every job has ended. A job that a running job posts after the wait took the
	// members of the cleanup group is not part of that wait, but NewThreadNamed counts the post
	// before the running job can end, so wait again until a whole wait passed without a post.
	do
	{
		posted = InterlockedCompareExchange(&thread_pool_posted, 0, 0);

		CloseThreadpoolCleanupGroupMembers(thread_pool_cleanup, FALSE, NULL);
	}
	while (InterlockedCompareExchange(&thread_pool_posted, 0, 0) != posted);

	CloseThreadpoolCleanupGroup(thread_pool_cleanup);
	thread_pool_cleanup = NULL;

	DestroyThreadpoolEnvironment(&thread_pool_env);

	CloseThreadpool(thread_pool);
	thread_pool = NULL;
}

// Pool callback of one THREAD job, called once on a thread of the pool: prepare the thread as a
// host thread (HostThreadProc), take the job, run it, wake the WaitThread callers, hold the thread
// until every other holder released the THREAD, and give the thread back as it was found
static void NTAPI ThreadPoolCallback(PTP_CALLBACK_INSTANCE instance, void *param)
{
	THREAD *thread = (THREAD *)param;
	HRESULT hr;
	if (thread == NULL)
	{
		return;
	}

	// A job may run for the life of the process. The environment marks every callback as long
	// running (InitThreading), so the pool keeps another thread for the next job; a call to
	// CallbackMayRunLong on such a callback raises STATUS_INVALID_PARAMETER in ntdll.
	Win32InitNewThread();

	hr = CoInitialize(NULL);

	thread->ThreadId = ThreadId();

	// NewThreadNamed returns from here on
	SetEvent((HANDLE)thread->StartedEvent);

	if (thread->Name != NULL)
	{
		SetThreadName(thread->ThreadId, thread->Name, thread->param);
	}
	else
	{
		SetThreadName(thread->ThreadId, "Unknown", 0);
	}

	thread->thread_proc(thread, thread->param);

	SetThreadName(thread->ThreadId, NULL, 0);

	// Every WaitThread caller, now or later, sees the end
	SetEvent((HANDLE)thread->EndedEvent);

	while (true)
	{
		if (Count(&thread->ref->c) <= 1)
		{
			break;
		}

		Wait(thread->release_event, 256);
	}

	ReleaseThread(thread);

	FreeOpenSSLThreadState();

	if (SUCCEEDED(hr))
	{
		CoUninitialize();
	}

	MsRestoreThreadPriority();
}

void SetThreadName(UINT thread_id, char *name, void *param)
{
	if (IsDebug())
	{
		char tmp[MAX_SIZE];

		if (name == NULL)
		{
			strcpy(tmp, "idle");
		}
		else
		{
			sprintf(tmp, "%s (0x%x)", name, (UINT)param);
		}

		Win32SetThreadName(thread_id, tmp);
	}
}

THREAD *NewThreadNamed(THREAD_PROC *thread_proc, void *param, char *name)
{
	THREAD *ret;
	UINT retry = 0;
	if (thread_proc == NULL)
	{
		return NULL;
	}

	ret = ZeroMalloc(sizeof(THREAD));
	ret->ref = NewRef();
	ret->thread_proc = thread_proc;
	ret->param = param;
	ret->pData = NULL;
	ret->init_finished_event = NewEvent();
	ret->StartedEvent = CreateEvent(NULL, FALSE, FALSE, NULL);
	ret->EndedEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
	ret->release_event = NewEvent();

	if (IsEmptyStr(name) == false)
	{
		ret->Name = CopyStr(name);
	}

	// The pool callback holds this reference until the job ended and every other holder let go
	AddRef(ret->ref);

	// Post the job, retried like the creation of a host thread
	while (TrySubmitThreadpoolCallback(ThreadPoolCallback, ret, &thread_pool_env) == FALSE)
	{
		if ((retry++) > 60)
		{
			printf("\n\n*** error: new thread create failed.\n\n");
			AbortExit();
		}

		SleepThread(500);
	}

	// Count the post before this returns, so that a running job's post is counted before the job ends
	InterlockedIncrement(&thread_pool_posted);

	// Return once a pool thread took the job
	if (ret->StartedEvent != NULL)
	{
		WaitForSingleObject((HANDLE)ret->StartedEvent, INFINITE);
		CloseHandle((HANDLE)ret->StartedEvent);
		ret->StartedEvent = NULL;
	}

	return ret;
}

static void CleanupThread(THREAD *t)
{
	if (t == NULL)
	{
		return;
	}

	ReleaseEvent(t->init_finished_event);
	ReleaseEvent(t->release_event);

	if (t->EndedEvent != NULL)
	{
		CloseHandle((HANDLE)t->EndedEvent);
	}

	if (t->Name != NULL)
	{
		Free(t->Name);
	}

	Free(t);
}

void ReleaseThread(THREAD *t)
{
	UINT ret;
	EVENT *e;
	if (t == NULL)
	{
		return;
	}

	e = t->release_event;
	if (e != NULL)
	{
		AddRef(e->ref);
	}

	ret = Release(t->ref);
	Set(e);

	ReleaseEvent(e);

	if (ret == 0)
	{
		CleanupThread(t);
	}
}

void NoticeThreadInit(THREAD *t)
{
	if (t == NULL)
	{
		return;
	}

	Set(t->init_finished_event);
}

void WaitThreadInit(THREAD *t)
{
	if (t == NULL)
	{
		return;
	}

	KS_INC(KS_WAITFORTHREAD_COUNT);

	Wait(t->init_finished_event, INFINITE);
}

bool WaitThread(THREAD *t, UINT timeout)
{
	if (t == NULL || t->EndedEvent == NULL)
	{
		return false;
	}

	// Any number of threads can wait: the end event is manual-reset and never reset.
	// Only a time-out gives false, as Wait gives for an EVENT.
	return (WaitForSingleObject((HANDLE)t->EndedEvent, timeout) != WAIT_TIMEOUT);
}

UINT ThreadId()
{
	return OSThreadId();
}

// Thread handle of a host THREAD (its pData), from the raw OS allocator
typedef struct HOST_THREAD
{
	HANDLE hThread;
} HOST_THREAD;

// Startup information of a host thread, from the raw OS allocator
typedef struct HOST_THREAD_STARTUP
{
	THREAD_PROC *thread_proc;
	void *param;
	THREAD *thread;
} HOST_THREAD_STARTUP;

// Host thread procedure: run the THREAD procedure on the new OS thread
static UINT __stdcall HostThreadProc(void *param)
{
	HOST_THREAD_STARTUP *info = (HOST_THREAD_STARTUP *)param;
	// Validate arguments
	if (info == NULL)
	{
		return 0;
	}

	Win32InitNewThread();

	CoInitialize(NULL);

	// Call the thread function
	info->thread_proc(info->thread, info->param);

	// Release the reference
	ReleaseThread(info->thread);

	Win32MemoryFree(info);

	FreeOpenSSLThreadState();

	CoUninitialize();

	_endthreadex(0);
	return 0;
}

THREAD *NewThreadInternal(THREAD_PROC *thread_proc, void *param)
{
	THREAD *t;
	UINT retry = 0;
	if (thread_proc == NULL)
	{
		return NULL;
	}

	t = ZeroMalloc(sizeof(THREAD));
	t->init_finished_event = NewEvent();

	t->param = param;
	t->ref = NewRef();
	t->thread_proc = thread_proc;

	while (true)
	{
		HOST_THREAD_STARTUP *info;
		HOST_THREAD *host;
		HANDLE h;

		if ((retry++) > 60)
		{
			printf("\n\n*** error: new thread create failed.\n\n");
			AbortExit();
		}

		// Creating the startup information: the new thread holds one reference
		info = Win32MemoryAlloc(sizeof(HOST_THREAD_STARTUP));
		info->thread_proc = t->thread_proc;
		info->param = t->param;
		info->thread = t;
		AddRef(t->ref);

		h = (HANDLE)_beginthreadex(NULL, 0, HostThreadProc, info, 0, NULL);
		if (h != NULL)
		{
			// Save the thread handle
			host = Win32MemoryAlloc(sizeof(HOST_THREAD));
			host->hThread = h;
			t->pData = host;
			break;
		}

		// Thread creation failure
		Release(t->ref);
		Win32MemoryFree(info);

		SleepThread(500);
	}

	KS_INC(KS_NEWTHREAD_COUNT);

	return t;
}

void ReleaseThreadInternal(THREAD *t)
{
	if (t == NULL)
	{
		return;
	}

	if (Release(t->ref) == 0)
	{
		CleanupThreadInternal(t);
	}
}

void CleanupThreadInternal(THREAD *t)
{
	HOST_THREAD *host;
	if (t == NULL)
	{
		return;
	}

	// Close the thread handle
	host = (HOST_THREAD *)t->pData;
	if (host != NULL)
	{
		CloseHandle(host->hThread);
		Win32MemoryFree(host);
		t->pData = NULL;
	}

	ReleaseEvent(t->init_finished_event);
	Free(t);

	KS_INC(KS_FREETHREAD_COUNT);
}

bool WaitThreadInternal(THREAD *t)
{
	HOST_THREAD *host;
	if (t == NULL)
	{
		return false;
	}

	host = (HOST_THREAD *)t->pData;
	if (host == NULL)
	{
		return false;
	}

	// Only WAIT_OBJECT_0 means that the thread ended
	return (WaitForSingleObject(host->hThread, INFINITE) == WAIT_OBJECT_0);
}

void NoticeThreadInitInternal(THREAD *t)
{
	if (t == NULL)
	{
		return;
	}

	Set(t->init_finished_event);
}

void GetDateTimeStrEx(wchar_t *str, UINT size, SYSTEMTIME *st, LOCALE *locale)
{
	wchar_t tmp1[MAX_SIZE];
	wchar_t tmp2[MAX_SIZE];
	if (str == NULL || st == NULL)
	{
		return;
	}

	GetDateStrEx(tmp1, sizeof(tmp1), st, locale);
	GetTimeStrEx(tmp2, sizeof(tmp2), st, locale);
	UniFormat(str, size, L"%s %s", tmp1, tmp2);
}

void GetTimeStrEx(wchar_t *str, UINT size, SYSTEMTIME *st, LOCALE *locale)
{
	wchar_t *tag = L"%02u%s%02u%s%02u%s";
	if (str == NULL || st == NULL)
	{
		return;
	}

	if (_GETLANG() == SE_LANG_JAPANESE || _GETLANG() == SE_LANG_CHINESE_ZH)
	{
		tag = L"%2u%s%2u%s%2u%s";
	}

	locale = (locale != NULL ? locale : &current_locale);
	UniFormat(str, size,
		tag,
		st->wHour, locale->HourStr,
		st->wMinute, locale->MinuteStr,
		st->wSecond, locale->SecondStr);
}

void GetDateStrEx(wchar_t *str, UINT size, SYSTEMTIME *st, LOCALE *locale)
{
	wchar_t *tag = L"%04u%s%02u%s%02u%s (%s)";
	if (str == NULL || st == NULL)
	{
		return;
	}

	if (_GETLANG() == SE_LANG_JAPANESE || _GETLANG() == SE_LANG_CHINESE_ZH)
	{
		tag = L"%4u%s%2u%s%2u%s(%s)";
	}

	locale = (locale != NULL ? locale : &current_locale);
	UniFormat(str, size,
		tag,
		st->wYear, locale->YearStr,
		st->wMonth, locale->MonthStr,
		st->wDay, locale->DayStr,
		locale->DayOfWeek[st->wDayOfWeek]);
}

void GetTimeStrMilli(char *str, UINT size, SYSTEMTIME *st)
{
	if (st == NULL || str == NULL)
	{
		return;
	}

	Format(str, size, "%02u:%02u:%02u.%03u",
		st->wHour, st->wMinute, st->wSecond, st->wMilliseconds);
}

void GetDateStr(char *str, UINT size, SYSTEMTIME *st)
{
	if (str == NULL || st == NULL)
	{
		return;
	}

	Format(str, size, "%04u-%02u-%02u",
		st->wYear, st->wMonth, st->wDay);
}

void GetDateTimeStr(char *str, UINT size, SYSTEMTIME *st)
{
	if (str == NULL || st == NULL)
	{
		return;
	}

	Format(str, size, "%04u-%02u-%02u %02u:%02u:%02u",
		st->wYear, st->wMonth, st->wDay,
		st->wHour, st->wMinute, st->wSecond);
}

void GetDateTimeStrMilli(char *str, UINT size, SYSTEMTIME *st)
{
	if (str == NULL || st == NULL)
	{
		return;
	}

	Format(str, size, "%04u-%02u-%02u %02u:%02u:%02u.%03u",
		st->wYear, st->wMonth, st->wDay,
		st->wHour, st->wMinute, st->wSecond,
		st->wMilliseconds);
}


// Print an RFC 3339 date-time: st is the local time and timezone_min its offset from UTC in
// minutes (local time minus UTC, positive east of UTC). Offset 0 prints "Z", any other offset
// prints "+HH:MM" or "-HH:MM", the sign taken from the whole offset and both fields two digits
void GetDateTimeStrRFC3339(char *str, UINT size, SYSTEMTIME *st, int timezone_min)
{
	UINT abs_min;
	if (str == NULL || st == NULL)
	{
		ClearStr(str, size);
		return;
	}

	if (timezone_min == 0)
	{
		Format(str, size, "%04u-%02u-%02uT%02u:%02u:%02u.%03uZ",
			st->wYear, st->wMonth, st->wDay,
			st->wHour, st->wMinute, st->wSecond,
			st->wMilliseconds);
	}
	else
	{
		abs_min = (timezone_min < 0) ? (UINT)(-timezone_min) : (UINT)timezone_min;

		Format(str, size, "%04u-%02u-%02uT%02u:%02u:%02u.%03u%s%02u:%02u",
			st->wYear, st->wMonth, st->wDay,
			st->wHour, st->wMinute, st->wSecond,
			st->wMilliseconds, (timezone_min < 0) ? "-" : "+", abs_min / 60, abs_min % 60);
	}
}

// Read count decimal digits at str. Stops at the first character that is not a digit, so it
// never reads past the end of the string
static bool ParseRFC3339Digits(char *str, UINT count, UINT *value)
{
	UINT i;

	*value = 0;
	for (i = 0; i < count; i++)
	{
		if (str[i] < '0' || str[i] > '9')
		{
			return false;
		}

		*value = *value * 10 + (UINT)(str[i] - '0');
	}

	return true;
}

// Parse an RFC 3339 date-time, "YYYY-MM-DDTHH:MM:SS", an optional fraction of a second and the
// offset "Z", "+HH:MM" or "-HH:MM", into the UTC time it names. Fraction digits after the third
// are dropped; "T" and "Z" may be lower case. A leap second (60) is refused, as SYSTEMTIME cannot
// hold it. Returns false, with st zeroed, for anything else, an invalid date included
bool DateTimeStrRFC3339ToSystemTime(SYSTEMTIME *st, char *str)
{
	UINT year, month, day, hour, minute, second;
	UINT msec = 0, msec_scale = 100;
	UINT offset_hour = 0, offset_minute = 0;
	INT64 offset_sign = 0;
	SYSTEMTIME tmp;
	FILETIME ft;
	UINT64 t;
	char *p;
	if (st == NULL)
	{
		return false;
	}

	Zero(st, sizeof(SYSTEMTIME));

	if (str == NULL)
	{
		return false;
	}

	if (ParseRFC3339Digits(str, 4, &year) == false || str[4] != '-' ||
		ParseRFC3339Digits(str + 5, 2, &month) == false || str[7] != '-' ||
		ParseRFC3339Digits(str + 8, 2, &day) == false || (str[10] != 'T' && str[10] != 't') ||
		ParseRFC3339Digits(str + 11, 2, &hour) == false || str[13] != ':' ||
		ParseRFC3339Digits(str + 14, 2, &minute) == false || str[16] != ':' ||
		ParseRFC3339Digits(str + 17, 2, &second) == false ||
		hour > 23 || minute > 59 || second > 59)
	{
		return false;
	}

	p = str + 19;

	// Fraction of a second: at least one digit, the first three kept
	if (*p == '.')
	{
		p++;
		if (*p < '0' || *p > '9')
		{
			return false;
		}

		while (*p >= '0' && *p <= '9')
		{
			msec += (UINT)(*p - '0') * msec_scale;
			msec_scale /= 10;
			p++;
		}
	}

	// Offset from UTC
	if (*p == 'Z' || *p == 'z')
	{
		p++;
	}
	else if (*p == '+' || *p == '-')
	{
		offset_sign = (*p == '-') ? -1 : 1;

		if (ParseRFC3339Digits(p + 1, 2, &offset_hour) == false || p[3] != ':' ||
			ParseRFC3339Digits(p + 4, 2, &offset_minute) == false ||
			offset_hour > 23 || offset_minute > 59)
		{
			return false;
		}

		p += 6;
	}
	else
	{
		return false;
	}

	if (*p != 0)
	{
		return false;
	}

	// SystemTimeToFileTime refuses an invalid date (month 13, February 30, ...)
	Zero(&tmp, sizeof(tmp));
	tmp.wYear = (WORD)year;
	tmp.wMonth = (WORD)month;
	tmp.wDay = (WORD)day;
	tmp.wHour = (WORD)hour;
	tmp.wMinute = (WORD)minute;
	tmp.wSecond = (WORD)second;
	tmp.wMilliseconds = (WORD)msec;

	if (SystemTimeToFileTime(&tmp, &ft) == FALSE)
	{
		return false;
	}

	// Local time minus the offset is UTC (FILETIME counts 100 ns units)
	t = ((UINT64)ft.dwHighDateTime << 32) | (UINT64)ft.dwLowDateTime;
	t = (UINT64)((INT64)t - offset_sign * (INT64)(offset_hour * 60 + offset_minute) * 600000000LL);
	ft.dwHighDateTime = (DWORD)(t >> 32);
	ft.dwLowDateTime = (DWORD)t;

	if (FileTimeToSystemTime(&ft, st) == FALSE)
	{
		Zero(st, sizeof(SYSTEMTIME));
		return false;
	}

	return true;
}

void GetSpanStrMilli(char *str, UINT size, UINT64 sec64)
{
	char tmp[MAX_SIZE];
	char days[MAX_SIZE];
	if (str == NULL)
	{
		return;
	}

	StrCpy(days, sizeof(days), "");
	if (sec64 >= (UINT64)(1000 * 3600 * 24))
	{
		Format(days, sizeof(days), "%u:", (UINT)(sec64 / (UINT64)(1000 * 3600 * 24)));
	}

	Format(tmp, sizeof(tmp), "%s%02u:%02u:%02u.%03u", days,
		(UINT)(sec64 % (UINT64)(1000 * 60 * 60 * 24)) / (1000 * 60 * 60),
		(UINT)(sec64 % (UINT64)(1000 * 60 * 60)) / (1000 * 60),
		(UINT)(sec64 % (UINT64)(1000 * 60)) / 1000,
		(UINT)(sec64 % (UINT64)(1000)));

	Trim(tmp);
	StrCpy(str, size, tmp);
}

void SetLocale(wchar_t *str)
{
	wchar_t *set_locale_str;
	LOCALE tmp;

	if (str != NULL)
	{
		set_locale_str = str;
	}
	else
	{
		set_locale_str = default_locale_str;
	}

	if (LoadLocale(&tmp, set_locale_str) == false)
	{
		if (LoadLocale(&tmp, default_locale_str) == false)
		{
			return;
		}
	}

	Copy(&current_locale, &tmp, sizeof(LOCALE));
}

#define	COPY_LOCALE_STR(dest, size, src)	UniStrCpy(dest, size, UniStrCmp(src, L"$") == 0 ? L"" : src)

bool LoadLocale(LOCALE *locale, wchar_t *str)
{
	UNI_TOKEN_LIST *tokens;
	UINT i;
	if (locale == NULL || str == NULL)
	{
		return false;
	}

	tokens = UniParseToken(str, L" ");
	if (tokens->NumTokens != 18)
	{
		UniFreeToken(tokens);
		return false;
	}

	Zero(locale, sizeof(LOCALE));
	COPY_LOCALE_STR(locale->YearStr, sizeof(locale->YearStr), tokens->Token[0]);
	COPY_LOCALE_STR(locale->MonthStr, sizeof(locale->MonthStr), tokens->Token[1]);
	COPY_LOCALE_STR(locale->DayStr, sizeof(locale->DayStr), tokens->Token[2]);
	COPY_LOCALE_STR(locale->HourStr, sizeof(locale->HourStr), tokens->Token[3]);
	COPY_LOCALE_STR(locale->MinuteStr, sizeof(locale->MinuteStr), tokens->Token[4]);
	COPY_LOCALE_STR(locale->SecondStr, sizeof(locale->SecondStr), tokens->Token[5]);

	for (i = 0;i < 7;i++)
	{
		COPY_LOCALE_STR(locale->DayOfWeek[i], sizeof(locale->DayOfWeek[i]),
			tokens->Token[6 + i]);
	}

	COPY_LOCALE_STR(locale->SpanDay, sizeof(locale->SpanDay), tokens->Token[13]);
	COPY_LOCALE_STR(locale->SpanHour, sizeof(locale->SpanHour), tokens->Token[14]);
	COPY_LOCALE_STR(locale->SpanMinute, sizeof(locale->SpanMinute), tokens->Token[15]);
	COPY_LOCALE_STR(locale->SpanSecond, sizeof(locale->SpanSecond), tokens->Token[16]);

	COPY_LOCALE_STR(locale->Unknown, sizeof(locale->Unknown), tokens->Token[17]);

	UniFreeToken(tokens);
	return true;
}

static void TmToSystem(SYSTEMTIME *st, struct tm *t)
{
	struct tm tmp;
	if (st == NULL || t == NULL)
	{
		return;
	}

	Copy(&tmp, t, sizeof(struct tm));
	NormalizeTm(&tmp);

	Zero(st, sizeof(SYSTEMTIME));
	st->wYear = MAKESURE(tmp.tm_year + 1900, 1970, 2099);
	st->wMonth = MAKESURE(tmp.tm_mon + 1, 1, 12);
	st->wDay = MAKESURE(tmp.tm_mday, 1, 31);
	st->wDayOfWeek = MAKESURE(tmp.tm_wday, 0, 6);
	st->wHour = MAKESURE(tmp.tm_hour, 0, 23);
	st->wMinute = MAKESURE(tmp.tm_min, 0, 59);
	st->wSecond = MAKESURE(tmp.tm_sec, 0, 59);
	st->wMilliseconds = 0;
}

static void SystemToTm(struct tm *t, SYSTEMTIME *st)
{
	if (t == NULL || st == NULL)
	{
		return;
	}

	Zero(t, sizeof(struct tm));
	t->tm_year = MAKESURE(st->wYear, 1970, 2099) - 1900;
	t->tm_mon = MAKESURE(st->wMonth, 1, 12) - 1;
	t->tm_mday = MAKESURE(st->wDay, 1, 31);
	t->tm_hour = MAKESURE(st->wHour, 0, 23);
	t->tm_min = MAKESURE(st->wMinute, 0, 59);
	t->tm_sec = MAKESURE(st->wSecond, 0, 59);

	t->tm_isdst = -1;
	NormalizeTm(t);
}

void TimeToSystem(SYSTEMTIME *st, time_64t t)
{
	struct tm tmp;
	if (st == NULL)
	{
		return;
	}

	TimeToTm(&tmp, t);
	TmToSystem(st, &tmp);
}

static time_64t SystemToTime(SYSTEMTIME *st)
{
	struct tm t;
	if (st == NULL)
	{
		return 0;
	}

	SystemToTm(&t, st);
	return TmToTime(&t);
}

time_64t TmToTime(struct tm *t)
{
	time_64t tmp;
	if (t == NULL)
	{
		return 0;
	}

	tmp = c_mkgmtime(t);
	if (tmp == (time_64t)-1)
	{
		return 0;
	}
	return tmp;
}

void TimeToTm(struct tm *t, time_64t time)
{
	if (t == NULL)
	{
		return;
	}

	Zero(t, sizeof(struct tm));
	c_gmtime_r(&time, t);
}

void NormalizeTm(struct tm *t)
{
	time_64t tmp;
	if (t == NULL)
	{
		return;
	}

	tmp = c_mkgmtime(t);
	if (tmp == (time_64t)-1)
	{
		return;
	}

	c_gmtime_r(&tmp, t);
}

void NormalizeSystem(SYSTEMTIME *st)
{
	UINT64 sec64;
	if (st == NULL)
	{
		return;
	}

	sec64 = SystemToUINT64(st);
	UINT64ToSystem(st, sec64);
}

UINT64 LocalToSystem64(UINT64 t)
{
	SYSTEMTIME st;
	UINT64ToSystem(&st, t);
	LocalToSystem(&st, &st);
	return SystemToUINT64(&st);
}

UINT64 SystemToLocal64(UINT64 t)
{
	SYSTEMTIME st;
	UINT64ToSystem(&st, t);
	SystemToLocal(&st, &st);
	return SystemToUINT64(&st);
}

void LocalToSystem(SYSTEMTIME *system, SYSTEMTIME *local)
{
	UINT64 sec64;
	if (local == NULL || system == NULL)
	{
		return;
	}

	sec64 = (UINT64)((INT64)SystemToUINT64(local) - GetTimeDiffEx(local, true));
	UINT64ToSystem(system, sec64);
}

void SystemToLocal(SYSTEMTIME *local, SYSTEMTIME *system)
{
	UINT64 sec64;
	if (local == NULL || system == NULL)
	{
		return;
	}

	sec64 = (UINT64)((INT64)SystemToUINT64(system) + GetTimeDiffEx(system, false));
	UINT64ToSystem(local, sec64);
}

INT64 GetTimeDiffEx(SYSTEMTIME *basetime, bool local_time)
{
	time_t tmp;
	struct tm t1, t2;
	SYSTEMTIME snow;
	struct tm now;
	SYSTEMTIME s1, s2;
	INT64 ret;

	Copy(&snow, basetime, sizeof(SYSTEMTIME));

	if (sizeof(time_t) == 4)
	{
		if (snow.wYear >= 2038)
		{
			// Clamp to 2037 to avoid the 2038 problem
			snow.wYear = 2037;
		}
	}

	SystemToTm(&now, &snow);
	if (local_time == false)
	{
		tmp = (time_t)c_mkgmtime(&now);
	}
	else
	{
		tmp = mktime(&now);
	}

	if (tmp == (time_t)-1)
	{
		return 0;
	}

	Copy(&t1, localtime(&tmp), sizeof(struct tm));
	Copy(&t2, gmtime(&tmp), sizeof(struct tm));

	TmToSystem(&s1, &t1);
	TmToSystem(&s2, &t2);

	ret = (INT)SystemToUINT64(&s1) - (INT)SystemToUINT64(&s2);

	return ret;
}

void UINT64ToSystem(SYSTEMTIME *st, UINT64 sec64)
{
	UINT64 tmp64;
	UINT sec, millisec;
	time_64t time;
	if (st == NULL)
	{
		return;
	}

	sec64 = SafeTime64(sec64 + 32400000ULL);
	tmp64 = sec64 / (UINT64)1000;
	millisec = (UINT)(sec64 - tmp64 * (UINT64)1000);
	sec = (UINT)tmp64;
	time = (time_64t)sec;
	TimeToSystem(st, time);
	st->wMilliseconds = (USHORT)millisec;
}

UINT64 SystemToUINT64(SYSTEMTIME *st)
{
	UINT64 sec64;
	time_64t time;
	if (st == NULL)
	{
		return 0;
	}

	time = SystemToTime(st);

	// Clamp times before 1970-01-01 to 0: the result is unsigned.
	// The bound allows for the 9-hour shift subtracted below.
	if( time < 32400000LL ) return 0;

	sec64 = (UINT64)time * (UINT64)1000;
	sec64 += st->wMilliseconds;

	return sec64 - 32400000ULL;
}

UINT64 LocalTime64()
{
	SYSTEMTIME s;
	LocalTime(&s);
	return SystemToUINT64(&s);
}

UINT64 SystemTime64()
{
	SYSTEMTIME s;
	SystemTime(&s);
	return SystemToUINT64(&s);
}

void LocalTime(SYSTEMTIME *st)
{
	SYSTEMTIME tmp;
	if (st == NULL)
	{
		return;
	}

	SystemTime(&tmp);
	SystemToLocal(st, &tmp);
}

void SystemTime(SYSTEMTIME *st)
{
	if (st == NULL)
	{
		return;
	}

	GetSystemTime(st);

	KS_INC(KS_GETTIME_COUNT);
}

time_64t c_mkgmtime(struct tm *tm)
{
	int years, months, days, hours, minutes, seconds;

	years = tm->tm_year + 1900;   /* year - 1900 -> year */
	months = tm->tm_mon;          /* 0..11 */
	days = tm->tm_mday - 1;       /* 1..31 -> 0..30 */
	hours = tm->tm_hour;          /* 0..23 */
	minutes = tm->tm_min;         /* 0..59 */
	seconds = tm->tm_sec;         /* 0..61 in ANSI C. */

	ADJUST_TM(seconds, minutes, 60);
	ADJUST_TM(minutes, hours, 60);
	ADJUST_TM(hours, days, 24);
	ADJUST_TM(months, years, 12);
	if (days < 0)
		do {
			if (--months < 0) {
				--years;
				months = 11;
			}
			days += monthlen(months, years);
		} while (days < 0);
	else
		while (days >= monthlen(months, years)) {
			days -= monthlen(months, years);
			if (++months >= 12) {
				++years;
				months = 0;
			}
		}

		tm->tm_year = years - 1900;
		tm->tm_mon = months;
		tm->tm_mday = days + 1;
		tm->tm_hour = hours;
		tm->tm_min = minutes;
		tm->tm_sec = seconds;

		days += ydays[months] + (months > 1 && leap (years));
		tm->tm_yday = days;

		days = (unsigned)days + 365 * (unsigned)(years - 1970) +
			(unsigned)(nleap (years));
		tm->tm_wday = ((unsigned)days + 4) % 7; /* Jan 1, 1970 was Thursday. */
		tm->tm_isdst = 0;

		if (years < 1970)
			return (time_64t)-1;

		if (years > TM_YEAR_MAX ||
			(years == TM_YEAR_MAX &&
			(tm->tm_yday > ydays[TM_MON_MAX] + (TM_MDAY_MAX - 1) +
			(TM_MON_MAX > 1 && leap (TM_YEAR_MAX)) ||
			(tm->tm_yday == ydays[TM_MON_MAX] + (TM_MDAY_MAX - 1) +
			(TM_MON_MAX > 1 && leap (TM_YEAR_MAX)) &&
			(hours > TM_HOUR_MAX ||
			(hours == TM_HOUR_MAX &&
			(minutes > TM_MIN_MAX ||
			(minutes == TM_MIN_MAX && seconds > TM_SEC_MAX) )))))))
			return (time_64t)-1;

		return (time_64t)(86400L * (unsigned long)(unsigned)days +
			3600L * (unsigned long)hours +
			(unsigned long)(60 * minutes + seconds));
}

void SleepThread(UINT time)
{
	KS_INC(KS_SLEEPTHREAD_COUNT);

	OSSleep(time);
}

void YieldCpu()
{
	OSYield();
}

void AbortExit()
{
	_exit(1);
}


void AbortExitEx(char *msg)
{
	FILE *f;
	if (msg == NULL)
	{
		msg = "Unknown Error";
	}

#ifdef	RANZ_FUZZING
	// libFuzzer build only (RANZ_FUZZ, cmake/RanzSanitizers.cmake): abort() instead of
	// _exit(1), so that libFuzzer's SIGABRT handler prints the stack and saves the input as a
	// crash artifact. No Windows Error Reporting when no SIGABRT handler is installed.
	fputs("Fatal Error: ", stdout);
	fputs(msg, stdout);
	fputs("\r\n", stdout);
	fflush(stdout);
	_set_abort_behavior(0, _WRITE_ABORT_MSG | _CALL_REPORTFAULT);
	abort();
#endif

	f = fopen("abort_error_log.txt", "w");
	if (f != NULL)
	{
		SYSTEMTIME time = { 0 };
		char time_str[128] = { 0 };
		char *crlf = "\r\n";
		char *tag = "---------";

		LocalTime(&time);

		sprintf(time_str, "%04u-%02u-%02u %02u:%02u:%02u",
			time.wYear, time.wMonth, time.wDay,
			time.wHour, time.wMinute, time.wSecond);

		fwrite(tag, 1, strlen(tag), f);

		fwrite(crlf, 1, strlen(crlf), f);

		fwrite(time_str, 1, strlen(time_str), f);

		fwrite(crlf, 1, strlen(crlf), f);

		fwrite(msg, 1, strlen(msg), f);

		fwrite(crlf, 1, strlen(crlf), f);

		fwrite(crlf, 1, strlen(crlf), f);

		fclose(f);
	}

	fputs("Fatal Error: ", stdout);
	fputs(msg, stdout);
	fputs("\r\n", stdout);

	_exit(1);
}


