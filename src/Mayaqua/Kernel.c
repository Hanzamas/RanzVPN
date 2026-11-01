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

// Constants of the UINT64 time encoding (Unix-epoch milliseconds minus 9 hours) and of the
// SYSTEMTIME conversions. A FILETIME counts 100 ns ticks since 1601-01-01 UTC.
#define TIME_TICKS_PER_MS     10000ULL              // FILETIME ticks in a millisecond
#define TIME_TICKS_PER_SEC    10000000ULL           // FILETIME ticks in a second
#define TIME_TICKS_PER_DAY    864000000000ULL       // FILETIME ticks in a day
#define TIME_UNIX_EPOCH_TICKS 116444736000000000ULL // 1970-01-01 00:00:00 UTC as a FILETIME
#define TIME_YEAR_MIN         1970                  // A SYSTEMTIME converted to the encoding is clamped to these years
#define TIME_YEAR_MAX         2099
#define TIME_ENCODE_OFFSET_MS 32400000ULL                    // 9 hours (ms), subtracted by the encoding
#define TIME_ENCODE_MIN_SEC   32400000ULL                    // Seconds after 1970 below which the encoding is 0: the offset above, compared with seconds (1971-01-11)
#define TIME_ENCODE_MAX_MS    4102243323123ULL               // Latest Unix-epoch time (ms) the encoding decodes (2099-12-29 16:02:03.123)
#define TIME_UNIX_SEC_MAX     (TIME_ENCODE_MAX_MS / 1000ULL) // Latest Unix time (s) TimeToSystem converts

static UINT cached_number_of_cpus = 0;


static wchar_t *default_locale_str =
    L"- - $ : : $ Sun Mon Tue Wed Thu Fri Sat : : : $ (None)";


static LOCALE current_locale;

UINT GetNumberOfCpu() {
	UINT ret = 0;

	if (cached_number_of_cpus == 0) {
		UINT i = 0;

		i = Win32GetNumberOfCpuInner();

		if (i == 0)
			i = 8;

		cached_number_of_cpus = i;
	}

	ret = cached_number_of_cpus;

	if (ret == 0)
		ret = 1;
	if (ret > 128)
		ret = 128;

	return ret;
}

// A value longer than the buffer is truncated
bool GetEnv(char *name, char *data, UINT size) {
	if (name == NULL || data == NULL)
		return false;

	StrCpy(data, size, "");

	// The size with the terminating null; 0 when the variable is not set
	DWORD len = GetEnvironmentVariableA(name, NULL, 0);
	if (len == 0)
		return false;

	char *tmp = ZeroMalloc(len);
	if (GetEnvironmentVariableA(name, tmp, len) < len)
		StrCpy(data, size, tmp);
	Free(tmp);

	return true;
}


INSTANCE *NewSingleInstance(char *instance_name) {
	char name[MAX_SIZE];
	void *data;

	if (instance_name != NULL) {
		HashInstanceName(name, sizeof(name), instance_name);

		data = Win32NewSingleInstance(name);
	} else {
		data = Win32NewSingleInstance(NULL);
	}

	if (data == NULL)
		return NULL;

	INSTANCE *ret = ZeroMalloc(sizeof(INSTANCE));
	if (instance_name != NULL)
		ret->Name = CopyStr(instance_name);

	ret->pData = data;

	return ret;
}

void FreeSingleInstance(INSTANCE *inst) {
	if (inst == NULL)
		return;

	Win32FreeSingleInstance(inst->pData);

	if (inst->Name != NULL)
		Free(inst->Name);
	Free(inst);
}

void HashInstanceName(char *name, UINT size, char *instance_name) {
	char tmp[MAX_SIZE];
	UCHAR hash[SHA1_SIZE];
	char key[11];
	if (name == NULL || instance_name == NULL)
		return;

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

void GetDateTimeStr64Uni(wchar_t *str, UINT size, UINT64 sec64) {
	char tmp[MAX_SIZE];
	if (str == NULL)
		return;

	GetDateTimeStr64(tmp, sizeof(tmp), sec64);
	StrToUni(str, size, tmp);
}
void GetDateTimeStr64(char *str, UINT size, UINT64 sec64) {
	SYSTEMTIME st;
	UINT64ToSystem(&st, sec64);
	GetDateTimeStr(str, size, &st);
}
void GetDateTimeStrMilli64(char *str, UINT size, UINT64 sec64) {
	SYSTEMTIME st;
	UINT64ToSystem(&st, sec64);
	GetDateTimeStrMilli(str, size, &st);
}
void GetDateStr64(char *str, UINT size, UINT64 sec64) {
	SYSTEMTIME st;
	if (sec64 == 0) {
		StrCpy(str, size, "(Unknown)");
		return;
	}
	UINT64ToSystem(&st, sec64);
	GetDateStr(str, size, &st);
}
void GetDateTimeStrEx64(wchar_t *str, UINT size, UINT64 sec64, LOCALE *locale) {
	SYSTEMTIME st;
	if (locale == NULL)
		locale = &current_locale;
	if (sec64 == 0 || SystemToLocal64(sec64) == 0 || LocalToSystem64(sec64) == 0) {
		UniStrCpy(str, size, locale->Unknown);
		return;
	}
	UINT64ToSystem(&st, sec64);
	GetDateTimeStrEx(str, size, &st, locale);
}
void GetDateStrEx64(wchar_t *str, UINT size, UINT64 sec64, LOCALE *locale) {
	SYSTEMTIME st;
	if (locale == NULL)
		locale = &current_locale;
	if (sec64 == 0 || SystemToLocal64(sec64) == 0 || LocalToSystem64(sec64) == 0) {
		UniStrCpy(str, size, locale->Unknown);
		return;
	}
	UINT64ToSystem(&st, sec64);
	GetDateStrEx(str, size, &st, locale);
}
void GetTimeStrMilli64(char *str, UINT size, UINT64 sec64) {
	SYSTEMTIME st;
	if (sec64 == 0 || SystemToLocal64(sec64) == 0 || LocalToSystem64(sec64) == 0) {
		StrCpy(str, size, "(Unknown)");
		return;
	}
	UINT64ToSystem(&st, sec64);
	GetTimeStrMilli(str, size, &st);
}

static UINT64 SafeTime64(UINT64 sec64) {
	return MAKESURE(sec64, 0, TIME_ENCODE_MAX_MS);
}

// A FILETIME as a count of 100 ns ticks, and back
static UINT64 FileTimeToTicks(FILETIME *ft) {
	return ((UINT64)ft->dwHighDateTime << 32) | (UINT64)ft->dwLowDateTime;
}

static void TicksToFileTime(FILETIME *ft, UINT64 ticks) {
	ft->dwHighDateTime = (DWORD)(ticks >> 32);
	ft->dwLowDateTime = (DWORD)ticks;
}

// The ticks of the UTC time in a SYSTEMTIME. Every field is clamped to its valid range and the
// year to 1970..2099; a day past the end of the month rolls into the next month. wMilliseconds
// and wDayOfWeek are not read. Returns 0 when the conversion fails
static UINT64 SystemToTicks(SYSTEMTIME *st) {
	SYSTEMTIME tmp;
	FILETIME ft;

	Zero(&tmp, sizeof(tmp));
	tmp.wYear = (WORD)MAKESURE(st->wYear, TIME_YEAR_MIN, TIME_YEAR_MAX);
	tmp.wMonth = (WORD)MAKESURE(st->wMonth, 1, 12);
	tmp.wDay = 1;
	tmp.wHour = (WORD)MAKESURE(st->wHour, 0, 23);
	tmp.wMinute = (WORD)MAKESURE(st->wMinute, 0, 59);
	tmp.wSecond = (WORD)MAKESURE(st->wSecond, 0, 59);

	if (SystemTimeToFileTime(&tmp, &ft) == FALSE)
		return 0;

	return FileTimeToTicks(&ft) + (UINT64)(MAKESURE(st->wDay, 1, 31) - 1) * TIME_TICKS_PER_DAY;
}

// The UINT64 time encoding of a time in ticks plus a number of milliseconds. Times before the
// lower limit encode as 0: the result is unsigned
static UINT64 TicksToTime64(UINT64 ticks, UINT64 add_ms) {
	if (ticks < TIME_UNIX_EPOCH_TICKS)
		return 0;

	UINT64 sec = (ticks - TIME_UNIX_EPOCH_TICKS) / TIME_TICKS_PER_SEC;
	if (sec < TIME_ENCODE_MIN_SEC)
		return 0;

	return sec * 1000ULL + add_ms - TIME_ENCODE_OFFSET_MS;
}

UINT64 FileTimeToUINT64(FILETIME *ft) {
	if (ft == NULL)
		return 0;

	UINT64 ticks = FileTimeToTicks(ft);

	return TicksToTime64(ticks, (ticks % TIME_TICKS_PER_SEC) / TIME_TICKS_PER_MS);
}

void UINT64ToFileTime(FILETIME *ft, UINT64 t) {
	if (ft == NULL)
		return;

	TicksToFileTime(ft, TIME_UNIX_EPOCH_TICKS + SafeTime64(t + TIME_ENCODE_OFFSET_MS) * TIME_TICKS_PER_MS);
}

// The THREAD jobs (NewThreadNamed) run on a private Windows thread pool. Every job joins the
// cleanup group, which FreeThreading waits on.
// The shutdown wait rests on an assumption: the Microsoft documentation of
// CloseThreadpoolCleanupGroupMembers names only work, wait and timer objects as members, and that
// a simple callback (TrySubmitThreadpoolCallback) joins the cleanup group of its environment is
// observed behaviour, not documented. The "NO MEMORY LEAKS" marker after the threadpool test of
// vpntest pins it: that test leaves a job running into the process exit.
#define THREAD_POOL_MAX_THREADS 65535 // Upper bound of pool threads: the Windows default (500) is too low for a server

static PTP_POOL thread_pool = NULL;
static PTP_CLEANUP_GROUP thread_pool_cleanup = NULL;
static TP_CALLBACK_ENVIRON thread_pool_env;
static volatile LONG thread_pool_posted = 0; // Jobs posted so far (only compared, so it may wrap)

void InitThreading() {
	thread_pool = CreateThreadpool(NULL);
	thread_pool_cleanup = CreateThreadpoolCleanupGroup();
	if (thread_pool == NULL || thread_pool_cleanup == NULL) {
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

void FreeThreading() {
	LONG posted;

	// Wait until every job has ended. A job that a running job posts after the wait took the
	// members of the cleanup group is not part of that wait, but NewThreadNamed counts the post
	// before the running job can end, so wait again until a whole wait passed without a post.
	do {
		posted = InterlockedCompareExchange(&thread_pool_posted, 0, 0);

		CloseThreadpoolCleanupGroupMembers(thread_pool_cleanup, FALSE, NULL);
	} while (InterlockedCompareExchange(&thread_pool_posted, 0, 0) != posted);

	CloseThreadpoolCleanupGroup(thread_pool_cleanup);
	thread_pool_cleanup = NULL;

	DestroyThreadpoolEnvironment(&thread_pool_env);

	CloseThreadpool(thread_pool);
	thread_pool = NULL;
}

// Pool callback of one THREAD job, called once on a thread of the pool: prepare the thread as a
// host thread (HostThreadProc), take the job, run it, wake the WaitThread callers, hold the thread
// until every other holder released the THREAD, and give the thread back as it was found
static void NTAPI ThreadPoolCallback(PTP_CALLBACK_INSTANCE instance, void *param) {
	THREAD *thread = (THREAD *)param;
	if (thread == NULL)
		return;

	// A job may run for the life of the process. The environment marks every callback as long
	// running (InitThreading), so the pool keeps another thread for the next job; a call to
	// CallbackMayRunLong on such a callback raises STATUS_INVALID_PARAMETER in ntdll.
	Win32InitNewThread();

	HRESULT hr = CoInitialize(NULL);

	thread->ThreadId = ThreadId();

	// NewThreadNamed returns from here on
	SetEvent((HANDLE)thread->StartedEvent);

	if (thread->Name != NULL)
		SetThreadName(thread->ThreadId, thread->Name, thread->param);
	else
		SetThreadName(thread->ThreadId, "Unknown", 0);

	thread->thread_proc(thread, thread->param);

	SetThreadName(thread->ThreadId, NULL, 0);

	// Every WaitThread caller, now or later, sees the end
	SetEvent((HANDLE)thread->EndedEvent);

	while (true) {
		if (Count(&thread->ref->c) <= 1)
			break;

		Wait(thread->release_event, 256);
	}

	ReleaseThread(thread);

	FreeOpenSSLThreadState();

	if (SUCCEEDED(hr))
		CoUninitialize();

	MsRestoreThreadPriority();
}

void SetThreadName(UINT thread_id, char *name, void *param) {
	if (IsDebug()) {
		char tmp[MAX_SIZE];

		if (name == NULL)
			StrCpy(tmp, sizeof(tmp), "idle");
		else
			snprintf(tmp, sizeof(tmp), "%s (%p)", name, param);

		Win32SetThreadName(thread_id, tmp);
	}
}

THREAD *NewThreadNamed(THREAD_PROC *thread_proc, void *param, char *name) {
	UINT retry = 0;
	if (thread_proc == NULL)
		return NULL;

	THREAD *ret = ZeroMalloc(sizeof(THREAD));
	ret->ref = NewRef();
	ret->thread_proc = thread_proc;
	ret->param = param;
	ret->pData = NULL;
	ret->init_finished_event = NewEvent();
	ret->StartedEvent = CreateEvent(NULL, FALSE, FALSE, NULL);
	ret->EndedEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
	ret->release_event = NewEvent();

	if (IsEmptyStr(name) == false)
		ret->Name = CopyStr(name);

	// The pool callback holds this reference until the job ended and every other holder let go
	AddRef(ret->ref);

	// Post the job, retried like the creation of a host thread
	while (TrySubmitThreadpoolCallback(ThreadPoolCallback, ret, &thread_pool_env) == FALSE) {
		if ((retry++) > 60) {
			printf("\n\n*** error: new thread create failed.\n\n");
			AbortExit();
		}

		SleepThread(500);
	}

	// Count the post before this returns, so that a running job's post is counted before the job ends
	InterlockedIncrement(&thread_pool_posted);

	// Return once a pool thread took the job
	if (ret->StartedEvent != NULL) {
		WaitForSingleObject((HANDLE)ret->StartedEvent, INFINITE);
		CloseHandle((HANDLE)ret->StartedEvent);
		ret->StartedEvent = NULL;
	}

	return ret;
}

static void CleanupThread(THREAD *t) {
	if (t == NULL)
		return;

	ReleaseEvent(t->init_finished_event);
	ReleaseEvent(t->release_event);

	if (t->EndedEvent != NULL)
		CloseHandle((HANDLE)t->EndedEvent);

	if (t->Name != NULL)
		Free(t->Name);

	Free(t);
}

void ReleaseThread(THREAD *t) {
	if (t == NULL)
		return;

	EVENT *e = t->release_event;
	if (e != NULL)
		AddRef(e->ref);

	UINT ret = Release(t->ref);
	Set(e);

	ReleaseEvent(e);

	if (ret == 0)
		CleanupThread(t);
}

void NoticeThreadInit(THREAD *t) {
	if (t == NULL)
		return;

	Set(t->init_finished_event);
}

void WaitThreadInit(THREAD *t) {
	if (t == NULL)
		return;

	KS_INC(KS_WAITFORTHREAD_COUNT);

	Wait(t->init_finished_event, INFINITE);
}

bool WaitThread(THREAD *t, UINT timeout) {
	if (t == NULL || t->EndedEvent == NULL)
		return false;

	// Any number of threads can wait: the end event is manual-reset and never reset.
	// Only a time-out gives false, as Wait gives for an EVENT.
	return (WaitForSingleObject((HANDLE)t->EndedEvent, timeout) != WAIT_TIMEOUT);
}

// Thread handle of a host THREAD (its pData), from the raw OS allocator
typedef struct HOST_THREAD {
	HANDLE hThread;
} HOST_THREAD;

// Startup information of a host thread, from the raw OS allocator
typedef struct HOST_THREAD_STARTUP {
	THREAD_PROC *thread_proc;
	void *param;
	THREAD *thread;
} HOST_THREAD_STARTUP;

// Host thread procedure: run the THREAD procedure on the new OS thread
static UINT __stdcall HostThreadProc(void *param) {
	HOST_THREAD_STARTUP *info = (HOST_THREAD_STARTUP *)param;
	// Validate arguments
	if (info == NULL)
		return 0;

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

THREAD *NewThreadInternal(THREAD_PROC *thread_proc, void *param) {
	UINT retry = 0;
	if (thread_proc == NULL)
		return NULL;

	THREAD *t = ZeroMalloc(sizeof(THREAD));
	t->init_finished_event = NewEvent();

	t->param = param;
	t->ref = NewRef();
	t->thread_proc = thread_proc;

	while (true) {
		HOST_THREAD *host;

		if ((retry++) > 60) {
			printf("\n\n*** error: new thread create failed.\n\n");
			AbortExit();
		}

		// Creating the startup information: the new thread holds one reference
		HOST_THREAD_STARTUP *info = Win32MemoryAlloc(sizeof(HOST_THREAD_STARTUP));
		info->thread_proc = t->thread_proc;
		info->param = t->param;
		info->thread = t;
		AddRef(t->ref);

		HANDLE h = (HANDLE)_beginthreadex(NULL, 0, HostThreadProc, info, 0, NULL);
		if (h != NULL) {
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

void ReleaseThreadInternal(THREAD *t) {
	if (t == NULL)
		return;

	if (Release(t->ref) == 0)
		CleanupThreadInternal(t);
}

void CleanupThreadInternal(THREAD *t) {
	if (t == NULL)
		return;

	// Close the thread handle
	HOST_THREAD *host = (HOST_THREAD *)t->pData;
	if (host != NULL) {
		CloseHandle(host->hThread);
		Win32MemoryFree(host);
		t->pData = NULL;
	}

	ReleaseEvent(t->init_finished_event);
	Free(t);

	KS_INC(KS_FREETHREAD_COUNT);
}

bool WaitThreadInternal(THREAD *t) {
	if (t == NULL)
		return false;

	HOST_THREAD *host = (HOST_THREAD *)t->pData;
	if (host == NULL)
		return false;

	// Only WAIT_OBJECT_0 means that the thread ended
	return (WaitForSingleObject(host->hThread, INFINITE) == WAIT_OBJECT_0);
}

void NoticeThreadInitInternal(THREAD *t) {
	if (t == NULL)
		return;

	Set(t->init_finished_event);
}

void GetDateTimeStrEx(wchar_t *str, UINT size, SYSTEMTIME *st, LOCALE *locale) {
	wchar_t tmp1[MAX_SIZE];
	wchar_t tmp2[MAX_SIZE];
	if (str == NULL || st == NULL)
		return;

	GetDateStrEx(tmp1, sizeof(tmp1), st, locale);
	GetTimeStrEx(tmp2, sizeof(tmp2), st, locale);
	UniFormat(str, size, L"%s %s", tmp1, tmp2);
}

void GetTimeStrEx(wchar_t *str, UINT size, SYSTEMTIME *st, LOCALE *locale) {
	if (str == NULL || st == NULL)
		return;

	locale = (locale != NULL ? locale : &current_locale);
	UniFormat(str, size,
	          L"%02u%s%02u%s%02u%s",
	          st->wHour, locale->HourStr,
	          st->wMinute, locale->MinuteStr,
	          st->wSecond, locale->SecondStr);
}

void GetDateStrEx(wchar_t *str, UINT size, SYSTEMTIME *st, LOCALE *locale) {
	if (str == NULL || st == NULL)
		return;

	locale = (locale != NULL ? locale : &current_locale);
	UniFormat(str, size,
	          L"%04u%s%02u%s%02u%s (%s)",
	          st->wYear, locale->YearStr,
	          st->wMonth, locale->MonthStr,
	          st->wDay, locale->DayStr,
	          locale->DayOfWeek[st->wDayOfWeek]);
}

// The narrow date strings write their digits by hand into a local string and copy it with
// StrCpy, which cuts it as Format did: at most size - 1 characters (no limit for size 0) and the
// terminator. Each field prints as the %0<width>u of its format: at least width digits,
// zero-padded, and every digit of a larger value.

// Room for the longest narrow date string and its terminator (54 bytes): every field of five
// digits, and an RFC 3339 offset of eight digits of hours
#define DATE_STR_SIZE 64

// Write v at p as %0<width>u prints it (width 10 at most); returns the end
static char *DateStrDigits(char *p, UINT v, UINT width) {
	char digits[10];
	UINT n = 0;

	do {
		digits[n++] = (char)('0' + v % 10);
		v /= 10;
	} while (v != 0);

	while (n < width)
		digits[n++] = '0';

	while (n != 0)
		*p++ = digits[--n];

	return p;
}

// Write the date of st at p as "%04u-%02u-%02u"; returns the end
static char *DateStrDate(char *p, SYSTEMTIME *st) {
	p = DateStrDigits(p, st->wYear, 4);
	*p++ = '-';
	p = DateStrDigits(p, st->wMonth, 2);
	*p++ = '-';
	return DateStrDigits(p, st->wDay, 2);
}

// Write the time of st at p as "%02u:%02u:%02u"; returns the end
static char *DateStrTime(char *p, SYSTEMTIME *st) {
	p = DateStrDigits(p, st->wHour, 2);
	*p++ = ':';
	p = DateStrDigits(p, st->wMinute, 2);
	*p++ = ':';
	return DateStrDigits(p, st->wSecond, 2);
}

// Write the milliseconds of st at p as ".%03u"; returns the end
static char *DateStrMilli(char *p, SYSTEMTIME *st) {
	*p++ = '.';
	return DateStrDigits(p, st->wMilliseconds, 3);
}

void GetTimeStrMilli(char *str, UINT size, SYSTEMTIME *st) {
	char tmp[DATE_STR_SIZE];
	if (st == NULL || str == NULL)
		return;

	char *p = DateStrTime(tmp, st);
	p = DateStrMilli(p, st);
	*p = 0;

	StrCpy(str, size, tmp);
}

void GetDateStr(char *str, UINT size, SYSTEMTIME *st) {
	char tmp[DATE_STR_SIZE];
	if (str == NULL || st == NULL)
		return;

	char *p = DateStrDate(tmp, st);
	*p = 0;

	StrCpy(str, size, tmp);
}

void GetDateTimeStr(char *str, UINT size, SYSTEMTIME *st) {
	char tmp[DATE_STR_SIZE];
	if (str == NULL || st == NULL)
		return;

	char *p = DateStrDate(tmp, st);
	*p++ = ' ';
	p = DateStrTime(p, st);
	*p = 0;

	StrCpy(str, size, tmp);
}

void GetDateTimeStrMilli(char *str, UINT size, SYSTEMTIME *st) {
	char tmp[DATE_STR_SIZE];
	if (str == NULL || st == NULL)
		return;

	char *p = DateStrDate(tmp, st);
	*p++ = ' ';
	p = DateStrTime(p, st);
	p = DateStrMilli(p, st);
	*p = 0;

	StrCpy(str, size, tmp);
}


// Print an RFC 3339 date-time: st is the local time and timezone_min its offset from UTC in
// minutes (local time minus UTC, positive east of UTC). Offset 0 prints "Z", any other offset
// prints "+HH:MM" or "-HH:MM", the sign taken from the whole offset and both fields two digits
void GetDateTimeStrRFC3339(char *str, UINT size, SYSTEMTIME *st, int timezone_min) {
	char tmp[DATE_STR_SIZE];
	UINT abs_min;
	if (str == NULL || st == NULL) {
		ClearStr(str, size);
		return;
	}

	char *p = DateStrDate(tmp, st);
	*p++ = 'T';
	p = DateStrTime(p, st);
	p = DateStrMilli(p, st);

	if (timezone_min == 0) {
		*p++ = 'Z';
	} else {
		abs_min = (timezone_min < 0) ? (UINT)(-timezone_min) : (UINT)timezone_min;

		*p++ = (timezone_min < 0) ? '-' : '+';
		p = DateStrDigits(p, abs_min / 60, 2);
		*p++ = ':';
		p = DateStrDigits(p, abs_min % 60, 2);
	}
	*p = 0;

	StrCpy(str, size, tmp);
}

// Read count decimal digits at str. Stops at the first character that is not a digit, so it
// never reads past the end of the string
static bool ParseRFC3339Digits(const char *str, UINT count, UINT *value) {
	*value = 0;
	for (UINT i = 0; i < count; i++) {
		if (str[i] < '0' || str[i] > '9')
			return false;

		*value = *value * 10 + (UINT)(str[i] - '0');
	}

	return true;
}

// Parse an RFC 3339 date-time, "YYYY-MM-DDTHH:MM:SS", an optional fraction of a second and the
// offset "Z", "+HH:MM" or "-HH:MM", into the UTC time it names. Fraction digits after the third
// are dropped; "T" and "Z" may be lower case. A leap second (60) is refused, as SYSTEMTIME cannot
// hold it. Returns false, with st zeroed, for anything else, an invalid date included
bool DateTimeStrRFC3339ToSystemTime(SYSTEMTIME *st, char *str) {
	UINT year, month, day, hour, minute, second;
	UINT msec = 0, msec_scale = 100;
	UINT offset_hour = 0, offset_minute = 0;
	INT64 offset_sign = 0;
	SYSTEMTIME tmp;
	FILETIME ft;
	if (st == NULL)
		return false;

	Zero(st, sizeof(SYSTEMTIME));

	if (str == NULL)
		return false;

	if (ParseRFC3339Digits(str, 4, &year) == false || str[4] != '-' ||
	    ParseRFC3339Digits(str + 5, 2, &month) == false || str[7] != '-' ||
	    ParseRFC3339Digits(str + 8, 2, &day) == false || (str[10] != 'T' && str[10] != 't') ||
	    ParseRFC3339Digits(str + 11, 2, &hour) == false || str[13] != ':' ||
	    ParseRFC3339Digits(str + 14, 2, &minute) == false || str[16] != ':' ||
	    ParseRFC3339Digits(str + 17, 2, &second) == false ||
	    hour > 23 || minute > 59 || second > 59)
		return false;

	char *p = str + 19;

	// Fraction of a second: at least one digit, the first three kept
	if (*p == '.') {
		p++;
		if (*p < '0' || *p > '9')
			return false;

		while (*p >= '0' && *p <= '9') {
			msec += (UINT)(*p - '0') * msec_scale;
			msec_scale /= 10;
			p++;
		}
	}

	// Offset from UTC
	if (*p == 'Z' || *p == 'z') {
		p++;
	} else if (*p == '+' || *p == '-') {
		offset_sign = (*p == '-') ? -1 : 1;

		if (ParseRFC3339Digits(p + 1, 2, &offset_hour) == false || p[3] != ':' ||
		    ParseRFC3339Digits(p + 4, 2, &offset_minute) == false ||
		    offset_hour > 23 || offset_minute > 59)
			return false;

		p += 6;
	} else {
		return false;
	}

	if (*p != 0)
		return false;

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
		return false;

	// Local time minus the offset is UTC (FILETIME counts 100 ns units)
	UINT64 t = FileTimeToTicks(&ft);
	t = (UINT64)((INT64)t - offset_sign * (INT64)(offset_hour * 60 + offset_minute) * (INT64)(60ULL * TIME_TICKS_PER_SEC));
	TicksToFileTime(&ft, t);

	if (FileTimeToSystemTime(&ft, st) == FALSE) {
		Zero(st, sizeof(SYSTEMTIME));
		return false;
	}

	return true;
}

void GetSpanStrMilli(char *str, UINT size, UINT64 sec64) {
	char tmp[MAX_SIZE];
	char days[MAX_SIZE];
	if (str == NULL)
		return;

	StrCpy(days, sizeof(days), "");
	if (sec64 >= (UINT64)(1000 * 3600 * 24))
		Format(days, sizeof(days), "%u:", (UINT)(sec64 / (UINT64)(1000 * 3600 * 24)));

	Format(tmp, sizeof(tmp), "%s%02u:%02u:%02u.%03u", days,
	       (UINT)(sec64 % (UINT64)(1000 * 60 * 60 * 24)) / (1000 * 60 * 60),
	       (UINT)(sec64 % (UINT64)(1000 * 60 * 60)) / (1000 * 60),
	       (UINT)(sec64 % (UINT64)(1000 * 60)) / 1000,
	       (UINT)(sec64 % (UINT64)(1000)));

	Trim(tmp);
	StrCpy(str, size, tmp);
}

void SetLocale(wchar_t *str) {
	wchar_t *set_locale_str;
	LOCALE tmp;

	if (str != NULL)
		set_locale_str = str;
	else
		set_locale_str = default_locale_str;

	if (LoadLocale(&tmp, set_locale_str) == false) {
		if (LoadLocale(&tmp, default_locale_str) == false)
			return;
	}

	Copy(&current_locale, &tmp, sizeof(LOCALE));
}

#define COPY_LOCALE_STR(dest, size, src) UniStrCpy(dest, size, UniStrCmp(src, L"$") == 0 ? L"" : src)

bool LoadLocale(LOCALE *locale, wchar_t *str) {
	if (locale == NULL || str == NULL)
		return false;

	UNI_TOKEN_LIST *tokens = UniParseToken(str, L" ");
	if (tokens->NumTokens != 18) {
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

	for (UINT i = 0; i < 7; i++)
		COPY_LOCALE_STR(locale->DayOfWeek[i], sizeof(locale->DayOfWeek[i]),
		                tokens->Token[6 + i]);

	COPY_LOCALE_STR(locale->SpanDay, sizeof(locale->SpanDay), tokens->Token[13]);
	COPY_LOCALE_STR(locale->SpanHour, sizeof(locale->SpanHour), tokens->Token[14]);
	COPY_LOCALE_STR(locale->SpanMinute, sizeof(locale->SpanMinute), tokens->Token[15]);
	COPY_LOCALE_STR(locale->SpanSecond, sizeof(locale->SpanSecond), tokens->Token[16]);

	COPY_LOCALE_STR(locale->Unknown, sizeof(locale->Unknown), tokens->Token[17]);

	UniFreeToken(tokens);
	return true;
}

void TimeToSystem(SYSTEMTIME *st, time_64t t) {
	FILETIME ft;
	if (st == NULL)
		return;

	// The times that the UINT64 encoding holds
	if (t < 0)
		t = 0;
	if (t > (time_64t)TIME_UNIX_SEC_MAX)
		t = (time_64t)TIME_UNIX_SEC_MAX;

	TicksToFileTime(&ft, TIME_UNIX_EPOCH_TICKS + (UINT64)t * TIME_TICKS_PER_SEC);
	if (FileTimeToSystemTime(&ft, st) == FALSE)
		Zero(st, sizeof(SYSTEMTIME));
}

void NormalizeSystem(SYSTEMTIME *st) {
	if (st == NULL)
		return;

	UINT64 sec64 = SystemToUINT64(st);
	UINT64ToSystem(st, sec64);
}

UINT64 LocalToSystem64(UINT64 t) {
	SYSTEMTIME st;
	UINT64ToSystem(&st, t);
	LocalToSystem(&st, &st);
	return SystemToUINT64(&st);
}

UINT64 SystemToLocal64(UINT64 t) {
	SYSTEMTIME st;
	UINT64ToSystem(&st, t);
	SystemToLocal(&st, &st);
	return SystemToUINT64(&st);
}

void LocalToSystem(SYSTEMTIME *system, SYSTEMTIME *local) {
	if (local == NULL || system == NULL)
		return;

	UINT64 sec64 = (UINT64)((INT64)SystemToUINT64(local) - GetTimeDiffEx(local, true));
	UINT64ToSystem(system, sec64);
}

void SystemToLocal(SYSTEMTIME *local, SYSTEMTIME *system) {
	if (local == NULL || system == NULL)
		return;

	UINT64 sec64 = (UINT64)((INT64)SystemToUINT64(system) + GetTimeDiffEx(system, false));
	UINT64ToSystem(local, sec64);
}

INT64 GetTimeDiffEx(SYSTEMTIME *basetime, bool local_time) {
	FILETIME ft;
	SYSTEMTIME base, other;
	if (basetime == NULL)
		return 0;

	// Clamp and normalize the fields as SystemToUINT64 does
	UINT64 base_ticks = SystemToTicks(basetime);
	if (base_ticks == 0)
		return 0;

	TicksToFileTime(&ft, base_ticks);
	if (FileTimeToSystemTime(&ft, &base) == FALSE)
		return 0;

	if (local_time == false) {
		// basetime is UTC
		if (SystemTimeToTzSpecificLocalTime(NULL, &base, &other) == FALSE)
			return 0;
	} else {
		// basetime is local time
		if (TzSpecificLocalTimeToSystemTime(NULL, &base, &other) == FALSE)
			return 0;
	}

	if (SystemTimeToFileTime(&other, &ft) == FALSE)
		return 0;
	UINT64 other_ticks = FileTimeToTicks(&ft);

	// Local time minus UTC, in milliseconds
	if (local_time == false)
		return ((INT64)other_ticks - (INT64)base_ticks) / (INT64)TIME_TICKS_PER_MS;

	return ((INT64)base_ticks - (INT64)other_ticks) / (INT64)TIME_TICKS_PER_MS;
}

void UINT64ToSystem(SYSTEMTIME *st, UINT64 sec64) {
	FILETIME ft;
	if (st == NULL)
		return;

	UINT64ToFileTime(&ft, sec64);
	if (FileTimeToSystemTime(&ft, st) == FALSE)
		Zero(st, sizeof(SYSTEMTIME));
}

UINT64 SystemToUINT64(SYSTEMTIME *st) {
	if (st == NULL)
		return 0;

	return TicksToTime64(SystemToTicks(st), st->wMilliseconds);
}

UINT64 LocalTime64() {
	return SystemToLocal64(SystemTime64());
}

UINT64 SystemTime64() {
	FILETIME ft;

	GetSystemTimeAsFileTime(&ft);

	KS_INC(KS_GETTIME_COUNT);

	return FileTimeToUINT64(&ft);
}

void LocalTime(SYSTEMTIME *st) {
	SYSTEMTIME tmp;
	if (st == NULL)
		return;

	SystemTime(&tmp);
	SystemToLocal(st, &tmp);
}

void SystemTime(SYSTEMTIME *st) {
	if (st == NULL)
		return;

	GetSystemTime(st);

	KS_INC(KS_GETTIME_COUNT);
}

void SleepThread(UINT time) {
	KS_INC(KS_SLEEPTHREAD_COUNT);

	Sleep(time);
}

void AbortExit() {
	_exit(1);
}


// The log goes beside the executable, not into the working directory (System32 for a service).
// Plain CRT and Win32 calls only: the caller may be out of memory.
void AbortExitEx(char *msg) {
	if (msg == NULL)
		msg = "Unknown Error";

#ifdef RANZ_FUZZING
	// libFuzzer build only (RANZ_FUZZ, cmake/RanzSanitizers.cmake): abort() instead of
	// _exit(1), so that libFuzzer's SIGABRT handler prints the stack and saves the input as a
	// crash artifact. No Windows Error Reporting when no SIGABRT handler is installed.
	fputs("Fatal Error: ", stdout);
	fputs(msg, stdout);
	fputs("\r\n", stdout);
	fflush(stdout);
	_set_abort_behavior(0, _WRITE_ABORT_MSG | _CALL_REPORTFAULT);
	abort();
#else  // RANZ_FUZZING
	FILE *f = NULL;
	wchar_t log_name[MAX_PATH + 32];
	DWORD len;

	len = GetModuleFileNameW(NULL, log_name, MAX_PATH);
	if (len != 0 && len < MAX_PATH) {
		wchar_t *sep = wcsrchr(log_name, L'\\');
		if (sep != NULL) {
			sep[1] = 0;
			wcscat_s(log_name, sizeof(log_name) / sizeof(wchar_t), L"abort_error_log.txt");
			f = _wfopen(log_name, L"w");
		}
	}
	if (f != NULL) {
		SYSTEMTIME time = {0};
		char time_str[128] = {0};
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
	fflush(stdout);

	_exit(1);
#endif // RANZ_FUZZING
}


// Offset of local time from UTC in minutes (positive east of UTC), for the time zone
// information and the zone ID that GetTimeZoneInformation returned. The biases of
// TIME_ZONE_INFORMATION are UTC minus local time: the offset is the zone bias plus the
// daylight or standard bias in effect, with the sign turned around
int GetTimezoneInfoOffsetWin32(TIME_ZONE_INFORMATION *info, UINT zone_id) {
	if (info == NULL)
		return 0;

	LONG bias = info->Bias;

	if (zone_id == TIME_ZONE_ID_DAYLIGHT)
		bias += info->DaylightBias;
	else if (zone_id == TIME_ZONE_ID_STANDARD)
		bias += info->StandardBias;

	return -(int)bias;
}

// Offset of local time from UTC in minutes (positive east of UTC) at the UTC time utc, for the
// time zone data info, or for the time zone of the OS when info is NULL. The OS converts that
// one time by the rule of the zone data, so the offset is right on the day that daylight saving
// time changes too. 0 when utc is NULL or the OS cannot convert it
int GetTimezoneOffsetAtUtcWin32(TIME_ZONE_INFORMATION *info, SYSTEMTIME *utc) {
	SYSTEMTIME local;
	FILETIME utc_ft, local_ft;
	if (utc == NULL)
		return 0;

	if (SystemTimeToTzSpecificLocalTime(info, utc, &local) == FALSE)
		return 0;
	if (SystemTimeToFileTime(utc, &utc_ft) == FALSE || SystemTimeToFileTime(&local, &local_ft) == FALSE)
		return 0;

	// Local time minus UTC, in minutes
	return (int)(((INT64)FileTimeToTicks(&local_ft) - (INT64)FileTimeToTicks(&utc_ft)) / (INT64)(60 * TIME_TICKS_PER_SEC));
}

// Current offset of local time from UTC in minutes (positive east of UTC), daylight saving
// time included when it is in effect at this moment; 0 when the OS cannot convert the time.
// The OS converts the moment, as SystemToLocal does. The zone ID of GetTimeZoneInformation is
// not used: on 2026-11-01, for hours before US daylight time ended, it gave -480 on the arm64
// runner where the conversion gave -420 (ticket #601)
int GetCurrentTimezone() {
	SYSTEMTIME utc;

	SystemTime(&utc);

	return GetTimezoneOffsetAtUtcWin32(NULL, &utc);
}
