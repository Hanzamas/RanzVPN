// SoftEther VPN Source Code - Developer Edition Master Branch
// Cedar Communication Module


// runtime.c
// Named runtime tests of vpntest (spec #30, Windows-native runtime)
//
// Each test pins behaviour that the Windows-native runtime (ADR-0016) must keep, and runs
// against the current implementation first. A test prints "<NAME> TEST OK" only when every
// check passes, and frees everything it allocates, so that the run still ends with
// "NO MEMORY LEAKS". The [PASS] lines carry no measured values; the [FAIL] details do.

#include "Mayaqua/Kernel.h"
#include "Mayaqua/Memory.h"
#include "Mayaqua/Object.h"
#include "Mayaqua/Str.h"
#include "Mayaqua/Tick64.h"

#include <stdarg.h>

// Limits
#define	RT_TICK_ORIGIN_MARGIN	10000		// Slack allowed above the process age (ms)

// Run state of one named test
typedef struct RT_CTX
{
	char *Marker;					// Name in the final line, upper case
	UINT NumChecks;					// Checks run so far
	UINT NumFailed;					// Checks failed so far
} RT_CTX;

// Start a named test
static void RtBegin(RT_CTX *ctx, char *marker, char *title)
{
	Zero(ctx, sizeof(RT_CTX));
	ctx->Marker = marker;

	Print("%s\n", title);
}

// Record one check: print [PASS], or [FAIL] with the formatted detail
static bool RtCheck(RT_CTX *ctx, bool ok, char *what, char *detail_fmt, ...)
{
	char detail[MAX_SIZE];
	va_list args;

	ctx->NumChecks++;

	if (ok)
	{
		Print("  [PASS] %s\n", what);
		return true;
	}

	va_start(args, detail_fmt);
	FormatArgs(detail, sizeof(detail), detail_fmt, args);
	va_end(args);

	Print("  [FAIL] %s (%s)\n", what, detail);

	ctx->NumFailed++;

	return false;
}

// Print the final line of a named test
static void RtEnd(RT_CTX *ctx)
{
	if (ctx->NumFailed == 0)
	{
		Print("%s TEST OK\n", ctx->Marker);
	}
	else
	{
		Print("%s TEST FAILED (%u of %u checks failed)\n", ctx->Marker, ctx->NumFailed, ctx->NumChecks);
	}
}

// Read a FILETIME as one 64-bit value (100 ns units)
static UINT64 RtFileTime64(FILETIME *ft)
{
	return ((UINT64)ft->dwHighDateTime << 32) | (UINT64)ft->dwLowDateTime;
}

// tickorigin: Tick64 counts from its first call in this process, so a value read at the
// start of the test is at least 1 and at most the age of the process
void tickorigin_test(UINT num, char **arg)
{
	RT_CTX ctx;
	FILETIME create_ft, exit_ft, kernel_ft, user_ft, now_ft;
	UINT64 tick, tick2;
	UINT64 age = 0;
	bool have_age;
	UINT err = 0;

	// Read the tick before anything else can take time
	tick = Tick64();

	RtBegin(&ctx, "TICKORIGIN", "Tick64 origin test");

	have_age = (GetProcessTimes(GetCurrentProcess(), &create_ft, &exit_ft, &kernel_ft, &user_ft) != FALSE);
	if (have_age == false)
	{
		err = GetLastError();
	}
	GetSystemTimeAsFileTime(&now_ft);
	if (have_age && RtFileTime64(&now_ft) >= RtFileTime64(&create_ft))
	{
		age = (RtFileTime64(&now_ft) - RtFileTime64(&create_ft)) / 10000ULL;
	}

	RtCheck(&ctx, have_age, "GetProcessTimes gives the process creation time", "error %u", err);
	RtCheck(&ctx, tick >= 1, "Tick64 is at least 1", "Tick64 = %I64u", tick);
	RtCheck(&ctx, have_age && tick <= age + RT_TICK_ORIGIN_MARGIN, "Tick64 is at most the process age plus the margin",
		"Tick64 = %I64u ms, process age = %I64u ms, margin = %u ms", tick, age, RT_TICK_ORIGIN_MARGIN);

	tick2 = Tick64();
	RtCheck(&ctx, tick2 >= tick, "Tick64 does not go back", "first %I64u, then %I64u", tick, tick2);

	RtEnd(&ctx);
}

// Constants of the timeenc test
#define	RT_TIME_TOLERANCE		2000					// Slack allowed between a Mayaqua clock and the OS clock (ms)
#define	RT_TIME_OFFSET			32400000ULL				// Offset subtracted by the UINT64 time encoding: 9 hours (ms)
#define	RT_UNIX_EPOCH_FILETIME	116444736000000000ULL	// 1970-01-01 00:00:00 UTC as a FILETIME (100 ns units)
#define	RT_TIME_2024			1709177696789ULL		// 2024-02-29 12:34:56.789 UTC, encoded
#define	RT_TIME_1971			32367600000ULL			// 1971-01-11 00:00:00.000 UTC, encoded: the smallest value above 0

// Distance between two UINT64 values
static UINT64 RtDiff64(UINT64 a, UINT64 b)
{
	return (a >= b) ? (a - b) : (b - a);
}

// Absolute value of an INT64
static INT64 RtAbs64(INT64 v)
{
	return (v < 0) ? -v : v;
}

// Fill a SYSTEMTIME (wDayOfWeek stays 0: the conversions ignore it on input)
static void RtSetSystem(SYSTEMTIME *st, UINT year, UINT month, UINT day, UINT hour, UINT minute, UINT second, UINT ms)
{
	Zero(st, sizeof(SYSTEMTIME));
	st->wYear = (WORD)year;
	st->wMonth = (WORD)month;
	st->wDay = (WORD)day;
	st->wHour = (WORD)hour;
	st->wMinute = (WORD)minute;
	st->wSecond = (WORD)second;
	st->wMilliseconds = (WORD)ms;
}

// Check that a SYSTEMTIME holds the given date, day of the week (0 = Sunday) and time
static void RtCheckSystem(RT_CTX *ctx, SYSTEMTIME *st, char *what, UINT year, UINT month, UINT day, UINT dow, UINT hour, UINT minute, UINT second, UINT ms)
{
	bool ok = (st->wYear == year && st->wMonth == month && st->wDay == day && st->wDayOfWeek == dow &&
		st->wHour == hour && st->wMinute == minute && st->wSecond == second && st->wMilliseconds == ms);

	RtCheck(ctx, ok, what, "got %04u-%02u-%02u %02u:%02u:%02u.%03u, day of the week %u",
		st->wYear, st->wMonth, st->wDay, st->wHour, st->wMinute, st->wSecond, st->wMilliseconds, st->wDayOfWeek);
}

// Offset of the OS time zone (local time minus UTC, ms) at the given UTC time
static bool RtOsZoneOffset(SYSTEMTIME *utc, INT64 *offset)
{
	SYSTEMTIME local;
	FILETIME utc_ft, local_ft;

	if (SystemTimeToTzSpecificLocalTime(NULL, utc, &local) == FALSE)
	{
		return false;
	}
	if (SystemTimeToFileTime(utc, &utc_ft) == FALSE || SystemTimeToFileTime(&local, &local_ft) == FALSE)
	{
		return false;
	}

	*offset = ((INT64)RtFileTime64(&local_ft) - (INT64)RtFileTime64(&utc_ft)) / 10000;

	return true;
}

// timeenc: the UINT64 time encoding is Unix-epoch milliseconds minus 9 hours, times before
// 1971-01-11 encode as 0, and local time is UTC plus the OS time zone offset
void timeenc_test(UINT num, char **arg)
{
	RT_CTX ctx;
	FILETIME now_ft;
	SYSTEMTIME st;
	UINT64 value, expect, local64, system64;
	INT64 offset, os_offset = 0;
	bool have_offset;

	RtBegin(&ctx, "TIMEENC", "Time encoding test");

	// SystemTime64 against the OS clock
	GetSystemTimeAsFileTime(&now_ft);
	value = SystemTime64();
	expect = (RtFileTime64(&now_ft) - RT_UNIX_EPOCH_FILETIME) / 10000ULL - RT_TIME_OFFSET;
	RtCheck(&ctx, RtDiff64(value, expect) <= RT_TIME_TOLERANCE, "SystemTime64 is the OS UTC time in Unix-epoch ms minus 9 hours",
		"SystemTime64 = %I64u, expected %I64u", value, expect);

	// LocalTime64 - SystemTime64 against the OS time zone offset
	GetSystemTime(&st);
	have_offset = RtOsZoneOffset(&st, &os_offset);
	local64 = LocalTime64();
	system64 = SystemTime64();
	offset = (INT64)local64 - (INT64)system64;
	RtCheck(&ctx, have_offset && RtAbs64(offset - os_offset) <= RT_TIME_TOLERANCE,
		"LocalTime64 - SystemTime64 is the OS time zone offset",
		"LocalTime64 - SystemTime64 = %I64d ms, OS offset = %I64d ms", offset, os_offset);

	// Fixed input: 2024-02-29 12:34:56.789 UTC, a Thursday
	RtSetSystem(&st, 2024, 2, 29, 12, 34, 56, 789);
	value = SystemToUINT64(&st);
	RtCheck(&ctx, value == RT_TIME_2024, "SystemToUINT64(2024-02-29 12:34:56.789)", "got %I64u, expected %I64u", value, RT_TIME_2024);
	UINT64ToSystem(&st, RT_TIME_2024);
	RtCheckSystem(&ctx, &st, "UINT64ToSystem gives back 2024-02-29 12:34:56.789", 2024, 2, 29, 4, 12, 34, 56, 789);

	// Fixed input at the lower limit: 1971-01-11 00:00:00.000 UTC is the smallest time above 0
	RtSetSystem(&st, 1971, 1, 11, 0, 0, 0, 0);
	value = SystemToUINT64(&st);
	RtCheck(&ctx, value == RT_TIME_1971, "SystemToUINT64(1971-01-11 00:00:00.000)", "got %I64u, expected %I64u", value, RT_TIME_1971);
	UINT64ToSystem(&st, RT_TIME_1971);
	RtCheckSystem(&ctx, &st, "UINT64ToSystem gives back 1971-01-11 00:00:00.000", 1971, 1, 11, 1, 0, 0, 0, 0);

	// Fixed inputs before the lower limit encode as 0
	RtSetSystem(&st, 1971, 1, 10, 23, 59, 59, 999);
	value = SystemToUINT64(&st);
	RtCheck(&ctx, value == 0, "SystemToUINT64(1971-01-10 23:59:59.999) is 0", "got %I64u", value);
	RtSetSystem(&st, 1970, 6, 15, 12, 0, 0, 0);
	value = SystemToUINT64(&st);
	RtCheck(&ctx, value == 0, "SystemToUINT64(1970-06-15 12:00:00.000) is 0", "got %I64u", value);

	// 0 decodes to 1970-01-01 09:00:00.000, a Thursday (the 9 hours added back)
	UINT64ToSystem(&st, 0);
	RtCheckSystem(&ctx, &st, "UINT64ToSystem(0) is 1970-01-01 09:00:00.000", 1970, 1, 1, 4, 9, 0, 0, 0);

	// SystemToLocal64 and LocalToSystem64 at the fixed input, against the OS time zone
	RtSetSystem(&st, 2024, 2, 29, 12, 34, 56, 789);
	have_offset = RtOsZoneOffset(&st, &os_offset);
	expect = (UINT64)((INT64)RT_TIME_2024 + os_offset);
	value = SystemToLocal64(RT_TIME_2024);
	RtCheck(&ctx, have_offset && value == expect, "SystemToLocal64(2024-02-29 12:34:56.789) adds the OS time zone offset",
		"got %I64u, expected %I64u", value, expect);
	value = LocalToSystem64(expect);
	RtCheck(&ctx, value == RT_TIME_2024, "LocalToSystem64 gives back 2024-02-29 12:34:56.789",
		"got %I64u, expected %I64u", value, RT_TIME_2024);

	// Times below the lower limit stay 0 in both directions
	value = SystemToLocal64(0);
	RtCheck(&ctx, value == 0, "SystemToLocal64(0) is 0", "got %I64u", value);
	value = LocalToSystem64(0);
	RtCheck(&ctx, value == 0, "LocalToSystem64(0) is 0", "got %I64u", value);

	RtEnd(&ctx);
}

// nullsafe: the LOCK, LIST, COUNTER, REF and EVENT functions accept NULL and do nothing
void nullsafe_test(UINT num, char **arg)
{
	RT_CTX ctx;
	LOCK *lock = NULL;				// A variable, not the NULL literal: the _DEBUG form of Lock() dereferences it
	COUNTER *counter = NULL;
	REF *ref = NULL;
	EVENT *e = NULL;
	LIST *o;
	UINT item = 1;
	UINT ret;

	RtBegin(&ctx, "NULLSAFE", "NULL safety test");

	// LOCK
	Lock(lock);
	Unlock(lock);
	RtCheck(&ctx, true, "Lock(NULL) and Unlock(NULL) return", "");
	RtCheck(&ctx, LockInner(lock) == false, "LockInner(NULL) returns false", "returned true");
	UnlockInner(lock);
	DeleteLock(lock);
	RtCheck(&ctx, true, "UnlockInner(NULL) and DeleteLock(NULL) return", "");

	// LockList/UnlockList on a list from NewListFast, which has no lock
	o = NewListFast(NULL);
	RtCheck(&ctx, o != NULL && o->lock == NULL, "NewListFast creates a list without a lock", "list %s", (o == NULL) ? "missing" : "has a lock");
	LockList(o);
	{
		Add(o, &item);
	}
	UnlockList(o);
	RtCheck(&ctx, LIST_NUM(o) == 1 && LIST_DATA(o, 0) == &item, "LockList and UnlockList work on that list", "%u items", LIST_NUM(o));
	ReleaseList(o);
	LockList(NULL);
	UnlockList(NULL);
	RtCheck(&ctx, true, "LockList(NULL) and UnlockList(NULL) return", "");

	// COUNTER and REF
	ret = Count(counter);
	RtCheck(&ctx, ret == 0, "Count(NULL) returns 0", "returned %u", ret);
	ret = Inc(counter);
	RtCheck(&ctx, ret == 0, "Inc(NULL) returns 0", "returned %u", ret);
	ret = Dec(counter);
	RtCheck(&ctx, ret == 0, "Dec(NULL) returns 0", "returned %u", ret);
	DeleteCounter(counter);
	ret = AddRef(ref);
	RtCheck(&ctx, ret == 0, "AddRef(NULL) returns 0", "returned %u", ret);
	ret = Release(ref);
	RtCheck(&ctx, ret == 0, "Release(NULL) returns 0", "returned %u", ret);

	// EVENT
	Set(e);
	RtCheck(&ctx, true, "Set(NULL) returns", "");
	RtCheck(&ctx, Wait(e, 0) == false, "Wait(NULL, 0) returns false", "returned true");
	ReleaseEvent(e);
	CleanupEvent(e);
	RtCheck(&ctx, true, "ReleaseEvent(NULL) and CleanupEvent(NULL) return", "");

	RtEnd(&ctx);
}
