// SoftEther VPN Source Code - Developer Edition Master Branch
// Cedar Communication Module


// runtime.c
// Named runtime tests of vpntest (spec #30, Windows-native runtime)
//
// Each test pins behaviour that the Windows-native runtime (ADR-0016) must keep, and runs
// against the current implementation first. A test prints "<NAME> TEST OK" only when every
// check passes, and frees everything it allocates, so that the run still ends with
// "NO MEMORY LEAKS". The [PASS] lines carry no measured values; the [FAIL] details do.

#include "Mayaqua/DNS.h"
#include "Mayaqua/Encrypt.h"
#include "Mayaqua/FileIO.h"
#include "Mayaqua/Internat.h"
#include "Mayaqua/Kernel.h"
#include "Mayaqua/Memory.h"
#include "Mayaqua/Network.h"
#include "Mayaqua/Object.h"
#include "Mayaqua/Str.h"
#include "Mayaqua/Tick64.h"

#include <stdarg.h>

#include <objbase.h>

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

// Constants of the nullsafe test
#define	RT_EVENT_NO_HANDLE_WAIT	1000		// Timeout given to Wait on an EVENT without a handle (ms)

// nullsafe: the LOCK, LIST, COUNTER, REF and EVENT functions accept NULL and do nothing
void nullsafe_test(UINT num, char **arg)
{
	RT_CTX ctx;
	LOCK *lock = NULL;				// A variable, not the NULL literal: the old _DEBUG macro form of Lock() dereferenced it
	COUNTER *counter = NULL;
	REF *ref = NULL;
	EVENT *e = NULL;
	LIST *o;
	UINT item = 1;
	UINT ret;
	UINT64 start, elapsed;
	bool waited;

	RtBegin(&ctx, "NULLSAFE", "NULL safety test");

	// LOCK
	Lock(lock);
	Unlock(lock);
	RtCheck(&ctx, true, "Lock(NULL) and Unlock(NULL) return", "");
	RtCheck(&ctx, Lock(lock) == false, "Lock(NULL) returns false", "returned true");
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

	// An EVENT without a kernel event, as an unchecked failed CreateEvent leaves it: Set does
	// nothing, Wait returns false without waiting, and ReleaseEvent still frees the EVENT.
	// WaitForSingleObject on the NULL handle would fail at once and give true (WAIT_FAILED)
	e = NewEvent();
	CloseHandle((HANDLE)e->pData);
	e->pData = NULL;
	Set(e);
	start = Tick64();
	waited = Wait(e, RT_EVENT_NO_HANDLE_WAIT);
	elapsed = Tick64() - start;
	RtCheck(&ctx, waited == false && elapsed < RT_EVENT_NO_HANDLE_WAIT, "Wait on an EVENT without a handle returns false at once",
		"returned %s after %I64u ms", waited ? "true" : "false", elapsed);
	ReleaseEvent(e);
	RtCheck(&ctx, true, "Set and ReleaseEvent on an EVENT without a handle return", "");

	RtEnd(&ctx);
}

// Constants of the fileio test
#define	RT_FILEIO_LOG_NAME		L"vpntest_fileio_log.tmp"	// Written through the "@" prefix (log directory)
#define	RT_FILEIO_DB_NAME		L"vpntest_fileio_db.tmp"	// Written through the "$" prefix (database directory)
#define	RT_FILEIO_DATA_SIZE		64							// Bytes written to each test file
#define	RT_FILEIO_AUX_NAME		L"vpntest_fileio_aux.tmp"	// Replaced, sought, dated, hidden and renamed through "@"
#define	RT_FILEIO_REN_NAME		L"vpntest_fileio_ren.tmp"	// Rename target through "@"
#define	RT_FILEIO_DIR_NAME		L"vpntest_fileio_dir.tmp"	// Directory made and deleted through "@"
#define	RT_FILEIO_SHORT_SIZE	8							// Bytes written when FileCreate replaces the aux file
#define	RT_FILEIO_CREATE_TIME	(RT_TIME_2024 - 86400000ULL)	// Creation date written on close: one day before RT_TIME_2024
#define	RT_FILEIO_DATE_SLACK	600000ULL					// Slack between the update date read on open and SystemTime64 (ms)

// Size and SHA-256 of the watermark, shared with watermark_test (vpntest.c)
extern UINT watermark_expect_size;
extern char *watermark_expect_sha256;

// Create a file through a prefixed name ("@" or "$"), write the test bytes, and check that
// the file is at the expected path
static void RtFileioCreate(RT_CTX *ctx, wchar_t *name, wchar_t *expect_path, UCHAR *data, char *label)
{
	IO *io;
	char what[MAX_SIZE];

	// A file left by an earlier failed run
	FileDeleteW(expect_path);

	Format(what, sizeof(what), "FileCreate through %s returns a file", label);
	io = FileCreateW(name);
	if (RtCheck(ctx, io != NULL, what, "returned NULL") == false)
	{
		return;
	}

	Format(what, sizeof(what), "FileWrite through %s writes the test bytes", label);
	RtCheck(ctx, FileWrite(io, data, RT_FILEIO_DATA_SIZE), what, "failed");

	Format(what, sizeof(what), "The file of %s is in its directory", label);
	RtCheck(ctx, UniStrCmpi(io->NameW, expect_path) == 0, what, "created as %S, expected %S", io->NameW, expect_path);

	FileClose(io);

	Format(what, sizeof(what), "The file of %s exists after FileClose", label);
	RtCheck(ctx, IsFileExistsW(expect_path), what, "not found");
}

// FileCreate empties an existing file; write mode opens read-write; a read-only file refuses
// writes. Leaves the aux file holding data[0..7] followed by data[0..63] (72 bytes).
static void RtFileioReplace(RT_CTX *ctx, wchar_t *aux_path, UCHAR *data)
{
	UCHAR buf[RT_FILEIO_DATA_SIZE];
	UINT64 size;
	IO *io;

	io = FileCreateW(L"@" RT_FILEIO_AUX_NAME);
	if (RtCheck(ctx, io != NULL, "FileCreate of the aux file", "returned NULL") == false)
	{
		return;
	}
	RtCheck(ctx, FileWrite(io, data, RT_FILEIO_DATA_SIZE), "FileWrite of the aux file", "failed");
	FileClose(io);

	io = FileCreateW(L"@" RT_FILEIO_AUX_NAME);
	if (RtCheck(ctx, io != NULL, "FileCreate of an existing file", "returned NULL") == false)
	{
		return;
	}
	size = FileSize64(io);
	RtCheck(ctx, size == 0, "FileCreate of an existing file empties it", "%I64u bytes", size);
	RtCheck(ctx, FileWrite(io, data, RT_FILEIO_SHORT_SIZE), "FileWrite of the short content", "failed");
	FileClose(io);

	// Write mode opens read-write: read the content back through the writer, then append
	io = FileOpenW(aux_path, true);
	if (RtCheck(ctx, io != NULL, "FileOpen of the aux file for writing", "returned NULL") == false)
	{
		return;
	}
	size = FileSize64(io);
	RtCheck(ctx, size == RT_FILEIO_SHORT_SIZE, "The replaced file holds only the new bytes",
		"%I64u bytes, expected %u", size, RT_FILEIO_SHORT_SIZE);
	RtCheck(ctx, FileRead(io, buf, RT_FILEIO_SHORT_SIZE) && Cmp(buf, data, RT_FILEIO_SHORT_SIZE) == 0,
		"A file opened for writing can be read", "read failed or the bytes differ");
	RtCheck(ctx, FileWrite(io, data, RT_FILEIO_DATA_SIZE), "FileWrite appends at the current position", "failed");
	size = FileSize64(io);
	RtCheck(ctx, size == RT_FILEIO_SHORT_SIZE + RT_FILEIO_DATA_SIZE, "FileSize64 of an open writer counts the appended bytes",
		"%I64u bytes, expected %u", size, RT_FILEIO_SHORT_SIZE + RT_FILEIO_DATA_SIZE);
	FileFlush(io);
	FileClose(io);

	io = FileOpenW(aux_path, false);
	if (RtCheck(ctx, io != NULL, "FileOpen of the aux file read-only", "returned NULL") == false)
	{
		return;
	}
	RtCheck(ctx, FileWrite(io, data, 1) == false, "FileWrite on a read-only file fails", "returned true");
	RtCheck(ctx, FileRead(io, buf, 0), "FileRead of 0 bytes succeeds", "returned false");
	FileClose(io);
}

// FileSeek: the three origins, an unknown origin, a position before the start, and the
// position that equals ERROR_NEGATIVE_SEEK (131). Kept as is: the backend compares the new
// position returned by SetFilePointer with that error code, so this seek reports failure.
static void RtFileioSeek(RT_CTX *ctx, wchar_t *aux_path, UCHAR *data)
{
	UCHAR buf[RT_FILEIO_SHORT_SIZE];
	IO *io;

	io = FileOpenW(aux_path, false);
	if (RtCheck(ctx, io != NULL, "FileOpen of the aux file for seeking", "returned NULL") == false)
	{
		return;
	}

	// The last 8 bytes are data[56..63]
	RtCheck(ctx, FileSeek(io, FILE_END, -RT_FILEIO_SHORT_SIZE) && FileRead(io, buf, RT_FILEIO_SHORT_SIZE) &&
		Cmp(buf, data + RT_FILEIO_DATA_SIZE - RT_FILEIO_SHORT_SIZE, RT_FILEIO_SHORT_SIZE) == 0,
		"FileSeek from the end", "seek or read failed, or the bytes differ");

	// Back 16 from the end lands on data[48..55]
	RtCheck(ctx, FileSeek(io, FILE_CURRENT, -2 * RT_FILEIO_SHORT_SIZE) && FileRead(io, buf, RT_FILEIO_SHORT_SIZE) &&
		Cmp(buf, data + RT_FILEIO_DATA_SIZE - 2 * RT_FILEIO_SHORT_SIZE, RT_FILEIO_SHORT_SIZE) == 0,
		"FileSeek from the current position", "seek or read failed, or the bytes differ");

	// Offset 8 is data[0..7]
	RtCheck(ctx, FileSeek(io, FILE_BEGIN, RT_FILEIO_SHORT_SIZE) && FileRead(io, buf, RT_FILEIO_SHORT_SIZE) &&
		Cmp(buf, data, RT_FILEIO_SHORT_SIZE) == 0,
		"FileSeek from the beginning", "seek or read failed, or the bytes differ");

	RtCheck(ctx, FileSeek(io, 3, 0) == false, "FileSeek with an unknown origin fails", "returned true");
	RtCheck(ctx, FileSeek(io, FILE_BEGIN, -1) == false, "FileSeek before the beginning fails", "returned true");
	RtCheck(ctx, FileSeek(io, FILE_BEGIN, ERROR_NEGATIVE_SEEK) == false,
		"FileSeek to offset 131 reports failure (kept as is)", "returned true");

	FileClose(io);
}

// File dates: FileOpen reads them; FileClose of a writer writes the dates set in the IO
static void RtFileioDates(RT_CTX *ctx, wchar_t *aux_path)
{
	UINT64 now;
	IO *io;

	io = FileOpenW(aux_path, true);
	if (RtCheck(ctx, io != NULL, "FileOpen of the aux file for the dates", "returned NULL") == false)
	{
		return;
	}
	now = SystemTime64();
	RtCheck(ctx, io->GetUpdateTime != 0 && RtDiff64(io->GetUpdateTime, now) <= RT_FILEIO_DATE_SLACK,
		"FileOpen reads the update date", "update date %I64u, SystemTime64 %I64u", io->GetUpdateTime, now);
	RtCheck(ctx, io->GetCreateTime != 0 && io->GetAccessTime != 0, "FileOpen reads the creation and access dates",
		"creation %I64u, access %I64u", io->GetCreateTime, io->GetAccessTime);

	io->SetCreateTime = RT_FILEIO_CREATE_TIME;
	io->SetUpdateTime = RT_TIME_2024;
	FileClose(io);

	io = FileOpenW(aux_path, false);
	if (RtCheck(ctx, io != NULL, "FileOpen of the aux file after the dates", "returned NULL") == false)
	{
		return;
	}
	RtCheck(ctx, io->GetUpdateTime == RT_TIME_2024, "FileClose of a writer writes the update date",
		"got %I64u, expected %I64u", io->GetUpdateTime, RT_TIME_2024);
	RtCheck(ctx, io->GetCreateTime == RT_FILEIO_CREATE_TIME, "FileClose of a writer writes the creation date",
		"got %I64u, expected %I64u", io->GetCreateTime, RT_FILEIO_CREATE_TIME);
	FileClose(io);
}

// FileCreate of a hidden file: CreateFileW with FILE_ATTRIBUTE_NORMAL is denied on it, and the
// retry with FILE_ATTRIBUTE_HIDDEN replaces it, so the file stays hidden
static void RtFileioHidden(RT_CTX *ctx, wchar_t *aux_path, UCHAR *data)
{
	DWORD attr;
	IO *io;
	BOOL marked;
	UINT err;

	// Read the error right after the call: argument evaluation order is unspecified in C
	marked = SetFileAttributesW(aux_path, FILE_ATTRIBUTE_HIDDEN);
	err = (marked == FALSE) ? GetLastError() : 0;
	RtCheck(ctx, marked != FALSE, "Mark the aux file hidden", "error %u", err);

	io = FileCreateW(L"@" RT_FILEIO_AUX_NAME);
	if (RtCheck(ctx, io != NULL, "FileCreate replaces a hidden file", "returned NULL"))
	{
		RtCheck(ctx, FileWrite(io, data, RT_FILEIO_SHORT_SIZE), "FileWrite of the replaced hidden file", "failed");
		FileClose(io);
	}

	attr = GetFileAttributesW(aux_path);
	RtCheck(ctx, attr != INVALID_FILE_ATTRIBUTES && (attr & FILE_ATTRIBUTE_HIDDEN) != 0, "The replaced file stays hidden",
		"attributes %u", attr);

	SetFileAttributesW(aux_path, FILE_ATTRIBUTE_NORMAL);
}

// More sharing: read-locked readers coexist and lock out a writer; a reader without the read
// lock lets a writer in; FileCreate shares read like a writer
static void RtFileioShare(RT_CTX *ctx, wchar_t *aux_path)
{
	IO *io, *io2;

	io = FileOpenW(aux_path, false);
	if (RtCheck(ctx, io != NULL, "FileOpen read-only", "returned NULL"))
	{
		io2 = FileOpenW(aux_path, false);
		RtCheck(ctx, io2 != NULL, "While it is open read-only, a second read-only FileOpen succeeds", "returned NULL");
		FileClose(io2);

		io2 = FileOpenW(aux_path, true);
		RtCheck(ctx, io2 == NULL, "While it is open read-only with the read lock, FileOpen for writing fails", "succeeded");
		FileClose(io2);

		FileClose(io);
	}

	io = FileOpenExW(aux_path, false, false);
	if (RtCheck(ctx, io != NULL, "FileOpenEx read-only without the read lock", "returned NULL"))
	{
		io2 = FileOpenW(aux_path, true);
		RtCheck(ctx, io2 != NULL, "While it is open without the read lock, FileOpen for writing succeeds", "returned NULL");
		FileClose(io2);

		FileClose(io);
	}

	io = FileCreateW(L"@" RT_FILEIO_AUX_NAME);
	if (RtCheck(ctx, io != NULL, "FileCreate of the aux file for sharing", "returned NULL"))
	{
		io2 = FileOpenExW(aux_path, false, false);
		RtCheck(ctx, io2 != NULL, "While FileCreate holds it, a read-only FileOpenEx without the read lock succeeds", "returned NULL");
		FileClose(io2);

		io2 = FileOpenW(aux_path, false);
		RtCheck(ctx, io2 == NULL, "While FileCreate holds it, a read-only FileOpen fails", "succeeded");
		FileClose(io2);

		FileClose(io);
	}
}

// FileRename moves a file and does not replace an existing target
static void RtFileioRename(RT_CTX *ctx, wchar_t *aux_path, wchar_t *ren_path)
{
	RtCheck(ctx, FileRenameW(L"@" RT_FILEIO_AUX_NAME, L"@" RT_FILEIO_REN_NAME), "FileRename through @", "failed");
	RtCheck(ctx, IsFileExistsW(ren_path) && IsFileExistsW(aux_path) == false, "FileRename moves the file",
		"source %s, target %s", IsFileExistsW(aux_path) ? "still there" : "gone", IsFileExistsW(ren_path) ? "there" : "missing");

	FileClose(FileCreateW(L"@" RT_FILEIO_AUX_NAME));
	RtCheck(ctx, FileRenameW(L"@" RT_FILEIO_AUX_NAME, L"@" RT_FILEIO_REN_NAME) == false, "FileRename onto an existing file fails",
		"returned true");
	RtCheck(ctx, IsFileExistsW(aux_path), "The source of the refused FileRename stays", "gone");

	RtCheck(ctx, FileDeleteW(L"@" RT_FILEIO_REN_NAME) && IsFileExistsW(ren_path) == false, "FileDelete of the rename target",
		"file still there");
}

// MakeDir and DeleteDir: each fails when there is nothing to do
static void RtFileioDir(RT_CTX *ctx, wchar_t *dir_path)
{
	DWORD attr;

	RtCheck(ctx, MakeDirW(L"@" RT_FILEIO_DIR_NAME), "MakeDir through @", "failed");
	attr = GetFileAttributesW(dir_path);
	RtCheck(ctx, attr != INVALID_FILE_ATTRIBUTES && (attr & FILE_ATTRIBUTE_DIRECTORY) != 0, "MakeDir creates the directory",
		"attributes %u", attr);
	RtCheck(ctx, MakeDirW(L"@" RT_FILEIO_DIR_NAME) == false, "MakeDir of an existing directory fails", "returned true");

	RtCheck(ctx, DeleteDirW(L"@" RT_FILEIO_DIR_NAME), "DeleteDir through @", "failed");
	RtCheck(ctx, GetFileAttributesW(dir_path) == INVALID_FILE_ATTRIBUTES, "DeleteDir removes the directory", "still there");
	RtCheck(ctx, DeleteDirW(L"@" RT_FILEIO_DIR_NAME) == false, "DeleteDir of a missing directory fails", "returned true");
}

// fileio: the "@", "$" and "|" prefixes, the path separator, the sharing modes, the
// all-or-nothing reads, and the create, seek, date, rename and directory semantics of FileIO
void fileio_test(UINT num, char **arg)
{
	RT_CTX ctx;
	wchar_t dir[MAX_SIZE];
	wchar_t log_path[MAX_SIZE];
	wchar_t db_path[MAX_SIZE];
	wchar_t aux_path[MAX_SIZE];
	wchar_t ren_path[MAX_SIZE];
	wchar_t dir_path[MAX_SIZE];
	wchar_t slash_path[MAX_SIZE];
	UCHAR data[RT_FILEIO_DATA_SIZE];
	UCHAR buf[RT_FILEIO_DATA_SIZE];
	UCHAR hash[SHA256_SIZE];
	char hash_str[SHA256_SIZE * 2 + 1];
	IO *io, *io2;
	UINT i, size;
	void *ham;
	bool ok;

	RtBegin(&ctx, "FILEIO", "FileIO test");

	for (i = 0;i < RT_FILEIO_DATA_SIZE;i++)
	{
		data[i] = (UCHAR)(i * 7 + 1);
	}

	GetExeDirW(dir, sizeof(dir));
	ConbinePathW(log_path, sizeof(log_path), dir, RT_FILEIO_LOG_NAME);
	ConbinePathW(aux_path, sizeof(aux_path), dir, RT_FILEIO_AUX_NAME);
	ConbinePathW(ren_path, sizeof(ren_path), dir, RT_FILEIO_REN_NAME);
	ConbinePathW(dir_path, sizeof(dir_path), dir, RT_FILEIO_DIR_NAME);
	GetExeDirW(dir, sizeof(dir));
	ConbinePathW(db_path, sizeof(db_path), dir, RT_FILEIO_DB_NAME);

	// "@" resolves under the log directory, "$" under the database directory
	RtFileioCreate(&ctx, L"@" RT_FILEIO_LOG_NAME, log_path, data, "@ (log directory)");
	RtFileioCreate(&ctx, L"$" RT_FILEIO_DB_NAME, db_path, data, "$ (database directory)");

	// "/" becomes "\": open the "@" file through its path written with forward slashes
	UniStrCpy(slash_path, sizeof(slash_path), log_path);
	for (i = 0;slash_path[i] != 0;i++)
	{
		if (slash_path[i] == L'\\')
		{
			slash_path[i] = L'/';
		}
	}
	io = FileOpenW(slash_path, false);
	if (RtCheck(&ctx, io != NULL, "FileOpen of the path written with forward slashes", "returned NULL"))
	{
		ok = true;
		for (i = 0;io->NameW[i] != 0;i++)
		{
			if (io->NameW[i] == L'/')
			{
				ok = false;
			}
		}
		RtCheck(&ctx, ok && UniStrCmpi(io->NameW, log_path) == 0, "Forward slashes become backslashes",
			"opened as %S, expected %S", io->NameW, log_path);

		// Reads are all or nothing: a read past the end fails instead of returning a short read
		RtCheck(&ctx, FileRead(io, buf, RT_FILEIO_DATA_SIZE) && Cmp(buf, data, RT_FILEIO_DATA_SIZE) == 0,
			"FileRead returns the written bytes", "read failed or the bytes differ");
		RtCheck(&ctx, FileRead(io, buf, 1) == false, "FileRead at the end fails", "returned true");
		RtCheck(&ctx, FileSeek(io, FILE_BEGIN, RT_FILEIO_DATA_SIZE / 2), "FileSeek on a disk file succeeds", "failed");
		RtCheck(&ctx, FileRead(io, buf, RT_FILEIO_DATA_SIZE) == false, "FileRead across the end fails", "returned true");

		FileClose(io);
	}

	// Sharing: while the file is open for writing, a read-only open without the read lock
	// succeeds, a read-only FileOpen (which takes the read lock) fails, and a second writer fails
	io = FileOpenW(log_path, true);
	if (RtCheck(&ctx, io != NULL, "FileOpen for writing", "returned NULL"))
	{
		io2 = FileOpenExW(log_path, false, false);
		RtCheck(&ctx, io2 != NULL, "While it is open for writing, a read-only FileOpenEx without the read lock succeeds", "returned NULL");
		FileClose(io2);

		io2 = FileOpenW(log_path, false);
		RtCheck(&ctx, io2 == NULL, "While it is open for writing, a read-only FileOpen fails", "succeeded");
		FileClose(io2);

		io2 = FileOpenW(log_path, true);
		RtCheck(&ctx, io2 == NULL, "While it is open for writing, a second FileOpen for writing fails", "succeeded");
		FileClose(io2);

		FileClose(io);
	}

	// "|" reads a hamcore file into memory: the watermark, which cannot seek
	io = FileOpen("|watermark.bin", false);
	if (RtCheck(&ctx, io != NULL, "FileOpen of |watermark.bin", "returned NULL"))
	{
		size = FileSize(io);
		RtCheck(&ctx, size == watermark_expect_size, "FileSize of |watermark.bin is the watermark size",
			"%u bytes, expected %u", size, watermark_expect_size);

		ham = ZeroMalloc(size + 1);
		ok = FileRead(io, ham, size);
		Sha2_256(hash, ham, size);
		BinToStr(hash_str, sizeof(hash_str), hash, sizeof(hash));
		RtCheck(&ctx, ok && StrCmpi(hash_str, watermark_expect_sha256) == 0, "FileRead of |watermark.bin returns the watermark bytes (SHA-256)",
			"read %s, SHA-256 = %s", ok ? "ok" : "failed", hash_str);
		Free(ham);

		RtCheck(&ctx, FileSeek(io, FILE_BEGIN, 0) == false, "FileSeek on a hamcore file fails", "succeeded");

		FileClose(io);
	}

	// Create, seek, dates, hidden retry, sharing, rename and directories on the aux file.
	// First remove what an earlier failed run may have left (a hidden file deletes too).
	FileDeleteW(aux_path);
	FileDeleteW(ren_path);
	DeleteDirW(dir_path);
	RtFileioReplace(&ctx, aux_path, data);
	RtFileioSeek(&ctx, aux_path, data);
	RtFileioDates(&ctx, aux_path);
	RtFileioHidden(&ctx, aux_path, data);
	RtFileioShare(&ctx, aux_path);
	RtFileioRename(&ctx, aux_path, ren_path);
	RtFileioDir(&ctx, dir_path);

	// Delete the files
	RtCheck(&ctx, FileDeleteW(L"@" RT_FILEIO_LOG_NAME) && IsFileExistsW(log_path) == false,
		"FileDelete through @ removes the file", "file still there");
	RtCheck(&ctx, FileDeleteW(L"$" RT_FILEIO_DB_NAME) && IsFileExistsW(db_path) == false,
		"FileDelete through $ removes the file", "file still there");
	RtCheck(&ctx, FileDeleteW(L"@" RT_FILEIO_AUX_NAME) && IsFileExistsW(aux_path) == false,
		"FileDelete of the aux file", "file still there");
	RtCheck(&ctx, FileDeleteW(L"@" RT_FILEIO_AUX_NAME) == false, "FileDelete of a missing file fails", "returned true");

	RtEnd(&ctx);
}

// Constants of the threadpool test
#define	RT_POOL_BOUND			5000	// Fail-safe bound of every wait in the threadpool test (ms)
#define	RT_POOL_SETTLE			300		// Time given to an idle pool thread to (wrongly) end (ms)
#define	RT_POOL_MAX_JOBS		32		// Held jobs started while looking for the idle pool thread
#define	RT_POOL_WAITERS			4		// Threads that wait on one THREAD at the same time
#define	RT_HOST_CYCLES			16		// Host threads created and ended by the handle check
#define	RT_POOL_MARK			0x5A17C0DE	// Per-thread mark the first job leaves on its pool thread

// Per-thread state of the pool thread: a later job on the same thread must see it
static __declspec(thread) UINT rt_pool_mark = 0;

// What a job of the threadpool test saw on its thread
typedef struct RT_POOL_JOB
{
	volatile bool *Go;				// Gate the job waits for before it ends, or NULL
	volatile UINT OsThreadId;		// GetCurrentThreadId() inside the job
	volatile UINT MayaThreadId;		// ThreadId() inside the job
	volatile bool ComReady;			// COM was already initialised on the thread of the job
	volatile bool Ran;				// The job ran
	UINT MarkSet;					// Per-thread mark the job leaves on its thread, or 0
	volatile UINT MarkSeen;			// Per-thread mark the job found on its thread
} RT_POOL_JOB;

// Threads that wait on one THREAD at the same time
typedef struct RT_POOL_WAIT_DATA
{
	THREAD *Target;					// THREAD that every waiter waits on
	volatile LONG Returned;			// Waiters whose WaitThread returned
	volatile LONG Joined;			// Waiters whose WaitThread returned true
} RT_POOL_WAIT_DATA;

// Wait until a flag is set, at most bound ms
static bool RtWaitFlag(volatile bool *flag, UINT bound)
{
	UINT64 end = Tick64() + bound;

	while (*flag == false)
	{
		if (Tick64() >= end)
		{
			return false;
		}

		SleepThread(1);
	}

	return true;
}

// Job: record what it sees on its thread, then wait for its gate when it has one.
// Used both as a pool job (NewThread) and as a host thread procedure (NewThreadInternal).
static void RtPoolJobThread(THREAD *t, void *param)
{
	RT_POOL_JOB *j = (RT_POOL_JOB *)param;
	HRESULT hr;

	if (t == NULL || j == NULL)
	{
		return;
	}

	j->OsThreadId = GetCurrentThreadId();
	j->MayaThreadId = ThreadId();

	// S_FALSE: COM is already initialised on this thread, by the host thread procedure
	hr = CoInitialize(NULL);
	j->ComReady = (hr == S_FALSE);
	if (SUCCEEDED(hr))
	{
		CoUninitialize();
	}

	// Per-thread state left by an earlier job on this thread
	j->MarkSeen = rt_pool_mark;
	if (j->MarkSet != 0)
	{
		rt_pool_mark = j->MarkSet;
	}

	j->Ran = true;

	if (j->Go != NULL)
	{
		RtWaitFlag(j->Go, RT_POOL_BOUND);
	}
}

// Waiter: wait on the target THREAD and count the result
static void RtPoolWaiterThread(THREAD *t, void *param)
{
	RT_POOL_WAIT_DATA *d = (RT_POOL_WAIT_DATA *)param;

	if (t == NULL || d == NULL)
	{
		return;
	}

	if (WaitThread(d->Target, RT_POOL_BOUND))
	{
		InterlockedIncrement(&d->Joined);
	}

	InterlockedIncrement(&d->Returned);
}

// threadpool: NewThread runs each job on a pooled host thread (open question 12 (a)).
// NewThread returns only after a host thread took the job, the job sees the thread id and
// the COM state of its host, an idle host thread stays alive and takes a later job, several
// threads can wait on one THREAD, and a host thread (NewThreadInternal) ends with its
// handle closed
void threadpool_test(UINT num, char **arg)
{
	RT_CTX ctx;
	RT_POOL_JOB first, host, target_job;
	RT_POOL_JOB held[RT_POOL_MAX_JOBS];
	THREAD *jobs[RT_POOL_MAX_JOBS];
	THREAD *waiters[RT_POOL_WAITERS];
	RT_POOL_WAIT_DATA wd;
	volatile bool go;
	THREAD *t;
	HANDLE h;
	UINT picked, i, num_jobs, joined, early, waited, ran, com_ready, found_index = 0;
	DWORD handles_before = 0, handles_after = 0;
	bool ended, alive, found, counted;

	RtBegin(&ctx, "THREADPOOL", "Thread pool test");

	// A job runs on a pool thread, which has already taken the job when NewThread returns
	Zero(&first, sizeof(first));
	first.MarkSet = RT_POOL_MARK;
	t = NewThread(RtPoolJobThread, &first);
	picked = t->ThreadId;
	RtCheck(&ctx, picked != 0, "NewThread returns after a pool thread took the job (ThreadId is set)", "ThreadId is 0");
	ended = WaitThread(t, RT_POOL_BOUND);
	RtCheck(&ctx, ended && first.Ran, "the job runs and WaitThread returns true", "WaitThread %s, job %s",
		ended ? "true" : "false", first.Ran ? "ran" : "did not run");
	RtCheck(&ctx, first.OsThreadId == picked && first.MayaThreadId == picked,
		"the job runs on the thread named by ThreadId, and ThreadId() in the job agrees",
		"THREAD ThreadId %u, GetCurrentThreadId %u, ThreadId() %u", picked, first.OsThreadId, first.MayaThreadId);
	RtCheck(&ctx, first.ComReady, "COM is already initialised on the thread of the job", "CoInitialize did not return S_FALSE");
	RtCheck(&ctx, WaitThreadInternal(NULL) == false && WaitThreadInternal(t) == false,
		"WaitThreadInternal returns false for NULL and for a pool job, which has no thread handle", "returned true");
	ReleaseThread(t);

	// The pool thread stays alive while it is idle (until FreeThreading)
	h = OpenThread(SYNCHRONIZE, FALSE, picked);
	alive = (h != NULL && WaitForSingleObject(h, RT_POOL_SETTLE) == WAIT_TIMEOUT);
	RtCheck(&ctx, alive, "the pool thread stays alive after its job ended", "the thread %s",
		(h == NULL) ? "is gone" : "ended");
	if (h != NULL)
	{
		CloseHandle(h);
	}

	// A later job runs on that idle pool thread. Every job is held at its gate, so each
	// NewThread takes another idle pool thread, until one of them is that thread.
	Zero(held, sizeof(held));
	go = false;
	found = false;
	num_jobs = 0;
	for (i = 0;i < RT_POOL_MAX_JOBS && found == false;i++)
	{
		held[i].Go = &go;
		jobs[i] = NewThread(RtPoolJobThread, &held[i]);
		num_jobs++;

		if (jobs[i]->ThreadId == picked)
		{
			found = true;
			found_index = i;
		}
	}
	go = true;
	joined = 0;
	for (i = 0;i < num_jobs;i++)
	{
		if (WaitThread(jobs[i], RT_POOL_BOUND))
		{
			joined++;
		}
		ReleaseThread(jobs[i]);
	}
	RtCheck(&ctx, found, "a later job runs on the same, idle pool thread", "not taken by any of %u jobs", num_jobs);
	RtCheck(&ctx, found && held[found_index].MarkSeen == RT_POOL_MARK,
		"per-thread state survives from one job to the next on the same pool thread",
		"mark 0x%X, expected 0x%X", found ? (UINT)held[found_index].MarkSeen : 0, (UINT)RT_POOL_MARK);
	RtCheck(&ctx, joined == num_jobs, "every held job ends once its gate opens", "%u of %u ended", joined, num_jobs);

	// Several threads wait on one THREAD at the same time, and every one of them sees it end
	Zero(&target_job, sizeof(target_job));
	Zero(&wd, sizeof(wd));
	go = false;
	target_job.Go = &go;
	wd.Target = NewThread(RtPoolJobThread, &target_job);
	for (i = 0;i < RT_POOL_WAITERS;i++)
	{
		waiters[i] = NewThread(RtPoolWaiterThread, &wd);
	}
	SleepThread(RT_POOL_SETTLE);
	early = (UINT)wd.Returned;
	go = true;
	waited = 0;
	for (i = 0;i < RT_POOL_WAITERS;i++)
	{
		if (WaitThread(waiters[i], RT_POOL_BOUND * 2))
		{
			waited++;
		}
		ReleaseThread(waiters[i]);
	}
	ended = WaitThread(wd.Target, RT_POOL_BOUND);
	ReleaseThread(wd.Target);
	RtCheck(&ctx, early == 0 && waited == RT_POOL_WAITERS && wd.Joined == RT_POOL_WAITERS && ended,
		"several threads wait on one THREAD at the same time, and all of them see it end",
		"%u returned before the end, %u of %u waiters ended, %u saw WaitThread return true",
		early, waited, RT_POOL_WAITERS, (UINT)wd.Joined);

	// Host threads (NewThreadInternal): the procedure runs with COM initialised,
	// WaitThreadInternal returns true once the thread ended, and the end closes the handle
	waited = ran = com_ready = 0;
	counted = (GetProcessHandleCount(GetCurrentProcess(), &handles_before) != FALSE);
	for (i = 0;i < RT_HOST_CYCLES;i++)
	{
		Zero(&host, sizeof(host));
		t = NewThreadInternal(RtPoolJobThread, &host);
		if (WaitThreadInternal(t))
		{
			waited++;
		}
		if (host.Ran)
		{
			ran++;
		}
		if (host.ComReady)
		{
			com_ready++;
		}
		ReleaseThreadInternal(t);
	}
	counted = counted && (GetProcessHandleCount(GetCurrentProcess(), &handles_after) != FALSE);
	RtCheck(&ctx, waited == RT_HOST_CYCLES && ran == RT_HOST_CYCLES,
		"WaitThreadInternal returns true once the procedure of a host thread ran",
		"%u of %u waits returned true, %u procedures ran", waited, RT_HOST_CYCLES, ran);
	RtCheck(&ctx, com_ready == RT_HOST_CYCLES, "COM is initialised on every host thread",
		"%u of %u", com_ready, RT_HOST_CYCLES);
	RtCheck(&ctx, counted && handles_after < handles_before + RT_HOST_CYCLES / 2,
		"releasing an ended host thread closes its handle",
		"%u handles before, %u after %u host threads", (UINT)handles_before, (UINT)handles_after, RT_HOST_CYCLES);

	RtEnd(&ctx);
}

// Constants of the dns test
#define	RT_DNS_IMMEDIATE_TIMEOUT	1				// Timeout that only the immediate answer meets reliably (ms)
#define	RT_DNS_RESOLVER_TIMEOUT		10000			// Timeout of the lookup through the resolver thread (ms)
#define	RT_DNS_IP4_LITERAL			"192.0.2.1"		// IPv4 documentation address (RFC 5737)
#define	RT_DNS_IP6_LITERAL			"2001:db8::1"	// IPv6 documentation address (RFC 3849)

// Check that an address list from DnsResolveEx holds exactly the expected address
static void RtDnsCheckList(RT_CTX *ctx, LIST *o, IP *expect, char *what)
{
	char str[MAX_SIZE];

	StrCpy(str, sizeof(str), "none");
	if (LIST_NUM(o) >= 1)
	{
		IPToStr(str, sizeof(str), LIST_DATA(o, 0));
	}

	RtCheck(ctx, LIST_NUM(o) == 1 && CmpIpAddr((IP *)LIST_DATA(o, 0), expect) == 0, what,
		"%u addresses, first %s", LIST_NUM(o), str);
}

// Check one immediate answer of DnsResolveEx: the call succeeds within the 1 ms timeout and
// fills only the lists it should (expect6 or expect4 NULL: that list stays unset)
static void RtDnsCheckImmediate(RT_CTX *ctx, char *hostname, IP *expect6, IP *expect4, volatile bool *cancel_flag, char *label)
{
	LIST *v6 = NULL;
	LIST *v4 = NULL;
	char what[MAX_SIZE];
	bool ret;

	ret = DnsResolveEx(&v6, &v4, hostname, RT_DNS_IMMEDIATE_TIMEOUT, cancel_flag);

	Format(what, sizeof(what), "DnsResolveEx(%s) succeeds with a timeout of 1 ms", label);
	RtCheck(ctx, ret, what, "returned false");

	if (expect6 != NULL)
	{
		Format(what, sizeof(what), "DnsResolveEx(%s) gives one IPv6 address, the expected one", label);
		RtDnsCheckList(ctx, v6, expect6, what);
	}
	else
	{
		Format(what, sizeof(what), "DnsResolveEx(%s) leaves the IPv6 list unset", label);
		RtCheck(ctx, v6 == NULL, what, "%u addresses", LIST_NUM(v6));
	}

	if (expect4 != NULL)
	{
		Format(what, sizeof(what), "DnsResolveEx(%s) gives one IPv4 address, the expected one", label);
		RtDnsCheckList(ctx, v4, expect4, what);
	}
	else
	{
		Format(what, sizeof(what), "DnsResolveEx(%s) leaves the IPv4 list unset", label);
		RtCheck(ctx, v4 == NULL, what, "%u addresses", LIST_NUM(v4));
	}

	FreeHostIPAddressList(v6);
	FreeHostIPAddressList(v4);
}

// dns: "localhost" and IP literals are answered at once, without a resolver thread, so they
// resolve even with a timeout of 1 ms; the computer name resolves through the resolver thread
void dns_test(UINT num, char **arg)
{
	RT_CTX ctx;
	LIST *v6, *v4;
	IP ip, local6, local4, lit6, lit4;
	char name[MAX_SIZE];
	char str[MAX_SIZE];
	volatile bool cancel = true;
	UINT threads, i;
	bool ret, ok;

	RtBegin(&ctx, "DNS", "DNS test");

	GetLocalHostIP6(&local6);
	GetLocalHostIP4(&local4);
	RtCheck(&ctx, StrToIP(&lit4, RT_DNS_IP4_LITERAL) && IsIP4(&lit4), "StrToIP parses the IPv4 literal", "failed");
	RtCheck(&ctx, StrToIP(&lit6, RT_DNS_IP6_LITERAL) && IsIP6(&lit6), "StrToIP parses the IPv6 literal", "failed");

	// "localhost" in any case gives ::1 and 127.0.0.1; a literal gives itself in its family
	RtDnsCheckImmediate(&ctx, "localhost", &local6, &local4, NULL, "\"localhost\"");
	RtDnsCheckImmediate(&ctx, "LocalHost", &local6, &local4, NULL, "\"LocalHost\"");
	RtDnsCheckImmediate(&ctx, RT_DNS_IP4_LITERAL, NULL, &lit4, NULL, "the IPv4 literal");
	RtDnsCheckImmediate(&ctx, RT_DNS_IP6_LITERAL, &lit6, NULL, NULL, "the IPv6 literal");

	// The immediate answer comes before the cancel flag is read
	RtDnsCheckImmediate(&ctx, "localhost", &local6, &local4, &cancel, "\"localhost\", cancel flag set");
	RtDnsCheckImmediate(&ctx, RT_DNS_IP4_LITERAL, NULL, &lit4, &cancel, "the IPv4 literal, cancel flag set");
	RtDnsCheckImmediate(&ctx, RT_DNS_IP6_LITERAL, &lit6, NULL, &cancel, "the IPv6 literal, cancel flag set");

	// The single-address forms: GetIPEx prefers IPv6, GetIP4Ex and GetIP6Ex pick their family
	ret = GetIPEx(&ip, "localhost", RT_DNS_IMMEDIATE_TIMEOUT, NULL);
	RtCheck(&ctx, ret && CmpIpAddr(&ip, &local6) == 0, "GetIPEx(\"localhost\") gives ::1", "returned %s", ret ? "another address" : "false");
	ret = GetIP4Ex(&ip, "localhost", RT_DNS_IMMEDIATE_TIMEOUT, NULL);
	RtCheck(&ctx, ret && CmpIpAddr(&ip, &local4) == 0, "GetIP4Ex(\"localhost\") gives 127.0.0.1", "returned %s", ret ? "another address" : "false");
	ret = GetIP4Ex(&ip, RT_DNS_IP4_LITERAL, RT_DNS_IMMEDIATE_TIMEOUT, NULL);
	RtCheck(&ctx, ret && CmpIpAddr(&ip, &lit4) == 0, "GetIP4Ex of the IPv4 literal gives it back", "returned %s", ret ? "another address" : "false");
	ret = GetIP6Ex(&ip, RT_DNS_IP6_LITERAL, RT_DNS_IMMEDIATE_TIMEOUT, NULL);
	RtCheck(&ctx, ret && CmpIpAddr(&ip, &lit6) == 0, "GetIP6Ex of the IPv6 literal gives it back", "returned %s", ret ? "another address" : "false");

	// The computer name resolves through the resolver thread to at least one address, each in
	// the list of its family; the thread count is back to its value afterwards
	GetMachineName(name, sizeof(name));
	threads = DnsThreadNum();
	v6 = v4 = NULL;
	ret = DnsResolveEx(&v6, &v4, name, RT_DNS_RESOLVER_TIMEOUT, NULL);
	RtCheck(&ctx, ret && (LIST_NUM(v6) + LIST_NUM(v4)) >= 1, "DnsResolveEx of the computer name gives at least one address",
		"name %s, returned %s, %u IPv6 and %u IPv4 addresses", name, ret ? "true" : "false", LIST_NUM(v6), LIST_NUM(v4));

	ok = true;
	StrCpy(str, sizeof(str), "none");
	for (i = 0;i < LIST_NUM(v6);i++)
	{
		if (IsIP6((IP *)LIST_DATA(v6, i)) == false)
		{
			IPToStr(str, sizeof(str), LIST_DATA(v6, i));
			ok = false;
		}
	}
	for (i = 0;i < LIST_NUM(v4);i++)
	{
		if (IsIP4((IP *)LIST_DATA(v4, i)) == false)
		{
			IPToStr(str, sizeof(str), LIST_DATA(v4, i));
			ok = false;
		}
	}
	RtCheck(&ctx, ok, "Each address of the computer name is in the list of its family", "misplaced %s", str);
	RtCheck(&ctx, DnsThreadNum() == threads, "DnsThreadNum is back to its value from before the lookup",
		"%u before, %u after", threads, DnsThreadNum());

	FreeHostIPAddressList(v6);
	FreeHostIPAddressList(v4);

	RtEnd(&ctx);
}
