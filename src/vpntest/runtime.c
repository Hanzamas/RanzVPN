// runtime.c
// Named runtime tests of vpntest (spec #30, Windows-native runtime)
//
// Each test pins behaviour that the Windows-native runtime (ADR-0016) must keep, and runs
// against the current implementation first. A test prints "<NAME> TEST OK" only when every
// check passes, and frees everything it allocates, so that the run still ends with
// "NO MEMORY LEAKS". The [PASS] lines carry no measured values; the [FAIL] details do.

#include "testlist.h"

#include "Mayaqua/DNS.h"
#include "Mayaqua/Encrypt.h"
#include "Mayaqua/FileIO.h"
#include "Mayaqua/Internat.h"
#include "Mayaqua/Kernel.h"
#include "Mayaqua/Mayaqua.h"
#include "Mayaqua/Memory.h"
#include "Mayaqua/Microsoft.h"
#include "Mayaqua/Network.h"
#include "Mayaqua/Object.h"
#include "Mayaqua/Str.h"
#include "Mayaqua/Tick64.h"
#include "Mayaqua/Trace.h"

#include <locale.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>

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
RANZ_TEST("tickorigin", tickorigin_test, "Tick64 origin: the first value is at least 1 and at most the process age.");
void tickorigin_test(UINT num, char **arg)
{
	RT_CTX ctx;
	FILETIME create_ft, exit_ft, kernel_ft, user_ft, now_ft;
	UINT64 age = 0;
	UINT err = 0;

	// Read the tick before anything else can take time
	UINT64 tick = Tick64();

	RtBegin(&ctx, "TICKORIGIN", "Tick64 origin test");

	bool have_age = (GetProcessTimes(GetCurrentProcess(), &create_ft, &exit_ft, &kernel_ft, &user_ft) != FALSE);
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

	UINT64 tick2 = Tick64();
	RtCheck(&ctx, tick2 >= tick, "Tick64 does not go back", "first %I64u, then %I64u", tick, tick2);

	RtEnd(&ctx);
}

// Constants of the timeenc test
#define	RT_TIME_TOLERANCE		2000					// Slack allowed between a Mayaqua clock and the OS clock (ms)
#define	RT_TIME_OFFSET			32400000ULL				// Offset subtracted by the UINT64 time encoding: 9 hours (ms)
#define	RT_UNIX_EPOCH_FILETIME	116444736000000000ULL	// 1970-01-01 00:00:00 UTC as a FILETIME (100 ns units)
#define	RT_TIME_2024			1709177696789ULL		// 2024-02-29 12:34:56.789 UTC, encoded
#define	RT_TIME_1971			32367600000ULL			// 1971-01-11 00:00:00.000 UTC, encoded: the smallest value above 0
#define	RT_TIME_DAY				86400000ULL				// A day (ms)
#define	RT_TIME_BEYOND_MAX		9000000000000ULL		// Encoded value above the latest time UINT64ToSystem decodes, 2099-12-29 16:02:03.123 UTC
#define	RT_TICK_TIME_WAIT		(TICK64_SPAN_WIN32 + 200)	// Wait that lets the periodic Tick64 clock check run at least once (ms)

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

// An RFC 3339 printing vector: a local time, its offset from UTC and the string printed for it
typedef struct RT_RFC3339_VECTOR
{
	char *What;
	UINT Year, Month, Day, Hour, Minute, Second, Ms;	// Local time
	int OffsetMin;										// Local time minus UTC (minutes)
	char *Str;
} RT_RFC3339_VECTOR;

// Printing vectors (ticket #102). The former printer took the offset as UTC minus local time and
// printed it with "%+02d:%02d": UTC+7 came out as "-7:00", UTC-3:30 as "+3:30", UTC+5:30 as "-5:-30"
static RT_RFC3339_VECTOR rt_rfc3339_vectors[] =
{
	{"RFC 3339: UTC prints Z", 2024, 2, 29, 12, 34, 56, 789, 0, "2024-02-29T12:34:56.789Z"},
	{"RFC 3339: UTC+7 prints +07:00", 2024, 2, 29, 12, 34, 56, 789, 420, "2024-02-29T12:34:56.789+07:00"},
	{"RFC 3339: UTC-3:30 prints -03:30", 2024, 2, 29, 12, 34, 56, 789, -210, "2024-02-29T12:34:56.789-03:30"},
	{"RFC 3339: UTC+5:30 prints +05:30", 2024, 2, 29, 12, 34, 56, 789, 330, "2024-02-29T12:34:56.789+05:30"},
	{"RFC 3339: UTC+5:45 prints +05:45", 2024, 2, 29, 12, 34, 56, 789, 345, "2024-02-29T12:34:56.789+05:45"},
	{"RFC 3339: UTC-10 prints -10:00", 2024, 2, 29, 12, 34, 56, 789, -600, "2024-02-29T12:34:56.789-10:00"},
	{"RFC 3339: UTC+14 prints +14:00", 2024, 2, 29, 12, 34, 56, 789, 840, "2024-02-29T12:34:56.789+14:00"},
	{"RFC 3339: UTC-0:30 prints -00:30, the sign of the whole offset", 2024, 2, 29, 12, 34, 56, 789, -30, "2024-02-29T12:34:56.789-00:30"},
	{"RFC 3339: single-digit fields print with leading zeros", 2025, 1, 5, 3, 4, 5, 6, 60, "2025-01-05T03:04:05.006+01:00"},
	{"RFC 3339: a local time just after midnight of New Year", 2024, 1, 1, 0, 30, 0, 0, 120, "2024-01-01T00:30:00.000+02:00"},
	{"RFC 3339: a local time just before midnight of New Year's Eve", 2023, 12, 31, 22, 0, 0, 0, -210, "2023-12-31T22:00:00.000-03:30"},
};

// GetDateTimeStrRFC3339 against the printing vectors
static void RtCheckRfc3339Print(RT_CTX *ctx)
{
	SYSTEMTIME st;
	char str[MAX_SIZE];

	for (UINT i = 0; i < _countof(rt_rfc3339_vectors); i++)
	{
		RT_RFC3339_VECTOR *v = &rt_rfc3339_vectors[i];

		RtSetSystem(&st, v->Year, v->Month, v->Day, v->Hour, v->Minute, v->Second, v->Ms);
		GetDateTimeStrRFC3339(str, sizeof(str), &st, v->OffsetMin);
		RtCheck(ctx, StrCmp(str, v->Str) == 0, v->What, "got \"%s\", expected \"%s\"", str, v->Str);
	}
}

// An RFC 3339 parsing vector: the string, whether DateTimeStrRFC3339ToSystemTime takes it, and
// the UTC time it names (day of the week: 0 = Sunday)
typedef struct RT_RFC3339_PARSE_VECTOR
{
	char *Str;
	bool Ok;
	UINT Year, Month, Day, DayOfWeek, Hour, Minute, Second, Ms;
} RT_RFC3339_PARSE_VECTOR;

// Parsing vectors (ticket #102): the offset is applied, so every time comes back as UTC
static RT_RFC3339_PARSE_VECTOR rt_rfc3339_parse_vectors[] =
{
	{"2024-02-29T12:34:56Z", true, 2024, 2, 29, 4, 12, 34, 56, 0},
	{"2024-02-29T19:34:56.789+07:00", true, 2024, 2, 29, 4, 12, 34, 56, 789},
	{"2024-02-29T09:04:56.789-03:30", true, 2024, 2, 29, 4, 12, 34, 56, 789},
	{"2024-02-29T12:34:56.789+00:00", true, 2024, 2, 29, 4, 12, 34, 56, 789},
	{"2024-02-29T12:34:56.789-00:00", true, 2024, 2, 29, 4, 12, 34, 56, 789},
	{"2024-02-29T13:34:56.7+01:00", true, 2024, 2, 29, 4, 12, 34, 56, 700},
	{"2024-02-29t12:34:56.123456z", true, 2024, 2, 29, 4, 12, 34, 56, 123},
	{"2024-03-01T03:00:00.000+07:00", true, 2024, 2, 29, 4, 20, 0, 0, 0},
	{"2023-12-31T22:00:00.000-03:30", true, 2024, 1, 1, 1, 1, 30, 0, 0},
	{"2024-02-29T12:34:56.789", false},
	{"2024-02-29T12:34:56.789+7:00", false},
	{"2024-02-29T12:34:56.789-5:-30", false},
	{"2024-02-29T12:34:56.789+0700", false},
	{"2024-02-29T12:34:56.+07:00", false},
	{"2024-02-29 12:34:56Z", false},
	{"2024-02-30T00:00:00Z", false},
	{"2023-02-29T00:00:00Z", false},
	{"2024-13-01T00:00:00Z", false},
	{"2024-02-29T24:00:00Z", false},
	{"2016-12-31T23:59:60Z", false},
	{"2024-02-29T12:34:56+24:00", false},
	{"2024-02-29T12:34:56+07:60", false},
	{"2024-02-29T12:34:56Z ", false},
	{"2024-02-29", false},
	{"", false},
};

// DateTimeStrRFC3339ToSystemTime against the parsing vectors, and every printing vector through
// the printer, the parser and the printer again
static void RtCheckRfc3339Parse(RT_CTX *ctx)
{
	SYSTEMTIME st, utc, back;
	char str[MAX_SIZE];
	char what[MAX_SIZE];
	UINT64 local64, utc64, expect64;
	bool ok;

	for (UINT i = 0; i < _countof(rt_rfc3339_parse_vectors); i++)
	{
		RT_RFC3339_PARSE_VECTOR *v = &rt_rfc3339_parse_vectors[i];

		RtSetSystem(&st, 2000, 1, 1, 1, 1, 1, 1);
		ok = DateTimeStrRFC3339ToSystemTime(&st, v->Str);

		if (v->Ok == false)
		{
			Format(what, sizeof(what), "RFC 3339 parse refuses \"%s\" and zeroes the result", v->Str);
			RtCheck(ctx, ok == false && IsZero(&st, sizeof(st)), what, "returned %s, result %s",
				ok ? "true" : "false", IsZero(&st, sizeof(st)) ? "zero" : "not zero");
			continue;
		}

		Format(what, sizeof(what), "RFC 3339 parse: \"%s\" is UTC %04u-%02u-%02u %02u:%02u:%02u.%03u",
			v->Str, v->Year, v->Month, v->Day, v->Hour, v->Minute, v->Second, v->Ms);
		if (ok)
		{
			RtCheckSystem(ctx, &st, what, v->Year, v->Month, v->Day, v->DayOfWeek, v->Hour, v->Minute, v->Second, v->Ms);
		}
		else
		{
			RtCheck(ctx, false, what, "refused");
		}
	}

	ok = DateTimeStrRFC3339ToSystemTime(&st, NULL);
	RtCheck(ctx, ok == false, "RFC 3339 parse refuses a NULL string", "returned true");
	ok = DateTimeStrRFC3339ToSystemTime(NULL, "2024-02-29T12:34:56Z");
	RtCheck(ctx, ok == false, "RFC 3339 parse refuses a NULL result", "returned true");

	// Round trip: printer, parser (UTC: the local time minus the offset), printer again
	for (UINT i = 0; i < _countof(rt_rfc3339_vectors); i++)
	{
		RT_RFC3339_VECTOR *v = &rt_rfc3339_vectors[i];

		RtSetSystem(&st, v->Year, v->Month, v->Day, v->Hour, v->Minute, v->Second, v->Ms);
		local64 = SystemToUINT64(&st);
		expect64 = (UINT64)((INT64)local64 - (INT64)v->OffsetMin * 60000);

		GetDateTimeStrRFC3339(str, sizeof(str), &st, v->OffsetMin);
		ok = DateTimeStrRFC3339ToSystemTime(&utc, str);
		utc64 = SystemToUINT64(&utc);

		UINT64ToSystem(&back, (UINT64)((INT64)utc64 + (INT64)v->OffsetMin * 60000));
		GetDateTimeStrRFC3339(str, sizeof(str), &back, v->OffsetMin);

		UINT64ToSystem(&st, expect64);

		Format(what, sizeof(what), "RFC 3339 round trip: \"%s\"", v->Str);
		RtCheck(ctx, ok && utc64 == expect64 && utc.wDayOfWeek == st.wDayOfWeek && StrCmp(str, v->Str) == 0, what,
			"parsed %s, UTC %I64u (expected %I64u), day of the week %u (expected %u), printed again \"%s\"",
			ok ? "ok" : "refused", utc64, expect64, utc.wDayOfWeek, st.wDayOfWeek, str);
	}
}

// A time zone vector: the biases of a TIME_ZONE_INFORMATION (UTC minus local time, minutes), the
// zone ID GetTimeZoneInformation returns with them, the offset from UTC and its printed form
typedef struct RT_ZONE_VECTOR
{
	char *What;
	LONG Bias, StandardBias, DaylightBias;
	UINT ZoneId;
	int OffsetMin;										// Local time minus UTC (minutes)
	char *Suffix;										// End of the RFC 3339 string with that offset
} RT_ZONE_VECTOR;

// Time zone vectors (ticket #102). The former GetCurrentTimezoneWin32 returned Bias alone: the
// sign was turned around and the daylight bias was never added
static RT_ZONE_VECTOR rt_zone_vectors[] =
{
	{"Zone offset: UTC+7 (Bias -420) is +420", -420, 0, 0, TIME_ZONE_ID_UNKNOWN, 420, "+07:00"},
	{"Zone offset: UTC (Bias 0) is 0", 0, 0, 0, TIME_ZONE_ID_UNKNOWN, 0, "Z"},
	{"Zone offset: UTC-3:30 in standard time (Bias 210) is -210", 210, 0, -60, TIME_ZONE_ID_STANDARD, -210, "-03:30"},
	{"Zone offset: UTC-3:30 in daylight time adds the daylight bias", 210, 0, -60, TIME_ZONE_ID_DAYLIGHT, -150, "-02:30"},
	{"Zone offset: UTC+1 in standard time (Bias -60) is +60", -60, 0, -60, TIME_ZONE_ID_STANDARD, 60, "+01:00"},
	{"Zone offset: UTC+1 in daylight time is +120", -60, 0, -60, TIME_ZONE_ID_DAYLIGHT, 120, "+02:00"},
	{"Zone offset: UTC+0 in daylight time is +60", 0, 0, -60, TIME_ZONE_ID_DAYLIGHT, 60, "+01:00"},
	{"Zone offset: UTC+10:30 in half-hour daylight time is +660", -630, 0, -30, TIME_ZONE_ID_DAYLIGHT, 660, "+11:00"},
	{"Zone offset: a standard bias is added in standard time", 300, 60, -60, TIME_ZONE_ID_STANDARD, -360, "-06:00"},
	{"Zone offset: no daylight bias in a zone without daylight saving time", -60, 0, -60, TIME_ZONE_ID_UNKNOWN, 60, "+01:00"},
};

// GetTimezoneInfoOffsetWin32 against the time zone vectors, and GetCurrentTimezone against the
// offset of the OS time zone now, daylight saving time included
static void RtCheckZoneOffset(RT_CTX *ctx)
{
	TIME_ZONE_INFORMATION info;
	SYSTEMTIME st;
	char str[MAX_SIZE];
	int offset;
	INT64 os_offset = 0;

	for (UINT i = 0; i < _countof(rt_zone_vectors); i++)
	{
		RT_ZONE_VECTOR *v = &rt_zone_vectors[i];

		Zero(&info, sizeof(info));
		info.Bias = v->Bias;
		info.StandardBias = v->StandardBias;
		info.DaylightBias = v->DaylightBias;

		offset = GetTimezoneInfoOffsetWin32(&info, v->ZoneId);
		RtSetSystem(&st, 2024, 2, 29, 12, 34, 56, 789);
		GetDateTimeStrRFC3339(str, sizeof(str), &st, offset);
		RtCheck(ctx, offset == v->OffsetMin && EndWith(str, v->Suffix), v->What,
			"offset %d, \"%s\"; expected %d, \"...%s\"", offset, str, v->OffsetMin, v->Suffix);
	}

	GetSystemTime(&st);
	bool have_offset = RtOsZoneOffset(&st, &os_offset);
	offset = GetCurrentTimezone();
	RtCheck(ctx, have_offset && (INT64)offset * 60000 == os_offset,
		"GetCurrentTimezone is the OS time zone offset now, daylight saving time included",
		"GetCurrentTimezone = %d min, OS offset = %I64d ms", offset, os_offset);
}

// timeenc: the UINT64 time encoding is Unix-epoch milliseconds minus 9 hours, times before
// 1971-01-11 encode as 0, local time is UTC plus the OS time zone offset, Tick64ToTime64
// maps a tick to that encoding, and RFC 3339 strings carry the offset from UTC as +HH:MM,
// -HH:MM or Z
RANZ_TEST("timeenc", timeenc_test, "Time encoding: SystemTime64/LocalTime64 against the OS clock, fixed-input conversions, RFC 3339 strings.");
void timeenc_test(UINT num, char **arg)
{
	RT_CTX ctx;
	FILETIME now_ft;
	SYSTEMTIME st;
	INT64 os_offset = 0;

	RtBegin(&ctx, "TIMEENC", "Time encoding test");

	// SystemTime64 against the OS clock
	GetSystemTimeAsFileTime(&now_ft);
	UINT64 value = SystemTime64();
	UINT64 expect = (RtFileTime64(&now_ft) - RT_UNIX_EPOCH_FILETIME) / 10000ULL - RT_TIME_OFFSET;
	RtCheck(&ctx, RtDiff64(value, expect) <= RT_TIME_TOLERANCE, "SystemTime64 is the OS UTC time in Unix-epoch ms minus 9 hours",
		"SystemTime64 = %I64u, expected %I64u", value, expect);

	// LocalTime64 - SystemTime64 against the OS time zone offset
	GetSystemTime(&st);
	bool have_offset = RtOsZoneOffset(&st, &os_offset);
	UINT64 local64 = LocalTime64();
	UINT64 system64 = SystemTime64();
	INT64 offset = (INT64)local64 - (INT64)system64;
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

	// A day past the end of the month rolls into the next month: February 30, 2024 is March 1
	RtSetSystem(&st, 2024, 2, 30, 12, 34, 56, 789);
	value = SystemToUINT64(&st);
	expect = RT_TIME_2024 + RT_TIME_DAY;
	RtCheck(&ctx, value == expect, "SystemToUINT64(2024-02-30 12:34:56.789) is 2024-03-01 12:34:56.789",
		"got %I64u, expected %I64u", value, expect);

	// The year is clamped to 1970..2099: 2150 reads as 2099
	RtSetSystem(&st, 2150, 1, 1, 0, 0, 0, 0);
	value = SystemToUINT64(&st);
	RtSetSystem(&st, 2099, 1, 1, 0, 0, 0, 0);
	expect = SystemToUINT64(&st);
	RtCheck(&ctx, value != 0 && value == expect, "SystemToUINT64 clamps the year 2150 to 2099",
		"got %I64u, 2099 is %I64u", value, expect);

	// Values above the latest decoded time stop at 2099-12-29 16:02:03.123, a Tuesday
	UINT64ToSystem(&st, RT_TIME_BEYOND_MAX);
	RtCheckSystem(&ctx, &st, "UINT64ToSystem stops at 2099-12-29 16:02:03.123", 2099, 12, 29, 2, 16, 2, 3, 123);

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

	// Tick64ToTime64 maps the current tick to the current time, before and after the
	// periodic clock check of Tick64 ran, and keeps 0 as "unset"
	value = Tick64ToTime64(Tick64());
	system64 = SystemTime64();
	RtCheck(&ctx, RtDiff64(value, system64) <= RT_TIME_TOLERANCE, "Tick64ToTime64 of the current tick is SystemTime64",
		"Tick64ToTime64 = %I64u, SystemTime64 = %I64u", value, system64);
	SleepThread(RT_TICK_TIME_WAIT);
	value = Tick64ToTime64(Tick64());
	system64 = SystemTime64();
	RtCheck(&ctx, RtDiff64(value, system64) <= RT_TIME_TOLERANCE,
		"Tick64ToTime64 of the current tick is still SystemTime64 after the periodic clock check",
		"Tick64ToTime64 = %I64u, SystemTime64 = %I64u", value, system64);
	value = Tick64ToTime64(0);
	RtCheck(&ctx, value == 0, "Tick64ToTime64(0) is 0", "got %I64u", value);

	// RFC 3339 strings of the strict syslog format
	RtCheckRfc3339Print(&ctx);
	RtCheckRfc3339Parse(&ctx);
	RtCheckZoneOffset(&ctx);

	RtEnd(&ctx);
}

// Constants of the nullsafe test
#define	RT_EVENT_NO_HANDLE_WAIT	1000		// Timeout given to Wait on an EVENT without a handle (ms)

// nullsafe: the LOCK, LIST, COUNTER, REF and EVENT functions accept NULL and do nothing
RANZ_TEST("nullsafe", nullsafe_test, "NULL safety of the LOCK, LIST, COUNTER, REF and EVENT functions.");
void nullsafe_test(UINT num, char **arg)
{
	RT_CTX ctx;
	LOCK *lock = NULL;				// A variable, not the NULL literal: the old _DEBUG macro form of Lock() dereferenced it
	COUNTER *counter = NULL;
	REF *ref = NULL;
	EVENT *e = NULL;
	UINT item = 1;
	UCHAR be[8];

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

	// Macro hygiene: Lock/Unlock, WRITE_* and KS_* are each one statement, so each stands in
	// an unbraced if/else (the KS_INC/KS_DEC branches compile but never run)
	Zero(be, sizeof(be));
	if (item == 1)
		Lock(lock);
	else
		Unlock(lock);
	if (item == 1)
		WRITE_UINT64(be, 0x0102030405060708ULL);
	else
		WRITE_USHORT(be, 0);
	if (item == 1)
		WRITE_USHORT(be + 6, 0x0A0B);
	else
		WRITE_UINT(be, 0);
	if (item == 1)
		WRITE_UINT(be, 0x11223344);
	else
		WRITE_UINT64(be, 0);
	if (item == 1)
		KS_ADD(KS_STRLEN_COUNT, 0);
	else
		KS_INC(KS_STRLEN_COUNT);
	if (item == 1)
		KS_SUB(KS_STRLEN_COUNT, 0);
	else
		KS_DEC(KS_STRLEN_COUNT);
	RtCheck(&ctx, READ_UINT64(be) == 0x1122334405060A0BULL, "WRITE_* in unbraced if/else write big-endian",
		"got %08x%08x", READ_UINT(be), READ_UINT(be + 4));

	// LockList/UnlockList on a list from NewListFast, which has no lock
	LIST *o = NewListFast(NULL);
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
	UINT ret = Count(counter);
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
	UINT64 start = Tick64();
	bool waited = Wait(e, RT_EVENT_NO_HANDLE_WAIT);
	UINT64 elapsed = Tick64() - start;
	RtCheck(&ctx, waited == false && elapsed < RT_EVENT_NO_HANDLE_WAIT, "Wait on an EVENT without a handle returns false at once",
		"returned %s after %I64u ms", waited ? "true" : "false", elapsed);
	ReleaseEvent(e);
	RtCheck(&ctx, true, "Set and ReleaseEvent on an EVENT without a handle return", "");

	RtEnd(&ctx);
}

// Constants of the charset test
#define	RT_CHARSET_BUF			128			// Code units, or bytes, of one conversion buffer
#define	RT_CHARSET_FILL			0xA5A5		// Fill of a wchar_t buffer: a conversion must leave it where it writes nothing
#define	RT_CHARSET_FILL_BYTE	0xA5		// Fill of a byte buffer
#define	RT_CHARSET_ROUNDS		20000		// Random strings checked in each direction
#define	RT_CHARSET_MAX_LEN		24			// Pieces (decoding) or code units (encoding) of the longest random string
#define	RT_CHARSET_SEED			0x2545F491	// Seed of the random strings: every run checks the same ones

// A fixed UTF-8 decoding vector: input bytes and the code units Mayaqua decodes them to
typedef struct RT_UTF8_DECODE_VECTOR
{
	char *What;
	char *Bytes;					// Input, Size bytes (may hold NUL bytes); Size 0: up to the first NUL
	UINT Size;
	UINT NumUnits;
	wchar_t Units[4];
} RT_UTF8_DECODE_VECTOR;

// A fixed UTF-8 encoding vector: a NUL-terminated string and the bytes Mayaqua encodes it to
typedef struct RT_UTF8_ENCODE_VECTOR
{
	char *What;
	wchar_t Units[6];
	UINT Size;
	char *Bytes;
} RT_UTF8_ENCODE_VECTOR;

// Decoding vectors. Mayaqua's decoder takes the length of a sequence from the lead byte alone
// (below 0x80: 1, bit 0x20 clear: 2, otherwise 3), ends at a sequence cut off by the end of the
// input, and uses the payload bits without validation
static RT_UTF8_DECODE_VECTOR rt_utf8_decode_vectors[] =
{
	{"UTF-8 decode: ASCII", "Az", 2, 2, {L'A', L'z'}},
	{"UTF-8 decode: C3 A9 gives U+00E9", "\xC3\xA9", 2, 1, {0x00E9}},
	{"UTF-8 decode: DF BF gives U+07FF", "\xDF\xBF", 2, 1, {0x07FF}},
	{"UTF-8 decode: E0 A0 80 gives U+0800", "\xE0\xA0\x80", 3, 1, {0x0800}},
	{"UTF-8 decode: E3 81 82 gives U+3042", "\xE3\x81\x82", 3, 1, {0x3042}},
	{"UTF-8 decode: a BOM is kept as U+FEFF", "\xEF\xBB\xBF" "A", 4, 2, {0xFEFF, L'A'}},
	{"UTF-8 decode: EF BF BF gives U+FFFF", "\xEF\xBF\xBF", 3, 1, {0xFFFF}},
	{"UTF-8 decode: a NUL byte inside the size gives U+0000", "A\0B", 3, 3, {L'A', 0x0000, L'B'}},
	{"UTF-8 decode: size 0 decodes up to the first NUL", "AB\0C", 0, 2, {L'A', L'B'}},
	{"UTF-8 decode: the empty string", "", 0, 0, {0}},
	{"UTF-8 decode: continuation byte 80 is a 2-byte lead (80 41 gives U+0001)", "\x80\x41", 2, 1, {0x0001}},
	{"UTF-8 decode: continuation byte A0 is a 3-byte lead (A0 41 42 gives U+0042)", "\xA0\x41\x42", 3, 1, {0x0042}},
	{"UTF-8 decode: a bad continuation byte is taken as is (C3 41 gives U+00C1)", "\xC3\x41", 2, 1, {0x00C1}},
	{"UTF-8 decode: overlong C0 80 gives U+0000", "\xC0\x80" "A", 3, 2, {0x0000, L'A'}},
	{"UTF-8 decode: overlong C1 BF gives U+007F", "\xC1\xBF", 2, 1, {0x007F}},
	{"UTF-8 decode: overlong E0 80 AF gives U+002F", "\xE0\x80\xAF", 3, 1, {0x002F}},
	{"UTF-8 decode: CESU-8 ED A0 80 gives the lone surrogate U+D800", "\xED\xA0\x80", 3, 1, {0xD800}},
	{"UTF-8 decode: CESU-8 surrogate pair gives U+D83D U+DE00", "\xED\xA0\xBD\xED\xB8\x80", 6, 2, {0xD83D, 0xDE00}},
	{"UTF-8 decode: 4-byte F0 9F 98 80 gives U+07D8, then the cut-off 2-byte lead 80 ends it", "\xF0\x9F\x98\x80", 4, 1, {0x07D8}},
	{"UTF-8 decode: 4-byte F0 9F 98 80 then A gives U+07D8 U+0001", "\xF0\x9F\x98\x80" "A", 5, 2, {0x07D8, 0x0001}},
	{"UTF-8 decode: a 2-byte sequence cut off at the end ends the input", "A\xC3", 2, 1, {L'A'}},
	{"UTF-8 decode: a 3-byte sequence cut off at the end ends the input", "A\xE3\x81", 3, 1, {L'A'}},
	{"UTF-8 decode: a lone continuation byte at the end ends the input", "A\x80", 2, 1, {L'A'}},
	{"UTF-8 decode: FF FF FF gives U+FFFF", "\xFF\xFF\xFF", 3, 1, {0xFFFF}},
	{"UTF-8 decode: FE alone gives nothing", "\xFE", 1, 0, {0}},
};

// Encoding vectors. Mayaqua's encoder writes every UTF-16 code unit on its own, so a surrogate
// is a 3-byte sequence (CESU-8) and a surrogate pair is two of them
static RT_UTF8_ENCODE_VECTOR rt_utf8_encode_vectors[] =
{
	{"UTF-8 encode: ASCII", {L'A', L'z', 0}, 2, "Az"},
	{"UTF-8 encode: U+0080 gives C2 80", {0x0080, 0}, 2, "\xC2\x80"},
	{"UTF-8 encode: U+07FF gives DF BF", {0x07FF, 0}, 2, "\xDF\xBF"},
	{"UTF-8 encode: U+0800 gives E0 A0 80", {0x0800, 0}, 3, "\xE0\xA0\x80"},
	{"UTF-8 encode: U+FEFF gives EF BB BF", {0xFEFF, 0}, 3, "\xEF\xBB\xBF"},
	{"UTF-8 encode: U+FFFF gives EF BF BF", {0xFFFF, 0}, 3, "\xEF\xBF\xBF"},
	{"UTF-8 encode: a surrogate pair gives two 3-byte sequences (CESU-8)", {0xD83D, 0xDE00, 0}, 6, "\xED\xA0\xBD\xED\xB8\x80"},
	{"UTF-8 encode: the lone high surrogate U+D800 gives ED A0 80", {0xD800, 0}, 3, "\xED\xA0\x80"},
	{"UTF-8 encode: the lone low surrogate U+DFFF gives ED BF BF", {0xDFFF, 0}, 3, "\xED\xBF\xBF"},
	{"UTF-8 encode: surrogates between text", {L'a', 0xDBFF, L'b', 0xDC00, 0}, 8, "a\xED\xAF\xBF" "b\xED\xB0\x80"},
	{"UTF-8 encode: the empty string", {0}, 0, ""},
};

// Bytes around the boundaries of the lead byte classes and of well-formed UTF-8
static BYTE rt_charset_bytes[] =
{
	0x00, 0x41, 0x7F, 0x80, 0x9F, 0xA0, 0xBF, 0xC0, 0xC2, 0xDF, 0xE0, 0xED, 0xEF, 0xF0, 0xF5, 0xFF,
};

// Pseudo-random numbers of the charset test (xorshift32)
static UINT RtCharsetRandom(UINT *state)
{
	UINT x = *state;

	x ^= x << 13;
	x ^= x >> 17;
	x ^= x << 5;
	*state = x;

	return x;
}

// Reference of the UTF-8 decoding Mayaqua has always done, independent of Internat.c (see the
// decoding vectors). Writes the code units to s when s is not NULL and returns their number
static UINT RtUtf8DecodeRef(wchar_t *s, const BYTE *u, UINT size)
{
	UINT i = 0, num = 0;

	while (i < size)
	{
		BYTE b = u[i];
		UINT type = (b < 0x80) ? 1 : (((b & 0x20) == 0) ? 2 : 3);
		wchar_t c;

		if (i + type > size)
		{
			break;
		}

		if (type == 1)
		{
			c = b;
		}
		else if (type == 2)
		{
			c = (wchar_t)(((b & 0x1f) << 6) | (u[i + 1] & 0x3f));
		}
		else
		{
			c = (wchar_t)(((b & 0x0f) << 12) | ((u[i + 1] & 0x3f) << 6) | (u[i + 2] & 0x3f));
		}

		if (s != NULL)
		{
			s[num] = c;
		}
		num++;
		i += type;
	}

	return num;
}

// Reference of the UTF-8 encoding Mayaqua has always done (see the encoding vectors): 1 byte
// below U+0080, 2 below U+0800, 3 otherwise. Writes the bytes to u and returns their number
static UINT RtUtf8EncodeRef(BYTE *u, const wchar_t *s, UINT len)
{
	UINT wp = 0;

	for (UINT i = 0;i < len;i++)
	{
		UINT c = s[i];

		if (c < 0x80)
		{
			u[wp++] = (BYTE)c;
		}
		else if (c < 0x800)
		{
			u[wp++] = (BYTE)(0xc0 | (c >> 6));
			u[wp++] = (BYTE)(0x80 | (c & 0x3f));
		}
		else
		{
			u[wp++] = (BYTE)(0xe0 | (c >> 12));
			u[wp++] = (BYTE)(0x80 | ((c >> 6) & 0x3f));
			u[wp++] = (BYTE)(0x80 | (c & 0x3f));
		}
	}

	return wp;
}

// Compare Utf8Len, CalcUtf8ToUni and Utf8ToUni on the size bytes of u (at least 1) with the
// reference. out_units is the size given to Utf8ToUni in wchar_t (0: no limit). On a difference,
// describe it in err and return false
static bool RtUtf8DecodeMatches(const BYTE *u, UINT size, UINT out_units, char *err, UINT err_size)
{
	wchar_t expect[RT_CHARSET_BUF];
	wchar_t got[RT_CHARSET_BUF];
	char hex[RT_CHARSET_BUF * 2 + 1];

	UINT n = RtUtf8DecodeRef(expect, u, size);
	UINT len = Utf8Len(u, size);
	UINT calc = CalcUtf8ToUni(u, size);

	memset(got, RT_CHARSET_FILL_BYTE, sizeof(got));
	UINT num = Utf8ToUni(got, (UINT)(out_units * sizeof(wchar_t)), u, size);
	UINT expect_num = (out_units == 0) ? n : MIN(n, out_units - 1);

	// The code units, the terminating NUL, and nothing written after it
	bool ok = (len == n && calc == (n + 1) * sizeof(wchar_t) && num == expect_num &&
		Cmp(got, expect, num * sizeof(wchar_t)) == 0 && got[num] == 0);
	for (UINT i = num + 1;ok && i < RT_CHARSET_BUF;i++)
	{
		ok = (got[i] == RT_CHARSET_FILL);
	}

	if (ok == false)
	{
		BinToStr(hex, sizeof(hex), u, size);
		Format(err, err_size, "input %s, room %u: Utf8Len %u, CalcUtf8ToUni %u, Utf8ToUni %u (first 0x%04X); expected %u units, %u written (first 0x%04X)",
			hex, out_units, len, calc, num, (UINT)got[0], n, expect_num, (UINT)expect[0]);
	}

	return ok;
}

// Compare CalcUniToUtf8 and UniToUtf8 on s (at most RT_CHARSET_BUF code units) with the
// reference. out_size is the size given to UniToUtf8 in bytes (0: no limit). On a difference,
// describe it in err and return false
static bool RtUtf8EncodeMatches(const wchar_t *s, UINT out_size, char *err, UINT err_size)
{
	BYTE expect[RT_CHARSET_BUF * 3];
	BYTE got[RT_CHARSET_BUF * 3 + 1];
	char hex[RT_CHARSET_BUF * 4 + 1];

	UINT len = UniStrLen(s);
	UINT n = RtUtf8EncodeRef(expect, s, len);
	UINT calc = CalcUniToUtf8(s);

	memset(got, RT_CHARSET_FILL_BYTE, sizeof(got));
	UINT wp = UniToUtf8(got, out_size, s);
	UINT expect_wp = (out_size == 0) ? n : MIN(n, out_size);

	// The bytes, then the terminating NUL only when there is room for it, and nothing else
	bool ok = (calc == n && wp == expect_wp && Cmp(got, expect, wp) == 0);
	UINT i = wp;
	if (ok && (out_size == 0 || wp < out_size))
	{
		ok = (got[wp] == 0);
		i++;
	}
	for (;ok && i < sizeof(got);i++)
	{
		ok = (got[i] == RT_CHARSET_FILL_BYTE);
	}

	if (ok == false)
	{
		BinToStr(hex, sizeof(hex), s, len * sizeof(wchar_t));
		Format(err, err_size, "input (UTF-16LE) %s, room %u: CalcUniToUtf8 %u, UniToUtf8 %u; expected %u bytes, %u written",
			hex, out_size, calc, wp, n, expect_wp);
	}

	return ok;
}

// Decode one fixed vector without a limit
static void RtCharsetDecodeVector(RT_CTX *ctx, RT_UTF8_DECODE_VECTOR *v)
{
	wchar_t got[RT_CHARSET_BUF];

	memset(got, RT_CHARSET_FILL_BYTE, sizeof(got));

	UINT len = Utf8Len((BYTE *)v->Bytes, v->Size);
	UINT calc = CalcUtf8ToUni((BYTE *)v->Bytes, v->Size);
	UINT num = Utf8ToUni(got, sizeof(got), (BYTE *)v->Bytes, v->Size);

	bool ok = (len == v->NumUnits && calc == (v->NumUnits + 1) * sizeof(wchar_t) && num == v->NumUnits &&
		Cmp(got, v->Units, num * sizeof(wchar_t)) == 0 && got[num] == 0 && got[num + 1] == RT_CHARSET_FILL);

	RtCheck(ctx, ok, v->What, "Utf8Len %u, CalcUtf8ToUni %u, Utf8ToUni %u, first unit 0x%04X; expected %u units, first 0x%04X",
		len, calc, num, (UINT)got[0], v->NumUnits, (UINT)v->Units[0]);
}

// Encode one fixed vector without a limit
static void RtCharsetEncodeVector(RT_CTX *ctx, RT_UTF8_ENCODE_VECTOR *v)
{
	BYTE got[RT_CHARSET_BUF];
	char hex[RT_CHARSET_BUF * 2 + 1];

	memset(got, RT_CHARSET_FILL_BYTE, sizeof(got));

	UINT calc = CalcUniToUtf8(v->Units);
	UINT wp = UniToUtf8(got, sizeof(got), v->Units);

	bool ok = (calc == v->Size && wp == v->Size && Cmp(got, v->Bytes, wp) == 0 && got[wp] == 0 &&
		got[wp + 1] == RT_CHARSET_FILL_BYTE);

	BinToStr(hex, sizeof(hex), got, MIN(wp, 32));
	RtCheck(ctx, ok, v->What, "CalcUniToUtf8 %u, UniToUtf8 %u bytes %s; expected %u bytes", calc, wp, hex, v->Size);
}

// UTF-8: the fixed vectors, the size limits, NULL arguments and the copy functions
static void RtCharsetUtf8Fixed(RT_CTX *ctx)
{
	wchar_t w[RT_CHARSET_BUF];
	BYTE b[RT_CHARSET_BUF];
	wchar_t mixed[] = {L'a', 0x00E9, 0xD83D, 0xDE00, 0};
	wchar_t two[] = {L'a', 0x00E9, 0};
	wchar_t high[] = {0xD800, 0};
	char *mixed_utf8 = "a\xC3\xA9\xED\xA0\xBD\xED\xB8\x80";

	for (UINT i = 0;i < _countof(rt_utf8_decode_vectors);i++)
	{
		RtCharsetDecodeVector(ctx, &rt_utf8_decode_vectors[i]);
	}
	for (UINT i = 0;i < _countof(rt_utf8_encode_vectors);i++)
	{
		RtCharsetEncodeVector(ctx, &rt_utf8_encode_vectors[i]);
	}

	// GetUtf8Type and GetUniType: the length classes
	bool ok = (GetUtf8Type((BYTE *)"A", 1, 0) == 1 && GetUtf8Type((BYTE *)"\xC3\xA9", 2, 0) == 2 &&
		GetUtf8Type((BYTE *)"\x80\x41", 2, 0) == 2 && GetUtf8Type((BYTE *)"\xA0\x41\x42", 3, 0) == 3 &&
		GetUtf8Type((BYTE *)"\xF0\x9F\x98\x80", 4, 0) == 3 && GetUtf8Type((BYTE *)"\xC3", 1, 0) == 0 &&
		GetUtf8Type((BYTE *)"\xE3\x81", 2, 0) == 0 && GetUtf8Type((BYTE *)"A", 1, 1) == 0 &&
		GetUtf8Type(NULL, 1, 0) == 0);
	RtCheck(ctx, ok, "GetUtf8Type: the length from the lead byte, 0 when cut off or past the end", "a value differs");
	ok = (GetUniType(0x0000) == 1 && GetUniType(0x007F) == 1 && GetUniType(0x0080) == 2 && GetUniType(0x07FF) == 2 &&
		GetUniType(0x0800) == 3 && GetUniType(0xD800) == 3 && GetUniType(0xFFFF) == 3);
	RtCheck(ctx, ok, "GetUniType: 1 below U+0080, 2 below U+0800, 3 otherwise", "a value differs");

	// Utf8ToUni size limits: size counts bytes, room for the NUL is kept, 0 means no limit
	memset(w, RT_CHARSET_FILL_BYTE, sizeof(w));
	UINT ret = Utf8ToUni(w, 3 * sizeof(wchar_t), (BYTE *)"ABCDE", 5);
	RtCheck(ctx, ret == 2 && w[0] == L'A' && w[1] == L'B' && w[2] == 0 && w[3] == RT_CHARSET_FILL,
		"Utf8ToUni with room for 3 code units writes 2 and the NUL", "returned %u", ret);
	memset(w, RT_CHARSET_FILL_BYTE, sizeof(w));
	ret = Utf8ToUni(w, 5, (BYTE *)"ABC", 3);
	RtCheck(ctx, ret == 1 && w[0] == L'A' && w[1] == 0 && w[2] == RT_CHARSET_FILL,
		"Utf8ToUni with an odd byte size rounds down to whole code units", "returned %u", ret);
	memset(w, RT_CHARSET_FILL_BYTE, sizeof(w));
	ret = Utf8ToUni(w, sizeof(wchar_t), (BYTE *)"AB", 2);
	RtCheck(ctx, ret == 0 && w[0] == 0 && w[1] == RT_CHARSET_FILL,
		"Utf8ToUni with room for 1 code unit writes only the NUL", "returned %u", ret);
	memset(w, RT_CHARSET_FILL_BYTE, sizeof(w));
	ret = Utf8ToUni(w, 3 * sizeof(wchar_t), (BYTE *)"\xC3\xA9\xC3\xA9\xC3\xA9", 6);
	RtCheck(ctx, ret == 2 && w[0] == 0x00E9 && w[1] == 0x00E9 && w[2] == 0 && w[3] == RT_CHARSET_FILL,
		"Utf8ToUni cuts well-formed UTF-8 at the room", "returned %u", ret);
	memset(w, RT_CHARSET_FILL_BYTE, sizeof(w));
	ret = Utf8ToUni(w, 2 * sizeof(wchar_t), (BYTE *)"\xF0\x9F\x98\x80" "A", 5);
	RtCheck(ctx, ret == 1 && w[0] == 0x07D8 && w[1] == 0 && w[2] == RT_CHARSET_FILL,
		"Utf8ToUni cuts input that is not well-formed at the room", "returned %u", ret);
	memset(w, RT_CHARSET_FILL_BYTE, sizeof(w));
	ret = Utf8ToUni(w, 0, (BYTE *)"\xC3\xA9" "B", 0);
	RtCheck(ctx, ret == 2 && w[0] == 0x00E9 && w[1] == L'B' && w[2] == 0 && w[3] == RT_CHARSET_FILL,
		"Utf8ToUni with size 0 and input size 0: no limit, up to the NUL", "returned %u", ret);

	// UniToUtf8 size limits: the first bytes of the encoding, cut inside a sequence when need be,
	// and the NUL only when there is room for it
	memset(b, RT_CHARSET_FILL_BYTE, sizeof(b));
	ret = UniToUtf8(b, 2, two);
	RtCheck(ctx, ret == 2 && b[0] == 'a' && b[1] == 0xC3 && b[2] == RT_CHARSET_FILL_BYTE,
		"UniToUtf8 with room for 2 bytes cuts inside a sequence and writes no NUL", "returned %u", ret);
	memset(b, RT_CHARSET_FILL_BYTE, sizeof(b));
	ret = UniToUtf8(b, 3, two);
	RtCheck(ctx, ret == 3 && b[1] == 0xC3 && b[2] == 0xA9 && b[3] == RT_CHARSET_FILL_BYTE,
		"UniToUtf8 with room for exactly the bytes writes no NUL", "returned %u", ret);
	memset(b, RT_CHARSET_FILL_BYTE, sizeof(b));
	ret = UniToUtf8(b, 4, two);
	RtCheck(ctx, ret == 3 && b[2] == 0xA9 && b[3] == 0 && b[4] == RT_CHARSET_FILL_BYTE,
		"UniToUtf8 with room for the NUL writes it", "returned %u", ret);
	memset(b, RT_CHARSET_FILL_BYTE, sizeof(b));
	ret = UniToUtf8(b, 1, high);
	RtCheck(ctx, ret == 1 && b[0] == 0xED && b[1] == RT_CHARSET_FILL_BYTE,
		"UniToUtf8 cuts a surrogate's 3-byte sequence at the room", "returned %u", ret);
	memset(b, RT_CHARSET_FILL_BYTE, sizeof(b));
	ret = UniToUtf8(b, 0, mixed);
	RtCheck(ctx, ret == 9 && Cmp(b, mixed_utf8, 9) == 0 && b[9] == 0 && b[10] == RT_CHARSET_FILL_BYTE,
		"UniToUtf8 with size 0: no limit", "returned %u", ret);

	// NULL arguments
	ok = (Utf8ToUni(NULL, sizeof(w), (BYTE *)"A", 1) == 0 && Utf8ToUni(w, sizeof(w), NULL, 1) == 0 &&
		Utf8Len(NULL, 1) == 0 && CalcUtf8ToUni(NULL, 1) == 0 && UniToUtf8(NULL, sizeof(b), two) == 0 &&
		UniToUtf8(b, sizeof(b), NULL) == 0 && CalcUniToUtf8(NULL) == 0 &&
		CopyUniToUtf(NULL) == NULL && CopyUtfToUni(NULL) == NULL);
	RtCheck(ctx, ok, "The UTF-8 functions return 0 or NULL on NULL arguments", "a call returned something else");

	// The copy functions: a surrogate pair goes out as CESU-8 and comes back unchanged
	char *utf = CopyUniToUtf(mixed);
	RtCheck(ctx, utf != NULL && StrLen(utf) == 9 && Cmp(utf, mixed_utf8, 10) == 0,
		"CopyUniToUtf writes CESU-8 for a surrogate pair", "length %u", StrLen(utf));
	wchar_t *uni = CopyUtfToUni(utf);
	RtCheck(ctx, uni != NULL && UniStrCmp(uni, mixed) == 0, "CopyUtfToUni gives the surrogate pair back", "length %u", UniStrLen(uni));
	Free(uni);
	Free(utf);
	uni = CopyUtfToUni("\xF0\x9F\x98\x80");
	RtCheck(ctx, uni != NULL && UniStrLen(uni) == 1 && uni[0] == 0x07D8,
		"CopyUtfToUni decodes 4-byte UTF-8 as Mayaqua always has", "length %u", UniStrLen(uni));
	Free(uni);
	ret = UtfToUni(w, sizeof(w), "x\xC3\xA9");
	RtCheck(ctx, ret == 2 && w[0] == L'x' && w[1] == 0x00E9 && w[2] == 0, "UtfToUni decodes and returns the length", "returned %u", ret);
}

// UTF-8: every code unit, every 1- and 2-byte input, 3-byte inputs over the boundary bytes, and
// random strings, each against the reference
static void RtCharsetUtf8Sweep(RT_CTX *ctx)
{
	char err[MAX_SIZE];
	char first[MAX_SIZE];
	BYTE u[RT_CHARSET_MAX_LEN * 4];
	wchar_t s[RT_CHARSET_MAX_LEN + 1];
	UINT c, n, bad_back, len, room, r;
	UINT state = RT_CHARSET_SEED;

	// Every code unit U+0001-U+FFFF alone: encoded as the reference does, decoded as the
	// reference does, and back to the same code unit
	UINT bad = bad_back = 0;
	StrCpy(first, sizeof(first), "");
	for (c = 1;c <= 0xFFFF;c++)
	{
		wchar_t one[2];
		wchar_t back[2];

		one[0] = (wchar_t)c;
		one[1] = 0;

		if (RtUtf8EncodeMatches(one, 0, err, sizeof(err)) == false || RtUtf8DecodeMatches(u, RtUtf8EncodeRef(u, one, 1), 0, err, sizeof(err)) == false)
		{
			if (bad++ == 0)
			{
				StrCpy(first, sizeof(first), err);
			}
		}

		n = RtUtf8EncodeRef(u, one, 1);
		if (Utf8ToUni(back, sizeof(back), u, n) != 1 || back[0] != one[0])
		{
			bad_back++;
		}
	}
	RtCheck(ctx, bad == 0, "Every code unit U+0001-U+FFFF encodes and decodes as Mayaqua's UTF-8 always has", "%u differ, first: %s", bad, first);
	RtCheck(ctx, bad_back == 0, "Every code unit U+0001-U+FFFF comes back from its own encoding", "%u differ", bad_back);

	// Every input of 1 and 2 bytes
	bad = 0;
	StrCpy(first, sizeof(first), "");
	for (UINT i = 0;i < 256;i++)
	{
		u[0] = (BYTE)i;
		if (RtUtf8DecodeMatches(u, 1, 0, err, sizeof(err)) == false && bad++ == 0)
		{
			StrCpy(first, sizeof(first), err);
		}
		for (UINT j = 0;j < 256;j++)
		{
			u[1] = (BYTE)j;
			if (RtUtf8DecodeMatches(u, 2, 0, err, sizeof(err)) == false && bad++ == 0)
			{
				StrCpy(first, sizeof(first), err);
			}
		}
	}
	RtCheck(ctx, bad == 0, "Every input of 1 and 2 bytes decodes as Mayaqua's UTF-8 always has", "%u differ, first: %s", bad, first);

	// Every lead byte followed by two boundary bytes
	bad = 0;
	StrCpy(first, sizeof(first), "");
	for (UINT i = 0;i < 256;i++)
	{
		for (UINT j = 0;j < sizeof(rt_charset_bytes);j++)
		{
			for (UINT k = 0;k < sizeof(rt_charset_bytes);k++)
			{
				u[0] = (BYTE)i;
				u[1] = rt_charset_bytes[j];
				u[2] = rt_charset_bytes[k];
				if (RtUtf8DecodeMatches(u, 3, 0, err, sizeof(err)) == false && bad++ == 0)
				{
					StrCpy(first, sizeof(first), err);
				}
			}
		}
	}
	RtCheck(ctx, bad == 0, "Every lead byte before two boundary bytes decodes as Mayaqua's UTF-8 always has", "%u differ, first: %s", bad, first);

	// Random strings of pieces: mostly encoded code units (CESU-8 for surrogates), some well-formed
	// 4-byte sequences and some boundary bytes; decoded with a random room
	bad = 0;
	StrCpy(first, sizeof(first), "");
	for (UINT i = 0;i < RT_CHARSET_ROUNDS;i++)
	{
		UINT pieces = 1 + RtCharsetRandom(&state) % RT_CHARSET_MAX_LEN;

		len = 0;
		for (UINT j = 0;j < pieces;j++)
		{
			r = RtCharsetRandom(&state);
			if ((r & 7) == 0)
			{
				u[len++] = rt_charset_bytes[(r >> 3) % sizeof(rt_charset_bytes)];
			}
			else if ((r & 15) == 1)
			{
				c = 0x10000 + (r >> 4) % 0x100000;
				u[len++] = (BYTE)(0xf0 | (c >> 18));
				u[len++] = (BYTE)(0x80 | ((c >> 12) & 0x3f));
				u[len++] = (BYTE)(0x80 | ((c >> 6) & 0x3f));
				u[len++] = (BYTE)(0x80 | (c & 0x3f));
			}
			else
			{
				wchar_t one = (wchar_t)(1 + (r >> 4) % 0xFFFF);
				len += RtUtf8EncodeRef(&u[len], &one, 1);
			}
		}

		n = RtUtf8DecodeRef(NULL, u, len);
		r = RtCharsetRandom(&state);
		room = ((r & 3) == 0) ? 0 : 1 + (r >> 2) % (n + 2);
		if (RtUtf8DecodeMatches(u, len, room, err, sizeof(err)) == false && bad++ == 0)
		{
			StrCpy(first, sizeof(first), err);
		}
	}
	RtCheck(ctx, bad == 0, "Random UTF-8 strings decode as Mayaqua's UTF-8 always has", "%u differ, first: %s", bad, first);

	// Random strings of code units (one in eight a surrogate), encoded with a random room
	bad = 0;
	StrCpy(first, sizeof(first), "");
	for (UINT i = 0;i < RT_CHARSET_ROUNDS;i++)
	{
		len = 1 + RtCharsetRandom(&state) % RT_CHARSET_MAX_LEN;
		for (UINT j = 0;j < len;j++)
		{
			r = RtCharsetRandom(&state);
			switch (r & 7)
			{
			case 0:
			case 1:
			case 2:
				c = 0x01 + (r >> 3) % 0x7F;
				break;
			case 3:
			case 4:
				c = 0x80 + (r >> 3) % 0x780;
				break;
			case 5:
			case 6:
				c = 0x800 + (r >> 3) % 0xF000;
				if (c >= 0xD800)
				{
					c += 0x800;
				}
				break;
			default:
				c = 0xD800 + (r >> 3) % 0x800;
				break;
			}
			s[j] = (wchar_t)c;
		}
		s[len] = 0;

		n = RtUtf8EncodeRef(u, s, len);
		r = RtCharsetRandom(&state);
		room = ((r & 3) == 0) ? 0 : 1 + (r >> 2) % (n + 2);
		if (RtUtf8EncodeMatches(s, room, err, sizeof(err)) == false && bad++ == 0)
		{
			StrCpy(first, sizeof(first), err);
		}
	}
	RtCheck(ctx, bad == 0, "Random UTF-16 strings encode as Mayaqua's UTF-8 always has", "%u differ, first: %s", bad, first);
}

// StrToUni, CalcStrToUni and CopyStrToUni of str in the current locale: expect, or an empty
// string with CalcStrToUni 0 when str does not convert (converts false)
static void RtCharsetStrToUni(RT_CTX *ctx, char *what, const char *str, const wchar_t *expect, bool converts)
{
	wchar_t got[RT_CHARSET_BUF];

	UINT expect_len = UniStrLen(expect);
	UINT calc = CalcStrToUni(str);
	UINT len = StrToUni(got, sizeof(got), str);
	wchar_t *copy = CopyStrToUni(str);

	bool ok = (calc == (converts ? (expect_len + 1) * sizeof(wchar_t) : 0) && len == expect_len &&
		Cmp(got, expect, (expect_len + 1) * sizeof(wchar_t)) == 0 && copy != NULL && UniStrCmp(copy, expect) == 0);

	RtCheck(ctx, ok, what, "CalcStrToUni %u, StrToUni %u (first 0x%04X); expected %u units", calc, len, (UINT)got[0], expect_len);

	Free(copy);
}

// UniToStr, CalcUniToStr and CopyUniToStr of s in the current locale: expect, or an empty string
// with CalcUniToStr 0 when s does not convert (converts false)
static void RtCharsetUniToStr(RT_CTX *ctx, char *what, const wchar_t *s, const char *expect, bool converts)
{
	char got[RT_CHARSET_BUF];
	char hex[RT_CHARSET_BUF * 2 + 1];

	UINT expect_len = StrLen(expect);
	UINT calc = CalcUniToStr(s);
	UINT len = UniToStr(got, sizeof(got), s);
	char *copy = CopyUniToStr(s);

	bool ok = (calc == (converts ? expect_len + 1 : 0) && len == expect_len && Cmp(got, expect, expect_len + 1) == 0 &&
		copy != NULL && Cmp(copy, expect, expect_len + 1) == 0);

	BinToStr(hex, sizeof(hex), got, MIN(StrLen(got), 32));
	RtCheck(ctx, ok, what, "CalcUniToStr %u, UniToStr %u bytes %s; expected %u bytes", calc, len, hex, expect_len);

	Free(copy);
}

// ANSI: the conversions follow the code page of the C runtime's LC_CTYPE locale. Checked in
// the locale of the process (ASCII only: every code page setlocale(LC_ALL, "") picks keeps it),
// then in the C locale and in code pages 1252, 932 and UTF-8
static void RtCharsetAnsi(RT_CTX *ctx)
{
	wchar_t w[RT_CHARSET_BUF];
	char a[RT_CHARSET_BUF];
	wchar_t latin[] = {0x0080, 0x00FF, 0};
	wchar_t e_acute[] = {0x00E9, 0};
	wchar_t euro_e[] = {0x20AC, 0x00E9, 0};
	wchar_t a_macron[] = {0x0100, 0};
	wchar_t hiragana_a[] = {0x3042, 0};
	wchar_t sjis[] = {L'A', 0x3042, L'B', 0};
	wchar_t pair[] = {0xD83D, 0xDE00, 0};
	char saved[MAX_SIZE];

	// The locale of the process
	RtCharsetStrToUni(ctx, "StrToUni: ASCII", "Hello, World 123", L"Hello, World 123", true);
	RtCharsetStrToUni(ctx, "StrToUni: the empty string", "", L"", true);
	RtCharsetUniToStr(ctx, "UniToStr: ASCII", L"Hello, World 123", "Hello, World 123", true);
	RtCharsetUniToStr(ctx, "UniToStr: the empty string", L"", "", true);

	UINT ret = StrToUni(w, 4 * sizeof(wchar_t), "abcdef");
	RtCheck(ctx, ret == 3 && UniStrCmp(w, L"abc") == 0, "StrToUni cuts at the room and keeps the NUL", "returned %u", ret);
	ret = UniToStr(a, 4, L"abcdef");
	RtCheck(ctx, ret == 3 && StrCmp(a, "abc") == 0, "UniToStr cuts at the room and keeps the NUL", "returned %u", ret);

	bool ok = (StrToUni(NULL, sizeof(w), "a") == 0 && StrToUni(w, sizeof(w), NULL) == 0 && UniToStr(NULL, sizeof(a), L"a") == 0 &&
		UniToStr(a, sizeof(a), NULL) == 0 && CalcStrToUni(NULL) == 0 && CalcUniToStr(NULL) == 0 &&
		CopyStrToUni(NULL) == NULL && CopyUniToStr(NULL) == NULL);
	RtCheck(ctx, ok, "The ANSI functions return 0 or NULL on NULL arguments", "a call returned something else");

	char *name = setlocale(LC_CTYPE, NULL);
	StrCpy(saved, sizeof(saved), (name == NULL) ? "" : name);

	// The C locale: the bytes map 1:1 to U+0000-U+00FF, and nothing above U+00FF converts
	ok = (setlocale(LC_CTYPE, "C") != NULL);
	RtCheck(ctx, ok, "setlocale(LC_CTYPE, \"C\") succeeds", "returned NULL");
	if (ok)
	{
		RtCharsetStrToUni(ctx, "C locale: StrToUni maps 80 FF to U+0080 U+00FF", "\x80\xFF", latin, true);
		RtCharsetUniToStr(ctx, "C locale: UniToStr maps U+00E9 to E9", e_acute, "\xE9", true);
		RtCharsetUniToStr(ctx, "C locale: U+20AC does not convert", &euro_e[0], "", false);
		RtCharsetUniToStr(ctx, "C locale: U+0100 does not convert (no best fit)", a_macron, "", false);
	}

	// Code page 1252: best-fit mappings convert, characters without one do not
	ok = (setlocale(LC_CTYPE, ".1252") != NULL);
	RtCheck(ctx, ok, "setlocale(LC_CTYPE, \".1252\") succeeds", "returned NULL");
	if (ok)
	{
		RtCharsetStrToUni(ctx, "Code page 1252: StrToUni maps 80 E9 to U+20AC U+00E9", "\x80\xE9", euro_e, true);
		RtCharsetUniToStr(ctx, "Code page 1252: UniToStr maps U+20AC U+00E9 to 80 E9", euro_e, "\x80\xE9", true);
		RtCharsetUniToStr(ctx, "Code page 1252: U+0100 converts to A by best fit", a_macron, "A", true);
		RtCharsetUniToStr(ctx, "Code page 1252: U+3042 does not convert", hiragana_a, "", false);
	}

	// Code page 932 (double-byte)
	if (setlocale(LC_CTYPE, ".932") != NULL)
	{
		RtCharsetStrToUni(ctx, "Code page 932: StrToUni maps 41 82 A0 42 to A U+3042 B", "A\x82\xA0" "B", sjis, true);
		RtCharsetStrToUni(ctx, "Code page 932: a lead byte at the end does not convert", "A\x82", L"", false);
		RtCharsetUniToStr(ctx, "Code page 932: UniToStr maps U+3042 to 82 A0", hiragana_a, "\x82\xA0", true);
	}
	else
	{
		Print("  [SKIP] Code page 932: setlocale(LC_CTYPE, \".932\") returned NULL\n");
	}

	// UTF-8: strict, with surrogate pairs for 4-byte sequences
	if (setlocale(LC_CTYPE, ".UTF8") != NULL)
	{
		RtCharsetStrToUni(ctx, "UTF-8 locale: StrToUni maps C3 A9 to U+00E9", "\xC3\xA9", e_acute, true);
		RtCharsetStrToUni(ctx, "UTF-8 locale: StrToUni maps F0 9F 98 80 to a surrogate pair", "\xF0\x9F\x98\x80", pair, true);
		RtCharsetStrToUni(ctx, "UTF-8 locale: a cut-off sequence does not convert", "\xC3", L"", false);
		RtCharsetStrToUni(ctx, "UTF-8 locale: overlong C0 80 does not convert", "\xC0\x80", L"", false);
		RtCharsetStrToUni(ctx, "UTF-8 locale: CESU-8 ED A0 80 does not convert", "\xED\xA0\x80", L"", false);
		RtCharsetUniToStr(ctx, "UTF-8 locale: UniToStr maps a surrogate pair to F0 9F 98 80", pair, "\xF0\x9F\x98\x80", true);
		RtCharsetUniToStr(ctx, "UTF-8 locale: UniToStr maps U+00E9 to C3 A9", e_acute, "\xC3\xA9", true);
	}
	else
	{
		Print("  [SKIP] UTF-8 locale: setlocale(LC_CTYPE, \".UTF8\") returned NULL\n");
	}

	name = setlocale(LC_CTYPE, saved);
	RtCheck(ctx, name != NULL, "The locale of the process is restored", "setlocale(LC_CTYPE, \"%s\") returned NULL", saved);
}

// Constants of the ANSI comparison of the charset test
#define	RT_ANSI_ROUNDS			1500		// Generated strings per direction and locale
#define	RT_ANSI_MAX_LEN			12			// Code units, or bytes, of the longest generated random string
#define	RT_ANSI_SEED			0x7C3A91E5	// Seed of the generated strings: every run checks the same ones

// Locales of the ANSI comparison (setlocale(LC_CTYPE) names); NULL is the locale of the process
static char *rt_ansi_locales[] =
{
	NULL, "C", ".1252", ".932", ".UTF8", ".28591",
};

// UTF-16 code units the generator favours: ASCII, the C1 and Latin-1 edges, characters with and
// without a best fit in the Western code pages, Japanese, surrogates and the last code units
static wchar_t rt_ansi_units[] =
{
	L'A', L'z', L' ', 0x007F, 0x0080, 0x009F, 0x00A0, 0x00E9, 0x00FF, 0x0100, 0x0152, 0x0192,
	0x20AC, 0x2122, 0x3042, 0x30A2, 0x4E00, 0xFF61, 0xD83D, 0xDE00, 0xFFFD, 0xFFFE, 0xFFFF,
};

// Bytes the generator favours: ASCII, the lead and trail bytes of code page 932, and the lead
// and continuation bytes of UTF-8 around the boundaries of well-formed input
static BYTE rt_ansi_bytes[] =
{
	0x41, 0x7F, 0x80, 0x81, 0x82, 0x9F, 0xA0, 0xA9, 0xBF, 0xC0, 0xC3, 0xDF, 0xE0, 0xE3, 0xED, 0xEF,
	0xF0, 0xF4, 0xF5, 0xFC, 0xFF,
};

// Result of the ANSI comparison in one locale. The first difference is kept as raw data and only
// formatted once the locale of the process is back (Format itself converts through the ANSI code page)
typedef struct RT_ANSI_DIFF
{
	bool Set;								// The locale was set and compared
	UINT NumCompared;						// Calls compared with the old code
	UINT NumDiffer;							// Calls whose result differs
	char *FirstFunc;						// Function of the first difference
	UINT FirstSize;							// Its size argument
	bool FirstIsUni;						// Its input is FirstUni (else FirstStr)
	wchar_t FirstUni[RT_ANSI_MAX_LEN + 1];	// Its UTF-16 input
	char FirstStr[RT_CHARSET_BUF];			// Its byte input
} RT_ANSI_DIFF;

// The old ANSI conversions of Internat.c (before NAT-5), kept as the live oracle: wcstombs and
// mbstowcs of the C runtime in its current LC_CTYPE locale
static UINT RtOldCalcUniToStr(wchar_t *s)
{
	if (s == NULL)
	{
		return 0;
	}

	UINT ret = (UINT)wcstombs(NULL, s, UniStrLen(s));
	if (ret == (UINT)-1)
	{
		return 0;
	}

	return ret + 1;
}

static UINT RtOldUniToStr(char *str, UINT size, wchar_t *s)
{
	if (s == NULL || str == NULL)
	{
		return 0;
	}

	UINT new_size = RtOldCalcUniToStr(s);
	if (new_size == 0)
	{
		if (size >= 1)
		{
			StrCpy(str, 0, "");
		}
		return 0;
	}
	char *tmp = Malloc(new_size);
	tmp[0] = 0;
	wcstombs(tmp, s, new_size);
	tmp[new_size - 1] = 0;
	UINT ret = StrCpy(str, size, tmp);
	Free(tmp);

	return ret;
}

static char *RtOldCopyUniToStr(wchar_t *unistr)
{
	if (unistr == NULL)
	{
		return NULL;
	}

	UINT str_size = RtOldCalcUniToStr(unistr);
	if (str_size == 0)
	{
		return CopyStr("");
	}
	char *str = Malloc(str_size);
	RtOldUniToStr(str, str_size, unistr);

	return str;
}

static UINT RtOldCalcStrToUni(char *str)
{
	if (str == NULL)
	{
		return 0;
	}

	UINT ret = (UINT)mbstowcs(NULL, str, StrLen(str));
	if (ret == (UINT)-1)
	{
		return 0;
	}

	return (ret + 1) * sizeof(wchar_t);
}

static UINT RtOldStrToUni(wchar_t *s, UINT size, char *str)
{
	if (s == NULL || str == NULL)
	{
		return 0;
	}

	UINT new_size = RtOldCalcStrToUni(str);
	if (new_size == 0)
	{
		if (size >= 2)
		{
			UniStrCpy(s, 0, L"");
		}
		return 0;
	}
	wchar_t *tmp = Malloc(new_size);
	tmp[0] = 0;
	mbstowcs(tmp, str, StrLen(str));
	tmp[(new_size - 1) / sizeof(wchar_t)] = 0;
	UINT ret = UniStrCpy(s, size, tmp);
	Free(tmp);

	return ret;
}

static wchar_t *RtOldCopyStrToUni(char *str)
{
	if (str == NULL)
	{
		return NULL;
	}

	UINT uni_size = RtOldCalcStrToUni(str);
	if (uni_size == 0)
	{
		return CopyUniStr(L"");
	}
	wchar_t *uni = Malloc(uni_size);
	RtOldStrToUni(uni, uni_size, str);

	return uni;
}

// Count one compared call, and keep the first one whose result differs
static void RtAnsiDiff(RT_ANSI_DIFF *d, bool same, char *func, UINT size, const wchar_t *w, const char *s)
{
	d->NumCompared++;
	if (same)
	{
		return;
	}

	if (d->NumDiffer++ == 0)
	{
		d->FirstFunc = func;
		d->FirstSize = size;
		d->FirstIsUni = (w != NULL);
		if (w != NULL)
		{
			Copy(d->FirstUni, w, (UniStrLen(w) + 1) * sizeof(wchar_t));
		}
		else
		{
			Copy(d->FirstStr, s, StrLen(s) + 1);
		}
	}
}

// Generate a UTF-16 string of up to RT_ANSI_MAX_LEN non-zero code units into w (RT_ANSI_MAX_LEN + 1
// units): favoured units, printable ASCII, U+0080-U+01FF, surrogate pairs (a lone high surrogate
// at the end), or any code unit
static void RtAnsiGenUni(UINT *state, wchar_t *w)
{
	UINT len = RtCharsetRandom(state) % (RT_ANSI_MAX_LEN + 1);

	for (UINT i = 0;i < len;i++)
	{
		UINT r = RtCharsetRandom(state);

		switch (r % 5)
		{
		case 0:
			w[i] = rt_ansi_units[(r >> 3) % (_countof(rt_ansi_units))];
			break;
		case 1:
			w[i] = (wchar_t)(0x20 + (r >> 3) % 0x5F);
			break;
		case 2:
			w[i] = (wchar_t)(0x80 + (r >> 3) % 0x180);
			break;
		case 3:
			w[i] = (wchar_t)(0xD800 + (r >> 3) % 0x400);
			if ((i + 1) < len)
			{
				i++;
				w[i] = (wchar_t)(0xDC00 + (r >> 13) % 0x400);
			}
			break;
		default:
			w[i] = (wchar_t)(1 + (r >> 3) % 0xFFFF);
			break;
		}
	}
	w[len] = 0;
}

// Generate a string of up to RT_ANSI_MAX_LEN ASCII code units (U+0001-U+007F) into w
// (RT_ANSI_MAX_LEN + 1 units): the input of the ASCII fast path of the ANSI functions (FND-216)
static void RtAnsiGenAscii(UINT *state, wchar_t *w)
{
	UINT len = RtCharsetRandom(state) % (RT_ANSI_MAX_LEN + 1);

	for (UINT i = 0;i < len;i++)
	{
		w[i] = (wchar_t)(1 + (RtCharsetRandom(state) >> 3) % 0x7F);
	}
	w[len] = 0;
}

// Generate a byte string into s (RT_CHARSET_BUF bytes): random bytes, favoured bytes, or the
// bytes of a generated UTF-16 string in the current locale (input that converts), the last
// now and then cut by a byte or with one byte replaced
static void RtAnsiGenStr(UINT *state, char *s)
{
	UINT mode = RtCharsetRandom(state) % 3;
	UINT len = 0;

	if (mode == 0 || mode == 1)
	{
		len = RtCharsetRandom(state) % (RT_ANSI_MAX_LEN + 1);
		for (UINT i = 0;i < len;i++)
		{
			UINT r = RtCharsetRandom(state);

			if (mode == 0)
			{
				s[i] = (char)(1 + (r >> 3) % 0xFF);
			}
			else
			{
				s[i] = (char)rt_ansi_bytes[(r >> 3) % sizeof(rt_ansi_bytes)];
			}
		}
		s[len] = 0;
		return;
	}

	{
		wchar_t w[RT_ANSI_MAX_LEN + 1];

		RtAnsiGenUni(state, w);
		len = RtOldUniToStr(s, RT_CHARSET_BUF, w);

		UINT r = RtCharsetRandom(state);
		if (len != 0 && (r % 3) == 0)
		{
			if (((r >> 2) % 2) == 0)
			{
				s[len - 1] = 0;
			}
			else
			{
				s[(r >> 3) % len] = (char)rt_ansi_bytes[(r >> 8) % sizeof(rt_ansi_bytes)];
			}
		}
	}
}

// UniToStr, CalcUniToStr and CopyUniToStr against the old code on wcstombs, StrToUni,
// CalcStrToUni and CopyStrToUni against the old code on mbstowcs, in the current locale. Each
// destination is filled first and compared whole, at size 0 (no limit), at the exact size and at
// a random size. Every fourth input is ASCII alone, which the ASCII fast path converts. Prints
// nothing: the current locale may not be the locale of the process.
static void RtAnsiCompare(RT_ANSI_DIFF *d, UINT *state)
{
	UINT i;

	for (UINT n = 0;n < RT_ANSI_ROUNDS;n++)
	{
		wchar_t w[RT_ANSI_MAX_LEN + 1];
		char got[RT_CHARSET_BUF];
		char want[RT_CHARSET_BUF];
		UINT sizes[3];

		if ((n % 4) == 0)
		{
			RtAnsiGenAscii(state, w);
		}
		else
		{
			RtAnsiGenUni(state, w);
		}
		UINT full = RtOldCalcUniToStr(w);
		RtAnsiDiff(d, CalcUniToStr(w) == full, "CalcUniToStr", 0, w, NULL);

		sizes[0] = 0;
		sizes[1] = full;
		sizes[2] = 1 + RtCharsetRandom(state) % (full + 2);
		for (i = 0;i < 3;i++)
		{
			memset(got, RT_CHARSET_FILL_BYTE, sizeof(got));
			memset(want, RT_CHARSET_FILL_BYTE, sizeof(want));
			UINT r1 = UniToStr(got, sizes[i], w);
			UINT r2 = RtOldUniToStr(want, sizes[i], w);
			RtAnsiDiff(d, r1 == r2 && Cmp(got, want, sizeof(got)) == 0, "UniToStr", sizes[i], w, NULL);
		}

		char *copy = CopyUniToStr(w);
		char *want_copy = RtOldCopyUniToStr(w);
		RtAnsiDiff(d, copy != NULL && want_copy != NULL && StrCmp(copy, want_copy) == 0, "CopyUniToStr", 0, w, NULL);
		Free(copy);
		Free(want_copy);
	}

	for (UINT n = 0;n < RT_ANSI_ROUNDS;n++)
	{
		char s[RT_CHARSET_BUF];
		wchar_t got[RT_CHARSET_BUF];
		wchar_t want[RT_CHARSET_BUF];
		UINT sizes[3];

		if ((n % 4) == 0)
		{
			wchar_t a[RT_ANSI_MAX_LEN + 1];

			RtAnsiGenAscii(state, a);
			for (i = 0;a[i] != 0;i++)
			{
				s[i] = (char)a[i];
			}
			s[i] = 0;
		}
		else
		{
			RtAnsiGenStr(state, s);
		}
		UINT full = RtOldCalcStrToUni(s);
		RtAnsiDiff(d, CalcStrToUni(s) == full, "CalcStrToUni", 0, NULL, s);

		sizes[0] = 0;
		sizes[1] = full;
		sizes[2] = 1 + RtCharsetRandom(state) % (full + 4);
		for (i = 0;i < 3;i++)
		{
			memset(got, RT_CHARSET_FILL_BYTE, sizeof(got));
			memset(want, RT_CHARSET_FILL_BYTE, sizeof(want));
			UINT r1 = StrToUni(got, sizes[i], s);
			UINT r2 = RtOldStrToUni(want, sizes[i], s);
			RtAnsiDiff(d, r1 == r2 && Cmp(got, want, sizeof(got)) == 0, "StrToUni", sizes[i], NULL, s);
		}

		wchar_t *copy = CopyStrToUni(s);
		wchar_t *want_copy = RtOldCopyStrToUni(s);
		RtAnsiDiff(d, copy != NULL && want_copy != NULL && UniStrCmp(copy, want_copy) == 0, "CopyStrToUni", 0, NULL, s);
		Free(copy);
		Free(want_copy);
	}
}

// ANSI against the old code, live: the six ANSI functions against copies of their old code on
// wcstombs and mbstowcs, on generated strings, in the locale of the process, in the C locale, and
// in code pages 1252, 932, UTF-8 and 28591 whenever setlocale accepts them. The checks are
// printed once the locale of the process is back.
static void RtCharsetAnsiOracle(RT_CTX *ctx)
{
	RT_ANSI_DIFF d[_countof(rt_ansi_locales)];
	UINT num = _countof(rt_ansi_locales);
	UINT state = RT_ANSI_SEED;
	char saved[MAX_SIZE];
	char what[MAX_SIZE];
	char input[MAX_SIZE];

	Zero(d, sizeof(d));

	char *name = setlocale(LC_CTYPE, NULL);
	StrCpy(saved, sizeof(saved), (name == NULL) ? "" : name);

	for (UINT i = 0;i < num;i++)
	{
		d[i].Set = (rt_ansi_locales[i] == NULL || setlocale(LC_CTYPE, rt_ansi_locales[i]) != NULL);
		if (d[i].Set)
		{
			RtAnsiCompare(&d[i], &state);
		}
	}

	bool restored = (setlocale(LC_CTYPE, saved) != NULL);

	for (UINT i = 0;i < num;i++)
	{
		char *label = (rt_ansi_locales[i] == NULL) ? "the process locale" : rt_ansi_locales[i];

		Format(what, sizeof(what), "ANSI functions match the old wcstombs and mbstowcs code in %s", label);
		if (d[i].Set == false)
		{
			if (StrCmp(rt_ansi_locales[i], "C") == 0)
			{
				RtCheck(ctx, false, what, "setlocale(LC_CTYPE, \"C\") returned NULL");
			}
			else
			{
				Print("  [SKIP] %s: setlocale(LC_CTYPE, \"%s\") returned NULL\n", what, label);
			}
			continue;
		}

		input[0] = 0;
		if (d[i].NumDiffer != 0)
		{
			if (d[i].FirstIsUni)
			{
				for (UINT j = 0;d[i].FirstUni[j] != 0;j++)
				{
					char unit[8];

					Format(unit, sizeof(unit), "%04X ", (UINT)d[i].FirstUni[j]);
					StrCat(input, sizeof(input), unit);
				}
			}
			else
			{
				BinToStrEx(input, sizeof(input), d[i].FirstStr, StrLen(d[i].FirstStr));
			}
		}

		RtCheck(ctx, d[i].NumCompared != 0 && d[i].NumDiffer == 0, what,
			"%u of %u calls differ, first: %s size %u, input %s", d[i].NumDiffer, d[i].NumCompared,
			(d[i].FirstFunc == NULL) ? "-" : d[i].FirstFunc, d[i].FirstSize, input);
	}

	RtCheck(ctx, restored, "The locale of the process is restored after the ANSI comparison",
		"setlocale(LC_CTYPE, \"%s\") returned NULL", saved);
}

// charset: the UTF-8 and ANSI conversions of Internat.c against fixed vectors (valid, invalid
// and boundary sequences) and against a reference of the UTF-8 coding Mayaqua has always done
RANZ_TEST("charset", charset_test, "Charset: UTF-8 and ANSI conversions against fixed vectors and the historic UTF-8 coding.");
void charset_test(UINT num, char **arg)
{
	RT_CTX ctx;

	RtBegin(&ctx, "CHARSET", "Charset conversion test");

	RtCharsetUtf8Fixed(&ctx);
	RtCharsetUtf8Sweep(&ctx);
	RtCharsetAnsi(&ctx);
	RtCharsetAnsiOracle(&ctx);

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
	char what[MAX_SIZE];

	// A file left by an earlier failed run
	FileDeleteW(expect_path);

	Format(what, sizeof(what), "FileCreate through %s returns a file", label);
	IO *io = FileCreateW(name);
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

	IO *io = FileCreateW(L"@" RT_FILEIO_AUX_NAME);
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
	UINT64 size = FileSize64(io);
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
// position that equals ERROR_NEGATIVE_SEEK (131), which is an ordinary offset for SetFilePointerEx
static void RtFileioSeek(RT_CTX *ctx, wchar_t *aux_path, UCHAR *data)
{
	UCHAR buf[RT_FILEIO_SHORT_SIZE];

	IO *io = FileOpenW(aux_path, false);
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
	RtCheck(ctx, FileSeek(io, FILE_BEGIN, ERROR_NEGATIVE_SEEK),
		"FileSeek to offset 131 succeeds (it reported failure)", "returned false");

	FileClose(io);
}

// File dates: FileOpen reads them; FileClose of a writer writes the dates set in the IO
static void RtFileioDates(RT_CTX *ctx, wchar_t *aux_path)
{
	IO *io = FileOpenW(aux_path, true);
	if (RtCheck(ctx, io != NULL, "FileOpen of the aux file for the dates", "returned NULL") == false)
	{
		return;
	}
	UINT64 now = SystemTime64();
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
	// Read the error right after the call: argument evaluation order is unspecified in C
	BOOL marked = SetFileAttributesW(aux_path, FILE_ATTRIBUTE_HIDDEN);
	UINT err = (marked == FALSE) ? GetLastError() : 0;
	RtCheck(ctx, marked != FALSE, "Mark the aux file hidden", "error %u", err);

	IO *io = FileCreateW(L"@" RT_FILEIO_AUX_NAME);
	if (RtCheck(ctx, io != NULL, "FileCreate replaces a hidden file", "returned NULL"))
	{
		RtCheck(ctx, FileWrite(io, data, RT_FILEIO_SHORT_SIZE), "FileWrite of the replaced hidden file", "failed");
		FileClose(io);
	}

	DWORD attr = GetFileAttributesW(aux_path);
	RtCheck(ctx, attr != INVALID_FILE_ATTRIBUTES && (attr & FILE_ATTRIBUTE_HIDDEN) != 0, "The replaced file stays hidden",
		"attributes %u", attr);

	SetFileAttributesW(aux_path, FILE_ATTRIBUTE_NORMAL);
}

// More sharing: read-locked readers coexist and lock out a writer; a reader without the read
// lock lets a writer in; FileCreate shares read like a writer; a file locked by another
// handle still exists
static void RtFileioShare(RT_CTX *ctx, wchar_t *aux_path)
{
	IO *io2;

	IO *io = FileOpenW(aux_path, false);
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

	HANDLE h = CreateFileW(aux_path, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (RtCheck(ctx, h != INVALID_HANDLE_VALUE, "CreateFileW of the aux file without sharing", "error %u", GetLastError()))
	{
		RtCheck(ctx, IsFileExistsW(aux_path), "IsFileExists of a file opened without sharing is true", "returned false");
		CloseHandle(h);
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
	RtCheck(ctx, MakeDirW(L"@" RT_FILEIO_DIR_NAME), "MakeDir through @", "failed");
	DWORD attr = GetFileAttributesW(dir_path);
	RtCheck(ctx, attr != INVALID_FILE_ATTRIBUTES && (attr & FILE_ATTRIBUTE_DIRECTORY) != 0, "MakeDir creates the directory",
		"attributes %u", attr);
	RtCheck(ctx, MakeDirW(L"@" RT_FILEIO_DIR_NAME) == false, "MakeDir of an existing directory fails", "returned true");
	RtCheck(ctx, IsFileExistsW(dir_path) == false, "IsFileExists of a directory is false", "returned true");

	RtCheck(ctx, DeleteDirW(L"@" RT_FILEIO_DIR_NAME), "DeleteDir through @", "failed");
	RtCheck(ctx, GetFileAttributesW(dir_path) == INVALID_FILE_ATTRIBUTES, "DeleteDir removes the directory", "still there");
	RtCheck(ctx, DeleteDirW(L"@" RT_FILEIO_DIR_NAME) == false, "DeleteDir of a missing directory fails", "returned true");
}

// fileio: the "@", "$" and "|" prefixes, the path separator, the sharing modes, the
// all-or-nothing reads, and the create, seek, date, rename and directory semantics of FileIO
RANZ_TEST("fileio", fileio_test, "FileIO: @, $ and | prefixes, path separator, sharing modes, reads past the end.");
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
	IO *io2;
	UINT size;
	void *ham;
	bool ok;

	RtBegin(&ctx, "FILEIO", "FileIO test");

	for (UINT i = 0;i < RT_FILEIO_DATA_SIZE;i++)
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
	for (UINT i = 0;slash_path[i] != 0;i++)
	{
		if (slash_path[i] == L'\\')
		{
			slash_path[i] = L'/';
		}
	}
	IO *io = FileOpenW(slash_path, false);
	if (RtCheck(&ctx, io != NULL, "FileOpen of the path written with forward slashes", "returned NULL"))
	{
		ok = true;
		for (UINT i = 0;io->NameW[i] != 0;i++)
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

// Constants of the resources test
#define	RT_RES_OVERRIDE_NAME	"empty.config"						// Hamcore file that a loose file replaces
#define	RT_RES_OVERRIDE_DATA	"vpntest resources override\r\n"	// Contents of that loose file
#define	RT_RES_MISSING_NAME		"vpntest_no_such_resource.bin"		// Name that no hamcore file has
#define	RT_RES_SLASH_NAME		"DriverPackages/SeLow_Win10/x64/SeLow_x64.sys"		// Read with "/" and with "\"
#define	RT_RES_BACKSLASH_NAME	"|DriverPackages\\SeLow_Win10\\x64\\SeLow_x64.sys"	// The same file, as SeLowUser.c names it

#define	RT_RES_SOURCE_DIR		RANZ_HAMCORE_SOURCE_DIR				// src/bin/hamcore of the source tree (src/vpntest/CMakeLists.txt)

// Both buffers were read and hold the same bytes
static bool RtResourceSame(const BUF *a, const BUF *b)
{
	return a != NULL && b != NULL && a->Size == b->Size && Cmp(a->Buf, b->Buf, a->Size) == 0;
}

// One file of src/bin/hamcore: ReadHamcore of its name and "|" with its name return the exact
// bytes of the source file. No CR byte is left out of the comparison, so a line-ending change
// between the source file and the resource shows. A name with folders also opens with "\"
// between them, as SeLowUser.c names the driver package files.
static void RtResourceFile(RT_CTX *ctx, char *path, char *name)
{
	char what[MAX_SIZE];
	char bar_name[MAX_SIZE];
	bool sub = false;

	BUF *src = ReadDump(path);
	Format(what, sizeof(what), "Read the source file of %s", name);
	if (RtCheck(ctx, src != NULL, what, "cannot read %s", path) == false)
	{
		return;
	}

	BUF *b = ReadHamcore(name);
	Format(what, sizeof(what), "ReadHamcore of %s returns the bytes of its source file", name);
	RtCheck(ctx, RtResourceSame(src, b), what, "source %u bytes, read %u bytes%s",
		src->Size, b != NULL ? b->Size : 0, b != NULL ? "" : " (NULL)");
	FreeBuf(b);

	Format(bar_name, sizeof(bar_name), "|%s", name);
	b = ReadDump(bar_name);
	Format(what, sizeof(what), "ReadDump of %s returns the bytes of its source file", bar_name);
	RtCheck(ctx, RtResourceSame(src, b), what, "source %u bytes, read %u bytes%s",
		src->Size, b != NULL ? b->Size : 0, b != NULL ? "" : " (NULL)");
	FreeBuf(b);

	for (UINT i = 0;bar_name[i] != 0;i++)
	{
		if (bar_name[i] == '/')
		{
			bar_name[i] = '\\';
			sub = true;
		}
	}
	if (sub)
	{
		b = ReadDump(bar_name);
		Format(what, sizeof(what), "ReadDump of %s returns the same bytes", bar_name);
		RtCheck(ctx, RtResourceSame(src, b), what, "source %u bytes, read %u bytes%s",
			src->Size, b != NULL ? b->Size : 0, b != NULL ? "" : " (NULL)");
		FreeBuf(b);
	}

	FreeBuf(src);
}

// Every file under a folder of src/bin/hamcore, its subfolders included, through
// RtResourceFile. rel is the path of the folder relative to src/bin/hamcore ("" for
// src/bin/hamcore itself, "/" between folders). Returns the number of files.
static UINT RtResourceDir(RT_CTX *ctx, char *dir, char *rel)
{
	char path[MAX_SIZE];
	char name[MAX_SIZE];
	UINT files = 0;

	DIRLIST *d = EnumDir(dir);
	for (UINT i = 0;d != NULL && i < d->NumFiles;i++)
	{
		DIRENT *e = d->File[i];

		Format(path, sizeof(path), "%s/%s", dir, e->FileName);
		if (rel[0] == 0)
		{
			StrCpy(name, sizeof(name), e->FileName);
		}
		else
		{
			Format(name, sizeof(name), "%s/%s", rel, e->FileName);
		}

		if (e->Folder)
		{
			files += RtResourceDir(ctx, path, name);
		}
		else
		{
			RtResourceFile(ctx, path, name);
			files++;
		}
	}
	FreeDir(d);

	return files;
}

// Executables of the build that carry the same hamcore resources as vpntest.exe, next to it
static wchar_t *rt_resource_exes[] =
{
	L"ranz-node.exe",
};

// State of RtResourceCompare: the module to compare with, and the counts it gives
typedef struct RT_RES_CMP
{
	HMODULE Other;		// Module whose resources are compared with the enumerated ones
	UINT Num;			// Resources enumerated
	UINT NumSame;		// Of them, the ones that Other holds with the same bytes
} RT_RES_CMP;

// EnumResourceNames callback: count the resource, and count it as the same when the other
// module holds a resource of that type and name with the same bytes
static BOOL CALLBACK RtResourceCompare(HMODULE module, LPCSTR type, LPSTR name, LONG_PTR param)
{
	RT_RES_CMP *c = (RT_RES_CMP *)param;
	HRSRC r1 = FindResourceA(module, name, type);
	HRSRC r2 = FindResourceA(c->Other, name, type);

	c->Num++;

	if (r1 != NULL && r2 != NULL)
	{
		UINT size1 = SizeofResource(module, r1);
		UINT size2 = SizeofResource(c->Other, r2);
		void *data1 = LockResource(LoadResource(module, r1));
		void *data2 = LockResource(LoadResource(c->Other, r2));

		if (size1 == size2 && data1 != NULL && data2 != NULL && Cmp(data1, data2, size1) == 0)
		{
			c->NumSame++;
		}
	}

	return TRUE;
}

// resources: the hamcore files (src/bin/hamcore) that ReadHamcore and the "|" prefix read.
// Every file with its exact bytes, "\" read as "/", a leading "/" skipped, a missing name, a
// new buffer for each read, a loose "hamcore" folder next to the executable winning over the
// built-in file, no hamcore.se2 archive next to the executable, and ranz-node.exe carrying
// the same resources as vpntest.exe (#89)
RANZ_TEST("resources", resources_test, "Resources: every hamcore file through ReadHamcore and |, the loose hamcore folder, no hamcore.se2, the same resources in ranz-node.");
void resources_test(UINT num, char **arg)
{
	RT_CTX ctx;
	wchar_t exe_dir[MAX_SIZE];
	wchar_t se2_path[MAX_SIZE];
	wchar_t dir_path[MAX_SIZE];
	wchar_t override_path[MAX_SIZE];
	char what[MAX_SIZE];
	UINT size;
	void *data;
	bool ok;

	RtBegin(&ctx, "RESOURCES", "Resources test");

	GetExeDirW(exe_dir, sizeof(exe_dir));
	ConbinePathW(se2_path, sizeof(se2_path), exe_dir, L"hamcore.se2");
	ConbinePathW(dir_path, sizeof(dir_path), exe_dir, L"" HAMCORE_DIR_NAME);
	ConbinePathW(override_path, sizeof(override_path), dir_path, L"" RT_RES_OVERRIDE_NAME);

	// The executable carries the files itself: the build writes no hamcore.se2 archive
	RtCheck(&ctx, IsFileExistsW(se2_path) == false, "No hamcore.se2 next to the executable", "%S exists", se2_path);

	// ranz-node.exe carries the same files: it holds every resource of type
	// HAMCORE_RESOURCE_TYPE of this executable with the same bytes, and no other one
	for (UINT i = 0;i < _countof(rt_resource_exes);i++)
	{
		wchar_t other_path[MAX_SIZE];
		HMODULE self = GetModuleHandleW(NULL);
		RT_RES_CMP mine, theirs;

		Zero(&mine, sizeof(mine));
		Zero(&theirs, sizeof(theirs));

		ConbinePathW(other_path, sizeof(other_path), exe_dir, rt_resource_exes[i]);
		HMODULE other = LoadLibraryExW(other_path, NULL, LOAD_LIBRARY_AS_DATAFILE | LOAD_LIBRARY_AS_IMAGE_RESOURCE);
		UINT err = GetLastError();
		Format(what, sizeof(what), "Load %S as a data file", rt_resource_exes[i]);
		if (RtCheck(&ctx, other != NULL, what, "cannot load %S (error %u)", other_path, err))
		{
			mine.Other = other;
			theirs.Other = self;
			EnumResourceNamesA(self, HAMCORE_RESOURCE_TYPE, RtResourceCompare, (LONG_PTR)&mine);
			EnumResourceNamesA(other, HAMCORE_RESOURCE_TYPE, RtResourceCompare, (LONG_PTR)&theirs);

			Format(what, sizeof(what), "%S holds the hamcore resources of vpntest.exe, and no other", rt_resource_exes[i]);
			RtCheck(&ctx, mine.Num != 0 && mine.NumSame == mine.Num && theirs.NumSame == theirs.Num, what,
				"%u of the %u resources of vpntest.exe and %u of its own %u are the same",
				mine.NumSame, mine.Num, theirs.NumSame, theirs.Num);

			FreeLibrary(other);
		}
	}

	// Every file of src/bin/hamcore, walked at run time, holds the bytes of its source file
	UINT files = RtResourceDir(&ctx, RT_RES_SOURCE_DIR, "");
	RtCheck(&ctx, files != 0, "The hamcore source folder holds files", "no file in %s", RT_RES_SOURCE_DIR);

	// "|" opens the same bytes, with "\" in the name read as "/"
	BUF *b = ReadHamcore(RT_RES_SLASH_NAME);
	IO *io = FileOpen(RT_RES_BACKSLASH_NAME, false);
	if (RtCheck(&ctx, io != NULL, "FileOpen of a \"|\" name written with backslashes", "returned NULL"))
	{
		size = FileSize(io);
		data = ZeroMalloc(size + 1);
		ok = FileRead(io, data, size);
		RtCheck(&ctx, b != NULL && ok && size == b->Size && Cmp(data, b->Buf, size) == 0,
			"FileRead through \"|\" returns the bytes of ReadHamcore", "read %s, %u bytes", ok ? "ok" : "failed", size);
		Free(data);
		FileClose(io);
	}
	FreeBuf(b);

	// A leading "/" is skipped, and each read returns its own buffer at offset 0
	b = ReadHamcore("watermark.bin");
	BUF *b2 = ReadHamcore("/watermark.bin");
	if (RtCheck(&ctx, b != NULL && b2 != NULL && b->Size != 0 && b2->Size == b->Size && Cmp(b2->Buf, b->Buf, b->Size) == 0,
		"ReadHamcore skips a leading \"/\"", "%s", b2 == NULL ? "returned NULL" : "the bytes differ"))
	{
		RtCheck(&ctx, b->Current == 0 && b2->Current == 0, "A read starts at offset 0", "offsets %u and %u", b->Current, b2->Current);

		((UCHAR *)b->Buf)[0] ^= 0xFF;
		FreeBuf(b2);
		b2 = ReadHamcore("watermark.bin");
		RtCheck(&ctx, b2 != NULL && b2->Size == b->Size && ((UCHAR *)b2->Buf)[0] == (((UCHAR *)b->Buf)[0] ^ 0xFF),
			"Each read returns its own copy", "%s", b2 == NULL ? "returned NULL" : "a change to an earlier read shows");
	}
	FreeBuf(b);
	FreeBuf(b2);

	// A name that no file has
	RtCheck(&ctx, ReadHamcore(NULL) == NULL, "ReadHamcore(NULL) returns NULL", "returned a buffer");
	b = ReadHamcore(RT_RES_MISSING_NAME);
	RtCheck(&ctx, b == NULL, "ReadHamcore of a missing name returns NULL", "returned a buffer");
	FreeBuf(b);
	io = FileOpen("|" RT_RES_MISSING_NAME, false);
	RtCheck(&ctx, io == NULL, "FileOpen of a missing \"|\" name returns NULL", "returned a file");
	FileClose(io);
	RtCheck(&ctx, IsFile("|watermark.bin"), "IsFile of a \"|\" name", "returned false");
	RtCheck(&ctx, IsFile("|" RT_RES_MISSING_NAME) == false, "IsFile of a missing \"|\" name", "returned true");

	// A file in a "hamcore" folder next to the executable wins over the built-in one, until it is deleted
	BUF *embedded = ReadHamcore(RT_RES_OVERRIDE_NAME);
	bool made_dir = MakeDirW(dir_path);
	b = NewBufFromMemory(RT_RES_OVERRIDE_DATA, StrLen(RT_RES_OVERRIDE_DATA));
	ok = DumpBufW(b, override_path);
	FreeBuf(b);
	if (RtCheck(&ctx, ok, "Write a loose hamcore/" RT_RES_OVERRIDE_NAME " next to the executable", "cannot write %S", override_path))
	{
		b = ReadHamcore(RT_RES_OVERRIDE_NAME);
		RtCheck(&ctx, b != NULL && b->Size == StrLen(RT_RES_OVERRIDE_DATA) && Cmp(b->Buf, RT_RES_OVERRIDE_DATA, b->Size) == 0,
			"ReadHamcore returns the loose file", "%s", b == NULL ? "returned NULL" : "returned other bytes");
		FreeBuf(b);

		b = ReadDump("|" RT_RES_OVERRIDE_NAME);
		RtCheck(&ctx, b != NULL && b->Size == StrLen(RT_RES_OVERRIDE_DATA) && Cmp(b->Buf, RT_RES_OVERRIDE_DATA, b->Size) == 0,
			"ReadDump through \"|\" returns the loose file", "%s", b == NULL ? "returned NULL" : "returned other bytes");
		FreeBuf(b);
	}
	RtCheck(&ctx, FileDeleteW(override_path), "Delete the loose file", "failed");
	if (made_dir)
	{
		DeleteDirW(dir_path);
	}
	b = ReadHamcore(RT_RES_OVERRIDE_NAME);
	RtCheck(&ctx, b != NULL && embedded != NULL && b->Size == embedded->Size && Cmp(b->Buf, embedded->Buf, b->Size) == 0,
		"Without the loose file, ReadHamcore returns the built-in file again", "%s", b == NULL ? "returned NULL" : "returned other bytes");
	FreeBuf(b);
	FreeBuf(embedded);

	RtEnd(&ctx);
}

// Constants of the threadpool test
#define	RT_POOL_BOUND			5000	// Fail-safe bound of every wait in the threadpool test (ms)
#define	RT_POOL_SETTLE			300		// Time given to an idle pool thread to (wrongly) end (ms)
#define	RT_POOL_MAX_JOBS		32		// Held jobs started while looking for the idle pool thread
#define	RT_POOL_WAITERS			4		// Threads that wait on one THREAD at the same time
#define	RT_HOST_CYCLES			16		// Host threads created and ended by the handle check
#define	RT_POOL_MARK			0x5A17C0DE	// Per-thread mark the first job leaves on its pool thread
#define	RT_POOL_LATE_PARENT		1500	// Time a released job outlives the test by, into the process exit (ms)
#define	RT_POOL_LATE_CHILD		500		// Time the job that it starts there runs (ms)

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
	int PrioritySet;				// Thread priority the job leaves on its thread (0: THREAD_PRIORITY_NORMAL, unchanged)
	volatile int PrioritySeen;		// Thread priority the job found on its thread
} RT_POOL_JOB;

// A job that is still running when the test ends. It owns this block and frees it at its end.
typedef struct RT_POOL_LATE
{
	UINT Delay;						// Time the job runs (ms)
	bool StartChild;				// Start another late job just before it ends
} RT_POOL_LATE;

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

	if (t == NULL || j == NULL)
	{
		return;
	}

	j->OsThreadId = GetCurrentThreadId();
	j->MayaThreadId = ThreadId();

	// S_FALSE: COM is already initialised on this thread, by the pool callback or the host thread procedure
	HRESULT hr = CoInitialize(NULL);
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

	// Thread priority, which the pool gives back as normal after each job
	j->PrioritySeen = GetThreadPriority(GetCurrentThread());
	if (j->PrioritySet != THREAD_PRIORITY_NORMAL)
	{
		SetThreadPriority(GetCurrentThread(), j->PrioritySet);
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

// Late job: run on into the process exit, start one more late job there if asked, then free
// its block. A FreeThreading that does not wait for both leaves their THREAD objects and blocks
// allocated at the leak check, so the run then ends without "NO MEMORY LEAKS".
static void RtPoolLateThread(THREAD *t, void *param)
{
	RT_POOL_LATE *late = (RT_POOL_LATE *)param;

	if (t == NULL || late == NULL)
	{
		return;
	}

	SleepThread(late->Delay);

	if (late->StartChild)
	{
		RT_POOL_LATE *child = ZeroMalloc(sizeof(RT_POOL_LATE));

		child->Delay = RT_POOL_LATE_CHILD;
		ReleaseThread(NewThread(RtPoolLateThread, child));
	}

	Free(late);
}

// threadpool: NewThread runs each job on a pooled thread (open question 12 (a)).
// NewThread returns only after a pool thread took the job, the job sees the thread id and
// the COM state of its pool thread, an idle pool thread stays alive and takes a later job at
// normal priority, several threads can wait on one THREAD, a host thread (NewThreadInternal)
// ends with its handle closed, and the process exit waits for a job that outlives the test
// and for the job that it starts during the exit (shown by "NO MEMORY LEAKS" after the test)
RANZ_TEST("threadpool", threadpool_test, "Thread pool: job pickup, host thread id and COM, idle reuse, many waiters, host handles.");
void threadpool_test(UINT num, char **arg)
{
	RT_CTX ctx;
	RT_POOL_JOB first, host, target_job;
	RT_POOL_JOB held[RT_POOL_MAX_JOBS];
	THREAD *jobs[RT_POOL_MAX_JOBS];
	THREAD *waiters[RT_POOL_WAITERS];
	RT_POOL_WAIT_DATA wd;
	volatile bool go;
	UINT ran, com_ready, found_index = 0;
	DWORD handles_before = 0, handles_after = 0;

	RtBegin(&ctx, "THREADPOOL", "Thread pool test");

	// A job runs on a pool thread, which has already taken the job when NewThread returns.
	// It also raises the priority of that thread, which a later job there must not see.
	Zero(&first, sizeof(first));
	first.MarkSet = RT_POOL_MARK;
	first.PrioritySet = THREAD_PRIORITY_HIGHEST;
	THREAD *t = NewThread(RtPoolJobThread, &first);
	UINT picked = t->ThreadId;
	RtCheck(&ctx, picked != 0, "NewThread returns after a pool thread took the job (ThreadId is set)", "ThreadId is 0");
	bool ended = WaitThread(t, RT_POOL_BOUND);
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
	HANDLE h = OpenThread(SYNCHRONIZE, FALSE, picked);
	bool alive = (h != NULL && WaitForSingleObject(h, RT_POOL_SETTLE) == WAIT_TIMEOUT);
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
	bool found = false;
	UINT num_jobs = 0;
	for (UINT i = 0;i < RT_POOL_MAX_JOBS && found == false;i++)
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
	UINT joined = 0;
	for (UINT i = 0;i < num_jobs;i++)
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
	RtCheck(&ctx, found && held[found_index].PrioritySeen == THREAD_PRIORITY_NORMAL,
		"the later job finds that pool thread back at normal priority, which the first job had raised",
		"priority %d, expected %d", found ? held[found_index].PrioritySeen : 0, THREAD_PRIORITY_NORMAL);
	RtCheck(&ctx, joined == num_jobs, "every held job ends once its gate opens", "%u of %u ended", joined, num_jobs);

	// Several threads wait on one THREAD at the same time, and every one of them sees it end
	Zero(&target_job, sizeof(target_job));
	Zero(&wd, sizeof(wd));
	go = false;
	target_job.Go = &go;
	wd.Target = NewThread(RtPoolJobThread, &target_job);
	for (UINT i = 0;i < RT_POOL_WAITERS;i++)
	{
		waiters[i] = NewThread(RtPoolWaiterThread, &wd);
	}
	SleepThread(RT_POOL_SETTLE);
	UINT early = (UINT)wd.Returned;
	go = true;
	UINT waited = 0;
	for (UINT i = 0;i < RT_POOL_WAITERS;i++)
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
	bool counted = (GetProcessHandleCount(GetCurrentProcess(), &handles_before) != FALSE);
	for (UINT i = 0;i < RT_HOST_CYCLES;i++)
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

	// The process exit waits for pool work: a released job runs on past this test into
	// FreeThreading and starts another job there. The run ends with "NO MEMORY LEAKS" only if
	// FreeThreading waited for both, including the one started while it was waiting.
	// The check that the job is still running keeps this pin honest: a job that had already
	// ended would let the run end with "NO MEMORY LEAKS" without testing the wait.
	RT_POOL_LATE *late = ZeroMalloc(sizeof(RT_POOL_LATE));
	late->Delay = RT_POOL_LATE_PARENT;
	late->StartChild = true;
	t = NewThread(RtPoolLateThread, late);
	RtCheck(&ctx, WaitThread(t, 0) == false, "the late job is still running when the test ends",
		"it has already ended");
	ReleaseThread(t);

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
static void RtDnsCheckImmediate(RT_CTX *ctx, const char *hostname, IP *expect6, IP *expect4, volatile bool *cancel_flag, char *label)
{
	LIST *v6 = NULL;
	LIST *v4 = NULL;
	char what[MAX_SIZE];

	bool ret = DnsResolveEx(&v6, &v4, hostname, RT_DNS_IMMEDIATE_TIMEOUT, cancel_flag);

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
RANZ_TEST("dns", dns_test, "DNS: localhost and IP literals answered at once, the computer name through the resolver thread.");
void dns_test(UINT num, char **arg)
{
	RT_CTX ctx;
	LIST *v4;
	IP ip, local6, local4, lit6, lit4;
	char name[MAX_SIZE];
	char str[MAX_SIZE];
	volatile bool cancel = true;

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
	bool ret = GetIPEx(&ip, "localhost", RT_DNS_IMMEDIATE_TIMEOUT, NULL);
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
	{
		char host[MAX_SIZE];

		Zero(host, sizeof(host));
		RtCheck(&ctx, gethostname(host, sizeof(host) - 1) == 0 && StrCmp(name, host) == 0, "GetMachineName equals gethostname()",
			"GetMachineName gave \"%s\", gethostname() gave \"%s\"", name, host);
	}
	UINT threads = DnsThreadNum();
	LIST *v6 = v4 = NULL;
	ret = DnsResolveEx(&v6, &v4, name, RT_DNS_RESOLVER_TIMEOUT, NULL);
	RtCheck(&ctx, ret && (LIST_NUM(v6) + LIST_NUM(v4)) >= 1, "DnsResolveEx of the computer name gives at least one address",
		"name %s, returned %s, %u IPv6 and %u IPv4 addresses", name, ret ? "true" : "false", LIST_NUM(v6), LIST_NUM(v4));

	bool ok = true;
	StrCpy(str, sizeof(str), "none");
	for (UINT i = 0;i < LIST_NUM(v6);i++)
	{
		if (IsIP6((IP *)LIST_DATA(v6, i)) == false)
		{
			IPToStr(str, sizeof(str), LIST_DATA(v6, i));
			ok = false;
		}
	}
	for (UINT i = 0;i < LIST_NUM(v4);i++)
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

// Probe message of the trace test; the ETW step of CI (.github/scripts/etw-trace.ps1) looks for
// "RANZ TRACE PROBE 92 debug-on" and "RANZ TRACE PROBE 92 debug-off" in the console output and in
// the trace session's .etl file
#define	RT_TRACE_PROBE_FMT		"RANZ TRACE PROBE %u %s\n"
#define	RT_TRACE_PROBE_NUM		92

// trace: Debug() prints only while debug output is on, with or without an ETW trace session, and
// hands every message to the TraceLogging provider while a session listens (ticket #92). One probe
// goes out with debug output on and one with it off. Run as "trace listening" inside the CI
// trace session, both probes must reach the session's .etl file; before the provider existed,
// neither did.
RANZ_TEST("trace", trace_test, "ETW trace: Debug() output unchanged, messages to the TraceLogging provider: trace [listening].");
void trace_test(UINT num, char **arg)
{
	RT_CTX ctx;
	bool listening = (num >= 1 && StrCmpi(arg[0], "listening") == 0);
	bool debug = g_debug;

	RtBegin(&ctx, "TRACE", listening ? "ETW trace test (inside a trace session)" : "ETW trace test (no trace session)");

	RtCheck(&ctx, debug, "vpntest runs with debug output on", "g_debug is off");
	RtCheck(&ctx, IsTraceEnabled() == listening,
		listening ? "The trace session enables the provider" : "Without a trace session the provider is off",
		"IsTraceEnabled() returned %s", IsTraceEnabled() ? "true" : "false");

	// Printed, and traced while a session listens
	Debug(RT_TRACE_PROBE_FMT, RT_TRACE_PROBE_NUM, "debug-on");

	// Not printed, but traced while a session listens. g_debug also switches the memory tracker
	// (IsTrackingEnabled), so the probe allocates and frees untracked and leaves the tracker
	// balanced; the other vpntest threads are idle at this point.
	g_debug = false;
	Debug(RT_TRACE_PROBE_FMT, RT_TRACE_PROBE_NUM, "debug-off");
	g_debug = debug;

	// No format: Debug() returns at once, also while a session listens
	Debug(NULL);

	RtEnd(&ctx);
}

// Event source and limits of the event log test
#define	RT_EVENTLOG_SOURCE		"vpntest"
#define	RT_EVENTLOG_WAIT		10000		// How long the entry may take to appear in the log (ms)
#define	RT_EVENTLOG_SCAN		2000		// Newest entries of the Application log searched

// Whether one of the newest entries of the Application log has the source, type and event ID,
// and the message as its only insertion string
static bool RtEventLogFind(const char *source, UINT type, UINT event_id, const char *message)
{
	DWORD buf_size = 0x10000;
	UINT scanned = 0;
	bool found = false;
	wchar_t source_w[MAX_SIZE];
	wchar_t message_w[MAX_SIZE];

	StrToUni(source_w, sizeof(source_w), source);
	StrToUni(message_w, sizeof(message_w), message);

	HANDLE h = OpenEventLogW(NULL, L"Application");
	if (h == NULL)
	{
		return false;
	}

	UCHAR *buf = Malloc(buf_size);

	// Newest first
	while (found == false && scanned < RT_EVENTLOG_SCAN)
	{
		DWORD read = 0;
		DWORD needed = 0;
		DWORD pos = 0;

		if (ReadEventLogW(h, EVENTLOG_SEQUENTIAL_READ | EVENTLOG_BACKWARDS_READ, 0, buf, buf_size, &read, &needed) == false)
		{
			if (GetLastError() == ERROR_INSUFFICIENT_BUFFER && needed > buf_size)
			{
				buf_size = needed;
				buf = ReAlloc(buf, buf_size);
				continue;
			}

			// ERROR_HANDLE_EOF: no older entries
			break;
		}

		while (found == false && pos + sizeof(EVENTLOGRECORD) <= read)
		{
			EVENTLOGRECORD *r = (EVENTLOGRECORD *)(buf + pos);
			wchar_t *rec_source = (wchar_t *)(buf + pos + sizeof(EVENTLOGRECORD));
			wchar_t *rec_message = (wchar_t *)(buf + pos + r->StringOffset);

			if (r->Length == 0)
			{
				break;
			}

			if (r->EventID == event_id && r->EventType == type && r->NumStrings == 1 &&
				UniStrCmp(rec_source, source_w) == 0 && UniStrCmp(rec_message, message_w) == 0)
			{
				found = true;
			}

			scanned++;
			pos += r->Length;
		}
	}

	Free(buf);
	CloseEventLog(h);

	return found;
}

// eventlog: MsWriteEventLog() writes an Application log entry that the Event Log gives back with
// its source, type, event ID and message, the way the service writes its start and stop entries
// (ticket #92); a NULL source or message writes nothing
RANZ_TEST("eventlog", eventlog_test, "Event Log: MsWriteEventLog entries read back from the Application log.");
void eventlog_test(UINT num, char **arg)
{
	RT_CTX ctx;
	char msg[MAX_SIZE];
	bool found = false;

	RtBegin(&ctx, "EVENTLOG", "Event log test");

	// Unique to this run, so that an entry of an earlier run does not count
	Format(msg, sizeof(msg), "vpntest event log probe %u %I64u", MsGetCurrentProcessId(), SystemTime64());

	bool ret = MsWriteEventLog(RT_EVENTLOG_SOURCE, EVENTLOG_INFORMATION_TYPE, MS_EVENT_SERVICE_STARTED, msg);
	UINT err = GetLastError();
	RtCheck(&ctx, ret, "MsWriteEventLog writes an information entry", "returned false, error %u", err);

	// The entry may take a moment to become readable
	UINT64 end = Tick64() + RT_EVENTLOG_WAIT;
	while (ret)
	{
		found = RtEventLogFind(RT_EVENTLOG_SOURCE, EVENTLOG_INFORMATION_TYPE, MS_EVENT_SERVICE_STARTED, msg);
		if (found || Tick64() >= end)
		{
			break;
		}

		SleepThread(100);
	}
	RtCheck(&ctx, found, "The Application log holds the entry with its source, type, event ID and message",
		"not among the newest %u entries within %u ms", RT_EVENTLOG_SCAN, RT_EVENTLOG_WAIT);

	RtCheck(&ctx, MsWriteEventLog(NULL, EVENTLOG_INFORMATION_TYPE, MS_EVENT_SERVICE_STARTED, msg) == false,
		"MsWriteEventLog with a NULL source returns false", "returned true");
	RtCheck(&ctx, MsWriteEventLog(RT_EVENTLOG_SOURCE, EVENTLOG_INFORMATION_TYPE, MS_EVENT_SERVICE_STARTED, NULL) == false,
		"MsWriteEventLog with a NULL message returns false", "returned true");

	RtEnd(&ctx);
}
