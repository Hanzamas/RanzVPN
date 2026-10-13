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
