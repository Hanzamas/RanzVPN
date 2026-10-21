// fuzz_common.c
// Shared part of the libFuzzer targets in src/fuzz

#include "fuzz_common.h"

#include "Mayaqua/Mayaqua.h"
#include "Mayaqua/Memory.h"

#include <stdio.h>
#include <stdlib.h>

// Release Mayaqua when libFuzzer exits normally (end of -runs or -max_total_time, or after
// running the inputs given as files). FreeMayaqua() then prints the kernel status and
// "NO MEMORY LEAKS", or "MEMORY LEAKS DETECTED" when Mayaqua memory, locks or references
// allocated while fuzzing were not released. A crash ends the process before this runs.
static void FuzzAtExit(void)
{
	FreeMayaqua();
}

// libFuzzer calls this once, before the first input
int LLVMFuzzerInitialize(int *argc, char ***argv)
{
	// Minimal mode: no hamcore files and no string table, which none of the parsers needs
	MayaquaMinimalMode();

	// Same flags as vpntest: no memcheck, debug on (debug enables the kernel status counters
	// that FreeMayaqua() checks for leaks)
	InitMayaqua(false, true);

	atexit(FuzzAtExit);

	return 0;
}

// Kernel status counters of live Mayaqua objects, the ones FreeMayaqua() checks for leaks
// (counted because InitMayaqua() runs with debug on)
#define	FUZZ_NUM_LIVE		3
static const UINT fuzz_live_ids[FUZZ_NUM_LIVE] = {KS_CURRENT_MEM_COUNT, KS_CURRENT_LOCK_COUNT, KS_CURRENT_REF_COUNT};
static const char *fuzz_live_names[FUZZ_NUM_LIVE] = {"memory blocks", "LOCK objects", "REF objects"};

// Current values of the live object counters
static void FuzzGetLive(UINT64 *live)
{
	for (UINT i = 0;i < FUZZ_NUM_LIVE;i++)
	{
		live[i] = KS_GET64(fuzz_live_ids[i]);
	}
}

// True when a live object counter is higher after than before
static bool FuzzLiveGrew(const UINT64 *before, const UINT64 *after)
{
	for (UINT i = 0;i < FUZZ_NUM_LIVE;i++)
	{
		if (after[i] > before[i])
		{
			return true;
		}
	}

	return false;
}

// Runs proc over the input and checks that every Mayaqua object it allocated was released.
// A run that leaves more live objects is run once more: a parser leak repeats on the same
// input, while a one-time lazy initialisation or an allocation by another Mayaqua thread
// (the Tick64 timer records clock adjustments) does not. A leak on both runs calls abort(),
// so that libFuzzer stops and saves the input as a crash artifact. libFuzzer's own leak
// detection needs LeakSanitizer, which Windows does not have, and OpenSSL allocations are
// not counted here: only -rss_limit_mb bounds them (src/fuzz/run_fuzzers.ps1).
void FuzzRun(FUZZ_PROC *proc, const uint8_t *data, size_t size)
{
	UINT64 before[FUZZ_NUM_LIVE];
	UINT64 after[FUZZ_NUM_LIVE];

	FuzzGetLive(before);
	proc(data, size);
	FuzzGetLive(after);
	if (FuzzLiveGrew(before, after) == false)
	{
		return;
	}

	FuzzGetLive(before);
	proc(data, size);
	FuzzGetLive(after);
	if (FuzzLiveGrew(before, after) == false)
	{
		return;
	}

	fprintf(stderr, "==RANZ FUZZ== Mayaqua objects leaked by this input (live count before -> after):\n");
	for (UINT i = 0;i < FUZZ_NUM_LIVE;i++)
	{
		fprintf(stderr, "  %s: %llu -> %llu\n", fuzz_live_names[i],
			(unsigned long long)before[i], (unsigned long long)after[i]);
	}
	fflush(stderr);

	// No abort message box and no Windows Error Reporting: libFuzzer's SIGABRT handler reports it
	_set_abort_behavior(0, _WRITE_ABORT_MSG | _CALL_REPORTFAULT);
	abort();
}

// Copy of the input as a BUF positioned at its beginning.
// NewBuf() reserves INIT_BUF_SIZE (10240) bytes; the storage is shrunk to the input size so
// that a read past b->Size reaches poisoned memory instead of unused capacity. Mayaqua's
// Malloc() rounds the block up to 8 bytes and appends its MEMTAG2 canary; with RANZ_ASAN
// that slack is poisoned (Memory.c), so the first byte past the input is already reported.
BUF *FuzzNewBuf(const uint8_t *data, size_t size)
{
	BUF *b = NewBuf();

	if (size != 0)
	{
		WriteBuf(b, (void *)data, (UINT)size);
		b->Buf = ReAlloc(b->Buf, b->Size);
		b->SizeReserved = b->Size;
	}

	SeekBufToBegin(b);

	return b;
}
