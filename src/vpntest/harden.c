// harden.c
// Named hardened licence-gate test of vpntest ("harden" command, SEC-4 #282, ADR-0036).
//
// Drives ranzguard.exe, the release-only hardened binary, twice: once as an ordinary child and once as
// a debuggee through the Win32 debug API. The hardened binary must report "RANZGUARD UNLOCKED" when it
// is not watched and degrade to "RANZGUARD LOCKED" under a debugger, and it must never crash (the
// degrade-or-deceive response of ADR-0036). When ranzguard.exe is absent, which is every build but the
// hardened one, the test skips and still reports OK, so it is safe in the ordinary CI jobs.

#include "Mayaqua/FileIO.h"
#include "Mayaqua/Kernel.h"
#include "Mayaqua/Memory.h"
#include "Mayaqua/Str.h"

#include <stdarg.h>

#define HARDEN_GUARD_EXE L"ranzguard.exe"
#define HARDEN_WAIT_MS 30000 // longest a single ranzguard run or debug step may take
#define HARDEN_TOKEN_UNLOCKED "RANZGUARD UNLOCKED"
#define HARDEN_TOKEN_LOCKED "RANZGUARD LOCKED"
#define HARDEN_CRASH_STATUS 0xC0000000 // the NTSTATUS error range: an exit code here is a crash

// Run state of the test
typedef struct HARDEN_CTX
{
	UINT NumChecks;		// Checks run so far
	UINT NumFailed;		// Checks failed so far
} HARDEN_CTX;

// Result of one ranzguard run
typedef struct HARDEN_RUN
{
	bool Started;		// CreateProcess succeeded and the run finished
	UINT ExitCode;		// Process exit code
	UINT LaunchError;	// GetLastError when CreateProcess failed, 0 otherwise
	bool Crashed;		// An unhandled (second-chance) exception, a crash exit code, or a timeout
	char Token[64];		// The first line ranzguard printed, trimmed of the newline
} HARDEN_RUN;

// Record one check: print [PASS], or [FAIL] with the formatted detail
static void HardenCheck(HARDEN_CTX *ctx, bool ok, char *what, char *detail_fmt, ...)
{
	char detail[MAX_SIZE];
	va_list args;

	ctx->NumChecks++;

	if (ok)
	{
		Print("  [PASS] %s\n", what);
		return;
	}

	va_start(args, detail_fmt);
	FormatArgs(detail, sizeof(detail), detail_fmt, args);
	va_end(args);

	Print("  [FAIL] %s (%s)\n", what, detail);

	ctx->NumFailed++;
}

// Read the pipe read-end into token, keep only the first line (up to a CR or LF), NUL-terminate. The
// child prints well under the pipe buffer, so this never blocks the child.
static void HardenReadToken(HANDLE rd, char *token, UINT size)
{
	UINT used = 0;
	token[0] = 0;

	for (;;)
	{
		char chunk[256];
		DWORD got = 0;

		if (ReadFile(rd, chunk, sizeof(chunk), &got, NULL) == FALSE || got == 0)
		{
			break;
		}
		for (DWORD i = 0; i < got && used + 1 < size; i++)
		{
			if (chunk[i] == '\r' || chunk[i] == '\n')
			{
				token[used] = 0;
				return;
			}
			token[used++] = chunk[i];
		}
	}

	token[used] = 0;
}

// Pump debug events until the debuggee exits, so a breakpoint never terminates it. A software
// breakpoint is swallowed with DBG_CONTINUE; any other first-chance exception is passed back to the
// debuggee's own handlers, and a second-chance exception is counted as a crash.
static bool HardenPumpDebugger(HANDLE process, UINT *exit_code, bool *crashed)
{
	DEBUG_EVENT ev;
	bool exited = false;

	*exit_code = 0;
	*crashed = false;

	for (;;)
	{
		if (WaitForDebugEvent(&ev, HARDEN_WAIT_MS) == FALSE)
		{
			TerminateProcess(process, 1);
			*crashed = true;
			return false;
		}

		DWORD cont = DBG_CONTINUE;

		switch (ev.dwDebugEventCode)
		{
		case EXCEPTION_DEBUG_EVENT:
		{
			DWORD code = ev.u.Exception.ExceptionRecord.ExceptionCode;
			DWORD first = ev.u.Exception.dwFirstChance;

			if (code == EXCEPTION_BREAKPOINT || code == EXCEPTION_SINGLE_STEP)
			{
				// Swallow it: the guard's vectored handler then never runs, so its own check sees the
				// breakpoint taken by a debugger
				cont = DBG_CONTINUE;
			}
			else if (first != 0)
			{
				cont = DBG_EXCEPTION_NOT_HANDLED;
			}
			else
			{
				*crashed = true;
				cont = DBG_CONTINUE;
			}
			break;
		}
		case CREATE_PROCESS_DEBUG_EVENT:
			if (ev.u.CreateProcessInfo.hFile != NULL)
			{
				CloseHandle(ev.u.CreateProcessInfo.hFile);
			}
			break;
		case LOAD_DLL_DEBUG_EVENT:
			if (ev.u.LoadDll.hFile != NULL)
			{
				CloseHandle(ev.u.LoadDll.hFile);
			}
			break;
		case EXIT_PROCESS_DEBUG_EVENT:
			*exit_code = ev.u.ExitProcess.dwExitCode;
			exited = true;
			break;
		default:
			break;
		}

		ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, cont);

		if (exited)
		{
			break;
		}
	}

	return true;
}

// Run ranzguard once, as an ordinary child or as a debuggee, capturing its first line and exit code
static void HardenRunGuard(wchar_t *exe, bool as_debuggee, HARDEN_RUN *out)
{
	SECURITY_ATTRIBUTES sa;
	STARTUPINFOW si;
	PROCESS_INFORMATION pi;
	HANDLE rd = NULL;
	HANDLE wr = NULL;
	HANDLE nul = INVALID_HANDLE_VALUE;

	Zero(out, sizeof(HARDEN_RUN));

	Zero(&sa, sizeof(sa));
	sa.nLength = sizeof(sa);
	sa.bInheritHandle = TRUE;
	sa.lpSecurityDescriptor = NULL;

	if (CreatePipe(&rd, &wr, &sa, 0) == FALSE)
	{
		out->LaunchError = GetLastError();
		return;
	}
	// The read end stays with this process, so it is not inherited
	SetHandleInformation(rd, HANDLE_FLAG_INHERIT, 0);

	// A valid, inheritable stdin for the child: the standard input of a non-interactive CI process can be
	// a closed or non-inheritable handle, and STARTF_USESTDHANDLES with such a handle fails CreateProcess
	nul = CreateFileW(L"NUL", GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, &sa, OPEN_EXISTING, 0, NULL);

	Zero(&si, sizeof(si));
	si.cb = sizeof(si);
	si.dwFlags = STARTF_USESTDHANDLES;
	si.hStdInput = nul;
	si.hStdOutput = wr;
	si.hStdError = wr;

	Zero(&pi, sizeof(pi));
	DWORD flags = as_debuggee ? DEBUG_ONLY_THIS_PROCESS : 0;

	if (CreateProcessW(exe, NULL, NULL, NULL, TRUE, flags, NULL, NULL, &si, &pi) == FALSE)
	{
		out->LaunchError = GetLastError();
		CloseHandle(rd);
		CloseHandle(wr);
		if (nul != INVALID_HANDLE_VALUE)
		{
			CloseHandle(nul);
		}
		return;
	}

	// The child inherited the write end and stdin; this process closes them so the read sees end-of-file
	CloseHandle(wr);
	if (nul != INVALID_HANDLE_VALUE)
	{
		CloseHandle(nul);
	}

	UINT exit_code = 0;
	bool crashed = false;

	if (as_debuggee)
	{
		out->Started = HardenPumpDebugger(pi.hProcess, &exit_code, &crashed);
	}
	else
	{
		DWORD waited = WaitForSingleObject(pi.hProcess, HARDEN_WAIT_MS);
		if (waited == WAIT_OBJECT_0)
		{
			DWORD code = 1;
			GetExitCodeProcess(pi.hProcess, &code);
			exit_code = code;
			out->Started = true;
		}
		else
		{
			TerminateProcess(pi.hProcess, 1);
			crashed = true;
		}
	}

	HardenReadToken(rd, out->Token, sizeof(out->Token));

	out->ExitCode = exit_code;
	out->Crashed = crashed || (out->Started && exit_code >= HARDEN_CRASH_STATUS);

	CloseHandle(pi.hThread);
	CloseHandle(pi.hProcess);
	CloseHandle(rd);
}

// harden: ranzguard reports unlocked unwatched and degrades to locked under a debugger, never crashing
void harden_test(UINT num, char **arg)
{
	HARDEN_CTX ctx;
	wchar_t dir[MAX_PATH];
	wchar_t exe[MAX_PATH];
	HARDEN_RUN clean;
	HARDEN_RUN watched;

	Zero(&ctx, sizeof(ctx));

	Print("Hardened licence gate test (ranzguard, ADR-0036)\n");

	GetExeDirW(dir, sizeof(dir));
	CombinePathW(exe, sizeof(exe), dir, HARDEN_GUARD_EXE);

	if (IsFileExistsW(exe) == false)
	{
		Print("  [SKIP] ranzguard.exe is not next to vpntest.exe: only the hardened build (RANZ_HARDENED) makes it\n");
		Print("HARDEN TEST OK\n");
		return;
	}

	// Unwatched: the gate is open
	HardenRunGuard(exe, false, &clean);
	HardenCheck(&ctx, clean.Started, "ranzguard runs as an ordinary child", "CreateProcess error %u", clean.LaunchError);
	HardenCheck(&ctx, clean.Started && clean.Crashed == false, "unwatched run does not crash", "exit code 0x%X", clean.ExitCode);
	HardenCheck(&ctx, clean.Started && clean.ExitCode == 0, "unwatched run exits 0", "exit code 0x%X", clean.ExitCode);
	HardenCheck(&ctx, clean.Started && StrCmpi(clean.Token, HARDEN_TOKEN_UNLOCKED) == 0,
		"unwatched run reports unlocked", "token \"%s\"", clean.Token);

	// Under a debugger: the gate degrades to locked, and still no crash
	HardenRunGuard(exe, true, &watched);
	HardenCheck(&ctx, watched.Started, "ranzguard runs under a debugger", "CreateProcess error %u or the debug loop did not finish", watched.LaunchError);
	HardenCheck(&ctx, watched.Started && watched.Crashed == false,
		"no crash under a debugger (degrade or deceive, never crash)", "exit code 0x%X", watched.ExitCode);
	HardenCheck(&ctx, watched.Started && watched.ExitCode == 0, "debuggee exits 0", "exit code 0x%X", watched.ExitCode);
	HardenCheck(&ctx, watched.Started && StrCmpi(watched.Token, HARDEN_TOKEN_LOCKED) == 0,
		"debuggee degrades to locked (the deceive response)", "token \"%s\"", watched.Token);

	if (ctx.NumFailed == 0)
	{
		Print("HARDEN TEST OK\n");
	}
	else
	{
		Print("HARDEN TEST FAILED (%u of %u checks failed)\n", ctx.NumFailed, ctx.NumChecks);
	}
}
