// vmdetect.c
// Named VM detection test of vpntest ("vmdetect" command, FIX-7 #103)
//
// MsIsInVm fills the b_is_in_vm capability at server start. It used to write detectvm.vbs to the
// temp directory of the process and run it through cscript.exe, waiting up to 30 seconds for the
// WMI queries of the script. The test pins the detection that replaces it: the first call writes
// no script, starts no child process and returns within VMDETECT_MAX_TIME, and it reports a
// virtual machine on the GitHub-hosted runners, which are virtual machines. The child processes
// are counted by a job object that the test puts its own process in. Prints "VMDETECT TEST OK"
// only when every check passes, and frees everything it allocates.

#include "Mayaqua/FileIO.h"
#include "Mayaqua/Kernel.h"
#include "Mayaqua/Memory.h"
#include "Mayaqua/Microsoft.h"
#include "Mayaqua/Str.h"
#include "Mayaqua/Tick64.h"

#include <stdarg.h>

#define	VMDETECT_MAX_TIME		1000				// Time that the first MsIsInVm call may take (ms)
#define	VMDETECT_SCRIPT			L"detectvm.vbs"		// Script that the former detection wrote to the temp directory of the process
#define	VMDETECT_BIOS_KEY		"HARDWARE\\DESCRIPTION\\System\\BIOS"	// SMBIOS strings as Windows records them at boot (printed only)

// Run state of the test
typedef struct VMDETECT_CTX
{
	UINT NumChecks;						// Checks run so far
	UINT NumFailed;						// Checks failed so far
} VMDETECT_CTX;

// Record one check: print [PASS], or [FAIL] with the formatted detail
static void VmDetectCheck(VMDETECT_CTX *ctx, bool ok, char *what, char *detail_fmt, ...)
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

// Number of processes that the job has held so far, the terminated ones included, or INFINITE
// when the query fails
static UINT VmDetectJobProcesses(HANDLE job)
{
	JOBOBJECT_BASIC_ACCOUNTING_INFORMATION info;

	Zero(&info, sizeof(info));

	if (QueryInformationJobObject(job, JobObjectBasicAccountingInformation, &info, sizeof(info), NULL) == FALSE)
	{
		return INFINITE;
	}

	return info.TotalProcesses;
}

// True on a GitHub-hosted runner: GitHub Actions without RUNNER_ENVIRONMENT=self-hosted
static bool VmDetectIsGitHubHosted()
{
	char tmp[MAX_SIZE];

	if (GetEnv("GITHUB_ACTIONS", tmp, sizeof(tmp)) == false || StrCmpi(tmp, "true") != 0)
	{
		return false;
	}

	if (GetEnv("RUNNER_ENVIRONMENT", tmp, sizeof(tmp)) && StrCmpi(tmp, "self-hosted") == 0)
	{
		return false;
	}

	return true;
}

// vmdetect: the first MsIsInVm call of the process writes no script, starts no process, returns
// within VMDETECT_MAX_TIME, and reports a VM on a GitHub-hosted runner
void vmdetect_test(UINT num, char **arg)
{
	VMDETECT_CTX ctx;
	wchar_t script[MAX_PATH];
	UINT before = INFINITE;
	UINT after = INFINITE;
	UINT err = 0;

	Zero(&ctx, sizeof(ctx));

	Print("VM detection test (MsIsInVm, the b_is_in_vm capability)\n");

	// The temp directory of the process is new, so no earlier run left the script there; remove it anyway
	CombinePathW(script, sizeof(script), MsGetMyTempDirW(), VMDETECT_SCRIPT);
	FileDeleteW(script);

	// From here on the job counts every process that this process starts
	HANDLE job = CreateJobObjectW(NULL, NULL);
	if (job == NULL || AssignProcessToJobObject(job, GetCurrentProcess()) == FALSE)
	{
		err = GetLastError();
	}
	else
	{
		before = VmDetectJobProcesses(job);
	}

	VmDetectCheck(&ctx, before != INFINITE, "This process is in a new job object that counts its child processes",
		"error %u", err);

	// Nothing in vpntest calls MsIsInVm before this test, so this is the call that detects
	UINT64 start = Tick64();
	bool vm = MsIsInVm();
	UINT64 took = Tick64() - start;

	if (before != INFINITE)
	{
		after = VmDetectJobProcesses(job);
	}

	if (job != NULL)
	{
		CloseHandle(job);
	}

	VmDetectCheck(&ctx, before != INFINITE && after == before, "MsIsInVm starts no process",
		"processes of the job: %u before the call, %u after it", before, after);

	VmDetectCheck(&ctx, IsFileExistsW(script) == false, "MsIsInVm writes no detectvm.vbs to the temp directory",
		"the file exists after the call");
	FileDeleteW(script);

	VmDetectCheck(&ctx, took <= VMDETECT_MAX_TIME, "MsIsInVm returns within the time limit",
		"took %I64u ms, limit %u ms", took, VMDETECT_MAX_TIME);

	// Informational: the answer, the SMBIOS strings that Windows recorded, and the time of the call
	char *manufacturer = MsRegReadStr(REG_LOCAL_MACHINE, VMDETECT_BIOS_KEY, "SystemManufacturer");
	char *product = MsRegReadStr(REG_LOCAL_MACHINE, VMDETECT_BIOS_KEY, "SystemProductName");
	Print("  MsIsInVm() = %s (system manufacturer \"%s\", product \"%s\")\n", vm ? "true" : "false",
		manufacturer == NULL ? "" : manufacturer, product == NULL ? "" : product);
	Free(manufacturer);
	Free(product);

	Print("BENCH vmdetect_first_call %I64u ms\n", took);

	if (VmDetectIsGitHubHosted())
	{
		VmDetectCheck(&ctx, vm, "MsIsInVm reports a VM on a GitHub-hosted runner, which is a virtual machine",
			"MsIsInVm() = false");
	}
	else
	{
		Print("  [SKIP] Not a GitHub-hosted runner: the answer of MsIsInVm is not checked\n");
	}

	if (ctx.NumFailed == 0)
	{
		Print("VMDETECT TEST OK\n");
	}
	else
	{
		Print("VMDETECT TEST FAILED (%u of %u checks failed)\n", ctx.NumFailed, ctx.NumChecks);
	}
}
