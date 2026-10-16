// selowtest.c
// Named SeLow test of vpntest ("selow" command, FIX-2 #98)
//
// Pins the SeLow user-mode side of the Local Bridge (SeLowUser.c, BridgeWin32.c):
// - Asking whether SeLow is supported (SuInitEx, Win32EthIsSuSupported, IsBridgeSupported) never
//   reaches the driver install step, leaves the SeLow service as it was, and does not use up the one
//   install attempt of the process.
// - Creating a Local Bridge (OpenEth) and listing the devices for one (GetEthList, the EnumEthernet
//   RPC) still reach the install step when the SeLow device is missing, at most once per process.
// - The adapter-list read (SuReadAdapterInfoList) accepts a list with SL_SIGNATURE and refuses a
//   wrong signature or a failed read. SuGetAdapterList frees its list on a failed read and leaves
//   the device handle open (SuFree closes it).
// The install step is replaced by a counting stub (SuSetInstallProc), so the test never installs a
// driver. The install checks run only on a machine without SeLow, such as the CI runners; elsewhere
// they are skipped. Prints "SELOW TEST OK" only when every check passes, and frees everything it
// allocates, so that the run still ends with "NO MEMORY LEAKS".

#include "Cedar/BridgeWin32.h"
#include "Cedar/SeLowUser.h"

#include "Mayaqua/FileIO.h"
#include "Mayaqua/Memory.h"
#include "Mayaqua/Microsoft.h"
#include "Mayaqua/Str.h"

#include <stdarg.h>

#define	SELOWTEST_FILE_NAME			L"selowtest_list.tmp"			// Adapter list file next to vpntest.exe
#define	SELOWTEST_VERSION			0x1234							// SeLowVersion written to the file
#define	SELOWTEST_BAD_SIGNATURE		0xDEADBEEE						// A signature that is not SL_SIGNATURE
#define	SELOWTEST_DEVICE			"selowtest(ID=0000000001)"		// Local Bridge device name that does not exist

// Run state of the test
typedef struct SELOWTEST_CTX
{
	UINT NumChecks;					// Checks run so far
	UINT NumFailed;					// Checks failed so far
} SELOWTEST_CTX;

// Calls of the install step since the test last reset it
static UINT selowtest_num_install = 0;

// Install step stub: counts the call and installs nothing
static bool SelowTestInstallProc(bool force)
{
	selowtest_num_install++;

	return false;
}

// Record one check: print [PASS], or [FAIL] with the formatted detail
static bool SelowTestCheck(SELOWTEST_CTX *ctx, bool ok, char *what, char *detail_fmt, ...)
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

// Write an adapter list with the given signature and no adapters to path
static bool SelowTestWriteList(wchar_t *path, UINT signature)
{
	SL_ADAPTER_INFO_LIST *list = ZeroMalloc(sizeof(SL_ADAPTER_INFO_LIST));
	HANDLE h;
	DWORD size = 0;
	bool ret = false;

	list->Signature = signature;
	list->SeLowVersion = SELOWTEST_VERSION;
	list->EnumCompleted = 1;
	list->NumAdapters = 0;

	h = CreateFileW(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (h != INVALID_HANDLE_VALUE)
	{
		if (WriteFile(h, list, sizeof(SL_ADAPTER_INFO_LIST), &size, NULL) && size == sizeof(SL_ADAPTER_INFO_LIST))
		{
			ret = true;
		}

		CloseHandle(h);
	}

	Free(list);

	return ret;
}

// Open the existing file path for reading, or for writing only (so that ReadFile on it fails)
static HANDLE SelowTestOpen(wchar_t *path, bool read)
{
	return CreateFileW(path, read ? GENERIC_READ : GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
		OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
}

// True when h is still an open handle
static bool SelowTestIsOpen(HANDLE h)
{
	DWORD flags = 0;

	return (GetHandleInformation(h, &flags) != FALSE);
}

// Close a handle that SelowTestOpen returned
static void SelowTestClose(HANDLE h)
{
	if (h != INVALID_HANDLE_VALUE)
	{
		CloseHandle(h);
	}
}

// The adapter-list read and signature check, and the cleanup of SuGetAdapterList
static void SelowTestRead(SELOWTEST_CTX *ctx, wchar_t *path)
{
	SL_ADAPTER_INFO_LIST *list = ZeroMalloc(sizeof(SL_ADAPTER_INFO_LIST));
	SU *u = ZeroMalloc(sizeof(SU));
	HANDLE h;
	LIST *o;
	bool ok;

	// A list with SL_SIGNATURE: accepted by the helper and by SuGetAdapterList
	ok = SelowTestWriteList(path, SL_SIGNATURE);
	if (SelowTestCheck(ctx, ok, "Write an adapter list with SL_SIGNATURE", "failed"))
	{
		h = SelowTestOpen(path, true);
		ok = SuReadAdapterInfoList(h, list);
		SelowTestCheck(ctx, ok && list->SeLowVersion == SELOWTEST_VERSION, "SuReadAdapterInfoList accepts a list with SL_SIGNATURE",
			"returned %u, SeLowVersion %u", ok, list->SeLowVersion);
		SelowTestClose(h);

		h = SelowTestOpen(path, true);
		u->hFile = h;
		o = SuGetAdapterList(u);
		SelowTestCheck(ctx, o != NULL && LIST_NUM(o) == 0, "SuGetAdapterList returns an empty list for a list with SL_SIGNATURE and no adapters",
			"returned %s", o == NULL ? "NULL" : "a list with entries");
		SelowTestCheck(ctx, SelowTestIsOpen(h), "SuGetAdapterList leaves the device handle open after a read", "handle closed");
		SuFreeAdapterList(o);
		SelowTestClose(h);

		// A failed read (a handle opened for writing only) is refused even though the file has SL_SIGNATURE
		h = SelowTestOpen(path, false);
		ok = SuReadAdapterInfoList(h, list);
		SelowTestCheck(ctx, h != INVALID_HANDLE_VALUE && ok == false, "SuReadAdapterInfoList refuses a failed read",
			"open %s, returned %u", h != INVALID_HANDLE_VALUE ? "ok" : "failed", ok);
		SelowTestClose(h);
	}

	// A wrong signature: refused; SuGetAdapterList frees its list and leaves the device handle open
	ok = SelowTestWriteList(path, SELOWTEST_BAD_SIGNATURE);
	if (SelowTestCheck(ctx, ok, "Write an adapter list with a wrong signature", "failed"))
	{
		h = SelowTestOpen(path, true);
		ok = SuReadAdapterInfoList(h, list);
		SelowTestCheck(ctx, ok == false, "SuReadAdapterInfoList refuses a wrong signature", "returned true");
		SelowTestClose(h);

		h = SelowTestOpen(path, true);
		u->hFile = h;
		o = SuGetAdapterList(u);
		SelowTestCheck(ctx, o == NULL, "SuGetAdapterList returns NULL for a wrong signature", "returned a list");
		SelowTestCheck(ctx, SelowTestIsOpen(h), "SuGetAdapterList leaves the device handle open after a failed read", "handle closed");
		SuFreeAdapterList(o);
		SelowTestClose(h);
	}

	SelowTestCheck(ctx, SuReadAdapterInfoList(NULL, list) == false, "SuReadAdapterInfoList refuses the NULL handle", "returned true");

	DeleteFileW(path);

	Free(u);
	Free(list);
}

// Asking whether SeLow is supported: never reaches the install step and leaves the SeLow service
// as it was. Returns whether SeLow is usable on this machine
static bool SelowTestQuery(SELOWTEST_CTX *ctx)
{
	bool supported;
	bool running_before, running_after;

	running_before = MsIsServiceRunning(SL_PROTOCOL_NAME);

	supported = Win32EthIsSuSupported();
	Win32EthIsSuSupported();
	IsBridgeSupported();
	SuFree(SuInitEx(0));

	running_after = MsIsServiceRunning(SL_PROTOCOL_NAME);

	SelowTestCheck(ctx, selowtest_num_install == 0, "Asking whether SeLow is supported never reaches the driver install",
		"install step ran %u times", selowtest_num_install);
	SelowTestCheck(ctx, running_before == running_after, "Asking whether SeLow is supported leaves the SeLow service as it was",
		"running %u before, %u after", running_before, running_after);

	return supported;
}

// Creating a Local Bridge, and listing the devices for one, reach the install step when the
// SeLow device is missing
static void SelowTestInstall(SELOWTEST_CTX *ctx, bool supported)
{
	ETH *e;
	TOKEN_LIST *t;

	if (supported)
	{
		Print("  [SKIP] Install step: the SeLow device is present on this machine\n");
		return;
	}

	if (SuIsSupportedOs(false) == false)
	{
		Print("  [SKIP] Install step: SeLow is turned off by the DisableSeLow registry value\n");
		return;
	}

	if (MsIsServiceInstalled(SL_PROTOCOL_NAME))
	{
		Print("  [SKIP] Install step: the SeLow service is installed, so the install path would start it\n");
		return;
	}

	// The queries before did not use up the one install attempt of the process
	selowtest_num_install = 0;
	e = OpenEth(SELOWTEST_DEVICE, false, false, NULL);
	SelowTestCheck(ctx, e == NULL && selowtest_num_install == 1, "Creating a Local Bridge without SeLow reaches the driver install",
		"OpenEth returned %s, install step ran %u times", e == NULL ? "NULL" : "an ETH", selowtest_num_install);
	CloseEth(e);

	// As before, the install step runs at most once per process
	e = OpenEth(SELOWTEST_DEVICE, false, false, NULL);
	SelowTestCheck(ctx, e == NULL && selowtest_num_install == 1, "The driver install runs at most once per process",
		"OpenEth returned %s, install step ran %u times", e == NULL ? "NULL" : "an ETH", selowtest_num_install);
	CloseEth(e);

	// Listing the devices for a Local Bridge (EnumEthernet) is the first step of creating one
	SuSetInstallProc(SelowTestInstallProc);
	selowtest_num_install = 0;
	t = GetEthList();
	SelowTestCheck(ctx, t == NULL && selowtest_num_install == 1, "Listing the devices for a Local Bridge without SeLow reaches the driver install",
		"GetEthList returned %s, install step ran %u times", t == NULL ? "NULL" : "a list", selowtest_num_install);
	FreeToken(t);
}

// selow: read-only capability query, explicit driver install, one adapter-list read (FIX-2 #98)
void selow_test(UINT num, char **arg)
{
	SELOWTEST_CTX ctx;
	wchar_t dir[MAX_SIZE];
	wchar_t path[MAX_SIZE];
	bool supported;

	Zero(&ctx, sizeof(ctx));

	Print("SeLow test: read-only capability query, explicit driver install, one adapter-list read\n");

	GetExeDirW(dir, sizeof(dir));
	ConbinePathW(path, sizeof(path), dir, SELOWTEST_FILE_NAME);

	SelowTestRead(&ctx, path);

	// From here on the install step only counts
	SuSetInstallProc(SelowTestInstallProc);
	selowtest_num_install = 0;

	supported = SelowTestQuery(&ctx);
	SelowTestInstall(&ctx, supported);

	SuSetInstallProc(NULL);

	if (ctx.NumFailed == 0)
	{
		Print("SELOW TEST OK\n");
	}
	else
	{
		Print("SELOW TEST FAILED (%u of %u checks failed)\n", ctx.NumFailed, ctx.NumChecks);
	}
}
