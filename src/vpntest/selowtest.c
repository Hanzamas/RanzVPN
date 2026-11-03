// selowtest.c
// Named SeLow test of vpntest ("selow" command, FIX-2 #98)
//
// Pins the user-mode side of SeLow (SeLowUser.c):
// - Asking whether SeLow is usable (SuInitEx) never reaches the driver install step, leaves the
//   SeLow service as it was, and does not use up the one install attempt of the process.
// - SeLow is not usable where no SeLow driver package exists (any architecture but x64, such as
//   arm64): SuIsSupportedOs is false there, elevated or not.
// - The install path of SeLow (SuInitInstall) still reaches the install step when the SeLow device
//   is missing, at most once per process.
// - The adapter-list read (SuReadAdapterInfoList) accepts a list with SL_SIGNATURE and refuses a
//   wrong signature or a failed read. SuGetAdapterList frees its list on a failed read and leaves
//   the device handle open (SuFree closes it).
// - An interface is bridgeable by its type data (MsIsBridgeableIf), not by title words: a wired NIC
//   is whatever it is called, a tunnel, PPP, Wi-Fi or RAS WAN Miniport interface is not whatever
//   its localized title says.
// - The net-class table (MsNetClassEnum, one SetupAPI pass) agrees with the Class and Enum registry
//   keys for every present network adapter, and has at least one.
// The install step is replaced by a counting stub (SuSetInstallProc), so the test never installs a
// driver. The install checks run only on a machine without SeLow, such as the CI runners; elsewhere
// they are skipped. Prints "SELOW TEST OK" only when every check passes, and frees everything it
// allocates, so that the run still ends with "NO MEMORY LEAKS".

#include "testlist.h"

#include "Cedar/SeLowUser.h"

#include "Mayaqua/FileIO.h"
#include "Mayaqua/Memory.h"
#include "Mayaqua/Microsoft.h"
#include "Mayaqua/Str.h"

#include <stdarg.h>
#include <iphlpapi.h>

#define	SELOWTEST_FILE_NAME			L"selowtest_list.tmp"			// Adapter list file next to vpntest.exe
#define	SELOWTEST_VERSION			0x1234							// SeLowVersion written to the file
#define	SELOWTEST_BAD_SIGNATURE		0xDEADBEEE						// A signature that is not SL_SIGNATURE

// Run state of the test
typedef struct SELOWTEST_CTX
{
	UINT NumChecks;					// Checks run so far
	UINT NumFailed;					// Checks failed so far
} SELOWTEST_CTX;

// Calls of the install step since the test last reset it
static UINT selowtest_num_install = 0;

// Install step stub: counts the call and installs nothing
static bool SelowTestInstallProc()
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
		o = SuGetAdapterList(u, NULL);
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
		o = SuGetAdapterList(u, NULL);
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

// Asking whether SeLow is usable (SuInitEx opens the device and reads its adapter list): never
// reaches the install step and leaves the SeLow service as it was. Returns whether SeLow is usable
// on this machine
static bool SelowTestQuery(SELOWTEST_CTX *ctx)
{
	bool running_before = MsIsServiceRunning(SL_PROTOCOL_NAME);

	SU *su = SuInitEx(0);
	bool supported = (su != NULL);
	SuFree(su);
	SuFree(SuInitEx(0));

	bool running_after = MsIsServiceRunning(SL_PROTOCOL_NAME);

	SelowTestCheck(ctx, selowtest_num_install == 0, "Asking whether SeLow is supported never reaches the driver install",
		"install step ran %u times", selowtest_num_install);
	SelowTestCheck(ctx, running_before == running_after, "Asking whether SeLow is supported leaves the SeLow service as it was",
		"running %u before, %u after", running_before, running_after);

#if defined(_M_ARM64)
	// No SeLow driver package for this architecture (arm64): SeLow is not usable, even when elevated
	{
		bool os = SuIsSupportedOs();

		SelowTestCheck(ctx, os == false && supported == false,
			"SeLow is not usable where no SeLow driver package exists",
			"SuIsSupportedOs %u, SuInitEx %u", os, supported);
	}
#endif	// defined(_M_ARM64)

	return supported;
}

// The install path of SeLow (SuInitInstall) reaches the install step when the SeLow device is
// missing, at most once per process
static void SelowTestInstall(SELOWTEST_CTX *ctx, bool supported)
{
	SU *su;

	if (supported)
	{
		Print("  [SKIP] Install step: the SeLow device is present on this machine\n");
		return;
	}

	if (SuIsSupportedOs() == false)
	{
#if defined(_M_ARM64)
		// No SeLow package exists for arm64: even the install path never reaches the install step
		selowtest_num_install = 0;
		su = SuInitInstall();
		SelowTestCheck(ctx, su == NULL && selowtest_num_install == 0, "On arm64, the install path of SeLow never reaches the driver install",
			"SuInitInstall returned %s, install step ran %u times", su == NULL ? "NULL" : "an SU", selowtest_num_install);
		SuFree(su);
#endif	// defined(_M_ARM64)
		Print("  [SKIP] Install step: SeLow is not supported (arm64, or the DisableSeLow registry value)\n");
		return;
	}

	if (MsIsServiceInstalled(SL_PROTOCOL_NAME))
	{
		Print("  [SKIP] Install step: the SeLow service is installed, so the install path would start it\n");
		return;
	}

	// The queries before did not use up the one install attempt of the process
	selowtest_num_install = 0;
	su = SuInitInstall();
	SelowTestCheck(ctx, su == NULL && selowtest_num_install == 1, "The install path of SeLow without its device reaches the driver install",
		"SuInitInstall returned %s, install step ran %u times", su == NULL ? "NULL" : "an SU", selowtest_num_install);
	SuFree(su);

	// As before, the install step runs at most once per process
	su = SuInitInstall();
	SelowTestCheck(ctx, su == NULL && selowtest_num_install == 1, "The driver install runs at most once per process",
		"SuInitInstall returned %s, install step ran %u times", su == NULL ? "NULL" : "an SU", selowtest_num_install);
	SuFree(su);
}

// Which interfaces are bridgeable (FND-182)
static void SelowTestClass(SELOWTEST_CTX *ctx)
{
	SelowTestCheck(ctx, MsIsBridgeableIf(IF_TYPE_ETHERNET_CSMACD, NdisMedium802_3, NdisPhysicalMedium802_3, true),
		"A wired NIC is listed, whatever its title (such as \"WAN port\")", "hidden");
	SelowTestCheck(ctx, MsIsBridgeableIf(IF_TYPE_ETHERNET_CSMACD, NdisMedium802_3, NdisPhysicalMediumUnspecified, true),
		"A NIC that does not report its physical medium is listed", "hidden");
	SelowTestCheck(ctx, MsIsBridgeableIf(IF_TYPE_TUNNEL, NdisMedium802_3, NdisPhysicalMediumUnspecified, false) == false,
		"A tunnel is hidden, whatever its localized title", "listed");
	SelowTestCheck(ctx, MsIsBridgeableIf(IF_TYPE_PPP, NdisMediumWan, NdisPhysicalMediumUnspecified, false) == false,
		"A PPP interface is hidden", "listed");
	SelowTestCheck(ctx, MsIsBridgeableIf(IF_TYPE_IEEE80211, NdisMedium802_3, NdisPhysicalMediumNative802_11, true) == false,
		"A Wi-Fi NIC is hidden", "listed");
	SelowTestCheck(ctx, MsIsBridgeableIf(IF_TYPE_ETHERNET_CSMACD, NdisMedium802_3, NdisPhysicalMediumUnspecified, false) == false,
		"A software interface without a physical medium (WAN Miniport) is hidden", "listed");
}

// The net-class table (MsNetClassEnum, FND-174): one SetupAPI pass over the
// present network adapters. Every entry agrees with the registry that the former lookup walked: its
// Class key holds its NetCfgInstanceId, and the Enum key of its device instance id names the same
// driver key. Every runner has at least one present network adapter
static void SelowTestNetClass(SELOWTEST_CTX *ctx)
{
	LIST *o = MsNetClassEnum();
	UINT num_ok = 0;

	for (UINT i = 0;i < LIST_NUM(o);i++)
	{
		MS_NETCLASS_DEVICE *d = LIST_DATA(o, i);
		char enum_key[MAX_SIZE];

		Format(enum_key, sizeof(enum_key), "SYSTEM\\CurrentControlSet\\Enum\\%s", d->DeviceInstanceId);

		char *guid = MsRegReadStr(REG_LOCAL_MACHINE, d->ClassKey, "NetCfgInstanceId");
		char *driver = MsRegReadStr(REG_LOCAL_MACHINE, enum_key, "Driver");

		if (StrCmpi(guid, d->Guid) == 0 && StrCmpi(driver, d->ShortKey) == 0)
		{
			num_ok++;
		}
		else
		{
			Print("  [INFO] %s: NetCfgInstanceId %s under %s, Driver %s under %s\n",
				d->Guid, guid == NULL ? "(none)" : guid, d->ClassKey, driver == NULL ? "(none)" : driver, enum_key);
		}

		Free(guid);
		Free(driver);
	}

	SelowTestCheck(ctx, LIST_NUM(o) != 0 && num_ok == LIST_NUM(o),
		"Net-class table: every present network adapter has its Class key, driver key and device instance id",
		"%u of %u devices agree with the registry", num_ok, LIST_NUM(o));

	MsNetClassFree(o);
}

// selow: read-only capability query, explicit driver install, one adapter-list read (FIX-2 #98)
RANZ_TEST("selow", selow_test, "SeLow: the capability query installs nothing, the install path reaches the driver install, one adapter-list read.");
void selow_test(UINT num, char **arg)
{
	SELOWTEST_CTX ctx;
	wchar_t dir[MAX_SIZE];
	wchar_t path[MAX_SIZE];

	Zero(&ctx, sizeof(ctx));

	Print("SeLow test: read-only capability query, explicit driver install, one adapter-list read\n");

	GetExeDirW(dir, sizeof(dir));
	ConbinePathW(path, sizeof(path), dir, SELOWTEST_FILE_NAME);

	SelowTestRead(&ctx, path);
	SelowTestClass(&ctx);
	SelowTestNetClass(&ctx);

	// From here on the install step only counts
	SuSetInstallProc(SelowTestInstallProc);
	selowtest_num_install = 0;

	bool supported = SelowTestQuery(&ctx);
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
