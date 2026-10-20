// SeLow: SoftEther Lightweight Network Protocol


// SeLowUser.c
// SoftEther Lightweight Network Protocol User-mode Library


#include "SeLowUser.h"

#include "Cedar.h"
#include "Win32Com.h"

#include "Mayaqua/Cfg.h"
#include "Mayaqua/Encrypt.h"
#include "Mayaqua/FileIO.h"
#include "Mayaqua/Internat.h"
#include "Mayaqua/Microsoft.h"
#include "Mayaqua/Memory.h"
#include "Mayaqua/Str.h"
#include "Mayaqua/Tick64.h"

#include <SetupAPI.h>
#include <sddl.h>
#include <winioctl.h>

static SU *SuInitMain(UINT wait_for_bind_complete_tick, bool start_service, bool install);
static bool SuInstallDriver();

// True if the published INF oem_name (an oemNN.inf in %windir%\inf) is a copy
// of a SoftEther SeLow INF: its original name starts with "selow" and its
// provider contains "softether"
static bool SuIsSeLowOemInf(wchar_t *oem_name)
{
	HINF inf;
	SP_INF_INFORMATION *info;
	SP_ORIGINAL_FILE_INFO_W original;
	INFCONTEXT ctx;
	wchar_t provider[MAX_SIZE];
	DWORD info_size = 0;
	bool ret = false;

	inf = SetupOpenInfFileW(oem_name, NULL, INF_STYLE_WIN4, NULL);
	if (inf == INVALID_HANDLE_VALUE)
	{
		return false;
	}

	if (SetupGetInfInformationW(inf, INFINFO_INF_SPEC_IS_HINF, NULL, 0, &info_size) && info_size != 0)
	{
		info = ZeroMalloc(info_size);

		Zero(&original, sizeof(original));
		original.cbSize = sizeof(original);

		if (SetupGetInfInformationW(inf, INFINFO_INF_SPEC_IS_HINF, info, info_size, NULL) &&
			SetupQueryInfOriginalFileInformationW(info, 0, NULL, &original) &&
			UniStartWith(original.OriginalInfName, L"selow") &&
			SetupFindFirstLineW(inf, L"Version", L"Provider", &ctx) &&
			SetupGetStringFieldW(&ctx, 1, provider, sizeof(provider) / sizeof(wchar_t), NULL) &&
			UniSearchStrEx(provider, L"softether", 0, false) != INFINITE)
		{
			ret = true;
		}

		Free(info);
	}

	SetupCloseInfFile(inf);

	return ret;
}

// Remove the stale oemNN.inf copies of SeLow from the driver store
static void SuDeleteGarbageInfs()
{
	wchar_t *list;
	wchar_t *name;
	DWORD list_size = 0;

	if (SetupGetInfFileListW(NULL, INF_STYLE_WIN4, NULL, 0, &list_size) && list_size != 0)
	{
		list = ZeroMalloc(list_size * sizeof(wchar_t));

		if (SetupGetInfFileListW(NULL, INF_STYLE_WIN4, list, list_size, NULL))
		{
			for (name = list; name < list + list_size && *name != 0; name += UniStrLen(name) + 1)
			{
				if (UniStartWith(name, L"oem") && SuIsSeLowOemInf(name))
				{
					BOOL deleted;

					deleted = SetupUninstallOEMInfW(name, SUOI_FORCEDELETE, NULL);

					Debug("Delete OEM INF %S: %u\n", name, deleted);
				}
			}
		}

		Free(list);
	}
}

// Driver install step: SuInstallDriver, or the stub that a test sets with SuSetInstallProc
static SU_INSTALL_PROC *su_install_proc = SuInstallDriver;
// Nonzero once the install step ran in this process: it runs at most once per process, also
// after a failed install. Local Bridge session threads and the RPC threads race on it, so it is
// taken only with InterlockedCompareExchange
static volatile LONG su_install_tried = 0;

// Test seam (vpntest selow): replace the driver install step with proc; NULL restores
// SuInstallDriver. Also forgets an earlier install attempt, so the next one runs the step again
void SuSetInstallProc(SU_INSTALL_PROC *proc)
{
	su_install_proc = (proc != NULL ? proc : SuInstallDriver);
	InterlockedExchange(&su_install_tried, 0);
}

// Remove a staging directory made by SuStageDriverPackage and everything in it
void SuUnstageDriverPackage(wchar_t *dir)
{
	if (UniIsEmptyStr(dir))
	{
		return;
	}

	MsDeleteAllFileW(dir);

	if (RemoveDirectoryW(dir) == FALSE)
	{
		Debug("SuUnstageDriverPackage: RemoveDirectoryW(%S) failed: %u\n", dir, (UINT)GetLastError());
	}
}

// Stage the driver package for one install attempt: make a new directory with a random name under
// %WINDIR%\Temp that only SYSTEM and Administrators can open, and copy the package files into it.
// CreateDirectoryW fails on a name that exists, so nothing is ever written through a directory or
// junction that someone else planted there. dir receives the path. On failure nothing stays behind
bool SuStageDriverPackage(wchar_t *dir, UINT dir_size)
{
	wchar_t *files[] = {SU_PACKAGE_SYS, SU_PACKAGE_CAT, SU_PACKAGE_INF};
	wchar_t temp_dir[MAX_PATH];
	wchar_t name[SU_STAGE_RANDOM_SIZE * 2 + 1];
	UCHAR random[SU_STAGE_RANDOM_SIZE];
	SECURITY_ATTRIBUTES sa;
	PSECURITY_DESCRIPTOR sd = NULL;
	bool created = false;
	UINT err = 0;
	UINT i;

	if (dir == NULL || dir_size == 0)
	{
		return false;
	}

	dir[0] = 0;

	if (ConvertStringSecurityDescriptorToSecurityDescriptorW(SU_STAGE_DIR_SDDL, SDDL_REVISION_1, &sd, NULL) == FALSE)
	{
		Debug("SuStageDriverPackage: ConvertStringSecurityDescriptorToSecurityDescriptorW failed: %u\n", (UINT)GetLastError());
		return false;
	}

	Zero(&sa, sizeof(sa));
	sa.nLength = sizeof(sa);
	sa.lpSecurityDescriptor = sd;
	sa.bInheritHandle = FALSE;

	CombinePathW(temp_dir, sizeof(temp_dir), MsGetWindowsDirW(), L"Temp");

	for (i = 0;i < SU_STAGE_MAX_TRIES;i++)
	{
		Rand(random, sizeof(random));
		BinToStrW(name, sizeof(name), random, sizeof(random));
		UniFormat(dir, dir_size, L"%s\\selow_%s", temp_dir, name);

		if (CreateDirectoryW(dir, &sa))
		{
			created = true;
			break;
		}

		// Only a name clash is worth another name
		err = GetLastError();
		if (err != ERROR_ALREADY_EXISTS)
		{
			break;
		}
	}

	LocalFree(sd);

	if (created == false)
	{
		Debug("SuStageDriverPackage: CreateDirectoryW(%S) failed: %u\n", dir, err);
		dir[0] = 0;
		return false;
	}

	for (i = 0;i < sizeof(files) / sizeof(files[0]);i++)
	{
		wchar_t src[MAX_PATH];
		wchar_t dst[MAX_PATH];

		UniFormat(src, sizeof(src), L"%s\\%s", SU_PACKAGE_DIR, files[i]);
		UniFormat(dst, sizeof(dst), L"%s\\%s", dir, files[i]);

		if (FileCopyW(src, dst) == false)
		{
			Debug("SuStageDriverPackage: FileCopyW(%S, %S) failed\n", src, dst);
			SuUnstageDriverPackage(dir);
			dir[0] = 0;
			return false;
		}
	}

	return true;
}

static bool SuInstallDriver()
{
	wchar_t sys_fullpath[MAX_PATH];
	bool ret = false;
	wchar_t *src_sys = SU_PACKAGE_DIR L"\\" SU_PACKAGE_SYS;
	wchar_t stage_dir[MAX_PATH];
	wchar_t dst_inf[MAX_PATH];

	if (SuIsSupportedOs() == false)
	{
		return false;
	}

	// Where the installed driver lives; SuCopySysFile also copies it there by hand
	CombinePathW(sys_fullpath, sizeof(sys_fullpath), MsGetSystem32DirW(), L"drivers\\" SU_PACKAGE_SYS);

	if (SuStageDriverPackage(stage_dir, sizeof(stage_dir)))
	{
		UniFormat(dst_inf, sizeof(dst_inf), L"%s\\%s", stage_dir, SU_PACKAGE_INF);

		SuDeleteGarbageInfs();

		if (InstallNdisProtocolDriver(dst_inf))
		{
			// Also copy by hand: the installer sometimes fails to copy the .sys file
			bool copied = SuCopySysFile(src_sys, sys_fullpath);

			Debug("SuCopySysFile from %S to %S: ret = %u\n", src_sys, sys_fullpath, copied);

			ret = true;

			MsRegWriteIntEx2(REG_LOCAL_MACHINE, SL_REG_KEY_NAME, "Start", SERVICE_SYSTEM_START, false);
		}

		// The driver store holds its own copy now: the staged one is no longer needed
		SuUnstageDriverPackage(stage_dir);
	}

	// Wait for the new driver to bind: it may start the service, it never installs again
	if (ret)
	{
		SuFree(SuInitMain(180 * 1000, true, false));
	}

	return ret;
}

bool SuCopySysFile(wchar_t *src, wchar_t *dst)
{
	wchar_t dst_rename[MAX_PATH];
	UINT i;
	if (src == NULL || dst == NULL)
	{
		return false;
	}
	if (FileCopyW(src, dst))
	{
		for (i = 1;i <= 100;i++)
		{
			UniFormat(dst_rename, sizeof(dst_rename), L"%s.old%u", dst, i);

			FileDeleteW(dst_rename);
		}

		return true;
	}

	for (i = 1;;i++)
	{
		UniFormat(dst_rename, sizeof(dst_rename), L"%s.old%u", dst, i);

		if (IsFileExistsW(dst_rename) == false)
		{
			break;
		}

		if (i >= 100)
		{
			return false;
		}
	}

	if (MoveFileW(dst, dst_rename) == false)
	{
		return false;
	}

	if (FileCopyW(src, dst))
	{
		for (i = 1;i <= 100;i++)
		{
			UniFormat(dst_rename, sizeof(dst_rename), L"%s.old%u", dst, i);

			FileDeleteW(dst_rename);
		}

		return true;
	}

	MoveFileW(dst_rename, dst);

	return false;
}

// SeLow is usable on this build and machine. Only an x64 driver package exists (hamcore
// DriverPackages\SeLow_Win10\x64), so on arm64 it never is: no service start, no staging and no
// install is tried there
bool SuIsSupportedOs()
{
#if defined(_M_ARM64)
	return false;
#else	// defined(_M_ARM64)
	if (MsRegReadIntEx2(REG_LOCAL_MACHINE, SL_REG_KEY_NAME, "EnableSeLow", false) != 0)
	{
		return true;
	}

	if (MsRegReadIntEx2(REG_LOCAL_MACHINE, SL_REG_KEY_NAME, "DisableSeLow", false) != 0)
	{
		return false;
	}

	return true;
#endif	// defined(_M_ARM64)
}

bool SuPutPacket(SU_ADAPTER *a, void *buf, UINT size)
{
	if (a == NULL)
	{
		return false;
	}
	if (a->Halt)
	{
		return false;
	}
	if (size > MAX_PACKET_SIZE)
	{
		return false;
	}

	if ((SL_NUM_PACKET(a->PutBuffer) >= SL_MAX_PACKET_EXCHANGE) ||
		(buf == NULL && SL_NUM_PACKET(a->PutBuffer) != 0))
	{
		if (SuPutPacketsToDriver(a) == false)
		{
			return false;
		}

		SL_NUM_PACKET(a->PutBuffer) = 0;
	}

	if (buf != NULL)
	{
		UINT i = SL_NUM_PACKET(a->PutBuffer);
		SL_NUM_PACKET(a->PutBuffer)++;

		SL_SIZE_OF_PACKET(a->PutBuffer, i) = size;
		Copy(SL_ADDR_OF_PACKET(a->PutBuffer, i), buf, size);

		Free(buf);
	}

	return true;
}

bool SuPutPacketsToDriver(SU_ADAPTER *a)
{
	DWORD write_size;
	if (a == NULL)
	{
		return false;
	}
	if (a->Halt)
	{
		return false;
	}

	if (WriteFile(a->hFile, a->PutBuffer, SL_EXCHANGE_BUFFER_SIZE, &write_size, NULL) == false)
	{
		a->Halt = true;
		return false;
	}

	if (write_size != SL_EXCHANGE_BUFFER_SIZE)
	{
		a->Halt = true;
		return false;
	}

	return true;
}

bool SuGetNextPacket(SU_ADAPTER *a, void **buf, UINT *size)
{
	if (a == NULL || buf == NULL || size == NULL)
	{
		return false;
	}

	if (a->Halt)
	{
		return false;
	}

	while (true)
	{
		if (a->CurrentPacketCount < SL_NUM_PACKET(a->GetBuffer))
		{
			*size = SL_SIZE_OF_PACKET(a->GetBuffer, a->CurrentPacketCount);
			*buf = Malloc(*size);
			Copy(*buf, SL_ADDR_OF_PACKET(a->GetBuffer, a->CurrentPacketCount), *size);

			a->CurrentPacketCount++;
			a->LastGetHadPacket = true;

			return true;
		}
		else
		{
			// The driver sets the event when it queues a frame and resets it when
			// a read empties its queue, so at the end of a drain an unsignalled
			// event means a read would return no frames. The driver resets the
			// event after it drops its queue lock, so a frame queued in that gap
			// leaves the event unsignalled: the first call of the next drain
			// always reads.
			if (a->LastGetHadPacket && WaitForSingleObject(a->hEvent, 0) == WAIT_TIMEOUT)
			{
				a->LastGetHadPacket = false;
				*buf = NULL;
				*size = 0;
				return true;
			}

			if (SuGetPacketsFromDriver(a) == false)
			{
				return false;
			}

			if (SL_NUM_PACKET(a->GetBuffer) == 0)
			{
				a->LastGetHadPacket = false;
				*buf = NULL;
				*size = 0;
				return true;
			}

			a->CurrentPacketCount = 0;
		}
	}
}

// Frames already read from the driver but not yet taken by SuGetNextPacket.
// The driver event does not signal them.
bool SuHasPendingPackets(SU_ADAPTER *a)
{
	if (a == NULL || a->Halt)
	{
		return false;
	}

	return a->CurrentPacketCount < SL_NUM_PACKET(a->GetBuffer);
}

bool SuGetPacketsFromDriver(SU_ADAPTER *a)
{
	DWORD read_size;
	if (a == NULL)
	{
		return false;
	}

	if (a->Halt)
	{
		return false;
	}

	if (ReadFile(a->hFile, a->GetBuffer, SL_EXCHANGE_BUFFER_SIZE, &read_size, NULL) == false)
	{
		a->Halt = true;
		return false;
	}

	if (read_size != SL_EXCHANGE_BUFFER_SIZE)
	{
		a->Halt = true;
		return false;
	}

	return true;
}

void SuCloseAdapter(SU_ADAPTER *a)
{
	if (a == NULL)
	{
		return;
	}

	if (a->hEvent != NULL)
	{
		CloseHandle(a->hEvent);
	}

	if (a->hFile != INVALID_HANDLE_VALUE)
	{
		CloseHandle(a->hFile);
		a->hFile = INVALID_HANDLE_VALUE;
	}

	Free(a);
}

SU_ADAPTER *SuOpenAdapter(char *adapter_id)
{
	char filename[MAX_PATH];
	void *h;
	SU_ADAPTER *a;
	SL_IOCTL_EVENT_NAME t;
	DWORD read_size;
	if (adapter_id == NULL)
	{
		return NULL;
	}

	Format(filename, sizeof(filename), SL_ADAPTER_DEVICE_FILENAME_WIN32, adapter_id);

	h = CreateFileA(filename, GENERIC_READ | GENERIC_WRITE,
		FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);

	if (h == INVALID_HANDLE_VALUE)
	{
		return NULL;
	}

	a = ZeroMalloc(sizeof(SU_ADAPTER));

	a->hFile = h;

	Zero(&t, sizeof(t));

	if (DeviceIoControl(h, SL_IOCTL_GET_EVENT_NAME, &t, sizeof(t), &t, sizeof(t), &read_size, NULL) == false)
	{
		SuCloseAdapter(a);
		return NULL;
	}

	a->hEvent = OpenEvent(EVENT_ALL_ACCESS, FALSE, t.EventNameWin32);

	if (a->hEvent == NULL)
	{
		SuCloseAdapter(a);
		return NULL;
	}

	return a;
}

// Read the adapter list from the SeLow basic device h into list and check its signature. This is
// the only copy of that read; each caller keeps its own cleanup when it fails
bool SuReadAdapterInfoList(void *h, SL_ADAPTER_INFO_LIST *list)
{
	DWORD read_size;
	if (h == NULL || list == NULL)
	{
		return false;
	}

	if (ReadFile(h, list, sizeof(SL_ADAPTER_INFO_LIST), &read_size, NULL) == false)
	{
		return false;
	}

	return (list->Signature == SL_SIGNATURE);
}

// The adapters of the SeLow device u. netclass: the net-class table of the caller (MsNetClassEnum),
// which gives the Class key of each adapter and the DriverDesc fallback of its name; an adapter
// that is not a present device of the network class is left out
LIST *SuGetAdapterList(SU *u, LIST *netclass)
{
	LIST *ret;
	UINT i;
	if (u == NULL)
	{
		return NULL;
	}

	ret = NewList(SuCmpAdapterList);

	// On a failed read, free the list; the device handle stays open (SuFree closes it)
	Zero(&u->AdapterInfoList, sizeof(u->AdapterInfoList));
	if (SuReadAdapterInfoList(u->hFile, &u->AdapterInfoList) == false)
	{
		SuFreeAdapterList(ret);
		return NULL;
	}

	for (i = 0;i < u->AdapterInfoList.NumAdapters;i++)
	{
		SL_ADAPTER_INFO *info = &u->AdapterInfoList.Adapters[i];

		if (IsEmptyStr(info->FriendlyName))
		{
			// Some NetAdapterCx drivers do not report FriendlyName in kernel mode,
			// so fall back to DriverDesc from the NetCfg registry key.
			char adapter_guid[MAX_PATH] = {0};
			MS_NETCLASS_DEVICE *d;

			UniToStr(adapter_guid, sizeof(adapter_guid), info->AdapterId + StrLen(SL_ADAPTER_ID_PREFIX));

			d = MsNetClassFind(netclass, adapter_guid);
			if (d != NULL)
			{
				char *driver_desc = MsRegReadStrEx2(REG_LOCAL_MACHINE, d->ClassKey, "DriverDesc", false);

				if (driver_desc != NULL)
				{
					StrCpy(info->FriendlyName, sizeof(info->FriendlyName), driver_desc);
					Free(driver_desc);
				}
			}
		}

		{
			SU_ADAPTER_LIST *a = SuAdapterInfoToAdapterList(info, netclass);

			if (a != NULL)
			{
				Add(ret, a);
			}
		}
	}

	Sort(ret);

	return ret;
}

int SuCmpAdapterList(void *p1, void *p2)
{
	int r;
	SU_ADAPTER_LIST *a1, *a2;
	if (p1 == NULL || p2 == NULL)
	{
		return 0;
	}
	a1 = *(SU_ADAPTER_LIST **)p1;
	a2 = *(SU_ADAPTER_LIST **)p2;
	if (a1 == NULL || a2 == NULL)
	{
		return 0;
	}

	r = StrCmpi(a1->SortKey, a2->SortKey);
	if (r != 0)
	{
		return 0;
	}

	return StrCmpi(a1->Guid, a2->Guid);
}

void SuFreeAdapterList(LIST *o)
{
	UINT i;
	if (o == NULL)
	{
		return;
	}

	for (i = 0;i < LIST_NUM(o);i++)
	{
		SU_ADAPTER_LIST *a = LIST_DATA(o, i);

		Free(a);
	}

	ReleaseList(o);
}

SU_ADAPTER_LIST *SuAdapterInfoToAdapterList(SL_ADAPTER_INFO *info, LIST *netclass)
{
	SU_ADAPTER_LIST t;
	char tmp[MAX_SIZE];
	MS_NETCLASS_DEVICE *d;
	if (info == NULL)
	{
		return NULL;
	}

	Zero(&t, sizeof(t));
	StrCpy(t.FriendlyName, sizeof(t.FriendlyName), info->FriendlyName);
	Copy(t.MacAddress, info->MacAddress, sizeof(t.MacAddress));

	UniToStr(tmp, sizeof(tmp), info->AdapterId);
	// List the NIC in Local Bridge settings even when its FriendlyName is empty.
	if (IsEmptyStr(tmp) || /* IsEmptyStr(info->FriendlyName) || */ StartWith(tmp, SL_ADAPTER_ID_PREFIX) == false)
	{
		return NULL;
	}

	StrCpy(t.Guid, sizeof(t.Guid), tmp + StrLen(SL_ADAPTER_ID_PREFIX));

	StrCpy(t.Name, sizeof(t.Name), tmp);

	d = MsNetClassFind(netclass, t.Guid);
	if (d == NULL)
	{
		return NULL;
	}

	StrCpy(t.SortKey, sizeof(t.SortKey), d->ClassKey);

	return Clone(&t, sizeof(t));
}

// Open the SeLow basic device and read its adapter list. Read-only: never starts the SeLow service
// or installs the driver, so asking whether SeLow is supported changes nothing (FIX-2 #98)
SU *SuInitEx(UINT wait_for_bind_complete_tick)
{
	return SuInitMain(wait_for_bind_complete_tick, false, false);
}

// Like SuInitEx, but when the device is missing, start the SeLow service and, when that fails,
// install the driver (at most once per process). Only for creating a Local Bridge or for an
// explicit admin action
SU *SuInitInstall()
{
	return SuInitMain(0, true, true);
}

// Open the SeLow basic device and read its adapter list. When the device is missing: with
// start_service, start the SeLow service once and try again; when that start fails, with install,
// run the driver install step (at most once per process) and try again
static SU *SuInitMain(UINT wait_for_bind_complete_tick, bool start_service, bool install)
{
	void *h;
	SU *u;
	bool flag = false;
	UINT64 giveup_tick = 0;

	if (SuIsSupportedOs() == false)
	{
		return NULL;
	}

LABEL_RETRY:

	h = CreateFileA(SL_BASIC_DEVICE_FILENAME_WIN32, GENERIC_READ | GENERIC_WRITE,
		FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);

	if (h == INVALID_HANDLE_VALUE)
	{
		if (start_service && flag == false)
		{
			if (MsStartService(SL_PROTOCOL_NAME) == false)
			{
				// Exactly one caller per process wins the latch and runs the install step
				if (install && InterlockedCompareExchange(&su_install_tried, 1, 0) == 0)
				{
					if (su_install_proc())
					{
						goto LABEL_RETRY;
					}
				}
			}
			else
			{
				flag = true;

				goto LABEL_RETRY;
			}
		}
		return NULL;
	}


	u = ZeroMalloc(sizeof(SU));

	giveup_tick = Tick64() + (UINT64)wait_for_bind_complete_tick;

	// On a failed read, free the SU and close the device handle
	if (wait_for_bind_complete_tick == 0)
	{
		if (SuReadAdapterInfoList(h, &u->AdapterInfoList) == false)
		{

			Free(u);
			CloseHandle(h);

			return NULL;
		}
	}
	else
	{
		while (giveup_tick >= Tick64())
		{
			if (SuReadAdapterInfoList(h, &u->AdapterInfoList) == false)
			{

				Free(u);
				CloseHandle(h);

				return NULL;
			}

			if (u->AdapterInfoList.EnumCompleted)
			{
				break;
			}

			SleepThread(25);
		}
	}

	u->hFile = h;

	return u;
}

void SuFree(SU *u)
{
	if (u == NULL)
	{
		return;
	}

	CloseHandle(u->hFile);

	Free(u);
}


