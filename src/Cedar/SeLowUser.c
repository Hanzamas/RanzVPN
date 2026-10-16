// SeLow: SoftEther Lightweight Network Protocol


// SeLowUser.c
// SoftEther Lightweight Network Protocol User-mode Library


#include "SeLowUser.h"

#include "BridgeWin32.h"
#include "Win32Com.h"

#include "Mayaqua/Cfg.h"
#include "Mayaqua/FileIO.h"
#include "Mayaqua/Internat.h"
#include "Mayaqua/Microsoft.h"
#include "Mayaqua/Memory.h"
#include "Mayaqua/Str.h"
#include "Mayaqua/Tick64.h"

#include <winioctl.h>

static bool SuLoadDriversHive()
{
	wchar_t config_dir[MAX_PATH];
	wchar_t filename[MAX_PATH];

	MsEnablePrivilege(SE_RESTORE_NAME, true);
	MsEnablePrivilege(SE_BACKUP_NAME, true);

	CombinePathW(config_dir, sizeof(config_dir), MsGetSystem32DirW(), L"config");
	CombinePathW(filename, sizeof(filename), config_dir, L"DRIVERS");

	return MsRegLoadHive(REG_LOCAL_MACHINE, L"DRIVERS", filename);
}

static void SuDeleteGarbageInfs()
{
	void *wow;
	bool load_hive = false;

	wow = MsDisableWow64FileSystemRedirection();

	load_hive = SuLoadDriversHive();

	SuDeleteGarbageInfsInner();

	MsRestoreWow64FileSystemRedirection(wow);
}
void SuDeleteGarbageInfsInner()
{
	char *base_key_name = "DRIVERS\\DriverDatabase\\DriverPackages";
	TOKEN_LIST *keys;
	HINSTANCE hSetupApiDll = NULL;
	BOOL (WINAPI *_SetupUninstallOEMInfA)(PCSTR, DWORD, PVOID) = NULL;

	hSetupApiDll = LoadLibraryA("setupapi.dll");
	if (hSetupApiDll == NULL)
	{
		return;
	}

    #pragma clang diagnostic push
    #pragma clang diagnostic ignored "-Wincompatible-function-pointer-types"
	_SetupUninstallOEMInfA =
		(UINT (__stdcall *)(PCSTR,DWORD,PVOID))
		GetProcAddress(hSetupApiDll, "SetupUninstallOEMInfA");
    #pragma clang diagnostic pop

	if (_SetupUninstallOEMInfA != NULL)
	{
		keys = MsRegEnumKeyEx2(REG_LOCAL_MACHINE, base_key_name, false, true);

		if (keys != NULL)
		{
			char full_key[MAX_PATH];
			UINT i;

			for (i = 0;i < keys->NumTokens;i++)
			{
				char *oem_name, *inf_name, *provider;

				Format(full_key, sizeof(full_key), "%s\\%s", base_key_name, keys->Token[i]);

				oem_name = MsRegReadStrEx2(REG_LOCAL_MACHINE, full_key, "", false, true);
				inf_name = MsRegReadStrEx2(REG_LOCAL_MACHINE, full_key, "InfName", false, true);
				provider = MsRegReadStrEx2(REG_LOCAL_MACHINE, full_key, "Provider", false, true);

				if (IsEmptyStr(oem_name) == false && IsEmptyStr(inf_name) == false)
				{
					if (StartWith(oem_name, "oem"))
					{
						if (StartWith(inf_name, "selow"))
						{
							if (InStr(provider, "softether"))
							{
								Debug("Delete OEM INF %s (%s): %u\n",
									oem_name, inf_name,
									_SetupUninstallOEMInfA(oem_name, 0x00000001, NULL));
							}
						}
					}
				}

				Free(oem_name);
				Free(inf_name);
				Free(provider);
			}

			FreeToken(keys);
		}
	}

	if (hSetupApiDll != NULL)
	{
		FreeLibrary(hSetupApiDll);
	}
}

static bool SuInstallDriver(bool force)
{
	bool ret;
	void *wow;

	wow = MsDisableWow64FileSystemRedirection();

	ret = SuInstallDriverInner(force);

	MsRestoreWow64FileSystemRedirection(wow);

	return ret;
}

// Driver install step: SuInstallDriver, or the stub that a test sets with SuSetInstallProc
static SU_INSTALL_PROC *su_install_proc = SuInstallDriver;
// The install step already ran in this process: it runs at most once per process
static bool su_install_tried = false;

// Test seam (vpntest selow): replace the driver install step with proc; NULL restores
// SuInstallDriver. Also forgets an earlier install attempt, so the next one runs the step again
void SuSetInstallProc(SU_INSTALL_PROC *proc)
{
	su_install_proc = (proc != NULL ? proc : SuInstallDriver);
	su_install_tried = false;
}

bool SuInstallDriverInner(bool force)
{
	wchar_t sys_fullpath[MAX_PATH];
	UINT current_sl_ver = 0;
	bool ret = false;
	wchar_t src_cat[MAX_PATH];
	wchar_t src_inf[MAX_PATH];
	wchar_t src_sys[MAX_PATH];
	wchar_t dst_cat[MAX_PATH];
	wchar_t dst_inf[MAX_PATH];
	wchar_t dst_sys[MAX_PATH];
	wchar_t tmp_dir[MAX_PATH];
	char *cpu_type = MsIsX64() ? "x64" : "x86";

	if (SuIsSupportedOs(true) == false)
	{
		return false;
	}

	CombinePathW(tmp_dir, sizeof(tmp_dir), MsGetWindowsDirW(), L"Temp");
	MakeDirExW(tmp_dir);

	UniStrCat(tmp_dir, sizeof(tmp_dir), L"\\selowtmp");
	MakeDirExW(tmp_dir);

	CombinePathW(sys_fullpath, sizeof(sys_fullpath), MsGetSystem32DirW(), L"drivers\\SeLow_%S.sys");
	UniFormat(sys_fullpath, sizeof(sys_fullpath), sys_fullpath, cpu_type);

	if (IsFileExistsW(sys_fullpath))
	{
		char *path;

		current_sl_ver = MsRegReadIntEx2(REG_LOCAL_MACHINE, SL_REG_KEY_NAME,
			SL_REG_VER_VALUE_WIN10,
			false, true);

		path = MsRegReadStrEx2(REG_LOCAL_MACHINE, SL_REG_KEY_NAME, "ImagePath", false, true);

		if (IsEmptyStr(path) || IsFileExists(path) == false || MsIsServiceInstalled(SL_PROTOCOL_NAME) == false)
		{
			current_sl_ver = 0;
		}

		Free(path);
	}

	if (force == false && current_sl_ver >= SL_VER)
	{
		return true;
	}

	UniFormat(src_sys, sizeof(src_sys), L"|DriverPackages\\SeLow_Win10\\%S\\SeLow_%S.sys",
		cpu_type, cpu_type);
	// Windows 10 uses WHQL catalog files
	UniFormat(src_cat, sizeof(src_cat), L"|DriverPackages\\SeLow_Win10\\%S\\SeLow_Win10_%S.cat", cpu_type, cpu_type);
	UniFormat(src_inf, sizeof(src_inf), L"|DriverPackages\\SeLow_Win10\\%S\\SeLow_%S.inf",
		cpu_type, cpu_type);

	UniFormat(dst_sys, sizeof(dst_cat), L"%s\\SeLow_%S.sys", tmp_dir, cpu_type);
	UniFormat(dst_cat, sizeof(dst_cat), L"%s\\SeLow_Win10_%S.cat", tmp_dir,
		cpu_type);

	UniFormat(dst_inf, sizeof(dst_inf), L"%s\\SeLow_%S.inf", tmp_dir, cpu_type);

	if (FileCopyW(src_sys, dst_sys) &&
		FileCopyW(src_cat, dst_cat) &&
		FileCopyW(src_inf, dst_inf))
	{
		NO_WARNING *nw;

		nw = MsInitNoWarningEx(SL_USER_AUTO_PUSH_TIMER);

		if (MsIsServiceInstalled(SL_PROTOCOL_NAME) == false && MsIsServiceRunning(SL_PROTOCOL_NAME) == false)
		{
		}

		SuDeleteGarbageInfs();

		if (InstallNdisProtocolDriver(dst_inf, L"SeLow", SL_USER_INSTALL_LOCK_TIMEOUT) == false)
		{
		}
		else
		{
			// Also copy by hand: the installer sometimes fails to copy the .sys file
			Debug("SuCopySysFile from %S to %s: ret = %u\n", src_sys, sys_fullpath, SuCopySysFile(src_sys, sys_fullpath));

			ret = true;

			MsRegWriteIntEx2(REG_LOCAL_MACHINE, SL_REG_KEY_NAME,
				SL_REG_VER_VALUE_WIN10,
				SL_VER, false, true);

			MsRegWriteIntEx2(REG_LOCAL_MACHINE, SL_REG_KEY_NAME, "Start", SERVICE_SYSTEM_START, false, true);
		}

		MsFreeNoWarning(nw);
	}

	if (ret)
	{
		SuFree(SuInitEx(180 * 1000));
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

bool SuIsSupportedOs(bool on_install)
{
	if (MsRegReadIntEx2(REG_LOCAL_MACHINE, SL_REG_KEY_NAME, "EnableSeLow", false, true) != 0)
	{
		return true;
	}

	if (MsRegReadIntEx2(REG_LOCAL_MACHINE, SL_REG_KEY_NAME, "DisableSeLow", false, true) != 0)
	{
		return false;
	}

	return true;
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

		SuCloseAdapterHandleInner(a);
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

			return true;
		}
		else
		{
			if (SuGetPacketsFromDriver(a) == false)
			{
				return false;
			}

			if (SL_NUM_PACKET(a->GetBuffer) == 0)
			{
				*buf = NULL;
				*size = 0;
				return true;
			}

			a->CurrentPacketCount = 0;
		}
	}
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

		SuCloseAdapterHandleInner(a);
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

void SuCloseAdapterHandleInner(SU_ADAPTER *a)
{
	return;
}

SU_ADAPTER *SuOpenAdapter(SU *u, char *adapter_id)
{
	char filename[MAX_PATH];
	void *h;
	SU_ADAPTER *a;
	SL_IOCTL_EVENT_NAME t;
	DWORD read_size;
	if (u == NULL || adapter_id == NULL)
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

	StrCpy(a->AdapterId, sizeof(a->AdapterId), adapter_id);
	StrCpy(a->DeviceName, sizeof(a->DeviceName), filename);

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

LIST *SuGetAdapterList(SU *u)
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
			char regkey[MAX_PATH] = {0};
			char tmp[MAX_PATH] = {0};
			char adapter_guid[MAX_PATH] = {0};

			UniToStr(adapter_guid, sizeof(adapter_guid), info->AdapterId + StrLen(SL_ADAPTER_ID_PREFIX));

			if (GetClassRegKeyWin32(regkey, sizeof(regkey), tmp, sizeof(tmp), adapter_guid))
			{
				char *driver_desc = MsRegReadStrEx2(REG_LOCAL_MACHINE, regkey, "DriverDesc", false, true);

				if (driver_desc != NULL)
				{
					StrCpy(info->FriendlyName, sizeof(info->FriendlyName), driver_desc);
					Free(driver_desc);
				}
			}
		}

		{
			SU_ADAPTER_LIST *a = SuAdapterInfoToAdapterList(info);

			char macstr[128] = {0};
			BinToStr(macstr, sizeof(macstr), info->MacAddress, sizeof(info->MacAddress));

			if (a != NULL)
			{

				Add(ret, a);
			}
			else
			{
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

SU_ADAPTER_LIST *SuAdapterInfoToAdapterList(SL_ADAPTER_INFO *info)
{
	SU_ADAPTER_LIST t;
	char tmp[MAX_SIZE];
	if (info == NULL)
	{
		return NULL;
	}

	Zero(&t, sizeof(t));
	Copy(&t.Info, info, sizeof(SL_ADAPTER_INFO));

	UniToStr(tmp, sizeof(tmp), info->AdapterId);
	// List the NIC in Local Bridge settings even when its FriendlyName is empty.
	if (IsEmptyStr(tmp) || /* IsEmptyStr(info->FriendlyName) || */ StartWith(tmp, SL_ADAPTER_ID_PREFIX) == false)
	{
		return NULL;
	}

	StrCpy(t.Guid, sizeof(t.Guid), tmp + StrLen(SL_ADAPTER_ID_PREFIX));

	StrCpy(t.Name, sizeof(t.Name), tmp);

	if (GetClassRegKeyWin32(t.SortKey, sizeof(t.SortKey), tmp, sizeof(tmp), t.Guid) == false)
	{
		return NULL;
	}

	return Clone(&t, sizeof(t));
}

SU *SuInitEx(UINT wait_for_bind_complete_tick)
{
	void *h;
	SU *u;
	bool flag = false;
	UINT64 giveup_tick = 0;

	if (SuIsSupportedOs(false) == false)
	{
		return NULL;
	}

LABEL_RETRY:

	h = CreateFileA(SL_BASIC_DEVICE_FILENAME_WIN32, GENERIC_READ | GENERIC_WRITE,
		FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);

	if (h == INVALID_HANDLE_VALUE)
	{
		if (flag == false)
		{
			if (MsStartService(SL_PROTOCOL_NAME) == false)
			{
				if (su_install_tried == false)
				{
					su_install_tried = true;

					if (su_install_proc(true))
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


