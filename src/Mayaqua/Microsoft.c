// SoftEther VPN Source Code - Developer Edition Master Branch
// Mayaqua Kernel


// Microsoft.c
// For Microsoft Windows code
// (not compiled on non-Windows environments)

#ifdef OS_WIN32

#define	MICROSOFT_C

#include "Microsoft.h"

#include "Cfg.h"
#include "FileIO.h"
#include "GlobalConst.h"
#include "Internat.h"
#include "Memory.h"
#include "Object.h"
#include "Str.h"
#include "Table.h"
#include "Tick64.h"
#include "Win32.h"

#define SECURITY_WIN32

#include <AclAPI.h>
#include <DbgHelp.h>
#include <dwmapi.h>
#include <iphlpapi.h>
#include <mmsystem.h>
#include <Msi.h>
#include <nb30.h>
#include <NTSecAPI.h>
#include <Psapi.h>
#include <sddl.h>
#include <security.h>
#include <shellapi.h>
#include <ShlObj.h>
#include <SoftPub.h>
#include <WtsApi32.h>

static MS *ms = NULL;

static LOCK *lock_adapter_list = NULL;
static MS_ADAPTER_LIST *last_adapter_list = NULL;

static SERVICE_STATUS_HANDLE ssh = NULL;
static SERVICE_STATUS status = { 0 };
static HANDLE service_stop_event = NULL;
static BOOL (WINAPI *_StartServiceCtrlDispatcher)(CONST LPSERVICE_TABLE_ENTRY) = NULL;
static SERVICE_STATUS_HANDLE (WINAPI *_RegisterServiceCtrlHandler)(LPCTSTR, LPHANDLER_FUNCTION) = NULL;
static BOOL (WINAPI *_SetServiceStatus)(SERVICE_STATUS_HANDLE, LPSERVICE_STATUS) = NULL;
static char g_service_name[MAX_SIZE];
static SERVICE_FUNCTION *g_start, *g_stop;
static bool exiting = false;
static bool wnd_end;
static bool is_usermode = false;
static HWND hWndUsermode = NULL;
static HANDLE hLsa = NULL;
static ULONG lsa_package_id = 0;
static TOKEN_SOURCE lsa_token_source;

static HINSTANCE hMsi = NULL;
static UINT (WINAPI *_MsiGetProductInfoW)(LPCWSTR, LPCWSTR, LPWSTR, LPDWORD) = NULL;
static UINT (WINAPI *_MsiConfigureProductW)(LPCWSTR, int, INSTALLSTATE) = NULL;
static INSTALLUILEVEL (WINAPI *_MsiSetInternalUI)(INSTALLUILEVEL, HWND *) = NULL;
static INSTALLSTATE (WINAPI *_MsiLocateComponentW)(LPCWSTR, LPWSTR, LPDWORD) = NULL;

void MsInitProcessCallOnce()
{
	// Mitigate DLL injection attacks
	char system_dir[MAX_PATH];
	char kernel32_path[MAX_PATH];
	UINT len;
	HINSTANCE hKernel32;

	memset(system_dir, 0, sizeof(system_dir));
	GetSystemDirectory(system_dir, sizeof(system_dir));
	len = lstrlenA(system_dir);
	if (system_dir[len] == '\\')
	{
		system_dir[len] = 0;
	}
	wsprintfA(kernel32_path, "%s\\kernel32.dll", system_dir);

	hKernel32 = LoadLibraryA(kernel32_path);
	if (hKernel32 != NULL)
	{
		BOOL (WINAPI *_SetDllDirectoryA)(LPCTSTR);

		_SetDllDirectoryA = (BOOL (WINAPI *)(LPCTSTR))
			GetProcAddress(hKernel32, "SetDllDirectoryA");

		if (_SetDllDirectoryA != NULL)
		{
			_SetDllDirectoryA("");
		}

		FreeLibrary(hKernel32);
	}
}

bool MsIsInVmMain()
{
	char *bat_data = "On Error Resume Next\r\n\r\nDim str\r\n\r\nSet wmi_svc = GetObject(\"winmgmts:{impersonationLevel=impersonate}!\\\\.\\root\\cimv2\")\r\n\r\nSet items = wmi_svc.ExecQuery(\"Select * from Win32_BaseBoard\")\r\n\r\nFor Each item in items\r\n	str = str & item.Manufacturer\r\nNext\r\n\r\nSet items = Nothing\r\n\r\nSet items = wmi_svc.ExecQuery(\"Select * from Win32_ComputerSystem\")\r\n\r\nFor Each item in items\r\n	str = str & item.Manufacturer\r\nNext\r\n\r\nSet items = Nothing\r\n\r\nSet wmi_svc = Nothing\r\n\r\nstr = LCase(str)\r\n\r\nDim ret\r\n\r\nret = 0\r\n\r\nif InStr(str, \"microsoft corporation\") > 0 then\r\n	ret = 1\r\nend if\r\n\r\nif InStr(str, \"vmware\") > 0 then\r\n	ret = 1\r\nend if\r\n\r\nif InStr(str, \"virtualbox\") > 0 then\r\n	ret = 1\r\nend if\r\n\r\nif InStr(str, \"virtualpc\") > 0 then\r\n	ret = 1\r\nend if\r\n\r\nif InStr(str, \"xen\") > 0 then\r\n	ret = 1\r\nend if\r\n\r\nif InStr(str, \"hvm\") > 0 then\r\n	ret = 1\r\nend if\r\n\r\nif InStr(str, \"domu\") > 0 then\r\n	ret = 1\r\nend if\r\n\r\nif InStr(str, \"kvm\") > 0 then\r\n	ret = 1\r\nend if\r\n\r\nif InStr(str, \"oracle vm\") > 0 then\r\n	ret = 1\r\nend if\r\n\r\nif InStr(str, \"qemu\") > 0 then\r\n	ret = 1\r\nend if\r\n\r\nif InStr(str, \"parallels\") > 0 then\r\n	ret = 1\r\nend if\r\n\r\nif InStr(str, \"xvm\") > 0 then\r\n	ret = 1\r\nend if\r\n\r\nif InStr(str, \"virtual\") > 0 then\r\n	ret = 1\r\nend if\r\n\r\nif InStr(str, \"bochs\") > 0 then\r\n	ret = 1\r\nend if\r\n\r\nwscript.quit ret\r\n\r\n";
	wchar_t bat_filename[MAX_SIZE];
	wchar_t cscript_exe[MAX_SIZE];
	wchar_t tmp[MAX_SIZE];
	void *process;
	bool ret = false;

	CombinePathW(bat_filename, sizeof(bat_filename), MsGetMyTempDirW(), L"detectvm.vbs");

	if (DumpDataW(bat_data, StrLen(bat_data), bat_filename) == false)
	{
		return false;
	}

	CombinePathW(cscript_exe, sizeof(cscript_exe), MsGetSystem32DirW(), L"cscript.exe");

	UniFormat(tmp, sizeof(tmp), L"\"%s\"", bat_filename);

	process = Win32RunEx3W(cscript_exe, tmp, true, NULL, true);

	if (process == NULL)
	{
		return false;
	}

	if (Win32WaitProcess(process, 30000))
	{
		DWORD exit_code = 0;

		if (GetExitCodeProcess(process, &exit_code))
		{
			if (exit_code == 1)
			{
				ret = true;
			}
		}
	}

	Win32CloseProcess(process);

	return ret;
}
bool MsIsInVm()
{
	static bool flag_detected = false;
	static bool flag_is_vm = false;

	if (flag_detected == false)
	{
		flag_is_vm = MsIsInVmMain();

		flag_detected = true;
	}

	return flag_is_vm;
}

UINT MsGetUserLocaleId()
{
	static UINT lcid_cache = 0;

	if (lcid_cache == 0)
	{
		lcid_cache = (UINT)GetUserDefaultLCID();
	}

	return lcid_cache;
}

void MsSendGlobalPulse(void *p)
{
	HANDLE h;
	if (p == NULL)
	{
		return;
	}

	h = (HANDLE)p;

	PulseEvent(h);
}

void MsCloseGlobalPulse(void *p)
{
	HANDLE h;
	if (p == NULL)
	{
		return;
	}

	h = (HANDLE)p;

	CloseHandle(h);
}

bool MsWaitForGlobalPulse(void *p, UINT timeout)
{
	HANDLE h;
	UINT ret;
	if (p == NULL)
	{
		return false;
	}
	if (timeout == TIMEOUT_INFINITE)
	{
		timeout = INFINITE;
	}

	h = (HANDLE)p;

	ret = WaitForSingleObject(h, timeout);

	if (ret == WAIT_OBJECT_0)
	{
		return true;
	}

	return false;
}

void *MsOpenOrCreateGlobalPulse(char *name)
{
	UCHAR hash[20];
	char tmp[MAX_SIZE];
	char tmp2[MAX_SIZE];
	HANDLE h;
	if (name == NULL)
	{
		return NULL;
	}

	StrCpy(tmp, sizeof(tmp), name);
	Trim(tmp);
	StrUpper(tmp);

	Sha1(hash, name, StrLen(name));

	BinToStr(tmp, sizeof(tmp), hash, sizeof(hash));
	Format(tmp2, sizeof(tmp2), "Global\\GlobalPulse_%s", tmp);

	h = CreateEvent(NULL, true, false, tmp2);

	return (void *)h;
}


bool MsGetFileInformation(void *h, void *info)
{
	if (h == INVALID_HANDLE_VALUE || info == NULL)
	{
		return false;
	}

	return GetFileInformationByHandle(h, info);
}

double MsGetHiResTimeSpan(UINT64 diff)
{
	LARGE_INTEGER t;
	UINT64 freq;

	if (QueryPerformanceFrequency(&t) == false)
	{
		freq = 1000ULL;
	}
	else
	{
		Copy(&freq, &t, sizeof(UINT64));
	}

	return (double)diff / (double)freq;
}
UINT64 MsGetHiResTimeSpanUSec(UINT64 diff)
{
	LARGE_INTEGER t;
	UINT64 freq;

	if (QueryPerformanceFrequency(&t) == false)
	{
		freq = 1000ULL;
	}
	else
	{
		Copy(&freq, &t, sizeof(UINT64));
	}

	return (UINT64)(diff) * 1000ULL * 1000ULL / (UINT64)freq;
}

UINT64 MsGetHiResCounter()
{
	LARGE_INTEGER t;
	UINT64 ret;

	if (QueryPerformanceCounter(&t) == false)
	{
		return Tick64();
	}

	Copy(&ret, &t, sizeof(UINT64));

	return ret;
}

void MsUniMakeDirEx(wchar_t *name)
{
	UINT wp;
	wchar_t *tmp;
	UINT i, len;
	if (name == NULL)
	{
		return;
	}

	tmp = ZeroMalloc(UniStrSize(name) * 2);
	wp = 0;
	len = UniStrLen(name);
	for (i = 0;i < len;i++)
	{
		wchar_t c = name[i];

		if (c == '\\')
		{
			if (UniStrCmpi(tmp, L"\\\\") != 0 && UniStrCmpi(tmp, L"\\") != 0)
			{
				MsUniMakeDir(tmp);
			}
		}

		tmp[wp++] = c;
	}

	Free(tmp);

	MsUniMakeDir(name);
}

bool MsUniMakeDir(wchar_t *name)
{
	if (name == NULL)
	{
		return false;
	}

	return CreateDirectoryW(name, NULL);
}

static wchar_t ms_computer_name_full_cache[MAX_SIZE] = {0};

void MsGetComputerNameFullEx(wchar_t *name, UINT size, bool with_cache)
{
	DWORD size2 = size;
	UniStrCpy(name, size, L"");
	if (name == NULL || size == 0)
	{
		return;
	}

	if (with_cache)
	{
		if (UniIsEmptyStr(ms_computer_name_full_cache) == false)
		{
			UniStrCpy(name, size, ms_computer_name_full_cache);
			return;
		}
	}

	if (GetComputerNameExW(ComputerNameDnsFullyQualified, name, &size2) == false)
	{
		char tmp[MAX_SIZE];

		MsGetComputerName(tmp, sizeof(tmp));

		StrToUni(name, size, tmp);
	}

	if (with_cache)
	{
		UniStrCpy(ms_computer_name_full_cache, sizeof(ms_computer_name_full_cache), name);
	}
}

void MsGetComputerName(char *name, UINT size)
{
	DWORD sz;
	if (name == NULL)
	{
		return;
	}

	sz = size;
	GetComputerName(name, &sz);
}

void *MsDisableWow64FileSystemRedirection()
{
	void *p = NULL;
	if (MsIs64BitWindows() == false)
	{
		return NULL;
	}

	if (Wow64DisableWow64FsRedirection(&p) == false)
	{
		return NULL;
	}

	if (p == NULL)
	{
		p = (void *)0x12345678;
	}

	return p;
}

void MsRestoreWow64FileSystemRedirection(void *p)
{
	if (p == NULL)
	{
		return;
	}
	if (p == (void *)0x12345678)
	{
		p = NULL;
	}
	if (MsIs64BitWindows() == false)
	{
		return;
	}

	Wow64RevertWow64FsRedirection(p);
}

bool MsIsX64()
{
	SYSTEM_INFO info;

	Zero(&info, sizeof(info));
	GetNativeSystemInfo(&info);

	if (info.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64)
	{
		return true;
	}

	return false;
}

bool MsIs64BitWindows()
{
	if (Is64())
	{
		return true;
	}

	BOOL b = false;
	if (IsWow64Process(GetCurrentProcess(), &b) == false)
	{
		return false;
	}

	return b;
}

void MsRegistWindowsFirewallEx2(char *title, char *exe, char *dir)
{
	char tmp[MAX_PATH];
	if (title == NULL || exe == NULL)
	{
		return;
	}
	if (dir == NULL || IsEmptyStr(dir))
	{
		dir = MsGetExeDirName();
	}

	ConbinePath(tmp, sizeof(tmp), dir, exe);

	if (IsFileExists(tmp) == false)
	{
		return;
	}

	MsRegistWindowsFirewallEx(title, tmp);
}
void MsRegistWindowsFirewallEx(char *title, char *exe)
{
	char *data;
	char *tmp;
	UINT tmp_size;
	char filename[MAX_PATH];
	char cscript[MAX_PATH];
	char arg[MAX_PATH];
	IO *o;
	char hash[MAX_PATH];
	UCHAR hashbin[SHA1_SIZE];
	UCHAR file_hash_bin[SHA1_SIZE];
	char file_hash_str[MAX_SIZE];
	if (title == NULL || exe == NULL)
	{
		return;
	}

	if (MsIsAdmin() == false)
	{
		return;
	}

	data = "Option Explicit\r\n\r\nConst PROFILES_ALL = 7\r\nConst NET_FW_ACTION_ALLOWNET_FW_ACTION_ALLOW = 1\r\n"
		"\r\nDim policy2\r\nDim rules\r\nDim new_rule\r\n\r\nOn Error Resume Next\r\n\r\n"
		"Set policy2 = CreateObject(\"HNetCfg.FwPolicy2\")\r\nSet rules = policy2.Rules\r\n"
		"Set new_rule = CreateObject(\"HNetCfg.FWRule\")\r\nnew_rule.Name = \"$TITLE$\"\r\n"
		"new_rule.Description = \"$TITLE$\"\r\nnew_rule.ApplicationName = \"$PATH$\"\r\n"
		"new_rule.Enabled = TRUE\r\nnew_rule.Profiles = PROFILES_ALL\r\nnew_rule.Action = "
		"NET_FW_ACTION_ALLOWNET_FW_ACTION_ALLOW\r\nrules.Add new_rule\r\n\r\n";

	tmp_size = StrLen(data) * 4;
	tmp = ZeroMalloc(tmp_size);

	Sha1(hashbin, exe, StrLen(exe));
	BinToStr(hash, sizeof(hash), hashbin, 6);

	ReplaceStrEx(tmp, tmp_size, data, "$TITLE$", title, false);
	ReplaceStrEx(tmp, tmp_size, tmp, "$PATH$", exe, false);

	Sha1(file_hash_bin, tmp, StrLen(tmp));
	BinToStr(file_hash_str, sizeof(file_hash_str), file_hash_bin, sizeof(file_hash_bin));

	if (MsRegReadIntEx2(REG_LOCAL_MACHINE, SOFTETHER_FW_SCRIPT_HASH, file_hash_str, false, true) == 0)
	{
		Format(filename, sizeof(filename), "%s\\winfire_%s.vbs", MsGetMyTempDir(), hash);
		o = FileCreate(filename);
		FileWrite(o, tmp, StrLen(tmp));
		FileClose(o);

		Format(cscript, sizeof(cscript), "%s\\cscript.exe", MsGetSystem32Dir());
		Format(arg, sizeof(arg), "\"%s\"", filename);

		if (Run(cscript, arg, true, false))
		{
			MsRegWriteIntEx2(REG_LOCAL_MACHINE, SOFTETHER_FW_SCRIPT_HASH, file_hash_str, 1, false, true);
		}
	}

	Free(tmp);
}

UINT MsGetThreadLocale()
{
	return (UINT)GetThreadLocale();
}

UINT MsSetConsoleWidth(UINT size)
{
	HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
	CONSOLE_SCREEN_BUFFER_INFO info;
	COORD c;
	UINT old_x, old_y;
	if (size == 0)
	{
		return 0;
	}
	if (h == INVALID_HANDLE_VALUE)
	{
		return 0;
	}

	Zero(&info, sizeof(info));
	if (GetConsoleScreenBufferInfo(h, &info) == false)
	{
		return 0;
	}

	old_x = info.dwSize.X;
	old_y = info.dwSize.Y;

	c.X = size;
	c.Y = old_y;

	SetConsoleScreenBufferSize(h, c);

	return old_x;
}

UINT MsGetConsoleWidth()
{
	HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
	CONSOLE_SCREEN_BUFFER_INFO info;

	if (h == INVALID_HANDLE_VALUE)
	{
		return 80;
	}

	Zero(&info, sizeof(info));
	if (GetConsoleScreenBufferInfo(h, &info) == false)
	{
		return 80;
	}

	return info.dwSize.X;
}

bool MsDisableIme()
{
	HINSTANCE h;
	bool ret = false;
	char dll_name[MAX_PATH];
	BOOL (WINAPI *_ImmDisableIME)(DWORD);

	Format(dll_name, sizeof(dll_name), "%s\\imm32.dll", MsGetSystem32Dir());
	h = MsLoadLibrary(dll_name);
	if (h == NULL)
	{
		return false;
	}

	_ImmDisableIME = (BOOL (__stdcall *)(DWORD))GetProcAddress(h, "ImmDisableIME");

	if (_ImmDisableIME != NULL)
	{
		ret = _ImmDisableIME(-1);
	}

	FreeLibrary(h);

	return ret;
}

void MsPrintTick()
{
	UINT tick = timeGetTime();
	static UINT tick_init = 0;
	if (tick_init == 0)
	{
		tick_init = tick;
		tick = 0;
	}
	else
	{
		tick -= tick_init;
	}

	printf("[%u]\n", tick);
}

void *MsLoadLibraryW(wchar_t *name)
{
	BUF *b;
	wchar_t tmp_dll_name[MAX_SIZE];
	char hash_str[MAX_SIZE];
	UCHAR hash[SHA1_SIZE];
	if (name == NULL)
	{
		return NULL;
	}

	Sha0(hash, name, UniStrSize(name));

	BinToStr(hash_str, sizeof(hash_str), hash, 4);

	UniFormat(tmp_dll_name, sizeof(tmp_dll_name), L"%s\\%S.dll", MsGetMyTempDirW(), hash_str);

	if (IsFileExistsW(tmp_dll_name) == false)
	{
		b = ReadDumpW(name);
		if (b == NULL)
		{
			return NULL;
		}

		DumpBufW(b, tmp_dll_name);
		FreeBuf(b);
	}

	return LoadLibraryW(tmp_dll_name);
}
void *MsLoadLibrary(char *name)
{
	wchar_t name_w[MAX_SIZE];
	if (name == NULL)
	{
		return NULL;
	}

	StrToUni(name_w, sizeof(name_w), name);

	return MsLoadLibraryW(name_w);
}

MS_ADAPTER *MsGetAdapterByGuid(char *guid)
{
	MS_ADAPTER_LIST *o;
	MS_ADAPTER *ret = NULL;
	if (guid == NULL)
	{
		return NULL;
	}

	o = MsCreateAdapterList();
	if (o == NULL)
	{
		return NULL;
	}

	ret = MsGetAdapterByGuidFromList(o, guid);

	MsFreeAdapterList(o);

	return ret;
}
MS_ADAPTER *MsGetAdapterByGuidFromList(MS_ADAPTER_LIST *o, char *guid)
{
	MS_ADAPTER *ret = NULL;
	UINT i;
	if (o == NULL || guid == NULL)
	{
		return NULL;
	}

	for (i = 0;i < o->Num;i++)
	{
		if (StrCmpi(o->Adapters[i]->Guid, guid) == 0)
		{
			ret = MsCloneAdapter(o->Adapters[i]);
			break;
		}
	}

	return ret;
}

// Detect a 32-bit counter wraparound
#define	CHECK_32BIT_OVERFLOW(old_value, new_value)				\
{																\
	if ((old_value) > (new_value))								\
	{															\
		(new_value) += ((UINT64)4294967296ULL);					\
	}															\
}

void MsGetAdapterTcpIpInformation(MS_ADAPTER *a)
{
	IP_ADAPTER_INFO *info, *info_top;
	ULONG info_size;
	ULONG ret;
	if (a == NULL)
	{
		return;
	}

	info_top = ZeroMalloc(sizeof(IP_ADAPTER_INFO));
	info_size = sizeof(IP_ADAPTER_INFO);

	ret = GetAdaptersInfo(info_top, &info_size);
	if (ret == ERROR_INSUFFICIENT_BUFFER || ret == ERROR_BUFFER_OVERFLOW)
	{
		Free(info_top);
		info_size *= 2;
		info_top = ZeroMalloc(info_size);

		if (GetAdaptersInfo(info_top, &info_size) != NO_ERROR)
		{
			Free(info_top);
			return;
		}
	}
	else if (ret != NO_ERROR)
	{
		Free(info_top);
		return;
	}

	info = info_top;

	while (info != NULL)
	{
		if (info->Index == a->Index)
		{
			IP_ADDR_STRING *s;

			a->NumIpAddress = 0;
			s = &info->IpAddressList;
			while (s != NULL)
			{
				if (a->NumIpAddress < MAX_MS_ADAPTER_IP_ADDRESS)
				{
					StrToIP(&a->IpAddresses[a->NumIpAddress], s->IpAddress.String);
					StrToIP(&a->SubnetMasks[a->NumIpAddress], s->IpMask.String);
					a->NumIpAddress++;
				}
				s = s->Next;
			}

			a->NumGateway = 0;
			s = &info->GatewayList;
			while (s != NULL)
			{
				if (a->NumGateway < MAX_MS_ADAPTER_IP_ADDRESS)
				{
					StrToIP(&a->Gateways[a->NumGateway], s->IpAddress.String);
					a->NumGateway++;
				}
				s = s->Next;
			}

			a->UseDhcp = (info->DhcpEnabled == 0 ? false : true);
			if (a->UseDhcp)
			{
				SYSTEMTIME st;

				StrToIP(&a->DhcpServer, info->DhcpServer.IpAddress.String);
				TimeToSystem(&st, info->LeaseObtained);
				a->DhcpLeaseStart = SystemToUINT64(&st);

				TimeToSystem(&st, info->LeaseExpires);
				a->DhcpLeaseExpires = SystemToUINT64(&st);
			}

			a->UseWins = info->HaveWins;
			if (a->UseWins)
			{
				StrToIP(&a->PrimaryWinsServer, info->PrimaryWinsServer.IpAddress.String);
				StrToIP(&a->SecondaryWinsServer, info->SecondaryWinsServer.IpAddress.String);
			}

			StrCpy(a->Guid, sizeof(a->Guid), info->AdapterName);

			a->Info = true;

			break;
		}

		info = info->Next;
	}

	Free(info_top);
}

MS_ADAPTER_LIST *MsCreateAdapterList()
{
	return MsCreateAdapterListEx(false);
}
MS_ADAPTER_LIST *MsCreateAdapterListEx(bool no_info)
{
	MS_ADAPTER_LIST *ret;

	if (no_info)
	{
		ret = MsCreateAdapterListInnerExVista(true);

		return ret;
	}

	Lock(lock_adapter_list);
	{
		MS_ADAPTER_LIST *old = last_adapter_list;
		UINT i;

		ret = MsCreateAdapterListInnerExVista(false);

		if (ret == NULL)
		{
			Unlock(lock_adapter_list);
			return NULL;
		}

		for (i = 0;i < ret->Num;i++)
		{
			UINT j;
			for (j = 0;j < old->Num;j++)
			{
				MS_ADAPTER *o = old->Adapters[j];
				MS_ADAPTER *n = ret->Adapters[i];

				if (StrCmpi(o->Title, n->Title) == 0)
				{
					CHECK_32BIT_OVERFLOW(o->RecvBytes, n->RecvBytes);
					CHECK_32BIT_OVERFLOW(o->RecvPacketsBroadcast, n->RecvPacketsBroadcast);
					CHECK_32BIT_OVERFLOW(o->RecvPacketsUnicast, n->RecvPacketsUnicast);
					CHECK_32BIT_OVERFLOW(o->SendBytes, n->SendBytes);
					CHECK_32BIT_OVERFLOW(o->SendPacketsBroadcast, n->SendPacketsBroadcast);
					CHECK_32BIT_OVERFLOW(o->SendPacketsUnicast, n->SendPacketsUnicast);
					break;
				}
			}
		}

		MsFreeAdapterList(old);

		last_adapter_list = MsCloneAdapterList(ret);
	}
	Unlock(lock_adapter_list);

	return ret;
}

void MsInitAdapterListModule()
{
	lock_adapter_list = NewLock(NULL);

	last_adapter_list = MsCreateAdapterListInnerExVista(false);
}

void MsFreeAdapterListModule()
{
	if (last_adapter_list != NULL)
	{
		MsFreeAdapterList(last_adapter_list);
		last_adapter_list = NULL;
	}

	DeleteLock(lock_adapter_list);
	lock_adapter_list = NULL;
}

MS_ADAPTER_LIST *MsCloneAdapterList(MS_ADAPTER_LIST *o)
{
	MS_ADAPTER_LIST *ret;
	UINT i;
	if (o == NULL)
	{
		return NULL;
	}

	ret = ZeroMalloc(sizeof(MS_ADAPTER_LIST));
	ret->Num = o->Num;
	ret->Adapters = ZeroMalloc(sizeof(MS_ADAPTER *) * ret->Num);

	for (i = 0;i < ret->Num;i++)
	{
		ret->Adapters[i] = ZeroMalloc(sizeof(MS_ADAPTER));
		Copy(ret->Adapters[i], o->Adapters[i], sizeof(MS_ADAPTER));
	}

	return ret;
}

MS_ADAPTER *MsCloneAdapter(MS_ADAPTER *a)
{
	MS_ADAPTER *ret;
	if (a == NULL)
	{
		return NULL;
	}

	ret = ZeroMalloc(sizeof(MS_ADAPTER));
	Copy(ret, a, sizeof(MS_ADAPTER));

	return ret;
}

MS_ADAPTER_LIST *MsCreateAdapterListInnerExVista(bool no_info)
{
	LIST *o;
	UINT i;
	UINT retcode;
	PMIB_IF_TABLE2 table;
	MS_ADAPTER_LIST *ret;

	retcode = GetIfTable2(&table);
	if (retcode != NO_ERROR || table == NULL)
	{
		return ZeroMalloc(sizeof(MS_ADAPTER_LIST));
	}

	o = NewListFast(NULL);

	for (i = 0;i < table->NumEntries;i++)
	{
		MIB_IF_ROW2 *r = &table->Table[i];
		wchar_t title[MAX_PATH];
		MS_ADAPTER *a;
		UINT j;

		{
			{
				for (j = 1;;j++)
				{
					UINT k;
					bool exists;
					if (j == 1)
					{
						UniStrCpy(title, sizeof(title), r->Description);
					}
					else
					{
						UniFormat(title, sizeof(title), L"%s (%u)", r->Description, j);
					}

					exists = false;

					for (k = 0;k < LIST_NUM(o);k++)
					{
						MS_ADAPTER *a = LIST_DATA(o, k);

						if (UniStrCmpi(a->TitleW, title) == 0)
						{
							exists = true;
							break;
						}
					}

					if (exists == false)
					{
						break;
					}
				}

				a = ZeroMalloc(sizeof(MS_ADAPTER));

				UniStrCpy(a->TitleW, sizeof(a->TitleW), title);
				UniToStr(a->Title, sizeof(a->Title), title);
				a->Index = r->InterfaceIndex;
				a->MediaConnectState = r->MediaConnectState;
				a->Type = r->Type;
				a->Status = ConvertMidStatusVistaToXp(r->OperStatus);
				a->Mtu = r->Mtu;
				a->Speed = MAX((UINT)r->TransmitLinkSpeed, (UINT)r->ReceiveLinkSpeed);
				a->AddressSize = MIN(sizeof(a->Address), r->PhysicalAddressLength);
				Copy(a->Address, r->PhysicalAddress, a->AddressSize);
				a->RecvBytes = r->InOctets;
				a->RecvPacketsBroadcast = r->InNUcastPkts;
				a->RecvPacketsUnicast = r->InUcastPkts;
				a->SendBytes = r->OutOctets;
				a->SendPacketsBroadcast = r->OutNUcastPkts;
				a->SendPacketsUnicast = r->OutUcastPkts;

				if (r->MediaType == NdisMediumWirelessWan || r->PhysicalMediumType == NdisPhysicalMediumWirelessLan ||
					r->PhysicalMediumType == NdisPhysicalMediumWirelessWan || r->PhysicalMediumType == NdisPhysicalMediumWiMax ||
					r->Type == IF_TYPE_IEEE80211)
				{
					a->IsWireless = true;
				}

				if (a->IsWireless ||
					r->Type != IF_TYPE_ETHERNET_CSMACD ||
					r->MediaType != NdisMedium802_3 || 
					(r->PhysicalMediumType != 0 && r->PhysicalMediumType != NdisPhysicalMedium802_3))
				{
					a->IsNotEthernetLan = true;
				}

				if (no_info == false)
				{
					MsGetAdapterTcpIpInformation(a);
				}

				Add(o, a);
			}
		}
	}

	ret = ZeroMalloc(sizeof(MS_ADAPTER_LIST));
	ret->Num = LIST_NUM(o);
	ret->Adapters = ToArray(o);

	ReleaseList(o);
	FreeMibTable(table);

	return ret;
}

UINT ConvertMidStatusVistaToXp(UINT st)
{
	switch (st)
	{
	case IfOperStatusUp:
		return MIB_IF_OPER_STATUS_CONNECTED;

	case IfOperStatusDown:
		return MIB_IF_OPER_STATUS_DISCONNECTED;
	}

	return MIB_IF_OPER_STATUS_NON_OPERATIONAL;
}

void MsFreeAdapterList(MS_ADAPTER_LIST *o)
{
	UINT i;
	if (o == NULL)
	{
		return;
	}

	for (i = 0;i < o->Num;i++)
	{
		MsFreeAdapter(o->Adapters[i]);
	}
	Free(o->Adapters);

	Free(o);
}

void MsFreeAdapter(MS_ADAPTER *a)
{
	if (a == NULL)
	{
		return;
	}

	Free(a);
}

MS_PROCESS *MsSearchProcessById(LIST *o, UINT id)
{
	MS_PROCESS *p, t;
	if (o == NULL)
	{
		return NULL;
	}

	Zero(&t, sizeof(t));
	t.ProcessId = id;

	p = Search(o, &t);

	return p;
}

int MsCompareProcessList(void *p1, void *p2)
{
	MS_PROCESS *e1, *e2;
	if (p1 == NULL || p2 == NULL)
	{
		return 0;
	}
	e1 = *(MS_PROCESS **)p1;
	e2 = *(MS_PROCESS **)p2;
	if (e1 == NULL || e2 == NULL)
	{
		return 0;
	}

	if (e1->ProcessId > e2->ProcessId)
	{
		return 1;
	}
	else if (e1->ProcessId < e2->ProcessId)
	{
		return -1;
	}
	else
	{
		return 0;
	}
}

void MsFreeProcessList(LIST *o)
{
	UINT i;
	if (o == NULL)
	{
		return;
	}

	for (i = 0;i < LIST_NUM(o);i++)
	{
		MS_PROCESS *p = LIST_DATA(o, i);
		Free(p);
	}

	ReleaseList(o);
}

LIST *MsGetProcessListNt()
{
	LIST *o;
	UINT max = 16384;
	DWORD *processes;
	DWORD needed;
	UINT num;
	UINT i;

	o = NewListFast(MsCompareProcessList);

	processes = ZeroMalloc(sizeof(DWORD) * max);

	if (EnumProcesses(processes, sizeof(DWORD) * max, &needed) == FALSE)
	{
		Free(processes);
		return NULL;
	}

	num = needed / sizeof(DWORD);

	for (i = 0;i < num;i++)
	{
		UINT id = processes[i];
		HANDLE h = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
			false, id);

		if (h != NULL)
		{
			HINSTANCE hInst = NULL;
			DWORD needed;
			char exe[MAX_SIZE];
			wchar_t exe_w[MAX_SIZE];
			bool ok = false;
			DWORD sz1, sz2;

			sz1 = sizeof(exe) - 1;
			sz2 = sizeof(exe_w) / sizeof(wchar_t) - 1;

			if (EnumProcessModules(h, &hInst, sizeof(hInst), &needed) == false)
			{
				hInst = NULL;
			}

			if (GetModuleFileNameExA(h, hInst, exe, sizeof(exe) - 1) &&
				GetModuleFileNameExW(h, hInst, exe_w, sizeof(exe_w) / sizeof(wchar_t) - 1))
			{
				ok = true;
			}
			else if (QueryFullProcessImageNameA(h, 0, exe, &sz1) &&
				QueryFullProcessImageNameW(h, 0, exe_w, &sz2))
			{
				ok = true;
			}

			if (ok)
			{
				MS_PROCESS *p = ZeroMalloc(sizeof(MS_PROCESS));

				StrCpy(p->ExeFilename, sizeof(p->ExeFilename), exe);
				UniStrCpy(p->ExeFilenameW, sizeof(p->ExeFilenameW), exe_w);
				p->ProcessId = id;

				Add(o, p);
			}

			CloseHandle(h);
		}
	}

	Sort(o);

	Free(processes);

	return o;
}

LIST *MsGetProcessList()
{
	return MsGetProcessListNt();
}

LRESULT CALLBACK MsUserModeWindowProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
	if (hWnd == NULL)
	{
		return 0;
	}

	switch (msg)
	{
	case WM_ENDSESSION:
		if (wParam == false)
		{
			break;
		}
	case WM_CREATE:
		exiting = false;
		g_start();
		break;
	case WM_QUERYENDSESSION:
		if (exiting == false)
		{
			exiting = true;
			g_stop();
			DestroyWindow(hWnd);
		}
		return TRUE;
	case WM_CLOSE:
		if (exiting == false)
		{
			exiting = true;
			g_stop();
			DestroyWindow(hWnd);
		}
		break;
	case WM_DESTROY:
		wnd_end = true;
		break;
	}
	return DefWindowProc(hWnd, msg, wParam, lParam);
}

bool MsIsUserMode()
{
	return is_usermode;
}

void *MsCreateUserModeSvcGlocalPulse(char *svc_name)
{
	char name[MAX_SIZE];
	if (svc_name == NULL)
	{
		return NULL;
	}

	MsGenerateUserModeSvcGlobalPulseName(name, sizeof(name), svc_name);

	return MsOpenOrCreateGlobalPulse(name);
}

void MsGenerateUserModeSvcGlobalPulseName(char *name, UINT size, char *svc_name)
{
	wchar_t tmp[MAX_SIZE];
	UCHAR hash[SHA1_SIZE];
	if (name == NULL || svc_name == NULL)
	{
		return;
	}

	UniFormat(tmp, sizeof(tmp), L"usersvc_%S_@_%s", svc_name, MsGetUserNameW());

	UniTrim(tmp);
	UniStrUpper(tmp);

	Sha1(hash, tmp, UniStrLen(tmp) * sizeof(wchar_t));

	BinToStr(name, size, hash, sizeof(hash));
}

void MsUserModeW(wchar_t *title, SERVICE_FUNCTION *start, SERVICE_FUNCTION *stop, UINT icon)
{
	WNDCLASS wc;
	HWND hWnd;
	MSG msg;
	INSTANCE *inst;
	char title_a[MAX_PATH];
	wchar_t msg_str[MAX_SIZE];
	MS_USERMODE_SVC_PULSE_THREAD_PARAM p;
	THREAD *recv_thread = NULL;
	if (title == NULL || start == NULL || stop == NULL)
	{
		return;
	}

	UniToStr(title_a, sizeof(title_a), title);

	is_usermode = true;
	g_start = start;
	g_stop = stop;

	inst = NewSingleInstance(NULL);
	if (inst == NULL)
	{
		UniFormat(msg_str, sizeof(msg_str), _UU("SVC_USERMODE_MUTEX"), ms->ExeFileNameW);
		UniPrint(L"%s\n", msg_str);
		return;
	}

	Zero(&wc, sizeof(wc));
	wc.hbrBackground = (HBRUSH)GetStockObject(WHITE_BRUSH);
	wc.hCursor = LoadCursor(NULL,IDC_ARROW);
	wc.hInstance = ms->hInst;
	wc.lpfnWndProc = MsUserModeWindowProc;
	wc.lpszClassName = title_a;
	if (RegisterClass(&wc) == 0)
	{
		return;
	}

	hWnd = CreateWindow(title_a, title_a, WS_OVERLAPPEDWINDOW,
		CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT,
		NULL, NULL, ms->hInst, NULL);

	if (hWnd == NULL)
	{
		return;
	}

	Zero(&p, sizeof(p));
	p.hWnd = hWnd;
	p.GlobalPulse = MsCreateUserModeSvcGlocalPulse(g_service_name);

	if (p.GlobalPulse != NULL)
	{
		p.Halt = false;

		recv_thread = NewThread(MsUserModeGlobalPulseRecvThread, &p);
	}

	hWndUsermode = hWnd;

	wnd_end = false;
	while (wnd_end == false)
	{
		GetMessage(&msg, NULL, 0, 0);
		TranslateMessage(&msg);
		DispatchMessage(&msg);
	}

	FreeSingleInstance(inst);

	p.hWnd = NULL;

	hWndUsermode = NULL;

	if (p.GlobalPulse != NULL)
	{
		p.Halt = true;
		MsSendGlobalPulse(p.GlobalPulse);

		WaitThread(recv_thread, INFINITE);
		ReleaseThread(recv_thread);

		MsCloseGlobalPulse(p.GlobalPulse);
	}

	_exit(0);
}

void MsUserModeGlobalPulseRecvThread(THREAD *thread, void *param)
{
	MS_USERMODE_SVC_PULSE_THREAD_PARAM *p = (MS_USERMODE_SVC_PULSE_THREAD_PARAM *)param;
	if (thread == NULL || p == NULL)
	{
		return;
	}

	while (p->Halt == false)
	{
		if (MsWaitForGlobalPulse(p->GlobalPulse, INFINITE))
		{
			break;
		}
	}

	if (p->hWnd != NULL)
	{
		PostMessageA(p->hWnd, WM_CLOSE, 0, 0);
	}
}

void MsServiceStoperMainThread(THREAD *t, void *p)
{
	g_stop();
}

bool MsServiceStopProc()
{
	THREAD *thread;
	bool ret = true;
	UINT64 selfkill_timeout = Tick64() + SVC_SELFKILL_TIMEOUT;

	thread = NewThread(MsServiceStoperMainThread, NULL);

	while (WaitThread(thread, 250) == false)
	{
		if (Tick64() >= selfkill_timeout)
		{
			ret = false;
			break;
		}
		status.dwWin32ExitCode = 0;
		status.dwWaitHint = 100000;
		status.dwCheckPoint++;
		status.dwCurrentState = SERVICE_STOP_PENDING;
		_SetServiceStatus(ssh, &status);
	}

	status.dwWin32ExitCode = 0;
	status.dwWaitHint = 0;
	status.dwCheckPoint = 0;
	status.dwCurrentState = SERVICE_STOPPED;
	_SetServiceStatus(ssh, &status);

	if (ret == false)
	{
		// The self-kill timeout fired: force an exit
		_exit(-1);
	}
	else
	{
		ReleaseThread(thread);
	}

	return ret;
}

void CALLBACK MsServiceHandler(DWORD opcode)
{
	switch (opcode)
	{
	case SERVICE_CONTROL_SHUTDOWN:
	case SERVICE_CONTROL_STOP:
		status.dwWin32ExitCode = 0;
		status.dwWaitHint = 100000;
		status.dwCheckPoint = 0;
		status.dwCurrentState = SERVICE_STOP_PENDING;

		if (service_stop_event != NULL)
		{
			SetEvent(service_stop_event);
		}
		break;
	}

	_SetServiceStatus(ssh, &status);
}

void CALLBACK MsServiceDispatcher(DWORD argc, LPTSTR *argv)
{
	service_stop_event = CreateEventA(NULL, true, false, NULL);

	Zero(&status, sizeof(status));
	status.dwServiceType = SERVICE_WIN32;
	status.dwCurrentState = SERVICE_START_PENDING;
	status.dwControlsAccepted = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN;

	ssh = _RegisterServiceCtrlHandler(g_service_name, MsServiceHandler);

	if (ssh == NULL)
	{
		MessageBox(NULL, "RegisterServiceCtrlHandler() Failed.", "MsServiceDispatcher()", MB_SETFOREGROUND | MB_TOPMOST | MB_SERVICE_NOTIFICATION | MB_OK | MB_ICONEXCLAMATION);
		return;
	}

	status.dwWaitHint = 300000;
	status.dwCheckPoint = 0;
	status.dwCheckPoint++;
	status.dwCurrentState = SERVICE_START_PENDING;
	_SetServiceStatus(ssh, &status);

	status.dwWaitHint = 0;
	status.dwCheckPoint = 0;
	status.dwCurrentState = SERVICE_RUNNING;
	_SetServiceStatus(ssh, &status);

#if defined(_DEBUG) || defined(DEBUG)	// In VC++ compilers, the macro is "_DEBUG", not "DEBUG".
	// memcheck = true logs every malloc/realloc/free to find leaks, but is very slow.
	InitMayaqua(false, true, 0, NULL);
#else
	InitMayaqua(false, false, 0, NULL);
#endif

	MsDisableIme();

	g_start();
	MsUpdateServiceConfig(g_service_name);

	WaitForSingleObject(service_stop_event, INFINITE);

	MsServiceStopProc();
}

void MsTestModeW(wchar_t *title, SERVICE_FUNCTION *start, SERVICE_FUNCTION *stop)
{
	INSTANCE *inst;
	wchar_t msg[MAX_SIZE];
	if (title == NULL || start == NULL || stop == NULL)
	{
		return;
	}

	is_usermode = true;

	inst = NewSingleInstance(NULL);
	if (inst == NULL)
	{
		UniFormat(msg, sizeof(msg), _UU("SVC_TEST_MUTEX"), ms->ExeFileNameW);
		UniPrint(L"%s\n", msg);
		return;
	}

	start();

	UniFormat(msg, sizeof(msg), _UU("SVC_TEST_MSG"), title);
	UniPrint(L"%s\n", msg);
	GetLine(NULL, 0);

	stop();

	FreeSingleInstance(inst);
}

void MsWriteCallingServiceManagerProcessId(char *svcname, UINT pid)
{
	char tmp[MAX_PATH];

	Format(tmp, sizeof(tmp), SVC_CALLING_SM_PROCESS_ID_KEY, svcname);

	if (pid != 0)
	{
		MsRegWriteInt(REG_LOCAL_MACHINE, tmp, SVC_CALLING_SM_PROCESS_ID_VALUE, pid);
		MsRegWriteInt(REG_CURRENT_USER, tmp, SVC_CALLING_SM_PROCESS_ID_VALUE, pid);
	}
	else
	{
		MsRegDeleteValue(REG_LOCAL_MACHINE, tmp, SVC_CALLING_SM_PROCESS_ID_VALUE);
		MsRegDeleteKeyEx2(REG_LOCAL_MACHINE, tmp, false, false);

		MsRegDeleteValue(REG_CURRENT_USER, tmp, SVC_CALLING_SM_PROCESS_ID_VALUE);
		MsRegDeleteKeyEx2(REG_CURRENT_USER, tmp, false, false);
	}
}

UINT MsService(char *name, SERVICE_FUNCTION *start, SERVICE_FUNCTION *stop, UINT icon, char *cmd_line)
{
	UINT mode;
	UINT ret = 0;
	char *arg;
	TOKEN_LIST *t = NULL;
	char *service_name;
	wchar_t *service_title;
	wchar_t *service_description;
	char tmp[MAX_SIZE];
	wchar_t msg[MAX_SIZE * 4];
	bool restoreReg = false;
	bool silent = false;
	bool is_win32_service_mode = false;
	if (name == NULL || start == NULL || stop == NULL)
	{
		return ret;
	}

	g_start = start;
	g_stop = stop;
	StrCpy(g_service_name, sizeof(g_service_name), name);
	StrLower(g_service_name);

	if (cmd_line != NULL && lstrcmpiA(cmd_line, SVC_ARG_SERVICE) == 0)
	{
		HINSTANCE h_advapi32 = LoadLibraryA("advapi32.dll");

		if (h_advapi32 != NULL)
		{
			_StartServiceCtrlDispatcher =
				(BOOL (__stdcall *)(const LPSERVICE_TABLE_ENTRY))
				GetProcAddress(h_advapi32, "StartServiceCtrlDispatcherW");

			_RegisterServiceCtrlHandler =
				(SERVICE_STATUS_HANDLE (__stdcall *)(LPCTSTR,LPHANDLER_FUNCTION))
				GetProcAddress(h_advapi32, "RegisterServiceCtrlHandlerW");

			_SetServiceStatus =
				(BOOL (__stdcall *)(SERVICE_STATUS_HANDLE,LPSERVICE_STATUS))
				GetProcAddress(h_advapi32, "SetServiceStatus");

			if (_StartServiceCtrlDispatcher != NULL &&
				_RegisterServiceCtrlHandler != NULL && 
				_SetServiceStatus != NULL)
			{
				is_win32_service_mode = true;
			}
		}
	}

	if (is_win32_service_mode)
	{
		SERVICE_TABLE_ENTRY dispatch_table[] =
		{
			{"", MsServiceDispatcher},
			{NULL, NULL},
		};

		SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX | SEM_NOOPENFILEERRORBOX);

		if (_StartServiceCtrlDispatcher(dispatch_table) == false)
		{
			MessageBox(NULL, "StartServiceCtrlDispatcher() Failed.", "MsServiceMode()", MB_SETFOREGROUND | MB_TOPMOST | MB_SERVICE_NOTIFICATION | MB_OK | MB_ICONEXCLAMATION);
		}
		else
		{
			MsUpdateServiceConfig(g_service_name);
		}

		_exit(0);
		return 0;
	}

#if defined(_DEBUG) || defined(DEBUG)	// In VC++ compilers, the macro is "_DEBUG", not "DEBUG".
	// memcheck = true logs every malloc/realloc/free to find leaks, but is very slow.
	InitMayaqua(false, true, 0, NULL);
#else
	InitMayaqua(false, false, 0, NULL);
#endif

	MsDisableIme();

	Format(tmp, sizeof(tmp), SVC_NAME, name);
	service_name = _SS(tmp);
	Format(tmp, sizeof(tmp), SVC_TITLE, name);
	service_title = _UU(tmp);
	Format(tmp, sizeof(tmp), SVC_DESCRIPT, name);
	service_description = _UU(tmp);

	if (StrLen(service_name) == 0 || UniStrLen(service_title) == 0)
	{
		UniFormat(msg, sizeof(msg), _UU("SVC_NOT_FOUND"), name);
		UniPrint(L"%s\n", msg);
	}
	else
	{
		wchar_t path[MAX_SIZE];
		mode = SVC_MODE_NONE;

		t = GetCommandLineToken();
		arg = NULL;

		if (t->NumTokens >= 1)
		{
			arg = t->Token[0];
		}
		if(t->NumTokens >= 2)
		{
			if(StrCmpi(t->Token[1], SVC_ARG_SILENT) == 0)
			{
				silent = true;
			}
		}

		if (arg != NULL)
		{
			if (StrCmpi(arg, SVC_ARG_INSTALL) == 0)
			{
				mode = SVC_MODE_INSTALL;
			}
			if (StrCmpi(arg, SVC_ARG_UNINSTALL) == 0)
			{
				mode = SVC_MODE_UNINSTALL;
			}
			if (StrCmpi(arg, SVC_ARG_START) == 0)
			{
				mode = SVC_MODE_START;
			}
			if (StrCmpi(arg, SVC_ARG_STOP) == 0)
			{
				mode = SVC_MODE_STOP;
			}
			if (StrCmpi(arg, SVC_ARG_TEST) == 0)
			{
				mode = SVC_MODE_TEST;
			}
			if (StrCmpi(arg, SVC_ARG_USERMODE) == 0)
			{
				mode = SVC_MODE_USERMODE;
			}
			if (StrCmpi(arg, SVC_ARG_SETUP_INSTALL) == 0)
			{
				mode = SVC_MODE_SETUP_INSTALL;
			}
			if (StrCmpi(arg, SVC_ARG_SETUP_UNINSTALL) == 0)
			{
				mode = SVC_MODE_SETUP_UNINSTALL;
			}
			if (StrCmpi(arg, SVC_ARG_USERMODE_SHOWTRAY) == 0 || StrCmpi(arg, SVC_ARG_USERMODE_HIDETRAY) == 0)
			{
				// Legacy arguments: there is no task tray icon any more, so these are the same as /usermode
				mode = SVC_MODE_USERMODE;
			}
			if (StrCmpi(arg, SVC_ARG_SERVICE) == 0)
			{
				mode = SVC_MODE_SERVICE;
			}

			if (mode != SVC_MODE_NONE)
			{
				MsInitGlobalNetworkConfig();
			}
		}

		UniFormat(path, sizeof(path), SVC_RUN_COMMANDLINE, ms->ExeFileNameW);

		if ((mode == SVC_MODE_INSTALL || mode == SVC_MODE_UNINSTALL || mode == SVC_MODE_START ||
			mode == SVC_MODE_STOP || mode == SVC_MODE_SERVICE) &&
			(ms->IsAdmin == false))
		{
			UniPrint(L"%s\n", _UU("SVC_NOT_ADMIN"));
		}
		else
		{
			switch (mode)
			{
			case SVC_MODE_NONE:
				UniFormat(msg, sizeof(msg), _UU("SVC_HELP"),
					service_title, service_name, service_title, service_title, service_name, service_title, service_name, service_title, service_name, service_title, service_name, service_title, service_title);
				UniPrint(L"%s\n", msg);
				break;

			case SVC_MODE_SETUP_INSTALL:
				MsWriteCallingServiceManagerProcessId(service_name, MsGetCurrentProcessId());
				restoreReg = true;

				if (MsIsServiceInstalled(service_name))
				{
					if (MsIsServiceRunning(service_name))
					{
						MsStopService(service_name);
					}
					MsUninstallService(service_name);
				}
				if (MsInstallServiceExW(service_name, service_title, service_description, path, NULL) == false)
				{
					ret = 1;
				}
				MsStartService(service_name);
				MsWriteCallingServiceManagerProcessId(service_name, 0);
				break;

			case SVC_MODE_SETUP_UNINSTALL:
				MsWriteCallingServiceManagerProcessId(service_name, MsGetCurrentProcessId());
				restoreReg = true;

				if (MsIsServiceInstalled(service_name))
				{
					if (MsIsServiceRunning(service_name))
					{
						MsStopService(service_name);
					}
					if (MsUninstallService(service_name) == false)
					{
						ret = 1;
					}
				}
				break;

			case SVC_MODE_INSTALL:
				MsWriteCallingServiceManagerProcessId(service_name, MsGetCurrentProcessId());
				restoreReg = true;

				if (MsIsServiceInstalled(service_name))
				{
					if(silent == true)
					{
						break;
					}
					// The operator explicitly requested /install, so uninstall and then re-install
					UniFormat(msg, sizeof(msg), _UU("SVC_ALREADY_INSTALLED"),
						service_title, service_name);
					UniPrint(L"%s\n", msg);

					if (MsIsServiceRunning(service_name))
					{
						if (MsStopService(service_name) == false)
						{
							if(silent == false)
							{
								UniFormat(msg, sizeof(msg), _UU("SVC_STOP_FAILED"),
									service_title, service_name);
								UniPrint(L"%s\n", msg);
							}
							break;
						}
					}
					if (MsUninstallService(service_name) == false)
					{
						if(silent == false)
						{
							UniFormat(msg, sizeof(msg), _UU("SVC_UNINSTALL_FAILED"),
								service_title, service_name);
							UniPrint(L"%s\n", msg);
						}
						break;
					}
				}

				if (MsInstallServiceExW(service_name, service_title, service_description, path, NULL) == false)
				{
					if(silent == false)
					{
						UniFormat(msg, sizeof(msg), _UU("SVC_INSTALL_FAILED"),
							service_title, service_name);
						UniPrint(L"%s\n", msg);
					}
					break;
				}

				if (MsStartService(service_name) == false)
				{
					if(silent == false)
					{
						UniFormat(msg, sizeof(msg), _UU("SVC_INSTALL_FAILED_2"),
							service_title, service_name, path);
						UniPrint(L"%s\n", msg);
					}
					break;
				}

				if(silent == false)
				{
					UniFormat(msg, sizeof(msg), _UU("SVC_INSTALL_OK"),
						service_title, service_name, path);
					UniPrint(L"%s\n", msg);
				}
				break;

			case SVC_MODE_UNINSTALL:
				MsWriteCallingServiceManagerProcessId(service_name, MsGetCurrentProcessId());
				restoreReg = true;

				if (MsIsServiceInstalled(service_name) == false)
				{
					if(silent == false)
					{
						UniFormat(msg, sizeof(msg), _UU("SVC_NOT_INSTALLED"),
							service_title, service_name, path);
						UniPrint(L"%s\n", msg);
					}
					break;
				}

				if (MsIsServiceRunning(service_name))
				{
					if (MsStopService(service_name) == false)
					{
						if(silent == false)
						{
							UniFormat(msg, sizeof(msg), _UU("SVC_STOP_FAILED"),
								service_title, service_name);
							UniPrint(L"%s\n", msg);
						}
						break;
					}
				}

				if (MsUninstallService(service_name) == false)
				{
					if(silent == false)
					{
						UniFormat(msg, sizeof(msg), _UU("SVC_UNINSTALL_FAILED"),
							service_title, service_name);
						UniPrint(L"%s\n", msg);
					}
					break;
				}

				if(silent == false)
				{
					UniFormat(msg, sizeof(msg), _UU("SVC_UNINSTALL_OK"),
						service_title, service_name);
					UniPrint(L"%s\n", msg);
				}
				break;

			case SVC_MODE_START:
				MsWriteCallingServiceManagerProcessId(service_name, MsGetCurrentProcessId());
				restoreReg = true;

				if (MsIsServiceInstalled(service_name) == false)
				{
					if(silent == false)
					{
						UniFormat(msg, sizeof(msg), _UU("SVC_NOT_INSTALLED"),
							service_title, service_name);
						UniPrint(L"%s\n", msg);
					}
					break;
				}

				if (MsIsServiceRunning(service_name))
				{
					if(silent == false)
					{
						UniFormat(msg, sizeof(msg), _UU("SVR_ALREADY_START"),
							service_title, service_name);
						UniPrint(L"%s\n", msg);
					}
					break;
				}

				if (MsStartService(service_name) == false)
				{
					if(silent == false)
					{
						UniFormat(msg, sizeof(msg), _UU("SVC_START_FAILED"),
							service_title, service_name);
						UniPrint(L"%s\n", msg);
					}
					break;
				}

				if(silent == false)
				{
					UniFormat(msg, sizeof(msg), _UU("SVC_START_OK"),
						service_title, service_name);
					UniPrint(L"%s\n", msg);
				}
				break;

			case SVC_MODE_STOP:
				MsWriteCallingServiceManagerProcessId(service_name, MsGetCurrentProcessId());
				restoreReg = true;

				if (MsIsServiceInstalled(service_name) == false)
				{
					if(silent == false)
					{
						UniFormat(msg, sizeof(msg), _UU("SVC_NOT_INSTALLED"),
							service_title, service_name);
						UniPrint(L"%s\n", msg);
					}
					break;
				}

				if (MsIsServiceRunning(service_name) == false)
				{
					if(silent == false)
					{
					UniFormat(msg, sizeof(msg), _UU("SVC_ALREADY_STOP"),
						service_title, service_name);
					UniPrint(L"%s\n", msg);
					}
					break;
				}
				if (MsStopService(service_name) == false)
				{
					if(silent == false)
					{
						UniFormat(msg, sizeof(msg), _UU("SVC_STOP_FAILED"),
							service_title, service_name);
						UniPrint(L"%s\n", msg);
					}
					break;
				}

				if(silent == false)
				{
					UniFormat(msg, sizeof(msg), _UU("SVC_STOP_OK"),
						service_title, service_name);
					UniPrint(L"%s\n", msg);
				}
				break;

			case SVC_MODE_TEST:
				MsTestModeW(service_title, start, stop);
				break;
			case SVC_MODE_USERMODE:
				MsUserModeW(service_title, start, stop, icon);
				break;
			case SVC_MODE_SERVICE:
				break;
			}

		}
		FreeToken(t);

		if (restoreReg)
		{
			MsWriteCallingServiceManagerProcessId(service_name, 0);
		}
	}

	FreeMayaqua();

	return 0;
}

bool MsStopService(char *name)
{
	SC_HANDLE sc, service;
	bool ret = false;
	if (name == NULL)
	{
		return false;
	}

	sc = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
	if (sc == NULL)
	{
		return false;
	}

	service = OpenService(sc, name, SERVICE_ALL_ACCESS);
	if (service != NULL)
	{
		SERVICE_STATUS st;
		ret = ControlService(service, SERVICE_CONTROL_STOP, &st);

		CloseServiceHandle(service);
	}

	if (ret)
	{
		UINT64 end = Tick64() + 10000ULL;
		while (Tick64() < end)
		{
			if (MsIsServiceRunning(name) == false)
			{
				break;
			}

			SleepThread(250);
		}
	}

	CloseServiceHandle(sc);
	return ret;
}

bool MsStartService(char *name)
{
	return MsStartServiceEx(name, NULL);
}
bool MsStartServiceEx(char *name, UINT *error_code)
{
	SC_HANDLE sc, service;
	bool ret = false;
	static UINT dummy = 0;
	if (name == NULL)
	{
		return false;
	}

	if (error_code == NULL)
	{
		error_code = &dummy;
	}

	*error_code = 0;

	sc = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
	if (sc == NULL)
	{
		*error_code = GetLastError();
		return false;
	}

	service = OpenService(sc, name, SERVICE_ALL_ACCESS);
	if (service != NULL)
	{
		ret = StartService(service, 0, NULL);

		CloseServiceHandle(service);
	}
	else
	{
		*error_code = GetLastError();
	}

	if (ret)
	{
		UINT64 end = Tick64() + 10000ULL;
		while (Tick64() < end)
		{
			if (MsIsServiceRunning(name))
			{
				break;
			}

			SleepThread(250);
		}
	}

	CloseServiceHandle(sc);
	return ret;
}

bool MsIsServiceRunning(char *name)
{
	SC_HANDLE sc, service;
	bool ret = false;
	if (name == NULL || IsEmptyStr(name))
	{
		return false;
	}

	sc = OpenSCManager(NULL, NULL, GENERIC_READ);
	if (sc == NULL)
	{
		return false;
	}

	service = OpenService(sc, name, GENERIC_READ);
	if (service != NULL)
	{
		SERVICE_STATUS st;
		Zero(&st, sizeof(st));
		if (QueryServiceStatus(service, &st))
		{
			switch (st.dwCurrentState)
			{
			case SERVICE_CONTINUE_PENDING:
			case SERVICE_PAUSE_PENDING:
			case SERVICE_PAUSED:
			case SERVICE_RUNNING:
			case SERVICE_START_PENDING:
			case SERVICE_STOP_PENDING:
				ret = true;
				break;
			}
		}

		CloseServiceHandle(service);
	}

	CloseServiceHandle(sc);
	return ret;
}

bool MsUninstallService(char *name)
{
	SC_HANDLE sc, service;
	bool ret = false;
	if (name == NULL)
	{
		return false;
	}

	MsStopService(name);

	sc = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
	if (sc == NULL)
	{
		return false;
	}

	service = OpenService(sc, name, SERVICE_ALL_ACCESS);
	if (service != NULL)
	{
		if (DeleteService(service))
		{
			ret = true;
		}
		CloseServiceHandle(service);
	}

	CloseServiceHandle(sc);

	if (ret)
	{
		SleepThread(2000);
	}

	return ret;
}

bool MsUpdateServiceConfig(char *name)
{
	SC_HANDLE sc, service;
	if (name == NULL)
	{
		return false;
	}

	// Shortly after Windows startup (prevents a deadlock)
	if (timeGetTime() <= (60 * 30 * 1000))
	{
		if (MsRegReadInt(REG_LOCAL_MACHINE, "Software\\" GC_REG_COMPANY_NAME "\\Update Service Config", name) != 0)
		{
			return false;
		}
	}

	sc = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
	if (sc == NULL)
	{
		return false;
	}

	service = OpenService(sc, name, SERVICE_ALL_ACCESS);
	if (service != NULL)
	{
		if (GET_KETA(GetOsInfo()->OsType, 100) >= 2)
		{
			SERVICE_FAILURE_ACTIONS action;
			SC_ACTION *e;
			Zero(&action, sizeof(action));
			e = ZeroMalloc(sizeof(SC_ACTION) * 3);
			e[0].Delay = 10000; e[0].Type = SC_ACTION_RESTART;
			e[1].Delay = 10000; e[1].Type = SC_ACTION_RESTART;
			e[2].Delay = 10000; e[2].Type = SC_ACTION_RESTART;
			action.cActions = 3;
			action.lpsaActions = e;
			action.dwResetPeriod = 1 * 60 * 60 * 24;
			ChangeServiceConfig2(service, SERVICE_CONFIG_FAILURE_ACTIONS, &action);

			MsRegWriteInt(REG_LOCAL_MACHINE, "Software\\" GC_REG_COMPANY_NAME "\\Update Service Config", name, 1);
		}

		
		if (GET_KETA(GetOsInfo()->OsType, 100) >= 2)
		{
			SERVICE_DESCRIPTIONW d;
			wchar_t *description;
			char dname[MAX_SIZE];

			Format(dname, sizeof(dname), "SVC_%s_DESCRIPT", name);

			description = _UU(dname);

			if (UniIsEmptyStr(description) == false)
			{
				Zero(&d, sizeof(d));
				d.lpDescription = description;
				ChangeServiceConfig2(service, SERVICE_CONFIG_DESCRIPTION, &d);
			}
		}

		CloseServiceHandle(service);
	}

	CloseServiceHandle(sc);

	return true;
}

bool MsInstallServiceExW(char *name, wchar_t *title, wchar_t *description, wchar_t *path, UINT *error_code)
{
	SC_HANDLE sc, service;
	bool ret = false;
	wchar_t name_w[MAX_SIZE];
	static UINT temp_int = 0;
	if (name == NULL || title == NULL || path == NULL)
	{
		return false;
	}

	if (error_code == NULL)
	{
		error_code = &temp_int;
	}

	*error_code = 0;

	StrToUni(name_w, sizeof(name_w), name);

	sc = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
	if (sc == NULL)
	{
		*error_code = GetLastError();
		return false;
	}

	service = CreateServiceW(sc, name_w, title, SERVICE_ALL_ACCESS,
		SERVICE_WIN32_OWN_PROCESS, SERVICE_AUTO_START,
		SERVICE_ERROR_NORMAL, path, NULL, NULL, NULL, NULL, NULL);

	if (service != NULL)
	{
		ret = true;

		if (GET_KETA(GetOsInfo()->OsType, 100) >= 2)
		{
			SERVICE_DESCRIPTIONW d;
			SERVICE_FAILURE_ACTIONS action;
			SC_ACTION *e;
			Zero(&d, sizeof(d));
			d.lpDescription = description;
			ChangeServiceConfig2(service, SERVICE_CONFIG_DESCRIPTION, &d);
			Zero(&action, sizeof(action));
			e = ZeroMalloc(sizeof(SC_ACTION) * 3);
			e[0].Delay = 10000; e[0].Type = SC_ACTION_RESTART;
			e[1].Delay = 10000; e[1].Type = SC_ACTION_RESTART;
			e[2].Delay = 10000; e[2].Type = SC_ACTION_RESTART;
			action.cActions = 3;
			action.lpsaActions = e;
			action.dwResetPeriod = 1 * 60 * 60 * 24;
			ChangeServiceConfig2(service, SERVICE_CONFIG_FAILURE_ACTIONS, &action);

			Free(e);
		}

		CloseServiceHandle(service);
	}
	else
	{
		*error_code = GetLastError();
	}

	CloseServiceHandle(sc);

	if (ret)
	{
		SleepThread(2000);
	}

	return ret;
}

bool MsIsServiceInstalled(char *name)
{
	SC_HANDLE sc;
	SC_HANDLE service;
	bool ret = false;
	if (name == NULL)
	{
		return false;
	}

	sc = OpenSCManager(NULL, NULL, GENERIC_READ);
	if (sc == NULL)
	{
		return false;
	}

	service = OpenService(sc, name, GENERIC_READ);
	if (service != NULL)
	{
		ret = true;
	}

	CloseServiceHandle(service);
	CloseServiceHandle(sc);

	return ret;
}

void MsSetThreadPriorityIdle()
{
	SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_IDLE);
}

void MsSetThreadPriorityRealtime()
{
	SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_ABOVE_NORMAL);
	SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_HIGHEST);
	SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_TIME_CRITICAL);
}

void MsRestoreThreadPriority()
{
	SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_NORMAL);
}

void MsApplyTcpConfig()
{
	if (MsIsAdmin())
	{
		MS_TCP tcp;

		if (MsLoadTcpConfigReg(&tcp))
		{
			MsSetTcpConfig(&tcp);
		}
	}
}

bool MsLoadTcpConfigReg(MS_TCP *tcp)
{
	if (tcp == NULL)
	{
		return false;
	}

	Zero(tcp, sizeof(MS_TCP));

	if (MsRegIsValueEx2(REG_LOCAL_MACHINE, MS_REG_TCP_SETTING_KEY, "RecvWindowSize", true, false) == false ||
		MsRegIsValueEx2(REG_LOCAL_MACHINE, MS_REG_TCP_SETTING_KEY, "SendWindowSize", true, false) == false)
	{
		return false;
	}

	tcp->RecvWindowSize = MsRegReadIntEx2(REG_LOCAL_MACHINE, MS_REG_TCP_SETTING_KEY, "RecvWindowSize", true, false);
	tcp->SendWindowSize = MsRegReadIntEx2(REG_LOCAL_MACHINE, MS_REG_TCP_SETTING_KEY, "SendWindowSize", true, false);

	return true;
}

void MsSetTcpConfig(MS_TCP *tcp)
{
	if (tcp == NULL)
	{
		return;
	}

	if (MsIsAdmin())
	{
		bool window_scaling = false;
		UINT tcp1323opts;

		if (tcp->RecvWindowSize >= 65536 || tcp->SendWindowSize >= 65536)
		{
			window_scaling = true;
		}

		tcp1323opts = MsRegReadInt(REG_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters", "Tcp1323Opts");
		if (window_scaling)
		{
			if (tcp1323opts == 0)
			{
				tcp1323opts = 1;
			}
			if (tcp1323opts == 2)
			{
				tcp1323opts = 3;
			}
		}
		else
		{
			if (tcp1323opts == 1)
			{
				tcp1323opts = 0;
			}
			if (tcp1323opts == 3)
			{
				tcp1323opts = 2;
			}
		}
		MsRegWriteInt(REG_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters", "Tcp1323Opts", tcp1323opts);

		if (tcp->RecvWindowSize == 0)
		{
			MsRegDeleteValue(REG_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\AFD\\Parameters",
				"DefaultReceiveWindow");
			MsRegDeleteValue(REG_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters",
				"TcpWindowSize");
			MsRegDeleteValue(REG_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters",
				"GlobalMaxTcpWindowSize");
		}
		else
		{
			MsRegWriteInt(REG_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\AFD\\Parameters",
				"DefaultReceiveWindow", tcp->RecvWindowSize);
			MsRegWriteInt(REG_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters",
				"TcpWindowSize", tcp->RecvWindowSize);
			MsRegWriteInt(REG_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters",
				"GlobalMaxTcpWindowSize", tcp->RecvWindowSize);
		}

		if (tcp->SendWindowSize == 0)
		{
			MsRegDeleteValue(REG_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\AFD\\Parameters",
				"DefaultSendWindow");
		}
		else
		{
			MsRegWriteInt(REG_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\AFD\\Parameters",
				"DefaultSendWindow", tcp->SendWindowSize);
		}
	}
}

void MsInitGlobalNetworkConfig()
{
	UINT current_window_size = MsRegReadInt(REG_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters", "TcpWindowSize");

	if (current_window_size == 65535 || current_window_size == 5980160 ||
		current_window_size == 16777216 || current_window_size == 16777214)
	{
		// Remove a stray value that old PacketiX VPN versions wrote
		MsRegDeleteValue(REG_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\AFD\\Parameters",
			"DefaultReceiveWindow");
		MsRegDeleteValue(REG_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\AFD\\Parameters",
			"DefaultSendWindow");
		MsRegDeleteValue(REG_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters",
			"Tcp1323Opts");
		MsRegDeleteValue(REG_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters",
			"TcpWindowSize");
		MsRegDeleteValue(REG_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters",
			"GlobalMaxTcpWindowSize");

		MsRegWriteInt(REG_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters", "vpn_no_change", 1);
		MsRegWriteInt(REG_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\AFD\\Parameters", "vpn_no_change", 1);
	}

	MsApplyTcpConfig();
}

BOOL CALLBACK MsEnumChildWindowProc(HWND hWnd, LPARAM lParam)
{
	LIST *o = (LIST *)lParam;

	if (o != NULL)
	{
		MsEnumChildWindows(o, hWnd);
	}

	return true;
}

LIST *MsEnumChildWindows(LIST *o, HWND hWnd)
{
	if (hWnd == NULL)
	{
		return NULL;
	}

	if (o == NULL)
	{
		o = NewListFast(NULL);
	}

	MsAddWindowToList(o, hWnd);

	EnumChildWindows(hWnd, MsEnumChildWindowProc, (LPARAM)o);

	return o;
}

void MsAddWindowToList(LIST *o, HWND hWnd)
{
	if (o == NULL || hWnd == NULL)
	{
		return;
	}

	if (IsInList(o, hWnd) == false)
	{
		Add(o, hWnd);
	}
}

BOOL CALLBACK EnumTopWindowProc(HWND hWnd, LPARAM lParam)
{
	LIST *o = (LIST *)lParam;
	HWND hParent;
	char c1[MAX_SIZE], c2[MAX_SIZE];
	if (hWnd == NULL || o == NULL)
	{
		return TRUE;
	}

	Zero(c1, sizeof(c1));
	Zero(c2, sizeof(c2));

	hParent = GetParent(hWnd);

	GetClassName(hWnd, c1, sizeof(c1));

	if (hParent != NULL)
	{
		GetClassName(hParent, c2, sizeof(c2));
	}

	if (StrCmpi(c1, "SysIPAddress32") != 0 && (IsEmptyStr(c2) || StrCmpi(c2, "SysIPAddress32") != 0))
	{
		AddWindow(o, hWnd);
	}

	return TRUE;
}

BOOL CALLBACK EnumChildWindowProc(HWND hWnd, LPARAM lParam)
{
	ENUM_CHILD_WINDOW_PARAM *p = (ENUM_CHILD_WINDOW_PARAM *)lParam;
	LIST *o;
	HWND hParent;
	char c1[MAX_SIZE], c2[MAX_SIZE];
	bool ok = false;
	if (hWnd == NULL || p == NULL)
	{
		return TRUE;
	}

	o = p->o;

	Zero(c1, sizeof(c1));
	Zero(c2, sizeof(c2));

	hParent = GetParent(hWnd);

	GetClassName(hWnd, c1, sizeof(c1));

	if (hParent != NULL)
	{
		GetClassName(hParent, c2, sizeof(c2));
	}

	if (p->include_ipcontrol || (StrCmpi(c1, "SysIPAddress32") != 0 && (IsEmptyStr(c2) || StrCmpi(c2, "SysIPAddress32") != 0)))
	{
		ok = true;
	}

	if (ok)
	{
		AddWindow(o, hWnd);

		if (p->no_recursion == false)
		{
			EnumChildWindows(hWnd, EnumChildWindowProc, (LPARAM)p);
		}
	}

	return TRUE;
}
LIST *EnumAllTopWindow()
{
	LIST *o = NewListFast(CmpWindowList);

	EnumWindows(EnumTopWindowProc, (LPARAM)o);

	return o;
}

LIST *EnumAllChildWindowEx(HWND hWnd, bool no_recursion, bool include_ipcontrol, bool no_self)
{
	ENUM_CHILD_WINDOW_PARAM p;
	LIST *o = NewListFast(CmpWindowList);

	Zero(&p, sizeof(p));
	p.include_ipcontrol = include_ipcontrol;
	p.no_recursion = no_recursion;
	p.o = o;

	if (no_self == false)
	{
		AddWindow(o, hWnd);
	}

	EnumChildWindows(hWnd, EnumChildWindowProc, (LPARAM)&p);

	return o;
}

void FreeWindowList(LIST *o)
{
	UINT i;
	if (o == NULL)
	{
		return;
	}

	for (i = 0;i < LIST_NUM(o);i++)
	{
		HWND *e = LIST_DATA(o, i);

		Free(e);
	}

	ReleaseList(o);
}

void AddWindow(LIST *o, HWND hWnd)
{
	HWND t, *e;
	if (o == NULL || hWnd == NULL)
	{
		return;
	}

	t = hWnd;

	if (Search(o, &t) != NULL)
	{
		return;
	}

	e = ZeroMalloc(sizeof(HWND));
	*e = hWnd;

	Insert(o, e);
}

int CmpWindowList(void *p1, void *p2)
{
	HWND *h1, *h2;
	if (p1 == NULL || p2 == NULL)
	{
		return 0;
	}
	h1 = *(HWND **)p1;
	h2 = *(HWND **)p2;
	if (h1 == NULL || h2 == NULL)
	{
		return 0;
	}

	return Cmp(h1, h2, sizeof(HWND));
}

bool MsGetWindowOwnerProcessExeName(char *path, UINT size, HWND hWnd)
{
	DWORD procId = 0;
	if (path == NULL || hWnd == NULL)
	{
		return false;
	}

	GetWindowThreadProcessId(hWnd, &procId);
	if (procId == 0)
	{
		return false;
	}

	if (MsGetProcessExeName(path, size, procId) == false)
	{
		return false;
	}

	return true;
}

bool MsGetProcessExeName(char *path, UINT size, UINT id)
{
	LIST *o;
	MS_PROCESS *proc;
	bool ret = false;
	if (path == NULL)
	{
		return false;
	}

	o = MsGetProcessList();
	proc = MsSearchProcessById(o, id);

	if (proc != NULL)
	{
		ret = true;
		StrCpy(path, size, proc->ExeFilename);
	}

	MsFreeProcessList(o);

	return ret;
}

bool MsCloseWarningWindow(NO_WARNING *nw, UINT thread_id)
{
	UINT i;
	LIST *o;
	bool ret = false;
	bool press = false;

	if (nw->StartTimer == 0)
	{
		press = true;
	}

	if (nw->StartTick != 0 && nw->StartTick <= Tick64())
	{
		press = true;
	}

	o = EnumAllTopWindow();

	for (i = 0;i < LIST_NUM(o);i++)
	{
		HWND hWnd;

		if (nw->Halt)
		{
			break;
		}
		
		hWnd = *((HWND *)LIST_DATA(o, i));

		if (hWnd != NULL)
		{
			if (true)
			{
				if (true)
				{
					char exe[MAX_PATH];

					if (MsGetWindowOwnerProcessExeName(exe, sizeof(exe), hWnd))
					{
						if (EndWith(exe, "rundll32.exe"))
						{
							LIST *o;
							HWND h;
							UINT i;

							o = EnumAllChildWindowEx(hWnd, false, false, false);

							if (o != NULL)
							{
								for (i = 0;i < LIST_NUM(o);i++)
								{
									char tmp[MAX_SIZE];

									h = *((HWND *)LIST_DATA(o, i));

									Zero(tmp, sizeof(tmp));
									GetClassNameA(h, tmp, sizeof(tmp));

									if (StrCmpi(tmp, "DirectUIHWND") == 0)
									{
										LIST *o = EnumAllChildWindowEx(h, false, false, false);

										if (o != NULL)
										{
											UINT j;
											UINT numDirectUIHWND = 0;
											UINT numButton = 0;
											HWND hButton1 = NULL;
											HWND hButton2 = NULL;

											for (j = 0;j < LIST_NUM(o);j++)
											{
												HWND hh;
												char tmp[MAX_SIZE];

												hh = *((HWND *)LIST_DATA(o, j));

												Zero(tmp, sizeof(tmp));
												GetClassNameA(hh, tmp, sizeof(tmp));

												if (StrCmpi(tmp, "DirectUIHWND") == 0)
												{
													numDirectUIHWND++;
												}

												if (StrCmpi(tmp, "button") == 0)
												{
													numButton++;
													if (hButton1 == NULL)
													{
														hButton1 = hh;
													}
													else
													{
														hButton2 = hh;
													}
												}
											}

											if ((numDirectUIHWND == 1 || numDirectUIHWND == 2) && numButton == 2)
											{
												if (hButton1 != NULL && hButton2 != NULL)
												{
													HWND hButton;
													HWND hParent;
													RECT r1, r2;

													GetWindowRect(hButton1, &r1);
													GetWindowRect(hButton2, &r2);

													hButton = hButton1;

													if (numDirectUIHWND == 1)
													{
														if (r1.top < r2.top)
														{
															hButton = hButton2;
														}
													}
													else
													{
														if (r1.left >= r2.left)
														{
															hButton = hButton2;
														}
													}

													hParent = GetParent(hButton);

													if (press)
													{
														PostMessage(hParent, WM_COMMAND, 1, 0);
													}

													ret = true;
												}
											}

											FreeWindowList(o);
										}
									}
								}

								FreeWindowList(o);
							}
						}
					}
				}
			}
		}
	}

	FreeWindowList(o);

	if (press == false)
	{
		if (ret)
		{
			ret = false;

			if (nw->StartTick == 0)
			{
				nw->StartTick = Tick64() + nw->StartTimer;
			}
		}
	}

	return ret;
}

void MsNoWarningThreadProc(THREAD *thread, void *param)
{
	NO_WARNING *nw;
	UINT interval;
	UINT i;
	bool found0 = false;
	if (thread == NULL)
	{
		return;
	}

	nw = (NO_WARNING *)param;

	nw->NoWarningThread = thread;
	AddRef(thread->ref);

	NoticeThreadInit(thread);

	interval = 1000;

	i = 0;

	while (nw->Halt == false)
	{
		bool found = false;

		found = MsCloseWarningWindow(nw, nw->ThreadId);
		if (i == 0)
		{
			found0 = found;
		}
		else
		{
			if (found0 == false && found)
			{
				break;
			}
		}
		i++;

		Wait(nw->HaltEvent, interval);
	}
}

NO_WARNING *MsInitNoWarningEx(UINT start_timer)
{
	THREAD *thread;
	NO_WARNING *nw = ZeroMalloc(sizeof(NO_WARNING));

	nw->StartTimer = (UINT64)start_timer;
	nw->ThreadId = GetCurrentThreadId();
	nw->HaltEvent = NewEvent();

	thread = NewThread(MsNoWarningThreadProc, nw);
	WaitThreadInit(thread);

	ReleaseThread(thread);

	return nw;
}

void MsFreeNoWarning(NO_WARNING *nw)
{
	if (nw == NULL)
	{
		return;
	}

	nw->Halt = true;
	Set(nw->HaltEvent);

	WaitThread(nw->NoWarningThread, INFINITE);

	ReleaseThread(nw->NoWarningThread);
	ReleaseEvent(nw->HaltEvent);
	Free(nw);
}

void MsDeleteTempDir()
{
	HANDLE h;
	wchar_t dir_mask[MAX_PATH];
	WIN32_FIND_DATAW data_w;

	Zero(&data_w, sizeof(data_w));

	UniFormat(dir_mask, sizeof(dir_mask), L"%s\\*", ms->TempDirW);

	h = FindFirstFileW(dir_mask, &data_w);

	if (h != INVALID_HANDLE_VALUE)
	{
		bool b = true;

		do
		{
			if (UniStrCmpi(data_w.cFileName, L".") != 0 &&
				UniStrCmpi(data_w.cFileName, L"..") != 0)
			{
				if (data_w.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
				{
					if (UniStartWith(data_w.cFileName, L"VPN_") && UniStrLen(data_w.cFileName) == 8)
					{
						wchar_t lock_file_name[MAX_PATH];
						wchar_t dir_name[MAX_PATH];
						bool delete_now = false;
						IO *io;

						UniFormat(dir_name, sizeof(dir_name), L"%s\\%s",
							ms->TempDirW, data_w.cFileName);
						MsGenLockFile(lock_file_name, sizeof(lock_file_name), dir_name);

						io = FileOpenExW(lock_file_name, false, false);
						if (io != NULL)
						{
							FileClose(io);
							io = FileOpenW(lock_file_name, true);
							if (io != NULL)
							{
								delete_now = true;
								FileClose(io);
							}
						}
						else
						{
							DIRLIST *d;

							delete_now = true;

							d = EnumDirW(dir_name);
							if (d != NULL)
							{
								UINT i;

								for (i = 0;i < d->NumFiles;i++)
								{
									wchar_t full_path[MAX_PATH];

									UniFormat(full_path, sizeof(full_path), L"%s\\%s", dir_name, d->File[i]->FileNameW);

									io = FileOpenW(full_path, true);
									if (io != NULL)
									{
										delete_now = true;
										FileClose(io);
									}
								}
								FreeDir(d);
							}
						}
						if (delete_now)
						{
							MsDeleteAllFileW(dir_name);

							Win32DeleteDirW(dir_name);
						}
					}
				}
			}


			Zero(&data_w, sizeof(data_w));

			b = FindNextFileW(h, &data_w);
		}
		while (b);

		FindClose(h);
	}
}

void MsDeleteAllFileW(wchar_t *dir)
{
	HANDLE h;
	wchar_t file_mask[MAX_PATH];
	WIN32_FIND_DATAW data;
	if (dir == NULL || UniIsEmptyStr(dir))
	{
		return;
	}

	UniFormat(file_mask, sizeof(file_mask), L"%s\\*.*", dir);

	h = FindFirstFileW(file_mask, &data);
	if (h != INVALID_HANDLE_VALUE)
	{
		do
		{
			if (UniStrCmpi(data.cFileName, L".") != 0 &&
				UniStrCmpi(data.cFileName, L"..") != 0)
			{
				wchar_t fullpath[MAX_PATH];

				UniFormat(fullpath, sizeof(fullpath), L"%s\\%s", dir, data.cFileName);

				if ((data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) == false)
				{
					DeleteFileW(fullpath);
				}
				else
				{
					MsDeleteAllFileW(fullpath);
					RemoveDirectoryW(fullpath);
				}
			}
		}
		while (FindNextFileW(h, &data));

		FindClose(h);
	}
}

void MsInitTempDir()
{
	wchar_t tmp[MAX_PATH];
	wchar_t tmp2[16];
	UCHAR random[2];
	wchar_t lockfilename[MAX_PATH];
	UINT num = 0;

	MsDeleteTempDir();

	while (true)
	{
		random[0] = rand() % 256;
		random[1] = rand() % 256;
		BinToStrW(tmp2, sizeof(tmp2), random, sizeof(random));

		UniFormat(tmp, sizeof(tmp), L"%s\\VPN_%s", ms->TempDirW, tmp2);

		if (MakeDirW(tmp))
		{
			break;
		}

		if ((num++) >= 100)
		{
			char msg[MAX_SIZE];
			Format(msg, sizeof(msg),
				"Couldn't create Temporary Directory: %s\r\n\r\n"
				"Please contact your system administrator.",
				tmp);
			exit(0);
		}
	}

	ms->MyTempDirW = CopyUniStr(tmp);
	ms->MyTempDir = CopyUniToStr(tmp);

	MsGenLockFile(lockfilename, sizeof(lockfilename), ms->MyTempDirW);
	ms->LockFile = FileCreateW(lockfilename);
}

void MsFreeTempDir()
{
	wchar_t lock_file_name[MAX_SIZE];

	MsGenLockFile(lock_file_name, sizeof(lock_file_name), ms->MyTempDirW);
	FileClose(ms->LockFile);

	Free(ms->MyTempDir);
	Free(ms->MyTempDirW);
	ms->MyTempDir = NULL;
	ms->MyTempDirW = NULL;

	MsDeleteTempDir();
}

void MsGenLockFile(wchar_t *name, UINT size, wchar_t *temp_dir)
{
	if (name == NULL || temp_dir == NULL)
	{
		return;
	}

	UniFormat(name, size, L"%s\\VPN_Lock.dat", temp_dir);
}

wchar_t *MsGetNetworkConnectionName(char *guid)
{
	wchar_t *ncname = NULL;
	char tmp[MAX_SIZE];
	if (guid == NULL)
	{
		return NULL;
	}

	Format(tmp, sizeof(tmp), "SYSTEM\\CurrentControlSet\\Control\\Network\\{4D36E972-E325-11CE-BFC1-08002BE10318}\\%s\\Connection", guid);
	ncname = MsRegReadStrEx2W(REG_LOCAL_MACHINE, tmp, "Name", false, false);

	return ncname;
}

bool MsCheckLogon(wchar_t *username, char *password)
{
	wchar_t password_unicode[MAX_SIZE];
	HANDLE h;
	if (username == NULL || password == NULL)
	{
		return false;
	}

	StrToUni(password_unicode, sizeof(password_unicode), password);

	if (GET_KETA(GetOsInfo()->OsType, 100) >= 2)
	{
		if (LogonUserW(username, NULL, password_unicode, LOGON32_LOGON_NETWORK, LOGON32_PROVIDER_DEFAULT, &h) == false)
		{
			return false;
		}
	}
	else
	{
		char username_ansi[MAX_SIZE];
		UniToStr(username_ansi, sizeof(username_ansi), username);

		if (LogonUserA(username_ansi, NULL, password, LOGON32_LOGON_NETWORK, LOGON32_PROVIDER_DEFAULT, &h) == false)
		{
			return false;
		}
	}

	CloseHandle(h);

	return true;
}

bool MsEnablePrivilege(char *name, bool enable)
{
	HANDLE hToken;
	LUID luid;
	TOKEN_PRIVILEGES *tp;
	bool ret;
	if (name == NULL)
	{
		return false;
	}

	if (OpenProcessToken(ms->hCurrentProcess, TOKEN_ADJUST_PRIVILEGES, &hToken) == false)
	{
		return false;
	}

	if (LookupPrivilegeValue(NULL, name, &luid) == FALSE)
	{
		CloseHandle(hToken);
		return false;
	}

	tp = ZeroMalloc(sizeof(TOKEN_PRIVILEGES));
	tp->PrivilegeCount = 1;
	tp->Privileges[0].Attributes = enable ? SE_PRIVILEGE_ENABLED : 0;
	Copy(&tp->Privileges[0].Luid, &luid, sizeof(LUID));

	ret = AdjustTokenPrivileges(hToken, false, tp, sizeof(TOKEN_PRIVILEGES), 0, 0);

	Free(tp);
	CloseHandle(hToken);

	return ret;
}

bool MsIsAdmin()
{
	return ms->IsAdmin;
}

// Access mask that forces the 32-bit or 64-bit registry view
UINT MsRegAccessMaskFor64BitEx(bool force32bit, bool force64bit)
{
	if (MsIs64BitWindows() == false)
	{
		return 0;
	}
	if (force32bit)
	{
		return KEY_WOW64_32KEY;
	}
	if (force64bit)
	{
		return KEY_WOW64_64KEY;
	}

	return 0;
}

bool MsRegLoadHive(UINT root, wchar_t *keyname, wchar_t *filename)
{
	LONG ret;
	if (keyname == NULL || filename == NULL)
	{
		return false;
	}
	ret = RegLoadKeyW(MsGetRootKeyFromInt(root), keyname, filename);

	if (ret != ERROR_SUCCESS)
	{
		return false;
	}

	return true;
}

bool MsRegDeleteValue(UINT root, char *keyname, char *valuename)
{
	return MsRegDeleteValueEx2(root, keyname, valuename, false, false);
}
bool MsRegDeleteValueEx2(UINT root, char *keyname, char *valuename, bool force32bit, bool force64bit)
{
	HKEY h;
	bool ret;
	if (keyname == NULL)
	{
		return false;
	}

	if (RegOpenKeyEx(MsGetRootKeyFromInt(root), keyname, 0, KEY_ALL_ACCESS | MsRegAccessMaskFor64BitEx(force32bit, force64bit), &h) != ERROR_SUCCESS)
	{
		return false;
	}

	if (RegDeleteValue(h, valuename) != ERROR_SUCCESS)
	{
		ret = false;
	}
	else
	{
		ret = true;
	}

	RegCloseKey(h);

	return ret;
}

bool MsRegDeleteKeyEx2(UINT root, char *keyname, bool force32bit, bool force64bit)
{
	if (keyname == NULL)
	{
		return false;
	}

	if (RegDeleteKeyExA(MsGetRootKeyFromInt(root), keyname, MsRegAccessMaskFor64BitEx(force32bit, force64bit), 0) != ERROR_SUCCESS)
	{
		return false;
	}

	return true;
}

TOKEN_LIST *MsRegEnumKey(UINT root, char *keyname)
{
	return MsRegEnumKeyEx2(root, keyname, false, false);
}
TOKEN_LIST *MsRegEnumKeyEx2(UINT root, char *keyname, bool force32bit, bool force64bit)
{
	HKEY h;
	UINT i;
	TOKEN_LIST *t;
	LIST *o;

	if (keyname == NULL)
	{
		h = MsGetRootKeyFromInt(root);
	}
	else
	{
		if (RegOpenKeyEx(MsGetRootKeyFromInt(root), keyname, 0, KEY_READ | MsRegAccessMaskFor64BitEx(force32bit, force64bit), &h) != ERROR_SUCCESS)
		{
			return NULL;
		}
	}

	o = NewListFast(CompareStr);

	for (i = 0;;i++)
	{
		char tmp[MAX_SIZE];
		UINT ret;
		DWORD size = sizeof(tmp);
		FILETIME ft;

		Zero(tmp, sizeof(tmp));
		ret = RegEnumKeyEx(h, i, tmp, &size, NULL, NULL, NULL, &ft);
		if (ret == ERROR_NO_MORE_ITEMS)
		{
			break;
		}
		else if (ret != ERROR_SUCCESS)
		{
			break;
		}

		Add(o, CopyStr(tmp));
	}

	Sort(o);

	t = ZeroMalloc(sizeof(TOKEN_LIST));
	t->NumTokens = LIST_NUM(o);
	t->Token = ZeroMalloc(sizeof(char *) * t->NumTokens);
	for (i = 0;i < t->NumTokens;i++)
	{
		t->Token[i] = LIST_DATA(o, i);
	}

	ReleaseList(o);

	if (keyname != NULL)
	{
		RegCloseKey(h);
	}

	return t;
}

bool MsRegWriteInt(UINT root, char *keyname, char *valuename, UINT value)
{
	return MsRegWriteIntEx2(root, keyname, valuename, value, false, false);
}
bool MsRegWriteIntEx2(UINT root, char *keyname, char *valuename, UINT value, bool force32bit, bool force64bit)
{
	if (keyname == NULL)
	{
		return false;
	}

	if (IsBigEndian())
	{
		value = Swap32(value);
	}

	return MsRegWriteValueEx2(root, keyname, valuename, REG_DWORD_LITTLE_ENDIAN, &value, sizeof(UINT), force32bit, force64bit);
}

bool MsRegWriteStr(UINT root, char *keyname, char *valuename, char *str)
{
	return MsRegWriteStrEx2(root, keyname, valuename, str, false, false);
}
bool MsRegWriteStrEx2(UINT root, char *keyname, char *valuename, char *str, bool force32bit, bool force64bit)
{
	if (keyname == NULL || str == NULL)
	{
		return false;
	}

	return MsRegWriteValueEx2(root, keyname, valuename, REG_SZ, str, StrSize(str), force32bit, force64bit);
}

bool MsRegWriteValueEx2(UINT root, char *keyname, char *valuename, UINT type, void *data, UINT size, bool force32bit, bool force64bit)
{
	HKEY h;
	if (keyname == NULL || (size != 0 && data == NULL))
	{
		return false;
	}

	MsRegNewKeyEx2(root, keyname, force32bit, force64bit);

	if (RegOpenKeyEx(MsGetRootKeyFromInt(root), keyname, 0, KEY_ALL_ACCESS | MsRegAccessMaskFor64BitEx(force32bit, force64bit), &h) != ERROR_SUCCESS)
	{
		return false;
	}

	if (RegSetValueEx(h, valuename, 0, type, data, size) != ERROR_SUCCESS)
	{
		RegCloseKey(h);
		return false;
	}

	RegCloseKey(h);

	return true;
}

UINT MsRegReadInt(UINT root, char *keyname, char *valuename)
{
	return MsRegReadIntEx2(root, keyname, valuename, false, false);
}
UINT MsRegReadIntEx2(UINT root, char *keyname, char *valuename, bool force32bit, bool force64bit)
{
	char *ret;
	DWORD type, size;
	UINT value;
	if (keyname == NULL || valuename == NULL)
	{
		return 0;
	}

	if (MsRegReadValueEx2(root, keyname, valuename, (void **)&ret, &type, &size, force32bit, force64bit) == false)
	{
		return 0;
	}

	if (type != REG_DWORD_LITTLE_ENDIAN && type != REG_DWORD_BIG_ENDIAN)
	{
		Free(ret);
		return 0;
	}

	if (size != sizeof(UINT))
	{
		Free(ret);
		return 0;
	}

	Copy(&value, ret, sizeof(UINT));

	Free(ret);

	if (IsLittleEndian())
	{
#ifdef	REG_DWORD_BIG_ENDIAN
		if (type == REG_DWORD_BIG_ENDIAN)
		{
			value = Swap32(value);
		}
#endif	// REG_DWORD_BIG_ENDIAN
	}
	else
	{
#ifdef	REG_DWORD_LITTLE_ENDIAN_FLAG
		if (type == REG_DWORD_LITTLE_ENDIAN_FLAG)
		{
			value = Swap32(value);
		}
#endif	// REG_DWORD_LITTLE_ENDIAN_FLAG
	}

	return value;
}

LIST *MsRegReadStrListEx2(UINT root, char *keyname, char *valuename, bool force32bit, bool force64bit)
{
	LIST *o;
	char *ret;
	DWORD type, size;
	if (keyname == NULL || valuename == NULL)
	{
		return NULL;
	}

	if (MsRegReadValueEx2(root, keyname, valuename, (void **)&ret, &type, &size, force32bit, force64bit) == false)
	{
		return NULL;
	}

	if (type != REG_MULTI_SZ)
	{
		Free(ret);
		return NULL;
	}

	if (size < 2)
	{
		Free(ret);
		return NULL;
	}

	if (ret[size - 1] != 0)
	{
		Free(ret);
		return NULL;
	}

	o = StrToStrList(ret, size);

	Free(ret);

	return o;
}

char *MsRegReadStr(UINT root, char *keyname, char *valuename)
{
	return MsRegReadStrEx2(root, keyname, valuename, false, false);
}
char *MsRegReadStrEx2(UINT root, char *keyname, char *valuename, bool force32bit, bool force64bit)
{
	char *ret;
	DWORD type, size;
	if (keyname == NULL || valuename == NULL)
	{
		return NULL;
	}

	if (MsRegReadValueEx2(root, keyname, valuename, (void **)&ret, &type, &size, force32bit, force64bit) == false)
	{
		return NULL;
	}

	if (type != REG_SZ && type != REG_EXPAND_SZ && type != REG_MULTI_SZ)
	{
		Free(ret);

		if (type == REG_MULTI_SZ)
		{
			LIST *o = MsRegReadStrListEx2(root, keyname, valuename, false, false);
			if (o != NULL)
			{
				if (LIST_NUM(o) >= 1)
				{
					ret = CopyStr(LIST_DATA(o, 0));
					FreeStrList(o);
					return ret;
				}
			}
		}
		return NULL;
	}

	if (size == 0)
	{
		Free(ret);

		return CopyStr("");
	}

	if (ret[size - 1] != 0)
	{
		Free(ret);
		return NULL;
	}

	return ret;
}
wchar_t *MsRegReadStrEx2W(UINT root, char *keyname, char *valuename, bool force32bit, bool force64bit)
{
	wchar_t *ret;
	DWORD type, size;
	if (keyname == NULL || valuename == NULL)
	{
		return NULL;
	}

	if (MsRegReadValueEx2W(root, keyname, valuename, (void **)&ret, &type, &size, force32bit, force64bit) == false)
	{
		return NULL;
	}

	if (type != REG_SZ && type != REG_EXPAND_SZ)
	{
		Free(ret);

		return NULL;
	}

	if (ret[size / sizeof(wchar_t) - 1] != 0)
	{
		Free(ret);
		return NULL;
	}

	return ret;
}

bool MsRegReadValueEx2(UINT root, char *keyname, char *valuename, void **data, DWORD *type, DWORD *size, bool force32bit, bool force64bit)
{
	HKEY h;
	UINT ret;
	if (keyname == NULL || data == NULL || type == NULL || size == NULL)
	{
		return false;
	}
	*type = 0;
	*size = 0;

	if (RegOpenKeyEx(MsGetRootKeyFromInt(root), keyname, 0, KEY_READ | MsRegAccessMaskFor64BitEx(force32bit, force64bit), &h) != ERROR_SUCCESS)
	{
		return false;
	}

	*data = ZeroMalloc(*size);
	ret = RegQueryValueEx(h, valuename, 0, type, *data, size);

	if (ret == ERROR_SUCCESS)
	{
		RegCloseKey(h);
		return true;
	}

	if (ret != ERROR_MORE_DATA)
	{
		Free(*data);
		*data = NULL;
		RegCloseKey(h);
		return false;
	}

	*data = ReAlloc(*data, *size);
	ret = RegQueryValueEx(h, valuename, 0, type, *data, size);
	if (ret != ERROR_SUCCESS)
	{
		Free(*data);
		*data = NULL;
		RegCloseKey(h);
	}

	RegCloseKey(h);

	return true;
}
bool MsRegReadValueEx2W(UINT root, char *keyname, char *valuename, void **data, DWORD *type, DWORD *size, bool force32bit, bool force64bit)
{
	HKEY h;
	UINT ret;
	wchar_t *valuename_w;
	if (keyname == NULL || data == NULL || type == NULL || size == NULL)
	{
		return false;
	}
	*type = 0;
	*size = 0;

	if (RegOpenKeyEx(MsGetRootKeyFromInt(root), keyname, 0, KEY_READ | MsRegAccessMaskFor64BitEx(force32bit, force64bit), &h) != ERROR_SUCCESS)
	{
		return false;
	}

	valuename_w = CopyStrToUni(valuename);

	*data = ZeroMalloc(*size);
	ret = RegQueryValueExW(h, valuename_w, 0, type, *data, size);

	if (ret == ERROR_SUCCESS)
	{
		RegCloseKey(h);
		Free(valuename_w);
		return true;
	}

	if (ret != ERROR_MORE_DATA)
	{
		Free(*data);
		*data = NULL;
		Free(valuename_w);
		RegCloseKey(h);
		return false;
	}

	*data = ReAlloc(*data, *size);
	ret = RegQueryValueExW(h, valuename_w, 0, type, *data, size);
	if (ret != ERROR_SUCCESS)
	{
		Free(*data);
		*data = NULL;
		Free(valuename_w);
		RegCloseKey(h);
	}

	Free(valuename_w);

	RegCloseKey(h);

	return true;
}

bool MsRegIsValue(UINT root, char *keyname, char *valuename)
{
	return MsRegIsValueEx2(root, keyname, valuename, false, false);
}
bool MsRegIsValueEx2(UINT root, char *keyname, char *valuename, bool force32bit, bool force64bit)
{
	HKEY h;
	DWORD type, size;
	UINT ret;
	if (keyname == NULL)
	{
		return false;
	}

	if (RegOpenKeyEx(MsGetRootKeyFromInt(root), keyname, 0, KEY_READ | MsRegAccessMaskFor64BitEx(force32bit, force64bit), &h) != ERROR_SUCCESS)
	{
		return false;
	}

	size = 0;
	ret = RegQueryValueEx(h, valuename, 0, &type, NULL, &size);

	if (ret == ERROR_SUCCESS || ret == ERROR_MORE_DATA)
	{
		RegCloseKey(h);
		return true;
	}

	RegCloseKey(h);

	return false;
}

bool MsRegNewKeyEx2(UINT root, char *keyname, bool force32bit, bool force64bit)
{
	HKEY h;
	if (keyname == NULL)
	{
		return false;
	}

	if (MsRegIsKeyEx2(root, keyname, force32bit, force64bit))
	{
		return true;
	}

	if (RegCreateKeyEx(MsGetRootKeyFromInt(root), keyname, 0, NULL, REG_OPTION_NON_VOLATILE,
		KEY_ALL_ACCESS | MsRegAccessMaskFor64BitEx(force32bit, force64bit), NULL, &h, NULL) != ERROR_SUCCESS)
	{
		return false;
	}

	RegCloseKey(h);

	return true;
}

bool MsRegIsKeyEx2(UINT root, char *name, bool force32bit, bool force64bit)
{
	HKEY h;
	if (name == NULL)
	{
		return false;
	}

	if (RegOpenKeyEx(MsGetRootKeyFromInt(root), name, 0, KEY_READ | MsRegAccessMaskFor64BitEx(force32bit, force64bit), &h) != ERROR_SUCCESS)
	{
		return false;
	}

	RegCloseKey(h);

	return true;
}

HKEY MsGetRootKeyFromInt(UINT root)
{
	switch (root)
	{
	case REG_CLASSES_ROOT:
		return HKEY_CLASSES_ROOT;

	case REG_LOCAL_MACHINE:
		return HKEY_LOCAL_MACHINE;

	case REG_CURRENT_USER:
		return HKEY_CURRENT_USER;

	case REG_USERS:
		return HKEY_USERS;
	}

	return NULL;
}

wchar_t *MsCutExeNameFromUniCommandLine(wchar_t *str)
{
	if (str == NULL)
	{
		return NULL;
	}

	if (str[0] != L'\"')
	{
		UINT i = UniSearchStrEx(str, L" ", 0, true);
		if (i == INFINITE)
		{
			return str + UniStrLen(str);
		}
		else
		{
			return str + i + 1;
		}
	}
	else
	{
		str++;
		while (true)
		{
			if ((*str) == 0)
			{
				return str + UniStrLen(str);
			}
			if ((*str) == L'\"')
			{
				break;
			}
			str++;
		}

		while (true)
		{
			if ((*str) == 0)
			{
				return str + UniStrLen(str);
			}
			if ((*str) == L' ')
			{
				return str + 1;
			}
			str++;
		}
	}
}

char *MsCutExeNameFromCommandLine(char *str)
{
	if (str == NULL)
	{
		return NULL;
	}

	if (str[0] != '\"')
	{
		UINT i = SearchStrEx(str, " ", 0, true);
		if (i == INFINITE)
		{
			return str + StrLen(str);
		}
		else
		{
			return str + i + 1;
		}
	}
	else
	{
		str++;
		while (true)
		{
			if ((*str) == 0)
			{
				return str + StrLen(str);
			}
			if ((*str) == '\"')
			{
				break;
			}
			str++;
		}

		while (true)
		{
			if ((*str) == 0)
			{
				return str + StrLen(str);
			}
			if ((*str) == ' ')
			{
				return str + 1;
			}
			str++;
		}
	}
}

UINT MsGetCurrentProcessId()
{
	return ms->CurrentProcessId;
}

char *MsGetExeDirName()
{
	return ms->ExeFileDir;
}

char *MsGetSpecialDir(int id)
{
	LPITEMIDLIST t = NULL;
	char tmp[MAX_PATH];

	if (SHGetSpecialFolderLocation(NULL, id, &t) != S_OK)
	{
		return CopyStr(ms->ExeFileDir);
	}

	if (SHGetPathFromIDList(t, tmp) == false)
	{
		return CopyStr(ms->ExeFileDir);
	}

	Win32NukuEn(tmp, sizeof(tmp), tmp);

	return CopyStr(tmp);
}
wchar_t *MsGetSpecialDirW(int id)
{
	LPITEMIDLIST t = NULL;
	wchar_t tmp[MAX_PATH];

	if (SHGetSpecialFolderLocation(NULL, id, &t) != S_OK)
	{
		return UniCopyStr(ms->ExeFileDirW);
	}

	if (SHGetPathFromIDListW(t, tmp) == false)
	{
		return UniCopyStr(ms->ExeFileDirW);
	}

	Win32NukuEnW(tmp, sizeof(tmp), tmp);

	return UniCopyStr(tmp);
}

void MsGetSpecialDirs()
{
	char tmp[MAX_PATH];

	GetSystemDirectory(tmp, sizeof(tmp));
	Win32NukuEn(tmp, sizeof(tmp), tmp);
	ms->System32Dir = CopyStr(tmp);
	ms->System32DirW = CopyStrToUni(tmp);

	// The Windows directory is parent of the System32 directory
	Win32GetDirFromPath(tmp, sizeof(tmp), tmp);
	Win32NukuEn(tmp, sizeof(tmp), tmp);
	ms->WindowsDir = CopyStr(tmp);
	ms->WindowsDirW = CopyStrToUni(tmp);

	Format(tmp, sizeof(tmp), "%s\\Temp", ms->WindowsDir);
	ms->WinTempDir = CopyStr(tmp);
	ms->WinTempDirW = CopyStrToUni(tmp);
	MsUniMakeDirEx(ms->WinTempDirW);

	tmp[2] = 0;
	ms->WindowsDrive = CopyStr(tmp);
	ms->WindowsDriveW = CopyStrToUni(tmp);

	GetTempPath(MAX_PATH, tmp);
	Win32NukuEn(tmp, sizeof(tmp), tmp);
	ms->TempDir = CopyStr(tmp);

	{
		wchar_t tmp_w[MAX_PATH];

		GetTempPathW(MAX_PATH, tmp_w);
		Win32NukuEnW(tmp_w, sizeof(tmp_w), tmp_w);

		ms->TempDirW = CopyUniStr(tmp_w);
	}
	MakeDirExW(ms->TempDirW);
	MakeDirEx(ms->TempDir);

	ms->ProgramFilesDir = MsGetSpecialDir(CSIDL_PROGRAM_FILES);
	if (StrCmpi(ms->ProgramFilesDir, ms->ExeFileDir) == 0)
	{
		char tmp[MAX_PATH];
		Format(tmp, sizeof(tmp), "%s\\Program Files", ms->WindowsDrive);

		Free(ms->ProgramFilesDir);
		ms->ProgramFilesDir = CopyStr(tmp);
	}

	ms->ProgramFilesDirW = MsGetSpecialDirW(CSIDL_PROGRAM_FILES);
	if (UniStrCmpi(ms->ProgramFilesDirW, ms->ExeFileDirW) == 0)
	{
		wchar_t tmp[MAX_PATH];
		UniFormat(tmp, sizeof(tmp), L"%s\\Program Files", ms->WindowsDriveW);

		Free(ms->ProgramFilesDirW);
		ms->ProgramFilesDirW = UniCopyStr(tmp);
	}

	ms->ProgramFilesDirX86 = MsGetSpecialDir(CSIDL_PROGRAM_FILESX86);
	if (StrCmpi(ms->ProgramFilesDirX86, ms->ExeFileDir) == 0)
	{
		if (MsIs64BitWindows())
		{
			char tmp[MAX_PATH];
			Format(tmp, sizeof(tmp), "%s\\Program Files (x86)", ms->WindowsDrive);

			Free(ms->ProgramFilesDirX86);
			ms->ProgramFilesDirX86 = CopyStr(tmp);
		}
		else
		{
			Free(ms->ProgramFilesDirX86);
			ms->ProgramFilesDirX86 = CopyStr(ms->ProgramFilesDir);
		}
	}

	ms->ProgramFilesDirX86W = MsGetSpecialDirW(CSIDL_PROGRAM_FILESX86);
	if (UniStrCmpi(ms->ProgramFilesDirX86W, ms->ExeFileDirW) == 0)
	{
		if (MsIs64BitWindows())
		{
			wchar_t tmp[MAX_PATH];
			UniFormat(tmp, sizeof(tmp), L"%s\\Program Files (x86)", ms->WindowsDriveW);

			Free(ms->ProgramFilesDirX86W);
			ms->ProgramFilesDirX86W = UniCopyStr(tmp);
		}
		else
		{
			Free(ms->ProgramFilesDirX86W);
			ms->ProgramFilesDirX86W = UniCopyStr(ms->ProgramFilesDirW);
		}
	}

	if (MsIs64BitWindows())
	{
		if (Is64())
		{
			ms->ProgramFilesDirX64 = CopyStr(ms->ProgramFilesDir);
			ms->ProgramFilesDirX64W = CopyUniStr(ms->ProgramFilesDirW);
		}
		else
		{
			char tmpa[MAX_SIZE];
			wchar_t tmpw[MAX_SIZE];

			ReplaceStrEx(tmpa, sizeof(tmpa), ms->ProgramFilesDir, "\\Program Files (x86)", "\\Program Files", false);
			UniReplaceStrEx(tmpw, sizeof(tmpw), ms->ProgramFilesDirW, L"\\Program Files (x86)", L"\\Program Files", false);

			ms->ProgramFilesDirX64 = CopyStr(tmpa);
			ms->ProgramFilesDirX64W = CopyUniStr(tmpw);
		}
	}
	else
	{
		ms->ProgramFilesDirX64 = CopyStr(ms->ProgramFilesDir);
		ms->ProgramFilesDirX64W = CopyUniStr(ms->ProgramFilesDirW);
	}

	ms->CommonStartMenuDir = MsGetSpecialDir(CSIDL_COMMON_STARTMENU);
	ms->CommonStartMenuDirW = MsGetSpecialDirW(CSIDL_COMMON_STARTMENU);

	ms->CommonProgramsDir = MsGetSpecialDir(CSIDL_COMMON_PROGRAMS);
	ms->CommonProgramsDirW = MsGetSpecialDirW(CSIDL_COMMON_PROGRAMS);

	ms->CommonStartupDir = MsGetSpecialDir(CSIDL_COMMON_STARTUP);
	ms->CommonStartupDirW = MsGetSpecialDirW(CSIDL_COMMON_STARTUP);

	ms->CommonAppDataDir = MsGetSpecialDir(CSIDL_COMMON_APPDATA);
	ms->CommonAppDataDirW = MsGetSpecialDirW(CSIDL_COMMON_APPDATA);

	ms->CommonDesktopDir = MsGetSpecialDir(CSIDL_COMMON_DESKTOPDIRECTORY);
	ms->CommonDesktopDirW = MsGetSpecialDirW(CSIDL_COMMON_DESKTOPDIRECTORY);

	ms->LocalAppDataDir = MsGetSpecialDir(CSIDL_LOCAL_APPDATA);
	ms->LocalAppDataDirW = MsGetSpecialDirW(CSIDL_LOCAL_APPDATA);
}

bool MsCheckIsAdmin()
{
	UCHAR test_bit[32];
	UCHAR tmp[32];
	UCHAR exe_hash[SHA1_SIZE];
	char *name_tag = "Vpn_Check_Admin_Key_%u";
	DWORD type;
	DWORD size;
	char name[MAX_SIZE];

	Sha1(exe_hash, MsGetExeFileNameW(), UniStrLen(MsGetExeFileNameW()));

	Format(name, sizeof(name), name_tag, *((UINT *)exe_hash));

	Rand(test_bit, sizeof(test_bit));

	if (RegSetValueEx(HKEY_LOCAL_MACHINE, name, 0, REG_BINARY, test_bit, sizeof(test_bit)) != ERROR_SUCCESS)
	{
		return false;
	}

	size = sizeof(tmp);
	if (RegQueryValueEx(HKEY_LOCAL_MACHINE, name, 0, &type, tmp, &size) != ERROR_SUCCESS)
	{
		RegDeleteValue(HKEY_LOCAL_MACHINE, name);
		return false;
	}

	RegDeleteValue(HKEY_LOCAL_MACHINE, name);

	if (Cmp(test_bit, tmp, 32) != 0)
	{
		return false;
	}

	return true;
}

void MsInit()
{
	char *str_ansi;
	wchar_t *str_unicode;
	char tmp[MAX_SIZE];
	DWORD size;
	if (ms != NULL)
	{
		return;
	}

	ms = ZeroMalloc(sizeof(MS));

	ms->hInst = GetModuleHandle(NULL);

	ms->hKernel32 = LoadLibrary("kernel32.dll");

	str_ansi = CopyStr(GetCommandLineA());
	Trim(str_ansi);
	str_unicode = UniCopyStr(GetCommandLineW());
	UniTrim(str_unicode);

	SetCommandLineStr(MsCutExeNameFromCommandLine(str_ansi));
	SetCommandLineUniStr(MsCutExeNameFromUniCommandLine(str_unicode));

	Free(str_unicode);
	Free(str_ansi);

	ms->IsAdmin = MsCheckIsAdmin();

	ms->hCurrentProcess = GetCurrentProcess();
	ms->CurrentProcessId = GetCurrentProcessId();

	GetModuleFileName(NULL, tmp, sizeof(tmp));
	ms->ExeFileName = CopyStr(tmp);
	Win32GetDirFromPath(tmp, sizeof(tmp), tmp);
	ms->ExeFileDir = CopyStr(tmp);

	{
		wchar_t tmp_w[MAX_PATH];

		GetModuleFileNameW(NULL, tmp_w, sizeof(tmp_w));
		ms->ExeFileNameW = CopyUniStr(tmp_w);

		Win32GetDirFromPathW(tmp_w, sizeof(tmp_w), tmp_w);
		ms->ExeFileDirW = CopyUniStr(tmp_w);
	}

	MsGetSpecialDirs();

	MsInitTempDir();

	size = sizeof(tmp);
	GetUserName(tmp, &size);
	ms->UserName = CopyStr(tmp);

	wchar_t tmp_w[MAX_PATH];

	size = sizeof(tmp_w);

	GetUserNameW(tmp_w, &size);
	ms->UserNameW = CopyUniStr(tmp_w);

	size = sizeof(tmp);
	if (GetUserNameExA(NameSamCompatible, tmp, &size))
	{
		ms->UserNameEx = CopyStr(tmp);
	}

	size = sizeof(tmp_w);
	if (GetUserNameExW(NameSamCompatible, tmp_w, &size))
	{
		ms->UserNameExW = CopyUniStr(tmp_w);
	}

	if (ms->UserNameEx == NULL)
	{
		ms->UserNameEx = CopyStr(ms->UserName);
	}
	if (ms->UserNameExW == NULL)
	{
		ms->UserNameExW = CopyUniStr(ms->UserNameW);
	}

	MsInitAdapterListModule();

	if (true)
	{
		wchar_t tmp[MAX_PATH];
		if (MsIsAdmin())
		{
			CombinePathW(tmp, sizeof(tmp), ms->ExeFileDirW, L"vpn_debug\\dump");
		}
		else
		{
			CombinePathW(tmp, sizeof(tmp), ms->TempDirW, L"vpn_debug\\dump");
		}
		ms->MinidumpBaseFileNameW = CopyUniStr(tmp);
	}

	MsSetEnableMinidump(true);
	SetUnhandledExceptionFilter(MsExceptionHandler);

	hLsa = NULL;
	lsa_package_id = 0;

	MsEnablePrivilege(SE_TCB_NAME, true);

	HANDLE h = NULL;
	NTSTATUS ret = LsaConnectUntrusted(&h);

	if (ret == 0)
	{
		LSA_STRING pkg_name;
		ULONG ul = 0;

		Zero(&pkg_name, sizeof(pkg_name));
		pkg_name.Buffer = MSV1_0_PACKAGE_NAME;
		pkg_name.Length = pkg_name.MaximumLength = StrLen(MSV1_0_PACKAGE_NAME);

		ret = LsaLookupAuthenticationPackage(h, &pkg_name, &ul);

		if (ret == 0)
		{
			Zero(&lsa_token_source, sizeof(lsa_token_source));

			AllocateLocallyUniqueId(&lsa_token_source.SourceIdentifier);
			Copy(lsa_token_source.SourceName, "SE-VPN  ", 8);

			lsa_package_id = ul;
			hLsa = h;
		}
		else
		{
			LsaDeregisterLogonProcess(h);
		}
	}

	if (hMsi == NULL)
	{
		hMsi = LoadLibrary("msi.dll");

		if (hMsi != NULL)
		{
			_MsiConfigureProductW =
				(UINT (__stdcall *)(LPCWSTR,int,INSTALLSTATE)) GetProcAddress(hMsi, "MsiConfigureProductW");
			_MsiGetProductInfoW =
				(UINT (__stdcall *)(LPCWSTR,LPCWSTR,LPWSTR,LPDWORD)) GetProcAddress(hMsi, "MsiGetProductInfoW");
			_MsiSetInternalUI =
				(INSTALLUILEVEL (__stdcall *)(INSTALLUILEVEL,HWND *)) GetProcAddress(hMsi, "MsiSetInternalUI");
			_MsiLocateComponentW =
				(INSTALLSTATE (__stdcall *)(LPCWSTR,LPWSTR,LPDWORD)) GetProcAddress(hMsi, "MsiLocateComponentW");
		}
	}
}

void MsSetEnableMinidump(bool enabled)
{
	ms->MiniDumpEnabled = enabled;
}

void MsWriteMinidump(wchar_t *filename, void *ex)
{
	wchar_t tmp[MAX_PATH];
	wchar_t dir[MAX_PATH];
	HANDLE h;
	MINIDUMP_EXCEPTION_INFORMATION info;
	struct _EXCEPTION_POINTERS *exp = (struct _EXCEPTION_POINTERS *)ex;

	if (filename != NULL)
	{
		UniStrCpy(tmp, sizeof(tmp), filename);
	}
	else
	{
		SYSTEMTIME tm;

		Zero(&tm, sizeof(tm));
		GetLocalTime(&tm);

		UniFormat(tmp, sizeof(tmp), L"%s_%04u%02u%02u_%02u%02u%02u.dmp",
			ms->MinidumpBaseFileNameW,
			tm.wYear, tm.wMonth, tm.wDay, tm.wHour, tm.wMinute, tm.wSecond);
	}

	GetDirNameFromFilePathW(dir, sizeof(dir), tmp);

	CreateDirectoryW(dir, NULL);

	Zero(&info, sizeof(info));

	if (exp != NULL)
	{
		info.ThreadId = GetCurrentThreadId();
		info.ExceptionPointers = exp;
		info.ClientPointers = true;
	}

	h = CreateFileW(tmp, GENERIC_READ | GENERIC_WRITE,
		FILE_SHARE_READ, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL,
		NULL);
	if (h != INVALID_HANDLE_VALUE)
	{
		MiniDumpWriteDump(ms->hCurrentProcess, ms->CurrentProcessId,
			h,
			MiniDumpNormal | MiniDumpWithFullMemory | MiniDumpWithDataSegs |
			MiniDumpWithHandleData
			,
			info.ThreadId == 0 ? NULL : &info, NULL, NULL);

		FlushFileBuffers(h);
		CloseHandle(h);
	}
}

LONG CALLBACK MsExceptionHandler(struct _EXCEPTION_POINTERS *ExceptionInfo)
{
	if (ms->MiniDumpEnabled)
	{
		MsWriteMinidump(NULL, ExceptionInfo);
	}

	return EXCEPTION_CONTINUE_SEARCH;
}

void MsFree()
{
	if (ms == NULL)
	{
		return;
	}

	if (hLsa != NULL)
	{
		LsaDeregisterLogonProcess(hLsa);

		hLsa = NULL;
	}

	MsFreeAdapterListModule();

	MsFreeTempDir();

	Free(ms->WindowsDir);
	Free(ms->System32Dir);
	Free(ms->TempDir);
	Free(ms->WinTempDir);
	Free(ms->WindowsDrive);
	Free(ms->ProgramFilesDir);
	Free(ms->CommonStartMenuDir);
	Free(ms->CommonProgramsDir);
	Free(ms->CommonStartupDir);
	Free(ms->CommonAppDataDir);
	Free(ms->CommonDesktopDir);
	Free(ms->PersonalStartMenuDir);
	Free(ms->PersonalProgramsDir);
	Free(ms->PersonalStartupDir);
	Free(ms->PersonalAppDataDir);
	Free(ms->PersonalDesktopDir);
	Free(ms->MyDocumentsDir);
	Free(ms->ExeFileDir);
	Free(ms->ExeFileName);
	Free(ms->UserName);
	Free(ms->UserNameEx);
	Free(ms->LocalAppDataDir);
	Free(ms->ProgramFilesDirX86);
	Free(ms->ProgramFilesDirX64);
	Free(ms->WindowsDirW);
	Free(ms->System32DirW);
	Free(ms->TempDirW);
	Free(ms->WinTempDirW);
	Free(ms->WindowsDriveW);
	Free(ms->ProgramFilesDirW);
	Free(ms->CommonStartMenuDirW);
	Free(ms->CommonProgramsDirW);
	Free(ms->CommonStartupDirW);
	Free(ms->CommonAppDataDirW);
	Free(ms->CommonDesktopDirW);
	Free(ms->PersonalStartMenuDirW);
	Free(ms->PersonalProgramsDirW);
	Free(ms->PersonalStartupDirW);
	Free(ms->PersonalAppDataDirW);
	Free(ms->PersonalDesktopDirW);
	Free(ms->MyDocumentsDirW);
	Free(ms->ExeFileDirW);
	Free(ms->ExeFileNameW);
	Free(ms->UserNameW);
	Free(ms->UserNameExW);
	Free(ms->LocalAppDataDirW);
	Free(ms->MinidumpBaseFileNameW);
	Free(ms->ProgramFilesDirX86W);
	Free(ms->ProgramFilesDirX64W);

	Free(ms);
	ms = NULL;
}

wchar_t *MsGetWindowsDirW()
{
	return ms->WindowsDirW;
}
char *MsGetSystem32Dir()
{
	return ms->System32Dir;
}
char *MsGetTempDir()
{
	return ms->TempDir;
}
char *MsGetMyTempDir()
{
	return ms->MyTempDir;
}

wchar_t *MsGetExeFileNameW()
{
	return ms == NULL ? L"Unknown" : ms->ExeFileNameW;
}
wchar_t *MsGetSystem32DirW()
{
	return ms->System32DirW;
}
wchar_t *MsGetMyTempDirW()
{
	return ms->MyTempDirW;
}
wchar_t *MsGetUserNameW()
{
	return ms->UserNameW;
}

#endif	// WIN32

