// SoftEther VPN Source Code - Developer Edition Master Branch
// Mayaqua Kernel


// MicrosoftSystem.c
// Windows system information and directories: VM detection, timers, computer name, WOW64, console, DLL loading, special and temporary directories

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

// Determine whether this is running in a VM
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

// Get the locale ID of the user
UINT MsGetUserLocaleId()
{
	static UINT lcid_cache = 0;

	if (lcid_cache == 0)
	{
		lcid_cache = (UINT)GetUserDefaultLCID();
	}

	return lcid_cache;
}

// Set the mode not to show the errors
void MsSetErrorModeToSilent()
{
	SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX | SEM_NOOPENFILEERRORBOX);
}

// Get the file information
bool MsGetFileInformation(void *h, void *info)
{
	// Validate arguments
	if (h == INVALID_HANDLE_VALUE || info == NULL)
	{
		return false;
	}

	return GetFileInformationByHandle(h, info);
}

// Get the precise time from the value of the high-resolution counter
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

// Get a high-resolution counter
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

// Recursive directory creation
void MsUniMakeDirEx(wchar_t *name)
{
	UINT wp;
	wchar_t *tmp;
	UINT i, len;
	// Validate arguments
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

// Create a directory
bool MsUniMakeDir(wchar_t *name)
{
	// Validate arguments
	if (name == NULL)
	{
		return false;
	}

	return CreateDirectoryW(name, NULL);
}

static wchar_t ms_computer_name_full_cache[MAX_SIZE] = {0};

// Get the full name of the computer
void MsGetComputerNameFullEx(wchar_t *name, UINT size, bool with_cache)
{
	DWORD size2 = size;
	// Validate arguments
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

// Get the computer name
void MsGetComputerName(char *name, UINT size)
{
	DWORD sz;
	// Validate arguments
	if (name == NULL)
	{
		return;
	}

	sz = size;
	GetComputerName(name, &sz);
}

// Disable the WoW64 redirection
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

// Restore the WoW64 redirection
void MsRestoreWow64FileSystemRedirection(void *p)
{
	// Validate arguments
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

// Get whether the x64 version of Windows is currently running
bool MsIsX64()
{
	SYSTEM_INFO info;

	if (MsIs64BitWindows() == false)
	{
		return false;
	}

	Zero(&info, sizeof(info));
	GetNativeSystemInfo(&info);

	if (info.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64)
	{
		return true;
	}

	return false;
}

// Acquisition whether it's a 64bit Windows
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

// Get the locale of the current thread
UINT MsGetThreadLocale()
{
	return (UINT)GetThreadLocale();
}

// Set the width of the current console
UINT MsSetConsoleWidth(UINT size)
{
	HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
	CONSOLE_SCREEN_BUFFER_INFO info;
	COORD c;
	UINT old_x, old_y;
	// Validate arguments
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

// Get the width of the current console
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

// Disable the MS-IME
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

// Display the current time
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

// LoadLibrary (compatible for Hamcore)
void *MsLoadLibraryW(wchar_t *name)
{
	BUF *b;
	wchar_t tmp_dll_name[MAX_SIZE];
	char hash_str[MAX_SIZE];
	UCHAR hash[SHA1_SIZE];
	// Validate arguments
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
	// Validate arguments
	if (name == NULL)
	{
		return NULL;
	}

	StrToUni(name_w, sizeof(name_w), name);

	return MsLoadLibraryW(name_w);
}

// Delete all the files in the specified directory
void MsDeleteAllFileW(wchar_t *dir)
{
	HANDLE h;
	wchar_t file_mask[MAX_PATH];
	WIN32_FIND_DATAW data;
	// Validate arguments
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

// Generation of the name of the lock file
void MsGenLockFile(wchar_t *name, UINT size, wchar_t *temp_dir)
{
	// Validate arguments
	if (name == NULL || temp_dir == NULL)
	{
		return;
	}

	UniFormat(name, size, L"%s\\VPN_Lock.dat", temp_dir);
}

// Cut the executable file name from the command line string (Unicode version)
wchar_t *MsCutExeNameFromUniCommandLine(wchar_t *str)
{
	// Validate arguments
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

// Cut the executable file name from the command line string
char *MsCutExeNameFromCommandLine(char *str)
{
	// Validate arguments
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

#endif	// WIN32

