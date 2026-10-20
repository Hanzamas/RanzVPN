// Win32.c
// Microsoft Windows dependent code
//
// WIN32_USE_HEAP_API_FOR_MEMORY (Malloc on a private heap) and WIN32_NO_DEBUG_HELP_DLL (no DbgHelp
// call stacks) come from the build, per configuration (cmake/RanzOptions.cmake)

#include "Win32.h"

#include "FileIO.h"
#include "GlobalConst.h"
#include "Internat.h"
#include "Microsoft.h"
#include "Memory.h"
#include "Object.h"
#include "Str.h"
#include "Tracking.h"

#include <stdlib.h>
#include <string.h>

#include <CommCtrl.h>
#include <objbase.h>
#include <timeapi.h>
#include <winioctl.h>

#ifndef	WIN32_NO_DEBUG_HELP_DLL
#include <DbgHelp.h>		// The call stacks of Win32GetCallStack and Win32GetCallStackSymbolInfo
#endif

static HANDLE heap_handle = NULL;
static HANDLE hstdout = INVALID_HANDLE_VALUE;
static HANDLE hstdin = INVALID_HANDLE_VALUE;

static HANDLE hCurrentProcessHandle = NULL;
static bool use_heap_api = false;

typedef struct WIN32MUTEX
{
	HANDLE hMutex;
} WIN32MUTEX;

#pragma pack(push,8)
typedef struct tagTHREADNAME_INFO
{
	DWORD dwType; // Must be 0x1000.
	LPCSTR szName; // Pointer to name (in user addr space).
	DWORD dwThreadID; // Thread ID (-1=caller thread).
	DWORD dwFlags; // Reserved for future use, must be zero.
} THREADNAME_INFO;
#pragma pack(pop)

void Win32SetThreadName(UINT thread_id, char *name)
{
	DWORD ms_vc_exception = 0x406D1388;
	THREADNAME_INFO t;
	if (thread_id == 0 || name == NULL)
	{
		return;
	}

	Zero(&t, sizeof(t));
	t.dwType = 0x1000;
	t.szName = name;
	t.dwThreadID = thread_id;
	t.dwFlags = 0;

	__try
	{
		RaiseException(ms_vc_exception, 0, sizeof(t) / sizeof(ULONG_PTR), (ULONG_PTR *)&t);
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
	}
}

void Win32InitNewThread()
{
	static HINSTANCE hDll = NULL;
	static bool (WINAPI *_SetThreadLocale)(LCID) = NULL;

	if (hDll == NULL)
	{
		hDll = LoadLibrary("kernel32.dll");

		_SetThreadLocale =
			(bool (__stdcall *)(LCID))
			GetProcAddress(hDll, "SetThreadLocale");
	}

	if (_SetThreadLocale != NULL)
	{
		_SetThreadLocale(LOCALE_USER_DEFAULT);
	}
}

bool Win32SetFolderCompress(char *path, bool compressed)
{
	HANDLE h;
	DWORD retsize = 0;
	USHORT flag;
	bool ret;
	char tmp[MAX_PATH];
	if (path == NULL)
	{
		return false;
	}

	InnerFilePath(tmp, sizeof(tmp), path);

	h = CreateFile(tmp, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, NULL);

	if (h == INVALID_HANDLE_VALUE)
	{
		return false;
	}

	flag = compressed ? COMPRESSION_FORMAT_DEFAULT : COMPRESSION_FORMAT_NONE;

	ret = (DeviceIoControl(h, FSCTL_SET_COMPRESSION, &flag, sizeof(USHORT),
		NULL, 0, &retsize, NULL) != FALSE);

	CloseHandle(h);

	return ret;
}

DIRLIST *Win32EnumDirExW(wchar_t *dirname, COMPARE *compare)
{
	WIN32_FIND_DATAW data_w;
	HANDLE h;
	wchar_t tmp[MAX_PATH];
	wchar_t tmp2[MAX_PATH];
	wchar_t dirname2[MAX_PATH];
	LIST *o;
	DIRLIST *d;

	UniStrCpy(tmp2, sizeof(tmp2), dirname);

	if (UniStrLen(tmp2) >= 1 && tmp2[UniStrLen(tmp2) - 1] == L'\\')
	{
		tmp2[UniStrLen(tmp2) - 1] = 0;
	}

	UniFormat(tmp, sizeof(tmp), L"%s\\*.*", tmp2);
	NormalizePathW(tmp, sizeof(tmp), tmp);
	NormalizePathW(dirname2, sizeof(dirname2), tmp2);

	o = NewListFast(compare);

	Zero(&data_w, sizeof(data_w));

	h = FindFirstFileW(tmp, &data_w);

	if (h != INVALID_HANDLE_VALUE)
	{
		bool b = true;

		do
		{
			if (UniStrCmpi(data_w.cFileName, L"..") != 0 &&
				UniStrCmpi(data_w.cFileName, L".") != 0)
			{
				DIRENT *f = ZeroMalloc(sizeof(DIRENT));
				wchar_t fullpath[MAX_SIZE];
				bool ok = false;
				HANDLE hfile;

				f->FileNameW = UniCopyStr(data_w.cFileName);
				f->FileName = CopyUniToStr(f->FileNameW);
				f->Folder = (data_w.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) ? true : false;

				CombinePathW(fullpath, sizeof(fullpath), dirname2, f->FileNameW);

				hfile = CreateFileW(fullpath, 0,
					FILE_SHARE_DELETE | FILE_SHARE_READ | FILE_SHARE_WRITE,
					NULL, OPEN_EXISTING, 0, NULL);

				if (hfile != INVALID_HANDLE_VALUE)
				{
					BY_HANDLE_FILE_INFORMATION info;

					Zero(&info, sizeof(info));

					if (GetFileInformationByHandle(hfile, &info))
					{
						f->UpdateDate = FileTimeToUINT64(&info.ftLastWriteTime);

						if (f->Folder == false)
						{
							f->FileSize = ((UINT64)info.nFileSizeHigh * (UINT64)((UINT64)MAXDWORD + (UINT64)1)) + (UINT64)info.nFileSizeLow;
						}

						ok = true;
					}

					CloseHandle(hfile);
				}

				if (ok == false)
				{
					f->UpdateDate = FileTimeToUINT64(&data_w.ftLastWriteTime);

					if (f->Folder == false)
					{
						f->FileSize = ((UINT64)data_w.nFileSizeHigh * (UINT64)((UINT64)MAXDWORD + (UINT64)1)) + (UINT64)data_w.nFileSizeLow;
					}
				}

				Add(o, f);
			}

			Zero(&data_w, sizeof(data_w));

			b = FindNextFileW(h, &data_w);
		}
		while (b);

		FindClose(h);
	}

	Sort(o);

	d = ZeroMalloc(sizeof(DIRLIST));
	d->NumFiles = LIST_NUM(o);
	d->File = ToArray(o);

	ReleaseList(o);

	return d;
}

// The path of the executable; num_chars counts wide characters, not bytes. Empty when it fails or
// does not fit.
void Win32GetExeNameW(wchar_t *name, UINT num_chars)
{
	DWORD ret;
	if (name == NULL || num_chars == 0)
	{
		return;
	}

	ret = GetModuleFileNameW(NULL, name, num_chars);
	if (ret == 0 || ret >= num_chars)
	{
		name[0] = 0;
	}
}

// The current directory; num_chars counts wide characters, not bytes. Empty when it fails or does
// not fit.
void Win32GetCurrentDirW(wchar_t *dir, UINT num_chars)
{
	DWORD ret;
	if (dir == NULL || num_chars == 0)
	{
		return;
	}

	ret = GetCurrentDirectoryW(num_chars, dir);
	if (ret == 0 || ret >= num_chars)
	{
		dir[0] = 0;
	}
}

void Win32Yield()
{
	Sleep(0);
}

void Win32GetMemInfo(MEMINFO *info)
{
	static HINSTANCE hDll = NULL;
	static bool (WINAPI *_GlobalMemoryStatusEx)(LPMEMORYSTATUSEX) = NULL;
	if (info == NULL)
	{
		return;
	}

	Zero(info, sizeof(MEMINFO));

	if (hDll == NULL)
	{
		hDll = LoadLibrary("kernel32.dll");
	}
	if (hDll != NULL)
	{
		if (_GlobalMemoryStatusEx == NULL)
		{
			_GlobalMemoryStatusEx =
				(bool (__stdcall *)(LPMEMORYSTATUSEX))GetProcAddress(hDll, "GlobalMemoryStatusEx");
		}
	}


	if (_GlobalMemoryStatusEx == NULL)
	{
		MEMORYSTATUS st;
		Zero(&st, sizeof(st));
		st.dwLength = sizeof(st);

		GlobalMemoryStatus(&st);

		info->TotalMemory = (UINT64)st.dwTotalPageFile;
		info->FreeMemory = (UINT64)st.dwAvailPageFile;
		info->UsedMemory = info->TotalMemory - info->FreeMemory;

		info->TotalPhys = (UINT64)st.dwTotalPhys;
		info->FreePhys = (UINT64)st.dwAvailPhys;
		info->UsedPhys = info->TotalPhys - info->FreePhys;
	}
	else
	{
		MEMORYSTATUSEX st;
		Zero(&st, sizeof(st));
		st.dwLength = sizeof(st);

		_GlobalMemoryStatusEx(&st);

		info->TotalMemory = st.ullTotalPageFile;
		info->FreeMemory = st.ullAvailPageFile;
		info->UsedMemory = info->TotalMemory - info->FreeMemory;

		info->TotalPhys = st.ullTotalPhys;
		info->FreePhys = st.ullAvailPhys;
		info->UsedPhys = info->TotalPhys - info->FreePhys;
	}
}

void *Win32NewSingleInstance(char *instance_name)
{
	WIN32MUTEX *ret;
	char tmp[MAX_SIZE];
	wchar_t name_w[MAX_SIZE];
	HANDLE hMutex;
	if (instance_name == NULL)
	{
		char exe_path[MAX_PATH];
		GetModuleFileName(NULL, exe_path, sizeof(exe_path));
		HashInstanceName(tmp, sizeof(tmp), exe_path);
		instance_name = tmp;
	}

	// One atomic create: an existing mutex (or one this account may not open) means another instance runs
	StrToUni(name_w, sizeof(name_w), instance_name);
	hMutex = CreateMutexW(NULL, FALSE, name_w);
	if (hMutex == NULL)
	{
		return NULL;
	}
	if (GetLastError() == ERROR_ALREADY_EXISTS)
	{
		CloseHandle(hMutex);
		return NULL;
	}

	ret = Win32MemoryAlloc(sizeof(WIN32MUTEX));
	ret->hMutex = hMutex;

	return (void *)ret;
}

void Win32FreeSingleInstance(void *data)
{
	WIN32MUTEX *m;
	if (data == NULL)
	{
		return;
	}

	m = (WIN32MUTEX *)data;
	ReleaseMutex(m->hMutex);
	CloseHandle(m->hMutex);

	Win32MemoryFree(m);
}

void Win32SetHighPriority()
{
	SetPriorityClass(GetCurrentProcess(), HIGH_PRIORITY_CLASS);
}

void Win32RestorePriority()
{
	SetPriorityClass(GetCurrentProcess(), NORMAL_PRIORITY_CLASS);
}

char* Win32GetProductId()
{
	return CopyStr("--");
}

// InitMayaqua() ends the process through MayaFatalExit() when this is false
bool Win32IsSupportedOs()
{
	return Win32GetOsType() != 0;
}

UINT Win32GetNumberOfCpuInner()
{
	UINT ret = 0;
	SYSTEM_INFO info;

	Zero(&info, sizeof(info));

	GetSystemInfo(&info);

	if (info.dwNumberOfProcessors >= 1 && info.dwNumberOfProcessors <= 128)
	{
		ret = info.dwNumberOfProcessors;
	}

	return ret;
}

void Win32GetOsInfo(OS_INFO *info)
{
	UINT type = Win32GetOsType();
	OSVERSIONINFOEX os;
	char tmp[MAX_SIZE];
	char *s;
	char *keyname = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion";
	if (info == NULL)
	{
		return;
	}

	Zero(&os, sizeof(os));
	os.dwOSVersionInfoSize = sizeof(os);
	Win32GetVersionExInternal((LPOSVERSIONINFOA)&os);

	info->OsType = Win32GetOsType();
	info->OsServicePack = os.wServicePackMajor;
	info->OsSystemName = CopyStr("Windows NT");
	Format(tmp, sizeof(tmp), "Build %u", os.dwBuildNumber);
	if (s = MsRegReadStr(REG_LOCAL_MACHINE, keyname, "CurrentType"))
	{
		char str[MAX_SIZE];
		Format(str, sizeof(str), ", %s", s);
		StrCat(tmp, sizeof(tmp), str);
		Free(s);
	}
	if (os.wServicePackMajor != 0)
	{
		char str[MAX_SIZE];
		Format(str, sizeof(str), ", Service Pack %u", os.wServicePackMajor);
		StrCat(tmp, sizeof(tmp), str);
	}
	if (s = MsRegReadStr(REG_LOCAL_MACHINE, keyname, "BuildLab"))
	{
		char str[MAX_SIZE];
		Format(str, sizeof(str), " (%s)", s);
		StrCat(tmp, sizeof(tmp), str);
		Free(s);
	}
	info->OsVersion = CopyStr(tmp);
	info->KernelName = CopyStr("NTOS Kernel");
	Format(tmp, sizeof(tmp), "Build %u", os.dwBuildNumber);
	if (s = MsRegReadStr(REG_LOCAL_MACHINE, keyname, "CurrentType"))
	{
		char str[MAX_SIZE];
		Format(str, sizeof(str), " %s", s);
		StrCat(tmp, sizeof(tmp), str);
		Free(s);
	}
	info->KernelVersion = CopyStr(tmp);

	info->OsProductName = CopyStr(OsTypeToStr(info->OsType));
	info->OsVendorName = CopyStr("Microsoft Corporation");
}

// GetVersionExA reports 6.2 on Windows 8.1 and later; read the real version from the registry
bool Win32GetVersionExInternal(void *info)
{
	OSVERSIONINFOA os;
	if (info == NULL)
	{
		return false;
	}

	Zero(&os, sizeof(os));
	os.dwOSVersionInfoSize = sizeof(os);

	if (GetVersionExA(&os))
	{
		if (os.dwPlatformId == VER_PLATFORM_WIN32_NT)
		{
			if ((os.dwMajorVersion == 6 && os.dwMinorVersion >= 2) ||
				(os.dwMajorVersion >= 7))
			{
				return Win32GetVersionExInternalForWindows81orLater(info);
			}
		}
	}

	return GetVersionExA(info);
}

bool Win32GetVersionExInternalForWindows81orLater(void *info)
{
	OSVERSIONINFOEXA *ex = (OSVERSIONINFOEXA *)info;
	char *str;
	UINT major1 = 0, major2 = 0;
	UINT minor1 = 0, minor2 = 0;
	UINT major = 0, minor = 0;
	if (info == NULL)
	{
		return false;
	}

	if (ex->dwOSVersionInfoSize != sizeof(OSVERSIONINFOEXA) &&
		ex->dwOSVersionInfoSize != sizeof(OSVERSIONINFOA))
	{
		return GetVersionExA(info);
	}

	if (GetVersionExA(info) == false)
	{
		return false;
	}

	str = MsRegReadStrEx2(REG_LOCAL_MACHINE,
		"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
		"CurrentVersion",
		false, true);

	if (IsEmptyStr(str) == false)
	{
		TOKEN_LIST *t = ParseToken(str, ".");

		if (t != NULL && t->NumTokens == 2)
		{
			major1 = ToInt(t->Token[0]);
			minor1 = ToInt(t->Token[1]);
		}

		FreeToken(t);
	}

	Free(str);

	major2 = MsRegReadIntEx2(REG_LOCAL_MACHINE,
		"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
		"CurrentMajorVersionNumber", false, true);

	minor2 = MsRegReadIntEx2(REG_LOCAL_MACHINE,
		"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
		"CurrentMinorVersionNumber", false, true);

	if ((major1 * 10000 + minor1) > (major2 * 10000 + minor2))
	{
		major = major1;
		minor = minor1;
	}
	else
	{
		major = major2;
		minor = minor2;
	}

	if (major >= 6)
	{
		ex->dwMajorVersion = major;
		ex->dwMinorVersion = minor;
	}

	return true;
}

UINT Win32GetOsType()
{
	OSVERSIONINFOEX os;
	Zero(&os, sizeof(os));
	os.dwOSVersionInfoSize = sizeof(os);

	if (Win32GetVersionExInternal((LPOSVERSIONINFOA)&os) == FALSE)
	{
		return 0;
	}

	if (os.dwPlatformId != VER_PLATFORM_WIN32_NT)
	{
		return 0;
	}

	if (os.dwMajorVersion < 6 || (os.dwMajorVersion == 6 && os.dwMinorVersion < 4))
	{
		return 0;
	}

	if ((os.dwMajorVersion == 6 && os.dwMinorVersion == 4) || (os.dwMajorVersion == 10 && os.dwMinorVersion == 0))
	{
		if (os.wProductType == VER_NT_WORKSTATION)
		{
			return OSTYPE_WINDOWS_10;
		}
		else
		{
			return OSTYPE_WINDOWS_SERVER_10;
		}
	}
	else
	{
		if (os.wProductType == VER_NT_WORKSTATION)
		{
			return OSTYPE_WINDOWS_11;
		}
		else
		{
			return OSTYPE_WINDOWS_SERVER_11;
		}
	}
}

void Win32CloseProcess(void *handle)
{
	if (handle == NULL)
	{
		return;
	}

	CloseHandle((HANDLE)handle);
}

bool Win32WaitProcess(void *h, UINT timeout)
{
	if (h == NULL)
	{
		return false;
	}
	if (timeout == 0)
	{
		timeout = INFINITE;
	}

	if (WaitForSingleObject((HANDLE)h, timeout) == WAIT_TIMEOUT)
	{
		return false;
	}

	return true;
}

void *Win32RunEx3W(wchar_t *filename, wchar_t *arg, bool hide, UINT *process_id, bool disableWow)
{
	STARTUPINFOW info;
	PROCESS_INFORMATION ret;
	wchar_t cmdline[MAX_SIZE];
	wchar_t name[MAX_PATH];
	void *p;
	if (filename == NULL)
	{
		return NULL;
	}

	UniStrCpy(name, sizeof(name), filename);
	UniTrim(name);

	// Quote a bare path so CreateProcess does not probe "C:\Program" first; a name that already has quotes goes as is
	if (UniSearchStr(name, L"\"", 0) == INFINITE)
	{
		if (arg == NULL)
		{
			UniFormat(cmdline, sizeof(cmdline), L"\"%s\"", name);
		}
		else
		{
			UniFormat(cmdline, sizeof(cmdline), L"\"%s\" %s", name, arg);
		}
	}
	else
	{
		if (arg == NULL)
		{
			UniFormat(cmdline, sizeof(cmdline), L"%s", name);
		}
		else
		{
			UniFormat(cmdline, sizeof(cmdline), L"%s %s", name, arg);
		}
	}

	Zero(&info, sizeof(info));
	Zero(&ret, sizeof(ret));
	info.cb = sizeof(info);
	info.dwFlags = STARTF_USESHOWWINDOW;
	info.wShowWindow = (hide == false ? SW_SHOWDEFAULT : SW_HIDE);

	UniTrim(cmdline);

	if (disableWow)
	{
		p = MsDisableWow64FileSystemRedirection();
	}

	// CREATE_NO_WINDOW is ignored together with CREATE_NEW_CONSOLE, so a hidden launch sets it alone
	if (CreateProcessW(NULL, cmdline, NULL, NULL, FALSE,
		(hide == false ? CREATE_NEW_CONSOLE : CREATE_NO_WINDOW) | NORMAL_PRIORITY_CLASS,
		NULL, NULL, &info, &ret) == FALSE)
	{
		if (disableWow)
		{
			MsRestoreWow64FileSystemRedirection(p);
		}
		return NULL;
	}

	if (disableWow)
	{
		MsRestoreWow64FileSystemRedirection(p);
	}

	if (process_id != NULL)
	{
		*process_id = ret.dwProcessId;
	}

	CloseHandle(ret.hThread);
	return ret.hProcess;
}

bool Win32Run(char *filename, char *arg, bool hide, bool wait)
{
	STARTUPINFO info;
	PROCESS_INFORMATION ret;
	char cmdline[MAX_SIZE];
	char name[MAX_PATH];
	if (filename == NULL)
	{
		return false;
	}

	StrCpy(name, sizeof(name), filename);
	Trim(name);

	// Quote a bare path so CreateProcess does not probe "C:\Program" first; a name that already has quotes goes as is
	if (SearchStr(name, "\"", 0) == INFINITE)
	{
		if (arg == NULL)
		{
			Format(cmdline, sizeof(cmdline), "\"%s\"", name);
		}
		else
		{
			Format(cmdline, sizeof(cmdline), "\"%s\" %s", name, arg);
		}
	}
	else
	{
		if (arg == NULL)
		{
			Format(cmdline, sizeof(cmdline), "%s", name);
		}
		else
		{
			Format(cmdline, sizeof(cmdline), "%s %s", name, arg);
		}
	}

	Zero(&info, sizeof(info));
	Zero(&ret, sizeof(ret));
	info.cb = sizeof(info);
	info.dwFlags = STARTF_USESHOWWINDOW;
	info.wShowWindow = (hide == false ? SW_SHOWDEFAULT : SW_HIDE);

	Trim(cmdline);

	// CREATE_NO_WINDOW is ignored together with CREATE_NEW_CONSOLE, so a hidden launch sets it alone
	if (CreateProcess(NULL, cmdline, NULL, NULL, FALSE,
		(hide == false ? CREATE_NEW_CONSOLE : CREATE_NO_WINDOW) | NORMAL_PRIORITY_CLASS,
		NULL, NULL, &info, &ret) == FALSE)
	{
		return false;
	}

	if (wait)
	{
		WaitForSingleObject(ret.hProcess, INFINITE);
	}

	CloseHandle(ret.hThread);
	CloseHandle(ret.hProcess);

	return true;
}

UINT Win32ThreadId()
{
	return GetCurrentThreadId();
}

void Win32NukuEnW(wchar_t *dst, UINT size, wchar_t *src)
{
	wchar_t str[MAX_SIZE];
	int i;
	if (src)
	{
		UniStrCpy(str, sizeof(str), src);
	}
	else
	{
		UniStrCpy(str, sizeof(str), dst);
	}
	i = UniStrLen(str);
	if (i > 0 && str[i - 1] == L'\\')
	{
		str[i - 1] = 0;
	}
	UniStrCpy(dst, size, str);
}
void Win32NukuEn(char *dst, UINT size, char *src)
{
	char str[MAX_SIZE];
	int i;
	if (src)
	{
		StrCpy(str, sizeof(str), src);
	}
	else
	{
		StrCpy(str, sizeof(str), dst);
	}
	i = StrLen(str);
	if (i > 0 && str[i - 1] == '\\')
	{
		str[i - 1] = 0;
	}
	StrCpy(dst, size, str);
}

void Win32GetDirFromPathW(wchar_t *dst, UINT size, wchar_t *src)
{
	wchar_t str[MAX_SIZE];
	int i,len;
	wchar_t c;
	wchar_t tmp[MAX_SIZE];
	int wp;
	if (src)
	{
		UniStrCpy(str, sizeof(str), src);
	}
	else
	{
		UniStrCpy(str, sizeof(str), dst);
	}
	Win32NukuEnW(str, sizeof(str), NULL);
	wp = 0;
	len = UniStrLen(str);
	dst[0] = 0;
	for (i = 0;i < len;i++)
	{
		c = str[i];
		switch (c)
		{
		case L'\\':
			tmp[wp] = 0;
			wp = 0;
			UniStrCat(dst, size, tmp);
			UniStrCat(dst, size, L"\\");
			break;
		default:
			tmp[wp] = c;
			wp++;
			break;
		}
	}
	Win32NukuEnW(dst, size, NULL);
}
void Win32GetDirFromPath(char *dst, UINT size, char *src)
{
	char str[MAX_SIZE];
	int i,len;
	char c;
	char tmp[MAX_SIZE];
	int wp;
	if (src)
	{
		StrCpy(str, sizeof(str), src);
	}
	else
	{
		StrCpy(str, sizeof(str), dst);
	}
	Win32NukuEn(str, sizeof(str), NULL);
	wp = 0;
	len = StrLen(str);
	dst[0] = 0;
	for (i = 0;i < len;i++)
	{
		c = str[i];
		switch (c)
		{
		case '\\':
			tmp[wp] = 0;
			wp = 0;
			StrCat(dst, size, tmp);
			StrCat(dst, size, "\\");
			break;
		default:
			tmp[wp] = c;
			wp++;
			break;
		}
	}
	Win32NukuEn(dst, size, NULL);
}

bool Win32DeleteDirW(wchar_t *name)
{
	if (name == NULL)
	{
		return false;
	}

	if (RemoveDirectoryW(name) == FALSE)
	{
		return false;
	}
	return true;
}

#define	CALLSTACK_DEPTH			12
#define	CALLSTACK_NAME_CHARS	512		// Longest symbol name that SymFromAddrW writes, with its NUL

// The frames of the calling thread: one CALLSTACK_DATA per return address, symbol names not resolved yet
CALLSTACK_DATA *Win32GetCallStack()
{
#ifndef	WIN32_NO_DEBUG_HELP_DLL
	void *frames[CALLSTACK_DEPTH];
	CALLSTACK_DATA *cs = NULL, *s = NULL;
	UINT num, i;

	// Frame 0 is this function (skip 0): the callers drop their own frames with WalkDownCallStack
	num = (UINT)CaptureStackBackTrace(0, CALLSTACK_DEPTH, frames, NULL);

	for (i = 0;i < num;i++)
	{
		CALLSTACK_DATA *n = OSMemoryAlloc(sizeof(CALLSTACK_DATA));

		n->symbol_cache = false;
		n->next = NULL;
		n->offset = (UINT64)(UINT_PTR)frames[i];
		n->disp = 0;
		n->name = NULL;
		n->line = 0;
		n->filename[0] = 0;

		if (s == NULL)
		{
			cs = n;
		}
		else
		{
			s->next = n;
		}
		s = n;
	}

	return cs;
#else
	return NULL;
#endif
}

// Resolves the name, the line and the file name of one frame, when a stack is printed
bool Win32GetCallStackSymbolInfo(CALLSTACK_DATA *s)
{
#ifdef	WIN32_NO_DEBUG_HELP_DLL
	return false;
#else
	struct
	{
		SYMBOL_INFOW info;
		wchar_t name_tail[CALLSTACK_NAME_CHARS];	// SYMBOL_INFOW.Name continues in here
	} sym;
	IMAGEHLP_LINEW64 line;
	DWORD64 disp64 = 0;
	DWORD disp32 = 0;		// The DWORD that SymGetLineFromAddrW64 writes
	wchar_t *file_name;
	int size;
	if (s == NULL)
	{
		return false;
	}

	if (s->symbol_cache)
	{
		return true;
	}

	Zero(&sym, sizeof(sym));
	sym.info.SizeOfStruct = sizeof(sym.info);
	sym.info.MaxNameLen = CALLSTACK_NAME_CHARS - 1;

	s->disp = 0;
	s->name = NULL;
	if (SymFromAddrW(hCurrentProcessHandle, s->offset, &disp64, &sym.info))
	{
		size = WideCharToMultiByte(CP_ACP, 0, sym.info.Name, -1, NULL, 0, NULL, NULL);
		if (size > 0)
		{
			s->name = OSMemoryAlloc((UINT)size);
			if (WideCharToMultiByte(CP_ACP, 0, sym.info.Name, -1, s->name, size, NULL, NULL) != 0)
			{
				s->disp = disp64;
			}
			else
			{
				OSMemoryFree(s->name);
				s->name = NULL;
			}
		}
	}

	s->line = 0;
	s->filename[0] = 0;
	Zero(&line, sizeof(line));
	line.SizeOfStruct = sizeof(line);
	if (SymGetLineFromAddrW64(hCurrentProcessHandle, s->offset, &disp32, &line))
	{
		// The file name without its directory
		file_name = wcsrchr(line.FileName, L'\\');
		file_name = (file_name == NULL) ? line.FileName : file_name + 1;
		if (WideCharToMultiByte(CP_ACP, 0, file_name, -1, s->filename, sizeof(s->filename), NULL, NULL) != 0)
		{
			s->line = line.LineNumber;
		}
		else
		{
			s->filename[0] = 0;
		}
	}

	s->symbol_cache = true;

	return true;
#endif
}

void Win32Init()
{
	INITCOMMONCONTROLSEX c;

	if (hstdout == INVALID_HANDLE_VALUE)
	{
		hstdout = GetStdHandle(STD_OUTPUT_HANDLE);
	}

	if (hstdin == INVALID_HANDLE_VALUE)
	{
		hstdin = GetStdHandle(STD_INPUT_HANDLE);
	}

	Win32InitNewThread();

	CoInitialize(NULL);

#ifdef	WIN32_USE_HEAP_API_FOR_MEMORY
	use_heap_api = true;
#else
	use_heap_api = false;
#endif

	if (use_heap_api)
	{
		heap_handle = HeapCreate(0, 0, 0);
	}

	hCurrentProcessHandle = GetCurrentProcess();


	if (IsMemCheck())
	{
#ifndef	WIN32_NO_DEBUG_HELP_DLL
		SymInitialize(hCurrentProcessHandle, NULL, TRUE);
#endif
	}

	Zero(&c, sizeof(INITCOMMONCONTROLSEX));
	c.dwSize = sizeof(INITCOMMONCONTROLSEX);
	c.dwICC = ICC_ANIMATE_CLASS | ICC_BAR_CLASSES | ICC_COOL_CLASSES |
		ICC_DATE_CLASSES | ICC_HOTKEY_CLASS | ICC_INTERNET_CLASSES |
		ICC_LISTVIEW_CLASSES | ICC_NATIVEFNTCTL_CLASS |
		ICC_PAGESCROLLER_CLASS | ICC_PROGRESS_CLASS |
		ICC_TAB_CLASSES | ICC_TREEVIEW_CLASSES | ICC_UPDOWN_CLASS | ICC_USEREX_CLASSES |
		ICC_WIN95_CLASSES;
	InitCommonControlsEx(&c);
}

void Win32Free()
{
	if (IsMemCheck())
	{
#ifndef	WIN32_NO_DEBUG_HELP_DLL
		SymCleanup(hCurrentProcessHandle);
#endif
	}

	if (use_heap_api)
	{
		HeapDestroy(heap_handle);
		heap_handle = NULL;
	}

	CoUninitialize();
}

void *Win32MemoryAlloc(UINT size)
{
	if (use_heap_api)
	{
		return HeapAlloc(heap_handle, 0, size);
	}
	else
	{
		return malloc(size);
	}
}

void *Win32MemoryReAlloc(void *addr, UINT size)
{
	if (use_heap_api)
	{
		return HeapReAlloc(heap_handle, 0, addr, size);
	}
	else
	{
		return realloc(addr, size);
	}
}

void Win32MemoryFree(void *addr)
{
	if (use_heap_api)
	{
		HeapFree(heap_handle, 0, addr);
	}
	else
	{
		free(addr);
	}
}

void Win32GetSystemTime(SYSTEMTIME *system_time)
{
	GetSystemTime(system_time);
}

void Win32Sleep(UINT time)
{
	Sleep(time);
}

bool Win32InputW(wchar_t *str, UINT size)
{
	bool ret = false;
	DWORD read_size = 0;
	if (str == NULL)
	{
		return false;
	}
	if (size == 0)
	{
		size = 0x7fffffff;
	}

	if (size <= sizeof(wchar_t))
	{
		Zero(str, size);

		Win32InputDiscardLine();

		return false;
	}

	if (ReadConsoleW(hstdin, str, (size / sizeof(wchar_t)) - 1, &read_size, NULL))
	{
		str[read_size] = 0;

		UniTrimCrlf(str);

		ret = true;
	}
	else
	{
		ret = Win32InputFromFileW(str, size);
	}

	return ret;
}

void Win32InputDiscardLine()
{
	char *a = Win32InputFromFileLineA();

	Free(a);
}

bool Win32InputFromFileW(wchar_t *str, UINT size)
{
	char *a;
	if (str == NULL)
	{
		return false;
	}

	a = Win32InputFromFileLineA();
	if (a == NULL)
	{
		UniStrCpy(str, size, L"");
		return false;
	}

	UtfToUni(str, size, a);

	UniTrimCrlf(str);

	Free(a);

	return true;
}
char *Win32InputFromFileLineA()
{
	BUF *b = NewBuf();
	char zero = 0;
	char *ret = NULL;
	bool ok = true;

	while (true)
	{
		char c;
		DWORD read_size = 0;

		if (ReadFile(hstdin, &c, 1, &read_size, NULL) == false)
		{
			ok = false;
			break;
		}
		if (read_size != 1)
		{
			ok = false;
			break;
		}

		WriteBuf(b, &c, 1);

		if (c == 10)
		{
			break;
		}
	}

	WriteBuf(b, &zero, 1);

	if (ok)
	{
		ret = CopyStr(b->Buf);
	}

	FreeBuf(b);

	return ret;
}

void Win32PrintW(wchar_t *str)
{
	DWORD write_size = 0;
	if (str == NULL)
	{
		return;
	}

	if (WriteConsoleW(hstdout, str, UniStrLen(str), &write_size, NULL) == false)
	{
		Win32PrintToFileW(str);
	}
}
void Win32PrintToFileW(wchar_t *str)
{
	char *utf;
	DWORD size = 0;
	if (str == NULL)
	{
		return;
	}

	utf = CopyUniToUtf(str);

	WriteFile(hstdout, utf, StrLen(utf), &size, NULL);

	Free(utf);
}

