// SoftEther VPN Source Code - Developer Edition Master Branch
// Mayaqua Kernel


// Win32.c
// Microsoft Windows dependent code

#ifdef OS_WIN32

#include "Win32.h"

#include "FileIO.h"
#include "GlobalConst.h"
#include "Internat.h"
#include "Microsoft.h"
#include "Memory.h"
#include "Object.h"
#include "Str.h"

#include <stdlib.h>

#include <CommCtrl.h>
#include <objbase.h>
#include <process.h>
#include <timeapi.h>
#include <winioctl.h>

static HANDLE heap_handle = NULL;
static HANDLE hstdout = INVALID_HANDLE_VALUE;
static HANDLE hstdin = INVALID_HANDLE_VALUE;

// Thread data for Win32
typedef struct WIN32THREAD
{
	HANDLE hThread;
	DWORD thread_id;
} WIN32THREAD;

// Thread startup information for Win32
typedef struct WIN32THREADSTARTUPINFO
{
	THREAD_PROC *thread_proc;
	void *param;
	THREAD *thread;
} WIN32THREADSTARTUPINFO;

// Function prototype for Win32
DWORD CALLBACK Win32DefaultThreadProc(void *param);

// Current process handle
static HANDLE hCurrentProcessHandle = NULL;
static bool use_heap_api = false;

// File I/O data for Win32
typedef struct WIN32IO
{
	HANDLE hFile;
	bool WriteMode;
} WIN32IO;

// Mutex data for Win32
typedef struct WIN32MUTEX
{
	HANDLE hMutex;
} WIN32MUTEX;

// Set the Thread name
#pragma pack(push,8)
typedef struct tagTHREADNAME_INFO
{
	DWORD dwType; // Must be 0x1000.
	LPCSTR szName; // Pointer to name (in user addr space).
	DWORD dwThreadID; // Thread ID (-1=caller thread).
	DWORD dwFlags; // Reserved for future use, must be zero.
} THREADNAME_INFO;
#pragma pack(pop)

// Create a dispatch table
OS_DISPATCH_TABLE *Win32GetDispatchTable()
{
	static OS_DISPATCH_TABLE t =
	{
		Win32Init,
		Win32Free,
		Win32MemoryAlloc,
		Win32MemoryReAlloc,
		Win32MemoryFree,
		Win32Inc32,
		Win32Dec32,
		Win32Sleep,
		Win32NewLock,
		Win32Lock,
		Win32Unlock,
		Win32DeleteLock,
		Win32ResetEvent,
		Win32WaitThread,
		Win32FreeThread,
		Win32InitThread,
		Win32ThreadId,
		Win32FileOpen,
		Win32FileOpenW,
		Win32FileCreate,
		Win32FileCreateW,
		Win32FileWrite,
		Win32FileRead,
		Win32FileClose,
		Win32FileFlush,
		Win32FileSize,
		Win32FileSeek,
		Win32FileDelete,
		Win32FileDeleteW,
		Win32MakeDir,
		Win32MakeDirW,
		Win32DeleteDir,
		Win32DeleteDirW,
		Win32GetCallStack,
		Win32GetCallStackSymbolInfo,
		Win32FileRename,
		Win32FileRenameW,
		Win32Run,
		Win32RunW,
		Win32IsSupportedOs,
		Win32GetOsInfo,
		Win32Alert,
		Win32AlertW,
		Win32GetProductId,
		Win32SetHighPriority,
		Win32RestorePriority,
		Win32NewSingleInstance,
		Win32FreeSingleInstance,
		Win32GetMemInfo,
		Win32Yield,
	};

	return &t;
}

// Set the thread name
void Win32SetThreadName(UINT thread_id, char *name)
{
	DWORD ms_vc_exception = 0x406D1388;
	THREADNAME_INFO t;
	// Validate arguments
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

// Initialization function of the new thread
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

// Set the compression flag of the folder
bool Win32SetFolderCompress(char *path, bool compressed)
{
	HANDLE h;
	DWORD retsize = 0;
	USHORT flag;
	char tmp[MAX_PATH];
	// Validate arguments
	if (path == NULL)
	{
		return false;
	}

	InnerFilePath(tmp, sizeof(tmp), path);

	// Open the folder
	h = CreateFile(tmp, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, NULL);

	if (h == INVALID_HANDLE_VALUE)
	{
		return false;
	}

	flag = compressed ? COMPRESSION_FORMAT_DEFAULT : COMPRESSION_FORMAT_NONE;

	if (DeviceIoControl(h, FSCTL_SET_COMPRESSION, &flag, sizeof(USHORT),
		NULL, 0, &retsize, NULL) == false)
	{
		return false;
	}

	CloseHandle(h);

	return true;
}

// Get the free space of the disk
bool Win32GetDiskFree(char *path, UINT64 *free_size, UINT64 *used_size, UINT64 *total_size)
{
	char tmp[MAX_SIZE];
	UINT count = 0;
	UINT i, n, len;
	ULARGE_INTEGER v1, v2, v3;
	bool ret = false;
	// Validate arguments
	if (path == NULL)
	{
		return false;
	}

	Zero(&v1, sizeof(v1));
	Zero(&v2, sizeof(v2));
	Zero(&v3, sizeof(v3));

	NormalizePath(tmp, sizeof(tmp), path);

	// Get the directory name
	if (StartWith(path, "\\\\"))
	{
		count = 4;
	}
	else
	{
		count = 1;
	}

	len = StrLen(tmp);
	n = 0;
	for (i = 0;i < len;i++)
	{
		if (tmp[i] == '\\')
		{
			n++;
			if (n >= count)
			{
				tmp[i + 1] = 0;
				break;
			}
		}
	}

	if (GetDiskFreeSpaceEx(tmp, &v1, &v2, &v3))
	{
		ret = true;
	}

	if (free_size != NULL)
	{
		*free_size = v1.QuadPart;
	}

	if (total_size != NULL)
	{
		*total_size = v2.QuadPart;
	}

	if (used_size != NULL)
	{
		*used_size = v2.QuadPart - v1.QuadPart;
	}

	return ret;
}

// Enumeration of directory
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
				SYSTEMTIME t1, t2;
				wchar_t fullpath[MAX_SIZE];
				bool ok = false;

				f->FileNameW = UniCopyStr(data_w.cFileName);
				f->FileName = CopyUniToStr(f->FileNameW);
				f->Folder = (data_w.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) ? true : false;

				CombinePathW(fullpath, sizeof(fullpath), dirname2, f->FileNameW);

				// Attempt to get the file information
				if (true)
				{
					HANDLE h = CreateFileW(fullpath, 0,
						FILE_SHARE_DELETE | FILE_SHARE_READ | FILE_SHARE_WRITE,
						NULL, OPEN_EXISTING, 0, NULL);

					if (h != INVALID_HANDLE_VALUE)
					{
						BY_HANDLE_FILE_INFORMATION info;

						Zero(&info, sizeof(info));

						if (MsGetFileInformation(h, &info))
						{
							Zero(&t1, sizeof(t1));
							Zero(&t2, sizeof(t2));
							FileTimeToSystemTime(&info.ftCreationTime, &t1);
							FileTimeToSystemTime(&info.ftLastWriteTime, &t2);
							f->CreateDate = SystemToUINT64(&t1);
							f->UpdateDate = SystemToUINT64(&t2);

							if (f->Folder == false)
							{
								f->FileSize = ((UINT64)info.nFileSizeHigh * (UINT64)((UINT64)MAXDWORD + (UINT64)1)) + (UINT64)info.nFileSizeLow;
							}

							ok = true;
						}

						CloseHandle(h);
					}
				}

				if (ok == false)
				{
					Zero(&t1, sizeof(t1));
					Zero(&t2, sizeof(t2));
					FileTimeToSystemTime(&data_w.ftCreationTime, &t1);
					FileTimeToSystemTime(&data_w.ftLastWriteTime, &t2);
					f->CreateDate = SystemToUINT64(&t1);
					f->UpdateDate = SystemToUINT64(&t2);

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

// Get the EXE file name
void Win32GetExeNameW(wchar_t *name, UINT size)
{
	// Validate arguments
	if (name == NULL)
	{
		return;
	}

	UniStrCpy(name, size, L"");

	GetModuleFileNameW(NULL, name, size);
}

// Get the current directory
void Win32GetCurrentDirW(wchar_t *dir, UINT size)
{
	// Validate arguments
	if (dir == NULL)
	{
		return;
	}

	GetCurrentDirectoryW(size, dir);
}

// Yield
void Win32Yield()
{
	Sleep(0);
}

// Get the memory information
void Win32GetMemInfo(MEMINFO *info)
{
	static HINSTANCE hDll = NULL;
	static bool (WINAPI *_GlobalMemoryStatusEx)(LPMEMORYSTATUSEX) = NULL;
	// Validate arguments
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
		// Old API
		MEMORYSTATUS st;
		Zero(&st, sizeof(st));
		st.dwLength = sizeof(st);

		GlobalMemoryStatus(&st);

		// Amount of the logical memory
		info->TotalMemory = (UINT64)st.dwTotalPageFile;
		info->FreeMemory = (UINT64)st.dwAvailPageFile;
		info->UsedMemory = info->TotalMemory - info->FreeMemory;

		// Amount of the physical memory
		info->TotalPhys = (UINT64)st.dwTotalPhys;
		info->FreePhys = (UINT64)st.dwAvailPhys;
		info->UsedPhys = info->TotalPhys - info->FreePhys;
	}
	else
	{
		// New API
		MEMORYSTATUSEX st;
		Zero(&st, sizeof(st));
		st.dwLength = sizeof(st);

		_GlobalMemoryStatusEx(&st);

		// Amount of the logical memory
		info->TotalMemory = st.ullTotalPageFile;
		info->FreeMemory = st.ullAvailPageFile;
		info->UsedMemory = info->TotalMemory - info->FreeMemory;

		// Amount of the physical memory
		info->TotalPhys = st.ullTotalPhys;
		info->FreePhys = st.ullAvailPhys;
		info->UsedPhys = info->TotalPhys - info->FreePhys;
	}
}

// Creating a single instance
void *Win32NewSingleInstance(char *instance_name)
{
	WIN32MUTEX *ret;
	char tmp[MAX_SIZE];
	HANDLE hMutex;
	// Validate arguments
	if (instance_name == NULL)
	{
		char exe_path[MAX_PATH];
		GetModuleFileName(NULL, exe_path, sizeof(exe_path));
		HashInstanceName(tmp, sizeof(tmp), exe_path);
		instance_name = tmp;
	}

	hMutex = OpenMutex(MUTEX_ALL_ACCESS, FALSE, instance_name);
	if (hMutex != NULL)
	{
		CloseHandle(hMutex);
		return NULL;
	}

	hMutex = CreateMutex(NULL, FALSE, instance_name);
	if (hMutex == NULL)
	{
		CloseHandle(hMutex);
		return NULL;
	}

	ret = Win32MemoryAlloc(sizeof(WIN32MUTEX));
	ret->hMutex = hMutex;

	return (void *)ret;
}

// Release the single instance
void Win32FreeSingleInstance(void *data)
{
	WIN32MUTEX *m;
	// Validate arguments
	if (data == NULL)
	{
		return;
	}

	m = (WIN32MUTEX *)data;
	ReleaseMutex(m->hMutex);
	CloseHandle(m->hMutex);

	Win32MemoryFree(m);
}

// Raise the priority
void Win32SetHighPriority()
{
	SetPriorityClass(GetCurrentProcess(), HIGH_PRIORITY_CLASS);
}

// Restore the priority
void Win32RestorePriority()
{
	SetPriorityClass(GetCurrentProcess(), NORMAL_PRIORITY_CLASS);
}

// Get the node information
char* Win32GetProductId()
{
	char *product_id;

	return CopyStr("--");

	// Product ID
	product_id = MsRegReadStr(REG_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", "ProductId");
	if (product_id == NULL)
	{
		product_id = MsRegReadStr(REG_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion", "ProductId");
	}

	return product_id;
}

// Acquisition whether the OS is currently supported
bool Win32IsSupportedOs()
{
	if (Win32GetOsType() == 0)
	{
		Win32Alert(
			CEDAR_PRODUCT_STR " VPN doesn't support this Windows Operating System.\n"
			CEDAR_PRODUCT_STR " VPN requires " SUPPORTED_WINDOWS_LIST ".\n\n"
			"Please contact your system administrator.", NULL);
		return false;
	}

	return true;
}

// Show an alert
void Win32AlertW(wchar_t *msg, wchar_t *caption)
{
	// Validate arguments
	if (msg == NULL)
	{
		msg = L"Alert";
	}
	if (caption == NULL)
	{
		caption = CEDAR_PRODUCT_STR_W L" VPN Kernel";
	}

	MessageBoxW(NULL, msg, caption, MB_SETFOREGROUND | MB_TOPMOST | MB_SERVICE_NOTIFICATION | MB_OK | MB_ICONEXCLAMATION);
}
void Win32Alert(char *msg, char *caption)
{
	// Validate arguments
	if (msg == NULL)
	{
		msg = "Alert";
	}
	if (caption == NULL)
	{
		caption = CEDAR_PRODUCT_STR " VPN Kernel";
	}

	MessageBox(NULL, msg, caption, MB_SETFOREGROUND | MB_TOPMOST | MB_SERVICE_NOTIFICATION | MB_OK | MB_ICONEXCLAMATION);
}
void Win32DebugAlert(char *msg)
{
	// Validate arguments
	if (msg == NULL)
	{
		msg = "Alert";
	}

	MessageBox(NULL, msg, "Debug", MB_SETFOREGROUND | MB_TOPMOST | MB_SERVICE_NOTIFICATION | MB_OK | MB_ICONEXCLAMATION);
}

// Get the number of CPUs
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

// Get the OS information
void Win32GetOsInfo(OS_INFO *info)
{
	UINT type = Win32GetOsType();
	OSVERSIONINFOEX os;
	char tmp[MAX_SIZE];
	// Validate arguments
	if (info == NULL)
	{
		return;
	}

	Zero(&os, sizeof(os));
	os.dwOSVersionInfoSize = sizeof(os);
	Win32GetVersionExInternal((LPOSVERSIONINFOA)&os);

	info->OsType = Win32GetOsType();
	info->OsServicePack = os.wServicePackMajor;
	if (true)
	{
		char *s;
		char *keyname = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion";
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
	}

	info->OsProductName = CopyStr(OsTypeToStr(info->OsType));
	info->OsVendorName = CopyStr("Microsoft Corporation");
}

// GetVersionEx API (Ignore the tricky features that have been added to the Windows 8.2 or later)
bool Win32GetVersionExInternal(void *info)
{
	OSVERSIONINFOA os;
	// Validate arguments
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
				// Windows 8 later
				return Win32GetVersionExInternalForWindows81orLater(info);
			}
		}
	}

	return GetVersionExA(info);
}

// GetVersionEx for Windows 8.1 and later
bool Win32GetVersionExInternalForWindows81orLater(void *info)
{
	OSVERSIONINFOEXA *ex = (OSVERSIONINFOEXA *)info;
	char *str;
	UINT major1 = 0, major2 = 0;
	UINT minor1 = 0, minor2 = 0;
	UINT major = 0, minor = 0;
	// Validate arguments
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
		// Is the version string formed as x.y?
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
		// Version number acquisition success
		ex->dwMajorVersion = major;
		ex->dwMinorVersion = minor;
	}

	return true;
}

// Get the OS type
UINT Win32GetOsType()
{
	OSVERSIONINFOEX os;
	Zero(&os, sizeof(os));
	os.dwOSVersionInfoSize = sizeof(os);

	if (Win32GetVersionExInternal((LPOSVERSIONINFOA)&os) == FALSE)
	{
		// Failure?
		return 0;
	}

	if (os.dwPlatformId != VER_PLATFORM_WIN32_NT)
	{
		// Can not be determined
		return 0;
	}

	if (os.dwMajorVersion < 6 || (os.dwMajorVersion == 6 && os.dwMinorVersion < 4))
	{
		// Windows 8.1 or earlier
		return 0;
	}

	if ((os.dwMajorVersion == 6 && os.dwMinorVersion == 4) || (os.dwMajorVersion == 10 && os.dwMinorVersion == 0))
	{
		if (os.wProductType == VER_NT_WORKSTATION)
		{
			// Windows 10
			return OSTYPE_WINDOWS_10;
		}
		else
		{
			// Windows Server 10
			return OSTYPE_WINDOWS_SERVER_10;
		}
	}
	else
	{
		if (os.wProductType == VER_NT_WORKSTATION)
		{
			// Windows 11 or later
			return OSTYPE_WINDOWS_11;
		}
		else
		{
			// Windows Server 11 or later
			return OSTYPE_WINDOWS_SERVER_11;
		}
	}
}

// Close the process
void Win32CloseProcess(void *handle)
{
	// Validate arguments
	if (handle == NULL)
	{
		return;
	}

	CloseHandle((HANDLE)handle);
}

// Wait for the process termination
bool Win32WaitProcess(void *h, UINT timeout)
{
	// Validate arguments
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

// Run the process (return the handle)
void *Win32RunEx3W(wchar_t *filename, wchar_t *arg, bool hide, UINT *process_id, bool disableWow)
{
	STARTUPINFOW info;
	PROCESS_INFORMATION ret;
	wchar_t cmdline[MAX_SIZE];
	wchar_t name[MAX_PATH];
	void *p;
	// Validate arguments
	if (filename == NULL)
	{
		return NULL;
	}

	UniStrCpy(name, sizeof(name), filename);
	UniTrim(name);

	if (UniSearchStr(name, L"\"", 0) == INFINITE)
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
	else
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

	if (CreateProcessW(NULL, cmdline, NULL, NULL, FALSE,
		(hide == false ? CREATE_NEW_CONSOLE : CREATE_NO_WINDOW | CREATE_NEW_CONSOLE) | NORMAL_PRIORITY_CLASS,
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

// Start the process
bool Win32RunW(wchar_t *filename, wchar_t *arg, bool hide, bool wait)
{
	STARTUPINFOW info;
	PROCESS_INFORMATION ret;
	wchar_t cmdline[MAX_SIZE];
	wchar_t name[MAX_PATH];
	// Validate arguments
	if (filename == NULL)
	{
		return false;
	}

	UniStrCpy(name, sizeof(name), filename);
	UniTrim(name);

	if (UniSearchStr(name, L"\"", 0) == INFINITE)
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
	else
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

	Zero(&info, sizeof(info));
	Zero(&ret, sizeof(ret));
	info.cb = sizeof(info);
	info.dwFlags = STARTF_USESHOWWINDOW;
	info.wShowWindow = (hide == false ? SW_SHOWDEFAULT : SW_HIDE);

	UniTrim(cmdline);

	if (CreateProcessW(NULL, cmdline, NULL, NULL, FALSE,
		(hide == false ? CREATE_NEW_CONSOLE : CREATE_NO_WINDOW | CREATE_NEW_CONSOLE) | NORMAL_PRIORITY_CLASS,
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
bool Win32Run(char *filename, char *arg, bool hide, bool wait)
{
	STARTUPINFO info;
	PROCESS_INFORMATION ret;
	char cmdline[MAX_SIZE];
	char name[MAX_PATH];
	// Validate arguments
	if (filename == NULL)
	{
		return false;
	}

	StrCpy(name, sizeof(name), filename);
	Trim(name);

	if (SearchStr(name, "\"", 0) == INFINITE)
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
	else
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

	Zero(&info, sizeof(info));
	Zero(&ret, sizeof(ret));
	info.cb = sizeof(info);
	info.dwFlags = STARTF_USESHOWWINDOW;
	info.wShowWindow = (hide == false ? SW_SHOWDEFAULT : SW_HIDE);

	Trim(cmdline);

	if (CreateProcess(NULL, cmdline, NULL, NULL, FALSE,
		(hide == false ? CREATE_NEW_CONSOLE : CREATE_NO_WINDOW | CREATE_NEW_CONSOLE) | NORMAL_PRIORITY_CLASS,
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

// Get the Thread ID
UINT Win32ThreadId()
{
	return GetCurrentThreadId();
}

// Rename the file
bool Win32FileRenameW(wchar_t *old_name, wchar_t *new_name)
{
	// Validate arguments
	if (old_name == NULL || new_name == NULL)
	{
		return false;
	}

	// Rename
	if (MoveFileW(old_name, new_name) == FALSE)
	{
		return false;
	}

	return true;
}
bool Win32FileRename(char *old_name, char *new_name)
{
	// Validate arguments
	if (old_name == NULL || new_name == NULL)
	{
		return false;
	}

	// Rename
	if (MoveFile(old_name, new_name) == FALSE)
	{
		return false;
	}

	return true;
}

// Remove the '\' at the end
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
	if (str[i - 1] == L'\\')
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
	if (str[i - 1] == '\\')
	{
		str[i - 1] = 0;
	}
	StrCpy(dst, size, str);
}

// Get the directory name from path
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

// Delete the directory
bool Win32DeleteDirW(wchar_t *name)
{
	// Validate arguments
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
bool Win32DeleteDir(char *name)
{
	// Validate arguments
	if (name == NULL)
	{
		return false;
	}

	if (RemoveDirectory(name) == FALSE)
	{
		return false;
	}
	return true;
}

// Create a directory
bool Win32MakeDirW(wchar_t *name)
{
	// Validate arguments
	if (name == NULL)
	{
		return false;
	}

	if (CreateDirectoryW(name, NULL) == FALSE)
	{
		return false;
	}

	return true;
}
bool Win32MakeDir(char *name)
{
	// Validate arguments
	if (name == NULL)
	{
		return false;
	}

	if (CreateDirectory(name, NULL) == FALSE)
	{
		return false;
	}

	return true;
}

// Delete the file
bool Win32FileDeleteW(wchar_t *name)
{
	// Validate arguments
	if (name == NULL)
	{
		return false;
	}

	if (DeleteFileW(name) == FALSE)
	{
		return false;
	}
	return true;
}
bool Win32FileDelete(char *name)
{
	// Validate arguments
	if (name == NULL)
	{
		return false;
	}

	if (DeleteFile(name) == FALSE)
	{
		return false;
	}
	return true;
}

// Seek in the file
bool Win32FileSeek(void *pData, UINT mode, int offset)
{
	WIN32IO *p;
	DWORD ret;
	// Validate arguments
	if (pData == NULL)
	{
		return false;
	}
	if (mode != FILE_BEGIN && mode != FILE_END && mode != FILE_CURRENT)
	{
		return false;
	}

	p = (WIN32IO *)pData;
	ret = SetFilePointer(p->hFile, (LONG)offset, NULL, mode);
	if (ret == INVALID_SET_FILE_POINTER || ret == ERROR_NEGATIVE_SEEK)
	{
		return false;
	}
	return true;
}

// Get the file size
UINT64 Win32FileSize(void *pData)
{
	WIN32IO *p;
	UINT64 ret;
	DWORD tmp;
	// Validate arguments
	if (pData == NULL)
	{
		return 0;
	}

	p = (WIN32IO *)pData;
	tmp = 0;
	ret = GetFileSize(p->hFile, &tmp);
	if (ret == (DWORD)-1)
	{
		return 0;
	}

	if (tmp != 0)
	{
		ret += (UINT64)tmp * 4294967296ULL;
	}

	return ret;
}

// Write to the file
bool Win32FileWrite(void *pData, void *buf, UINT size)
{
	WIN32IO *p;
	DWORD write_size;
	// Validate arguments
	if (pData == NULL || buf == NULL || size == 0)
	{
		return false;
	}

	p = (WIN32IO *)pData;
	if (WriteFile(p->hFile, buf, size, &write_size, NULL) == FALSE)
	{
		return false;
	}

	if (write_size != size)
	{
		return false;
	}

	return true;
}

// Read from a file
bool Win32FileRead(void *pData, void *buf, UINT size)
{
	WIN32IO *p;
	DWORD read_size;
	// Validate arguments
	if (pData == NULL || buf == NULL || size == 0)
	{
		return false;
	}

	p = (WIN32IO *)pData;
	if (ReadFile(p->hFile, buf, size, &read_size, NULL) == FALSE)
	{
		return false;
	}

	if (read_size != size)
	{
		return false;
	}
	
	return true;;
}

// Close the file
void Win32FileClose(void *pData, bool no_flush)
{
	WIN32IO *p;
	// Validate arguments
	if (pData == NULL)
	{
		return;
	}

	p = (WIN32IO *)pData;
	if (p->WriteMode && no_flush == false)
	{
		FlushFileBuffers(p->hFile);
	}
	CloseHandle(p->hFile);
	p->hFile = NULL;

	// Memory release
	Win32MemoryFree(p);
}

// Get the date of the file
bool Win32FileGetDate(void *pData, UINT64 *created_time, UINT64 *updated_time, UINT64 *accessed_date)
{
	WIN32IO *p;
	BY_HANDLE_FILE_INFORMATION info;
	SYSTEMTIME st_create, st_update, st_access;
	// Validate arguments
	if (pData == NULL)
	{
		return false;
	}

	p = (WIN32IO *)pData;

	Zero(&info, sizeof(info));

	if (GetFileInformationByHandle(p->hFile, &info) == false)
	{
		return false;
	}

	Zero(&st_create, sizeof(st_create));
	Zero(&st_update, sizeof(st_update));
	Zero(&st_access, sizeof(st_access));

	FileTimeToSystemTime(&info.ftCreationTime, &st_create);
	FileTimeToSystemTime(&info.ftLastWriteTime, &st_update);
	FileTimeToSystemTime(&info.ftLastAccessTime, &st_access);

	if (created_time != NULL)
	{
		*created_time = SystemToUINT64(&st_create);
	}

	if (updated_time != NULL)
	{
		*updated_time = SystemToUINT64(&st_update);
	}

	if (accessed_date != NULL)
	{
		*accessed_date = SystemToUINT64(&st_access);
	}

	return true;
}

// Set the date of the file
bool Win32FileSetDate(void *pData, UINT64 created_time, UINT64 updated_time)
{
	WIN32IO *p;
	SYSTEMTIME st_created_time, st_updated_time;
	FILETIME ft_created_time, ft_updated_time;
	FILETIME *p_created_time = NULL, *p_updated_time = NULL;
	// Validate arguments
	if (pData == NULL || (created_time == 0 && updated_time == 0))
	{
		return false;
	}

	p = (WIN32IO *)pData;

	Zero(&st_created_time, sizeof(st_created_time));
	Zero(&st_updated_time, sizeof(st_updated_time));

	if (created_time != 0)
	{
		UINT64ToSystem(&st_created_time, created_time);

		SystemTimeToFileTime(&st_created_time, &ft_created_time);

		p_created_time = &ft_created_time;
	}

	if (updated_time != 0)
	{
		UINT64ToSystem(&st_updated_time, updated_time);

		SystemTimeToFileTime(&st_updated_time, &ft_updated_time);

		p_updated_time = &ft_updated_time;
	}

	return SetFileTime(p->hFile, p_created_time, NULL, p_updated_time);
}

// Flush to the file
void Win32FileFlush(void *pData)
{
	WIN32IO *p;
	// Validate arguments
	if (pData == NULL)
	{
		return;
	}

	p = (WIN32IO *)pData;
	if (p->WriteMode)
	{
		FlushFileBuffers(p->hFile);
	}
}

// Open the file
void *Win32FileOpenW(wchar_t *name, bool write_mode, bool read_lock)
{
	WIN32IO *p;
	HANDLE h;
	DWORD lock_mode;
	// Validate arguments
	if (name == NULL)
	{
		return NULL;
	}

	if (write_mode)
	{
		lock_mode = FILE_SHARE_READ;
	}
	else
	{
		if (read_lock == false)
		{
			lock_mode = FILE_SHARE_READ | FILE_SHARE_WRITE;
		}
		else
		{
			lock_mode = FILE_SHARE_READ;
		}
	}

	// Open the file
	h = CreateFileW(name,
		(write_mode ? GENERIC_READ | GENERIC_WRITE : GENERIC_READ),
		lock_mode,
		NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (h == INVALID_HANDLE_VALUE)
	{
		UINT ret = GetLastError();
		// Failure
		return NULL;
	}

	// Memory allocation
	p = Win32MemoryAlloc(sizeof(WIN32IO));
	// Store Handle
	p->hFile = h;

	p->WriteMode = write_mode;

	return (void *)p;
}
void *Win32FileOpen(char *name, bool write_mode, bool read_lock)
{
	WIN32IO *p;
	HANDLE h;
	DWORD lock_mode;
	// Validate arguments
	if (name == NULL)
	{
		return NULL;
	}

	if (write_mode)
	{
		lock_mode = FILE_SHARE_READ;
	}
	else
	{
		if (read_lock == false)
		{
			lock_mode = FILE_SHARE_READ | FILE_SHARE_WRITE;
		}
		else
		{
			lock_mode = FILE_SHARE_READ;
		}
	}

	// Open the file
	h = CreateFile(name,
		(write_mode ? GENERIC_READ | GENERIC_WRITE : GENERIC_READ),
		lock_mode,
		NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (h == INVALID_HANDLE_VALUE)
	{
		UINT ret = GetLastError();
		// Failure
		return NULL;
	}

	// Memory allocation
	p = Win32MemoryAlloc(sizeof(WIN32IO));
	// Store Handle
	p->hFile = h;

	p->WriteMode = write_mode;

	return (void *)p;
}

// Create a file
void *Win32FileCreateW(wchar_t *name)
{
	WIN32IO *p;
	HANDLE h;
	// Validate arguments
	if (name == NULL)
	{
		return NULL;
	}

	// Create a file
	h = CreateFileW(name, GENERIC_READ | GENERIC_WRITE,
		FILE_SHARE_READ, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL,
		NULL);
	if (h == INVALID_HANDLE_VALUE)
	{
		h = CreateFileW(name, GENERIC_READ | GENERIC_WRITE,
			FILE_SHARE_READ, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_HIDDEN,
			NULL);
		if (h == INVALID_HANDLE_VALUE)
		{
			return NULL;
		}
	}

	// Memory allocation
	p = Win32MemoryAlloc(sizeof(WIN32IO));
	// Store Handle
	p->hFile = h;

	p->WriteMode = true;

	return (void *)p;
}
void *Win32FileCreate(char *name)
{
	WIN32IO *p;
	HANDLE h;
	// Validate arguments
	if (name == NULL)
	{
		return NULL;
	}

	// Create a file
	h = CreateFile(name, GENERIC_READ | GENERIC_WRITE,
		FILE_SHARE_READ, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL,
		NULL);
	if (h == INVALID_HANDLE_VALUE)
	{
		h = CreateFile(name, GENERIC_READ | GENERIC_WRITE,
			FILE_SHARE_READ, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_HIDDEN,
			NULL);
		if (h == INVALID_HANDLE_VALUE)
		{
			return NULL;
		}
	}

	// Memory allocation
	p = Win32MemoryAlloc(sizeof(WIN32IO));
	// Store Handle
	p->hFile = h;

	p->WriteMode = true;

	return (void *)p;
}

#define	SIZE_OF_CALLSTACK_SYM	10000
#define	CALLSTACK_DEPTH			12

// Get the call stack
CALLSTACK_DATA *Win32GetCallStack()
{
#ifndef	WIN32_NO_DEBUG_HELP_DLL
	DWORD current_eip32 = 0, current_esp32 = 0, current_ebp32 = 0;
	UINT64 current_eip = 0, current_esp = 0, current_ebp = 0;
	STACKFRAME64 sf;
	CALLSTACK_DATA *cs = NULL, *s;

#ifdef	CPU_64
	CONTEXT context;
#endif	// CPU_64

	bool ret;
	UINT depth = 0;

#ifndef	CPU_64
	// Register acquisition (32 bit)
	__asm
	{
		mov current_esp32, esp
		mov current_ebp32, ebp
	};

	current_eip32 = (DWORD)Win32GetCallStack;

	current_eip = (UINT64)current_eip32;
	current_esp = (UINT64)current_esp32;
	current_ebp = (UINT64)current_ebp32;
#else	// CPU_64
	// Register acquisition (64 bit)
	Zero(&context, sizeof(context));
	context.ContextFlags = CONTEXT_FULL;
	RtlCaptureContext(&context);
#endif	// CPU_64

	Zero(&sf, sizeof(sf));

#ifndef	CPU_64
	sf.AddrPC.Offset = current_eip;
	sf.AddrStack.Offset = current_esp;
	sf.AddrFrame.Offset = current_ebp;
#else	// CPU_64
	sf.AddrPC.Offset = context.Rip;
	sf.AddrStack.Offset = context.Rsp;
	sf.AddrFrame.Offset = context.Rsp;
#endif	// CPU_64

	sf.AddrPC.Mode = AddrModeFlat;
	sf.AddrStack.Mode = AddrModeFlat;
	sf.AddrFrame.Mode = AddrModeFlat;

	while (true)
	{
		DWORD type = IMAGE_FILE_MACHINE_I386;

#ifdef	CPU_64
		type = IMAGE_FILE_MACHINE_AMD64;
#endif	// CPU_64

		if ((depth++) >= CALLSTACK_DEPTH)
		{
			break;
		}

#ifndef	CPU_64
		ret = StackWalk64(type,
			hCurrentProcessHandle,
			GetCurrentThread(),
			&sf,
			NULL, NULL, SymFunctionTableAccess64, SymGetModuleBase64, NULL);
#else	// CPU_64
		ret = StackWalk64(type,
			hCurrentProcessHandle,
			GetCurrentThread(),
			&sf,
			&context, NULL, SymFunctionTableAccess64, SymGetModuleBase64, NULL);
#endif	// CPU_64
		if (ret == false || sf.AddrFrame.Offset == 0)
		{
			break;
		}

		if (cs == NULL)
		{
			cs = OSMemoryAlloc(sizeof(CALLSTACK_DATA));
			s = cs;
		}
		else
		{
			s->next = OSMemoryAlloc(sizeof(CALLSTACK_DATA));
			s = s->next;
		}
		s->symbol_cache = false;
		s->next = NULL;
		s->offset = sf.AddrPC.Offset;
		s->disp = 0;
		s->name = NULL;
		s->line = 0;
		s->filename[0] = 0;
	}

	return cs;
#else	// WIN32_NO_DEBUG_HELP_DLL
	return NULL;
#endif	// WIN32_NO_DEBUG_HELP_DLL
}

// Get the symbol information from the call stack
bool Win32GetCallStackSymbolInfo(CALLSTACK_DATA *s)
{
#ifdef	WIN32_NO_DEBUG_HELP_DLL
	return false;
#else	// WIN32_NO_DEBUG_HELP_DLL
	UINT64 disp;
	UINT disp32, len;
	IMAGEHLP_SYMBOL64 *sym;
	IMAGEHLP_LINE64 line;
	char tmp[MAX_PATH];
	// Validate arguments
	if (s == NULL)
	{
		return false;
	}

	if (s->symbol_cache)
	{
		return true;
	}

	sym = OSMemoryAlloc(SIZE_OF_CALLSTACK_SYM);
	sym->SizeOfStruct = SIZE_OF_CALLSTACK_SYM;
	sym->MaxNameLength = SIZE_OF_CALLSTACK_SYM - sizeof(IMAGEHLP_SYMBOL64);

	if (SymGetSymFromAddr64(hCurrentProcessHandle, s->offset, &disp, sym))
	{
		s->disp = disp;
		s->name = OSMemoryAlloc((UINT)strlen(sym->Name) + 1);
		lstrcpy(s->name, sym->Name);
	}
	else
	{
		s->disp = 0;
		s->name = NULL;
	}

	Zero(&line, sizeof(line));
	line.SizeOfStruct = sizeof(line);
	if (SymGetLineFromAddr64(hCurrentProcessHandle, s->offset, &disp32, &line))
	{
		disp = (UINT64)disp32;
		s->line = line.LineNumber;
		lstrcpy(s->filename, line.FileName);
		Win32GetDirFromPath(tmp, sizeof(tmp), s->filename);
		len = lstrlen(tmp);
		lstrcpy(tmp, &s->filename[len + 1]);
		lstrcpy(s->filename, tmp);
	}
	else
	{
		s->line = 0;
		s->filename[0] = 0;
	}

	OSMemoryFree(sym);

	s->symbol_cache = true;

	return true;
#endif	// WIN32_NO_DEBUG_HELP_DLL
}

// Default Win32 thread
DWORD CALLBACK Win32DefaultThreadProc(void *param)
{
	WIN32THREADSTARTUPINFO *info = (WIN32THREADSTARTUPINFO *)param;
	// Validate arguments
	if (info == NULL)
	{
		return 0;
	}

	Win32InitNewThread();

	CoInitialize(NULL);

	// Call the thread function
	info->thread_proc(info->thread, info->param);

	// Release the reference
	ReleaseThread(info->thread);

	Win32MemoryFree(info);

	FreeOpenSSLThreadState();

	CoUninitialize();

	_endthreadex(0);
	return 0;
}

// Wait for the termination of the thread
bool Win32WaitThread(THREAD *t)
{
	WIN32THREAD *w;
	// Validate arguments
	if (t == NULL)
	{
		return false;
	}
	w = (WIN32THREAD *)t->pData;
	if (w == NULL)
	{
		return false;
	}

	// Wait for the thread event
	if (WaitForSingleObject(w->hThread, INFINITE) == WAIT_OBJECT_0)
	{
		// The thread was signaled
		return true;
	}

	// Wait failure (time-out, etc.)
	return false;
}

// Release the thread
void Win32FreeThread(THREAD *t)
{
	WIN32THREAD *w;
	// Validate arguments
	if (t == NULL)
	{
		return;
	}
	w = (WIN32THREAD *)t->pData;
	if (w == NULL)
	{
		return;
	}

	// Close the handle
	CloseHandle(w->hThread);

	// Memory release
	Win32MemoryFree(t->pData);
	t->pData = NULL;
}

// Thread initialization
bool Win32InitThread(THREAD *t)
{
	WIN32THREAD *w;
	HANDLE hThread;
	UINT thread_id;
	WIN32THREADSTARTUPINFO *info;
	// Validate arguments
	if (t == NULL)
	{
		return false;
	}
	if (t->thread_proc == NULL)
	{
		return false;
	}

	// Thread data generation
	w = Win32MemoryAlloc(sizeof(WIN32THREAD));

	// Creating the startup information
	info = Win32MemoryAlloc(sizeof(WIN32THREADSTARTUPINFO));
	info->param = t->param;
	info->thread_proc = t->thread_proc;
	info->thread = t;
	AddRef(t->ref);

	// Thread creation
	t->pData = w;
    #pragma clang diagnostic push
    #pragma clang diagnostic ignored "-Wincompatible-function-pointer-types"
	hThread = (HANDLE)_beginthreadex(NULL, 0, Win32DefaultThreadProc, info, 0, &thread_id);
    #pragma clang diagnostic pop
	if (hThread == NULL)
	{
		// Thread creation failure
		t->pData = NULL;
		Release(t->ref);
		Win32MemoryFree(info);
		Win32MemoryFree(w);
		return false;
	}

	// Save the thread information
	w->hThread = hThread;
	w->thread_id = thread_id;

	return true;
}

// Initialize the library for Win32
void Win32Init()
{
	INITCOMMONCONTROLSEX c;

	// Open the stdout
	if (hstdout == INVALID_HANDLE_VALUE)
	{
		hstdout = GetStdHandle(STD_OUTPUT_HANDLE);
	}

	// Open the stdin
	if (hstdin == INVALID_HANDLE_VALUE)
	{
		hstdin = GetStdHandle(STD_INPUT_HANDLE);
	}

	Win32InitNewThread();

	CoInitialize(NULL);

#ifdef	WIN32_USE_HEAP_API_FOR_MEMORY
	use_heap_api = true;
#else	// WIN32_USE_HEAP_API_FOR_MEMORY
	use_heap_api = false;
#endif	// WIN32_USE_HEAP_API_FOR_MEMORY

	if (MayaquaIsDotNetMode())
	{
		// If an heap API is called from .NET API, it might crush
		use_heap_api = false;
	}

	if (use_heap_api)
	{
		heap_handle = HeapCreate(0, 0, 0);
	}

	// Get the process pseudo handle
	hCurrentProcessHandle = GetCurrentProcess();

	// Initialization of the current directory
	// Win32InitCurrentDir(); /* Don't do */

	// Initialization of the symbol handler
	if (IsMemCheck())
	{
#ifndef	WIN32_NO_DEBUG_HELP_DLL
		SymInitialize(hCurrentProcessHandle, NULL, TRUE);
#endif	// WIN32_NO_DEBUG_HELP_DLL
	}

	// Initialization of the Common Control
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

// Release the library for Win32
void Win32Free()
{
	// Close the symbol handler
	if (IsMemCheck())
	{
#ifndef	WIN32_NO_DEBUG_HELP_DLL
		SymCleanup(hCurrentProcessHandle);
#endif	// WIN32_NO_DEBUG_HELP_DLL
	}

	if (use_heap_api)
	{
		HeapDestroy(heap_handle);
		heap_handle = NULL;
	}

	CoUninitialize();
}

// Memory allocation
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

// Memory reallocation
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

// Memory allocation
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

// Get the system timer
UINT Win32GetTick()
{
	return (UINT)timeGetTime();
}

// Get the System Time
void Win32GetSystemTime(SYSTEMTIME *system_time)
{
	// Get the System Time
	GetSystemTime(system_time);
}

// Increment of 32bit integer
void Win32Inc32(UINT *value)
{
	InterlockedIncrement((volatile LONG *)value);
}

// Decrement of 32bit integer
void Win32Dec32(UINT *value)
{
	InterlockedDecrement((volatile LONG *)value);
}

// Sleep the thread
void Win32Sleep(UINT time)
{
	Sleep(time);
}

// Creating a lock
LOCK *Win32NewLock()
{
	// Memory allocation
	LOCK *lock = Win32MemoryAlloc(sizeof(LOCK));

	// Allocate a critical section
	CRITICAL_SECTION *critical_section = Win32MemoryAlloc(sizeof(CRITICAL_SECTION));

	if (lock == NULL || critical_section == NULL)
	{
		Win32MemoryFree(lock);
		Win32MemoryFree(critical_section);
		return NULL;
	}

	// Initialize the critical section
	InitializeCriticalSection(critical_section);

	lock->pData = (void *)critical_section;
	lock->Ready = true;

	return lock;
}

// Lock
bool Win32Lock(LOCK *lock)
{
	CRITICAL_SECTION *critical_section;
	if (lock->Ready == false)
	{
		// State is invalid
		return false;
	}

	// Enter the critical section
	critical_section = (CRITICAL_SECTION *)lock->pData;
	EnterCriticalSection(critical_section);

	return true;
}

// Unlock
void Win32Unlock(LOCK *lock)
{
	Win32UnlockEx(lock, false);
}
void Win32UnlockEx(LOCK *lock, bool inner)
{
	CRITICAL_SECTION *critical_section;
	if (lock->Ready == false && inner == false)
	{
		// State is invalid
		return;
	}

	// Leave the critical section
	critical_section = (CRITICAL_SECTION *)lock->pData;
	LeaveCriticalSection(critical_section);
}

// Delete the lock
void Win32DeleteLock(LOCK *lock)
{
	CRITICAL_SECTION *critical_section;
	// Reset the Ready flag safely
	Win32Lock(lock);
	lock->Ready = false;
	Win32UnlockEx(lock, true);

	// Delete the critical section
	critical_section = (CRITICAL_SECTION *)lock->pData;
	DeleteCriticalSection(critical_section);

	// Memory release
	Win32MemoryFree(critical_section);
	Win32MemoryFree(lock);
}

// Reset the event
void Win32ResetEvent(EVENT *event)
{
	HANDLE hEvent = (HANDLE)event->pData;
	if (hEvent == NULL)
	{
		return;
	}

	ResetEvent(hEvent);
}

// Read a string from the console
bool Win32InputW(wchar_t *str, UINT size)
{
	bool ret = false;
	DWORD read_size = 0;
	// Validate arguments
	if (str == NULL)
	{
		return false;
	}
	if (size == 0)
	{
		size = 0x7fffffff;
	}

	if (str == NULL || size <= sizeof(wchar_t))
	{
		if (str != NULL)
		{
			Zero(str, size);
		}

		return Win32InputFromFileW(NULL, 0);
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
// Get a line from standard input
bool Win32InputFromFileW(wchar_t *str, UINT size)
{
	char *a;
	if (str == NULL)
	{
		wchar_t tmp[MAX_SIZE];
		Win32InputFromFileW(tmp, sizeof(tmp));
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

// Print the string to the console
void Win32PrintW(wchar_t *str)
{
	DWORD write_size = 0;
	// Validate arguments
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
	// Validate arguments
	if (str == NULL)
	{
		return;
	}

	utf = CopyUniToUtf(str);

	WriteFile(hstdout, utf, StrLen(utf), &size, NULL);

	Free(utf);
}


#endif	// WIN32


