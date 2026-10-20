// Win32.c
// Microsoft Windows dependent code
//
// WIN32_USE_HEAP_API_FOR_MEMORY (Malloc on a private heap) and WIN32_NO_DEBUG_HELP_DLL (no DbgHelp
// call stacks) come from the build, per configuration (cmake/RanzOptions.cmake)

#include "Win32.h"

#include "FileIO.h"
#include "GlobalConst.h"
#include "Internat.h"
#include "Mayaqua.h"
#include "Microsoft.h"
#include "Memory.h"
#include "Object.h"
#include "Str.h"
#include "Tracking.h"

#include <stdlib.h>
#include <string.h>

#include <objbase.h>
#include <timeapi.h>
#include <winioctl.h>

#ifndef	WIN32_NO_DEBUG_HELP_DLL
#include <DbgHelp.h>		// The call stacks of Win32GetCallStack and Win32GetCallStackSymbolInfo
#endif

static HANDLE heap_handle = NULL;
static HANDLE hstdout = INVALID_HANDLE_VALUE;
static HANDLE hstdin = INVALID_HANDLE_VALUE;

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
	SetThreadLocale(LOCALE_USER_DEFAULT);
}

void Win32GetMemInfo(MEMINFO *info)
{
	MEMORYSTATUSEX st;
	if (info == NULL)
	{
		return;
	}

	Zero(info, sizeof(MEMINFO));

	Zero(&st, sizeof(st));
	st.dwLength = sizeof(st);

	if (GlobalMemoryStatusEx(&st) == false)
	{
		return;
	}

	info->TotalMemory = st.ullTotalPageFile;
	info->FreeMemory = st.ullAvailPageFile;
	info->UsedMemory = info->TotalMemory - info->FreeMemory;

	info->TotalPhys = st.ullTotalPhys;
	info->FreePhys = st.ullAvailPhys;
	info->UsedPhys = info->TotalPhys - info->FreePhys;
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

void Win32Init()
{
	Win32InitConsole();

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

	Win32InitCallStack();
}

void Win32Free()
{
	Win32FreeCallStack();

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

// The standard handles that the console input and output functions read and write
void Win32InitConsole()
{
	if (hstdout == INVALID_HANDLE_VALUE)
	{
		hstdout = GetStdHandle(STD_OUTPUT_HANDLE);
	}

	if (hstdin == INVALID_HANDLE_VALUE)
	{
		hstdin = GetStdHandle(STD_INPUT_HANDLE);
	}
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

