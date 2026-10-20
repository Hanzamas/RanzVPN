// Win32.c
// Microsoft Windows dependent code
//
// WIN32_USE_HEAP_API_FOR_MEMORY (Malloc on a private heap) and WIN32_NO_DEBUG_HELP_DLL (no DbgHelp
// call stacks) come from the build, per configuration (cmake/RanzOptions.cmake)

#include "Win32.h"

#include "Internat.h"
#include "Mayaqua.h"
#include "Memory.h"

#include <stdlib.h>

#include <objbase.h>

#ifndef	WIN32_NO_DEBUG_HELP_DLL
#endif

static HANDLE heap_handle = NULL;
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

