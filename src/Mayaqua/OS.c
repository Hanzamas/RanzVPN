// OS.c
// Operating system dependent code

#include "OS.h"

#include "Native.h"

char *OsTypeToStr(UINT type)
{
	switch (type)
	{
	case 0:
		return "Unsupported OS by Ranz VPN\0\n";
	case OSTYPE_WINDOWS_10:
		return "Windows 10\0\n";
	case OSTYPE_WINDOWS_SERVER_10:
		return "Windows Server 2016\0\n";
	case OSTYPE_WINDOWS_11:
		return "Newer than Windows 10\0\n";
	case OSTYPE_WINDOWS_SERVER_11:
		return "Newer than Windows Server 2016\0\n";
	}

	return "Unknown OS";
}

void OSInit()
{
	Win32Init();
}

void OSFree()
{
	Win32Free();
}

void OSGetMemInfo(MEMINFO *info)
{
	if (info == NULL)
	{
		return;
	}

	Win32GetMemInfo(info);
}

void OSYield()
{
	Win32Yield();
}

void *OSNewSingleInstance(char *instance_name)
{
	return Win32NewSingleInstance(instance_name);
}

void OSFreeSingleInstance(void *data)
{
	Win32FreeSingleInstance(data);
}

void OSSetHighPriority()
{
	Win32SetHighPriority();
}

void OSRestorePriority()
{
	Win32RestorePriority();
}

char* OSGetProductId()
{
	return Win32GetProductId();
}

bool OSIsSupportedOs()
{
	return Win32IsSupportedOs();
}

void OSGetOsInfo(OS_INFO *info)
{
	Win32GetOsInfo(info);
}

bool OSRun(char *filename, char *arg, bool hide, bool wait)
{
	return Win32Run(filename, arg, hide, wait);
}

UINT OSThreadId()
{
	return Win32ThreadId();
}

CALLSTACK_DATA *OSGetCallStack()
{
	return Win32GetCallStack();
}

bool OSGetCallStackSymbolInfo(CALLSTACK_DATA *s)
{
	return Win32GetCallStackSymbolInfo(s);
}

void *OSMemoryAlloc(UINT size)
{
	return Win32MemoryAlloc(size);
}

void *OSMemoryReAlloc(void *addr, UINT size)
{
	return Win32MemoryReAlloc(addr, size);
}

void OSMemoryFree(void *addr)
{
	Win32MemoryFree(addr);
}

void OSSleep(UINT time)
{
	Win32Sleep(time);
}

// Create a Lock. This is the raw LOCK: it never touches the KS_ counters, because
// KS_INC itself takes such a lock. One heap block from the raw OS allocator.
LOCK *OSNewLock()
{
	// Memory allocation
	LOCK *lock = Win32MemoryAlloc(sizeof(LOCK));

	if (lock == NULL)
	{
		return NULL;
	}

	// Initialize the critical section
	InitializeCriticalSection(&lock->CriticalSection);
	lock->Ready = true;

	return lock;
}

bool OSLock(LOCK *lock)
{
	if (lock->Ready == false)
	{
		// State is invalid
		return false;
	}

	// Enter the critical section
	EnterCriticalSection(&lock->CriticalSection);

	return true;
}

void OSUnlock(LOCK *lock)
{
	if (lock->Ready == false)
	{
		// State is invalid
		return;
	}

	// Leave the critical section
	LeaveCriticalSection(&lock->CriticalSection);
}

void OSDeleteLock(LOCK *lock)
{
	// Reset the Ready flag safely
	EnterCriticalSection(&lock->CriticalSection);
	lock->Ready = false;
	LeaveCriticalSection(&lock->CriticalSection);

	// Delete the critical section
	DeleteCriticalSection(&lock->CriticalSection);

	// Memory release
	Win32MemoryFree(lock);
}


