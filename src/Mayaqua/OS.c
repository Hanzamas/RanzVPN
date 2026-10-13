// SoftEther VPN Source Code - Developer Edition Master Branch
// Mayaqua Kernel


// OS.c
// Operating system dependent code

#include "OS.h"

#undef Yield

// Convert OS type to a string
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
	case OSTYPE_UNIX_UNKNOWN:
		return "UNIX System\0\n";
	case OSTYPE_LINUX:
		return "Linux\0\n";
	case OSTYPE_SOLARIS:
		return "Sun Solaris\0\n";
	case OSTYPE_CYGWIN:
		return "Gnu Cygwin\0\n";
	case OSTYPE_BSD:
		return "BSD System\0\n";
	case OSTYPE_MACOS_X:
		return "Mac OS X\0\n";
	}

	return "Unknown OS";
}

// Initialization
void OSInit()
{
	// Calling the OS-specific initialization function
	Win32Init();
}

// Release
void OSFree()
{
	Win32Free();
}

// Get the memory information
void OSGetMemInfo(MEMINFO *info)
{
	// Validate arguments
	if (info == NULL)
	{
		return;
	}

	Win32GetMemInfo(info);
}

// Yield
void OSYield()
{
	Win32Yield();
}

// Start a Single instance
void *OSNewSingleInstance(char *instance_name)
{
	return Win32NewSingleInstance(instance_name);
}

void OSFreeSingleInstance(void *data)
{
	Win32FreeSingleInstance(data);
}

// Raise the priority
void OSSetHighPriority()
{
	Win32SetHighPriority();
}

// Restore the priority
void OSRestorePriority()
{
	Win32RestorePriority();
}

// Get the product ID
char* OSGetProductId()
{
	return Win32GetProductId();
}

// Check whether the OS is supported
bool OSIsSupportedOs()
{
	return Win32IsSupportedOs();
}

// Getting OS information
void OSGetOsInfo(OS_INFO *info)
{
	Win32GetOsInfo(info);
}

// Show an alert
void OSAlert(char *msg, char *caption)
{
	Win32Alert(msg, caption);
}
void OSAlertW(wchar_t *msg, wchar_t *caption)
{
	Win32AlertW(msg, caption);
}

// Run a process
bool OSRun(char *filename, char *arg, bool hide, bool wait)
{
	return Win32Run(filename, arg, hide, wait);
}
bool OSRunW(wchar_t *filename, wchar_t *arg, bool hide, bool wait)
{
	return Win32RunW(filename, arg, hide, wait);
}

// Get the Thread ID
UINT OSThreadId()
{
	return Win32ThreadId();
}

// Get the call stack
CALLSTACK_DATA *OSGetCallStack()
{
	return Win32GetCallStack();
}

// Get the symbol information
bool OSGetCallStackSymbolInfo(CALLSTACK_DATA *s)
{
	return Win32GetCallStackSymbolInfo(s);
}

// Wait for the termination of the thread
bool OSWaitThread(THREAD *t)
{
	return Win32WaitThread(t);
}

// Release of thread
void OSFreeThread(THREAD *t)
{
	Win32FreeThread(t);
}

// Thread initialization
bool OSInitThread(THREAD *t)
{
	return Win32InitThread(t);
}

// Memory allocation
void *OSMemoryAlloc(UINT size)
{
	return Win32MemoryAlloc(size);
}

// Memory reallocation
void *OSMemoryReAlloc(void *addr, UINT size)
{
	return Win32MemoryReAlloc(addr, size);
}

// Memory release
void OSMemoryFree(void *addr)
{
	Win32MemoryFree(addr);
}

// Sleep the thread
void OSSleep(UINT time)
{
	Win32Sleep(time);
}

// Create a Lock
LOCK *OSNewLock()
{
	return Win32NewLock();
}

// Lock
bool OSLock(LOCK *lock)
{
	return Win32Lock(lock);
}

// Unlock
void OSUnlock(LOCK *lock)
{
	Win32Unlock(lock);
}

// Delete the lock
void OSDeleteLock(LOCK *lock)
{
	Win32DeleteLock(lock);
}

// Event initialization
void OSInitEvent(EVENT *event)
{
	Win32InitEvent(event);
}

// Set event
void OSSetEvent(EVENT *event)
{
	Win32SetEvent(event);
}

// Wait for event
bool OSWaitEvent(EVENT *event, UINT timeout)
{
	return Win32WaitEvent(event, timeout);
}

// Release of the event
void OSFreeEvent(EVENT *event)
{
	Win32FreeEvent(event);
}

