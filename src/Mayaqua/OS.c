// SoftEther VPN Source Code - Developer Edition Master Branch
// Mayaqua Kernel


// OS.c
// Operating system dependent code

#include "OS.h"

#include "Native.h"

#undef Yield

// Dispatch table
static OS_DISPATCH_TABLE *os = NULL;

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
	// Get the dispatch table
#ifdef	OS_WIN32
	os = Win32GetDispatchTable();
#endif	// OS_WIN32

	// Calling the OS-specific initialization function
	os->Init();
}

// Release
void OSFree()
{
	os->Free();
}

// Get the memory information
void OSGetMemInfo(MEMINFO *info)
{
	// Validate arguments
	if (info == NULL)
	{
		return;
	}

	os->GetMemInfo(info);
}

// Yield
void OSYield()
{
	os->Yield();
}

// Start a Single instance
void *OSNewSingleInstance(char *instance_name)
{
	return os->NewSingleInstance(instance_name);
}

void OSFreeSingleInstance(void *data)
{
	os->FreeSingleInstance(data);
}

// Raise the priority
void OSSetHighPriority()
{
	os->SetHighPriority();
}

// Restore the priority
void OSRestorePriority()
{
	os->RestorePriority();
}

// Get the product ID
char* OSGetProductId()
{
	return os->GetProductId();
}

// Check whether the OS is supported
bool OSIsSupportedOs()
{
	return os->IsSupportedOs();
}

// Getting OS information
void OSGetOsInfo(OS_INFO *info)
{
	os->GetOsInfo(info);
}

// Show an alert
void OSAlert(char *msg, char *caption)
{
	os->Alert(msg, caption);
}
void OSAlertW(wchar_t *msg, wchar_t *caption)
{
	os->AlertW(msg, caption);
}

// Run a process
bool OSRun(char *filename, char *arg, bool hide, bool wait)
{
	return os->Run(filename, arg, hide, wait);
}
bool OSRunW(wchar_t *filename, wchar_t *arg, bool hide, bool wait)
{
	return os->RunW(filename, arg, hide, wait);
}

// Get the Thread ID
UINT OSThreadId()
{
	return os->ThreadId();
}

// Rename
bool OSFileRenameW(wchar_t *old_name, wchar_t *new_name)
{
	return os->FileRenameW(old_name, new_name);
}

// Get the file size
UINT64 OSFileSize(void *pData)
{
	return os->FileSize(pData);
}

// Seek the file
bool OSFileSeek(void *pData, UINT mode, int offset)
{
	return os->FileSeek(pData, mode, offset);
}

// Delete the file
bool OSFileDeleteW(wchar_t *name)
{
	return os->FileDeleteW(name);
}

// Create a directory
bool OSMakeDirW(wchar_t *name)
{
	return os->MakeDirW(name);
}

// Delete the directory
bool OSDeleteDirW(wchar_t *name)
{
	return os->DeleteDirW(name);
}

// Open the file
void *OSFileOpenW(wchar_t *name, bool write_mode, bool read_lock)
{
	return os->FileOpenW(name, write_mode, read_lock);
}

// Create a file
void *OSFileCreateW(wchar_t *name)
{
	return os->FileCreateW(name);
}

// Write to a file
bool OSFileWrite(void *pData, void *buf, UINT size)
{
	return os->FileWrite(pData, buf, size);
}

// Read from a file
bool OSFileRead(void *pData, void *buf, UINT size)
{
	return os->FileRead(pData, buf, size);
}

// Close the file
void OSFileClose(void *pData, bool no_flush)
{
	os->FileClose(pData, no_flush);
}

// Flush to the file
void OSFileFlush(void *pData)
{
	os->FileFlush(pData);
}

// Get the call stack
CALLSTACK_DATA *OSGetCallStack()
{
	return os->GetCallStack();
}

// Get the symbol information
bool OSGetCallStackSymbolInfo(CALLSTACK_DATA *s)
{
	return os->GetCallStackSymbolInfo(s);
}

// Wait for the termination of the thread
bool OSWaitThread(THREAD *t)
{
	return os->WaitThread(t);
}

// Release of thread
void OSFreeThread(THREAD *t)
{
	os->FreeThread(t);
}

// Thread initialization
bool OSInitThread(THREAD *t)
{
	return os->InitThread(t);
}

// Memory allocation
void *OSMemoryAlloc(UINT size)
{
	return os->MemoryAlloc(size);
}

// Memory reallocation
void *OSMemoryReAlloc(void *addr, UINT size)
{
	return os->MemoryReAlloc(addr, size);
}

// Memory release
void OSMemoryFree(void *addr)
{
	os->MemoryFree(addr);
}

// Sleep the thread
void OSSleep(UINT time)
{
	os->Sleep(time);
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

// Lock
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

// Unlock
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

// Delete the lock
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

