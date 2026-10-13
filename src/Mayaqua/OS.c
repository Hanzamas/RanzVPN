// OS.c
// Operating system dependent code

#include "OS.h"

#undef Yield

static OS_DISPATCH_TABLE *os = NULL;

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

void OSInit()
{
	os = Win32GetDispatchTable();

	os->Init();
}

void OSFree()
{
	os->Free();
}

void OSGetMemInfo(MEMINFO *info)
{
	if (info == NULL)
	{
		return;
	}

	os->GetMemInfo(info);
}

void OSYield()
{
	os->Yield();
}

void *OSNewSingleInstance(char *instance_name)
{
	return os->NewSingleInstance(instance_name);
}

void OSFreeSingleInstance(void *data)
{
	os->FreeSingleInstance(data);
}

void OSSetHighPriority()
{
	os->SetHighPriority();
}

void OSRestorePriority()
{
	os->RestorePriority();
}

char* OSGetProductId()
{
	return os->GetProductId();
}

bool OSIsSupportedOs()
{
	return os->IsSupportedOs();
}

void OSGetOsInfo(OS_INFO *info)
{
	os->GetOsInfo(info);
}

void OSAlert(char *msg, char *caption)
{
	os->Alert(msg, caption);
}
void OSAlertW(wchar_t *msg, wchar_t *caption)
{
	os->AlertW(msg, caption);
}

bool OSRun(char *filename, char *arg, bool hide, bool wait)
{
	return os->Run(filename, arg, hide, wait);
}
bool OSRunW(wchar_t *filename, wchar_t *arg, bool hide, bool wait)
{
	return os->RunW(filename, arg, hide, wait);
}

UINT OSThreadId()
{
	return os->ThreadId();
}

bool OSFileRenameW(wchar_t *old_name, wchar_t *new_name)
{
	return os->FileRenameW(old_name, new_name);
}

UINT64 OSFileSize(void *pData)
{
	return os->FileSize(pData);
}

bool OSFileSeek(void *pData, UINT mode, int offset)
{
	return os->FileSeek(pData, mode, offset);
}

bool OSFileDeleteW(wchar_t *name)
{
	return os->FileDeleteW(name);
}

bool OSMakeDirW(wchar_t *name)
{
	return os->MakeDirW(name);
}

bool OSDeleteDirW(wchar_t *name)
{
	return os->DeleteDirW(name);
}

void *OSFileOpenW(wchar_t *name, bool write_mode, bool read_lock)
{
	return os->FileOpenW(name, write_mode, read_lock);
}

void *OSFileCreateW(wchar_t *name)
{
	return os->FileCreateW(name);
}

bool OSFileWrite(void *pData, void *buf, UINT size)
{
	return os->FileWrite(pData, buf, size);
}

bool OSFileRead(void *pData, void *buf, UINT size)
{
	return os->FileRead(pData, buf, size);
}

void OSFileClose(void *pData, bool no_flush)
{
	os->FileClose(pData, no_flush);
}

void OSFileFlush(void *pData)
{
	os->FileFlush(pData);
}

CALLSTACK_DATA *OSGetCallStack()
{
	return os->GetCallStack();
}

bool OSGetCallStackSymbolInfo(CALLSTACK_DATA *s)
{
	return os->GetCallStackSymbolInfo(s);
}

bool OSWaitThread(THREAD *t)
{
	return os->WaitThread(t);
}

void OSFreeThread(THREAD *t)
{
	os->FreeThread(t);
}

bool OSInitThread(THREAD *t)
{
	return os->InitThread(t);
}

void *OSMemoryAlloc(UINT size)
{
	return os->MemoryAlloc(size);
}

void *OSMemoryReAlloc(void *addr, UINT size)
{
	return os->MemoryReAlloc(addr, size);
}

void OSMemoryFree(void *addr)
{
	os->MemoryFree(addr);
}

UINT OSGetTick()
{
	return os->GetTick();
}

void OSGetSystemTime(SYSTEMTIME *system_time)
{
	os->GetSystemTime(system_time);
}

void OSSleep(UINT time)
{
	os->Sleep(time);
}

LOCK *OSNewLock()
{
	return os->NewLock();
}

bool OSLock(LOCK *lock)
{
	return os->Lock(lock);
}

void OSUnlock(LOCK *lock)
{
	os->Unlock(lock);
}

void OSDeleteLock(LOCK *lock)
{
	os->DeleteLock(lock);
}

void OSInitEvent(EVENT *event)
{
	os->InitEvent(event);
}

void OSSetEvent(EVENT *event)
{
	os->SetEvent(event);
}

bool OSWaitEvent(EVENT *event, UINT timeout)
{
	return os->WaitEvent(event, timeout);
}

void OSFreeEvent(EVENT *event)
{
	os->FreeEvent(event);
}

