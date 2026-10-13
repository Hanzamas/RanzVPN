// SoftEther VPN Source Code - Developer Edition Master Branch
// Mayaqua Kernel


// OS.h
// Header of OS.c

#ifndef	OS_H
#define	OS_H

#include "MayaType.h"

// Function prototype
char *OsTypeToStr(UINT type);

void OSInit();
void OSFree();
void *OSMemoryAlloc(UINT size);
void *OSMemoryReAlloc(void *addr, UINT size);
void OSMemoryFree(void *addr);
void OSSleep(UINT time);
LOCK *OSNewLock();
bool OSLock(LOCK *lock);
void OSUnlock(LOCK *lock);
void OSDeleteLock(LOCK *lock);
void OSInitEvent(EVENT *event);
void OSSetEvent(EVENT *event);
bool OSWaitEvent(EVENT *event, UINT timeout);
void OSFreeEvent(EVENT *event);
bool OSWaitThread(THREAD *t);
void OSFreeThread(THREAD *t);
bool OSInitThread(THREAD *t);
CALLSTACK_DATA *OSGetCallStack();
bool OSGetCallStackSymbolInfo(CALLSTACK_DATA *s);
UINT OSThreadId();
bool OSRun(char *filename, char *arg, bool hide, bool wait);
bool OSRunW(wchar_t *filename, wchar_t *arg, bool hide, bool wait);
bool OSIsSupportedOs();
void OSGetOsInfo(OS_INFO *info);
void OSAlert(char *msg, char *caption);
void OSAlertW(wchar_t *msg, wchar_t *caption);
char* OSGetProductId();
void OSSetHighPriority();
void OSRestorePriority();
void *OSNewSingleInstance(char *instance_name);
void OSFreeSingleInstance(void *data);
void OSGetMemInfo(MEMINFO *info);
void OSYield();

// Include the OS-specific header
#ifdef	OS_WIN32
#include <Mayaqua/Win32.h>
#endif	// OS_WIN32

#endif	// OS_H

