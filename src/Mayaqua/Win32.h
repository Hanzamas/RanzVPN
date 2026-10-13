// SoftEther VPN Source Code - Developer Edition Master Branch
// Mayaqua Kernel


// Win32.h
// Header of Win32.c

#ifdef OS_WIN32

#ifndef	WIN32_H
#define	WIN32_H

#include "OS.h"

// Function prototype
void Win32Init();
void Win32Free();
void *Win32MemoryAlloc(UINT size);
void *Win32MemoryReAlloc(void *addr, UINT size);
void Win32MemoryFree(void *addr);
UINT Win32GetTick();
void Win32GetSystemTime(SYSTEMTIME *system_time);
void Win32Sleep(UINT time);
LOCK *Win32NewLock();
bool Win32Lock(LOCK *lock);
void Win32Unlock(LOCK *lock);
void Win32DeleteLock(LOCK *lock);
void Win32InitEvent(EVENT *event);
void Win32SetEvent(EVENT *event);
bool Win32WaitEvent(EVENT *event, UINT timeout);
void Win32FreeEvent(EVENT *event);
bool Win32WaitThread(THREAD *t);
void Win32FreeThread(THREAD *t);
bool Win32InitThread(THREAD *t);
UINT Win32ThreadId();
bool Win32DeleteDirW(wchar_t *name);
CALLSTACK_DATA *Win32GetCallStack();
bool Win32GetCallStackSymbolInfo(CALLSTACK_DATA *s);
bool Win32Run(char *filename, char *arg, bool hide, bool wait);
bool Win32RunW(wchar_t *filename, wchar_t *arg, bool hide, bool wait);
void *Win32RunEx3W(wchar_t *filename, wchar_t *arg, bool hide, UINT *process_id, bool disableWow);
bool Win32WaitProcess(void *h, UINT timeout);
void Win32CloseProcess(void *handle);
bool Win32IsSupportedOs();
void Win32GetOsInfo(OS_INFO *info);
void Win32Alert(char *msg, char *caption);
void Win32AlertW(wchar_t *msg, wchar_t *caption);
void Win32DebugAlert(char *msg);
char* Win32GetProductId();
void Win32SetHighPriority();
void Win32RestorePriority();
void *Win32NewSingleInstance(char *instance_name);
void Win32FreeSingleInstance(void *data);
void Win32GetMemInfo(MEMINFO *info);
void Win32Yield();

void Win32UnlockEx(LOCK *lock, bool inner);
UINT Win32GetOsType();
UINT Win32GetOsSpVer();
void Win32NukuEn(char *dst, UINT size, char *src);
void Win32NukuEnW(wchar_t *dst, UINT size, wchar_t *src);
void Win32GetDirFromPath(char *dst, UINT size, char *src);
void Win32GetDirFromPathW(wchar_t *dst, UINT size, wchar_t *src);
void Win32GetCurrentDirW(wchar_t *dir, UINT size);
void Win32GetExeNameW(wchar_t *name, UINT size);
DIRLIST *Win32EnumDirExW(wchar_t *dirname, COMPARE *compare);
bool Win32GetDiskFree(char *path, UINT64 *free_size, UINT64 *used_size, UINT64 *total_size);
bool Win32SetFolderCompress(char *path, bool compressed);
void Win32InitNewThread();
bool Win32InputW(wchar_t *str, UINT size);
bool Win32InputFromFileW(wchar_t *str, UINT size);
char *Win32InputFromFileLineA();
void Win32PrintW(wchar_t *str);
void Win32PrintToFileW(wchar_t *str);
bool Win32GetVersionExInternal(void *info);
bool Win32GetVersionExInternalForWindows81orLater(void *info);
UINT Win32GetNumberOfCpuInner();


void Win32SetThreadName(UINT thread_id, char *name);

#endif	// WIN32_H

#endif	// OS_WIN32


