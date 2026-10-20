// Win32.h
// Header of Win32.c

#ifndef	WIN32_H
#define	WIN32_H

#include "MayaType.h"

void Win32Init();
void Win32Free();
void Win32InitConsole();
void Win32InitCallStack();
void Win32FreeCallStack();
void *Win32MemoryAlloc(UINT size);
void *Win32MemoryReAlloc(void *addr, UINT size);
void Win32MemoryFree(void *addr);
void Win32InitNewThread();
bool Win32DeleteDirW(wchar_t *name);
CALLSTACK_DATA *Win32GetCallStack();
bool Win32GetCallStackSymbolInfo(CALLSTACK_DATA *s);
bool Win32Run(char *filename, char *arg, bool hide, bool wait);
bool Win32WaitProcess(void *h, UINT timeout);
void Win32CloseProcess(void *handle);
bool Win32IsSupportedOs();
void Win32GetOsInfo(OS_INFO *info);
void Win32SetHighPriority();
void Win32RestorePriority();
void *Win32NewSingleInstance(char *instance_name);
void Win32FreeSingleInstance(void *data);
void Win32GetMemInfo(MEMINFO *info);

const OSVERSIONINFOEXW *Win32GetOsVersion();
UINT Win32GetOsType();
UINT Win32ClassifyOs(UINT major, UINT build, bool server, char **name);
void Win32NukuEn(char *dst, UINT size, char *src);
void Win32NukuEnW(wchar_t *dst, UINT size, wchar_t *src);
void Win32GetDirFromPath(char *dst, UINT size, char *src);
void Win32GetCurrentDirW(wchar_t *dir, UINT num_chars);
void Win32GetExeNameW(wchar_t *name, UINT num_chars);
DIRLIST *Win32EnumDirExW(wchar_t *dirname, COMPARE *compare);
bool Win32SetFolderCompress(char *path, bool compressed);
bool Win32InputW(wchar_t *str, UINT size);
void Win32InputDiscardLine();
bool Win32InputFromFileW(wchar_t *str, UINT size);
char *Win32InputFromFileLineA();
void Win32PrintW(wchar_t *str);
void Win32PrintToFileW(wchar_t *str);
UINT Win32GetNumberOfCpuInner();


void Win32SetThreadName(UINT thread_id, char *name);

#endif

