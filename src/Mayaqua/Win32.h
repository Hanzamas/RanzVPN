// Win32.h
// Header of Win32.c

#ifndef	WIN32_H
#define	WIN32_H

#include "MayaType.h"
#include "Platform.h"

void Win32SetThreadName(UINT thread_id, char *name);
void Win32InitNewThread();
void *Win32NewSingleInstance(char *instance_name);
void Win32FreeSingleInstance(void *data);
void Win32RestorePriority();
void Win32Init();
void Win32Free();
void *Win32MemoryAlloc(UINT size);
void *Win32MemoryReAlloc(void *addr, UINT size);
void Win32MemoryFree(void *addr);

bool Win32IsSupportedOs();
UINT Win32GetNumberOfCpuInner();
UINT Win32ClassifyOs(UINT major, UINT build, bool server, char **name);
void Win32GetOsInfo(OS_INFO *info);
UINT Win32GetOsType();

void Win32CloseProcess(void *handle);
bool Win32WaitProcess(void *h, UINT timeout);
bool Win32Run(char *filename, char *arg, bool hide, bool wait);

CALLSTACK_DATA *Win32GetCallStack();
bool Win32GetCallStackSymbolInfo(CALLSTACK_DATA *s);
void Win32InitCallStack();
void Win32FreeCallStack();

void Win32InitConsole();
bool Win32InputW(wchar_t *str, UINT size);
void Win32InputDiscardLine();
bool Win32InputFromFileW(wchar_t *str, UINT size);
char *Win32InputFromFileLineA();
void Win32PrintW(wchar_t *str);
void Win32PrintToFileW(wchar_t *str);

DIRLIST *Win32EnumDirExW(wchar_t *dirname, COMPARE *compare);
void Win32GetExeNameW(wchar_t *name, UINT num_chars);
void Win32GetCurrentDirW(wchar_t *dir, UINT num_chars);
void Win32NukuEnW(wchar_t *dst, UINT size, wchar_t *src);
void Win32NukuEn(char *dst, UINT size, char *src);
void Win32GetDirFromPath(char *dst, UINT size, char *src);
bool Win32DeleteDirW(wchar_t *name);

#endif

