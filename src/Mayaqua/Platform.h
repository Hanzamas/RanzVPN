// Platform.h
// The platform functions that Cedar calls: memory info and priority (Win32.c), the OS version
// (OsInfo.c) and folder compression (FileIO.c). Win32.h includes it for the Mayaqua files.

#ifndef	PLATFORM_H
#define	PLATFORM_H

#include "MayaType.h"

void Win32GetMemInfo(MEMINFO *info);
void Win32SetHighPriority();

const OSVERSIONINFOEXW *Win32GetOsVersion();

bool Win32SetFolderCompress(char *path, bool compressed);

#endif

