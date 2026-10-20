// Win32Com.h
// Header of Win32Com.c


#ifndef WIN32COM_H
#define WIN32COM_H

#include "Mayaqua/MayaType.h"

bool InstallNdisProtocolDriver(wchar_t *inf_path, wchar_t *id, UINT lock_timeout);

#endif // WIN32COM_H

