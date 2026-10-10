// SoftEther VPN Source Code - Developer Edition Master Branch
// Cedar Communication Module


// Win32Com.h
// Header of Win32Com.cpp

#ifdef OS_WIN32

#ifndef WIN32COM_H
#define WIN32COM_H

#include "Mayaqua/MayaType.h"

#if	defined(__cplusplus)
extern "C"
{
#endif

	bool InstallNdisProtocolDriver(wchar_t *inf_path, wchar_t *id, UINT lock_timeout);
	bool UninstallNdisProtocolDriver(wchar_t *id, UINT lock_timeout);

#if	defined(__cplusplus)
}
#endif

#endif // WIN32COM_H

#endif // OS_WIN32
