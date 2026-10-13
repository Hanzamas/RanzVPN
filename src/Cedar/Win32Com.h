// Win32Com.h
// Header of Win32Com.cpp


#ifndef WIN32COM_H
#define WIN32COM_H

#include "Mayaqua/MayaType.h"

#if	defined(__cplusplus)
extern "C"
{
#endif

	bool InstallNdisProtocolDriver(wchar_t *inf_path, wchar_t *id, UINT lock_timeout);

#if	defined(__cplusplus)
}
#endif

#endif // WIN32COM_H

