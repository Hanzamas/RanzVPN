// SoftEther VPN Source Code - Developer Edition Master Branch
// Mayaqua Kernel


// Native.h
// Thin header: static inline Mayaqua functions that call the Windows API directly
// Leaf header: it includes MayaType.h only, so any module header can include it

#ifndef	NATIVE_H
#define	NATIVE_H

#include "MayaType.h"

// Event object
struct EVENT
{
	REF *ref;
	void *pData;
};

// Set event: an unnamed auto-reset kernel event (NewEvent); no effect without the event or its handle
static inline void Set(EVENT *e)
{
	if (e != NULL && e->pData != NULL)
	{
		SetEvent((HANDLE)e->pData);
	}
}

#endif	// NATIVE_H
