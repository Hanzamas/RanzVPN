// SeLow: SoftEther Lightweight Network Protocol


// SeLowUser.h
// Header for SeLowUser.c

#ifndef	SELOWUSER_H
#define	SELOWUSER_H

#include "CedarType.h"

#include "Mayaqua/Mayaqua.h"

#include <SeLow/SeLowCommon.h>

#define	SL_USER_INSTALL_LOCK_TIMEOUT		60000		// Lock acquisition timeout
#define	SL_USER_AUTO_PUSH_TIMER				60000		// Timer to start the installation automatically

// Driver install step (SuInstallDriver); a test replaces it with SuSetInstallProc
typedef bool (SU_INSTALL_PROC)(bool force);

struct SU
{
	void *hFile;
	SL_ADAPTER_INFO_LIST AdapterInfoList;
};

struct SU_ADAPTER
{
	char AdapterId[MAX_PATH];
	char DeviceName[MAX_PATH];
	void *hFile;
	void *hEvent;
	bool Halt;
	UINT CurrentPacketCount;
	bool LastGetHadPacket;		// The previous SuGetNextPacket call returned a frame
	UCHAR GetBuffer[SL_EXCHANGE_BUFFER_SIZE];
	UCHAR PutBuffer[SL_EXCHANGE_BUFFER_SIZE];
};

struct SU_ADAPTER_LIST
{
	SL_ADAPTER_INFO Info;
	char Guid[128];
	char Name[MAX_SIZE];
	char SortKey[MAX_SIZE];
};


SU *SuInitEx(UINT wait_for_bind_complete_tick);
SU *SuInitInstall();
void SuFree(SU *u);
SU_ADAPTER *SuOpenAdapter(SU *u, char *adapter_id);
void SuCloseAdapter(SU_ADAPTER *a);
void SuCloseAdapterHandleInner(SU_ADAPTER *a);
bool SuGetPacketsFromDriver(SU_ADAPTER *a);
bool SuGetNextPacket(SU_ADAPTER *a, void **buf, UINT *size);
bool SuHasPendingPackets(SU_ADAPTER *a);
bool SuPutPacketsToDriver(SU_ADAPTER *a);
bool SuPutPacket(SU_ADAPTER *a, void *buf, UINT size);

SU_ADAPTER_LIST *SuAdapterInfoToAdapterList(SL_ADAPTER_INFO *info);
bool SuReadAdapterInfoList(void *h, SL_ADAPTER_INFO_LIST *list);
LIST *SuGetAdapterList(SU *u);
void SuFreeAdapterList(LIST *o);
int SuCmpAdapterList(void *p1, void *p2);

bool SuInstallDriverInner(bool force);
void SuSetInstallProc(SU_INSTALL_PROC *proc);
bool SuIsSupportedOs(bool on_install);
bool SuCopySysFile(wchar_t *src, wchar_t *dst);

void SuDeleteGarbageInfsInner();

#endif	// SELOWUSER_H



