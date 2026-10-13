// SoftEther VPN Source Code - Developer Edition Master Branch
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


SU *SuInit();
SU *SuInitEx(UINT wait_for_bind_complete_tick);
void SuFree(SU *u);
SU_ADAPTER *SuOpenAdapter(SU *u, char *adapter_id);
void SuCloseAdapter(SU_ADAPTER *a);
void SuCloseAdapterHandleInner(SU_ADAPTER *a);
bool SuGetPacketsFromDriver(SU_ADAPTER *a);
bool SuGetNextPacket(SU_ADAPTER *a, void **buf, UINT *size);
bool SuPutPacketsToDriver(SU_ADAPTER *a);
bool SuPutPacket(SU_ADAPTER *a, void *buf, UINT size);

SU_ADAPTER_LIST *SuAdapterInfoToAdapterList(SL_ADAPTER_INFO *info);
LIST *SuGetAdapterList(SU *u);
void SuFreeAdapterList(LIST *o);
int SuCmpAdapterList(void *p1, void *p2);

bool SuInstallDriver(bool force);
bool SuInstallDriverInner(bool force);
bool SuIsSupportedOs(bool on_install);
bool SuCopySysFile(wchar_t *src, wchar_t *dst);

void SuDeleteGarbageInfs();
void SuDeleteGarbageInfsInner();
bool SuLoadDriversHive();

#endif	// SELOWUSER_H



