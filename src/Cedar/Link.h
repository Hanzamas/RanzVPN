// Link.h
// Header of Link.c

#ifndef	LINK_H
#define	LINK_H

#include "CedarType.h"

#include "Mayaqua/MayaType.h"

struct LINK
{
	bool Started;
	volatile bool Halting;
	bool Offline;
	bool NoOnline;
	REF *ref;
	LOCK *lock;
	CEDAR *Cedar;
	HUB *Hub;
	SESSION *ClientSession;
	SESSION *ServerSession;
	CLIENT_OPTION *Option;
	CLIENT_AUTH *Auth;
	POLICY *Policy;
	QUEUE *SendPacketQueue;
	UINT CurrentSendPacketQueueSize;
	UINT LastError;
	bool CheckServerCert;
	bool AddDefaultCA;
	X *ServerCert;
	bool LockFlag;
	bool *StopAllLinkFlag;
	UINT LastServerConnectionReceivedBlocksNum;
	UINT Flag1;
};


bool LinkValidateAuthAndPolicy(CLIENT_AUTH *auth, POLICY *policy);
void NormalizeLinkOption(CLIENT_OPTION *option);
LINK *FindLinkByAccountName(HUB *hub, wchar_t *account_name);
LINK *NewLink(CEDAR *cedar, HUB *hub, CLIENT_OPTION *option, CLIENT_AUTH *auth, POLICY *policy);
void StartLink(LINK *k);
void StopLink(LINK *k);
void DelLink(HUB *hub, LINK *k);
void LockLink(LINK *k);
void UnlockLink(LINK *k);
void StopAllLink(HUB *h);
void StartAllLink(HUB *h);
void SetLinkOnline(LINK *k);
void SetLinkOffline(LINK *k);
void ReleaseLink(LINK *k);
void CleanupLink(LINK *k);
void ReleaseAllLink(HUB *h);

#endif	// LINK_H




