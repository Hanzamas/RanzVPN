// SoftEther VPN Source Code - Developer Edition Master Branch
// Cedar Communication Module


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


PACKET_ADAPTER *LinkGetPacketAdapter();
bool LinkPaInit(SESSION *s);
CANCEL *LinkPaGetCancel(SESSION *s);
UINT LinkPaGetNextPacket(SESSION *s, void **data);
bool LinkPaPutPacket(SESSION *s, void *data, UINT size);
void LinkPaFree(SESSION *s);

void LinkServerSessionThread(THREAD *t, void *param);
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
void NormalizeLinkPolicy(POLICY *p);

#endif	// LINK_H




