// Listener.h
// Header of Listener.c

#ifndef	LISTENER_H
#define	LISTENER_H

#include "CedarType.h"

#include "Mayaqua/MayaType.h"
#include "Mayaqua/Kernel.h"
#include "Mayaqua/Network.h"

struct DOS
{
	IP IpAddress;
	UINT64 FirstConnectedTick;
	UINT64 LastConnectedTick;
	UINT64 CurrentExpireSpan;
	UINT64 DeleteEntryTick;
	UINT AccessCount;
};

struct LISTENER
{
	LOCK *lock;
	REF *ref;
	CEDAR *Cedar;
	UINT Protocol;
	UINT Port;
	THREAD *Thread;
	SOCK *Sock;
	EVENT *Event;
	volatile bool Halt;
	UINT Status;
	void *BindEvent;			// Manual-reset kernel event, set once the listener thread has tried to bind (WaitListenerBind)

	LIST *DosList;
	UINT64 DosListLastRefreshTime;

	bool ShadowIPv6;
	LISTENER *ShadowListener;
	bool DisableDos;
};

struct TCP_ACCEPTED_PARAM
{
	LISTENER *r;
	SOCK *s;
};

struct UDP_ENTRY
{
	UINT SessionKey32;
	SESSION *Session;
};

LISTENER *NewListener(CEDAR *cedar, UINT port);
void ReleaseListener(LISTENER *r);
void StopListener(LISTENER *r);
bool WaitListenerBind(LISTENER *r, UINT timeout);
int CompareListener(void *p1, void *p2);
void EnableDosProtect();
void DisableDosProtect();
int CompareUDPEntry(void *p1, void *p2);
void AddUDPEntry(CEDAR *cedar, SESSION *session);
void DelUDPEntry(CEDAR *cedar, SESSION *session);
SESSION *GetSessionFromUDPEntry(CEDAR *cedar, UINT key32);
UINT GetMaxConnectionsPerIp();
void SetMaxConnectionsPerIp(UINT num);
UINT GetMaxUnestablishedConnections();
void SetMaxUnestablishedConnections(UINT num);

DOS *SearchDosList(LISTENER *r, IP *ip);
void RefreshDosList(LISTENER *r);
bool CheckDosAttack(LISTENER *r, SOCK *s);

#endif

