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
	IP IpAddress;				// Rate-limit key of the source (GetRateLimitKey)
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
	bool DosListFullLogged;		// MakeRoomInDosList has logged that DosList reached RATE_LIMIT_TABLE_MAX

	UINT64 AcceptErrorLogTick;	// Tick64 of the last log of a transient accept() error, 0 if none yet
	UINT NumAcceptErrors;		// Transient accept() errors since that log

	bool DisableDos;
};

struct TCP_ACCEPTED_PARAM
{
	LISTENER *r;
	SOCK *s;
};

LISTENER *NewListener(CEDAR *cedar, UINT port);
void ReleaseListener(LISTENER *r);
void StopListener(LISTENER *r);
bool WaitListenerBind(LISTENER *r, UINT timeout);
int CompareListener(void *p1, void *p2);
void EnableDosProtect();
void DisableDosProtect();
UINT GetMaxConnectionsPerIp();
void SetMaxConnectionsPerIp(UINT num);
UINT GetMaxUnestablishedConnections();
void SetMaxUnestablishedConnections(UINT num);

int CompareDos(void *p1, void *p2);
DOS *SearchDosList(LISTENER *r, IP *ip);
void RefreshDosList(LISTENER *r);
bool CheckDosAttack(LISTENER *r, SOCK *s);

#endif

