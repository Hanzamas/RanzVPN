// Listener.c
// Listener module

#include "Listener.h"

#include "Cedar.h"
#include "Connection.h"
#include "HttpListener.h"
#include "HubLog.h"
#include "Protocol.h"
#include "Server.h"
#include "Session.h"

#include "Mayaqua/Mayaqua.h"
#include "Mayaqua/Memory.h"
#include "Mayaqua/Object.h"
#include "Mayaqua/Str.h"
#include "Mayaqua/Tick64.h"

static bool disable_dos = false;
static UINT max_connections_per_ip = DEFAULT_MAX_CONNECTIONS_PER_IP;
static UINT max_unestablished_connections = DEFAULT_MAX_UNESTABLISHED_CONNECTIONS;

UINT GetMaxUnestablishedConnections() {
	return max_unestablished_connections;
}

void SetMaxUnestablishedConnections(UINT num) {
	if (num == 0)
		num = DEFAULT_MAX_UNESTABLISHED_CONNECTIONS;

	max_unestablished_connections = MAX(num, max_connections_per_ip);
}

UINT GetMaxConnectionsPerIp() {
	return max_connections_per_ip;
}

void SetMaxConnectionsPerIp(UINT num) {
	if (num == 0)
		num = DEFAULT_MAX_CONNECTIONS_PER_IP;
	max_connections_per_ip = MAX(num, MIN_MAX_CONNECTIONS_PER_IP);
}

void EnableDosProtect() {
	disable_dos = false;
}

void DisableDosProtect() {
	disable_dos = true;
}

// The server log key of a listener event: name for a VPN listener, http_name for the HTTP listener
static char *ListenerLogKey(const LISTENER *r, char *name, char *http_name) {
	return (r->Protocol == LISTENER_HTTP ? http_name : name);
}

// One connection of an HTTP listener: HttpListener.c answers its one request, then the connection closes
static void HttpAcceptedThread(THREAD *t, void *param) {
	HTTP_LISTENER_CONN *c = (HTTP_LISTENER_CONN *)param;
	if (t == NULL || c == NULL)
		return;

	HttpListenerServe(c->Listener->Cedar, c->Sock, c->Listener->Port);

	Disconnect(c->Sock);
}

// Join and free the connections of an HTTP listener that have ended. With all, every connection: its socket is
// disconnected first, so that one still waiting for its request ends at once
static void HttpJoinConnections(LISTENER *r, bool all) {
	LockList(r->HttpConnList);
	{
		HTTP_LISTENER_CONN **conns = ToArray(r->HttpConnList);
		UINT num = LIST_NUM(r->HttpConnList);

		for (UINT i = 0; i < num; i++) {
			HTTP_LISTENER_CONN *c = conns[i];

			if (all)
				Disconnect(c->Sock);

			if (WaitThread(c->Thread, all ? INFINITE : 0) == false)
				continue;

			Delete(r->HttpConnList, c);
			ReleaseThread(c->Thread);
			ReleaseSock(c->Sock);
			Free(c);
		}

		Free(conns);
	}
	UnlockList(r->HttpConnList);
}

// A connection accepted by an HTTP listener: the per-source DoS guard of the VPN listeners, a limit on the open
// connections, then a thread of its own. Ended connections are joined first
static void HttpAccepted(LISTENER *r, SOCK *s) {
	char tmp[MAX_SIZE];

	if (disable_dos == false && r->DisableDos == false && CheckDosAttack(r, s) == false) {
		IPToStr(tmp, sizeof(tmp), &s->RemoteIP);
		SLog(r->Cedar, "LS_LISTENER_DOS", r->Port, tmp, s->RemotePort);
		return;
	}

	HttpJoinConnections(r, false);

	LockList(r->HttpConnList);
	{
		if (LIST_NUM(r->HttpConnList) < HTTP_LISTENER_MAX_CONNECTIONS) {
			HTTP_LISTENER_CONN *c = ZeroMalloc(sizeof(HTTP_LISTENER_CONN));

			c->Listener = r;
			c->Sock = s;
			AddRef(s->ref);
			c->Thread = NewThread(HttpAcceptedThread, c);

			Add(r->HttpConnList, c);
		}
	}
	UnlockList(r->HttpConnList);
}

static void TCPAcceptedThread(THREAD *t, void *param) {
	char tmp[128];
	if (t == NULL || param == NULL)
		return;

	TCP_ACCEPTED_PARAM *data = (TCP_ACCEPTED_PARAM *)param;
	LISTENER *r = data->r;
	SOCK *s = data->s;
	AddRef(r->ref);
	AddRef(s->ref);

	CONNECTION *c = NewServerConnection(r->Cedar, s, t);

	AddConnection(c->Cedar, c);

	NoticeThreadInit(t);

	AcceptInit(s);
	StrCpy(c->ClientHostname, sizeof(c->ClientHostname), s->RemoteHostname);
	IPToStr(tmp, sizeof(tmp), &s->RemoteIP);
	SLog(r->Cedar, "LS_LISTENER_ACCEPT", r->Port, tmp, s->RemoteHostname, s->RemotePort);

	ConnectionAccept(c);
	bool flag1 = c->flag1;

	SLog(r->Cedar, "LS_CONNECTION_END_1", c->Name);
	ReleaseConnection(c);

	if (flag1 == false) {
		IPToStr(tmp, sizeof(tmp), &s->RemoteIP);

		SLog(r->Cedar, "LS_LISTENER_DISCONNECT", tmp, s->RemotePort);
		Disconnect(s);
	}
	ReleaseSock(s);
	ReleaseListener(r);
}

static void TCPAccepted(LISTENER *r, SOCK *s) {
	char tmp[MAX_SIZE];
	UINT num_clients_from_this_ip = 0;
	if (r == NULL || s == NULL)
		return;

	if (r->Protocol == LISTENER_HTTP) {
		HttpAccepted(r, s);
		return;
	}

	CEDAR *cedar = r->Cedar;

	num_clients_from_this_ip = GetNumIpClient(&s->RemoteIP);

	if (disable_dos == false && r->DisableDos == false) {
		if (CheckDosAttack(r, s) == false) {
			IPToStr(tmp, sizeof(tmp), &s->RemoteIP);
			SLog(r->Cedar, "LS_LISTENER_DOS", r->Port, tmp, s->RemotePort);
			return;
		}
		if (StrCmpi(s->UnderlayProtocol, SOCK_UNDERLAY_NATIVE_V6) == 0 ||
		    StrCmpi(s->UnderlayProtocol, SOCK_UNDERLAY_NATIVE_V4) == 0) {
			if (IsInNoSsl(r->Cedar, &s->RemoteIP)) {
				IPToStr(tmp, sizeof(tmp), &s->RemoteIP);
				SLog(r->Cedar, "LS_LISTENER_DOS", r->Port, tmp, s->RemotePort);
				return;
			}
		}
		if (num_clients_from_this_ip > GetMaxConnectionsPerIp()) {
			IPToStr(tmp, sizeof(tmp), &s->RemoteIP);
			SLog(r->Cedar, "LS_LISTENER_DOS", r->Port, tmp, s->RemotePort);
			return;
		}
		UINT max_uec = GetMaxUnestablishedConnections();
		UINT now_uec = GetUnestablishedConnections(cedar);
		if (now_uec > max_uec) {
			SLog(r->Cedar, "LS_LISTENER_MAXUEC", max_uec, now_uec);
			return;
		}
	}

	TCP_ACCEPTED_PARAM *data = ZeroMalloc(sizeof(TCP_ACCEPTED_PARAM));
	data->r = r;
	data->s = s;

	Inc(cedar->AcceptingSockets);

	THREAD *t = NewThread(TCPAcceptedThread, data);
	WaitThreadInit(t);
	Free(data);
	ReleaseThread(t);
}

static bool IsDosExpired(void *p, void *param) {
	DOS *d = p;
	UINT64 now = *(UINT64 *)param;

	return ((d->LastConnectedTick + d->CurrentExpireSpan) <= now || d->DeleteEntryTick <= now);
}

// Drop the DoS entries whose expire span or total lifetime has run out
static void DeleteExpiredDos(LISTENER *r, UINT64 now) {
	DeleteAndFreeIf(r->DosList, IsDosExpired, &now);
}

// The DoS table is full: drop the expired entries, else the least recently seen one; log the first time
static void MakeRoomInDosList(LISTENER *r) {
	DeleteExpiredDos(r, Tick64());

	if (LIST_NUM(r->DosList) >= RATE_LIMIT_TABLE_MAX) {
		DOS *oldest = NULL;

		for (UINT i = 0; i < LIST_NUM(r->DosList); i++) {
			DOS *d = LIST_DATA(r->DosList, i);

			if (oldest == NULL || d->LastConnectedTick < oldest->LastConnectedTick)
				oldest = d;
		}

		if (oldest != NULL) {
			Delete(r->DosList, oldest);
			Free(oldest);
		}
	}

	if (r->DosListFullLogged == false) {
		r->DosListFullLogged = true;
		SLog(r->Cedar, "LS_LISTENER_DOS_TABLE_FULL", r->Port, (UINT)RATE_LIMIT_TABLE_MAX);
	}
}

bool CheckDosAttack(LISTENER *r, SOCK *s) {
	DOS *d;
	bool ok = true;
	if (r == NULL || s == NULL)
		return false;

	LockList(r->DosList);
	{
		RefreshDosList(r);

		d = SearchDosList(r, &s->RemoteIP);

		if (d != NULL) {
			d->LastConnectedTick = Tick64();
			d->CurrentExpireSpan = MIN(d->CurrentExpireSpan * (UINT64)2, DOS_TABLE_EXPIRES_MAX);
			d->AccessCount++;
			if (d->AccessCount > DOS_TABLE_MAX_LIMIT_PER_IP)
				ok = false;
		} else {
			if (LIST_NUM(r->DosList) >= RATE_LIMIT_TABLE_MAX)
				MakeRoomInDosList(r);

			d = ZeroMalloc(sizeof(DOS));
			d->CurrentExpireSpan = (UINT64)DOS_TABLE_EXPIRES_FIRST;
			d->FirstConnectedTick = d->LastConnectedTick = Tick64();
			d->AccessCount = 1;
			d->DeleteEntryTick = d->FirstConnectedTick + (UINT64)DOS_TABLE_EXPIRES_TOTAL;
			GetRateLimitKey(&d->IpAddress, &s->RemoteIP);
			Insert(r->DosList, d);
		}
	}
	UnlockList(r->DosList);

	return ok;
}

void RefreshDosList(LISTENER *r) {
	if (r == NULL)
		return;

	if (r->DosListLastRefreshTime == 0 ||
	    (r->DosListLastRefreshTime + (UINT64)DOS_TABLE_REFRESH_INTERVAL) <= Tick64()) {
		UINT64 now = Tick64();
		r->DosListLastRefreshTime = now;

		DeleteExpiredDos(r, now);
	}
}

DOS *SearchDosList(LISTENER *r, IP *ip) {
	DOS t;
	if (r == NULL || ip == NULL)
		return NULL;

	GetRateLimitKey(&t.IpAddress, ip);

	DOS *d = Search(r->DosList, &t);

	if (d != NULL) {
		UINT64 now = Tick64();

		if (IsDosExpired(d, &now)) {
			Delete(r->DosList, d);
			Free(d);
			return NULL;
		}
	}

	return d;
}

int CompareDos(void *p1, void *p2) {
	if (p1 == NULL || p2 == NULL)
		return 0;
	DOS *d1 = *(DOS **)p1;
	DOS *d2 = *(DOS **)p2;
	if (d1 == NULL || d2 == NULL)
		return 0;

	return CmpIpAddr(&d1->IpAddress, &d2->IpAddress);
}

// Wake WaitListenerBind: the listener thread has tried to bind, r->Status holds the result
static void ListenerBindTried(const LISTENER *r) {
	if (r->BindEvent != NULL)
		SetEvent((HANDLE)r->BindEvent);
}

// A transient accept() error (IsTransientAcceptError) keeps the listening socket: log it at most once per
// ACCEPT_ERROR_LOG_INTERVAL with the number of errors since the last log, then wait ACCEPT_RETRY_TIME
// (StopListener sets r->Event and ends the wait)
static void ListenerAcceptRetry(LISTENER *r, UINT err) {
	UINT64 now = Tick64();

	r->NumAcceptErrors++;

	if (r->AcceptErrorLogTick == 0 || (r->AcceptErrorLogTick + (UINT64)ACCEPT_ERROR_LOG_INTERVAL) <= now) {
		SLog(r->Cedar, "LS_LISTENER_ACCEPT_RETRY", r->Port, err, r->NumAcceptErrors);
		r->AcceptErrorLogTick = now;
		r->NumAcceptErrors = 0;
	}

	Wait(r->Event, ACCEPT_RETRY_TIME);
}

static void ListenerTCPMainLoop(LISTENER *r) {
	SOCK *new_sock;
	SOCK *s;
	if (r == NULL)
		return;

	r->Status = LISTENER_STATUS_TRYING;

	while (true) {
		bool first_failed = true;
		r->Status = LISTENER_STATUS_TRYING;

		while (true) {
			if (r->Halt)
				return;

			// One socket per port: dual-stack unless IPv6 is disabled or the ListenIP is IPv4
			s = Listen(r->Port, &r->Cedar->Server->ListenIP, r->Cedar->DisableIPv6Listener);

			if (s != NULL) {
				AddRef(s->ref);

				Lock(r->lock);
				{
					r->Sock = s;
				}
				Unlock(r->lock);

				SLog(r->Cedar, ListenerLogKey(r, "LS_LISTENER_START_2", "LS_HTTP_LISTENER_START_2"), r->Port);
				break;
			}

			if (first_failed) {
				first_failed = false;
				SLog(r->Cedar, ListenerLogKey(r, "LS_LISTENER_START_3", "LS_HTTP_LISTENER_START_3"), r->Port, LISTEN_RETRY_TIME / 1000);
			}

			// Status is LISTENER_STATUS_TRYING: the bind failed, the thread retries after the interval
			ListenerBindTried(r);

			Wait(r->Event, LISTEN_RETRY_TIME);

			if (r->Halt)
				return;
		}

		r->Status = LISTENER_STATUS_LISTENING;
		ListenerBindTried(r);

		if (r->Halt)
			goto STOP;

		while (true) {
			new_sock = Accept(s);
			if (new_sock != NULL) {
				TCPAccepted(r, new_sock);
				ReleaseSock(new_sock);
			} else if (r->Halt == false && s->CancelAccept == false && IsTransientAcceptError(s->AcceptError)) {
				// The peer left before the accept, or buffers or descriptors ran short: the listening socket and its backlog stay
				ListenerAcceptRetry(r, s->AcceptError);
			} else {
			STOP:
				Disconnect(s);
				ReleaseSock(s);
				s = NULL;

				Lock(r->lock);
				{
					if (r->Sock != NULL) {
						s = r->Sock;
						r->Sock = NULL;
					}
				}
				Unlock(r->lock);

				if (s != NULL)
					ReleaseSock(s);

				s = NULL;

				break;
			}
		}

		if (r->Halt)
			return;
	}
}

static void ListenerThread(THREAD *thread, void *param) {
	if (thread == NULL || param == NULL)
		return;

	LISTENER *r = (LISTENER *)param;
	AddRef(r->ref);
	r->Thread = thread;
	AddRef(thread->ref);
	NoticeThreadInit(thread);

	switch (r->Protocol) {
	case LISTENER_TCP:
	case LISTENER_HTTP:
		ListenerTCPMainLoop(r);
		break;
	}

	// Halted before any bind attempt: a waiter must not wait for a thread that has ended
	ListenerBindTried(r);

	ReleaseListener(r);
}

void StopListener(LISTENER *r) {
	SOCK *s = NULL;
	if (r == NULL)
		return;

	Lock(r->lock);
	if (r->Halt) {
		Unlock(r->lock);
		return;
	}

	r->Halt = true;

	if (r->Sock != NULL) {
		s = r->Sock;

		AddRef(s->ref);
	}

	Unlock(r->lock);

	UINT port = r->Port;

	SLog(r->Cedar, ListenerLogKey(r, "LS_LISTENER_STOP_1", "LS_HTTP_LISTENER_STOP_1"), port);

	if (s != NULL) {
		Disconnect(s);
		ReleaseSock(s);
		s = NULL;
	}

	Set(r->Event);

	WaitThread(r->Thread, INFINITE);

	// The accept thread has ended: no connection of an HTTP listener starts any more
	if (r->HttpConnList != NULL)
		HttpJoinConnections(r, true);

	SLog(r->Cedar, ListenerLogKey(r, "LS_LISTENER_STOP_2", "LS_HTTP_LISTENER_STOP_2"), port);
}

// Wait until the listener thread has tried to bind the port, at most timeout ms. True when the port is bound;
// false when the bind failed (the thread keeps retrying every LISTEN_RETRY_TIME) or did not finish in time.
bool WaitListenerBind(LISTENER *r, UINT timeout) {
	if (r == NULL)
		return false;

	// The event is set after the thread wrote r->Status and stays set
	if (r->BindEvent != NULL)
		WaitForSingleObject((HANDLE)r->BindEvent, timeout);

	return (r->Status == LISTENER_STATUS_LISTENING);
}

static void CleanupListener(LISTENER *r) {
	UINT i = 0;
	if (r == NULL)
		return;

	for (i = 0; i < LIST_NUM(r->DosList); i++) {
		DOS *d = LIST_DATA(r->DosList, i);
		Free(d);
	}
	ReleaseList(r->DosList);

	if (r->HttpConnList != NULL) {
		HttpJoinConnections(r, true);
		ReleaseList(r->HttpConnList);
	}

	if (r->Sock != NULL)
		ReleaseSock(r->Sock);

	DeleteLock(r->lock);
	ReleaseThread(r->Thread);
	ReleaseEvent(r->Event);

	if (r->BindEvent != NULL)
		CloseHandle((HANDLE)r->BindEvent);

	ReleaseCedar(r->Cedar);

	Free(r);
}

void ReleaseListener(LISTENER *r) {
	if (r == NULL)
		return;

	if (Release(r->ref) == 0)
		CleanupListener(r);
}

int CompareListener(void *p1, void *p2) {
	if (p1 == NULL || p2 == NULL)
		return 0;
	LISTENER *r1 = *(LISTENER **)p1;
	LISTENER *r2 = *(LISTENER **)p2;
	if (r1 == NULL || r2 == NULL)
		return 0;

	if (r1->Protocol > r2->Protocol)
		return 1;
	else if (r1->Protocol < r2->Protocol)
		return -1;
	else if (r1->Port > r2->Port)
		return 1;
	else if (r1->Port < r2->Port)
		return -1;
	else
		return 0;
}

LISTENER *NewListener(CEDAR *cedar, UINT port) {
	return NewListenerEx(cedar, LISTENER_TCP, port);
}

// A listener on port of the kind proto: LISTENER_TCP for a VPN listener, LISTENER_HTTP for the HTTP listener
LISTENER *NewListenerEx(CEDAR *cedar, UINT proto, UINT port) {
	if (port == 0 || cedar == NULL)
		return NULL;

	LISTENER *r = ZeroMalloc(sizeof(LISTENER));

	r->Cedar = cedar;
	AddRef(r->Cedar->ref);
	r->lock = NewLock();
	r->ref = NewRef();
	r->Protocol = proto;
	r->Port = port;
	r->Event = NewEvent();
	// Manual-reset: every waiter of WaitListenerBind sees the first bind attempt, also after it happened
	r->BindEvent = CreateEventW(NULL, TRUE, FALSE, NULL);

	r->DosList = NewList(CompareDos);

	if (proto == LISTENER_HTTP)
		r->HttpConnList = NewList(NULL);

	SLog(cedar, ListenerLogKey(r, "LS_LISTENER_START_1", "LS_HTTP_LISTENER_START_1"), port);

	THREAD *t = NewThread(ListenerThread, r);
	WaitThreadInit(t);
	ReleaseThread(t);

	AddListener(cedar, r);

	return r;
}

void AddListener(CEDAR *c, LISTENER *r) {
	if (c == NULL || r == NULL)
		return;

	LockList(c->ListenerList);
	{
		Add(c->ListenerList, r);
		AddRef(r->ref);
	}
	UnlockList(c->ListenerList);
}

// Stop and release every listener in the ListenerList of c. The server stops its Cedar's listeners with it before it
// stops the Cedar (SiReleaseServer)
void StopAllListener(CEDAR *c) {
	LISTENER **array;
	UINT num;
	if (c == NULL)
		return;

	LockList(c->ListenerList);
	{
		array = ToArray(c->ListenerList);
		num = LIST_NUM(c->ListenerList);
		DeleteAll(c->ListenerList);
	}
	UnlockList(c->ListenerList);

	for (UINT i = 0; i < num; i++) {
		StopListener(array[i]);
		ReleaseListener(array[i]);
	}
	Free(array);
}

