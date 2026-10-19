// Listener.c
// Listener module

#include "Listener.h"

#include "Cedar.h"
#include "Connection.h"
#include "Logging.h"
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

UINT GetMaxUnestablishedConnections()
{
	return max_unestablished_connections;
}

void SetMaxUnestablishedConnections(UINT num)
{
	if (num == 0)
	{
		num = DEFAULT_MAX_UNESTABLISHED_CONNECTIONS;
	}

	max_unestablished_connections = MAX(num, max_connections_per_ip);
}

UINT GetMaxConnectionsPerIp()
{
	return max_connections_per_ip;
}

void SetMaxConnectionsPerIp(UINT num)
{
	if (num == 0)
	{
		num = DEFAULT_MAX_CONNECTIONS_PER_IP;
	}
	max_connections_per_ip = MAX(num, MIN_MAX_CONNECTIONS_PER_IP);
}

void EnableDosProtect()
{
	disable_dos = false;
}

void DisableDosProtect()
{
	disable_dos = true;
}

static void TCPAcceptedThread(THREAD *t, void *param)
{
	TCP_ACCEPTED_PARAM *data;
	LISTENER *r;
	SOCK *s;
	CONNECTION *c;
	bool flag1;
	char tmp[128];
	if (t == NULL || param == NULL)
	{
		return;
	}

	data = (TCP_ACCEPTED_PARAM *)param;
	r = data->r;
	s = data->s;
	AddRef(r->ref);
	AddRef(s->ref);

	c = NewServerConnection(r->Cedar, s, t);

	AddRef(r->ref);
	c->Listener = r;

	AddConnection(c->Cedar, c);

	NoticeThreadInit(t);

	AcceptInit(s);
	StrCpy(c->ClientHostname, sizeof(c->ClientHostname), s->RemoteHostname);
	IPToStr(tmp, sizeof(tmp), &s->RemoteIP);
	if (IS_SPECIAL_PORT(s->RemotePort) == false)
	{
		SLog(r->Cedar, "LS_LISTENER_ACCEPT", r->Port, tmp, s->RemoteHostname, s->RemotePort);
	}

	ConnectionAccept(c);
	flag1 = c->flag1;

	SLog(r->Cedar, "LS_CONNECTION_END_1", c->Name);
	ReleaseListener(c->Listener);
	c->Listener = NULL;
	ReleaseConnection(c);

	if (flag1 == false)
	{
		IPToStr(tmp, sizeof(tmp), &s->RemoteIP);

		if (IS_SPECIAL_PORT(s->RemotePort) == false)
		{
			SLog(r->Cedar, "LS_LISTENER_DISCONNECT", tmp, s->RemotePort);
		}
		Disconnect(s);
	}
	ReleaseSock(s);
	ReleaseListener(r);
}

static void TCPAccepted(LISTENER *r, SOCK *s)
{
	TCP_ACCEPTED_PARAM *data;
	THREAD *t;
	char tmp[MAX_SIZE];
	UINT num_clients_from_this_ip = 0;
	CEDAR *cedar;
	if (r == NULL || s == NULL)
	{
		return;
	}

	cedar = r->Cedar;

	num_clients_from_this_ip = GetNumIpClient(&s->RemoteIP);

	if (disable_dos == false && r->DisableDos == false)
	{
		UINT max_uec, now_uec;
		if (CheckDosAttack(r, s) == false)
		{
			IPToStr(tmp, sizeof(tmp), &s->RemoteIP);
			SLog(r->Cedar, "LS_LISTENER_DOS", r->Port, tmp, s->RemotePort);
			return;
		}
		if (StrCmpi(s->UnderlayProtocol, SOCK_UNDERLAY_NATIVE_V6) == 0 ||
			StrCmpi(s->UnderlayProtocol, SOCK_UNDERLAY_NATIVE_V4) == 0)
		{
			if (IsInNoSsl(r->Cedar, &s->RemoteIP))
			{
				IPToStr(tmp, sizeof(tmp), &s->RemoteIP);
				SLog(r->Cedar, "LS_LISTENER_DOS", r->Port, tmp, s->RemotePort);
				return;
			}
		}
		if (num_clients_from_this_ip > GetMaxConnectionsPerIp())
		{
			IPToStr(tmp, sizeof(tmp), &s->RemoteIP);
			SLog(r->Cedar, "LS_LISTENER_DOS", r->Port, tmp, s->RemotePort);
			return;
		}
		max_uec = GetMaxUnestablishedConnections();
		now_uec = GetUnestablishedConnections(cedar);
		if (now_uec > max_uec)
		{
			SLog(r->Cedar, "LS_LISTENER_MAXUEC", max_uec, now_uec);
			return;
		}
	}

	IPToStr(tmp, sizeof(tmp), &s->RemoteIP);

	data = ZeroMalloc(sizeof(TCP_ACCEPTED_PARAM));
	data->r = r;
	data->s = s;

	if (r->ThreadProc == TCPAcceptedThread)
	{
		Inc(cedar->AcceptingSockets);
	}

	t = NewThread(r->ThreadProc, data);
	WaitThreadInit(t);
	Free(data);
	ReleaseThread(t);
}

bool CheckDosAttack(LISTENER *r, SOCK *s)
{
	DOS *d;
	bool ok = true;
	if (r == NULL || s == NULL)
	{
		return false;
	}

	LockList(r->DosList);
	{
		RefreshDosList(r);

		d = SearchDosList(r, &s->RemoteIP);

		if (d != NULL)
		{
			d->LastConnectedTick = Tick64();
			d->CurrentExpireSpan = MIN(d->CurrentExpireSpan * (UINT64)2, DOS_TABLE_EXPIRES_MAX);
			d->AccessCount++;
			if (d->AccessCount > DOS_TABLE_MAX_LIMIT_PER_IP)
			{
				ok = false;
			}
		}
		else
		{
			d = ZeroMalloc(sizeof(DOS));
			d->CurrentExpireSpan = (UINT64)DOS_TABLE_EXPIRES_FIRST;
			d->FirstConnectedTick = d->LastConnectedTick = Tick64();
			d->AccessCount = 1;
			d->DeleteEntryTick = d->FirstConnectedTick + (UINT64)DOS_TABLE_EXPIRES_TOTAL;
			Copy(&d->IpAddress, &s->RemoteIP, sizeof(IP));
			Add(r->DosList, d);
		}
	}
	UnlockList(r->DosList);

	return ok;
}

void RefreshDosList(LISTENER *r)
{
	if (r == NULL)
	{
		return;
	}

	if (r->DosListLastRefreshTime == 0 ||
		(r->DosListLastRefreshTime + (UINT64)DOS_TABLE_REFRESH_INTERVAL) <= Tick64())
	{
		UINT i;
		LIST *o;
		r->DosListLastRefreshTime = Tick64();

		o = NewListFast(NULL);
		for (i = 0;i < LIST_NUM(r->DosList);i++)
		{
			DOS *d = LIST_DATA(r->DosList, i);
			if ((d->LastConnectedTick + d->CurrentExpireSpan) <= Tick64() ||
				(d->DeleteEntryTick <= Tick64()))
			{
				Add(o, d);
			}
		}

		for (i = 0;i < LIST_NUM(o);i++)
		{
			DOS *d = LIST_DATA(o, i);
			Delete(r->DosList, d);
			Free(d);
		}

		ReleaseList(o);
	}
}

DOS *SearchDosList(LISTENER *r, IP *ip)
{
	DOS *d, t;
	if (r == NULL || ip == NULL)
	{
		return NULL;
	}

	Copy(&t.IpAddress, ip, sizeof(IP));

	d = Search(r->DosList, &t);

	if (d != NULL)
	{
		if ((d->LastConnectedTick + d->CurrentExpireSpan) <= Tick64() ||
			(d->DeleteEntryTick <= Tick64()))
		{
			Delete(r->DosList, d);
			Free(d);
			return NULL;
		}
	}

	return d;
}

static int CompareDos(void *p1, void *p2)
{
	DOS *d1, *d2;
	if (p1 == NULL || p2 == NULL)
	{
		return 0;
	}
	d1 = *(DOS **)p1;
	d2 = *(DOS **)p2;
	if (d1 == NULL || d2 == NULL)
	{
		return 0;
	}

	return CmpIpAddr(&d1->IpAddress, &d2->IpAddress);
}

// Wake WaitListenerBind: the listener thread has tried to bind, r->Status holds the result
static void ListenerBindTried(LISTENER *r)
{
	if (r->BindEvent != NULL)
	{
		SetEvent((HANDLE)r->BindEvent);
	}
}

static void ListenerTCPMainLoop(LISTENER *r)
{
	SOCK *new_sock;
	SOCK *s;
	if (r == NULL)
	{
		return;
	}

	r->Status = LISTENER_STATUS_TRYING;

	while (true)
	{
		bool first_failed = true;
		r->Status = LISTENER_STATUS_TRYING;

		while (true)
		{
			UINT interval;
			if (r->Halt)
			{
				return;
			}

			s = NULL;

			if (r->Protocol == LISTENER_TCP)
			{
				if (r->ShadowIPv6 == false)
				{
					if (r->Cedar->Server == NULL)
					{
						s = ListenEx2(r->Port, r->LocalOnly, r->EnableConditionalAccept, NULL);
					}
					else
					{
						s = ListenEx2(r->Port, r->LocalOnly, r->EnableConditionalAccept, &r->Cedar->Server->ListenIP);
					}
				}
				else
				{
					if (r->Cedar->Server == NULL)
					{
						s = ListenEx6(r->Port, r->LocalOnly);
					}
					else
					{
						s = ListenEx63(r->Port, r->LocalOnly, false, &r->Cedar->Server->ListenIP);
					}
				}
			}

			if (s != NULL)
			{
				AddRef(s->ref);

				Lock(r->lock);
				{
					r->Sock = s;
				}
				Unlock(r->lock);

				if (r->ShadowIPv6 == false && r->Protocol == LISTENER_TCP)
				{
					SLog(r->Cedar, "LS_LISTENER_START_2", r->Port);
				}
				break;
			}

			if (first_failed)
			{
				first_failed = false;
				if (r->ShadowIPv6 == false && r->Protocol == LISTENER_TCP)
				{
					SLog(r->Cedar, "LS_LISTENER_START_3", r->Port, LISTEN_RETRY_TIME / 1000);
				}
			}

			// Status is LISTENER_STATUS_TRYING: the bind failed, the thread retries after the interval
			ListenerBindTried(r);

			interval = LISTEN_RETRY_TIME;

			if (r->ShadowIPv6)
			{
				if (IsIPv6Supported() == false)
				{
					interval = LISTEN_RETRY_TIME_NOIPV6;

				}
			}

			Wait(r->Event, interval);

			if (r->Halt)
			{
				return;
			}
		}

		r->Status = LISTENER_STATUS_LISTENING;
		ListenerBindTried(r);

		if (r->Halt)
		{
			goto STOP;
		}

		while (true)
		{
			new_sock = Accept(s);
			if (new_sock != NULL)
			{
				TCPAccepted(r, new_sock);
				ReleaseSock(new_sock);
			}
			else
			{
STOP:
				Disconnect(s);
				ReleaseSock(s);
				s = NULL;

				Lock(r->lock);
				{
					if (r->Sock != NULL)
					{
						s = r->Sock;
						r->Sock = NULL;
					}
				}
				Unlock(r->lock);

				if (s != NULL)
				{
					ReleaseSock(s);
				}

				s = NULL;

				break;
			}
		}

		if (r->Halt)
		{
			return;
		}
	}
}

static void ListenerThread(THREAD *thread, void *param)
{
	LISTENER *r;
	if (thread == NULL || param == NULL)
	{
		return;
	}

	r = (LISTENER *)param;
	AddRef(r->ref);
	r->Thread = thread;
	AddRef(thread->ref);
	NoticeThreadInit(thread);

	switch (r->Protocol)
	{
	case LISTENER_TCP:
		ListenerTCPMainLoop(r);
		break;
	}

	// Halted before any bind attempt: a waiter must not wait for a thread that has ended
	ListenerBindTried(r);

	ReleaseListener(r);
}

void StopListener(LISTENER *r)
{
	UINT port;
	SOCK *s = NULL;
	if (r == NULL)
	{
		return;
	}

	Lock(r->lock);
	if (r->Halt)
	{
		Unlock(r->lock);
		return;
	}

	r->Halt = true;

	if (r->Sock != NULL)
	{
		s = r->Sock;

		AddRef(s->ref);
	}

	Unlock(r->lock);

	port = r->Port;

	if (r->ShadowIPv6 == false && r->Protocol == LISTENER_TCP)
	{
		SLog(r->Cedar, "LS_LISTENER_STOP_1", port);
	}

	if (s != NULL)
	{
		Disconnect(s);
		ReleaseSock(s);
		s = NULL;
	}

	Set(r->Event);

	WaitThread(r->Thread, INFINITE);

	if (r->ShadowIPv6 == false)
	{
		if (r->ShadowListener != NULL)
		{
			StopListener(r->ShadowListener);

			ReleaseListener(r->ShadowListener);

			r->ShadowListener = NULL;
		}
	}

	if (r->ShadowIPv6 == false && r->Protocol == LISTENER_TCP)
	{
		SLog(r->Cedar, "LS_LISTENER_STOP_2", port);
	}
}

// Wait until the listener thread has tried to bind the port, at most timeout ms. True when the port is bound;
// false when the bind failed (the thread keeps retrying every LISTEN_RETRY_TIME) or did not finish in time.
bool WaitListenerBind(LISTENER *r, UINT timeout)
{
	if (r == NULL)
	{
		return false;
	}

	// The event is set after the thread wrote r->Status and stays set
	if (r->BindEvent != NULL)
	{
		WaitForSingleObject((HANDLE)r->BindEvent, timeout);
	}

	return (r->Status == LISTENER_STATUS_LISTENING);
}

static void CleanupListener(LISTENER *r)
{
	UINT i = 0;
	if (r == NULL)
	{
		return;
	}

	for (i = 0;i < LIST_NUM(r->DosList);i++)
	{
		DOS *d = LIST_DATA(r->DosList, i);
		Free(d);
	}
	ReleaseList(r->DosList);

	if (r->Sock != NULL)
	{
		ReleaseSock(r->Sock);
	}

	DeleteLock(r->lock);
	ReleaseThread(r->Thread);
	ReleaseEvent(r->Event);

	if (r->BindEvent != NULL)
	{
		CloseHandle((HANDLE)r->BindEvent);
	}

	ReleaseCedar(r->Cedar);

	Free(r);
}

void ReleaseListener(LISTENER *r)
{
	if (r == NULL)
	{
		return;
	}

	if (Release(r->ref) == 0)
	{
		CleanupListener(r);
	}
}

int CompareListener(void *p1, void *p2)
{
	LISTENER *r1, *r2;
	if (p1 == NULL || p2 == NULL)
	{
		return 0;
	}
	r1 = *(LISTENER **)p1;
	r2 = *(LISTENER **)p2;
	if (r1 == NULL || r2 == NULL)
	{
		return 0;
	}

	if (r1->Protocol > r2->Protocol)
	{
		return 1;
	}
	else if (r1->Protocol < r2->Protocol)
	{
		return -1;
	}
	else if (r1->Port > r2->Port)
	{
		return 1;
	}
	else if (r1->Port < r2->Port)
	{
		return -1;
	}
	else
	{
		return 0;
	}
}

LISTENER *NewListener(CEDAR *cedar, UINT proto, UINT port)
{
	return NewListenerEx5(cedar, proto, port, TCPAcceptedThread, NULL, false, false, false);
}
LISTENER *NewListenerEx5(CEDAR *cedar, UINT proto, UINT port, THREAD_PROC *proc, void *thread_param, bool local_only, bool shadow_ipv6, bool enable_ca)
{
	LISTENER *r;
	THREAD *t;
	if ((proto == LISTENER_TCP && port == 0) || cedar == NULL)
	{
		return NULL;
	}
	if (proto != LISTENER_TCP)
	{
		return NULL;
	}

	r = ZeroMalloc(sizeof(LISTENER));

	r->ThreadProc = proc;
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

	r->LocalOnly = local_only;
	r->ShadowIPv6 = shadow_ipv6;
	r->EnableConditionalAccept = enable_ca;

	if (r->ShadowIPv6 == false)
	{
		if (proto == LISTENER_TCP)
		{
			SLog(cedar, "LS_LISTENER_START_1", port);
		}
	}

	t = NewThread(ListenerThread, r);
	WaitThreadInit(t);
	ReleaseThread(t);

	if (r->ShadowIPv6 == false && proto == LISTENER_TCP)
	{
		if (r->Cedar->DisableIPv6Listener == false)
		{
			r->ShadowListener = NewListenerEx5(cedar, proto, port, proc, thread_param,
				local_only, true, false);
		}
	}

	if (r->ShadowIPv6 == false)
	{
		AddListener(cedar, r);
	}

	return r;
}

