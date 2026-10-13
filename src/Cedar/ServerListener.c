// ServerListener.c
// VPN Server listener list: add, delete, enable, disable and stop the TCP listeners

#include "Server.h"

#include "Admin.h"
#include "BridgeWin32.h"
#include "Connection.h"
#include "Link.h"
#include "Listener.h"
#include "Protocol.h"
#include "Sam.h"

#include "Mayaqua/Cfg.h"
#include "Mayaqua/DNS.h"
#include "Mayaqua/FileIO.h"
#include "Mayaqua/Internat.h"
#include "Mayaqua/Memory.h"
#include "Mayaqua/Microsoft.h"
#include "Mayaqua/Object.h"
#include "Mayaqua/OS.h"
#include "Mayaqua/Pack.h"
#include "Mayaqua/Str.h"
#include "Mayaqua/Table.h"
#include "Mayaqua/TcpIp.h"
#include "Mayaqua/Tick64.h"
#include "Mayaqua/Win32.h"
#include "ServerInternal.h"

void SiInitListenerList(SERVER *s)
{
	if (s == NULL)
	{
		return;
	}

	SiLockListenerList(s);
	{
		{
			// Default listeners: 443 and 5555
			SiAddListenerEx(s, SERVER_DEF_PORTS_1, true, false);
			SiAddListenerEx(s, SERVER_DEF_PORTS_4, true, false);
		}
	}
	SiUnlockListenerList(s);
}

bool SiDeleteListener(SERVER *s, UINT port)
{
	SERVER_LISTENER *e;
	if (s == NULL || port == 0)
	{
		return false;
	}

	e = SiGetListener(s, port);
	if (e == NULL)
	{
		return false;
	}

	SiDisableListener(s, port);

	if (e->Listener != NULL)
	{
		ReleaseListener(e->Listener);
	}

	Delete(s->ServerListenerList, e);
	Free(e);

	return true;
}

int CompareServerListener(void *p1, void *p2)
{
	SERVER_LISTENER *s1, *s2;
	if (p1 == NULL || p2 == NULL)
	{
		return 0;
	}
	s1 = *(SERVER_LISTENER **)p1;
	s2 = *(SERVER_LISTENER **)p2;
	if (s1 == NULL || s2 == NULL)
	{
		return 0;
	}

	if (s1->Port > s2->Port)
	{
		return 1;
	}
	else if (s1->Port < s2->Port)
	{
		return -1;
	}
	else
	{
		return 0;
	}
}

bool SiDisableListener(SERVER *s, UINT port)
{
	SERVER_LISTENER *e;
	if (s == NULL || port == 0)
	{
		return false;
	}

	e = SiGetListener(s, port);
	if (e == NULL)
	{
		return false;
	}

	if (e->Enabled == false || e->Listener == NULL)
	{
		return true;
	}

	StopListener(e->Listener);

	ReleaseListener(e->Listener);
	e->Listener = NULL;

	e->Enabled = false;

	return true;
}

bool SiEnableListener(SERVER *s, UINT port)
{
	SERVER_LISTENER *e;
	if (s == NULL || port == 0)
	{
		return false;
	}

	e = SiGetListener(s, port);
	if (e == NULL)
	{
		return false;
	}

	if (e->Enabled)
	{
		return true;
	}

	e->Listener = NewListener(s->Cedar, LISTENER_TCP, e->Port);
	if (e->Listener == NULL)
	{
		return false;
	}

	e->Listener->DisableDos = e->DisableDos;

	e->Enabled = true;

	return true;
}

SERVER_LISTENER *SiGetListener(SERVER *s, UINT port)
{
	UINT i;
	if (s == NULL || port == 0)
	{
		return NULL;
	}

	for (i = 0;i < LIST_NUM(s->ServerListenerList);i++)
	{
		SERVER_LISTENER *e = LIST_DATA(s->ServerListenerList, i);
		if (e->Port == port)
		{
			return e;
		}
	}

	return NULL;
}

bool SiAddListenerEx(SERVER *s, UINT port, bool enabled, bool disable_dos)
{
	SERVER_LISTENER *e;
	UINT i;
	if (s == NULL || port == 0)
	{
		return false;
	}

	for (i = 0;i < LIST_NUM(s->ServerListenerList);i++)
	{
		e = LIST_DATA(s->ServerListenerList, i);
		if (e->Port == port)
		{
			return false;
		}
	}

	e = ZeroMalloc(sizeof(SERVER_LISTENER));
	e->Enabled = enabled;
	e->Port = port;
	e->DisableDos = disable_dos;

	if (e->Enabled)
	{
		e->Listener = NewListener(s->Cedar, LISTENER_TCP, e->Port);
		if (e->Listener != NULL)
		{
			e->Listener->DisableDos = e->DisableDos;
		}
	}

	Insert(s->ServerListenerList, e);

	return true;
}

void SiLockListenerList(SERVER *s)
{
	if (s == NULL)
	{
		return;
	}

	LockList(s->ServerListenerList);
}

void SiUnlockListenerList(SERVER *s)
{
	if (s == NULL)
	{
		return;
	}

	UnlockList(s->ServerListenerList);
}

void SiStopAllListener(SERVER *s)
{
	if (s == NULL)
	{
		return;
	}

	SiLockListenerList(s);
	{
		UINT i;
		LIST *o = NewListFast(NULL);
		for (i = 0;i < LIST_NUM(s->ServerListenerList);i++)
		{
			SERVER_LISTENER *e = LIST_DATA(s->ServerListenerList, i);
			Add(o, e);
		}

		for (i = 0;i < LIST_NUM(o);i++)
		{
			SERVER_LISTENER *e = LIST_DATA(o, i);
			SiDeleteListener(s, e->Port);
		}

		ReleaseList(o);
	}
	SiUnlockListenerList(s);

	ReleaseList(s->ServerListenerList);
}
