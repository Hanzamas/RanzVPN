// ServerListener.c
// VPN Server listener list: add, delete, enable, disable, find, lock and enumerate the TCP listeners

#include "Server.h"

#include "Admin.h"
#include "BridgeWin32.h"
#include "Connection.h"
#include "Link.h"
#include "Listener.h"
#include "Protocol.h"
#include "RpcField.h"

#include "Mayaqua/Memory.h"
#include "Mayaqua/TcpIp.h"

#include <stdlib.h>
#include "ServerInternal.h"

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

	e->Listener = NewListener(s->Cedar, e->Port);
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
	if (s == NULL || port == 0)
	{
		return NULL;
	}

	for (UINT i = 0;i < LIST_NUM(s->ServerListenerList);i++)
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
	if (s == NULL || port == 0)
	{
		return false;
	}

	for (UINT i = 0;i < LIST_NUM(s->ServerListenerList);i++)
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
		e->Listener = NewListener(s->Cedar, e->Port);
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

// Port, enabled flag and bind state of every listener, in list order, all taken under the listener list lock.
// The caller frees the array with Free
SERVER_LISTENER_INFO *SiEnumListeners(SERVER *s, UINT *num)
{
	SERVER_LISTENER_INFO *ret;
	if (s == NULL || num == NULL)
	{
		return NULL;
	}

	SiLockListenerList(s);
	{
		*num = LIST_NUM(s->ServerListenerList);
		ret = ZeroMalloc(sizeof(SERVER_LISTENER_INFO) * (*num));

		for (UINT i = 0;i < *num;i++)
		{
			SERVER_LISTENER *o = LIST_DATA(s->ServerListenerList, i);

			ret[i].Port = o->Port;
			ret[i].Enabled = o->Enabled;
			if (o->Enabled && o->Listener->Status == LISTENER_STATUS_TRYING)
			{
				ret[i].Trying = true;
			}
		}
	}
	SiUnlockListenerList(s);

	return ret;
}
