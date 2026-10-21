// AdminServer.c
// Admin RPC area: server information and status, cipher, certificate, password and listeners

#include "Admin.h"

#include "BridgeWin32.h"
#include "BuildInfo.h"
#include "Connection.h"
#include "Link.h"
#include "Listener.h"
#include "RpcField.h"
#include "Protocol.h"
#include "Server.h"

#include "Mayaqua/Cfg.h"
#include "Mayaqua/Internat.h"
#include "Mayaqua/Memory.h"
#include "Mayaqua/Object.h"
#include "Mayaqua/Platform.h"
#include "Mayaqua/Str.h"
#include "Mayaqua/Tick64.h"
#include "AdminInternal.h"

static void CopyOsInfo(OS_INFO *dst, OS_INFO *info);

UINT StSetServerCipher(ADMIN *a, RPC_STR *t)
{
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;

	if (IsEmptyStr(t->String))
	{
		return ERR_INVALID_PARAMETER;
	}

	SERVER_ADMIN_ONLY;

	StrUpper(t->String);

	ALog(a, NULL, "LA_SET_SERVER_CIPHER", t->String);

	Lock(c->lock);
	{
		SetCedarCipherList(c, t->String);
	}
	Unlock(c->lock);

	IncrementServerConfigRevision(s);

	return ERR_NO_ERROR;
}

UINT StGetServerCipher(ADMIN *a, RPC_STR *t)
{
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;

	FreeRpcStr(t);
	Zero(t, sizeof(RPC_STR));

	Lock(c->lock);
	{
		t->String = CopyStr(c->CipherList);
	}
	Unlock(c->lock);

	return ERR_NO_ERROR;
}

UINT StGetServerCipherList(ADMIN *a, RPC_STR *t)
{
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;

	FreeRpcStr(t);
	Zero(t, sizeof(RPC_STR));

	Lock(c->lock);
	{
		UINT i;
		TOKEN_LIST *ciphers = GetCipherList();
		if (ciphers->NumTokens > 0)
		{
			UINT size = StrSize(ciphers->Token[0]);
			t->String = Malloc(size);
			StrCpy(t->String, size, ciphers->Token[0]);
			i = 1;

			for (; i < ciphers->NumTokens; i++)
			{
				// We use StrSize() because we need the extra space for ';'
				size += StrSize(ciphers->Token[i]);
				t->String = ReAlloc(t->String, size);
				StrCat(t->String, size, ";");
				StrCat(t->String, size, ciphers->Token[i]);
			}
		}

		FreeToken(ciphers);
	}
	Unlock(c->lock);

	return ERR_NO_ERROR;
}

UINT StGetServerCert(ADMIN *a, RPC_KEY_PAIR *t)
{
	bool admin;
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;

	admin = a->ServerAdmin;

	FreeRpcKeyPair(t);
	Zero(t, sizeof(RPC_KEY_PAIR));

	Lock(c->lock);
	{

		t->Cert = CloneX(c->ServerX);
		if (admin)
		{
			t->Key = CloneK(c->ServerK);
		}
	}
	Unlock(c->lock);

	return ERR_NO_ERROR;
}

UINT StSetServerCert(ADMIN *a, RPC_KEY_PAIR *t)
{
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;

	SERVER_ADMIN_ONLY;

	if (t->Cert == NULL || t->Key == NULL)
	{
		return ERR_PROTOCOL_ERROR;
	}

	if (CheckXandK(t->Cert, t->Key) == false)
	{
		return ERR_PROTOCOL_ERROR;
	}

	t->Flag1 = 1;
	if (t->Cert->root_cert == false)
	{
		if (DownloadAndSaveIntermediateCertificatesIfNecessary(t->Cert) == false)
		{
			t->Flag1 = 0;
		}
	}

	SetCedarCertAndChain(c, t->Cert, t->Key, t->Chain);

	ALog(a, NULL, "LA_SET_SERVER_CERT");

	IncrementServerConfigRevision(s);

	return ERR_NO_ERROR;
}

UINT StSetServerPassword(ADMIN *a, RPC_SET_PASSWORD *t)
{
	SERVER_ADMIN_ONLY;

	if (IsZero(t->HashedPassword, sizeof(t->HashedPassword)))
	{
		// For JSON-RPC
		HashAdminPassword(t->HashedPassword, t->PlainTextPassword);
	}

	Copy(a->Server->HashedPassword, t->HashedPassword, SHA1_SIZE);

	ALog(a, NULL, "LA_SET_SERVER_PASSWORD");

	IncrementServerConfigRevision(a->Server);

	return ERR_NO_ERROR;
}

// Wait for the bind attempt of the listener on a port, at most LISTENER_BIND_WAIT_TIME: ERR_NO_ERROR when the port
// is bound, ERR_LISTENER_BIND_FAILED when it is not (the listener stays registered and keeps retrying)
static UINT StWaitListenerBind(SERVER *s, UINT port)
{
	SERVER_LISTENER *e;
	LISTENER *r = NULL;
	bool bound;

	SiLockListenerList(s);
	{
		e = SiGetListener(s, port);
		if (e != NULL && e->Listener != NULL)
		{
			r = e->Listener;
			AddRef(r->ref);
		}
	}
	SiUnlockListenerList(s);

	// Outside the list lock: other admin calls take it, the listener thread does not
	bound = WaitListenerBind(r, LISTENER_BIND_WAIT_TIME);

	ReleaseListener(r);

	return (bound ? ERR_NO_ERROR : ERR_LISTENER_BIND_FAILED);
}

UINT StEnableListener(ADMIN *a, RPC_LISTENER *t)
{
	UINT ret = ERR_NO_ERROR;

	SERVER_ADMIN_ONLY;


	SiLockListenerList(a->Server);
	{
		if (t->Enable)
		{
			if (SiEnableListener(a->Server, t->Port) == false)
			{
				ret = ERR_LISTENER_NOT_FOUND;
			}
			else
			{
				ALog(a, NULL, "LA_ENABLE_LISTENER", t->Port);
			}
		}
		else
		{
			if (SiDisableListener(a->Server, t->Port) == false)
			{
				ret = ERR_LISTENER_NOT_FOUND;
			}
			else
			{
				ALog(a, NULL, "LA_DISABLE_LISTENER", t->Port);
			}
		}
	}
	SiUnlockListenerList(a->Server);

	IncrementServerConfigRevision(a->Server);

	// Disabling is synchronous (StopListener waits for the listener thread); enabling reports the bind
	if (ret == ERR_NO_ERROR && t->Enable)
	{
		ret = StWaitListenerBind(a->Server, t->Port);
	}

	return ret;
}

UINT StDeleteListener(ADMIN *a, RPC_LISTENER *t)
{
	UINT ret = ERR_NO_ERROR;

	SERVER_ADMIN_ONLY;


	SiLockListenerList(a->Server);
	{
		if (SiDeleteListener(a->Server, t->Port) == false)
		{
			ret = ERR_LISTENER_NOT_FOUND;
		}
		else
		{
			ALog(a, NULL, "LA_DELETE_LISTENER", t->Port);

			IncrementServerConfigRevision(a->Server);
		}
	}
	SiUnlockListenerList(a->Server);

	return ret;
}

UINT StEnumListener(ADMIN *a, RPC_LISTENER_LIST *t)
{
	SERVER_LISTENER_INFO *o;

	SERVER_ADMIN_ONLY;

	FreeRpcListenerList(t);
	Zero(t, sizeof(RPC_LISTENER_LIST));

	o = SiEnumListeners(a->Server, &t->NumPort);
	t->Ports = ZeroMalloc(sizeof(UINT) * t->NumPort);
	t->Enables = ZeroMalloc(sizeof(bool) * t->NumPort);
	t->Errors = ZeroMalloc(sizeof(bool) * t->NumPort);

	for (UINT i = 0;i < t->NumPort;i++)
	{
		t->Ports[i] = o[i].Port;
		t->Enables[i] = o[i].Enabled;
		t->Errors[i] = o[i].Trying;
	}

	Free(o);

	return ERR_NO_ERROR;
}

UINT StCreateListener(ADMIN *a, RPC_LISTENER *t)
{
	UINT ret = ERR_NO_ERROR;

	if (t->Port == 0 || t->Port > 65535)
	{
		return ERR_INVALID_PARAMETER;
	}

	SERVER_ADMIN_ONLY;

	SiLockListenerList(a->Server);
	{
		if (SiAddListenerEx(a->Server, t->Port, t->Enable, false) == false)
		{
			ret = ERR_LISTENER_ALREADY_EXISTS;
		}
		else
		{
			ALog(a, NULL, "LA_CREATE_LISTENER", t->Port);

			IncrementServerConfigRevision(a->Server);
		}
	}
	SiUnlockListenerList(a->Server);

	// A disabled listener has no bind to wait for
	if (ret == ERR_NO_ERROR && t->Enable)
	{
		ret = StWaitListenerBind(a->Server, t->Port);
	}

	return ret;
}

UINT StGetServerStatus(ADMIN *a, RPC_SERVER_STATUS *t)
{
	CEDAR *c;

	c = a->Server->Cedar;

	Zero(t, sizeof(RPC_SERVER_STATUS));

	Lock(c->TrafficLock);
	{
		Copy(&t->Traffic, c->Traffic, sizeof(TRAFFIC));
	}
	Unlock(c->TrafficLock);

	// Hide the memory figures of the host from hub administrators
	if (a->ServerAdmin)
	{
		Win32GetMemInfo(&t->MemInfo);
	}

	t->NumTcpConnections = t->NumTcpConnectionsLocal = 0;
	t->NumSessionsTotal = t->NumSessionsLocal = 0;

	t->NumTcpConnectionsLocal = Count(c->CurrentTcpConnections);

	t->NumMacTables = t->NumIpTables = t->NumUsers = t->NumGroups = 0;

	LockList(c->HubList);
	{
		t->NumHubTotal = LIST_NUM(c->HubList);

		t->NumHubStandalone = 0;

		for (UINT i = 0;i < LIST_NUM(c->HubList);i++)
		{
			HUB *h = LIST_DATA(c->HubList, i);
			HUB_STATS st;

			HubGetStats(h, &st);

			t->NumHubStandalone++;

			t->NumMacTables += st.NumMacTables;
			t->NumIpTables += st.NumIpTables;
			t->NumUsers += st.NumUsers;
			t->NumGroups += st.NumGroups;
		}
	}
	UnlockList(c->HubList);

	t->NumSessionsLocal = Count(c->CurrentSessions);
	t->NumSessionsTotal = t->NumSessionsLocal;
	t->NumTcpConnections = t->NumTcpConnectionsLocal;

	t->AssignedBridgeLicenses = Count(c->AssignedBridgeLicense);
	t->AssignedClientLicenses = Count(c->AssignedClientLicense);

	t->AssignedBridgeLicensesTotal = t->AssignedBridgeLicenses;
	t->AssignedClientLicensesTotal = t->AssignedClientLicenses;

	t->CurrentTick = Tick64();
	t->CurrentTime = SystemTime64();

	t->StartTime = a->Server->StartTime;

	return ERR_NO_ERROR;
}

UINT StGetServerInfo(ADMIN *a, RPC_SERVER_INFO *t)
{
	CEDAR *c;
	OS_INFO *info;
	SYSTEMTIME st;
	if (a == NULL || t == NULL)
	{
		return ERR_INTERNAL_ERROR;
	}

	FreeRpcServerInfo(t);
	Zero(t, sizeof(RPC_SERVER_INFO));

	c = a->Server->Cedar;

	GetServerProductName(a->Server, t->ServerProductName, sizeof(t->ServerProductName));

	StrCpy(t->ServerVersionString, sizeof(t->ServerVersionString), c->VerString);
	StrCpy(t->ServerBuildInfoString, sizeof(t->ServerBuildInfoString), c->BuildInfo);
	t->ServerVerInt = c->Version;
	t->ServerBuildInt = c->Build;

	Zero(&st, sizeof(st));
	st.wYear = BUILD_DATE_Y;
	st.wMonth = BUILD_DATE_M;
	st.wDay = BUILD_DATE_D;
	st.wHour = BUILD_DATE_HO;
	st.wMinute = BUILD_DATE_MI;
	st.wSecond = BUILD_DATE_SE;

	t->ServerBuildDate = SystemToUINT64(&st);

	if (a->ServerAdmin)
	{
		GetMachineName(t->ServerHostName, sizeof(t->ServerHostName));

		info = GetOsInfo();
		if (info != NULL)
		{
			CopyOsInfo(&t->OsInfo, info);
		}
	}
	else
	{
		// Hide the host name and the OS from hub administrators; the empty
		// strings keep the reply's Pack layout the same
		OS_INFO hidden;

		Zero(&hidden, sizeof(hidden));
		hidden.OsSystemName = hidden.OsProductName = hidden.OsVendorName = "";
		hidden.OsVersion = hidden.KernelName = hidden.KernelVersion = "";

		CopyOsInfo(&t->OsInfo, &hidden);
	}

	return ERR_NO_ERROR;
}

static void CopyOsInfo(OS_INFO *dst, OS_INFO *info)
{
	if (info == NULL || dst == NULL)
	{
		return;
	}

	dst->OsType = info->OsType;
	dst->OsServicePack = info->OsServicePack;
	dst->OsSystemName = CopyStr(info->OsSystemName);
	dst->OsProductName = CopyStr(info->OsProductName);
	dst->OsVendorName = CopyStr(info->OsVendorName);
	dst->OsVersion = CopyStr(info->OsVersion);
	dst->KernelName = CopyStr(info->KernelName);
	dst->KernelVersion = CopyStr(info->KernelVersion);
}
