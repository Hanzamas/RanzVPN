// AdminServer.c
// Admin RPC area: server information and status, cipher, certificate, password and listeners

#include "Admin.h"

#include "Account.h"
#include "BridgeWin32.h"
#include "Connection.h"
#include "Link.h"
#include "Listener.h"
#include "MsChapV2.h"
#include "Remote.h"
#include "Protocol.h"
#include "Sam.h"
#include "Server.h"
#include "Session.h"
#include "Wpc.h"

#include "Mayaqua/Cfg.h"
#include "Mayaqua/FileIO.h"
#include "Mayaqua/Internat.h"
#include "Mayaqua/HTTP.h"
#include "Mayaqua/Memory.h"
#include "Mayaqua/Microsoft.h"
#include "Mayaqua/Object.h"
#include "Mayaqua/Pack.h"
#include "Mayaqua/Str.h"
#include "Mayaqua/Table.h"
#include "Mayaqua/Tick64.h"
#include "AdminInternal.h"

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

UINT StEnableListener(ADMIN *a, RPC_LISTENER *t)
{
	UINT ret = ERR_NO_ERROR;

	SERVER_ADMIN_ONLY;


	LockList(a->Server->ServerListenerList);
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
	UnlockList(a->Server->ServerListenerList);

	IncrementServerConfigRevision(a->Server);

	SleepThread(250);

	return ret;
}

UINT StDeleteListener(ADMIN *a, RPC_LISTENER *t)
{
	UINT ret = ERR_NO_ERROR;

	SERVER_ADMIN_ONLY;


	LockList(a->Server->ServerListenerList);
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
	UnlockList(a->Server->ServerListenerList);

	return ret;
}

UINT StEnumListener(ADMIN *a, RPC_LISTENER_LIST *t)
{
	CEDAR *c = a->Server->Cedar;
	UINT i;

	FreeRpcListenerList(t);
	Zero(t, sizeof(RPC_LISTENER_LIST));

	LockList(a->Server->ServerListenerList);
	{
		t->NumPort = LIST_NUM(a->Server->ServerListenerList);
		t->Ports = ZeroMalloc(sizeof(UINT) * t->NumPort);
		t->Enables = ZeroMalloc(sizeof(bool) * t->NumPort);
		t->Errors = ZeroMalloc(sizeof(bool) * t->NumPort);

		for (i = 0;i < t->NumPort;i++)
		{
			SERVER_LISTENER *o = LIST_DATA(a->Server->ServerListenerList, i);

			t->Ports[i] = o->Port;
			t->Enables[i] = o->Enabled;
			if (t->Enables[i])
			{
				if (o->Listener->Status == LISTENER_STATUS_TRYING)
				{
					t->Errors[i] = true;
				}
			}
		}
	}
	UnlockList(a->Server->ServerListenerList);

	return ERR_NO_ERROR;
}

UINT StCreateListener(ADMIN *a, RPC_LISTENER *t)
{
	UINT ret = ERR_NO_ERROR;
	CEDAR *c = a->Server->Cedar;

	if (t->Port == 0 || t->Port > 65535)
	{
		return ERR_INVALID_PARAMETER;
	}

	SERVER_ADMIN_ONLY;

	LockList(a->Server->ServerListenerList);
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
	UnlockList(a->Server->ServerListenerList);

	SleepThread(250);

	return ret;
}

UINT StGetServerStatus(ADMIN *a, RPC_SERVER_STATUS *t)
{
	CEDAR *c;
	UINT i;

	c = a->Server->Cedar;

	Zero(t, sizeof(RPC_SERVER_STATUS));

	Lock(c->TrafficLock);
	{
		Copy(&t->Traffic, c->Traffic, sizeof(TRAFFIC));
	}
	Unlock(c->TrafficLock);

	GetMemInfo(&t->MemInfo);

	t->NumTcpConnections = t->NumTcpConnectionsLocal = 0;
	t->NumSessionsTotal = t->NumSessionsLocal = 0;

	t->NumTcpConnectionsLocal = Count(c->CurrentTcpConnections);

	t->NumMacTables = t->NumIpTables = t->NumUsers = t->NumGroups = 0;

	LockList(c->HubList);
	{
		t->NumHubTotal = LIST_NUM(c->HubList);

		t->NumHubStandalone = 0;

		for (i = 0;i < LIST_NUM(c->HubList);i++)
		{
			HUB *h = LIST_DATA(c->HubList, i);
			Lock(h->lock);
			{
				t->NumHubStandalone++;
			}

			t->NumMacTables += HASH_LIST_NUM(h->MacHashTable);
			t->NumIpTables += LIST_NUM(h->IpTable);

			if (h->HubDb != NULL)
			{
				t->NumUsers += LIST_NUM(h->HubDb->UserList);
				t->NumGroups += LIST_NUM(h->HubDb->GroupList);
			}

			Unlock(h->lock);
		}
	}
	UnlockList(c->HubList);

	t->NumSessionsLocal = Count(c->CurrentSessions);
	t->NumSessionsTotal = t->NumSessionsLocal;
	t->NumTcpConnections = t->NumTcpConnectionsLocal;

	t->AssignedBridgeLicenses = Count(c->AssignedBridgeLicense);
	t->AssignedClientLicenses = Count(c->AssignedClientLicense);

	t->AssignedBridgeLicensesTotal = a->Server->CurrentAssignedBridgeLicense;
	t->AssignedClientLicensesTotal = a->Server->CurrentAssignedClientLicense;

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
	GetMachineName(t->ServerHostName, sizeof(t->ServerHostName));

	Zero(&st, sizeof(st));
	st.wYear = BUILD_DATE_Y;
	st.wMonth = BUILD_DATE_M;
	st.wDay = BUILD_DATE_D;
	st.wHour = BUILD_DATE_HO;
	st.wMinute = BUILD_DATE_MI;
	st.wSecond = BUILD_DATE_SE;

	t->ServerBuildDate = SystemToUINT64(&st);

	info = GetOsInfo();
	if (info != NULL)
	{
		CopyOsInfo(&t->OsInfo, info);
	}

	return ERR_NO_ERROR;
}

void CopyOsInfo(OS_INFO *dst, OS_INFO *info)
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
