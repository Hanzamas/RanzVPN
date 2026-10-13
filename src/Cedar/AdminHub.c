// SoftEther VPN Source Code - Developer Edition Master Branch
// Cedar Communication Module


// AdminHub.c
// Admin RPC area: Virtual Hubs (create, set, enumerate, delete, status, log settings) and server connections

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

// Get logging configuration of the hub
UINT StGetHubLog(ADMIN *a, RPC_HUB_LOG *t)
{
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;
	HUB *h;

	CHECK_RIGHT;

	LockHubList(c);
	{
		h = GetHub(c, t->HubName);
	}
	UnlockHubList(c);

	if (h == NULL)
	{
		return ERR_HUB_NOT_FOUND;
	}

	GetHubLogSetting(h, &t->LogSetting);

	ReleaseHub(h);

	return ERR_NO_ERROR;
}

// Set logging configuration into the hub
UINT StSetHubLog(ADMIN *a, RPC_HUB_LOG *t)
{
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;
	HUB *h;

	CHECK_RIGHT;


	LockHubList(c);
	{
		h = GetHub(c, t->HubName);
	}
	UnlockHubList(c);

	if (h == NULL)
	{
		return ERR_HUB_NOT_FOUND;
	}

	if (a->ServerAdmin == false && GetHubAdminOption(h, "no_change_log_config") != 0)
	{
		ReleaseHub(h);
		return ERR_NOT_ENOUGH_RIGHT;
	}

	ALog(a, h, "LA_SET_HUB_LOG");

	SetHubLogSettingEx(h, &t->LogSetting,
		(a->ServerAdmin == false && GetHubAdminOption(h, "no_change_log_switch_type") != 0));

	ReleaseHub(h);

	IncrementServerConfigRevision(s);

	return ERR_NO_ERROR;
}

// Get hub status
UINT StGetHubStatus(ADMIN *a, RPC_HUB_STATUS *t)
{
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;
	HUB *h;

	CHECK_RIGHT;

	LockHubList(c);
	{
		h = GetHub(c, t->HubName);
	}
	UnlockHubList(c);

	if (h == NULL)
	{
		return ERR_HUB_NOT_FOUND;
	}

	Zero(t, sizeof(RPC_HUB_STATUS));

	Lock(h->lock);
	{
		StrCpy(t->HubName, sizeof(t->HubName), h->Name);
		t->Online = h->Offline ? false : true;
		t->NumSessions = LIST_NUM(h->SessionList);
		t->NumSessionsClient = Count(h->NumSessionsClient);
		t->NumSessionsBridge = Count(h->NumSessionsBridge);
		t->NumAccessLists = LIST_NUM(h->AccessList);

		if (h->HubDb != NULL)
		{
			t->NumUsers = LIST_NUM(h->HubDb->UserList);
			t->NumGroups = LIST_NUM(h->HubDb->GroupList);
		}

		t->NumMacTables = HASH_LIST_NUM(h->MacHashTable);
		t->NumIpTables = LIST_NUM(h->IpTable);

		Lock(h->TrafficLock);
		{
			Copy(&t->Traffic, h->Traffic, sizeof(TRAFFIC));
		}
		Unlock(h->TrafficLock);

		t->NumLogin = h->NumLogin;
		t->LastCommTime = h->LastCommTime;
		t->LastLoginTime = h->LastLoginTime;
		t->CreatedTime = h->CreatedTime;
	}
	Unlock(h->lock);

	ReleaseHub(h);

	return ERR_NO_ERROR;
}

// Make a hub on-line or off-line
UINT StSetHubOnline(ADMIN *a, RPC_SET_HUB_ONLINE *t)
{
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;
	HUB *h;


	NO_SUPPORT_FOR_BRIDGE;

	CHECK_RIGHT;

	LockHubList(c);
	{
		h = GetHub(c, t->HubName);
	}
	UnlockHubList(c);

	if (h == NULL)
	{
		return ERR_HUB_NOT_FOUND;
	}

	if (a->ServerAdmin == false && t->Online && GetHubAdminOption(h, "no_online") != 0)
	{
		ReleaseHub(h);
		return ERR_NOT_ENOUGH_RIGHT;
	}

	if (a->ServerAdmin == false && t->Online == false && GetHubAdminOption(h, "no_offline") != 0)
	{
		ReleaseHub(h);
		return ERR_NOT_ENOUGH_RIGHT;
	}

	if (t->Online)
	{
		ALog(a, h, "LA_SET_HUB_ONLINE");
		SetHubOnline(h);
	}
	else
	{
		ALog(a, h, "LA_SET_HUB_OFFLINE");
		SetHubOffline(h);
	}

	IncrementServerConfigRevision(s);

	ReleaseHub(h);

	return ERR_NO_ERROR;
}

// Get connection information
UINT StGetConnectionInfo(ADMIN *a, RPC_CONNECTION_INFO *t)
{
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;
	CONNECTION *connection;
	char name[MAX_CONNECTION_NAME_LEN + 1];

	if (IsEmptyStr(t->Name))
	{
		return ERR_INVALID_PARAMETER;
	}

	SERVER_ADMIN_ONLY;

	LockList(c->ConnectionList);
	{
		CONNECTION tt;
		Zero(&tt, sizeof(tt));
		tt.Name = t->Name;
		StrCpy(name, sizeof(name), t->Name);

		connection = Search(c->ConnectionList, &tt);

		if (connection != NULL)
		{
			AddRef(connection->ref);
		}
	}
	UnlockList(c->ConnectionList);

	if (connection == NULL)
	{
		return ERR_OBJECT_NOT_FOUND;
	}

	Zero(t, sizeof(RPC_CONNECTION_INFO));
	StrCpy(t->Name, sizeof(t->Name), name);

	Lock(connection->lock);
	{
		SOCK *s = connection->FirstSock;

		if (s != NULL)
		{
			t->Ip = IPToUINT(&s->RemoteIP);
			t->Port = s->RemotePort;
			StrCpy(t->Hostname, sizeof(t->Hostname), s->RemoteHostname);
		}

		StrCpy(t->Name, sizeof(t->Name), connection->Name);
		t->ConnectedTime = TickToTime(connection->ConnectedTick);
		t->Type = connection->Type;

		StrCpy(t->ServerStr, sizeof(t->ServerStr), connection->ServerStr);
		StrCpy(t->ClientStr, sizeof(t->ClientStr), connection->ClientStr);
		t->ServerVer = connection->ServerVer;
		t->ServerBuild = connection->ServerBuild;
		t->ClientVer = connection->ClientVer;
		t->ClientBuild = connection->ClientBuild;
	}
	Unlock(connection->lock);

	ReleaseConnection(connection);

	return ERR_NO_ERROR;
}

// Disconnect a connection
UINT StDisconnectConnection(ADMIN *a, RPC_DISCONNECT_CONNECTION *t)
{
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;
	CONNECTION *connection;

	if (IsEmptyStr(t->Name))
	{
		return ERR_INVALID_PARAMETER;
	}

	SERVER_ADMIN_ONLY;

	LockList(c->ConnectionList);
	{
		CONNECTION tt;
		Zero(&tt, sizeof(tt));
		tt.Name = t->Name;

		connection = Search(c->ConnectionList, &tt);
		if (connection != NULL)
		{
			AddRef(connection->ref);
		}
	}
	UnlockList(c->ConnectionList);

	if (connection == NULL)
	{
		return ERR_OBJECT_NOT_FOUND;
	}

	StopConnection(connection, true);

	ReleaseConnection(connection);

	ALog(a, NULL, "LA_DISCONNECT_CONN", t->Name);

	return ERR_NO_ERROR;
}

// Enumerate connections
UINT StEnumConnection(ADMIN *a, RPC_ENUM_CONNECTION *t)
{
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;

	SERVER_ADMIN_ONLY;

	FreeRpcEnumConnection(t);
	Zero(t, sizeof(RPC_ENUM_CONNECTION));

	LockList(c->ConnectionList);
	{
		UINT i;
		t->NumConnection = LIST_NUM(c->ConnectionList);
		t->Connections = ZeroMalloc(sizeof(RPC_ENUM_CONNECTION_ITEM) * t->NumConnection);
		
		for (i = 0;i < t->NumConnection;i++)
		{
			RPC_ENUM_CONNECTION_ITEM *e = &t->Connections[i];
			CONNECTION *connection = LIST_DATA(c->ConnectionList, i);

			Lock(connection->lock);
			{
				SOCK *s = connection->FirstSock;

				if (s != NULL)
				{
					e->Ip = IPToUINT(&s->RemoteIP);
					e->Port = s->RemotePort;
					StrCpy(e->Hostname, sizeof(e->Hostname), s->RemoteHostname);
				}

				StrCpy(e->Name, sizeof(e->Name), connection->Name);
				e->ConnectedTime = TickToTime(connection->ConnectedTick);
				e->Type = connection->Type;
			}
			Unlock(connection->lock);
		}
	}
	UnlockList(c->ConnectionList);

	return ERR_NO_ERROR;
}

// Delete a hub
UINT StDeleteHub(ADMIN *a, RPC_DELETE_HUB *t)
{
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;
	HUB *h = NULL;


	if (IsEmptyStr(t->HubName) || IsSafeStr(t->HubName) == false)
	{
		return ERR_INVALID_PARAMETER;
	}

	NO_SUPPORT_FOR_BRIDGE;

	SERVER_ADMIN_ONLY;

	LockHubList(c);
	{
		h = GetHub(c, t->HubName);
	}
	UnlockHubList(c);

	if (h == NULL)
	{
		return ERR_HUB_NOT_FOUND;
	}

	StopHub(h);

	IncrementServerConfigRevision(s);

	DelHub(c, h);
	ReleaseHub(h);

	ALog(a, NULL, "LA_DELETE_HUB", t->HubName);

	return ERR_NO_ERROR;
}

// Enumerate hubs
UINT StEnumHub(ADMIN *a, RPC_ENUM_HUB *t)
{
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;
	HUB *h = NULL;

	FreeRpcEnumHub(t);

	Zero(t, sizeof(RPC_ENUM_HUB));

	LockHubList(c);
	{
		UINT i, num, j;

		num = 0;

		for (i = 0;i < LIST_NUM(c->HubList);i++)
		{
			HUB *h = LIST_DATA(c->HubList, i);

			Lock(h->lock);

			if (a->ServerAdmin == false &&
				h->Option != NULL &&
				StrCmpi(h->Name, a->HubName) != 0)
			{
				// This hub is not listed
			}
			else
			{
				// This hub is listed
				num++;
			}
		}

		t->NumHub = num;

		t->Hubs = ZeroMalloc(sizeof(RPC_ENUM_HUB_ITEM) * num);

		i = 0;
		for (j = 0;j < LIST_NUM(c->HubList);j++)
		{
			HUB *h = LIST_DATA(c->HubList, j);

			if (a->ServerAdmin == false &&
				h->Option != NULL &&
				StrCmpi(h->Name, a->HubName) != 0)
			{
				// This hub is not listed
			}
			else
			{
				// This hub is listed
				RPC_ENUM_HUB_ITEM *e = &t->Hubs[i++];

				StrCpy(e->HubName, sizeof(e->HubName), h->Name);
				e->Online = h->Offline ? false : true;

				e->NumSessions = LIST_NUM(h->SessionList);

				LockHashList(h->MacHashTable);
				{
					e->NumMacTables = HASH_LIST_NUM(h->MacHashTable);
				}
				UnlockHashList(h->MacHashTable);

				LockList(h->IpTable);
				{
					e->NumIpTables = LIST_NUM(h->IpTable);
				}
				UnlockList(h->IpTable);

				if (h->HubDb != NULL)
				{
					LockList(h->HubDb->UserList);
					{
						e->NumUsers = LIST_NUM(h->HubDb->UserList);
					}
					UnlockList(h->HubDb->UserList);

					LockList(h->HubDb->GroupList);
					{
						e->NumGroups = LIST_NUM(h->HubDb->GroupList);
					}
					UnlockList(h->HubDb->GroupList);
				}

				e->LastCommTime = h->LastCommTime;
				e->LastLoginTime = h->LastLoginTime;
				e->NumLogin = h->NumLogin;
				e->CreatedTime = h->CreatedTime;

				Lock(h->TrafficLock);
				{
					Copy(&e->Traffic, h->Traffic, sizeof(TRAFFIC));
				}
				Unlock(h->TrafficLock);

				e->IsTrafficFilled = true;
			}

			Unlock(h->lock);
		}
	}
	UnlockHubList(c);

	return ERR_NO_ERROR;
}

// Get hub configuration
UINT StGetHub(ADMIN *a, RPC_CREATE_HUB *t)
{
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;
	UINT ret = ERR_NO_ERROR;
	HUB *h;

	if (IsEmptyStr(t->HubName) || IsSafeStr(t->HubName) == false)
	{
		return ERR_INVALID_PARAMETER;
	}

	NO_SUPPORT_FOR_BRIDGE;
	CHECK_RIGHT;

	LockHubList(c);
	{
		h = GetHub(c, t->HubName);
	}
	UnlockHubList(c);

	Zero(t, sizeof(RPC_CREATE_HUB));

	if (h == NULL)
	{
		return ERR_HUB_NOT_FOUND;
	}

	Lock(h->lock);
	{
		StrCpy(t->HubName, sizeof(t->HubName), h->Name);
		t->Online = h->Offline ? false : true;
		t->HubOption.MaxSession = h->Option->MaxSession;
		t->HubOption.NoEnum = h->Option->NoEnum;
	}
	Unlock(h->lock);

	ReleaseHub(h);

	return ret;
}

// Set hub configuration
UINT StSetHub(ADMIN *a, RPC_CREATE_HUB *t)
{
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;
	HUB *h;
	UINT ret = ERR_NO_ERROR;

	if (IsEmptyStr(t->HubName) || IsSafeStr(t->HubName) == false)
	{
		return ERR_INVALID_PARAMETER;
	}

	CHECK_RIGHT;
	NO_SUPPORT_FOR_BRIDGE;

	LockHubList(c);
	{
		h = GetHub(c, t->HubName);
	}
	UnlockHubList(c);

	if (h == NULL)
	{
		return ERR_HUB_NOT_FOUND;
	}

	// For JSON-RPC
	if (StrLen(t->AdminPasswordPlainText) != 0)
	{
		Sha0(t->HashedPassword, t->AdminPasswordPlainText, StrLen(t->AdminPasswordPlainText));
		HashPassword(t->SecurePassword, ADMINISTRATOR_USERNAME, t->AdminPasswordPlainText);
	}

	if (IsZero(t->HashedPassword, sizeof(t->HashedPassword)) == false &&
		IsZero(t->SecurePassword, sizeof(t->SecurePassword)) == false)
	{
		if (a->ServerAdmin == false && GetHubAdminOption(h, "no_change_admin_password") != 0)
		{
			ReleaseHub(h);
			return ERR_NOT_ENOUGH_RIGHT;
		}
	}

	// Is the password to be set blank
	{
		UCHAR hash1[SHA1_SIZE], hash2[SHA1_SIZE];
		HashPassword(hash1, ADMINISTRATOR_USERNAME, "");
		Sha0(hash2, "", 0);

		if (Cmp(t->HashedPassword, hash2, SHA1_SIZE) == 0 || Cmp(t->SecurePassword, hash1, SHA1_SIZE) == 0)
		{
			if (a->ServerAdmin == false && IsLocalHostIP(&a->Rpc->Sock->RemoteIP) == false)
			{
				// Refuse to set a blank password to hub admin from remote host
				ReleaseHub(h);
				return ERR_INVALID_PARAMETER;
			}
		}
	}

	Lock(h->lock);
	{
		h->Option->MaxSession = t->HubOption.MaxSession;
		h->Option->NoEnum = t->HubOption.NoEnum;

		if (IsZero(t->HashedPassword, sizeof(t->HashedPassword)) == false &&
			IsZero(t->SecurePassword, sizeof(t->SecurePassword)) == false)
		{
			Copy(h->HashedPassword, t->HashedPassword, SHA1_SIZE);
			Copy(h->SecurePassword, t->SecurePassword, SHA1_SIZE);
		}
	}
	Unlock(h->lock);

	if (t->Online)
	{
		if (a->ServerAdmin || GetHubAdminOption(h, "no_online") == 0)
		{
			SetHubOnline(h);
		}
	}
	else
	{
		if (a->ServerAdmin || GetHubAdminOption(h, "no_offline") == 0)
		{
			SetHubOffline(h);
		}
	}

	IncrementServerConfigRevision(s);

	ALog(a, h, "LA_SET_HUB");

	ReleaseHub(h);

	return ret;
}

// Create a hub
UINT StCreateHub(ADMIN *a, RPC_CREATE_HUB *t)
{
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;
	HUB *h;
	HUB_OPTION o;
	UINT current_hub_num;
	bool b;

	if (IsEmptyStr(t->HubName) || IsSafeStr(t->HubName) == false)
	{
		return ERR_INVALID_PARAMETER;
	}

	NO_SUPPORT_FOR_BRIDGE;

	SERVER_ADMIN_ONLY;

	Trim(t->HubName);
	if (StrLen(t->HubName) == 0)
	{
		return ERR_INVALID_PARAMETER;
	}
	if (StartWith(t->HubName, ".") || EndWith(t->HubName, "."))
	{
		return ERR_INVALID_PARAMETER;
	}

	// Create a hub object
	Zero(&o, sizeof(o));
	o.MaxSession = t->HubOption.MaxSession;
	o.NoEnum = t->HubOption.NoEnum;

	// Default setting for hub admin options
	SiSetDefaultHubOption(&o);

	LockList(c->HubList);
	{
		current_hub_num = LIST_NUM(c->HubList);
	}
	UnlockList(c->HubList);

	if (current_hub_num > GetServerCapsInt(a->Server, "i_max_hubs"))
	{
		return ERR_TOO_MANY_HUBS;
	}

	LockList(c->HubList);
	{
		b = IsHub(c, t->HubName);
	}
	UnlockList(c->HubList);

	if (b)
	{
		return ERR_HUB_ALREADY_EXISTS;
	}

	ALog(a, NULL, "LA_CREATE_HUB", t->HubName);

	// For JSON-RPC
	if ((IsZero(t->HashedPassword, sizeof(t->HashedPassword)) &&
		IsZero(t->SecurePassword, sizeof(t->SecurePassword))) ||
		StrLen(t->AdminPasswordPlainText) != 0)
	{
		Sha0(t->HashedPassword, t->AdminPasswordPlainText, StrLen(t->AdminPasswordPlainText));
		HashPassword(t->SecurePassword, ADMINISTRATOR_USERNAME, t->AdminPasswordPlainText);
	}

	h = NewHub(c, t->HubName, &o);
	Copy(h->HashedPassword, t->HashedPassword, SHA1_SIZE);
	Copy(h->SecurePassword, t->SecurePassword, SHA1_SIZE);

	AddHub(c, h);

	if (t->Online)
	{
		h->Offline = true;
		SetHubOnline(h);
	}
	else
	{
		h->Offline = false;
		SetHubOffline(h);
	}

	h->CreatedTime = SystemTime64();

	ReleaseHub(h);

	IncrementServerConfigRevision(s);

	return ERR_NO_ERROR;
}
