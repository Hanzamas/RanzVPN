// AdminHub.c
// Admin RPC area: Virtual Hubs (create, set, enumerate, delete, status, online, log settings) and the server connections

#include "Admin.h"

#include "BridgeWin32.h"
#include "Connection.h"
#include "Link.h"
#include "Listener.h"
#include "Remote.h"
#include "RpcField.h"
#include "Protocol.h"
#include "Server.h"

#include "Mayaqua/Cfg.h"
#include "Mayaqua/FileIO.h"
#include "Mayaqua/Memory.h"
#include "Mayaqua/Microsoft.h"
#include "Mayaqua/Object.h"
#include "Mayaqua/Str.h"
#include "Mayaqua/Table.h"
#include "Mayaqua/Tick64.h"
#include "AdminInternal.h"

UINT StGetHubLog(ADMIN *a, RPC_HUB_LOG *t) {
	UINT err;

	HUB *h = AdminGetHub(a, t->HubName, NULL, &err);
	if (h == NULL) {
		return err;
	}

	GetHubLogSetting(h, &t->LogSetting);

	ReleaseHub(h);

	return ERR_NO_ERROR;
}

UINT StSetHubLog(ADMIN *a, RPC_HUB_LOG *t) {
	SERVER *s = a->Server;
	UINT err;

	HUB *h = AdminGetHub(a, t->HubName, "no_change_log_config", &err);
	if (h == NULL) {
		return err;
	}

	ALog(a, h, "LA_SET_HUB_LOG");

	SetHubLogSettingEx(h, &t->LogSetting,
	                   (a->ServerAdmin == false && GetHubAdminOption(h, "no_change_log_switch_type") != 0));

	ReleaseHub(h);

	IncrementServerConfigRevision(s);

	return ERR_NO_ERROR;
}

UINT StGetHubStatus(ADMIN *a, RPC_HUB_STATUS *t) {
	UINT err;
	HUB_STATS st;

	HUB *h = AdminGetHub(a, t->HubName, NULL, &err);
	if (h == NULL) {
		return err;
	}

	Zero(t, sizeof(RPC_HUB_STATUS));

	HubGetStats(h, &st);

	StrCpy(t->HubName, sizeof(t->HubName), h->Name);
	t->Online = st.Online;
	t->NumSessions = st.NumSessions;
	t->NumSessionsClient = st.NumSessionsClient;
	t->NumSessionsBridge = st.NumSessionsBridge;
	t->NumAccessLists = st.NumAccessLists;
	t->NumUsers = st.NumUsers;
	t->NumGroups = st.NumGroups;
	t->NumMacTables = st.NumMacTables;
	t->NumIpTables = st.NumIpTables;
	Copy(&t->Traffic, &st.Traffic, sizeof(TRAFFIC));
	t->NumLogin = st.NumLogin;
	t->LastCommTime = st.LastCommTime;
	t->LastLoginTime = st.LastLoginTime;
	t->CreatedTime = st.CreatedTime;

	ReleaseHub(h);

	return ERR_NO_ERROR;
}

UINT StSetHubOnline(ADMIN *a, RPC_SET_HUB_ONLINE *t) {
	SERVER *s = a->Server;
	UINT err;


	HUB *h = AdminGetHub(a, t->HubName, NULL, &err);
	if (h == NULL) {
		return err;
	}

	if (a->ServerAdmin == false && t->Online && GetHubAdminOption(h, "no_online") != 0) {
		ReleaseHub(h);
		return ERR_NOT_ENOUGH_RIGHT;
	}

	if (a->ServerAdmin == false && t->Online == false && GetHubAdminOption(h, "no_offline") != 0) {
		ReleaseHub(h);
		return ERR_NOT_ENOUGH_RIGHT;
	}

	if (t->Online) {
		ALog(a, h, "LA_SET_HUB_ONLINE");
		SetHubOnline(h);
	} else {
		ALog(a, h, "LA_SET_HUB_OFFLINE");
		SetHubOffline(h);
	}

	IncrementServerConfigRevision(s);

	ReleaseHub(h);

	return ERR_NO_ERROR;
}

UINT StGetConnectionInfo(ADMIN *a, RPC_CONNECTION_INFO *t) {
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;
	CONNECTION *connection;
	CONNECTION_INFO info;

	if (IsEmptyStr(t->Name)) {
		return ERR_INVALID_PARAMETER;
	}

	SERVER_ADMIN_ONLY;

	LockList(c->ConnectionList);
	{
		CONNECTION tt;
		Zero(&tt, sizeof(tt));
		tt.Name = t->Name;

		connection = Search(c->ConnectionList, &tt);

		if (connection != NULL) {
			AddRef(connection->ref);
		}
	}
	UnlockList(c->ConnectionList);

	if (connection == NULL) {
		return ERR_OBJECT_NOT_FOUND;
	}

	ConnectionGetInfo(connection, &info);

	ReleaseConnection(connection);

	Zero(t, sizeof(RPC_CONNECTION_INFO));
	StrCpy(t->Name, sizeof(t->Name), info.Name);
	t->Ip = IPToUINT(&info.RemoteIp);
	t->Port = info.RemotePort;
	StrCpy(t->Hostname, sizeof(t->Hostname), info.RemoteHostname);
	t->ConnectedTime = Tick64ToTime64(info.ConnectedTick);
	t->Type = info.Type;

	StrCpy(t->ServerStr, sizeof(t->ServerStr), info.ServerStr);
	StrCpy(t->ClientStr, sizeof(t->ClientStr), info.ClientStr);
	t->ServerVer = info.ServerVer;
	t->ServerBuild = info.ServerBuild;
	t->ClientVer = info.ClientVer;
	t->ClientBuild = info.ClientBuild;

	return ERR_NO_ERROR;
}

UINT StDisconnectConnection(ADMIN *a, RPC_DISCONNECT_CONNECTION *t) {
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;
	CONNECTION *connection;

	if (IsEmptyStr(t->Name)) {
		return ERR_INVALID_PARAMETER;
	}

	SERVER_ADMIN_ONLY;

	LockList(c->ConnectionList);
	{
		CONNECTION tt;
		Zero(&tt, sizeof(tt));
		tt.Name = t->Name;

		connection = Search(c->ConnectionList, &tt);
		if (connection != NULL) {
			AddRef(connection->ref);
		}
	}
	UnlockList(c->ConnectionList);

	if (connection == NULL) {
		return ERR_OBJECT_NOT_FOUND;
	}

	StopConnection(connection, true);

	ReleaseConnection(connection);

	ALog(a, NULL, "LA_DISCONNECT_CONN", t->Name);

	return ERR_NO_ERROR;
}

UINT StEnumConnection(ADMIN *a, RPC_ENUM_CONNECTION *t) {
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;

	SERVER_ADMIN_ONLY;

	FreeRpcEnumConnection(t);
	Zero(t, sizeof(RPC_ENUM_CONNECTION));

	LockList(c->ConnectionList);
	{
		t->NumConnection = LIST_NUM(c->ConnectionList);
		t->Connections = ZeroMalloc(sizeof(RPC_ENUM_CONNECTION_ITEM) * t->NumConnection);

		for (UINT i = 0; i < t->NumConnection; i++) {
			RPC_ENUM_CONNECTION_ITEM *e = &t->Connections[i];
			CONNECTION_INFO info;

			ConnectionGetInfo(LIST_DATA(c->ConnectionList, i), &info);

			e->Ip = IPToUINT(&info.RemoteIp);
			e->Port = info.RemotePort;
			StrCpy(e->Hostname, sizeof(e->Hostname), info.RemoteHostname);
			StrCpy(e->Name, sizeof(e->Name), info.Name);
			e->ConnectedTime = Tick64ToTime64(info.ConnectedTick);
			e->Type = info.Type;
		}
	}
	UnlockList(c->ConnectionList);

	return ERR_NO_ERROR;
}

UINT StDeleteHub(ADMIN *a, RPC_DELETE_HUB *t) {
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;
	HUB *h = NULL;


	if (IsEmptyStr(t->HubName) || IsSafeStr(t->HubName) == false) {
		return ERR_INVALID_PARAMETER;
	}

	SERVER_ADMIN_ONLY;

	h = GetHub(c, t->HubName);

	if (h == NULL) {
		return ERR_HUB_NOT_FOUND;
	}

	StopHub(h);

	IncrementServerConfigRevision(s);

	DelHub(c, h);
	ReleaseHub(h);

	ALog(a, NULL, "LA_DELETE_HUB", t->HubName);

	return ERR_NO_ERROR;
}

UINT StEnumHub(ADMIN *a, RPC_ENUM_HUB *t) {
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;

	FreeRpcEnumHub(t);

	Zero(t, sizeof(RPC_ENUM_HUB));

	LockHubList(c);
	{
		// Sized for every hub; NumHub counts the ones this admin may see
		t->Hubs = ZeroMalloc(sizeof(RPC_ENUM_HUB_ITEM) * LIST_NUM(c->HubList));

		for (UINT i = 0; i < LIST_NUM(c->HubList); i++) {
			HUB *h = LIST_DATA(c->HubList, i);
			HUB_STATS st;

			if (a->ServerAdmin == false && StrCmpi(h->Name, a->HubName) != 0) {
				continue;
			}

			RPC_ENUM_HUB_ITEM *e = &t->Hubs[t->NumHub++];

			HubGetStats(h, &st);

			StrCpy(e->HubName, sizeof(e->HubName), h->Name);
			e->Online = st.Online;
			e->NumSessions = st.NumSessions;
			e->NumMacTables = st.NumMacTables;
			e->NumIpTables = st.NumIpTables;
			e->NumUsers = st.NumUsers;
			e->NumGroups = st.NumGroups;
			e->LastCommTime = st.LastCommTime;
			e->LastLoginTime = st.LastLoginTime;
			e->NumLogin = st.NumLogin;
			e->CreatedTime = st.CreatedTime;
			Copy(&e->Traffic, &st.Traffic, sizeof(TRAFFIC));

			e->IsTrafficFilled = true;
		}
	}
	UnlockHubList(c);

	return ERR_NO_ERROR;
}

UINT StGetHub(ADMIN *a, RPC_CREATE_HUB *t) {
	UINT ret = ERR_NO_ERROR;

	if (IsEmptyStr(t->HubName) || IsSafeStr(t->HubName) == false) {
		return ERR_INVALID_PARAMETER;
	}

	HUB *h = AdminGetHub(a, t->HubName, NULL, &ret);

	Zero(t, sizeof(RPC_CREATE_HUB));

	if (h == NULL) {
		return ret;
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

UINT StSetHub(ADMIN *a, RPC_CREATE_HUB *t) {
	SERVER *s = a->Server;
	UINT err;
	UINT ret = ERR_NO_ERROR;

	if (IsEmptyStr(t->HubName) || IsSafeStr(t->HubName) == false) {
		return ERR_INVALID_PARAMETER;
	}

	CHECK_RIGHT;

	HUB *h = AdminGetHub(a, t->HubName, NULL, &err);
	if (h == NULL) {
		return err;
	}

	// For JSON-RPC
	if (StrLen(t->AdminPasswordPlainText) != 0) {
		Sha0(t->HashedPassword, t->AdminPasswordPlainText, StrLen(t->AdminPasswordPlainText));
		HashPassword(t->SecurePassword, ADMINISTRATOR_USERNAME, t->AdminPasswordPlainText);
	}

	if (IsZero(t->HashedPassword, sizeof(t->HashedPassword)) == false &&
	    IsZero(t->SecurePassword, sizeof(t->SecurePassword)) == false) {
		if (a->ServerAdmin == false && GetHubAdminOption(h, "no_change_admin_password") != 0) {
			ReleaseHub(h);
			return ERR_NOT_ENOUGH_RIGHT;
		}
	}

	{
		UCHAR hash1[SHA1_SIZE], hash2[SHA1_SIZE];
		HashPassword(hash1, ADMINISTRATOR_USERNAME, "");
		Sha0(hash2, "", 0);

		if (Cmp(t->HashedPassword, hash2, SHA1_SIZE) == 0 || Cmp(t->SecurePassword, hash1, SHA1_SIZE) == 0) {
			if (a->ServerAdmin == false && IsLocalHostIP(&a->RemoteIP) == false) {
				// Refuse a blank hub admin password set from a remote host
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
		    IsZero(t->SecurePassword, sizeof(t->SecurePassword)) == false) {
			Copy(h->HashedPassword, t->HashedPassword, SHA1_SIZE);
			Copy(h->SecurePassword, t->SecurePassword, SHA1_SIZE);
		}
	}
	Unlock(h->lock);

	if (t->Online) {
		if (a->ServerAdmin || GetHubAdminOption(h, "no_online") == 0) {
			SetHubOnline(h);
		}
	} else {
		if (a->ServerAdmin || GetHubAdminOption(h, "no_offline") == 0) {
			SetHubOffline(h);
		}
	}

	IncrementServerConfigRevision(s);

	ALog(a, h, "LA_SET_HUB");

	ReleaseHub(h);

	return ret;
}

UINT StCreateHub(ADMIN *a, RPC_CREATE_HUB *t) {
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;
	HUB_OPTION o;
	UINT current_hub_num;
	bool b;

	if (IsEmptyStr(t->HubName) || IsSafeStr(t->HubName) == false) {
		return ERR_INVALID_PARAMETER;
	}

	SERVER_ADMIN_ONLY;

	Trim(t->HubName);
	if (StrLen(t->HubName) == 0) {
		return ERR_INVALID_PARAMETER;
	}
	if (StartWith(t->HubName, ".") || EndWith(t->HubName, ".")) {
		return ERR_INVALID_PARAMETER;
	}

	Zero(&o, sizeof(o));
	o.MaxSession = t->HubOption.MaxSession;
	o.NoEnum = t->HubOption.NoEnum;

	SiSetDefaultHubOption(&o);

	LockList(c->HubList);
	{
		current_hub_num = LIST_NUM(c->HubList);
	}
	UnlockList(c->HubList);

	if (current_hub_num > SERVER_MAX_SESSIONS) {
		return ERR_TOO_MANY_HUBS;
	}

	LockList(c->HubList);
	{
		b = IsHub(c, t->HubName);
	}
	UnlockList(c->HubList);

	if (b) {
		return ERR_HUB_ALREADY_EXISTS;
	}

	ALog(a, NULL, "LA_CREATE_HUB", t->HubName);

	// For JSON-RPC
	if ((IsZero(t->HashedPassword, sizeof(t->HashedPassword)) &&
	     IsZero(t->SecurePassword, sizeof(t->SecurePassword))) ||
	    StrLen(t->AdminPasswordPlainText) != 0) {
		Sha0(t->HashedPassword, t->AdminPasswordPlainText, StrLen(t->AdminPasswordPlainText));
		HashPassword(t->SecurePassword, ADMINISTRATOR_USERNAME, t->AdminPasswordPlainText);
	}

	HUB *h = NewHub(c, t->HubName, &o);
	Copy(h->HashedPassword, t->HashedPassword, SHA1_SIZE);
	Copy(h->SecurePassword, t->SecurePassword, SHA1_SIZE);

	AddHub(c, h);

	HubApplyInitialState(h, t->Online);

	h->CreatedTime = SystemTime64();

	ReleaseHub(h);

	IncrementServerConfigRevision(s);

	return ERR_NO_ERROR;
}
