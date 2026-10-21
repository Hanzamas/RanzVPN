// AdminSession.c
// Admin RPC area: IP and MAC tables and sessions of a Virtual Hub

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
#include "Mayaqua/Str.h"
#include "Mayaqua/Table.h"
#include "Mayaqua/Tick64.h"
#include "AdminInternal.h"

static void SiEnumLocalSession(SERVER *s, char *hubname, RPC_ENUM_SESSION *t);

UINT StDeleteIpTable(ADMIN *a, RPC_DELETE_TABLE *t) {
	HUB *h = NULL;
	UINT err;
	UINT ret = ERR_NO_ERROR;

	h = AdminGetHub(a, t->HubName, "no_delete_iptable", &err);
	if (h == NULL) {
		return err;
	}

	if (IpTableDeleteByKey(h, t->Key) == false) {
		ret = ERR_OBJECT_NOT_FOUND;
	}

	ReleaseHub(h);

	return ret;
}

static UINT SiEnumIpTable(SERVER *s, char *hubname, RPC_ENUM_IP_TABLE *t) {
	HUB *h = NULL;
	if (s == NULL || hubname == NULL || t == NULL) {
		return ERR_INTERNAL_ERROR;
	}

	h = GetHub(s->Cedar, hubname);

	if (h == NULL) {
		return ERR_HUB_NOT_FOUND;
	}

	StrCpy(t->HubName, sizeof(t->HubName), hubname);

	HubLockTables(h);
	{
		t->NumIpTable = HubIpTableNum(h);
		t->IpTables = ZeroMalloc(sizeof(RPC_ENUM_IP_TABLE_ITEM) * t->NumIpTable);

		for (UINT i = 0; i < t->NumIpTable; i++) {
			RPC_ENUM_IP_TABLE_ITEM *e = &t->IpTables[i];
			IP_TABLE_ENTRY *table = IpTableGet(h, i);

			e->Key = POINTER_TO_KEY(table);
			StrCpy(e->SessionName, sizeof(e->SessionName), table->Session->Name);
			e->Ip = IPToUINT(&table->Ip);
			Copy(&e->IpV6, &table->Ip, sizeof(IP));
			Copy(&e->IpAddress, &table->Ip, sizeof(IP));
			e->DhcpAllocated = table->DhcpAllocated;
			e->CreatedTime = Tick64ToTime64(table->CreatedTime);
			e->UpdatedTime = Tick64ToTime64(table->UpdatedTime);
		}
	}
	HubUnlockTables(h);

	ReleaseHub(h);

	return ERR_NO_ERROR;
}

UINT StEnumIpTable(ADMIN *a, RPC_ENUM_IP_TABLE *t) {
	SERVER *s = a->Server;
	char hubname[MAX_HUBNAME_LEN + 1];

	CHECK_RIGHT;

	StrCpy(hubname, sizeof(hubname), t->HubName);
	FreeRpcEnumIpTable(t);
	Zero(t, sizeof(RPC_ENUM_IP_TABLE));
	StrCpy(t->HubName, sizeof(t->HubName), hubname);

	return SiEnumIpTable(s, hubname, t);
}

UINT StDeleteMacTable(ADMIN *a, RPC_DELETE_TABLE *t) {
	HUB *h = NULL;
	UINT err;
	UINT ret = ERR_NO_ERROR;

	h = AdminGetHub(a, t->HubName, "no_delete_mactable", &err);
	if (h == NULL) {
		return err;
	}

	if (MacTableDeleteByKey(h, t->Key) == false) {
		ret = ERR_OBJECT_NOT_FOUND;
	}

	ReleaseHub(h);

	return ret;
}

static UINT SiEnumMacTable(SERVER *s, char *hubname, RPC_ENUM_MAC_TABLE *t) {
	HUB *h = NULL;
	if (s == NULL || hubname == NULL || t == NULL) {
		return ERR_INTERNAL_ERROR;
	}

	h = GetHub(s->Cedar, hubname);

	if (h == NULL) {
		return ERR_HUB_NOT_FOUND;
	}

	StrCpy(t->HubName, sizeof(t->HubName), hubname);

	HubLockTables(h);
	{
		MAC_TABLE_ENTRY **pp = MacTableEnum(h, &t->NumMacTable);
		t->MacTables = ZeroMalloc(sizeof(RPC_ENUM_MAC_TABLE_ITEM) * t->NumMacTable);

		for (UINT i = 0; i < t->NumMacTable; i++) {
			RPC_ENUM_MAC_TABLE_ITEM *e = &t->MacTables[i];
			MAC_TABLE_ENTRY *mac = pp[i];

			e->Key = POINTER_TO_KEY(mac);
			StrCpy(e->SessionName, sizeof(e->SessionName), mac->Session->Name);
			Copy(e->MacAddress, mac->MacAddress, sizeof(e->MacAddress));
			e->CreatedTime = Tick64ToTime64(mac->CreatedTime);
			e->UpdatedTime = Tick64ToTime64(mac->UpdatedTime);
			e->VlanId = mac->VlanId;
		}

		Free(pp);
	}
	HubUnlockTables(h);

	ReleaseHub(h);

	return ERR_NO_ERROR;
}

UINT StEnumMacTable(ADMIN *a, RPC_ENUM_MAC_TABLE *t) {
	SERVER *s = a->Server;
	char hubname[MAX_HUBNAME_LEN + 1];

	CHECK_RIGHT;

	StrCpy(hubname, sizeof(hubname), t->HubName);
	FreeRpcEnumMacTable(t);
	Zero(t, sizeof(RPC_ENUM_MAC_TABLE));

	return SiEnumMacTable(s, hubname, t);
}

UINT StDeleteSession(ADMIN *a, RPC_DELETE_SESSION *t) {
	HUB *h = NULL;
	UINT err;
	UINT ret = ERR_NO_ERROR;
	char name[MAX_SESSION_NAME_LEN + 1];

	if (IsEmptyStr(t->Name)) {
		return ERR_INVALID_PARAMETER;
	}

	StrCpy(name, sizeof(name), t->Name);

	h = AdminGetHub(a, t->HubName, "no_disconnect_session", &err);
	if (h == NULL) {
		return err;
	}

	SESSION *sess = GetSessionByName(h, name);

	if (sess == NULL) {
		ret = ERR_OBJECT_NOT_FOUND;
	} else {
		if (sess->LinkModeServer) {
			ret = ERR_LINK_CANT_DISCONNECT;
		} else if (sess->BridgeMode) {
			ret = ERR_BRIDGE_CANT_DISCONNECT;
		} else {
			StopSession(sess);
		}
		ReleaseSession(sess);
	}

	if (ret == ERR_NO_ERROR) {
		ALog(a, h, "LA_DELETE_SESSION", t->Name);
	}

	ReleaseHub(h);

	return ret;
}

UINT StGetSessionStatus(ADMIN *a, RPC_SESSION_STATUS *t) {
	HUB *h = NULL;
	UINT err;
	UINT ret = ERR_NO_ERROR;
	char hubname[MAX_HUBNAME_LEN + 1];
	char name[MAX_SESSION_NAME_LEN + 1];

	StrCpy(hubname, sizeof(hubname), t->HubName);
	StrCpy(name, sizeof(name), t->Name);

	if (IsEmptyStr(t->Name)) {
		return ERR_INVALID_PARAMETER;
	}

	h = AdminGetHub(a, t->HubName, "no_query_session", &err);
	if (h == NULL) {
		return err;
	}

	FreeRpcSessionStatus(t);
	Zero(t, sizeof(RPC_SESSION_STATUS));
	StrCpy(t->HubName, sizeof(t->HubName), hubname);
	StrCpy(t->Name, sizeof(t->Name), name);

	SESSION *sess = GetSessionByName(h, t->Name);

	if (sess == NULL) {
		ret = ERR_OBJECT_NOT_FOUND;
	} else {
		SESSION_INFO info;

		SessionGetInfo(sess, &info);

		StrCpy(t->Username, sizeof(t->Username), info.Username);
		StrCpy(t->RealUsername, sizeof(t->RealUsername), info.RealUsername);
		StrCpy(t->GroupName, sizeof(t->GroupName), info.GroupName);
		Copy(&t->NodeInfo, &info.NodeInfo, sizeof(NODE_INFO));

		t->ClientIp = IPToUINT(&info.ClientIp);
		if (IsIP6(&info.ClientIp)) {
			Copy(&t->ClientIp6, &info.ClientIp.address, sizeof(t->ClientIp6));
		}

		CopyIP(&t->ClientIpAddress, &info.ClientIp);

		StrCpy(t->ClientHostName, sizeof(t->ClientHostName), info.ClientHostname);

		CiGetSessionStatus(&t->Status, sess);

		ReleaseSession(sess);
	}

	ReleaseHub(h);

	return ret;
}

UINT StEnumSession(ADMIN *a, RPC_ENUM_SESSION *t) {
	SERVER *s = a->Server;
	HUB *h = NULL;
	UINT err;
	UINT ret = ERR_NO_ERROR;
	char hubname[MAX_HUBNAME_LEN + 1];

	h = AdminGetHub(a, t->HubName, "no_enum_session", &err);
	if (h == NULL) {
		return err;
	}

	StrCpy(hubname, sizeof(hubname), t->HubName);

	FreeRpcEnumSession(t);
	Zero(t, sizeof(RPC_ENUM_SESSION));
	StrCpy(t->HubName, sizeof(t->HubName), hubname);

	SiEnumLocalSession(s, hubname, t);

	ReleaseHub(h);

	return ret;
}

static void SiEnumLocalSession(SERVER *s, char *hubname, RPC_ENUM_SESSION *t) {
	UINT64 now = Tick64();
	if (s == NULL || hubname == NULL || t == NULL) {
		return;
	}

	HUB *h = GetHub(s->Cedar, hubname);

	if (h == NULL) {
		t->NumSession = 0;
		t->Sessions = ZeroMalloc(0);
		return;
	}

	UINT64 dormant_interval = h->Option->DetectDormantSessionInterval * (UINT64)1000;

	SESSION_INFO *info = HubEnumSessions(h, &t->NumSession);
	t->Sessions = ZeroMalloc(sizeof(RPC_ENUM_SESSION_ITEM) * t->NumSession);

	for (UINT i = 0; i < t->NumSession; i++) {
		SESSION_INFO *si = &info[i];
		RPC_ENUM_SESSION_ITEM *e = &t->Sessions[i];

		StrCpy(e->Name, sizeof(e->Name), si->Name);
		StrCpy(e->Username, sizeof(e->Username), si->Username);
		e->Ip = IPToUINT(&si->ClientIp);
		CopyIP(&e->ClientIP, &si->ClientIp);
		StrCpy(e->Hostname, sizeof(e->Hostname), si->ClientHostname);
		e->MaxNumTcp = si->MaxConnection;
		e->CreatedTime = Tick64ToTime64(si->CreatedTime);
		e->LastCommTime = Tick64ToTime64(si->LastCommTime);
		e->LinkMode = si->LinkModeServer;
		e->BridgeMode = si->BridgeMode;
		e->VLanId = si->VLanId;
		e->CurrentNumTcp = si->NumTcp;
		e->PacketSize = si->PacketSize;
		e->PacketNum = si->PacketNum;
		e->Client_BridgeMode = si->IsBridgeMode;
		e->Client_MonitorMode = si->IsMonitorMode;
		Copy(e->UniqueId, si->NodeInfo.UniqueId, 16);

		if (si->NormalClient) {
			e->IsDormantEnabled = (dormant_interval == 0 ? false : true);
			if (e->IsDormantEnabled) {
				if (si->LastCommTimeForDormant == 0) {
					e->LastCommDormant = (UINT64)0x7FFFFFFF;
				} else {
					e->LastCommDormant = now - si->LastCommTimeForDormant;
				}
				if (si->LastCommTimeForDormant == 0) {
					e->IsDormant = true;
				} else {
					if ((si->LastCommTimeForDormant + dormant_interval) < now) {
						e->IsDormant = true;
					}
				}
			}
		}
	}

	Free(info);

	ReleaseHub(h);
}
