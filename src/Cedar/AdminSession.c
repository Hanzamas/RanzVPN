// AdminSession.c
// Admin RPC area: IP and MAC tables and sessions of a Virtual Hub

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

UINT StDeleteIpTable(ADMIN *a, RPC_DELETE_TABLE *t)
{
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;
	HUB *h = NULL;
	UINT ret = ERR_NO_ERROR;

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

	if (a->ServerAdmin == false && GetHubAdminOption(h, "no_delete_iptable") != 0)
	{
		ReleaseHub(h);
		return ERR_NOT_ENOUGH_RIGHT;
	}

	LockList(h->IpTable);
	{
		if (IsInListKey(h->IpTable, t->Key))
		{
			IP_TABLE_ENTRY *e = ListKeyToPointer(h->IpTable, t->Key);
			Free(e);
			Delete(h->IpTable, e);
		}
		else
		{
			ret = ERR_OBJECT_NOT_FOUND;
		}
	}
	UnlockList(h->IpTable);

	ReleaseHub(h);

	return ret;
}

UINT SiEnumIpTable(SERVER *s, char *hubname, RPC_ENUM_IP_TABLE *t)
{
	CEDAR *c;
	UINT i;
	HUB *h = NULL;
	if (s == NULL || hubname == NULL || t == NULL)
	{
		return ERR_INTERNAL_ERROR;
	}

	c = s->Cedar;

	LockHubList(c);
	{
		h = GetHub(c, hubname);
	}
	UnlockHubList(c);

	if (h == NULL)
	{
		return ERR_HUB_NOT_FOUND;
	}

	StrCpy(t->HubName, sizeof(t->HubName), hubname);

	LockList(h->IpTable);
	{
		t->NumIpTable = LIST_NUM(h->IpTable);
		t->IpTables = ZeroMalloc(sizeof(RPC_ENUM_IP_TABLE_ITEM) * t->NumIpTable);

		for (i = 0;i < t->NumIpTable;i++)
		{
			RPC_ENUM_IP_TABLE_ITEM *e = &t->IpTables[i];
			IP_TABLE_ENTRY *table = LIST_DATA(h->IpTable, i);

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
	UnlockList(h->IpTable);

	ReleaseHub(h);

	return ERR_NO_ERROR;
}

UINT StEnumIpTable(ADMIN *a, RPC_ENUM_IP_TABLE *t)
{
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;
	UINT ret = ERR_NO_ERROR;
	char hubname[MAX_HUBNAME_LEN + 1];

	CHECK_RIGHT;

	StrCpy(hubname, sizeof(hubname), t->HubName);
	FreeRpcEnumIpTable(t);
	Zero(t, sizeof(RPC_ENUM_IP_TABLE));
	StrCpy(t->HubName, sizeof(t->HubName), hubname);

	ret = SiEnumIpTable(s, hubname, t);
	if (ret != ERR_NO_ERROR)
	{
		return ret;
	}

	return ret;
}

UINT StDeleteMacTable(ADMIN *a, RPC_DELETE_TABLE *t)
{
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;
	HUB *h = NULL;
	UINT ret = ERR_NO_ERROR;

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

	if (a->ServerAdmin == false && GetHubAdminOption(h, "no_delete_mactable") != 0)
	{
		ReleaseHub(h);
		return ERR_NOT_ENOUGH_RIGHT;
	}

	LockHashList(h->MacHashTable);
	{
		if (IsInHashListKey(h->MacHashTable, t->Key))
		{
			MAC_TABLE_ENTRY *e = HashListKeyToPointer(h->MacHashTable, t->Key);
			DeleteHash(h->MacHashTable, e);
			Free(e);
		}
		else
		{
			ret = ERR_OBJECT_NOT_FOUND;
		}
	}
	UnlockHashList(h->MacHashTable);

	ReleaseHub(h);

	return ret;
}

UINT SiEnumMacTable(SERVER *s, char *hubname, RPC_ENUM_MAC_TABLE *t)
{
	CEDAR *c;
	UINT i;
	HUB *h = NULL;
	if (s == NULL || hubname == NULL || t == NULL)
	{
		return ERR_INTERNAL_ERROR;
	}

	c = s->Cedar;

	LockHubList(c);
	{
		h = GetHub(c, hubname);
	}
	UnlockHubList(c);

	if (h == NULL)
	{
		return ERR_HUB_NOT_FOUND;
	}

	StrCpy(t->HubName, sizeof(t->HubName), hubname);

	LockHashList(h->MacHashTable);
	{
		MAC_TABLE_ENTRY **pp = (MAC_TABLE_ENTRY **)HashListToArray(h->MacHashTable, &t->NumMacTable);
		t->MacTables = ZeroMalloc(sizeof(RPC_ENUM_MAC_TABLE_ITEM) * t->NumMacTable);

		for (i = 0;i < t->NumMacTable;i++)
		{
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
	UnlockHashList(h->MacHashTable);

	ReleaseHub(h);

	return ERR_NO_ERROR;
}

UINT StEnumMacTable(ADMIN *a, RPC_ENUM_MAC_TABLE *t)
{
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;
	HUB *h = NULL;
	UINT ret = ERR_NO_ERROR;
	char hubname[MAX_HUBNAME_LEN + 1];

	CHECK_RIGHT;

	StrCpy(hubname, sizeof(hubname), t->HubName);
	FreeRpcEnumMacTable(t);
	Zero(t, sizeof(RPC_ENUM_MAC_TABLE));

	ret = SiEnumMacTable(s, hubname, t);
	if (ret != ERR_NO_ERROR)
	{
		return ret;
	}

	return ret;
}

UINT StDeleteSession(ADMIN *a, RPC_DELETE_SESSION *t)
{
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;
	HUB *h = NULL;
	UINT ret = ERR_NO_ERROR;
	char hubname[MAX_HUBNAME_LEN + 1];
	char name[MAX_SESSION_NAME_LEN + 1];
	SESSION *sess;

	if (IsEmptyStr(t->Name))
	{
		return ERR_INVALID_PARAMETER;
	}

	StrCpy(hubname, sizeof(hubname), t->HubName);
	StrCpy(name, sizeof(name), t->Name);

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

	if (a->ServerAdmin == false && GetHubAdminOption(h, "no_disconnect_session") != 0)
	{
		ReleaseHub(h);
		return ERR_NOT_ENOUGH_RIGHT;
	}

	sess = GetSessionByName(h, name);

	if (sess == NULL)
	{
		ret = ERR_OBJECT_NOT_FOUND;
	}
	else
	{
		if (sess->LinkModeServer)
		{
			ret = ERR_LINK_CANT_DISCONNECT;
		}
		else if (sess->BridgeMode)
		{
			ret = ERR_BRIDGE_CANT_DISCONNECT;
		}
		else
		{
			StopSession(sess);
		}
		ReleaseSession(sess);
	}

	if (ret != ERR_NO_ERROR)
	{
		ALog(a, h, "LA_DELETE_SESSION", t->Name);
	}

	ReleaseHub(h);

	return ret;
}

UINT StGetSessionStatus(ADMIN *a, RPC_SESSION_STATUS *t)
{
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;
	HUB *h = NULL;
	UINT ret = ERR_NO_ERROR;
	char hubname[MAX_HUBNAME_LEN + 1];
	char name[MAX_SESSION_NAME_LEN + 1];
	SESSION *sess;

	StrCpy(hubname, sizeof(hubname), t->HubName);
	StrCpy(name, sizeof(name), t->Name);

	if (IsEmptyStr(t->Name))
	{
		return ERR_INVALID_PARAMETER;
	}

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

	if (a->ServerAdmin == false && GetHubAdminOption(h, "no_query_session") != 0)
	{
		ReleaseHub(h);
		return ERR_NOT_ENOUGH_RIGHT;
	}

	FreeRpcSessionStatus(t);
	Zero(t, sizeof(RPC_SESSION_STATUS));
	StrCpy(t->HubName, sizeof(t->HubName), hubname);
	StrCpy(t->Name, sizeof(t->Name), name);

	sess = GetSessionByName(h, t->Name);

	if (sess == NULL)
	{
		ret = ERR_OBJECT_NOT_FOUND;
	}
	else
	{
		SESSION *s = sess;

		Lock(s->lock);
		{
			StrCpy(t->Username, sizeof(t->Username), s->Username);
			StrCpy(t->RealUsername, sizeof(t->RealUsername), s->UserNameReal);
			StrCpy(t->GroupName, sizeof(t->GroupName), s->GroupName);
			Copy(&t->NodeInfo, &s->NodeInfo, sizeof(NODE_INFO));

			if (s->Connection != NULL)
			{
				t->ClientIp = IPToUINT(&s->Connection->ClientIp);
				if (IsIP6(&s->Connection->ClientIp))
				{
					Copy(&t->ClientIp6, &s->Connection->ClientIp.address, sizeof(t->ClientIp6));
				}

				CopyIP(&t->ClientIpAddress, &s->Connection->ClientIp);

				StrCpy(t->ClientHostName, sizeof(t->ClientHostName), s->Connection->ClientHostname);
			}
		}
		Unlock(s->lock);

		CiGetSessionStatus(&t->Status, s);

		ReleaseSession(s);
	}

	ReleaseHub(h);

	return ret;
}

void SiEnumSessionMain(SERVER *s, RPC_ENUM_SESSION *t)
{
	char hubname[MAX_HUBNAME_LEN + 1];
	UINT ret = ERR_NO_ERROR;
	UINT num;
	if (s == NULL || t == NULL)
	{
		return;
	}

	StrCpy(hubname, sizeof(hubname), t->HubName);

	FreeRpcEnumSession(t);
	Zero(t, sizeof(RPC_ENUM_SESSION));
	StrCpy(t->HubName, sizeof(t->HubName), hubname);

	num = 0;
	SiEnumLocalSession(s, hubname, t);

}

UINT StEnumSession(ADMIN *a, RPC_ENUM_SESSION *t)
{
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;
	HUB *h = NULL;
	UINT ret = ERR_NO_ERROR;

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

	if (a->ServerAdmin == false && GetHubAdminOption(h, "no_enum_session") != 0)
	{
		ReleaseHub(h);
		return ERR_NOT_ENOUGH_RIGHT;
	}

	SiEnumSessionMain(s, t);

	ReleaseHub(h);

	return ret;
}

void SiEnumLocalSession(SERVER *s, char *hubname, RPC_ENUM_SESSION *t)
{
	HUB *h;
	UINT64 now = Tick64();
	UINT64 dormant_interval = 0;
	if (s == NULL || hubname == NULL || t == NULL)
	{
		return;
	}

	LockHubList(s->Cedar);
	h = GetHub(s->Cedar, hubname);
	UnlockHubList(s->Cedar);

	if (h == NULL)
	{
		t->NumSession = 0;
		t->Sessions = ZeroMalloc(0);
		return;
	}

	if (h->Option != NULL)
	{
		dormant_interval = h->Option->DetectDormantSessionInterval * (UINT64)1000;
	}

	LockList(h->SessionList);
	{
		UINT i;
		t->NumSession = LIST_NUM(h->SessionList);
		t->Sessions = ZeroMalloc(sizeof(RPC_ENUM_SESSION_ITEM) * t->NumSession);

		for (i = 0;i < t->NumSession;i++)
		{
			SESSION *s = LIST_DATA(h->SessionList, i);
			RPC_ENUM_SESSION_ITEM *e = &t->Sessions[i];
			Lock(s->lock);
			{
				StrCpy(e->Name, sizeof(e->Name), s->Name);
				StrCpy(e->Username, sizeof(e->Username), s->Username);
				e->Ip = IPToUINT(&s->Connection->ClientIp);
				CopyIP(&e->ClientIP, &s->Connection->ClientIp);
				StrCpy(e->Hostname, sizeof(e->Hostname), s->Connection->ClientHostname);
				e->MaxNumTcp = s->MaxConnection;
				e->CreatedTime = Tick64ToTime64(s->CreatedTime);
				e->LastCommTime = Tick64ToTime64(s->LastCommTime);
				e->LinkMode = s->LinkModeServer;
				e->BridgeMode = s->BridgeMode;
				e->VLanId = s->VLanId;
				LockList(s->Connection->Tcp->TcpSockList);
				{
					e->CurrentNumTcp = s->Connection->Tcp->TcpSockList->num_item;
				}
				UnlockList(s->Connection->Tcp->TcpSockList);
				Lock(s->TrafficLock);
				{
					e->PacketSize = GetTrafficPacketSize(s->Traffic);
					e->PacketNum = GetTrafficPacketNum(s->Traffic);
				}
				Unlock(s->TrafficLock);
				e->Client_BridgeMode = s->IsBridgeMode;
				e->Client_MonitorMode = s->IsMonitorMode;
				Copy(e->UniqueId, s->NodeInfo.UniqueId, 16);

				if (s->NormalClient)
				{
					e->IsDormantEnabled = (dormant_interval == 0 ? false : true);
					if (e->IsDormantEnabled)
					{
						if (s->LastCommTimeForDormant == 0)
						{
							e->LastCommDormant = (UINT64)0x7FFFFFFF;
						}
						else
						{
							e->LastCommDormant = now - s->LastCommTimeForDormant;
						}
						if (s->LastCommTimeForDormant == 0)
						{
							e->IsDormant = true;
						}
						else
						{
							if ((s->LastCommTimeForDormant + dormant_interval) < now)
							{
								e->IsDormant = true;
							}
						}
					}
				}
			}
			Unlock(s->lock);
		}
	}
	UnlockList(h->SessionList);

	ReleaseHub(h);
}
