// Bridge.c
// Ethernet Bridge Program (Local Bridge)

#include "Bridge.h"
#include "BridgeWin32.h"

#include "Connection.h"
#include "Hub.h"
#include "Session.h"

#include "Mayaqua/Memory.h"
#include "Mayaqua/Microsoft.h"
#include "Mayaqua/Object.h"
#include "Mayaqua/Str.h"
#include "Mayaqua/TcpIp.h"

UINT GetEthDeviceHash()
{
	UINT ret = 0;
	MS_ADAPTER_LIST *a = MsCreateAdapterListEx(true);
	UINT num;
	UINT i;
	char tmp[4096];
	UCHAR hash[SHA1_SIZE];

	tmp[0] = 0;
	if (a != NULL)
	{
		for (i = 0;i < a->Num;i++)
		{
			StrCat(tmp, sizeof(tmp), a->Adapters[i]->Title);
		}
	}
	MsFreeAdapterList(a);

	Sha0(hash, tmp, StrLen(tmp));

	Copy(&num, hash, sizeof(UINT));

	return num;
}

bool IsBridgeSupported()
{
	UINT type = GetOsInfo()->OsType;

	if (OS_IS_WINDOWS(type))
	{
		if (IsEthSupported())
		{
			return true;
		}
		else
		{
			bool ret = false;

			ret = MsIsAdmin();

			return ret;
		}
	}
	else
	{
		return IsEthSupported();
	}
}

bool DeleteLocalBridge(CEDAR *c, char *hubname, char *devicename)
{
	bool ret = false;
	if (c == NULL || hubname == NULL || devicename == NULL)
	{
		return false;
	}

	LockList(c->HubList);
	{
		LockList(c->LocalBridgeList);
		{
			UINT i;

			for (i = 0;i < LIST_NUM(c->LocalBridgeList);i++)
			{
				LOCALBRIDGE *br = LIST_DATA(c->LocalBridgeList, i);

				if (StrCmpi(br->HubName, hubname) == 0)
				{
					if (StrCmpi(br->DeviceName, devicename) == 0)
					{
						if (br->Bridge != NULL)
						{
							BrFreeBridge(br->Bridge);
							br->Bridge = NULL;
						}

						Delete(c->LocalBridgeList, br);
						Free(br);

						ret = true;
						break;
					}
				}
			}
		}
		UnlockList(c->LocalBridgeList);
	}
	UnlockList(c->HubList);

	return ret;
}

void AddLocalBridge(CEDAR *c, char *hubname, char *devicename, bool local, bool monitor, bool tapmode, char *tapaddr, bool limit_broadcast)
{
	UINT i;
	HUB *h = NULL;
	LOCALBRIDGE *br = NULL;
	if (c == NULL || hubname == NULL || devicename == NULL)
	{
		return;
	}

	tapmode = false;

	LockList(c->HubList);
	{
		LockList(c->LocalBridgeList);
		{
			bool exists = false;

			for (i = 0;i < LIST_NUM(c->LocalBridgeList);i++)
			{
				LOCALBRIDGE *br = LIST_DATA(c->LocalBridgeList, i);
				if (StrCmpi(br->DeviceName, devicename) == 0)
				{
					if (StrCmpi(br->HubName, hubname) == 0)
					{
						if (br->TapMode == tapmode)
						{
							exists = true;
						}
					}
				}
			}

			if (exists == false)
			{
				br = ZeroMalloc(sizeof(LOCALBRIDGE));
				StrCpy(br->HubName, sizeof(br->HubName), hubname);
				StrCpy(br->DeviceName, sizeof(br->DeviceName), devicename);
				br->Bridge = NULL;
				br->Local = local;
				br->TapMode = tapmode;
				br->LimitBroadcast = limit_broadcast;
				br->Monitor = monitor;
				if (br->TapMode)
				{
					if (tapaddr != NULL && IsZero(tapaddr, 6) == false)
					{
						Copy(br->TapMacAddress, tapaddr, 6);
					}
					else
					{
						GenMacAddress(br->TapMacAddress);
					}
				}

				Add(c->LocalBridgeList, br);

				for (i = 0;i < LIST_NUM(c->HubList);i++)
				{
					HUB *hub = LIST_DATA(c->HubList, i);
					if (StrCmpi(hub->Name, br->HubName) == 0)
					{
						h = hub;
						AddRef(h->ref);
						break;
					}
				}
			}
		}
		UnlockList(c->LocalBridgeList);
	}
	UnlockList(c->HubList);

	if (h != NULL && br != NULL)
	{
		Lock(h->lock_online);
		{
			if (h->Offline == false)
			{
				LockList(c->LocalBridgeList);
				{
					if (IsInList(c->LocalBridgeList, br))
					{
						if (br->Bridge == NULL)
						{
							br->Bridge = BrNewBridge(h, br->DeviceName, NULL, br->Local, br->Monitor, br->TapMode, br->TapMacAddress, br->LimitBroadcast, br);
						}
					}
				}
				UnlockList(c->LocalBridgeList);
			}
		}
		Unlock(h->lock_online);
	}

	ReleaseHub(h);
}

void InitLocalBridgeList(CEDAR *c)
{
	if (c == NULL)
	{
		return;
	}

	c->LocalBridgeList = NewList(NULL);
}

void FreeLocalBridgeList(CEDAR *c)
{
	UINT i;
	if (c == NULL)
	{
		return;
	}

	for (i = 0;i < LIST_NUM(c->LocalBridgeList);i++)
	{
		LOCALBRIDGE *br = LIST_DATA(c->LocalBridgeList, i);
		Free(br);
	}

	ReleaseList(c->LocalBridgeList);
	c->LocalBridgeList = NULL;
}

void BrBridgeThread(THREAD *thread, void *param)
{
	BRIDGE *b;
	CONNECTION *c;
	SESSION *s;
	HUB *h;
	char name[MAX_SIZE];
	if (thread == NULL || param == NULL)
	{
		return;
	}

	b = (BRIDGE *)param;

	c = NewServerConnection(b->Cedar, NULL, thread);
	c->Protocol = CONNECTION_HUB_BRIDGE;

	s = NewServerSession(b->Cedar, c, b->Hub, BRIDGE_USER_NAME, b->Policy);
	HLog(b->Hub, "LH_START_BRIDGE", b->Name, s->Name);
	StrCpy(name, sizeof(name), b->Name);
	h = b->Hub;
	AddRef(h->ref);
	s->BridgeMode = true;
	s->Bridge = b;
	c->Session = s;
	ReleaseConnection(c);

	s->Username = CopyStr(BRIDGE_USER_NAME_PRINT);

	b->Session = s;
	AddRef(s->ref);

	NoticeThreadInit(thread);

	SessionMain(s);

	HLog(h, "LH_STOP_BRIDGE", name);

	ReleaseHub(h);

	ReleaseSession(s);
}

void BrFreeBridge(BRIDGE *b)
{
	if (b == NULL)
	{
		return;
	}

	if (b->ParentLocalBridge != NULL)
	{
		b->ParentLocalBridge = NULL;
	}

	StopSession(b->Session);
	ReleaseSession(b->Session);

	Free(b);
}

BRIDGE *BrNewBridge(HUB *h, char *name, POLICY *p, bool local, bool monitor, bool tapmode, char *tapaddr, bool limit_broadcast, LOCALBRIDGE *parent_local_bridge)
{
	BRIDGE *b;
	POLICY *policy;
	THREAD *t;
	if (h == NULL || name == NULL || parent_local_bridge == NULL)
	{
		return NULL;
	}

	if (p == NULL)
	{
		policy = ClonePolicy(GetDefaultPolicy());
	}
	else
	{
		policy = ClonePolicy(p);
	}

	b = ZeroMalloc(sizeof(BRIDGE));
	b->Cedar = h->Cedar;
	b->Hub = h;
	StrCpy(b->Name, sizeof(b->Name), name);
	b->Policy = policy;
	b->Local = local;
	b->Monitor = monitor;
	b->TapMode = tapmode;
	b->LimitBroadcast = limit_broadcast;
	b->ParentLocalBridge = parent_local_bridge;

	if (b->TapMode)
	{
		if (tapaddr != NULL && IsZero(tapaddr, 6) == false)
		{
			Copy(b->TapMacAddress, tapaddr, 6);
		}
		else
		{
			GenMacAddress(b->TapMacAddress);
		}
	}

	if (monitor)
	{
		policy->MonitorPort = true;
	}

	if (b->LimitBroadcast == false)
	{
		policy->NoBroadcastLimiter = true;
	}

	t = NewThread(BrBridgeThread, b);
	WaitThreadInit(t);
	ReleaseThread(t);

	return b;
}

