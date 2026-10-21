// Bridge.c
// Ethernet Bridge Program (Local Bridge)

#include "Bridge.h"
#include "BridgeWin32.h"

#include "Connection.h"
#include "Hub.h"
#include "SeLowUser.h"
#include "Session.h"

#include "Mayaqua/Memory.h"
#include "Mayaqua/Microsoft.h"
#include "Mayaqua/Object.h"
#include "Mayaqua/Str.h"
#include "Mayaqua/TcpIp.h"
#include "Mayaqua/Tick64.h"

UINT GetEthDeviceHash()
{
	MS_ADAPTER_LIST *a = MsCreateAdapterList();
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

// Whether this machine can run a Local Bridge. SeLow must exist for this OS and architecture
// (SuIsSupportedOs: no claim where no SeLow driver package exists, such as arm64), and then be
// usable now or installable by this elevated process (FND-173)
bool IsBridgeSupported()
{
	if (SuIsSupportedOs() == false)
	{
		return false;
	}

	return Win32EthIsSuSupported() || MsIsAdmin();
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

void AddLocalBridge(CEDAR *c, char *hubname, char *devicename, bool local, bool monitor, bool limit_broadcast)
{
	UINT i;
	HUB *h = NULL;
	LOCALBRIDGE *br = NULL;
	if (c == NULL || hubname == NULL || devicename == NULL)
	{
		return;
	}

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
						exists = true;
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
				br->LimitBroadcast = limit_broadcast;
				br->Monitor = monitor;

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
							br->Bridge = BrNewBridge(h, br);
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

static void BrBridgeThread(THREAD *thread, void *param)
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

BRIDGE *BrNewBridge(HUB *h, LOCALBRIDGE *parent_local_bridge)
{
	BRIDGE *b;
	POLICY *policy;
	THREAD *t;
	if (h == NULL || parent_local_bridge == NULL)
	{
		return NULL;
	}

	policy = ClonePolicy(GetDefaultPolicy());

	b = ZeroMalloc(sizeof(BRIDGE));
	b->Cedar = h->Cedar;
	b->Hub = h;
	StrCpy(b->Name, sizeof(b->Name), parent_local_bridge->DeviceName);
	b->Policy = policy;
	b->ParentLocalBridge = parent_local_bridge;

	if (parent_local_bridge->Monitor)
	{
		policy->MonitorPort = true;
	}

	if (parent_local_bridge->LimitBroadcast == false)
	{
		policy->NoBroadcastLimiter = true;
	}

	t = NewThread(BrBridgeThread, b);
	WaitThreadInit(t);
	ReleaseThread(t);

	return b;
}

// Sends the blocks queued on a Local Bridge connection to its Ethernet device
void BrSendBlocks(CONNECTION *c)
{
	SESSION *s;
	HUB *hub;
	BRIDGE *b;
	if (c == NULL)
	{
		return;
	}

	s = c->Session;
	hub = s->Hub;
	b = s->Bridge;

	if (b != NULL)
	{
		if (b->Active)
		{
			BLOCK *block;
			UINT num_packet = c->SendBlocks->num_item;

			if (num_packet != 0)
			{
				void **datas = Malloc(sizeof(void *) * num_packet);
				UINT *sizes = Malloc(sizeof(UINT) * num_packet);
				UINT i;

				i = 0;
				while (block = GetNext(c->SendBlocks))
				{
					if (hub != NULL && hub->Option->DisableUdpFilterForLocalBridgeNic == false &&
						b->Eth != NULL && IsDhcpPacketForSpecificMac(block->Buf, block->Size, b->Eth->MacAddress))
					{
						datas[i] = NULL;
						sizes[i] = 0;

						Free(block->Buf);
					}
					else
					{
						datas[i] = block->Buf;
						sizes[i] = block->Size;
					}

					c->CurrentSendQueueSize -= block->Size;
					Free(block);
					i++;
				}

				EthPutPackets(b->Eth, num_packet, datas, sizes);

				Free(datas);
				Free(sizes);
			}
		}
	}
}

// Takes the frames that the Ethernet device of a Local Bridge connection has received, or
// opens the device again while the bridge is not active
void BrReceiveBlocks(CONNECTION *c, CANCEL *c1, CANCEL *c2)
{
	SESSION *s;
	HUB *hub;
	BRIDGE *b;
	bool no_spinlock_for_delay = false;
	if (c == NULL)
	{
		return;
	}

	s = c->Session;
	hub = s->Hub;
	b = s->Bridge;

	if (hub != NULL)
	{
		no_spinlock_for_delay = hub->Option->NoSpinLockForPacketDelay;
	}

	if (b->Active)
	{
		void *data;
		UINT ret;
		UINT num = 0;
		bool device_changed = false;
		UINT time = SELECT_TIME;
		UINT next_delay_packet_diff = 0;
		UINT num_delayed = 0;

		next_delay_packet_diff = GetNextDelayedPacketTickDiff(s);
		time = MIN(time, next_delay_packet_diff);
		num_delayed = LIST_NUM(s->DelayedPacketList);

		// Frames left in the bridge's receive buffer by the last drain do not
		// signal c2, so take them without waiting
		if (EthHasPendingFrames(b->Eth))
		{
			Select(NULL, 0, c1, c2);
		}
		else if (no_spinlock_for_delay || time >= 50 || num_delayed == false)
		{
			Select(NULL, (num_delayed == 0 ? time : (time > 100 ? (time - 100) : 1)), c1, c2);
		}
		else
		{
			YieldCpu();
		}

		if ((b->LastNumDeviceCheck + BRIDGE_NUM_DEVICE_CHECK_SPAN) <= Tick64())
		{
			device_changed = (b->LastNumDevice != GetEthDeviceHash());
			b->LastNumDeviceCheck = Tick64();
		}

		while (true)
		{
			if (device_changed)
			{
				ret = INFINITE;
			}
			else
			{
				ret = EthGetPacket(b->Eth, &data);
			}

			if (ret == INFINITE)
			{
				CloseEth(b->Eth);
				b->Eth = NULL;
				b->Active = false;
				ReleaseCancel(s->Cancel2);
				s->Cancel2 = NULL;

				HLog(s->Hub, "LH_BRIDGE_2", s->Name, b->Name);

				break;
			}
			else if (ret == 0)
			{
				break;
			}
			else
			{
				if (hub != NULL && hub->Option->DisableUdpFilterForLocalBridgeNic == false &&
					b->Eth != NULL && IsDhcpPacketForSpecificMac(data, ret, b->Eth->MacAddress))
				{
					Free(data);
				}
				else
				{
					BLOCK *block = NewBlock(data, ret, 0);

					if (block->Size > MAX_PACKET_SIZE)
					{
						FreeBlock(block);
					}
					else
					{
						InsertReceivedBlockToQueue(c, block);
					}
					num++;
					if (num >= MAX_SEND_SOCKET_QUEUE_NUM)
					{
						break;
					}
				}
			}
		}
	}
	else
	{
		ETH *e;
		Select(NULL, SELECT_TIME, c1, NULL);

		if (b->LastBridgeTry == 0 || (b->LastBridgeTry + BRIDGE_TRY_SPAN) <= Tick64())
		{
			b->LastBridgeTry = Tick64();

			e = OpenEth(b->Name);
			if (e != NULL)
			{
				b->Eth = e;
				b->Active = true;
				b->LastNumDeviceCheck = Tick64();
				b->LastNumDevice = GetEthDeviceHash();

				if (IsEmptyStr(e->Title) == false)
				{
					StrCpy(b->Name, sizeof(b->Name), e->Title);

					if (b->ParentLocalBridge != NULL)
					{
						StrCpy(b->ParentLocalBridge->DeviceName, sizeof(b->ParentLocalBridge->DeviceName), e->Title);
					}
				}


				HLog(c->Session->Hub, "LH_BRIDGE_1", c->Session->Name, b->Name);

				s->Cancel2 = EthGetCancel(b->Eth);
			}
		}
	}
}

