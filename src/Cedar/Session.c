// Session.c
// Session Manager

#include "Session.h"

#include "Account.h"
#include "BridgeWin32.h"
#include "Connection.h"
#include "Hub.h"
#include "Link.h"
#include "Protocol.h"
#include "Server.h"
#include "UdpAccel.h"

#include "Mayaqua/Internat.h"
#include "Mayaqua/Kernel.h"
#include "Mayaqua/Mayaqua.h"
#include "Mayaqua/Memory.h"
#include "Mayaqua/Object.h"
#include "Mayaqua/Str.h"
#include "Mayaqua/Table.h"
#include "Mayaqua/TcpIp.h"
#include "Mayaqua/Tick64.h"
#include "Mayaqua/Win32.h"

void SessionMain(SESSION *s)
{
	CONNECTION *c;
	POLICY *policy;
	UINT64 now;
	UINT i = 0;
	PACKET_ADAPTER *pa;
	bool pa_inited = false;
	UINT packet_size;
	void *packet;
	bool packet_put;
	bool pa_fail = false;
	UINT test = 0;
	bool update_hub_last_comm = false;
	UINT err = ERR_SESSION_TIMEOUT;
	UINT64 next_black_list_check = 0;
	UINT64 next_update_hub_last_comm = 0;
	bool block_all_packets = false;
	UINT64 next_check_block_all_packets = 0;
	TRAFFIC t;
	bool is_server_session = false;
	bool lock_receive_blocks_queue = false;

	if (s == NULL)
	{
		return;
	}

	BinToStr(s->SessionKeyStr, sizeof(s->SessionKeyStr), s->SessionKey, sizeof(s->SessionKey));

	s->CurrentRetryCount = 0;
	s->ConnectSucceed = true;
	s->SessionTimeOuted = false;
	s->NumDisconnected = 0;

	c = s->Connection;
	policy = s->Policy;

	pa = s->PacketAdapter;
	if (pa->Init(s) == false)
	{
		if (s->VLanDeviceErrorCount >= 2)
		{
			s->ForceStopFlag = true;
		}
		else
		{
			s->VLanDeviceErrorCount++;
		}
		err = ERR_DEVICE_DRIVER_ERROR;
		goto CLEANUP;
	}
	pa_inited = true;

	if (s->BridgeMode == false)
	{
		s->Cancel2 = pa->GetCancel(s);
	}
	else
	{
		CANCEL *c = pa->GetCancel(s);
		CANCEL *old = s->Cancel1;
		s->Cancel1 = c;
		ReleaseCancel(old);
	}

	s->RetryFlag = false;

	s->LastCommTime = Tick64();
	if (s->ServerMode == false)
	{
		s->NextConnectionTime = Tick64() + (UINT64)((UINT64)s->ClientOption->AdditionalConnectionInterval * (UINT64)1000);
	}

	s->NumConnectionsEstablished++;
	s->CurrentConnectionEstablishTime = Tick64();
	if (s->FirstConnectionEstablisiedTime == 0) /* !!! Do not correct the spelling to keep the backward protocol compatibility !!!  */
	{
		s->FirstConnectionEstablisiedTime = Tick64(); /* !!! Do not correct the spelling to keep the backward protocol compatibility !!!  */
	}

	s->LastIncrementTraffic = Tick64();

	c->Err = ERR_SESSION_TIMEOUT;
	s->VLanDeviceErrorCount = 0;

	s->LastTryAddConnectTime = Tick64();

	if (policy != NULL)
	{
		if (policy->MonitorPort)
		{
			s->IsMonitorMode = true;
		}

		if (policy->NoRouting == false || policy->NoBridge == false)
		{
			s->IsBridgeMode = true;
		}
	}

	is_server_session = s->ServerMode;

	lock_receive_blocks_queue = s->LinkModeServer;

	now = Tick64();

	while (true)
	{
		Zero(&t, sizeof(t));

		if (next_update_hub_last_comm == 0 ||
			(next_update_hub_last_comm <= now))
		{
			next_update_hub_last_comm = now + 1000;

			if (s->Hub != NULL)
			{
				if (update_hub_last_comm)
				{
					Lock(s->Hub->lock);
					{
						s->Hub->LastCommTime = SystemTime64();
					}
					Unlock(s->Hub->lock);

					update_hub_last_comm = false;
				}
			}
		}

		if (is_server_session && s->LinkModeServer == false && s->BridgeMode == false)
		{
			if (s->Hub != NULL && s->Hub->ForceDisableComm)
			{
				err = ERR_SERVER_CANT_ACCEPT;
				pa_fail = true;
			}
		}

		if (is_server_session == false)
		{
			if (GetGlobalServerFlag(GSF_DISABLE_SESSION_RECONNECT) == false)
			{
				ClientAdditionalConnectChance(s);
			}
		}

		ConnectionReceive(c, s->Cancel1, s->Cancel2);

		now = Tick64();

		if (s->UseUdpAcceleration && s->UdpAccel != NULL && s->UdpAccel->FatalError)
		{
			// A send error on the UDP acceleration socket is fatal
			err = ERR_DISCONNECTED;
			pa_fail = true;
		}

		if (lock_receive_blocks_queue)
		{
			LockQueue(c->ReceivedBlocks);
		}
		{
			BLOCK *b;
			packet_put = false;
			while (true)
			{
				b = GetNext(c->ReceivedBlocks);
				if (b == NULL)
				{
					break;
				}

				PROBE_DATA2("GetNext", b->Buf, b->Size);

				update_hub_last_comm = true;

				if (b->Size >= 14)
				{
					if (b->Buf[0] & 0x01)
					{
						if (is_server_session == false)
						{
							t.Recv.BroadcastCount++;
							t.Recv.BroadcastBytes += (UINT64)b->Size;
						}
						else
						{
							t.Send.BroadcastCount++;
							t.Send.BroadcastBytes += (UINT64)b->Size;
						}
					}
					else
					{
						if (is_server_session == false)
						{
							t.Recv.UnicastCount++;
							t.Recv.UnicastBytes += (UINT64)b->Size;
						}
						else
						{
							t.Send.UnicastCount++;
							t.Send.UnicastBytes += (UINT64)b->Size;
						}
					}
				}

				packet_put = true;
				PROBE_DATA2("pa->PutPacket", b->Buf, b->Size);
				if (pa->PutPacket(s, b->Buf, b->Size) == false)
				{
					pa_fail = true;
					err = ERR_DEVICE_DRIVER_ERROR;
					Free(b->Buf);
				}
				Free(b);
			}

			if (true)
			{
				PROBE_DATA2("pa->PutPacket", NULL, 0);
				if (pa->PutPacket(s, NULL, 0) == false)
				{
					pa_fail = true;
					err = ERR_DEVICE_DRIVER_ERROR;
				}
			}
		}
		if (lock_receive_blocks_queue)
		{
			UnlockQueue(c->ReceivedBlocks);
		}

		{
			UINT i, max_num = MAX_SEND_SOCKET_QUEUE_NUM;
			i = 0;
			while (packet_size = pa->GetNextPacket(s, &packet))
			{
				BLOCK *b;
				if (packet_size == INFINITE)
				{
					err = ERR_DEVICE_DRIVER_ERROR;
					pa_fail = true;
					break;
				}

				update_hub_last_comm = true;

				if ((c->CurrentSendQueueSize > MAX_BUFFERING_PACKET_SIZE) ||
					block_all_packets)
				{
					Free(packet);
				}
				else
				{
					bool priority;
					QUEUE *q = NULL;
					if (packet_size >= 14)
					{
						UCHAR *buf = (UCHAR *)packet;
						if (buf[0] & 0x01)
						{
							if (is_server_session == false)
							{
								t.Send.BroadcastCount++;
								t.Send.BroadcastBytes += (UINT64)packet_size;
							}
							else
							{
								t.Recv.BroadcastCount++;
								t.Recv.BroadcastBytes += (UINT64)packet_size;
							}
						}
						else
						{
							if (is_server_session == false)
							{
								t.Send.UnicastCount++;
								t.Send.UnicastBytes += (UINT64)packet_size;
							}
							else
							{
								t.Recv.UnicastCount++;
								t.Recv.UnicastBytes += (UINT64)packet_size;
							}
						}
					}
					priority = IsPriorityHighestPacketForQoS(packet, packet_size);

					b = NewBlock(packet, packet_size, s->UseCompress ? 1 : 0);
					b->PriorityQoS = priority;

					if (b->PriorityQoS && c->Protocol == CONNECTION_TCP && s->QoS)
					{
						q = c->SendBlocks2;
					}
					else
					{
						q = c->SendBlocks;
					}

					if (q->num_item > MAX_STORED_QUEUE_NUM)
					{
						q = NULL;
					}

					if (q != NULL)
					{
						c->CurrentSendQueueSize += b->Size;
						InsertQueue(q, b);
					}
					else
					{
						FreeBlock(b);
					}
				}

				if ((i % 16) == 0)
				{
					int diff = ((int)c->CurrentSendQueueSize) - ((int)c->LastPacketQueueSize);
					CedarAddCurrentTcpQueueSize(c->Cedar, diff);
					c->LastPacketQueueSize = c->CurrentSendQueueSize;
				}

				i++;
				if (i >= max_num)
				{
					break;
				}
			}
		}

		AddTrafficForSession(s, &t);

		if (true)
		{
			int diff = ((int)c->CurrentSendQueueSize) - ((int)c->LastPacketQueueSize);
			CedarAddCurrentTcpQueueSize(c->Cedar, diff);
			c->LastPacketQueueSize = c->CurrentSendQueueSize;
		}

		now = Tick64();

		ConnectionSend(c, now);

		if (s->Halt)
		{
			if (s->ForceStopFlag)
			{
				err = ERR_USER_CANCEL;
			}
			break;
		}

		// Count the login only after the session has lasted 30 seconds,
		// so DoS attempts and failed connections do not raise the counters.
		if (s->NumLoginIncrementTick != 0 && s->NumLoginIncrementTick <= now)
		{
			s->NumLoginIncrementTick = 0;

			if (s->NumLoginIncrementHubObject != NULL)
			{
				s->NumLoginIncrementHubObject->NumLogin++;
			}

			if (s->NumLoginIncrementUserObject != NULL)
			{
				s->NumLoginIncrementUserObject->NumLogin++;
			}
		}

		if (is_server_session)
		{
			if ((s->LastIncrementTraffic + INCREMENT_TRAFFIC_INTERVAL) <= now)
			{
				IncrementUserTraffic(s->Hub, s->UserNameReal, s);
				s->LastIncrementTraffic = now;
			}
		}

		if (s->LinkModeServer == false && s->BridgeMode == false)
		{
			bool timeouted = false;

			if ((now > s->LastCommTime) && ((now - s->LastCommTime) >= ((UINT64)s->Timeout)))
			{
				timeouted = true;
				WHERE;
			}

			if (c->Protocol == CONNECTION_TCP)
			{
				if (GetGlobalServerFlag(GSF_DISABLE_SESSION_RECONNECT))
				{
					UINT num_tcp_connections = Count(c->CurrentNumConnection);

					if (num_tcp_connections == 0)
					{
						timeouted = true;
					}
				}
			}

			if (is_server_session == false && s->ClientOption != NULL && s->ClientOption->ConnectionDisconnectSpan == 0)
			{
				if (LIST_NUM(s->Connection->Tcp->TcpSockList) < s->MaxConnection)
				{
					if ((s->LastTryAddConnectTime +
						(UINT64)(s->ClientOption->AdditionalConnectionInterval * 1000 * 2 + CONNECTING_TIMEOUT * 2))
						<= Tick64())
					{
						timeouted = true;
						WHERE;
					}

					UINT num_tcp_conn = LIST_NUM(s->Connection->Tcp->TcpSockList);
					UINT max_conn = s->ClientOption->MaxConnection;

					if ((s->CurrentConnectionEstablishTime +
						(UINT64)(num_tcp_conn * s->ClientOption->AdditionalConnectionInterval * 1000 * 2 + CONNECTING_TIMEOUT * 2))
						<= Tick64())
					{
						if (s->ClientOption->BindLocalPort != 0 || num_tcp_conn == 0)
						{
							timeouted = true;
							WHERE;
						}
					}

				}
			}

			if (timeouted)
			{
				s->SessionTimeOuted = true;
				err = ERR_SESSION_TIMEOUT;
			}
		}

		if (pa_fail || s->SessionTimeOuted)
		{
			s->Halt = true;
			s->RetryFlag = true;
			break;
		}
	}

CLEANUP:

	if (s->ServerMode)
	{
		IncrementUserTraffic(s->Hub, s->UserNameReal, s);

		DelSession(s->Hub, s);
	}

	s->ConnectSucceed = false;

	if (s->Connection)
	{
		int diff =  -((int)s->Connection->LastTcpQueueSize);
		s->Connection->LastTcpQueueSize = 0;
		s->Connection->Halt = true;
		CedarAddCurrentTcpQueueSize(s->Cedar, diff);

		diff = ((int)c->CurrentSendQueueSize) - ((int)c->LastPacketQueueSize);
		CedarAddCurrentTcpQueueSize(c->Cedar, diff);
		c->LastPacketQueueSize = c->CurrentSendQueueSize;
	}

	if (pa_inited)
	{
		pa->Free(s);
	}

	if (s->ServerMode == false)
	{
		StopAllAdditionalConnectThread(s->Connection);
	}

	if (s->BridgeMode)
	{
		if (s->Bridge->Active)
		{
			CloseEth(s->Bridge->Eth);
			s->Bridge->Eth = NULL;
		}
	}

	if (s->Cancel2 != NULL)
	{
		ReleaseCancel(s->Cancel2);
		s->Cancel2 = NULL;
	}

	EndTunnelingMode(c);

	c->Err = err;
}

UINT GetNextDelayedPacketTickDiff(SESSION *s)
{
	UINT i;
	UINT ret = 0x7fffffff;
	UINT64 now;
	if (s == NULL)
	{
		return 0;
	}

	if (LIST_NUM(s->DelayedPacketList) >= 1)
	{
		now = TickHighres64();

		LockList(s->DelayedPacketList);
		{
			for (i = 0;i < LIST_NUM(s->DelayedPacketList);i++)
			{
				PKT *p = LIST_DATA(s->DelayedPacketList, i);
				UINT64 t = p->DelayedForwardTick;
				UINT d = 0x7fffffff;

				if (now >= t)
				{
					d = 0;
				}
				else
				{
					d = (UINT)(t - now);
				}

				ret = MIN(ret, d);
			}
		}
		UnlockList(s->DelayedPacketList);
	}

	return ret;
}

bool IsPriorityHighestPacketForQoS(void *data, UINT size)
{
	UCHAR *buf;
	if (data == NULL)
	{
		return false;
	}

	buf = (UCHAR *)data;
	if (size >= 16)
	{
		if (buf[12] == 0x08 && buf[13] == 0x00 && buf[15] != 0x00 && buf[15] != 0x08)
		{
			return true;
		}

		if (size >= 34 && size <= 128)
		{
			if (buf[12] == 0x08 && buf[13] == 0x00 && buf[23] == 0x01)
			{
				return true;
			}
		}
	}

	return false;
}

void IncrementUserTraffic(HUB *hub, char *username, SESSION *s)
{
	TRAFFIC report_traffic;
	if (hub == NULL || username == NULL || s == NULL)
	{
		return;
	}

	Lock(s->TrafficLock);
	{
		report_traffic.Send.BroadcastBytes =
			s->Traffic->Send.BroadcastBytes - s->OldTraffic->Send.BroadcastBytes;
		report_traffic.Send.BroadcastCount =
			s->Traffic->Send.BroadcastCount - s->OldTraffic->Send.BroadcastCount;
		report_traffic.Send.UnicastBytes =
			s->Traffic->Send.UnicastBytes - s->OldTraffic->Send.UnicastBytes;
		report_traffic.Send.UnicastCount =
			s->Traffic->Send.UnicastCount - s->OldTraffic->Send.UnicastCount;
		report_traffic.Recv.BroadcastBytes =
			s->Traffic->Recv.BroadcastBytes - s->OldTraffic->Recv.BroadcastBytes;
		report_traffic.Recv.BroadcastCount =
			s->Traffic->Recv.BroadcastCount - s->OldTraffic->Recv.BroadcastCount;
		report_traffic.Recv.UnicastBytes =
			s->Traffic->Recv.UnicastBytes - s->OldTraffic->Recv.UnicastBytes;
		report_traffic.Recv.UnicastCount =
			s->Traffic->Recv.UnicastCount - s->OldTraffic->Recv.UnicastCount;
		Copy(s->OldTraffic, s->Traffic, sizeof(TRAFFIC));

		AcLock(hub);
		{
			USER *u = AcGetUser(hub, username);
			if (u != NULL)
			{
				Lock(u->lock);
				{
					AddTraffic(u->Traffic, &report_traffic);
				}
				Unlock(u->lock);
				if (u->Group != NULL)
				{
					Lock(u->Group->lock);
					{
						AddTraffic(u->Group->Traffic, &report_traffic);
					}
					Unlock(u->Group->lock);
				}
				ReleaseUser(u);
			}
		}
		AcUnlock(hub);
	}
	Unlock(s->TrafficLock);
}

void AddTrafficForSession(SESSION *s, TRAFFIC *t)
{
	HUB *h;
	TRAFFIC t2;
	if (s == NULL || t == NULL)
	{
		return;
	}

	Lock(s->TrafficLock);
	{
		AddTraffic(s->Traffic, t);
	}
	Unlock(s->TrafficLock);

	if (s->ServerMode)
	{
		Copy(&t2.Recv, &t->Send, sizeof(TRAFFIC_ENTRY));
		Copy(&t2.Send, &t->Recv, sizeof(TRAFFIC_ENTRY));
		Lock(s->Cedar->TrafficLock);
		{
			AddTraffic(s->Cedar->Traffic, &t2);
		}
		Unlock(s->Cedar->TrafficLock);

		h = s->Hub;
		Lock(h->TrafficLock);
		{
			AddTraffic(h->Traffic, &t2);
		}
		Unlock(h->TrafficLock);
	}
}

void ClientAdditionalConnectChance(SESSION *s)
{
	if (s == NULL)
	{
		return;
	}

	if (s->ServerMode)
	{
		return;
	}
	if (s->Connection->Protocol != CONNECTION_TCP)
	{
		return;
	}
	while (true)
	{
		if (s->Halt)
		{
			return;
		}
		if (Count(s->Connection->CurrentNumConnection) < s->MaxConnection)
		{
			UINT64 now = Tick64();

			if (s->NextConnectionTime == 0 ||
				s->ClientOption->AdditionalConnectionInterval == 0 ||
				(s->NextConnectionTime <= now))
			{
				s->NextConnectionTime = now + ((UINT64)s->ClientOption->AdditionalConnectionInterval * (UINT64)1000);
				SessionAdditionalConnect(s);
			}
			else
			{
				break;
			}
		}
		else
		{
			break;
		}
	}
}

void FreePacketAdapter(PACKET_ADAPTER *pa)
{
	if (pa == NULL)
	{
		return;
	}

	Free(pa);
}

PACKET_ADAPTER *NewPacketAdapter(PA_INIT *init, PA_GETCANCEL *getcancel, PA_GETNEXTPACKET *getnext,
								 PA_PUTPACKET *put, PA_FREE *free)
{
	PACKET_ADAPTER *pa;
	if (init == NULL || getcancel == NULL || getnext == NULL || put == NULL || free == NULL)
	{
		return NULL;
	}

	pa = ZeroMalloc(sizeof(PACKET_ADAPTER));

	pa->Init = init;
	pa->Free = free;
	pa->GetCancel = getcancel;
	pa->GetNextPacket = getnext;
	pa->PutPacket = put;

	return pa;
}

void ClientAdditionalThread(THREAD *t, void *param)
{
	SESSION *s;
	CONNECTION *c;
	if (t == NULL || param == NULL)
	{
		return;
	}

	s = (SESSION *)param;

	s->LastTryAddConnectTime = Tick64();

	c = s->Connection;
	Inc(c->CurrentNumConnection);
	LockList(c->ConnectingThreads);
	{
		Add(c->ConnectingThreads, t);
		AddRef(t->ref);
	}
	UnlockList(c->ConnectingThreads);

	NoticeThreadInit(t);

	Debug("Additional Connection #%u\n", Count(c->CurrentNumConnection));

	if (ClientAdditionalConnect(c, t) == false)
	{
		Dec(c->CurrentNumConnection);

		if (c->AdditionalConnectionFailedCounter == 0)
		{
			c->LastCounterResetTick = Tick64();
		}

		c->AdditionalConnectionFailedCounter++;

		if ((c->LastCounterResetTick + (UINT64)ADDITIONAL_CONNECTION_COUNTER_RESET_INTERVAL) <= Tick64())
		{
			c->AdditionalConnectionFailedCounter = 0;
			c->LastCounterResetTick = Tick64();
		}
	}
	else
	{
		s->LastTryAddConnectTime = Tick64();
		c->AdditionalConnectionFailedCounter = 0;
		c->LastCounterResetTick = Tick64();
	}

	LockList(c->ConnectingThreads);
	{
		if (Delete(c->ConnectingThreads, t))
		{
			ReleaseThread(t);
		}
	}
	UnlockList(c->ConnectingThreads);
	ReleaseSession(s);
}

void SessionAdditionalConnect(SESSION *s)
{
	THREAD *t;
	if (s == NULL)
	{
		return;
	}

	AddRef(s->ref);
	t = NewThread(ClientAdditionalThread, (void *)s);
	WaitThreadInit(t);
	ReleaseThread(t);
}

bool SessionConnect(SESSION *s)
{
	CONNECTION *c;
	bool ret = false;
	if (s == NULL)
	{
		return false;
	}

	s->ClientStatus = CLIENT_STATUS_CONNECTING;

	Lock(s->lock);
	{
		s->Err = ERR_NO_ERROR;
		if (s->Policy != NULL)
		{
			Free(s->Policy);
			s->Policy = NULL;
		}
	}
	Unlock(s->lock);

	s->CancelConnect = false;

	c = NewClientConnection(s);
	s->Connection = c;

	ret = ClientConnect(c);
	s->Err = c->Err;

	s->CancelConnect = false;

	s->Connection = NULL;
	ReleaseConnection(c);

	Lock(s->lock);
	{
		if (s->Policy != NULL)
		{
			Free(s->Policy);
			s->Policy = NULL;
		}
	}
	Unlock(s->lock);

	return ret;
}

void StopSession(SESSION *s)
{
	StopSessionEx(s, false);
}
void StopSessionEx(SESSION *s, bool no_wait)
{
	if (s == NULL)
	{
		return;
	}

	s->UserCanceled = true;
	s->CancelConnect = true;
	s->Halt = true;

	Cancel(s->Cancel1);

	Set(s->HaltEvent);

	if (s->Connection)
	{
		CONNECTION *c = s->Connection;
		AddRef(c->ref);
		StopConnection(c, no_wait);
		ReleaseConnection(c);
	}

	if (no_wait == false)
	{
		while (true)
		{
			s->ForceStopFlag = true;
			s->Halt = true;
			if (WaitThread(s->Thread, 20))
			{
				break;
			}
		}
	}
	else
	{
		s->ForceStopFlag = true;
		s->Halt = true;
	}
}

void CleanupSession(SESSION *s)
{
	if (s == NULL)
	{
		return;
	}

	if (s->DelayedPacketList != NULL)
	{
		UINT i;
		for (i = 0;i < LIST_NUM(s->DelayedPacketList);i++)
		{
			PKT *p = LIST_DATA(s->DelayedPacketList, i);

			Free(p->PacketData);
			FreePacket(p);
		}

		ReleaseList(s->DelayedPacketList);
	}

	if (s->ClientOption != NULL)
	{
		Free(s->ClientOption);
	}

	if (s->ClientAuth != NULL)
	{
		if (s->ClientAuth->ClientX != NULL)
		{
			FreeX(s->ClientAuth->ClientX);
		}
		if (s->ClientAuth->ClientX != NULL)
		{
			FreeK(s->ClientAuth->ClientK);
		}
		Free(s->ClientAuth);
	}

	if (s->SslOption != NULL)
	{
		FreeXList(s->SslOption->CaList);
		FreeX(s->SslOption->SavedCert);
		Free(s->SslOption);
	}

	FreeTraffic(s->Traffic);
	Free(s->Name);

	if (s->Thread != NULL)
	{
		ReleaseThread(s->Thread);
	}

	DeleteLock(s->lock);

	ReleaseEvent(s->HaltEvent);

	if (s->Cancel1)
	{
		ReleaseCancel(s->Cancel1);
	}

	if (s->Cancel2)
	{
		ReleaseCancel(s->Cancel2);
	}

	if (s->Policy)
	{
		Free(s->Policy);
	}

	if (s->Connection)
	{
		ReleaseConnection(s->Connection);
	}

	Free(s->Username);

	if (s->PacketAdapter)
	{
		FreePacketAdapter(s->PacketAdapter);
	}

	if (s->OldTraffic != NULL)
	{
		FreeTraffic(s->OldTraffic);
	}

	DeleteLock(s->TrafficLock);

	if (s->CancelList != NULL)
	{
		ReleaseCancelList(s->CancelList);
	}

	if (s->Client_Message != NULL)
	{
		Free(s->Client_Message);
	}

	DeleteCounter(s->LoggingRecordCount);

	Free(s);
}

void ReleaseSession(SESSION *s)
{
	if (s == NULL)
	{
		return;
	}

	if (Release(s->ref) == 0)
	{
		CleanupSession(s);
	}
}

void PrintSessionTotalDataSize(SESSION *s)
{
	if (s == NULL)
	{
		return;
	}
}

void ClientThread(THREAD *t, void *param)
{
	SESSION *s;
	CEDAR *cedar;
	if (t == NULL || param == NULL)
	{
		return;
	}

	s = (SESSION *)param;
	AddRef(s->ref);
	s->Thread = t;
	AddRef(t->ref);

	NoticeThreadInit(t);

	cedar = s->Cedar;

	s->ClientStatus = CLIENT_STATUS_CONNECTING;
	s->RetryFlag = true;
	s->CurrentRetryCount = 0;

	while (true)
	{
		Zero(&s->ServerIP_CacheForNextConnect, sizeof(IP));
		Zero(&s->LocalIP_CacheForNextConnect, sizeof(IP));
		Zero(s->UnderlayProtocol, sizeof(s->UnderlayProtocol));
		Zero(s->ProtocolDetails, sizeof(s->ProtocolDetails));

		if (s->Link != NULL && ((*s->Link->StopAllLinkFlag) || s->Link->Halting))
		{
			s->Err = ERR_USER_CANCEL;
			break;
		}

		if (s->LinkModeClient && s->Link != NULL)
		{
			HLog(s->Link->Hub, "LH_CONNECT_1", s->ClientOption->AccountName, s->CurrentRetryCount + 1);
		}

		s->NextConnectionTime = 0;

		s->ClientStatus = CLIENT_STATUS_CONNECTING;
		s->Halt = false;
		SessionConnect(s);
		if (s->UserCanceled)
		{
			s->Err = ERR_USER_CANCEL;
		}

		PrintSessionTotalDataSize(s);

		if (s->LinkModeClient && s->Link != NULL)
		{
			HLog(s->Link->Hub, "LH_CONNECT_ERROR", s->ClientOption->AccountName,
				GetUniErrorStr(s->Err), s->Err);
		}

		s->ClientStatus = CLIENT_STATUS_RETRY;

		if (s->Link != NULL)
		{
			((LINK *)s->Link)->LastError = s->Err;
		}

		if (s->Halt && (s->RetryFlag == false) || s->ForceStopFlag)
		{
			break;
		}
		UINT retry_interval = s->RetryInterval;

		if (s->LinkModeClient)
		{
			UINT current_num_links = Count(s->Cedar->CurrentActiveLinks);
			UINT max_retry_interval = MAX(1000 * current_num_links, retry_interval);

			retry_interval += retry_interval * MIN(s->CurrentRetryCount, 1000);
			retry_interval = MIN(retry_interval, max_retry_interval);

			if (retry_interval >= 1000 && retry_interval <= (60 * 60 * 1000))
			{
				retry_interval = (retry_interval * 8 / 10) + (Rand32() % (retry_interval * 4 / 10));
			}
		}

		if (s->Err == ERR_HUB_IS_BUSY || s->Err == ERR_LICENSE_ERROR ||
			s->Err == ERR_HUB_STOPPING || s->Err == ERR_TOO_MANY_USER_SESSION)
		{
			retry_interval = RETRY_INTERVAL_SPECIAL;
		}

		if (s->CurrentRetryCount >= s->ClientOption->NumRetry)
		{
			break;
		}

		Wait(s->HaltEvent, retry_interval);

SKIP:
		if (s->ConnectSucceed == false)
		{
			s->CurrentRetryCount++;
		}

		if (s->ForceStopFlag)
		{
			break;
		}
	}

	s->ClientStatus = CLIENT_STATUS_IDLE;

	if (s->Account != NULL)
	{
		s->Account->ClientSession = NULL;
		ReleaseSession(s);
	}

	ReleaseSession(s);
}

SESSION *NewRpcSessionEx2(CEDAR *cedar, CLIENT_OPTION *option, UINT *err, char *client_str, void *hWnd)
{
	SESSION *s;
	CONNECTION *c;
	SOCK *sock;
	if (cedar == NULL || option == NULL)
	{
		return NULL;
	}

	s = ZeroMalloc(sizeof(SESSION));

	s->LoggingRecordCount = NewCounter();
	s->lock = NewLock();
	s->ref = NewRef();
	s->Cedar = cedar;
	s->ServerMode = false;
	s->Name = CopyStr("CLIENT_RPC_SESSION");
	s->CreatedTime = s->LastCommTime = Tick64();
	s->Traffic = NewTraffic();
	s->HaltEvent = NewEvent();
	s->TrafficLock = NewLock();
	s->Cancel1 = NewCancel();

	s->ClientOption = Malloc(sizeof(CLIENT_OPTION));
	Copy(s->ClientOption, option, sizeof(CLIENT_OPTION));

	s->MaxConnection = option->MaxConnection;
	s->UseEncrypt = option->UseEncrypt;
	s->UseCompress = option->UseCompress;

	c = s->Connection = NewClientConnectionEx(s, client_str, cedar->Version, cedar->Build);
	c->hWndForUI = hWnd;

	sock = ClientConnectToServer(c);
	if (sock == NULL)
	{
		if (err != NULL)
		{
			*err = c->Err;
		}
		ReleaseSession(s);
		return NULL;
	}

	if (ClientUploadSignature(sock) == false)
	{
		if (err != NULL)
		{
			*err = c->Err;
		}
		ReleaseSession(s);
		return NULL;
	}

	if (ClientDownloadHello(c, sock) == false)
	{
		if (err != NULL)
		{
			*err = c->Err;
		}
		ReleaseSession(s);
		return NULL;
	}

	return s;
}

SESSION *NewClientSessionEx(CEDAR *cedar, CLIENT_OPTION *option, CLIENT_AUTH *auth, PACKET_ADAPTER *pa, ACCOUNT *account)
{
	SESSION *s;
	THREAD *t;
	if (cedar == NULL || option == NULL || auth == NULL || pa == NULL)
	{
		return NULL;
	}

	s = ZeroMalloc(sizeof(SESSION));

	s->LoggingRecordCount = NewCounter();

	s->lock = NewLock();
	s->ref = NewRef();
	s->Cedar = cedar;
	s->ServerMode = false;
	s->Name = CopyStr("CLIENT_SESSION");
	s->CreatedTime = s->LastCommTime = Tick64();
	s->Traffic = NewTraffic();
	s->HaltEvent = NewEvent();
	s->PacketAdapter = pa;
	s->TrafficLock = NewLock();
	s->OldTraffic = NewTraffic();
	s->Cancel1 = NewCancel();
	s->CancelList = NewList(NULL);

	s->ClientOption = Malloc(sizeof(CLIENT_OPTION));
	Copy(s->ClientOption, option, sizeof(CLIENT_OPTION));

	if (GetGlobalServerFlag(GSF_DISABLE_SESSION_RECONNECT))
	{
		s->ClientOption->DisableQoS = true;
		s->ClientOption->MaxConnection = 1;
		s->ClientOption->HalfConnection = false;
	}

	s->MaxConnection = option->MaxConnection;
	s->UseEncrypt = option->UseEncrypt;
	s->UseCompress = option->UseCompress;

	s->RetryInterval = MAKESURE(option->RetryInterval, 0, 4000000) * 1000;
	s->RetryInterval = MAKESURE(s->RetryInterval, MIN_RETRY_INTERVAL, MAX_RETRY_INTERVAL);

	s->ClientOption->AdditionalConnectionInterval = MAX(s->ClientOption->AdditionalConnectionInterval, 1);

	s->ClientAuth = Malloc(sizeof(CLIENT_AUTH));
	Copy(s->ClientAuth, auth, sizeof(CLIENT_AUTH));

	if (s->ClientAuth->ClientX != NULL)
	{
		s->ClientAuth->ClientX = CloneX(s->ClientAuth->ClientX);
	}
	if (s->ClientAuth->ClientK != NULL)
	{
		if (s->ClientAuth->AuthType != CLIENT_AUTHTYPE_OPENSSLENGINE)
		{
			s->ClientAuth->ClientK = CloneK(s->ClientAuth->ClientK);
		}
		else
		{
			s->ClientAuth->ClientK = OpensslEngineToK(s->ClientAuth->OpensslEnginePrivateKeyName, s->ClientAuth->OpensslEngineName);
		}
	}

	if (StrCmpi(s->ClientOption->DeviceName, LINK_DEVICE_NAME) == 0)
	{
		s->LinkModeClient = true;
		s->Link = (LINK *)s->PacketAdapter->Param;
		if (s->Link != NULL && s->Link->CheckServerCert && s->Link->Hub->HubDb != NULL)
		{
			s->SslOption = ZeroMalloc(sizeof(SSL_VERIFY_OPTION));
			s->SslOption->VerifyPeer = true;
			s->SslOption->AddDefaultCA = s->Link->AddDefaultCA;
			s->SslOption->VerifyHostname = true;
			s->SslOption->SavedCert = CloneX(s->Link->ServerCert);

			LIST *o = s->Link->Hub->HubDb->RootCertList;
			s->SslOption->CaList = CloneXList(o);
		}
	}
	else
	{
		if (account != NULL && account->CheckServerCert)
		{
			s->SslOption = ZeroMalloc(sizeof(SSL_VERIFY_OPTION));
			s->SslOption->VerifyPeer = true;
#ifdef	OS_WIN32
			s->SslOption->PromptOnVerifyFail = true;
#endif
			s->SslOption->AddDefaultCA = account->AddDefaultCA;
			s->SslOption->VerifyHostname = true;
			s->SslOption->SavedCert = CloneX(account->ServerCert);

			LIST *o = cedar->CaList;
			s->SslOption->CaList = CloneXList(o);
		}
	}

	if (StrCmpi(s->ClientOption->DeviceName, BRIDGE_DEVICE_NAME) == 0)
	{
		s->BridgeMode = true;
	}

	s->Account = account;

	t = NewThread(ClientThread, (void *)s);
	WaitThreadInit(t);
	ReleaseThread(t);

	return s;
}
SESSION *NewClientSession(CEDAR *cedar, CLIENT_OPTION *option, CLIENT_AUTH *auth, PACKET_ADAPTER *pa)
{
	return NewClientSessionEx(cedar, option, auth, pa, NULL);
}

SESSION *GetSessionFromKey(CEDAR *cedar, UCHAR *session_key)
{
	HUB *h;
	UINT i, j;
	if (cedar == NULL || session_key == NULL)
	{
		return NULL;
	}

	LockList(cedar->HubList);
	{
		for (i = 0;i < LIST_NUM(cedar->HubList);i++)
		{
			h = LIST_DATA(cedar->HubList, i);
			LockList(h->SessionList);
			{
				for (j = 0;j < LIST_NUM(h->SessionList);j++)
				{
					SESSION *s = LIST_DATA(h->SessionList, j);
					Lock(s->lock);
					{
						if (Cmp(s->SessionKey, session_key, SHA1_SIZE) == 0)
						{
							AddRef(s->ref);

							Unlock(s->lock);
							UnlockList(h->SessionList);
							UnlockList(cedar->HubList);
							return s;
						}
					}
					Unlock(s->lock);
				}
			}
			UnlockList(h->SessionList);
		}
	}
	UnlockList(cedar->HubList);

	return NULL;
}

void NewSessionKey(CEDAR *cedar, UCHAR *session_key, UINT *session_key_32)
{
	if (cedar == NULL || session_key == NULL || session_key_32 == NULL)
	{
		return;
	}

	Rand(session_key, SHA1_SIZE);
	*session_key_32 = Rand32();
}

SESSION *NewServerSession(CEDAR *cedar, CONNECTION *c, HUB *h, char *username, POLICY *policy)
{
	SESSION *s;
	char name[MAX_SIZE];
	char hub_name_upper[MAX_SIZE];
	char user_name_upper[MAX_USERNAME_LEN + 1];
	if (cedar == NULL || c == NULL || h == NULL || username == NULL || policy == NULL)
	{
		return NULL;
	}

	s = ZeroMalloc(sizeof(SESSION));

	s->LoggingRecordCount = NewCounter();
	s->lock = NewLock();
	s->ref = NewRef();
	s->Cedar = cedar;
	s->ServerMode = true;
	s->CreatedTime = s->LastCommTime = Tick64();
	s->Traffic = NewTraffic();
	s->HaltEvent = NewEvent();
	s->Cancel1 = NewCancel();
	s->CancelList = NewList(NULL);
	s->Thread = c->Thread;
	s->TrafficLock = NewLock();
	s->OldTraffic = NewTraffic();
	s->QoS = GetServerCapsBool(cedar->Server, "b_support_qos");
	AddRef(s->Thread->ref);
	s->Hub = h;
	s->ClientStatus = CLIENT_STATUS_ESTABLISHED;

	s->DelayedPacketList = NewList(NULL);

	s->PacketAdapter = GetHubPacketAdapter();

	s->Connection = c;
	AddRef(c->ref);

	StrCpy(hub_name_upper, sizeof(hub_name_upper), h->Name);
	StrUpper(hub_name_upper);
	StrCpy(user_name_upper, sizeof(user_name_upper), username);
	StrUpper(user_name_upper);

	Format(name, sizeof(name), "SID-%s-%u", user_name_upper, Inc(h->SessionCounter));

	s->Name = CopyStr(name);
	s->Policy = policy;

	AddSession(h, s);

	NewSessionKey(cedar, s->SessionKey, &s->SessionKey32);

	return s;
}

void PrintStatus(SESSION *s, wchar_t *str)
{
	if (s == NULL || str == NULL || s->Account == NULL || s->Account->StatusPrinter == NULL)
	{
		return;
	}

	s->Account->StatusPrinter(s, str);
}

// Add c to the cancel list o once. The flood loop of StorePacket adds the cancel of every session of the hub,
// so a scan of o on every add made each flooded frame cost O(N^2) compares. Two marks on c skip the scan:
// CancelListOwner == o means c is in o (only the thread of o sets it to o, and clears it when o is emptied);
// CancelListNum == 0 means c is in no list. Otherwise (c is in some list, the owner mark is not o) the old
// scan runs, so o stays a set exactly as before.
void AddCancelList(LIST *o, CANCEL *c)
{
	UINT i;
	if (o == NULL || c == NULL)
	{
		return;
	}

	if (c->CancelListOwner == o)
	{
		return;
	}

	if (c->CancelListNum != 0)
	{
		for (i = 0;i < LIST_NUM(o);i++)
		{
			CANCEL *t = LIST_DATA(o, i);
			if (t == c)
			{
				c->CancelListOwner = o;
				return;
			}
		}
	}

	AddRef(c->ref);
	Add(o, c);
	Win32Inc32(&c->CancelListNum);
	c->CancelListOwner = o;
}

// c leaves the cancel list o: undo the marks of AddCancelList before o drops its reference to c
static void LeaveCancelList(LIST *o, CANCEL *c)
{
	if (c->CancelListOwner == o)
	{
		c->CancelListOwner = NULL;
	}

	Win32Dec32(&c->CancelListNum);
}

void CancelList(LIST *o)
{
	UINT i;
	if (o == NULL)
	{
		return;
	}

	for (i = 0;i < LIST_NUM(o);i++)
	{
		CANCEL *c = LIST_DATA(o, i);
		LeaveCancelList(o, c);
		Cancel(c);
		ReleaseCancel(c);
	}

	DeleteAll(o);
}

void ReleaseCancelList(LIST *o)
{
	UINT i;
	if (o == NULL)
	{
		return;
	}

	for (i = 0;i < LIST_NUM(o);i++)
	{
		CANCEL *c = LIST_DATA(o, i);
		LeaveCancelList(o, c);
		ReleaseCancel(c);
	}

	ReleaseList(o);
}
