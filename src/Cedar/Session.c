// Session.c
// Session Manager

#include "Session.h"

#include "Account.h"
#include "Bridge.h"
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

void SessionMain(SESSION *s) {
	CONNECTION *c;
	POLICY *policy;
	UINT64 now;
	PACKET_ADAPTER *pa;
	bool pa_inited = false;
	UINT packet_size;
	void *packet;
	bool pa_fail = false;
	bool update_hub_last_comm = false;
	UINT err = ERR_SESSION_TIMEOUT;
	UINT64 next_update_hub_last_comm = 0;
	TRAFFIC t;
	int packet_queue_diff;
	bool is_server_session = false;
	bool lock_receive_blocks_queue = false;
	HUB *udp_accel_log_hub;

	if (s == NULL)
		return;

	// The drop counters of the UDP Acceleration go to the log of the session's hub, or for a
	// cascade connection to the log of the local hub of the cascade
	udp_accel_log_hub = (s->Hub != NULL ? s->Hub : (s->Link != NULL ? s->Link->Hub : NULL));

	s->CurrentRetryCount = 0;
	s->ConnectSucceed = true;
	s->SessionTimeOuted = false;

	c = s->Connection;
	policy = s->Policy;

	pa = s->PacketAdapter;
	if (pa->Init(s) == false) {
		if (s->VLanDeviceErrorCount >= 2)
			s->ForceStopFlag = true;
		else
			s->VLanDeviceErrorCount++;
		err = ERR_DEVICE_DRIVER_ERROR;
		goto CLEANUP;
	}
	pa_inited = true;

	if (s->BridgeMode == false) {
		s->Cancel2 = pa->GetCancel(s);
	} else {
		CANCEL *c = pa->GetCancel(s);
		CANCEL *old = s->Cancel1;
		s->Cancel1 = c;
		ReleaseCancel(old);
	}

	s->RetryFlag = false;

	s->LastCommTime = Tick64();
	if (s->ServerMode == false)
		s->NextConnectionTime = Tick64() + (UINT64)((UINT64)s->ClientOption->AdditionalConnectionInterval * (UINT64)1000);

	s->NumConnectionsEstablished++;
	s->CurrentConnectionEstablishTime = Tick64();
	if (s->FirstConnectionEstablisiedTime == 0)       /* !!! Do not correct the spelling to keep the backward protocol compatibility !!!  */
		s->FirstConnectionEstablisiedTime = Tick64(); /* !!! Do not correct the spelling to keep the backward protocol compatibility !!!  */

	s->LastIncrementTraffic = Tick64();

	c->Err = ERR_SESSION_TIMEOUT;
	s->VLanDeviceErrorCount = 0;

	s->LastTryAddConnectTime = Tick64();

	if (policy != NULL) {
		if (policy->MonitorPort)
			s->IsMonitorMode = true;

		if (policy->NoRouting == false || policy->NoBridge == false)
			s->IsBridgeMode = true;
	}

	is_server_session = s->ServerMode;

	lock_receive_blocks_queue = s->LinkModeServer;

	now = Tick64();

	while (true) {
		Zero(&t, sizeof(t));

		if (next_update_hub_last_comm == 0 ||
		    (next_update_hub_last_comm <= now)) {
			next_update_hub_last_comm = now + 1000;

			if (s->Hub != NULL) {
				if (update_hub_last_comm) {
					Lock(s->Hub->lock);
					{
						s->Hub->LastCommTime = SystemTime64();
					}
					Unlock(s->Hub->lock);

					update_hub_last_comm = false;
				}
			}
		}

		if (is_server_session && s->LinkModeServer == false && s->BridgeMode == false) {
			if (s->Hub != NULL && s->Hub->ForceDisableComm) {
				err = ERR_SERVER_CANT_ACCEPT;
				pa_fail = true;
			}
		}

		if (is_server_session == false) {
			if (GetGlobalServerFlag(GSF_DISABLE_SESSION_RECONNECT) == false)
				ClientAdditionalConnectChance(s);
		}

		ConnectionReceive(c, s->Cancel1, s->Cancel2);

		now = Tick64();

		if (s->UseUdpAcceleration && s->UdpAccel != NULL && s->UdpAccel->FatalError) {
			// A send error on the UDP acceleration socket is fatal
			err = ERR_DISCONNECTED;
			pa_fail = true;
		}

		if (s->UseUdpAcceleration && s->UdpAccel != NULL) {
			// Dropped datagrams of the UDP Acceleration port, at most one entry per interval
			UdpAccelLogDrops(s->UdpAccel, udp_accel_log_hub, s->Name, false);
		}

		if (lock_receive_blocks_queue)
			LockQueue(c->ReceivedBlocks);
		{
			BLOCK *b;
			while (true) {
				b = GetNext(c->ReceivedBlocks);
				if (b == NULL)
					break;

				update_hub_last_comm = true;

				TrafficCountFrame(is_server_session ? &t.Send : &t.Recv, b->Buf, b->Size);

				if (pa->PutPacket(s, b->Buf, b->Size) == false) {
					pa_fail = true;
					err = ERR_DEVICE_DRIVER_ERROR;
					Free(b->Buf);
				}
				Free(b);
			}

			if (pa->PutPacket(s, NULL, 0) == false) {
				pa_fail = true;
				err = ERR_DEVICE_DRIVER_ERROR;
			}
		}
		if (lock_receive_blocks_queue)
			UnlockQueue(c->ReceivedBlocks);

		{
			UINT i, max_num = MAX_SEND_SOCKET_QUEUE_NUM;
			i = 0;
			while (packet_size = pa->GetNextPacket(s, &packet)) {
				BLOCK *b;
				if (packet_size == INFINITE) {
					err = ERR_DEVICE_DRIVER_ERROR;
					pa_fail = true;
					break;
				}

				update_hub_last_comm = true;

				if (c->CurrentSendQueueSize > MAX_BUFFERING_PACKET_SIZE) {
					Free(packet);
				} else {
					bool priority;
					QUEUE *q = NULL;
					TrafficCountFrame(is_server_session ? &t.Recv : &t.Send, (UCHAR *)packet, packet_size);
					priority = IsPriorityHighestPacketForQoS(packet, packet_size);

					b = NewBlock(packet, packet_size, s->UseCompress ? 1 : 0);
					b->PriorityQoS = priority;

					if (b->PriorityQoS && c->Protocol == CONNECTION_TCP && s->QoS)
						q = c->SendBlocks2;
					else
						q = c->SendBlocks;

					if (q->num_item > MAX_STORED_QUEUE_NUM)
						q = NULL;

					if (q != NULL) {
						c->CurrentSendQueueSize += b->Size;
						InsertQueue(q, b);
					} else {
						FreeBlock(b);
					}
				}

				if ((i % 16) == 0) {
					int diff = ((int)c->CurrentSendQueueSize) - ((int)c->LastPacketQueueSize);
					CedarAddCurrentTcpQueueSize(c->Cedar, diff);
					c->LastPacketQueueSize = c->CurrentSendQueueSize;
				}

				i++;
				if (i >= max_num)
					break;
			}
		}

		AddTrafficForSession(s, &t);

		packet_queue_diff = ((int)c->CurrentSendQueueSize) - ((int)c->LastPacketQueueSize);
		CedarAddCurrentTcpQueueSize(c->Cedar, packet_queue_diff);
		c->LastPacketQueueSize = c->CurrentSendQueueSize;

		now = Tick64();

		ConnectionSend(c, now);

		if (s->Halt) {
			if (s->ForceStopFlag)
				err = ERR_USER_CANCEL;
			break;
		}

		// Count the login only after the session has lasted 30 seconds,
		// so DoS attempts and failed connections do not raise the counters.
		if (s->NumLoginIncrementTick != 0 && s->NumLoginIncrementTick <= now) {
			s->NumLoginIncrementTick = 0;

			if (s->NumLoginIncrementHubObject != NULL)
				s->NumLoginIncrementHubObject->NumLogin++;

			if (s->NumLoginIncrementUserObject != NULL)
				s->NumLoginIncrementUserObject->NumLogin++;
		}

		if (is_server_session) {
			if ((s->LastIncrementTraffic + INCREMENT_TRAFFIC_INTERVAL) <= now) {
				IncrementUserTraffic(s->Hub, s->UserNameReal, s);
				s->LastIncrementTraffic = now;
			}
		}

		if (s->LinkModeServer == false && s->BridgeMode == false) {
			bool timeouted = false;

			if ((now > s->LastCommTime) && ((now - s->LastCommTime) >= ((UINT64)s->Timeout)))
				timeouted = true;

			if (c->Protocol == CONNECTION_TCP) {
				if (GetGlobalServerFlag(GSF_DISABLE_SESSION_RECONNECT)) {
					UINT num_tcp_connections = Count(c->CurrentNumConnection);

					if (num_tcp_connections == 0)
						timeouted = true;
				}
			}

			if (is_server_session == false && s->ClientOption != NULL && s->ClientOption->ConnectionDisconnectSpan == 0) {
				if (LIST_NUM(s->Connection->Tcp->TcpSockList) < s->MaxConnection) {
					if ((s->LastTryAddConnectTime +
					     (UINT64)(s->ClientOption->AdditionalConnectionInterval * 1000 * 2 + CONNECTING_TIMEOUT * 2)) <= Tick64())
						timeouted = true;

					UINT num_tcp_conn = LIST_NUM(s->Connection->Tcp->TcpSockList);

					if ((s->CurrentConnectionEstablishTime +
					     (UINT64)(num_tcp_conn * s->ClientOption->AdditionalConnectionInterval * 1000 * 2 + CONNECTING_TIMEOUT * 2)) <= Tick64()) {
						if (s->ClientOption->BindLocalPort != 0 || num_tcp_conn == 0)
							timeouted = true;
					}
				}
			}

			if (timeouted) {
				s->SessionTimeOuted = true;
				err = ERR_SESSION_TIMEOUT;
			}
		}

		if (pa_fail || s->SessionTimeOuted) {
			s->Halt = true;
			s->RetryFlag = true;
			break;
		}
	}

CLEANUP:

	if (s->UdpAccel != NULL) {
		// The drops since the last entry, before the UDP Acceleration of this connection is freed
		UdpAccelLogDrops(s->UdpAccel, udp_accel_log_hub, s->Name, true);
	}

	if (s->ServerMode) {
		IncrementUserTraffic(s->Hub, s->UserNameReal, s);

		DelSession(s->Hub, s);
	}

	s->ConnectSucceed = false;

	if (s->Connection) {
		int diff = -((int)s->Connection->LastTcpQueueSize);
		s->Connection->LastTcpQueueSize = 0;
		FlagWrite(&s->Connection->Halt, true);
		CedarAddCurrentTcpQueueSize(s->Cedar, diff);

		diff = ((int)c->CurrentSendQueueSize) - ((int)c->LastPacketQueueSize);
		CedarAddCurrentTcpQueueSize(c->Cedar, diff);
		c->LastPacketQueueSize = c->CurrentSendQueueSize;
	}

	if (pa_inited)
		pa->Free(s);

	if (s->ServerMode == false)
		StopAllAdditionalConnectThread(s->Connection);

	if (s->BridgeMode)
		BrSessionCleanup(s);

	if (s->Cancel2 != NULL) {
		ReleaseCancel(s->Cancel2);
		s->Cancel2 = NULL;
	}

	EndTunnelingMode(c);

	c->Err = err;
}

UINT GetNextDelayedPacketTickDiff(SESSION *s) {
	UINT ret = 0x7fffffff;
	UINT64 now;
	if (s == NULL)
		return 0;

	if (LIST_NUM(s->DelayedPacketList) >= 1) {
		now = TickHighres64();

		LockList(s->DelayedPacketList);
		{
			for (UINT i = 0; i < LIST_NUM(s->DelayedPacketList); i++) {
				PKT *p = LIST_DATA(s->DelayedPacketList, i);
				UINT64 t = p->DelayedForwardTick;
				UINT d = 0x7fffffff;

				if (now >= t)
					d = 0;
				else
					d = (UINT)(t - now);

				ret = MIN(ret, d);
			}
		}
		UnlockList(s->DelayedPacketList);
	}

	return ret;
}

bool IsPriorityHighestPacketForQoS(void *data, UINT size) {
	if (data == NULL)
		return false;

	UCHAR *buf = (UCHAR *)data;
	if (size >= 16) {
		if (buf[12] == 0x08 && buf[13] == 0x00 && buf[15] != 0x00 && buf[15] != 0x08)
			return true;

		if (size >= 34 && size <= 128) {
			if (buf[12] == 0x08 && buf[13] == 0x00 && buf[23] == 0x01)
				return true;
		}
	}

	return false;
}

void IncrementUserTraffic(HUB *hub, char *username, SESSION *s) {
	TRAFFIC report_traffic;
	if (hub == NULL || username == NULL || s == NULL)
		return;

	Lock(s->TrafficLock);
	{
		SubTraffic(&report_traffic, s->Traffic, s->OldTraffic);
		Copy(s->OldTraffic, s->Traffic, sizeof(TRAFFIC));

		AcLock(hub);
		{
			USER *u = AcGetUser(hub, username);
			if (u != NULL) {
				Lock(u->lock);
				{
					AddTraffic(u->Traffic, &report_traffic);
				}
				Unlock(u->lock);
				if (u->Group != NULL) {
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

void AddTrafficForSession(SESSION *s, TRAFFIC *t) {
	HUB *h;
	TRAFFIC t2;
	if (s == NULL || t == NULL)
		return;

	Lock(s->TrafficLock);
	{
		AddTraffic(s->Traffic, t);
	}
	Unlock(s->TrafficLock);

	if (s->ServerMode) {
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

void ClientAdditionalConnectChance(SESSION *s) {
	if (s == NULL)
		return;

	if (s->ServerMode)
		return;
	if (s->Connection->Protocol != CONNECTION_TCP)
		return;
	while (true) {
		if (s->Halt)
			return;
		if (Count(s->Connection->CurrentNumConnection) < s->MaxConnection) {
			UINT64 now = Tick64();

			if (s->NextConnectionTime == 0 ||
			    s->ClientOption->AdditionalConnectionInterval == 0 ||
			    (s->NextConnectionTime <= now)) {
				s->NextConnectionTime = now + ((UINT64)s->ClientOption->AdditionalConnectionInterval * (UINT64)1000);
				SessionAdditionalConnect(s);
			} else {
				break;
			}
		} else {
			break;
		}
	}
}

static void FreePacketAdapter(PACKET_ADAPTER *pa) {
	if (pa == NULL)
		return;

	Free(pa);
}

PACKET_ADAPTER *NewPacketAdapter(PA_INIT *init, PA_GETCANCEL *getcancel, PA_GETNEXTPACKET *getnext,
                                 PA_PUTPACKET *put, PA_FREE *free) {
	if (init == NULL || getcancel == NULL || getnext == NULL || put == NULL || free == NULL)
		return NULL;

	PACKET_ADAPTER *pa = ZeroMalloc(sizeof(PACKET_ADAPTER));

	pa->Init = init;
	pa->Free = free;
	pa->GetCancel = getcancel;
	pa->GetNextPacket = getnext;
	pa->PutPacket = put;

	return pa;
}

static void ClientAdditionalThread(THREAD *t, void *param) {
	if (t == NULL || param == NULL)
		return;

	SESSION *s = (SESSION *)param;

	s->LastTryAddConnectTime = Tick64();

	CONNECTION *c = s->Connection;
	Inc(c->CurrentNumConnection);
	LockList(c->ConnectingThreads);
	{
		Add(c->ConnectingThreads, t);
		AddRef(t->ref);
	}
	UnlockList(c->ConnectingThreads);

	NoticeThreadInit(t);

	if (ClientAdditionalConnect(c) == false) {
		Dec(c->CurrentNumConnection);

		if (c->AdditionalConnectionFailedCounter == 0)
			c->LastCounterResetTick = Tick64();

		c->AdditionalConnectionFailedCounter++;

		if ((c->LastCounterResetTick + (UINT64)ADDITIONAL_CONNECTION_COUNTER_RESET_INTERVAL) <= Tick64()) {
			c->AdditionalConnectionFailedCounter = 0;
			c->LastCounterResetTick = Tick64();
		}
	} else {
		s->LastTryAddConnectTime = Tick64();
		c->AdditionalConnectionFailedCounter = 0;
		c->LastCounterResetTick = Tick64();
	}

	LockList(c->ConnectingThreads);
	{
		if (Delete(c->ConnectingThreads, t))
			ReleaseThread(t);
	}
	UnlockList(c->ConnectingThreads);
	ReleaseSession(s);
}

void SessionAdditionalConnect(SESSION *s) {
	if (s == NULL)
		return;

	AddRef(s->ref);
	THREAD *t = NewThread(ClientAdditionalThread, (void *)s);
	WaitThreadInit(t);
	ReleaseThread(t);
}

static bool SessionConnect(SESSION *s) {
	bool ret = false;
	if (s == NULL)
		return false;

	s->ClientStatus = CLIENT_STATUS_CONNECTING;

	Lock(s->lock);
	{
		s->Err = ERR_NO_ERROR;
		if (s->Policy != NULL) {
			Free(s->Policy);
			s->Policy = NULL;
		}
	}
	Unlock(s->lock);

	CONNECTION *c = NewClientConnectionEx(s, NULL);

	// StopSessionEx reads s->Connection and takes its ref under s->lock
	Lock(s->lock);
	{
		s->Connection = c;
	}
	Unlock(s->lock);

	ret = ClientConnect(c);
	s->Err = c->Err;

	Lock(s->lock);
	{
		s->Connection = NULL;
	}
	Unlock(s->lock);
	ReleaseConnection(c);

	Lock(s->lock);
	{
		if (s->Policy != NULL) {
			Free(s->Policy);
			s->Policy = NULL;
		}
	}
	Unlock(s->lock);

	return ret;
}

void StopSession(SESSION *s) {
	StopSessionEx(s, false);
}

// Teardown lock order: LINK lock, then SESSION lock, then CONNECTION lock. The teardown paths
// (StopLink, StopSessionEx, StopConnection) take each lock only to read the child pointer and
// add a ref, and release it before they stop the child, so no two of these locks nest there.
// None of them is taken under the MacHashTable lock of a hub.
void StopSessionEx(SESSION *s, bool no_wait) {
	CONNECTION *c;
	if (s == NULL)
		return;

	s->UserCanceled = true;
	s->Halt = true;

	Cancel(s->Cancel1);

	Set(s->HaltEvent);

	// SessionConnect sets and clears s->Connection under s->lock and then releases it
	Lock(s->lock);
	{
		c = s->Connection;
		if (c != NULL)
			AddRef(c->ref);
	}
	Unlock(s->lock);

	if (c != NULL) {
		StopConnection(c, no_wait);
		ReleaseConnection(c);
	}

	if (no_wait == false) {
		while (true) {
			s->ForceStopFlag = true;
			s->Halt = true;
			if (WaitThread(s->Thread, 20))
				break;
		}
	} else {
		s->ForceStopFlag = true;
		s->Halt = true;
	}
}

static void CleanupSession(SESSION *s) {
	if (s == NULL)
		return;

	if (s->DelayedPacketList != NULL) {
		for (UINT i = 0; i < LIST_NUM(s->DelayedPacketList); i++) {
			PKT *p = LIST_DATA(s->DelayedPacketList, i);

			Free(p->PacketData);
			FreePacket(p);
		}

		ReleaseList(s->DelayedPacketList);
	}

	if (s->ClientOption != NULL)
		Free(s->ClientOption);

	ClientAuthFree(s->ClientAuth);

	if (s->SslOption != NULL) {
		FreeXList(s->SslOption->CaList);
		FreeX(s->SslOption->SavedCert);
		Free(s->SslOption);
	}

	FreeTraffic(s->Traffic);
	Free(s->Name);

	if (s->Thread != NULL)
		ReleaseThread(s->Thread);

	DeleteLock(s->lock);

	ReleaseEvent(s->HaltEvent);

	if (s->Cancel1)
		ReleaseCancel(s->Cancel1);

	if (s->Cancel2)
		ReleaseCancel(s->Cancel2);

	if (s->Policy)
		Free(s->Policy);

	if (s->Connection)
		ReleaseConnection(s->Connection);

	Free(s->Username);

	if (s->PacketAdapter)
		FreePacketAdapter(s->PacketAdapter);

	if (s->OldTraffic != NULL)
		FreeTraffic(s->OldTraffic);

	DeleteLock(s->TrafficLock);

	if (s->CancelList != NULL)
		ReleaseCancelList(s->CancelList);

	if (s->Client_Message != NULL)
		Free(s->Client_Message);

	DeleteCounter(s->LoggingRecordCount);

	Free(s);
}

void ReleaseSession(SESSION *s) {
	if (s == NULL)
		return;

	if (Release(s->ref) == 0)
		CleanupSession(s);
}

static void ClientThread(THREAD *t, void *param) {
	if (t == NULL || param == NULL)
		return;

	SESSION *s = (SESSION *)param;
	AddRef(s->ref);
	s->Thread = t;
	AddRef(t->ref);

	NoticeThreadInit(t);

	s->ClientStatus = CLIENT_STATUS_CONNECTING;
	s->RetryFlag = true;
	s->CurrentRetryCount = 0;

	while (true) {
		Zero(&s->ServerIP_CacheForNextConnect, sizeof(IP));
		Zero(&s->LocalIP_CacheForNextConnect, sizeof(IP));
		Zero(s->UnderlayProtocol, sizeof(s->UnderlayProtocol));
		Zero(s->ProtocolDetails, sizeof(s->ProtocolDetails));

		if (s->Link != NULL && ((*s->Link->StopAllLinkFlag) || s->Link->Halting)) {
			s->Err = ERR_USER_CANCEL;
			break;
		}

		if (s->LinkModeClient && s->Link != NULL)
			HLog(s->Link->Hub, "LH_CONNECT_1", s->ClientOption->AccountName, s->CurrentRetryCount + 1);

		s->NextConnectionTime = 0;

		s->ClientStatus = CLIENT_STATUS_CONNECTING;
		s->Halt = false;
		SessionConnect(s);
		if (s->UserCanceled)
			s->Err = ERR_USER_CANCEL;

		if (s->LinkModeClient && s->Link != NULL)
			HLog(s->Link->Hub, "LH_CONNECT_ERROR", s->ClientOption->AccountName,
			     GetUniErrorStr(s->Err), s->Err);

		s->ClientStatus = CLIENT_STATUS_RETRY;

		if (s->Link != NULL)
			((LINK *)s->Link)->LastError = s->Err;

		if (s->Halt && (s->RetryFlag == false) || s->ForceStopFlag)
			break;
		UINT retry_interval = s->RetryInterval;

		if (s->LinkModeClient) {
			UINT current_num_links = Count(s->Cedar->CurrentActiveLinks);
			UINT max_retry_interval = MAX(1000 * current_num_links, retry_interval);

			retry_interval += retry_interval * MIN(s->CurrentRetryCount, 1000);
			retry_interval = MIN(retry_interval, max_retry_interval);

			if (retry_interval >= 1000 && retry_interval <= (60 * 60 * 1000))
				retry_interval = (retry_interval * 8 / 10) + (Rand32() % (retry_interval * 4 / 10));
		}

		if (s->Err == ERR_HUB_IS_BUSY || s->Err == ERR_LICENSE_ERROR ||
		    s->Err == ERR_HUB_STOPPING || s->Err == ERR_TOO_MANY_USER_SESSION)
			retry_interval = RETRY_INTERVAL_SPECIAL;

		if (s->CurrentRetryCount >= s->ClientOption->NumRetry)
			break;

		Wait(s->HaltEvent, retry_interval);

		if (s->ConnectSucceed == false)
			s->CurrentRetryCount++;

		if (s->ForceStopFlag)
			break;
	}

	s->ClientStatus = CLIENT_STATUS_IDLE;

	ReleaseSession(s);
}

// The fields every session constructor sets the same way
static SESSION *NewSessionBase(CEDAR *cedar, bool server_mode) {
	SESSION *s = ZeroMalloc(sizeof(SESSION));

	s->LoggingRecordCount = NewCounter();
	s->lock = NewLock();
	s->ref = NewRef();
	s->Cedar = cedar;
	s->ServerMode = server_mode;
	s->CreatedTime = s->LastCommTime = Tick64();
	s->Traffic = NewTraffic();
	s->HaltEvent = NewEvent();
	s->TrafficLock = NewLock();
	s->Cancel1 = NewCancel();

	return s;
}

SESSION *NewRpcSession(CEDAR *cedar, CLIENT_OPTION *option, UINT *err, char *client_str) {
	if (cedar == NULL || option == NULL) {
		if (err != NULL)
			*err = ERR_INTERNAL_ERROR;
		return NULL;
	}

	SESSION *s = NewSessionBase(cedar, false);

	s->Name = CopyStr("CLIENT_RPC_SESSION");

	s->ClientOption = ClientOptionClone(option);

	s->MaxConnection = option->MaxConnection;
	s->UseEncrypt = option->UseEncrypt;
	s->UseCompress = option->UseCompress;

	CONNECTION *c = s->Connection = NewClientConnectionEx(s, client_str);

	SOCK *sock = ClientConnectToServer(c);
	if (sock == NULL) {
		if (err != NULL)
			*err = c->Err;
		ReleaseSession(s);
		return NULL;
	}

	if (ClientUploadSignature(sock) == false) {
		// ClientUploadSignature has no connection to set the error of: the socket broke
		c->Err = ERR_DISCONNECTED;
		if (err != NULL)
			*err = c->Err;
		ReleaseSession(s);
		return NULL;
	}

	if (ClientDownloadHello(c, sock) == false) {
		if (err != NULL)
			*err = c->Err;
		ReleaseSession(s);
		return NULL;
	}

	return s;
}

SESSION *NewClientSession(CEDAR *cedar, CLIENT_OPTION *option, CLIENT_AUTH *auth, PACKET_ADAPTER *pa) {
	if (cedar == NULL || option == NULL || auth == NULL || pa == NULL)
		return NULL;

	SESSION *s = NewSessionBase(cedar, false);

	s->Name = CopyStr("CLIENT_SESSION");
	s->PacketAdapter = pa;
	s->OldTraffic = NewTraffic();
	s->CancelList = NewList(NULL);

	s->ClientOption = ClientOptionClone(option);

	if (GetGlobalServerFlag(GSF_DISABLE_SESSION_RECONNECT)) {
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

	s->ClientAuth = ClientAuthClone(auth);

	if (StrCmpi(s->ClientOption->DeviceName, LINK_DEVICE_NAME) == 0) {
		s->LinkModeClient = true;
		s->Link = (LINK *)s->PacketAdapter->Param;
		if (s->Link != NULL && s->Link->CheckServerCert && s->Link->Hub->HubDb != NULL) {
			s->SslOption = ZeroMalloc(sizeof(SSL_VERIFY_OPTION));
			s->SslOption->VerifyPeer = true;
			s->SslOption->AddDefaultCA = s->Link->AddDefaultCA;
			s->SslOption->VerifyHostname = true;
			s->SslOption->SavedCert = CloneX(s->Link->ServerCert);

			LIST *o = s->Link->Hub->HubDb->RootCertList;
			s->SslOption->CaList = CloneXList(o);
		}
	}

	THREAD *t = NewThread(ClientThread, (void *)s);
	WaitThreadInit(t);
	ReleaseThread(t);

	return s;
}

SESSION *GetSessionFromKey(CEDAR *cedar, UCHAR *session_key) {
	HUB *h;
	if (cedar == NULL || session_key == NULL)
		return NULL;

	LockList(cedar->HubList);
	{
		for (UINT i = 0; i < LIST_NUM(cedar->HubList); i++) {
			h = LIST_DATA(cedar->HubList, i);
			LockList(h->SessionList);
			{
				for (UINT j = 0; j < LIST_NUM(h->SessionList); j++) {
					SESSION *s = LIST_DATA(h->SessionList, j);
					Lock(s->lock);
					{
						if (Cmp(s->SessionKey, session_key, SHA1_SIZE) == 0) {
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

static void NewSessionKey(UCHAR *session_key, UINT *session_key_32) {
	if (session_key == NULL || session_key_32 == NULL)
		return;

	Rand(session_key, SHA1_SIZE);
	*session_key_32 = Rand32();
}

SESSION *NewServerSession(CEDAR *cedar, CONNECTION *c, HUB *h, char *username, POLICY *policy) {
	char name[MAX_SIZE];
	char hub_name_upper[MAX_SIZE];
	char user_name_upper[MAX_USERNAME_LEN + 1];
	if (cedar == NULL || c == NULL || h == NULL || username == NULL || policy == NULL)
		return NULL;

	SESSION *s = NewSessionBase(cedar, true);

	s->CancelList = NewList(NULL);
	s->Thread = c->Thread;
	s->OldTraffic = NewTraffic();
	s->QoS = true;
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

	NewSessionKey(s->SessionKey, &s->SessionKey32);

	return s;
}

// Add c to the cancel list o once. The flood loop of StorePacket adds the cancel of every session of the hub,
// so a scan of o on every add made each flooded frame cost O(N^2) compares. Two marks on c skip the scan:
// CancelListOwner == o means c is in o (only the thread of o sets it to o, and clears it when o is emptied);
// CancelListNum == 0 means c is in no list. Otherwise (c is in some list, the owner mark is not o) the old
// scan runs, so o stays a set exactly as before.
void AddCancelList(LIST *o, CANCEL *c) {
	if (o == NULL || c == NULL)
		return;

	if (c->CancelListOwner == o)
		return;

	if (c->CancelListNum != 0) {
		for (UINT i = 0; i < LIST_NUM(o); i++) {
			CANCEL *t = LIST_DATA(o, i);
			if (t == c) {
				c->CancelListOwner = o;
				return;
			}
		}
	}

	AddRef(c->ref);
	Add(o, c);
	InterlockedIncrement((volatile LONG *)&c->CancelListNum);
	c->CancelListOwner = o;
}

// c leaves the cancel list o: undo the marks of AddCancelList before o drops its reference to c
static void LeaveCancelList(const LIST *o, CANCEL *c) {
	if (c->CancelListOwner == o)
		c->CancelListOwner = NULL;

	InterlockedDecrement((volatile LONG *)&c->CancelListNum);
}

void CancelList(LIST *o) {
	if (o == NULL)
		return;

	for (UINT i = 0; i < LIST_NUM(o); i++) {
		CANCEL *c = LIST_DATA(o, i);
		LeaveCancelList(o, c);
		Cancel(c);
		ReleaseCancel(c);
	}

	DeleteAll(o);
}

void ReleaseCancelList(LIST *o) {
	if (o == NULL)
		return;

	for (UINT i = 0; i < LIST_NUM(o); i++) {
		CANCEL *c = LIST_DATA(o, i);
		LeaveCancelList(o, c);
		ReleaseCancel(c);
	}

	ReleaseList(o);
}

// Copy what the admin RPCs report about the session. Lock order as in HubCountUserSessions: the caller may hold the
// hub's SessionList; this takes s->lock, then the TcpSockList lock and the traffic lock
void SessionGetInfo(SESSION *s, SESSION_INFO *info) {
	if (info == NULL)
		return;

	Zero(info, sizeof(SESSION_INFO));

	if (s == NULL)
		return;

	Lock(s->lock);
	{
		StrCpy(info->Name, sizeof(info->Name), s->Name);
		StrCpy(info->Username, sizeof(info->Username), s->Username);
		StrCpy(info->RealUsername, sizeof(info->RealUsername), s->UserNameReal);
		StrCpy(info->GroupName, sizeof(info->GroupName), s->GroupName);
		Copy(&info->NodeInfo, &s->NodeInfo, sizeof(NODE_INFO));

		if (s->Connection != NULL) {
			CONNECTION *c = s->Connection;

			Copy(&info->ClientIp, &c->ClientIp, sizeof(IP));
			StrCpy(info->ClientHostname, sizeof(info->ClientHostname), c->ClientHostname);

			LockList(c->Tcp->TcpSockList);
			{
				info->NumTcp = LIST_NUM(c->Tcp->TcpSockList);
			}
			UnlockList(c->Tcp->TcpSockList);
		}

		info->MaxConnection = s->MaxConnection;
		info->CreatedTime = s->CreatedTime;
		info->LastCommTime = s->LastCommTime;
		info->LastCommTimeForDormant = s->LastCommTimeForDormant;
		info->LinkModeServer = s->LinkModeServer;
		info->BridgeMode = s->BridgeMode;
		info->NormalClient = s->NormalClient;
		info->IsBridgeMode = s->IsBridgeMode;
		info->IsMonitorMode = s->IsMonitorMode;
		info->VLanId = s->VLanId;

		Lock(s->TrafficLock);
		{
			info->PacketSize = GetTrafficPacketSize(s->Traffic);
			info->PacketNum = GetTrafficPacketNum(s->Traffic);
		}
		Unlock(s->TrafficLock);
	}
	Unlock(s->lock);
}
