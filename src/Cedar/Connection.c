// Connection.c
// Connection Manager

#include "Connection.h"

#include "Bridge.h"
#include "Hub.h"
#include "Link.h"
#include "Listener.h"
#include "Protocol.h"
#include "Server.h"
#include "Session.h"
#include "UdpAccel.h"

#include "Mayaqua/DNS.h"
#include "Mayaqua/Kernel.h"
#include "Mayaqua/Mayaqua.h"
#include "Mayaqua/Memory.h"
#include "Mayaqua/Object.h"
#include "Mayaqua/Pack.h"
#include "Mayaqua/Str.h"
#include "Mayaqua/Table.h"
#include "Mayaqua/TcpIp.h"
#include "Mayaqua/Tick64.h"

#include "ConnectionInternal.h"

#define IS_SEND_TCP_SOCK(ts) \
	((ts->Direction == TCP_BOTH) || ((ts->Direction == TCP_SERVER_TO_CLIENT) && (s->ServerMode)) || ((ts->Direction == TCP_CLIENT_TO_SERVER) && (s->ServerMode == false)))

#define IS_RECV_TCP_SOCK(ts) \
	((ts->Direction == TCP_BOTH) || ((ts->Direction == TCP_SERVER_TO_CLIENT) && (s->ServerMode == false)) || ((ts->Direction == TCP_CLIENT_TO_SERVER) && (s->ServerMode)))

static void WriteSendFifo(TCPSOCK *ts, const void *data, UINT size) {
	if (ts == NULL || data == NULL)
		return;

	WriteFifo(ts->SendFifo, data, size);
}

static void WriteRecvFifo(TCPSOCK *ts, const void *data, UINT size) {
	if (ts == NULL || data == NULL)
		return;

	WriteFifo(ts->RecvFifo, data, size);
}

void InsertReceivedBlockToQueue(CONNECTION *c, BLOCK *block) {
	if (c == NULL || block == NULL)
		return;

	SESSION *s = c->Session;

	if (c->Protocol == CONNECTION_TCP) {
		s->TotalRecvSizeReal += block->SizeofData;
		s->TotalRecvSize += block->Size;
	}

	if (c->ReceivedBlocks->num_item < MAX_STORED_QUEUE_NUM)
		InsertQueue(c->ReceivedBlocks, block);
	else
		FreeBlock(block);
}

// Queues one block received from the peer, or drops it when it is oversized or the Cedar queue budget is
// spent. A queued block then syncs the queue budget: every block when packet_index is NULL, else every
// 32nd block counted through *packet_index
static void ConnectionEnqueueReceivedBlock(CONNECTION *c, BLOCK *b, UINT *packet_index) {
	if (b->Size > MAX_PACKET_SIZE || CedarGetQueueBudgetBalance(c->Cedar) == 0) {
		FreeBlock(b);
		return;
	}

	InsertReceivedBlockToQueue(c, b);

	if (packet_index == NULL || (*packet_index % 32) == 0)
		CedarSyncQueueBudget(c->Cedar, c->ReceivedBlocks->num_item, &c->LastRecvBlocksNum);

	if (packet_index != NULL)
		(*packet_index)++;
}

// Randomize the Keep-Alive interval to spread network load.
UINT GenNextKeepAliveSpan(CONNECTION *c) {
	if (c == NULL)
		return INFINITE;

	// Clamped to the bounds of ServerAccept: a timeout below 2 would divide by zero
	UINT a = MAKESURE(c->Session->Timeout, TIMEOUT_MIN, TIMEOUT_MAX);
	UINT b = Rand32() % (a / 2);
	b = MAX(b, a / 5);

	return b;
}

static void SendKeepAlive(CONNECTION *c, TCPSOCK *ts) {
	if (c == NULL || ts == NULL)
		return;

	SESSION *s = c->Session;
	if (s == NULL)
		return;

	UINT size = Rand32() % MAX_KEEPALIVE_SIZE;
	UINT num = KEEP_ALIVE_MAGIC;

	UCHAR *buf = Malloc(size);
	Rand(buf, size);

	num = Endian32(num);
	UINT size_be = Endian32(size);
	WriteSendFifo(ts, &num, sizeof(UINT));
	WriteSendFifo(ts, &size_be, sizeof(UINT));
	WriteSendFifo(ts, buf, size);

	c->Session->TotalSendSize += sizeof(UINT) * 2 + size;
	c->Session->TotalSendSizeReal += sizeof(UINT) * 2 + size;

	Free(buf);
}

void ConnectionSend(CONNECTION *c, UINT64 now) {
	UINT i, num;
	UINT min_count;
	TCPSOCK **tcpsocks;
	UINT size;
	SESSION *s;
	bool use_qos = false;
	if (c == NULL)
		return;

	s = c->Session;

	use_qos = s->QoS;

	if (c->Protocol == CONNECTION_TCP) {
		TCP *tcp = c->Tcp;
		TCPSOCK *ts;
		TCPSOCK *ts_hp;
		UINT num_available;
		UINT tcp_queue_size = 0;
		int tcp_queue_size_diff = 0;
		LockList(tcp->TcpSockList);
		{
			num = LIST_NUM(tcp->TcpSockList);
			tcpsocks = ToArrayEx(tcp->TcpSockList, true);
		}
		UnlockList(tcp->TcpSockList);

		min_count = INFINITE;
		ts = NULL;
		ts_hp = NULL;

		num_available = 0;

		for (i = 0; i < num; i++) {
			TCPSOCK *tcpsock = tcpsocks[i];
			if (tcpsock->Sock->Connected && tcpsock->Sock->AsyncMode &&
			    IS_SEND_TCP_SOCK(tcpsock)) {
				if (now >= tcpsock->NextKeepAliveTime || tcpsock->NextKeepAliveTime == 0) {
					SendKeepAlive(c, tcpsock);
					tcpsock->NextKeepAliveTime = now + (UINT64)GenNextKeepAliveSpan(c);
				}

				num_available++;

				ts_hp = tcpsock;
			}
		}

		for (i = 0; i < num; i++) {
			TCPSOCK *tcpsock = tcpsocks[i];
			if (tcpsock->Sock->Connected && tcpsock->Sock->AsyncMode &&
			    IS_SEND_TCP_SOCK(tcpsock)) {
				bool b = false;

				if (use_qos == false)
					b = true;
				else if (num_available < 2)
					b = true;
				else if (tcpsock != ts_hp)
					b = true;

				if (b) {
					if (tcpsock->LateCount <= min_count) {
						min_count = tcpsock->LateCount;
						ts = tcpsock;
					}
				}
			}

			tcp_queue_size += tcpsock->SendFifo->size;
		}

		tcp_queue_size_diff = ((int)tcp_queue_size) - ((int)c->LastTcpQueueSize);

		CedarAddCurrentTcpQueueSize(c->Cedar, tcp_queue_size_diff);

		c->LastTcpQueueSize = tcp_queue_size;

		if (ts_hp == NULL)
			ts_hp = ts;

		if (use_qos == false)
			ts_hp = ts;

		if (ts != NULL && ts_hp != NULL) {
			TCPSOCK *tss;
			QUEUE *q;

			if (s->UdpAccel != NULL)
				UdpAccelSetTick(s->UdpAccel, now);

			for (UINT j = 0; j < 2; j++) {
				if (j == 0) {
					q = c->SendBlocks2;
					tss = ts_hp;
				} else {
					q = c->SendBlocks;
					tss = ts;
				}
				if (q->num_item != 0) {
					UINT num_data;
					BLOCK *b;
					UINT size_quota_v1 = MAX_SEND_SOCKET_QUEUE_SIZE / s->MaxConnection;
					UINT size_quota_v2 = MIN_SEND_SOCKET_QUEUE_SIZE;
					UINT size_quota = MAX(size_quota_v1, size_quota_v2);

					if (tss->SendFifo->size >= size_quota) {
						while (b = GetNext(q)) {
							if (b != NULL) {
								c->CurrentSendQueueSize -= b->Size;
								FreeBlock(b);
							}
						}
					} else if (s->UseUdpAcceleration && s->UdpAccel != NULL && UdpAccelIsSendReady(s->UdpAccel, true)) {
						while (b = GetNext(q)) {
							UdpAccelSendBlock(s->UdpAccel, b);

							s->TotalSendSize += b->Size;
							s->TotalSendSizeReal += b->Size;

							c->CurrentSendQueueSize -= b->Size;

							FreeBlock(b);
						}
					} else {
						bool update_keepalive_timer = false;
						num_data = Endian32(q->num_item);
						WriteSendFifo(tss, &num_data, sizeof(UINT));

						s->TotalSendSize += sizeof(UINT);
						s->TotalSendSizeReal += sizeof(UINT);

						while (b = GetNext(q)) {
							UINT size_data;
							size_data = Endian32(b->Size);
							WriteSendFifo(tss, &size_data, sizeof(UINT));

							c->CurrentSendQueueSize -= b->Size;

							s->TotalSendSize += sizeof(UINT);
							s->TotalSendSizeReal += sizeof(UINT);

							WriteSendFifo(tss, b->Buf, b->Size);

							s->TotalSendSize += b->SizeofData;
							s->TotalSendSizeReal += b->Size;

							update_keepalive_timer = true;

							FreeBlock(b);
						}

						if (s->UseUdpAcceleration && s->UdpAccel != NULL && UdpAccelIsSendReady(s->UdpAccel, false))
							update_keepalive_timer = false;

						if (update_keepalive_timer)
							tss->NextKeepAliveTime = now + (UINT64)GenNextKeepAliveSpan(c);
					}
				}
			}
		}

		for (i = 0; i < num; i++) {
			ts = tcpsocks[i];

		SEND_START:
			if (ts->Sock->Connected == false) {
				s->LastTryAddConnectTime = Tick64();
				LockList(tcp->TcpSockList);
				{
					Delete(tcp->TcpSockList, ts);
					FreeTcpSock(ts);
					Dec(c->CurrentNumConnection);
				}
				UnlockList(tcp->TcpSockList);

				continue;
			}

			if (ts->SendFifo->size != 0) {
				UCHAR *buf;
				UINT want_send_size;
				buf = (UCHAR *)ts->SendFifo->p + ts->SendFifo->pos;
				want_send_size = ts->SendFifo->size;

				size = Send(ts->Sock, buf, want_send_size, s->UseEncrypt);

				if (size == 0) {
					continue;
				} else if (size == SOCK_LATER) {
					ts->LateCount++;
				} else {
					ReadFifo(ts->SendFifo, NULL, size);
					if (size >= want_send_size)
						ts->LateCount = 0;
					UPDATE_LAST_COMM_TIME(c->Session->LastCommTime, now);

					goto SEND_START;
				}
			}
		}

		Free(tcpsocks);
	} else if (c->Protocol == CONNECTION_HUB_LINK_SERVER) {
		LINK *k = (LINK *)s->Link;

		if (k != NULL) {
			UINT num_blocks = 0;
			LockQueue(k->SendPacketQueue);
			{
				BLOCK *block;

				while (block = GetNext(c->SendBlocks)) {
					c->CurrentSendQueueSize -= block->Size;

					if (k->SendPacketQueue->num_item >= MAX_STORED_QUEUE_NUM) {
						FreeBlock(block);
					} else {
						num_blocks++;
						InsertQueue(k->SendPacketQueue, block);
					}
				}
			}
			UnlockQueue(k->SendPacketQueue);

			if (num_blocks != 0)
				Cancel(k->ClientSession->Cancel1);
		}
	} else if (c->Protocol == CONNECTION_HUB_BRIDGE) {
		BrSendBlocks(c);
	} else if (c->Protocol == CONNECTION_NOISE) {
		TunnelSendBlocks(c);
	}
}

void ConnectionReceive(CONNECTION *c, CANCEL *c1, CANCEL *c2) {
	UINT i, num;
	SOCKSET set;
	SESSION *s;
	TCPSOCK **tcpsocks;
	UCHAR *buf;
	UINT size;
	UINT time;
	UINT num_delayed = 0;
	bool no_spinlock_for_delay = false;
	UINT64 now = Tick64();
	HUB *hub = NULL;
	if (c == NULL)
		return;


	s = c->Session;

	hub = s->Hub;

	if (hub != NULL)
		no_spinlock_for_delay = hub->Option->NoSpinLockForPacketDelay;

	if (c->RecvBuf == NULL)
		c->RecvBuf = Malloc(RECV_BUF_SIZE);
	buf = c->RecvBuf;

	if (c->Protocol == CONNECTION_TCP) {
		TCP *tcp = c->Tcp;
		UINT next_delay_packet_diff = 0;
		UINT current_recv_fifo_size = 0;
		int recv_fifo_size_middle_update = 0;
		int fifo_diff;

		if (s->ServerMode == false) {
			if (s->ClientOption->ConnectionDisconnectSpan != 0) {
				LockList(tcp->TcpSockList);
				{
					for (UINT i = 0; i < LIST_NUM(tcp->TcpSockList); i++) {
						TCPSOCK *ts = LIST_DATA(tcp->TcpSockList, i);
						if (ts->DisconnectTick != 0 &&
						    ts->DisconnectTick <= now)
							Disconnect(ts->Sock);
					}
				}
				UnlockList(tcp->TcpSockList);
			}
		}

		if (s->HalfConnection && (s->ServerMode == false)) {
			// If the connection count is at the limit and all sockets share one direction, disconnect one.
			LockList(tcp->TcpSockList);
			{
				UINT num;
				UINT c2s, s2c;
				c2s = s2c = 0;
				num = LIST_NUM(tcp->TcpSockList);
				if (num >= s->MaxConnection) {
					TCPSOCK *ts;
					for (UINT i = 0; i < num; i++) {
						ts = LIST_DATA(tcp->TcpSockList, i);
						if (ts->Direction == TCP_SERVER_TO_CLIENT)
							s2c++;
						else
							c2s++;
					}
					if (s2c == 0 || c2s == 0)
						Disconnect(ts->Sock);
				}
			}
			UnlockList(tcp->TcpSockList);
		}

		InitSockSet(&set);
		LockList(tcp->TcpSockList);
		{
			num = LIST_NUM(tcp->TcpSockList);
			tcpsocks = ToArrayEx(tcp->TcpSockList, true);
		}
		UnlockList(tcp->TcpSockList);

		for (i = 0; i < num; i++)
			AddSockSet(&set, tcpsocks[i]->Sock);

		if (s->UseUdpAcceleration && s->UdpAccel != NULL) {
			if (s->UdpAccel->UdpSock != NULL)
				AddSockSet(&set, s->UdpAccel->UdpSock);
		}

		time = SELECT_TIME;
		next_delay_packet_diff = GetNextDelayedPacketTickDiff(s);
		time = MIN(time, next_delay_packet_diff);
		if (s->UseUdpAcceleration && UdpAccelIsRecvBudgetSpent(s->UdpAccel)) {
			// The per-tick receive budget is spent and no read re-arms the socket event:
			// come back on the next tick instead of after SELECT_TIME
			time = MIN(time, 1);
		}
		num_delayed = LIST_NUM(s->DelayedPacketList);


		if (s->Flag1 != set.NumSocket) {
			Select(&set, (num_delayed == 0 ? time : 1), c1, c2);
			s->Flag1 = set.NumSocket;
		} else if (no_spinlock_for_delay || time >= 50 || num_delayed == false) {
			Select(&set, (num_delayed == 0 ? time : (time > 100 ? (time - 100) : 1)), c1, c2);
			s->Flag1 = set.NumSocket;
		} else {
			YieldCpu();
		}

		now = Tick64();


		if (s->UseUdpAcceleration && s->UdpAccel != NULL) {
			UdpAccelSetTick(s->UdpAccel, now);
			UdpAccelPoll(s->UdpAccel);

			if (s->UdpAccelMss == 0)
				s->UdpAccelMss = UdpAccelCalcMss(s->UdpAccel);

			while (true) {
				BLOCK *b = GetNext(s->UdpAccel->RecvBlockQueue);

				if (b == NULL)
					break;

				ConnectionEnqueueReceivedBlock(c, b, NULL);
			}
		}

		s->IsUsingUdpAcceleration = UdpAccelIsSendReady(s->UdpAccel, true);

		for (i = 0; i < num; i++) {
			TCPSOCK *ts = tcpsocks[i];

			UINT current_fifo_budget = 0;
			UINT current_packet_index = 0;
			if (ts->WantSize == 0)
				ts->WantSize = sizeof(UINT);

			now = Tick64();

		RECV_START:
			current_fifo_budget = CedarGetFifoBudgetBalance(c->Cedar);
			if (ts->RecvFifo->size < current_fifo_budget) {
				UINT recv_buf_size = current_fifo_budget - ts->RecvFifo->size;

				recv_buf_size = MIN(recv_buf_size, RECV_BUF_SIZE);

				size = Recv(ts->Sock, buf, recv_buf_size, s->UseEncrypt);
			} else {
				size = SOCK_LATER;

				UPDATE_LAST_COMM_TIME(c->Session->LastCommTime, now);
				UPDATE_LAST_COMM_TIME(ts->LastCommTime, now);
			}


			if (size == 0) {
			DISCONNECT_THIS_TCP:
				s->LastTryAddConnectTime = Tick64();
				LockList(tcp->TcpSockList);
				{
					Delete(tcp->TcpSockList, ts);
					FreeTcpSock(ts);
					Dec(c->CurrentNumConnection);
				}
				UnlockList(tcp->TcpSockList);

				continue;
			} else if (size == SOCK_LATER) {
				if (IS_RECV_TCP_SOCK(ts)) {
					if ((now > ts->LastCommTime) && ((now - ts->LastCommTime) >= ((UINT64)s->Timeout)))
						goto DISCONNECT_THIS_TCP;
				}
			} else {
				UINT budget_balance = CedarGetFifoBudgetBalance(c->Cedar);
				UINT fifo_size_limit = budget_balance;

				if (fifo_size_limit > MAX_BUFFERING_PACKET_SIZE)
					fifo_size_limit = MAX_BUFFERING_PACKET_SIZE;

				UPDATE_LAST_COMM_TIME(c->Session->LastCommTime, now);

				CedarAddFifoBudget(c->Cedar, (int)size);
				recv_fifo_size_middle_update += (int)size;

				WriteRecvFifo(ts, buf, size);

				if (ts->RecvFifo->size < fifo_size_limit)
					goto RECV_START;
			}

			current_recv_fifo_size += FifoSize(ts->RecvFifo);

			while (ts->RecvFifo->size >= ts->WantSize) {
				UCHAR *buf;
				void *data;
				BLOCK *block;
				UINT sz;
				buf = (UCHAR *)ts->RecvFifo->p + ts->RecvFifo->pos;

				switch (ts->Mode) {
				case 0:
					ts->WantSize = sizeof(UINT);
					Copy(&sz, buf, sizeof(UINT));
					sz = Endian32(sz);
					ts->NextBlockNum = sz;
					ReadFifo(ts->RecvFifo, NULL, sizeof(UINT));

					s->TotalRecvSize += sizeof(UINT);
					s->TotalRecvSizeReal += sizeof(UINT);

					ts->CurrentPacketNum = 0;
					if (ts->NextBlockNum != 0) {
						if (ts->NextBlockNum == KEEP_ALIVE_MAGIC)
							ts->Mode = 3;
						else
							ts->Mode = 1;
					}
					break;

				case 1:
					Copy(&sz, buf, sizeof(UINT));
					sz = Endian32(sz);
					if (sz > (MAX_PACKET_SIZE * 2))
						Disconnect(ts->Sock);
					ts->NextBlockSize = MIN(sz, MAX_PACKET_SIZE * 2);
					ReadFifo(ts->RecvFifo, NULL, sizeof(UINT));

					s->TotalRecvSize += sizeof(UINT);
					s->TotalRecvSizeReal += sizeof(UINT);

					ts->WantSize = ts->NextBlockSize;
					if (ts->WantSize != 0) {
						ts->Mode = 2;
					} else {
						ts->Mode = 1;
						ts->WantSize = sizeof(UINT);
						ts->CurrentPacketNum++;
						if (ts->CurrentPacketNum >= ts->NextBlockNum)
							ts->Mode = 0;
					}
					break;

				case 2:
					ts->WantSize = sizeof(UINT);
					ts->CurrentPacketNum++;
					data = Malloc(ts->NextBlockSize);
					Copy(data, buf, ts->NextBlockSize);
					ReadFifo(ts->RecvFifo, NULL, ts->NextBlockSize);
					block = NewBlock(data, ts->NextBlockSize, s->UseCompress ? -1 : 0);

					UPDATE_LAST_COMM_TIME(c->Session->LastCommTime, now);
					UPDATE_LAST_COMM_TIME(ts->LastCommTime, now);

					ConnectionEnqueueReceivedBlock(c, block, &current_packet_index);

					if (ts->CurrentPacketNum >= ts->NextBlockNum)
						ts->Mode = 0;
					else
						ts->Mode = 1;
					break;

				case 3:
					ts->Mode = 4;
					Copy(&sz, buf, sizeof(UINT));
					sz = Endian32(sz);
					if (sz > MAX_KEEPALIVE_SIZE)
						Disconnect(ts->Sock);
					ts->NextBlockSize = MIN(sz, MAX_KEEPALIVE_SIZE);
					ReadFifo(ts->RecvFifo, NULL, sizeof(UINT));

					UPDATE_LAST_COMM_TIME(c->Session->LastCommTime, now);
					UPDATE_LAST_COMM_TIME(ts->LastCommTime, now);

					s->TotalRecvSize += sizeof(UINT);
					s->TotalRecvSizeReal += sizeof(UINT);

					ts->WantSize = sz;
					break;

				case 4:
					ts->Mode = 0;
					sz = ts->NextBlockSize;

					ReadFifo(ts->RecvFifo, NULL, sz);

					UPDATE_LAST_COMM_TIME(c->Session->LastCommTime, now);
					UPDATE_LAST_COMM_TIME(ts->LastCommTime, now);

					s->TotalRecvSize += sz;
					s->TotalRecvSizeReal += sz;

					ts->WantSize = sizeof(UINT);
					break;
				}
			}

			ShrinkFifoMemory(ts->RecvFifo);
		}

		fifo_diff = (int)current_recv_fifo_size - (int)c->LastRecvFifoTotalSize;

		CedarAddFifoBudget(c->Cedar, (fifo_diff - recv_fifo_size_middle_update));

		c->LastRecvFifoTotalSize = current_recv_fifo_size;

		CedarSyncQueueBudget(c->Cedar, c->ReceivedBlocks->num_item, &c->LastRecvBlocksNum);

		Free(tcpsocks);
	} else if (c->Protocol == CONNECTION_HUB_LINK_SERVER) {
		if (c->SendBlocks->num_item == 0) {
			UINT time = SELECT_TIME;
			UINT next_delay_packet_diff = 0;

			next_delay_packet_diff = GetNextDelayedPacketTickDiff(s);
			time = MIN(time, next_delay_packet_diff);
			num_delayed = LIST_NUM(s->DelayedPacketList);

			if (no_spinlock_for_delay || time >= 50 || num_delayed == false)
				Select(NULL, (num_delayed == 0 ? time : (time > 100 ? (time - 100) : 1)), c1, c2);
			else
				YieldCpu();
		}
	} else if (c->Protocol == CONNECTION_HUB_BRIDGE) {
		BrReceiveBlocks(c, c1, c2);
	} else if (c->Protocol == CONNECTION_NOISE) {
		TunnelReceiveBlocks(c, c1, c2);
	}
}

void FreeBlock(BLOCK *b) {
	if (b == NULL)
		return;

	Free(b->Buf);
	Free(b);
}

// Frees the blocks still in q, then q itself
void FreeBlockQueue(QUEUE *q) {
	BLOCK *b;
	if (q == NULL)
		return;

	LockQueue(q);
	{
		while (b = GetNext(q))
			FreeBlock(b);
	}
	UnlockQueue(q);

	ReleaseQueue(q);
}

BLOCK *NewBlock(void *data, UINT size, int compress) {
	if (data == NULL)
		return NULL;

	BLOCK *b = Malloc(sizeof(BLOCK));

	b->IsFlooding = false;

	b->PriorityQoS = false;

	if (compress == 0) {
		b->Compressed = false;
		b->Buf = data;
		b->Size = size;
		b->SizeofData = size;
	} else if (compress == 1) {
		b->Compressed = true;
		UINT max_size = CalcCompress(size);
		b->Buf = Malloc(max_size);
		b->Size = Compress(b->Buf, max_size, data, size);
		b->SizeofData = size;

		Free(data);
	} else {
		b->Compressed = false;
		UINT max_size = MAX_PACKET_SIZE;
		b->Buf = Malloc(max_size);
		b->Size = Uncompress(b->Buf, max_size, data, size);
		b->SizeofData = size;

		Free(data);
	}

	return b;
}

TCPSOCK *NewTcpSock(SOCK *s) {
	if (s == NULL)
		return NULL;

	TCPSOCK *ts = ZeroMalloc(sizeof(TCPSOCK));

	ts->Sock = s;
	AddRef(s->ref);

	ts->RecvFifo = NewFifo();
	ts->SendFifo = NewFifo();
	ts->LastCommTime = Tick64();

	SetTimeout(s, TIMEOUT_INFINITE);

	return ts;
}

void FreeTcpSock(TCPSOCK *ts) {
	if (ts == NULL)
		return;

	Disconnect(ts->Sock);
	ReleaseSock(ts->Sock);
	ReleaseFifo(ts->RecvFifo);
	ReleaseFifo(ts->SendFifo);

	Free(ts);
}

void EndTunnelingMode(CONNECTION *c) {
	if (c == NULL)
		return;

	if (c->Protocol == CONNECTION_TCP)
		DisconnectTcpSockets(c);
}

void StartTunnelingMode(CONNECTION *c) {
	SOCK *s;
	TCPSOCK *ts;
	if (c == NULL)
		return;

	TCP *tcp = c->Tcp;

	if (c->Protocol == CONNECTION_TCP) {
		s = c->FirstSock;

		ts = NewTcpSock(s);

		if (c->ServerMode == false) {
			if (c->Session->ClientOption->ConnectionDisconnectSpan != 0)
				ts->DisconnectTick = Tick64() + c->Session->ClientOption->ConnectionDisconnectSpan * (UINT64)1000;
		}

		LockList(tcp->TcpSockList);
		{
			Add(tcp->TcpSockList, ts);
		}
		UnlockList(tcp->TcpSockList);
		Lock(c->lock);
		{
			c->FirstSock = NULL;
		}
		Unlock(c->lock);
		ReleaseSock(s);
	}
}

// The Cedar error of a TLS_ERR_* result of StartSSLEx3 or StartSSLServer (ERR_NO_ERROR for TLS_ERR_NONE)
UINT TlsErrToCedarErr(UINT tls_err) {
	switch (tls_err) {
	case TLS_ERR_NONE:
		return ERR_NO_ERROR;
	case TLS_ERR_CERT_NOT_TRUSTED:
		return ERR_CERT_NOT_TRUSTED;
	case TLS_ERR_CERT_EXPIRED:
		return ERR_SERVER_CERT_EXPIRES;
	case TLS_ERR_HOSTNAME_MISMATCH:
		return ERR_HOSTNAME_MISMATCH;
	case TLS_ERR_PROTOCOL_VERSION:
		return ERR_SSL_PROTOCOL_VERSION;
	case TLS_ERR_SHARED_CIPHER:
		return ERR_SSL_SHARED_CIPHER;
	default:
		return ERR_SSL_HANDSHAKE;
	}
}

void StopAllAdditionalConnectThread(CONNECTION *c) {
	UINT num;
	SOCK **socks;
	THREAD **threads;
	if (c == NULL || c->ServerMode != false)
		return;

	LockList(c->ConnectingSocks);
	{
		num = LIST_NUM(c->ConnectingSocks);
		socks = ToArray(c->ConnectingSocks);
		DeleteAll(c->ConnectingSocks);
	}
	UnlockList(c->ConnectingSocks);
	for (UINT i = 0; i < num; i++) {
		Disconnect(socks[i]);
		ReleaseSock(socks[i]);
	}
	Free(socks);

	LockList(c->ConnectingThreads);
	{
		num = LIST_NUM(c->ConnectingThreads);
		threads = ToArray(c->ConnectingThreads);
		DeleteAll(c->ConnectingThreads);
	}
	UnlockList(c->ConnectingThreads);
	for (UINT i = 0; i < num; i++) {
		WaitThread(threads[i], INFINITE);
		ReleaseThread(threads[i]);
	}
	Free(threads);
}

void StopConnection(CONNECTION *c, bool no_wait) {
	SOCK *s;
	if (c == NULL)
		return;


	FlagWrite(&c->Halt, true);

	// The connection thread clears c->FirstSock under c->lock before it releases the socket:
	// take a ref under the same lock so the socket outlives the Disconnect
	Lock(c->lock);
	{
		s = c->FirstSock;
		if (s != NULL)
			AddRef(s->ref);
	}
	Unlock(c->lock);

	Disconnect(s);
	ReleaseSock(s);

	if (no_wait == false)
		WaitThread(c->Thread, INFINITE);
}

void DisconnectTcpSockets(CONNECTION *c) {
	UINT num;
	TCPSOCK **tcpsocks;
	if (c == NULL)
		return;
	if (c->Protocol != CONNECTION_TCP)
		return;

	TCP *tcp = c->Tcp;
	LockList(tcp->TcpSockList);
	{
		tcpsocks = ToArray(tcp->TcpSockList);
		num = LIST_NUM(tcp->TcpSockList);
		DeleteAll(tcp->TcpSockList);
	}
	UnlockList(tcp->TcpSockList);

	if (num != 0) {
		for (UINT i = 0; i < num; i++) {
			TCPSOCK *ts = tcpsocks[i];
			FreeTcpSock(ts);
		}
	}

	Free(tcpsocks);
}

static void CleanupConnection(CONNECTION *c) {
	UINT num;
	if (c == NULL)
		return;

	if (c->LastRecvFifoTotalSize != 0) {
		CedarAddFifoBudget(c->Cedar, -((int)c->LastRecvFifoTotalSize));
		c->LastRecvFifoTotalSize = 0;
	}

	CedarSyncQueueBudget(c->Cedar, 0, &c->LastRecvBlocksNum);

	if (c->LastTcpQueueSize != 0) {
		int diff = -((int)c->LastTcpQueueSize);
		CedarAddCurrentTcpQueueSize(c->Cedar, diff);
		c->LastTcpQueueSize = 0;
	}

	if (c->LastPacketQueueSize != 0) {
		int diff = -((int)c->LastPacketQueueSize);
		CedarAddCurrentTcpQueueSize(c->Cedar, diff);
		c->LastPacketQueueSize = 0;
	}

	DeleteLock(c->lock);
	ReleaseCedar(c->Cedar);

	DisconnectTcpSockets(c);
	FreeTunnel(c);

	ReleaseList(c->Tcp->TcpSockList);
	Free(c->Tcp);

	ReleaseSock(c->FirstSock);
	c->FirstSock = NULL;

	ReleaseThread(c->Thread);
	Free(c->Name);

	FreeBlockQueue(c->SendBlocks);
	FreeBlockQueue(c->SendBlocks2);
	FreeBlockQueue(c->ReceivedBlocks);

	if (c->ConnectingThreads) {
		THREAD **threads;
		LockList(c->ConnectingThreads);
		{
			num = LIST_NUM(c->ConnectingThreads);
			threads = ToArray(c->ConnectingThreads);
			for (UINT i = 0; i < num; i++)
				ReleaseThread(threads[i]);
			Free(threads);
		}
		UnlockList(c->ConnectingThreads);
		ReleaseList(c->ConnectingThreads);
	}

	if (c->ConnectingSocks) {
		SOCK **socks;
		LockList(c->ConnectingSocks);
		{
			num = LIST_NUM(c->ConnectingSocks);
			socks = ToArray(c->ConnectingSocks);
			for (UINT i = 0; i < num; i++) {
				Disconnect(socks[i]);
				ReleaseSock(socks[i]);
			}
			Free(socks);
		}
		UnlockList(c->ConnectingSocks);
		ReleaseList(c->ConnectingSocks);
	}

	if (c->RecvBuf)
		Free(c->RecvBuf);

	if (c->ServerX != NULL)
		FreeX(c->ServerX);

	if (c->ClientX != NULL)
		FreeX(c->ClientX);

	DeleteCounter(c->CurrentNumConnection);

	if (c->CipherName != NULL)
		Free(c->CipherName);

	if (c->SslVersion != NULL)
		Free(c->SslVersion);

	Free(c);
}

void ReleaseConnection(CONNECTION *c) {
	if (c == NULL)
		return;

	if (Release(c->ref) == 0)
		CleanupConnection(c);
}

int CompareConnection(void *p1, void *p2) {
	if (p1 == NULL || p2 == NULL)
		return 0;
	CONNECTION *c1 = *(CONNECTION **)p1;
	CONNECTION *c2 = *(CONNECTION **)p2;
	if (c1 == NULL || c2 == NULL)
		return 0;

	return StrCmpi(c1->Name, c2->Name);
}

// The fields both constructors set the same way: the TCP state, the three block queues and the connection counter
static CONNECTION *NewConnectionBase(CEDAR *cedar, bool server_mode) {
	CONNECTION *c = ZeroMalloc(sizeof(CONNECTION));
	c->ConnectedTick = Tick64();
	c->lock = NewLock();
	c->ref = NewRef();
	c->Cedar = cedar;
	AddRef(c->Cedar->ref);
	c->Protocol = CONNECTION_TCP;
	c->Tcp = ZeroMalloc(sizeof(TCP));
	c->Tcp->TcpSockList = NewList(NULL);
	c->ServerMode = server_mode;
	c->CurrentNumConnection = NewCounter();
	Inc(c->CurrentNumConnection);

	c->ReceivedBlocks = NewQueue();
	c->SendBlocks = NewQueue();
	c->SendBlocks2 = NewQueue();

	return c;
}

CONNECTION *NewServerConnection(CEDAR *cedar, SOCK *s, THREAD *t) {
	if (cedar == NULL)
		return NULL;

	CONNECTION *c = NewConnectionBase(cedar, true);
	c->Type = CONNECTION_TYPE_INIT;
	c->FirstSock = s;
	if (s != NULL) {
		AddRef(c->FirstSock->ref);
		Copy(&c->ClientIp, &s->RemoteIP, sizeof(IP));
		StrCpy(c->ClientHostname, sizeof(c->ClientHostname), s->RemoteHostname);
	}
	c->Status = CONNECTION_STATUS_ACCEPTED;
	c->Name = CopyStr("INITING");
	c->Thread = t;
	AddRef(t->ref);

	c->ServerVer = cedar->Version;
	c->ServerBuild = cedar->Build;
	StrCpy(c->ServerStr, sizeof(c->ServerStr), cedar->ServerStr);
	GetServerProductName(cedar->Server, c->ServerStr, sizeof(c->ServerStr));

	if (s != NULL && s->RemoteX != NULL)
		c->ServerX = CloneX(s->RemoteX);

	return c;
}

CONNECTION *NewClientConnectionEx(SESSION *s, char *client_str) {
	CONNECTION *c = NewConnectionBase(s->Cedar, false);
	c->Status = CONNECTION_STATUS_CONNECTING;
	c->Name = CopyStr("CLIENT_CONNECTION");
	c->Session = s;
	c->LastCounterResetTick = Tick64();

	c->ConnectingThreads = NewList(NULL);
	c->ConnectingSocks = NewList(NULL);

	c->ClientVer = s->Cedar->Version;
	c->ClientBuild = s->Cedar->Build;

	if (client_str == NULL)
		if (c->Session->LinkModeClient == false)
			StrCpy(c->ClientStr, sizeof(c->ClientStr), CEDAR_CLIENT_STR);
		else
			StrCpy(c->ClientStr, sizeof(c->ClientStr), CEDAR_SERVER_LINK_STR);
	else
		StrCpy(c->ClientStr, sizeof(c->ClientStr), client_str);

	StrCpy(c->ServerName, sizeof(c->ServerName), s->ClientOption->Hostname);
	c->ServerPort = s->ClientOption->Port;

	return c;
}

// Copy what the admin RPCs report about the connection; the caller may hold the Cedar's ConnectionList
void ConnectionGetInfo(CONNECTION *c, CONNECTION_INFO *info) {
	if (info == NULL)
		return;

	Zero(info, sizeof(CONNECTION_INFO));

	if (c == NULL)
		return;

	Lock(c->lock);
	{
		SOCK *s = c->FirstSock;

		if (s != NULL) {
			Copy(&info->RemoteIp, &s->RemoteIP, sizeof(IP));
			info->RemotePort = s->RemotePort;
			StrCpy(info->RemoteHostname, sizeof(info->RemoteHostname), s->RemoteHostname);
		}

		StrCpy(info->Name, sizeof(info->Name), c->Name);
		info->ConnectedTick = c->ConnectedTick;
		info->Type = c->Type;

		StrCpy(info->ServerStr, sizeof(info->ServerStr), c->ServerStr);
		StrCpy(info->ClientStr, sizeof(info->ClientStr), c->ClientStr);
		info->ServerVer = c->ServerVer;
		info->ServerBuild = c->ServerBuild;
		info->ClientVer = c->ClientVer;
		info->ClientBuild = c->ClientBuild;
	}
	Unlock(c->lock);
}

void GetServerProductName(SERVER *s, char *name, UINT size) {
	if (s == NULL || name == NULL)
		return;

	StrCpy(name, size, CEDAR_SERVER_STR " (64 bit)");
}
