// Connection.c
// Connection Manager

#include "Connection.h"

#include "BridgeWin32.h"
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

#include <stdlib.h>

#define	IS_SEND_TCP_SOCK(ts)		\
	((ts->Direction == TCP_BOTH) || ((ts->Direction == TCP_SERVER_TO_CLIENT) && (s->ServerMode)) || ((ts->Direction == TCP_CLIENT_TO_SERVER) && (s->ServerMode == false)))

#define	IS_RECV_TCP_SOCK(ts)		\
	((ts->Direction == TCP_BOTH) || ((ts->Direction == TCP_SERVER_TO_CLIENT) && (s->ServerMode == false)) || ((ts->Direction == TCP_CLIENT_TO_SERVER) && (s->ServerMode)))

CLIENT_AUTH *CopyClientAuth(CLIENT_AUTH *a)
{
	CLIENT_AUTH *ret;
	if (a == NULL)
	{
		return NULL;
	}

	ret = ZeroMallocEx(sizeof(CLIENT_AUTH), true);

	ret->AuthType = a->AuthType;
	StrCpy(ret->Username, sizeof(ret->Username), a->Username);

	switch (a->AuthType)
	{
	case CLIENT_AUTHTYPE_ANONYMOUS:
		break;

	case CLIENT_AUTHTYPE_PASSWORD:
		Copy(ret->HashedPassword, a->HashedPassword, SHA1_SIZE);
		break;

	case CLIENT_AUTHTYPE_PLAIN_PASSWORD:
		StrCpy(ret->PlainPassword, sizeof(ret->PlainPassword), a->PlainPassword);
		break;

	case CLIENT_AUTHTYPE_CERT:
		ret->ClientX = CloneX(a->ClientX);
		ret->ClientK = CloneK(a->ClientK);
		break;

	case CLIENT_AUTHTYPE_OPENSSLENGINE:
		ret->ClientX = CloneX(a->ClientX);
		StrCpy(ret->OpensslEnginePrivateKeyName, sizeof(ret->OpensslEnginePrivateKeyName), a->OpensslEnginePrivateKeyName);
		StrCpy(ret->OpensslEngineName, sizeof(ret->OpensslEngineName), a->OpensslEngineName);
    ret->ClientK = OpensslEngineToK(ret->OpensslEnginePrivateKeyName, ret->OpensslEngineName);
		break;
	}

	return ret;
}

static void WriteSendFifo(SESSION *s, TCPSOCK *ts, void *data, UINT size)
{
	if (s == NULL || ts == NULL || data == NULL)
	{
		return;
	}

	WriteFifo(ts->SendFifo, data, size);
}

static void WriteRecvFifo(SESSION *s, TCPSOCK *ts, void *data, UINT size)
{
	if (s == NULL || ts == NULL || data == NULL)
	{
		return;
	}

	WriteFifo(ts->RecvFifo, data, size);
}

void InsertReceivedBlockToQueue(CONNECTION *c, BLOCK *block)
{
	SESSION *s;
	if (c == NULL || block == NULL)
	{
		return;
	}

	s = c->Session;
	
	if (c->Protocol == CONNECTION_TCP)
	{
		s->TotalRecvSizeReal += block->SizeofData;
		s->TotalRecvSize += block->Size;
	}

	if (c->ReceivedBlocks->num_item < MAX_STORED_QUEUE_NUM)
	{
		InsertQueue(c->ReceivedBlocks, block);
	}
	else
	{
		FreeBlock(block);
	}
}

// Queues one block received from the peer, or drops it when it is oversized or the Cedar queue budget is
// spent. A queued block then syncs the queue budget: every block when packet_index is NULL, else every
// 32nd block counted through *packet_index
static void ConnectionEnqueueReceivedBlock(CONNECTION *c, BLOCK *b, UINT *packet_index)
{
	if (b->Size > MAX_PACKET_SIZE || CedarGetQueueBudgetBalance(c->Cedar) == 0)
	{
		FreeBlock(b);
		return;
	}

	InsertReceivedBlockToQueue(c, b);

	if (packet_index == NULL || (*packet_index % 32) == 0)
	{
		CedarSyncQueueBudget(c->Cedar, c->ReceivedBlocks->num_item, &c->LastRecvBlocksNum);
	}

	if (packet_index != NULL)
	{
		(*packet_index)++;
	}
}

// Randomize the Keep-Alive interval to spread network load.
UINT GenNextKeepAliveSpan(CONNECTION *c)
{
	UINT a, b;
	if (c == NULL)
	{
		return INFINITE;
	}

	// Clamped to the bounds of ServerAccept: a timeout below 2 would divide by zero
	a = MAKESURE(c->Session->Timeout, TIMEOUT_MIN, TIMEOUT_MAX);
	b = rand() % (a / 2);
	b = MAX(b, a / 5);

	return b;
}

static void SendKeepAlive(CONNECTION *c, TCPSOCK *ts)
{
	UINT size, i, num;
	UINT size_be;
	SESSION *s;
	UCHAR *buf;
	if (c == NULL || ts == NULL)
	{
		return;
	}

	s = c->Session;
	if (s == NULL)
	{
		return;
	}

	size = rand() % MAX_KEEPALIVE_SIZE;
	num = KEEP_ALIVE_MAGIC;

	buf = MallocFast(size);

	for (i = 0; i < size; ++i)
	{
		buf[i] = rand();
	}

	num = Endian32(num);
	size_be = Endian32(size);
	WriteSendFifo(c->Session, ts, &num, sizeof(UINT));
	WriteSendFifo(c->Session, ts, &size_be, sizeof(UINT));
	WriteSendFifo(c->Session, ts, buf, size);

	c->Session->TotalSendSize += sizeof(UINT) * 2 + size;
	c->Session->TotalSendSizeReal += sizeof(UINT) * 2 + size;

	Free(buf);
}

void ConnectionSend(CONNECTION *c, UINT64 now)
{
	UINT i, num;
	UINT min_count;
	TCPSOCK **tcpsocks;
	UINT size;
	SESSION *s;
	HUB *hub = NULL;
	bool use_qos = false;
	if (c == NULL)
	{
		return;
	}

	s = c->Session;

	if (s != NULL)
	{
		hub = s->Hub;
		use_qos = s->QoS;
	}

	if (c->Protocol == CONNECTION_TCP)
	{
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

		for (i = 0;i < num;i++)
		{
			TCPSOCK *tcpsock = tcpsocks[i];
			if (s != NULL && tcpsock->Sock->Connected && tcpsock->Sock->AsyncMode &&
				IS_SEND_TCP_SOCK(tcpsock))
			{
				if (now >= tcpsock->NextKeepAliveTime || tcpsock->NextKeepAliveTime == 0)
				{
					SendKeepAlive(c, tcpsock);
					tcpsock->NextKeepAliveTime = now + (UINT64)GenNextKeepAliveSpan(c);
				}

				num_available++;

				ts_hp = tcpsock;
			}
		}

		for (i = 0;i < num;i++)
		{
			TCPSOCK *tcpsock = tcpsocks[i];
			if (tcpsock->Sock->Connected && tcpsock->Sock->AsyncMode &&
				IS_SEND_TCP_SOCK(tcpsock))
			{
				bool b = false;

				if (use_qos == false)
				{
					b = true;
				}
				else if (num_available < 2)
				{
					b = true;
				}
				else if (tcpsock != ts_hp)
				{
					b = true;
				}

				if (b)
				{
					if (tcpsock->LateCount <= min_count)
					{
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
		{
			ts_hp = ts;
		}

		if (use_qos == false)
		{
			ts_hp = ts;
		}

		if (ts == NULL || ts_hp == NULL)
		{
		}
		else
		{
			TCPSOCK *tss;
			UINT j;
			QUEUE *q;

			if (s != NULL && s->UdpAccel != NULL)
			{
				UdpAccelSetTick(s->UdpAccel, now);
			}

			for (j = 0;j < 2;j++)
			{
				if (j == 0)
				{
					q = c->SendBlocks2;
					tss = ts_hp;
				}
				else
				{
					q = c->SendBlocks;
					tss = ts;
				}
				if (q->num_item != 0)
				{
					UINT num_data;
					BLOCK *b;
					UINT size_quota_v1 = MAX_SEND_SOCKET_QUEUE_SIZE / s->MaxConnection;
					UINT size_quota_v2 = MIN_SEND_SOCKET_QUEUE_SIZE;
					UINT size_quota = MAX(size_quota_v1, size_quota_v2);

					if (tss->SendFifo->size >= size_quota)
					{
						while (b = GetNext(q))
						{
							if (b != NULL)
							{
								c->CurrentSendQueueSize -= b->Size;
								FreeBlock(b);
							}
						}
					}
					else
					{
						if (s->UseUdpAcceleration && s->UdpAccel != NULL && UdpAccelIsSendReady(s->UdpAccel, true))
						{
							while (b = GetNext(q))
							{
								UdpAccelSendBlock(s->UdpAccel, b);

								s->TotalSendSize += b->Size;
								s->TotalSendSizeReal += b->Size;

								c->CurrentSendQueueSize -= b->Size;

								FreeBlock(b);
							}
						}
						else
						{
							bool update_keepalive_timer = false;
							num_data = Endian32(q->num_item);
							WriteSendFifo(s, tss, &num_data, sizeof(UINT));

							s->TotalSendSize += sizeof(UINT);
							s->TotalSendSizeReal += sizeof(UINT);

							while (b = GetNext(q))
							{
								UINT size_data;
								size_data = Endian32(b->Size);
								WriteSendFifo(s, tss, &size_data, sizeof(UINT));

								c->CurrentSendQueueSize -= b->Size;

								s->TotalSendSize += sizeof(UINT);
								s->TotalSendSizeReal += sizeof(UINT);

								WriteSendFifo(s, tss, b->Buf, b->Size);

								s->TotalSendSize += b->SizeofData;
								s->TotalSendSizeReal += b->Size;

								update_keepalive_timer = true;

								FreeBlock(b);
							}

							if (s->UseUdpAcceleration && s->UdpAccel != NULL && UdpAccelIsSendReady(s->UdpAccel, false))
							{
								update_keepalive_timer = false;
							}

							if (update_keepalive_timer)
							{
								tss->NextKeepAliveTime = now + (UINT64)GenNextKeepAliveSpan(c);
							}
						}
					}
				}
			}
		}

		for (i = 0;i < num;i++)
		{
			ts = tcpsocks[i];

SEND_START:
			if (ts->Sock->Connected == false)
			{
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

			if (ts->SendFifo->size != 0)
			{
				UCHAR *buf;
				UINT want_send_size;
				buf = (UCHAR *)ts->SendFifo->p + ts->SendFifo->pos;
				want_send_size = ts->SendFifo->size;

				size = Send(ts->Sock, buf, want_send_size, s->UseEncrypt);

				if (size == 0)
				{
					continue;
				}
				else if (size == SOCK_LATER)
				{
					ts->LateCount++;
				}
				else
				{
					ReadFifo(ts->SendFifo, NULL, size);
					if (size < want_send_size)
					{
					}
					else
					{
						ts->LateCount = 0;

					}
					UPDATE_LAST_COMM_TIME(c->Session->LastCommTime, now);

					goto SEND_START;
				}
			}
		}

		Free(tcpsocks);
	}
	else if (c->Protocol == CONNECTION_HUB_LINK_SERVER)
	{
		LINK *k = (LINK *)s->Link;

		if (k != NULL)
		{
			UINT num_blocks = 0;
			LockQueue(k->SendPacketQueue);
			{
				BLOCK *block;

				while (block = GetNext(c->SendBlocks))
				{
					c->CurrentSendQueueSize -= block->Size;

					if (k->SendPacketQueue->num_item >= MAX_STORED_QUEUE_NUM)
					{
						FreeBlock(block);
					}
					else
					{
						num_blocks++;
						k->CurrentSendPacketQueueSize += block->Size;
						InsertQueue(k->SendPacketQueue, block);
					}
				}
			}
			UnlockQueue(k->SendPacketQueue);

			if (num_blocks != 0)
			{
				Cancel(k->ClientSession->Cancel1);
			}
		}
	}
	else if (c->Protocol == CONNECTION_HUB_BRIDGE)
	{
		BRIDGE *b = s->Bridge;

		if (b != NULL)
		{
			if (b->Active)
			{
				BLOCK *block;
				UINT num_packet = c->SendBlocks->num_item;

				if (num_packet != 0)
				{
					void **datas = MallocFast(sizeof(void *) * num_packet);
					UINT *sizes = MallocFast(sizeof(UINT) * num_packet);
					UINT i;

					i = 0;
					while (block = GetNext(c->SendBlocks))
					{
						if (hub != NULL && hub->Option != NULL && hub->Option->DisableUdpFilterForLocalBridgeNic == false &&
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

							if (block->Size > 1514)
							{
								NormalizeEthMtu(b, c, block->Size);
							}
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
}

void ConnectionReceive(CONNECTION *c, CANCEL *c1, CANCEL *c2)
{
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
	{
		return;
	}


	s = c->Session;

	if (s != NULL)
	{
		hub = s->Hub;
	}

	if (hub != NULL)
	{
		no_spinlock_for_delay = hub->Option->NoSpinLockForPacketDelay;
	}

	if (c->RecvBuf == NULL)
	{
		c->RecvBuf = Malloc(RECV_BUF_SIZE);
	}
	buf = c->RecvBuf;

	if (c->Protocol == CONNECTION_TCP)
	{
		TCP *tcp = c->Tcp;
		UINT next_delay_packet_diff = 0;
		UINT current_recv_fifo_size = 0;
		int recv_fifo_size_middle_update = 0;

		if (s->ServerMode == false)
		{
			if (s->ClientOption->ConnectionDisconnectSpan != 0)
			{
				LockList(tcp->TcpSockList);
				{
					UINT i;
					for (i = 0;i < LIST_NUM(tcp->TcpSockList);i++)
					{
						TCPSOCK *ts = LIST_DATA(tcp->TcpSockList, i);
						if (ts->DisconnectTick != 0 &&
							ts->DisconnectTick <= now)
						{
							Disconnect(ts->Sock);
						}
					}
				}
				UnlockList(tcp->TcpSockList);
			}
		}

		if (s->HalfConnection && (s->ServerMode == false))
		{
			// If the connection count is at the limit and all sockets share one direction, disconnect one.
			LockList(tcp->TcpSockList);
			{
				UINT i, num;
				UINT c2s, s2c;
				c2s = s2c = 0;
				num = LIST_NUM(tcp->TcpSockList);
				if (num >= s->MaxConnection)
				{
					TCPSOCK *ts;
					for (i = 0;i < num;i++)
					{
						ts = LIST_DATA(tcp->TcpSockList, i);
						if (ts->Direction == TCP_SERVER_TO_CLIENT)
						{
							s2c++;
						}
						else
						{
							c2s++;
						}
					}
					if (s2c == 0 || c2s == 0)
					{
						Disconnect(ts->Sock);
					}
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

		for (i = 0;i < num;i++)
		{
			AddSockSet(&set, tcpsocks[i]->Sock);
		}

		if (s->UseUdpAcceleration && s->UdpAccel != NULL)
		{
			if (s->UdpAccel->UdpSock != NULL)
			{
				AddSockSet(&set, s->UdpAccel->UdpSock);
			}
		}

		time = SELECT_TIME;
		next_delay_packet_diff = GetNextDelayedPacketTickDiff(s);
		time = MIN(time, next_delay_packet_diff);
		if (s->UseUdpAcceleration && UdpAccelIsRecvBudgetSpent(s->UdpAccel))
		{
			// The per-tick receive budget is spent and no read re-arms the socket event:
			// come back on the next tick instead of after SELECT_TIME
			time = MIN(time, 1);
		}
		num_delayed = LIST_NUM(s->DelayedPacketList);


		if (s->Flag1 != set.NumSocket)
		{
			Select(&set, (num_delayed == 0 ? time : 1), c1, c2);
			s->Flag1 = set.NumSocket;
		}
		else
		{
			if (no_spinlock_for_delay || time >= 50 || num_delayed == false)
			{
				Select(&set, (num_delayed == 0 ? time : (time > 100 ? (time - 100) : 1)), c1, c2);
				s->Flag1 = set.NumSocket;
			}
			else
			{
				YieldCpu();
			}
		}

		now = Tick64();


		if (s->UseUdpAcceleration && s->UdpAccel != NULL)
		{
			UdpAccelSetTick(s->UdpAccel, now);
			UdpAccelPoll(s->UdpAccel);

			if (s->UdpAccelMss == 0)
			{
				s->UdpAccelMss = UdpAccelCalcMss(s->UdpAccel);
			}

			while (true)
			{
				BLOCK *b = GetNext(s->UdpAccel->RecvBlockQueue);

				if (b == NULL)
				{
					break;
				}

				ConnectionEnqueueReceivedBlock(c, b, NULL);
			}
		}

		{
			bool new_status = UdpAccelIsSendReady(s->UdpAccel, true);

			if (s->IsUsingUdpAcceleration != new_status)
			{
			}

			s->IsUsingUdpAcceleration = new_status;
		}

		for (i = 0;i < num;i++)
		{
			TCPSOCK *ts = tcpsocks[i];

			UINT current_fifo_budget = 0;
			UINT current_packet_index = 0;
			if (ts->WantSize == 0)
			{
				ts->WantSize = sizeof(UINT);
			}

			now = Tick64();

RECV_START:
			current_fifo_budget = CedarGetFifoBudgetBalance(c->Cedar);
			if (ts->RecvFifo->size < current_fifo_budget)
			{
				UINT recv_buf_size = current_fifo_budget - ts->RecvFifo->size;

				recv_buf_size = MIN(recv_buf_size, RECV_BUF_SIZE);

				size = Recv(ts->Sock, buf, recv_buf_size, s->UseEncrypt);
			}
			else
			{
				size = SOCK_LATER;

				UPDATE_LAST_COMM_TIME(c->Session->LastCommTime, now);
				UPDATE_LAST_COMM_TIME(ts->LastCommTime, now);
			}


			if (size == 0)
			{
DISCONNECT_THIS_TCP:
				s->LastTryAddConnectTime = Tick64();
				s->NumDisconnected++;
				LockList(tcp->TcpSockList);
				{
					Delete(tcp->TcpSockList, ts);
					FreeTcpSock(ts);
					Dec(c->CurrentNumConnection);
				}
				UnlockList(tcp->TcpSockList);

				continue;
			}
			else if (size == SOCK_LATER)
			{
				if (IS_RECV_TCP_SOCK(ts))
				{
					if ((now > ts->LastCommTime) && ((now - ts->LastCommTime) >= ((UINT64)s->Timeout)))
					{
						goto DISCONNECT_THIS_TCP;
					}
				}
			}
			else
			{
				UINT budget_balance = CedarGetFifoBudgetBalance(c->Cedar);
				UINT fifo_size_limit = budget_balance;

				if (fifo_size_limit > MAX_BUFFERING_PACKET_SIZE)
				{
					fifo_size_limit = MAX_BUFFERING_PACKET_SIZE;
				}

				UPDATE_LAST_COMM_TIME(c->Session->LastCommTime, now);
				UPDATE_LAST_COMM_TIME(ts->LastRecvTime, now);

				CedarAddFifoBudget(c->Cedar, (int)size);
				recv_fifo_size_middle_update += (int)size;

				WriteRecvFifo(s, ts, buf, size);

				if (ts->RecvFifo->size < fifo_size_limit)
				{
					goto RECV_START;
				}
			}

			current_recv_fifo_size += FifoSize(ts->RecvFifo);

			while (ts->RecvFifo->size >= ts->WantSize)
			{
				UCHAR *buf;
				void *data;
				BLOCK *block;
				UINT sz;
				buf = (UCHAR *)ts->RecvFifo->p + ts->RecvFifo->pos;

				switch (ts->Mode)
				{
				case 0:
					ts->WantSize = sizeof(UINT);
					Copy(&sz, buf, sizeof(UINT));
					sz = Endian32(sz);
					ts->NextBlockNum = sz;
					ReadFifo(ts->RecvFifo, NULL, sizeof(UINT));

					s->TotalRecvSize += sizeof(UINT);
					s->TotalRecvSizeReal += sizeof(UINT);

					ts->CurrentPacketNum = 0;
					if (ts->NextBlockNum != 0)
					{
						if (ts->NextBlockNum == KEEP_ALIVE_MAGIC)
						{
							ts->Mode = 3;
						}
						else
						{
							ts->Mode = 1;
						}
					}
					break;

				case 1:
					Copy(&sz, buf, sizeof(UINT));
					sz = Endian32(sz);
					if (sz > (MAX_PACKET_SIZE * 2))
					{
						Disconnect(ts->Sock);
					}
					ts->NextBlockSize = MIN(sz, MAX_PACKET_SIZE * 2);
					ReadFifo(ts->RecvFifo, NULL, sizeof(UINT));

					s->TotalRecvSize += sizeof(UINT);
					s->TotalRecvSizeReal += sizeof(UINT);

					ts->WantSize = ts->NextBlockSize;
					if (ts->WantSize != 0)
					{
						ts->Mode = 2;
					}
					else
					{
						ts->Mode = 1;
						ts->WantSize = sizeof(UINT);
						ts->CurrentPacketNum++;
						if (ts->CurrentPacketNum >= ts->NextBlockNum)
						{
							ts->Mode = 0;
						}
					}
					break;

				case 2:
					ts->WantSize = sizeof(UINT);
					ts->CurrentPacketNum++;
					data = MallocFast(ts->NextBlockSize);
					Copy(data, buf, ts->NextBlockSize);
					ReadFifo(ts->RecvFifo, NULL, ts->NextBlockSize);
					block = NewBlock(data, ts->NextBlockSize, s->UseCompress ? -1 : 0);

					UPDATE_LAST_COMM_TIME(c->Session->LastCommTime, now);
					UPDATE_LAST_COMM_TIME(ts->LastCommTime, now);

					ConnectionEnqueueReceivedBlock(c, block, &current_packet_index);

					if (ts->CurrentPacketNum >= ts->NextBlockNum)
					{
						ts->Mode = 0;
					}
					else
					{
						ts->Mode = 1;
					}
					break;

				case 3:
					ts->Mode = 4;
					Copy(&sz, buf, sizeof(UINT));
					sz = Endian32(sz);
					if (sz > MAX_KEEPALIVE_SIZE)
					{
						Disconnect(ts->Sock);
					}
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

		if (true)
		{
			int diff;

			diff = (int)current_recv_fifo_size - (int)c->LastRecvFifoTotalSize;

			CedarAddFifoBudget(c->Cedar, (diff - recv_fifo_size_middle_update));

			c->LastRecvFifoTotalSize = current_recv_fifo_size;
		}

		CedarSyncQueueBudget(c->Cedar, c->ReceivedBlocks->num_item, &c->LastRecvBlocksNum);

		Free(tcpsocks);
	}
	else if (c->Protocol == CONNECTION_HUB_LINK_SERVER)
	{
		if (c->SendBlocks->num_item == 0)
		{
			UINT time = SELECT_TIME;
			UINT next_delay_packet_diff = 0;

			next_delay_packet_diff = GetNextDelayedPacketTickDiff(s);
			time = MIN(time, next_delay_packet_diff);
			num_delayed = LIST_NUM(s->DelayedPacketList);

			if (no_spinlock_for_delay || time >= 50 || num_delayed == false)
			{
				Select(NULL, (num_delayed == 0 ? time : (time > 100 ? (time - 100) : 1)), c1, c2);
			}
			else
			{
				YieldCpu();
			}
		}
	}
	else if (c->Protocol == CONNECTION_HUB_BRIDGE)
	{
		BRIDGE *b = c->Session->Bridge;

		if (b->Active)
		{
			void *data;
			UINT ret;
			UINT num = 0;
			bool check_device_num = false;
			UINT time = SELECT_TIME;
			UINT next_delay_packet_diff = 0;

			next_delay_packet_diff = GetNextDelayedPacketTickDiff(s);
			time = MIN(time, next_delay_packet_diff);
			num_delayed = LIST_NUM(s->DelayedPacketList);

			if (no_spinlock_for_delay || time >= 50 || num_delayed == false)
			{
				Select(NULL, (num_delayed == 0 ? time : (time > 100 ? (time - 100) : 1)), c1, c2);
			}
			else
			{
				YieldCpu();
			}

			if ((b->LastNumDeviceCheck + BRIDGE_NUM_DEVICE_CHECK_SPAN) <= Tick64())
			{
				check_device_num = true;
				b->LastNumDeviceCheck = Tick64();
			}

			while (true)
			{
				if (check_device_num && b->LastNumDevice != GetEthDeviceHash())
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
					if (hub != NULL && hub->Option != NULL && hub->Option->DisableUdpFilterForLocalBridgeNic == false &&
						b->Eth != NULL && IsDhcpPacketForSpecificMac(data, ret, b->Eth->MacAddress))
					{
						Free(data);
					}
					else
					{
						BLOCK *block = NewBlock(data, ret, 0);


						if (ret > 1514)
						{
							NormalizeEthMtu(b, c, ret);
						}

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

				e = OpenEth(b->Name, b->Local, b->TapMode, b->TapMacAddress);
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
}

void NormalizeEthMtu(BRIDGE *b, CONNECTION *c, UINT packet_size)
{
	if (packet_size == 0 || b == NULL || c == NULL)
	{
		return;
	}

	if (EthIsChangeMtuSupported(b->Eth))
	{
		UINT currentMtu = EthGetMtu(b->Eth);
		if (currentMtu != 0)
		{
			if (packet_size > currentMtu)
			{
				bool ok = EthSetMtu(b->Eth, packet_size);

				if (ok)
				{
					HLog(c->Session->Hub, "LH_SET_MTU", c->Session->Name,
						b->Name, currentMtu, packet_size, packet_size);
				}
				else
				{
					UINT64 now = Tick64();

					if (b->LastChangeMtuError == 0 ||
						now >= (b->LastChangeMtuError + 60000ULL))
					{
						HLog(c->Session->Hub, "LH_SET_MTU_ERROR", c->Session->Name,
							b->Name, currentMtu, packet_size, packet_size);

						b->LastChangeMtuError = now;
					}
				}
			}
		}
	}
}

void FreeBlock(BLOCK *b)
{
	if (b == NULL)
	{
		return;
	}

	Free(b->Buf);
	Free(b);
}

BLOCK *NewBlock(void *data, UINT size, int compress)
{
	BLOCK *b;
	if (data == NULL)
	{
		return NULL;
	}

	b = MallocFast(sizeof(BLOCK));

	b->IsFlooding = false;

	b->PriorityQoS = b->Param1 = 0;

	if (compress == 0)
	{
		b->Compressed = false;
		b->Buf = data;
		b->Size = size;
		b->SizeofData = size;
	}
	else if (compress == 1)
	{
		UINT max_size;

		b->Compressed = true;
		max_size = CalcCompress(size);
		b->Buf = MallocFast(max_size);
		b->Size = Compress(b->Buf, max_size, data, size);
		b->SizeofData = size;

		Free(data);
	}
	else
	{
		UINT max_size;

		b->Compressed = false;
		max_size = MAX_PACKET_SIZE;
		b->Buf = MallocFast(max_size);
		b->Size = Uncompress(b->Buf, max_size, data, size);
		b->SizeofData = size;

		Free(data);
	}

	return b;
}

TCPSOCK *NewTcpSock(SOCK *s)
{
	TCPSOCK *ts;
	if (s == NULL)
	{
		return NULL;
	}

	ts = ZeroMalloc(sizeof(TCPSOCK));

	ts->Sock = s;
	AddRef(s->ref);

	ts->RecvFifo = NewFifo();
	ts->SendFifo = NewFifo();
	ts->EstablishedTick = ts->LastRecvTime = ts->LastCommTime = Tick64();

	SetTimeout(s, TIMEOUT_INFINITE);

	return ts;
}

void FreeTcpSock(TCPSOCK *ts)
{
	if (ts == NULL)
	{
		return;
	}

	Disconnect(ts->Sock);
	ReleaseSock(ts->Sock);
	ReleaseFifo(ts->RecvFifo);
	ReleaseFifo(ts->SendFifo);

	if (ts->SendKey)
	{
		FreeCrypt(ts->SendKey);
	}
	if (ts->RecvKey)
	{
		FreeCrypt(ts->RecvKey);
	}

	Free(ts);
}

void EndTunnelingMode(CONNECTION *c)
{
	if (c == NULL)
	{
		return;
	}

	if (c->Protocol == CONNECTION_TCP)
	{
		DisconnectTcpSockets(c);
	}
}

void StartTunnelingMode(CONNECTION *c)
{
	SOCK *s;
	TCP *tcp;
	TCPSOCK *ts;
	if (c == NULL)
	{
		return;
	}

	tcp = c->Tcp;

	if (c->Protocol == CONNECTION_TCP)
	{
		s = c->FirstSock;

		ts = NewTcpSock(s);

		if (c->ServerMode == false)
		{
			if (c->Session->ClientOption->ConnectionDisconnectSpan != 0)
			{
				ts->DisconnectTick = Tick64() + c->Session->ClientOption->ConnectionDisconnectSpan * (UINT64)1000;
			}
		}

		LockList(tcp->TcpSockList);
		{
			Add(tcp->TcpSockList, ts);
		}
		UnlockList(tcp->TcpSockList);
		ReleaseSock(s);
		c->FirstSock = NULL;
	}
}

static UINT GetMachineRand()
{
	char pcname[MAX_SIZE];
	UCHAR hash[SHA1_SIZE];

	Zero(pcname, sizeof(pcname));
	GetMachineName(pcname, sizeof(pcname));

	Sha1(hash, pcname, StrLen(pcname));

	return READ_UINT(hash);
}

void ConnectionAccept(CONNECTION *c)
{
	SOCK *s;
	X *x;
	K *k;
	LIST *chain;
	char tmp[128];
	UINT initial_timeout = CONNECTING_TIMEOUT;
	UCHAR ctoken_hash[SHA1_SIZE];

	if (c == NULL)
	{
		return;
	}

	Zero(ctoken_hash, sizeof(ctoken_hash));

	s = c->FirstSock;
	AddRef(s->ref);

	Dec(c->Cedar->AcceptingSockets);

	IPToStr(tmp, sizeof(tmp), &s->RemoteIP);

	SLog(c->Cedar, "LS_CONNECTION_START_1", tmp, s->RemoteHostname, (IS_SPECIAL_PORT(s->RemotePort) ? 0 : s->RemotePort), c->Name);

	initial_timeout += GetMachineRand() % (CONNECTING_TIMEOUT / 2);
	SetTimeout(s, initial_timeout);

	Lock(c->Cedar->lock);
	{
		if (c->Cedar->CipherList != NULL)
		{
			SetWantToUseCipher(s, c->Cedar->CipherList);
		}

		x = CloneX(c->Cedar->ServerX);
		k = CloneK(c->Cedar->ServerK);
		chain = CloneXList(c->Cedar->ServerChain);
	}
	Unlock(c->Cedar->lock);

	Copy(&s->SslAcceptSettings, &c->Cedar->SslAcceptSettings, sizeof(SSL_ACCEPT_SETTINGS));
	UINT ssl_err = 0;
	if (StartSSLEx3(s, x, k, chain, 0, NULL, NULL, &ssl_err) == false)
	{
		AddNoSsl(c->Cedar, &s->RemoteIP);
		if (ssl_err != 0)
		{
			SLog(c->Cedar, "LS_SSL_START_ERROR", c->Name, GetUniErrorStr(ssl_err), ssl_err);
		}
		FreeX(x);
		FreeK(k);
		FreeXList(chain);

		goto FINAL;
	}

	FreeX(x);
	FreeK(k);
	FreeXList(chain);

	SLog(c->Cedar, "LS_SSL_START", c->Name, s->SslVersion, s->CipherName);

	Copy(c->CToken_Hash, ctoken_hash, SHA1_SIZE);

	if (ServerAccept(c) == false)
	{
	}

FINAL:
	if (c->flag1 == false)
	{
		Disconnect(s);
	}

	DelConnection(c->Cedar, c);
	ReleaseSock(s);
}

void StopAllAdditionalConnectThread(CONNECTION *c)
{
	UINT i, num;
	SOCK **socks;
	THREAD **threads;
	if (c == NULL || c->ServerMode != false)
	{
		return;
	}

	LockList(c->ConnectingSocks);
	{
		num = LIST_NUM(c->ConnectingSocks);
		socks = ToArray(c->ConnectingSocks);
		DeleteAll(c->ConnectingSocks);
	}
	UnlockList(c->ConnectingSocks);
	for (i = 0;i < num;i++)
	{
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
	for (i = 0;i < num;i++)
	{
		WaitThread(threads[i], INFINITE);
		ReleaseThread(threads[i]);
	}
	Free(threads);
}

void StopConnection(CONNECTION *c, bool no_wait)
{
	if (c == NULL)
	{
		return;
	}


	c->Halt = true;
	Disconnect(c->FirstSock);

	if (no_wait == false)
	{
		WaitThread(c->Thread, INFINITE);
	}
}

void DisconnectTcpSockets(CONNECTION *c)
{
	UINT i, num;
	TCP *tcp;
	TCPSOCK **tcpsocks;
	if (c == NULL)
	{
		return;
	}
	if (c->Protocol != CONNECTION_TCP)
	{
		return;
	}

	tcp = c->Tcp;
	LockList(tcp->TcpSockList);
	{
		tcpsocks = ToArray(tcp->TcpSockList);
		num = LIST_NUM(tcp->TcpSockList);
		DeleteAll(tcp->TcpSockList);
	}
	UnlockList(tcp->TcpSockList);

	if (num != 0)
	{
		for (i = 0;i < num;i++)
		{
			TCPSOCK *ts = tcpsocks[i];
			FreeTcpSock(ts);
		}
	}

	Free(tcpsocks);
}

static void CleanupConnection(CONNECTION *c)
{
	UINT i, num;
	if (c == NULL)
	{
		return;
	}

	if (c->LastRecvFifoTotalSize != 0)
	{
		CedarAddFifoBudget(c->Cedar, -((int)c->LastRecvFifoTotalSize));
		c->LastRecvFifoTotalSize = 0;
	}

	CedarSyncQueueBudget(c->Cedar, 0, &c->LastRecvBlocksNum);

	if (c->LastTcpQueueSize != 0)
	{
		int diff = -((int)c->LastTcpQueueSize);
		CedarAddCurrentTcpQueueSize(c->Cedar, diff);
		c->LastTcpQueueSize = 0;
	}

	if (c->LastPacketQueueSize != 0)
	{
		int diff = -((int)c->LastPacketQueueSize);
		CedarAddCurrentTcpQueueSize(c->Cedar, diff);
		c->LastPacketQueueSize = 0;
	}

	DeleteLock(c->lock);
	ReleaseCedar(c->Cedar);

	DisconnectTcpSockets(c);

	ReleaseList(c->Tcp->TcpSockList);
	Free(c->Tcp);

	ReleaseSock(c->FirstSock);
	c->FirstSock = NULL;

	ReleaseThread(c->Thread);
	Free(c->Name);

	if (c->SendBlocks)
	{
		LockQueue(c->SendBlocks);
		{
			BLOCK *b;
			while (b = GetNext(c->SendBlocks))
			{
				FreeBlock(b);
			}
		}
		UnlockQueue(c->SendBlocks);
	}
	if (c->SendBlocks2)
	{
		LockQueue(c->SendBlocks2);
		{
			BLOCK *b;
			while (b = GetNext(c->SendBlocks2))
			{
				FreeBlock(b);
			}
		}
		UnlockQueue(c->SendBlocks2);
	}
	if (c->ReceivedBlocks)
	{
		LockQueue(c->ReceivedBlocks);
		{
			BLOCK *b;
			while (b = GetNext(c->ReceivedBlocks))
			{
				FreeBlock(b);
			}
		}
		UnlockQueue(c->ReceivedBlocks);
	}

	if (c->ConnectingThreads)
	{
		THREAD **threads;
		LockList(c->ConnectingThreads);
		{
			num = LIST_NUM(c->ConnectingThreads);
			threads = ToArray(c->ConnectingThreads);
			for (i = 0;i < num;i++)
			{
				ReleaseThread(threads[i]);
			}
			Free(threads);
		}
		UnlockList(c->ConnectingThreads);
		ReleaseList(c->ConnectingThreads);
	}

	if (c->ConnectingSocks)
	{
		SOCK **socks;
		LockList(c->ConnectingSocks);
		{
			num = LIST_NUM(c->ConnectingSocks);
			socks = ToArray(c->ConnectingSocks);
			for (i = 0;i < num;i++)
			{
				Disconnect(socks[i]);
				ReleaseSock(socks[i]);
			}
			Free(socks);
		}
		UnlockList(c->ConnectingSocks);
		ReleaseList(c->ConnectingSocks);
	}

	if (c->RecvBuf)
	{
		Free(c->RecvBuf);
	}

	if (c->ServerX != NULL)
	{
		FreeX(c->ServerX);
	}

	if (c->ClientX != NULL)
	{
		FreeX(c->ClientX);
	}

	ReleaseQueue(c->ReceivedBlocks);
	ReleaseQueue(c->SendBlocks);
	ReleaseQueue(c->SendBlocks2);

	DeleteCounter(c->CurrentNumConnection);

	if (c->CipherName != NULL)
	{
		Free(c->CipherName);
	}

	if (c->SslVersion != NULL)
	{
		Free(c->SslVersion);
	}

	Free(c);
}

void ReleaseConnection(CONNECTION *c)
{
	if (c == NULL)
	{
		return;
	}

	if (Release(c->ref) == 0)
	{
		CleanupConnection(c);
	}
}

int CompareConnection(void *p1, void *p2)
{
	CONNECTION *c1, *c2;
	if (p1 == NULL || p2 == NULL)
	{
		return 0;
	}
	c1 = *(CONNECTION **)p1;
	c2 = *(CONNECTION **)p2;
	if (c1 == NULL || c2 == NULL)
	{
		return 0;
	}

	return StrCmpi(c1->Name, c2->Name);
}

CONNECTION *NewServerConnection(CEDAR *cedar, SOCK *s, THREAD *t)
{
	CONNECTION *c;
	if (cedar == NULL)
	{
		return NULL;
	}

	c = ZeroMalloc(sizeof(CONNECTION));
	c->ConnectedTick = Tick64();
	c->lock = NewLock();
	c->ref = NewRef();
	c->Cedar = cedar;
	AddRef(c->Cedar->ref);
	c->Protocol = CONNECTION_TCP;
	c->Type = CONNECTION_TYPE_INIT;
	c->FirstSock = s;
	if (s != NULL)
	{
		AddRef(c->FirstSock->ref);
		Copy(&c->ClientIp, &s->RemoteIP, sizeof(IP));
		StrCpy(c->ClientHostname, sizeof(c->ClientHostname), s->RemoteHostname);
	}
	c->Tcp = ZeroMalloc(sizeof(TCP));
	c->Tcp->TcpSockList = NewList(NULL);
	c->ServerMode = true;
	c->Status = CONNECTION_STATUS_ACCEPTED;
	c->Name = CopyStr("INITING");
	c->Thread = t;
	AddRef(t->ref);
	c->CurrentNumConnection = NewCounter();
	Inc(c->CurrentNumConnection);

	c->ServerVer = cedar->Version;
	c->ServerBuild = cedar->Build;
	StrCpy(c->ServerStr, sizeof(c->ServerStr), cedar->ServerStr);
	GetServerProductName(cedar->Server, c->ServerStr, sizeof(c->ServerStr));

	if (s != NULL && s->RemoteX != NULL)
	{
		c->ServerX = CloneX(s->RemoteX);
	}

	c->ReceivedBlocks = NewQueue();
	c->SendBlocks = NewQueue();
	c->SendBlocks2 = NewQueue();

	return c;
}

CONNECTION *NewClientConnectionEx(SESSION *s, char *client_str, UINT client_ver, UINT client_build)
{
	CONNECTION *c;

	c = ZeroMalloc(sizeof(CONNECTION));
	c->ConnectedTick = Tick64();
	c->lock = NewLock();
	c->ref = NewRef();
	c->Cedar = s->Cedar;
	AddRef(c->Cedar->ref);
	c->Protocol = CONNECTION_TCP;
	c->Tcp = ZeroMalloc(sizeof(TCP));
	c->Tcp->TcpSockList = NewList(NULL);
	c->ServerMode = false;
	c->Status = CONNECTION_STATUS_CONNECTING;
	c->Name = CopyStr("CLIENT_CONNECTION");
	c->Session = s;
	c->CurrentNumConnection = NewCounter();
	c->LastCounterResetTick = Tick64();
	Inc(c->CurrentNumConnection);

	c->ConnectingThreads = NewList(NULL);
	c->ConnectingSocks = NewList(NULL);

	if (client_str == NULL)
	{
		c->ClientVer = s->Cedar->Version;
		c->ClientBuild = s->Cedar->Build;

		if (c->Session->LinkModeClient == false)
		{
			StrCpy(c->ClientStr, sizeof(c->ClientStr), CEDAR_CLIENT_STR);
		}
		else
		{
			StrCpy(c->ClientStr, sizeof(c->ClientStr), CEDAR_SERVER_LINK_STR);
		}
	}
	else
	{
		c->ClientVer = client_ver;
		c->ClientBuild = client_build;
		StrCpy(c->ClientStr, sizeof(c->ClientStr), client_str);
	}

	StrCpy(c->ServerName, sizeof(c->ServerName), s->ClientOption->Hostname);
	c->ServerPort = s->ClientOption->Port;

	c->ReceivedBlocks = NewQueue();
	c->SendBlocks = NewQueue();
	c->SendBlocks2 = NewQueue();

	return c;
}
