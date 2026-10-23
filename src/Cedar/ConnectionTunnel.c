// ConnectionTunnel.c
// The Tunnel of a Connection of type CONNECTION_NOISE (CORE-S1-2, #68): the Noise sessions of the new core between one
// client node and the server role (Core/Transport.h), whose data records carry the Ethernet frames of the Connection's
// Session. So the frames of the new transport enter the existing Hub and are forwarded as the frames of a SE-VPN
// session are, under the unchanged forwarding plane until the new switch replaces it (ADR-0022, strangler steps 1 and
// 4). Each connection has a reader thread, which takes the records of its Noise session (TransportNoiseReceive sends
// the keepalives while it waits) and queues the frames for the Session. On the thread of the Session,
// ConnectionReceive hands them to the Hub, and ConnectionSend sends each frame of the Hub over the connection that its
// flow hash selects (NoiseTunnelFlowHash, NoiseTunnelRoute), so that one inner flow keeps its order. A connection that
// ends leaves the Tunnel and its flows move to the others; the Session ends when none is left.

#include "Connection.h"

#include "Hub.h"
#include "Session.h"

#include "Mayaqua/Kernel.h"
#include "Mayaqua/Memory.h"
#include "Mayaqua/Network.h"
#include "Mayaqua/Object.h"
#include "Mayaqua/Tick64.h"

#include "Core/Transport.h"

#include "ConnectionInternal.h"

_Static_assert(TUNNEL_MAX_CONNECTIONS == NOISE_TUNNEL_MAX_CONNECTIONS, "a Tunnel has the connections of a NOISE_TUNNEL");

#define TUNNEL_READ_TIME 100 // ms that a reader waits for a record before it looks at the halt of its Tunnel

// One connection of a Tunnel. An index is used once: a Tunnel takes TUNNEL_MAX_CONNECTIONS connections in its life, so
// the Session never sends on a Noise session that a later connection freed.
typedef struct TUNNEL_CONN {
	TUNNEL *Tunnel;         // The Tunnel
	UINT Index;             // The index of the connection in the Tunnel (NOISE_TUNNEL)
	TRANSPORT_NOISE *Noise; // Its Noise session, NULL while the index is free
	THREAD *Reader;         // Its reader thread
	UINT64 NumReceived;     // The frames received on it, under the lock of the Tunnel
	UINT64 NumSent;         // The frames sent on it, under the lock of the Tunnel
} TUNNEL_CONN;

struct TUNNEL {
	LOCK *Lock;                               // The routes, the connections, the queue and the counters
	NOISE_TUNNEL Routes;                      // The Noise sessions by connection index: the route of a frame of the Hub
	TUNNEL_CONN Conn[TUNNEL_MAX_CONNECTIONS]; // The connections
	QUEUE *Received;                          // The frames that the readers received (BLOCK) and the Session did not take yet
	CANCEL *Cancel;                           // Wakes the Session: its Cancel1, referenced
	volatile bool Halt;                       // The readers end and no connection joins; through FlagRead and FlagWrite
};

// Close and free a Noise session of the Tunnel, which no thread reads or writes any more
static void TunnelFreeNoise(TRANSPORT_NOISE *n) {
	if (n == NULL)
		return;

	TransportNoiseClose(n);
	Free(n);
}

// Queue one frame of a reader for the Session and wake it. A frame larger than a Hub takes, or one that finds the
// queue at MAX_STORED_QUEUE_NUM, is dropped, as the TCP receive of a Connection drops it.
static void TunnelQueueFrame(TUNNEL *t, TUNNEL_CONN *k, UCHAR *frame, UINT size) {
	if (size == 0 || size > MAX_PACKET_SIZE)
		return;

	BLOCK *b = NewBlock(Clone(frame, size), size, 0);

	Lock(t->Lock);
	{
		k->NumReceived++;
		if (GetQueueNum(t->Received) < MAX_STORED_QUEUE_NUM) {
			InsertQueue(t->Received, b);
			b = NULL;
		}
	}
	Unlock(t->Lock);

	FreeBlock(b);
	Cancel(t->Cancel);
}

// The reader of one connection: the records of its Noise session until the session ends or the Tunnel stops. A data
// record is a frame for the Session; the control stream carries nothing for the Hub yet. A connection that ends
// leaves the routes, so its flows move to the connections left, and the Session hears of it at once.
static void TunnelReaderThread(THREAD *thread, void *param) {
	TUNNEL_CONN *k = (TUNNEL_CONN *)param;
	TUNNEL *t = k->Tunnel;
	UCHAR *buf = Malloc(NOISE_MAX_PAYLOAD);

	NoticeThreadInit(thread);

	while (FlagRead(&t->Halt) == false) {
		UINT size = 0;
		UINT ret = TransportNoiseReceive(k->Noise, buf, NOISE_MAX_PAYLOAD, &size, TUNNEL_READ_TIME);

		if (ret == NOISE_RECEIVE_DATA)
			TunnelQueueFrame(t, k, buf, size);
		else if (ret != NOISE_RECEIVE_NONE && ret != NOISE_RECEIVE_CONTROL)
			break;
	}

	Lock(t->Lock);
	NoiseTunnelLose(&t->Routes, k->Index);
	Unlock(t->Lock);

	Cancel(t->Cancel);
	Free(buf);
}

// Start the reader of connection k, which has its Noise session; the caller holds the lock of the Tunnel
static void TunnelStartReader(TUNNEL_CONN *k) {
	k->Reader = NewThread(TunnelReaderThread, k);
	WaitThreadInit(k->Reader);
}

// Give c, a Connection of type CONNECTION_NOISE whose Session is set, the Tunnel of first: an open Noise session whose
// Login the caller accepted, which becomes connection 0 and starts its reader. The Connection takes first, also when
// this fails (first is then closed and freed); false when first is not open or c has a Tunnel.
bool TunnelStart(CONNECTION *c, TRANSPORT_NOISE *first) {
	if (first == NULL)
		return false;

	TUNNEL *t = ZeroMalloc(sizeof(TUNNEL));
	t->Lock = NewLock();
	t->Received = NewQueueFast();
	for (UINT i = 0; i < TUNNEL_MAX_CONNECTIONS; i++) {
		t->Conn[i].Tunnel = t;
		t->Conn[i].Index = i;
	}

	if (c == NULL || c->Protocol != CONNECTION_NOISE || c->Session == NULL || c->Tunnel != NULL ||
	    NoiseTunnelInit(&t->Routes, &first->Session, TUNNEL_MAX_CONNECTIONS) == false) {
		TunnelFreeNoise(first);
		ReleaseQueue(t->Received);
		DeleteLock(t->Lock);
		Free(t);
		return false;
	}

	t->Cancel = c->Session->Cancel1;
	AddRef(t->Cancel->ref);

	Lock(t->Lock);
	{
		t->Conn[0].Noise = first;
		TunnelStartReader(&t->Conn[0]);
	}
	Unlock(t->Lock);

	c->Tunnel = t;

	return true;
}

// Join n, an open Noise session whose join Login named the Tunnel id, to the Tunnel of c when c carries the Tunnel of
// that id and n is of the same peer node: n takes the next free index and its reader starts. false when c carries
// another Tunnel or none, n is of another node, no index is free or the Tunnel stops; the caller keeps n then.
bool TunnelJoin(CONNECTION *c, const UCHAR *id, TRANSPORT_NOISE *n) {
	TUNNEL *t;
	bool ok = false;

	if (c == NULL || id == NULL || n == NULL || c->Protocol != CONNECTION_NOISE || (t = c->Tunnel) == NULL)
		return false;

	Lock(t->Lock);
	{
		if (FlagRead(&t->Halt) == false && Cmp(t->Routes.Id, id, NOISE_TUNNEL_ID_SIZE) == 0) {
			for (UINT i = 0; i < TUNNEL_MAX_CONNECTIONS && ok == false; i++) {
				TUNNEL_CONN *k = &t->Conn[i];

				if (k->Noise == NULL && NoiseTunnelJoin(&t->Routes, i, &n->Session)) {
					k->Noise = n;
					TunnelStartReader(k);
					ok = true;
				}
			}
		}
	}
	Unlock(t->Lock);

	return ok;
}

// Stop the Tunnel of c once its Session ended, on the thread of the Session after SessionMain: no connection joins any
// more, the readers end and are joined, then every connection is closed
void TunnelStop(CONNECTION *c) {
	TUNNEL *t;

	if (c == NULL || (t = c->Tunnel) == NULL)
		return;

	Lock(t->Lock);
	FlagWrite(&t->Halt, true);
	Unlock(t->Lock);

	// No reader starts after the halt
	for (UINT i = 0; i < TUNNEL_MAX_CONNECTIONS; i++) {
		TUNNEL_CONN *k = &t->Conn[i];

		if (k->Reader != NULL) {
			WaitThread(k->Reader, INFINITE);
			ReleaseThread(k->Reader);
			k->Reader = NULL;
		}

		TunnelFreeNoise(k->Noise);
		k->Noise = NULL;
	}
}

// Free the Tunnel of a Connection that is cleaned up (CleanupConnection), stopping it first if its Session did not
void FreeTunnel(CONNECTION *c) {
	TUNNEL *t;
	BLOCK *b;

	if (c == NULL || (t = c->Tunnel) == NULL)
		return;

	TunnelStop(c);

	while ((b = GetNext(t->Received)) != NULL)
		FreeBlock(b);
	ReleaseQueue(t->Received);
	ReleaseCancel(t->Cancel);
	DeleteLock(t->Lock);
	Free(t);

	c->Tunnel = NULL;
}

// The receive of a Connection of type CONNECTION_NOISE, on the thread of its Session (ConnectionReceive): it waits as
// the server half of a Cascade does, for a frame of a reader (c1), of the Hub (c2) or the halt, then hands the frames
// that the readers queued to the Session. While a connection of the Tunnel is up the Session is not idle; once none is
// left, it ends.
void TunnelReceiveBlocks(CONNECTION *c, CANCEL *c1, CANCEL *c2) {
	TUNNEL *t = c->Tunnel;
	SESSION *s = c->Session;
	bool no_spinlock_for_delay = false;
	UINT queued = 0;
	UINT alive = 0;
	BLOCK *b;

	if (t == NULL || s == NULL)
		return;

	if (s->Hub != NULL)
		no_spinlock_for_delay = s->Hub->Option->NoSpinLockForPacketDelay;

	Lock(t->Lock);
	queued = GetQueueNum(t->Received);
	Unlock(t->Lock);

	if (queued == 0 && c->SendBlocks->num_item == 0) {
		UINT time = MIN(SELECT_TIME, GetNextDelayedPacketTickDiff(s));
		UINT num_delayed = LIST_NUM(s->DelayedPacketList);

		if (no_spinlock_for_delay || time >= 50 || num_delayed == 0)
			Select(NULL, (num_delayed == 0 ? time : (time > 100 ? (time - 100) : 1)), c1, c2);
		else
			YieldCpu();
	}

	UINT64 now = Tick64();

	Lock(t->Lock);
	{
		while ((b = GetNext(t->Received)) != NULL) {
			s->TotalRecvSize += b->Size;
			s->TotalRecvSizeReal += b->Size;
			InsertReceivedBlockToQueue(c, b);
		}

		alive = NoiseTunnelNumAlive(&t->Routes);
	}
	Unlock(t->Lock);

	if (alive == 0) {
		s->Halt = true;
	} else {
		UPDATE_LAST_COMM_TIME(s->LastCommTime, now);
	}
}

// The send of a Connection of type CONNECTION_NOISE, on the thread of its Session (ConnectionSend): each frame of the
// Hub goes as a data record over the connection that its flow hash selects; without a connection left it is dropped
void TunnelSendBlocks(CONNECTION *c) {
	TUNNEL *t = c->Tunnel;
	SESSION *s = c->Session;
	BLOCK *b;

	if (t == NULL || s == NULL)
		return;

	while ((b = GetNext(c->SendBlocks)) != NULL) {
		TUNNEL_CONN *k = NULL;

		c->CurrentSendQueueSize -= b->Size;

		Lock(t->Lock);
		{
			NOISE_SESSION *route = NoiseTunnelRoute(&t->Routes, NoiseTunnelFlowHash(b->Buf, b->Size));

			for (UINT i = 0; i < TUNNEL_MAX_CONNECTIONS && route != NULL && k == NULL; i++)
				if (t->Conn[i].Noise != NULL && &t->Conn[i].Noise->Session == route)
					k = &t->Conn[i];
		}
		Unlock(t->Lock);

		// The Noise session of k stays until TunnelStop, which runs on this thread
		if (k != NULL && TransportNoiseSend(k->Noise, NOISE_RECORD_DATA, b->Buf, b->Size)) {
			s->TotalSendSize += b->Size;
			s->TotalSendSizeReal += b->Size;

			Lock(t->Lock);
			k->NumSent++;
			Unlock(t->Lock);
		}

		FreeBlock(b);
	}
}

// What the Tunnel of c reports; zero for a Connection without one
void TunnelGetStatus(CONNECTION *c, TUNNEL_STATUS *st) {
	TUNNEL *t;

	if (st == NULL)
		return;

	Zero(st, sizeof(TUNNEL_STATUS));
	if (c == NULL || (t = c->Tunnel) == NULL)
		return;

	Lock(t->Lock);
	{
		st->NumConnections = NoiseTunnelNumAlive(&t->Routes);
		for (UINT i = 0; i < TUNNEL_MAX_CONNECTIONS; i++) {
			st->Received[i] = t->Conn[i].NumReceived;
			st->Sent[i] = t->Conn[i].NumSent;
		}
	}
	Unlock(t->Lock);
}
