// Connection.c
// Connection Manager

#include "Connection.h"

#include "Hub.h"
#include "Session.h"

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

void InsertReceivedBlockToQueue(CONNECTION *c, BLOCK *block) {
	if (c == NULL || block == NULL)
		return;

	if (c->ReceivedBlocks->num_item < MAX_STORED_QUEUE_NUM)
		InsertQueue(c->ReceivedBlocks, block);
	else
		FreeBlock(block);
}

// The send of a Connection, on the thread of its Session: the Tunnel of a Connection of type CONNECTION_NOISE sends the
// blocks that the Session queued. A Connection without a transport sends nothing
void ConnectionSend(CONNECTION *c) {
	if (c == NULL)
		return;

	if (c->Protocol == CONNECTION_NOISE)
		TunnelSendBlocks(c);
}

// The receive of a Connection, on the thread of its Session: the Tunnel of a Connection of type CONNECTION_NOISE hands
// the blocks that it received to the Session. A Connection without a transport receives nothing
void ConnectionReceive(CONNECTION *c, CANCEL *c1, CANCEL *c2) {
	if (c == NULL)
		return;

	if (c->Protocol == CONNECTION_NOISE)
		TunnelReceiveBlocks(c, c1, c2);
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

static void CleanupConnection(CONNECTION *c) {
	if (c == NULL)
		return;

	if (c->LastPacketQueueSize != 0) {
		int diff = -((int)c->LastPacketQueueSize);
		CedarAddCurrentTcpQueueSize(c->Cedar, diff);
		c->LastPacketQueueSize = 0;
	}

	DeleteLock(c->lock);
	ReleaseCedar(c->Cedar);

	FreeTunnel(c);

	ReleaseSock(c->FirstSock);
	c->FirstSock = NULL;

	ReleaseThread(c->Thread);
	Free(c->Name);

	FreeBlockQueue(c->SendBlocks);
	FreeBlockQueue(c->ReceivedBlocks);

	if (c->ServerX != NULL)
		FreeX(c->ServerX);

	if (c->ClientX != NULL)
		FreeX(c->ClientX);

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

CONNECTION *NewServerConnection(CEDAR *cedar, SOCK *s, THREAD *t) {
	if (cedar == NULL)
		return NULL;

	CONNECTION *c = ZeroMalloc(sizeof(CONNECTION));
	c->ConnectedTick = Tick64();
	c->lock = NewLock();
	c->ref = NewRef();
	c->Cedar = cedar;
	AddRef(c->Cedar->ref);
	c->Protocol = CONNECTION_TCP;
	c->ServerMode = true;

	c->ReceivedBlocks = NewQueue();
	c->SendBlocks = NewQueue();

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

	if (s != NULL && s->RemoteX != NULL)
		c->ServerX = CloneX(s->RemoteX);

	return c;
}
