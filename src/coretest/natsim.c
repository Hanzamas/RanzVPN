// natsim.c
// The NAT simulator of coretest (CORE-S5-2, #78): an in-process datagram network that carries the datagrams of the
// peer layer (src/Core/Peer.c) between hosts in place of UDP sockets. A host is on the public side or behind a NAT
// of its own. A NAT maps a private address and port to a public port (RFC 4787 section 4.1): once for every
// destination (endpoint independent mapping) or once per destination address and port (address and port dependent
// mapping, a symmetric NAT), on public ports that it allocates in order. It lets a datagram from outside in to a
// mapping from any address (endpoint independent filtering) or only from an address and port that the mapping
// sent to (address and port dependent filtering, section 5). What the network drops, it counts.
//
// One delivery thread hands the datagrams to PeerInput of the receiving host, in the order they were sent, so
// that a receiver that sends from its receive procedure queues behind the datagram it took.

#include "coretest.h"

#include <string.h>

#define NATSIM_MAX_HOSTS    16
#define NATSIM_MAX_NATS     8
#define NATSIM_MAX_MAPPINGS 64
#define NATSIM_MAX_SENT     16    // Destinations that one mapping remembers for its filter
#define NATSIM_FIRST_PORT   40000 // The first public port that a NAT allocates

// One mapping of a NAT
typedef struct NATSIM_MAPPING {
	PEER_ADDR Inside;                // The private address and port
	PEER_ADDR Remote;                // The destination it was made for, with address and port dependent mapping
	USHORT Port;                     // The public port
	UINT NumSent;                    // The destinations it sent to
	PEER_ADDR Sent[NATSIM_MAX_SENT]; // ... their addresses and ports
} NATSIM_MAPPING;

struct NATSIM_NAT {
	PEER_ADDR Public;                             // The public address, port 0
	UINT Mapping;                                 // NATSIM_MAP_*
	UINT Filtering;                               // NATSIM_FILTER_*
	USHORT NextPort;                              // The next public port it allocates
	UINT NumMappings;                             // Its mappings
	NATSIM_MAPPING Mappings[NATSIM_MAX_MAPPINGS]; // ... in the order it made them
	volatile LONG Filtered;                       // Datagrams from outside that its filter dropped
};

struct NATSIM_HOST {
	NATSIM *Sim;       // The network
	NATSIM_NAT *Nat;   // Its NAT, NULL on the public side
	PEER_ADDR Addr;    // Its address: private behind a NAT
	PEER_AGENT *Agent; // The peer layer that its datagrams go to
};

// One datagram on its way
typedef struct NATSIM_ITEM {
	struct NATSIM_ITEM *Next;      // The next one in the queue
	NATSIM_HOST *To;               // The receiving host
	PEER_ADDR From;                // The address it comes from, as the receiver sees it
	UINT Size;                     // Its size
	UCHAR Data[PEER_MAX_DATAGRAM]; // Its bytes
} NATSIM_ITEM;

struct NATSIM {
	CRITICAL_SECTION Lock;               // The NATs, the hosts and the queue
	HANDLE Event;                        // Set when the queue holds datagrams
	HANDLE Thread;                       // The delivery thread
	volatile LONG Stop;                  // Ends it
	NATSIM_ITEM *Head;                   // The queue: first
	NATSIM_ITEM *Tail;                   // ... and last datagram
	UINT NumNats;                        // The NATs
	NATSIM_NAT Nats[NATSIM_MAX_NATS];    // ... of the network
	UINT NumHosts;                       // The hosts
	NATSIM_HOST Hosts[NATSIM_MAX_HOSTS]; // ... of the network
	volatile LONG Queued;                // Datagrams queued so far
	volatile LONG Done;                  // ... and handed to their receiver so far
	volatile LONG Unroutable;            // Datagrams to an address that no host and no NAT has
};

static bool NatSimSameIp(const PEER_ADDR *a, const PEER_ADDR *b) {
	return memcmp(a->Ip, b->Ip, sizeof(a->Ip)) == 0;
}

// The delivery thread: one datagram at a time, in queue order
static DWORD WINAPI NatSimThread(void *param) {
	NATSIM *s = (NATSIM *)param;

	while (InterlockedCompareExchange(&s->Stop, 0, 0) == 0) {
		EnterCriticalSection(&s->Lock);
		NATSIM_ITEM *item = s->Head;
		if (item != NULL) {
			s->Head = item->Next;
			if (s->Head == NULL)
				s->Tail = NULL;
		}
		PEER_AGENT *agent = (item != NULL ? item->To->Agent : NULL);
		LeaveCriticalSection(&s->Lock);

		if (item == NULL) {
			WaitForSingleObject(s->Event, 100);
			continue;
		}

		if (agent != NULL)
			PeerInput(agent, &item->From, item->Data, item->Size);

		HeapFree(GetProcessHeap(), 0, item);
		InterlockedIncrement(&s->Done);
	}

	return 0;
}

NATSIM *NatSimNew() {
	NATSIM *s = (NATSIM *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(NATSIM));
	if (s == NULL)
		return NULL;

	InitializeCriticalSection(&s->Lock);
	s->Event = CreateEventW(NULL, FALSE, FALSE, NULL);
	s->Thread = CreateThread(NULL, 0, NatSimThread, s, 0, NULL);

	return s;
}

// Stop the delivery thread and free the network; the datagrams still queued are dropped
void NatSimFree(NATSIM *s) {
	if (s == NULL)
		return;

	InterlockedExchange(&s->Stop, 1);
	SetEvent(s->Event);
	if (s->Thread != NULL) {
		WaitForSingleObject(s->Thread, INFINITE);
		CloseHandle(s->Thread);
	}

	while (s->Head != NULL) {
		NATSIM_ITEM *next = s->Head->Next;

		HeapFree(GetProcessHeap(), 0, s->Head);
		s->Head = next;
	}

	CloseHandle(s->Event);
	DeleteCriticalSection(&s->Lock);
	HeapFree(GetProcessHeap(), 0, s);
}

// A NAT with the public address b0.b1.b2.b3, its mapping (NATSIM_MAP_*) and its filtering (NATSIM_FILTER_*)
NATSIM_NAT *NatSimAddNat(NATSIM *s, UCHAR b0, UCHAR b1, UCHAR b2, UCHAR b3, UINT mapping, UINT filtering) {
	NATSIM_NAT *n = NULL;

	EnterCriticalSection(&s->Lock);
	if (s->NumNats < NATSIM_MAX_NATS) {
		n = &s->Nats[s->NumNats++];
		PeerAddrSetV4(&n->Public, b0, b1, b2, b3, 0);
		n->Mapping = mapping;
		n->Filtering = filtering;
		n->NextPort = NATSIM_FIRST_PORT;
	}
	LeaveCriticalSection(&s->Lock);

	return n;
}

// A host with the address addr behind the NAT nat, or on the public side for NULL
NATSIM_HOST *NatSimAddHost(NATSIM *s, NATSIM_NAT *nat, const PEER_ADDR *addr) {
	NATSIM_HOST *h = NULL;

	EnterCriticalSection(&s->Lock);
	if (s->NumHosts < NATSIM_MAX_HOSTS) {
		h = &s->Hosts[s->NumHosts++];
		h->Sim = s;
		h->Nat = nat;
		h->Addr = *addr;
	}
	LeaveCriticalSection(&s->Lock);

	return h;
}

// The peer layer that the datagrams to the host go to; NULL drops them
void NatSimAttach(NATSIM_HOST *h, PEER_AGENT *a) {
	EnterCriticalSection(&h->Sim->Lock);
	h->Agent = a;
	LeaveCriticalSection(&h->Sim->Lock);
}

// The mapping of the NAT for a datagram from the private address inside to remote: the one there is, or a new one.
// The caller holds the lock.
static NATSIM_MAPPING *NatSimMap(NATSIM_NAT *n, const PEER_ADDR *inside, const PEER_ADDR *remote) {
	NATSIM_MAPPING *m = NULL;

	for (UINT i = 0; i < n->NumMappings && m == NULL; i++) {
		NATSIM_MAPPING *c = &n->Mappings[i];

		if (PeerAddrEqual(&c->Inside, inside) && (n->Mapping == NATSIM_MAP_ENDPOINT_INDEPENDENT || PeerAddrEqual(&c->Remote, remote)))
			m = c;
	}

	if (m == NULL && n->NumMappings < NATSIM_MAX_MAPPINGS) {
		m = &n->Mappings[n->NumMappings++];
		ZeroMemory(m, sizeof(NATSIM_MAPPING));
		m->Inside = *inside;
		if (n->Mapping != NATSIM_MAP_ENDPOINT_INDEPENDENT)
			m->Remote = *remote;
		m->Port = n->NextPort++;
	}

	if (m != NULL) {
		bool known = false;

		for (UINT i = 0; i < m->NumSent; i++)
			if (PeerAddrEqual(&m->Sent[i], remote))
				known = true;
		if (known == false && m->NumSent < NATSIM_MAX_SENT)
			m->Sent[m->NumSent++] = *remote;
	}

	return m;
}

// The host behind the NAT n that a datagram from outside, from the address from to the public port, goes to; NULL
// when the NAT has no such mapping or its filter drops the datagram. The caller holds the lock.
static NATSIM_HOST *NatSimInbound(NATSIM *s, NATSIM_NAT *n, USHORT port, const PEER_ADDR *from) {
	for (UINT i = 0; i < n->NumMappings; i++) {
		NATSIM_MAPPING *m = &n->Mappings[i];
		bool allowed = (n->Filtering == NATSIM_FILTER_ENDPOINT_INDEPENDENT);

		if (m->Port != port)
			continue;

		for (UINT j = 0; j < m->NumSent && allowed == false; j++)
			if (PeerAddrEqual(&m->Sent[j], from))
				allowed = true;

		if (allowed == false)
			break;

		for (UINT j = 0; j < s->NumHosts; j++)
			if (s->Hosts[j].Nat == n && PeerAddrEqual(&s->Hosts[j].Addr, &m->Inside))
				return &s->Hosts[j];

		return NULL;
	}

	InterlockedIncrement(&n->Filtered);
	return NULL;
}

// The PEER_SEND_PROC of a host (param): the datagram leaves through the host's NAT, if it has one, and goes to the
// public host of dst, or through the NAT that owns the address of dst to the host behind it. It always leaves the
// host, so this returns true; what the network drops, it counts.
bool NatSimSend(void *param, const PEER_ADDR *dst, const void *data, UINT size) {
	NATSIM_HOST *h = (NATSIM_HOST *)param;
	NATSIM *s = h->Sim;
	NATSIM_HOST *to = NULL;
	bool routed = false;

	if (size == 0 || size > PEER_MAX_DATAGRAM)
		return false;

	NATSIM_ITEM *item = (NATSIM_ITEM *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(NATSIM_ITEM));
	if (item == NULL)
		return false;

	EnterCriticalSection(&s->Lock);
	{
		item->From = h->Addr;

		if (h->Nat != NULL) {
			NATSIM_MAPPING *m = NatSimMap(h->Nat, &h->Addr, dst);

			item->From = h->Nat->Public;
			item->From.Port = (m != NULL ? m->Port : 0);
		}

		for (UINT i = 0; i < s->NumHosts && to == NULL; i++)
			if (s->Hosts[i].Nat == NULL && PeerAddrEqual(&s->Hosts[i].Addr, dst))
				to = &s->Hosts[i];

		for (UINT i = 0; i < s->NumNats && to == NULL && routed == false; i++) {
			if (NatSimSameIp(&s->Nats[i].Public, dst)) {
				routed = true;
				to = NatSimInbound(s, &s->Nats[i], dst->Port, &item->From);
			}
		}

		if (to == NULL && routed == false)
			InterlockedIncrement(&s->Unroutable);

		if (to != NULL && item->From.Port != 0) {
			item->To = to;
			item->Size = size;
			CopyMemory(item->Data, data, size);

			if (s->Tail != NULL)
				s->Tail->Next = item;
			else
				s->Head = item;
			s->Tail = item;
			InterlockedIncrement(&s->Queued);
			item = NULL;
		}
	}
	LeaveCriticalSection(&s->Lock);

	if (item != NULL)
		HeapFree(GetProcessHeap(), 0, item);
	else
		SetEvent(s->Event);

	return true;
}

// Wait until every datagram sent so far, and every one that its receiver sent back meanwhile, was handed over;
// false when that takes longer than timeout ms
bool NatSimWaitIdle(NATSIM *s, UINT timeout) {
	ULONGLONG end = GetTickCount64() + timeout;

	while (InterlockedCompareExchange(&s->Done, 0, 0) != InterlockedCompareExchange(&s->Queued, 0, 0)) {
		if (GetTickCount64() >= end)
			return false;
		Sleep(1);
	}

	return true;
}

// The datagrams from outside that the filter of the NAT dropped
UINT NatSimFiltered(NATSIM_NAT *n) {
	return (UINT)InterlockedCompareExchange(&n->Filtered, 0, 0);
}

// The datagrams to an address that no host and no NAT of the network has
UINT NatSimUnroutable(NATSIM *s) {
	return (UINT)InterlockedCompareExchange(&s->Unroutable, 0, 0);
}

// The public address and port of the newest mapping of the NAT for the private address inside, for the checks of
// the tests; false when it has none
bool NatSimMapped(NATSIM_NAT *n, const PEER_ADDR *inside, PEER_ADDR *pub) {
	bool ret = false;

	ZeroMemory(pub, sizeof(PEER_ADDR));
	for (UINT i = 0; i < n->NumMappings; i++) {
		if (PeerAddrEqual(&n->Mappings[i].Inside, inside)) {
			*pub = n->Public;
			pub->Port = n->Mappings[i].Port;
			ret = true;
		}
	}

	return ret;
}
