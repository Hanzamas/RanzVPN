// natsim.c
// The NAT simulator of coretest (CORE-S5-2, #78): an in-process datagram network that carries the datagrams of the
// peer layer (src/Core/Peer.c) between hosts in place of UDP sockets. A host is on the public side or behind a NAT
// of its own. A NAT maps a private address and port to a public port (RFC 4787 section 4.1): once for every
// destination (endpoint independent mapping) or once per destination address and port (address and port dependent
// mapping, a symmetric NAT), on public ports that it allocates in order. It lets a datagram from outside in to a
// mapping from any address (endpoint independent filtering) or only from an address and port that the mapping
// sent to (address and port dependent filtering, section 5). A NAT may age its mappings, as a real one does (RFC 4787
// REQ-5): a mapping that carried no datagram out for its timeout is gone, and a datagram from outside to it is dropped.
// What the network drops, it counts.
//
// A NAT can also forward a public port to a host behind it, as a home gateway does for the port mapping that PCP,
// NAT-PMP or UPnP asked for (CORE-S5-6, #412; the simulated gateway of homegw.c): the forward takes datagrams from any
// address, never ages, and carries every datagram of that host out, whatever its destination. A test can drop the
// mappings of a host, as a NAT that restarts loses them, so that its next datagram out gets a new public port.
//
// One delivery thread hands the datagrams to PeerInput of the receiving host, in the order they were sent, so
// that a receiver that sends from its receive procedure queues behind the datagram it took.
//
// A carrier-grade NAT shares its public ports with other subscribers (CORE-S5-7, #413): NatSimTake lets them take a
// number of ports that the seeded generator of the NAT draws, so the next mapping of a host lands that many ports further
// on, as the port prediction of a host cannot know. A cut loses the datagrams between two NATs on the way, as a path that
// went down, and an injection hands a host a datagram past its NAT, as an attacker on its link would.

#include "natsim.h"

#include <string.h>

#define NATSIM_MAX_HOSTS    16
#define NATSIM_MAX_NATS     8
#define NATSIM_MAX_MAPPINGS 512   // The punch of CORE-S5-7 makes a mapping for each probe of a symmetric NAT
#define NATSIM_MAX_SENT     32    // Destinations that one mapping remembers for its filter
#define NATSIM_FIRST_PORT   40000 // The first public port that a NAT allocates

// One mapping of a NAT
typedef struct NATSIM_MAPPING {
	PEER_ADDR Inside;                // The private address and port
	PEER_ADDR Remote;                // The destination it was made for, with address and port dependent mapping
	USHORT Port;                     // The public port
	bool Forward;                    // A port forward (NatSimForward): in from anywhere, out to anywhere, never aged
	UINT NumSent;                    // The destinations it sent to
	PEER_ADDR Sent[NATSIM_MAX_SENT]; // ... their addresses and ports
	UINT64 LastOut;                  // When it last carried a datagram out (GetTickCount64)
} NATSIM_MAPPING;

struct NATSIM_NAT {
	PEER_ADDR Public;                             // The public address, port 0
	UINT Mapping;                                 // NATSIM_MAP_*
	UINT Filtering;                               // NATSIM_FILTER_*
	UINT Allocation;                              // NATSIM_ALLOC_*: how it picks the public port of a new mapping
	UINT32 RandState;                             // The generator of NATSIM_ALLOC_RANDOM, seeded per NAT
	USHORT NextPort;                              // The next public port it allocates, with NATSIM_ALLOC_SEQUENTIAL
	UINT NumMappings;                             // Its mappings
	NATSIM_MAPPING Mappings[NATSIM_MAX_MAPPINGS]; // ... in the order it made them
	volatile LONG Filtered;                       // Datagrams from outside that its filter dropped
	UINT Timeout;                                 // ms after which a mapping that carried nothing out is gone, 0 for never
	volatile LONG Expired;                        // Mappings that aged out
	bool Cut;                                     // The datagrams between it and another NAT are lost on the way (NatSimCut)
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
	volatile LONG CutCount;              // Datagrams between two NATs that a cut lost (NatSimCut)
	NATSIM_TAP *Tap;                     // Sees every datagram sent and may drop it, NULL for none
	void *TapParam;                      // ... its parameter
	volatile LONG Hold;                  // The delivery waits while it is set
	NATSIM_HOST *Delivering;             // The host whose peer layer the delivery thread hands a datagram to now
	DWORD ThreadId;                      // The delivery thread
};

static bool NatSimSameIp(const PEER_ADDR *a, const PEER_ADDR *b) {
	return memcmp(a->Ip, b->Ip, sizeof(a->Ip)) == 0;
}

// The delivery thread: one datagram at a time, in queue order. The host that it delivers to is marked while it does, so
// that a peer layer that leaves its host (NatSimAttach) is never handed a datagram after.
static DWORD WINAPI NatSimThread(void *param) {
	NATSIM *s = (NATSIM *)param;

	while (InterlockedCompareExchange(&s->Stop, 0, 0) == 0) {
		if (InterlockedCompareExchange(&s->Hold, 0, 0) != 0) {
			WaitForSingleObject(s->Event, 10);
			continue;
		}

		EnterCriticalSection(&s->Lock);
		NATSIM_ITEM *item = s->Head;
		if (item != NULL) {
			s->Head = item->Next;
			if (s->Head == NULL)
				s->Tail = NULL;
		}
		PEER_AGENT *agent = (item != NULL ? item->To->Agent : NULL);
		s->Delivering = (agent != NULL ? item->To : NULL);
		LeaveCriticalSection(&s->Lock);

		if (item == NULL) {
			WaitForSingleObject(s->Event, 100);
			continue;
		}

		if (agent != NULL)
			PeerInput(agent, &item->From, item->Data, item->Size);

		EnterCriticalSection(&s->Lock);
		s->Delivering = NULL;
		LeaveCriticalSection(&s->Lock);

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
	s->Thread = CreateThread(NULL, 0, NatSimThread, s, 0, &s->ThreadId);

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
		n->Allocation = NATSIM_ALLOC_SEQUENTIAL;
		n->RandState = 1;
		n->NextPort = NATSIM_FIRST_PORT;
	}
	LeaveCriticalSection(&s->Lock);

	return n;
}

// Set how the NAT picks the public port of a new mapping (NATSIM_ALLOC_*); seed is the generator of
// NATSIM_ALLOC_RANDOM, so a test is reproducible
void NatSimSetAllocation(NATSIM_NAT *n, UINT allocation, UINT32 seed) {
	n->Allocation = allocation;
	n->RandState = (seed != 0 ? seed : 1);
}

// Set the time after which a mapping of the NAT that carried no datagram out is gone, in ms (0: never, the default). A
// datagram out refreshes its mapping, one in does not (RFC 4787 REQ-6 lets a NAT choose).
void NatSimSetTimeout(NATSIM *s, NATSIM_NAT *n, UINT timeout) {
	EnterCriticalSection(&s->Lock);
	n->Timeout = timeout;
	LeaveCriticalSection(&s->Lock);
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

// The peer layer that the datagrams to the host go to; NULL drops them. A peer layer that leaves its host gets no
// datagram once this returns: it waits for the one that the delivery thread may be handing it, unless it runs on that
// thread, so the caller may free the layer after.
void NatSimAttach(NATSIM_HOST *h, PEER_AGENT *a) {
	NATSIM *s = h->Sim;

	while (true) {
		EnterCriticalSection(&s->Lock);
		bool busy = (a == NULL && s->Delivering == h && GetCurrentThreadId() != s->ThreadId);
		if (busy == false)
			h->Agent = a;
		LeaveCriticalSection(&s->Lock);

		if (busy == false)
			return;
		Sleep(1);
	}
}

// Whether the NAT already has a mapping on the public port, so a new one cannot reuse it
static bool NatSimPortUsed(NATSIM_NAT *n, USHORT port) {
	for (UINT i = 0; i < n->NumMappings; i++)
		if (n->Mappings[i].Port == port)
			return true;

	return false;
}

// One step of a seeded xorshift generator (George Marsaglia), for NATSIM_ALLOC_RANDOM
static UINT32 NatSimRand(NATSIM_NAT *n) {
	UINT32 x = n->RandState;

	x ^= x << 13;
	x ^= x >> 17;
	x ^= x << 5;
	n->RandState = x;

	return x;
}

// The public port of a new mapping of the NAT for the private address inside, by its allocation (NATSIM_ALLOC_*):
// the next free port in order, the private port where it is free, or a free port a seeded generator picks. The caller
// holds the lock.
static USHORT NatSimAllocPort(NATSIM_NAT *n, const PEER_ADDR *inside) {
	if (n->Allocation == NATSIM_ALLOC_PRESERVING && NatSimPortUsed(n, inside->Port) == false)
		return inside->Port;

	if (n->Allocation == NATSIM_ALLOC_RANDOM) {
		for (UINT i = 0; i < 64; i++) {
			USHORT port = (USHORT)(NATSIM_FIRST_PORT + NatSimRand(n) % (60000 - NATSIM_FIRST_PORT));

			if (NatSimPortUsed(n, port) == false)
				return port;
		}
	}

	// Sequential, or the fallback of a preserving or random NAT that found no free port: the next port in order
	while (NatSimPortUsed(n, n->NextPort))
		n->NextPort++;

	return n->NextPort++;
}

// Age the mappings of the NAT at now: the ones that carried no datagram out for its timeout are gone, a port forward
// never. The caller holds the lock.
static void NatSimAge(NATSIM_NAT *n, UINT64 now) {
	UINT kept = 0;

	if (n->Timeout == 0)
		return;

	for (UINT i = 0; i < n->NumMappings; i++) {
		if (n->Mappings[i].Forward == false && now - n->Mappings[i].LastOut >= n->Timeout) {
			InterlockedIncrement(&n->Expired);
			continue;
		}
		if (kept != i)
			n->Mappings[kept] = n->Mappings[i];
		kept++;
	}

	n->NumMappings = kept;
}

// The mapping of the NAT for a datagram from the private address inside to remote at now: a port forward of inside,
// else the one there is, or a new one. The caller holds the lock.
static NATSIM_MAPPING *NatSimMap(NATSIM_NAT *n, const PEER_ADDR *inside, const PEER_ADDR *remote, UINT64 now) {
	NATSIM_MAPPING *m = NULL;

	for (UINT i = 0; i < n->NumMappings && m == NULL; i++)
		if (n->Mappings[i].Forward && PeerAddrEqual(&n->Mappings[i].Inside, inside))
			m = &n->Mappings[i];

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
		m->Port = NatSimAllocPort(n, inside);
	}

	if (m != NULL) {
		bool known = false;

		for (UINT i = 0; i < m->NumSent; i++)
			if (PeerAddrEqual(&m->Sent[i], remote))
				known = true;
		if (known == false && m->NumSent < NATSIM_MAX_SENT)
			m->Sent[m->NumSent++] = *remote;
		m->LastOut = now;
	}

	return m;
}

// The host behind the NAT n that a datagram from outside, from the address from to the public port, goes to; NULL
// when the NAT has no such mapping or its filter drops the datagram. The caller holds the lock.
static NATSIM_HOST *NatSimInbound(NATSIM *s, NATSIM_NAT *n, USHORT port, const PEER_ADDR *from) {
	for (UINT i = 0; i < n->NumMappings; i++) {
		NATSIM_MAPPING *m = &n->Mappings[i];
		bool allowed = (n->Filtering == NATSIM_FILTER_ENDPOINT_INDEPENDENT || m->Forward);

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

	EnterCriticalSection(&s->Lock);
	NATSIM_TAP *tap = s->Tap;
	void *tap_param = s->TapParam;
	LeaveCriticalSection(&s->Lock);

	// What the tap drops leaves the host and is lost on the way
	if (tap != NULL && tap(tap_param, h, dst, (const UCHAR *)data, size) == false)
		return true;

	NATSIM_ITEM *item = (NATSIM_ITEM *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(NATSIM_ITEM));
	if (item == NULL)
		return false;

	EnterCriticalSection(&s->Lock);
	{
		UINT64 now = GetTickCount64();

		item->From = h->Addr;

		if (h->Nat != NULL) {
			NatSimAge(h->Nat, now);
			NATSIM_MAPPING *m = NatSimMap(h->Nat, &h->Addr, dst, now);

			item->From = h->Nat->Public;
			item->From.Port = (m != NULL ? m->Port : 0);
		}

		for (UINT i = 0; i < s->NumHosts && to == NULL; i++)
			if (s->Hosts[i].Nat == NULL && PeerAddrEqual(&s->Hosts[i].Addr, dst))
				to = &s->Hosts[i];

		for (UINT i = 0; i < s->NumNats && to == NULL && routed == false; i++) {
			if (NatSimSameIp(&s->Nats[i].Public, dst)) {
				routed = true;
				if (h->Nat != NULL && (h->Nat->Cut || s->Nats[i].Cut)) {
					// A cut between two NATs loses it on the way, after the NAT of the sender mapped it
					InterlockedIncrement(&s->CutCount);
					break;
				}
				NatSimAge(&s->Nats[i], now);
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

// Set the tap that sees every datagram sent from now on, NULL for none
void NatSimSetTap(NATSIM *s, NATSIM_TAP *tap, void *param) {
	EnterCriticalSection(&s->Lock);
	s->Tap = tap;
	s->TapParam = param;
	LeaveCriticalSection(&s->Lock);
}

// Hold the delivery of the datagrams, or release it
void NatSimHold(NATSIM *s, bool hold) {
	InterlockedExchange(&s->Hold, hold ? 1 : 0);
	SetEvent(s->Event);
}

// The datagrams from outside that the filter of the NAT dropped
UINT NatSimFiltered(NATSIM_NAT *n) {
	return (UINT)InterlockedCompareExchange(&n->Filtered, 0, 0);
}

// The mappings of the NAT that aged out (NatSimSetTimeout)
UINT NatSimExpired(NATSIM_NAT *n) {
	return (UINT)InterlockedCompareExchange(&n->Expired, 0, 0);
}

// The datagrams to an address that no host and no NAT of the network has
UINT NatSimUnroutable(NATSIM *s) {
	return (UINT)InterlockedCompareExchange(&s->Unroutable, 0, 0);
}

// The public address of the NAT, port 0
void NatSimPublic(NATSIM_NAT *n, PEER_ADDR *pub) {
	*pub = n->Public;
}

// Forward the public port of the NAT to the host behind it whose port is inside_port, as a home gateway does for a
// port mapping: false when the NAT has a mapping on that port already, or no such host
bool NatSimForward(NATSIM *s, NATSIM_NAT *n, USHORT port, USHORT inside_port) {
	bool ok = false;

	EnterCriticalSection(&s->Lock);
	{
		NATSIM_HOST *h = NULL;

		for (UINT i = 0; i < s->NumHosts && h == NULL; i++)
			if (s->Hosts[i].Nat == n && s->Hosts[i].Addr.Port == inside_port)
				h = &s->Hosts[i];

		if (port != 0 && h != NULL && NatSimPortUsed(n, port) == false && n->NumMappings < NATSIM_MAX_MAPPINGS) {
			NATSIM_MAPPING *m = &n->Mappings[n->NumMappings++];

			ZeroMemory(m, sizeof(NATSIM_MAPPING));
			m->Inside = h->Addr;
			m->Port = port;
			m->Forward = true;
			m->LastOut = GetTickCount64();
			ok = true;
		}
	}
	LeaveCriticalSection(&s->Lock);

	return ok;
}

// Remove the forward of the public port of the NAT; false when it has none there
bool NatSimUnforward(NATSIM *s, NATSIM_NAT *n, USHORT port) {
	bool found = false;

	EnterCriticalSection(&s->Lock);
	{
		UINT kept = 0;

		for (UINT i = 0; i < n->NumMappings; i++) {
			if (n->Mappings[i].Forward && n->Mappings[i].Port == port) {
				found = true;
				continue;
			}
			if (kept != i)
				n->Mappings[kept] = n->Mappings[i];
			kept++;
		}

		n->NumMappings = kept;
	}
	LeaveCriticalSection(&s->Lock);

	return found;
}

// Drop every mapping of the NAT for the private address inside but a port forward, as a NAT that restarts loses them:
// a datagram from outside to one of their ports is dropped, and the next datagram of inside out gets a new mapping.
// Returns how many it dropped.
UINT NatSimDrop(NATSIM *s, NATSIM_NAT *n, const PEER_ADDR *inside) {
	UINT dropped = 0;

	EnterCriticalSection(&s->Lock);
	{
		UINT kept = 0;

		for (UINT i = 0; i < n->NumMappings; i++) {
			if (n->Mappings[i].Forward == false && PeerAddrEqual(&n->Mappings[i].Inside, inside)) {
				dropped++;
				continue;
			}
			if (kept != i)
				n->Mappings[kept] = n->Mappings[i];
			kept++;
		}

		n->NumMappings = kept;
	}
	LeaveCriticalSection(&s->Lock);

	return dropped;
}

// The other subscribers of a carrier-grade NAT take public ports now, between two mappings of the hosts of the test: as
// many as the seeded generator of the NAT draws from 0 to max, so the next mapping of a host lands that many ports
// further on, a step that its port prediction cannot see. Only a NAT that allocates in order has ports to take; returns
// how many the others took.
UINT NatSimTake(NATSIM *s, NATSIM_NAT *n, UINT max) {
	UINT taken = 0;

	EnterCriticalSection(&s->Lock);
	if (n->Allocation == NATSIM_ALLOC_SEQUENTIAL) {
		taken = NatSimRand(n) % (max + 1);

		for (UINT i = 0; i < taken; i++) {
			while (NatSimPortUsed(n, n->NextPort))
				n->NextPort++;
			n->NextPort++;
		}
	}
	LeaveCriticalSection(&s->Lock);

	return taken;
}

// Cut the NAT off from every other NAT, or join it again: while it is cut, a datagram between its public address and the
// public address of another NAT is lost on the way, after the NAT that sent it mapped it, as on a path that went down,
// while the datagrams to and from the public hosts pass
void NatSimCut(NATSIM *s, NATSIM_NAT *n, bool cut) {
	EnterCriticalSection(&s->Lock);
	n->Cut = cut;
	LeaveCriticalSection(&s->Lock);
}

// The datagrams between two NATs that a cut lost
UINT NatSimCutCount(NATSIM *s) {
	return (UINT)InterlockedCompareExchange(&s->CutCount, 0, 0);
}

// Hand the host to a datagram from the address from, past its NAT, as an attacker on the link of the host would; it
// queues behind the datagrams on their way. False when there is no memory for it.
bool NatSimInject(NATSIM_HOST *to, const PEER_ADDR *from, const void *data, UINT size) {
	NATSIM *s = to->Sim;

	if (size == 0 || size > PEER_MAX_DATAGRAM)
		return false;

	NATSIM_ITEM *item = (NATSIM_ITEM *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(NATSIM_ITEM));
	if (item == NULL)
		return false;

	item->To = to;
	item->From = *from;
	item->Size = size;
	CopyMemory(item->Data, data, size);

	EnterCriticalSection(&s->Lock);
	if (s->Tail != NULL)
		s->Tail->Next = item;
	else
		s->Head = item;
	s->Tail = item;
	InterlockedIncrement(&s->Queued);
	LeaveCriticalSection(&s->Lock);

	SetEvent(s->Event);

	return true;
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
