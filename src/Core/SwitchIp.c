// SwitchIp.c
// The IP table of the L2 switch (Switch.h; SDN-50-N, #492): the IP addresses that the members of a Network send from, per
// VLAN, each with the MAC address and the port of its last frame, as the IP table of the Hub holds them. The switch learns
// them on its one ingress, once the filter let a frame through and its VLAN took it (SwitchIpLearn): the source address of
// an IPv4 packet whose header is whole, the sender address of an ARP packet of IPv4 over Ethernet, and the source address of
// an IPv6 packet whose header is whole, each with the source address of the frame. An address that no host sends from is not
// learnt: 0.0.0.0/8 (a DHCP client before its lease, an ARP probe), 127.0.0.0/8, an IPv4 multicast, reserved or broadcast
// address (224.0.0.0 and above), and the unspecified, the loopback and the multicast addresses of IPv6. A frame whose
// EtherType after its addresses and its tag is another, a second tag among them, teaches the table nothing. The table forgets
// the entries of a port that a member leaves or whose VLANs change, as the MAC table does, and ages with it (SwitchAge); the
// operators read it (SwitchGetIps) and clear it, every entry or the entries of one address (SwitchClearIps).
//
// The table is split into SWITCH_IP_SHARDS shards by a keyed hash of the VLAN and the address, each a table with open
// addressing and linear probing under a lock of its own. The data path holds the lock of a shard shared to find the entry of
// a frame, and a frame from the MAC address and the port of its entry within SWITCH_IP_REFRESH writes nothing; a change holds
// it exclusive. So the frames of a known host only read the table, and no lock serialises the switch.

#include "Core/SwitchInternal.h"

#include <stdlib.h>
#include <string.h>

#define SWITCH_IP_CACHE_LINE 64                          // The cache line that a shard keeps to itself
#define SWITCH_IP_SHARD_BITS 6                           // The table in 2^6 shards, chosen by the top bits of the hash
#define SWITCH_IP_SHARDS     (1 << SWITCH_IP_SHARD_BITS) // ... their number
#define SWITCH_IP_MIN_SLOTS  8                           // Slots of a shard at least
#define SWITCH_IP_REFRESH    1000                        // ms between two refreshes of an entry by the frames from its host, as for the MAC table

// The frames that the table learns from: their EtherType, and the least size of their packet
#define SWITCH_IP_IPV4        0x0800 // IPv4 ...
#define SWITCH_IP_IPV4_HEADER 20     // ... its header without options
#define SWITCH_IP_ARP         0x0806 // ARP ...
#define SWITCH_IP_ARP_SIZE    28     // ... a packet of IPv4 over Ethernet
#define SWITCH_IP_IPV6        0x86DD // IPv6 ...
#define SWITCH_IP_IPV6_HEADER 40     // ... its header

// What a sweep of the table takes out (SWITCH_IP_SWEEP)
#define SWITCH_IP_SWEEP_AGE     0 // The entries that no frame refreshed for the aging time
#define SWITCH_IP_SWEEP_PORT    1 // The entries of one port
#define SWITCH_IP_SWEEP_ADDRESS 2 // The entries of one address, in every VLAN
#define SWITCH_IP_SWEEP_ALL     3 // Every entry

// One entry of the table. A free slot has the tag 0, which no entry has, as a VLAN id of a frame is never 0.
typedef struct SWITCH_IP_SLOT {
	UINT Tag;          // The VLAN id (bits 8 to 19) and the size of the address, 4 or 16 (bits 0 to 7)
	UCHAR Address[16]; // The address: an IPv4 one in its first 4 bytes, zeroes after them
	UCHAR Mac[6];      // The MAC address of the last frame from it
	UINT Port;         // ... the port that the frame came in at
	UINT Gen;          // ... the generation of the port then
	UINT64 LastSeen;   // ... and the time of the frame (ms)
} SWITCH_IP_SLOT;

// A shard of the table, on a cache line of its own
typedef union SWITCH_IP_SHARD {
	struct {
		SRWLOCK Lock;          // Shared to find an entry, exclusive to change the slots
		UINT Num;              // The entries
		UINT MaxNum;           // ... at most: three quarters of the slots, so that every probe ends at a free slot
		UINT Mask;             // The number of slots, a power of 2, less 1
		SWITCH_IP_SLOT *Slots; // The slots
	};
	UCHAR Line[SWITCH_IP_CACHE_LINE];
} SWITCH_IP_SHARD;

// The IP table of a switch
struct SWITCH_IP_TABLE {
	UINT64 Seed;             // The random key of the hash, so that the members of a Network cannot choose the slots of their addresses
	UINT MaxIps;             // Entries at most
	SWITCH_IP_SHARD *Shards; // The shards, each on a cache line of its own
	SWITCH_IP_SLOT *Slots;   // The slots of every shard
	volatile LONG NumIps;    // The entries
	volatile LONG64 Learnt;  // Entries learnt
	volatile LONG64 Moved;   // ... that came from another MAC address or port
	volatile LONG64 Refused; // Addresses not learnt, as the table was full
};

// What a sweep takes out
typedef struct SWITCH_IP_SWEEP {
	UINT Kind;         // SWITCH_IP_SWEEP_*
	UINT64 Now;        // AGE: the time now ...
	UINT Aging;        // ... and the aging time (ms)
	UINT Port;         // PORT: the port
	UCHAR Address[16]; // ADDRESS: the address, an IPv4 one followed by zeroes ...
	UINT Size;         // ... and its size, 4 or 16
} SWITCH_IP_SWEEP;

//
// The slots
//

// The finaliser of SplitMix64
static UINT64 SwitchIpMix(UINT64 h) {
	h = (h ^ (h >> 30)) * 0xBF58476D1CE4E5B9ULL;
	h = (h ^ (h >> 27)) * 0x94D049BB133111EBULL;
	return h ^ (h >> 31);
}

// The hash of the tag and the 16 bytes of an address under the random key of the table: its top bits choose the shard, and
// its low bits the slot where the probe of the entry starts
static UINT64 SwitchIpHash(const SWITCH_IP_TABLE *t, UINT tag, const UCHAR *address) {
	UINT64 lo = 0;
	UINT64 hi = 0;

	CopyMemory(&lo, address, sizeof(lo));
	CopyMemory(&hi, address + 8, sizeof(hi));

	return SwitchIpMix(SwitchIpMix(SwitchIpMix(t->Seed ^ tag) ^ lo) ^ hi);
}

// The shard of a hash
static SWITCH_IP_SHARD *SwitchIpShardOf(SWITCH_IP_TABLE *t, UINT64 h) {
	return &t->Shards[h >> (64 - SWITCH_IP_SHARD_BITS)];
}

// The slot of the entry of tag and address in a shard, or the free slot that ends its probe; NULL when no slot is free. The
// caller holds the lock of the shard.
static SWITCH_IP_SLOT *SwitchIpFind(SWITCH_IP_SHARD *s, UINT tag, const UCHAR *address, UINT64 h) {
	UINT i = (UINT)h & s->Mask;

	for (UINT n = 0; n <= s->Mask; n++) {
		SWITCH_IP_SLOT *e = &s->Slots[i];

		if (e->Tag == 0 || (e->Tag == tag && memcmp(e->Address, address, sizeof(e->Address)) == 0))
			return e;
		i = (i + 1) & s->Mask;
	}

	return NULL;
}

// Take out the entry in slot i of a shard. The entries after it in its probe move back, so that no probe meets a free slot
// before its entry: deletion in linear probing without tombstones, as in the MAC table. The caller holds the lock of the
// shard exclusive.
static void SwitchIpDelete(const SWITCH_IP_TABLE *t, SWITCH_IP_SHARD *s, UINT i) {
	UINT j = i;

	while (true) {
		j = (j + 1) & s->Mask;

		const SWITCH_IP_SLOT *e = &s->Slots[j];
		if (e->Tag == 0)
			break;

		// The entry in j stays when the slot where its probe starts lies cyclically in (i, j]
		UINT home = (UINT)SwitchIpHash(t, e->Tag, e->Address) & s->Mask;
		if (i <= j ? (i < home && home <= j) : (i < home || home <= j))
			continue;

		s->Slots[i] = *e;
		i = j;
	}

	ZeroMemory(&s->Slots[i], sizeof(SWITCH_IP_SLOT));
	s->Num--;
}

// Take one more entry of the table; false when it holds MaxIps
static bool SwitchIpTakeOne(SWITCH_IP_TABLE *t) {
	if (InterlockedIncrement(&t->NumIps) <= (LONG)t->MaxIps)
		return true;

	InterlockedDecrement(&t->NumIps);
	return false;
}

// Learn that the address of size bytes at address, in the VLAN vlan, sent the frame of the MAC address mac that came in at
// port, of the generation gen, at now: a new entry, or an entry that moves to another MAC address or port. An entry of that
// MAC address and port that a frame refreshed within SWITCH_IP_REFRESH is only read.
static void SwitchIpTake(SWITCH_IP_TABLE *t, UINT64 now, UINT vlan, const UCHAR *address, UINT size, const UCHAR *mac, UINT port, UINT gen) {
	UCHAR key[16];
	UINT tag = (vlan << 8) | size;

	ZeroMemory(key, sizeof(key));
	CopyMemory(key, address, size);

	UINT64 h = SwitchIpHash(t, tag, key);
	SWITCH_IP_SHARD *s = SwitchIpShardOf(t, h);

	AcquireSRWLockShared(&s->Lock);
	const SWITCH_IP_SLOT *e = SwitchIpFind(s, tag, key, h);
	bool fresh = (e != NULL && e->Tag != 0 && e->Port == port && e->Gen == gen && memcmp(e->Mac, mac, sizeof(e->Mac)) == 0 && now < e->LastSeen + SWITCH_IP_REFRESH);
	ReleaseSRWLockShared(&s->Lock);
	if (fresh)
		return;

	AcquireSRWLockExclusive(&s->Lock);
	{
		SWITCH_IP_SLOT *w = SwitchIpFind(s, tag, key, h);

		if (w != NULL && w->Tag != 0) {
			if (w->Port != port || w->Gen != gen || memcmp(w->Mac, mac, sizeof(w->Mac)) != 0) {
				CopyMemory(w->Mac, mac, sizeof(w->Mac));
				w->Port = port;
				w->Gen = gen;
				InterlockedIncrement64(&t->Moved);
			}
			if (now > w->LastSeen)
				w->LastSeen = now;
		} else if (w != NULL && s->Num < s->MaxNum && SwitchIpTakeOne(t)) {
			w->Tag = tag;
			CopyMemory(w->Address, key, sizeof(w->Address));
			CopyMemory(w->Mac, mac, sizeof(w->Mac));
			w->Port = port;
			w->Gen = gen;
			w->LastSeen = now;
			s->Num++;
			InterlockedIncrement64(&t->Learnt);
		} else {
			InterlockedIncrement64(&t->Refused);
		}
	}
	ReleaseSRWLockExclusive(&s->Lock);
}

// Whether an IPv4 address is one that a host sends from: not in 0.0.0.0/8 or 127.0.0.0/8, and below 224.0.0.0 (multicast,
// reserved and broadcast)
static bool SwitchIpHost4(const UCHAR *a) {
	return a[0] != 0 && a[0] != 127 && a[0] < 224;
}

// Whether an IPv6 address is one that a host sends from: not multicast (ff00::/8), not the unspecified address (::) and not
// the loopback address (::1)
static bool SwitchIpHost6(const UCHAR *a) {
	static const UCHAR zero[15] = {0};

	if (a[0] == 0xFF)
		return false;

	return memcmp(a, zero, sizeof(zero)) != 0 || a[15] > 1;
}

//
// The sweeps
//

// Whether the sweep w takes out the entry e
static bool SwitchIpSweeps(const SWITCH_IP_SLOT *e, const SWITCH_IP_SWEEP *w) {
	switch (w->Kind) {
	case SWITCH_IP_SWEEP_AGE:
		return w->Now >= e->LastSeen + w->Aging;
	case SWITCH_IP_SWEEP_PORT:
		return e->Port == w->Port;
	case SWITCH_IP_SWEEP_ADDRESS:
		return (e->Tag & 0xFF) == w->Size && memcmp(e->Address, w->Address, sizeof(e->Address)) == 0;
	default:
		return true;
	}
}

// Take out the entries of the table that the sweep w takes; their number
static UINT SwitchIpSweep(SWITCH_IP_TABLE *t, const SWITCH_IP_SWEEP *w) {
	UINT num = 0;

	if (t == NULL)
		return 0;

	for (UINT k = 0; k < SWITCH_IP_SHARDS; k++) {
		SWITCH_IP_SHARD *s = &t->Shards[k];
		UINT i = 0;

		AcquireSRWLockExclusive(&s->Lock);
		while (i <= s->Mask) {
			if (s->Slots[i].Tag == 0 || SwitchIpSweeps(&s->Slots[i], w) == false) {
				i++;
				continue;
			}

			// Slot i takes the next entry of the probe, which the loop looks at next
			SwitchIpDelete(t, s, i);
			num++;
		}
		ReleaseSRWLockExclusive(&s->Lock);
	}
	if (num != 0)
		InterlockedExchangeAdd(&t->NumIps, -(LONG)num);

	return num;
}

//
// The table
//

SWITCH_IP_TABLE *SwitchIpNew(UINT max, UINT64 seed) {
	SWITCH_IP_TABLE *t = (SWITCH_IP_TABLE *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(SWITCH_IP_TABLE));

	if (t == NULL)
		return NULL;

	t->Seed = seed;
	t->MaxIps = max;

	// The slots of a shard: twice its share of max, a power of 2, of which it fills three quarters at most
	UINT share = (max + SWITCH_IP_SHARDS - 1) / SWITCH_IP_SHARDS;
	UINT slots = SWITCH_IP_MIN_SLOTS;
	while (slots < share * 2)
		slots *= 2;

	// The shards from VirtualAlloc: zeroed, and each on a cache line of its own
	t->Shards = (SWITCH_IP_SHARD *)VirtualAlloc(NULL, sizeof(SWITCH_IP_SHARD) * SWITCH_IP_SHARDS, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	t->Slots = (SWITCH_IP_SLOT *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(SWITCH_IP_SLOT) * slots * SWITCH_IP_SHARDS);
	if (t->Shards == NULL || t->Slots == NULL) {
		SwitchIpFree(t);
		return NULL;
	}

	for (UINT i = 0; i < SWITCH_IP_SHARDS; i++) {
		SWITCH_IP_SHARD *s = &t->Shards[i];

		InitializeSRWLock(&s->Lock);
		s->Mask = slots - 1;
		s->MaxNum = slots - slots / 4;
		s->Slots = &t->Slots[(SIZE_T)i * slots];
	}

	return t;
}

void SwitchIpFree(SWITCH_IP_TABLE *t) {
	if (t == NULL)
		return;

	if (t->Shards != NULL)
		VirtualFree(t->Shards, 0, MEM_RELEASE);
	if (t->Slots != NULL)
		HeapFree(GetProcessHeap(), 0, t->Slots);

	HeapFree(GetProcessHeap(), 0, t);
}

// Learn the source address of a host that a frame carries: the source of an IPv4 packet, the sender of an ARP packet of IPv4
// over Ethernet, or the source of an IPv6 packet, with the source address of the frame. The frame is size bytes, whose
// EtherType is at inner; the switch took it in the VLAN vlan from port, of the generation gen, at now.
void SwitchIpLearn(SWITCH_IP_TABLE *t, UINT64 now, UINT vlan, const UCHAR *frame, UINT size, UINT inner, UINT port, UINT gen) {
	if (t == NULL || frame == NULL || size < inner + 2)
		return;

	UINT type = ((UINT)frame[inner] << 8) | frame[inner + 1];
	const UCHAR *packet = frame + inner + 2;
	UINT len = size - inner - 2;

	switch (type) {
	case SWITCH_IP_IPV4:
		// The source address of a header that is whole (version 4)
		if (len >= SWITCH_IP_IPV4_HEADER && (packet[0] >> 4) == 4 && SwitchIpHost4(packet + 12))
			SwitchIpTake(t, now, vlan, packet + 12, 4, frame + 6, port, gen);
		break;

	case SWITCH_IP_ARP:
		// The sender address of a request or a reply of IPv4 over Ethernet: hardware type 1, protocol type 0x0800, and
		// addresses of 6 and 4 bytes
		if (len >= SWITCH_IP_ARP_SIZE && packet[0] == 0 && packet[1] == 1 && packet[2] == 0x08 && packet[3] == 0x00 && packet[4] == 6 && packet[5] == 4 &&
		    SwitchIpHost4(packet + 14))
			SwitchIpTake(t, now, vlan, packet + 14, 4, frame + 6, port, gen);
		break;

	case SWITCH_IP_IPV6:
		// The source address of a header that is whole (version 6)
		if (len >= SWITCH_IP_IPV6_HEADER && (packet[0] >> 4) == 6 && SwitchIpHost6(packet + 8))
			SwitchIpTake(t, now, vlan, packet + 8, 16, frame + 6, port, gen);
		break;

	default:
		break;
	}
}

UINT SwitchIpAge(SWITCH_IP_TABLE *t, UINT64 now, UINT aging) {
	SWITCH_IP_SWEEP w;

	ZeroMemory(&w, sizeof(w));
	w.Kind = SWITCH_IP_SWEEP_AGE;
	w.Now = now;
	w.Aging = aging;

	return SwitchIpSweep(t, &w);
}

UINT SwitchIpForget(SWITCH_IP_TABLE *t, UINT port) {
	SWITCH_IP_SWEEP w;

	ZeroMemory(&w, sizeof(w));
	w.Kind = SWITCH_IP_SWEEP_PORT;
	w.Port = port;

	return SwitchIpSweep(t, &w);
}

void SwitchIpStats(SWITCH_IP_TABLE *t, SWITCH_STATS *st) {
	if (t == NULL || st == NULL)
		return;

	st->NumIps = (UINT)ReadNoFence(&t->NumIps);
	st->IpsLearnt = (UINT64)ReadNoFence64(&t->Learnt);
	st->IpsMoved = (UINT64)ReadNoFence64(&t->Moved);
	st->IpsRefused = (UINT64)ReadNoFence64(&t->Refused);
}

//
// The first entries of a table
//

// Swap the entries i and j of size bytes of list
static void SwitchKeepSwap(UCHAR *list, UINT i, UINT j, SIZE_T size) {
	UCHAR *a = list + (SIZE_T)i * size;
	UCHAR *b = list + (SIZE_T)j * size;

	for (SIZE_T k = 0; k < size; k++) {
		UCHAR c = a[k];

		a[k] = b[k];
		b[k] = c;
	}
}

// The heap holds the largest of the entries that it keeps at its root: an entry that comes after it is no one of the first,
// and one that comes before it takes its place once the heap is full
void SwitchKeepFirst(void *list, UINT *num, UINT max, const void *e, SIZE_T size, int (*compare)(const void *, const void *)) {
	UCHAR *heap = (UCHAR *)list;
	UINT i = 0;

	if (*num < max) {
		// The heap grows: the entry goes last and rises above the entries that come before it
		i = *num;
		*num = i + 1;
		CopyMemory(heap + (SIZE_T)i * size, e, size);
		while (i > 0) {
			UINT parent = (i - 1) / 2;

			if (compare(heap + (SIZE_T)parent * size, heap + (SIZE_T)i * size) >= 0)
				break;

			SwitchKeepSwap(heap, i, parent, size);
			i = parent;
		}
		return;
	}

	if (max == 0 || compare(e, heap) >= 0)
		return;

	// The entry takes the place of the largest and sinks below the entries that come after it
	CopyMemory(heap, e, size);
	while (true) {
		UINT largest = i;
		UINT left = 2 * i + 1;
		UINT right = left + 1;

		if (left < max && compare(heap + (SIZE_T)left * size, heap + (SIZE_T)largest * size) > 0)
			largest = left;
		if (right < max && compare(heap + (SIZE_T)right * size, heap + (SIZE_T)largest * size) > 0)
			largest = right;
		if (largest == i)
			break;

		SwitchKeepSwap(heap, i, largest, size);
		i = largest;
	}
}

//
// The operators' calls
//

// The order of two entries: by VLAN, then an IPv4 address before an IPv6 one, then by address
static int SwitchIpCompare(const void *p1, const void *p2) {
	const SWITCH_IP_ENTRY *a = (const SWITCH_IP_ENTRY *)p1;
	const SWITCH_IP_ENTRY *b = (const SWITCH_IP_ENTRY *)p2;

	if (a->Vlan != b->Vlan)
		return (a->Vlan < b->Vlan ? -1 : 1);
	if (a->AddressSize != b->AddressSize)
		return (a->AddressSize < b->AddressSize ? -1 : 1);

	return memcmp(a->Address, b->Address, sizeof(a->Address));
}

// The first max entries of the IP table by VLAN and address; their number
UINT SwitchGetIps(SWITCH *sw, SWITCH_IP_ENTRY *list, UINT max) {
	SWITCH_IP_TABLE *t = SwitchIpTable(sw);
	UINT num = 0;

	if (t == NULL || list == NULL)
		return 0;

	for (UINT k = 0; k < SWITCH_IP_SHARDS; k++) {
		SWITCH_IP_SHARD *s = &t->Shards[k];

		// The lock keeps the writers of the shard out while its entries are copied
		AcquireSRWLockShared(&s->Lock);
		for (UINT i = 0; i <= s->Mask; i++) {
			const SWITCH_IP_SLOT *e = &s->Slots[i];
			SWITCH_IP_ENTRY m;

			if (e->Tag == 0)
				continue;

			ZeroMemory(&m, sizeof(m));
			m.Vlan = e->Tag >> 8;
			m.AddressSize = e->Tag & 0xFF;
			CopyMemory(m.Address, e->Address, sizeof(m.Address));
			CopyMemory(m.Mac, e->Mac, sizeof(m.Mac));
			m.Port = e->Port;
			m.LastSeen = e->LastSeen;
			SwitchKeepFirst(list, &num, max, &m, sizeof(m), SwitchIpCompare);
		}
		ReleaseSRWLockShared(&s->Lock);
	}

	if (num > 1)
		qsort(list, num, sizeof(SWITCH_IP_ENTRY), SwitchIpCompare);

	return num;
}

// Take out the entries of the address of size bytes at address, 4 for IPv4 or 16 for IPv6, in every VLAN, or every entry of
// the IP table for NULL; their number
UINT SwitchClearIps(SWITCH *sw, const UCHAR *address, UINT size) {
	SWITCH_IP_SWEEP w;

	ZeroMemory(&w, sizeof(w));
	w.Kind = SWITCH_IP_SWEEP_ALL;
	if (address != NULL) {
		if (size != 4 && size != 16)
			return 0;

		w.Kind = SWITCH_IP_SWEEP_ADDRESS;
		CopyMemory(w.Address, address, size);
		w.Size = size;
	}

	return SwitchIpSweep(SwitchIpTable(sw), &w);
}
