// Switch.c
// The L2 switch of the new core (Switch.h): the ports, the VLAN of a frame, the MAC table, the groups of each VLAN with
// their subscribers, the limits and counters of each VLAN, and SwitchInput, the one ingress of every frame. The IP table is
// SwitchIp.c's.
//
// No lock serialises the switch on the data path (spec #31 D2; ADR-0022, Threading):
// - The MAC table is split into SWITCH_SHARDS shards by a keyed hash of the VLAN and the address, each a table with
//   open addressing and linear probing. A reader takes no lock: it reads the sequence number of the shard before and
//   after it looks, and looks again when a writer changed the shard in between. A writer (it learns, moves, refreshes or
//   takes out entries) holds the lock of its shard and keeps the sequence number odd while it writes. A frame from an
//   address that its port has, refreshed within SWITCH_REFRESH, writes nothing, so the frames of a known flow only read
//   the table.
// - Each port has a lock. The data path holds it shared while it reads the port, and while it hands a frame to the
//   port's member; a change of the port holds it exclusive, so the member of a port gets no frame once the change that
//   took the port out returned.
// - Each VLAN has a lock for its groups, which the data path holds shared for a frame to a group, and one for its
//   limits. Its counters are kept per slot of processors, each slot on cache lines of its own, so that the cores that
//   forward in one VLAN share no line.
// - The changes (ports, subscriptions) hold ConfigLock, which the data path never takes. A change takes the lock of a
//   group, then of a port, then of a shard, and holds the lock of a group or a port only while it waits for none. The
//   data path holds the shared lock of its port while it takes the shared lock of a group and of other ports, and takes
//   the lock of a shard or of a limit alone.

#include "Core/Switch.h"

#include "Core/SwitchInternal.h"

#include <bcrypt.h>

#include <stdlib.h>
#include <string.h>

#define SWITCH_CACHE_LINE    64                       // The cache line that a port, a shard and a slot of counters keep to themselves
#define SWITCH_SHARD_BITS    8                        // The MAC table in 2^8 shards, chosen by the top bits of the hash
#define SWITCH_SHARDS        (1 << SWITCH_SHARD_BITS) // ... their number
#define SWITCH_MIN_SLOTS     8                        // Slots of a shard at least
#define SWITCH_SLOTS         16                       // The slots of processors of the counters of a VLAN, a power of 2
#define SWITCH_REFRESH       1000                     // ms between two refreshes of an entry by the frames from its address
#define SWITCH_SPIN          256                      // Looks of a reader at a shard that a writer holds before it gives up its processor
#define SWITCH_VID_MASK      0x0FFF                   // The VLAN id in the tag control information
#define SWITCH_PRIORITY_MASK 0xF000                   // ... its priority and DEI
#define SWITCH_VID_RESERVED  0x0FFF                   // VLAN id 4095
#define SWITCH_VLAN_MAP      (SWITCH_NUM_VLANS / 8)   // Bytes of the bitmap of the VLANs of a trunk port
#define SWITCH_FIRST_PORTS   4                        // Room for subscribers that a group gets first
#define SWITCH_FIRST_GROUPS  4                        // Room for groups that a VLAN gets first

// The counters of a VLAN (SWITCH_VLAN_STATS), per slot of processors
#define SWITCH_IN_FRAMES    0
#define SWITCH_IN_BYTES     1
#define SWITCH_UNICAST      2
#define SWITCH_FLOODED      3
#define SWITCH_BROADCAST    4
#define SWITCH_MULTICAST    5
#define SWITCH_LIMIT_DROPS  6
#define SWITCH_FILTERED     7
#define SWITCH_OUT_FRAMES   8
#define SWITCH_OUT_BYTES    9
#define SWITCH_NUM_COUNTERS 10

// What a sweep of the MAC table takes out (SwitchSweep)
#define SWITCH_SWEEP_AGE  0 // The entries that no frame refreshed for the aging time
#define SWITCH_SWEEP_PORT 1 // The entries of one port
#define SWITCH_SWEEP_ALL  2 // Every entry
#define SWITCH_SWEEP_MAC  3 // The entries of one MAC address, in every VLAN (SDN-50-N, #492)

// One entry of the MAC table. A free slot has the key 0, which no entry has, as a VLAN id of a frame is never 0.
typedef struct SWITCH_MAC {
	volatile LONG64 Key;      // The VLAN id (bits 48 to 59) and the MAC address (bits 0 to 47)
	volatile LONG64 LastSeen; // The time of the last frame from the address (ms)
	volatile LONG Port;       // The port it was learnt on
	volatile LONG Gen;        // ... and the generation of the port then
} SWITCH_MAC;

// A shard of the MAC table, on a cache line of its own
typedef union SWITCH_SHARD {
	struct {
		SRWLOCK Lock;      // The writers of the shard
		volatile LONG Seq; // Odd while a writer changes the slots, so that a reader looks again
		UINT Num;          // The entries
		UINT MaxNum;       // ... at most: three quarters of the slots, so that every probe ends at a free slot
		UINT Mask;         // The number of slots, a power of 2, less 1
		SWITCH_MAC *Slots; // The slots
	};
	UCHAR Line[SWITCH_CACHE_LINE];
} SWITCH_SHARD;

// A port, on a cache line of its own
typedef union SWITCH_PORT {
	struct {
		SRWLOCK Lock;           // Shared on the data path, exclusive for a change
		bool InUse;             // A member holds the port
		UINT Mode;              // SWITCH_ACCESS or SWITCH_TRUNK
		UINT Vlan;              // The access VLAN, or the native VLAN of a trunk port (0 for none)
		UINT Gen;               // The generation: one more each time a member leaves the port, so that a frame that found the port of an address before gets to no later member
		UINT Member;            // Its member for the filter of the switch (SWITCH_PORT_CONFIG.Member)
		UCHAR *Allowed;         // A trunk port: the bitmap of the VLANs that it carries, its native VLAN included
		SWITCH_SEND_PROC *Send; // Takes the frames of the port
		void *Param;            // ... its first parameter
	};
	UCHAR Line[SWITCH_CACHE_LINE];
} SWITCH_PORT;

// The counters of a VLAN on one slot of processors, on cache lines of their own
typedef union SWITCH_COUNTERS {
	volatile LONG64 Count[SWITCH_NUM_COUNTERS];
	UCHAR Lines[2 * SWITCH_CACHE_LINE];
} SWITCH_COUNTERS;

// A limit of one kind of frame of a VLAN: a bucket that holds one second of frames at the rate of the limit
typedef struct SWITCH_LIMIT {
	UINT Rate;     // Frames per second, 0 for no limit
	UINT64 Credit; // What the bucket holds, in thousandths of a frame
	UINT64 Last;   // The time of its last refill (ms)
} SWITCH_LIMIT;

// A group of a VLAN and its subscribers
typedef struct SWITCH_GROUP {
	UCHAR Mac[6];  // The group address
	UINT NumPorts; // The subscribers
	UINT MaxPorts; // ... room for them
	UINT *Ports;   // ... in ascending order
} SWITCH_GROUP;

// The state of a VLAN: made by its first frame, subscription or limit, and kept until the switch is freed
typedef struct SWITCH_VLAN {
	SWITCH_COUNTERS Counters[SWITCH_SLOTS]; // The counters, per slot of processors: first, at the start of a cache line
	void *Block;                            // The memory block that holds the state
	SRWLOCK LimitLock;                      // The limits
	SWITCH_LIMIT Broadcast;                 // The limit of broadcast frames and of frames to an address that the VLAN has not learnt
	SWITCH_LIMIT Multicast;                 // The limit of multicast frames
	SRWLOCK GroupLock;                      // The groups: shared on the data path, exclusive for a change
	SWITCH_GROUP All;                       // The subscribers of every group
	UINT NumGroups;                         // The groups with subscribers
	UINT MaxGroups;                         // ... room for them
	SWITCH_GROUP *Groups;                   // ... in ascending order of their addresses
} SWITCH_VLAN;

// The L2 switch of a Network
struct SWITCH {
	USHORT Tpid;                                   // The TPID of its tags
	UINT MaxPorts;                                 // Its ports
	UINT MaxMacs;                                  // Entries of its MAC table at most
	UINT AgingTime;                                // ms after which SwitchAge takes out an entry
	UINT BroadcastLimit;                           // The limits of a new VLAN
	UINT MulticastLimit;                           // ...
	SWITCH_ADMIT_PROC *Admit;                      // The filter of the switch, NULL for none (SWITCH_CONFIG)
	SWITCH_DELIVER_PROC *Deliver;                  // ...
	void *FilterParam;                             // ... their first parameter
	UINT64 Seed;                                   // The random key of the hash of the MAC table
	SWITCH_PORT *Ports;                            // The ports, each on a cache line of its own
	SWITCH_SHARD *Shards;                          // The shards of the MAC table, ditto
	SWITCH_MAC *Slots;                             // The slots of every shard
	SRWLOCK ConfigLock;                            // The changes: ports and subscriptions; never taken on the data path
	UINT NumPorts;                                 // The ports that members hold, under ConfigLock
	SWITCH_VLAN *volatile Vlans[SWITCH_NUM_VLANS]; // The VLANs with a state, by VLAN id
	volatile LONG NumVlans;                        // ... their number
	volatile LONG NumMacs;                         // The entries of the MAC table
	volatile LONG64 Learnt;                        // Entries learnt
	volatile LONG64 Moved;                         // ... moved
	volatile LONG64 Refused;                       // Sources not learnt, as the table was full
	volatile LONG64 Drops[SWITCH_NUM_REASONS];     // Frames dropped before their VLAN took them
	SWITCH_IP_TABLE *Ips;                          // The IP table (SwitchIp.c; SDN-50-N, #492)
};

// A frame on its way out: the frame as it came, and its other form, built once for the first port that takes it
typedef struct SWITCH_EGRESS {
	const UCHAR *Data;  // The frame as it came
	UINT Size;          // ... its size
	UINT Inner;         // The offset of its EtherType or length: after the addresses and its tag
	USHORT Tpid;        // The TPID of the switch
	USHORT Tci;         // The tag control information of its tag, 0 without a tag
	bool VlanTag;       // It came with a VLAN tag: then the frame as it came is its tagged form, else its untagged form
	UINT Vlan;          // Its VLAN
	SWITCH_VLAN *State; // ... and the state of the VLAN
	UINT Member;        // The member of the port it came from, for the filter of the switch
	UINT Slot;          // The slot of processors of the counters
	UCHAR *Buf;         // The other form, room for SWITCH_MAX_FRAME + SWITCH_TAG_SIZE bytes
	UINT BufSize;       // ... its size, 0 before it is built
} SWITCH_EGRESS;

static const UCHAR switch_broadcast[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

// A 16-bit value at p, big-endian
static USHORT SwitchGet16(const UCHAR *p) {
	return (USHORT)(((UINT)p[0] << 8) | p[1]);
}

// Put a 16-bit value at p, big-endian
static void SwitchPut16(UCHAR *p, UINT v) {
	p[0] = (UCHAR)(v >> 8);
	p[1] = (UCHAR)v;
}

// Count n on a counter of a VLAN, in a slot of processors
static void SwitchCount(SWITCH_VLAN *v, UINT slot, UINT counter, UINT64 n) {
	if (slot < SWITCH_SLOTS && counter < SWITCH_NUM_COUNTERS)
		InterlockedExchangeAdd64(&v->Counters[slot].Count[counter], (LONG64)n);
}

// Count a frame that the switch dropped before its VLAN took it; 0, the number of ports it went to
static UINT SwitchDrop(SWITCH *sw, UINT reason) {
	if (reason < SWITCH_NUM_REASONS)
		InterlockedIncrement64(&sw->Drops[reason]);

	return 0;
}

//
// The MAC table
//

// The key of a VLAN and a MAC address
static UINT64 SwitchMacKey(UINT vlan, const UCHAR *mac) {
	return ((UINT64)vlan << 48) | ((UINT64)mac[0] << 40) | ((UINT64)mac[1] << 32) | ((UINT64)mac[2] << 24) | ((UINT64)mac[3] << 16) | ((UINT64)mac[4] << 8) | mac[5];
}

// The hash of a key under the random seed of the switch (the finaliser of SplitMix64), so that the members of a
// Network cannot choose the shards and slots that their addresses take
static UINT64 SwitchHash(const SWITCH *sw, UINT64 key) {
	UINT64 h = key ^ sw->Seed;

	h = (h ^ (h >> 30)) * 0xBF58476D1CE4E5B9ULL;
	h = (h ^ (h >> 27)) * 0x94D049BB133111EBULL;
	return h ^ (h >> 31);
}

// The shard of a hash: its top bits; the slot where its probe starts is its low bits
static SWITCH_SHARD *SwitchShardOf(SWITCH *sw, UINT64 h) {
	return &sw->Shards[h >> (64 - SWITCH_SHARD_BITS)];
}

// The port of the entry of key in a shard, SWITCH_PORT_NONE when the shard has none; *gen is the generation of the port
// and *seen the time of the last refresh of the entry. The reader takes no lock: when a writer changed the shard while
// it looked, the sequence number is odd or has moved on, and the reader looks again.
static UINT SwitchShardLookup(SWITCH_SHARD *s, UINT64 key, UINT64 h, UINT *gen, UINT64 *seen) {
	for (UINT spin = 1;; spin++) {
		LONG seq = ReadAcquire(&s->Seq);

		if ((seq & 1) == 0) {
			UINT port = SWITCH_PORT_NONE;
			UINT g = 0;
			UINT64 last = 0;
			UINT i = (UINT)h & s->Mask;

			for (UINT n = 0; n <= s->Mask; n++) {
				LONG64 k = ReadNoFence64(&s->Slots[i].Key);

				if (k == 0)
					break;
				if ((UINT64)k == key) {
					port = (UINT)ReadNoFence(&s->Slots[i].Port);
					g = (UINT)ReadNoFence(&s->Slots[i].Gen);
					last = (UINT64)ReadNoFence64(&s->Slots[i].LastSeen);
					break;
				}
				i = (i + 1) & s->Mask;
			}

			// The slots are read before the sequence number is read again
			MemoryBarrier();
			if (ReadNoFence(&s->Seq) == seq) {
				*gen = g;
				*seen = last;
				return port;
			}
		}

		if ((spin % SWITCH_SPIN) == 0)
			Sleep(0);
		else
			YieldProcessor();
	}
}

// The slot of key in a shard, or the free slot that ends its probe; NULL when no slot is free. The caller holds the
// lock of the shard.
static SWITCH_MAC *SwitchShardFind(SWITCH_SHARD *s, UINT64 key, UINT64 h) {
	UINT i = (UINT)h & s->Mask;

	for (UINT n = 0; n <= s->Mask; n++) {
		SWITCH_MAC *e = &s->Slots[i];

		if (e->Key == 0 || (UINT64)e->Key == key)
			return e;
		i = (i + 1) & s->Mask;
	}

	return NULL;
}

// Take out the entry in slot i of a shard. The entries after it in its probe move back, so that no probe meets a free
// slot before its key: deletion in linear probing without tombstones. The caller holds the lock of the shard and made
// its sequence number odd.
static void SwitchShardDelete(const SWITCH *sw, SWITCH_SHARD *s, UINT i) {
	UINT j = i;

	while (true) {
		j = (j + 1) & s->Mask;

		SWITCH_MAC *e = &s->Slots[j];
		if (e->Key == 0)
			break;

		// The entry in j stays when the slot where its probe starts lies cyclically in (i, j]
		UINT home = (UINT)SwitchHash(sw, (UINT64)e->Key) & s->Mask;
		if (i <= j ? (i < home && home <= j) : (i < home || home <= j))
			continue;

		s->Slots[i].Key = e->Key;
		s->Slots[i].LastSeen = e->LastSeen;
		s->Slots[i].Port = e->Port;
		s->Slots[i].Gen = e->Gen;
		i = j;
	}

	s->Slots[i].Key = 0;
	s->Slots[i].LastSeen = 0;
	s->Slots[i].Port = 0;
	s->Slots[i].Gen = 0;
	s->Num--;
}

// Whether a sweep takes out the entry e. mac is the address of SWITCH_SWEEP_MAC, in the bits 0 to 47 of a key.
static bool SwitchSweeps(const SWITCH *sw, const SWITCH_MAC *e, UINT kind, UINT64 now, UINT port, UINT64 mac) {
	switch (kind) {
	case SWITCH_SWEEP_AGE:
		return now >= (UINT64)e->LastSeen + sw->AgingTime;
	case SWITCH_SWEEP_PORT:
		return (UINT)e->Port == port;
	case SWITCH_SWEEP_MAC:
		return ((UINT64)e->Key & 0xFFFFFFFFFFFFULL) == mac;
	default:
		return true;
	}
}

// Take out the entries of a shard that a sweep takes; their number. The sequence number turns odd before the first one
// goes, so the readers look again only when the shard changes.
static UINT SwitchShardSweep(const SWITCH *sw, SWITCH_SHARD *s, UINT kind, UINT64 now, UINT port, UINT64 mac) {
	UINT num = 0;
	UINT i = 0;

	AcquireSRWLockExclusive(&s->Lock);
	while (i <= s->Mask) {
		if (s->Slots[i].Key == 0 || SwitchSweeps(sw, &s->Slots[i], kind, now, port, mac) == false) {
			i++;
			continue;
		}

		// Slot i takes the next entry of the probe, which the loop looks at next
		if (num == 0)
			InterlockedIncrement(&s->Seq);
		SwitchShardDelete(sw, s, i);
		num++;
	}
	if (num != 0)
		InterlockedIncrement(&s->Seq);
	ReleaseSRWLockExclusive(&s->Lock);

	return num;
}

// Sweep the whole MAC table; the number of entries taken out
static UINT SwitchSweep(SWITCH *sw, UINT kind, UINT64 now, UINT port, UINT64 mac) {
	UINT num = 0;

	for (UINT i = 0; i < SWITCH_SHARDS; i++)
		num += SwitchShardSweep(sw, &sw->Shards[i], kind, now, port, mac);
	if (num != 0)
		InterlockedExchangeAdd(&sw->NumMacs, -(LONG)num);

	return num;
}

// Take one more entry of the MAC table; false when it holds MaxMacs
static bool SwitchTakeMac(SWITCH *sw) {
	if (InterlockedIncrement(&sw->NumMacs) <= (LONG)sw->MaxMacs)
		return true;

	InterlockedDecrement(&sw->NumMacs);
	return false;
}

// Learn that the address mac of the VLAN vlan is on port, of the generation gen: a new entry, or an entry that moves to
// the port. An entry of the port that a frame refreshed within SWITCH_REFRESH is only read.
static void SwitchLearn(SWITCH *sw, UINT64 now, UINT vlan, const UCHAR *mac, UINT port, UINT gen) {
	UINT64 key = SwitchMacKey(vlan, mac);
	UINT64 h = SwitchHash(sw, key);
	SWITCH_SHARD *s = SwitchShardOf(sw, h);
	UINT64 seen = 0;
	UINT g = 0;

	if (SwitchShardLookup(s, key, h, &g, &seen) == port && g == gen && now < seen + SWITCH_REFRESH)
		return;

	AcquireSRWLockExclusive(&s->Lock);
	InterlockedIncrement(&s->Seq);
	{
		SWITCH_MAC *e = SwitchShardFind(s, key, h);

		if (e != NULL && (UINT64)e->Key == key) {
			if ((UINT)e->Port != port || (UINT)e->Gen != gen) {
				e->Port = (LONG)port;
				e->Gen = (LONG)gen;
				InterlockedIncrement64(&sw->Moved);
			}
			if (now > (UINT64)e->LastSeen)
				e->LastSeen = (LONG64)now;
		} else if (e != NULL && s->Num < s->MaxNum && SwitchTakeMac(sw)) {
			e->Port = (LONG)port;
			e->Gen = (LONG)gen;
			e->LastSeen = (LONG64)now;
			e->Key = (LONG64)key;
			s->Num++;
			InterlockedIncrement64(&sw->Learnt);
		} else {
			InterlockedIncrement64(&sw->Refused);
		}
	}
	InterlockedIncrement(&s->Seq);
	ReleaseSRWLockExclusive(&s->Lock);
}

// The port that the MAC table has for an address of a VLAN, SWITCH_PORT_NONE for none; *gen is the generation of the
// port when the entry was learnt
static UINT SwitchLookup(SWITCH *sw, UINT vlan, const UCHAR *mac, UINT *gen) {
	UINT64 key = SwitchMacKey(vlan, mac);
	UINT64 h = SwitchHash(sw, key);
	UINT64 seen = 0;

	return SwitchShardLookup(SwitchShardOf(sw, h), key, h, gen, &seen);
}

//
// The ports and the VLANs
//

// Whether a port carries a VLAN
static bool SwitchCarries(const SWITCH_PORT *p, UINT vlan) {
	if (p->Mode == SWITCH_ACCESS)
		return vlan == p->Vlan;

	return vlan < SWITCH_NUM_VLANS && p->Allowed != NULL && (p->Allowed[vlan >> 3] & (1u << (vlan & 7))) != 0;
}

// A limit of rate frames per second, its bucket full
static void SwitchSetLimit(SWITCH_LIMIT *l, UINT rate) {
	l->Rate = rate;
	l->Credit = (UINT64)rate * 1000;
	l->Last = 0;
}

// The state of a VLAN, NULL while it has none
static SWITCH_VLAN *SwitchVlanState(SWITCH *sw, UINT vlan) {
	if (vlan >= SWITCH_NUM_VLANS)
		return NULL;

	return (SWITCH_VLAN *)ReadPointerAcquire((PVOID const volatile *)&sw->Vlans[vlan]);
}

// The state of a VLAN, made on first use with the limits of the switch; NULL for a VLAN id that is none, or when there
// is no memory. The state stays until the switch is freed, so that a pointer to it never dangles.
static SWITCH_VLAN *SwitchVlan(SWITCH *sw, UINT vlan) {
	if (vlan < SWITCH_MIN_VLAN || vlan > SWITCH_MAX_VLAN)
		return NULL;

	SWITCH_VLAN *v = SwitchVlanState(sw, vlan);
	if (v != NULL)
		return v;

	// The state at the start of a cache line in its block
	UCHAR *block = (UCHAR *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(SWITCH_VLAN) + SWITCH_CACHE_LINE);
	if (block == NULL)
		return NULL;

	v = (SWITCH_VLAN *)(block + SWITCH_CACHE_LINE - ((UINT_PTR)block & (SWITCH_CACHE_LINE - 1)));
	v->Block = block;
	InitializeSRWLock(&v->LimitLock);
	InitializeSRWLock(&v->GroupLock);
	SwitchSetLimit(&v->Broadcast, sw->BroadcastLimit);
	SwitchSetLimit(&v->Multicast, sw->MulticastLimit);

	// Another thread may make the state at the same time: the first one stays
	SWITCH_VLAN *old = (SWITCH_VLAN *)InterlockedCompareExchangePointer((PVOID volatile *)&sw->Vlans[vlan], v, NULL);
	if (old != NULL) {
		HeapFree(GetProcessHeap(), 0, block);
		return old;
	}

	InterlockedIncrement(&sw->NumVlans);
	return v;
}

// Free the state of a VLAN
static void SwitchFreeVlan(SWITCH_VLAN *v) {
	// Each list through a local: HeapFree invalidates the pointer that it is given, which /analyze would then see in
	// every element of the array
	for (UINT i = 0; i < v->NumGroups; i++) {
		UINT *ports = v->Groups[i].Ports;

		if (ports != NULL)
			HeapFree(GetProcessHeap(), 0, ports);
	}
	if (v->Groups != NULL)
		HeapFree(GetProcessHeap(), 0, v->Groups);
	if (v->All.Ports != NULL)
		HeapFree(GetProcessHeap(), 0, v->All.Ports);

	HeapFree(GetProcessHeap(), 0, v->Block);
}

//
// The groups of a VLAN and their subscribers
//

// Where a port is among the subscribers of a group, or would be; *found tells which
static UINT SwitchPortIndex(const SWITCH_GROUP *g, UINT port, bool *found) {
	UINT lo = 0;
	UINT hi = g->NumPorts;

	*found = false;
	while (lo < hi) {
		UINT mid = lo + (hi - lo) / 2;

		if (g->Ports[mid] == port) {
			*found = true;
			return mid;
		}
		if (g->Ports[mid] > port)
			hi = mid;
		else
			lo = mid + 1;
	}

	return lo;
}

// Where a group address is among the groups of a VLAN, or would be; *found tells which
static UINT SwitchGroupIndex(const SWITCH_VLAN *v, const UCHAR *mac, bool *found) {
	UINT lo = 0;
	UINT hi = v->NumGroups;

	*found = false;
	while (lo < hi) {
		UINT mid = lo + (hi - lo) / 2;
		int c = memcmp(v->Groups[mid].Mac, mac, sizeof(v->Groups[mid].Mac));

		if (c == 0) {
			*found = true;
			return mid;
		}
		if (c > 0)
			hi = mid;
		else
			lo = mid + 1;
	}

	return lo;
}

// Add a port to the subscribers of a group; false when there is no memory
static bool SwitchGroupAddPort(SWITCH_GROUP *g, UINT port) {
	bool found = false;
	UINT i = SwitchPortIndex(g, port, &found);

	if (found)
		return true;

	if (g->NumPorts == g->MaxPorts) {
		UINT max = (g->MaxPorts == 0 ? SWITCH_FIRST_PORTS : g->MaxPorts * 2);
		UINT *ports = (UINT *)HeapAlloc(GetProcessHeap(), 0, sizeof(UINT) * max);

		if (ports == NULL)
			return false;

		if (g->Ports != NULL) {
			CopyMemory(ports, g->Ports, sizeof(UINT) * g->NumPorts);
			HeapFree(GetProcessHeap(), 0, g->Ports);
		}
		g->Ports = ports;
		g->MaxPorts = max;
	}

	MoveMemory(&g->Ports[i + 1], &g->Ports[i], sizeof(UINT) * (g->NumPorts - i));
	g->Ports[i] = port;
	g->NumPorts++;

	return true;
}

// Take a port out of the subscribers of a group; false when it was none of them
static bool SwitchGroupDelPort(SWITCH_GROUP *g, UINT port) {
	bool found = false;
	UINT i = SwitchPortIndex(g, port, &found);

	if (found == false)
		return false;

	MoveMemory(&g->Ports[i], &g->Ports[i + 1], sizeof(UINT) * (g->NumPorts - i - 1));
	g->NumPorts--;

	return true;
}

// Take out the group i of a VLAN, which has no subscriber left
static void SwitchVlanDelGroup(SWITCH_VLAN *v, UINT i) {
	UINT *ports = v->Groups[i].Ports;

	if (ports != NULL)
		HeapFree(GetProcessHeap(), 0, ports);

	MoveMemory(&v->Groups[i], &v->Groups[i + 1], sizeof(SWITCH_GROUP) * (v->NumGroups - i - 1));
	v->NumGroups--;
}

// Subscribe a port to a group of a VLAN, or to every group for NULL; false when the VLAN has SWITCH_MAX_GROUPS groups
// or there is no memory. The caller holds the group lock of the VLAN.
static bool SwitchVlanSubscribe(SWITCH_VLAN *v, const UCHAR *mac, UINT port) {
	bool found = false;

	if (mac == NULL)
		return SwitchGroupAddPort(&v->All, port);

	UINT i = SwitchGroupIndex(v, mac, &found);
	if (found)
		return SwitchGroupAddPort(&v->Groups[i], port);
	if (v->NumGroups >= SWITCH_MAX_GROUPS)
		return false;

	if (v->NumGroups == v->MaxGroups) {
		UINT max = (v->MaxGroups == 0 ? SWITCH_FIRST_GROUPS : v->MaxGroups * 2);
		SWITCH_GROUP *groups = (SWITCH_GROUP *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(SWITCH_GROUP) * max);

		if (groups == NULL)
			return false;

		if (v->Groups != NULL) {
			CopyMemory(groups, v->Groups, sizeof(SWITCH_GROUP) * v->NumGroups);
			HeapFree(GetProcessHeap(), 0, v->Groups);
		}
		v->Groups = groups;
		v->MaxGroups = max;
	}

	// A new group with the port as its one subscriber
	SWITCH_GROUP g;
	ZeroMemory(&g, sizeof(g));
	CopyMemory(g.Mac, mac, sizeof(g.Mac));
	if (SwitchGroupAddPort(&g, port) == false)
		return false;

	MoveMemory(&v->Groups[i + 1], &v->Groups[i], sizeof(SWITCH_GROUP) * (v->NumGroups - i));
	v->Groups[i] = g;
	v->NumGroups++;

	return true;
}

// Take a port out of a group of a VLAN, or out of every group for NULL; false when it did not subscribe. A group goes
// with its last subscriber. The caller holds the group lock of the VLAN.
static bool SwitchVlanUnsubscribe(SWITCH_VLAN *v, const UCHAR *mac, UINT port) {
	bool found = false;

	if (mac == NULL)
		return SwitchGroupDelPort(&v->All, port);

	UINT i = SwitchGroupIndex(v, mac, &found);
	if (found == false || SwitchGroupDelPort(&v->Groups[i], port) == false)
		return false;

	if (v->Groups[i].NumPorts == 0)
		SwitchVlanDelGroup(v, i);

	return true;
}

// Take a port out of every group of a VLAN and out of its subscribers of every group. The caller holds the group lock
// of the VLAN.
static void SwitchVlanDropPort(SWITCH_VLAN *v, UINT port) {
	UINT i = 0;

	SwitchGroupDelPort(&v->All, port);
	while (i < v->NumGroups) {
		if (SwitchGroupDelPort(&v->Groups[i], port) && v->Groups[i].NumPorts == 0) {
			// The next group moved to i
			SwitchVlanDelGroup(v, i);
			continue;
		}
		i++;
	}
}

// Whether one more frame passes a limit of its VLAN at now. The bucket is full at first and refills at the rate of the
// limit; a frame takes a thousand thousandths of a frame from it.
static bool SwitchLimitPass(SWITCH_VLAN *v, SWITCH_LIMIT *l, UINT64 now) {
	bool pass = true;

	AcquireSRWLockExclusive(&v->LimitLock);
	if (l->Rate != 0) {
		UINT64 full = (UINT64)l->Rate * 1000;

		if (now > l->Last) {
			UINT64 elapsed = now - l->Last;

			if (elapsed >= 1000 || l->Credit + (UINT64)l->Rate * elapsed >= full)
				l->Credit = full;
			else
				l->Credit += (UINT64)l->Rate * elapsed;
			l->Last = now;
		}

		pass = (l->Credit >= 1000);
		if (pass)
			l->Credit -= 1000;
	}
	ReleaseSRWLockExclusive(&v->LimitLock);

	return pass;
}

//
// The data path
//

// The frame as a port takes it: with the tag of its VLAN (tagged), or without (a priority tag stays). One of the two
// forms is the frame as it came; the other is built once, for the first port that takes it.
static const UCHAR *SwitchEgressFrame(SWITCH_EGRESS *e, bool tagged, UINT *size) {
	if (tagged == e->VlanTag) {
		*size = e->Size;
		return e->Data;
	}

	if (e->BufSize == 0) {
		UINT pos = SWITCH_ADDR_SIZE;

		CopyMemory(e->Buf, e->Data, SWITCH_ADDR_SIZE);
		if (tagged) {
			// The tag of the VLAN, with the priority and DEI of a priority tag
			SwitchPut16(e->Buf + pos, e->Tpid);
			SwitchPut16(e->Buf + pos + 2, (e->Tci & SWITCH_PRIORITY_MASK) | e->Vlan);
			pos += SWITCH_TAG_SIZE;
		}
		CopyMemory(e->Buf + pos, e->Data + e->Inner, e->Size - e->Inner);
		e->BufSize = pos + e->Size - e->Inner;
	}

	*size = e->BufSize;
	return e->Buf;
}

// Deliver a frame to a port of its VLAN, under the shared lock of the port, so that the member of a port that a change
// took out gets nothing after the change. A frame to the port of a learnt address (check) goes only to a port of the
// generation gen, the one of the entry; any other frame only where the filter of the switch lets it (Deliver). False when
// no member holds the port, it does not carry the VLAN, another member holds it, or the filter refuses it.
static bool SwitchSendTo(SWITCH *sw, SWITCH_EGRESS *e, UINT port, bool check, UINT gen) {
	SWITCH_PORT *p = &sw->Ports[port];
	bool sent = false;

	AcquireSRWLockShared(&p->Lock);
	if (p->InUse && SwitchCarries(p, e->Vlan) && (check == false || p->Gen == gen) &&
	    (check || sw->Deliver == NULL || sw->Deliver(sw->FilterParam, e->Member, p->Member, e->Data, e->Size))) {
		UINT size = 0;
		const UCHAR *frame = SwitchEgressFrame(e, p->Mode == SWITCH_TRUNK && p->Vlan != e->Vlan, &size);

		p->Send(p->Param, port, frame, size);
		SwitchCount(e->State, e->Slot, SWITCH_OUT_FRAMES, 1);
		SwitchCount(e->State, e->Slot, SWITCH_OUT_BYTES, size);
		sent = true;
	}
	ReleaseSRWLockShared(&p->Lock);

	return sent;
}

// Deliver a frame to the subscribers of the group mac of its VLAN and to the subscribers of every group, each port once
// and never back to the port it came from; the number of ports it went to
static UINT SwitchSendGroup(SWITCH *sw, SWITCH_EGRESS *e, const UCHAR *mac, UINT from) {
	SWITCH_VLAN *v = e->State;
	UINT num = 0;

	AcquireSRWLockShared(&v->GroupLock);
	{
		bool found = false;
		UINT i = SwitchGroupIndex(v, mac, &found);
		const SWITCH_GROUP *g = (found ? &v->Groups[i] : NULL);

		for (UINT k = 0; k < v->All.NumPorts; k++) {
			UINT q = v->All.Ports[k];

			if (q != from && SwitchSendTo(sw, e, q, false, 0))
				num++;
		}
		for (UINT k = 0; g != NULL && k < g->NumPorts; k++) {
			UINT q = g->Ports[k];
			bool all = false;

			// A subscriber of every group has the frame already
			SwitchPortIndex(&v->All, q, &all);
			if (q != from && all == false && SwitchSendTo(sw, e, q, false, 0))
				num++;
		}
	}
	ReleaseSRWLockShared(&v->GroupLock);

	return num;
}

// Whether the filter of the switch lets a frame of the VLAN vlan from port through (p, whose shared lock the caller
// holds): to the member of the port of its destination when the VLAN learnt that address, else to a group. The port of
// the destination is read under its shared lock, as SwitchSendTo reads it.
static bool SwitchAdmit(SWITCH *sw, UINT64 now, UINT port, const SWITCH_PORT *p, UINT vlan, const UCHAR *frame, UINT size) {
	UINT to = SWITCH_NO_MEMBER;

	if ((frame[0] & 1) == 0) {
		UINT gen = 0;
		UINT q = SwitchLookup(sw, vlan, frame, &gen);

		if (q == port) {
			to = p->Member;
		} else if (q < sw->MaxPorts) {
			SWITCH_PORT *d = &sw->Ports[q];

			AcquireSRWLockShared(&d->Lock);
			if (d->InUse && d->Gen == gen && SwitchCarries(d, vlan))
				to = d->Member;
			ReleaseSRWLockShared(&d->Lock);
		}
	}

	return sw->Admit(sw->FilterParam, now, p->Member, to, vlan, frame, size);
}

// A frame from a port, under the shared lock of the port: its VLAN, the learning of its source and its delivery; the
// number of ports it went to
static UINT SwitchForward(SWITCH *sw, UINT64 now, UINT port, const SWITCH_PORT *p, const UCHAR *frame, UINT size) {
	UCHAR buf[SWITCH_MAX_FRAME + SWITCH_TAG_SIZE];
	SWITCH_EGRESS e;
	UINT vid = 0;
	UINT vlan = 0;

	ZeroMemory(&e, sizeof(e));
	e.Data = frame;
	e.Size = size;
	e.Inner = SWITCH_ADDR_SIZE;
	e.Tpid = sw->Tpid;
	e.Slot = GetCurrentProcessorNumber() & (SWITCH_SLOTS - 1);
	e.Buf = buf;

	if (SwitchGet16(frame + SWITCH_ADDR_SIZE) == sw->Tpid) {
		if (size < SWITCH_MIN_FRAME + SWITCH_TAG_SIZE)
			return SwitchDrop(sw, SWITCH_DROP_MALFORMED);

		e.Tci = SwitchGet16(frame + SWITCH_ADDR_SIZE + 2);
		e.Inner = SWITCH_ADDR_SIZE + SWITCH_TAG_SIZE;
		vid = e.Tci & SWITCH_VID_MASK;
		e.VlanTag = (vid != 0);
	}

	// The VLAN of the frame (IEEE 802.1Q): an untagged or priority-tagged frame is in the VLAN of its port; an access
	// port takes the tag of its own VLAN only, a trunk port the tag of a VLAN that it carries
	if (vid == 0)
		vlan = p->Vlan;
	else if (vid != SWITCH_VID_RESERVED && (p->Mode == SWITCH_TRUNK ? SwitchCarries(p, vid) : vid == p->Vlan))
		vlan = vid;
	if (vlan == 0)
		return SwitchDrop(sw, SWITCH_DROP_VLAN);
	if ((frame[6] & 1) != 0)
		return SwitchDrop(sw, SWITCH_DROP_SOURCE);
	// The filter of the switch, before its source is learnt: the security of an L2 Network (SwitchSecurity.h)
	if (sw->Admit != NULL && SwitchAdmit(sw, now, port, p, vlan, frame, size) == false)
		return SwitchDrop(sw, SWITCH_DROP_FILTER);

	e.Vlan = vlan;
	e.Member = p->Member;
	e.State = SwitchVlan(sw, vlan);
	if (e.State == NULL)
		return SwitchDrop(sw, SWITCH_DROP_VLAN);

	SwitchCount(e.State, e.Slot, SWITCH_IN_FRAMES, 1);
	SwitchCount(e.State, e.Slot, SWITCH_IN_BYTES, size);
	SwitchLearn(sw, now, vlan, frame + 6, port, p->Gen);
	// ... and the address of its host, which the IP table learns (SwitchIp.c; SDN-50-N, #492)
	SwitchIpLearn(sw->Ips, now, vlan, frame, size, e.Inner, port, p->Gen);

	// A unicast frame to an address that the VLAN learnt goes to its port alone, never back to the port it came from
	if ((frame[0] & 1) == 0) {
		UINT gen = 0;
		UINT to = SwitchLookup(sw, vlan, frame, &gen);

		if (to != SWITCH_PORT_NONE) {
			bool sent = (to != port && SwitchSendTo(sw, &e, to, true, gen));

			SwitchCount(e.State, e.Slot, sent ? SWITCH_UNICAST : SWITCH_FILTERED, 1);
			return (sent ? 1 : 0);
		}
	}

	// Any other frame goes to a group, through a limit of the VLAN first: a broadcast frame, and a frame to an address
	// that the VLAN has not learnt, to the broadcast group under the broadcast limit; a multicast frame to its group under
	// the multicast limit
	const UCHAR *group = frame;
	SWITCH_LIMIT *limit = &e.State->Multicast;
	UINT fate = SWITCH_MULTICAST;

	if ((frame[0] & 1) == 0) {
		group = switch_broadcast;
		limit = &e.State->Broadcast;
		fate = SWITCH_FLOODED;
	} else if (memcmp(frame, switch_broadcast, sizeof(switch_broadcast)) == 0) {
		limit = &e.State->Broadcast;
		fate = SWITCH_BROADCAST;
	}

	if (SwitchLimitPass(e.State, limit, now) == false) {
		SwitchCount(e.State, e.Slot, SWITCH_LIMIT_DROPS, 1);
		return 0;
	}

	UINT num = SwitchSendGroup(sw, &e, group, port);
	SwitchCount(e.State, e.Slot, num != 0 ? fate : SWITCH_FILTERED, 1);

	return num;
}

//
// The changes
//

// Whether a membership is one: an access port of a VLAN, or a trunk port whose native VLAN (or 0) and allowed VLANs are
// VLANs, with a procedure that takes its frames
static bool SwitchPortConfigOk(const SWITCH_PORT_CONFIG *cfg) {
	if (cfg == NULL || cfg->Send == NULL)
		return false;
	if (cfg->Mode == SWITCH_ACCESS)
		return cfg->Vlan >= SWITCH_MIN_VLAN && cfg->Vlan <= SWITCH_MAX_VLAN;
	if (cfg->Mode != SWITCH_TRUNK || cfg->Vlan > SWITCH_MAX_VLAN || (cfg->Allowed == NULL && cfg->NumAllowed != 0))
		return false;

	for (UINT i = 0; i < cfg->NumAllowed; i++) {
		if (cfg->Allowed[i] < SWITCH_MIN_VLAN || cfg->Allowed[i] > SWITCH_MAX_VLAN)
			return false;
	}

	return true;
}

// The bitmap of the VLANs of a trunk port, its native VLAN included; NULL when there is no memory
static UCHAR *SwitchNewAllowed(const SWITCH_PORT_CONFIG *cfg) {
	UCHAR *map = (UCHAR *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, SWITCH_VLAN_MAP);

	if (map == NULL)
		return NULL;

	for (UINT i = 0; i < cfg->NumAllowed; i++) {
		UINT vlan = cfg->Allowed[i];

		if (vlan < SWITCH_NUM_VLANS)
			map[vlan >> 3] |= (UCHAR)(1u << (vlan & 7));
	}
	if (cfg->Vlan != 0 && cfg->Vlan < SWITCH_NUM_VLANS)
		map[cfg->Vlan >> 3] |= (UCHAR)(1u << (cfg->Vlan & 7));

	return map;
}

// Give a port a membership and its bitmap. The caller holds the lock of the port exclusive.
static void SwitchSetConfig(SWITCH_PORT *p, const SWITCH_PORT_CONFIG *cfg, UCHAR *allowed) {
	p->InUse = true;
	p->Mode = cfg->Mode;
	p->Vlan = cfg->Vlan;
	p->Allowed = allowed;
	p->Send = cfg->Send;
	p->Param = cfg->Param;
	p->Member = cfg->Member;
}

// Take a port out of the groups of the VLANs that it carries and that next, its membership to be (NULL for none), does
// not. The caller holds ConfigLock and no lock of the port.
static void SwitchDropGroups(SWITCH *sw, const SWITCH_PORT *p, const SWITCH_PORT *next, UINT port) {
	for (UINT i = SWITCH_MIN_VLAN; i <= SWITCH_MAX_VLAN; i++) {
		SWITCH_VLAN *v = SwitchVlanState(sw, i);

		if (v == NULL || SwitchCarries(p, i) == false || (next != NULL && SwitchCarries(next, i)))
			continue;

		AcquireSRWLockExclusive(&v->GroupLock);
		SwitchVlanDropPort(v, port);
		ReleaseSRWLockExclusive(&v->GroupLock);
	}
}

// Subscribe a port of the VLAN vlan to a group, or take it out of one
static bool SwitchChangeGroup(SWITCH *sw, UINT port, UINT vlan, const UCHAR *group, bool subscribe) {
	bool ok = false;

	if (sw == NULL || port >= sw->MaxPorts || (group != NULL && (group[0] & 1) == 0))
		return false;

	SWITCH_VLAN *v = SwitchVlan(sw, vlan);
	if (v == NULL)
		return false;

	// The membership of a port changes under ConfigLock only, so it is read here without the lock of the port
	AcquireSRWLockExclusive(&sw->ConfigLock);
	{
		const SWITCH_PORT *p = &sw->Ports[port];

		if (p->InUse && SwitchCarries(p, vlan)) {
			AcquireSRWLockExclusive(&v->GroupLock);
			ok = (subscribe ? SwitchVlanSubscribe(v, group, port) : SwitchVlanUnsubscribe(v, group, port));
			ReleaseSRWLockExclusive(&v->GroupLock);
		}
	}
	ReleaseSRWLockExclusive(&sw->ConfigLock);

	return ok;
}

//
// The switch
//

// A switch with the configuration cfg (NULL for the defaults); NULL when cfg is no configuration of one, or there is no
// memory
SWITCH *SwitchNew(const SWITCH_CONFIG *cfg) {
	SWITCH_CONFIG c;

	ZeroMemory(&c, sizeof(c));
	if (cfg != NULL)
		c = *cfg;
	if (c.Tpid == 0)
		c.Tpid = SWITCH_TPID_8021Q;
	if (c.MaxPorts == 0)
		c.MaxPorts = SWITCH_DEFAULT_PORTS;
	if (c.MaxMacs == 0)
		c.MaxMacs = SWITCH_DEFAULT_MACS;
	if (c.AgingTime == 0)
		c.AgingTime = SWITCH_DEFAULT_AGING;
	if (c.MaxIps == 0)
		c.MaxIps = SWITCH_DEFAULT_IPS;
	if (c.Tpid < SWITCH_MIN_TPID || c.MaxPorts > SWITCH_MAX_PORTS || c.MaxMacs > SWITCH_MAX_MACS || c.MaxIps > SWITCH_MAX_IPS)
		return NULL;

	SWITCH *sw = (SWITCH *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(SWITCH));
	if (sw == NULL)
		return NULL;

	sw->Tpid = c.Tpid;
	sw->MaxPorts = c.MaxPorts;
	sw->MaxMacs = c.MaxMacs;
	sw->AgingTime = c.AgingTime;
	sw->BroadcastLimit = c.BroadcastLimit;
	sw->MulticastLimit = c.MulticastLimit;
	sw->Admit = c.Admit;
	sw->Deliver = c.Deliver;
	sw->FilterParam = c.FilterParam;
	InitializeSRWLock(&sw->ConfigLock);

	// The slots of a shard: twice its share of MaxMacs, a power of 2, of which it fills three quarters at most
	UINT share = (c.MaxMacs + SWITCH_SHARDS - 1) / SWITCH_SHARDS;
	UINT slots = SWITCH_MIN_SLOTS;
	while (slots < share * 2)
		slots *= 2;

	// The ports and the shards from VirtualAlloc: zeroed, and each on a cache line of its own
	sw->Ports = (SWITCH_PORT *)VirtualAlloc(NULL, sizeof(SWITCH_PORT) * c.MaxPorts, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	sw->Shards = (SWITCH_SHARD *)VirtualAlloc(NULL, sizeof(SWITCH_SHARD) * SWITCH_SHARDS, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	sw->Slots = (SWITCH_MAC *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(SWITCH_MAC) * slots * SWITCH_SHARDS);
	if (sw->Ports == NULL || sw->Shards == NULL || sw->Slots == NULL ||
	    BCRYPT_SUCCESS(BCryptGenRandom(NULL, (PUCHAR)&sw->Seed, sizeof(sw->Seed), BCRYPT_USE_SYSTEM_PREFERRED_RNG)) == false) {
		SwitchFree(sw);
		return NULL;
	}

	for (UINT i = 0; i < c.MaxPorts; i++)
		InitializeSRWLock(&sw->Ports[i].Lock);
	for (UINT i = 0; i < SWITCH_SHARDS; i++) {
		SWITCH_SHARD *s = &sw->Shards[i];

		InitializeSRWLock(&s->Lock);
		s->Mask = slots - 1;
		s->MaxNum = slots - slots / 4;
		s->Slots = &sw->Slots[(SIZE_T)i * slots];
	}

	// The IP table, whose hash takes the random key of the MAC table (SwitchIp.c; SDN-50-N, #492)
	sw->Ips = SwitchIpNew(c.MaxIps, sw->Seed);
	if (sw->Ips == NULL) {
		SwitchFree(sw);
		return NULL;
	}

	return sw;
}

// Free a switch. Every thread that calls into it must have stopped before.
void SwitchFree(SWITCH *sw) {
	if (sw == NULL)
		return;

	for (UINT i = 0; i < SWITCH_NUM_VLANS; i++) {
		SWITCH_VLAN *v = SwitchVlanState(sw, i);

		if (v != NULL)
			SwitchFreeVlan(v);
	}

	if (sw->Ports != NULL) {
		for (UINT i = 0; i < sw->MaxPorts; i++) {
			UCHAR *allowed = sw->Ports[i].Allowed;

			if (allowed != NULL)
				HeapFree(GetProcessHeap(), 0, allowed);
		}
		VirtualFree(sw->Ports, 0, MEM_RELEASE);
	}
	if (sw->Shards != NULL)
		VirtualFree(sw->Shards, 0, MEM_RELEASE);
	if (sw->Slots != NULL)
		HeapFree(GetProcessHeap(), 0, sw->Slots);
	SwitchIpFree(sw->Ips);

	HeapFree(GetProcessHeap(), 0, sw);
}

// A port for a member with the membership cfg: the free port of the lowest number. SWITCH_PORT_NONE when cfg is no
// membership, every port is taken or there is no memory.
UINT SwitchAddPort(SWITCH *sw, const SWITCH_PORT_CONFIG *cfg) {
	UINT port = SWITCH_PORT_NONE;
	UCHAR *allowed = NULL;

	if (sw == NULL || SwitchPortConfigOk(cfg) == false)
		return SWITCH_PORT_NONE;
	if (cfg->Mode == SWITCH_TRUNK) {
		allowed = SwitchNewAllowed(cfg);
		if (allowed == NULL)
			return SWITCH_PORT_NONE;
	}

	AcquireSRWLockExclusive(&sw->ConfigLock);
	for (UINT i = 0; i < sw->MaxPorts && port == SWITCH_PORT_NONE; i++) {
		SWITCH_PORT *p = &sw->Ports[i];

		if (p->InUse)
			continue;

		AcquireSRWLockExclusive(&p->Lock);
		SwitchSetConfig(p, cfg, allowed);
		ReleaseSRWLockExclusive(&p->Lock);
		sw->NumPorts++;
		port = i;
	}
	ReleaseSRWLockExclusive(&sw->ConfigLock);

	// Every port is taken: the bitmap goes again
	if (port == SWITCH_PORT_NONE && allowed != NULL)
		HeapFree(GetProcessHeap(), 0, allowed);

	return port;
}

// Give a port that a member holds the membership cfg. The port leaves the groups of the VLANs that it no longer carries,
// and the MAC table forgets its addresses, which the port learns again in the VLANs that it carries now. False when
// cfg is no membership, no member holds the port or there is no memory.
bool SwitchSetPort(SWITCH *sw, UINT port, const SWITCH_PORT_CONFIG *cfg) {
	UCHAR *allowed = NULL;
	UCHAR *old = NULL;
	bool ok = false;

	if (sw == NULL || port >= sw->MaxPorts || SwitchPortConfigOk(cfg) == false)
		return false;
	if (cfg->Mode == SWITCH_TRUNK) {
		allowed = SwitchNewAllowed(cfg);
		if (allowed == NULL)
			return false;
	}

	AcquireSRWLockExclusive(&sw->ConfigLock);
	{
		SWITCH_PORT *p = &sw->Ports[port];

		if (p->InUse) {
			SWITCH_PORT next;

			ZeroMemory(&next, sizeof(next));
			next.Mode = cfg->Mode;
			next.Vlan = cfg->Vlan;
			next.Allowed = allowed;
			SwitchDropGroups(sw, p, &next, port);

			// A frame that the port takes or sends now ends before the lock is taken, and the next one sees the new
			// membership
			AcquireSRWLockExclusive(&p->Lock);
			old = p->Allowed;
			SwitchSetConfig(p, cfg, allowed);
			ReleaseSRWLockExclusive(&p->Lock);

			SwitchSweep(sw, SWITCH_SWEEP_PORT, 0, port, 0);
			SwitchIpForget(sw->Ips, port);
			ok = true;
		}
	}
	ReleaseSRWLockExclusive(&sw->ConfigLock);

	if (ok == false)
		old = allowed;
	if (old != NULL)
		HeapFree(GetProcessHeap(), 0, old);

	return ok;
}

// Take the member out of a port: the port leaves every group, the MAC table forgets its addresses, and once this
// returns, the switch calls the procedure of the port no more. False when no member holds the port.
bool SwitchDelPort(SWITCH *sw, UINT port) {
	UCHAR *old = NULL;
	bool ok = false;

	if (sw == NULL || port >= sw->MaxPorts)
		return false;

	AcquireSRWLockExclusive(&sw->ConfigLock);
	{
		SWITCH_PORT *p = &sw->Ports[port];

		if (p->InUse) {
			SwitchDropGroups(sw, p, NULL, port);

			// A frame that the port takes or sends now ends before the lock is taken, and the next one finds no member
			AcquireSRWLockExclusive(&p->Lock);
			old = p->Allowed;
			p->InUse = false;
			p->Mode = SWITCH_ACCESS;
			p->Vlan = 0;
			p->Gen++;
			p->Allowed = NULL;
			p->Send = NULL;
			p->Param = NULL;
			ReleaseSRWLockExclusive(&p->Lock);

			sw->NumPorts--;
			SwitchSweep(sw, SWITCH_SWEEP_PORT, 0, port, 0);
			SwitchIpForget(sw->Ips, port);
			ok = true;
		}
	}
	ReleaseSRWLockExclusive(&sw->ConfigLock);

	if (old != NULL)
		HeapFree(GetProcessHeap(), 0, old);

	return ok;
}

// Subscribe a port to the group address group of the VLAN vlan, which the port carries: the broadcast address for the
// broadcast group, which also takes the frames to an address that the VLAN has not learnt; NULL for every group. False
// when group is no group address, the port does not carry the VLAN, the VLAN has SWITCH_MAX_GROUPS groups or there is
// no memory.
bool SwitchSubscribe(SWITCH *sw, UINT port, UINT vlan, const UCHAR *group) {
	return SwitchChangeGroup(sw, port, vlan, group, true);
}

// Take a port out of the group group of the VLAN vlan, or out of every group for NULL; false when it did not subscribe
bool SwitchUnsubscribe(SWITCH *sw, UINT port, UINT vlan, const UCHAR *group) {
	return SwitchChangeGroup(sw, port, vlan, group, false);
}

// Set the limits of the VLAN vlan: broadcast and multicast frames per second, 0 for no limit. The bucket of each starts
// full. False for a VLAN id that is none, or when there is no memory.
bool SwitchSetVlanLimits(SWITCH *sw, UINT vlan, UINT broadcast, UINT multicast) {
	if (sw == NULL)
		return false;

	SWITCH_VLAN *v = SwitchVlan(sw, vlan);
	if (v == NULL)
		return false;

	AcquireSRWLockExclusive(&v->LimitLock);
	SwitchSetLimit(&v->Broadcast, broadcast);
	SwitchSetLimit(&v->Multicast, multicast);
	ReleaseSRWLockExclusive(&v->LimitLock);

	return true;
}

// The one ingress of the switch: frame, size bytes, that the member of port sent at now (ms). It runs to completion on
// the calling thread: the VLAN of the frame, the learning of its source and the calls of the procedures of the ports it
// goes to. The number of those ports.
UINT SwitchInput(SWITCH *sw, UINT64 now, UINT port, const UCHAR *frame, UINT size) {
	UINT num = 0;

	if (sw == NULL)
		return 0;
	if (frame == NULL || size < SWITCH_MIN_FRAME || size > SWITCH_MAX_FRAME)
		return SwitchDrop(sw, SWITCH_DROP_MALFORMED);
	if (port >= sw->MaxPorts)
		return SwitchDrop(sw, SWITCH_DROP_PORT);

	SWITCH_PORT *p = &sw->Ports[port];
	AcquireSRWLockShared(&p->Lock);
	if (p->InUse)
		num = SwitchForward(sw, now, port, p, frame, size);
	else
		num = SwitchDrop(sw, SWITCH_DROP_PORT);
	ReleaseSRWLockShared(&p->Lock);

	return num;
}

// Take out the entries of the MAC table that no frame refreshed for the aging time until now; their number. The IP table
// ages with it (SwitchIp.c).
UINT SwitchAge(SWITCH *sw, UINT64 now) {
	if (sw == NULL)
		return 0;

	SwitchIpAge(sw->Ips, now, sw->AgingTime);
	return SwitchSweep(sw, SWITCH_SWEEP_AGE, now, 0, 0);
}

// Take out every entry of the MAC table; their number
UINT SwitchClearMacs(SWITCH *sw) {
	if (sw == NULL)
		return 0;

	return SwitchSweep(sw, SWITCH_SWEEP_ALL, 0, 0, 0);
}

// Take out the entries of the MAC address mac in every VLAN (SDN-50-N, #492); their number
UINT SwitchClearMac(SWITCH *sw, const UCHAR *mac) {
	if (sw == NULL || mac == NULL)
		return 0;

	return SwitchSweep(sw, SWITCH_SWEEP_MAC, 0, 0, SwitchMacKey(0, mac));
}

// Learn that the address mac of the VLAN vlan is on port without a frame from it, at now, as the routes of a control plane say:
// the remote MAC addresses of a Stretch at its port of the fabric (Cedar/NodeStretch.c; SDN-64, #291), so that a frame to one
// goes to that port alone and floods nowhere. A new entry, or the entry of the port refreshed, as SwitchInput learns the source
// of a frame; an address that the table has at another port stays there, as what a member sends wins over what a route says.
// True when the table has the address at the port afterwards; false when no member holds the port, it does not carry the
// VLAN, mac is a group address or the table is full.
bool SwitchLearnAt(SWITCH *sw, UINT64 now, UINT port, UINT vlan, const UCHAR *mac) {
	UINT gen = 0;
	bool ok = false;

	if (sw == NULL || mac == NULL || port >= sw->MaxPorts || (mac[0] & 1) != 0 || vlan < SWITCH_MIN_VLAN || vlan > SWITCH_MAX_VLAN)
		return false;

	SWITCH_PORT *p = &sw->Ports[port];
	AcquireSRWLockShared(&p->Lock);
	if (p->InUse && SwitchCarries(p, vlan)) {
		UINT at = SwitchLookup(sw, vlan, mac, &gen);

		if (at == SWITCH_PORT_NONE || at == port)
			SwitchLearn(sw, now, vlan, mac, port, p->Gen);
		ok = (SwitchLookup(sw, vlan, mac, &gen) == port && gen == p->Gen);
	}
	ReleaseSRWLockShared(&p->Lock);

	return ok;
}

// The IP table of a switch, for SwitchIp.c
SWITCH_IP_TABLE *SwitchIpTable(SWITCH *sw) {
	return (sw != NULL ? sw->Ips : NULL);
}

// The order of two entries: by VLAN, then by address
static int SwitchCompareEntry(const void *p1, const void *p2) {
	const SWITCH_MAC_ENTRY *a = (const SWITCH_MAC_ENTRY *)p1;
	const SWITCH_MAC_ENTRY *b = (const SWITCH_MAC_ENTRY *)p2;

	if (a->Vlan != b->Vlan)
		return (a->Vlan < b->Vlan ? -1 : 1);

	return memcmp(a->Mac, b->Mac, sizeof(a->Mac));
}

// The first max entries of the MAC table by VLAN and address; their number
UINT SwitchGetMacs(SWITCH *sw, SWITCH_MAC_ENTRY *list, UINT max) {
	UINT num = 0;

	if (sw == NULL || list == NULL)
		return 0;

	for (UINT i = 0; i < SWITCH_SHARDS; i++) {
		SWITCH_SHARD *s = &sw->Shards[i];

		// The lock keeps the writers of the shard out while its entries are copied
		AcquireSRWLockShared(&s->Lock);
		for (UINT j = 0; j <= s->Mask; j++) {
			const SWITCH_MAC *e = &s->Slots[j];
			UINT64 key = (UINT64)e->Key;
			SWITCH_MAC_ENTRY m;

			if (key == 0)
				continue;

			ZeroMemory(&m, sizeof(m));
			m.Vlan = (UINT)(key >> 48);
			for (UINT k = 0; k < sizeof(m.Mac); k++)
				m.Mac[k] = (UCHAR)(key >> (40 - 8 * k));
			m.Port = (UINT)e->Port;
			m.LastSeen = (UINT64)e->LastSeen;
			// A table of more entries than max gives its first max (SDN-50-N, #492)
			SwitchKeepFirst(list, &num, max, &m, sizeof(m), SwitchCompareEntry);
		}
		ReleaseSRWLockShared(&s->Lock);
	}

	if (num > 1)
		qsort(list, num, sizeof(SWITCH_MAC_ENTRY), SwitchCompareEntry);

	return num;
}

void SwitchGetStats(SWITCH *sw, SWITCH_STATS *st) {
	if (st == NULL)
		return;

	ZeroMemory(st, sizeof(SWITCH_STATS));
	if (sw == NULL)
		return;

	AcquireSRWLockShared(&sw->ConfigLock);
	st->NumPorts = sw->NumPorts;
	ReleaseSRWLockShared(&sw->ConfigLock);

	st->NumMacs = (UINT)ReadNoFence(&sw->NumMacs);
	st->NumVlans = (UINT)ReadNoFence(&sw->NumVlans);
	st->Learnt = (UINT64)ReadNoFence64(&sw->Learnt);
	st->Moved = (UINT64)ReadNoFence64(&sw->Moved);
	st->Refused = (UINT64)ReadNoFence64(&sw->Refused);
	for (UINT i = 0; i < SWITCH_NUM_REASONS; i++)
		st->Drops[i] = (UINT64)ReadNoFence64(&sw->Drops[i]);
	// The counters of the IP table (SwitchIp.c; SDN-50-N, #492)
	SwitchIpStats(sw->Ips, st);
}

// The counters and limits of the VLAN vlan; false while it has no state
bool SwitchGetVlanStats(SWITCH *sw, UINT vlan, SWITCH_VLAN_STATS *st) {
	UINT64 sum[SWITCH_NUM_COUNTERS];

	if (st == NULL)
		return false;

	ZeroMemory(st, sizeof(SWITCH_VLAN_STATS));
	if (sw == NULL || vlan < SWITCH_MIN_VLAN || vlan > SWITCH_MAX_VLAN)
		return false;

	SWITCH_VLAN *v = SwitchVlanState(sw, vlan);
	if (v == NULL)
		return false;

	ZeroMemory(sum, sizeof(sum));
	for (UINT i = 0; i < SWITCH_SLOTS; i++) {
		for (UINT j = 0; j < SWITCH_NUM_COUNTERS; j++)
			sum[j] += (UINT64)ReadNoFence64(&v->Counters[i].Count[j]);
	}

	st->InFrames = sum[SWITCH_IN_FRAMES];
	st->InBytes = sum[SWITCH_IN_BYTES];
	st->Unicast = sum[SWITCH_UNICAST];
	st->Flooded = sum[SWITCH_FLOODED];
	st->Broadcast = sum[SWITCH_BROADCAST];
	st->Multicast = sum[SWITCH_MULTICAST];
	st->LimitDrops = sum[SWITCH_LIMIT_DROPS];
	st->Filtered = sum[SWITCH_FILTERED];
	st->OutFrames = sum[SWITCH_OUT_FRAMES];
	st->OutBytes = sum[SWITCH_OUT_BYTES];

	AcquireSRWLockShared(&v->LimitLock);
	st->BroadcastLimit = v->Broadcast.Rate;
	st->MulticastLimit = v->Multicast.Rate;
	ReleaseSRWLockShared(&v->LimitLock);

	return true;
}
