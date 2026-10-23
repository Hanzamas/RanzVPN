// NodeShape.c
// The MTU, the TCP MSS clamp and the rate limits of the overlay of a node (SDN-20, #196; ADR-0025 decisions 16 and
// 17). The controller gives each VRF an MTU, 1280 when the intent leaves it out and more where an override raises it
// because the underlay allows, and the node and each VRF a rate limit in bits per second. Each Generation that the
// overlay applies (NodeOverlay.c) gets its shaping table beside its forwarding tables (NodeShapeAttach): the two go in
// together (NodeSwapVrfs) and are freed together, so a packet meets the MTU and the limits of the Generation that
// routes it. Once a Generation is in, the host's adapter of each VRF whose MTU is new or changed takes it
// (NodeShapeApplied, NODE_ADAPTER_MTU_PROC): the Wintun adapter of the VRF (SDN-5, #181), a fake adapter in the
// vpntest harness.
//
// A packet of the host on its way to a peer (NodeOverlayInput) passes NodeShapeOutput. A TCP SYN gets its MSS clamped
// to the MTU of its VRF less the IPv4 and TCP headers by AdjustTcpMssL3 (TcpIp), which takes 20 bytes more for IPv6
// and leaves every other packet alone, so encapsulation, 4via6 and VXLAN never fragment by surprise. Then the token
// bucket of its VRF and the one of the node take its bytes, or it is dropped: a limit polices and queues nothing
// (priority queues come after v1). A bucket runs GCRA, the generic cell rate algorithm of ITU-T I.371 that the relay
// role of the peer module runs too (Core/Peer.c), with bytes for cells and nanoseconds of the performance counter: one
// theoretical arrival time, which a compare-exchange moves on, so the workers and the I/O threads share a bucket
// without a lock. A bucket holds a burst of NODE_SHAPE_BURST ms of its rate, and at least NODE_SHAPE_MIN_BURST bytes,
// so a packet of any size passes once the bucket is full. The buckets keep their state from one Generation to the
// next. No byte of an IP header changes: a packet reaches the far end with the DSCP and ECN bits of its host.

#include "Node.h"

#include "Mayaqua/Memory.h"
#include "Mayaqua/Object.h"
#include "Mayaqua/TcpIp.h"

#include "Core/Control.h"

#include <stdlib.h>

#include "NodeInternal.h"

#define NODE_SHAPE_NS 1000000000ULL // ns in a second

// The state of one VRF that outlives the Generations: its bucket, and what the adapter and the node log took last
typedef struct NODE_SHAPE_STATE {
	UINT VrfId;          // The VRF
	volatile LONG64 Tat; // The theoretical arrival time of its bucket in ns
	UINT Mtu;            // The MTU that the host's adapter of the VRF took last, 0 while no state holds the VRF
	UINT64 Rate;         // The rate limit that the node log named last
} NODE_SHAPE_STATE;

// The shaping of the overlay of a node, while the overlay runs
struct NODE_SHAPE {
	LOCK *Lock;                        // States, NodeRate and the fields of the states but Tat
	LIST *States;                      // The state of each VRF that a Generation named (NODE_SHAPE_STATE)
	volatile LONG64 NodeTat;           // The theoretical arrival time of the node's bucket in ns
	UINT64 NodeRate;                   // The rate limit of the node that the node log named last
	UINT64 Frequency;                  // The frequency of the performance counter
	NODE_ADAPTER_MTU_PROC *AdapterMtu; // Takes the MTU of each VRF for the host's adapter of the VRF, NULL for none
	void *AdapterParam;                // ... and its second parameter
	volatile LONG64 Clamped;           // TCP SYNs that left with their MSS clamped to the MTU of their VRF
	volatile LONG64 Limited;           // Packets that a rate limit dropped
};

// A rate limit of one Generation on a bucket
typedef struct NODE_SHAPE_LIMIT {
	UINT64 Rate;          // Bits per second, 0 for no limit
	LONG64 Burst;         // What the bucket holds, in ns at the rate
	volatile LONG64 *Tat; // The theoretical arrival time of the bucket
} NODE_SHAPE_LIMIT;

// One VRF of a shaping table
typedef struct NODE_SHAPE_VRF {
	UINT VrfId;             // The VRF
	UINT Mtu;               // Its MTU
	NODE_SHAPE_LIMIT Limit; // Its rate limit
} NODE_SHAPE_VRF;

// The shaping table of one Generation: the rate limit of the node, and the MTU and the rate limit of each VRF of its
// desired state. It rides on the forwarding tables of the Generation (NODE_VRF_TABLES), which the data path reads
// without a lock.
struct NODE_SHAPE_TABLE {
	UINT64 Frequency;                      // The frequency of the performance counter
	NODE_SHAPE_LIMIT Node;                 // The rate limit of the node
	UINT NumVrfs;                          // Number of VRFs
	NODE_SHAPE_VRF Vrfs[CONTROL_MAX_VRFS]; // ... by VRF id
};

// The time of the shaping: ns of the performance counter, whose frequency is freq
static LONG64 NodeShapeNow(UINT64 freq) {
	LARGE_INTEGER counter;

	QueryPerformanceCounter(&counter);

	UINT64 t = (UINT64)counter.QuadPart;
	return (LONG64)((t / freq) * NODE_SHAPE_NS + (t % freq) * NODE_SHAPE_NS / freq);
}

// The ns that size bytes take at rate bits per second (not 0), rounded up. size is at most NODE_SHAPE_MIN_BURST, so
// the product stays far inside 64 bits.
static LONG64 NodeShapeCost(UINT64 rate, UINT size) {
	UINT64 ns = (UINT64)size * 8 * NODE_SHAPE_NS;

	return (LONG64)(ns / rate + (ns % rate != 0 ? 1 : 0));
}

// The rate limit of rate bits per second, 0 for none, on the bucket whose theoretical arrival time is at tat
static void NodeShapeLimit(NODE_SHAPE_LIMIT *l, UINT64 rate, volatile LONG64 *tat) {
	Zero(l, sizeof(NODE_SHAPE_LIMIT));
	l->Tat = tat;
	if (rate == 0)
		return;

	LONG64 min_burst = NodeShapeCost(rate, NODE_SHAPE_MIN_BURST);

	l->Rate = rate;
	l->Burst = MAX(min_burst, (LONG64)NODE_SHAPE_BURST * 1000000);
}

// GCRA on one bucket: a packet of size bytes passes when the bucket, with the packet in it, holds no more than its
// burst, and the theoretical arrival time moves on by the packet. Without a limit every packet passes.
static bool NodeShapeTake(const NODE_SHAPE_LIMIT *l, UINT size, LONG64 now) {
	if (l->Rate == 0)
		return true;
	if (size > NODE_SHAPE_MIN_BURST)
		return false;

	LONG64 cost = NodeShapeCost(l->Rate, size);

	while (true) {
		LONG64 tat = ReadAcquire64(l->Tat);
		LONG64 next = MAX(tat, now) + cost;

		if (next - now > l->Burst)
			return false;

		if (InterlockedCompareExchange64(l->Tat, next, tat) == tat)
			return true;
	}
}

// Give a bucket back what NodeShapeTake took for a packet that the next bucket refused
static void NodeShapeGiveBack(const NODE_SHAPE_LIMIT *l, UINT size) {
	if (l->Rate != 0 && size <= NODE_SHAPE_MIN_BURST)
		InterlockedExchangeAdd64(l->Tat, -NodeShapeCost(l->Rate, size));
}

// The VRF vrf_id of a shaping table, NULL when it holds none
static const NODE_SHAPE_VRF *NodeShapeFind(const NODE_SHAPE_TABLE *t, UINT vrf_id) {
	if (t == NULL)
		return NULL;

	UINT low = 0, high = t->NumVrfs;
	while (low < high) {
		UINT mid = low + (high - low) / 2;
		const NODE_SHAPE_VRF *e = &t->Vrfs[mid];

		if (e->VrfId == vrf_id)
			return e;

		if (e->VrfId < vrf_id)
			low = mid + 1;
		else
			high = mid;
	}

	return NULL;
}

static int NodeShapeCompareVrf(const void *p1, const void *p2) {
	const NODE_SHAPE_VRF *v1 = (const NODE_SHAPE_VRF *)p1;
	const NODE_SHAPE_VRF *v2 = (const NODE_SHAPE_VRF *)p2;

	if (v1->VrfId == v2->VrfId)
		return 0;

	return (v1->VrfId < v2->VrfId ? -1 : 1);
}

// The MTU of a VRF of the desired state: below the default, which is the least that IPv6 allows, it is the default
static UINT NodeShapeMtu(UINT mtu) {
	return (mtu >= NODE_SHAPE_DEFAULT_MTU ? MIN(mtu, NODE_SHAPE_MAX_MTU) : NODE_SHAPE_DEFAULT_MTU);
}

// Whether VRF i of the state repeats the id of a VRF before it, which the controller never sends; the first one counts
static bool NodeShapeRepeated(const CONTROL_STATE *st, UINT i) {
	for (UINT j = 0; j < i; j++)
		if (st->Vrfs[j].Id == st->Vrfs[i].Id)
			return true;

	return false;
}

// Whether the state holds the VRF vrf_id
static bool NodeShapeHolds(const CONTROL_STATE *st, UINT vrf_id) {
	for (UINT i = 0; i < st->NumVrfs && i < CONTROL_MAX_VRFS; i++)
		if (st->Vrfs[i].Id == vrf_id)
			return true;

	return false;
}

// The state of the VRF vrf_id, a new one the first time. The caller holds the lock.
static NODE_SHAPE_STATE *NodeShapeState(NODE_SHAPE *s, UINT vrf_id) {
	for (UINT i = 0; i < LIST_NUM(s->States); i++) {
		NODE_SHAPE_STATE *found = LIST_DATA(s->States, i);

		if (found->VrfId == vrf_id)
			return found;
	}

	NODE_SHAPE_STATE *e = ZeroMalloc(sizeof(NODE_SHAPE_STATE));
	e->VrfId = vrf_id;
	Add(s->States, e);

	return e;
}

// Start the shaping of the overlay of a node (NodeOverlayStart): the adapter procedure of the configuration takes the
// MTU of each VRF
void NodeShapeStart(NODE *n, const NODE_OVERLAY_CONFIG *cfg) {
	LARGE_INTEGER freq;

	if (n == NULL || cfg == NULL || n->Shape != NULL)
		return;

	NODE_SHAPE *s = ZeroMalloc(sizeof(NODE_SHAPE));
	QueryPerformanceFrequency(&freq);
	s->Frequency = MAX((UINT64)freq.QuadPart, 1);
	s->Lock = NewLock();
	s->States = NewListFast(NULL);
	s->AdapterMtu = cfg->AdapterMtu;
	s->AdapterParam = cfg->AdapterParam;

	n->Shape = s;
}

// Stop the shaping of the overlay of a node (NodeOverlayStop), once no forwarding tables are left whose shaping
// tables lead to its buckets
void NodeShapeStop(NODE *n) {
	NODE_SHAPE *s = (n != NULL ? n->Shape : NULL);

	if (s == NULL)
		return;

	n->Shape = NULL;

	for (UINT i = 0; i < LIST_NUM(s->States); i++)
		Free(LIST_DATA(s->States, i));
	ReleaseList(s->States);
	DeleteLock(s->Lock);
	Free(s);
}

// The shaping table of the Generation of st onto its forwarding tables v, before they go in: the rate limit of the
// node, and the MTU and the rate limit of each VRF of the state, on buckets that keep their state from the
// Generations before
void NodeShapeAttach(NODE *n, NODE_VRF_TABLES *v, const CONTROL_STATE *st) {
	NODE_SHAPE *s = (n != NULL ? n->Shape : NULL);

	if (s == NULL || v == NULL || st == NULL)
		return;

	NODE_SHAPE_TABLE *t = ZeroMalloc(sizeof(NODE_SHAPE_TABLE));
	t->Frequency = s->Frequency;
	NodeShapeLimit(&t->Node, st->RateLimit, &s->NodeTat);

	Lock(s->Lock);
	{
		for (UINT i = 0; i < st->NumVrfs && i < CONTROL_MAX_VRFS; i++) {
			const CONTROL_VRF *cv = &st->Vrfs[i];

			if (NodeShapeRepeated(st, i))
				continue;

			NODE_SHAPE_VRF *e = &t->Vrfs[t->NumVrfs++];
			e->VrfId = cv->Id;
			e->Mtu = NodeShapeMtu(cv->Mtu);
			NodeShapeLimit(&e->Limit, cv->RateLimit, &NodeShapeState(s, cv->Id)->Tat);
		}
	}
	Unlock(s->Lock);

	qsort(t->Vrfs, t->NumVrfs, sizeof(NODE_SHAPE_VRF), NodeShapeCompareVrf);

	NodeShapeFreeTable(v->Shape);
	v->Shape = t;
}

// The Generation of st went in: the host's adapter of each VRF whose MTU is new or changed takes it, and the node log
// names each MTU and rate limit that changed. A VRF that the state does not hold takes its MTU again once a later
// state brings it back, with a new adapter then. The adapter procedure runs on the caller's thread, without the lock.
void NodeShapeApplied(NODE *n, const CONTROL_STATE *st) {
	NODE_SHAPE *s = (n != NULL ? n->Shape : NULL);
	UINT mtus[CONTROL_MAX_VRFS];
	UINT rates[CONTROL_MAX_VRFS];
	UINT num_mtus = 0, num_rates = 0;
	bool node_rate = false;

	if (s == NULL || st == NULL)
		return;

	Zero(mtus, sizeof(mtus));
	Zero(rates, sizeof(rates));

	// What changed, by the index of its VRF in the state, collected under the lock
	Lock(s->Lock);
	{
		for (UINT i = 0; i < LIST_NUM(s->States); i++) {
			NODE_SHAPE_STATE *e = LIST_DATA(s->States, i);

			if (NodeShapeHolds(st, e->VrfId) == false) {
				e->Mtu = 0;
				e->Rate = 0;
			}
		}

		for (UINT i = 0; i < st->NumVrfs && i < CONTROL_MAX_VRFS; i++) {
			const CONTROL_VRF *cv = &st->Vrfs[i];

			if (NodeShapeRepeated(st, i))
				continue;

			NODE_SHAPE_STATE *e = NodeShapeState(s, cv->Id);
			UINT mtu = NodeShapeMtu(cv->Mtu);

			if (e->Mtu != mtu) {
				e->Mtu = mtu;
				mtus[num_mtus++] = i;
			}
			if (e->Rate != cv->RateLimit) {
				e->Rate = cv->RateLimit;
				rates[num_rates++] = i;
			}
		}

		node_rate = (s->NodeRate != st->RateLimit);
		s->NodeRate = st->RateLimit;
	}
	Unlock(s->Lock);

	for (UINT k = 0; k < num_mtus; k++) {
		const CONTROL_VRF *cv = &st->Vrfs[mtus[k]];
		UINT mtu = NodeShapeMtu(cv->Mtu);

		NodeLog(n, "Shape: VRF %s (%u): MTU %u, the MSS of a TCP SYN at most %u", cv->Name, cv->Id, mtu, mtu - NODE_SHAPE_MSS_HEADERS);
		if (s->AdapterMtu != NULL)
			s->AdapterMtu(n, s->AdapterParam, cv->Id, mtu);
	}

	for (UINT k = 0; k < num_rates; k++) {
		const CONTROL_VRF *cv = &st->Vrfs[rates[k]];

		if (cv->RateLimit != 0)
			NodeLog(n, "Shape: VRF %s (%u): rate limit %I64u bit/s", cv->Name, cv->Id, cv->RateLimit);
		else
			NodeLog(n, "Shape: VRF %s (%u): no rate limit", cv->Name, cv->Id);
	}

	if (node_rate && st->RateLimit != 0)
		NodeLog(n, "Shape: the rate limit of the node is %I64u bit/s", st->RateLimit);
	else if (node_rate)
		NodeLog(n, "Shape: the node has no rate limit");
}

// A packet of the host in the VRF vrf_id on its way to a peer, in the copy that the overlay sends: a TCP SYN gets its
// MSS clamped to the MTU of the VRF in the shaping table of v (NODE_SHAPE_DEFAULT_MTU for a VRF that the table does not
// hold), then the buckets of the VRF and of the node take its bytes. False when a rate limit drops it. The caller is an
// online reader of the node's table snapshot, which holds v.
bool NodeShapeOutput(NODE *n, NODE_VRF_TABLES *v, UINT vrf_id, UCHAR *packet, UINT size) {
	NODE_SHAPE *s = (n != NULL ? n->Shape : NULL);
	NODE_SHAPE_TABLE *t = (v != NULL ? v->Shape : NULL);
	const NODE_SHAPE_VRF *e = NodeShapeFind(t, vrf_id);
	bool ok = true;

	if (packet == NULL || size == 0)
		return false;

	// The MSS of a SYN is the MTU less the IPv4 and TCP headers; AdjustTcpMssL3 takes 20 bytes more for IPv6, and
	// leaves an MSS that is lower alone
	UINT mtu = (e != NULL ? e->Mtu : NODE_SHAPE_DEFAULT_MTU);
	bool clamped = AdjustTcpMssL3(packet, size, mtu - NODE_SHAPE_MSS_HEADERS);

	// The bucket of the VRF, then the one of the node, which gives the VRF its bytes back when it refuses them
	if (t != NULL && (t->Node.Rate != 0 || (e != NULL && e->Limit.Rate != 0))) {
		LONG64 now = NodeShapeNow(t->Frequency);

		ok = (e == NULL || NodeShapeTake(&e->Limit, size, now));
		if (ok && NodeShapeTake(&t->Node, size, now) == false) {
			if (e != NULL)
				NodeShapeGiveBack(&e->Limit, size);
			ok = false;
		}
	}

	if (s != NULL && ok == false)
		InterlockedIncrement64(&s->Limited);
	if (s != NULL && ok && clamped)
		InterlockedIncrement64(&s->Clamped);

	return ok;
}

// Free a shaping table, wiped first as NodeFreeTable does
void NodeShapeFreeTable(NODE_SHAPE_TABLE *t) {
	if (t == NULL)
		return;

	Zero(t, sizeof(NODE_SHAPE_TABLE));
	Free(t);
}

// The counters of the shaping of the overlay of a node
void NodeShapeGetStatus(NODE *n, NODE_SHAPE_STATUS *st) {
	if (st == NULL)
		return;

	Zero(st, sizeof(NODE_SHAPE_STATUS));
	NODE_SHAPE *s = (n != NULL ? n->Shape : NULL);
	if (s == NULL)
		return;

	st->Clamped = (UINT64)ReadAcquire64(&s->Clamped);
	st->Limited = (UINT64)ReadAcquire64(&s->Limited);
}
