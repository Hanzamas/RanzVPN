// NodeTable.c
// The table snapshot of a node: the read-mostly MAC, route and policy tables that the data path reads without
// a lock, swapped by pointer (ADR-0022, Threading). A swap frees the old snapshot after a grace period: once
// every online reader has passed a quiescent point, none can still hold it (quiescent-state-based reclamation,
// which suits run-to-completion loops: a reader keeps no snapshot from one batch to the next). The forwarding
// tables of the VRFs (NodeVrf.c; SDN-4, #180) are part of the snapshot and swapped the same way, on their own.

#include "Node.h"

#include "Mayaqua/Memory.h"
#include "Mayaqua/Object.h"

#include <stdlib.h>
#include <string.h>
#include "NodeEvpn.h"
#include "NodeInternal.h"

// How a writer waits for a reader in the grace period: a pass takes microseconds, so it spins first, then
// gives the core to a reader that it may have preempted, then sleeps
#define NODE_GRACE_SPINS  1000
#define NODE_GRACE_YIELDS 100

// Order two entries by key, for qsort and bsearch
static int NodeCompareEntry(const void *p1, const void *p2) {
	const NODE_TABLE_ENTRY *e1 = (const NODE_TABLE_ENTRY *)p1;
	const NODE_TABLE_ENTRY *e2 = (const NODE_TABLE_ENTRY *)p2;

	return memcmp(e1->Key, e2->Key, NODE_TABLE_KEY_SIZE);
}

// A table of a copy of the num entries, sorted by key; NULL for too many entries
NODE_TABLE *NodeNewTable(NODE_TABLE_ENTRY *entries, UINT num) {
	if ((entries == NULL && num != 0) || num > NODE_TABLE_MAX_ENTRIES)
		return NULL;

	NODE_TABLE *t = ZeroMalloc(sizeof(NODE_TABLE));
	t->NumEntries = num;
	t->Entries = ZeroMalloc(sizeof(NODE_TABLE_ENTRY) * MAX(num, 1));

	if (num != 0) {
		Copy(t->Entries, entries, sizeof(NODE_TABLE_ENTRY) * num);
		qsort(t->Entries, num, sizeof(NODE_TABLE_ENTRY), NodeCompareEntry);
	}

	return t;
}

// Free a table. It is wiped first, so that a reader that kept it past its quiescent point finds no entry that
// looks valid instead of the old one
void NodeFreeTable(NODE_TABLE *t) {
	if (t == NULL)
		return;

	Zero(t->Entries, sizeof(NODE_TABLE_ENTRY) * MAX(t->NumEntries, 1));
	Free(t->Entries);

	Zero(t, sizeof(NODE_TABLE));
	Free(t);
}

// The entry of the key (NODE_TABLE_KEY_SIZE bytes), NULL when the table has none
NODE_TABLE_ENTRY *NodeTableLookup(NODE_TABLE *t, UCHAR *key) {
	NODE_TABLE_ENTRY probe;
	if (t == NULL || key == NULL || t->NumEntries == 0)
		return NULL;

	Copy(probe.Key, key, NODE_TABLE_KEY_SIZE);

	return bsearch(&probe, t->Entries, t->NumEntries, sizeof(NODE_TABLE_ENTRY), NodeCompareEntry);
}

// The MAC table key of a MAC address on a VLAN: the VLAN ID (0 when untagged) in two bytes, big-endian, then
// the six bytes of the address
void NodeMacKey(UCHAR *key, UINT vlan_id, UCHAR *mac) {
	if (key == NULL)
		return;

	Zero(key, NODE_TABLE_KEY_SIZE);
	key[0] = (UCHAR)((vlan_id >> 8) & 0x0F);
	key[1] = (UCHAR)(vlan_id & 0xFF);

	if (mac != NULL)
		Copy(key + 2, mac, 6);
}

// A snapshot of the three tables, which it takes over; a NULL table becomes an empty one. It holds no forwarding
// tables of VRFs: NodeSwapTables keeps the ones installed.
NODE_TABLES *NodeNewTables(NODE_TABLE *mac, NODE_TABLE *route, NODE_TABLE *policy) {
	NODE_TABLES *t = ZeroMalloc(sizeof(NODE_TABLES));

	t->Mac = (mac != NULL ? mac : NodeNewTable(NULL, 0));
	t->Route = (route != NULL ? route : NodeNewTable(NULL, 0));
	t->Policy = (policy != NULL ? policy : NodeNewTable(NULL, 0));

	return t;
}

// Free a snapshot and its tables, wiped first as NodeFreeTable does
void NodeFreeTables(NODE_TABLES *t) {
	if (t == NULL)
		return;

	NodeFreeTable(t->Mac);
	NodeFreeTable(t->Route);
	NodeFreeTable(t->Policy);
	NodeFreeVrfTables(t->Vrfs);
	// The routes of the fabric of an EVPN gateway (NodeEvpn.c; SDN-25, #201)
	NodeEvpnFreeTable(t->Evpn);

	Zero(t, sizeof(NODE_TABLES));
	Free(t);
}

// The current table snapshot of the node. A registered reader may use it until its next quiescent point.
// NULL while the node is stopped.
NODE_TABLES *NodeGetTables(NODE *n) {
	if (n == NULL)
		return NULL;

	return (NODE_TABLES *)ReadPointerAcquire((PVOID const volatile *)&n->Tables);
}

// Register r as a reader of the table snapshot of the node, online from now on, for the calling thread
void NodeReaderRegister(NODE *n, NODE_READER *r) {
	if (n == NULL || r == NULL)
		return;

	r->ThreadId = GetCurrentThreadId();

	Lock(n->TableLock);
	{
		InterlockedExchange64(&r->Seen, ReadAcquire64(&n->Epoch));
		Add(n->ReaderList, r);
	}
	Unlock(n->TableLock);
}

// Remove r from the readers; it holds no snapshot any more
void NodeReaderUnregister(NODE *n, NODE_READER *r) {
	if (n == NULL || r == NULL)
		return;

	// Offline first: a swap that holds the table lock does not wait for r, so the lock below is taken
	NodeReaderOffline(r);

	Lock(n->TableLock);
	{
		Delete(n->ReaderList, r);
	}
	Unlock(n->TableLock);
}

// A quiescent point of r: it holds no snapshot that it read before this call. The release store keeps every
// read of an older snapshot before the epoch that it publishes.
void NodeReaderQuiescent(NODE *n, NODE_READER *r) {
	if (n == NULL || r == NULL)
		return;

	WriteRelease64(&r->Seen, ReadAcquire64(&n->Epoch));
}

// r goes offline, before its thread blocks: it holds no snapshot until NodeReaderOnline
void NodeReaderOffline(NODE_READER *r) {
	if (r == NULL)
		return;

	WriteRelease64(&r->Seen, 0);
}

// r comes back online. The full barrier of the exchange orders the store before the reads of the snapshot
// that follow: a writer that swapped either sees r online and waits for it, or r reads the new snapshot.
void NodeReaderOnline(NODE *n, NODE_READER *r) {
	if (n == NULL || r == NULL)
		return;

	InterlockedExchange64(&r->Seen, ReadAcquire64(&n->Epoch));
}

// Whether the calling thread is an online reader: a swap there would wait for itself
static bool NodeIsReaderThread(NODE *n) {
	UINT id = GetCurrentThreadId();

	for (UINT i = 0; i < LIST_NUM(n->ReaderList); i++) {
		NODE_READER *r = LIST_DATA(n->ReaderList, i);

		if (r->ThreadId == id && ReadAcquire64(&r->Seen) != 0)
			return true;
	}

	return false;
}

// The grace period of a swap to epoch target: wait until every registered reader is offline or has passed a
// quiescent point at target or later. The caller holds the table lock.
static void NodeWaitGracePeriod(NODE *n, LONG64 target) {
	for (UINT i = 0; i < LIST_NUM(n->ReaderList); i++) {
		NODE_READER *r = LIST_DATA(n->ReaderList, i);
		UINT tries = 0;

		while (true) {
			LONG64 seen = ReadAcquire64(&r->Seen);
			if (seen == 0 || seen >= target)
				break;

			if (tries < NODE_GRACE_SPINS)
				YieldProcessor();
			else if (tries < NODE_GRACE_SPINS + NODE_GRACE_YIELDS)
				Sleep(0);
			else
				Sleep(1);

			tries++;
		}
	}
}

// Install the snapshot t (which the node takes over) in place of the current one, which is freed after the
// grace period. The forwarding tables of the VRFs of the current one carry over: NodeSwapVrfs replaces them.
// False, and t stays the caller's, while the node is stopped or when the calling thread is an online reader.
// Never call it with a lock that a reader takes: the data path takes none.
bool NodeSwapTables(NODE *n, NODE_TABLES *t) {
	bool ret = false;
	if (n == NULL || t == NULL)
		return false;

	Lock(n->TableLock);
	{
		if (n->Tables != NULL && NodeIsReaderThread(n) == false) {
			t->Generation = ++n->LastGeneration;
			t->Vrfs = n->Tables->Vrfs;
			t->Evpn = n->Tables->Evpn;

			NODE_TABLES *old = InterlockedExchangePointer((PVOID volatile *)&n->Tables, t);
			WriteRelease64(&n->Generation, (LONG64)t->Generation);

			NodeWaitGracePeriod(n, InterlockedIncrement64(&n->Epoch));

			old->Vrfs = NULL;
			old->Evpn = NULL;
			NodeFreeTables(old);
			ret = true;
		}
	}
	Unlock(n->TableLock);

	return ret;
}

// Install the forwarding tables v of the VRFs (NodeVrf.c), which the node takes over, in a new snapshot that keeps
// the MAC, route and policy tables of the current one; the forwarding tables before are freed after the grace
// period, so a reader sees either them or v, and none of them half-built. v may be NULL: no forwarding tables. False,
// and v stays the caller's, while the node is stopped or when the calling thread is an online reader. Never call it
// with a lock that a reader takes.
bool NodeSwapVrfs(NODE *n, NODE_VRF_TABLES *v) {
	bool ret = false;
	if (n == NULL)
		return false;

	Lock(n->TableLock);
	{
		NODE_TABLES *old = n->Tables;

		if (old != NULL && NodeIsReaderThread(n) == false) {
			NODE_TABLES *t = ZeroMalloc(sizeof(NODE_TABLES));

			t->Generation = ++n->LastGeneration;
			t->Mac = old->Mac;
			t->Route = old->Route;
			t->Policy = old->Policy;
			t->Vrfs = v;
			// The routes of the fabric of an EVPN gateway carry over (NodeEvpn.c; SDN-25, #201)
			t->Evpn = old->Evpn;

			InterlockedExchangePointer((PVOID volatile *)&n->Tables, t);
			WriteRelease64(&n->Generation, (LONG64)t->Generation);

			NodeWaitGracePeriod(n, InterlockedIncrement64(&n->Epoch));

			// The new snapshot holds the MAC, route and policy tables now; the old forwarding tables go with the old one
			old->Mac = NULL;
			old->Route = NULL;
			old->Policy = NULL;
			old->Evpn = NULL;
			NodeFreeTables(old);
			ret = true;
		}
	}
	Unlock(n->TableLock);

	return ret;
}

// Install the IP prefix routes e of the fabric of an EVPN gateway (NodeEvpn.c; SDN-25, #201), which the node takes over, in a
// new snapshot that keeps the other tables of the current one, as NodeSwapVrfs does for the forwarding tables of the VRFs: the
// routes before are freed after the grace period, so a reader sees either them or e. e may be NULL: no routes. False, and e
// stays the caller's, while the node is stopped or when the calling thread is an online reader. Never call it with a lock that
// a reader takes.
bool NodeSwapEvpn(NODE *n, NODE_EVPN_TABLE *e) {
	bool ret = false;
	if (n == NULL)
		return false;

	Lock(n->TableLock);
	{
		NODE_TABLES *old = n->Tables;

		if (old != NULL && NodeIsReaderThread(n) == false) {
			NODE_TABLES *t = ZeroMalloc(sizeof(NODE_TABLES));

			t->Generation = ++n->LastGeneration;
			t->Mac = old->Mac;
			t->Route = old->Route;
			t->Policy = old->Policy;
			t->Vrfs = old->Vrfs;
			t->Evpn = e;

			InterlockedExchangePointer((PVOID volatile *)&n->Tables, t);
			WriteRelease64(&n->Generation, (LONG64)t->Generation);

			NodeWaitGracePeriod(n, InterlockedIncrement64(&n->Epoch));

			// The new snapshot holds the other tables now; the routes before go with the old one
			old->Mac = NULL;
			old->Route = NULL;
			old->Policy = NULL;
			old->Vrfs = NULL;
			NodeFreeTables(old);
			ret = true;
		}
	}
	Unlock(n->TableLock);

	return ret;
}

// The first snapshot of a start: empty tables, before any reader runs
void NodeTablesStart(NODE *n) {
	NODE_TABLES *t = NodeNewTables(NULL, NULL, NULL);

	Lock(n->TableLock);
	{
		t->Generation = ++n->LastGeneration;

		InterlockedExchangePointer((PVOID volatile *)&n->Tables, t);
		WriteRelease64(&n->Generation, (LONG64)t->Generation);
	}
	Unlock(n->TableLock);
}

// Take the snapshot away at a stop and free it after a grace period for the readers still registered
void NodeTablesStop(NODE *n) {
	Lock(n->TableLock);
	{
		NODE_TABLES *t = InterlockedExchangePointer((PVOID volatile *)&n->Tables, NULL);
		WriteRelease64(&n->Generation, 0);

		NodeWaitGracePeriod(n, InterlockedIncrement64(&n->Epoch));

		NodeFreeTables(t);
	}
	Unlock(n->TableLock);
}
