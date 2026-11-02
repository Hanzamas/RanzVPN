// NodeVrf.c
// The forwarding tables of the VRFs of a node (SDN-4, #180; ADR-0025 decision 2): one immutable longest-prefix-match
// table per VRF, DIR-24-8 for IPv4 and a multibit trie of 8-bit strides for IPv6, in the style of DPDK's rte_lpm. The
// tables of one Generation of the desired state are built off the data path from their routes, beside the live ones,
// and installed together by NodeSwapVrfs (NodeTable.c), so a lookup sees the tables of the Generation before or those
// of the new one, never a half-built table, and two VRFs may use the same range. Readers take no lock: they read the
// tables as readers of the table snapshot, between two quiescent points.
//
// An entry of a table is 32 bits: NODE_VRF_VALID and the next hop of a route, NODE_VRF_GROUP and the index of the
// block of NODE_VRF_BLOCK entries below it (a tbl8 group of DIR-24-8, a node of the trie), or 0 for no route. The
// routes go in by ascending prefix length, so a longer prefix overwrites the entries of a shorter one, which makes a
// lookup the longest-prefix match without a depth in the entries; a new block takes the entry that it replaces into
// each of its entries. The /0 route of each family stands apart and answers for an address that no entry holds, so
// tbl24, 64 MiB of address space that VirtualAlloc gives as zero pages, takes memory only for the pages that are used.

#include "Node.h"
#include "NodeEgress.h"
#include "NodeExit.h"
#include "NodeGateway.h"
#include "NodeLink.h"
#include "NodeProfile.h"
#include "NodeSourceGroup.h"

#include "Mayaqua/Memory.h"

#include <stdlib.h>
#include <string.h>

#define NODE_VRF_VALID      0x80000000 // The entry holds the next hop of a route in NODE_VRF_VALUE
#define NODE_VRF_GROUP      0x40000000 // The entry holds the index of the block below it in NODE_VRF_VALUE
#define NODE_VRF_VALUE      0x3FFFFFFF // The next hop or the block of an entry
#define NODE_VRF_BLOCK      256        // Entries of a block: a tbl8 group, a node of the trie
#define NODE_VRF_TBL24      0x1000000  // Entries of tbl24, one per /24
#define NODE_VRF_MAX_BLOCKS 0x100000   // Blocks of one family of a table at most

// The forwarding table of one VRF
struct NODE_VRF_TABLE {
	UINT VrfId;     // The VRF
	UINT Default4;  // The entry of the IPv4 /0 route, 0 for none: it answers for an address that no entry holds
	UINT *Tbl24;    // NODE_VRF_TBL24 entries, one per /24; NULL without an IPv4 route longer than /0
	UINT NumTbl8;   // The tbl8 groups, one entry per address of their /24 ...
	UINT *Tbl8;     // ... in one array
	UINT Default6;  // The entry of the IPv6 /0 route, 0 for none
	UINT NumNodes6; // The nodes of the IPv6 trie, the root first, one entry per value of the byte of their level ...
	UINT *Nodes6;   // ... in one array; NULL without an IPv6 route longer than /0
};

// Order routes by VRF, family and prefix length, the order in which a table takes them; then by prefix and next hop,
// so that of two routes of one prefix the one with the greater next hop goes in last and wins
static int NodeCompareRoute(const void *p1, const void *p2) {
	const NODE_VRF_ROUTE *r1 = (const NODE_VRF_ROUTE *)p1;
	const NODE_VRF_ROUTE *r2 = (const NODE_VRF_ROUTE *)p2;

	if (r1->VrfId != r2->VrfId)
		return (r1->VrfId < r2->VrfId ? -1 : 1);
	if (r1->AddressSize != r2->AddressSize)
		return (r1->AddressSize < r2->AddressSize ? -1 : 1);
	if (r1->Length != r2->Length)
		return (r1->Length < r2->Length ? -1 : 1);

	int c = memcmp(r1->Address, r2->Address, r1->AddressSize);
	if (c != 0)
		return c;

	if (r1->NextHop == r2->NextHop)
		return 0;

	return (r1->NextHop < r2->NextHop ? -1 : 1);
}

// Clear the host bits of the prefix of r, and the bytes past its address
static void NodeVrfMask(NODE_VRF_ROUTE *r) {
	for (UINT i = 0; i < sizeof(r->Address); i++) {
		UINT bits = (r->Length > i * 8 ? r->Length - i * 8 : 0);

		if (i >= r->AddressSize)
			r->Address[i] = 0;
		else if (bits < 8)
			r->Address[i] &= (UCHAR)(0xFF00 >> bits);
	}
}

// Append a block of NODE_VRF_BLOCK entries, each of them fill, to the blocks of one family of a table (num in use,
// allocated of room): its index, or INFINITE past NODE_VRF_MAX_BLOCKS
static UINT NodeVrfNewBlock(UINT **blocks, UINT *num, UINT *allocated, UINT fill) {
	if (*num >= NODE_VRF_MAX_BLOCKS)
		return INFINITE;

	if (*num == *allocated) {
		*allocated = MIN(MAX(*allocated * 2, 16), NODE_VRF_MAX_BLOCKS);

		UINT size = sizeof(UINT) * NODE_VRF_BLOCK * *allocated;
		*blocks = (*blocks == NULL ? Malloc(size) : ReAlloc(*blocks, size));
	}

	UINT *b = *blocks + *num * NODE_VRF_BLOCK;
	for (UINT i = 0; i < NODE_VRF_BLOCK; i++)
		b[i] = fill;

	return (*num)++;
}

// Put an IPv4 route, its prefix masked, into the DIR-24-8 table of t: false when tbl24 cannot be had or the tbl8
// groups run out
static bool NodeVrfAdd4(NODE_VRF_TABLE *t, const NODE_VRF_ROUTE *r, UINT *max_tbl8) {
	UINT entry = NODE_VRF_VALID | r->NextHop;
	UINT addr = READ_UINT(r->Address);

	if (r->Length == 0) {
		t->Default4 = entry;
		return true;
	}

	if (t->Tbl24 == NULL) {
		t->Tbl24 = VirtualAlloc(NULL, sizeof(UINT) * NODE_VRF_TBL24, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
		if (t->Tbl24 == NULL)
			return false;
	}

	// A prefix of /24 or shorter fills its /24s in tbl24
	if (r->Length <= 24) {
		UINT first = addr >> 8;
		UINT num = 1U << (24 - r->Length);

		for (UINT i = 0; i < num; i++)
			t->Tbl24[first + i] = entry;

		return true;
	}

	// A longer one fills its addresses in the tbl8 group of its /24, which takes the entry of the /24 first
	UINT *e = &t->Tbl24[addr >> 8];
	if ((*e & NODE_VRF_GROUP) == 0) {
		UINT group = NodeVrfNewBlock(&t->Tbl8, &t->NumTbl8, max_tbl8, *e);
		if (group == INFINITE)
			return false;

		*e = NODE_VRF_GROUP | group;
	}

	UINT *entries = t->Tbl8 + (*e & NODE_VRF_VALUE) * NODE_VRF_BLOCK;
	UINT first = addr & 0xFF;
	UINT num = 1U << (32 - r->Length);

	for (UINT i = 0; i < num; i++)
		entries[first + i] = entry;

	return true;
}

// Put an IPv6 route, its prefix masked, into the trie of t: false when the nodes run out
static bool NodeVrfAdd6(NODE_VRF_TABLE *t, const NODE_VRF_ROUTE *r, UINT *max_nodes6) {
	UINT entry = NODE_VRF_VALID | r->NextHop;
	UINT node = 0;

	if (r->Length == 0) {
		t->Default6 = entry;
		return true;
	}

	if (t->Nodes6 == NULL && NodeVrfNewBlock(&t->Nodes6, &t->NumNodes6, max_nodes6, 0) == INFINITE)
		return false;

	// Down the levels that the prefix passes, one byte each; a new node takes the entry that it replaces
	for (UINT level = 0; r->Length > (level + 1) * 8; level++) {
		UINT index = node * NODE_VRF_BLOCK + r->Address[level];

		if ((t->Nodes6[index] & NODE_VRF_GROUP) == 0) {
			UINT child = NodeVrfNewBlock(&t->Nodes6, &t->NumNodes6, max_nodes6, t->Nodes6[index]);
			if (child == INFINITE)
				return false;

			t->Nodes6[index] = NODE_VRF_GROUP | child;
		}

		node = t->Nodes6[index] & NODE_VRF_VALUE;
	}

	// The level that the prefix ends in: the entries of the values of its last byte
	UINT last = (r->Length - 1) / 8;
	UINT first = r->Address[last];
	UINT num = 1U << (8 - (r->Length - last * 8));

	for (UINT i = 0; i < num; i++)
		t->Nodes6[node * NODE_VRF_BLOCK + first + i] = entry;

	return true;
}

// Free the table of one VRF. tbl24 goes back to the system, so a reader that kept it past its quiescent point faults
// instead of reading it; the other entries are wiped first, as NodeFreeTable does.
static void NodeFreeVrfTable(NODE_VRF_TABLE *t) {
	if (t == NULL)
		return;

	if (t->Tbl24 != NULL)
		VirtualFree(t->Tbl24, 0, MEM_RELEASE);

	Zero(t->Tbl8, sizeof(UINT) * NODE_VRF_BLOCK * t->NumTbl8);
	Free(t->Tbl8);
	Zero(t->Nodes6, sizeof(UINT) * NODE_VRF_BLOCK * t->NumNodes6);
	Free(t->Nodes6);

	Zero(t, sizeof(NODE_VRF_TABLE));
	Free(t);
}

// The table of one VRF from its num routes (at least one), sorted by NodeCompareRoute and masked; NULL when its
// memory cannot be had
static NODE_VRF_TABLE *NodeNewVrfTable(const NODE_VRF_ROUTE *routes, UINT num) {
	NODE_VRF_TABLE *t = ZeroMalloc(sizeof(NODE_VRF_TABLE));
	UINT max_tbl8 = 0, max_nodes6 = 0;
	bool ok = true;

	t->VrfId = routes[0].VrfId;

	for (UINT i = 0; i < num && ok; i++)
		ok = (routes[i].AddressSize == 4 ? NodeVrfAdd4(t, &routes[i], &max_tbl8) : NodeVrfAdd6(t, &routes[i], &max_nodes6));

	if (ok == false) {
		NodeFreeVrfTable(t);
		return NULL;
	}

	return t;
}

// The forwarding tables of the VRFs of one Generation: one table for each VRF that the num routes name, in any order,
// and a copy of the num_hops next hops that their NextHop indexes (the objects stay the caller's). The host bits of a
// prefix are ignored. NULL for a route that is not valid (an address size other than 4 or 16, a prefix longer than
// its address, a next hop that is neither an index of hops nor NODE_VRF_LOCAL), for more than NODE_VRF_MAX_ROUTES
// routes or NODE_VRF_MAX_HOPS next hops, or when the memory of a table cannot be had.
NODE_VRF_TABLES *NodeNewVrfTables(UINT64 generation, const NODE_VRF_ROUTE *routes, UINT num, void **hops, UINT num_hops) {
	if ((routes == NULL && num != 0) || (hops == NULL && num_hops != 0) || num > NODE_VRF_MAX_ROUTES || num_hops > NODE_VRF_MAX_HOPS)
		return NULL;

	for (UINT i = 0; i < num; i++) {
		const NODE_VRF_ROUTE *r = &routes[i];

		if ((r->AddressSize != 4 && r->AddressSize != 16) || r->Length > r->AddressSize * 8 || (r->NextHop >= num_hops && r->NextHop != NODE_VRF_LOCAL))
			return NULL;
	}

	NODE_VRF_ROUTE *sorted = ZeroMalloc(sizeof(NODE_VRF_ROUTE) * MAX(num, 1));
	UINT num_vrfs = 0;

	for (UINT i = 0; i < num; i++) {
		Copy(&sorted[i], &routes[i], sizeof(NODE_VRF_ROUTE));
		NodeVrfMask(&sorted[i]);
	}
	if (num != 0)
		qsort(sorted, num, sizeof(NODE_VRF_ROUTE), NodeCompareRoute);

	for (UINT i = 0; i < num; i++)
		if (i == 0 || sorted[i].VrfId != sorted[i - 1].VrfId)
			num_vrfs++;

	NODE_VRF_TABLES *v = ZeroMalloc(sizeof(NODE_VRF_TABLES));
	v->Generation = generation;
	v->Vrfs = ZeroMalloc(sizeof(NODE_VRF_TABLE *) * MAX(num_vrfs, 1));
	v->NumHops = num_hops;
	v->Hops = ZeroMalloc(sizeof(void *) * MAX(num_hops, 1));
	if (num_hops != 0)
		Copy(v->Hops, hops, sizeof(void *) * num_hops);

	// One table per run of routes of one VRF, in VRF order
	bool ok = true;
	for (UINT start = 0; start < num && ok;) {
		UINT end = start + 1;

		while (end < num && sorted[end].VrfId == sorted[start].VrfId)
			end++;

		NODE_VRF_TABLE *t = NodeNewVrfTable(sorted + start, end - start);
		if (t != NULL)
			v->Vrfs[v->NumVrfs++] = t;
		else
			ok = false;

		start = end;
	}

	Free(sorted);

	if (ok == false) {
		NodeFreeVrfTables(v);
		return NULL;
	}

	return v;
}

// Free the tables of the VRFs, their shaping table, the 1:1 NAT rules and the Mirrors installed with them and the VRFs
// of their next hops, wiped first as NodeFreeTable does; the objects of the next hops stay the caller's
void NodeFreeVrfTables(NODE_VRF_TABLES *v) {
	if (v == NULL)
		return;

	NodeFreeMirrorTable(v->Mirror);
	// The links of kind vxlan and geneve (NodeLink.c; SDN-76, #356)
	NodeFreeLinkTable(v->Link);
	// The groups of gateways and the hubs (NodeGateway.c; SDN-19, #195)
	NodeFreeGatewayTable(v->Gateway);
	// The source groups (NodeSourceGroup.c; SDN-87, #386)
	NodeFreeSourceGroupTable(v->SourceGroups);
	// The VRFs whose internet exit the node is (NodeEgress.c; SDN-12, #188)
	NodeFreeEgressTable(v->Egress);
	for (UINT i = 0; i < v->NumVrfs; i++)
		NodeFreeVrfTable(v->Vrfs[i]);
	NodeShapeFreeTable(v->Shape);
	NodePolicyFreeTable(v->Policy);
	// The session profiles (NodeProfile.c; SDN-40, #233)
	NodeProfileFreeTable(v->Profile);
	// The exit nodes (NodeExit.c; SDN-55, #248)
	NodeExitFreeTable(v->Exit);

	NodeFreeNat(v->Nat);
	Free(v->HopVrfs);
	Zero(v->Hops, sizeof(void *) * v->NumHops);
	Free(v->Hops);
	Free(v->Vrfs);

	Zero(v, sizeof(NODE_VRF_TABLES));
	Free(v);
}

// The table of the VRF vrf_id, NULL when the tables have none
NODE_VRF_TABLE *NodeGetVrfTable(NODE_VRF_TABLES *v, UINT vrf_id) {
	if (v == NULL)
		return NULL;

	UINT low = 0, high = v->NumVrfs;
	while (low < high) {
		UINT mid = low + (high - low) / 2;
		NODE_VRF_TABLE *t = v->Vrfs[mid];

		if (t->VrfId == vrf_id)
			return t;

		if (t->VrfId < vrf_id)
			low = mid + 1;
		else
			high = mid;
	}

	return NULL;
}

// The next hop of the address addr (size bytes: 4 for IPv4, 16 for IPv6, in network byte order) in the table t of a
// VRF: an index of the next hops of its tables, NODE_VRF_LOCAL for an address of the node itself, or NODE_VRF_NONE
// when no route holds it. At most two reads for IPv4 and one per byte of the address for IPv6.
UINT NodeVrfLookup(NODE_VRF_TABLE *t, const UCHAR *addr, UINT size) {
	UINT e = 0;
	if (t == NULL || addr == NULL)
		return NODE_VRF_NONE;

	if (size == 4) {
		UINT a = READ_UINT(addr);

		if (t->Tbl24 != NULL) {
			e = t->Tbl24[a >> 8];
			if ((e & NODE_VRF_GROUP) != 0)
				e = t->Tbl8[(e & NODE_VRF_VALUE) * NODE_VRF_BLOCK + (a & 0xFF)];
		}
		if ((e & NODE_VRF_VALID) == 0)
			e = t->Default4;
	} else if (size == 16) {
		if (t->Nodes6 != NULL) {
			UINT node = 0;

			for (UINT i = 0; i < 16; i++) {
				e = t->Nodes6[node * NODE_VRF_BLOCK + addr[i]];
				if ((e & NODE_VRF_GROUP) == 0)
					break;

				node = e & NODE_VRF_VALUE;
			}
		}
		if ((e & NODE_VRF_VALID) == 0)
			e = t->Default6;
	}

	return ((e & NODE_VRF_VALID) != 0 ? (e & NODE_VRF_VALUE) : NODE_VRF_NONE);
}

// Whether the /0 route of its family alone holds the address addr (size bytes, as NodeVrfLookup takes it) in the table t
// of a VRF: the table has that route, and no longer prefix holds the address. The internet exit of a VRF takes what its
// default route leads to the host, and nothing that another route of the VRF holds (NodeEgress.c; SDN-12, #188).
bool NodeVrfDefault(NODE_VRF_TABLE *t, const UCHAR *addr, UINT size) {
	UINT e = 0;
	if (t == NULL || addr == NULL)
		return false;

	if (size == 4) {
		UINT a = READ_UINT(addr);

		if (t->Tbl24 != NULL) {
			e = t->Tbl24[a >> 8];
			if ((e & NODE_VRF_GROUP) != 0)
				e = t->Tbl8[(e & NODE_VRF_VALUE) * NODE_VRF_BLOCK + (a & 0xFF)];
		}

		return ((e & NODE_VRF_VALID) == 0 && (t->Default4 & NODE_VRF_VALID) != 0);
	}

	if (size == 16) {
		if (t->Nodes6 != NULL) {
			UINT node = 0;

			for (UINT i = 0; i < 16; i++) {
				e = t->Nodes6[node * NODE_VRF_BLOCK + addr[i]];
				if ((e & NODE_VRF_GROUP) == 0)
					break;

				node = e & NODE_VRF_VALUE;
			}
		}

		return ((e & NODE_VRF_VALID) == 0 && (t->Default6 & NODE_VRF_VALID) != 0);
	}

	return false;
}
