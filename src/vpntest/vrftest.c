// vrftest.c
// Named VRF forwarding table test of vpntest ("vrf" command, SDN-4 #180)
//
// The forwarding tables of the VRFs of a node (Cedar/NodeVrf.c, NodeTable.c) and the overlay that forwards on them
// (NodeOverlay.c), in process, as seam 2 of #45 runs the data plane: fake adapters stand in for the hosts of the
// nodes, the in-process loopback transport carries the Noise sessions between them, and the test applies the desired
// states itself (NodeOverlayApply).
// - Edges: no route, the /0 routes, a prefix with host bits, two routes of one prefix, a family without routes, and
//   routes that are not valid.
// - Reference: random route sets of three VRFs, IPv4 prefixes of every length from /0 to /32 and IPv6 ones from /0 to
//   /128 nested around a few addresses, their host bits random, built into the tables of one Generation (DIR-24-8 and
//   the trie). Every lookup, of random addresses and of the first and the last address of every prefix, gives the
//   next hop that a linear scan of the routes of that VRF finds: the longest prefix that holds the address, and of two
//   routes of one prefix the one with the greater next hop.
// - Swap: readers on every worker of a node look probes of two VRFs up while the main thread swaps in the tables of
//   Generation after Generation, each with other routes around the probes and its next hops in another order: no
//   lookup misses, finds a wrong next hop or the tables of an older Generation.
// - Isolation: VRFs red and blue both use 10.0.0.0/24 and fd00::/64, with the same address on different nodes.
//   node-a, node-b and node-c send packets in each VRF, and node-x, a peer that the test plays itself on a session of
//   its own to node-a, sends records tagged with the VRF it shares with node-a, with one it does not share, with a VRF
//   of no node, with a source that is not its own and with a destination of another node. Where each packet arrives
//   (at the host of which node, in which VRF) or which node drops it, and the counters of each node, match the golden
//   file tests/golden/vrf/vrf_isolation.txt (golden family "vrf"): no packet crosses from one VRF into the other.
// - Stream: node-a sends a stream of packets in both VRFs to node-b while both apply Generation after Generation, with
//   a peer that comes and goes and moves the next hops of the others: every packet arrives at node-b once, in its VRF,
//   none arrives anywhere else, and none is refused.
// Print "VRF TEST OK" only when every check passes.

#include "golden.h"
#include "testlist.h"

#include "Cedar/ConfigStore.h"
#include "Cedar/Node.h"

#include "Mayaqua/Encrypt.h"
#include "Mayaqua/FileIO.h"
#include "Mayaqua/Internat.h"
#include "Mayaqua/IpAddr.h"
#include "Mayaqua/Kernel.h"
#include "Mayaqua/Memory.h"
#include "Mayaqua/Microsoft.h"
#include "Mayaqua/Network.h"
#include "Mayaqua/Str.h"
#include "Mayaqua/TcpIp.h"
#include "Mayaqua/Tick64.h"

#include "Core/Control.h"
#include "Core/Transport.h"

#include <stdio.h>

#define	VRFTEST_BUDGET			300000		// The whole test ends within this time, or the watchdog ends the process (ms)
#define	VRFTEST_BOUND			10000		// A bounded wait on observable state (ms)
#define	VRFTEST_POLL			10			// Poll interval of observable state (ms)
#define	VRFTEST_ROUNDS			3			// Rounds of the reference case, one seed each
#define	VRFTEST_REF_VRFS		3			// VRFs of a round
#define	VRFTEST_REF_ROUTES		500			// Routes of each family in each VRF of a round
#define	VRFTEST_REF_LOOKUPS		5000		// Random lookups of each family in each VRF of a round
#define	VRFTEST_REF_HOPS		40			// Next hops of a round
#define	VRFTEST_ANCHORS			6			// Addresses that the routes of one family nest around
#define	VRFTEST_SHOW			5			// Mismatches of a round that the test prints at most
#define	VRFTEST_SWAP_TIME		1000		// The swaps of the table case run this long (ms) ...
#define	VRFTEST_SWAP_MAX		5000		// ... or this many
#define	VRFTEST_PROBES			32			// Addresses of the table case, each a probe in two VRFs
#define	VRFTEST_SWAP_HOPS		8			// Next hops of the table case
#define	VRFTEST_SWAP_CHURN		24			// Routes of each family and VRF that differ from one Generation to the next
#define	VRFTEST_GENERATIONS		100			// Generations that node-a and node-b each apply while the stream runs
#define	VRFTEST_STREAM_STEP		5			// Packets that the stream sends at least between two Generations
#define	VRFTEST_STREAM_MAX		4000000		// Packets of the stream at most
#define	VRFTEST_PAYLOAD			16			// The data of a test packet after its ICMP header
#define	VRFTEST_NUM_NODES		3			// node-a, node-b and node-c
#define	VRFTEST_GOLDEN			"vrf_isolation.txt"

// The VRFs of the isolation and stream cases; green is a VRF of no node
#define	VRFTEST_RED				0
#define	VRFTEST_BLUE			1
#define	VRFTEST_GREEN			2

static UINT vrftest_vrf_ids[3] = {101, 202, 303};
static char *vrftest_vrf_names[3] = {"red", "blue", "green"};

// The nodes of the isolation case, and node-x, the peer that the test plays itself
#define	VRFTEST_A				0
#define	VRFTEST_B				1
#define	VRFTEST_C				2
#define	VRFTEST_X				3

static char *vrftest_names[4] = {"node-a", "node-b", "node-c", "node-x"};

// One address of a node in the isolation case
typedef struct VRFTEST_ADDR
{
	UINT Node;							// VRFTEST_A to VRFTEST_X
	UINT Vrf;							// VRFTEST_RED or VRFTEST_BLUE
	char *Address;
} VRFTEST_ADDR;

// red and blue both use 10.0.0.0/24 and fd00::/64: 10.0.0.2 is node-b in red and node-c in blue, fd00::2 the same
static VRFTEST_ADDR vrftest_addrs[] =
{
	{VRFTEST_A, VRFTEST_RED, "10.0.0.1"},
	{VRFTEST_A, VRFTEST_RED, "fd00::1"},
	{VRFTEST_A, VRFTEST_BLUE, "10.0.0.1"},
	{VRFTEST_A, VRFTEST_BLUE, "fd00::1"},
	{VRFTEST_B, VRFTEST_RED, "10.0.0.2"},
	{VRFTEST_B, VRFTEST_RED, "fd00::2"},
	{VRFTEST_B, VRFTEST_BLUE, "10.0.0.3"},
	{VRFTEST_C, VRFTEST_BLUE, "10.0.0.2"},
	{VRFTEST_C, VRFTEST_BLUE, "fd00::2"},
	{VRFTEST_X, VRFTEST_BLUE, "10.0.0.5"},
};

// One packet of the isolation case: the VRF it is sent in, the node that sends it, its source and destination, and for
// node-x the bytes of its record that go, 0 for all of them
typedef struct VRFTEST_SEND
{
	UINT Vrf;
	UINT From;
	char *Src;
	char *Dst;
	UINT Cut;
} VRFTEST_SEND;

static VRFTEST_SEND vrftest_sends[] =
{
	// The same destination in two VRFs reaches two nodes; an address of the other VRF reaches none
	{VRFTEST_RED, VRFTEST_A, "10.0.0.1", "10.0.0.2"},
	{VRFTEST_BLUE, VRFTEST_A, "10.0.0.1", "10.0.0.2"},
	{VRFTEST_RED, VRFTEST_A, "10.0.0.1", "10.0.0.3"},
	{VRFTEST_BLUE, VRFTEST_A, "10.0.0.1", "10.0.0.3"},
	// The one session between node-a and node-b carries both VRFs: the tag decides where a packet arrives
	{VRFTEST_RED, VRFTEST_B, "10.0.0.2", "10.0.0.1"},
	{VRFTEST_BLUE, VRFTEST_B, "10.0.0.3", "10.0.0.1"},
	{VRFTEST_BLUE, VRFTEST_B, "10.0.0.3", "10.0.0.2"},
	{VRFTEST_BLUE, VRFTEST_C, "10.0.0.2", "10.0.0.1"},
	{VRFTEST_RED, VRFTEST_C, "10.0.0.2", "10.0.0.1"},
	{VRFTEST_BLUE, VRFTEST_C, "10.0.0.2", "10.0.0.3"},
	// No route, and sources that are not addresses of the sender in the VRF
	{VRFTEST_RED, VRFTEST_B, "10.0.0.2", "10.0.0.4"},
	{VRFTEST_RED, VRFTEST_A, "10.0.0.9", "10.0.0.2"},
	{VRFTEST_BLUE, VRFTEST_B, "10.0.0.2", "10.0.0.1"},
	// IPv6, through the trie
	{VRFTEST_RED, VRFTEST_A, "fd00::1", "fd00::2"},
	{VRFTEST_BLUE, VRFTEST_A, "fd00::1", "fd00::2"},
	{VRFTEST_RED, VRFTEST_B, "fd00::2", "fd00::1"},
	{VRFTEST_BLUE, VRFTEST_C, "fd00::2", "fd00::1"},
	{VRFTEST_BLUE, VRFTEST_C, "fd00::2", "fd00::3"},
	// Records of node-x to node-a: the VRF they share, one they do not share, a source of node-c, a VRF of no node,
	// and a destination of node-b
	{VRFTEST_BLUE, VRFTEST_X, "10.0.0.5", "10.0.0.1"},
	{VRFTEST_RED, VRFTEST_X, "10.0.0.5", "10.0.0.1"},
	{VRFTEST_BLUE, VRFTEST_X, "10.0.0.2", "10.0.0.1"},
	{VRFTEST_GREEN, VRFTEST_X, "10.0.0.5", "10.0.0.1"},
	{VRFTEST_BLUE, VRFTEST_X, "10.0.0.5", "10.0.0.3"},
	// Records of node-x cut short: half of the VRF id, and the VRF id with half an IPv4 header
	{VRFTEST_BLUE, VRFTEST_X, "10.0.0.5", "10.0.0.1", 2},
	{VRFTEST_BLUE, VRFTEST_X, "10.0.0.5", "10.0.0.1", 14},
};

// One route of the edge case: its VRF, prefix, length and next hop
typedef struct VRFTEST_EDGE_ROUTE
{
	UINT VrfId;
	char *Prefix;
	UINT Length;
	UINT NextHop;
} VRFTEST_EDGE_ROUTE;

static VRFTEST_EDGE_ROUTE vrftest_edge_routes[] =
{
	{9, "0.0.0.0", 0, 0},
	{9, "10.0.0.0", 8, 1},
	{9, "10.1.2.3", 16, 2},				// Host bits: it is 10.1.0.0/16
	{9, "10.1.2.0", 24, 3},
	{9, "10.1.2.128", 25, 4},
	{9, "10.1.2.200", 32, NODE_VRF_LOCAL},
	{9, "10.1.2.200", 32, 5},			// The same prefix again: NODE_VRF_LOCAL, the greater next hop, wins
	{9, "::", 0, 6},
	{9, "fd00::", 8, 7},
	{9, "fd00::1", 128, NODE_VRF_LOCAL},
	{10, "fd00::", 16, 0},				// A VRF without IPv4 routes
};

// One lookup of the edge case and the next hop it must give
typedef struct VRFTEST_EDGE_LOOKUP
{
	UINT VrfId;
	char *Address;
	UINT NextHop;
} VRFTEST_EDGE_LOOKUP;

static VRFTEST_EDGE_LOOKUP vrftest_edge_lookups[] =
{
	{9, "192.0.2.1", 0},
	{9, "10.200.0.1", 1},
	{9, "10.1.200.1", 2},
	{9, "10.1.2.1", 3},
	{9, "10.1.2.129", 4},
	{9, "10.1.2.200", NODE_VRF_LOCAL},
	{9, "10.1.2.255", 4},
	{9, "2001:db8::1", 6},
	{9, "fd00::2", 7},
	{9, "fd00::1", NODE_VRF_LOCAL},
	{10, "10.0.0.1", NODE_VRF_NONE},
	{10, "fd00::1", 0},
	{10, "fe80::1", NODE_VRF_NONE},
	{11, "10.0.0.1", NODE_VRF_NONE},
};

// The objects that the next hops of the reference and table cases lead to: their addresses
static UCHAR vrftest_objects[VRFTEST_REF_HOPS];

// The checks of the test
typedef struct VRFTEST_CTX
{
	UINT NumChecks;
	UINT NumFailed;
} VRFTEST_CTX;

// A packet that the fake adapter of a host took
typedef struct VRFTEST_PACKET
{
	UINT VrfId;
	UINT Size;
	UCHAR Data[128];
} VRFTEST_PACKET;

// One node of the overlay cases and the fake adapter of its host
typedef struct VRFTEST_NODE
{
	char *Name;
	wchar_t Dir[MAX_PATH];				// Its data directory
	PEER_KEY Key;						// Its static key
	NODE *Node;
	NODE_READER Reader;					// The test thread as a reader of the node's forwarding tables, online while it sends
	SRWLOCK Lock;						// Packets
	LIST *Packets;						// What the adapter took (VRFTEST_PACKET), while the stream does not run
	volatile LONG Stream;				// The stream runs: the adapter counts its packets instead
	volatile LONG Arrivals;				// Packets of the stream that the host took in their VRF
	volatile LONG Wrong;				// Packets that the host took while the stream ran and that are not of the stream, or in the wrong VRF
	UCHAR *Seen;						// How often each packet of the stream arrived (node-b)
} VRFTEST_NODE;

// The stream of the stream case: node-a sends in red and blue to node-b
typedef struct VRFTEST_STREAM
{
	VRFTEST_NODE *From;
	volatile LONG Stop;					// Ends the sender
	volatile LONG Sent;					// Packets that the overlay took
	volatile LONG Refused;				// Packets that it did not take
} VRFTEST_STREAM;

// The state of the readers of the table case
typedef struct VRFTEST_SWAP
{
	volatile LONG Stop;					// Ends the reader items
	volatile LONG Done;					// Reader items that ended
} VRFTEST_SWAP;

static VRFTEST_SWAP vrftest_swap;

// What the reader item of one worker saw
typedef struct VRFTEST_READER
{
	UINT64 Passes;						// Passes over the probes
	UINT64 Lost;						// Probes that found no next hop
	UINT64 Wrong;						// Probes that found another next hop than theirs
	UINT64 Backwards;					// Tables older than the ones of the pass before
	UINT64 Distinct;					// Changes of the Generation between two passes
	UINT64 Last;						// The Generation of the last pass
} VRFTEST_READER;

// One probe of the table case: an address in a VRF and the object that it leads to in every Generation
typedef struct VRFTEST_PROBE
{
	UINT VrfId;
	UCHAR Address[16];
	UINT Size;
	UINT Object;
} VRFTEST_PROBE;

static VRFTEST_PROBE vrftest_probes[VRFTEST_PROBES * 2];

static bool VrfTestCheck(VRFTEST_CTX *ctx, bool ok, char *what, char *fmt, ...) RANZ_PRINTF_FORMAT(4, 5);
static bool VrfTestCheck(VRFTEST_CTX *ctx, bool ok, char *what, char *fmt, ...)
{
	char detail[MAX_SIZE * 2];
	va_list args;

	ctx->NumChecks++;

	if (ok)
	{
		Print("  [PASS] %s\n", what);
		return true;
	}

	va_start(args, fmt);
	FormatArgs(detail, sizeof(detail), fmt, args);
	va_end(args);

	Print("  [FAIL] %s: %s\n", what, detail);
	ctx->NumFailed++;

	return false;
}

// The watchdog: a native thread that ends a run that hangs, so that a lost packet is a failed test instead of a hung
// CI step
static DWORD WINAPI VrfTestWatchdog(LPVOID param)
{
	char msg[MAX_SIZE];
	DWORD written = 0;

	if (WaitForSingleObject((HANDLE)param, VRFTEST_BUDGET) != WAIT_TIMEOUT)
	{
		return 0;
	}

	int len = snprintf(msg, sizeof(msg), "VRF TEST FAILED (did not finish within %u ms)\n", VRFTEST_BUDGET);
	if (len > 0)
	{
		WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), msg, (DWORD)MIN((UINT)len, (UINT)sizeof(msg) - 1), &written, NULL);
	}

	TerminateProcess(GetCurrentProcess(), 1);

	return 0;
}

//
// Addresses and routes
//

// A xorshift64* generator, so that a round is the same on every run
static UINT64 VrfTestRand(UINT64 *s)
{
	*s ^= *s >> 12;
	*s ^= *s << 25;
	*s ^= *s >> 27;

	return *s * 0x2545F4914F6CDD1DULL;
}

// The address of a text: 4 bytes for IPv4, 16 for IPv6, and their number; 0 for no address
static UINT VrfTestAddress(UCHAR *addr, char *str)
{
	IP ip;

	Zero(addr, 16);
	if (StrToIP(&ip, str) == false)
	{
		return 0;
	}

	if (IsIP4(&ip))
	{
		Copy(addr, IPV4(ip.address), 4);
		return 4;
	}

	Copy(addr, ip.address, 16);
	return 16;
}

// The text of an address of size bytes
static void VrfTestAddressStr(char *str, UINT str_size, const UCHAR *addr, UINT size)
{
	if (size == 4)
	{
		UINT a;

		Copy(&a, addr, 4);
		IPToStr32(str, str_size, a);
	}
	else
	{
		IP ip;

		SetIP6(&ip, addr);
		IPToStr(str, str_size, &ip);
	}
}

// The text of a next hop
static void VrfTestHopStr(char *str, UINT size, UINT hop)
{
	if (hop == NODE_VRF_LOCAL)
	{
		StrCpy(str, size, "local");
	}
	else if (hop == NODE_VRF_NONE)
	{
		StrCpy(str, size, "none");
	}
	else
	{
		Format(str, size, "%u", hop);
	}
}

// A random prefix length for an address of size bytes: any length, a byte boundary, the full length, or one of the
// longer half
static UINT VrfTestLength(UINT64 *s, UINT size)
{
	UINT bits = size * 8;
	UINT64 r = VrfTestRand(s);

	switch (r % 4)
	{
	case 0:
		return (UINT)((r >> 8) % (bits + 1));
	case 1:
		return (UINT)(((r >> 8) % (size + 1)) * 8);
	case 2:
		return bits;
	default:
		return bits / 2 + (UINT)((r >> 8) % (bits / 2 + 1));
	}
}

// A random address of size bytes near one of the anchors: the bits of the anchor up to a random length, random bits
// after them
static void VrfTestNear(UINT64 *s, UCHAR *addr, UCHAR anchors[VRFTEST_ANCHORS][16], UINT size)
{
	UCHAR *anchor = anchors[VrfTestRand(s) % VRFTEST_ANCHORS];
	UINT keep = (UINT)(VrfTestRand(s) % (size * 8 + 1));

	Zero(addr, 16);
	for (UINT i = 0;i < size;i++)
	{
		UINT bits = (keep > i * 8 ? keep - i * 8 : 0);
		UCHAR mask = (bits >= 8 ? 0xFF : (UCHAR)(0xFF00 >> bits));

		addr[i] = (UCHAR)((anchor[i] & mask) | ((UCHAR)VrfTestRand(s) & (UCHAR)~mask));
	}
}

// The first or the last address of the prefix of a route
static void VrfTestEdgeAddress(const NODE_VRF_ROUTE *r, UCHAR *addr, bool last)
{
	Zero(addr, 16);
	for (UINT i = 0;i < r->AddressSize;i++)
	{
		UINT bits = (r->Length > i * 8 ? r->Length - i * 8 : 0);
		UCHAR mask = (bits >= 8 ? 0xFF : (UCHAR)(0xFF00 >> bits));

		addr[i] = (UCHAR)((r->Address[i] & mask) | (last ? (UCHAR)~mask : 0));
	}
}

// Whether the prefix of route r holds the address addr
static bool VrfTestHolds(const NODE_VRF_ROUTE *r, const UCHAR *addr)
{
	UINT full = r->Length / 8, rest = r->Length % 8;

	if (Cmp(r->Address, addr, full) != 0)
	{
		return false;
	}
	if (rest == 0)
	{
		return true;
	}

	UCHAR mask = (UCHAR)(0xFF00 >> rest);

	return ((r->Address[full] ^ addr[full]) & mask) == 0;
}

// The reference: the next hop that a linear scan of num routes of one VRF and family finds for an address, the
// longest prefix that holds it, and of two routes of one prefix the one with the greater next hop; NODE_VRF_NONE for
// none
static UINT VrfTestReferenceHop(const NODE_VRF_ROUTE *routes, UINT num, const UCHAR *addr)
{
	UINT best = NODE_VRF_NONE, best_length = 0;
	bool found = false;

	for (UINT i = 0;i < num;i++)
	{
		const NODE_VRF_ROUTE *r = &routes[i];

		if (VrfTestHolds(r, addr) == false)
		{
			continue;
		}

		if (found == false || r->Length > best_length || (r->Length == best_length && r->NextHop > best))
		{
			found = true;
			best = r->NextHop;
			best_length = r->Length;
		}
	}

	return best;
}

//
// The edges
//

static void VrfTestEdges(VRFTEST_CTX *ctx)
{
	UINT num = sizeof(vrftest_edge_routes) / sizeof(vrftest_edge_routes[0]);
	NODE_VRF_ROUTE *routes = ZeroMalloc(sizeof(NODE_VRF_ROUTE) * (NODE_VRF_MAX_ROUTES + 1));
	void *hops[8];
	UCHAR addr[16];
	char what[MAX_SIZE];
	char got_str[64], want_str[64];

	for (UINT i = 0;i < 8;i++)
	{
		hops[i] = &vrftest_objects[i];
	}

	// No route: tables without a VRF
	NODE_VRF_TABLES *v = NodeNewVrfTables(1, NULL, 0, NULL, 0);
	Zero(addr, sizeof(addr));
	VrfTestCheck(ctx, v != NULL && v->NumVrfs == 0 && NodeGetVrfTable(v, 9) == NULL && NodeVrfLookup(NULL, addr, 4) == NODE_VRF_NONE,
		"Tables without routes hold no VRF, and a lookup without a table finds no next hop", "tables %p", v);
	NodeFreeVrfTables(v);

	for (UINT i = 0;i < num;i++)
	{
		NODE_VRF_ROUTE *r = &routes[i];
		VRFTEST_EDGE_ROUTE *e = &vrftest_edge_routes[i];

		r->VrfId = e->VrfId;
		r->AddressSize = VrfTestAddress(r->Address, e->Prefix);
		r->Length = e->Length;
		r->NextHop = e->NextHop;
	}

	v = NodeNewVrfTables(2, routes, num, hops, 8);
	if (VrfTestCheck(ctx, v != NULL && v->NumVrfs == 2 && v->Generation == 2 && v->NumHops == 8 && v->Hops[3] == hops[3],
		"The tables of the edge routes hold their two VRFs, their Generation and a copy of the next hops", "tables %p", v))
	{
		UINT bad = 0;

		for (UINT i = 0;i < sizeof(vrftest_edge_lookups) / sizeof(vrftest_edge_lookups[0]);i++)
		{
			VRFTEST_EDGE_LOOKUP *l = &vrftest_edge_lookups[i];
			UINT size = VrfTestAddress(addr, l->Address);
			UINT got = NodeVrfLookup(NodeGetVrfTable(v, l->VrfId), addr, size);

			if (got != l->NextHop)
			{
				VrfTestHopStr(got_str, sizeof(got_str), got);
				VrfTestHopStr(want_str, sizeof(want_str), l->NextHop);
				Print("  [INFO] VRF %u, %s: next hop %s, not %s\n", l->VrfId, l->Address, got_str, want_str);
				bad++;
			}
		}

		VrfTestCheck(ctx, bad == 0, "The /0 routes, a prefix with host bits, two routes of one prefix and a family without routes give the next hops of the longest prefix",
			"%u lookups wrong", bad);

		Zero(addr, sizeof(addr));
		VrfTestCheck(ctx, NodeVrfLookup(NodeGetVrfTable(v, 9), addr, 5) == NODE_VRF_NONE, "A lookup of an address that is neither IPv4 nor IPv6 finds no next hop", "a next hop");
	}
	NodeFreeVrfTables(v);

	// Routes that are not valid: no tables at all
	NODE_VRF_ROUTE saved;
	Copy(&saved, &routes[0], sizeof(saved));

	routes[0].AddressSize = 5;
	NODE_VRF_TABLES *size5 = NodeNewVrfTables(3, routes, num, hops, 8);
	routes[0].AddressSize = 4;
	routes[0].Length = 33;
	NODE_VRF_TABLES *v4_33 = NodeNewVrfTables(3, routes, num, hops, 8);
	Copy(&routes[0], &saved, sizeof(saved));
	routes[7].Length = 129;
	NODE_VRF_TABLES *v6_129 = NodeNewVrfTables(3, routes, num, hops, 8);
	routes[7].Length = 0;
	routes[1].NextHop = 8;
	NODE_VRF_TABLES *far_hop = NodeNewVrfTables(3, routes, num, hops, 8);
	routes[1].NextHop = 1;
	NODE_VRF_TABLES *many = NodeNewVrfTables(3, routes, NODE_VRF_MAX_ROUTES + 1, hops, 8);
	NODE_VRF_TABLES *many_hops = NodeNewVrfTables(3, routes, num, hops, NODE_VRF_MAX_HOPS + 1);

	Format(what, sizeof(what), "Routes that are not valid build no tables: an address of 5 bytes, /33, /129, a next hop past the next hops, %u routes, %u next hops",
		NODE_VRF_MAX_ROUTES + 1, NODE_VRF_MAX_HOPS + 1);
	VrfTestCheck(ctx, size5 == NULL && v4_33 == NULL && v6_129 == NULL && far_hop == NULL && many == NULL && many_hops == NULL, what,
		"%p %p %p %p %p %p", size5, v4_33, v6_129, far_hop, many, many_hops);

	Free(routes);
}

//
// The reference
//

// One lookup of a round: the next hop of the tables against the one of the reference
static bool VrfTestCompare(NODE_VRF_TABLE *t, const NODE_VRF_ROUTE *routes, UINT num, UINT vrf_id, const UCHAR *addr, UINT size, UINT *shown)
{
	UINT got = NodeVrfLookup(t, addr, size);
	UINT want = VrfTestReferenceHop(routes, num, addr);

	if (got == want)
	{
		return true;
	}

	if (*shown < VRFTEST_SHOW)
	{
		char addr_str[64], got_str[64], want_str[64];

		VrfTestAddressStr(addr_str, sizeof(addr_str), addr, size);
		VrfTestHopStr(got_str, sizeof(got_str), got);
		VrfTestHopStr(want_str, sizeof(want_str), want);
		Print("  [INFO] VRF %u, %s: next hop %s, the reference finds %s\n", vrf_id, addr_str, got_str, want_str);
		(*shown)++;
	}

	return false;
}

static void VrfTestReferenceRound(VRFTEST_CTX *ctx, UINT round, UINT64 seed)
{
	UINT num = VRFTEST_REF_VRFS * 2 * VRFTEST_REF_ROUTES;
	NODE_VRF_ROUTE *routes = ZeroMalloc(sizeof(NODE_VRF_ROUTE) * num);
	UCHAR anchors[2][VRFTEST_ANCHORS][16];
	void *hops[VRFTEST_REF_HOPS];
	UINT vrf_ids[VRFTEST_REF_VRFS] = {7, 1000, 0xFFFFFFF0};
	UINT64 s = seed;
	UINT wrong = 0, shown = 0, lookups[2] = {0, 0};
	char what[MAX_SIZE];

	for (UINT i = 0;i < VRFTEST_REF_HOPS;i++)
	{
		hops[i] = &vrftest_objects[i];
	}

	for (UINT f = 0;f < 2;f++)
	{
		for (UINT a = 0;a < VRFTEST_ANCHORS;a++)
		{
			for (UINT i = 0;i < 16;i++)
			{
				anchors[f][a][i] = (UCHAR)VrfTestRand(&s);
			}
		}
	}

	// Routes in blocks of one VRF and one family: IPv4 (f 0) and IPv6 (f 1) of each VRF
	for (UINT v = 0;v < VRFTEST_REF_VRFS;v++)
	{
		for (UINT f = 0;f < 2;f++)
		{
			for (UINT i = 0;i < VRFTEST_REF_ROUTES;i++)
			{
				NODE_VRF_ROUTE *r = &routes[(v * 2 + f) * VRFTEST_REF_ROUTES + i];
				UINT size = (f == 0 ? 4 : 16);

				r->VrfId = vrf_ids[v];
				r->AddressSize = size;
				VrfTestNear(&s, r->Address, anchors[f], size);
				r->Length = VrfTestLength(&s, size);
				r->NextHop = (VrfTestRand(&s) % 8 == 0 ? NODE_VRF_LOCAL : (UINT)(VrfTestRand(&s) % VRFTEST_REF_HOPS));
			}
		}
	}

	NODE_VRF_TABLES *t = NodeNewVrfTables(seed, routes, num, hops, VRFTEST_REF_HOPS);
	Format(what, sizeof(what), "Round %u (seed %I64u): %u random routes build one table per VRF", round, seed, num);
	if (VrfTestCheck(ctx, t != NULL && t->NumVrfs == VRFTEST_REF_VRFS, what, "tables %p", t) == false)
	{
		NodeFreeVrfTables(t);
		Free(routes);
		return;
	}

	for (UINT v = 0;v < VRFTEST_REF_VRFS;v++)
	{
		NODE_VRF_TABLE *vt = NodeGetVrfTable(t, vrf_ids[v]);

		for (UINT f = 0;f < 2;f++)
		{
			const NODE_VRF_ROUTE *block = &routes[(v * 2 + f) * VRFTEST_REF_ROUTES];
			UINT size = (f == 0 ? 4 : 16);
			UCHAR addr[16];

			// Random addresses, most of them near the routes
			for (UINT i = 0;i < VRFTEST_REF_LOOKUPS;i++)
			{
				if (i % 3 == 2)
				{
					Zero(addr, sizeof(addr));
					for (UINT j = 0;j < size;j++)
					{
						addr[j] = (UCHAR)VrfTestRand(&s);
					}
				}
				else
				{
					VrfTestNear(&s, addr, anchors[f], size);
				}

				if (VrfTestCompare(vt, block, VRFTEST_REF_ROUTES, vrf_ids[v], addr, size, &shown) == false)
				{
					wrong++;
				}
				lookups[f]++;
			}

			// The first and the last address of every prefix
			for (UINT i = 0;i < VRFTEST_REF_ROUTES;i++)
			{
				for (UINT last = 0;last < 2;last++)
				{
					VrfTestEdgeAddress(&block[i], addr, last != 0);
					if (VrfTestCompare(vt, block, VRFTEST_REF_ROUTES, vrf_ids[v], addr, size, &shown) == false)
					{
						wrong++;
					}
					lookups[f]++;
				}
			}
		}
	}

	Format(what, sizeof(what), "Round %u: %u IPv4 and %u IPv6 lookups in %u VRFs give the next hops of the reference", round, lookups[0], lookups[1], VRFTEST_REF_VRFS);
	VrfTestCheck(ctx, wrong == 0 && NodeGetVrfTable(t, 8) == NULL, what, "%u lookups differ", wrong);

	NodeFreeVrfTables(t);
	Free(routes);
}

static void VrfTestReference(VRFTEST_CTX *ctx)
{
	for (UINT i = 0;i < VRFTEST_ROUNDS;i++)
	{
		VrfTestReferenceRound(ctx, i + 1, 0x9E3779B97F4A7C15ULL * (i + 1));
	}
}

//
// The nodes
//

// A new empty data directory under the temp directory of the process, with a configuration store that runs no role
// on num_workers workers (0: one per core)
static void VrfTestNewDir(wchar_t *dir, UINT size, char *name, UINT num_workers)
{
	wchar_t tmp[MAX_PATH];
	wchar_t path[MAX_PATH];
	char workers[16];

	UniFormat(tmp, sizeof(tmp), L"vrftest_%S_%u", name, Rand32());
	ConbinePathW(dir, size, MsGetMyTempDirW(), tmp);
	MakeDirExW(dir);

	Format(workers, sizeof(workers), "%u", num_workers);
	ConbinePathW(path, sizeof(path), dir, CS_FILE_NAME);
	CONFIG_STORE *s = CsOpen(path);
	if (s != NULL)
	{
		CsSetSetting(s, NODE_SETTING_ROLES, "none");
		CsSetSetting(s, NODE_SETTING_WORKERS, workers);
		CsClose(s);
	}
}

// Delete the files of a directory, then the directory (it holds no subdirectory)
static void VrfTestDeleteFiles(wchar_t *dir)
{
	DIRLIST *d = EnumDirW(dir);

	for (UINT i = 0;d != NULL && i < d->NumFiles;i++)
	{
		DIRENT *e = d->File[i];
		wchar_t path[MAX_PATH];

		if (e->Folder == false)
		{
			ConbinePathW(path, sizeof(path), dir, e->FileNameW);
			FileDeleteW(path);
		}
	}

	FreeDir(d);
	DeleteDirW(dir);
}

// Delete a data directory: the node log, then the configuration store
static void VrfTestDeleteDir(wchar_t *dir)
{
	wchar_t log_dir[MAX_PATH];

	ConbinePathW(log_dir, sizeof(log_dir), dir, NODE_LOG_DIR_NAME);
	VrfTestDeleteFiles(log_dir);
	VrfTestDeleteFiles(dir);
}

// The fake adapter of a host: it keeps each packet, or counts the packets of the stream while it runs
static void VrfTestAdapter(NODE *n, void *param, UINT vrf_id, const UCHAR *packet, UINT size)
{
	VRFTEST_NODE *t = (VRFTEST_NODE *)param;

	if (InterlockedCompareExchange(&t->Stream, 0, 0) != 0)
	{
		// The stream: from 10.0.0.1, the sequence number in the first bytes of the data, red when it is even
		UINT seq = (size >= 32 ? READ_UINT(packet + 28) : INFINITE);
		UINT want = vrftest_vrf_ids[(seq % 2 == 0) ? VRFTEST_RED : VRFTEST_BLUE];

		if (t->Seen != NULL && seq < VRFTEST_STREAM_MAX && vrf_id == want && packet[12] == 10 && packet[15] == 1)
		{
			t->Seen[seq]++;
			InterlockedIncrement(&t->Arrivals);
		}
		else
		{
			InterlockedIncrement(&t->Wrong);
		}
		return;
	}

	VRFTEST_PACKET *p = ZeroMalloc(sizeof(VRFTEST_PACKET));
	p->VrfId = vrf_id;
	p->Size = MIN(size, (UINT)sizeof(p->Data));
	Copy(p->Data, packet, p->Size);

	AcquireSRWLockExclusive(&t->Lock);
	Add(t->Packets, p);
	ReleaseSRWLockExclusive(&t->Lock);
}

// The packets that the host of t took
static UINT VrfTestNumPackets(VRFTEST_NODE *t)
{
	AcquireSRWLockShared(&t->Lock);
	UINT num = LIST_NUM(t->Packets);
	ReleaseSRWLockShared(&t->Lock);

	return num;
}

// The packet index that the host of t took: whether it is the one of size bytes at packet, and its VRF
static bool VrfTestPacketIs(VRFTEST_NODE *t, UINT index, UCHAR *packet, UINT size, UINT *vrf_id)
{
	bool same = false;

	AcquireSRWLockShared(&t->Lock);
	if (index < LIST_NUM(t->Packets))
	{
		VRFTEST_PACKET *p = LIST_DATA(t->Packets, index);

		same = (p->Size == size && Cmp(p->Data, packet, size) == 0);
		*vrf_id = p->VrfId;
	}
	ReleaseSRWLockShared(&t->Lock);

	return same;
}

// The counters of the overlay of a node
static void VrfTestStatus(VRFTEST_NODE *t, NODE_OVERLAY_STATUS *st)
{
	NodeOverlayGetStatus(t->Node, st);
}

// A test packet from src to dst, both IPv4 or both IPv6: an ICMP echo request, an ICMPv6 one for IPv6, whose
// identifier, sequence number and first bytes of data are seq. Its size, 0 when the two are not of one family.
static UINT VrfTestPacket(UCHAR *buf, char *src, char *dst, UINT seq)
{
	UCHAR s[16], d[16];
	UINT s_size = VrfTestAddress(s, src), d_size = VrfTestAddress(d, dst);
	UCHAR *icmp;
	UINT size;

	if (s_size == 0 || s_size != d_size)
	{
		return 0;
	}

	if (s_size == 4)
	{
		size = 20 + 8 + VRFTEST_PAYLOAD;
		Zero(buf, size);
		buf[0] = 0x45;
		buf[2] = (UCHAR)(size >> 8);
		buf[3] = (UCHAR)size;
		buf[8] = 64;
		buf[9] = IP_PROTO_ICMPV4;
		Copy(buf + 12, s, 4);
		Copy(buf + 16, d, 4);
		USHORT sum = IpChecksum(buf, 20);
		Copy(buf + 10, &sum, 2);
		icmp = buf + 20;
		icmp[0] = 8;
	}
	else
	{
		size = 40 + 8 + VRFTEST_PAYLOAD;
		Zero(buf, size);
		buf[0] = 0x60;
		buf[5] = 8 + VRFTEST_PAYLOAD;
		buf[6] = IP_PROTO_ICMPV6;
		buf[7] = 64;
		Copy(buf + 8, s, 16);
		Copy(buf + 24, d, 16);
		icmp = buf + 40;
		icmp[0] = 128;
	}

	WRITE_UINT(icmp + 4, seq);
	WRITE_UINT(icmp + 8, seq);
	for (UINT i = 4;i < VRFTEST_PAYLOAD;i++)
	{
		icmp[8 + i] = (UCHAR)('a' + i);
	}

	if (s_size == 4)
	{
		USHORT sum = IpChecksum(icmp, 8 + VRFTEST_PAYLOAD);
		Copy(icmp + 2, &sum, 2);
	}

	return size;
}

// The addresses of node i in the isolation case into a, at most max: their number
static UINT VrfTestNodeAddresses(UINT i, CONTROL_ADDRESS *a, UINT max)
{
	UINT num = 0;

	for (UINT k = 0;k < sizeof(vrftest_addrs) / sizeof(vrftest_addrs[0]) && num < max;k++)
	{
		VRFTEST_ADDR *x = &vrftest_addrs[k];

		if (x->Node != i)
		{
			continue;
		}

		CONTROL_ADDRESS *c = &a[num++];
		Zero(c, sizeof(CONTROL_ADDRESS));
		StrCpy(c->Network, sizeof(c->Network), vrftest_vrf_names[x->Vrf]);
		c->VrfId = vrftest_vrf_ids[x->Vrf];
		c->AddressSize = VrfTestAddress(c->Address, x->Address);
		c->Length = (c->AddressSize == 4 ? 24 : 64);
	}

	return num;
}

// Whether node i of the isolation case has an address in the VRF vrf
static bool VrfTestInVrf(UINT i, UINT vrf)
{
	for (UINT k = 0;k < sizeof(vrftest_addrs) / sizeof(vrftest_addrs[0]);k++)
	{
		if (vrftest_addrs[k].Node == i && vrftest_addrs[k].Vrf == vrf)
		{
			return true;
		}
	}

	return false;
}

// Node j as a peer of node i: its name and key, the VRFs they share and its addresses in them; false when they share
// none
static bool VrfTestPeer(CONTROL_PEER *p, UINT i, UINT j, const UCHAR *key)
{
	CONTROL_ADDRESS all[CONTROL_MAX_ADDRESSES];
	UINT num = VrfTestNodeAddresses(j, all, CONTROL_MAX_ADDRESSES);

	Zero(p, sizeof(CONTROL_PEER));
	StrCpy(p->Name, sizeof(p->Name), vrftest_names[j]);
	Copy(p->Key, key, PEER_KEY_SIZE);

	for (UINT vrf = VRFTEST_RED;vrf <= VRFTEST_BLUE;vrf++)
	{
		if (VrfTestInVrf(i, vrf) && VrfTestInVrf(j, vrf))
		{
			p->VrfIds[p->NumVrfs++] = vrftest_vrf_ids[vrf];
		}
	}

	for (UINT k = 0;k < num;k++)
	{
		for (UINT v = 0;v < p->NumVrfs;v++)
		{
			if (all[k].VrfId == p->VrfIds[v])
			{
				Copy(&p->Addresses[p->NumAddresses++], &all[k], sizeof(CONTROL_ADDRESS));
			}
		}
	}

	return (p->NumVrfs != 0);
}

// The desired state of node i at Generation g: its addresses, and the nodes that share a VRF with it as its peers, in
// name order; node-x is a peer of node-a only. With churn, the state of a Generation of the stream case: more
// addresses of the node, and in an odd Generation node-0 first, a peer that never comes up, which moves the next hops
// of the others.
static CONTROL_STATE *VrfTestState(VRFTEST_NODE *nodes, PEER_KEY *x, PEER_KEY *zero, UINT i, UINT64 g, bool churn)
{
	CONTROL_STATE *st = ZeroMalloc(sizeof(CONTROL_STATE));

	st->Generation = g;
	StrCpy(st->Name, sizeof(st->Name), vrftest_names[i]);
	st->NumAddresses = VrfTestNodeAddresses(i, st->Addresses, CONTROL_MAX_ADDRESSES);
	st->Peers = ZeroMalloc(sizeof(CONTROL_PEER) * (VRFTEST_NUM_NODES + 2));

	if (churn)
	{
		CONTROL_ADDRESS *a = &st->Addresses[st->NumAddresses++];
		char tmp[64];

		Format(tmp, sizeof(tmp), "10.%u.%u.1", (UINT)(1 + g % 200), (UINT)(g % 7));
		StrCpy(a->Network, sizeof(a->Network), "red");
		a->VrfId = vrftest_vrf_ids[VRFTEST_RED];
		a->AddressSize = VrfTestAddress(a->Address, tmp);
		a->Length = 24;

		a = &st->Addresses[st->NumAddresses++];
		Format(tmp, sizeof(tmp), "fd00:1:%x::%x", (UINT)(g % 100), (UINT)(1 + g % 13));
		StrCpy(a->Network, sizeof(a->Network), "blue");
		a->VrfId = vrftest_vrf_ids[VRFTEST_BLUE];
		a->AddressSize = VrfTestAddress(a->Address, tmp);
		a->Length = 64;

		if (g % 2 == 1)
		{
			CONTROL_PEER *p = &st->Peers[st->NumPeers++];

			StrCpy(p->Name, sizeof(p->Name), "node-0");
			Copy(p->Key, zero->Public, PEER_KEY_SIZE);
			p->NumVrfs = 1;
			p->VrfIds[0] = vrftest_vrf_ids[VRFTEST_RED];
			p->NumAddresses = 1;
			StrCpy(p->Addresses[0].Network, sizeof(p->Addresses[0].Network), "red");
			p->Addresses[0].VrfId = vrftest_vrf_ids[VRFTEST_RED];
			p->Addresses[0].AddressSize = VrfTestAddress(p->Addresses[0].Address, "10.0.0.200");
			p->Addresses[0].Length = 24;
		}
	}

	for (UINT j = 0;j < VRFTEST_NUM_NODES;j++)
	{
		if (j != i && VrfTestPeer(&st->Peers[st->NumPeers], i, j, nodes[j].Key.Public))
		{
			st->NumPeers++;
		}
	}
	if (i == VRFTEST_A && VrfTestPeer(&st->Peers[st->NumPeers], i, VRFTEST_X, x->Public))
	{
		st->NumPeers++;
	}

	return st;
}

static void VrfTestFreeState(CONTROL_STATE *st)
{
	if (st != NULL)
	{
		Free(st->Peers);
		Free(st);
	}
}

// Apply the state of node i at Generation g
static bool VrfTestApply(VRFTEST_NODE *nodes, PEER_KEY *x, PEER_KEY *zero, UINT i, UINT64 g, bool churn)
{
	CONTROL_STATE *st = VrfTestState(nodes, x, zero, i, g, churn);
	bool ok = NodeOverlayApply(nodes[i].Node, st);

	VrfTestFreeState(st);

	return ok;
}

// Whether every node has a session to each of its peers within VRFTEST_BOUND
static bool VrfTestWaitLinks(VRFTEST_NODE *nodes, UINT *want)
{
	UINT64 end = Tick64() + VRFTEST_BOUND;

	while (true)
	{
		bool all = true;

		for (UINT i = 0;i < VRFTEST_NUM_NODES;i++)
		{
			NODE_OVERLAY_STATUS st;

			VrfTestStatus(&nodes[i], &st);
			if (st.NumPeers != want[i] || st.NumLinks != want[i])
			{
				all = false;
			}
		}

		if (all)
		{
			return true;
		}
		if (Tick64() >= end)
		{
			return false;
		}
		SleepThread(VRFTEST_POLL);
	}
}

//
// The swap of the tables
//

// One pass of a reader over every probe, then the next pass on the same worker; the worker passes its quiescent point
// between two passes
static void VrfTestReaderItem(NODE_WORKER *w, void *param)
{
	VRFTEST_READER *r = (VRFTEST_READER *)param;
	NODE_TABLES *t = NodeGetTables(w->Node);
	NODE_VRF_TABLES *v = (t != NULL ? t->Vrfs : NULL);

	if (v == NULL)
	{
		r->Lost++;
	}
	else
	{
		for (UINT i = 0;i < VRFTEST_PROBES * 2;i++)
		{
			VRFTEST_PROBE *p = &vrftest_probes[i];
			UINT hop = NodeVrfLookup(NodeGetVrfTable(v, p->VrfId), p->Address, p->Size);

			if (hop >= v->NumHops)
			{
				r->Lost++;
			}
			else if (v->Hops[hop] != &vrftest_objects[p->Object])
			{
				r->Wrong++;
			}
		}

		if (v->Generation < r->Last)
		{
			r->Backwards++;
		}
		if (v->Generation != r->Last)
		{
			r->Distinct++;
		}
		r->Last = v->Generation;
	}

	r->Passes++;

	if (InterlockedCompareExchange(&vrftest_swap.Stop, 0, 0) != 0 || NodePost(w->Node, w->Index, VrfTestReaderItem, r) == false)
	{
		InterlockedIncrement(&vrftest_swap.Done);
	}
}

// The probes: address k is 10.0.k.1, or fd00::k:1 from VRFTEST_PROBES / 2 on; in VRF 1 it leads to object
// k % VRFTEST_SWAP_HOPS, in VRF 2 to object (k + 3) % VRFTEST_SWAP_HOPS
static void VrfTestProbes()
{
	for (UINT k = 0;k < VRFTEST_PROBES;k++)
	{
		for (UINT v = 0;v < 2;v++)
		{
			VRFTEST_PROBE *p = &vrftest_probes[k * 2 + v];

			Zero(p, sizeof(VRFTEST_PROBE));
			p->VrfId = v + 1;
			p->Object = (k + v * 3) % VRFTEST_SWAP_HOPS;
			if (k < VRFTEST_PROBES / 2)
			{
				p->Size = 4;
				p->Address[0] = 10;
				p->Address[2] = (UCHAR)k;
				p->Address[3] = 1;
			}
			else
			{
				p->Size = 16;
				p->Address[0] = 0xfd;
				p->Address[13] = (UCHAR)k;
				p->Address[15] = 1;
			}
		}
	}
}

// The tables of Generation g of the table case: next hop j is object (j + g) % VRFTEST_SWAP_HOPS, so the next hop of
// an object moves with each Generation; a host route to every probe, and random routes around them, shorter than a
// host route, that differ from one Generation to the next
static NODE_VRF_TABLES *VrfTestSwapTables(UINT64 g, UINT64 *s)
{
	void *hops[VRFTEST_SWAP_HOPS];
	UINT num = VRFTEST_PROBES * 2 + 2 * 2 * VRFTEST_SWAP_CHURN, n = 0;
	NODE_VRF_ROUTE *routes = ZeroMalloc(sizeof(NODE_VRF_ROUTE) * num);

	for (UINT j = 0;j < VRFTEST_SWAP_HOPS;j++)
	{
		hops[j] = &vrftest_objects[(j + g) % VRFTEST_SWAP_HOPS];
	}

	for (UINT i = 0;i < VRFTEST_PROBES * 2;i++)
	{
		VRFTEST_PROBE *p = &vrftest_probes[i];
		NODE_VRF_ROUTE *r = &routes[n++];

		r->VrfId = p->VrfId;
		Copy(r->Address, p->Address, sizeof(r->Address));
		r->AddressSize = p->Size;
		r->Length = p->Size * 8;
		r->NextHop = (UINT)((p->Object + VRFTEST_SWAP_HOPS - g % VRFTEST_SWAP_HOPS) % VRFTEST_SWAP_HOPS);
	}

	for (UINT v = 1;v <= 2;v++)
	{
		for (UINT i = 0;i < 2 * VRFTEST_SWAP_CHURN;i++)
		{
			NODE_VRF_ROUTE *r = &routes[n++];
			bool v6 = (i >= VRFTEST_SWAP_CHURN);

			r->VrfId = v;
			r->AddressSize = (v6 ? 16 : 4);
			for (UINT j = 0;j < r->AddressSize;j++)
			{
				r->Address[j] = (UCHAR)VrfTestRand(s);
			}
			if (v6)
			{
				r->Address[0] = 0xfd;
				r->Address[1] = 0;
				r->Length = 16 + (UINT)(VrfTestRand(s) % 112);
			}
			else
			{
				r->Address[0] = 10;
				r->Address[1] = 0;
				r->Length = 12 + (UINT)(VrfTestRand(s) % 20);
			}
			r->NextHop = (UINT)(VrfTestRand(s) % VRFTEST_SWAP_HOPS);
		}
	}

	NODE_VRF_TABLES *t = NodeNewVrfTables(g, routes, n, hops, VRFTEST_SWAP_HOPS);
	Free(routes);

	return t;
}

static void VrfTestTableSwap(VRFTEST_CTX *ctx)
{
	wchar_t dir[MAX_PATH];
	NODE_STATUS st;
	char what[MAX_SIZE];
	UINT64 s = 0x5DEECE66DULL;
	UINT64 g = 1;

	VrfTestProbes();
	VrfTestNewDir(dir, sizeof(dir), "swap", 0);

	NODE *n = NewNode(dir);
	NodeStart(n);
	NodeGetStatus(n, &st);
	UINT num = st.NumWorkers;

	// The tables of Generation 1 before the readers start
	NODE_VRF_TABLES *t = VrfTestSwapTables(g, &s);
	bool ok = (t != NULL && NodeSwapVrfs(n, t));
	VrfTestCheck(ctx, ok, "NodeSwapVrfs installs the forwarding tables of Generation 1 from a thread that is no reader", "tables %p", t);
	if (ok == false)
	{
		NodeFreeVrfTables(t);
	}

	Zero(&vrftest_swap, sizeof(vrftest_swap));
	VRFTEST_READER *readers = ZeroMalloc(sizeof(VRFTEST_READER) * MAX(num, 1));
	for (UINT i = 0;i < num && ok;i++)
	{
		NodePost(n, i, VrfTestReaderItem, &readers[i]);
	}

	UINT swaps = 0, refused = 0;
	UINT64 end = Tick64() + VRFTEST_SWAP_TIME;
	while (ok && Tick64() < end && swaps < VRFTEST_SWAP_MAX)
	{
		t = VrfTestSwapTables(++g, &s);
		if (t != NULL && NodeSwapVrfs(n, t))
		{
			swaps++;
		}
		else
		{
			NodeFreeVrfTables(t);
			refused++;
		}
	}

	InterlockedExchange(&vrftest_swap.Stop, 1);
	bool ended = (ok == false || num == 0);
	for (UINT64 bound = Tick64() + VRFTEST_BOUND;ended == false && Tick64() < bound;)
	{
		ended = (InterlockedCompareExchange(&vrftest_swap.Done, 0, 0) >= (LONG)num);
		SleepThread(1);
	}

	UINT64 passes = 0, lost = 0, wrong = 0, backwards = 0;
	UINT few = 0;
	for (UINT i = 0;i < num;i++)
	{
		passes += readers[i].Passes;
		lost += readers[i].Lost;
		wrong += readers[i].Wrong;
		backwards += readers[i].Backwards;
		if (readers[i].Distinct < 2)
		{
			few++;
		}
	}
	Free(readers);

	Print("  %u swaps of the tables of two VRFs in %u ms under %u readers, %I64u passes over %u probes\n", swaps, VRFTEST_SWAP_TIME, num, passes, VRFTEST_PROBES * 2);

	Format(what, sizeof(what), "Swaps under a reader on each of the %u workers: no probe misses its next hop or finds another one, no reader sees older tables", num);
	VrfTestCheck(ctx, ok && ended && refused == 0 && lost == 0 && wrong == 0 && backwards == 0, what,
		"readers ended %u, %u swaps refused, %I64u lost, %I64u wrong, %I64u older", (UINT)ended, refused, lost, wrong, backwards);
	VrfTestCheck(ctx, ok && ended && swaps >= 10 && few == 0, "Every reader sees several Generations while the swaps run",
		"%u swaps, %u readers saw fewer than two Generations", swaps, few);

	// A thread that registered itself as a reader may not swap while it is online
	NODE_READER r;
	Zero(&r, sizeof(r));
	NodeReaderRegister(n, &r);
	t = VrfTestSwapTables(++g, &s);
	ok = NodeSwapVrfs(n, t);
	if (ok == false)
	{
		NodeFreeVrfTables(t);
	}
	NodeReaderUnregister(n, &r);
	VrfTestCheck(ctx, ok == false, "NodeSwapVrfs from an online reader is refused instead of waiting for itself", "swapped");

	// A stopped node has no snapshot to swap into
	NodeStop(n);
	t = VrfTestSwapTables(++g, &s);
	ok = NodeSwapVrfs(n, t);
	if (ok == false)
	{
		NodeFreeVrfTables(t);
	}
	VrfTestCheck(ctx, ok == false && NodeGetTables(n) == NULL, "A stopped node refuses a swap of its forwarding tables", "swapped");

	FreeNode(n);
	VrfTestDeleteDir(dir);
}

//
// The overlay: isolation and stream
//

// Send one packet of the isolation case: from the host of a node into its overlay, or from node-x on its session
static void VrfTestSendOne(VRFTEST_NODE *nodes, TRANSPORT_NOISE *x, VRFTEST_SEND *send, UCHAR *packet, UINT size)
{
	UINT vrf_id = vrftest_vrf_ids[send->Vrf];

	if (send->From == VRFTEST_X)
	{
		UCHAR record[256];

		WRITE_UINT(record, vrf_id);
		Copy(record + NODE_OVERLAY_VRF_TAG, packet, size);
		TransportNoiseSend(x, NOISE_RECORD_DATA, record, (send->Cut != 0 ? send->Cut : NODE_OVERLAY_VRF_TAG + size));
		return;
	}

	VRFTEST_NODE *t = &nodes[send->From];

	NodeReaderOnline(t->Node, &t->Reader);
	NodeOverlayInput(t->Node, vrf_id, packet, size);
	NodeReaderOffline(&t->Reader);
}

// Where the packet of size bytes went within VRFTEST_BOUND: to the host of which node and in which VRF, or dropped by
// which node; num_before and dropped_before are the packets that each host took and the drops of each node before
static void VrfTestOutcome(VRFTEST_NODE *nodes, UINT *num_before, UINT64 *dropped_before, UCHAR *packet, UINT size, char *outcome, UINT outcome_size)
{
	UINT64 end = Tick64() + VRFTEST_BOUND;

	StrCpy(outcome, outcome_size, "lost");

	while (Tick64() < end)
	{
		for (UINT i = 0;i < VRFTEST_NUM_NODES;i++)
		{
			NODE_OVERLAY_STATUS st;

			if (VrfTestNumPackets(&nodes[i]) > num_before[i])
			{
				UINT vrf_id = 0;
				bool same = VrfTestPacketIs(&nodes[i], num_before[i], packet, size, &vrf_id);
				char *vrf = "an unknown VRF";

				for (UINT v = 0;v < 3;v++)
				{
					if (vrftest_vrf_ids[v] == vrf_id)
					{
						vrf = vrftest_vrf_names[v];
					}
				}

				Format(outcome, outcome_size, "%s to %s in %s", (same ? "delivered" : "a changed packet delivered"), nodes[i].Name, vrf);
				return;
			}

			VrfTestStatus(&nodes[i], &st);
			if (st.Dropped > dropped_before[i])
			{
				Format(outcome, outcome_size, "dropped by %s", nodes[i].Name);
				return;
			}
		}

		SleepThread(1);
	}
}

// The packets of the isolation case, their outcomes and the counters of the nodes, as the text of the golden file
static char *VrfTestIsolation(VRFTEST_NODE *nodes, TRANSPORT_NOISE *x)
{
	BUF *b = NewBuf();
	char line[MAX_SIZE];
	UINT num = sizeof(vrftest_sends) / sizeof(vrftest_sends[0]);

	Format(line, sizeof(line), "# VRFs red (%u) and blue (%u) both use 10.0.0.0/24 and fd00::/64; green (%u) is a VRF of no node\n",
		vrftest_vrf_ids[VRFTEST_RED], vrftest_vrf_ids[VRFTEST_BLUE], vrftest_vrf_ids[VRFTEST_GREEN]);
	WriteBuf(b, line, StrLen(line));

	for (UINT k = 0;k < num;k++)
	{
		VRFTEST_SEND *send = &vrftest_sends[k];
		UINT num_before[VRFTEST_NUM_NODES];
		UINT64 dropped_before[VRFTEST_NUM_NODES];
		UCHAR packet[128];
		char outcome[MAX_SIZE];
		char cut[64] = "";

		for (UINT i = 0;i < VRFTEST_NUM_NODES;i++)
		{
			NODE_OVERLAY_STATUS st;

			VrfTestStatus(&nodes[i], &st);
			num_before[i] = VrfTestNumPackets(&nodes[i]);
			dropped_before[i] = st.Dropped;
		}

		UINT size = VrfTestPacket(packet, send->Src, send->Dst, k + 1);
		VrfTestSendOne(nodes, x, send, packet, size);
		VrfTestOutcome(nodes, num_before, dropped_before, packet, size, outcome, sizeof(outcome));

		if (send->Cut != 0)
		{
			Format(cut, sizeof(cut), " (%u bytes of the record)", send->Cut);
		}
		Format(line, sizeof(line), "%s: %s %s > %s%s: %s\n", vrftest_vrf_names[send->Vrf], vrftest_names[send->From], send->Src, send->Dst, cut, outcome);
		Print("  %s", line);
		WriteBuf(b, line, StrLen(line));
	}

	for (UINT i = 0;i < VRFTEST_NUM_NODES;i++)
	{
		NODE_OVERLAY_STATUS st;

		VrfTestStatus(&nodes[i], &st);
		Format(line, sizeof(line), "%s: forwarded %I64u, delivered %I64u, dropped %I64u, VRFs %u\n", nodes[i].Name, st.Forwarded, st.Delivered, st.Dropped, st.NumVrfs);
		Print("  %s", line);
		WriteBuf(b, line, StrLen(line));
	}

	char *text = HarnessBufToStr(b);
	FreeBuf(b);

	return text;
}

// The sender of the stream: packets from 10.0.0.1 in red to 10.0.0.2 and in blue to 10.0.0.3 by turns, numbered, each
// sent as an online reader of node-a with a quiescent point after it
static DWORD WINAPI VrfTestStreamThread(LPVOID param)
{
	VRFTEST_STREAM *s = (VRFTEST_STREAM *)param;
	NODE *n = s->From->Node;
	NODE_READER r;
	UCHAR packet[128];

	Zero(&r, sizeof(r));
	NodeReaderRegister(n, &r);

	while (InterlockedCompareExchange(&s->Stop, 0, 0) == 0 && s->Sent < VRFTEST_STREAM_MAX)
	{
		UINT seq = (UINT)s->Sent;
		UINT vrf = (seq % 2 == 0 ? VRFTEST_RED : VRFTEST_BLUE);
		UINT size = VrfTestPacket(packet, "10.0.0.1", (vrf == VRFTEST_RED ? "10.0.0.2" : "10.0.0.3"), seq);

		if (NodeOverlayInput(n, vrftest_vrf_ids[vrf], packet, size) == false)
		{
			InterlockedIncrement(&s->Refused);
			break;
		}

		InterlockedIncrement(&s->Sent);
		NodeReaderQuiescent(n, &r);
	}

	NodeReaderUnregister(n, &r);

	return 0;
}

// Whether the stream sent at least target packets within VRFTEST_BOUND, or all of its packets; false when it stopped
// before, refused, or did not get there
static bool VrfTestWaitSent(VRFTEST_STREAM *s, LONG target, HANDLE thread)
{
	UINT64 end = Tick64() + VRFTEST_BOUND;

	while (InterlockedCompareExchange(&s->Sent, 0, 0) < target)
	{
		if (WaitForSingleObject(thread, 0) == WAIT_OBJECT_0)
		{
			return (s->Refused == 0 && s->Sent >= VRFTEST_STREAM_MAX);
		}
		if (Tick64() >= end)
		{
			return false;
		}
		SleepThread(1);
	}

	return true;
}

static void VrfTestStream(VRFTEST_CTX *ctx, VRFTEST_NODE *nodes, PEER_KEY *x, PEER_KEY *zero)
{
	VRFTEST_STREAM s;
	char what[MAX_SIZE];
	UINT64 g = 1;
	UINT applied = 0;

	Zero(&s, sizeof(s));
	s.From = &nodes[VRFTEST_A];
	nodes[VRFTEST_B].Seen = ZeroMalloc(VRFTEST_STREAM_MAX);
	for (UINT i = 0;i < VRFTEST_NUM_NODES;i++)
	{
		InterlockedExchange(&nodes[i].Stream, 1);
	}

	HANDLE thread = CreateThread(NULL, 0, VrfTestStreamThread, &s, 0, NULL);

	// Generation after Generation for node-a and node-b, with the stream between them
	for (UINT i = 0;i < VRFTEST_GENERATIONS && thread != NULL;i++)
	{
		if (VrfTestWaitSent(&s, InterlockedCompareExchange(&s.Sent, 0, 0) + VRFTEST_STREAM_STEP, thread) == false)
		{
			break;
		}

		g++;
		if (VrfTestApply(nodes, x, zero, VRFTEST_A, g, true) && VrfTestApply(nodes, x, zero, VRFTEST_B, g, true))
		{
			applied++;
		}
	}

	InterlockedExchange(&s.Stop, 1);
	if (thread != NULL)
	{
		WaitForSingleObject(thread, INFINITE);
		CloseHandle(thread);
	}

	// Every packet that the overlay took arrives
	LONG sent = InterlockedCompareExchange(&s.Sent, 0, 0);
	UINT64 end = Tick64() + VRFTEST_BOUND;
	while (InterlockedCompareExchange(&nodes[VRFTEST_B].Arrivals, 0, 0) < sent && Tick64() < end)
	{
		SleepThread(VRFTEST_POLL);
	}

	UINT missing = 0, twice = 0;
	for (LONG i = 0;i < sent;i++)
	{
		if (nodes[VRFTEST_B].Seen[i] == 0)
		{
			missing++;
		}
		else if (nodes[VRFTEST_B].Seen[i] > 1)
		{
			twice++;
		}
	}

	NODE_OVERLAY_STATUS sa, sb;
	VrfTestStatus(&nodes[VRFTEST_A], &sa);
	VrfTestStatus(&nodes[VRFTEST_B], &sb);
	LONG wrong = nodes[VRFTEST_A].Wrong + nodes[VRFTEST_B].Wrong + nodes[VRFTEST_C].Wrong;

	Print("  %u packets in red and blue while node-a and node-b applied %u Generations each (last %I64u)\n", (UINT)sent, applied, g);

	Format(what, sizeof(what), "node-a and node-b apply %u Generations each while the packets flow, and run the last", VRFTEST_GENERATIONS);
	VrfTestCheck(ctx, applied == VRFTEST_GENERATIONS && sa.Generation == g && sb.Generation == g, what,
		"%u applied, generations %I64u and %I64u of %I64u", applied, sa.Generation, sb.Generation, g);
	VrfTestCheck(ctx, s.Refused == 0 && sent >= VRFTEST_GENERATIONS * VRFTEST_STREAM_STEP && missing == 0 && twice == 0 && wrong == 0,
		"Table swaps under the stream lose or misroute no packet: each arrives at node-b once, in its VRF, and none anywhere else",
		"%u refused, %u sent, %u missing, %u twice, %u elsewhere or in the wrong VRF", (UINT)s.Refused, (UINT)sent, missing, twice, (UINT)wrong);

	for (UINT i = 0;i < VRFTEST_NUM_NODES;i++)
	{
		InterlockedExchange(&nodes[i].Stream, 0);
	}
}

static void VrfTestOverlay(VRFTEST_CTX *ctx)
{
	VRFTEST_NODE *nodes = ZeroMalloc(sizeof(VRFTEST_NODE) * VRFTEST_NUM_NODES);
	TRANSPORT *loopback = TransportLoopbackNew("loopback", 0, false);
	PEER_KEY x, zero;
	TRANSPORT_NOISE xs;
	UCHAR scalar[PEER_KEY_SIZE];
	char out_dir[MAX_SIZE];
	char golden_dir[MAX_SIZE];
	char what[MAX_SIZE];
	bool update;
	bool started = (loopback != NULL);
	UINT want_links[VRFTEST_NUM_NODES] = {3, 2, 2};

	Zero(&x, sizeof(x));
	Zero(&zero, sizeof(zero));
	Zero(&xs, sizeof(xs));

	// The nodes, each with its static key (the scalars 1, 2, ... of the conformance tests) and the fake adapter of its
	// host, and their overlays without a control stream
	for (UINT i = 0;i < VRFTEST_NUM_NODES && started;i++)
	{
		VRFTEST_NODE *t = &nodes[i];
		NODE_OVERLAY_CONFIG c;

		t->Name = vrftest_names[i];
		InitializeSRWLock(&t->Lock);
		t->Packets = NewListFast(NULL);
		for (UINT j = 0;j < PEER_KEY_SIZE;j++)
		{
			scalar[j] = (UCHAR)(1 + PEER_KEY_SIZE * i + j);
		}
		started = PeerKeyFromScalar(&t->Key, scalar);

		VrfTestNewDir(t->Dir, sizeof(t->Dir), t->Name, 1);
		t->Node = NewNode(t->Dir);
		NodeStart(t->Node);
		NodeReaderRegister(t->Node, &t->Reader);
		NodeReaderOffline(&t->Reader);

		Zero(&c, sizeof(c));
		c.Data = loopback;
		c.Key = &t->Key;
		c.Adapter = VrfTestAdapter;
		c.AdapterParam = t;
		Format(what, sizeof(what), "%s: its overlay runs without a control stream", t->Name);
		started = VrfTestCheck(ctx, started && NodeOverlayStart(t->Node, &c), what, "NodeOverlayStart failed") && started;
	}

	// node-x dials node-a, so its static key is below node-a's; node-0 never comes up
	for (UINT k = 0;k < 256 && started;k++)
	{
		for (UINT j = 0;j < PEER_KEY_SIZE;j++)
		{
			scalar[j] = (UCHAR)(0xA0 + k + j);
		}
		PeerKeyClose(&x);
		if (PeerKeyFromScalar(&x, scalar) && Cmp(x.Public, nodes[VRFTEST_A].Key.Public, PEER_KEY_SIZE) < 0)
		{
			break;
		}
	}
	for (UINT j = 0;j < PEER_KEY_SIZE;j++)
	{
		scalar[j] = (UCHAR)(0x60 + j);
	}
	started = started && Cmp(x.Public, nodes[VRFTEST_A].Key.Public, PEER_KEY_SIZE) < 0 && PeerKeyFromScalar(&zero, scalar);
	Zero(scalar, sizeof(scalar));

	if (started)
	{
		bool applied = true;

		for (UINT i = 0;i < VRFTEST_NUM_NODES;i++)
		{
			applied = VrfTestApply(nodes, &x, &zero, i, 1, false) && applied;
		}

		// node-x: the initiator of a Noise session to node-a, as a node with the lower static key dials
		NOISE_SESSION_CONFIG c;
		Zero(&c, sizeof(c));
		c.Suite = NOISE_SUITE_IK;
		c.StaticKey = x.Private;
		c.RemoteStatic = nodes[VRFTEST_A].Key.Public;
		bool dialled = false;
		for (UINT64 end = Tick64() + VRFTEST_BOUND;dialled == false && Tick64() < end;)
		{
			TRANSPORT_STREAM *stream = TransportDial(loopback, vrftest_names[VRFTEST_A], NULL);

			Zero(&xs, sizeof(xs));
			dialled = (stream != NULL && TransportNoiseConnect(&xs, stream, &c, VRFTEST_BOUND));
			if (dialled == false)
			{
				Zero(&xs, sizeof(xs));
				SleepThread(VRFTEST_POLL);
			}
		}

		bool linked = VrfTestWaitLinks(nodes, want_links);
		started = VrfTestCheck(ctx, applied && dialled && linked,
			"The three nodes apply their states, red and blue on 10.0.0.0/24 and fd00::/64, node-x dials node-a, and every session is up",
			"applied %u, node-x %u, sessions %u", (UINT)applied, (UINT)dialled, (UINT)linked);
	}

	if (started)
	{
		HARNESS h;

		HarnessGetFamilyDirs("vrf", out_dir, sizeof(out_dir), golden_dir, sizeof(golden_dir), &update);
		MakeDirEx(out_dir);
		Print("VRF GOLDEN MODE %s\n", update ? "update" : "compare");
		Print("  golden directory: %s\n", golden_dir);

		char *text = VrfTestIsolation(nodes, &xs);
		Zero(&h, sizeof(h));
		HarnessCompareGolden(&h, out_dir, golden_dir, VRFTEST_GOLDEN, text, update);
		Free(text);
		VrfTestCheck(ctx, h.NumFail == 0, "Two VRFs on 10.0.0.0/24 and fd00::/64 stay apart: the packets arrive as the golden file " VRFTEST_GOLDEN " says", "it differs");

		VrfTestStream(ctx, nodes, &x, &zero);
	}

	// node-x first, then the nodes: their overlays stop, every thread is joined
	if (xs.Stream != NULL)
	{
		TransportNoiseClose(&xs);
	}

	for (UINT i = 0;i < VRFTEST_NUM_NODES;i++)
	{
		VRFTEST_NODE *t = &nodes[i];

		if (t->Node != NULL)
		{
			NodeReaderUnregister(t->Node, &t->Reader);
			NodeStop(t->Node);
			FreeNode(t->Node);
			VrfTestDeleteDir(t->Dir);
		}
		PeerKeyClose(&t->Key);

		if (t->Packets != NULL)
		{
			for (UINT k = 0;k < LIST_NUM(t->Packets);k++)
			{
				Free(LIST_DATA(t->Packets, k));
			}
			ReleaseList(t->Packets);
		}
		Free(t->Seen);
	}

	PeerKeyClose(&x);
	PeerKeyClose(&zero);
	TransportLoopbackFree(loopback);
	Free(nodes);
}

// vrf: the forwarding tables of the VRFs and the overlay that forwards on them
RANZ_TEST("vrf", vrf_test, "VRF forwarding tables: DIR-24-8 and trie lookups against a reference on random routes, swaps under readers, two VRFs on 10.0.0.0/24 kept apart over the overlay (golden family vrf), a stream that loses no packet while the tables swap.");
void vrf_test(UINT num, char **arg)
{
	VRFTEST_CTX ctx;
	HANDLE done = CreateEventW(NULL, TRUE, FALSE, NULL);
	HANDLE watchdog = (done != NULL ? CreateThread(NULL, 0, VrfTestWatchdog, done, 0, NULL) : NULL);

	Zero(&ctx, sizeof(ctx));

	Print("VRF forwarding table test: DIR-24-8 and trie lookups against a reference, swaps under readers, two VRFs on one range over the overlay\n");

	VrfTestEdges(&ctx);
	VrfTestReference(&ctx);
	VrfTestTableSwap(&ctx);
	VrfTestOverlay(&ctx);

	if (watchdog != NULL)
	{
		SetEvent(done);
		WaitForSingleObject(watchdog, INFINITE);
		CloseHandle(watchdog);
	}
	if (done != NULL)
	{
		CloseHandle(done);
	}

	if (ctx.NumFailed == 0)
	{
		Print("VRF TEST OK\n");
	}
	else
	{
		Print("VRF TEST FAILED (%u of %u checks failed)\n", ctx.NumFailed, ctx.NumChecks);
	}
}
