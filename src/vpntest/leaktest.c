// leaktest.c
// Named route leaking test of vpntest ("leak" command, SDN-7 #183)
//
// Route leaking in the data plane of a node (Cedar/NodeLeak.c) and the overlay that runs it (NodeOverlay.c), in
// process, as seam 2 of #45 runs the data plane. Four VRFs leak as route targets make them: shared exports to red and
// blue and imports from both, red and blue import from shared only, and lab imports from red, which imports nothing of
// lab. The test compiles the state of each node as the controller does (controller/internal/desired/leak.go): a route
// that a VRF of a peer leaks into a VRF of the node is a route of that Peer with the VRF of the peer that it goes into.
// - Tables: the leaked routes of a state get next hops of their own after those of the peers, which lead to the peer
//   and carry the VRF that the route goes into; a route of a 1:1 NAT rule of a peer stays a route to the peer itself.
// - Overlay: a host of red and a host of blue each reach node-s of shared, and node-s each of them; each packet arrives
//   in the VRF that leaked its route, and the answer goes back into the VRF of the sender. red and blue import nothing
//   of each other, so a packet between them goes nowhere. A one-way leak carries nothing: node-l of lab has a route to
//   node-r of red, but red does not route lab back, so node-r drops the packet in red: the VRF that a leak leads into
//   decides what passes. node-b presents the LAN 192.168.1.0/24 behind it as 10.92.1.0/24 in blue (1:1 NAT), and blue
//   leaks that prefix into shared: node-s reaches the LAN, which answers through the outside prefix.
// - A Generation without the leaks: the packets that the leaks carried go nowhere.
// Print "LEAK TEST OK" only when every check passes.

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

#define	LEAKTEST_BUDGET			120000		// The whole test ends within this time, or the watchdog ends the process (ms)
#define	LEAKTEST_BOUND			10000		// A bounded wait on observable state (ms)
#define	LEAKTEST_POLL			10			// Poll interval of observable state (ms)
#define	LEAKTEST_DATA			16			// The data of a test datagram after its UDP header
#define	LEAKTEST_PACKET			(20 + 8 + LEAKTEST_DATA)	// The bytes of a test packet
#define	LEAKTEST_NUM_NODES		4			// node-s, node-r, node-b and node-l
#define	LEAKTEST_NUM_VRFS		4			// shared, red, blue and lab
#define	LEAKTEST_NONE			INFINITE	// No node: the overlay drops the packet

// The VRFs
#define	LEAKTEST_SHARED			0
#define	LEAKTEST_RED			1
#define	LEAKTEST_BLUE			2
#define	LEAKTEST_LAB			3

static UINT leaktest_vrf_ids[LEAKTEST_NUM_VRFS] = {10, 1, 2, 3};
static char *leaktest_vrf_names[LEAKTEST_NUM_VRFS] = {"shared", "red", "blue", "lab"};

// The nodes, one in each VRF
#define	LEAKTEST_S				0
#define	LEAKTEST_R				1
#define	LEAKTEST_B				2
#define	LEAKTEST_L				3

static char *leaktest_names[LEAKTEST_NUM_NODES] = {"node-s", "node-r", "node-b", "node-l"};
static UINT leaktest_node_vrfs[LEAKTEST_NUM_NODES] = {LEAKTEST_SHARED, LEAKTEST_RED, LEAKTEST_BLUE, LEAKTEST_LAB};
static char *leaktest_addresses[LEAKTEST_NUM_NODES] = {"10.10.0.1", "10.1.0.1", "10.2.0.1", "10.3.0.1"};

// One leak: the routes of the VRF From go into the VRF To, which imports a route target that From exports
typedef struct LEAKTEST_LEAK
{
	UINT From;
	UINT To;
} LEAKTEST_LEAK;

static LEAKTEST_LEAK leaktest_leaks[] =
{
	{LEAKTEST_SHARED, LEAKTEST_RED},
	{LEAKTEST_SHARED, LEAKTEST_BLUE},
	{LEAKTEST_RED, LEAKTEST_SHARED},
	{LEAKTEST_BLUE, LEAKTEST_SHARED},
	{LEAKTEST_RED, LEAKTEST_LAB},
};

// The 1:1 NAT rule of node-b in blue: the LAN behind it as blue sees it
#define	LEAKTEST_NAT_INSIDE		"192.168.1.0"
#define	LEAKTEST_NAT_OUTSIDE	"10.92.1.0"
#define	LEAKTEST_NAT_LENGTH		24

// One packet of the overlay case: the node whose host sends it in its VRF, its source and destination, and the node
// whose host takes it (LEAKTEST_NONE: the node Dropper drops it) with the source and destination that it sees
typedef struct LEAKTEST_SEND
{
	UINT From;
	char *Src;
	char *Dst;
	UINT To;
	char *WantSrc;
	char *WantDst;
	UINT Dropper;
} LEAKTEST_SEND;

static LEAKTEST_SEND leaktest_sends[] =
{
	// red and blue reach shared, and shared reaches them; each packet arrives in the VRF of its destination
	{LEAKTEST_R, "10.1.0.1", "10.10.0.1", LEAKTEST_S, "10.1.0.1", "10.10.0.1"},
	{LEAKTEST_S, "10.10.0.1", "10.1.0.1", LEAKTEST_R, "10.10.0.1", "10.1.0.1"},
	{LEAKTEST_B, "10.2.0.1", "10.10.0.1", LEAKTEST_S, "10.2.0.1", "10.10.0.1"},
	{LEAKTEST_S, "10.10.0.1", "10.2.0.1", LEAKTEST_B, "10.10.0.1", "10.2.0.1"},
	// red and blue import nothing of each other
	{LEAKTEST_R, "10.1.0.1", "10.2.0.1", LEAKTEST_NONE, NULL, NULL, LEAKTEST_R},
	{LEAKTEST_B, "10.2.0.1", "10.1.0.1", LEAKTEST_NONE, NULL, NULL, LEAKTEST_B},
	// lab imports red, but red imports nothing of lab: node-r drops what node-l sends it
	{LEAKTEST_L, "10.3.0.1", "10.1.0.1", LEAKTEST_NONE, NULL, NULL, LEAKTEST_R},
	{LEAKTEST_R, "10.1.0.1", "10.3.0.1", LEAKTEST_NONE, NULL, NULL, LEAKTEST_R},
	// blue leaks the outside prefix of the LAN behind node-b into shared
	{LEAKTEST_S, "10.10.0.1", "10.92.1.7", LEAKTEST_B, "10.10.0.1", "192.168.1.7"},
	{LEAKTEST_B, "192.168.1.7", "10.10.0.1", LEAKTEST_S, "10.92.1.7", "10.10.0.1"},
	{LEAKTEST_R, "10.1.0.1", "10.92.1.7", LEAKTEST_NONE, NULL, NULL, LEAKTEST_R},
};

// The checks of the test
typedef struct LEAKTEST_CTX
{
	UINT NumChecks;
	UINT NumFailed;
} LEAKTEST_CTX;

// A packet that the fake adapter of a host took
typedef struct LEAKTEST_TAKEN
{
	UINT VrfId;
	UINT Size;
	UCHAR Data[LEAKTEST_PACKET];
} LEAKTEST_TAKEN;

// One node of the overlay case and the fake adapter of its host
typedef struct LEAKTEST_NODE
{
	char *Name;
	wchar_t Dir[MAX_PATH];				// Its data directory
	PEER_KEY Key;						// Its static key
	NODE *Node;
	NODE_READER Reader;					// The test thread as a reader of the node's forwarding tables, online while it sends
	SRWLOCK Lock;						// Taken
	LIST *Taken;						// What the adapter took (LEAKTEST_TAKEN)
} LEAKTEST_NODE;

static bool LeakTestCheck(LEAKTEST_CTX *ctx, bool ok, char *what, char *fmt, ...) RANZ_PRINTF_FORMAT(4, 5);
static bool LeakTestCheck(LEAKTEST_CTX *ctx, bool ok, char *what, char *fmt, ...)
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
static DWORD WINAPI LeakTestWatchdog(LPVOID param)
{
	char msg[MAX_SIZE];
	DWORD written = 0;

	if (WaitForSingleObject((HANDLE)param, LEAKTEST_BUDGET) != WAIT_TIMEOUT)
	{
		return 0;
	}

	int len = snprintf(msg, sizeof(msg), "LEAK TEST FAILED (did not finish within %u ms)\n", LEAKTEST_BUDGET);
	if (len > 0)
	{
		WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), msg, (DWORD)MIN((UINT)len, (UINT)sizeof(msg) - 1), &written, NULL);
	}

	TerminateProcess(GetCurrentProcess(), 1);

	return 0;
}

//
// States
//

// The IPv4 address of a text into addr (4 bytes): false for anything else
static bool LeakTestAddress(UCHAR *addr, char *str)
{
	IP ip;

	Zero(addr, 4);
	if (str == NULL || StrToIP(&ip, str) == false || IsIP4(&ip) == false)
	{
		return false;
	}

	Copy(addr, IPV4(ip.address), 4);
	return true;
}

// Whether the routes of the VRF from leak into the VRF to (with_leaks: the leaks are in the intent)
static bool LeakTestLeaks(UINT from, UINT to, bool with_leaks)
{
	for (UINT i = 0;with_leaks && i < sizeof(leaktest_leaks) / sizeof(leaktest_leaks[0]);i++)
	{
		if (leaktest_leaks[i].From == from && leaktest_leaks[i].To == to)
		{
			return true;
		}
	}

	return false;
}

// Add the route of address/length in the VRF of node i, which leads into the VRF of node j, to p
static void LeakTestAddRoute(CONTROL_PEER *p, UINT i, UINT j, char *address, UINT length)
{
	if (p->NumRoutes >= CONTROL_MAX_ROUTES)
	{
		return;
	}

	CONTROL_ROUTE *r = &p->Routes[p->NumRoutes++];
	Zero(r, sizeof(CONTROL_ROUTE));
	r->VrfId = leaktest_vrf_ids[leaktest_node_vrfs[i]];
	r->AddressSize = (LeakTestAddress(r->Address, address) ? 4 : 0);
	r->Length = length;
	r->PeerVrfId = leaktest_vrf_ids[leaktest_node_vrfs[j]];
}

// The desired state of node i at generation gen, as the controller compiles it: its address and, for node-b, its 1:1
// NAT rule; every node whose VRF leaks into the VRF of node i, or the other way round, as its peer, with the routes
// that leak into the VRF of node i as the routes of that Peer: the address of the peer, and for node-b the outside
// prefix of its rule. No two nodes share a VRF, so a peer has no address of a shared VRF.
static CONTROL_STATE *LeakTestState(LEAKTEST_NODE *nodes, UINT i, UINT64 gen, bool with_leaks)
{
	CONTROL_STATE *st = ZeroMalloc(sizeof(CONTROL_STATE));
	UINT vrf = leaktest_node_vrfs[i];

	st->Generation = gen;
	StrCpy(st->Name, sizeof(st->Name), leaktest_names[i]);
	st->NumAddresses = 1;
	StrCpy(st->Addresses[0].Network, sizeof(st->Addresses[0].Network), leaktest_vrf_names[vrf]);
	st->Addresses[0].VrfId = leaktest_vrf_ids[vrf];
	st->Addresses[0].AddressSize = (LeakTestAddress(st->Addresses[0].Address, leaktest_addresses[i]) ? 4 : 0);
	st->Addresses[0].Length = 24;
	st->NumVrfs = 1;
	StrCpy(st->Vrfs[0].Name, sizeof(st->Vrfs[0].Name), leaktest_vrf_names[vrf]);
	st->Vrfs[0].Id = leaktest_vrf_ids[vrf];
	st->Vrfs[0].Mtu = 1280;

	if (i == LEAKTEST_B)
	{
		CONTROL_NAT *n = &st->Nats[st->NumNats++];

		n->VrfId = leaktest_vrf_ids[LEAKTEST_BLUE];
		n->InsideSize = (LeakTestAddress(n->Inside, LEAKTEST_NAT_INSIDE) ? 4 : 0);
		n->InsideLength = LEAKTEST_NAT_LENGTH;
		n->OutsideSize = (LeakTestAddress(n->Outside, LEAKTEST_NAT_OUTSIDE) ? 4 : 0);
		n->OutsideLength = LEAKTEST_NAT_LENGTH;
	}

	st->Peers = ZeroMalloc(sizeof(CONTROL_PEER) * LEAKTEST_NUM_NODES);
	for (UINT j = 0;j < LEAKTEST_NUM_NODES;j++)
	{
		UINT other = leaktest_node_vrfs[j];
		CONTROL_PEER *p = &st->Peers[st->NumPeers];

		if (j == i || (LeakTestLeaks(other, vrf, with_leaks) == false && LeakTestLeaks(vrf, other, with_leaks) == false))
		{
			continue;
		}

		Zero(p, sizeof(CONTROL_PEER));
		StrCpy(p->Name, sizeof(p->Name), leaktest_names[j]);
		Copy(p->Key, nodes[j].Key.Public, PEER_KEY_SIZE);
		if (LeakTestLeaks(other, vrf, with_leaks))
		{
			LeakTestAddRoute(p, i, j, leaktest_addresses[j], 32);
			if (j == LEAKTEST_B)
			{
				LeakTestAddRoute(p, i, j, LEAKTEST_NAT_OUTSIDE, LEAKTEST_NAT_LENGTH);
			}
		}
		st->NumPeers++;
	}

	return st;
}

static void LeakTestFreeState(CONTROL_STATE *st)
{
	if (st != NULL)
	{
		Free(st->Peers);
		Free(st);
	}
}

//
// The tables
//

// The leaked routes of the state of node-s get next hops after those of its peers, node-r and node-b: each leads to
// its peer and carries the VRF that it goes into, while a route of a 1:1 NAT rule of a peer leads to that peer in the
// VRF of the route
static void LeakTestTables(LEAKTEST_CTX *ctx, LEAKTEST_NODE *nodes)
{
	CONTROL_STATE *st = LeakTestState(nodes, LEAKTEST_S, 1, true);
	// The next hops of the peers of node-s, in the order of its state: node-r, then node-b
	void *hops[2] = {&nodes[LEAKTEST_R], &nodes[LEAKTEST_B]};
	NODE_VRF_ROUTE routes[16];
	UCHAR addr[4];
	UINT shared = leaktest_vrf_ids[LEAKTEST_SHARED];

	Print("[tables]\n");

	if (LeakTestCheck(ctx, st->NumPeers == 2 && st->Peers[1].NumRoutes == 2, "The state of node-s has node-r and node-b as its peers, with the routes that red and blue leak",
		"%u peers", st->NumPeers) == false)
	{
		LeakTestFreeState(st);
		return;
	}

	// A route of node-b in shared of a 1:1 NAT rule, as SDN-6 gives it: no VRF of the peer
	CONTROL_ROUTE *r = &st->Peers[1].Routes[st->Peers[1].NumRoutes++];
	Zero(r, sizeof(CONTROL_ROUTE));
	r->VrfId = shared;
	r->AddressSize = (LeakTestAddress(r->Address, "10.77.0.0") ? 4 : 0);
	r->Length = 16;

	UINT num = NodeLeakRoutes(st, NULL);
	UINT nat = NodeNatRoutes(st, NULL);
	Zero(routes, sizeof(routes));
	bool counted = (num == 3 && nat == 1 && NodeLeakRoutes(st, routes) == 3);
	LeakTestCheck(ctx, counted && routes[0].VrfId == shared && routes[0].NextHop == 2 && routes[1].NextHop == 3 && routes[2].NextHop == 4 &&
		routes[2].Length == LEAKTEST_NAT_LENGTH,
		"The three routes that red and blue leak into shared go to next hops 2, 3 and 4, after the two peers; the route of the NAT rule stays with NodeNatRoutes",
		"%u leaked and %u NAT routes", num, nat);

	num += NodeNatRoutes(st, routes + num);
	NODE_VRF_TABLES *v = NodeLeakNewTables(st, routes, num, hops);
	if (LeakTestCheck(ctx, v != NULL && v->NumHops == 5 && v->HopVrfs != NULL, "The tables of the state, with a next hop for each leaked route",
		"%s", (v == NULL ? "NodeLeakNewTables failed" : "the next hops are wrong")) == false)
	{
		NodeFreeVrfTables(v);
		LeakTestFreeState(st);
		return;
	}

	NODE_VRF_TABLE *t = NodeGetVrfTable(v, shared);
	struct
	{
		char *Address;
		void *Peer;
		UINT Vrf;
	} want[] =
	{
		{"10.1.0.1", &nodes[LEAKTEST_R], leaktest_vrf_ids[LEAKTEST_RED]},
		{"10.2.0.1", &nodes[LEAKTEST_B], leaktest_vrf_ids[LEAKTEST_BLUE]},
		{"10.92.1.7", &nodes[LEAKTEST_B], leaktest_vrf_ids[LEAKTEST_BLUE]},
		{"10.77.1.1", &nodes[LEAKTEST_B], shared},
	};
	for (UINT i = 0;i < sizeof(want) / sizeof(want[0]);i++)
	{
		char what[MAX_SIZE];
		UINT hop = NODE_VRF_NONE;

		if (LeakTestAddress(addr, want[i].Address))
		{
			hop = NodeVrfLookup(t, addr, 4);
		}

		Format(what, sizeof(what), "In shared, %s leads to %s, and a packet to it goes into VRF %u", want[i].Address, ((LEAKTEST_NODE *)want[i].Peer)->Name, want[i].Vrf);
		LeakTestCheck(ctx, hop < v->NumHops && v->Hops[hop] == want[i].Peer && NodeLeakVrf(v, hop, shared) == want[i].Vrf, what,
			"next hop %u, VRF %u", hop, (hop < v->NumHops ? NodeLeakVrf(v, hop, shared) : 0));
	}

	NodeFreeVrfTables(v);
	LeakTestFreeState(st);
}

//
// The overlay
//

// A new empty data directory under the temp directory of the process, with a configuration store that runs no role
// on one worker
static void LeakTestNewDir(wchar_t *dir, UINT size, char *name)
{
	wchar_t tmp[MAX_PATH];
	wchar_t path[MAX_PATH];

	UniFormat(tmp, sizeof(tmp), L"leaktest_%S_%u", name, Rand32());
	ConbinePathW(dir, size, MsGetMyTempDirW(), tmp);
	MakeDirExW(dir);

	ConbinePathW(path, sizeof(path), dir, CS_FILE_NAME);
	CONFIG_STORE *s = CsOpen(path);
	if (s != NULL)
	{
		CsSetSetting(s, NODE_SETTING_ROLES, "none");
		CsSetSetting(s, NODE_SETTING_WORKERS, "1");
		CsClose(s);
	}
}

// Delete the files of a directory, then the directory, which holds no subdirectory
static void LeakTestDeleteFiles(wchar_t *dir)
{
	DIRLIST *d = EnumDirW(dir);

	for (UINT i = 0;d != NULL && i < d->NumFiles;i++)
	{
		wchar_t path[MAX_PATH];

		if (d->File[i]->Folder)
		{
			continue;
		}
		ConbinePathW(path, sizeof(path), dir, d->File[i]->FileNameW);
		FileDeleteW(path);
	}

	FreeDir(d);
	DeleteDirW(dir);
}

// The fake adapter of a host: it keeps each packet
static void LeakTestAdapter(NODE *n, void *param, UINT vrf_id, const UCHAR *packet, UINT size)
{
	LEAKTEST_NODE *t = (LEAKTEST_NODE *)param;
	LEAKTEST_TAKEN *p = ZeroMalloc(sizeof(LEAKTEST_TAKEN));

	p->VrfId = vrf_id;
	p->Size = MIN(size, (UINT)sizeof(p->Data));
	Copy(p->Data, packet, p->Size);

	AcquireSRWLockExclusive(&t->Lock);
	Add(t->Taken, p);
	ReleaseSRWLockExclusive(&t->Lock);
}

// The packets that the host of t took so far, and a copy of the one of index into p when p is not NULL
static UINT LeakTestTaken(LEAKTEST_NODE *t, UINT index, LEAKTEST_TAKEN *p)
{
	AcquireSRWLockShared(&t->Lock);
	UINT num = LIST_NUM(t->Taken);
	if (p != NULL && index < num)
	{
		Copy(p, LIST_DATA(t->Taken, index), sizeof(LEAKTEST_TAKEN));
	}
	ReleaseSRWLockShared(&t->Lock);

	return num;
}

// A UDP datagram of IPv4 from src to dst into buf (LEAKTEST_PACKET bytes): its size, 0 when an address is not IPv4. The
// header has no options, TTL 64, identification 0 and Don't Fragment.
static UINT LeakTestPacket(UCHAR *buf, char *src, char *dst)
{
	UCHAR *udp = buf + 20;
	UINT s, d;
	USHORT sum;

	Zero(buf, LEAKTEST_PACKET);
	if (LeakTestAddress(buf + 12, src) == false || LeakTestAddress(buf + 16, dst) == false)
	{
		return 0;
	}

	buf[0] = 0x45;
	WRITE_USHORT(buf + 2, LEAKTEST_PACKET);
	WRITE_USHORT(buf + 6, 0x4000);
	buf[8] = 64;
	buf[9] = IP_PROTO_UDP;
	sum = IpChecksum(buf, 20);
	Copy(buf + 10, &sum, 2);

	WRITE_USHORT(udp, 40000);
	WRITE_USHORT(udp + 2, 53);
	WRITE_USHORT(udp + 4, 8 + LEAKTEST_DATA);
	for (UINT i = 0;i < LEAKTEST_DATA;i++)
	{
		udp[8 + i] = (UCHAR)('A' + i);
	}
	Copy(&s, buf + 12, 4);
	Copy(&d, buf + 16, 4);
	sum = CalcChecksumForIPv4(s, d, IP_PROTO_UDP, udp, 8 + LEAKTEST_DATA, 0);
	if (sum == 0)
	{
		sum = 0xFFFF;
	}
	Copy(udp + 6, &sum, 2);

	return LEAKTEST_PACKET;
}

// The name of the VRF of the id id
static char *LeakTestVrfName(UINT id)
{
	for (UINT i = 0;i < LEAKTEST_NUM_VRFS;i++)
	{
		if (leaktest_vrf_ids[i] == id)
		{
			return leaktest_vrf_names[i];
		}
	}

	return "an unknown VRF";
}

// Apply the states of a Generation to every node, and wait until each has a session to each of its peers: want[i]
static bool LeakTestApply(LEAKTEST_NODE *nodes, UINT64 gen, bool with_leaks, UINT *want)
{
	bool applied = true;

	for (UINT i = 0;i < LEAKTEST_NUM_NODES;i++)
	{
		CONTROL_STATE *st = LeakTestState(nodes, i, gen, with_leaks);

		applied = NodeOverlayApply(nodes[i].Node, st) && applied;
		LeakTestFreeState(st);
	}

	UINT64 end = Tick64() + LEAKTEST_BOUND;
	while (applied)
	{
		bool all = true;

		for (UINT i = 0;i < LEAKTEST_NUM_NODES;i++)
		{
			NODE_OVERLAY_STATUS st;

			NodeOverlayGetStatus(nodes[i].Node, &st);
			if (st.Generation != gen || st.NumPeers != want[i] || st.NumLinks != want[i])
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
		SleepThread(LEAKTEST_POLL);
	}

	return false;
}

// Send one packet and check where it went within LEAKTEST_BOUND: to the host the send names, in the VRF of that host,
// as the packet the test builds for that side, or dropped by the node the send names
static void LeakTestSend(LEAKTEST_CTX *ctx, LEAKTEST_NODE *nodes, LEAKTEST_SEND *send, char *label)
{
	LEAKTEST_NODE *t = &nodes[send->From];
	UINT vrf_id = leaktest_vrf_ids[leaktest_node_vrfs[send->From]];
	UINT num_before[LEAKTEST_NUM_NODES];
	UINT64 dropped_before[LEAKTEST_NUM_NODES];
	UCHAR packet[LEAKTEST_PACKET], want[LEAKTEST_PACKET];
	char what[MAX_SIZE], outcome[MAX_SIZE];
	bool ok = false;

	for (UINT i = 0;i < LEAKTEST_NUM_NODES;i++)
	{
		NODE_OVERLAY_STATUS st;

		NodeOverlayGetStatus(nodes[i].Node, &st);
		num_before[i] = LeakTestTaken(&nodes[i], 0, NULL);
		dropped_before[i] = st.Dropped;
	}

	UINT size = LeakTestPacket(packet, send->Src, send->Dst);
	UINT want_size = (send->To != LEAKTEST_NONE ? LeakTestPacket(want, send->WantSrc, send->WantDst) : 0);
	if (send->To != LEAKTEST_NONE)
	{
		Format(what, sizeof(what), "%s: %s sends %s > %s in %s; %s takes it in %s as %s > %s", label, t->Name, send->Src, send->Dst, LeakTestVrfName(vrf_id),
			nodes[send->To].Name, leaktest_vrf_names[leaktest_node_vrfs[send->To]], send->WantSrc, send->WantDst);
	}
	else
	{
		Format(what, sizeof(what), "%s: %s sends %s > %s in %s; %s drops it", label, t->Name, send->Src, send->Dst, LeakTestVrfName(vrf_id), nodes[send->Dropper].Name);
	}

	NodeReaderOnline(t->Node, &t->Reader);
	NodeOverlayInput(t->Node, vrf_id, packet, size);
	NodeReaderOffline(&t->Reader);

	StrCpy(outcome, sizeof(outcome), "lost");
	for (UINT64 end = Tick64() + LEAKTEST_BOUND;Tick64() < end && StrCmp(outcome, "lost") == 0;)
	{
		for (UINT i = 0;i < LEAKTEST_NUM_NODES && StrCmp(outcome, "lost") == 0;i++)
		{
			LEAKTEST_TAKEN p;
			NODE_OVERLAY_STATUS st;

			if (LeakTestTaken(&nodes[i], num_before[i], &p) > num_before[i])
			{
				bool same = (want_size != 0 && p.Size == want_size && Cmp(p.Data, want, want_size) == 0);

				Format(outcome, sizeof(outcome), "taken by %s in %s, %s", nodes[i].Name, LeakTestVrfName(p.VrfId), (same ? "the packet expected" : "NOT the packet expected"));
				ok = (same && i == send->To && p.VrfId == leaktest_vrf_ids[leaktest_node_vrfs[i]]);
				continue;
			}

			NodeOverlayGetStatus(nodes[i].Node, &st);
			if (st.Dropped > dropped_before[i])
			{
				Format(outcome, sizeof(outcome), "dropped by %s", nodes[i].Name);
				ok = (send->To == LEAKTEST_NONE && i == send->Dropper);
			}
		}

		if (StrCmp(outcome, "lost") == 0)
		{
			SleepThread(1);
		}
	}

	LeakTestCheck(ctx, size != 0 && ok, what, "%s", outcome);
}

static void LeakTestOverlay(LEAKTEST_CTX *ctx, LEAKTEST_NODE *nodes, TRANSPORT *loopback)
{
	char what[MAX_SIZE];
	bool started = (loopback != NULL);
	// The sessions of each node: node-s with node-r and node-b, node-r with node-s and node-l
	UINT want_links[LEAKTEST_NUM_NODES] = {2, 2, 1, 1};
	UINT no_links[LEAKTEST_NUM_NODES] = {0, 0, 0, 0};

	Print("[overlay]\n");

	// The nodes and the fake adapters of their hosts, and their overlays without a control stream
	for (UINT i = 0;i < LEAKTEST_NUM_NODES && started;i++)
	{
		LEAKTEST_NODE *t = &nodes[i];
		NODE_OVERLAY_CONFIG c;

		LeakTestNewDir(t->Dir, sizeof(t->Dir), t->Name);
		t->Node = NewNode(t->Dir);
		NodeStart(t->Node);
		NodeReaderRegister(t->Node, &t->Reader);
		NodeReaderOffline(&t->Reader);

		Zero(&c, sizeof(c));
		c.Data = loopback;
		c.Key = &t->Key;
		c.Adapter = LeakTestAdapter;
		c.AdapterParam = t;
		Format(what, sizeof(what), "%s: its overlay runs without a control stream", t->Name);
		started = LeakTestCheck(ctx, NodeOverlayStart(t->Node, &c), what, "NodeOverlayStart failed");
	}

	if (started)
	{
		started = LeakTestCheck(ctx, LeakTestApply(nodes, 1, true, want_links),
			"The four nodes apply the states of the leaks, and every node has a session to the nodes of the VRFs that leak into its VRF or that its VRF leaks into",
			"the states or the sessions did not come up");
	}

	for (UINT k = 0;started && k < sizeof(leaktest_sends) / sizeof(leaktest_sends[0]);k++)
	{
		LeakTestSend(ctx, nodes, &leaktest_sends[k], "leaks");
	}

	// The next Generation without the leaks: the nodes share no VRF, so they have no peers, and nothing goes anywhere
	if (started && LeakTestCheck(ctx, LeakTestApply(nodes, 2, false, no_links), "The nodes apply a Generation without the leaks, and every session closes",
		"the states or the sessions did not go"))
	{
		LEAKTEST_SEND gone[] =
		{
			{LEAKTEST_R, "10.1.0.1", "10.10.0.1", LEAKTEST_NONE, NULL, NULL, LEAKTEST_R},
			{LEAKTEST_S, "10.10.0.1", "10.92.1.7", LEAKTEST_NONE, NULL, NULL, LEAKTEST_S},
		};

		for (UINT k = 0;k < sizeof(gone) / sizeof(gone[0]);k++)
		{
			LeakTestSend(ctx, nodes, &gone[k], "no leaks");
		}
	}

	for (UINT i = 0;i < LEAKTEST_NUM_NODES;i++)
	{
		NODE_OVERLAY_STATUS st;

		if (nodes[i].Node == NULL)
		{
			continue;
		}
		NodeOverlayGetStatus(nodes[i].Node, &st);
		Print("  %s: forwarded %I64u, delivered %I64u, dropped %I64u, VRFs %u\n", nodes[i].Name, st.Forwarded, st.Delivered, st.Dropped, st.NumVrfs);
	}
}

// leak: route leaking with route targets in the data plane, on the tables and over the overlay
RANZ_TEST("leak", leak_test, "Route leaking: the routes that a VRF leaks lead to their peer and carry the VRF they go into; over the overlay a shared-services VRF reaches red and blue and they reach it, red and blue do not reach each other, a one-way leak carries nothing, a 1:1 NAT prefix leaks, and without the leaks nothing passes.");
void leak_test(UINT num, char **arg)
{
	LEAKTEST_CTX ctx;
	LEAKTEST_NODE *nodes = ZeroMalloc(sizeof(LEAKTEST_NODE) * LEAKTEST_NUM_NODES);
	TRANSPORT *loopback = TransportLoopbackNew("loopback", 0, false);
	HANDLE done = CreateEventW(NULL, TRUE, FALSE, NULL);
	HANDLE watchdog = (done != NULL ? CreateThread(NULL, 0, LeakTestWatchdog, done, 0, NULL) : NULL);
	UCHAR scalar[PEER_KEY_SIZE];
	bool keys = true;

	Zero(&ctx, sizeof(ctx));

	Print("LEAK test: route leaking of the node's data plane, on the forwarding tables and over the overlay of in-process nodes\n");

	// The nodes with their static keys
	for (UINT i = 0;i < LEAKTEST_NUM_NODES;i++)
	{
		LEAKTEST_NODE *t = &nodes[i];

		t->Name = leaktest_names[i];
		InitializeSRWLock(&t->Lock);
		t->Taken = NewListFast(NULL);
		for (UINT j = 0;j < PEER_KEY_SIZE;j++)
		{
			scalar[j] = (UCHAR)(7 + PEER_KEY_SIZE * i + j);
		}
		keys = PeerKeyFromScalar(&t->Key, scalar) && keys;
	}
	Zero(scalar, sizeof(scalar));

	if (LeakTestCheck(&ctx, keys, "The static keys of the four nodes", "PeerKeyFromScalar failed"))
	{
		LeakTestTables(&ctx, nodes);
		LeakTestOverlay(&ctx, nodes, loopback);
	}

	for (UINT i = 0;i < LEAKTEST_NUM_NODES;i++)
	{
		LEAKTEST_NODE *t = &nodes[i];
		wchar_t log_dir[MAX_PATH];

		if (t->Node != NULL)
		{
			NodeReaderUnregister(t->Node, &t->Reader);
			NodeStop(t->Node);
			FreeNode(t->Node);
			ConbinePathW(log_dir, sizeof(log_dir), t->Dir, NODE_LOG_DIR_NAME);
			LeakTestDeleteFiles(log_dir);
			LeakTestDeleteFiles(t->Dir);
		}
		PeerKeyClose(&t->Key);

		for (UINT k = 0;k < LIST_NUM(t->Taken);k++)
		{
			Free(LIST_DATA(t->Taken, k));
		}
		ReleaseList(t->Taken);
	}

	TransportLoopbackFree(loopback);
	Free(nodes);

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
		Print("LEAK TEST OK\n");
	}
	else
	{
		Print("LEAK TEST FAILED (%u of %u checks failed)\n", ctx.NumFailed, ctx.NumChecks);
	}
}
