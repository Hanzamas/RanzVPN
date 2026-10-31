// peeringtest.c
// Named BGP peering test of vpntest ("peering" command, SDN-77 #357)
//
// The BGP peering of the standard mode (Cedar/NodePeering.c) on the harness with three Nodes of the ticket: three
// in-process nodes, each with its own sidecar ranz bgp (ranz.exe next to vpntest, GoBGP), which listens on TCP 179 of the
// address of its node on the network that the operator trusts, 127.0.0.2 for node-a, 127.0.0.3 for node-b and 127.0.0.4
// for node-c, and connects from there. The test applies the desired states of the nodes itself (NodeOverlayApply), as the
// Controller compiles them (controller/internal/desired/peering.go): the settings of the sidecar of each node with the
// LAN subnets that it announces, and for each peer the address of its sidecar, the hold time of their session, its VRFs
// and what the peer may announce there, its addresses and its LAN subnets; with the LAN subnets behind each node, which lead
// to its host, and in a VRF that does not peer by BGP the LAN subnet of each peer there as its route, as the Controller
// gives them (desired/topology.go; SDN-19). Node-a is a member of VRF red (101), node-b and
// node-c of red and of blue (102), and 192.168.1.0/24 is the LAN of node-a in red and the LAN of node-b in blue. Fake
// adapters stand in for the hosts, and the in-process loopback transport carries the packets between the nodes: on one
// host the tunnel endpoints of three nodes would all send from 127.0.0.1, and a link of kind vxlan names its peer by the
// source address alone (NodeLink.c), so the links of the harness are of kind noise. The peering fills the forwarding
// tables whatever the kind of the links, which only carry what the tables route.
// - The full mesh: each node starts its sidecar, whose pipe has the strict DACL, and has a session established with each
//   other node; each learns exactly what the others announce in the VRFs that they share, each prefix in its VRF, and the
//   forwarding table of the VRF leads the LAN of each peer to that peer, so a packet of each host to the LAN of each other
//   node arrives at the host of that node, in that VRF. The adapter of the host of each node takes the LAN of each other node
//   in a VRF that the two share as a route of that node there, the learned ones as the others, as the adapters of the VRFs of
//   the client role take a state and put its routes into the Windows routing table through IP Helper (NodeClient.c,
//   NodeVrfAdapter.c). The two LANs 192.168.1.0/24 stay apart: node-c reaches the one of node-a in red and the one of node-b
//   in blue, and node-a, which is in no VRF blue, learns nothing of blue.
// - A session from 127.0.0.9, an address that the Controller did not name, is refused, and node-a counts it.
// - The report on the control stream: the report that the control stream of each node sends holds the peers of its sidecar,
//   the state of each session, the prefixes learned from each and the sessions refused. Written as the client writes it, it is
//   one Telemetry message whose peering has them by the fields of the schema, and a report that did not change is not written
//   again.
// - Red stops peering (Generation 2): node-a, in no VRF that peers any more, stops its sidecar, and no node holds a route of
//   red that it learned by BGP any more; node-b and node-c keep their session in blue. The Controller gives the LAN subnets
//   of red as routes of their nodes again, so the packets to a LAN of red go by those. Red peers again (Generation 3):
//   node-a starts a new sidecar and the mesh converges again.
// - The sidecar of node-c stops answering, as a host that loses power: its threads are suspended. Node-a and node-b remove
//   its routes within the hold time of the sessions, from their forwarding tables and from the adapters of their hosts, and
//   keep each other's; once it answers again, the mesh converges.
// - Node-c stops: its sidecar ends the sessions, and node-a and node-b remove its routes within the hold time.
// The findings of the review of SDN-77 (SDN-77-R1, #531), with an extra LAN subnet in red of node-b (192.168.5.0/24) and of
// node-a (192.168.6.0/24 and 192.168.7.0/24), which the Controller may name in the accept lists and the announcements of a
// Generation:
// - The window of an apply: the apply of a Generation at node-a holds in the adapter of its host, where the overlay runs the
//   Generation already and the BGP peering does not have it yet; meanwhile node-b announces its extra LAN, and later withdraws it,
//   so that the learned and the withdrawn message reach node-a in the window. The worker of node-a meets the apply, and after both
//   the forwarding tables of the Generation have the change.
// - A failed copy and a failed rebuild: node-b announces its extra LAN while the next copy of the state for a rebuild at node-a
//   fails, and then the next rebuild (NodePeeringFailNext); node-a logs and counts each, keeps the change, and a later pass builds
//   the forwarding tables of the Generation with it.
// - A narrower accept list: a Generation that takes the extra LAN of node-b from the accept lists while node-b still announces it
//   has no route to it in the tables that node-a builds with it, though its sidecar has not withdrawn the route yet.
// - A hostile peer: node-b announces more specific prefixes of its LAN in red, which no accept list holds; no node learns any of
//   them, and every other route of every peer and VRF is learned.
// - A failed send and a large mesh: the sidecar of node-a stops answering, and a Generation gives node-a 200 more peers, whose
//   peers messages fill its pipe, a new extra LAN to announce and an extra LAN to withdraw. The send fails, node-a ends the sidecar
//   and starts another, which has the peers, the announced prefixes and not the withdrawn one of the Generation in force; node-a
//   holds and counts its 202 peers, each of which the new sidecar names.
// - A hung sidecar: node-c notices that its sidecar does not answer, ends it, and its learned routes go; another starts.
// - The halt: the sidecar of node-b stops answering while its worker sends peers, and NodeOverlayStop of node-b under the lock of
//   the node returns at once; the sidecar exits after the time that the node gives it.
// Print "PEERING TEST OK" only when every check passes. .github/scripts/bgp-peering.ps1 builds ranz.exe and runs it.

#include "testlist.h"

#include "Cedar/Cedar.h"
#include "Cedar/ConfigStore.h"
#include "Cedar/Node.h"
#include "Cedar/NodePeering.h"

#include "Mayaqua/Encrypt.h"
#include "Mayaqua/FileIO.h"
#include "Mayaqua/Internat.h"
#include "Mayaqua/IpAddr.h"
#include "Mayaqua/Kernel.h"
#include "Mayaqua/Memory.h"
#include "Mayaqua/Microsoft.h"
#include "Mayaqua/Object.h"
#include "Mayaqua/Str.h"
#include "Mayaqua/TcpIp.h"
#include "Mayaqua/Tick64.h"

#include "Core/Control.h"
#include "Core/Transport.h"

#include <TlHelp32.h>
#include <WS2tcpip.h>

#include <stdio.h>

#define	PEERINGTEST_BUDGET		600000		// The whole test ends within this time, or the watchdog ends the process (ms)
#define	PEERINGTEST_BOUND		60000		// A bounded wait on observable state (ms)
#define	PEERINGTEST_ARRIVE		10000		// A packet that the overlay took arrives within this time (ms)
#define	PEERINGTEST_QUIET		300			// A host that gets nothing gets nothing within this time (ms)
#define	PEERINGTEST_POLL		50			// Poll interval of observable state (ms)
#define	PEERINGTEST_SIZE		100			// The size of a test packet
#define	PEERINGTEST_TEXT		4096		// The size of the text of the report of a node
#define	PEERINGTEST_WIRE		4096		// A frame of the report of a node on the control stream at most
#define	PEERINGTEST_ASN			4200000000U	// The AS of the overlay, one for every node (intent.PeeringASN)
#define	PEERINGTEST_HOLD		9			// The BGP hold time of the sessions in s, as the VRFs of the Intent name it
#define	PEERINGTEST_GRACE		1000		// What the sidecar and the node take past the hold time to remove the routes (ms)
#define	PEERINGTEST_PORT		179			// The BGP port of the sidecars
#define	PEERINGTEST_STRANGER	"127.0.0.9"	// An address that the Controller did not name
#define	PEERINGTEST_RED			101			// The id of VRF red ...
#define	PEERINGTEST_BLUE		102			// ... and of VRF blue
#define	PEERINGTEST_LENGTH		24			// The prefix length of the Networks and of the LAN subnets
#define	PEERINGTEST_EXIT		15000		// The sidecar of a peering that stopped exits within this time: what the node gives it, and a grace (ms)
#define	PEERINGTEST_HALT		4000		// NodeOverlayStop of a node whose sidecar does not answer returns within this time (ms)
#define	PEERINGTEST_DUMMIES		200			// The peers that a large mesh adds to a node: no node, and their sidecars never answer
#define	PEERINGTEST_ACCEPTS		31			// ... each with as many prefixes to accept from it, so that its peers fill a pipe
#define	PEERINGTEST_HOSTILE		12			// The more specific prefixes of its LAN that a hostile node-b announces
#define	PEERINGTEST_WINDOWS		2			// The windows of an apply at node-a (PeeringTestWindow)

// The nodes
#define	PEERINGTEST_A			0
#define	PEERINGTEST_B			1
#define	PEERINGTEST_C			2
#define	PEERINGTEST_NODES		3

static char *peeringtest_names[PEERINGTEST_NODES] = {"node-a", "node-b", "node-c"};

// The address of each node on the network that the operator trusts: its sidecar listens on TCP 179 there and connects from
// there, and it is the router id of the node, as the Controller makes one of an IPv4 tunnel endpoint (intent.RouterID)
static char *peeringtest_addrs[PEERINGTEST_NODES] = {"127.0.0.2", "127.0.0.3", "127.0.0.4"};

// The VRFs of the test in name order, blue before red, and in the order of their id
static const UINT peeringtest_by_name[2] = {PEERINGTEST_BLUE, PEERINGTEST_RED};
static const UINT peeringtest_by_id[2] = {PEERINGTEST_RED, PEERINGTEST_BLUE};

// A node in a VRF: its address there, and the LAN subnet behind it there with a host of that subnet
typedef struct PEERINGTEST_MEMBER
{
	UINT Node;
	UINT VrfId;
	char *Address;
	char *Lan;
	char *LanHost;
} PEERINGTEST_MEMBER;

// The members of the VRFs, by node, then VRF id: the LAN 192.168.1.0/24 is the one of node-a in red and of node-b in blue
static PEERINGTEST_MEMBER peeringtest_members[] =
{
	{PEERINGTEST_A, PEERINGTEST_RED, "10.0.0.1", "192.168.1.0", "192.168.1.10"},
	{PEERINGTEST_B, PEERINGTEST_RED, "10.0.0.2", "192.168.2.0", "192.168.2.10"},
	{PEERINGTEST_B, PEERINGTEST_BLUE, "10.1.0.2", "192.168.1.0", "192.168.1.10"},
	{PEERINGTEST_C, PEERINGTEST_RED, "10.0.0.3", "192.168.3.0", "192.168.3.10"},
	{PEERINGTEST_C, PEERINGTEST_BLUE, "10.1.0.3", "192.168.4.0", "192.168.4.10"},
};

#define	PEERINGTEST_MEMBERS		(sizeof(peeringtest_members) / sizeof(peeringtest_members[0]))

// An extra LAN subnet of a node in red, which a Generation may name in the accept lists of the peers of the node (Accepted) and
// among the LAN subnets that the node announces and has behind it (Announced), each on its own (SDN-77-R1, #531)
typedef struct PEERINGTEST_EXTRA
{
	UINT Node;
	char *Lan;
	char *LanHost;
} PEERINGTEST_EXTRA;

#define	PEERINGTEST_EXTRA_B		0			// The extra LAN of node-b: the window of an apply and the narrower accept list
#define	PEERINGTEST_EXTRA_A6	1			// The extra LANs of node-a: the one that a failed send withdraws ...
#define	PEERINGTEST_EXTRA_A7	2			// ... and the one that it announces

static PEERINGTEST_EXTRA peeringtest_extras[] =
{
	{PEERINGTEST_B, "192.168.5.0", "192.168.5.10"},
	{PEERINGTEST_A, "192.168.6.0", "192.168.6.10"},
	{PEERINGTEST_A, "192.168.7.0", "192.168.7.10"},
};

#define	PEERINGTEST_EXTRAS		(sizeof(peeringtest_extras) / sizeof(peeringtest_extras[0]))

// A route of a peer in a state that the adapter of a host took, with the node of that peer
typedef struct PEERINGTEST_HOST_ROUTE
{
	UINT Node;							// The node of the peer, PEERINGTEST_NODES for a peer of another name
	CONTROL_ROUTE Route;
} PEERINGTEST_HOST_ROUTE;

#define	PEERINGTEST_HOST_ROUTES	((PEERINGTEST_NODES - 1) * CONTROL_MAX_ROUTES)

// One node and the fake adapter of its host, which keeps the last packet that the host took and the routes of the peers in
// the last state that it took
typedef struct PEERINGTEST_NODE
{
	wchar_t Dir[MAX_PATH];				// Its data directory
	PEER_KEY Key;						// Its static key
	NODE *Node;
	NODE_READER Reader;					// The test thread as a reader of the node's tables, online while it looks up or sends
	bool Gone;							// Its sidecar does not answer, or it stopped: the other nodes have no route of it
	bool Stopped;						// It stopped
	SRWLOCK Lock;						// LastVrf, Last, LastSize, NumHostRoutes and HostRoutes
	volatile LONG Arrivals;				// Packets that the host took
	UINT LastVrf;						// The VRF of the last one ...
	UCHAR Last[PEERINGTEST_SIZE * 2];	// ... and the packet, as much as fits
	UINT LastSize;
	UINT NumHostRoutes;					// The routes of the peers in the last state that the adapter took
	PEERINGTEST_HOST_ROUTE HostRoutes[PEERINGTEST_HOST_ROUTES];
	volatile UINT64 Hold;				// The Generation whose apply the adapter holds, 0 for none (PeeringTestHostState) ...
	HANDLE Held;						// ... which sets this once it holds it ...
	HANDLE Release;						// ... until this is set
} PEERINGTEST_NODE;

// A thread of a sidecar that the test suspended
typedef struct PEERINGTEST_THREAD
{
	DWORD Id;
	HANDLE Handle;
} PEERINGTEST_THREAD;

// The test
typedef struct PEERINGTEST_CTX
{
	UINT NumChecks;
	UINT NumFailed;
	TRANSPORT *Loopback;				// The in-process loopback transport of the nodes
	PEERINGTEST_NODE Nodes[PEERINGTEST_NODES];
	UINT64 Generation;					// The Generation that the nodes run ...
	bool RedPeers;						// ... and whether red peers by BGP in it
	bool Accepted[PEERINGTEST_EXTRAS];	// ... whether the accept lists of the peers of the node of each extra LAN hold it,
	bool Announced[PEERINGTEST_EXTRAS];	// ... whether that node announces it and has it behind it,
	bool Hostile;						// ... whether node-b announces more specific prefixes of its LAN in red,
	UINT NumDummies[PEERINGTEST_NODES];	// ... and the peers of a large mesh that each node has
	UINT Starts[PEERINGTEST_NODES];		// The sidecars that each node started so far
	UINT NumWindows;					// The windows of an apply whose apply the worker of node-a met (PeeringTestHeld), each with
	UINT64 WindowFrom[PEERINGTEST_WINDOWS];	// ... the Generation of its rebuild, which went out of force in the window,
	UINT64 WindowTo[PEERINGTEST_WINDOWS];	// ... and the one that the apply put in force
	UINT64 Failed;						// The Generation whose first copy and rebuild at node-a failed (PeeringTestFailed), 0 for none
	bool Ran;							// The nodes started their sidecars
	UINT Seq;							// The data of the next test packet
} PEERINGTEST_CTX;

// An apply of a state to a node on a thread of its own, which the adapter of its host holds (PeeringTestHeld)
typedef struct PEERINGTEST_APPLY
{
	NODE *Node;
	CONTROL_STATE *State;
	bool Applied;
} PEERINGTEST_APPLY;

static bool PeeringTestCheck(PEERINGTEST_CTX *ctx, bool ok, char *what, char *fmt, ...) RANZ_PRINTF_FORMAT(4, 5);
static bool PeeringTestCheck(PEERINGTEST_CTX *ctx, bool ok, char *what, char *fmt, ...)
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

// The watchdog: a native thread that ends a run that hangs, so that a session that never comes is a failed test instead of
// a hung CI step
static DWORD WINAPI PeeringTestWatchdog(LPVOID param)
{
	char msg[MAX_SIZE];
	DWORD written = 0;

	if (WaitForSingleObject((HANDLE)param, PEERINGTEST_BUDGET) != WAIT_TIMEOUT)
	{
		return 0;
	}

	int len = snprintf(msg, sizeof(msg), "PEERING TEST FAILED (did not finish within %u ms)\n", PEERINGTEST_BUDGET);
	if (len > 0)
	{
		WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), msg, (DWORD)MIN((UINT)len, (UINT)sizeof(msg) - 1), &written, NULL);
	}

	TerminateProcess(GetCurrentProcess(), 1);

	return 0;
}

//
// The scenario
//

// The IPv4 address of a text into addr, 4 bytes: false for anything else
static bool PeeringTestIp(UCHAR *addr, char *str)
{
	IP ip;

	Zero(addr, 4);
	if (StrToIP(&ip, str) == false || IsIP4(&ip) == false)
	{
		return false;
	}

	Copy(addr, IPV4(ip.address), 4);
	return true;
}

// The name of a VRF of the test
static char *PeeringTestVrfName(UINT vrf_id)
{
	return (vrf_id == PEERINGTEST_RED ? "red" : (vrf_id == PEERINGTEST_BLUE ? "blue" : "?"));
}

// Node i in the VRF vrf_id, NULL when it is not a member of it
static PEERINGTEST_MEMBER *PeeringTestMember(UINT i, UINT vrf_id)
{
	for (UINT k = 0;k < PEERINGTEST_MEMBERS;k++)
	{
		if (peeringtest_members[k].Node == i && peeringtest_members[k].VrfId == vrf_id)
		{
			return &peeringtest_members[k];
		}
	}

	return NULL;
}

// Whether the nodes of the VRF vrf_id peer by BGP in the Generation that runs: blue always, red unless the test stopped it
static bool PeeringTestPeers(PEERINGTEST_CTX *ctx, UINT vrf_id)
{
	return (vrf_id == PEERINGTEST_BLUE || (vrf_id == PEERINGTEST_RED && ctx->RedPeers));
}

// Whether nodes i and j share a VRF, or with peering one that peers by BGP
static bool PeeringTestShare(PEERINGTEST_CTX *ctx, UINT i, UINT j, bool peering)
{
	for (UINT k = 0;k < 2;k++)
	{
		UINT vrf_id = peeringtest_by_id[k];

		if (PeeringTestMember(i, vrf_id) != NULL && PeeringTestMember(j, vrf_id) != NULL && (peering == false || PeeringTestPeers(ctx, vrf_id)))
		{
			return true;
		}
	}

	return false;
}

// The index of node j among the peers of node i, the next hop of its routes in the forwarding tables of node i: every two
// nodes share red, so the peers of a node are the other two, in name order
static UINT PeeringTestHop(UINT i, UINT j)
{
	return (j < i ? j : j - 1);
}

// What the next hop hop of the forwarding tables of node i is, in words
static char *PeeringTestHopName(UINT i, UINT hop)
{
	if (hop == NODE_VRF_LOCAL)
	{
		return "its host";
	}
	if (hop == NODE_VRF_NONE)
	{
		return "no route";
	}
	if (hop < PEERINGTEST_NODES - 1)
	{
		return peeringtest_names[hop < i ? hop : hop + 1];
	}

	return "another next hop";
}

// A route of the control protocol: the IPv4 prefix addr/length of the VRF vrf_id
static void PeeringTestRoute(CONTROL_ROUTE *r, UINT vrf_id, char *addr, UINT length)
{
	Zero(r, sizeof(CONTROL_ROUTE));
	r->VrfId = vrf_id;
	r->AddressSize = 4;
	r->Length = length;
	PeeringTestIp(r->Address, addr);
}

// The address of the member m, as the control protocol carries it
static void PeeringTestAddress(CONTROL_ADDRESS *a, PEERINGTEST_MEMBER *m)
{
	Zero(a, sizeof(CONTROL_ADDRESS));
	StrCpy(a->Network, sizeof(a->Network), PeeringTestVrfName(m->VrfId));
	a->VrfId = m->VrfId;
	a->AddressSize = 4;
	a->Length = PEERINGTEST_LENGTH;
	PeeringTestIp(a->Address, m->Address);
}

// Whether the extra LAN k is in the Generation that runs, only while red peers by BGP: as one that its node announces and has
// behind it (announced), or as one that the accept lists of its peers hold
static bool PeeringTestExtra(PEERINGTEST_CTX *ctx, UINT k, bool announced)
{
	return (ctx->RedPeers && (announced ? ctx->Announced[k] : ctx->Accepted[k]));
}

// The desired state of node i in the Generation that runs, as the Controller compiles it: its VRFs in name order, each with a
// link of kind noise in the harness and the peering of the Generation, and its address in each, in the order of their
// Network, which has the name of the VRF; the LAN subnets behind it, by VRF id; while a VRF of it peers by BGP, the settings
// of its sidecar and the LAN subnets that it announces there; and the other two nodes as its peers in name order, each with
// its addresses in the VRFs that the two share, its LAN subnet in each of those that does not peer by BGP as its route, and
// while one of those peers by BGP, the address of its sidecar, the hold time, the VRFs of their session and what it may
// announce there, its address as a host route and its LAN subnet in each. The extra LANs in red of the Generation go with the
// LAN of their node in red, the more specific prefixes of a hostile node-b with what it announces, and the peers of a large
// mesh after the nodes. PeeringTestFreeState frees it.
static CONTROL_STATE *PeeringTestState(PEERINGTEST_CTX *ctx, UINT i)
{
	CONTROL_STATE *st = ZeroMalloc(sizeof(CONTROL_STATE));
	bool peers = false;

	st->Generation = ctx->Generation;
	StrCpy(st->Name, sizeof(st->Name), peeringtest_names[i]);

	for (UINT k = 0;k < 2;k++)
	{
		PEERINGTEST_MEMBER *m = PeeringTestMember(i, peeringtest_by_name[k]);

		if (m == NULL)
		{
			continue;
		}

		CONTROL_VRF *v = &st->Vrfs[st->NumVrfs++];
		StrCpy(v->Name, sizeof(v->Name), PeeringTestVrfName(m->VrfId));
		v->Id = m->VrfId;
		v->Link = CONTROL_LINK_NOISE;
		v->Peering = PeeringTestPeers(ctx, m->VrfId);
		peers = peers || v->Peering;

		PeeringTestAddress(&st->Addresses[st->NumAddresses++], m);
	}

	// The LAN subnets behind the node in its VRFs, which lead to its host, whether a VRF peers by BGP or not (SDN-19), and its
	// extra LANs in red that it announces
	for (UINT k = 0;k < 2;k++)
	{
		PEERINGTEST_MEMBER *m = PeeringTestMember(i, peeringtest_by_id[k]);

		if (m == NULL)
		{
			continue;
		}

		PeeringTestRoute(&st->LanSubnets[st->NumLanSubnets++], m->VrfId, m->Lan, PEERINGTEST_LENGTH);
		for (UINT e = 0;e < PEERINGTEST_EXTRAS && m->VrfId == PEERINGTEST_RED;e++)
		{
			if (peeringtest_extras[e].Node == i && PeeringTestExtra(ctx, e, true))
			{
				PeeringTestRoute(&st->LanSubnets[st->NumLanSubnets++], PEERINGTEST_RED, peeringtest_extras[e].Lan, PEERINGTEST_LENGTH);
			}
		}
	}

	if (peers)
	{
		CONTROL_PEERING *own = ZeroMalloc(sizeof(CONTROL_PEERING));

		own->Asn = PEERINGTEST_ASN;
		PeeringTestIp(own->RouterId, peeringtest_addrs[i]);
		PeeringTestIp(own->Address, peeringtest_addrs[i]);
		own->AddressSize = 4;
		for (UINT k = 0;k < 2;k++)
		{
			PEERINGTEST_MEMBER *m = PeeringTestMember(i, peeringtest_by_id[k]);

			if (m == NULL || PeeringTestPeers(ctx, m->VrfId) == false)
			{
				continue;
			}

			PeeringTestRoute(&own->Announce[own->NumAnnounce++], m->VrfId, m->Lan, PEERINGTEST_LENGTH);
			if (m->VrfId != PEERINGTEST_RED)
			{
				continue;
			}

			// A hostile node-b announces more specific prefixes of its LAN in red too, which no accept list holds
			for (UINT h = 1;i == PEERINGTEST_B && ctx->Hostile && h <= PEERINGTEST_HOSTILE;h++)
			{
				char addr[MAX_SIZE];

				Format(addr, sizeof(addr), "192.168.2.%u", h * 16);
				PeeringTestRoute(&own->Announce[own->NumAnnounce++], PEERINGTEST_RED, addr, 28);
			}
			for (UINT e = 0;e < PEERINGTEST_EXTRAS;e++)
			{
				if (peeringtest_extras[e].Node == i && PeeringTestExtra(ctx, e, true))
				{
					PeeringTestRoute(&own->Announce[own->NumAnnounce++], PEERINGTEST_RED, peeringtest_extras[e].Lan, PEERINGTEST_LENGTH);
				}
			}
		}
		st->Peering = own;
	}

	st->Peers = ZeroMalloc(sizeof(CONTROL_PEER) * (PEERINGTEST_NODES - 1 + ctx->NumDummies[i]));
	for (UINT j = 0;j < PEERINGTEST_NODES;j++)
	{
		if (j == i || PeeringTestShare(ctx, i, j, false) == false)
		{
			continue;
		}

		CONTROL_PEER *cp = &st->Peers[st->NumPeers++];
		StrCpy(cp->Name, sizeof(cp->Name), peeringtest_names[j]);
		Copy(cp->Key, ctx->Nodes[j].Key.Public, PEER_KEY_SIZE);

		for (UINT k = 0;k < 2;k++)
		{
			if (PeeringTestMember(i, peeringtest_by_id[k]) != NULL && PeeringTestMember(j, peeringtest_by_id[k]) != NULL)
			{
				cp->VrfIds[cp->NumVrfs++] = peeringtest_by_id[k];
			}
		}
		for (UINT k = 0;k < 2;k++)
		{
			PEERINGTEST_MEMBER *m = PeeringTestMember(j, peeringtest_by_name[k]);

			if (m != NULL && PeeringTestMember(i, m->VrfId) != NULL)
			{
				PeeringTestAddress(&cp->Addresses[cp->NumAddresses++], m);
			}
		}

		// In a VRF of the two that does not peer by BGP, the Controller gives the LAN subnet of the peer there as its route, but
		// for a prefix that node i has behind it there too (intent.GatewayRoutes; SDN-19)
		for (UINT k = 0;k < 2;k++)
		{
			PEERINGTEST_MEMBER *m = PeeringTestMember(j, peeringtest_by_id[k]);
			PEERINGTEST_MEMBER *own = PeeringTestMember(i, peeringtest_by_id[k]);

			if (m != NULL && own != NULL && PeeringTestPeers(ctx, m->VrfId) == false && StrCmp(m->Lan, own->Lan) != 0)
			{
				PeeringTestRoute(&cp->Routes[cp->NumRoutes++], m->VrfId, m->Lan, PEERINGTEST_LENGTH);
			}
		}

		if (PeeringTestShare(ctx, i, j, true) == false)
		{
			continue;
		}

		CONTROL_PEER_PEERING *pp = ZeroMalloc(sizeof(CONTROL_PEER_PEERING));
		PeeringTestIp(pp->Address, peeringtest_addrs[j]);
		pp->AddressSize = 4;
		pp->HoldTime = PEERINGTEST_HOLD;
		for (UINT k = 0;k < 2;k++)
		{
			PEERINGTEST_MEMBER *m = PeeringTestMember(j, peeringtest_by_id[k]);

			if (m == NULL || PeeringTestMember(i, m->VrfId) == NULL || PeeringTestPeers(ctx, m->VrfId) == false)
			{
				continue;
			}

			pp->VrfIds[pp->NumVrfs++] = m->VrfId;
			PeeringTestRoute(&pp->Accept[pp->NumAccept++], m->VrfId, m->Address, 32);
			PeeringTestRoute(&pp->Accept[pp->NumAccept++], m->VrfId, m->Lan, PEERINGTEST_LENGTH);
			for (UINT e = 0;e < PEERINGTEST_EXTRAS && m->VrfId == PEERINGTEST_RED;e++)
			{
				if (peeringtest_extras[e].Node == j && PeeringTestExtra(ctx, e, false))
				{
					PeeringTestRoute(&pp->Accept[pp->NumAccept++], PEERINGTEST_RED, peeringtest_extras[e].Lan, PEERINGTEST_LENGTH);
				}
			}
		}
		cp->Peering = pp;
	}

	// The peers of a large mesh while red peers: no node, and their sidecars at 127.0.1.1 and up never answer. Each may announce
	// PEERINGTEST_ACCEPTS prefixes in red, so that the peers messages of the node fill more than its pipe holds.
	for (UINT d = 0;d < ctx->NumDummies[i] && ctx->RedPeers;d++)
	{
		CONTROL_PEER *cp = &st->Peers[st->NumPeers++];
		CONTROL_PEER_PEERING *pp = ZeroMalloc(sizeof(CONTROL_PEER_PEERING));
		char addr[MAX_SIZE];

		Format(cp->Name, sizeof(cp->Name), "dummy-%u", d);
		cp->Key[2] = (UCHAR)(d >> 8);
		cp->Key[3] = (UCHAR)d;
		cp->Key[PEER_KEY_SIZE - 1] = 1;
		cp->NumVrfs = 1;
		cp->VrfIds[0] = PEERINGTEST_RED;

		Format(addr, sizeof(addr), "127.0.1.%u", d + 1);
		PeeringTestIp(pp->Address, addr);
		pp->AddressSize = 4;
		pp->HoldTime = PEERINGTEST_HOLD;
		pp->NumVrfs = 1;
		pp->VrfIds[0] = PEERINGTEST_RED;
		for (UINT a = 0;a < PEERINGTEST_ACCEPTS;a++)
		{
			Format(addr, sizeof(addr), "172.16.%u.%u", d, a * 8);
			PeeringTestRoute(&pp->Accept[pp->NumAccept++], PEERINGTEST_RED, addr, 29);
		}
		cp->Peering = pp;
	}

	return st;
}

static void PeeringTestFreeState(CONTROL_STATE *st)
{
	for (UINT i = 0;i < st->NumPeers;i++)
	{
		Free(st->Peers[i].Peering);
	}

	Free(st->Peers);
	Free(st->Peering);
	Free(st);
}

//
// The nodes
//

// A new empty data directory under the temp directory of the process, with a configuration store that runs no role on one
// worker
static void PeeringTestNewDir(wchar_t *dir, UINT size, char *name)
{
	wchar_t tmp[MAX_PATH];
	wchar_t path[MAX_PATH];

	UniFormat(tmp, sizeof(tmp), L"peeringtest_%S_%u", name, Rand32());
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

// Delete the files of a directory, which holds no subdirectory, and then the directory
static void PeeringTestDeleteFiles(wchar_t *dir)
{
	DIRLIST *d = EnumDirW(dir);

	for (UINT i = 0;d != NULL && i < d->NumFiles;i++)
	{
		wchar_t path[MAX_PATH];

		if (d->File[i]->Folder == false)
		{
			ConbinePathW(path, sizeof(path), dir, d->File[i]->FileNameW);
			FileDeleteW(path);
		}
	}

	FreeDir(d);
	DeleteDirW(dir);
}

// The text of a file of the node log directory of dir, or of every file there for NULL; NULL when there is none. The caller
// frees it.
static char *PeeringTestReadLog(wchar_t *dir, wchar_t *name)
{
	wchar_t log_dir[MAX_PATH];
	BUF *all = NewBuf();

	ConbinePathW(log_dir, sizeof(log_dir), dir, NODE_LOG_DIR_NAME);

	DIRLIST *d = EnumDirW(log_dir);
	for (UINT i = 0;d != NULL && i < d->NumFiles;i++)
	{
		DIRENT *e = d->File[i];
		wchar_t path[MAX_PATH];

		if (e->Folder || (name != NULL && UniStrCmpi(e->FileNameW, name) != 0))
		{
			continue;
		}

		ConbinePathW(path, sizeof(path), log_dir, e->FileNameW);

		BUF *b = ReadDumpW(path);
		if (b != NULL)
		{
			WriteBuf(all, b->Buf, b->Size);
			FreeBuf(b);
		}
	}
	FreeDir(d);

	char *ret = NULL;
	if (all->Size != 0)
	{
		ret = ZeroMalloc(all->Size + 1);
		Copy(ret, all->Buf, all->Size);
	}
	FreeBuf(all);

	return ret;
}

// The fake adapter of a host: it counts the packets that the host takes and keeps the last one
static void PeeringTestAdapter(NODE *n, void *param, UINT vrf_id, const UCHAR *packet, UINT size)
{
	PEERINGTEST_NODE *t = (PEERINGTEST_NODE *)param;

	AcquireSRWLockExclusive(&t->Lock);
	{
		t->LastVrf = vrf_id;
		t->LastSize = size;
		Copy(t->Last, packet, MIN(size, sizeof(t->Last)));
		InterlockedIncrement(&t->Arrivals);
	}
	ReleaseSRWLockExclusive(&t->Lock);
}

// The fake adapter of a host takes a state that the overlay applied, as the adapters of the VRFs of the client role take one
// and put the routes of its peers into the Windows routing table through IP Helper (NodeClient.c, NodeVrfAdapter.c): with each
// Generation, and with the forwarding tables that the BGP peering builds anew when the routes that it learned change. It keeps
// the routes of the peers, each with the node of its peer.
static void PeeringTestHostState(NODE *n, void *param, const CONTROL_STATE *st)
{
	PEERINGTEST_NODE *t = (PEERINGTEST_NODE *)param;

	// The test holds the apply of a Generation here, where the overlay runs the Generation already and the BGP peering does not
	// have it yet (NodeOverlayState): the window of the review of SDN-77 (SDN-77-R1, #531)
	if (t->Hold != 0 && st->Generation == t->Hold)
	{
		t->Hold = 0;
		SetEvent(t->Held);
		WaitForSingleObject(t->Release, PEERINGTEST_BOUND);
	}

	AcquireSRWLockExclusive(&t->Lock);
	{
		t->NumHostRoutes = 0;
		for (UINT i = 0;i < st->NumPeers;i++)
		{
			const CONTROL_PEER *cp = &st->Peers[i];
			UINT node = PEERINGTEST_NODES;

			for (UINT j = 0;j < PEERINGTEST_NODES;j++)
			{
				if (StrCmp(cp->Name, peeringtest_names[j]) == 0)
				{
					node = j;
				}
			}

			for (UINT j = 0;j < cp->NumRoutes && j < CONTROL_MAX_ROUTES && t->NumHostRoutes < PEERINGTEST_HOST_ROUTES;j++)
			{
				PEERINGTEST_HOST_ROUTE *r = &t->HostRoutes[t->NumHostRoutes++];

				r->Node = node;
				Copy(&r->Route, &cp->Routes[j], sizeof(CONTROL_ROUTE));
			}
		}
	}
	ReleaseSRWLockExclusive(&t->Lock);
}

// Whether the host of node t took at least target packets within timeout
static bool PeeringTestArrived(PEERINGTEST_NODE *t, LONG target, UINT timeout)
{
	UINT64 end = Tick64() + timeout;

	while (InterlockedCompareExchange(&t->Arrivals, 0, 0) < target)
	{
		if (Tick64() >= end)
		{
			return false;
		}
		SleepThread(PEERINGTEST_POLL);
	}

	return true;
}

// A UDP packet of IPv4 from src to dst with the data seq, PEERINGTEST_SIZE bytes, into buf: its size, 0 when an end is no
// IPv4 address
static UINT PeeringTestPacket(UCHAR *buf, char *src, char *dst, UINT seq)
{
	UCHAR s[4], d[4];

	if (PeeringTestIp(s, src) == false || PeeringTestIp(d, dst) == false)
	{
		return 0;
	}

	Zero(buf, PEERINGTEST_SIZE);
	buf[0] = 0x45;
	WRITE_USHORT(buf + 2, PEERINGTEST_SIZE);
	buf[8] = 64;
	buf[9] = IP_PROTO_UDP;
	Copy(buf + 12, s, 4);
	Copy(buf + 16, d, 4);
	USHORT sum = IpChecksum(buf, 20);
	Copy(buf + 10, &sum, 2);

	WRITE_USHORT(buf + 20, 5000);
	WRITE_USHORT(buf + 22, 53);
	WRITE_USHORT(buf + 24, PEERINGTEST_SIZE - 20);
	WRITE_UINT(buf + 28, seq);
	for (UINT i = 32;i < PEERINGTEST_SIZE;i++)
	{
		buf[i] = (UCHAR)(i * 13 + seq);
	}

	return PEERINGTEST_SIZE;
}

// Whether the process pid ended; 0 is none
static bool PeeringTestExited(UINT pid)
{
	HANDLE p = (pid != 0 ? OpenProcess(SYNCHRONIZE, FALSE, pid) : NULL);
	bool exited = (p == NULL || WaitForSingleObject(p, 0) == WAIT_OBJECT_0);

	if (p != NULL)
	{
		CloseHandle(p);
	}

	return exited;
}

// Whether the process pid ends within PEERINGTEST_EXIT: a node does not wait for the sidecar that it stops (SDN-77-R1, #531)
static bool PeeringTestWaitExited(UINT pid)
{
	UINT64 end = Tick64() + PEERINGTEST_EXIT;

	while (PeeringTestExited(pid) == false)
	{
		if (Tick64() >= end)
		{
			return false;
		}
		SleepThread(PEERINGTEST_POLL);
	}

	return true;
}

// Suspend every thread of the process pid, as a host that loses power stops it without a word: each pass over the threads of
// the system takes the ones that the passes before did not, until one finds none, so a thread that starts meanwhile is taken
// too. The threads go into list for PeeringTestThaw. Whether it took any.
static bool PeeringTestFreeze(UINT pid, LIST *list)
{
	bool found = true;

	for (UINT pass = 0;pass < 16 && found;pass++)
	{
		THREADENTRY32 e;
		HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);

		found = false;
		if (snap == INVALID_HANDLE_VALUE)
		{
			break;
		}

		Zero(&e, sizeof(e));
		e.dwSize = sizeof(e);
		for (BOOL more = Thread32First(snap, &e);more;more = Thread32Next(snap, &e))
		{
			bool taken = false;

			if (e.th32OwnerProcessID != pid)
			{
				continue;
			}
			for (UINT i = 0;i < LIST_NUM(list) && taken == false;i++)
			{
				taken = (((PEERINGTEST_THREAD *)LIST_DATA(list, i))->Id == e.th32ThreadID);
			}
			if (taken)
			{
				continue;
			}

			// A thread that ended meanwhile cannot be opened
			HANDLE h = OpenThread(THREAD_SUSPEND_RESUME, FALSE, e.th32ThreadID);
			if (h == NULL)
			{
				continue;
			}
			if (SuspendThread(h) == (DWORD)-1)
			{
				CloseHandle(h);
				continue;
			}

			PEERINGTEST_THREAD *t = ZeroMalloc(sizeof(PEERINGTEST_THREAD));
			t->Id = e.th32ThreadID;
			t->Handle = h;
			Add(list, t);
			found = true;
		}

		CloseHandle(snap);
	}

	return (LIST_NUM(list) != 0);
}

// Resume the threads that PeeringTestFreeze suspended
static void PeeringTestThaw(LIST *list)
{
	for (UINT i = 0;i < LIST_NUM(list);i++)
	{
		PEERINGTEST_THREAD *t = LIST_DATA(list, i);

		ResumeThread(t->Handle);
		CloseHandle(t->Handle);
		Free(t);
	}

	DeleteAll(list);
}

// Stop a node, on a thread of its own, so that the test watches the other nodes meanwhile
static DWORD WINAPI PeeringTestStopThread(LPVOID param)
{
	NodeStop((NODE *)param);

	return 0;
}

//
// What the nodes do
//

// Apply Generation gen to each node that runs, with red peering by BGP or not: whether each took it
static bool PeeringTestApply(PEERINGTEST_CTX *ctx, UINT64 gen, bool red_peers)
{
	bool ok = true;

	ctx->Generation = gen;
	ctx->RedPeers = red_peers;

	for (UINT i = 0;i < PEERINGTEST_NODES;i++)
	{
		if (ctx->Nodes[i].Stopped)
		{
			continue;
		}

		CONTROL_STATE *st = PeeringTestState(ctx, i);
		ok = NodeOverlayApply(ctx->Nodes[i].Node, st) && ok;
		PeeringTestFreeState(st);
	}

	return ok;
}

// Whether each node runs the Generation of the test with its sessions of the overlay to the other two up, within
// PEERINGTEST_BOUND
static bool PeeringTestWaitOverlay(PEERINGTEST_CTX *ctx)
{
	UINT64 end = Tick64() + PEERINGTEST_BOUND;

	while (true)
	{
		bool ok = true;

		for (UINT i = 0;i < PEERINGTEST_NODES && ok;i++)
		{
			NODE_OVERLAY_STATUS st;

			NodeOverlayGetStatus(ctx->Nodes[i].Node, &st);
			ok = (st.Generation == ctx->Generation && st.NumLinks == PEERINGTEST_NODES - 1);
		}
		if (ok)
		{
			return true;
		}
		if (Tick64() >= end)
		{
			return false;
		}
		SleepThread(PEERINGTEST_POLL);
	}
}

// The num peers of a report as text: a line for each, with the address of its sidecar, the state of their session and the
// prefixes learned from it, each after the name of its VRF. The peers of a large mesh, at 127.0.1.0/24, are left out: their
// sidecars never answer, and the state of their sessions is whatever GoBGP tries.
static void PeeringTestPeersText(CONTROL_PEERING_PEER *peers, UINT num, char *text, UINT size)
{
	StrCpy(text, size, "");
	for (UINT i = 0;i < num;i++)
	{
		CONTROL_PEERING_PEER *p = &peers[i];
		char line[MAX_SIZE * 2];

		if (p->AddressSize == 4 && p->Address[0] == 127 && p->Address[1] == 0 && p->Address[2] == 1)
		{
			continue;
		}

		Format(line, sizeof(line), "    %u.%u.%u.%u %s:", (UINT)p->Address[0], (UINT)p->Address[1], (UINT)p->Address[2], (UINT)p->Address[3], p->State);
		for (UINT j = 0;j < p->NumLearned && j < CONTROL_MAX_LEARNED;j++)
		{
			CONTROL_ROUTE *r = &p->Learned[j];
			char part[MAX_SIZE];

			if (r->AddressSize == 4)
			{
				Format(part, sizeof(part), " %s %u.%u.%u.%u/%u", PeeringTestVrfName(r->VrfId), (UINT)r->Address[0], (UINT)r->Address[1], (UINT)r->Address[2], (UINT)r->Address[3], r->Length);
			}
			else
			{
				Format(part, sizeof(part), " %s an IPv6 prefix/%u", PeeringTestVrfName(r->VrfId), r->Length);
			}
			StrCat(line, sizeof(line), part);
		}
		StrCat(line, sizeof(line), "\n");
		StrCat(text, size, line);
	}
}

// The report of the peering of node t as text (NodePeeringGetPeers, what the Telemetry of the node carries and ranz explain
// prints): a line for each peer of its sidecar in the order of its address, with the state of their session and the
// prefixes learned from it, each after the name of its VRF
static void PeeringTestReport(PEERINGTEST_NODE *t, char *text, UINT size)
{
	CONTROL_PEERING_PEER *peers = ZeroMalloc(sizeof(CONTROL_PEERING_PEER) * CONTROL_MAX_PEERING_PEERS);
	UINT num = NodePeeringGetPeers(t->Node, peers, CONTROL_MAX_PEERING_PEERS);

	PeeringTestPeersText(peers, num, text, size);
	Free(peers);
}

// The report of node i once the mesh of the Generation converged: a line for each other node with which it shares a VRF that
// peers by BGP, in the order of their addresses, with the session established and what that node announces in those VRFs,
// its address and its LAN subnet in each, in the order of the VRF id, then the prefix
static void PeeringTestExpected(PEERINGTEST_CTX *ctx, UINT i, char *text, UINT size)
{
	StrCpy(text, size, "");
	for (UINT j = 0;j < PEERINGTEST_NODES;j++)
	{
		char line[MAX_SIZE * 2];

		if (j == i || PeeringTestShare(ctx, i, j, true) == false)
		{
			continue;
		}

		Format(line, sizeof(line), "    %s established:", peeringtest_addrs[j]);
		for (UINT k = 0;k < PEERINGTEST_MEMBERS;k++)
		{
			PEERINGTEST_MEMBER *m = &peeringtest_members[k];
			char part[MAX_SIZE];

			if (m->Node != j || PeeringTestMember(i, m->VrfId) == NULL || PeeringTestPeers(ctx, m->VrfId) == false)
			{
				continue;
			}

			Format(part, sizeof(part), " %s %s/32 %s %s/%u", PeeringTestVrfName(m->VrfId), m->Address, PeeringTestVrfName(m->VrfId), m->Lan, (UINT)PEERINGTEST_LENGTH);
			StrCat(line, sizeof(line), part);

			// ... and in red the extra LANs of that node that it announces and may announce, after its LAN in the order of the prefix
			for (UINT e = 0;e < PEERINGTEST_EXTRAS && m->VrfId == PEERINGTEST_RED;e++)
			{
				if (peeringtest_extras[e].Node == j && PeeringTestExtra(ctx, e, true) && PeeringTestExtra(ctx, e, false))
				{
					Format(part, sizeof(part), " red %s/%u", peeringtest_extras[e].Lan, (UINT)PEERINGTEST_LENGTH);
					StrCat(line, sizeof(line), part);
				}
			}
		}
		StrCat(line, sizeof(line), "\n");
		StrCat(text, size, line);
	}
}

// Whether the report of each node is the one of the converged mesh (PeeringTestExpected), within PEERINGTEST_BOUND. The
// reports are printed, each with the one of the converged mesh where it differs.
static bool PeeringTestWaitReports(PEERINGTEST_CTX *ctx)
{
	char *got = ZeroMalloc(PEERINGTEST_TEXT);
	char *want = ZeroMalloc(PEERINGTEST_TEXT);
	UINT64 end = Tick64() + PEERINGTEST_BOUND;
	bool ok = false;

	while (true)
	{
		ok = true;
		for (UINT i = 0;i < PEERINGTEST_NODES && ok;i++)
		{
			PeeringTestReport(&ctx->Nodes[i], got, PEERINGTEST_TEXT);
			PeeringTestExpected(ctx, i, want, PEERINGTEST_TEXT);
			ok = (StrCmp(got, want) == 0);
		}
		if (ok || Tick64() >= end)
		{
			break;
		}
		SleepThread(PEERINGTEST_POLL);
	}

	for (UINT i = 0;i < PEERINGTEST_NODES;i++)
	{
		PeeringTestReport(&ctx->Nodes[i], got, PEERINGTEST_TEXT);
		PeeringTestExpected(ctx, i, want, PEERINGTEST_TEXT);
		Print("  [INFO] the peers of the sidecar of %s and the prefixes learned from each:\n%s", peeringtest_names[i], IsEmptyStr(got) ? "    (none)\n" : got);
		if (StrCmp(got, want) != 0)
		{
			Print("  [INFO] ... where the mesh converged:\n%s", IsEmptyStr(want) ? "    (none)\n" : want);
		}
	}

	Free(got);
	Free(want);

	return ok;
}

// The next hop of the address addr in the VRF vrf_id of the forwarding tables of node t: the index of a peer, NODE_VRF_LOCAL
// for its host, or NODE_VRF_NONE for no route and for a VRF that the tables do not have
static UINT PeeringTestLookup(PEERINGTEST_NODE *t, UINT vrf_id, char *addr)
{
	UCHAR a[4];
	UINT hop = NODE_VRF_NONE;

	if (PeeringTestIp(a, addr) == false)
	{
		return NODE_VRF_NONE;
	}

	NodeReaderOnline(t->Node, &t->Reader);
	{
		NODE_TABLES *tables = NodeGetTables(t->Node);
		NODE_VRF_TABLE *vt = NodeGetVrfTable(tables != NULL ? tables->Vrfs : NULL, vrf_id);

		if (vt != NULL)
		{
			hop = NodeVrfLookup(vt, a, 4);
		}
	}
	NodeReaderOffline(&t->Reader);

	return hop;
}

// Where the forwarding tables of node i lead the host of the LAN subnet of the member m in the Generation that runs: in a VRF
// of node i, its own LAN to its host; the LAN of another node to that node, in a VRF that peers by BGP by the route that node i
// learned from it while that node is there, and in a VRF that does not by the route that the Controller gives; anywhere else
// nowhere
static UINT PeeringTestWant(PEERINGTEST_CTX *ctx, UINT i, PEERINGTEST_MEMBER *m)
{
	if (PeeringTestMember(i, m->VrfId) == NULL)
	{
		return NODE_VRF_NONE;
	}
	if (m->Node == i)
	{
		return NODE_VRF_LOCAL;
	}
	if (PeeringTestPeers(ctx, m->VrfId) && ctx->Nodes[m->Node].Gone)
	{
		return NODE_VRF_NONE;
	}

	return PeeringTestHop(i, m->Node);
}

// Where the forwarding tables of node i lead the host of the extra LAN e in red in the Generation that runs: its own extra LAN to
// its host while it has it behind it, the one of another node to that node while that node announces it, its accept lists hold it
// and that node is there; anywhere else nowhere
static UINT PeeringTestWantExtra(PEERINGTEST_CTX *ctx, UINT i, UINT e)
{
	PEERINGTEST_EXTRA *x = &peeringtest_extras[e];

	if (PeeringTestMember(i, PEERINGTEST_RED) == NULL)
	{
		return NODE_VRF_NONE;
	}
	if (x->Node == i)
	{
		return (PeeringTestExtra(ctx, e, true) ? NODE_VRF_LOCAL : NODE_VRF_NONE);
	}
	if (PeeringTestExtra(ctx, e, true) == false || PeeringTestExtra(ctx, e, false) == false || ctx->Nodes[x->Node].Gone)
	{
		return NODE_VRF_NONE;
	}

	return PeeringTestHop(i, x->Node);
}

// Whether the forwarding tables of each node that is there lead the host of each LAN subnet where PeeringTestWant says, and the
// host of each extra LAN where PeeringTestWantExtra says; the first that does not goes into diff
static bool PeeringTestTablesAre(PEERINGTEST_CTX *ctx, char *diff, UINT diff_size)
{
	StrCpy(diff, diff_size, "");

	for (UINT i = 0;i < PEERINGTEST_NODES;i++)
	{
		if (ctx->Nodes[i].Gone)
		{
			continue;
		}

		for (UINT k = 0;k < PEERINGTEST_MEMBERS;k++)
		{
			PEERINGTEST_MEMBER *m = &peeringtest_members[k];
			UINT got = PeeringTestLookup(&ctx->Nodes[i], m->VrfId, m->LanHost);
			UINT want = PeeringTestWant(ctx, i, m);

			if (got != want)
			{
				Format(diff, diff_size, "the forwarding table of %s in %s leads %s to %s, not to %s", peeringtest_names[i], PeeringTestVrfName(m->VrfId), m->LanHost,
					PeeringTestHopName(i, got), PeeringTestHopName(i, want));
				return false;
			}
		}

		for (UINT e = 0;e < PEERINGTEST_EXTRAS;e++)
		{
			PEERINGTEST_EXTRA *x = &peeringtest_extras[e];
			UINT got = PeeringTestLookup(&ctx->Nodes[i], PEERINGTEST_RED, x->LanHost);
			UINT want = PeeringTestWantExtra(ctx, i, e);

			if (got != want)
			{
				Format(diff, diff_size, "the forwarding table of %s in red leads %s, of the extra LAN of %s, to %s, not to %s", peeringtest_names[i], x->LanHost,
					peeringtest_names[x->Node], PeeringTestHopName(i, got), PeeringTestHopName(i, want));
				return false;
			}
		}
	}

	return true;
}

// Whether the forwarding tables come to PeeringTestTablesAre within PEERINGTEST_BOUND; the difference that stayed is printed
static bool PeeringTestWaitTables(PEERINGTEST_CTX *ctx)
{
	char diff[MAX_SIZE];
	UINT64 end = Tick64() + PEERINGTEST_BOUND;

	while (PeeringTestTablesAre(ctx, diff, sizeof(diff)) == false)
	{
		if (Tick64() >= end)
		{
			Print("  [INFO] %s\n", diff);
			return false;
		}
		SleepThread(PEERINGTEST_POLL);
	}

	return true;
}

// Whether the adapter of the host of each node that is there took the routes of the peers that PeeringTestWant says: for each
// LAN subnet of another node in a VRF of the node that its forwarding table leads to that node, a route of that node to it in
// that VRF, and no other route of a peer. The first difference goes into diff.
static bool PeeringTestHostRoutesAre(PEERINGTEST_CTX *ctx, char *diff, UINT diff_size)
{
	StrCpy(diff, diff_size, "");

	for (UINT i = 0;i < PEERINGTEST_NODES;i++)
	{
		PEERINGTEST_NODE *t = &ctx->Nodes[i];
		UINT want = 0;
		bool ok = true;

		if (t->Gone)
		{
			continue;
		}

		AcquireSRWLockShared(&t->Lock);
		{
			for (UINT k = 0;k < PEERINGTEST_MEMBERS && ok;k++)
			{
				PEERINGTEST_MEMBER *m = &peeringtest_members[k];
				CONTROL_ROUTE lan;
				bool found = false;

				if (m->Node == i || PeeringTestWant(ctx, i, m) == NODE_VRF_NONE)
				{
					continue;
				}

				want++;
				PeeringTestRoute(&lan, m->VrfId, m->Lan, PEERINGTEST_LENGTH);
				for (UINT j = 0;j < t->NumHostRoutes && found == false;j++)
				{
					CONTROL_ROUTE *r = &t->HostRoutes[j].Route;

					found = (t->HostRoutes[j].Node == m->Node && r->VrfId == lan.VrfId && r->AddressSize == lan.AddressSize && r->Length == lan.Length &&
						Cmp(r->Address, lan.Address, lan.AddressSize) == 0);
				}
				if (found == false)
				{
					Format(diff, diff_size, "the adapter of the host of %s has no route to %s/%u of %s in %s", peeringtest_names[i], m->Lan, (UINT)PEERINGTEST_LENGTH,
						peeringtest_names[m->Node], PeeringTestVrfName(m->VrfId));
					ok = false;
				}
			}
			// ... and for each extra LAN of another node that its forwarding table leads to that node, a route of that node to it
			for (UINT e = 0;e < PEERINGTEST_EXTRAS && ok;e++)
			{
				PEERINGTEST_EXTRA *x = &peeringtest_extras[e];
				CONTROL_ROUTE lan;
				bool found = false;

				if (x->Node == i || PeeringTestWantExtra(ctx, i, e) == NODE_VRF_NONE)
				{
					continue;
				}

				want++;
				PeeringTestRoute(&lan, PEERINGTEST_RED, x->Lan, PEERINGTEST_LENGTH);
				for (UINT j = 0;j < t->NumHostRoutes && found == false;j++)
				{
					CONTROL_ROUTE *r = &t->HostRoutes[j].Route;

					found = (t->HostRoutes[j].Node == x->Node && r->VrfId == lan.VrfId && r->AddressSize == lan.AddressSize && r->Length == lan.Length &&
						Cmp(r->Address, lan.Address, lan.AddressSize) == 0);
				}
				if (found == false)
				{
					Format(diff, diff_size, "the adapter of the host of %s has no route to %s/%u, the extra LAN of %s, in red", peeringtest_names[i], x->Lan,
						(UINT)PEERINGTEST_LENGTH, peeringtest_names[x->Node]);
					ok = false;
				}
			}
			if (ok && t->NumHostRoutes != want)
			{
				Format(diff, diff_size, "the adapter of the host of %s took %u routes of its peers, not %u", peeringtest_names[i], t->NumHostRoutes, want);
				ok = false;
			}
		}
		ReleaseSRWLockShared(&t->Lock);

		if (ok == false)
		{
			return false;
		}
	}

	return true;
}

// Whether the routes that the adapters of the hosts took come to PeeringTestHostRoutesAre within PEERINGTEST_BOUND; the
// difference that stayed is printed
static bool PeeringTestWaitHost(PEERINGTEST_CTX *ctx)
{
	char diff[MAX_SIZE];
	UINT64 end = Tick64() + PEERINGTEST_BOUND;

	while (PeeringTestHostRoutesAre(ctx, diff, sizeof(diff)) == false)
	{
		if (Tick64() >= end)
		{
			Print("  [INFO] %s\n", diff);
			return false;
		}
		SleepThread(PEERINGTEST_POLL);
	}

	return true;
}

// The prefixes that node t learned from the sidecar of node j, with the state of their session into state: 0 and "none"
// while the sidecar of node t has no such peer
static UINT PeeringTestLearnedFrom(PEERINGTEST_NODE *t, UINT j, char *state, UINT state_size)
{
	CONTROL_PEERING_PEER *peers = ZeroMalloc(sizeof(CONTROL_PEERING_PEER) * CONTROL_MAX_PEERING_PEERS);
	UINT num = NodePeeringGetPeers(t->Node, peers, CONTROL_MAX_PEERING_PEERS);
	UCHAR addr[4];
	UINT ret = 0;

	PeeringTestIp(addr, peeringtest_addrs[j]);
	StrCpy(state, state_size, "none");
	for (UINT i = 0;i < num;i++)
	{
		if (peers[i].AddressSize == 4 && Cmp(peers[i].Address, addr, 4) == 0)
		{
			StrCpy(state, state_size, peers[i].State);
			ret = peers[i].NumLearned;
		}
	}

	Free(peers);

	return ret;
}

// Wait until no node but node j, which is gone, has a route of node j: none learned from its sidecar, and none to its LAN
// subnets in their forwarding tables, while their routes of each other stay. Whether that came within PEERINGTEST_BOUND of
// start, and the ms that it took from start into took.
static bool PeeringTestWaitGone(PEERINGTEST_CTX *ctx, UINT j, UINT64 start, UINT64 *took)
{
	char diff[MAX_SIZE];
	char state[CONTROL_PEERING_STATE_SIZE];

	while (true)
	{
		bool gone = PeeringTestTablesAre(ctx, diff, sizeof(diff));

		for (UINT i = 0;i < PEERINGTEST_NODES && gone;i++)
		{
			gone = (i == j || PeeringTestLearnedFrom(&ctx->Nodes[i], j, state, sizeof(state)) == 0);
		}

		UINT64 now = Tick64();
		*took = now - start;
		if (gone)
		{
			return true;
		}
		if (now >= start + PEERINGTEST_BOUND)
		{
			Print("  [INFO] %s\n", IsEmptyStr(diff) ? "a node still holds prefixes learned from the gone node" : diff);
			return false;
		}
		SleepThread(PEERINGTEST_POLL);
	}
}

// A packet of the host of node from in the VRF vrf_id, from its address there to dst: it arrives as it was sent at the host of
// node to, in that VRF, or with to PEERINGTEST_NODES the overlay does not take it and no host gets it
static void PeeringTestSend(PEERINGTEST_CTX *ctx, UINT from, UINT vrf_id, char *dst, UINT to)
{
	PEERINGTEST_NODE *t = &ctx->Nodes[from];
	PEERINGTEST_MEMBER *m = PeeringTestMember(from, vrf_id);
	UCHAR packet[PEERINGTEST_SIZE];
	LONG arrivals[PEERINGTEST_NODES];
	char what[MAX_SIZE];
	UINT size = 0;

	for (UINT i = 0;i < PEERINGTEST_NODES;i++)
	{
		arrivals[i] = InterlockedCompareExchange(&ctx->Nodes[i].Arrivals, 0, 0);
	}

	if (m != NULL)
	{
		size = PeeringTestPacket(packet, m->Address, dst, ctx->Seq++);
	}

	NodeReaderOnline(t->Node, &t->Reader);
	bool taken = (size != 0 && NodeOverlayInput(t->Node, vrf_id, packet, size));
	NodeReaderOffline(&t->Reader);

	if (to < PEERINGTEST_NODES)
	{
		PEERINGTEST_NODE *r = &ctx->Nodes[to];
		bool arrived = (taken && PeeringTestArrived(r, arrivals[to] + 1, PEERINGTEST_ARRIVE));
		bool same = false;

		AcquireSRWLockShared(&r->Lock);
		{
			same = (arrived && r->LastVrf == vrf_id && r->LastSize == size && Cmp(r->Last, packet, size) == 0);
		}
		ReleaseSRWLockShared(&r->Lock);

		Format(what, sizeof(what), "  %s in %s: %s > %s arrives at the host of %s as it was sent", peeringtest_names[from], PeeringTestVrfName(vrf_id),
			m != NULL ? m->Address : "?", dst, peeringtest_names[to]);
		PeeringTestCheck(ctx, taken && same, what, "the overlay took it %u, it arrived in %s as it was sent %u", (UINT)taken, PeeringTestVrfName(vrf_id), (UINT)same);
		return;
	}

	SleepThread(PEERINGTEST_QUIET);

	bool quiet = true;
	for (UINT i = 0;i < PEERINGTEST_NODES;i++)
	{
		quiet = quiet && (InterlockedCompareExchange(&ctx->Nodes[i].Arrivals, 0, 0) == arrivals[i]);
	}

	Format(what, sizeof(what), "  %s in %s: %s > %s goes nowhere: the forwarding table of %s has no route there", peeringtest_names[from], PeeringTestVrfName(vrf_id),
		m != NULL ? m->Address : "?", dst, PeeringTestVrfName(vrf_id));
	PeeringTestCheck(ctx, size != 0 && taken == false && quiet, what, "the overlay took it %u, no host got it %u", (UINT)taken, (UINT)quiet);
}

//
// The cases
//

// Each host sends a packet to the LAN of each other node in each VRF that the two share: it arrives at the host of that node,
// in that VRF, by the route learned by BGP where the VRF peers and by the route of the Controller where it does not. The routes
// of a VRF stay in it: a packet of node-a in red to the LAN of node-c in blue goes nowhere, as does one of node-c in blue to the
// LAN of node-b in red.
static void PeeringTestPackets(PEERINGTEST_CTX *ctx)
{
	for (UINT i = 0;i < PEERINGTEST_NODES;i++)
	{
		for (UINT k = 0;k < PEERINGTEST_MEMBERS;k++)
		{
			PEERINGTEST_MEMBER *m = &peeringtest_members[k];

			if (m->Node != i && PeeringTestMember(i, m->VrfId) != NULL)
			{
				PeeringTestSend(ctx, i, m->VrfId, m->LanHost, m->Node);
			}
		}
	}

	PeeringTestSend(ctx, PEERINGTEST_A, PEERINGTEST_RED, "192.168.4.10", PEERINGTEST_NODES);
	PeeringTestSend(ctx, PEERINGTEST_C, PEERINGTEST_BLUE, "192.168.2.10", PEERINGTEST_NODES);
}

// The state of the peering of each node once the mesh converged: a node in a VRF that peers by BGP runs its sidecar, which
// named GoBGP in its ready, with the strict DACL on its pipe (ADR-0039 decision 3), has a session established with each other
// node with which it shares such a VRF and holds the peers of a large mesh too, announces its address and its LAN subnet in
// each, with its extra LANs and the more specific prefixes of a hostile node-b, and its sidecar sent no error; a node in none
// runs no sidecar and has no peer and no learned route. Each node started ctx->Starts sidecars so far.
static void PeeringTestStatus(PEERINGTEST_CTX *ctx)
{
	for (UINT i = 0;i < PEERINGTEST_NODES;i++)
	{
		NODE_PEERING_STATUS st;
		UINT peers = 0;
		UINT vrfs = 0;
		UINT announced = 0;
		char what[MAX_SIZE];

		for (UINT j = 0;j < PEERINGTEST_NODES;j++)
		{
			if (j != i && PeeringTestShare(ctx, i, j, true))
			{
				peers++;
			}
		}
		for (UINT k = 0;k < PEERINGTEST_MEMBERS;k++)
		{
			if (peeringtest_members[k].Node == i && PeeringTestPeers(ctx, peeringtest_members[k].VrfId))
			{
				vrfs++;
			}
		}
		announced = 2 * vrfs + (i == PEERINGTEST_B && ctx->Hostile && ctx->RedPeers ? PEERINGTEST_HOSTILE : 0);
		for (UINT e = 0;e < PEERINGTEST_EXTRAS;e++)
		{
			if (peeringtest_extras[e].Node == i && PeeringTestExtra(ctx, e, true))
			{
				announced++;
			}
		}

		NodePeeringGetStatus(ctx->Nodes[i].Node, &st);

		if (vrfs == 0)
		{
			Format(what, sizeof(what), "  %s, in no VRF that peers by BGP: it runs no sidecar and has no peer and no learned route", peeringtest_names[i]);
			PeeringTestCheck(ctx, st.Configured == false && st.Running == false && st.ProcessId == 0 && st.NumPeers == 0 && st.NumLearned == 0 && st.NumStarts == ctx->Starts[i], what,
				"configured %u, running %u, process %u, %u peers, %u learned routes, %u sidecars started", (UINT)st.Configured, (UINT)st.Running, st.ProcessId, st.NumPeers,
				st.NumLearned, st.NumStarts);
			continue;
		}

		bool acl = (StrCmp(st.PipeAcl, "D:P(A;;FA;;;OW)") == 0 || StrCmp(st.PipeAcl, "D:P(A;;GA;;;OW)") == 0);
		Format(what, sizeof(what), "  %s: its sidecar runs GoBGP, with the strict DACL on its pipe, has %u sessions established of %u peers and announces %u prefixes, without an error",
			peeringtest_names[i], peers, peers + ctx->NumDummies[i], announced);
		PeeringTestCheck(ctx, st.Configured && st.Running && st.ProcessId != 0 && SearchStrEx(st.Version, "GoBGP", 0, false) != INFINITE && acl &&
			st.NumPeers == peers + ctx->NumDummies[i] && st.NumEstablished == peers && st.NumAnnounced == announced && st.NumErrors == 0 && st.NumStarts == ctx->Starts[i], what,
			"configured %u, running %u, process %u, version \"%s\", DACL \"%s\", %u peers, %u established, %u announced, %u errors, %u sidecars started", (UINT)st.Configured,
			(UINT)st.Running, st.ProcessId, st.Version, st.PipeAcl, st.NumPeers, st.NumEstablished, st.NumAnnounced, st.NumErrors, st.NumStarts);
	}
}

// The mesh of the Generation that the nodes took: the sessions of the overlay, the report of each node, its forwarding tables, the
// adapter of its host and the state of its peering. Whether the forwarding tables came to what the Generation gives.
static bool PeeringTestConverge(PEERINGTEST_CTX *ctx, bool applied)
{
	char what[MAX_SIZE];

	bool overlay = (applied && PeeringTestWaitOverlay(ctx));
	Format(what, sizeof(what), "Generation %I64u goes in at each node, and the sessions of the overlay between the three are up", ctx->Generation);
	PeeringTestCheck(ctx, applied && overlay, what, "applied %u, the Generation and the sessions at each node %u", (UINT)applied, (UINT)overlay);

	bool converged = (overlay && PeeringTestWaitReports(ctx));
	PeeringTestCheck(ctx, converged, "Each node learns from the sidecar of each other node, over an established session, exactly what that node announces in the VRFs that the two share and that peer by BGP, each prefix in its VRF",
		"%s", "see the reports above");

	bool tables = (converged && PeeringTestWaitTables(ctx));
	PeeringTestCheck(ctx, tables, "The forwarding table of each VRF leads the LAN of each other node to that node, by BGP where the VRF peers and by the route of the Controller where it does not, and the LAN of the node to its host, and no other table leads there",
		"%s", "see the line above");

	bool host = (tables && PeeringTestWaitHost(ctx));
	PeeringTestCheck(ctx, host, "The adapter of the host of each node takes the LAN of each other node as a route of that node in their VRF, by BGP where the VRF peers and by the route of the Controller where it does not, and no other route of a peer",
		"%s", "see the line above");

	PeeringTestStatus(ctx);

	return tables;
}

// Generation gen of the three nodes, with red peering by BGP or not, and the mesh that it gives (PeeringTestConverge), with the
// packets between the hosts. Whether the mesh converged.
static bool PeeringTestMesh(PEERINGTEST_CTX *ctx, UINT64 gen, bool red_peers)
{
	Print("[Generation %I64u: red %s by BGP, blue peers by BGP]\n", gen, red_peers ? "peers" : "does not peer");

	bool tables = PeeringTestConverge(ctx, PeeringTestApply(ctx, gen, red_peers));
	if (tables)
	{
		PeeringTestPackets(ctx);
	}

	return tables;
}

// A session from 127.0.0.9, an address that the Controller did not name, to the sidecar of node-a: the sidecar refuses it and
// node-a counts it, and its sessions with node-b and node-c stay
static void PeeringTestRefused(PEERINGTEST_CTX *ctx)
{
	PEERINGTEST_NODE *a = &ctx->Nodes[PEERINGTEST_A];
	NODE_PEERING_STATUS before, after;
	struct sockaddr_in local, remote;
	UINT err = 0;

	Print("[a session from an address that the Controller did not name]\n");

	NodePeeringGetStatus(a->Node, &before);

	Zero(&local, sizeof(local));
	local.sin_family = AF_INET;
	InetPtonA(AF_INET, PEERINGTEST_STRANGER, &local.sin_addr);
	Zero(&remote, sizeof(remote));
	remote.sin_family = AF_INET;
	remote.sin_port = htons(PEERINGTEST_PORT);
	InetPtonA(AF_INET, peeringtest_addrs[PEERINGTEST_A], &remote.sin_addr);

	SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	bool connected = (s != INVALID_SOCKET && bind(s, (struct sockaddr *)&local, sizeof(local)) == 0 && connect(s, (struct sockaddr *)&remote, sizeof(remote)) == 0);
	if (connected == false)
	{
		err = (UINT)WSAGetLastError();
	}

	UINT64 end = Tick64() + PEERINGTEST_BOUND;
	while (true)
	{
		NodePeeringGetStatus(a->Node, &after);
		if (connected == false || after.Refused > before.Refused || Tick64() >= end)
		{
			break;
		}
		SleepThread(PEERINGTEST_POLL);
	}

	if (s != INVALID_SOCKET)
	{
		closesocket(s);
	}

	PeeringTestCheck(ctx, connected && after.Refused == before.Refused + 1, "The sidecar of node-a refuses a session from 127.0.0.9, an address that the Controller did not name, and node-a counts it",
		"connected %u (error %u), %I64u sessions refused before and %I64u after", (UINT)connected, err, before.Refused, after.Refused);
	PeeringTestCheck(ctx, after.NumEstablished == PEERINGTEST_NODES - 1, "The sessions of node-a with node-b and node-c stay established", "%u established", after.NumEstablished);
}

// A field of a message of the schema, as PeeringTestField reads it
typedef struct PEERINGTEST_FIELD
{
	UINT Number;						// Its number
	bool Bytes;							// It is length-delimited (wire type 2), else a varint (wire type 0) ...
	UINT64 Value;						// ... whose value this is
	UCHAR *Data;						// The bytes of a length-delimited one ...
	UINT Size;							// ... and their number
} PEERINGTEST_FIELD;

// The varint at *pos of buf, size bytes, into *value; false when it is cut short or longer than 64 bits
static bool PeeringTestVarint(UCHAR *buf, UINT size, UINT *pos, UINT64 *value)
{
	UINT64 v = 0;

	for (UINT shift = 0;shift < 64 && *pos < size;shift += 7)
	{
		UCHAR b = buf[(*pos)++];

		v |= (UINT64)(b & 0x7F) << shift;
		if ((b & 0x80) == 0)
		{
			*value = v;
			return true;
		}
	}

	return false;
}

// The field at *pos of buf, size bytes, into f, and *pos moves behind it: false when it is cut short, or of a wire type other
// than a varint and a length-delimited one
static bool PeeringTestField(UCHAR *buf, UINT size, UINT *pos, PEERINGTEST_FIELD *f)
{
	UINT64 tag = 0;

	Zero(f, sizeof(PEERINGTEST_FIELD));
	if (PeeringTestVarint(buf, size, pos, &tag) == false || (tag >> 3) == 0 || (tag >> 3) > 0x1FFFFFFF)
	{
		return false;
	}

	f->Number = (UINT)(tag >> 3);
	if ((tag & 7) == 0)
	{
		return PeeringTestVarint(buf, size, pos, &f->Value);
	}
	if ((tag & 7) != 2 || PeeringTestVarint(buf, size, pos, &f->Value) == false || f->Value > (UINT64)(size - *pos))
	{
		return false;
	}

	f->Bytes = true;
	f->Data = buf + *pos;
	f->Size = (UINT)f->Value;
	*pos += f->Size;

	return true;
}

// The Prefix of a route, size bytes at buf (Prefix of the schema: the bytes address 1 and the varint length 2), into r: false
// for anything else, and for an address that is neither IPv4 nor IPv6
static bool PeeringTestDecodePrefix(UCHAR *buf, UINT size, CONTROL_ROUTE *r)
{
	PEERINGTEST_FIELD f;
	UINT pos = 0;

	while (pos < size)
	{
		if (PeeringTestField(buf, size, &pos, &f) == false)
		{
			return false;
		}
		if (f.Number == 1 && f.Bytes && (f.Size == 4 || f.Size == 16))
		{
			Copy(r->Address, f.Data, f.Size);
			r->AddressSize = f.Size;
		}
		else if (f.Number == 2 && f.Bytes == false && f.Value <= 128)
		{
			r->Length = (UINT)f.Value;
		}
		else
		{
			return false;
		}
	}

	return (r->AddressSize != 0);
}

// A route that a node learned, size bytes at buf (Route of the schema: the varint vrf_id 1 and the Prefix 2), into r, which the
// caller zeroed: false for anything else
static bool PeeringTestDecodeRoute(UCHAR *buf, UINT size, CONTROL_ROUTE *r)
{
	PEERINGTEST_FIELD f;
	UINT pos = 0;
	bool prefix = false;

	while (pos < size)
	{
		if (PeeringTestField(buf, size, &pos, &f) == false)
		{
			return false;
		}
		if (f.Number == 1 && f.Bytes == false && f.Value <= 0xFFFFFFFF)
		{
			r->VrfId = (UINT)f.Value;
		}
		else if (f.Number == 2 && f.Bytes && prefix == false && PeeringTestDecodePrefix(f.Data, f.Size, r))
		{
			prefix = true;
		}
		else
		{
			return false;
		}
	}

	return prefix;
}

// A peer of a report, size bytes at buf (PeeringPeer of the schema: the bytes address 1, the string state 2 and the Routes
// learned 3), into p, which the caller zeroed: false for anything else
static bool PeeringTestDecodePeer(UCHAR *buf, UINT size, CONTROL_PEERING_PEER *p)
{
	PEERINGTEST_FIELD f;
	UINT pos = 0;

	while (pos < size)
	{
		if (PeeringTestField(buf, size, &pos, &f) == false || f.Bytes == false)
		{
			return false;
		}
		if (f.Number == 1 && (f.Size == 4 || f.Size == 16))
		{
			Copy(p->Address, f.Data, f.Size);
			p->AddressSize = f.Size;
		}
		else if (f.Number == 2 && f.Size < sizeof(p->State))
		{
			Zero(p->State, sizeof(p->State));
			Copy(p->State, f.Data, f.Size);
		}
		else if (f.Number == 3 && p->NumLearned < CONTROL_MAX_LEARNED && PeeringTestDecodeRoute(f.Data, f.Size, &p->Learned[p->NumLearned]))
		{
			p->NumLearned++;
		}
		else
		{
			return false;
		}
	}

	return (p->AddressSize != 0);
}

// The report of one frame that ControlWritePeeringReport wrote, as the schema says: 4 bytes of length, then a ControlMessage
// whose one field is the Telemetry 7, whose one field is the PeeringReport 8, which repeats the PeeringPeer 1 and has the
// varint refused 2. The peers go into list, max at most, and the refused sessions into *refused: the number of the peers, or
// INFINITE when the frame is no such message.
static UINT PeeringTestDecodeReport(UCHAR *frame, UINT size, CONTROL_PEERING_PEER *list, UINT max, UINT64 *refused)
{
	PEERINGTEST_FIELD f;
	UINT pos = 4;
	UINT num = 0;

	*refused = 0;
	Zero(list, sizeof(CONTROL_PEERING_PEER) * max);
	if (size < 4 || READ_UINT(frame) != size - 4)
	{
		return INFINITE;
	}

	// The Telemetry, the only field of the ControlMessage, and the PeeringReport, the only field of the Telemetry
	if (PeeringTestField(frame, size, &pos, &f) == false || f.Number != 7 || f.Bytes == false || pos != size)
	{
		return INFINITE;
	}

	UCHAR *t = f.Data;
	UINT t_size = f.Size;
	UINT t_pos = 0;
	if (PeeringTestField(t, t_size, &t_pos, &f) == false || f.Number != 8 || f.Bytes == false || t_pos != t_size)
	{
		return INFINITE;
	}

	UCHAR *r = f.Data;
	UINT r_size = f.Size;
	UINT r_pos = 0;
	while (r_pos < r_size)
	{
		if (PeeringTestField(r, r_size, &r_pos, &f) == false)
		{
			return INFINITE;
		}
		if (f.Number == 1 && f.Bytes && num < max && PeeringTestDecodePeer(f.Data, f.Size, &list[num]))
		{
			num++;
		}
		else if (f.Number == 2 && f.Bytes == false)
		{
			*refused = f.Value;
		}
		else
		{
			return INFINITE;
		}
	}

	return num;
}

// One frame from s into buf, size bytes at most: its 4 bytes of length and its message, as the client writes them. Its size, 0
// when none came whole within PEERINGTEST_BOUND.
static UINT PeeringTestReadFrame(TRANSPORT_STREAM *s, UCHAR *buf, UINT size)
{
	UINT have = 0;
	UINT need = 4;
	UINT64 end = Tick64() + PEERINGTEST_BOUND;

	while (have < need && Tick64() < end)
	{
		UINT got = TransportRead(s, buf + have, need - have, PEERINGTEST_POLL);

		if (got == 0)
		{
			return 0;
		}
		if (got != TRANSPORT_LATER)
		{
			have += got;
		}
		if (have >= 4 && need == 4)
		{
			need = 4 + READ_UINT(buf);
			if (need < 4 || need > size)
			{
				return 0;
			}
		}
	}

	return (have == need ? need : 0);
}

// The report on the control stream: the report that the control stream of each node sends holds what the node reports of its
// peering, the peers of its sidecar with the state of each session and the prefixes learned from each, and the sessions that
// its sidecar refused. Written as the client writes it, it is one Telemetry message whose peering has them, read here field
// by field from the schema (proto/ranz/control/v1/control.proto), not through nanopb, and a report that did not change is not
// written again. No control stream of the harness sends the reports, so the test writes each one itself.
static void PeeringTestWire(PEERINGTEST_CTX *ctx)
{
	CONTROL_PEERING_PEER *held = ZeroMalloc(sizeof(CONTROL_PEERING_PEER) * CONTROL_MAX_PEERING_PEERS);
	CONTROL_PEERING_PEER *sent = ZeroMalloc(sizeof(CONTROL_PEERING_PEER) * CONTROL_MAX_PEERING_PEERS);
	char *want = ZeroMalloc(PEERINGTEST_TEXT);
	char *got = ZeroMalloc(PEERINGTEST_TEXT);
	UCHAR *frame = ZeroMalloc(PEERINGTEST_WIRE);
	char what[MAX_SIZE];

	Print("[the report on the control stream]\n");

	TRANSPORT_LISTENER *l = TransportListen(ctx->Loopback, "peering-report");
	TRANSPORT_STREAM *dialled = (l != NULL ? TransportDial(ctx->Loopback, "peering-report", NULL) : NULL);
	TRANSPORT_STREAM *accepted = (dialled != NULL ? TransportAccept(l, PEERINGTEST_BOUND) : NULL);
	PeeringTestCheck(ctx, accepted != NULL, "A stream for the reports, as the control stream of a node", "listener %u, dialled %u, accepted %u", (UINT)(l != NULL),
		(UINT)(dialled != NULL), (UINT)(accepted != NULL));

	for (UINT i = 0;i < PEERINGTEST_NODES && accepted != NULL;i++)
	{
		PEERINGTEST_NODE *t = &ctx->Nodes[i];
		CONTROL_PEERING_REPORT *report = NodePeeringGetReport(t->Node);
		NODE_PEERING_STATUS st;
		UINT64 refused = 0;
		UINT num = 0;
		bool same = false;

		// The worker of the peering of the node puts what the node holds into the report once it changed
		UINT64 end = Tick64() + PEERINGTEST_BOUND;
		while (true)
		{
			NodePeeringGetStatus(t->Node, &st);
			PeeringTestReport(t, want, PEERINGTEST_TEXT);
			num = ControlGetPeeringReport(report, held, CONTROL_MAX_PEERING_PEERS, &refused);
			PeeringTestPeersText(held, num, got, PEERINGTEST_TEXT);
			same = (report != NULL && num != 0 && StrCmp(got, want) == 0 && refused == st.Refused);
			if (same || Tick64() >= end)
			{
				break;
			}
			SleepThread(PEERINGTEST_POLL);
		}

		if (same == false)
		{
			Print("  [INFO] the report of the control stream of %s:\n%s  ... where the node holds:\n%s", peeringtest_names[i], IsEmptyStr(got) ? "    (none)\n" : got,
				IsEmptyStr(want) ? "    (none)\n" : want);
		}
		Format(what, sizeof(what), "  %s: the report of its control stream holds the peers of its sidecar, the state of each session, the prefixes learned from each and the %I64u sessions refused",
			peeringtest_names[i], st.Refused);
		PeeringTestCheck(ctx, same, what, "the report %u, %u peers in it and %I64u sessions refused, where the node counts %I64u", (UINT)(report != NULL), num, refused, st.Refused);

		// Written as the client writes it: one Telemetry message with the report in its peering
		UINT64 sent_refused = 0;
		bool wrote = (same && ControlWritePeeringReport(report, dialled));
		UINT size = (wrote ? PeeringTestReadFrame(accepted, frame, PEERINGTEST_WIRE) : 0);
		UINT sent_num = (size != 0 ? PeeringTestDecodeReport(frame, size, sent, CONTROL_MAX_PEERING_PEERS, &sent_refused) : INFINITE);
		bool equal = (sent_num == num && sent_refused == refused && Cmp(sent, held, sizeof(CONTROL_PEERING_PEER) * num) == 0);

		if (sent_num != INFINITE && equal == false)
		{
			PeeringTestPeersText(sent, sent_num, got, PEERINGTEST_TEXT);
			Print("  [INFO] the report of %s as it was written:\n%s", peeringtest_names[i], IsEmptyStr(got) ? "    (none)\n" : got);
		}
		Format(what, sizeof(what), "  %s: written as the client writes it, the report is one Telemetry message of the schema whose peering has those peers, sessions, prefixes and refused sessions",
			peeringtest_names[i]);
		PeeringTestCheck(ctx, wrote && size != 0 && equal, what, "wrote %u, a frame of %u bytes, %u peers in it and %I64u sessions refused", (UINT)wrote, size, sent_num, sent_refused);

		// Nothing changed since: the client writes nothing
		bool again = (wrote && ControlWritePeeringReport(report, dialled) && TransportRead(accepted, frame, 1, PEERINGTEST_QUIET) == TRANSPORT_LATER);
		Format(what, sizeof(what), "  %s: a report that did not change is not written again", peeringtest_names[i]);
		PeeringTestCheck(ctx, again, what, "%s", "the write failed, or it wrote a frame");
	}

	TransportClose(dialled);
	TransportClose(accepted);
	TransportCloseListener(l);
	Free(frame);
	Free(got);
	Free(want);
	Free(sent);
	Free(held);
}

// The sidecar of node-c stops answering, as a host that loses power: its threads are suspended, so it holds its sessions and
// sends nothing. Node-a and node-b remove its routes once their hold timers expire, within the hold time, or once node-c ends it,
// and keep each other's. Node-c notices that its sidecar does not answer whether it runs, ends it and drops the routes that it
// learned, and starts another (SDN-77-R1, #531); then the sessions come back and the mesh converges again.
static void PeeringTestSilent(PEERINGTEST_CTX *ctx)
{
	PEERINGTEST_NODE *c = &ctx->Nodes[PEERINGTEST_C];
	NODE_PEERING_STATUS st, hung;
	LIST *threads = NewListFast(NULL);
	UINT64 took = 0;
	char what[MAX_SIZE];

	Print("[the sidecar of node-c stops answering]\n");

	NodePeeringGetStatus(c->Node, &st);
	UINT64 start = Tick64();
	bool frozen = (st.ProcessId != 0 && PeeringTestFreeze(st.ProcessId, threads));
	PeeringTestCheck(ctx, frozen, "The threads of the sidecar of node-c are suspended: it holds its sessions and sends nothing", "process %u, %u threads suspended", st.ProcessId,
		LIST_NUM(threads));

	c->Gone = true;
	bool gone = (frozen && PeeringTestWaitGone(ctx, PEERINGTEST_C, start, &took));
	Print("  [INFO] node-a and node-b removed the routes of node-c %I64u ms after its sidecar stopped answering; the hold time is %u s\n", took, (UINT)PEERINGTEST_HOLD);
	Format(what, sizeof(what), "Node-a and node-b remove the routes of node-c within the hold time of %u s, with %u ms for the sidecar and the node to take it, and keep each other's",
		(UINT)PEERINGTEST_HOLD, (UINT)PEERINGTEST_GRACE);
	PeeringTestCheck(ctx, gone && took <= (UINT64)PEERINGTEST_HOLD * 1000 + PEERINGTEST_GRACE, what, "removed %u, after %I64u ms", (UINT)gone, took);
	if (gone)
	{
		PeeringTestCheck(ctx, PeeringTestWaitHost(ctx), "The adapters of the hosts of node-a and node-b take no route of node-c any more, and keep each other's", "%s",
			"see the line above");
		PeeringTestSend(ctx, PEERINGTEST_A, PEERINGTEST_RED, "192.168.2.10", PEERINGTEST_B);
		PeeringTestSend(ctx, PEERINGTEST_A, PEERINGTEST_RED, "192.168.3.10", PEERINGTEST_NODES);
	}

	// Node-c asks its sidecar whether it runs, and ends it when it does not answer: the routes that it learned go with it, before
	// another sidecar starts after NODE_PEERING_RESTART
	UINT64 end = Tick64() + NODE_PEERING_PING + NODE_PEERING_ANSWER + PEERINGTEST_BOUND;
	bool noticed = false;
	Zero(&hung, sizeof(hung));
	while (frozen)
	{
		NodePeeringGetStatus(c->Node, &hung);
		noticed = (hung.NumHung == st.NumHung + 1 && hung.NumLearned == 0 && hung.Running == false);
		if (noticed || Tick64() >= end)
		{
			break;
		}
		SleepThread(PEERINGTEST_POLL);
	}
	Print("  [INFO] node-c ended its sidecar that did not answer %I64u ms after it stopped answering\n", Tick64() - start);
	PeeringTestCheck(ctx, noticed, "Node-c notices that its sidecar does not answer whether it runs, ends it, and keeps none of the routes that it learned",
		"%u hung sidecars before and %u after, %u learned routes, running %u", st.NumHung, hung.NumHung, hung.NumLearned, (UINT)hung.Running);
	if (noticed)
	{
		ctx->Starts[PEERINGTEST_C]++;
	}

	PeeringTestThaw(threads);
	ReleaseList(threads);
	c->Gone = false;

	bool converged = (PeeringTestWaitReports(ctx) && PeeringTestWaitTables(ctx) && PeeringTestWaitHost(ctx));
	PeeringTestCheck(ctx, converged, "Once node-c runs a sidecar that answers, the sessions come back and the mesh converges again", "%s", "see the lines above");
}

// Node-c stops, on a thread of its own: its sidecar ends the sessions, so node-a and node-b remove its routes within the hold
// time and keep each other's, and the sidecar exits with the node
static void PeeringTestStop(PEERINGTEST_CTX *ctx)
{
	PEERINGTEST_NODE *c = &ctx->Nodes[PEERINGTEST_C];
	NODE_PEERING_STATUS st;
	UINT64 took = 0;
	char what[MAX_SIZE];

	Print("[node-c stops]\n");

	NodePeeringGetStatus(c->Node, &st);
	NodeReaderUnregister(c->Node, &c->Reader);
	c->Gone = true;
	c->Stopped = true;

	UINT64 start = Tick64();
	HANDLE stop = CreateThread(NULL, 0, PeeringTestStopThread, c->Node, 0, NULL);
	bool gone = (stop != NULL && PeeringTestWaitGone(ctx, PEERINGTEST_C, start, &took));
	if (stop != NULL)
	{
		WaitForSingleObject(stop, INFINITE);
		CloseHandle(stop);
	}
	else
	{
		NodeStop(c->Node);
	}

	Print("  [INFO] node-a and node-b removed the routes of node-c %I64u ms after it began to stop\n", took);
	Format(what, sizeof(what), "Node-c stops: node-a and node-b remove its routes within the hold time of %u s, and keep each other's", (UINT)PEERINGTEST_HOLD);
	PeeringTestCheck(ctx, gone && took <= (UINT64)PEERINGTEST_HOLD * 1000, what, "removed %u, after %I64u ms", (UINT)gone, took);
	// The node does not wait for its sidecar to exit (SDN-77-R1, #531): the sidecar has the time that the node gives it
	PeeringTestCheck(ctx, st.ProcessId != 0 && PeeringTestWaitExited(st.ProcessId), "The sidecar of node-c exits with the node", "process %u", st.ProcessId);
	PeeringTestCheck(ctx, gone && PeeringTestWaitHost(ctx), "The adapters of the hosts of node-a and node-b take no route of node-c any more, and keep each other's", "%s",
		"see the line above");

	PeeringTestSend(ctx, PEERINGTEST_A, PEERINGTEST_RED, "192.168.2.10", PEERINGTEST_B);
	PeeringTestSend(ctx, PEERINGTEST_B, PEERINGTEST_RED, "192.168.1.10", PEERINGTEST_A);
	PeeringTestSend(ctx, PEERINGTEST_A, PEERINGTEST_RED, "192.168.3.10", PEERINGTEST_NODES);
}

//
// The findings of the review of SDN-77 (SDN-77-R1, #531)
//

// Apply the state of an apply on a thread of its own (PeeringTestHeld)
static DWORD WINAPI PeeringTestApplyThread(LPVOID param)
{
	PEERINGTEST_APPLY *a = (PEERINGTEST_APPLY *)param;

	a->Applied = NodeOverlayApply(a->Node, a->State);

	return 0;
}

// Whether node t holds the route to the prefix lan/24 of red that it learned from the sidecar of node j (NodePeeringGetPeers)
static bool PeeringTestHasLearned(PEERINGTEST_NODE *t, UINT j, char *lan)
{
	CONTROL_PEERING_PEER *peers = ZeroMalloc(sizeof(CONTROL_PEERING_PEER) * CONTROL_MAX_PEERING_PEERS);
	UINT num = NodePeeringGetPeers(t->Node, peers, CONTROL_MAX_PEERING_PEERS);
	CONTROL_ROUTE want;
	UCHAR addr[4];
	bool ret = false;

	PeeringTestRoute(&want, PEERINGTEST_RED, lan, PEERINGTEST_LENGTH);
	PeeringTestIp(addr, peeringtest_addrs[j]);
	for (UINT i = 0;i < num;i++)
	{
		CONTROL_PEERING_PEER *p = &peers[i];

		if (p->AddressSize != 4 || Cmp(p->Address, addr, 4) != 0)
		{
			continue;
		}

		for (UINT k = 0;k < p->NumLearned && k < CONTROL_MAX_LEARNED;k++)
		{
			CONTROL_ROUTE *r = &p->Learned[k];

			ret = ret || (r->VrfId == want.VrfId && r->AddressSize == 4 && r->Length == want.Length && Cmp(r->Address, want.Address, 4) == 0);
		}
	}

	Free(peers);

	return ret;
}

// Whether the forwarding table of red of node t leads host to hop within PEERINGTEST_ARRIVE; where it leads it into got
static bool PeeringTestWaitHop(PEERINGTEST_NODE *t, char *host, UINT hop, UINT *got)
{
	UINT64 end = Tick64() + PEERINGTEST_ARRIVE;

	while ((*got = PeeringTestLookup(t, PEERINGTEST_RED, host)) != hop)
	{
		if (Tick64() >= end)
		{
			return false;
		}
		SleepThread(PEERINGTEST_POLL);
	}

	return true;
}

// Generation gen with node-b announcing its extra LAN or not, while the apply of the Generation at node-a holds in the adapter of
// its host (PeeringTestHostState), where the overlay runs the Generation already and the BGP peering does not have it yet. In that
// window node-b and node-c take the Generation, and the learned or the withdrawn message of the extra LAN of node-b reaches node-a,
// whose worker meets the apply. After both, the forwarding tables of node-a of the Generation have the change.
static void PeeringTestHeld(PEERINGTEST_CTX *ctx, UINT64 gen, bool announced)
{
	PEERINGTEST_NODE *a = &ctx->Nodes[PEERINGTEST_A];
	PEERINGTEST_EXTRA *x = &peeringtest_extras[PEERINGTEST_EXTRA_B];
	PEERINGTEST_APPLY apply;
	NODE_PEERING_STATUS before, during;
	char what[MAX_SIZE * 2];
	UINT hop = NODE_VRF_NONE;

	Print("[Generation %I64u: node-b %s its extra LAN %s/%u while the apply at node-a holds]\n", gen, announced ? "announces" : "withdraws", x->Lan, (UINT)PEERINGTEST_LENGTH);

	// The Generation that the BGP peering of node-a has until the apply is done: the one of the rebuild that meets the apply
	UINT64 from = ctx->Generation;
	ctx->Generation = gen;
	ctx->Announced[PEERINGTEST_EXTRA_B] = announced;
	NodePeeringGetStatus(a->Node, &before);

	Zero(&apply, sizeof(apply));
	apply.Node = a->Node;
	apply.State = PeeringTestState(ctx, PEERINGTEST_A);
	ResetEvent(a->Held);
	ResetEvent(a->Release);
	a->Hold = gen;

	HANDLE thread = CreateThread(NULL, 0, PeeringTestApplyThread, &apply, 0, NULL);
	bool held = (thread != NULL && WaitForSingleObject(a->Held, PEERINGTEST_BOUND) == WAIT_OBJECT_0);

	// The window: node-b and node-c take the Generation, and the sidecar of node-a learns or withdraws the extra LAN of node-b
	bool others = true;
	for (UINT i = PEERINGTEST_B;i < PEERINGTEST_NODES;i++)
	{
		CONTROL_STATE *st = PeeringTestState(ctx, i);

		others = NodeOverlayApply(ctx->Nodes[i].Node, st) && others;
		PeeringTestFreeState(st);
	}

	UINT64 end = Tick64() + PEERINGTEST_BOUND;
	bool message = false;
	while (held && others)
	{
		message = (PeeringTestHasLearned(a, PEERINGTEST_B, x->Lan) == announced);
		if (message || Tick64() >= end)
		{
			break;
		}
		SleepThread(PEERINGTEST_POLL);
	}

	// ... and the worker of node-a, which the message woke, meets the apply that holds: its rebuild counts as one that met an apply
	// at once, while the apply still holds (NODE_PEERING_STATUS.NumDeferred)
	end = Tick64() + PEERINGTEST_BOUND;
	bool met = false;
	Zero(&during, sizeof(during));
	while (held && message)
	{
		NodePeeringGetStatus(a->Node, &during);
		met = (during.NumDeferred > before.NumDeferred);
		if (met || Tick64() >= end)
		{
			break;
		}
		SleepThread(PEERINGTEST_POLL);
	}

	a->Hold = 0;
	SetEvent(a->Release);
	if (thread != NULL)
	{
		WaitForSingleObject(thread, INFINITE);
		CloseHandle(thread);
	}
	PeeringTestFreeState(apply.State);

	Format(what, sizeof(what), "  The %s message of %s/%u of node-b reaches node-a while its apply of Generation %I64u holds, after the overlay took the Generation and before the BGP peering did",
		announced ? "learned" : "withdrawn", x->Lan, (UINT)PEERINGTEST_LENGTH, gen);
	PeeringTestCheck(ctx, held && others && message && apply.Applied, what, "held %u, node-b and node-c took the Generation %u, the message came %u, the apply at node-a went in %u",
		(UINT)held, (UINT)others, (UINT)message, (UINT)apply.Applied);
	PeeringTestCheck(ctx, met, "  The worker of node-a meets the apply that holds: its rebuild of the forwarding tables waits for the apply and is not lost",
		"%u rebuilds met an apply before the window and %u in it", before.NumDeferred, during.NumDeferred);
	// The node log of node-a says the rest once the node is freed (PeeringTestClose)
	if (met && ctx->NumWindows < PEERINGTEST_WINDOWS)
	{
		ctx->WindowFrom[ctx->NumWindows] = from;
		ctx->WindowTo[ctx->NumWindows] = gen;
		ctx->NumWindows++;
	}

	// After both: the forwarding tables of node-a of the Generation have the change, at once, and the mesh is the one of the Generation
	UINT want = (announced ? PeeringTestHop(PEERINGTEST_A, PEERINGTEST_B) : NODE_VRF_NONE);
	bool in = PeeringTestWaitHop(a, x->LanHost, want, &hop);
	Format(what, sizeof(what), "  After both, the forwarding table of red of node-a of Generation %I64u leads %s to %s", gen, x->LanHost, PeeringTestHopName(PEERINGTEST_A, want));
	PeeringTestCheck(ctx, in, what, "it leads it to %s %u ms after the apply", PeeringTestHopName(PEERINGTEST_A, hop), (UINT)PEERINGTEST_ARRIVE);

	PeeringTestConverge(ctx, apply.Applied && others);
}

// The window of an apply: the accept lists of the peers of node-b hold its extra LAN, which it does not announce yet (Generation 4).
// Then node-b announces it while the apply of Generation 5 at node-a holds, and withdraws it while the apply of Generation 6 holds:
// each message is in the forwarding tables of the Generation that node-a applied meanwhile.
static void PeeringTestWindow(PEERINGTEST_CTX *ctx)
{
	Print("[Generation 4: the accept lists hold the extra LAN of node-b, which node-b does not announce yet]\n");
	ctx->Accepted[PEERINGTEST_EXTRA_B] = true;
	ctx->Announced[PEERINGTEST_EXTRA_B] = false;
	PeeringTestConverge(ctx, PeeringTestApply(ctx, 4, true));

	PeeringTestHeld(ctx, 5, true);
	PeeringTestHeld(ctx, 6, false);
}

// A failed copy and a failed rebuild: node-b announces its extra LAN, which the accept lists hold (Generation 7), while the next copy
// of the Generation in force for a rebuild of the forwarding tables at node-a fails, as when there is no memory for it, and then the
// next rebuild, as when the tables cannot be built (NodePeeringFailNext). Node-a counts each and keeps the change: with no other
// change of the routes, a later pass builds the forwarding tables of the Generation with it. Its node log says each, which
// PeeringTestClose reads once the node is freed.
static void PeeringTestFailed(PEERINGTEST_CTX *ctx)
{
	PEERINGTEST_NODE *a = &ctx->Nodes[PEERINGTEST_A];
	PEERINGTEST_EXTRA *x = &peeringtest_extras[PEERINGTEST_EXTRA_B];
	NODE_PEERING_STATUS before, after;
	char what[MAX_SIZE * 2];

	Print("[Generation 7: node-b announces its extra LAN, which the accept lists hold, while the next copy of the state and then the next rebuild at node-a fail]\n");
	NodePeeringGetStatus(a->Node, &before);
	NodePeeringFailNext(a->Node, 1, 1);
	ctx->Accepted[PEERINGTEST_EXTRA_B] = true;
	ctx->Announced[PEERINGTEST_EXTRA_B] = true;
	bool tables = PeeringTestConverge(ctx, PeeringTestApply(ctx, 7, true));

	// The apply at node-a went in before node-b announced the extra LAN, so only a rebuild of the worker of node-a brings it in
	NodePeeringGetStatus(a->Node, &after);
	UINT hop = PeeringTestLookup(a, PEERINGTEST_RED, x->LanHost);
	bool failed = (after.NumFailed == before.NumFailed + 2);
	Format(what, sizeof(what), "  Node-a counts the failed copy and the failed rebuild, keeps the change, and a later pass builds its forwarding tables of Generation 7 with the route to %s/%u",
		x->Lan, (UINT)PEERINGTEST_LENGTH);
	PeeringTestCheck(ctx, tables && failed && after.NumRebuilds > before.NumRebuilds && hop == PeeringTestHop(PEERINGTEST_A, PEERINGTEST_B), what,
		"%u failed rebuilds before and %u after, %u rebuilds before and %u after, the table of red leads %s to %s", before.NumFailed, after.NumFailed, before.NumRebuilds,
		after.NumRebuilds, x->LanHost, PeeringTestHopName(PEERINGTEST_A, hop));
	if (failed)
	{
		ctx->Failed = 7;
	}
}

// A narrower accept list: node-b announces its extra LAN, which node-a learned with Generation 7 (PeeringTestFailed); Generation 8
// takes it from the accept lists of node-b at node-a and node-c, while node-b still announces it. The forwarding tables that node-a
// builds with Generation 8 have no route to it at once, before its sidecar takes the peers of the Generation and withdraws the route.
static void PeeringTestNarrowed(PEERINGTEST_CTX *ctx)
{
	PEERINGTEST_NODE *a = &ctx->Nodes[PEERINGTEST_A];
	PEERINGTEST_EXTRA *x = &peeringtest_extras[PEERINGTEST_EXTRA_B];
	char what[MAX_SIZE * 2];

	Print("[Generation 8: the accept lists no longer hold the extra LAN of node-b, which node-b still announces]\n");
	ctx->Generation = 8;
	ctx->Accepted[PEERINGTEST_EXTRA_B] = false;

	CONTROL_STATE *st = PeeringTestState(ctx, PEERINGTEST_A);
	bool applied = NodeOverlayApply(a->Node, st);
	PeeringTestFreeState(st);

	UINT hop = PeeringTestLookup(a, PEERINGTEST_RED, x->LanHost);
	bool learned = PeeringTestHasLearned(a, PEERINGTEST_B, x->Lan);
	Print("  [INFO] node-a %s the route to %s/%u that it learned from node-b when its forwarding tables of Generation 8 went in\n", learned ? "still held" : "no longer held", x->Lan,
		(UINT)PEERINGTEST_LENGTH);
	Format(what, sizeof(what), "  The forwarding tables of node-a of Generation 8 have no route to %s/%u, which the accept list of node-b there no longer holds", x->Lan, (UINT)PEERINGTEST_LENGTH);
	PeeringTestCheck(ctx, applied && hop == NODE_VRF_NONE, what, "applied %u, the table of red leads %s to %s", (UINT)applied, x->LanHost, PeeringTestHopName(PEERINGTEST_A, hop));

	bool others = true;
	for (UINT i = PEERINGTEST_B;i < PEERINGTEST_NODES;i++)
	{
		st = PeeringTestState(ctx, i);
		others = NodeOverlayApply(ctx->Nodes[i].Node, st) && others;
		PeeringTestFreeState(st);
	}

	PeeringTestConverge(ctx, applied && others);
}

// The routes that node i learns in the mesh of the Generation that runs: of each other node with which it shares a VRF that peers by
// BGP, its address and its LAN there, and its extra LANs in red that it announces and that its accept lists hold
static UINT PeeringTestNumLearned(PEERINGTEST_CTX *ctx, UINT i)
{
	UINT num = 0;

	for (UINT k = 0;k < PEERINGTEST_MEMBERS;k++)
	{
		PEERINGTEST_MEMBER *m = &peeringtest_members[k];

		if (m->Node != i && PeeringTestMember(i, m->VrfId) != NULL && PeeringTestPeers(ctx, m->VrfId) && ctx->Nodes[m->Node].Gone == false)
		{
			num += 2;
		}
	}
	for (UINT e = 0;e < PEERINGTEST_EXTRAS;e++)
	{
		if (PeeringTestWantExtra(ctx, i, e) != NODE_VRF_NONE && peeringtest_extras[e].Node != i)
		{
			num++;
		}
	}

	return num;
}

// A hostile peer: node-b announces more specific prefixes of its LAN in red, which no accept list holds (Generation 9). No node learns
// any of them, and every other route of every peer in red and in blue is learned: the reports, the forwarding tables and the adapters
// of the hosts are the ones of the mesh, and each node holds exactly the routes that its peers may announce.
static void PeeringTestHostile(PEERINGTEST_CTX *ctx)
{
	char what[MAX_SIZE * 2];

	Print("[Generation 9: node-b announces %u more specific prefixes of its LAN in red, which no accept list holds]\n", (UINT)PEERINGTEST_HOSTILE);
	ctx->Accepted[PEERINGTEST_EXTRA_B] = false;
	ctx->Announced[PEERINGTEST_EXTRA_B] = false;
	ctx->Hostile = true;
	PeeringTestConverge(ctx, PeeringTestApply(ctx, 9, true));

	for (UINT i = 0;i < PEERINGTEST_NODES;i++)
	{
		NODE_PEERING_STATUS st;
		UINT want = PeeringTestNumLearned(ctx, i);

		if (i == PEERINGTEST_B)
		{
			continue;
		}

		NodePeeringGetStatus(ctx->Nodes[i].Node, &st);
		Format(what, sizeof(what), "  %s holds the %u routes that its peers may announce, and none of the more specific prefixes of node-b", peeringtest_names[i], want);
		PeeringTestCheck(ctx, st.NumLearned == want, what, "%u learned routes", st.NumLearned);
	}

	ctx->Hostile = false;
}

// A failed send and a large mesh: node-a announces its extra LAN 192.168.6.0/24 (Generation 10). Then its sidecar stops answering,
// and Generation 11 gives node-a 200 more peers, whose sidecars never answer and whose peers messages fill more than the pipe holds,
// takes 192.168.6.0/24 from what it announces and gives it 192.168.7.0/24 to announce, while the accept lists of node-a hold both.
// The peers do not reach the sidecar, so node-a ends it and starts another, which has the 202 peers and announces 192.168.7.0/24 and
// not 192.168.6.0/24. Node-a holds and counts its 202 peers, beyond the 64 of a report, and the new sidecar names each of them.
static void PeeringTestLarge(PEERINGTEST_CTX *ctx)
{
	PEERINGTEST_NODE *a = &ctx->Nodes[PEERINGTEST_A];
	NODE_PEERING_STATUS before, after;
	LIST *threads = NewListFast(NULL);
	char what[MAX_SIZE * 2];

	Print("[Generation 10: node-a announces its extra LAN 192.168.6.0/24]\n");
	ctx->Accepted[PEERINGTEST_EXTRA_A6] = true;
	ctx->Announced[PEERINGTEST_EXTRA_A6] = true;
	ctx->Accepted[PEERINGTEST_EXTRA_A7] = true;
	ctx->Announced[PEERINGTEST_EXTRA_A7] = false;
	PeeringTestConverge(ctx, PeeringTestApply(ctx, 10, true));

	Print("[Generation 11: the sidecar of node-a does not answer, and node-a gets %u more peers, 192.168.7.0/24 to announce and not 192.168.6.0/24]\n",
		(UINT)PEERINGTEST_DUMMIES);
	NodePeeringGetStatus(a->Node, &before);
	bool frozen = (before.ProcessId != 0 && PeeringTestFreeze(before.ProcessId, threads));
	PeeringTestCheck(ctx, frozen, "  The threads of the sidecar of node-a are suspended: it reads nothing from its pipe", "process %u, %u threads suspended", before.ProcessId,
		LIST_NUM(threads));

	ctx->NumDummies[PEERINGTEST_A] = PEERINGTEST_DUMMIES;
	ctx->Announced[PEERINGTEST_EXTRA_A6] = false;
	ctx->Announced[PEERINGTEST_EXTRA_A7] = true;
	bool applied = PeeringTestApply(ctx, 11, true);

	// The peers do not reach the sidecar: node-a ends it, and another starts after NODE_PEERING_RESTART
	UINT64 end = Tick64() + NODE_PEERING_RESTART + PEERINGTEST_BOUND;
	bool replaced = false;
	Zero(&after, sizeof(after));
	while (applied && frozen)
	{
		NodePeeringGetStatus(a->Node, &after);
		replaced = (after.NumUnsent == before.NumUnsent + 1 && after.NumStarts == before.NumStarts + 1 && after.Running && after.ProcessId != before.ProcessId);
		if (replaced || Tick64() >= end)
		{
			break;
		}
		SleepThread(PEERINGTEST_POLL);
	}
	PeeringTestThaw(threads);
	ReleaseList(threads);
	PeeringTestCheck(ctx, replaced, "  The peers of node-a do not reach its sidecar, whose pipe is full: node-a ends it and starts another",
		"applied %u, %u messages did not reach a sidecar before and %u after, %u sidecars started before and %u after, running %u", (UINT)applied, before.NumUnsent, after.NumUnsent,
		before.NumStarts, after.NumStarts, (UINT)after.Running);
	if (replaced)
	{
		ctx->Starts[PEERINGTEST_A]++;
	}

	// The new sidecar has every peer, and names each of them; node-a holds and counts them, beyond the 64 of a report
	end = Tick64() + PEERINGTEST_BOUND;
	bool whole = false;
	while (replaced)
	{
		NodePeeringGetStatus(a->Node, &after);
		whole = (after.NumPeers == PEERINGTEST_NODES - 1 + PEERINGTEST_DUMMIES && after.NumNamed == after.NumPeers && after.NumEstablished == PEERINGTEST_NODES - 1);
		if (whole || Tick64() >= end)
		{
			break;
		}
		SleepThread(PEERINGTEST_POLL);
	}
	Format(what, sizeof(what), "  Node-a holds and counts its %u peers, more than the %u of a report, and its new sidecar names the session of each: it took them all",
		(UINT)(PEERINGTEST_NODES - 1 + PEERINGTEST_DUMMIES), (UINT)CONTROL_MAX_PEERING_PEERS);
	PeeringTestCheck(ctx, whole, what, "%u peers, %u named by the sidecar, %u established", after.NumPeers, after.NumNamed, after.NumEstablished);

	// ... and announces 192.168.7.0/24 and not 192.168.6.0/24: the mesh of Generation 11
	PeeringTestConverge(ctx, applied);

	Print("[Generation 12: node-a without the peers of the large mesh and without its extra LANs]\n");
	ctx->NumDummies[PEERINGTEST_A] = 0;
	for (UINT e = 0;e < PEERINGTEST_EXTRAS;e++)
	{
		ctx->Accepted[e] = false;
		ctx->Announced[e] = false;
	}
	PeeringTestConverge(ctx, PeeringTestApply(ctx, 12, true));
}

// NodeOverlayStop of a node under the lock of the node, as NodeClientFree calls it, on a thread of its own
typedef struct PEERINGTEST_STOP
{
	NODE *Node;
	UINT64 Took;						// How long NodeOverlayStop took (ms)
} PEERINGTEST_STOP;

static DWORD WINAPI PeeringTestOverlayStopThread(LPVOID param)
{
	PEERINGTEST_STOP *s = (PEERINGTEST_STOP *)param;

	Lock(s->Node->Lock);
	{
		UINT64 start = Tick64();

		NodeOverlayStop(s->Node);
		s->Took = Tick64() - start;
	}
	Unlock(s->Node->Lock);

	return 0;
}

// The halt: the sidecar of node-b stops answering, and a Generation of node-b with a large mesh makes its worker send peers into the
// pipe that the sidecar does not read. NodeOverlayStop of node-b under the lock of the node, as NodeClientFree calls it, returns
// within PEERINGTEST_HALT: it waits neither for the send nor for the sidecar, which exits later, within the time that the node gives
// it, ended by its job.
static void PeeringTestHalt(PEERINGTEST_CTX *ctx)
{
	PEERINGTEST_NODE *b = &ctx->Nodes[PEERINGTEST_B];
	NODE_PEERING_STATUS st;
	PEERINGTEST_STOP stop;
	LIST *threads = NewListFast(NULL);
	char what[MAX_SIZE * 2];

	Print("[the sidecar of node-b does not answer, and node-b stops its overlay under the lock of the node]\n");

	NodePeeringGetStatus(b->Node, &st);
	bool frozen = (st.ProcessId != 0 && PeeringTestFreeze(st.ProcessId, threads));
	PeeringTestCheck(ctx, frozen, "  The threads of the sidecar of node-b are suspended: it reads nothing from its pipe", "process %u, %u threads suspended", st.ProcessId,
		LIST_NUM(threads));

	// A Generation of node-b alone with a large mesh: its worker sends the peers into the pipe that the sidecar does not read
	ctx->Generation = 13;
	ctx->NumDummies[PEERINGTEST_B] = PEERINGTEST_DUMMIES;
	CONTROL_STATE *state = PeeringTestState(ctx, PEERINGTEST_B);
	bool applied = NodeOverlayApply(b->Node, state);
	PeeringTestFreeState(state);
	SleepThread(PEERINGTEST_GRACE);

	NodeReaderUnregister(b->Node, &b->Reader);
	b->Gone = true;

	Zero(&stop, sizeof(stop));
	stop.Node = b->Node;
	HANDLE thread = CreateThread(NULL, 0, PeeringTestOverlayStopThread, &stop, 0, NULL);
	bool returned = (thread != NULL && WaitForSingleObject(thread, PEERINGTEST_BOUND) == WAIT_OBJECT_0);
	if (thread != NULL)
	{
		WaitForSingleObject(thread, INFINITE);
		CloseHandle(thread);
	}

	Format(what, sizeof(what), "  NodeOverlayStop of node-b under the lock of the node returns within %u ms, while its sidecar does not answer and its worker sends it peers",
		(UINT)PEERINGTEST_HALT);
	PeeringTestCheck(ctx, applied && returned && stop.Took <= PEERINGTEST_HALT, what, "applied %u, returned %u, after %I64u ms", (UINT)applied, (UINT)returned, stop.Took);
	PeeringTestCheck(ctx, st.ProcessId != 0 && PeeringTestWaitExited(st.ProcessId), "  The sidecar of node-b, which does not answer, exits within the time that the node gives it",
		"process %u", st.ProcessId);

	PeeringTestThaw(threads);
	ReleaseList(threads);

	// The rest of node-b stops here, without its reader
	NodeStop(b->Node);
	b->Stopped = true;
}

// The nodes and their overlays without a control stream, the test thread a reader of the tables of each
static bool PeeringTestOpen(PEERINGTEST_CTX *ctx, TRANSPORT *loopback)
{
	UCHAR scalar[PEER_KEY_SIZE];
	char what[MAX_SIZE];
	bool ok = (loopback != NULL);

	Print("[the nodes and their overlays]\n");

	for (UINT i = 0;i < PEERINGTEST_NODES && ok;i++)
	{
		PEERINGTEST_NODE *t = &ctx->Nodes[i];
		NODE_OVERLAY_CONFIG c;

		InitializeSRWLock(&t->Lock);
		// The events with which the test holds an apply in the adapter of the host (PeeringTestHostState)
		t->Held = CreateEventW(NULL, TRUE, FALSE, NULL);
		t->Release = CreateEventW(NULL, TRUE, FALSE, NULL);
		for (UINT j = 0;j < PEER_KEY_SIZE;j++)
		{
			scalar[j] = (UCHAR)(0x71 + PEER_KEY_SIZE * i + j);
		}
		ok = PeerKeyFromScalar(&t->Key, scalar) && t->Held != NULL && t->Release != NULL;

		PeeringTestNewDir(t->Dir, sizeof(t->Dir), peeringtest_names[i]);
		t->Node = NewNode(t->Dir);
		if (i == 0)
		{
			ok = PeeringTestCheck(ctx, IsFileExistsW(t->Node->BgpSidecar), "ranz.exe, which holds the sidecar ranz bgp, is next to vpntest.exe", "%S is missing",
				t->Node->BgpSidecar) && ok;
		}
		NodeStart(t->Node);
		NodeReaderRegister(t->Node, &t->Reader);
		NodeReaderOffline(&t->Reader);

		Zero(&c, sizeof(c));
		c.Data = loopback;
		c.Key = &t->Key;
		c.Adapter = PeeringTestAdapter;
		c.AdapterParam = t;
		c.State = PeeringTestHostState;
		Format(what, sizeof(what), "  %s: its overlay runs without a control stream, and its sidecar will listen on TCP %u of %s", peeringtest_names[i],
			(UINT)PEERINGTEST_PORT, peeringtest_addrs[i]);
		ok = PeeringTestCheck(ctx, ok && NodeOverlayStart(t->Node, &c), what, "%s", "PeerKeyFromScalar or NodeOverlayStart failed") && ok;
	}
	Zero(scalar, sizeof(scalar));

	return ok;
}

// The nodes that run stop, with every thread joined, and each is freed. The log of the sidecar of each node shows that the
// node started ranz.exe bgp; when a check failed, the log of each node and of its sidecar is printed before the data
// directories go.
static void PeeringTestClose(PEERINGTEST_CTX *ctx)
{
	for (UINT i = 0;i < PEERINGTEST_NODES;i++)
	{
		PEERINGTEST_NODE *t = &ctx->Nodes[i];

		if (t->Node != NULL && t->Stopped == false)
		{
			NodeReaderUnregister(t->Node, &t->Reader);
			NodeStop(t->Node);
		}
		if (t->Node != NULL)
		{
			FreeNode(t->Node);
		}
	}

	for (UINT i = 0;i < PEERINGTEST_NODES && ctx->Ran;i++)
	{
		char *log = PeeringTestReadLog(ctx->Nodes[i].Dir, NODE_PEERING_LOG_NAME);
		char what[MAX_SIZE];

		Format(what, sizeof(what), "The log of the sidecar of %s shows its command line: ranz.exe bgp -pipe", peeringtest_names[i]);
		PeeringTestCheck(ctx, log != NULL && SearchStrEx(log, "ranz.exe bgp -pipe", 0, true) != INFINITE, what, "%s", log == NULL ? "there is no log" : "no such line");
		Free(log);
	}

	// The node log of node-a, whole once the node is freed: the rebuild that met the apply of each window (PeeringTestHeld) found the
	// Generation that the apply put in force and said so, and a later pass built the tables of that Generation (SDN-77-R1, #531)
	char *node_log = (ctx->NumWindows != 0 || ctx->Failed != 0 ? PeeringTestReadLog(ctx->Nodes[PEERINGTEST_A].Dir, NULL) : NULL);
	for (UINT k = 0;k < ctx->NumWindows;k++)
	{
		char stale[MAX_SIZE], built[MAX_SIZE], what[MAX_SIZE];

		Format(stale, sizeof(stale), "BGP peering: generation %I64u went out of force while its forwarding tables were built anew", ctx->WindowFrom[k]);
		Format(built, sizeof(built), "BGP peering: the forwarding tables of generation %I64u built anew", ctx->WindowTo[k]);
		UINT at = (node_log != NULL ? SearchStrEx(node_log, stale, 0, true) : INFINITE);
		bool rebuilt = (at != INFINITE && SearchStrEx(node_log, built, at, true) != INFINITE);

		Format(what, sizeof(what), "The node log of node-a says that its rebuild with Generation %I64u found Generation %I64u in force, and a later pass built the tables of Generation %I64u",
			ctx->WindowFrom[k], ctx->WindowTo[k], ctx->WindowTo[k]);
		PeeringTestCheck(ctx, rebuilt, what, "%s", node_log == NULL ? "there is no log" : (at == INFINITE ? "no line of the rebuild that found another Generation" : "no rebuild of that Generation after it"));
	}

	// ... and that the copy of the state for a rebuild failed, then a rebuild of Generation ctx->Failed, and that a later pass built
	// the tables of that Generation (PeeringTestFailed)
	if (ctx->Failed != 0)
	{
		char copy[MAX_SIZE], rebuild[MAX_SIZE], built[MAX_SIZE];

		StrCpy(copy, sizeof(copy), "BGP peering: the forwarding tables are not built anew with the learned routes: no memory for a copy of the Generation in force");
		Format(rebuild, sizeof(rebuild), "BGP peering: the forwarding tables of generation %I64u could not be built anew with the learned routes", ctx->Failed);
		Format(built, sizeof(built), "BGP peering: the forwarding tables of generation %I64u built anew", ctx->Failed);
		UINT at = (node_log != NULL ? SearchStrEx(node_log, copy, 0, true) : INFINITE);
		UINT again = (at != INFINITE ? SearchStrEx(node_log, rebuild, at, true) : INFINITE);
		bool said = (again != INFINITE && SearchStrEx(node_log, built, again, true) != INFINITE);

		PeeringTestCheck(ctx, said, "The node log of node-a says that a copy of the state for a rebuild failed, then a rebuild, and that a later pass built the tables of the Generation",
			"%s", node_log == NULL ? "there is no log" : (at == INFINITE ? "no line of the failed copy" : (again == INFINITE ? "no line of the failed rebuild after it" : "no rebuild after them")));
	}
	Free(node_log);

	for (UINT i = 0;i < PEERINGTEST_NODES;i++)
	{
		PEERINGTEST_NODE *t = &ctx->Nodes[i];
		wchar_t log_dir[MAX_PATH];

		if (t->Node != NULL)
		{
			if (ctx->NumFailed != 0)
			{
				char *log = PeeringTestReadLog(t->Dir, NULL);

				Print("  --- the node log and the sidecar log of %s ---\n%s  ---\n", peeringtest_names[i], log == NULL ? "(none)\n" : log);
				Free(log);
			}

			ConbinePathW(log_dir, sizeof(log_dir), t->Dir, NODE_LOG_DIR_NAME);
			PeeringTestDeleteFiles(log_dir);
			PeeringTestDeleteFiles(t->Dir);
			t->Node = NULL;
		}
		PeerKeyClose(&t->Key);
		if (t->Held != NULL)
		{
			CloseHandle(t->Held);
		}
		if (t->Release != NULL)
		{
			CloseHandle(t->Release);
		}
	}
}

// The full mesh, the refused session, the report on the control stream, red without the peering and back, the findings of the
// review of SDN-77 (SDN-77-R1, #531), the sidecar of node-c that stops answering, node-c that stops, and the halt of node-b
static void PeeringTestRun(PEERINGTEST_CTX *ctx)
{
	NODE_PEERING_STATUS a;

	ctx->Ran = true;
	for (UINT i = 0;i < PEERINGTEST_NODES;i++)
	{
		ctx->Starts[i] = 1;
	}
	if (PeeringTestMesh(ctx, 1, true) == false)
	{
		return;
	}

	PeeringTestRefused(ctx);
	PeeringTestWire(ctx);

	// Red stops peering: node-a, in no VRF that peers any more, stops its sidecar
	NodePeeringGetStatus(ctx->Nodes[PEERINGTEST_A].Node, &a);
	PeeringTestMesh(ctx, 2, false);
	PeeringTestCheck(ctx, a.ProcessId != 0 && PeeringTestWaitExited(a.ProcessId), "The sidecar of node-a of Generation 1 exited", "process %u", a.ProcessId);

	// Red peers again: node-a starts a new sidecar
	ctx->Starts[PEERINGTEST_A] = 2;
	if (PeeringTestMesh(ctx, 3, true) == false)
	{
		return;
	}

	PeeringTestWindow(ctx);
	PeeringTestFailed(ctx);
	PeeringTestNarrowed(ctx);
	PeeringTestHostile(ctx);
	PeeringTestLarge(ctx);

	PeeringTestSilent(ctx);
	PeeringTestStop(ctx);
	PeeringTestHalt(ctx);
}

// peering: the BGP peering of the standard mode between three nodes
RANZ_TEST("peering", peering_test, "BGP peering of the standard mode: three nodes, each with its sidecar ranz bgp (ranz.exe next to vpntest) on TCP 179 of a loopback address of its own, in a full mesh of two VRFs; what each learns and installs in its forwarding tables and on the adapter of its host, a session from an address that the Controller did not name refused and counted, the report on the control stream, the peering of a VRF removed and back, a route change during an apply, a failed copy of the state and a failed rebuild, a narrower accept list, a hostile peer, a failed send in a large mesh, the routes of a node whose sidecar stops answering, or that stops, gone from the other two within the hold time, and a halt that waits for no sidecar.");
void peering_test(UINT num, char **arg)
{
	PEERINGTEST_CTX *ctx = ZeroMalloc(sizeof(PEERINGTEST_CTX));
	HANDLE done = CreateEventW(NULL, TRUE, FALSE, NULL);
	HANDLE watchdog = (done != NULL ? CreateThread(NULL, 0, PeeringTestWatchdog, done, 0, NULL) : NULL);
	TRANSPORT *loopback = TransportLoopbackNew("loopback", 0, false);

	Print("BGP peering test: three nodes peer by BGP in the standard mode, each with its own sidecar ranz bgp\n");

	ctx->Seq = 1;
	ctx->Loopback = loopback;
	if (PeeringTestOpen(ctx, loopback))
	{
		PeeringTestRun(ctx);
	}

	PeeringTestClose(ctx);
	TransportLoopbackFree(loopback);

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

	if (ctx->NumFailed == 0)
	{
		Print("PEERING TEST OK\n");
	}
	else
	{
		Print("PEERING TEST FAILED (%u of %u checks failed)\n", ctx->NumFailed, ctx->NumChecks);
	}

	Free(ctx);
}
