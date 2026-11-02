// reflectortest.c
// Named route reflector test of vpntest ("reflector" command, SDN-79 #359)
//
// The route reflectors of the BGP peering of the standard mode (Cedar/NodePeering.c, ranz-bgp/internal/sidecar/reflector.go) on
// the harness of the ticket, a reflector and three clients: in-process nodes, each with its own sidecar ranz bgp (ranz.exe next to
// vpntest, GoBGP), which listens on TCP 179 of the address of its node on the network that the operator trusts and connects from
// there: 127.0.0.2 for the reflector node-r, 127.0.0.3, 127.0.0.4 and 127.0.0.5 for the clients node-a, node-b and node-c, and
// 127.0.0.6 for node-s, which is in no VRF until Generation 2 makes it the second reflector. The test applies the desired states of
// the nodes itself (NodeOverlayApply), as the Controller compiles them (controller/internal/desired/peering.go and reflector.go): for
// each peer the address of its sidecar, the hold time of their session, its VRFs, what the peer may announce there, its address and
// its LAN subnet, and its role there: a reflector, a client of the node, or reflected, when both are clients. Every node is a member
// of VRF red (101), and all but node-a of VRF blue (102); the Intent names the same reflectors for both, which have no LAN subnet of
// their own. 192.168.1.0/24 is the LAN of node-a in red and the LAN of node-c in blue. Fake adapters stand in for the hosts, and the
// in-process loopback transport carries the packets between the nodes: the links of the VRFs stay a full mesh, of kind noise in the
// harness (see peeringtest.c), and only the BGP sessions go through the reflectors.
// - One reflector and three clients (Generation 1): each client has a session with node-r and with no other node, and node-r has one
//   with each client; the TCP table of the host holds no connection between two clients on TCP 179. Each client learns from node-r
//   what node-r and the other clients announce in the VRFs that the two share, each prefix in its VRF, and its forwarding tables lead
//   the LAN of each other client to that client, never to the reflector, as do the routes that the adapter of its host takes. A packet
//   of each host to the LAN of each other node arrives at the host of that node, in that VRF.
// - No route crosses into another VRF: node-a, in no VRF blue, learns nothing of blue, and the two LANs 192.168.1.0/24 stay apart:
//   node-b reaches the one of node-a in red and the one of node-c in blue, and a packet of a VRF to a LAN of the other goes nowhere.
// - A session from 127.0.0.9, an address that the Controller did not name, to node-r is refused, and node-r counts it; so is a session
//   from the address of node-b to node-a: the Controller names node-b to node-a only as another client of the reflectors.
// - The only reflector stops answering, as a host that loses power: the threads of the sidecar of node-r are suspended. Each client
//   withdraws the routes of the other clients within the hold time. Once node-r runs a sidecar that answers, they come back.
// - Two reflectors (Generation 2): node-s joins red and blue as their second reflector, and each client has a session with each
//   reflector. Node-r stops answering again: each client keeps the routes of the other clients through node-s at every look, past
//   the hold time after which its session with node-r ends, and the packets between the clients still arrive.
// Print "REFLECTOR TEST OK" only when every check passes. .github/scripts/bgp-peering.ps1 builds ranz.exe and runs it.

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
#include <iphlpapi.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define	REFLECTORTEST_BUDGET		600000		// The whole test ends within this time, or the watchdog ends the process (ms)
#define	REFLECTORTEST_BOUND			60000		// A bounded wait on observable state (ms)
#define	REFLECTORTEST_ARRIVE		10000		// A packet that the overlay took arrives within this time (ms)
#define	REFLECTORTEST_QUIET			300			// A host that gets nothing gets nothing within this time (ms)
#define	REFLECTORTEST_POLL			50			// Poll interval of observable state (ms)
#define	REFLECTORTEST_SIZE			100			// The size of a test packet
#define	REFLECTORTEST_TEXT			4096		// The size of the text of the report of a node
#define	REFLECTORTEST_ASN			4200000000U	// The AS of the overlay, one for every node (intent.PeeringASN)
#define	REFLECTORTEST_HOLD			9			// The BGP hold time of the sessions in s, as the VRFs of the Intent name it
#define	REFLECTORTEST_GRACE			1000		// What the sidecar and the node take past the hold time to remove the routes (ms)
#define	REFLECTORTEST_PORT			179			// The BGP port of the sidecars
#define	REFLECTORTEST_STRANGER		"127.0.0.9"	// An address that the Controller did not name
#define	REFLECTORTEST_RED			101			// The id of VRF red ...
#define	REFLECTORTEST_BLUE			102			// ... and of VRF blue
#define	REFLECTORTEST_LENGTH		24			// The prefix length of the Networks and of the LAN subnets

// The nodes, in name order, which is the order of the peers in a state
#define	REFLECTORTEST_A				0
#define	REFLECTORTEST_B				1
#define	REFLECTORTEST_C				2
#define	REFLECTORTEST_R				3
#define	REFLECTORTEST_S				4
#define	REFLECTORTEST_NODES			5

static char *reflectortest_names[REFLECTORTEST_NODES] = {"node-a", "node-b", "node-c", "node-r", "node-s"};

// The address of each node on the network that the operator trusts: its sidecar listens on TCP 179 there and connects from there,
// and it is the router id of the node, as the Controller makes one of an IPv4 tunnel endpoint (intent.RouterID)
static char *reflectortest_addrs[REFLECTORTEST_NODES] = {"127.0.0.3", "127.0.0.4", "127.0.0.5", "127.0.0.2", "127.0.0.6"};

// The VRFs of the test in name order, blue before red, and in the order of their id
static const UINT reflectortest_by_name[2] = {REFLECTORTEST_BLUE, REFLECTORTEST_RED};
static const UINT reflectortest_by_id[2] = {REFLECTORTEST_RED, REFLECTORTEST_BLUE};

// A node in a VRF: its address there, and the LAN subnet behind it there with a host of that subnet, NULL for none
typedef struct REFLECTORTEST_MEMBER
{
	UINT Node;
	UINT VrfId;
	char *Address;
	char *Lan;
	char *LanHost;
} REFLECTORTEST_MEMBER;

// The members of the VRFs, by node, then VRF id: the LAN 192.168.1.0/24 is the one of node-a in red and of node-c in blue, and the
// reflectors have no LAN subnet. Node-s is a member only while it is the second reflector (ReflectorTestMember).
static REFLECTORTEST_MEMBER reflectortest_members[] =
{
	{REFLECTORTEST_A, REFLECTORTEST_RED, "10.0.0.3", "192.168.1.0", "192.168.1.10"},
	{REFLECTORTEST_B, REFLECTORTEST_RED, "10.0.0.4", "192.168.2.0", "192.168.2.10"},
	{REFLECTORTEST_B, REFLECTORTEST_BLUE, "10.1.0.4", "192.168.4.0", "192.168.4.10"},
	{REFLECTORTEST_C, REFLECTORTEST_RED, "10.0.0.5", "192.168.3.0", "192.168.3.10"},
	{REFLECTORTEST_C, REFLECTORTEST_BLUE, "10.1.0.5", "192.168.1.0", "192.168.1.10"},
	{REFLECTORTEST_R, REFLECTORTEST_RED, "10.0.0.2", NULL, NULL},
	{REFLECTORTEST_R, REFLECTORTEST_BLUE, "10.1.0.2", NULL, NULL},
	{REFLECTORTEST_S, REFLECTORTEST_RED, "10.0.0.6", NULL, NULL},
	{REFLECTORTEST_S, REFLECTORTEST_BLUE, "10.1.0.6", NULL, NULL},
};

#define	REFLECTORTEST_MEMBERS		(sizeof(reflectortest_members) / sizeof(reflectortest_members[0]))

// A route of a peer in a state that the adapter of a host took, with the node of that peer
typedef struct REFLECTORTEST_HOST_ROUTE
{
	UINT Node;							// The node of the peer, REFLECTORTEST_NODES for a peer of another name
	CONTROL_ROUTE Route;
} REFLECTORTEST_HOST_ROUTE;

#define	REFLECTORTEST_HOST_ROUTES	((REFLECTORTEST_NODES - 1) * CONTROL_MAX_ROUTES)

// One node and the fake adapter of its host, which keeps the last packet that the host took and the routes of the peers in the
// last state that it took
typedef struct REFLECTORTEST_NODE
{
	wchar_t Dir[MAX_PATH];				// Its data directory
	PEER_KEY Key;						// Its static key
	NODE *Node;
	NODE_READER Reader;					// The test thread as a reader of the node's tables, online while it looks up or sends
	bool Gone;							// Its sidecar does not answer: the test looks neither at its tables nor at its host
	SRWLOCK Lock;						// LastVrf, Last, LastSize, NumHostRoutes and HostRoutes
	volatile LONG Arrivals;				// Packets that the host took
	UINT LastVrf;						// The VRF of the last one ...
	UCHAR Last[REFLECTORTEST_SIZE * 2];	// ... and the packet, as much as fits
	UINT LastSize;
	UINT NumHostRoutes;					// The routes of the peers in the last state that the adapter took
	REFLECTORTEST_HOST_ROUTE HostRoutes[REFLECTORTEST_HOST_ROUTES];
} REFLECTORTEST_NODE;

// A thread of a sidecar that the test suspended
typedef struct REFLECTORTEST_THREAD
{
	DWORD Id;
	HANDLE Handle;
} REFLECTORTEST_THREAD;

// The test
typedef struct REFLECTORTEST_CTX
{
	UINT NumChecks;
	UINT NumFailed;
	REFLECTORTEST_NODE Nodes[REFLECTORTEST_NODES];
	UINT64 Generation;					// The Generation that the nodes run ...
	bool Second;						// ... and whether node-s is the second reflector of red and blue in it; else it is in no VRF
	bool Cut;							// The only reflector does not answer: no client has a route of another
	UINT Seq;							// The data of the next test packet
} REFLECTORTEST_CTX;

static bool ReflectorTestCheck(REFLECTORTEST_CTX *ctx, bool ok, char *what, char *fmt, ...) RANZ_PRINTF_FORMAT(4, 5);
static bool ReflectorTestCheck(REFLECTORTEST_CTX *ctx, bool ok, char *what, char *fmt, ...)
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

// The watchdog: a native thread that ends a run that hangs, so that a session that never comes is a failed test instead of a hung
// CI step
static DWORD WINAPI ReflectorTestWatchdog(LPVOID param)
{
	char msg[MAX_SIZE];
	DWORD written = 0;

	if (WaitForSingleObject((HANDLE)param, REFLECTORTEST_BUDGET) != WAIT_TIMEOUT)
	{
		return 0;
	}

	int len = snprintf(msg, sizeof(msg), "REFLECTOR TEST FAILED (did not finish within %u ms)\n", REFLECTORTEST_BUDGET);
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
static bool ReflectorTestIp(UCHAR *addr, char *str)
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
static char *ReflectorTestVrfName(UINT vrf_id)
{
	return (vrf_id == REFLECTORTEST_RED ? "red" : (vrf_id == REFLECTORTEST_BLUE ? "blue" : "?"));
}

// Whether node i is in the Generation that runs: node-s only while it is the second reflector
static bool ReflectorTestIn(REFLECTORTEST_CTX *ctx, UINT i)
{
	return (i != REFLECTORTEST_S || ctx->Second);
}

// Node i in the VRF vrf_id in the Generation that runs, NULL when it is not a member of it
static REFLECTORTEST_MEMBER *ReflectorTestMember(REFLECTORTEST_CTX *ctx, UINT i, UINT vrf_id)
{
	if (ReflectorTestIn(ctx, i) == false)
	{
		return NULL;
	}

	for (UINT k = 0;k < REFLECTORTEST_MEMBERS;k++)
	{
		if (reflectortest_members[k].Node == i && reflectortest_members[k].VrfId == vrf_id)
		{
			return &reflectortest_members[k];
		}
	}

	return NULL;
}

// Whether node i is a route reflector of red and blue in the Generation that runs: node-r always, node-s while it is the second one
static bool ReflectorTestReflector(REFLECTORTEST_CTX *ctx, UINT i)
{
	return (i == REFLECTORTEST_R || (i == REFLECTORTEST_S && ctx->Second));
}

// Whether nodes i and j share a VRF in the Generation that runs; every VRF of the test peers by BGP
static bool ReflectorTestShare(REFLECTORTEST_CTX *ctx, UINT i, UINT j)
{
	for (UINT k = 0;k < 2;k++)
	{
		if (ReflectorTestMember(ctx, i, reflectortest_by_id[k]) != NULL && ReflectorTestMember(ctx, j, reflectortest_by_id[k]) != NULL)
		{
			return true;
		}
	}

	return false;
}

// Whether the sidecars of nodes i and j have a session in the Generation that runs: they share a VRF, and one of them at least is
// a reflector of it, as the Controller expects it (intent.PeeringSession)
static bool ReflectorTestSession(REFLECTORTEST_CTX *ctx, UINT i, UINT j)
{
	return (i != j && ReflectorTestShare(ctx, i, j) && (ReflectorTestReflector(ctx, i) || ReflectorTestReflector(ctx, j)));
}

// The index of node j among the peers of node i, the next hop of its routes in the forwarding tables of node i: every two nodes of
// the Generation share red, and node-s, the last in name order, is in it or in no VRF, so the peers of a node of the Generation are
// the other nodes of the Generation, in name order
static UINT ReflectorTestHop(UINT i, UINT j)
{
	return (j < i ? j : j - 1);
}

// What the next hop hop of the forwarding tables of node i is, in words
static char *ReflectorTestHopName(UINT i, UINT hop)
{
	if (hop == NODE_VRF_LOCAL)
	{
		return "its host";
	}
	if (hop == NODE_VRF_NONE)
	{
		return "no route";
	}
	if (hop < REFLECTORTEST_NODES - 1)
	{
		return reflectortest_names[hop < i ? hop : hop + 1];
	}

	return "another next hop";
}

// A route of the control protocol: the IPv4 prefix addr/length of the VRF vrf_id
static void ReflectorTestRoute(CONTROL_ROUTE *r, UINT vrf_id, char *addr, UINT length)
{
	Zero(r, sizeof(CONTROL_ROUTE));
	r->VrfId = vrf_id;
	r->AddressSize = 4;
	r->Length = length;
	ReflectorTestIp(r->Address, addr);
}

// The address of the member m, as the control protocol carries it
static void ReflectorTestAddress(CONTROL_ADDRESS *a, REFLECTORTEST_MEMBER *m)
{
	Zero(a, sizeof(CONTROL_ADDRESS));
	StrCpy(a->Network, sizeof(a->Network), ReflectorTestVrfName(m->VrfId));
	a->VrfId = m->VrfId;
	a->AddressSize = 4;
	a->Length = REFLECTORTEST_LENGTH;
	ReflectorTestIp(a->Address, m->Address);
}

// The desired state of node i in the Generation that runs, as the Controller compiles it: its VRFs in name order, each with a link
// of kind noise in the harness and peering by BGP, and its address in each, in the order of their Network, which has the name of the
// VRF; the LAN subnets behind it, by VRF id; the settings of its sidecar with the LAN subnets that it announces; and the other nodes
// of its VRFs as its peers in name order, each with its addresses in the VRFs that the two share and the BGP peering with it: the
// address of its sidecar, the hold time, the VRFs of their session, what it may announce there, its address as a host route and its
// LAN subnet in each, and its role in each (intent.PeeringRole, desired/reflector.go): a reflector, a client of node i, a reflector
// there, or reflected, when both are clients. ReflectorTestFreeState frees it.
static CONTROL_STATE *ReflectorTestState(REFLECTORTEST_CTX *ctx, UINT i)
{
	CONTROL_STATE *st = ZeroMalloc(sizeof(CONTROL_STATE));
	CONTROL_PEERING *own = ZeroMalloc(sizeof(CONTROL_PEERING));

	st->Generation = ctx->Generation;
	StrCpy(st->Name, sizeof(st->Name), reflectortest_names[i]);

	for (UINT k = 0;k < 2;k++)
	{
		REFLECTORTEST_MEMBER *m = ReflectorTestMember(ctx, i, reflectortest_by_name[k]);

		if (m == NULL)
		{
			continue;
		}

		CONTROL_VRF *v = &st->Vrfs[st->NumVrfs++];
		StrCpy(v->Name, sizeof(v->Name), ReflectorTestVrfName(m->VrfId));
		v->Id = m->VrfId;
		v->Link = CONTROL_LINK_NOISE;
		v->Peering = true;

		ReflectorTestAddress(&st->Addresses[st->NumAddresses++], m);
	}

	// The LAN subnets behind the node in its VRFs, which lead to its host and which it announces
	own->Asn = REFLECTORTEST_ASN;
	ReflectorTestIp(own->RouterId, reflectortest_addrs[i]);
	ReflectorTestIp(own->Address, reflectortest_addrs[i]);
	own->AddressSize = 4;
	for (UINT k = 0;k < 2;k++)
	{
		REFLECTORTEST_MEMBER *m = ReflectorTestMember(ctx, i, reflectortest_by_id[k]);

		if (m == NULL || m->Lan == NULL)
		{
			continue;
		}

		ReflectorTestRoute(&st->LanSubnets[st->NumLanSubnets++], m->VrfId, m->Lan, REFLECTORTEST_LENGTH);
		ReflectorTestRoute(&own->Announce[own->NumAnnounce++], m->VrfId, m->Lan, REFLECTORTEST_LENGTH);
	}
	st->Peering = own;

	st->Peers = ZeroMalloc(sizeof(CONTROL_PEER) * (REFLECTORTEST_NODES - 1));
	for (UINT j = 0;j < REFLECTORTEST_NODES;j++)
	{
		if (j == i || ReflectorTestShare(ctx, i, j) == false)
		{
			continue;
		}

		CONTROL_PEER *cp = &st->Peers[st->NumPeers++];
		CONTROL_PEER_PEERING *pp = ZeroMalloc(sizeof(CONTROL_PEER_PEERING));

		StrCpy(cp->Name, sizeof(cp->Name), reflectortest_names[j]);
		Copy(cp->Key, ctx->Nodes[j].Key.Public, PEER_KEY_SIZE);
		for (UINT k = 0;k < 2;k++)
		{
			REFLECTORTEST_MEMBER *m = ReflectorTestMember(ctx, j, reflectortest_by_name[k]);

			if (m != NULL && ReflectorTestMember(ctx, i, m->VrfId) != NULL)
			{
				ReflectorTestAddress(&cp->Addresses[cp->NumAddresses++], m);
			}
		}

		ReflectorTestIp(pp->Address, reflectortest_addrs[j]);
		pp->AddressSize = 4;
		pp->HoldTime = REFLECTORTEST_HOLD;
		for (UINT k = 0;k < 2;k++)
		{
			REFLECTORTEST_MEMBER *m = ReflectorTestMember(ctx, j, reflectortest_by_id[k]);

			if (m == NULL || ReflectorTestMember(ctx, i, m->VrfId) == NULL)
			{
				continue;
			}

			cp->VrfIds[cp->NumVrfs++] = m->VrfId;
			pp->VrfIds[pp->NumVrfs++] = m->VrfId;
			ReflectorTestRoute(&pp->Accept[pp->NumAccept++], m->VrfId, m->Address, 32);
			if (m->Lan != NULL)
			{
				ReflectorTestRoute(&pp->Accept[pp->NumAccept++], m->VrfId, m->Lan, REFLECTORTEST_LENGTH);
			}

			// The role of node j for node i in the VRF
			if (ReflectorTestReflector(ctx, j))
			{
				pp->ReflectorVrfIds[pp->NumReflectorVrfs++] = m->VrfId;
			}
			else if (ReflectorTestReflector(ctx, i))
			{
				pp->ClientVrfIds[pp->NumClientVrfs++] = m->VrfId;
			}
			else
			{
				pp->ReflectedVrfIds[pp->NumReflectedVrfs++] = m->VrfId;
			}
		}
		cp->Peering = pp;
	}

	return st;
}

static void ReflectorTestFreeState(CONTROL_STATE *st)
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

// A new empty data directory under the temp directory of the process, with a configuration store that runs no role on one worker
static void ReflectorTestNewDir(wchar_t *dir, UINT size, char *name)
{
	wchar_t tmp[MAX_PATH];
	wchar_t path[MAX_PATH];

	UniFormat(tmp, sizeof(tmp), L"reflectortest_%S_%u", name, Rand32());
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
static void ReflectorTestDeleteFiles(wchar_t *dir)
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

// The text of a file of the node log directory of dir, or of every file there for NULL; NULL when there is none. The caller frees it.
static char *ReflectorTestReadLog(wchar_t *dir, wchar_t *name)
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
static void ReflectorTestAdapter(NODE *n, void *param, UINT vrf_id, const UCHAR *packet, UINT size)
{
	REFLECTORTEST_NODE *t = (REFLECTORTEST_NODE *)param;

	AcquireSRWLockExclusive(&t->Lock);
	{
		t->LastVrf = vrf_id;
		t->LastSize = size;
		Copy(t->Last, packet, MIN(size, sizeof(t->Last)));
		InterlockedIncrement(&t->Arrivals);
	}
	ReleaseSRWLockExclusive(&t->Lock);
}

// The fake adapter of a host takes a state that the overlay applied, as the adapters of the VRFs of the client role take one and
// put the routes of its peers into the Windows routing table through IP Helper (NodeClient.c, NodeVrfAdapter.c): with each
// Generation, and with the forwarding tables that the BGP peering builds anew when the routes that it learned change. It keeps the
// routes of the peers, each with the node of its peer.
static void ReflectorTestHostState(NODE *n, void *param, const CONTROL_STATE *st)
{
	REFLECTORTEST_NODE *t = (REFLECTORTEST_NODE *)param;

	AcquireSRWLockExclusive(&t->Lock);
	{
		t->NumHostRoutes = 0;
		for (UINT i = 0;i < st->NumPeers;i++)
		{
			const CONTROL_PEER *cp = &st->Peers[i];
			UINT node = REFLECTORTEST_NODES;

			for (UINT j = 0;j < REFLECTORTEST_NODES;j++)
			{
				if (StrCmp(cp->Name, reflectortest_names[j]) == 0)
				{
					node = j;
				}
			}

			for (UINT j = 0;j < cp->NumRoutes && j < CONTROL_MAX_ROUTES && t->NumHostRoutes < REFLECTORTEST_HOST_ROUTES;j++)
			{
				REFLECTORTEST_HOST_ROUTE *r = &t->HostRoutes[t->NumHostRoutes++];

				r->Node = node;
				Copy(&r->Route, &cp->Routes[j], sizeof(CONTROL_ROUTE));
			}
		}
	}
	ReleaseSRWLockExclusive(&t->Lock);
}

// Whether the host of node t took at least target packets within timeout
static bool ReflectorTestArrived(REFLECTORTEST_NODE *t, LONG target, UINT timeout)
{
	UINT64 end = Tick64() + timeout;

	while (InterlockedCompareExchange(&t->Arrivals, 0, 0) < target)
	{
		if (Tick64() >= end)
		{
			return false;
		}
		SleepThread(REFLECTORTEST_POLL);
	}

	return true;
}

// A UDP packet of IPv4 from src to dst with the data seq, REFLECTORTEST_SIZE bytes, into buf: its size, 0 when an end is no IPv4
// address
static UINT ReflectorTestPacket(UCHAR *buf, char *src, char *dst, UINT seq)
{
	UCHAR s[4], d[4];

	if (ReflectorTestIp(s, src) == false || ReflectorTestIp(d, dst) == false)
	{
		return 0;
	}

	Zero(buf, REFLECTORTEST_SIZE);
	buf[0] = 0x45;
	WRITE_USHORT(buf + 2, REFLECTORTEST_SIZE);
	buf[8] = 64;
	buf[9] = IP_PROTO_UDP;
	Copy(buf + 12, s, 4);
	Copy(buf + 16, d, 4);
	USHORT sum = IpChecksum(buf, 20);
	Copy(buf + 10, &sum, 2);

	WRITE_USHORT(buf + 20, 5000);
	WRITE_USHORT(buf + 22, 53);
	WRITE_USHORT(buf + 24, REFLECTORTEST_SIZE - 20);
	WRITE_UINT(buf + 28, seq);
	for (UINT i = 32;i < REFLECTORTEST_SIZE;i++)
	{
		buf[i] = (UCHAR)(i * 13 + seq);
	}

	return REFLECTORTEST_SIZE;
}

// Suspend every thread of the process pid, as a host that loses power stops it without a word: each pass over the threads of the
// system takes the ones that the passes before did not, until one finds none, so a thread that starts meanwhile is taken too. The
// threads go into list for ReflectorTestThaw. Whether it took any.
static bool ReflectorTestFreeze(UINT pid, LIST *list)
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
				taken = (((REFLECTORTEST_THREAD *)LIST_DATA(list, i))->Id == e.th32ThreadID);
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

			REFLECTORTEST_THREAD *t = ZeroMalloc(sizeof(REFLECTORTEST_THREAD));
			t->Id = e.th32ThreadID;
			t->Handle = h;
			Add(list, t);
			found = true;
		}

		CloseHandle(snap);
	}

	return (LIST_NUM(list) != 0);
}

// Resume the threads that ReflectorTestFreeze suspended
static void ReflectorTestThaw(LIST *list)
{
	for (UINT i = 0;i < LIST_NUM(list);i++)
	{
		REFLECTORTEST_THREAD *t = LIST_DATA(list, i);

		ResumeThread(t->Handle);
		CloseHandle(t->Handle);
		Free(t);
	}

	DeleteAll(list);
}

//
// What the nodes do
//

// Apply Generation gen to each node of it, with node-s as the second reflector or in no VRF: whether each took it
static bool ReflectorTestApply(REFLECTORTEST_CTX *ctx, UINT64 gen, bool second)
{
	bool ok = true;

	ctx->Generation = gen;
	ctx->Second = second;

	for (UINT i = 0;i < REFLECTORTEST_NODES;i++)
	{
		if (ReflectorTestIn(ctx, i) == false)
		{
			continue;
		}

		CONTROL_STATE *st = ReflectorTestState(ctx, i);
		ok = NodeOverlayApply(ctx->Nodes[i].Node, st) && ok;
		ReflectorTestFreeState(st);
	}

	return ok;
}

// Whether each node of the Generation runs it with its sessions of the overlay to each of its peers up, within REFLECTORTEST_BOUND:
// the links of the VRFs are a full mesh, whatever the BGP sessions
static bool ReflectorTestWaitOverlay(REFLECTORTEST_CTX *ctx)
{
	UINT64 end = Tick64() + REFLECTORTEST_BOUND;

	while (true)
	{
		bool ok = true;

		for (UINT i = 0;i < REFLECTORTEST_NODES && ok;i++)
		{
			NODE_OVERLAY_STATUS st;
			UINT peers = 0;

			if (ReflectorTestIn(ctx, i) == false)
			{
				continue;
			}

			for (UINT j = 0;j < REFLECTORTEST_NODES;j++)
			{
				if (j != i && ReflectorTestShare(ctx, i, j))
				{
					peers++;
				}
			}

			NodeOverlayGetStatus(ctx->Nodes[i].Node, &st);
			ok = (st.Generation == ctx->Generation && st.NumLinks == peers);
		}
		if (ok)
		{
			return true;
		}
		if (Tick64() >= end)
		{
			return false;
		}
		SleepThread(REFLECTORTEST_POLL);
	}
}

// The number of the nodes that node i has a session with in the Generation that runs (ReflectorTestSession)
static UINT ReflectorTestSessions(REFLECTORTEST_CTX *ctx, UINT i)
{
	UINT num = 0;

	for (UINT j = 0;j < REFLECTORTEST_NODES;j++)
	{
		if (ReflectorTestSession(ctx, i, j))
		{
			num++;
		}
	}

	return num;
}

// Whether the sidecar of each node of the Generation that the test looks at has exactly the peers that it has a session with, each
// with its session established, within REFLECTORTEST_BOUND: a client has the reflectors alone, and a reflector every other node of
// its VRFs. The nodes whose peers differ are printed.
static bool ReflectorTestWaitSessions(REFLECTORTEST_CTX *ctx)
{
	UINT64 end = Tick64() + REFLECTORTEST_BOUND;
	bool ok = false;

	while (true)
	{
		ok = true;
		for (UINT i = 0;i < REFLECTORTEST_NODES && ok;i++)
		{
			NODE_PEERING_STATUS st;
			UINT sessions = ReflectorTestSessions(ctx, i);

			if (ReflectorTestIn(ctx, i) == false || ctx->Nodes[i].Gone)
			{
				continue;
			}

			NodePeeringGetStatus(ctx->Nodes[i].Node, &st);
			ok = (st.Running && st.NumPeers == sessions && st.NumEstablished == sessions);
		}
		if (ok || Tick64() >= end)
		{
			break;
		}
		SleepThread(REFLECTORTEST_POLL);
	}

	for (UINT i = 0;i < REFLECTORTEST_NODES && ok == false;i++)
	{
		NODE_PEERING_STATUS st;

		if (ReflectorTestIn(ctx, i) == false || ctx->Nodes[i].Gone)
		{
			continue;
		}

		NodePeeringGetStatus(ctx->Nodes[i].Node, &st);
		Print("  [INFO] %s: running %u, %u peers, %u established, want %u of each\n", reflectortest_names[i], (UINT)st.Running, st.NumPeers, st.NumEstablished,
			ReflectorTestSessions(ctx, i));
	}

	return ok;
}

// The num peers of a report as text: a line for each, with the address of its sidecar, the state of their session and the prefixes
// learned from it, each after the name of its VRF
static void ReflectorTestPeersText(CONTROL_PEERING_PEER *peers, UINT num, char *text, UINT size)
{
	StrCpy(text, size, "");
	for (UINT i = 0;i < num;i++)
	{
		CONTROL_PEERING_PEER *p = &peers[i];
		char line[MAX_SIZE * 2];

		Format(line, sizeof(line), "    %u.%u.%u.%u %s:", (UINT)p->Address[0], (UINT)p->Address[1], (UINT)p->Address[2], (UINT)p->Address[3], p->State);
		for (UINT j = 0;j < p->NumLearned && j < CONTROL_MAX_LEARNED;j++)
		{
			CONTROL_ROUTE *r = &p->Learned[j];
			char part[MAX_SIZE];

			if (r->AddressSize == 4)
			{
				Format(part, sizeof(part), " %s %u.%u.%u.%u/%u", ReflectorTestVrfName(r->VrfId), (UINT)r->Address[0], (UINT)r->Address[1], (UINT)r->Address[2],
					(UINT)r->Address[3], r->Length);
			}
			else
			{
				Format(part, sizeof(part), " %s an IPv6 prefix/%u", ReflectorTestVrfName(r->VrfId), r->Length);
			}
			StrCat(line, sizeof(line), part);
		}
		StrCat(line, sizeof(line), "\n");
		StrCat(text, size, line);
	}
}

// The report of the peering of node t as text (NodePeeringGetPeers, what the Telemetry of the node carries and ranz explain prints)
static void ReflectorTestReport(REFLECTORTEST_NODE *t, char *text, UINT size)
{
	CONTROL_PEERING_PEER *peers = ZeroMalloc(sizeof(CONTROL_PEERING_PEER) * CONTROL_MAX_PEERING_PEERS);
	UINT num = NodePeeringGetPeers(t->Node, peers, CONTROL_MAX_PEERING_PEERS);

	ReflectorTestPeersText(peers, num, text, size);
	Free(peers);
}

// The order of the peers of a report: by their address, as the node orders them
static int ReflectorTestComparePeer(const void *p1, const void *p2)
{
	const CONTROL_PEERING_PEER *a = (const CONTROL_PEERING_PEER *)p1;
	const CONTROL_PEERING_PEER *b = (const CONTROL_PEERING_PEER *)p2;

	if (a->AddressSize != b->AddressSize)
	{
		return (a->AddressSize < b->AddressSize ? -1 : 1);
	}

	return memcmp(a->Address, b->Address, a->AddressSize);
}

// The order of the prefixes learned from a peer: by VRF id, then prefix, as the node orders them
static int ReflectorTestCompareRoute(const void *p1, const void *p2)
{
	const CONTROL_ROUTE *a = (const CONTROL_ROUTE *)p1;
	const CONTROL_ROUTE *b = (const CONTROL_ROUTE *)p2;

	if (a->VrfId != b->VrfId)
	{
		return (a->VrfId < b->VrfId ? -1 : 1);
	}
	if (a->AddressSize != b->AddressSize)
	{
		return (a->AddressSize < b->AddressSize ? -1 : 1);
	}

	int c = memcmp(a->Address, b->Address, a->AddressSize);
	if (c != 0)
	{
		return c;
	}
	if (a->Length != b->Length)
	{
		return (a->Length < b->Length ? -1 : 1);
	}

	return 0;
}

// The report of node i once the routes of the Generation converged, with node-r as the one reflector: a line for each node that it
// has a session with, in the order of their address, with the session established and what node i learned from it: what that node
// announces in the VRFs that the two share, its address and its LAN subnet in each, and from a reflector of a client what each other
// client announces in the VRFs that node i shares with it, each prefix in its VRF, in the order of the VRF id, then the prefix. The
// reflector passes on nothing of a VRF to a node outside it.
static void ReflectorTestExpected(REFLECTORTEST_CTX *ctx, UINT i, char *text, UINT size)
{
	CONTROL_PEERING_PEER *peers = ZeroMalloc(sizeof(CONTROL_PEERING_PEER) * REFLECTORTEST_NODES);
	UINT num = 0;

	for (UINT j = 0;j < REFLECTORTEST_NODES;j++)
	{
		if (ReflectorTestSession(ctx, i, j) == false)
		{
			continue;
		}

		CONTROL_PEERING_PEER *p = &peers[num++];
		ReflectorTestIp(p->Address, reflectortest_addrs[j]);
		p->AddressSize = 4;
		StrCpy(p->State, sizeof(p->State), "established");

		for (UINT k = 0;k < REFLECTORTEST_MEMBERS;k++)
		{
			REFLECTORTEST_MEMBER *m = &reflectortest_members[k];
			bool reflected = (m->Node != i && m->Node != j && ReflectorTestReflector(ctx, j) && ReflectorTestReflector(ctx, i) == false &&
				ReflectorTestReflector(ctx, m->Node) == false);

			if (ReflectorTestMember(ctx, m->Node, m->VrfId) == NULL || ReflectorTestMember(ctx, i, m->VrfId) == NULL ||
				ReflectorTestMember(ctx, j, m->VrfId) == NULL || (m->Node != j && reflected == false))
			{
				continue;
			}

			ReflectorTestRoute(&p->Learned[p->NumLearned++], m->VrfId, m->Address, 32);
			if (m->Lan != NULL)
			{
				ReflectorTestRoute(&p->Learned[p->NumLearned++], m->VrfId, m->Lan, REFLECTORTEST_LENGTH);
			}
		}
		qsort(p->Learned, p->NumLearned, sizeof(CONTROL_ROUTE), ReflectorTestCompareRoute);
	}
	qsort(peers, num, sizeof(CONTROL_PEERING_PEER), ReflectorTestComparePeer);

	ReflectorTestPeersText(peers, num, text, size);
	Free(peers);
}

// Whether the report of each node of the Generation is the one of the routes that converged (ReflectorTestExpected), within
// REFLECTORTEST_BOUND. The reports are printed, each with the one of the routes that converged where it differs.
static bool ReflectorTestWaitReports(REFLECTORTEST_CTX *ctx)
{
	char *got = ZeroMalloc(REFLECTORTEST_TEXT);
	char *want = ZeroMalloc(REFLECTORTEST_TEXT);
	UINT64 end = Tick64() + REFLECTORTEST_BOUND;
	bool ok = false;

	while (true)
	{
		ok = true;
		for (UINT i = 0;i < REFLECTORTEST_NODES && ok;i++)
		{
			if (ReflectorTestIn(ctx, i) == false)
			{
				continue;
			}

			ReflectorTestReport(&ctx->Nodes[i], got, REFLECTORTEST_TEXT);
			ReflectorTestExpected(ctx, i, want, REFLECTORTEST_TEXT);
			ok = (StrCmp(got, want) == 0);
		}
		if (ok || Tick64() >= end)
		{
			break;
		}
		SleepThread(REFLECTORTEST_POLL);
	}

	for (UINT i = 0;i < REFLECTORTEST_NODES;i++)
	{
		if (ReflectorTestIn(ctx, i) == false)
		{
			continue;
		}

		ReflectorTestReport(&ctx->Nodes[i], got, REFLECTORTEST_TEXT);
		ReflectorTestExpected(ctx, i, want, REFLECTORTEST_TEXT);
		Print("  [INFO] the peers of the sidecar of %s and the prefixes learned from each:\n%s", reflectortest_names[i], IsEmptyStr(got) ? "    (none)\n" : got);
		if (StrCmp(got, want) != 0)
		{
			Print("  [INFO] ... where the routes converged:\n%s", IsEmptyStr(want) ? "    (none)\n" : want);
		}
	}

	Free(got);
	Free(want);

	return ok;
}

// The next hop of the address addr in the VRF vrf_id of the forwarding tables of node t: the index of a peer, NODE_VRF_LOCAL for its
// host, or NODE_VRF_NONE for no route and for a VRF that the tables do not have
static UINT ReflectorTestLookup(REFLECTORTEST_NODE *t, UINT vrf_id, char *addr)
{
	UCHAR a[4];
	UINT hop = NODE_VRF_NONE;

	if (ReflectorTestIp(a, addr) == false)
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

// Where the forwarding tables of node i lead the host of the LAN of the member m in the Generation that runs: in a VRF of node i, its
// own LAN to its host, and the LAN of another node to that node, also when node i learned it from a reflector, never to the reflector;
// while the only reflector does not answer, no client has a route to the LAN of another; anywhere else nowhere
static UINT ReflectorTestWant(REFLECTORTEST_CTX *ctx, UINT i, REFLECTORTEST_MEMBER *m)
{
	if (ReflectorTestMember(ctx, i, m->VrfId) == NULL || ReflectorTestMember(ctx, m->Node, m->VrfId) == NULL)
	{
		return NODE_VRF_NONE;
	}
	if (m->Node == i)
	{
		return NODE_VRF_LOCAL;
	}
	if (ctx->Cut && ReflectorTestReflector(ctx, i) == false && ReflectorTestReflector(ctx, m->Node) == false)
	{
		return NODE_VRF_NONE;
	}

	return ReflectorTestHop(i, m->Node);
}

// Whether the forwarding tables of each node of the Generation that the test looks at lead the host of each LAN where
// ReflectorTestWant says; the first that does not goes into diff
static bool ReflectorTestTablesAre(REFLECTORTEST_CTX *ctx, char *diff, UINT diff_size)
{
	StrCpy(diff, diff_size, "");

	for (UINT i = 0;i < REFLECTORTEST_NODES;i++)
	{
		if (ReflectorTestIn(ctx, i) == false || ctx->Nodes[i].Gone)
		{
			continue;
		}

		for (UINT k = 0;k < REFLECTORTEST_MEMBERS;k++)
		{
			REFLECTORTEST_MEMBER *m = &reflectortest_members[k];

			if (m->LanHost == NULL)
			{
				continue;
			}

			UINT got = ReflectorTestLookup(&ctx->Nodes[i], m->VrfId, m->LanHost);
			UINT want = ReflectorTestWant(ctx, i, m);

			if (got != want)
			{
				Format(diff, diff_size, "the forwarding table of %s in %s leads %s, of %s, to %s, not to %s", reflectortest_names[i], ReflectorTestVrfName(m->VrfId), m->LanHost,
					reflectortest_names[m->Node], ReflectorTestHopName(i, got), ReflectorTestHopName(i, want));
				return false;
			}
		}
	}

	return true;
}

// Whether the forwarding tables come to ReflectorTestTablesAre within REFLECTORTEST_BOUND; the difference that stayed is printed
static bool ReflectorTestWaitTables(REFLECTORTEST_CTX *ctx)
{
	char diff[MAX_SIZE];
	UINT64 end = Tick64() + REFLECTORTEST_BOUND;

	while (ReflectorTestTablesAre(ctx, diff, sizeof(diff)) == false)
	{
		if (Tick64() >= end)
		{
			Print("  [INFO] %s\n", diff);
			return false;
		}
		SleepThread(REFLECTORTEST_POLL);
	}

	return true;
}

// Whether the adapter of the host of each node of the Generation that the test looks at took the routes of the peers that
// ReflectorTestWant says: for each LAN of another node in a VRF of the node that its forwarding table leads to that node, a route of
// that node to it in that VRF, and no other route of a peer, so none of a reflector. The first difference goes into diff.
static bool ReflectorTestHostRoutesAre(REFLECTORTEST_CTX *ctx, char *diff, UINT diff_size)
{
	StrCpy(diff, diff_size, "");

	for (UINT i = 0;i < REFLECTORTEST_NODES;i++)
	{
		REFLECTORTEST_NODE *t = &ctx->Nodes[i];
		UINT want = 0;
		bool ok = true;

		if (ReflectorTestIn(ctx, i) == false || t->Gone)
		{
			continue;
		}

		AcquireSRWLockShared(&t->Lock);
		{
			for (UINT k = 0;k < REFLECTORTEST_MEMBERS && ok;k++)
			{
				REFLECTORTEST_MEMBER *m = &reflectortest_members[k];
				CONTROL_ROUTE lan;
				bool found = false;

				if (m->Lan == NULL || m->Node == i || ReflectorTestWant(ctx, i, m) == NODE_VRF_NONE)
				{
					continue;
				}

				want++;
				ReflectorTestRoute(&lan, m->VrfId, m->Lan, REFLECTORTEST_LENGTH);
				for (UINT j = 0;j < t->NumHostRoutes && found == false;j++)
				{
					CONTROL_ROUTE *r = &t->HostRoutes[j].Route;

					found = (t->HostRoutes[j].Node == m->Node && r->VrfId == lan.VrfId && r->AddressSize == lan.AddressSize && r->Length == lan.Length &&
						Cmp(r->Address, lan.Address, lan.AddressSize) == 0);
				}
				if (found == false)
				{
					Format(diff, diff_size, "the adapter of the host of %s has no route to %s/%u of %s in %s", reflectortest_names[i], m->Lan, (UINT)REFLECTORTEST_LENGTH,
						reflectortest_names[m->Node], ReflectorTestVrfName(m->VrfId));
					ok = false;
				}
			}
			if (ok && t->NumHostRoutes != want)
			{
				Format(diff, diff_size, "the adapter of the host of %s took %u routes of its peers, not %u", reflectortest_names[i], t->NumHostRoutes, want);
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

// Whether the routes that the adapters of the hosts took come to ReflectorTestHostRoutesAre within REFLECTORTEST_BOUND; the
// difference that stayed is printed
static bool ReflectorTestWaitHost(REFLECTORTEST_CTX *ctx)
{
	char diff[MAX_SIZE];
	UINT64 end = Tick64() + REFLECTORTEST_BOUND;

	while (ReflectorTestHostRoutesAre(ctx, diff, sizeof(diff)) == false)
	{
		if (Tick64() >= end)
		{
			Print("  [INFO] %s\n", diff);
			return false;
		}
		SleepThread(REFLECTORTEST_POLL);
	}

	return true;
}

// A packet of the host of node from in the VRF vrf_id, from its address there to dst: it arrives as it was sent at the host of node
// to, in that VRF, or with to REFLECTORTEST_NODES the overlay does not take it and no host gets it
static void ReflectorTestSend(REFLECTORTEST_CTX *ctx, UINT from, UINT vrf_id, char *dst, UINT to)
{
	REFLECTORTEST_NODE *t = &ctx->Nodes[from];
	REFLECTORTEST_MEMBER *m = ReflectorTestMember(ctx, from, vrf_id);
	UCHAR packet[REFLECTORTEST_SIZE];
	LONG arrivals[REFLECTORTEST_NODES];
	char what[MAX_SIZE];
	UINT size = 0;

	for (UINT i = 0;i < REFLECTORTEST_NODES;i++)
	{
		arrivals[i] = InterlockedCompareExchange(&ctx->Nodes[i].Arrivals, 0, 0);
	}

	if (m != NULL)
	{
		size = ReflectorTestPacket(packet, m->Address, dst, ctx->Seq++);
	}

	NodeReaderOnline(t->Node, &t->Reader);
	bool taken = (size != 0 && NodeOverlayInput(t->Node, vrf_id, packet, size));
	NodeReaderOffline(&t->Reader);

	if (to < REFLECTORTEST_NODES)
	{
		REFLECTORTEST_NODE *r = &ctx->Nodes[to];
		bool arrived = (taken && ReflectorTestArrived(r, arrivals[to] + 1, REFLECTORTEST_ARRIVE));
		bool same = false;

		AcquireSRWLockShared(&r->Lock);
		{
			same = (arrived && r->LastVrf == vrf_id && r->LastSize == size && Cmp(r->Last, packet, size) == 0);
		}
		ReleaseSRWLockShared(&r->Lock);

		Format(what, sizeof(what), "  %s in %s: %s > %s arrives at the host of %s as it was sent", reflectortest_names[from], ReflectorTestVrfName(vrf_id),
			m != NULL ? m->Address : "?", dst, reflectortest_names[to]);
		ReflectorTestCheck(ctx, taken && same, what, "the overlay took it %u, it arrived in %s as it was sent %u", (UINT)taken, ReflectorTestVrfName(vrf_id), (UINT)same);
		return;
	}

	SleepThread(REFLECTORTEST_QUIET);

	bool quiet = true;
	for (UINT i = 0;i < REFLECTORTEST_NODES;i++)
	{
		quiet = quiet && (InterlockedCompareExchange(&ctx->Nodes[i].Arrivals, 0, 0) == arrivals[i]);
	}

	Format(what, sizeof(what), "  %s in %s: %s > %s goes nowhere: the forwarding table of %s has no route there", reflectortest_names[from], ReflectorTestVrfName(vrf_id),
		m != NULL ? m->Address : "?", dst, ReflectorTestVrfName(vrf_id));
	ReflectorTestCheck(ctx, size != 0 && taken == false && quiet, what, "the overlay took it %u, no host got it %u", (UINT)taken, (UINT)quiet);
}

//
// The cases
//

// Each host of the Generation sends a packet to the LAN of each other node in each VRF that the two share: it arrives at the host of
// that node, in that VRF, though no client has a BGP session with another. The routes of a VRF stay in it: node-b reaches
// 192.168.1.0/24 of node-a in red and of node-c in blue, a packet of node-a in red to the LAN of node-b in blue goes nowhere, and so
// does one of node-c in blue to the LAN of node-b in red.
static void ReflectorTestPackets(REFLECTORTEST_CTX *ctx)
{
	for (UINT i = 0;i < REFLECTORTEST_NODES;i++)
	{
		if (ReflectorTestIn(ctx, i) == false)
		{
			continue;
		}

		for (UINT k = 0;k < REFLECTORTEST_MEMBERS;k++)
		{
			REFLECTORTEST_MEMBER *m = &reflectortest_members[k];

			if (m->LanHost != NULL && m->Node != i && ReflectorTestMember(ctx, i, m->VrfId) != NULL)
			{
				ReflectorTestSend(ctx, i, m->VrfId, m->LanHost, m->Node);
			}
		}
	}

	ReflectorTestSend(ctx, REFLECTORTEST_A, REFLECTORTEST_RED, "192.168.4.10", REFLECTORTEST_NODES);
	ReflectorTestSend(ctx, REFLECTORTEST_C, REFLECTORTEST_BLUE, "192.168.2.10", REFLECTORTEST_NODES);
}

// The state of the peering of each node of the Generation once the routes converged: its sidecar runs GoBGP, has a session
// established with each node that it has one with and no other peer, announces its address and its LAN subnet in each of its VRFs,
// and sent no error
static void ReflectorTestStatus(REFLECTORTEST_CTX *ctx)
{
	for (UINT i = 0;i < REFLECTORTEST_NODES;i++)
	{
		NODE_PEERING_STATUS st;
		UINT sessions = ReflectorTestSessions(ctx, i);
		UINT announced = 0;
		char what[MAX_SIZE];

		if (ReflectorTestIn(ctx, i) == false)
		{
			continue;
		}

		for (UINT k = 0;k < REFLECTORTEST_MEMBERS;k++)
		{
			REFLECTORTEST_MEMBER *m = &reflectortest_members[k];

			if (m->Node == i)
			{
				announced += (m->Lan != NULL ? 2 : 1);
			}
		}

		NodePeeringGetStatus(ctx->Nodes[i].Node, &st);
		Format(what, sizeof(what), "  %s, %s: its sidecar runs GoBGP, has %u peers, each with its session established, and announces %u prefixes, without an error",
			reflectortest_names[i], ReflectorTestReflector(ctx, i) ? "a reflector" : "a client", sessions, announced);
		ReflectorTestCheck(ctx, st.Configured && st.Running && st.ProcessId != 0 && SearchStrEx(st.Version, "GoBGP", 0, false) != INFINITE && st.NumPeers == sessions &&
			st.NumEstablished == sessions && st.NumNamed == sessions && st.NumAnnounced == announced && st.NumErrors == 0, what,
			"configured %u, running %u, process %u, version \"%s\", %u peers, %u established, %u named, %u announced, %u errors", (UINT)st.Configured, (UINT)st.Running,
			st.ProcessId, st.Version, st.NumPeers, st.NumEstablished, st.NumNamed, st.NumAnnounced, st.NumErrors);
	}
}

// Whether the address addr of 4 bytes, as the TCP table of the host holds it, is the address of a client: node-a, node-b or node-c
static bool ReflectorTestClientAddr(DWORD addr)
{
	for (UINT i = REFLECTORTEST_A;i <= REFLECTORTEST_C;i++)
	{
		UCHAR a[4];

		if (ReflectorTestIp(a, reflectortest_addrs[i]) && Cmp(a, &addr, 4) == 0)
		{
			return true;
		}
	}

	return false;
}

// The TCP connections of the host between the addresses of two clients with TCP 179 at one end, which a BGP session of two clients
// would be, but for the ones in TIME_WAIT, which a session that a sidecar refused leaves: their number, with the first into text;
// INFINITE when the table cannot be read
static UINT ReflectorTestClientConnections(char *text, UINT size)
{
	DWORD len = 0;
	UINT num = 0;

	StrCpy(text, size, "none");
	GetExtendedTcpTable(NULL, &len, FALSE, (ULONG)AF_INET, TCP_TABLE_OWNER_PID_CONNECTIONS, 0);
	if (len == 0)
	{
		return INFINITE;
	}

	// Room for the connections that come between the two calls
	len += (DWORD)(sizeof(MIB_TCPROW_OWNER_PID) * 64);
	void *table = ZeroMalloc(len);
	if (GetExtendedTcpTable(table, &len, FALSE, (ULONG)AF_INET, TCP_TABLE_OWNER_PID_CONNECTIONS, 0) != NO_ERROR)
	{
		Free(table);
		return INFINITE;
	}

	MIB_TCPTABLE_OWNER_PID *t = (MIB_TCPTABLE_OWNER_PID *)table;
	for (DWORD k = 0;k < t->dwNumEntries;k++)
	{
		MIB_TCPROW_OWNER_PID *row = &t->table[k];
		USHORT local_port = ntohs((USHORT)row->dwLocalPort);
		USHORT remote_port = ntohs((USHORT)row->dwRemotePort);
		UCHAR *l = (UCHAR *)&row->dwLocalAddr;
		UCHAR *r = (UCHAR *)&row->dwRemoteAddr;

		if (row->dwState == (DWORD)MIB_TCP_STATE_TIME_WAIT || (local_port != REFLECTORTEST_PORT && remote_port != REFLECTORTEST_PORT) ||
			ReflectorTestClientAddr(row->dwLocalAddr) == false || ReflectorTestClientAddr(row->dwRemoteAddr) == false)
		{
			continue;
		}

		if (num++ == 0)
		{
			Format(text, size, "%u.%u.%u.%u:%u to %u.%u.%u.%u:%u in the state %u", (UINT)l[0], (UINT)l[1], (UINT)l[2], (UINT)l[3], (UINT)local_port, (UINT)r[0], (UINT)r[1],
				(UINT)r[2], (UINT)r[3], (UINT)remote_port, (UINT)row->dwState);
		}
	}

	Free(table);

	return num;
}

// No client peers with another: the TCP table of the host holds no connection between two clients on TCP 179
static void ReflectorTestNoClientSessions(REFLECTORTEST_CTX *ctx)
{
	char first[MAX_SIZE];
	UINT num = ReflectorTestClientConnections(first, sizeof(first));

	ReflectorTestCheck(ctx, num == 0, "The TCP table of the host holds no connection between two clients on TCP 179: no client peers with another",
		"%s", num == INFINITE ? "the TCP table cannot be read" : first);
}

// The routes of the Generation that the nodes took: the sessions of the overlay, the BGP sessions, the report of each node while
// node-r is the one reflector, the forwarding tables, the adapters of the hosts, the state of the peering of each node and the TCP
// table of the host. Whether the forwarding tables came to what the Generation gives.
static bool ReflectorTestConverge(REFLECTORTEST_CTX *ctx, bool applied)
{
	char what[MAX_SIZE];

	bool overlay = (applied && ReflectorTestWaitOverlay(ctx));
	Format(what, sizeof(what), "Generation %I64u goes in at each node of it, and the sessions of the overlay between them are up: the links stay a full mesh", ctx->Generation);
	ReflectorTestCheck(ctx, applied && overlay, what, "applied %u, the Generation and the sessions at each node %u", (UINT)applied, (UINT)overlay);

	bool sessions = (overlay && ReflectorTestWaitSessions(ctx));
	ReflectorTestCheck(ctx, sessions, "Each client has a session established with each reflector and with no other node, and each reflector one with each other node of its VRFs",
		"%s", "see the lines above");

	bool converged = sessions;
	if (ctx->Second == false)
	{
		converged = (sessions && ReflectorTestWaitReports(ctx));
		ReflectorTestCheck(ctx, converged, "Each client learns from node-r what node-r and the other clients announce in the VRFs that the two share, each prefix in its VRF and nothing of another VRF, and node-r learns from each client what it announces",
			"%s", "see the reports above");
	}

	bool tables = (converged && ReflectorTestWaitTables(ctx));
	ReflectorTestCheck(ctx, tables, "The forwarding table of each VRF of each node leads the LAN of each other node to that node, also the LAN that a client learned from a reflector, never to the reflector, and the LAN of the node to its host",
		"%s", "see the line above");

	bool host = (tables && ReflectorTestWaitHost(ctx));
	ReflectorTestCheck(ctx, host, "The adapter of the host of each node takes the LAN of each other node as a route of that node in their VRF, and no other route of a peer", "%s",
		"see the line above");

	ReflectorTestStatus(ctx);
	ReflectorTestNoClientSessions(ctx);

	return tables;
}

// A session to the sidecar of node to from the address from, which the Controller named as no peer that node to has a session with:
// the sidecar refuses it and node to counts it, and its sessions stay
static void ReflectorTestRefused(REFLECTORTEST_CTX *ctx, UINT to, char *from, char *who)
{
	REFLECTORTEST_NODE *t = &ctx->Nodes[to];
	NODE_PEERING_STATUS before, after;
	struct sockaddr_in local, remote;
	char what[MAX_SIZE * 2];
	UINT err = 0;

	NodePeeringGetStatus(t->Node, &before);

	Zero(&local, sizeof(local));
	local.sin_family = AF_INET;
	InetPtonA(AF_INET, from, &local.sin_addr);
	Zero(&remote, sizeof(remote));
	remote.sin_family = AF_INET;
	remote.sin_port = htons(REFLECTORTEST_PORT);
	InetPtonA(AF_INET, reflectortest_addrs[to], &remote.sin_addr);

	SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	bool connected = (s != INVALID_SOCKET && bind(s, (struct sockaddr *)&local, sizeof(local)) == 0 && connect(s, (struct sockaddr *)&remote, sizeof(remote)) == 0);
	if (connected == false)
	{
		err = (UINT)WSAGetLastError();
	}

	UINT64 end = Tick64() + REFLECTORTEST_BOUND;
	while (true)
	{
		NodePeeringGetStatus(t->Node, &after);
		if (connected == false || after.Refused > before.Refused || Tick64() >= end)
		{
			break;
		}
		SleepThread(REFLECTORTEST_POLL);
	}

	if (s != INVALID_SOCKET)
	{
		closesocket(s);
	}

	Format(what, sizeof(what), "The sidecar of %s refuses a session from %s, and %s counts it, while its %u sessions stay established", reflectortest_names[to], who,
		reflectortest_names[to], before.NumEstablished);
	ReflectorTestCheck(ctx, connected && after.Refused == before.Refused + 1 && after.NumEstablished == before.NumEstablished, what,
		"connected %u (error %u), %I64u sessions refused before and %I64u after, %u established after", (UINT)connected, err, before.Refused, after.Refused,
		after.NumEstablished);
}

// Freeze the sidecar of node-r, as a host that loses power stops: its threads are suspended, so it holds its sessions and sends
// nothing. The threads go into threads, and node-r is gone for the test. Whether it is frozen; start is when.
static bool ReflectorTestStopReflector(REFLECTORTEST_CTX *ctx, LIST *threads, UINT64 *start)
{
	REFLECTORTEST_NODE *r = &ctx->Nodes[REFLECTORTEST_R];
	NODE_PEERING_STATUS st;

	NodePeeringGetStatus(r->Node, &st);
	*start = Tick64();
	bool frozen = (st.ProcessId != 0 && ReflectorTestFreeze(st.ProcessId, threads));
	ReflectorTestCheck(ctx, frozen, "  The threads of the sidecar of node-r are suspended: it holds its sessions and sends nothing", "process %u, %u threads suspended",
		st.ProcessId, LIST_NUM(threads));
	r->Gone = true;

	return frozen;
}

// The sidecar of node-r runs again: its threads are resumed, or node-r ended it because it did not answer and runs another. Each
// node of the Generation has its sessions again, and the routes that they carry converge.
static void ReflectorTestResumeReflector(REFLECTORTEST_CTX *ctx, LIST *threads)
{
	ReflectorTestThaw(threads);
	ctx->Nodes[REFLECTORTEST_R].Gone = false;
	ctx->Cut = false;

	bool back = (ReflectorTestWaitSessions(ctx) && (ctx->Second || ReflectorTestWaitReports(ctx)) && ReflectorTestWaitTables(ctx) && ReflectorTestWaitHost(ctx));
	ReflectorTestCheck(ctx, back, "Once node-r runs a sidecar that answers, each node has its sessions again, and the routes of each client reach the other clients again",
		"%s", "see the lines above");
}

// The only reflector stops answering: node-r of Generation 1. Each client withdraws the routes of the other clients within the hold
// time, after which its session with node-r ends, and keeps its own; a packet of node-a to the LAN of node-b goes nowhere. Then node-r
// runs a sidecar that answers again.
static void ReflectorTestCut(REFLECTORTEST_CTX *ctx)
{
	LIST *threads = NewListFast(NULL);
	char diff[MAX_SIZE];
	char what[MAX_SIZE];
	UINT64 start = 0;
	UINT64 took = 0;
	bool withdrawn = false;

	Print("[node-r, the only reflector, stops answering]\n");

	bool frozen = ReflectorTestStopReflector(ctx, threads, &start);
	ctx->Cut = true;
	StrCpy(diff, sizeof(diff), "");
	while (frozen)
	{
		withdrawn = ReflectorTestTablesAre(ctx, diff, sizeof(diff));
		took = Tick64() - start;
		if (withdrawn || took >= REFLECTORTEST_BOUND)
		{
			break;
		}
		SleepThread(REFLECTORTEST_POLL);
	}

	Print("  [INFO] the clients withdrew the routes of each other %I64u ms after node-r stopped answering; the hold time is %u s\n", took, (UINT)REFLECTORTEST_HOLD);
	if (withdrawn == false)
	{
		Print("  [INFO] %s\n", diff);
	}
	Format(what, sizeof(what), "Without a second reflector, each client withdraws the routes of the other clients within the hold time of %u s, with %u ms for the sidecar and the node to take it, and keeps its own",
		(UINT)REFLECTORTEST_HOLD, (UINT)REFLECTORTEST_GRACE);
	ReflectorTestCheck(ctx, withdrawn && took <= (UINT64)REFLECTORTEST_HOLD * 1000 + REFLECTORTEST_GRACE, what, "withdrawn %u, after %I64u ms", (UINT)withdrawn, took);
	if (withdrawn)
	{
		ReflectorTestCheck(ctx, ReflectorTestWaitHost(ctx), "The adapters of the hosts of the clients take no route of another client any more", "%s", "see the line above");
		ReflectorTestSend(ctx, REFLECTORTEST_A, REFLECTORTEST_RED, "192.168.2.10", REFLECTORTEST_NODES);
	}

	ReflectorTestResumeReflector(ctx, threads);
	ReleaseList(threads);
}

// Whether the session of each client with node-r is other than established, as its report names it
static bool ReflectorTestClientsLostR(REFLECTORTEST_CTX *ctx)
{
	CONTROL_PEERING_PEER *peers = ZeroMalloc(sizeof(CONTROL_PEERING_PEER) * CONTROL_MAX_PEERING_PEERS);
	UCHAR r[4];
	bool lost = true;

	ReflectorTestIp(r, reflectortest_addrs[REFLECTORTEST_R]);
	for (UINT i = REFLECTORTEST_A;i <= REFLECTORTEST_C && lost;i++)
	{
		UINT num = NodePeeringGetPeers(ctx->Nodes[i].Node, peers, CONTROL_MAX_PEERING_PEERS);

		for (UINT j = 0;j < num;j++)
		{
			if (peers[j].AddressSize == 4 && Cmp(peers[j].Address, r, 4) == 0 && StrCmp(peers[j].State, "established") == 0)
			{
				lost = false;
			}
		}
	}

	Free(peers);

	return lost;
}

// Node-r stops answering while node-s is the second reflector (Generation 2): each client keeps the routes of the other clients
// through node-s, and its forwarding tables lead them to those clients at every look, from when node-r stops until its session with
// node-r ended, within the hold time, and a grace after; a packet of each client to the LAN of each other client still arrives. Then
// node-r runs a sidecar that answers again.
static void ReflectorTestRedundant(REFLECTORTEST_CTX *ctx)
{
	LIST *threads = NewListFast(NULL);
	char diff[MAX_SIZE];
	char lost[MAX_SIZE];
	char what[MAX_SIZE];
	UINT64 start = 0;
	UINT64 lost_at = 0;
	UINT64 ended_at = 0;
	bool kept = true;
	bool ended = false;

	Print("[node-r stops answering, and node-s is the second reflector]\n");

	bool frozen = ReflectorTestStopReflector(ctx, threads, &start);
	StrCpy(lost, sizeof(lost), "");
	while (frozen)
	{
		UINT64 now = Tick64() - start;

		if (kept && ReflectorTestTablesAre(ctx, diff, sizeof(diff)) == false)
		{
			kept = false;
			lost_at = now;
			StrCpy(lost, sizeof(lost), diff);
		}
		if (ended == false && ReflectorTestClientsLostR(ctx))
		{
			ended = true;
			ended_at = now;
		}
		if ((ended && now >= ended_at + REFLECTORTEST_GRACE) || now >= REFLECTORTEST_BOUND)
		{
			break;
		}
		SleepThread(REFLECTORTEST_POLL);
	}

	Print("  [INFO] the session of each client with node-r ended %I64u ms after node-r stopped answering; the hold time is %u s\n", ended_at, (UINT)REFLECTORTEST_HOLD);
	Format(what, sizeof(what), "  The session of each client with node-r ends within the hold time of %u s, with %u ms for the sidecar and the node to take it",
		(UINT)REFLECTORTEST_HOLD, (UINT)REFLECTORTEST_GRACE);
	ReflectorTestCheck(ctx, ended && ended_at <= (UINT64)REFLECTORTEST_HOLD * 1000 + REFLECTORTEST_GRACE, what, "ended %u, after %I64u ms", (UINT)ended, ended_at);
	ReflectorTestCheck(ctx, frozen && kept, "With node-s as the second reflector, each client keeps the routes of the other clients when node-r stops, past the hold time: its forwarding tables lead them to those clients at every look",
		"lost %I64u ms after node-r stopped: %s", lost_at, lost);

	ReflectorTestSend(ctx, REFLECTORTEST_A, REFLECTORTEST_RED, "192.168.2.10", REFLECTORTEST_B);
	ReflectorTestSend(ctx, REFLECTORTEST_B, REFLECTORTEST_BLUE, "192.168.1.10", REFLECTORTEST_C);
	ReflectorTestSend(ctx, REFLECTORTEST_C, REFLECTORTEST_RED, "192.168.1.10", REFLECTORTEST_A);

	ReflectorTestResumeReflector(ctx, threads);
	ReleaseList(threads);
}

// The nodes and their overlays without a control stream, the test thread a reader of the tables of each
static bool ReflectorTestOpen(REFLECTORTEST_CTX *ctx, TRANSPORT *loopback)
{
	UCHAR scalar[PEER_KEY_SIZE];
	char what[MAX_SIZE];
	bool ok = (loopback != NULL);

	Print("[the nodes and their overlays]\n");

	for (UINT i = 0;i < REFLECTORTEST_NODES && ok;i++)
	{
		REFLECTORTEST_NODE *t = &ctx->Nodes[i];
		NODE_OVERLAY_CONFIG c;

		InitializeSRWLock(&t->Lock);
		for (UINT j = 0;j < PEER_KEY_SIZE;j++)
		{
			scalar[j] = (UCHAR)(0x51 + PEER_KEY_SIZE * i + j);
		}
		ok = PeerKeyFromScalar(&t->Key, scalar);

		ReflectorTestNewDir(t->Dir, sizeof(t->Dir), reflectortest_names[i]);
		t->Node = NewNode(t->Dir);
		if (i == 0)
		{
			ok = ReflectorTestCheck(ctx, IsFileExistsW(t->Node->BgpSidecar), "ranz.exe, which holds the sidecar ranz bgp, is next to vpntest.exe", "%S is missing",
				t->Node->BgpSidecar) && ok;
		}
		NodeStart(t->Node);
		NodeReaderRegister(t->Node, &t->Reader);
		NodeReaderOffline(&t->Reader);

		Zero(&c, sizeof(c));
		c.Data = loopback;
		c.Key = &t->Key;
		c.Adapter = ReflectorTestAdapter;
		c.AdapterParam = t;
		c.State = ReflectorTestHostState;
		Format(what, sizeof(what), "  %s: its overlay runs without a control stream, and its sidecar will listen on TCP %u of %s", reflectortest_names[i],
			(UINT)REFLECTORTEST_PORT, reflectortest_addrs[i]);
		ok = ReflectorTestCheck(ctx, ok && NodeOverlayStart(t->Node, &c), what, "%s", "PeerKeyFromScalar or NodeOverlayStart failed") && ok;
	}
	Zero(scalar, sizeof(scalar));

	return ok;
}

// The nodes stop, with every thread joined, and each is freed. The node log of each client says that its sidecar named the state of
// no session with a peer that the Controller did not name a session with: it had none with another client. When a check failed, the
// log of each node and of its sidecar is printed before the data directories go.
static void ReflectorTestClose(REFLECTORTEST_CTX *ctx, bool ran)
{
	for (UINT i = 0;i < REFLECTORTEST_NODES;i++)
	{
		REFLECTORTEST_NODE *t = &ctx->Nodes[i];

		if (t->Node != NULL)
		{
			NodeReaderUnregister(t->Node, &t->Reader);
			NodeStop(t->Node);
			FreeNode(t->Node);
		}
	}

	for (UINT i = REFLECTORTEST_A;i <= REFLECTORTEST_C && ran;i++)
	{
		char *log = ReflectorTestReadLog(ctx->Nodes[i].Dir, NULL);
		char what[MAX_SIZE];

		Format(what, sizeof(what), "The node log of %s names the state of no session of its sidecar with a peer that it has no session with", reflectortest_names[i]);
		ReflectorTestCheck(ctx, log != NULL && SearchStrEx(log, "(not a peer that the Controller named)", 0, true) == INFINITE, what, "%s",
			log == NULL ? "there is no log" : "it names one");
		Free(log);
	}

	for (UINT i = 0;i < REFLECTORTEST_NODES;i++)
	{
		REFLECTORTEST_NODE *t = &ctx->Nodes[i];
		wchar_t log_dir[MAX_PATH];

		if (t->Node != NULL)
		{
			if (ctx->NumFailed != 0)
			{
				char *log = ReflectorTestReadLog(t->Dir, NULL);

				Print("  --- the node log and the sidecar log of %s ---\n%s  ---\n", reflectortest_names[i], log == NULL ? "(none)\n" : log);
				Free(log);
			}

			ConbinePathW(log_dir, sizeof(log_dir), t->Dir, NODE_LOG_DIR_NAME);
			ReflectorTestDeleteFiles(log_dir);
			ReflectorTestDeleteFiles(t->Dir);
			t->Node = NULL;
		}
		PeerKeyClose(&t->Key);
	}
}

// One reflector and three clients, the sessions from addresses that the Controller did not name, the only reflector that stops
// answering, and two reflectors, one of which stops answering
static void ReflectorTestRun(REFLECTORTEST_CTX *ctx)
{
	Print("[Generation 1: node-r reflects red and blue to its clients node-a, node-b and node-c]\n");
	if (ReflectorTestConverge(ctx, ReflectorTestApply(ctx, 1, false)) == false)
	{
		return;
	}
	ReflectorTestPackets(ctx);

	Print("[sessions from addresses that the Controller did not name]\n");
	ReflectorTestRefused(ctx, REFLECTORTEST_R, REFLECTORTEST_STRANGER, "127.0.0.9, an address that the Controller did not name");
	ReflectorTestRefused(ctx, REFLECTORTEST_A, reflectortest_addrs[REFLECTORTEST_B], "the address of node-b, which the Controller names to node-a as another client of the reflectors");

	ReflectorTestCut(ctx);

	Print("[Generation 2: node-s is the second reflector of red and blue]\n");
	if (ReflectorTestConverge(ctx, ReflectorTestApply(ctx, 2, true)) == false)
	{
		return;
	}
	ReflectorTestPackets(ctx);

	ReflectorTestRedundant(ctx);
}

// reflector: the route reflectors of the BGP peering of the standard mode, with a reflector and three clients
RANZ_TEST("reflector", reflector_test, "Route reflectors of the BGP peering of the standard mode: a reflector and three clients, each node with its sidecar ranz bgp (ranz.exe next to vpntest) on TCP 179 of a loopback address of its own, in two VRFs; each client learns the routes of the others through the reflector and leads them to the client that announced them, no client peers with another, no route crosses into another VRF, a session from an address that the Controller did not name refused, the routes of the clients withdrawn within the hold time when the only reflector stops, and kept through a second reflector when one of two stops.");
void reflector_test(UINT num, char **arg)
{
	REFLECTORTEST_CTX *ctx = ZeroMalloc(sizeof(REFLECTORTEST_CTX));
	HANDLE done = CreateEventW(NULL, TRUE, FALSE, NULL);
	HANDLE watchdog = (done != NULL ? CreateThread(NULL, 0, ReflectorTestWatchdog, done, 0, NULL) : NULL);
	TRANSPORT *loopback = TransportLoopbackNew("loopback", 0, false);

	Print("Route reflector test: a reflector and three clients peer by BGP in the standard mode, each node with its own sidecar ranz bgp\n");

	ctx->Seq = 1;
	bool ran = ReflectorTestOpen(ctx, loopback);
	if (ran)
	{
		ReflectorTestRun(ctx);
	}

	ReflectorTestClose(ctx, ran);
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
		Print("REFLECTOR TEST OK\n");
	}
	else
	{
		Print("REFLECTOR TEST FAILED (%u of %u checks failed)\n", ctx->NumFailed, ctx->NumChecks);
	}

	Free(ctx);
}
