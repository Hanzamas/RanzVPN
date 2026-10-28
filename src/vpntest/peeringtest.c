// peeringtest.c
// Named BGP peering test of vpntest ("peering" command, SDN-77 #357)
//
// The BGP peering of the standard mode (Cedar/NodePeering.c) on the harness with three Nodes of the ticket: three
// in-process nodes, each with its own sidecar ranz bgp (ranz.exe next to vpntest, GoBGP), which listens on TCP 179 of the
// address of its node on the network that the operator trusts, 127.0.0.2 for node-a, 127.0.0.3 for node-b and 127.0.0.4
// for node-c, and connects from there. The test applies the desired states of the nodes itself (NodeOverlayApply), as the
// Controller compiles them (controller/internal/desired/peering.go): the settings of the sidecar of each node with the
// LAN subnets that it announces, and for each peer the address of its sidecar, the hold time of their session, its VRFs
// and what the peer may announce there, its addresses and its LAN subnets. Node-a is a member of VRF red (101), node-b and
// node-c of red and of blue (102), and 192.168.1.0/24 is the LAN of node-a in red and the LAN of node-b in blue. Fake
// adapters stand in for the hosts, and the in-process loopback transport carries the packets between the nodes: on one
// host the tunnel endpoints of three nodes would all send from 127.0.0.1, and a link of kind vxlan names its peer by the
// source address alone (NodeLink.c), so the links of the harness are of kind noise. The peering fills the forwarding
// tables whatever the kind of the links, which only carry what the tables route.
// - The full mesh: each node starts its sidecar, whose pipe has the strict DACL, and has a session established with each
//   other node; each learns exactly what the others announce in the VRFs that they share, each prefix in its VRF, and the
//   forwarding table of the VRF leads the LAN of each peer to that peer, so a packet of each host to the LAN of each other
//   node arrives at the host of that node, in that VRF. The two LANs 192.168.1.0/24 stay apart: node-c reaches the one of
//   node-a in red and the one of node-b in blue, and node-a, which is in no VRF blue, learns nothing of blue.
// - A session from 127.0.0.9, an address that the Controller did not name, is refused, and node-a counts it.
// - Red stops peering (Generation 2): node-a, in no VRF that peers any more, stops its sidecar and its learned routes go;
//   node-b and node-c keep their session in blue, and no packet goes to a LAN of red any more. Red peers again (Generation
//   3): node-a starts a new sidecar and the mesh converges again.
// - The sidecar of node-c stops answering, as a host that loses power: its threads are suspended. Node-a and node-b remove
//   its routes within the hold time of the sessions, and keep each other's; once it answers again, the mesh converges.
// - Node-c stops: its sidecar ends the sessions, and node-a and node-b remove its routes within the hold time.
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
#include "Mayaqua/Str.h"
#include "Mayaqua/TcpIp.h"
#include "Mayaqua/Tick64.h"

#include "Core/Control.h"
#include "Core/Transport.h"

#include <TlHelp32.h>
#include <WS2tcpip.h>

#include <stdio.h>

#define	PEERINGTEST_BUDGET		300000		// The whole test ends within this time, or the watchdog ends the process (ms)
#define	PEERINGTEST_BOUND		60000		// A bounded wait on observable state (ms)
#define	PEERINGTEST_ARRIVE		10000		// A packet that the overlay took arrives within this time (ms)
#define	PEERINGTEST_QUIET		300			// A host that gets nothing gets nothing within this time (ms)
#define	PEERINGTEST_POLL		50			// Poll interval of observable state (ms)
#define	PEERINGTEST_SIZE		100			// The size of a test packet
#define	PEERINGTEST_TEXT		4096		// The size of the text of the report of a node
#define	PEERINGTEST_ASN			4200000000U	// The AS of the overlay, one for every node (intent.PeeringASN)
#define	PEERINGTEST_HOLD		9			// The BGP hold time of the sessions in s, as the VRFs of the Intent name it
#define	PEERINGTEST_GRACE		1000		// What the sidecar and the node take past the hold time to remove the routes (ms)
#define	PEERINGTEST_PORT		179			// The BGP port of the sidecars
#define	PEERINGTEST_STRANGER	"127.0.0.9"	// An address that the Controller did not name
#define	PEERINGTEST_RED			101			// The id of VRF red ...
#define	PEERINGTEST_BLUE		102			// ... and of VRF blue
#define	PEERINGTEST_LENGTH		24			// The prefix length of the Networks and of the LAN subnets

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

// One node and the fake adapter of its host, which keeps the last packet that the host took
typedef struct PEERINGTEST_NODE
{
	wchar_t Dir[MAX_PATH];				// Its data directory
	PEER_KEY Key;						// Its static key
	NODE *Node;
	NODE_READER Reader;					// The test thread as a reader of the node's tables, online while it looks up or sends
	bool Gone;							// Its sidecar does not answer, or it stopped: the other nodes have no route of it
	bool Stopped;						// It stopped
	SRWLOCK Lock;						// LastVrf, Last and LastSize
	volatile LONG Arrivals;				// Packets that the host took
	UINT LastVrf;						// The VRF of the last one ...
	UCHAR Last[PEERINGTEST_SIZE * 2];	// ... and the packet, as much as fits
	UINT LastSize;
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
	PEERINGTEST_NODE Nodes[PEERINGTEST_NODES];
	UINT64 Generation;					// The Generation that the nodes run ...
	bool RedPeers;						// ... and whether red peers by BGP in it
	bool Ran;							// The nodes started their sidecars
	UINT Seq;							// The data of the next test packet
} PEERINGTEST_CTX;

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

// The desired state of node i in the Generation that runs, as the Controller compiles it: its VRFs in name order, each with a
// link of kind noise in the harness and the peering of the Generation, and its address in each, in the order of their
// Network, which has the name of the VRF; while a VRF of it peers by BGP, the settings of its sidecar and the LAN subnets that
// it announces there; and the other two nodes as its peers in name order, each with its addresses in the VRFs that the two
// share, and while one of those peers by BGP, the address of its sidecar, the hold time, the VRFs of their session and what
// it may announce there, its address as a host route and its LAN subnet in each. PeeringTestFreeState frees it.
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

			if (m != NULL && PeeringTestPeers(ctx, m->VrfId))
			{
				PeeringTestRoute(&own->Announce[own->NumAnnounce++], m->VrfId, m->Lan, PEERINGTEST_LENGTH);
			}
		}
		st->Peering = own;
	}

	st->Peers = ZeroMalloc(sizeof(CONTROL_PEER) * (PEERINGTEST_NODES - 1));
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

// The report of the peering of node t as text (NodePeeringGetPeers, what the Telemetry of the node carries and ranz explain
// prints): a line for each peer of its sidecar in the order of its address, with the state of their session and the
// prefixes learned from it, each after the name of its VRF
static void PeeringTestReport(PEERINGTEST_NODE *t, char *text, UINT size)
{
	CONTROL_PEERING_PEER *peers = ZeroMalloc(sizeof(CONTROL_PEERING_PEER) * CONTROL_MAX_PEERING_PEERS);
	UINT num = NodePeeringGetPeers(t->Node, peers, CONTROL_MAX_PEERING_PEERS);

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
// of node i that peers by BGP, its own LAN to its host and the LAN of another node to that node, while that node is there;
// anywhere else nowhere
static UINT PeeringTestWant(PEERINGTEST_CTX *ctx, UINT i, PEERINGTEST_MEMBER *m)
{
	if (PeeringTestMember(i, m->VrfId) == NULL || PeeringTestPeers(ctx, m->VrfId) == false || ctx->Nodes[m->Node].Gone)
	{
		return NODE_VRF_NONE;
	}

	return (m->Node == i ? NODE_VRF_LOCAL : PeeringTestHop(i, m->Node));
}

// Whether the forwarding tables of each node that is there lead the host of each LAN subnet where PeeringTestWant says; the
// first that does not goes into diff
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

// Each host sends a packet to the LAN of each other node in each VRF that the two share: where the VRF peers by BGP it arrives
// at the host of that node, in that VRF, and else it goes nowhere. The routes of a VRF stay in it: a packet of node-a in red
// to the LAN of node-c in blue goes nowhere, as does one of node-c in blue to the LAN of node-b in red.
static void PeeringTestPackets(PEERINGTEST_CTX *ctx)
{
	for (UINT i = 0;i < PEERINGTEST_NODES;i++)
	{
		for (UINT k = 0;k < PEERINGTEST_MEMBERS;k++)
		{
			PEERINGTEST_MEMBER *m = &peeringtest_members[k];

			if (m->Node != i && PeeringTestMember(i, m->VrfId) != NULL)
			{
				PeeringTestSend(ctx, i, m->VrfId, m->LanHost, PeeringTestPeers(ctx, m->VrfId) ? m->Node : PEERINGTEST_NODES);
			}
		}
	}

	PeeringTestSend(ctx, PEERINGTEST_A, PEERINGTEST_RED, "192.168.4.10", PEERINGTEST_NODES);
	PeeringTestSend(ctx, PEERINGTEST_C, PEERINGTEST_BLUE, "192.168.2.10", PEERINGTEST_NODES);
}

// The state of the peering of each node once the mesh converged: a node in a VRF that peers by BGP runs its sidecar, which
// named GoBGP in its ready, with the strict DACL on its pipe (ADR-0039 decision 3), has a session established with each other
// node with which it shares such a VRF, announces its address and its LAN subnet in each, and its sidecar sent no error; a
// node in none runs no sidecar and has no peer and no learned route. starts: the sidecars that each node started so far.
static void PeeringTestStatus(PEERINGTEST_CTX *ctx, const UINT *starts)
{
	for (UINT i = 0;i < PEERINGTEST_NODES;i++)
	{
		NODE_PEERING_STATUS st;
		UINT peers = 0;
		UINT vrfs = 0;
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

		NodePeeringGetStatus(ctx->Nodes[i].Node, &st);

		if (vrfs == 0)
		{
			Format(what, sizeof(what), "  %s, in no VRF that peers by BGP: it runs no sidecar and has no peer and no learned route", peeringtest_names[i]);
			PeeringTestCheck(ctx, st.Configured == false && st.Running == false && st.ProcessId == 0 && st.NumPeers == 0 && st.NumLearned == 0 && st.NumStarts == starts[i], what,
				"configured %u, running %u, process %u, %u peers, %u learned routes, %u sidecars started", (UINT)st.Configured, (UINT)st.Running, st.ProcessId, st.NumPeers,
				st.NumLearned, st.NumStarts);
			continue;
		}

		bool acl = (StrCmp(st.PipeAcl, "D:P(A;;FA;;;OW)") == 0 || StrCmp(st.PipeAcl, "D:P(A;;GA;;;OW)") == 0);
		Format(what, sizeof(what), "  %s: its sidecar runs GoBGP, with the strict DACL on its pipe, has %u sessions established and announces %u prefixes, without an error",
			peeringtest_names[i], peers, 2 * vrfs);
		PeeringTestCheck(ctx, st.Configured && st.Running && st.ProcessId != 0 && SearchStrEx(st.Version, "GoBGP", 0, false) != INFINITE && acl && st.NumPeers == peers &&
			st.NumEstablished == peers && st.NumAnnounced == 2 * vrfs && st.NumErrors == 0 && st.NumStarts == starts[i], what,
			"configured %u, running %u, process %u, version \"%s\", DACL \"%s\", %u peers, %u established, %u announced, %u errors, %u sidecars started", (UINT)st.Configured,
			(UINT)st.Running, st.ProcessId, st.Version, st.PipeAcl, st.NumPeers, st.NumEstablished, st.NumAnnounced, st.NumErrors, st.NumStarts);
	}
}

// Generation gen of the three nodes, with red peering by BGP or not, and the mesh that it gives: the sessions of the overlay,
// the report of each node, its forwarding tables, the state of its peering (starts: the sidecars that each node started so
// far) and the packets between the hosts. Whether the mesh converged.
static bool PeeringTestMesh(PEERINGTEST_CTX *ctx, UINT64 gen, bool red_peers, const UINT *starts)
{
	char what[MAX_SIZE];

	Print("[Generation %I64u: red %s by BGP, blue peers by BGP]\n", gen, red_peers ? "peers" : "does not peer");

	bool applied = PeeringTestApply(ctx, gen, red_peers);
	bool overlay = (applied && PeeringTestWaitOverlay(ctx));
	Format(what, sizeof(what), "Generation %I64u goes in at each node, and the sessions of the overlay between the three are up", gen);
	PeeringTestCheck(ctx, applied && overlay, what, "applied %u, the Generation and the sessions at each node %u", (UINT)applied, (UINT)overlay);

	bool converged = (overlay && PeeringTestWaitReports(ctx));
	PeeringTestCheck(ctx, converged, "Each node learns from the sidecar of each other node, over an established session, exactly what that node announces in the VRFs that the two share and that peer by BGP, each prefix in its VRF",
		"%s", "see the reports above");

	bool tables = (converged && PeeringTestWaitTables(ctx));
	PeeringTestCheck(ctx, tables, "The forwarding table of each VRF that peers by BGP leads the LAN of each other node to that node and the LAN of the node to its host, and no other table leads there",
		"%s", "see the line above");

	PeeringTestStatus(ctx, starts);
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

// The sidecar of node-c stops answering, as a host that loses power: its threads are suspended, so it holds its sessions and
// sends nothing. Node-a and node-b remove its routes once their hold timers expire, within the hold time, and keep each
// other's; once it answers again, the sessions come back and the mesh converges again.
static void PeeringTestSilent(PEERINGTEST_CTX *ctx)
{
	PEERINGTEST_NODE *c = &ctx->Nodes[PEERINGTEST_C];
	NODE_PEERING_STATUS st;
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
		PeeringTestSend(ctx, PEERINGTEST_A, PEERINGTEST_RED, "192.168.2.10", PEERINGTEST_B);
		PeeringTestSend(ctx, PEERINGTEST_A, PEERINGTEST_RED, "192.168.3.10", PEERINGTEST_NODES);
	}

	PeeringTestThaw(threads);
	ReleaseList(threads);
	c->Gone = false;

	bool converged = (PeeringTestWaitReports(ctx) && PeeringTestWaitTables(ctx));
	PeeringTestCheck(ctx, converged, "Once the sidecar of node-c answers again, the sessions come back and the mesh converges again", "%s", "see the lines above");
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
	PeeringTestCheck(ctx, st.ProcessId != 0 && PeeringTestExited(st.ProcessId), "The sidecar of node-c exited with the node", "process %u", st.ProcessId);

	PeeringTestSend(ctx, PEERINGTEST_A, PEERINGTEST_RED, "192.168.2.10", PEERINGTEST_B);
	PeeringTestSend(ctx, PEERINGTEST_B, PEERINGTEST_RED, "192.168.1.10", PEERINGTEST_A);
	PeeringTestSend(ctx, PEERINGTEST_A, PEERINGTEST_RED, "192.168.3.10", PEERINGTEST_NODES);
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
		for (UINT j = 0;j < PEER_KEY_SIZE;j++)
		{
			scalar[j] = (UCHAR)(0x71 + PEER_KEY_SIZE * i + j);
		}
		ok = PeerKeyFromScalar(&t->Key, scalar);

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
	}
}

// The full mesh, the refused session, red without the peering and back, the sidecar of node-c that stops answering and node-c
// that stops
static void PeeringTestRun(PEERINGTEST_CTX *ctx)
{
	UINT starts[PEERINGTEST_NODES] = {1, 1, 1};
	NODE_PEERING_STATUS a;

	ctx->Ran = true;
	if (PeeringTestMesh(ctx, 1, true, starts) == false)
	{
		return;
	}

	PeeringTestRefused(ctx);

	// Red stops peering: node-a, in no VRF that peers any more, stops its sidecar
	NodePeeringGetStatus(ctx->Nodes[PEERINGTEST_A].Node, &a);
	PeeringTestMesh(ctx, 2, false, starts);
	PeeringTestCheck(ctx, a.ProcessId != 0 && PeeringTestExited(a.ProcessId), "The sidecar of node-a of Generation 1 exited", "process %u", a.ProcessId);

	// Red peers again: node-a starts a new sidecar
	starts[PEERINGTEST_A] = 2;
	if (PeeringTestMesh(ctx, 3, true, starts) == false)
	{
		return;
	}

	PeeringTestSilent(ctx);
	PeeringTestStop(ctx);
}

// peering: the BGP peering of the standard mode between three nodes
RANZ_TEST("peering", peering_test, "BGP peering of the standard mode: three nodes, each with its sidecar ranz bgp (ranz.exe next to vpntest) on TCP 179 of a loopback address of its own, in a full mesh of two VRFs; what each learns and installs, a session from an address that the Controller did not name refused and counted, the peering of a VRF removed and back, and the routes of a node whose sidecar stops answering, or that stops, gone from the other two within the hold time.");
void peering_test(UINT num, char **arg)
{
	PEERINGTEST_CTX *ctx = ZeroMalloc(sizeof(PEERINGTEST_CTX));
	HANDLE done = CreateEventW(NULL, TRUE, FALSE, NULL);
	HANDLE watchdog = (done != NULL ? CreateThread(NULL, 0, PeeringTestWatchdog, done, 0, NULL) : NULL);
	TRANSPORT *loopback = TransportLoopbackNew("loopback", 0, false);

	Print("BGP peering test: three nodes peer by BGP in the standard mode, each with its own sidecar ranz bgp\n");

	ctx->Seq = 1;
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
