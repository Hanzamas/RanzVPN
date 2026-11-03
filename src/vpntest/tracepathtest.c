// tracepathtest.c
// Named trace path test of vpntest ("tracepath" command, SDN-89 #388)
//
// A packet of a Network whose trace is on crosses two nodes, and each records the trace ID, the ingress node, the group
// that the packet carried and the verdict of its policy (Cedar/NodeTrace.c). The test runs the overlay of two in-process
// nodes, as grouppolicytest.c does: fake adapters stand in for the hosts of node-a (10.0.0.1) and node-b (10.0.0.2), the
// in-process loopback transport carries their Noise sessions, each has a tunnel endpoint on 127.0.0.1, and the test
// applies their desired states itself (NodeOverlayApply), as the controller makes them: VRF red (101), the pool
// 10.0.0.0/24 of its Network, the tag mode trusted-underlay, node-a in the group guest (2) and node-b in server (3), each
// the peer of the other with the frame version 1. Node-a enforces the rules deny-9002 (UDP to port 9002) and allow-all,
// node-b allow-9000 (UDP to port 9000) under default deny. Each case sends one UDP packet of node-a's host to node-b's
// host from a source port of its own, NODE_TRACE_INTERVAL ms after the one before, so that node-a traces it.
// - The trace of the Network is on at both nodes, over noise, vxlan and geneve. A packet to port 9000 arrives, and node-a
//   and node-b record it with one trace ID, node-a as its ingress node, the group guest and the verdict allowed; one to
//   port 9001 is dropped at node-b, which records it as denied; one to port 9002 never leaves node-a, which records it as
//   denied, and node-b records nothing. Over vxlan node-b records nothing: the VXLAN header has no room for the option.
// - The trace is on at node-a and off at node-b, as at a node that does not know the option, over noise and geneve: the
//   packet with the option arrives at node-b, which records nothing.
// - The trace is off at both, over noise: the packet arrives, and neither node traces or records anything.
// - On the wire, over geneve and vxlan: a Generation of node-a sends its datagrams to node-b to a harness tunnel endpoint.
//   With the trace off, the datagram of geneve carries the option of the source group alone, and the one of vxlan the
//   group policy extension: no trace option, and the sizes of the datagrams before SDN-89. With it on, the datagram of
//   geneve carries the trace option after the option of the source group, with the trace ID that node-a recorded and its
//   static key, 16 bytes more, and the one of vxlan keeps its size.
// Print "TRACEPATH TEST OK" only when every check passes.

#include "testlist.h"

#include "Cedar/ConfigStore.h"
#include "Cedar/Node.h"
#include "Cedar/NodeLink.h"
#include "Cedar/NodeSourceGroup.h"
#include "Cedar/NodeTrace.h"

#include "Mayaqua/Encrypt.h"
#include "Mayaqua/FileIO.h"
#include "Mayaqua/Internat.h"
#include "Mayaqua/IpAddr.h"
#include "Mayaqua/Kernel.h"
#include "Mayaqua/Memory.h"
#include "Mayaqua/Microsoft.h"
#include "Mayaqua/Network.h"
#include "Mayaqua/Object.h"
#include "Mayaqua/Str.h"
#include "Mayaqua/TcpIp.h"
#include "Mayaqua/Tick64.h"

#include "Core/Control.h"
#include "Core/Transport.h"
#include "Core/Vxlan.h"

#include <WS2tcpip.h>

#include <stdio.h>

#define	TPTEST_BUDGET			120000		// The whole test ends within this time, or the watchdog ends the process (ms)
#define	TPTEST_BOUND			10000		// A bounded wait on observable state (ms)
#define	TPTEST_QUIET			300			// A host that gets nothing gets nothing within this time (ms)
#define	TPTEST_POLL				10			// Poll interval of observable state (ms)
#define	TPTEST_SIZE				100			// The size of a test packet
#define	TPTEST_VNI				5101		// The VNI of red over vxlan and geneve
#define	TPTEST_VRF				101			// The id of red
#define	TPTEST_FIRST_PORT		21000		// The UDP source port of the first case; each case takes the next
#define	TPTEST_ALLOWED			9000		// The UDP port that both policies allow
#define	TPTEST_DENIED_B			9001		// ... that the policy of node-b denies
#define	TPTEST_DENIED_A			9002		// ... that the policy of node-a denies
#define	TPTEST_GUEST			2			// The group of node-a ...
#define	TPTEST_GUEST_TAGS		0x2ULL		// ... and its tag set
#define	TPTEST_SERVER			3			// The group of node-b ...
#define	TPTEST_SERVER_TAGS		0x4ULL		// ... and its tag set

// The two nodes
#define	TPTEST_A				0
#define	TPTEST_B				1
#define	TPTEST_NUM_NODES		2

static char *tptest_names[TPTEST_NUM_NODES] = {"node-a", "node-b"};
static char *tptest_addrs[TPTEST_NUM_NODES] = {"10.0.0.1", "10.0.0.2"};
static char *tptest_tags[TPTEST_NUM_NODES] = {"guest", "server"};
static char *tptest_kind_names[3] = {"noise", "vxlan", "geneve"};

// The MAC address of both ends of the Ethernet header of a frame of a link (NodeLink.c)
static const UCHAR tptest_mac[6] = {0x02, 0x52, 0x5A, 0x00, 0x00, 0x03};

// One case: a packet of node-a's host to a port of node-b's host, the verdicts of the policies of the two nodes on it
typedef struct TPTEST_CASE
{
	UINT Port;
	bool AllowedA;
	bool AllowedB;
	char *What;
} TPTEST_CASE;

static TPTEST_CASE tptest_cases[] =
{
	{TPTEST_ALLOWED, true, true, "a packet to port 9000, which both policies allow, arrives"},
	{TPTEST_DENIED_B, true, false, "a packet to port 9001, which the policy of node-b denies, is dropped at node-b"},
	{TPTEST_DENIED_A, false, false, "a packet to port 9002, which the policy of node-a denies, never leaves node-a"},
};

// One node and the fake adapter of its host, which keeps the last packet that the host took
typedef struct TPTEST_NODE
{
	wchar_t Dir[MAX_PATH];				// Its data directory
	PEER_KEY Key;						// Its static key
	NODE *Node;
	NODE_READER Reader;					// The test thread as a reader of the node's tables, online while it sends
	USHORT VxlanPort;					// The UDP port of its socket of VXLAN ...
	USHORT GenevePort;					// ... and of Geneve
	UINT64 Generation;					// The Generation of the last state that the test applied
	SRWLOCK Lock;						// Arrivals, Last and LastSize
	volatile LONG Arrivals;				// Packets that the host took
	UCHAR Last[TPTEST_SIZE * 2];		// The last one, as much as fits
	UINT LastSize;
} TPTEST_NODE;

// The test
typedef struct TPTEST_CTX
{
	UINT NumChecks;
	UINT NumFailed;
	TPTEST_NODE Nodes[TPTEST_NUM_NODES];
	SOCKET Vtep;						// The harness tunnel endpoint, on 127.0.0.1, which takes the datagrams of node-a in place of node-b ...
	USHORT VtepPort;					// ... on this UDP port
	UINT NextPort;						// The UDP source port of the next case
} TPTEST_CTX;

static bool TpTestCheck(TPTEST_CTX *ctx, bool ok, char *what, char *fmt, ...) RANZ_PRINTF_FORMAT(4, 5);
static bool TpTestCheck(TPTEST_CTX *ctx, bool ok, char *what, char *fmt, ...)
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

// The watchdog: a native thread that ends a run that hangs, so that a lost packet is a failed test instead of a hung CI
// step
static DWORD WINAPI TpTestWatchdog(LPVOID param)
{
	char msg[MAX_SIZE];
	DWORD written = 0;

	if (WaitForSingleObject((HANDLE)param, TPTEST_BUDGET) != WAIT_TIMEOUT)
	{
		return 0;
	}

	int len = snprintf(msg, sizeof(msg), "TRACEPATH TEST FAILED (did not finish within %u ms)\n", TPTEST_BUDGET);
	if (len > 0)
	{
		WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), msg, (DWORD)MIN((UINT)len, (UINT)sizeof(msg) - 1), &written, NULL);
	}

	TerminateProcess(GetCurrentProcess(), 1);

	return 0;
}

// The IPv4 address of a text into addr, 4 bytes
static void TpTestAddress(UCHAR *addr, char *str)
{
	IP ip;

	Zero(addr, 4);
	if (StrToIP(&ip, str) && IsIP4(&ip))
	{
		Copy(addr, IPV4(ip.address), 4);
	}
}

// The test packet from node-a's address and the UDP port sport to node-b's address on the UDP port dport, TPTEST_SIZE
// bytes of IPv4, into buf
static void TpTestPacket(UCHAR *buf, UINT sport, UINT dport)
{
	UCHAR addr[4];

	Zero(buf, TPTEST_SIZE);
	buf[0] = 0x45;
	WRITE_USHORT(buf + 2, TPTEST_SIZE);
	buf[8] = 64;
	buf[9] = IP_PROTO_UDP;
	TpTestAddress(addr, tptest_addrs[TPTEST_A]);
	Copy(buf + 12, addr, 4);
	TpTestAddress(addr, tptest_addrs[TPTEST_B]);
	Copy(buf + 16, addr, 4);
	USHORT sum = IpChecksum(buf, 20);
	Copy(buf + 10, &sum, 2);

	WRITE_USHORT(buf + 20, sport);
	WRITE_USHORT(buf + 22, dport);
	WRITE_USHORT(buf + 24, TPTEST_SIZE - 20);
	for (UINT i = 28;i < TPTEST_SIZE;i++)
	{
		buf[i] = (UCHAR)(i * 13 + sport);
	}
}

// The num free UDP ports of the wildcard address into ports, which the system picks, each another: the sockets that
// found them stay open until all are found. False when one cannot be found.
static bool TpTestFreePorts(USHORT *ports, UINT num)
{
	SOCKET sockets[4] = {INVALID_SOCKET, INVALID_SOCKET, INVALID_SOCKET, INVALID_SOCKET};
	bool ok = (num <= 4);

	for (UINT i = 0;i < num && ok;i++)
	{
		struct sockaddr_in6 sa;
		int sa_size = sizeof(sa);

		ports[i] = 0;
		sockets[i] = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
		Zero(&sa, sizeof(sa));
		sa.sin6_family = AF_INET6;
		if (sockets[i] != INVALID_SOCKET && bind(sockets[i], (struct sockaddr *)&sa, sizeof(sa)) == 0 && getsockname(sockets[i], (struct sockaddr *)&sa, &sa_size) == 0)
		{
			ports[i] = ntohs(sa.sin6_port);
		}
		ok = (ports[i] != 0);
	}

	for (UINT i = 0;i < num && i < 4;i++)
	{
		if (sockets[i] != INVALID_SOCKET)
		{
			closesocket(sockets[i]);
		}
	}

	return ok;
}

// The harness tunnel endpoint: a UDP socket on 127.0.0.1, on a port that the system picks, into ctx
static bool TpTestOpenVtep(TPTEST_CTX *ctx)
{
	struct sockaddr_in sa;
	int sa_size = sizeof(sa);

	ctx->Vtep = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (ctx->Vtep == INVALID_SOCKET)
	{
		return false;
	}

	Zero(&sa, sizeof(sa));
	sa.sin_family = AF_INET;
	sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	if (bind(ctx->Vtep, (struct sockaddr *)&sa, sizeof(sa)) != 0 || getsockname(ctx->Vtep, (struct sockaddr *)&sa, &sa_size) != 0)
	{
		return false;
	}

	ctx->VtepPort = ntohs(sa.sin_port);
	return (ctx->VtepPort != 0);
}

// The next datagram that the harness tunnel endpoint takes within timeout ms, into buf of size bytes: its size, 0 for none
static UINT TpTestTake(TPTEST_CTX *ctx, UCHAR *buf, UINT size, UINT timeout)
{
	fd_set fds;
	struct timeval tv;

	FD_ZERO(&fds);
	FD_SET(ctx->Vtep, &fds);
	tv.tv_sec = (long)(timeout / 1000);
	tv.tv_usec = (long)((timeout % 1000) * 1000);
	if (select(0, &fds, NULL, NULL, &tv) != 1)
	{
		return 0;
	}

	int got = recvfrom(ctx->Vtep, (char *)buf, (int)size, 0, NULL, NULL);

	return (got > 0 ? (UINT)got : 0);
}

//
// The nodes
//

// A new empty data directory under the temp directory of the process, with a configuration store that runs no role
// on one worker
static void TpTestNewDir(wchar_t *dir, UINT size, char *name)
{
	wchar_t tmp[MAX_PATH];
	wchar_t path[MAX_PATH];

	UniFormat(tmp, sizeof(tmp), L"tracepathtest_%S_%u", name, Rand32());
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
static void TpTestDeleteFiles(wchar_t *dir)
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

// The fake adapter of a host: it counts the packets that the host takes and keeps the last one. A link delivers on the
// receive thread of its socket and a session on the thread of the overlay, so the lock orders the two.
static void TpTestAdapter(NODE *n, void *param, UINT vrf_id, const UCHAR *packet, UINT size)
{
	TPTEST_NODE *t = (TPTEST_NODE *)param;

	AcquireSRWLockExclusive(&t->Lock);
	{
		t->LastSize = size;
		Copy(t->Last, packet, MIN(size, sizeof(t->Last)));
		InterlockedIncrement(&t->Arrivals);
	}
	ReleaseSRWLockExclusive(&t->Lock);
}

// The address of node i in red into a
static void TpTestAddressOf(UINT i, CONTROL_ADDRESS *a)
{
	Zero(a, sizeof(CONTROL_ADDRESS));
	StrCpy(a->Network, sizeof(a->Network), "red-lan");
	a->VrfId = TPTEST_VRF;
	a->AddressSize = 4;
	TpTestAddress(a->Address, tptest_addrs[i]);
	a->Length = 24;
}

// The tunnel endpoint of node i into v: 127.0.0.1 and its ports, or only its ports for itself; the harness tunnel
// endpoint in its place with harness
static void TpTestVtep(TPTEST_CTX *ctx, UINT i, CONTROL_VTEP *v, bool address, bool harness)
{
	Zero(v, sizeof(CONTROL_VTEP));
	if (address)
	{
		v->AddressSize = 4;
		TpTestAddress(v->Address, "127.0.0.1");
	}
	v->VxlanPort = (harness ? ctx->VtepPort : ctx->Nodes[i].VxlanPort);
	v->GenevePort = (harness ? ctx->VtepPort : ctx->Nodes[i].GenevePort);
}

// One rule of red into r: name, priority, deny or allow, of UDP to port, 0 for any protocol and port
static void TpTestRule(CONTROL_RULE *r, char *name, UINT priority, bool deny, UINT port)
{
	Zero(r, sizeof(CONTROL_RULE));
	StrCpy(r->Name, sizeof(r->Name), name);
	r->VrfId = TPTEST_VRF;
	r->Priority = priority;
	r->Deny = deny;
	if (port != 0)
	{
		r->Protocol = IP_PROTO_UDP;
		r->NumPorts = 1;
		r->FirstPort[0] = port;
		r->LastPort[0] = port;
	}
}

// Apply the next Generation of node i: its address and its tag in red, its own group, its tunnel endpoint and its rules;
// VRF red with the link of kind in the tag mode trusted-underlay and its policy; the other node as its peer, with its group
// and the frame version 1, and the harness tunnel endpoint in place of the tunnel endpoint of node-b when harness is set; and
// with traced, the pool 10.0.0.0/24 of the Network of red, whose trace is on
static bool TpTestApply(TPTEST_CTX *ctx, UINT i, UINT kind, bool traced, bool harness)
{
	CONTROL_STATE *st = ZeroMalloc(sizeof(CONTROL_STATE));
	CONTROL_RULE *rules = ZeroMalloc(sizeof(CONTROL_RULE) * 2);
	CONTROL_PEER *p = ZeroMalloc(sizeof(CONTROL_PEER));
	TPTEST_NODE *t = &ctx->Nodes[i];
	bool b = (i == TPTEST_B);
	UINT j = 1 - i;

	st->Generation = ++t->Generation;
	StrCpy(st->Name, sizeof(st->Name), tptest_names[i]);
	st->NumAddresses = 1;
	TpTestAddressOf(i, &st->Addresses[0]);
	st->NumTags = 1;
	StrCpy(st->Tags[0], sizeof(st->Tags[0]), tptest_tags[i]);
	TpTestVtep(ctx, i, &st->Vtep, false, false);

	st->NumVrfs = 1;
	StrCpy(st->Vrfs[0].Name, sizeof(st->Vrfs[0].Name), "red");
	st->Vrfs[0].Id = TPTEST_VRF;
	st->Vrfs[0].Policy = true;
	st->Vrfs[0].Link = kind;
	st->Vrfs[0].Vni = (kind != CONTROL_LINK_NOISE ? TPTEST_VNI : 0);
	st->Vrfs[0].TagMode = CONTROL_TAG_MODE_TRUSTED;

	// The rules of red at each node, in name order: node-a denies UDP to port 9002 and allows the rest, node-b allows UDP to
	// port 9000 under default deny
	if (b)
	{
		TpTestRule(&rules[0], "allow-9000", 100, false, TPTEST_ALLOWED);
		st->NumRules = 1;
	}
	else
	{
		TpTestRule(&rules[0], "allow-all", 100, false, 0);
		TpTestRule(&rules[1], "deny-9002", 10, true, TPTEST_DENIED_A);
		st->NumRules = 2;
	}
	st->Rules = rules;

	// Its own source group in red, as the controller gives a node that reports the Capability tags
	st->NumGroups = 1;
	st->Groups[0].VrfId = TPTEST_VRF;
	st->Groups[0].Group = (b ? TPTEST_SERVER : TPTEST_GUEST);
	st->Groups[0].TagSet = (b ? TPTEST_SERVER_TAGS : TPTEST_GUEST_TAGS);
	st->Groups[0].Generation = 1;

	// The other node, its peer, with its group and the frame version 1
	StrCpy(p->Name, sizeof(p->Name), tptest_names[j]);
	Copy(p->Key, ctx->Nodes[j].Key.Public, PEER_KEY_SIZE);
	p->NumVrfs = 1;
	p->VrfIds[0] = TPTEST_VRF;
	p->NumAddresses = 1;
	TpTestAddressOf(j, &p->Addresses[0]);
	p->NumTags = 1;
	StrCpy(p->Tags[0], sizeof(p->Tags[0]), tptest_tags[j]);
	TpTestVtep(ctx, j, &p->Vtep, true, harness && b == false);
	p->NumGroups = 1;
	p->Groups[0].VrfId = TPTEST_VRF;
	p->Groups[0].Group = (b ? TPTEST_GUEST : TPTEST_SERVER);
	p->Groups[0].TagSet = (b ? TPTEST_GUEST_TAGS : TPTEST_SERVER_TAGS);
	p->Groups[0].Generation = 1;
	p->FrameVersion = NODE_FRAME_VERSION;
	st->NumPeers = 1;
	st->Peers = p;

	// The trace of the Network of red, whose pool is 10.0.0.0/24
	if (traced)
	{
		st->NumTraced = 1;
		st->Traced[0].VrfId = TPTEST_VRF;
		st->Traced[0].Pool.AddressSize = 4;
		TpTestAddress(st->Traced[0].Pool.Address, "10.0.0.0");
		st->Traced[0].Pool.Length = 24;
	}

	bool ok = NodeOverlayApply(t->Node, st);

	Free(p);
	Free(rules);
	Free(st);

	return ok;
}

// Whether each node runs the Generation that the test applied last with its session to the other up, within TPTEST_BOUND
static bool TpTestWaitLinks(TPTEST_CTX *ctx)
{
	UINT64 end = Tick64() + TPTEST_BOUND;

	while (true)
	{
		NODE_OVERLAY_STATUS a, b;

		NodeOverlayGetStatus(ctx->Nodes[TPTEST_A].Node, &a);
		NodeOverlayGetStatus(ctx->Nodes[TPTEST_B].Node, &b);
		if (a.NumLinks == 1 && b.NumLinks == 1 && a.Generation == ctx->Nodes[TPTEST_A].Generation && b.Generation == ctx->Nodes[TPTEST_B].Generation)
		{
			return true;
		}
		if (Tick64() >= end)
		{
			return false;
		}
		SleepThread(TPTEST_POLL);
	}
}

// One Generation of each node with the link of kind, node-b first, the trace on at node-a when traced_a and at node-b when
// traced_b, and the harness tunnel endpoint in place of node-b's in the state of node-a with harness: each runs it and the
// session stays up
static bool TpTestSwitch(TPTEST_CTX *ctx, UINT kind, bool traced_a, bool traced_b, bool harness)
{
	char what[MAX_SIZE];

	bool applied = TpTestApply(ctx, TPTEST_B, kind, traced_b, false) && TpTestApply(ctx, TPTEST_A, kind, traced_a, harness);
	bool linked = applied && TpTestWaitLinks(ctx);

	Format(what, sizeof(what), "The link of red is %s, the trace of its Network %s at node-a and %s at node-b%s: one Generation of each node, and the session stays up",
		tptest_kind_names[kind], traced_a ? "on" : "off", traced_b ? "on" : "off", harness ? ", node-a sends its datagrams to the harness tunnel endpoint" : "");
	return TpTestCheck(ctx, applied && linked, what, "applied %u, the Generations %I64u and %I64u and the session on both %u", (UINT)applied,
		ctx->Nodes[TPTEST_A].Generation, ctx->Nodes[TPTEST_B].Generation, (UINT)linked);
}

// Whether the host of node t took at least target packets within timeout
static bool TpTestArrived(TPTEST_NODE *t, LONG target, UINT timeout)
{
	UINT64 end = Tick64() + timeout;

	while (InterlockedCompareExchange(&t->Arrivals, 0, 0) < target)
	{
		if (Tick64() >= end)
		{
			return false;
		}
		SleepThread(TPTEST_POLL);
	}

	return true;
}

// The record of the trace id that node t holds in the queue of its control stream into *r, waiting until it holds one
// within timeout ms; false for none
static bool TpTestRecordOf(TPTEST_NODE *t, UINT id, CONTROL_TRACE *r, UINT timeout)
{
	NODE_TRACE_STATUS *st = ZeroMalloc(sizeof(NODE_TRACE_STATUS));
	UINT64 end = Tick64() + timeout;
	bool found = false;

	while (found == false)
	{
		NodeTraceGetStatus(t->Node, st);
		for (UINT i = 0;i < st->NumRecords && found == false;i++)
		{
			if (st->Records[i].Id == id)
			{
				Copy(r, &st->Records[i], sizeof(CONTROL_TRACE));
				found = true;
			}
		}
		if (found || Tick64() >= end)
		{
			break;
		}
		SleepThread(TPTEST_POLL);
	}

	Free(st);
	return found;
}

// The record that node t made last into *r: false when it made none since it had made recorded records
static bool TpTestLastRecord(TPTEST_NODE *t, UINT64 recorded, CONTROL_TRACE *r)
{
	NODE_TRACE_STATUS *st = ZeroMalloc(sizeof(NODE_TRACE_STATUS));

	NodeTraceGetStatus(t->Node, st);
	bool ok = (st->Recorded > recorded && st->NumRecords != 0);
	if (ok)
	{
		Copy(r, &st->Records[st->NumRecords - 1], sizeof(CONTROL_TRACE));
	}

	Free(st);
	return ok;
}

// The records that node t made since its overlay started
static UINT64 TpTestRecorded(TPTEST_NODE *t)
{
	NODE_TRACE_STATUS *st = ZeroMalloc(sizeof(NODE_TRACE_STATUS));

	NodeTraceGetStatus(t->Node, st);
	UINT64 recorded = st->Recorded;

	Free(st);
	return recorded;
}

// Send the packet of the case from node-a's host, once NODE_TRACE_INTERVAL ms passed since the one before, so that node-a
// traces it when the trace of the Network is on there. Whether it went.
static bool TpTestSend(TPTEST_CTX *ctx, UCHAR *packet, UINT port)
{
	TPTEST_NODE *a = &ctx->Nodes[TPTEST_A];

	SleepThread(NODE_TRACE_INTERVAL + 50);
	TpTestPacket(packet, ctx->NextPort++, port);

	NodeReaderOnline(a->Node, &a->Reader);
	bool sent = NodeOverlayInput(a->Node, TPTEST_VRF, packet, TPTEST_SIZE);
	NodeReaderOffline(&a->Reader);

	return sent;
}

//
// The cases
//

// One case over the link of kind with the trace on at both nodes, or at node-a alone unless traced_b: the packet goes when
// the policy of node-a allows it, and NodeOverlayInput says that it went nowhere when that policy denies it; node-a records
// the packet as its ingress node with the group guest and its verdict; node-b records it with the same trace ID, ingress
// node and group and its own verdict, when the packet left node-a, the link carries the option and the trace is on at
// node-b, and nothing otherwise; and node-b's host takes the packet as it was sent when both policies allow it
static void TpTestCase(TPTEST_CTX *ctx, UINT kind, TPTEST_CASE *c, bool traced_b)
{
	TPTEST_NODE *a = &ctx->Nodes[TPTEST_A];
	TPTEST_NODE *b = &ctx->Nodes[TPTEST_B];
	UCHAR packet[TPTEST_SIZE];
	CONTROL_TRACE ra, rb;
	char what[MAX_SIZE * 2];
	bool same = false;

	UINT64 recorded_a = TpTestRecorded(a);
	UINT64 recorded_b = TpTestRecorded(b);
	LONG arrivals = InterlockedCompareExchange(&b->Arrivals, 0, 0);
	bool sent = TpTestSend(ctx, packet, c->Port);

	// Node-a records the packet that it handled as its ingress node, before it goes out
	Zero(&ra, sizeof(ra));
	bool ingress = TpTestLastRecord(a, recorded_a, &ra) && ra.Id != 0 && Cmp(ra.Ingress, a->Key.Public, CONTROL_TRACE_INGRESS) == 0 &&
		ra.VrfId == TPTEST_VRF && ra.Group == TPTEST_GUEST && ra.Allowed == c->AllowedA;

	// Node-b records it with the same trace ID when the trace reaches it
	bool reaches = (c->AllowedA && traced_b && kind != CONTROL_LINK_VXLAN);
	bool recorded = false;
	Zero(&rb, sizeof(rb));
	if (reaches)
	{
		recorded = ingress && TpTestRecordOf(b, ra.Id, &rb, TPTEST_BOUND) && Cmp(rb.Ingress, a->Key.Public, CONTROL_TRACE_INGRESS) == 0 &&
			rb.VrfId == TPTEST_VRF && rb.Group == TPTEST_GUEST && rb.Allowed == c->AllowedB;
	}

	bool arrived = sent && TpTestArrived(b, arrivals + 1, (c->AllowedA && c->AllowedB) ? TPTEST_BOUND : TPTEST_QUIET);
	AcquireSRWLockShared(&b->Lock);
	{
		same = (arrived && b->LastSize == TPTEST_SIZE && Cmp(b->Last, packet, TPTEST_SIZE) == 0);
	}
	ReleaseSRWLockShared(&b->Lock);

	// ... and nothing more: no record when the trace does not reach it
	bool quiet = (reaches || TpTestRecorded(b) == recorded_b);

	if (reaches)
	{
		Format(what, sizeof(what), "  %s: %s; node-a records it as its ingress node, node-b with the same trace ID, both with the group guest, node-a as %s and node-b as %s",
			tptest_kind_names[kind], c->What, c->AllowedA ? "allowed" : "denied", c->AllowedB ? "allowed" : "denied");
	}
	else
	{
		Format(what, sizeof(what), "  %s: %s; node-a records it as its ingress node with the group guest as %s, and node-b records nothing%s", tptest_kind_names[kind], c->What,
			c->AllowedA ? "allowed" : "denied", (kind == CONTROL_LINK_VXLAN && c->AllowedA) ? ", as the VXLAN header has no room for the trace option" :
			(traced_b == false && c->AllowedA) ? ", as its trace is off" : "");
	}
	TpTestCheck(ctx, sent == c->AllowedA && ingress && (reaches == false || recorded) && quiet && arrived == (c->AllowedA && c->AllowedB) && (arrived == false || same), what,
		"sent %u, node-a recorded %u (trace 0x%08x, group %u, allowed %u), node-b recorded %u (trace 0x%08x, group %u, allowed %u), node-b quiet %u, arrived %u, as it was sent %u",
		(UINT)sent, (UINT)ingress, ra.Id, ra.Group, (UINT)ra.Allowed, (UINT)recorded, rb.Id, rb.Group, (UINT)rb.Allowed, (UINT)quiet, (UINT)arrived, (UINT)same);
}

// The packet of node-a's host that node-a sends to the harness tunnel endpoint over the link of kind, with the trace of the
// Network off and then on at node-a: the datagram of each, its size and whether it carries the trace option of the trace
// that node-a recorded
static void TpTestWire(TPTEST_CTX *ctx, UINT kind)
{
	TPTEST_NODE *a = &ctx->Nodes[TPTEST_A];
	bool geneve = (kind == CONTROL_LINK_GENEVE);
	UINT before = (geneve ? GENEVE_HEADER_SIZE + GENEVE_GROUP_OPTION : VXLAN_HEADER_SIZE) + NODE_LINK_ETHER + TPTEST_SIZE;
	UCHAR packet[TPTEST_SIZE];
	UCHAR datagram[VXLAN_MAX_DATAGRAM];
	char what[MAX_SIZE * 2];

	for (UINT on = 0;on < 2;on++)
	{
		if (TpTestSwitch(ctx, kind, on != 0, true, true) == false)
		{
			return;
		}

		// What the harness tunnel endpoint holds from before goes
		while (TpTestTake(ctx, datagram, sizeof(datagram), 0) != 0)
		{
		}

		UINT64 recorded = TpTestRecorded(a);
		bool sent = TpTestSend(ctx, packet, TPTEST_ALLOWED);
		UINT size = (sent ? TpTestTake(ctx, datagram, sizeof(datagram), TPTEST_BOUND) : 0);
		CONTROL_TRACE r;
		Zero(&r, sizeof(r));
		bool traced = TpTestLastRecord(a, recorded, &r);

		// The frame of the packet after the header and its options, and the trace option after the option of the source group
		UINT header = (geneve ? GENEVE_HEADER_SIZE + (datagram[0] & 0x3F) * 4 : VXLAN_HEADER_SIZE);
		bool frame = (size == header + NODE_LINK_ETHER + TPTEST_SIZE && Cmp(datagram + header, tptest_mac, 6) == 0 &&
			Cmp(datagram + header + NODE_LINK_ETHER, packet, TPTEST_SIZE) == 0);
		const UCHAR *o = datagram + GENEVE_HEADER_SIZE + GENEVE_GROUP_OPTION;
		bool option = (geneve && size >= GENEVE_HEADER_SIZE + GENEVE_GROUP_OPTION + GENEVE_TRACE_OPTION && header == GENEVE_HEADER_SIZE + GENEVE_GROUP_OPTION + GENEVE_TRACE_OPTION &&
			READ_USHORT(o) == GENEVE_CLASS_RANZ && o[2] == GENEVE_TYPE_TRACE && o[3] == GENEVE_TRACE_DATA / 4 && READ_UINT(o + 4) == r.Id &&
			Cmp(o + 8, a->Key.Public, VXLAN_TRACE_INGRESS) == 0);

		if (on == 0)
		{
			Format(what, sizeof(what), "  %s: with the trace off, the datagram carries no trace option and has the size of a datagram before SDN-89, %u bytes", tptest_kind_names[kind], before);
			TpTestCheck(ctx, sent && frame && size == before && traced == false, what, "sent %u, a datagram of %u bytes with a header of %u, the frame as it was sent %u, recorded %u",
				(UINT)sent, size, header, (UINT)frame, (UINT)traced);
		}
		else if (geneve)
		{
			Format(what, sizeof(what), "  %s: with the trace on, the datagram carries the trace option of node-a after the option of the source group, %u bytes more, %u",
				tptest_kind_names[kind], GENEVE_TRACE_OPTION, before + GENEVE_TRACE_OPTION);
			TpTestCheck(ctx, sent && frame && traced && option && size == before + GENEVE_TRACE_OPTION, what,
				"sent %u, a datagram of %u bytes with a header of %u, the frame as it was sent %u, recorded %u (trace 0x%08x), the trace option %u", (UINT)sent, size, header,
				(UINT)frame, (UINT)traced, r.Id, (UINT)option);
		}
		else
		{
			Format(what, sizeof(what), "  %s: with the trace on, the datagram keeps its size, %u bytes, as the VXLAN header has no room for the trace option; node-a records the packet",
				tptest_kind_names[kind], before);
			TpTestCheck(ctx, sent && frame && traced && size == before, what, "sent %u, a datagram of %u bytes, the frame as it was sent %u, recorded %u", (UINT)sent, size,
				(UINT)frame, (UINT)traced);
		}
	}
}

// The trace of the Network off at both nodes, over noise: the packet arrives, and neither node traces or records anything
static void TpTestOff(TPTEST_CTX *ctx)
{
	TPTEST_NODE *a = &ctx->Nodes[TPTEST_A];
	TPTEST_NODE *b = &ctx->Nodes[TPTEST_B];
	UCHAR packet[TPTEST_SIZE];
	NODE_TRACE_STATUS *sa = ZeroMalloc(sizeof(NODE_TRACE_STATUS));
	NODE_TRACE_STATUS *sb = ZeroMalloc(sizeof(NODE_TRACE_STATUS));

	if (TpTestSwitch(ctx, CONTROL_LINK_NOISE, false, false, false))
	{
		NodeTraceGetStatus(a->Node, sa);
		UINT64 traced = sa->Traced;
		UINT64 recorded_a = sa->Recorded;
		NodeTraceGetStatus(b->Node, sb);
		UINT64 recorded_b = sb->Recorded;
		LONG arrivals = InterlockedCompareExchange(&b->Arrivals, 0, 0);

		bool sent = TpTestSend(ctx, packet, TPTEST_ALLOWED);
		bool arrived = sent && TpTestArrived(b, arrivals + 1, TPTEST_BOUND);
		NodeTraceGetStatus(a->Node, sa);
		NodeTraceGetStatus(b->Node, sb);

		TpTestCheck(ctx, sent && arrived && sa->Traced == traced && sa->Recorded == recorded_a && sb->Recorded == recorded_b,
			"  noise: with the trace off at both nodes, the packet arrives, and neither node traces or records it",
			"sent %u, arrived %u, node-a traced %I64u and recorded %I64u more, node-b recorded %I64u more", (UINT)sent, (UINT)arrived, sa->Traced - traced,
			sa->Recorded - recorded_a, sb->Recorded - recorded_b);
	}

	Free(sb);
	Free(sa);
}

// The nodes, their overlays and the harness tunnel endpoint, and the first Generation of both: noise, the trace on at both
static bool TpTestOpen(TPTEST_CTX *ctx, TRANSPORT *loopback)
{
	UCHAR scalar[PEER_KEY_SIZE];
	char what[MAX_SIZE];
	bool ok = (loopback != NULL);
	USHORT ports[4];

	Print("[the nodes, their overlays and the harness tunnel endpoint]\n");

	// The UDP ports of VXLAN and of Geneve of node-a and node-b
	ok = TpTestCheck(ctx, ok && TpTestFreePorts(ports, 4), "Four free UDP ports for the tunnel endpoints of the nodes", "error %u", (UINT)WSAGetLastError()) && ok;
	ok = TpTestCheck(ctx, ok && TpTestOpenVtep(ctx), "A harness tunnel endpoint on 127.0.0.1", "error %u", (UINT)WSAGetLastError()) && ok;

	for (UINT i = 0;i < TPTEST_NUM_NODES && ok;i++)
	{
		TPTEST_NODE *t = &ctx->Nodes[i];
		NODE_OVERLAY_CONFIG c;

		InitializeSRWLock(&t->Lock);
		t->VxlanPort = ports[2 * i];
		t->GenevePort = ports[2 * i + 1];
		for (UINT j = 0;j < PEER_KEY_SIZE;j++)
		{
			scalar[j] = (UCHAR)(0x31 + PEER_KEY_SIZE * i + j);
		}
		ok = PeerKeyFromScalar(&t->Key, scalar);

		TpTestNewDir(t->Dir, sizeof(t->Dir), tptest_names[i]);
		t->Node = NewNode(t->Dir);
		NodeStart(t->Node);
		NodeReaderRegister(t->Node, &t->Reader);
		NodeReaderOffline(&t->Reader);

		Zero(&c, sizeof(c));
		c.Data = loopback;
		c.Key = &t->Key;
		c.Adapter = TpTestAdapter;
		c.AdapterParam = t;
		Format(what, sizeof(what), "  %s: its overlay runs without a control stream, its tunnel endpoint on the UDP ports %u (VXLAN) and %u (Geneve)", tptest_names[i], (UINT)t->VxlanPort, (UINT)t->GenevePort);
		ok = TpTestCheck(ctx, ok && NodeOverlayStart(t->Node, &c), what, "PeerKeyFromScalar or NodeOverlayStart failed") && ok;
	}
	Zero(scalar, sizeof(scalar));

	return ok && TpTestSwitch(ctx, CONTROL_LINK_NOISE, true, true, false);
}

// The nodes first, whose overlays stop with every thread joined, then the harness tunnel endpoint
static void TpTestClose(TPTEST_CTX *ctx)
{
	for (UINT i = 0;i < TPTEST_NUM_NODES;i++)
	{
		TPTEST_NODE *t = &ctx->Nodes[i];
		wchar_t log_dir[MAX_PATH];

		if (t->Node != NULL)
		{
			NodeReaderUnregister(t->Node, &t->Reader);
			NodeStop(t->Node);
			FreeNode(t->Node);

			ConbinePathW(log_dir, sizeof(log_dir), t->Dir, NODE_LOG_DIR_NAME);
			TpTestDeleteFiles(log_dir);
			TpTestDeleteFiles(t->Dir);
		}
		PeerKeyClose(&t->Key);
	}

	if (ctx->Vtep != INVALID_SOCKET)
	{
		closesocket(ctx->Vtep);
	}
}

// The cases over noise, vxlan and geneve with the trace on at both nodes; over noise and geneve with the trace off at
// node-b; over noise with it off at both; and the datagrams of geneve and vxlan on the wire
static void TpTestRun(TPTEST_CTX *ctx)
{
	UINT kinds[3] = {CONTROL_LINK_NOISE, CONTROL_LINK_VXLAN, CONTROL_LINK_GENEVE};
	UINT num = sizeof(tptest_cases) / sizeof(tptest_cases[0]);

	for (UINT k = 0;k < 3;k++)
	{
		Print("[the trace of the Network of red is on at both nodes, the link of red is %s]\n", tptest_kind_names[kinds[k]]);
		if (k != 0 && TpTestSwitch(ctx, kinds[k], true, true, false) == false)
		{
			return;
		}
		for (UINT i = 0;i < num;i++)
		{
			TpTestCase(ctx, kinds[k], &tptest_cases[i], true);
		}
	}

	// Node-b, whose trace is off, takes the option as a node that does not know it: it forwards the packet to its host
	for (UINT k = 0;k < 3;k++)
	{
		if (kinds[k] == CONTROL_LINK_VXLAN)
		{
			continue;
		}
		Print("[the trace is on at node-a and off at node-b, as at a node that does not know the option, the link of red is %s]\n", tptest_kind_names[kinds[k]]);
		if (TpTestSwitch(ctx, kinds[k], true, false, false))
		{
			TpTestCase(ctx, kinds[k], &tptest_cases[0], false);
		}
	}

	Print("[the trace is off at both nodes]\n");
	TpTestOff(ctx);

	// The datagrams on the wire
	for (UINT k = 0;k < 3;k++)
	{
		if (kinds[k] == CONTROL_LINK_NOISE)
		{
			continue;
		}
		Print("[the datagrams of node-a on the wire, the link of red is %s]\n", tptest_kind_names[kinds[k]]);
		TpTestWire(ctx, kinds[k]);
	}
}

// tracepath: a traced packet through two nodes
RANZ_TEST_TAGS("tracepath", tracepath_test, "core", "Trace path (SDN-89): a packet of a Network whose trace is on crosses two nodes over noise, vxlan and geneve, and each records the trace ID, the ingress node, the group that the packet carried and the verdict of its policy; over vxlan the trace ends at the ingress node; a node whose trace is off forwards the packet with the option; with the trace off no option goes and a datagram keeps its size.");
void tracepath_test(UINT num, char **arg)
{
	TPTEST_CTX *ctx = ZeroMalloc(sizeof(TPTEST_CTX));
	HANDLE done = CreateEventW(NULL, TRUE, FALSE, NULL);
	HANDLE watchdog = (done != NULL ? CreateThread(NULL, 0, TpTestWatchdog, done, 0, NULL) : NULL);
	TRANSPORT *loopback = TransportLoopbackNew("loopback", 0, false);

	Print("Trace path test: a traced packet crosses two nodes, and each records it\n");

	ctx->Vtep = INVALID_SOCKET;
	ctx->NextPort = TPTEST_FIRST_PORT;

	if (TpTestOpen(ctx, loopback))
	{
		TpTestRun(ctx);
	}

	TpTestClose(ctx);
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
		Print("TRACEPATH TEST OK\n");
	}
	else
	{
		Print("TRACEPATH TEST FAILED (%u of %u checks failed)\n", ctx->NumFailed, ctx->NumChecks);
	}

	Free(ctx);
}
