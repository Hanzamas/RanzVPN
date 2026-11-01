// vrfpolicytest.c
// Named VRF policy test of vpntest ("vrfpolicy" command, SDN-8 #184)
//
// The policy of the VRFs of a node (Cedar/NodePolicy.c) on the overlay that carries the packets between two nodes
// (NodeOverlay.c), in process, as seam 2 of #45 runs the data plane: fake adapters stand in for the Wintun adapters of
// their hosts, the in-process loopback transport carries their Noise session, the test applies the desired states
// itself (NodeOverlayApply) with the rules that the controller compiles from the Policy resources of the intent
// (controller/internal/desired), and a clock of the test gives the policy its time. node-a has the tag web, node-b the
// tag db; they share VRF default (1), with the starter rule, red (101), whose conntrack quota is 4 flows, and blue (202),
// whose intent gives each protocol a timeout of its own.
// - Starter rule: in VRF default every packet passes, both ways.
// - Default deny: in red, a packet that no rule allows is dropped by the node that sends it.
// - Tag rules: in red, web-to-db lets node-a (web) open TCP flows to node-b (db) on its ports, and the replies pass on
//   the conntrack table without a rule of their own; db opens no flow to web; a deny rule of a lower priority number
//   takes a port of an address out of web-to-db; a rule matches the address of an end as well as its tags.
// - Both ends: in Generation 2 node-a has a rule that node-b does not have: node-b drops the packet that node-a lets out.
// - Quota: a flow of blue stays while node-a opens more flows in red than the conntrack quota of red holds: red's table
//   gives its least recently used flows to the new ones, and blue's table keeps its own.
// - Timeouts: in blue, the flows of each protocol end after the timeout that the intent gives that protocol: a reply
//   within it passes, a reply after it is the first packet of a new flow from db to web, which node-b drops.
// Where each packet goes, the documents of rules that the nodes compiled and their counters match the golden file
// tests/golden/vrfpolicy/vrfpolicy_overlay.txt (golden family "vrfpolicy").
// Print "VRFPOLICY TEST OK" only when every check passes.

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

#define	VPTEST_BUDGET			300000		// The whole test ends within this time, or the watchdog ends the process (ms)
#define	VPTEST_BOUND			10000		// A bounded wait on observable state (ms)
#define	VPTEST_POLL				10			// Poll interval of observable state (ms)
#define	VPTEST_START			1000000		// The time of the clock of the test at the start (ms)
#define	VPTEST_FLOOD			8			// The new flows of red in the quota case
#define	VPTEST_GOLDEN			"vrfpolicy_overlay.txt"

// The VRFs of the test
#define	VPTEST_DEFAULT			0
#define	VPTEST_RED				1
#define	VPTEST_BLUE				2

static UINT vptest_vrf_ids[3] = {1, 101, 202};
static char *vptest_vrf_names[3] = {"default", "red", "blue"};

// node-a and node-b, their tags and their addresses in each VRF
static char *vptest_names[2] = {"node-a", "node-b"};
static char *vptest_tags[2] = {"web", "db"};
static char *vptest_addrs[2][3] =
{
	{"100.64.0.1", "10.0.0.1", "10.0.0.1"},
	{"100.64.0.2", "10.0.0.2", "10.0.0.2"},
};

// The packets of the test
#define	VPTEST_SYN				0			// A TCP SYN
#define	VPTEST_SYNACK			1			// A TCP SYN-ACK
#define	VPTEST_ACK				2			// A TCP ACK
#define	VPTEST_UDP				3			// A UDP datagram
#define	VPTEST_ECHO				4			// An ICMP echo request
#define	VPTEST_REPLY			5			// An ICMP echo reply
#define	VPTEST_GRE				6			// A GRE packet

static char *vptest_kinds[7] = {"TCP SYN", "TCP SYN-ACK", "TCP ACK", "UDP", "ICMP echo", "ICMP echo reply", "GRE"};

// Where a packet goes
#define	VPTEST_DELIVERED		0			// To the host of the other node
#define	VPTEST_DROPPED_SENDER	1			// The node that sends it drops it
#define	VPTEST_DROPPED_RECEIVER	2			// The node that gets it drops it

// One packet of the test: when it is sent (ms after VPTEST_START), in which VRF, by which node, what it is with its
// ports (the id of an ICMP echo in Src), and where it must go
typedef struct VPTEST_STEP
{
	UINT64 Time;
	UINT Vrf;
	UINT From;
	UINT Kind;
	USHORT Src;
	USHORT Dst;
	UINT Expect;
	char *What;
} VPTEST_STEP;

// Generation 1: the starter rule, default deny and the tag rules
static VPTEST_STEP vptest_rules[] =
{
	{0, VPTEST_DEFAULT, 0, VPTEST_ECHO, 1, 0, VPTEST_DELIVERED, "the starter rule lets node-a ping node-b in VRF default"},
	{0, VPTEST_DEFAULT, 1, VPTEST_REPLY, 1, 0, VPTEST_DELIVERED, "the echo reply of node-b comes back"},
	{0, VPTEST_DEFAULT, 1, VPTEST_ECHO, 2, 0, VPTEST_DELIVERED, "the starter rule lets node-b ping node-a too"},
	{0, VPTEST_RED, 0, VPTEST_UDP, 40000, 53, VPTEST_DROPPED_SENDER, "no rule of red lets this UDP through: default deny"},
	{0, VPTEST_RED, 1, VPTEST_SYN, 40001, 80, VPTEST_DROPPED_SENDER, "no rule of red lets node-b open TCP to node-a: default deny"},
	{0, VPTEST_RED, 0, VPTEST_SYN, 40002, 5432, VPTEST_DELIVERED, "web-to-db lets node-a (web) open TCP to node-b (db) on port 5432"},
	{0, VPTEST_RED, 1, VPTEST_SYNACK, 5432, 40002, VPTEST_DELIVERED, "the SYN-ACK of node-b passes on the conntrack table of red, with no rule of its own"},
	{0, VPTEST_RED, 1, VPTEST_SYN, 40003, 5432, VPTEST_DROPPED_SENDER, "web-to-db goes from web to db: node-b (db) opens no flow to node-a (web)"},
	{0, VPTEST_RED, 0, VPTEST_SYN, 40004, 22, VPTEST_DROPPED_SENDER, "port 22 is no port of web-to-db"},
	{0, VPTEST_RED, 0, VPTEST_SYN, 40005, 8080, VPTEST_DROPPED_SENDER, "no-8080 (priority 50, deny) takes port 8080 of the address 10.0.0.2 out of web-to-db"},
	{0, VPTEST_RED, 0, VPTEST_SYN, 40006, 8081, VPTEST_DELIVERED, "port 8081 is in the range 8000-8100 of web-to-db"},
	{0, VPTEST_RED, 1, VPTEST_UDP, 40007, 514, VPTEST_DELIVERED, "db-syslog lets node-b (db) send UDP 514 to the address 10.0.0.1"},
	{0, VPTEST_RED, 0, VPTEST_UDP, 40008, 514, VPTEST_DROPPED_SENDER, "db-syslog goes from db: node-a (web) may not send UDP 514"},
};

// Generation 2: a rule that node-a has and node-b does not
static VPTEST_STEP vptest_ends[] =
{
	{0, VPTEST_RED, 0, VPTEST_UDP, 40009, 9999, VPTEST_DROPPED_RECEIVER, "a-only, a rule of node-a alone, lets UDP 9999 out of node-a; node-b, whose rules let none in, drops it"},
};

// The quota of red: a flow of blue, a flood of new flows in red (VPTEST_FLOOD of them, between the first two), then the
// reply of the flow of blue and the SYN-ACK of the first flow of red
static VPTEST_STEP vptest_quota[] =
{
	{0, VPTEST_BLUE, 0, VPTEST_UDP, 40010, 7000, VPTEST_DELIVERED, "blue-web lets node-a send UDP to node-b in blue: a flow of blue"},
	{0, VPTEST_RED, 0, VPTEST_SYN, 41000, 5432, VPTEST_DELIVERED, "a new TCP flow of red"},
	{0, VPTEST_BLUE, 1, VPTEST_UDP, 7000, 40010, VPTEST_DELIVERED, "the reply of the flow of blue passes: the flows of red took no place of blue's table"},
	{0, VPTEST_RED, 1, VPTEST_SYNACK, 5432, 40002, VPTEST_DROPPED_SENDER, "the flow of port 40002 left red's full table: its SYN-ACK opens a flow from db to web, which node-b drops"},
};

// The timeouts of blue: tcpEstablished 10 s, tcpTransitory 3 s, udp 5 s, icmp 2 s, other 4 s
static VPTEST_STEP vptest_timeouts[] =
{
	{100000, VPTEST_BLUE, 0, VPTEST_UDP, 42000, 5000, VPTEST_DELIVERED, "node-a opens a UDP flow in blue"},
	{100000, VPTEST_BLUE, 0, VPTEST_ECHO, 300, 0, VPTEST_DELIVERED, "node-a opens an ICMP echo flow"},
	{100000, VPTEST_BLUE, 0, VPTEST_GRE, 0, 0, VPTEST_DELIVERED, "node-a opens a GRE flow"},
	{100000, VPTEST_BLUE, 0, VPTEST_SYN, 42001, 443, VPTEST_DELIVERED, "node-a opens a TCP flow"},
	{102500, VPTEST_BLUE, 1, VPTEST_REPLY, 300, 0, VPTEST_DROPPED_SENDER, "2.5 s after the echo its reply is dropped: the ICMP flow ended after icmp, 2 s"},
	{102500, VPTEST_BLUE, 1, VPTEST_SYNACK, 443, 42001, VPTEST_DELIVERED, "the SYN-ACK passes within tcpTransitory, 3 s: the TCP flow is established"},
	{102500, VPTEST_BLUE, 1, VPTEST_GRE, 0, 0, VPTEST_DELIVERED, "GRE passes within other, 4 s"},
	{102500, VPTEST_BLUE, 1, VPTEST_UDP, 5000, 42000, VPTEST_DELIVERED, "UDP passes within udp, 5 s"},
	{107000, VPTEST_BLUE, 1, VPTEST_GRE, 0, 0, VPTEST_DROPPED_SENDER, "4.5 s after its last packet GRE is dropped: other, 4 s"},
	{107000, VPTEST_BLUE, 1, VPTEST_UDP, 5000, 42000, VPTEST_DELIVERED, "UDP passes 4.5 s after its last packet"},
	{107000, VPTEST_BLUE, 1, VPTEST_ACK, 443, 42001, VPTEST_DELIVERED, "TCP passes 4.5 s after its last packet"},
	{113000, VPTEST_BLUE, 1, VPTEST_UDP, 5000, 42000, VPTEST_DROPPED_SENDER, "6 s after its last packet UDP is dropped: udp, 5 s"},
	{113000, VPTEST_BLUE, 1, VPTEST_ACK, 443, 42001, VPTEST_DELIVERED, "TCP passes 6 s after its last packet"},
	{124000, VPTEST_BLUE, 1, VPTEST_ACK, 443, 42001, VPTEST_DROPPED_SENDER, "11 s after its last packet TCP is dropped: tcpEstablished, 10 s"},
	{124000, VPTEST_BLUE, 0, VPTEST_SYN, 42002, 443, VPTEST_DELIVERED, "node-a opens another TCP flow"},
	{127500, VPTEST_BLUE, 1, VPTEST_SYNACK, 443, 42002, VPTEST_DROPPED_SENDER, "3.5 s after its SYN the SYN-ACK is dropped: tcpTransitory, 3 s"},
};

// The checks of the test
typedef struct VPTEST_CTX
{
	UINT NumChecks;
	UINT NumFailed;
} VPTEST_CTX;

// One node of the test and the fake adapter of its host
typedef struct VPTEST_NODE
{
	char *Name;
	wchar_t Dir[MAX_PATH];				// Its data directory
	PEER_KEY Key;						// Its static key
	NODE *Node;
	NODE_READER Reader;					// The test thread as a reader of the node's forwarding tables, online while it sends
	volatile LONG Packets;				// The packets that the adapter took
	volatile LONG Other;				// ... of which in another VRF than the one sent in last
	volatile LONG Vrf;					// The VRF of the packet sent last
} VPTEST_NODE;

// The time of the clock of the test, which both nodes read
static volatile LONG64 vptest_now = VPTEST_START;

static bool VpTestCheck(VPTEST_CTX *ctx, bool ok, char *what, char *fmt, ...) RANZ_PRINTF_FORMAT(4, 5);
static bool VpTestCheck(VPTEST_CTX *ctx, bool ok, char *what, char *fmt, ...)
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
static DWORD WINAPI VpTestWatchdog(LPVOID param)
{
	char msg[MAX_SIZE];
	DWORD written = 0;

	if (WaitForSingleObject((HANDLE)param, VPTEST_BUDGET) != WAIT_TIMEOUT)
	{
		return 0;
	}

	int len = snprintf(msg, sizeof(msg), "VRFPOLICY TEST FAILED (did not finish within %u ms)\n", VPTEST_BUDGET);
	if (len > 0)
	{
		WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), msg, (DWORD)MIN((UINT)len, (UINT)sizeof(msg) - 1), &written, NULL);
	}

	TerminateProcess(GetCurrentProcess(), 1);

	return 0;
}

// The clock of the policy of both nodes
static UINT64 VpTestClock(NODE *n, void *param)
{
	return (UINT64)ReadAcquire64(&vptest_now);
}

// Append a text to the report
static void VpTestWrite(BUF *b, char *s)
{
	WriteBuf(b, s, StrLen(s));
}

// The fake adapter of a host: it counts the packets it takes, and those of another VRF than the one sent in last
static void VpTestAdapter(NODE *n, void *param, UINT vrf_id, const UCHAR *packet, UINT size)
{
	VPTEST_NODE *t = (VPTEST_NODE *)param;

	if ((UINT)InterlockedCompareExchange(&t->Vrf, 0, 0) != vrf_id)
	{
		InterlockedIncrement(&t->Other);
	}
	InterlockedIncrement(&t->Packets);
}

//
// The packets
//

// The IPv4 address of a text in network byte order into addr
static void VpTestAddress(UCHAR *addr, char *str)
{
	IP ip;

	Zero(addr, 4);
	if (StrToIP(&ip, str))
	{
		Copy(addr, IPV4(ip.address), 4);
	}
}

// The IPv4 packet of a step, from the node that sends it to the other one in its VRF: its size
static UINT VpTestPacket(UCHAR *buf, VPTEST_STEP *s)
{
	UCHAR *l4 = buf + 20;
	UINT l4_size = 0;
	UCHAR proto = 0;

	Zero(buf, 64);

	switch (s->Kind)
	{
	case VPTEST_SYN:
	case VPTEST_SYNACK:
	case VPTEST_ACK:
		proto = IP_PROTO_TCP;
		l4_size = 20;
		WRITE_USHORT(l4, s->Src);
		WRITE_USHORT(l4 + 2, s->Dst);
		WRITE_UINT(l4 + 4, 0x1000);
		WRITE_UINT(l4 + 8, (s->Kind == VPTEST_SYN ? 0 : 0x2000));
		l4[12] = (UCHAR)(5 << 4);
		l4[13] = (UCHAR)(s->Kind == VPTEST_SYN ? TCP_SYN : (s->Kind == VPTEST_SYNACK ? TCP_SYN | TCP_ACK : TCP_ACK));
		WRITE_USHORT(l4 + 14, 64240);
		break;

	case VPTEST_UDP:
		proto = IP_PROTO_UDP;
		l4_size = 16;
		WRITE_USHORT(l4, s->Src);
		WRITE_USHORT(l4 + 2, s->Dst);
		WRITE_USHORT(l4 + 4, l4_size);
		break;

	case VPTEST_ECHO:
	case VPTEST_REPLY:
		proto = IP_PROTO_ICMPV4;
		l4_size = 16;
		l4[0] = (UCHAR)(s->Kind == VPTEST_ECHO ? 8 : 0);
		WRITE_USHORT(l4 + 4, s->Src);
		WRITE_USHORT(l4 + 6, 1);
		break;

	default:
		proto = 47;
		l4_size = 4;
		WRITE_USHORT(l4 + 2, 0x0800);
		break;
	}

	UINT size = 20 + l4_size;
	buf[0] = 0x45;
	buf[2] = (UCHAR)(size >> 8);
	buf[3] = (UCHAR)size;
	buf[8] = 64;
	buf[9] = proto;
	VpTestAddress(buf + 12, vptest_addrs[s->From][s->Vrf]);
	VpTestAddress(buf + 16, vptest_addrs[1 - s->From][s->Vrf]);
	USHORT sum = IpChecksum(buf, 20);
	Copy(buf + 10, &sum, 2);

	return size;
}

// The packet of a step as one line of the report: its VRF, its ends and what it is
static void VpTestDescribe(char *str, UINT size, VPTEST_STEP *s)
{
	char ports[64] = "";

	if (s->Kind == VPTEST_ECHO || s->Kind == VPTEST_REPLY)
	{
		Format(ports, sizeof(ports), " id %u", (UINT)s->Src);
	}
	else if (s->Kind != VPTEST_GRE)
	{
		Format(ports, sizeof(ports), " %u > %u", (UINT)s->Src, (UINT)s->Dst);
	}

	Format(str, size, "%s %s %s > %s %s %s%s", vptest_vrf_names[s->Vrf], vptest_names[s->From], vptest_addrs[s->From][s->Vrf],
		vptest_names[1 - s->From], vptest_addrs[1 - s->From][s->Vrf], vptest_kinds[s->Kind], ports);
}

//
// The nodes and their states
//

// A new empty data directory under the temp directory of the process, with a configuration store that runs no role
// on one worker
static void VpTestNewDir(wchar_t *dir, UINT size, char *name)
{
	wchar_t tmp[MAX_PATH];
	wchar_t path[MAX_PATH];

	UniFormat(tmp, sizeof(tmp), L"vrfpolicytest_%S_%u", name, Rand32());
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

// Delete the files of a directory, then the directory (it holds no subdirectory)
static void VpTestDeleteFiles(wchar_t *dir)
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

// A prefix of an end of a rule
static void VpTestPrefix(CONTROL_RULE_END *e, char *addr, UINT length)
{
	CONTROL_PREFIX *p = &e->Prefixes[e->NumPrefixes++];

	VpTestAddress(p->Address, addr);
	p->AddressSize = 4;
	p->Length = length;
}

// A tag of an end of a rule
static void VpTestTag(CONTROL_RULE_END *e, char *tag)
{
	StrCpy(e->Tags[e->NumTags], sizeof(e->Tags[e->NumTags]), tag);
	e->NumTags++;
}

// A rule of a state, with its name, VRF, priority and action
static CONTROL_RULE *VpTestRule(CONTROL_STATE *st, char *name, UINT vrf, UINT priority, bool deny)
{
	CONTROL_RULE *r = &st->Rules[st->NumRules++];

	StrCpy(r->Name, sizeof(r->Name), name);
	r->VrfId = vptest_vrf_ids[vrf];
	r->Priority = priority;
	r->Deny = deny;

	return r;
}

// A range of destination ports of a rule
static void VpTestPorts(CONTROL_RULE *r, UINT first, UINT last)
{
	r->FirstPort[r->NumPorts] = first;
	r->LastPort[r->NumPorts] = last;
	r->NumPorts++;
}

// The rules of the states, as the controller compiles the Policy resources of the intent (in name order): the starter
// rule of default; no-8080, web-to-db and db-syslog of red, with a-only for node-a in Generation 2; blue-web of blue
static void VpTestRules(CONTROL_STATE *st, bool a_only)
{
	CONTROL_RULE *r;

	st->Rules = ZeroMalloc(sizeof(CONTROL_RULE) * 6);

	if (a_only)
	{
		r = VpTestRule(st, "a-only", VPTEST_RED, 200, false);
		VpTestTag(&r->From, "web");
		VpTestTag(&r->To, "db");
		r->Protocol = IP_PROTO_UDP;
		VpTestPorts(r, 9999, 9999);
	}

	r = VpTestRule(st, "blue-web", VPTEST_BLUE, 1000, false);
	VpTestTag(&r->From, "web");

	r = VpTestRule(st, "db-syslog", VPTEST_RED, 1000, false);
	VpTestTag(&r->From, "db");
	VpTestPrefix(&r->To, "10.0.0.1", 32);
	r->Protocol = IP_PROTO_UDP;
	VpTestPorts(r, 514, 514);

	VpTestRule(st, "default-allow-all", VPTEST_DEFAULT, 1000, false);

	r = VpTestRule(st, "no-8080", VPTEST_RED, 50, true);
	VpTestPrefix(&r->To, "10.0.0.2", 32);
	r->Protocol = IP_PROTO_TCP;
	VpTestPorts(r, 8080, 8080);

	r = VpTestRule(st, "web-to-db", VPTEST_RED, 100, false);
	VpTestTag(&r->From, "web");
	VpTestTag(&r->To, "db");
	r->Protocol = IP_PROTO_TCP;
	VpTestPorts(r, 5432, 5432);
	VpTestPorts(r, 8000, 8100);
}

// The VRF v of a state, with its policy as the intent of the test declares it
static void VpTestVrf(CONTROL_VRF *cv, UINT v)
{
	Zero(cv, sizeof(CONTROL_VRF));
	StrCpy(cv->Name, sizeof(cv->Name), vptest_vrf_names[v]);
	cv->Id = vptest_vrf_ids[v];
	cv->Mtu = 1280;
	cv->Policy = true;

	if (v == VPTEST_RED)
	{
		cv->MaxFlows = 4;
	}
	else if (v == VPTEST_BLUE)
	{
		cv->MaxFlows = 1024;
		cv->TcpEstablished = 10;
		cv->TcpTransitory = 3;
		cv->Udp = 5;
		cv->Icmp = 2;
		cv->Other = 4;
	}
}

// The addresses of node i in the three VRFs into a: their number
static UINT VpTestAddresses(UINT i, CONTROL_ADDRESS *a)
{
	for (UINT v = 0;v < 3;v++)
	{
		CONTROL_ADDRESS *c = &a[v];

		Zero(c, sizeof(CONTROL_ADDRESS));
		StrCpy(c->Network, sizeof(c->Network), vptest_vrf_names[v]);
		c->VrfId = vptest_vrf_ids[v];
		VpTestAddress(c->Address, vptest_addrs[i][v]);
		c->AddressSize = 4;
		c->Length = (v == VPTEST_DEFAULT ? 10 : 24);
	}

	return 3;
}

// The desired state of node i at Generation g: itself with its tag, the three VRFs in name order with their policies,
// the other node as its peer with its tag, and the rules; in Generation 2 node-a has a-only
static CONTROL_STATE *VpTestState(VPTEST_NODE *nodes, UINT i, UINT64 g)
{
	CONTROL_STATE *st = ZeroMalloc(sizeof(CONTROL_STATE));
	UINT j = 1 - i;

	st->Generation = g;
	StrCpy(st->Name, sizeof(st->Name), vptest_names[i]);
	st->NumAddresses = VpTestAddresses(i, st->Addresses);
	st->NumTags = 1;
	StrCpy(st->Tags[0], sizeof(st->Tags[0]), vptest_tags[i]);

	// blue, default, red
	st->NumVrfs = 3;
	VpTestVrf(&st->Vrfs[0], VPTEST_BLUE);
	VpTestVrf(&st->Vrfs[1], VPTEST_DEFAULT);
	VpTestVrf(&st->Vrfs[2], VPTEST_RED);

	st->Peers = ZeroMalloc(sizeof(CONTROL_PEER));
	st->NumPeers = 1;
	CONTROL_PEER *p = &st->Peers[0];
	StrCpy(p->Name, sizeof(p->Name), vptest_names[j]);
	Copy(p->Key, nodes[j].Key.Public, PEER_KEY_SIZE);
	p->NumVrfs = 3;
	for (UINT v = 0;v < 3;v++)
	{
		p->VrfIds[v] = vptest_vrf_ids[v];
	}
	p->NumAddresses = VpTestAddresses(j, p->Addresses);
	p->NumTags = 1;
	StrCpy(p->Tags[0], sizeof(p->Tags[0]), vptest_tags[j]);

	VpTestRules(st, (g >= 2 && i == 0));

	return st;
}

static void VpTestFreeState(CONTROL_STATE *st)
{
	Free(st->Rules);
	Free(st->Peers);
	Free(st);
}

// Apply the states of Generation g to both nodes, and write the document of rules that each compiles into the report
static bool VpTestApply(VPTEST_NODE *nodes, UINT64 g, BUF *report)
{
	bool ok = true;

	for (UINT i = 0;i < 2;i++)
	{
		CONTROL_STATE *st = VpTestState(nodes, i, g);
		char *doc = NodePolicyDocument(st);
		char line[MAX_SIZE];

		Format(line, sizeof(line), "the rules of %s in generation %I64u:\n", nodes[i].Name, g);
		VpTestWrite(report, line);
		VpTestWrite(report, (doc != NULL ? doc : "(none)"));
		VpTestWrite(report, "\n");
		Free(doc);

		ok = NodeOverlayApply(nodes[i].Node, st) && ok;
		VpTestFreeState(st);
	}

	return ok;
}

// Whether both nodes have their session to each other within VPTEST_BOUND
static bool VpTestWaitLink(VPTEST_NODE *nodes)
{
	UINT64 end = Tick64() + VPTEST_BOUND;

	while (true)
	{
		bool all = true;

		for (UINT i = 0;i < 2;i++)
		{
			NODE_OVERLAY_STATUS st;

			NodeOverlayGetStatus(nodes[i].Node, &st);
			if (st.NumPeers != 1 || st.NumLinks != 1)
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
		SleepThread(VPTEST_POLL);
	}
}

// The packets that the overlay of node i dropped
static UINT64 VpTestDropped(VPTEST_NODE *t)
{
	NODE_OVERLAY_STATUS st;

	NodeOverlayGetStatus(t->Node, &st);

	return st.Dropped;
}

// Send the packet of a step and find where it went within VPTEST_BOUND: VPTEST_DELIVERED, VPTEST_DROPPED_SENDER,
// VPTEST_DROPPED_RECEIVER, or INFINITE when it went nowhere or into another VRF
static UINT VpTestSend(VPTEST_NODE *nodes, VPTEST_STEP *s)
{
	VPTEST_NODE *from = &nodes[s->From], *to = &nodes[1 - s->From];
	UCHAR packet[128];
	UINT size = VpTestPacket(packet, s);
	UINT vrf_id = vptest_vrf_ids[s->Vrf];
	LONG packets = InterlockedCompareExchange(&to->Packets, 0, 0);
	UINT64 dropped_from = VpTestDropped(from), dropped_to = VpTestDropped(to);

	InterlockedExchange64(&vptest_now, (LONG64)(VPTEST_START + s->Time));
	InterlockedExchange(&to->Vrf, (LONG)vrf_id);

	NodeReaderOnline(from->Node, &from->Reader);
	NodeOverlayInput(from->Node, vrf_id, packet, size);
	NodeReaderOffline(&from->Reader);

	for (UINT64 end = Tick64() + VPTEST_BOUND;Tick64() < end;SleepThread(1))
	{
		if (InterlockedCompareExchange(&to->Packets, 0, 0) != packets)
		{
			return (InterlockedCompareExchange(&to->Other, 0, 0) == 0 ? VPTEST_DELIVERED : INFINITE);
		}
		if (VpTestDropped(from) != dropped_from)
		{
			return VPTEST_DROPPED_SENDER;
		}
		if (VpTestDropped(to) != dropped_to)
		{
			return VPTEST_DROPPED_RECEIVER;
		}
	}

	return INFINITE;
}

// The packets of the steps: each is sent, and where it went goes into the report and is checked
static void VpTestSteps(VPTEST_CTX *ctx, VPTEST_NODE *nodes, VPTEST_STEP *steps, UINT num, BUF *report)
{
	for (UINT k = 0;k < num;k++)
	{
		VPTEST_STEP *s = &steps[k];
		char desc[MAX_SIZE], line[MAX_SIZE * 2], outcome[MAX_SIZE];
		UINT got = VpTestSend(nodes, s);

		VpTestDescribe(desc, sizeof(desc), s);
		switch (got)
		{
		case VPTEST_DELIVERED:
			Format(outcome, sizeof(outcome), "delivered to %s", vptest_names[1 - s->From]);
			break;
		case VPTEST_DROPPED_SENDER:
			Format(outcome, sizeof(outcome), "dropped by %s", vptest_names[s->From]);
			break;
		case VPTEST_DROPPED_RECEIVER:
			Format(outcome, sizeof(outcome), "dropped by %s", vptest_names[1 - s->From]);
			break;
		default:
			StrCpy(outcome, sizeof(outcome), "lost");
			break;
		}

		Format(line, sizeof(line), "t+%I64u.%03I64u %s: %s\n", s->Time / 1000, s->Time % 1000, desc, outcome);
		VpTestWrite(report, line);

		Format(line, sizeof(line), "%s (%s)", s->What, desc);
		VpTestCheck(ctx, got == s->Expect, line, "%s", outcome);
	}
}

// The quota case: the flow of blue, VPTEST_FLOOD new flows of red, then the reply of blue and the SYN-ACK of red
static void VpTestQuota(VPTEST_CTX *ctx, VPTEST_NODE *nodes, BUF *report)
{
	VPTEST_STEP flood[VPTEST_FLOOD];

	VpTestSteps(ctx, nodes, &vptest_quota[0], 1, report);
	for (UINT i = 0;i < VPTEST_FLOOD;i++)
	{
		flood[i] = vptest_quota[1];
		flood[i].Src = (USHORT)(vptest_quota[1].Src + i);
	}
	VpTestSteps(ctx, nodes, flood, VPTEST_FLOOD, report);
	VpTestSteps(ctx, nodes, &vptest_quota[2], 2, report);

	for (UINT i = 0;i < 2;i++)
	{
		NODE_POLICY_VRF_STATUS red, blue;
		char what[MAX_SIZE];
		bool got_red = NodePolicyGetVrf(nodes[i].Node, "red", &red), got_blue = NodePolicyGetVrf(nodes[i].Node, "blue", &blue);

		Format(what, sizeof(what), "%s: red's table holds its quota of 4 flows and gave its least recently used flows to new ones; blue's table, of 1024, gave none", nodes[i].Name);
		VpTestCheck(ctx, got_red && got_blue && red.MaxFlows == 4 && red.Flows == 4 && red.Evicted != 0 && blue.MaxFlows == 1024 && blue.Evicted == 0, what,
			"red %u of %u flows, %I64u evicted; blue %u of %u flows, %I64u evicted", red.Flows, red.MaxFlows, red.Evicted, blue.Flows, blue.MaxFlows, blue.Evicted);
	}
}

// The counters of the policy of each node, as the CLI shows them, into the report
static void VpTestCounters(VPTEST_CTX *ctx, VPTEST_NODE *nodes, BUF *report)
{
	for (UINT i = 0;i < 2;i++)
	{
		char *text = NodePolicyCountersText(nodes[i].Node);
		char line[MAX_SIZE];
		NODE_POLICY_VRF_STATUS def;
		char what[MAX_SIZE];

		Format(line, sizeof(line), "the policy of %s:\n", nodes[i].Name);
		VpTestWrite(report, line);
		VpTestWrite(report, (text != NULL ? text : "(none)\n"));
		Free(text);

		Format(what, sizeof(what), "%s: VRF default has the quota of a VRF that declares none, 65536 flows, and its 3 members", nodes[i].Name);
		bool got = NodePolicyGetVrf(nodes[i].Node, "default", &def);
		VpTestCheck(ctx, got && def.MaxFlows == 65536 && def.NumMembers == 3 && def.NumRules == 1, what, "found %u, %u flows at most, %u members, %u rules",
			(UINT)got, def.MaxFlows, def.NumMembers, def.NumRules);
	}
}

// vrfpolicy: the policy of the VRFs of two nodes on the overlay
RANZ_TEST("vrfpolicy", vrfpolicy_test, "VRF policy of the overlay: the starter rule, default deny, tag and address rules enforced at both ends with replies on the conntrack table, a conntrack quota per VRF and the timeouts of each protocol (golden family vrfpolicy).");
void vrfpolicy_test(UINT num, char **arg)
{
	VPTEST_CTX ctx;
	VPTEST_NODE *nodes = ZeroMalloc(sizeof(VPTEST_NODE) * 2);
	TRANSPORT *loopback = TransportLoopbackNew("loopback", 0, false);
	HANDLE done = CreateEventW(NULL, TRUE, FALSE, NULL);
	HANDLE watchdog = (done != NULL ? CreateThread(NULL, 0, VpTestWatchdog, done, 0, NULL) : NULL);
	UCHAR scalar[PEER_KEY_SIZE];
	char what[MAX_SIZE];
	BUF *report = NewBuf();
	bool started = (loopback != NULL);

	Zero(&ctx, sizeof(ctx));

	Print("VRF policy test: the starter rule, default deny, tag rules at both ends, the conntrack quota of a VRF and the timeouts of each protocol\n");

	// The nodes, each with its static key (the scalars 1, 2, ... of the conformance tests), the fake adapter of its host
	// and the clock of the test, and their overlays without a control stream
	for (UINT i = 0;i < 2 && started;i++)
	{
		VPTEST_NODE *t = &nodes[i];
		NODE_OVERLAY_CONFIG c;

		t->Name = vptest_names[i];
		for (UINT j = 0;j < PEER_KEY_SIZE;j++)
		{
			scalar[j] = (UCHAR)(1 + PEER_KEY_SIZE * i + j);
		}
		started = PeerKeyFromScalar(&t->Key, scalar);

		VpTestNewDir(t->Dir, sizeof(t->Dir), t->Name);
		t->Node = NewNode(t->Dir);
		NodeStart(t->Node);
		NodeReaderRegister(t->Node, &t->Reader);
		NodeReaderOffline(&t->Reader);

		Zero(&c, sizeof(c));
		c.Data = loopback;
		c.Key = &t->Key;
		c.Adapter = VpTestAdapter;
		c.AdapterParam = t;
		c.Clock = VpTestClock;
		Format(what, sizeof(what), "%s: its overlay runs without a control stream", t->Name);
		started = VpTestCheck(&ctx, started && NodeOverlayStart(t->Node, &c), what, "NodeOverlayStart failed") && started;
	}
	Zero(scalar, sizeof(scalar));

	if (started)
	{
		bool applied = VpTestApply(nodes, 1, report);
		bool linked = VpTestWaitLink(nodes);
		started = VpTestCheck(&ctx, applied && linked, "Both nodes apply Generation 1 of VRFs default, red and blue with their rules, and their session is up",
			"applied %u, linked %u", (UINT)applied, (UINT)linked);
	}

	if (started)
	{
		VpTestSteps(&ctx, nodes, vptest_rules, sizeof(vptest_rules) / sizeof(vptest_rules[0]), report);

		VpTestWrite(report, "generation 2: node-a has the rule a-only, which node-b does not have\n");
		VpTestCheck(&ctx, VpTestApply(nodes, 2, report), "Both nodes apply Generation 2", "not applied");
		VpTestSteps(&ctx, nodes, vptest_ends, sizeof(vptest_ends) / sizeof(vptest_ends[0]), report);

		VpTestQuota(&ctx, nodes, report);
		VpTestSteps(&ctx, nodes, vptest_timeouts, sizeof(vptest_timeouts) / sizeof(vptest_timeouts[0]), report);
		VpTestCounters(&ctx, nodes, report);

		HARNESS h;
		char out_dir[MAX_SIZE], golden_dir[MAX_SIZE];
		bool update = false;

		HarnessGetFamilyDirs("vrfpolicy", out_dir, sizeof(out_dir), golden_dir, sizeof(golden_dir), &update);
		MakeDirEx(out_dir);
		Print("VRFPOLICY GOLDEN MODE %s\n", update ? "update" : "compare");
		Print("  golden directory: %s\n", golden_dir);

		char *text = HarnessBufToStr(report);
		Zero(&h, sizeof(h));
		HarnessCompareGolden(&h, out_dir, golden_dir, VPTEST_GOLDEN, text, update);
		Free(text);
		VpTestCheck(&ctx, h.NumFail == 0, "Where each packet went, the documents of rules and the counters of both nodes match the golden file " VPTEST_GOLDEN, "it differs");
	}

	// The nodes stop, every thread is joined
	for (UINT i = 0;i < 2;i++)
	{
		VPTEST_NODE *t = &nodes[i];
		wchar_t log_dir[MAX_PATH];

		if (t->Node != NULL)
		{
			NodeReaderUnregister(t->Node, &t->Reader);
			NodeStop(t->Node);
			FreeNode(t->Node);
			ConbinePathW(log_dir, sizeof(log_dir), t->Dir, NODE_LOG_DIR_NAME);
			VpTestDeleteFiles(log_dir);
			VpTestDeleteFiles(t->Dir);
		}
		PeerKeyClose(&t->Key);
	}

	FreeBuf(report);
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
		Print("VRFPOLICY TEST OK\n");
	}
	else
	{
		Print("VRFPOLICY TEST FAILED (%u of %u checks failed)\n", ctx.NumFailed, ctx.NumChecks);
	}
}
