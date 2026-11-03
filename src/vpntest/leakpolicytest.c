// leakpolicytest.c
// Named test of the policy of leaked traffic of vpntest ("leakpolicy" command, SDN-8 #184 on SDN-7 #183)
//
// Policy applies to leaked traffic (ADR-0029 decision 6, ADR-0025 decision 8): a leak is reachability, not a firewall
// bypass. In process, as seam 2 of #45 runs the data plane (leaktest.c, vrfpolicytest.c): fake adapters stand in for
// the Wintun adapters of the hosts, the in-process loopback transport carries the Noise session of the two nodes, and
// the test applies their desired states itself (NodeOverlayApply) as the controller compiles them
// (controller/internal/desired, leak.go and policy.go). node-s of VRF shared (tag dns) and node-r of VRF red (tag app)
// share no VRF; shared and red leak into each other, as the route targets of a two-way leak make them, so each node has
// the other as its peer with the route that the VRF of the other leaks into its own. Both VRFs have their policy:
// shared-allow-all lets every flow of shared pass, as the starter rule does in VRF default, so node-s lets out whatever
// it sends; red has the rules of the test. node-r judges a packet that comes in on a leaked route in red, as a packet of
// the end outside the VRF, which has no tag (Cedar/NodePolicy.c): the rules of red name its addresses.
// - An allow rule of red lets the leaked traffic of the addresses of shared in, and the answers of node-r go back on
//   the conntrack tables of red and shared.
// - A deny rule of red, of a lower priority number than the allow rule that matches the same packet, drops it at
//   node-r after node-s let it out; so does default deny, for a packet that no rule of red allows.
// - On the way out of red default deny holds as well: no rule of red lets node-r open a flow into shared.
// - Generation 2 adds no-shared, a deny rule for every flow from shared: node-r drops the next packet of the flow that
//   an allow rule let in, as the new rules judge it again, and a new flow.
// The policy of each node counts what it dropped: node-r every packet of the test that was dropped, node-s none.
// Print "LEAKPOLICY TEST OK" only when every check passes.

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

#define	LPTEST_BUDGET			120000		// The whole test ends within this time, or the watchdog ends the process (ms)
#define	LPTEST_BOUND			10000		// A bounded wait on observable state (ms)
#define	LPTEST_POLL				10			// Poll interval of observable state (ms)
#define	LPTEST_PACKET			64			// The bytes of the buffer of a test packet
#define	LPTEST_SHARED_NET		"10.10.0.0"	// The Network of shared, /24: the rules of red name its addresses

// The two nodes, each the only member of its VRF
#define	LPTEST_S				0			// node-s of VRF shared
#define	LPTEST_R				1			// node-r of VRF red

static char *lptest_names[2] = {"node-s", "node-r"};
static char *lptest_tags[2] = {"dns", "app"};
static UINT lptest_vrf_ids[2] = {10, 1};
static char *lptest_vrf_names[2] = {"shared", "red"};
static char *lptest_addrs[2] = {"10.10.0.1", "10.1.0.1"};

// The packets of the test
#define	LPTEST_UDP				0			// A UDP datagram
#define	LPTEST_SYN				1			// A TCP SYN
#define	LPTEST_SYNACK			2			// A TCP SYN-ACK

static char *lptest_kinds[3] = {"UDP", "TCP SYN", "TCP SYN-ACK"};

// Where a packet goes
#define	LPTEST_DELIVERED		0			// To the host of the other node
#define	LPTEST_DROPPED_SENDER	1			// The node that sends it drops it
#define	LPTEST_DROPPED_RECEIVER	2			// The node that gets it drops it

// One packet of the test: the node that sends it in its VRF to the address of the other node, which a leaked route
// leads to, what it is with its ports, and where it must go
typedef struct LPTEST_STEP
{
	UINT From;
	UINT Kind;
	USHORT Src;
	USHORT Dst;
	UINT Expect;
	char *What;
} LPTEST_STEP;

// Generation 1: the rules of red judge the traffic that the leaks carry between shared and red
static LPTEST_STEP lptest_rules[] =
{
	{LPTEST_S, LPTEST_UDP, 40000, 53, LPTEST_DELIVERED, "node-s sends DNS to node-r over the route that red leaks into shared: shared-dns, an allow rule of red, lets it in"},
	{LPTEST_R, LPTEST_UDP, 53, 40000, LPTEST_DELIVERED, "the answer of node-r goes back over the route that shared leaks into red and passes on the conntrack tables of red and shared"},
	{LPTEST_S, LPTEST_UDP, 40001, 123, LPTEST_DROPPED_RECEIVER, "no rule of red lets UDP 123 from shared in: node-r drops the leaked packet that node-s let out, default deny"},
	{LPTEST_S, LPTEST_SYN, 40002, 22, LPTEST_DELIVERED, "shared-tcp, an allow rule of red, lets node-s open TCP to node-r"},
	{LPTEST_R, LPTEST_SYNACK, 22, 40002, LPTEST_DELIVERED, "the SYN-ACK of node-r passes on the conntrack tables of red and shared"},
	{LPTEST_S, LPTEST_SYN, 40003, 23, LPTEST_DROPPED_RECEIVER, "no-telnet, a deny rule of red of priority 50, drops the leaked TCP 23 that shared-tcp allows too"},
	{LPTEST_R, LPTEST_UDP, 40004, 53, LPTEST_DROPPED_SENDER, "no rule of red lets node-r open a flow into shared: the policy of red judges leaked traffic on its way out too"},
};

// Generation 2: no-shared, a deny rule for every flow from shared, joins the rules of red
static LPTEST_STEP lptest_deny[] =
{
	{LPTEST_S, LPTEST_UDP, 40000, 53, LPTEST_DROPPED_RECEIVER, "no-shared ends the flow that shared-dns let in: the new rules judge it again on its next packet, which node-r drops"},
	{LPTEST_S, LPTEST_SYN, 40005, 22, LPTEST_DROPPED_RECEIVER, "no-shared drops a new leaked flow that shared-tcp would let in"},
};

// The checks of the test
typedef struct LPTEST_CTX
{
	UINT NumChecks;
	UINT NumFailed;
} LPTEST_CTX;

// One node of the test and the fake adapter of its host
typedef struct LPTEST_NODE
{
	char *Name;
	wchar_t Dir[MAX_PATH];				// Its data directory
	PEER_KEY Key;						// Its static key
	NODE *Node;
	NODE_READER Reader;					// The test thread as a reader of the node's forwarding tables, online while it sends
	volatile LONG Packets;				// The packets that the adapter took
	volatile LONG Other;				// ... of which in another VRF than the one that the test expects
	volatile LONG Vrf;					// The VRF that the test expects the next packet in
} LPTEST_NODE;

static bool LpTestCheck(LPTEST_CTX *ctx, bool ok, char *what, char *fmt, ...) RANZ_PRINTF_FORMAT(4, 5);
static bool LpTestCheck(LPTEST_CTX *ctx, bool ok, char *what, char *fmt, ...)
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
static DWORD WINAPI LpTestWatchdog(LPVOID param)
{
	char msg[MAX_SIZE];
	DWORD written = 0;

	if (WaitForSingleObject((HANDLE)param, LPTEST_BUDGET) != WAIT_TIMEOUT)
	{
		return 0;
	}

	int len = snprintf(msg, sizeof(msg), "LEAKPOLICY TEST FAILED (did not finish within %u ms)\n", LPTEST_BUDGET);
	if (len > 0)
	{
		WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), msg, (DWORD)MIN((UINT)len, (UINT)sizeof(msg) - 1), &written, NULL);
	}

	TerminateProcess(GetCurrentProcess(), 1);

	return 0;
}

// The fake adapter of a host: it counts the packets it takes, and those of another VRF than the one that the test
// expects
static void LpTestAdapter(NODE *n, void *param, UINT vrf_id, const UCHAR *packet, UINT size)
{
	LPTEST_NODE *t = (LPTEST_NODE *)param;

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
static void LpTestAddress(UCHAR *addr, char *str)
{
	IP ip;

	Zero(addr, 4);
	if (StrToIP(&ip, str))
	{
		Copy(addr, IPV4(ip.address), 4);
	}
}

// The IPv4 packet of a step, from the address of the node that sends it to the address of the other node: its size
static UINT LpTestPacket(UCHAR *buf, LPTEST_STEP *s)
{
	UCHAR *l4 = buf + 20;
	UINT l4_size = 16;
	UCHAR proto = IP_PROTO_UDP;

	Zero(buf, LPTEST_PACKET);

	WRITE_USHORT(l4, s->Src);
	WRITE_USHORT(l4 + 2, s->Dst);
	if (s->Kind == LPTEST_UDP)
	{
		WRITE_USHORT(l4 + 4, l4_size);
	}
	else
	{
		proto = IP_PROTO_TCP;
		l4_size = 20;
		WRITE_UINT(l4 + 4, 0x1000);
		WRITE_UINT(l4 + 8, (s->Kind == LPTEST_SYN ? 0 : 0x2000));
		l4[12] = (UCHAR)(5 << 4);
		l4[13] = (UCHAR)(s->Kind == LPTEST_SYN ? TCP_SYN : TCP_SYN | TCP_ACK);
		WRITE_USHORT(l4 + 14, 64240);
	}

	UINT size = 20 + l4_size;
	buf[0] = 0x45;
	buf[2] = (UCHAR)(size >> 8);
	buf[3] = (UCHAR)size;
	buf[8] = 64;
	buf[9] = proto;
	LpTestAddress(buf + 12, lptest_addrs[s->From]);
	LpTestAddress(buf + 16, lptest_addrs[1 - s->From]);
	USHORT sum = IpChecksum(buf, 20);
	Copy(buf + 10, &sum, 2);

	return size;
}

//
// The nodes and their states
//

// A new empty data directory under the temp directory of the process, with a configuration store that runs no role
// on one worker
static void LpTestNewDir(wchar_t *dir, UINT size, char *name)
{
	wchar_t tmp[MAX_PATH];
	wchar_t path[MAX_PATH];

	UniFormat(tmp, sizeof(tmp), L"leakpolicytest_%S_%u", name, Rand32());
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
static void LpTestDeleteFiles(wchar_t *dir)
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

// A rule of the VRF of node i, with its name, priority and action
static CONTROL_RULE *LpTestRule(CONTROL_STATE *st, UINT i, char *name, UINT priority, bool deny)
{
	CONTROL_RULE *r = &st->Rules[st->NumRules++];

	StrCpy(r->Name, sizeof(r->Name), name);
	r->VrfId = lptest_vrf_ids[i];
	r->Priority = priority;
	r->Deny = deny;

	return r;
}

// The Network of shared as the From end of a rule of red: the addresses of the traffic that shared sends into red
static void LpTestFromShared(CONTROL_RULE *r)
{
	CONTROL_PREFIX *p = &r->From.Prefixes[r->From.NumPrefixes++];

	LpTestAddress(p->Address, LPTEST_SHARED_NET);
	p->AddressSize = 4;
	p->Length = 24;
}

// The tag of node-r as the To end of a rule of red
static void LpTestToApp(CONTROL_RULE *r)
{
	StrCpy(r->To.Tags[r->To.NumTags], sizeof(r->To.Tags[r->To.NumTags]), lptest_tags[LPTEST_R]);
	r->To.NumTags++;
}

// A destination port of a rule
static void LpTestPort(CONTROL_RULE *r, UINT port)
{
	r->FirstPort[r->NumPorts] = port;
	r->LastPort[r->NumPorts] = port;
	r->NumPorts++;
}

// The rules of node i at Generation g, in name order, as the controller compiles the Policy resources of the intent:
// for node-s shared-allow-all, which lets every flow of shared pass as the starter rule does in VRF default; for node-r
// the rules of red, no-telnet, shared-dns and shared-tcp, with no-shared from Generation 2
static void LpTestRules(CONTROL_STATE *st, UINT i, UINT64 g)
{
	CONTROL_RULE *r;

	st->Rules = ZeroMalloc(sizeof(CONTROL_RULE) * 4);

	if (i == LPTEST_S)
	{
		LpTestRule(st, i, "shared-allow-all", 1000, false);
		return;
	}

	if (g >= 2)
	{
		r = LpTestRule(st, i, "no-shared", 10, true);
		LpTestFromShared(r);
	}

	r = LpTestRule(st, i, "no-telnet", 50, true);
	LpTestFromShared(r);
	r->Protocol = IP_PROTO_TCP;
	LpTestPort(r, 23);

	r = LpTestRule(st, i, "shared-dns", 1000, false);
	LpTestFromShared(r);
	LpTestToApp(r);
	r->Protocol = IP_PROTO_UDP;
	LpTestPort(r, 53);

	r = LpTestRule(st, i, "shared-tcp", 1000, false);
	LpTestFromShared(r);
	LpTestToApp(r);
	r->Protocol = IP_PROTO_TCP;
}

// The desired state of node i at Generation g, as the controller compiles it: its address and its tag, its VRF with its
// policy, and the other node as its peer with the tag of that node, which shares no VRF with node i and so has no
// address in one, and the route that the VRF of that node leaks into the VRF of node i; then the rules
static CONTROL_STATE *LpTestState(LPTEST_NODE *nodes, UINT i, UINT64 g)
{
	CONTROL_STATE *st = ZeroMalloc(sizeof(CONTROL_STATE));
	UINT j = 1 - i;

	st->Generation = g;
	StrCpy(st->Name, sizeof(st->Name), lptest_names[i]);
	st->NumTags = 1;
	StrCpy(st->Tags[0], sizeof(st->Tags[0]), lptest_tags[i]);

	st->NumAddresses = 1;
	CONTROL_ADDRESS *a = &st->Addresses[0];
	StrCpy(a->Network, sizeof(a->Network), lptest_vrf_names[i]);
	a->VrfId = lptest_vrf_ids[i];
	LpTestAddress(a->Address, lptest_addrs[i]);
	a->AddressSize = 4;
	a->Length = 24;

	st->NumVrfs = 1;
	CONTROL_VRF *cv = &st->Vrfs[0];
	StrCpy(cv->Name, sizeof(cv->Name), lptest_vrf_names[i]);
	cv->Id = lptest_vrf_ids[i];
	cv->Mtu = 1280;
	cv->Policy = true;

	st->Peers = ZeroMalloc(sizeof(CONTROL_PEER));
	st->NumPeers = 1;
	CONTROL_PEER *p = &st->Peers[0];
	StrCpy(p->Name, sizeof(p->Name), lptest_names[j]);
	Copy(p->Key, nodes[j].Key.Public, PEER_KEY_SIZE);
	p->NumTags = 1;
	StrCpy(p->Tags[0], sizeof(p->Tags[0]), lptest_tags[j]);

	// The address of the other node, as a host route, leaks from its VRF into the VRF of node i
	p->NumRoutes = 1;
	CONTROL_ROUTE *r = &p->Routes[0];
	r->VrfId = lptest_vrf_ids[i];
	LpTestAddress(r->Address, lptest_addrs[j]);
	r->AddressSize = 4;
	r->Length = 32;
	r->PeerVrfId = lptest_vrf_ids[j];

	LpTestRules(st, i, g);

	return st;
}

static void LpTestFreeState(CONTROL_STATE *st)
{
	Free(st->Rules);
	Free(st->Peers);
	Free(st);
}

// Apply the states of Generation g to both nodes, with the document of rules that each compiles in the output, and wait
// until both run it and have their session to each other
static bool LpTestApply(LPTEST_NODE *nodes, UINT64 g)
{
	bool applied = true;

	for (UINT i = 0;i < 2;i++)
	{
		CONTROL_STATE *st = LpTestState(nodes, i, g);
		char *doc = NodePolicyDocument(st);

		Print("  [INFO] the rules of %s in generation %I64u: %s\n", nodes[i].Name, g, (doc != NULL ? doc : "(none)"));
		Free(doc);

		applied = NodeOverlayApply(nodes[i].Node, st) && applied;
		LpTestFreeState(st);
	}

	UINT64 end = Tick64() + LPTEST_BOUND;
	while (applied)
	{
		bool all = true;

		for (UINT i = 0;i < 2;i++)
		{
			NODE_OVERLAY_STATUS st;

			NodeOverlayGetStatus(nodes[i].Node, &st);
			if (st.Generation != g || st.NumPeers != 1 || st.NumLinks != 1)
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
		SleepThread(LPTEST_POLL);
	}

	return false;
}

// The packets that the overlay of a node dropped
static UINT64 LpTestDropped(LPTEST_NODE *t)
{
	NODE_OVERLAY_STATUS st;

	NodeOverlayGetStatus(t->Node, &st);

	return st.Dropped;
}

// Send the packet of a step and find where it went within LPTEST_BOUND: LPTEST_DELIVERED, LPTEST_DROPPED_SENDER,
// LPTEST_DROPPED_RECEIVER, or INFINITE when it went nowhere or into another VRF than the one of the host that took it
static UINT LpTestSend(LPTEST_NODE *nodes, LPTEST_STEP *s)
{
	LPTEST_NODE *from = &nodes[s->From], *to = &nodes[1 - s->From];
	UCHAR packet[LPTEST_PACKET];
	UINT size = LpTestPacket(packet, s);
	LONG packets = InterlockedCompareExchange(&to->Packets, 0, 0);
	UINT64 dropped_from = LpTestDropped(from), dropped_to = LpTestDropped(to);

	// The host that takes the packet takes it in its own VRF: a leaked route leads into the VRF that leaked it
	InterlockedExchange(&to->Vrf, (LONG)lptest_vrf_ids[1 - s->From]);

	NodeReaderOnline(from->Node, &from->Reader);
	NodeOverlayInput(from->Node, lptest_vrf_ids[s->From], packet, size);
	NodeReaderOffline(&from->Reader);

	for (UINT64 end = Tick64() + LPTEST_BOUND;Tick64() < end;SleepThread(1))
	{
		if (InterlockedCompareExchange(&to->Packets, 0, 0) != packets)
		{
			return (InterlockedCompareExchange(&to->Other, 0, 0) == 0 ? LPTEST_DELIVERED : INFINITE);
		}
		if (LpTestDropped(from) != dropped_from)
		{
			return LPTEST_DROPPED_SENDER;
		}
		if (LpTestDropped(to) != dropped_to)
		{
			return LPTEST_DROPPED_RECEIVER;
		}
	}

	return INFINITE;
}

// The packets of the steps: each is sent, and where it went is checked
static void LpTestSteps(LPTEST_CTX *ctx, LPTEST_NODE *nodes, LPTEST_STEP *steps, UINT num)
{
	for (UINT k = 0;k < num;k++)
	{
		LPTEST_STEP *s = &steps[k];
		char what[MAX_SIZE * 2], outcome[MAX_SIZE];
		UINT got = LpTestSend(nodes, s);

		switch (got)
		{
		case LPTEST_DELIVERED:
			Format(outcome, sizeof(outcome), "delivered to %s", lptest_names[1 - s->From]);
			break;
		case LPTEST_DROPPED_SENDER:
			Format(outcome, sizeof(outcome), "dropped by %s", lptest_names[s->From]);
			break;
		case LPTEST_DROPPED_RECEIVER:
			Format(outcome, sizeof(outcome), "dropped by %s", lptest_names[1 - s->From]);
			break;
		default:
			StrCpy(outcome, sizeof(outcome), "lost, or taken in another VRF");
			break;
		}

		Format(what, sizeof(what), "%s (%s %s:%u > %s:%u)", s->What, lptest_kinds[s->Kind], lptest_addrs[s->From], (UINT)s->Src,
			lptest_addrs[1 - s->From], (UINT)s->Dst);
		LpTestCheck(ctx, got == s->Expect, what, "%s", outcome);
	}
}

// The packets of the steps that node-r drops: those of node-s that its policy keeps out of red, and its own that the
// policy keeps in
static UINT LpTestDroppedByR(LPTEST_STEP *steps, UINT num)
{
	UINT ret = 0;

	for (UINT k = 0;k < num;k++)
	{
		if ((steps[k].From == LPTEST_S && steps[k].Expect == LPTEST_DROPPED_RECEIVER) || (steps[k].From == LPTEST_R && steps[k].Expect == LPTEST_DROPPED_SENDER))
		{
			ret++;
		}
	}

	return ret;
}

// The policy of each node after the steps: the VRF of each has its rules and two members, the host and the end outside
// the VRF, which the other node is to it; node-r's policy dropped every packet that the steps dropped, node-s's none
static void LpTestPolicies(LPTEST_CTX *ctx, LPTEST_NODE *nodes)
{
	UINT by_r = LpTestDroppedByR(lptest_rules, sizeof(lptest_rules) / sizeof(lptest_rules[0])) +
		LpTestDroppedByR(lptest_deny, sizeof(lptest_deny) / sizeof(lptest_deny[0]));

	for (UINT i = 0;i < 2;i++)
	{
		NODE_POLICY_VRF_STATUS vs;
		char what[MAX_SIZE];
		UINT rules = (i == LPTEST_S ? 1 : 4);
		UINT64 dropped = (i == LPTEST_S ? 0 : by_r);
		bool got = NodePolicyGetVrf(nodes[i].Node, lptest_vrf_names[i], &vs);

		Format(what, sizeof(what), "%s: %s has its %u rules and two members, the host and the end outside the VRF, which the other node is; its policy dropped %I64u packets",
			nodes[i].Name, lptest_vrf_names[i], rules, dropped);
		LpTestCheck(ctx, got && vs.NumRules == rules && vs.NumMembers == 2 && vs.Dropped == dropped, what, "found %u, %u rules, %u members, %I64u packets dropped",
			(UINT)got, vs.NumRules, vs.NumMembers, vs.Dropped);
	}
}

// leakpolicy: the policy of the VRF that leaked traffic goes into judges it
RANZ_TEST("leakpolicy", leakpolicy_test, "Policy of leaked traffic: a route that one VRF leaks into another leaves the traffic under the policy of the VRF it goes into; an allow rule lets it pass with its answers on the conntrack tables, a deny rule and default deny drop it, default deny holds on the way out, and a deny rule of a later Generation ends a leaked flow.");
void leakpolicy_test(UINT num, char **arg)
{
	LPTEST_CTX ctx;
	LPTEST_NODE *nodes = ZeroMalloc(sizeof(LPTEST_NODE) * 2);
	TRANSPORT *loopback = TransportLoopbackNew("loopback", 0, false);
	HANDLE done = CreateEventW(NULL, TRUE, FALSE, NULL);
	HANDLE watchdog = (done != NULL ? CreateThread(NULL, 0, LpTestWatchdog, done, 0, NULL) : NULL);
	UCHAR scalar[PEER_KEY_SIZE];
	char what[MAX_SIZE];
	bool started = (loopback != NULL);

	Zero(&ctx, sizeof(ctx));

	Print("Leaked traffic policy test: shared and red leak into each other, and the policy of the VRF that the traffic goes into judges it\n");

	// The nodes, each with its static key, the fake adapter of its host, and its overlay without a control stream
	for (UINT i = 0;i < 2 && started;i++)
	{
		LPTEST_NODE *t = &nodes[i];
		NODE_OVERLAY_CONFIG c;

		t->Name = lptest_names[i];
		for (UINT j = 0;j < PEER_KEY_SIZE;j++)
		{
			scalar[j] = (UCHAR)(13 + PEER_KEY_SIZE * i + j);
		}
		started = PeerKeyFromScalar(&t->Key, scalar);

		LpTestNewDir(t->Dir, sizeof(t->Dir), t->Name);
		t->Node = NewNode(t->Dir);
		NodeStart(t->Node);
		NodeReaderRegister(t->Node, &t->Reader);
		NodeReaderOffline(&t->Reader);

		Zero(&c, sizeof(c));
		c.Data = loopback;
		c.Key = &t->Key;
		c.Adapter = LpTestAdapter;
		c.AdapterParam = t;
		Format(what, sizeof(what), "%s: its overlay runs without a control stream", t->Name);
		started = LpTestCheck(&ctx, started && NodeOverlayStart(t->Node, &c), what, "NodeOverlayStart failed") && started;
	}
	Zero(scalar, sizeof(scalar));

	if (started)
	{
		started = LpTestCheck(&ctx, LpTestApply(nodes, 1),
			"node-s and node-r apply Generation 1, shared and red with their policies and the route that each leaks into the other, and their session is up",
			"the states or the session did not come up");
	}

	if (started)
	{
		LpTestSteps(&ctx, nodes, lptest_rules, sizeof(lptest_rules) / sizeof(lptest_rules[0]));

		if (LpTestCheck(&ctx, LpTestApply(nodes, 2), "node-s and node-r apply Generation 2, in which no-shared joins the rules of red", "the states did not go in"))
		{
			LpTestSteps(&ctx, nodes, lptest_deny, sizeof(lptest_deny) / sizeof(lptest_deny[0]));
		}

		LpTestPolicies(&ctx, nodes);

		for (UINT i = 0;i < 2;i++)
		{
			NODE_OVERLAY_STATUS st;

			NodeOverlayGetStatus(nodes[i].Node, &st);
			Print("  %s: forwarded %I64u, delivered %I64u, dropped %I64u\n", nodes[i].Name, st.Forwarded, st.Delivered, st.Dropped);
		}
	}

	// The nodes stop, every thread is joined
	for (UINT i = 0;i < 2;i++)
	{
		LPTEST_NODE *t = &nodes[i];
		wchar_t log_dir[MAX_PATH];

		if (t->Node != NULL)
		{
			NodeReaderUnregister(t->Node, &t->Reader);
			NodeStop(t->Node);
			FreeNode(t->Node);
			ConbinePathW(log_dir, sizeof(log_dir), t->Dir, NODE_LOG_DIR_NAME);
			LpTestDeleteFiles(log_dir);
			LpTestDeleteFiles(t->Dir);
		}
		PeerKeyClose(&t->Key);
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
		Print("LEAKPOLICY TEST OK\n");
	}
	else
	{
		Print("LEAKPOLICY TEST FAILED (%u of %u checks failed)\n", ctx.NumFailed, ctx.NumChecks);
	}
}
