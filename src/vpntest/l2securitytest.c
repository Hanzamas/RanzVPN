// l2securitytest.c
// Named L2 security test of vpntest ("l2security" command, SDN-41 #234)
//
// The security of an L2 Network (src/Core/SwitchSecurity.h) in process: the switch of the new core (Switch.h) with the
// policy engine (Policy.h) as its filter, harness members on its ports that record every frame they get, byte for byte,
// and a document of rules whose starter rule lets every frame through, so that only the protections drop one.
// - Golden family "l2security". Each case puts one frame into the port of one member and lists what every member got,
//   and the verdicts of the policy engine on it; it must reach exactly the members that it names, and the report must
//   match the golden file. A report ends with the MAC table, the counters of the VLAN and of the switch, and the frames of
//   the policy engine by the reason of their verdict.
//   - l2security_spoofing.txt: the MAC and IP checks with their limits. The frames of a client from its own addresses
//     pass; from the address of another client or of the gateway, past its limits, or in an ARP reply that claims the
//     address of the gateway, they go nowhere, and the MAC table keeps each address on its own port. The gateway takes
//     back an address that a client took before the gateway sent from it. A frame behind two tags is judged by what it
//     carries; behind three tags it carries more than the policy engine reads, and goes nowhere.
//   - l2security_broadcast.txt: ARP and DHCP only. A client sends and gets ARP, DHCP, DHCPv6 and IPv6 neighbour
//     discovery to a group address, and no other broadcast or multicast, which still reaches a second gateway; its
//     unicast frames pass.
//   - l2security_gateway.txt: the DHCP and RA guards. A client that acts as a DHCP or DHCPv6 server or sends router
//     advertisements is blocked; the DHCP messages and the router advertisements of the gateway reach the clients. A
//     client cannot hide a DHCP server message or a router advertisement behind tags or IPv6 extension headers.
// - Then: the guard of each role of a port and the members that SwitchSecurityMember makes; and the security of the L2
//   Networks of a desired state as the control module takes it from the wire (Network.security, ControlInput): an L2
//   Network carries it, an L3 Network and a Network without one do not, and a delta changes it.
// Print "L2SECURITY TEST OK" only when every check passes.

#include "golden.h"
#include "testlist.h"

#include "Mayaqua/FileIO.h"
#include "Mayaqua/Memory.h"
#include "Mayaqua/Str.h"

#include "Core/Control.h"
#include "Core/SwitchSecurity.h"

#include <stdio.h>

#define	L2T_BUDGET				60000		// The test ends within this time, or the watchdog ends the process (ms)
#define	L2T_MAX_MEMBERS			6			// Members of a golden Network at most
#define	L2T_MAX_COPIES			4			// Frames that a member records in one case at most
#define	L2T_FRAME_MAX			160			// Bytes of a frame of a case at most
#define	L2T_MAX_MACS			16			// Entries of a MAC table that a report lists at most
#define	L2T_MAX_SECURITIES		4			// Securities of a desired state that the owner of a client keeps
#define	L2T_VLAN				10			// The VLAN of every port
#define	L2T_NOW					1000		// The time of the switch and of the policy engine (ms)
#define	L2T_NETWORK				"lan"		// The Network of every golden switch

#define	L2T_BIT(i)				(1u << (i))	// A member in the set of members that a case must reach

// The reasons of a verdict (POLICY_PASS_*, POLICY_DROP_*) in a report
static const char *const l2t_reasons[POLICY_NUM_REASONS] =
{
	"pass-rule", "pass-default", "pass-flow", "pass-related", "pass-control", "drop-rule", "drop-default", "drop-malformed",
	"drop-member", "drop-network", "drop-isolated", "drop-mac", "drop-ip", "drop-broadcast", "drop-dhcp-server", "drop-ra",
	"drop-protocol",
};

// The document of every golden engine: the L2 Network lan, whose starter rule lets every frame through
static const char l2t_document[] = "{\"networks\": [{\"name\": \"" L2T_NETWORK "\", \"mode\": \"l2\"}], \"rules\": [{\"name\": \"starter\", \"action\": \"allow\"}]}";

// Group addresses
static const UCHAR l2t_mac_bcast[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
static const UCHAR l2t_mac_all_nodes[6] = {0x33, 0x33, 0x00, 0x00, 0x00, 0x01};		// IPv6 ff02::1
static const UCHAR l2t_mac_all_routers[6] = {0x33, 0x33, 0x00, 0x00, 0x00, 0x02};	// IPv6 ff02::2
static const UCHAR l2t_mac_dhcpv6[6] = {0x33, 0x33, 0x00, 0x01, 0x00, 0x02};		// IPv6 ff02::1:2, the DHCPv6 servers and relays
static const UCHAR l2t_mac_solicited_b[6] = {0x33, 0x33, 0xFF, 0x00, 0x00, 0x0B};	// IPv6 ff02::1:ff00:b, the solicited node of fe80::b
static const UCHAR l2t_mac_mdns[6] = {0x01, 0x00, 0x5E, 0x00, 0x00, 0xFB};			// IPv4 224.0.0.251 (mDNS)
static const UCHAR l2t_mac_zero[6] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};			// The target of an ARP request
static const UCHAR l2t_ip_bcast[4] = {255, 255, 255, 255};
static const UCHAR l2t_ip_subnet_bcast[4] = {10, 5, 0, 255};
static const UCHAR l2t_ip_any[4] = {0, 0, 0, 0};
static const UCHAR l2t_ip_mdns[4] = {224, 0, 0, 251};
static const UCHAR l2t_ip6_all_nodes[16] = {0xFF, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01};
static const UCHAR l2t_ip6_all_routers[16] = {0xFF, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x02};
static const UCHAR l2t_ip6_dhcpv6[16] = {0xFF, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01, 0, 0x02};
static const UCHAR l2t_ip6_solicited_b[16] = {0xFF, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01, 0xFF, 0x00, 0x00, 0x0B};

// The members: the gateways GW and GW2, and the clients A, B and C
static const UCHAR l2t_mac_gw[6] = {0x02, 0x00, 0x00, 0x00, 0x05, 0x01};
static const UCHAR l2t_mac_gw2[6] = {0x02, 0x00, 0x00, 0x00, 0x05, 0x02};
static const UCHAR l2t_mac_a[6] = {0x02, 0x00, 0x00, 0x00, 0x05, 0x0A};
static const UCHAR l2t_mac_b[6] = {0x02, 0x00, 0x00, 0x00, 0x05, 0x0B};
static const UCHAR l2t_mac_b2[6] = {0x02, 0x00, 0x00, 0x00, 0x05, 0x1B};			// A second address of B, past its limit
static const UCHAR l2t_mac_c[6] = {0x02, 0x00, 0x00, 0x00, 0x05, 0x0C};
static const UCHAR l2t_ip_gw[4] = {10, 5, 0, 1};
static const UCHAR l2t_ip_gw2[4] = {10, 5, 0, 2};
static const UCHAR l2t_ip_a[4] = {10, 5, 0, 10};
static const UCHAR l2t_ip_b[4] = {10, 5, 0, 11};
static const UCHAR l2t_ip_b2[4] = {10, 5, 0, 12};
static const UCHAR l2t_ip_b3[4] = {10, 5, 0, 13};
static const UCHAR l2t_ip6_gw[16] = {0xFE, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01};		// fe80::1
static const UCHAR l2t_ip6_a[16] = {0xFE, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x0A};		// fe80::a
static const UCHAR l2t_ip6_b[16] = {0xFE, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x0B};		// fe80::b
static const UCHAR l2t_ip6_c[16] = {0xFE, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x0C};		// fe80::c

// The reachable time and the retransmission timer of a router advertisement
static const UCHAR l2t_ra_timers[8] = {0x00, 0x00, 0x75, 0x30, 0x00, 0x00, 0x03, 0xE8};

// The members of l2security_spoofing.txt
#define	L2S_GW					0			// The gateway
#define	L2S_A					1			// Clients
#define	L2S_B					2
#define	L2S_C					3

// The members of l2security_broadcast.txt
#define	L2B_GW					0			// The gateways
#define	L2B_GW2					1
#define	L2B_A					2			// Clients
#define	L2B_B					3

// The members of l2security_gateway.txt
#define	L2G_GW					0			// The gateway
#define	L2G_A					1			// Clients
#define	L2G_B					2

// The test
typedef struct L2T_CTX
{
	UINT NumChecks;
	UINT NumFailed;
	char OutDir[MAX_SIZE];						// The output and golden directories of the golden family "l2security"
	char GoldenDir[MAX_SIZE];
	bool Update;								// Update mode: the golden files are written, not compared
} L2T_CTX;

// A member of a port of a golden Network, and what it got in the current case
typedef struct L2T_MEMBER
{
	const char *Name;							// Its name in the report
	UINT Port;									// Its port
	UINT Member;								// ... and its member in the policy engine
	UINT NumFrames;								// The frames it got in the current case
	UINT Sizes[L2T_MAX_COPIES];					// ... their sizes
	UCHAR Frames[L2T_MAX_COPIES][L2T_FRAME_MAX];	// ... and their bytes
} L2T_MEMBER;

// A golden Network: its policy engine, its switch with the engine as its filter, its security and its members
typedef struct L2T_NET
{
	POLICY_ENGINE *Policy;
	SWITCH *Switch;
	SWITCH_SECURITY Security;
	bool SetupOk;								// The engine, its document, the switch, the members and their subscriptions were made
	UINT NumMembers;
	L2T_MEMBER Members[L2T_MAX_MEMBERS];
	BUF *Report;								// The report of the golden file
	UINT NumCases;
	UINT NumWrong;								// Cases that reached other members than they name
	char Wrong[MAX_SIZE];						// ... their numbers
} L2T_NET;

// What the owner of a client of the control module took: the number of the states, and the securities of the last one
typedef struct L2T_STATE
{
	UINT NumStates;
	UINT NumSecurities;
	CONTROL_SECURITY Securities[L2T_MAX_SECURITIES];
} L2T_STATE;

static bool L2tCheck(L2T_CTX *ctx, bool ok, const char *what, const char *fmt, ...) RANZ_PRINTF_FORMAT(4, 5);
static bool L2tCheck(L2T_CTX *ctx, bool ok, const char *what, const char *fmt, ...)
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

// The watchdog: a native thread that ends a run that hangs, so that a lost wake-up is a failed test instead of a hung CI
// step. Its parameter is the event that ends it.
static DWORD WINAPI L2tWatchdog(LPVOID param)
{
	char msg[MAX_SIZE];
	DWORD written = 0;

	if (WaitForSingleObject((HANDLE)param, L2T_BUDGET) != WAIT_TIMEOUT)
	{
		return 0;
	}

	int len = snprintf(msg, sizeof(msg), "L2SECURITY TEST FAILED (did not finish within %u ms)\n", (UINT)L2T_BUDGET);
	if (len > 0)
	{
		WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), msg, (DWORD)MIN((UINT)len, (UINT)sizeof(msg) - 1), &written, NULL);
	}

	TerminateProcess(GetCurrentProcess(), 1);

	return 0;
}

// The name of the reason of a verdict
static const char *L2tReason(UINT reason)
{
	return (reason < POLICY_NUM_REASONS ? l2t_reasons[reason] : "unknown");
}

// Add a string to a buffer
static void L2tAdd(BUF *b, const char *s)
{
	WriteBuf(b, s, StrLen(s));
}

//
// The frames
//

// The Ethernet header of a frame at f: to dst from src, of the EtherType type; its size
static UINT L2tEth(UCHAR *f, const UCHAR *dst, const UCHAR *src, USHORT type)
{
	Copy(f, dst, 6);
	Copy(f + 6, src, 6);
	f[12] = (UCHAR)(type >> 8);
	f[13] = (UCHAR)type;

	return 14;
}

// An IP packet at f of the family family (POLICY_IPV4: addresses of 4 bytes, POLICY_IPV6: of 16) from src to dst of the
// IP protocol protocol, with the l4_size bytes at l4 after its header; its size
static UINT L2tIp(UCHAR *f, UINT family, const UCHAR *src, const UCHAR *dst, UCHAR protocol, const UCHAR *l4, UINT l4_size)
{
	if (family == POLICY_IPV4)
	{
		Zero(f, 20);
		f[0] = 0x45;
		f[2] = (UCHAR)((20 + l4_size) >> 8);
		f[3] = (UCHAR)(20 + l4_size);
		f[8] = 64;
		f[9] = protocol;
		Copy(f + 12, src, 4);
		Copy(f + 16, dst, 4);
		Copy(f + 20, l4, l4_size);

		return 20 + l4_size;
	}

	Zero(f, 40);
	f[0] = 0x60;
	f[4] = (UCHAR)(l4_size >> 8);
	f[5] = (UCHAR)l4_size;
	f[6] = protocol;
	f[7] = 255;
	Copy(f + 8, src, 16);
	Copy(f + 24, dst, 16);
	Copy(f + 40, l4, l4_size);

	return 40 + l4_size;
}

// A frame at f: the Ethernet header to dmac from smac, then the IP packet of L2tIp; its size
static UINT L2tFrame(UCHAR *f, const UCHAR *dmac, const UCHAR *smac, UINT family, const UCHAR *src, const UCHAR *dst, UCHAR protocol, const UCHAR *l4,
	UINT l4_size)
{
	UINT head = L2tEth(f, dmac, smac, family == POLICY_IPV4 ? 0x0800 : 0x86DD);

	return head + L2tIp(f + head, family, src, dst, protocol, l4, l4_size);
}

// A frame at f of a UDP datagram from the port sport to dport with 4 bytes of data; its size
static UINT L2tUdpFrame(UCHAR *f, const UCHAR *dmac, const UCHAR *smac, UINT family, const UCHAR *src, const UCHAR *dst, USHORT sport, USHORT dport)
{
	UCHAR l4[12];

	Zero(l4, 8);
	l4[0] = (UCHAR)(sport >> 8);
	l4[1] = (UCHAR)sport;
	l4[2] = (UCHAR)(dport >> 8);
	l4[3] = (UCHAR)dport;
	l4[5] = 12;
	Copy(l4 + 8, "RANZ", 4);

	return L2tFrame(f, dmac, smac, family, src, dst, 17, l4, sizeof(l4));
}

// A frame at f of an ICMPv6 message of the type type: the type, the code 0, the checksum, the 32 bits of word (the hop
// limit, the flags and the lifetime of a router advertisement, the flags of a neighbour advertisement), then the
// body_size bytes at body; its size
static UINT L2tIcmp6Frame(UCHAR *f, const UCHAR *dmac, const UCHAR *smac, const UCHAR *src, const UCHAR *dst, UCHAR type, UINT word, const UCHAR *body,
	UINT body_size)
{
	UCHAR l4[L2T_FRAME_MAX];

	Zero(l4, 8);
	l4[0] = type;
	l4[4] = (UCHAR)(word >> 24);
	l4[5] = (UCHAR)(word >> 16);
	l4[6] = (UCHAR)(word >> 8);
	l4[7] = (UCHAR)word;
	if (body_size != 0)
	{
		Copy(l4 + 8, body, body_size);
	}

	return L2tFrame(f, dmac, smac, POLICY_IPV6, src, dst, 58, l4, 8 + body_size);
}

// A frame at f of the router advertisement of the cases from smac and src to the all-nodes address, behind num IPv6
// destination options headers of 8 bytes, each with a PadN option; its size
static UINT L2tHiddenRaFrame(UCHAR *f, const UCHAR *smac, const UCHAR *src, UINT num)
{
	UCHAR l4[L2T_FRAME_MAX];
	UINT pos = 0;

	for (UINT i = 0; i < num; i++)
	{
		Zero(l4 + pos, 8);
		l4[pos] = (UCHAR)(i + 1 < num ? 60 : 58);	// The next header: another destination options header, then ICMPv6
		l4[pos + 2] = 1;							// PadN, of 4 bytes
		l4[pos + 3] = 4;
		pos += 8;
	}

	// The router advertisement: the hop limit 64, no flags and the router lifetime of 1800 s, then the timers
	Zero(l4 + pos, 8);
	l4[pos] = 134;
	l4[pos + 4] = 0x40;
	l4[pos + 6] = 0x07;
	l4[pos + 7] = 0x08;
	Copy(l4 + pos + 8, l2t_ra_timers, sizeof(l2t_ra_timers));

	return L2tFrame(f, l2t_mac_all_nodes, smac, POLICY_IPV6, src, l2t_ip6_all_nodes, 60, l4, pos + 16);
}

// Put num priority tags (TPID 0x8100, VLAN id 0) into the Ethernet frame f of size bytes, after its addresses: the outer
// and the inner tag of a QinQ frame, or tags that a frame hides behind; its new size
static UINT L2tTags(UCHAR *f, UINT size, UINT num)
{
	MoveMemory(f + 12 + num * 4, f + 12, size - 12);
	for (UINT i = 0; i < num; i++)
	{
		f[12 + i * 4] = 0x81;
		f[13 + i * 4] = 0x00;
		f[14 + i * 4] = 0x00;
		f[15 + i * 4] = 0x00;
	}

	return size + num * 4;
}

// An ARP frame at f for Ethernet and IPv4 from smac to dmac: the operation op of the sender sha, spa for the target tha,
// tpa; its size
static UINT L2tArpFrame(UCHAR *f, const UCHAR *dmac, const UCHAR *smac, USHORT op, const UCHAR *sha, const UCHAR *spa, const UCHAR *tha,
	const UCHAR *tpa)
{
	UCHAR *a = f + L2tEth(f, dmac, smac, 0x0806);

	Zero(a, 28);
	a[1] = 1;									// Ethernet
	a[2] = 0x08;								// IPv4
	a[4] = 6;
	a[5] = 4;
	a[6] = (UCHAR)(op >> 8);
	a[7] = (UCHAR)op;
	Copy(a + 8, sha, 6);
	Copy(a + 14, spa, 4);
	Copy(a + 18, tha, 6);
	Copy(a + 24, tpa, 4);

	return 14 + 28;
}

//
// The golden Networks
//

// The procedure of a member of a golden Network: it records the frame
static void L2tRecord(void *param, UINT port, const UCHAR *frame, UINT size)
{
	L2T_MEMBER *m = (L2T_MEMBER *)param;

	if (m->NumFrames < L2T_MAX_COPIES)
	{
		m->Sizes[m->NumFrames] = size;
		Copy(m->Frames[m->NumFrames], frame, MIN(size, L2T_FRAME_MAX));
	}
	m->NumFrames++;
}

// A golden Network of the security sec: a policy engine with the document of the test, and a switch with the engine as
// its filter
static L2T_NET *L2tNewNet(const SWITCH_SECURITY *sec)
{
	L2T_NET *net = ZeroMalloc(sizeof(L2T_NET));
	char error[MAX_SIZE];
	SWITCH_CONFIG c;

	Copy(&net->Security, sec, sizeof(SWITCH_SECURITY));
	net->Report = NewBuf();
	net->Policy = PolicyNew(L2T_MAX_MEMBERS);
	net->SetupOk = (net->Policy != NULL && PolicySetRules(net->Policy, l2t_document, StrLen(l2t_document), error, sizeof(error)));

	Zero(&c, sizeof(c));
	c.MaxPorts = L2T_MAX_MEMBERS;
	c.MaxMacs = 1024;
	SwitchSecurityFilter(&c, net->Policy);
	net->Switch = SwitchNew(&c);
	if (net->Switch == NULL)
	{
		net->SetupOk = false;
	}

	return net;
}

static void L2tFreeNet(L2T_NET *net)
{
	// The switch calls the engine: it goes first
	SwitchFree(net->Switch);
	PolicyFree(net->Policy);
	FreeBuf(net->Report);
	Free(net);
}

// A member of a golden Network on the next port, an access port of L2T_VLAN, in the role role
static void L2tMember(L2T_NET *net, const char *name, UINT role)
{
	L2T_MEMBER *m = &net->Members[net->NumMembers];
	POLICY_MEMBER_CONFIG pc;
	SWITCH_PORT_CONFIG c;

	Zero(&pc, sizeof(pc));
	pc.Network = L2T_NETWORK;
	m->Name = name;
	m->Member = SwitchSecurityMember(net->Policy, &pc, &net->Security, role);

	Zero(&c, sizeof(c));
	c.Mode = SWITCH_ACCESS;
	c.Vlan = L2T_VLAN;
	c.Send = L2tRecord;
	c.Param = m;
	c.Member = m->Member;
	m->Port = SwitchAddPort(net->Switch, &c);

	if (m->Member == POLICY_NO_MEMBER || m->Port != net->NumMembers)
	{
		net->SetupOk = false;
	}
	net->NumMembers++;
}

// A subscription of a member of a golden Network to a group of L2T_VLAN
static void L2tJoin(L2T_NET *net, UINT member, const UCHAR *group)
{
	if (SwitchSubscribe(net->Switch, net->Members[member].Port, L2T_VLAN, group) == false)
	{
		net->SetupOk = false;
	}
}

// Whether a golden Network was made
static bool L2tSetupOk(L2T_CTX *ctx, L2T_NET *net, const char *what)
{
	char tmp[MAX_SIZE];

	Format(tmp, sizeof(tmp), "%s: the policy engine with its document, the switch with the engine as its filter, the members of its ports and their subscriptions are made",
		what);
	return L2tCheck(ctx, net->SetupOk, tmp, "PolicyNew, PolicySetRules, SwitchNew, SwitchSecurityMember, SwitchAddPort or SwitchSubscribe failed");
}

// The name of the member of a port, "-" for none
static const char *L2tPortName(L2T_NET *net, UINT port)
{
	for (UINT i = 0; i < net->NumMembers; i++)
	{
		if (net->Members[i].Port == port)
		{
			return net->Members[i].Name;
		}
	}

	return "-";
}

// The next case of a golden Network: the frame f of size bytes into the port of the member from. What each member got
// goes to the report as "<n> <name>: <member> got <hex>", or the case as "<n> <name>: nothing" when no member got
// anything; then the verdicts of the policy engine on it as "<n> <name>: verdict <reason>...". It must reach the members
// of expect (L2T_BIT).
static void L2tCase(L2T_NET *net, const char *name, UINT from, const UCHAR *f, UINT size, UINT expect)
{
	POLICY_STATS before, after;
	char line[MAX_SIZE * 2];
	char hex[L2T_FRAME_MAX * 2 + 1];
	char num[16];
	UINT got = 0;
	bool judged = false;
	UINT n = ++net->NumCases;

	for (UINT i = 0; i < net->NumMembers; i++)
	{
		net->Members[i].NumFrames = 0;
	}

	PolicyGetStats(net->Policy, &before);
	SwitchInput(net->Switch, L2T_NOW, net->Members[from].Port, f, size);
	PolicyGetStats(net->Policy, &after);

	for (UINT i = 0; i < net->NumMembers; i++)
	{
		L2T_MEMBER *m = &net->Members[i];

		for (UINT k = 0; k < m->NumFrames && k < L2T_MAX_COPIES; k++)
		{
			BinToStr(hex, sizeof(hex), m->Frames[k], MIN(m->Sizes[k], L2T_FRAME_MAX));
			Format(line, sizeof(line), "%u %s: %s got %s\n", n, name, m->Name, hex);
			L2tAdd(net->Report, line);
		}
		if (m->NumFrames != 0)
		{
			got |= L2T_BIT(i);
		}
	}

	if (got == 0)
	{
		Format(line, sizeof(line), "%u %s: nothing\n", n, name);
		L2tAdd(net->Report, line);
	}

	// The reasons whose counters the frame moved
	Format(line, sizeof(line), "%u %s: verdict", n, name);
	for (UINT k = 0; k < POLICY_NUM_REASONS; k++)
	{
		if (after.Reasons[k] != before.Reasons[k])
		{
			StrCat(line, sizeof(line), " ");
			StrCat(line, sizeof(line), L2tReason(k));
			judged = true;
		}
	}
	StrCat(line, sizeof(line), judged ? "\n" : " none\n");
	L2tAdd(net->Report, line);

	if (got != expect)
	{
		Format(num, sizeof(num), " %u", n);
		StrCat(net->Wrong, sizeof(net->Wrong), num);
		net->NumWrong++;
	}
}

// The end of a report: the MAC table, the counters of the VLAN, of the switch and of the policy engine. Checks that the
// fates of the frames of the VLAN add up to the frames that it took, and that the frames that the policy engine dropped
// are those that the filter of the switch refused.
static void L2tTrailer(L2T_CTX *ctx, L2T_NET *net, const char *what)
{
	SWITCH_MAC_ENTRY *macs = ZeroMalloc(sizeof(SWITCH_MAC_ENTRY) * L2T_MAX_MACS);
	UINT num = SwitchGetMacs(net->Switch, macs, L2T_MAX_MACS);
	char line[MAX_SIZE * 2];
	char tmp[MAX_SIZE];
	char mac[MAX_SIZE];
	SWITCH_VLAN_STATS v;
	SWITCH_STATS st;
	POLICY_STATS ps;
	UINT64 drops = 0;

	for (UINT i = 0; i < num; i++)
	{
		MacToStr(mac, sizeof(mac), macs[i].Mac);
		Format(line, sizeof(line), "mac %u %s: %s\n", macs[i].Vlan, mac, L2tPortName(net, macs[i].Port));
		L2tAdd(net->Report, line);
	}

	bool ok = SwitchGetVlanStats(net->Switch, L2T_VLAN, &v);
	Format(line, sizeof(line), "vlan %u: in %I64u frames; unicast %I64u, flooded %I64u, broadcast %I64u, multicast %I64u, limit drops %I64u, filtered %I64u; out %I64u frames\n",
		(UINT)L2T_VLAN, v.InFrames, v.Unicast, v.Flooded, v.Broadcast, v.Multicast, v.LimitDrops, v.Filtered, v.OutFrames);
	L2tAdd(net->Report, line);

	SwitchGetStats(net->Switch, &st);
	Format(line, sizeof(line), "switch: ports %u, macs %u, learnt %I64u, moved %I64u, refused %I64u; drops malformed %I64u, port %I64u, vlan %I64u, source %I64u, filter %I64u\n",
		st.NumPorts, st.NumMacs, st.Learnt, st.Moved, st.Refused, st.Drops[SWITCH_DROP_MALFORMED], st.Drops[SWITCH_DROP_PORT], st.Drops[SWITCH_DROP_VLAN],
		st.Drops[SWITCH_DROP_SOURCE], st.Drops[SWITCH_DROP_FILTER]);
	L2tAdd(net->Report, line);

	PolicyGetStats(net->Policy, &ps);
	Format(line, sizeof(line), "policy: %I64u frames", ps.Frames);
	for (UINT k = 0; k < POLICY_NUM_REASONS; k++)
	{
		if (ps.Reasons[k] != 0)
		{
			Format(tmp, sizeof(tmp), ", %s %I64u", L2tReason(k), ps.Reasons[k]);
			StrCat(line, sizeof(line), tmp);
		}
		if (k > POLICY_PASS_CONTROL)
		{
			drops += ps.Reasons[k];
		}
	}
	StrCat(line, sizeof(line), "\n");
	L2tAdd(net->Report, line);

	Format(tmp, sizeof(tmp), "%s: the fates of the frames of the VLAN add up to the frames that it took", what);
	L2tCheck(ctx, ok && v.InFrames == v.Unicast + v.Flooded + v.Broadcast + v.Multicast + v.LimitDrops + v.Filtered, tmp, "the counters are in the report");
	Format(tmp, sizeof(tmp), "%s: the frames that the policy engine dropped are the ones that the filter of the switch refused", what);
	L2tCheck(ctx, drops == st.Drops[SWITCH_DROP_FILTER] && ps.Frames == v.InFrames + drops, tmp, "the policy engine judged %I64u frames and dropped %I64u, the filter refused %I64u",
		ps.Frames, drops, st.Drops[SWITCH_DROP_FILTER]);

	Free(macs);
}

// The end of a golden Network: its trailer, and its report compared with the golden file
static void L2tGolden(L2T_CTX *ctx, L2T_NET *net, char *file, const char *what)
{
	HARNESS h;
	char tmp[MAX_SIZE];

	L2tTrailer(ctx, net, what);

	Format(tmp, sizeof(tmp), "%s: every case reaches exactly the members that it names", what);
	L2tCheck(ctx, net->NumWrong == 0, tmp, "cases%s reach other members (the report is below)", net->Wrong);

	char *report = HarnessBufToStr(net->Report);
	if (net->NumWrong != 0)
	{
		Print("--- the report of %s:\n%s", file, report);
	}

	Zero(&h, sizeof(h));
	HarnessCompareGolden(&h, ctx->OutDir, ctx->GoldenDir, file, report, ctx->Update);
	Format(tmp, sizeof(tmp), "%s: the report matches the golden file %s", what, file);
	L2tCheck(ctx, h.NumFail == 0, tmp, "it differs from the golden file (the diff is above)");

	Free(report);
}

// l2security_spoofing.txt: the MAC and IP checks of the clients A, B and C, with one MAC address and two IP addresses
// each, and the gateway GW
static void L2tSpoofing(L2T_CTX *ctx)
{
	SWITCH_SECURITY sec;
	UCHAR f[L2T_FRAME_MAX];
	UINT size;

	Print("[spoofing: the MAC and IP checks with their limits, and the addresses of the gateway]\n");

	Zero(&sec, sizeof(sec));
	sec.CheckMac = true;
	sec.CheckIp = true;
	sec.MaxMacs = 1;
	sec.MaxIps = 2;

	L2T_NET *net = L2tNewNet(&sec);
	L2tMember(net, "GW", SWITCH_GATEWAY);
	L2tMember(net, "A", SWITCH_CLIENT);
	L2tMember(net, "B", SWITCH_CLIENT);
	L2tMember(net, "C", SWITCH_CLIENT);
	for (UINT i = 0; i < net->NumMembers; i++)
	{
		L2tJoin(net, i, l2t_mac_bcast);
		L2tJoin(net, i, l2t_mac_all_nodes);
	}

	if (L2tSetupOk(ctx, net, "spoofing"))
	{
		// The first addresses of each member are its own
		size = L2tArpFrame(f, l2t_mac_bcast, l2t_mac_gw, 1, l2t_mac_gw, l2t_ip_gw, l2t_mac_zero, l2t_ip_gw);
		L2tCase(net, "gateway_arp_announcement", L2S_GW, f, size, L2T_BIT(L2S_A) | L2T_BIT(L2S_B) | L2T_BIT(L2S_C));
		size = L2tArpFrame(f, l2t_mac_bcast, l2t_mac_a, 1, l2t_mac_a, l2t_ip_a, l2t_mac_zero, l2t_ip_gw);
		L2tCase(net, "a_arp_request", L2S_A, f, size, L2T_BIT(L2S_GW) | L2T_BIT(L2S_B) | L2T_BIT(L2S_C));
		size = L2tUdpFrame(f, l2t_mac_gw, l2t_mac_a, POLICY_IPV4, l2t_ip_a, l2t_ip_gw, 40000, 53);
		L2tCase(net, "a_to_the_gateway", L2S_A, f, size, L2T_BIT(L2S_GW));
		size = L2tUdpFrame(f, l2t_mac_a, l2t_mac_gw, POLICY_IPV4, l2t_ip_gw, l2t_ip_a, 53, 40000);
		L2tCase(net, "reply_of_the_gateway", L2S_GW, f, size, L2T_BIT(L2S_A));

		// A spoofed source goes nowhere, and its frame leaves the MAC table as it was
		size = L2tUdpFrame(f, l2t_mac_gw, l2t_mac_a, POLICY_IPV4, l2t_ip_b, l2t_ip_gw, 40001, 53);
		L2tCase(net, "b_from_the_mac_of_a", L2S_B, f, size, 0);
		size = L2tUdpFrame(f, l2t_mac_a, l2t_mac_gw, POLICY_IPV4, l2t_ip_gw, l2t_ip_a, 53, 40000);
		L2tCase(net, "gateway_to_a_after_the_spoof", L2S_GW, f, size, L2T_BIT(L2S_A));
		size = L2tUdpFrame(f, l2t_mac_a, l2t_mac_b, POLICY_IPV4, l2t_ip_gw, l2t_ip_a, 53, 40000);
		L2tCase(net, "b_from_the_ip_of_the_gateway", L2S_B, f, size, 0);
		size = L2tArpFrame(f, l2t_mac_a, l2t_mac_b, 2, l2t_mac_b, l2t_ip_gw, l2t_mac_a, l2t_ip_a);
		L2tCase(net, "b_arp_reply_for_the_gateway", L2S_B, f, size, 0);

		// The limits: one MAC address and two IP addresses
		size = L2tUdpFrame(f, l2t_mac_gw, l2t_mac_b, POLICY_IPV4, l2t_ip_b, l2t_ip_gw, 40002, 53);
		L2tCase(net, "b_from_its_own_addresses", L2S_B, f, size, L2T_BIT(L2S_GW));
		size = L2tUdpFrame(f, l2t_mac_gw, l2t_mac_b2, POLICY_IPV4, l2t_ip_b, l2t_ip_gw, 40003, 53);
		L2tCase(net, "b_from_a_second_mac_past_its_limit", L2S_B, f, size, 0);
		size = L2tUdpFrame(f, l2t_mac_gw, l2t_mac_b, POLICY_IPV4, l2t_ip_b2, l2t_ip_gw, 40004, 53);
		L2tCase(net, "b_from_a_second_ip_within_its_limit", L2S_B, f, size, L2T_BIT(L2S_GW));
		size = L2tUdpFrame(f, l2t_mac_gw, l2t_mac_b, POLICY_IPV4, l2t_ip_b3, l2t_ip_gw, 40005, 53);
		L2tCase(net, "b_from_a_third_ip_past_its_limit", L2S_B, f, size, 0);

		// An address that the gateway never sent from is a client's to take, until the gateway sends from it
		size = L2tUdpFrame(f, l2t_mac_a, l2t_mac_c, POLICY_IPV6, l2t_ip6_gw, l2t_ip6_a, 40006, 9);
		L2tCase(net, "c_from_an_address_the_gateway_never_sent_from", L2S_C, f, size, L2T_BIT(L2S_A));
		size = L2tIcmp6Frame(f, l2t_mac_all_nodes, l2t_mac_gw, l2t_ip6_gw, l2t_ip6_all_nodes, 134, 0x40000708, l2t_ra_timers, sizeof(l2t_ra_timers));
		L2tCase(net, "router_advertisement_of_the_gateway", L2S_GW, f, size, L2T_BIT(L2S_A) | L2T_BIT(L2S_B) | L2T_BIT(L2S_C));
		size = L2tUdpFrame(f, l2t_mac_a, l2t_mac_c, POLICY_IPV6, l2t_ip6_gw, l2t_ip6_a, 40007, 9);
		L2tCase(net, "c_after_the_gateway_took_it_back", L2S_C, f, size, 0);
		size = L2tUdpFrame(f, l2t_mac_a, l2t_mac_c, POLICY_IPV6, l2t_ip6_c, l2t_ip6_a, 40008, 9);
		L2tCase(net, "c_from_its_own_address", L2S_C, f, size, L2T_BIT(L2S_A));

		// Behind two tags, an outer and an inner one, a frame is judged by what it carries; behind three, it carries more
		// than the policy engine reads and goes nowhere
		size = L2tTags(f, L2tUdpFrame(f, l2t_mac_a, l2t_mac_b, POLICY_IPV4, l2t_ip_gw, l2t_ip_a, 53, 40000), 2);
		L2tCase(net, "b_from_the_ip_of_the_gateway_behind_two_tags", L2S_B, f, size, 0);
		size = L2tTags(f, L2tUdpFrame(f, l2t_mac_a, l2t_mac_b, POLICY_IPV4, l2t_ip_b, l2t_ip_a, 40009, 9), 2);
		L2tCase(net, "b_from_its_own_address_behind_two_tags", L2S_B, f, size, L2T_BIT(L2S_A));
		size = L2tTags(f, L2tUdpFrame(f, l2t_mac_a, l2t_mac_b, POLICY_IPV4, l2t_ip_b, l2t_ip_a, 40010, 9), 3);
		L2tCase(net, "b_from_its_own_address_behind_three_tags", L2S_B, f, size, 0);

		L2tGolden(ctx, net, "l2security_spoofing.txt", "spoofing");
	}

	L2tFreeNet(net);
}

// l2security_broadcast.txt: ARP and DHCP only for the clients A and B, and the gateways GW and GW2
static void L2tBroadcast(L2T_CTX *ctx)
{
	SWITCH_SECURITY sec;
	UCHAR f[L2T_FRAME_MAX];
	UINT size;

	Print("[broadcast: ARP and DHCP only, on the frames that a client sends and on those it gets]\n");

	Zero(&sec, sizeof(sec));
	sec.ArpDhcpOnly = true;

	L2T_NET *net = L2tNewNet(&sec);
	L2tMember(net, "GW", SWITCH_GATEWAY);
	L2tMember(net, "GW2", SWITCH_GATEWAY);
	L2tMember(net, "A", SWITCH_CLIENT);
	L2tMember(net, "B", SWITCH_CLIENT);
	for (UINT i = 0; i < net->NumMembers; i++)
	{
		L2tJoin(net, i, l2t_mac_bcast);
		L2tJoin(net, i, l2t_mac_mdns);
	}
	L2tJoin(net, L2B_GW, l2t_mac_dhcpv6);
	L2tJoin(net, L2B_B, l2t_mac_solicited_b);

	if (L2tSetupOk(ctx, net, "broadcast"))
	{
		// A client sends ARP, DHCP, DHCPv6 and neighbour discovery to a group, and no other broadcast or multicast
		size = L2tArpFrame(f, l2t_mac_bcast, l2t_mac_a, 1, l2t_mac_a, l2t_ip_a, l2t_mac_zero, l2t_ip_gw);
		L2tCase(net, "a_arp_request", L2B_A, f, size, L2T_BIT(L2B_GW) | L2T_BIT(L2B_GW2) | L2T_BIT(L2B_B));
		size = L2tUdpFrame(f, l2t_mac_bcast, l2t_mac_a, POLICY_IPV4, l2t_ip_any, l2t_ip_bcast, 68, 67);
		L2tCase(net, "a_dhcp_discover", L2B_A, f, size, L2T_BIT(L2B_GW) | L2T_BIT(L2B_GW2) | L2T_BIT(L2B_B));
		size = L2tUdpFrame(f, l2t_mac_bcast, l2t_mac_a, POLICY_IPV4, l2t_ip_a, l2t_ip_subnet_bcast, 137, 137);
		L2tCase(net, "a_netbios_broadcast", L2B_A, f, size, 0);
		size = L2tUdpFrame(f, l2t_mac_mdns, l2t_mac_a, POLICY_IPV4, l2t_ip_a, l2t_ip_mdns, 5353, 5353);
		L2tCase(net, "a_mdns_multicast", L2B_A, f, size, 0);
		size = L2tIcmp6Frame(f, l2t_mac_solicited_b, l2t_mac_a, l2t_ip6_a, l2t_ip6_solicited_b, 135, 0, l2t_ip6_b, sizeof(l2t_ip6_b));
		L2tCase(net, "a_neighbour_solicitation_for_b", L2B_A, f, size, L2T_BIT(L2B_B));
		size = L2tUdpFrame(f, l2t_mac_dhcpv6, l2t_mac_a, POLICY_IPV6, l2t_ip6_a, l2t_ip6_dhcpv6, 546, 547);
		L2tCase(net, "a_dhcpv6_solicit", L2B_A, f, size, L2T_BIT(L2B_GW));

		// The other broadcasts of the gateways reach the gateways only; their ARP and DHCP reach the clients
		size = L2tUdpFrame(f, l2t_mac_bcast, l2t_mac_gw, POLICY_IPV4, l2t_ip_gw, l2t_ip_subnet_bcast, 137, 137);
		L2tCase(net, "gateway_netbios_broadcast", L2B_GW, f, size, L2T_BIT(L2B_GW2));
		size = L2tUdpFrame(f, l2t_mac_mdns, l2t_mac_gw, POLICY_IPV4, l2t_ip_gw, l2t_ip_mdns, 5353, 5353);
		L2tCase(net, "gateway_mdns_multicast", L2B_GW, f, size, L2T_BIT(L2B_GW2));
		size = L2tArpFrame(f, l2t_mac_bcast, l2t_mac_gw, 1, l2t_mac_gw, l2t_ip_gw, l2t_mac_zero, l2t_ip_a);
		L2tCase(net, "gateway_arp_request", L2B_GW, f, size, L2T_BIT(L2B_GW2) | L2T_BIT(L2B_A) | L2T_BIT(L2B_B));
		size = L2tUdpFrame(f, l2t_mac_bcast, l2t_mac_gw, POLICY_IPV4, l2t_ip_gw, l2t_ip_bcast, 67, 68);
		L2tCase(net, "gateway_dhcp_offer", L2B_GW, f, size, L2T_BIT(L2B_GW2) | L2T_BIT(L2B_A) | L2T_BIT(L2B_B));
		size = L2tArpFrame(f, l2t_mac_bcast, l2t_mac_gw2, 1, l2t_mac_gw2, l2t_ip_gw2, l2t_mac_zero, l2t_ip_gw);
		L2tCase(net, "second_gateway_arp_request", L2B_GW2, f, size, L2T_BIT(L2B_GW) | L2T_BIT(L2B_A) | L2T_BIT(L2B_B));

		// ARP and DHCP only holds for the frames to a group: the unicast frames of a client pass
		size = L2tUdpFrame(f, l2t_mac_gw, l2t_mac_a, POLICY_IPV4, l2t_ip_a, l2t_ip_gw, 40000, 80);
		L2tCase(net, "a_unicast_to_the_gateway", L2B_A, f, size, L2T_BIT(L2B_GW));

		L2tGolden(ctx, net, "l2security_broadcast.txt", "broadcast");
	}

	L2tFreeNet(net);
}

// l2security_gateway.txt: the DHCP and RA guards of the clients A and B, and the gateway GW
static void L2tGateway(L2T_CTX *ctx)
{
	SWITCH_SECURITY sec;
	UCHAR f[L2T_FRAME_MAX];
	UINT size;

	Print("[gateway: the DHCP and RA guards block a client acting as a DHCP server or a router, and not the gateway]\n");

	Zero(&sec, sizeof(sec));
	sec.DhcpGuard = true;
	sec.RaGuard = true;

	L2T_NET *net = L2tNewNet(&sec);
	L2tMember(net, "GW", SWITCH_GATEWAY);
	L2tMember(net, "A", SWITCH_CLIENT);
	L2tMember(net, "B", SWITCH_CLIENT);
	for (UINT i = 0; i < net->NumMembers; i++)
	{
		L2tJoin(net, i, l2t_mac_bcast);
		L2tJoin(net, i, l2t_mac_all_nodes);
	}
	L2tJoin(net, L2G_GW, l2t_mac_all_routers);
	L2tJoin(net, L2G_GW, l2t_mac_dhcpv6);

	if (L2tSetupOk(ctx, net, "gateway"))
	{
		// DHCP: the clients are DHCP clients, and only the gateway answers them
		size = L2tUdpFrame(f, l2t_mac_bcast, l2t_mac_a, POLICY_IPV4, l2t_ip_any, l2t_ip_bcast, 68, 67);
		L2tCase(net, "a_dhcp_discover", L2G_A, f, size, L2T_BIT(L2G_GW) | L2T_BIT(L2G_B));
		size = L2tUdpFrame(f, l2t_mac_bcast, l2t_mac_b, POLICY_IPV4, l2t_ip_any, l2t_ip_bcast, 68, 67);
		L2tCase(net, "b_dhcp_discover", L2G_B, f, size, L2T_BIT(L2G_GW) | L2T_BIT(L2G_A));
		size = L2tUdpFrame(f, l2t_mac_bcast, l2t_mac_gw, POLICY_IPV4, l2t_ip_gw, l2t_ip_bcast, 67, 68);
		L2tCase(net, "gateway_dhcp_offer", L2G_GW, f, size, L2T_BIT(L2G_A) | L2T_BIT(L2G_B));
		size = L2tUdpFrame(f, l2t_mac_bcast, l2t_mac_a, POLICY_IPV4, l2t_ip_a, l2t_ip_bcast, 67, 68);
		L2tCase(net, "a_dhcp_offer_as_a_rogue_server", L2G_A, f, size, 0);
		size = L2tUdpFrame(f, l2t_mac_b, l2t_mac_a, POLICY_IPV4, l2t_ip_a, l2t_ip_b, 67, 68);
		L2tCase(net, "a_dhcp_ack_to_b", L2G_A, f, size, 0);
		size = L2tUdpFrame(f, l2t_mac_a, l2t_mac_gw, POLICY_IPV4, l2t_ip_gw, l2t_ip_a, 67, 68);
		L2tCase(net, "gateway_dhcp_ack_to_a", L2G_GW, f, size, L2T_BIT(L2G_A));

		// IPv6: only the gateway advertises a router or answers DHCPv6; the clients still solicit and get both
		size = L2tIcmp6Frame(f, l2t_mac_all_routers, l2t_mac_b, l2t_ip6_b, l2t_ip6_all_routers, 133, 0, NULL, 0);
		L2tCase(net, "b_router_solicitation", L2G_B, f, size, L2T_BIT(L2G_GW));
		size = L2tIcmp6Frame(f, l2t_mac_all_nodes, l2t_mac_gw, l2t_ip6_gw, l2t_ip6_all_nodes, 134, 0x40000708, l2t_ra_timers, sizeof(l2t_ra_timers));
		L2tCase(net, "gateway_router_advertisement", L2G_GW, f, size, L2T_BIT(L2G_A) | L2T_BIT(L2G_B));
		size = L2tIcmp6Frame(f, l2t_mac_all_nodes, l2t_mac_a, l2t_ip6_a, l2t_ip6_all_nodes, 134, 0x40000708, l2t_ra_timers, sizeof(l2t_ra_timers));
		L2tCase(net, "a_router_advertisement", L2G_A, f, size, 0);
		size = L2tUdpFrame(f, l2t_mac_b, l2t_mac_a, POLICY_IPV6, l2t_ip6_a, l2t_ip6_b, 547, 546);
		L2tCase(net, "a_dhcpv6_advertise_as_a_rogue_server", L2G_A, f, size, 0);
		size = L2tUdpFrame(f, l2t_mac_b, l2t_mac_gw, POLICY_IPV6, l2t_ip6_gw, l2t_ip6_b, 547, 546);
		L2tCase(net, "gateway_dhcpv6_advertise", L2G_GW, f, size, L2T_BIT(L2G_B));
		size = L2tIcmp6Frame(f, l2t_mac_b, l2t_mac_a, l2t_ip6_a, l2t_ip6_b, 136, 0x60000000, l2t_ip6_a, sizeof(l2t_ip6_a));
		L2tCase(net, "a_neighbour_advertisement", L2G_A, f, size, L2T_BIT(L2G_B));
		size = L2tUdpFrame(f, l2t_mac_b, l2t_mac_a, POLICY_IPV4, l2t_ip_a, l2t_ip_b, 40000, 80);
		L2tCase(net, "a_unicast_to_b", L2G_A, f, size, L2T_BIT(L2G_B));

		// A client cannot hide a DHCP server message or a router advertisement: behind two tags the guard reads it, and
		// behind three tags or nine IPv6 extension headers it carries more than the policy engine reads and goes nowhere
		size = L2tTags(f, L2tUdpFrame(f, l2t_mac_bcast, l2t_mac_a, POLICY_IPV4, l2t_ip_a, l2t_ip_bcast, 67, 68), 2);
		L2tCase(net, "a_dhcp_offer_behind_two_tags", L2G_A, f, size, 0);
		size = L2tTags(f, L2tUdpFrame(f, l2t_mac_bcast, l2t_mac_a, POLICY_IPV4, l2t_ip_a, l2t_ip_bcast, 67, 68), 3);
		L2tCase(net, "a_dhcp_offer_behind_three_tags", L2G_A, f, size, 0);
		size = L2tHiddenRaFrame(f, l2t_mac_a, l2t_ip6_a, 9);
		L2tCase(net, "a_router_advertisement_behind_nine_extension_headers", L2G_A, f, size, 0);

		L2tGolden(ctx, net, "l2security_gateway.txt", "gateway");
	}

	L2tFreeNet(net);
}

//
// The guards and the members
//

// The guard of each role of a port; the limits, the guard and the refusals of SwitchSecurityMember; the filter of a switch
static void L2tGuards(L2T_CTX *ctx)
{
	const UINT client = POLICY_GUARD_CHECK_MAC | POLICY_GUARD_CHECK_IP | POLICY_GUARD_ARP_DHCP_ONLY | POLICY_GUARD_NO_DHCP_SERVER | POLICY_GUARD_NO_ROUTER;
	SWITCH_SECURITY all, guards, big;
	POLICY_MEMBER_CONFIG pc;
	POLICY_RESULT r;
	SWITCH_CONFIG c;
	UCHAR f[L2T_FRAME_MAX];
	char error[MAX_SIZE];

	Print("[guards: the guard of each role of a port and the members of SwitchSecurityMember]\n");

	Zero(&all, sizeof(all));
	all.CheckMac = true;
	all.CheckIp = true;
	all.ArpDhcpOnly = true;
	all.DhcpGuard = true;
	all.RaGuard = true;
	Zero(&guards, sizeof(guards));
	guards.DhcpGuard = true;
	guards.RaGuard = true;

	UINT g1 = SwitchSecurityGuard(&all, SWITCH_CLIENT);
	UINT g2 = SwitchSecurityGuard(&all, SWITCH_GATEWAY);
	UINT g3 = SwitchSecurityGuard(&all, 7);
	L2tCheck(ctx, g1 == client && g2 == POLICY_GUARD_GATEWAY && g3 == client,
		"guards: a client takes the flag of each protection that is on, the gateway POLICY_GUARD_GATEWAY alone, and a role that is none a client's",
		"the client 0x%X, the gateway 0x%X, role 7 0x%X", g1, g2, g3);
	g1 = SwitchSecurityGuard(&guards, SWITCH_CLIENT);
	g2 = SwitchSecurityGuard(&guards, SWITCH_GATEWAY);
	g3 = SwitchSecurityGuard(NULL, SWITCH_CLIENT) | SwitchSecurityGuard(NULL, SWITCH_GATEWAY);
	L2tCheck(ctx, g1 == (POLICY_GUARD_NO_DHCP_SERVER | POLICY_GUARD_NO_ROUTER) && g2 == 0 && g3 == 0,
		"guards: without a MAC or IP check the gateway takes no flag, and without a security no port takes one",
		"the client 0x%X, the gateway 0x%X, without a security 0x%X", g1, g2, g3);

	POLICY_ENGINE *p = PolicyNew(8);
	bool ok = (p != NULL && PolicySetRules(p, l2t_document, StrLen(l2t_document), error, sizeof(error)));
	if (L2tCheck(ctx, ok, "guards: the policy engine and its document are made", "PolicyNew or PolicySetRules failed") == false)
	{
		PolicyFree(p);
		return;
	}

	Zero(&pc, sizeof(pc));
	pc.Network = L2T_NETWORK;
	Copy(&big, &all, sizeof(big));
	big.MaxMacs = POLICY_MAX_BOUND + 1;
	UINT m1 = SwitchSecurityMember(p, &pc, &big, SWITCH_CLIENT);
	UINT m2 = SwitchSecurityMember(p, NULL, &all, SWITCH_CLIENT);
	UINT m3 = SwitchSecurityMember(p, &pc, &big, SWITCH_GATEWAY);
	L2tCheck(ctx, m1 == POLICY_NO_MEMBER && m2 == POLICY_NO_MEMBER && m3 != POLICY_NO_MEMBER,
		"guards: a client past the limit of POLICY_MAX_BOUND, or without a configuration, is no member; the gateway takes no limit",
		"members %u, %u and %u", m1, m2, m3);

	// The guard of the configuration stays: two clients that isolate themselves do not reach each other
	pc.Guard = POLICY_GUARD_ISOLATE;
	m1 = SwitchSecurityMember(p, &pc, &all, SWITCH_CLIENT);
	m2 = SwitchSecurityMember(p, &pc, &all, SWITCH_CLIENT);
	UINT size = L2tUdpFrame(f, l2t_mac_b, l2t_mac_a, POLICY_IPV4, l2t_ip_a, l2t_ip_b, 40000, 80);
	PolicyInput(p, L2T_NOW, m1, m2, L2T_VLAN, f, size, &r);
	L2tCheck(ctx, m1 != POLICY_NO_MEMBER && m2 != POLICY_NO_MEMBER && r.Pass == false && r.Reason == POLICY_DROP_ISOLATED,
		"guards: the guard of the configuration of a member stays besides the one of its role", "the verdict is %s", L2tReason(r.Reason));

	Zero(&c, sizeof(c));
	SwitchSecurityFilter(&c, p);
	SwitchSecurityFilter(NULL, p);
	L2tCheck(ctx, c.Admit != NULL && c.Deliver != NULL && c.FilterParam == p, "guards: SwitchSecurityFilter makes the policy engine the filter of a switch",
		"the filter is not set");

	PolicyFree(p);
}

//
// The security of the L2 Networks in a desired state
//

// A varint of the protobuf wire format into b
static void L2tVarint(BUF *b, UINT64 v)
{
	UCHAR c;

	while (v >= 0x80)
	{
		c = (UCHAR)(v | 0x80);
		WriteBuf(b, &c, 1);
		v >>= 7;
	}
	c = (UCHAR)v;
	WriteBuf(b, &c, 1);
}

// The field field of the varint v
static void L2tField(BUF *b, UINT field, UINT64 v)
{
	L2tVarint(b, (UINT64)field << 3);
	L2tVarint(b, v);
}

// The field field of size bytes at data: a string or a message
static void L2tBytes(BUF *b, UINT field, const void *data, UINT size)
{
	L2tVarint(b, ((UINT64)field << 3) | 2);
	L2tVarint(b, size);
	WriteBuf(b, data, size);
}

// The field field of the message m, which it frees
static void L2tMessage(BUF *b, UINT field, BUF *m)
{
	L2tBytes(b, field, m->Buf, m->Size);
	FreeBuf(m);
}

// An Object of the Network name of VRF 10 and of the mode mode (NetworkMode: 1 for L3, 2 for L2), with the security sec
// and its gateways when sec is not NULL
static BUF *L2tNetworkObject(const char *name, UINT mode, const SWITCH_SECURITY *sec, const char *const *gateways, UINT num_gateways)
{
	BUF *nw = NewBuf();
	BUF *o = NewBuf();

	L2tBytes(nw, 1, name, StrLen(name));
	L2tField(nw, 2, 10);
	L2tField(nw, 3, mode);
	if (sec != NULL)
	{
		BUF *s = NewBuf();

		L2tField(s, 1, sec->CheckMac);
		L2tField(s, 2, sec->CheckIp);
		L2tField(s, 3, sec->MaxMacs);
		L2tField(s, 4, sec->MaxIps);
		L2tField(s, 5, sec->ArpDhcpOnly);
		L2tField(s, 6, sec->DhcpGuard);
		L2tField(s, 7, sec->RaGuard);
		for (UINT i = 0; i < num_gateways; i++)
		{
			L2tBytes(s, 8, gateways[i], StrLen(gateways[i]));
		}
		L2tMessage(nw, 7, s);
	}
	L2tMessage(o, 3, nw);

	return o;
}

// A ControlMessage with the Update to the Generation gen from base (0 for a full state) that sets the num objects of
// set, which it frees
static BUF *L2tUpdate(UINT64 gen, UINT64 base, BUF **set, UINT num)
{
	BUF *u = NewBuf();
	BUF *m = NewBuf();

	L2tField(u, 1, gen);
	if (base != 0)
	{
		L2tField(u, 2, base);
	}
	for (UINT i = 0; i < num; i++)
	{
		L2tMessage(u, 3, set[i]);
	}
	L2tMessage(m, 2, u);

	return m;
}

// The owner of a client of the control module (CONTROL_STATE_PROC): it keeps the securities of the state
static void L2tStateProc(void *param, const CONTROL_STATE *state)
{
	L2T_STATE *st = (L2T_STATE *)param;

	st->NumStates++;
	st->NumSecurities = state->NumSecurities;
	for (UINT i = 0; i < state->NumSecurities && i < L2T_MAX_SECURITIES; i++)
	{
		Copy(&st->Securities[i], &state->Securities[i], sizeof(CONTROL_SECURITY));
	}
}

// Whether the security s is the one of the Network network with the protections and the limits of sec and the gateways
// gw-a and gw-b
static bool L2tSecurityIs(const CONTROL_SECURITY *s, const char *network, const SWITCH_SECURITY *sec)
{
	return StrCmp(s->Network, network) == 0 && s->VrfId == 10 && s->CheckMac == sec->CheckMac && s->CheckIp == sec->CheckIp && s->MaxMacs == sec->MaxMacs &&
		s->MaxIps == sec->MaxIps && s->ArpDhcpOnly == sec->ArpDhcpOnly && s->DhcpGuard == sec->DhcpGuard && s->RaGuard == sec->RaGuard && s->NumGateways == 2 &&
		StrCmp(s->Gateways[0], "gw-a") == 0 && StrCmp(s->Gateways[1], "gw-b") == 0;
}

// The security of the L2 Networks of a desired state, as a client of the control module takes it from the wire
static void L2tControl(L2T_CTX *ctx)
{
	static const char *const gateways[] = {"gw-a", "gw-b"};
	static const UCHAR key[NOISE_KEY_SIZE] = {0x01};
	static TRANSPORT transport = {"l2security"};
	L2T_STATE *st = ZeroMalloc(sizeof(L2T_STATE));
	SWITCH_SECURITY sec, guards;
	CONTROL_CONFIG cfg;
	BUF *set[3];

	Print("[control: the security of the L2 Networks of a desired state, from the wire]\n");

	Zero(&cfg, sizeof(cfg));
	cfg.Transport = &transport;
	StrCpy(cfg.Address, sizeof(cfg.Address), "controller");
	cfg.StaticKey = key;
	cfg.Proc = L2tStateProc;
	cfg.Param = st;

	CONTROL_CLIENT *c = ControlNew(&cfg);
	if (L2tCheck(ctx, c != NULL, "control: ControlNew makes a client without its thread", "it refused a complete configuration") == false)
	{
		Free(st);
		return;
	}

	Zero(&sec, sizeof(sec));
	sec.CheckMac = true;
	sec.CheckIp = true;
	sec.MaxMacs = 2;
	sec.MaxIps = 4;
	sec.ArpDhcpOnly = true;
	sec.DhcpGuard = true;
	sec.RaGuard = true;
	Zero(&guards, sizeof(guards));
	guards.DhcpGuard = true;
	guards.RaGuard = true;

	// Generation 1: the L2 Network lan with a security, the L3 Network wan with one that the node leaves out, and the L2
	// Network dmz without one
	set[0] = L2tNetworkObject("lan", 2, &sec, gateways, 2);
	set[1] = L2tNetworkObject("wan", 1, &sec, gateways, 2);
	set[2] = L2tNetworkObject("dmz", 2, NULL, NULL, 0);
	BUF *m = L2tUpdate(1, 0, set, 3);
	bool ok = ControlInput(c, m->Buf, m->Size);
	FreeBuf(m);
	L2tCheck(ctx, ok && st->NumStates == 1 && st->NumSecurities == 1 && L2tSecurityIs(&st->Securities[0], "lan", &sec),
		"control: an L2 Network of a state carries its security, with its protections, its limits and its gateways; an L3 Network and an L2 Network without one carry none",
		"the client took it: %s, %u states, %u securities", ok ? "yes" : "no", st->NumStates, st->NumSecurities);

	// Generation 2, a delta: dmz gets a security, and the securities are in Network name order
	set[0] = L2tNetworkObject("dmz", 2, &guards, gateways, 2);
	m = L2tUpdate(2, 1, set, 1);
	ok = ControlInput(c, m->Buf, m->Size);
	FreeBuf(m);
	L2tCheck(ctx, ok && st->NumStates == 2 && st->NumSecurities == 2 && L2tSecurityIs(&st->Securities[0], "dmz", &guards) &&
		L2tSecurityIs(&st->Securities[1], "lan", &sec),
		"control: a delta that gives an L2 Network a security adds it, in Network name order", "the client took it: %s, %u securities", ok ? "yes" : "no",
		st->NumSecurities);

	// Generation 3, a delta: lan without its security
	set[0] = L2tNetworkObject("lan", 2, NULL, NULL, 0);
	m = L2tUpdate(3, 2, set, 1);
	ok = ControlInput(c, m->Buf, m->Size);
	FreeBuf(m);
	L2tCheck(ctx, ok && st->NumStates == 3 && st->NumSecurities == 1 && L2tSecurityIs(&st->Securities[0], "dmz", &guards),
		"control: a delta that takes the security of an L2 Network away leaves the others", "the client took it: %s, %u securities", ok ? "yes" : "no",
		st->NumSecurities);

	ControlFree(c);
	Free(st);
}

RANZ_TEST_TAGS("l2security", l2security_test, "core", "L2 security: the security of an L2 Network (SDN-41) on its switch, with the policy engine as its filter, against golden files (golden family l2security): spoofed MAC and IP frames dropped and legitimate ones passed, ARP and DHCP only, and the DHCP and RA guards that block a client and not the gateway; the guard of each role of a port, and the security of the L2 Networks of a desired state from the wire.");
void l2security_test(UINT num, char **arg)
{
	L2T_CTX *ctx = ZeroMalloc(sizeof(L2T_CTX));
	HANDLE done = CreateEventW(NULL, TRUE, FALSE, NULL);
	HANDLE watchdog = (done != NULL ? CreateThread(NULL, 0, L2tWatchdog, done, 0, NULL) : NULL);

	Print("L2 security test: the security of an L2 Network on its switch, against golden frames and verdicts\n");

	HarnessGetFamilyDirs("l2security", ctx->OutDir, sizeof(ctx->OutDir), ctx->GoldenDir, sizeof(ctx->GoldenDir), &ctx->Update);
	MakeDirEx(ctx->OutDir);
	Print("L2SECURITY GOLDEN MODE %s\n", ctx->Update ? "update" : "compare");
	Print("  golden directory: %s\n", ctx->GoldenDir);

	L2tSpoofing(ctx);
	L2tBroadcast(ctx);
	L2tGateway(ctx);
	L2tGuards(ctx);
	L2tControl(ctx);

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
		Print("L2SECURITY TEST OK\n");
	}
	else
	{
		Print("L2SECURITY TEST FAILED (%u of %u checks failed)\n", ctx->NumFailed, ctx->NumChecks);
	}

	Free(ctx);
}
