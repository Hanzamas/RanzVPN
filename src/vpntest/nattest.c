// nattest.c
// Named 1:1 NAT and 4via6 test of vpntest ("nat" command, SDN-6 #182)
//
// The 1:1 NAT and the 4via6 of the data plane of a node (Cedar/NodeNat.c) and the overlay that runs them
// (NodeOverlay.c), in process, as seam 2 of #45 runs the data plane. The test builds every packet itself, with the
// checksums of Mayaqua (IpChecksum, CalcChecksumForIPv4, CalcChecksumForIPv6), so a translation is right when its
// bytes are those of the packet that the test builds for the other side.
// - Translation: packets of the host and of the peers through the rules of four VRFs: the 4via6 of red, 1:1 NAT rules
//   of IPv4 and of IPv6 in lab, the 4via6 of combo with a 1:1 NAT rule of IPv4 behind it, and a rule from IPv4 to IPv6
//   in odd, which the node refuses. ICMP errors take the packet that they quote along, Packet Too Big and
//   Fragmentation Needed their MTU, a UDP datagram of IPv4 without a checksum gets one in IPv6, and what cannot be
//   translated is dropped: an IPv6 packet with an extension header, a fragment of IPv4, a packet with one address only
//   in the 4via6 /96. The routes that the rules add to the forwarding tables lead where they should.
// - Overlay: node-a joins red and blue, which both use 10.0.0.0/24, with the 4via6 of each: 10.0.0.5 is node-b in red
//   and node-c in blue, and the host of node-a reaches each of them through a 4via6 address of its own, both ways,
//   with ICMP errors too. In lab, node-d presents the LAN 192.168.1.0/24 behind it as 10.99.1.0/24 (1:1 NAT), and
//   node-a reaches it: the source and the destination are rewritten both ways, in ICMP errors too. Where each packet
//   arrives and as which packet, and the counters of each node, match the golden file tests/golden/nat/nat_overlay.txt
//   (golden family "nat").
// Print "NAT TEST OK" only when every check passes.

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

#define	NATTEST_BUDGET			120000		// The whole test ends within this time, or the watchdog ends the process (ms)
#define	NATTEST_BOUND			10000		// A bounded wait on observable state (ms)
#define	NATTEST_POLL			10			// Poll interval of observable state (ms)
#define	NATTEST_DATA			16			// The data of a test packet after its ICMP or UDP header
#define	NATTEST_MAX_PACKET		512			// The bytes of a test packet at most
#define	NATTEST_NUM_NODES		4			// node-a, node-b, node-c and node-d
#define	NATTEST_NONE			INFINITE	// No node: the overlay drops the packet
#define	NATTEST_GOLDEN			"nat_overlay.txt"

// The kinds of a test packet
#define	NATTEST_ECHO_REQUEST		1		// An ICMP or ICMPv6 Echo Request, identifier 0x4E41, sequence 1
#define	NATTEST_ECHO_REPLY			2		// ... the Echo Reply
#define	NATTEST_UDP					3		// A UDP datagram from port 40000 to 53
#define	NATTEST_UDP0				4		// ... without a checksum (0)
#define	NATTEST_TCP_SYN				5		// A TCP SYN from port 40001 to 80
#define	NATTEST_PORT_UNREACHABLE	6		// An ICMP error: Port Unreachable ...
#define	NATTEST_TIME_EXCEEDED		7		// ... Time Exceeded ...
#define	NATTEST_TOO_BIG				8		// ... Fragmentation Needed in IPv4, Packet Too Big in IPv6, with an MTU
#define	NATTEST_UDP_HOP				9		// NATTEST_UDP of IPv6 behind a hop-by-hop options header
#define	NATTEST_UDP_FRAG			10		// NATTEST_UDP of IPv4 as the first fragment of more

// What a translation does with a packet
#define	NATTEST_ASIS			0			// No rule holds it: it goes as it is
#define	NATTEST_GO				1			// It goes as the packet that the case wants
#define	NATTEST_DROP			2			// It is dropped

// The VRFs of the overlay case
#define	NATTEST_RED				0
#define	NATTEST_BLUE			1
#define	NATTEST_LAB				2

static UINT nattest_vrf_ids[3] = {101, 202, 303};
static char *nattest_vrf_names[3] = {"red", "blue", "lab"};

// The nodes of the overlay case
#define	NATTEST_A				0
#define	NATTEST_B				1
#define	NATTEST_C				2
#define	NATTEST_D				3

static char *nattest_names[NATTEST_NUM_NODES] = {"node-a", "node-b", "node-c", "node-d"};

// A test packet: an IP packet of the family of its addresses
typedef struct NATTEST_PKT
{
	char *Src;							// Its source ...
	char *Dst;							// ... and its destination
	UINT Kind;							// NATTEST_ECHO_REQUEST and the others
	UINT Mtu;							// The MTU of NATTEST_TOO_BIG
	char *QSrc;							// An error: the source of the packet that it quotes ...
	char *QDst;							// ... its destination ...
	UINT QKind;							// ... its kind ...
	UINT QCut;							// ... and the bytes of its upper layer that the error holds, 0 for all
} NATTEST_PKT;

// One case of the translation: a packet of the VRF vrf_id that goes into the overlay (Out) or to the host, what the
// translation does with it, and the packet that it must become
typedef struct NATTEST_CASE
{
	UINT VrfId;
	bool Out;
	NATTEST_PKT Packet;
	UINT Result;
	NATTEST_PKT Want;
} NATTEST_CASE;

// The rules of the translation case, as a state gives them: the VRF, the inside prefix, the outside prefix
typedef struct NATTEST_RULE
{
	UINT VrfId;
	char *Inside;
	UINT InsideLength;
	char *Outside;
	UINT OutsideLength;
} NATTEST_RULE;

static NATTEST_RULE nattest_rules[] =
{
	// red: its 4via6
	{101, "fd00:101:0:ffff::", 96, "0.0.0.0", 0},
	// lab: 1:1 NAT of IPv4 and of IPv6
	{303, "192.168.1.0", 24, "10.99.1.0", 24},
	{303, "fd00:7::", 64, "fd00:303:0:99::", 64},
	// combo: its 4via6, and 10.4.0.0/24 behind it as 10.204.0.0/24
	{404, "fd00:404:0:ffff::", 96, "0.0.0.0", 0},
	{404, "10.4.0.0", 24, "10.204.0.0", 24},
	// odd: IPv4 inside and IPv6 outside, which a packet of the host would grow by: the node refuses it
	{505, "10.5.0.0", 24, "fd00:505::", 120},
};

#define	NATTEST_V6RED(x)		"fd00:101:0:ffff::" x
#define	NATTEST_V6COMBO(x)		"fd00:404:0:ffff::" x

static NATTEST_CASE nattest_cases[] =
{
	// The 4via6 of red: IPv6 of the host in the /96 is IPv4 in the overlay, and IPv4 of the overlay is IPv6 to the host
	{101, true, {NATTEST_V6RED("a00:1"), NATTEST_V6RED("a00:5"), NATTEST_ECHO_REQUEST}, NATTEST_GO, {"10.0.0.1", "10.0.0.5", NATTEST_ECHO_REQUEST}},
	{101, false, {"10.0.0.5", "10.0.0.1", NATTEST_ECHO_REPLY}, NATTEST_GO, {NATTEST_V6RED("a00:5"), NATTEST_V6RED("a00:1"), NATTEST_ECHO_REPLY}},
	{101, true, {NATTEST_V6RED("a00:1"), NATTEST_V6RED("a00:5"), NATTEST_TCP_SYN}, NATTEST_GO, {"10.0.0.1", "10.0.0.5", NATTEST_TCP_SYN}},
	{101, false, {"10.0.0.5", "10.0.0.1", NATTEST_UDP}, NATTEST_GO, {NATTEST_V6RED("a00:5"), NATTEST_V6RED("a00:1"), NATTEST_UDP}},
	{101, false, {"10.0.0.5", "10.0.0.1", NATTEST_UDP0}, NATTEST_GO, {NATTEST_V6RED("a00:5"), NATTEST_V6RED("a00:1"), NATTEST_UDP}},
	// ICMP errors: the quoted packet goes along, and the MTU follows the header of the family
	{101, false, {"10.0.0.9", "10.0.0.1", NATTEST_TOO_BIG, 1400, "10.0.0.1", "10.0.0.5", NATTEST_UDP, 8}, NATTEST_GO,
		{NATTEST_V6RED("a00:9"), NATTEST_V6RED("a00:1"), NATTEST_TOO_BIG, 1420, NATTEST_V6RED("a00:1"), NATTEST_V6RED("a00:5"), NATTEST_UDP, 8}},
	{101, true, {NATTEST_V6RED("a00:1"), NATTEST_V6RED("a00:5"), NATTEST_TOO_BIG, 1500, NATTEST_V6RED("a00:5"), NATTEST_V6RED("a00:1"), NATTEST_UDP}, NATTEST_GO,
		{"10.0.0.1", "10.0.0.5", NATTEST_TOO_BIG, 1480, "10.0.0.5", "10.0.0.1", NATTEST_UDP}},
	{101, false, {"10.0.0.9", "10.0.0.1", NATTEST_TIME_EXCEEDED, 0, "10.0.0.1", "10.0.0.5", NATTEST_ECHO_REQUEST}, NATTEST_GO,
		{NATTEST_V6RED("a00:9"), NATTEST_V6RED("a00:1"), NATTEST_TIME_EXCEEDED, 0, NATTEST_V6RED("a00:1"), NATTEST_V6RED("a00:5"), NATTEST_ECHO_REQUEST}},
	{101, true, {NATTEST_V6RED("a00:1"), NATTEST_V6RED("a00:5"), NATTEST_PORT_UNREACHABLE, 0, NATTEST_V6RED("a00:5"), NATTEST_V6RED("a00:1"), NATTEST_UDP}, NATTEST_GO,
		{"10.0.0.1", "10.0.0.5", NATTEST_PORT_UNREACHABLE, 0, "10.0.0.5", "10.0.0.1", NATTEST_UDP}},
	// What 4via6 cannot translate, and what no rule holds
	{101, true, {NATTEST_V6RED("a00:1"), NATTEST_V6RED("a00:5"), NATTEST_UDP_HOP}, NATTEST_DROP},
	{101, false, {"10.0.0.5", "10.0.0.1", NATTEST_UDP_FRAG}, NATTEST_DROP},
	{101, true, {"fd00:101:0:1::1", NATTEST_V6RED("a00:5"), NATTEST_ECHO_REQUEST}, NATTEST_DROP},
	{101, true, {"10.0.0.1", "10.0.0.5", NATTEST_ECHO_REQUEST}, NATTEST_ASIS},
	{101, false, {"fd00:101:0:1::5", "fd00:101:0:1::1", NATTEST_ECHO_REQUEST}, NATTEST_ASIS},
	// 1:1 NAT in lab: the source on the way out, the destination on the way in, in ICMP errors the quoted packet too
	{303, true, {"192.168.1.7", "10.3.0.1", NATTEST_UDP}, NATTEST_GO, {"10.99.1.7", "10.3.0.1", NATTEST_UDP}},
	{303, false, {"10.3.0.1", "10.99.1.7", NATTEST_TCP_SYN}, NATTEST_GO, {"10.3.0.1", "192.168.1.7", NATTEST_TCP_SYN}},
	{303, false, {"10.3.0.1", "10.99.1.7", NATTEST_UDP0}, NATTEST_GO, {"10.3.0.1", "192.168.1.7", NATTEST_UDP0}},
	{303, false, {"10.3.0.1", "10.99.1.7", NATTEST_PORT_UNREACHABLE, 0, "10.99.1.7", "10.3.0.1", NATTEST_UDP}, NATTEST_GO,
		{"10.3.0.1", "192.168.1.7", NATTEST_PORT_UNREACHABLE, 0, "192.168.1.7", "10.3.0.1", NATTEST_UDP}},
	{303, true, {"192.168.1.7", "10.3.0.1", NATTEST_TIME_EXCEEDED, 0, "10.3.0.1", "192.168.1.7", NATTEST_UDP, 8}, NATTEST_GO,
		{"10.99.1.7", "10.3.0.1", NATTEST_TIME_EXCEEDED, 0, "10.3.0.1", "10.99.1.7", NATTEST_UDP, 8}},
	{303, true, {"fd00:7::7", "fd00:303:0:1::1", NATTEST_ECHO_REQUEST}, NATTEST_GO, {"fd00:303:0:99::7", "fd00:303:0:1::1", NATTEST_ECHO_REQUEST}},
	{303, false, {"fd00:303:0:1::1", "fd00:303:0:99::7", NATTEST_UDP}, NATTEST_GO, {"fd00:303:0:1::1", "fd00:7::7", NATTEST_UDP}},
	{303, true, {"192.168.2.7", "10.3.0.1", NATTEST_UDP}, NATTEST_ASIS},
	{101, true, {"192.168.1.7", "10.3.0.1", NATTEST_UDP}, NATTEST_ASIS},
	// combo: the 4via6 first and the 1:1 NAT rule behind it on the way out, the other way round on the way in
	{404, true, {NATTEST_V6COMBO("a04:7"), NATTEST_V6COMBO("a00:5"), NATTEST_ECHO_REQUEST}, NATTEST_GO, {"10.204.0.7", "10.0.0.5", NATTEST_ECHO_REQUEST}},
	{404, false, {"10.0.0.5", "10.204.0.7", NATTEST_ECHO_REPLY}, NATTEST_GO, {NATTEST_V6COMBO("a00:5"), NATTEST_V6COMBO("a04:7"), NATTEST_ECHO_REPLY}},
	// odd: the refused rule holds nothing
	{505, true, {"10.5.0.7", "10.5.0.1", NATTEST_ECHO_REQUEST}, NATTEST_ASIS},
};

// One address of a node in the overlay case
typedef struct NATTEST_ADDR
{
	UINT Node;
	UINT Vrf;
	char *Address;
} NATTEST_ADDR;

// red and blue both use 10.0.0.0/24: 10.0.0.5 is node-b in red and node-c in blue; node-a is 10.0.0.1 in both
static NATTEST_ADDR nattest_addrs[] =
{
	{NATTEST_A, NATTEST_RED, "10.0.0.1"},
	{NATTEST_A, NATTEST_BLUE, "10.0.0.1"},
	{NATTEST_A, NATTEST_LAB, "10.3.0.1"},
	{NATTEST_B, NATTEST_RED, "10.0.0.5"},
	{NATTEST_C, NATTEST_BLUE, "10.0.0.5"},
	{NATTEST_D, NATTEST_LAB, "10.3.0.4"},
};

// One 1:1 NAT rule of a node in the overlay case, as the controller gives it
typedef struct NATTEST_NODE_RULE
{
	UINT Node;
	UINT Vrf;
	char *Inside;
	UINT InsideLength;
	char *Outside;
	UINT OutsideLength;
} NATTEST_NODE_RULE;

// node-a joins two VRFs on one range, so it has the 4via6 of both; node-d presents the LAN behind it
static NATTEST_NODE_RULE nattest_node_rules[] =
{
	{NATTEST_A, NATTEST_RED, "fd00:101:0:ffff::", 96, "0.0.0.0", 0},
	{NATTEST_A, NATTEST_BLUE, "fd00:202:0:ffff::", 96, "0.0.0.0", 0},
	{NATTEST_D, NATTEST_LAB, "192.168.1.0", 24, "10.99.1.0", 24},
};

#define	NATTEST_V6BLUE(x)		"fd00:202:0:ffff::" x

// One packet of the overlay case: the VRF it is sent in, the node whose host sends it, the node whose host takes it
// (NATTEST_NONE: the overlay drops it), and as which packet
typedef struct NATTEST_SEND
{
	UINT Vrf;
	UINT From;
	NATTEST_PKT Sent;
	UINT To;
	NATTEST_PKT Want;
} NATTEST_SEND;

static NATTEST_SEND nattest_sends[] =
{
	// The host of node-a reaches 10.0.0.5 of red and 10.0.0.5 of blue through two 4via6 addresses, and the answers come
	// back to it as IPv6
	{NATTEST_RED, NATTEST_A, {NATTEST_V6RED("a00:1"), NATTEST_V6RED("a00:5"), NATTEST_ECHO_REQUEST}, NATTEST_B, {"10.0.0.1", "10.0.0.5", NATTEST_ECHO_REQUEST}},
	{NATTEST_BLUE, NATTEST_A, {NATTEST_V6BLUE("a00:1"), NATTEST_V6BLUE("a00:5"), NATTEST_ECHO_REQUEST}, NATTEST_C, {"10.0.0.1", "10.0.0.5", NATTEST_ECHO_REQUEST}},
	{NATTEST_RED, NATTEST_B, {"10.0.0.5", "10.0.0.1", NATTEST_ECHO_REPLY}, NATTEST_A, {NATTEST_V6RED("a00:5"), NATTEST_V6RED("a00:1"), NATTEST_ECHO_REPLY}},
	{NATTEST_BLUE, NATTEST_C, {"10.0.0.5", "10.0.0.1", NATTEST_ECHO_REPLY}, NATTEST_A, {NATTEST_V6BLUE("a00:5"), NATTEST_V6BLUE("a00:1"), NATTEST_ECHO_REPLY}},
	{NATTEST_RED, NATTEST_A, {NATTEST_V6RED("a00:1"), NATTEST_V6RED("a00:5"), NATTEST_UDP}, NATTEST_B, {"10.0.0.1", "10.0.0.5", NATTEST_UDP}},
	{NATTEST_BLUE, NATTEST_C, {"10.0.0.5", "10.0.0.1", NATTEST_UDP}, NATTEST_A, {NATTEST_V6BLUE("a00:5"), NATTEST_V6BLUE("a00:1"), NATTEST_UDP}},
	{NATTEST_BLUE, NATTEST_A, {NATTEST_V6BLUE("a00:1"), NATTEST_V6BLUE("a00:5"), NATTEST_TCP_SYN}, NATTEST_C, {"10.0.0.1", "10.0.0.5", NATTEST_TCP_SYN}},
	// ICMP errors through 4via6: the packet that an error quotes changes family with it
	{NATTEST_RED, NATTEST_B, {"10.0.0.5", "10.0.0.1", NATTEST_PORT_UNREACHABLE, 0, "10.0.0.1", "10.0.0.5", NATTEST_UDP}, NATTEST_A,
		{NATTEST_V6RED("a00:5"), NATTEST_V6RED("a00:1"), NATTEST_PORT_UNREACHABLE, 0, NATTEST_V6RED("a00:1"), NATTEST_V6RED("a00:5"), NATTEST_UDP}},
	{NATTEST_BLUE, NATTEST_A, {NATTEST_V6BLUE("a00:1"), NATTEST_V6BLUE("a00:5"), NATTEST_TIME_EXCEEDED, 0, NATTEST_V6BLUE("a00:5"), NATTEST_V6BLUE("a00:1"), NATTEST_ECHO_REQUEST}, NATTEST_C,
		{"10.0.0.1", "10.0.0.5", NATTEST_TIME_EXCEEDED, 0, "10.0.0.5", "10.0.0.1", NATTEST_ECHO_REQUEST}},
	// A source outside the /96, an address of the /96 of blue in red, and IPv4 of the host, which goes as it is
	{NATTEST_RED, NATTEST_A, {"fd00:101:0:1::1", NATTEST_V6RED("a00:5"), NATTEST_ECHO_REQUEST}, NATTEST_NONE},
	{NATTEST_RED, NATTEST_A, {NATTEST_V6BLUE("a00:1"), NATTEST_V6BLUE("a00:5"), NATTEST_ECHO_REQUEST}, NATTEST_NONE},
	{NATTEST_RED, NATTEST_A, {"10.0.0.1", "10.0.0.5", NATTEST_ECHO_REQUEST}, NATTEST_B, {"10.0.0.1", "10.0.0.5", NATTEST_ECHO_REQUEST}},
	// 1:1 NAT in lab: node-a reaches the LAN behind node-d at 10.99.1.0/24; the destination is rewritten on the way to
	// the LAN, the source on the way back, and an ICMP error carries the packet that it quotes as each side sent it
	{NATTEST_LAB, NATTEST_A, {"10.3.0.1", "10.99.1.7", NATTEST_UDP}, NATTEST_D, {"10.3.0.1", "192.168.1.7", NATTEST_UDP}},
	{NATTEST_LAB, NATTEST_D, {"192.168.1.7", "10.3.0.1", NATTEST_UDP}, NATTEST_A, {"10.99.1.7", "10.3.0.1", NATTEST_UDP}},
	{NATTEST_LAB, NATTEST_A, {"10.3.0.1", "10.99.1.7", NATTEST_TCP_SYN}, NATTEST_D, {"10.3.0.1", "192.168.1.7", NATTEST_TCP_SYN}},
	{NATTEST_LAB, NATTEST_D, {"192.168.1.7", "10.3.0.1", NATTEST_PORT_UNREACHABLE, 0, "10.3.0.1", "192.168.1.7", NATTEST_UDP}, NATTEST_A,
		{"10.99.1.7", "10.3.0.1", NATTEST_PORT_UNREACHABLE, 0, "10.3.0.1", "10.99.1.7", NATTEST_UDP}},
	{NATTEST_LAB, NATTEST_A, {"10.3.0.1", "10.99.1.7", NATTEST_PORT_UNREACHABLE, 0, "10.99.1.7", "10.3.0.1", NATTEST_UDP}, NATTEST_D,
		{"10.3.0.1", "192.168.1.7", NATTEST_PORT_UNREACHABLE, 0, "192.168.1.7", "10.3.0.1", NATTEST_UDP}},
	{NATTEST_LAB, NATTEST_D, {"192.168.1.7", "10.3.0.1", NATTEST_ECHO_REQUEST}, NATTEST_A, {"10.99.1.7", "10.3.0.1", NATTEST_ECHO_REQUEST}},
	// The address of node-d goes as it is; a source of no rule and of no address of node-d, and the inside prefix as
	// node-a would see it, go nowhere
	{NATTEST_LAB, NATTEST_D, {"10.3.0.4", "10.3.0.1", NATTEST_ECHO_REQUEST}, NATTEST_A, {"10.3.0.4", "10.3.0.1", NATTEST_ECHO_REQUEST}},
	{NATTEST_LAB, NATTEST_D, {"192.168.2.7", "10.3.0.1", NATTEST_ECHO_REQUEST}, NATTEST_NONE},
	{NATTEST_LAB, NATTEST_A, {"10.3.0.1", "192.168.1.7", NATTEST_ECHO_REQUEST}, NATTEST_NONE},
};

// The checks of the test
typedef struct NATTEST_CTX
{
	UINT NumChecks;
	UINT NumFailed;
} NATTEST_CTX;

// A packet that the fake adapter of a host took
typedef struct NATTEST_PACKET
{
	UINT VrfId;
	UINT Size;
	UCHAR Data[NATTEST_MAX_PACKET];
} NATTEST_PACKET;

// One node of the overlay case and the fake adapter of its host
typedef struct NATTEST_NODE
{
	char *Name;
	wchar_t Dir[MAX_PATH];				// Its data directory
	PEER_KEY Key;						// Its static key
	NODE *Node;
	NODE_READER Reader;					// The test thread as a reader of the node's forwarding tables, online while it sends
	SRWLOCK Lock;						// Packets
	LIST *Packets;						// What the adapter took (NATTEST_PACKET)
} NATTEST_NODE;

static bool NatTestCheck(NATTEST_CTX *ctx, bool ok, char *what, char *fmt, ...) RANZ_PRINTF_FORMAT(4, 5);
static bool NatTestCheck(NATTEST_CTX *ctx, bool ok, char *what, char *fmt, ...)
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
static DWORD WINAPI NatTestWatchdog(LPVOID param)
{
	char msg[MAX_SIZE];
	DWORD written = 0;

	if (WaitForSingleObject((HANDLE)param, NATTEST_BUDGET) != WAIT_TIMEOUT)
	{
		return 0;
	}

	int len = snprintf(msg, sizeof(msg), "NAT TEST FAILED (did not finish within %u ms)\n", NATTEST_BUDGET);
	if (len > 0)
	{
		WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), msg, (DWORD)MIN((UINT)len, (UINT)sizeof(msg) - 1), &written, NULL);
	}

	TerminateProcess(GetCurrentProcess(), 1);

	return 0;
}

//
// Packets
//

// The address of a text: 4 bytes for IPv4, 16 for IPv6, and their number; 0 for no address
static UINT NatTestAddress(UCHAR *addr, char *str)
{
	IP ip;

	Zero(addr, 16);
	if (str == NULL || StrToIP(&ip, str) == false)
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
static void NatTestAddressStr(char *str, UINT str_size, const UCHAR *addr, UINT size)
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

// Write the checksum of the upper layer at l4, size bytes of the protocol, of the packet at ip whose addresses are
// addr_size bytes each: Mayaqua's, over the pseudo-header but in ICMP. UDP sends a checksum of 0 as 0xFFFF.
static void NatTestSum(UCHAR *ip, UINT addr_size, UCHAR *l4, UINT size, UINT protocol)
{
	UINT field = (protocol == IP_PROTO_TCP ? 16 : (protocol == IP_PROTO_UDP ? 6 : 2));
	USHORT sum;

	WRITE_USHORT(l4 + field, 0);
	if (addr_size == 4 && protocol == IP_PROTO_ICMPV4)
	{
		sum = IpChecksum(l4, size);
	}
	else if (addr_size == 4)
	{
		UINT src, dst;

		Copy(&src, ip + 12, 4);
		Copy(&dst, ip + 16, 4);
		sum = CalcChecksumForIPv4(src, dst, (UCHAR)protocol, l4, size, 0);
	}
	else
	{
		IPV6_ADDR src, dst;

		Copy(&src, ip + 8, 16);
		Copy(&dst, ip + 24, 16);
		sum = CalcChecksumForIPv6(&src, &dst, (UCHAR)protocol, l4, size, 0);
	}

	if (sum == 0 && protocol == IP_PROTO_UDP)
	{
		sum = 0xFFFF;
	}
	Copy(l4 + field, &sum, 2);
}

// Build the packet p into buf (NATTEST_MAX_PACKET bytes): its size, 0 when its addresses are not of one family or its
// kind is not one of IPv4 or IPv6. An IPv4 header has no options, TTL 64, identification 0 and Don't Fragment; an IPv6
// header traffic class 0, flow label 0 and hop limit 64. An error quotes the packet that the test builds of QSrc, QDst
// and QKind, cut to its IP header and QCut bytes of its upper layer.
static UINT NatTestBuild(UCHAR *buf, NATTEST_PKT *p)
{
	UCHAR src[16], dst[16];
	UCHAR quoted[NATTEST_MAX_PACKET];
	UINT quoted_size = 0;
	UINT addr_size = NatTestAddress(src, p->Src);
	UINT header = (addr_size == 4 ? 20 : 40);
	UINT ext = (p->Kind == NATTEST_UDP_HOP ? 8 : 0);
	UINT protocol = 0, size = 0;
	UCHAR *l4 = buf + header + ext;
	bool v4 = (addr_size == 4);

	if (addr_size == 0 || NatTestAddress(dst, p->Dst) != addr_size || (ext != 0 && v4) || (p->Kind == NATTEST_UDP_FRAG && v4 == false))
	{
		return 0;
	}

	if (p->QSrc != NULL)
	{
		NATTEST_PKT q;

		Zero(&q, sizeof(q));
		q.Src = p->QSrc;
		q.Dst = p->QDst;
		q.Kind = p->QKind;
		quoted_size = NatTestBuild(quoted, &q);
		if (p->QCut != 0)
		{
			quoted_size = MIN(quoted_size, header + p->QCut);
		}
	}

	Zero(buf, NATTEST_MAX_PACKET);
	switch (p->Kind)
	{
	case NATTEST_ECHO_REQUEST:
	case NATTEST_ECHO_REPLY:
		protocol = (v4 ? IP_PROTO_ICMPV4 : IP_PROTO_ICMPV6);
		size = 8 + NATTEST_DATA;
		if (p->Kind == NATTEST_ECHO_REQUEST)
		{
			l4[0] = (v4 ? 8 : 128);
		}
		else
		{
			l4[0] = (v4 ? 0 : 129);
		}
		WRITE_USHORT(l4 + 4, 0x4E41);
		WRITE_USHORT(l4 + 6, 1);
		for (UINT i = 0;i < NATTEST_DATA;i++)
		{
			l4[8 + i] = (UCHAR)('a' + i);
		}
		break;

	case NATTEST_UDP:
	case NATTEST_UDP0:
	case NATTEST_UDP_HOP:
	case NATTEST_UDP_FRAG:
		protocol = IP_PROTO_UDP;
		size = 8 + NATTEST_DATA;
		WRITE_USHORT(l4, 40000);
		WRITE_USHORT(l4 + 2, 53);
		WRITE_USHORT(l4 + 4, size);
		for (UINT i = 0;i < NATTEST_DATA;i++)
		{
			l4[8 + i] = (UCHAR)('A' + i);
		}
		break;

	case NATTEST_TCP_SYN:
		protocol = IP_PROTO_TCP;
		size = 20;
		WRITE_USHORT(l4, 40001);
		WRITE_USHORT(l4 + 2, 80);
		WRITE_UINT(l4 + 4, 0x01020304);
		l4[12] = 0x50;
		l4[13] = TCP_SYN;
		WRITE_USHORT(l4 + 14, 0xFFFF);
		break;

	case NATTEST_PORT_UNREACHABLE:
	case NATTEST_TIME_EXCEEDED:
	case NATTEST_TOO_BIG:
		protocol = (v4 ? IP_PROTO_ICMPV4 : IP_PROTO_ICMPV6);
		size = 8 + quoted_size;
		if (p->Kind == NATTEST_PORT_UNREACHABLE)
		{
			l4[0] = (v4 ? 3 : 1);
			l4[1] = (v4 ? 3 : 4);
		}
		else if (p->Kind == NATTEST_TIME_EXCEEDED)
		{
			l4[0] = (v4 ? 11 : 3);
		}
		else if (v4)
		{
			l4[0] = 3;
			l4[1] = 4;
			WRITE_USHORT(l4 + 6, p->Mtu);
		}
		else
		{
			l4[0] = 2;
			WRITE_UINT(l4 + 4, p->Mtu);
		}
		Copy(l4 + 8, quoted, quoted_size);
		break;

	default:
		return 0;
	}

	if (v4)
	{
		USHORT sum;

		buf[0] = 0x45;
		WRITE_USHORT(buf + 2, 20 + size);
		WRITE_USHORT(buf + 6, (p->Kind == NATTEST_UDP_FRAG ? 0x2000 : 0x4000));
		buf[8] = 64;
		buf[9] = (UCHAR)protocol;
		Copy(buf + 12, src, 4);
		Copy(buf + 16, dst, 4);
		sum = IpChecksum(buf, 20);
		Copy(buf + 10, &sum, 2);
	}
	else
	{
		buf[0] = 0x60;
		WRITE_USHORT(buf + 4, ext + size);
		buf[6] = (UCHAR)(ext != 0 ? IPV6_HEADER_HOP : protocol);
		buf[7] = 64;
		Copy(buf + 8, src, 16);
		Copy(buf + 24, dst, 16);
		if (ext != 0)
		{
			// A hop-by-hop options header of 8 bytes: the next header, its length (0) and a PadN option of 4 bytes
			buf[40] = (UCHAR)protocol;
			buf[42] = 1;
			buf[43] = 4;
		}
	}

	if (p->Kind != NATTEST_UDP0)
	{
		NatTestSum(buf, addr_size, l4, size, protocol);
	}

	return header + ext + size;
}

// The text of a packet: its addresses and what it is, the packet that an error quotes after it
static void NatTestDescribe(char *str, UINT str_size, const UCHAR *packet, UINT size)
{
	char src[64], dst[64], what[MAX_SIZE], quoted[MAX_SIZE];
	UINT v = (size >= 20 ? packet[0] >> 4 : 0);
	UINT header = (v == 4 ? (packet[0] & 0x0F) * 4 : 40);
	UINT a = (v == 4 ? 4 : 16);
	UINT protocol;
	const UCHAR *l4;
	UINT room;

	if ((v != 4 && v != 6) || size < header)
	{
		StrCpy(str, str_size, "no IP packet");
		return;
	}

	protocol = packet[v == 4 ? 9 : 6];
	if (v == 6 && protocol == IPV6_HEADER_HOP && size >= 48)
	{
		protocol = packet[40];
		header += 8;
	}
	l4 = packet + header;
	room = size - header;
	NatTestAddressStr(src, sizeof(src), packet + (v == 4 ? 12 : 8), a);
	NatTestAddressStr(dst, sizeof(dst), packet + (v == 4 ? 16 : 24), a);
	StrCpy(quoted, sizeof(quoted), "");

	if ((protocol == IP_PROTO_ICMPV4 || protocol == IP_PROTO_ICMPV6) && room >= 8)
	{
		char *name = (protocol == IP_PROTO_ICMPV4 ? "icmp" : "icmpv6");
		UINT type = l4[0], code = l4[1];

		if (type == (v == 4 ? 8U : 128U) || type == (v == 4 ? 0U : 129U))
		{
			Format(what, sizeof(what), "%s %s", name, (type == 8 || type == 128 ? "echo-request" : "echo-reply"));
		}
		else
		{
			Format(what, sizeof(what), "%s %u/%u", name, type, code);
			if (v == 4 && type == 3 && code == 4)
			{
				Format(what, sizeof(what), "%s fragmentation-needed mtu %u", name, (UINT)READ_USHORT(l4 + 6));
			}
			else if (v == 6 && type == 2)
			{
				Format(what, sizeof(what), "%s packet-too-big mtu %u", name, READ_UINT(l4 + 4));
			}
			else if ((v == 4 && type == 3 && code == 3) || (v == 6 && type == 1 && code == 4))
			{
				Format(what, sizeof(what), "%s port-unreachable", name);
			}
			else if ((v == 4 && type == 11) || (v == 6 && type == 3))
			{
				Format(what, sizeof(what), "%s time-exceeded", name);
			}

			if (room > 8)
			{
				char inner[MAX_SIZE];

				NatTestDescribe(inner, sizeof(inner), l4 + 8, room - 8);
				Format(quoted, sizeof(quoted), ", quoting %s", inner);
			}
		}
	}
	else if (protocol == IP_PROTO_UDP && room >= 8)
	{
		Format(what, sizeof(what), "udp %u > %u%s", (UINT)READ_USHORT(l4), (UINT)READ_USHORT(l4 + 2), (READ_USHORT(l4 + 6) == 0 ? " without checksum" : ""));
	}
	else if (protocol == IP_PROTO_TCP && room >= 14)
	{
		Format(what, sizeof(what), "tcp %u > %u%s", (UINT)READ_USHORT(l4), (UINT)READ_USHORT(l4 + 2), ((l4[13] & TCP_SYN) != 0 ? " syn" : ""));
	}
	else
	{
		Format(what, sizeof(what), "protocol %u", protocol);
	}

	Format(str, str_size, "%s > %s %s%s", src, dst, what, quoted);
}

// The text of a case of the translation
static void NatTestCaseText(char *str, UINT size, NATTEST_CASE *c, UCHAR *packet, UINT packet_size, UCHAR *want, UINT want_size)
{
	char from[MAX_SIZE], to[MAX_SIZE];

	NatTestDescribe(from, sizeof(from), packet, packet_size);
	switch (c->Result)
	{
	case NATTEST_GO:
		NatTestDescribe(to, sizeof(to), want, want_size);
		Format(str, size, "VRF %u, %s: %s goes as %s", c->VrfId, (c->Out ? "into the overlay" : "to the host"), from, to);
		break;
	case NATTEST_ASIS:
		Format(str, size, "VRF %u, %s: %s goes as it is", c->VrfId, (c->Out ? "into the overlay" : "to the host"), from);
		break;
	default:
		Format(str, size, "VRF %u, %s: %s is dropped", c->VrfId, (c->Out ? "into the overlay" : "to the host"), from);
		break;
	}
}

//
// The translation
//

// The state of the translation case: the rules of nattest_rules, and a peer whose route is 10.77.0.0/16 of lab
static CONTROL_STATE *NatTestRulesState()
{
	CONTROL_STATE *st = ZeroMalloc(sizeof(CONTROL_STATE));

	st->Generation = 1;
	StrCpy(st->Name, sizeof(st->Name), "node-a");
	for (UINT i = 0;i < sizeof(nattest_rules) / sizeof(nattest_rules[0]) && st->NumNats < CONTROL_MAX_NATS;i++)
	{
		NATTEST_RULE *r = &nattest_rules[i];
		CONTROL_NAT *c = &st->Nats[st->NumNats++];

		c->VrfId = r->VrfId;
		c->InsideSize = NatTestAddress(c->Inside, r->Inside);
		c->InsideLength = r->InsideLength;
		c->OutsideSize = NatTestAddress(c->Outside, r->Outside);
		c->OutsideLength = r->OutsideLength;
	}

	st->NumPeers = 1;
	st->Peers = ZeroMalloc(sizeof(CONTROL_PEER));
	StrCpy(st->Peers[0].Name, sizeof(st->Peers[0].Name), "node-b");
	st->Peers[0].NumRoutes = 1;
	st->Peers[0].Routes[0].VrfId = 303;
	st->Peers[0].Routes[0].AddressSize = NatTestAddress(st->Peers[0].Routes[0].Address, "10.77.0.0");
	st->Peers[0].Routes[0].Length = 16;

	return st;
}

static void NatTestFreeState(CONTROL_STATE *st)
{
	if (st != NULL)
	{
		Free(st->Peers);
		Free(st);
	}
}

// Run one case through the rules of v: what the translation did, as a check
static void NatTestOneCase(NATTEST_CTX *ctx, NODE_VRF_TABLES *v, NATTEST_CASE *c)
{
	UCHAR packet[NATTEST_MAX_PACKET], want[NATTEST_MAX_PACKET], out[NATTEST_MAX_PACKET + NODE_NAT_GROWTH];
	UCHAR src[16], dst[16];
	char what[MAX_SIZE * 2];
	UINT packet_size = NatTestBuild(packet, &c->Packet);
	UINT want_size = (c->Result == NATTEST_GO ? NatTestBuild(want, &c->Want) : 0);
	UINT result = NATTEST_DROP, out_size = 0, addr_size = 0;
	bool ends_ok = true;

	NatTestCaseText(what, sizeof(what), c, packet, packet_size, want, want_size);

	if (packet_size == 0 || (c->Result == NATTEST_GO && want_size == 0))
	{
		NatTestCheck(ctx, false, what, "the test cannot build its packets");
		return;
	}

	if (c->Out)
	{
		// Into the overlay: the addresses that the tables route, then the packet in the record
		bool ends = NodeNatEnds(v, c->VrfId, packet, packet_size, src, dst, &addr_size);

		Zero(out, sizeof(out));
		out_size = NodeNatCopy(v, c->VrfId, out, packet, packet_size);
		if (ends == false)
		{
			result = NATTEST_DROP;
			ends_ok = (out_size == 0);
		}
		else if (out_size == packet_size && Cmp(out, packet, packet_size) == 0)
		{
			result = NATTEST_ASIS;
		}
		else
		{
			result = NATTEST_GO;
		}
		if (ends)
		{
			// The tables route the addresses of the packet that goes into the record
			ends_ok = (out_size >= 20 && addr_size == ((out[0] >> 4) == 4 ? 4U : 16U) && Cmp(src, out + (addr_size == 4 ? 12 : 8), addr_size) == 0 &&
				Cmp(dst, out + (addr_size == 4 ? 16 : 24), addr_size) == 0);
		}
	}
	else
	{
		// To the host
		const UCHAR *p = packet;
		UINT size = packet_size;

		if (NodeNatInbound(v, c->VrfId, &p, &size, out, sizeof(out)) == false)
		{
			result = NATTEST_DROP;
		}
		else if (p == packet)
		{
			result = NATTEST_ASIS;
			out_size = packet_size;
			Copy(out, packet, packet_size);
		}
		else
		{
			result = NATTEST_GO;
			out_size = size;
		}
	}

	if (c->Result == NATTEST_GO)
	{
		char got[MAX_SIZE];

		NatTestDescribe(got, sizeof(got), out, out_size);
		NatTestCheck(ctx, result == NATTEST_GO && ends_ok && out_size == want_size && Cmp(out, want, want_size) == 0, what,
			"result %u, the addresses for the tables %s, %u bytes as %s, want %u bytes", result, (ends_ok ? "right" : "wrong"), out_size, got, want_size);
	}
	else
	{
		NatTestCheck(ctx, result == c->Result && ends_ok, what, "result %u, want %u; the addresses for the tables %s", result, c->Result, (ends_ok ? "right" : "wrong"));
	}
}

// The translation: every case through the rules of nattest_rules, and the routes that they add
static void NatTestTranslation(NATTEST_CTX *ctx)
{
	CONTROL_STATE *st = NatTestRulesState();
	NODE_VRF_TABLES *v = NodeNewVrfTables(1, NULL, 0, NULL, 0);
	NODE_VRF_ROUTE routes[8];
	UINT num_routes;

	Print("[translation]\n");

	if (NatTestCheck(ctx, v != NULL, "Empty forwarding tables of one Generation", "NodeNewVrfTables failed") == false)
	{
		NatTestFreeState(st);
		return;
	}

	v->Nat = NodeNewNat(st);
	NatTestCheck(ctx, v->Nat != NULL, "The rules of the state of the case", "NodeNewNat took none");

	for (UINT i = 0;i < sizeof(nattest_cases) / sizeof(nattest_cases[0]);i++)
	{
		NatTestOneCase(ctx, v, &nattest_cases[i]);
	}

	// The outside prefixes of the rules of one family lead to the host, the route of the peer to it: 10.99.1.0/24,
	// fd00:303:0:99::/64, 10.204.0.0/24, and 10.77.0.0/16 to next hop 0; neither 4via6 nor the refused rule
	Zero(routes, sizeof(routes));
	num_routes = NodeNatRoutes(st, NULL);
	NatTestCheck(ctx, num_routes == 4 && NodeNatRoutes(st, routes) == 4 &&
		routes[0].VrfId == 303 && routes[0].AddressSize == 4 && routes[0].Address[1] == 99 && routes[0].Length == 24 && routes[0].NextHop == NODE_VRF_LOCAL &&
		routes[1].VrfId == 303 && routes[1].AddressSize == 16 && routes[1].Address[7] == 0x99 && routes[1].Length == 64 && routes[1].NextHop == NODE_VRF_LOCAL &&
		routes[2].VrfId == 404 && routes[2].AddressSize == 4 && routes[2].Address[1] == 204 && routes[2].Length == 24 && routes[2].NextHop == NODE_VRF_LOCAL &&
		routes[3].VrfId == 303 && routes[3].AddressSize == 4 && routes[3].Address[1] == 77 && routes[3].Length == 16 && routes[3].NextHop == 0,
		"The rules add the routes of their outside prefixes to the host, and the routes of a peer to that peer", "%u routes", num_routes);

	NodeFreeVrfTables(v);
	NatTestFreeState(st);
}

//
// The overlay
//

// A new empty data directory under the temp directory of the process, with a configuration store that runs no role
// on one worker
static void NatTestNewDir(wchar_t *dir, UINT size, char *name)
{
	wchar_t tmp[MAX_PATH];
	wchar_t path[MAX_PATH];

	UniFormat(tmp, sizeof(tmp), L"nattest_%S_%u", name, Rand32());
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
static void NatTestDeleteFiles(wchar_t *dir)
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
static void NatTestDeleteDir(wchar_t *dir)
{
	wchar_t log_dir[MAX_PATH];

	ConbinePathW(log_dir, sizeof(log_dir), dir, NODE_LOG_DIR_NAME);
	NatTestDeleteFiles(log_dir);
	NatTestDeleteFiles(dir);
}

// The fake adapter of a host: it keeps each packet
static void NatTestAdapter(NODE *n, void *param, UINT vrf_id, const UCHAR *packet, UINT size)
{
	NATTEST_NODE *t = (NATTEST_NODE *)param;
	NATTEST_PACKET *p = ZeroMalloc(sizeof(NATTEST_PACKET));

	p->VrfId = vrf_id;
	p->Size = MIN(size, (UINT)sizeof(p->Data));
	Copy(p->Data, packet, p->Size);

	AcquireSRWLockExclusive(&t->Lock);
	Add(t->Packets, p);
	ReleaseSRWLockExclusive(&t->Lock);
}

// The packets that the host of t took
static UINT NatTestNumPackets(NATTEST_NODE *t)
{
	AcquireSRWLockShared(&t->Lock);
	UINT num = LIST_NUM(t->Packets);
	ReleaseSRWLockShared(&t->Lock);

	return num;
}

// A copy of the packet index that the host of t took
static void NatTestGetPacket(NATTEST_NODE *t, UINT index, NATTEST_PACKET *p)
{
	Zero(p, sizeof(NATTEST_PACKET));

	AcquireSRWLockShared(&t->Lock);
	if (index < LIST_NUM(t->Packets))
	{
		Copy(p, LIST_DATA(t->Packets, index), sizeof(NATTEST_PACKET));
	}
	ReleaseSRWLockShared(&t->Lock);
}

// The addresses of node i in the VRF vrf into a, at most max: their number
static UINT NatTestNodeAddresses(UINT i, UINT vrf, CONTROL_ADDRESS *a, UINT max)
{
	UINT num = 0;

	for (UINT k = 0;k < sizeof(nattest_addrs) / sizeof(nattest_addrs[0]) && num < max;k++)
	{
		NATTEST_ADDR *x = &nattest_addrs[k];

		if (x->Node != i || (vrf != INFINITE && x->Vrf != vrf))
		{
			continue;
		}

		CONTROL_ADDRESS *c = &a[num++];
		Zero(c, sizeof(CONTROL_ADDRESS));
		StrCpy(c->Network, sizeof(c->Network), nattest_vrf_names[x->Vrf]);
		c->VrfId = nattest_vrf_ids[x->Vrf];
		c->AddressSize = NatTestAddress(c->Address, x->Address);
		c->Length = 24;
	}

	return num;
}

// Whether node i of the overlay case has an address in the VRF vrf
static bool NatTestInVrf(UINT i, UINT vrf)
{
	CONTROL_ADDRESS a[CONTROL_MAX_ADDRESSES];

	return (NatTestNodeAddresses(i, vrf, a, CONTROL_MAX_ADDRESSES) != 0);
}

// The desired state of node i, as the controller compiles it: its addresses and its 1:1 NAT rules, and the nodes that
// share a VRF with it as its peers, with their addresses and the outside prefixes of their rules of one family in
// those VRFs as their routes
static CONTROL_STATE *NatTestState(NATTEST_NODE *nodes, UINT i)
{
	CONTROL_STATE *st = ZeroMalloc(sizeof(CONTROL_STATE));

	st->Generation = 1;
	StrCpy(st->Name, sizeof(st->Name), nattest_names[i]);
	st->NumAddresses = NatTestNodeAddresses(i, INFINITE, st->Addresses, CONTROL_MAX_ADDRESSES);
	st->Peers = ZeroMalloc(sizeof(CONTROL_PEER) * NATTEST_NUM_NODES);

	for (UINT k = 0;k < sizeof(nattest_node_rules) / sizeof(nattest_node_rules[0]);k++)
	{
		NATTEST_NODE_RULE *r = &nattest_node_rules[k];

		if (r->Node == i)
		{
			CONTROL_NAT *c = &st->Nats[st->NumNats++];

			c->VrfId = nattest_vrf_ids[r->Vrf];
			c->InsideSize = NatTestAddress(c->Inside, r->Inside);
			c->InsideLength = r->InsideLength;
			c->OutsideSize = NatTestAddress(c->Outside, r->Outside);
			c->OutsideLength = r->OutsideLength;
		}
	}

	for (UINT j = 0;j < NATTEST_NUM_NODES;j++)
	{
		CONTROL_PEER *p = &st->Peers[st->NumPeers];

		if (j == i)
		{
			continue;
		}

		Zero(p, sizeof(CONTROL_PEER));
		StrCpy(p->Name, sizeof(p->Name), nattest_names[j]);
		Copy(p->Key, nodes[j].Key.Public, PEER_KEY_SIZE);
		for (UINT vrf = NATTEST_RED;vrf <= NATTEST_LAB;vrf++)
		{
			if (NatTestInVrf(i, vrf) == false || NatTestInVrf(j, vrf) == false)
			{
				continue;
			}

			p->VrfIds[p->NumVrfs++] = nattest_vrf_ids[vrf];
			p->NumAddresses += NatTestNodeAddresses(j, vrf, &p->Addresses[p->NumAddresses], CONTROL_MAX_ADDRESSES - p->NumAddresses);
			for (UINT k = 0;k < sizeof(nattest_node_rules) / sizeof(nattest_node_rules[0]);k++)
			{
				NATTEST_NODE_RULE *r = &nattest_node_rules[k];
				UCHAR inside[16];

				if (r->Node == j && r->Vrf == vrf && NatTestAddress(inside, r->Inside) == NatTestAddress(inside, r->Outside))
				{
					CONTROL_ROUTE *route = &p->Routes[p->NumRoutes++];

					route->VrfId = nattest_vrf_ids[vrf];
					route->AddressSize = NatTestAddress(route->Address, r->Outside);
					route->Length = r->OutsideLength;
				}
			}
		}

		if (p->NumVrfs != 0)
		{
			st->NumPeers++;
		}
	}

	return st;
}

// Whether every node has a session to each of its peers within NATTEST_BOUND
static bool NatTestWaitLinks(NATTEST_NODE *nodes, UINT *want)
{
	UINT64 end = Tick64() + NATTEST_BOUND;

	while (true)
	{
		bool all = true;

		for (UINT i = 0;i < NATTEST_NUM_NODES;i++)
		{
			NODE_OVERLAY_STATUS st;

			NodeOverlayGetStatus(nodes[i].Node, &st);
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
		SleepThread(NATTEST_POLL);
	}
}

// Where the packet of one send went within NATTEST_BOUND: to the host of which node, in which VRF and as which
// packet, or dropped by which node; num_before and dropped_before are the packets that each host took and the drops
// of each node before. ok tells whether that is what the send wants.
static void NatTestOutcome(NATTEST_NODE *nodes, NATTEST_SEND *send, UINT *num_before, UINT64 *dropped_before, char *outcome, UINT outcome_size, bool *ok)
{
	UINT64 end = Tick64() + NATTEST_BOUND;
	UCHAR want[NATTEST_MAX_PACKET];
	UINT want_size = (send->To != NATTEST_NONE ? NatTestBuild(want, &send->Want) : 0);

	StrCpy(outcome, outcome_size, "lost");
	*ok = false;

	while (Tick64() < end)
	{
		for (UINT i = 0;i < NATTEST_NUM_NODES;i++)
		{
			NODE_OVERLAY_STATUS st;

			if (NatTestNumPackets(&nodes[i]) > num_before[i])
			{
				NATTEST_PACKET p;
				char text[MAX_SIZE];
				char *vrf = "an unknown VRF";
				bool same;

				NatTestGetPacket(&nodes[i], num_before[i], &p);
				for (UINT v = 0;v < 3;v++)
				{
					if (nattest_vrf_ids[v] == p.VrfId)
					{
						vrf = nattest_vrf_names[v];
					}
				}

				same = (want_size != 0 && p.Size == want_size && Cmp(p.Data, want, want_size) == 0);
				NatTestDescribe(text, sizeof(text), p.Data, p.Size);
				Format(outcome, outcome_size, "delivered to %s in %s as %s, %s", nodes[i].Name, vrf, text, (same ? "the packet expected" : "NOT the packet expected"));
				*ok = (same && i == send->To && p.VrfId == nattest_vrf_ids[send->Vrf]);
				return;
			}

			NodeOverlayGetStatus(nodes[i].Node, &st);
			if (st.Dropped > dropped_before[i])
			{
				Format(outcome, outcome_size, "dropped by %s", nodes[i].Name);
				*ok = (send->To == NATTEST_NONE && i == send->From);
				return;
			}
		}

		SleepThread(1);
	}
}

// The packets of the overlay case, their outcomes and the counters of the nodes, as the text of the golden file;
// *all_ok tells whether every packet went where and as the case wants
static char *NatTestSends(NATTEST_NODE *nodes, bool *all_ok)
{
	BUF *b = NewBuf();
	char line[MAX_SIZE * 2];
	UINT num = sizeof(nattest_sends) / sizeof(nattest_sends[0]);

	*all_ok = true;
	Format(line, sizeof(line), "# red (%u, 4via6 fd00:101:0:ffff::/96) and blue (%u, 4via6 fd00:202:0:ffff::/96) both use 10.0.0.0/24; in lab (%u) node-d presents 192.168.1.0/24 as 10.99.1.0/24\n",
		nattest_vrf_ids[NATTEST_RED], nattest_vrf_ids[NATTEST_BLUE], nattest_vrf_ids[NATTEST_LAB]);
	WriteBuf(b, line, StrLen(line));

	for (UINT k = 0;k < num;k++)
	{
		NATTEST_SEND *send = &nattest_sends[k];
		NATTEST_NODE *t = &nodes[send->From];
		UINT num_before[NATTEST_NUM_NODES];
		UINT64 dropped_before[NATTEST_NUM_NODES];
		UCHAR packet[NATTEST_MAX_PACKET];
		char sent[MAX_SIZE];
		char outcome[MAX_SIZE];
		bool ok = false;

		for (UINT i = 0;i < NATTEST_NUM_NODES;i++)
		{
			NODE_OVERLAY_STATUS st;

			NodeOverlayGetStatus(nodes[i].Node, &st);
			num_before[i] = NatTestNumPackets(&nodes[i]);
			dropped_before[i] = st.Dropped;
		}

		UINT size = NatTestBuild(packet, &send->Sent);
		NatTestDescribe(sent, sizeof(sent), packet, size);

		NodeReaderOnline(t->Node, &t->Reader);
		NodeOverlayInput(t->Node, nattest_vrf_ids[send->Vrf], packet, size);
		NodeReaderOffline(&t->Reader);

		NatTestOutcome(nodes, send, num_before, dropped_before, outcome, sizeof(outcome), &ok);
		if (ok == false)
		{
			*all_ok = false;
		}

		Format(line, sizeof(line), "%s: %s %s: %s\n", nattest_vrf_names[send->Vrf], nattest_names[send->From], sent, outcome);
		Print("  %s", line);
		WriteBuf(b, line, StrLen(line));
	}

	for (UINT i = 0;i < NATTEST_NUM_NODES;i++)
	{
		NODE_OVERLAY_STATUS st;

		NodeOverlayGetStatus(nodes[i].Node, &st);
		Format(line, sizeof(line), "%s: forwarded %I64u, delivered %I64u, dropped %I64u, VRFs %u\n", nodes[i].Name, st.Forwarded, st.Delivered, st.Dropped, st.NumVrfs);
		Print("  %s", line);
		WriteBuf(b, line, StrLen(line));
	}

	char *text = HarnessBufToStr(b);
	FreeBuf(b);

	return text;
}

static void NatTestOverlay(NATTEST_CTX *ctx)
{
	NATTEST_NODE *nodes = ZeroMalloc(sizeof(NATTEST_NODE) * NATTEST_NUM_NODES);
	TRANSPORT *loopback = TransportLoopbackNew("loopback", 0, false);
	UCHAR scalar[PEER_KEY_SIZE];
	char out_dir[MAX_SIZE];
	char golden_dir[MAX_SIZE];
	char what[MAX_SIZE];
	bool update;
	bool started = (loopback != NULL);
	UINT want_links[NATTEST_NUM_NODES] = {3, 1, 1, 1};

	Print("[overlay]\n");

	// The nodes, each with its static key and the fake adapter of its host, and their overlays without a control stream
	for (UINT i = 0;i < NATTEST_NUM_NODES && started;i++)
	{
		NATTEST_NODE *t = &nodes[i];
		NODE_OVERLAY_CONFIG c;

		t->Name = nattest_names[i];
		InitializeSRWLock(&t->Lock);
		t->Packets = NewListFast(NULL);
		for (UINT j = 0;j < PEER_KEY_SIZE;j++)
		{
			scalar[j] = (UCHAR)(1 + PEER_KEY_SIZE * i + j);
		}
		started = PeerKeyFromScalar(&t->Key, scalar);

		NatTestNewDir(t->Dir, sizeof(t->Dir), t->Name);
		t->Node = NewNode(t->Dir);
		NodeStart(t->Node);
		NodeReaderRegister(t->Node, &t->Reader);
		NodeReaderOffline(&t->Reader);

		Zero(&c, sizeof(c));
		c.Data = loopback;
		c.Key = &t->Key;
		c.Adapter = NatTestAdapter;
		c.AdapterParam = t;
		Format(what, sizeof(what), "%s: its overlay runs without a control stream", t->Name);
		started = NatTestCheck(ctx, started && NodeOverlayStart(t->Node, &c), what, "NodeOverlayStart failed") && started;
	}
	Zero(scalar, sizeof(scalar));

	if (started)
	{
		bool applied = true;

		for (UINT i = 0;i < NATTEST_NUM_NODES;i++)
		{
			CONTROL_STATE *st = NatTestState(nodes, i);

			applied = NodeOverlayApply(nodes[i].Node, st) && applied;
			NatTestFreeState(st);
		}

		bool linked = NatTestWaitLinks(nodes, want_links);
		started = NatTestCheck(ctx, applied && linked, "The four nodes apply their states, with the 4via6 of node-a and the 1:1 NAT of node-d, and every session is up",
			"applied %u, sessions %u", (UINT)applied, (UINT)linked);
	}

	if (started)
	{
		HARNESS h;
		bool all_ok = false;

		HarnessGetFamilyDirs("nat", out_dir, sizeof(out_dir), golden_dir, sizeof(golden_dir), &update);
		MakeDirEx(out_dir);
		Print("NAT GOLDEN MODE %s\n", update ? "update" : "compare");
		Print("  golden directory: %s\n", golden_dir);

		char *text = NatTestSends(nodes, &all_ok);
		NatTestCheck(ctx, all_ok, "Every packet of the overlay arrives at the host the case names, in its VRF, as the packet the test builds for that side, or is dropped where the case says",
			"see the lines above");
		Zero(&h, sizeof(h));
		HarnessCompareGolden(&h, out_dir, golden_dir, NATTEST_GOLDEN, text, update);
		Free(text);
		NatTestCheck(ctx, h.NumFail == 0, "4via6 and 1:1 NAT over the overlay: the packets arrive as the golden file " NATTEST_GOLDEN " says", "it differs");
	}

	for (UINT i = 0;i < NATTEST_NUM_NODES;i++)
	{
		NATTEST_NODE *t = &nodes[i];

		if (t->Node != NULL)
		{
			NodeReaderUnregister(t->Node, &t->Reader);
			NodeStop(t->Node);
			FreeNode(t->Node);
			NatTestDeleteDir(t->Dir);
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
	}

	TransportLoopbackFree(loopback);
	Free(nodes);
}

// nat: 1:1 NAT and 4via6 of the data plane, on packets and over the overlay
RANZ_TEST("nat", nat_test, "1:1 NAT and 4via6: packets through the rules of four VRFs against packets that the test builds, ICMP errors included; over the overlay a host in two VRFs on 10.0.0.0/24 reaches 10.0.0.5 in each through two 4via6 addresses, and a 1:1 NAT rule rewrites both ways (golden family nat).");
void nat_test(UINT num, char **arg)
{
	NATTEST_CTX ctx;
	HANDLE done = CreateEventW(NULL, TRUE, FALSE, NULL);
	HANDLE watchdog = (done != NULL ? CreateThread(NULL, 0, NatTestWatchdog, done, 0, NULL) : NULL);

	Zero(&ctx, sizeof(ctx));

	Print("NAT test: 1:1 NAT and 4via6 of the node's data plane, on packets against packets that the test builds, and over the overlay of in-process nodes\n");

	NatTestTranslation(&ctx);
	NatTestOverlay(&ctx);

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
		Print("NAT TEST OK\n");
	}
	else
	{
		Print("NAT TEST FAILED (%u of %u checks failed)\n", ctx.NumFailed, ctx.NumChecks);
	}
}
