// operationstest.c
// Named live operations test of vpntest ("operations" command, SDN-50-N #492)
//
// A Node answers the Operation frames of the Controller (ADR-0027 and ADR-0031 amendments of 2026-10-27): it reads and clears
// the MAC table and the IP table of the switch of an L2 Network that it holds. In process, as seam 2 of #45 runs the switch:
// - The IP table of the switch (Core/SwitchIp.c): the source of an IPv4 packet, the sender of an ARP packet and the source of
//   an IPv6 packet are learnt per VLAN with the MAC address and the port of their frame, and no address that no host sends
//   from, nor one of a frame cut short or of another EtherType; an address that another MAC address sends from moves to it;
//   a read gives the first entries by VLAN, then IPv4 before IPv6, then by address, and the MAC table its first ones too; a
//   clear takes every entry or the entries of one address, in every VLAN, and the MAC table the entries of one MAC address;
//   the table ages with the MAC table, forgets the entries of a port that goes, and a full table refuses more.
// - The node: a Node whose overlay has its control stream to a stand-in of the Controller of this file over a bound loopback
//   transport (Core/Control.h): the handshake bound to its exporter, the Hello, the Update of the desired state with the L2
//   Network lan and the L3 Network wan, and the Operations, which the stand-in sends and whose OperationResult frames it reads
//   as the Controller does, with the messages that nanopb generates from control.proto, the ones of the frames that the
//   controller conformance tests exchange (the nanopb round trip of tests/control): every answer decodes and encodes back to
//   its bytes. The Hello reports the Capability operations. The L2 data path of the test attaches the switch of lan
//   (NodeOperationAttach), whose members client-a, client-b and bridge send ARP, IPv4 and IPv6 in VLAN 1 and VLAN 7. A read
//   of the MAC table and of the IP table gives the entries that the switch learnt, in the TableEntry form, with the member
//   of each and the time of its last frame; a clear of one entry and of every entry takes them out, the next read shows them
//   gone and the traffic that follows learns them again; an Operation for wan, an L3 Network, or for dmz, which the node does
//   not hold, is no-network; one of no kind, or with a MAC address of 5 bytes, failed; a table of more than 512 entries is
//   listed with its first 512 and its total; and once the switch is detached the node holds no table of lan. The stream
//   stays up through all of it.
// Print "OPERATIONS TEST OK" only when every check passes.
//
// "opstrace" is the harness Node of the operations tracer (.github/scripts/operations-tracer.ps1), which asks it through a
// running ranz controller: "vpntest opstrace <host:port> <key> <ready file> <again file> <stop file>", the address of the
// controller's TLS port and its static key in base64. node-a, with the static key of sdntrace.c, opens its control stream to
// the controller over the TLS transport of sdntrace.c (controltls.h), whose Intent holds its Node resource and the L2 Network
// lan in its VRF. Its Hello reports the Capabilities of the host, the L2 backend that the switch of the test stands in for
// (the Controller refuses a node that holds an L2 Network and reports neither XDP nor SeLow) and the Capability operations.
// Once it applied its state, the test attaches the switch of lan with its members and sends their traffic, prints a line
// "OPSTRACE MEMBER <name> VLAN <vlan> MAC <mac> ADDRESS <address>" for each member and creates the ready file; then it runs
// until the stop file exists, and whenever the again file exists it deletes it, sends the traffic again and creates the ready
// file anew, so that the script sees the tables learnt again after its clears. At its end it prints the operations of the
// node log. Print "OPSTRACE TEST OK" only when every check passes.

#include "controltls.h"
#include "testlist.h"

#include "Cedar/ConfigStore.h"
#include "Cedar/Node.h"
#include "Cedar/NodeCaps.h"

#include "Mayaqua/Encrypt.h"
#include "Mayaqua/FileIO.h"
#include "Mayaqua/Internat.h"
#include "Mayaqua/Kernel.h"
#include "Mayaqua/Memory.h"
#include "Mayaqua/Microsoft.h"
#include "Mayaqua/Str.h"
#include "Mayaqua/Tick64.h"

#include "Core/Control.h"
#include "Core/Crypto.h"
#include "Core/Switch.h"
#include "Core/Transport.h"

#include <pb_decode.h>
#include <pb_encode.h>

#include "ranz/control/v1/control.pb.h"

#include <stdio.h>

#define	OPS_BUDGET			120000		// The whole test ends within this time, or the watchdog ends the process (ms)
#define	OPS_BOUND			20000		// A bounded wait on the node: its stream, an Ack, an answer (ms)
#define	OPS_READ			100			// ms that one read of the control stream at the stand-in waits
#define	OPS_FRAME_HEADER	4			// The size of a frame of a control stream, big-endian, before its message
#define	OPS_MAX_FRAME		(1 << 20)	// The largest frame that the stand-in reads, as the node does (CONTROL_MAX_FRAME)
#define	OPS_OUT_FRAME		65536		// The largest frame that the stand-in writes
#define	OPS_MAX_RESULT		65536		// The largest OperationResult that the Controller takes (MaxOperationResult of controller/internal/control)
#define	OPS_VRF				1			// The id of VRF default
#define	OPS_VLAN			1			// The VLAN of the clients of lan
#define	OPS_BRIDGE_VLAN		7			// ... and the other VLAN of the trunk port of the bridge
#define	OPS_SOURCES			600			// The sources of the limits case: more than an answer lists
#define	OPS_LIST			64			// The entries of a table that the cases of the switch list at most
#define	OPS_SMALL_IPS		8			// The IP table of the full-table case
#define	OPS_AGING			5000		// The aging time of the switch of the cases of the switch (ms)
#define	OPS_SHOW			4096		// The text of a table at most

// What a read of a frame of the control stream at the stand-in gave
#define	OPS_FRAME_DONE		0			// A whole frame is in Frame
#define	OPS_FRAME_LATER		1			// Not within the timeout: the bytes read so far stay in Frame
#define	OPS_FRAME_END		2			// The stream ended, or its next frame is larger than allowed

// The members of lan on the switch of the node
#define	OPS_CLIENT_A		0
#define	OPS_CLIENT_B		1
#define	OPS_BRIDGE			2
#define	OPS_NUM_MEMBERS		3

static char *ops_members[OPS_NUM_MEMBERS] = {"client-a", "client-b", "bridge"};
static const UCHAR ops_macs[OPS_NUM_MEMBERS][6] = {
	{0x02, 0x00, 0x00, 0x00, 0x50, 0x0A},
	{0x02, 0x00, 0x00, 0x00, 0x50, 0x0B},
	{0x02, 0x00, 0x00, 0x00, 0x50, 0x1E},
};
static const UCHAR ops_bc[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
static const UCHAR ops_ip_a[4] = {10, 20, 0, 8};
static const UCHAR ops_ip_b[4] = {10, 20, 0, 9};
static const UCHAR ops_ip_x[4] = {192, 0, 2, 7};
static const UCHAR ops_ip6_b[16] = {0xFD, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x09};

// The stand-in of the Controller: the controller's end of the control stream of the node
typedef struct OPS_STANDIN
{
	TRANSPORT *Transport;						// The bound loopback transport of the control stream
	TRANSPORT_LISTENER *Listener;				// ... where it listens
	PEER_KEY Key;								// Its static key
	TRANSPORT_STREAM *Stream;					// The control stream of the node, once it took it
	UCHAR *Frame;								// The frame being read: its size, then its message
	UINT FrameSize;								// ... its bytes read so far
	UCHAR *Out;									// The frame being written
	UCHAR *Again;								// A message encoded once more, for the round trip
	ranz_control_v1_ControlMessage *Message;	// The message read last, or written
	UINT64 NextId;								// The id of the next Operation
	UINT Answers;								// The answers that it read
	UINT RoundTrips;							// ... of them that nanopb encoded back to their bytes
	UINT LargestFrame;							// ... and the size of the largest
} OPS_STANDIN;

// The state of the test
typedef struct OPS_CTX
{
	UINT NumChecks;
	UINT NumFailed;
	OPS_STANDIN Standin;
	TRANSPORT *Data;							// The transport of the Noise sessions, which this node does not dial
	PEER_KEY NodeKey;							// The static key of the node
	wchar_t Dir[MAX_PATH];						// Its data directory
	NODE *Node;
	SWITCH *Switch;								// The switch of lan, which the L2 data path of the test attaches
	UINT Ports[OPS_NUM_MEMBERS];				// ... the ports of its members
	bool LongNames;								// The members have names of 63 characters (the limits case)
	ranz_control_v1_OperationResult *Result;	// The answer to the Operation that the stand-in sent last
	UINT Status;								// ... its status, as the stand-in read it
} OPS_CTX;

static bool OpsCheck(OPS_CTX *ctx, bool ok, char *what, char *fmt, ...) RANZ_PRINTF_FORMAT(4, 5);
static bool OpsCheck(OPS_CTX *ctx, bool ok, char *what, char *fmt, ...)
{
	char detail[MAX_SIZE * 4];
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

// The watchdog: a native thread that ends a run that hangs, so that a lost answer is a failed test instead of a hung CI step
static DWORD WINAPI OpsWatchdog(LPVOID param)
{
	char msg[MAX_SIZE];
	DWORD written = 0;

	if (WaitForSingleObject((HANDLE)param, OPS_BUDGET) != WAIT_TIMEOUT)
	{
		return 0;
	}

	int len = snprintf(msg, sizeof(msg), "OPERATIONS TEST FAILED (did not finish within %u ms)\n", (UINT)OPS_BUDGET);
	if (len > 0)
	{
		WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), msg, (DWORD)MIN((UINT)len, (UINT)sizeof(msg) - 1), &written, NULL);
	}

	TerminateProcess(GetCurrentProcess(), 1);

	return 0;
}

// The Unix time in ms
static UINT64 OpsUnixNow()
{
	FILETIME ft;

	GetSystemTimeAsFileTime(&ft);
	UINT64 t = ((UINT64)ft.dwHighDateTime << 32) | ft.dwLowDateTime;

	return (t - 116444736000000000ULL) / 10000;
}

//
// The frames of the members
//

// A frame from src to dst of the EtherType type, with a VLAN tag of vlan when it is not 0, and its payload: its size
static UINT OpsFrame(UCHAR *buf, const UCHAR *dst, const UCHAR *src, UINT vlan, USHORT type, const UCHAR *payload, UINT size)
{
	UINT pos = 12;

	Copy(buf, dst, 6);
	Copy(buf + 6, src, 6);
	if (vlan != 0)
	{
		WRITE_USHORT(buf + pos, SWITCH_TPID_8021Q);
		WRITE_USHORT(buf + pos + 2, vlan);
		pos += 4;
	}
	WRITE_USHORT(buf + pos, type);
	Copy(buf + pos + 2, payload, size);

	return pos + 2 + size;
}

// An IPv4 packet from src to dst of UDP, its header and a UDP header of 8 bytes, cut to size bytes, with the version
// version: its frame
static UINT OpsIpv4(UCHAR *buf, const UCHAR *dst_mac, const UCHAR *src_mac, UINT vlan, const UCHAR *src, const UCHAR *dst, UINT size, UINT version)
{
	UCHAR ip[28];

	Zero(ip, sizeof(ip));
	ip[0] = (UCHAR)((version << 4) | 5);
	ip[3] = sizeof(ip);
	ip[8] = 64;
	ip[9] = 17;
	Copy(ip + 12, src, 4);
	Copy(ip + 16, dst, 4);

	return OpsFrame(buf, dst_mac, src_mac, vlan, 0x0800, ip, MIN(size, (UINT)sizeof(ip)));
}

// An ARP request of the sender src_mac, src for target: its frame, to the broadcast address
static UINT OpsArp(UCHAR *buf, const UCHAR *src_mac, const UCHAR *src, const UCHAR *target)
{
	UCHAR arp[28];

	Zero(arp, sizeof(arp));
	WRITE_USHORT(arp, 1);
	WRITE_USHORT(arp + 2, 0x0800);
	arp[4] = 6;
	arp[5] = 4;
	WRITE_USHORT(arp + 6, 1);
	Copy(arp + 8, src_mac, 6);
	Copy(arp + 14, src, 4);
	Copy(arp + 24, target, 4);

	return OpsFrame(buf, ops_bc, src_mac, 0, 0x0806, arp, sizeof(arp));
}

// An IPv6 packet from src to dst with no next header: its frame
static UINT OpsIpv6(UCHAR *buf, const UCHAR *dst_mac, const UCHAR *src_mac, UINT vlan, const UCHAR *src, const UCHAR *dst)
{
	UCHAR ip[40];

	Zero(ip, sizeof(ip));
	ip[0] = 0x60;
	ip[6] = 59;
	ip[7] = 64;
	Copy(ip + 8, src, 16);
	Copy(ip + 24, dst, 16);

	return OpsFrame(buf, dst_mac, src_mac, vlan, 0x86DD, ip, sizeof(ip));
}

// The procedure of every member of a switch of the test: it takes the frames and keeps none
static void OpsSend(void *param, UINT port, const UCHAR *frame, UINT size)
{
	UNREFERENCED_PARAMETER(param);
	UNREFERENCED_PARAMETER(port);
	UNREFERENCED_PARAMETER(frame);
	UNREFERENCED_PARAMETER(size);
}

// A port of the switch sw for a member: an access port of vlan, or with trunk a trunk port of vlan and of trunk (no native
// VLAN), subscribed to the broadcast group of vlan
static UINT OpsPort(SWITCH *sw, UINT vlan, UINT trunk)
{
	SWITCH_PORT_CONFIG p;
	USHORT allowed[2];

	Zero(&p, sizeof(p));
	p.Send = OpsSend;
	p.Mode = SWITCH_ACCESS;
	p.Vlan = vlan;
	if (trunk != 0)
	{
		allowed[0] = (USHORT)vlan;
		allowed[1] = (USHORT)trunk;
		p.Mode = SWITCH_TRUNK;
		p.Vlan = 0;
		p.Allowed = allowed;
		p.NumAllowed = 2;
	}

	UINT port = SwitchAddPort(sw, &p);
	if (port != SWITCH_PORT_NONE && SwitchSubscribe(sw, port, vlan, ops_bc) == false)
	{
		SwitchDelPort(sw, port);
		return SWITCH_PORT_NONE;
	}

	return port;
}

// An address as text: dotted for IPv4, 32 hex digits for IPv6
static void OpsAddress(char *str, UINT str_size, const UCHAR *addr, UINT size)
{
	if (size == 4)
	{
		Format(str, str_size, "%u.%u.%u.%u", (UINT)addr[0], (UINT)addr[1], (UINT)addr[2], (UINT)addr[3]);
		return;
	}

	str[0] = 0;
	for (UINT i = 0;i < size && i < 16;i++)
	{
		char hex[4];

		Format(hex, sizeof(hex), "%02x", (UINT)addr[i]);
		StrCat(str, str_size, hex);
	}
}

// A MAC address as text
static void OpsMac(char *str, UINT size, const UCHAR *mac)
{
	Format(str, size, "%02x:%02x:%02x:%02x:%02x:%02x", (UINT)mac[0], (UINT)mac[1], (UINT)mac[2], (UINT)mac[3], (UINT)mac[4], (UINT)mac[5]);
}

//
// The IP table of the switch
//

// The IP table of sw as text, its first max entries: one line "<vlan> <address> <mac> <port>" each
static UINT OpsIps(SWITCH *sw, UINT max, char *text, UINT size)
{
	SWITCH_IP_ENTRY list[OPS_LIST];
	UINT num = SwitchGetIps(sw, list, MIN(max, (UINT)OPS_LIST));

	text[0] = 0;
	for (UINT i = 0;i < num;i++)
	{
		char addr[64], mac[32], line[MAX_SIZE];

		OpsAddress(addr, sizeof(addr), list[i].Address, list[i].AddressSize);
		OpsMac(mac, sizeof(mac), list[i].Mac);
		Format(line, sizeof(line), "%u %s %s %u\n", list[i].Vlan, addr, mac, list[i].Port);
		StrCat(text, size, line);
	}

	return num;
}

// The IP table of the switch: what it learns, the moves, the first entries, the clears, the ports that go, the ageing and a
// full table; and the MAC table: the clear of one MAC address and its first entries
static void OpsSwitchCases(OPS_CTX *ctx)
{
	static const UCHAR zero4[4] = {0, 0, 0, 0};
	static const UCHAR loop4[4] = {127, 0, 0, 1};
	static const UCHAR mcast4[4] = {224, 0, 0, 5};
	static const UCHAR none6[16] = {0};
	static const UCHAR loop6[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};
	static const UCHAR mcast6[16] = {0xFF, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};
	char text[OPS_SHOW];
	char expect[OPS_SHOW];
	UCHAR frame[128];
	SWITCH_CONFIG c;
	SWITCH_STATS st;
	UINT size;

	Print("[the IP table of the switch]\n");

	Zero(&c, sizeof(c));
	c.MaxPorts = 4;
	c.AgingTime = OPS_AGING;
	c.MaxIps = SWITCH_MAX_IPS + 1;
	SWITCH *refused = SwitchNew(&c);
	OpsCheck(ctx, refused == NULL, "a switch of more IP table entries than SWITCH_MAX_IPS is refused", "SwitchNew made one");
	SwitchFree(refused);

	c.MaxIps = 0;
	SWITCH *sw = SwitchNew(&c);
	UINT a = (sw != NULL ? OpsPort(sw, OPS_VLAN, 0) : SWITCH_PORT_NONE);
	UINT b = (sw != NULL ? OpsPort(sw, OPS_VLAN, 0) : SWITCH_PORT_NONE);
	UINT t = (sw != NULL ? OpsPort(sw, OPS_VLAN, OPS_BRIDGE_VLAN) : SWITCH_PORT_NONE);
	if (OpsCheck(ctx, sw != NULL && a != SWITCH_PORT_NONE && b != SWITCH_PORT_NONE && t != SWITCH_PORT_NONE, "a switch of two access ports of VLAN 1 and a trunk port of VLANs 1 and 7",
		"SwitchNew, SwitchAddPort or SwitchSubscribe failed") == false)
	{
		SwitchFree(sw);
		return;
	}

	// What it learns: an IPv4 source, an ARP sender and an IPv6 source, and the same address in another VLAN
	size = OpsIpv4(frame, ops_macs[OPS_CLIENT_B], ops_macs[OPS_CLIENT_A], 0, ops_ip_a, ops_ip_b, 28, 4);
	SwitchInput(sw, 1000, a, frame, size);
	size = OpsArp(frame, ops_macs[OPS_CLIENT_B], ops_ip_b, ops_ip_a);
	SwitchInput(sw, 1000, b, frame, size);
	size = OpsIpv6(frame, ops_macs[OPS_CLIENT_A], ops_macs[OPS_CLIENT_B], 0, ops_ip6_b, ops_ip6_b);
	SwitchInput(sw, 1000, b, frame, size);
	size = OpsIpv4(frame, ops_bc, ops_macs[OPS_BRIDGE], OPS_BRIDGE_VLAN, ops_ip_a, ops_ip_x, 28, 4);
	SwitchInput(sw, 1000, t, frame, size);

	// ... and what it does not: the sources that no host sends from, a header cut short, another version and another EtherType
	size = OpsIpv4(frame, ops_bc, ops_macs[OPS_CLIENT_A], 0, zero4, ops_ip_b, 28, 4);
	SwitchInput(sw, 1000, a, frame, size);
	size = OpsIpv4(frame, ops_bc, ops_macs[OPS_CLIENT_A], 0, loop4, ops_ip_b, 28, 4);
	SwitchInput(sw, 1000, a, frame, size);
	size = OpsIpv4(frame, ops_bc, ops_macs[OPS_CLIENT_A], 0, mcast4, ops_ip_b, 28, 4);
	SwitchInput(sw, 1000, a, frame, size);
	size = OpsIpv4(frame, ops_bc, ops_macs[OPS_CLIENT_A], 0, ops_ip_x, ops_ip_b, 19, 4);
	SwitchInput(sw, 1000, a, frame, size);
	size = OpsIpv4(frame, ops_bc, ops_macs[OPS_CLIENT_A], 0, ops_ip_x, ops_ip_b, 28, 6);
	SwitchInput(sw, 1000, a, frame, size);
	size = OpsArp(frame, ops_macs[OPS_CLIENT_A], zero4, ops_ip_x);
	SwitchInput(sw, 1000, a, frame, size);
	size = OpsIpv6(frame, ops_bc, ops_macs[OPS_CLIENT_B], 0, none6, ops_ip6_b);
	SwitchInput(sw, 1000, b, frame, size);
	size = OpsIpv6(frame, ops_bc, ops_macs[OPS_CLIENT_B], 0, loop6, ops_ip6_b);
	SwitchInput(sw, 1000, b, frame, size);
	size = OpsIpv6(frame, ops_bc, ops_macs[OPS_CLIENT_B], 0, mcast6, ops_ip6_b);
	SwitchInput(sw, 1000, b, frame, size);
	size = OpsFrame(frame, ops_bc, ops_macs[OPS_CLIENT_A], 0, 0x88B5, ops_ip_x, 4);
	SwitchInput(sw, 1000, a, frame, size);

	OpsIps(sw, OPS_LIST, text, sizeof(text));
	SwitchGetStats(sw, &st);
	Format(expect, sizeof(expect), "1 10.20.0.8 02:00:00:00:50:0a %u\n1 10.20.0.9 02:00:00:00:50:0b %u\n1 fd000000000000000000000000000009 02:00:00:00:50:0b %u\n7 10.20.0.8 02:00:00:00:50:1e %u\n", a, b, b, t);
	OpsCheck(ctx, StrCmp(text, expect) == 0 && st.NumIps == 4 && st.IpsLearnt == 4,
		"the IP table learns the IPv4 source, the ARP sender and the IPv6 source of each VLAN with the MAC address and the port of its frame, by VLAN, then IPv4 before IPv6, and no address that no host sends from",
		"%u entries, %I64u learnt:\n%s", st.NumIps, st.IpsLearnt, text);

	// A move: client-b sends from the address of client-a; and the first two entries alone
	size = OpsIpv4(frame, ops_macs[OPS_CLIENT_A], ops_macs[OPS_CLIENT_B], 0, ops_ip_a, ops_ip_b, 28, 4);
	SwitchInput(sw, 2000, b, frame, size);
	UINT num = OpsIps(sw, 2, text, sizeof(text));
	SwitchGetStats(sw, &st);
	Format(expect, sizeof(expect), "1 10.20.0.8 02:00:00:00:50:0b %u\n1 10.20.0.9 02:00:00:00:50:0b %u\n", b, b);
	OpsCheck(ctx, num == 2 && StrCmp(text, expect) == 0 && st.IpsMoved == 1,
		"an address that another MAC address sends from moves to it, and a read of two entries gives the first two", "%u entries, %I64u moved:\n%s", num, st.IpsMoved, text);

	// The clear of one address takes it from every VLAN
	UINT cleared = SwitchClearIps(sw, ops_ip_a, 4);
	num = OpsIps(sw, OPS_LIST, text, sizeof(text));
	OpsCheck(ctx, cleared == 2 && num == 2 && SwitchClearIps(sw, ops_ip_a, 5) == 0, "a clear of one address takes its entries out of every VLAN, and an address of 5 bytes is none",
		"%u taken out, %u left:\n%s", cleared, num, text);

	// A port that goes takes its entries along, and the frames of a port that moves to another VLAN are learnt there
	bool deleted = SwitchDelPort(sw, b);
	num = OpsIps(sw, OPS_LIST, text, sizeof(text));
	OpsCheck(ctx, deleted && num == 0, "the IP table forgets the entries of a port that goes", "deleted %u, %u left:\n%s", (UINT)deleted, num, text);

	// Ageing: nothing before the aging time, every entry at it
	size = OpsIpv4(frame, ops_macs[OPS_CLIENT_B], ops_macs[OPS_CLIENT_A], 0, ops_ip_a, ops_ip_b, 28, 4);
	SwitchInput(sw, 3000, a, frame, size);
	SwitchAge(sw, 3000 + OPS_AGING - 1);
	SwitchGetStats(sw, &st);
	UINT before = st.NumIps;
	SwitchAge(sw, 3000 + OPS_AGING);
	SwitchGetStats(sw, &st);
	OpsCheck(ctx, before == 1 && st.NumIps == 0, "the IP table ages with the MAC table: an entry stays until the aging time, and goes at it", "%u, then %u", before, st.NumIps);
	SwitchFree(sw);

	// A full table refuses more addresses; a clear of every entry empties it
	c.MaxIps = OPS_SMALL_IPS;
	sw = SwitchNew(&c);
	a = (sw != NULL ? OpsPort(sw, OPS_VLAN, 0) : SWITCH_PORT_NONE);
	if (OpsCheck(ctx, sw != NULL && a != SWITCH_PORT_NONE, "a switch of 8 IP table entries", "SwitchNew or SwitchAddPort failed") == false)
	{
		SwitchFree(sw);
		return;
	}
	for (UINT i = 0;i < OPS_SMALL_IPS + 4;i++)
	{
		UCHAR src[4] = {10, 40, 0, (UCHAR)(1 + i)};

		size = OpsIpv4(frame, ops_bc, ops_macs[OPS_CLIENT_A], 0, src, ops_ip_b, 28, 4);
		SwitchInput(sw, 1000, a, frame, size);
	}
	SwitchGetStats(sw, &st);
	UINT full = st.NumIps;
	UINT64 refused_ips = st.IpsRefused;
	cleared = SwitchClearIps(sw, NULL, 0);
	SwitchGetStats(sw, &st);
	OpsCheck(ctx, full == OPS_SMALL_IPS && refused_ips == 4 && cleared == OPS_SMALL_IPS && st.NumIps == 0,
		"a full IP table refuses the addresses after its last entry, and a clear of every entry empties it", "%u entries, %I64u refused, %u taken out, %u left", full, refused_ips,
		cleared, st.NumIps);
	SwitchFree(sw);

	// The MAC table: the clear of one MAC address in every VLAN, and its first entries
	c.MaxIps = 0;
	sw = SwitchNew(&c);
	a = (sw != NULL ? OpsPort(sw, OPS_VLAN, 0) : SWITCH_PORT_NONE);
	t = (sw != NULL ? OpsPort(sw, OPS_VLAN, OPS_BRIDGE_VLAN) : SWITCH_PORT_NONE);
	if (OpsCheck(ctx, sw != NULL && a != SWITCH_PORT_NONE && t != SWITCH_PORT_NONE, "a switch of an access port and a trunk port", "SwitchNew or SwitchAddPort failed") == false)
	{
		SwitchFree(sw);
		return;
	}
	for (UINT i = 0;i < 20;i++)
	{
		UCHAR src[6] = {0x02, 0x00, 0x00, 0x02, 0x00, (UCHAR)(19 - i)};

		size = OpsFrame(frame, ops_bc, src, 0, 0x88B5, ops_ip_x, 4);
		SwitchInput(sw, 1000, a, frame, size);
	}
	size = OpsFrame(frame, ops_bc, ops_macs[OPS_BRIDGE], 0, 0x88B5, ops_ip_x, 4);
	SwitchInput(sw, 1000, a, frame, size);
	size = OpsFrame(frame, ops_bc, ops_macs[OPS_BRIDGE], OPS_BRIDGE_VLAN, 0x88B5, ops_ip_x, 4);
	SwitchInput(sw, 1000, t, frame, size);

	SWITCH_MAC_ENTRY all[OPS_LIST];
	SWITCH_MAC_ENTRY first[5];
	UINT num_all = SwitchGetMacs(sw, all, OPS_LIST);
	UINT num_first = SwitchGetMacs(sw, first, 5);
	bool same = (num_all == 22 && num_first == 5);
	for (UINT i = 0;same && i < num_first;i++)
	{
		same = (first[i].Vlan == all[i].Vlan && Cmp(first[i].Mac, all[i].Mac, 6) == 0);
	}
	OpsCheck(ctx, same, "a read of five entries of a MAC table of 22 gives its first five by VLAN and address", "%u of all, %u first", num_all, num_first);

	cleared = SwitchClearMac(sw, ops_macs[OPS_BRIDGE]);
	SwitchGetStats(sw, &st);
	OpsCheck(ctx, cleared == 2 && st.NumMacs == 20, "a clear of one MAC address takes its entries out of every VLAN and leaves the others", "%u taken out, %u left", cleared, st.NumMacs);
	SwitchFree(sw);
}

//
// The stand-in of the Controller
//

// Read the next frame of the stream within timeout into Frame (OPS_FRAME_*)
static UINT OpsRead(OPS_STANDIN *s, UINT timeout)
{
	UINT64 end = Tick64() + timeout;

	while (true)
	{
		UINT need = OPS_FRAME_HEADER;

		if (s->FrameSize >= OPS_FRAME_HEADER)
		{
			UINT size = READ_UINT(s->Frame);

			if (size == 0 || size > OPS_MAX_FRAME - OPS_FRAME_HEADER)
			{
				return OPS_FRAME_END;
			}
			need += size;
			if (s->FrameSize == need)
			{
				return OPS_FRAME_DONE;
			}
		}

		UINT64 now = Tick64();
		if (now >= end)
		{
			return OPS_FRAME_LATER;
		}

		UINT got = TransportRead(s->Stream, s->Frame + s->FrameSize, need - s->FrameSize, (UINT)(end - now));
		if (got == 0 || (got != TRANSPORT_LATER && got > need - s->FrameSize))
		{
			return OPS_FRAME_END;
		}
		if (got != TRANSPORT_LATER)
		{
			s->FrameSize += got;
		}
	}
}

// Decode the frame in Frame into Message: false for bytes that are no ControlMessage
static bool OpsDecode(OPS_STANDIN *s)
{
	pb_istream_t is = pb_istream_from_buffer(s->Frame + OPS_FRAME_HEADER, s->FrameSize - OPS_FRAME_HEADER);

	Zero(s->Message, sizeof(ranz_control_v1_ControlMessage));

	return pb_decode(&is, ranz_control_v1_ControlMessage_fields, s->Message);
}

// Write Message as one frame
static bool OpsWrite(OPS_STANDIN *s)
{
	pb_ostream_t os = pb_ostream_from_buffer(s->Out + OPS_FRAME_HEADER, OPS_OUT_FRAME - OPS_FRAME_HEADER);

	if (pb_encode(&os, ranz_control_v1_ControlMessage_fields, s->Message) == false)
	{
		return false;
	}

	WRITE_UINT(s->Out, (UINT)os.bytes_written);

	return TransportWrite(s->Stream, s->Out, OPS_FRAME_HEADER + (UINT)os.bytes_written);
}

// Take the control stream of the node and run the responder of its handshake, as the Controller does: Noise_IK with the
// static key of the stand-in, bound to the exporter of the stream after the prologue of the control stream. The static key of
// the node goes into remote.
static bool OpsAccept(OPS_STANDIN *s, UCHAR *remote)
{
	UCHAR prologue[sizeof(CONTROL_PROLOGUE_LABEL) - 1 + CONTROL_EXPORTER_SIZE];
	UCHAR binding[NOISE_MAX_BINDING];
	NOISE_HANDSHAKE hs;
	UINT size = 0;
	UINT payload_size = 0;

	s->Stream = TransportAccept(s->Listener, OPS_BOUND);
	if (s->Stream == NULL || TransportBinding(s->Stream, binding, sizeof(binding), &size) != NOISE_BINDING_EXPORTER || size != CONTROL_EXPORTER_SIZE)
	{
		return false;
	}
	Copy(prologue, CONTROL_PROLOGUE_LABEL, sizeof(CONTROL_PROLOGUE_LABEL) - 1);
	Copy(prologue + sizeof(CONTROL_PROLOGUE_LABEL) - 1, binding, CONTROL_EXPORTER_SIZE);

	s->FrameSize = 0;
	if (OpsRead(s, CONTROL_TIMEOUT) != OPS_FRAME_DONE)
	{
		return false;
	}

	bool ok = NoiseHandshakeInit(&hs, NOISE_SUITE_IK, false, prologue, (UINT)sizeof(prologue), s->Key.Private, NULL, NULL);
	ok = ok && NoiseHandshakeRead(&hs, s->Frame + OPS_FRAME_HEADER, s->FrameSize - OPS_FRAME_HEADER, NULL, 0, &payload_size);
	ok = ok && NoiseHandshakeWrite(&hs, NULL, 0, s->Out + OPS_FRAME_HEADER, OPS_OUT_FRAME - OPS_FRAME_HEADER, &size);
	if (ok)
	{
		Copy(remote, hs.RemoteStatic, PEER_KEY_SIZE);
	}
	NoiseHandshakeFree(&hs);
	s->FrameSize = 0;

	if (ok)
	{
		WRITE_UINT(s->Out, size);
		ok = TransportWrite(s->Stream, s->Out, OPS_FRAME_HEADER + size);
	}

	return ok;
}

// Read frames of the node within OPS_BOUND until one whose body is which comes: false when none came. The frames of
// another body (Leases, Telemetry) are passed over.
static bool OpsReadBody(OPS_STANDIN *s, pb_size_t which)
{
	for (UINT64 end = Tick64() + OPS_BOUND;Tick64() < end;)
	{
		UINT r = OpsRead(s, OPS_READ);

		if (r == OPS_FRAME_END)
		{
			return false;
		}
		if (r != OPS_FRAME_DONE)
		{
			continue;
		}

		bool ok = OpsDecode(s);
		if (ok && s->Message->which_body == which)
		{
			return true;
		}
		s->FrameSize = 0;
	}

	return false;
}

// The desired state of the node at Generation 1: the node, VRF default, the L2 Network lan and the L3 Network wan
static void OpsState(OPS_STANDIN *s)
{
	Zero(s->Message, sizeof(ranz_control_v1_ControlMessage));
	s->Message->which_body = ranz_control_v1_ControlMessage_update_tag;

	ranz_control_v1_Update *u = &s->Message->body.update;
	u->generation = 1;

	ranz_control_v1_Object *o = &u->set[u->set_count++];
	o->which_kind = ranz_control_v1_Object_node_tag;
	StrCpy(o->kind.node.name, sizeof(o->kind.node.name), "node-a");

	o = &u->set[u->set_count++];
	o->which_kind = ranz_control_v1_Object_vrf_tag;
	StrCpy(o->kind.vrf.name, sizeof(o->kind.vrf.name), "default");
	o->kind.vrf.id = OPS_VRF;
	o->kind.vrf.mtu = 1280;

	o = &u->set[u->set_count++];
	o->which_kind = ranz_control_v1_Object_network_tag;
	StrCpy(o->kind.network.name, sizeof(o->kind.network.name), "lan");
	o->kind.network.vrf_id = OPS_VRF;
	o->kind.network.mode = ranz_control_v1_NetworkMode_NETWORK_MODE_L2;

	o = &u->set[u->set_count++];
	o->which_kind = ranz_control_v1_Object_network_tag;
	StrCpy(o->kind.network.name, sizeof(o->kind.network.name), "wan");
	o->kind.network.vrf_id = OPS_VRF;
	o->kind.network.mode = ranz_control_v1_NetworkMode_NETWORK_MODE_L3;
}

// Send the node the Operation of kind on network, with the MAC address or the address of mac_size or address_size bytes,
// and read its answer into ctx->Result: false when none came within OPS_BOUND. Each answer must decode and encode back to
// its bytes through nanopb, as the frames of the controller conformance tests do.
static bool OpsAsk(OPS_CTX *ctx, UINT kind, char *network, const UCHAR *mac, UINT mac_size, const UCHAR *address, UINT address_size)
{
	OPS_STANDIN *s = &ctx->Standin;
	UINT64 id = s->NextId++;

	Zero(ctx->Result, sizeof(ranz_control_v1_OperationResult));
	ctx->Status = 0;

	Zero(s->Message, sizeof(ranz_control_v1_ControlMessage));
	s->Message->which_body = ranz_control_v1_ControlMessage_operation_tag;
	ranz_control_v1_Operation *op = &s->Message->body.operation;
	op->id = id;
	op->kind = (ranz_control_v1_OperationKind)kind;
	StrCpy(op->network, sizeof(op->network), network);
	op->mac.size = (pb_size_t)MIN(mac_size, (UINT)sizeof(op->mac.bytes));
	if (mac != NULL)
	{
		Copy(op->mac.bytes, mac, op->mac.size);
	}
	op->address.size = (pb_size_t)MIN(address_size, (UINT)sizeof(op->address.bytes));
	if (address != NULL)
	{
		Copy(op->address.bytes, address, op->address.size);
	}
	if (OpsWrite(s) == false)
	{
		return false;
	}

	while (OpsReadBody(s, ranz_control_v1_ControlMessage_operation_result_tag))
	{
		UINT size = s->FrameSize - OPS_FRAME_HEADER;
		pb_ostream_t os = pb_ostream_from_buffer(s->Again, OPS_MAX_FRAME);

		s->FrameSize = 0;
		if (s->Message->body.operation_result.id != id)
		{
			continue;
		}

		s->Answers++;
		s->LargestFrame = MAX(s->LargestFrame, size);
		if (pb_encode(&os, ranz_control_v1_ControlMessage_fields, s->Message) && os.bytes_written == size && Cmp(s->Again, s->Frame + OPS_FRAME_HEADER, size) == 0)
		{
			s->RoundTrips++;
		}
		Copy(ctx->Result, &s->Message->body.operation_result, sizeof(ranz_control_v1_OperationResult));
		ctx->Status = (UINT)ctx->Result->status;
		return true;
	}

	return false;
}

//
// The node
//

// The procedure of the switch of lan that names the member of each port (NODE_PORT_NAME_PROC)
static void OpsMember(void *param, UINT port, char *name, UINT size)
{
	OPS_CTX *ctx = (OPS_CTX *)param;

	for (UINT i = 0;i < OPS_NUM_MEMBERS;i++)
	{
		if (ctx->Ports[i] != port)
		{
			continue;
		}

		if (ctx->LongNames)
		{
			// A name of 63 characters: the largest that an entry carries
			char long_name[CONTROL_NAME_SIZE];

			Format(long_name, sizeof(long_name), "%s-", ops_members[i]);
			while (StrLen(long_name) < CONTROL_NAME_SIZE - 1)
			{
				StrCat(long_name, sizeof(long_name), "x");
			}
			StrCpy(name, size, long_name);
			return;
		}

		StrCpy(name, size, ops_members[i]);
		return;
	}
}

// The traffic of the members of lan: client-a sends an ARP request and an IPv4 packet in VLAN 1, client-b an IPv4 and an IPv6
// packet in VLAN 1, and the bridge an IPv4 packet in VLAN 7
static void OpsTraffic(OPS_CTX *ctx)
{
	UCHAR frame[128];
	UINT size;

	size = OpsArp(frame, ops_macs[OPS_CLIENT_A], ops_ip_a, ops_ip_b);
	SwitchInput(ctx->Switch, GetTickCount64(), ctx->Ports[OPS_CLIENT_A], frame, size);
	size = OpsIpv4(frame, ops_macs[OPS_CLIENT_B], ops_macs[OPS_CLIENT_A], 0, ops_ip_a, ops_ip_b, 28, 4);
	SwitchInput(ctx->Switch, GetTickCount64(), ctx->Ports[OPS_CLIENT_A], frame, size);
	size = OpsIpv4(frame, ops_macs[OPS_CLIENT_A], ops_macs[OPS_CLIENT_B], 0, ops_ip_b, ops_ip_a, 28, 4);
	SwitchInput(ctx->Switch, GetTickCount64(), ctx->Ports[OPS_CLIENT_B], frame, size);
	size = OpsIpv6(frame, ops_macs[OPS_CLIENT_A], ops_macs[OPS_CLIENT_B], 0, ops_ip6_b, ops_ip6_b);
	SwitchInput(ctx->Switch, GetTickCount64(), ctx->Ports[OPS_CLIENT_B], frame, size);
	size = OpsIpv4(frame, ops_bc, ops_macs[OPS_BRIDGE], OPS_BRIDGE_VLAN, ops_ip_x, ops_ip_a, 28, 4);
	SwitchInput(ctx->Switch, GetTickCount64(), ctx->Ports[OPS_BRIDGE], frame, size);
}

// The answer in ctx->Result as text: one line "<vlan> <mac> <member>" for each entry of the MAC table, "<vlan> <address>
// <mac> <member>" for the IP table. Whether every entry has a MAC address of 6 bytes, an address of 4 or 16 bytes for the IP
// table and none for the MAC table, and the time of its last frame from since on.
static bool OpsShow(OPS_CTX *ctx, bool ip, UINT64 since, char *text, UINT size)
{
	ranz_control_v1_OperationResult *r = ctx->Result;
	UINT64 until = OpsUnixNow();
	bool ok = true;

	text[0] = 0;
	for (UINT i = 0;i < r->entries_count;i++)
	{
		const ranz_control_v1_TableEntry *e = &r->entries[i];
		char addr[64], mac[32], line[MAX_SIZE];

		ok = ok && e->mac.size == 6 && (ip ? (e->address.size == 4 || e->address.size == 16) : e->address.size == 0);
		// The switch refreshes the time of an entry once a second at most
		ok = ok && e->last_seen_ms + 1000 >= since && e->last_seen_ms <= until + 1000;

		OpsMac(mac, sizeof(mac), e->mac.bytes);
		if (ip)
		{
			OpsAddress(addr, sizeof(addr), e->address.bytes, e->address.size);
			Format(line, sizeof(line), "%u %s %s %s\n", e->vlan, addr, mac, e->member);
		}
		else
		{
			Format(line, sizeof(line), "%u %s %s\n", e->vlan, mac, e->member);
		}
		StrCat(text, size, line);
	}

	return ok;
}

// Read the table of lan (ip: the IP table) and check that it is expect, every entry well formed with the time of its last
// frame from since on
static void OpsCheckTable(OPS_CTX *ctx, bool ip, UINT64 since, char *expect, char *what)
{
	char text[OPS_SHOW];

	bool asked = OpsAsk(ctx, (ip ? CONTROL_OPERATION_IP_TABLE : CONTROL_OPERATION_MAC_TABLE), "lan", NULL, 0, NULL, 0);
	bool formed = asked && OpsShow(ctx, ip, since, text, sizeof(text));
	if (asked == false)
	{
		StrCpy(text, sizeof(text), "(no answer)\n");
	}

	OpsCheck(ctx, asked && ctx->Status == CONTROL_OPERATION_OK && formed && ctx->Result->total == ctx->Result->entries_count && StrCmp(text, expect) == 0, what,
		"status %u, total %u, %u entries, well formed %u, message \"%s\":\n%s", ctx->Status, ctx->Result->total, (UINT)ctx->Result->entries_count, (UINT)formed,
		ctx->Result->message, text);
}

// Clear the table of lan (ip: the IP table), one entry or every entry, and check that it took out expect entries
static void OpsCheckClear(OPS_CTX *ctx, bool ip, const UCHAR *entry, UINT entry_size, UINT expect, char *what)
{
	bool asked = OpsAsk(ctx, (ip ? CONTROL_OPERATION_CLEAR_IP_TABLE : CONTROL_OPERATION_CLEAR_MAC_TABLE), "lan", (ip ? NULL : entry), (ip ? 0 : entry_size),
		(ip ? entry : NULL), (ip ? entry_size : 0));

	OpsCheck(ctx, asked && ctx->Status == CONTROL_OPERATION_OK && ctx->Result->total == expect && ctx->Result->entries_count == 0, what,
		"answered %u, status %u, total %u, %u entries, message \"%s\"", (UINT)asked, ctx->Status, ctx->Result->total, (UINT)ctx->Result->entries_count, ctx->Result->message);
}

// Send the Operation of kind on network, with a MAC address of mac_size bytes, and check that its answer has the status
// status, with a message, and lists nothing
static void OpsCheckRefused(OPS_CTX *ctx, UINT kind, char *network, UINT mac_size, UINT status, char *what)
{
	static const UCHAR mac[6] = {0x02, 0x00, 0x00, 0x00, 0x50, 0x0A};

	bool asked = OpsAsk(ctx, kind, network, (mac_size != 0 ? mac : NULL), mac_size, NULL, 0);

	OpsCheck(ctx, asked && ctx->Status == status && ctx->Result->message[0] != 0 && ctx->Result->entries_count == 0, what, "answered %u, status %u, message \"%s\"", (UINT)asked,
		ctx->Status, ctx->Result->message);
}

// A new empty data directory under the temp directory of the process, with a configuration store that runs no role on one
// worker
static void OpsNewDir(wchar_t *dir, UINT size)
{
	wchar_t tmp[MAX_PATH];
	wchar_t path[MAX_PATH];

	UniFormat(tmp, sizeof(tmp), L"operationstest_%u", Rand32());
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
static void OpsDeleteFiles(wchar_t *dir)
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

// Start the stand-in and the node, whose overlay dials the stand-in on its control stream, and take the stream: the
// handshake, the Hello with the Capability operations, and Generation 1, which the node acknowledges
static bool OpsStartNode(OPS_CTX *ctx)
{
	OPS_STANDIN *s = &ctx->Standin;
	NODE_OVERLAY_CONFIG c;
	UCHAR scalar[PEER_KEY_SIZE];
	UCHAR remote[PEER_KEY_SIZE];
	bool ok = true;

	// The static keys: the scalars 1 to 32 of node-a of the conformance tests for the node, 129 on for the stand-in
	for (UINT i = 0;i < 2;i++)
	{
		for (UINT j = 0;j < PEER_KEY_SIZE;j++)
		{
			scalar[j] = (UCHAR)(1 + 128 * i + j);
		}
		ok = PeerKeyFromScalar(i == 0 ? &ctx->NodeKey : &s->Key, scalar) && ok;
	}
	Zero(scalar, sizeof(scalar));

	s->Transport = TransportLoopbackNew("control", 0, true);
	s->Listener = (s->Transport != NULL ? TransportListen(s->Transport, "controller") : NULL);
	ctx->Data = TransportLoopbackNew("loopback", 0, false);
	if (OpsCheck(ctx, ok && s->Listener != NULL && ctx->Data != NULL, "the static keys, the bound loopback transport of the control stream with the stand-in of the Controller on it, and the transport of the sessions",
		"PeerKeyFromScalar, TransportLoopbackNew or TransportListen failed") == false)
	{
		return false;
	}

	OpsNewDir(ctx->Dir, sizeof(ctx->Dir));
	ctx->Node = NewNode(ctx->Dir);
	NodeStart(ctx->Node);

	Zero(&c, sizeof(c));
	c.Control = s->Transport;
	StrCpy(c.Controller, sizeof(c.Controller), "controller");
	Copy(c.ControllerKey, s->Key.Public, PEER_KEY_SIZE);
	c.Data = ctx->Data;
	c.Key = &ctx->NodeKey;
	if (OpsCheck(ctx, NodeOverlayStart(ctx->Node, &c), "the node runs its overlay with its control stream to the stand-in", "NodeOverlayStart failed") == false)
	{
		return false;
	}

	ok = OpsAccept(s, remote) && Cmp(remote, ctx->NodeKey.Public, PEER_KEY_SIZE) == 0;
	if (OpsCheck(ctx, ok, "the stand-in takes the control stream of the node: the handshake bound to the exporter, with the static key of the node", "no stream or no handshake within %u ms",
		(UINT)OPS_BOUND) == false)
	{
		return false;
	}

	bool hello = OpsReadBody(s, ranz_control_v1_ControlMessage_hello_tag);
	bool operations = hello && s->Message->body.hello.has_capabilities && s->Message->body.hello.capabilities.operations;
	s->FrameSize = 0;
	OpsCheck(ctx, operations, "the Hello of the node reports the Capability operations", "Hello %u, Capabilities %u", (UINT)hello, (UINT)(hello && s->Message->body.hello.has_capabilities));

	OpsState(s);
	bool acked = OpsWrite(s) && OpsReadBody(s, ranz_control_v1_ControlMessage_ack_tag) && s->Message->body.ack.generation == 1;
	s->FrameSize = 0;

	return OpsCheck(ctx, acked, "the node applies Generation 1, which gives it the L2 Network lan and the L3 Network wan, and acknowledges it", "no Ack of Generation 1 within %u ms",
		(UINT)OPS_BOUND);
}

// The L2 data path of the test: the switch of lan with its three members, attached to the node
static bool OpsAttach(OPS_CTX *ctx)
{
	SWITCH_CONFIG c;
	bool ok;

	Zero(&c, sizeof(c));
	c.MaxPorts = 8;
	ctx->Switch = SwitchNew(&c);
	ok = (ctx->Switch != NULL);
	for (UINT i = 0;ok && i < OPS_NUM_MEMBERS;i++)
	{
		ctx->Ports[i] = OpsPort(ctx->Switch, OPS_VLAN, (i == OPS_BRIDGE ? OPS_BRIDGE_VLAN : 0));
		ok = (ctx->Ports[i] != SWITCH_PORT_NONE);
	}

	return OpsCheck(ctx, ok && NodeOperationAttach(ctx->Node, "lan", ctx->Switch, OpsMember, ctx), "the L2 data path attaches the switch of lan, with client-a and client-b on access ports of VLAN 1 and the bridge on a trunk port of VLANs 1 and 7",
		"SwitchNew, SwitchAddPort or NodeOperationAttach failed");
}

// The Operations of the stand-in on the tables of the node
static void OpsNodeCases(OPS_CTX *ctx)
{
	static const char *mac_table = "1 02:00:00:00:50:0a client-a\n1 02:00:00:00:50:0b client-b\n7 02:00:00:00:50:1e bridge\n";
	static const char *ip_table = "1 10.20.0.8 02:00:00:00:50:0a client-a\n1 10.20.0.9 02:00:00:00:50:0b client-b\n1 fd000000000000000000000000000009 02:00:00:00:50:0b client-b\n"
		"7 192.0.2.7 02:00:00:00:50:1e bridge\n";
	char expect[OPS_SHOW];

	Print("[the node: the Operations of the Controller on the tables of its switch]\n");

	UINT64 since = OpsUnixNow();
	OpsTraffic(ctx);
	OpsCheckTable(ctx, false, since, (char *)mac_table,
		"a read of the MAC table of lan gives the entries that the switch learnt from the traffic, by VLAN and MAC address, each with its member and the time of its last frame");
	OpsCheckTable(ctx, true, since, (char *)ip_table,
		"a read of the IP table of lan gives the addresses that the members sent from, by VLAN, IPv4 before IPv6, each with its MAC address, its member and the time of its last frame");

	// The clear of one entry and of every entry; the next read shows them gone, and the traffic learns them again
	OpsCheckClear(ctx, false, ops_macs[OPS_CLIENT_A], 6, 1, "a clear of the entry of the MAC address of client-a takes one entry out");
	Format(expect, sizeof(expect), "1 02:00:00:00:50:0b client-b\n7 02:00:00:00:50:1e bridge\n");
	OpsCheckTable(ctx, false, since, expect, "the next read of the MAC table shows the entry gone and the others there");
	OpsCheckClear(ctx, false, NULL, 0, 2, "a clear of the MAC table takes its two other entries out");
	OpsCheckTable(ctx, false, since, "", "the next read of the MAC table shows none");

	OpsCheckClear(ctx, true, ops_ip_b, 4, 1, "a clear of the entry of 10.20.0.9 of the IP table takes one entry out");
	OpsCheckClear(ctx, true, ops_ip6_b, 16, 1, "a clear of the entry of fd00::9 takes one entry out");
	Format(expect, sizeof(expect), "1 10.20.0.8 02:00:00:00:50:0a client-a\n7 192.0.2.7 02:00:00:00:50:1e bridge\n");
	OpsCheckTable(ctx, true, since, expect, "the next read of the IP table shows the two entries gone and the others there");
	OpsCheckClear(ctx, true, NULL, 0, 2, "a clear of the IP table takes its two other entries out");
	OpsCheckTable(ctx, true, since, "", "the next read of the IP table shows none");

	since = OpsUnixNow();
	OpsTraffic(ctx);
	OpsCheckTable(ctx, false, since, (char *)mac_table, "the traffic that follows the clears learns the entries of the MAC table again");
	OpsCheckTable(ctx, true, since, (char *)ip_table, "... and those of the IP table");

	// What the node does not do
	OpsCheckRefused(ctx, CONTROL_OPERATION_MAC_TABLE, "wan", 0, CONTROL_OPERATION_NO_NETWORK, "an Operation for wan, an L3 Network of the node, is no-network");
	OpsCheckRefused(ctx, CONTROL_OPERATION_IP_TABLE, "dmz", 0, CONTROL_OPERATION_NO_NETWORK, "an Operation for dmz, which the node does not hold, is no-network");
	OpsCheckRefused(ctx, 9, "lan", 0, CONTROL_OPERATION_FAILED, "an Operation of a kind that the node does not know failed");
	OpsCheckRefused(ctx, CONTROL_OPERATION_CLEAR_MAC_TABLE, "lan", 5, CONTROL_OPERATION_FAILED, "a clear with a MAC address of 5 bytes failed");
}

// More entries than an answer lists: 600 sources of the bridge in VLAN 1, each with an IPv4 address, and members with names
// of 63 characters
static void OpsLimits(OPS_CTX *ctx)
{
	UCHAR frame[128];
	char first[64], last[64];

	Print("[the limits of an answer: 512 entries of a table and its total]\n");

	ctx->LongNames = true;
	for (UINT i = 0;i < OPS_SOURCES;i++)
	{
		UCHAR mac[6] = {0x02, 0x00, 0x00, 0x01, (UCHAR)(i >> 8), (UCHAR)i};
		UCHAR src[4] = {10, 30, (UCHAR)(i >> 8), (UCHAR)i};

		UINT size = OpsIpv4(frame, ops_bc, mac, OPS_VLAN, src, ops_ip_a, 28, 4);
		SwitchInput(ctx->Switch, GetTickCount64(), ctx->Ports[OPS_BRIDGE], frame, size);
	}

	// The MAC table: client-a, client-b and the 600 sources in VLAN 1, the bridge in VLAN 7; its first 512 are client-a,
	// client-b and the sources 0 to 509
	bool asked = OpsAsk(ctx, CONTROL_OPERATION_MAC_TABLE, "lan", NULL, 0, NULL, 0);
	ranz_control_v1_OperationResult *r = ctx->Result;
	bool ordered = asked && r->entries_count == CONTROL_MAX_ENTRIES;
	for (UINT i = 1;ordered && i < r->entries_count;i++)
	{
		ordered = (r->entries[i - 1].vlan < r->entries[i].vlan || (r->entries[i - 1].vlan == r->entries[i].vlan && Cmp(r->entries[i - 1].mac.bytes, r->entries[i].mac.bytes, 6) < 0));
	}
	OpsMac(first, sizeof(first), (asked && r->entries_count != 0 ? r->entries[0].mac.bytes : ops_bc));
	OpsMac(last, sizeof(last), (asked && r->entries_count != 0 ? r->entries[r->entries_count - 1].mac.bytes : ops_bc));
	OpsCheck(ctx, ordered && r->total == OPS_SOURCES + 3 && StrCmp(first, "02:00:00:00:50:0a") == 0 && StrCmp(last, "02:00:00:01:01:fd") == 0 && StrLen(r->entries[0].member) == CONTROL_NAME_SIZE - 1,
		"a read of a MAC table of 603 entries lists its first 512 by VLAN and MAC address, as many as the nanopb options allow, with its total, and members of 63 characters",
		"answered %u, %u entries, total %u, ordered %u, first %s, last %s", (UINT)asked, (UINT)r->entries_count, r->total, (UINT)ordered, first, last);

	// The IP table: the addresses of client-a and client-b, the 600 sources and fd00::9 in VLAN 1, the bridge in VLAN 7
	asked = OpsAsk(ctx, CONTROL_OPERATION_IP_TABLE, "lan", NULL, 0, NULL, 0);
	OpsAddress(first, sizeof(first), (asked && r->entries_count != 0 ? r->entries[0].address.bytes : ops_bc), 4);
	OpsAddress(last, sizeof(last), (asked && r->entries_count != 0 ? r->entries[r->entries_count - 1].address.bytes : ops_bc), 4);
	OpsCheck(ctx, asked && r->entries_count == CONTROL_MAX_ENTRIES && r->total == OPS_SOURCES + 4 && StrCmp(first, "10.20.0.8") == 0 && StrCmp(last, "10.30.1.253") == 0,
		"a read of an IP table of 604 entries lists its first 512 by VLAN and address, with its total", "answered %u, %u entries, total %u, first %s, last %s", (UINT)asked,
		(UINT)r->entries_count, r->total, first, last);

	OpsCheck(ctx, ctx->Standin.LargestFrame <= OPS_MAX_RESULT, "the largest answer is a frame that the Controller takes (MaxOperationResult)", "%u bytes", ctx->Standin.LargestFrame);
	ctx->LongNames = false;
}

RANZ_TEST_TAGS("operations", operations_test, "core", "Live operations of the Controller on a Node (SDN-50-N): the IP table of the L2 switch, and a Node that reads and clears the MAC table and the IP table of its L2 Network for the Operation frames of a stand-in Controller on its control stream.");
void operations_test(UINT num, char **arg)
{
	OPS_CTX *ctx = ZeroMalloc(sizeof(OPS_CTX));
	OPS_STANDIN *s = &ctx->Standin;
	HANDLE done = CreateEventW(NULL, TRUE, FALSE, NULL);
	HANDLE watchdog = (done != NULL ? CreateThread(NULL, 0, OpsWatchdog, done, 0, NULL) : NULL);

	Print("Live operations test: the IP table of the switch, and the answers of a Node to the Operation frames of the Controller\n");

	s->Frame = Malloc(OPS_MAX_FRAME);
	s->Out = Malloc(OPS_OUT_FRAME);
	s->Again = Malloc(OPS_MAX_FRAME);
	s->Message = ZeroMalloc(sizeof(ranz_control_v1_ControlMessage));
	s->NextId = 1;
	ctx->Result = ZeroMalloc(sizeof(ranz_control_v1_OperationResult));

	OpsSwitchCases(ctx);

	if (OpsCheck(ctx, CryptoInit(), "the crypto module of the new core runs on CNG", "CryptoInit failed") && OpsStartNode(ctx) && OpsAttach(ctx))
	{
		OpsNodeCases(ctx);
		OpsLimits(ctx);

		// Without its switch the node holds no table of lan
		NodeOperationDetach(ctx->Node, "lan");
		OpsCheckRefused(ctx, CONTROL_OPERATION_MAC_TABLE, "lan", 0, CONTROL_OPERATION_FAILED, "once the L2 data path detached the switch of lan, a read of its MAC table failed");

		OpsCheck(ctx, s->Answers != 0 && s->RoundTrips == s->Answers, "every answer of the node went on its one control stream, and decodes and encodes back to its bytes through nanopb",
			"%u answers, %u round trips", s->Answers, s->RoundTrips);
	}

	if (ctx->Node != NULL)
	{
		wchar_t log_dir[MAX_PATH];

		NodeOperationDetach(ctx->Node, "lan");
		NodeStop(ctx->Node);
		FreeNode(ctx->Node);
		ConbinePathW(log_dir, sizeof(log_dir), ctx->Dir, NODE_LOG_DIR_NAME);
		OpsDeleteFiles(log_dir);
		OpsDeleteFiles(ctx->Dir);
	}
	SwitchFree(ctx->Switch);
	if (s->Stream != NULL)
	{
		TransportClose(s->Stream);
	}
	if (s->Listener != NULL)
	{
		TransportCloseListener(s->Listener);
	}
	if (s->Transport != NULL)
	{
		TransportLoopbackFree(s->Transport);
	}
	if (ctx->Data != NULL)
	{
		TransportLoopbackFree(ctx->Data);
	}
	PeerKeyClose(&ctx->NodeKey);
	PeerKeyClose(&s->Key);

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
		Print("OPERATIONS TEST OK\n");
	}
	else
	{
		Print("OPERATIONS TEST FAILED (%u of %u checks failed)\n", ctx->NumFailed, ctx->NumChecks);
	}

	Free(s->Frame);
	Free(s->Out);
	Free(s->Again);
	Free(s->Message);
	Free(ctx->Result);
	Free(ctx);
}

//
// The harness Node of the operations tracer
//

#define	OPSTRACE_BUDGET		900000		// The tracer ends within this time, or the watchdog ends the process (ms)
#define	OPSTRACE_JOIN		60000		// The node applied its state from the controller within this time (ms)
#define	OPSTRACE_HOLD		600000		// The test waits this long for the stop file (ms)
#define	OPSTRACE_POLL		100			// Poll interval of the state of the node and of the files of the script (ms)

// node-a: the X25519 public key of its static scalar 1, 2, ... 32, which sdntrace.c and the controller conformance tests use
static char *opstrace_key = "B6N8vBQgk8i3VdwbEOhstCY3StFqqFPtC9/AsrhtHHw=";

// The watchdog of the tracer, as OpsWatchdog
static DWORD WINAPI OpsTraceWatchdog(LPVOID param)
{
	char msg[MAX_SIZE];
	DWORD written = 0;

	if (WaitForSingleObject((HANDLE)param, OPSTRACE_BUDGET) != WAIT_TIMEOUT)
	{
		return 0;
	}

	int len = snprintf(msg, sizeof(msg), "OPSTRACE TEST FAILED (did not finish within %u ms)\n", (UINT)OPSTRACE_BUDGET);
	if (len > 0)
	{
		WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), msg, (DWORD)MIN((UINT)len, (UINT)sizeof(msg) - 1), &written, NULL);
	}

	TerminateProcess(GetCurrentProcess(), 1);

	return 0;
}

// The Capabilities of the harness Node (NODE_OVERLAY_CONFIG.Caps): those of the host, and SeLow, the L2 backend that the
// switch of the test stands in for
static void OpsTraceCaps(void *param, CONTROL_CAPS *caps)
{
	UNREFERENCED_PARAMETER(param);

	NodeCapsProc(NULL, caps);
	caps->SeLow = true;
}

// Create a file of the script
static bool OpsTraceTouch(char *file)
{
	HANDLE f = CreateFileA(file, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

	if (f == INVALID_HANDLE_VALUE)
	{
		return false;
	}

	CloseHandle(f);
	return true;
}

// Print the lines of the node log of the node in dir that name the operations and the control stream
static void OpsTracePrintLog(wchar_t *dir)
{
	wchar_t log_dir[MAX_PATH];

	ConbinePathW(log_dir, sizeof(log_dir), dir, NODE_LOG_DIR_NAME);
	DIRLIST *d = EnumDirW(log_dir);

	for (UINT i = 0;d != NULL && i < d->NumFiles;i++)
	{
		DIRENT *e = d->File[i];
		wchar_t path[MAX_PATH];

		if (e->Folder)
		{
			continue;
		}

		ConbinePathW(path, sizeof(path), log_dir, e->FileNameW);
		BUF *b = ReadDumpW(path);
		if (b == NULL)
		{
			continue;
		}

		char *text = ZeroMalloc(b->Size + 1);
		Copy(text, b->Buf, b->Size);
		TOKEN_LIST *t = ParseToken(text, "\r\n");
		for (UINT j = 0;j < t->NumTokens;j++)
		{
			char *line = t->Token[j];

			if (InStr(line, "Operation") || InStr(line, "Overlay") || InStr(line, "Capabilities"))
			{
				Print("  [LOG] %s\n", line);
			}
		}
		FreeToken(t);
		Free(text);
		FreeBuf(b);
	}

	FreeDir(d);
}

// Print a line for each member of lan, which the script compares the tables of the Controller with
static void OpsTraceMembers()
{
	const UCHAR *addresses[OPS_NUM_MEMBERS] = {ops_ip_a, ops_ip_b, ops_ip_x};
	UINT vlans[OPS_NUM_MEMBERS] = {OPS_VLAN, OPS_VLAN, OPS_BRIDGE_VLAN};

	for (UINT i = 0;i < OPS_NUM_MEMBERS;i++)
	{
		char mac[32], addr[64];

		OpsMac(mac, sizeof(mac), ops_macs[i]);
		OpsAddress(addr, sizeof(addr), addresses[i], 4);
		Print("OPSTRACE MEMBER %s VLAN %u MAC %s ADDRESS %s\n", ops_members[i], vlans[i], mac, addr);
	}
	Print("OPSTRACE MEMBER client-b VLAN %u MAC 02:00:00:00:50:0b ADDRESS fd00::9\n", (UINT)OPS_VLAN);
}

RANZ_TEST("opstrace", opstrace_test, "Harness Node of the operations tracer: opstrace <host:port> <key> <ready file> <again file> <stop file>: node-a holds the L2 Network lan of a running controller, whose switch learns the traffic of its members, and answers the table calls of the Controller (.github/scripts/operations-tracer.ps1).");
void opstrace_test(UINT num, char **arg)
{
	OPS_CTX *ctx = ZeroMalloc(sizeof(OPS_CTX));
	TRANSPORT *tls = ZeroMalloc(sizeof(TRANSPORT));
	HANDLE done = CreateEventW(NULL, TRUE, FALSE, NULL);
	HANDLE watchdog = (done != NULL ? CreateThread(NULL, 0, OpsTraceWatchdog, done, 0, NULL) : NULL);
	char *ready_file = (num >= 5 ? arg[2] : NULL);
	char *again_file = (num >= 5 ? arg[3] : NULL);
	char *stop_file = (num >= 5 ? arg[4] : NULL);
	UCHAR controller_key[PEER_KEY_SIZE];
	UCHAR scalar[PEER_KEY_SIZE];
	NODE_OVERLAY_CONFIG c;
	NODE_OVERLAY_STATUS st;
	bool ok = false;

	Print("Operations tracer: node-a holds the L2 Network lan of the controller, whose switch learns the traffic of its members\n");

	// The controller: its address and its static key; and the files of the script
	Zero(controller_key, sizeof(controller_key));
	if (num >= 5)
	{
		UINT key_size = 0;
		void *key = Base64ToBin(&key_size, arg[1], StrLen(arg[1]));

		ok = (key != NULL && key_size == PEER_KEY_SIZE);
		if (ok)
		{
			Copy(controller_key, key, PEER_KEY_SIZE);
		}
		Free(key);
	}
	if (OpsCheck(ctx, ok, "the controller: its address and its static key, and the ready, again and stop files",
		"usage: opstrace <host:port of the controller> <its static key in base64> <ready file> <again file> <stop file>") == false)
	{
		goto END;
	}

	// Files of an earlier run are not this run's
	DeleteFileA(ready_file);
	DeleteFileA(again_file);
	DeleteFileA(stop_file);

	// The transports: TLS to the controller, and the transport of the sessions, which this node does not dial
	SdnTraceTlsInit(tls);
	ctx->Data = TransportLoopbackNew("loopback", 0, false);

	// node-a with the static key of its Node resource
	for (UINT j = 0;j < PEER_KEY_SIZE;j++)
	{
		scalar[j] = (UCHAR)(1 + j);
	}
	bool keyed = PeerKeyFromScalar(&ctx->NodeKey, scalar);
	Zero(scalar, sizeof(scalar));
	UINT pub_size = 0;
	void *pub = Base64ToBin(&pub_size, opstrace_key, StrLen(opstrace_key));
	ok = (keyed && pub != NULL && pub_size == PEER_KEY_SIZE && Cmp(pub, ctx->NodeKey.Public, PEER_KEY_SIZE) == 0 && ctx->Data != NULL);
	Free(pub);
	if (OpsCheck(ctx, ok, "node-a: its static key is the one of its Node resource, and the transport of the sessions", "%s", opstrace_key) == false)
	{
		goto END;
	}

	OpsNewDir(ctx->Dir, sizeof(ctx->Dir));
	ctx->Node = NewNode(ctx->Dir);
	NodeStart(ctx->Node);

	Zero(&c, sizeof(c));
	c.Control = tls;
	StrCpy(c.Controller, sizeof(c.Controller), arg[0]);
	Copy(c.ControllerKey, controller_key, PEER_KEY_SIZE);
	c.Data = ctx->Data;
	c.Key = &ctx->NodeKey;
	c.Caps = OpsTraceCaps;
	if (OpsCheck(ctx, NodeOverlayStart(ctx->Node, &c), "node-a runs its overlay, with its control stream to the controller", "NodeOverlayStart failed") == false)
	{
		goto END;
	}

	// It applies its state, which gives it lan
	bool joined = false;
	Zero(&st, sizeof(st));
	for (UINT64 end = Tick64() + OPSTRACE_JOIN;Tick64() < end && joined == false;SleepThread(OPSTRACE_POLL))
	{
		NodeOverlayGetStatus(ctx->Node, &st);
		joined = (st.Connected && st.Generation >= 1);
	}
	if (OpsCheck(ctx, joined, "node-a applied its state from the controller", "connected %u, generation %I64u within %u ms", (UINT)st.Connected, st.Generation, (UINT)OPSTRACE_JOIN) == false ||
		OpsAttach(ctx) == false)
	{
		goto END;
	}

	OpsTraffic(ctx);
	OpsTraceMembers();
	Print("OPSTRACE READY\n");
	OpsCheck(ctx, OpsTraceTouch(ready_file), "the ready file", "CreateFile %s: error %u", ready_file, (UINT)GetLastError());

	// The script reads and clears the tables through the controller; the traffic comes again when it asks
	bool stopped = false;
	UINT again = 0;
	for (UINT64 end = Tick64() + OPSTRACE_HOLD;Tick64() < end && stopped == false;SleepThread(OPSTRACE_POLL))
	{
		if (GetFileAttributesA(again_file) != INVALID_FILE_ATTRIBUTES && DeleteFileA(again_file))
		{
			OpsTraffic(ctx);
			again++;
			Print("OPSTRACE AGAIN %u\n", again);
			OpsTraceTouch(ready_file);
		}
		stopped = (GetFileAttributesA(stop_file) != INVALID_FILE_ATTRIBUTES);
	}
	OpsCheck(ctx, stopped, "the script created the stop file", "not within %u ms", (UINT)OPSTRACE_HOLD);

	NodeOverlayGetStatus(ctx->Node, &st);
	OpsCheck(ctx, st.Connected, "the control stream of node-a stayed up through the operations", "it is down");

END:
	if (ctx->Node != NULL)
	{
		wchar_t log_dir[MAX_PATH];

		NodeOperationDetach(ctx->Node, "lan");
		NodeStop(ctx->Node);
		FreeNode(ctx->Node);
		// The node log is written once the node is freed
		OpsTracePrintLog(ctx->Dir);
		ConbinePathW(log_dir, sizeof(log_dir), ctx->Dir, NODE_LOG_DIR_NAME);
		OpsDeleteFiles(log_dir);
		OpsDeleteFiles(ctx->Dir);
	}
	SwitchFree(ctx->Switch);
	if (ctx->Data != NULL)
	{
		TransportLoopbackFree(ctx->Data);
	}
	PeerKeyClose(&ctx->NodeKey);

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
		Print("OPSTRACE TEST OK\n");
	}
	else
	{
		Print("OPSTRACE TEST FAILED (%u of %u checks failed)\n", ctx->NumFailed, ctx->NumChecks);
	}

	Free(tls);
	Free(ctx);
}
