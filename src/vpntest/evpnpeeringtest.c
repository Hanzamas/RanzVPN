// evpnpeeringtest.c
// Named EVPN peering test of vpntest ("evpnpeering" command, SDN-78 #358)
//
// The EVPN peering of the standard mode (Cedar/NodeEvpnPeering.c, ranz-bgp/internal/sidecar/evpnpeering.go) on the harness of the
// ticket, the Nodes and the harness VTEP: in-process nodes, each with its own sidecar ranz bgp (ranz.exe next to vpntest, GoBGP),
// which listens on TCP 179 of the address of its node on the network that the operator trusts and connects from there: 127.0.0.2
// for node-a, 127.0.0.3 for node-b and 127.0.0.4 for node-c, which is a member of VRF dc in Generation 2 alone. The test applies the
// desired states of the nodes itself (NodeOverlayApply), as the Controller compiles them for a VRF whose peering is evpn
// (controller/internal/desired/peering.go): VRF dc (101) of a link of kind vxlan whose VNI 10101 is its L3 VNI, its L2 Network lan
// with the L2 VNI 5010, and the configuration of the peers alone: the settings of the sidecar of each node with the LAN subnet that
// it announces, and for each peer the address of its sidecar, the hold time of their session, the VRF and what the peer may
// announce there, its address and its LAN subnet, with no tunnel endpoint and no route of the peer. Each node runs the EVPN of dc
// with its sidecar, its VTEP the address of its node on a UDP port of its own. On one host every VTEP sends from 127.0.0.1 (see
// peeringtest.c), the VTEP of no node, so the VTEPs of the peers of each node are the harness VTEPs on 127.0.0.2, 127.0.0.3 and
// 127.0.0.4, on one UDP port (NodePeeringSetFabricPort): each takes what a node sends to the VTEP of its node, and the test passes a
// datagram on to the node that it went to from the harness VTEP of the node that sent it, so that it comes from the address of that
// node, as between two hosts. The switch of lan of node-a and of node-b is the L2 data path of the test (NodeStretchAttach, as in
// stretchtest.c): host 1 and host m at node-a and host 2 at node-b, each a member that announces its MAC address and its IP address
// with a gratuitous ARP; host 1 and host 2 subscribe to the broadcast group. Fake adapters stand in for the hosts of the VRF.
// - The routes of lan (type 2 and type 3): node-b holds the type-3 route of node-a, its flood list, and the type-2 routes of host 1
//   and host m, MAC only and MAC plus IP, via the VTEP of node-a; node-a holds the type-3 route of node-b and the type-2 routes of
//   host 2 via the VTEP of node-b.
// - A frame to a MAC address of the other node goes there over VXLAN: a frame of host 2 to host 1 goes to the VTEP of node-a alone,
//   byte for byte on the L2 VNI, and node-a delivers it to host 1 alone.
// - The flood list: a broadcast of host 1 goes to the VTEP of node-b once, the type-3 route of node-b at node-a.
// - The prefixes (type 5): each node holds the IP prefix routes of the other, its address and its LAN subnet, with the L3 VNI of dc
//   and the VTEP of the other; a packet of the host of node-a to the LAN of node-b goes to the VTEP of node-b on the L3 VNI, and
//   arrives at the host of node-b.
// - Not the form that the Controller fills (SDN-76): the links of each node carry no VNI though dc has a link of kind vxlan, and a
//   packet of the host of node-a to the address of node-b, which the state names among the addresses of the peer, goes by the IP
//   prefix route of node-b on the L3 VNI and never over the session of the overlay with node-b, which is up.
// - MAC mobility: host m moves to node-b, where it announces itself. The type-2 routes of host m move: node-a holds the ones of
//   node-b, node-b none of node-a; node-a counts the move and holds host m at the port of the fabric, and a frame of host 1 to host m
//   goes to the VTEP of node-b, which delivers it to host m there, while the old port of host m at node-a gets nothing.
// - The flood list changes while the nodes run: node-c joins dc (Generation 2), and a broadcast of host 1 goes to the VTEPs of
//   node-b and node-c once each; node-c leaves (Generation 3), and one goes to the VTEP of node-b alone.
// - A session from 127.0.0.9, an address that the Controller did not name, to node-a is refused, and node-a counts it.
// Print "EVPNPEERING TEST OK" only when every check passes. .github/scripts/bgp-peering.ps1 builds ranz.exe and runs it.

#include "testlist.h"

#include "Cedar/Cedar.h"
#include "Cedar/ConfigStore.h"
#include "Cedar/Node.h"
#include "Cedar/NodeEvpn.h"
#include "Cedar/NodeLink.h"
#include "Cedar/NodePeering.h"

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
#include "Core/Switch.h"
#include "Core/Transport.h"
#include "Core/Vxlan.h"

#include <WS2tcpip.h>

#include <stdio.h>

#define	EVPNPEERINGTEST_BUDGET		420000		// The whole test ends within this time, or the watchdog ends the process (ms)
#define	EVPNPEERINGTEST_BOUND		60000		// A bounded wait on BGP: the sessions and the routes (ms)
#define	EVPNPEERINGTEST_WAIT		10000		// A bounded wait on a frame, a packet or the switch (ms)
#define	EVPNPEERINGTEST_QUIET		500			// A side that gets nothing gets nothing within this time (ms)
#define	EVPNPEERINGTEST_POLL		20			// Poll interval of observable state (ms)
#define	EVPNPEERINGTEST_ASN			4200000000U	// The AS of the overlay, one for every node (intent.PeeringASN)
#define	EVPNPEERINGTEST_HOLD		9			// The BGP hold time of the sessions in s, as the VRF of the Intent names it
#define	EVPNPEERINGTEST_PORT		179			// The BGP port of the sidecars
#define	EVPNPEERINGTEST_STRANGER	"127.0.0.9"	// An address that the Controller did not name
#define	EVPNPEERINGTEST_VRF			101			// The id of VRF dc ...
#define	EVPNPEERINGTEST_L3VNI		10101		// ... and its L3 VNI, the VNI of its link of kind vxlan
#define	EVPNPEERINGTEST_L2VNI		5010		// The L2 VNI of its L2 Network lan
#define	EVPNPEERINGTEST_VLAN		1			// The VLAN of lan on each switch
#define	EVPNPEERINGTEST_LENGTH		24			// The prefix length of the Network dc-net and of the LAN subnets
#define	EVPNPEERINGTEST_FRAME		78			// A test frame of lan: the Ethernet header and an IPv4 packet of UDP of 64 bytes
#define	EVPNPEERINGTEST_SIZE		100			// A test packet of dc: an IPv4 packet of UDP
#define	EVPNPEERINGTEST_ROUTES		16			// The routes of the peers that a node of the test holds at most
#define	EVPNPEERINGTEST_TEXT		64			// A prefix as text, with its NUL

// The nodes, in name order, which is the order of the peers in a state
#define	EVPNPEERINGTEST_A			0
#define	EVPNPEERINGTEST_B			1
#define	EVPNPEERINGTEST_C			2
#define	EVPNPEERINGTEST_NODES		3

// The hosts of lan: host 1 and host m at node-a, host 2 at node-b, and host m at node-b once it moved there
#define	EVPNPEERINGTEST_HOST_1		0
#define	EVPNPEERINGTEST_HOST_M		1
#define	EVPNPEERINGTEST_HOST_2		2
#define	EVPNPEERINGTEST_HOST_MOVED	3
#define	EVPNPEERINGTEST_HOSTS		4

static char *evpnpeeringtest_names[EVPNPEERINGTEST_NODES] = {"node-a", "node-b", "node-c"};

// The address of each node on the network that the operator trusts, as text and in host byte order: its sidecar listens on TCP 179
// there and connects from there, its VTEP is there, it is its router id, as the Controller makes one of an IPv4 tunnel endpoint
// (intent.RouterID), and its harness VTEP is there
static char *evpnpeeringtest_addrs[EVPNPEERINGTEST_NODES] = {"127.0.0.2", "127.0.0.3", "127.0.0.4"};
static const UINT evpnpeeringtest_addr_values[EVPNPEERINGTEST_NODES] = {0x7F000002, 0x7F000003, 0x7F000004};

// The address of each node in the Network dc-net of dc, and the LAN subnet behind it in dc with a host of that subnet, NULL for none
static char *evpnpeeringtest_dc[EVPNPEERINGTEST_NODES] = {"10.0.0.2", "10.0.0.3", "10.0.0.4"};
static char *evpnpeeringtest_lans[EVPNPEERINGTEST_NODES] = {"192.168.10.0", "192.168.20.0", NULL};
static char *evpnpeeringtest_lan_hosts[EVPNPEERINGTEST_NODES] = {"192.168.10.10", "192.168.20.10", NULL};

// The broadcast address
static const UCHAR evpnpeeringtest_broadcast[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

// A host of lan: a member of the switch of lan of its node, which keeps the last frame that it took
typedef struct EVPNPEERINGTEST_HOST
{
	char *Name;
	UINT Node;							// The node of its switch
	UCHAR Mac[6];						// Its MAC address ...
	char *Ip;							// ... and its IP address
	bool Broadcast;						// It subscribes to the broadcast group
	UINT Port;							// Its port on the switch
	SRWLOCK Lock;						// Last and LastSize
	volatile LONG Frames;				// Frames that it took
	UCHAR Last[EVPNPEERINGTEST_FRAME];	// The last one, as much as fits ...
	UINT LastSize;						// ... and its size
} EVPNPEERINGTEST_HOST;

// One node, the fake adapter of its host, which keeps the last packet of dc that the host took, its harness VTEP and its switch of
// lan, whose L2 data path is the test
typedef struct EVPNPEERINGTEST_NODE
{
	wchar_t Dir[MAX_PATH];					// Its data directory
	PEER_KEY Key;							// Its static key
	NODE *Node;
	NODE_READER Reader;						// The test thread as a reader of the node's tables, online while it sends
	bool Applied;							// The test applied a state to it
	USHORT Port;							// The UDP port of its VTEP, where its EVPN takes datagrams
	SOCKET Vtep;							// Its harness VTEP: what the other nodes send to its VTEP comes here
	SWITCH *Switch;							// The switch of lan, NULL at node-c
	bool Attached;							// The test attached it to the stretch of the node
	SRWLOCK Lock;							// LastVrf, Last and LastSize
	volatile LONG Arrivals;					// Packets that the host took
	UINT LastVrf;							// The VRF of the last one ...
	UCHAR Last[EVPNPEERINGTEST_SIZE * 2];	// ... and the packet, as much as fits
	UINT LastSize;
} EVPNPEERINGTEST_NODE;

// The test
typedef struct EVPNPEERINGTEST_CTX
{
	UINT NumChecks;
	UINT NumFailed;
	UINT64 Generation;					// The Generation that the test applies ...
	bool WithC;							// ... and whether node-c is a member of dc in it
	UINT Seq;							// The data of the next test frame or packet
	USHORT FabricPort;					// The UDP port of the harness VTEPs: the port of the VTEPs of the peers of each node
	UCHAR RouterMac[6];					// The router MAC of every node (NODE_EVPN_ROUTER_MAC)
	EVPNPEERINGTEST_NODE Nodes[EVPNPEERINGTEST_NODES];
	EVPNPEERINGTEST_HOST Hosts[EVPNPEERINGTEST_HOSTS];
} EVPNPEERINGTEST_CTX;

static bool EvpnPeeringTestCheck(EVPNPEERINGTEST_CTX *ctx, bool ok, char *what, char *fmt, ...) RANZ_PRINTF_FORMAT(4, 5);
static bool EvpnPeeringTestCheck(EVPNPEERINGTEST_CTX *ctx, bool ok, char *what, char *fmt, ...)
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

// The watchdog: a native thread that ends a run that hangs, so that a lost session, route or frame is a failed test instead of a hung
// CI step
static DWORD WINAPI EvpnPeeringTestWatchdog(LPVOID param)
{
	char msg[MAX_SIZE];
	DWORD written = 0;

	if (WaitForSingleObject((HANDLE)param, EVPNPEERINGTEST_BUDGET) != WAIT_TIMEOUT)
	{
		return 0;
	}

	int len = snprintf(msg, sizeof(msg), "EVPNPEERING TEST FAILED (did not finish within %u ms)\n", EVPNPEERINGTEST_BUDGET);
	if (len > 0)
	{
		WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), msg, (DWORD)MIN((UINT)len, (UINT)sizeof(msg) - 1), &written, NULL);
	}

	TerminateProcess(GetCurrentProcess(), 1);

	return 0;
}

//
// Frames, packets and the harness VTEPs
//

// The IPv4 address of a text into addr, 4 bytes; false for none
static bool EvpnPeeringTestIp4(UCHAR *addr, char *str)
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

// The gratuitous ARP of host h into buf, an ARP request for its own address to every host: the switch of its node learns its MAC
// address and its IP address from it. Its size.
static UINT EvpnPeeringTestAnnounce(UCHAR *buf, EVPNPEERINGTEST_HOST *h)
{
	UCHAR ip[4];

	EvpnPeeringTestIp4(ip, h->Ip);
	Zero(buf, 42);
	Copy(buf, evpnpeeringtest_broadcast, 6);
	Copy(buf + 6, h->Mac, 6);
	WRITE_USHORT(buf + 12, MAC_PROTO_ARPV4);
	WRITE_USHORT(buf + 14, 1);
	WRITE_USHORT(buf + 16, MAC_PROTO_IPV4);
	buf[18] = 6;
	buf[19] = 4;
	WRITE_USHORT(buf + 20, 1);
	Copy(buf + 22, h->Mac, 6);
	Copy(buf + 28, ip, 4);
	Copy(buf + 38, ip, 4);

	return 42;
}

// A frame of host from to the MAC address mac into buf, EVPNPEERINGTEST_FRAME bytes: an IPv4 packet of UDP from the address of the
// host to the address to, with the data seq. Its size.
static UINT EvpnPeeringTestFrame(UCHAR *buf, EVPNPEERINGTEST_HOST *from, const UCHAR *mac, char *to, UINT seq)
{
	UCHAR *ip = buf + 14;
	UCHAR *udp = ip + 20;

	Zero(buf, EVPNPEERINGTEST_FRAME);
	Copy(buf, mac, 6);
	Copy(buf + 6, from->Mac, 6);
	WRITE_USHORT(buf + 12, MAC_PROTO_IPV4);

	ip[0] = 0x45;
	WRITE_USHORT(ip + 2, EVPNPEERINGTEST_FRAME - 14);
	ip[8] = 64;
	ip[9] = IP_PROTO_UDP;
	EvpnPeeringTestIp4(ip + 12, from->Ip);
	EvpnPeeringTestIp4(ip + 16, to);
	USHORT sum = IpChecksum(ip, 20);
	Copy(ip + 10, &sum, 2);

	WRITE_USHORT(udp, 5000);
	WRITE_USHORT(udp + 2, 5001);
	WRITE_USHORT(udp + 4, EVPNPEERINGTEST_FRAME - 14 - 20);
	WRITE_UINT(udp + 8, seq);
	for (UINT i = 34 + 12;i < EVPNPEERINGTEST_FRAME;i++)
	{
		buf[i] = (UCHAR)(i * 7 + seq);
	}

	return EVPNPEERINGTEST_FRAME;
}

// A UDP packet of IPv4 from src to dst with the data seq, EVPNPEERINGTEST_SIZE bytes, into buf: its size, 0 when an end is no IPv4
// address
static UINT EvpnPeeringTestPacket(UCHAR *buf, char *src, char *dst, UINT seq)
{
	UCHAR s[4], d[4];

	if (EvpnPeeringTestIp4(s, src) == false || EvpnPeeringTestIp4(d, dst) == false)
	{
		return 0;
	}

	Zero(buf, EVPNPEERINGTEST_SIZE);
	buf[0] = 0x45;
	WRITE_USHORT(buf + 2, EVPNPEERINGTEST_SIZE);
	buf[8] = 64;
	buf[9] = IP_PROTO_UDP;
	Copy(buf + 12, s, 4);
	Copy(buf + 16, d, 4);
	USHORT sum = IpChecksum(buf, 20);
	Copy(buf + 10, &sum, 2);

	WRITE_USHORT(buf + 20, 5000);
	WRITE_USHORT(buf + 22, 53);
	WRITE_USHORT(buf + 24, EVPNPEERINGTEST_SIZE - 20);
	WRITE_UINT(buf + 28, seq);
	for (UINT i = 32;i < EVPNPEERINGTEST_SIZE;i++)
	{
		buf[i] = (UCHAR)(i * 13 + seq);
	}

	return EVPNPEERINGTEST_SIZE;
}

// A free UDP port of the wildcard address, which the system picks: 0 for none
static USHORT EvpnPeeringTestFreePort(void)
{
	struct sockaddr_in6 sa;
	int size = sizeof(sa);
	USHORT port = 0;
	SOCKET s = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);

	if (s == INVALID_SOCKET)
	{
		return 0;
	}

	Zero(&sa, sizeof(sa));
	sa.sin6_family = AF_INET6;
	if (bind(s, (struct sockaddr *)&sa, sizeof(sa)) == 0 && getsockname(s, (struct sockaddr *)&sa, &size) == 0)
	{
		port = ntohs(sa.sin6_port);
	}

	closesocket(s);

	return port;
}

// A UDP socket on the IPv4 address addr, in host byte order, and port, 0 for one that the system picks, into *s: its port, 0 when it
// could not be opened
static USHORT EvpnPeeringTestBind(SOCKET *s, UINT addr, USHORT port)
{
	struct sockaddr_in sa;
	int size = sizeof(sa);

	*s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (*s == INVALID_SOCKET)
	{
		return 0;
	}

	Zero(&sa, sizeof(sa));
	sa.sin_family = AF_INET;
	sa.sin_addr.s_addr = htonl(addr);
	sa.sin_port = htons(port);
	if (bind(*s, (struct sockaddr *)&sa, sizeof(sa)) != 0 || getsockname(*s, (struct sockaddr *)&sa, &size) != 0)
	{
		closesocket(*s);
		*s = INVALID_SOCKET;
		return 0;
	}

	return ntohs(sa.sin_port);
}

// The harness VTEPs on the addresses of the nodes, on one UDP port that the system picks for the first, into ctx: whether all opened
static bool EvpnPeeringTestOpenVteps(EVPNPEERINGTEST_CTX *ctx)
{
	bool all = false;

	for (UINT tries = 0;tries < 8 && all == false;tries++)
	{
		for (UINT i = 0;i < EVPNPEERINGTEST_NODES;i++)
		{
			if (ctx->Nodes[i].Vtep != INVALID_SOCKET)
			{
				closesocket(ctx->Nodes[i].Vtep);
				ctx->Nodes[i].Vtep = INVALID_SOCKET;
			}
		}

		ctx->FabricPort = EvpnPeeringTestBind(&ctx->Nodes[0].Vtep, evpnpeeringtest_addr_values[0], 0);
		all = (ctx->FabricPort != 0);
		for (UINT i = 1;i < EVPNPEERINGTEST_NODES && all;i++)
		{
			all = (EvpnPeeringTestBind(&ctx->Nodes[i].Vtep, evpnpeeringtest_addr_values[i], ctx->FabricPort) != 0);
		}
	}

	return all;
}

// The next datagram that the socket s takes within timeout ms, into buf of size bytes: its size, 0 for none
static UINT EvpnPeeringTestTake(SOCKET s, UCHAR *buf, UINT size, UINT timeout)
{
	fd_set fds;
	struct timeval tv;

	FD_ZERO(&fds);
	FD_SET(s, &fds);
	tv.tv_sec = (long)(timeout / 1000);
	tv.tv_usec = (long)((timeout % 1000) * 1000);

	if (select(0, &fds, NULL, NULL, &tv) != 1)
	{
		return 0;
	}

	int got = recvfrom(s, (char *)buf, (int)size, 0, NULL, NULL);

	return (got > 0 ? (UINT)got : 0);
}

// Drop what the harness VTEPs hold
static void EvpnPeeringTestDrain(EVPNPEERINGTEST_CTX *ctx)
{
	UCHAR buf[VXLAN_MAX_DATAGRAM];

	for (UINT i = 0;i < EVPNPEERINGTEST_NODES;i++)
	{
		while (EvpnPeeringTestTake(ctx->Nodes[i].Vtep, buf, sizeof(buf), 0) != 0)
		{
		}
	}
}

// The VNI of the VXLAN header of the datagram d, which holds one
static UINT EvpnPeeringTestVni(const UCHAR *d)
{
	return (((UINT)d[4] << 16) | ((UINT)d[5] << 8) | d[6]);
}

// The VNI of the datagram d of size bytes as the detail of a check: 0 for a datagram too short for a VXLAN header
static UINT EvpnPeeringTestVniOf(const UCHAR *d, UINT size)
{
	return (size >= VXLAN_HEADER_SIZE ? EvpnPeeringTestVni(d) : 0);
}

// Whether the datagram d of size bytes is the VXLAN datagram of frame, frame_size bytes, on the L2 VNI of lan: the I flag and the VNI,
// then the frame as it was sent
static bool EvpnPeeringTestIsFrame(const UCHAR *d, UINT size, const UCHAR *frame, UINT frame_size)
{
	if (size != VXLAN_HEADER_SIZE + frame_size || d[0] != VXLAN_FLAG_VNI || EvpnPeeringTestVni(d) != EVPNPEERINGTEST_L2VNI)
	{
		return false;
	}

	return (Cmp(d + VXLAN_HEADER_SIZE, frame, frame_size) == 0);
}

// Whether the datagram d of size bytes is the VXLAN datagram of the IP packet packet, packet_size bytes, on the L3 VNI of dc: the I
// flag and the VNI, an Ethernet header from the router MAC to the router MAC with the EtherType of IPv4, then the packet as it was sent
static bool EvpnPeeringTestIsPacket(EVPNPEERINGTEST_CTX *ctx, const UCHAR *d, UINT size, const UCHAR *packet, UINT packet_size)
{
	const UCHAR *f = d + VXLAN_HEADER_SIZE;

	if (size != VXLAN_HEADER_SIZE + NODE_EVPN_ETHER + packet_size || d[0] != VXLAN_FLAG_VNI || EvpnPeeringTestVni(d) != EVPNPEERINGTEST_L3VNI)
	{
		return false;
	}

	return (Cmp(f, ctx->RouterMac, 6) == 0 && Cmp(f + 6, ctx->RouterMac, 6) == 0 && READ_USHORT(f + 12) == MAC_PROTO_IPV4 &&
		Cmp(f + NODE_EVPN_ETHER, packet, packet_size) == 0);
}

// Pass the datagram d of size bytes on to the VTEP of node to, from the harness VTEP of node from, so that it comes from the address
// of node from, as it would between two hosts: whether it went
static bool EvpnPeeringTestRelay(EVPNPEERINGTEST_CTX *ctx, UINT from, UINT to, const UCHAR *d, UINT size)
{
	struct sockaddr_in sa;

	Zero(&sa, sizeof(sa));
	sa.sin_family = AF_INET;
	sa.sin_addr.s_addr = htonl(evpnpeeringtest_addr_values[to]);
	sa.sin_port = htons(ctx->Nodes[to].Port);

	return sendto(ctx->Nodes[from].Vtep, (const char *)d, (int)size, 0, (struct sockaddr *)&sa, sizeof(sa)) == (int)size;
}

//
// The hosts of lan and the switches
//

// A host takes a frame that the switch of its node delivers to its port (SWITCH_SEND_PROC): a frame of another node comes on the
// receive thread of the VTEP of the node, one of another host on the thread of the test, so the lock orders the two
static void EvpnPeeringTestHostTake(void *param, UINT port, const UCHAR *frame, UINT size)
{
	EVPNPEERINGTEST_HOST *h = (EVPNPEERINGTEST_HOST *)param;

	UNREFERENCED_PARAMETER(port);

	AcquireSRWLockExclusive(&h->Lock);
	{
		h->LastSize = size;
		Copy(h->Last, frame, MIN(size, (UINT)sizeof(h->Last)));
		InterlockedIncrement(&h->Frames);
	}
	ReleaseSRWLockExclusive(&h->Lock);
}

// The frames that host h took so far
static LONG EvpnPeeringTestFrames(EVPNPEERINGTEST_HOST *h)
{
	return InterlockedCompareExchange(&h->Frames, 0, 0);
}

// Whether host h took more than before frames within timeout ms
static bool EvpnPeeringTestArrived(EVPNPEERINGTEST_HOST *h, LONG before, UINT timeout)
{
	UINT64 end = Tick64() + timeout;

	while (EvpnPeeringTestFrames(h) <= before)
	{
		if (Tick64() >= end)
		{
			return false;
		}
		SleepThread(EVPNPEERINGTEST_POLL);
	}

	return true;
}

// Whether the last frame of host h is frame, size bytes
static bool EvpnPeeringTestLastIs(EVPNPEERINGTEST_HOST *h, const UCHAR *frame, UINT size)
{
	bool same = false;

	AcquireSRWLockShared(&h->Lock);
	{
		same = (h->LastSize == size && size <= sizeof(h->Last) && Cmp(h->Last, frame, size) == 0);
	}
	ReleaseSRWLockShared(&h->Lock);

	return same;
}

// Host h sends frame, size bytes, into the switch of its node
static void EvpnPeeringTestSend(EVPNPEERINGTEST_CTX *ctx, EVPNPEERINGTEST_HOST *h, const UCHAR *frame, UINT size)
{
	SwitchInput(ctx->Nodes[h->Node].Switch, GetTickCount64(), h->Port, frame, size);
}

// Host h announces its MAC address and its IP address with a gratuitous ARP into the switch of its node
static void EvpnPeeringTestAnnounceHost(EVPNPEERINGTEST_CTX *ctx, EVPNPEERINGTEST_HOST *h)
{
	UCHAR arp[42];
	UINT size = EvpnPeeringTestAnnounce(arp, h);

	EvpnPeeringTestSend(ctx, h, arp, size);
}

// Whether the switch of node i holds the MAC address mac at a port that is no port of a host of the test, the port of the fabric,
// within EVPNPEERINGTEST_WAIT
static bool EvpnPeeringTestWaitRemoteMac(EVPNPEERINGTEST_CTX *ctx, UINT i, const UCHAR *mac)
{
	UINT64 end = Tick64() + EVPNPEERINGTEST_WAIT;
	SWITCH_MAC_ENTRY list[32];

	while (true)
	{
		UINT num = SwitchGetMacs(ctx->Nodes[i].Switch, list, 32);

		for (UINT k = 0;k < num && k < 32;k++)
		{
			bool host = false;

			for (UINT j = 0;j < EVPNPEERINGTEST_HOSTS;j++)
			{
				host = host || (ctx->Hosts[j].Node == i && ctx->Hosts[j].Port == list[k].Port);
			}
			if (Cmp(list[k].Mac, mac, 6) == 0 && host == false)
			{
				return true;
			}
		}
		if (Tick64() >= end)
		{
			return false;
		}
		SleepThread(EVPNPEERINGTEST_POLL);
	}
}

//
// The nodes and their desired states
//

// The fake adapter of a host of dc: it counts the packets that the host takes and keeps the last one
static void EvpnPeeringTestAdapter(NODE *n, void *param, UINT vrf_id, const UCHAR *packet, UINT size)
{
	EVPNPEERINGTEST_NODE *t = (EVPNPEERINGTEST_NODE *)param;

	AcquireSRWLockExclusive(&t->Lock);
	{
		t->LastVrf = vrf_id;
		t->LastSize = size;
		Copy(t->Last, packet, MIN(size, sizeof(t->Last)));
		InterlockedIncrement(&t->Arrivals);
	}
	ReleaseSRWLockExclusive(&t->Lock);
}

// The packets that the host of node t took so far
static LONG EvpnPeeringTestArrivals(EVPNPEERINGTEST_NODE *t)
{
	return InterlockedCompareExchange(&t->Arrivals, 0, 0);
}

// Whether the host of node t took more than before packets within timeout, the last of them packet, size bytes, in dc
static bool EvpnPeeringTestDelivered(EVPNPEERINGTEST_NODE *t, LONG before, UINT timeout, const UCHAR *packet, UINT size)
{
	UINT64 end = Tick64() + timeout;
	bool same = false;

	while (EvpnPeeringTestArrivals(t) <= before)
	{
		if (Tick64() >= end)
		{
			return false;
		}
		SleepThread(EVPNPEERINGTEST_POLL);
	}

	AcquireSRWLockShared(&t->Lock);
	{
		same = (t->LastVrf == EVPNPEERINGTEST_VRF && t->LastSize == size && Cmp(t->Last, packet, size) == 0);
	}
	ReleaseSRWLockShared(&t->Lock);

	return same;
}

// The host of node i sends packet, size bytes, into dc: whether the overlay took it
static bool EvpnPeeringTestInput(EVPNPEERINGTEST_CTX *ctx, UINT i, const UCHAR *packet, UINT size)
{
	EVPNPEERINGTEST_NODE *t = &ctx->Nodes[i];

	NodeReaderOnline(t->Node, &t->Reader);
	bool taken = (size != 0 && NodeOverlayInput(t->Node, EVPNPEERINGTEST_VRF, packet, size));
	NodeReaderOffline(&t->Reader);

	return taken;
}

// Whether node i is a member of dc in the Generation that the test applies: node-a and node-b always, node-c in Generation 2
static bool EvpnPeeringTestIn(EVPNPEERINGTEST_CTX *ctx, UINT i)
{
	return (i != EVPNPEERINGTEST_C || ctx->WithC);
}

// The members of dc in the Generation that the test applies
static UINT EvpnPeeringTestMembers(EVPNPEERINGTEST_CTX *ctx)
{
	UINT num = 0;

	for (UINT i = 0;i < EVPNPEERINGTEST_NODES;i++)
	{
		num += (EvpnPeeringTestIn(ctx, i) ? 1 : 0);
	}

	return num;
}

// A route of the control protocol: the IPv4 prefix addr/length of dc
static void EvpnPeeringTestRoute(CONTROL_ROUTE *r, char *addr, UINT length)
{
	Zero(r, sizeof(CONTROL_ROUTE));
	r->VrfId = EVPNPEERINGTEST_VRF;
	r->AddressSize = 4;
	r->Length = length;
	EvpnPeeringTestIp4(r->Address, addr);
}

// The address of node i in dc-net, as the control protocol carries it
static void EvpnPeeringTestAddress(CONTROL_ADDRESS *a, UINT i)
{
	Zero(a, sizeof(CONTROL_ADDRESS));
	StrCpy(a->Network, sizeof(a->Network), "dc-net");
	a->VrfId = EVPNPEERINGTEST_VRF;
	a->AddressSize = 4;
	a->Length = EVPNPEERINGTEST_LENGTH;
	EvpnPeeringTestIp4(a->Address, evpnpeeringtest_dc[i]);
}

// The desired state of node i in the Generation that the test applies, as the Controller compiles it for a VRF whose peering is evpn:
// VRF dc of a link of kind vxlan, whose VNI is its L3 VNI, that peers by EVPN; the address of the node in dc-net; the LAN subnet behind
// it, which leads to its host and which it announces; the L2 VNI of lan; the UDP port of its VTEP; the settings of its sidecar; and the
// other members of dc as its peers in name order, each with its address in dc-net and the BGP peering with it: the address of its
// sidecar, the hold time, the VRF and what the peer may announce there, its address as a host route and its LAN subnet. No peer has a
// tunnel endpoint or a route: the routes of the peers fill the flood list and lead to them. A node that is no member of dc has the
// state of the Generation without a VRF. EvpnPeeringTestFreeState frees it.
static CONTROL_STATE *EvpnPeeringTestState(EVPNPEERINGTEST_CTX *ctx, UINT i)
{
	CONTROL_STATE *st = ZeroMalloc(sizeof(CONTROL_STATE));

	st->Generation = ctx->Generation;
	StrCpy(st->Name, sizeof(st->Name), evpnpeeringtest_names[i]);
	if (EvpnPeeringTestIn(ctx, i) == false)
	{
		return st;
	}

	CONTROL_VRF *v = &st->Vrfs[st->NumVrfs++];
	StrCpy(v->Name, sizeof(v->Name), "dc");
	v->Id = EVPNPEERINGTEST_VRF;
	v->Link = CONTROL_LINK_VXLAN;
	v->Vni = EVPNPEERINGTEST_L3VNI;
	v->Peering = true;
	v->PeeringEvpn = true;

	EvpnPeeringTestAddress(&st->Addresses[st->NumAddresses++], i);
	st->Vtep.VxlanPort = ctx->Nodes[i].Port;

	CONTROL_L2VNI *l = &st->L2Vnis[st->NumL2Vnis++];
	StrCpy(l->Network, sizeof(l->Network), "lan");
	l->VrfId = EVPNPEERINGTEST_VRF;
	l->Vni = EVPNPEERINGTEST_L2VNI;

	CONTROL_PEERING *own = ZeroMalloc(sizeof(CONTROL_PEERING));
	own->Asn = EVPNPEERINGTEST_ASN;
	EvpnPeeringTestIp4(own->RouterId, evpnpeeringtest_addrs[i]);
	EvpnPeeringTestIp4(own->Address, evpnpeeringtest_addrs[i]);
	own->AddressSize = 4;
	if (evpnpeeringtest_lans[i] != NULL)
	{
		EvpnPeeringTestRoute(&st->LanSubnets[st->NumLanSubnets++], evpnpeeringtest_lans[i], EVPNPEERINGTEST_LENGTH);
		EvpnPeeringTestRoute(&own->Announce[own->NumAnnounce++], evpnpeeringtest_lans[i], EVPNPEERINGTEST_LENGTH);
	}
	st->Peering = own;

	st->Peers = ZeroMalloc(sizeof(CONTROL_PEER) * (EVPNPEERINGTEST_NODES - 1));
	for (UINT j = 0;j < EVPNPEERINGTEST_NODES;j++)
	{
		if (j == i || EvpnPeeringTestIn(ctx, j) == false)
		{
			continue;
		}

		CONTROL_PEER *cp = &st->Peers[st->NumPeers++];
		CONTROL_PEER_PEERING *pp = ZeroMalloc(sizeof(CONTROL_PEER_PEERING));

		StrCpy(cp->Name, sizeof(cp->Name), evpnpeeringtest_names[j]);
		Copy(cp->Key, ctx->Nodes[j].Key.Public, PEER_KEY_SIZE);
		cp->VrfIds[cp->NumVrfs++] = EVPNPEERINGTEST_VRF;
		EvpnPeeringTestAddress(&cp->Addresses[cp->NumAddresses++], j);

		EvpnPeeringTestIp4(pp->Address, evpnpeeringtest_addrs[j]);
		pp->AddressSize = 4;
		pp->HoldTime = EVPNPEERINGTEST_HOLD;
		pp->VrfIds[pp->NumVrfs++] = EVPNPEERINGTEST_VRF;
		EvpnPeeringTestRoute(&pp->Accept[pp->NumAccept++], evpnpeeringtest_dc[j], 32);
		if (evpnpeeringtest_lans[j] != NULL)
		{
			EvpnPeeringTestRoute(&pp->Accept[pp->NumAccept++], evpnpeeringtest_lans[j], EVPNPEERINGTEST_LENGTH);
		}
		cp->Peering = pp;
	}

	return st;
}

static void EvpnPeeringTestFreeState(CONTROL_STATE *st)
{
	for (UINT i = 0;i < st->NumPeers;i++)
	{
		Free(st->Peers[i].Peering);
	}

	Free(st->Peers);
	Free(st->Peering);
	Free(st);
}

// A new empty data directory under the temp directory of the process, with a configuration store that runs no role on one worker
static void EvpnPeeringTestNewDir(wchar_t *dir, UINT size, char *name)
{
	wchar_t tmp[MAX_PATH];
	wchar_t path[MAX_PATH];

	UniFormat(tmp, sizeof(tmp), L"evpnpeeringtest_%S_%u", name, Rand32());
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
static void EvpnPeeringTestDeleteFiles(wchar_t *dir)
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

// The text of every file of the node log directory of dir, the log of the sidecar among them; NULL when there is none. The caller frees
// it.
static char *EvpnPeeringTestReadLog(wchar_t *dir)
{
	wchar_t log_dir[MAX_PATH];
	BUF *all = NewBuf();

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

// Apply the Generation gen, in which node-c is a member of dc with with_c, to each member of dc, and to a node that had a state before
// and is no member now: whether every node took its state
static bool EvpnPeeringTestApply(EVPNPEERINGTEST_CTX *ctx, UINT64 gen, bool with_c)
{
	bool ok = true;

	ctx->Generation = gen;
	ctx->WithC = with_c;

	for (UINT i = 0;i < EVPNPEERINGTEST_NODES;i++)
	{
		EVPNPEERINGTEST_NODE *t = &ctx->Nodes[i];

		if (EvpnPeeringTestIn(ctx, i) == false && t->Applied == false)
		{
			continue;
		}

		CONTROL_STATE *st = EvpnPeeringTestState(ctx, i);
		ok = NodeOverlayApply(t->Node, st) && ok;
		t->Applied = true;
		EvpnPeeringTestFreeState(st);
	}

	return ok;
}

// Whether each member of dc runs the Generation with its session of the overlay to each other member up, within EVPNPEERINGTEST_BOUND
static bool EvpnPeeringTestWaitOverlay(EVPNPEERINGTEST_CTX *ctx)
{
	UINT64 end = Tick64() + EVPNPEERINGTEST_BOUND;
	UINT peers = EvpnPeeringTestMembers(ctx) - 1;

	while (true)
	{
		bool ok = true;

		for (UINT i = 0;i < EVPNPEERINGTEST_NODES && ok;i++)
		{
			NODE_OVERLAY_STATUS st;

			if (EvpnPeeringTestIn(ctx, i) == false)
			{
				continue;
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
		SleepThread(EVPNPEERINGTEST_POLL);
	}
}

// Whether the sidecar of each member of dc runs with exactly the other members as its peers, each with its session established, within
// EVPNPEERINGTEST_BOUND. The members whose peers differ are printed.
static bool EvpnPeeringTestWaitSessions(EVPNPEERINGTEST_CTX *ctx)
{
	UINT64 end = Tick64() + EVPNPEERINGTEST_BOUND;
	UINT peers = EvpnPeeringTestMembers(ctx) - 1;
	bool ok = false;

	while (true)
	{
		ok = true;
		for (UINT i = 0;i < EVPNPEERINGTEST_NODES && ok;i++)
		{
			NODE_PEERING_STATUS st;

			if (EvpnPeeringTestIn(ctx, i) == false)
			{
				continue;
			}

			NodePeeringGetStatus(ctx->Nodes[i].Node, &st);
			ok = (st.Running && st.NumPeers == peers && st.NumEstablished == peers);
		}
		if (ok || Tick64() >= end)
		{
			break;
		}
		SleepThread(EVPNPEERINGTEST_POLL);
	}

	for (UINT i = 0;i < EVPNPEERINGTEST_NODES && ok == false;i++)
	{
		NODE_PEERING_STATUS st;

		if (EvpnPeeringTestIn(ctx, i) == false)
		{
			continue;
		}

		NodePeeringGetStatus(ctx->Nodes[i].Node, &st);
		Print("  [INFO] %s: running %u, %u peers, %u established, want %u of each\n", evpnpeeringtest_names[i], (UINT)st.Running, st.NumPeers, st.NumEstablished, peers);
	}

	return ok;
}

// Apply the Generation gen, in which node-c is a member of dc with with_c, and wait for its overlays and its sessions: whether they run
static bool EvpnPeeringTestGeneration(EVPNPEERINGTEST_CTX *ctx, UINT64 gen, bool with_c, char *what)
{
	bool applied = EvpnPeeringTestApply(ctx, gen, with_c);
	bool overlays = applied && EvpnPeeringTestWaitOverlay(ctx);
	bool sessions = overlays && EvpnPeeringTestWaitSessions(ctx);

	return EvpnPeeringTestCheck(ctx, sessions, what, "applied %u, the overlays run it with their sessions up %u, the sessions of the sidecars established %u", (UINT)applied,
		(UINT)overlays, (UINT)sessions);
}

//
// The routes
//

// Whether list, num routes of lan, holds the type-3 route of the VTEP vtep (mac NULL), or the type-2 route of mac with the IP address
// ip (NULL for MAC only) via the VTEP vtep, on the L2 VNI of lan
static bool EvpnPeeringTestHasRoute(const NODE_STRETCH_ROUTE *list, UINT num, const UCHAR *mac, char *ip, char *vtep)
{
	UCHAR want_vtep[16];
	UCHAR want_ip[4];

	Zero(want_vtep, sizeof(want_vtep));
	Zero(want_ip, sizeof(want_ip));
	want_vtep[10] = 0xFF;
	want_vtep[11] = 0xFF;
	EvpnPeeringTestIp4(want_vtep + 12, vtep);
	if (ip != NULL)
	{
		EvpnPeeringTestIp4(want_ip, ip);
	}

	for (UINT i = 0;i < num;i++)
	{
		const NODE_STRETCH_ROUTE *r = &list[i];

		if (r->Vni != EVPNPEERINGTEST_L2VNI || r->Imet != (mac == NULL) || Cmp(r->Vtep, want_vtep, 16) != 0)
		{
			continue;
		}
		if (mac == NULL)
		{
			return true;
		}
		if (Cmp(r->Mac, mac, 6) == 0 && ((ip == NULL && r->IpSize == 0) || (ip != NULL && r->IpSize == 4 && Cmp(r->Ip, want_ip, 4) == 0)))
		{
			return true;
		}
	}

	return false;
}

// Whether node i of Generation 1 holds the routes of lan of the other node, and these only, before host m moves (moved false) or after
// (moved true): node-a the type-3 route of node-b and the type-2 routes of host 2, MAC only and MAC plus IP, via the VTEP of node-b,
// and after the move those of host m too; node-b the type-3 route of node-a and the type-2 routes of host 1 via the VTEP of node-a,
// and before the move those of host m too
static bool EvpnPeeringTestL2Routes(EVPNPEERINGTEST_CTX *ctx, UINT i, bool moved)
{
	NODE_STRETCH_ROUTE list[EVPNPEERINGTEST_ROUTES];
	UINT num = NodeStretchGetRoutes(ctx->Nodes[i].Node, list, EVPNPEERINGTEST_ROUTES);
	EVPNPEERINGTEST_HOST *m = &ctx->Hosts[EVPNPEERINGTEST_HOST_M];
	EVPNPEERINGTEST_HOST *h = &ctx->Hosts[i == EVPNPEERINGTEST_A ? EVPNPEERINGTEST_HOST_2 : EVPNPEERINGTEST_HOST_1];
	char *other = evpnpeeringtest_addrs[i == EVPNPEERINGTEST_A ? EVPNPEERINGTEST_B : EVPNPEERINGTEST_A];
	bool with_m = (moved == (i == EVPNPEERINGTEST_A));

	if (num > EVPNPEERINGTEST_ROUTES)
	{
		return false;
	}

	bool ok = EvpnPeeringTestHasRoute(list, num, NULL, NULL, other) && EvpnPeeringTestHasRoute(list, num, h->Mac, NULL, other) &&
		EvpnPeeringTestHasRoute(list, num, h->Mac, h->Ip, other);
	if (with_m)
	{
		ok = ok && EvpnPeeringTestHasRoute(list, num, m->Mac, NULL, other) && EvpnPeeringTestHasRoute(list, num, m->Mac, m->Ip, other);
	}

	return (ok && num == (with_m ? 5U : 3U));
}

// Whether node-a and node-b hold their routes of lan before or after the move (EvpnPeeringTestL2Routes), within EVPNPEERINGTEST_BOUND
static bool EvpnPeeringTestWaitL2Routes(EVPNPEERINGTEST_CTX *ctx, bool moved)
{
	UINT64 end = Tick64() + EVPNPEERINGTEST_BOUND;

	while (EvpnPeeringTestL2Routes(ctx, EVPNPEERINGTEST_A, moved) == false || EvpnPeeringTestL2Routes(ctx, EVPNPEERINGTEST_B, moved) == false)
	{
		if (Tick64() >= end)
		{
			return false;
		}
		SleepThread(EVPNPEERINGTEST_POLL * 5);
	}

	return true;
}

// Whether list, num IP prefix routes, holds the route of addr/length in dc via the VTEP vtep with the L3 VNI of dc
static bool EvpnPeeringTestHasPrefix(const NODE_EVPN_ROUTE *list, UINT num, char *addr, UINT length, char *vtep)
{
	char prefix[EVPNPEERINGTEST_TEXT];

	Format(prefix, sizeof(prefix), "%s/%u", addr, length);

	for (UINT i = 0;i < num;i++)
	{
		const NODE_EVPN_ROUTE *r = &list[i];

		if (r->VrfId == EVPNPEERINGTEST_VRF && r->Vni == EVPNPEERINGTEST_L3VNI && StrCmp(r->Prefix, prefix) == 0 && StrCmp(r->NextHop, vtep) == 0)
		{
			return true;
		}
	}

	return false;
}

// Whether node i holds the IP prefix routes of each other member of dc, and these only: its address as a host route and its LAN subnet,
// via its VTEP with the L3 VNI of dc
static bool EvpnPeeringTestPrefixes(EVPNPEERINGTEST_CTX *ctx, UINT i)
{
	NODE_EVPN_ROUTE *list = ZeroMalloc(sizeof(NODE_EVPN_ROUTE) * EVPNPEERINGTEST_ROUTES);
	UINT num = NodePeeringGetEvpnRoutes(ctx->Nodes[i].Node, list, EVPNPEERINGTEST_ROUTES);
	UINT want = 0;
	bool ok = (num <= EVPNPEERINGTEST_ROUTES);

	for (UINT j = 0;j < EVPNPEERINGTEST_NODES && ok;j++)
	{
		if (j == i || EvpnPeeringTestIn(ctx, j) == false)
		{
			continue;
		}

		want++;
		ok = EvpnPeeringTestHasPrefix(list, num, evpnpeeringtest_dc[j], 32, evpnpeeringtest_addrs[j]);
		if (ok && evpnpeeringtest_lans[j] != NULL)
		{
			want++;
			ok = EvpnPeeringTestHasPrefix(list, num, evpnpeeringtest_lans[j], EVPNPEERINGTEST_LENGTH, evpnpeeringtest_addrs[j]);
		}
	}

	Free(list);

	return (ok && num == want);
}

// Whether each member of dc holds the IP prefix routes of the others (EvpnPeeringTestPrefixes), within EVPNPEERINGTEST_BOUND
static bool EvpnPeeringTestWaitPrefixes(EVPNPEERINGTEST_CTX *ctx)
{
	UINT64 end = Tick64() + EVPNPEERINGTEST_BOUND;

	while (true)
	{
		bool ok = true;

		for (UINT i = 0;i < EVPNPEERINGTEST_NODES && ok;i++)
		{
			ok = (EvpnPeeringTestIn(ctx, i) == false || EvpnPeeringTestPrefixes(ctx, i));
		}
		if (ok)
		{
			return true;
		}
		if (Tick64() >= end)
		{
			return false;
		}
		SleepThread(EVPNPEERINGTEST_POLL * 5);
	}
}

// The type-3 routes of lan that node-a holds: the VTEPs of its flood list
static UINT EvpnPeeringTestFloodListSize(EVPNPEERINGTEST_CTX *ctx)
{
	NODE_STRETCH_STATUS st;

	NodeStretchGetStatus(ctx->Nodes[EVPNPEERINGTEST_A].Node, &st);

	return st.NumVteps;
}

// Whether node-a holds num type-3 routes of lan, the VTEPs of its flood list, within EVPNPEERINGTEST_BOUND
static bool EvpnPeeringTestWaitFloodList(EVPNPEERINGTEST_CTX *ctx, UINT num)
{
	UINT64 end = Tick64() + EVPNPEERINGTEST_BOUND;

	while (EvpnPeeringTestFloodListSize(ctx) != num)
	{
		if (Tick64() >= end)
		{
			return false;
		}
		SleepThread(EVPNPEERINGTEST_POLL * 5);
	}

	return true;
}

//
// The cases
//

// The nodes, their overlays and their harness VTEPs, the switches of lan of node-a and node-b with their hosts, which the L2 data path
// of the test attaches to the stretch of each node before its first Generation, and Generation 1: node-a and node-b in dc, each with its
// EVPN on the VTEP of its address, the switch of lan the stretch of its L2 VNI
static bool EvpnPeeringTestOpen(EVPNPEERINGTEST_CTX *ctx, TRANSPORT *loopback)
{
	UCHAR scalar[PEER_KEY_SIZE];
	char what[MAX_SIZE * 2];
	bool ok = (loopback != NULL && NodeEvpnParseMac(NODE_EVPN_ROUTER_MAC, ctx->RouterMac));

	Print("[the nodes, their overlays, the switches of lan and the harness VTEPs]\n");

	// The UDP port of the VTEP of each node, each another, and the harness VTEPs on the addresses of the nodes on one more port
	bool ports = true;
	for (UINT i = 0;i < EVPNPEERINGTEST_NODES;i++)
	{
		ctx->Nodes[i].Port = EvpnPeeringTestFreePort();
		ports = (ctx->Nodes[i].Port != 0) && ports;
	}
	ports = EvpnPeeringTestOpenVteps(ctx) && ports;
	for (UINT i = 0;i < EVPNPEERINGTEST_NODES;i++)
	{
		ports = (ctx->Nodes[i].Port != ctx->FabricPort) && ports;
		for (UINT j = 0;j < i;j++)
		{
			ports = (ctx->Nodes[i].Port != ctx->Nodes[j].Port) && ports;
		}
	}
	ok = EvpnPeeringTestCheck(ctx, ok && ports, "Free ports: the UDP ports of the VTEPs of the nodes, and the harness VTEPs on 127.0.0.2, 127.0.0.3 and 127.0.0.4 on one more",
		"VTEP ports %u, %u and %u, harness VTEP port %u, error %u", (UINT)ctx->Nodes[0].Port, (UINT)ctx->Nodes[1].Port, (UINT)ctx->Nodes[2].Port, (UINT)ctx->FabricPort,
		(UINT)WSAGetLastError()) && ok;
	if (ok == false)
	{
		return false;
	}
	Print("  [INFO] VTEP ports: node-a %u, node-b %u, node-c %u; the harness VTEPs, the VTEPs of the peers of each node: port %u\n", (UINT)ctx->Nodes[0].Port,
		(UINT)ctx->Nodes[1].Port, (UINT)ctx->Nodes[2].Port, (UINT)ctx->FabricPort);

	for (UINT i = 0;i < EVPNPEERINGTEST_NODES && ok;i++)
	{
		EVPNPEERINGTEST_NODE *t = &ctx->Nodes[i];
		NODE_OVERLAY_CONFIG c;

		InitializeSRWLock(&t->Lock);
		for (UINT j = 0;j < PEER_KEY_SIZE;j++)
		{
			scalar[j] = (UCHAR)(0x61 + PEER_KEY_SIZE * i + j);
		}
		ok = PeerKeyFromScalar(&t->Key, scalar);

		EvpnPeeringTestNewDir(t->Dir, sizeof(t->Dir), evpnpeeringtest_names[i]);
		t->Node = NewNode(t->Dir);
		if (i == 0)
		{
			ok = EvpnPeeringTestCheck(ctx, IsFileExistsW(t->Node->BgpSidecar), "ranz.exe, which holds the sidecar ranz bgp, is next to vpntest.exe", "%S is missing",
				t->Node->BgpSidecar) && ok;
		}
		NodeStart(t->Node);
		NodeReaderRegister(t->Node, &t->Reader);
		NodeReaderOffline(&t->Reader);

		Zero(&c, sizeof(c));
		c.Data = loopback;
		c.Key = &t->Key;
		c.Adapter = EvpnPeeringTestAdapter;
		c.AdapterParam = t;
		Format(what, sizeof(what), "  %s: its overlay runs without a control stream, its sidecar will listen on TCP %u of %s, and the VTEPs of its peers are the harness VTEPs",
			evpnpeeringtest_names[i], (UINT)EVPNPEERINGTEST_PORT, evpnpeeringtest_addrs[i]);
		ok = EvpnPeeringTestCheck(ctx, ok && NodeOverlayStart(t->Node, &c), what, "%s", "PeerKeyFromScalar or NodeOverlayStart failed") && ok;
		// The VTEPs of the peers are the harness VTEPs, on their port
		NodePeeringSetFabricPort(t->Node, ctx->FabricPort);
	}
	Zero(scalar, sizeof(scalar));
	if (ok == false)
	{
		return false;
	}

	// The switch of lan of node-a and node-b, with their hosts, attached to the stretch of the node before its first Generation
	bool members = true;
	for (UINT i = EVPNPEERINGTEST_A;i <= EVPNPEERINGTEST_B;i++)
	{
		ctx->Nodes[i].Switch = SwitchNew(NULL);
		members = (ctx->Nodes[i].Switch != NULL) && members;
	}
	for (UINT i = 0;i < EVPNPEERINGTEST_HOSTS && members;i++)
	{
		EVPNPEERINGTEST_HOST *h = &ctx->Hosts[i];
		EVPNPEERINGTEST_NODE *t = &ctx->Nodes[h->Node];
		SWITCH_PORT_CONFIG pc;

		Zero(&pc, sizeof(pc));
		pc.Mode = SWITCH_ACCESS;
		pc.Vlan = EVPNPEERINGTEST_VLAN;
		pc.Send = EvpnPeeringTestHostTake;
		pc.Param = h;
		h->Port = SwitchAddPort(t->Switch, &pc);
		members = (h->Port != SWITCH_PORT_NONE) && members;
		if (h->Broadcast)
		{
			members = (h->Port != SWITCH_PORT_NONE && SwitchSubscribe(t->Switch, h->Port, EVPNPEERINGTEST_VLAN, evpnpeeringtest_broadcast)) && members;
		}
	}
	for (UINT i = EVPNPEERINGTEST_A;i <= EVPNPEERINGTEST_B && members;i++)
	{
		EVPNPEERINGTEST_NODE *t = &ctx->Nodes[i];

		t->Attached = NodeStretchAttach(t->Node, "lan", t->Switch, EVPNPEERINGTEST_VLAN);
		members = t->Attached && members;
	}
	ok = EvpnPeeringTestCheck(ctx, members, "The switch of lan of node-a with host 1 and host m, and of node-b with host 2 and the port where host m comes later; the L2 data path of the test attaches each to the stretch of its node",
		"%s", "SwitchNew, SwitchAddPort, SwitchSubscribe or NodeStretchAttach failed") && ok;
	if (ok == false)
	{
		return false;
	}

	Print("[Generation 1: node-a and node-b peer by EVPN in dc]\n");
	if (EvpnPeeringTestGeneration(ctx, 1, false, "node-a and node-b run Generation 1, with their sessions of the overlay up, and the sidecar of each has the other as its peer, its session established") == false)
	{
		return false;
	}

	// The EVPN of each node, of the VRF that peers by EVPN, on the VTEP of its address, with the stretch of lan
	for (UINT i = EVPNPEERINGTEST_A;i <= EVPNPEERINGTEST_B;i++)
	{
		EVPNPEERINGTEST_NODE *t = &ctx->Nodes[i];
		NODE_EVPN_STATUS es;
		NODE_STRETCH_STATUS ss;
		bool running = NodePeeringGetEvpnStatus(t->Node, &es);

		NodeStretchGetStatus(t->Node, &ss);
		Format(what, sizeof(what), "%s: the EVPN of dc runs with its sidecar of the peering on UDP port %u of its VTEP, one EVPN VRF and the stretch of lan on its switch",
			evpnpeeringtest_names[i], (UINT)t->Port);
		ok = EvpnPeeringTestCheck(ctx, running && es.Running && es.Port == t->Port && es.FabricPort == ctx->FabricPort && es.NumVrfs == 1 && ss.NumStretches == 1 &&
			ss.NumAttached == 1, what, "running %u, port %u, the VTEPs of the peers on port %u, %u VRFs, %u stretches, %u attached", (UINT)running, (UINT)es.Port,
			(UINT)es.FabricPort, es.NumVrfs, ss.NumStretches, ss.NumAttached) && ok;
	}

	// The hosts announce themselves into their switches, and the nodes announce them
	EvpnPeeringTestAnnounceHost(ctx, &ctx->Hosts[EVPNPEERINGTEST_HOST_1]);
	EvpnPeeringTestAnnounceHost(ctx, &ctx->Hosts[EVPNPEERINGTEST_HOST_M]);
	EvpnPeeringTestAnnounceHost(ctx, &ctx->Hosts[EVPNPEERINGTEST_HOST_2]);

	return ok;
}

// A MAC address learned on one node is a type-2 route at the other, and the type-3 route of each is the flood list of the other: node-b
// holds the routes of host 1 and host m via the VTEP of node-a, node-a those of host 2 via the VTEP of node-b. A frame of host 2 to
// host 1 goes from node-b to the VTEP of node-a over VXLAN, and node-a delivers it to host 1 alone.
static void EvpnPeeringTestMacs(EVPNPEERINGTEST_CTX *ctx)
{
	EVPNPEERINGTEST_HOST *h1 = &ctx->Hosts[EVPNPEERINGTEST_HOST_1];
	EVPNPEERINGTEST_HOST *hm = &ctx->Hosts[EVPNPEERINGTEST_HOST_M];
	EVPNPEERINGTEST_HOST *h2 = &ctx->Hosts[EVPNPEERINGTEST_HOST_2];
	UCHAR frame[EVPNPEERINGTEST_FRAME];
	UCHAR d[VXLAN_MAX_DATAGRAM];

	Print("[a MAC address of one node is a type-2 route at the other, and a frame to it goes there over VXLAN]\n");

	bool routes = EvpnPeeringTestWaitL2Routes(ctx, false);
	EvpnPeeringTestCheck(ctx, routes, "node-b holds the type-3 route of node-a and the type-2 routes of host 1 and host m, MAC only and MAC plus IP, via the VTEP of node-a; node-a the type-3 route of node-b and the type-2 routes of host 2 via the VTEP of node-b",
		"node-a holds %u routes of lan, node-b %u", NodeStretchGetRoutes(ctx->Nodes[EVPNPEERINGTEST_A].Node, NULL, 0),
		NodeStretchGetRoutes(ctx->Nodes[EVPNPEERINGTEST_B].Node, NULL, 0));
	if (routes == false)
	{
		return;
	}

	bool remote = EvpnPeeringTestWaitRemoteMac(ctx, EVPNPEERINGTEST_B, h1->Mac);
	EvpnPeeringTestCheck(ctx, remote, "node-b: the type-2 route of host 1 puts its MAC address into the switch of lan at the port of the fabric", "not there within %u ms",
		(UINT)EVPNPEERINGTEST_WAIT);

	EvpnPeeringTestDrain(ctx);
	LONG before_1 = EvpnPeeringTestFrames(h1);
	LONG before_m = EvpnPeeringTestFrames(hm);
	UINT size = EvpnPeeringTestFrame(frame, h2, h1->Mac, h1->Ip, ctx->Seq++);
	EvpnPeeringTestSend(ctx, h2, frame, size);

	UINT got = EvpnPeeringTestTake(ctx->Nodes[EVPNPEERINGTEST_A].Vtep, d, sizeof(d), EVPNPEERINGTEST_WAIT);
	bool vxlan = EvpnPeeringTestIsFrame(d, got, frame, size);
	EvpnPeeringTestCheck(ctx, vxlan, "A frame of host 2 to host 1 goes from node-b to the VTEP of node-a over VXLAN, byte for byte on the L2 VNI 5010",
		"the harness VTEP of node-a took %u bytes, VNI %u", got, EvpnPeeringTestVniOf(d, got));

	bool relayed = (vxlan && EvpnPeeringTestRelay(ctx, EVPNPEERINGTEST_B, EVPNPEERINGTEST_A, d, got));
	bool arrived = (relayed && EvpnPeeringTestArrived(h1, before_1, EVPNPEERINGTEST_WAIT) && EvpnPeeringTestLastIs(h1, frame, size));
	SleepThread(EVPNPEERINGTEST_QUIET);
	EvpnPeeringTestCheck(ctx, arrived && EvpnPeeringTestFrames(hm) == before_m, "node-a takes the datagram from the VTEP of node-b and delivers the frame to host 1 alone, as it was sent",
		"passed on %u, host 1 took it %u, host m took %d frames", (UINT)relayed, (UINT)arrived, (int)(EvpnPeeringTestFrames(hm) - before_m));
}

// A broadcast of host 1 goes to the VTEP of each other member of dc once, by the flood list of node-a, which their type-3 routes fill:
// the harness VTEP of each takes one datagram, the broadcast on the L2 VNI, and the harness VTEP of node-a and of a node that is no
// member take none
static void EvpnPeeringTestFlood(EVPNPEERINGTEST_CTX *ctx, char *what)
{
	EVPNPEERINGTEST_HOST *h1 = &ctx->Hosts[EVPNPEERINGTEST_HOST_1];
	UCHAR frame[EVPNPEERINGTEST_FRAME];
	UCHAR d[VXLAN_MAX_DATAGRAM];
	UINT copies[EVPNPEERINGTEST_NODES];
	UINT same[EVPNPEERINGTEST_NODES];
	bool ok = true;

	EvpnPeeringTestDrain(ctx);
	UINT size = EvpnPeeringTestFrame(frame, h1, evpnpeeringtest_broadcast, "10.50.0.255", ctx->Seq++);
	EvpnPeeringTestSend(ctx, h1, frame, size);

	for (UINT i = 0;i < EVPNPEERINGTEST_NODES;i++)
	{
		bool member = (i != EVPNPEERINGTEST_A && EvpnPeeringTestIn(ctx, i));
		UINT got = EvpnPeeringTestTake(ctx->Nodes[i].Vtep, d, sizeof(d), member ? EVPNPEERINGTEST_WAIT : EVPNPEERINGTEST_QUIET);

		copies[i] = 0;
		same[i] = 0;
		while (got != 0)
		{
			copies[i]++;
			same[i] += (EvpnPeeringTestIsFrame(d, got, frame, size) ? 1 : 0);
			got = EvpnPeeringTestTake(ctx->Nodes[i].Vtep, d, sizeof(d), EVPNPEERINGTEST_QUIET);
		}
		ok = ok && copies[i] == (member ? 1U : 0U) && same[i] == copies[i];
	}

	EvpnPeeringTestCheck(ctx, ok, what, "the harness VTEPs of node-a, node-b and node-c took %u, %u and %u datagrams, %u, %u and %u of them the broadcast", copies[0], copies[1],
		copies[2], same[0], same[1], same[2]);
}

// A prefix of dc at node-b is reachable from node-a through the IP prefix route of node-b with the L3 VNI of dc: each node holds the
// IP prefix routes of the other, and a packet of the host of node-a to the LAN of node-b goes to the VTEP of node-b on the L3 VNI and
// arrives at the host of node-b
static void EvpnPeeringTestPrefix(EVPNPEERINGTEST_CTX *ctx)
{
	EVPNPEERINGTEST_NODE *b = &ctx->Nodes[EVPNPEERINGTEST_B];
	UCHAR packet[EVPNPEERINGTEST_SIZE];
	UCHAR d[VXLAN_MAX_DATAGRAM];

	Print("[a prefix of dc at one node is reachable from the other by a type-5 route with the L3 VNI of dc]\n");

	bool routes = EvpnPeeringTestWaitPrefixes(ctx);
	EvpnPeeringTestCheck(ctx, routes, "Each node holds the IP prefix routes of the other, its address as a host route and its LAN subnet, via its VTEP with the L3 VNI 10101 of dc",
		"node-a holds %u, node-b %u", NodePeeringGetEvpnRoutes(ctx->Nodes[EVPNPEERINGTEST_A].Node, NULL, 0), NodePeeringGetEvpnRoutes(b->Node, NULL, 0));
	if (routes == false)
	{
		return;
	}

	EvpnPeeringTestDrain(ctx);
	LONG before = EvpnPeeringTestArrivals(b);
	UINT size = EvpnPeeringTestPacket(packet, evpnpeeringtest_dc[EVPNPEERINGTEST_A], evpnpeeringtest_lan_hosts[EVPNPEERINGTEST_B], ctx->Seq++);
	bool taken = EvpnPeeringTestInput(ctx, EVPNPEERINGTEST_A, packet, size);

	UINT got = EvpnPeeringTestTake(b->Vtep, d, sizeof(d), EVPNPEERINGTEST_WAIT);
	bool vxlan = (taken && EvpnPeeringTestIsPacket(ctx, d, got, packet, size));
	EvpnPeeringTestCheck(ctx, vxlan, "node-a: a packet of its host from 10.0.0.2 to 192.168.20.10, in the LAN of node-b, goes to the VTEP of node-b over VXLAN on the L3 VNI 10101, from the router MAC to the router MAC",
		"the overlay took it %u, the harness VTEP of node-b took %u bytes, VNI %u", (UINT)taken, got, EvpnPeeringTestVniOf(d, got));

	bool relayed = (vxlan && EvpnPeeringTestRelay(ctx, EVPNPEERINGTEST_A, EVPNPEERINGTEST_B, d, got));
	bool arrived = (relayed && EvpnPeeringTestDelivered(b, before, EVPNPEERINGTEST_WAIT, packet, size));
	EvpnPeeringTestCheck(ctx, arrived, "node-b takes the datagram from the VTEP of node-a and delivers the packet to its host in dc, as it was sent",
		"passed on %u, the host of node-b took %d packets", (UINT)relayed, (int)(EvpnPeeringTestArrivals(b) - before));
}

// A VRF that peers by EVPN does not also use the form of the links of kind vxlan that the Controller fills (SDN-76): the links of each
// node carry no VNI, though dc has a link of kind vxlan; and a packet of the host of node-a to 10.0.0.3, the address of node-b in dc,
// which the state names among the addresses of the peer node-b, goes by the IP prefix route of node-b on the L3 VNI, and never over the
// session of the overlay with node-b, which is up
static void EvpnPeeringTestNoControllerForm(EVPNPEERINGTEST_CTX *ctx)
{
	EVPNPEERINGTEST_NODE *b = &ctx->Nodes[EVPNPEERINGTEST_B];
	UCHAR packet[EVPNPEERINGTEST_SIZE];
	UCHAR d[VXLAN_MAX_DATAGRAM];
	char what[MAX_SIZE * 2];
	NODE_OVERLAY_STATUS os;

	Print("[dc does not also use the routes and the flood list that the Controller fills for a link of kind vxlan]\n");

	for (UINT i = EVPNPEERINGTEST_A;i <= EVPNPEERINGTEST_B;i++)
	{
		NODE_LINK_STATUS ls;

		NodeLinkGetStatus(ctx->Nodes[i].Node, &ls);
		Format(what, sizeof(what), "%s: the VXLAN module of its links carries no VNI, though dc has a link of kind vxlan: the EVPN of dc carries it", evpnpeeringtest_names[i]);
		EvpnPeeringTestCheck(ctx, ls.Running == false && ls.NumVnis == 0, what, "running %u, %u VNIs, VXLAN port %u", (UINT)ls.Running, ls.NumVnis, (UINT)ls.VxlanPort);
	}

	NodeOverlayGetStatus(ctx->Nodes[EVPNPEERINGTEST_A].Node, &os);
	EvpnPeeringTestDrain(ctx);
	LONG before = EvpnPeeringTestArrivals(b);
	UINT size = EvpnPeeringTestPacket(packet, evpnpeeringtest_dc[EVPNPEERINGTEST_A], evpnpeeringtest_dc[EVPNPEERINGTEST_B], ctx->Seq++);
	bool taken = EvpnPeeringTestInput(ctx, EVPNPEERINGTEST_A, packet, size);

	UINT got = EvpnPeeringTestTake(b->Vtep, d, sizeof(d), EVPNPEERINGTEST_WAIT);
	bool vxlan = (taken && EvpnPeeringTestIsPacket(ctx, d, got, packet, size));
	SleepThread(EVPNPEERINGTEST_QUIET);
	LONG arrivals = EvpnPeeringTestArrivals(b) - before;
	EvpnPeeringTestCheck(ctx, vxlan && arrivals == 0 && os.NumLinks == 1,
		"node-a: a packet of its host to 10.0.0.3, the address of node-b in dc that the state names, goes to the VTEP of node-b on the L3 VNI by its IP prefix route, and not over the session of the overlay with node-b, which is up",
		"the overlay took it %u, the harness VTEP of node-b took %u bytes, VNI %u, the host of node-b took %d packets without a VTEP, %u sessions of the overlay up",
		(UINT)taken, got, EvpnPeeringTestVniOf(d, got), (int)arrivals, os.NumLinks);
}

// MAC mobility (RFC 7432 section 15): host m moves from node-a to node-b, where it announces itself. The type-2 routes of host m move:
// node-a holds the ones of node-b, MAC only and MAC plus IP, and node-b holds none of node-a; node-a counts the move and holds host m at
// the port of the fabric; a frame of host 1 to host m goes to the VTEP of node-b, which delivers it to host m there, and the old port of
// host m at node-a gets nothing
static void EvpnPeeringTestMobility(EVPNPEERINGTEST_CTX *ctx)
{
	EVPNPEERINGTEST_HOST *h1 = &ctx->Hosts[EVPNPEERINGTEST_HOST_1];
	EVPNPEERINGTEST_HOST *hm = &ctx->Hosts[EVPNPEERINGTEST_HOST_M];
	EVPNPEERINGTEST_HOST *moved = &ctx->Hosts[EVPNPEERINGTEST_HOST_MOVED];
	NODE_STRETCH_STATUS before, after;
	UCHAR frame[EVPNPEERINGTEST_FRAME];
	UCHAR d[VXLAN_MAX_DATAGRAM];

	Print("[MAC mobility: host m moves from node-a to node-b]\n");

	NodeStretchGetStatus(ctx->Nodes[EVPNPEERINGTEST_A].Node, &before);
	EvpnPeeringTestAnnounceHost(ctx, moved);

	bool routes = EvpnPeeringTestWaitL2Routes(ctx, true);
	EvpnPeeringTestCheck(ctx, routes, "The type-2 routes of host m move: node-a holds the ones of node-b, MAC only and MAC plus IP via the VTEP of node-b, and node-b holds none of node-a any more",
		"node-a holds %u routes of lan, node-b %u", NodeStretchGetRoutes(ctx->Nodes[EVPNPEERINGTEST_A].Node, NULL, 0),
		NodeStretchGetRoutes(ctx->Nodes[EVPNPEERINGTEST_B].Node, NULL, 0));

	NodeStretchGetStatus(ctx->Nodes[EVPNPEERINGTEST_A].Node, &after);
	EvpnPeeringTestCheck(ctx, after.Moved > before.Moved, "node-a counts the move of host m: the sidecar named the route of node-b as a MAC address of node-a that moved",
		"%I64u moves before, %I64u after", before.Moved, after.Moved);

	bool remote = (routes && EvpnPeeringTestWaitRemoteMac(ctx, EVPNPEERINGTEST_A, hm->Mac));
	EvpnPeeringTestCheck(ctx, remote, "node-a: the switch of lan holds host m at the port of the fabric, and no longer at the port where host m was", "not there within %u ms",
		(UINT)EVPNPEERINGTEST_WAIT);
	if (remote == false)
	{
		return;
	}

	EvpnPeeringTestDrain(ctx);
	LONG before_m = EvpnPeeringTestFrames(hm);
	LONG before_moved = EvpnPeeringTestFrames(moved);
	UINT size = EvpnPeeringTestFrame(frame, h1, hm->Mac, hm->Ip, ctx->Seq++);
	EvpnPeeringTestSend(ctx, h1, frame, size);

	UINT got = EvpnPeeringTestTake(ctx->Nodes[EVPNPEERINGTEST_B].Vtep, d, sizeof(d), EVPNPEERINGTEST_WAIT);
	bool vxlan = EvpnPeeringTestIsFrame(d, got, frame, size);
	EvpnPeeringTestCheck(ctx, vxlan, "A frame of host 1 to host m goes from node-a to the VTEP of node-b over VXLAN, byte for byte on the L2 VNI 5010",
		"the harness VTEP of node-b took %u bytes, VNI %u", got, EvpnPeeringTestVniOf(d, got));

	bool relayed = (vxlan && EvpnPeeringTestRelay(ctx, EVPNPEERINGTEST_A, EVPNPEERINGTEST_B, d, got));
	bool arrived = (relayed && EvpnPeeringTestArrived(moved, before_moved, EVPNPEERINGTEST_WAIT) && EvpnPeeringTestLastIs(moved, frame, size));
	SleepThread(EVPNPEERINGTEST_QUIET);
	EvpnPeeringTestCheck(ctx, arrived && EvpnPeeringTestFrames(hm) == before_m,
		"node-b delivers the frame to host m, now at node-b, and the old port of host m at node-a gets nothing: node-a forwards to it no longer",
		"passed on %u, host m at node-b took it %u, its old port at node-a took %d frames", (UINT)relayed, (UINT)arrived, (int)(EvpnPeeringTestFrames(hm) - before_m));
}

// The flood list of lan at node-a changes while the nodes run: node-c joins dc (Generation 2), and its type-3 route joins the flood list
// of node-a; node-c leaves (Generation 3), and it goes again
static void EvpnPeeringTestFloodChanges(EVPNPEERINGTEST_CTX *ctx)
{
	Print("[Generation 2: node-c joins dc, and its type-3 route joins the flood list of node-a]\n");
	if (EvpnPeeringTestGeneration(ctx, 2, true, "node-a, node-b and node-c run Generation 2, and the sidecar of each has the two others as its peers, their sessions established") == false)
	{
		return;
	}
	EvpnPeeringTestCheck(ctx, EvpnPeeringTestWaitFloodList(ctx, 2), "node-a: the type-3 routes of node-b and node-c are the flood list of lan", "%u VTEPs within %u ms",
		EvpnPeeringTestFloodListSize(ctx), (UINT)EVPNPEERINGTEST_BOUND);
	EvpnPeeringTestFlood(ctx, "A broadcast of host 1 goes to the VTEPs of node-b and node-c once each, by the flood list of node-a");

	Print("[Generation 3: node-c leaves dc, and its type-3 route leaves the flood list of node-a]\n");
	if (EvpnPeeringTestGeneration(ctx, 3, false, "node-a and node-b run Generation 3 without node-c, and the sidecar of each has the other as its peer again") == false)
	{
		return;
	}
	EvpnPeeringTestCheck(ctx, EvpnPeeringTestWaitFloodList(ctx, 1), "node-a: the type-3 route of node-b alone is the flood list of lan again", "%u VTEPs within %u ms",
		EvpnPeeringTestFloodListSize(ctx), (UINT)EVPNPEERINGTEST_BOUND);
	EvpnPeeringTestFlood(ctx, "A broadcast of host 1 goes to the VTEP of node-b once, and none to node-c");
}

// A session from from to the sidecar of node-a, from an address that the Controller did not name, is refused, and node-a counts it,
// while its sessions stay established
static void EvpnPeeringTestRefused(EVPNPEERINGTEST_CTX *ctx, char *from)
{
	EVPNPEERINGTEST_NODE *t = &ctx->Nodes[EVPNPEERINGTEST_A];
	NODE_PEERING_STATUS before, after;
	struct sockaddr_in local, remote;
	char what[MAX_SIZE * 2];
	UINT err = 0;

	Print("[a session from an address that the Controller did not name]\n");

	NodePeeringGetStatus(t->Node, &before);

	Zero(&local, sizeof(local));
	local.sin_family = AF_INET;
	InetPtonA(AF_INET, from, &local.sin_addr);
	Zero(&remote, sizeof(remote));
	remote.sin_family = AF_INET;
	remote.sin_port = htons(EVPNPEERINGTEST_PORT);
	InetPtonA(AF_INET, evpnpeeringtest_addrs[EVPNPEERINGTEST_A], &remote.sin_addr);

	SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	bool connected = (s != INVALID_SOCKET && bind(s, (struct sockaddr *)&local, sizeof(local)) == 0 && connect(s, (struct sockaddr *)&remote, sizeof(remote)) == 0);
	if (connected == false)
	{
		err = (UINT)WSAGetLastError();
	}

	UINT64 end = Tick64() + EVPNPEERINGTEST_BOUND;
	while (true)
	{
		NodePeeringGetStatus(t->Node, &after);
		if (connected == false || after.Refused > before.Refused || Tick64() >= end)
		{
			break;
		}
		SleepThread(EVPNPEERINGTEST_POLL);
	}

	if (s != INVALID_SOCKET)
	{
		closesocket(s);
	}

	Format(what, sizeof(what), "The sidecar of node-a refuses a session from %s, an address that the Controller did not name, and node-a counts it, while its %u sessions stay established",
		from, before.NumEstablished);
	EvpnPeeringTestCheck(ctx, connected && after.Refused == before.Refused + 1 && after.NumEstablished == before.NumEstablished, what,
		"connected %u (error %u), %I64u sessions refused before and %I64u after, %u established after", (UINT)connected, err, before.Refused, after.Refused, after.NumEstablished);
}

// The switches leave the stretches, the nodes stop with their sidecars and EVPNs, each is freed, and the node log of node-a tells the
// story: its EVPN on the VTEP of its address, the move of host m, and its stop. When a check failed, the log of each node and of its
// sidecar is printed before the data directories go.
static void EvpnPeeringTestClose(EVPNPEERINGTEST_CTX *ctx, bool ran)
{
	for (UINT i = 0;i < EVPNPEERINGTEST_NODES;i++)
	{
		EVPNPEERINGTEST_NODE *t = &ctx->Nodes[i];

		if (t->Node != NULL)
		{
			if (t->Attached)
			{
				NodeStretchDetach(t->Node, "lan");
			}
			NodeReaderUnregister(t->Node, &t->Reader);
			NodeStop(t->Node);
		}
	}

	// A node holds the file of its log open while it lives: FreeNode writes the last lines and closes it (FreeLog)
	for (UINT i = 0;i < EVPNPEERINGTEST_NODES;i++)
	{
		if (ctx->Nodes[i].Node != NULL)
		{
			FreeNode(ctx->Nodes[i].Node);
		}
		if (ctx->Nodes[i].Switch != NULL)
		{
			SwitchFree(ctx->Nodes[i].Switch);
			ctx->Nodes[i].Switch = NULL;
		}
	}

	if (ran)
	{
		char *log = EvpnPeeringTestReadLog(ctx->Nodes[EVPNPEERINGTEST_A].Dir);
		char *lines[] =
		{
			"EVPN started: the VTEP 127.0.0.2 on UDP port",
			"MAC addresses of the node moved to a VTEP of the fabric (MAC mobility)",
			"EVPN stopped:",
		};
		char missing[MAX_SIZE * 2];
		bool all = true;

		StrCpy(missing, sizeof(missing), "");
		for (UINT i = 0;i < sizeof(lines) / sizeof(lines[0]);i++)
		{
			if (log == NULL || SearchStrEx(log, lines[i], 0, true) == INFINITE)
			{
				all = false;
				StrCat(missing, sizeof(missing), " \"");
				StrCat(missing, sizeof(missing), lines[i]);
				StrCat(missing, sizeof(missing), "\"");
			}
		}
		EvpnPeeringTestCheck(ctx, all, "The node log of node-a names its EVPN on the VTEP of its address, the move of host m and the stop of its EVPN", "missing:%s", missing);
		Free(log);
	}

	for (UINT i = 0;i < EVPNPEERINGTEST_NODES;i++)
	{
		EVPNPEERINGTEST_NODE *t = &ctx->Nodes[i];
		wchar_t log_dir[MAX_PATH];

		if (t->Node != NULL)
		{
			if (ctx->NumFailed != 0)
			{
				char *log = EvpnPeeringTestReadLog(t->Dir);

				Print("  --- the node log and the sidecar log of %s ---\n%s  ---\n", evpnpeeringtest_names[i], log == NULL ? "(none)\n" : log);
				Free(log);
			}

			ConbinePathW(log_dir, sizeof(log_dir), t->Dir, NODE_LOG_DIR_NAME);
			EvpnPeeringTestDeleteFiles(log_dir);
			EvpnPeeringTestDeleteFiles(t->Dir);
			t->Node = NULL;
		}
		PeerKeyClose(&t->Key);

		if (t->Vtep != INVALID_SOCKET)
		{
			closesocket(t->Vtep);
			t->Vtep = INVALID_SOCKET;
		}
	}
}

// The hosts of lan: host 1 and host m at node-a, host 2 at node-b, and the port of node-b where host m comes, with its MAC address and
// its IP address
static void EvpnPeeringTestHosts(EVPNPEERINGTEST_CTX *ctx)
{
	static const UCHAR macs[EVPNPEERINGTEST_HOSTS][6] =
	{
		{0x02, 0x52, 0x5A, 0x64, 0x00, 0x01},
		{0x02, 0x52, 0x5A, 0x64, 0x00, 0x09},
		{0x02, 0x52, 0x5A, 0x64, 0x00, 0x02},
		{0x02, 0x52, 0x5A, 0x64, 0x00, 0x09},
	};
	static char *names[EVPNPEERINGTEST_HOSTS] = {"host 1", "host m", "host 2", "host m at node-b"};
	static char *ips[EVPNPEERINGTEST_HOSTS] = {"10.50.0.1", "10.50.0.9", "10.50.0.2", "10.50.0.9"};
	static const UINT nodes[EVPNPEERINGTEST_HOSTS] = {EVPNPEERINGTEST_A, EVPNPEERINGTEST_A, EVPNPEERINGTEST_B, EVPNPEERINGTEST_B};

	for (UINT i = 0;i < EVPNPEERINGTEST_HOSTS;i++)
	{
		EVPNPEERINGTEST_HOST *h = &ctx->Hosts[i];

		h->Name = names[i];
		h->Node = nodes[i];
		Copy(h->Mac, macs[i], 6);
		h->Ip = ips[i];
		h->Broadcast = (i == EVPNPEERINGTEST_HOST_1 || i == EVPNPEERINGTEST_HOST_2);
		h->Port = SWITCH_PORT_NONE;
		InitializeSRWLock(&h->Lock);
	}
}

// evpnpeering: the EVPN peering of the standard mode between Nodes
RANZ_TEST("evpnpeering", evpnpeering_test, "EVPN peering of the standard mode: in-process nodes whose sidecars ranz bgp (ranz.exe next to vpntest) peer by EVPN in a VRF of a link of kind vxlan on TCP 179 of loopback addresses of their own, with harness VTEPs on those addresses; a MAC address of one node a type-2 route at the other and a frame to it over VXLAN, the flood list of the type-3 routes of the peers as nodes join and leave, a prefix reachable by a type-5 route with the L3 VNI, no link of the Controller for the VRF, MAC mobility that moves the route and stops the old node forwarding, and a session from an address that the Controller did not name refused.");
void evpnpeering_test(UINT num, char **arg)
{
	EVPNPEERINGTEST_CTX *ctx = ZeroMalloc(sizeof(EVPNPEERINGTEST_CTX));
	HANDLE done = CreateEventW(NULL, TRUE, FALSE, NULL);
	HANDLE watchdog = (done != NULL ? CreateThread(NULL, 0, EvpnPeeringTestWatchdog, done, 0, NULL) : NULL);
	TRANSPORT *loopback = TransportLoopbackNew("loopback", 0, false);

	Print("EVPN peering test: the Nodes of a VRF peer by EVPN in the standard mode, each with its own sidecar ranz bgp, and VXLAN carries their frames and packets\n");

	ctx->Seq = 1;
	for (UINT i = 0;i < EVPNPEERINGTEST_NODES;i++)
	{
		ctx->Nodes[i].Vtep = INVALID_SOCKET;
	}
	EvpnPeeringTestHosts(ctx);

	bool ran = EvpnPeeringTestOpen(ctx, loopback);
	if (ran)
	{
		EvpnPeeringTestMacs(ctx);
		EvpnPeeringTestFlood(ctx, "A broadcast of host 1 goes to the VTEP of node-b once, the type-3 route of node-b at node-a, and none to node-a itself or to node-c, which is no member");
		EvpnPeeringTestPrefix(ctx);
		EvpnPeeringTestNoControllerForm(ctx);
		EvpnPeeringTestMobility(ctx);
		EvpnPeeringTestFloodChanges(ctx);
		EvpnPeeringTestRefused(ctx, EVPNPEERINGTEST_STRANGER);
	}

	EvpnPeeringTestClose(ctx, ran);
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
		Print("EVPNPEERING TEST OK\n");
	}
	else
	{
		Print("EVPNPEERING TEST FAILED (%u of %u checks failed)\n", ctx->NumFailed, ctx->NumChecks);
	}

	Free(ctx);
}
