// irbtest.c
// Named IRB test of vpntest ("irb" command, SDN-67 #294)
//
// The symmetric IRB of a stretch (Cedar/NodeStretch.c, Cedar/NodeEvpn.c, ranz-bgp/internal/sidecar/irb.go; ADR-0032 amendment of
// 2026-10-22): node gw stretches the L2 Networks lan-red and lan-blue, which have the same addresses 10.50.0.0/24 in the VRFs red
// (101) and blue (102), into a data-centre fabric with irb, each on its own L2 VNI (5020 and 5021) and routing in its VRF through
// the L3 VNI of the VRF (10101 and 10102), and stretches lan-plain (5030) without irb. The fabric is one leaf with symmetric IRB on
// this runner, as the multi-node seam has it (ADR-0002 amendment of 2026-10-21: no second host; FRR on a second host is TestFRRIRB of
// ranz.yml): the node leaf, whose sidecar carries the same three stretches, the two with irb in its VRFs 201 and 202, which import
// and export the route targets of red and blue, with a gateway IP and a router MAC of its own; it announces 172.16.1.0/24 and
// fd16::/64 of its VRFs and listens on 127.0.0.2, where the sidecar of gw dials it. Its data plane is a harness VTEP on 127.0.0.2,
// which takes and sends the VXLAN datagrams of the fabric (the leaf sends its own to a port where nothing listens). Behind the leaf,
// on lan-red and on lan-blue, is a host of the fabric with the same address 10.50.0.10 (host a and host b); at gw, host 1 on lan-red
// and host 2 on lan-blue have the same address 10.50.0.20, host 1 also fd50::20, and host 3 on lan-plain has 10.53.0.5. The L2 data
// path of each node is the test's: it attaches the switches before the node starts, and each host announces itself into its switch.
// Node peer is an overlay node of another Network, 10.60.0.2 in red and in blue, whose prefix 10.60.0.0/24 gw announces in both VRFs,
// and whose state routes 10.50.0.0/24 of red and of blue to gw; the hosts of gw and peer are fake adapters, and the in-process
// loopback transport carries their Noise session.
// - The routes: gw holds the host route 10.50.0.10/32 of the fabric in red on the L3 VNI of red and in blue on that of blue, each
//   with the router MAC of the leaf, which its sidecar takes from the type-2 routes of host a and host b; the leaf holds 10.60.0.0/24
//   in its two VRFs, and each host of the overlay at gw on a stretch with irb as a host route of the VRF of its stretch alone, with
//   the L3 VNI of the VRF and the router MAC of gw.
// - With irb off, no gateway IP or MAC of the Network is announced: the leaf holds the gateway IPs of the two stretches with irb as
//   type-2 routes of the router MAC of gw, and on the L2 VNI of lan-plain the type-3 route of gw and the two routes of host 3 alone,
//   none of the router MAC of gw and no gateway IP, and no host route of host 3 in a VRF.
// - A host of the fabric reaches an overlay node of another Network of its VRF through the L3 VNI: the harness VTEP sends a packet
//   of host a to 10.60.0.2 on the L3 VNI of red, and the same packet on that of blue, and the host of peer takes each in the VRF of
//   its VNI. Back, the host of peer sends to 10.50.0.10 in red and in blue, and gw forwards each to the harness VTEP on the L3 VNI of
//   its VRF alone, by the host route, to the router MAC of the leaf. The two VRFs have the same addresses and stay apart.
// - Into the stretched Network, the node half of symmetric IRB: a packet of the fabric subnet 172.16.1.0/24 to 10.50.0.20 on the L3
//   VNI of red reaches host 1 alone, in a frame from the router MAC of gw to the MAC address of host 1, and on that of blue host 2
//   alone; an IPv6 one to fd50::20 reaches host 1; a packet to an address of the gateway IP prefix that no host sends from reaches no
//   host and is counted; and a packet to host 3, on the stretch without irb, reaches no host.
// Print "IRB TEST OK" only when every check passes. .github/scripts/bgp-spike.ps1 runs it, with ranz.exe next to vpntest.

#include "harness_int.h"
#include "testlist.h"

#include "Cedar/ConfigStore.h"
#include "Cedar/Node.h"
#include "Cedar/NodeEvpn.h"

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
#include "Core/Switch.h"
#include "Core/Transport.h"
#include "Core/Vxlan.h"

#include <WS2tcpip.h>

#include <stdio.h>

#define	IRBTEST_BUDGET			300000		// The whole test ends within this time, or the watchdog ends the process (ms)
#define	IRBTEST_BOUND			120000		// A bounded wait on BGP: the session, which waits out the idle hold time of the leaf after a reset, and the routes (ms)
#define	IRBTEST_WAIT			10000		// A bounded wait on a packet, a frame or a counter (ms)
#define	IRBTEST_QUIET			500			// A side that gets nothing gets nothing within this time (ms)
#define	IRBTEST_SETTLE			3000		// Routes that should not come have had time to come: six rounds of the thread of the stretch (ms)
#define	IRBTEST_POLL			20			// Poll interval of observable state (ms)
#define	IRBTEST_SIZE			100			// The size of a test packet
#define	IRBTEST_FRAME			(NODE_EVPN_ETHER + IRBTEST_SIZE)	// A test packet in a frame, as the IRB of gw routes it into a switch
#define	IRBTEST_VLAN			1			// The VLAN of each Network on its switch
#define	IRBTEST_ROUTES			32			// The routes of a node that the test reads at most
#define	IRBTEST_RED				101			// The VRFs of the overlay at gw: red ...
#define	IRBTEST_BLUE			102			// ... and blue
#define	IRBTEST_LEAF_RED		201			// ... and the same VRFs at the leaf
#define	IRBTEST_LEAF_BLUE		202
#define	IRBTEST_VNI_RED			10101		// The L3 VNIs of red and blue
#define	IRBTEST_VNI_BLUE		10102

// The nodes
#define	IRBTEST_GW				0
#define	IRBTEST_LEAF			1
#define	IRBTEST_PEER			2

static char *irbtest_names[3] = {"gw", "leaf", "peer"};

// The stretched Networks, each with a switch at gw and at the leaf, and their L2 VNIs
#define	IRBTEST_NET_RED			0
#define	IRBTEST_NET_BLUE		1
#define	IRBTEST_NET_PLAIN		2
#define	IRBTEST_NETS			3

static char *irbtest_nets[IRBTEST_NETS] = {"lan-red", "lan-blue", "lan-plain"};
static const UINT irbtest_l2[IRBTEST_NETS] = {5020, 5021, 5030};

// The hosts: three of the overlay at gw, and two of the fabric behind the leaf
#define	IRBTEST_HOST_1			0
#define	IRBTEST_HOST_2			1
#define	IRBTEST_HOST_3			2
#define	IRBTEST_HOST_A			3
#define	IRBTEST_HOST_B			4
#define	IRBTEST_HOSTS			5
#define	IRBTEST_NO_HOST			IRBTEST_HOSTS	// No host takes it
#define	IRBTEST_GW_HOSTS		3				// The hosts of gw are the first ones

// The router MACs: of gw (the default of the node and of the sidecar) and of the leaf
static const UCHAR irbtest_gw_mac[6] = {0x02, 0x52, 0x5A, 0x00, 0x00, 0x05};
static const UCHAR irbtest_leaf_mac[6] = {0x02, 0x00, 0x5E, 0x20, 0x00, 0x01};

// The broadcast address, and the MAC address of the IPv6 group of all nodes
static const UCHAR irbtest_broadcast[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
static const UCHAR irbtest_all_nodes[6] = {0x33, 0x33, 0x00, 0x00, 0x00, 0x01};

// The Bgp setting of gw (the BGP port of the leaf, the UDP port of its VTEP and of the VTEPs of the fabric): its sidecar has no
// listener and dials the leaf; red and blue hand 10.60.0.0/24 to the fabric, each on its L3 VNI and its route target, and take the
// subnets of the fabric; lan-red routes in red with a gateway IP of each family, lan-blue in blue with the same IPv4 one, and
// lan-plain has no irb
#define	IRBTEST_GW_BGP	"{\"asn\":65001,\"router_id\":\"192.0.2.1\",\"listen_port\":-1," \
	"\"peers\":[{\"address\":\"127.0.0.2\",\"asn\":65020,\"port\":%u}]," \
	"\"evpn\":{\"vtep\":\"127.0.0.1\",\"port\":%u,\"fabric_port\":%u,\"vrfs\":[" \
	"{\"vrf\":101,\"vni\":10101,\"import\":[\"65000:10101\"],\"export\":[\"65000:10101\"],\"accept\":[\"172.16.0.0/12\",\"fd16::/48\"]}," \
	"{\"vrf\":102,\"vni\":10102,\"import\":[\"65000:10102\"],\"export\":[\"65000:10102\"],\"accept\":[\"172.16.0.0/12\",\"fd16::/48\"]}]," \
	"\"stretches\":[{\"network\":\"lan-red\",\"vni\":5020,\"route_targets\":[\"65000:5020\"],\"irb\":true,\"vrf\":101,\"gateway_ips\":[\"10.50.0.1/24\",\"fd50::1/64\"]}," \
	"{\"network\":\"lan-blue\",\"vni\":5021,\"route_targets\":[\"65000:5021\"],\"irb\":true,\"vrf\":102,\"gateway_ips\":[\"10.50.0.1/24\"]}," \
	"{\"network\":\"lan-plain\",\"vni\":5030,\"route_targets\":[\"65000:5030\"]}]}," \
	"\"announce\":[{\"prefix\":\"10.60.0.0/24\",\"vrf\":101},{\"prefix\":\"10.60.0.0/24\",\"vrf\":102}]}"

// The Bgp setting of the leaf (its BGP port, the UDP port of its own VTEP and of the VTEP of gw for it): its sidecar listens on
// 127.0.0.2 for gw, and stretches the same Networks as a leaf with symmetric IRB, lan-red and lan-blue with irb in its VRFs 201 and
// 202 with a gateway IP of its own and its own router MAC; it announces 172.16.1.0/24 of both VRFs and fd16::/64 of 201. The VTEP of
// gw for it is on a port where nothing listens, so the VXLAN of the leaf reaches no one: the harness VTEP on 127.0.0.2 is its data
// plane.
#define	IRBTEST_LEAF_BGP	"{\"asn\":65020,\"router_id\":\"192.0.2.20\",\"listen_port\":%u,\"listen_addresses\":[\"127.0.0.2\"]," \
	"\"peers\":[{\"address\":\"127.0.0.1\",\"asn\":65001,\"passive\":true}]," \
	"\"evpn\":{\"vtep\":\"127.0.0.2\",\"router_mac\":\"02:00:5e:20:00:01\",\"port\":%u,\"fabric_port\":%u,\"vrfs\":[" \
	"{\"vrf\":201,\"vni\":10101,\"import\":[\"65000:10101\"],\"export\":[\"65000:10101\"],\"accept\":[\"10.60.0.0/16\"]}," \
	"{\"vrf\":202,\"vni\":10102,\"import\":[\"65000:10102\"],\"export\":[\"65000:10102\"],\"accept\":[\"10.60.0.0/16\"]}]," \
	"\"stretches\":[{\"network\":\"lan-red\",\"vni\":5020,\"route_targets\":[\"65000:5020\"],\"irb\":true,\"vrf\":201,\"gateway_ips\":[\"10.50.0.254/24\",\"fd50::fe/64\"]}," \
	"{\"network\":\"lan-blue\",\"vni\":5021,\"route_targets\":[\"65000:5021\"],\"irb\":true,\"vrf\":202,\"gateway_ips\":[\"10.50.0.254/24\"]}," \
	"{\"network\":\"lan-plain\",\"vni\":5030,\"route_targets\":[\"65000:5030\"]}]}," \
	"\"announce\":[{\"prefix\":\"172.16.1.0/24\",\"vrf\":201},{\"prefix\":\"172.16.1.0/24\",\"vrf\":202},{\"prefix\":\"fd16::/64\",\"vrf\":201}]}"

// A host: a member of the switch of its Network at its node, which keeps the last frame that it took
typedef struct IRBTEST_HOST
{
	char *Name;
	UINT Node;							// The node of its switch ...
	UINT Net;							// ... and its Network
	UCHAR Mac[6];						// Its MAC address ...
	char *Ip;							// ... its IPv4 address ...
	char *Ip6;							// ... and the IPv6 address that it sends from too, NULL for none
	UINT Port;							// Its port on the switch
	SRWLOCK Lock;						// Last and LastSize
	volatile LONG Frames;				// Frames that it took
	UCHAR Last[IRBTEST_FRAME];			// The last one, as much as fits ...
	UINT LastSize;						// ... and its size
} IRBTEST_HOST;

// A node, the switches of its stretched Networks (gw and the leaf) and the fake adapter of its host (gw and peer)
typedef struct IRBTEST_NODE
{
	wchar_t Dir[MAX_PATH];				// Its data directory
	PEER_KEY Key;						// Its static key
	NODE *Node;
	NODE_READER Reader;					// gw and peer: the test thread as a reader of the node's tables, online while it sends ...
	bool Registered;					// ... once registered
	SWITCH *Switches[IRBTEST_NETS];		// The switch of each stretched Network ...
	bool Attached[IRBTEST_NETS];		// ... which the test attached to the stretch of the node
	SRWLOCK Lock;						// Arrivals, LastVrf, Last and LastSize
	volatile LONG Arrivals;				// Packets that the host took
	UINT LastVrf;						// The VRF of the last one ...
	UCHAR Last[IRBTEST_SIZE * 2];		// ... and the packet, as much as fits
	UINT LastSize;
} IRBTEST_NODE;

// The test
typedef struct IRBTEST_CTX
{
	UINT NumChecks;
	UINT NumFailed;
	IRBTEST_NODE Nodes[3];
	IRBTEST_HOST Hosts[IRBTEST_HOSTS];
	SOCKET Vtep;						// The harness VTEP of the leaf, on 127.0.0.2 ...
	USHORT FabricPort;					// ... and its UDP port: the port of the VTEPs of the fabric for gw
	USHORT GwPort;						// The UDP port of the VTEP of gw
} IRBTEST_CTX;

// A packet that the leaf routes into the L3 VNI of a VRF to a host of a stretched Network at gw: the VNI, the two ends of a UDP
// packet, and the host that takes it, IRBTEST_NO_HOST for none, with why
typedef struct IRBTEST_INTO
{
	UINT Vni;
	char *Src;
	char *Dst;
	UINT To;
	char *Why;
} IRBTEST_INTO;

static IRBTEST_INTO irbtest_into[] =
{
	{IRBTEST_VNI_RED, "172.16.1.10", "10.50.0.20", IRBTEST_HOST_1, "host 1 on lan-red, the stretch with irb in red"},
	{IRBTEST_VNI_BLUE, "172.16.1.10", "10.50.0.20", IRBTEST_HOST_2, "host 2 on lan-blue, the stretch with irb in blue, which has the same address"},
	{IRBTEST_VNI_RED, "fd16::10", "fd50::20", IRBTEST_HOST_1, "host 1 by its IPv6 address, in the IPv6 gateway IP prefix of lan-red"},
	{IRBTEST_VNI_RED, "172.16.1.10", "10.50.0.99", IRBTEST_NO_HOST, "an address of the gateway IP prefix of lan-red that no host sends from"},
	{IRBTEST_VNI_RED, "172.16.1.10", "10.53.0.5", IRBTEST_NO_HOST, "host 3 on lan-plain, the stretch without irb, which routes nothing"},
};

static bool IrbTestCheck(IRBTEST_CTX *ctx, bool ok, char *what, char *fmt, ...) RANZ_PRINTF_FORMAT(4, 5);
static bool IrbTestCheck(IRBTEST_CTX *ctx, bool ok, char *what, char *fmt, ...)
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

// The watchdog: a native thread that ends a run that hangs, so that a lost session, packet or frame is a failed test instead of a
// hung CI step
static DWORD WINAPI IrbTestWatchdog(LPVOID param)
{
	char msg[MAX_SIZE];
	DWORD written = 0;

	if (WaitForSingleObject((HANDLE)param, IRBTEST_BUDGET) != WAIT_TIMEOUT)
	{
		return 0;
	}

	int len = snprintf(msg, sizeof(msg), "IRB TEST FAILED (did not finish within %u ms)\n", IRBTEST_BUDGET);
	if (len > 0)
	{
		WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), msg, (DWORD)MIN((UINT)len, (UINT)sizeof(msg) - 1), &written, NULL);
	}

	TerminateProcess(GetCurrentProcess(), 1);

	return 0;
}

//
// Packets, frames and the harness VTEP
//

// The address of a text into addr: 4 bytes for IPv4, 16 for IPv6, and their number; 0 for no address
static UINT IrbTestAddress(UCHAR *addr, char *str)
{
	IP ip;

	Zero(addr, 16);
	if (StrToIP(&ip, str) == false)
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

// A UDP packet from src port 5000 to dst port 53 with the data seq, IRBTEST_SIZE bytes, into buf: its size, 0 when its two ends are
// not of one family
static UINT IrbTestPacket(UCHAR *buf, char *src, char *dst, UINT seq)
{
	UCHAR s[16], d[16];
	UINT size = IrbTestAddress(s, src);
	UINT ip = (size == 4 ? 20 : 40);
	UCHAR *udp = buf + ip;

	if (size == 0 || IrbTestAddress(d, dst) != size)
	{
		return 0;
	}

	Zero(buf, IRBTEST_SIZE);
	if (size == 4)
	{
		buf[0] = 0x45;
		WRITE_USHORT(buf + 2, IRBTEST_SIZE);
		buf[8] = 64;
		buf[9] = IP_PROTO_UDP;
		Copy(buf + 12, s, 4);
		Copy(buf + 16, d, 4);
		USHORT sum = IpChecksum(buf, 20);
		Copy(buf + 10, &sum, 2);
	}
	else
	{
		buf[0] = 0x60;
		WRITE_USHORT(buf + 4, IRBTEST_SIZE - 40);
		buf[6] = IP_PROTO_UDP;
		buf[7] = 64;
		Copy(buf + 8, s, 16);
		Copy(buf + 24, d, 16);
	}

	WRITE_USHORT(udp, 5000);
	WRITE_USHORT(udp + 2, 53);
	WRITE_USHORT(udp + 4, IRBTEST_SIZE - ip);
	WRITE_UINT(udp + 8, seq);
	for (UINT i = ip + 12;i < IRBTEST_SIZE;i++)
	{
		buf[i] = (UCHAR)(i * 7 + seq);
	}

	return IRBTEST_SIZE;
}

// The gratuitous ARP of host h into buf, an ARP request for its own IPv4 address to every host: the switch of its node learns its MAC
// address and its IPv4 address from it. Its size.
static UINT IrbTestAnnounce(UCHAR *buf, IRBTEST_HOST *h)
{
	UCHAR ip[16];

	IrbTestAddress(ip, h->Ip);
	Zero(buf, 42);
	Copy(buf, irbtest_broadcast, 6);
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

// An IPv6 packet of UDP without data from the IPv6 address of host h to the group of all nodes into buf: the switch of its node learns
// its IPv6 address from it. Its size.
static UINT IrbTestAnnounce6(UCHAR *buf, IRBTEST_HOST *h)
{
	UCHAR *ip = buf + 14;

	Zero(buf, 62);
	Copy(buf, irbtest_all_nodes, 6);
	Copy(buf + 6, h->Mac, 6);
	WRITE_USHORT(buf + 12, MAC_PROTO_IPV6);
	ip[0] = 0x60;
	WRITE_USHORT(ip + 4, 8);
	ip[6] = IP_PROTO_UDP;
	ip[7] = 1;
	IrbTestAddress(ip + 8, h->Ip6);
	ip[24] = 0xFF;
	ip[25] = 0x02;
	ip[39] = 1;
	WRITE_USHORT(ip + 40, 5000);
	WRITE_USHORT(ip + 42, 5000);
	WRITE_USHORT(ip + 44, 8);

	return 62;
}

// The frame in which the IRB of gw routes packet, size bytes, to host h into its switch, into buf: from the router MAC of gw to the
// MAC address of the host, untagged, with the EtherType of the IP version of the packet. Its size.
static UINT IrbTestRouted(UCHAR *buf, IRBTEST_HOST *h, const UCHAR *packet, UINT size)
{
	Copy(buf, h->Mac, 6);
	Copy(buf + 6, irbtest_gw_mac, 6);
	WRITE_USHORT(buf + 12, (packet[0] >> 4) == 6 ? MAC_PROTO_IPV6 : MAC_PROTO_IPV4);
	Copy(buf + NODE_EVPN_ETHER, packet, size);

	return NODE_EVPN_ETHER + size;
}

// A free port, which the system picks: of UDP on the wildcard address, or of TCP on 127.0.0.1 with tcp. 0 for none.
static USHORT IrbTestFreePort(bool tcp)
{
	struct sockaddr_in6 sa6;
	struct sockaddr_in sa4;
	int size;
	USHORT port = 0;
	SOCKET s = (tcp ? socket(AF_INET, SOCK_STREAM, IPPROTO_TCP) : socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP));

	if (s == INVALID_SOCKET)
	{
		return 0;
	}

	if (tcp)
	{
		Zero(&sa4, sizeof(sa4));
		sa4.sin_family = AF_INET;
		sa4.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
		size = sizeof(sa4);
		if (bind(s, (struct sockaddr *)&sa4, sizeof(sa4)) == 0 && getsockname(s, (struct sockaddr *)&sa4, &size) == 0)
		{
			port = ntohs(sa4.sin_port);
		}
	}
	else
	{
		Zero(&sa6, sizeof(sa6));
		sa6.sin6_family = AF_INET6;
		size = sizeof(sa6);
		if (bind(s, (struct sockaddr *)&sa6, sizeof(sa6)) == 0 && getsockname(s, (struct sockaddr *)&sa6, &size) == 0)
		{
			port = ntohs(sa6.sin6_port);
		}
	}

	closesocket(s);

	return port;
}

// A UDP socket on the IPv4 address addr, in host byte order, on a port that the system picks, into *s: its port, 0 when it could not be
// opened
static USHORT IrbTestBind(SOCKET *s, UINT addr)
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
	if (bind(*s, (struct sockaddr *)&sa, sizeof(sa)) != 0 || getsockname(*s, (struct sockaddr *)&sa, &size) != 0)
	{
		closesocket(*s);
		*s = INVALID_SOCKET;
		return 0;
	}

	return ntohs(sa.sin_port);
}

// The next datagram that the harness VTEP takes within timeout ms, into buf of size bytes: its size, 0 for none
static UINT IrbTestTake(IRBTEST_CTX *ctx, UCHAR *buf, UINT size, UINT timeout)
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

// The next datagram on the VNI vni that the harness VTEP takes within timeout ms, into buf of size bytes: its size, 0 for none. The
// datagrams of other VNIs before it, as the broadcasts of the hosts of gw on the L2 VNIs, go.
static UINT IrbTestTakeVni(IRBTEST_CTX *ctx, UCHAR *buf, UINT size, UINT vni, UINT timeout)
{
	UINT64 end = Tick64() + timeout;

	while (true)
	{
		UINT64 now = Tick64();
		UINT got = (now < end ? IrbTestTake(ctx, buf, size, (UINT)(end - now)) : 0);

		if (got == 0)
		{
			return 0;
		}
		if (got >= VXLAN_HEADER_SIZE && ((((UINT)buf[4] << 16) | ((UINT)buf[5] << 8) | buf[6]) == vni))
		{
			return got;
		}
	}
}

// Drop what the harness VTEP holds
static void IrbTestDrain(IRBTEST_CTX *ctx)
{
	UCHAR buf[VXLAN_MAX_DATAGRAM];

	while (IrbTestTake(ctx, buf, sizeof(buf), 0) != 0)
	{
	}
}

// Whether the datagram d of size bytes is the VXLAN datagram of packet, packet_size bytes, on vni: the I flag and the VNI, then the
// Ethernet header from the router MAC of gw to the router MAC of the leaf, untagged, with the EtherType of the IP version of the
// packet, and the packet
static bool IrbTestIsFrame(const UCHAR *d, UINT size, UINT vni, const UCHAR *packet, UINT packet_size)
{
	UINT ether = ((packet[0] >> 4) == 6 ? MAC_PROTO_IPV6 : MAC_PROTO_IPV4);

	if (size != VXLAN_HEADER_SIZE + NODE_EVPN_ETHER + packet_size || d[0] != VXLAN_FLAG_VNI)
	{
		return false;
	}

	if ((((UINT)d[4] << 16) | ((UINT)d[5] << 8) | d[6]) != vni)
	{
		return false;
	}

	return (Cmp(d + VXLAN_HEADER_SIZE, irbtest_leaf_mac, 6) == 0 && Cmp(d + VXLAN_HEADER_SIZE + 6, irbtest_gw_mac, 6) == 0 &&
		READ_USHORT(d + VXLAN_HEADER_SIZE + 12) == ether && Cmp(d + VXLAN_HEADER_SIZE + NODE_EVPN_ETHER, packet, packet_size) == 0);
}

// Send gw, from the harness VTEP, a VXLAN datagram on vni with the frame of packet, size bytes, from the router MAC of the leaf to the
// router MAC of gw, as the leaf routes a packet into the L3 VNI of a VRF: whether it went
static bool IrbTestInject(IRBTEST_CTX *ctx, UINT vni, const UCHAR *packet, UINT size)
{
	UCHAR d[VXLAN_HEADER_SIZE + IRBTEST_FRAME];
	struct sockaddr_in sa;

	if (size > IRBTEST_SIZE)
	{
		return false;
	}

	Zero(d, sizeof(d));
	d[0] = VXLAN_FLAG_VNI;
	d[4] = (UCHAR)(vni >> 16);
	d[5] = (UCHAR)(vni >> 8);
	d[6] = (UCHAR)vni;
	Copy(d + VXLAN_HEADER_SIZE, irbtest_gw_mac, 6);
	Copy(d + VXLAN_HEADER_SIZE + 6, irbtest_leaf_mac, 6);
	WRITE_USHORT(d + VXLAN_HEADER_SIZE + 12, (packet[0] >> 4) == 6 ? MAC_PROTO_IPV6 : MAC_PROTO_IPV4);
	Copy(d + VXLAN_HEADER_SIZE + NODE_EVPN_ETHER, packet, size);

	Zero(&sa, sizeof(sa));
	sa.sin_family = AF_INET;
	sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	sa.sin_port = htons(ctx->GwPort);

	UINT len = VXLAN_HEADER_SIZE + NODE_EVPN_ETHER + size;

	return sendto(ctx->Vtep, (char *)d, (int)len, 0, (struct sockaddr *)&sa, sizeof(sa)) == (int)len;
}

//
// The hosts and the switches
//

// A host takes a frame that the switch of its node delivers to its port (SWITCH_SEND_PROC): a frame that the IRB of gw routes comes on
// the receive thread of the socket of gw, a broadcast of another host on the thread of the test, so the lock orders the two
static void IrbTestHostTake(void *param, UINT port, const UCHAR *frame, UINT size)
{
	IRBTEST_HOST *h = (IRBTEST_HOST *)param;

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
static LONG IrbTestFrames(IRBTEST_HOST *h)
{
	return InterlockedCompareExchange(&h->Frames, 0, 0);
}

// Whether host h took more than before frames within timeout ms
static bool IrbTestHostArrived(IRBTEST_HOST *h, LONG before, UINT timeout)
{
	UINT64 end = Tick64() + timeout;

	while (IrbTestFrames(h) <= before)
	{
		if (Tick64() >= end)
		{
			return false;
		}
		SleepThread(IRBTEST_POLL);
	}

	return true;
}

// Whether the last frame of host h is frame, size bytes
static bool IrbTestLastIs(IRBTEST_HOST *h, const UCHAR *frame, UINT size)
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
static UINT IrbTestSend(IRBTEST_CTX *ctx, IRBTEST_HOST *h, const UCHAR *frame, UINT size)
{
	return SwitchInput(ctx->Nodes[h->Node].Switches[h->Net], GetTickCount64(), h->Port, frame, size);
}

//
// The nodes
//

// A new empty data directory under the temp directory of the process, with a configuration store that runs no role on one worker, with
// the Bgp setting bgp, none for NULL
static void IrbTestNewDir(wchar_t *dir, UINT size, char *name, char *bgp)
{
	wchar_t tmp[MAX_PATH];
	wchar_t path[MAX_PATH];

	UniFormat(tmp, sizeof(tmp), L"irbtest_%S_%u", name, (UINT)Tick64());
	ConbinePathW(dir, size, MsGetMyTempDirW(), tmp);
	MakeDirExW(dir);

	ConbinePathW(path, sizeof(path), dir, CS_FILE_NAME);
	CONFIG_STORE *s = CsOpen(path);
	if (s != NULL)
	{
		CsSetSetting(s, NODE_SETTING_ROLES, "none");
		CsSetSetting(s, NODE_SETTING_WORKERS, "1");
		if (bgp != NULL)
		{
			CsSetSetting(s, NODE_SETTING_BGP, bgp);
		}
		CsClose(s);
	}
}

// Delete the files of a directory, which holds no subdirectory, and then the directory
static void IrbTestDeleteFiles(wchar_t *dir)
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
static char *IrbTestReadLog(wchar_t *dir, wchar_t *name)
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

// Print the log of the sidecar of node t, so that the job log shows its BGP session and its routes
static void IrbTestPrintSidecarLog(IRBTEST_NODE *t, char *name)
{
	char *log = IrbTestReadLog(t->Dir, NODE_BGP_LOG_NAME);

	Print("  --- %s: %S ---\n%s  ---\n", name, NODE_BGP_LOG_NAME, log == NULL ? "(none)\n" : log);

	Free(log);
}

// The fake adapter of a host: it counts the packets that the host takes and keeps the last one. A packet of the fabric comes on the
// receive thread of the socket of gw, one of a peer on the thread of the overlay, so the lock orders the two.
static void IrbTestAdapter(NODE *n, void *param, UINT vrf_id, const UCHAR *packet, UINT size)
{
	IRBTEST_NODE *t = (IRBTEST_NODE *)param;

	UNREFERENCED_PARAMETER(n);

	AcquireSRWLockExclusive(&t->Lock);
	{
		t->LastVrf = vrf_id;
		t->LastSize = size;
		Copy(t->Last, packet, MIN(size, (UINT)sizeof(t->Last)));
		InterlockedIncrement(&t->Arrivals);
	}
	ReleaseSRWLockExclusive(&t->Lock);
}

// The address of a in the Network network of the VRF vrf_id, of the length of a host's Network
static void IrbTestAddr(CONTROL_ADDRESS *a, char *network, UINT vrf_id, char *addr)
{
	Zero(a, sizeof(CONTROL_ADDRESS));
	StrCpy(a->Network, sizeof(a->Network), network);
	a->VrfId = vrf_id;
	a->AddressSize = IrbTestAddress(a->Address, addr);
	a->Length = (a->AddressSize == 4 ? 24 : 64);
}

// A route of the VRF vrf_id to prefix/length that leads to a peer
static void IrbTestRoute(CONTROL_ROUTE *r, UINT vrf_id, char *prefix, UINT length)
{
	Zero(r, sizeof(CONTROL_ROUTE));
	r->VrfId = vrf_id;
	r->AddressSize = IrbTestAddress(r->Address, prefix);
	r->Length = length;
}

// Apply Generation 1 of gw and peer: each has its address in the Network of red and of blue, gw 10.60.0.1 and peer 10.60.0.2, the same
// in both VRFs; the state of peer routes 10.50.0.0/24 of red and of blue, the stretched Networks of the two VRFs, to gw. No VRF has a
// policy.
static bool IrbTestApply(IRBTEST_CTX *ctx)
{
	static const UINT nodes[2] = {IRBTEST_GW, IRBTEST_PEER};
	bool ok = true;

	for (UINT i = 0;i < 2;i++)
	{
		UINT self = nodes[i];
		UINT other = nodes[1 - i];
		bool gw = (self == IRBTEST_GW);
		char *own = (gw ? "10.60.0.1" : "10.60.0.2");
		char *theirs = (gw ? "10.60.0.2" : "10.60.0.1");
		CONTROL_STATE *st = ZeroMalloc(sizeof(CONTROL_STATE));
		CONTROL_PEER *p = ZeroMalloc(sizeof(CONTROL_PEER));

		st->Generation = 1;
		StrCpy(st->Name, sizeof(st->Name), irbtest_names[self]);
		// In the order of the Network names, and the VRFs in name order
		IrbTestAddr(&st->Addresses[0], "blue", IRBTEST_BLUE, own);
		IrbTestAddr(&st->Addresses[1], "red", IRBTEST_RED, own);
		st->NumAddresses = 2;
		StrCpy(st->Vrfs[0].Name, sizeof(st->Vrfs[0].Name), "blue");
		st->Vrfs[0].Id = IRBTEST_BLUE;
		StrCpy(st->Vrfs[1].Name, sizeof(st->Vrfs[1].Name), "red");
		st->Vrfs[1].Id = IRBTEST_RED;
		st->NumVrfs = 2;

		StrCpy(p->Name, sizeof(p->Name), irbtest_names[other]);
		Copy(p->Key, ctx->Nodes[other].Key.Public, PEER_KEY_SIZE);
		p->NumVrfs = 2;
		p->VrfIds[0] = IRBTEST_RED;
		p->VrfIds[1] = IRBTEST_BLUE;
		IrbTestAddr(&p->Addresses[0], "blue", IRBTEST_BLUE, theirs);
		IrbTestAddr(&p->Addresses[1], "red", IRBTEST_RED, theirs);
		p->NumAddresses = 2;
		if (gw == false)
		{
			IrbTestRoute(&p->Routes[0], IRBTEST_RED, "10.50.0.0", 24);
			IrbTestRoute(&p->Routes[1], IRBTEST_BLUE, "10.50.0.0", 24);
			p->NumRoutes = 2;
		}
		st->Peers = p;
		st->NumPeers = 1;

		ok = NodeOverlayApply(ctx->Nodes[self].Node, st) && ok;

		Free(p);
		Free(st);
	}

	return ok;
}

// Whether gw and peer run Generation 1 with their session up, within IRBTEST_WAIT
static bool IrbTestWaitLinks(IRBTEST_CTX *ctx)
{
	UINT64 end = Tick64() + IRBTEST_WAIT;

	while (true)
	{
		NODE_OVERLAY_STATUS a, b;

		NodeOverlayGetStatus(ctx->Nodes[IRBTEST_GW].Node, &a);
		NodeOverlayGetStatus(ctx->Nodes[IRBTEST_PEER].Node, &b);
		if (a.NumLinks == 1 && b.NumLinks == 1 && a.Generation == 1 && b.Generation == 1)
		{
			return true;
		}
		if (Tick64() >= end)
		{
			return false;
		}
		SleepThread(IRBTEST_POLL);
	}
}

// Whether the sidecar of node t runs (ready) with established sessions, within IRBTEST_BOUND
static bool IrbTestWaitBgp(IRBTEST_NODE *t, UINT established)
{
	UINT64 end = Tick64() + IRBTEST_BOUND;

	while (true)
	{
		NODE_BGP_STATUS st;

		NodeBgpGetStatus(t->Node, &st);
		if (st.Running && st.NumEstablished == established)
		{
			return true;
		}
		if (Tick64() >= end)
		{
			return false;
		}
		SleepThread(IRBTEST_POLL * 10);
	}
}

// Whether the host of node t took at least target packets within timeout
static bool IrbTestArrived(IRBTEST_NODE *t, LONG target, UINT timeout)
{
	UINT64 end = Tick64() + timeout;

	while (InterlockedCompareExchange(&t->Arrivals, 0, 0) < target)
	{
		if (Tick64() >= end)
		{
			return false;
		}
		SleepThread(IRBTEST_POLL);
	}

	return true;
}

// Whether the EVPN of gw counted at least target packets of the fabric that the overlay did not take, within IRBTEST_WAIT
static bool IrbTestWaitUndelivered(IRBTEST_NODE *gw, UINT64 target)
{
	UINT64 end = Tick64() + IRBTEST_WAIT;

	while (true)
	{
		NODE_EVPN_STATUS st;

		NodeEvpnGetStatus(gw->Node, &st);
		if (st.Undelivered >= target)
		{
			return true;
		}
		if (Tick64() >= end)
		{
			return false;
		}
		SleepThread(IRBTEST_POLL);
	}
}

// Whether ready holds for ctx within timeout
static bool IrbTestWait(IRBTEST_CTX *ctx, bool (*ready)(IRBTEST_CTX *ctx), UINT timeout)
{
	UINT64 end = Tick64() + timeout;

	while (ready(ctx) == false)
	{
		if (Tick64() >= end)
		{
			return false;
		}
		SleepThread(IRBTEST_POLL * 5);
	}

	return true;
}

//
// The routes
//

// Whether node t holds the route of the fabric to prefix in its VRF vrf_id via next_hop, on vni, with the router MAC mac
static bool IrbTestHasRoute(IRBTEST_NODE *t, UINT vrf_id, char *prefix, char *next_hop, UINT vni, const UCHAR *mac)
{
	NODE_EVPN_ROUTE list[IRBTEST_ROUTES];
	UINT num = NodeEvpnGetRoutes(t->Node, list, IRBTEST_ROUTES);

	for (UINT i = 0;i < num && i < IRBTEST_ROUTES;i++)
	{
		NODE_EVPN_ROUTE *r = &list[i];

		if (r->VrfId == vrf_id && StrCmpi(r->Prefix, prefix) == 0 && StrCmp(r->NextHop, next_hop) == 0 && r->Vni == vni && Cmp(r->RouterMac, mac, 6) == 0)
		{
			return true;
		}
	}

	return false;
}

// Whether node t holds a route of the fabric to prefix in any VRF
static bool IrbTestHasPrefix(IRBTEST_NODE *t, char *prefix)
{
	NODE_EVPN_ROUTE list[IRBTEST_ROUTES];
	UINT num = NodeEvpnGetRoutes(t->Node, list, IRBTEST_ROUTES);

	for (UINT i = 0;i < num && i < IRBTEST_ROUTES;i++)
	{
		if (StrCmpi(list[i].Prefix, prefix) == 0)
		{
			return true;
		}
	}

	return false;
}

// Whether gw holds the routes of the fabric that the leaf gives it, and these only: the host route 10.50.0.10/32 of host a in red on
// the L3 VNI of red and of host b in blue on that of blue, and the subnets of the leaf, each via the VTEP of the leaf with its router
// MAC
static bool IrbTestGwRoutes(IRBTEST_CTX *ctx)
{
	IRBTEST_NODE *gw = &ctx->Nodes[IRBTEST_GW];

	return (NodeEvpnGetRoutes(gw->Node, NULL, 0) == 5 &&
		IrbTestHasRoute(gw, IRBTEST_RED, "10.50.0.10/32", "127.0.0.2", IRBTEST_VNI_RED, irbtest_leaf_mac) &&
		IrbTestHasRoute(gw, IRBTEST_BLUE, "10.50.0.10/32", "127.0.0.2", IRBTEST_VNI_BLUE, irbtest_leaf_mac) &&
		IrbTestHasRoute(gw, IRBTEST_RED, "172.16.1.0/24", "127.0.0.2", IRBTEST_VNI_RED, irbtest_leaf_mac) &&
		IrbTestHasRoute(gw, IRBTEST_BLUE, "172.16.1.0/24", "127.0.0.2", IRBTEST_VNI_BLUE, irbtest_leaf_mac) &&
		IrbTestHasRoute(gw, IRBTEST_RED, "fd16::/64", "127.0.0.2", IRBTEST_VNI_RED, irbtest_leaf_mac));
}

// Whether the leaf holds the routes that gw gives it, and these only: 10.60.0.0/24 of red and of blue, and the hosts of the overlay
// on the stretches with irb as host routes of the VRF of their stretch alone, each via the VTEP of gw with its router MAC
static bool IrbTestLeafRoutes(IRBTEST_CTX *ctx)
{
	IRBTEST_NODE *leaf = &ctx->Nodes[IRBTEST_LEAF];

	return (NodeEvpnGetRoutes(leaf->Node, NULL, 0) == 5 &&
		IrbTestHasRoute(leaf, IRBTEST_LEAF_RED, "10.60.0.0/24", "127.0.0.1", IRBTEST_VNI_RED, irbtest_gw_mac) &&
		IrbTestHasRoute(leaf, IRBTEST_LEAF_BLUE, "10.60.0.0/24", "127.0.0.1", IRBTEST_VNI_BLUE, irbtest_gw_mac) &&
		IrbTestHasRoute(leaf, IRBTEST_LEAF_RED, "10.50.0.20/32", "127.0.0.1", IRBTEST_VNI_RED, irbtest_gw_mac) &&
		IrbTestHasRoute(leaf, IRBTEST_LEAF_BLUE, "10.50.0.20/32", "127.0.0.1", IRBTEST_VNI_BLUE, irbtest_gw_mac) &&
		IrbTestHasRoute(leaf, IRBTEST_LEAF_RED, "fd50::20/128", "127.0.0.1", IRBTEST_VNI_RED, irbtest_gw_mac));
}

// Whether list, num routes of a stretch, holds on the L2 VNI vni the type-3 route of the VTEP vtep (mac NULL), or the type-2 route of
// mac with the IP address ip (NULL for MAC only) via the VTEP vtep
static bool IrbTestHasStretch(const NODE_STRETCH_ROUTE *list, UINT num, UINT vni, const UCHAR *mac, char *ip, char *vtep)
{
	UCHAR want_vtep[16];
	UCHAR want_ip[16];
	UCHAR v4[16];
	UINT ip_size = 0;

	Zero(want_vtep, sizeof(want_vtep));
	Zero(want_ip, sizeof(want_ip));
	want_vtep[10] = 0xFF;
	want_vtep[11] = 0xFF;
	IrbTestAddress(v4, vtep);
	Copy(want_vtep + 12, v4, 4);
	if (ip != NULL)
	{
		ip_size = IrbTestAddress(want_ip, ip);
	}

	for (UINT i = 0;i < num;i++)
	{
		const NODE_STRETCH_ROUTE *r = &list[i];

		if (r->Vni != vni || r->Imet != (mac == NULL) || Cmp(r->Vtep, want_vtep, 16) != 0)
		{
			continue;
		}
		if (mac == NULL)
		{
			return true;
		}
		if (Cmp(r->Mac, mac, 6) == 0 && r->IpSize == ip_size && Cmp(r->Ip, want_ip, ip_size) == 0)
		{
			return true;
		}
	}

	return false;
}

// The routes of list, num routes of a stretch, on the L2 VNI vni, and of these with the router MAC of gw as their MAC address into
// *gw_macs
static UINT IrbTestOnVni(const NODE_STRETCH_ROUTE *list, UINT num, UINT vni, UINT *gw_macs)
{
	UINT on = 0;

	*gw_macs = 0;
	for (UINT i = 0;i < num;i++)
	{
		if (list[i].Vni != vni)
		{
			continue;
		}
		on++;
		if (list[i].Imet == false && Cmp(list[i].Mac, irbtest_gw_mac, 6) == 0)
		{
			(*gw_macs)++;
		}
	}

	return on;
}

// Whether the leaf holds the routes of the stretches of gw, and these only: on each L2 VNI the type-3 route of gw and the type-2 routes
// of its host there, MAC only and MAC plus IP, and on the two with irb the gateway IPs of gw with its router MAC, each via the VTEP
// of gw
static bool IrbTestLeafStretch(IRBTEST_CTX *ctx)
{
	NODE_STRETCH_ROUTE list[IRBTEST_ROUTES];
	UINT num = NodeStretchGetRoutes(ctx->Nodes[IRBTEST_LEAF].Node, list, IRBTEST_ROUTES);
	IRBTEST_HOST *h1 = &ctx->Hosts[IRBTEST_HOST_1];
	IRBTEST_HOST *h2 = &ctx->Hosts[IRBTEST_HOST_2];
	IRBTEST_HOST *h3 = &ctx->Hosts[IRBTEST_HOST_3];
	UINT red = irbtest_l2[IRBTEST_NET_RED];
	UINT blue = irbtest_l2[IRBTEST_NET_BLUE];
	UINT plain = irbtest_l2[IRBTEST_NET_PLAIN];

	return (num == 13 &&
		IrbTestHasStretch(list, num, red, NULL, NULL, "127.0.0.1") && IrbTestHasStretch(list, num, red, h1->Mac, NULL, "127.0.0.1") &&
		IrbTestHasStretch(list, num, red, h1->Mac, h1->Ip, "127.0.0.1") && IrbTestHasStretch(list, num, red, h1->Mac, h1->Ip6, "127.0.0.1") &&
		IrbTestHasStretch(list, num, red, irbtest_gw_mac, "10.50.0.1", "127.0.0.1") && IrbTestHasStretch(list, num, red, irbtest_gw_mac, "fd50::1", "127.0.0.1") &&
		IrbTestHasStretch(list, num, blue, NULL, NULL, "127.0.0.1") && IrbTestHasStretch(list, num, blue, h2->Mac, NULL, "127.0.0.1") &&
		IrbTestHasStretch(list, num, blue, h2->Mac, h2->Ip, "127.0.0.1") && IrbTestHasStretch(list, num, blue, irbtest_gw_mac, "10.50.0.1", "127.0.0.1") &&
		IrbTestHasStretch(list, num, plain, NULL, NULL, "127.0.0.1") && IrbTestHasStretch(list, num, plain, h3->Mac, NULL, "127.0.0.1") &&
		IrbTestHasStretch(list, num, plain, h3->Mac, h3->Ip, "127.0.0.1"));
}

//
// The cases
//

// The nodes, the sidecars of gw and the leaf with their session, the switches of the stretched Networks, which the L2 data path of the
// test attaches before each node starts, the harness VTEP of the leaf, and the overlays of gw and peer
static bool IrbTestOpen(IRBTEST_CTX *ctx, TRANSPORT *loopback)
{
	char bgp[MAX_SIZE * 8];
	UCHAR scalar[PEER_KEY_SIZE];
	USHORT leaf_bgp = 0;
	USHORT leaf_own = 0;
	USHORT nowhere = 0;
	bool ok = (loopback != NULL);

	Print("[the nodes, their sidecars, the switches of the stretched Networks, the harness VTEP of the leaf and the overlays]\n");

	for (UINT i = 0;i < 3;i++)
	{
		IRBTEST_NODE *t = &ctx->Nodes[i];

		InitializeSRWLock(&t->Lock);
		for (UINT j = 0;j < PEER_KEY_SIZE;j++)
		{
			scalar[j] = (UCHAR)(0x31 + PEER_KEY_SIZE * i + j);
		}
		ok = PeerKeyFromScalar(&t->Key, scalar) && ok;
	}
	Zero(scalar, sizeof(scalar));

	ctx->GwPort = IrbTestFreePort(false);
	leaf_own = IrbTestFreePort(false);
	nowhere = IrbTestFreePort(false);
	leaf_bgp = IrbTestFreePort(true);
	ctx->FabricPort = IrbTestBind(&ctx->Vtep, 0x7F000002);
	ok = IrbTestCheck(ctx, ok && ctx->GwPort != 0 && leaf_own != 0 && nowhere != 0 && leaf_bgp != 0 && ctx->FabricPort != 0 && ctx->GwPort != leaf_own &&
		ctx->GwPort != nowhere && leaf_own != nowhere,
		"Free ports: the UDP ports of the VTEPs of gw and the leaf, the TCP port of the sidecar of the leaf and the harness VTEP on 127.0.0.2",
		"VTEP ports %u, %u and %u, BGP port %u, harness VTEP port %u, error %u", (UINT)ctx->GwPort, (UINT)leaf_own, (UINT)nowhere, (UINT)leaf_bgp,
		(UINT)ctx->FabricPort, (UINT)WSAGetLastError());
	if (ok == false)
	{
		return false;
	}
	Print("  [INFO] gw: VTEP 127.0.0.1:%u; leaf: sidecar on 127.0.0.2:%u, harness VTEP 127.0.0.2:%u\n", (UINT)ctx->GwPort, (UINT)leaf_bgp, (UINT)ctx->FabricPort);

	Format(bgp, sizeof(bgp), IRBTEST_GW_BGP, (UINT)leaf_bgp, (UINT)ctx->GwPort, (UINT)ctx->FabricPort);
	IrbTestNewDir(ctx->Nodes[IRBTEST_GW].Dir, sizeof(ctx->Nodes[IRBTEST_GW].Dir), "gw", bgp);
	Format(bgp, sizeof(bgp), IRBTEST_LEAF_BGP, (UINT)leaf_bgp, (UINT)leaf_own, (UINT)nowhere);
	IrbTestNewDir(ctx->Nodes[IRBTEST_LEAF].Dir, sizeof(ctx->Nodes[IRBTEST_LEAF].Dir), "leaf", bgp);
	IrbTestNewDir(ctx->Nodes[IRBTEST_PEER].Dir, sizeof(ctx->Nodes[IRBTEST_PEER].Dir), "peer", NULL);
	for (UINT i = 0;i < 3;i++)
	{
		ctx->Nodes[i].Node = NewNode(ctx->Nodes[i].Dir);
	}
	ok = IrbTestCheck(ctx, IsFileExistsW(ctx->Nodes[IRBTEST_GW].Node->BgpSidecar), "ranz.exe is next to vpntest.exe", "%S is missing",
		ctx->Nodes[IRBTEST_GW].Node->BgpSidecar) && ok;

	// The switch of each stretched Network at gw and at the leaf, with its hosts, attached to the stretch of the node before it starts
	bool members = true;
	for (UINT i = IRBTEST_GW;i <= IRBTEST_LEAF;i++)
	{
		for (UINT k = 0;k < IRBTEST_NETS;k++)
		{
			ctx->Nodes[i].Switches[k] = SwitchNew(NULL);
			members = (ctx->Nodes[i].Switches[k] != NULL) && members;
		}
	}
	for (UINT i = 0;i < IRBTEST_HOSTS;i++)
	{
		IRBTEST_HOST *h = &ctx->Hosts[i];
		SWITCH *sw = ctx->Nodes[h->Node].Switches[h->Net];
		SWITCH_PORT_CONFIG pc;

		Zero(&pc, sizeof(pc));
		pc.Mode = SWITCH_ACCESS;
		pc.Vlan = IRBTEST_VLAN;
		pc.Send = IrbTestHostTake;
		pc.Param = h;
		h->Port = (sw != NULL ? SwitchAddPort(sw, &pc) : SWITCH_PORT_NONE);
		members = (h->Port != SWITCH_PORT_NONE) && members;
	}
	for (UINT i = IRBTEST_GW;i <= IRBTEST_LEAF;i++)
	{
		IRBTEST_NODE *t = &ctx->Nodes[i];

		for (UINT k = 0;k < IRBTEST_NETS;k++)
		{
			t->Attached[k] = (t->Switches[k] != NULL && NodeStretchAttach(t->Node, irbtest_nets[k], t->Switches[k], IRBTEST_VLAN));
			members = t->Attached[k] && members;
		}
	}
	ok = IrbTestCheck(ctx, members, "The switches of lan-red, lan-blue and lan-plain at gw and at the leaf, with host 1, host 2 and host 3 at gw and host a and host b at the leaf; the L2 data path of the test attaches each to the stretch of its node",
		"%s", "SwitchNew, SwitchAddPort or NodeStretchAttach failed") && ok;

	// The leaf first, which gw dials once its sidecar starts
	NodeStart(ctx->Nodes[IRBTEST_LEAF].Node);
	ok = IrbTestCheck(ctx, IrbTestWaitBgp(&ctx->Nodes[IRBTEST_LEAF], 0), "leaf: its sidecar runs, listening on 127.0.0.2 for gw", "%s", "not ready") && ok;

	NodeStart(ctx->Nodes[IRBTEST_GW].Node);
	bool established = IrbTestWaitBgp(&ctx->Nodes[IRBTEST_GW], 1) && IrbTestWaitBgp(&ctx->Nodes[IRBTEST_LEAF], 1);
	ok = IrbTestCheck(ctx, established, "The sidecar of gw dials the leaf: their EVPN session is established", "%s", "not established") && ok;

	NODE_STRETCH_STATUS st;
	NODE_EVPN_STATUS es;
	NodeStretchGetStatus(ctx->Nodes[IRBTEST_GW].Node, &st);
	NodeEvpnGetStatus(ctx->Nodes[IRBTEST_GW].Node, &es);
	ok = IrbTestCheck(ctx, es.Running && es.Port == ctx->GwPort && es.FabricPort == ctx->FabricPort && es.NumVrfs == 2 && st.NumStretches == 3 && st.NumAttached == 3,
		"gw: its EVPN runs on the VTEP of its Bgp setting with two EVPN VRFs and three stretches, two of them with irb, and the fabric is a member of the switch of each stretched Network",
		"EVPN running %u, port %u, fabric port %u, %u VRFs, %u stretches, %u attached", (UINT)es.Running, (UINT)es.Port, (UINT)es.FabricPort, es.NumVrfs,
		st.NumStretches, st.NumAttached) && ok;

	// peer, and the overlays of gw and peer over the in-process loopback transport
	NodeStart(ctx->Nodes[IRBTEST_PEER].Node);

	bool started = true;
	for (UINT i = 0;i < 2;i++)
	{
		IRBTEST_NODE *t = &ctx->Nodes[i == 0 ? IRBTEST_GW : IRBTEST_PEER];
		NODE_OVERLAY_CONFIG c;

		NodeReaderRegister(t->Node, &t->Reader);
		NodeReaderOffline(&t->Reader);
		t->Registered = true;

		Zero(&c, sizeof(c));
		c.Data = loopback;
		c.Key = &t->Key;
		c.Adapter = IrbTestAdapter;
		c.AdapterParam = t;
		started = NodeOverlayStart(t->Node, &c) && started;
	}

	bool applied = started && IrbTestApply(ctx) && IrbTestWaitLinks(ctx);
	ok = IrbTestCheck(ctx, applied, "The overlays of gw and peer run Generation 1, with their session up", "started %u, applied and linked %u", (UINT)started, (UINT)applied) && ok;

	return ok;
}

// The routes: each host announces itself into its switch, the routes of each side reach the other, and the stretch without irb
// announces no gateway IP or MAC of its Network
static void IrbTestRoutes(IRBTEST_CTX *ctx)
{
	UCHAR frame[64];
	NODE_STRETCH_ROUTE list[IRBTEST_ROUTES];
	NODE_BGP_STATUS bs;
	UINT gw_red = 0, gw_blue = 0, gw_plain = 0;

	Print("[the routes: the host routes of symmetric IRB both ways, and the gateway IPs]\n");

	for (UINT i = 0;i < IRBTEST_HOSTS;i++)
	{
		IRBTEST_HOST *h = &ctx->Hosts[i];

		IrbTestSend(ctx, h, frame, IrbTestAnnounce(frame, h));
		if (h->Ip6 != NULL)
		{
			IrbTestSend(ctx, h, frame, IrbTestAnnounce6(frame, h));
		}
	}

	bool gw = IrbTestWait(ctx, IrbTestGwRoutes, IRBTEST_BOUND);
	IrbTestCheck(ctx, gw, "gw holds the host route 10.50.0.10/32 of the fabric in red on VNI 10101 and in blue on VNI 10102, which its sidecar takes from the type-2 routes of host a and host b, and 172.16.1.0/24 and fd16::/64 of the leaf, each via the VTEP of the leaf with its router MAC",
		"%u routes of the fabric", NodeEvpnGetRoutes(ctx->Nodes[IRBTEST_GW].Node, NULL, 0));

	bool leaf = IrbTestWait(ctx, IrbTestLeafRoutes, IRBTEST_BOUND);
	IrbTestCheck(ctx, leaf, "The leaf holds 10.60.0.0/24 of gw in each of its VRFs, and each host of the overlay on a stretch with irb as a host route of the VRF of its stretch alone (10.50.0.20/32 of host 1 in 201 on VNI 10101 and of host 2 in 202 on VNI 10102, fd50::20/128 of host 1 in 201), each via the VTEP of gw with its router MAC",
		"%u routes of the fabric", NodeEvpnGetRoutes(ctx->Nodes[IRBTEST_LEAF].Node, NULL, 0));

	bool stretch = IrbTestWait(ctx, IrbTestLeafStretch, IRBTEST_BOUND);

	// No route that should not come comes later
	SleepThread(IRBTEST_SETTLE);
	UINT num = MIN(NodeStretchGetRoutes(ctx->Nodes[IRBTEST_LEAF].Node, list, IRBTEST_ROUTES), (UINT)IRBTEST_ROUTES);
	UINT red = IrbTestOnVni(list, num, irbtest_l2[IRBTEST_NET_RED], &gw_red);
	UINT blue = IrbTestOnVni(list, num, irbtest_l2[IRBTEST_NET_BLUE], &gw_blue);
	UINT plain = IrbTestOnVni(list, num, irbtest_l2[IRBTEST_NET_PLAIN], &gw_plain);
	IrbTestCheck(ctx, gw && leaf && stretch && IrbTestGwRoutes(ctx) && IrbTestLeafRoutes(ctx) && IrbTestLeafStretch(ctx),
		"Each side holds these routes and no others after a while: the leaf has the type-3 route of gw on each L2 VNI and the type-2 routes of its hosts, MAC only and MAC plus IP",
		"%u routes of the stretches at the leaf: %u on VNI 5020, %u on VNI 5021, %u on VNI 5030", num, red, blue, plain);

	IrbTestCheck(ctx, stretch && gw_red == 2 && gw_blue == 1,
		"With irb on, the leaf holds the gateway IPs of lan-red (10.50.0.1 and fd50::1) and of lan-blue (10.50.0.1) as type-2 routes of the router MAC of gw via its VTEP",
		"%u routes of the router MAC of gw on VNI 5020, %u on VNI 5021", gw_red, gw_blue);

	IrbTestCheck(ctx, stretch && plain == 3 && gw_plain == 0 && IrbTestHasPrefix(&ctx->Nodes[IRBTEST_LEAF], "10.53.0.5/32") == false,
		"With irb off, no gateway IP or MAC of the Network: on VNI 5030 of lan-plain the leaf holds the type-3 route of gw and the two routes of host 3 alone, none of the router MAC of gw and no gateway IP, and no host route of host 3 in a VRF",
		"%u routes on VNI 5030, %u of the router MAC of gw", plain, gw_plain);

	NodeBgpGetStatus(ctx->Nodes[IRBTEST_GW].Node, &bs);
	IrbTestCheck(ctx, bs.NumRoutes == 0 && bs.NumErrors == 0, "gw installs no route of the fabric into the Windows routing table, and its sidecar refused nothing",
		"%u routes installed, %u errors", bs.NumRoutes, bs.NumErrors);
}

// A host of the fabric reaches an overlay node of another Network of its VRF through the L3 VNI: the same packet of host a and host b
// to 10.60.0.2, on the L3 VNI of red and of blue, reaches the host of peer in the VRF of its VNI
static void IrbTestToOverlay(IRBTEST_CTX *ctx)
{
	IRBTEST_NODE *peer = &ctx->Nodes[IRBTEST_PEER];
	char what[MAX_SIZE * 2];

	Print("[a host of the fabric on the stretched Network reaches an overlay node of another Network of its VRF through the L3 VNI]\n");

	for (UINT k = 0;k < 2;k++)
	{
		UINT vrf = (k == 0 ? IRBTEST_RED : IRBTEST_BLUE);
		UINT vni = (k == 0 ? IRBTEST_VNI_RED : IRBTEST_VNI_BLUE);
		UCHAR packet[IRBTEST_SIZE];
		UINT size = IrbTestPacket(packet, "10.50.0.10", "10.60.0.2", 300);
		LONG arrivals = InterlockedCompareExchange(&peer->Arrivals, 0, 0);

		bool sent = (size != 0 && IrbTestInject(ctx, vni, packet, size));
		bool arrived = sent && IrbTestArrived(peer, arrivals + 1, IRBTEST_WAIT);
		bool same = false;

		AcquireSRWLockShared(&peer->Lock);
		{
			same = (arrived && peer->LastVrf == vrf && peer->LastSize == size && Cmp(peer->Last, packet, size) == 0);
		}
		ReleaseSRWLockShared(&peer->Lock);

		Format(what, sizeof(what), "VNI %u: udp 10.50.0.10 > 10.60.0.2 of the host of the fabric reaches the overlay node in VRF %u, as it was sent", vni, vrf);
		IrbTestCheck(ctx, same, what, "sent %u, arrived %u, VRF %u, %u bytes", (UINT)sent, (UINT)arrived, peer->LastVrf, peer->LastSize);
	}
}

// ... and back: the host of peer sends to 10.50.0.10 in red and in blue, and gw forwards each to the fabric on the L3 VNI of its VRF
// alone, by the host route of the fabric, to the router MAC of the leaf
static void IrbTestFromOverlay(IRBTEST_CTX *ctx)
{
	IRBTEST_NODE *peer = &ctx->Nodes[IRBTEST_PEER];
	UCHAR d[VXLAN_MAX_DATAGRAM];
	char what[MAX_SIZE * 2];

	Print("[back: the overlay node reaches the host of the fabric through the L3 VNI of its VRF, by the host route]\n");

	for (UINT k = 0;k < 2;k++)
	{
		UINT vrf = (k == 0 ? IRBTEST_RED : IRBTEST_BLUE);
		UINT vni = (k == 0 ? IRBTEST_VNI_RED : IRBTEST_VNI_BLUE);
		UINT other = (k == 0 ? IRBTEST_VNI_BLUE : IRBTEST_VNI_RED);
		UCHAR packet[IRBTEST_SIZE];
		UINT size = IrbTestPacket(packet, "10.60.0.2", "10.50.0.10", 400);

		IrbTestDrain(ctx);

		NodeReaderOnline(peer->Node, &peer->Reader);
		bool taken = (size != 0 && NodeOverlayInput(peer->Node, vrf, packet, size));
		NodeReaderOffline(&peer->Reader);

		UINT got = IrbTestTakeVni(ctx, d, sizeof(d), vni, IRBTEST_WAIT);
		bool is_frame = IrbTestIsFrame(d, got, vni, packet, size);
		UINT stray = IrbTestTakeVni(ctx, d, sizeof(d), other, IRBTEST_QUIET);

		Format(what, sizeof(what), "peer, VRF %u: udp 10.60.0.2 > 10.50.0.10 goes through gw to the fabric on VNI %u alone, from the router MAC of gw to the router MAC of the leaf, as it was sent", vrf, vni);
		IrbTestCheck(ctx, taken && is_frame && stray == 0, what, "taken %u, the harness VTEP took %u bytes on VNI %u (the frame %u) and %u bytes on VNI %u", (UINT)taken, got, vni,
			(UINT)is_frame, stray, other);
	}
}

// Into the stretched Network: each packet of irbtest_into from the harness VTEP, which the IRB of gw routes into the switch of its
// Network to the host of its destination, or which reaches no host
static void IrbTestIntoNetwork(IRBTEST_CTX *ctx)
{
	IRBTEST_NODE *gw = &ctx->Nodes[IRBTEST_GW];
	NODE_STRETCH_STATUS first, last;
	char what[MAX_SIZE * 2];

	Print("[into the stretched Network: gw routes a packet of the L3 VNI to a host of the overlay into the switch of its Network]\n");

	NodeStretchGetStatus(gw->Node, &first);

	for (UINT k = 0;k < sizeof(irbtest_into) / sizeof(irbtest_into[0]);k++)
	{
		IRBTEST_INTO *c = &irbtest_into[k];
		UCHAR packet[IRBTEST_SIZE];
		UCHAR want[IRBTEST_FRAME];
		LONG before[IRBTEST_GW_HOSTS];
		NODE_EVPN_STATUS es;
		UINT size = IrbTestPacket(packet, c->Src, c->Dst, 500 + k);
		bool others = true;

		for (UINT i = 0;i < IRBTEST_GW_HOSTS;i++)
		{
			before[i] = IrbTestFrames(&ctx->Hosts[i]);
		}
		NodeEvpnGetStatus(gw->Node, &es);

		bool sent = (size != 0 && IrbTestInject(ctx, c->Vni, packet, size));

		if (c->To != IRBTEST_NO_HOST)
		{
			IRBTEST_HOST *h = &ctx->Hosts[c->To];
			UINT want_size = IrbTestRouted(want, h, packet, size);
			bool arrived = sent && IrbTestHostArrived(h, before[c->To], IRBTEST_WAIT);
			bool same = arrived && IrbTestLastIs(h, want, want_size);

			SleepThread(IRBTEST_QUIET);
			for (UINT i = 0;i < IRBTEST_GW_HOSTS;i++)
			{
				others = others && (i == c->To || IrbTestFrames(&ctx->Hosts[i]) == before[i]);
			}

			Format(what, sizeof(what), "VNI %u: udp %s > %s reaches %s alone, in a frame from the router MAC of gw to its MAC address with the packet as it was sent", c->Vni,
				c->Src, c->Dst, c->Why);
			IrbTestCheck(ctx, same && others, what, "sent %u, arrived %u, the frame %u, other hosts untouched %u", (UINT)sent, (UINT)arrived, (UINT)same, (UINT)others);
		}
		else
		{
			bool counted = sent && IrbTestWaitUndelivered(gw, es.Undelivered + 1);

			SleepThread(IRBTEST_QUIET);
			for (UINT i = 0;i < IRBTEST_GW_HOSTS;i++)
			{
				others = others && (IrbTestFrames(&ctx->Hosts[i]) == before[i]);
			}

			Format(what, sizeof(what), "VNI %u: udp %s > %s, to %s, reaches no host, and gw counts it as a packet of the fabric that it did not deliver", c->Vni, c->Src, c->Dst,
				c->Why);
			IrbTestCheck(ctx, counted && others, what, "sent %u, counted %u, no host took it %u", (UINT)sent, (UINT)counted, (UINT)others);
		}
	}

	NodeStretchGetStatus(gw->Node, &last);
	IrbTestCheck(ctx, last.Routed - first.Routed == 3 && last.Unrouted - first.Unrouted == 1,
		"The stretch of gw counts the three packets that its IRB routed into a switch, and the one to an address of a gateway IP prefix that no host sends from",
		"%I64u routed, %I64u not", last.Routed - first.Routed, last.Unrouted - first.Unrouted);
}

// The switches leave the stretches, the nodes stop and their sidecars with them, and the node log of gw tells the story; the logs of
// the sidecars go into the job log when a check failed
static void IrbTestClose(IRBTEST_CTX *ctx)
{
	IRBTEST_NODE *gw = &ctx->Nodes[IRBTEST_GW];
	bool gw_ran = (gw->Node != NULL);

	for (UINT i = 0;i < 3;i++)
	{
		IRBTEST_NODE *t = &ctx->Nodes[i];

		if (t->Node == NULL)
		{
			continue;
		}
		for (UINT k = 0;k < IRBTEST_NETS;k++)
		{
			if (t->Attached[k])
			{
				NodeStretchDetach(t->Node, irbtest_nets[k]);
			}
		}
		if (t->Registered)
		{
			NodeReaderUnregister(t->Node, &t->Reader);
		}
		NodeStop(t->Node);
	}

	if (gw_ran)
	{
		NODE_STRETCH_STATUS st;
		NODE_EVPN_STATUS es;
		NODE_BGP_STATUS bs;

		NodeStretchGetStatus(gw->Node, &st);
		NodeEvpnGetStatus(gw->Node, &es);
		NodeBgpGetStatus(gw->Node, &bs);
		IrbTestCheck(ctx, st.NumStretches == 0 && st.NumAttached == 0 && es.Running == false && bs.ProcessId == 0, "NodeStop ends the stretches and the EVPN of gw with its sidecar",
			"%u stretches, %u attached, EVPN running %u, sidecar %u", st.NumStretches, st.NumAttached, (UINT)es.Running, bs.ProcessId);
	}

	// A node holds the file of its log open while it lives: FreeNode writes the last lines and closes it (FreeLog)
	for (UINT i = 0;i < 3;i++)
	{
		IRBTEST_NODE *t = &ctx->Nodes[i];

		FreeNode(t->Node);
		t->Node = NULL;
		for (UINT k = 0;k < IRBTEST_NETS;k++)
		{
			if (t->Switches[k] != NULL)
			{
				SwitchFree(t->Switches[k]);
				t->Switches[k] = NULL;
			}
		}
	}

	if (gw_ran)
	{
		char *log = IrbTestReadLog(gw->Dir, NULL);
		char *lines[] =
		{
			"EVPN started: the VTEP 127.0.0.1 on UDP port",
			"EVPN stretch: the IRB of the L2 Network lan-red routes in VRF 101, with 2 gateway IPs",
			"EVPN stretch: the IRB of the L2 Network lan-blue routes in VRF 102, with 1 gateway IPs",
			"EVPN stretch: 3 L2 Networks stretched into the fabric",
			"EVPN route 10.50.0.10/32 of VRF 101 learned: via the VTEP 127.0.0.2, VNI 10101, router MAC 02:00:5e:20:00:01, from 127.0.0.2",
			"EVPN route 10.50.0.10/32 of VRF 102 learned: via the VTEP 127.0.0.2, VNI 10102, router MAC 02:00:5e:20:00:01, from 127.0.0.2",
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
		IrbTestCheck(ctx, all, "The node log of gw names its EVPN, the IRB of lan-red and lan-blue, the host routes of the fabric that it learned in each VRF and the stop",
			"missing:%s", missing);
		Free(log);

		if (ctx->NumFailed != 0)
		{
			IrbTestPrintSidecarLog(gw, "gw");
			IrbTestPrintSidecarLog(&ctx->Nodes[IRBTEST_LEAF], "leaf");
		}
	}

	// The data directory of each node that the test made (IrbTestNewDir)
	for (UINT i = 0;i < 3;i++)
	{
		IRBTEST_NODE *t = &ctx->Nodes[i];
		wchar_t log_dir[MAX_PATH];

		if (UniIsEmptyStr(t->Dir) == false)
		{
			ConbinePathW(log_dir, sizeof(log_dir), t->Dir, NODE_LOG_DIR_NAME);
			IrbTestDeleteFiles(log_dir);
			IrbTestDeleteFiles(t->Dir);
		}
		PeerKeyClose(&t->Key);
	}

	if (ctx->Vtep != INVALID_SOCKET)
	{
		closesocket(ctx->Vtep);
	}
}

// The hosts of the test: host 1, host 2 and host 3 of the overlay at gw, host a and host b of the fabric behind the leaf
static void IrbTestHosts(IRBTEST_CTX *ctx)
{
	static const UCHAR macs[IRBTEST_HOSTS][6] =
	{
		{0x02, 0x52, 0x5A, 0x67, 0x00, 0x01},
		{0x02, 0x52, 0x5A, 0x67, 0x00, 0x02},
		{0x02, 0x52, 0x5A, 0x67, 0x00, 0x03},
		{0x02, 0x00, 0x5E, 0x67, 0x00, 0x0A},
		{0x02, 0x00, 0x5E, 0x67, 0x00, 0x0B},
	};
	static char *names[IRBTEST_HOSTS] = {"host 1", "host 2", "host 3", "host a", "host b"};
	static char *ips[IRBTEST_HOSTS] = {"10.50.0.20", "10.50.0.20", "10.53.0.5", "10.50.0.10", "10.50.0.10"};
	static char *ip6s[IRBTEST_HOSTS] = {"fd50::20", NULL, NULL, NULL, NULL};
	static const UINT nodes[IRBTEST_HOSTS] = {IRBTEST_GW, IRBTEST_GW, IRBTEST_GW, IRBTEST_LEAF, IRBTEST_LEAF};
	static const UINT nets[IRBTEST_HOSTS] = {IRBTEST_NET_RED, IRBTEST_NET_BLUE, IRBTEST_NET_PLAIN, IRBTEST_NET_RED, IRBTEST_NET_BLUE};

	for (UINT i = 0;i < IRBTEST_HOSTS;i++)
	{
		IRBTEST_HOST *h = &ctx->Hosts[i];

		h->Name = names[i];
		h->Node = nodes[i];
		h->Net = nets[i];
		Copy(h->Mac, macs[i], 6);
		h->Ip = ips[i];
		h->Ip6 = ip6s[i];
		h->Port = SWITCH_PORT_NONE;
		InitializeSRWLock(&h->Lock);
	}
}

// irb: the symmetric IRB of a stretch against a leaf of a fabric
RANZ_TEST("irb", irb_test, "EVPN symmetric IRB: a gateway node stretches two L2 Networks with the same addresses in two VRFs into a fabric with irb, and one without, through ranz bgp (ranz.exe next to vpntest) against a leaf with symmetric IRB: the host routes of each VRF both ways, a host of the fabric reaching an overlay node of another Network of its VRF through the L3 VNI and back, a packet of the L3 VNI routed into the switch of the stretched Network, and no gateway IP or MAC of the Network on the stretch without irb.");
void irb_test(UINT num, char **arg)
{
	IRBTEST_CTX *ctx = ZeroMalloc(sizeof(IRBTEST_CTX));
	HANDLE done = CreateEventW(NULL, TRUE, FALSE, NULL);
	HANDLE watchdog = (done != NULL ? CreateThread(NULL, 0, IrbTestWatchdog, done, 0, NULL) : NULL);
	TRANSPORT *loopback = TransportLoopbackNew("loopback", 0, false);

	Print("IRB test: a gateway routes between two stretched L2 Networks of two VRFs with the same addresses and the other Networks of each VRF through its L3 VNI, against a leaf with symmetric IRB\n");

	ctx->Vtep = INVALID_SOCKET;
	IrbTestHosts(ctx);

	if (IrbTestOpen(ctx, loopback))
	{
		IrbTestRoutes(ctx);
		IrbTestToOverlay(ctx);
		IrbTestFromOverlay(ctx);
		IrbTestIntoNetwork(ctx);
	}

	IrbTestClose(ctx);
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
		Print("IRB TEST OK\n");
	}
	else
	{
		Print("IRB TEST FAILED (%u of %u checks failed)\n", ctx->NumFailed, ctx->NumChecks);
	}

	Free(ctx);
}
