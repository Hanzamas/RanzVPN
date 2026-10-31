// evpntest.c
// Named EVPN gateway test of vpntest ("evpn" command, SDN-25 #201)
//
// The EVPN of a gateway (Cedar/NodeEvpn.c; ADR-0032 decisions 1 to 3): node gw hands the VRFs red (101) and blue (102) of
// the overlay to a data-centre fabric as IP prefix routes, EVPN route type 5, through its BGP sidecar (ranz.exe bgp), and
// does the VXLAN of the fabric itself. The fabric is two things on this runner, as the multi-node seam has it (ADR-0002
// amendment of 2026-10-21: no second host): its BGP speaker, the node fabric, whose own sidecar (GoBGP) dials the sidecar of
// gw on 127.0.0.1 and hands the fabric's VRFs 201 and 202 to gw, and its data plane, a harness VTEP on 127.0.0.2 that takes
// and sends the VXLAN datagrams of the fabric. Both VRFs use the same prefixes on both sides: 10.10.0.0/24 and fd10::/64 in
// the overlay, 172.16.1.0/24 and fd16::/64 in the fabric, each VRF on its own L3 VNI and route target (red 10101, blue
// 10102). Node peer has its addresses in red, and its state routes 172.16.0.0/12 and fd16::/48 of red to gw, as the
// Controller routes the LAN subnets of a gateway; the hosts of gw and peer are fake adapters, and the in-process loopback
// transport carries their Noise session.
// - The routes: each side holds the routes of the other in each VRF, once per VRF, with the L3 VNI of the VRF, the router MAC
//   and the VTEP of the other side, and gw installs none of them into the Windows routing table.
// - Overlay to fabric: the host of gw sends the same packet in red and in blue, IPv4 and IPv6, and the host of peer sends one
//   in red through gw. The harness VTEP takes each as a VXLAN datagram on the VNI of its VRF, with the Ethernet header from
//   the router MAC of gw to the router MAC of the fabric, untagged, with the EtherType of its IP version, and the packet as
//   it was sent; a packet to an address that no route holds goes nowhere.
// - Fabric to overlay: the harness VTEP sends the same packet on each VNI, and the host of gw takes it in the VRF of the VNI;
//   a packet to the address of peer in red reaches the host of peer through gw.
// - The guard: a datagram on a VNI of no EVPN VRF, a frame to another MAC address, a packet from a source that the fabric did
//   not announce and a packet to an address of no route are dropped and counted, and no host takes them.
// - The session profile and the Mirror: at gw, peer runs under a session profile with no-server, and a Mirror of red copies TCP
//   port 80 to a sensor on 127.0.0.1, as for the packets of a peer to a LAN subnet behind a gateway. The SYN-ACK of a server of
//   peer to the fabric is dropped and counted, and neither the fabric nor the sensor takes it; the SYN of a client of peer goes
//   to the fabric, and the sensor takes its copy as peer sent it.
// - Overlap: the fabric withdraws 172.16.1.0/24 of its red; a packet of red to it goes nowhere, and the same packet of blue
//   still goes on the VNI of blue.
// - The internet exit (SDN-25-R2, #550): the fabric announces 172.16.1.0/24 of its red again, and in Generation 2 peer is the
//   internet exit of red. The state of gw routes 0.0.0.0/0 and ::/0 of red to peer, as the Controller gives every other Node
//   of a VRF with an exit its default route (it gives 0.0.0.0/0 alone; the node takes ::/0 the same way), and the host of peer
//   takes 198.51.100.0/24 and 2001:db8:51::/48, a LAN behind it that stands for the internet. A route of the fabric wins over
//   the default route of red: the packets of the host of gw, and those of the host of peer that gw forwards, to 172.16.1.0/24
//   and fd16::/64 go to the fabric, and a packet of gw to any other address still goes to the exit. Then the fabric announces
//   0.0.0.0/0 and ::/0 of its red, which gw takes in red: of two default routes the one of red wins, for the packets of gw and
//   of peer, while 172.16.1.0/24 of the fabric still wins over both. In Generation 3 red has no exit again, and the default
//   routes of the fabric take what no route of red holds, as before.
// Print "EVPN TEST OK" only when every check passes. .github/scripts/bgp-spike.ps1 runs it, with ranz.exe next to vpntest.

#include "harness_int.h"
#include "testlist.h"

#include "Cedar/ConfigStore.h"
#include "Cedar/Node.h"
#include "Cedar/NodeEvpn.h"
#include "Cedar/NodeProfile.h"

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
#include "Core/Vxlan.h"

#include <WS2tcpip.h>

#include <stdio.h>

#define	EVPNTEST_BUDGET			300000		// The whole test ends within this time, or the watchdog ends the process (ms)
#define	EVPNTEST_BOUND			90000		// A bounded wait on BGP: the sessions and the routes (ms)
#define	EVPNTEST_WAIT			10000		// A bounded wait on a packet or a counter (ms)
#define	EVPNTEST_QUIET			500			// A side that gets nothing gets nothing within this time (ms)
#define	EVPNTEST_POLL			20			// Poll interval of observable state (ms)
#define	EVPNTEST_SIZE			100			// The size of a test packet
#define	EVPNTEST_DATAGRAM		(VXLAN_HEADER_SIZE + NODE_EVPN_ETHER + EVPNTEST_SIZE)
#define	EVPNTEST_RED			101			// The VRFs of the overlay at gw: red ...
#define	EVPNTEST_BLUE			102			// ... and blue
#define	EVPNTEST_FABRIC_RED		201			// ... and the same VRFs at the fabric
#define	EVPNTEST_FABRIC_BLUE	202
#define	EVPNTEST_VNI_RED		10101		// The L3 VNIs of red and blue
#define	EVPNTEST_VNI_BLUE		10102
#define	EVPNTEST_OTHER_VNI		999			// A VNI of no VRF
#define	EVPNTEST_WEB			80			// The TCP port that the Mirror of gw copies, of the server of peer
#define	EVPNTEST_CLIENT			5000		// ... and the port of the client of peer

// The nodes
#define	EVPNTEST_GW				0
#define	EVPNTEST_PEER			1
#define	EVPNTEST_FABRIC			2
#define	EVPNTEST_NONE			3			// No host

static char *evpntest_names[3] = {"gw", "peer", "fabric"};

// The router MACs: of gw (the default of the node and of the sidecar), of the fabric, and of no one
static const UCHAR evpntest_gw_mac[6] = {0x02, 0x52, 0x5A, 0x00, 0x00, 0x05};
static const UCHAR evpntest_fabric_mac[6] = {0x02, 0x00, 0x5E, 0x10, 0x00, 0x01};
static const UCHAR evpntest_other_mac[6] = {0x02, 0x00, 0x5E, 0x99, 0x99, 0x99};

// The Bgp setting of gw (its BGP port, the UDP port of its VTEP and of the VTEPs of the fabric): its sidecar listens on
// 127.0.0.1 for the fabric, which dials it; red and blue hand the same prefixes of the overlay to the fabric, each on its L3
// VNI and its route target. Red takes every prefix of the fabric, its default routes among them (SDN-25-R2, #550), and blue
// takes 172.16.0.0/12 and fd16::/48.
#define	EVPNTEST_GW_BGP	"{\"asn\":65001,\"router_id\":\"192.0.2.1\",\"listen_port\":%u,\"listen_addresses\":[\"127.0.0.1\"]," \
	"\"peers\":[{\"address\":\"127.0.0.1\",\"asn\":65010,\"passive\":true}]," \
	"\"evpn\":{\"vtep\":\"127.0.0.1\",\"port\":%u,\"fabric_port\":%u,\"vrfs\":[" \
	"{\"vrf\":101,\"vni\":10101,\"import\":[\"65000:10101\"],\"export\":[\"65000:10101\"],\"accept\":[\"0.0.0.0/0\",\"::/0\"]}," \
	"{\"vrf\":102,\"vni\":10102,\"import\":[\"65000:10102\"],\"export\":[\"65000:10102\"],\"accept\":[\"172.16.0.0/12\",\"fd16::/48\"]}]}," \
	"\"announce\":[{\"prefix\":\"10.10.0.0/24\",\"vrf\":101},{\"prefix\":\"10.10.0.0/24\",\"vrf\":102},{\"prefix\":\"fd10::/64\",\"vrf\":101}]}"

// The Bgp setting of the node fabric (the BGP port of gw, the UDP port of its own VTEP and of gw's): its sidecar dials gw and
// hands the VRFs 201 and 202 of the fabric, which import and export the route targets of red and blue, with the same prefixes
#define	EVPNTEST_FABRIC_BGP	"{\"asn\":65010,\"router_id\":\"192.0.2.10\",\"listen_port\":-1," \
	"\"peers\":[{\"address\":\"127.0.0.1\",\"asn\":65001,\"port\":%u}]," \
	"\"evpn\":{\"vtep\":\"127.0.0.2\",\"router_mac\":\"02:00:5e:10:00:01\",\"port\":%u,\"fabric_port\":%u,\"vrfs\":[" \
	"{\"vrf\":201,\"vni\":10101,\"import\":[\"65000:10101\"],\"export\":[\"65000:10101\"],\"accept\":[\"10.10.0.0/16\",\"fd10::/48\"]}," \
	"{\"vrf\":202,\"vni\":10102,\"import\":[\"65000:10102\"],\"export\":[\"65000:10102\"],\"accept\":[\"10.10.0.0/16\",\"fd10::/48\"]}]}," \
	"\"announce\":[{\"prefix\":\"172.16.1.0/24\",\"vrf\":201},{\"prefix\":\"172.16.1.0/24\",\"vrf\":202},{\"prefix\":\"fd16::/64\",\"vrf\":201}]}"

// One node and the fake adapter of its host, which keeps the last packet that the host took
typedef struct EVPNTEST_NODE
{
	wchar_t Dir[MAX_PATH];				// Its data directory
	PEER_KEY Key;						// Its static key
	NODE *Node;
	NODE_READER Reader;					// The test thread as a reader of the node's tables, online while it sends
	SRWLOCK Lock;						// Arrivals, LastVrf, Last and LastSize
	volatile LONG Arrivals;				// Packets that the host took
	UINT LastVrf;						// The VRF of the last one ...
	UCHAR Last[EVPNTEST_SIZE * 2];		// ... and the packet, as much as fits
	UINT LastSize;
} EVPNTEST_NODE;

// The test
typedef struct EVPNTEST_CTX
{
	UINT NumChecks;
	UINT NumFailed;
	EVPNTEST_NODE Nodes[3];
	SOCKET Vtep;						// The harness VTEP of the fabric, on 127.0.0.2 ...
	USHORT VtepPort;					// ... and its UDP port: the port of the VTEPs of the fabric for gw
	USHORT GwPort;						// The UDP port of the VTEP of gw
	USHORT FabricPort;					// ... and of the VTEP of the node fabric, which nothing sends to
	USHORT BgpPort;						// The TCP port of the sidecar of gw on 127.0.0.1
	SOCKET Sensor;						// The sensor of the Mirror of gw, on 127.0.0.1 ...
	USHORT SensorPort;					// ... and its UDP port
	bool Overlays;						// The overlays of gw and peer run
} EVPNTEST_CTX;

// A packet that a host sends to the fabric: the node and the VRF of the host, the two ends of an UDP packet, and the VNI
// that the fabric takes it on, 0 for a packet that goes nowhere
typedef struct EVPNTEST_OUT
{
	UINT From;
	UINT VrfId;
	char *Src;
	char *Dst;
	UINT Vni;
} EVPNTEST_OUT;

static EVPNTEST_OUT evpntest_out[] =
{
	{EVPNTEST_GW, EVPNTEST_RED, "10.10.0.1", "172.16.1.10", EVPNTEST_VNI_RED},
	{EVPNTEST_GW, EVPNTEST_BLUE, "10.10.0.1", "172.16.1.10", EVPNTEST_VNI_BLUE},
	{EVPNTEST_GW, EVPNTEST_RED, "fd10::1", "fd16::10", EVPNTEST_VNI_RED},
	{EVPNTEST_PEER, EVPNTEST_RED, "10.10.0.2", "172.16.1.20", EVPNTEST_VNI_RED},
	{EVPNTEST_GW, EVPNTEST_BLUE, "10.10.0.1", "172.16.9.9", 0},
};

// A packet that the fabric sends: the VNI, the inner destination MAC and the two ends of an UDP packet, and the node and the
// VRF of the host that takes it, EVPNTEST_NONE for none
typedef struct EVPNTEST_IN
{
	UINT Vni;
	const UCHAR *Mac;
	char *Src;
	char *Dst;
	UINT To;
	UINT VrfId;
} EVPNTEST_IN;

static EVPNTEST_IN evpntest_in[] =
{
	{EVPNTEST_VNI_RED, evpntest_gw_mac, "172.16.1.10", "10.10.0.1", EVPNTEST_GW, EVPNTEST_RED},
	{EVPNTEST_VNI_BLUE, evpntest_gw_mac, "172.16.1.10", "10.10.0.1", EVPNTEST_GW, EVPNTEST_BLUE},
	{EVPNTEST_VNI_RED, evpntest_gw_mac, "fd16::10", "fd10::1", EVPNTEST_GW, EVPNTEST_RED},
	{EVPNTEST_VNI_RED, evpntest_gw_mac, "172.16.1.20", "10.10.0.2", EVPNTEST_PEER, EVPNTEST_RED},
};

// A packet of the host of gw or of peer in red, with an internet exit of red and after it (SDN-25-R2, #550): the two ends of an
// UDP packet, the VNI that the fabric takes it on, 0 for none, whether the host of peer, the exit, takes it, and why
typedef struct EVPNTEST_EXIT
{
	UINT From;
	char *Src;
	char *Dst;
	UINT Vni;
	bool Exit;
	char *Why;
} EVPNTEST_EXIT;

// Generation 2: peer is the internet exit of red, and the fabric announces no default route
static EVPNTEST_EXIT evpntest_exit[] =
{
	{EVPNTEST_GW, "10.10.0.1", "172.16.1.10", EVPNTEST_VNI_RED, false, "172.16.1.0/24 of the fabric wins over the default route of red"},
	{EVPNTEST_GW, "fd10::1", "fd16::10", EVPNTEST_VNI_RED, false, "fd16::/64 of the fabric wins over the default route of red"},
	{EVPNTEST_PEER, "10.10.0.2", "172.16.1.20", EVPNTEST_VNI_RED, false, "gw forwards it: 172.16.1.0/24 of the fabric wins over the default route of red"},
	{EVPNTEST_PEER, "fd10::2", "fd16::20", EVPNTEST_VNI_RED, false, "gw forwards it: fd16::/64 of the fabric wins over the default route of red"},
	{EVPNTEST_GW, "10.10.0.1", "198.51.100.7", 0, true, "no route of the fabric holds it"},
	{EVPNTEST_GW, "fd10::1", "2001:db8:51::7", 0, true, "no route of the fabric holds it"},
};

// ... and the fabric announces 0.0.0.0/0 and ::/0 of its red too
static EVPNTEST_EXIT evpntest_defaults[] =
{
	{EVPNTEST_GW, "10.10.0.1", "198.51.100.7", 0, true, "the default route of red wins over the default route of the fabric"},
	{EVPNTEST_GW, "fd10::1", "2001:db8:51::7", 0, true, "the default route of red wins over the default route of the fabric"},
	{EVPNTEST_PEER, "10.10.0.2", "172.16.9.9", 0, false, "at gw the default route of red wins over the default route of the fabric"},
	{EVPNTEST_PEER, "fd10::2", "fd16:0:0:1::9", 0, false, "at gw the default route of red wins over the default route of the fabric"},
	{EVPNTEST_GW, "10.10.0.1", "172.16.1.10", EVPNTEST_VNI_RED, false, "172.16.1.0/24 of the fabric wins over both default routes"},
};

// Generation 3: red has no internet exit again, and the default routes of the fabric take what no route of red holds, as before
static EVPNTEST_EXIT evpntest_no_exit[] =
{
	{EVPNTEST_GW, "10.10.0.1", "198.51.100.7", EVPNTEST_VNI_RED, false, "no route of red holds it, the default route of the fabric does"},
	{EVPNTEST_GW, "fd10::1", "2001:db8:51::7", EVPNTEST_VNI_RED, false, "no route of red holds it, the default route of the fabric does"},
	{EVPNTEST_PEER, "10.10.0.2", "172.16.9.9", EVPNTEST_VNI_RED, false, "gw forwards it: no route of red holds it, the default route of the fabric does"},
};

static bool EvpnTestCheck(EVPNTEST_CTX *ctx, bool ok, char *what, char *fmt, ...) RANZ_PRINTF_FORMAT(4, 5);
static bool EvpnTestCheck(EVPNTEST_CTX *ctx, bool ok, char *what, char *fmt, ...)
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

// The watchdog: a native thread that ends a run that hangs, so that a lost session or packet is a failed test instead of a
// hung CI step
static DWORD WINAPI EvpnTestWatchdog(LPVOID param)
{
	char msg[MAX_SIZE];
	DWORD written = 0;

	if (WaitForSingleObject((HANDLE)param, EVPNTEST_BUDGET) != WAIT_TIMEOUT)
	{
		return 0;
	}

	int len = snprintf(msg, sizeof(msg), "EVPN TEST FAILED (did not finish within %u ms)\n", EVPNTEST_BUDGET);
	if (len > 0)
	{
		WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), msg, (DWORD)MIN((UINT)len, (UINT)sizeof(msg) - 1), &written, NULL);
	}

	TerminateProcess(GetCurrentProcess(), 1);

	return 0;
}

//
// Packets and the harness VTEP
//

// The address of a text into addr: 4 bytes for IPv4, 16 for IPv6, and their number; 0 for no address
static UINT EvpnTestAddress(UCHAR *addr, char *str)
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

// A packet from src to dst with the data seq, EVPNTEST_SIZE bytes, into buf: a TCP segment from port sport to port dport with
// the flags flags and a header of 20 bytes, or for flags 0 a UDP packet from port 5000 to port 53. Its size, 0 when its two ends
// are not of one family.
static UINT EvpnTestSegment(UCHAR *buf, char *src, char *dst, UCHAR flags, USHORT sport, USHORT dport, UINT seq)
{
	UCHAR s[16], d[16];
	UINT size = EvpnTestAddress(s, src);
	UINT ip = (size == 4 ? 20 : 40);
	UCHAR *l4 = buf + ip;
	UCHAR proto = (flags != 0 ? IP_PROTO_TCP : IP_PROTO_UDP);

	if (size == 0 || EvpnTestAddress(d, dst) != size)
	{
		return 0;
	}

	Zero(buf, EVPNTEST_SIZE);
	if (size == 4)
	{
		buf[0] = 0x45;
		WRITE_USHORT(buf + 2, EVPNTEST_SIZE);
		buf[8] = 64;
		buf[9] = proto;
		Copy(buf + 12, s, 4);
		Copy(buf + 16, d, 4);
		USHORT sum = IpChecksum(buf, 20);
		Copy(buf + 10, &sum, 2);
	}
	else
	{
		buf[0] = 0x60;
		WRITE_USHORT(buf + 4, EVPNTEST_SIZE - 40);
		buf[6] = proto;
		buf[7] = 64;
		Copy(buf + 8, s, 16);
		Copy(buf + 24, d, 16);
	}

	// The sequence number of the segment, or the length and the first data of the UDP packet; then the data
	UINT data = ip + 12;
	if (flags != 0)
	{
		WRITE_USHORT(l4, sport);
		WRITE_USHORT(l4 + 2, dport);
		WRITE_UINT(l4 + 4, seq);
		l4[12] = 0x50;
		l4[13] = flags;
		WRITE_USHORT(l4 + 14, 65535);
		data = ip + 20;
	}
	else
	{
		WRITE_USHORT(l4, 5000);
		WRITE_USHORT(l4 + 2, 53);
		WRITE_USHORT(l4 + 4, EVPNTEST_SIZE - ip);
		WRITE_UINT(l4 + 8, seq);
	}
	for (UINT i = data;i < EVPNTEST_SIZE;i++)
	{
		buf[i] = (UCHAR)(i * 7 + seq);
	}

	return EVPNTEST_SIZE;
}

// A UDP packet from src port 5000 to dst port 53 with the data seq, EVPNTEST_SIZE bytes, into buf: its size, 0 when its two
// ends are not of one family
static UINT EvpnTestPacket(UCHAR *buf, char *src, char *dst, UINT seq)
{
	return EvpnTestSegment(buf, src, dst, 0, 0, 0, seq);
}

// A free UDP port of the wildcard address, or TCP of 127.0.0.1 with tcp, which the system picks: 0 for none
static USHORT EvpnTestFreePort(bool tcp)
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

// A UDP socket on the IPv4 address addr, in host byte order, on a port that the system picks, into *s: its port, 0 when it
// could not be opened
static USHORT EvpnTestBind(SOCKET *s, UINT addr)
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
		return 0;
	}

	return ntohs(sa.sin_port);
}

// The harness VTEP of the fabric on 127.0.0.2 and the sensor of the Mirror of gw on 127.0.0.1, each a UDP socket on a port that
// the system picks, into ctx
static bool EvpnTestOpenVtep(EVPNTEST_CTX *ctx)
{
	ctx->VtepPort = EvpnTestBind(&ctx->Vtep, 0x7F000002);
	ctx->SensorPort = EvpnTestBind(&ctx->Sensor, INADDR_LOOPBACK);

	return (ctx->VtepPort != 0 && ctx->SensorPort != 0);
}

// The next datagram that the socket s takes within timeout ms, into buf of size bytes: its size, 0 for none
static UINT EvpnTestTakeFrom(SOCKET s, UCHAR *buf, UINT size, UINT timeout)
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

// The next datagram that the harness VTEP takes within timeout ms, into buf of size bytes: its size, 0 for none
static UINT EvpnTestTake(EVPNTEST_CTX *ctx, UCHAR *buf, UINT size, UINT timeout)
{
	return EvpnTestTakeFrom(ctx->Vtep, buf, size, timeout);
}

// Drop what the harness VTEP and the sensor hold
static void EvpnTestDrain(EVPNTEST_CTX *ctx)
{
	UCHAR buf[VXLAN_MAX_DATAGRAM];

	while (EvpnTestTake(ctx, buf, sizeof(buf), 0) != 0)
	{
	}
	while (EvpnTestTakeFrom(ctx->Sensor, buf, sizeof(buf), 0) != 0)
	{
	}
}

// Whether the datagram d of size bytes is the VXLAN datagram of packet, packet_size bytes, on vni: the I flag and the VNI,
// then the Ethernet header from the router MAC of gw to the router MAC of the fabric, untagged, with the EtherType of the IP
// version of the packet, and the packet
static bool EvpnTestIsFrame(const UCHAR *d, UINT size, UINT vni, const UCHAR *packet, UINT packet_size)
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

	return (Cmp(d + VXLAN_HEADER_SIZE, evpntest_fabric_mac, 6) == 0 && Cmp(d + VXLAN_HEADER_SIZE + 6, evpntest_gw_mac, 6) == 0 &&
		READ_USHORT(d + VXLAN_HEADER_SIZE + 12) == ether && Cmp(d + VXLAN_HEADER_SIZE + NODE_EVPN_ETHER, packet, packet_size) == 0);
}

// Send gw, from the harness VTEP, a VXLAN datagram on vni with the frame of packet, size bytes, from the router MAC of the
// fabric to mac: whether it went
static bool EvpnTestInject(EVPNTEST_CTX *ctx, UINT vni, const UCHAR *mac, const UCHAR *packet, UINT size)
{
	UCHAR d[EVPNTEST_DATAGRAM];
	struct sockaddr_in sa;

	if (size > EVPNTEST_SIZE)
	{
		return false;
	}

	Zero(d, sizeof(d));
	d[0] = VXLAN_FLAG_VNI;
	d[4] = (UCHAR)(vni >> 16);
	d[5] = (UCHAR)(vni >> 8);
	d[6] = (UCHAR)vni;
	Copy(d + VXLAN_HEADER_SIZE, mac, 6);
	Copy(d + VXLAN_HEADER_SIZE + 6, evpntest_fabric_mac, 6);
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
// The nodes
//

// A new empty data directory under the temp directory of the process, with a configuration store that runs no role on one
// worker, with the Bgp setting bgp, none for NULL
static void EvpnTestNewDir(wchar_t *dir, UINT size, char *name, char *bgp)
{
	wchar_t tmp[MAX_PATH];
	wchar_t path[MAX_PATH];

	UniFormat(tmp, sizeof(tmp), L"evpntest_%S_%u", name, (UINT)Tick64());
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
static void EvpnTestDeleteFiles(wchar_t *dir)
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

// The text of a file of the node log directory of dir, or of every file there for NULL; NULL when there is none. The
// caller frees it.
static char *EvpnTestReadLog(wchar_t *dir, wchar_t *name)
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

// Whether the text holds part
static bool EvpnTestHas(char *text, char *part)
{
	return (text != NULL && SearchStrEx(text, part, 0, true) != INFINITE);
}

// The fake adapter of a host: it counts the packets that the host takes and keeps the last one. A packet of the fabric comes
// on the receive thread of the socket of gw, one of a peer on the thread of the overlay, so the lock orders the two.
static void EvpnTestAdapter(NODE *n, void *param, UINT vrf_id, const UCHAR *packet, UINT size)
{
	EVPNTEST_NODE *t = (EVPNTEST_NODE *)param;

	AcquireSRWLockExclusive(&t->Lock);
	{
		t->LastVrf = vrf_id;
		t->LastSize = size;
		Copy(t->Last, packet, MIN(size, sizeof(t->Last)));
		InterlockedIncrement(&t->Arrivals);
	}
	ReleaseSRWLockExclusive(&t->Lock);
}

// The address of a in the Network network of the VRF vrf_id, of the length of a host's Network
static void EvpnTestAddr(CONTROL_ADDRESS *a, char *network, UINT vrf_id, char *addr)
{
	Zero(a, sizeof(CONTROL_ADDRESS));
	StrCpy(a->Network, sizeof(a->Network), network);
	a->VrfId = vrf_id;
	a->AddressSize = EvpnTestAddress(a->Address, addr);
	a->Length = (a->AddressSize == 4 ? 24 : 64);
}

// A route of the VRF vrf_id to prefix/length that leads to a peer, or a LAN subnet behind the node
static void EvpnTestRoute(CONTROL_ROUTE *r, UINT vrf_id, char *prefix, UINT length)
{
	Zero(r, sizeof(CONTROL_ROUTE));
	r->VrfId = vrf_id;
	r->AddressSize = EvpnTestAddress(r->Address, prefix);
	r->Length = length;
}

// Apply the Generation generation of gw and peer: gw has 10.10.0.1 in red and in blue and fd10::1 in red, peer 10.10.0.2 and
// fd10::2 in red; the state of peer routes 172.16.0.0/12 and fd16::/48 of red to gw, as the Controller routes the LAN subnets
// of a gateway. At gw, peer runs under a session profile with no-server, and a Mirror copies TCP port 80 of red to the sensor.
// No VRF has a policy. With has_exit, peer is the internet exit of red (SDN-25-R2, #550): the state of gw routes 0.0.0.0/0 and
// ::/0 of red to peer, as the Controller gives every other Node of a VRF its default route to the exit, and the host of peer
// takes 198.51.100.0/24 and 2001:db8:51::/48, a LAN behind it that stands for the internet.
static bool EvpnTestApply(EVPNTEST_CTX *ctx, UINT generation, bool has_exit)
{
	bool ok = true;

	for (UINT i = 0;i < 2;i++)
	{
		CONTROL_STATE *st = ZeroMalloc(sizeof(CONTROL_STATE));
		CONTROL_PEER *p = ZeroMalloc(sizeof(CONTROL_PEER));
		UINT j = 1 - i;
		bool gw = (i == EVPNTEST_GW);

		st->Generation = generation;
		StrCpy(st->Name, sizeof(st->Name), evpntest_names[i]);
		EvpnTestAddr(&st->Addresses[0], "red", EVPNTEST_RED, gw ? "10.10.0.1" : "10.10.0.2");
		EvpnTestAddr(&st->Addresses[1], "red", EVPNTEST_RED, gw ? "fd10::1" : "fd10::2");
		st->NumAddresses = 2;
		if (gw)
		{
			EvpnTestAddr(&st->Addresses[2], "blue", EVPNTEST_BLUE, "10.10.0.1");
			st->NumAddresses = 3;
		}

		// In name order
		if (gw)
		{
			StrCpy(st->Vrfs[st->NumVrfs].Name, sizeof(st->Vrfs[0].Name), "blue");
			st->Vrfs[st->NumVrfs++].Id = EVPNTEST_BLUE;
		}
		StrCpy(st->Vrfs[st->NumVrfs].Name, sizeof(st->Vrfs[0].Name), "red");
		st->Vrfs[st->NumVrfs++].Id = EVPNTEST_RED;

		StrCpy(p->Name, sizeof(p->Name), evpntest_names[j]);
		Copy(p->Key, ctx->Nodes[j].Key.Public, PEER_KEY_SIZE);
		p->NumVrfs = 1;
		p->VrfIds[0] = EVPNTEST_RED;
		EvpnTestAddr(&p->Addresses[0], "red", EVPNTEST_RED, gw ? "10.10.0.2" : "10.10.0.1");
		EvpnTestAddr(&p->Addresses[1], "red", EVPNTEST_RED, gw ? "fd10::2" : "fd10::1");
		p->NumAddresses = 2;
		if (gw == false)
		{
			EvpnTestRoute(&p->Routes[0], EVPNTEST_RED, "172.16.0.0", 12);
			EvpnTestRoute(&p->Routes[1], EVPNTEST_RED, "fd16::", 48);
			p->NumRoutes = 2;
			if (has_exit)
			{
				EvpnTestRoute(&st->LanSubnets[0], EVPNTEST_RED, "198.51.100.0", 24);
				EvpnTestRoute(&st->LanSubnets[1], EVPNTEST_RED, "2001:db8:51::", 48);
				st->NumLanSubnets = 2;
			}
		}
		else
		{
			CONTROL_MIRROR *m = &st->Mirrors[st->NumMirrors++];

			p->Profile.Set = true;
			StrCpy(p->Profile.Name, sizeof(p->Profile.Name), "no-server");
			StrCpy(p->Profile.User, sizeof(p->Profile.User), "peer");
			p->Profile.NoServer = true;

			StrCpy(m->Name, sizeof(m->Name), "web");
			m->VrfId = EVPNTEST_RED;
			m->Protocol = IP_PROTO_TCP;
			m->Port = EVPNTEST_WEB;
			m->SensorSize = EvpnTestAddress(m->Sensor, "127.0.0.1");
			m->SensorPort = ctx->SensorPort;

			if (has_exit)
			{
				EvpnTestRoute(&p->Routes[0], EVPNTEST_RED, "0.0.0.0", 0);
				EvpnTestRoute(&p->Routes[1], EVPNTEST_RED, "::", 0);
				p->NumRoutes = 2;
			}
		}
		st->Peers = p;
		st->NumPeers = 1;

		ok = NodeOverlayApply(ctx->Nodes[i].Node, st) && ok;

		Free(p);
		Free(st);
	}

	return ok;
}

// Whether gw and peer run the Generation generation with their session up, within EVPNTEST_WAIT
static bool EvpnTestWaitLinks(EVPNTEST_CTX *ctx, UINT generation)
{
	UINT64 end = Tick64() + EVPNTEST_WAIT;

	while (true)
	{
		NODE_OVERLAY_STATUS a, b;

		NodeOverlayGetStatus(ctx->Nodes[EVPNTEST_GW].Node, &a);
		NodeOverlayGetStatus(ctx->Nodes[EVPNTEST_PEER].Node, &b);
		if (a.NumLinks == 1 && b.NumLinks == 1 && a.Generation == generation && b.Generation == generation)
		{
			return true;
		}
		if (Tick64() >= end)
		{
			return false;
		}
		SleepThread(EVPNTEST_POLL);
	}
}

// Whether the sidecar of node t runs (ready) and, with established, has its session with its peer up, within EVPNTEST_BOUND
static bool EvpnTestWaitBgp(EVPNTEST_NODE *t, bool established)
{
	UINT64 end = Tick64() + EVPNTEST_BOUND;

	while (true)
	{
		NODE_BGP_STATUS st;

		NodeBgpGetStatus(t->Node, &st);
		if (st.Running && (established == false || st.NumEstablished == 1))
		{
			return true;
		}
		if (Tick64() >= end)
		{
			return false;
		}
		SleepThread(EVPNTEST_POLL * 10);
	}
}

// Whether node t holds num routes of the fabric within EVPNTEST_BOUND
static bool EvpnTestWaitRoutes(EVPNTEST_NODE *t, UINT num)
{
	UINT64 end = Tick64() + EVPNTEST_BOUND;

	while (true)
	{
		NODE_EVPN_STATUS st;

		NodeEvpnGetStatus(t->Node, &st);
		if (st.NumRoutes == num)
		{
			return true;
		}
		if (Tick64() >= end)
		{
			return false;
		}
		SleepThread(EVPNTEST_POLL * 5);
	}
}

// Whether the host of node t took at least target packets within timeout
static bool EvpnTestArrived(EVPNTEST_NODE *t, LONG target, UINT timeout)
{
	UINT64 end = Tick64() + timeout;

	while (InterlockedCompareExchange(&t->Arrivals, 0, 0) < target)
	{
		if (Tick64() >= end)
		{
			return false;
		}
		SleepThread(EVPNTEST_POLL);
	}

	return true;
}

// Whether node t holds the route of the fabric to prefix in its VRF vrf_id via next_hop, on vni, with the router MAC mac
static bool EvpnTestHasRoute(EVPNTEST_NODE *t, UINT vrf_id, char *prefix, char *next_hop, UINT vni, const UCHAR *mac)
{
	NODE_EVPN_ROUTE list[16];
	UINT num = NodeEvpnGetRoutes(t->Node, list, 16);

	for (UINT i = 0;i < num && i < 16;i++)
	{
		NODE_EVPN_ROUTE *r = &list[i];

		if (r->VrfId == vrf_id && StrCmpi(r->Prefix, prefix) == 0 && StrCmp(r->NextHop, next_hop) == 0 && r->Vni == vni && Cmp(r->RouterMac, mac, 6) == 0)
		{
			return true;
		}
	}

	return false;
}

// Print the log of the sidecar of node t, so that the job log shows its BGP session and its routes
static void EvpnTestPrintSidecarLog(EVPNTEST_NODE *t, char *name)
{
	char *log = EvpnTestReadLog(t->Dir, NODE_BGP_LOG_NAME);

	Print("  --- %s: %S ---\n%s  ---\n", name, NODE_BGP_LOG_NAME, log == NULL ? "(none)\n" : log);

	Free(log);
}

// The nodes, the sidecars of gw and fabric with their session, the harness VTEP, and the overlays of gw and peer
static bool EvpnTestOpen(EVPNTEST_CTX *ctx, TRANSPORT *loopback)
{
	char bgp[MAX_SIZE * 4];
	char what[MAX_SIZE];
	UCHAR scalar[PEER_KEY_SIZE];
	bool ok = (loopback != NULL);

	Print("[the nodes, their sidecars and the harness VTEP of the fabric]\n");

	for (UINT i = 0;i < 3;i++)
	{
		EVPNTEST_NODE *t = &ctx->Nodes[i];

		InitializeSRWLock(&t->Lock);
		for (UINT j = 0;j < PEER_KEY_SIZE;j++)
		{
			scalar[j] = (UCHAR)(0x61 + PEER_KEY_SIZE * i + j);
		}
		ok = PeerKeyFromScalar(&t->Key, scalar) && ok;
	}
	Zero(scalar, sizeof(scalar));

	ctx->GwPort = EvpnTestFreePort(false);
	ctx->FabricPort = EvpnTestFreePort(false);
	ctx->BgpPort = EvpnTestFreePort(true);
	ok = EvpnTestCheck(ctx, ok && ctx->GwPort != 0 && ctx->FabricPort != 0 && ctx->BgpPort != 0 && ctx->GwPort != ctx->FabricPort && EvpnTestOpenVtep(ctx),
		"Free ports: the UDP ports of the VTEPs of gw and fabric, the TCP port of the sidecar of gw, the harness VTEP on 127.0.0.2 and the sensor on 127.0.0.1",
		"VTEP ports %u and %u, BGP port %u, harness VTEP port %u, sensor port %u, error %u", (UINT)ctx->GwPort, (UINT)ctx->FabricPort, (UINT)ctx->BgpPort, (UINT)ctx->VtepPort,
		(UINT)ctx->SensorPort, (UINT)WSAGetLastError()) && ok;
	if (ok == false)
	{
		return false;
	}
	Print("  [INFO] gw: VTEP 127.0.0.1:%u, sidecar on 127.0.0.1:%u; harness VTEP of the fabric 127.0.0.2:%u; sensor of the Mirror of gw 127.0.0.1:%u\n",
		(UINT)ctx->GwPort, (UINT)ctx->BgpPort, (UINT)ctx->VtepPort, (UINT)ctx->SensorPort);

	// gw first: the sidecar of fabric dials it once, a few seconds after it starts
	Format(bgp, sizeof(bgp), EVPNTEST_GW_BGP, (UINT)ctx->BgpPort, (UINT)ctx->GwPort, (UINT)ctx->VtepPort);
	EvpnTestNewDir(ctx->Nodes[EVPNTEST_GW].Dir, sizeof(ctx->Nodes[EVPNTEST_GW].Dir), "gw", bgp);
	ctx->Nodes[EVPNTEST_GW].Node = NewNode(ctx->Nodes[EVPNTEST_GW].Dir);
	ok = EvpnTestCheck(ctx, IsFileExistsW(ctx->Nodes[EVPNTEST_GW].Node->BgpSidecar), "ranz.exe is next to vpntest.exe", "%S is missing", ctx->Nodes[EVPNTEST_GW].Node->BgpSidecar) && ok;
	NodeStart(ctx->Nodes[EVPNTEST_GW].Node);

	NODE_EVPN_STATUS es;
	bool ready = EvpnTestWaitBgp(&ctx->Nodes[EVPNTEST_GW], false);
	NodeEvpnGetStatus(ctx->Nodes[EVPNTEST_GW].Node, &es);
	ok = EvpnTestCheck(ctx, ready && es.Running && es.Port == ctx->GwPort && es.FabricPort == ctx->VtepPort && es.NumVrfs == 2,
		"gw: its sidecar runs, and its EVPN with the VTEP of its Bgp setting and two EVPN VRFs",
		"ready %u, EVPN running %u, port %u, fabric port %u, %u VRFs", (UINT)ready, (UINT)es.Running, (UINT)es.Port, (UINT)es.FabricPort, es.NumVrfs) && ok;

	Format(bgp, sizeof(bgp), EVPNTEST_FABRIC_BGP, (UINT)ctx->BgpPort, (UINT)ctx->FabricPort, (UINT)ctx->GwPort);
	EvpnTestNewDir(ctx->Nodes[EVPNTEST_FABRIC].Dir, sizeof(ctx->Nodes[EVPNTEST_FABRIC].Dir), "fabric", bgp);
	ctx->Nodes[EVPNTEST_FABRIC].Node = NewNode(ctx->Nodes[EVPNTEST_FABRIC].Dir);
	NodeStart(ctx->Nodes[EVPNTEST_FABRIC].Node);

	bool established = EvpnTestWaitBgp(&ctx->Nodes[EVPNTEST_GW], true) && EvpnTestWaitBgp(&ctx->Nodes[EVPNTEST_FABRIC], true);
	ok = EvpnTestCheck(ctx, established, "The sidecar of fabric dials the sidecar of gw: the EVPN session of the two is established", "%s", "not established") && ok;

	// peer, and the overlays of gw and peer over the in-process loopback transport
	EvpnTestNewDir(ctx->Nodes[EVPNTEST_PEER].Dir, sizeof(ctx->Nodes[EVPNTEST_PEER].Dir), "peer", NULL);
	ctx->Nodes[EVPNTEST_PEER].Node = NewNode(ctx->Nodes[EVPNTEST_PEER].Dir);
	NodeStart(ctx->Nodes[EVPNTEST_PEER].Node);

	bool started = true;
	for (UINT i = 0;i < 2;i++)
	{
		EVPNTEST_NODE *t = &ctx->Nodes[i];
		NODE_OVERLAY_CONFIG c;

		NodeReaderRegister(t->Node, &t->Reader);
		NodeReaderOffline(&t->Reader);

		Zero(&c, sizeof(c));
		c.Data = loopback;
		c.Key = &t->Key;
		c.Adapter = EvpnTestAdapter;
		c.AdapterParam = t;
		started = NodeOverlayStart(t->Node, &c) && started;
	}
	ctx->Overlays = started;

	bool applied = started && EvpnTestApply(ctx, 1, false) && EvpnTestWaitLinks(ctx, 1);
	Format(what, sizeof(what), "The overlays of gw and peer run Generation 1, with their session up");
	ok = EvpnTestCheck(ctx, applied, what, "started %u, applied and linked %u", (UINT)started, (UINT)applied) && ok;

	return ok;
}

// The nodes first, whose overlays and sidecars stop with every thread joined, then the harness VTEP and the sensor. The node
// log of gw tells the story, and the logs of both sidecars go into the job log.
static void EvpnTestClose(EVPNTEST_CTX *ctx)
{
	EVPNTEST_NODE *gw = &ctx->Nodes[EVPNTEST_GW];
	bool gw_ran = (gw->Node != NULL);

	for (UINT i = 0;i < 3;i++)
	{
		EVPNTEST_NODE *t = &ctx->Nodes[i];

		if (t->Node != NULL)
		{
			if (i != EVPNTEST_FABRIC)
			{
				NodeReaderUnregister(t->Node, &t->Reader);
			}
			NodeStop(t->Node);
		}
	}

	if (gw_ran)
	{
		NODE_EVPN_STATUS es;
		NODE_BGP_STATUS bs;

		NodeEvpnGetStatus(gw->Node, &es);
		NodeBgpGetStatus(gw->Node, &bs);
		EvpnTestCheck(ctx, es.Running == false && bs.ProcessId == 0, "NodeStop ends the EVPN of gw with its sidecar", "EVPN running %u, sidecar %u", (UINT)es.Running, bs.ProcessId);
	}

	// A node holds the file of its log open while it lives: FreeNode writes the last lines and closes it (FreeLog)
	for (UINT i = 0;i < 3;i++)
	{
		FreeNode(ctx->Nodes[i].Node);
		ctx->Nodes[i].Node = NULL;
	}

	if (gw_ran)
	{
		char *log = EvpnTestReadLog(gw->Dir, NULL);
		char *lines[] =
		{
			"EVPN started: the VTEP 127.0.0.1 on UDP port",
			"BGP prefix 10.10.0.0/24 of VRF 101 announced",
			"BGP prefix 10.10.0.0/24 of VRF 102 announced",
			"EVPN route 172.16.1.0/24 of VRF 101 learned: via the VTEP 127.0.0.2, VNI 10101, router MAC 02:00:5e:10:00:01, from 127.0.0.1",
			"EVPN route 172.16.1.0/24 of VRF 102 learned: via the VTEP 127.0.0.2, VNI 10102, router MAC 02:00:5e:10:00:01, from 127.0.0.1",
			"EVPN route 172.16.1.0/24 of VRF 101 withdrawn by 127.0.0.1",
			"EVPN stopped:",
		};
		char missing[MAX_SIZE * 2];
		bool all = true;

		StrCpy(missing, sizeof(missing), "");
		for (UINT i = 0;i < sizeof(lines) / sizeof(lines[0]);i++)
		{
			if (EvpnTestHas(log, lines[i]) == false)
			{
				all = false;
				StrCat(missing, sizeof(missing), " \"");
				StrCat(missing, sizeof(missing), lines[i]);
				StrCat(missing, sizeof(missing), "\"");
			}
		}
		EvpnTestCheck(ctx, all, "The node log of gw names its EVPN, the prefixes it announces in each VRF and the routes of the fabric it learned and lost", "missing:%s", missing);
		Free(log);

		if (ctx->NumFailed != 0)
		{
			EvpnTestPrintSidecarLog(gw, "gw");
			EvpnTestPrintSidecarLog(&ctx->Nodes[EVPNTEST_FABRIC], "fabric");
		}
	}

	// The data directory of each node that the test made (EvpnTestNewDir)
	for (UINT i = 0;i < 3;i++)
	{
		EVPNTEST_NODE *t = &ctx->Nodes[i];
		wchar_t log_dir[MAX_PATH];

		if (UniIsEmptyStr(t->Dir) == false)
		{
			ConbinePathW(log_dir, sizeof(log_dir), t->Dir, NODE_LOG_DIR_NAME);
			EvpnTestDeleteFiles(log_dir);
			EvpnTestDeleteFiles(t->Dir);
		}
		PeerKeyClose(&t->Key);
	}

	if (ctx->Vtep != INVALID_SOCKET)
	{
		closesocket(ctx->Vtep);
	}
	if (ctx->Sensor != INVALID_SOCKET)
	{
		closesocket(ctx->Sensor);
	}
}

//
// The cases
//

// The routes of both sides, in each VRF once, with its L3 VNI, the router MAC and the VTEP of the other side; none in the
// Windows routing table
static void EvpnTestRoutes(EVPNTEST_CTX *ctx)
{
	EVPNTEST_NODE *gw = &ctx->Nodes[EVPNTEST_GW];
	EVPNTEST_NODE *fabric = &ctx->Nodes[EVPNTEST_FABRIC];
	NODE_BGP_STATUS bs;

	Print("[the IP prefix routes of both sides]\n");

	bool both = EvpnTestWaitRoutes(gw, 3) && EvpnTestWaitRoutes(fabric, 3);
	EvpnTestCheck(ctx, both, "gw holds the three routes of the fabric, and the fabric the three of gw", "%s", "the routes did not come");

	EvpnTestCheck(ctx, EvpnTestHasRoute(gw, EVPNTEST_RED, "172.16.1.0/24", "127.0.0.2", EVPNTEST_VNI_RED, evpntest_fabric_mac) &&
		EvpnTestHasRoute(gw, EVPNTEST_BLUE, "172.16.1.0/24", "127.0.0.2", EVPNTEST_VNI_BLUE, evpntest_fabric_mac) &&
		EvpnTestHasRoute(gw, EVPNTEST_RED, "fd16::/64", "127.0.0.2", EVPNTEST_VNI_RED, evpntest_fabric_mac),
		"gw: 172.16.1.0/24 in red on VNI 10101 and in blue on VNI 10102, fd16::/64 in red, each via the VTEP 127.0.0.2 with the router MAC of the fabric",
		"%s", "a route is missing or wrong");

	EvpnTestCheck(ctx, EvpnTestHasRoute(fabric, EVPNTEST_FABRIC_RED, "10.10.0.0/24", "127.0.0.1", EVPNTEST_VNI_RED, evpntest_gw_mac) &&
		EvpnTestHasRoute(fabric, EVPNTEST_FABRIC_BLUE, "10.10.0.0/24", "127.0.0.1", EVPNTEST_VNI_BLUE, evpntest_gw_mac) &&
		EvpnTestHasRoute(fabric, EVPNTEST_FABRIC_RED, "fd10::/64", "127.0.0.1", EVPNTEST_VNI_RED, evpntest_gw_mac),
		"The fabric: 10.10.0.0/24 of red and of blue, each in its VRF on its VNI, and fd10::/64 of red, via the VTEP 127.0.0.1 of gw with its router MAC",
		"%s", "a route is missing or wrong");

	NodeBgpGetStatus(gw->Node, &bs);
	EvpnTestCheck(ctx, bs.NumRoutes == 0 && bs.NumErrors == 0, "gw installs no route of the fabric into the Windows routing table, and its sidecar refused nothing",
		"%u routes installed, %u errors", bs.NumRoutes, bs.NumErrors);
}

// Overlay to fabric: each packet of evpntest_out from the host of its node, as the harness VTEP takes it
static void EvpnTestIntoFabric(EVPNTEST_CTX *ctx)
{
	UCHAR d[VXLAN_MAX_DATAGRAM];
	char what[MAX_SIZE];

	Print("[overlay to fabric]\n");

	for (UINT k = 0;k < sizeof(evpntest_out) / sizeof(evpntest_out[0]);k++)
	{
		EVPNTEST_OUT *o = &evpntest_out[k];
		EVPNTEST_NODE *t = &ctx->Nodes[o->From];
		UCHAR packet[EVPNTEST_SIZE];
		UINT size = EvpnTestPacket(packet, o->Src, o->Dst, 100 + k);

		EvpnTestDrain(ctx);

		NodeReaderOnline(t->Node, &t->Reader);
		bool taken = (size != 0 && NodeOverlayInput(t->Node, o->VrfId, packet, size));
		NodeReaderOffline(&t->Reader);

		UINT got = EvpnTestTake(ctx, d, sizeof(d), o->Vni != 0 ? EVPNTEST_WAIT : EVPNTEST_QUIET);

		if (o->Vni != 0)
		{
			Format(what, sizeof(what), "%s, VRF %u: udp %s > %s goes to the fabric on VNI %u, from the router MAC of gw to the router MAC of the fabric, as it was sent",
				evpntest_names[o->From], o->VrfId, o->Src, o->Dst, o->Vni);
			EvpnTestCheck(ctx, taken && EvpnTestIsFrame(d, got, o->Vni, packet, size), what, "taken %u, the harness VTEP took %u bytes", (UINT)taken, got);
		}
		else
		{
			Format(what, sizeof(what), "%s, VRF %u: udp %s > %s, an address that no route holds, goes nowhere", evpntest_names[o->From], o->VrfId, o->Src, o->Dst);
			EvpnTestCheck(ctx, taken == false && got == 0, what, "taken %u, the harness VTEP took %u bytes", (UINT)taken, got);
		}
	}
}

// Fabric to overlay: each packet of evpntest_in from the harness VTEP, as the host of its node takes it
static void EvpnTestFromFabric(EVPNTEST_CTX *ctx)
{
	char what[MAX_SIZE];

	Print("[fabric to overlay]\n");

	for (UINT k = 0;k < sizeof(evpntest_in) / sizeof(evpntest_in[0]);k++)
	{
		EVPNTEST_IN *in = &evpntest_in[k];
		EVPNTEST_NODE *to = &ctx->Nodes[in->To];
		UCHAR packet[EVPNTEST_SIZE];
		UINT size = EvpnTestPacket(packet, in->Src, in->Dst, 200 + k);
		LONG arrivals = InterlockedCompareExchange(&to->Arrivals, 0, 0);

		bool sent = (size != 0 && EvpnTestInject(ctx, in->Vni, in->Mac, packet, size));
		bool arrived = sent && EvpnTestArrived(to, arrivals + 1, EVPNTEST_WAIT);
		bool same = false;

		AcquireSRWLockShared(&to->Lock);
		{
			same = (arrived && to->LastVrf == in->VrfId && to->LastSize == size && Cmp(to->Last, packet, size) == 0);
		}
		ReleaseSRWLockShared(&to->Lock);

		Format(what, sizeof(what), "VNI %u: udp %s > %s reaches the host of %s in VRF %u as it was sent", in->Vni, in->Src, in->Dst, evpntest_names[in->To], in->VrfId);
		EvpnTestCheck(ctx, same, what, "sent %u, arrived %u, VRF %u, %u bytes", (UINT)sent, (UINT)arrived, to->LastVrf, to->LastSize);
	}
}

// One packet of the guard from the harness VTEP, which no host takes and which the counter that get reads counts within
// EVPNTEST_WAIT
static void EvpnTestDrop(EVPNTEST_CTX *ctx, char *what, UINT vni, const UCHAR *mac, char *src, char *dst, UINT64 (*get)(const NODE_EVPN_STATUS *))
{
	EVPNTEST_NODE *gw = &ctx->Nodes[EVPNTEST_GW];
	EVPNTEST_NODE *peer = &ctx->Nodes[EVPNTEST_PEER];
	UCHAR packet[EVPNTEST_SIZE];
	NODE_EVPN_STATUS before, after;
	UINT size = EvpnTestPacket(packet, src, dst, 300);
	LONG gw_arrivals = InterlockedCompareExchange(&gw->Arrivals, 0, 0);
	LONG peer_arrivals = InterlockedCompareExchange(&peer->Arrivals, 0, 0);
	UINT64 end = Tick64() + EVPNTEST_WAIT;
	bool counted = false;

	NodeEvpnGetStatus(gw->Node, &before);
	bool sent = (size != 0 && EvpnTestInject(ctx, vni, mac, packet, size));

	while (sent && counted == false && Tick64() < end)
	{
		NodeEvpnGetStatus(gw->Node, &after);
		counted = (get(&after) == get(&before) + 1);
		if (counted == false)
		{
			SleepThread(EVPNTEST_POLL);
		}
	}

	bool quiet = (EvpnTestArrived(gw, gw_arrivals + 1, EVPNTEST_QUIET) == false && EvpnTestArrived(peer, peer_arrivals + 1, 0) == false);
	EvpnTestCheck(ctx, counted && quiet, what, "sent %u, counted %u, no host took it %u", (UINT)sent, (UINT)counted, (UINT)quiet);
}

static UINT64 EvpnTestUnknownVni(const NODE_EVPN_STATUS *st)
{
	return st->UnknownVni;
}

static UINT64 EvpnTestNotOurs(const NODE_EVPN_STATUS *st)
{
	return st->NotOurs;
}

static UINT64 EvpnTestStrangers(const NODE_EVPN_STATUS *st)
{
	return st->Strangers;
}

static UINT64 EvpnTestUndelivered(const NODE_EVPN_STATUS *st)
{
	return st->Undelivered;
}

// The guard of gw: what the fabric may not send is dropped and counted
static void EvpnTestGuard(EVPNTEST_CTX *ctx)
{
	Print("[the guard of gw]\n");

	EvpnTestDrop(ctx, "A datagram on VNI 999, of no EVPN VRF, is dropped and counted", EVPNTEST_OTHER_VNI, evpntest_gw_mac, "172.16.1.10", "10.10.0.1", EvpnTestUnknownVni);
	EvpnTestDrop(ctx, "A frame of red to another MAC address than the router MAC of gw is dropped and counted", EVPNTEST_VNI_RED, evpntest_other_mac, "172.16.1.10", "10.10.0.1", EvpnTestNotOurs);
	EvpnTestDrop(ctx, "A packet of red from 192.0.2.99, which the fabric did not announce, is dropped and counted", EVPNTEST_VNI_RED, evpntest_gw_mac, "192.0.2.99", "10.10.0.1", EvpnTestStrangers);
	EvpnTestDrop(ctx, "A packet of red to 10.10.0.9, an address of no route of red, is dropped and counted", EVPNTEST_VNI_RED, evpntest_gw_mac, "172.16.1.10", "10.10.0.9", EvpnTestUndelivered);
}

// A TCP segment of the host of peer in red from 10.10.0.2 port sport to 172.16.1.20 port dport with the flags flags, which gw
// forwards to the fabric, into packet: its size, and whether peer sent it
static UINT EvpnTestFromPeer(EVPNTEST_CTX *ctx, UCHAR *packet, UCHAR flags, USHORT sport, USHORT dport, UINT seq, bool *sent)
{
	EVPNTEST_NODE *peer = &ctx->Nodes[EVPNTEST_PEER];
	UINT size = EvpnTestSegment(packet, "10.10.0.2", "172.16.1.20", flags, sport, dport, seq);

	EvpnTestDrain(ctx);

	NodeReaderOnline(peer->Node, &peer->Reader);
	*sent = (size != 0 && NodeOverlayInput(peer->Node, EVPNTEST_RED, packet, size));
	NodeReaderOffline(&peer->Reader);

	return size;
}

// The session profile of peer and the Mirror of gw judge the packets of peer to the fabric as those of a peer to a LAN subnet
// behind a gateway: no-server drops the SYN-ACK of a server of peer, which neither the fabric nor the sensor takes, and the SYN
// of a client of peer goes to the fabric, and to the sensor as peer sent it
static void EvpnTestProfile(EVPNTEST_CTX *ctx)
{
	EVPNTEST_NODE *gw = &ctx->Nodes[EVPNTEST_GW];
	UCHAR d[VXLAN_MAX_DATAGRAM];
	UCHAR packet[EVPNTEST_SIZE];
	NODE_PROFILE_STATUS before, after;
	NODE_MIRROR_STATUS copies, copies_after;
	bool sent = false;

	Print("[the session profile of peer and the Mirror of gw]\n");

	NodeProfileGetStatus(gw->Node, &before);
	NodeMirrorGetStatus(gw->Node, &copies);

	UINT size = EvpnTestFromPeer(ctx, packet, TCP_SYN | TCP_ACK, EVPNTEST_WEB, EVPNTEST_CLIENT, 500, &sent);
	UINT64 end = Tick64() + EVPNTEST_WAIT;
	bool counted = false;

	while (sent && counted == false && Tick64() < end)
	{
		NodeProfileGetStatus(gw->Node, &after);
		counted = (after.Server == before.Server + 1);
		if (counted == false)
		{
			SleepThread(EVPNTEST_POLL);
		}
	}

	UINT got = EvpnTestTake(ctx, d, sizeof(d), EVPNTEST_QUIET);
	UINT copied = EvpnTestTakeFrom(ctx->Sensor, d, sizeof(d), 0);
	NodeMirrorGetStatus(gw->Node, &copies_after);
	EvpnTestCheck(ctx, size != 0 && counted && got == 0 && copied == 0 && copies_after.Copied == copies.Copied,
		"peer, VRF 101: no-server of the session profile of peer drops the SYN-ACK of tcp 10.10.0.2:80 > 172.16.1.20:5000 at gw, counted, and neither the fabric nor the sensor takes it",
		"sent %u, counted %u, the harness VTEP took %u bytes, the sensor %u bytes, %u copies", (UINT)sent, (UINT)counted, got, copied,
		(UINT)(copies_after.Copied - copies.Copied));

	size = EvpnTestFromPeer(ctx, packet, TCP_SYN, EVPNTEST_CLIENT, EVPNTEST_WEB, 501, &sent);
	got = EvpnTestTake(ctx, d, sizeof(d), EVPNTEST_WAIT);
	bool went = (sent && EvpnTestIsFrame(d, got, EVPNTEST_VNI_RED, packet, size));

	// The copy: the VXLAN header on the VNI of the VRF, the Ethernet header of the Mirror, and the packet as peer sent it
	copied = EvpnTestTakeFrom(ctx->Sensor, d, sizeof(d), EVPNTEST_WAIT);
	bool copy = (copied == VXLAN_HEADER_SIZE + NODE_MIRROR_ETHER + size && d[0] == VXLAN_FLAG_VNI &&
		(((UINT)d[4] << 16) | ((UINT)d[5] << 8) | d[6]) == EVPNTEST_RED && Cmp(d + VXLAN_HEADER_SIZE + NODE_MIRROR_ETHER, packet, size) == 0);
	EvpnTestCheck(ctx, went && copy,
		"peer, VRF 101: the SYN of tcp 10.10.0.2:5000 > 172.16.1.20:80 goes to the fabric on VNI 10101, and the Mirror of gw copies it to the sensor on VNI 101 as peer sent it",
		"sent %u, to the fabric %u (%u bytes), copied %u (%u bytes)", (UINT)sent, (UINT)went, got, (UINT)copy, copied);
}

// Overlap: the fabric withdraws 172.16.1.0/24 of its red; red at gw loses it, blue keeps it
static void EvpnTestOverlap(EVPNTEST_CTX *ctx)
{
	EVPNTEST_NODE *gw = &ctx->Nodes[EVPNTEST_GW];
	EVPNTEST_NODE *fabric = &ctx->Nodes[EVPNTEST_FABRIC];
	UCHAR d[VXLAN_MAX_DATAGRAM];
	UCHAR packet[EVPNTEST_SIZE];
	NODE_EVPN_STATUS st;

	Print("[two VRFs of one prefix: the fabric withdraws it in red]\n");

	bool withdrawn = NodeBgpWithdrawVrf(fabric->Node, EVPNTEST_FABRIC_RED, "172.16.1.0/24");
	bool gone = withdrawn && EvpnTestWaitRoutes(gw, 2);
	EvpnTestCheck(ctx, gone && EvpnTestHasRoute(gw, EVPNTEST_RED, "172.16.1.0/24", "127.0.0.2", EVPNTEST_VNI_RED, evpntest_fabric_mac) == false &&
		EvpnTestHasRoute(gw, EVPNTEST_BLUE, "172.16.1.0/24", "127.0.0.2", EVPNTEST_VNI_BLUE, evpntest_fabric_mac),
		"The fabric withdraws 172.16.1.0/24 of its red: gw loses it in red and keeps it in blue", "withdrawn %u, gone %u", (UINT)withdrawn, (UINT)gone);

	UINT size = EvpnTestPacket(packet, "10.10.0.1", "172.16.1.10", 400);
	EvpnTestDrain(ctx);
	NodeReaderOnline(gw->Node, &gw->Reader);
	bool red = NodeOverlayInput(gw->Node, EVPNTEST_RED, packet, size);
	NodeReaderOffline(&gw->Reader);
	UINT got = EvpnTestTake(ctx, d, sizeof(d), EVPNTEST_QUIET);
	EvpnTestCheck(ctx, red == false && got == 0, "gw, VRF 101: udp 10.10.0.1 > 172.16.1.10 goes nowhere now", "taken %u, the harness VTEP took %u bytes", (UINT)red, got);

	NodeReaderOnline(gw->Node, &gw->Reader);
	bool blue = NodeOverlayInput(gw->Node, EVPNTEST_BLUE, packet, size);
	NodeReaderOffline(&gw->Reader);
	got = EvpnTestTake(ctx, d, sizeof(d), EVPNTEST_WAIT);
	EvpnTestCheck(ctx, blue && EvpnTestIsFrame(d, got, EVPNTEST_VNI_BLUE, packet, size), "gw, VRF 102: the same packet still goes to the fabric on VNI 10102",
		"taken %u, the harness VTEP took %u bytes", (UINT)blue, got);

	// Six packets went to the fabric, the SYN of peer among them, and four came from it; the guard dropped one of each kind
	NodeEvpnGetStatus(gw->Node, &st);
	Print("  [INFO] gw: sent %I64u, failed %I64u, delivered %I64u, undelivered %I64u, strangers %I64u, not ours %I64u, unknown VNI %I64u, malformed %I64u\n",
		st.Sent, st.Failed, st.Delivered, st.Undelivered, st.Strangers, st.NotOurs, st.UnknownVni, st.Malformed);
	EvpnTestCheck(ctx, st.Sent == 6 && st.Failed == 0 && st.Delivered == 4 && st.Undelivered == 1 && st.Strangers == 1 && st.NotOurs == 1 && st.UnknownVni == 1 && st.Malformed == 0,
		"The counters of the EVPN of gw: 6 packets to the fabric, 4 from it, one drop of each kind of the guard", "%s", "see the line above");
}

// One packet of each of the num cases, from the host of its node in red (SDN-25-R2, #550): it goes to the fabric on its VNI as
// it was sent; or to peer, the exit of red, whose host takes it as it was sent, and not to the fabric; or not to the fabric.
// The data of the packet of case k is seq + k.
static void EvpnTestExitCases(EVPNTEST_CTX *ctx, EVPNTEST_EXIT *cases, UINT num, UINT seq)
{
	EVPNTEST_NODE *peer = &ctx->Nodes[EVPNTEST_PEER];
	UCHAR d[VXLAN_MAX_DATAGRAM];
	char what[MAX_SIZE];

	for (UINT k = 0;k < num;k++)
	{
		EVPNTEST_EXIT *c = &cases[k];
		EVPNTEST_NODE *t = &ctx->Nodes[c->From];
		UCHAR packet[EVPNTEST_SIZE];
		UINT size = EvpnTestPacket(packet, c->Src, c->Dst, seq + k);
		LONG arrivals = InterlockedCompareExchange(&peer->Arrivals, 0, 0);

		EvpnTestDrain(ctx);

		NodeReaderOnline(t->Node, &t->Reader);
		bool taken = (size != 0 && NodeOverlayInput(t->Node, EVPNTEST_RED, packet, size));
		NodeReaderOffline(&t->Reader);

		bool arrived = (c->Exit && taken && EvpnTestArrived(peer, arrivals + 1, EVPNTEST_WAIT));
		UINT got = EvpnTestTake(ctx, d, sizeof(d), c->Vni != 0 ? EVPNTEST_WAIT : EVPNTEST_QUIET);
		bool same = false;

		AcquireSRWLockShared(&peer->Lock);
		{
			same = (arrived && peer->LastVrf == EVPNTEST_RED && peer->LastSize == size && Cmp(peer->Last, packet, size) == 0);
		}
		ReleaseSRWLockShared(&peer->Lock);

		if (c->Vni != 0)
		{
			Format(what, sizeof(what), "%s, VRF 101: udp %s > %s goes to the fabric on VNI %u as it was sent: %s", evpntest_names[c->From], c->Src, c->Dst, c->Vni, c->Why);
			EvpnTestCheck(ctx, taken && EvpnTestIsFrame(d, got, c->Vni, packet, size), what, "taken %u, the harness VTEP took %u bytes", (UINT)taken, got);
		}
		else if (c->Exit)
		{
			Format(what, sizeof(what), "%s, VRF 101: udp %s > %s goes to peer, the exit of red, whose host takes it as it was sent, and not to the fabric: %s",
				evpntest_names[c->From], c->Src, c->Dst, c->Why);
			EvpnTestCheck(ctx, same && got == 0, what, "taken %u, arrived %u, VRF %u, %u bytes, the harness VTEP took %u bytes", (UINT)taken, (UINT)arrived, peer->LastVrf,
				peer->LastSize, got);
		}
		else
		{
			Format(what, sizeof(what), "%s, VRF 101: udp %s > %s does not go to the fabric: %s", evpntest_names[c->From], c->Src, c->Dst, c->Why);
			EvpnTestCheck(ctx, taken && got == 0, what, "taken %u, the harness VTEP took %u bytes", (UINT)taken, got);
		}
	}
}

// A VRF with an internet exit (SDN-25-R2, #550): a route of the fabric wins over the default route of red, and of two default
// routes the one of red wins; once red has no exit again, the default routes of the fabric take what no route of red holds
static void EvpnTestExit(EVPNTEST_CTX *ctx)
{
	EVPNTEST_NODE *gw = &ctx->Nodes[EVPNTEST_GW];
	EVPNTEST_NODE *fabric = &ctx->Nodes[EVPNTEST_FABRIC];
	NODE_EVPN_STATUS before, after;

	Print("[a VRF with an internet exit: the routes of the fabric and the default routes]\n");

	NodeEvpnGetStatus(gw->Node, &before);

	// The route of red that the fabric withdrew in the case before comes back, and peer becomes the exit of red
	bool again = NodeBgpAnnounceVrf(fabric->Node, EVPNTEST_FABRIC_RED, "172.16.1.0/24") && EvpnTestWaitRoutes(gw, 3);
	EvpnTestCheck(ctx, again && EvpnTestHasRoute(gw, EVPNTEST_RED, "172.16.1.0/24", "127.0.0.2", EVPNTEST_VNI_RED, evpntest_fabric_mac),
		"The fabric announces 172.16.1.0/24 of its red again: gw holds it in red again", "announced and learned %u", (UINT)again);

	bool applied = EvpnTestApply(ctx, 2, true) && EvpnTestWaitLinks(ctx, 2);
	EvpnTestCheck(ctx, applied, "Generation 2: peer is the internet exit of red, and the state of gw routes 0.0.0.0/0 and ::/0 of red to peer", "%s",
		"not applied, or the session is down");
	EvpnTestExitCases(ctx, evpntest_exit, sizeof(evpntest_exit) / sizeof(evpntest_exit[0]), 600);

	// Two default routes: the fabric announces its own of red
	bool defaults = NodeBgpAnnounceVrf(fabric->Node, EVPNTEST_FABRIC_RED, "0.0.0.0/0") && NodeBgpAnnounceVrf(fabric->Node, EVPNTEST_FABRIC_RED, "::/0") &&
		EvpnTestWaitRoutes(gw, 5);
	EvpnTestCheck(ctx, defaults && EvpnTestHasRoute(gw, EVPNTEST_RED, "0.0.0.0/0", "127.0.0.2", EVPNTEST_VNI_RED, evpntest_fabric_mac) &&
		EvpnTestHasRoute(gw, EVPNTEST_RED, "::/0", "127.0.0.2", EVPNTEST_VNI_RED, evpntest_fabric_mac),
		"The fabric announces 0.0.0.0/0 and ::/0 of its red: gw holds both in red, via the VTEP 127.0.0.2 on VNI 10101", "announced and learned %u", (UINT)defaults);
	EvpnTestExitCases(ctx, evpntest_defaults, sizeof(evpntest_defaults) / sizeof(evpntest_defaults[0]), 700);

	// No exit: red as in Generation 1, whose packets to an address of no route of red the default routes of the fabric take
	applied = EvpnTestApply(ctx, 3, false) && EvpnTestWaitLinks(ctx, 3);
	EvpnTestCheck(ctx, applied, "Generation 3: red has no internet exit again, and the state of gw no default route of red", "%s", "not applied, or the session is down");
	EvpnTestExitCases(ctx, evpntest_no_exit, sizeof(evpntest_no_exit) / sizeof(evpntest_no_exit[0]), 800);

	// Eight packets of these cases went to the fabric, and no send failed
	NodeEvpnGetStatus(gw->Node, &after);
	EvpnTestCheck(ctx, after.Sent == before.Sent + 8 && after.Failed == before.Failed, "The counters of the EVPN of gw: 8 more packets to the fabric, none failed",
		"sent %I64u and failed %I64u before, sent %I64u and failed %I64u after", before.Sent, before.Failed, after.Sent, after.Failed);
}

// evpn: the EVPN of a gateway against a fabric
RANZ_TEST("evpn", evpn_test, "EVPN gateway: a node hands two VRFs of the overlay with the same prefixes to a fabric as EVPN type-5 routes through ranz bgp (ranz.exe next to vpntest), and both ways of VXLAN reach the hosts of the overlay and the VTEP of the fabric in the VRF of their VNI; in a VRF with an internet exit a route of the fabric wins over its default route, and of two default routes the one of the VRF wins.");
void evpn_test(UINT num, char **arg)
{
	EVPNTEST_CTX *ctx = ZeroMalloc(sizeof(EVPNTEST_CTX));
	HANDLE done = CreateEventW(NULL, TRUE, FALSE, NULL);
	HANDLE watchdog = (done != NULL ? CreateThread(NULL, 0, EvpnTestWatchdog, done, 0, NULL) : NULL);
	TRANSPORT *loopback = TransportLoopbackNew("loopback", 0, false);

	Print("EVPN test: a gateway hands two VRFs of one prefix to a fabric as EVPN type-5 routes, and VXLAN carries their packets both ways\n");

	ctx->Vtep = INVALID_SOCKET;
	ctx->Sensor = INVALID_SOCKET;

	if (EvpnTestOpen(ctx, loopback))
	{
		EvpnTestRoutes(ctx);
		EvpnTestIntoFabric(ctx);
		EvpnTestFromFabric(ctx);
		EvpnTestGuard(ctx);
		EvpnTestProfile(ctx);
		EvpnTestOverlap(ctx);
		EvpnTestExit(ctx);
	}

	EvpnTestClose(ctx);
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
		Print("EVPN TEST OK\n");
	}
	else
	{
		Print("EVPN TEST FAILED (%u of %u checks failed)\n", ctx->NumFailed, ctx->NumChecks);
	}

	Free(ctx);
}
