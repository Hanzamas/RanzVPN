// mirrortest.c
// Named Mirror test of vpntest ("mirror" command, SDN-23 #199)
//
// The Mirrors of a node (Cedar/NodeMirror.c) on the overlay of two in-process nodes, as seam 2 of #45 runs the data
// plane: fake adapters stand in for the hosts of node-a and node-b, the in-process loopback transport carries the
// Noise session between them, and the test applies their desired states itself (NodeOverlayApply). node-a applies
// three Mirrors, each to a harness sensor: a UDP socket of this file on 127.0.0.1 that reads the VXLAN datagrams of
// node-a byte for byte.
// - dns: UDP to or from port 53 in VRF red, to sensor 1, on the VNI of the VRF id (101);
// - ping: ICMP and ICMPv6 in VRF blue, to sensor 2, on VNI 4242;
// - load: TCP to or from port 8080 in VRF red, to sensor 3, on VNI 7, at most 1 Mbit/s.
// - Matching: packets of node-a's host to node-b, and of node-b's host that node-a delivers, IPv4 and IPv6, one
//   behind a hop-by-hop options header: each arrives at its sensor as the golden datagram, the VXLAN header with the
//   I flag and the VNI, the Ethernet header of the way it went and the identical IP packet, and at the other host.
// - Not matching: another protocol, another port, another VRF, a fragment after the first of a datagram to port 53,
//   and a packet that the overlay does not forward: no sensor reads anything, and node-a counts no copy.
// - Load: node-a's host sends TCP to port 8080 as fast as it can for a second, far above the rate limit of the load
//   Mirror: sensor 3 reads at most the burst and the rate times the span of the load, a good part of it, and every
//   packet is either copied or counted as limited.
// Print "MIRROR TEST OK" only when every check passes.

#include "testlist.h"

#include "Cedar/ConfigStore.h"
#include "Cedar/Node.h"

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

#define	MIRRORTEST_BUDGET		120000		// The whole test ends within this time, or the watchdog ends the process (ms)
#define	MIRRORTEST_BOUND		10000		// A bounded wait on observable state (ms)
#define	MIRRORTEST_TIMEOUT		5000		// A copy arrives at its sensor within this time (ms)
#define	MIRRORTEST_QUIET		300			// A sensor that gets nothing gets nothing within this time (ms)
#define	MIRRORTEST_POLL			10			// Poll interval of observable state (ms)
#define	MIRRORTEST_RCVBUF		(4 * 1024 * 1024)	// The receive buffer of a sensor: every copy of the load fits in it
#define	MIRRORTEST_SIZE			100			// The size of a test packet
#define	MIRRORTEST_LOAD_SIZE	1000		// The size of a packet of the load
#define	MIRRORTEST_LOAD_TIME	1000		// The load runs this long (ms)
#define	MIRRORTEST_LOAD_RATE	1000000		// The rate limit of the load Mirror in bits per second
#define	MIRRORTEST_VNI_PING		4242		// The VNI of the ping Mirror (0x001092)
#define	MIRRORTEST_VNI_LOAD		7			// The VNI of the load Mirror
#define	MIRRORTEST_NUM_SENSORS	3			// Sensors 1 to 3

// The nodes and the VRFs
#define	MIRRORTEST_A			0
#define	MIRRORTEST_B			1
#define	MIRRORTEST_RED			0
#define	MIRRORTEST_BLUE			1

static char *mirrortest_names[2] = {"node-a", "node-b"};
static UINT mirrortest_vrf_ids[2] = {101, 202};
static char *mirrortest_vrf_names[2] = {"red", "blue"};

// The addresses of each node in red and in blue, IPv4 and IPv6
static char *mirrortest_addrs[2][4] =
{
	{"10.0.0.1", "fd00::1", "10.1.0.1", "fd01::1"},
	{"10.0.0.2", "fd00::2", "10.1.0.2", "fd01::2"},
};

// How a test packet is built
#define	MIRRORTEST_PLAIN		0			// As it is
#define	MIRRORTEST_HOP			1			// IPv6: a hop-by-hop options header in front of the upper layer
#define	MIRRORTEST_FRAGMENT		2			// IPv4: a fragment after the first of its datagram

// The Ethernet headers of the copies: of a packet of node-a's host, and of a packet that node-a delivers to its host
static const UCHAR mirrortest_eth_out[12] = {0x02, 0x52, 0x5A, 0x00, 0x00, 0x02, 0x02, 0x52, 0x5A, 0x00, 0x00, 0x01};
static const UCHAR mirrortest_eth_in[12] = {0x02, 0x52, 0x5A, 0x00, 0x00, 0x01, 0x02, 0x52, 0x5A, 0x00, 0x00, 0x02};

// One packet of the matching and not matching cases: the node whose host sends it, its VRF, its ends, its protocol
// (ICMP is ICMPv6 for IPv6) and ports, how it is built, the sensor that reads its copy (0 for none) and the VNI of the
// copy, and whether the overlay forwards it
typedef struct MIRRORTEST_SEND
{
	UINT From;
	UINT Vrf;
	char *Src;
	char *Dst;
	UINT Protocol;
	UINT SrcPort;
	UINT DstPort;
	UINT Shape;
	UINT Sensor;
	UINT Vni;
	bool Forwarded;
	char *What;
} MIRRORTEST_SEND;

static MIRRORTEST_SEND mirrortest_matching[] =
{
	{MIRRORTEST_A, MIRRORTEST_RED, "10.0.0.1", "10.0.0.2", IP_PROTO_UDP, 5000, 53, MIRRORTEST_PLAIN, 1, 101, true, "a DNS query of node-a's host in red"},
	{MIRRORTEST_B, MIRRORTEST_RED, "10.0.0.2", "10.0.0.1", IP_PROTO_UDP, 53, 5000, MIRRORTEST_PLAIN, 1, 101, true, "the answer of node-b's host, which node-a delivers"},
	{MIRRORTEST_A, MIRRORTEST_RED, "fd00::1", "fd00::2", IP_PROTO_UDP, 5001, 53, MIRRORTEST_PLAIN, 1, 101, true, "a DNS query over IPv6"},
	{MIRRORTEST_A, MIRRORTEST_RED, "fd00::1", "fd00::2", IP_PROTO_UDP, 5002, 53, MIRRORTEST_HOP, 1, 101, true, "a DNS query over IPv6 behind a hop-by-hop options header"},
	{MIRRORTEST_A, MIRRORTEST_BLUE, "10.1.0.1", "10.1.0.2", IP_PROTO_ICMPV4, 0, 0, MIRRORTEST_PLAIN, 2, MIRRORTEST_VNI_PING, true, "an ICMP echo request in blue"},
	{MIRRORTEST_B, MIRRORTEST_BLUE, "10.1.0.2", "10.1.0.1", IP_PROTO_ICMPV4, 0, 0, MIRRORTEST_PLAIN, 2, MIRRORTEST_VNI_PING, true, "an ICMP echo request of node-b's host in blue, which node-a delivers"},
	{MIRRORTEST_A, MIRRORTEST_BLUE, "fd01::1", "fd01::2", IP_PROTO_ICMPV4, 0, 0, MIRRORTEST_PLAIN, 2, MIRRORTEST_VNI_PING, true, "an ICMPv6 echo request in blue, which the Mirror of ICMP takes"},
};

static MIRRORTEST_SEND mirrortest_other[] =
{
	{MIRRORTEST_A, MIRRORTEST_RED, "10.0.0.1", "10.0.0.2", IP_PROTO_TCP, 5000, 53, MIRRORTEST_PLAIN, 0, 0, true, "TCP to port 53 in red"},
	{MIRRORTEST_A, MIRRORTEST_RED, "10.0.0.1", "10.0.0.2", IP_PROTO_UDP, 5000, 54, MIRRORTEST_PLAIN, 0, 0, true, "UDP to port 54 in red"},
	{MIRRORTEST_A, MIRRORTEST_BLUE, "10.1.0.1", "10.1.0.2", IP_PROTO_UDP, 5000, 53, MIRRORTEST_PLAIN, 0, 0, true, "UDP to port 53 in blue"},
	{MIRRORTEST_A, MIRRORTEST_RED, "10.0.0.1", "10.0.0.2", IP_PROTO_ICMPV4, 0, 0, MIRRORTEST_PLAIN, 0, 0, true, "an ICMP echo request in red"},
	{MIRRORTEST_B, MIRRORTEST_RED, "fd00::2", "fd00::1", IP_PROTO_TCP, 8081, 40000, MIRRORTEST_PLAIN, 0, 0, true, "TCP from port 8081 of node-b's host in red"},
	{MIRRORTEST_A, MIRRORTEST_RED, "10.0.0.1", "10.0.0.2", IP_PROTO_UDP, 5000, 53, MIRRORTEST_FRAGMENT, 0, 0, true, "a fragment after the first of a datagram to port 53, which holds no ports"},
	{MIRRORTEST_A, MIRRORTEST_RED, "10.0.0.1", "10.0.0.9", IP_PROTO_UDP, 5000, 53, MIRRORTEST_PLAIN, 0, 0, false, "a DNS query to an address of no node, which the overlay does not send"},
};

// A sensor: a UDP socket on 127.0.0.1
typedef struct MIRRORTEST_SENSOR
{
	SOCKET Socket;
	USHORT Port;
} MIRRORTEST_SENSOR;

// One node and the fake adapter of its host
typedef struct MIRRORTEST_NODE
{
	wchar_t Dir[MAX_PATH];				// Its data directory
	PEER_KEY Key;						// Its static key
	NODE *Node;
	NODE_READER Reader;					// The test thread as a reader of the node's tables, online while it sends
	volatile LONG Arrivals;				// Packets that the host took
} MIRRORTEST_NODE;

// The load: node-a's host sends TCP to port 8080 in red
typedef struct MIRRORTEST_LOAD
{
	NODE *Node;
	UINT64 Start;						// The performance counter before the first packet ...
	UINT64 End;							// ... and after the last
	UINT Sent;							// Packets that the overlay took
	UINT Refused;						// ... and that it did not
} MIRRORTEST_LOAD;

// The test
typedef struct MIRRORTEST_CTX
{
	UINT NumChecks;
	UINT NumFailed;
	MIRRORTEST_NODE Nodes[2];
	MIRRORTEST_SENSOR Sensors[MIRRORTEST_NUM_SENSORS + 1];	// Sensors 1 to 3; 0 unused
	UCHAR Datagram[VXLAN_MAX_DATAGRAM + 1];					// The datagram that a sensor read
	UCHAR Want[VXLAN_MAX_DATAGRAM];							// The datagram that it must read
} MIRRORTEST_CTX;

static bool MirrorTestCheck(MIRRORTEST_CTX *ctx, bool ok, char *what, char *fmt, ...) RANZ_PRINTF_FORMAT(4, 5);
static bool MirrorTestCheck(MIRRORTEST_CTX *ctx, bool ok, char *what, char *fmt, ...)
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

// The watchdog: a native thread that ends a run that hangs, so that a lost copy is a failed test instead of a hung CI
// step
static DWORD WINAPI MirrorTestWatchdog(LPVOID param)
{
	char msg[MAX_SIZE];
	DWORD written = 0;

	if (WaitForSingleObject((HANDLE)param, MIRRORTEST_BUDGET) != WAIT_TIMEOUT)
	{
		return 0;
	}

	int len = snprintf(msg, sizeof(msg), "MIRROR TEST FAILED (did not finish within %u ms)\n", MIRRORTEST_BUDGET);
	if (len > 0)
	{
		WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), msg, (DWORD)MIN((UINT)len, (UINT)sizeof(msg) - 1), &written, NULL);
	}

	TerminateProcess(GetCurrentProcess(), 1);

	return 0;
}

// The address of a text into addr: 4 bytes for IPv4, 16 for IPv6, and their number; 0 for no address
static UINT MirrorTestAddress(UCHAR *addr, char *str)
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

// A test packet from src to dst, both IPv4 or both IPv6, of size bytes (at least its headers and 4 bytes of data) in
// buf: UDP or TCP between the ports sport and dport, or an ICMP echo request, ICMPv6 for IPv6; the data begins with
// seq. A TCP segment carries ACK alone, so that no MSS clamp changes it. Its size, 0 when the two are not of one family.
static UINT MirrorTestPacket(UCHAR *buf, UINT buf_size, char *src, char *dst, UINT protocol, UINT sport, UINT dport, UINT shape, UINT size, UINT seq)
{
	UCHAR s[16], d[16];
	UINT s_size = MirrorTestAddress(s, src);
	UINT d_size = MirrorTestAddress(d, dst);
	UINT ip = (s_size == 4 ? 20 : 40 + (shape == MIRRORTEST_HOP ? 8 : 0));
	UINT l4 = (protocol == IP_PROTO_TCP ? 20 : 8);
	UINT next = (protocol == IP_PROTO_ICMPV4 && s_size == 16 ? IP_PROTO_ICMPV6 : protocol);

	size = MAX(size, ip + l4 + 4);
	if (s_size == 0 || s_size != d_size || size > buf_size)
	{
		return 0;
	}

	Zero(buf, size);
	if (s_size == 4)
	{
		buf[0] = 0x45;
		WRITE_USHORT(buf + 2, size);
		if (shape == MIRRORTEST_FRAGMENT)
		{
			// Fragment offset 185, 1480 bytes into its datagram
			WRITE_USHORT(buf + 6, 185);
		}
		buf[8] = 64;
		buf[9] = (UCHAR)next;
		Copy(buf + 12, s, 4);
		Copy(buf + 16, d, 4);
		USHORT sum = IpChecksum(buf, 20);
		Copy(buf + 10, &sum, 2);
	}
	else
	{
		buf[0] = 0x60;
		WRITE_USHORT(buf + 4, size - 40);
		buf[6] = (UCHAR)(shape == MIRRORTEST_HOP ? IPV6_HEADER_HOP : next);
		buf[7] = 64;
		Copy(buf + 8, s, 16);
		Copy(buf + 24, d, 16);
		if (shape == MIRRORTEST_HOP)
		{
			// The next header, a length of 8 bytes, and a PadN option of 4 bytes
			buf[40] = (UCHAR)next;
			buf[42] = 1;
			buf[43] = 4;
		}
	}

	UCHAR *l = buf + ip;
	if (protocol == IP_PROTO_UDP || protocol == IP_PROTO_TCP)
	{
		WRITE_USHORT(l, sport);
		WRITE_USHORT(l + 2, dport);
		if (protocol == IP_PROTO_UDP)
		{
			WRITE_USHORT(l + 4, size - ip);
		}
		else
		{
			l[12] = 0x50;
			l[13] = 0x10;
		}
	}
	else
	{
		l[0] = (UCHAR)(s_size == 4 ? 8 : 128);
	}

	WRITE_UINT(l + l4, seq);
	for (UINT i = ip + l4 + 4;i < size;i++)
	{
		buf[i] = (UCHAR)(i * 7 + seq);
	}

	return size;
}

// The datagram that a sensor must read for the copy of packet, of size bytes, on vni: the VXLAN header with the I
// flag, then the Ethernet header of the way the packet went, the EtherType of its IP version and the identical packet.
// Its size.
static UINT MirrorTestGolden(UCHAR *want, UINT vni, bool out, const UCHAR *packet, UINT size)
{
	Zero(want, VXLAN_HEADER_SIZE);
	want[0] = 0x08;
	want[4] = (UCHAR)(vni >> 16);
	want[5] = (UCHAR)(vni >> 8);
	want[6] = (UCHAR)vni;
	Copy(want + VXLAN_HEADER_SIZE, out ? mirrortest_eth_out : mirrortest_eth_in, 12);
	WRITE_USHORT(want + VXLAN_HEADER_SIZE + 12, (packet[0] >> 4) == 4 ? MAC_PROTO_IPV4 : MAC_PROTO_IPV6);
	Copy(want + VXLAN_HEADER_SIZE + NODE_MIRROR_ETHER, packet, size);

	return VXLAN_HEADER_SIZE + NODE_MIRROR_ETHER + size;
}

//
// The sensors
//

// Open a sensor: a UDP socket on 127.0.0.1 and a port that the system picks, with a receive buffer for the load
static bool MirrorTestOpenSensor(MIRRORTEST_SENSOR *t)
{
	struct sockaddr_in sa;
	int sa_size = sizeof(sa);
	int rcvbuf = MIRRORTEST_RCVBUF;

	t->Socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (t->Socket == INVALID_SOCKET)
	{
		return false;
	}

	setsockopt(t->Socket, SOL_SOCKET, SO_RCVBUF, (char *)&rcvbuf, sizeof(rcvbuf));

	Zero(&sa, sizeof(sa));
	sa.sin_family = AF_INET;
	sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	if (bind(t->Socket, (struct sockaddr *)&sa, sizeof(sa)) != 0 || getsockname(t->Socket, (struct sockaddr *)&sa, &sa_size) != 0)
	{
		return false;
	}

	t->Port = ntohs(sa.sin_port);

	return true;
}

// The next datagram that the sensor t reads within timeout, into the datagram of the test: its size, 0 for none
static UINT MirrorTestRead(MIRRORTEST_CTX *ctx, MIRRORTEST_SENSOR *t, UINT timeout)
{
	WSAPOLLFD p;

	Zero(&p, sizeof(p));
	p.fd = t->Socket;
	p.events = POLLRDNORM;
	if (WSAPoll(&p, 1, (INT)timeout) != 1)
	{
		return 0;
	}

	int n = recv(t->Socket, (char *)ctx->Datagram, (int)sizeof(ctx->Datagram), 0);

	return (n > 0 ? (UINT)n : 0);
}

// The sensors that read something within MIRRORTEST_QUIET, as a bit mask: 0 when none does
static UINT MirrorTestNoisy(MIRRORTEST_CTX *ctx)
{
	UINT noisy = 0;

	for (UINT i = 1;i <= MIRRORTEST_NUM_SENSORS;i++)
	{
		if (MirrorTestRead(ctx, &ctx->Sensors[i], MIRRORTEST_QUIET) != 0)
		{
			noisy |= (1 << i);
		}
	}

	return noisy;
}

//
// The nodes
//

// A new empty data directory under the temp directory of the process, with a configuration store that runs no role
// on one worker
static void MirrorTestNewDir(wchar_t *dir, UINT size, char *name)
{
	wchar_t tmp[MAX_PATH];
	wchar_t path[MAX_PATH];

	UniFormat(tmp, sizeof(tmp), L"mirrortest_%S_%u", name, Rand32());
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
static void MirrorTestDeleteFiles(wchar_t *dir)
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

// The fake adapter of a host: it counts the packets that the host takes
static void MirrorTestAdapter(NODE *n, void *param, UINT vrf_id, const UCHAR *packet, UINT size)
{
	MIRRORTEST_NODE *t = (MIRRORTEST_NODE *)param;

	InterlockedIncrement(&t->Arrivals);
}

// The addresses of node i into a: its addresses in red and blue, IPv4 and IPv6
static UINT MirrorTestAddresses(UINT i, CONTROL_ADDRESS *a)
{
	for (UINT k = 0;k < 4;k++)
	{
		UINT vrf = (k < 2 ? MIRRORTEST_RED : MIRRORTEST_BLUE);

		Zero(&a[k], sizeof(CONTROL_ADDRESS));
		StrCpy(a[k].Network, sizeof(a[k].Network), mirrortest_vrf_names[vrf]);
		a[k].VrfId = mirrortest_vrf_ids[vrf];
		a[k].AddressSize = MirrorTestAddress(a[k].Address, mirrortest_addrs[i][k]);
		a[k].Length = (a[k].AddressSize == 4 ? 24 : 64);
	}

	return 4;
}

// One Mirror of node-a into m: its name, VRF, protocol, port, sensor, VNI and rate limit
static void MirrorTestMirror(CONTROL_MIRROR *m, char *name, UINT vrf, UINT protocol, UINT port, MIRRORTEST_SENSOR *sensor, UINT vni, UINT64 rate)
{
	Zero(m, sizeof(CONTROL_MIRROR));
	StrCpy(m->Name, sizeof(m->Name), name);
	m->VrfId = mirrortest_vrf_ids[vrf];
	m->Protocol = protocol;
	m->Port = port;
	m->SensorSize = MirrorTestAddress(m->Sensor, "127.0.0.1");
	m->SensorPort = sensor->Port;
	m->Vni = vni;
	m->RateLimit = rate;
}

// Apply the state of node i at Generation 1: its addresses, the other node as its peer in red and blue, and for
// node-a the three Mirrors
static bool MirrorTestApply(MIRRORTEST_CTX *ctx, UINT i)
{
	CONTROL_STATE *st = ZeroMalloc(sizeof(CONTROL_STATE));
	UINT j = 1 - i;

	st->Generation = 1;
	StrCpy(st->Name, sizeof(st->Name), mirrortest_names[i]);
	st->NumAddresses = MirrorTestAddresses(i, st->Addresses);

	st->Peers = ZeroMalloc(sizeof(CONTROL_PEER));
	st->NumPeers = 1;
	StrCpy(st->Peers[0].Name, sizeof(st->Peers[0].Name), mirrortest_names[j]);
	Copy(st->Peers[0].Key, ctx->Nodes[j].Key.Public, PEER_KEY_SIZE);
	st->Peers[0].NumVrfs = 2;
	st->Peers[0].VrfIds[0] = mirrortest_vrf_ids[MIRRORTEST_RED];
	st->Peers[0].VrfIds[1] = mirrortest_vrf_ids[MIRRORTEST_BLUE];
	st->Peers[0].NumAddresses = MirrorTestAddresses(j, st->Peers[0].Addresses);

	if (i == MIRRORTEST_A)
	{
		MirrorTestMirror(&st->Mirrors[0], "dns", MIRRORTEST_RED, IP_PROTO_UDP, 53, &ctx->Sensors[1], 0, 0);
		MirrorTestMirror(&st->Mirrors[1], "load", MIRRORTEST_RED, IP_PROTO_TCP, 8080, &ctx->Sensors[3], MIRRORTEST_VNI_LOAD, MIRRORTEST_LOAD_RATE);
		MirrorTestMirror(&st->Mirrors[2], "ping", MIRRORTEST_BLUE, IP_PROTO_ICMPV4, 0, &ctx->Sensors[2], MIRRORTEST_VNI_PING, 0);
		st->NumMirrors = 3;
	}

	bool ok = NodeOverlayApply(ctx->Nodes[i].Node, st);

	Free(st->Peers);
	Free(st);

	return ok;
}

// Whether each node has its session to the other within MIRRORTEST_BOUND
static bool MirrorTestWaitLinks(MIRRORTEST_CTX *ctx)
{
	UINT64 end = Tick64() + MIRRORTEST_BOUND;

	while (true)
	{
		NODE_OVERLAY_STATUS a, b;

		NodeOverlayGetStatus(ctx->Nodes[MIRRORTEST_A].Node, &a);
		NodeOverlayGetStatus(ctx->Nodes[MIRRORTEST_B].Node, &b);
		if (a.NumLinks == 1 && b.NumLinks == 1)
		{
			return true;
		}
		if (Tick64() >= end)
		{
			return false;
		}
		SleepThread(MIRRORTEST_POLL);
	}
}

// Whether the host of node t took at least target packets within MIRRORTEST_BOUND
static bool MirrorTestArrived(MIRRORTEST_NODE *t, LONG target)
{
	UINT64 end = Tick64() + MIRRORTEST_BOUND;

	while (InterlockedCompareExchange(&t->Arrivals, 0, 0) < target)
	{
		if (Tick64() >= end)
		{
			return false;
		}
		SleepThread(MIRRORTEST_POLL);
	}

	return true;
}

// The host of the node of s sends the packet of s, with data seq, as an online reader of its tables; the packet and
// its size into packet and *size. Whether the overlay took it.
static bool MirrorTestSend(MIRRORTEST_CTX *ctx, MIRRORTEST_SEND *s, UINT seq, UCHAR *packet, UINT *size)
{
	MIRRORTEST_NODE *t = &ctx->Nodes[s->From];

	*size = MirrorTestPacket(packet, MIRRORTEST_SIZE, s->Src, s->Dst, s->Protocol, s->SrcPort, s->DstPort, s->Shape, MIRRORTEST_SIZE, seq);

	NodeReaderOnline(t->Node, &t->Reader);
	bool ok = (*size != 0 && NodeOverlayInput(t->Node, mirrortest_vrf_ids[s->Vrf], packet, *size));
	NodeReaderOffline(&t->Reader);

	return ok;
}

//
// The cases
//

// The packets that Mirrors take arrive at their sensors as the golden datagrams, and at the other host
static void MirrorTestMatching(MIRRORTEST_CTX *ctx)
{
	UCHAR packet[MIRRORTEST_SIZE];
	NODE_MIRROR_STATUS before, after;
	UINT num = sizeof(mirrortest_matching) / sizeof(mirrortest_matching[0]);

	Print("[packets that a Mirror takes]\n");
	NodeMirrorGetStatus(ctx->Nodes[MIRRORTEST_A].Node, &before);

	for (UINT i = 0;i < num;i++)
	{
		MIRRORTEST_SEND *s = &mirrortest_matching[i];
		MIRRORTEST_NODE *to = &ctx->Nodes[1 - s->From];
		LONG arrivals = InterlockedCompareExchange(&to->Arrivals, 0, 0);
		char what[MAX_SIZE];
		UINT size = 0;

		bool sent = MirrorTestSend(ctx, s, 100 + i, packet, &size);
		bool arrived = sent && MirrorTestArrived(to, arrivals + 1);
		UINT want = MirrorTestGolden(ctx->Want, s->Vni, s->From == MIRRORTEST_A, packet, size);
		UINT got = MirrorTestRead(ctx, &ctx->Sensors[s->Sensor], MIRRORTEST_TIMEOUT);

		Format(what, sizeof(what), "  %s: it reaches %s, and sensor %u reads the VXLAN header with VNI %u, the Ethernet header and the identical packet",
			s->What, mirrortest_names[1 - s->From], s->Sensor, s->Vni);
		MirrorTestCheck(ctx, sent && arrived && got == want && Cmp(ctx->Datagram, ctx->Want, want) == 0, what,
			"sent %u, arrived %u, %u bytes read, %u wanted, same %u", (UINT)sent, (UINT)arrived, got, want, (UINT)(got == want && Cmp(ctx->Datagram, ctx->Want, want) == 0));
	}

	UINT noisy = MirrorTestNoisy(ctx);
	NodeMirrorGetStatus(ctx->Nodes[MIRRORTEST_A].Node, &after);
	MirrorTestCheck(ctx, noisy == 0 && after.Copied == before.Copied + num && after.Limited == before.Limited && after.Failed == before.Failed,
		"  one copy of each packet and no other: node-a counted each copy, and no sensor reads more",
		"sensors 0x%x read more; %I64u copies before, %I64u after; %I64u limited, %I64u failed", noisy, before.Copied, after.Copied, after.Limited, after.Failed);
}

// The packets that no Mirror takes reach the other host and no sensor
static void MirrorTestOther(MIRRORTEST_CTX *ctx)
{
	UCHAR packet[MIRRORTEST_SIZE];
	NODE_MIRROR_STATUS before, after;
	UINT num = sizeof(mirrortest_other) / sizeof(mirrortest_other[0]);
	bool forwarded = true;

	Print("[packets that no Mirror takes]\n");
	NodeMirrorGetStatus(ctx->Nodes[MIRRORTEST_A].Node, &before);

	for (UINT i = 0;i < num;i++)
	{
		MIRRORTEST_SEND *s = &mirrortest_other[i];
		MIRRORTEST_NODE *to = &ctx->Nodes[1 - s->From];
		LONG arrivals = InterlockedCompareExchange(&to->Arrivals, 0, 0);
		UINT size = 0;

		bool sent = MirrorTestSend(ctx, s, 200 + i, packet, &size);
		if (sent != s->Forwarded || (sent && MirrorTestArrived(to, arrivals + 1) == false))
		{
			Print("  [INFO] %s: sent %u, not as the overlay should\n", s->What, (UINT)sent);
			forwarded = false;
		}
	}

	UINT noisy = MirrorTestNoisy(ctx);
	NodeMirrorGetStatus(ctx->Nodes[MIRRORTEST_A].Node, &after);
	MirrorTestCheck(ctx, forwarded && noisy == 0 && after.Copied == before.Copied && after.Limited == before.Limited && after.Failed == before.Failed,
		"  another protocol, another port, another VRF, a later fragment, a packet that the overlay does not send: no sensor reads a copy, and node-a counts none",
		"forwarded as they should %u, sensors 0x%x read something, %I64u copies before, %I64u after", (UINT)forwarded, noisy, before.Copied, after.Copied);
}

// The load: TCP to port 8080 in red as fast as the overlay takes it, each packet sent as an online reader of node-a
// with a quiescent point after it
static DWORD WINAPI MirrorTestLoadThread(LPVOID param)
{
	MIRRORTEST_LOAD *l = (MIRRORTEST_LOAD *)param;
	UCHAR packet[MIRRORTEST_LOAD_SIZE];
	LARGE_INTEGER now;
	NODE_READER r;

	Zero(&r, sizeof(r));
	NodeReaderRegister(l->Node, &r);

	UINT size = MirrorTestPacket(packet, sizeof(packet), "10.0.0.1", "10.0.0.2", IP_PROTO_TCP, 40000, 8080, MIRRORTEST_PLAIN, MIRRORTEST_LOAD_SIZE, 0);
	UINT64 end = Tick64() + MIRRORTEST_LOAD_TIME;

	QueryPerformanceCounter(&now);
	l->Start = (UINT64)now.QuadPart;
	while (Tick64() < end)
	{
		WRITE_UINT(packet + 40, l->Sent);
		if (NodeOverlayInput(l->Node, mirrortest_vrf_ids[MIRRORTEST_RED], packet, size))
		{
			l->Sent++;
		}
		else
		{
			l->Refused++;
		}
		NodeReaderQuiescent(l->Node, &r);
	}
	QueryPerformanceCounter(&now);
	l->End = (UINT64)now.QuadPart;

	NodeReaderUnregister(l->Node, &r);

	return 0;
}

// The rate limit of the load Mirror holds under a load far above it
static void MirrorTestLoad(MIRRORTEST_CTX *ctx)
{
	MIRRORTEST_LOAD l;
	NODE_MIRROR_STATUS before, after;
	LARGE_INTEGER frequency;
	UCHAR packet[MIRRORTEST_LOAD_SIZE];
	UINT64 bytes = 0;
	UINT num = 0, wrong = 0, n;
	char what[MAX_SIZE];

	Print("[the rate limit of a Mirror under load]\n");

	Zero(&l, sizeof(l));
	l.Node = ctx->Nodes[MIRRORTEST_A].Node;
	NodeMirrorGetStatus(l.Node, &before);

	HANDLE thread = CreateThread(NULL, 0, MirrorTestLoadThread, &l, 0, NULL);
	if (MirrorTestCheck(ctx, thread != NULL, "  the load starts", "CreateThread failed") == false)
	{
		return;
	}
	WaitForSingleObject(thread, INFINITE);
	CloseHandle(thread);

	// Every copy that node-a sent is in the receive buffer of sensor 3: the golden datagram of a packet of the load
	UINT size = MirrorTestPacket(packet, sizeof(packet), "10.0.0.1", "10.0.0.2", IP_PROTO_TCP, 40000, 8080, MIRRORTEST_PLAIN, MIRRORTEST_LOAD_SIZE, 0);
	while ((n = MirrorTestRead(ctx, &ctx->Sensors[3], MIRRORTEST_QUIET)) != 0)
	{
		UINT seq = (n > VXLAN_HEADER_SIZE + NODE_MIRROR_ETHER + 44 ? READ_UINT(ctx->Datagram + VXLAN_HEADER_SIZE + NODE_MIRROR_ETHER + 40) : 0);
		UINT want;

		WRITE_UINT(packet + 40, seq);
		want = MirrorTestGolden(ctx->Want, MIRRORTEST_VNI_LOAD, true, packet, size);
		if (n != want || Cmp(ctx->Datagram, ctx->Want, want) != 0)
		{
			wrong++;
		}

		num++;
		bytes += n;
	}
	NodeMirrorGetStatus(l.Node, &after);

	// What the rate allowed over the span of the load: the burst of the bucket and the rate times the span, and one
	// datagram for the rounding of the burst
	QueryPerformanceFrequency(&frequency);
	double span = (double)(l.End - l.Start) / (double)frequency.QuadPart;
	double rate = MIRRORTEST_LOAD_RATE / 8.0;
	double burst = MAX(rate * NODE_MIRROR_BURST / 1000.0, (double)NODE_MIRROR_MIN_BURST);
	double allowed = burst + rate * span + (VXLAN_HEADER_SIZE + NODE_MIRROR_ETHER + MIRRORTEST_LOAD_SIZE);
	double offered = (double)l.Sent * (VXLAN_HEADER_SIZE + NODE_MIRROR_ETHER + MIRRORTEST_LOAD_SIZE);

	Print("  [INFO] %u packets in %.3f s, %u refused: %.0f bytes of copies offered, %.0f allowed, %I64u read in %u datagrams\n",
		l.Sent, span, l.Refused, offered, allowed, bytes, num);

	MirrorTestCheck(ctx, l.Refused == 0 && offered >= 4 * allowed, "  the load offers its Mirror more than four times what the rate limit of 1 Mbit/s allows",
		"%u refused, %.0f bytes offered, %.0f allowed", l.Refused, offered, allowed);
	Format(what, sizeof(what), "  sensor 3 reads at most the burst and the rate times the span of the load, %.0f bytes, and at least a quarter of the rate times the span", allowed);
	MirrorTestCheck(ctx, wrong == 0 && (double)bytes <= allowed && (double)bytes >= rate * span / 4, what,
		"%I64u bytes in %u datagrams, %u not golden", bytes, num, wrong);
	MirrorTestCheck(ctx, after.Copied - before.Copied == num && after.Limited - before.Limited == l.Sent - num && after.Failed == before.Failed,
		"  every packet of the load is copied or counted as limited, and each copy arrives",
		"%I64u copied, %I64u limited, %I64u failed, of %u packets; %u datagrams read", after.Copied - before.Copied, after.Limited - before.Limited, after.Failed - before.Failed, l.Sent, num);
}

// The nodes, their overlays and the sensors
static bool MirrorTestOpen(MIRRORTEST_CTX *ctx, TRANSPORT *loopback)
{
	UCHAR scalar[PEER_KEY_SIZE];
	char what[MAX_SIZE];
	bool ok = (loopback != NULL);

	Print("[the nodes, their overlays and the sensors]\n");

	for (UINT i = 1;i <= MIRRORTEST_NUM_SENSORS && ok;i++)
	{
		ok = MirrorTestOpenSensor(&ctx->Sensors[i]);
	}
	MirrorTestCheck(ctx, ok, "  three sensors, each a UDP socket on 127.0.0.1", "error %u", (UINT)WSAGetLastError());

	for (UINT i = 0;i < 2 && ok;i++)
	{
		MIRRORTEST_NODE *t = &ctx->Nodes[i];
		NODE_OVERLAY_CONFIG c;

		for (UINT j = 0;j < PEER_KEY_SIZE;j++)
		{
			scalar[j] = (UCHAR)(0x31 + PEER_KEY_SIZE * i + j);
		}
		ok = PeerKeyFromScalar(&t->Key, scalar);

		MirrorTestNewDir(t->Dir, sizeof(t->Dir), mirrortest_names[i]);
		t->Node = NewNode(t->Dir);
		NodeStart(t->Node);
		NodeReaderRegister(t->Node, &t->Reader);
		NodeReaderOffline(&t->Reader);

		Zero(&c, sizeof(c));
		c.Data = loopback;
		c.Key = &t->Key;
		c.Adapter = MirrorTestAdapter;
		c.AdapterParam = t;
		Format(what, sizeof(what), "  %s: its overlay runs without a control stream", mirrortest_names[i]);
		ok = MirrorTestCheck(ctx, ok && NodeOverlayStart(t->Node, &c), what, "NodeOverlayStart failed") && ok;
	}
	Zero(scalar, sizeof(scalar));

	if (ok)
	{
		bool applied = MirrorTestApply(ctx, MIRRORTEST_A) && MirrorTestApply(ctx, MIRRORTEST_B);
		bool linked = applied && MirrorTestWaitLinks(ctx);

		ok = MirrorTestCheck(ctx, applied && linked, "  node-a applies its state with the Mirrors dns, load and ping, node-b its own, and their session is up",
			"applied %u, linked %u", (UINT)applied, (UINT)linked);
		Print("  [INFO] sensors 1, 2 and 3 on the ports %u, %u and %u of 127.0.0.1\n", (UINT)ctx->Sensors[1].Port, (UINT)ctx->Sensors[2].Port, (UINT)ctx->Sensors[3].Port);
	}

	return ok;
}

// The nodes first, whose overlays stop with every thread joined, then the sensors
static void MirrorTestClose(MIRRORTEST_CTX *ctx)
{
	for (UINT i = 0;i < 2;i++)
	{
		MIRRORTEST_NODE *t = &ctx->Nodes[i];
		wchar_t log_dir[MAX_PATH];

		if (t->Node != NULL)
		{
			NodeReaderUnregister(t->Node, &t->Reader);
			NodeStop(t->Node);
			FreeNode(t->Node);

			ConbinePathW(log_dir, sizeof(log_dir), t->Dir, NODE_LOG_DIR_NAME);
			MirrorTestDeleteFiles(log_dir);
			MirrorTestDeleteFiles(t->Dir);
		}
		PeerKeyClose(&t->Key);
	}

	for (UINT i = 1;i <= MIRRORTEST_NUM_SENSORS;i++)
	{
		if (ctx->Sensors[i].Socket != INVALID_SOCKET)
		{
			closesocket(ctx->Sensors[i].Socket);
		}
	}
}

// mirror: the Mirrors of a node over VXLAN
RANZ_TEST("mirror", mirror_test, "Mirror: packets of the overlay that a Mirror takes (VRF, protocol, port) arrive at a harness sensor in VXLAN as golden datagrams, both ways and over IPv6; no other packet is copied; the rate limit of a Mirror holds under a load far above it.");
void mirror_test(UINT num, char **arg)
{
	MIRRORTEST_CTX *ctx = ZeroMalloc(sizeof(MIRRORTEST_CTX));
	HANDLE done = CreateEventW(NULL, TRUE, FALSE, NULL);
	HANDLE watchdog = (done != NULL ? CreateThread(NULL, 0, MirrorTestWatchdog, done, 0, NULL) : NULL);
	TRANSPORT *loopback = TransportLoopbackNew("loopback", 0, false);

	Print("Mirror test: the Mirrors of a node copy the matching packets of the overlay to harness sensors in VXLAN, rate-limited\n");

	for (UINT i = 0;i <= MIRRORTEST_NUM_SENSORS;i++)
	{
		ctx->Sensors[i].Socket = INVALID_SOCKET;
	}

	if (MirrorTestOpen(ctx, loopback))
	{
		MirrorTestMatching(ctx);
		MirrorTestOther(ctx);
		MirrorTestLoad(ctx);
	}

	MirrorTestClose(ctx);
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
		Print("MIRROR TEST OK\n");
	}
	else
	{
		Print("MIRROR TEST FAILED (%u of %u checks failed)\n", ctx->NumFailed, ctx->NumChecks);
	}

	Free(ctx);
}
