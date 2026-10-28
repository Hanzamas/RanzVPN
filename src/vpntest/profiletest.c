// profiletest.c
// Named session profile test of vpntest ("profile" command, SDN-40 #233)
//
// The session profiles of the overlay of a node (Cedar/NodeProfile.c), in process, as seam 2 of #45 runs the data plane:
// five nodes in VRF red, fake adapters for their hosts, the in-process loopback transport for their Noise sessions, and the
// desired states that the test applies itself (NodeOverlayApply). node-a runs under no profile; node-b, node-c and node-d
// are the devices of alice, node-e the device of bob. node-a has the greatest static key, so the devices dial it. node-b
// has two IPv4 addresses and one IPv6 address of its own more than the others, and two 1:1 NAT rules, one of IPv4 and one
// of IPv6, whose outside prefixes are routes of node-b at every other node: prefixes that node-b routes.
// - Rates: alice runs under an upload limit of 8 Mbit/s and a download limit of 4 Mbit/s. node-a sends to node-b as fast as
//   it can for 1.5 s, and its overlay sends node-b the burst of the bucket and 4 Mbit/s over the time; node-b, paced by a
//   rate limit of its own of 16 Mbit/s, sends to node-a, whose host takes the burst and 8 Mbit/s over the time, and node-a
//   drops the rest. Every packet is counted: what arrives, and what the limits drop.
// - Flags at the peers (the Peer objects carry the profile, the NodeConfigs do not): node-a drops a TCP SYN to node-b, in
//   IPv4 and behind a hop-by-hop header of IPv6, and a SYN-ACK from it (no-server), passes a SYN from it, an ACK and UDP to
//   it; drops a packet to the outside of a NAT rule of node-b and one from it, in IPv4 and in IPv6 (no-routing); takes
//   the first two IPv4 addresses and the first IPv6 address that node-b sends from and drops the next ones (the counts);
//   node-b and node-c reach each other, since the privacy filter needs the profiles of both ends.
// - Flags on the devices themselves (the NodeConfigs carry the profile, the Peer objects do not): node-b drops the SYN of
//   node-a to its host and the SYN-ACK of its host, and the packet to the outside of a NAT rule and the one from it, in
//   IPv4 and in IPv6.
// - Flags at both: the privacy filter keeps node-b and node-c apart at the node that sends, while each reaches node-a and
//   node-e, which runs under the profile of bob without it.
// - Sessions: alice runs under at most 2 sessions at a node, bob under 1. node-a holds 2 of the 3 devices of alice and
//   refuses the third while they are up, and holds the one of bob; once node-a drops one of the two, the third comes up.
// - Idle timeout: under 2 s, the session of node-b at node-a stays while node-a sends to it every 250 ms, and ends about
//   2 s after the last packet; node-b dials again.
// - Automatic disconnect: under 2 s, the session of node-b at node-a ends about 2 s after it came up, while packets flow.
// - L2: the switch of an L2 Network with the policy engine as its filter (Core/SwitchSecurity.h), and a port for the session
//   of each device, whose member carries the guard of the profile of the device (NodeProfileMember): a session under 2 MAC
//   addresses sends from 2 and not from a third, one under no-bridge from its first only, two under the privacy filter do
//   not reach each other, by unicast or broadcast, and each reaches a session under none. A frame that a profile refuses
//   goes nowhere, and the MAC table does not learn its source.
// A Generation without profiles lets everything through again. Print "PROFILE TEST OK" only when every check passes.

#include "testlist.h"

#include "Cedar/ConfigStore.h"
#include "Cedar/Node.h"
#include "Cedar/NodeProfile.h"

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
#include "Core/Policy.h"
#include "Core/SwitchSecurity.h"
#include "Core/Transport.h"

#include <stdio.h>

#define	PROFILETEST_BUDGET		300000		// The whole test ends within this time, or the watchdog ends the process (ms)
#define	PROFILETEST_BOUND		10000		// A bounded wait on observable state (ms)
#define	PROFILETEST_POLL		10			// Poll interval of observable state (ms)
#define	PROFILETEST_NODES		5
#define	PROFILETEST_VRF			101			// The VRF red of every node
#define	PROFILETEST_UPLOAD		8000000		// The upload limit of the rate cases (bits per second) ...
#define	PROFILETEST_DOWNLOAD	4000000		// ... and their download limit
#define	PROFILETEST_PACE		16000000	// The rate limit of node-b itself in the upload case, which paces what it sends
#define	PROFILETEST_RATE_TIME	1500		// How long a rate case sends (ms)
#define	PROFILETEST_PAYLOAD		972			// The UDP data of a packet of the rate cases: 1000 bytes with its headers
#define	PROFILETEST_LOW			90			// The bytes that a rate case passes at least, in percent of what its limit lets through
#define	PROFILETEST_TIMEOUT		2			// The idle timeout and the automatic disconnect of the timeout cases (s)
#define	PROFILETEST_BEAT		250			// ms between two packets of a session that must not idle
#define	PROFILETEST_SLACK		1500		// ms that the overlay may take beyond a timeout to end a session
#define	PROFILETEST_STABLE		1500		// ms that the sessions of the session case stay as they are
#define	PROFILETEST_MAX_PACKET	1500		// A packet of the test at most
#define	PROFILETEST_KEEP		256			// The bytes of a packet that the adapter of a host keeps
#define	PROFILETEST_NS			1000000000ULL

// The nodes
#define	PROFILETEST_A			0			// node-a: under no profile, with the greatest key
#define	PROFILETEST_B			1			// node-b, node-c, node-d: the devices of alice
#define	PROFILETEST_C			2
#define	PROFILETEST_D			3
#define	PROFILETEST_E			4			// node-e: the device of bob
#define	PROFILETEST_NONE		PROFILETEST_NODES
#define	PROFILETEST_BIT(i)		(1u << (i))

static char *profiletest_names[PROFILETEST_NODES] = {"node-a", "node-b", "node-c", "node-d", "node-e"};

// The addresses of each node in red, its first IPv4 and IPv6 address first; node-b has more of its own, which the counts
// send from
static char *profiletest_addrs[PROFILETEST_NODES][6] =
{
	{"10.0.0.1", "fd00::1", NULL},
	{"10.0.0.2", "fd00::2", "10.0.0.12", "10.0.0.22", "fd00::12", NULL},
	{"10.0.0.3", "fd00::3", NULL},
	{"10.0.0.4", "fd00::4", NULL},
	{"10.0.0.5", "fd00::5", NULL},
};

// The 1:1 NAT rules of node-b: its LAN 192.168.9.0/24 is 10.9.0.0/24 in red, and its LAN fd09:9::/64 is fd00:9::/64, each
// outside prefix a route of node-b at the other nodes
#define	PROFILETEST_NAT_INSIDE	"192.168.9.0"
#define	PROFILETEST_NAT_OUTSIDE	"10.9.0.0"
#define	PROFILETEST_LAN_HOST	"192.168.9.5"
#define	PROFILETEST_ROUTED		"10.9.0.5"
#define	PROFILETEST_NAT6_INSIDE		"fd09:9::"
#define	PROFILETEST_NAT6_OUTSIDE	"fd00:9::"
#define	PROFILETEST_LAN6_HOST		"fd09:9::5"
#define	PROFILETEST_ROUTED6			"fd00:9::5"

// Where a case expects a packet to end
#define	PROFILETEST_DELIVERED	0			// The host of the receiver takes it
#define	PROFILETEST_AT_SENDER	1			// The overlay of the sender drops it
#define	PROFILETEST_AT_RECEIVER	2			// The overlay of the receiver drops it
#define	PROFILETEST_CHANGED		3			// The host of the receiver takes another packet, or none comes

// The counter of NODE_PROFILE_STATUS that a drop counts in
#define	PROFILETEST_NO_REASON	0
#define	PROFILETEST_ROUTING		1
#define	PROFILETEST_SERVER		2
#define	PROFILETEST_ISOLATED	3
#define	PROFILETEST_ADDRESSES	4

// The kinds of a packet of a case
#define	PROFILETEST_SYN			0			// A TCP SYN
#define	PROFILETEST_SYN_ACK		1			// ... a SYN-ACK
#define	PROFILETEST_ACK			2			// ... a segment that is no SYN
#define	PROFILETEST_UDP			3
#define	PROFILETEST_ICMP		4			// An echo request of ICMP or ICMPv6
#define	PROFILETEST_SYN_HOP		5			// A TCP SYN behind a hop-by-hop options header of IPv6

// The L2 case: the sessions of the switch of an L2 Network
#define	PROFILETEST_L2_MEMBERS	5			// Under 2 MAC addresses, under no-bridge, twice under the privacy filter, and under none
#define	PROFILETEST_L2_VLAN		1			// The VLAN of every port
#define	PROFILETEST_L2_NOW		1000		// The time of the switch and of the policy engine (ms)
#define	PROFILETEST_L2_LEARNT	8			// The addresses that its MAC table learns

// The checks of the test
typedef struct PROFILETEST_CTX
{
	UINT NumChecks;
	UINT NumFailed;
	UINT NextId;						// The port, sequence number or identifier of the next packet of a case
} PROFILETEST_CTX;

// A packet that the fake adapter of a host took
typedef struct PROFILETEST_PACKET
{
	UINT Size;
	UCHAR Data[PROFILETEST_KEEP];
} PROFILETEST_PACKET;

// One node of the test and the fake adapter of its host
typedef struct PROFILETEST_NODE
{
	char *Name;
	wchar_t Dir[MAX_PATH];				// Its data directory
	PEER_KEY Key;						// Its static key
	NODE *Node;
	NODE_READER Reader;					// The test thread as a reader of the node's forwarding tables, online while it sends
	SRWLOCK Lock;						// Packets
	LIST *Packets;						// What the adapter took (PROFILETEST_PACKET), while Counting is 0
	volatile LONG Counting;				// A rate case runs: the adapter counts what it takes instead
	volatile LONG64 Count;				// ... the packets ...
	volatile LONG64 Last;				// ... and the time of the last (ns of the performance counter)
} PROFILETEST_NODE;

// The desired states of one Generation
typedef struct PROFILETEST_GEN
{
	UINT64 Generation;
	CONTROL_PROFILE Profiles[PROFILETEST_NODES];	// The profile that each node runs under, not Set for none
	bool Own;										// The NodeConfig of each node carries its profile ...
	bool Peers;										// ... and the Peer object of each node at the others
	UINT64 RateB;									// The rate limit of node-b itself (NodeShape.c), 0 for none
	UINT Without;									// The nodes that node-a does not hold as peers, nor they node-a (PROFILETEST_BIT)
	bool Spokes;									// The devices hold node-a alone as a peer, not each other
} PROFILETEST_GEN;

// The sender of a rate case: one node sends one packet to another as fast as its overlay takes it
typedef struct PROFILETEST_STREAM
{
	PROFILETEST_NODE *From;
	UCHAR Packet[PROFILETEST_MAX_PACKET];
	UINT Size;
	volatile LONG Stop;					// Ends the sender
	UINT64 Start;						// When it sent its first packet (ns of the performance counter) ...
	UINT64 End;							// ... and when its last send returned
	UINT64 Sent;						// Packets that the overlay sent
	UINT64 Refused;						// ... and that it dropped
} PROFILETEST_STREAM;

// A port of the switch of the L2 case: the session of a device, its member in the policy engine, and what the port
// delivered in the current case
typedef struct PROFILETEST_PORT
{
	UINT Port;
	UINT Member;
	UINT NumFrames;						// The frames it delivered
	UINT Size;							// The last of them ...
	UCHAR Frame[PROFILETEST_KEEP];		// ...
} PROFILETEST_PORT;

static bool ProfileTestCheck(PROFILETEST_CTX *ctx, bool ok, char *what, char *fmt, ...) RANZ_PRINTF_FORMAT(4, 5);
static bool ProfileTestCheck(PROFILETEST_CTX *ctx, bool ok, char *what, char *fmt, ...)
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

// The watchdog: a native thread that ends a run that hangs, so that a lost session is a failed test instead of a hung CI
// step
static DWORD WINAPI ProfileTestWatchdog(LPVOID param)
{
	char msg[MAX_SIZE];
	DWORD written = 0;

	if (WaitForSingleObject((HANDLE)param, PROFILETEST_BUDGET) != WAIT_TIMEOUT)
	{
		return 0;
	}

	int len = snprintf(msg, sizeof(msg), "PROFILE TEST FAILED (did not finish within %u ms)\n", PROFILETEST_BUDGET);
	if (len > 0)
	{
		WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), msg, (DWORD)MIN((UINT)len, (UINT)sizeof(msg) - 1), &written, NULL);
	}

	TerminateProcess(GetCurrentProcess(), 1);

	return 0;
}

// The time of the rate cases: ns of the performance counter, as the buckets of the profiles count it
static UINT64 ProfileTestNow()
{
	LARGE_INTEGER counter, freq;

	QueryPerformanceCounter(&counter);
	QueryPerformanceFrequency(&freq);

	UINT64 t = (UINT64)counter.QuadPart, f = MAX((UINT64)freq.QuadPart, 1);

	return (t / f) * PROFILETEST_NS + (t % f) * PROFILETEST_NS / f;
}

//
// The packets
//

// The address of a text: 4 bytes for IPv4, 16 for IPv6, and their number; 0 for no address
static UINT ProfileTestAddress(UCHAR *addr, char *str)
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

// The IP header of a packet from src to dst, both IPv4 or both IPv6, with l4_size bytes of the protocol proto after it,
// and for IPv6 a hop-by-hop options header of 8 bytes before them when hop is set: the bytes before the protocol, 0 when
// the two addresses are not of one family. An IPv4 header gets its checksum.
static UINT ProfileTestIp(UCHAR *buf, char *src, char *dst, UCHAR proto, UINT l4_size, bool hop)
{
	UCHAR s[16], d[16];
	UINT s_size = ProfileTestAddress(s, src), d_size = ProfileTestAddress(d, dst);

	if (s_size == 0 || s_size != d_size)
	{
		return 0;
	}

	if (s_size == 4)
	{
		UINT size = 20 + l4_size;

		Zero(buf, 20);
		buf[0] = 0x45;
		buf[2] = (UCHAR)(size >> 8);
		buf[3] = (UCHAR)size;
		buf[8] = 64;
		buf[9] = proto;
		Copy(buf + 12, s, 4);
		Copy(buf + 16, d, 4);
		USHORT sum = IpChecksum(buf, 20);
		Copy(buf + 10, &sum, 2);

		return 20;
	}

	UINT ext = (hop ? 8 : 0);

	Zero(buf, 40 + ext);
	buf[0] = 0x60;
	buf[4] = (UCHAR)((ext + l4_size) >> 8);
	buf[5] = (UCHAR)(ext + l4_size);
	buf[6] = (hop ? IPV6_HEADER_HOP : proto);
	buf[7] = 64;
	Copy(buf + 8, s, 16);
	Copy(buf + 24, d, 16);
	if (hop)
	{
		// The next header, the length 0 (8 bytes), and a PadN option over the 4 bytes left
		buf[40] = proto;
		buf[42] = 1;
		buf[43] = 4;
	}

	return 40 + ext;
}

// The checksum of the TCP, UDP or ICMPv6 message of size bytes behind the headers of hdr bytes of buf, into the field at
// offset field of the message
static void ProfileTestChecksum(UCHAR *buf, UINT hdr, UCHAR proto, UINT size, UINT field)
{
	UCHAR *l4 = buf + hdr;
	USHORT sum;

	Zero(l4 + field, 2);
	if ((buf[0] >> 4) == 4)
	{
		UINT src, dst;

		Copy(&src, buf + 12, 4);
		Copy(&dst, buf + 16, 4);
		sum = CalcChecksumForIPv4(src, dst, proto, l4, size, 0);
	}
	else
	{
		sum = CalcChecksumForIPv6((IPV6_ADDR *)(buf + 8), (IPV6_ADDR *)(buf + 24), proto, l4, size, 0);
	}
	Copy(l4 + field, &sum, 2);
}

// A UDP datagram from src to dst with payload bytes of data that begin with id: its size, 0 for none
static UINT ProfileTestDatagram(UCHAR *buf, char *src, char *dst, UINT id, UINT payload)
{
	UINT len = 8 + payload;
	UINT hdr = ProfileTestIp(buf, src, dst, IP_PROTO_UDP, len, false);

	if (hdr == 0 || payload < 4 || hdr + len > PROFILETEST_MAX_PACKET)
	{
		return 0;
	}

	UCHAR *udp = buf + hdr;

	Zero(udp, len);
	WRITE_USHORT(udp, 40000 + id % 20000);
	WRITE_USHORT(udp + 2, 53);
	WRITE_USHORT(udp + 4, len);
	WRITE_UINT(udp + 8, id);
	ProfileTestChecksum(buf, hdr, IP_PROTO_UDP, len, 6);

	return hdr + len;
}

// A packet of the kind from src to dst whose port, sequence number or identifier is id: its size, 0 for none
static UINT ProfileTestPacket(UCHAR *buf, UINT kind, char *src, char *dst, UINT id)
{
	UCHAR any[16];
	UINT hdr, len;
	UCHAR *l4;

	if (kind == PROFILETEST_UDP)
	{
		return ProfileTestDatagram(buf, src, dst, id, 16);
	}

	if (kind == PROFILETEST_ICMP)
	{
		bool v6 = (ProfileTestAddress(any, src) == 16);

		len = 16;
		hdr = ProfileTestIp(buf, src, dst, (v6 ? IP_PROTO_ICMPV6 : IP_PROTO_ICMPV4), len, false);
		if (hdr == 0)
		{
			return 0;
		}
		l4 = buf + hdr;
		Zero(l4, len);
		l4[0] = (v6 ? 128 : 8);
		WRITE_USHORT(l4 + 4, id);
		WRITE_USHORT(l4 + 6, 1);
		if (v6)
		{
			ProfileTestChecksum(buf, hdr, IP_PROTO_ICMPV6, len, 2);
		}
		else
		{
			USHORT sum = IpChecksum(l4, len);
			Copy(l4 + 2, &sum, 2);
		}
		return hdr + len;
	}

	// A TCP segment of 20 bytes, without options
	len = 20;
	hdr = ProfileTestIp(buf, src, dst, IP_PROTO_TCP, len, kind == PROFILETEST_SYN_HOP);
	if (hdr == 0)
	{
		return 0;
	}
	l4 = buf + hdr;
	Zero(l4, len);
	WRITE_USHORT(l4, 40000 + id % 20000);
	WRITE_USHORT(l4 + 2, 443);
	WRITE_UINT(l4 + 4, 0x1000 + id);
	WRITE_UINT(l4 + 8, (kind == PROFILETEST_SYN_ACK || kind == PROFILETEST_ACK ? 0x2000 : 0));
	l4[12] = (UCHAR)((len / 4) << 4);
	l4[13] = (UCHAR)(kind == PROFILETEST_SYN_ACK ? (TCP_SYN | TCP_ACK) : (kind == PROFILETEST_ACK ? TCP_ACK : TCP_SYN));
	WRITE_USHORT(l4 + 14, 64240);
	ProfileTestChecksum(buf, hdr, IP_PROTO_TCP, len, 16);

	return hdr + len;
}

//
// The nodes
//

// A new empty data directory under the temp directory of the process, with a configuration store that runs no role on one
// worker
static void ProfileTestNewDir(wchar_t *dir, UINT size, char *name)
{
	wchar_t tmp[MAX_PATH];
	wchar_t path[MAX_PATH];

	UniFormat(tmp, sizeof(tmp), L"profiletest_%S_%u", name, Rand32());
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
static void ProfileTestDeleteFiles(wchar_t *dir)
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

// The fake adapter of a host: it keeps each packet, or counts them while a rate case runs
static void ProfileTestAdapter(NODE *n, void *param, UINT vrf_id, const UCHAR *packet, UINT size)
{
	PROFILETEST_NODE *t = (PROFILETEST_NODE *)param;

	if (InterlockedCompareExchange(&t->Counting, 0, 0) != 0)
	{
		InterlockedIncrement64(&t->Count);
		InterlockedExchange64(&t->Last, (LONG64)ProfileTestNow());
		return;
	}

	PROFILETEST_PACKET *p = ZeroMalloc(sizeof(PROFILETEST_PACKET));
	p->Size = size;
	Copy(p->Data, packet, MIN(size, (UINT)sizeof(p->Data)));

	AcquireSRWLockExclusive(&t->Lock);
	Add(t->Packets, p);
	ReleaseSRWLockExclusive(&t->Lock);
}

// The packets that the host of t took
static UINT ProfileTestNumPackets(PROFILETEST_NODE *t)
{
	AcquireSRWLockShared(&t->Lock);
	UINT num = LIST_NUM(t->Packets);
	ReleaseSRWLockShared(&t->Lock);

	return num;
}

// Whether one of the packets that the host of t took from index from on is the one of size bytes at want. Every packet of
// the test carries an id of its own, so the one of a case is found among packets of earlier cases that came late.
static bool ProfileTestFind(PROFILETEST_NODE *t, UINT from, UCHAR *want, UINT size)
{
	bool found = false;

	AcquireSRWLockShared(&t->Lock);
	for (UINT i = from;i < LIST_NUM(t->Packets) && found == false;i++)
	{
		PROFILETEST_PACKET *p = LIST_DATA(t->Packets, i);

		found = (p->Size == size && Cmp(p->Data, want, MIN(size, (UINT)sizeof(p->Data))) == 0);
	}
	ReleaseSRWLockShared(&t->Lock);

	return found;
}

// The packets that the overlay of a node dropped
static UINT64 ProfileTestDropped(PROFILETEST_NODE *t)
{
	NODE_OVERLAY_STATUS st;

	NodeOverlayGetStatus(t->Node, &st);
	return st.Dropped;
}

// The counter of the profiles of a node that a drop of the reason counts in
static UINT64 ProfileTestCounter(PROFILETEST_NODE *t, UINT reason)
{
	NODE_PROFILE_STATUS st;

	NodeProfileGetStatus(t->Node, &st);
	switch (reason)
	{
	case PROFILETEST_ROUTING:
		return st.Routing;
	case PROFILETEST_SERVER:
		return st.Server;
	case PROFILETEST_ISOLATED:
		return st.Isolated;
	case PROFILETEST_ADDRESSES:
		return st.Addresses;
	}

	return 0;
}

// The addresses of node i in red into a: their number
static UINT ProfileTestAddresses(UINT i, CONTROL_ADDRESS *a)
{
	UINT num = 0;

	for (UINT k = 0;profiletest_addrs[i][k] != NULL;k++)
	{
		CONTROL_ADDRESS *c = &a[num++];

		Zero(c, sizeof(CONTROL_ADDRESS));
		StrCpy(c->Network, sizeof(c->Network), "red");
		c->VrfId = PROFILETEST_VRF;
		c->AddressSize = ProfileTestAddress(c->Address, profiletest_addrs[i][k]);
		c->Length = (c->AddressSize == 4 ? 24 : 64);
	}

	return num;
}

// A 1:1 NAT rule of node-b in red from the prefix inside, which its host sees, to the prefix outside, which the VRF sees:
// /24 for IPv4, /64 for IPv6
static void ProfileTestNat(CONTROL_NAT *c, char *inside, char *outside)
{
	c->VrfId = PROFILETEST_VRF;
	c->InsideSize = ProfileTestAddress(c->Inside, inside);
	c->InsideLength = (c->InsideSize == 4 ? 24 : 64);
	c->OutsideSize = ProfileTestAddress(c->Outside, outside);
	c->OutsideLength = (c->OutsideSize == 4 ? 24 : 64);
}

// The route of node-b at another node to the outside prefix of one of its NAT rules: /24 for IPv4, /64 for IPv6
static void ProfileTestRoute(CONTROL_ROUTE *r, char *prefix)
{
	r->VrfId = PROFILETEST_VRF;
	r->AddressSize = ProfileTestAddress(r->Address, prefix);
	r->Length = (r->AddressSize == 4 ? 24 : 64);
}

// Whether node i holds node j as a peer in the Generation g: every other node, but node-a and the nodes that g leaves out,
// and two devices when g holds the devices to node-a alone
static bool ProfileTestPeers(PROFILETEST_GEN *g, UINT i, UINT j)
{
	if (i == j || (g->Spokes && i != PROFILETEST_A && j != PROFILETEST_A))
	{
		return false;
	}

	if ((i == PROFILETEST_A && (g->Without & PROFILETEST_BIT(j)) != 0) || (j == PROFILETEST_A && (g->Without & PROFILETEST_BIT(i)) != 0))
	{
		return false;
	}

	return true;
}

// The desired state of node i in the Generation g
static CONTROL_STATE *ProfileTestState(PROFILETEST_NODE *nodes, PROFILETEST_GEN *g, UINT i)
{
	CONTROL_STATE *st = ZeroMalloc(sizeof(CONTROL_STATE));

	st->Generation = g->Generation;
	StrCpy(st->Name, sizeof(st->Name), profiletest_names[i]);
	st->NumAddresses = ProfileTestAddresses(i, st->Addresses);
	st->NumVrfs = 1;
	StrCpy(st->Vrfs[0].Name, sizeof(st->Vrfs[0].Name), "red");
	st->Vrfs[0].Id = PROFILETEST_VRF;
	if (g->Own)
	{
		Copy(&st->Profile, &g->Profiles[i], sizeof(CONTROL_PROFILE));
	}

	if (i == PROFILETEST_B)
	{
		st->RateLimit = g->RateB;
		ProfileTestNat(&st->Nats[st->NumNats++], PROFILETEST_NAT_INSIDE, PROFILETEST_NAT_OUTSIDE);
		ProfileTestNat(&st->Nats[st->NumNats++], PROFILETEST_NAT6_INSIDE, PROFILETEST_NAT6_OUTSIDE);
	}

	// The other nodes in name order, which is the order of their indexes
	st->Peers = ZeroMalloc(sizeof(CONTROL_PEER) * PROFILETEST_NODES);
	for (UINT j = 0;j < PROFILETEST_NODES;j++)
	{
		if (ProfileTestPeers(g, i, j) == false)
		{
			continue;
		}

		CONTROL_PEER *p = &st->Peers[st->NumPeers++];
		StrCpy(p->Name, sizeof(p->Name), profiletest_names[j]);
		Copy(p->Key, nodes[j].Key.Public, PEER_KEY_SIZE);
		p->NumVrfs = 1;
		p->VrfIds[0] = PROFILETEST_VRF;
		p->NumAddresses = ProfileTestAddresses(j, p->Addresses);
		if (j == PROFILETEST_B)
		{
			ProfileTestRoute(&p->Routes[p->NumRoutes++], PROFILETEST_NAT_OUTSIDE);
			ProfileTestRoute(&p->Routes[p->NumRoutes++], PROFILETEST_NAT6_OUTSIDE);
		}
		if (g->Peers)
		{
			Copy(&p->Profile, &g->Profiles[j], sizeof(CONTROL_PROFILE));
		}
	}

	return st;
}

// Apply the states of the Generation g to every node
static bool ProfileTestApply(PROFILETEST_NODE *nodes, PROFILETEST_GEN *g)
{
	bool ok = true;

	for (UINT i = 0;i < PROFILETEST_NODES;i++)
	{
		CONTROL_STATE *st = ProfileTestState(nodes, g, i);

		ok = NodeOverlayApply(nodes[i].Node, st) && ok;
		Free(st->Peers);
		Free(st);
	}

	return ok;
}

// The session of node i to node j as the overlay of node i reports it: whether it is up, and since when
static bool ProfileTestSession(PROFILETEST_NODE *nodes, UINT i, UINT j, UINT64 *since)
{
	NODE_OVERLAY_SESSION list[PROFILETEST_NODES];
	UINT num = NodeOverlayGetSessions(nodes[i].Node, list, PROFILETEST_NODES, NULL, 0);
	bool up = false;

	for (UINT k = 0;k < num && k < PROFILETEST_NODES;k++)
	{
		if (StrCmp(list[k].Name, profiletest_names[j]) == 0 && list[k].Up)
		{
			up = true;
			if (since != NULL)
			{
				*since = list[k].Since;
			}
		}
	}

	return up;
}

// The devices of alice whose sessions node-a holds, as bits of their indexes, and their number
static UINT ProfileTestAliceAtA(PROFILETEST_NODE *nodes, UINT *num)
{
	UINT bits = 0;

	*num = 0;
	for (UINT i = PROFILETEST_B;i <= PROFILETEST_D;i++)
	{
		if (ProfileTestSession(nodes, PROFILETEST_A, i, NULL))
		{
			bits |= PROFILETEST_BIT(i);
			(*num)++;
		}
	}

	return bits;
}

// Whether every node has the session to each of its peers in the Generation g within PROFILETEST_BOUND
static bool ProfileTestWaitLinks(PROFILETEST_NODE *nodes, PROFILETEST_GEN *g)
{
	UINT64 end = Tick64() + PROFILETEST_BOUND;

	while (true)
	{
		bool all = true;

		for (UINT i = 0;i < PROFILETEST_NODES && all;i++)
		{
			for (UINT j = 0;j < PROFILETEST_NODES && all;j++)
			{
				if (ProfileTestPeers(g, i, j) && ProfileTestSession(nodes, i, j, NULL) == false)
				{
					all = false;
				}
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
		SleepThread(PROFILETEST_POLL);
	}
}

// A packet of the host of t, sent while the test thread is an online reader of the node's tables
static bool ProfileTestInput(PROFILETEST_NODE *t, UCHAR *packet, UINT size)
{
	NodeReaderOnline(t->Node, &t->Reader);
	bool ok = NodeOverlayInput(t->Node, PROFILETEST_VRF, packet, size);
	NodeReaderOffline(&t->Reader);

	return ok;
}

// The profile name of the User user, with no limit and no flag, which the cases set
static void ProfileTestProfile(CONTROL_PROFILE *p, char *name, char *user)
{
	Zero(p, sizeof(CONTROL_PROFILE));
	p->Set = true;
	StrCpy(p->Name, sizeof(p->Name), name);
	StrCpy(p->User, sizeof(p->User), user);
}

// The Generation g of the number generation in which the devices of alice run under alice and the one of bob under bob,
// NULL for none, carried by the NodeConfigs when own is set and by the Peer objects when peers is
static void ProfileTestGen(PROFILETEST_GEN *g, UINT64 generation, CONTROL_PROFILE *alice, CONTROL_PROFILE *bob, bool own, bool peers)
{
	Zero(g, sizeof(PROFILETEST_GEN));
	g->Generation = generation;
	g->Own = own;
	g->Peers = peers;
	for (UINT i = PROFILETEST_B;alice != NULL && i <= PROFILETEST_D;i++)
	{
		Copy(&g->Profiles[i], alice, sizeof(CONTROL_PROFILE));
	}
	if (bob != NULL)
	{
		Copy(&g->Profiles[PROFILETEST_E], bob, sizeof(CONTROL_PROFILE));
	}
}

//
// The cases
//

// One case: node from sends a packet of the kind from its address src to the address dst of node to, and it must end as
// expect says, a drop counted in the counter of the reason at the node that drops it and at no other
static void ProfileTestCase(PROFILETEST_CTX *ctx, PROFILETEST_NODE *nodes, UINT from, UINT to, UINT kind, char *src, char *dst, UINT expect, UINT reason, char *what)
{
	static char *ends[] = {"is delivered", "is dropped by the sender", "is dropped by the receiver", "arrives changed or not at all"};
	UCHAR packet[PROFILETEST_MAX_PACKET];
	PROFILETEST_NODE *f = &nodes[from], *r = &nodes[to];
	UINT size = ProfileTestPacket(packet, kind, src, dst, ++ctx->NextId);
	UINT before = ProfileTestNumPackets(r);
	UINT64 dropped = ProfileTestDropped(r);
	UINT64 counts[PROFILETEST_NODES];
	UINT end = PROFILETEST_CHANGED;

	for (UINT i = 0;i < PROFILETEST_NODES;i++)
	{
		counts[i] = ProfileTestCounter(&nodes[i], reason);
	}

	if (size == 0 || ProfileTestInput(f, packet, size) == false)
	{
		end = PROFILETEST_AT_SENDER;
	}
	else
	{
		// The host of the receiver takes it, or its overlay drops it. A packet that an earlier case sent may reach the host
		// after this one was sent: the beats of the timeout cases go to node-b until the test sees its new session up at
		// node-a, so node-b may take the last of them once it reads that session. Such a packet is not the one of this case.
		UINT64 limit = Tick64() + PROFILETEST_BOUND;

		while (Tick64() < limit)
		{
			if (ProfileTestFind(r, before, packet, size))
			{
				end = PROFILETEST_DELIVERED;
				break;
			}
			if (ProfileTestDropped(r) != dropped)
			{
				end = PROFILETEST_AT_RECEIVER;
				break;
			}
			SleepThread(1);
		}
	}

	// The reason counts the drop at the node that dropped it, and at no other
	UINT at = (expect == PROFILETEST_AT_SENDER ? from : (expect == PROFILETEST_AT_RECEIVER ? to : PROFILETEST_NONE));
	bool counted = true;
	for (UINT i = 0;i < PROFILETEST_NODES && reason != PROFILETEST_NO_REASON;i++)
	{
		if (ProfileTestCounter(&nodes[i], reason) != counts[i] + (i == at ? 1 : 0))
		{
			counted = false;
		}
	}

	ProfileTestCheck(ctx, end == expect && counted, what, "it %s, and the drop is %s; the host of %s took %u packets meanwhile", ends[end],
		counted ? "counted as it must" : "not counted at the node that dropped it alone", r->Name, ProfileTestNumPackets(r) - before);
}

// The stream thread of s sends its packet as fast as the overlay of its node takes it
static DWORD WINAPI ProfileTestStreamThread(LPVOID param)
{
	PROFILETEST_STREAM *s = (PROFILETEST_STREAM *)param;
	NODE *n = s->From->Node;
	NODE_READER r;

	Zero(&r, sizeof(r));
	NodeReaderRegister(n, &r);

	s->Start = ProfileTestNow();
	while (InterlockedCompareExchange(&s->Stop, 0, 0) == 0)
	{
		if (NodeOverlayInput(n, PROFILETEST_VRF, s->Packet, s->Size))
		{
			s->Sent++;
		}
		else
		{
			s->Refused++;
		}
		NodeReaderQuiescent(n, &r);
	}
	s->End = ProfileTestNow();

	NodeReaderUnregister(n, &r);

	return 0;
}

// The stream of a rate case: node from sends datagrams of 1000 bytes to node to for PROFILETEST_RATE_TIME, and the host of to
// counts what it takes; false when the thread did not start
static bool ProfileTestStream(PROFILETEST_NODE *nodes, UINT from, UINT to, PROFILETEST_STREAM *s)
{
	PROFILETEST_NODE *r = &nodes[to];

	Zero(s, sizeof(PROFILETEST_STREAM));
	s->From = &nodes[from];
	s->Size = ProfileTestDatagram(s->Packet, profiletest_addrs[from][0], profiletest_addrs[to][0], 7, PROFILETEST_PAYLOAD);

	InterlockedExchange64(&r->Count, 0);
	InterlockedExchange64(&r->Last, 0);
	InterlockedExchange(&r->Counting, 1);

	HANDLE thread = (s->Size != 0 ? CreateThread(NULL, 0, ProfileTestStreamThread, s, 0, NULL) : NULL);
	if (thread == NULL)
	{
		InterlockedExchange(&r->Counting, 0);
		return false;
	}

	SleepThread(PROFILETEST_RATE_TIME);
	InterlockedExchange(&s->Stop, 1);
	WaitForSingleObject(thread, INFINITE);
	CloseHandle(thread);

	return true;
}

// The bytes that a bucket of rate bits per second lets through from full in ns nanoseconds: its burst, then the rate
static UINT64 ProfileTestAllowed(UINT64 rate, UINT64 ns)
{
	UINT64 burst = MAX(rate / 8 * NODE_PROFILE_BURST / 1000, (UINT64)NODE_PROFILE_MIN_BURST);

	return burst + rate / 8 * ns / PROFILETEST_NS;
}

// The rate cases: the download limit of node-b at node-a on the way to it, then its upload limit at node-a on the way from it
static void ProfileTestRates(PROFILETEST_CTX *ctx, PROFILETEST_NODE *nodes)
{
	PROFILETEST_STREAM *s = ZeroMalloc(sizeof(PROFILETEST_STREAM));
	NODE_PROFILE_STATUS before, after;
	char what[MAX_SIZE];

	// The download: node-a sends to node-b, and every packet that its overlay sent arrives
	NodeProfileGetStatus(nodes[PROFILETEST_A].Node, &before);
	bool ok = ProfileTestStream(nodes, PROFILETEST_A, PROFILETEST_B, s);
	UINT64 end = Tick64() + PROFILETEST_BOUND;
	while ((UINT64)InterlockedCompareExchange64(&nodes[PROFILETEST_B].Count, 0, 0) < s->Sent && Tick64() < end)
	{
		SleepThread(PROFILETEST_POLL);
	}
	InterlockedExchange(&nodes[PROFILETEST_B].Counting, 0);
	NodeProfileGetStatus(nodes[PROFILETEST_A].Node, &after);

	UINT64 ns = s->End - s->Start;
	UINT64 bytes = s->Sent * s->Size;
	UINT64 allowed = ProfileTestAllowed(PROFILETEST_DOWNLOAD, ns);
	UINT64 low = allowed * PROFILETEST_LOW / 100, high = allowed + s->Size;
	UINT64 arrived = (UINT64)InterlockedCompareExchange64(&nodes[PROFILETEST_B].Count, 0, 0);

	Print("  the download of node-b limited to %u bit/s, %I64u ms: node-a sent %I64u bytes (%I64u packets dropped), at most %I64u allowed; %I64u packets arrived\n",
		(UINT)PROFILETEST_DOWNLOAD, ns / 1000000, bytes, s->Refused, allowed, arrived);
	Format(what, sizeof(what), "The download limit of alice of %u bit/s shapes what node-a sends to node-b: the burst of its bucket and the rate over the time, and every packet sent arrives",
		(UINT)PROFILETEST_DOWNLOAD);
	ProfileTestCheck(ctx, ok && bytes >= low && bytes <= high && s->Refused != 0 && arrived == s->Sent && after.Download - before.Download == s->Refused, what,
		"%I64u bytes in %I64u ms, between %I64u and %I64u expected; %I64u of %I64u packets arrived; %I64u dropped, %I64u counted", bytes, ns / 1000000, low, high, arrived,
		s->Sent, s->Refused, after.Download - before.Download);

	// The upload: node-b, paced by its own rate limit, sends to node-a, which takes the burst and the rate and drops the rest
	NodeProfileGetStatus(nodes[PROFILETEST_A].Node, &before);
	ok = ProfileTestStream(nodes, PROFILETEST_B, PROFILETEST_A, s);
	UINT64 taken = 0, limited = 0;
	end = Tick64() + PROFILETEST_BOUND;
	while (Tick64() < end)
	{
		NodeProfileGetStatus(nodes[PROFILETEST_A].Node, &after);
		taken = (UINT64)InterlockedCompareExchange64(&nodes[PROFILETEST_A].Count, 0, 0);
		limited = after.Upload - before.Upload;
		if (taken + limited >= s->Sent)
		{
			break;
		}
		SleepThread(PROFILETEST_POLL);
	}
	InterlockedExchange(&nodes[PROFILETEST_A].Counting, 0);

	UINT64 last = (UINT64)InterlockedCompareExchange64(&nodes[PROFILETEST_A].Last, 0, 0);
	ns = (last > s->Start ? last - s->Start : 0);
	bytes = taken * s->Size;
	allowed = ProfileTestAllowed(PROFILETEST_UPLOAD, ns);
	low = allowed * PROFILETEST_LOW / 100;
	high = allowed + s->Size;

	Print("  the upload of node-b limited to %u bit/s and paced at %u bit/s, %I64u ms: node-b sent %I64u packets, node-a took %I64u bytes and dropped %I64u packets, at most %I64u allowed\n",
		(UINT)PROFILETEST_UPLOAD, (UINT)PROFILETEST_PACE, ns / 1000000, s->Sent, bytes, limited, allowed);
	Format(what, sizeof(what), "The upload limit of alice of %u bit/s shapes what node-a takes from node-b: the burst of its bucket and the rate over the time, and node-a drops the rest",
		(UINT)PROFILETEST_UPLOAD);
	ProfileTestCheck(ctx, ok && bytes >= low && bytes <= high && limited != 0 && taken + limited == s->Sent, what,
		"%I64u bytes in %I64u ms, between %I64u and %I64u expected; of %I64u packets sent %I64u taken and %I64u dropped", bytes, ns / 1000000, low, high, s->Sent, taken, limited);

	Free(s);
}

// The flags at the peers: the Peer objects carry the profile of alice, the NodeConfigs do not
static void ProfileTestFlagsAtPeers(PROFILETEST_CTX *ctx, PROFILETEST_NODE *nodes)
{
	char *a4 = "10.0.0.1", *a6 = "fd00::1", *b4 = "10.0.0.2", *b6 = "fd00::2", *c4 = "10.0.0.3";

	// No-server
	ProfileTestCase(ctx, nodes, PROFILETEST_A, PROFILETEST_B, PROFILETEST_SYN, a4, b4, PROFILETEST_AT_SENDER, PROFILETEST_SERVER,
		"No-server at the peer: node-a drops a TCP SYN to node-b");
	ProfileTestCase(ctx, nodes, PROFILETEST_A, PROFILETEST_B, PROFILETEST_SYN_HOP, a6, b6, PROFILETEST_AT_SENDER, PROFILETEST_SERVER,
		"No-server at the peer: node-a drops a TCP SYN to node-b behind a hop-by-hop options header of IPv6");
	ProfileTestCase(ctx, nodes, PROFILETEST_A, PROFILETEST_B, PROFILETEST_ACK, a4, b4, PROFILETEST_DELIVERED, PROFILETEST_SERVER,
		"No-server at the peer: a TCP segment that is no SYN reaches node-b");
	ProfileTestCase(ctx, nodes, PROFILETEST_A, PROFILETEST_B, PROFILETEST_UDP, a6, b6, PROFILETEST_DELIVERED, PROFILETEST_SERVER,
		"No-server at the peer: UDP reaches node-b");
	ProfileTestCase(ctx, nodes, PROFILETEST_B, PROFILETEST_A, PROFILETEST_SYN, b4, a4, PROFILETEST_DELIVERED, PROFILETEST_SERVER,
		"No-server at the peer: a TCP SYN of node-b reaches node-a, as node-b may open connections");
	ProfileTestCase(ctx, nodes, PROFILETEST_B, PROFILETEST_A, PROFILETEST_SYN_ACK, b4, a4, PROFILETEST_AT_RECEIVER, PROFILETEST_SERVER,
		"No-server at the peer: node-a drops the SYN-ACK of node-b, which would accept a connection");

	// No-routing: the outside prefixes of the NAT rules of node-b are routes of node-b, not addresses of its own. A packet that
	// no-routing drops takes none of the addresses that the counts below let node-b send from.
	ProfileTestCase(ctx, nodes, PROFILETEST_A, PROFILETEST_B, PROFILETEST_UDP, a4, PROFILETEST_ROUTED, PROFILETEST_AT_SENDER, PROFILETEST_ROUTING,
		"No-routing at the peer: node-a drops a packet to the outside of the NAT rule of node-b");
	ProfileTestCase(ctx, nodes, PROFILETEST_B, PROFILETEST_A, PROFILETEST_UDP, PROFILETEST_LAN_HOST, a4, PROFILETEST_AT_RECEIVER, PROFILETEST_ROUTING,
		"No-routing at the peer: node-a drops the packet of the LAN behind node-b, which node-b translates to its outside");
	ProfileTestCase(ctx, nodes, PROFILETEST_A, PROFILETEST_B, PROFILETEST_UDP, a4, b4, PROFILETEST_DELIVERED, PROFILETEST_ROUTING,
		"No-routing at the peer: a packet to the own address of node-b reaches it");
	ProfileTestCase(ctx, nodes, PROFILETEST_A, PROFILETEST_B, PROFILETEST_UDP, a6, PROFILETEST_ROUTED6, PROFILETEST_AT_SENDER, PROFILETEST_ROUTING,
		"No-routing at the peer: node-a drops an IPv6 packet to the outside of the IPv6 NAT rule of node-b");
	ProfileTestCase(ctx, nodes, PROFILETEST_B, PROFILETEST_A, PROFILETEST_UDP, PROFILETEST_LAN6_HOST, a6, PROFILETEST_AT_RECEIVER, PROFILETEST_ROUTING,
		"No-routing at the peer: node-a drops the IPv6 packet of the LAN behind node-b, which node-b translates to its outside");
	ProfileTestCase(ctx, nodes, PROFILETEST_A, PROFILETEST_B, PROFILETEST_UDP, a6, b6, PROFILETEST_DELIVERED, PROFILETEST_ROUTING,
		"No-routing at the peer: an IPv6 packet to the own address of node-b reaches it");

	// The counts: the SYN of node-b above came from 10.0.0.2, its first IPv4 address at node-a
	ProfileTestCase(ctx, nodes, PROFILETEST_B, PROFILETEST_A, PROFILETEST_UDP, "10.0.0.12", a4, PROFILETEST_DELIVERED, PROFILETEST_ADDRESSES,
		"The counts: node-a takes the second IPv4 address that node-b sends from");
	ProfileTestCase(ctx, nodes, PROFILETEST_B, PROFILETEST_A, PROFILETEST_UDP, "10.0.0.22", a4, PROFILETEST_AT_RECEIVER, PROFILETEST_ADDRESSES,
		"The counts: node-a drops a packet of node-b from a third IPv4 address, beyond the 2 of alice");
	ProfileTestCase(ctx, nodes, PROFILETEST_B, PROFILETEST_A, PROFILETEST_UDP, b4, a4, PROFILETEST_DELIVERED, PROFILETEST_ADDRESSES,
		"The counts: node-a takes the first address of node-b again");
	ProfileTestCase(ctx, nodes, PROFILETEST_B, PROFILETEST_A, PROFILETEST_UDP, b6, a6, PROFILETEST_DELIVERED, PROFILETEST_ADDRESSES,
		"The counts: node-a takes the first IPv6 address that node-b sends from");
	ProfileTestCase(ctx, nodes, PROFILETEST_B, PROFILETEST_A, PROFILETEST_UDP, "fd00::12", a6, PROFILETEST_AT_RECEIVER, PROFILETEST_ADDRESSES,
		"The counts: node-a drops a packet of node-b from a second IPv6 address, beyond the 1 of alice");

	// The privacy filter needs the profiles of both ends: neither node-b nor node-c runs under its own here
	ProfileTestCase(ctx, nodes, PROFILETEST_B, PROFILETEST_C, PROFILETEST_ICMP, b4, c4, PROFILETEST_DELIVERED, PROFILETEST_ISOLATED,
		"The privacy filter at the peers alone: node-b reaches node-c, as neither runs under the filter itself");
}

// The flags on the devices themselves: the NodeConfigs carry the profile of alice, the Peer objects do not
static void ProfileTestFlagsOwn(PROFILETEST_CTX *ctx, PROFILETEST_NODE *nodes)
{
	char *a4 = "10.0.0.1", *a6 = "fd00::1", *b4 = "10.0.0.2", *b6 = "fd00::2", *c4 = "10.0.0.3";

	ProfileTestCase(ctx, nodes, PROFILETEST_A, PROFILETEST_B, PROFILETEST_SYN, a4, b4, PROFILETEST_AT_RECEIVER, PROFILETEST_SERVER,
		"No-server on the device: node-b drops the TCP SYN of node-a to its host");
	ProfileTestCase(ctx, nodes, PROFILETEST_B, PROFILETEST_A, PROFILETEST_SYN_ACK, b4, a4, PROFILETEST_AT_SENDER, PROFILETEST_SERVER,
		"No-server on the device: node-b drops the SYN-ACK of its host");
	ProfileTestCase(ctx, nodes, PROFILETEST_B, PROFILETEST_A, PROFILETEST_SYN, b4, a4, PROFILETEST_DELIVERED, PROFILETEST_SERVER,
		"No-server on the device: the TCP SYN of its host leaves node-b");
	ProfileTestCase(ctx, nodes, PROFILETEST_A, PROFILETEST_B, PROFILETEST_UDP, a4, PROFILETEST_ROUTED, PROFILETEST_AT_RECEIVER, PROFILETEST_ROUTING,
		"No-routing on the device: node-b drops a packet to the outside of its NAT rule");
	ProfileTestCase(ctx, nodes, PROFILETEST_B, PROFILETEST_A, PROFILETEST_UDP, PROFILETEST_LAN_HOST, a4, PROFILETEST_AT_SENDER, PROFILETEST_ROUTING,
		"No-routing on the device: node-b drops the packet of its LAN, which its NAT rule translates");
	ProfileTestCase(ctx, nodes, PROFILETEST_A, PROFILETEST_B, PROFILETEST_UDP, a6, PROFILETEST_ROUTED6, PROFILETEST_AT_RECEIVER, PROFILETEST_ROUTING,
		"No-routing on the device: node-b drops an IPv6 packet to the outside of its IPv6 NAT rule");
	ProfileTestCase(ctx, nodes, PROFILETEST_B, PROFILETEST_A, PROFILETEST_UDP, PROFILETEST_LAN6_HOST, a6, PROFILETEST_AT_SENDER, PROFILETEST_ROUTING,
		"No-routing on the device: node-b drops the IPv6 packet of its LAN, which its IPv6 NAT rule translates");
	ProfileTestCase(ctx, nodes, PROFILETEST_B, PROFILETEST_A, PROFILETEST_UDP, b6, a6, PROFILETEST_DELIVERED, PROFILETEST_ROUTING,
		"No-routing on the device: an IPv6 packet from the own address of node-b leaves it");
	ProfileTestCase(ctx, nodes, PROFILETEST_B, PROFILETEST_C, PROFILETEST_ICMP, b4, c4, PROFILETEST_DELIVERED, PROFILETEST_ISOLATED,
		"The privacy filter on the devices alone: node-b reaches node-c, as neither holds the profile of the other");
}

// The flags at both: the NodeConfigs and the Peer objects carry the profiles, alice with the privacy filter and no-server,
// bob with neither
static void ProfileTestFlagsBoth(PROFILETEST_CTX *ctx, PROFILETEST_NODE *nodes)
{
	char *a4 = "10.0.0.1", *b4 = "10.0.0.2", *c4 = "10.0.0.3", *e4 = "10.0.0.5";

	ProfileTestCase(ctx, nodes, PROFILETEST_B, PROFILETEST_C, PROFILETEST_ICMP, b4, c4, PROFILETEST_AT_SENDER, PROFILETEST_ISOLATED,
		"The privacy filter: node-b does not reach node-c, both devices under it");
	ProfileTestCase(ctx, nodes, PROFILETEST_C, PROFILETEST_B, PROFILETEST_ICMP, c4, b4, PROFILETEST_AT_SENDER, PROFILETEST_ISOLATED,
		"The privacy filter: node-c does not reach node-b");
	ProfileTestCase(ctx, nodes, PROFILETEST_B, PROFILETEST_A, PROFILETEST_ICMP, b4, a4, PROFILETEST_DELIVERED, PROFILETEST_ISOLATED,
		"The privacy filter: node-b reaches node-a, which runs under no profile");
	ProfileTestCase(ctx, nodes, PROFILETEST_A, PROFILETEST_B, PROFILETEST_ICMP, a4, b4, PROFILETEST_DELIVERED, PROFILETEST_ISOLATED,
		"The privacy filter: node-a reaches node-b");
	ProfileTestCase(ctx, nodes, PROFILETEST_B, PROFILETEST_E, PROFILETEST_ICMP, b4, e4, PROFILETEST_DELIVERED, PROFILETEST_ISOLATED,
		"The privacy filter: node-b reaches node-e, whose profile has none");
	ProfileTestCase(ctx, nodes, PROFILETEST_E, PROFILETEST_B, PROFILETEST_ICMP, e4, b4, PROFILETEST_DELIVERED, PROFILETEST_ISOLATED,
		"The privacy filter: node-e reaches node-b");
	ProfileTestCase(ctx, nodes, PROFILETEST_A, PROFILETEST_B, PROFILETEST_SYN, a4, b4, PROFILETEST_AT_SENDER, PROFILETEST_SERVER,
		"No-server at both: node-a drops the TCP SYN to node-b first");
}

// The session case: alice under at most 2 sessions at a node, bob under 1, and the devices hold node-a alone as a peer, so
// that node-a is the one node that holds more than one device of alice. The devices of alice leave node-a, so that their
// sessions come up again under the profile: node-a then holds 2 of them and the one of bob, and refuses the third while the
// two are up; once node-a drops one of the two, the third comes up.
static void ProfileTestSessions(PROFILETEST_CTX *ctx, PROFILETEST_NODE *nodes, CONTROL_PROFILE *alice, CONTROL_PROFILE *bob, UINT64 *generation)
{
	PROFILETEST_GEN g;
	NODE_PROFILE_STATUS st;
	UINT num = 0, held = 0;
	char what[MAX_SIZE];

	alice->MaxSessions = 2;
	bob->MaxSessions = 1;
	ProfileTestGen(&g, ++(*generation), alice, bob, true, true);
	g.Spokes = true;
	g.Without = PROFILETEST_BIT(PROFILETEST_B) | PROFILETEST_BIT(PROFILETEST_C) | PROFILETEST_BIT(PROFILETEST_D);
	bool ok = ProfileTestApply(nodes, &g) && ProfileTestWaitLinks(nodes, &g);
	UINT64 limit = Tick64() + PROFILETEST_BOUND;
	while (ProfileTestAliceAtA(nodes, &num) != 0 && Tick64() < limit)
	{
		SleepThread(PROFILETEST_POLL);
	}
	ProfileTestCheck(ctx, ok && num == 0, "Sessions: the devices of alice leave node-a, and node-e keeps its session", "applied and linked %u, %u of alice at node-a", (UINT)ok, num);

	NodeProfileGetStatus(nodes[PROFILETEST_A].Node, &st);
	UINT64 refused = st.Refused;

	g.Generation = ++(*generation);
	g.Without = 0;
	ok = ProfileTestApply(nodes, &g);

	// node-a holds 2 of the 3 and refuses the third
	UINT64 end = Tick64() + PROFILETEST_BOUND;
	while (Tick64() < end)
	{
		held = ProfileTestAliceAtA(nodes, &num);
		NodeProfileGetStatus(nodes[PROFILETEST_A].Node, &st);
		if (num == 2 && st.Refused > refused)
		{
			break;
		}
		SleepThread(PROFILETEST_POLL);
	}
	Format(what, sizeof(what), "Sessions: node-a holds 2 sessions of the 3 devices of alice and refuses the third, under the most of 2 sessions of alice");
	ProfileTestCheck(ctx, ok && num == 2 && st.Refused > refused, what, "applied %u, %u sessions of alice, %I64u refused", (UINT)ok, num, st.Refused - refused);

	// ... while the two are up, as long as they stay
	SleepThread(PROFILETEST_STABLE);
	UINT now = ProfileTestAliceAtA(nodes, &num);
	ProfileTestCheck(ctx, now == held && num == 2 && ProfileTestSession(nodes, PROFILETEST_A, PROFILETEST_E, NULL),
		"Sessions: the third device of alice stays refused while the two others are up, and node-a holds the one device of bob under his most of 1",
		"devices 0x%x then 0x%x of alice, node-e %s", held, now, ProfileTestSession(nodes, PROFILETEST_A, PROFILETEST_E, NULL) ? "up" : "down");

	// node-a drops one of the two: the third comes up
	UINT first = PROFILETEST_NONE, third = PROFILETEST_NONE;
	for (UINT i = PROFILETEST_B;i <= PROFILETEST_D;i++)
	{
		if ((held & PROFILETEST_BIT(i)) != 0 && first == PROFILETEST_NONE)
		{
			first = i;
		}
		if ((held & PROFILETEST_BIT(i)) == 0)
		{
			third = i;
		}
	}

	g.Generation = ++(*generation);
	g.Without = (first < PROFILETEST_NODES ? PROFILETEST_BIT(first) : 0);
	ok = ProfileTestApply(nodes, &g);
	end = Tick64() + PROFILETEST_BOUND;
	while (Tick64() < end)
	{
		now = ProfileTestAliceAtA(nodes, &num);
		if (third < PROFILETEST_NODES && (now & PROFILETEST_BIT(third)) != 0 && num == 2)
		{
			break;
		}
		SleepThread(PROFILETEST_POLL);
	}
	ProfileTestCheck(ctx, ok && first < PROFILETEST_NODES && third < PROFILETEST_NODES && (now & PROFILETEST_BIT(third)) != 0 && (now & PROFILETEST_BIT(first)) == 0 && num == 2,
		"Sessions: once node-a drops one of the two devices of alice, the third comes up, and node-a holds 2 again", "applied %u, devices 0x%x, %u sessions", (UINT)ok, now, num);

	// Every device back at node-a, under no most of sessions
	alice->MaxSessions = 0;
	bob->MaxSessions = 0;
	ProfileTestGen(&g, ++(*generation), alice, bob, true, true);
	ok = ProfileTestApply(nodes, &g) && ProfileTestWaitLinks(nodes, &g);
	ProfileTestCheck(ctx, ok, "Sessions: without a most of sessions every device of alice has its session to node-a again", "applied and linked %u", (UINT)ok);
}

// A UDP datagram from node-a to node-b, which refreshes their session: whether the overlay of node-a sent it
static bool ProfileTestBeat(PROFILETEST_CTX *ctx, PROFILETEST_NODE *nodes)
{
	UCHAR packet[PROFILETEST_MAX_PACKET];
	UINT size = ProfileTestPacket(packet, PROFILETEST_UDP, "10.0.0.1", "10.0.0.2", ++ctx->NextId);

	return ProfileTestInput(&nodes[PROFILETEST_A], packet, size);
}

// The idle timeout: under PROFILETEST_TIMEOUT s, the session of node-b at node-a stays while node-a sends to it every
// PROFILETEST_BEAT ms, and ends that long after the last packet; node-b dials again. The times are the GetTickCount64 of
// the overlay, which says when a session came up.
static void ProfileTestIdle(PROFILETEST_CTX *ctx, PROFILETEST_NODE *nodes, CONTROL_PROFILE *alice, UINT64 *generation)
{
	PROFILETEST_GEN g;
	NODE_PROFILE_STATUS st;
	UINT64 since = 0, again = 0;

	// node-b alone runs under the idle timeout. A packet just before the Generation goes in keeps its session to node-a from
	// having idled under the profile before it, which ran under none of it.
	ProfileTestGen(&g, ++(*generation), NULL, NULL, true, true);
	Copy(&g.Profiles[PROFILETEST_B], alice, sizeof(CONTROL_PROFILE));
	g.Profiles[PROFILETEST_B].IdleTimeout = PROFILETEST_TIMEOUT;
	bool ok = ProfileTestBeat(ctx, nodes) && ProfileTestApply(nodes, &g) && ProfileTestSession(nodes, PROFILETEST_A, PROFILETEST_B, &since);
	NodeProfileGetStatus(nodes[PROFILETEST_A].Node, &st);
	UINT64 idle = st.Idle;

	// Packets every PROFILETEST_BEAT ms for twice the timeout: the session stays
	UINT64 end = GetTickCount64() + PROFILETEST_TIMEOUT * 2000;
	UINT64 last = GetTickCount64();
	UINT sent = 0;
	while (ok && GetTickCount64() < end)
	{
		if (ProfileTestBeat(ctx, nodes))
		{
			sent++;
			last = GetTickCount64();
		}
		SleepThread(PROFILETEST_BEAT);
	}
	UINT64 still = 0;
	bool up = ProfileTestSession(nodes, PROFILETEST_A, PROFILETEST_B, &still);
	NodeProfileGetStatus(nodes[PROFILETEST_A].Node, &st);
	ProfileTestCheck(ctx, ok && sent != 0 && up && still == since && st.Idle == idle,
		"Idle timeout: the session of node-b at node-a stays while a packet goes every 250 ms, for twice its idle timeout of 2 s",
		"applied %u, %u packets, up %u, the same session %u, %I64u ended", (UINT)ok, sent, (UINT)up, (UINT)(still == since), st.Idle - idle);

	// No packet: node-a ends it that long after the last, and node-b dials again
	end = last + PROFILETEST_TIMEOUT * 1000 + PROFILETEST_SLACK + PROFILETEST_BOUND;
	UINT64 ended = 0;
	while (GetTickCount64() < end)
	{
		NodeProfileGetStatus(nodes[PROFILETEST_A].Node, &st);
		if (ended == 0 && st.Idle != idle)
		{
			ended = GetTickCount64();
		}
		if (ended != 0 && ProfileTestSession(nodes, PROFILETEST_A, PROFILETEST_B, &again) && again > since)
		{
			break;
		}
		SleepThread(PROFILETEST_POLL);
	}
	UINT64 after = (ended > last ? ended - last : 0);
	ProfileTestCheck(ctx, ended != 0 && after + 300 >= PROFILETEST_TIMEOUT * 1000 && after <= PROFILETEST_TIMEOUT * 1000 + PROFILETEST_SLACK && again > since,
		"Idle timeout: node-a ends the session of node-b 2 s after its last packet, and node-b dials again",
		"ended %I64u ms after the last packet, a new session %u", after, (UINT)(again > since));
}

// The automatic disconnect: under PROFILETEST_TIMEOUT s, the session of node-b at node-a ends that long after it came up,
// while packets flow; node-b dials again. The times are the GetTickCount64 of the overlay.
static void ProfileTestDisconnect(PROFILETEST_CTX *ctx, PROFILETEST_NODE *nodes, CONTROL_PROFILE *alice, UINT64 *generation)
{
	PROFILETEST_GEN g;
	NODE_PROFILE_STATUS st;
	UINT64 since = 0, again = 0;

	ProfileTestGen(&g, ++(*generation), NULL, NULL, true, true);
	Copy(&g.Profiles[PROFILETEST_B], alice, sizeof(CONTROL_PROFILE));
	g.Profiles[PROFILETEST_B].AutoDisconnect = PROFILETEST_TIMEOUT;
	UINT64 applied = GetTickCount64();
	bool ok = ProfileTestApply(nodes, &g);

	// A session of node-b that came up under the Generation: the one before it, which came up earlier, may end first
	UINT64 end = applied + PROFILETEST_TIMEOUT * 1000 + PROFILETEST_SLACK + PROFILETEST_BOUND;
	while (GetTickCount64() < end && (ProfileTestSession(nodes, PROFILETEST_A, PROFILETEST_B, &since) == false || since < applied))
	{
		ProfileTestBeat(ctx, nodes);
		SleepThread(PROFILETEST_POLL);
	}
	NodeProfileGetStatus(nodes[PROFILETEST_A].Node, &st);
	UINT64 disconnected = st.Disconnected;

	// Packets flow until node-a ends it and node-b dials again
	end = since + PROFILETEST_TIMEOUT * 1000 + PROFILETEST_SLACK + PROFILETEST_BOUND;
	UINT64 ended = 0;
	UINT sent = 0;
	while (ok && since >= applied && GetTickCount64() < end)
	{
		if (ProfileTestBeat(ctx, nodes))
		{
			sent++;
		}
		NodeProfileGetStatus(nodes[PROFILETEST_A].Node, &st);
		if (ended == 0 && st.Disconnected != disconnected)
		{
			ended = GetTickCount64();
		}
		if (ended != 0 && ProfileTestSession(nodes, PROFILETEST_A, PROFILETEST_B, &again) && again > since)
		{
			break;
		}
		SleepThread(PROFILETEST_BEAT / 5);
	}
	UINT64 after = (ended > since ? ended - since : 0);
	ProfileTestCheck(ctx, ok && ended != 0 && sent != 0 && after + 300 >= PROFILETEST_TIMEOUT * 1000 && after <= PROFILETEST_TIMEOUT * 1000 + PROFILETEST_SLACK && again > since,
		"Automatic disconnect: node-a ends the session of node-b 2 s after it came up while packets flow, and node-b dials again",
		"applied %u, %u packets, ended %I64u ms after the session came up, a new session %u", (UINT)ok, sent, after, (UINT)(again > since));
}

// An Ethernet frame of an IPv4 UDP datagram from the MAC address src_mac and the address src to dst_mac and dst: its size
static UINT ProfileTestFrame(UCHAR *f, UCHAR *dst_mac, UCHAR *src_mac, char *src, char *dst)
{
	Copy(f, dst_mac, 6);
	Copy(f + 6, src_mac, 6);
	WRITE_USHORT(f + 12, 0x0800);

	return 14 + ProfileTestDatagram(f + 14, src, dst, 1, 16);
}

// The procedure of a port of the switch of the L2 case, on the thread of SwitchInput: it counts the frames that the port
// delivers, and keeps the last
static void ProfileTestPortSend(void *param, UINT port, const UCHAR *frame, UINT size)
{
	PROFILETEST_PORT *p = (PROFILETEST_PORT *)param;

	p->NumFrames++;
	p->Size = size;
	Copy(p->Frame, frame, MIN(size, (UINT)sizeof(p->Frame)));
}

// The ports of the L2 case, but the one of member to, that delivered a frame of the current case
static UINT ProfileTestStrays(PROFILETEST_PORT *ports, UINT to)
{
	UINT num = 0;

	for (UINT i = 0;i < PROFILETEST_L2_MEMBERS;i++)
	{
		if (i != to && ports[i].NumFrames != 0)
		{
			num++;
		}
	}

	return num;
}

// The L2 case: the switch of an L2 Network with the policy engine as its filter (Core/SwitchSecurity.h), as the L2 data path
// of a node runs it, and a port for the session of each device, whose member carries the guard of the profile of the device
// (NodeProfileMember) in a Network that turns on no protection of its own, so that only the profiles refuse a frame. Every
// session first sends from its first MAC address, which the switch learns; then the frame of each case goes from one
// session to the first address of another, and reaches the port of that one alone, or goes nowhere for the reason of the
// guard and leaves no address in the MAC table.
static void ProfileTestL2(PROFILETEST_CTX *ctx)
{
	static const char doc[] = "{\"networks\": [{\"name\": \"lan\", \"mode\": \"l2\"}], \"rules\": [{\"name\": \"starter\", \"action\": \"allow\", \"priority\": 1000000}]}";
	static char *names[PROFILETEST_L2_MEMBERS] = {"two-macs", "no-bridge", "isolated-1", "isolated-2", "plain"};
	static UCHAR broadcast[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
	// The addresses that the MAC table learns: member, then its MAC address
	static const UINT learnt[PROFILETEST_L2_LEARNT][2] = {{0, 0}, {0, 1}, {1, 0}, {2, 0}, {3, 0}, {4, 0}, {4, 1}, {4, 2}};
	CONTROL_PROFILE p[PROFILETEST_L2_MEMBERS];
	PROFILETEST_PORT ports[PROFILETEST_L2_MEMBERS];
	UCHAR macs[PROFILETEST_L2_MEMBERS][3][6];
	UCHAR f[PROFILETEST_MAX_PACKET];
	SWITCH_MAC_ENTRY list[PROFILETEST_L2_LEARNT * 2];
	SWITCH_SECURITY sec;
	SWITCH_CONFIG sc;
	SWITCH_STATS sb, sa;
	POLICY_STATS pb, pa;
	char error[MAX_SIZE], src[MAX_SIZE], dst[MAX_SIZE];

	// The profiles: 2 MAC addresses, no-bridge, the privacy filter twice, and none
	for (UINT i = 0;i < 4;i++)
	{
		ProfileTestProfile(&p[i], "l2", "alice");
	}
	Zero(&p[4], sizeof(CONTROL_PROFILE));
	p[0].MaxMacs = 2;
	p[1].NoBridge = true;
	p[2].PrivacyFilter = true;
	p[3].PrivacyFilter = true;

	// The policy engine with the document of the L2 Network, and the switch of the Network with the engine as its filter
	POLICY_ENGINE *e = PolicyNew(16);
	bool ok = (e != NULL && PolicySetRules(e, doc, StrLen(doc), error, sizeof(error)));
	Zero(&sc, sizeof(sc));
	sc.MaxPorts = PROFILETEST_L2_MEMBERS;
	sc.MaxMacs = 64;
	SwitchSecurityFilter(&sc, e);
	SWITCH *sw = (ok ? SwitchNew(&sc) : NULL);
	ok = (ok && sw != NULL);

	// A member and an access port of the VLAN of the Network for each session: the guard of its profile, then the security
	// of the Network, which adds nothing
	Zero(&sec, sizeof(sec));
	Zero(ports, sizeof(ports));
	for (UINT i = 0;i < PROFILETEST_L2_MEMBERS;i++)
	{
		POLICY_MEMBER_CONFIG c;
		SWITCH_PORT_CONFIG pc;

		Zero(&c, sizeof(c));
		c.Network = "lan";
		c.User = (i < 4 ? "alice" : NULL);
		NodeProfileMember(&p[i], &c);
		ports[i].Member = (ok ? SwitchSecurityMember(e, &c, &sec, SWITCH_CLIENT) : POLICY_NO_MEMBER);

		Zero(&pc, sizeof(pc));
		pc.Mode = SWITCH_ACCESS;
		pc.Vlan = PROFILETEST_L2_VLAN;
		pc.Send = ProfileTestPortSend;
		pc.Param = &ports[i];
		pc.Member = ports[i].Member;
		ports[i].Port = (ok ? SwitchAddPort(sw, &pc) : SWITCH_PORT_NONE);
		ok = (ok && ports[i].Member != POLICY_NO_MEMBER && ports[i].Port != SWITCH_PORT_NONE);

		for (UINT k = 0;k < 3;k++)
		{
			UCHAR mac[6] = {0x02, 0x52, 0x5A, 0x40, (UCHAR)i, (UCHAR)k};

			Copy(macs[i][k], mac, 6);
		}
	}

	// Every session sends from its first MAC address to the broadcast address, which no port takes yet: the switch learns
	// the address on its port
	for (UINT i = 0;i < PROFILETEST_L2_MEMBERS && ok;i++)
	{
		Format(src, sizeof(src), "10.20.0.%u", 10 + i * 3);
		UINT size = ProfileTestFrame(f, broadcast, macs[i][0], src, "10.20.0.255");

		SwitchInput(sw, PROFILETEST_L2_NOW, ports[i].Port, f, size);
	}
	SwitchGetStats(sw, &sa);
	if (ProfileTestCheck(ctx, ok && sa.NumMacs == PROFILETEST_L2_MEMBERS,
		"L2: the switch of the L2 Network, with the policy engine as its filter, takes a port for each session and learns the first MAC address of each",
		"made %u, %u addresses learnt", (UINT)ok, sa.NumMacs) == false)
	{
		SwitchFree(sw);
		PolicyFree(e);
		return;
	}

	// The frame of member From from its MAC address Mac to the first address of member To: it reaches the port of To alone,
	// or the filter of the switch refuses it for Reason and it goes nowhere
	struct
	{
		UINT From;
		UINT Mac;
		UINT To;
		bool Pass;
		UINT Reason;
		char *What;
	} cases[] =
	{
		{0, 0, 4, true, 0, "L2: the session under 2 MAC addresses sends from its first"},
		{0, 1, 4, true, 0, "L2: ... and from its second"},
		{0, 2, 4, false, POLICY_DROP_MAC, "L2: ... and not from a third: the frame goes nowhere"},
		{0, 0, 4, true, 0, "L2: ... and from its first again"},
		{1, 0, 4, true, 0, "L2: the session under no-bridge sends from its first MAC address"},
		{1, 1, 4, false, POLICY_DROP_MAC, "L2: ... and from no other, so no LAN behind it is bridged"},
		{2, 0, 3, false, POLICY_DROP_ISOLATED, "L2: the privacy filter keeps two sessions under it apart"},
		{3, 0, 2, false, POLICY_DROP_ISOLATED, "L2: ... both ways"},
		{2, 0, 4, true, 0, "L2: a session under the privacy filter reaches one under none"},
		{4, 0, 2, true, 0, "L2: ... and that one reaches it"},
		{4, 1, 0, true, 0, "L2: a session under no profile sends from a second MAC address ..."},
		{4, 2, 0, true, 0, "L2: ... and from a third"},
	};

	for (UINT i = 0;i < sizeof(cases) / sizeof(cases[0]);i++)
	{
		UINT from = cases[i].From, to = cases[i].To;

		Format(src, sizeof(src), "10.20.0.%u", 10 + from * 3 + cases[i].Mac);
		Format(dst, sizeof(dst), "10.20.0.%u", 10 + to * 3);
		UINT size = ProfileTestFrame(f, macs[to][0], macs[from][cases[i].Mac], src, dst);

		for (UINT k = 0;k < PROFILETEST_L2_MEMBERS;k++)
		{
			ports[k].NumFrames = 0;
		}
		SwitchGetStats(sw, &sb);
		PolicyGetStats(e, &pb);
		UINT reached = SwitchInput(sw, PROFILETEST_L2_NOW, ports[from].Port, f, size);
		SwitchGetStats(sw, &sa);
		PolicyGetStats(e, &pa);

		UINT64 refused = sa.Drops[SWITCH_DROP_FILTER] - sb.Drops[SWITCH_DROP_FILTER];
		UINT strays = ProfileTestStrays(ports, to);
		bool got = (ports[to].NumFrames == 1 && ports[to].Size == size && Cmp(ports[to].Frame, f, MIN(size, (UINT)sizeof(ports[to].Frame))) == 0);
		bool pass = (reached == 1 && got && refused == 0);
		bool dropped = (reached == 0 && ports[to].NumFrames == 0 && refused == 1 && pa.Reasons[cases[i].Reason] == pb.Reasons[cases[i].Reason] + 1);

		ProfileTestCheck(ctx, strays == 0 && (cases[i].Pass ? pass : dropped), cases[i].What,
			"the frame of %s from its MAC address %u went to %u ports, %u of them not the port of %s; the filter of the switch refused %I64u", names[from], cases[i].Mac,
			reached, strays, names[to], refused);
	}

	// A broadcast of a session under the privacy filter reaches the session under none, and not the other session under it
	ok = (SwitchSubscribe(sw, ports[3].Port, PROFILETEST_L2_VLAN, broadcast) && SwitchSubscribe(sw, ports[4].Port, PROFILETEST_L2_VLAN, broadcast));
	for (UINT k = 0;k < PROFILETEST_L2_MEMBERS;k++)
	{
		ports[k].NumFrames = 0;
	}
	UINT size = ProfileTestFrame(f, broadcast, macs[2][0], "10.20.0.16", "10.20.0.255");
	UINT reached = SwitchInput(sw, PROFILETEST_L2_NOW, ports[2].Port, f, size);
	ProfileTestCheck(ctx, ok && reached == 1 && ports[4].NumFrames == 1 && ProfileTestStrays(ports, 4) == 0,
		"L2: a broadcast of a session under the privacy filter reaches the session under none, and not the other session under it",
		"subscribed %u, it went to %u ports: isolated-2 got %u frames, plain %u", (UINT)ok, reached, ports[3].NumFrames, ports[4].NumFrames);

	// The MAC table holds the addresses that the sessions sent from, each on its port, and none that the filter refused
	UINT num = SwitchGetMacs(sw, list, PROFILETEST_L2_LEARNT * 2), found = 0;
	for (UINT i = 0;i < PROFILETEST_L2_LEARNT;i++)
	{
		UINT m = learnt[i][0];

		for (UINT k = 0;k < num;k++)
		{
			if (list[k].Port == ports[m].Port && Cmp(list[k].Mac, macs[m][learnt[i][1]], 6) == 0)
			{
				found++;
				break;
			}
		}
	}
	ProfileTestCheck(ctx, num == PROFILETEST_L2_LEARNT && found == PROFILETEST_L2_LEARNT,
		"L2: the MAC table holds the addresses that the sessions sent from, each on its port, and none of those that the filter refused",
		"%u entries, %u of the %u expected", num, found, (UINT)PROFILETEST_L2_LEARNT);

	// The switch calls the engine: it goes first
	SwitchFree(sw);
	PolicyFree(e);
}

// profile: the session profiles of the devices of a User in the data plane of a node
RANZ_TEST("profile", profile_test, "Session profiles of the overlay: upload and download limits shape a session, the counts of sessions and addresses refuse one more, the idle timeout and the automatic disconnect end a session, no-routing, no-server and the privacy filter block what they name, and the MAC addresses, no-bridge and the privacy filter of a session on the switch of an L2 Network.");
void profile_test(UINT num, char **arg)
{
	PROFILETEST_CTX ctx;
	PROFILETEST_NODE *nodes = ZeroMalloc(sizeof(PROFILETEST_NODE) * PROFILETEST_NODES);
	TRANSPORT *loopback = TransportLoopbackNew("loopback", 0, false);
	HANDLE done = CreateEventW(NULL, TRUE, FALSE, NULL);
	HANDLE watchdog = (done != NULL ? CreateThread(NULL, 0, ProfileTestWatchdog, done, 0, NULL) : NULL);
	PEER_KEY keys[PROFILETEST_NODES];
	CONTROL_PROFILE alice, bob;
	PROFILETEST_GEN g;
	UCHAR scalar[PEER_KEY_SIZE];
	char what[MAX_SIZE];
	UINT64 generation = 0;
	bool started = (loopback != NULL);

	Zero(&ctx, sizeof(ctx));
	Zero(keys, sizeof(keys));

	Print("Session profile test: rates, counts, sessions, timeouts and the flags of the profiles of the devices of a User\n");

	// The static keys (the scalars 1, 2, ... of the conformance tests), the greatest public key for node-a, so that the
	// devices dial it
	UINT greatest = 0;
	for (UINT i = 0;i < PROFILETEST_NODES && started;i++)
	{
		for (UINT j = 0;j < PEER_KEY_SIZE;j++)
		{
			scalar[j] = (UCHAR)(1 + PEER_KEY_SIZE * i + j);
		}
		started = PeerKeyFromScalar(&keys[i], scalar);
		if (started && Cmp(keys[i].Public, keys[greatest].Public, PEER_KEY_SIZE) > 0)
		{
			greatest = i;
		}
	}
	Zero(scalar, sizeof(scalar));

	// The nodes, each with the fake adapter of its host, and their overlays without a control stream
	for (UINT i = 0;i < PROFILETEST_NODES && started;i++)
	{
		PROFILETEST_NODE *t = &nodes[i];
		NODE_OVERLAY_CONFIG c;
		UINT k = (i == PROFILETEST_A ? greatest : (i == greatest ? PROFILETEST_A : i));

		t->Name = profiletest_names[i];
		Copy(&t->Key, &keys[k], sizeof(PEER_KEY));
		InitializeSRWLock(&t->Lock);
		t->Packets = NewListFast(NULL);

		ProfileTestNewDir(t->Dir, sizeof(t->Dir), t->Name);
		t->Node = NewNode(t->Dir);
		NodeStart(t->Node);
		NodeReaderRegister(t->Node, &t->Reader);
		NodeReaderOffline(&t->Reader);

		Zero(&c, sizeof(c));
		c.Data = loopback;
		c.Key = &t->Key;
		c.Adapter = ProfileTestAdapter;
		c.AdapterParam = t;
		Format(what, sizeof(what), "%s: its overlay runs without a control stream", t->Name);
		started = ProfileTestCheck(&ctx, NodeOverlayStart(t->Node, &c), what, "NodeOverlayStart failed") && started;
	}
	Zero(keys, sizeof(keys));

	// Generation 1: no profile, every session up, and a SYN to node-b passes
	if (started)
	{
		ProfileTestGen(&g, ++generation, NULL, NULL, true, true);
		bool applied = ProfileTestApply(nodes, &g);
		bool linked = ProfileTestWaitLinks(nodes, &g);
		started = ProfileTestCheck(&ctx, applied && linked, "The five nodes apply a Generation without profiles, and every session is up", "applied %u, linked %u", (UINT)applied, (UINT)linked);
		ProfileTestCase(&ctx, nodes, PROFILETEST_A, PROFILETEST_B, PROFILETEST_SYN, "10.0.0.1", "10.0.0.2", PROFILETEST_DELIVERED, PROFILETEST_SERVER,
			"Without a profile a TCP SYN reaches node-b");
	}

	if (started)
	{
		NODE_PROFILE_STATUS st;

		ProfileTestProfile(&alice, "laptops", "alice");
		ProfileTestProfile(&bob, "contractors", "bob");

		// The rates, with node-b paced by its own rate limit
		alice.UploadLimit = PROFILETEST_UPLOAD;
		alice.DownloadLimit = PROFILETEST_DOWNLOAD;
		ProfileTestGen(&g, ++generation, &alice, &bob, true, true);
		g.RateB = PROFILETEST_PACE;
		ProfileTestCheck(&ctx, ProfileTestApply(nodes, &g), "The nodes apply the Generation of the rate limits of alice", "not applied");
		NodeProfileGetStatus(nodes[PROFILETEST_B].Node, &st);
		ProfileTestCheck(&ctx, st.Own.Set && StrCmp(st.Own.Name, "laptops") == 0 && StrCmp(st.Own.User, "alice") == 0 && st.NumPeers == 3,
			"node-b runs under SessionProfile laptops of alice, and 3 of its peers under a profile", "%s %s of %s, %u peers", st.Own.Set ? "under" : "not under", st.Own.Name,
			st.Own.User, st.NumPeers);
		ProfileTestRates(&ctx, nodes);
		alice.UploadLimit = 0;
		alice.DownloadLimit = 0;

		// The flags at the peers, with the counts
		alice.MaxIpv4 = 2;
		alice.MaxIpv6 = 1;
		alice.NoServer = true;
		alice.NoRouting = true;
		alice.PrivacyFilter = true;
		ProfileTestGen(&g, ++generation, &alice, &bob, false, true);
		ProfileTestCheck(&ctx, ProfileTestApply(nodes, &g), "The nodes apply the Generation of the flags at the peers", "not applied");
		ProfileTestFlagsAtPeers(&ctx, nodes);
		alice.MaxIpv4 = 0;
		alice.MaxIpv6 = 0;

		// The flags on the devices themselves
		ProfileTestGen(&g, ++generation, &alice, &bob, true, false);
		ProfileTestCheck(&ctx, ProfileTestApply(nodes, &g), "The nodes apply the Generation of the flags on the devices", "not applied");
		ProfileTestFlagsOwn(&ctx, nodes);

		// The flags at both
		alice.NoRouting = false;
		ProfileTestGen(&g, ++generation, &alice, &bob, true, true);
		ProfileTestCheck(&ctx, ProfileTestApply(nodes, &g), "The nodes apply the Generation of the flags at both", "not applied");
		ProfileTestFlagsBoth(&ctx, nodes);
		alice.NoServer = false;
		alice.PrivacyFilter = false;

		// The sessions, the idle timeout and the automatic disconnect
		ProfileTestSessions(&ctx, nodes, &alice, &bob, &generation);
		ProfileTestIdle(&ctx, nodes, &alice, &generation);
		ProfileTestDisconnect(&ctx, nodes, &alice, &generation);

		// A Generation without profiles lets everything through again
		ProfileTestGen(&g, ++generation, NULL, NULL, true, true);
		bool applied = ProfileTestApply(nodes, &g) && ProfileTestWaitLinks(nodes, &g);
		ProfileTestCheck(&ctx, applied, "The nodes apply a Generation without profiles again, and every session is up", "applied and linked %u", (UINT)applied);
		ProfileTestCase(&ctx, nodes, PROFILETEST_A, PROFILETEST_B, PROFILETEST_SYN, "10.0.0.1", "10.0.0.2", PROFILETEST_DELIVERED, PROFILETEST_SERVER,
			"Without a profile again a TCP SYN reaches node-b");
		NodeProfileGetStatus(nodes[PROFILETEST_A].Node, &st);
		ProfileTestCheck(&ctx, st.Own.Set == false && st.NumPeers == 0, "Without a profile node-a holds none of its own and none of its peers", "%u, %u peers", (UINT)st.Own.Set, st.NumPeers);
	}

	ProfileTestL2(&ctx);

	// The nodes stop, every thread is joined
	for (UINT i = 0;i < PROFILETEST_NODES;i++)
	{
		PROFILETEST_NODE *t = &nodes[i];
		wchar_t log_dir[MAX_PATH];

		if (t->Node != NULL)
		{
			NodeReaderUnregister(t->Node, &t->Reader);
			NodeStop(t->Node);
			FreeNode(t->Node);
			ConbinePathW(log_dir, sizeof(log_dir), t->Dir, NODE_LOG_DIR_NAME);
			ProfileTestDeleteFiles(log_dir);
			ProfileTestDeleteFiles(t->Dir);
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
		Print("PROFILE TEST OK\n");
	}
	else
	{
		Print("PROFILE TEST FAILED (%u of %u checks failed)\n", ctx.NumFailed, ctx.NumChecks);
	}
}
