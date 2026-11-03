// kmtesttest.c
// Named KM-TEST adapter test of vpntest ("kmtest" command, CORE-S3-2 #72)
//
// The L2 adapter of the node on a real Microsoft KM-TEST Loopback Adapter (Cedar/NodeKmTest.c, Cedar/NodeL2.c), with the
// backend that the host gives it: XDP for Windows where ranz install installed its runtime, SeLow where it did not (ranz
// install --no-xdp), found at run time. The XDP job of windows.yml runs it on Windows Server 2022 and 2025 x64 as
// administrator (.github/scripts/kmtest.ps1); it needs the drivers, so the smoke loop leaves it out
// (.github/quality/smoke-exclude.txt). Its argument is the backend that the host must give: "xdp" (the default) or
// "selow"; the second argument "quick" leaves out the long parts (the paused consumer and the benchmark), "soak" with a
// number of seconds runs the soak alone, and "bare" measures only senders with USO, on an adapter without an L2 adapter
// and on adapters with one (KMTEST DIAG lines).
// - The adapter: NodeKmTestNew creates a KM-TEST adapter with the MAC address of NodeL2Mac, which Windows reports for its
//   interface, and finds the same adapter again; a second Network gets a second adapter with another address. With XDP,
//   the number of queues that an AF_XDP socket binds to is measured (#72, multi-queue), and the L2 adapter binds all of
//   them.
// - TX inspect: UDP datagrams that the host's stack sends to a neighbour on the adapter are captured, from the MAC
//   address of the adapter. RX inject: IPv4/UDP frames that the node sends to the host reach a UDP socket bound to the
//   adapter's address, and the host answers an ARP request that the node injects with an ARP reply that is captured.
// - An L2 Network with LAN discovery: the adapter is an access port of VLAN 10 of an L2 switch (Core/Switch.c) whose
//   other port is a peer subscribed to every group. The ARP, IGMP, LLMNR and NetBIOS frames of the host reach the peer,
//   and the peer's ARP request reaches the host, whose reply comes back to the peer. Broadcasts of the host beyond the
//   broadcast limit of VLAN 10 are dropped and counted there, while VLAN 20 forwards every broadcast.
// - The paused consumer (#72, risk R1; XDP): four sender threads with USO (UDP_SEND_MSG_SIZE) flood the adapter while
//   the owner of the adapter stops taking frames for 10 s. No send() blocks for 1 s, the drops of the capture ring rise,
//   and within 2 s of the owner going on, the capture rate is back at half its baseline at least. The same with plain
//   send(), and with the AF_XDP rings undersized.
// - The benchmark (ADR-0022 amendment of 2026-10-19; XDP): RX inject at batch sizes 1, 16, 64 and 256 and TX capture,
//   in packets per second, printed as KMTEST BENCH lines: a regression number of the runner, not a gate (ADR-0002
//   amendment of 2026-10-21).
// - Health, recovery and shutdown (#72, risks R2 and R3): the probes of the receive path succeed and cause no
//   reattach; NodeL2Recover reattaches the backend and the frames flow again; NodeL2Free takes the adapter down within
//   its timeouts.
// Prints "KMTEST TEST OK" only when every check passes.

#include "testlist.h"

#include "Cedar/ConfigStore.h"
#include "Cedar/Node.h"
#include "Cedar/NodeL2.h"

#include "Mayaqua/FileIO.h"
#include "Mayaqua/Internat.h"
#include "Mayaqua/Kernel.h"
#include "Mayaqua/Memory.h"
#include "Mayaqua/Microsoft.h"
#include "Mayaqua/Str.h"

#include "Core/Switch.h"

#include <iphlpapi.h>

#include <stdio.h>

#ifndef	UDP_SEND_MSG_SIZE
#define	UDP_SEND_MSG_SIZE		2			// ws2ipdef.h of Windows 10 version 1703 on: USO, the size of each datagram of a send
#endif

#define	KMTEST_BUDGET			600000		// The whole test ends within this time, or the watchdog ends the process (ms)
#define	KMTEST_BOUND			15000		// A bounded wait on observable state (ms)
#define	KMTEST_POLL				20			// Poll interval of observable state (ms)
#define	KMTEST_NETWORK			72			// The Network ids of the two adapters
#define	KMTEST_NETWORK2			73
#define	KMTEST_NETWORK3			74			// ... and of the adapter of the measurement "bare"
#define	KMTEST_BARE_TIME		3000		// ms that the senders of "bare" send
#define	KMTEST_LENGTH			24			// The prefix length of the address of an adapter
#define	KMTEST_TX_PORT			5555		// UDP port of the datagrams that the host sends to the neighbour
#define	KMTEST_RX_PORT			5556		// UDP port of the socket that takes the injected datagrams
#define	KMTEST_BENCH_PORT		5557		// UDP port of the sink of the benchmark
#define	KMTEST_FLOOD_PORT		9			// UDP port of the broadcasts beyond the limit
#define	KMTEST_LLMNR_PORT		5355
#define	KMTEST_NETBIOS_PORT		137
#define	KMTEST_SENDERS			4			// Sender threads of the paused consumer
#define	KMTEST_SEGMENT			1472		// Bytes of a datagram of the senders: frames of 1514 bytes
#define	KMTEST_SEGMENTS			44			// Datagrams of one send() with USO
#define	KMTEST_PAUSE			10000		// ms that the owner stops taking frames
#define	KMTEST_BASELINE			2000		// ms over which the capture rate is measured before the pause
#define	KMTEST_BLOCK_LIMIT		1000000		// Microseconds that no send() may block
#define	KMTEST_BENCH_TIME		2000		// ms of each benchmark run
#define	KMTEST_LIMIT			20			// The broadcast limit of VLAN 10, frames per second
#define	KMTEST_FLOOD			500			// Broadcasts of the host beyond the limit
#define	KMTEST_VLAN				10			// The VLAN of the adapter in the switch
#define	KMTEST_VLAN2			20			// The VLAN of two members of the test
#define	KMTEST_ARP_FRAME		60			// Bytes of an ARP frame, padded to the shortest Ethernet frame
#define	KMTEST_SOAK_PHASE		10000		// ms of each phase of the soak
#define	KMTEST_SOAK_PHASES		10			// The phases of one round of the soak

// What a frame of the host is
#define	KMTEST_KIND_OTHER		0
#define	KMTEST_KIND_TX			1			// A UDP datagram of the host to KMTEST_TX_PORT
#define	KMTEST_KIND_ARP			2			// An ARP request
#define	KMTEST_KIND_ARP_REPLY	3			// An ARP reply
#define	KMTEST_KIND_IGMP		4
#define	KMTEST_KIND_LLMNR		5
#define	KMTEST_KIND_NETBIOS		6
#define	KMTEST_KIND_FLOOD		7			// A broadcast to KMTEST_FLOOD_PORT
#define	KMTEST_KINDS			8

static char *kmtest_kind_names[KMTEST_KINDS] = {"other", "UDP to the neighbour", "ARP request", "ARP reply", "IGMP", "LLMNR", "NetBIOS", "broadcast"};

// The MAC addresses of the neighbour of the adapter (a permanent neighbour entry), of the prober of the ARP check and of
// the peer of the switch
static UCHAR kmtest_neighbour_mac[6] = {0x02, 0x00, 0x00, 0x00, 0x72, 0x02};
static UCHAR kmtest_prober_mac[6] = {0x02, 0x00, 0x00, 0x00, 0x72, 0x03};
static UCHAR kmtest_peer_mac[6] = {0x02, 0x00, 0x00, 0x00, 0x72, 0x04};

// The time that the watchdog gives the run: KMTEST_BUDGET, and the soak on top
static DWORD kmtest_budget = KMTEST_BUDGET;

// The checks of the test, and the senders that stayed blocked in send(): an adapter is not removed then, as its removal
// would wait for their frames
typedef struct KMTEST_CTX
{
	UINT NumChecks;
	UINT NumFailed;
	UINT Stuck;
} KMTEST_CTX;

// The owner of the adapter: it counts the frames of the host by kind, and hands each to the switch when one is set. It
// waits while it is paused.
typedef struct KMTEST_OWNER
{
	volatile LONG Paused;						// The owner waits for Resume while this is set
	HANDLE Resume;
	volatile LONG64 Frames;						// Frames that it got
	volatile LONG64 Kinds[KMTEST_KINDS];		// ... by kind
	volatile LONG64 FromAdapter;				// ... of the kind KMTEST_KIND_TX from the MAC address of the adapter
	volatile LONG64 RepliesToProber;			// ARP replies to the prober
	UCHAR Mac[6];								// The MAC address of the adapter
	SRWLOCK Lock;								// Switch and HostPort
	SWITCH *Switch;								// The switch, NULL for none
	UINT HostPort;								// ... and the port of the adapter
} KMTEST_OWNER;

// A member of the switch that the test plays: it counts what the switch delivers to it, by kind
typedef struct KMTEST_PEER
{
	volatile LONG64 Frames;
	volatile LONG64 Kinds[KMTEST_KINDS];
	volatile LONG64 RepliesToPeer;				// ARP replies to the peer's MAC address
} KMTEST_PEER;

// One adapter of the test
typedef struct KMTEST_ADAPTER
{
	NODE_KMTEST *KmTest;
	UINT IfIndex;
	UINT64 Luid;
	UCHAR Mac[6];
	UINT Address;					// Its IPv4 address: 198.18.<Network>.1
	UINT Neighbour;					// ... .2, the permanent neighbour
	UINT Prober;					// ... .3, the prober of the ARP check
	UINT Peer;						// ... .4, the peer of the switch
	UINT Unknown;					// ... .9, an address that no one has
	UINT Broadcast;					// ... .255
	KMTEST_OWNER Owner;
	NODE_L2 *L2;
} KMTEST_ADAPTER;

// A sender thread
typedef struct KMTEST_SENDER
{
	SOCKET Sock;
	USHORT Port;					// Its local UDP port
	bool Uso;
	UINT Size;						// Bytes of the payload of a datagram (KMTEST_SEGMENT for frames of 1514 bytes)
	UINT Segments;					// Datagrams of one send() with USO, KMTEST_SEGMENTS at most
	volatile LONG64 LastSend;		// GetTickCount64() after the last send() that went through
	volatile LONG *Stop;
	HANDLE Thread;
	bool Stuck;						// Still blocked in send() when it was stopped
	volatile LONG64 Sends;
	volatile LONG64 Errors;
	volatile LONG LastError;		// The Winsock error of the last send() that failed
	volatile LONG64 SlowestUs;
} KMTEST_SENDER;

// The senders of a part of the test and the flag that stops them. They are on the heap of the process, outside the
// memory that Mayaqua counts: a sender that stays blocked in send() keeps them, and the test leaves them to its thread.
typedef struct KMTEST_SENDER_SET
{
	volatile LONG Stop;
	UINT64 Stopped;					// GetTickCount64() when they were stopped
	KMTEST_SENDER Senders[KMTEST_SENDERS];
} KMTEST_SENDER_SET;

// The sink of the benchmark
typedef struct KMTEST_SINK
{
	SOCKET Sock;
	volatile LONG Stop;
	HANDLE Thread;
	volatile LONG64 Received;
} KMTEST_SINK;

static bool KmCheck(KMTEST_CTX *ctx, bool ok, char *what, char *fmt, ...) RANZ_PRINTF_FORMAT(4, 5);
static bool KmCheck(KMTEST_CTX *ctx, bool ok, char *what, char *fmt, ...)
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

// The watchdog: a native thread that ends a run that hangs, so that a stuck driver is a failed test instead of a hung CI step
static DWORD WINAPI KmWatchdog(LPVOID param)
{
	char msg[MAX_SIZE];
	DWORD written = 0;

	if (WaitForSingleObject((HANDLE)param, kmtest_budget) != WAIT_TIMEOUT)
	{
		return 0;
	}

	int len = snprintf(msg, sizeof(msg), "KMTEST TEST FAILED (did not finish within %u ms)\n", (UINT)kmtest_budget);
	if (len > 0)
	{
		WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), msg, (DWORD)MIN((UINT)len, (UINT)sizeof(msg) - 1), &written, NULL);
	}

	TerminateProcess(GetCurrentProcess(), 1);

	return 0;
}

// An IPv4 address of four bytes, in network byte order
static UINT KmAddr(UCHAR a, UCHAR b, UCHAR c, UCHAR d)
{
	UCHAR x[4];
	UINT ret = 0;

	x[0] = a;
	x[1] = b;
	x[2] = c;
	x[3] = d;
	Copy(&ret, x, 4);

	return ret;
}

// Wait up to KMTEST_BOUND ms until *value reaches at least want; false when it does not
static bool KmWait64(volatile LONG64 *value, LONG64 want)
{
	UINT64 end = GetTickCount64() + KMTEST_BOUND;

	while (ReadAcquire64(value) < want)
	{
		if (GetTickCount64() >= end)
		{
			return false;
		}
		Sleep(KMTEST_POLL);
	}

	return true;
}

//
// Frames
//

// The kind of a frame of the host
static UINT KmKind(const UCHAR *f, UINT size)
{
	if (size < 14)
	{
		return KMTEST_KIND_OTHER;
	}

	USHORT type = (USHORT)((f[12] << 8) | f[13]);

	if (type == 0x0806 && size >= 42)
	{
		USHORT op = (USHORT)((f[20] << 8) | f[21]);
		return (op == 1 ? KMTEST_KIND_ARP : (op == 2 ? KMTEST_KIND_ARP_REPLY : KMTEST_KIND_OTHER));
	}

	if (type != 0x0800 || size < 14 + 20)
	{
		return KMTEST_KIND_OTHER;
	}

	UINT ihl = (UINT)(f[14] & 0x0F) * 4;
	UCHAR proto = f[14 + 9];

	if (proto == 2)
	{
		return KMTEST_KIND_IGMP;
	}

	if (proto != 17 || ihl < 20 || size < 14 + ihl + 8)
	{
		return KMTEST_KIND_OTHER;
	}

	USHORT port = (USHORT)((f[14 + ihl + 2] << 8) | f[14 + ihl + 3]);
	switch (port)
	{
	case KMTEST_TX_PORT:
		return KMTEST_KIND_TX;
	case KMTEST_LLMNR_PORT:
		return KMTEST_KIND_LLMNR;
	case KMTEST_NETBIOS_PORT:
	case KMTEST_NETBIOS_PORT + 1:
		return KMTEST_KIND_NETBIOS;
	case KMTEST_FLOOD_PORT:
		return KMTEST_KIND_FLOOD;
	}

	return KMTEST_KIND_OTHER;
}

// An IPv4/UDP frame into f from src to dst (addresses and ports), with payload_size bytes of payload; its size. The UDP
// checksum is 0, which IPv4 allows.
static UINT KmUdpFrame(UCHAR *f, const UCHAR *dst_mac, const UCHAR *src_mac, UINT src, UINT dst, USHORT sport, USHORT dport, UINT payload_size)
{
	UCHAR *ip = f + 14;
	UCHAR *udp = ip + 20;
	UINT ip_len = 20 + 8 + payload_size;
	UINT sum = 0;

	Zero(f, 14 + ip_len);
	Copy(f, dst_mac, 6);
	Copy(f + 6, src_mac, 6);
	f[12] = 0x08;
	f[13] = 0x00;

	ip[0] = 0x45;
	ip[2] = (UCHAR)(ip_len >> 8);
	ip[3] = (UCHAR)ip_len;
	ip[8] = 64;
	ip[9] = 17;
	Copy(ip + 12, &src, 4);
	Copy(ip + 16, &dst, 4);
	for (UINT i = 0;i < 20;i += 2)
	{
		sum += (UINT)((ip[i] << 8) | ip[i + 1]);
	}
	while ((sum >> 16) != 0)
	{
		sum = (sum & 0xFFFF) + (sum >> 16);
	}
	sum = ~sum & 0xFFFF;
	ip[10] = (UCHAR)(sum >> 8);
	ip[11] = (UCHAR)sum;

	udp[0] = (UCHAR)(sport >> 8);
	udp[1] = (UCHAR)sport;
	udp[2] = (UCHAR)(dport >> 8);
	udp[3] = (UCHAR)dport;
	udp[4] = (UCHAR)((8 + payload_size) >> 8);
	udp[5] = (UCHAR)(8 + payload_size);
	for (UINT i = 0;i < payload_size;i++)
	{
		udp[8 + i] = (UCHAR)('a' + i % 26);
	}

	return 14 + ip_len;
}

// An ARP request into f, broadcast from the MAC address mac and the address src for the address target; its size
static UINT KmArpRequest(UCHAR *f, const UCHAR *mac, UINT src, UINT target)
{
	Zero(f, KMTEST_ARP_FRAME);
	memset(f, 0xFF, 6);
	Copy(f + 6, mac, 6);
	f[12] = 0x08;
	f[13] = 0x06;
	f[15] = 0x01;		// Ethernet
	f[16] = 0x08;		// IPv4
	f[18] = 6;
	f[19] = 4;
	f[21] = 1;			// A request
	Copy(f + 22, mac, 6);
	Copy(f + 28, &src, 4);
	Copy(f + 38, &target, 4);

	return KMTEST_ARP_FRAME;
}

//
// The owner and the switch
//

// The owner of the adapter: counts the frame by kind, then hands it to the switch when one is set
static void KmOwnerProc(NODE_L2 *a, void *param, const UCHAR *frame, UINT size)
{
	KMTEST_OWNER *o = (KMTEST_OWNER *)param;
	UINT kind = KmKind(frame, size);

	if (ReadAcquire(&o->Paused) != 0)
	{
		WaitForSingleObject(o->Resume, KMTEST_PAUSE * 2);
	}

	InterlockedIncrement64(&o->Frames);
	InterlockedIncrement64(&o->Kinds[kind]);
	if (kind == KMTEST_KIND_TX && Cmp(frame + 6, o->Mac, 6) == 0)
	{
		InterlockedIncrement64(&o->FromAdapter);
	}
	if (kind == KMTEST_KIND_ARP_REPLY && Cmp(frame, kmtest_prober_mac, 6) == 0)
	{
		InterlockedIncrement64(&o->RepliesToProber);
	}

	AcquireSRWLockShared(&o->Lock);
	if (o->Switch != NULL)
	{
		SwitchInput(o->Switch, GetTickCount64(), o->HostPort, frame, size);
	}
	ReleaseSRWLockShared(&o->Lock);
}

// The port of the adapter in the switch: what the switch delivers to it goes to the host
static void KmSwitchToHost(void *param, UINT port, const UCHAR *frame, UINT size)
{
	NodeL2Send((NODE_L2 *)param, frame, size);
}

// A member of the switch that the test plays: counts by kind
static void KmSwitchToPeer(void *param, UINT port, const UCHAR *frame, UINT size)
{
	KMTEST_PEER *p = (KMTEST_PEER *)param;
	UINT kind = KmKind(frame, size);

	InterlockedIncrement64(&p->Frames);
	InterlockedIncrement64(&p->Kinds[kind]);
	if (kind == KMTEST_KIND_ARP_REPLY && Cmp(frame, kmtest_peer_mac, 6) == 0)
	{
		InterlockedIncrement64(&p->RepliesToPeer);
	}
}

//
// The host's stack
//

// A UDP socket bound to the address addr and port port (0 for any)
static SOCKET KmSocket(UINT addr, USHORT port)
{
	SOCKADDR_IN sa;
	SOCKET s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);

	if (s == INVALID_SOCKET)
	{
		return s;
	}

	Zero(&sa, sizeof(sa));
	sa.sin_family = AF_INET;
	sa.sin_addr.s_addr = addr;
	sa.sin_port = htons(port);
	if (bind(s, (SOCKADDR *)&sa, sizeof(sa)) != 0)
	{
		closesocket(s);
		return INVALID_SOCKET;
	}

	return s;
}

// Send num datagrams of size bytes from the socket s to the address dst and port port
static UINT KmSendTo(SOCKET s, UINT dst, USHORT port, UINT num, UINT size)
{
	char buf[KMTEST_SEGMENT];
	SOCKADDR_IN sa;
	UINT sent = 0;

	Zero(buf, sizeof(buf));
	Zero(&sa, sizeof(sa));
	sa.sin_family = AF_INET;
	sa.sin_addr.s_addr = dst;
	sa.sin_port = htons(port);

	for (UINT i = 0;i < num;i++)
	{
		if (sendto(s, buf, (int)MIN(size, (UINT)sizeof(buf)), 0, (SOCKADDR *)&sa, sizeof(sa)) > 0)
		{
			sent++;
		}
	}

	return sent;
}

// Give the adapter its IPv4 address and the permanent neighbour, and wait until the address is preferred; false, with the
// step that failed and its error in error, when one does not succeed. NodeKmTestNew returned the adapter once the IPv4
// stack of the host had its interface, so the address is not refused for an interface that the stack does not know yet.
static bool KmSetUp(KMTEST_ADAPTER *x, char *error, UINT error_size)
{
	MIB_UNICASTIPADDRESS_ROW row;
	MIB_IPNET_ROW2 nb;

	InitializeUnicastIpAddressEntry(&row);
	row.InterfaceLuid.Value = x->Luid;
	row.Address.Ipv4.sin_family = AF_INET;
	row.Address.Ipv4.sin_addr.s_addr = x->Address;
	row.OnLinkPrefixLength = KMTEST_LENGTH;
	row.DadState = IpDadStatePreferred;
	DWORD err = CreateUnicastIpAddressEntry(&row);
	if (err != NO_ERROR && err != ERROR_OBJECT_ALREADY_EXISTS)
	{
		Format(error, error_size, "CreateUnicastIpAddressEntry: error %u", (UINT)err);
		return false;
	}

	Zero(&nb, sizeof(nb));
	nb.InterfaceLuid.Value = x->Luid;
	nb.Address.Ipv4.sin_family = AF_INET;
	nb.Address.Ipv4.sin_addr.s_addr = x->Neighbour;
	Copy(nb.PhysicalAddress, kmtest_neighbour_mac, 6);
	nb.PhysicalAddressLength = 6;
	nb.State = NlnsPermanent;
	err = CreateIpNetEntry2(&nb);
	if (err != NO_ERROR && err != ERROR_OBJECT_ALREADY_EXISTS)
	{
		Format(error, error_size, "CreateIpNetEntry2: error %u", (UINT)err);
		return false;
	}

	UINT state = 0;
	for (UINT64 end = GetTickCount64() + KMTEST_BOUND;GetTickCount64() < end;Sleep(100))
	{
		MIB_UNICASTIPADDRESS_ROW r;

		InitializeUnicastIpAddressEntry(&r);
		r.InterfaceLuid.Value = x->Luid;
		r.Address.Ipv4.sin_family = AF_INET;
		r.Address.Ipv4.sin_addr.s_addr = x->Address;
		err = GetUnicastIpAddressEntry(&r);
		if (err == NO_ERROR && r.DadState == IpDadStatePreferred)
		{
			return true;
		}
		state = (UINT)r.DadState;
	}

	Format(error, error_size, "the address did not become preferred within %u ms (GetUnicastIpAddressEntry: error %u, DAD state %u)", KMTEST_BOUND, (UINT)err, state);
	return false;
}

// The KM-TEST adapter of the Network network_id on the node n, with the MAC address of the static key key
static bool KmNewAdapter(KMTEST_CTX *ctx, KMTEST_ADAPTER *x, NODE *n, const UCHAR *key, UINT network_id)
{
	MIB_IF_ROW2 row;
	NET_LUID luid;
	char error[MAX_SIZE];

	Zero(x, sizeof(KMTEST_ADAPTER));
	NodeL2Mac(x->Mac, key, network_id);
	x->Address = KmAddr(198, 18, (UCHAR)network_id, 1);
	x->Neighbour = KmAddr(198, 18, (UCHAR)network_id, 2);
	x->Prober = KmAddr(198, 18, (UCHAR)network_id, 3);
	x->Peer = KmAddr(198, 18, (UCHAR)network_id, 4);
	x->Unknown = KmAddr(198, 18, (UCHAR)network_id, 9);
	x->Broadcast = KmAddr(198, 18, (UCHAR)network_id, 255);
	x->Owner.Resume = CreateEventW(NULL, TRUE, FALSE, NULL);
	InitializeSRWLock(&x->Owner.Lock);
	Copy(x->Owner.Mac, x->Mac, 6);

	x->KmTest = NodeKmTestNew(n, x->Mac);
	x->IfIndex = NodeKmTestIndex(x->KmTest);

	Zero(&row, sizeof(row));
	row.InterfaceIndex = x->IfIndex;
	bool up = (x->KmTest != NULL && GetIfEntry2(&row) == NO_ERROR);
	if (KmCheck(ctx, up && row.PhysicalAddressLength == 6 && Cmp(row.PhysicalAddress, x->Mac, 6) == 0,
		"a KM-TEST adapter comes up with the MAC address of the node and the Network", "adapter %s, interface %u, its MAC %02X-%02X-%02X-%02X-%02X-%02X",
		x->KmTest != NULL ? "created" : "not created", x->IfIndex, (UINT)row.PhysicalAddress[0], (UINT)row.PhysicalAddress[1], (UINT)row.PhysicalAddress[2],
		(UINT)row.PhysicalAddress[3], (UINT)row.PhysicalAddress[4], (UINT)row.PhysicalAddress[5]) == false)
	{
		return false;
	}

	if (ConvertInterfaceIndexToLuid(x->IfIndex, &luid) != NO_ERROR)
	{
		return false;
	}
	x->Luid = luid.Value;

	Print("  adapter of Network %u: interface %u, MAC %02X-%02X-%02X-%02X-%02X-%02X\n", network_id, x->IfIndex, (UINT)x->Mac[0], (UINT)x->Mac[1],
		(UINT)x->Mac[2], (UINT)x->Mac[3], (UINT)x->Mac[4], (UINT)x->Mac[5]);

	StrCpy(error, sizeof(error), "");
	return KmCheck(ctx, KmSetUp(x, error, sizeof(error)), "the adapter takes its IPv4 address and the permanent neighbour", "%s", error);
}

// The L2 adapter on the KM-TEST adapter, with ring entries of the AF_XDP rings (0 for the default) and batches of batch
// frames (0 for the default)
static NODE_L2 *KmNewL2(KMTEST_ADAPTER *x, NODE *n, UINT ring, UINT batch)
{
	NODE_L2_CONFIG cfg;

	Zero(&cfg, sizeof(cfg));
	cfg.IfIndex = x->IfIndex;
	cfg.Proc = KmOwnerProc;
	cfg.Param = &x->Owner;
	cfg.Reset = NodeKmTestReset;
	cfg.ResetParam = x->KmTest;
	cfg.BackendRing = ring;
	cfg.Batch = batch;

	return NodeL2New(n, &cfg);
}

//
// The parts of the test
//

// TX inspect and RX inject
static void KmTxRx(KMTEST_CTX *ctx, KMTEST_ADAPTER *x, char *when)
{
	char what[MAX_SIZE];
	UCHAR frame[NODE_L2_MAX_FRAME];
	int timeout = 200;
	char buf[2048];

	// TX inspect: what the host sends to the neighbour is captured, from the MAC address of the adapter
	LONG64 before = ReadAcquire64(&x->Owner.FromAdapter);
	SOCKET s = KmSocket(x->Address, 0);
	UINT sent = (s != INVALID_SOCKET ? KmSendTo(s, x->Neighbour, KMTEST_TX_PORT, 20, 64) : 0);
	if (s != INVALID_SOCKET)
	{
		closesocket(s);
	}
	bool captured = KmWait64(&x->Owner.FromAdapter, before + 20);
	Format(what, sizeof(what), "TX inspect %s: the UDP datagrams that the host sends to a neighbour are captured, from the MAC address of the adapter", when);
	KmCheck(ctx, sent == 20 && captured, what, "%u sent, %I64u captured", sent, (UINT64)(ReadAcquire64(&x->Owner.FromAdapter) - before));

	// RX inject: datagrams that the node sends to the host reach a socket of the host
	UINT got = 0;
	SOCKET r = KmSocket(x->Address, KMTEST_RX_PORT);
	if (r != INVALID_SOCKET)
	{
		setsockopt(r, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout, sizeof(timeout));
		for (UINT i = 0;i < 5;i++)
		{
			UINT size = KmUdpFrame(frame, x->Mac, kmtest_neighbour_mac, x->Neighbour, x->Address, 40000, KMTEST_RX_PORT, 32);
			NodeL2Send(x->L2, frame, size);
			if (recv(r, buf, sizeof(buf), 0) > 0)
			{
				got++;
			}
		}
		for (UINT i = 0;i < 5 && got < 5;i++)
		{
			if (recv(r, buf, sizeof(buf), 0) > 0)
			{
				got++;
			}
		}
		closesocket(r);
	}
	Format(what, sizeof(what), "RX inject %s: the IPv4/UDP frames that the node sends to the host reach a socket bound to the adapter's address", when);
	KmCheck(ctx, got >= 4, what, "%u of 5 received (the socket %s)", got, r != INVALID_SOCKET ? "bound" : "did not bind");

	// RX inject and TX inspect without the firewall: the host answers an injected ARP request
	before = ReadAcquire64(&x->Owner.RepliesToProber);
	for (UINT i = 0;i < 3;i++)
	{
		UINT size = KmArpRequest(frame, kmtest_prober_mac, x->Prober, x->Address);
		NodeL2Send(x->L2, frame, size);
		Sleep(50);
	}
	bool replied = KmWait64(&x->Owner.RepliesToProber, before + 1);
	Format(what, sizeof(what), "RX inject %s: the host answers an ARP request that the node injects, and its reply is captured", when);
	KmCheck(ctx, replied, what, "no ARP reply to the prober");
}

// The adapter as a port of an L2 switch: LAN discovery, the peer's ARP, and the broadcast limit of each VLAN
static void KmDiscovery(KMTEST_CTX *ctx, KMTEST_ADAPTER *x)
{
	SWITCH_CONFIG c;
	SWITCH_PORT_CONFIG pc;
	SWITCH_VLAN_STATS vs;
	KMTEST_PEER peer, a20, b20;
	UCHAR frame[NODE_L2_MAX_FRAME];
	struct ip_mreq mreq;
	DWORD one = 1;

	Zero(&c, sizeof(c));
	Zero(&peer, sizeof(peer));
	Zero(&a20, sizeof(a20));
	Zero(&b20, sizeof(b20));

	SWITCH *sw = SwitchNew(&c);
	if (KmCheck(ctx, sw != NULL, "an L2 switch for the Network", "SwitchNew failed") == false)
	{
		return;
	}

	Zero(&pc, sizeof(pc));
	pc.Mode = SWITCH_ACCESS;
	pc.Vlan = KMTEST_VLAN;
	pc.Send = KmSwitchToHost;
	pc.Param = x->L2;
	UINT host = SwitchAddPort(sw, &pc);
	pc.Send = KmSwitchToPeer;
	pc.Param = &peer;
	UINT peer_port = SwitchAddPort(sw, &pc);
	pc.Vlan = KMTEST_VLAN2;
	pc.Param = &a20;
	UINT a20_port = SwitchAddPort(sw, &pc);
	pc.Param = &b20;
	UINT b20_port = SwitchAddPort(sw, &pc);
	bool ok = (host != SWITCH_PORT_NONE && peer_port != SWITCH_PORT_NONE && a20_port != SWITCH_PORT_NONE && b20_port != SWITCH_PORT_NONE);
	ok = ok && SwitchSubscribe(sw, host, KMTEST_VLAN, NULL) && SwitchSubscribe(sw, peer_port, KMTEST_VLAN, NULL);
	ok = ok && SwitchSubscribe(sw, a20_port, KMTEST_VLAN2, NULL) && SwitchSubscribe(sw, b20_port, KMTEST_VLAN2, NULL);
	if (KmCheck(ctx, ok, "the adapter and a peer are access ports of VLAN 10, two members of the test of VLAN 20", "SwitchAddPort or SwitchSubscribe failed") == false)
	{
		SwitchFree(sw);
		return;
	}

	AcquireSRWLockExclusive(&x->Owner.Lock);
	x->Owner.Switch = sw;
	x->Owner.HostPort = host;
	ReleaseSRWLockExclusive(&x->Owner.Lock);

	// The LAN discovery of the host: ARP for an address that no one has, an IGMP report for a group it joins, an LLMNR
	// query and a NetBIOS name query
	SOCKET s = KmSocket(x->Address, 0);
	if (s != INVALID_SOCKET)
	{
		KmSendTo(s, x->Unknown, KMTEST_TX_PORT, 1, 32);

		Zero(&mreq, sizeof(mreq));
		mreq.imr_multiaddr.s_addr = KmAddr(239, 72, 0, 1);
		mreq.imr_interface.s_addr = x->Address;
		setsockopt(s, IPPROTO_IP, IP_ADD_MEMBERSHIP, (char *)&mreq, sizeof(mreq));

		IN_ADDR ifaddr;
		ifaddr.s_addr = x->Address;
		setsockopt(s, IPPROTO_IP, IP_MULTICAST_IF, (char *)&ifaddr, sizeof(ifaddr));
		KmSendTo(s, KmAddr(224, 0, 0, 252), KMTEST_LLMNR_PORT, 2, 32);

		setsockopt(s, SOL_SOCKET, SO_BROADCAST, (char *)&one, sizeof(one));
		KmSendTo(s, x->Broadcast, KMTEST_NETBIOS_PORT, 2, 50);
	}

	UINT64 end = GetTickCount64() + KMTEST_BOUND;
	while ((peer.Kinds[KMTEST_KIND_ARP] == 0 || peer.Kinds[KMTEST_KIND_IGMP] == 0 || peer.Kinds[KMTEST_KIND_LLMNR] == 0 || peer.Kinds[KMTEST_KIND_NETBIOS] == 0) && GetTickCount64() < end)
	{
		Sleep(KMTEST_POLL);
	}
	UINT kinds[4] = {KMTEST_KIND_ARP, KMTEST_KIND_IGMP, KMTEST_KIND_LLMNR, KMTEST_KIND_NETBIOS};
	for (UINT i = 0;i < 4;i++)
	{
		char what[MAX_SIZE];

		Format(what, sizeof(what), "the %s frames of the host's LAN discovery reach the peer through the switch", kmtest_kind_names[kinds[i]]);
		KmCheck(ctx, peer.Kinds[kinds[i]] > 0, what, "%I64u of them at the peer, %I64u captured", (UINT64)peer.Kinds[kinds[i]], (UINT64)x->Owner.Kinds[kinds[i]]);
	}

	// The peer's ARP request reaches the host, whose reply comes back to the peer
	UINT size = KmArpRequest(frame, kmtest_peer_mac, x->Peer, x->Address);
	for (UINT i = 0;i < 3 && peer.RepliesToPeer == 0;i++)
	{
		SwitchInput(sw, GetTickCount64(), peer_port, frame, size);
		KmWait64(&peer.RepliesToPeer, 1);
	}
	KmCheck(ctx, peer.RepliesToPeer > 0, "the peer's ARP request reaches the host through the switch, and the host's reply comes back to the peer", "no reply");

	// The broadcast limit of VLAN 10: a burst of broadcasts of the host beyond it is dropped and counted there
	SwitchSetVlanLimits(sw, KMTEST_VLAN, KMTEST_LIMIT, 0);
	LONG64 captured = ReadAcquire64(&x->Owner.Kinds[KMTEST_KIND_FLOOD]);
	LONG64 at_peer = ReadAcquire64(&peer.Kinds[KMTEST_KIND_FLOOD]);
	UINT flooded = (s != INVALID_SOCKET ? KmSendTo(s, x->Broadcast, KMTEST_FLOOD_PORT, KMTEST_FLOOD, 32) : 0);
	KmWait64(&x->Owner.Kinds[KMTEST_KIND_FLOOD], captured + flooded);
	Sleep(200);
	LONG64 reached = ReadAcquire64(&peer.Kinds[KMTEST_KIND_FLOOD]) - at_peer;
	SwitchGetVlanStats(sw, KMTEST_VLAN, &vs);
	KmCheck(ctx, flooded == KMTEST_FLOOD && reached > 0 && reached < KMTEST_FLOOD / 2 && vs.LimitDrops > 0,
		"the broadcasts of the host beyond the broadcast limit of VLAN 10 are dropped and counted there",
		"%u sent, %I64u captured, %I64u reached the peer, %I64u dropped over the limit", flooded, (UINT64)(ReadAcquire64(&x->Owner.Kinds[KMTEST_KIND_FLOOD]) - captured), (UINT64)reached, vs.LimitDrops);

	// VLAN 20 has a limit of its own: none, so every broadcast of a member reaches the other
	UINT bsize = KmUdpFrame(frame, (const UCHAR *)"\xFF\xFF\xFF\xFF\xFF\xFF", kmtest_peer_mac, x->Peer, x->Broadcast, 40000, KMTEST_FLOOD_PORT, 32);
	for (UINT i = 0;i < 200;i++)
	{
		SwitchInput(sw, GetTickCount64(), a20_port, frame, bsize);
	}
	SwitchGetVlanStats(sw, KMTEST_VLAN2, &vs);
	KmCheck(ctx, b20.Kinds[KMTEST_KIND_FLOOD] == 200 && vs.LimitDrops == 0, "the broadcast limit is per VLAN: VLAN 20 forwards every broadcast",
		"%I64u of 200 reached the other member, %I64u dropped over a limit", (UINT64)b20.Kinds[KMTEST_KIND_FLOOD], vs.LimitDrops);

	if (s != INVALID_SOCKET)
	{
		closesocket(s);
	}

	AcquireSRWLockExclusive(&x->Owner.Lock);
	x->Owner.Switch = NULL;
	ReleaseSRWLockExclusive(&x->Owner.Lock);
	SwitchFree(sw);
}

// A sender thread: send() to its connected neighbour until it is stopped, with the time of the slowest call
static DWORD WINAPI KmSenderThread(LPVOID param)
{
	KMTEST_SENDER *s = (KMTEST_SENDER *)param;
	static char buf[KMTEST_SEGMENT * KMTEST_SEGMENTS];
	int len = (s->Uso ? (int)(KMTEST_SEGMENT * MIN(s->Segments, KMTEST_SEGMENTS)) : (int)MIN(s->Size, (UINT)sizeof(buf)));
	LARGE_INTEGER freq;

	QueryPerformanceFrequency(&freq);

	while (ReadAcquire(s->Stop) == 0)
	{
		LARGE_INTEGER t0, t1;

		QueryPerformanceCounter(&t0);
		int r = send(s->Sock, buf, len, 0);
		QueryPerformanceCounter(&t1);

		LONG64 us = (LONG64)((t1.QuadPart - t0.QuadPart) * 1000000 / freq.QuadPart);
		if (us > s->SlowestUs)
		{
			s->SlowestUs = us;
		}

		if (r > 0)
		{
			s->Sends++;
			s->LastSend = (LONG64)GetTickCount64();
		}
		else
		{
			s->Errors++;
			InterlockedExchange(&s->LastError, (LONG)WSAGetLastError());
			Sleep(1);
		}
	}

	return 0;
}

// New senders, none started
static KMTEST_SENDER_SET *KmNewSenderSet()
{
	return (KMTEST_SENDER_SET *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(KMTEST_SENDER_SET));
}

// Free the senders once KmStopSenders joined all of them; senders that are still blocked in send() keep them
static void KmFreeSenderSet(KMTEST_SENDER_SET *f)
{
	if (f == NULL)
	{
		return;
	}

	for (UINT i = 0;i < KMTEST_SENDERS;i++)
	{
		if (f->Senders[i].Stuck)
		{
			return;
		}
	}

	HeapFree(GetProcessHeap(), 0, f);
}

// Start KMTEST_SENDERS sender threads to the neighbour of the adapter, with USO, each send() segments datagrams of size
// bytes of payload (0 for KMTEST_SEGMENTS), or with plain send() of size bytes; false when one could not start
static bool KmStartSenders(KMTEST_ADAPTER *x, KMTEST_SENDER_SET *f, bool uso, UINT size, UINT segments)
{
	SOCKADDR_IN sa;
	DWORD segment = KMTEST_SEGMENT;

	if (f == NULL)
	{
		return false;
	}

	Zero(&sa, sizeof(sa));
	sa.sin_family = AF_INET;
	sa.sin_addr.s_addr = x->Neighbour;
	sa.sin_port = htons(KMTEST_TX_PORT);

	for (UINT i = 0;i < KMTEST_SENDERS;i++)
	{
		KMTEST_SENDER *s = &f->Senders[i];
		SOCKADDR_IN local;
		int local_len = sizeof(local);

		Zero(s, sizeof(KMTEST_SENDER));
		s->Stop = &f->Stop;
		s->Size = size;
		s->Segments = (segments != 0 ? segments : KMTEST_SEGMENTS);
		s->Sock = KmSocket(x->Address, 0);
		if (s->Sock == INVALID_SOCKET || connect(s->Sock, (SOCKADDR *)&sa, sizeof(sa)) != 0)
		{
			return false;
		}
		Zero(&local, sizeof(local));
		if (getsockname(s->Sock, (SOCKADDR *)&local, &local_len) == 0)
		{
			s->Port = ntohs(local.sin_port);
		}
		s->Uso = (uso && setsockopt(s->Sock, IPPROTO_UDP, UDP_SEND_MSG_SIZE, (char *)&segment, sizeof(segment)) == 0);
		s->Thread = CreateThread(NULL, 0, KmSenderThread, s, 0, NULL);
		if (s->Thread == NULL)
		{
			return false;
		}
	}

	return true;
}

// Stop and join the sender threads, KMTEST_BOUND ms for each at most; the slowest send() of all of them in microseconds.
// A sender that is still blocked in send() then counts as KMTEST_BOUND ms and keeps its thread and its socket (Stuck,
// counted in stuck); uso and sends count the others.
static LONG64 KmStopSenders(KMTEST_SENDER_SET *f, UINT *uso, LONG64 *sends, UINT *stuck)
{
	LONG64 slowest = 0;

	*uso = 0;
	*sends = 0;
	*stuck = 0;
	if (f == NULL)
	{
		return 0;
	}

	f->Stopped = GetTickCount64();
	InterlockedExchange(&f->Stop, 1);
	for (UINT i = 0;i < KMTEST_SENDERS;i++)
	{
		KMTEST_SENDER *s = &f->Senders[i];

		if (s->Thread != NULL)
		{
			if (WaitForSingleObject(s->Thread, KMTEST_BOUND) != WAIT_OBJECT_0)
			{
				s->Stuck = true;
				(*stuck)++;
				slowest = MAX(slowest, (LONG64)KMTEST_BOUND * 1000);
				continue;
			}
			CloseHandle(s->Thread);
			s->Thread = NULL;
		}
		if (s->Sock != INVALID_SOCKET && s->Sock != 0)
		{
			closesocket(s->Sock);
			s->Sock = INVALID_SOCKET;
		}
		slowest = MAX(slowest, s->SlowestUs);
		*uso += (s->Uso ? 1 : 0);
		*sends += s->Sends;
	}

	return slowest;
}

// Wait up to KMTEST_BOUND ms once more for the senders that stayed blocked in send(), now that the L2 adapter is down,
// and close the ones that end; how many are still blocked. A sender that ends now had frames held by the backend.
static UINT KmReleaseSenders(KMTEST_SENDER_SET *f)
{
	UINT64 end = GetTickCount64() + KMTEST_BOUND;
	UINT left = 0;

	for (UINT i = 0;f != NULL && i < KMTEST_SENDERS;i++)
	{
		KMTEST_SENDER *s = &f->Senders[i];
		UINT64 now = GetTickCount64();

		if (s->Stuck == false)
		{
			continue;
		}
		if (WaitForSingleObject(s->Thread, (DWORD)(now < end ? end - now : 0)) != WAIT_OBJECT_0)
		{
			left++;
			continue;
		}
		CloseHandle(s->Thread);
		s->Thread = NULL;
		closesocket(s->Sock);
		s->Sock = INVALID_SOCKET;
		s->Stuck = false;
	}

	return left;
}

// One line for each sender: its local port, its sends and errors with the last error, its slowest send(), and whether
// it stayed blocked in send(), with the time of its last send() that went through before the stop
static void KmPrintSenders(char *name, KMTEST_SENDER_SET *f)
{
	for (UINT i = 0;f != NULL && i < KMTEST_SENDERS;i++)
	{
		KMTEST_SENDER *s = &f->Senders[i];
		UINT64 last = (UINT64)s->LastSend;
		char when[MAX_SIZE];

		StrCpy(when, sizeof(when), ", no send() went through");
		if (last != 0)
		{
			Format(when, sizeof(when), ", the last send() that went through %I64u ms before the stop", f->Stopped > last ? f->Stopped - last : 0);
		}
		Print("    %s, sender %u: port %u%s, %I64u sends, %I64u errors (the last %u), the slowest send() %I64u us%s%s\n", name, i + 1, (UINT)s->Port,
			s->Uso ? " with USO" : "", (UINT64)s->Sends, (UINT64)s->Errors, (UINT)s->LastError, (UINT64)s->SlowestUs, s->Stuck ? ", blocked in send() when stopped" : "", when);
	}
}

// What the backend tells of its driver: the queues that it captures from and the ones that frames came in on, the
// frames that the driver dropped, and the waits on the driver that failed
static void KmPrintDriver(char *name, NODE_L2_STATUS *st)
{
	Print("  %s: the %s backend captures from %u queue(s), frames came in on %u; the driver dropped %I64u, %I64u waits on it failed (the last 0x%08X)\n", name, st->Backend,
		st->Queues, st->BusyQueues, st->DriverDrops, st->WaitFailures, st->WaitError);
}

// The paused consumer (#72, risk R1): senders flood the adapter while the owner stops taking frames for KMTEST_PAUSE ms
static void KmPausedConsumer(KMTEST_CTX *ctx, KMTEST_ADAPTER *x, NODE *n, bool uso, UINT ring, char *name)
{
	NODE_L2_STATUS st;
	char what[MAX_SIZE];
	UINT uso_senders = 0;
	UINT stuck = 0;
	LONG64 sends = 0;

	x->L2 = KmNewL2(x, n, ring, 0);
	Format(what, sizeof(what), "the paused consumer, %s: the adapter is up", name);
	if (KmCheck(ctx, x->L2 != NULL, what, "NodeL2New failed") == false)
	{
		return;
	}

	KMTEST_SENDER_SET *f = KmNewSenderSet();
	bool started = KmStartSenders(x, f, uso, KMTEST_SEGMENT, 0);
	Sleep(500);

	LONG64 f0 = ReadAcquire64(&x->Owner.Frames);
	Sleep(KMTEST_BASELINE);
	LONG64 baseline = (ReadAcquire64(&x->Owner.Frames) - f0) * 1000 / KMTEST_BASELINE;

	NodeL2GetStatus(x->L2, &st);
	UINT64 drops = st.CaptureDrops;
	ResetEvent(x->Owner.Resume);
	InterlockedExchange(&x->Owner.Paused, 1);
	Sleep(KMTEST_PAUSE);
	NodeL2GetStatus(x->L2, &st);
	UINT64 paused_drops = st.CaptureDrops - drops;

	InterlockedExchange(&x->Owner.Paused, 0);
	SetEvent(x->Owner.Resume);
	Sleep(1000);
	LONG64 f1 = ReadAcquire64(&x->Owner.Frames);
	Sleep(1000);
	LONG64 resumed = ReadAcquire64(&x->Owner.Frames) - f1;

	LONG64 slowest = KmStopSenders(f, &uso_senders, &sends, &stuck);
	NodeL2GetStatus(x->L2, &st);

	Print("  %s: %u senders (%u with USO), %I64u sends, capture %I64u frames/s before the pause and %I64u frames/s in the second second after it, %I64u dropped during the pause, the slowest send() %I64u us\n",
		name, KMTEST_SENDERS, uso_senders, (UINT64)sends, (UINT64)baseline, (UINT64)resumed, paused_drops, (UINT64)slowest);
	KmPrintSenders(name, f);
	KmPrintDriver(name, &st);
	if (uso)
	{
		Print("KMTEST BENCH tx_capture %s: %I64u frames/s\n", name, (UINT64)baseline);
	}

	Format(what, sizeof(what), "the paused consumer, %s: no sender blocks for 1 s", name);
	KmCheck(ctx, started && slowest < KMTEST_BLOCK_LIMIT && (uso == false || uso_senders > 0), what, "the senders %s, the slowest send() took %I64u us, %u with USO",
		started ? "started" : "did not start", (UINT64)slowest, uso_senders);
	Format(what, sizeof(what), "the paused consumer, %s: the drops of the capture ring rise while the owner is paused", name);
	KmCheck(ctx, paused_drops > 0, what, "%I64u dropped", paused_drops);
	Format(what, sizeof(what), "the paused consumer, %s: within 2 s of the owner going on, the capture rate is back at half its baseline at least", name);
	KmCheck(ctx, baseline > 0 && resumed * 2 >= baseline, what, "%I64u frames/s before, %I64u after", (UINT64)baseline, (UINT64)resumed);

	bool freed = NodeL2Free(x->L2);
	x->L2 = NULL;
	Format(what, sizeof(what), "the paused consumer, %s: NodeL2Free takes the adapter down in time after the flood", name);
	KmCheck(ctx, freed, what, "a step did not finish in time");

	if (stuck != 0)
	{
		UINT left = KmReleaseSenders(f);

		Print("  %s: %u of the %u senders that were blocked in send() ended once the L2 adapter was down, %u did not\n", name, stuck - left, stuck, left);
		ctx->Stuck += left;
	}
	KmFreeSenderSet(f);
}

// The sink of the benchmark: counts the datagrams that reach it
static DWORD WINAPI KmSinkThread(LPVOID param)
{
	KMTEST_SINK *k = (KMTEST_SINK *)param;
	char buf[2048];

	while (ReadAcquire(&k->Stop) == 0)
	{
		if (recv(k->Sock, buf, sizeof(buf), 0) > 0)
		{
			InterlockedIncrement64(&k->Received);
		}
	}

	return 0;
}

// The benchmark of RX inject at the batch sizes of the ADR-0022 amendment of 2026-10-19: frames of 1514 bytes sent into
// the adapter for KMTEST_BENCH_TIME ms at each batch size, with what the backend took and what reached a socket
static void KmBench(KMTEST_CTX *ctx, KMTEST_ADAPTER *x, NODE *n)
{
	static UINT batches[4] = {1, 16, 64, 256};
	UCHAR frame[NODE_L2_MAX_FRAME];
	NODE_L2_STATUS st;
	KMTEST_SINK sink;
	int timeout = 100;
	int rcvbuf = 16 << 20;
	bool all = true;

	UINT size = KmUdpFrame(frame, x->Mac, kmtest_neighbour_mac, x->Neighbour, x->Address, 40000, KMTEST_BENCH_PORT, KMTEST_SEGMENT);

	for (UINT i = 0;i < 4;i++)
	{
		Zero(&sink, sizeof(sink));
		sink.Sock = KmSocket(x->Address, KMTEST_BENCH_PORT);
		x->L2 = KmNewL2(x, n, 0, batches[i]);
		if (sink.Sock == INVALID_SOCKET || x->L2 == NULL)
		{
			all = false;
			if (sink.Sock != INVALID_SOCKET)
			{
				closesocket(sink.Sock);
			}
			NodeL2Free(x->L2);
			x->L2 = NULL;
			continue;
		}
		setsockopt(sink.Sock, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout, sizeof(timeout));
		setsockopt(sink.Sock, SOL_SOCKET, SO_RCVBUF, (char *)&rcvbuf, sizeof(rcvbuf));
		sink.Thread = CreateThread(NULL, 0, KmSinkThread, &sink, 0, NULL);

		UINT64 end = GetTickCount64() + KMTEST_BENCH_TIME;
		while (GetTickCount64() < end)
		{
			for (UINT j = 0;j < 1024;j++)
			{
				NodeL2Send(x->L2, frame, size);
			}
		}
		Sleep(200);
		NodeL2GetStatus(x->L2, &st);

		InterlockedExchange(&sink.Stop, 1);
		if (sink.Thread != NULL)
		{
			WaitForSingleObject(sink.Thread, INFINITE);
			CloseHandle(sink.Thread);
		}
		closesocket(sink.Sock);

		Print("KMTEST BENCH rx_inject batch %u: %I64u frames/s taken by the backend, %I64u frames/s delivered to a socket, %I64u batches\n", batches[i],
			st.Injected * 1000 / KMTEST_BENCH_TIME, (UINT64)sink.Received * 1000 / KMTEST_BENCH_TIME, st.Batches);
		all = all && st.Injected > 0 && sink.Received > 0;

		NodeL2Free(x->L2);
		x->L2 = NULL;
	}

	KmCheck(ctx, all, "RX inject at the batch sizes 1, 16, 64 and 256 delivers frames to the host (the rates are printed as KMTEST BENCH lines)", "a run delivered nothing");
}

// The soak (#72, risks R2 and R3): seconds of traffic in phases of KMTEST_SOAK_PHASE ms each, TX, RX and both, of frames
// of 64 and of 1514 bytes, first in one order and then in the other: TX before RX is the order that stalled RX inject once
// in the SeLow-vs-XDP benchmark. The health check of the adapter recovers a stall by itself and counts it; afterwards the
// frames flow both ways. The counters of each phase are printed.
static void KmSoak(KMTEST_CTX *ctx, KMTEST_ADAPTER *x, NODE *n, UINT seconds)
{
	static char *phase_names[KMTEST_SOAK_PHASES] = {"TX 64", "RX 64", "TX 1514", "RX 1514", "TX+RX 1514", "RX 64", "TX 64", "RX 1514", "TX 1514", "TX+RX 64"};
	static UINT phase_sizes[KMTEST_SOAK_PHASES] = {64, 64, 1514, 1514, 1514, 64, 64, 1514, 1514, 64};
	static UINT phase_ways[KMTEST_SOAK_PHASES] = {1, 2, 1, 2, 3, 2, 1, 2, 1, 3};
	UCHAR frame[NODE_L2_MAX_FRAME];
	NODE_L2_STATUS st;
	UINT phases = 0;

	x->L2 = KmNewL2(x, n, 0, 0);
	if (KmCheck(ctx, x->L2 != NULL, "the soak: the adapter is up", "NodeL2New failed") == false)
	{
		return;
	}
	NodeL2GetStatus(x->L2, &st);

	UINT64 end = GetTickCount64() + (UINT64)seconds * 1000;
	for (UINT i = 0;GetTickCount64() < end;i = (i + 1) % KMTEST_SOAK_PHASES)
	{
		KMTEST_SENDER_SET *f = NULL;
		UINT size = phase_sizes[i];
		UINT tx = 0;
		UINT64 phase_end = GetTickCount64() + KMTEST_SOAK_PHASE;

		if ((phase_ways[i] & 1) != 0)
		{
			f = KmNewSenderSet();
			tx = (KmStartSenders(x, f, false, size - 42, 0) ? KMTEST_SENDERS : 0);
		}

		UINT fsize = KmUdpFrame(frame, x->Mac, kmtest_neighbour_mac, x->Neighbour, x->Address, 40000, KMTEST_BENCH_PORT, size - 42);
		while (GetTickCount64() < phase_end)
		{
			if ((phase_ways[i] & 2) != 0)
			{
				for (UINT j = 0;j < 256;j++)
				{
					NodeL2Send(x->L2, frame, fsize);
				}
				YieldProcessor();
			}
			else
			{
				Sleep(KMTEST_POLL);
			}
		}

		UINT uso = 0;
		UINT stuck = 0;
		LONG64 sends = 0;
		LONG64 slowest = KmStopSenders(f, &uso, &sends, &stuck);
		NodeL2GetStatus(x->L2, &st);
		phases++;
		Print("  soak phase %u (%s): %u senders, %I64u sends, the slowest %I64u us; captured %I64u (%I64u dropped, %I64u by the driver, on %u of %u queues), injected %I64u (%I64u refused), %I64u probes (%I64u failed), %I64u reattaches, %I64u resets\n",
			phases, phase_names[i], tx, (UINT64)sends, (UINT64)slowest, st.Captured, st.CaptureDrops, st.DriverDrops, st.BusyQueues, st.Queues, st.Injected, st.InjectDrops,
			st.Probes, st.ProbeFailures, st.Reattaches, st.Resets);
		if (stuck != 0 || (tx != 0 && sends == 0))
		{
			KmPrintSenders("the soak", f);
		}
		ctx->Stuck += stuck;
		KmFreeSenderSet(f);
	}

	Print("KMTEST BENCH soak: %u phases in %u s, %I64u probes, %I64u of them failed, %I64u reattaches, %I64u resets\n", phases, seconds, st.Probes, st.ProbeFailures, st.Reattaches, st.Resets);
	KmCheck(ctx, st.ProbeFailures <= st.Reattaches, "the soak: each stall that a probe found was recovered by a reattach", "%I64u probes failed, %I64u reattaches", st.ProbeFailures, st.Reattaches);
	KmTxRx(ctx, x, "after the soak");

	bool freed = NodeL2Free(x->L2);
	x->L2 = NULL;
	KmCheck(ctx, freed, "the soak: NodeL2Free takes the adapter down in time after the traffic", "a step did not finish in time");
}

// A new empty data directory under the temp directory of the process, with a configuration store: no role, one worker
static void KmNewDir(wchar_t *dir, UINT size)
{
	wchar_t tmp[MAX_PATH];
	wchar_t path[MAX_PATH];

	UniFormat(tmp, sizeof(tmp), L"kmtesttest_%u", Rand32());
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

// The lines of the node log about the L2 adapters, then the files of a data directory and the directory
static void KmDeleteDir(wchar_t *dir, bool print_log)
{
	wchar_t log_dir[MAX_PATH];

	ConbinePathW(log_dir, sizeof(log_dir), dir, NODE_LOG_DIR_NAME);
	for (UINT pass = 0;pass < 2;pass++)
	{
		wchar_t *d_name = (pass == 0 ? log_dir : dir);
		DIRLIST *d = EnumDirW(d_name);

		for (UINT i = 0;d != NULL && i < d->NumFiles;i++)
		{
			DIRENT *e = d->File[i];
			wchar_t path[MAX_PATH];

			if (e->Folder)
			{
				continue;
			}

			ConbinePathW(path, sizeof(path), d_name, e->FileNameW);
			if (pass == 0 && print_log)
			{
				BUF *b = ReadDumpW(path);
				if (b != NULL)
				{
					char *text = ZeroMalloc(b->Size + 1);
					Copy(text, b->Buf, b->Size);
					TOKEN_LIST *t = ParseToken(text, "\r\n");
					for (UINT j = 0;j < t->NumTokens;j++)
					{
						if (InStr(t->Token[j], "L2 adapter") || InStr(t->Token[j], "KM-TEST"))
						{
							Print("  [LOG] %s\n", t->Token[j]);
						}
					}
					FreeToken(t);
					Free(text);
					FreeBuf(b);
				}
			}
			FileDeleteW(path);
		}

		FreeDir(d);
		DeleteDirW(d_name);
	}
}

// Senders with USO of segments datagrams a send() for KMTEST_BARE_TIME ms on a KM-TEST adapter of their own, the
// Network network_id, with the L2 adapter of the host's backend (attach) or none, so no program of XDP and no socket of
// SeLow: KMTEST DIAG lines, no check of the L2 adapter
static void KmUsoMeasure(KMTEST_CTX *ctx, NODE *n, const UCHAR *key, UINT network_id, bool attach, UINT segments)
{
	KMTEST_ADAPTER y;
	NODE_L2_STATUS st;
	char name[MAX_SIZE];
	UINT uso = 0;
	UINT stuck = 0;
	LONG64 sends = 0;

	Format(name, sizeof(name), "%s, %u segments a send()", attach ? "the L2 adapter" : "the bare adapter", segments);
	if (KmNewAdapter(ctx, &y, n, key, network_id))
	{
		y.L2 = (attach ? KmNewL2(&y, n, 0, 0) : NULL);
		NodeL2GetStatus(y.L2, &st);

		KMTEST_SENDER_SET *f = KmNewSenderSet();
		bool started = KmStartSenders(&y, f, true, KMTEST_SEGMENT, segments);
		Sleep(KMTEST_BARE_TIME);
		LONG64 slowest = KmStopSenders(f, &uso, &sends, &stuck);
		NodeL2GetStatus(y.L2, &st);

		Print("KMTEST DIAG %s: 4 senders %s, %u with USO, %I64u sends in %u ms, the slowest send() %I64u us, %u blocked in send() when stopped; %I64u frames captured\n",
			name, started ? "started" : "did not start", uso, (UINT64)sends, KMTEST_BARE_TIME, (UINT64)slowest, stuck, st.Captured);
		KmPrintSenders(name, f);
		if (y.L2 != NULL)
		{
			KmPrintDriver(name, &st);
		}

		NodeL2Free(y.L2);
		y.L2 = NULL;
		if (stuck != 0)
		{
			UINT left = KmReleaseSenders(f);

			Print("KMTEST DIAG %s: %u of the %u senders that were blocked in send() ended once the L2 adapter was down, %u did not\n", name, stuck - left, stuck, left);
			stuck = left;
		}
		ctx->Stuck += stuck;
		KmFreeSenderSet(f);
	}

	NodeKmTestFree(y.KmTest, stuck == 0);
	CloseHandle(y.Owner.Resume);
}

// The measurement "bare": senders with USO on a KM-TEST adapter without an L2 adapter, which shows whether the host's
// stack and the adapter carry USO without the backend, then on adapters with the L2 adapter, without a pause of its
// owner, with datagrams of 16 and of 44 segments a send(). Each on an adapter of its own, so that one that keeps frames
// leaves the others alone.
static void KmBare(KMTEST_CTX *ctx, NODE *n, const UCHAR *key)
{
	KmUsoMeasure(ctx, n, key, KMTEST_NETWORK3, false, KMTEST_SEGMENTS);
	KmUsoMeasure(ctx, n, key, KMTEST_NETWORK3 + 1, true, 16);
	KmUsoMeasure(ctx, n, key, KMTEST_NETWORK3 + 2, true, KMTEST_SEGMENTS);
}

// The test on the backend expect: the long parts with full, only the soak of soak seconds when that is not 0, or only
// the measurement of senders on an adapter without an L2 adapter with bare
static void KmRun(KMTEST_CTX *ctx, NODE *n, char *expect, bool full, UINT soak, bool bare)
{
	KMTEST_ADAPTER x;
	NODE_L2_STATUS st;
	UCHAR key[PEER_KEY_SIZE];
	char error[MAX_SIZE];
	bool xdp = (StrCmpi(expect, "xdp") == 0);

	memset(key, 0x72, sizeof(key));

	if (bare)
	{
		KmBare(ctx, n, key);
		return;
	}

	if (KmNewAdapter(ctx, &x, n, key, KMTEST_NETWORK) == false)
	{
		NodeKmTestFree(x.KmTest, true);
		CloseHandle(x.Owner.Resume);
		return;
	}

	if (soak != 0)
	{
		KmSoak(ctx, &x, n, soak);
		NodeKmTestFree(x.KmTest, ctx->Stuck == 0);
		CloseHandle(x.Owner.Resume);
		return;
	}

	// The adapter is found again by its address, and a second Network gets another one
	NODE_KMTEST *again = NodeKmTestNew(n, x.Mac);
	KmCheck(ctx, again != NULL && NodeKmTestIndex(again) == x.IfIndex, "the node finds the adapter of a Network again by its MAC address", "interface %u, not %u", NodeKmTestIndex(again), x.IfIndex);
	NodeKmTestFree(again, false);

	UCHAR mac2[6];
	NodeL2Mac(mac2, key, KMTEST_NETWORK2);
	NODE_KMTEST *second = NodeKmTestNew(n, mac2);
	KmCheck(ctx, second != NULL && NodeKmTestIndex(second) != x.IfIndex && Cmp(mac2, x.Mac, 6) != 0, "a second Network gets a second adapter with another MAC address",
		"%s, interface %u", second != NULL ? "created" : "not created", NodeKmTestIndex(second));
	NodeKmTestFree(second, true);

	// The queues of the adapter (XDP only): the receive queues that KM-TEST reports for RSS, each of which the L2 adapter
	// binds
	if (xdp)
	{
		UINT64 t0 = GetTickCount64();
		UINT queues = NodeL2XdpQueues(x.IfIndex, NODE_L2_XDP_MAX_QUEUES, error, sizeof(error));
		Print("KMTEST BENCH queues: an AF_XDP socket binds to %u queue(s) of the KM-TEST adapter, found in %I64u ms (%s)\n", queues, GetTickCount64() - t0, error);
		KmCheck(ctx, queues >= 1, "an AF_XDP socket binds to queue 0 of the adapter (the number of queues is measured)", "%u queues: %s", queues, error);
	}

	// The backend that the host gives
	UINT64 t1 = GetTickCount64();
	x.L2 = KmNewL2(&x, n, 0, 0);
	NodeL2GetStatus(x.L2, &st);
	Print("  the L2 adapter came up in %I64u ms\n", GetTickCount64() - t1);
	char what[MAX_SIZE];
	Format(what, sizeof(what), "the L2 adapter binds the %s backend, the one that this host gives", expect);
	if (KmCheck(ctx, x.L2 != NULL && StrCmpi(st.Backend, expect) == 0, what, "%s, backend '%s'", x.L2 != NULL ? "an adapter" : "no adapter", st.Backend))
	{
		KmTxRx(ctx, &x, "");
		KmDiscovery(ctx, &x);

		// Recovery: the backend is detached and attached again, and the frames flow again
		bool recovered = NodeL2Recover(x.L2);
		NodeL2GetStatus(x.L2, &st);
		KmCheck(ctx, recovered && StrCmpi(st.Backend, expect) == 0, "NodeL2Recover detaches the backend and attaches it again", "%s, backend '%s'", recovered ? "true" : "false", st.Backend);
		KmTxRx(ctx, &x, "after the recovery");

		// The probes of the receive path work and cause no reattach of their own
		for (UINT64 end = GetTickCount64() + KMTEST_BOUND;st.Probes < 2 && GetTickCount64() < end;Sleep(200))
		{
			NodeL2GetStatus(x.L2, &st);
		}
		KmCheck(ctx, st.Probes >= 2 && st.ProbeFailures == 0 && st.Reattaches == 1, "the probes of the receive path of the host succeed and cause no reattach",
			"%I64u probes, %I64u failed, %I64u reattaches", st.Probes, st.ProbeFailures, st.Reattaches);
		Print("  status: captured %I64u (%I64u dropped), delivered %I64u, sent %I64u (%I64u dropped), injected %I64u (%I64u refused) in %I64u batches, %I64u probes\n",
			st.Captured, st.CaptureDrops, st.Delivered, st.Sent, st.SendDrops, st.Injected, st.InjectDrops, st.Batches, st.Probes);
		KmPrintDriver("status", &st);

		UINT64 t0 = GetTickCount64();
		bool freed = NodeL2Free(x.L2);
		x.L2 = NULL;
		KmCheck(ctx, freed, "NodeL2Free stops the injector, then the backend drains, closes and joins its thread, each in time", "a step did not finish in time (%I64u ms)", GetTickCount64() - t0);

		if (xdp && full)
		{
			KmPausedConsumer(ctx, &x, n, true, 0, "4 USO senders");
			KmPausedConsumer(ctx, &x, n, false, 0, "4 plain senders");
			KmPausedConsumer(ctx, &x, n, true, 64, "4 USO senders, AF_XDP rings of 64");
			KmBench(ctx, &x, n);
		}
	}
	else
	{
		NodeL2Free(x.L2);
		x.L2 = NULL;
	}

	if (ctx->Stuck != 0)
	{
		Print("  %u senders stayed blocked in send(): the KM-TEST adapter stays, as its removal would wait for their frames\n", ctx->Stuck);
	}
	NodeKmTestFree(x.KmTest, ctx->Stuck == 0);
	CloseHandle(x.Owner.Resume);
}

// kmtest: the L2 adapter of the node on a KM-TEST adapter with the backend of this host (CORE-S3-2)
RANZ_TEST("kmtest", kmtest_test, "KM-TEST adapter: the L2 adapter of the node on a real KM-TEST Loopback Adapter with XDP or SeLow (argument: xdp or selow, then quick, soak <seconds> or bare): TX inspect, RX inject, LAN discovery through an L2 switch with per-VLAN broadcast limits, the paused consumer, the benchmark, recovery and shutdown (administrator rights, the drivers of ranz install).");
void kmtest_test(UINT num, char **arg)
{
	KMTEST_CTX ctx;
	WSADATA wsa;
	wchar_t dir[MAX_PATH];
	char *expect = (num >= 1 ? arg[0] : "xdp");
	bool full = (num < 2);
	UINT soak = (num >= 3 && StrCmpi(arg[1], "soak") == 0 ? ToInt(arg[2]) : 0);
	bool bare = (num >= 2 && StrCmpi(arg[1], "bare") == 0);

	kmtest_budget = KMTEST_BUDGET + soak * 1000;
	HANDLE done = CreateEventW(NULL, TRUE, FALSE, NULL);
	HANDLE watchdog = (done != NULL ? CreateThread(NULL, 0, KmWatchdog, done, 0, NULL) : NULL);

	Zero(&ctx, sizeof(ctx));
	WSAStartup(MAKEWORD(2, 2), &wsa);

	Print("KM-TEST adapter test: the L2 adapter of the node on a KM-TEST Loopback Adapter, the %s backend%s\n", expect,
		bare ? ", senders on a bare adapter" : (soak != 0 ? ", the soak" : (full ? "" : ", quick")));

	KmNewDir(dir, sizeof(dir));
	NODE *n = NewNode(dir);
	bool started = (n != NULL && NodeStart(n));

	if (KmCheck(&ctx, started, "a node without a role runs for the adapters", "NewNode or NodeStart failed"))
	{
		KmRun(&ctx, n, expect, full, soak, bare);
	}

	if (n != NULL)
	{
		NodeStop(n);
		FreeNode(n);
	}
	KmDeleteDir(dir, ctx.NumFailed != 0 || ctx.Stuck != 0);

	// A sender that stayed blocked in send() keeps Winsock in use
	if (ctx.Stuck == 0)
	{
		WSACleanup();
	}

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
		Print("KMTEST TEST OK\n");
	}
	else
	{
		Print("KMTEST TEST FAILED (%u of %u checks failed)\n", ctx.NumFailed, ctx.NumChecks);
	}
}
