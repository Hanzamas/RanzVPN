// nicbridgetest.c
// Named NIC bridge test of vpntest ("nicbridge" command, CORE-S3-3 #73)
//
// The bridge of the L2 adapter of the node (Cedar/NodeL2Bridge.c) through the backend interface, on the two attachments
// that CI has (ADR-0002 amendment of 2026-10-21): the runner's own NIC, the physical side, and a KM-TEST adapter standing
// in for the host vNIC of a Hyper-V virtual switch, whose host stack plays the devices on the switch. The XDP job of
// windows.yml runs it after ranz install as administrator (.github/scripts/kmtest.ps1); it needs the drivers, so the
// smoke loop leaves it out (.github/quality/smoke-exclude.txt). Its argument names the backends: "selow" (the default),
// "xdp" (SeLow, then XDP, on the same attachments, for the comparison) or "npcap".
// The spike of ADR-0018 decision 3, for each backend on each attachment:
// - Foreign-MAC transmit: frames of the overlay from a member's MAC address leave the NIC (its counter of sent frames
//   rises by them), and the backend takes them for the switch of the stand-in. Datagrams of the member reach a socket of
//   the host on the attachment, and an ARP request of the member for the attachment's address is answered: the host is
//   the device on the LAN that CI has, since no network of a runner carries the frames of another MAC address.
// - Foreign-MAC receive: the host's ARP reply to the member, and the datagrams that the host sends to the member (a
//   permanent neighbour), are captured with the member's address as their destination.
// - Coexistence with the host stack, on the runner's NIC: the host's own TCP connection through the NIC works while the
//   bridge is on and after it went, the host resolves its gateway again while the bridge is on, and the bridge sends no
//   probe onto the LAN. The gateway's ARP reply is a frame of the wire to the NIC's own address, which the XDP backend
//   takes on RX inspect, as no rule lets an ARP frame pass, and hands back to the host (NODE_L2_STATUS.ToHost).
// - Throughput against SeLow: on the stand-in, frames of 1514 bytes onto the switch and to the host, and the host's
//   datagrams to the member, for 2 s each, printed as NICBRIDGE BENCH lines for each backend: a regression number of the
//   runner, not a gate (ADR-0002 amendment of 2026-10-21).
// XDP takes the frames that come in from below the adapter, and NDIS loopback is no such frame (XDP inspects none of
// them), while neither a KM-TEST adapter nor the network of a runner gives one for a member's address. So for XDP the
// lines of the frames to and from the host are printed (NICBRIDGE DIAG), and the checks are the transmit onto the wire,
// coexistence, the frames of the wire that come back to the host, shutdown and the benchmark; the NIC is held in
// promiscuous mode by the device of SeLow, the test's own stand-in for Npcap, which ranz install does not put on a runner.
// - Npcap and the default: a bridge whose owner names no backend binds SeLow on the NIC. Npcap is used only where it is
//   installed: on a runner without it, a bridge on Npcap alone does not come up; where it is installed, "npcap" runs the
//   spike with it.
// Prints "NICBRIDGE TEST OK" only when every check passes.

#include "harness_int.h"
#include "testlist.h"

#include "Cedar/ConfigStore.h"
#include "Cedar/Node.h"
#include "Cedar/NodeL2.h"
#include "Cedar/SeLowUser.h"

#include "Mayaqua/FileIO.h"
#include "Mayaqua/Internat.h"
#include "Mayaqua/Kernel.h"
#include "Mayaqua/Memory.h"
#include "Mayaqua/Microsoft.h"
#include "Mayaqua/Str.h"

#include <iphlpapi.h>
#include <ws2tcpip.h>

#include <stdio.h>

#define	NICBRIDGE_BUDGET		480000		// The whole test ends within this time, or the watchdog ends the process (ms)
#define	NICBRIDGE_BOUND			15000		// A bounded wait on observable state (ms)
#define	NICBRIDGE_ANSWER		5000		// ms that an answer of the host may take
#define	NICBRIDGE_POLL			20			// Poll interval of observable state (ms)
#define	NICBRIDGE_NETWORK		76			// The Network id of the stand-in, and of the MAC addresses of the test after it
#define	NICBRIDGE_LENGTH		24			// The prefix length of the address of the stand-in
#define	NICBRIDGE_RX_PORT		5566		// UDP port of the socket of the host that takes the datagrams of the member
#define	NICBRIDGE_TX_PORT		5567		// UDP port of the datagrams that the host sends to the member
#define	NICBRIDGE_BENCH_PORT	5568		// UDP port of the sink of the benchmark
#define	NICBRIDGE_WIRE			1000		// Frames of the member onto the wire, to another address
#define	NICBRIDGE_ETHERTYPE		0x88B5		// The local experimental EtherType of IEEE 802 for those frames
#define	NICBRIDGE_BENCH_TIME	2000		// ms of each benchmark run
#define	NICBRIDGE_SEGMENT		1472		// Bytes of the payload of a datagram of the benchmark: frames of 1514 bytes
#define	NICBRIDGE_ARP_FRAME		60			// Bytes of an ARP frame, padded to the shortest Ethernet frame
#define	NICBRIDGE_TCP_HOST		"github.com"	// A host on the internet that the runner reaches through its NIC
#define	NICBRIDGE_TCP_PORT		"443"

// The checks of the test
typedef struct NICBRIDGE_CTX
{
	UINT NumChecks;
	UINT NumFailed;
} NICBRIDGE_CTX;

// The owner of a bridge: counts the frames that the bridge took from the segment, and those of them to the member
typedef struct NICBRIDGE_OWNER
{
	UCHAR Member[6];					// The MAC address of the member of the overlay
	volatile LONG64 Frames;				// Frames that the bridge took from the segment
	volatile LONG64 ToMember;			// ... to the member
	volatile LONG64 ArpReplies;			// ... of these, ARP replies
	volatile LONG64 Udp;				// ... of these, UDP datagrams to NICBRIDGE_TX_PORT
} NICBRIDGE_OWNER;

// One attachment of the test: the runner's NIC, or the KM-TEST adapter that stands in for a Hyper-V switch
typedef struct NICBRIDGE_PORT
{
	char *Name;							// What it is, in the lines of the test
	char *Tag;							// ... in the NICBRIDGE BENCH lines
	UINT IfIndex;
	UINT64 Luid;
	UCHAR Mac[6];
	UINT Address;						// Its IPv4 address, in network byte order; 0 for none
	UINT Member;						// The IPv4 address of the member of the overlay on its subnet; 0 for none
	UINT Gateway;						// The IPv4 address of its default gateway, in network byte order; 0 for none
	NODE_KMTEST *KmTest;				// The KM-TEST adapter of the stand-in, NULL for the NIC
} NICBRIDGE_PORT;

// The sink of the benchmark
typedef struct NICBRIDGE_SINK
{
	SOCKET Sock;
	volatile LONG Stop;
	HANDLE Thread;
	volatile LONG64 Received;
} NICBRIDGE_SINK;

// The MAC addresses of the test, derived as NodeL2Mac derives those of adapters: the stand-in, the member of the overlay
// and another address of the segment
static UCHAR nicbridge_standin_mac[6];
static UCHAR nicbridge_member_mac[6];
static UCHAR nicbridge_other_mac[6];

static bool NicBridgeCheck(NICBRIDGE_CTX *ctx, bool ok, char *what, char *fmt, ...) RANZ_PRINTF_FORMAT(4, 5);
static bool NicBridgeCheck(NICBRIDGE_CTX *ctx, bool ok, char *what, char *fmt, ...)
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
static DWORD WINAPI NicBridgeWatchdog(LPVOID param)
{
	char msg[MAX_SIZE];
	DWORD written = 0;

	if (WaitForSingleObject((HANDLE)param, NICBRIDGE_BUDGET) != WAIT_TIMEOUT)
	{
		return 0;
	}

	int len = snprintf(msg, sizeof(msg), "NICBRIDGE TEST FAILED (did not finish within %u ms)\n", NICBRIDGE_BUDGET);
	if (len > 0)
	{
		WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), msg, (DWORD)MIN((UINT)len, (UINT)sizeof(msg) - 1), &written, NULL);
	}

	TerminateProcess(GetCurrentProcess(), 1);

	return 0;
}

// An IPv4 address of four bytes, in network byte order
static UINT NicBridgeAddr(UCHAR a, UCHAR b, UCHAR c, UCHAR d)
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

// Wait up to bound ms until *value reaches at least want; false when it does not
static bool NicBridgeWait64(volatile LONG64 *value, LONG64 want, UINT bound)
{
	UINT64 end = GetTickCount64() + bound;

	while (ReadAcquire64(value) < want)
	{
		if (GetTickCount64() >= end)
		{
			return false;
		}
		Sleep(NICBRIDGE_POLL);
	}

	return true;
}

// Wait up to NICBRIDGE_BOUND ms until the backend of the bridge took at least want frames, into st
static bool NicBridgeWaitInjected(NODE_L2 *a, UINT64 want, NODE_L2_STATUS *st)
{
	UINT64 end = GetTickCount64() + NICBRIDGE_BOUND;

	while (true)
	{
		NodeL2GetStatus(a, st);
		if (st->Injected >= want)
		{
			return true;
		}
		if (GetTickCount64() >= end)
		{
			return false;
		}
		Sleep(NICBRIDGE_POLL);
	}
}

//
// Frames
//

// An IPv4/UDP frame into f from src to dst (addresses and ports), with payload_size bytes of payload; its size. The UDP
// checksum is 0, which IPv4 allows.
static UINT NicBridgeUdpFrame(UCHAR *f, const UCHAR *dst_mac, const UCHAR *src_mac, UINT src, UINT dst, USHORT sport, USHORT dport, UINT payload_size)
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
static UINT NicBridgeArpRequest(UCHAR *f, const UCHAR *mac, UINT src, UINT target)
{
	Zero(f, NICBRIDGE_ARP_FRAME);
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

	return NICBRIDGE_ARP_FRAME;
}

// A frame of size bytes into f from the member to dst_mac, of the local experimental EtherType, which no device of a LAN
// takes; its size
static UINT NicBridgeWireFrame(UCHAR *f, const UCHAR *dst_mac, UINT size)
{
	Zero(f, size);
	Copy(f, dst_mac, 6);
	Copy(f + 6, nicbridge_member_mac, 6);
	f[12] = (UCHAR)(NICBRIDGE_ETHERTYPE >> 8);
	f[13] = (UCHAR)NICBRIDGE_ETHERTYPE;

	return size;
}

//
// The owner and the host's stack
//

// The owner of a bridge: counts the frames, and those to the member by kind
static void NicBridgeOwnerProc(NODE_L2 *a, void *param, const UCHAR *frame, UINT size)
{
	NICBRIDGE_OWNER *o = (NICBRIDGE_OWNER *)param;

	InterlockedIncrement64(&o->Frames);
	if (size < 14 || Cmp(frame, o->Member, 6) != 0)
	{
		return;
	}

	InterlockedIncrement64(&o->ToMember);

	USHORT type = (USHORT)((frame[12] << 8) | frame[13]);
	if (type == 0x0806 && size >= 42 && frame[20] == 0 && frame[21] == 2)
	{
		InterlockedIncrement64(&o->ArpReplies);
	}

	if (type == 0x0800 && size >= 14 + 20)
	{
		UINT ihl = (UINT)(frame[14] & 0x0F) * 4;

		if (frame[14 + 9] == 17 && ihl >= 20 && size >= 14 + ihl + 8 && (USHORT)((frame[14 + ihl + 2] << 8) | frame[14 + ihl + 3]) == NICBRIDGE_TX_PORT)
		{
			InterlockedIncrement64(&o->Udp);
		}
	}
}

// What holds the NIC of a bridge in promiscuous mode for the XDP backend in this test: the device of SeLow on the
// interface, which sets the mode when it is opened. The product takes Npcap (NodeL2NpcapHold), which a runner does not have.
static bool NicBridgeHold(NODE_L2 *a, void **hold, char *error, UINT error_size)
{
	char id[MAX_SIZE];
	const GUID *g = &a->Guid;

	Format(id, sizeof(id), SL_ADAPTER_ID_PREFIX "{%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X}", (UINT)g->Data1, (UINT)g->Data2, (UINT)g->Data3, (UINT)g->Data4[0],
		(UINT)g->Data4[1], (UINT)g->Data4[2], (UINT)g->Data4[3], (UINT)g->Data4[4], (UINT)g->Data4[5], (UINT)g->Data4[6], (UINT)g->Data4[7]);

	SU_ADAPTER *su = SuOpenAdapter(id);
	if (su == NULL)
	{
		Format(error, error_size, "the SeLow device %s cannot be opened (error %u)", id, (UINT)GetLastError());
		return false;
	}

	*hold = su;

	return true;
}

static void NicBridgeLetGo(void *hold)
{
	if (hold != NULL)
	{
		SuCloseAdapter((SU_ADAPTER *)hold);
	}
}

// A UDP socket bound to the address addr and port port (0 for any)
static SOCKET NicBridgeSocket(UINT addr, USHORT port)
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
static UINT NicBridgeSendTo(SOCKET s, UINT dst, USHORT port, UINT num, UINT size)
{
	char buf[NICBRIDGE_SEGMENT];
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

// Make the address addr a permanent neighbour of the MAC address mac on the interface luid, or (add false) take any
// neighbour entry of that address away again
static bool NicBridgeNeighbour(UINT64 luid, UINT addr, const UCHAR *mac, bool add)
{
	MIB_IPNET_ROW2 nb;

	Zero(&nb, sizeof(nb));
	nb.InterfaceLuid.Value = luid;
	nb.Address.Ipv4.sin_family = AF_INET;
	nb.Address.Ipv4.sin_addr.s_addr = addr;
	DeleteIpNetEntry2(&nb);
	if (add == false)
	{
		return true;
	}

	Copy(nb.PhysicalAddress, mac, 6);
	nb.PhysicalAddressLength = 6;
	nb.State = NlnsPermanent;
	DWORD err = CreateIpNetEntry2(&nb);
	if (err != NO_ERROR)
	{
		Print("  CreateIpNetEntry2: error %u\n", (UINT)err);
		return false;
	}

	return true;
}

// Whether the host learnt the address addr on the interface luid with the MAC address mac
static bool NicBridgeLearnt(UINT64 luid, UINT addr, const UCHAR *mac)
{
	MIB_IPNET_ROW2 nb;

	Zero(&nb, sizeof(nb));
	nb.InterfaceLuid.Value = luid;
	nb.Address.Ipv4.sin_family = AF_INET;
	nb.Address.Ipv4.sin_addr.s_addr = addr;
	if (GetIpNetEntry2(&nb) != NO_ERROR)
	{
		return false;
	}

	return (nb.PhysicalAddressLength == 6 && Cmp(nb.PhysicalAddress, mac, 6) == 0);
}

// Make the host ask for the MAC address of the address addr on the interface luid again: its neighbour entry goes, and
// ResolveIpNetEntry2 asks and waits for the answer. True when the host learnt a MAC address for it.
static bool NicBridgeResolve(UINT64 luid, UINT addr)
{
	MIB_IPNET_ROW2 nb;

	Zero(&nb, sizeof(nb));
	nb.InterfaceLuid.Value = luid;
	nb.Address.Ipv4.sin_family = AF_INET;
	nb.Address.Ipv4.sin_addr.s_addr = addr;
	DeleteIpNetEntry2(&nb);

	DWORD err = ResolveIpNetEntry2(&nb, NULL);
	if (err != NO_ERROR)
	{
		Print("  ResolveIpNetEntry2: error %u\n", (UINT)err);
		return false;
	}

	return (nb.PhysicalAddressLength == 6);
}

// The IPv4 address of the default gateway of the interface luid, in network byte order; 0 for none
static UINT NicBridgeGateway(UINT64 luid)
{
	MIB_IPFORWARD_TABLE2 *t = NULL;
	UINT gateway = 0;

	if (GetIpForwardTable2(AF_INET, &t) != NO_ERROR)
	{
		return 0;
	}

	for (ULONG i = 0;i < t->NumEntries && gateway == 0;i++)
	{
		MIB_IPFORWARD_ROW2 *r = &t->Table[i];

		if (r->InterfaceLuid.Value == luid && r->DestinationPrefix.PrefixLength == 0)
		{
			gateway = r->NextHop.Ipv4.sin_addr.s_addr;
		}
	}

	FreeMibTable(t);

	return gateway;
}

// The frames that the interface if_index has sent, unicast and not, by its own counters
static UINT64 NicBridgeSent(UINT if_index)
{
	MIB_IF_ROW2 row;

	Zero(&row, sizeof(row));
	row.InterfaceIndex = if_index;
	if (GetIfEntry2(&row) != NO_ERROR)
	{
		return 0;
	}

	return (UINT64)row.OutUcastPkts + (UINT64)row.OutNUcastPkts;
}

// Whether the host's own TCP connection to NICBRIDGE_TCP_HOST, through the NIC, comes up: its name resolved, and the
// connection made and closed
static bool NicBridgeTcp()
{
	ADDRINFOA hints;
	ADDRINFOA *list = NULL;
	bool ok = false;

	Zero(&hints, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;
	if (getaddrinfo(NICBRIDGE_TCP_HOST, NICBRIDGE_TCP_PORT, &hints, &list) != 0)
	{
		Print("  getaddrinfo of %s: error %d\n", NICBRIDGE_TCP_HOST, WSAGetLastError());
		return false;
	}

	for (ADDRINFOA *ai = list;ai != NULL && ok == false;ai = ai->ai_next)
	{
		SOCKET s = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);

		if (s == INVALID_SOCKET)
		{
			continue;
		}
		ok = (connect(s, ai->ai_addr, (int)ai->ai_addrlen) == 0);
		closesocket(s);
	}

	freeaddrinfo(list);

	return ok;
}

// The sink of the benchmark: counts the datagrams that reach it
static DWORD WINAPI NicBridgeSinkThread(LPVOID param)
{
	NICBRIDGE_SINK *k = (NICBRIDGE_SINK *)param;
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

//
// The attachments
//

// The runner's NIC: the interface of its route to 8.8.8.8, its IPv4 address, and for the member of the overlay the last
// address of its subnet but one, which no device of a runner's network has
static bool NicBridgeNic(NICBRIDGE_CTX *ctx, NICBRIDGE_PORT *p)
{
	UCHAR dst[4] = {8, 8, 8, 8};
	IPAddr route = 0;
	DWORD index = 0;
	MIB_IF_ROW2 row;
	MIB_UNICASTIPADDRESS_TABLE *t = NULL;
	char alias[MAX_SIZE];
	char error[MAX_SIZE * 2];
	UINT length = 0;

	Zero(p, sizeof(NICBRIDGE_PORT));
	p->Name = "the runner's NIC";
	p->Tag = "nic";

	Copy(&route, dst, 4);
	Zero(&row, sizeof(row));
	bool found = (GetBestInterface(route, &index) == NO_ERROR);
	row.InterfaceIndex = index;
	found = found && GetIfEntry2(&row) == NO_ERROR;
	if (NicBridgeCheck(ctx, found, "this runner has a NIC with a route to the internet", "interface %u", (UINT)index) == false)
	{
		return false;
	}

	// The interface as the owner of a bridge names it: by its alias
	Zero(alias, sizeof(alias));
	UniToUtf8(alias, sizeof(alias) - 1, row.Alias);
	p->IfIndex = NodeL2BridgeIndex(alias, error, sizeof(error));
	if (NicBridgeCheck(ctx, p->IfIndex == (UINT)index, "NodeL2BridgeIndex finds the NIC by its alias", "'%s': interface %u, not %u: %s", alias, p->IfIndex, (UINT)index, error) == false)
	{
		return false;
	}
	p->Luid = row.InterfaceLuid.Value;
	Copy(p->Mac, row.PhysicalAddress, 6);

	if (GetUnicastIpAddressTable(AF_INET, &t) == NO_ERROR)
	{
		for (ULONG i = 0;i < t->NumEntries && p->Address == 0;i++)
		{
			if (t->Table[i].InterfaceLuid.Value == p->Luid)
			{
				p->Address = t->Table[i].Address.Ipv4.sin_addr.s_addr;
				length = t->Table[i].OnLinkPrefixLength;
			}
		}
		FreeMibTable(t);
	}

	if (p->Address != 0 && length >= 8 && length <= 30)
	{
		UINT host = Endian32(p->Address);
		UINT mask = 0xFFFFFFFF << (32 - length);
		UINT member = (host & mask) | (~mask - 1);

		if (member == host)
		{
			member--;
		}
		p->Member = Endian32(member);
	}
	p->Gateway = NicBridgeGateway(p->Luid);

	Print("  the runner's NIC: interface %u, '%s', MAC %02X-%02X-%02X-%02X-%02X-%02X, %u.%u.%u.%u/%u, the member at %u.%u.%u.%u\n", p->IfIndex, alias,
		(UINT)p->Mac[0], (UINT)p->Mac[1], (UINT)p->Mac[2], (UINT)p->Mac[3], (UINT)p->Mac[4], (UINT)p->Mac[5], p->Address & 0xFF, (p->Address >> 8) & 0xFF,
		(p->Address >> 16) & 0xFF, p->Address >> 24, length, p->Member & 0xFF, (p->Member >> 8) & 0xFF, (p->Member >> 16) & 0xFF, p->Member >> 24);
	Zero(alias, sizeof(alias));
	UniToUtf8(alias, sizeof(alias) - 1, row.Description);
	Print("  the runner's NIC is '%s', its gateway %u.%u.%u.%u\n", alias, p->Gateway & 0xFF, (p->Gateway >> 8) & 0xFF, (p->Gateway >> 16) & 0xFF, p->Gateway >> 24);

	return true;
}

// The stand-in of a Hyper-V switch: a KM-TEST adapter of the node with its IPv4 address, whose host stack plays the
// devices on the switch, found by its alias as the owner of a bridge names it
static bool NicBridgeStandIn(NICBRIDGE_CTX *ctx, NICBRIDGE_PORT *p, NODE *n)
{
	MIB_UNICASTIPADDRESS_ROW addr;
	MIB_IF_ROW2 row;
	char alias[MAX_SIZE];
	char error[MAX_SIZE * 2];

	Zero(p, sizeof(NICBRIDGE_PORT));
	p->Name = "the stand-in of a Hyper-V switch";
	p->Tag = "hyperv";
	Copy(p->Mac, nicbridge_standin_mac, 6);
	p->Address = NicBridgeAddr(198, 18, NICBRIDGE_NETWORK, 1);
	p->Member = NicBridgeAddr(198, 18, NICBRIDGE_NETWORK, 2);

	p->KmTest = NodeKmTestNew(n, p->Mac);
	UINT index = NodeKmTestIndex(p->KmTest);
	Zero(&row, sizeof(row));
	row.InterfaceIndex = index;
	bool up = (p->KmTest != NULL && GetIfEntry2(&row) == NO_ERROR);
	if (NicBridgeCheck(ctx, up, "a KM-TEST adapter comes up to stand in for the host vNIC of a Hyper-V switch", "adapter %s, interface %u", p->KmTest != NULL ? "created" : "not created", index) == false)
	{
		return false;
	}

	Zero(alias, sizeof(alias));
	UniToUtf8(alias, sizeof(alias) - 1, row.Alias);
	p->IfIndex = NodeL2BridgeIndex(alias, error, sizeof(error));
	if (NicBridgeCheck(ctx, p->IfIndex == index, "NodeL2BridgeIndex finds the stand-in by its alias", "'%s': interface %u, not %u: %s", alias, p->IfIndex, index, error) == false)
	{
		return false;
	}
	p->Luid = row.InterfaceLuid.Value;

	InitializeUnicastIpAddressEntry(&addr);
	addr.InterfaceLuid.Value = p->Luid;
	addr.Address.Ipv4.sin_family = AF_INET;
	addr.Address.Ipv4.sin_addr.s_addr = p->Address;
	addr.OnLinkPrefixLength = NICBRIDGE_LENGTH;
	addr.DadState = IpDadStatePreferred;
	DWORD err = CreateUnicastIpAddressEntry(&addr);
	bool ok = (err == NO_ERROR || err == ERROR_OBJECT_ALREADY_EXISTS);

	for (UINT64 end = GetTickCount64() + NICBRIDGE_BOUND;ok && GetTickCount64() < end;Sleep(100))
	{
		MIB_UNICASTIPADDRESS_ROW r;

		InitializeUnicastIpAddressEntry(&r);
		r.InterfaceLuid.Value = p->Luid;
		r.Address.Ipv4.sin_family = AF_INET;
		r.Address.Ipv4.sin_addr.s_addr = p->Address;
		if (GetUnicastIpAddressEntry(&r) == NO_ERROR && r.DadState == IpDadStatePreferred)
		{
			break;
		}
	}

	Print("  the stand-in: interface %u, '%s', MAC %02X-%02X-%02X-%02X-%02X-%02X, 198.18.%u.1/%u, the member at 198.18.%u.2\n", p->IfIndex, alias, (UINT)p->Mac[0],
		(UINT)p->Mac[1], (UINT)p->Mac[2], (UINT)p->Mac[3], (UINT)p->Mac[4], (UINT)p->Mac[5], (UINT)NICBRIDGE_NETWORK, (UINT)NICBRIDGE_LENGTH, (UINT)NICBRIDGE_NETWORK);

	return NicBridgeCheck(ctx, ok, "the stand-in takes its IPv4 address", "CreateUnicastIpAddressEntry: error %u", (UINT)err);
}

//
// The parts of the test
//

// The benchmark on the stand-in (ADR-0018 decision 3, throughput against SeLow): frames of 1514 bytes of the member onto
// the switch and to the host, and for a backend that sees the host's sends, the host's datagrams to the member, each for
// NICBRIDGE_BENCH_TIME ms. Rates in frames per second, as NICBRIDGE BENCH lines.
static void NicBridgeBench(NICBRIDGE_CTX *ctx, NICBRIDGE_PORT *p, NODE_L2 *a, NICBRIDGE_OWNER *o, char *backend, bool host_sends)
{
	UCHAR frame[NODE_L2_MAX_FRAME];
	NODE_L2_STATUS st;
	NICBRIDGE_SINK sink;
	int timeout = 100;
	int rcvbuf = 16 << 20;

	// Onto the switch
	NodeL2GetStatus(a, &st);
	UINT64 before = st.Injected;
	UINT size = NicBridgeWireFrame(frame, nicbridge_other_mac, 14 + 20 + 8 + NICBRIDGE_SEGMENT);
	UINT64 end = GetTickCount64() + NICBRIDGE_BENCH_TIME;
	while (GetTickCount64() < end)
	{
		for (UINT i = 0;i < 1024;i++)
		{
			NodeL2Send(a, frame, size);
		}
	}
	Sleep(200);
	NodeL2GetStatus(a, &st);
	UINT64 wire = (st.Injected - before) * 1000 / NICBRIDGE_BENCH_TIME;
	Print("NICBRIDGE BENCH %s %s onto the switch: %I64u frames/s taken by the backend\n", backend, p->Tag, wire);

	// To the host, into a socket
	Zero(&sink, sizeof(sink));
	sink.Sock = NicBridgeSocket(p->Address, NICBRIDGE_BENCH_PORT);
	UINT64 host = 0;
	if (sink.Sock != INVALID_SOCKET)
	{
		setsockopt(sink.Sock, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout, sizeof(timeout));
		setsockopt(sink.Sock, SOL_SOCKET, SO_RCVBUF, (char *)&rcvbuf, sizeof(rcvbuf));
		sink.Thread = CreateThread(NULL, 0, NicBridgeSinkThread, &sink, 0, NULL);

		NodeL2GetStatus(a, &st);
		before = st.Injected;
		size = NicBridgeUdpFrame(frame, p->Mac, nicbridge_member_mac, p->Member, p->Address, 40000, NICBRIDGE_BENCH_PORT, NICBRIDGE_SEGMENT);
		end = GetTickCount64() + NICBRIDGE_BENCH_TIME;
		while (GetTickCount64() < end)
		{
			for (UINT i = 0;i < 1024;i++)
			{
				NodeL2Send(a, frame, size);
			}
		}
		Sleep(200);
		NodeL2GetStatus(a, &st);
		host = (st.Injected - before) * 1000 / NICBRIDGE_BENCH_TIME;

		InterlockedExchange(&sink.Stop, 1);
		if (sink.Thread != NULL)
		{
			WaitForSingleObject(sink.Thread, INFINITE);
			CloseHandle(sink.Thread);
		}
		closesocket(sink.Sock);
	}
	Print("NICBRIDGE BENCH %s %s to the host: %I64u frames/s taken by the backend, %I64u frames/s delivered to a socket\n", backend, p->Tag, host,
		(UINT64)sink.Received * 1000 / NICBRIDGE_BENCH_TIME);

	// The host's datagrams to the member
	UINT64 captured = 0;
	if (host_sends && NicBridgeNeighbour(p->Luid, p->Member, nicbridge_member_mac, true))
	{
		SOCKET s = NicBridgeSocket(p->Address, 0);
		LONG64 udp = ReadAcquire64(&o->Udp);

		if (s != INVALID_SOCKET)
		{
			end = GetTickCount64() + NICBRIDGE_BENCH_TIME;
			while (GetTickCount64() < end)
			{
				NicBridgeSendTo(s, p->Member, NICBRIDGE_TX_PORT, 256, NICBRIDGE_SEGMENT);
			}
			closesocket(s);
		}
		Sleep(200);
		captured = (UINT64)(ReadAcquire64(&o->Udp) - udp) * 1000 / NICBRIDGE_BENCH_TIME;
		NicBridgeNeighbour(p->Luid, p->Member, NULL, false);
		Print("NICBRIDGE BENCH %s %s from the host: %I64u frames/s captured\n", backend, p->Tag, captured);
	}

	char what[MAX_SIZE];
	Format(what, sizeof(what), "the benchmark of the %s backend moves frames onto the switch and to the host (the rates are the NICBRIDGE BENCH lines)", backend);
	NicBridgeCheck(ctx, wire > 0 && host > 0 && (host_sends == false || captured > 0), what, "%I64u, %I64u, %I64u frames/s", wire, host, captured);
}

// The spike of ADR-0018 decision 3 for the backend b on the attachment p, through the backend interface
static void NicBridgeRun(NICBRIDGE_CTX *ctx, NODE *n, NICBRIDGE_PORT *p, const NODE_L2_BACKEND *b)
{
	const NODE_L2_BACKEND *list[1];
	NODE_L2_CONFIG cfg;
	NODE_L2_STATUS st;
	NICBRIDGE_OWNER o;
	UCHAR frame[NODE_L2_MAX_FRAME];
	char what[MAX_SIZE];
	char buf[2048];
	int timeout = 200;
	// XDP takes only what comes in from below the adapter, which no attachment of a runner gives for the member
	bool from_host = (StrCmp(b->Name, "xdp") != 0);
	bool nic = (p->KmTest == NULL);

	Zero(&o, sizeof(o));
	Copy(o.Member, nicbridge_member_mac, 6);
	list[0] = b;
	Zero(&cfg, sizeof(cfg));
	cfg.IfIndex = p->IfIndex;
	cfg.Proc = NicBridgeOwnerProc;
	cfg.Param = &o;
	cfg.Backends = list;
	cfg.NumBackends = 1;
	cfg.Bridge = true;
	cfg.Hold = NicBridgeHold;
	cfg.LetGo = NicBridgeLetGo;

	Print("The %s backend on %s\n", b->Name, p->Name);
	NODE_L2 *a = NodeL2New(n, &cfg);
	NodeL2GetStatus(a, &st);
	Format(what, sizeof(what), "the %s backend binds a bridge on %s through the backend interface", b->Name, p->Name);
	if (NicBridgeCheck(ctx, a != NULL && StrCmp(st.Backend, b->Name) == 0 && st.Bridge, what, "%s, backend '%s'", a != NULL ? "a bridge" : "no bridge", st.Backend) == false)
	{
		NodeL2Free(a);
		return;
	}
	Print("  the bridge is on %u queue(s) of the driver\n", st.Queues);

	// Foreign-MAC transmit onto the wire: frames of the member to another address of the segment, which the backend takes,
	// and which the NIC counts as sent
	UINT64 sent_before = NicBridgeSent(p->IfIndex);
	UINT64 injected_before = st.Injected;
	UINT size = NicBridgeWireFrame(frame, nicbridge_other_mac, 64);
	UINT sent = 0;
	for (UINT i = 0;i < NICBRIDGE_WIRE;i++)
	{
		sent += (NodeL2Send(a, frame, size) ? 1 : 0);
		if ((i % 100) == 99)
		{
			Sleep(1);
		}
	}
	bool taken = NicBridgeWaitInjected(a, injected_before + sent, &st);
	Sleep(500);
	UINT64 counted = NicBridgeSent(p->IfIndex) - sent_before;
	Format(what, sizeof(what), "foreign-MAC transmit on %s: the backend takes the frames of the member for the segment%s", p->Name, nic ? ", and the NIC counts them as sent" : "");
	NicBridgeCheck(ctx, sent == NICBRIDGE_WIRE && taken && (nic == false || counted >= sent), what, "%u sent, %I64u taken by the backend, %I64u counted by the interface",
		sent, st.Injected - injected_before, counted);
	if (nic == false)
	{
		Print("NICBRIDGE DIAG %s %s: %I64u frames counted as sent by the KM-TEST adapter\n", b->Name, p->Tag, counted);
	}

	// Foreign-MAC transmit to the host: datagrams of the member reach a socket of the host on the attachment
	UINT got = 0;
	SOCKET r = (p->Address != 0 && p->Member != 0 ? NicBridgeSocket(p->Address, NICBRIDGE_RX_PORT) : INVALID_SOCKET);
	if (r != INVALID_SOCKET)
	{
		setsockopt(r, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout, sizeof(timeout));
		for (UINT i = 0;i < 5;i++)
		{
			UINT usize = NicBridgeUdpFrame(frame, p->Mac, nicbridge_member_mac, p->Member, p->Address, 40000, NICBRIDGE_RX_PORT, 32);
			NodeL2Send(a, frame, usize);
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

	// Foreign-MAC transmit and receive: an ARP request of the member for the attachment's address; the host learns the
	// member, and its reply to the member is captured
	bool learnt = false;
	bool replied = false;
	if (p->Address != 0 && p->Member != 0)
	{
		LONG64 replies = ReadAcquire64(&o.ArpReplies);

		NicBridgeNeighbour(p->Luid, p->Member, NULL, false);
		for (UINT i = 0;i < 3;i++)
		{
			UINT asize = NicBridgeArpRequest(frame, nicbridge_member_mac, p->Member, p->Address);
			NodeL2Send(a, frame, asize);
			Sleep(50);
		}
		replied = NicBridgeWait64(&o.ArpReplies, replies + 1, from_host ? NICBRIDGE_ANSWER : 1000);
		learnt = NicBridgeLearnt(p->Luid, p->Member, nicbridge_member_mac);
	}

	// Foreign-MAC receive: the host's datagrams to the member, a permanent neighbour, are captured
	UINT usent = 0;
	bool captured = false;
	if (p->Address != 0 && p->Member != 0 && NicBridgeNeighbour(p->Luid, p->Member, nicbridge_member_mac, true))
	{
		LONG64 before = ReadAcquire64(&o.Udp);
		SOCKET s = NicBridgeSocket(p->Address, 0);

		usent = (s != INVALID_SOCKET ? NicBridgeSendTo(s, p->Member, NICBRIDGE_TX_PORT, 20, 64) : 0);
		if (s != INVALID_SOCKET)
		{
			closesocket(s);
		}
		captured = NicBridgeWait64(&o.Udp, before + 20, from_host ? NICBRIDGE_BOUND : 1000);
	}
	NicBridgeNeighbour(p->Luid, p->Member, NULL, false);

	if (from_host)
	{
		Format(what, sizeof(what), "foreign-MAC transmit on %s: the datagrams of the member reach a socket of the host", p->Name);
		NicBridgeCheck(ctx, got >= 4, what, "%u of 5 received", got);
		Format(what, sizeof(what), "foreign-MAC transmit and receive on %s: the host answers the ARP request of the member, and its reply to the member is captured", p->Name);
		NicBridgeCheck(ctx, replied, what, "no reply captured; the host %s the member", learnt ? "learnt" : "did not learn");
		Format(what, sizeof(what), "foreign-MAC receive on %s: the datagrams that the host sends to the member are captured", p->Name);
		NicBridgeCheck(ctx, usent == 20 && captured, what, "%u sent, %I64u captured", usent, (UINT64)ReadAcquire64(&o.Udp));
	}
	Print("NICBRIDGE DIAG %s %s: %u of 5 datagrams of the member at the host, the host %s the member, %s its ARP reply, %u of its datagrams to the member, %I64u captured; %I64u frames from the segment, %I64u to the member\n",
		b->Name, p->Tag, got, learnt ? "learnt" : "did not learn", replied ? "captured" : "did not capture", usent, (UINT64)ReadAcquire64(&o.Udp),
		(UINT64)ReadAcquire64(&o.Frames), (UINT64)ReadAcquire64(&o.ToMember));

	// Coexistence with the host stack, on the runner's NIC: the host's own TCP connection through the NIC works while the
	// bridge is on, the host resolves its gateway again, and the bridge sends no probe onto the LAN. On XDP the gateway's
	// ARP reply, a frame of the wire to the NIC's own address that no rule lets pass, reaches the host only through the
	// bridge, which hands it back; the health check reports those frames once a second.
	if (nic)
	{
		Format(what, sizeof(what), "coexistence on %s: the host's own TCP connection to %s through the NIC works while the bridge is on", p->Name, NICBRIDGE_TCP_HOST);
		NicBridgeCheck(ctx, NicBridgeTcp(), what, "it did not");

		NodeL2GetStatus(a, &st);
		UINT64 to_host = st.ToHost;
		bool resolved = (p->Gateway != 0 && NicBridgeResolve(p->Luid, p->Gateway));
		UINT64 end = GetTickCount64() + NICBRIDGE_ANSWER;
		NodeL2GetStatus(a, &st);
		while (from_host == false && st.ToHost == to_host && GetTickCount64() < end)
		{
			Sleep(NICBRIDGE_POLL);
			NodeL2GetStatus(a, &st);
		}
		Format(what, sizeof(what), "coexistence on %s: the host resolves its gateway again while the bridge is on%s", p->Name,
			from_host ? "" : ", and its ARP reply, a frame of the wire that RX inspect takes, comes back to the host through the bridge");
		NicBridgeCheck(ctx, resolved && (from_host || st.ToHost > to_host), what, "%s, %I64u frames of the wire handed back to the host",
			p->Gateway == 0 ? "no gateway found" : (resolved ? "resolved" : "not resolved"), st.ToHost - to_host);

		Sleep(NODE_L2_PROBE + 1000);
		NodeL2GetStatus(a, &st);
		NicBridgeCheck(ctx, st.Probes == 0, "a bridge sends no probe of the receive path onto the LAN", "%I64u probes", st.Probes);
	}
	else
	{
		NicBridgeBench(ctx, p, a, &o, b->Name, from_host);
	}

	NodeL2GetStatus(a, &st);
	Print("  status: captured %I64u (%I64u dropped), delivered %I64u, sent %I64u (%I64u dropped), injected %I64u (%I64u refused) in %I64u batches, %I64u handed back to the host (%I64u dropped), %I64u reattaches\n",
		st.Captured, st.CaptureDrops, st.Delivered, st.Sent, st.SendDrops, st.Injected, st.InjectDrops, st.Batches, st.ToHost, st.ToHostDrops, st.Reattaches);

	UINT64 t0 = GetTickCount64();
	bool freed = NodeL2Free(a);
	Format(what, sizeof(what), "NodeL2Free takes the bridge on %s down in time", p->Name);
	NicBridgeCheck(ctx, freed, what, "a step did not finish in time (%I64u ms)", GetTickCount64() - t0);

	if (nic)
	{
		Format(what, sizeof(what), "coexistence on %s: the host's own TCP connection through the NIC works after the bridge went", p->Name);
		NicBridgeCheck(ctx, NicBridgeTcp(), what, "it did not");
	}
}

// SeLow is the default of a bridge, and Npcap is used only where it is installed
static void NicBridgeDefault(NICBRIDGE_CTX *ctx, NODE *n, NICBRIDGE_PORT *p)
{
	const NODE_L2_BACKEND *list[1];
	NODE_L2_CONFIG cfg;
	NODE_L2_STATUS st;
	NICBRIDGE_OWNER o;
	char error[MAX_SIZE];

	Zero(&o, sizeof(o));
	Zero(&cfg, sizeof(cfg));
	cfg.IfIndex = p->IfIndex;
	cfg.Proc = NicBridgeOwnerProc;
	cfg.Param = &o;
	cfg.Bridge = true;

	NODE_L2 *a = NodeL2New(n, &cfg);
	NodeL2GetStatus(a, &st);
	NicBridgeCheck(ctx, a != NULL && StrCmp(st.Backend, "selow") == 0, "a bridge on the runner's NIC whose owner names no backend binds SeLow, the default", "%s, backend '%s'",
		a != NULL ? "a bridge" : "no bridge", st.Backend);
	NodeL2Free(a);

	if (NodeL2NpcapPresent(error, sizeof(error)))
	{
		Print("  Npcap is installed here: nicbridge npcap runs the spike with it\n");
		return;
	}

	Print("NICBRIDGE NPCAP absent: %s\n", error);
	list[0] = NodeL2NpcapBackend();
	cfg.Backends = list;
	cfg.NumBackends = 1;
	a = NodeL2New(n, &cfg);
	NicBridgeCheck(ctx, a == NULL, "Npcap is used only where it is installed: without it a bridge on Npcap alone does not come up", "a bridge came up");
	NodeL2Free(a);
}

// A new empty data directory under the temp directory of the process, with a configuration store: no role, one worker
static void NicBridgeNewDir(wchar_t *dir, UINT size)
{
	wchar_t tmp[MAX_PATH];
	wchar_t path[MAX_PATH];

	UniFormat(tmp, sizeof(tmp), L"nicbridgetest_%u", Rand32());
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

// The lines of the node log about the bridges and the KM-TEST adapter, then the files of a data directory and the
// directory
static void NicBridgeDeleteDir(wchar_t *dir)
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
			if (pass == 0)
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

// nicbridge: the bridge of an L2 Network on the runner's NIC and on a stand-in of a Hyper-V switch (CORE-S3-3)
RANZ_TEST("nicbridge", nicbridge_test, "NIC bridge: the bridge of an L2 Network through the backend interface on the runner's NIC and on a KM-TEST adapter standing in for a Hyper-V switch, with SeLow, XDP or Npcap (argument: selow, xdp or npcap): foreign-MAC transmit and receive, coexistence with the host stack, the benchmark against SeLow, SeLow the default and Npcap only where it is installed (administrator rights, the drivers of ranz install).");
void nicbridge_test(UINT num, char **arg)
{
	NICBRIDGE_CTX ctx;
	NICBRIDGE_PORT nic;
	NICBRIDGE_PORT standin;
	WSADATA wsa;
	UCHAR key[PEER_KEY_SIZE];
	wchar_t dir[MAX_PATH];
	char *mode = (num >= 1 ? arg[0] : "selow");
	bool xdp = (StrCmpi(mode, "xdp") == 0);
	bool npcap = (StrCmpi(mode, "npcap") == 0);

	HANDLE done = CreateEventW(NULL, TRUE, FALSE, NULL);
	HANDLE watchdog = (done != NULL ? CreateThread(NULL, 0, NicBridgeWatchdog, done, 0, NULL) : NULL);

	Zero(&ctx, sizeof(ctx));
	Zero(&standin, sizeof(standin));
	WSAStartup(MAKEWORD(2, 2), &wsa);

	memset(key, 0x73, sizeof(key));
	NodeL2Mac(nicbridge_standin_mac, key, NICBRIDGE_NETWORK);
	NodeL2Mac(nicbridge_member_mac, key, NICBRIDGE_NETWORK + 1);
	NodeL2Mac(nicbridge_other_mac, key, NICBRIDGE_NETWORK + 2);

	Print("NIC bridge test: the bridge of an L2 Network on the runner's NIC and on a stand-in of a Hyper-V switch, mode %s\n", mode);

	NicBridgeNewDir(dir, sizeof(dir));
	NODE *n = NewNode(dir);
	bool started = (n != NULL && NodeStart(n));

	if (NicBridgeCheck(&ctx, started, "a node without a role runs for the bridges", "NewNode or NodeStart failed"))
	{
		bool have_nic = NicBridgeNic(&ctx, &nic);
		bool have_standin = NicBridgeStandIn(&ctx, &standin, n);

		if (have_nic)
		{
			NicBridgeDefault(&ctx, n, &nic);
		}

		if (npcap)
		{
			char error[MAX_SIZE];

			if (NodeL2NpcapPresent(error, sizeof(error)))
			{
				if (have_standin)
				{
					NicBridgeRun(&ctx, n, &standin, NodeL2NpcapBackend());
				}
				if (have_nic)
				{
					NicBridgeRun(&ctx, n, &nic, NodeL2NpcapBackend());
				}
			}
		}
		else
		{
			// SeLow first, then XDP, on the stand-in and then on the runner's NIC
			if (have_standin)
			{
				NicBridgeRun(&ctx, n, &standin, NodeL2SeLowBackend());
			}
			if (have_standin && xdp)
			{
				NicBridgeRun(&ctx, n, &standin, NodeL2XdpBackend());
			}
			if (have_nic)
			{
				NicBridgeRun(&ctx, n, &nic, NodeL2SeLowBackend());
			}
			if (have_nic && xdp)
			{
				NicBridgeRun(&ctx, n, &nic, NodeL2XdpBackend());
			}
		}
	}

	if (n != NULL)
	{
		NodeKmTestFree(standin.KmTest, true);
		NodeStop(n);
		FreeNode(n);
	}
	NicBridgeDeleteDir(dir);

	WSACleanup();

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
		Print("NICBRIDGE TEST OK\n");
	}
	else
	{
		Print("NICBRIDGE TEST FAILED (%u of %u checks failed)\n", ctx.NumFailed, ctx.NumChecks);
	}
}
