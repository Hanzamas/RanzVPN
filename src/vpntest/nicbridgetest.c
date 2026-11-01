// nicbridgetest.c
// Named NIC bridge test of vpntest ("nicbridge" command, CORE-S3-3 #73)
//
// The bridge of an L2 Network to a segment through the backend interface (Cedar/NodeL2Bridge.c): in each run an L2 bridge
// (NodeL2BridgeNew) is the member of a port of the switch of an L2 Network, beside a member of the Network that the test
// plays at another port, so that the bridged L2 segment reaches the devices of the segment. The attachments are the ones
// that CI has (ADR-0002 amendment of 2026-10-21):
// - the runner's own NIC, the physical side, whose LAN device is the host stack on the NIC, since no network of a
//   runner carries the frames of another MAC address: the member asks the gateway of the NIC for its MAC address from
//   its own, and whether the gateway answered is printed for the record (NICBRIDGE DIAG <backend> nic gateway);
// - a KM-TEST adapter standing in for the host vNIC of a Hyper-V virtual switch, whose host stack plays the devices on
//   the switch;
// - and, when the job made one (.github/scripts/kmtest.ps1), a Hyper-V virtual switch of the runner itself: the bridge
//   takes the host vNIC of the switch, found by the name of the switch (NodeL2HyperVIndex), and a second host vNIC on
//   the switch is a device of the Hyper-V network, whose frames reach the bridge from below its vNIC, through the switch,
//   as the frames of a virtual machine do.
// The XDP job of windows.yml runs it after ranz install as administrator (.github/scripts/kmtest.ps1); it needs the
// drivers, so the smoke loop leaves it out (.github/quality/smoke-exclude.txt). Its arguments: the backends, "selow" (the
// default), "xdp" (SeLow, then XDP, on the same attachments, for the comparison) or "npcap" (SeLow, then Npcap, then XDP
// with Npcap's hold, on the same attachments); then the name of the Hyper-V switch and of the device's vNIC on it, when
// the job made them, and the name of the external switch that the test makes itself.
// The spike of ADR-0018 decision 3, for each backend on each attachment:
// - Foreign-MAC transmit: frames of the overlay from the member's MAC address go through the switch to the bridge, which
//   puts them onto the segment (on the NIC its counter of sent frames rises by them). Datagrams of the member reach a
//   socket of the device, and an ARP request of the member for the device's address is answered.
// - Foreign-MAC receive: the device's ARP reply to the member, and the datagrams that the device sends to the member (a
//   permanent neighbour), are captured with the member's address as their destination and reach the member through the
//   switch.
// - Coexistence with the host stack: on the runner's NIC the host's own TCP connection through the NIC works while the
//   bridge is on and after it went, the host resolves its gateway again while the bridge is on, and the bridge sends no
//   probe onto the LAN; the gateway's ARP reply is a frame of the wire to the NIC's own address, which the XDP backend
//   takes on RX inspect, as no rule lets an ARP frame pass, and hands back to the host (NODE_L2_STATUS.ToHost). On a
//   Hyper-V switch the host resolves the link-local address of the device through the bridged vNIC while the bridge is
//   on and after it went.
// - Throughput against SeLow: on the stand-in and on a Hyper-V switch, frames of 1514 bytes of the member onto the
//   segment and to the device, and the device's datagrams to the member, for 2 s each, printed as NICBRIDGE BENCH lines
//   for each backend; each backend that runs after SeLow on the same attachment also prints its rates as shares of
//   SeLow's ("NICBRIDGE BENCH <backend> <attachment> against selow"): a regression number of the runner, not a gate
//   (ADR-0002 amendment of 2026-10-21).
// XDP takes the frames that come in from below the interface, and NDIS loopback is no such frame (XDP inspects none of
// them), while neither a KM-TEST adapter nor the network of a runner gives one for a member's address. So for XDP on
// those two the lines of the frames to and from the device are printed (NICBRIDGE DIAG), and its checks there are the
// transmit onto the wire, coexistence, the frames of the wire that come back to the host, shutdown and the benchmark; on
// a Hyper-V switch, where the device's frames come from below, XDP passes every check. The NIC is held in promiscuous
// mode for XDP by the device of SeLow (the test's own hold) in the xdp mode, and by the product's hold through Npcap
// (NodeL2NpcapHold) in the npcap mode.
// - Npcap and the default: an L2 bridge whose owner names no backend binds SeLow on the NIC. Npcap is used only where it
//   is installed: on a runner without it, a bridge on Npcap alone does not come up. No runner may carry Npcap (its free
//   licence allows five installations and has no silent install), so the npcap mode gives the Npcap backend a stand-in
//   of Npcap's pcap API (NodeL2NpcapStandIn) whose handles are the SeLow device of the adapter: SeLow keeps the adapter
//   promiscuous while its device is open, and hands over no frame that the handle sent itself, as Npcap does for a handle
//   opened with PCAP_OPENFLAG_PROMISCUOUS and PCAP_OPENFLAG_NOCAPTURE_LOCAL. The Npcap backend, then XDP with Npcap's
//   hold, pass the spike on it.
// - The NIC of an external Hyper-V virtual switch, when the job names one (the scope note of #73): the switch owns the
//   NIC, so an XDP program or a bridge there would take the frames of every port of the switch, the host's vNIC among
//   them. The test binds an external switch of that name to a KM-TEST adapter of its own with the cmdlets of Hyper-V
//   (New-VMSwitch -NetAdapterName, with a vNIC of the host), so that the runner's NIC stays as it is: NodeL2BridgeIndex
//   refuses the adapter, which it took before, and names the host vNIC of the switch, which NodeL2HyperVIndex finds.
// The stand-in is a new interface of the host in each run, and Windows Firewall quarantines a new interface until it has
// categorized its network: in that time it drops every new inbound connection, whatever its rules say, and it dropped
// the datagrams of the member so for seconds now and then (CI-FLAKE-3, #569). So before the stand-in takes part, the test
// waits until its address is preferred and its host stack takes a datagram that the SeLow device of its adapter hands
// it, without a bridge; and the datagrams of the member must then all reach the socket of the device, 5 of 5.
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

#include "Core/Switch.h"

#include <iphlpapi.h>
#include <ws2tcpip.h>

#include <stdio.h>

// The GUIDs of the conditions of the filter engine are defined here, as NodeWireGuardFilter.c defines them: the test reads
// the drops that the engine recorded of datagrams that did not reach a socket (CI-FLAKE-3, #569)
#include <initguid.h>
#include <fwpmu.h>

#define	NICBRIDGE_BUDGET		480000		// The whole test ends within this time, or the watchdog ends the process (ms)
#define	NICBRIDGE_BOUND			15000		// A bounded wait on observable state (ms)
#define	NICBRIDGE_ANSWER		5000		// ms that an answer of the host may take
#define	NICBRIDGE_POLL			20			// Poll interval of observable state (ms)
#define	NICBRIDGE_NETWORK		76			// The Network id of the stand-in, and of the MAC addresses of the test after it
#define	NICBRIDGE_LENGTH		24			// The prefix length of the addresses of the stand-in and of the device on a Hyper-V switch
#define	NICBRIDGE_VLAN			1			// The VLAN of the member and of the bridge in the switch of a run
#define	NICBRIDGE_RX_PORT		5566		// UDP port of the socket of the device that takes the datagrams of the member
#define	NICBRIDGE_TX_PORT		5567		// UDP port of the datagrams that the device sends to the member
#define	NICBRIDGE_BENCH_PORT	5568		// UDP port of the sink of the benchmark
#define	NICBRIDGE_WIRE			1000		// Frames of the member onto the wire, to another address
#define	NICBRIDGE_ETHERTYPE		0x88B5		// The local experimental EtherType of IEEE 802 for those frames
#define	NICBRIDGE_BENCH_TIME	2000		// ms of each benchmark run
#define	NICBRIDGE_RATES			3			// The rates of a benchmark: onto the segment, to the device, from the device
#define	NICBRIDGE_SEGMENT		1472		// Bytes of the payload of a datagram of the benchmark: frames of 1514 bytes
#define	NICBRIDGE_ARP_FRAME		60			// Bytes of an ARP frame, padded to the shortest Ethernet frame
#define	NICBRIDGE_TCP_HOST		"github.com"	// A host on the internet that the runner reaches through its NIC
#define	NICBRIDGE_TCP_PORT		"443"
#define	NICBRIDGE_PCAP_ERRBUF	256			// Bytes of the error text of a pcap call (PCAP_ERRBUF_SIZE)
#define	NICBRIDGE_PCAP_READS	4			// Reads of the SeLow device that one pcap_next_ex of the stand-in makes at most
#define	NICBRIDGE_NPF			"\\Device\\NPF_"	// What the device of a handle of Npcap begins with, before the GUID of the adapter
#define	NICBRIDGE_PS_WAIT		120000		// ms that a command of PowerShell may take
#define	NICBRIDGE_PS_OUTPUT		65536		// Bytes of the pipe of its output, more than it writes
#define	NICBRIDGE_LATE			20000		// ms that the record of a lost datagram waits at most for one that arrives (#569)
#define	NICBRIDGE_DROPS			64			// Net events of the filter engine that one read of the record of dropped datagrams takes
#define	NICBRIDGE_FILTERS		8			// Filters that the record of dropped datagrams names at most
#define	NICBRIDGE_READY_PORT	5569		// UDP port of the socket of the stand-in that takes the datagrams of the wait for its host stack
#define	NICBRIDGE_READY_EVERY	100			// ms between two of those datagrams
#define	NICBRIDGE_QUARANTINE	60000		// ms that the host stack of the stand-in may take to take datagrams from the segment (#569)

// The checks of the test
typedef struct NICBRIDGE_CTX
{
	UINT NumChecks;
	UINT NumFailed;
} NICBRIDGE_CTX;

// The member of the L2 Network that the test plays at a port of its switch: counts the frames that the switch hands it,
// and those of them to its address
typedef struct NICBRIDGE_OWNER
{
	UCHAR Member[6];					// The MAC address of the member of the overlay
	UINT Gateway;						// The IPv4 address of the gateway of the attachment, in network byte order; 0 for none
	volatile LONG64 Frames;				// Frames that the switch handed the member
	volatile LONG64 ToMember;			// ... to the member
	volatile LONG64 ArpReplies;			// ... of these, ARP replies
	volatile LONG64 GatewayReplies;		// ... of the ARP replies, the gateway's
	volatile LONG64 Udp;				// ... of the frames to the member, UDP datagrams to NICBRIDGE_TX_PORT
} NICBRIDGE_OWNER;

// One attachment of the test: the runner's NIC, the KM-TEST adapter that stands in for a Hyper-V switch, or a Hyper-V switch
typedef struct NICBRIDGE_PORT
{
	char *Name;							// What it is, in the lines of the test
	char *Tag;							// ... in the NICBRIDGE BENCH lines
	UINT IfIndex;						// The interface of the bridge
	UINT64 Luid;
	UCHAR Mac[6];
	UINT64 HostLuid;					// The interface of the host stack that plays the device: the bridge's, or the device's vNIC on a Hyper-V switch
	UCHAR HostMac[6];
	UINT Address;						// The IPv4 address of the device, in network byte order; 0 for none
	UINT Member;						// The IPv4 address of the member of the overlay on its subnet; 0 for none
	UINT Gateway;						// The IPv4 address of its default gateway, in network byte order; 0 for none
	bool Wire;							// The device's frames reach the bridge from below its interface, through a Hyper-V switch
	NODE_KMTEST *KmTest;				// The KM-TEST adapter of the stand-in, NULL for the others
	UINT64 Made;						// ... the tick at which it was made, 0 for the others
	UINT64 SeLow[NICBRIDGE_RATES];		// The rates of SeLow's benchmark on it in this run, for the backends after it (frames/s)
	bool HaveSeLow;						// ... measured
} NICBRIDGE_PORT;

// The L2 Network of a run: its switch, the port of the member that the test plays, and the L2 bridge
typedef struct NICBRIDGE_NET
{
	SWITCH *Switch;
	UINT MemberPort;
	NODE_L2_BRIDGE *Bridge;
} NICBRIDGE_NET;

// The sink of the benchmark
typedef struct NICBRIDGE_SINK
{
	SOCKET Sock;
	volatile LONG Stop;
	HANDLE Thread;
	volatile LONG64 Received;
} NICBRIDGE_SINK;

// A handle of the stand-in of Npcap's pcap API (NodeL2NpcapStandIn): the SeLow device of the adapter that it was opened
// on, the next frame of its read buffer, and a filter that takes no frame
typedef struct NICBRIDGE_PCAP
{
	SU_ADAPTER *Su;
	UINT Next;
	bool Reject;
	NODE_L2_PCAP_HEADER Header;
	char Error[MAX_SIZE];
} NICBRIDGE_PCAP;

// The drops of datagrams that the filter engine recorded for one of its filters, in the record of dropped datagrams (#569)
typedef struct NICBRIDGE_DROP
{
	UINT64 FilterId;
	UINT Layer;							// The layer of the filter engine where it dropped them
	UINT Count;							// The drops, which can be more than the datagrams
	UINT64 First;						// ms after the start of the record that it dropped the first of them
	UINT64 Last;						// ... and the last
} NICBRIDGE_DROP;

// The MAC addresses of the test, derived as NodeL2Mac derives those of adapters: the stand-in, the member of the overlay,
// another address of the segment and the KM-TEST adapter that is the NIC of an external switch
static UCHAR nicbridge_standin_mac[6];
static UCHAR nicbridge_member_mac[6];
static UCHAR nicbridge_other_mac[6];
static UCHAR nicbridge_external_mac[6];
static UCHAR nicbridge_broadcast[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

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
static bool NicBridgeWaitInjected(NODE_L2_BRIDGE *b, UINT64 want, NODE_L2_STATUS *st)
{
	UINT64 end = GetTickCount64() + NICBRIDGE_BOUND;

	while (true)
	{
		NodeL2BridgeGetStatus(b, st);
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
// The member, the holds and the stand-in of Npcap
//

// The port of the member in the switch (SWITCH_SEND_PROC): counts the frames, and those to the member by kind
static void NicBridgeMemberSend(void *param, UINT port, const UCHAR *frame, UINT size)
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

		// The address of the sender of the reply, after its MAC address
		if (o->Gateway != 0 && Cmp(frame + 28, &o->Gateway, 4) == 0)
		{
			InterlockedIncrement64(&o->GatewayReplies);
		}
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

// The id of the SeLow device of the adapter of the GUID g, which SuOpenAdapter opens, into id
static void NicBridgeSeLowId(char *id, UINT size, const GUID *g)
{
	Format(id, size, SL_ADAPTER_ID_PREFIX "{%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X}", (UINT)g->Data1, (UINT)g->Data2, (UINT)g->Data3, (UINT)g->Data4[0],
		(UINT)g->Data4[1], (UINT)g->Data4[2], (UINT)g->Data4[3], (UINT)g->Data4[4], (UINT)g->Data4[5], (UINT)g->Data4[6], (UINT)g->Data4[7]);
}

// One frame through the exchange buffer of the SeLow device su, which hands it to the host as the selow backend's frames;
// whether the device took it
static bool NicBridgeSeLowPut(SU_ADAPTER *su, const UCHAR *frame, UINT size)
{
	UCHAR *buf = su->PutBuffer;

	if (size < SL_MIN_PACKET_SIZE || size > SL_MAX_PACKET_SIZE)
	{
		return false;
	}

	SL_NUM_PACKET(buf) = 1;
	SL_SIZE_OF_PACKET(buf, 0) = size;
	Copy(SL_ADDR_OF_PACKET(buf, 0), frame, size);

	return SuPutPacketsToDriver(su);
}

// What holds the NIC of a bridge in promiscuous mode for the XDP backend in the xdp mode: the device of SeLow on the
// interface, which sets the mode when it is opened. The product takes Npcap (NodeL2NpcapHold), as the npcap mode does.
static bool NicBridgeHold(NODE_L2 *a, void **hold, char *error, UINT error_size)
{
	char id[MAX_SIZE];

	NicBridgeSeLowId(id, sizeof(id), &a->Guid);

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

// pcap_open of the stand-in: the SeLow device of the adapter of the GUID that the device of Npcap names
static void *NicBridgePcapOpen(const char *source, int snaplen, int flags, int read_timeout, void *auth, char *errbuf)
{
	char id[MAX_SIZE];

	if (source == NULL || StartWith(source, NICBRIDGE_NPF) == false)
	{
		StrCpy(errbuf, NICBRIDGE_PCAP_ERRBUF, "the stand-in of Npcap opens devices of Npcap only");
		return NULL;
	}

	Format(id, sizeof(id), SL_ADAPTER_ID_PREFIX "%s", source + StrLen(NICBRIDGE_NPF));
	SU_ADAPTER *su = SuOpenAdapter(id);
	if (su == NULL)
	{
		Format(errbuf, NICBRIDGE_PCAP_ERRBUF, "the SeLow device %s cannot be opened (error %u)", id, (UINT)GetLastError());
		return NULL;
	}

	NICBRIDGE_PCAP *p = ZeroMalloc(sizeof(NICBRIDGE_PCAP));
	p->Su = su;

	return p;
}

static void NicBridgePcapClose(void *h)
{
	NICBRIDGE_PCAP *p = (NICBRIDGE_PCAP *)h;

	SuCloseAdapter(p->Su);
	Free(p);
}

// pcap_next_ex of the stand-in: the next frame of the read buffer of the device, in place, which the device fills again
// once it is used up. 0 when the device holds no frame, -1 when its read failed.
static int NicBridgePcapNextEx(void *h, NODE_L2_PCAP_HEADER **header, const UCHAR **data)
{
	NICBRIDGE_PCAP *p = (NICBRIDGE_PCAP *)h;
	UCHAR *buf = p->Su->GetBuffer;
	UINT reads = 0;

	if (p->Reject)
	{
		return 0;
	}

	while (true)
	{
		UINT num = MIN(SL_NUM_PACKET(buf), (UINT)SL_MAX_PACKET_EXCHANGE);

		if (p->Next < num)
		{
			UINT size = SL_SIZE_OF_PACKET(buf, p->Next);

			*data = (const UCHAR *)SL_ADDR_OF_PACKET(buf, p->Next);
			p->Next++;
			Zero(&p->Header, sizeof(p->Header));
			p->Header.Captured = size;
			p->Header.Size = size;
			*header = &p->Header;
			return 1;
		}

		if (reads == NICBRIDGE_PCAP_READS)
		{
			return 0;
		}
		reads++;

		if (SuGetPacketsFromDriver(p->Su) == false)
		{
			StrCpy(p->Error, sizeof(p->Error), "a read of the SeLow device failed");
			return -1;
		}
		p->Next = 0;

		// An empty read: the device's queue is empty, and it signals its event for the next frame
		if (SL_NUM_PACKET(buf) == 0 && SL_LEFT_FLAG(buf) == 0)
		{
			return 0;
		}
	}
}

// pcap_sendpacket of the stand-in: one frame through the exchange buffer of the device
static int NicBridgePcapSendPacket(void *h, const UCHAR *data, int size)
{
	NICBRIDGE_PCAP *p = (NICBRIDGE_PCAP *)h;

	return ((size > 0 && NicBridgeSeLowPut(p->Su, data, (UINT)size)) ? 0 : -1);
}

static HANDLE NicBridgePcapGetEvent(void *h)
{
	return (HANDLE)((NICBRIDGE_PCAP *)h)->Su->hEvent;
}

// pcap_setfilter of the stand-in: the one instruction "ret #0" takes no frame; it takes no other filter
static int NicBridgePcapSetFilter(void *h, NODE_L2_BPF_PROGRAM *program)
{
	NICBRIDGE_PCAP *p = (NICBRIDGE_PCAP *)h;

	if (program == NULL || program->Length != 1 || program->Instructions[0].Code != NODE_L2_BPF_REJECT || program->Instructions[0].K != 0)
	{
		StrCpy(p->Error, sizeof(p->Error), "the stand-in of Npcap takes no other filter");
		return -1;
	}
	p->Reject = true;

	return 0;
}

static char *NicBridgePcapGetErr(void *h)
{
	return ((NICBRIDGE_PCAP *)h)->Error;
}

static const NODE_L2_PCAP_API nicbridge_pcap_api = {NicBridgePcapOpen, NicBridgePcapClose, NicBridgePcapNextEx, NicBridgePcapSendPacket, NicBridgePcapGetEvent, NicBridgePcapSetFilter, NicBridgePcapGetErr};

//
// The L2 Network of a run
//

// The L2 Network of a run: a switch with the member that the test plays and an L2 bridge of the backend b (NULL for the
// default ones) on the attachment p, both access ports of one VLAN; the member takes the broadcast group, which also
// takes the frames to an address that the Network has not learnt. own_hold: the test's own hold of promiscuous mode for
// XDP, else the product's (NodeL2NpcapHold). False when the bridge did not come up.
static bool NicBridgeNetNew(NICBRIDGE_NET *net, NODE *n, NICBRIDGE_PORT *p, const NODE_L2_BACKEND *b, NICBRIDGE_OWNER *o, bool own_hold)
{
	const NODE_L2_BACKEND *list[1];
	SWITCH_PORT_CONFIG pc;
	NODE_L2_CONFIG cfg;

	Zero(net, sizeof(NICBRIDGE_NET));
	net->MemberPort = SWITCH_PORT_NONE;
	net->Switch = SwitchNew(NULL);
	if (net->Switch == NULL)
	{
		return false;
	}

	Zero(&pc, sizeof(pc));
	pc.Mode = SWITCH_ACCESS;
	pc.Vlan = NICBRIDGE_VLAN;
	pc.Send = NicBridgeMemberSend;
	pc.Param = o;
	net->MemberPort = SwitchAddPort(net->Switch, &pc);
	if (net->MemberPort == SWITCH_PORT_NONE || SwitchSubscribe(net->Switch, net->MemberPort, NICBRIDGE_VLAN, nicbridge_broadcast) == false)
	{
		return false;
	}

	pc.Send = NULL;
	pc.Param = NULL;
	Zero(&cfg, sizeof(cfg));
	cfg.IfIndex = p->IfIndex;
	if (b != NULL)
	{
		list[0] = b;
		cfg.Backends = list;
		cfg.NumBackends = 1;
	}
	if (own_hold)
	{
		cfg.Hold = NicBridgeHold;
		cfg.LetGo = NicBridgeLetGo;
	}
	net->Bridge = NodeL2BridgeNew(n, net->Switch, &pc, &cfg);

	return (net->Bridge != NULL);
}

// Take the L2 bridge of a run down, then its switch; false when the bridge did not go in time, which leaves the switch
static bool NicBridgeNetFree(NICBRIDGE_NET *net)
{
	bool ok = NodeL2BridgeFree(net->Bridge);

	if (ok && net->Switch != NULL)
	{
		SwitchFree(net->Switch);
	}
	Zero(net, sizeof(NICBRIDGE_NET));

	return ok;
}

// A frame of the member into the switch of its Network; whether the switch handed it to a port
static bool NicBridgeFromMember(NICBRIDGE_NET *net, const UCHAR *frame, UINT size)
{
	return (SwitchInput(net->Switch, GetTickCount64(), net->MemberPort, frame, size) != 0);
}

//
// The host's stack
//

// A UDP socket bound to the address addr and port port (0 for any). INVALID_SOCKET when it cannot be made or bound, with
// the error of Winsock in *error, which is 0 for a socket that was made and bound.
static SOCKET NicBridgeSocket(UINT addr, USHORT port, int *error)
{
	SOCKADDR_IN sa;
	SOCKET s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);

	*error = 0;
	if (s == INVALID_SOCKET)
	{
		*error = WSAGetLastError();
		return s;
	}

	Zero(&sa, sizeof(sa));
	sa.sin_family = AF_INET;
	sa.sin_addr.s_addr = addr;
	sa.sin_port = htons(port);
	if (bind(s, (SOCKADDR *)&sa, sizeof(sa)) != 0)
	{
		*error = WSAGetLastError();
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

// The preferred link-local IPv6 address of the interface luid into addr; false for none
static bool NicBridgeLinkLocal(UINT64 luid, UCHAR *addr)
{
	MIB_UNICASTIPADDRESS_TABLE *t = NULL;
	bool ret = false;

	if (GetUnicastIpAddressTable(AF_INET6, &t) != NO_ERROR)
	{
		return false;
	}

	for (ULONG i = 0;i < t->NumEntries && ret == false;i++)
	{
		MIB_UNICASTIPADDRESS_ROW *row = &t->Table[i];
		const UCHAR *p = row->Address.Ipv6.sin6_addr.u.Byte;

		if (row->InterfaceLuid.Value != luid || row->DadState != IpDadStatePreferred || p[0] != 0xFE || (p[1] & 0xC0) != 0x80)
		{
			continue;
		}

		Copy(addr, p, 16);
		ret = true;
	}

	FreeMibTable(t);

	return ret;
}

// Make the host ask, on the interface luid, for the MAC address of the link-local IPv6 address addr again: its neighbour
// entry goes, and ResolveIpNetEntry2 sends a Neighbor Solicitation and waits for the advertisement. True when the host
// learnt the MAC address mac for it.
static bool NicBridgeResolve6(UINT64 luid, const UCHAR *addr, const UCHAR *mac)
{
	MIB_IPNET_ROW2 nb;

	Zero(&nb, sizeof(nb));
	nb.InterfaceLuid.Value = luid;
	nb.Address.Ipv6.sin6_family = AF_INET6;
	Copy(&nb.Address.Ipv6.sin6_addr, addr, 16);
	DeleteIpNetEntry2(&nb);

	DWORD err = ResolveIpNetEntry2(&nb, NULL);
	if (err != NO_ERROR)
	{
		Print("  ResolveIpNetEntry2 of a link-local address: error %u\n", (UINT)err);
		return false;
	}

	return (nb.PhysicalAddressLength == 6 && Cmp(nb.PhysicalAddress, mac, 6) == 0);
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

// The state of duplicate address detection of the IPv4 address addr of the interface luid, in words into s: true when the
// address is preferred, the one state in which the host takes datagrams to it
static bool NicBridgeAddressState(UINT64 luid, UINT addr, char *s, UINT size)
{
	MIB_UNICASTIPADDRESS_ROW row;
	char *names[] = {"invalid", "tentative", "duplicate", "deprecated", "preferred"};

	InitializeUnicastIpAddressEntry(&row);
	row.InterfaceLuid.Value = luid;
	row.Address.Ipv4.sin_family = AF_INET;
	row.Address.Ipv4.sin_addr.s_addr = addr;
	DWORD err = GetUnicastIpAddressEntry(&row);
	if (err != NO_ERROR)
	{
		Format(s, size, "not on the interface (GetUnicastIpAddressEntry: error %u)", (UINT)err);
		return false;
	}

	Format(s, size, "%s", (UINT)row.DadState < sizeof(names) / sizeof(names[0]) ? names[row.DadState] : "in an unknown state");

	return (row.DadState == IpDadStatePreferred);
}

// Give the interface luid the IPv4 address addr/length, and wait up to NICBRIDGE_BOUND ms until it is preferred: false,
// with what went wrong in error, when the interface did not take it or it did not become preferred in that time
static bool NicBridgeAddAddress(UINT64 luid, UINT addr, UINT length, char *error, UINT error_size)
{
	MIB_UNICASTIPADDRESS_ROW row;
	char state[MAX_SIZE];

	InitializeUnicastIpAddressEntry(&row);
	row.InterfaceLuid.Value = luid;
	row.Address.Ipv4.sin_family = AF_INET;
	row.Address.Ipv4.sin_addr.s_addr = addr;
	row.OnLinkPrefixLength = (UCHAR)length;
	row.DadState = IpDadStatePreferred;
	DWORD err = CreateUnicastIpAddressEntry(&row);
	if (err != NO_ERROR && err != ERROR_OBJECT_ALREADY_EXISTS)
	{
		Format(error, error_size, "CreateUnicastIpAddressEntry: error %u", (UINT)err);
		return false;
	}

	UINT64 end = GetTickCount64() + NICBRIDGE_BOUND;
	while (NicBridgeAddressState(luid, addr, state, sizeof(state)) == false)
	{
		if (GetTickCount64() >= end)
		{
			Format(error, error_size, "the address is %s, not preferred, %u ms after it was given", state, (UINT)NICBRIDGE_BOUND);
			return false;
		}
		Sleep(NICBRIDGE_POLL);
	}

	StrCpy(error, error_size, "");

	return true;
}

// Take the IPv4 address addr off the interface luid again
static void NicBridgeDelAddress(UINT64 luid, UINT addr)
{
	MIB_UNICASTIPADDRESS_ROW row;

	InitializeUnicastIpAddressEntry(&row);
	row.InterfaceLuid.Value = luid;
	row.Address.Ipv4.sin_family = AF_INET;
	row.Address.Ipv4.sin_addr.s_addr = addr;
	DeleteUnicastIpAddressEntry(&row);
}

// What the test finds of the device of p before the member sends it datagrams, into s: whether the socket of the device
// bound to its address and the port port (bind_error is the error of Winsock when it did not), the state of the address,
// and the interface of the host stack that holds it, with its index, its MAC address and whether it is up; for the
// stand-in also the time since its adapter was made (CI-FLAKE-3, #569)
static void NicBridgeHostState(NICBRIDGE_PORT *p, USHORT port, int bind_error, char *s, UINT size)
{
	MIB_IF_ROW2 row;
	MIB_IPINTERFACE_ROW ip;
	char socket_text[MAX_SIZE];
	char address[MAX_SIZE];
	char state[MAX_SIZE];
	char made[MAX_SIZE];

	if (bind_error == 0)
	{
		Format(socket_text, sizeof(socket_text), "the socket of the device bound to %u.%u.%u.%u:%u", p->Address & 0xFF, (p->Address >> 8) & 0xFF, (p->Address >> 16) & 0xFF,
			p->Address >> 24, (UINT)port);
	}
	else
	{
		Format(socket_text, sizeof(socket_text), "the socket of the device did not bind to %u.%u.%u.%u:%u (Winsock error %d)", p->Address & 0xFF, (p->Address >> 8) & 0xFF,
			(p->Address >> 16) & 0xFF, p->Address >> 24, (UINT)port, bind_error);
	}

	NicBridgeAddressState(p->HostLuid, p->Address, address, sizeof(address));

	Zero(&row, sizeof(row));
	row.InterfaceLuid.Value = p->HostLuid;
	DWORD err = GetIfEntry2(&row);
	if (err == NO_ERROR)
	{
		InitializeIpInterfaceEntry(&ip);
		ip.Family = AF_INET;
		ip.InterfaceLuid.Value = p->HostLuid;
		bool ipv4 = (GetIpInterfaceEntry(&ip) == NO_ERROR && ip.Connected);

		Format(state, sizeof(state), "interface %u, MAC %02X-%02X-%02X-%02X-%02X-%02X, %s, media %s, IPv4 %s", (UINT)row.InterfaceIndex, (UINT)row.PhysicalAddress[0],
			(UINT)row.PhysicalAddress[1], (UINT)row.PhysicalAddress[2], (UINT)row.PhysicalAddress[3], (UINT)row.PhysicalAddress[4], (UINT)row.PhysicalAddress[5],
			row.OperStatus == IfOperStatusUp ? "up" : "not up",
			row.MediaConnectState == MediaConnectStateConnected ? "connected" : (row.MediaConnectState == MediaConnectStateDisconnected ? "disconnected" : "unknown"),
			ipv4 ? "connected" : "not connected");
	}
	else
	{
		Format(state, sizeof(state), "its interface cannot be read (GetIfEntry2: error %u)", (UINT)err);
	}

	StrCpy(made, sizeof(made), "");
	if (p->Made != 0)
	{
		Format(made, sizeof(made), ", %I64u ms after the adapter was made", GetTickCount64() - p->Made);
	}

	Format(s, size, "%s, the address %s, %s%s", socket_text, address, state, made);
}

// The drops of datagrams to the UDP port port of this host that the filter engine recorded since the time since, for the
// record (CI-FLAKE-3, #569): a NICBRIDGE DIAG line of who for each filter that dropped them, with how many drops it
// recorded, its name and the name of its sublayer, then one with how many drops were recorded in all, which it returns.
// The engine can record more than one drop of one datagram (2 to 4 in the logs of #569), so the count is of drops, not of
// datagrams. The name of the filter with the most drops goes into filter, "" for none. The engine keeps such net events
// while its option FWPM_ENGINE_COLLECT_NET_EVENTS is on.
static UINT NicBridgeDrops(char *who, USHORT port, const FILETIME *since, char *filter, UINT filter_size)
{
	FWPM_SESSION0 session;
	FWPM_NET_EVENT_ENUM_TEMPLATE0 t;
	FWPM_FILTER_CONDITION0 c;
	FWP_VALUE0 *collect = NULL;
	NICBRIDGE_DROP list[NICBRIDGE_FILTERS];
	HANDLE engine = NULL;
	HANDLE en = NULL;
	UINT num_list = 0;
	UINT drops = 0;
	UINT most = 0;

	Zero(filter, filter_size);
	Zero(list, sizeof(list));
	Zero(&session, sizeof(session));
	DWORD err = FwpmEngineOpen0(NULL, RPC_C_AUTHN_WINNT, NULL, &session, &engine);
	if (err != ERROR_SUCCESS)
	{
		Print("NICBRIDGE DIAG %s wfp: the filter engine cannot be opened (error 0x%x)\n", who, (UINT)err);
		return 0;
	}

	bool on = (FwpmEngineGetOption0(engine, FWPM_ENGINE_COLLECT_NET_EVENTS, &collect) == ERROR_SUCCESS && collect != NULL && collect->type == FWP_UINT32 && collect->uint32 != 0);
	if (collect != NULL)
	{
		FwpmFreeMemory0((void **)&collect);
	}

	Zero(&c, sizeof(c));
	c.fieldKey = FWPM_CONDITION_IP_LOCAL_PORT;
	c.matchType = FWP_MATCH_EQUAL;
	c.conditionValue.type = FWP_UINT16;
	c.conditionValue.uint16 = port;
	Zero(&t, sizeof(t));
	t.startTime = *since;
	GetSystemTimeAsFileTime(&t.endTime);
	t.numFilterConditions = 1;
	t.filterCondition = &c;

	err = FwpmNetEventCreateEnumHandle0(engine, &t, &en);

	// The events come in reads of NICBRIDGE_DROPS each, and the drops of each filter are counted
	UINT64 from = ((UINT64)since->dwHighDateTime << 32) | since->dwLowDateTime;
	UINT32 num = NICBRIDGE_DROPS;
	while (err == ERROR_SUCCESS && num == NICBRIDGE_DROPS)
	{
		FWPM_NET_EVENT0 **events = NULL;

		num = 0;
		err = FwpmNetEventEnum0(engine, en, NICBRIDGE_DROPS, &events, &num);
		for (UINT32 i = 0;err == ERROR_SUCCESS && events != NULL && i < num;i++)
		{
			FWPM_NET_EVENT0 *e = events[i];
			UINT j = 0;

			if (e == NULL || e->type != FWPM_NET_EVENT_TYPE_CLASSIFY_DROP || e->classifyDrop == NULL)
			{
				continue;
			}
			drops++;

			UINT64 at = ((UINT64)e->header.timeStamp.dwHighDateTime << 32) | e->header.timeStamp.dwLowDateTime;
			at = (at >= from ? (at - from) / 10000 : 0);
			while (j < num_list && list[j].FilterId != e->classifyDrop->filterId)
			{
				j++;
			}
			if (j == num_list)
			{
				if (num_list == NICBRIDGE_FILTERS)
				{
					continue;
				}
				list[j].FilterId = e->classifyDrop->filterId;
				list[j].Layer = (UINT)e->classifyDrop->layerId;
				list[j].First = at;
				num_list++;
			}
			list[j].Count++;
			list[j].Last = at;
		}
		if (events != NULL)
		{
			FwpmFreeMemory0((void **)&events);
		}
	}

	for (UINT j = 1;j < num_list;j++)
	{
		if (list[j].Count > list[most].Count)
		{
			most = j;
		}
	}
	for (UINT j = 0;j < num_list;j++)
	{
		FWPM_FILTER0 *f = NULL;
		FWPM_SUBLAYER0 *sub = NULL;

		if (FwpmFilterGetById0(engine, list[j].FilterId, &f) == ERROR_SUCCESS && f != NULL)
		{
			FwpmSubLayerGetByKey0(engine, &f->subLayerKey, &sub);
		}

		wchar_t *name = ((f != NULL && f->displayData.name != NULL) ? f->displayData.name : L"?");
		Print("NICBRIDGE DIAG %s wfp: %u drops of datagrams to port %u by filter %I64u '%S' of the sublayer '%S' at layer %u, from %I64u to %I64u ms after the step began\n",
			who, list[j].Count, (UINT)port, list[j].FilterId, name, (sub != NULL && sub->displayData.name != NULL) ? sub->displayData.name : L"?", list[j].Layer,
			list[j].First, list[j].Last);
		if (j == most)
		{
			UniToUtf8(filter, filter_size - 1, name);
		}

		if (sub != NULL)
		{
			FwpmFreeMemory0((void **)&sub);
		}
		if (f != NULL)
		{
			FwpmFreeMemory0((void **)&f);
		}
	}

	if (en != NULL)
	{
		FwpmNetEventDestroyEnumHandle0(engine, en);
	}
	FwpmEngineClose0(engine);

	Print("NICBRIDGE DIAG %s wfp: %u drops of datagrams to port %u recorded since the step began (the engine %s net events; error 0x%x)\n", who, drops, (UINT)port,
		on ? "collects" : "does not collect", (UINT)err);

	return drops;
}

// Wait until the host stack of the stand-in p takes datagrams from the segment, NICBRIDGE_QUARANTINE ms at most: its
// interface up, and out of the quarantine of Windows Firewall. Windows Firewall quarantines an interface that changed, a
// new one among them, until it has categorized its network, and in that time drops every new inbound connection, whatever
// its rules say; so it dropped, for seconds now and then, the datagrams of the member that a bridge put into the host
// stack of a stand-in made a moment before, by its filter 'Quarantine Default Inbound Block' (CI-FLAKE-3, #569). A
// datagram from another address of the segment goes to a socket of the stand-in every NICBRIDGE_READY_EVERY ms until one
// arrives, through the SeLow device of the adapter of the GUID guid, which hands frames to the host as the selow backend
// does, but without a bridge. What the wait found goes into s; false when no datagram arrived.
static bool NicBridgeHostReady(NICBRIDGE_PORT *p, const GUID *guid, char *s, UINT size)
{
	UCHAR frame[NODE_L2_MAX_FRAME];
	MIB_IF_ROW2 row;
	FILETIME since;
	SU_ADAPTER *su = NULL;
	char buf[2048];
	char id[MAX_SIZE];
	char who[MAX_SIZE];
	char filter[MAX_SIZE];
	char dropped[MAX_SIZE * 2];
	int timeout = NICBRIDGE_READY_EVERY;
	int error = 0;
	UINT sent = 0;
	bool up = false;
	bool opened = false;
	bool arrived = false;

	NicBridgeSeLowId(id, sizeof(id), guid);
	GetSystemTimeAsFileTime(&since);
	UINT64 start = GetTickCount64();

	SOCKET r = NicBridgeSocket(p->Address, NICBRIDGE_READY_PORT, &error);
	if (r == INVALID_SOCKET)
	{
		Format(s, size, "a socket of the stand-in did not bind to %u.%u.%u.%u:%u (Winsock error %d)", p->Address & 0xFF, (p->Address >> 8) & 0xFF, (p->Address >> 16) & 0xFF,
			p->Address >> 24, (UINT)NICBRIDGE_READY_PORT, error);
		return false;
	}
	setsockopt(r, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout, sizeof(timeout));

	UINT fsize = NicBridgeUdpFrame(frame, p->HostMac, nicbridge_other_mac, NicBridgeAddr(198, 18, NICBRIDGE_NETWORK, 3), p->Address, 40000, NICBRIDGE_READY_PORT, 32);
	while (arrived == false && GetTickCount64() < start + NICBRIDGE_QUARANTINE)
	{
		// The interface is up, and SeLow has bound to its adapter, which gives the device
		Zero(&row, sizeof(row));
		row.InterfaceLuid.Value = p->HostLuid;
		up = (GetIfEntry2(&row) == NO_ERROR && row.OperStatus == IfOperStatusUp);
		if (up && su == NULL)
		{
			su = SuOpenAdapter(id);
			opened = (su != NULL);
		}
		if (up == false || su == NULL)
		{
			Sleep(NICBRIDGE_POLL);
			continue;
		}

		sent += (NicBridgeSeLowPut(su, frame, fsize) ? 1 : 0);
		arrived = (recv(r, buf, sizeof(buf), 0) > 0);
	}
	UINT64 now = GetTickCount64();
	closesocket(r);
	if (su != NULL)
	{
		SuCloseAdapter(su);
	}

	// The record of the datagrams that did not arrive
	UINT drops = 0;
	StrCpy(dropped, sizeof(dropped), "");
	if (sent > (arrived ? 1u : 0u))
	{
		Format(who, sizeof(who), "%s ready", p->Tag);
		drops = NicBridgeDrops(who, NICBRIDGE_READY_PORT, &since, filter, sizeof(filter));
		Format(dropped, sizeof(dropped), ", the filter engine recorded %u drops of them%s%s%s", drops, IsEmptyStr(filter) ? "" : ", the most by its filter '", filter,
			IsEmptyStr(filter) ? "" : "'");
	}

	if (arrived)
	{
		Format(s, size, "the stand-in's host stack takes datagrams from the segment %I64u ms after the adapter was made, after %I64u ms of the wait: datagram %u reached its socket%s",
			now - p->Made, now - start, sent, dropped);
		return true;
	}

	Format(s, size, "no datagram from the segment reached a socket of the stand-in within %u ms, %I64u ms after the adapter was made: its interface %s, the SeLow device of its adapter %s, %u datagrams written to it%s",
		(UINT)NICBRIDGE_QUARANTINE, now - p->Made, up ? "up" : "not up", opened ? "opened" : "not opened", sent, dropped);

	return false;
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

// Run a command of Windows PowerShell, whose cmdlets make and remove Hyper-V virtual switches, and wait for it, with its
// output and errors into out: true when it ended with exit code 0 within NICBRIDGE_PS_WAIT. A command that does not end
// in time is ended. Its input is NUL, as powershell.exe waits for the end of an input that a pipe or a console gives it.
static bool NicBridgePowerShell(char *command, char *out, UINT out_size)
{
	wchar_t exe[MAX_PATH];
	wchar_t cmd[MAX_SIZE * 4];
	SECURITY_ATTRIBUTES sa;
	STARTUPINFOW si;
	PROCESS_INFORMATION pi;
	HANDLE rd = NULL;
	HANDLE wr = NULL;
	DWORD code = INFINITE;
	UINT len = 0;

	StrCpy(out, out_size, "");

	UINT dir_len = (UINT)GetSystemDirectoryW(exe, MAX_PATH);
	if (dir_len == 0 || dir_len >= MAX_PATH - 64)
	{
		Format(out, out_size, "the system directory cannot be read (error %u)", (UINT)GetLastError());
		return false;
	}
	UniStrCat(exe, sizeof(exe), L"\\WindowsPowerShell\\v1.0\\powershell.exe");
	UniFormat(cmd, sizeof(cmd), L"\"%s\" -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command \"%S\"", exe, command);

	Zero(&sa, sizeof(sa));
	sa.nLength = sizeof(sa);
	sa.bInheritHandle = TRUE;

	HANDLE nul = CreateFileW(L"NUL", GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, &sa, OPEN_EXISTING, 0, NULL);
	if (nul == INVALID_HANDLE_VALUE)
	{
		Format(out, out_size, "NUL cannot be opened (error %u)", (UINT)GetLastError());
		return false;
	}
	if (CreatePipe(&rd, &wr, &sa, NICBRIDGE_PS_OUTPUT) == FALSE)
	{
		Format(out, out_size, "CreatePipe: error %u", (UINT)GetLastError());
		CloseHandle(nul);
		return false;
	}
	SetHandleInformation(rd, HANDLE_FLAG_INHERIT, 0);

	Zero(&si, sizeof(si));
	si.cb = sizeof(si);
	si.dwFlags = STARTF_USESTDHANDLES;
	si.hStdInput = nul;
	si.hStdOutput = wr;
	si.hStdError = wr;
	Zero(&pi, sizeof(pi));

	BOOL started = CreateProcessW(exe, cmd, NULL, NULL, TRUE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi);
	CloseHandle(wr);
	CloseHandle(nul);

	if (started == FALSE)
	{
		Format(out, out_size, "%S cannot be started (error %u)", exe, (UINT)GetLastError());
		CloseHandle(rd);
		return false;
	}

	// The command ends, or is ended, before its output is read: it writes far less than the pipe holds
	if (WaitForSingleObject(pi.hProcess, NICBRIDGE_PS_WAIT) == WAIT_OBJECT_0)
	{
		GetExitCodeProcess(pi.hProcess, &code);
	}
	else
	{
		TerminateProcess(pi.hProcess, 1);
		WaitForSingleObject(pi.hProcess, NICBRIDGE_ANSWER);
	}

	while (len + 1 < out_size)
	{
		char buf[MAX_SIZE];
		DWORD got = 0;

		if (ReadFile(rd, buf, (DWORD)MIN((UINT)sizeof(buf), out_size - 1 - len), &got, NULL) == FALSE || got == 0)
		{
			break;
		}
		Copy(out + len, buf, got);
		len += got;
	}
	out[len] = 0;

	CloseHandle(rd);
	CloseHandle(pi.hThread);
	CloseHandle(pi.hProcess);

	return (code == 0);
}

// The Ethernet interfaces of this runner, for the record: a Hyper-V virtual switch gives the host a vNIC that Hyper-V
// names "vEthernet (<switch>)"
static void NicBridgeInterfaces()
{
	MIB_IF_TABLE2 *t = NULL;

	if (GetIfTable2(&t) != NO_ERROR)
	{
		return;
	}

	for (ULONG i = 0;i < t->NumEntries;i++)
	{
		MIB_IF_ROW2 *r = &t->Table[i];
		char alias[MAX_SIZE];
		char description[MAX_SIZE];

		if (r->Type != IF_TYPE_ETHERNET_CSMACD || r->InterfaceAndOperStatusFlags.FilterInterface)
		{
			continue;
		}

		Zero(alias, sizeof(alias));
		Zero(description, sizeof(description));
		UniToUtf8(alias, sizeof(alias) - 1, r->Alias);
		UniToUtf8(description, sizeof(description) - 1, r->Description);
		Print("  an Ethernet interface of this runner: %u, '%s', '%s', MAC %02X-%02X-%02X-%02X-%02X-%02X, %s, %s\n", (UINT)r->InterfaceIndex, alias, description,
			(UINT)r->PhysicalAddress[0], (UINT)r->PhysicalAddress[1], (UINT)r->PhysicalAddress[2], (UINT)r->PhysicalAddress[3], (UINT)r->PhysicalAddress[4],
			(UINT)r->PhysicalAddress[5], r->InterfaceAndOperStatusFlags.HardwareInterface ? "hardware" : "virtual", r->OperStatus == IfOperStatusUp ? "up" : "not up");
	}

	FreeMibTable(t);
}

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
	NicBridgeInterfaces();

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
	p->HostLuid = p->Luid;
	Copy(p->HostMac, p->Mac, 6);

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
// devices on the switch, found by its alias as the owner of a bridge names it. It takes part once its address is preferred
// and its host stack takes datagrams from the segment, which Windows Firewall lets through once it has taken the new
// interface out of quarantine (#569).
static bool NicBridgeStandIn(NICBRIDGE_CTX *ctx, NICBRIDGE_PORT *p, NODE *n)
{
	MIB_IF_ROW2 row;
	char alias[MAX_SIZE];
	char error[MAX_SIZE * 2];
	char ready[MAX_SIZE * 2];

	Zero(p, sizeof(NICBRIDGE_PORT));
	p->Name = "the stand-in of a Hyper-V switch";
	p->Tag = "standin";
	Copy(p->Mac, nicbridge_standin_mac, 6);
	Copy(p->HostMac, nicbridge_standin_mac, 6);
	p->Address = NicBridgeAddr(198, 18, NICBRIDGE_NETWORK, 1);
	p->Member = NicBridgeAddr(198, 18, NICBRIDGE_NETWORK, 2);

	p->KmTest = NodeKmTestNew(n, p->Mac);
	p->Made = GetTickCount64();
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
	p->HostLuid = p->Luid;

	UINT64 given = GetTickCount64();
	bool ok = NicBridgeAddAddress(p->Luid, p->Address, NICBRIDGE_LENGTH, error, sizeof(error));
	UINT64 now = GetTickCount64();
	char state[MAX_SIZE];
	NicBridgeAddressState(p->Luid, p->Address, state, sizeof(state));

	Print("  the stand-in: interface %u, '%s', MAC %02X-%02X-%02X-%02X-%02X-%02X, 198.18.%u.1/%u, the member at 198.18.%u.2\n", p->IfIndex, alias, (UINT)p->Mac[0],
		(UINT)p->Mac[1], (UINT)p->Mac[2], (UINT)p->Mac[3], (UINT)p->Mac[4], (UINT)p->Mac[5], (UINT)NICBRIDGE_NETWORK, (UINT)NICBRIDGE_LENGTH, (UINT)NICBRIDGE_NETWORK);
	Print("  the stand-in's address is %s %I64u ms after it was given, %I64u ms after the adapter was made\n", state, now - given, now - p->Made);

	if (NicBridgeCheck(ctx, ok, "the stand-in takes its IPv4 address", "%s", error) == false)
	{
		return false;
	}

	// The datagrams of the member reach the stand-in only once Windows Firewall has taken the new interface out of quarantine
	bool taken = NicBridgeHostReady(p, &row.InterfaceGuid, ready, sizeof(ready));
	if (taken)
	{
		Print("  %s\n", ready);
	}

	return NicBridgeCheck(ctx, taken, "the stand-in's host stack takes datagrams from the segment once Windows Firewall has taken the new interface out of quarantine", "%s", ready);
}

// The Hyper-V switch of the runner that the job made, named sw_name: the bridge takes the host vNIC of the switch, found by
// the name of the switch as the owner of a bridge names it (NodeL2HyperVIndex), and the second host vNIC on the switch,
// named device, is a device of the Hyper-V network with an IPv4 address of its own
static bool NicBridgeHyperV(NICBRIDGE_CTX *ctx, NICBRIDGE_PORT *p, char *sw_name, char *device)
{
	MIB_IF_ROW2 row;
	char alias[MAX_SIZE];
	char error[MAX_SIZE * 2];

	Zero(p, sizeof(NICBRIDGE_PORT));
	p->Name = "a Hyper-V switch of the runner";
	p->Tag = "vswitch";
	p->Wire = true;
	p->Address = NicBridgeAddr(198, 18, NICBRIDGE_NETWORK + 1, 2);
	p->Member = NicBridgeAddr(198, 18, NICBRIDGE_NETWORK + 1, 3);

	// The bridge's vNIC, by the name of the switch
	p->IfIndex = NodeL2HyperVIndex(sw_name, error, sizeof(error));
	Zero(&row, sizeof(row));
	row.InterfaceIndex = p->IfIndex;
	bool found = (p->IfIndex != 0 && GetIfEntry2(&row) == NO_ERROR);
	if (NicBridgeCheck(ctx, found, "NodeL2HyperVIndex finds the host vNIC of the Hyper-V switch of the runner by the name of the switch", "'%s': interface %u: %s", sw_name, p->IfIndex, error) == false)
	{
		return false;
	}
	p->Luid = row.InterfaceLuid.Value;
	Copy(p->Mac, row.PhysicalAddress, 6);
	Zero(alias, sizeof(alias));
	UniToUtf8(alias, sizeof(alias) - 1, row.Alias);
	Print("  the bridge's vNIC: interface %u, '%s', MAC %02X-%02X-%02X-%02X-%02X-%02X\n", p->IfIndex, alias, (UINT)p->Mac[0], (UINT)p->Mac[1], (UINT)p->Mac[2], (UINT)p->Mac[3],
		(UINT)p->Mac[4], (UINT)p->Mac[5]);

	// The device: the second host vNIC of the switch
	Format(alias, sizeof(alias), "vEthernet (%s)", device);
	UINT index = NodeL2BridgeIndex(alias, error, sizeof(error));
	Zero(&row, sizeof(row));
	row.InterfaceIndex = index;
	found = (index != 0 && GetIfEntry2(&row) == NO_ERROR);
	if (NicBridgeCheck(ctx, found, "a second host vNIC of the Hyper-V switch is a device of the Hyper-V network", "'%s': interface %u: %s", alias, index, error) == false)
	{
		return false;
	}
	p->HostLuid = row.InterfaceLuid.Value;
	Copy(p->HostMac, row.PhysicalAddress, 6);

	bool ok = NicBridgeAddAddress(p->HostLuid, p->Address, NICBRIDGE_LENGTH, error, sizeof(error));

	Print("  the device: interface %u, '%s', MAC %02X-%02X-%02X-%02X-%02X-%02X, 198.18.%u.2/%u, the member at 198.18.%u.3\n", index, alias, (UINT)p->HostMac[0],
		(UINT)p->HostMac[1], (UINT)p->HostMac[2], (UINT)p->HostMac[3], (UINT)p->HostMac[4], (UINT)p->HostMac[5], (UINT)NICBRIDGE_NETWORK + 1, (UINT)NICBRIDGE_LENGTH,
		(UINT)NICBRIDGE_NETWORK + 1);

	return NicBridgeCheck(ctx, ok, "the device on the Hyper-V switch takes its IPv4 address", "%s", error);
}

//
// The parts of the test
//

// The benchmark on the stand-in and on a Hyper-V switch (ADR-0018 decision 3, throughput against SeLow): frames of 1514
// bytes of the member onto the segment and to the device, and for a backend that sees the device's sends, the device's
// datagrams to the member, each for NICBRIDGE_BENCH_TIME ms. Rates in frames per second, as NICBRIDGE BENCH lines, and
// into rates (NICBRIDGE_RATES of them, 0 for one not measured).
static void NicBridgeBench(NICBRIDGE_CTX *ctx, NICBRIDGE_PORT *p, NICBRIDGE_NET *net, NICBRIDGE_OWNER *o, char *backend, bool host_sends, UINT64 *rates)
{
	UCHAR frame[NODE_L2_MAX_FRAME];
	NODE_L2_STATUS st;
	NICBRIDGE_SINK sink;
	int timeout = 100;
	int rcvbuf = 16 << 20;
	int error = 0;

	// Onto the segment
	NodeL2BridgeGetStatus(net->Bridge, &st);
	UINT64 before = st.Injected;
	UINT size = NicBridgeWireFrame(frame, nicbridge_other_mac, 14 + 20 + 8 + NICBRIDGE_SEGMENT);
	UINT64 end = GetTickCount64() + NICBRIDGE_BENCH_TIME;
	while (GetTickCount64() < end)
	{
		for (UINT i = 0;i < 1024;i++)
		{
			NicBridgeFromMember(net, frame, size);
		}
	}
	Sleep(200);
	NodeL2BridgeGetStatus(net->Bridge, &st);
	UINT64 wire = (st.Injected - before) * 1000 / NICBRIDGE_BENCH_TIME;
	Print("NICBRIDGE BENCH %s %s onto the segment: %I64u frames/s taken by the backend\n", backend, p->Tag, wire);

	// To the device, into a socket
	Zero(&sink, sizeof(sink));
	sink.Sock = NicBridgeSocket(p->Address, NICBRIDGE_BENCH_PORT, &error);
	UINT64 host = 0;
	if (sink.Sock != INVALID_SOCKET)
	{
		setsockopt(sink.Sock, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout, sizeof(timeout));
		setsockopt(sink.Sock, SOL_SOCKET, SO_RCVBUF, (char *)&rcvbuf, sizeof(rcvbuf));
		sink.Thread = CreateThread(NULL, 0, NicBridgeSinkThread, &sink, 0, NULL);

		NodeL2BridgeGetStatus(net->Bridge, &st);
		before = st.Injected;
		size = NicBridgeUdpFrame(frame, p->HostMac, nicbridge_member_mac, p->Member, p->Address, 40000, NICBRIDGE_BENCH_PORT, NICBRIDGE_SEGMENT);
		end = GetTickCount64() + NICBRIDGE_BENCH_TIME;
		while (GetTickCount64() < end)
		{
			for (UINT i = 0;i < 1024;i++)
			{
				NicBridgeFromMember(net, frame, size);
			}
		}
		Sleep(200);
		NodeL2BridgeGetStatus(net->Bridge, &st);
		host = (st.Injected - before) * 1000 / NICBRIDGE_BENCH_TIME;

		InterlockedExchange(&sink.Stop, 1);
		if (sink.Thread != NULL)
		{
			WaitForSingleObject(sink.Thread, INFINITE);
			CloseHandle(sink.Thread);
		}
		closesocket(sink.Sock);
	}
	else
	{
		Print("NICBRIDGE DIAG %s %s: the sink of the benchmark did not bind (Winsock error %d)\n", backend, p->Tag, error);
	}
	Print("NICBRIDGE BENCH %s %s to the device: %I64u frames/s taken by the backend, %I64u frames/s delivered to a socket\n", backend, p->Tag, host,
		(UINT64)sink.Received * 1000 / NICBRIDGE_BENCH_TIME);

	// The device's datagrams to the member
	UINT64 captured = 0;
	if (host_sends && NicBridgeNeighbour(p->HostLuid, p->Member, nicbridge_member_mac, true))
	{
		SOCKET s = NicBridgeSocket(p->Address, 0, &error);
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
		NicBridgeNeighbour(p->HostLuid, p->Member, NULL, false);
		Print("NICBRIDGE BENCH %s %s from the device: %I64u frames/s captured and handed to the member\n", backend, p->Tag, captured);
	}

	rates[0] = wire;
	rates[1] = host;
	rates[2] = captured;

	char what[MAX_SIZE];
	Format(what, sizeof(what), "the benchmark of the %s backend on %s moves frames onto the segment and to the device%s (the rates are the NICBRIDGE BENCH lines)", backend, p->Name,
		host_sends ? ", and captures the device's" : "");
	NicBridgeCheck(ctx, wire > 0 && host > 0 && (host_sends == false || captured > 0), what, "%I64u, %I64u, %I64u frames/s", wire, host, captured);
}

// The share of SeLow's rate selow that the rate of another backend is, in percent, into s, with both rates: "n/a" when
// SeLow moved nothing there
static void NicBridgeShare(char *s, UINT size, UINT64 rate, UINT64 selow)
{
	if (selow == 0)
	{
		Format(s, size, "n/a (%I64u frames/s, SeLow none)", rate);
		return;
	}

	Format(s, size, "%I64u%% (%I64u of SeLow's %I64u frames/s)", rate * 100 / selow, rate, selow);
}

// The throughput of a backend against SeLow on the same attachment in this run (ADR-0018 decision 3): its rates as shares
// of SeLow's, as a NICBRIDGE BENCH line. A regression number of the runner, not a gate (ADR-0002 amendment of 2026-10-21).
// SeLow's own rates are kept for the backends that run after it.
static void NicBridgeAgainstSeLow(NICBRIDGE_PORT *p, char *backend, const UINT64 *rates, bool host_sends)
{
	char wire[MAX_SIZE];
	char host[MAX_SIZE];
	char from[MAX_SIZE];

	if (StrCmp(backend, "selow") == 0)
	{
		Copy(p->SeLow, rates, sizeof(p->SeLow));
		p->HaveSeLow = true;
		return;
	}

	if (p->HaveSeLow == false)
	{
		return;
	}

	NicBridgeShare(wire, sizeof(wire), rates[0], p->SeLow[0]);
	NicBridgeShare(host, sizeof(host), rates[1], p->SeLow[1]);
	StrCpy(from, sizeof(from), "not measured, as the backend sees no frame of the device there");
	if (host_sends)
	{
		NicBridgeShare(from, sizeof(from), rates[2], p->SeLow[2]);
	}
	Print("NICBRIDGE BENCH %s %s against selow: onto the segment %s, to the device %s, from the device %s\n", backend, p->Tag, wire, host, from);
}

// Coexistence on a Hyper-V switch: the host resolves the link-local IPv6 address of the device through the bridged vNIC,
// with a solicitation that it sends and an advertisement that comes back through the switch
static void NicBridgeVswitchHost(NICBRIDGE_CTX *ctx, NICBRIDGE_PORT *p, char *when)
{
	UCHAR ll[16];
	char what[MAX_SIZE];

	bool have = NicBridgeLinkLocal(p->HostLuid, ll);
	bool resolved = (have && NicBridgeResolve6(p->Luid, ll, p->HostMac));
	Format(what, sizeof(what), "coexistence on %s: the host resolves the link-local address of the device through the bridged vNIC %s", p->Name, when);
	NicBridgeCheck(ctx, resolved, what, "%s", have ? "not resolved to the device's MAC address" : "the device has no preferred link-local address");
}

// A device of the LAN other than the host, on the runner's NIC: the member asks the gateway of the NIC for its MAC address
// from its own MAC address and its address on the subnet, and whether the gateway answered is printed for the record
// (NICBRIDGE DIAG), not checked. A hosted runner is a virtual machine of a public cloud, whose network takes no frame of
// a MAC address other than that of its NIC (MAC address spoofing is not possible there, as Microsoft's guide to nested
// virtualization says of a public cloud), so no other device of its LAN exchanges frames with the member, and the host
// stack on the NIC plays the LAN device.
static void NicBridgeLanDevice(NICBRIDGE_NET *net, NICBRIDGE_PORT *p, NICBRIDGE_OWNER *o, char *backend)
{
	UCHAR frame[NICBRIDGE_ARP_FRAME];

	if (p->Gateway == 0 || p->Member == 0)
	{
		Print("NICBRIDGE DIAG %s %s gateway: no gateway, or no address of the member on the subnet of the NIC\n", backend, p->Tag);
		return;
	}

	LONG64 before = ReadAcquire64(&o->GatewayReplies);
	for (UINT i = 0;i < 3;i++)
	{
		UINT size = NicBridgeArpRequest(frame, nicbridge_member_mac, p->Member, p->Gateway);
		NicBridgeFromMember(net, frame, size);
		Sleep(50);
	}
	bool answered = NicBridgeWait64(&o->GatewayReplies, before + 1, NICBRIDGE_ANSWER);

	// The host may have learnt the member from the requests: its entry goes again
	NicBridgeNeighbour(p->HostLuid, p->Member, NULL, false);

	Print("NICBRIDGE DIAG %s %s gateway: the gateway %u.%u.%u.%u of the LAN %s the ARP request that the member sent from its own MAC address%s\n", backend, p->Tag,
		p->Gateway & 0xFF, (p->Gateway >> 8) & 0xFF, (p->Gateway >> 16) & 0xFF, p->Gateway >> 24, answered ? "answered" : "did not answer",
		answered ? "" : " (the network of a hosted runner takes no frame of a MAC address other than that of its NIC)");
}

// The connection profile of the interface of the host stack of p, as Windows gives it, with its IPv4 address and IPv4
// interface, for the record (CI-FLAKE-3, #569): through the cmdlets of PowerShell, which take a few seconds
static void NicBridgeProfile(NICBRIDGE_PORT *p, char *backend, char *when)
{
	NET_LUID luid;
	NET_IFINDEX index = 0;
	char command[MAX_SIZE * 3];
	char out[MAX_SIZE * 4];

	luid.Value = p->HostLuid;
	ConvertInterfaceLuidToIndex(&luid, &index);
	Format(command, sizeof(command),
		"$c = @(Get-NetConnectionProfile -InterfaceIndex %u -ErrorAction SilentlyContinue); if ($c.Count -eq 0) { 'no connection profile' }; "
		"$c | ForEach-Object { 'connection profile ' + $_.Name + ', ' + $_.NetworkCategory + ', IPv4 ' + $_.IPv4Connectivity }; "
		"Get-NetIPAddress -InterfaceIndex %u -AddressFamily IPv4 -ErrorAction SilentlyContinue | ForEach-Object { 'address ' + $_.IPAddress + ', ' + $_.AddressState + ', ' + $_.PrefixOrigin }; "
		"Get-NetIPInterface -InterfaceIndex %u -AddressFamily IPv4 -ErrorAction SilentlyContinue | ForEach-Object { 'IPv4 interface ' + $_.ConnectionState + ', DHCP ' + $_.Dhcp }",
		(UINT)index, (UINT)index, (UINT)index);
	bool ok = NicBridgePowerShell(command, out, sizeof(out));

	TOKEN_LIST *t = ParseToken(out, "\r\n");
	for (UINT i = 0;i < t->NumTokens;i++)
	{
		Print("NICBRIDGE DIAG %s %s profile %s: %s\n", backend, p->Tag, when, t->Token[i]);
	}
	if (ok == false || t->NumTokens == 0)
	{
		Print("NICBRIDGE DIAG %s %s profile %s: PowerShell %s\n", backend, p->Tag, when, ok ? "printed nothing" : "failed");
	}
	FreeToken(t);
}

// For the record, when datagrams of the member did not reach the socket of the device (CI-FLAKE-3, #569): the drops that
// the filter engine recorded of datagrams to its port since the step began at since (began, as a tick), the connection
// profile of the host interface, and how long it takes until a datagram of the member does reach the socket, through the
// same bridge, one every 100 ms for NICBRIDGE_LATE ms at most
static void NicBridgeLate(NICBRIDGE_NET *net, NICBRIDGE_PORT *p, char *backend, const FILETIME *since, UINT64 began)
{
	UCHAR frame[NODE_L2_MAX_FRAME];
	char buf[2048];
	char made[MAX_SIZE];
	char who[MAX_SIZE];
	char filter[MAX_SIZE];
	int timeout = 100;
	int error = 0;
	UINT sent = 0;
	bool arrived = false;

	Format(who, sizeof(who), "%s %s", backend, p->Tag);
	NicBridgeDrops(who, NICBRIDGE_RX_PORT, since, filter, sizeof(filter));
	NicBridgeProfile(p, backend, "when they were lost");

	SOCKET r = NicBridgeSocket(p->Address, NICBRIDGE_RX_PORT, &error);
	bool bound = (r != INVALID_SOCKET);
	UINT64 start = GetTickCount64();
	if (bound)
	{
		setsockopt(r, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout, sizeof(timeout));
		while (arrived == false && GetTickCount64() < start + NICBRIDGE_LATE)
		{
			UINT usize = NicBridgeUdpFrame(frame, p->HostMac, nicbridge_member_mac, p->Member, p->Address, 40000, NICBRIDGE_RX_PORT, 32);
			NicBridgeFromMember(net, frame, usize);
			sent++;
			arrived = (recv(r, buf, sizeof(buf), 0) > 0);
		}
		closesocket(r);
	}

	UINT64 now = GetTickCount64();
	StrCpy(made, sizeof(made), "");
	if (p->Made != 0)
	{
		Format(made, sizeof(made), ", %I64u ms after the adapter was made", now - p->Made);
	}
	Print("NICBRIDGE DIAG %s %s late: %s, after %u more datagrams of the member in %I64u ms, %I64u ms after the step began%s\n", backend, p->Tag,
		arrived ? "a datagram of the member reached the socket" : (bound ? "no datagram of the member reached the socket" : "the socket did not bind"), sent, now - start,
		now - began, made);
	if (bound == false)
	{
		Print("NICBRIDGE DIAG %s %s late: Winsock error %d\n", backend, p->Tag, error);
	}
	NicBridgeProfile(p, backend, arrived ? "once one arrived" : "at the end of the wait");
}

// The spike of ADR-0018 decision 3 for the backend b on the attachment p, through the backend interface: an L2 bridge, the
// member of a port of the switch of an L2 Network beside the member that the test plays. own_hold: the test's own hold
// of promiscuous mode for XDP (the SeLow device), else the product's (NodeL2NpcapHold).
static void NicBridgeRun(NICBRIDGE_CTX *ctx, NODE *n, NICBRIDGE_PORT *p, const NODE_L2_BACKEND *b, bool own_hold)
{
	NICBRIDGE_NET net;
	NODE_L2_STATUS st;
	NICBRIDGE_OWNER o;
	UCHAR frame[NODE_L2_MAX_FRAME];
	char what[MAX_SIZE];
	char buf[2048];
	int timeout = 200;
	// XDP takes only what comes in from below the interface: the device's frames on a Hyper-V switch do; on the NIC and on
	// the stand-in no frame of the host for the member does
	bool from_host = (StrCmp(b->Name, "xdp") != 0 || p->Wire);
	bool nic = (p->KmTest == NULL && p->Wire == false);

	Zero(&o, sizeof(o));
	Copy(o.Member, nicbridge_member_mac, 6);
	o.Gateway = p->Gateway;

	Print("The %s backend on %s\n", b->Name, p->Name);
	bool up = NicBridgeNetNew(&net, n, p, b, &o, own_hold);
	NodeL2BridgeGetStatus(net.Bridge, &st);
	Format(what, sizeof(what), "the %s backend binds an L2 bridge on %s, the member of a port of the switch of an L2 Network, through the backend interface", b->Name, p->Name);
	if (NicBridgeCheck(ctx, up && StrCmp(st.Backend, b->Name) == 0 && st.Bridge, what, "%s, backend '%s'", up ? "a bridge" : "no bridge", st.Backend) == false)
	{
		NicBridgeNetFree(&net);
		return;
	}
	Print("  the bridge is on %u queue(s) of the driver, at port %u of the switch\n", st.Queues, NodeL2BridgePort(net.Bridge));

	// Foreign-MAC transmit onto the segment: frames of the member to another address of the segment, which the switch hands
	// the bridge, whose backend takes them, and which the NIC counts as sent
	UINT64 sent_before = NicBridgeSent(p->IfIndex);
	UINT64 injected_before = st.Injected;
	UINT size = NicBridgeWireFrame(frame, nicbridge_other_mac, 64);
	UINT sent = 0;
	for (UINT i = 0;i < NICBRIDGE_WIRE;i++)
	{
		sent += (NicBridgeFromMember(&net, frame, size) ? 1 : 0);
		if ((i % 100) == 99)
		{
			Sleep(1);
		}
	}
	bool taken = NicBridgeWaitInjected(net.Bridge, injected_before + sent, &st);
	Sleep(500);
	UINT64 counted = NicBridgeSent(p->IfIndex) - sent_before;
	Format(what, sizeof(what), "foreign-MAC transmit on %s: the member's frames go through the switch to the bridge, whose backend takes them for the segment%s", p->Name,
		nic ? ", and the NIC counts them as sent" : "");
	NicBridgeCheck(ctx, sent == NICBRIDGE_WIRE && taken && (nic == false || counted >= sent), what, "%u handed to the bridge, %I64u taken by the backend, %I64u counted by the interface",
		sent, st.Injected - injected_before, counted);
	if (nic == false)
	{
		Print("NICBRIDGE DIAG %s %s: %I64u frames counted as sent by the bridge's interface\n", b->Name, p->Tag, counted);
	}

	// Foreign-MAC transmit to the device: the 5 datagrams of the member reach a socket of the device, every one of them. What
	// the test finds of the device goes to the log first: whether its socket bound, the state of its address and of its
	// interface (#569).
	UINT got = 0;
	int bind_error = 0;
	char host[MAX_SIZE * 2];
	FILETIME udp_time;
	UINT64 udp_tick = GetTickCount64();
	GetSystemTimeAsFileTime(&udp_time);
	NodeL2BridgeGetStatus(net.Bridge, &st);
	UINT64 udp_injected = st.Injected;
	SOCKET r = INVALID_SOCKET;
	StrCpy(host, sizeof(host), "the attachment has no address of a device");
	if (p->Address != 0 && p->Member != 0)
	{
		r = NicBridgeSocket(p->Address, NICBRIDGE_RX_PORT, &bind_error);
		NicBridgeHostState(p, NICBRIDGE_RX_PORT, bind_error, host, sizeof(host));
		Print("NICBRIDGE DIAG %s %s udp: %s\n", b->Name, p->Tag, host);
	}
	if (r != INVALID_SOCKET)
	{
		setsockopt(r, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout, sizeof(timeout));
		for (UINT i = 0;i < 5;i++)
		{
			UINT usize = NicBridgeUdpFrame(frame, p->HostMac, nicbridge_member_mac, p->Member, p->Address, 40000, NICBRIDGE_RX_PORT, 32);
			NicBridgeFromMember(&net, frame, usize);
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
	// The injector adds a batch to its count once the backend has taken it, which can be after the host stack delivered its
	// datagrams to the socket: so the count is read once it holds each datagram that arrived
	NicBridgeWaitInjected(net.Bridge, udp_injected + got, &st);
	UINT64 udp_taken = st.Injected - udp_injected;
	if (from_host && p->Address != 0 && p->Member != 0 && got < 5)
	{
		NicBridgeLate(&net, p, b->Name, &udp_time, udp_tick);
	}

	// Foreign-MAC transmit and receive: an ARP request of the member for the device's address; the device learns the
	// member, and its reply to the member reaches the member through the bridge and the switch
	bool learnt = false;
	bool replied = false;
	if (p->Address != 0 && p->Member != 0)
	{
		LONG64 replies = ReadAcquire64(&o.ArpReplies);

		NicBridgeNeighbour(p->HostLuid, p->Member, NULL, false);
		for (UINT i = 0;i < 3;i++)
		{
			UINT asize = NicBridgeArpRequest(frame, nicbridge_member_mac, p->Member, p->Address);
			NicBridgeFromMember(&net, frame, asize);
			Sleep(50);
		}
		replied = NicBridgeWait64(&o.ArpReplies, replies + 1, from_host ? NICBRIDGE_ANSWER : 1000);
		learnt = NicBridgeLearnt(p->HostLuid, p->Member, nicbridge_member_mac);
	}

	// Foreign-MAC receive: the device's datagrams to the member, a permanent neighbour, are captured and reach the member
	UINT usent = 0;
	bool captured = false;
	if (p->Address != 0 && p->Member != 0 && NicBridgeNeighbour(p->HostLuid, p->Member, nicbridge_member_mac, true))
	{
		LONG64 before = ReadAcquire64(&o.Udp);
		int error = 0;
		SOCKET s = NicBridgeSocket(p->Address, 0, &error);

		usent = (s != INVALID_SOCKET ? NicBridgeSendTo(s, p->Member, NICBRIDGE_TX_PORT, 20, 64) : 0);
		if (s != INVALID_SOCKET)
		{
			closesocket(s);
		}
		captured = NicBridgeWait64(&o.Udp, before + 20, from_host ? NICBRIDGE_BOUND : 1000);
	}
	NicBridgeNeighbour(p->HostLuid, p->Member, NULL, false);

	if (from_host)
	{
		Format(what, sizeof(what), "foreign-MAC transmit on %s: the datagrams of the member reach a socket of the device", p->Name);
		NicBridgeCheck(ctx, got == 5, what, "%u of 5 received, %I64u taken by the backend; %s", got, udp_taken, host);
		Format(what, sizeof(what), "foreign-MAC transmit and receive on %s: the device answers the ARP request of the member, and its reply reaches the member", p->Name);
		NicBridgeCheck(ctx, replied, what, "no reply captured; the device %s the member", learnt ? "learnt" : "did not learn");
		Format(what, sizeof(what), "foreign-MAC receive on %s: the datagrams that the device sends to the member are captured and reach the member", p->Name);
		NicBridgeCheck(ctx, usent == 20 && captured, what, "%u sent, %I64u captured", usent, (UINT64)ReadAcquire64(&o.Udp));
	}
	Print("NICBRIDGE DIAG %s %s: %u of 5 datagrams of the member at the device (%I64u taken by the backend), the device %s the member, %s its ARP reply, %u of its datagrams to the member, %I64u captured; %I64u frames handed to the member, %I64u to its address\n",
		b->Name, p->Tag, got, udp_taken, learnt ? "learnt" : "did not learn", replied ? "captured" : "did not capture", usent, (UINT64)ReadAcquire64(&o.Udp),
		(UINT64)ReadAcquire64(&o.Frames), (UINT64)ReadAcquire64(&o.ToMember));

	// Coexistence with the host stack, on the runner's NIC: the host's own TCP connection through the NIC works while the
	// bridge is on, the host resolves its gateway again, and the bridge sends no probe onto the LAN. On XDP the gateway's
	// ARP reply, a frame of the wire to the NIC's own address that no rule lets pass, reaches the host only through the
	// bridge, which hands it back; the health check reports those frames once a second.
	if (nic)
	{
		Format(what, sizeof(what), "coexistence on %s: the host's own TCP connection to %s through the NIC works while the bridge is on", p->Name, NICBRIDGE_TCP_HOST);
		NicBridgeCheck(ctx, NicBridgeTcp(), what, "it did not");

		NodeL2BridgeGetStatus(net.Bridge, &st);
		UINT64 to_host = st.ToHost;
		bool resolved = (p->Gateway != 0 && NicBridgeResolve(p->Luid, p->Gateway));
		UINT64 end = GetTickCount64() + NICBRIDGE_ANSWER;
		NodeL2BridgeGetStatus(net.Bridge, &st);
		while (StrCmp(b->Name, "xdp") == 0 && st.ToHost == to_host && GetTickCount64() < end)
		{
			Sleep(NICBRIDGE_POLL);
			NodeL2BridgeGetStatus(net.Bridge, &st);
		}
		Format(what, sizeof(what), "coexistence on %s: the host resolves its gateway again while the bridge is on%s", p->Name,
			StrCmp(b->Name, "xdp") == 0 ? ", and its ARP reply, a frame of the wire that RX inspect takes, comes back to the host through the bridge" : "");
		NicBridgeCheck(ctx, resolved && (StrCmp(b->Name, "xdp") != 0 || st.ToHost > to_host), what, "%s, %I64u frames of the wire handed back to the host",
			p->Gateway == 0 ? "no gateway found" : (resolved ? "resolved" : "not resolved"), st.ToHost - to_host);

		NicBridgeLanDevice(&net, p, &o, b->Name);

		Sleep(NODE_L2_PROBE + 1000);
		NodeL2BridgeGetStatus(net.Bridge, &st);
		NicBridgeCheck(ctx, st.Probes == 0, "a bridge sends no probe of the receive path onto the LAN", "%I64u probes", st.Probes);
	}
	else
	{
		UINT64 rates[NICBRIDGE_RATES];

		if (p->Wire)
		{
			NicBridgeVswitchHost(ctx, p, "while the bridge is on");
		}
		NicBridgeBench(ctx, p, &net, &o, b->Name, from_host, rates);
		NicBridgeAgainstSeLow(p, b->Name, rates, from_host);
	}

	NodeL2BridgeGetStatus(net.Bridge, &st);
	Print("  status: captured %I64u (%I64u dropped), delivered %I64u, sent %I64u (%I64u dropped), injected %I64u (%I64u refused) in %I64u batches, %I64u handed back to the host (%I64u dropped), %I64u reattaches\n",
		st.Captured, st.CaptureDrops, st.Delivered, st.Sent, st.SendDrops, st.Injected, st.InjectDrops, st.Batches, st.ToHost, st.ToHostDrops, st.Reattaches);

	UINT64 t0 = GetTickCount64();
	bool freed = NicBridgeNetFree(&net);
	Format(what, sizeof(what), "NodeL2BridgeFree takes the L2 bridge on %s off its switch and down in time", p->Name);
	NicBridgeCheck(ctx, freed, what, "a step did not finish in time (%I64u ms)", GetTickCount64() - t0);

	if (nic)
	{
		Format(what, sizeof(what), "coexistence on %s: the host's own TCP connection through the NIC works after the bridge went", p->Name);
		NicBridgeCheck(ctx, NicBridgeTcp(), what, "it did not");
	}
	else if (p->Wire)
	{
		NicBridgeVswitchHost(ctx, p, "after the bridge went");
	}
}

// SeLow is the default of an L2 bridge, and Npcap is used only where it is installed
static void NicBridgeDefault(NICBRIDGE_CTX *ctx, NODE *n, NICBRIDGE_PORT *p)
{
	NICBRIDGE_NET net;
	NICBRIDGE_OWNER o;
	NODE_L2_STATUS st;
	char error[MAX_SIZE];

	Zero(&o, sizeof(o));
	Copy(o.Member, nicbridge_member_mac, 6);

	bool up = NicBridgeNetNew(&net, n, p, NULL, &o, false);
	NodeL2BridgeGetStatus(net.Bridge, &st);
	NicBridgeCheck(ctx, up && StrCmp(st.Backend, "selow") == 0, "an L2 bridge on the runner's NIC whose owner names no backend binds SeLow, the default", "%s, backend '%s'",
		up ? "a bridge" : "no bridge", st.Backend);
	NicBridgeNetFree(&net);

	if (NodeL2NpcapPresent(error, sizeof(error)))
	{
		Print("  Npcap is installed here: the check of a host without it is left out\n");
		return;
	}

	Print("NICBRIDGE NPCAP absent: %s\n", error);
	up = NicBridgeNetNew(&net, n, p, NodeL2NpcapBackend(), &o, false);
	NicBridgeCheck(ctx, up == false, "Npcap is used only where it is installed: without it an L2 bridge on Npcap alone does not come up", "a bridge came up");
	NicBridgeNetFree(&net);
}

// The NIC of an external Hyper-V virtual switch: a KM-TEST adapter of the node, so that the runner's NIC stays as it is, to
// which the test binds the external switch sw_name with a vNIC of the host (New-VMSwitch -NetAdapterName -AllowManagementOS).
// The switch owns its NIC, so a bridge refuses it (NodeL2BridgeIndex) and takes the host vNIC of the switch instead
// (NodeL2HyperVIndex). The switch, then the adapter, go again at the end; a switch of that name that an earlier run left
// goes first.
static void NicBridgeExternal(NICBRIDGE_CTX *ctx, NODE *n, char *sw_name)
{
	MIB_IF_ROW2 row;
	char alias[MAX_SIZE];
	char command[MAX_SIZE * 2];
	char out[MAX_SIZE * 4];
	char error[MAX_SIZE * 2];

	Print("The NIC of an external Hyper-V virtual switch\n");
	NODE_KMTEST *k = NodeKmTestNew(n, nicbridge_external_mac);
	UINT index = NodeKmTestIndex(k);
	Zero(&row, sizeof(row));
	row.InterfaceIndex = index;
	bool up = (k != NULL && GetIfEntry2(&row) == NO_ERROR);
	if (NicBridgeCheck(ctx, up, "a second KM-TEST adapter comes up to be the NIC of an external Hyper-V switch", "adapter %s, interface %u", k != NULL ? "created" : "not created", index) == false)
	{
		NodeKmTestFree(k, true);
		return;
	}
	Zero(alias, sizeof(alias));
	UniToUtf8(alias, sizeof(alias) - 1, row.Alias);

	UINT before = NodeL2BridgeIndex(alias, error, sizeof(error));
	NicBridgeCheck(ctx, before == index, "NodeL2BridgeIndex takes the KM-TEST adapter while no virtual switch owns it", "'%s': interface %u, not %u: %s", alias, before, index, error);

	Format(command, sizeof(command), "Get-VMSwitch -Name '%s' -ErrorAction SilentlyContinue | Remove-VMSwitch -Force; New-VMSwitch -Name '%s' -NetAdapterName '%s' -AllowManagementOS $true -ErrorAction Stop | Out-Null",
		sw_name, sw_name, alias);
	bool made = NicBridgePowerShell(command, out, sizeof(out));
	if (NicBridgeCheck(ctx, made, "an external Hyper-V virtual switch takes the KM-TEST adapter as its NIC, with a vNIC of the host", "New-VMSwitch on '%s': %s", alias, out))
	{
		// The binding of the switch's protocol to its NIC, and the host's vNIC, as the network configuration shows them
		UINT64 end = GetTickCount64() + NICBRIDGE_BOUND;
		UINT refused = NodeL2BridgeIndex(alias, error, sizeof(error));
		while (refused != 0 && GetTickCount64() < end)
		{
			Sleep(500);
			refused = NodeL2BridgeIndex(alias, error, sizeof(error));
		}
		NicBridgeCheck(ctx, refused == 0 && InStr(error, "external Hyper-V virtual switch"), "a bridge refuses the NIC of an external Hyper-V virtual switch, which owns it, and names the host vNIC of the switch instead",
			"'%s': interface %u: '%s'", alias, refused, error);

		end = GetTickCount64() + NICBRIDGE_BOUND;
		UINT vnic = NodeL2HyperVIndex(sw_name, error, sizeof(error));
		while (vnic == 0 && GetTickCount64() < end)
		{
			Sleep(500);
			vnic = NodeL2HyperVIndex(sw_name, error, sizeof(error));
		}
		NicBridgeCheck(ctx, vnic != 0 && vnic != index, "NodeL2HyperVIndex finds the host vNIC of the external switch, which a bridge takes instead of its NIC", "'%s': interface %u: %s", sw_name, vnic, error);
		Print("  the external switch %s: its NIC interface %u, '%s', the host's vNIC interface %u\n", sw_name, index, alias, vnic);
	}

	// The switch goes before its NIC
	Format(command, sizeof(command), "Remove-VMSwitch -Name '%s' -Force -ErrorAction Stop", sw_name);
	bool removed = NicBridgePowerShell(command, out, sizeof(out));
	if (made)
	{
		NicBridgeCheck(ctx, removed, "the external Hyper-V virtual switch goes again", "Remove-VMSwitch: %s", out);
	}
	NodeKmTestFree(k, true);
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
						if (InStr(t->Token[j], "L2 adapter") || InStr(t->Token[j], "L2 bridge") || InStr(t->Token[j], "KM-TEST"))
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

// nicbridge: the bridge of an L2 Network on the runner's NIC, on a stand-in of a Hyper-V switch and on a Hyper-V switch of
// the runner (CORE-S3-3)
RANZ_TEST("nicbridge", nicbridge_test, "NIC bridge: an L2 bridge of an L2 Network through the backend interface on the runner's NIC, on a KM-TEST adapter standing in for a Hyper-V switch and on a Hyper-V switch of the runner, with SeLow, XDP or Npcap through a stand-in of its pcap API (arguments: selow, xdp or npcap, then the Hyper-V switch and its device vNIC, then the name of an external switch to make): foreign-MAC transmit and receive, coexistence with the host stack, the benchmark against SeLow, SeLow the default and Npcap only where it is installed, the NIC of an external Hyper-V switch refused (administrator rights, the drivers of ranz install).");
void nicbridge_test(UINT num, char **arg)
{
	NICBRIDGE_CTX ctx;
	NICBRIDGE_PORT nic;
	NICBRIDGE_PORT standin;
	NICBRIDGE_PORT vsw;
	NICBRIDGE_PORT *ports[3];
	WSADATA wsa;
	UCHAR key[PEER_KEY_SIZE];
	wchar_t dir[MAX_PATH];
	char error[MAX_SIZE];
	char *mode = (num >= 1 ? arg[0] : "selow");
	char *vswitch = (num >= 3 ? arg[1] : NULL);
	char *device = (num >= 3 ? arg[2] : NULL);
	char *external = (num >= 4 ? arg[3] : NULL);
	bool xdp = (StrCmpi(mode, "xdp") == 0);
	bool npcap = (StrCmpi(mode, "npcap") == 0);
	UINT num_ports = 0;

	HANDLE done = CreateEventW(NULL, TRUE, FALSE, NULL);
	HANDLE watchdog = (done != NULL ? CreateThread(NULL, 0, NicBridgeWatchdog, done, 0, NULL) : NULL);

	Zero(&ctx, sizeof(ctx));
	Zero(&nic, sizeof(nic));
	Zero(&standin, sizeof(standin));
	Zero(&vsw, sizeof(vsw));
	Zero(ports, sizeof(ports));
	WSAStartup(MAKEWORD(2, 2), &wsa);

	memset(key, 0x73, sizeof(key));
	NodeL2Mac(nicbridge_standin_mac, key, NICBRIDGE_NETWORK);
	NodeL2Mac(nicbridge_member_mac, key, NICBRIDGE_NETWORK + 1);
	NodeL2Mac(nicbridge_other_mac, key, NICBRIDGE_NETWORK + 2);
	NodeL2Mac(nicbridge_external_mac, key, NICBRIDGE_NETWORK + 3);

	Print("NIC bridge test: an L2 bridge of an L2 Network on the runner's NIC, on a stand-in of a Hyper-V switch%s, mode %s%s\n",
		vswitch != NULL ? " and on a Hyper-V switch of the runner" : "", mode, external != NULL ? ", and the NIC of an external switch" : "");

	NicBridgeNewDir(dir, sizeof(dir));
	NODE *n = NewNode(dir);
	bool started = (n != NULL && NodeStart(n));

	if (NicBridgeCheck(&ctx, started, "a node without a role runs for the bridges", "NewNode or NodeStart failed"))
	{
		bool have_nic = NicBridgeNic(&ctx, &nic);

		// The stand-in first, then the Hyper-V switch that the job made, then the runner's NIC
		if (NicBridgeStandIn(&ctx, &standin, n))
		{
			ports[num_ports++] = &standin;
		}
		if (vswitch != NULL && NicBridgeHyperV(&ctx, &vsw, vswitch, device))
		{
			ports[num_ports++] = &vsw;
		}
		if (have_nic)
		{
			ports[num_ports++] = &nic;
			NicBridgeDefault(&ctx, n, &nic);
		}

		if (npcap)
		{
			// SeLow first, on each attachment, for the comparison
			for (UINT i = 0;i < num_ports;i++)
			{
				NicBridgeRun(&ctx, n, ports[i], NodeL2SeLowBackend(), false);
			}

			// No runner may carry Npcap: the stand-in of its pcap API over the SeLow device of each adapter
			NodeL2NpcapStandIn(&nicbridge_pcap_api);
			bool present = NodeL2NpcapPresent(error, sizeof(error));
			Print("NICBRIDGE NPCAP stand-in: the pcap API of Npcap over the SeLow device of each adapter\n");
			if (NicBridgeCheck(&ctx, present, "the Npcap backend takes the stand-in of Npcap's pcap API", "'%s'", error))
			{
				for (UINT i = 0;i < num_ports;i++)
				{
					NicBridgeRun(&ctx, n, ports[i], NodeL2NpcapBackend(), false);
				}
				// XDP carries the frames, and Npcap, the product's hold, holds the NIC in promiscuous mode
				for (UINT i = 0;i < num_ports;i++)
				{
					NicBridgeRun(&ctx, n, ports[i], NodeL2XdpBackend(), false);
				}
			}
			NodeL2NpcapStandIn(NULL);
		}
		else
		{
			// SeLow, then XDP on the same attachment, for the comparison
			for (UINT i = 0;i < num_ports;i++)
			{
				NicBridgeRun(&ctx, n, ports[i], NodeL2SeLowBackend(), true);
				if (xdp)
				{
					NicBridgeRun(&ctx, n, ports[i], NodeL2XdpBackend(), true);
				}
			}
		}

		// Last, as it changes the network configuration of the host: the NIC of an external switch
		if (external != NULL)
		{
			NicBridgeExternal(&ctx, n, external);
		}
	}

	if (n != NULL)
	{
		NodeKmTestFree(standin.KmTest, true);
		NodeStop(n);
		FreeNode(n);
	}
	if (vsw.HostLuid != 0)
	{
		NicBridgeDelAddress(vsw.HostLuid, vsw.Address);
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
