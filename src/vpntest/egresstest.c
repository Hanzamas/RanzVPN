// egresstest.c
// Internet exit test of vpntest ("egress" command, SDN-12 #188)
//
// The internet exit of a VRF (Cedar/NodeEgress.c; ADR-0025 decisions 13 to 15) with the proxy on the TCP/IP stack of the
// runner, the Egress tier that every host has, Home, Pro and arm64 among them. node-x is the exit of VRF corp (301) and a
// member of VRF lab (302): its adapters of the two VRFs are Wintun adapters of the runner with the forwarding of an exit
// (Cedar/NodeVrfAdapter.c), and its state names corp as a VRF whose exit it is. node-c, whose fake host is the test, has
// node-x as its peer in corp with the default route 0.0.0.0/0 of corp as a route of node-x, as the Controller gives every
// other Node of a VRF with an exit (controller/internal/desired/egress.go). The two run on the in-process loopback
// transport.
// - The outside is the runner itself: a TCP echo server and a UDP echo server on its own address, the source of its route to
//   the internet, which the proxy dials as any address outside the VRF, and the ICMP echo of that address. From its address
//   in corp node-c's host opens a TCP connection to the TCP server, sends a line and gets it back; sends the UDP server a
//   datagram and gets it back; and sends the runner an echo request and gets its reply. Each answer comes from the address
//   and the port outside the VRF that node-c named, with checksums that hold, and the Egress counts the flows.
// - The reply on another interface: the test brings up two Wintun adapters of its own, uplink-a and uplink-b, each with an
//   address and a default route of a high metric, so the runner's own traffic keeps its route, and a route through uplink-a
//   to a network outside. Before node-x is an exit the interfaces have Forwarding, WeakHostSend and WeakHostReceive off;
//   while it is the exit of corp they carry the egress and have the three on, as GetIpInterfaceEntry reads them back. A UDP
//   datagram and an echo request of node-c to an address of that network leave the runner by uplink-a, where the test takes
//   them, and the test answers each on uplink-b, an interface that holds no address of the request: the answer reaches
//   node-c, which the strong host model of Windows would have dropped. Once node-x is the exit of no VRF any more, the two
//   interfaces have the settings that they had before.
// - Refused: datagrams of node-c to the loopback, to a link-local address and to an address of lab, another VRF of node-x,
//   get no answer, and the Egress counts them as refused, so the egress of one VRF never leads into another.
// Print "EGRESS TEST OK" only when every check passes. Needs administrator rights and wintun.dll next to vpntest
// (.github/scripts/fetch-wintun.ps1). node-x takes the proxy there whatever tier the runner gives
// (NODE_OVERLAY_CONFIG.EgressTier).
//
// The tiers on the NAT of Windows (Cedar/NodeEgressNat.c) are the commands egressnat and egressrras, on the same nodes and
// uplinks, with node-x on the tier that the runner gives it (NodeCapsDecide) and the answers of the network behind uplink-a
// put back into uplink-a, where the NAT took the requests out:
// - The tier: the Capabilities of the runner give it, from its edition, RRAS, Hyper-V, WinNAT and the NAT networks of WinNAT
//   that a look of the test found, as a node sees them once it looked, and the Egress of node-x uses it.
// - Egress: a UDP datagram, an echo request and a TCP SYN of node-c to the network behind uplink-a leave the runner by uplink-a
//   with the address of uplink-a as their source, translated by the NAT of Windows, and each answer reaches node-c from the
//   address and port that it named.
// - The reconcile: the NAT setting of the node taken away behind its back (its NAT network of WinNAT, or the NAT information
//   of the adapter of corp in RRAS) is set again by the next reconcile, which the Egress counts, and the egress works again.
// - The supernet (WinNAT, which takes one NAT network per host): once node-x is the exit of lab too, its NAT network of WinNAT
//   holds 198.19.60.0/22, the supernet of corp and lab, in place of the prefix of corp, and the egress of node-c goes through it.
// - Once node-x is the exit of no VRF, the NAT of Windows holds nothing of the node, and the IPv4 router of RRAS holds the NAT
//   routing protocol as it did before node-x: the node takes out again the one that it added.
// egressnat checks the tier that the runner gives: WinNAT where Hyper-V and WinNAT are present and no NAT network of WinNAT of
// another program exists; then a NAT network of WinNAT of another name, which the test creates where there is none, makes the
// runner give the proxy once a look found it; a new node-x on WinNAT, the tier of a node that has not looked yet, finds it at
// its first reconcile and falls back to the proxy, which carries the egress; and the other NAT network is still there as it
// was once the node stopped, never touched. On a runner without Hyper-V or WinNAT it checks that the runner gives the proxy.
// egressrras needs a Windows Server whose Routing and Remote Access runs as a LAN router (the egress-rras job of windows.yml
// installs it, .github/scripts/egress-nat.ps1 -Rras) and checks RRAS NAT there.

#include "testlist.h"

#include "Cedar/ConfigStore.h"
#include "Cedar/Node.h"
#include "Cedar/NodeCaps.h"
#include "Cedar/NodeEgress.h"

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
#include "Core/Transport.h"

#include <iphlpapi.h>

#include <stdio.h>

#define	EGRESSTEST_BUDGET		150000		// The whole test ends within this time, or the watchdog ends the process (ms)
#define	EGRESSTEST_BOUND		10000		// A bounded wait on observable state (ms)
#define	EGRESSTEST_POLL			20			// Poll interval of observable state (ms)
#define	EGRESSTEST_QUIET		1500		// ms that a packet that must get no answer waits for one
#define	EGRESSTEST_CORP			301			// The VRF whose internet exit node-x is
#define	EGRESSTEST_LAB			302			// Another VRF of node-x, which node-c is no member of
#define	EGRESSTEST_LENGTH		24			// The prefix length of the Networks of the test
#define	EGRESSTEST_MAX_PACKET	2048		// Bytes of a packet that the host of node-c keeps at most
#define	EGRESSTEST_MAX_PACKETS	256			// Packets that it keeps: the last ones
#define	EGRESSTEST_METRIC		9000		// The metric of the default routes of the uplinks: the runner's own traffic keeps its route
#define	EGRESSTEST_ISN			0x52414E5A	// The initial sequence number of node-c's TCP ("RANZ")
#define	EGRESSTEST_ECHO_ID		0x4547		// The identifier of node-c's echo requests ("EG")
#define	EGRESSTEST_ECHO_PORT	7			// The UDP port of the echo behind uplink-a
#define	EGRESSTEST_MSS			1360		// The MSS that node-c's SYN asks for
#define	EGRESSTEST_NODE_X		"node-x"
#define	EGRESSTEST_NODE_C		"node-c"
#define	EGRESSTEST_TCP_DATA		"ranz egress tcp\n"
#define	EGRESSTEST_UDP_DATA		"ranz egress udp"
#define	EGRESSTEST_ICMP_DATA	"ranz egress icmp"
#define	EGRESSTEST_UPLINK_DATA	"ranz egress uplink"
#define	EGRESSTEST_REFUSED_DATA	"ranz egress refused"
#define	EGRESSTEST_NAT_DATA		"ranz egress nat"
#define	EGRESSTEST_NAT_BUDGET	240000		// The whole of a test of the tiers on the NAT of Windows ends within this time (ms)
#define	EGRESSTEST_NAT_BOUND	30000		// A bounded wait on the NAT of Windows: a reconcile every NODE_EGRESS_NAT_SCAN (ms)
#define	EGRESSTEST_TCP_PORT		80			// The TCP port of the address behind uplink-a, which answers a SYN
#define	EGRESSTEST_SERVER_ISN	0x53525652	// The initial sequence number of that address ("SRVR")
#define	EGRESSTEST_FOREIGN		L"RanzVPN-Test-Foreign"	// The NAT network of WinNAT of another program that egressnat creates
#define	EGRESSTEST_FOREIGN_NET	L"198.18.200.0/24"		// ... over a prefix of no VRF of the test
#define	EGRESSTEST_EXIT_NONE	0			// node-x is the exit of no VRF ...
#define	EGRESSTEST_EXIT_CORP	1			// ... of corp ...
#define	EGRESSTEST_EXIT_BOTH	2			// ... or of corp and lab
#define	EGRESSTEST_SUPERNET		L"198.19.60.0/22"		// The supernet of corp and lab, which the NAT network of WinNAT of node-x holds for the two

// The addresses of the test, in network byte order
static UINT egresstest_x_corp;		// node-x in corp: 198.19.61.1
static UINT egresstest_c_corp;		// node-c in corp: 198.19.61.2
static UINT egresstest_x_lab;		// node-x in lab: 198.19.62.1
static UINT egresstest_lab_other;	// Another address of lab: 198.19.62.5
static UINT egresstest_uplink_a;	// uplink-a: 198.18.61.1
static UINT egresstest_uplink_b;	// uplink-b: 198.18.62.1
static UINT egresstest_behind_net;	// The network behind uplink-a: 198.18.63.0/24 ...
static UINT egresstest_behind;		// ... and the address there that answers: 198.18.63.10

// The checks of the test
typedef struct EGRESSTEST_CTX
{
	UINT NumChecks;
	UINT NumFailed;
} EGRESSTEST_CTX;

// The fake host of node-c: the last packets that the overlay delivered to it in corp
typedef struct EGRESSTEST_HOST
{
	SRWLOCK Lock;
	UINT Taken;											// Packets taken in all; packet i is at i % EGRESSTEST_MAX_PACKETS
	UINT Sizes[EGRESSTEST_MAX_PACKETS];
	UCHAR Packets[EGRESSTEST_MAX_PACKETS][EGRESSTEST_MAX_PACKET];
} EGRESSTEST_HOST;

// What a packet that the host of node-c waits for is
typedef struct EGRESSTEST_MATCH
{
	UINT Protocol;		// IP_PROTO_TCP, IP_PROTO_UDP or IP_PROTO_ICMPV4
	UINT Src;			// Its source ...
	UINT SrcPort;		// ... and source port (TCP and UDP)
	UINT Dst;			// Its destination ...
	UINT DstPort;		// ... and destination port (TCP and UDP)
	UINT TcpFlags;		// TCP: the flags that it has, all of them
	UINT EchoSeq;		// ICMP: the sequence number of the echo reply, whose identifier is EGRESSTEST_ECHO_ID
	char *Payload;		// What its payload begins with, NULL for any
} EGRESSTEST_MATCH;

// The network outside behind uplink-a: what leaves the runner by uplink-a to it gets its answer on uplink-b, or with Back on
// uplink-a itself, where a NAT of Windows took it out
typedef struct EGRESSTEST_UPLINKS
{
	NODE_WINTUN *A;						// uplink-a ...
	NODE_WINTUN *B;						// ... and uplink-b
	bool Back;							// The answers go back into uplink-a (the tiers on the NAT of Windows)
	volatile LONG Datagrams;			// UDP datagrams to the echo port of the address behind uplink-a that left by uplink-a
	volatile LONG Echoes;				// Echo requests to that address that left by uplink-a
	volatile LONG Segments;				// TCP SYNs to its TCP port that left by uplink-a
	volatile LONG Translated;			// Packets to that address that left with the address of uplink-a as their source
	volatile LONG Answered;				// Answers that the test put into uplink-b, or uplink-a with Back
} EGRESSTEST_UPLINKS;

// What the watchdog of a test waits for: its end within its budget
typedef struct EGRESSTEST_WATCH
{
	HANDLE Done;						// Set when the test ends
	UINT Budget;						// ms that the test has
	char *Name;							// The name of the test in capitals, for the line that says it failed
} EGRESSTEST_WATCH;

// The echo servers of the runner on its own address
typedef struct EGRESSTEST_SERVERS
{
	SOCKET Tcp;							// The TCP listener ...
	SOCKET Udp;							// ... and the UDP socket
	UINT TcpPort;						// Their ports
	UINT UdpPort;
	volatile LONG Stop;					// Ends their threads
	HANDLE TcpThread;
	HANDLE UdpThread;
	volatile LONG TcpEchoed;			// Bytes that the TCP server sent back
	volatile LONG UdpEchoed;			// Datagrams that the UDP server sent back
} EGRESSTEST_SERVERS;

static bool EgressTestCheck(EGRESSTEST_CTX *ctx, bool ok, char *what, char *fmt, ...) RANZ_PRINTF_FORMAT(4, 5);
static bool EgressTestCheck(EGRESSTEST_CTX *ctx, bool ok, char *what, char *fmt, ...)
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

// The watchdog: a native thread that ends a run that hangs, so that a lost packet is a failed test instead of a hung CI step
static DWORD WINAPI EgressTestWatchdog(LPVOID param)
{
	EGRESSTEST_WATCH *w = (EGRESSTEST_WATCH *)param;
	char msg[MAX_SIZE];
	DWORD written = 0;

	if (WaitForSingleObject(w->Done, w->Budget) != WAIT_TIMEOUT)
	{
		return 0;
	}

	int len = snprintf(msg, sizeof(msg), "%s TEST FAILED (did not finish within %u ms)\n", w->Name, w->Budget);
	if (len > 0)
	{
		WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), msg, (DWORD)MIN((UINT)len, (UINT)sizeof(msg) - 1), &written, NULL);
	}

	TerminateProcess(GetCurrentProcess(), 1);

	return 0;
}

// An IPv4 address of four bytes, in network byte order
static UINT EgressTestAddr(UCHAR a, UCHAR b, UCHAR c, UCHAR d)
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

// An address as text
static void EgressTestAddrStr(char *str, UINT size, UINT addr)
{
	IPToStr32(str, size, addr);
}

//
// The nodes
//

// A new empty data directory under the temp directory of the process, with a configuration store: no role, one worker
static void EgressTestNewDir(wchar_t *dir, UINT size, char *name)
{
	wchar_t tmp[MAX_PATH];
	wchar_t path[MAX_PATH];

	UniFormat(tmp, sizeof(tmp), L"egresstest_%S_%u", name, Rand32());
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
static void EgressTestDeleteDir(wchar_t *dir)
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

// The lines of the node log in a data directory that tell about the Egress and the adapters, for a part of the test that
// failed
static void EgressTestPrintLog(wchar_t *dir)
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
			if (InStr(t->Token[j], "Egress") || InStr(t->Token[j], "Wintun") || InStr(t->Token[j], "VRF adapters") || InStr(t->Token[j], "Overlay"))
			{
				Print("  [LOG] %s\n", t->Token[j]);
			}
		}
		FreeToken(t);
		Free(text);
		FreeBuf(b);
	}

	FreeDir(d);
}

// Stop and free a node of the test, and delete its data directory with its node log, whose lines about the Egress are
// printed first with print_log
static void EgressTestFreeNode(NODE *n, wchar_t *dir, bool print_log)
{
	wchar_t log_dir[MAX_PATH];

	if (n == NULL)
	{
		return;
	}

	NodeStop(n);
	FreeNode(n);

	if (print_log)
	{
		EgressTestPrintLog(dir);
	}

	ConbinePathW(log_dir, sizeof(log_dir), dir, NODE_LOG_DIR_NAME);
	EgressTestDeleteDir(log_dir);
	EgressTestDeleteDir(dir);
}

// The address addr of a node in the Network network of the VRF vrf_id
static void EgressTestAddress(CONTROL_ADDRESS *a, char *network, UINT vrf_id, UINT addr)
{
	Zero(a, sizeof(CONTROL_ADDRESS));
	StrCpy(a->Network, sizeof(a->Network), network);
	a->VrfId = vrf_id;
	Copy(a->Address, &addr, 4);
	a->AddressSize = 4;
	a->Length = EGRESSTEST_LENGTH;
}

// The desired state of node-x in corp and lab, with node-c as its peer in corp; node-x is the exit of the VRFs that exits names
// (EGRESSTEST_EXIT_*). In the order of the protocol: the addresses by Network name, the VRFs by name, the exits by id.
static void EgressTestStateX(CONTROL_STATE *st, CONTROL_PEER *peer, UINT64 generation, const UCHAR *c_key, UINT exits)
{
	Zero(st, sizeof(CONTROL_STATE));
	Zero(peer, sizeof(CONTROL_PEER));

	st->Generation = generation;
	StrCpy(st->Name, sizeof(st->Name), EGRESSTEST_NODE_X);
	EgressTestAddress(&st->Addresses[0], "corp-lan", EGRESSTEST_CORP, egresstest_x_corp);
	EgressTestAddress(&st->Addresses[1], "lab-lan", EGRESSTEST_LAB, egresstest_x_lab);
	st->NumAddresses = 2;
	StrCpy(st->Vrfs[0].Name, sizeof(st->Vrfs[0].Name), "corp");
	st->Vrfs[0].Id = EGRESSTEST_CORP;
	StrCpy(st->Vrfs[1].Name, sizeof(st->Vrfs[1].Name), "lab");
	st->Vrfs[1].Id = EGRESSTEST_LAB;
	st->NumVrfs = 2;

	StrCpy(peer->Name, sizeof(peer->Name), EGRESSTEST_NODE_C);
	Copy(peer->Key, c_key, PEER_KEY_SIZE);
	peer->VrfIds[0] = EGRESSTEST_CORP;
	peer->NumVrfs = 1;
	EgressTestAddress(&peer->Addresses[0], "corp-lan", EGRESSTEST_CORP, egresstest_c_corp);
	peer->NumAddresses = 1;
	st->Peers = peer;
	st->NumPeers = 1;

	if (exits != EGRESSTEST_EXIT_NONE)
	{
		st->EgressVrfIds[st->NumEgress++] = EGRESSTEST_CORP;
	}
	if (exits == EGRESSTEST_EXIT_BOTH)
	{
		st->EgressVrfIds[st->NumEgress++] = EGRESSTEST_LAB;
	}
}

// The desired state of node-c in corp, with node-x as its peer; with exit, the default route of corp leads to node-x
static void EgressTestStateC(CONTROL_STATE *st, CONTROL_PEER *peer, UINT64 generation, const UCHAR *x_key, bool exit)
{
	Zero(st, sizeof(CONTROL_STATE));
	Zero(peer, sizeof(CONTROL_PEER));

	st->Generation = generation;
	StrCpy(st->Name, sizeof(st->Name), EGRESSTEST_NODE_C);
	EgressTestAddress(&st->Addresses[0], "corp-lan", EGRESSTEST_CORP, egresstest_c_corp);
	st->NumAddresses = 1;
	StrCpy(st->Vrfs[0].Name, sizeof(st->Vrfs[0].Name), "corp");
	st->Vrfs[0].Id = EGRESSTEST_CORP;
	st->NumVrfs = 1;

	StrCpy(peer->Name, sizeof(peer->Name), EGRESSTEST_NODE_X);
	Copy(peer->Key, x_key, PEER_KEY_SIZE);
	peer->VrfIds[0] = EGRESSTEST_CORP;
	peer->NumVrfs = 1;
	EgressTestAddress(&peer->Addresses[0], "corp-lan", EGRESSTEST_CORP, egresstest_x_corp);
	peer->NumAddresses = 1;
	if (exit)
	{
		peer->Routes[0].VrfId = EGRESSTEST_CORP;
		peer->Routes[0].AddressSize = 4;
		peer->Routes[0].Length = 0;
		peer->NumRoutes = 1;
	}
	st->Peers = peer;
	st->NumPeers = 1;
}

// Apply the states of a Generation to node-x and node-c, as the control stream does: node-x the exit of the VRFs that exits
// names (EGRESSTEST_EXIT_*), and node-c with the default route of corp to node-x while node-x is the exit of corp
static bool EgressTestApply(NODE *x, NODE *c, UINT64 generation, const UCHAR *x_key, const UCHAR *c_key, UINT exits)
{
	CONTROL_STATE *st = ZeroMalloc(sizeof(CONTROL_STATE));
	CONTROL_PEER *peer = ZeroMalloc(sizeof(CONTROL_PEER));

	EgressTestStateX(st, peer, generation, c_key, exits);
	bool ok = NodeOverlayApply(x, st);
	EgressTestStateC(st, peer, generation, x_key, exits != EGRESSTEST_EXIT_NONE);
	ok = NodeOverlayApply(c, st) && ok;

	Free(peer);
	Free(st);

	return ok;
}

// The number of Noise sessions of the overlay of a node
static UINT EgressTestLinks(NODE *n)
{
	NODE_OVERLAY_STATUS st;

	NodeOverlayGetStatus(n, &st);

	return st.NumLinks;
}

// The host of node-x: its adapters of the VRFs, which the test plugs into its overlay as the client role does
static void EgressTestToHost(NODE *n, void *param, UINT vrf_id, const UCHAR *packet, UINT size)
{
	NodeVrfAdaptersSend((NODE_VRF_ADAPTERS *)param, vrf_id, packet, size);
}

static void EgressTestApplied(NODE *n, void *param, const CONTROL_STATE *st)
{
	NodeVrfAdaptersApply((NODE_VRF_ADAPTERS *)param, st);
}

static void EgressTestHalt(NODE *n, void *param)
{
	NodeVrfAdaptersHalt((NODE_VRF_ADAPTERS *)param);
}

// The host of node-c, on the thread of its overlay: it keeps the packets of corp
static void EgressTestClientHost(NODE *n, void *param, UINT vrf_id, const UCHAR *packet, UINT size)
{
	EGRESSTEST_HOST *h = (EGRESSTEST_HOST *)param;

	if (vrf_id != EGRESSTEST_CORP || size == 0 || size > EGRESSTEST_MAX_PACKET)
	{
		return;
	}

	AcquireSRWLockExclusive(&h->Lock);
	{
		UINT i = h->Taken % EGRESSTEST_MAX_PACKETS;

		Copy(h->Packets[i], packet, size);
		h->Sizes[i] = size;
		h->Taken++;
	}
	ReleaseSRWLockExclusive(&h->Lock);
}

//
// Packets
//

// An IPv4 packet of the protocol from src to dst around the upper layer l4 of size bytes into buf: the checksum of its
// header, and of TCP and UDP over the pseudo-header, of ICMP over the message. Its size.
static UINT EgressTestIp(UCHAR *buf, UINT protocol, UINT src, UINT dst, const UCHAR *l4, UINT size)
{
	USHORT sum;
	UINT total = 20 + size;

	Zero(buf, 20);
	buf[0] = 0x45;
	buf[2] = (UCHAR)(total >> 8);
	buf[3] = (UCHAR)total;
	buf[6] = 0x40;
	buf[8] = 64;
	buf[9] = (UCHAR)protocol;
	Copy(buf + 12, &src, 4);
	Copy(buf + 16, &dst, 4);
	sum = IpChecksum(buf, 20);
	Copy(buf + 10, &sum, 2);
	Copy(buf + 20, l4, size);

	if (protocol == IP_PROTO_TCP || protocol == IP_PROTO_UDP)
	{
		UINT at = 20 + (protocol == IP_PROTO_TCP ? 16 : 6);

		buf[at] = 0;
		buf[at + 1] = 0;
		sum = CalcChecksumForIPv4(src, dst, (UCHAR)protocol, buf + 20, size, 0);
		Copy(buf + at, &sum, 2);
	}
	else
	{
		buf[22] = 0;
		buf[23] = 0;
		sum = IpChecksum(buf + 20, size);
		Copy(buf + 22, &sum, 2);
	}

	return total;
}

// A UDP datagram of node-c from src_port to dst:dst_port with data into buf: its size
static UINT EgressTestUdp(UCHAR *buf, UINT src_port, UINT dst, UINT dst_port, char *data)
{
	UCHAR l4[EGRESSTEST_MAX_PACKET];
	UINT size = 8 + StrLen(data);

	Zero(l4, 8);
	WRITE_USHORT(l4, src_port);
	WRITE_USHORT(l4 + 2, dst_port);
	WRITE_USHORT(l4 + 4, size);
	Copy(l4 + 8, data, StrLen(data));

	return EgressTestIp(buf, IP_PROTO_UDP, egresstest_c_corp, dst, l4, size);
}

// A TCP segment of node-c from src_port to dst:dst_port with the sequence and acknowledgment numbers, the flags and data
// (NULL for none) into buf, with an MSS option on a SYN: its size
static UINT EgressTestTcp(UCHAR *buf, UINT src_port, UINT dst, UINT dst_port, UINT seq, UINT ack, UINT flags, char *data)
{
	UCHAR l4[EGRESSTEST_MAX_PACKET];
	UINT header = ((flags & TCP_SYN) != 0 ? 24 : 20);
	UINT data_size = (data != NULL ? StrLen(data) : 0);

	Zero(l4, header);
	WRITE_USHORT(l4, src_port);
	WRITE_USHORT(l4 + 2, dst_port);
	WRITE_UINT(l4 + 4, seq);
	WRITE_UINT(l4 + 8, ack);
	l4[12] = (UCHAR)((header / 4) << 4);
	l4[13] = (UCHAR)flags;
	WRITE_USHORT(l4 + 14, 65535);
	if (header == 24)
	{
		l4[20] = 2;
		l4[21] = 4;
		WRITE_USHORT(l4 + 22, EGRESSTEST_MSS);
	}
	if (data_size != 0)
	{
		Copy(l4 + header, data, data_size);
	}

	return EgressTestIp(buf, IP_PROTO_TCP, egresstest_c_corp, dst, l4, header + data_size);
}

// An echo request of node-c to dst with the sequence number seq and data into buf: its size
static UINT EgressTestEcho(UCHAR *buf, UINT dst, UINT seq, char *data)
{
	UCHAR l4[EGRESSTEST_MAX_PACKET];
	UINT size = 8 + StrLen(data);

	Zero(l4, 8);
	l4[0] = 8;
	WRITE_USHORT(l4 + 4, EGRESSTEST_ECHO_ID);
	WRITE_USHORT(l4 + 6, seq);
	Copy(l4 + 8, data, StrLen(data));

	return EgressTestIp(buf, IP_PROTO_ICMPV4, egresstest_c_corp, dst, l4, size);
}

// Put a packet of node-c's host into its overlay in corp, as a reader of its tables for the call
static bool EgressTestSend(NODE *c, const UCHAR *packet, UINT size)
{
	NODE_READER r;

	Zero(&r, sizeof(r));
	NodeReaderRegister(c, &r);
	bool ok = NodeOverlayInput(c, EGRESSTEST_CORP, packet, size);
	NodeReaderUnregister(c, &r);

	return ok;
}

// Whether the checksums of the IPv4 packet that p read at packet hold: of its header, and of TCP and UDP over the
// pseudo-header (a UDP datagram without one holds), of ICMP over the message
static bool EgressTestChecksums(const UCHAR *packet, const NODE_EGRESS_PACKET *p)
{
	UINT src = 0;
	UINT dst = 0;
	UINT size = p->Total - p->HeaderSize;
	const UCHAR *l4 = packet + p->HeaderSize;

	Copy(&src, packet + 12, 4);
	Copy(&dst, packet + 16, 4);

	if (IpChecksum((void *)packet, p->HeaderSize) != 0)
	{
		return false;
	}
	if (p->Protocol == IP_PROTO_UDP && l4[6] == 0 && l4[7] == 0)
	{
		return true;
	}
	if (p->Protocol == IP_PROTO_TCP || p->Protocol == IP_PROTO_UDP)
	{
		return (CalcChecksumForIPv4(src, dst, (UCHAR)p->Protocol, (void *)l4, size, 0) == 0);
	}

	return (IpChecksum((void *)l4, size) == 0);
}

// Whether the host of node-c took a packet that m names within wait ms: its copy into out (EGRESSTEST_MAX_PACKET bytes) and
// its size into out_size
static bool EgressTestTake(EGRESSTEST_HOST *h, const EGRESSTEST_MATCH *m, UINT wait, UCHAR *out, UINT *out_size)
{
	for (UINT64 end = Tick64() + wait;;)
	{
		bool found = false;

		AcquireSRWLockShared(&h->Lock);
		for (UINT i = 0;i < MIN(h->Taken, (UINT)EGRESSTEST_MAX_PACKETS) && found == false;i++)
		{
			const UCHAR *packet = h->Packets[i];
			NODE_EGRESS_PACKET p;
			UINT src = 0;
			UINT dst = 0;

			if (NodeEgressParse(packet, h->Sizes[i], &p) == false || p.Protocol != m->Protocol)
			{
				continue;
			}

			Copy(&src, p.Src, 4);
			Copy(&dst, p.Dst, 4);
			if (src != m->Src || dst != m->Dst)
			{
				continue;
			}

			if (m->Protocol == IP_PROTO_ICMPV4)
			{
				if (p.IcmpType != 0 || p.EchoId != EGRESSTEST_ECHO_ID || p.EchoSeq != m->EchoSeq)
				{
					continue;
				}
			}
			else if (p.SrcPort != m->SrcPort || p.DstPort != m->DstPort ||
				(m->Protocol == IP_PROTO_TCP && (packet[p.HeaderSize + 13] & m->TcpFlags) != m->TcpFlags))
			{
				continue;
			}

			if (m->Payload != NULL && (p.Total - p.Payload < StrLen(m->Payload) || Cmp(packet + p.Payload, m->Payload, StrLen(m->Payload)) != 0))
			{
				continue;
			}

			Copy(out, packet, h->Sizes[i]);
			*out_size = h->Sizes[i];
			found = true;
		}
		ReleaseSRWLockShared(&h->Lock);

		if (found)
		{
			return true;
		}
		if (Tick64() >= end)
		{
			return false;
		}

		SleepThread(EGRESSTEST_POLL);
	}
}

//
// The outside
//

// The address of the runner: the source of its route to the internet, 0 for none
static UINT EgressTestRunnerAddress()
{
	SOCKADDR_INET d;
	SOCKADDR_INET from;
	MIB_IPFORWARD_ROW2 best;
	UINT ret = 0;
	UINT google = EgressTestAddr(8, 8, 8, 8);

	Zero(&d, sizeof(d));
	Zero(&from, sizeof(from));
	Zero(&best, sizeof(best));
	d.Ipv4.sin_family = AF_INET;
	Copy(&d.Ipv4.sin_addr, &google, 4);

	if (GetBestRoute2(NULL, 0, NULL, &d, 0, &best, &from) != NO_ERROR)
	{
		return 0;
	}

	Copy(&ret, &from.Ipv4.sin_addr, 4);

	return ret;
}

// The TCP echo server: each connection gets back the bytes of its first read, then the server closes it
static DWORD WINAPI EgressTestTcpServer(LPVOID param)
{
	EGRESSTEST_SERVERS *s = (EGRESSTEST_SERVERS *)param;

	while (ReadAcquire(&s->Stop) == 0)
	{
		WSAPOLLFD fd;
		char buf[1024];
		DWORD timeout = 5000;

		fd.fd = s->Tcp;
		fd.events = POLLRDNORM;
		fd.revents = 0;
		if (WSAPoll(&fd, 1, 100) <= 0)
		{
			continue;
		}

		SOCKET c = accept(s->Tcp, NULL, NULL);
		if (c == INVALID_SOCKET)
		{
			continue;
		}

		setsockopt(c, SOL_SOCKET, SO_RCVTIMEO, (const char *)&timeout, sizeof(timeout));
		int r = recv(c, buf, sizeof(buf), 0);
		if (r > 0 && send(c, buf, r, 0) == r)
		{
			InterlockedAdd(&s->TcpEchoed, r);
		}
		shutdown(c, SD_SEND);
		closesocket(c);
	}

	return 0;
}

// The UDP echo server: each datagram goes back to where it came from
static DWORD WINAPI EgressTestUdpServer(LPVOID param)
{
	EGRESSTEST_SERVERS *s = (EGRESSTEST_SERVERS *)param;

	while (ReadAcquire(&s->Stop) == 0)
	{
		WSAPOLLFD fd;
		char buf[1024];
		SOCKADDR_IN from;
		int from_size = sizeof(from);

		fd.fd = s->Udp;
		fd.events = POLLRDNORM;
		fd.revents = 0;
		if (WSAPoll(&fd, 1, 100) <= 0)
		{
			continue;
		}

		int r = recvfrom(s->Udp, buf, sizeof(buf), 0, (SOCKADDR *)&from, &from_size);
		if (r > 0 && sendto(s->Udp, buf, r, 0, (SOCKADDR *)&from, from_size) == r)
		{
			InterlockedIncrement(&s->UdpEchoed);
		}
	}

	return 0;
}

// A socket of the type bound to addr on a port that the system picks, its port into port: INVALID_SOCKET when it cannot be
// had
static SOCKET EgressTestBind(UINT addr, int type, UINT *port)
{
	SOCKADDR_IN a;
	int size = sizeof(a);

	SOCKET s = socket(AF_INET, type, (type == SOCK_STREAM ? IPPROTO_TCP : IPPROTO_UDP));
	if (s == INVALID_SOCKET)
	{
		return INVALID_SOCKET;
	}

	Zero(&a, sizeof(a));
	a.sin_family = AF_INET;
	Copy(&a.sin_addr, &addr, 4);
	if (bind(s, (SOCKADDR *)&a, sizeof(a)) != 0 || (type == SOCK_STREAM && listen(s, SOMAXCONN) != 0) || getsockname(s, (SOCKADDR *)&a, &size) != 0)
	{
		closesocket(s);
		return INVALID_SOCKET;
	}

	*port = ntohs(a.sin_port);

	return s;
}

// Start the echo servers on the address of the runner: false when a socket or a thread cannot be had
static bool EgressTestServersStart(EGRESSTEST_SERVERS *s, UINT addr)
{
	Zero(s, sizeof(EGRESSTEST_SERVERS));
	s->Tcp = EgressTestBind(addr, SOCK_STREAM, &s->TcpPort);
	s->Udp = EgressTestBind(addr, SOCK_DGRAM, &s->UdpPort);
	if (s->Tcp != INVALID_SOCKET)
	{
		s->TcpThread = CreateThread(NULL, 0, EgressTestTcpServer, s, 0, NULL);
	}
	if (s->Udp != INVALID_SOCKET)
	{
		s->UdpThread = CreateThread(NULL, 0, EgressTestUdpServer, s, 0, NULL);
	}

	return (s->TcpThread != NULL && s->UdpThread != NULL);
}

// Stop the echo servers
static void EgressTestServersStop(EGRESSTEST_SERVERS *s)
{
	InterlockedExchange(&s->Stop, 1);

	for (UINT i = 0;i < 2;i++)
	{
		HANDLE t = (i == 0 ? s->TcpThread : s->UdpThread);

		if (t != NULL)
		{
			WaitForSingleObject(t, INFINITE);
			CloseHandle(t);
		}
	}
	if (s->Tcp != INVALID_SOCKET)
	{
		closesocket(s->Tcp);
	}
	if (s->Udp != INVALID_SOCKET)
	{
		closesocket(s->Udp);
	}
}

// What the runner sends out by uplink-a, on the I/O thread of its adapter queue: a UDP datagram to the echo port of the
// address behind it, an echo request to that address and a TCP SYN to its TCP port get their answer from that address on
// uplink-b, or on uplink-a with Back. A packet whose source is the address of uplink-a was translated by a NAT of Windows.
static void EgressTestUplinkA(NODE_WINTUN *w, void *param, const UCHAR *packet, UINT size)
{
	EGRESSTEST_UPLINKS *u = (EGRESSTEST_UPLINKS *)param;
	NODE_EGRESS_PACKET p;
	UCHAR reply[EGRESSTEST_MAX_PACKET];
	UINT src = 0;
	UINT dst = 0;
	UINT total = 0;

	if (NodeEgressParse(packet, size, &p) == false || p.Total > sizeof(reply))
	{
		return;
	}

	Copy(&src, p.Src, 4);
	Copy(&dst, p.Dst, 4);
	if (dst != egresstest_behind)
	{
		return;
	}

	if (src == egresstest_uplink_a)
	{
		InterlockedIncrement(&u->Translated);
	}

	if (p.Protocol == IP_PROTO_TCP && p.DstPort == EGRESSTEST_TCP_PORT && (p.TcpFlags & (TCP_SYN | TCP_ACK | TCP_RST)) == TCP_SYN)
	{
		UCHAR l4[20];

		// The SYN-ACK: the ports swapped, the sequence number of the address behind uplink-a, the SYN acknowledged
		Zero(l4, sizeof(l4));
		WRITE_USHORT(l4, p.DstPort);
		WRITE_USHORT(l4 + 2, p.SrcPort);
		WRITE_UINT(l4 + 4, EGRESSTEST_SERVER_ISN);
		WRITE_UINT(l4 + 8, READ_UINT(packet + p.HeaderSize + 4) + 1);
		l4[12] = 5 << 4;
		l4[13] = TCP_SYN | TCP_ACK;
		WRITE_USHORT(l4 + 14, 65535);
		total = EgressTestIp(reply, IP_PROTO_TCP, dst, src, l4, sizeof(l4));
		InterlockedIncrement(&u->Segments);
	}
	else if (p.Protocol == IP_PROTO_UDP && p.DstPort == EGRESSTEST_ECHO_PORT)
	{
		UCHAR l4[EGRESSTEST_MAX_PACKET];
		UINT l4_size = p.Total - p.HeaderSize;

		// The datagram back: its ports swapped
		Copy(l4, packet + p.HeaderSize, l4_size);
		WRITE_USHORT(l4, p.DstPort);
		WRITE_USHORT(l4 + 2, p.SrcPort);
		total = EgressTestIp(reply, IP_PROTO_UDP, dst, src, l4, l4_size);
		InterlockedIncrement(&u->Datagrams);
	}
	else if (p.Protocol == IP_PROTO_ICMPV4 && p.IcmpType == 8)
	{
		UCHAR l4[EGRESSTEST_MAX_PACKET];
		UINT l4_size = p.Total - p.HeaderSize;

		// The echo reply: type 0, the rest of the message as it is
		Copy(l4, packet + p.HeaderSize, l4_size);
		l4[0] = 0;
		total = EgressTestIp(reply, IP_PROTO_ICMPV4, dst, src, l4, l4_size);
		InterlockedIncrement(&u->Echoes);
	}

	if (total != 0 && NodeWintunSend(u->Back ? u->A : u->B, reply, total))
	{
		InterlockedIncrement(&u->Answered);
	}
}

// What the runner sends out by uplink-b: nothing that the test answers
static void EgressTestUplinkB(NODE_WINTUN *w, void *param, const UCHAR *packet, UINT size)
{
}

// A default route of the metric EGRESSTEST_METRIC through the interface of luid: false when it cannot be added
static bool EgressTestDefaultRoute(UINT64 luid)
{
	MIB_IPFORWARD_ROW2 row;

	InitializeIpForwardEntry(&row);
	row.InterfaceLuid.Value = luid;
	row.DestinationPrefix.Prefix.Ipv4.sin_family = AF_INET;
	row.DestinationPrefix.PrefixLength = 0;
	row.NextHop.Ipv4.sin_family = AF_INET;
	row.Metric = EGRESSTEST_METRIC;
	row.Protocol = MIB_IPPROTO_NETMGMT;

	DWORD err = CreateIpForwardEntry2(&row);

	return (err == NO_ERROR || err == ERROR_OBJECT_ALREADY_EXISTS);
}

// The forwarding of the IPv4 interface of luid as Windows holds it: bit 0 Forwarding, bit 1 WeakHostSend, bit 2
// WeakHostReceive; 8 when it cannot be read
static UINT EgressTestFlags(UINT64 luid)
{
	MIB_IPINTERFACE_ROW row;

	InitializeIpInterfaceEntry(&row);
	row.Family = AF_INET;
	row.InterfaceLuid.Value = luid;
	if (GetIpInterfaceEntry(&row) != NO_ERROR)
	{
		return 8;
	}

	return (row.ForwardingEnabled ? 1 : 0) | (row.WeakHostSend ? 2 : 0) | (row.WeakHostReceive ? 4 : 0);
}

// Whether the interfaces of uplink-a and uplink-b have the forwarding want_a and want_b (EgressTestFlags) within
// EGRESSTEST_BOUND; what they have into got_a and got_b
static bool EgressTestWaitFlags(UINT64 a, UINT64 b, UINT want_a, UINT want_b, UINT *got_a, UINT *got_b)
{
	for (UINT64 end = Tick64() + EGRESSTEST_BOUND;;SleepThread(EGRESSTEST_POLL))
	{
		*got_a = EgressTestFlags(a);
		*got_b = EgressTestFlags(b);
		if ((*got_a == want_a && *got_b == want_b) || Tick64() >= end)
		{
			return (*got_a == want_a && *got_b == want_b);
		}
	}
}

// Bring up uplink-a and uplink-b on the node n: their addresses, a default route of a high metric through each and a route
// through uplink-a to the network behind it, whose answers go back into uplink-a with back. False when one cannot be had.
static bool EgressTestUplinksStart(EGRESSTEST_UPLINKS *u, NODE *n, bool back)
{
	wchar_t name[MAX_SIZE];
	NODE_PREFIX p;
	UINT r = Rand32() & 0xFFFF;

	Zero(u, sizeof(EGRESSTEST_UPLINKS));
	u->Back = back;

	// uplink-b first: the answers of uplink-a go into it
	UniFormat(name, sizeof(name), L"RanzEb%04x", r);
	u->B = NodeWintunNew(n, name, EgressTestUplinkB, u);
	UniFormat(name, sizeof(name), L"RanzEa%04x", r);
	u->A = (u->B != NULL ? NodeWintunNew(n, name, EgressTestUplinkA, u) : NULL);
	if (u->A == NULL)
	{
		return false;
	}

	Zero(&p, sizeof(p));
	p.AddressSize = 4;
	p.Length = 32;
	Copy(p.Address, &egresstest_uplink_a, 4);
	bool ok = NodeWintunSetAddresses(u->A, &p, 1);
	Copy(p.Address, &egresstest_uplink_b, 4);
	ok = NodeWintunSetAddresses(u->B, &p, 1) && ok;
	Copy(p.Address, &egresstest_behind_net, 4);
	p.Length = EGRESSTEST_LENGTH;
	ok = NodeWintunSetRoutes(u->A, &p, 1) && ok;
	ok = EgressTestDefaultRoute(NodeWintunLuid(u->A)) && ok;
	ok = EgressTestDefaultRoute(NodeWintunLuid(u->B)) && ok;

	return ok;
}

// Take uplink-a and uplink-b away with their addresses and routes: uplink-a stops answering into uplink-b first
static void EgressTestUplinksStop(EGRESSTEST_UPLINKS *u)
{
	NodeWintunHalt(u->A);
	NodeWintunFree(u->B);
	NodeWintunFree(u->A);
	u->A = NULL;
	u->B = NULL;
}

// Whether a UDP datagram of a socket of the runner bound to uplink-a, to the echo port of the address behind it, gets its
// answer, which comes on uplink-b, within EGRESSTEST_QUIET
static bool EgressTestStrongHost()
{
	UINT port = 0;
	DWORD timeout = EGRESSTEST_QUIET;
	char buf[64];
	SOCKADDR_IN to;

	SOCKET s = EgressTestBind(egresstest_uplink_a, SOCK_DGRAM, &port);
	if (s == INVALID_SOCKET)
	{
		return false;
	}

	Zero(&to, sizeof(to));
	to.sin_family = AF_INET;
	Copy(&to.sin_addr, &egresstest_behind, 4);
	to.sin_port = htons(EGRESSTEST_ECHO_PORT);
	setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char *)&timeout, sizeof(timeout));

	bool back = (sendto(s, EGRESSTEST_UPLINK_DATA, StrLen(EGRESSTEST_UPLINK_DATA), 0, (SOCKADDR *)&to, sizeof(to)) > 0 && recv(s, buf, sizeof(buf), 0) > 0);
	closesocket(s);

	return back;
}

//
// The test
//

// The flows of node-c through the proxy of node-x to the runner, its own address outside: TCP, UDP and an echo
static void EgressTestOutside(EGRESSTEST_CTX *ctx, NODE *x, NODE *c, EGRESSTEST_HOST *h, EGRESSTEST_SERVERS *s, UINT outside)
{
	UCHAR packet[EGRESSTEST_MAX_PACKET];
	UCHAR got[EGRESSTEST_MAX_PACKET];
	UINT got_size = 0;
	EGRESSTEST_MATCH m;
	NODE_EGRESS_PACKET p;
	char a[64];
	char what[MAX_SIZE];

	EgressTestAddrStr(a, sizeof(a), outside);

	// An echo request to the runner
	bool sent = EgressTestSend(c, packet, EgressTestEcho(packet, outside, 1, EGRESSTEST_ICMP_DATA));
	Zero(&m, sizeof(m));
	m.Protocol = IP_PROTO_ICMPV4;
	m.Src = outside;
	m.Dst = egresstest_c_corp;
	m.EchoSeq = 1;
	m.Payload = EGRESSTEST_ICMP_DATA;
	bool back = (sent && EgressTestTake(h, &m, EGRESSTEST_BOUND, got, &got_size) && NodeEgressParse(got, got_size, &p) && EgressTestChecksums(got, &p));
	Format(what, sizeof(what), "an echo request of node-c in corp to the runner (%s) gets its echo reply from the runner, with its data and checksums that hold", a);
	EgressTestCheck(ctx, back, what, "sent %u", (UINT)sent);

	// A UDP datagram to the UDP echo server of the runner
	sent = EgressTestSend(c, packet, EgressTestUdp(packet, 41001, outside, s->UdpPort, EGRESSTEST_UDP_DATA));
	Zero(&m, sizeof(m));
	m.Protocol = IP_PROTO_UDP;
	m.Src = outside;
	m.SrcPort = s->UdpPort;
	m.Dst = egresstest_c_corp;
	m.DstPort = 41001;
	m.Payload = EGRESSTEST_UDP_DATA;
	back = (sent && EgressTestTake(h, &m, EGRESSTEST_BOUND, got, &got_size) && NodeEgressParse(got, got_size, &p) && EgressTestChecksums(got, &p));
	Format(what, sizeof(what), "a UDP datagram of node-c to the echo server of the runner (%s:%u) comes back from the server's address and port, with checksums that hold", a, s->UdpPort);
	EgressTestCheck(ctx, back, what, "sent %u, the server echoed %d datagrams", (UINT)sent, (int)ReadAcquire(&s->UdpEchoed));

	// A TCP connection to the TCP echo server of the runner: the SYN gets its SYN-ACK
	sent = EgressTestSend(c, packet, EgressTestTcp(packet, 41002, outside, s->TcpPort, EGRESSTEST_ISN, 0, TCP_SYN, NULL));
	Zero(&m, sizeof(m));
	m.Protocol = IP_PROTO_TCP;
	m.Src = outside;
	m.SrcPort = s->TcpPort;
	m.Dst = egresstest_c_corp;
	m.DstPort = 41002;
	m.TcpFlags = TCP_SYN | TCP_ACK;
	back = (sent && EgressTestTake(h, &m, EGRESSTEST_BOUND, got, &got_size) && NodeEgressParse(got, got_size, &p) && EgressTestChecksums(got, &p) &&
		READ_UINT(got + p.HeaderSize + 8) == EGRESSTEST_ISN + 1);
	Format(what, sizeof(what), "a TCP SYN of node-c to the echo server of the runner (%s:%u) gets its SYN-ACK from the server's address and port", a, s->TcpPort);
	bool open = EgressTestCheck(ctx, back, what, "sent %u", (UINT)sent);

	// ... the line of node-c comes back from the server
	if (open)
	{
		UINT seq = READ_UINT(got + p.HeaderSize + 4);
		UINT next = EGRESSTEST_ISN + 1;

		sent = EgressTestSend(c, packet, EgressTestTcp(packet, 41002, outside, s->TcpPort, next, seq + 1, TCP_ACK | TCP_PSH, EGRESSTEST_TCP_DATA));
		m.TcpFlags = TCP_ACK;
		m.Payload = EGRESSTEST_TCP_DATA;
		back = (sent && EgressTestTake(h, &m, EGRESSTEST_BOUND, got, &got_size) && NodeEgressParse(got, got_size, &p) && EgressTestChecksums(got, &p));
		EgressTestCheck(ctx, back, "the line that node-c sends on its TCP connection comes back from the echo server of the runner through the proxy",
			"sent %u, the server echoed %d bytes", (UINT)sent, (int)ReadAcquire(&s->TcpEchoed));

		// The connection ends with a reset of node-c
		EgressTestSend(c, packet, EgressTestTcp(packet, 41002, outside, s->TcpPort, next + StrLen(EGRESSTEST_TCP_DATA), 0, TCP_RST, NULL));
	}
}

// The flows of node-c to the network behind uplink-a, whose answers come back on uplink-b
static void EgressTestUplinks(EGRESSTEST_CTX *ctx, NODE *c, EGRESSTEST_HOST *h, EGRESSTEST_UPLINKS *u)
{
	UCHAR packet[EGRESSTEST_MAX_PACKET];
	UCHAR got[EGRESSTEST_MAX_PACKET];
	UINT got_size = 0;
	EGRESSTEST_MATCH m;
	LONG datagrams = ReadAcquire(&u->Datagrams);
	LONG echoes = ReadAcquire(&u->Echoes);

	bool sent = EgressTestSend(c, packet, EgressTestUdp(packet, 41003, egresstest_behind, EGRESSTEST_ECHO_PORT, EGRESSTEST_UPLINK_DATA));
	Zero(&m, sizeof(m));
	m.Protocol = IP_PROTO_UDP;
	m.Src = egresstest_behind;
	m.SrcPort = EGRESSTEST_ECHO_PORT;
	m.Dst = egresstest_c_corp;
	m.DstPort = 41003;
	m.Payload = EGRESSTEST_UPLINK_DATA;
	bool back = (sent && EgressTestTake(h, &m, EGRESSTEST_BOUND, got, &got_size));
	EgressTestCheck(ctx, back && ReadAcquire(&u->Datagrams) > datagrams,
		"a UDP datagram of node-c to the network behind uplink-a leaves the runner by uplink-a, and its answer, which comes on uplink-b, reaches node-c",
		"sent %u, %d datagrams left by uplink-a, %d answers went into uplink-b", (UINT)sent, (int)(ReadAcquire(&u->Datagrams) - datagrams), (int)ReadAcquire(&u->Answered));

	sent = EgressTestSend(c, packet, EgressTestEcho(packet, egresstest_behind, 2, EGRESSTEST_UPLINK_DATA));
	Zero(&m, sizeof(m));
	m.Protocol = IP_PROTO_ICMPV4;
	m.Src = egresstest_behind;
	m.Dst = egresstest_c_corp;
	m.EchoSeq = 2;
	m.Payload = EGRESSTEST_UPLINK_DATA;
	back = (sent && EgressTestTake(h, &m, EGRESSTEST_BOUND, got, &got_size));
	EgressTestCheck(ctx, back && ReadAcquire(&u->Echoes) > echoes,
		"an echo request of node-c to the network behind uplink-a leaves the runner by uplink-a, and its reply, which comes on uplink-b, reaches node-c",
		"sent %u, %d echo requests left by uplink-a, %d answers went into uplink-b", (UINT)sent, (int)(ReadAcquire(&u->Echoes) - echoes), (int)ReadAcquire(&u->Answered));
}

// Datagrams of node-c to the loopback, to a link-local address and to an address of lab: no answer, and the Egress counts
// them as refused
static void EgressTestRefused(EGRESSTEST_CTX *ctx, NODE *x, NODE *c, EGRESSTEST_HOST *h, EGRESSTEST_SERVERS *s)
{
	UCHAR packet[EGRESSTEST_MAX_PACKET];
	UCHAR got[EGRESSTEST_MAX_PACKET];
	UINT got_size = 0;
	NODE_EGRESS_STATUS before;
	NODE_EGRESS_STATUS after;
	UINT targets[3];
	bool any = false;

	targets[0] = EgressTestAddr(127, 0, 0, 1);
	targets[1] = EgressTestAddr(169, 254, 1, 1);
	targets[2] = egresstest_lab_other;

	NodeEgressGetStatus(x, &before);
	for (UINT i = 0;i < 3;i++)
	{
		EgressTestSend(c, packet, EgressTestUdp(packet, 41010 + i, targets[i], s->UdpPort, EGRESSTEST_REFUSED_DATA));
	}

	for (UINT i = 0;i < 3 && any == false;i++)
	{
		EGRESSTEST_MATCH m;

		Zero(&m, sizeof(m));
		m.Protocol = IP_PROTO_UDP;
		m.Src = targets[i];
		m.SrcPort = s->UdpPort;
		m.Dst = egresstest_c_corp;
		m.DstPort = 41010 + i;
		any = EgressTestTake(h, &m, (i == 0 ? EGRESSTEST_QUIET : 0), got, &got_size);
	}

	for (UINT64 end = Tick64() + EGRESSTEST_BOUND;;SleepThread(EGRESSTEST_POLL))
	{
		NodeEgressGetStatus(x, &after);
		if (after.Refused >= before.Refused + 3 || Tick64() >= end)
		{
			break;
		}
	}

	EgressTestCheck(ctx, any == false && after.Refused >= before.Refused + 3,
		"datagrams of node-c to the loopback, to a link-local address and to an address of lab, another VRF of node-x, get no answer, and the Egress refuses them",
		"answered %u, %I64u refused (%I64u before)", (UINT)any, after.Refused, before.Refused);
}

static void EgressTestRun(EGRESSTEST_CTX *ctx)
{
	NODE *x = NULL;
	NODE *c = NULL;
	wchar_t x_dir[MAX_PATH];
	wchar_t c_dir[MAX_PATH];
	wchar_t name[MAX_SIZE];
	char a[64];
	UCHAR scalar[PEER_KEY_SIZE];
	PEER_KEY x_key;
	PEER_KEY c_key;
	NODE_OVERLAY_CONFIG cfg;
	NODE_EGRESS_STATUS es;
	EGRESSTEST_SERVERS servers;
	EGRESSTEST_UPLINKS uplinks;
	NODE_VRF_ADAPTERS *set = NULL;
	EGRESSTEST_HOST *host = ZeroMalloc(sizeof(EGRESSTEST_HOST));
	TRANSPORT *loopback = TransportLoopbackNew("loopback", 0, false);
	UINT failed = ctx->NumFailed;
	UINT flags_a = 0;
	UINT flags_b = 0;
	UINT before_a = 8;
	UINT before_b = 8;
	bool servers_up = false;
	bool uplinks_up = false;

	InitializeSRWLock(&host->Lock);
	Zero(&x_key, sizeof(x_key));
	Zero(&c_key, sizeof(c_key));
	Zero(&servers, sizeof(servers));
	Zero(&uplinks, sizeof(uplinks));
	servers.Tcp = INVALID_SOCKET;
	servers.Udp = INVALID_SOCKET;
	UniFormat(name, sizeof(name), L"RanzX%04x", Rand32() & 0xFFFF);

	UINT outside = EgressTestRunnerAddress();
	EgressTestAddrStr(a, sizeof(a), outside);
	Print("  [INFO] the outside: the runner's own address %s, the source of its route to the internet\n", a);

	// The static keys of the two nodes: random scalars, so the adapters of a run have GUIDs of their own
	Rand(scalar, sizeof(scalar));
	bool ok = PeerKeyFromScalar(&x_key, scalar);
	Rand(scalar, sizeof(scalar));
	ok = PeerKeyFromScalar(&c_key, scalar) && ok;
	Zero(scalar, sizeof(scalar));
	ok = EgressTestCheck(ctx, ok && loopback != NULL && outside != 0, "node-x and node-c: their static keys, the in-process loopback transport and the address of the runner",
		"a key, the transport or the address failed (address %s)", a);

	if (ok)
	{
		servers_up = EgressTestServersStart(&servers, outside);
		ok = EgressTestCheck(ctx, servers_up, "the echo servers of TCP and UDP listen on the address of the runner", "TCP port %u, UDP port %u", servers.TcpPort, servers.UdpPort);
	}

	if (ok)
	{
		// node-x: its adapters of the VRFs are the host of its overlay, with the forwarding of an exit
		EgressTestNewDir(x_dir, sizeof(x_dir), "nodex");
		x = NewNode(x_dir);
		NodeStart(x);
		set = NodeVrfAdaptersNew(x, name, x_key.Public, true);
		Zero(&cfg, sizeof(cfg));
		cfg.Data = loopback;
		cfg.Key = &x_key;
		cfg.Adapter = EgressTestToHost;
		cfg.AdapterParam = set;
		cfg.AdapterStop = EgressTestHalt;
		cfg.State = EgressTestApplied;
		// The proxy, whatever tier this runner gives: egressnattest.c checks the tiers on the NAT of Windows
		cfg.EgressTier = CONTROL_EGRESS_PROXY;
		ok = (set != NULL && NodeOverlayStart(x, &cfg));

		// node-c: its fake host is the test
		EgressTestNewDir(c_dir, sizeof(c_dir), "nodec");
		c = NewNode(c_dir);
		NodeStart(c);
		Zero(&cfg, sizeof(cfg));
		cfg.Data = loopback;
		cfg.Key = &c_key;
		cfg.Adapter = EgressTestClientHost;
		cfg.AdapterParam = host;
		ok = NodeOverlayStart(c, &cfg) && ok;

		ok = EgressTestCheck(ctx, ok, "node-x and node-c: their overlays run, node-x with its adapters of the VRFs as its host", "NodeVrfAdaptersNew or NodeOverlayStart failed");
	}

	// The uplinks, and what the strong host model does before node-x is an exit
	if (ok)
	{
		uplinks_up = EgressTestUplinksStart(&uplinks, c, false);
		ok = EgressTestCheck(ctx, uplinks_up, "uplink-a and uplink-b: two Wintun adapters of the test with their addresses, a default route of a high metric each and a route through uplink-a to the network behind it",
			"an adapter, an address or a route failed");
	}

	if (ok)
	{
		before_a = EgressTestFlags(NodeWintunLuid(uplinks.A));
		before_b = EgressTestFlags(NodeWintunLuid(uplinks.B));
		EgressTestCheck(ctx, before_a == 0 && before_b == 0, "before node-x is an exit, uplink-a and uplink-b have Forwarding, WeakHostSend and WeakHostReceive off",
			"uplink-a %u, uplink-b %u", before_a, before_b);
		Print("  [INFO] before node-x is an exit, a datagram of the runner by uplink-a whose answer comes on uplink-b gets it: %u (the strong host model drops it)\n",
			(UINT)EgressTestStrongHost());
	}

	// node-x is the exit of corp, and node-c has the default route of corp to node-x
	if (ok)
	{
		bool applied = EgressTestApply(x, c, 1, x_key.Public, c_key.Public, EGRESSTEST_EXIT_CORP);
		bool up = false;

		for (UINT64 end = Tick64() + EGRESSTEST_BOUND;applied && up == false && Tick64() < end;SleepThread(EGRESSTEST_POLL))
		{
			up = (EgressTestLinks(x) == 1 && EgressTestLinks(c) == 1);
		}

		ok = EgressTestCheck(ctx, applied && up, "node-x, the exit of corp (301), and node-c apply their states, and their session is up", "applied %u, sessions %u and %u",
			(UINT)applied, EgressTestLinks(x), EgressTestLinks(c));
	}

	if (ok)
	{
		bool ready = false;

		for (UINT64 end = Tick64() + EGRESSTEST_BOUND;ready == false && Tick64() < end;SleepThread(EGRESSTEST_POLL))
		{
			NodeEgressGetStatus(x, &es);
			ready = (es.NumVrfs == 1 && es.NumReady == 1);
		}

		NodeEgressGetStatus(x, &es);
		ok = EgressTestCheck(ctx, ready && es.Tier == CONTROL_EGRESS_PROXY,
			"the Egress of node-x uses the proxy, the tier of every host, and its proxy listens on the address of node-x in corp", "tier %u, %u VRFs, %u ready",
			es.Tier, es.NumVrfs, es.NumReady);
	}

	if (ok)
	{
		bool on = EgressTestWaitFlags(NodeWintunLuid(uplinks.A), NodeWintunLuid(uplinks.B), 7, 7, &flags_a, &flags_b);

		NodeEgressGetStatus(x, &es);
		EgressTestCheck(ctx, on && es.NumUplinks >= 2,
			"while node-x is the exit of corp, uplink-a and uplink-b carry the egress: Forwarding, WeakHostSend and WeakHostReceive on, as GetIpInterfaceEntry reads them back",
			"uplink-a %u, uplink-b %u, %u interfaces that carry the egress", flags_a, flags_b, es.NumUplinks);
	}

	if (ok)
	{
		Print("[the outside: the runner]\n");
		EgressTestOutside(ctx, x, c, host, &servers, outside);

		Print("[the reply on another interface]\n");
		EgressTestUplinks(ctx, c, host, &uplinks);

		Print("[refused]\n");
		EgressTestRefused(ctx, x, c, host, &servers);

		NodeEgressGetStatus(x, &es);
		Print("  [INFO] the Egress of node-x: %u flows, %I64u TCP connections, %I64u UDP flows, %I64u echo requests, %I64u replies, %I64u refused, %I64u dropped\n",
			es.NumFlows, es.Tcp, es.Udp, es.Echoes, es.EchoReplies, es.Refused, es.Dropped);
		EgressTestCheck(ctx, es.Tcp >= 1 && es.Udp >= 2 && es.Echoes >= 2 && es.EchoReplies >= 2,
			"the Egress counts the TCP connection, the UDP flows and the echo requests and replies that it carried", "%I64u, %I64u, %I64u, %I64u", es.Tcp, es.Udp,
			es.Echoes, es.EchoReplies);
	}

	// node-x is the exit of no VRF any more: the uplinks get back what they had
	if (ok)
	{
		bool applied = EgressTestApply(x, c, 2, x_key.Public, c_key.Public, EGRESSTEST_EXIT_NONE);
		bool back = EgressTestWaitFlags(NodeWintunLuid(uplinks.A), NodeWintunLuid(uplinks.B), before_a, before_b, &flags_a, &flags_b);

		NodeEgressGetStatus(x, &es);
		EgressTestCheck(ctx, applied && back && es.NumVrfs == 0,
			"once node-x is the exit of no VRF, uplink-a and uplink-b have the forwarding that they had before, and the Egress holds no VRF",
			"applied %u, uplink-a %u (before %u), uplink-b %u (before %u), %u VRFs", (UINT)applied, flags_a, before_a, flags_b, before_b, es.NumVrfs);
	}

	// The overlays stop, node-x's halting its adapters first, then the adapters, the uplinks and the servers go
	if (c != NULL)
	{
		NodeOverlayStop(c);
	}
	if (x != NULL)
	{
		NodeOverlayStop(x);
	}
	if (set != NULL)
	{
		NodeVrfAdaptersFree(set);
	}
	if (uplinks.A != NULL)
	{
		EgressTestUplinksStop(&uplinks);
	}
	else if (uplinks.B != NULL)
	{
		NodeWintunFree(uplinks.B);
	}
	if (servers.TcpThread != NULL || servers.UdpThread != NULL || servers.Tcp != INVALID_SOCKET || servers.Udp != INVALID_SOCKET)
	{
		EgressTestServersStop(&servers);
	}

	EgressTestFreeNode(x, x_dir, ctx->NumFailed != failed);
	EgressTestFreeNode(c, c_dir, false);
	if (loopback != NULL)
	{
		TransportLoopbackFree(loopback);
	}
	PeerKeyClose(&x_key);
	PeerKeyClose(&c_key);
	Free(host);
}

//
// The tiers on the NAT of Windows
//

// The two nodes of a test of the tiers on the NAT of Windows, on the in-process loopback transport: node-x with its adapters of
// the VRFs as its host, on the tier that the runner gives, and node-c, whose host is the test
typedef struct EGRESSTEST_PAIR
{
	NODE *X;
	NODE *C;
	wchar_t XDir[MAX_PATH];
	wchar_t CDir[MAX_PATH];
	PEER_KEY XKey;
	PEER_KEY CKey;
	NODE_VRF_ADAPTERS *Set;				// The adapters of the VRFs of node-x
	EGRESSTEST_HOST *Host;				// The host of node-c
	TRANSPORT *Loopback;
} EGRESSTEST_PAIR;

// The name of an Egress tier as the test prints it
static char *EgressTestTierName(UINT tier)
{
	switch (tier)
	{
	case CONTROL_EGRESS_RRAS:
		return "RRAS NAT";
	case CONTROL_EGRESS_WINNAT:
		return "WinNAT";
	case CONTROL_EGRESS_PROXY:
		return "the proxy";
	default:
		return "no tier";
	}
}

// The Egress tier that the Capabilities of the runner give a node, with what decides it into host, once a look at the NAT
// networks of WinNAT of the runner, as the Egress of a node makes when it serves tier 2, found what exists: the Capabilities
// take what the last look saw (NodeEgressForeignNetNat). With print, the facts go to the output.
static UINT EgressTestHostTier(NODE_CAPS_HOST *host, bool print)
{
	CONTROL_CAPS caps;

	NodeEgressNetNatPrefix(NODE_EGRESS_NETNAT_NAME, NULL, 0);
	NodeCapsReadHost(host);
	NodeCapsDecide(host, &caps);

	if (print)
	{
		Print("  [INFO] this runner: SKU %u, RRAS as a LAN router %u, Hyper-V %u, WinNAT %u, a NAT network of WinNAT of another program %u: %s (tier %u)\n",
			caps.Sku, (UINT)host->Rras, (UINT)host->HyperV, (UINT)host->WinNat, (UINT)host->NetNat, EgressTestTierName(caps.EgressTier), caps.EgressTier);
	}

	return caps.EgressTier;
}

// The LUID of the interface of the runner that holds the address addr into *luid: false for none
static bool EgressTestLuidOf(UINT addr, UINT64 *luid)
{
	MIB_UNICASTIPADDRESS_TABLE *table = NULL;
	bool found = false;

	if (GetUnicastIpAddressTable(AF_INET, &table) != NO_ERROR)
	{
		return false;
	}

	for (ULONG i = 0;i < table->NumEntries && found == false;i++)
	{
		if (Cmp(&table->Table[i].Address.Ipv4.sin_addr, &addr, 4) == 0)
		{
			*luid = table->Table[i].InterfaceLuid.Value;
			found = true;
		}
	}

	FreeMibTable(table);

	return found;
}

// Whether the NAT of Windows of the tier holds the setting of the node for corp: its NAT network of WinNAT over 198.19.61.0/24,
// the supernet of corp, or the adapter of corp at luid a private interface of the NAT of RRAS
static bool EgressTestNatHolds(UINT tier, UINT64 luid)
{
	wchar_t prefix[MAX_PATH];
	UINT flags = 0;

	if (tier == CONTROL_EGRESS_WINNAT)
	{
		return (NodeEgressNetNatPrefix(NODE_EGRESS_NETNAT_NAME, prefix, sizeof(prefix)) && UniStrCmpi(prefix, L"198.19.61.0/24") == 0);
	}

	return (NodeEgressRrasFlags(luid, &flags) && flags == 0);
}

// Take the setting of the node for corp away from the NAT of Windows of the tier behind its back, as an operator or a reset does.
// With RRAS the test says how its running router let the NAT information of the adapter of corp go.
static bool EgressTestNatTakeAway(UINT tier, UINT64 luid)
{
	UINT how = 0;

	if (tier == CONTROL_EGRESS_WINNAT)
	{
		return NodeEgressNetNatRemove(NODE_EGRESS_NETNAT_NAME);
	}

	bool taken = NodeEgressRrasRemove(luid, &how);
	Print("  [INFO] the NAT information of the adapter of corp taken out of the running router of RRAS: %s\n",
		how == NODE_EGRESS_TAKEN_EMPTY ? "by an empty NAT block" :
		how == NODE_EGRESS_TAKEN_TRANSPORT ? "it kept the information after an empty NAT block, so by the IPv4 transport of the interface anew without it" :
		"no, the router held none or holds it still");

	return taken;
}

// Whether the NAT of Windows of the tier holds nothing of the node: no NAT network of WinNAT of the node, or no NAT information
// of the adapter of corp at corp or of uplink-a at uplink in RRAS
static bool EgressTestNatEmpty(UINT tier, UINT64 corp, UINT64 uplink)
{
	UINT flags = 0;

	if (tier == CONTROL_EGRESS_WINNAT)
	{
		return (NodeEgressNetNatPrefix(NODE_EGRESS_NETNAT_NAME, NULL, 0) == false);
	}

	return (NodeEgressRrasFlags(corp, &flags) == false && NodeEgressRrasFlags(uplink, &flags) == false);
}

// Start the pair, with tag in the names of the data directories of the nodes and node-x on tier (CONTROL_EGRESS_*), 0 for the
// one that the Capabilities of the runner give: false when a key, the transport, the adapters or an overlay cannot be had.
// EgressTestPairStop takes what it started, whatever the result.
static bool EgressTestPairStart(EGRESSTEST_PAIR *p, char *tag, UINT tier)
{
	NODE_OVERLAY_CONFIG cfg;
	UCHAR scalar[PEER_KEY_SIZE];
	wchar_t name[MAX_SIZE];
	char dir[MAX_SIZE];

	Zero(p, sizeof(EGRESSTEST_PAIR));
	p->Host = ZeroMalloc(sizeof(EGRESSTEST_HOST));
	InitializeSRWLock(&p->Host->Lock);
	p->Loopback = TransportLoopbackNew("loopback", 0, false);
	UniFormat(name, sizeof(name), L"RanzN%04x", Rand32() & 0xFFFF);

	// Random scalars, so the adapters of a run have GUIDs of their own
	Rand(scalar, sizeof(scalar));
	bool ok = PeerKeyFromScalar(&p->XKey, scalar);
	Rand(scalar, sizeof(scalar));
	ok = PeerKeyFromScalar(&p->CKey, scalar) && ok;
	Zero(scalar, sizeof(scalar));
	if (ok == false || p->Loopback == NULL)
	{
		return false;
	}

	// node-x: the tier of the test, or with 0 none in its configuration, so the Egress takes the one of the runner
	Format(dir, sizeof(dir), "%sx", tag);
	EgressTestNewDir(p->XDir, sizeof(p->XDir), dir);
	p->X = NewNode(p->XDir);
	NodeStart(p->X);
	p->Set = NodeVrfAdaptersNew(p->X, name, p->XKey.Public, true);
	Zero(&cfg, sizeof(cfg));
	cfg.Data = p->Loopback;
	cfg.Key = &p->XKey;
	cfg.Adapter = EgressTestToHost;
	cfg.AdapterParam = p->Set;
	cfg.AdapterStop = EgressTestHalt;
	cfg.State = EgressTestApplied;
	cfg.EgressTier = tier;
	ok = (p->Set != NULL && NodeOverlayStart(p->X, &cfg));

	Format(dir, sizeof(dir), "%sc", tag);
	EgressTestNewDir(p->CDir, sizeof(p->CDir), dir);
	p->C = NewNode(p->CDir);
	NodeStart(p->C);
	Zero(&cfg, sizeof(cfg));
	cfg.Data = p->Loopback;
	cfg.Key = &p->CKey;
	cfg.Adapter = EgressTestClientHost;
	cfg.AdapterParam = p->Host;

	return (NodeOverlayStart(p->C, &cfg) && ok);
}

// Stop the pair: the overlays, node-x halting its adapters first, then its adapters, the uplinks u (NULL for none) and the
// nodes, with the lines of the node log of node-x about the Egress printed with print_log
static void EgressTestPairStop(EGRESSTEST_PAIR *p, EGRESSTEST_UPLINKS *u, bool print_log)
{
	if (p->C != NULL)
	{
		NodeOverlayStop(p->C);
	}
	if (p->X != NULL)
	{
		NodeOverlayStop(p->X);
	}
	if (p->Set != NULL)
	{
		NodeVrfAdaptersFree(p->Set);
	}
	if (u != NULL && u->A != NULL)
	{
		EgressTestUplinksStop(u);
	}
	else if (u != NULL && u->B != NULL)
	{
		NodeWintunFree(u->B);
	}

	EgressTestFreeNode(p->X, p->XDir, print_log);
	EgressTestFreeNode(p->C, p->CDir, false);
	if (p->Loopback != NULL)
	{
		TransportLoopbackFree(p->Loopback);
	}
	PeerKeyClose(&p->XKey);
	PeerKeyClose(&p->CKey);
	Free(p->Host);
	Zero(p, sizeof(EGRESSTEST_PAIR));
}

// What a test waits for of the Egress of node-x, given its status (EgressTestWant*)
typedef bool (EGRESSTEST_WANT_PROC)(const NODE_EGRESS_STATUS *es);

// Make node-x the exit of the VRFs that exits names (EGRESSTEST_EXIT_*), with node-c routing to it in corp, and wait until their
// session is up and want holds of the Egress of node-x, within EGRESSTEST_NAT_BOUND: whether it did, the status into es
static bool EgressTestExit(EGRESSTEST_PAIR *p, UINT64 generation, UINT exits, EGRESSTEST_WANT_PROC *want, NODE_EGRESS_STATUS *es)
{
	bool applied = EgressTestApply(p->X, p->C, generation, p->XKey.Public, p->CKey.Public, exits);
	bool done = false;

	for (UINT64 end = Tick64() + EGRESSTEST_NAT_BOUND;applied && done == false && Tick64() < end;SleepThread(EGRESSTEST_POLL))
	{
		NodeEgressGetStatus(p->X, es);
		done = (EgressTestLinks(p->X) == 1 && EgressTestLinks(p->C) == 1 && want(es));
	}

	NodeEgressGetStatus(p->X, es);

	return (applied && done);
}

// The Egress serves corp through the NAT of Windows: it holds what corp wants
static bool EgressTestWantNat(const NODE_EGRESS_STATUS *es)
{
	return (es->NumVrfs == 1 && es->NatReady);
}

// The Egress serves corp and lab through WinNAT: it holds what the two want, and the NAT network of WinNAT of the node is over
// their supernet
static bool EgressTestWantSupernet(const NODE_EGRESS_STATUS *es)
{
	wchar_t prefix[MAX_PATH];

	return (es->NumVrfs == 2 && es->NatReady && NodeEgressNetNatPrefix(NODE_EGRESS_NETNAT_NAME, prefix, sizeof(prefix)) &&
		UniStrCmpi(prefix, EGRESSTEST_SUPERNET) == 0);
}

// The Egress serves corp through the proxy: it listens on the address of node-x in corp
static bool EgressTestWantProxy(const NODE_EGRESS_STATUS *es)
{
	return (es->NumVrfs == 1 && es->NumReady == 1);
}

// The Egress serves no VRF, and the NAT of Windows takes nothing of it
static bool EgressTestWantNone(const NODE_EGRESS_STATUS *es)
{
	return (es->NumVrfs == 0 && es->NatReady == false);
}

// The flows of node-c through the NAT of Windows of node-x to the network behind uplink-a, from port and the ports after it
// (when names the moment): a UDP datagram, an echo request and a TCP SYN leave the runner by uplink-a with the address of
// uplink-a as their source, translated, and each answer reaches node-c from the address and port that it named
static void EgressTestNatFlows(EGRESSTEST_CTX *ctx, NODE *c, EGRESSTEST_HOST *h, EGRESSTEST_UPLINKS *u, UINT port, char *when)
{
	UCHAR packet[EGRESSTEST_MAX_PACKET];
	UCHAR got[EGRESSTEST_MAX_PACKET];
	UINT got_size = 0;
	EGRESSTEST_MATCH m;
	NODE_EGRESS_PACKET p;
	char what[MAX_SIZE];

	// A UDP datagram to the echo port
	LONG translated = ReadAcquire(&u->Translated);
	LONG left = ReadAcquire(&u->Datagrams);
	bool sent = EgressTestSend(c, packet, EgressTestUdp(packet, port, egresstest_behind, EGRESSTEST_ECHO_PORT, EGRESSTEST_NAT_DATA));
	Zero(&m, sizeof(m));
	m.Protocol = IP_PROTO_UDP;
	m.Src = egresstest_behind;
	m.SrcPort = EGRESSTEST_ECHO_PORT;
	m.Dst = egresstest_c_corp;
	m.DstPort = port;
	m.Payload = EGRESSTEST_NAT_DATA;
	bool back = (sent && EgressTestTake(h, &m, EGRESSTEST_BOUND, got, &got_size) && NodeEgressParse(got, got_size, &p) && EgressTestChecksums(got, &p));
	Format(what, sizeof(what), "%s: a UDP datagram of node-c to the network behind uplink-a leaves by uplink-a with the address of uplink-a as its source, and its answer reaches node-c", when);
	EgressTestCheck(ctx, back && ReadAcquire(&u->Datagrams) > left && ReadAcquire(&u->Translated) > translated, what,
		"sent %u, answered %u, %d datagrams left by uplink-a, %d of the packets translated", (UINT)sent, (UINT)back, (int)(ReadAcquire(&u->Datagrams) - left),
		(int)(ReadAcquire(&u->Translated) - translated));

	// An echo request, whose identifier the NAT translates and gives back
	translated = ReadAcquire(&u->Translated);
	left = ReadAcquire(&u->Echoes);
	sent = EgressTestSend(c, packet, EgressTestEcho(packet, egresstest_behind, port, EGRESSTEST_NAT_DATA));
	Zero(&m, sizeof(m));
	m.Protocol = IP_PROTO_ICMPV4;
	m.Src = egresstest_behind;
	m.Dst = egresstest_c_corp;
	m.EchoSeq = port;
	m.Payload = EGRESSTEST_NAT_DATA;
	back = (sent && EgressTestTake(h, &m, EGRESSTEST_BOUND, got, &got_size) && NodeEgressParse(got, got_size, &p) && EgressTestChecksums(got, &p));
	Format(what, sizeof(what), "%s: an echo request of node-c to the network behind uplink-a leaves by uplink-a with the address of uplink-a as its source, and its reply reaches node-c", when);
	EgressTestCheck(ctx, back && ReadAcquire(&u->Echoes) > left && ReadAcquire(&u->Translated) > translated, what,
		"sent %u, answered %u, %d echo requests left by uplink-a, %d of the packets translated", (UINT)sent, (UINT)back, (int)(ReadAcquire(&u->Echoes) - left),
		(int)(ReadAcquire(&u->Translated) - translated));

	// A TCP SYN to the TCP port, whose SYN-ACK acknowledges it
	translated = ReadAcquire(&u->Translated);
	left = ReadAcquire(&u->Segments);
	sent = EgressTestSend(c, packet, EgressTestTcp(packet, port + 1, egresstest_behind, EGRESSTEST_TCP_PORT, EGRESSTEST_ISN, 0, TCP_SYN, NULL));
	Zero(&m, sizeof(m));
	m.Protocol = IP_PROTO_TCP;
	m.Src = egresstest_behind;
	m.SrcPort = EGRESSTEST_TCP_PORT;
	m.Dst = egresstest_c_corp;
	m.DstPort = port + 1;
	m.TcpFlags = TCP_SYN | TCP_ACK;
	back = (sent && EgressTestTake(h, &m, EGRESSTEST_BOUND, got, &got_size) && NodeEgressParse(got, got_size, &p) && EgressTestChecksums(got, &p) &&
		READ_UINT(got + p.HeaderSize + 8) == EGRESSTEST_ISN + 1);
	Format(what, sizeof(what), "%s: a TCP SYN of node-c to the network behind uplink-a leaves by uplink-a with the address of uplink-a as its source, and its SYN-ACK reaches node-c", when);
	EgressTestCheck(ctx, back && ReadAcquire(&u->Segments) > left && ReadAcquire(&u->Translated) > translated, what,
		"sent %u, answered %u, %d SYNs left by uplink-a, %d of the packets translated", (UINT)sent, (UINT)back, (int)(ReadAcquire(&u->Segments) - left),
		(int)(ReadAcquire(&u->Translated) - translated));

	// The connection ends with a reset of node-c
	EgressTestSend(c, packet, EgressTestTcp(packet, port + 1, egresstest_behind, EGRESSTEST_TCP_PORT, EGRESSTEST_ISN + 1, 0, TCP_RST, NULL));
}

// The tier on the NAT of Windows that the runner gives, tier (CONTROL_EGRESS_RRAS or CONTROL_EGRESS_WINNAT), with node-x on it:
// the egress of node-c through the NAT, the reconcile of the setting of the node taken away behind its back, and the NAT empty
// of the node once it is the exit of no VRF
static void EgressTestNatRun(EGRESSTEST_CTX *ctx, UINT tier)
{
	EGRESSTEST_PAIR pair;
	EGRESSTEST_UPLINKS uplinks;
	NODE_EGRESS_STATUS es;
	char what[MAX_SIZE];
	char *name = EgressTestTierName(tier);
	UINT failed = ctx->NumFailed;
	UINT64 corp = 0;
	UINT flags = 0;
	// RRAS: whether its IPv4 router holds the NAT routing protocol before node-x, which the node adds where it lacks it and
	// takes out again once it is the exit of no VRF
	bool protocol = (tier == CONTROL_EGRESS_RRAS && NodeEgressRrasProtocolHeld());

	Zero(&uplinks, sizeof(uplinks));
	Zero(&es, sizeof(es));
	Print("[%s]\n", name);

	bool ok = EgressTestPairStart(&pair, "nat", 0);
	NodeEgressGetStatus(pair.X, &es);
	Format(what, sizeof(what), "node-x and node-c: their overlays run, and the Egress of node-x uses %s, the tier that the runner gives", name);
	ok = EgressTestCheck(ctx, ok && es.Tier == tier, what, "overlays %u, tier %u", (UINT)ok, es.Tier);

	if (ok)
	{
		ok = EgressTestCheck(ctx, EgressTestUplinksStart(&uplinks, pair.C, true),
			"uplink-a and uplink-b: two Wintun adapters of the test with their addresses, a default route of a high metric each and a route through uplink-a to the network behind it",
			"an adapter, an address or a route failed");
	}

	// node-x is the exit of corp: the NAT of Windows takes the traffic of corp
	if (ok)
	{
		bool done = EgressTestExit(&pair, 1, EGRESSTEST_EXIT_CORP, EgressTestWantNat, &es);

		Format(what, sizeof(what), "node-x, the exit of corp (301), and node-c apply their states, their session is up, and the NAT of Windows holds what corp wants (%s)", name);
		ok = EgressTestCheck(ctx, done && es.Tier == tier, what, "%u VRFs, NAT ready %u, tier %u (fell back from %u)", es.NumVrfs, (UINT)es.NatReady, es.Tier,
			es.Fallback);
	}

	if (ok && tier == CONTROL_EGRESS_WINNAT)
	{
		ok = EgressTestCheck(ctx, EgressTestLuidOf(egresstest_x_corp, &corp) && EgressTestNatHolds(tier, corp),
			"the NAT network of WinNAT of the node, RanzVPN-Egress, exists over 198.19.61.0/24, the supernet of corp", "it is not there as such");
	}
	else if (ok)
	{
		bool holds = (EgressTestLuidOf(egresstest_x_corp, &corp) && EgressTestNatHolds(tier, corp));
		bool boundary = (NodeEgressRrasFlags(NodeWintunLuid(uplinks.A), &flags) && flags == NODE_EGRESS_RRAS_PUBLIC);

		ok = EgressTestCheck(ctx, holds && boundary,
			"the adapter of corp is a private interface of the NAT of RRAS, and uplink-a, an interface that carries the egress, a public one with address and port translation",
			"adapter of corp %u, uplink-a %u (its flags 0x%x)", (UINT)holds, (UINT)boundary, flags);
	}

	if (ok)
	{
		EgressTestNatFlows(ctx, pair.C, pair.Host, &uplinks, 41020, "through the NAT");
	}

	// The setting of the node taken away behind its back: the next reconcile sets it again, and the egress works again
	if (ok)
	{
		bool again = false;

		NodeEgressGetStatus(pair.X, &es);
		UINT64 before = es.Restored;
		bool taken = EgressTestNatTakeAway(tier, corp);

		for (UINT64 end = Tick64() + EGRESSTEST_NAT_BOUND;taken && again == false && Tick64() < end;SleepThread(EGRESSTEST_POLL * 10))
		{
			NodeEgressGetStatus(pair.X, &es);
			again = (es.Restored > before && EgressTestNatHolds(tier, corp));
		}

		Format(what, sizeof(what), "%s taken away behind the back of node-x is set again by the next reconcile, which the Egress counts",
			tier == CONTROL_EGRESS_WINNAT ? "the NAT network of WinNAT of the node" : "the NAT information of the adapter of corp in RRAS");
		ok = EgressTestCheck(ctx, taken && again, what, "taken away %u, %I64u set again (%I64u before)", (UINT)taken, es.Restored, before);
	}

	if (ok)
	{
		EgressTestNatFlows(ctx, pair.C, pair.Host, &uplinks, 41030, "after the reconcile");
	}

	// WinNAT takes one NAT network per host: once node-x is the exit of lab too, the NAT network of the node holds the supernet of
	// corp and lab in place of the prefix of corp, and the egress of corp goes through it
	if (ok && tier == CONTROL_EGRESS_WINNAT)
	{
		wchar_t prefix[MAX_PATH];
		bool done = EgressTestExit(&pair, 2, EGRESSTEST_EXIT_BOTH, EgressTestWantSupernet, &es);

		NodeEgressNetNatPrefix(NODE_EGRESS_NETNAT_NAME, prefix, sizeof(prefix));
		ok = EgressTestCheck(ctx, done && es.Tier == tier,
			"node-x, the exit of corp (301) and lab (302), applies its state, and the NAT network of WinNAT of the node, RanzVPN-Egress, is over 198.19.60.0/22 now, the supernet of the two",
			"%u VRFs, NAT ready %u, tier %u (fell back from %u), the NAT network of the node over '%S'", es.NumVrfs, (UINT)es.NatReady, es.Tier, es.Fallback, prefix);
	}

	if (ok && tier == CONTROL_EGRESS_WINNAT)
	{
		EgressTestNatFlows(ctx, pair.C, pair.Host, &uplinks, 41040, "through the supernet of corp and lab");
	}

	// node-x is the exit of no VRF: the NAT of Windows holds nothing of it, and with RRAS the running router holds the NAT routing
	// protocol as it did before node-x
	if (ok)
	{
		bool done = EgressTestExit(&pair, 3, EGRESSTEST_EXIT_NONE, EgressTestWantNone, &es);
		bool empty = false;
		bool held = protocol;

		for (UINT64 end = Tick64() + EGRESSTEST_NAT_BOUND;done && empty == false && Tick64() < end;SleepThread(EGRESSTEST_POLL * 10))
		{
			held = (tier == CONTROL_EGRESS_RRAS && NodeEgressRrasProtocolHeld());
			empty = (EgressTestNatEmpty(tier, corp, NodeWintunLuid(uplinks.A)) && held == protocol);
		}

		EgressTestCheck(ctx, done && empty, "once node-x is the exit of no VRF, the NAT of Windows holds nothing of the node", "applied %u, %u VRFs, empty %u, the NAT routing protocol of RRAS %u (before node-x %u)",
			(UINT)done, es.NumVrfs, (UINT)empty, (UINT)held, (UINT)protocol);
	}

	EgressTestPairStop(&pair, &uplinks, ctx->NumFailed != failed);
}

// A NAT network of WinNAT of another program, which the test creates where none exists: once a look found it the runner gives
// the proxy; a new node-x on WinNAT, as a node that has not looked yet starts, finds it at its first reconcile and falls back to
// the proxy, which answers an echo request of node-c from the runner; and the other NAT network is still there as it was once
// the node stopped
static void EgressTestForeign(EGRESSTEST_CTX *ctx)
{
	EGRESSTEST_PAIR pair;
	NODE_CAPS_HOST host;
	NODE_EGRESS_STATUS es;
	UCHAR packet[EGRESSTEST_MAX_PACKET];
	UCHAR got[EGRESSTEST_MAX_PACKET];
	UINT got_size = 0;
	wchar_t before[MAX_PATH];
	wchar_t after[MAX_PATH];
	UINT failed = ctx->NumFailed;
	bool created = false;
	bool ok = true;

	Zero(&es, sizeof(es));
	before[0] = 0;
	after[0] = 0;
	Print("[a NAT network of WinNAT of another program]\n");

	// Whether a NAT network of WinNAT of another program exists on the runner already, as a look sees it
	EgressTestHostTier(&host, false);
	if (host.NetNat == false)
	{
		created = NodeEgressNetNatAdd(EGRESSTEST_FOREIGN, EGRESSTEST_FOREIGN_NET);
		ok = EgressTestCheck(ctx, created && NodeEgressNetNatPrefix(EGRESSTEST_FOREIGN, before, sizeof(before)),
			"a NAT network of WinNAT of another program, RanzVPN-Test-Foreign over 198.18.200.0/24, created as New-NetNat does", "created %u", (UINT)created);
	}

	// The Capabilities take what the last look at the NAT networks saw: the look of EgressTestHostTier finds the other one
	if (ok)
	{
		UINT tier = EgressTestHostTier(&host, true);

		ok = EgressTestCheck(ctx, tier == CONTROL_EGRESS_PROXY && host.NetNat,
			"with a NAT network of WinNAT of another program, which WinNAT allows one of per host, the runner gives the proxy", "tier %u, another NAT network %u", tier,
			(UINT)host.NetNat);
	}

	// node-x on WinNAT, as a node starts whose Capabilities saw no NAT network of WinNAT yet: its first reconcile finds the other
	// one, which it leaves alone, and it falls back to the proxy
	if (ok)
	{
		ok = EgressTestPairStart(&pair, "foreign", CONTROL_EGRESS_WINNAT);
		NodeEgressGetStatus(pair.X, &es);
		ok = EgressTestCheck(ctx, ok && es.Tier == CONTROL_EGRESS_WINNAT,
			"a new node-x on WinNAT, the tier of a node that has not looked at the NAT networks of WinNAT yet, and node-c: their overlays run", "overlays %u, tier %u", (UINT)ok,
			es.Tier);

		if (ok)
		{
			bool done = EgressTestExit(&pair, 1, EGRESSTEST_EXIT_CORP, EgressTestWantProxy, &es);

			ok = EgressTestCheck(ctx, done && es.Tier == CONTROL_EGRESS_PROXY && es.Fallback == CONTROL_EGRESS_WINNAT,
				"node-x is the exit of corp: its first reconcile finds the NAT network of the other program, and it falls back from WinNAT to the proxy, which listens on its address in corp",
				"%u VRFs, %u ready, tier %u (fell back from %u)", es.NumVrfs, es.NumReady, es.Tier, es.Fallback);
		}

		if (ok)
		{
			UINT outside = EgressTestRunnerAddress();
			EGRESSTEST_MATCH m;

			bool sent = (outside != 0 && EgressTestSend(pair.C, packet, EgressTestEcho(packet, outside, 3, EGRESSTEST_ICMP_DATA)));
			Zero(&m, sizeof(m));
			m.Protocol = IP_PROTO_ICMPV4;
			m.Src = outside;
			m.Dst = egresstest_c_corp;
			m.EchoSeq = 3;
			m.Payload = EGRESSTEST_ICMP_DATA;
			EgressTestCheck(ctx, sent && EgressTestTake(pair.Host, &m, EGRESSTEST_BOUND, got, &got_size),
				"an echo request of node-c to the runner gets its echo reply through the proxy", "sent %u", (UINT)sent);
		}

		EgressTestPairStop(&pair, NULL, ctx->NumFailed != failed);
	}

	// The other NAT network as it was: the node never touched it, and made none of its own
	if (created)
	{
		bool same = (NodeEgressNetNatPrefix(EGRESSTEST_FOREIGN, after, sizeof(after)) && UniStrCmpi(after, before) == 0);

		EgressTestCheck(ctx, same && NodeEgressNetNatPrefix(NODE_EGRESS_NETNAT_NAME, NULL, 0) == false,
			"once the node stopped, the NAT network of WinNAT of the other program is still there as it was, and the node made none of its own", "the same %u", (UINT)same);
		EgressTestCheck(ctx, NodeEgressNetNatRemove(EGRESSTEST_FOREIGN), "the test removes the NAT network of WinNAT that it created", "Remove failed");
	}
	else
	{
		EgressTestCheck(ctx, NodeEgressNetNatPrefix(NODE_EGRESS_NETNAT_NAME, NULL, 0) == false,
			"once the node stopped, the node made no NAT network of WinNAT of its own beside the one of the other program", "it made one");
	}
}

// egressnat: the tier that the runner gives, and the tiers on the NAT of Windows that it has
static void EgressTestNatHost(EGRESSTEST_CTX *ctx)
{
	NODE_CAPS_HOST host;
	UINT tier = EgressTestHostTier(&host, true);

	if (tier == CONTROL_EGRESS_WINNAT || tier == CONTROL_EGRESS_RRAS)
	{
		EgressTestNatRun(ctx, tier);
	}

	if (host.HyperV && host.WinNat)
	{
		EgressTestForeign(ctx);
	}
	else
	{
		EgressTestCheck(ctx, tier == CONTROL_EGRESS_PROXY || tier == CONTROL_EGRESS_RRAS,
			"without Hyper-V and WinNAT the runner gives the proxy, or RRAS NAT on a Windows Server whose RRAS runs as a LAN router", "tier %u", tier);
	}
}

// egressrras: RRAS NAT on a Windows Server whose Routing and Remote Access runs as a LAN router
static void EgressTestRras(EGRESSTEST_CTX *ctx)
{
	NODE_CAPS_HOST host;
	UINT tier = EgressTestHostTier(&host, true);

	if (EgressTestCheck(ctx, tier == CONTROL_EGRESS_RRAS, "this runner, a Windows Server whose Routing and Remote Access runs as a LAN router, gives RRAS NAT", "tier %u, RRAS %u",
		tier, (UINT)host.Rras))
	{
		EgressTestNatRun(ctx, CONTROL_EGRESS_RRAS);
	}
}

// The body of a command of the test
typedef void (EGRESSTEST_PROC)(EGRESSTEST_CTX *ctx);

// Run a command of the test under its watchdog of budget ms: the addresses of the test, the crypto module and wintun.dll, then
// run. "<NAME> TEST OK" only when every check passes.
static void EgressTestMain(char *name, char *title, UINT budget, EGRESSTEST_PROC *run)
{
	EGRESSTEST_CTX ctx;
	EGRESSTEST_WATCH watch;
	UINT error = 0;

	Zero(&ctx, sizeof(ctx));
	watch.Done = CreateEventW(NULL, TRUE, FALSE, NULL);
	watch.Budget = budget;
	watch.Name = name;
	HANDLE watchdog = (watch.Done != NULL ? CreateThread(NULL, 0, EgressTestWatchdog, &watch, 0, NULL) : NULL);

	Print("%s\n", title);

	egresstest_x_corp = EgressTestAddr(198, 19, 61, 1);
	egresstest_c_corp = EgressTestAddr(198, 19, 61, 2);
	egresstest_x_lab = EgressTestAddr(198, 19, 62, 1);
	egresstest_lab_other = EgressTestAddr(198, 19, 62, 5);
	egresstest_uplink_a = EgressTestAddr(198, 18, 61, 1);
	egresstest_uplink_b = EgressTestAddr(198, 18, 62, 1);
	egresstest_behind_net = EgressTestAddr(198, 18, 63, 0);
	egresstest_behind = EgressTestAddr(198, 18, 63, 10);

	bool ready = EgressTestCheck(&ctx, CryptoInit(), "the crypto module of the new core runs on CNG", "CryptoInit failed");
	ready = EgressTestCheck(&ctx, NodeWintunAvailable(&error), "wintun.dll is next to vpntest and has the API of wintun.h", "error %u", error) && ready;

	if (ready)
	{
		run(&ctx);
	}

	if (watchdog != NULL)
	{
		SetEvent(watch.Done);
		WaitForSingleObject(watchdog, INFINITE);
		CloseHandle(watchdog);
	}
	if (watch.Done != NULL)
	{
		CloseHandle(watch.Done);
	}

	if (ctx.NumFailed == 0)
	{
		Print("%s TEST OK\n", name);
	}
	else
	{
		Print("%s TEST FAILED (%u of %u checks failed)\n", name, ctx.NumFailed, ctx.NumChecks);
	}
}

// egress: the internet exit of a VRF with the proxy (SDN-12)
RANZ_TEST("egress", egress_test, "Internet exit of a VRF: the proxy of an exit carries TCP, UDP and ICMP echo of a peer to the outside, the interfaces that carry the egress get Forwarding and weak host so a reply on another interface reaches the peer, and the loopback, link-local and other VRFs are refused (administrator rights, wintun.dll).");
void egress_test(UINT num, char **arg)
{
	EgressTestMain("EGRESS", "Egress test: the internet exit of a VRF with the proxy on the TCP/IP stack of the runner", EGRESSTEST_BUDGET, EgressTestRun);
}

// egressnat: the internet exit of a VRF on the NAT of Windows that the runner gives (SDN-12)
RANZ_TEST("egressnat", egressnat_test, "Internet exit of a VRF on the NAT of Windows: the tier that the runner gives; WinNAT where Hyper-V is present translates the egress of a peer over the supernet of the VRFs of the exit, has a removed NAT network set again by the next reconcile and leaves a NAT network of another program alone, the node then taking the proxy (administrator rights, wintun.dll).");
void egressnat_test(UINT num, char **arg)
{
	EgressTestMain("EGRESSNAT", "Egress test: the internet exit of a VRF on the NAT of Windows of the runner", EGRESSTEST_NAT_BUDGET, EgressTestNatHost);
}

// egressrras: the internet exit of a VRF on RRAS NAT (SDN-12)
RANZ_TEST("egressrras", egressrras_test, "Internet exit of a VRF on RRAS NAT: a Windows Server whose Routing and Remote Access runs as a LAN router gives RRAS NAT, which translates the egress of a peer, and a removed NAT setting is set again by the next reconcile (administrator rights, wintun.dll, RRAS: the egress-rras job).");
void egressrras_test(UINT num, char **arg)
{
	EgressTestMain("EGRESSRRAS", "Egress test: the internet exit of a VRF on RRAS NAT of the runner", EGRESSTEST_NAT_BUDGET, EgressTestRras);
}
