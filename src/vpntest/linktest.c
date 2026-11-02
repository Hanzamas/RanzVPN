// linktest.c
// Named link kinds test of vpntest ("links" command, SDN-76 #356)
//
// The kinds of the links between two nodes (Cedar/NodeLink.c) on the overlay of two in-process nodes, as seam 2 of #45
// runs the data plane: fake adapters stand in for the hosts of node-a and node-b, the in-process loopback transport
// carries their Noise session, and the test applies their desired states itself (NodeOverlayApply). Both nodes have a
// tunnel endpoint on 127.0.0.1, each on a VXLAN port and a Geneve port of its own, and share VRF red (101), whose link
// is noise in Generation 1, vxlan on VNI 5101 in Generation 2, geneve in Generation 3 and noise again in Generation 4.
// - Frames: in each Generation the hosts send the same packets of red, IPv4 and IPv6, both ways, and one to an address
//   of no node. What arrives at the other host, and the counters of the overlays, are the same text for each kind of
//   link, which matches the golden file tests/golden/link/link_frames.txt (golden family "link"). Over vxlan and
//   geneve the VXLAN module of each node sent and delivered every packet, and over noise none.
// - The guard: over vxlan and over geneve, a harness tunnel endpoint sends node-b datagrams of red. One from [::1],
//   an address that the Controller did not name, and one on VNI 999, of no VRF, are dropped and counted; over geneve,
//   so is a datagram of VXLAN on the VNI of red, whose link is geneve. The same datagram from 127.0.0.1, the address
//   of node-a, arrives at the host, so the drops come from the guard and not from the form of the datagrams.
// - The switch: each change of the kind is one Generation of each node, the session stays up, and from noise to vxlan
//   a sender that runs through the switch loses no packet that the overlay took: node-b takes the Generation first.
// Print "LINKS TEST OK" only when every check passes.

#include "golden.h"
#include "testlist.h"

#include "Cedar/ConfigStore.h"
#include "Cedar/Node.h"
#include "Cedar/NodeLink.h"

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

#define	LINKTEST_BUDGET			120000		// The whole test ends within this time, or the watchdog ends the process (ms)
#define	LINKTEST_BOUND			10000		// A bounded wait on observable state (ms)
#define	LINKTEST_QUIET			300			// A host that gets nothing gets nothing within this time (ms)
#define	LINKTEST_POLL			10			// Poll interval of observable state (ms)
#define	LINKTEST_SIZE			100			// The size of a test packet
#define	LINKTEST_SWITCH_TIME	500			// The sender of the switch runs this long before and after it (ms)
#define	LINKTEST_VNI			5101		// The VNI of red over vxlan and geneve
#define	LINKTEST_OTHER_VNI		999			// A VNI of no VRF
#define	LINKTEST_VRF			101			// The id of red
#define	LINKTEST_GOLDEN			"link_frames.txt"

// The nodes
#define	LINKTEST_A				0
#define	LINKTEST_B				1

static char *linktest_names[2] = {"node-a", "node-b"};

// The addresses of each node in red, IPv4 and IPv6
static char *linktest_addrs[2][2] =
{
	{"10.0.0.1", "fd00::1"},
	{"10.0.0.2", "fd00::2"},
};

// The kinds of the links of the four Generations
static UINT linktest_kinds[4] = {CONTROL_LINK_NOISE, CONTROL_LINK_VXLAN, CONTROL_LINK_GENEVE, CONTROL_LINK_NOISE};
static char *linktest_kind_names[3] = {"noise", "vxlan", "geneve"};

// The MAC address of both ends of the Ethernet header of a frame of a link
static const UCHAR linktest_mac[6] = {0x02, 0x52, 0x5A, 0x00, 0x00, 0x03};

// One packet of the frames case: the node whose host sends it, its ends, UDP between two ports or an ICMP echo
// request (ICMPv6 for IPv6), and whether the overlay sends it
typedef struct LINKTEST_SEND
{
	UINT From;
	char *Src;
	char *Dst;
	UINT Protocol;
	UINT SrcPort;
	UINT DstPort;
	bool Forwarded;
} LINKTEST_SEND;

static LINKTEST_SEND linktest_sends[] =
{
	{LINKTEST_A, "10.0.0.1", "10.0.0.2", IP_PROTO_UDP, 5000, 53, true},
	{LINKTEST_B, "10.0.0.2", "10.0.0.1", IP_PROTO_UDP, 53, 5000, true},
	{LINKTEST_A, "10.0.0.1", "10.0.0.2", IP_PROTO_ICMPV4, 0, 0, true},
	{LINKTEST_A, "fd00::1", "fd00::2", IP_PROTO_UDP, 40000, 8080, true},
	{LINKTEST_B, "fd00::2", "fd00::1", IP_PROTO_ICMPV4, 0, 0, true},
	{LINKTEST_A, "10.0.0.1", "10.0.0.9", IP_PROTO_UDP, 5000, 53, false},
};

// One node and the fake adapter of its host, which keeps the last packet that the host took
typedef struct LINKTEST_NODE
{
	wchar_t Dir[MAX_PATH];				// Its data directory
	PEER_KEY Key;						// Its static key
	NODE *Node;
	NODE_READER Reader;					// The test thread as a reader of the node's tables, online while it sends
	USHORT VxlanPort;					// The UDP port of its socket of VXLAN ...
	USHORT GenevePort;					// ... and of Geneve
	SRWLOCK Lock;						// Arrivals, Last and LastSize
	volatile LONG Arrivals;				// Packets that the host took
	UINT LastVrf;						// The VRF of the last one ...
	UCHAR Last[LINKTEST_SIZE * 2];		// ... and the packet, as much as fits
	UINT LastSize;
} LINKTEST_NODE;

// The sender of the switch: node-a's host sends to node-b's while the kind changes
typedef struct LINKTEST_SENDER
{
	NODE *Node;
	volatile bool Halt;
	UINT Sent;							// Packets that the overlay took
} LINKTEST_SENDER;

// The test
typedef struct LINKTEST_CTX
{
	UINT NumChecks;
	UINT NumFailed;
	LINKTEST_NODE Nodes[2];
	SOCKET Named;						// A harness tunnel endpoint on 127.0.0.1, the address of node-a
	SOCKET Stranger;					// ... and one on [::1], an address that the Controller did not name
} LINKTEST_CTX;

static bool LinkTestCheck(LINKTEST_CTX *ctx, bool ok, char *what, char *fmt, ...) RANZ_PRINTF_FORMAT(4, 5);
static bool LinkTestCheck(LINKTEST_CTX *ctx, bool ok, char *what, char *fmt, ...)
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

// The watchdog: a native thread that ends a run that hangs, so that a lost packet is a failed test instead of a hung CI
// step
static DWORD WINAPI LinkTestWatchdog(LPVOID param)
{
	char msg[MAX_SIZE];
	DWORD written = 0;

	if (WaitForSingleObject((HANDLE)param, LINKTEST_BUDGET) != WAIT_TIMEOUT)
	{
		return 0;
	}

	int len = snprintf(msg, sizeof(msg), "LINKS TEST FAILED (did not finish within %u ms)\n", LINKTEST_BUDGET);
	if (len > 0)
	{
		WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), msg, (DWORD)MIN((UINT)len, (UINT)sizeof(msg) - 1), &written, NULL);
	}

	TerminateProcess(GetCurrentProcess(), 1);

	return 0;
}

// The address of a text into addr: 4 bytes for IPv4, 16 for IPv6, and their number; 0 for no address
static UINT LinkTestAddress(UCHAR *addr, char *str)
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

// The test packet of s with the data seq, LINKTEST_SIZE bytes, into buf: UDP, or an ICMP echo request, ICMPv6 for IPv6.
// Its size, 0 when its two ends are not of one family.
static UINT LinkTestPacket(UCHAR *buf, LINKTEST_SEND *s, UINT seq)
{
	UCHAR src[16], dst[16];
	UINT src_size = LinkTestAddress(src, s->Src);
	UINT ip = (src_size == 4 ? 20 : 40);
	UCHAR *l4 = buf + ip;

	if (src_size == 0 || LinkTestAddress(dst, s->Dst) != src_size)
	{
		return 0;
	}

	Zero(buf, LINKTEST_SIZE);
	if (src_size == 4)
	{
		buf[0] = 0x45;
		WRITE_USHORT(buf + 2, LINKTEST_SIZE);
		buf[8] = 64;
		buf[9] = (UCHAR)s->Protocol;
		Copy(buf + 12, src, 4);
		Copy(buf + 16, dst, 4);
		USHORT sum = IpChecksum(buf, 20);
		Copy(buf + 10, &sum, 2);
	}
	else
	{
		buf[0] = 0x60;
		WRITE_USHORT(buf + 4, LINKTEST_SIZE - 40);
		buf[6] = (UCHAR)(s->Protocol == IP_PROTO_ICMPV4 ? IP_PROTO_ICMPV6 : s->Protocol);
		buf[7] = 64;
		Copy(buf + 8, src, 16);
		Copy(buf + 24, dst, 16);
	}

	if (s->Protocol == IP_PROTO_UDP)
	{
		WRITE_USHORT(l4, s->SrcPort);
		WRITE_USHORT(l4 + 2, s->DstPort);
		WRITE_USHORT(l4 + 4, LINKTEST_SIZE - ip);
	}
	else
	{
		l4[0] = (UCHAR)(src_size == 4 ? 8 : 128);
	}

	WRITE_UINT(l4 + 8, seq);
	for (UINT i = ip + 12;i < LINKTEST_SIZE;i++)
	{
		buf[i] = (UCHAR)(i * 13 + seq);
	}

	return LINKTEST_SIZE;
}

// The num free UDP ports of the wildcard address into ports, which the system picks, each another: the sockets that
// found them stay open until all are found. False when one cannot be found.
static bool LinkTestFreePorts(USHORT *ports, UINT num)
{
	SOCKET sockets[4] = {INVALID_SOCKET, INVALID_SOCKET, INVALID_SOCKET, INVALID_SOCKET};
	bool ok = (num <= 4);

	for (UINT i = 0;i < num && ok;i++)
	{
		struct sockaddr_in6 sa;
		int sa_size = sizeof(sa);

		ports[i] = 0;
		sockets[i] = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
		Zero(&sa, sizeof(sa));
		sa.sin6_family = AF_INET6;
		if (sockets[i] != INVALID_SOCKET && bind(sockets[i], (struct sockaddr *)&sa, sizeof(sa)) == 0 && getsockname(sockets[i], (struct sockaddr *)&sa, &sa_size) == 0)
		{
			ports[i] = ntohs(sa.sin6_port);
		}
		ok = (ports[i] != 0);
	}

	for (UINT i = 0;i < num && i < 4;i++)
	{
		if (sockets[i] != INVALID_SOCKET)
		{
			closesocket(sockets[i]);
		}
	}

	return ok;
}

// A harness tunnel endpoint: a UDP socket on 127.0.0.1, or on [::1] for v6, on a port that the system picks
static SOCKET LinkTestOpenVtep(bool v6)
{
	SOCKET s = socket(v6 ? AF_INET6 : AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	struct sockaddr_in sa4;
	struct sockaddr_in6 sa6;
	int ret;

	if (s == INVALID_SOCKET)
	{
		return INVALID_SOCKET;
	}

	if (v6)
	{
		Zero(&sa6, sizeof(sa6));
		sa6.sin6_family = AF_INET6;
		sa6.sin6_addr.s6_addr[15] = 1;
		ret = bind(s, (struct sockaddr *)&sa6, sizeof(sa6));
	}
	else
	{
		Zero(&sa4, sizeof(sa4));
		sa4.sin_family = AF_INET;
		sa4.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
		ret = bind(s, (struct sockaddr *)&sa4, sizeof(sa4));
	}

	if (ret != 0)
	{
		closesocket(s);
		return INVALID_SOCKET;
	}

	return s;
}

// Send node-b, from the harness tunnel endpoint s, a datagram on vni in the encapsulation geneve, to its port of that
// encapsulation unless to_vxlan: the header, then the frame of a UDP packet of node-a's host to node-b's in red. Whether
// it went.
static bool LinkTestInject(LINKTEST_CTX *ctx, SOCKET s, bool v6, bool geneve, bool to_vxlan, UINT vni, UINT seq)
{
	UCHAR datagram[8 + NODE_LINK_ETHER + LINKTEST_SIZE];
	LINKTEST_NODE *b = &ctx->Nodes[LINKTEST_B];
	USHORT port = (to_vxlan ? b->VxlanPort : b->GenevePort);
	struct sockaddr_in sa4;
	struct sockaddr_in6 sa6;
	int ret;

	Zero(datagram, sizeof(datagram));
	if (geneve)
	{
		// Version 0 without options, no O or C bit, the protocol of an Ethernet frame
		WRITE_USHORT(datagram + 2, GENEVE_PROTOCOL_ETHERNET);
	}
	else
	{
		datagram[0] = VXLAN_FLAG_VNI;
	}
	datagram[4] = (UCHAR)(vni >> 16);
	datagram[5] = (UCHAR)(vni >> 8);
	datagram[6] = (UCHAR)vni;

	// The frame: the Ethernet header of a link and the packet
	Copy(datagram + 8, linktest_mac, 6);
	Copy(datagram + 8 + 6, linktest_mac, 6);
	WRITE_USHORT(datagram + 8 + 12, MAC_PROTO_IPV4);
	LinkTestPacket(datagram + 8 + NODE_LINK_ETHER, &linktest_sends[0], seq);

	if (v6)
	{
		Zero(&sa6, sizeof(sa6));
		sa6.sin6_family = AF_INET6;
		sa6.sin6_addr.s6_addr[15] = 1;
		sa6.sin6_port = htons(port);
		ret = sendto(s, (char *)datagram, (int)sizeof(datagram), 0, (struct sockaddr *)&sa6, sizeof(sa6));
	}
	else
	{
		Zero(&sa4, sizeof(sa4));
		sa4.sin_family = AF_INET;
		sa4.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
		sa4.sin_port = htons(port);
		ret = sendto(s, (char *)datagram, (int)sizeof(datagram), 0, (struct sockaddr *)&sa4, sizeof(sa4));
	}

	return ret == (int)sizeof(datagram);
}

//
// The nodes
//

// A new empty data directory under the temp directory of the process, with a configuration store that runs no role
// on one worker
static void LinkTestNewDir(wchar_t *dir, UINT size, char *name)
{
	wchar_t tmp[MAX_PATH];
	wchar_t path[MAX_PATH];

	UniFormat(tmp, sizeof(tmp), L"linktest_%S_%u", name, Rand32());
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
static void LinkTestDeleteFiles(wchar_t *dir)
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

// The fake adapter of a host: it counts the packets that the host takes and keeps the last one. A link delivers on the
// receive thread of its socket and a session on the thread of the overlay, so the lock orders the two.
static void LinkTestAdapter(NODE *n, void *param, UINT vrf_id, const UCHAR *packet, UINT size)
{
	LINKTEST_NODE *t = (LINKTEST_NODE *)param;

	AcquireSRWLockExclusive(&t->Lock);
	{
		t->LastVrf = vrf_id;
		t->LastSize = size;
		Copy(t->Last, packet, MIN(size, sizeof(t->Last)));
		InterlockedIncrement(&t->Arrivals);
	}
	ReleaseSRWLockExclusive(&t->Lock);
}

// The addresses of node i in red into a
static UINT LinkTestAddresses(UINT i, CONTROL_ADDRESS *a)
{
	for (UINT k = 0;k < 2;k++)
	{
		Zero(&a[k], sizeof(CONTROL_ADDRESS));
		StrCpy(a[k].Network, sizeof(a[k].Network), "red");
		a[k].VrfId = LINKTEST_VRF;
		a[k].AddressSize = LinkTestAddress(a[k].Address, linktest_addrs[i][k]);
		a[k].Length = (a[k].AddressSize == 4 ? 24 : 64);
	}

	return 2;
}

// The tunnel endpoint of node i into v: 127.0.0.1 and its ports, or only its ports for itself
static void LinkTestVtep(LINKTEST_CTX *ctx, UINT i, CONTROL_VTEP *v, bool address)
{
	Zero(v, sizeof(CONTROL_VTEP));
	if (address)
	{
		v->AddressSize = LinkTestAddress(v->Address, "127.0.0.1");
	}
	v->VxlanPort = ctx->Nodes[i].VxlanPort;
	v->GenevePort = ctx->Nodes[i].GenevePort;
}

// Apply the state of node i at Generation gen: its addresses and its tunnel endpoint, VRF red with the link of kind,
// and the other node as its peer in red, with its tunnel endpoint
static bool LinkTestApply(LINKTEST_CTX *ctx, UINT i, UINT64 gen, UINT kind)
{
	CONTROL_STATE *st = ZeroMalloc(sizeof(CONTROL_STATE));
	UINT j = 1 - i;

	st->Generation = gen;
	StrCpy(st->Name, sizeof(st->Name), linktest_names[i]);
	st->NumAddresses = LinkTestAddresses(i, st->Addresses);
	LinkTestVtep(ctx, i, &st->Vtep, false);

	st->NumVrfs = 1;
	StrCpy(st->Vrfs[0].Name, sizeof(st->Vrfs[0].Name), "red");
	st->Vrfs[0].Id = LINKTEST_VRF;
	st->Vrfs[0].Link = kind;
	st->Vrfs[0].Vni = (kind != CONTROL_LINK_NOISE ? LINKTEST_VNI : 0);

	st->Peers = ZeroMalloc(sizeof(CONTROL_PEER));
	st->NumPeers = 1;
	StrCpy(st->Peers[0].Name, sizeof(st->Peers[0].Name), linktest_names[j]);
	Copy(st->Peers[0].Key, ctx->Nodes[j].Key.Public, PEER_KEY_SIZE);
	st->Peers[0].NumVrfs = 1;
	st->Peers[0].VrfIds[0] = LINKTEST_VRF;
	st->Peers[0].NumAddresses = LinkTestAddresses(j, st->Peers[0].Addresses);
	LinkTestVtep(ctx, j, &st->Peers[0].Vtep, true);

	bool ok = NodeOverlayApply(ctx->Nodes[i].Node, st);

	Free(st->Peers);
	Free(st);

	return ok;
}

// Whether each node runs Generation gen with its session to the other up, within LINKTEST_BOUND
static bool LinkTestWaitLinks(LINKTEST_CTX *ctx, UINT64 gen)
{
	UINT64 end = Tick64() + LINKTEST_BOUND;

	while (true)
	{
		NODE_OVERLAY_STATUS a, b;

		NodeOverlayGetStatus(ctx->Nodes[LINKTEST_A].Node, &a);
		NodeOverlayGetStatus(ctx->Nodes[LINKTEST_B].Node, &b);
		if (a.NumLinks == 1 && b.NumLinks == 1 && a.Generation == gen && b.Generation == gen)
		{
			return true;
		}
		if (Tick64() >= end)
		{
			return false;
		}
		SleepThread(LINKTEST_POLL);
	}
}

// Whether the host of node t took at least target packets within timeout
static bool LinkTestArrived(LINKTEST_NODE *t, LONG target, UINT timeout)
{
	UINT64 end = Tick64() + timeout;

	while (InterlockedCompareExchange(&t->Arrivals, 0, 0) < target)
	{
		if (Tick64() >= end)
		{
			return false;
		}
		SleepThread(LINKTEST_POLL);
	}

	return true;
}

// Whether the counter of the link status of node t that get reads reaches target within LINKTEST_BOUND
static bool LinkTestCounted(LINKTEST_NODE *t, UINT64 (*get)(const NODE_LINK_STATUS *), UINT64 target)
{
	UINT64 end = Tick64() + LINKTEST_BOUND;

	while (true)
	{
		NODE_LINK_STATUS st;

		NodeLinkGetStatus(t->Node, &st);
		if (get(&st) >= target)
		{
			return true;
		}
		if (Tick64() >= end)
		{
			return false;
		}
		SleepThread(LINKTEST_POLL);
	}
}

static UINT64 LinkTestStrangers(const NODE_LINK_STATUS *st)
{
	return st->Strangers;
}

static UINT64 LinkTestUnknownVni(const NODE_LINK_STATUS *st)
{
	return st->UnknownVni;
}

//
// The cases
//

// The packets of the frames case over the link of the Generation that runs, as the text of the golden file; *all_ok
// tells whether each went as the case wants
static char *LinkTestFrames(LINKTEST_CTX *ctx, bool *all_ok)
{
	BUF *b = NewBuf();
	char line[MAX_SIZE * 2];
	NODE_OVERLAY_STATUS before[2], after[2];
	UINT num = sizeof(linktest_sends) / sizeof(linktest_sends[0]);

	*all_ok = true;
	StrCpy(line, sizeof(line), "# VRF red (101) between node-a and node-b: the packets that each host sends, and what the other host takes\n");
	WriteBuf(b, line, StrLen(line));

	for (UINT i = 0;i < 2;i++)
	{
		NodeOverlayGetStatus(ctx->Nodes[i].Node, &before[i]);
	}

	for (UINT k = 0;k < num;k++)
	{
		LINKTEST_SEND *s = &linktest_sends[k];
		LINKTEST_NODE *t = &ctx->Nodes[s->From];
		LINKTEST_NODE *to = &ctx->Nodes[1 - s->From];
		UCHAR packet[LINKTEST_SIZE];
		char sent[MAX_SIZE];
		char *outcome;
		LONG arrivals = InterlockedCompareExchange(&to->Arrivals, 0, 0);
		UINT size = LinkTestPacket(packet, s, 100 + k);

		NodeReaderOnline(t->Node, &t->Reader);
		bool taken = (size != 0 && NodeOverlayInput(t->Node, LINKTEST_VRF, packet, size));
		NodeReaderOffline(&t->Reader);

		bool arrived = LinkTestArrived(to, arrivals + 1, taken ? LINKTEST_BOUND : LINKTEST_QUIET);
		bool same = false;

		AcquireSRWLockShared(&to->Lock);
		{
			same = (arrived && to->LastVrf == LINKTEST_VRF && to->LastSize == size && Cmp(to->Last, packet, size) == 0);
		}
		ReleaseSRWLockShared(&to->Lock);

		if (taken && same)
		{
			outcome = "arrives as it was sent";
		}
		else if (taken == false && arrived == false)
		{
			outcome = "not sent";
		}
		else
		{
			outcome = (taken ? (arrived ? "arrives changed" : "lost") : "arrives though not sent");
		}

		if (taken != s->Forwarded || (taken && same == false) || (taken == false && arrived))
		{
			*all_ok = false;
		}

		if (s->Protocol == IP_PROTO_UDP)
		{
			Format(sent, sizeof(sent), "udp %s:%u > %s:%u", s->Src, s->SrcPort, s->Dst, s->DstPort);
		}
		else
		{
			Format(sent, sizeof(sent), "%s echo request %s > %s", InStr(s->Src, ":") ? "icmpv6" : "icmp", s->Src, s->Dst);
		}

		Format(line, sizeof(line), "%s -> %s: red %s, %u bytes: %s\n", linktest_names[s->From], linktest_names[1 - s->From], sent, size, outcome);
		Print("  %s", line);
		WriteBuf(b, line, StrLen(line));
	}

	for (UINT i = 0;i < 2;i++)
	{
		NodeOverlayGetStatus(ctx->Nodes[i].Node, &after[i]);
		Format(line, sizeof(line), "%s: forwarded %I64u, delivered %I64u, dropped %I64u\n", linktest_names[i],
			after[i].Forwarded - before[i].Forwarded, after[i].Delivered - before[i].Delivered, after[i].Dropped - before[i].Dropped);
		Print("  %s", line);
		WriteBuf(b, line, StrLen(line));
	}

	char *text = HarnessBufToStr(b);
	FreeBuf(b);

	return text;
}

// The guard of the link of kind of the Generation that runs: datagrams from an address that the Controller did not name,
// on a VNI of no VRF, and over geneve in VXLAN on the VNI of red, are dropped and counted; the same datagram from the
// address of node-a arrives
static void LinkTestGuard(LINKTEST_CTX *ctx, UINT kind)
{
	LINKTEST_NODE *b = &ctx->Nodes[LINKTEST_B];
	bool geneve = (kind == CONTROL_LINK_GENEVE);
	NODE_LINK_STATUS before, after;
	char what[MAX_SIZE];

	NodeLinkGetStatus(b->Node, &before);

	LONG arrivals = InterlockedCompareExchange(&b->Arrivals, 0, 0);
	bool sent = LinkTestInject(ctx, ctx->Stranger, true, geneve, geneve == false, LINKTEST_VNI, 300);
	bool counted = sent && LinkTestCounted(b, LinkTestStrangers, before.Strangers + 1);
	bool quiet = (LinkTestArrived(b, arrivals + 1, LINKTEST_QUIET) == false);
	Format(what, sizeof(what), "  %s: a datagram of red from [::1], an address that the Controller did not name, is dropped and counted", linktest_kind_names[kind]);
	LinkTestCheck(ctx, counted && quiet, what, "sent %u, counted %u, the host took nothing %u", (UINT)sent, (UINT)counted, (UINT)quiet);

	sent = LinkTestInject(ctx, ctx->Named, false, geneve, geneve == false, LINKTEST_OTHER_VNI, 301);
	counted = sent && LinkTestCounted(b, LinkTestUnknownVni, before.UnknownVni + 1);
	quiet = (LinkTestArrived(b, arrivals + 1, LINKTEST_QUIET) == false);
	Format(what, sizeof(what), "  %s: a datagram from 127.0.0.1, the address of node-a, on VNI %u of no VRF is dropped and counted", linktest_kind_names[kind], LINKTEST_OTHER_VNI);
	LinkTestCheck(ctx, counted && quiet, what, "sent %u, counted %u, the host took nothing %u", (UINT)sent, (UINT)counted, (UINT)quiet);

	UINT64 unknown = before.UnknownVni + 1;
	if (geneve)
	{
		sent = LinkTestInject(ctx, ctx->Named, false, false, true, LINKTEST_VNI, 302);
		counted = sent && LinkTestCounted(b, LinkTestUnknownVni, before.UnknownVni + 2);
		quiet = (LinkTestArrived(b, arrivals + 1, LINKTEST_QUIET) == false);
		LinkTestCheck(ctx, counted && quiet, "  geneve: a datagram of VXLAN from 127.0.0.1 on the VNI of red, whose link is geneve, is dropped and counted as on an unknown VNI",
			"sent %u, counted %u, the host took nothing %u", (UINT)sent, (UINT)counted, (UINT)quiet);
		unknown++;
	}

	sent = LinkTestInject(ctx, ctx->Named, false, geneve, geneve == false, LINKTEST_VNI, 303);
	bool arrived = sent && LinkTestArrived(b, arrivals + 1, LINKTEST_BOUND);
	NodeLinkGetStatus(b->Node, &after);
	Format(what, sizeof(what), "  %s: the same datagram from 127.0.0.1, the address of node-a, on VNI %u arrives at node-b's host, and no other drop is counted", linktest_kind_names[kind], LINKTEST_VNI);
	LinkTestCheck(ctx, arrived && after.Delivered == before.Delivered + 1 && after.Strangers == before.Strangers + 1 && after.UnknownVni == unknown && after.Malformed == before.Malformed, what,
		"sent %u, arrived %u; delivered %I64u to %I64u, strangers %I64u to %I64u, unknown VNI %I64u to %I64u, malformed %I64u to %I64u", (UINT)sent, (UINT)arrived,
		before.Delivered, after.Delivered, before.Strangers, after.Strangers, before.UnknownVni, after.UnknownVni, before.Malformed, after.Malformed);
}

// One Generation of each node with the link of kind, node-b first: the Generation of each is gen and the session stays up
static bool LinkTestSwitch(LINKTEST_CTX *ctx, UINT64 gen, UINT kind)
{
	char what[MAX_SIZE];

	bool applied = LinkTestApply(ctx, LINKTEST_B, gen, kind) && LinkTestApply(ctx, LINKTEST_A, gen, kind);
	bool linked = applied && LinkTestWaitLinks(ctx, gen);

	Format(what, sizeof(what), "Generation %I64u: the link of red is %s, one Generation of each node, node-b first, and the session stays up", gen, linktest_kind_names[kind]);
	return LinkTestCheck(ctx, applied && linked, what, "applied %u, generation %I64u and the session on both %u", (UINT)applied, gen, (UINT)linked);
}

// The sender of the switch: UDP of node-a's host to node-b's in red, one packet a millisecond, each as an online reader
// of node-a with a quiescent point after it
static DWORD WINAPI LinkTestSenderThread(LPVOID param)
{
	LINKTEST_SENDER *s = (LINKTEST_SENDER *)param;
	UCHAR packet[LINKTEST_SIZE];
	NODE_READER r;

	Zero(&r, sizeof(r));
	NodeReaderRegister(s->Node, &r);

	while (s->Halt == false)
	{
		LinkTestPacket(packet, &linktest_sends[0], 1000 + s->Sent);
		if (NodeOverlayInput(s->Node, LINKTEST_VRF, packet, LINKTEST_SIZE))
		{
			s->Sent++;
		}
		NodeReaderQuiescent(s->Node, &r);
		SleepThread(1);
	}

	NodeReaderUnregister(s->Node, &r);

	return 0;
}

// The switch from noise to vxlan under a sender: every packet that the overlay of node-a took arrives at node-b's host
static void LinkTestSwitchUnderLoad(LINKTEST_CTX *ctx, UINT64 gen)
{
	LINKTEST_SENDER s;
	LINKTEST_NODE *b = &ctx->Nodes[LINKTEST_B];

	Zero(&s, sizeof(s));
	s.Node = ctx->Nodes[LINKTEST_A].Node;

	LONG arrivals = InterlockedCompareExchange(&b->Arrivals, 0, 0);
	HANDLE thread = CreateThread(NULL, 0, LinkTestSenderThread, &s, 0, NULL);
	if (LinkTestCheck(ctx, thread != NULL, "The sender of the switch starts", "CreateThread failed") == false)
	{
		return;
	}

	SleepThread(LINKTEST_SWITCH_TIME);
	bool switched = LinkTestSwitch(ctx, gen, CONTROL_LINK_VXLAN);
	SleepThread(LINKTEST_SWITCH_TIME);
	s.Halt = true;
	WaitForSingleObject(thread, INFINITE);
	CloseHandle(thread);

	bool all = LinkTestArrived(b, arrivals + (LONG)s.Sent, LINKTEST_BOUND);
	LONG got = InterlockedCompareExchange(&b->Arrivals, 0, 0) - arrivals;
	Print("  [INFO] the sender sent %u packets through the switch, node-b's host took %d\n", s.Sent, (int)got);
	LinkTestCheck(ctx, switched && all && s.Sent > 0 && got == (LONG)s.Sent, "From noise to vxlan under a sender: no packet that the overlay of node-a took is lost",
		"switched %u, %u sent, %d arrived", (UINT)switched, s.Sent, (int)got);
}

// The nodes, their overlays and the harness tunnel endpoints
static bool LinkTestOpen(LINKTEST_CTX *ctx, TRANSPORT *loopback)
{
	UCHAR scalar[PEER_KEY_SIZE];
	char what[MAX_SIZE];
	bool ok = (loopback != NULL);
	USHORT ports[4];

	Print("[the nodes, their overlays and the harness tunnel endpoints]\n");

	// The UDP ports of VXLAN and of Geneve of each node
	ok = LinkTestCheck(ctx, ok && LinkTestFreePorts(ports, 4), "Four free UDP ports for the tunnel endpoints of the nodes", "error %u", (UINT)WSAGetLastError()) && ok;

	ctx->Named = LinkTestOpenVtep(false);
	ctx->Stranger = LinkTestOpenVtep(true);
	ok = LinkTestCheck(ctx, ok && ctx->Named != INVALID_SOCKET && ctx->Stranger != INVALID_SOCKET, "Two harness tunnel endpoints, on 127.0.0.1 and on [::1]", "error %u", (UINT)WSAGetLastError()) && ok;

	for (UINT i = 0;i < 2 && ok;i++)
	{
		LINKTEST_NODE *t = &ctx->Nodes[i];
		NODE_OVERLAY_CONFIG c;

		InitializeSRWLock(&t->Lock);
		t->VxlanPort = ports[2 * i];
		t->GenevePort = ports[2 * i + 1];
		for (UINT j = 0;j < PEER_KEY_SIZE;j++)
		{
			scalar[j] = (UCHAR)(0x51 + PEER_KEY_SIZE * i + j);
		}
		ok = PeerKeyFromScalar(&t->Key, scalar);

		LinkTestNewDir(t->Dir, sizeof(t->Dir), linktest_names[i]);
		t->Node = NewNode(t->Dir);
		NodeStart(t->Node);
		NodeReaderRegister(t->Node, &t->Reader);
		NodeReaderOffline(&t->Reader);

		Zero(&c, sizeof(c));
		c.Data = loopback;
		c.Key = &t->Key;
		c.Adapter = LinkTestAdapter;
		c.AdapterParam = t;
		Format(what, sizeof(what), "  %s: its overlay runs without a control stream, its tunnel endpoint on the UDP ports %u (VXLAN) and %u (Geneve)", linktest_names[i], (UINT)t->VxlanPort, (UINT)t->GenevePort);
		ok = LinkTestCheck(ctx, ok && NodeOverlayStart(t->Node, &c), what, "PeerKeyFromScalar or NodeOverlayStart failed") && ok;
	}
	Zero(scalar, sizeof(scalar));

	return ok && LinkTestSwitch(ctx, 1, CONTROL_LINK_NOISE);
}

// The nodes first, whose overlays stop with every thread joined, then the harness tunnel endpoints
static void LinkTestClose(LINKTEST_CTX *ctx)
{
	for (UINT i = 0;i < 2;i++)
	{
		LINKTEST_NODE *t = &ctx->Nodes[i];
		wchar_t log_dir[MAX_PATH];

		if (t->Node != NULL)
		{
			NodeReaderUnregister(t->Node, &t->Reader);
			NodeStop(t->Node);
			FreeNode(t->Node);

			ConbinePathW(log_dir, sizeof(log_dir), t->Dir, NODE_LOG_DIR_NAME);
			LinkTestDeleteFiles(log_dir);
			LinkTestDeleteFiles(t->Dir);
		}
		PeerKeyClose(&t->Key);
	}

	if (ctx->Named != INVALID_SOCKET)
	{
		closesocket(ctx->Named);
	}
	if (ctx->Stranger != INVALID_SOCKET)
	{
		closesocket(ctx->Stranger);
	}
}

// The four Generations: the frames over each kind of link against the golden file and each other, the guard over vxlan
// and geneve, and the switch from noise to vxlan under a sender
static void LinkTestRun(LINKTEST_CTX *ctx)
{
	char *texts[4] = {NULL, NULL, NULL, NULL};
	char out_dir[MAX_SIZE];
	char golden_dir[MAX_SIZE];
	char what[MAX_SIZE];
	bool update;

	for (UINT g = 0;g < 4;g++)
	{
		UINT kind = linktest_kinds[g];
		UINT64 gen = g + 1;
		NODE_LINK_STATUS before[2], after[2];
		bool all_ok = false;

		Print("[Generation %I64u: the link of red is %s]\n", gen, linktest_kind_names[kind]);
		if (g == 1)
		{
			LinkTestSwitchUnderLoad(ctx, gen);
		}
		else if (g != 0 && LinkTestSwitch(ctx, gen, kind) == false)
		{
			break;
		}

		for (UINT i = 0;i < 2;i++)
		{
			NodeLinkGetStatus(ctx->Nodes[i].Node, &before[i]);
		}

		texts[g] = LinkTestFrames(ctx, &all_ok);
		Format(what, sizeof(what), "  %s: every packet arrives at the other host as it was sent, or is not sent where the case says", linktest_kind_names[kind]);
		LinkTestCheck(ctx, all_ok, what, "see the lines above");

		// Node-a sends 3 packets and node-b 2: over vxlan and geneve each goes as a datagram of the module, over noise none
		UINT want[2] = {3, 2};
		bool counted = true;
		for (UINT i = 0;i < 2;i++)
		{
			NodeLinkGetStatus(ctx->Nodes[i].Node, &after[i]);
			UINT64 sent = after[i].Sent - before[i].Sent;
			UINT64 delivered = after[i].Delivered - before[i].Delivered;
			UINT64 expect_sent = (kind != CONTROL_LINK_NOISE ? want[i] : 0);
			UINT64 expect_delivered = (kind != CONTROL_LINK_NOISE ? want[1 - i] : 0);

			Print("  [INFO] %s: the module sent %I64u and delivered %I64u, %u VNIs, ports %u and %u\n", linktest_names[i], sent, delivered, after[i].NumVnis, (UINT)after[i].VxlanPort, (UINT)after[i].GenevePort);
			counted = counted && sent == expect_sent && delivered == expect_delivered && after[i].Failed == before[i].Failed;
		}
		Format(what, sizeof(what), "  %s: the VXLAN module of each node sent and delivered %s", linktest_kind_names[kind], kind != CONTROL_LINK_NOISE ? "every packet of the link" : "none of them");
		LinkTestCheck(ctx, counted, what, "see the lines above");

		if (kind != CONTROL_LINK_NOISE)
		{
			LinkTestGuard(ctx, kind);
		}
	}

	HARNESS h;

	HarnessGetFamilyDirs("link", out_dir, sizeof(out_dir), golden_dir, sizeof(golden_dir), &update);
	MakeDirEx(out_dir);
	Print("[golden]\n");
	Print("LINK GOLDEN MODE %s\n", update ? "update" : "compare");
	Print("  golden directory: %s\n", golden_dir);

	bool same = (texts[0] != NULL);
	for (UINT g = 1;g < 4;g++)
	{
		same = same && texts[g] != NULL && StrCmp(texts[g], texts[0]) == 0;
	}
	LinkTestCheck(ctx, same, "The frames over vxlan, over geneve and over noise again are those over noise, the text of the golden file", "the texts differ");

	if (texts[0] != NULL)
	{
		Zero(&h, sizeof(h));
		HarnessCompareGolden(&h, out_dir, golden_dir, LINKTEST_GOLDEN, texts[0], update);
		LinkTestCheck(ctx, h.NumFail == 0, "The frames over noise match the golden file " LINKTEST_GOLDEN, "it differs");
	}

	for (UINT g = 0;g < 4;g++)
	{
		Free(texts[g]);
	}
}

// links: the kinds of the links between two nodes, noise, vxlan and geneve
RANZ_TEST_TAGS("links", links_test, "core", "Link kinds: two nodes exchange the same frames of one VRF over noise, vxlan and geneve (golden family link); a datagram from an address that the Controller did not name, or on an unknown VNI, is dropped and counted; each switch of the kind is one Generation, and noise to vxlan under a sender loses no packet.");
void links_test(UINT num, char **arg)
{
	LINKTEST_CTX *ctx = ZeroMalloc(sizeof(LINKTEST_CTX));
	HANDLE done = CreateEventW(NULL, TRUE, FALSE, NULL);
	HANDLE watchdog = (done != NULL ? CreateThread(NULL, 0, LinkTestWatchdog, done, 0, NULL) : NULL);
	TRANSPORT *loopback = TransportLoopbackNew("loopback", 0, false);

	Print("Link kinds test: two nodes exchange the frames of one VRF over noise, vxlan and geneve, and the guard of a plain link drops what the Controller did not name\n");

	ctx->Named = INVALID_SOCKET;
	ctx->Stranger = INVALID_SOCKET;

	if (LinkTestOpen(ctx, loopback))
	{
		LinkTestRun(ctx);
	}

	LinkTestClose(ctx);
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
		Print("LINKS TEST OK\n");
	}
	else
	{
		Print("LINKS TEST FAILED (%u of %u checks failed)\n", ctx->NumFailed, ctx->NumChecks);
	}

	Free(ctx);
}
