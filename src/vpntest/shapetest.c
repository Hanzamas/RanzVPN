// shapetest.c
// Named shaping test of vpntest ("shape" command, SDN-20 #196)
//
// The MTU, the TCP MSS clamp and the rate limits of the overlay of a node (Cedar/NodeShape.c), in process, as seam 2
// of #45 runs the data plane: node-a and node-b share the VRFs red and blue, fake adapters stand in for the Wintun
// adapters of their hosts, the in-process loopback transport carries their Noise session, and the test applies the
// desired states itself (NodeOverlayApply).
// - MTU: in Generation 1 the adapter of red on each node takes the MTU 1280 that a VRF has by default, and the one of
//   blue the 1400 of its override; Generation 2 raises the MTU of red to 1500, and only the adapter of red takes the
//   new MTU.
// - MSS: TCP SYNs and SYN-ACKs of the host of node-a, IPv4 and IPv6, leave with their MSS clamped to the MTU of their
//   VRF less 40 bytes (60 for IPv6) and arrive at the host of node-b so, with a valid checksum; a SYN whose MSS is
//   below that and a segment that is no SYN arrive as they were sent. In Generation 2 the SYNs of red keep the MSS that
//   the MTU 1500 allows.
// - DSCP: packets of every TOS byte (IPv4) and every traffic class (IPv6), and clamped SYNs of DSCP EF, arrive with the
//   DSCP and ECN bits that the host sent: every byte of their IP headers as it was.
// - Rates: with a rate limit of 8 Mbit/s on red, node-a sends red and blue by turns as fast as it can for 1.5 s: red
//   leaves at the configured rate (the burst of its bucket, then 8 Mbit/s), blue loses no packet. With the limit on
//   the node instead, red and blue together leave at that rate. Every packet that the overlay sent arrives at node-b.
// Print "SHAPE TEST OK" only when every check passes.

#include "testlist.h"

#include "Cedar/ConfigStore.h"
#include "Cedar/Node.h"

#include "Mayaqua/Encrypt.h"
#include "Mayaqua/FileIO.h"
#include "Mayaqua/Internat.h"
#include "Mayaqua/IpAddr.h"
#include "Mayaqua/Kernel.h"
#include "Mayaqua/Memory.h"
#include "Mayaqua/Microsoft.h"
#include "Mayaqua/Str.h"
#include "Mayaqua/TcpIp.h"
#include "Mayaqua/Tick64.h"

#include "Core/Control.h"
#include "Core/Transport.h"

#include <stdio.h>

#define	SHAPETEST_BUDGET		300000		// The whole test ends within this time, or the watchdog ends the process (ms)
#define	SHAPETEST_BOUND			10000		// A bounded wait on observable state (ms)
#define	SHAPETEST_POLL			10			// Poll interval of observable state (ms)
#define	SHAPETEST_RATE			8000000		// The rate limit of the rate cases (bits per second)
#define	SHAPETEST_RATE_TIME		1500		// How long node-a sends in a rate case (ms)
#define	SHAPETEST_RATE_PAYLOAD	972			// The UDP data of a packet of the rate cases, 1000 bytes with its headers
#define	SHAPETEST_LOW			90			// The bytes that a rate case sends at least, in percent of what its limit lets through
#define	SHAPETEST_PAYLOAD		16			// The UDP data of a packet of the DSCP case
#define	SHAPETEST_MAX_PACKET	1500		// A packet of the test at most
#define	SHAPETEST_SHOW			5			// Mismatches of the DSCP case that the test prints at most
#define	SHAPETEST_EF			0xB8		// The TOS byte of DSCP EF (46)
#define	SHAPETEST_NS			1000000000ULL

// The VRFs of the test, and their MTUs: red has the default, blue an override
#define	SHAPETEST_RED			0
#define	SHAPETEST_BLUE			1
#define	SHAPETEST_BLUE_MTU		1400
#define	SHAPETEST_RED_MTU2		1500		// The MTU that Generation 2 raises red to

static UINT shapetest_vrf_ids[2] = {101, 202};
static char *shapetest_vrf_names[2] = {"red", "blue"};

// node-a and node-b, and their addresses: [node][vrf][IPv4, IPv6]
static char *shapetest_names[2] = {"node-a", "node-b"};
static char *shapetest_addrs[2][2][2] =
{
	{{"10.0.0.1", "fd00::1"}, {"10.1.0.1", "fd01::1"}},
	{{"10.0.0.2", "fd00::2"}, {"10.1.0.2", "fd01::2"}},
};

// One case of the MSS clamp: a TCP segment of the host of node-a in a VRF, of one family, with its flags and the MSS
// that it asks for, and the MSS that it must arrive with in Generation 1 and in Generation 2
typedef struct SHAPETEST_MSS
{
	UINT Vrf;							// SHAPETEST_RED or SHAPETEST_BLUE
	UINT Family;						// 0 for IPv4, 1 for IPv6
	UCHAR Flags;
	USHORT Mss;
	USHORT Mss1;						// The MSS that it arrives with in Generation 1: red at MTU 1280, blue at 1400
	USHORT Mss2;						// ... and in Generation 2: red at MTU 1500
	char *What;
} SHAPETEST_MSS;

static SHAPETEST_MSS shapetest_mss[] =
{
	{SHAPETEST_RED, 0, TCP_SYN, 1460, 1240, 1460, "a SYN of red, IPv4"},
	{SHAPETEST_RED, 1, TCP_SYN, 1440, 1220, 1440, "a SYN of red, IPv6"},
	{SHAPETEST_BLUE, 0, TCP_SYN, 1460, 1360, 1360, "a SYN of blue, IPv4"},
	{SHAPETEST_BLUE, 1, TCP_SYN, 1440, 1340, 1340, "a SYN of blue, IPv6"},
	{SHAPETEST_BLUE, 0, TCP_SYN | TCP_ACK, 1460, 1360, 1360, "a SYN-ACK of blue, IPv4"},
	{SHAPETEST_RED, 1, TCP_SYN, 9000, 1220, 1440, "a SYN of red asking for a jumbo MSS, IPv6"},
	{SHAPETEST_RED, 0, TCP_SYN, 1200, 1200, 1200, "a SYN of red whose MSS is below the clamp, IPv4"},
	{SHAPETEST_RED, 0, TCP_ACK, 1460, 1460, 1460, "a segment of red that is no SYN, IPv4"},
};

// The checks of the test
typedef struct SHAPETEST_CTX
{
	UINT NumChecks;
	UINT NumFailed;
} SHAPETEST_CTX;

// A packet that the fake adapter of a host took
typedef struct SHAPETEST_PACKET
{
	UINT VrfId;
	UINT Size;
	UCHAR Data[256];
} SHAPETEST_PACKET;

// One node of the test and the fake adapter of its host
typedef struct SHAPETEST_NODE
{
	char *Name;
	wchar_t Dir[MAX_PATH];				// Its data directory
	PEER_KEY Key;						// Its static key
	NODE *Node;
	NODE_READER Reader;					// The test thread as a reader of the node's forwarding tables, online while it sends
	SRWLOCK Lock;						// Packets, Mtu, MtuCalls and MtuOther
	LIST *Packets;						// What the adapter took (SHAPETEST_PACKET), while Counting is 0
	UINT Mtu[2];						// The MTU that the adapter of red and of blue took last
	UINT MtuCalls[2];					// ... and how often it took one
	UINT MtuOther;						// MTUs of other VRFs that it took
	volatile LONG Counting;				// A rate case runs: the adapter counts the bytes of each VRF instead
	volatile LONG64 Bytes[2];			// ... of red and of blue
	volatile LONG64 Other;				// ... and the packets of other VRFs
} SHAPETEST_NODE;

// The sender of a rate case: node-a sends packets in red and in blue by turns, as fast as its overlay takes them
typedef struct SHAPETEST_STREAM
{
	SHAPETEST_NODE *From;
	volatile LONG Stop;					// Ends the sender
	UINT64 Start;						// When it sent its first packet (ns of the performance counter) ...
	UINT64 End;							// ... and when its last send returned
	UINT64 Sent[2];						// Bytes that the overlay sent in red and in blue
	UINT64 Refused[2];					// Packets that it dropped in red and in blue
} SHAPETEST_STREAM;

static bool ShapeTestCheck(SHAPETEST_CTX *ctx, bool ok, char *what, char *fmt, ...) RANZ_PRINTF_FORMAT(4, 5);
static bool ShapeTestCheck(SHAPETEST_CTX *ctx, bool ok, char *what, char *fmt, ...)
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

// The watchdog: a native thread that ends a run that hangs, so that a lost packet is a failed test instead of a hung
// CI step
static DWORD WINAPI ShapeTestWatchdog(LPVOID param)
{
	char msg[MAX_SIZE];
	DWORD written = 0;

	if (WaitForSingleObject((HANDLE)param, SHAPETEST_BUDGET) != WAIT_TIMEOUT)
	{
		return 0;
	}

	int len = snprintf(msg, sizeof(msg), "SHAPE TEST FAILED (did not finish within %u ms)\n", SHAPETEST_BUDGET);
	if (len > 0)
	{
		WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), msg, (DWORD)MIN((UINT)len, (UINT)sizeof(msg) - 1), &written, NULL);
	}

	TerminateProcess(GetCurrentProcess(), 1);

	return 0;
}

// The time of the rate cases: ns of the performance counter, as the shaping of the node counts it
static UINT64 ShapeTestNow()
{
	LARGE_INTEGER counter, freq;

	QueryPerformanceCounter(&counter);
	QueryPerformanceFrequency(&freq);

	UINT64 t = (UINT64)counter.QuadPart, f = MAX((UINT64)freq.QuadPart, 1);

	return (t / f) * SHAPETEST_NS + (t % f) * SHAPETEST_NS / f;
}

// The index of the VRF vrf_id among red and blue, 2 for another VRF
static UINT ShapeTestVrf(UINT vrf_id)
{
	for (UINT v = 0;v < 2;v++)
	{
		if (shapetest_vrf_ids[v] == vrf_id)
		{
			return v;
		}
	}

	return 2;
}

//
// The packets
//

// The address of a text: 4 bytes for IPv4, 16 for IPv6, and their number; 0 for no address
static UINT ShapeTestAddress(UCHAR *addr, char *str)
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

// The IP header of a packet from src to dst, both IPv4 or both IPv6, with the TOS byte or traffic class tos and
// l4_size bytes of the protocol proto after it: its size, 0 when the two are not of one family. An IPv4 header gets
// its checksum.
static UINT ShapeTestIp(UCHAR *buf, char *src, char *dst, UCHAR tos, UCHAR proto, UINT l4_size)
{
	UCHAR s[16], d[16];
	UINT s_size = ShapeTestAddress(s, src), d_size = ShapeTestAddress(d, dst);

	if (s_size == 0 || s_size != d_size)
	{
		return 0;
	}

	if (s_size == 4)
	{
		UINT size = 20 + l4_size;

		Zero(buf, 20);
		buf[0] = 0x45;
		buf[1] = tos;
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

	Zero(buf, 40);
	buf[0] = (UCHAR)(0x60 | (tos >> 4));
	buf[1] = (UCHAR)(tos << 4);
	buf[4] = (UCHAR)(l4_size >> 8);
	buf[5] = (UCHAR)l4_size;
	buf[6] = proto;
	buf[7] = 64;
	Copy(buf + 8, s, 16);
	Copy(buf + 24, d, 16);

	return 40;
}

// The checksum of the TCP or UDP segment of size bytes behind the IP header of hdr bytes of buf, into the field at
// offset field of the segment
static void ShapeTestChecksum(UCHAR *buf, UINT hdr, UCHAR proto, UINT size, UINT field)
{
	UCHAR *l4 = buf + hdr;
	USHORT sum;

	Zero(l4 + field, 2);
	if (hdr == 20)
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

// A UDP datagram from src to dst with the TOS byte or traffic class tos, with payload bytes of data that begin with
// seq: its size, 0 for none
static UINT ShapeTestUdp(UCHAR *buf, char *src, char *dst, UCHAR tos, UINT seq, UINT payload)
{
	UINT len = 8 + payload;
	UINT hdr = ShapeTestIp(buf, src, dst, tos, IP_PROTO_UDP, len);

	if (hdr == 0 || payload < 4 || hdr + len > SHAPETEST_MAX_PACKET)
	{
		return 0;
	}

	UCHAR *udp = buf + hdr;

	Zero(udp, len);
	WRITE_USHORT(udp, 50000);
	WRITE_USHORT(udp + 2, 7);
	WRITE_USHORT(udp + 4, len);
	WRITE_UINT(udp + 8, seq);
	for (UINT i = 12;i < len;i++)
	{
		udp[i] = (UCHAR)('a' + i % 26);
	}
	ShapeTestChecksum(buf, hdr, IP_PROTO_UDP, len, 6);

	return hdr + len;
}

// A TCP segment from src to dst with the TOS byte or traffic class tos and the flags, whose options are the MSS mss,
// two No-Operations and SACK permitted, with a valid checksum: its size, 0 for none
static UINT ShapeTestTcp(UCHAR *buf, char *src, char *dst, UCHAR tos, UCHAR flags, USHORT mss)
{
	UINT len = 20 + 8;
	UINT hdr = ShapeTestIp(buf, src, dst, tos, IP_PROTO_TCP, len);

	if (hdr == 0)
	{
		return 0;
	}

	UCHAR *tcp = buf + hdr;

	Zero(tcp, len);
	WRITE_USHORT(tcp, 50000);
	WRITE_USHORT(tcp + 2, 443);
	WRITE_UINT(tcp + 4, 0x1000);
	WRITE_UINT(tcp + 8, ((flags & TCP_ACK) != 0 ? 0x2000 : 0));
	tcp[12] = (UCHAR)((len / 4) << 4);
	tcp[13] = flags;
	WRITE_USHORT(tcp + 14, 64240);
	tcp[20] = 2;
	tcp[21] = 4;
	WRITE_USHORT(tcp + 22, mss);
	tcp[24] = 1;
	tcp[25] = 1;
	tcp[26] = 4;
	tcp[27] = 2;
	ShapeTestChecksum(buf, hdr, IP_PROTO_TCP, len, 16);

	return hdr + len;
}

// The TCP segment of an MSS case from node-a to node-b, with the MSS mss and the TOS byte tos: its size
static UINT ShapeTestMssPacket(UCHAR *buf, SHAPETEST_MSS *m, USHORT mss, UCHAR tos)
{
	return ShapeTestTcp(buf, shapetest_addrs[0][m->Vrf][m->Family], shapetest_addrs[1][m->Vrf][m->Family], tos, m->Flags, mss);
}

//
// The nodes
//

// A new empty data directory under the temp directory of the process, with a configuration store that runs no role
// on one worker
static void ShapeTestNewDir(wchar_t *dir, UINT size, char *name)
{
	wchar_t tmp[MAX_PATH];
	wchar_t path[MAX_PATH];

	UniFormat(tmp, sizeof(tmp), L"shapetest_%S_%u", name, Rand32());
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
static void ShapeTestDeleteFiles(wchar_t *dir)
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

// The fake adapter of a host: it keeps each packet, or counts the bytes of each VRF while a rate case runs
static void ShapeTestAdapter(NODE *n, void *param, UINT vrf_id, const UCHAR *packet, UINT size)
{
	SHAPETEST_NODE *t = (SHAPETEST_NODE *)param;

	if (InterlockedCompareExchange(&t->Counting, 0, 0) != 0)
	{
		UINT v = ShapeTestVrf(vrf_id);

		if (v < 2)
		{
			InterlockedExchangeAdd64(&t->Bytes[v], size);
		}
		else
		{
			InterlockedIncrement64(&t->Other);
		}
		return;
	}

	SHAPETEST_PACKET *p = ZeroMalloc(sizeof(SHAPETEST_PACKET));
	p->VrfId = vrf_id;
	p->Size = MIN(size, (UINT)sizeof(p->Data));
	Copy(p->Data, packet, p->Size);

	AcquireSRWLockExclusive(&t->Lock);
	Add(t->Packets, p);
	ReleaseSRWLockExclusive(&t->Lock);
}

// The MTU of a VRF for the fake adapter of a host, as the Wintun adapter of the VRF takes it
static void ShapeTestAdapterMtu(NODE *n, void *param, UINT vrf_id, UINT mtu)
{
	SHAPETEST_NODE *t = (SHAPETEST_NODE *)param;
	UINT v = ShapeTestVrf(vrf_id);

	AcquireSRWLockExclusive(&t->Lock);
	if (v < 2)
	{
		t->Mtu[v] = mtu;
		t->MtuCalls[v]++;
	}
	else
	{
		t->MtuOther++;
	}
	ReleaseSRWLockExclusive(&t->Lock);
}

// The packets that the host of t took
static UINT ShapeTestNumPackets(SHAPETEST_NODE *t)
{
	AcquireSRWLockShared(&t->Lock);
	UINT num = LIST_NUM(t->Packets);
	ReleaseSRWLockShared(&t->Lock);

	return num;
}

// Whether the host of t took num packets within SHAPETEST_BOUND
static bool ShapeTestWaitPackets(SHAPETEST_NODE *t, UINT num)
{
	UINT64 end = Tick64() + SHAPETEST_BOUND;

	while (ShapeTestNumPackets(t) < num)
	{
		if (Tick64() >= end)
		{
			return false;
		}
		SleepThread(1);
	}

	return true;
}

// Whether packet index that the host of t took is the one of size bytes at want, in the VRF vrf_id
static bool ShapeTestPacketIs(SHAPETEST_NODE *t, UINT index, UINT vrf_id, UCHAR *want, UINT size)
{
	bool same = false;

	AcquireSRWLockShared(&t->Lock);
	if (index < LIST_NUM(t->Packets))
	{
		SHAPETEST_PACKET *p = LIST_DATA(t->Packets, index);

		same = (p->VrfId == vrf_id && p->Size == size && Cmp(p->Data, want, size) == 0);
	}
	ReleaseSRWLockShared(&t->Lock);

	return same;
}

// The MSS of the TCP segment that the host of t took as packet index, 0 when there is none
static USHORT ShapeTestArrivedMss(SHAPETEST_NODE *t, UINT index)
{
	USHORT mss = 0;

	AcquireSRWLockShared(&t->Lock);
	if (index < LIST_NUM(t->Packets))
	{
		SHAPETEST_PACKET *p = LIST_DATA(t->Packets, index);
		UINT hdr = ((p->Data[0] >> 4) == 4 ? 20 : 40);

		if (p->Size >= hdr + 24)
		{
			mss = READ_USHORT(p->Data + hdr + 22);
		}
	}
	ReleaseSRWLockShared(&t->Lock);

	return mss;
}

// The addresses of node i in red and blue, IPv4 and IPv6, into a: their number
static UINT ShapeTestAddresses(UINT i, CONTROL_ADDRESS *a)
{
	UINT num = 0;

	for (UINT v = 0;v < 2;v++)
	{
		for (UINT f = 0;f < 2;f++)
		{
			CONTROL_ADDRESS *c = &a[num++];

			Zero(c, sizeof(CONTROL_ADDRESS));
			StrCpy(c->Network, sizeof(c->Network), shapetest_vrf_names[v]);
			c->VrfId = shapetest_vrf_ids[v];
			c->AddressSize = ShapeTestAddress(c->Address, shapetest_addrs[i][v][f]);
			c->Length = (c->AddressSize == 4 ? 24 : 64);
		}
	}

	return num;
}

// The desired state of node i at Generation g: VRFs blue (MTU 1400) and red (red_mtu, and the rate limit red_rate),
// the rate limit node_rate of the node, its addresses in both VRFs, and the other node as its peer
static CONTROL_STATE *ShapeTestState(SHAPETEST_NODE *nodes, UINT i, UINT64 g, UINT red_mtu, UINT64 red_rate, UINT64 node_rate)
{
	CONTROL_STATE *st = ZeroMalloc(sizeof(CONTROL_STATE));
	UINT j = 1 - i;

	st->Generation = g;
	StrCpy(st->Name, sizeof(st->Name), shapetest_names[i]);
	st->NumAddresses = ShapeTestAddresses(i, st->Addresses);
	st->RateLimit = node_rate;

	// The VRFs in name order: blue, then red
	st->NumVrfs = 2;
	StrCpy(st->Vrfs[0].Name, sizeof(st->Vrfs[0].Name), shapetest_vrf_names[SHAPETEST_BLUE]);
	st->Vrfs[0].Id = shapetest_vrf_ids[SHAPETEST_BLUE];
	st->Vrfs[0].Mtu = SHAPETEST_BLUE_MTU;
	StrCpy(st->Vrfs[1].Name, sizeof(st->Vrfs[1].Name), shapetest_vrf_names[SHAPETEST_RED]);
	st->Vrfs[1].Id = shapetest_vrf_ids[SHAPETEST_RED];
	st->Vrfs[1].Mtu = red_mtu;
	st->Vrfs[1].RateLimit = red_rate;

	st->Peers = ZeroMalloc(sizeof(CONTROL_PEER));
	st->NumPeers = 1;
	CONTROL_PEER *p = &st->Peers[0];
	StrCpy(p->Name, sizeof(p->Name), shapetest_names[j]);
	Copy(p->Key, nodes[j].Key.Public, PEER_KEY_SIZE);
	p->NumVrfs = 2;
	p->VrfIds[0] = shapetest_vrf_ids[SHAPETEST_RED];
	p->VrfIds[1] = shapetest_vrf_ids[SHAPETEST_BLUE];
	p->NumAddresses = ShapeTestAddresses(j, p->Addresses);

	return st;
}

// Apply the states of Generation g to both nodes
static bool ShapeTestApply(SHAPETEST_NODE *nodes, UINT64 g, UINT red_mtu, UINT64 red_rate, UINT64 node_rate)
{
	bool ok = true;

	for (UINT i = 0;i < 2;i++)
	{
		CONTROL_STATE *st = ShapeTestState(nodes, i, g, red_mtu, red_rate, node_rate);

		ok = NodeOverlayApply(nodes[i].Node, st) && ok;
		Free(st->Peers);
		Free(st);
	}

	return ok;
}

// Whether both nodes have their session to each other within SHAPETEST_BOUND
static bool ShapeTestWaitLink(SHAPETEST_NODE *nodes)
{
	UINT64 end = Tick64() + SHAPETEST_BOUND;

	while (true)
	{
		bool all = true;

		for (UINT i = 0;i < 2;i++)
		{
			NODE_OVERLAY_STATUS st;

			NodeOverlayGetStatus(nodes[i].Node, &st);
			if (st.NumPeers != 1 || st.NumLinks != 1)
			{
				all = false;
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
		SleepThread(SHAPETEST_POLL);
	}
}

// A packet of the host of t in the VRF vrf_id, sent while the test thread is an online reader of the node's tables
static bool ShapeTestInput(SHAPETEST_NODE *t, UINT vrf_id, UCHAR *packet, UINT size)
{
	NodeReaderOnline(t->Node, &t->Reader);
	bool ok = NodeOverlayInput(t->Node, vrf_id, packet, size);
	NodeReaderOffline(&t->Reader);

	return ok;
}

//
// The cases
//

// The MTUs that the adapters of both nodes took, and how often, after Generation g
static void ShapeTestMtu(SHAPETEST_CTX *ctx, SHAPETEST_NODE *nodes, UINT64 g, UINT red_mtu, UINT red_calls)
{
	char what[MAX_SIZE];

	for (UINT i = 0;i < 2;i++)
	{
		SHAPETEST_NODE *t = &nodes[i];

		AcquireSRWLockShared(&t->Lock);
		UINT red = t->Mtu[SHAPETEST_RED], blue = t->Mtu[SHAPETEST_BLUE];
		UINT calls_red = t->MtuCalls[SHAPETEST_RED], calls_blue = t->MtuCalls[SHAPETEST_BLUE], other = t->MtuOther;
		ReleaseSRWLockShared(&t->Lock);

		Print("  %s, generation %I64u: the adapter of red has MTU %u (%u times given), the adapter of blue %u (%u times)\n",
			t->Name, g, red, calls_red, blue, calls_blue);

		Format(what, sizeof(what), "%s, generation %I64u: the adapter of red takes the MTU %u of its VRF, the adapter of blue the override %u, each only when it changed",
			t->Name, g, red_mtu, (UINT)SHAPETEST_BLUE_MTU);
		ShapeTestCheck(ctx, red == red_mtu && blue == SHAPETEST_BLUE_MTU && calls_red == red_calls && calls_blue == 1 && other == 0, what,
			"red %u (%u times), blue %u (%u times), %u of other VRFs", red, calls_red, blue, calls_blue, other);
	}
}

// The MSS cases in Generation 1 or 2: each segment arrives at node-b with the MSS of the case and a valid checksum
static UINT ShapeTestMss(SHAPETEST_CTX *ctx, SHAPETEST_NODE *nodes, UINT generation)
{
	UINT clamped = 0;

	for (UINT k = 0;k < sizeof(shapetest_mss) / sizeof(shapetest_mss[0]);k++)
	{
		SHAPETEST_MSS *m = &shapetest_mss[k];
		UCHAR packet[SHAPETEST_MAX_PACKET], expect[SHAPETEST_MAX_PACKET];
		USHORT mss = (generation == 1 ? m->Mss1 : m->Mss2);
		UINT vrf_id = shapetest_vrf_ids[m->Vrf];
		char what[MAX_SIZE];
		UINT before = ShapeTestNumPackets(&nodes[1]);

		UINT size = ShapeTestMssPacket(packet, m, m->Mss, 0);
		UINT expect_size = ShapeTestMssPacket(expect, m, mss, 0);
		bool sent = ShapeTestInput(&nodes[0], vrf_id, packet, size);
		bool arrived = sent && ShapeTestWaitPackets(&nodes[1], before + 1);
		bool same = arrived && ShapeTestPacketIs(&nodes[1], before, vrf_id, expect, expect_size);

		if (mss != m->Mss)
		{
			clamped++;
		}

		Format(what, sizeof(what), "generation %u: %s with MSS %u leaves node-a and arrives at node-b with MSS %u and a valid checksum",
			generation, m->What, (UINT)m->Mss, (UINT)mss);
		ShapeTestCheck(ctx, same, what, "sent %u, arrived %u, MSS %u", (UINT)sent, (UINT)arrived, (UINT)(arrived ? ShapeTestArrivedMss(&nodes[1], before) : 0));
	}

	return clamped;
}

// The DSCP case: UDP packets of every TOS byte and every traffic class, and SYNs of DSCP EF that the clamp rewrites,
// sent in red; each arrives at node-b with the IP header that the host of node-a gave it
static UINT ShapeTestDscp(SHAPETEST_CTX *ctx, SHAPETEST_NODE *nodes)
{
	UINT vrf_id = shapetest_vrf_ids[SHAPETEST_RED];
	UINT before = ShapeTestNumPackets(&nodes[1]);
	UINT num = 0, wrong = 0, shown = 0, refused = 0;
	UCHAR packet[SHAPETEST_MAX_PACKET], expect[SHAPETEST_MAX_PACKET];

	// 256 IPv4 packets, 256 IPv6 packets, then the two SYNs
	for (UINT k = 0;k < 2 * 256 + 2;k++)
	{
		UINT size;

		if (k < 2 * 256)
		{
			UINT f = k / 256;

			size = ShapeTestUdp(packet, shapetest_addrs[0][SHAPETEST_RED][f], shapetest_addrs[1][SHAPETEST_RED][f], (UCHAR)(k % 256), k, SHAPETEST_PAYLOAD);
		}
		else
		{
			size = ShapeTestMssPacket(packet, &shapetest_mss[k - 2 * 256], 1460, SHAPETEST_EF);
		}

		if (ShapeTestInput(&nodes[0], vrf_id, packet, size) == false)
		{
			refused++;
		}
		num++;
	}

	bool arrived = (refused == 0 && ShapeTestWaitPackets(&nodes[1], before + num));

	for (UINT k = 0;arrived && k < num;k++)
	{
		UINT size;

		if (k < 2 * 256)
		{
			UINT f = k / 256;

			size = ShapeTestUdp(expect, shapetest_addrs[0][SHAPETEST_RED][f], shapetest_addrs[1][SHAPETEST_RED][f], (UCHAR)(k % 256), k, SHAPETEST_PAYLOAD);
		}
		else
		{
			SHAPETEST_MSS *m = &shapetest_mss[k - 2 * 256];

			size = ShapeTestMssPacket(expect, m, m->Mss1, SHAPETEST_EF);
		}

		if (ShapeTestPacketIs(&nodes[1], before + k, vrf_id, expect, size) == false)
		{
			wrong++;
			if (shown < SHAPETEST_SHOW)
			{
				Print("  [INFO] packet %u (TOS or traffic class 0x%02X) did not arrive as expected\n", k, (k < 2 * 256 ? k % 256 : SHAPETEST_EF));
				shown++;
			}
		}
	}

	ShapeTestCheck(ctx, arrived && wrong == 0,
		"DSCP and ECN: 256 IPv4 packets of every TOS byte, 256 IPv6 packets of every traffic class and two SYNs of DSCP EF that the clamp rewrote arrive with the IP header that their host gave them",
		"%u refused, arrived %u, %u wrong", refused, (UINT)arrived, wrong);

	return 2;
}

// The sender of a rate case: packets in red and in blue by turns, each sent as an online reader of node-a with a
// quiescent point after it
static DWORD WINAPI ShapeTestStreamThread(LPVOID param)
{
	SHAPETEST_STREAM *s = (SHAPETEST_STREAM *)param;
	NODE *n = s->From->Node;
	NODE_READER r;
	UCHAR packets[2][SHAPETEST_MAX_PACKET];
	UINT sizes[2];

	for (UINT v = 0;v < 2;v++)
	{
		sizes[v] = ShapeTestUdp(packets[v], shapetest_addrs[0][v][0], shapetest_addrs[1][v][0], 0, v, SHAPETEST_RATE_PAYLOAD);
	}

	Zero(&r, sizeof(r));
	NodeReaderRegister(n, &r);

	s->Start = ShapeTestNow();
	for (UINT64 i = 0;InterlockedCompareExchange(&s->Stop, 0, 0) == 0;i++)
	{
		UINT v = (UINT)(i % 2);

		if (NodeOverlayInput(n, shapetest_vrf_ids[v], packets[v], sizes[v]))
		{
			s->Sent[v] += sizes[v];
		}
		else
		{
			s->Refused[v]++;
		}
		NodeReaderQuiescent(n, &r);
	}
	s->End = ShapeTestNow();

	NodeReaderUnregister(n, &r);

	return 0;
}

// One rate case: node-a sends for SHAPETEST_RATE_TIME, and every byte that its overlay sent arrives at node-b. The
// bytes that a bucket of rate bits per second lets through in the time are its burst and the rate over the time.
static bool ShapeTestStream(SHAPETEST_NODE *nodes, SHAPETEST_STREAM *s)
{
	Zero(s, sizeof(SHAPETEST_STREAM));
	s->From = &nodes[0];
	for (UINT v = 0;v < 2;v++)
	{
		InterlockedExchange64(&nodes[1].Bytes[v], 0);
	}
	InterlockedExchange64(&nodes[1].Other, 0);
	InterlockedExchange(&nodes[1].Counting, 1);

	HANDLE thread = CreateThread(NULL, 0, ShapeTestStreamThread, s, 0, NULL);
	if (thread == NULL)
	{
		InterlockedExchange(&nodes[1].Counting, 0);
		return false;
	}

	SleepThread(SHAPETEST_RATE_TIME);
	InterlockedExchange(&s->Stop, 1);
	WaitForSingleObject(thread, INFINITE);
	CloseHandle(thread);

	UINT64 end = Tick64() + SHAPETEST_BOUND;
	bool all = false;
	while (all == false && Tick64() < end)
	{
		all = ((UINT64)InterlockedCompareExchange64(&nodes[1].Bytes[0], 0, 0) == s->Sent[0] &&
			(UINT64)InterlockedCompareExchange64(&nodes[1].Bytes[1], 0, 0) == s->Sent[1]);
		if (all == false)
		{
			SleepThread(SHAPETEST_POLL);
		}
	}

	InterlockedExchange(&nodes[1].Counting, 0);

	return all && InterlockedCompareExchange64(&nodes[1].Other, 0, 0) == 0;
}

// The bytes that a bucket of rate bits per second lets through from full in ns nanoseconds: its burst, then the rate
static UINT64 ShapeTestAllowed(UINT64 rate, UINT64 ns)
{
	UINT64 burst = MAX(rate / 8 * NODE_SHAPE_BURST / 1000, (UINT64)NODE_SHAPE_MIN_BURST);

	return burst + rate / 8 * ns / SHAPETEST_NS;
}

// The rate cases: the limit of red, then the limit of the node
static UINT64 ShapeTestRates(SHAPETEST_CTX *ctx, SHAPETEST_NODE *nodes)
{
	SHAPETEST_STREAM s;
	char what[MAX_SIZE];
	UINT64 refused = 0;

	Zero(&s, sizeof(s));

	// Generation 3: 8 Mbit/s on red, none on blue and on the node
	bool applied = ShapeTestApply(nodes, 3, SHAPETEST_RED_MTU2, SHAPETEST_RATE, 0);
	bool ok = applied && ShapeTestStream(nodes, &s);
	UINT64 ns = s.End - s.Start;
	UINT64 allowed = ShapeTestAllowed(SHAPETEST_RATE, ns);
	UINT64 low = allowed * SHAPETEST_LOW / 100;
	UINT64 high = allowed + 20 + 8 + SHAPETEST_RATE_PAYLOAD;

	Print("  red limited to %u bit/s, %I64u ms: red %I64u bytes sent (%I64u dropped packets), at most %I64u allowed; blue %I64u bytes sent (%I64u dropped)\n",
		(UINT)SHAPETEST_RATE, ns / 1000000, s.Sent[SHAPETEST_RED], s.Refused[SHAPETEST_RED], allowed, s.Sent[SHAPETEST_BLUE], s.Refused[SHAPETEST_BLUE]);
	refused += s.Refused[0] + s.Refused[1];

	ShapeTestCheck(ctx, ok, "Generation 3 limits red: every byte that node-a sent in red and blue arrives at node-b, in its VRF", "applied %u, ok %u", (UINT)applied, (UINT)ok);
	Format(what, sizeof(what), "Traffic of red above its limit of %u bit/s is shaped to that rate: red leaves with the burst of its bucket and %u bit/s over the time, and the rest is dropped",
		(UINT)SHAPETEST_RATE, (UINT)SHAPETEST_RATE);
	ShapeTestCheck(ctx, ok && s.Sent[SHAPETEST_RED] >= low && s.Sent[SHAPETEST_RED] <= high && s.Refused[SHAPETEST_RED] != 0, what,
		"%I64u bytes in %I64u ms, between %I64u and %I64u expected, %I64u packets dropped", s.Sent[SHAPETEST_RED], ns / 1000000, low, high, s.Refused[SHAPETEST_RED]);
	ShapeTestCheck(ctx, ok && s.Refused[SHAPETEST_BLUE] == 0 && s.Sent[SHAPETEST_BLUE] > s.Sent[SHAPETEST_RED],
		"Blue, which has no limit, loses no packet beside the limited red, and leaves faster",
		"%I64u packets dropped, %I64u bytes sent", s.Refused[SHAPETEST_BLUE], s.Sent[SHAPETEST_BLUE]);

	// Generation 4: 8 Mbit/s on the node, none on the VRFs
	Zero(&s, sizeof(s));
	applied = ShapeTestApply(nodes, 4, SHAPETEST_RED_MTU2, 0, SHAPETEST_RATE);
	ok = applied && ShapeTestStream(nodes, &s);
	ns = s.End - s.Start;
	allowed = ShapeTestAllowed(SHAPETEST_RATE, ns);
	low = allowed * SHAPETEST_LOW / 100;
	high = allowed + 20 + 8 + SHAPETEST_RATE_PAYLOAD;
	UINT64 total = s.Sent[0] + s.Sent[1];

	Print("  node-a limited to %u bit/s, %I64u ms: red %I64u and blue %I64u bytes sent (%I64u dropped packets), at most %I64u allowed\n",
		(UINT)SHAPETEST_RATE, ns / 1000000, s.Sent[SHAPETEST_RED], s.Sent[SHAPETEST_BLUE], s.Refused[0] + s.Refused[1], allowed);
	refused += s.Refused[0] + s.Refused[1];

	ShapeTestCheck(ctx, ok, "Generation 4 limits the node: every byte that node-a sent arrives at node-b, in its VRF", "applied %u, ok %u", (UINT)applied, (UINT)ok);
	Format(what, sizeof(what), "Traffic of the node above its limit of %u bit/s is shaped to that rate: red and blue together leave with the burst of its bucket and %u bit/s over the time",
		(UINT)SHAPETEST_RATE, (UINT)SHAPETEST_RATE);
	ShapeTestCheck(ctx, ok && total >= low && total <= high && s.Refused[0] + s.Refused[1] != 0 && s.Sent[SHAPETEST_RED] != 0 && s.Sent[SHAPETEST_BLUE] != 0, what,
		"%I64u bytes (red %I64u, blue %I64u) in %I64u ms, between %I64u and %I64u expected, %I64u packets dropped", total, s.Sent[SHAPETEST_RED], s.Sent[SHAPETEST_BLUE],
		ns / 1000000, low, high, s.Refused[0] + s.Refused[1]);

	return refused;
}

// shape: the MTU, the MSS clamp, DSCP and the rate limits of the overlay
RANZ_TEST("shape", shape_test, "Shaping of the overlay: the MTU of each VRF on its adapter and an override that raises it, TCP SYNs that leave with the MSS clamped to it, DSCP and ECN through the tunnel unchanged, traffic above the rate limit of a VRF and of the node shaped to that rate.");
void shape_test(UINT num, char **arg)
{
	SHAPETEST_CTX ctx;
	SHAPETEST_NODE *nodes = ZeroMalloc(sizeof(SHAPETEST_NODE) * 2);
	TRANSPORT *loopback = TransportLoopbackNew("loopback", 0, false);
	HANDLE done = CreateEventW(NULL, TRUE, FALSE, NULL);
	HANDLE watchdog = (done != NULL ? CreateThread(NULL, 0, ShapeTestWatchdog, done, 0, NULL) : NULL);
	UCHAR scalar[PEER_KEY_SIZE];
	char what[MAX_SIZE];
	bool started = (loopback != NULL);

	Zero(&ctx, sizeof(ctx));

	Print("Shaping test: the MTU of each VRF on its adapter, the TCP MSS clamp, DSCP through the tunnel and the rate limits of a VRF and of the node\n");

	// The nodes, each with its static key (the scalars 1, 2, ... of the conformance tests) and the fake adapter of its
	// host, and their overlays without a control stream
	for (UINT i = 0;i < 2 && started;i++)
	{
		SHAPETEST_NODE *t = &nodes[i];
		NODE_OVERLAY_CONFIG c;

		t->Name = shapetest_names[i];
		InitializeSRWLock(&t->Lock);
		t->Packets = NewListFast(NULL);
		for (UINT j = 0;j < PEER_KEY_SIZE;j++)
		{
			scalar[j] = (UCHAR)(1 + PEER_KEY_SIZE * i + j);
		}
		started = PeerKeyFromScalar(&t->Key, scalar);

		ShapeTestNewDir(t->Dir, sizeof(t->Dir), t->Name);
		t->Node = NewNode(t->Dir);
		NodeStart(t->Node);
		NodeReaderRegister(t->Node, &t->Reader);
		NodeReaderOffline(&t->Reader);

		Zero(&c, sizeof(c));
		c.Data = loopback;
		c.Key = &t->Key;
		c.Adapter = ShapeTestAdapter;
		c.AdapterMtu = ShapeTestAdapterMtu;
		c.AdapterParam = t;
		Format(what, sizeof(what), "%s: its overlay runs without a control stream", t->Name);
		started = ShapeTestCheck(&ctx, started && NodeOverlayStart(t->Node, &c), what, "NodeOverlayStart failed") && started;
	}
	Zero(scalar, sizeof(scalar));

	if (started)
	{
		// Generation 1: red at the default MTU, blue at its override, no rate limit
		bool applied = ShapeTestApply(nodes, 1, NODE_SHAPE_DEFAULT_MTU, 0, 0);
		bool linked = ShapeTestWaitLink(nodes);
		started = ShapeTestCheck(&ctx, applied && linked, "Both nodes apply Generation 1 of VRFs red and blue, and their session is up", "applied %u, linked %u", (UINT)applied, (UINT)linked);
	}

	if (started)
	{
		ShapeTestMtu(&ctx, nodes, 1, NODE_SHAPE_DEFAULT_MTU, 1);
		UINT clamped = ShapeTestMss(&ctx, nodes, 1);
		clamped += ShapeTestDscp(&ctx, nodes);

		// Generation 2: an override raises the MTU of red
		ShapeTestCheck(&ctx, ShapeTestApply(nodes, 2, SHAPETEST_RED_MTU2, 0, 0), "Both nodes apply Generation 2, which raises the MTU of red to 1500", "not applied");
		ShapeTestMtu(&ctx, nodes, 2, SHAPETEST_RED_MTU2, 2);
		clamped += ShapeTestMss(&ctx, nodes, 2);

		UINT64 refused = ShapeTestRates(&ctx, nodes);
		ShapeTestMtu(&ctx, nodes, 4, SHAPETEST_RED_MTU2, 2);

		NODE_SHAPE_STATUS sa, sb;
		NodeShapeGetStatus(nodes[0].Node, &sa);
		NodeShapeGetStatus(nodes[1].Node, &sb);
		Format(what, sizeof(what), "The counters of node-a: %u SYNs that left with their MSS clamped, each packet that a rate limit dropped; node-b sent nothing", clamped);
		ShapeTestCheck(&ctx, sa.Clamped == clamped && sa.Limited == refused && sb.Clamped == 0 && sb.Limited == 0, what,
			"node-a: %I64u clamped, %I64u limited of %I64u dropped; node-b: %I64u clamped, %I64u limited", sa.Clamped, sa.Limited, refused, sb.Clamped, sb.Limited);
	}

	// The nodes stop, every thread is joined
	for (UINT i = 0;i < 2;i++)
	{
		SHAPETEST_NODE *t = &nodes[i];
		wchar_t log_dir[MAX_PATH];

		if (t->Node != NULL)
		{
			NodeReaderUnregister(t->Node, &t->Reader);
			NodeStop(t->Node);
			FreeNode(t->Node);
			ConbinePathW(log_dir, sizeof(log_dir), t->Dir, NODE_LOG_DIR_NAME);
			ShapeTestDeleteFiles(log_dir);
			ShapeTestDeleteFiles(t->Dir);
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
		Print("SHAPE TEST OK\n");
	}
	else
	{
		Print("SHAPE TEST FAILED (%u of %u checks failed)\n", ctx.NumFailed, ctx.NumChecks);
	}
}
