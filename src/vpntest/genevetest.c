// genevetest.c
// Named Geneve test of vpntest ("geneve" command, SDN-71 #347)
//
// Geneve (RFC 8926) in the VXLAN module of the new core (src/Core/Vxlan.h): the module on a UDP socket of Geneve, which
// it sends through, and one of VXLAN, against three harness VTEPs, the VTEPs of the vxlan test extended to Geneve: UDP
// sockets of this file on 127.0.0.1 that read and write datagrams byte for byte, so that the test compares what goes
// over the wire with golden bytes. G and H speak Geneve, X speaks VXLAN. A frame, untagged and 802.1Q-tagged, goes out
// on a VNI behind a Geneve header without options and arrives at G as the identical frame; a datagram of G reaches the
// receiver of the module as the identical frame on its VNI, and the module answers G in Geneve. Options of G that are
// not critical are skipped and the frame reaches the receiver without them; a critical option, which the module does
// not know, drops the datagram and is counted, and so does a control message. A datagram on a VNI that the module does
// not carry, or one that is no Geneve datagram, is dropped and counted. One flood list holds G and X: each reads the
// frame in its own encapsulation, and the module takes the datagrams of both on the one VNI, each on its own socket.
// Print "GENEVE TEST OK" only when every check passes.

#include "testlist.h"

#include "Mayaqua/Kernel.h"
#include "Mayaqua/Memory.h"
#include "Mayaqua/Str.h"
#include "Mayaqua/Tick64.h"

#include "Core/Vxlan.h"

#include <WS2tcpip.h>

#include <stdio.h>

#define	GENEVETEST_BUDGET		60000		// The whole test ends within this time, or the watchdog ends the process (ms)
#define	GENEVETEST_TIMEOUT		5000		// A datagram, a frame or a count arrives within this time (ms)
#define	GENEVETEST_QUIET		300			// A harness VTEP or the receiver that gets nothing gets nothing within this time (ms)
#define	GENEVETEST_POLL			10			// Poll interval of the receiver and the counters of the module (ms)
#define	GENEVETEST_NUM_VTEPS	3			// The harness VTEPs G and H, of Geneve, and X, of VXLAN
#define	GENEVETEST_SMALL		60			// An untagged frame of the smallest Ethernet size, without its FCS
#define	GENEVETEST_MAX_OPTIONS	252			// The longest options of a Geneve header: 63 words
#define	GENEVETEST_VNI			6001		// The VNI with the flood list G (0x001771)
#define	GENEVETEST_VNI_MIXED	6002		// The VNI with the flood list G and X (0x001772)
#define	GENEVETEST_VNI_UNKNOWN	7777		// A VNI that the module never carries (0x001E61)

// The Geneve headers that the module must send (RFC 8926 section 3.4): version 0 and no options, neither the O nor the
// C bit, the protocol of an Ethernet frame (0x6558), the VNI in bytes 4 to 6, the reserved bits zero
static const UCHAR genevetest_header[GENEVE_HEADER_SIZE] = {0x00, 0x00, 0x65, 0x58, 0x00, 0x17, 0x71, 0x00};			// GENEVETEST_VNI
static const UCHAR genevetest_header_mixed[GENEVE_HEADER_SIZE] = {0x00, 0x00, 0x65, 0x58, 0x00, 0x17, 0x72, 0x00};	// GENEVETEST_VNI_MIXED
static const UCHAR genevetest_header_max[GENEVE_HEADER_SIZE] = {0x00, 0x00, 0x65, 0x58, 0xFF, 0xFF, 0xFF, 0x00};		// VXLAN_MAX_VNI: all 24 bits
static const UCHAR genevetest_header_unknown[GENEVE_HEADER_SIZE] = {0x00, 0x00, 0x65, 0x58, 0x00, 0x1E, 0x61, 0x00};	// GENEVETEST_VNI_UNKNOWN

// The VXLAN header that X reads and sends on GENEVETEST_VNI_MIXED (RFC 7348 section 5)
static const UCHAR genevetest_vxlan_mixed[VXLAN_HEADER_SIZE] = {0x08, 0x00, 0x00, 0x00, 0x00, 0x17, 0x72, 0x00};

// Headers that G sends on GENEVETEST_VNI, before the options that the test puts behind them: every reserved bit set (the
// six of byte 1 and byte 7), which the module ignores; the C bit, an option is critical; the O bit, a control message;
// version 1; the protocol of IPv4, no Ethernet frame
static const UCHAR genevetest_header_reserved[GENEVE_HEADER_SIZE] = {0x00, 0x3F, 0x65, 0x58, 0x00, 0x17, 0x71, 0xFF};
static const UCHAR genevetest_header_critical[GENEVE_HEADER_SIZE] = {0x00, 0x40, 0x65, 0x58, 0x00, 0x17, 0x71, 0x00};
static const UCHAR genevetest_header_control[GENEVE_HEADER_SIZE] = {0x00, 0x80, 0x65, 0x58, 0x00, 0x17, 0x71, 0x00};
static const UCHAR genevetest_header_version[GENEVE_HEADER_SIZE] = {0x40, 0x00, 0x65, 0x58, 0x00, 0x17, 0x71, 0x00};
static const UCHAR genevetest_header_ipv4[GENEVE_HEADER_SIZE] = {0x00, 0x00, 0x08, 0x00, 0x00, 0x17, 0x71, 0x00};

// Options that G sends (RFC 8926 section 3.5): the class in 2 bytes, the type, whose high bit is the critical bit, then
// 3 reserved bits and the length of the data in words, then the data. Not critical: one of the class of OVN (0x0102)
// with 4 bytes of data, and one of the experimental class 0xFF00 without data and with its reserved bits set, which the
// module ignores. Critical: one of the experimental class 0xFF01, type 0x81, which the module does not know. And one
// whose data, 2 words, is longer than what an option length of 2 words leaves after its header.
static const UCHAR genevetest_opt_ovn[8] = {0x01, 0x02, 0x01, 0x01, 0xDE, 0xAD, 0xBE, 0xEF};
static const UCHAR genevetest_opt_reserved[4] = {0xFF, 0x00, 0x7F, 0xE0};
static const UCHAR genevetest_opt_critical[4] = {0xFF, 0x01, 0x81, 0x00};
static const UCHAR genevetest_opt_long[12] = {0xFF, 0x00, 0x01, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

// A harness VTEP: a UDP socket on 127.0.0.1
typedef struct GENEVETEST_VTEP
{
	char *Name;								// G, H or X
	SOCKET Socket;							// The socket
	VXLAN_ADDR Addr;						// Its address and encapsulation, as the module sends to it
} GENEVETEST_VTEP;

// What the receiver of the module took
typedef struct GENEVETEST_RECEIVER
{
	HANDLE Arrived;							// It took a frame (auto-reset)
	SRWLOCK Lock;							// The fields below
	UINT NumFrames;							// Frames taken so far
	UINT Vni;								// The VNI of the last one
	VXLAN_ADDR From;						// ... the VTEP it came from, with its encapsulation
	UINT Size;								// ... its size
	UCHAR Frame[VXLAN_MAX_FRAME];			// ... and its bytes
} GENEVETEST_RECEIVER;

// The test: its checks, the module on its sockets, the harness VTEPs and what the receiver took
typedef struct GENEVETEST_CTX
{
	UINT NumChecks;									// Checks run so far
	UINT NumFailed;									// Checks failed so far
	VXLAN *Vxlan;									// The module
	VXLAN_UDP *Udp;									// ... its socket of Geneve, which it sends through
	VXLAN_UDP *UdpVxlan;							// ... and its socket of VXLAN
	USHORT Port;									// The port of the socket of Geneve
	USHORT PortVxlan;								// ... and of the socket of VXLAN
	GENEVETEST_VTEP Vteps[GENEVETEST_NUM_VTEPS];	// The harness VTEPs G, H and X
	GENEVETEST_RECEIVER Receiver;					// What the receiver of the module took
	UCHAR Datagram[VXLAN_MAX_DATAGRAM + 1];			// The datagram that a harness VTEP read or writes
	UCHAR Frame[VXLAN_MAX_FRAME];					// A frame of the test
} GENEVETEST_CTX;

static bool GeneveTestCheck(GENEVETEST_CTX *ctx, bool ok, char *what, char *fmt, ...) RANZ_PRINTF_FORMAT(4, 5);
static bool GeneveTestCheck(GENEVETEST_CTX *ctx, bool ok, char *what, char *fmt, ...)
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

// The watchdog: a native thread that ends a run that hangs, so that a lost datagram is a failed test instead of a hung
// CI step
static DWORD WINAPI GeneveTestWatchdog(LPVOID param)
{
	char msg[MAX_SIZE];
	DWORD written = 0;

	if (WaitForSingleObject((HANDLE)param, GENEVETEST_BUDGET) != WAIT_TIMEOUT)
	{
		return 0;
	}

	int len = snprintf(msg, sizeof(msg), "GENEVE TEST FAILED (did not finish within %u ms)\n", GENEVETEST_BUDGET);
	if (len > 0)
	{
		WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), msg, (DWORD)MIN((UINT)len, (UINT)sizeof(msg) - 1), &written, NULL);
	}

	TerminateProcess(GetCurrentProcess(), 1);

	return 0;
}

// A frame of the test, size bytes from 5e:00:00:00:00:01 to 5e:00:00:00:00:02: the EtherType of IPv4, with the 802.1Q
// tag of VLAN 10 before it when tagged, then the sequence number seq in two bytes and bytes that depend on their
// position and seq
static void GeneveTestFrame(UCHAR *f, UINT size, bool tagged, UINT seq)
{
	static const UCHAR dst[6] = {0x5e, 0x00, 0x00, 0x00, 0x00, 0x02};
	static const UCHAR src[6] = {0x5e, 0x00, 0x00, 0x00, 0x00, 0x01};
	UINT pos = 12;

	Copy(f, dst, sizeof(dst));
	Copy(f + 6, src, sizeof(src));
	if (tagged)
	{
		f[pos++] = 0x81;
		f[pos++] = 0x00;
		f[pos++] = 0x00;
		f[pos++] = 0x0A;
	}
	f[pos++] = 0x08;
	f[pos++] = 0x00;
	f[pos++] = (UCHAR)(seq >> 8);
	f[pos++] = (UCHAR)seq;

	for (UINT i = pos;i < size;i++)
	{
		f[i] = (UCHAR)(i * 7 + seq);
	}
}

// A Geneve header that G sends, in h: the fixed header base, with the option length of the size bytes of opts (a
// multiple of 4), then those options. Its size.
static UINT GeneveTestHeader(UCHAR *h, const UCHAR *base, const UCHAR *opts, UINT size)
{
	Copy(h, base, GENEVE_HEADER_SIZE);
	h[0] = (UCHAR)((base[0] & 0xC0) | (size / 4));
	Copy(h + GENEVE_HEADER_SIZE, opts, size);

	return GENEVE_HEADER_SIZE + size;
}

// The sum of the drops of the module, by every reason
static UINT64 GeneveTestNumDrops(const VXLAN_STATS *st)
{
	UINT64 sum = 0;

	for (UINT i = 0;i < VXLAN_NUM_REASONS;i++)
	{
		sum += st->Drops[i];
	}

	return sum;
}

//
// The harness VTEPs
//

// Open the harness VTEP t, which speaks the encapsulation encap: a UDP socket on 127.0.0.1 and a port that the system
// picks
static bool GeneveTestOpenVtep(GENEVETEST_VTEP *t, char *name, USHORT encap)
{
	struct sockaddr_in sa;
	int sa_size = sizeof(sa);

	t->Name = name;
	t->Socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (t->Socket == INVALID_SOCKET)
	{
		return false;
	}

	Zero(&sa, sizeof(sa));
	sa.sin_family = AF_INET;
	sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	if (bind(t->Socket, (struct sockaddr *)&sa, sizeof(sa)) != 0 || getsockname(t->Socket, (struct sockaddr *)&sa, &sa_size) != 0)
	{
		return false;
	}

	VxlanAddrSetV4(&t->Addr, 127, 0, 0, 1, ntohs(sa.sin_port));
	t->Addr.Encap = encap;

	return true;
}

// The next datagram that the harness VTEP t reads within timeout, into the datagram of the test: its size, 0 for none;
// *port is the UDP port it came from
static UINT GeneveTestRead(GENEVETEST_CTX *ctx, GENEVETEST_VTEP *t, UINT timeout, USHORT *port)
{
	WSAPOLLFD p;
	struct sockaddr_in from;
	int from_size = sizeof(from);

	*port = 0;
	Zero(&p, sizeof(p));
	p.fd = t->Socket;
	p.events = POLLRDNORM;
	if (WSAPoll(&p, 1, (INT)timeout) != 1)
	{
		return 0;
	}

	int n = recvfrom(t->Socket, (char *)ctx->Datagram, (int)sizeof(ctx->Datagram), 0, (struct sockaddr *)&from, &from_size);
	if (n <= 0)
	{
		return 0;
	}

	*port = ntohs(from.sin_port);

	return (UINT)n;
}

// Read away what the harness VTEPs still hold
static void GeneveTestDrain(GENEVETEST_CTX *ctx)
{
	USHORT port = 0;

	for (UINT i = 0;i < GENEVETEST_NUM_VTEPS;i++)
	{
		while (GeneveTestRead(ctx, &ctx->Vteps[i], 0, &port) != 0)
		{
		}
	}
}

// Whether the harness VTEP t reads, within GENEVETEST_TIMEOUT, a datagram from the socket of Geneve of the module, which
// it sends through, that is header and then the identical frame of size bytes. The module sends a Geneve header
// without options, GENEVE_HEADER_SIZE bytes, or a VXLAN header, which is as long.
static bool GeneveTestGot(GENEVETEST_CTX *ctx, GENEVETEST_VTEP *t, const UCHAR *header, const UCHAR *frame, UINT size)
{
	USHORT port = 0;
	UINT n = GeneveTestRead(ctx, t, GENEVETEST_TIMEOUT, &port);

	return (n == GENEVE_HEADER_SIZE + size && port == ctx->Port && Cmp(ctx->Datagram, header, GENEVE_HEADER_SIZE) == 0 &&
		Cmp(ctx->Datagram + GENEVE_HEADER_SIZE, frame, size) == 0);
}

// Whether the harness VTEP t reads nothing within GENEVETEST_QUIET
static bool GeneveTestNothing(GENEVETEST_CTX *ctx, GENEVETEST_VTEP *t)
{
	USHORT port = 0;

	return (GeneveTestRead(ctx, t, GENEVETEST_QUIET, &port) == 0);
}

// The harness VTEP t sends a datagram to the socket of the module on port: header, header_size bytes, then size bytes
// of frame
static bool GeneveTestWrite(GENEVETEST_CTX *ctx, GENEVETEST_VTEP *t, USHORT port, const UCHAR *header, UINT header_size, const UCHAR *frame, UINT size)
{
	struct sockaddr_in to;
	UINT len = header_size + size;

	Copy(ctx->Datagram, header, header_size);
	Copy(ctx->Datagram + header_size, frame, size);

	Zero(&to, sizeof(to));
	to.sin_family = AF_INET;
	to.sin_port = htons(port);
	to.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

	return (sendto(t->Socket, (char *)ctx->Datagram, (int)len, 0, (struct sockaddr *)&to, sizeof(to)) == (int)len);
}

//
// The receiver of the module
//

// The receiver: it keeps the frame that it took last
static void GeneveTestReceive(VXLAN *v, void *param, UINT vni, const VXLAN_ADDR *from, const UCHAR *frame, UINT size)
{
	GENEVETEST_RECEIVER *r = (GENEVETEST_RECEIVER *)param;

	AcquireSRWLockExclusive(&r->Lock);
	r->NumFrames++;
	r->Vni = vni;
	r->From = *from;
	r->Size = MIN(size, (UINT)sizeof(r->Frame));
	Copy(r->Frame, frame, r->Size);
	ReleaseSRWLockExclusive(&r->Lock);

	SetEvent(r->Arrived);
}

// Forget the frame that the receiver took last, and give the number of frames it took so far
static UINT GeneveTestForget(GENEVETEST_CTX *ctx)
{
	GENEVETEST_RECEIVER *r = &ctx->Receiver;
	UINT num;

	AcquireSRWLockExclusive(&r->Lock);
	r->Size = 0;
	num = r->NumFrames;
	ReleaseSRWLockExclusive(&r->Lock);

	return num;
}

// Whether the receiver of the module takes, within GENEVETEST_TIMEOUT, the identical frame of size bytes on vni from the
// harness VTEP t, in the encapsulation of t
static bool GeneveTestDelivered(GENEVETEST_CTX *ctx, GENEVETEST_VTEP *t, UINT vni, const UCHAR *frame, UINT size)
{
	GENEVETEST_RECEIVER *r = &ctx->Receiver;
	UINT64 end = Tick64() + GENEVETEST_TIMEOUT;

	while (Tick64() < end)
	{
		bool same;

		WaitForSingleObject(r->Arrived, GENEVETEST_POLL);
		AcquireSRWLockExclusive(&r->Lock);
		same = (r->Size == size && r->Vni == vni && Cmp(&r->From, &t->Addr, sizeof(VXLAN_ADDR)) == 0 && Cmp(r->Frame, frame, size) == 0);
		ReleaseSRWLockExclusive(&r->Lock);
		if (same)
		{
			return true;
		}
	}

	return false;
}

// Whether the module counted at least target datagrams dropped for reason within GENEVETEST_TIMEOUT
static bool GeneveTestDropped(GENEVETEST_CTX *ctx, UINT reason, UINT64 target)
{
	UINT64 end = Tick64() + GENEVETEST_TIMEOUT;

	while (true)
	{
		VXLAN_STATS st;

		VxlanGetStats(ctx->Vxlan, &st);
		if (st.Drops[reason] >= target)
		{
			return true;
		}
		if (Tick64() >= end)
		{
			return false;
		}
		SleepThread(GENEVETEST_POLL);
	}
}

//
// The cases
//

// The module on a UDP socket of Geneve, which it sends through, and one of VXLAN, and the three harness VTEPs
static bool GeneveTestOpen(GENEVETEST_CTX *ctx)
{
	char *names[GENEVETEST_NUM_VTEPS] = {"G", "H", "X"};
	USHORT encaps[GENEVETEST_NUM_VTEPS] = {VXLAN_ENCAP_GENEVE, VXLAN_ENCAP_GENEVE, VXLAN_ENCAP_VXLAN};
	bool ok = true;

	Print("[the module on its sockets of Geneve and VXLAN, and the harness VTEPs]\n");

	ctx->Receiver.Arrived = CreateEventW(NULL, FALSE, FALSE, NULL);
	InitializeSRWLock(&ctx->Receiver.Lock);
	for (UINT i = 0;i < GENEVETEST_NUM_VTEPS;i++)
	{
		ctx->Vteps[i].Socket = INVALID_SOCKET;
	}

	ctx->Udp = VxlanUdpNewGeneve(0);
	ctx->UdpVxlan = VxlanUdpNew(0);
	ctx->Vxlan = VxlanNew(VxlanUdpSend, ctx->Udp, GeneveTestReceive, &ctx->Receiver);
	ctx->Port = VxlanUdpPort(ctx->Udp);
	ctx->PortVxlan = VxlanUdpPort(ctx->UdpVxlan);
	ok = (ctx->Udp != NULL && ctx->UdpVxlan != NULL && ctx->Vxlan != NULL && ctx->Receiver.Arrived != NULL &&
		VxlanUdpStart(ctx->Udp, ctx->Vxlan) && VxlanUdpStart(ctx->UdpVxlan, ctx->Vxlan));
	GeneveTestCheck(ctx, ok, "  the module runs on a socket of Geneve, which it sends through, and one of VXLAN, each with its receive thread", "VxlanUdpNewGeneve, VxlanUdpNew, VxlanNew or VxlanUdpStart failed");

	for (UINT i = 0;i < GENEVETEST_NUM_VTEPS && ok;i++)
	{
		ok = GeneveTestOpenVtep(&ctx->Vteps[i], names[i], encaps[i]);
	}
	if (GeneveTestCheck(ctx, ok, "  three harness VTEPs, each a UDP socket on 127.0.0.1: G and H speak Geneve, X speaks VXLAN", "error %u", (UINT)WSAGetLastError()))
	{
		Print("  [INFO] the module on the ports %u (Geneve) and %u (VXLAN); G, H and X on the ports %u, %u and %u of 127.0.0.1\n", (UINT)ctx->Port,
			(UINT)ctx->PortVxlan, (UINT)ctx->Vteps[0].Addr.Port, (UINT)ctx->Vteps[1].Addr.Port, (UINT)ctx->Vteps[2].Addr.Port);
	}

	return ok;
}

// A frame on a VNI to a VTEP of Geneve, untagged and tagged, a frame back from that VTEP to the receiver of the module,
// and the answer of the module to the VTEP that the receiver names
static void GeneveTestOne(GENEVETEST_CTX *ctx)
{
	GENEVETEST_VTEP *g = &ctx->Vteps[0];
	GENEVETEST_VTEP *h = &ctx->Vteps[1];
	VXLAN_STATS before, after;
	VXLAN_ADDR from;
	UCHAR *f = ctx->Frame;

	Print("[a frame on a VNI, to a VTEP of Geneve and back]\n");
	GeneveTestDrain(ctx);

	bool set = VxlanSetVni(ctx->Vxlan, GENEVETEST_VNI, &g->Addr, 1) && VxlanSetVni(ctx->Vxlan, VXLAN_MAX_VNI, &g->Addr, 1);
	GeneveTestCheck(ctx, set, "  the module carries VNI 6001 and VNI 16777215, each with the flood list G", "VxlanSetVni failed");

	// Out: the golden Geneve header, then the identical frame
	GeneveTestFrame(f, GENEVETEST_SMALL, false, 1);
	GeneveTestCheck(ctx, VxlanSend(ctx->Vxlan, GENEVETEST_VNI, f, GENEVETEST_SMALL) && GeneveTestGot(ctx, g, genevetest_header, f, GENEVETEST_SMALL),
		"  an untagged frame of 60 bytes on VNI 6001: G reads a Geneve header of version 0 without options, the protocol 0x6558 and VNI 6001, then the identical frame", "not within %u ms", GENEVETEST_TIMEOUT);
	GeneveTestFrame(f, GENEVETEST_SMALL + 4, true, 2);
	GeneveTestCheck(ctx, VxlanSend(ctx->Vxlan, GENEVETEST_VNI, f, GENEVETEST_SMALL + 4) && GeneveTestGot(ctx, g, genevetest_header, f, GENEVETEST_SMALL + 4),
		"  an 802.1Q-tagged frame of 64 bytes (VLAN 10) on VNI 6001: G reads the identical frame, its tag included", "not within %u ms", GENEVETEST_TIMEOUT);
	GeneveTestFrame(f, VXLAN_MAX_FRAME, true, 3);
	GeneveTestCheck(ctx, VxlanSend(ctx->Vxlan, VXLAN_MAX_VNI, f, VXLAN_MAX_FRAME) && GeneveTestGot(ctx, g, genevetest_header_max, f, VXLAN_MAX_FRAME),
		"  the largest frame, 9208 bytes, on VNI 16777215: G reads all 24 bits of the VNI and the identical frame", "not within %u ms", GENEVETEST_TIMEOUT);

	// To one VTEP, whether the module carries the VNI or not
	GeneveTestFrame(f, GENEVETEST_SMALL, false, 4);
	GeneveTestCheck(ctx, VxlanSendTo(ctx->Vxlan, GENEVETEST_VNI_UNKNOWN, &h->Addr, f, GENEVETEST_SMALL) && GeneveTestGot(ctx, h, genevetest_header_unknown, f, GENEVETEST_SMALL) && GeneveTestNothing(ctx, g),
		"  a frame on VNI 7777 to the one VTEP H (VxlanSendTo): H reads it behind a Geneve header, G nothing", "not within %u ms", GENEVETEST_TIMEOUT);

	// Back: the receiver of the module takes the identical frame, on its VNI and from G, a VTEP of Geneve
	VxlanGetStats(ctx->Vxlan, &before);
	GeneveTestFrame(f, GENEVETEST_SMALL, false, 5);
	GeneveTestForget(ctx);
	GeneveTestCheck(ctx, GeneveTestWrite(ctx, g, ctx->Port, genevetest_header, GENEVE_HEADER_SIZE, f, GENEVETEST_SMALL) && GeneveTestDelivered(ctx, g, GENEVETEST_VNI, f, GENEVETEST_SMALL),
		"  G sends an untagged frame on VNI 6001: the receiver of the module takes the identical frame, on VNI 6001 and from G, a VTEP of Geneve", "not within %u ms", GENEVETEST_TIMEOUT);
	GeneveTestFrame(f, GENEVETEST_SMALL + 4, true, 6);
	GeneveTestForget(ctx);
	GeneveTestCheck(ctx, GeneveTestWrite(ctx, g, ctx->Port, genevetest_header, GENEVE_HEADER_SIZE, f, GENEVETEST_SMALL + 4) && GeneveTestDelivered(ctx, g, GENEVETEST_VNI, f, GENEVETEST_SMALL + 4),
		"  G sends an 802.1Q-tagged frame on VNI 6001: the receiver takes the identical frame, its tag included", "not within %u ms", GENEVETEST_TIMEOUT);
	GeneveTestFrame(f, GENEVETEST_SMALL, false, 7);
	GeneveTestForget(ctx);
	GeneveTestCheck(ctx, GeneveTestWrite(ctx, g, ctx->Port, genevetest_header_reserved, GENEVE_HEADER_SIZE, f, GENEVETEST_SMALL) && GeneveTestDelivered(ctx, g, GENEVETEST_VNI, f, GENEVETEST_SMALL),
		"  G sends a frame with every reserved bit of the header set: the module ignores them (RFC 8926 section 3.4) and takes the frame", "not within %u ms", GENEVETEST_TIMEOUT);
	VxlanGetStats(ctx->Vxlan, &after);
	GeneveTestCheck(ctx, after.Delivered == before.Delivered + 3, "  the module counted the three frames as delivered", "%I64u delivered before, %I64u after", before.Delivered, after.Delivered);

	// The answer goes to the VTEP that the receiver names, in its encapsulation
	AcquireSRWLockExclusive(&ctx->Receiver.Lock);
	from = ctx->Receiver.From;
	ReleaseSRWLockExclusive(&ctx->Receiver.Lock);
	GeneveTestFrame(f, GENEVETEST_SMALL, false, 8);
	GeneveTestCheck(ctx, from.Encap == VXLAN_ENCAP_GENEVE && VxlanSendTo(ctx->Vxlan, GENEVETEST_VNI, &from, f, GENEVETEST_SMALL) && GeneveTestGot(ctx, g, genevetest_header, f, GENEVETEST_SMALL),
		"  the module answers the VTEP that the receiver names, G, in Geneve: G reads the Geneve header and the identical frame", "encapsulation %u", (UINT)from.Encap);
}

// Options of G: those that are not critical are skipped and the frame reaches the receiver without them; a critical
// option, which the module does not know, drops the datagram and is counted
static void GeneveTestOptions(GENEVETEST_CTX *ctx)
{
	GENEVETEST_VTEP *g = &ctx->Vteps[0];
	VXLAN_STATS before, after;
	UCHAR opts[GENEVETEST_MAX_OPTIONS];
	UCHAR h[GENEVE_HEADER_SIZE + GENEVETEST_MAX_OPTIONS];
	UCHAR *f = ctx->Frame;
	UINT size, n;

	Print("[options that are not critical, and critical options that the module does not know]\n");
	GeneveTestDrain(ctx);

	// OVN's option, the one with its reserved bits set, and the largest that an option holds: class 0x0104, type 5,
	// 124 bytes of data
	Copy(opts, genevetest_opt_ovn, sizeof(genevetest_opt_ovn));
	size = sizeof(genevetest_opt_ovn);
	Copy(opts + size, genevetest_opt_reserved, sizeof(genevetest_opt_reserved));
	size += sizeof(genevetest_opt_reserved);
	opts[size++] = 0x01;
	opts[size++] = 0x04;
	opts[size++] = 0x05;
	opts[size++] = GENEVE_MAX_OPTION_DATA / 4;
	for (UINT i = 0;i < GENEVE_MAX_OPTION_DATA;i++)
	{
		opts[size++] = (UCHAR)(0xA0 + i);
	}

	VxlanGetStats(ctx->Vxlan, &before);
	GeneveTestFrame(f, GENEVETEST_SMALL, false, 30);
	GeneveTestForget(ctx);
	n = GeneveTestHeader(h, genevetest_header, opts, size);
	bool taken = GeneveTestWrite(ctx, g, ctx->Port, h, n, f, GENEVETEST_SMALL) && GeneveTestDelivered(ctx, g, GENEVETEST_VNI, f, GENEVETEST_SMALL);
	VxlanGetStats(ctx->Vxlan, &after);
	GeneveTestCheck(ctx, taken && after.Delivered == before.Delivered + 1 && GeneveTestNumDrops(&after) == GeneveTestNumDrops(&before),
		"  G sends a frame on VNI 6001 behind three options that are not critical, 140 bytes, the largest option and reserved bits among them: the receiver takes the identical frame without them",
		"taken %u, %I64u delivered before, %I64u after", (UINT)taken, before.Delivered, after.Delivered);

	// The longest options: 63 words, as 63 options of the experimental class without data
	for (UINT i = 0;i < GENEVETEST_MAX_OPTIONS / 4;i++)
	{
		opts[i * 4] = 0xFF;
		opts[i * 4 + 1] = 0x00;
		opts[i * 4 + 2] = (UCHAR)i;
		opts[i * 4 + 3] = 0x00;
	}
	GeneveTestFrame(f, GENEVETEST_SMALL, false, 31);
	GeneveTestForget(ctx);
	n = GeneveTestHeader(h, genevetest_header, opts, GENEVETEST_MAX_OPTIONS);
	taken = GeneveTestWrite(ctx, g, ctx->Port, h, n, f, GENEVETEST_SMALL) && GeneveTestDelivered(ctx, g, GENEVETEST_VNI, f, GENEVETEST_SMALL);
	GeneveTestCheck(ctx, taken, "  G sends a frame on VNI 6001 behind the longest options, 63 options that are not critical in 252 bytes: the receiver takes the identical frame", "not within %u ms", GENEVETEST_TIMEOUT);

	// A critical option: alone, with the C bit of the header; after an option that is not critical; and without the C
	// bit, since the critical bit of the option decides (RFC 8926 section 3.5.1)
	VxlanGetStats(ctx->Vxlan, &before);
	GeneveTestFrame(f, GENEVETEST_SMALL, false, 32);
	UINT frames = GeneveTestForget(ctx);
	n = GeneveTestHeader(h, genevetest_header_critical, genevetest_opt_critical, sizeof(genevetest_opt_critical));
	bool written = GeneveTestWrite(ctx, g, ctx->Port, h, n, f, GENEVETEST_SMALL);
	Copy(opts, genevetest_opt_ovn, sizeof(genevetest_opt_ovn));
	Copy(opts + sizeof(genevetest_opt_ovn), genevetest_opt_critical, sizeof(genevetest_opt_critical));
	n = GeneveTestHeader(h, genevetest_header_critical, opts, sizeof(genevetest_opt_ovn) + sizeof(genevetest_opt_critical));
	written = GeneveTestWrite(ctx, g, ctx->Port, h, n, f, GENEVETEST_SMALL) && written;
	n = GeneveTestHeader(h, genevetest_header, genevetest_opt_critical, sizeof(genevetest_opt_critical));
	written = GeneveTestWrite(ctx, g, ctx->Port, h, n, f, GENEVETEST_SMALL) && written;
	bool dropped = GeneveTestDropped(ctx, VXLAN_DROP_CRITICAL, before.Drops[VXLAN_DROP_CRITICAL] + 3);
	SleepThread(GENEVETEST_QUIET);
	VxlanGetStats(ctx->Vxlan, &after);
	GeneveTestCheck(ctx, written && dropped && after.Drops[VXLAN_DROP_CRITICAL] == before.Drops[VXLAN_DROP_CRITICAL] + 3 && GeneveTestNumDrops(&after) == GeneveTestNumDrops(&before) + 3 &&
		after.Delivered == before.Delivered && GeneveTestForget(ctx) == frames,
		"  G sends a frame on VNI 6001 with a critical option that the module does not know, alone, after an option that is not critical, and without the C bit: each is dropped and counted as a critical option, and the receiver takes nothing",
		"critical %I64u before, %I64u after; %I64u delivered before, %I64u after", before.Drops[VXLAN_DROP_CRITICAL], after.Drops[VXLAN_DROP_CRITICAL], before.Delivered, after.Delivered);
}

// Datagrams that the module drops and counts: a VNI that it does not carry, a control message, and datagrams that are
// no Geneve datagrams
static void GeneveTestDrops(GENEVETEST_CTX *ctx)
{
	GENEVETEST_VTEP *g = &ctx->Vteps[0];
	VXLAN_STATS before, after;
	UCHAR h[GENEVE_HEADER_SIZE + GENEVETEST_MAX_OPTIONS];
	UCHAR *f = ctx->Frame;
	UINT n;

	Print("[a datagram on a VNI that the module does not carry, and a control message]\n");
	GeneveTestDrain(ctx);

	VxlanGetStats(ctx->Vxlan, &before);
	GeneveTestFrame(f, GENEVETEST_SMALL, false, 40);
	UINT frames = GeneveTestForget(ctx);
	bool written = GeneveTestWrite(ctx, g, ctx->Port, genevetest_header_unknown, GENEVE_HEADER_SIZE, f, GENEVETEST_SMALL);
	bool dropped = GeneveTestDropped(ctx, VXLAN_DROP_VNI, before.Drops[VXLAN_DROP_VNI] + 1);
	SleepThread(GENEVETEST_QUIET);
	VxlanGetStats(ctx->Vxlan, &after);
	GeneveTestCheck(ctx, written && dropped && after.Drops[VXLAN_DROP_VNI] == before.Drops[VXLAN_DROP_VNI] + 1 && after.Delivered == before.Delivered && GeneveTestForget(ctx) == frames,
		"  G sends a frame on VNI 7777: the module drops it, counts it once as an unknown VNI, and the receiver takes nothing",
		"unknown VNI %I64u before, %I64u after; %I64u delivered before, %I64u after", before.Drops[VXLAN_DROP_VNI], after.Drops[VXLAN_DROP_VNI], before.Delivered, after.Delivered);

	// A control message on a VNI that the module carries: a tunnel endpoint does not forward its payload (RFC 8926
	// section 3.4)
	VxlanGetStats(ctx->Vxlan, &before);
	frames = GeneveTestForget(ctx);
	written = GeneveTestWrite(ctx, g, ctx->Port, genevetest_header_control, GENEVE_HEADER_SIZE, f, GENEVETEST_SMALL);
	dropped = GeneveTestDropped(ctx, VXLAN_DROP_CONTROL, before.Drops[VXLAN_DROP_CONTROL] + 1);
	SleepThread(GENEVETEST_QUIET);
	VxlanGetStats(ctx->Vxlan, &after);
	GeneveTestCheck(ctx, written && dropped && after.Drops[VXLAN_DROP_CONTROL] == before.Drops[VXLAN_DROP_CONTROL] + 1 && after.Delivered == before.Delivered && GeneveTestForget(ctx) == frames,
		"  G sends a control message (the O bit) on VNI 6001: the module drops it, counts it once as a control message, and the receiver takes nothing",
		"control %I64u before, %I64u after; %I64u delivered before, %I64u after", before.Drops[VXLAN_DROP_CONTROL], after.Drops[VXLAN_DROP_CONTROL], before.Delivered, after.Delivered);

	Print("[datagrams that are no Geneve datagrams]\n");

	// Version 1; an option whose data runs past the option length of 2 words; an option length of 63 words in a datagram
	// of 68 bytes; an IPv4 packet behind the protocol 0x0800; a frame one byte short of an Ethernet header; 7 bytes, less
	// than the fixed header
	VxlanGetStats(ctx->Vxlan, &before);
	frames = GeneveTestForget(ctx);
	written = GeneveTestWrite(ctx, g, ctx->Port, genevetest_header_version, GENEVE_HEADER_SIZE, f, GENEVETEST_SMALL);
	n = GeneveTestHeader(h, genevetest_header, genevetest_opt_long, sizeof(genevetest_opt_long));
	h[0] = 2;
	written = GeneveTestWrite(ctx, g, ctx->Port, h, n, f, GENEVETEST_SMALL) && written;
	n = GeneveTestHeader(h, genevetest_header, NULL, 0);
	h[0] = 63;
	written = GeneveTestWrite(ctx, g, ctx->Port, h, n, f, GENEVETEST_SMALL) && written;
	written = GeneveTestWrite(ctx, g, ctx->Port, genevetest_header_ipv4, GENEVE_HEADER_SIZE, f + 14, GENEVETEST_SMALL - 14) && written;
	written = GeneveTestWrite(ctx, g, ctx->Port, genevetest_header, GENEVE_HEADER_SIZE, f, VXLAN_MIN_FRAME - 1) && written;
	written = GeneveTestWrite(ctx, g, ctx->Port, genevetest_header, GENEVE_HEADER_SIZE - 1, f, 0) && written;
	dropped = GeneveTestDropped(ctx, VXLAN_DROP_MALFORMED, before.Drops[VXLAN_DROP_MALFORMED] + 6);
	SleepThread(GENEVETEST_QUIET);
	VxlanGetStats(ctx->Vxlan, &after);
	GeneveTestCheck(ctx, written && dropped && after.Drops[VXLAN_DROP_MALFORMED] == before.Drops[VXLAN_DROP_MALFORMED] + 6 && GeneveTestNumDrops(&after) == GeneveTestNumDrops(&before) + 6 &&
		after.Delivered == before.Delivered && GeneveTestForget(ctx) == frames,
		"  G sends version 1, an option past the option length, an option length past the datagram, an IPv4 packet behind the protocol 0x0800, a frame of 13 bytes and 7 bytes: each dropped and counted as malformed",
		"malformed %I64u before, %I64u after; %I64u delivered before, %I64u after", before.Drops[VXLAN_DROP_MALFORMED], after.Drops[VXLAN_DROP_MALFORMED], before.Delivered, after.Delivered);
}

// One flood list of a VTEP of Geneve and one of VXLAN: each reads the frame in its own encapsulation, and the module
// takes the datagrams of both on the one VNI, each on its own socket
static void GeneveTestMixed(GENEVETEST_CTX *ctx)
{
	GENEVETEST_VTEP *g = &ctx->Vteps[0];
	GENEVETEST_VTEP *h = &ctx->Vteps[1];
	GENEVETEST_VTEP *x = &ctx->Vteps[2];
	VXLAN_ADDR gx[2];
	VXLAN_STATS before, after;
	UCHAR *f = ctx->Frame;

	Print("[one flood list of a VTEP of Geneve and one of VXLAN]\n");
	GeneveTestDrain(ctx);

	gx[0] = g->Addr;
	gx[1] = x->Addr;
	GeneveTestCheck(ctx, VxlanSetVni(ctx->Vxlan, GENEVETEST_VNI_MIXED, gx, 2), "  the module carries VNI 6002 with the flood list G, of Geneve, and X, of VXLAN", "VxlanSetVni failed");

	VxlanGetStats(ctx->Vxlan, &before);
	GeneveTestFrame(f, GENEVETEST_SMALL, false, 50);
	bool sent = VxlanSend(ctx->Vxlan, GENEVETEST_VNI_MIXED, f, GENEVETEST_SMALL);
	bool got_g = GeneveTestGot(ctx, g, genevetest_header_mixed, f, GENEVETEST_SMALL);
	bool got_x = GeneveTestGot(ctx, x, genevetest_vxlan_mixed, f, GENEVETEST_SMALL);
	bool none_h = GeneveTestNothing(ctx, h);
	VxlanGetStats(ctx->Vxlan, &after);
	GeneveTestCheck(ctx, sent && got_g && got_x && none_h && after.Sent == before.Sent + 2,
		"  a frame on VNI 6002 arrives at G behind a Geneve header and at X behind a VXLAN header, as the identical frame, one datagram each; H, not on the list, reads nothing",
		"sent %u, G %u, X %u, nothing at H %u, %I64u datagrams", (UINT)sent, (UINT)got_g, (UINT)got_x, (UINT)none_h, after.Sent - before.Sent);

	// Back on the one VNI: X to the socket of VXLAN, G to the socket of Geneve
	GeneveTestFrame(f, GENEVETEST_SMALL, false, 51);
	GeneveTestForget(ctx);
	bool from_x = GeneveTestWrite(ctx, x, ctx->PortVxlan, genevetest_vxlan_mixed, VXLAN_HEADER_SIZE, f, GENEVETEST_SMALL) && GeneveTestDelivered(ctx, x, GENEVETEST_VNI_MIXED, f, GENEVETEST_SMALL);
	GeneveTestFrame(f, GENEVETEST_SMALL, false, 52);
	GeneveTestForget(ctx);
	bool from_g = GeneveTestWrite(ctx, g, ctx->Port, genevetest_header_mixed, GENEVE_HEADER_SIZE, f, GENEVETEST_SMALL) && GeneveTestDelivered(ctx, g, GENEVETEST_VNI_MIXED, f, GENEVETEST_SMALL);
	GeneveTestCheck(ctx, from_x && from_g,
		"  X sends a VXLAN datagram to the socket of VXLAN and G a Geneve datagram to the socket of Geneve, both on VNI 6002: the receiver takes each frame on VNI 6002, from X and from G in their encapsulations",
		"from X %u, from G %u", (UINT)from_x, (UINT)from_g);

	// The socket decides the encapsulation: a Geneve datagram on the socket of VXLAN is read as VXLAN, without the I flag
	VxlanGetStats(ctx->Vxlan, &before);
	UINT frames = GeneveTestForget(ctx);
	bool written = GeneveTestWrite(ctx, g, ctx->PortVxlan, genevetest_header_mixed, GENEVE_HEADER_SIZE, f, GENEVETEST_SMALL);
	bool dropped = GeneveTestDropped(ctx, VXLAN_DROP_MALFORMED, before.Drops[VXLAN_DROP_MALFORMED] + 1);
	SleepThread(GENEVETEST_QUIET);
	VxlanGetStats(ctx->Vxlan, &after);
	GeneveTestCheck(ctx, written && dropped && after.Drops[VXLAN_DROP_MALFORMED] == before.Drops[VXLAN_DROP_MALFORMED] + 1 && after.Delivered == before.Delivered && GeneveTestForget(ctx) == frames,
		"  G sends its Geneve datagram to the socket of VXLAN, which reads it as VXLAN: no I flag, dropped and counted as malformed",
		"malformed %I64u before, %I64u after; %I64u delivered before, %I64u after", before.Drops[VXLAN_DROP_MALFORMED], after.Drops[VXLAN_DROP_MALFORMED], before.Delivered, after.Delivered);

	GeneveTestCheck(ctx, after.Drops[VXLAN_DROP_SEND] == 0, "  the module failed no send", "%I64u sends failed", after.Drops[VXLAN_DROP_SEND]);
}

// The receive threads first, then the module that they hand the datagrams to, then the harness VTEPs
static void GeneveTestClose(GENEVETEST_CTX *ctx)
{
	VxlanUdpFree(ctx->Udp);
	VxlanUdpFree(ctx->UdpVxlan);
	VxlanFree(ctx->Vxlan);

	for (UINT i = 0;i < GENEVETEST_NUM_VTEPS;i++)
	{
		if (ctx->Vteps[i].Socket != INVALID_SOCKET)
		{
			closesocket(ctx->Vteps[i].Socket);
		}
	}

	if (ctx->Receiver.Arrived != NULL)
	{
		CloseHandle(ctx->Receiver.Arrived);
	}
}

RANZ_TEST_TAGS("geneve", geneve_test, "core", "Geneve in the VXLAN module: a frame goes out as Geneve with its VNI and reaches a harness VTEP identical, and back to the module; options that are not critical are skipped, a critical option and a control message are dropped and counted; a datagram on an unknown VNI is dropped and counted; one flood list holds a VTEP of Geneve and one of VXLAN.");
void geneve_test(UINT num, char **arg)
{
	GENEVETEST_CTX *ctx = ZeroMalloc(sizeof(GENEVETEST_CTX));
	HANDLE done = CreateEventW(NULL, TRUE, FALSE, NULL);
	HANDLE watchdog = (done != NULL ? CreateThread(NULL, 0, GeneveTestWatchdog, done, 0, NULL) : NULL);

	Print("Geneve test: Geneve in the VXLAN module of the new core against harness VTEPs on 127.0.0.1\n");

	if (GeneveTestOpen(ctx))
	{
		VXLAN_STATS st;

		GeneveTestOne(ctx);
		GeneveTestOptions(ctx);
		GeneveTestDrops(ctx);
		GeneveTestMixed(ctx);

		VxlanGetStats(ctx->Vxlan, &st);
		Print("  [INFO] the module: %u VNIs, %I64u datagrams sent, %I64u frames delivered; dropped: %I64u malformed, %I64u on an unknown VNI, %I64u with a critical option, %I64u control messages, %I64u sends\n",
			st.NumVnis, st.Sent, st.Delivered, st.Drops[VXLAN_DROP_MALFORMED], st.Drops[VXLAN_DROP_VNI], st.Drops[VXLAN_DROP_CRITICAL], st.Drops[VXLAN_DROP_CONTROL], st.Drops[VXLAN_DROP_SEND]);
	}

	GeneveTestClose(ctx);

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
		Print("GENEVE TEST OK\n");
	}
	else
	{
		Print("GENEVE TEST FAILED (%u of %u checks failed)\n", ctx->NumFailed, ctx->NumChecks);
	}

	Free(ctx);
}
