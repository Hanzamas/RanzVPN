// vxlantest.c
// Named VXLAN test of vpntest ("vxlan" command, SDN-62 #289)
//
// The VXLAN module of the new core (src/Core/Vxlan.h) on its UDP socket, against four harness VTEPs: UDP sockets of
// this file on 127.0.0.1 that read and write VXLAN datagrams byte for byte, so that the test compares what goes over
// the wire with golden bytes. A frame, untagged and 802.1Q-tagged, goes out on a VNI behind the VXLAN header of RFC
// 7348 and arrives at a harness VTEP as the identical frame, and the datagram of a harness VTEP reaches the receiver of
// the module as the identical frame on its VNI. A frame sent to a flood list of three VTEPs arrives at each of the
// three; the list changes, also during a burst of frames, while the socket and the receive thread of the module keep
// running, and the next frame reaches the new list only. A datagram on a VNI that the module does not carry, or one
// that is no VXLAN datagram, is dropped and counted. Print "VXLAN TEST OK" only when every check passes.

#include "Mayaqua/Kernel.h"
#include "Mayaqua/Memory.h"
#include "Mayaqua/Str.h"
#include "Mayaqua/Tick64.h"

#include "Core/Vxlan.h"

#include <WS2tcpip.h>

#include <stdio.h>

#define	VXLANTEST_BUDGET		60000		// The whole test ends within this time, or the watchdog ends the process (ms)
#define	VXLANTEST_TIMEOUT		5000		// A datagram, a frame or a count arrives within this time (ms)
#define	VXLANTEST_QUIET			300			// A harness VTEP or the receiver that gets nothing gets nothing within this time (ms)
#define	VXLANTEST_POLL			10			// Poll interval of the receiver and the counters of the module (ms)
#define	VXLANTEST_NUM_VTEPS		4			// The harness VTEPs A, B, C and D
#define	VXLANTEST_BURST			200			// The frames of the burst during which the flood list changes
#define	VXLANTEST_BURST_PAUSE	10			// The burst pauses after every this many frames, so that the change meets it halfway
#define	VXLANTEST_RCVBUF		(4 * 1024 * 1024)	// The receive buffer of a harness VTEP: a whole burst fits in it
#define	VXLANTEST_SMALL			60			// An untagged frame of the smallest Ethernet size, without its FCS
#define	VXLANTEST_VNI			5001		// The VNI with the flood list A (0x001389)
#define	VXLANTEST_VNI_FLOOD		5002		// The VNI with the flood list of three VTEPs (0x00138A)
#define	VXLANTEST_VNI_UNKNOWN	7777		// A VNI that the module never carries (0x001E61)

// The VXLAN headers that the module must send (RFC 7348 section 5): the I flag, the reserved bits zero, the VNI in bytes
// 4 to 6
static const UCHAR vxlantest_header[VXLAN_HEADER_SIZE] = {0x08, 0x00, 0x00, 0x00, 0x00, 0x13, 0x89, 0x00};			// VXLANTEST_VNI
static const UCHAR vxlantest_header_flood[VXLAN_HEADER_SIZE] = {0x08, 0x00, 0x00, 0x00, 0x00, 0x13, 0x8A, 0x00};	// VXLANTEST_VNI_FLOOD
static const UCHAR vxlantest_header_max[VXLAN_HEADER_SIZE] = {0x08, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0x00};		// VXLAN_MAX_VNI: all 24 bits

// Headers that a harness VTEP sends: every reserved bit set, which the module ignores; no I flag; a VNI that the module
// does not carry
static const UCHAR vxlantest_header_reserved[VXLAN_HEADER_SIZE] = {0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x13, 0x89, 0xFF};	// VXLANTEST_VNI
static const UCHAR vxlantest_header_no_flag[VXLAN_HEADER_SIZE] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x13, 0x8A, 0x00};	// VXLANTEST_VNI_FLOOD
static const UCHAR vxlantest_header_unknown[VXLAN_HEADER_SIZE] = {0x08, 0x00, 0x00, 0x00, 0x00, 0x1E, 0x61, 0x00};	// VXLANTEST_VNI_UNKNOWN

// A harness VTEP: a UDP socket on 127.0.0.1
typedef struct VXLANTEST_VTEP
{
	char *Name;								// A, B, C or D
	SOCKET Socket;							// The socket
	VXLAN_ADDR Addr;						// Its address, as the module sends to it
} VXLANTEST_VTEP;

// What the receiver of the module took
typedef struct VXLANTEST_RECEIVER
{
	HANDLE Arrived;							// It took a frame (auto-reset)
	SRWLOCK Lock;							// The fields below
	UINT NumFrames;							// Frames taken so far
	UINT Vni;								// The VNI of the last one
	VXLAN_ADDR From;						// ... the VTEP it came from
	UINT Size;								// ... its size
	UCHAR Frame[VXLAN_MAX_FRAME];			// ... and its bytes
} VXLANTEST_RECEIVER;

// The test: its checks, the module on its socket, the harness VTEPs and what the receiver took
typedef struct VXLANTEST_CTX
{
	UINT NumChecks;								// Checks run so far
	UINT NumFailed;								// Checks failed so far
	VXLAN *Vxlan;								// The module
	VXLAN_UDP *Udp;								// ... its socket
	USHORT Port;								// ... and the port of that socket
	VXLANTEST_VTEP Vteps[VXLANTEST_NUM_VTEPS];	// The harness VTEPs A, B, C and D
	VXLANTEST_RECEIVER Receiver;				// What the receiver of the module took
	UCHAR Datagram[VXLAN_MAX_DATAGRAM + 1];		// The datagram that a harness VTEP read or writes
	UCHAR Frame[VXLAN_MAX_FRAME];				// A frame of the test
} VXLANTEST_CTX;

// The burst of frames that a thread of its own sends on VXLANTEST_VNI_FLOOD while the flood list changes
typedef struct VXLANTEST_BURST
{
	VXLAN *Vxlan;							// The module
	volatile LONG NumSent;					// Frames sent so far
	UINT NumFailed;							// ... of them that the module did not send
} VXLANTEST_BURST;

static bool VxlanTestCheck(VXLANTEST_CTX *ctx, bool ok, char *what, char *fmt, ...) RANZ_PRINTF_FORMAT(4, 5);
static bool VxlanTestCheck(VXLANTEST_CTX *ctx, bool ok, char *what, char *fmt, ...)
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
static DWORD WINAPI VxlanTestWatchdog(LPVOID param)
{
	char msg[MAX_SIZE];
	DWORD written = 0;

	if (WaitForSingleObject((HANDLE)param, VXLANTEST_BUDGET) != WAIT_TIMEOUT)
	{
		return 0;
	}

	int len = snprintf(msg, sizeof(msg), "VXLAN TEST FAILED (did not finish within %u ms)\n", VXLANTEST_BUDGET);
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
static void VxlanTestFrame(UCHAR *f, UINT size, bool tagged, UINT seq)
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

//
// The harness VTEPs
//

// Open the harness VTEP t: a UDP socket on 127.0.0.1 and a port that the system picks, with a receive buffer that
// holds a whole burst
static bool VxlanTestOpenVtep(VXLANTEST_VTEP *t, char *name)
{
	struct sockaddr_in sa;
	int sa_size = sizeof(sa);
	int rcvbuf = VXLANTEST_RCVBUF;

	t->Name = name;
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

	VxlanAddrSetV4(&t->Addr, 127, 0, 0, 1, ntohs(sa.sin_port));

	return true;
}

// The next datagram that the harness VTEP t reads within timeout, into the datagram of the test: its size, 0 for none;
// *port is the UDP port it came from
static UINT VxlanTestRead(VXLANTEST_CTX *ctx, VXLANTEST_VTEP *t, UINT timeout, USHORT *port)
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
static void VxlanTestDrain(VXLANTEST_CTX *ctx)
{
	USHORT port = 0;

	for (UINT i = 0;i < VXLANTEST_NUM_VTEPS;i++)
	{
		while (VxlanTestRead(ctx, &ctx->Vteps[i], 0, &port) != 0)
		{
		}
	}
}

// Whether the harness VTEP t reads, within VXLANTEST_TIMEOUT, a datagram from the port of the module that is header
// and then the identical frame of size bytes
static bool VxlanTestGot(VXLANTEST_CTX *ctx, VXLANTEST_VTEP *t, const UCHAR *header, const UCHAR *frame, UINT size)
{
	USHORT port = 0;
	UINT n = VxlanTestRead(ctx, t, VXLANTEST_TIMEOUT, &port);

	return (n == VXLAN_HEADER_SIZE + size && port == ctx->Port && Cmp(ctx->Datagram, header, VXLAN_HEADER_SIZE) == 0 &&
		Cmp(ctx->Datagram + VXLAN_HEADER_SIZE, frame, size) == 0);
}

// Whether the harness VTEP t reads nothing within VXLANTEST_QUIET
static bool VxlanTestNothing(VXLANTEST_CTX *ctx, VXLANTEST_VTEP *t)
{
	USHORT port = 0;

	return (VxlanTestRead(ctx, t, VXLANTEST_QUIET, &port) == 0);
}

// The harness VTEP t sends the module a datagram: header, then size bytes of frame
static bool VxlanTestWrite(VXLANTEST_CTX *ctx, VXLANTEST_VTEP *t, const UCHAR *header, const UCHAR *frame, UINT size)
{
	struct sockaddr_in to;
	UINT len = VXLAN_HEADER_SIZE + size;

	Copy(ctx->Datagram, header, VXLAN_HEADER_SIZE);
	Copy(ctx->Datagram + VXLAN_HEADER_SIZE, frame, size);

	Zero(&to, sizeof(to));
	to.sin_family = AF_INET;
	to.sin_port = htons(ctx->Port);
	to.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

	return (sendto(t->Socket, (char *)ctx->Datagram, (int)len, 0, (struct sockaddr *)&to, sizeof(to)) == (int)len);
}

// Read every datagram of the burst that the harness VTEP t holds, until it reads nothing for VXLANTEST_QUIET, and count
// each frame by its sequence number in seen: false when a datagram is not the golden header and a frame of the burst
static bool VxlanTestTally(VXLANTEST_CTX *ctx, VXLANTEST_VTEP *t, UINT *seen)
{
	UCHAR want[VXLANTEST_SMALL];
	USHORT port = 0;
	bool ok = true;
	UINT n;

	while ((n = VxlanTestRead(ctx, t, VXLANTEST_QUIET, &port)) != 0)
	{
		UINT seq = ((UINT)ctx->Datagram[VXLAN_HEADER_SIZE + 14] << 8) | ctx->Datagram[VXLAN_HEADER_SIZE + 15];

		VxlanTestFrame(want, sizeof(want), false, seq);
		if (n != VXLAN_HEADER_SIZE + sizeof(want) || port != ctx->Port || seq >= VXLANTEST_BURST ||
			Cmp(ctx->Datagram, vxlantest_header_flood, VXLAN_HEADER_SIZE) != 0 || Cmp(ctx->Datagram + VXLAN_HEADER_SIZE, want, sizeof(want)) != 0)
		{
			ok = false;
			continue;
		}

		seen[seq]++;
	}

	return ok;
}

//
// The receiver of the module
//

// The receiver: it keeps the frame that it took last
static void VxlanTestReceive(VXLAN *v, void *param, UINT vni, const VXLAN_ADDR *from, const UCHAR *frame, UINT size)
{
	VXLANTEST_RECEIVER *r = (VXLANTEST_RECEIVER *)param;

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
static UINT VxlanTestForget(VXLANTEST_CTX *ctx)
{
	VXLANTEST_RECEIVER *r = &ctx->Receiver;
	UINT num;

	AcquireSRWLockExclusive(&r->Lock);
	r->Size = 0;
	num = r->NumFrames;
	ReleaseSRWLockExclusive(&r->Lock);

	return num;
}

// Whether the receiver of the module takes, within VXLANTEST_TIMEOUT, the identical frame of size bytes on vni from the
// harness VTEP t
static bool VxlanTestDelivered(VXLANTEST_CTX *ctx, VXLANTEST_VTEP *t, UINT vni, const UCHAR *frame, UINT size)
{
	VXLANTEST_RECEIVER *r = &ctx->Receiver;
	UINT64 end = Tick64() + VXLANTEST_TIMEOUT;

	while (Tick64() < end)
	{
		bool same;

		WaitForSingleObject(r->Arrived, VXLANTEST_POLL);
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

// Whether the module counted at least target datagrams dropped for reason within VXLANTEST_TIMEOUT
static bool VxlanTestDropped(VXLANTEST_CTX *ctx, UINT reason, UINT64 target)
{
	UINT64 end = Tick64() + VXLANTEST_TIMEOUT;

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
		SleepThread(VXLANTEST_POLL);
	}
}

//
// The cases
//

// The module on a UDP socket of its own, and the four harness VTEPs
static bool VxlanTestOpen(VXLANTEST_CTX *ctx)
{
	char *names[VXLANTEST_NUM_VTEPS] = {"A", "B", "C", "D"};
	bool ok = true;

	Print("[the module and the harness VTEPs]\n");

	ctx->Receiver.Arrived = CreateEventW(NULL, FALSE, FALSE, NULL);
	InitializeSRWLock(&ctx->Receiver.Lock);
	for (UINT i = 0;i < VXLANTEST_NUM_VTEPS;i++)
	{
		ctx->Vteps[i].Socket = INVALID_SOCKET;
	}

	ctx->Udp = VxlanUdpNew(0);
	ctx->Vxlan = VxlanNew(VxlanUdpSend, ctx->Udp, VxlanTestReceive, &ctx->Receiver);
	ctx->Port = VxlanUdpPort(ctx->Udp);
	ok = (ctx->Udp != NULL && ctx->Vxlan != NULL && ctx->Receiver.Arrived != NULL && VxlanUdpStart(ctx->Udp, ctx->Vxlan));
	VxlanTestCheck(ctx, ok, "  the module runs on its UDP socket, dual-stack on the wildcard address, with its receive thread", "VxlanUdpNew, VxlanNew or VxlanUdpStart failed");

	for (UINT i = 0;i < VXLANTEST_NUM_VTEPS && ok;i++)
	{
		ok = VxlanTestOpenVtep(&ctx->Vteps[i], names[i]);
	}
	if (VxlanTestCheck(ctx, ok, "  four harness VTEPs A, B, C and D, each a UDP socket on 127.0.0.1", "error %u", (UINT)WSAGetLastError()))
	{
		Print("  [INFO] the module on port %u; A, B, C and D on the ports %u, %u, %u and %u of 127.0.0.1\n", (UINT)ctx->Port,
			(UINT)ctx->Vteps[0].Addr.Port, (UINT)ctx->Vteps[1].Addr.Port, (UINT)ctx->Vteps[2].Addr.Port, (UINT)ctx->Vteps[3].Addr.Port);
	}

	return ok;
}

// A frame on a VNI to one VTEP, untagged and tagged, and a frame back from that VTEP to the receiver of the module
static void VxlanTestOne(VXLANTEST_CTX *ctx)
{
	VXLANTEST_VTEP *a = &ctx->Vteps[0];
	VXLANTEST_VTEP *b = &ctx->Vteps[1];
	VXLAN_STATS before, after;
	UCHAR *f = ctx->Frame;

	Print("[a frame on a VNI, to one VTEP and back]\n");
	VxlanTestDrain(ctx);

	bool set = VxlanSetVni(ctx->Vxlan, VXLANTEST_VNI, &a->Addr, 1) && VxlanSetVni(ctx->Vxlan, VXLAN_MAX_VNI, &a->Addr, 1);
	VxlanTestCheck(ctx, set, "  the module carries VNI 5001 and VNI 16777215, each with the flood list A", "VxlanSetVni failed");

	// Out: the golden VXLAN header, then the identical frame
	VxlanTestFrame(f, VXLANTEST_SMALL, false, 1);
	VxlanTestCheck(ctx, VxlanSend(ctx->Vxlan, VXLANTEST_VNI, f, VXLANTEST_SMALL) && VxlanTestGot(ctx, a, vxlantest_header, f, VXLANTEST_SMALL),
		"  an untagged frame of 60 bytes on VNI 5001: A reads the VXLAN header with the I flag and VNI 5001, then the identical frame", "not within %u ms", VXLANTEST_TIMEOUT);
	VxlanTestFrame(f, VXLANTEST_SMALL + 4, true, 2);
	VxlanTestCheck(ctx, VxlanSend(ctx->Vxlan, VXLANTEST_VNI, f, VXLANTEST_SMALL + 4) && VxlanTestGot(ctx, a, vxlantest_header, f, VXLANTEST_SMALL + 4),
		"  an 802.1Q-tagged frame of 64 bytes (VLAN 10) on VNI 5001: A reads the identical frame, its tag included", "not within %u ms", VXLANTEST_TIMEOUT);
	VxlanTestFrame(f, VXLAN_MAX_FRAME, true, 3);
	VxlanTestCheck(ctx, VxlanSend(ctx->Vxlan, VXLAN_MAX_VNI, f, VXLAN_MAX_FRAME) && VxlanTestGot(ctx, a, vxlantest_header_max, f, VXLAN_MAX_FRAME),
		"  the largest frame, 9208 bytes, on VNI 16777215: A reads all 24 bits of the VNI and the identical frame", "not within %u ms", VXLANTEST_TIMEOUT);

	// To one destination, whether the module carries the VNI or not: a Mirror to its sensor
	VxlanTestFrame(f, VXLANTEST_SMALL, false, 4);
	VxlanTestCheck(ctx, VxlanSendTo(ctx->Vxlan, VXLANTEST_VNI_UNKNOWN, &b->Addr, f, VXLANTEST_SMALL) && VxlanTestGot(ctx, b, vxlantest_header_unknown, f, VXLANTEST_SMALL) && VxlanTestNothing(ctx, a),
		"  a frame on VNI 7777 to the one VTEP B (VxlanSendTo): B reads it, A nothing", "not within %u ms", VXLANTEST_TIMEOUT);

	// What the module does not send
	bool refused = (VxlanSend(ctx->Vxlan, VXLANTEST_VNI, f, VXLAN_MIN_FRAME - 1) == false && VxlanSend(ctx->Vxlan, VXLANTEST_VNI, f, VXLAN_MAX_FRAME + 1) == false &&
		VxlanSend(ctx->Vxlan, VXLANTEST_VNI_UNKNOWN, f, VXLANTEST_SMALL) == false && VxlanSendTo(ctx->Vxlan, VXLAN_MAX_VNI + 1, &b->Addr, f, VXLANTEST_SMALL) == false);
	VxlanTestCheck(ctx, refused && VxlanTestNothing(ctx, a) && VxlanTestNothing(ctx, b),
		"  nothing sent for a frame shorter than an Ethernet header or longer than the largest, a VNI the module does not carry, a VNI of 25 bits", "refused %u", (UINT)refused);

	// Back: the receiver of the module takes the identical frame, on its VNI and from A
	VxlanGetStats(ctx->Vxlan, &before);
	VxlanTestFrame(f, VXLANTEST_SMALL, false, 5);
	VxlanTestForget(ctx);
	VxlanTestCheck(ctx, VxlanTestWrite(ctx, a, vxlantest_header, f, VXLANTEST_SMALL) && VxlanTestDelivered(ctx, a, VXLANTEST_VNI, f, VXLANTEST_SMALL),
		"  A sends an untagged frame on VNI 5001: the receiver of the module takes the identical frame, on VNI 5001 and from A", "not within %u ms", VXLANTEST_TIMEOUT);
	VxlanTestFrame(f, VXLANTEST_SMALL + 4, true, 6);
	VxlanTestForget(ctx);
	VxlanTestCheck(ctx, VxlanTestWrite(ctx, a, vxlantest_header, f, VXLANTEST_SMALL + 4) && VxlanTestDelivered(ctx, a, VXLANTEST_VNI, f, VXLANTEST_SMALL + 4),
		"  A sends an 802.1Q-tagged frame on VNI 5001: the receiver takes the identical frame, its tag included", "not within %u ms", VXLANTEST_TIMEOUT);
	VxlanTestFrame(f, VXLANTEST_SMALL, false, 7);
	VxlanTestForget(ctx);
	VxlanTestCheck(ctx, VxlanTestWrite(ctx, a, vxlantest_header_reserved, f, VXLANTEST_SMALL) && VxlanTestDelivered(ctx, a, VXLANTEST_VNI, f, VXLANTEST_SMALL),
		"  A sends a frame with every reserved bit of the header set: the module ignores them (RFC 7348 section 5) and takes the frame", "not within %u ms", VXLANTEST_TIMEOUT);
	VxlanGetStats(ctx->Vxlan, &after);
	VxlanTestCheck(ctx, after.Delivered == before.Delivered + 3, "  the module counted the three frames as delivered", "%I64u delivered before, %I64u after", before.Delivered, after.Delivered);
}

// The burst: VXLANTEST_BURST frames on VXLANTEST_VNI_FLOOD numbered from 0, with a short pause after every
// VXLANTEST_BURST_PAUSE of them
static void VxlanTestBurstThread(THREAD *thread, void *param)
{
	VXLANTEST_BURST *b = (VXLANTEST_BURST *)param;
	UCHAR frame[VXLANTEST_SMALL];

	for (UINT i = 0;i < VXLANTEST_BURST;i++)
	{
		VxlanTestFrame(frame, sizeof(frame), false, i);
		if (VxlanSend(b->Vxlan, VXLANTEST_VNI_FLOOD, frame, sizeof(frame)) == false)
		{
			b->NumFailed++;
		}
		InterlockedIncrement(&b->NumSent);

		if ((i + 1) % VXLANTEST_BURST_PAUSE == 0)
		{
			SleepThread(1);
		}
	}
}

// A frame to the flood list of three VTEPs, and the list changing while the module runs, also during a burst
static void VxlanTestFlood(VXLANTEST_CTX *ctx)
{
	VXLANTEST_VTEP *a = &ctx->Vteps[0];
	VXLANTEST_VTEP *b = &ctx->Vteps[1];
	VXLANTEST_VTEP *c = &ctx->Vteps[2];
	VXLANTEST_VTEP *d = &ctx->Vteps[3];
	VXLAN_ADDR abc[3], dcbd[4];
	VXLAN_STATS before, after;
	UINT seen[VXLANTEST_NUM_VTEPS][VXLANTEST_BURST];
	UCHAR *f = ctx->Frame;

	Print("[a frame to the flood list of three VTEPs, and the list changing while the module runs]\n");
	VxlanTestDrain(ctx);

	abc[0] = a->Addr;
	abc[1] = b->Addr;
	abc[2] = c->Addr;
	VxlanTestCheck(ctx, VxlanSetVni(ctx->Vxlan, VXLANTEST_VNI_FLOOD, abc, 3), "  the module carries VNI 5002 with the flood list A, B, C", "VxlanSetVni failed");

	// Ingress replication: one datagram to each VTEP of the list
	VxlanGetStats(ctx->Vxlan, &before);
	VxlanTestFrame(f, VXLANTEST_SMALL, false, 10);
	bool sent = VxlanSend(ctx->Vxlan, VXLANTEST_VNI_FLOOD, f, VXLANTEST_SMALL);
	bool got_a = VxlanTestGot(ctx, a, vxlantest_header_flood, f, VXLANTEST_SMALL);
	bool got_b = VxlanTestGot(ctx, b, vxlantest_header_flood, f, VXLANTEST_SMALL);
	bool got_c = VxlanTestGot(ctx, c, vxlantest_header_flood, f, VXLANTEST_SMALL);
	bool none_d = VxlanTestNothing(ctx, d);
	VxlanGetStats(ctx->Vxlan, &after);
	VxlanTestCheck(ctx, sent && got_a && got_b && got_c && none_d && after.Sent == before.Sent + 3,
		"  a frame on VNI 5002 arrives at A, B and C as the identical frame, one datagram each; D, not on the list, reads nothing",
		"sent %u, A %u, B %u, C %u, nothing at D %u, %I64u datagrams", (UINT)sent, (UINT)got_a, (UINT)got_b, (UINT)got_c, (UINT)none_d, after.Sent - before.Sent);

	// The list changes to D, C, B, D (another order, D twice) while a thread sends a burst on VNI 5002: each frame goes to
	// the whole old list or the whole new one
	dcbd[0] = d->Addr;
	dcbd[1] = c->Addr;
	dcbd[2] = b->Addr;
	dcbd[3] = d->Addr;
	VXLANTEST_BURST *burst = ZeroMalloc(sizeof(VXLANTEST_BURST));
	burst->Vxlan = ctx->Vxlan;
	THREAD *thread = NewThread(VxlanTestBurstThread, burst);
	UINT64 end = Tick64() + VXLANTEST_TIMEOUT;
	while (InterlockedCompareExchange(&burst->NumSent, 0, 0) < VXLANTEST_BURST / 4 && Tick64() < end)
	{
		SleepThread(1);
	}
	bool changed = VxlanSetVni(ctx->Vxlan, VXLANTEST_VNI_FLOOD, dcbd, 4);
	UINT at = (UINT)InterlockedCompareExchange(&burst->NumSent, 0, 0);
	WaitThread(thread, INFINITE);
	ReleaseThread(thread);

	Zero(seen, sizeof(seen));
	bool tallied = true;
	for (UINT i = 0;i < VXLANTEST_NUM_VTEPS;i++)
	{
		tallied = VxlanTestTally(ctx, &ctx->Vteps[i], seen[i]) && tallied;
	}

	bool split = true;
	UINT num_a = 0, num_d = 0, last_a = 0, first_d = VXLANTEST_BURST;
	for (UINT i = 0;i < VXLANTEST_BURST;i++)
	{
		// B and C are on both lists, so they read every frame once; A and D read each frame once between them
		if (seen[1][i] != 1 || seen[2][i] != 1 || seen[0][i] + seen[3][i] != 1)
		{
			split = false;
		}
		if (seen[0][i] != 0)
		{
			num_a++;
			last_a = i;
		}
		if (seen[3][i] != 0 && num_d++ == 0)
		{
			first_d = i;
		}
	}
	split = split && (num_a == 0 || num_d == 0 || last_a < first_d);
	VxlanTestCheck(ctx, changed && burst->NumFailed == 0 && tallied && split,
		"  the list changes to D, C, B, D during a burst of 200 frames: B and C read every frame once, A the frames before the change, D the frames after it",
		"changed %u, %u sends failed, tallied %u, %u frames at A, %u at D", (UINT)changed, burst->NumFailed, (UINT)tallied, num_a, num_d);
	Print("  [INFO] the list changed after %u of the %u frames: A read %u of them, D %u\n", at, VXLANTEST_BURST, num_a, num_d);
	Free(burst);

	// The new list: B, C and D, each once
	VxlanTestDrain(ctx);
	VxlanGetStats(ctx->Vxlan, &before);
	VxlanTestFrame(f, VXLANTEST_SMALL, false, 11);
	sent = VxlanSend(ctx->Vxlan, VXLANTEST_VNI_FLOOD, f, VXLANTEST_SMALL);
	got_b = VxlanTestGot(ctx, b, vxlantest_header_flood, f, VXLANTEST_SMALL);
	got_c = VxlanTestGot(ctx, c, vxlantest_header_flood, f, VXLANTEST_SMALL);
	bool got_d = VxlanTestGot(ctx, d, vxlantest_header_flood, f, VXLANTEST_SMALL);
	bool none_a = VxlanTestNothing(ctx, a);
	VxlanGetStats(ctx->Vxlan, &after);
	VxlanTestCheck(ctx, sent && got_b && got_c && got_d && none_a && after.Sent == before.Sent + 3,
		"  the next frame on VNI 5002 arrives at B, C and D, one datagram each (D given twice), and A reads nothing",
		"sent %u, B %u, C %u, D %u, nothing at A %u, %I64u datagrams", (UINT)sent, (UINT)got_b, (UINT)got_c, (UINT)got_d, (UINT)none_a, after.Sent - before.Sent);

	// No restart: the same socket and receive thread, and the other VNIs as they were
	VxlanTestFrame(f, VXLANTEST_SMALL, false, 12);
	VxlanTestForget(ctx);
	bool back = VxlanTestWrite(ctx, d, vxlantest_header_flood, f, VXLANTEST_SMALL) && VxlanTestDelivered(ctx, d, VXLANTEST_VNI_FLOOD, f, VXLANTEST_SMALL);
	VxlanTestFrame(f, VXLANTEST_SMALL, false, 13);
	bool other = VxlanSend(ctx->Vxlan, VXLANTEST_VNI, f, VXLANTEST_SMALL) && VxlanTestGot(ctx, a, vxlantest_header, f, VXLANTEST_SMALL);
	VxlanTestCheck(ctx, VxlanUdpPort(ctx->Udp) == ctx->Port && back && other,
		"  no restart: the module kept its socket on the same port and its receive thread, which takes D's frame on VNI 5002, and VNI 5001 still goes to A",
		"port %u, back %u, VNI 5001 %u", (UINT)VxlanUdpPort(ctx->Udp), (UINT)back, (UINT)other);
}

// Datagrams that the module drops and counts: a VNI that it does not carry, and no VXLAN datagram
static void VxlanTestDrops(VXLANTEST_CTX *ctx)
{
	VXLANTEST_VTEP *a = &ctx->Vteps[0];
	VXLAN_STATS before, after;
	UCHAR *f = ctx->Frame;

	Print("[a datagram on a VNI that the module does not carry]\n");
	VxlanTestDrain(ctx);

	VxlanGetStats(ctx->Vxlan, &before);
	VxlanTestFrame(f, VXLANTEST_SMALL, false, 20);
	UINT frames = VxlanTestForget(ctx);
	bool written = VxlanTestWrite(ctx, a, vxlantest_header_unknown, f, VXLANTEST_SMALL);
	bool dropped = VxlanTestDropped(ctx, VXLAN_DROP_VNI, before.Drops[VXLAN_DROP_VNI] + 1);
	SleepThread(VXLANTEST_QUIET);
	VxlanGetStats(ctx->Vxlan, &after);
	VxlanTestCheck(ctx, written && dropped && after.Drops[VXLAN_DROP_VNI] == before.Drops[VXLAN_DROP_VNI] + 1 && after.Delivered == before.Delivered && VxlanTestForget(ctx) == frames,
		"  A sends a frame on VNI 7777: the module drops it, counts it once as an unknown VNI, and the receiver takes nothing",
		"unknown VNI %I64u before, %I64u after; %I64u delivered before, %I64u after", before.Drops[VXLAN_DROP_VNI], after.Drops[VXLAN_DROP_VNI], before.Delivered, after.Delivered);

	// A VNI that the module no longer carries is unknown too
	VxlanGetStats(ctx->Vxlan, &before);
	bool removed = VxlanDelVni(ctx->Vxlan, VXLANTEST_VNI) && VxlanDelVni(ctx->Vxlan, VXLANTEST_VNI) == false;
	written = VxlanTestWrite(ctx, a, vxlantest_header, f, VXLANTEST_SMALL);
	dropped = VxlanTestDropped(ctx, VXLAN_DROP_VNI, before.Drops[VXLAN_DROP_VNI] + 1);
	VxlanGetStats(ctx->Vxlan, &after);
	VxlanTestCheck(ctx, removed && written && dropped && after.NumVnis + 1 == before.NumVnis && VxlanSend(ctx->Vxlan, VXLANTEST_VNI, f, VXLANTEST_SMALL) == false && VxlanTestNothing(ctx, a),
		"  VNI 5001 no longer carried (VxlanDelVni): A's frame on it is dropped and counted as an unknown VNI, and the module sends nothing on it",
		"removed %u, %u VNIs before, %u after, unknown VNI %I64u before, %I64u after", (UINT)removed, before.NumVnis, after.NumVnis, before.Drops[VXLAN_DROP_VNI], after.Drops[VXLAN_DROP_VNI]);

	Print("[datagrams that are no VXLAN datagrams]\n");

	VxlanGetStats(ctx->Vxlan, &before);
	frames = VxlanTestForget(ctx);
	written = VxlanTestWrite(ctx, a, vxlantest_header_no_flag, f, VXLANTEST_SMALL) && VxlanTestWrite(ctx, a, vxlantest_header_flood, f, VXLAN_MIN_FRAME - 1);
	dropped = VxlanTestDropped(ctx, VXLAN_DROP_MALFORMED, before.Drops[VXLAN_DROP_MALFORMED] + 2);
	SleepThread(VXLANTEST_QUIET);
	VxlanGetStats(ctx->Vxlan, &after);
	VxlanTestCheck(ctx, written && dropped && after.Drops[VXLAN_DROP_MALFORMED] == before.Drops[VXLAN_DROP_MALFORMED] + 2 && after.Drops[VXLAN_DROP_VNI] == before.Drops[VXLAN_DROP_VNI] &&
		after.Delivered == before.Delivered && VxlanTestForget(ctx) == frames,
		"  A sends a frame on VNI 5002 without the I flag, and a datagram one byte short of the header and an Ethernet header: both dropped and counted as malformed",
		"malformed %I64u before, %I64u after; %I64u delivered before, %I64u after", before.Drops[VXLAN_DROP_MALFORMED], after.Drops[VXLAN_DROP_MALFORMED], before.Delivered, after.Delivered);

	VxlanTestCheck(ctx, after.Drops[VXLAN_DROP_SEND] == 0, "  the module failed no send", "%I64u sends failed", after.Drops[VXLAN_DROP_SEND]);
}

// The receive thread first, then the module that it hands the datagrams to, then the harness VTEPs
static void VxlanTestClose(VXLANTEST_CTX *ctx)
{
	VxlanUdpFree(ctx->Udp);
	VxlanFree(ctx->Vxlan);

	for (UINT i = 0;i < VXLANTEST_NUM_VTEPS;i++)
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

void vxlan_test(UINT num, char **arg)
{
	VXLANTEST_CTX *ctx = ZeroMalloc(sizeof(VXLANTEST_CTX));
	HANDLE done = CreateEventW(NULL, TRUE, FALSE, NULL);
	HANDLE watchdog = (done != NULL ? CreateThread(NULL, 0, VxlanTestWatchdog, done, 0, NULL) : NULL);

	Print("VXLAN test: the VXLAN module of the new core against harness VTEPs on 127.0.0.1\n");

	if (VxlanTestOpen(ctx))
	{
		VXLAN_STATS st;

		VxlanTestOne(ctx);
		VxlanTestFlood(ctx);
		VxlanTestDrops(ctx);

		VxlanGetStats(ctx->Vxlan, &st);
		Print("  [INFO] the module: %u VNIs, %I64u datagrams sent, %I64u frames delivered; dropped: %I64u malformed, %I64u on an unknown VNI, %I64u sends\n",
			st.NumVnis, st.Sent, st.Delivered, st.Drops[VXLAN_DROP_MALFORMED], st.Drops[VXLAN_DROP_VNI], st.Drops[VXLAN_DROP_SEND]);
	}

	VxlanTestClose(ctx);

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
		Print("VXLAN TEST OK\n");
	}
	else
	{
		Print("VXLAN TEST FAILED (%u of %u checks failed)\n", ctx->NumFailed, ctx->NumChecks);
	}

	Free(ctx);
}
