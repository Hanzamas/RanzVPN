// handshakepooltest.c
// Handshake pool test of vpntest ("handshakepool" command, AUD1-DT-1 #449)
//
// The handshakes of the streams that a node accepts (Cedar/NodeHandshake.c) on the overlay of in-process nodes, as seam 2
// of #45 runs the data plane: fake adapters stand in for the hosts of node-a and node-b, the in-process loopback
// transport carries the Noise session between them, and the test applies their desired states itself
// (NodeOverlayApply). A silent stream is one that the test dials on the loopback transport, whose outer handshake is
// done when the dial returns, and on which it then sends nothing.
// - Forwarding: while 64 silent streams reach node-b, node-a's host sends a packet to node-b's host every
//   HANDSHAKEPOOLTEST_GAP ms, each once the one before arrived, until the handshakes of the silent streams had their
//   time and more. No packet takes longer than HANDSHAKEPOOLTEST_DELAY ms, a fifth of NODE_OVERLAY_HANDSHAKE, to reach
//   node-b's host: the thread of node-b's overlay reads no silent stream. A thread that read one would hold every packet
//   for up to NODE_OVERLAY_HANDSHAKE.
// - Time: each handshake of a silent stream that did not finish in NODE_OVERLAY_HANDSHAKE is closed, so the stream
//   reads its end, and counted in the status of node-b's overlay as timed out; the session of node-a and node-b stays
//   up.
// - Limit: node-c, whose overlay runs at most HANDSHAKEPOOLTEST_MAX handshakes, takes that many of
//   HANDSHAKEPOOLTEST_MAX + HANDSHAKEPOOLTEST_OVER silent streams; the others are refused at the accept, so they read
//   their end at once, and counted. Once those handshakes timed out, a stream whose first frame is no handshake fails
//   at once and is counted as failed.
// Print "HANDSHAKEPOOL TEST OK" only when every check passes.

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

#include <stdio.h>

#define	HANDSHAKEPOOLTEST_BUDGET	120000		// The whole test ends within this time, or the watchdog ends the process (ms)
#define	HANDSHAKEPOOLTEST_BOUND		10000		// A bounded wait on observable state (ms)
#define	HANDSHAKEPOOLTEST_POLL		10			// Poll interval of observable state (ms)
#define	HANDSHAKEPOOLTEST_SILENT	64			// The silent streams to node-b
#define	HANDSHAKEPOOLTEST_DIALS		(NODE_OVERLAY_HANDSHAKE / 2)	// The silent streams are dialled within this time (ms)
#define	HANDSHAKEPOOLTEST_DELAY		(NODE_OVERLAY_HANDSHAKE / 5)	// A packet reaches the other host within this time (ms)
#define	HANDSHAKEPOOLTEST_GAP		20			// ms between a packet that arrived and the next
#define	HANDSHAKEPOOLTEST_SIZE		64			// The size of a test packet
#define	HANDSHAKEPOOLTEST_VRF		101			// The one VRF
#define	HANDSHAKEPOOLTEST_MAX		8			// The handshakes in flight at most of node-c
#define	HANDSHAKEPOOLTEST_OVER		4			// The silent streams to node-c beyond them
#define	HANDSHAKEPOOLTEST_LIMITED	(HANDSHAKEPOOLTEST_MAX + HANDSHAKEPOOLTEST_OVER)

// The nodes: node-a and node-b are peers, node-c has none
#define	HANDSHAKEPOOLTEST_A			0
#define	HANDSHAKEPOOLTEST_B			1
#define	HANDSHAKEPOOLTEST_C			2
#define	HANDSHAKEPOOLTEST_NODES		3

static char *handshakepooltest_names[HANDSHAKEPOOLTEST_NODES] = {"node-a", "node-b", "node-c"};
static char *handshakepooltest_addrs[HANDSHAKEPOOLTEST_NODES] = {"10.0.0.1", "10.0.0.2", "10.0.0.3"};

// One node and the fake adapter of its host
typedef struct HANDSHAKEPOOLTEST_NODE
{
	wchar_t Dir[MAX_PATH];				// Its data directory
	PEER_KEY Key;						// Its static key
	NODE *Node;
	volatile LONG Arrivals;				// Packets that the host took
} HANDSHAKEPOOLTEST_NODE;

// The packets of node-a's host to node-b's host while the silent streams reach node-b
typedef struct HANDSHAKEPOOLTEST_PROBE
{
	HANDSHAKEPOOLTEST_NODE *From;
	HANDSHAKEPOOLTEST_NODE *To;
	volatile bool Halt;					// Ends the probe
	UINT Sent;							// Packets that the overlay took
	UINT Refused;						// ... and that it did not
	UINT Lost;							// Packets that did not arrive within HANDSHAKEPOOLTEST_BOUND
	UINT64 MaxDelay;					// The longest time a packet took to arrive (ms)
} HANDSHAKEPOOLTEST_PROBE;

// The test
typedef struct HANDSHAKEPOOLTEST_CTX
{
	UINT NumChecks;
	UINT NumFailed;
	TRANSPORT *Loopback;
	HANDSHAKEPOOLTEST_NODE Nodes[HANDSHAKEPOOLTEST_NODES];
	TRANSPORT_STREAM *Silent[HANDSHAKEPOOLTEST_SILENT];		// The silent streams to node-b
	TRANSPORT_STREAM *Limited[HANDSHAKEPOOLTEST_LIMITED];	// ... and to node-c
	TRANSPORT_STREAM *Garbage;								// The stream to node-c whose first frame is no handshake
} HANDSHAKEPOOLTEST_CTX;

static bool HandshakePoolTestCheck(HANDSHAKEPOOLTEST_CTX *ctx, bool ok, char *what, char *fmt, ...) RANZ_PRINTF_FORMAT(4, 5);
static bool HandshakePoolTestCheck(HANDSHAKEPOOLTEST_CTX *ctx, bool ok, char *what, char *fmt, ...)
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

// The watchdog: a native thread that ends a run that hangs, so that a stalled overlay is a failed test instead of a
// hung CI step
static DWORD WINAPI HandshakePoolTestWatchdog(LPVOID param)
{
	char msg[MAX_SIZE];
	DWORD written = 0;

	if (WaitForSingleObject((HANDLE)param, HANDSHAKEPOOLTEST_BUDGET) != WAIT_TIMEOUT)
	{
		return 0;
	}

	int len = snprintf(msg, sizeof(msg), "HANDSHAKEPOOL TEST FAILED (did not finish within %u ms)\n", HANDSHAKEPOOLTEST_BUDGET);
	if (len > 0)
	{
		WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), msg, (DWORD)MIN((UINT)len, (UINT)sizeof(msg) - 1), &written, NULL);
	}

	TerminateProcess(GetCurrentProcess(), 1);

	return 0;
}

// The IPv4 address of a text into addr, in network byte order
static void HandshakePoolTestAddress(UCHAR *addr, char *str)
{
	IP ip;

	Zero(addr, 4);
	if (StrToIP(&ip, str) && IsIP4(&ip))
	{
		Copy(addr, IPV4(ip.address), 4);
	}
}

// A UDP packet of HANDSHAKEPOOLTEST_SIZE bytes from node-a's host to node-b's host into buf, its data seq
static UINT HandshakePoolTestPacket(UCHAR *buf, UINT seq)
{
	UINT size = HANDSHAKEPOOLTEST_SIZE;

	Zero(buf, size);
	buf[0] = 0x45;
	WRITE_USHORT(buf + 2, size);
	buf[8] = 64;
	buf[9] = IP_PROTO_UDP;
	HandshakePoolTestAddress(buf + 12, handshakepooltest_addrs[HANDSHAKEPOOLTEST_A]);
	HandshakePoolTestAddress(buf + 16, handshakepooltest_addrs[HANDSHAKEPOOLTEST_B]);
	USHORT sum = IpChecksum(buf, 20);
	Copy(buf + 10, &sum, 2);

	WRITE_USHORT(buf + 20, 5000);
	WRITE_USHORT(buf + 22, 5001);
	WRITE_USHORT(buf + 24, size - 20);
	WRITE_UINT(buf + 28, seq);

	return size;
}

//
// The nodes
//

// A new empty data directory under the temp directory of the process, with a configuration store that runs no role
// on one worker
static void HandshakePoolTestNewDir(wchar_t *dir, UINT size, char *name)
{
	wchar_t tmp[MAX_PATH];
	wchar_t path[MAX_PATH];

	UniFormat(tmp, sizeof(tmp), L"handshakepooltest_%S_%u", name, Rand32());
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
static void HandshakePoolTestDeleteFiles(wchar_t *dir)
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
static void HandshakePoolTestAdapter(NODE *n, void *param, UINT vrf_id, const UCHAR *packet, UINT size)
{
	HANDSHAKEPOOLTEST_NODE *t = (HANDSHAKEPOOLTEST_NODE *)param;

	InterlockedIncrement(&t->Arrivals);
}

// The address of node i in the one VRF into a
static void HandshakePoolTestAddresses(UINT i, CONTROL_ADDRESS *a)
{
	Zero(a, sizeof(CONTROL_ADDRESS));
	StrCpy(a->Network, sizeof(a->Network), "red");
	a->VrfId = HANDSHAKEPOOLTEST_VRF;
	a->AddressSize = 4;
	HandshakePoolTestAddress(a->Address, handshakepooltest_addrs[i]);
	a->Length = 24;
}

// Apply the state of node i at Generation 1: its address, and for node-a and node-b the other as its peer
static bool HandshakePoolTestApply(HANDSHAKEPOOLTEST_CTX *ctx, UINT i)
{
	CONTROL_STATE *st = ZeroMalloc(sizeof(CONTROL_STATE));
	UINT j = (i == HANDSHAKEPOOLTEST_A ? HANDSHAKEPOOLTEST_B : HANDSHAKEPOOLTEST_A);

	st->Generation = 1;
	StrCpy(st->Name, sizeof(st->Name), handshakepooltest_names[i]);
	st->NumAddresses = 1;
	HandshakePoolTestAddresses(i, &st->Addresses[0]);

	st->Peers = ZeroMalloc(sizeof(CONTROL_PEER));
	if (i != HANDSHAKEPOOLTEST_C)
	{
		st->NumPeers = 1;
		StrCpy(st->Peers[0].Name, sizeof(st->Peers[0].Name), handshakepooltest_names[j]);
		Copy(st->Peers[0].Key, ctx->Nodes[j].Key.Public, PEER_KEY_SIZE);
		st->Peers[0].NumVrfs = 1;
		st->Peers[0].VrfIds[0] = HANDSHAKEPOOLTEST_VRF;
		st->Peers[0].NumAddresses = 1;
		HandshakePoolTestAddresses(j, &st->Peers[0].Addresses[0]);
	}

	bool ok = NodeOverlayApply(ctx->Nodes[i].Node, st);

	Free(st->Peers);
	Free(st);

	return ok;
}

// Whether each node has its session to the other within HANDSHAKEPOOLTEST_BOUND
static bool HandshakePoolTestWaitLinks(HANDSHAKEPOOLTEST_CTX *ctx)
{
	UINT64 end = Tick64() + HANDSHAKEPOOLTEST_BOUND;

	while (true)
	{
		NODE_OVERLAY_STATUS a, b;

		NodeOverlayGetStatus(ctx->Nodes[HANDSHAKEPOOLTEST_A].Node, &a);
		NodeOverlayGetStatus(ctx->Nodes[HANDSHAKEPOOLTEST_B].Node, &b);
		if (a.NumLinks == 1 && b.NumLinks == 1)
		{
			return true;
		}
		if (Tick64() >= end)
		{
			return false;
		}
		SleepThread(HANDSHAKEPOOLTEST_POLL);
	}
}

// The probe: node-a's host sends a packet to node-b's host, as a reader of node-a's tables, and waits for it to arrive
// before the next, until Halt
static DWORD WINAPI HandshakePoolTestProbeThread(LPVOID param)
{
	HANDSHAKEPOOLTEST_PROBE *p = (HANDSHAKEPOOLTEST_PROBE *)param;
	UCHAR packet[HANDSHAKEPOOLTEST_SIZE];
	NODE_READER r;

	Zero(&r, sizeof(r));
	NodeReaderRegister(p->From->Node, &r);
	NodeReaderOffline(&r);

	for (UINT seq = 0;p->Halt == false;seq++)
	{
		UINT size = HandshakePoolTestPacket(packet, seq);
		LONG arrivals = InterlockedCompareExchange(&p->To->Arrivals, 0, 0);
		UINT64 start = Tick64();

		// Online only while it sends
		NodeReaderOnline(p->From->Node, &r);
		bool sent = NodeOverlayInput(p->From->Node, HANDSHAKEPOOLTEST_VRF, packet, size);
		NodeReaderOffline(&r);
		if (sent == false)
		{
			p->Refused++;
			SleepThread(HANDSHAKEPOOLTEST_GAP);
			continue;
		}
		p->Sent++;

		// The time that it takes to arrive, or HANDSHAKEPOOLTEST_BOUND for a packet that does not
		while (InterlockedCompareExchange(&p->To->Arrivals, 0, 0) <= arrivals && Tick64() < start + HANDSHAKEPOOLTEST_BOUND)
		{
			SleepThread(1);
		}
		UINT64 delay = Tick64() - start;
		if (InterlockedCompareExchange(&p->To->Arrivals, 0, 0) <= arrivals)
		{
			p->Lost++;
		}
		p->MaxDelay = MAX(p->MaxDelay, delay);

		SleepThread(HANDSHAKEPOOLTEST_GAP);
	}

	NodeReaderUnregister(p->From->Node, &r);

	return 0;
}

// Dial num silent streams to name into streams within HANDSHAKEPOOLTEST_DIALS: a dial that finds the queue of the
// listener full is tried again. The number of the streams.
static UINT HandshakePoolTestDialSilent(HANDSHAKEPOOLTEST_CTX *ctx, char *name, TRANSPORT_STREAM **streams, UINT num)
{
	UINT64 end = Tick64() + HANDSHAKEPOOLTEST_DIALS;
	UINT ret = 0;

	while (ret < num && Tick64() < end)
	{
		streams[ret] = TransportDial(ctx->Loopback, name, NULL);
		if (streams[ret] != NULL)
		{
			ret++;
		}
		else
		{
			SleepThread(1);
		}
	}

	return ret;
}

//
// The cases
//

// The forwarding of the session between node-a and node-b while 64 silent streams reach node-b
static void HandshakePoolTestForwarding(HANDSHAKEPOOLTEST_CTX *ctx)
{
	HANDSHAKEPOOLTEST_PROBE p;
	char what[MAX_SIZE];

	Print("[the forwarding while %u silent streams reach node-b]\n", HANDSHAKEPOOLTEST_SILENT);

	Zero(&p, sizeof(p));
	p.From = &ctx->Nodes[HANDSHAKEPOOLTEST_A];
	p.To = &ctx->Nodes[HANDSHAKEPOOLTEST_B];

	HANDLE thread = CreateThread(NULL, 0, HandshakePoolTestProbeThread, &p, 0, NULL);
	if (HandshakePoolTestCheck(ctx, thread != NULL, "  the probe starts", "CreateThread failed") == false)
	{
		return;
	}

	// The probe runs alone first, then while the silent streams wait for their handshakes, until they had their time
	SleepThread(HANDSHAKEPOOLTEST_DELAY);
	UINT64 start = Tick64();
	UINT num = HandshakePoolTestDialSilent(ctx, handshakepooltest_names[HANDSHAKEPOOLTEST_B], ctx->Silent, HANDSHAKEPOOLTEST_SILENT);
	UINT64 dialled = Tick64() - start;
	SleepThread(NODE_OVERLAY_HANDSHAKE + HANDSHAKEPOOLTEST_DELAY);

	p.Halt = true;
	WaitForSingleObject(thread, INFINITE);
	CloseHandle(thread);

	Print("  [INFO] %u silent streams dialled in %I64u ms; %u packets sent, %u refused, %u lost, the longest took %I64u ms\n",
		num, dialled, p.Sent, p.Refused, p.Lost, p.MaxDelay);

	Format(what, sizeof(what), "  %u silent streams reach node-b within %u ms", HANDSHAKEPOOLTEST_SILENT, HANDSHAKEPOOLTEST_DIALS);
	HandshakePoolTestCheck(ctx, num == HANDSHAKEPOOLTEST_SILENT, what, "%u of them", num);
	Format(what, sizeof(what), "  every packet of node-a's host reaches node-b's host within %u ms, a fifth of the %u ms of a handshake", HANDSHAKEPOOLTEST_DELAY, NODE_OVERLAY_HANDSHAKE);
	HandshakePoolTestCheck(ctx, p.Sent >= 10 && p.Refused == 0 && p.Lost == 0 && p.MaxDelay <= HANDSHAKEPOOLTEST_DELAY, what,
		"%u sent, %u refused, %u lost, the longest took %I64u ms", p.Sent, p.Refused, p.Lost, p.MaxDelay);
}

// The status of the overlay of node i once done says so, or once HANDSHAKEPOOLTEST_BOUND passed, into st
typedef bool (HANDSHAKEPOOLTEST_DONE)(const NODE_OVERLAY_STATUS *st, UINT64 want);
static void HandshakePoolTestWait(HANDSHAKEPOOLTEST_CTX *ctx, UINT i, HANDSHAKEPOOLTEST_DONE *done, UINT64 want, NODE_OVERLAY_STATUS *st)
{
	UINT64 end = Tick64() + HANDSHAKEPOOLTEST_BOUND;

	while (true)
	{
		NodeOverlayGetStatus(ctx->Nodes[i].Node, st);
		if (done(st, want) || Tick64() >= end)
		{
			return;
		}
		SleepThread(HANDSHAKEPOOLTEST_POLL);
	}
}

static bool HandshakePoolTestTimedOut(const NODE_OVERLAY_STATUS *st, UINT64 want)
{
	return (st->HandshakesTimedOut >= want);
}

static bool HandshakePoolTestTaken(const NODE_OVERLAY_STATUS *st, UINT64 want)
{
	return (st->HandshakesInFlight + st->HandshakesRefused >= want);
}

static bool HandshakePoolTestFailed(const NODE_OVERLAY_STATUS *st, UINT64 want)
{
	return (st->HandshakesFailed >= want);
}

// The streams of num that read their end at once: the node closed them
static UINT HandshakePoolTestEnded(TRANSPORT_STREAM **streams, UINT num)
{
	UINT ret = 0;

	for (UINT i = 0;i < num;i++)
	{
		UCHAR c;

		if (streams[i] != NULL && TransportRead(streams[i], &c, 1, 0) == 0)
		{
			ret++;
		}
	}

	return ret;
}

// The handshakes of the silent streams to node-b timed out: closed and counted, and the session stays up
static void HandshakePoolTestTime(HANDSHAKEPOOLTEST_CTX *ctx)
{
	NODE_OVERLAY_STATUS st;
	char what[MAX_SIZE];

	Print("[the handshakes that do not finish in their time]\n");

	HandshakePoolTestWait(ctx, HANDSHAKEPOOLTEST_B, HandshakePoolTestTimedOut, HANDSHAKEPOOLTEST_SILENT, &st);
	UINT ended = HandshakePoolTestEnded(ctx->Silent, HANDSHAKEPOOLTEST_SILENT);

	Format(what, sizeof(what), "  node-b counts the %u handshakes as timed out, none failed or refused, none in flight, and each silent stream reads its end", HANDSHAKEPOOLTEST_SILENT);
	HandshakePoolTestCheck(ctx, st.HandshakesTimedOut == HANDSHAKEPOOLTEST_SILENT && st.HandshakesFailed == 0 && st.HandshakesRefused == 0 && st.HandshakesInFlight == 0 && ended == HANDSHAKEPOOLTEST_SILENT, what,
		"%I64u timed out, %I64u failed, %I64u refused, %u in flight, %u streams ended", st.HandshakesTimedOut, st.HandshakesFailed, st.HandshakesRefused, st.HandshakesInFlight, ended);
	HandshakePoolTestCheck(ctx, st.NumLinks == 1, "  the session of node-b to node-a stays up", "%u links", st.NumLinks);
}

// node-c runs at most HANDSHAKEPOOLTEST_MAX handshakes: the streams after them are refused at the accept and counted
static void HandshakePoolTestLimit(HANDSHAKEPOOLTEST_CTX *ctx)
{
	NODE_OVERLAY_STATUS st;
	char what[MAX_SIZE];
	UCHAR frame[4];

	Print("[the limit of the handshakes in flight]\n");

	UINT num = HandshakePoolTestDialSilent(ctx, handshakepooltest_names[HANDSHAKEPOOLTEST_C], ctx->Limited, HANDSHAKEPOOLTEST_LIMITED);
	HandshakePoolTestWait(ctx, HANDSHAKEPOOLTEST_C, HandshakePoolTestTaken, HANDSHAKEPOOLTEST_LIMITED, &st);
	UINT ended = HandshakePoolTestEnded(ctx->Limited, num);

	Format(what, sizeof(what), "  of %u silent streams to node-c, %u are in flight, its limit, and %u are refused at the accept and read their end",
		HANDSHAKEPOOLTEST_LIMITED, HANDSHAKEPOOLTEST_MAX, HANDSHAKEPOOLTEST_OVER);
	HandshakePoolTestCheck(ctx, num == HANDSHAKEPOOLTEST_LIMITED && st.MaxHandshakes == HANDSHAKEPOOLTEST_MAX && st.HandshakesInFlight == HANDSHAKEPOOLTEST_MAX && st.HandshakesRefused == HANDSHAKEPOOLTEST_OVER && ended == HANDSHAKEPOOLTEST_OVER, what,
		"%u dialled, limit %u, %u in flight, %I64u refused, %u streams ended", num, st.MaxHandshakes, st.HandshakesInFlight, st.HandshakesRefused, ended);

	HandshakePoolTestWait(ctx, HANDSHAKEPOOLTEST_C, HandshakePoolTestTimedOut, HANDSHAKEPOOLTEST_MAX, &st);
	HandshakePoolTestCheck(ctx, st.HandshakesTimedOut == HANDSHAKEPOOLTEST_MAX && st.HandshakesInFlight == 0, "  the handshakes in flight time out, and none is in flight any more",
		"%I64u timed out, %u in flight", st.HandshakesTimedOut, st.HandshakesInFlight);

	// A frame of no bytes is no handshake
	Zero(frame, sizeof(frame));
	UINT got = HandshakePoolTestDialSilent(ctx, handshakepooltest_names[HANDSHAKEPOOLTEST_C], &ctx->Garbage, 1);
	bool written = (got == 1 && TransportWrite(ctx->Garbage, frame, sizeof(frame)));
	HandshakePoolTestWait(ctx, HANDSHAKEPOOLTEST_C, HandshakePoolTestFailed, 1, &st);
	HandshakePoolTestCheck(ctx, written && st.HandshakesFailed == 1 && st.HandshakesTimedOut == HANDSHAKEPOOLTEST_MAX && st.HandshakesRefused == HANDSHAKEPOOLTEST_OVER,
		"  a stream whose first frame is no handshake is counted as failed, and nothing else changes",
		"written %u, %I64u failed, %I64u timed out, %I64u refused", (UINT)written, st.HandshakesFailed, st.HandshakesTimedOut, st.HandshakesRefused);
}

// The nodes and their overlays, and the session between them
static bool HandshakePoolTestOpen(HANDSHAKEPOOLTEST_CTX *ctx)
{
	UCHAR scalar[PEER_KEY_SIZE];
	char what[MAX_SIZE];
	bool ok = (ctx->Loopback != NULL);

	Print("[the nodes and their overlays]\n");

	for (UINT i = 0;i < HANDSHAKEPOOLTEST_NODES && ok;i++)
	{
		HANDSHAKEPOOLTEST_NODE *t = &ctx->Nodes[i];
		NODE_OVERLAY_CONFIG c;

		for (UINT j = 0;j < PEER_KEY_SIZE;j++)
		{
			scalar[j] = (UCHAR)(0x51 + PEER_KEY_SIZE * i + j);
		}
		ok = PeerKeyFromScalar(&t->Key, scalar);

		HandshakePoolTestNewDir(t->Dir, sizeof(t->Dir), handshakepooltest_names[i]);
		t->Node = NewNode(t->Dir);
		NodeStart(t->Node);

		Zero(&c, sizeof(c));
		c.Data = ctx->Loopback;
		c.Key = &t->Key;
		c.Adapter = HandshakePoolTestAdapter;
		c.AdapterParam = t;
		// node-c runs fewer handshakes at once than the default
		c.MaxHandshakes = (i == HANDSHAKEPOOLTEST_C ? HANDSHAKEPOOLTEST_MAX : 0);
		Format(what, sizeof(what), "  %s: its overlay runs without a control stream", handshakepooltest_names[i]);
		ok = HandshakePoolTestCheck(ctx, ok && NodeOverlayStart(t->Node, &c), what, "NodeOverlayStart failed") && ok;
	}
	Zero(scalar, sizeof(scalar));

	if (ok)
	{
		bool applied = HandshakePoolTestApply(ctx, HANDSHAKEPOOLTEST_A) && HandshakePoolTestApply(ctx, HANDSHAKEPOOLTEST_B) && HandshakePoolTestApply(ctx, HANDSHAKEPOOLTEST_C);
		bool linked = applied && HandshakePoolTestWaitLinks(ctx);

		ok = HandshakePoolTestCheck(ctx, applied && linked, "  node-a, node-b and node-c apply their states, and the session of node-a and node-b is up",
			"applied %u, linked %u", (UINT)applied, (UINT)linked);
	}

	return ok;
}

// Close the streams of num that are open
static void HandshakePoolTestCloseStreams(TRANSPORT_STREAM **streams, UINT num)
{
	for (UINT i = 0;i < num;i++)
	{
		if (streams[i] != NULL)
		{
			TransportClose(streams[i]);
			streams[i] = NULL;
		}
	}
}

// The test's streams first, then the nodes, whose overlays stop with every thread joined
static void HandshakePoolTestClose(HANDSHAKEPOOLTEST_CTX *ctx)
{
	HandshakePoolTestCloseStreams(ctx->Silent, HANDSHAKEPOOLTEST_SILENT);
	HandshakePoolTestCloseStreams(ctx->Limited, HANDSHAKEPOOLTEST_LIMITED);
	HandshakePoolTestCloseStreams(&ctx->Garbage, 1);

	for (UINT i = 0;i < HANDSHAKEPOOLTEST_NODES;i++)
	{
		HANDSHAKEPOOLTEST_NODE *t = &ctx->Nodes[i];
		wchar_t log_dir[MAX_PATH];

		if (t->Node != NULL)
		{
			NodeStop(t->Node);
			FreeNode(t->Node);

			ConbinePathW(log_dir, sizeof(log_dir), t->Dir, NODE_LOG_DIR_NAME);
			HandshakePoolTestDeleteFiles(log_dir);
			HandshakePoolTestDeleteFiles(t->Dir);
		}
		PeerKeyClose(&t->Key);
	}
}

// handshakepool: the handshakes of the streams that a node accepts run off the thread of its overlay
RANZ_TEST("handshakepool", handshakepool_test, "Handshake pool (AUD1-DT-1): while 64 silent streams reach a node, the packets of its session to a peer arrive within a fifth of the handshake time; a handshake that times out is closed and counted; the streams beyond the limit in flight are refused and counted.");
void handshakepool_test(UINT num, char **arg)
{
	HANDSHAKEPOOLTEST_CTX *ctx = ZeroMalloc(sizeof(HANDSHAKEPOOLTEST_CTX));
	HANDLE done = CreateEventW(NULL, TRUE, FALSE, NULL);
	HANDLE watchdog = (done != NULL ? CreateThread(NULL, 0, HandshakePoolTestWatchdog, done, 0, NULL) : NULL);

	Print("Handshake pool test: silent streams to a node do not hold the forwarding of its overlay\n");

	ctx->Loopback = TransportLoopbackNew("loopback", 0, false);
	if (HandshakePoolTestOpen(ctx))
	{
		HandshakePoolTestForwarding(ctx);
		HandshakePoolTestTime(ctx);
		HandshakePoolTestLimit(ctx);
	}

	HandshakePoolTestClose(ctx);
	TransportLoopbackFree(ctx->Loopback);

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
		Print("HANDSHAKEPOOL TEST OK\n");
	}
	else
	{
		Print("HANDSHAKEPOOL TEST FAILED (%u of %u checks failed)\n", ctx->NumFailed, ctx->NumChecks);
	}

	Free(ctx);
}
