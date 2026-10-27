// relaypathtest.c
// Named relay path test of vpntest ("relaypath" command, CORE-S5-5 #411)
//
// Two Nodes that both sit behind NAT exchange the packets of their hosts through a Relay (the peer agent of the overlay,
// Cedar/NodeAgent.c), in a world of the NAT simulator of the core tests (src/coretest/natsim.c), in process, as seam 2 of #45
// runs the data plane:
// - node-a sits behind a NAT of endpoint independent mapping, node-b behind a symmetric NAT, both with address and port
//   dependent filtering, and both NATs drop a mapping that carried nothing out for RELAYPATH_NAT_TIMEOUT. node-c and relay-1
//   are on the public side. Neither node-a nor node-b names an endpoint, so no Node can dial them and their pair takes the
//   datagram path through relay-1. node-c names one, so node-a and node-b dial it, and their pairs with it keep a stream
//   session over the in-process loopback transport, which finds a peer by its name.
// - relay-1 is the peer layer of the relay role, as NodeRelayStart makes it, on the network of the simulator in place of its
//   UDP socket. It binds the three Nodes, which share VRF default with it, and forwards between them.
// - The Controller is a stand-in of this file on the control stream of each Node (Core/Control.h): the handshake bound to the
//   exporter of a bound loopback transport, then the Updates of the desired state of each Node, encoded with the messages
//   that nanopb generates from control.proto, and the Signals of the Nodes, which it carries to the peer they name under
//   the name of their sender, as the Controller does (TestRelaysAndSignals of controller/internal/controller).
// - A fake adapter stands in for the host of each Node, and the test sends the packets of each host into its Node. A tap of
//   the network sees every datagram that a host sends, on whatever link, before the network routes it.
// The steps:
// a. Bring-up: every Node applies Generation 1 from its control stream; node-a and node-b exchange their Signals through the
//    stand-in and come up through relay-1, while each has its stream session with node-c.
// b. Signals: they went on the control streams and the stand-in carried them. It cannot read one: no envelope holds the
//    static key or the address of relay-1, which every Signal names, and its own static key opens none. It cannot alter
//    one: node-b drops as forged the first Signal of node-a, whose envelope the stand-in altered on the way, and one that the
//    stand-in sealed itself in the name of node-a, naming a relay of its own.
// c. Data: packets of the host of node-a reach the host of node-b through relay-1 and come back, one of the MTU of the VRF
//    among them, while node-a reaches node-c on its stream session; the capture finds no 8 bytes in a row of them.
// d. Counters: the sessions of node-a and node-b say relay for their pair and stream for node-c, with the records of the
//    overlay that went each way on the datagram path, and so does the answer of the admin pipe of node-a to state, which
//    ranz node state prints.
// e. Relay restart: relay-1 starts again with no Binding. The next keepalive of each Node binds it again, and the packets go
//    through as before, with no new Signal, no new Generation, the same control stream and the same peer session.
// f. NAT ageing: after a quiet time of three NAT timeouts the packets still go through, on the same mappings, which the
//    keepalive of each Node kept, while a mapping that the test opened on the NAT of node-b and left aged out.
// g. Policy: in Generation 2 a rule of every Node denies node-a to node-b and node-c, and node-a drops the packet to either;
//    in Generation 3 only node-b and node-c hold the rule, and each drops what node-a sent, on the datagram path as on the
//    stream path.
// Print "RELAYPATH TEST OK" only when every check passes.

#include "testlist.h"

#include "Cedar/ConfigStore.h"
#include "Cedar/Node.h"
#include "Cedar/NodeAgent.h"

#include "Mayaqua/Encrypt.h"
#include "Mayaqua/FileIO.h"
#include "Mayaqua/Internat.h"
#include "Mayaqua/Kernel.h"
#include "Mayaqua/Memory.h"
#include "Mayaqua/Microsoft.h"
#include "Mayaqua/Str.h"
#include "Mayaqua/TcpIp.h"
#include "Mayaqua/Tick64.h"

#include "Core/Control.h"
#include "Core/Crypto.h"
#include "Core/Transport.h"

#include "natsim.h"

#include <pb_decode.h>
#include <pb_encode.h>

#include "ranz/control/v1/control.pb.h"

#include <stdio.h>

#define	RELAYPATH_BUDGET		240000		// The whole test ends within this time, or the watchdog ends the process (ms)
#define	RELAYPATH_BOUND			20000		// A bounded wait on observable state (ms)
#define	RELAYPATH_POLL			20			// Poll interval of observable state (ms)
#define	RELAYPATH_READ			50			// ms that one read of a control stream of the stand-in waits
#define	RELAYPATH_TICK			100			// ms between two ticks of the peer layer of relay-1
#define	RELAYPATH_BIND			400			// The keepalive of the Bindings of the Nodes: their BindInterval (ms) ...
#define	RELAYPATH_BIND_RETRY	200			// ... and their BindRetry (ms)
#define	RELAYPATH_EXPIRY		3000		// The BindExpiry of relay-1 (ms)
#define	RELAYPATH_NAT_TIMEOUT	1500		// A mapping of either NAT that carried nothing out for this long is gone (ms)
#define	RELAYPATH_QUIET			4500		// The quiet time of the ageing step: three NAT timeouts (ms)
#define	RELAYPATH_VRF			1			// The id of VRF default ...
#define	RELAYPATH_VRF_NAME		"default"	// ... its name and the name of its Network ...
#define	RELAYPATH_MTU			1280		// ... and its MTU
#define	RELAYPATH_FRAME_HEADER	4			// The size of a frame of a control stream, big-endian, before its message
#define	RELAYPATH_MAX_FRAME		(1 << 20)	// The largest frame that the stand-in reads, as the node does (CONTROL_MAX_FRAME)
#define	RELAYPATH_OUT_FRAME		65536		// The largest frame that it writes
#define	RELAYPATH_MAX_STREAMS	16			// Control streams that the stand-in serves in one run at most
#define	RELAYPATH_MAX_WINDOWS	128			// The 8-byte windows that the capture looks for at most
#define	RELAYPATH_NUM_NODES		3
#define	RELAYPATH_A				0			// node-a, behind a NAT of endpoint independent mapping
#define	RELAYPATH_B				1			// node-b, behind a symmetric NAT
#define	RELAYPATH_C				2			// node-c, on the public side with an endpoint
#define	RELAYPATH_CONTROLLER	"controller"		// The address of the stand-in on the transport of the control streams
#define	RELAYPATH_ENDPOINT		"198.51.100.3:443"	// The endpoint of node-c in its Node resource
#define	RELAYPATH_RELAY			"relay-1"	// The node name of the Relay
#define	RELAYPATH_RELAY_PORT	3478		// The UDP port of its relay role
#define	RELAYPATH_ECHO_PORT		7			// The UDP port that the packets of the hosts go to
#define	RELAYPATH_ECHOES		3			// The echoes of the data step

// Where a packet of a host went
#define	RELAYPATH_DELIVERED			0		// The host of the other Node took it as it was sent
#define	RELAYPATH_DROPPED_SENDER	1		// The Node of the sending host dropped it
#define	RELAYPATH_DROPPED_RECEIVER	2		// The Node of the other host dropped it
#define	RELAYPATH_LOST				3		// Neither within RELAYPATH_BOUND, or it came altered

// What a read of a frame of a control stream at the stand-in gave
#define	RELAYPATH_FRAME_DONE	0			// A whole frame is in Frame
#define	RELAYPATH_FRAME_LATER	1			// Not within the timeout: the bytes read so far stay in Frame
#define	RELAYPATH_FRAME_END		2			// The stream ended, or its next frame is larger than allowed

// The links of node-a and node-b with relay-1, on which the capture counts the records of peer sessions
#define	RELAYPATH_LINK_A_RELAY	0			// node-a to relay-1
#define	RELAYPATH_LINK_RELAY_A	1			// relay-1 to node-a
#define	RELAYPATH_LINK_B_RELAY	2			// node-b to relay-1
#define	RELAYPATH_LINK_RELAY_B	3			// relay-1 to node-b
#define	RELAYPATH_NUM_LINKS		4

static char *relaypath_names[RELAYPATH_NUM_NODES] = {"node-a", "node-b", "node-c"};
static char *relaypath_tags[RELAYPATH_NUM_NODES] = {"site-a", "site-b", "site-c"};
static char *relaypath_links[RELAYPATH_NUM_LINKS] = {"node-a to relay-1", "relay-1 to node-a", "node-b to relay-1", "relay-1 to node-b"};

// The payload of every packet of a host, once or repeated: no 8 bytes of it in a row may show on a link
static char relaypath_marker[] = "RELAYPATH: the packet of a host, which no link of the network may carry in the clear. ";

// One Node of the test, its host on the network of the simulator and the fake adapter of the host
typedef struct RELAYPATH_NODE
{
	char *Name;
	wchar_t Dir[MAX_PATH];					// Its data directory
	PEER_KEY Key;							// Its static key
	PEER_ADDR Addr;							// The address of its host: private behind a NAT
	NATSIM_NAT *Nat;						// ... its NAT, NULL on the public side
	NATSIM_HOST *Host;						// ... and the host on the network
	NODE *Node;
	NODE_READER Reader;						// The test thread as a reader of the node's forwarding tables, online while it sends
	SRWLOCK Lock;							// Last, LastSize and LastVrf
	UCHAR Last[PEER_MAX_DATAGRAM];			// The packet that the adapter took last ...
	UINT LastSize;							// ... its size
	UINT LastVrf;							// ... and its VRF
	volatile LONG Packets;					// The packets that the adapter took
} RELAYPATH_NODE;

// The control stream of one Node at the stand-in of the Controller
typedef struct RELAYPATH_LINK
{
	CONTROL_SIGNALS *Out;					// The Signals that the stand-in carries to the Node
	volatile LONG Active;					// A stream of the Node is served now
	volatile LONG Streams;					// The streams of the Node that the stand-in served
	volatile LONG64 Posted;					// The Generation of the desired state that the Node is to get
	volatile LONG64 Acked;					// The Generation that the Node acknowledged last
	volatile LONG64 Signals;				// The Signals that the Node sent on its stream
} RELAYPATH_LINK;

// One stream that the stand-in took, and its thread
typedef struct RELAYPATH_STREAM
{
	struct RELAYPATH_CTX *Ctx;
	TRANSPORT_STREAM *Stream;
	HANDLE Thread;
	UCHAR *Frame;							// The frame being read: its size, then its message
	UINT FrameSize;							// ... its bytes read so far
	UCHAR *Out;								// The frame being written
	ranz_control_v1_ControlMessage *Message;	// The message read last, or written
} RELAYPATH_STREAM;

// The state of the test
typedef struct RELAYPATH_CTX
{
	UINT NumChecks;
	UINT NumFailed;
	RELAYPATH_NODE Nodes[RELAYPATH_NUM_NODES];
	PEER_CONFIG PathConfig;					// The peer layer of the agents of the Nodes: the shorter timers of a test

	// The network of the simulator, its NATs, and relay-1
	NATSIM *Sim;
	NATSIM_NAT *NatA;
	NATSIM_NAT *NatB;
	PEER_ADDR PublicA;						// The public address of the NAT of node-a, port 0
	PEER_ADDR PublicB;						// ... and of node-b
	PEER_KEY RelayKey;						// The static key of relay-1
	PEER_ADDR RelayAddr;					// The address of its relay role
	PEER_CONFIG RelayConfig;				// ... and its configuration
	NATSIM_HOST *RelayHost;
	SRWLOCK RelayLock;						// Relay: its ticker and a restart
	PEER_AGENT *Relay;						// The peer layer of the relay role of relay-1
	HANDLE Ticker;							// ... which this thread ticks
	volatile LONG Halt;						// Ends the threads of the test

	// The capture of every datagram that a host sends
	UCHAR Windows[RELAYPATH_MAX_WINDOWS][8];	// The 8 bytes in a row that no datagram may hold
	UINT NumWindows;
	volatile LONG64 Captured;				// The datagrams that the tap saw
	volatile LONG64 Clear;					// ... that held a window
	volatile LONG64 Records[RELAYPATH_NUM_LINKS];	// The records of peer sessions on each link of node-a and node-b with relay-1

	// The transports: the data streams between the Nodes, and the control streams to the stand-in
	TRANSPORT *Data;
	TRANSPORT *Control;

	// The stand-in of the Controller
	PEER_KEY ControllerKey;					// Its static key
	TRANSPORT_LISTENER *Listener;
	HANDLE Acceptor;						// The thread that takes the streams
	RELAYPATH_LINK Links[RELAYPATH_NUM_NODES];
	RELAYPATH_STREAM *Streams[RELAYPATH_MAX_STREAMS];
	volatile LONG NumStreams;
	volatile LONG Carry;					// It carries the Signals: every Node applied its first state
	volatile LONG Tamper;					// It alters the envelope of the next Signal of node-a to node-b
	volatile LONG64 Carried;				// The Signals that it carried
	volatile LONG64 Altered;				// ... of them altered on the way
	volatile LONG64 Inspected;				// The envelopes that it looked into
	volatile LONG64 Readable;				// ... that held the static key or the address of relay-1
	volatile LONG64 Opened;					// ... that its own static key opened
} RELAYPATH_CTX;

// One packet of the policy step: from which host to which, its source port, and where it must go
typedef struct RELAYPATH_STEP
{
	UINT From;
	UINT To;
	USHORT Port;
	UINT Expect;
	char *What;
} RELAYPATH_STEP;

static bool RelayPathCheck(RELAYPATH_CTX *ctx, bool ok, char *what, char *fmt, ...) RANZ_PRINTF_FORMAT(4, 5);
static bool RelayPathCheck(RELAYPATH_CTX *ctx, bool ok, char *what, char *fmt, ...)
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
static DWORD WINAPI RelayPathWatchdog(LPVOID param)
{
	char msg[MAX_SIZE];
	DWORD written = 0;

	if (WaitForSingleObject((HANDLE)param, RELAYPATH_BUDGET) != WAIT_TIMEOUT)
	{
		return 0;
	}

	int len = snprintf(msg, sizeof(msg), "RELAYPATH TEST FAILED (did not finish within %u ms)\n", (UINT)RELAYPATH_BUDGET);
	if (len > 0)
	{
		WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), msg, (DWORD)MIN((UINT)len, (UINT)sizeof(msg) - 1), &written, NULL);
	}

	TerminateProcess(GetCurrentProcess(), 1);

	return 0;
}

//
// The packets of the hosts
//

// The address of node i in VRF default, 100.64.0.(1 + i), into addr
static void RelayPathIp(UCHAR *addr, UINT i)
{
	addr[0] = 100;
	addr[1] = 64;
	addr[2] = 0;
	addr[3] = (UCHAR)(1 + i);
}

// A UDP packet of size bytes in all from the host of node from, port sport, to the host of node to, port dport, whose
// payload is the marker, repeated to fill it: its size
static UINT RelayPathPacket(UCHAR *buf, UINT from, UINT to, USHORT sport, USHORT dport, UINT size)
{
	UINT len = StrLen(relaypath_marker);
	UCHAR *udp = buf + 20;

	Zero(buf, size);
	buf[0] = 0x45;
	buf[2] = (UCHAR)(size >> 8);
	buf[3] = (UCHAR)size;
	buf[8] = 64;
	buf[9] = IP_PROTO_UDP;
	RelayPathIp(buf + 12, from);
	RelayPathIp(buf + 16, to);
	USHORT sum = IpChecksum(buf, 20);
	Copy(buf + 10, &sum, 2);

	WRITE_USHORT(udp, sport);
	WRITE_USHORT(udp + 2, dport);
	WRITE_USHORT(udp + 4, size - 20);
	for (UINT i = 28; i < size; i++)
	{
		buf[i] = (UCHAR)relaypath_marker[(i - 28) % len];
	}

	return size;
}

// The size of a packet that holds the marker once
static UINT RelayPathSmall()
{
	return 28 + StrLen(relaypath_marker);
}

// The fake adapter of a host: it keeps the packet that it took last and counts them
static void RelayPathAdapter(NODE *n, void *param, UINT vrf_id, const UCHAR *packet, UINT size)
{
	RELAYPATH_NODE *t = (RELAYPATH_NODE *)param;

	AcquireSRWLockExclusive(&t->Lock);
	{
		t->LastSize = MIN(size, (UINT)sizeof(t->Last));
		Copy(t->Last, packet, t->LastSize);
		t->LastVrf = vrf_id;
	}
	ReleaseSRWLockExclusive(&t->Lock);

	InterlockedIncrement(&t->Packets);
}

// The packets that the overlay of node t dropped
static UINT64 RelayPathDropped(RELAYPATH_NODE *t)
{
	NODE_OVERLAY_STATUS st;

	NodeOverlayGetStatus(t->Node, &st);

	return st.Dropped;
}

// Send the packet, size bytes, of the host of node from into its Node, and find where it went within RELAYPATH_BOUND
// (RELAYPATH_DELIVERED, RELAYPATH_DROPPED_SENDER, RELAYPATH_DROPPED_RECEIVER or RELAYPATH_LOST)
static UINT RelayPathDeliver(RELAYPATH_CTX *ctx, UINT from, UINT to, const UCHAR *packet, UINT size)
{
	RELAYPATH_NODE *f = &ctx->Nodes[from], *t = &ctx->Nodes[to];
	LONG packets = InterlockedCompareExchange(&t->Packets, 0, 0);
	UINT64 dropped_from = RelayPathDropped(f), dropped_to = RelayPathDropped(t);

	NodeReaderOnline(f->Node, &f->Reader);
	bool sent = NodeOverlayInput(f->Node, RELAYPATH_VRF, packet, size);
	NodeReaderOffline(&f->Reader);

	if (sent == false)
	{
		return (RelayPathDropped(f) != dropped_from ? RELAYPATH_DROPPED_SENDER : RELAYPATH_LOST);
	}

	for (UINT64 end = Tick64() + RELAYPATH_BOUND;Tick64() < end;SleepThread(1))
	{
		if (InterlockedCompareExchange(&t->Packets, 0, 0) != packets)
		{
			bool same;

			AcquireSRWLockShared(&t->Lock);
			same = (t->LastSize == size && t->LastVrf == RELAYPATH_VRF && Cmp(t->Last, packet, size) == 0);
			ReleaseSRWLockShared(&t->Lock);

			return (same ? RELAYPATH_DELIVERED : RELAYPATH_LOST);
		}
		if (RelayPathDropped(t) != dropped_to)
		{
			return RELAYPATH_DROPPED_RECEIVER;
		}
	}

	return RELAYPATH_LOST;
}

// What RelayPathDeliver gave, as text
static char *RelayPathOutcome(UINT outcome)
{
	switch (outcome)
	{
	case RELAYPATH_DELIVERED:
		return "delivered";
	case RELAYPATH_DROPPED_SENDER:
		return "dropped by the sender";
	case RELAYPATH_DROPPED_RECEIVER:
		return "dropped by the receiver";
	default:
		return "lost";
	}
}

// A packet of size bytes from the host of node from, port sport, to the host of node to, and the answer of that host back
// to port sport: whether both came as they were sent
static bool RelayPathEcho(RELAYPATH_CTX *ctx, UINT from, UINT to, USHORT sport, UINT size, char *detail, UINT detail_size)
{
	UCHAR *packet = Malloc(size);

	RelayPathPacket(packet, from, to, sport, RELAYPATH_ECHO_PORT, size);
	UINT there = RelayPathDeliver(ctx, from, to, packet, size);
	UINT back = RELAYPATH_LOST;
	if (there == RELAYPATH_DELIVERED)
	{
		RelayPathPacket(packet, to, from, RELAYPATH_ECHO_PORT, sport, size);
		back = RelayPathDeliver(ctx, to, from, packet, size);
	}
	Free(packet);

	Format(detail, detail_size, "%s to %s: %s; back: %s", relaypath_names[from], relaypath_names[to], RelayPathOutcome(there), there == RELAYPATH_DELIVERED ? RelayPathOutcome(back) : "not sent");

	return (there == RELAYPATH_DELIVERED && back == RELAYPATH_DELIVERED);
}

//
// The network of the simulator
//

// The 8 bytes in a row that no datagram of the network may hold: every 8 bytes of the payload of the packets of the hosts,
// also across two copies of it, and the addresses of node-a and node-b one after the other, as an IP header holds them
static void RelayPathWindows(RELAYPATH_CTX *ctx)
{
	UINT len = StrLen(relaypath_marker);

	ctx->NumWindows = 0;
	for (UINT i = 0;i < len && ctx->NumWindows < RELAYPATH_MAX_WINDOWS - 2;i++)
	{
		for (UINT k = 0;k < 8;k++)
		{
			ctx->Windows[ctx->NumWindows][k] = (UCHAR)relaypath_marker[(i + k) % len];
		}
		ctx->NumWindows++;
	}

	RelayPathIp(ctx->Windows[ctx->NumWindows], RELAYPATH_A);
	RelayPathIp(ctx->Windows[ctx->NumWindows] + 4, RELAYPATH_B);
	ctx->NumWindows++;
	RelayPathIp(ctx->Windows[ctx->NumWindows], RELAYPATH_B);
	RelayPathIp(ctx->Windows[ctx->NumWindows] + 4, RELAYPATH_A);
	ctx->NumWindows++;
}

// Whether a datagram holds one of the windows
static bool RelayPathClear(RELAYPATH_CTX *ctx, const UCHAR *data, UINT size)
{
	for (UINT i = 0;i + 8 <= size;i++)
	{
		for (UINT w = 0;w < ctx->NumWindows;w++)
		{
			if (data[i] == ctx->Windows[w][0] && Cmp(data + i, ctx->Windows[w], 8) == 0)
			{
				return true;
			}
		}
	}

	return false;
}

// Whether a and b have the same IP address, whatever their ports
static bool RelayPathSameIp(const PEER_ADDR *a, const PEER_ADDR *b)
{
	return (Cmp(a->Ip, b->Ip, sizeof(a->Ip)) == 0);
}

// The tap of the network (NATSIM_TAP): every datagram that a host sends, on whatever link, before the network routes it. It
// counts the datagrams that hold a window, and the records of peer sessions on each link of node-a and node-b with relay-1.
// It drops nothing.
static bool RelayPathTap(void *param, NATSIM_HOST *from, const PEER_ADDR *dst, const UCHAR *data, UINT size)
{
	RELAYPATH_CTX *ctx = (RELAYPATH_CTX *)param;
	UINT link = RELAYPATH_NUM_LINKS;

	InterlockedIncrement64(&ctx->Captured);
	if (RelayPathClear(ctx, data, size))
	{
		InterlockedIncrement64(&ctx->Clear);
	}

	if (size == 0 || data[0] != PEER_MSG_RECORD)
	{
		return true;
	}

	if (from == ctx->Nodes[RELAYPATH_A].Host && PeerAddrEqual(dst, &ctx->RelayAddr))
	{
		link = RELAYPATH_LINK_A_RELAY;
	}
	else if (from == ctx->Nodes[RELAYPATH_B].Host && PeerAddrEqual(dst, &ctx->RelayAddr))
	{
		link = RELAYPATH_LINK_B_RELAY;
	}
	else if (from == ctx->RelayHost && RelayPathSameIp(dst, &ctx->PublicA))
	{
		link = RELAYPATH_LINK_RELAY_A;
	}
	else if (from == ctx->RelayHost && RelayPathSameIp(dst, &ctx->PublicB))
	{
		link = RELAYPATH_LINK_RELAY_B;
	}

	if (link < RELAYPATH_NUM_LINKS)
	{
		InterlockedIncrement64(&ctx->Records[link]);
	}

	return true;
}

// The ticker of relay-1: the timers of its peer layer, which drop the Bindings that were not renewed, as the receive thread
// of its UDP socket runs them on a Node
static DWORD WINAPI RelayPathTicker(LPVOID param)
{
	RELAYPATH_CTX *ctx = (RELAYPATH_CTX *)param;

	while (InterlockedCompareExchange(&ctx->Halt, 0, 0) == 0)
	{
		AcquireSRWLockShared(&ctx->RelayLock);
		PeerTick(ctx->Relay);
		ReleaseSRWLockShared(&ctx->RelayLock);

		Sleep(RELAYPATH_TICK);
	}

	return 0;
}

// Start the peer layer of the relay role of relay-1 on its host, with the three Nodes as its peers in VRF default, as the
// Peer objects of its desired state give them
static bool RelayPathRelayStart(RELAYPATH_CTX *ctx)
{
	PEER_INFO peers[RELAYPATH_NUM_NODES];

	for (UINT i = 0;i < RELAYPATH_NUM_NODES;i++)
	{
		Zero(&peers[i], sizeof(PEER_INFO));
		StrCpy(peers[i].Name, sizeof(peers[i].Name), relaypath_names[i]);
		Copy(peers[i].Key, ctx->Nodes[i].Key.Public, PEER_KEY_SIZE);
		peers[i].NumVrfs = 1;
		peers[i].VrfIds[0] = RELAYPATH_VRF;
	}

	PEER_AGENT *p = PeerNew(&ctx->RelayKey, &ctx->RelayConfig, NatSimSend, ctx->RelayHost, NULL, NULL);
	if (p == NULL)
	{
		return false;
	}
	PeerSetPeers(p, peers, RELAYPATH_NUM_NODES);

	AcquireSRWLockExclusive(&ctx->RelayLock);
	ctx->Relay = p;
	ReleaseSRWLockExclusive(&ctx->RelayLock);

	NatSimAttach(ctx->RelayHost, p);

	return true;
}

// Stop the peer layer of relay-1: it leaves its host, so that no datagram comes to it, and the ticker holds it no more
static void RelayPathRelayStop(RELAYPATH_CTX *ctx)
{
	NatSimAttach(ctx->RelayHost, NULL);

	AcquireSRWLockExclusive(&ctx->RelayLock);
	PEER_AGENT *p = ctx->Relay;
	ctx->Relay = NULL;
	ReleaseSRWLockExclusive(&ctx->RelayLock);

	PeerFree(p);
}

// The counters of relay-1
static void RelayPathRelayStats(RELAYPATH_CTX *ctx, PEER_STATS *st)
{
	AcquireSRWLockShared(&ctx->RelayLock);
	PeerGetStats(ctx->Relay, st);
	ReleaseSRWLockShared(&ctx->RelayLock);
}

// Whether relay-1 holds a Binding of every Node within RELAYPATH_BOUND
static bool RelayPathWaitBindings(RELAYPATH_CTX *ctx)
{
	for (UINT64 end = Tick64() + RELAYPATH_BOUND;Tick64() < end;SleepThread(RELAYPATH_POLL))
	{
		PEER_STATS st;

		RelayPathRelayStats(ctx, &st);
		if (st.NumBindings == RELAYPATH_NUM_NODES)
		{
			return true;
		}
	}

	return false;
}

//
// The stand-in of the Controller
//

// Read the next frame of the stream t within timeout into Frame (RELAYPATH_FRAME_*)
static UINT RelayPathRead(RELAYPATH_STREAM *t, UINT timeout)
{
	UINT64 end = Tick64() + timeout;

	while (true)
	{
		UINT need = RELAYPATH_FRAME_HEADER;

		if (t->FrameSize >= RELAYPATH_FRAME_HEADER)
		{
			UINT size = ((UINT)t->Frame[0] << 24) | ((UINT)t->Frame[1] << 16) | ((UINT)t->Frame[2] << 8) | t->Frame[3];

			if (size == 0 || size > RELAYPATH_MAX_FRAME - RELAYPATH_FRAME_HEADER)
			{
				return RELAYPATH_FRAME_END;
			}
			need += size;
			if (t->FrameSize == need)
			{
				return RELAYPATH_FRAME_DONE;
			}
		}

		UINT64 now = Tick64();
		if (now >= end)
		{
			return RELAYPATH_FRAME_LATER;
		}

		UINT got = TransportRead(t->Stream, t->Frame + t->FrameSize, need - t->FrameSize, (UINT)(end - now));
		if (got == 0 || (got != TRANSPORT_LATER && got > need - t->FrameSize))
		{
			return RELAYPATH_FRAME_END;
		}
		if (got != TRANSPORT_LATER)
		{
			t->FrameSize += got;
		}
	}
}

// Write size bytes at Out after the frame header, as one frame
static bool RelayPathWriteFrame(RELAYPATH_STREAM *t, UINT size)
{
	t->Out[0] = (UCHAR)(size >> 24);
	t->Out[1] = (UCHAR)(size >> 16);
	t->Out[2] = (UCHAR)(size >> 8);
	t->Out[3] = (UCHAR)size;

	return TransportWrite(t->Stream, t->Out, RELAYPATH_FRAME_HEADER + size);
}

// Decode the frame in Frame into Message: false for bytes that are no ControlMessage
static bool RelayPathDecode(RELAYPATH_STREAM *t)
{
	pb_istream_t is = pb_istream_from_buffer(t->Frame + RELAYPATH_FRAME_HEADER, t->FrameSize - RELAYPATH_FRAME_HEADER);

	Zero(t->Message, sizeof(ranz_control_v1_ControlMessage));

	return pb_decode(&is, ranz_control_v1_ControlMessage_fields, t->Message);
}

// The responder of the handshake of a control stream, as the Controller runs it: Noise_IK with the static key of the
// stand-in, bound to the exporter of the stream after the prologue of the control stream. The static key of the Node goes
// into remote.
static bool RelayPathHandshake(RELAYPATH_CTX *ctx, RELAYPATH_STREAM *t, UCHAR *remote)
{
	UCHAR prologue[sizeof(CONTROL_PROLOGUE_LABEL) - 1 + CONTROL_EXPORTER_SIZE];
	UCHAR binding[NOISE_MAX_BINDING];
	NOISE_HANDSHAKE hs;
	UINT size = 0;
	UINT payload_size = 0;

	if (TransportBinding(t->Stream, binding, sizeof(binding), &size) != NOISE_BINDING_EXPORTER || size != CONTROL_EXPORTER_SIZE)
	{
		return false;
	}
	Copy(prologue, CONTROL_PROLOGUE_LABEL, sizeof(CONTROL_PROLOGUE_LABEL) - 1);
	Copy(prologue + sizeof(CONTROL_PROLOGUE_LABEL) - 1, binding, CONTROL_EXPORTER_SIZE);

	t->FrameSize = 0;
	if (RelayPathRead(t, CONTROL_TIMEOUT) != RELAYPATH_FRAME_DONE)
	{
		return false;
	}

	bool ok = NoiseHandshakeInit(&hs, NOISE_SUITE_IK, false, prologue, (UINT)sizeof(prologue), ctx->ControllerKey.Private, NULL, NULL);
	ok = ok && NoiseHandshakeRead(&hs, t->Frame + RELAYPATH_FRAME_HEADER, t->FrameSize - RELAYPATH_FRAME_HEADER, NULL, 0, &payload_size);
	ok = ok && NoiseHandshakeWrite(&hs, NULL, 0, t->Out + RELAYPATH_FRAME_HEADER, RELAYPATH_OUT_FRAME - RELAYPATH_FRAME_HEADER, &size);
	if (ok)
	{
		Copy(remote, hs.RemoteStatic, PEER_KEY_SIZE);
	}
	NoiseHandshakeFree(&hs);
	t->FrameSize = 0;

	return ok && RelayPathWriteFrame(t, size);
}

// The Hello that a Node sends first after the handshake
static bool RelayPathHello(RELAYPATH_STREAM *t)
{
	bool ok = (RelayPathRead(t, CONTROL_TIMEOUT) == RELAYPATH_FRAME_DONE && RelayPathDecode(t) && t->Message->which_body == ranz_control_v1_ControlMessage_hello_tag);

	t->FrameSize = 0;

	return ok;
}

// The address of node i in VRF default as an Address of the control protocol
static void RelayPathAddress(ranz_control_v1_Address *a, UINT i)
{
	StrCpy(a->network, sizeof(a->network), RELAYPATH_VRF_NAME);
	a->vrf_id = RELAYPATH_VRF;
	a->has_prefix = true;
	a->prefix.address.size = 4;
	RelayPathIp(a->prefix.address.bytes, i);
	a->prefix.length = 10;
}

// The endpoint of node-c, under which the others dial it; the data transport of the test finds it by its name
static void RelayPathEndpoint(ranz_control_v1_Endpoint *e)
{
	e->transport = ranz_control_v1_Transport_TRANSPORT_TLS;
	StrCpy(e->address, sizeof(e->address), RELAYPATH_ENDPOINT);
}

// A rule of VRF default with its name, priority and action
static ranz_control_v1_Rule *RelayPathRule(ranz_control_v1_Update *u, char *name, UINT priority, bool deny)
{
	ranz_control_v1_Object *o = &u->set[u->set_count++];
	ranz_control_v1_Rule *r = &o->kind.rule;

	o->which_kind = ranz_control_v1_Object_rule_tag;
	StrCpy(r->name, sizeof(r->name), name);
	r->vrf_id = RELAYPATH_VRF;
	r->priority = priority;
	r->action = (deny ? ranz_control_v1_RuleAction_RULE_ACTION_DENY : ranz_control_v1_RuleAction_RULE_ACTION_ALLOW);

	return r;
}

// The desired state of node i at Generation g, as an Update of the stand-in, into m: the Node with its tag, its address and,
// for node-c, its endpoint; VRF default with its policy; the other Nodes as its peers; relay-1; and the rules: allow-all, the
// starter rule, and from Generation 2 deny-a, which denies node-a to node-b and node-c, in Generation 3 at node-b and node-c
// only
static void RelayPathState(RELAYPATH_CTX *ctx, UINT i, UINT64 g, ranz_control_v1_ControlMessage *m)
{
	Zero(m, sizeof(ranz_control_v1_ControlMessage));
	m->which_body = ranz_control_v1_ControlMessage_update_tag;

	ranz_control_v1_Update *u = &m->body.update;
	u->generation = g;

	ranz_control_v1_Object *o = &u->set[u->set_count++];
	ranz_control_v1_NodeConfig *node = &o->kind.node;
	o->which_kind = ranz_control_v1_Object_node_tag;
	StrCpy(node->name, sizeof(node->name), relaypath_names[i]);
	node->tags_count = 1;
	StrCpy(node->tags[0], sizeof(node->tags[0]), relaypath_tags[i]);
	node->addresses_count = 1;
	RelayPathAddress(&node->addresses[0], i);
	if (i == RELAYPATH_C)
	{
		node->endpoints_count = 1;
		RelayPathEndpoint(&node->endpoints[0]);
	}

	o = &u->set[u->set_count++];
	o->which_kind = ranz_control_v1_Object_vrf_tag;
	StrCpy(o->kind.vrf.name, sizeof(o->kind.vrf.name), RELAYPATH_VRF_NAME);
	o->kind.vrf.id = RELAYPATH_VRF;
	o->kind.vrf.mtu = RELAYPATH_MTU;
	o->kind.vrf.has_policy = true;

	for (UINT j = 0;j < RELAYPATH_NUM_NODES;j++)
	{
		if (j == i)
		{
			continue;
		}

		o = &u->set[u->set_count++];
		ranz_control_v1_Peer *p = &o->kind.peer;
		o->which_kind = ranz_control_v1_Object_peer_tag;
		StrCpy(p->name, sizeof(p->name), relaypath_names[j]);
		p->public_key.size = PEER_KEY_SIZE;
		Copy(p->public_key.bytes, ctx->Nodes[j].Key.Public, PEER_KEY_SIZE);
		p->vrf_ids_count = 1;
		p->vrf_ids[0] = RELAYPATH_VRF;
		p->addresses_count = 1;
		RelayPathAddress(&p->addresses[0], j);
		p->tags_count = 1;
		StrCpy(p->tags[0], sizeof(p->tags[0]), relaypath_tags[j]);
		if (j == RELAYPATH_C)
		{
			p->endpoints_count = 1;
			RelayPathEndpoint(&p->endpoints[0]);
		}
	}

	o = &u->set[u->set_count++];
	ranz_control_v1_Relay *r = &o->kind.relay;
	o->which_kind = ranz_control_v1_Object_relay_tag;
	StrCpy(r->name, sizeof(r->name), RELAYPATH_RELAY);
	r->public_key.size = PEER_KEY_SIZE;
	Copy(r->public_key.bytes, ctx->RelayKey.Public, PEER_KEY_SIZE);
	r->address.size = 4;
	Copy(r->address.bytes, ctx->RelayAddr.Ip + 12, 4);
	r->port = RELAYPATH_RELAY_PORT;

	RelayPathRule(u, "allow-all", 1000, false);

	if (g == 2 || (g >= 3 && i != RELAYPATH_A))
	{
		ranz_control_v1_Rule *deny = RelayPathRule(u, "deny-a", 10, true);

		deny->has_from = true;
		deny->from.tags_count = 1;
		StrCpy(deny->from.tags[0], sizeof(deny->from.tags[0]), relaypath_tags[RELAYPATH_A]);
		deny->has_to = true;
		deny->to.tags_count = 2;
		StrCpy(deny->to.tags[0], sizeof(deny->to.tags[0]), relaypath_tags[RELAYPATH_B]);
		StrCpy(deny->to.tags[1], sizeof(deny->to.tags[1]), relaypath_tags[RELAYPATH_C]);
	}
}

// Write Message as one frame
static bool RelayPathWrite(RELAYPATH_STREAM *t)
{
	pb_ostream_t os = pb_ostream_from_buffer(t->Out + RELAYPATH_FRAME_HEADER, RELAYPATH_OUT_FRAME - RELAYPATH_FRAME_HEADER);

	if (pb_encode(&os, ranz_control_v1_ControlMessage_fields, t->Message) == false)
	{
		return false;
	}

	return RelayPathWriteFrame(t, (UINT)os.bytes_written);
}

// Whether data, size bytes, holds the size bytes of what
static bool RelayPathHolds(const UCHAR *data, UINT size, const UCHAR *what, UINT what_size)
{
	for (UINT i = 0;i + what_size <= size;i++)
	{
		if (Cmp(data + i, what, what_size) == 0)
		{
			return true;
		}
	}

	return false;
}

// A Signal of node i that the stand-in read from its stream: it looks into the envelope, as a Controller could, and carries
// it to the Node that it names, under the name of its sender. The first Signal of node-a to node-b gets an altered envelope.
static void RelayPathCarry(RELAYPATH_CTX *ctx, UINT i, const ranz_control_v1_Signal *s)
{
	UCHAR env[CONTROL_MAX_ENVELOPE];
	UCHAR sender[PEER_KEY_SIZE];
	UCHAR *payload = Malloc(PEER_MAX_ENVELOPE);
	UINT len = 0;
	UINT to = RELAYPATH_NUM_NODES;
	UINT size = MIN((UINT)s->envelope.size, (UINT)sizeof(env));

	Copy(env, s->envelope.bytes, size);

	// What a Controller sees of it: the static key and the address of relay-1, which the Signal names, are not there in the
	// clear, and its own static key does not open it
	InterlockedIncrement64(&ctx->Inspected);
	if (RelayPathHolds(env, size, ctx->RelayKey.Public, PEER_KEY_SIZE) || RelayPathHolds(env, size, ctx->RelayAddr.Ip, sizeof(ctx->RelayAddr.Ip)))
	{
		InterlockedIncrement64(&ctx->Readable);
	}
	if (PeerEnvelopeOpen(&ctx->ControllerKey, env, size, sender, payload, PEER_MAX_ENVELOPE, &len))
	{
		InterlockedIncrement64(&ctx->Opened);
	}
	Free(payload);

	for (UINT j = 0;j < RELAYPATH_NUM_NODES && to == RELAYPATH_NUM_NODES;j++)
	{
		if (StrCmp(s->peer, relaypath_names[j]) == 0)
		{
			to = j;
		}
	}
	if (to == RELAYPATH_NUM_NODES || size == 0)
	{
		return;
	}

	if (i == RELAYPATH_A && to == RELAYPATH_B && InterlockedCompareExchange(&ctx->Tamper, 0, 1) == 1)
	{
		env[size - 1] ^= 0x01;
		InterlockedIncrement64(&ctx->Altered);
	}

	if (ControlSendSignal(ctx->Links[to].Out, relaypath_names[i], env, size))
	{
		InterlockedIncrement64(&ctx->Carried);
	}
}

// A frame that node i sent on its stream: an Ack, or a Signal for a peer; a Leases or a Telemetry message changes nothing here
static void RelayPathTake(RELAYPATH_CTX *ctx, RELAYPATH_STREAM *t, UINT i)
{
	RELAYPATH_LINK *l = &ctx->Links[i];

	if (RelayPathDecode(t) == false)
	{
		return;
	}

	switch (t->Message->which_body)
	{
	case ranz_control_v1_ControlMessage_ack_tag:
		InterlockedExchange64(&l->Acked, (LONG64)t->Message->body.ack.generation);
		break;

	case ranz_control_v1_ControlMessage_signal_tag:
		InterlockedIncrement64(&l->Signals);
		RelayPathCarry(ctx, i, &t->Message->body.signal);
		break;

	default:
		break;
	}
}

// One control stream at the stand-in: the handshake names its Node, which says Hello; then the Updates that the test posts
// for the Node, the Signals that the stand-in carries to it once it carries them, and the frames of the Node, until the
// stream ends or the test halts. One stream of a Node is served at a time.
static DWORD WINAPI RelayPathServe(LPVOID param)
{
	RELAYPATH_STREAM *t = (RELAYPATH_STREAM *)param;
	RELAYPATH_CTX *ctx = t->Ctx;
	RELAYPATH_LINK *l = NULL;
	UCHAR remote[PEER_KEY_SIZE];
	UINT i = RELAYPATH_NUM_NODES;
	UINT64 sent = 0;

	if (RelayPathHandshake(ctx, t, remote))
	{
		for (UINT j = 0;j < RELAYPATH_NUM_NODES && i == RELAYPATH_NUM_NODES;j++)
		{
			if (Cmp(remote, ctx->Nodes[j].Key.Public, PEER_KEY_SIZE) == 0)
			{
				i = j;
			}
		}
	}
	if (i < RELAYPATH_NUM_NODES && InterlockedCompareExchange(&ctx->Links[i].Active, 1, 0) == 0)
	{
		l = &ctx->Links[i];
	}

	bool ok = (l != NULL && RelayPathHello(t));
	if (ok)
	{
		InterlockedIncrement(&l->Streams);
	}

	while (ok && InterlockedCompareExchange(&ctx->Halt, 0, 0) == 0)
	{
		UINT64 posted = (UINT64)InterlockedCompareExchange64(&l->Posted, 0, 0);

		if (posted > sent)
		{
			RelayPathState(ctx, i, posted, t->Message);
			ok = RelayPathWrite(t);
			sent = posted;
		}
		if (ok && InterlockedCompareExchange(&ctx->Carry, 0, 0) != 0)
		{
			ok = ControlWriteSignals(l->Out, t->Stream);
		}
		if (ok == false)
		{
			break;
		}

		UINT r = RelayPathRead(t, RELAYPATH_READ);
		if (r == RELAYPATH_FRAME_END)
		{
			break;
		}
		if (r == RELAYPATH_FRAME_DONE)
		{
			RelayPathTake(ctx, t, i);
			t->FrameSize = 0;
		}
	}

	if (l != NULL)
	{
		InterlockedExchange(&l->Active, 0);
	}

	TransportClose(t->Stream);
	t->Stream = NULL;

	return 0;
}

// The thread of the stand-in that takes the control streams, one thread each
static DWORD WINAPI RelayPathAccept(LPVOID param)
{
	RELAYPATH_CTX *ctx = (RELAYPATH_CTX *)param;

	while (InterlockedCompareExchange(&ctx->Halt, 0, 0) == 0)
	{
		TRANSPORT_STREAM *s = TransportAccept(ctx->Listener, RELAYPATH_TICK);
		LONG n = InterlockedCompareExchange(&ctx->NumStreams, 0, 0);

		if (s == NULL)
		{
			continue;
		}
		if (n >= RELAYPATH_MAX_STREAMS)
		{
			TransportClose(s);
			continue;
		}

		RELAYPATH_STREAM *t = ZeroMalloc(sizeof(RELAYPATH_STREAM));
		t->Ctx = ctx;
		t->Stream = s;
		t->Frame = Malloc(RELAYPATH_MAX_FRAME);
		t->Out = Malloc(RELAYPATH_OUT_FRAME);
		t->Message = ZeroMalloc(sizeof(ranz_control_v1_ControlMessage));
		ctx->Streams[n] = t;
		InterlockedExchange(&ctx->NumStreams, n + 1);

		t->Thread = CreateThread(NULL, 0, RelayPathServe, t, 0, NULL);
		if (t->Thread == NULL)
		{
			TransportClose(t->Stream);
			t->Stream = NULL;
		}
	}

	return 0;
}

// The stand-in seals a Signal of its own to node-b in the name of node-a, naming a relay of its own, and carries it: false
// when it could not
static bool RelayPathForge(RELAYPATH_CTX *ctx)
{
	PEER_SIGNAL s;
	UCHAR *payload = Malloc(PEER_MAX_ENVELOPE);
	UCHAR env[PEER_MAX_ENVELOPE];
	UINT size = 0;

	Zero(&s, sizeof(s));
	s.Type = PEER_SIGNAL_OFFER;
	s.Sequence = 0xFFFFFFFFFFFFFF00ULL;
	Copy(s.RelayKey, ctx->ControllerKey.Public, PEER_KEY_SIZE);
	PeerAddrSetV4(&s.Relay, 192, 0, 2, 66, RELAYPATH_RELAY_PORT);

	UINT len = PeerSignalEncode(&s, payload, PEER_MAX_ENVELOPE);
	if (len != 0)
	{
		size = PeerEnvelopeSeal(&ctx->ControllerKey, ctx->Nodes[RELAYPATH_B].Key.Public, PEER_MSG_SIGNAL, NULL, payload, len, env, sizeof(env));
	}
	Free(payload);

	if (size == 0)
	{
		return false;
	}

	// ... in the name of node-a: the static key of the sender in the clear head of the envelope
	Copy(env + 1, ctx->Nodes[RELAYPATH_A].Key.Public, PEER_KEY_SIZE);

	return ControlSendSignal(ctx->Links[RELAYPATH_B].Out, relaypath_names[RELAYPATH_A], env, size);
}

// Post Generation g for node i: its stream sends it at once
static void RelayPathPost(RELAYPATH_CTX *ctx, UINT i, UINT64 g)
{
	InterlockedExchange64(&ctx->Links[i].Posted, (LONG64)g);
}

// Whether node i acknowledged Generation g within RELAYPATH_BOUND
static bool RelayPathWaitAck(RELAYPATH_CTX *ctx, UINT i, UINT64 g)
{
	for (UINT64 end = Tick64() + RELAYPATH_BOUND;Tick64() < end;SleepThread(RELAYPATH_POLL))
	{
		if ((UINT64)InterlockedCompareExchange64(&ctx->Links[i].Acked, 0, 0) >= g)
		{
			return true;
		}
	}

	return false;
}

// Post Generation g for every Node and wait for their acknowledgements
static bool RelayPathApply(RELAYPATH_CTX *ctx, UINT64 g)
{
	bool ok = true;

	for (UINT i = 0;i < RELAYPATH_NUM_NODES;i++)
	{
		RelayPathPost(ctx, i, g);
	}
	for (UINT i = 0;i < RELAYPATH_NUM_NODES;i++)
	{
		ok = RelayPathWaitAck(ctx, i, g) && ok;
	}

	return ok;
}

//
// The Nodes
//

// A new empty data directory under the temp directory of the process, with a configuration store that runs no role
// on one worker
static void RelayPathNewDir(wchar_t *dir, UINT size, char *name)
{
	wchar_t tmp[MAX_PATH];
	wchar_t path[MAX_PATH];

	UniFormat(tmp, sizeof(tmp), L"relaypathtest_%S_%u", name, Rand32());
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
static void RelayPathDeleteFiles(wchar_t *dir)
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

// The data transport dials a peer only at an endpoint: a Node behind a NAT, which names none, is dialled by no one
static bool RelayPathDialable(NODE *n, void *param, const char *name, const struct CONTROL_ENDPOINT *endpoints, UINT num)
{
	return (num != 0);
}

// The network of the simulator takes the peer layer of the agent of a Node, and NULL before it stops (NODE_PATH_ATTACH_PROC)
static void RelayPathAttach(NODE *n, void *param, PEER_AGENT *agent)
{
	RELAYPATH_NODE *t = (RELAYPATH_NODE *)param;

	NatSimAttach(t->Host, agent);
}

// Start node i: its data directory, its Node, and its overlay with the control stream to the stand-in, the data transport,
// the fake adapter of its host and the network of the simulator for its agent
static bool RelayPathStartNode(RELAYPATH_CTX *ctx, UINT i)
{
	RELAYPATH_NODE *t = &ctx->Nodes[i];
	NODE_OVERLAY_CONFIG c;
	char what[MAX_SIZE];

	RelayPathNewDir(t->Dir, sizeof(t->Dir), t->Name);
	t->Node = NewNode(t->Dir);
	NodeStart(t->Node);
	NodeReaderRegister(t->Node, &t->Reader);
	NodeReaderOffline(&t->Reader);

	Zero(&c, sizeof(c));
	c.Control = ctx->Control;
	StrCpy(c.Controller, sizeof(c.Controller), RELAYPATH_CONTROLLER);
	Copy(c.ControllerKey, ctx->ControllerKey.Public, PEER_KEY_SIZE);
	c.Data = ctx->Data;
	c.Key = &t->Key;
	c.Adapter = RelayPathAdapter;
	c.AdapterParam = t;
	c.Dialable = RelayPathDialable;
	c.PathSend = NatSimSend;
	c.PathSendParam = t->Host;
	c.PathAttach = RelayPathAttach;
	c.PathConfig = &ctx->PathConfig;

	Format(what, sizeof(what), "%s: its overlay runs, with its control stream to the stand-in of the Controller and its peer agent on the network of the simulator", t->Name);

	return RelayPathCheck(ctx, NodeOverlayStart(t->Node, &c), what, "NodeOverlayStart failed");
}

// The session of the peer name in the state of node i into s: false when the Node has no such peer
static bool RelayPathSession(RELAYPATH_CTX *ctx, UINT i, char *name, NODE_OVERLAY_SESSION *s)
{
	NODE_OVERLAY_SESSION list[RELAYPATH_NUM_NODES];
	UINT num = NodeOverlayGetSessions(ctx->Nodes[i].Node, list, RELAYPATH_NUM_NODES, NULL, 0);

	for (UINT k = 0;k < num && k < RELAYPATH_NUM_NODES;k++)
	{
		if (StrCmp(list[k].Name, name) == 0)
		{
			Copy(s, &list[k], sizeof(NODE_OVERLAY_SESSION));
			return true;
		}
	}

	Zero(s, sizeof(NODE_OVERLAY_SESSION));

	return false;
}

// Whether every Node is up within RELAYPATH_BOUND: node-a and node-b each have their Path to the other, each has its stream
// session to node-c, and relay-1 holds a Binding of every Node
static bool RelayPathWaitUp(RELAYPATH_CTX *ctx, char *detail, UINT detail_size)
{
	NODE_OVERLAY_STATUS st[RELAYPATH_NUM_NODES];
	PEER_STATS rs;
	bool ab = false, ba = false;

	Zero(st, sizeof(st));
	Zero(&rs, sizeof(rs));

	for (UINT64 end = Tick64() + RELAYPATH_BOUND;Tick64() < end;SleepThread(RELAYPATH_POLL))
	{
		for (UINT i = 0;i < RELAYPATH_NUM_NODES;i++)
		{
			NodeOverlayGetStatus(ctx->Nodes[i].Node, &st[i]);
		}
		RelayPathRelayStats(ctx, &rs);
		ab = NodeAgentHasPath(ctx->Nodes[RELAYPATH_A].Node, ctx->Nodes[RELAYPATH_B].Key.Public);
		ba = NodeAgentHasPath(ctx->Nodes[RELAYPATH_B].Node, ctx->Nodes[RELAYPATH_A].Key.Public);

		if (ab && ba && st[RELAYPATH_A].NumLinks == 1 && st[RELAYPATH_B].NumLinks == 1 && st[RELAYPATH_C].NumLinks == 2 && rs.NumBindings == RELAYPATH_NUM_NODES)
		{
			return true;
		}
	}

	Format(detail, detail_size, "path of node-a to node-b %u, of node-b to node-a %u; stream sessions: node-a %u, node-b %u, node-c %u; Bindings at relay-1 %u", (UINT)ab, (UINT)ba,
		st[RELAYPATH_A].NumLinks, st[RELAYPATH_B].NumLinks, st[RELAYPATH_C].NumLinks, rs.NumBindings);

	return false;
}

//
// The steps
//

// a. Bring-up: the control streams say Hello; node-c gets Generation 1 first and listens on the data transport, then node-a
// and node-b get theirs; the stand-in carries the Signals from then on, and the pairs come up
static bool RelayPathBringUp(RELAYPATH_CTX *ctx)
{
	char detail[MAX_SIZE * 2];
	char listener[TRANSPORT_NAME_SIZE];
	bool hello = false;

	Print("[a. bring-up: Generation 1 on the control streams, the Signals through the stand-in, the Path through relay-1]\n");

	for (UINT64 end = Tick64() + RELAYPATH_BOUND;Tick64() < end && hello == false;SleepThread(RELAYPATH_POLL))
	{
		hello = true;
		for (UINT i = 0;i < RELAYPATH_NUM_NODES;i++)
		{
			hello = hello && (InterlockedCompareExchange(&ctx->Links[i].Streams, 0, 0) != 0);
		}
	}
	if (RelayPathCheck(ctx, hello, "Every Node opens its control stream to the stand-in of the Controller: the handshake bound to the exporter, then its Hello", "not every Node said Hello") == false)
	{
		return false;
	}

	// node-c listens before the others dial it
	RelayPathPost(ctx, RELAYPATH_C, 1);
	bool acked = RelayPathWaitAck(ctx, RELAYPATH_C, 1);
	bool listening = false;
	for (UINT64 end = Tick64() + RELAYPATH_BOUND;acked && Tick64() < end && listening == false;SleepThread(RELAYPATH_POLL))
	{
		NodeOverlayGetSessions(ctx->Nodes[RELAYPATH_C].Node, NULL, 0, listener, sizeof(listener));
		listening = (StrCmp(listener, ctx->Data->Name) == 0);
	}
	RelayPathPost(ctx, RELAYPATH_A, 1);
	RelayPathPost(ctx, RELAYPATH_B, 1);
	acked = RelayPathWaitAck(ctx, RELAYPATH_A, 1) && RelayPathWaitAck(ctx, RELAYPATH_B, 1) && acked;
	if (RelayPathCheck(ctx, acked && listening, "Every Node applies Generation 1 from its control stream and acknowledges it, and node-c listens on the data transport",
		"acknowledged %u, node-c listening %u", (UINT)acked, (UINT)listening) == false)
	{
		return false;
	}

	InterlockedExchange(&ctx->Carry, 1);

	bool up = RelayPathWaitUp(ctx, detail, sizeof(detail));
	RelayPathCheck(ctx, up, "node-a and node-b come up through relay-1 after their Signals, and each has its stream session to node-c; relay-1 binds the three Nodes", "%s", detail);

	return up;
}

// b. Signals: on the control streams, carried by the stand-in, which can neither read nor alter one, nor forge one
static void RelayPathSignals(RELAYPATH_CTX *ctx)
{
	NODE_AGENT_STATUS a, b;
	NODE_OVERLAY_SESSION s;

	Print("[b. Signals: on the control streams, carried by the Controller, which can neither read nor alter them]\n");

	NodeAgentGetStatus(ctx->Nodes[RELAYPATH_A].Node, &a);
	NodeAgentGetStatus(ctx->Nodes[RELAYPATH_B].Node, &b);
	UINT64 from_a = (UINT64)InterlockedCompareExchange64(&ctx->Links[RELAYPATH_A].Signals, 0, 0);
	UINT64 from_b = (UINT64)InterlockedCompareExchange64(&ctx->Links[RELAYPATH_B].Signals, 0, 0);
	UINT64 carried = (UINT64)InterlockedCompareExchange64(&ctx->Carried, 0, 0);

	RelayPathCheck(ctx, a.SignalsSent != 0 && b.SignalsSent != 0 && from_a != 0 && from_b != 0 && carried >= 2,
		"node-a and node-b send their Signals on their control streams, and the stand-in carries each to the peer that it names",
		"node-a sent %I64u and the stand-in read %I64u of them; node-b %I64u and %I64u; %I64u carried", a.SignalsSent, from_a, b.SignalsSent, from_b, carried);
	RelayPathCheck(ctx, a.SignalsTaken != 0 && b.SignalsTaken != 0, "node-a and node-b take the Signals that came whole through the Controller",
		"node-a took %I64u, node-b %I64u", a.SignalsTaken, b.SignalsTaken);

	UINT64 inspected = (UINT64)InterlockedCompareExchange64(&ctx->Inspected, 0, 0);
	UINT64 readable = (UINT64)InterlockedCompareExchange64(&ctx->Readable, 0, 0);
	UINT64 opened = (UINT64)InterlockedCompareExchange64(&ctx->Opened, 0, 0);
	RelayPathCheck(ctx, inspected >= 2 && readable == 0 && opened == 0,
		"The Controller cannot read a Signal: no envelope that it carried holds the static key or the address of relay-1, which every Signal names, and its own static key opens none",
		"%I64u envelopes, %I64u with relay-1 in the clear, %I64u opened", inspected, readable, opened);

	// A Signal that a Node sealed before its peer took the state that names it can also be dropped as a replay (the floor of a
	// new peer, PeerFloorOf): only the forged ones are the stand-in's doing
	UINT64 altered = (UINT64)InterlockedCompareExchange64(&ctx->Altered, 0, 0);
	RelayPathCheck(ctx, altered == 1 && b.SignalsDropped >= 1 && b.Peer.Drops[PEER_DROP_FORGED] == 1 && a.Peer.Drops[PEER_DROP_FORGED] == 0,
		"The Controller cannot alter a Signal: node-b drops the first Signal of node-a, whose envelope the stand-in altered on the way, as forged",
		"%I64u altered; node-b dropped %I64u Signals, %I64u envelopes as forged; node-a %I64u as forged", altered, b.SignalsDropped, b.Peer.Drops[PEER_DROP_FORGED],
		a.Peer.Drops[PEER_DROP_FORGED]);

	// A Signal that the stand-in sealed itself in the name of node-a, which names a relay of its own
	bool forged = RelayPathForge(ctx);
	bool dropped = false;
	for (UINT64 end = Tick64() + RELAYPATH_BOUND;forged && Tick64() < end && dropped == false;SleepThread(RELAYPATH_POLL))
	{
		NODE_AGENT_STATUS now;

		NodeAgentGetStatus(ctx->Nodes[RELAYPATH_B].Node, &now);
		dropped = (now.SignalsDropped == b.SignalsDropped + 1 && now.Peer.Drops[PEER_DROP_FORGED] == b.Peer.Drops[PEER_DROP_FORGED] + 1);
	}
	RelayPathSession(ctx, RELAYPATH_B, relaypath_names[RELAYPATH_A], &s);
	RelayPathCheck(ctx, forged && dropped && s.Path == NODE_PATH_RELAY,
		"The Controller cannot forge a Signal: node-b drops as forged one that the stand-in sealed in the name of node-a, naming a relay of its own, and still reaches node-a through relay-1",
		"sealed %u, dropped %u, path of node-a at node-b %s", (UINT)forged, (UINT)dropped, NodeAgentPathName(s.Path));
}

// c. Data: echoes between the hosts of node-a and node-b through relay-1, one of the MTU of the VRF, and between node-a and
// node-c on their stream session; nothing of them in the clear on any link
static void RelayPathData(RELAYPATH_CTX *ctx)
{
	PEER_STATS before, after;
	char detail[MAX_SIZE * 2];
	char what[MAX_SIZE];
	UINT ok = 0;

	Print("[c. data: the hosts of node-a and node-b through relay-1, node-a and node-c on their stream session]\n");

	RelayPathRelayStats(ctx, &before);

	for (UINT k = 0;k < RELAYPATH_ECHOES;k++)
	{
		if (RelayPathEcho(ctx, RELAYPATH_A, RELAYPATH_B, (USHORT)(40000 + k), RelayPathSmall(), detail, sizeof(detail)))
		{
			ok++;
		}
		else
		{
			Print("  [INFO] echo %u: %s\n", k, detail);
		}
	}
	RelayPathRelayStats(ctx, &after);
	Format(what, sizeof(what), "%u packets of the host of node-a reach the host of node-b in VRF default, whose policy allows them, and come back, through relay-1", (UINT)RELAYPATH_ECHOES);
	RelayPathCheck(ctx, ok == RELAYPATH_ECHOES && after.Forwarded >= before.Forwarded + 2 * RELAYPATH_ECHOES, what, "%u of %u came back; relay-1 forwarded %I64u records",
		ok, (UINT)RELAYPATH_ECHOES, after.Forwarded - before.Forwarded);

	bool mtu = RelayPathEcho(ctx, RELAYPATH_A, RELAYPATH_B, 40010, RELAYPATH_MTU, detail, sizeof(detail));
	Format(what, sizeof(what), "A packet of the MTU of the VRF, %u bytes, goes on the datagram path both ways", (UINT)RELAYPATH_MTU);
	RelayPathCheck(ctx, mtu, what, "%s", detail);

	bool stream = RelayPathEcho(ctx, RELAYPATH_A, RELAYPATH_C, 40020, RelayPathSmall(), detail, sizeof(detail));
	RelayPathCheck(ctx, stream, "At the same time node-a reaches node-c, which has an endpoint, on its stream session, and back", "%s", detail);

	UINT64 captured = (UINT64)InterlockedCompareExchange64(&ctx->Captured, 0, 0);
	UINT64 clear = (UINT64)InterlockedCompareExchange64(&ctx->Clear, 0, 0);
	bool every = true;
	for (UINT k = 0;k < RELAYPATH_NUM_LINKS;k++)
	{
		UINT64 records = (UINT64)InterlockedCompareExchange64(&ctx->Records[k], 0, 0);

		Print("  [INFO] the capture saw %I64u records of peer sessions on the link %s\n", records, relaypath_links[k]);
		every = every && (records != 0);
	}
	RelayPathCheck(ctx, captured != 0 && every && clear == 0,
		"A capture of every datagram on every link, the records of the peer session on each link of node-a and node-b with relay-1 among them, shows no 8 bytes in a row of the packets in the clear",
		"%I64u datagrams, %I64u with 8 bytes of a packet in the clear, records on every link %u", captured, clear, (UINT)every);
}

// d. The counters of each peer: its path, relay or stream, and the records of the overlay that went each way on the
// datagram path
static void RelayPathCounters(RELAYPATH_CTX *ctx)
{
	NODE_OVERLAY_SESSION ab, ac, ba, bc;
	UINT64 n = RELAYPATH_ECHOES + 1;

	Print("[d. counters: the path of each peer and the datagrams each way]\n");

	bool found = RelayPathSession(ctx, RELAYPATH_A, relaypath_names[RELAYPATH_B], &ab) && RelayPathSession(ctx, RELAYPATH_A, relaypath_names[RELAYPATH_C], &ac) &&
		RelayPathSession(ctx, RELAYPATH_B, relaypath_names[RELAYPATH_A], &ba) && RelayPathSession(ctx, RELAYPATH_B, relaypath_names[RELAYPATH_C], &bc);

	Print("  [INFO] node-a: node-b path %s, up %u, %I64u datagrams out, %I64u in; node-c path %s, up %u over %s, %I64u out, %I64u in\n", NodeAgentPathName(ab.Path), (UINT)ab.Up,
		ab.DatagramsOut, ab.DatagramsIn, NodeAgentPathName(ac.Path), (UINT)ac.Up, ac.Transport, ac.DatagramsOut, ac.DatagramsIn);

	RelayPathCheck(ctx, found && ab.Up == false && ab.Path == NODE_PATH_RELAY && ac.Up && ac.Path == NODE_PATH_STREAM && StrCmp(ac.Transport, ctx->Data->Name) == 0,
		"node-a holds both kinds at the same time: node-b on the datagram path through relay-1, node-c, which has an endpoint, on its stream session",
		"node-b %s (up %u), node-c %s (up %u, over %s)", NodeAgentPathName(ab.Path), (UINT)ab.Up, NodeAgentPathName(ac.Path), (UINT)ac.Up, ac.Transport);
	RelayPathCheck(ctx, found && ba.Path == NODE_PATH_RELAY && bc.Path == NODE_PATH_STREAM, "node-b too: node-a through relay-1, node-c on its stream session",
		"node-a %s, node-c %s", NodeAgentPathName(ba.Path), NodeAgentPathName(bc.Path));
	RelayPathCheck(ctx, ab.DatagramsOut == n && ab.DatagramsIn == n && ba.DatagramsOut == n && ba.DatagramsIn == n && ac.DatagramsOut == 0 && ac.DatagramsIn == 0 && bc.DatagramsOut == 0 && bc.DatagramsIn == 0,
		"The counters of each peer say how many records went each way on the datagram path, and none for a peer on its stream session",
		"node-a to node-b %I64u out, %I64u in; node-b to node-a %I64u out, %I64u in; node-c %I64u and %I64u at node-a, %I64u and %I64u at node-b; %I64u each way expected", ab.DatagramsOut,
		ab.DatagramsIn, ba.DatagramsOut, ba.DatagramsIn, ac.DatagramsOut, ac.DatagramsIn, bc.DatagramsOut, bc.DatagramsIn, n);

	// The answer of the admin pipe of node-a to state, which ranz node state prints: the entry of node-b, whole, and the path
	// and the datagrams of node-c, after its age
	char *reply = ZeroMalloc(NODE_ADMIN_REPLY);
	char relay[MAX_SIZE];
	NodeAdminCommand(ctx->Nodes[RELAYPATH_A].Node, "state", reply, NODE_ADMIN_REPLY);
	Format(relay, sizeof(relay), "{\"peer\":\"node-b\",\"up\":false,\"transport\":\"\",\"ageSeconds\":0,\"path\":\"relay\",\"datagramsOut\":%I64u,\"datagramsIn\":%I64u}", n, n);
	bool shown = InStr(reply, relay) && InStr(reply, "{\"peer\":\"node-c\",\"up\":true,") && InStr(reply, "\"path\":\"stream\",\"datagramsOut\":0,\"datagramsIn\":0}");
	UINT sessions = SearchStr(reply, "\"sessions\":", 0);
	RelayPathCheck(ctx, shown,
		"The state of node-a, as its admin pipe answers it and ranz node state prints it, says the path of each peer, relay for node-b with the datagrams each way and stream for node-c",
		"the answer from its sessions on is %s", (sessions != INFINITE ? reply + sessions : reply));
	Free(reply);
}

// What stays the same at a Node across the restart of relay-1 and the quiet time of the NATs
typedef struct RELAYPATH_SAME
{
	UINT64 Generation;		// The Generation that its overlay runs
	UINT64 Since;			// Since when its control stream is open
	LONG Streams;			// The control streams that the stand-in served for it
	UINT64 SignalsSent;		// The Signals that its agent sent
	UINT64 Handshakes;		// The handshakes of its peer sessions
} RELAYPATH_SAME;

static void RelayPathSnapshot(RELAYPATH_CTX *ctx, UINT i, RELAYPATH_SAME *s)
{
	NODE_OVERLAY_STATUS os;
	NODE_AGENT_STATUS as;

	NodeOverlayGetStatus(ctx->Nodes[i].Node, &os);
	NodeAgentGetStatus(ctx->Nodes[i].Node, &as);

	s->Generation = os.Generation;
	s->Since = os.Since;
	s->Streams = InterlockedCompareExchange(&ctx->Links[i].Streams, 0, 0);
	s->SignalsSent = as.SignalsSent;
	s->Handshakes = as.Peer.Handshakes;
}

// Whether node i is as it was: no restart, no new control stream, no new Signal, the same peer session
static bool RelayPathSame(RELAYPATH_CTX *ctx, UINT i, const RELAYPATH_SAME *before, char *detail, UINT detail_size)
{
	RELAYPATH_SAME now;

	RelayPathSnapshot(ctx, i, &now);
	Format(detail, detail_size, "%s: Generation %I64u and %I64u, control streams %u and %u, Signals sent %I64u and %I64u, handshakes %I64u and %I64u", relaypath_names[i], before->Generation,
		now.Generation, (UINT)before->Streams, (UINT)now.Streams, before->SignalsSent, now.SignalsSent, before->Handshakes, now.Handshakes);

	return (now.Generation == before->Generation && now.Since == before->Since && now.Streams == before->Streams && now.SignalsSent == before->SignalsSent &&
		now.Handshakes == before->Handshakes);
}

// e. Relay restart: relay-1 starts again with no Binding, the keepalives of the Nodes bind it again, and the packets go on
static void RelayPathRestart(RELAYPATH_CTX *ctx)
{
	RELAYPATH_SAME a, b;
	PEER_STATS st;
	char detail[MAX_SIZE * 2];
	char what[MAX_SIZE];

	Print("[e. relay restart: the Bindings come back from the keepalives, and the traffic goes on]\n");

	RelayPathSnapshot(ctx, RELAYPATH_A, &a);
	RelayPathSnapshot(ctx, RELAYPATH_B, &b);

	// A new peer layer of the relay role, with a new secret of its bind challenges and no Binding, as after a restart of the
	// Node of relay-1
	RelayPathRelayStop(ctx);
	bool started = RelayPathRelayStart(ctx);
	RelayPathCheck(ctx, started, "relay-1 restarts, with no Binding", "its peer layer did not start");

	bool bound = (started && RelayPathWaitBindings(ctx));
	RelayPathRelayStats(ctx, &st);
	Format(what, sizeof(what), "The next keepalive of each Node, %u ms apart, binds it again: the restarted relay-1 challenged each stale cookie, and each Node answered at once", (UINT)RELAYPATH_BIND);
	RelayPathCheck(ctx, bound && st.NumBindings == RELAYPATH_NUM_NODES && st.Binds >= RELAYPATH_NUM_NODES && st.Challenges >= RELAYPATH_NUM_NODES, what,
		"bound %u, %u Bindings, %I64u binds, %I64u challenges", (UINT)bound, st.NumBindings, st.Binds, st.Challenges);

	bool echo = RelayPathEcho(ctx, RELAYPATH_A, RELAYPATH_B, 40030, RelayPathSmall(), detail, sizeof(detail));
	RelayPathRelayStats(ctx, &st);
	RelayPathCheck(ctx, echo && st.Forwarded >= 2, "The traffic goes on through the restarted relay-1", "%s; it forwarded %I64u records", detail, st.Forwarded);

	bool same = RelayPathSame(ctx, RELAYPATH_A, &a, detail, sizeof(detail));
	RelayPathCheck(ctx, same, "node-a did not restart: the same Generation and control stream, no new Signal, the same peer session with node-b", "%s", detail);
	same = RelayPathSame(ctx, RELAYPATH_B, &b, detail, sizeof(detail));
	RelayPathCheck(ctx, same, "node-b did not restart either", "%s", detail);
}

// f. NAT ageing: the quiet time of three NAT timeouts ends no path, as the keepalive of each Node keeps its mapping
static void RelayPathAgeing(RELAYPATH_CTX *ctx)
{
	PEER_ADDR probe, pub_a, pub_b, now_a, now_b;
	PEER_STATS before, after;
	RELAYPATH_SAME a, b;
	char detail[MAX_SIZE * 2];
	char what[MAX_SIZE];

	Print("[f. NAT ageing: the keepalives keep the mappings to relay-1 through a quiet time]\n");

	bool mapped = NatSimMapped(ctx->NatA, &ctx->Nodes[RELAYPATH_A].Addr, &pub_a) && NatSimMapped(ctx->NatB, &ctx->Nodes[RELAYPATH_B].Addr, &pub_b);
	UINT expired_a = NatSimExpired(ctx->NatA);
	UINT expired_b = NatSimExpired(ctx->NatB);
	RelayPathSnapshot(ctx, RELAYPATH_A, &a);
	RelayPathSnapshot(ctx, RELAYPATH_B, &b);
	RelayPathRelayStats(ctx, &before);

	// A datagram of the host of node-b to an address that sends nothing back: a mapping that carries nothing more
	PeerAddrSetV4(&probe, 198, 51, 100, 99, 9);
	NatSimSend(ctx->Nodes[RELAYPATH_B].Host, &probe, "probe", 5);

	SleepThread(RELAYPATH_QUIET);

	bool aged = false;
	for (UINT64 end = Tick64() + RELAYPATH_BOUND;Tick64() < end && aged == false;SleepThread(RELAYPATH_POLL))
	{
		aged = (NatSimExpired(ctx->NatB) > expired_b);
	}
	mapped = mapped && NatSimMapped(ctx->NatA, &ctx->Nodes[RELAYPATH_A].Addr, &now_a) && NatSimMapped(ctx->NatB, &ctx->Nodes[RELAYPATH_B].Addr, &now_b);
	RelayPathRelayStats(ctx, &after);

	Format(what, sizeof(what), "The NAT of node-b ages a mapping that carried nothing out for %u ms", (UINT)RELAYPATH_NAT_TIMEOUT);
	RelayPathCheck(ctx, aged && NatSimExpired(ctx->NatB) == expired_b + 1, what, "%u mappings aged out of %u before", NatSimExpired(ctx->NatB), expired_b);

	Format(what, sizeof(what), "Through a quiet time of %u ms the keepalive of each Node, every %u ms, kept its mapping to relay-1: the same public port, and its Binding", (UINT)RELAYPATH_QUIET,
		(UINT)RELAYPATH_BIND);
	RelayPathCheck(ctx, mapped && PeerAddrEqual(&pub_a, &now_a) && PeerAddrEqual(&pub_b, &now_b) && NatSimExpired(ctx->NatA) == expired_a && after.NumBindings == RELAYPATH_NUM_NODES &&
		after.Binds >= before.Binds + RELAYPATH_NUM_NODES, what, "mapped %u, port of node-a %u and %u, of node-b %u and %u, %u mappings of the NAT of node-a aged, %u Bindings, %I64u binds",
		(UINT)mapped, (UINT)pub_a.Port, (UINT)now_a.Port, (UINT)pub_b.Port, (UINT)now_b.Port, NatSimExpired(ctx->NatA) - expired_a, after.NumBindings, after.Binds - before.Binds);

	bool echo = RelayPathEcho(ctx, RELAYPATH_A, RELAYPATH_B, 40040, RelayPathSmall(), detail, sizeof(detail));
	RelayPathCheck(ctx, echo, "The path did not end: the packets go through relay-1 after the quiet time", "%s", detail);

	char detail_b[MAX_SIZE * 2];
	bool same_a = RelayPathSame(ctx, RELAYPATH_A, &a, detail, sizeof(detail));
	bool same_b = RelayPathSame(ctx, RELAYPATH_B, &b, detail_b, sizeof(detail_b));
	RelayPathCheck(ctx, same_a && same_b, "... with no new Signal and the same peer session at node-a and node-b", "%s; %s", detail, detail_b);
}

// g. Policy: a rule that denies a pair blocks it on the datagram path as on the stream path, at the sender and at the
// receiver
static RELAYPATH_STEP relaypath_deny[] =
{
	{RELAYPATH_A, RELAYPATH_B, 41000, RELAYPATH_DROPPED_SENDER, "deny-a of Generation 2 denies node-a to node-b: node-a drops the packet before the datagram path"},
	{RELAYPATH_A, RELAYPATH_C, 41001, RELAYPATH_DROPPED_SENDER, "... and node-a to node-c: node-a drops the packet before the stream session"},
	{RELAYPATH_B, RELAYPATH_A, 41002, RELAYPATH_DELIVERED, "deny-a goes from node-a: node-b still reaches node-a through relay-1"},
};

static RELAYPATH_STEP relaypath_receiver[] =
{
	{RELAYPATH_A, RELAYPATH_B, 42000, RELAYPATH_DROPPED_RECEIVER, "In Generation 3 only node-b and node-c hold deny-a: node-b drops what node-a sent it on the datagram path"},
	{RELAYPATH_A, RELAYPATH_C, 42001, RELAYPATH_DROPPED_RECEIVER, "... and node-c drops what node-a sent it on the stream session"},
};

static void RelayPathSteps(RELAYPATH_CTX *ctx, RELAYPATH_STEP *steps, UINT num)
{
	UCHAR packet[RELAYPATH_MTU];

	for (UINT k = 0;k < num;k++)
	{
		RELAYPATH_STEP *s = &steps[k];
		UINT size = RelayPathPacket(packet, s->From, s->To, s->Port, RELAYPATH_ECHO_PORT, RelayPathSmall());
		UINT got = RelayPathDeliver(ctx, s->From, s->To, packet, size);

		RelayPathCheck(ctx, got == s->Expect, s->What, "%s, %s expected", RelayPathOutcome(got), RelayPathOutcome(s->Expect));
	}
}

static void RelayPathPolicy(RELAYPATH_CTX *ctx)
{
	NODE_OVERLAY_SESSION before, after;

	Print("[g. policy: a rule that denies a pair blocks it on the datagram path as on the stream path]\n");

	RelayPathCheck(ctx, RelayPathApply(ctx, 2), "Every Node applies Generation 2, with deny-a", "not acknowledged");
	RelayPathSteps(ctx, relaypath_deny, sizeof(relaypath_deny) / sizeof(relaypath_deny[0]));

	RelayPathCheck(ctx, RelayPathApply(ctx, 3), "Every Node applies Generation 3, with deny-a at node-b and node-c only", "not acknowledged");
	RelayPathSession(ctx, RELAYPATH_A, relaypath_names[RELAYPATH_B], &before);
	RelayPathSteps(ctx, relaypath_receiver, sizeof(relaypath_receiver) / sizeof(relaypath_receiver[0]));
	RelayPathSession(ctx, RELAYPATH_A, relaypath_names[RELAYPATH_B], &after);
	RelayPathCheck(ctx, after.DatagramsOut == before.DatagramsOut + 1, "The packet that node-b dropped went from node-a on the datagram path, through relay-1",
		"%I64u records out before, %I64u after", before.DatagramsOut, after.DatagramsOut);
}

//
// The world
//

// Build the world: the keys, the network of the simulator with its NATs, its tap and relay-1, the transports, the stand-in of
// the Controller and the three Nodes
static bool RelayPathStart(RELAYPATH_CTX *ctx)
{
	UCHAR scalar[PEER_KEY_SIZE];
	bool ok = true;

	// The static keys: the scalars 1, 2, ... of the conformance tests for the Nodes, others for relay-1 and the Controller
	for (UINT i = 0;i < RELAYPATH_NUM_NODES + 2;i++)
	{
		PEER_KEY *k = (i < RELAYPATH_NUM_NODES ? &ctx->Nodes[i].Key : (i == RELAYPATH_NUM_NODES ? &ctx->RelayKey : &ctx->ControllerKey));

		for (UINT j = 0;j < PEER_KEY_SIZE;j++)
		{
			scalar[j] = (UCHAR)(1 + PEER_KEY_SIZE * (i < RELAYPATH_NUM_NODES ? i : i + 1) + j);
		}
		ok = PeerKeyFromScalar(k, scalar) && ok;
	}
	Zero(scalar, sizeof(scalar));
	if (RelayPathCheck(ctx, ok, "The static keys of the Nodes, relay-1 and the Controller", "PeerKeyFromScalar failed") == false)
	{
		return false;
	}

	// The network: node-a behind a NAT of endpoint independent mapping, node-b behind a symmetric NAT, both with address and
	// port dependent filtering and ageing mappings; node-c and relay-1 on the public side
	ctx->Sim = NatSimNew();
	if (RelayPathCheck(ctx, ctx->Sim != NULL, "The network of the NAT simulator", "NatSimNew failed") == false)
	{
		return false;
	}
	RelayPathWindows(ctx);
	NatSimSetTap(ctx->Sim, RelayPathTap, ctx);

	ctx->NatA = NatSimAddNat(ctx->Sim, 203, 0, 113, 10, NATSIM_MAP_ENDPOINT_INDEPENDENT, NATSIM_FILTER_ADDRESS_PORT_DEPENDENT);
	ctx->NatB = NatSimAddNat(ctx->Sim, 203, 0, 113, 20, NATSIM_MAP_ADDRESS_PORT_DEPENDENT, NATSIM_FILTER_ADDRESS_PORT_DEPENDENT);
	PeerAddrSetV4(&ctx->PublicA, 203, 0, 113, 10, 0);
	PeerAddrSetV4(&ctx->PublicB, 203, 0, 113, 20, 0);
	NatSimSetTimeout(ctx->Sim, ctx->NatA, RELAYPATH_NAT_TIMEOUT);
	NatSimSetTimeout(ctx->Sim, ctx->NatB, RELAYPATH_NAT_TIMEOUT);

	for (UINT i = 0;i < RELAYPATH_NUM_NODES;i++)
	{
		RELAYPATH_NODE *t = &ctx->Nodes[i];

		t->Name = relaypath_names[i];
		InitializeSRWLock(&t->Lock);
		if (i == RELAYPATH_C)
		{
			PeerAddrSetV4(&t->Addr, 198, 51, 100, 3, 4000);
		}
		else
		{
			PeerAddrSetV4(&t->Addr, 10, 0, 0, 2, 5000);
		}
		t->Nat = (i == RELAYPATH_A ? ctx->NatA : (i == RELAYPATH_B ? ctx->NatB : NULL));
		t->Host = NatSimAddHost(ctx->Sim, t->Nat, &t->Addr);
		ok = (t->Host != NULL) && ok;
	}

	PeerAddrSetV4(&ctx->RelayAddr, 198, 51, 100, 1, RELAYPATH_RELAY_PORT);
	ctx->RelayHost = NatSimAddHost(ctx->Sim, NULL, &ctx->RelayAddr);
	InitializeSRWLock(&ctx->RelayLock);
	PeerDefaultConfig(&ctx->RelayConfig);
	ctx->RelayConfig.Relay = true;
	ctx->RelayConfig.BindExpiry = RELAYPATH_EXPIRY;
	ok = ok && ctx->RelayHost != NULL && RelayPathRelayStart(ctx);
	ctx->Ticker = (ok ? CreateThread(NULL, 0, RelayPathTicker, ctx, 0, NULL) : NULL);
	if (RelayPathCheck(ctx, ok && ctx->Ticker != NULL, "The hosts of the network, and relay-1, the peer layer of the relay role, on its host",
		"a host or relay-1 could not start") == false)
	{
		return false;
	}

	// The peer layer of the agents: the keepalive of the Bindings in the time of a test
	PeerDefaultConfig(&ctx->PathConfig);
	ctx->PathConfig.BindInterval = RELAYPATH_BIND;
	ctx->PathConfig.BindRetry = RELAYPATH_BIND_RETRY;

	// The transports, and the stand-in of the Controller, which listens on the bound one
	ctx->Data = TransportLoopbackNew("loopback", 0, false);
	ctx->Control = TransportLoopbackNew("control", 0, true);
	ctx->Listener = (ctx->Control != NULL ? TransportListen(ctx->Control, RELAYPATH_CONTROLLER) : NULL);
	for (UINT i = 0;i < RELAYPATH_NUM_NODES;i++)
	{
		ctx->Links[i].Out = ControlNewSignals();
		ok = (ctx->Links[i].Out != NULL) && ok;
	}
	InterlockedExchange(&ctx->Tamper, 1);
	ctx->Acceptor = (ok && ctx->Data != NULL && ctx->Listener != NULL ? CreateThread(NULL, 0, RelayPathAccept, ctx, 0, NULL) : NULL);
	if (RelayPathCheck(ctx, ctx->Acceptor != NULL, "The stand-in of the Controller listens on the bound loopback transport of the control streams", "it could not start") == false)
	{
		return false;
	}

	for (UINT i = 0;i < RELAYPATH_NUM_NODES;i++)
	{
		ok = RelayPathStartNode(ctx, i) && ok;
	}

	return ok;
}

// Stop the world: the Nodes first, which close their control streams and leave the network, then the stand-in, relay-1 and
// the network, and delete what the test made
static void RelayPathStop(RELAYPATH_CTX *ctx)
{
	for (UINT i = 0;i < RELAYPATH_NUM_NODES;i++)
	{
		RELAYPATH_NODE *t = &ctx->Nodes[i];
		wchar_t log_dir[MAX_PATH];

		if (t->Node != NULL)
		{
			NodeReaderUnregister(t->Node, &t->Reader);
			NodeStop(t->Node);
			FreeNode(t->Node);
			t->Node = NULL;
			ConbinePathW(log_dir, sizeof(log_dir), t->Dir, NODE_LOG_DIR_NAME);
			RelayPathDeleteFiles(log_dir);
			RelayPathDeleteFiles(t->Dir);
		}
	}

	InterlockedExchange(&ctx->Halt, 1);

	if (ctx->Listener != NULL)
	{
		TransportCloseListener(ctx->Listener);
	}
	if (ctx->Acceptor != NULL)
	{
		WaitForSingleObject(ctx->Acceptor, INFINITE);
		CloseHandle(ctx->Acceptor);
	}
	for (LONG i = 0;i < InterlockedCompareExchange(&ctx->NumStreams, 0, 0);i++)
	{
		RELAYPATH_STREAM *t = ctx->Streams[i];

		if (t->Thread != NULL)
		{
			WaitForSingleObject(t->Thread, INFINITE);
			CloseHandle(t->Thread);
		}
		if (t->Stream != NULL)
		{
			TransportClose(t->Stream);
		}
		Free(t->Frame);
		Free(t->Out);
		Free(t->Message);
		Free(t);
	}
	for (UINT i = 0;i < RELAYPATH_NUM_NODES;i++)
	{
		ControlFreeSignals(ctx->Links[i].Out);
	}

	if (ctx->Ticker != NULL)
	{
		WaitForSingleObject(ctx->Ticker, INFINITE);
		CloseHandle(ctx->Ticker);
	}
	if (ctx->RelayHost != NULL)
	{
		RelayPathRelayStop(ctx);
	}
	NatSimFree(ctx->Sim);

	if (ctx->Data != NULL)
	{
		TransportLoopbackFree(ctx->Data);
	}
	if (ctx->Control != NULL)
	{
		TransportLoopbackFree(ctx->Control);
	}

	for (UINT i = 0;i < RELAYPATH_NUM_NODES;i++)
	{
		PeerKeyClose(&ctx->Nodes[i].Key);
	}
	PeerKeyClose(&ctx->RelayKey);
	PeerKeyClose(&ctx->ControllerKey);
}

// relaypath: two Nodes behind NATs exchange the packets of their hosts through a Relay
RANZ_TEST_TAGS("relaypath", relaypath_test, "core", "Relay path of the new core (CORE-S5-5): two Nodes behind NATs of the simulator exchange the packets of their hosts through a Relay, with their Signals on the control streams of a stand-in Controller that can neither read nor alter them, a stream session beside, a Relay restart, ageing NATs and a deny rule on both paths.");
void relaypath_test(UINT num, char **arg)
{
	RELAYPATH_CTX *ctx = ZeroMalloc(sizeof(RELAYPATH_CTX));
	HANDLE done = CreateEventW(NULL, TRUE, FALSE, NULL);
	HANDLE watchdog = (done != NULL ? CreateThread(NULL, 0, RelayPathWatchdog, done, 0, NULL) : NULL);

	Print("Relay path test: two Nodes behind NATs exchange packets through a Relay, with their Signals on the control stream\n");

	if (RelayPathCheck(ctx, CryptoInit(), "The crypto module of the new core runs on CNG", "CryptoInit failed") && RelayPathStart(ctx) && RelayPathBringUp(ctx))
	{
		RelayPathSignals(ctx);
		RelayPathData(ctx);
		RelayPathCounters(ctx);
		RelayPathRestart(ctx);
		RelayPathAgeing(ctx);
		RelayPathPolicy(ctx);

		UINT64 clear = (UINT64)InterlockedCompareExchange64(&ctx->Clear, 0, 0);
		RelayPathCheck(ctx, clear == 0, "Over the whole run no datagram on any link held 8 bytes in a row of a packet of a host in the clear", "%I64u did", clear);
	}

	RelayPathStop(ctx);

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
		Print("RELAYPATH TEST OK\n");
	}
	else
	{
		Print("RELAYPATH TEST FAILED (%u of %u checks failed)\n", ctx->NumFailed, ctx->NumChecks);
	}

	Free(ctx);
}
