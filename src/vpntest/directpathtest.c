// directpathtest.c
// Named direct path test of vpntest ("directpath" command, CORE-S5-6 #412)
//
// A pair of Nodes that starts on the Relay moves to a direct path when ICE finds one, and back to the Relay when that path
// dies (the peer agent of the overlay, Cedar/NodeAgent.c, with ICE of the peer layer, Core/PeerIce.c), in a world of the NAT
// simulator of the core tests (src/coretest/natsim.c) with cone NATs, in process, as seam 2 of #45 runs the data plane:
// - node-a and node-b sit behind NATs of endpoint independent mapping with address and port dependent filtering (port
//   restricted cones). Neither names an endpoint, so their pair takes the datagram path. relay-1 is the peer layer of the
//   relay role on the public side, and stun-1, a STUN server there, is one that no Node is told of.
// - node-c joins later, behind a symmetric NAT whose home gateway grants port mappings (the simulated gateway of homegw.c,
//   which libplum finds with SSDP on the loopback interfaces of the host and whose mapping is a port forward of the NAT).
//   The setting PortMapping of node-c is 1; node-a and node-b have none, so their port mapping is off.
// - The Controller is a stand-in of this file on the control stream of each Node, as in relaypathtest.c: the Updates of the
//   desired state of each Node, and the Signals of the Nodes, which it carries to the Node they name. It keeps the Upgrades
//   and the Fallbacks that each Node reports in its Telemetry.
// - A fake adapter stands in for the host of each Node, and the test sends the packets of each host into its Node. A tap of
//   the network sees every datagram that a host sends before the network routes it, and drops the STUN messages while the
//   test holds ICE back.
// The steps:
// a. Bring-up: node-a and node-b apply Generation 1 and come up through relay-1, while the tap holds ICE back.
// b. Upgrade: packets of the host of node-a reach the host of node-b through relay-1 while ICE is held back. Once the tap lets
//    the checks through, ICE validates the direct path in the background and both ends move to it, an Upgrade each, with not
//    one packet of a stream that goes on through the move missing, and in the same peer session. relay-1 carries no data of
//    the pair after the move.
// c. Candidates: each Node offers its host address and the address that relay-1 saw it at, the answer of its bind, and the
//    direct path runs between those addresses. The capture finds no STUN message to anything but a candidate of a Node, and
//    no datagram at all to stun-1.
// d. Fallback: the NAT of node-a drops its mappings, as a NAT that restarts does. Consent freshness fails the direct path at
//    both ends, which fall back to relay-1, a Fallback each, and the packets go on there in the same peer session.
// e. Port mapping: the gateway was asked nothing while node-a and node-b ran with port mapping off. node-c joins with it on:
//    libplum gets a public port from the gateway, node-c offers it first among its candidates, and node-b reaches node-c
//    directly at that port.
// f. Export: the state of each Node, as its admin pipe answers it and ranz node state prints it, and the Telemetry that it
//    reports to the stand-in of the Controller, which the Controller exports, hold its Upgrades and Fallbacks.
// Print "DIRECTPATH TEST OK" only when every check passes.

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

#define	DIRECTPATH_BUDGET		300000		// The whole test ends within this time, or the watchdog ends the process (ms)
#define	DIRECTPATH_BOUND		20000		// A bounded wait on observable state (ms)
#define	DIRECTPATH_POLL			20			// Poll interval of observable state (ms)
#define	DIRECTPATH_READ			50			// ms that one read of a control stream of the stand-in waits
#define	DIRECTPATH_TICK			100			// ms between two ticks of the peer layer of relay-1
#define	DIRECTPATH_BIND			400			// The keepalive of the Bindings of the Nodes: their BindInterval (ms) ...
#define	DIRECTPATH_BIND_RETRY	200			// ... and their BindRetry (ms)
#define	DIRECTPATH_MAP_TIMEOUT	2000		// ms that libplum waits for a gateway, per protocol
#define	DIRECTPATH_MAP_WAIT		30000		// ms for the gateway to grant node-c a public port through libplum
#define	DIRECTPATH_UP_WAIT		30000		// ms for ICE to validate and nominate a direct path once its checks pass
#define	DIRECTPATH_FAIL_WAIT	90000		// ms for consent freshness to fail a direct path: 30 s without an answer
#define	DIRECTPATH_GAP			10			// ms between two packets of a stream
#define	DIRECTPATH_SETTLED		20			// Packets of a stream on the relay, and with both ends on the direct path before it ends
#define	DIRECTPATH_ECHOES		3			// The echoes of a step
#define	DIRECTPATH_VRF			1			// The id of VRF default ...
#define	DIRECTPATH_VRF_NAME		"default"	// ... its name and the name of its Network ...
#define	DIRECTPATH_MTU			1280		// ... and its MTU
#define	DIRECTPATH_FRAME_HEADER	4			// The size of a frame of a control stream, big-endian, before its message
#define	DIRECTPATH_MAX_FRAME	(1 << 20)	// The largest frame that the stand-in reads, as the node does (CONTROL_MAX_FRAME)
#define	DIRECTPATH_OUT_FRAME	65536		// The largest frame that it writes
#define	DIRECTPATH_MAX_STREAMS	16			// Control streams that the stand-in serves in one run at most
#define	DIRECTPATH_NUM_NODES	3
#define	DIRECTPATH_A			0			// node-a, behind a port restricted cone NAT
#define	DIRECTPATH_B			1			// node-b, behind another
#define	DIRECTPATH_C			2			// node-c, behind a symmetric NAT with a home gateway, from step e on
#define	DIRECTPATH_CONTROLLER	"controller"		// The address of the stand-in on the transport of the control streams
#define	DIRECTPATH_RELAY		"relay-1"	// The node name of the Relay
#define	DIRECTPATH_RELAY_PORT	5300		// The UDP port of its relay role
#define	DIRECTPATH_STUN_PORT	3478		// The UDP port of stun-1, the one of STUN
#define	DIRECTPATH_HOST_PORT	5000		// The port of the socket of the peer agent of each Node on its host
#define	DIRECTPATH_ECHO_PORT	7			// The UDP port that the packets of the hosts go to

// What a read of a frame of a control stream at the stand-in gave
#define	DIRECTPATH_FRAME_DONE	0			// A whole frame is in Frame
#define	DIRECTPATH_FRAME_LATER	1			// Not within the timeout: the bytes read so far stay in Frame
#define	DIRECTPATH_FRAME_END	2			// The stream ended, or its next frame is larger than allowed

static char *directpath_names[DIRECTPATH_NUM_NODES] = {"node-a", "node-b", "node-c"};
static char *directpath_tags[DIRECTPATH_NUM_NODES] = {"site-a", "site-b", "site-c"};

// The payload of every packet of a host, once or repeated
static char directpath_marker[] = "DIRECTPATH: the packet of a host, on the Relay or on the direct path that ICE validated. ";

// One Node of the test, its host on the network of the simulator and the fake adapter of the host
typedef struct DIRECTPATH_NODE
{
	char *Name;
	wchar_t Dir[MAX_PATH];					// Its data directory
	PEER_KEY Key;							// Its static key
	PEER_ADDR Addr;							// The address of the host of the Node behind its NAT, with the port of its socket
	NATSIM_NAT *Nat;						// ... its NAT
	PEER_ADDR Public;						// ... the public address of that NAT, port 0
	NATSIM_HOST *Host;						// ... and the host on the network
	NODE *Node;								// NULL until it starts
	PEER_AGENT *volatile Agent;				// The peer layer of its agent, which the network took, NULL before
	NODE_READER Reader;						// The test thread as a reader of the node's forwarding tables, online while it sends
	SRWLOCK Lock;							// Last, LastSize and LastVrf
	UCHAR Last[PEER_MAX_DATAGRAM];			// The packet that the adapter took last ...
	UINT LastSize;							// ... its size
	UINT LastVrf;							// ... and its VRF
	volatile LONG Packets;					// The packets that the adapter took
} DIRECTPATH_NODE;

// The control stream of one Node at the stand-in of the Controller
typedef struct DIRECTPATH_LINK
{
	CONTROL_SIGNALS *Out;					// The Signals that the stand-in carries to the Node
	volatile LONG Active;					// A stream of the Node is served now
	volatile LONG Streams;					// The streams of the Node that the stand-in served
	volatile LONG64 Posted;					// The Generation of the desired state that the Node is to get
	volatile LONG64 Acked;					// The Generation that the Node acknowledged last
	volatile LONG Reports;					// The Telemetry messages with the Paths of the Node that it took
	volatile LONG64 Upgrades;				// ... the Upgrades of the last of them
	volatile LONG64 Fallbacks;				// ... and its Fallbacks
} DIRECTPATH_LINK;

// One stream that the stand-in took, and its thread
typedef struct DIRECTPATH_STREAM
{
	struct DIRECTPATH_CTX *Ctx;
	TRANSPORT_STREAM *Stream;
	HANDLE Thread;
	UCHAR *Frame;							// The frame being read: its size, then its message
	UINT FrameSize;							// ... its bytes read so far
	UCHAR *Out;								// The frame being written
	ranz_control_v1_ControlMessage *Message;	// The message read last, or written
} DIRECTPATH_STREAM;

// The state of the test
typedef struct DIRECTPATH_CTX
{
	UINT NumChecks;
	UINT NumFailed;
	DIRECTPATH_NODE Nodes[DIRECTPATH_NUM_NODES];
	PEER_CONFIG PathConfig;					// The peer layer of the agents of the Nodes: ICE on, and the shorter timers of a test

	// The network of the simulator, relay-1, stun-1 and the home gateway of node-c
	NATSIM *Sim;
	PEER_KEY RelayKey;						// The static key of relay-1
	PEER_ADDR RelayAddr;					// The address of its relay role
	PEER_CONFIG RelayConfig;				// ... and its configuration
	NATSIM_HOST *RelayHost;
	SRWLOCK RelayLock;						// Relay: its ticker
	PEER_AGENT *Relay;						// The peer layer of the relay role of relay-1
	HANDLE Ticker;							// ... which this thread ticks
	PEER_ADDR StunAddr;						// The address of stun-1
	NATSIM_HOST *StunHost;					// ... and its host, which no Node is told of
	HOMEGW *Gateway;						// The home gateway of the NAT of node-c
	volatile LONG Halt;						// Ends the threads of the test

	// The capture of every datagram that a host sends
	volatile LONG BlockIce;					// The tap drops every STUN message while it is set
	volatile LONG64 Stun;					// The STUN messages that the hosts sent: the checks of ICE and their answers
	volatile LONG64 StunElsewhere;			// ... to an address that is no candidate of a Node: relay-1, stun-1 or another
	volatile LONG64 ToStun;					// The datagrams of any kind to stun-1
	volatile LONG64 RelayRecords;			// The records of peer sessions on the links of node-a and node-b with relay-1

	// The transports: the data streams between the Nodes, which none dials, and the control streams to the stand-in
	TRANSPORT *Data;
	TRANSPORT *Control;

	// The stand-in of the Controller
	PEER_KEY ControllerKey;					// Its static key
	TRANSPORT_LISTENER *Listener;
	HANDLE Acceptor;						// The thread that takes the streams
	DIRECTPATH_LINK Links[DIRECTPATH_NUM_NODES];
	DIRECTPATH_STREAM *Streams[DIRECTPATH_MAX_STREAMS];
	volatile LONG NumStreams;
	volatile LONG Carry;					// It carries the Signals: node-a and node-b applied their first state
	volatile LONG64 Carried;				// The Signals that it carried
} DIRECTPATH_CTX;

static bool DirectPathCheck(DIRECTPATH_CTX *ctx, bool ok, char *what, char *fmt, ...) RANZ_PRINTF_FORMAT(4, 5);
static bool DirectPathCheck(DIRECTPATH_CTX *ctx, bool ok, char *what, char *fmt, ...)
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
static DWORD WINAPI DirectPathWatchdog(LPVOID param)
{
	char msg[MAX_SIZE];
	DWORD written = 0;

	if (WaitForSingleObject((HANDLE)param, DIRECTPATH_BUDGET) != WAIT_TIMEOUT)
	{
		return 0;
	}

	int len = snprintf(msg, sizeof(msg), "DIRECTPATH TEST FAILED (did not finish within %u ms)\n", (UINT)DIRECTPATH_BUDGET);
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
static void DirectPathIp(UCHAR *addr, UINT i)
{
	addr[0] = 100;
	addr[1] = 64;
	addr[2] = 0;
	addr[3] = (UCHAR)(1 + i);
}

// A UDP packet from the host of node from, port sport, to the host of node to, port dport, whose payload is the marker:
// its size
static UINT DirectPathPacket(UCHAR *buf, UINT from, UINT to, USHORT sport, USHORT dport)
{
	UINT len = StrLen(directpath_marker);
	UINT size = 28 + len;
	UCHAR *udp = buf + 20;

	Zero(buf, size);
	buf[0] = 0x45;
	buf[2] = (UCHAR)(size >> 8);
	buf[3] = (UCHAR)size;
	buf[8] = 64;
	buf[9] = IP_PROTO_UDP;
	DirectPathIp(buf + 12, from);
	DirectPathIp(buf + 16, to);
	USHORT sum = IpChecksum(buf, 20);
	Copy(buf + 10, &sum, 2);

	WRITE_USHORT(udp, sport);
	WRITE_USHORT(udp + 2, dport);
	WRITE_USHORT(udp + 4, size - 20);
	Copy(buf + 28, directpath_marker, len);

	return size;
}

// The fake adapter of a host: it keeps the packet that it took last and counts them
static void DirectPathAdapter(NODE *n, void *param, UINT vrf_id, const UCHAR *packet, UINT size)
{
	DIRECTPATH_NODE *t = (DIRECTPATH_NODE *)param;

	AcquireSRWLockExclusive(&t->Lock);
	{
		t->LastSize = MIN(size, (UINT)sizeof(t->Last));
		Copy(t->Last, packet, t->LastSize);
		t->LastVrf = vrf_id;
	}
	ReleaseSRWLockExclusive(&t->Lock);

	InterlockedIncrement(&t->Packets);
}

// Send one packet of the host of node from into its Node, to the host of node to, from port sport: false when the Node
// took it nowhere
static bool DirectPathSend(DIRECTPATH_CTX *ctx, UINT from, UINT to, USHORT sport)
{
	DIRECTPATH_NODE *f = &ctx->Nodes[from];
	UCHAR packet[PEER_MAX_DATAGRAM];
	UINT size = DirectPathPacket(packet, from, to, sport, DIRECTPATH_ECHO_PORT);

	NodeReaderOnline(f->Node, &f->Reader);
	bool sent = NodeOverlayInput(f->Node, DIRECTPATH_VRF, packet, size);
	NodeReaderOffline(&f->Reader);

	return sent;
}

// Whether the adapter of node t took count packets within DIRECTPATH_BOUND, the last of them as sent: the network carries
// the rest of a stream
static bool DirectPathWaitPackets(DIRECTPATH_CTX *ctx, UINT t, LONG count)
{
	for (UINT64 end = Tick64() + DIRECTPATH_BOUND;Tick64() < end;SleepThread(1))
	{
		if (InterlockedCompareExchange(&ctx->Nodes[t].Packets, 0, 0) >= count)
		{
			return true;
		}
	}

	return false;
}

// A packet from the host of node from, port sport, to the host of node to, and the answer of that host back: whether both
// came whole, as they were sent
static bool DirectPathEcho(DIRECTPATH_CTX *ctx, UINT from, UINT to, USHORT sport)
{
	UCHAR packet[PEER_MAX_DATAGRAM];
	bool ok = true;

	for (UINT k = 0;k < 2 && ok;k++)
	{
		UINT src = (k == 0 ? from : to), dst = (k == 0 ? to : from);
		USHORT sp = (USHORT)(k == 0 ? sport : DIRECTPATH_ECHO_PORT), dp = (USHORT)(k == 0 ? DIRECTPATH_ECHO_PORT : sport);
		DIRECTPATH_NODE *t = &ctx->Nodes[dst];
		LONG before = InterlockedCompareExchange(&t->Packets, 0, 0);
		UINT size = DirectPathPacket(packet, src, dst, sp, dp);

		NodeReaderOnline(ctx->Nodes[src].Node, &ctx->Nodes[src].Reader);
		ok = NodeOverlayInput(ctx->Nodes[src].Node, DIRECTPATH_VRF, packet, size);
		NodeReaderOffline(&ctx->Nodes[src].Reader);

		ok = ok && DirectPathWaitPackets(ctx, dst, before + 1);
		if (ok)
		{
			AcquireSRWLockShared(&t->Lock);
			ok = (t->LastSize == size && t->LastVrf == DIRECTPATH_VRF && Cmp(t->Last, packet, size) == 0);
			ReleaseSRWLockShared(&t->Lock);
		}
	}

	return ok;
}

//
// The network of the simulator
//

// Whether a datagram is a STUN message: the magic cookie of RFC 8489 where a STUN message has it, and a length that
// matches. No datagram of the peer layer has it there.
static bool DirectPathIsStun(const UCHAR *data, UINT size)
{
	return (size >= 20 && (data[0] & 0xC0) == 0 && data[4] == 0x21 && data[5] == 0x12 && data[6] == 0xA4 && data[7] == 0x42 &&
		(UINT)((data[2] << 8) | data[3]) + 20 == size);
}

// Whether a and b have the same IP address, whatever their ports
static bool DirectPathSameIp(const PEER_ADDR *a, const PEER_ADDR *b)
{
	return (Cmp(a->Ip, b->Ip, sizeof(a->Ip)) == 0);
}

// Whether dst can be a candidate of a Node: the public address of its NAT, at any port, which its server reflexive and its
// mapped candidates are on, or the address of its host
static bool DirectPathCandidateAddr(DIRECTPATH_CTX *ctx, const PEER_ADDR *dst)
{
	for (UINT i = 0;i < DIRECTPATH_NUM_NODES;i++)
	{
		if (DirectPathSameIp(dst, &ctx->Nodes[i].Public) || PeerAddrEqual(dst, &ctx->Nodes[i].Addr))
		{
			return true;
		}
	}

	return false;
}

// The tap of the network (NATSIM_TAP): every datagram that a host sends, on whatever link, before the network routes it.
// It counts the STUN messages and where they go, the datagrams to stun-1, and the records of peer sessions on the links
// of node-a and node-b with relay-1; it drops the STUN messages while the test holds ICE back.
static bool DirectPathTap(void *param, NATSIM_HOST *from, const PEER_ADDR *dst, const UCHAR *data, UINT size)
{
	DIRECTPATH_CTX *ctx = (DIRECTPATH_CTX *)param;

	if (DirectPathSameIp(dst, &ctx->StunAddr))
	{
		InterlockedIncrement64(&ctx->ToStun);
	}

	if (DirectPathIsStun(data, size))
	{
		InterlockedIncrement64(&ctx->Stun);
		if (DirectPathCandidateAddr(ctx, dst) == false)
		{
			InterlockedIncrement64(&ctx->StunElsewhere);
		}

		return (InterlockedCompareExchange(&ctx->BlockIce, 0, 0) == 0);
	}

	if (size != 0 && data[0] == PEER_MSG_RECORD)
	{
		bool to_relay = ((from == ctx->Nodes[DIRECTPATH_A].Host || from == ctx->Nodes[DIRECTPATH_B].Host) && PeerAddrEqual(dst, &ctx->RelayAddr));
		bool from_relay = (from == ctx->RelayHost && (DirectPathSameIp(dst, &ctx->Nodes[DIRECTPATH_A].Public) || DirectPathSameIp(dst, &ctx->Nodes[DIRECTPATH_B].Public)));

		if (to_relay || from_relay)
		{
			InterlockedIncrement64(&ctx->RelayRecords);
		}
	}

	return true;
}

// The ticker of relay-1: the timers of its peer layer, which drop the Bindings that were not renewed, as the receive thread
// of its UDP socket runs them on a Node
static DWORD WINAPI DirectPathTicker(LPVOID param)
{
	DIRECTPATH_CTX *ctx = (DIRECTPATH_CTX *)param;

	while (InterlockedCompareExchange(&ctx->Halt, 0, 0) == 0)
	{
		AcquireSRWLockShared(&ctx->RelayLock);
		PeerTick(ctx->Relay);
		ReleaseSRWLockShared(&ctx->RelayLock);

		Sleep(DIRECTPATH_TICK);
	}

	return 0;
}

// Start the peer layer of the relay role of relay-1 on its host, with the three Nodes as its peers in VRF default, as the
// Peer objects of its desired state give them
static bool DirectPathRelayStart(DIRECTPATH_CTX *ctx)
{
	PEER_INFO peers[DIRECTPATH_NUM_NODES];

	for (UINT i = 0;i < DIRECTPATH_NUM_NODES;i++)
	{
		Zero(&peers[i], sizeof(PEER_INFO));
		StrCpy(peers[i].Name, sizeof(peers[i].Name), directpath_names[i]);
		Copy(peers[i].Key, ctx->Nodes[i].Key.Public, PEER_KEY_SIZE);
		peers[i].NumVrfs = 1;
		peers[i].VrfIds[0] = DIRECTPATH_VRF;
	}

	PEER_AGENT *p = PeerNew(&ctx->RelayKey, &ctx->RelayConfig, NatSimSend, ctx->RelayHost, NULL, NULL);
	if (p == NULL)
	{
		return false;
	}
	PeerSetPeers(p, peers, DIRECTPATH_NUM_NODES);

	AcquireSRWLockExclusive(&ctx->RelayLock);
	ctx->Relay = p;
	ReleaseSRWLockExclusive(&ctx->RelayLock);

	NatSimAttach(ctx->RelayHost, p);

	return true;
}

// The counters of relay-1
static void DirectPathRelayStats(DIRECTPATH_CTX *ctx, PEER_STATS *st)
{
	AcquireSRWLockShared(&ctx->RelayLock);
	PeerGetStats(ctx->Relay, st);
	ReleaseSRWLockShared(&ctx->RelayLock);
}

// The peer layer of the agent of node i, NULL before the network took it
static PEER_AGENT *DirectPathAgent(DIRECTPATH_CTX *ctx, UINT i)
{
	return (PEER_AGENT *)ReadPointerAcquire((PVOID const volatile *)&ctx->Nodes[i].Agent);
}

// How node i reaches node j, into st: false when it does not know j as a peer
static bool DirectPathStatus(DIRECTPATH_CTX *ctx, UINT i, UINT j, PEER_STATUS *st)
{
	return PeerGetStatus(DirectPathAgent(ctx, i), ctx->Nodes[j].Key.Public, st);
}

// The counters of the peer layer of the agent of node i, into st
static void DirectPathStats(DIRECTPATH_CTX *ctx, UINT i, PEER_STATS *st)
{
	NODE_AGENT_STATUS as;

	NodeAgentGetStatus(ctx->Nodes[i].Node, &as);
	Copy(st, &as.Peer, sizeof(PEER_STATS));
}

// The name of a path of PEER_PATH_*
static char *DirectPathPathName(UINT path)
{
	switch (path)
	{
	case PEER_PATH_RELAY:
		return "relay";
	case PEER_PATH_DIRECT:
		return "direct";
	default:
		return "none";
	}
}

// The name of an ICE state of PEER_ICE_*
static char *DirectPathIceName(UINT ice)
{
	switch (ice)
	{
	case PEER_ICE_CHECKING:
		return "checking";
	case PEER_ICE_CONNECTED:
		return "connected";
	case PEER_ICE_COMPLETED:
		return "completed";
	case PEER_ICE_FAILED:
		return "failed";
	default:
		return "none";
	}
}

//
// The stand-in of the Controller
//

// Read the next frame of the stream t within timeout into Frame (DIRECTPATH_FRAME_*)
static UINT DirectPathRead(DIRECTPATH_STREAM *t, UINT timeout)
{
	UINT64 end = Tick64() + timeout;

	while (true)
	{
		UINT need = DIRECTPATH_FRAME_HEADER;

		if (t->FrameSize >= DIRECTPATH_FRAME_HEADER)
		{
			UINT size = ((UINT)t->Frame[0] << 24) | ((UINT)t->Frame[1] << 16) | ((UINT)t->Frame[2] << 8) | t->Frame[3];

			if (size == 0 || size > DIRECTPATH_MAX_FRAME - DIRECTPATH_FRAME_HEADER)
			{
				return DIRECTPATH_FRAME_END;
			}
			need += size;
			if (t->FrameSize == need)
			{
				return DIRECTPATH_FRAME_DONE;
			}
		}

		UINT64 now = Tick64();
		if (now >= end)
		{
			return DIRECTPATH_FRAME_LATER;
		}

		UINT got = TransportRead(t->Stream, t->Frame + t->FrameSize, need - t->FrameSize, (UINT)(end - now));
		if (got == 0 || (got != TRANSPORT_LATER && got > need - t->FrameSize))
		{
			return DIRECTPATH_FRAME_END;
		}
		if (got != TRANSPORT_LATER)
		{
			t->FrameSize += got;
		}
	}
}

// Write size bytes at Out after the frame header, as one frame
static bool DirectPathWriteFrame(DIRECTPATH_STREAM *t, UINT size)
{
	t->Out[0] = (UCHAR)(size >> 24);
	t->Out[1] = (UCHAR)(size >> 16);
	t->Out[2] = (UCHAR)(size >> 8);
	t->Out[3] = (UCHAR)size;

	return TransportWrite(t->Stream, t->Out, DIRECTPATH_FRAME_HEADER + size);
}

// Decode the frame in Frame into Message: false for bytes that are no ControlMessage
static bool DirectPathDecode(DIRECTPATH_STREAM *t)
{
	pb_istream_t is = pb_istream_from_buffer(t->Frame + DIRECTPATH_FRAME_HEADER, t->FrameSize - DIRECTPATH_FRAME_HEADER);

	Zero(t->Message, sizeof(ranz_control_v1_ControlMessage));

	return pb_decode(&is, ranz_control_v1_ControlMessage_fields, t->Message);
}

// The responder of the handshake of a control stream, as the Controller runs it: Noise_IK with the static key of the
// stand-in, bound to the exporter of the stream after the prologue of the control stream. The static key of the Node goes
// into remote.
static bool DirectPathHandshake(DIRECTPATH_CTX *ctx, DIRECTPATH_STREAM *t, UCHAR *remote)
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
	if (DirectPathRead(t, CONTROL_TIMEOUT) != DIRECTPATH_FRAME_DONE)
	{
		return false;
	}

	bool ok = NoiseHandshakeInit(&hs, NOISE_SUITE_IK, false, prologue, (UINT)sizeof(prologue), ctx->ControllerKey.Private, NULL, NULL);
	ok = ok && NoiseHandshakeRead(&hs, t->Frame + DIRECTPATH_FRAME_HEADER, t->FrameSize - DIRECTPATH_FRAME_HEADER, NULL, 0, &payload_size);
	ok = ok && NoiseHandshakeWrite(&hs, NULL, 0, t->Out + DIRECTPATH_FRAME_HEADER, DIRECTPATH_OUT_FRAME - DIRECTPATH_FRAME_HEADER, &size);
	if (ok)
	{
		Copy(remote, hs.RemoteStatic, PEER_KEY_SIZE);
	}
	NoiseHandshakeFree(&hs);
	t->FrameSize = 0;

	return ok && DirectPathWriteFrame(t, size);
}

// The Hello that a Node sends first after the handshake
static bool DirectPathHello(DIRECTPATH_STREAM *t)
{
	bool ok = (DirectPathRead(t, CONTROL_TIMEOUT) == DIRECTPATH_FRAME_DONE && DirectPathDecode(t) && t->Message->which_body == ranz_control_v1_ControlMessage_hello_tag);

	t->FrameSize = 0;

	return ok;
}

// The address of node i in VRF default as an Address of the control protocol
static void DirectPathAddress(ranz_control_v1_Address *a, UINT i)
{
	StrCpy(a->network, sizeof(a->network), DIRECTPATH_VRF_NAME);
	a->vrf_id = DIRECTPATH_VRF;
	a->has_prefix = true;
	a->prefix.address.size = 4;
	DirectPathIp(a->prefix.address.bytes, i);
	a->prefix.length = 10;
}

// The desired state of node i at Generation g, as an Update of the stand-in, into m: the Node with its tag and its address,
// VRF default with its policy, its peers, relay-1 and the rule allow-all. In Generation 1 node-a and node-b are the peers of
// each other; from Generation 2 node-c is a peer of both, and they are its peers.
static void DirectPathState(DIRECTPATH_CTX *ctx, UINT i, UINT64 g, ranz_control_v1_ControlMessage *m)
{
	Zero(m, sizeof(ranz_control_v1_ControlMessage));
	m->which_body = ranz_control_v1_ControlMessage_update_tag;

	ranz_control_v1_Update *u = &m->body.update;
	u->generation = g;

	ranz_control_v1_Object *o = &u->set[u->set_count++];
	ranz_control_v1_NodeConfig *node = &o->kind.node;
	o->which_kind = ranz_control_v1_Object_node_tag;
	StrCpy(node->name, sizeof(node->name), directpath_names[i]);
	node->tags_count = 1;
	StrCpy(node->tags[0], sizeof(node->tags[0]), directpath_tags[i]);
	node->addresses_count = 1;
	DirectPathAddress(&node->addresses[0], i);

	o = &u->set[u->set_count++];
	o->which_kind = ranz_control_v1_Object_vrf_tag;
	StrCpy(o->kind.vrf.name, sizeof(o->kind.vrf.name), DIRECTPATH_VRF_NAME);
	o->kind.vrf.id = DIRECTPATH_VRF;
	o->kind.vrf.mtu = DIRECTPATH_MTU;
	o->kind.vrf.has_policy = true;

	for (UINT j = 0;j < DIRECTPATH_NUM_NODES;j++)
	{
		if (j == i || (j == DIRECTPATH_C && g < 2))
		{
			continue;
		}

		o = &u->set[u->set_count++];
		ranz_control_v1_Peer *p = &o->kind.peer;
		o->which_kind = ranz_control_v1_Object_peer_tag;
		StrCpy(p->name, sizeof(p->name), directpath_names[j]);
		p->public_key.size = PEER_KEY_SIZE;
		Copy(p->public_key.bytes, ctx->Nodes[j].Key.Public, PEER_KEY_SIZE);
		p->vrf_ids_count = 1;
		p->vrf_ids[0] = DIRECTPATH_VRF;
		p->addresses_count = 1;
		DirectPathAddress(&p->addresses[0], j);
		p->tags_count = 1;
		StrCpy(p->tags[0], sizeof(p->tags[0]), directpath_tags[j]);
	}

	o = &u->set[u->set_count++];
	ranz_control_v1_Relay *r = &o->kind.relay;
	o->which_kind = ranz_control_v1_Object_relay_tag;
	StrCpy(r->name, sizeof(r->name), DIRECTPATH_RELAY);
	r->public_key.size = PEER_KEY_SIZE;
	Copy(r->public_key.bytes, ctx->RelayKey.Public, PEER_KEY_SIZE);
	r->address.size = 4;
	Copy(r->address.bytes, ctx->RelayAddr.Ip + 12, 4);
	r->port = DIRECTPATH_RELAY_PORT;

	o = &u->set[u->set_count++];
	ranz_control_v1_Rule *rule = &o->kind.rule;
	o->which_kind = ranz_control_v1_Object_rule_tag;
	StrCpy(rule->name, sizeof(rule->name), "allow-all");
	rule->vrf_id = DIRECTPATH_VRF;
	rule->priority = 1000;
	rule->action = ranz_control_v1_RuleAction_RULE_ACTION_ALLOW;
}

// Write Message as one frame
static bool DirectPathWrite(DIRECTPATH_STREAM *t)
{
	pb_ostream_t os = pb_ostream_from_buffer(t->Out + DIRECTPATH_FRAME_HEADER, DIRECTPATH_OUT_FRAME - DIRECTPATH_FRAME_HEADER);

	if (pb_encode(&os, ranz_control_v1_ControlMessage_fields, t->Message) == false)
	{
		return false;
	}

	return DirectPathWriteFrame(t, (UINT)os.bytes_written);
}

// A frame that node i sent on its stream: an Ack; a Signal for a peer, which the stand-in carries to the Node that it names,
// under the name of its sender; or a Telemetry message, whose counts of the Paths it keeps
static void DirectPathTake(DIRECTPATH_CTX *ctx, DIRECTPATH_STREAM *t, UINT i)
{
	DIRECTPATH_LINK *l = &ctx->Links[i];

	if (DirectPathDecode(t) == false)
	{
		return;
	}

	switch (t->Message->which_body)
	{
	case ranz_control_v1_ControlMessage_ack_tag:
		InterlockedExchange64(&l->Acked, (LONG64)t->Message->body.ack.generation);
		break;

	case ranz_control_v1_ControlMessage_signal_tag:
		{
			const ranz_control_v1_Signal *s = &t->Message->body.signal;
			UINT size = MIN((UINT)s->envelope.size, (UINT)CONTROL_MAX_ENVELOPE);

			for (UINT j = 0;j < DIRECTPATH_NUM_NODES;j++)
			{
				if (StrCmp(s->peer, directpath_names[j]) == 0 && size != 0 &&
					ControlSendSignal(ctx->Links[j].Out, directpath_names[i], s->envelope.bytes, size))
				{
					InterlockedIncrement64(&ctx->Carried);
				}
			}
		}
		break;

	case ranz_control_v1_ControlMessage_telemetry_tag:
		if (t->Message->body.telemetry.has_paths)
		{
			InterlockedExchange64(&l->Upgrades, (LONG64)t->Message->body.telemetry.paths.upgrades);
			InterlockedExchange64(&l->Fallbacks, (LONG64)t->Message->body.telemetry.paths.fallbacks);
			InterlockedIncrement(&l->Reports);
		}
		break;

	default:
		break;
	}
}

// One control stream at the stand-in: the handshake names its Node, which says Hello; then the Updates that the test posts
// for the Node, the Signals that the stand-in carries to it once it carries them, and the frames of the Node, until the
// stream ends or the test halts. One stream of a Node is served at a time.
static DWORD WINAPI DirectPathServe(LPVOID param)
{
	DIRECTPATH_STREAM *t = (DIRECTPATH_STREAM *)param;
	DIRECTPATH_CTX *ctx = t->Ctx;
	DIRECTPATH_LINK *l = NULL;
	UCHAR remote[PEER_KEY_SIZE];
	UINT i = DIRECTPATH_NUM_NODES;
	UINT64 sent = 0;

	if (DirectPathHandshake(ctx, t, remote))
	{
		for (UINT j = 0;j < DIRECTPATH_NUM_NODES && i == DIRECTPATH_NUM_NODES;j++)
		{
			if (Cmp(remote, ctx->Nodes[j].Key.Public, PEER_KEY_SIZE) == 0)
			{
				i = j;
			}
		}
	}
	if (i < DIRECTPATH_NUM_NODES && InterlockedCompareExchange(&ctx->Links[i].Active, 1, 0) == 0)
	{
		l = &ctx->Links[i];
	}

	bool ok = (l != NULL && DirectPathHello(t));
	if (ok)
	{
		InterlockedIncrement(&l->Streams);
	}

	while (ok && InterlockedCompareExchange(&ctx->Halt, 0, 0) == 0)
	{
		UINT64 posted = (UINT64)InterlockedCompareExchange64(&l->Posted, 0, 0);

		if (posted > sent)
		{
			DirectPathState(ctx, i, posted, t->Message);
			ok = DirectPathWrite(t);
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

		UINT r = DirectPathRead(t, DIRECTPATH_READ);
		if (r == DIRECTPATH_FRAME_END)
		{
			break;
		}
		if (r == DIRECTPATH_FRAME_DONE)
		{
			DirectPathTake(ctx, t, i);
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
static DWORD WINAPI DirectPathAccept(LPVOID param)
{
	DIRECTPATH_CTX *ctx = (DIRECTPATH_CTX *)param;

	while (InterlockedCompareExchange(&ctx->Halt, 0, 0) == 0)
	{
		TRANSPORT_STREAM *s = TransportAccept(ctx->Listener, DIRECTPATH_TICK);
		LONG n = InterlockedCompareExchange(&ctx->NumStreams, 0, 0);

		if (s == NULL)
		{
			continue;
		}
		if (n >= DIRECTPATH_MAX_STREAMS)
		{
			TransportClose(s);
			continue;
		}

		DIRECTPATH_STREAM *t = ZeroMalloc(sizeof(DIRECTPATH_STREAM));
		t->Ctx = ctx;
		t->Stream = s;
		t->Frame = Malloc(DIRECTPATH_MAX_FRAME);
		t->Out = Malloc(DIRECTPATH_OUT_FRAME);
		t->Message = ZeroMalloc(sizeof(ranz_control_v1_ControlMessage));
		ctx->Streams[n] = t;
		InterlockedExchange(&ctx->NumStreams, n + 1);

		t->Thread = CreateThread(NULL, 0, DirectPathServe, t, 0, NULL);
		if (t->Thread == NULL)
		{
			TransportClose(t->Stream);
			t->Stream = NULL;
		}
	}

	return 0;
}

// Post Generation g for node i, whose stream sends it at once, and whether the Node acknowledged it within DIRECTPATH_BOUND
static bool DirectPathApply(DIRECTPATH_CTX *ctx, UINT i, UINT64 g)
{
	InterlockedExchange64(&ctx->Links[i].Posted, (LONG64)g);

	for (UINT64 end = Tick64() + DIRECTPATH_BOUND;Tick64() < end;SleepThread(DIRECTPATH_POLL))
	{
		if ((UINT64)InterlockedCompareExchange64(&ctx->Links[i].Acked, 0, 0) >= g)
		{
			return true;
		}
	}

	return false;
}

// Whether node i opened its control stream to the stand-in and said Hello within DIRECTPATH_BOUND
static bool DirectPathWaitHello(DIRECTPATH_CTX *ctx, UINT i)
{
	for (UINT64 end = Tick64() + DIRECTPATH_BOUND;Tick64() < end;SleepThread(DIRECTPATH_POLL))
	{
		if (InterlockedCompareExchange(&ctx->Links[i].Streams, 0, 0) != 0)
		{
			return true;
		}
	}

	return false;
}

//
// The Nodes
//

// A new empty data directory under the temp directory of the process, with a configuration store that runs no role on one
// worker; with port_mapping, its setting PortMapping is 1
static void DirectPathNewDir(wchar_t *dir, UINT size, char *name, bool port_mapping)
{
	wchar_t tmp[MAX_PATH];
	wchar_t path[MAX_PATH];

	UniFormat(tmp, sizeof(tmp), L"directpathtest_%S_%u", name, Rand32());
	ConbinePathW(dir, size, MsGetMyTempDirW(), tmp);
	MakeDirExW(dir);

	ConbinePathW(path, sizeof(path), dir, CS_FILE_NAME);
	CONFIG_STORE *s = CsOpen(path);
	if (s != NULL)
	{
		CsSetSetting(s, NODE_SETTING_ROLES, "none");
		CsSetSetting(s, NODE_SETTING_WORKERS, "1");
		if (port_mapping)
		{
			CsSetSetting(s, NODE_SETTING_PORT_MAPPING, "1");
		}
		CsClose(s);
	}
}

// Delete the files of a directory, then the directory (it holds no subdirectory)
static void DirectPathDeleteFiles(wchar_t *dir)
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

// The data transport dials a peer only at an endpoint, and no Node of the test names one
static bool DirectPathDialable(NODE *n, void *param, const char *name, const struct CONTROL_ENDPOINT *endpoints, UINT num)
{
	return (num != 0);
}

// The network of the simulator takes the peer layer of the agent of a Node, and NULL before it stops (NODE_PATH_ATTACH_PROC).
// The host candidate of the layer is the address of the host of the Node, with the port of its socket there.
static void DirectPathAttach(NODE *n, void *param, PEER_AGENT *agent)
{
	DIRECTPATH_NODE *t = (DIRECTPATH_NODE *)param;

	if (agent != NULL)
	{
		PeerSetHostCandidates(agent, &t->Addr, 1);
	}
	NatSimAttach(t->Host, agent);
	InterlockedExchangePointer((PVOID volatile *)&t->Agent, agent);
}

// Start node i: its data directory, with the setting PortMapping for node-c, its Node, and its overlay with the control
// stream to the stand-in, the data transport, the fake adapter of its host and the network of the simulator for its agent
static bool DirectPathStartNode(DIRECTPATH_CTX *ctx, UINT i)
{
	DIRECTPATH_NODE *t = &ctx->Nodes[i];
	NODE_OVERLAY_CONFIG c;
	char what[MAX_SIZE];

	DirectPathNewDir(t->Dir, sizeof(t->Dir), t->Name, i == DIRECTPATH_C);
	t->Node = NewNode(t->Dir);
	NodeStart(t->Node);
	NodeReaderRegister(t->Node, &t->Reader);
	NodeReaderOffline(&t->Reader);

	Zero(&c, sizeof(c));
	c.Control = ctx->Control;
	StrCpy(c.Controller, sizeof(c.Controller), DIRECTPATH_CONTROLLER);
	Copy(c.ControllerKey, ctx->ControllerKey.Public, PEER_KEY_SIZE);
	c.Data = ctx->Data;
	c.Key = &t->Key;
	c.Adapter = DirectPathAdapter;
	c.AdapterParam = t;
	c.Dialable = DirectPathDialable;
	c.PathSend = NatSimSend;
	c.PathSendParam = t->Host;
	c.PathAttach = DirectPathAttach;
	c.PathConfig = &ctx->PathConfig;

	Format(what, sizeof(what), "%s: its overlay runs, with its control stream to the stand-in of the Controller and its peer agent with ICE on the network of the simulator%s",
		t->Name, i == DIRECTPATH_C ? ", and its setting PortMapping is 1" : "");

	return DirectPathCheck(ctx, NodeOverlayStart(t->Node, &c), what, "NodeOverlayStart failed");
}

// The session of the peer name in the state of node i into s: false when the Node has no such peer
static bool DirectPathSession(DIRECTPATH_CTX *ctx, UINT i, char *name, NODE_OVERLAY_SESSION *s)
{
	NODE_OVERLAY_SESSION list[DIRECTPATH_NUM_NODES];
	UINT num = NodeOverlayGetSessions(ctx->Nodes[i].Node, list, DIRECTPATH_NUM_NODES, NULL, 0);

	for (UINT k = 0;k < num && k < DIRECTPATH_NUM_NODES;k++)
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

// Whether i and j each reach the other on path within timeout ms, with their ICE sessions in the state ice (0 for any)
static bool DirectPathWaitPath(DIRECTPATH_CTX *ctx, UINT i, UINT j, UINT path, UINT ice, UINT timeout, PEER_STATUS *si, PEER_STATUS *sj)
{
	for (UINT64 end = Tick64() + timeout;Tick64() < end;SleepThread(DIRECTPATH_POLL))
	{
		bool ok = DirectPathStatus(ctx, i, j, si) && DirectPathStatus(ctx, j, i, sj) && si->Path == path && sj->Path == path;

		if (ok && (ice == 0 || (si->Ice == ice && sj->Ice == ice)))
		{
			return true;
		}
	}

	return false;
}

//
// The steps
//

// a. Bring-up: the control streams of node-a and node-b say Hello, both apply Generation 1, and the stand-in carries their
// Signals from then on; they come up through relay-1 while the tap holds ICE back
static bool DirectPathBringUp(DIRECTPATH_CTX *ctx)
{
	PEER_STATUS ab, ba;
	PEER_STATS rs;

	Print("[a. bring-up: Generation 1 on the control streams, the Signals through the stand-in, the Path through relay-1]\n");

	bool hello = DirectPathWaitHello(ctx, DIRECTPATH_A) && DirectPathWaitHello(ctx, DIRECTPATH_B);
	if (DirectPathCheck(ctx, hello, "node-a and node-b open their control streams to the stand-in of the Controller and say Hello", "not both said Hello") == false)
	{
		return false;
	}

	// The checks of ICE are lost on the way until the pair is under way on the relay
	InterlockedExchange(&ctx->BlockIce, 1);

	bool acked = DirectPathApply(ctx, DIRECTPATH_A, 1) && DirectPathApply(ctx, DIRECTPATH_B, 1);
	if (DirectPathCheck(ctx, acked, "node-a and node-b apply Generation 1 from their control streams and acknowledge it", "not acknowledged") == false)
	{
		return false;
	}

	InterlockedExchange(&ctx->Carry, 1);

	bool up = DirectPathWaitPath(ctx, DIRECTPATH_A, DIRECTPATH_B, PEER_PATH_RELAY, PEER_ICE_CHECKING, DIRECTPATH_BOUND, &ab, &ba);
	DirectPathRelayStats(ctx, &rs);
	DirectPathCheck(ctx, up && rs.NumBindings == 2,
		"node-a and node-b come up through relay-1 after their Signals, which named the address that relay-1 saw each at, while ICE checks the candidate pairs in the background",
		"path of node-a to node-b %s and ICE %s, of node-b to node-a %s and ICE %s; Bindings at relay-1 %u", DirectPathPathName(ab.Path), DirectPathIceName(ab.Ice),
		DirectPathPathName(ba.Path), DirectPathIceName(ba.Ice), rs.NumBindings);

	return up;
}

// What stays the same at both ends of the pair of node-a and node-b through a move: their peer session
typedef struct DIRECTPATH_SESSION
{
	UCHAR IdA[PEER_SESSION_ID_SIZE];		// The id of the keys of the session at node-a ...
	UCHAR IdB[PEER_SESSION_ID_SIZE];		// ... and at node-b
	UINT64 HandshakesA;						// The handshakes that completed at node-a ...
	UINT64 HandshakesB;						// ... and at node-b
} DIRECTPATH_SESSION;

static bool DirectPathSessionOf(DIRECTPATH_CTX *ctx, DIRECTPATH_SESSION *s)
{
	PEER_STATUS ab, ba;

	bool ok = DirectPathStatus(ctx, DIRECTPATH_A, DIRECTPATH_B, &ab) && DirectPathStatus(ctx, DIRECTPATH_B, DIRECTPATH_A, &ba);
	Copy(s->IdA, ab.SessionId, PEER_SESSION_ID_SIZE);
	Copy(s->IdB, ba.SessionId, PEER_SESSION_ID_SIZE);
	s->HandshakesA = ab.Handshakes;
	s->HandshakesB = ba.Handshakes;

	return ok && ab.Session == PEER_SESSION_UP && ba.Session == PEER_SESSION_UP;
}

// Whether the peer session of the pair is the one of before: the same keys at both ends, the same at each, and no new
// handshake
static bool DirectPathSameSession(DIRECTPATH_CTX *ctx, const DIRECTPATH_SESSION *before, char *detail, UINT detail_size)
{
	static const UCHAR zero[PEER_SESSION_ID_SIZE] = {0};
	DIRECTPATH_SESSION now;

	bool up = DirectPathSessionOf(ctx, &now);
	Format(detail, detail_size, "session up %u; handshakes at node-a %I64u and %I64u, at node-b %I64u and %I64u; the same keys at node-a %u, at node-b %u, at both ends %u",
		(UINT)up, before->HandshakesA, now.HandshakesA, before->HandshakesB, now.HandshakesB, (UINT)(Cmp(now.IdA, before->IdA, PEER_SESSION_ID_SIZE) == 0),
		(UINT)(Cmp(now.IdB, before->IdB, PEER_SESSION_ID_SIZE) == 0), (UINT)(Cmp(now.IdA, now.IdB, PEER_SESSION_ID_SIZE) == 0));

	return (up && Cmp(now.IdA, zero, PEER_SESSION_ID_SIZE) != 0 && Cmp(now.IdA, before->IdA, PEER_SESSION_ID_SIZE) == 0 &&
		Cmp(now.IdB, before->IdB, PEER_SESSION_ID_SIZE) == 0 && Cmp(now.IdA, now.IdB, PEER_SESSION_ID_SIZE) == 0 &&
		now.HandshakesA == before->HandshakesA && now.HandshakesB == before->HandshakesB);
}

// b. Upgrade: the pair on the relay first, then the move to the direct path that ICE validates, with a stream of packets
// that goes on through it and the same peer session; relay-1 carries no data of the pair after the move
static bool DirectPathUpgrade(DIRECTPATH_CTX *ctx, DIRECTPATH_SESSION *session)
{
	PEER_STATUS ab, ba;
	PEER_STATS before, after, st_a, st_b;
	PEER_ADDR pub_a, pub_b;
	char detail[MAX_SIZE * 2];
	char what[MAX_SIZE];
	char addr_a[64], addr_b[64];
	LONG sent = 0;

	Print("[b. upgrade: the stream from the host of node-a to the host of node-b moves from relay-1 to the direct path]\n");

	// The first packet starts the peer session of the pair, through relay-1
	bool first = DirectPathEcho(ctx, DIRECTPATH_A, DIRECTPATH_B, 39000);
	DirectPathCheck(ctx, first, "A packet of the host of node-a reaches the host of node-b through relay-1 and comes back, in the peer session that it started", "it did not come back");

	// A stream through relay-1 while the checks of ICE are lost
	DirectPathRelayStats(ctx, &before);
	LONG base = InterlockedCompareExchange(&ctx->Nodes[DIRECTPATH_B].Packets, 0, 0);
	for (UINT k = 0;k < DIRECTPATH_SETTLED;k++)
	{
		if (DirectPathSend(ctx, DIRECTPATH_A, DIRECTPATH_B, (USHORT)(40000 + k)))
		{
			sent++;
		}
		SleepThread(DIRECTPATH_GAP);
	}
	bool all = DirectPathWaitPackets(ctx, DIRECTPATH_B, base + sent);
	NatSimWaitIdle(ctx->Sim, DIRECTPATH_BOUND);
	DirectPathRelayStats(ctx, &after);
	bool relay = DirectPathStatus(ctx, DIRECTPATH_A, DIRECTPATH_B, &ab) && ab.Path == PEER_PATH_RELAY && DirectPathStatus(ctx, DIRECTPATH_B, DIRECTPATH_A, &ba) && ba.Path == PEER_PATH_RELAY;
	Format(what, sizeof(what), "A stream of %u packets of the host of node-a reaches the host of node-b through relay-1, in the peer session of the pair, while ICE is held back", (UINT)DIRECTPATH_SETTLED);
	DirectPathCheck(ctx, sent == DIRECTPATH_SETTLED && all && relay && after.Forwarded >= before.Forwarded + DIRECTPATH_SETTLED, what, "%ld sent, %ld taken, on the relay %u, relay-1 forwarded %I64u records",
		sent, InterlockedCompareExchange(&ctx->Nodes[DIRECTPATH_B].Packets, 0, 0) - base, (UINT)relay, after.Forwarded - before.Forwarded);

	bool up = DirectPathSessionOf(ctx, session);
	DirectPathCheck(ctx, up, "The peer session of the pair is up at both ends, on the relay", "it is not");

	// The checks pass: ICE validates and nominates the direct path, and the stream goes on through the move
	InterlockedExchange(&ctx->BlockIce, 0);
	UINT64 t0 = Tick64();
	UINT64 moved = 0;
	UINT settled = 0;
	LONG stream = 0;
	base = InterlockedCompareExchange(&ctx->Nodes[DIRECTPATH_B].Packets, 0, 0);
	while (settled < DIRECTPATH_SETTLED && Tick64() - t0 < DIRECTPATH_UP_WAIT)
	{
		if (DirectPathSend(ctx, DIRECTPATH_A, DIRECTPATH_B, (USHORT)(41000 + (stream % 1000))))
		{
			stream++;
		}

		bool direct = (DirectPathStatus(ctx, DIRECTPATH_A, DIRECTPATH_B, &ab) && ab.Path == PEER_PATH_DIRECT && DirectPathStatus(ctx, DIRECTPATH_B, DIRECTPATH_A, &ba) && ba.Path == PEER_PATH_DIRECT);
		if (direct && moved == 0)
		{
			moved = Tick64() - t0;
		}
		settled = (direct ? settled + 1 : 0);
		SleepThread(DIRECTPATH_GAP);
	}
	all = DirectPathWaitPackets(ctx, DIRECTPATH_B, base + stream);
	LONG taken = InterlockedCompareExchange(&ctx->Nodes[DIRECTPATH_B].Packets, 0, 0) - base;
	Print("  [INFO] ICE moved both ends to the direct path %I64u ms after the checks passed; %ld packets of the stream went, and %ld came\n", moved, stream, taken);

	DirectPathCheck(ctx, settled == DIRECTPATH_SETTLED && ab.Ice == PEER_ICE_COMPLETED && ba.Ice == PEER_ICE_COMPLETED,
		"ICE validated and nominated the direct path in the background, and both ends moved to it", "settled %u, ICE at node-a %s, at node-b %s", settled, DirectPathIceName(ab.Ice), DirectPathIceName(ba.Ice));
	DirectPathCheck(ctx, all && taken == stream && stream != 0, "Not one packet of the stream went missing through the move from relay-1 to the direct path", "%ld sent, %ld taken", stream, taken);

	DirectPathStats(ctx, DIRECTPATH_A, &st_a);
	DirectPathStats(ctx, DIRECTPATH_B, &st_b);
	DirectPathCheck(ctx, st_a.Upgrades == 1 && st_b.Upgrades == 1 && st_a.Fallbacks == 0 && st_b.Fallbacks == 0, "Each end counts one Upgrade", "Upgrades %I64u and %I64u, Fallbacks %I64u and %I64u",
		st_a.Upgrades, st_b.Upgrades, st_a.Fallbacks, st_b.Fallbacks);

	bool same = DirectPathSameSession(ctx, session, detail, sizeof(detail));
	DirectPathCheck(ctx, same, "The peer session survived the move: the same keys at both ends, and no new handshake", "%s", detail);

	// The direct path runs between the addresses that relay-1 saw the two at
	bool mapped = NatSimMapped(ctx->Nodes[DIRECTPATH_A].Nat, &ctx->Nodes[DIRECTPATH_A].Addr, &pub_a) && NatSimMapped(ctx->Nodes[DIRECTPATH_B].Nat, &ctx->Nodes[DIRECTPATH_B].Addr, &pub_b);
	PeerAddrToStr(addr_a, sizeof(addr_a), &ba.Direct);
	PeerAddrToStr(addr_b, sizeof(addr_b), &ab.Direct);
	Print("  [INFO] node-b reaches node-a at %s, and node-a reaches node-b at %s\n", addr_a, addr_b);
	DirectPathCheck(ctx, mapped && PeerAddrEqual(&ba.Direct, &pub_a) && PeerAddrEqual(&ab.Direct, &pub_b), "Each end reaches the other at the public port of its NAT, the one that relay-1 saw it at",
		"node-b reaches node-a at %s, node-a reaches node-b at %s", addr_a, addr_b);

	// relay-1 carries no data of the pair after the move: neither a record on the links of the two with it, nor a forward
	NatSimWaitIdle(ctx->Sim, DIRECTPATH_BOUND);
	DirectPathRelayStats(ctx, &before);
	LONG64 records = InterlockedCompareExchange64(&ctx->RelayRecords, 0, 0);
	UINT echoes = 0;
	for (UINT k = 0;k < DIRECTPATH_ECHOES;k++)
	{
		if (DirectPathEcho(ctx, DIRECTPATH_A, DIRECTPATH_B, (USHORT)(42000 + k)))
		{
			echoes++;
		}
	}
	NatSimWaitIdle(ctx->Sim, DIRECTPATH_BOUND);
	DirectPathRelayStats(ctx, &after);
	LONG64 records_after = InterlockedCompareExchange64(&ctx->RelayRecords, 0, 0);
	Format(what, sizeof(what), "After the move %u packets of the host of node-a reach the host of node-b and come back on the direct path, and relay-1 carries no data of the pair: no record on the links of node-a and node-b with it, and none forwarded",
		(UINT)DIRECTPATH_ECHOES);
	DirectPathCheck(ctx, echoes == DIRECTPATH_ECHOES && after.Forwarded == before.Forwarded && records_after == records, what, "%u echoes came back; relay-1 forwarded %I64u records, and %I64d crossed the links with it",
		echoes, after.Forwarded - before.Forwarded, records_after - records);

	NODE_OVERLAY_SESSION s;
	DirectPathSession(ctx, DIRECTPATH_A, directpath_names[DIRECTPATH_B], &s);
	DirectPathCheck(ctx, s.Path == NODE_PATH_DIRECT, "The state of node-a says direct for node-b", "it says %s", NodeAgentPathName(s.Path));

	return settled == DIRECTPATH_SETTLED;
}

// c. Candidates: the host address and the address that relay-1 saw each Node at, and no STUN server
static void DirectPathCandidates(DIRECTPATH_CTX *ctx)
{
	Print("[c. candidates: the host addresses and the answers of relay-1, and no STUN server]\n");

	for (UINT i = DIRECTPATH_A;i <= DIRECTPATH_B;i++)
	{
		DIRECTPATH_NODE *t = &ctx->Nodes[i];
		PEER_CANDIDATE c[PEER_MAX_CANDIDATES];
		PEER_ADDR pub;
		PEER_STATUS st;
		char srflx[64], host[64], what[MAX_SIZE];

		UINT num = PeerGetCandidates(DirectPathAgent(ctx, i), c, PEER_MAX_CANDIDATES);
		bool mapped = NatSimMapped(t->Nat, &t->Addr, &pub);
		srflx[0] = host[0] = 0;
		if (num == 2)
		{
			PeerAddrToStr(srflx, sizeof(srflx), &c[0].Addr);
			PeerAddrToStr(host, sizeof(host), &c[1].Addr);
		}
		Print("  [INFO] %s offers %u candidates: %s (server reflexive) and %s (host)\n", t->Name, num, srflx, host);

		Format(what, sizeof(what), "%s offers two candidates: the address that relay-1 saw it at, which the answer of its bind gave, and the address of its host", t->Name);
		DirectPathCheck(ctx, num == 2 && mapped && c[0].Type == PEER_CANDIDATE_SRFLX && PeerAddrEqual(&c[0].Addr, &pub) && c[1].Type == PEER_CANDIDATE_HOST && PeerAddrEqual(&c[1].Addr, &t->Addr),
			what, "%u candidates, the first of type %u, the second of type %u", num, num > 0 ? c[0].Type : 0, num > 1 ? c[1].Type : 0);

		UINT other = (i == DIRECTPATH_A ? DIRECTPATH_B : DIRECTPATH_A);
		bool known = DirectPathStatus(ctx, other, i, &st);
		Format(what, sizeof(what), "%s took both from the last Signal of %s", ctx->Nodes[other].Name, t->Name);
		DirectPathCheck(ctx, known && st.NumCandidates == 2, what, "%u candidates", st.NumCandidates);
	}

	UINT64 stun = (UINT64)InterlockedCompareExchange64(&ctx->Stun, 0, 0);
	UINT64 elsewhere = (UINT64)InterlockedCompareExchange64(&ctx->StunElsewhere, 0, 0);
	UINT64 to_stun = (UINT64)InterlockedCompareExchange64(&ctx->ToStun, 0, 0);
	Print("  [INFO] the capture saw %I64u STUN messages, the checks of ICE and their answers\n", stun);
	DirectPathCheck(ctx, stun != 0 && elsewhere == 0 && to_stun == 0,
		"With no STUN server configured, no packet leaves for one: the capture of every datagram finds no STUN message to anything but a candidate of a Node, and no datagram at all to stun-1",
		"%I64u STUN messages, %I64u of them to another address; %I64u datagrams to stun-1", stun, elsewhere, to_stun);
}

// d. Fallback: the NAT of node-a drops its mappings, the direct path dies, and the pair falls back to relay-1, where its
// packets go on
static void DirectPathFallback(DIRECTPATH_CTX *ctx, DIRECTPATH_SESSION *session)
{
	PEER_STATUS ab, ba;
	PEER_STATS before, after, st_a, st_b;
	char detail[MAX_SIZE * 2];
	char what[MAX_SIZE];

	Print("[d. fallback: the NAT of node-a drops its mappings, and the pair falls back to relay-1]\n");

	UINT dropped = NatSimDrop(ctx->Sim, ctx->Nodes[DIRECTPATH_A].Nat, &ctx->Nodes[DIRECTPATH_A].Addr);
	DirectPathCheck(ctx, dropped != 0, "The NAT of node-a drops the mappings of its host, as a NAT that restarts does", "it had none");

	UINT64 t0 = Tick64();
	bool fell = DirectPathWaitPath(ctx, DIRECTPATH_A, DIRECTPATH_B, PEER_PATH_RELAY, PEER_ICE_FAILED, DIRECTPATH_FAIL_WAIT, &ab, &ba);
	Print("  [INFO] both ends were back on relay-1 %I64u ms after the NAT dropped the mappings\n", Tick64() - t0);
	DirectPathCheck(ctx, fell, "Consent freshness failed the direct path at both ends, and both fell back to relay-1", "ICE at node-a %s, at node-b %s", DirectPathIceName(ab.Ice), DirectPathIceName(ba.Ice));

	DirectPathStats(ctx, DIRECTPATH_A, &st_a);
	DirectPathStats(ctx, DIRECTPATH_B, &st_b);
	DirectPathCheck(ctx, st_a.Fallbacks == 1 && st_b.Fallbacks == 1 && st_a.Upgrades == 1 && st_b.Upgrades == 1, "Each end counts one Fallback", "Fallbacks %I64u and %I64u, Upgrades %I64u and %I64u",
		st_a.Fallbacks, st_b.Fallbacks, st_a.Upgrades, st_b.Upgrades);

	DirectPathRelayStats(ctx, &before);
	UINT echoes = 0;
	for (UINT k = 0;k < DIRECTPATH_ECHOES;k++)
	{
		if (DirectPathEcho(ctx, DIRECTPATH_A, DIRECTPATH_B, (USHORT)(43000 + k)))
		{
			echoes++;
		}
	}
	DirectPathRelayStats(ctx, &after);
	Format(what, sizeof(what), "The traffic goes on: %u packets of the host of node-a reach the host of node-b and come back through relay-1", (UINT)DIRECTPATH_ECHOES);
	DirectPathCheck(ctx, echoes == DIRECTPATH_ECHOES && after.Forwarded >= before.Forwarded + 2 * DIRECTPATH_ECHOES, what, "%u echoes came back; relay-1 forwarded %I64u records", echoes,
		after.Forwarded - before.Forwarded);

	bool same = DirectPathSameSession(ctx, session, detail, sizeof(detail));
	DirectPathCheck(ctx, same, "... in the same peer session, which the Fallback kept as the Upgrade did", "%s", detail);

	NODE_OVERLAY_SESSION s;
	DirectPathSession(ctx, DIRECTPATH_A, directpath_names[DIRECTPATH_B], &s);
	DirectPathCheck(ctx, s.Path == NODE_PATH_RELAY, "The state of node-a says relay for node-b again", "it says %s", NodeAgentPathName(s.Path));
}

// e. Port mapping: off at node-a and node-b, which asked the gateway nothing; on at node-c, which gets a public port, offers
// it first and is reached there
static void DirectPathPortMapping(DIRECTPATH_CTX *ctx)
{
	PEER_STATS st_a, st_b, st_c;
	PEER_STATUS bc, cb;
	PEER_CANDIDATE c[PEER_MAX_CANDIDATES];
	PEER_ADDR mapped;
	USHORT external = 0, internal = 0;
	char addr[64];

	Zero(&st_c, sizeof(st_c));
	Print("[e. port mapping: off at node-a and node-b, on at node-c, which joins behind a symmetric NAT with a home gateway]\n");

	DirectPathStats(ctx, DIRECTPATH_A, &st_a);
	DirectPathStats(ctx, DIRECTPATH_B, &st_b);
	PEER_CANDIDATE ca[PEER_MAX_CANDIDATES], cb_list[PEER_MAX_CANDIDATES];
	UINT na = PeerGetCandidates(DirectPathAgent(ctx, DIRECTPATH_A), ca, PEER_MAX_CANDIDATES);
	UINT nb = PeerGetCandidates(DirectPathAgent(ctx, DIRECTPATH_B), cb_list, PEER_MAX_CANDIDATES);
	bool no_mapped = true;
	for (UINT k = 0;k < na;k++)
	{
		no_mapped = no_mapped && ca[k].Type != PEER_CANDIDATE_MAPPED;
	}
	for (UINT k = 0;k < nb;k++)
	{
		no_mapped = no_mapped && cb_list[k].Type != PEER_CANDIDATE_MAPPED;
	}
	UINT searches = HomeGwSearches(ctx->Gateway), requests = HomeGwRequests(ctx->Gateway);
	DirectPathCheck(ctx, st_a.PortMap == PEER_PORTMAP_OFF && st_b.PortMap == PEER_PORTMAP_OFF && no_mapped && searches == 0 && requests == 0,
		"With port mapping off, no mapping request left node-a or node-b through all the steps before: the gateway of the world was asked nothing, and neither offers a mapped candidate",
		"port mapping of node-a %s, of node-b %s; the gateway answered %u M-SEARCH and %u HTTP requests; a mapped candidate %u", NodeAgentPortMapName(st_a.PortMap),
		NodeAgentPortMapName(st_b.PortMap), searches, requests, (UINT)(no_mapped == false));

	// node-c joins: node-a and node-b learn of it first, so that its Signals find it among their peers
	bool acked = DirectPathApply(ctx, DIRECTPATH_A, 2) && DirectPathApply(ctx, DIRECTPATH_B, 2);
	DirectPathCheck(ctx, acked, "node-a and node-b apply Generation 2, with node-c as their peer", "not acknowledged");
	if (DirectPathStartNode(ctx, DIRECTPATH_C) == false)
	{
		return;
	}
	acked = DirectPathWaitHello(ctx, DIRECTPATH_C) && DirectPathApply(ctx, DIRECTPATH_C, 2);
	if (DirectPathCheck(ctx, acked, "node-c says Hello and applies Generation 2, with node-a and node-b as its peers", "not acknowledged") == false)
	{
		return;
	}

	// libplum tries PCP and NAT-PMP at the default gateway of the host first, then UPnP, which the gateway of the world answers
	UINT64 t0 = Tick64();
	bool granted = false;
	for (UINT64 end = t0 + DIRECTPATH_MAP_WAIT;Tick64() < end && granted == false;SleepThread(50))
	{
		DirectPathStats(ctx, DIRECTPATH_C, &st_c);
		granted = (st_c.PortMap == PEER_PORTMAP_MAPPED);
	}
	PeerAddrToStr(addr, sizeof(addr), &st_c.Mapped);
	Print("  [INFO] the gateway answered %u M-SEARCH and %u HTTP requests; node-c had its public port %s after %I64u ms\n", HomeGwSearches(ctx->Gateway), HomeGwRequests(ctx->Gateway), addr,
		Tick64() - t0);
	mapped = ctx->Nodes[DIRECTPATH_C].Public;
	bool forward = HomeGwMapped(ctx->Gateway, &external, &internal);
	mapped.Port = external;
	DirectPathCheck(ctx, granted && forward && internal == DIRECTPATH_HOST_PORT && PeerAddrEqual(&st_c.Mapped, &mapped),
		"With port mapping on, libplum found the gateway of the simulator and it mapped a public port of the NAT of node-c to the socket of its peer agent",
		"port mapping %s at %s; the gateway forwards %u to %u", NodeAgentPortMapName(st_c.PortMap), addr, (UINT)external, (UINT)internal);

	UINT num = PeerGetCandidates(DirectPathAgent(ctx, DIRECTPATH_C), c, PEER_MAX_CANDIDATES);
	DirectPathCheck(ctx, num != 0 && c[0].Type == PEER_CANDIDATE_MAPPED && PeerAddrEqual(&c[0].Addr, &mapped), "node-c offers that public port first among its candidates",
		"%u candidates, the first of type %u", num, num > 0 ? c[0].Type : 0);

	// node-c offers again with the public port, and node-b reaches it there: the only way in through its symmetric NAT
	bool direct = DirectPathWaitPath(ctx, DIRECTPATH_B, DIRECTPATH_C, PEER_PATH_DIRECT, PEER_ICE_COMPLETED, DIRECTPATH_UP_WAIT, &bc, &cb);
	PeerAddrToStr(addr, sizeof(addr), &bc.Direct);
	Print("  [INFO] node-b reaches node-c at %s\n", addr);
	DirectPathCheck(ctx, direct && PeerAddrEqual(&bc.Direct, &mapped), "The mapped port is used: node-b reaches node-c on the direct path at the public port that the gateway granted",
		"path of node-b to node-c %u, ICE %s, at %s", bc.Path, DirectPathIceName(bc.Ice), addr);

	bool echo = DirectPathEcho(ctx, DIRECTPATH_B, DIRECTPATH_C, 44000);
	DirectPathStats(ctx, DIRECTPATH_C, &st_c);
	DirectPathCheck(ctx, echo && st_c.Upgrades >= 1, "A packet of the host of node-b reaches the host of node-c on that path and comes back, and node-c counts its Upgrade",
		"echo %u, Upgrades of node-c %I64u", (UINT)echo, st_c.Upgrades);
}

// f. Export: the Upgrades and the Fallbacks of each Node in its state, as ranz node state prints it, and in the Telemetry
// that it reported to the stand-in of the Controller
static void DirectPathExport(DIRECTPATH_CTX *ctx)
{
	char *reply = ZeroMalloc(NODE_ADMIN_REPLY);

	Print("[f. export: the Upgrades and the Fallbacks of each Node in its state and in its Telemetry]\n");

	for (UINT i = 0;i < DIRECTPATH_NUM_NODES;i++)
	{
		DIRECTPATH_NODE *t = &ctx->Nodes[i];
		DIRECTPATH_LINK *l = &ctx->Links[i];
		PEER_STATS st;
		char counts[MAX_SIZE];
		char what[MAX_SIZE];
		bool state = false, reported = false;

		if (t->Node == NULL)
		{
			continue;
		}

		Zero(&st, sizeof(st));
		counts[0] = 0;

		// The counts can change while they are read, as an Upgrade with node-c may still come: the three must agree once
		for (UINT64 end = Tick64() + DIRECTPATH_BOUND;Tick64() < end && (state == false || reported == false);SleepThread(DIRECTPATH_POLL))
		{
			DirectPathStats(ctx, i, &st);
			Format(counts, sizeof(counts), "\"upgrades\":%I64u,\"fallbacks\":%I64u,\"portMapping\":\"%s\"", st.Upgrades, st.Fallbacks, NodeAgentPortMapName(st.PortMap));
			Zero(reply, NODE_ADMIN_REPLY);
			NodeAdminCommand(t->Node, "state", reply, NODE_ADMIN_REPLY);
			state = InStr(reply, counts) && InStr(reply, "\"datagramPath\":{\"running\":true,\"ice\":true,");
			reported = (InterlockedCompareExchange(&l->Reports, 0, 0) != 0 && (UINT64)InterlockedCompareExchange64(&l->Upgrades, 0, 0) == st.Upgrades &&
				(UINT64)InterlockedCompareExchange64(&l->Fallbacks, 0, 0) == st.Fallbacks);
		}

		UINT at = SearchStr(reply, "\"datagramPath\":", 0);
		Print("  [INFO] %s: %I64u Upgrades and %I64u Fallbacks; its state from its datagram path on: %.200s\n", t->Name, st.Upgrades, st.Fallbacks, at != INFINITE ? reply + at : reply);

		Format(what, sizeof(what), "The state of %s, as its admin pipe answers it and ranz node state prints it, holds its Upgrades and Fallbacks and its port mapping", t->Name);
		DirectPathCheck(ctx, state && st.Upgrades >= 1 && (i == DIRECTPATH_C || st.Fallbacks == 1), what, "it lacks %s", counts);

		Format(what, sizeof(what), "%s reported its Upgrades and Fallbacks in its Telemetry to the stand-in of the Controller, which exports them", t->Name);
		DirectPathCheck(ctx, reported, what, "%ld reports, the last with %I64d Upgrades and %I64d Fallbacks, against %I64u and %I64u", InterlockedCompareExchange(&l->Reports, 0, 0),
			InterlockedCompareExchange64(&l->Upgrades, 0, 0), InterlockedCompareExchange64(&l->Fallbacks, 0, 0), st.Upgrades, st.Fallbacks);
	}

	Free(reply);
}

//
// The world
//

// Build the world: the keys, the network of the simulator with its NATs, its tap, relay-1, stun-1 and the home gateway of
// node-c, the transports, the stand-in of the Controller, and node-a and node-b
static bool DirectPathStart(DIRECTPATH_CTX *ctx)
{
	UCHAR scalar[PEER_KEY_SIZE];
	bool ok = true;

	// The static keys: the scalars 1, 2, ... of the conformance tests for the Nodes, others for relay-1 and the Controller
	for (UINT i = 0;i < DIRECTPATH_NUM_NODES + 2;i++)
	{
		PEER_KEY *k = (i < DIRECTPATH_NUM_NODES ? &ctx->Nodes[i].Key : (i == DIRECTPATH_NUM_NODES ? &ctx->RelayKey : &ctx->ControllerKey));

		for (UINT j = 0;j < PEER_KEY_SIZE;j++)
		{
			scalar[j] = (UCHAR)(1 + PEER_KEY_SIZE * (i < DIRECTPATH_NUM_NODES ? i : i + 1) + j);
		}
		ok = PeerKeyFromScalar(k, scalar) && ok;
	}
	Zero(scalar, sizeof(scalar));
	if (DirectPathCheck(ctx, ok, "The static keys of the Nodes, relay-1 and the Controller", "PeerKeyFromScalar failed") == false)
	{
		return false;
	}

	ctx->Sim = NatSimNew();
	if (DirectPathCheck(ctx, ctx->Sim != NULL, "The network of the NAT simulator", "NatSimNew failed") == false)
	{
		return false;
	}
	NatSimSetTap(ctx->Sim, DirectPathTap, ctx);

	// node-a and node-b behind port restricted cone NATs, node-c behind a symmetric one
	for (UINT i = 0;i < DIRECTPATH_NUM_NODES;i++)
	{
		DIRECTPATH_NODE *t = &ctx->Nodes[i];
		UINT mapping = (i == DIRECTPATH_C ? NATSIM_MAP_ADDRESS_PORT_DEPENDENT : NATSIM_MAP_ENDPOINT_INDEPENDENT);

		t->Name = directpath_names[i];
		InitializeSRWLock(&t->Lock);
		t->Nat = NatSimAddNat(ctx->Sim, 203, 0, 113, (UCHAR)(10 * (i + 1)), mapping, NATSIM_FILTER_ADDRESS_PORT_DEPENDENT);
		PeerAddrSetV4(&t->Public, 203, 0, 113, (UCHAR)(10 * (i + 1)), 0);
		if (i == DIRECTPATH_A)
		{
			PeerAddrSetV4(&t->Addr, 192, 168, 1, 2, DIRECTPATH_HOST_PORT);
		}
		else if (i == DIRECTPATH_B)
		{
			PeerAddrSetV4(&t->Addr, 10, 0, 0, 2, DIRECTPATH_HOST_PORT);
		}
		else
		{
			PeerAddrSetV4(&t->Addr, 172, 16, 0, 2, DIRECTPATH_HOST_PORT);
		}
		t->Host = (t->Nat != NULL ? NatSimAddHost(ctx->Sim, t->Nat, &t->Addr) : NULL);
		ok = (t->Host != NULL) && ok;
	}

	PeerAddrSetV4(&ctx->RelayAddr, 198, 51, 100, 1, DIRECTPATH_RELAY_PORT);
	ctx->RelayHost = NatSimAddHost(ctx->Sim, NULL, &ctx->RelayAddr);
	PeerAddrSetV4(&ctx->StunAddr, 198, 51, 100, 9, DIRECTPATH_STUN_PORT);
	ctx->StunHost = NatSimAddHost(ctx->Sim, NULL, &ctx->StunAddr);
	InitializeSRWLock(&ctx->RelayLock);
	PeerDefaultConfig(&ctx->RelayConfig);
	ctx->RelayConfig.Relay = true;
	ok = ok && ctx->RelayHost != NULL && ctx->StunHost != NULL && DirectPathRelayStart(ctx);
	ctx->Ticker = (ok ? CreateThread(NULL, 0, DirectPathTicker, ctx, 0, NULL) : NULL);
	if (DirectPathCheck(ctx, ok && ctx->Ticker != NULL, "The hosts of the network, relay-1, the peer layer of the relay role, on its host, and stun-1, which no Node is told of",
		"a host or relay-1 could not start") == false)
	{
		return false;
	}

	// The gateway of the home of node-c answers from the start, so that it would see any request of a Node
	ctx->Gateway = HomeGwNew(ctx->Sim, ctx->Nodes[DIRECTPATH_C].Nat);
	if (DirectPathCheck(ctx, ctx->Gateway != NULL, "The home gateway of the NAT of node-c answers SSDP and HTTP on the loopback interfaces of the host", "HomeGwNew failed") == false)
	{
		return false;
	}

	// The peer layer of the agents: ICE on, with no STUN server, the port mapping off unless the setting of a Node turns it
	// on, and the keepalive of the Bindings in the time of a test
	PeerDefaultConfig(&ctx->PathConfig);
	ctx->PathConfig.Ice = true;
	ctx->PathConfig.PortMapTimeout = DIRECTPATH_MAP_TIMEOUT;
	ctx->PathConfig.BindInterval = DIRECTPATH_BIND;
	ctx->PathConfig.BindRetry = DIRECTPATH_BIND_RETRY;

	// The transports, and the stand-in of the Controller, which listens on the bound one
	ctx->Data = TransportLoopbackNew("loopback", 0, false);
	ctx->Control = TransportLoopbackNew("control", 0, true);
	ctx->Listener = (ctx->Control != NULL ? TransportListen(ctx->Control, DIRECTPATH_CONTROLLER) : NULL);
	for (UINT i = 0;i < DIRECTPATH_NUM_NODES;i++)
	{
		ctx->Links[i].Out = ControlNewSignals();
		ok = (ctx->Links[i].Out != NULL) && ok;
	}
	ctx->Acceptor = (ok && ctx->Data != NULL && ctx->Listener != NULL ? CreateThread(NULL, 0, DirectPathAccept, ctx, 0, NULL) : NULL);
	if (DirectPathCheck(ctx, ctx->Acceptor != NULL, "The stand-in of the Controller listens on the bound loopback transport of the control streams", "it could not start") == false)
	{
		return false;
	}

	return DirectPathStartNode(ctx, DIRECTPATH_A) && DirectPathStartNode(ctx, DIRECTPATH_B);
}

// Stop the world: the Nodes first, which close their control streams and leave the network, then the stand-in, relay-1,
// the gateway and the network, and delete what the test made
static void DirectPathStop(DIRECTPATH_CTX *ctx)
{
	for (UINT i = 0;i < DIRECTPATH_NUM_NODES;i++)
	{
		DIRECTPATH_NODE *t = &ctx->Nodes[i];
		wchar_t log_dir[MAX_PATH];

		if (t->Node != NULL)
		{
			NodeReaderUnregister(t->Node, &t->Reader);
			NodeStop(t->Node);
			FreeNode(t->Node);
			t->Node = NULL;
			ConbinePathW(log_dir, sizeof(log_dir), t->Dir, NODE_LOG_DIR_NAME);
			DirectPathDeleteFiles(log_dir);
			DirectPathDeleteFiles(t->Dir);
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
		DIRECTPATH_STREAM *t = ctx->Streams[i];

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
	for (UINT i = 0;i < DIRECTPATH_NUM_NODES;i++)
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
		NatSimAttach(ctx->RelayHost, NULL);
		PeerFree(ctx->Relay);
		ctx->Relay = NULL;
	}
	HomeGwFree(ctx->Gateway);
	NatSimFree(ctx->Sim);

	if (ctx->Data != NULL)
	{
		TransportLoopbackFree(ctx->Data);
	}
	if (ctx->Control != NULL)
	{
		TransportLoopbackFree(ctx->Control);
	}

	for (UINT i = 0;i < DIRECTPATH_NUM_NODES;i++)
	{
		PeerKeyClose(&ctx->Nodes[i].Key);
	}
	PeerKeyClose(&ctx->RelayKey);
	PeerKeyClose(&ctx->ControllerKey);
}

// directpath: a pair of Nodes behind cone NATs moves from the Relay to the direct path that ICE finds, and back
RANZ_TEST_TAGS("directpath", directpath_test, "core", "Direct path of the new core (CORE-S5-6): a pair of Nodes behind cone NATs of the simulator moves from a Relay to the direct path that ICE validates in the same peer session, with no STUN server, falls back to the Relay when the NAT drops its mapping, and a Node with port mapping on offers the public port that a home gateway grants first.");
void directpath_test(UINT num, char **arg)
{
	DIRECTPATH_CTX *ctx = ZeroMalloc(sizeof(DIRECTPATH_CTX));
	DIRECTPATH_SESSION session;
	HANDLE done = CreateEventW(NULL, TRUE, FALSE, NULL);
	HANDLE watchdog = (done != NULL ? CreateThread(NULL, 0, DirectPathWatchdog, done, 0, NULL) : NULL);

	Print("Direct path test: a pair of Nodes behind cone NATs moves from a Relay to the direct path that ICE validates, and back\n");

	Zero(&session, sizeof(session));
	if (DirectPathCheck(ctx, CryptoInit(), "The crypto module of the new core runs on CNG", "CryptoInit failed") && DirectPathStart(ctx) && DirectPathBringUp(ctx) && DirectPathUpgrade(ctx, &session))
	{
		DirectPathCandidates(ctx);
		DirectPathFallback(ctx, &session);
		DirectPathPortMapping(ctx);
		DirectPathExport(ctx);
	}

	DirectPathStop(ctx);

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
		Print("DIRECTPATH TEST OK\n");
	}
	else
	{
		Print("DIRECTPATH TEST FAILED (%u of %u checks failed)\n", ctx->NumFailed, ctx->NumChecks);
	}

	Free(ctx);
}
