// punchpathtest.c
// Named punch path test of vpntest ("punchpath" command, CORE-S5-7 #413)
//
// Two Nodes behind symmetric NATs, which ICE leaves on the Relay, get a direct path by punching (the peer agent of the
// overlay, Cedar/NodeAgent.c, with the port prediction and birthday punching of the peer layer, Core/PeerPunch.c), in a
// world of the NAT simulator of the core tests (src/coretest/natsim.c), in process, as seam 2 of #45 runs the data plane:
// - node-a and node-b sit behind NATs of address and port dependent mapping and filtering (symmetric NATs) that allocate
//   their ports in order. The NATs are carrier-grade: their other subscribers take a number of ports while ICE runs, which a
//   generator draws from the seed of the world, so a run is reproducible for its seed and the prediction of each Node misses
//   by as many ports. Neither Node names an endpoint, so their pair takes the datagram path.
// - relay-1 and relay-2 are the peer layers of two relay roles on the public side; relay-1 is the home relay of both
//   Nodes, and each Node binds both, so that the answers of the two binds tell it that its NAT is symmetric.
// - The Controller is a stand-in of this file on the control stream of each Node, as in directpathtest.c: the Updates of
//   the desired state, the Signals of the Nodes, which it carries to the Node they name, and the Telemetry with the Paths
//   and the punches of each Node.
// - A fake adapter stands in for the host of each Node, and the test sends the packets of each host into its Node. A tap
//   sees every datagram that a host sends, counts the punch messages of each Node with their times, and keeps the last
//   probe of node-b, which an attacker on the link of node-a sends again from an address of its own. A cut of the
//   simulator loses every datagram between the two NATs while the test holds the punch back.
// The steps:
// a. Bring-up: node-a and node-b apply Generation 1 and come up through relay-1; each tells from the answers of its binds
//    to relay-1 and relay-2 that its NAT is a sequential symmetric one, and predicts the port of its next mapping. The
//    other subscribers of each NAT take their ports.
// b. ICE fails: no check passes two symmetric NATs, so the ICE session of the pair fails at both ends, while the pair
//    stays on relay-1 in its peer session.
// c. Limits: the path between the NATs is cut. The Node that offers the pair sends a punch offer, the other takes it and
//    answers, and both probe; each attempt spends its budget and fails, within the rate per second and the budget per
//    attempt. A captured probe of node-b that an attacker sends from its own address moves node-a to no direct path there,
//    the same probe with a byte of its tag changed is dropped as forged and counted, and a probe of a node that is no peer
//    is dropped and counted. More captured probes of node-b, which the attacker sends again, draw answers of node-a only
//    within its rate and the budget of its attempt, which counts the probes and the answers of the attempt together. After
//    the attempts that met nothing the pair stays on relay-1 until the backoff ends, its traffic going on in the same peer
//    session.
// d. The punch: the cut is lifted before the backoff ends, and the attempt after it meets: both ends move to the direct
//    path, in the same peer session, at the mapping of the peer that proved itself; relay-1 carries no data of the pair
//    after the move.
// e. Fallback: the path between the NATs is cut again, the keepalives of the punched path go unanswered, and both ends
//    fall back to relay-1 with their peer session. Records that name node-b as their source and open in no session, which
//    an attacker sends node-a from the address of node-b on the punched path, do not hold node-a there.
// f. Export: the state of each Node, as its admin pipe answers it and ranz node state prints it, and the Telemetry that it
//    reports to the stand-in of the Controller, which the Controller exports, hold its NAT and its punches.
// g. Seeds: the same punch, at the peer layers of two Nodes on the network of the simulator, over many seeds of the
//    other subscribers: the success rate and the time to the direct path of each load, which the job log shows. A seed
//    that met and one that stayed on relay-1 run again and end the same way, the one that met at the same two mappings:
//    the simulator is deterministic for a seed.
// Print "PUNCHPATH TEST OK" only when every check passes.

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

#define	PUNCHPATH_BUDGET		540000		// The whole test ends within this time, or the watchdog ends the process (ms)
#define	PUNCHPATH_BOUND			20000		// A bounded wait on observable state (ms)
#define	PUNCHPATH_POLL			20			// Poll interval of observable state (ms)
#define	PUNCHPATH_READ			50			// ms that one read of a control stream of the stand-in waits
#define	PUNCHPATH_TICK			100			// ms between two ticks of the peer layers of the relays
#define	PUNCHPATH_BIND			400			// The keepalive of the Bindings of the Nodes: their BindInterval (ms) ...
#define	PUNCHPATH_BIND_RETRY	200			// ... and their BindRetry (ms)
#define	PUNCHPATH_ICE_WAIT		90000		// ms for ICE to give up the pair: libjuice fails a pair whose checks get no answer for 39.5 s
#define	PUNCHPATH_RETRY			3000		// The PunchRetry of the Nodes: ms from the end of an attempt to the next
#define	PUNCHPATH_ATTEMPTS		3			// The PunchAttempts of the Nodes: attempts that meet nothing before the backoff
#define	PUNCHPATH_BACKOFF		20000		// The PunchBackoff of the Nodes (ms)
#define	PUNCHPATH_CONSENT		6000		// The PunchConsent of the Nodes: ms of silence that end a punched path
#define	PUNCHPATH_FAIL_WAIT		60000		// ms for the attempts before the backoff to begin and fail
#define	PUNCHPATH_MEET_WAIT		30000		// ms for the attempt after the backoff to begin and meet
#define	PUNCHPATH_FALL_WAIT		30000		// ms for a punched path whose peer went silent to fall back ...
#define	PUNCHPATH_FALL_SLACK	3000		// ... which it does within this time after its PunchConsent
#define	PUNCHPATH_FORGE_EVERY	500			// ms between two datagrams of the attacker on the punched path, well under the PunchConsent
#define	PUNCHPATH_TAKE			8			// The most ports that the other subscribers of a NAT take while ICE runs ...
#define	PUNCHPATH_HEAVY_TAKE	24			// ... and in the heavy load of the seeds, more than the range of the punch covers
#define	PUNCHPATH_SEEDS			24			// The seeds of each load of step g
#define	PUNCHPATH_SEED			1			// The seed of the world, unless the command line names one
#define	PUNCHPATH_SWEEP_TICKS	20			// The ticks that one seed of step g is given to meet
#define	PUNCHPATH_SWEEP_TICK	50			// ms between two of them
#define	PUNCHPATH_ECHOES		3			// The echoes of a step
#define	PUNCHPATH_FLOOD			16			// The captured probes of node-b that the attacker sends again at once, more than an attempt keeps room to answer
#define	PUNCHPATH_TIMES			4096		// Punch messages of each Node whose times the tap keeps
#define	PUNCHPATH_VRF			1			// The id of VRF default ...
#define	PUNCHPATH_VRF_NAME		"default"	// ... its name and the name of its Network ...
#define	PUNCHPATH_MTU			1280		// ... and its MTU
#define	PUNCHPATH_FRAME_HEADER	4			// The size of a frame of a control stream, big-endian, before its message
#define	PUNCHPATH_MAX_FRAME		(1 << 20)	// The largest frame that the stand-in reads, as the node does (CONTROL_MAX_FRAME)
#define	PUNCHPATH_OUT_FRAME		65536		// The largest frame that it writes
#define	PUNCHPATH_MAX_STREAMS	16			// Control streams that the stand-in serves in one run at most
#define	PUNCHPATH_NUM_NODES		2
#define	PUNCHPATH_A				0			// node-a, behind a symmetric NAT
#define	PUNCHPATH_B				1			// node-b, behind another
#define	PUNCHPATH_NUM_RELAYS	2			// relay-1, the home relay, and relay-2
#define	PUNCHPATH_CONTROLLER	"controller"	// The address of the stand-in on the transport of the control streams
#define	PUNCHPATH_RELAY_PORT	5300		// The UDP port of the relay roles
#define	PUNCHPATH_HOST_PORT		5000		// The port of the socket of the peer agent of each Node on its host
#define	PUNCHPATH_ECHO_PORT		7			// The UDP port that the packets of the hosts go to
#define	PUNCHPATH_PAYLOAD_SIZE	42			// A punch message: version, sequence, type, a nonce and an echo of 16 bytes each

// What a read of a frame of a control stream at the stand-in gave
#define	PUNCHPATH_FRAME_DONE	0			// A whole frame is in Frame
#define	PUNCHPATH_FRAME_LATER	1			// Not within the timeout: the bytes read so far stay in Frame
#define	PUNCHPATH_FRAME_END		2			// The stream ended, or its next frame is larger than allowed

static char *punchpath_names[PUNCHPATH_NUM_NODES] = {"node-a", "node-b"};
static char *punchpath_tags[PUNCHPATH_NUM_NODES] = {"site-a", "site-b"};
static char *punchpath_relays[PUNCHPATH_NUM_RELAYS] = {"relay-1", "relay-2"};

// The payload of every packet of a host
static char punchpath_marker[] = "PUNCHPATH: the packet of a host, on the Relay or on the direct path that a punch found. ";

// One Node of the test, its host on the network of the simulator and the fake adapter of the host
typedef struct PUNCHPATH_NODE
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
} PUNCHPATH_NODE;

// The control stream of one Node at the stand-in of the Controller
typedef struct PUNCHPATH_LINK
{
	CONTROL_SIGNALS *Out;					// The Signals that the stand-in carries to the Node
	volatile LONG Active;					// A stream of the Node is served now
	volatile LONG Streams;					// The streams of the Node that the stand-in served
	volatile LONG64 Posted;					// The Generation of the desired state that the Node is to get
	volatile LONG64 Acked;					// The Generation that the Node acknowledged last
	volatile LONG Reports;					// The Telemetry messages with the Paths of the Node that it took
	volatile LONG64 Upgrades;				// ... the Upgrades of the last of them
	volatile LONG64 Fallbacks;				// ... its Fallbacks
	volatile LONG64 PunchAttempts;			// ... its punch attempts
	volatile LONG64 PunchSuccesses;			// ... the ones that met
	volatile LONG64 PunchFailures;			// ... and the ones whose prediction failed
} PUNCHPATH_LINK;

// One stream that the stand-in took, and its thread
typedef struct PUNCHPATH_STREAM
{
	struct PUNCHPATH_CTX *Ctx;
	TRANSPORT_STREAM *Stream;
	HANDLE Thread;
	UCHAR *Frame;							// The frame being read: its size, then its message
	UINT FrameSize;							// ... its bytes read so far
	UCHAR *Out;								// The frame being written
	ranz_control_v1_ControlMessage *Message;	// The message read last, or written
} PUNCHPATH_STREAM;

// The state of the test
typedef struct PUNCHPATH_CTX
{
	UINT NumChecks;
	UINT NumFailed;
	UINT Seed;								// The seed of the world
	bool Started;							// The keys and the addresses of the world are set: step g can run
	PUNCHPATH_NODE Nodes[PUNCHPATH_NUM_NODES];
	PEER_CONFIG PathConfig;					// The peer layer of the agents of the Nodes: ICE and the punch on, and the timers of a test

	// The network of the simulator and the two relays
	NATSIM *Sim;
	PEER_KEY RelayKeys[PUNCHPATH_NUM_RELAYS];		// The static keys of relay-1 and relay-2
	PEER_ADDR RelayAddrs[PUNCHPATH_NUM_RELAYS];		// The addresses of their relay roles
	PEER_CONFIG RelayConfig;						// ... and their configuration
	NATSIM_HOST *RelayHosts[PUNCHPATH_NUM_RELAYS];
	SRWLOCK RelayLock;								// Relays: their ticker
	PEER_AGENT *Relays[PUNCHPATH_NUM_RELAYS];		// The peer layers of the relay roles
	HANDLE Ticker;									// ... which this thread ticks
	volatile LONG Halt;								// Ends the threads of the test

	// The capture of every datagram that a host sends
	SRWLOCK TapLock;						// Everything below to Watched
	UINT NumTimes[PUNCHPATH_NUM_NODES];		// The punch messages that each Node sent ...
	UINT64 Times[PUNCHPATH_NUM_NODES][PUNCHPATH_TIMES];	// ... the times of the first PUNCHPATH_TIMES of them (ms of the performance counter)
	UCHAR Probe[PEER_MAX_DATAGRAM];			// The last punch message of node-b ...
	UINT ProbeSize;							// ... and its size, 0 for none
	PEER_ADDR Watch;						// The datagrams of node-a to this address ...
	UINT Watched;							// ... are counted here
	volatile LONG64 RelayRecords;			// The records of peer sessions on the links of the Nodes with relay-1

	// The transports: the data streams between the Nodes, which neither dials, and the control streams to the stand-in
	TRANSPORT *Data;
	TRANSPORT *Control;

	// The stand-in of the Controller
	PEER_KEY ControllerKey;					// Its static key
	TRANSPORT_LISTENER *Listener;
	HANDLE Acceptor;						// The thread that takes the streams
	PUNCHPATH_LINK Links[PUNCHPATH_NUM_NODES];
	PUNCHPATH_STREAM *Streams[PUNCHPATH_MAX_STREAMS];
	volatile LONG NumStreams;
	volatile LONG Carry;					// It carries the Signals: the Nodes applied their first state

	// The peer session of the pair, which stays through every step
	UCHAR SessionA[PEER_SESSION_ID_SIZE];
	UCHAR SessionB[PEER_SESSION_ID_SIZE];
	UINT64 HandshakesA;
	UINT64 HandshakesB;
} PUNCHPATH_CTX;

static bool PunchPathCheck(PUNCHPATH_CTX *ctx, bool ok, char *what, char *fmt, ...) RANZ_PRINTF_FORMAT(4, 5);
static bool PunchPathCheck(PUNCHPATH_CTX *ctx, bool ok, char *what, char *fmt, ...)
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
static DWORD WINAPI PunchPathWatchdog(LPVOID param)
{
	char msg[MAX_SIZE];
	DWORD written = 0;

	if (WaitForSingleObject((HANDLE)param, PUNCHPATH_BUDGET) != WAIT_TIMEOUT)
	{
		return 0;
	}

	int len = snprintf(msg, sizeof(msg), "PUNCHPATH TEST FAILED (did not finish within %u ms)\n", (UINT)PUNCHPATH_BUDGET);
	if (len > 0)
	{
		WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), msg, (DWORD)MIN((UINT)len, (UINT)sizeof(msg) - 1), &written, NULL);
	}

	TerminateProcess(GetCurrentProcess(), 1);

	return 0;
}

// The time of the performance counter in ms, as the tap records the punch messages
static UINT64 PunchPathClock()
{
	LARGE_INTEGER now, freq;

	QueryPerformanceCounter(&now);
	QueryPerformanceFrequency(&freq);

	return (UINT64)now.QuadPart * 1000 / (UINT64)freq.QuadPart;
}

//
// The packets of the hosts
//

// The address of node i in VRF default, 100.64.0.(1 + i), into addr
static void PunchPathIp(UCHAR *addr, UINT i)
{
	addr[0] = 100;
	addr[1] = 64;
	addr[2] = 0;
	addr[3] = (UCHAR)(1 + i);
}

// A UDP packet from the host of node from, port sport, to the host of node to, port dport, whose payload is the marker:
// its size
static UINT PunchPathPacket(UCHAR *buf, UINT from, UINT to, USHORT sport, USHORT dport)
{
	UINT len = StrLen(punchpath_marker);
	UINT size = 28 + len;
	UCHAR *udp = buf + 20;

	Zero(buf, size);
	buf[0] = 0x45;
	buf[2] = (UCHAR)(size >> 8);
	buf[3] = (UCHAR)size;
	buf[8] = 64;
	buf[9] = IP_PROTO_UDP;
	PunchPathIp(buf + 12, from);
	PunchPathIp(buf + 16, to);
	USHORT sum = IpChecksum(buf, 20);
	Copy(buf + 10, &sum, 2);

	WRITE_USHORT(udp, sport);
	WRITE_USHORT(udp + 2, dport);
	WRITE_USHORT(udp + 4, size - 20);
	Copy(buf + 28, punchpath_marker, len);

	return size;
}

// The fake adapter of a host: it keeps the packet that it took last and counts them
static void PunchPathAdapter(NODE *n, void *param, UINT vrf_id, const UCHAR *packet, UINT size)
{
	PUNCHPATH_NODE *t = (PUNCHPATH_NODE *)param;

	AcquireSRWLockExclusive(&t->Lock);
	{
		t->LastSize = MIN(size, (UINT)sizeof(t->Last));
		Copy(t->Last, packet, t->LastSize);
		t->LastVrf = vrf_id;
	}
	ReleaseSRWLockExclusive(&t->Lock);

	InterlockedIncrement(&t->Packets);
}

// Whether the adapter of node t took count packets within PUNCHPATH_BOUND
static bool PunchPathWaitPackets(PUNCHPATH_CTX *ctx, UINT t, LONG count)
{
	for (UINT64 end = Tick64() + PUNCHPATH_BOUND;Tick64() < end;SleepThread(1))
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
static bool PunchPathEcho(PUNCHPATH_CTX *ctx, UINT from, UINT to, USHORT sport)
{
	UCHAR packet[PEER_MAX_DATAGRAM];
	bool ok = true;

	for (UINT k = 0;k < 2 && ok;k++)
	{
		UINT src = (k == 0 ? from : to), dst = (k == 0 ? to : from);
		USHORT sp = (USHORT)(k == 0 ? sport : PUNCHPATH_ECHO_PORT), dp = (USHORT)(k == 0 ? PUNCHPATH_ECHO_PORT : sport);
		PUNCHPATH_NODE *t = &ctx->Nodes[dst];
		LONG before = InterlockedCompareExchange(&t->Packets, 0, 0);
		UINT size = PunchPathPacket(packet, src, dst, sp, dp);

		NodeReaderOnline(ctx->Nodes[src].Node, &ctx->Nodes[src].Reader);
		ok = NodeOverlayInput(ctx->Nodes[src].Node, PUNCHPATH_VRF, packet, size);
		NodeReaderOffline(&ctx->Nodes[src].Reader);

		ok = ok && PunchPathWaitPackets(ctx, dst, before + 1);
		if (ok)
		{
			AcquireSRWLockShared(&t->Lock);
			ok = (t->LastSize == size && t->LastVrf == PUNCHPATH_VRF && Cmp(t->Last, packet, size) == 0);
			ReleaseSRWLockShared(&t->Lock);
		}
	}

	return ok;
}

//
// The network of the simulator
//

// Whether a and b have the same IP address, whatever their ports
static bool PunchPathSameIp(const PEER_ADDR *a, const PEER_ADDR *b)
{
	return (Cmp(a->Ip, b->Ip, sizeof(a->Ip)) == 0);
}

// The tap of the network (NATSIM_TAP): every datagram that a host sends, on whatever link, before the network routes it.
// It counts the punch messages of each Node with their times, keeps the last one of node-b, counts the datagrams of
// node-a to the watched address, and the records of peer sessions on the links of the Nodes with relay-1.
static bool PunchPathTap(void *param, NATSIM_HOST *from, const PEER_ADDR *dst, const UCHAR *data, UINT size)
{
	PUNCHPATH_CTX *ctx = (PUNCHPATH_CTX *)param;

	if (size == 0)
	{
		return true;
	}

	AcquireSRWLockExclusive(&ctx->TapLock);
	{
		for (UINT i = 0;i < PUNCHPATH_NUM_NODES;i++)
		{
			if (from != ctx->Nodes[i].Host)
			{
				continue;
			}

			if (data[0] == PEER_MSG_PUNCH)
			{
				if (ctx->NumTimes[i] < PUNCHPATH_TIMES)
				{
					ctx->Times[i][ctx->NumTimes[i]] = PunchPathClock();
				}
				ctx->NumTimes[i]++;

				if (i == PUNCHPATH_B && size <= sizeof(ctx->Probe))
				{
					Copy(ctx->Probe, data, size);
					ctx->ProbeSize = size;
				}
			}

			if (i == PUNCHPATH_A && PeerAddrEqual(dst, &ctx->Watch))
			{
				ctx->Watched++;
			}
		}
	}
	ReleaseSRWLockExclusive(&ctx->TapLock);

	if (data[0] == PEER_MSG_RECORD)
	{
		bool nodes = (from == ctx->Nodes[PUNCHPATH_A].Host || from == ctx->Nodes[PUNCHPATH_B].Host);
		bool to_relay = (nodes && PeerAddrEqual(dst, &ctx->RelayAddrs[0]));
		bool from_relay = (from == ctx->RelayHosts[0]);

		if (to_relay || from_relay)
		{
			InterlockedIncrement64(&ctx->RelayRecords);
		}
	}

	return true;
}

// The most punch messages that node i sent within any 1000 ms that the tap saw, among the first PUNCHPATH_TIMES of them
static UINT PunchPathPeak(PUNCHPATH_CTX *ctx, UINT i)
{
	UINT peak = 0;

	AcquireSRWLockShared(&ctx->TapLock);
	{
		UINT num = MIN(ctx->NumTimes[i], (UINT)PUNCHPATH_TIMES);

		for (UINT k = 0;k < num;k++)
		{
			UINT n = 0;

			for (UINT j = k;j < num && ctx->Times[i][j] - ctx->Times[i][k] < 1000;j++)
			{
				n++;
			}
			peak = MAX(peak, n);
		}
	}
	ReleaseSRWLockShared(&ctx->TapLock);

	return peak;
}

// The punch messages that node i sent in all, as the tap counted them
static UINT PunchPathMessages(PUNCHPATH_CTX *ctx, UINT i)
{
	AcquireSRWLockShared(&ctx->TapLock);
	UINT n = ctx->NumTimes[i];
	ReleaseSRWLockShared(&ctx->TapLock);

	return n;
}

// The ticker of the relays: the timers of their peer layers, which drop the Bindings that were not renewed
static DWORD WINAPI PunchPathTicker(LPVOID param)
{
	PUNCHPATH_CTX *ctx = (PUNCHPATH_CTX *)param;

	while (InterlockedCompareExchange(&ctx->Halt, 0, 0) == 0)
	{
		AcquireSRWLockShared(&ctx->RelayLock);
		for (UINT r = 0;r < PUNCHPATH_NUM_RELAYS;r++)
		{
			PeerTick(ctx->Relays[r]);
		}
		ReleaseSRWLockShared(&ctx->RelayLock);

		Sleep(PUNCHPATH_TICK);
	}

	return 0;
}

// The peer infos of the two Nodes in VRF default, as the Peer objects of the desired state of a relay give them
static void PunchPathPeerInfos(PUNCHPATH_CTX *ctx, PEER_INFO *peers)
{
	for (UINT i = 0;i < PUNCHPATH_NUM_NODES;i++)
	{
		Zero(&peers[i], sizeof(PEER_INFO));
		StrCpy(peers[i].Name, sizeof(peers[i].Name), punchpath_names[i]);
		Copy(peers[i].Key, ctx->Nodes[i].Key.Public, PEER_KEY_SIZE);
		peers[i].NumVrfs = 1;
		peers[i].VrfIds[0] = PUNCHPATH_VRF;
	}
}

// Start the peer layers of the relay roles of relay-1 and relay-2 on their hosts, with the two Nodes as their peers
static bool PunchPathRelayStart(PUNCHPATH_CTX *ctx)
{
	PEER_INFO peers[PUNCHPATH_NUM_NODES];

	PunchPathPeerInfos(ctx, peers);

	for (UINT r = 0;r < PUNCHPATH_NUM_RELAYS;r++)
	{
		PEER_AGENT *p = PeerNew(&ctx->RelayKeys[r], &ctx->RelayConfig, NatSimSend, ctx->RelayHosts[r], NULL, NULL);
		if (p == NULL)
		{
			return false;
		}
		PeerSetPeers(p, peers, PUNCHPATH_NUM_NODES);

		AcquireSRWLockExclusive(&ctx->RelayLock);
		ctx->Relays[r] = p;
		ReleaseSRWLockExclusive(&ctx->RelayLock);

		NatSimAttach(ctx->RelayHosts[r], p);
	}

	return true;
}

// The counters of relay r
static void PunchPathRelayStats(PUNCHPATH_CTX *ctx, UINT r, PEER_STATS *st)
{
	AcquireSRWLockShared(&ctx->RelayLock);
	PeerGetStats(ctx->Relays[r], st);
	ReleaseSRWLockShared(&ctx->RelayLock);
}

// The peer layer of the agent of node i, NULL before the network took it
static PEER_AGENT *PunchPathAgent(PUNCHPATH_CTX *ctx, UINT i)
{
	return (PEER_AGENT *)ReadPointerAcquire((PVOID const volatile *)&ctx->Nodes[i].Agent);
}

// How node i reaches node j, into st: false when it does not know j as a peer
static bool PunchPathStatus(PUNCHPATH_CTX *ctx, UINT i, UINT j, PEER_STATUS *st)
{
	return PeerGetStatus(PunchPathAgent(ctx, i), ctx->Nodes[j].Key.Public, st);
}

// The counters of the peer layer of the agent of node i, into st
static void PunchPathStats(PUNCHPATH_CTX *ctx, UINT i, PEER_STATS *st)
{
	NODE_AGENT_STATUS as;

	NodeAgentGetStatus(ctx->Nodes[i].Node, &as);
	Copy(st, &as.Peer, sizeof(PEER_STATS));
}

// The name of a path of PEER_PATH_*
static char *PunchPathPathName(UINT path)
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
static char *PunchPathIceName(UINT ice)
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

// The name of a punch state of PEER_PUNCH_*
static char *PunchPathPunchName(UINT punch)
{
	switch (punch)
	{
	case PEER_PUNCH_PROBING:
		return "probing";
	case PEER_PUNCH_CONNECTED:
		return "connected";
	case PEER_PUNCH_FAILED:
		return "failed";
	default:
		return "none";
	}
}

// The name of a NAT of PEER_NAT_*
static char *PunchPathNatName(UINT nat)
{
	switch (nat)
	{
	case PEER_NAT_CONE:
		return "cone";
	case PEER_NAT_SEQUENTIAL:
		return "sequential";
	case PEER_NAT_RANDOM:
		return "random";
	default:
		return "unknown";
	}
}

// What node i saw of its pair with node j, into str: the path, the ICE session, the punch, the address of the direct path,
// its punches, and what its peer layer dropped, by reason
static void PunchPathPairWords(PUNCHPATH_CTX *ctx, UINT i, UINT j, char *str, UINT size)
{
	PEER_STATUS st;
	PEER_STATS stats;
	char addr[64];
	char one[MAX_SIZE];

	bool known = PunchPathStatus(ctx, i, j, &st);
	PunchPathStats(ctx, i, &stats);
	PeerAddrToStr(addr, sizeof(addr), &st.Direct);
	Format(str, size, "%s to %s: %s, ICE %s, punch %s at %s, %I64u attempts, %I64u met, %I64u failed, %I64u probes; drops:", ctx->Nodes[i].Name, ctx->Nodes[j].Name,
		known ? PunchPathPathName(st.Path) : "no peer", PunchPathIceName(st.Ice), PunchPathPunchName(st.Punch), addr, stats.PunchAttempts, stats.PunchSuccesses,
		stats.PunchFailures, stats.PunchProbes);

	for (UINT r = PEER_OK + 1;r < PEER_NUM_REASONS;r++)
	{
		if (stats.Drops[r] != 0)
		{
			Format(one, sizeof(one), " %s %I64u", PeerReasonName(r), stats.Drops[r]);
			StrCat(str, size, one);
		}
	}
}

//
// The stand-in of the Controller
//

// Read the next frame of the stream t within timeout into Frame (PUNCHPATH_FRAME_*)
static UINT PunchPathRead(PUNCHPATH_STREAM *t, UINT timeout)
{
	UINT64 end = Tick64() + timeout;

	while (true)
	{
		UINT need = PUNCHPATH_FRAME_HEADER;

		if (t->FrameSize >= PUNCHPATH_FRAME_HEADER)
		{
			UINT size = ((UINT)t->Frame[0] << 24) | ((UINT)t->Frame[1] << 16) | ((UINT)t->Frame[2] << 8) | t->Frame[3];

			if (size == 0 || size > PUNCHPATH_MAX_FRAME - PUNCHPATH_FRAME_HEADER)
			{
				return PUNCHPATH_FRAME_END;
			}
			need += size;
			if (t->FrameSize == need)
			{
				return PUNCHPATH_FRAME_DONE;
			}
		}

		UINT64 now = Tick64();
		if (now >= end)
		{
			return PUNCHPATH_FRAME_LATER;
		}

		UINT got = TransportRead(t->Stream, t->Frame + t->FrameSize, need - t->FrameSize, (UINT)(end - now));
		if (got == 0 || (got != TRANSPORT_LATER && got > need - t->FrameSize))
		{
			return PUNCHPATH_FRAME_END;
		}
		if (got != TRANSPORT_LATER)
		{
			t->FrameSize += got;
		}
	}
}

// Write size bytes at Out after the frame header, as one frame
static bool PunchPathWriteFrame(PUNCHPATH_STREAM *t, UINT size)
{
	t->Out[0] = (UCHAR)(size >> 24);
	t->Out[1] = (UCHAR)(size >> 16);
	t->Out[2] = (UCHAR)(size >> 8);
	t->Out[3] = (UCHAR)size;

	return TransportWrite(t->Stream, t->Out, PUNCHPATH_FRAME_HEADER + size);
}

// Decode the frame in Frame into Message: false for bytes that are no ControlMessage
static bool PunchPathDecode(PUNCHPATH_STREAM *t)
{
	pb_istream_t is = pb_istream_from_buffer(t->Frame + PUNCHPATH_FRAME_HEADER, t->FrameSize - PUNCHPATH_FRAME_HEADER);

	Zero(t->Message, sizeof(ranz_control_v1_ControlMessage));

	return pb_decode(&is, ranz_control_v1_ControlMessage_fields, t->Message);
}

// The responder of the handshake of a control stream, as the Controller runs it: Noise_IK with the static key of the
// stand-in, bound to the exporter of the stream after the prologue of the control stream. The static key of the Node goes
// into remote.
static bool PunchPathHandshake(PUNCHPATH_CTX *ctx, PUNCHPATH_STREAM *t, UCHAR *remote)
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
	if (PunchPathRead(t, CONTROL_TIMEOUT) != PUNCHPATH_FRAME_DONE)
	{
		return false;
	}

	bool ok = NoiseHandshakeInit(&hs, NOISE_SUITE_IK, false, prologue, (UINT)sizeof(prologue), ctx->ControllerKey.Private, NULL, NULL);
	ok = ok && NoiseHandshakeRead(&hs, t->Frame + PUNCHPATH_FRAME_HEADER, t->FrameSize - PUNCHPATH_FRAME_HEADER, NULL, 0, &payload_size);
	ok = ok && NoiseHandshakeWrite(&hs, NULL, 0, t->Out + PUNCHPATH_FRAME_HEADER, PUNCHPATH_OUT_FRAME - PUNCHPATH_FRAME_HEADER, &size);
	if (ok)
	{
		Copy(remote, hs.RemoteStatic, PEER_KEY_SIZE);
	}
	NoiseHandshakeFree(&hs);
	t->FrameSize = 0;

	return ok && PunchPathWriteFrame(t, size);
}

// The Hello that a Node sends first after the handshake
static bool PunchPathHello(PUNCHPATH_STREAM *t)
{
	bool ok = (PunchPathRead(t, CONTROL_TIMEOUT) == PUNCHPATH_FRAME_DONE && PunchPathDecode(t) && t->Message->which_body == ranz_control_v1_ControlMessage_hello_tag);

	t->FrameSize = 0;

	return ok;
}

// The address of node i in VRF default as an Address of the control protocol
static void PunchPathAddress(ranz_control_v1_Address *a, UINT i)
{
	StrCpy(a->network, sizeof(a->network), PUNCHPATH_VRF_NAME);
	a->vrf_id = PUNCHPATH_VRF;
	a->has_prefix = true;
	a->prefix.address.size = 4;
	PunchPathIp(a->prefix.address.bytes, i);
	a->prefix.length = 10;
}

// The desired state of node i at Generation g, as an Update of the stand-in, into m: the Node with its tag and its address,
// VRF default with its policy, the other Node as its peer, relay-1 and relay-2, and the rule allow-all
static void PunchPathState(PUNCHPATH_CTX *ctx, UINT i, UINT64 g, ranz_control_v1_ControlMessage *m)
{
	UINT j = (i == PUNCHPATH_A ? PUNCHPATH_B : PUNCHPATH_A);

	Zero(m, sizeof(ranz_control_v1_ControlMessage));
	m->which_body = ranz_control_v1_ControlMessage_update_tag;

	ranz_control_v1_Update *u = &m->body.update;
	u->generation = g;

	ranz_control_v1_Object *o = &u->set[u->set_count++];
	ranz_control_v1_NodeConfig *node = &o->kind.node;
	o->which_kind = ranz_control_v1_Object_node_tag;
	StrCpy(node->name, sizeof(node->name), punchpath_names[i]);
	node->tags_count = 1;
	StrCpy(node->tags[0], sizeof(node->tags[0]), punchpath_tags[i]);
	node->addresses_count = 1;
	PunchPathAddress(&node->addresses[0], i);

	o = &u->set[u->set_count++];
	o->which_kind = ranz_control_v1_Object_vrf_tag;
	StrCpy(o->kind.vrf.name, sizeof(o->kind.vrf.name), PUNCHPATH_VRF_NAME);
	o->kind.vrf.id = PUNCHPATH_VRF;
	o->kind.vrf.mtu = PUNCHPATH_MTU;
	o->kind.vrf.has_policy = true;

	o = &u->set[u->set_count++];
	ranz_control_v1_Peer *p = &o->kind.peer;
	o->which_kind = ranz_control_v1_Object_peer_tag;
	StrCpy(p->name, sizeof(p->name), punchpath_names[j]);
	p->public_key.size = PEER_KEY_SIZE;
	Copy(p->public_key.bytes, ctx->Nodes[j].Key.Public, PEER_KEY_SIZE);
	p->vrf_ids_count = 1;
	p->vrf_ids[0] = PUNCHPATH_VRF;
	p->addresses_count = 1;
	PunchPathAddress(&p->addresses[0], j);
	p->tags_count = 1;
	StrCpy(p->tags[0], sizeof(p->tags[0]), punchpath_tags[j]);

	for (UINT r = 0;r < PUNCHPATH_NUM_RELAYS;r++)
	{
		o = &u->set[u->set_count++];
		ranz_control_v1_Relay *relay = &o->kind.relay;
		o->which_kind = ranz_control_v1_Object_relay_tag;
		StrCpy(relay->name, sizeof(relay->name), punchpath_relays[r]);
		relay->public_key.size = PEER_KEY_SIZE;
		Copy(relay->public_key.bytes, ctx->RelayKeys[r].Public, PEER_KEY_SIZE);
		relay->address.size = 4;
		Copy(relay->address.bytes, ctx->RelayAddrs[r].Ip + 12, 4);
		relay->port = PUNCHPATH_RELAY_PORT;
	}

	o = &u->set[u->set_count++];
	ranz_control_v1_Rule *rule = &o->kind.rule;
	o->which_kind = ranz_control_v1_Object_rule_tag;
	StrCpy(rule->name, sizeof(rule->name), "allow-all");
	rule->vrf_id = PUNCHPATH_VRF;
	rule->priority = 1000;
	rule->action = ranz_control_v1_RuleAction_RULE_ACTION_ALLOW;
}

// Write Message as one frame
static bool PunchPathWrite(PUNCHPATH_STREAM *t)
{
	pb_ostream_t os = pb_ostream_from_buffer(t->Out + PUNCHPATH_FRAME_HEADER, PUNCHPATH_OUT_FRAME - PUNCHPATH_FRAME_HEADER);

	if (pb_encode(&os, ranz_control_v1_ControlMessage_fields, t->Message) == false)
	{
		return false;
	}

	return PunchPathWriteFrame(t, (UINT)os.bytes_written);
}

// A frame that node i sent on its stream: an Ack; a Signal for a peer, which the stand-in carries to the Node that it names,
// under the name of its sender; or a Telemetry message, whose Paths and punches it keeps
static void PunchPathTake(PUNCHPATH_CTX *ctx, PUNCHPATH_STREAM *t, UINT i)
{
	PUNCHPATH_LINK *l = &ctx->Links[i];

	if (PunchPathDecode(t) == false)
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

			for (UINT j = 0;j < PUNCHPATH_NUM_NODES;j++)
			{
				if (StrCmp(s->peer, punchpath_names[j]) == 0 && size != 0)
				{
					ControlSendSignal(ctx->Links[j].Out, punchpath_names[i], s->envelope.bytes, size);
				}
			}
		}
		break;

	case ranz_control_v1_ControlMessage_telemetry_tag:
		if (t->Message->body.telemetry.has_paths)
		{
			const ranz_control_v1_PathCounters *pc = &t->Message->body.telemetry.paths;

			InterlockedExchange64(&l->Upgrades, (LONG64)pc->upgrades);
			InterlockedExchange64(&l->Fallbacks, (LONG64)pc->fallbacks);
			InterlockedExchange64(&l->PunchAttempts, (LONG64)pc->punch_attempts);
			InterlockedExchange64(&l->PunchSuccesses, (LONG64)pc->punch_successes);
			InterlockedExchange64(&l->PunchFailures, (LONG64)pc->punch_failures);
			InterlockedIncrement(&l->Reports);
		}
		break;

	default:
		break;
	}
}

// One control stream at the stand-in: the handshake names its Node, which says Hello; then the Updates that the test posts
// for the Node, the Signals that the stand-in carries to it once it carries them, and the frames of the Node, until the
// stream ends or the test halts
static DWORD WINAPI PunchPathServe(LPVOID param)
{
	PUNCHPATH_STREAM *t = (PUNCHPATH_STREAM *)param;
	PUNCHPATH_CTX *ctx = t->Ctx;
	PUNCHPATH_LINK *l = NULL;
	UCHAR remote[PEER_KEY_SIZE];
	UINT i = PUNCHPATH_NUM_NODES;
	UINT64 sent = 0;

	if (PunchPathHandshake(ctx, t, remote))
	{
		for (UINT j = 0;j < PUNCHPATH_NUM_NODES && i == PUNCHPATH_NUM_NODES;j++)
		{
			if (Cmp(remote, ctx->Nodes[j].Key.Public, PEER_KEY_SIZE) == 0)
			{
				i = j;
			}
		}
	}
	if (i < PUNCHPATH_NUM_NODES && InterlockedCompareExchange(&ctx->Links[i].Active, 1, 0) == 0)
	{
		l = &ctx->Links[i];
	}

	bool ok = (l != NULL && PunchPathHello(t));
	if (ok)
	{
		InterlockedIncrement(&l->Streams);
	}

	while (ok && InterlockedCompareExchange(&ctx->Halt, 0, 0) == 0)
	{
		UINT64 posted = (UINT64)InterlockedCompareExchange64(&l->Posted, 0, 0);

		if (posted > sent)
		{
			PunchPathState(ctx, i, posted, t->Message);
			ok = PunchPathWrite(t);
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

		UINT r = PunchPathRead(t, PUNCHPATH_READ);
		if (r == PUNCHPATH_FRAME_END)
		{
			break;
		}
		if (r == PUNCHPATH_FRAME_DONE)
		{
			PunchPathTake(ctx, t, i);
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
static DWORD WINAPI PunchPathAccept(LPVOID param)
{
	PUNCHPATH_CTX *ctx = (PUNCHPATH_CTX *)param;

	while (InterlockedCompareExchange(&ctx->Halt, 0, 0) == 0)
	{
		TRANSPORT_STREAM *s = TransportAccept(ctx->Listener, PUNCHPATH_TICK);
		LONG n = InterlockedCompareExchange(&ctx->NumStreams, 0, 0);

		if (s == NULL)
		{
			continue;
		}
		if (n >= PUNCHPATH_MAX_STREAMS)
		{
			TransportClose(s);
			continue;
		}

		PUNCHPATH_STREAM *t = ZeroMalloc(sizeof(PUNCHPATH_STREAM));
		t->Ctx = ctx;
		t->Stream = s;
		t->Frame = Malloc(PUNCHPATH_MAX_FRAME);
		t->Out = Malloc(PUNCHPATH_OUT_FRAME);
		t->Message = ZeroMalloc(sizeof(ranz_control_v1_ControlMessage));
		ctx->Streams[n] = t;
		InterlockedExchange(&ctx->NumStreams, n + 1);

		t->Thread = CreateThread(NULL, 0, PunchPathServe, t, 0, NULL);
		if (t->Thread == NULL)
		{
			TransportClose(t->Stream);
			t->Stream = NULL;
		}
	}

	return 0;
}

// Post Generation g for node i, whose stream sends it at once, and whether the Node acknowledged it within PUNCHPATH_BOUND
static bool PunchPathApply(PUNCHPATH_CTX *ctx, UINT i, UINT64 g)
{
	InterlockedExchange64(&ctx->Links[i].Posted, (LONG64)g);

	for (UINT64 end = Tick64() + PUNCHPATH_BOUND;Tick64() < end;SleepThread(PUNCHPATH_POLL))
	{
		if ((UINT64)InterlockedCompareExchange64(&ctx->Links[i].Acked, 0, 0) >= g)
		{
			return true;
		}
	}

	return false;
}

// Whether node i opened its control stream to the stand-in and said Hello within PUNCHPATH_BOUND
static bool PunchPathWaitHello(PUNCHPATH_CTX *ctx, UINT i)
{
	for (UINT64 end = Tick64() + PUNCHPATH_BOUND;Tick64() < end;SleepThread(PUNCHPATH_POLL))
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
// worker
static void PunchPathNewDir(wchar_t *dir, UINT size, char *name)
{
	wchar_t tmp[MAX_PATH];
	wchar_t path[MAX_PATH];

	UniFormat(tmp, sizeof(tmp), L"punchpathtest_%S_%u", name, Rand32());
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
static void PunchPathDeleteFiles(wchar_t *dir)
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

// The data transport dials a peer only at an endpoint, and neither Node names one
static bool PunchPathDialable(NODE *n, void *param, const char *name, const struct CONTROL_ENDPOINT *endpoints, UINT num)
{
	return (num != 0);
}

// The network of the simulator takes the peer layer of the agent of a Node, and NULL before it stops (NODE_PATH_ATTACH_PROC).
// The host candidate of the layer is the address of the host of the Node, with the port of its socket there.
static void PunchPathAttach(NODE *n, void *param, PEER_AGENT *agent)
{
	PUNCHPATH_NODE *t = (PUNCHPATH_NODE *)param;

	if (agent != NULL)
	{
		PeerSetHostCandidates(agent, &t->Addr, 1);
	}
	NatSimAttach(t->Host, agent);
	InterlockedExchangePointer((PVOID volatile *)&t->Agent, agent);
}

// Start node i: its data directory, its Node, and its overlay with the control stream to the stand-in, the data transport,
// the fake adapter of its host and the network of the simulator for its agent
static bool PunchPathStartNode(PUNCHPATH_CTX *ctx, UINT i)
{
	PUNCHPATH_NODE *t = &ctx->Nodes[i];
	NODE_OVERLAY_CONFIG c;
	char what[MAX_SIZE];

	PunchPathNewDir(t->Dir, sizeof(t->Dir), t->Name);
	t->Node = NewNode(t->Dir);
	NodeStart(t->Node);
	NodeReaderRegister(t->Node, &t->Reader);
	NodeReaderOffline(&t->Reader);

	Zero(&c, sizeof(c));
	c.Control = ctx->Control;
	StrCpy(c.Controller, sizeof(c.Controller), PUNCHPATH_CONTROLLER);
	Copy(c.ControllerKey, ctx->ControllerKey.Public, PEER_KEY_SIZE);
	c.Data = ctx->Data;
	c.Key = &t->Key;
	c.Adapter = PunchPathAdapter;
	c.AdapterParam = t;
	c.Dialable = PunchPathDialable;
	c.PathSend = NatSimSend;
	c.PathSendParam = t->Host;
	c.PathAttach = PunchPathAttach;
	c.PathConfig = &ctx->PathConfig;

	Format(what, sizeof(what), "%s: its overlay runs, with its control stream to the stand-in of the Controller and its peer agent with ICE and the punch on the network of the simulator", t->Name);

	return PunchPathCheck(ctx, NodeOverlayStart(t->Node, &c), what, "NodeOverlayStart failed");
}

// Whether node-a and node-b each reach the other on path within timeout ms
static bool PunchPathWaitPath(PUNCHPATH_CTX *ctx, UINT path, UINT timeout, PEER_STATUS *sa, PEER_STATUS *sb)
{
	for (UINT64 end = Tick64() + timeout;Tick64() < end;SleepThread(PUNCHPATH_POLL))
	{
		if (PunchPathStatus(ctx, PUNCHPATH_A, PUNCHPATH_B, sa) && PunchPathStatus(ctx, PUNCHPATH_B, PUNCHPATH_A, sb) && sa->Path == path && sb->Path == path)
		{
			return true;
		}
	}

	return false;
}

// The Node of the lower static key: the one that offers the pair and its punches, and that leads the exchange of the nonces
static UINT PunchPathLower(PUNCHPATH_CTX *ctx)
{
	return (Cmp(ctx->Nodes[PUNCHPATH_A].Key.Public, ctx->Nodes[PUNCHPATH_B].Key.Public, PEER_KEY_SIZE) < 0 ? PUNCHPATH_A : PUNCHPATH_B);
}

// Whether the peer session of the pair is the one of step a: the same keys at both ends, and no new handshake
static bool PunchPathSameSession(PUNCHPATH_CTX *ctx, char *detail, UINT size)
{
	PEER_STATUS sa, sb;

	bool known = PunchPathStatus(ctx, PUNCHPATH_A, PUNCHPATH_B, &sa) && PunchPathStatus(ctx, PUNCHPATH_B, PUNCHPATH_A, &sb);
	bool same = known && sa.Session == PEER_SESSION_UP && sb.Session == PEER_SESSION_UP && Cmp(sa.SessionId, ctx->SessionA, PEER_SESSION_ID_SIZE) == 0 &&
		Cmp(sb.SessionId, ctx->SessionB, PEER_SESSION_ID_SIZE) == 0 && Cmp(sa.SessionId, sb.SessionId, PEER_SESSION_ID_SIZE) == 0 &&
		sa.Handshakes == ctx->HandshakesA && sb.Handshakes == ctx->HandshakesB;

	Format(detail, size, "session up at node-a %u and at node-b %u; handshakes at node-a %I64u (%I64u before), at node-b %I64u (%I64u before); the same keys %u",
		(UINT)(sa.Session == PEER_SESSION_UP), (UINT)(sb.Session == PEER_SESSION_UP), sa.Handshakes, ctx->HandshakesA, sb.Handshakes, ctx->HandshakesB,
		(UINT)(Cmp(sa.SessionId, sb.SessionId, PEER_SESSION_ID_SIZE) == 0));

	return same;
}

// The echoes of a step from the host of node-a to the host of node-b and back, from ports from port on: how many came back
static UINT PunchPathEchoes(PUNCHPATH_CTX *ctx, USHORT port)
{
	UINT echoes = 0;

	for (UINT k = 0;k < PUNCHPATH_ECHOES;k++)
	{
		if (PunchPathEcho(ctx, PUNCHPATH_A, PUNCHPATH_B, (USHORT)(port + k)))
		{
			echoes++;
		}
	}

	return echoes;
}

//
// The steps
//

// a. Bring-up: the control streams say Hello, both Nodes apply Generation 1, and the stand-in carries their Signals from
// then on; they come up through relay-1, bind both relays and tell their NATs from the answers, and the other subscribers of
// each NAT take their ports while ICE runs
static bool PunchPathBringUp(PUNCHPATH_CTX *ctx)
{
	PEER_STATUS ab, ba;
	PEER_STATS st_a, st_b, rs;
	char words[MAX_SIZE * 2];
	char what[MAX_SIZE];

	Print("[a. bring-up: Generation 1, the Signals through the stand-in, the Path through relay-1, two binds that tell each NAT]\n");

	bool hello = PunchPathWaitHello(ctx, PUNCHPATH_A) && PunchPathWaitHello(ctx, PUNCHPATH_B);
	if (PunchPathCheck(ctx, hello, "node-a and node-b open their control streams to the stand-in of the Controller and say Hello", "not both said Hello") == false)
	{
		return false;
	}

	bool acked = PunchPathApply(ctx, PUNCHPATH_A, 1) && PunchPathApply(ctx, PUNCHPATH_B, 1);
	if (PunchPathCheck(ctx, acked, "node-a and node-b apply Generation 1, with relay-1 and relay-2, and acknowledge it", "not acknowledged") == false)
	{
		return false;
	}

	InterlockedExchange(&ctx->Carry, 1);

	bool up = PunchPathWaitPath(ctx, PEER_PATH_RELAY, PUNCHPATH_BOUND, &ab, &ba);
	PunchPathRelayStats(ctx, 0, &rs);
	PunchPathCheck(ctx, up && rs.NumBindings == 2, "node-a and node-b come up through relay-1 after their Signals", "path of node-a %s, of node-b %s; Bindings at relay-1 %u",
		PunchPathPathName(ab.Path), PunchPathPathName(ba.Path), rs.NumBindings);
	if (up == false)
	{
		return false;
	}

	// The two binds of each Node: the answers of relay-1 and relay-2 name two ports of its NAT. The checks of ICE make new
	// mappings meanwhile, so the prediction of each is read once it names the port after the newest mapping of its NAT.
	bool told = false;
	for (UINT64 end = Tick64() + PUNCHPATH_BOUND;Tick64() < end && told == false;SleepThread(PUNCHPATH_POLL))
	{
		PEER_ADDR mapped_a, mapped_b;

		PunchPathStats(ctx, PUNCHPATH_A, &st_a);
		PunchPathStats(ctx, PUNCHPATH_B, &st_b);
		told = (st_a.NumBound == 2 && st_b.NumBound == 2 && st_a.Nat == PEER_NAT_SEQUENTIAL && st_b.Nat == PEER_NAT_SEQUENTIAL &&
			NatSimMapped(ctx->Nodes[PUNCHPATH_A].Nat, &ctx->Nodes[PUNCHPATH_A].Addr, &mapped_a) && st_a.Predicted.Port == mapped_a.Port + 1 &&
			NatSimMapped(ctx->Nodes[PUNCHPATH_B].Nat, &ctx->Nodes[PUNCHPATH_B].Addr, &mapped_b) && st_b.Predicted.Port == mapped_b.Port + 1);
	}
	for (UINT i = 0;i < PUNCHPATH_NUM_NODES;i++)
	{
		PEER_STATS st = (i == PUNCHPATH_A ? st_a : st_b);
		PEER_ADDR mapped;
		char addr[64];

		NatSimMapped(ctx->Nodes[i].Nat, &ctx->Nodes[i].Addr, &mapped);
		PeerAddrToStr(addr, sizeof(addr), &st.Predicted);
		Print("  [INFO] %s is bound to %u Relays; its NAT is %s, and it predicts its next mapping at %s, after the newest one on port %u\n", ctx->Nodes[i].Name, st.NumBound,
			PunchPathNatName(st.Nat), addr, (UINT)mapped.Port);
		Format(what, sizeof(what), "%s binds relay-1 and relay-2, whose answers name two ports in a row of its NAT: it tells it is a symmetric NAT that allocates in order, and predicts the port of its next mapping",
			ctx->Nodes[i].Name);
		PunchPathCheck(ctx, told && st.Nat == PEER_NAT_SEQUENTIAL && PunchPathSameIp(&st.Predicted, &ctx->Nodes[i].Public), what,
			"%u Relays bound, NAT %s, the next mapping predicted at %s while the newest one is on port %u", st.NumBound, PunchPathNatName(st.Nat), addr, (UINT)mapped.Port);
	}

	// The first packet starts the peer session of the pair, through relay-1
	bool echo = PunchPathEcho(ctx, PUNCHPATH_A, PUNCHPATH_B, 39000);
	bool known = PunchPathStatus(ctx, PUNCHPATH_A, PUNCHPATH_B, &ab) && PunchPathStatus(ctx, PUNCHPATH_B, PUNCHPATH_A, &ba);
	Copy(ctx->SessionA, ab.SessionId, PEER_SESSION_ID_SIZE);
	Copy(ctx->SessionB, ba.SessionId, PEER_SESSION_ID_SIZE);
	ctx->HandshakesA = ab.Handshakes;
	ctx->HandshakesB = ba.Handshakes;
	PunchPathPairWords(ctx, PUNCHPATH_A, PUNCHPATH_B, words, sizeof(words));
	PunchPathCheck(ctx, echo && known && ab.Session == PEER_SESSION_UP && ba.Session == PEER_SESSION_UP && Cmp(ab.SessionId, ba.SessionId, PEER_SESSION_ID_SIZE) == 0,
		"A packet of the host of node-a reaches the host of node-b through relay-1 and comes back, in the peer session that it started", "%s", words);

	// The other subscribers of each carrier-grade NAT take their ports while ICE runs: the predictions miss by that many
	UINT take_a = NatSimTake(ctx->Sim, ctx->Nodes[PUNCHPATH_A].Nat, PUNCHPATH_TAKE);
	UINT take_b = NatSimTake(ctx->Sim, ctx->Nodes[PUNCHPATH_B].Nat, PUNCHPATH_TAKE);
	Print("  [INFO] seed %u: the other subscribers of the NAT of node-a take %u ports, of the NAT of node-b %u, while ICE runs\n", ctx->Seed, take_a, take_b);

	return echo;
}

// b. ICE fails: no check passes the two symmetric NATs, so the ICE session of the pair fails at both ends, while the pair
// stays on relay-1 in its peer session
static bool PunchPathIceFails(PUNCHPATH_CTX *ctx)
{
	PEER_STATUS ab, ba;
	char detail[MAX_SIZE * 2];
	bool failed = false;

	Print("[b. ICE fails: no check of ICE passes two symmetric NATs]\n");

	UINT64 t0 = Tick64();
	for (UINT64 end = t0 + PUNCHPATH_ICE_WAIT;Tick64() < end && failed == false;SleepThread(PUNCHPATH_POLL))
	{
		failed = (PunchPathStatus(ctx, PUNCHPATH_A, PUNCHPATH_B, &ab) && PunchPathStatus(ctx, PUNCHPATH_B, PUNCHPATH_A, &ba) && ab.Ice == PEER_ICE_FAILED && ba.Ice == PEER_ICE_FAILED);
	}
	Print("  [INFO] ICE gave the pair up %I64u ms after the bring-up\n", Tick64() - t0);
	PunchPathCheck(ctx, failed && ab.Path == PEER_PATH_RELAY && ba.Path == PEER_PATH_RELAY, "The ICE session of the pair fails at both ends, and the pair stays on relay-1",
		"ICE at node-a %s, at node-b %s; path of node-a %s, of node-b %s", PunchPathIceName(ab.Ice), PunchPathIceName(ba.Ice), PunchPathPathName(ab.Path), PunchPathPathName(ba.Path));

	UINT echoes = PunchPathEchoes(ctx, 40000);
	bool same = PunchPathSameSession(ctx, detail, sizeof(detail));
	PunchPathCheck(ctx, echoes == PUNCHPATH_ECHOES && same, "Packets of the hosts go on through relay-1 in the same peer session", "%u echoes came back; %s", echoes, detail);

	return failed;
}

// The probe of node-b that the tap kept last, into probe: its size, 0 for none
static UINT PunchPathKeptProbe(PUNCHPATH_CTX *ctx, UCHAR *probe)
{
	UINT size = 0;

	AcquireSRWLockShared(&ctx->TapLock);
	if (ctx->ProbeSize != 0)
	{
		Copy(probe, ctx->Probe, ctx->ProbeSize);
		size = ctx->ProbeSize;
	}
	ReleaseSRWLockShared(&ctx->TapLock);

	return size;
}

// Count the datagrams of node-a to the address addr from now on
static void PunchPathWatch(PUNCHPATH_CTX *ctx, const PEER_ADDR *addr)
{
	AcquireSRWLockExclusive(&ctx->TapLock);
	ctx->Watch = *addr;
	ctx->Watched = 0;
	ReleaseSRWLockExclusive(&ctx->TapLock);
}

// The datagrams of node-a to the watched address
static UINT PunchPathWatched(PUNCHPATH_CTX *ctx)
{
	AcquireSRWLockShared(&ctx->TapLock);
	UINT n = ctx->Watched;
	ReleaseSRWLockShared(&ctx->TapLock);

	return n;
}

// The payload of a probe with the sequence seq, as PeerPunchTick seals one: the version, the sequence, the type of a probe
// and two empty nonces
static void PunchPathProbe(UCHAR *payload, UINT64 seq)
{
	Zero(payload, PUNCHPATH_PAYLOAD_SIZE);
	payload[0] = 1;
	for (UINT k = 0;k < 8;k++)
	{
		payload[1 + k] = (UCHAR)(seq >> (56 - 8 * k));
	}
	payload[9] = 1;
}

// A sequence above every one that a Node sent before: the wall clock in 100 ns units, as the peer layer draws one
static UINT64 PunchPathSequence()
{
	FILETIME ft;

	GetSystemTimePreciseAsFileTime(&ft);

	return ((UINT64)ft.dwHighDateTime << 32) | ft.dwLowDateTime;
}

// While node-a has an attempt open: an attacker on the link of node-a sends a captured probe of node-b again from an address
// of its own, then the same probe with one byte of its tag changed, and a node that is no peer sends a probe of its own.
// node-a moves to no direct path at the attacker's address, drops and counts the altered probe as forged, and drops and
// counts the probe of the stranger; it answers neither. Then the attacker sends more captured probes of node-b than an
// attempt keeps room to answer: node-a answers them only within its rate and the budget of its attempt, which step c
// counts with the probes of the attempt.
static void PunchPathAttacker(PUNCHPATH_CTX *ctx)
{
	PEER_STATUS ab;
	PEER_STATS before, after;
	PEER_ADDR attacker, stranger_addr, flooder;
	PEER_KEY stranger;
	UCHAR scalar[PEER_KEY_SIZE];
	UCHAR probe[PEER_MAX_DATAGRAM];
	UCHAR altered[PEER_MAX_DATAGRAM];
	UCHAR env[PEER_MAX_ENVELOPE];
	UCHAR payload[PUNCHPATH_PAYLOAD_SIZE];
	char words[MAX_SIZE * 2];

	// An attempt of node-a is open, and the tap kept a probe of node-b of the attempt
	bool open = false;
	for (UINT64 end = Tick64() + PUNCHPATH_BOUND;Tick64() < end && open == false;SleepThread(PUNCHPATH_POLL))
	{
		open = (PunchPathStatus(ctx, PUNCHPATH_A, PUNCHPATH_B, &ab) && ab.Punch == PEER_PUNCH_PROBING && PunchPathKeptProbe(ctx, probe) != 0);
	}

	UINT size = PunchPathKeptProbe(ctx, probe);
	PeerAddrSetV4(&attacker, 198, 51, 100, 66, 4000);
	PunchPathWatch(ctx, &attacker);
	bool injected = open && NatSimInject(ctx->Nodes[PUNCHPATH_A].Host, &attacker, probe, size);
	NatSimWaitIdle(ctx->Sim, PUNCHPATH_BOUND);
	PunchPathStatus(ctx, PUNCHPATH_A, PUNCHPATH_B, &ab);
	UINT answers = PunchPathWatched(ctx);
	PunchPathPairWords(ctx, PUNCHPATH_A, PUNCHPATH_B, words, sizeof(words));
	Print("  [INFO] the attacker sent a captured probe of node-b to node-a from %s; node-a answered it %u times, sealed to node-b\n", "198.51.100.66:4000", answers);
	PunchPathCheck(ctx, injected && ab.Path == PEER_PATH_RELAY && PeerAddrEqual(&ab.Direct, &attacker) == false && answers <= 1,
		"A punch does not set the direct path of node-b at an address that only a probe names: the captured probe of node-b that an attacker sends from its own address moves node-a to no direct path there, as only node-b can echo the nonce of node-a",
		"open %u, injected %u, %u answers to the attacker; %s", (UINT)open, (UINT)injected, answers, words);

	// The probes are authenticated: the same probe with one byte of its tag changed opens at no Node, so node-a drops it as
	// forged, counts it and answers it nothing
	Copy(altered, probe, size);
	if (size != 0)
	{
		altered[size - 1] ^= 0x80;
	}
	PunchPathWatch(ctx, &attacker);
	PunchPathStats(ctx, PUNCHPATH_A, &before);
	bool forged = open && size != 0 && NatSimInject(ctx->Nodes[PUNCHPATH_A].Host, &attacker, altered, size);
	NatSimWaitIdle(ctx->Sim, PUNCHPATH_BOUND);
	PunchPathStats(ctx, PUNCHPATH_A, &after);
	answers = PunchPathWatched(ctx);
	PunchPathCheck(ctx, forged && after.Drops[PEER_DROP_FORGED] == before.Drops[PEER_DROP_FORGED] + 1 && answers == 0,
		"The probes are authenticated: the captured probe of node-b with one byte of its tag changed is dropped as forged and counted, and node-a answers it nothing",
		"injected %u; drops as forged %I64u before, %I64u after; %u datagrams of node-a to the attacker", (UINT)forged, before.Drops[PEER_DROP_FORGED],
		after.Drops[PEER_DROP_FORGED], answers);

	// A probe of a node that is no peer of node-a
	for (UINT j = 0;j < PEER_KEY_SIZE;j++)
	{
		scalar[j] = (UCHAR)(200 + j);
	}
	bool keyed = PeerKeyFromScalar(&stranger, scalar);
	Zero(scalar, sizeof(scalar));

	PunchPathProbe(payload, PunchPathSequence());
	UINT env_size = (keyed ? PeerEnvelopeSeal(&stranger, ctx->Nodes[PUNCHPATH_A].Key.Public, PEER_MSG_PUNCH, NULL, payload, sizeof(payload), env, sizeof(env)) : 0);
	PeerAddrSetV4(&stranger_addr, 198, 51, 100, 77, 4000);
	PunchPathWatch(ctx, &stranger_addr);
	PunchPathStats(ctx, PUNCHPATH_A, &before);
	bool sent = (env_size != 0 && NatSimInject(ctx->Nodes[PUNCHPATH_A].Host, &stranger_addr, env, env_size));
	NatSimWaitIdle(ctx->Sim, PUNCHPATH_BOUND);
	PunchPathStats(ctx, PUNCHPATH_A, &after);
	answers = PunchPathWatched(ctx);
	PunchPathCheck(ctx, sent && after.Drops[PEER_DROP_POLICY] == before.Drops[PEER_DROP_POLICY] + 1 && answers == 0,
		"A probe of a node that is no peer of node-a is dropped and counted, and node-a answers it nothing",
		"sent %u; drops for the policy %I64u before, %I64u after; %u datagrams of node-a to its address", (UINT)sent, before.Drops[PEER_DROP_POLICY], after.Drops[PEER_DROP_POLICY], answers);

	PeerKeyClose(&stranger);

	// The attacker captured more probes of node-b and sends each of them again once, from an address of its own, in the
	// order that node-b sent them (the test seals them with the key of node-b, as node-b sealed the ones that the attacker
	// captured). Each would draw an answer of node-a to the attacker: node-a answers them only within its rate and the
	// budget of its attempt, and drops and counts the others.
	PeerAddrSetV4(&flooder, 198, 51, 100, 88, 4000);
	PunchPathWatch(ctx, &flooder);
	PunchPathStats(ctx, PUNCHPATH_A, &before);
	UINT64 first = PunchPathSequence();
	UINT flooded = 0;
	for (UINT k = 0;k < PUNCHPATH_FLOOD && open;k++)
	{
		PunchPathProbe(payload, first + k);
		env_size = PeerEnvelopeSeal(&ctx->Nodes[PUNCHPATH_B].Key, ctx->Nodes[PUNCHPATH_A].Key.Public, PEER_MSG_PUNCH, NULL, payload, sizeof(payload), env, sizeof(env));
		if (env_size != 0 && NatSimInject(ctx->Nodes[PUNCHPATH_A].Host, &flooder, env, env_size))
		{
			flooded++;
		}
	}
	NatSimWaitIdle(ctx->Sim, PUNCHPATH_BOUND);
	PunchPathStats(ctx, PUNCHPATH_A, &after);
	answers = PunchPathWatched(ctx);
	UINT64 held = after.Drops[PEER_DROP_RATE] - before.Drops[PEER_DROP_RATE];
	Print("  [INFO] the attacker sent node-a %u more captured probes of node-b from %s; node-a answered %u of them, sealed to node-b, and held back %I64u\n", flooded,
		"198.51.100.88:4000", answers, held);
	PunchPathCheck(ctx, flooded == PUNCHPATH_FLOOD && answers != 0 && answers + held == flooded,
		"Captured probes of node-b that an attacker sends again from its own address draw answers of node-a only within its rate and the budget of its attempt: the others are dropped and counted",
		"%u sent, %u answered, %I64u held back", flooded, answers, held);
}

// c. Limits: the path between the NATs is cut, so the attempts that the punch offers begin fail; each keeps to the budget
// of an attempt and the rate of the node, and after the attempts that met nothing the pair stays on relay-1 until the
// backoff ends
static bool PunchPathLimits(PUNCHPATH_CTX *ctx, UINT64 *third)
{
	PEER_STATS st[PUNCHPATH_NUM_NODES];
	UINT64 probes[PUNCHPATH_NUM_NODES][PUNCHPATH_ATTEMPTS + 2];
	UINT messages[PUNCHPATH_NUM_NODES][PUNCHPATH_ATTEMPTS + 2];
	UINT64 failures_seen[PUNCHPATH_NUM_NODES];
	UINT64 attempts_seen = 0;
	UINT64 starts[PUNCHPATH_ATTEMPTS + 2];
	char detail[MAX_SIZE * 2];
	char what[MAX_SIZE];
	char words[MAX_SIZE * 2];
	bool attacked = false;
	bool failed = false;
	UINT lower = PunchPathLower(ctx);

	Print("[c. limits: the path between the NATs is cut, the attempts fail within the budget and the rate, and the pair waits out the backoff on relay-1]\n");

	Zero(probes, sizeof(probes));
	Zero(messages, sizeof(messages));
	Zero(failures_seen, sizeof(failures_seen));
	Zero(starts, sizeof(starts));

	// The attempts, until both ends counted PUNCHPATH_ATTEMPTS failures: the probes and the punch messages that each end sent
	// in all by the failure of each of its attempts, as the next one begins after it, and the start of each attempt of the
	// Node that offers them
	for (UINT64 end = Tick64() + PUNCHPATH_FAIL_WAIT;Tick64() < end && failed == false;SleepThread(PUNCHPATH_POLL))
	{
		for (UINT i = 0;i < PUNCHPATH_NUM_NODES;i++)
		{
			PunchPathStats(ctx, i, &st[i]);
			while (failures_seen[i] < st[i].PunchFailures && failures_seen[i] < PUNCHPATH_ATTEMPTS + 1)
			{
				probes[i][failures_seen[i]] = st[i].PunchProbes;
				messages[i][failures_seen[i]] = PunchPathMessages(ctx, i);
				failures_seen[i]++;
			}
			while (i == lower && attempts_seen < st[i].PunchAttempts && attempts_seen < PUNCHPATH_ATTEMPTS + 1)
			{
				starts[attempts_seen] = Tick64();
				attempts_seen++;
			}
		}

		if (attacked == false && st[PUNCHPATH_A].PunchAttempts == 1)
		{
			attacked = true;
			PunchPathAttacker(ctx);
		}

		failed = (st[PUNCHPATH_A].PunchFailures >= PUNCHPATH_ATTEMPTS && st[PUNCHPATH_B].PunchFailures >= PUNCHPATH_ATTEMPTS);
	}
	*third = starts[PUNCHPATH_ATTEMPTS - 1];

	for (UINT i = 0;i < PUNCHPATH_NUM_NODES;i++)
	{
		PunchPathStats(ctx, i, &st[i]);
		Print("  [INFO] %s: %I64u attempts, %I64u failed, %I64u probes in all\n", ctx->Nodes[i].Name, st[i].PunchAttempts, st[i].PunchFailures, st[i].PunchProbes);
	}
	PunchPathPairWords(ctx, PUNCHPATH_A, PUNCHPATH_B, words, sizeof(words));
	Format(what, sizeof(what), "Once ICE failed, the Node that offers the pair offers the punch, and both ends make %u attempts, each of which spends its probes and fails while the path between the NATs is cut",
		(UINT)PUNCHPATH_ATTEMPTS);
	PunchPathCheck(ctx, failed && attacked && st[PUNCHPATH_A].PunchAttempts == PUNCHPATH_ATTEMPTS && st[PUNCHPATH_B].PunchAttempts == PUNCHPATH_ATTEMPTS &&
		st[PUNCHPATH_A].PunchSuccesses == 0 && st[PUNCHPATH_B].PunchSuccesses == 0, what, "%s", words);

	// The budget of each attempt: the punch messages that the tap saw leave the Node from the failure of the one before to
	// its own failure, its probes and its answers together, the answers of node-a to the captured probes of the attacker
	// among them
	bool within = true;
	for (UINT i = 0;i < PUNCHPATH_NUM_NODES;i++)
	{
		for (UINT k = 0;k < PUNCHPATH_ATTEMPTS;k++)
		{
			UINT64 sent = probes[i][k] - (k != 0 ? probes[i][k - 1] : 0);
			UINT all = messages[i][k] - (k != 0 ? messages[i][k - 1] : 0);

			Print("  [INFO] %s, attempt %u: %u punch messages, %I64u of them probes\n", ctx->Nodes[i].Name, k + 1, all, sent);
			within = within && sent != 0 && all >= sent && all <= PEER_DEFAULT_PUNCH_BUDGET;
		}
	}
	Format(what, sizeof(what), "Each attempt sends at most its budget of %u punch messages, its probes and its answers together", (UINT)PEER_DEFAULT_PUNCH_BUDGET);
	PunchPathCheck(ctx, within, what, "an attempt sent no probe, or more punch messages than its budget");

	UINT peak_a = PunchPathPeak(ctx, PUNCHPATH_A);
	UINT peak_b = PunchPathPeak(ctx, PUNCHPATH_B);
	Print("  [INFO] the tap saw at most %u punch messages of node-a and %u of node-b within one second\n", peak_a, peak_b);
	Format(what, sizeof(what), "No Node sends more than its rate of %u punch messages within any second", (UINT)PEER_DEFAULT_PUNCH_RATE);
	PunchPathCheck(ctx, peak_a != 0 && peak_b != 0 && peak_a <= PEER_DEFAULT_PUNCH_RATE && peak_b <= PEER_DEFAULT_PUNCH_RATE, what, "node-a %u, node-b %u", peak_a, peak_b);

	// The pair goes on through relay-1 in its peer session while the attempts fail
	UINT echoes = PunchPathEchoes(ctx, 41000);
	bool same = PunchPathSameSession(ctx, detail, sizeof(detail));
	PunchPathCheck(ctx, echoes == PUNCHPATH_ECHOES && same, "When the punch fails, the pair stays on relay-1 with no loss of its session: packets of the hosts go on through relay-1 in the same peer session",
		"%u echoes came back; %s", echoes, detail);

	// The backoff: no attempt begins until it ends, PUNCHPATH_BACKOFF ms after the end of the third attempt, which began at
	// *third
	UINT64 quiet_until = *third + PUNCHPATH_BACKOFF - 2 * PUNCHPATH_RETRY;
	UINT64 attempts_a = st[PUNCHPATH_A].PunchAttempts, attempts_b = st[PUNCHPATH_B].PunchAttempts;
	bool quiet = true;
	while (Tick64() < quiet_until)
	{
		PunchPathStats(ctx, PUNCHPATH_A, &st[PUNCHPATH_A]);
		PunchPathStats(ctx, PUNCHPATH_B, &st[PUNCHPATH_B]);
		quiet = quiet && st[PUNCHPATH_A].PunchAttempts == attempts_a && st[PUNCHPATH_B].PunchAttempts == attempts_b;
		SleepThread(PUNCHPATH_POLL * 10);
	}
	Format(what, sizeof(what), "After %u attempts that met nothing the pair stays on relay-1, and no attempt begins in the backoff of %u ms", (UINT)PUNCHPATH_ATTEMPTS, (UINT)PUNCHPATH_BACKOFF);
	PunchPathCheck(ctx, quiet, what, "attempts of node-a %I64u, of node-b %I64u, against %I64u and %I64u", st[PUNCHPATH_A].PunchAttempts, st[PUNCHPATH_B].PunchAttempts, attempts_a, attempts_b);

	return failed;
}

// d. The punch: the cut is lifted before the backoff ends, and the attempt after it meets; both ends move to the direct path
// in the same peer session, at the mapping of the peer that proved itself, and relay-1 carries no data of the pair after
// the move
static bool PunchPathMeet(PUNCHPATH_CTX *ctx, UINT64 third)
{
	PEER_STATUS ab, ba;
	PEER_STATS st_a, st_b, before, after;
	char detail[MAX_SIZE * 2];
	char what[MAX_SIZE];
	char words[MAX_SIZE * 2];
	char addr_a[64], addr_b[64];

	Print("[d. the punch: the cut is lifted, and the attempt after the backoff meets]\n");

	NatSimCut(ctx->Sim, ctx->Nodes[PUNCHPATH_A].Nat, false);

	UINT64 began = 0;
	bool met = false;
	for (UINT64 end = Tick64() + PUNCHPATH_MEET_WAIT;Tick64() < end && met == false;SleepThread(PUNCHPATH_POLL))
	{
		PunchPathStats(ctx, PunchPathLower(ctx), &st_a);
		if (began == 0 && st_a.PunchAttempts > PUNCHPATH_ATTEMPTS)
		{
			began = Tick64();
		}
		met = (PunchPathStatus(ctx, PUNCHPATH_A, PUNCHPATH_B, &ab) && PunchPathStatus(ctx, PUNCHPATH_B, PUNCHPATH_A, &ba) && ab.Path == PEER_PATH_DIRECT && ba.Path == PEER_PATH_DIRECT);
	}
	UINT64 at = Tick64();
	Print("  [INFO] the attempt after the backoff began %I64u ms after the third one, and both ends were on the direct path %I64u ms after it began\n", began - third, began != 0 ? at - began : 0);

	PunchPathStats(ctx, PUNCHPATH_A, &st_a);
	PunchPathStats(ctx, PUNCHPATH_B, &st_b);
	PunchPathPairWords(ctx, PUNCHPATH_A, PUNCHPATH_B, words, sizeof(words));
	Format(what, sizeof(what), "The next attempt waits for the end of the backoff, %u ms after the third", (UINT)PUNCHPATH_BACKOFF);
	PunchPathCheck(ctx, began != 0 && began - third + 1000 >= PUNCHPATH_BACKOFF, what, "it began %I64u ms after the third", began - third);

	PunchPathCheck(ctx, met && ab.Punch == PEER_PUNCH_CONNECTED && ba.Punch == PEER_PUNCH_CONNECTED && st_a.PunchSuccesses == 1 && st_b.PunchSuccesses == 1,
		"In the world with two symmetric NATs the pair gets a direct path by punching: the probes of the two ends meet and both move off relay-1", "%s", words);

	// The direct path is at the mapping of the peer on its NAT, which echoed the nonce, and not the attacker's
	PeerAddrToStr(addr_a, sizeof(addr_a), &ba.Direct);
	PeerAddrToStr(addr_b, sizeof(addr_b), &ab.Direct);
	Print("  [INFO] node-a reaches node-b at %s, and node-b reaches node-a at %s\n", addr_b, addr_a);
	PunchPathCheck(ctx, PunchPathSameIp(&ab.Direct, &ctx->Nodes[PUNCHPATH_B].Public) && PunchPathSameIp(&ba.Direct, &ctx->Nodes[PUNCHPATH_A].Public),
		"Each end reaches the other at a mapping of the NAT of the other, which proved itself by the echo of a nonce", "node-a reaches node-b at %s, node-b reaches node-a at %s", addr_b, addr_a);

	PunchPathCheck(ctx, st_a.Upgrades == 1 && st_b.Upgrades == 1 && st_a.PunchFailures == PUNCHPATH_ATTEMPTS && st_b.PunchFailures == PUNCHPATH_ATTEMPTS,
		"Each end counts the move as an Upgrade, next to the failures of the attempts before", "Upgrades %I64u and %I64u, failures %I64u and %I64u", st_a.Upgrades, st_b.Upgrades,
		st_a.PunchFailures, st_b.PunchFailures);

	bool same = PunchPathSameSession(ctx, detail, sizeof(detail));
	PunchPathCheck(ctx, same, "The peer session survived the move: the same keys at both ends, and no new handshake", "%s", detail);

	// relay-1 carries no data of the pair after the move
	NatSimWaitIdle(ctx->Sim, PUNCHPATH_BOUND);
	PunchPathRelayStats(ctx, 0, &before);
	LONG64 records = InterlockedCompareExchange64(&ctx->RelayRecords, 0, 0);
	UINT echoes = PunchPathEchoes(ctx, 42000);
	NatSimWaitIdle(ctx->Sim, PUNCHPATH_BOUND);
	PunchPathRelayStats(ctx, 0, &after);
	LONG64 records_after = InterlockedCompareExchange64(&ctx->RelayRecords, 0, 0);
	Format(what, sizeof(what), "After the move %u packets of the host of node-a reach the host of node-b and come back on the direct path, and relay-1 carries no data of the pair",
		(UINT)PUNCHPATH_ECHOES);
	PunchPathCheck(ctx, echoes == PUNCHPATH_ECHOES && after.Forwarded == before.Forwarded && records_after == records, what,
		"%u echoes came back; relay-1 forwarded %I64u records, and %I64d crossed the links with it", echoes, after.Forwarded - before.Forwarded, records_after - records);

	return met;
}

// e. Fallback: the path between the NATs is cut again; the keepalives of the punched path go unanswered, and both ends fall
// back to relay-1 with their peer session. Meanwhile an attacker that sends from the address of node-b on the punched path
// sends node-a records that name node-b as their source and open in no session: anyone can send such a datagram, so it is
// no word of node-b there, and node-a falls back as it would without them.
static void PunchPathFallback(PUNCHPATH_CTX *ctx)
{
	PEER_STATUS ab, ba;
	PEER_STATS st_a, st_b, before, after;
	PEER_ADDR at_b;
	UCHAR forged[PEER_RECORD_HEADER + PEER_RECORD_TAG];
	char detail[MAX_SIZE * 2];
	char what[MAX_SIZE];
	char addr[64];
	UINT forgeries = 0;

	Print("[e. fallback: the path between the NATs is cut again, and the punched path falls back to relay-1]\n");

	// The address of node-b on the punched path, as node-a has it, and a record from node-b to node-a, as its clear header
	// names them, under the session index 0, which no keys of node-a have: it opens in no session
	Zero(&at_b, sizeof(at_b));
	if (PunchPathStatus(ctx, PUNCHPATH_A, PUNCHPATH_B, &ab))
	{
		at_b = ab.Direct;
	}
	Zero(forged, sizeof(forged));
	forged[0] = PEER_MSG_RECORD;
	Copy(forged + 1, ctx->Nodes[PUNCHPATH_B].Key.Public, PEER_KEY_SIZE);
	Copy(forged + 1 + PEER_KEY_SIZE, ctx->Nodes[PUNCHPATH_A].Key.Public, PEER_KEY_SIZE);
	PunchPathStats(ctx, PUNCHPATH_A, &before);

	NatSimCut(ctx->Sim, ctx->Nodes[PUNCHPATH_A].Nat, true);

	// Until both ends are back on relay-1, while the forged records of the attacker go to node-a as long as it is on the
	// punched path
	UINT64 t0 = Tick64();
	UINT64 fell_a = 0;
	UINT64 next = t0;
	bool fell = false;
	for (UINT64 end = t0 + PUNCHPATH_FALL_WAIT;Tick64() < end && fell == false;SleepThread(PUNCHPATH_POLL))
	{
		bool known = PunchPathStatus(ctx, PUNCHPATH_A, PUNCHPATH_B, &ab) && PunchPathStatus(ctx, PUNCHPATH_B, PUNCHPATH_A, &ba);

		if (known && ab.Path == PEER_PATH_RELAY && fell_a == 0)
		{
			fell_a = Tick64();
		}
		if (fell_a == 0 && Tick64() >= next)
		{
			if (NatSimInject(ctx->Nodes[PUNCHPATH_A].Host, &at_b, forged, sizeof(forged)))
			{
				forgeries++;
			}
			next = Tick64() + PUNCHPATH_FORGE_EVERY;
		}
		fell = (known && ab.Path == PEER_PATH_RELAY && ba.Path == PEER_PATH_RELAY);
	}
	Print("  [INFO] node-a was back on relay-1 %I64u ms after the cut, and both ends %I64u ms after it\n", fell_a != 0 ? fell_a - t0 : 0, Tick64() - t0);

	// A forged record reaches node-a on the punched path and finds no keys there, or once node-a fell back finds no path of
	// node-b at that address: either way node-a drops and counts it
	NatSimWaitIdle(ctx->Sim, PUNCHPATH_BOUND);
	PunchPathStats(ctx, PUNCHPATH_A, &after);
	UINT64 dropped = (after.Drops[PEER_DROP_SESSION] - before.Drops[PEER_DROP_SESSION]) + (after.Drops[PEER_DROP_SOURCE] - before.Drops[PEER_DROP_SOURCE]);
	PeerAddrToStr(addr, sizeof(addr), &at_b);
	Print("  [INFO] the attacker sent node-a %u records of node-b from %s, one every %u ms, and node-a dropped %I64u datagrams of no session or no path\n", forgeries, addr,
		(UINT)PUNCHPATH_FORGE_EVERY, dropped);
	Format(what, sizeof(what), "A datagram that names node-b as its source, from its address on the punched path, is no word of node-b there unless it opens: node-a drops the forged records and falls back within %u ms of the cut all the same",
		(UINT)(PUNCHPATH_CONSENT + PUNCHPATH_FALL_SLACK));
	PunchPathCheck(ctx, forgeries != 0 && dropped >= forgeries && fell_a != 0 && fell_a - t0 <= PUNCHPATH_CONSENT + PUNCHPATH_FALL_SLACK, what,
		"%u forged records, %I64u dropped; node-a back on relay-1: %s, after %I64u ms", forgeries, dropped, fell_a != 0 ? "yes" : "no", fell_a != 0 ? fell_a - t0 : Tick64() - t0);

	PunchPathStats(ctx, PUNCHPATH_A, &st_a);
	PunchPathStats(ctx, PUNCHPATH_B, &st_b);
	Format(what, sizeof(what), "The peer goes silent on the punched path, and after %u ms both ends fall back to relay-1, a Fallback each", (UINT)PUNCHPATH_CONSENT);
	PunchPathCheck(ctx, fell && st_a.Fallbacks == 1 && st_b.Fallbacks == 1, what, "path of node-a %s, of node-b %s; Fallbacks %I64u and %I64u", PunchPathPathName(ab.Path),
		PunchPathPathName(ba.Path), st_a.Fallbacks, st_b.Fallbacks);

	UINT echoes = PunchPathEchoes(ctx, 43000);
	bool same = PunchPathSameSession(ctx, detail, sizeof(detail));
	PunchPathCheck(ctx, echoes == PUNCHPATH_ECHOES && same, "Packets of the hosts go on through relay-1 in the same peer session, which the Fallback kept", "%u echoes came back; %s",
		echoes, detail);
}

// f. Export: the NAT and the punches of each Node in its state, as ranz node state prints it, and in the Telemetry that it
// reported to the stand-in of the Controller
static void PunchPathExport(PUNCHPATH_CTX *ctx)
{
	char *reply = ZeroMalloc(NODE_ADMIN_REPLY);

	Print("[f. export: the punches of each Node in its state and in its Telemetry]\n");

	for (UINT i = 0;i < PUNCHPATH_NUM_NODES;i++)
	{
		PUNCHPATH_NODE *t = &ctx->Nodes[i];
		PUNCHPATH_LINK *l = &ctx->Links[i];
		PEER_STATS st;
		char counts[MAX_SIZE];
		char what[MAX_SIZE];
		bool state = false, reported = false;

		Zero(&st, sizeof(st));
		counts[0] = 0;

		// The counts can change while they are read, as an attempt may still begin: the three must agree once
		for (UINT64 end = Tick64() + PUNCHPATH_BOUND;Tick64() < end && (state == false || reported == false);SleepThread(PUNCHPATH_POLL))
		{
			PunchPathStats(ctx, i, &st);
			Format(counts, sizeof(counts), "\"nat\":\"sequential\",\"punchAttempts\":%I64u,\"punchSuccesses\":%I64u,\"punchFailures\":%I64u", st.PunchAttempts, st.PunchSuccesses,
				st.PunchFailures);
			Zero(reply, NODE_ADMIN_REPLY);
			NodeAdminCommand(t->Node, "state", reply, NODE_ADMIN_REPLY);
			state = InStr(reply, counts);
			reported = (InterlockedCompareExchange(&l->Reports, 0, 0) != 0 && (UINT64)InterlockedCompareExchange64(&l->PunchAttempts, 0, 0) == st.PunchAttempts &&
				(UINT64)InterlockedCompareExchange64(&l->PunchSuccesses, 0, 0) == st.PunchSuccesses &&
				(UINT64)InterlockedCompareExchange64(&l->PunchFailures, 0, 0) == st.PunchFailures &&
				(UINT64)InterlockedCompareExchange64(&l->Upgrades, 0, 0) == st.Upgrades && (UINT64)InterlockedCompareExchange64(&l->Fallbacks, 0, 0) == st.Fallbacks);
		}

		UINT at = SearchStr(reply, "\"datagramPath\":", 0);
		Print("  [INFO] %s: %I64u attempts, %I64u met, %I64u failed; its state from its datagram path on: %.300s\n", t->Name, st.PunchAttempts, st.PunchSuccesses, st.PunchFailures,
			at != INFINITE ? reply + at : reply);

		Format(what, sizeof(what), "The state of %s, as its admin pipe answers it and ranz node state prints it, holds its NAT, its attempts, its successes and the failures of its prediction",
			t->Name);
		PunchPathCheck(ctx, state && st.PunchAttempts >= PUNCHPATH_ATTEMPTS + 1 && st.PunchSuccesses == 1, what, "it lacks %s", counts);

		Format(what, sizeof(what), "%s reported its punches with its Paths in its Telemetry to the stand-in of the Controller, which exports them", t->Name);
		PunchPathCheck(ctx, reported, what, "%ld reports, the last with %I64d attempts, %I64d met and %I64d failed, against %I64u, %I64u and %I64u",
			InterlockedCompareExchange(&l->Reports, 0, 0), InterlockedCompareExchange64(&l->PunchAttempts, 0, 0), InterlockedCompareExchange64(&l->PunchSuccesses, 0, 0),
			InterlockedCompareExchange64(&l->PunchFailures, 0, 0), st.PunchAttempts, st.PunchSuccesses, st.PunchFailures);
	}

	Free(reply);
}

//
// g. The seeds
//

// One node of a world of step g: its host and its peer layer
typedef struct PUNCHPATH_SWEEP_NODE
{
	NATSIM_HOST *Host;
	PEER_AGENT *Agent;
	PEER_ADDR Addr;
	PEER_KEY *Key;
	volatile LONG Received;
} PUNCHPATH_SWEEP_NODE;

// The receive procedure of a node of step g: it counts the datagrams of the peer
static void PunchPathSweepRecv(PEER_AGENT *a, void *param, const UCHAR *src, UINT path, const void *data, UINT size)
{
	PUNCHPATH_SWEEP_NODE *n = (PUNCHPATH_SWEEP_NODE *)param;

	InterlockedIncrement(&n->Received);
}

// One seed of step g: node-a and node-b on their peer layers, behind the two symmetric NATs of the world with the generators of
// seed, relay-1 and relay-2 on the public side, and the Signals that the test carries as the stand-in of the Controller.
// The pair comes up through relay-1, the other subscribers of each NAT take up to max ports, and the node of the lower
// key offers the punch. Whether the pair met within PUNCHPATH_SWEEP_TICKS ticks, and if so in how many ms into ms and the
// address at which the node of the lower key reaches the other and the one at which the other reaches it into direct[0]
// and direct[1]; when it did not, whether the pair stays on relay-1 with its datagrams going on there into relayed.
static bool PunchPathSweepOne(PUNCHPATH_CTX *ctx, UINT seed, UINT max, UINT64 *ms, bool *relayed, PEER_ADDR *direct)
{
	PUNCHPATH_SWEEP_NODE nodes[PUNCHPATH_NUM_NODES];
	PEER_AGENT *relays[PUNCHPATH_NUM_RELAYS];
	NATSIM_NAT *nats[PUNCHPATH_NUM_NODES];
	PEER_INFO peers[PUNCHPATH_NUM_NODES];
	PEER_RELAY_INFO ri[PUNCHPATH_NUM_RELAYS];
	PEER_CONFIG rc, pc;
	PEER_STATUS sa, sb;
	UCHAR env[PEER_MAX_ENVELOPE];
	bool met = false;
	bool ok = true;

	Zero(nodes, sizeof(nodes));
	Zero(relays, sizeof(relays));
	Zero(&sa, sizeof(sa));
	Zero(&sb, sizeof(sb));
	Zero(direct, sizeof(PEER_ADDR) * 2);
	*ms = 0;
	*relayed = false;

	NATSIM *sim = NatSimNew();
	if (sim == NULL)
	{
		return false;
	}

	PeerDefaultConfig(&rc);
	rc.Relay = true;
	PeerDefaultConfig(&pc);
	pc.Punch = true;

	PunchPathPeerInfos(ctx, peers);
	for (UINT r = 0;r < PUNCHPATH_NUM_RELAYS;r++)
	{
		NATSIM_HOST *h = NatSimAddHost(sim, NULL, &ctx->RelayAddrs[r]);

		relays[r] = (h != NULL ? PeerNew(&ctx->RelayKeys[r], &rc, NatSimSend, h, NULL, NULL) : NULL);
		ok = ok && relays[r] != NULL;
		if (relays[r] != NULL)
		{
			PeerSetPeers(relays[r], peers, PUNCHPATH_NUM_NODES);
			NatSimAttach(h, relays[r]);
		}

		Zero(&ri[r], sizeof(PEER_RELAY_INFO));
		StrCpy(ri[r].Name, sizeof(ri[r].Name), punchpath_relays[r]);
		Copy(ri[r].Key, ctx->RelayKeys[r].Public, PEER_KEY_SIZE);
		ri[r].Addr = ctx->RelayAddrs[r];
	}

	for (UINT i = 0;i < PUNCHPATH_NUM_NODES;i++)
	{
		PUNCHPATH_SWEEP_NODE *n = &nodes[i];
		UINT other = (i == PUNCHPATH_A ? PUNCHPATH_B : PUNCHPATH_A);

		nats[i] = NatSimAddNat(sim, 203, 0, 113, (UCHAR)(10 * (i + 1)), NATSIM_MAP_ADDRESS_PORT_DEPENDENT, NATSIM_FILTER_ADDRESS_PORT_DEPENDENT);
		ok = ok && nats[i] != NULL;
		if (nats[i] == NULL)
		{
			continue;
		}
		NatSimSetAllocation(nats[i], NATSIM_ALLOC_SEQUENTIAL, seed * 2 + i + 1);

		n->Addr = ctx->Nodes[i].Addr;
		n->Key = &ctx->Nodes[i].Key;
		n->Host = NatSimAddHost(sim, nats[i], &n->Addr);
		n->Agent = (n->Host != NULL ? PeerNew(n->Key, &pc, NatSimSend, n->Host, PunchPathSweepRecv, n) : NULL);
		ok = ok && n->Agent != NULL;
		if (n->Agent != NULL)
		{
			NatSimAttach(n->Host, n->Agent);
			PeerSetPeers(n->Agent, &peers[other], 1);
			PeerSetHostCandidates(n->Agent, &n->Addr, 1);
			PeerSetRelays(n->Agent, ri, PUNCHPATH_NUM_RELAYS);
		}
	}
	ok = ok && NatSimWaitIdle(sim, PUNCHPATH_BOUND);

	// The pair comes up through relay-1: an offer and an answer, which the test carries
	UINT x = PunchPathLower(ctx);
	UINT y = (x == PUNCHPATH_A ? PUNCHPATH_B : PUNCHPATH_A);
	if (ok)
	{
		UINT size = PeerSealSignal(nodes[x].Agent, nodes[y].Key->Public, PEER_SIGNAL_OFFER, env, sizeof(env));
		ok = PeerOpenSignal(nodes[y].Agent, env, size, NULL) == PEER_OK;
		size = PeerSealSignal(nodes[y].Agent, nodes[x].Key->Public, PEER_SIGNAL_ANSWER, env, sizeof(env));
		ok = ok && PeerOpenSignal(nodes[x].Agent, env, size, NULL) == PEER_OK;
		ok = ok && PeerSend(nodes[x].Agent, nodes[y].Key->Public, "first", 5) && NatSimWaitIdle(sim, PUNCHPATH_BOUND);
	}

	// The other subscribers take their ports while ICE runs, which the punch of the node of the lower key follows
	for (UINT i = 0;i < PUNCHPATH_NUM_NODES && ok;i++)
	{
		NatSimTake(sim, nats[i], max);
	}

	UINT64 t0 = Tick64();
	if (ok)
	{
		UINT size = PeerSealSignal(nodes[x].Agent, nodes[y].Key->Public, PEER_SIGNAL_PUNCH_OFFER, env, sizeof(env));
		ok = PeerOpenSignal(nodes[y].Agent, env, size, NULL) == PEER_OK;
		size = PeerSealSignal(nodes[y].Agent, nodes[x].Key->Public, PEER_SIGNAL_PUNCH_ANSWER, env, sizeof(env));
		ok = ok && PeerOpenSignal(nodes[x].Agent, env, size, NULL) == PEER_OK;
	}

	for (UINT k = 0;k < PUNCHPATH_SWEEP_TICKS && ok && met == false;k++)
	{
		PeerTick(nodes[x].Agent);
		PeerTick(nodes[y].Agent);
		NatSimWaitIdle(sim, PUNCHPATH_BOUND);

		met = (PeerGetStatus(nodes[x].Agent, nodes[y].Key->Public, &sa) && PeerGetStatus(nodes[y].Agent, nodes[x].Key->Public, &sb) && sa.Path == PEER_PATH_DIRECT &&
			sb.Path == PEER_PATH_DIRECT);
		if (met == false)
		{
			SleepThread(PUNCHPATH_SWEEP_TICK);
		}
	}
	*ms = Tick64() - t0;

	if (met)
	{
		direct[0] = sa.Direct;
		direct[1] = sb.Direct;
	}

	// A pair that did not meet goes on through relay-1
	if (ok && met == false)
	{
		LONG received = InterlockedCompareExchange(&nodes[y].Received, 0, 0);

		*relayed = (PeerGetStatus(nodes[x].Agent, nodes[y].Key->Public, &sa) && sa.Path == PEER_PATH_RELAY && PeerSend(nodes[x].Agent, nodes[y].Key->Public, "relayed", 7) &&
			NatSimWaitIdle(sim, PUNCHPATH_BOUND) && InterlockedCompareExchange(&nodes[y].Received, 0, 0) == received + 1);
	}

	NatSimFree(sim);
	for (UINT i = 0;i < PUNCHPATH_NUM_NODES;i++)
	{
		PeerFree(nodes[i].Agent);
	}
	for (UINT r = 0;r < PUNCHPATH_NUM_RELAYS;r++)
	{
		PeerFree(relays[r]);
	}

	return ok && met;
}

// The simulator is deterministic for a seed: with the heavier load of step g, the seed met, at which the two ends reached
// each other at the addresses direct, meets again at the same two mappings, and the seed stayed, which stayed on relay-1,
// stays there again; 0 for no such seed
static void PunchPathAgain(PUNCHPATH_CTX *ctx, UINT met, const PEER_ADDR *direct, UINT stayed)
{
	PEER_ADDR again[2];
	UINT64 ms = 0;
	bool relayed = false;
	bool same_met = true;
	bool same_stayed = true;
	char first_a[64], first_b[64], addr_a[64], addr_b[64];
	char what[MAX_SIZE];

	if (met != 0)
	{
		bool ok = PunchPathSweepOne(ctx, met, PUNCHPATH_HEAVY_TAKE, &ms, &relayed, again);

		PeerAddrToStr(first_a, sizeof(first_a), &direct[0]);
		PeerAddrToStr(first_b, sizeof(first_b), &direct[1]);
		PeerAddrToStr(addr_a, sizeof(addr_a), &again[0]);
		PeerAddrToStr(addr_b, sizeof(addr_b), &again[1]);
		Print("  [INFO] load of up to %u ports, seed %u again: %s in %I64u ms, the two ends at %s and %s; the first time at %s and %s\n", (UINT)PUNCHPATH_HEAVY_TAKE, met,
			ok ? "met" : "did not meet", ms, addr_a, addr_b, first_a, first_b);
		same_met = (ok && PeerAddrEqual(&again[0], &direct[0]) && PeerAddrEqual(&again[1], &direct[1]));
	}

	if (stayed != 0)
	{
		bool ok = PunchPathSweepOne(ctx, stayed, PUNCHPATH_HEAVY_TAKE, &ms, &relayed, again);

		Print("  [INFO] load of up to %u ports, seed %u again: %s in %I64u ms\n", (UINT)PUNCHPATH_HEAVY_TAKE, stayed, ok ? "met" : (relayed ? "stayed on relay-1" : "did not run"), ms);
		same_stayed = (ok == false && relayed);
	}

	Format(what, sizeof(what), "The simulator is deterministic for a seed: with up to %u ports taken, a seed that met meets again at the same two mappings, and a seed that stayed on relay-1 stays there again",
		(UINT)PUNCHPATH_HEAVY_TAKE);
	PunchPathCheck(ctx, (met != 0 || stayed != 0) && same_met && same_stayed, what, "seed %u met again at the same mappings: %s; seed %u stayed again: %s", met, same_met ? "yes" : "no", stayed,
		same_stayed ? "yes" : "no");
}

// g. The seeds: the punch over PUNCHPATH_SEEDS seeds of the other subscribers, with a load that the range of the punch covers
// and with a heavier one: the success rate of each and the time to the direct path, for the job log; with the first load,
// every seed meets, and a seed that does not meet stays on relay-1 with its datagrams going on. The first seed of the
// heavier load that met and the first one that stayed run again, and end as before (PunchPathAgain).
static void PunchPathSeeds(PUNCHPATH_CTX *ctx)
{
	UINT loads[] = {PUNCHPATH_TAKE, PUNCHPATH_HEAVY_TAKE};
	UINT met_seed = 0;
	UINT stayed_seed = 0;
	PEER_ADDR met_direct[2];
	char what[MAX_SIZE];

	Zero(met_direct, sizeof(met_direct));

	Print("[g. seeds: the punch of the two symmetric NATs over %u seeds of the other subscribers of each NAT, with two loads]\n", (UINT)PUNCHPATH_SEEDS);

	for (UINT l = 0;l < sizeof(loads) / sizeof(loads[0]);l++)
	{
		UINT met = 0;
		UINT stayed = 0;
		UINT64 total = 0, longest = 0;

		for (UINT s = 1;s <= PUNCHPATH_SEEDS;s++)
		{
			UINT64 ms = 0;
			bool relayed = false;
			PEER_ADDR direct[2];
			bool ok = PunchPathSweepOne(ctx, s, loads[l], &ms, &relayed, direct);

			Print("  [INFO] load of up to %u ports, seed %u: %s in %I64u ms\n", loads[l], s, ok ? "met" : (relayed ? "stayed on relay-1" : "did not run"), ms);
			if (ok)
			{
				met++;
				total += ms;
				longest = MAX(longest, ms);
				if (loads[l] == PUNCHPATH_HEAVY_TAKE && met_seed == 0)
				{
					met_seed = s;
					Copy(met_direct, direct, sizeof(met_direct));
				}
			}
			else if (relayed)
			{
				stayed++;
				if (loads[l] == PUNCHPATH_HEAVY_TAKE && stayed_seed == 0)
				{
					stayed_seed = s;
				}
			}
		}

		Print("  [INFO] load of up to %u ports: %u of %u seeds met, in %I64u ms on average and %I64u ms at most; %u stayed on relay-1\n", loads[l], met, (UINT)PUNCHPATH_SEEDS,
			met != 0 ? total / met : 0, longest, stayed);
		Print("PUNCHPATH SEEDS load=%u met=%u of=%u average_ms=%I64u longest_ms=%I64u\n", loads[l], met, (UINT)PUNCHPATH_SEEDS, met != 0 ? total / met : 0, longest);

		if (loads[l] == PUNCHPATH_TAKE)
		{
			Format(what, sizeof(what), "With up to %u ports taken by the other subscribers of each NAT, within the range of the punch, the pair meets for every one of %u seeds",
				(UINT)PUNCHPATH_TAKE, (UINT)PUNCHPATH_SEEDS);
			PunchPathCheck(ctx, met == PUNCHPATH_SEEDS, what, "%u of %u met", met, (UINT)PUNCHPATH_SEEDS);
		}
		else
		{
			Format(what, sizeof(what), "With up to %u ports taken, beyond the range of the punch for some seeds, every seed either meets or stays on relay-1 with its datagrams going on",
				(UINT)PUNCHPATH_HEAVY_TAKE);
			PunchPathCheck(ctx, met + stayed == PUNCHPATH_SEEDS, what, "%u met and %u stayed of %u", met, stayed, (UINT)PUNCHPATH_SEEDS);
		}
	}

	PunchPathAgain(ctx, met_seed, met_direct, stayed_seed);
}

//
// The world
//

// Build the world: the keys, the network of the simulator with the two symmetric NATs of the seed, its tap and its cut,
// relay-1 and relay-2, the transports, the stand-in of the Controller, and node-a and node-b
static bool PunchPathStart(PUNCHPATH_CTX *ctx)
{
	UCHAR scalar[PEER_KEY_SIZE];
	bool ok = true;

	// The static keys: the scalars 1, 2, ... of the conformance tests for the Nodes, others for the relays and the Controller
	for (UINT i = 0;i < PUNCHPATH_NUM_NODES + PUNCHPATH_NUM_RELAYS + 1;i++)
	{
		PEER_KEY *k = (i < PUNCHPATH_NUM_NODES ? &ctx->Nodes[i].Key : (i < PUNCHPATH_NUM_NODES + PUNCHPATH_NUM_RELAYS ? &ctx->RelayKeys[i - PUNCHPATH_NUM_NODES] : &ctx->ControllerKey));

		for (UINT j = 0;j < PEER_KEY_SIZE;j++)
		{
			scalar[j] = (UCHAR)(1 + PEER_KEY_SIZE * (i < PUNCHPATH_NUM_NODES ? i : i + 1) + j);
		}
		ok = PeerKeyFromScalar(k, scalar) && ok;
	}
	Zero(scalar, sizeof(scalar));
	if (PunchPathCheck(ctx, ok, "The static keys of the Nodes, the relays and the Controller", "PeerKeyFromScalar failed") == false)
	{
		return false;
	}

	ctx->Sim = NatSimNew();
	if (PunchPathCheck(ctx, ctx->Sim != NULL, "The network of the NAT simulator", "NatSimNew failed") == false)
	{
		return false;
	}
	InitializeSRWLock(&ctx->TapLock);
	NatSimSetTap(ctx->Sim, PunchPathTap, ctx);

	// node-a and node-b behind symmetric NATs that allocate in order, whose other subscribers draw from the seed
	for (UINT i = 0;i < PUNCHPATH_NUM_NODES;i++)
	{
		PUNCHPATH_NODE *t = &ctx->Nodes[i];

		t->Name = punchpath_names[i];
		InitializeSRWLock(&t->Lock);
		t->Nat = NatSimAddNat(ctx->Sim, 203, 0, 113, (UCHAR)(10 * (i + 1)), NATSIM_MAP_ADDRESS_PORT_DEPENDENT, NATSIM_FILTER_ADDRESS_PORT_DEPENDENT);
		PeerAddrSetV4(&t->Public, 203, 0, 113, (UCHAR)(10 * (i + 1)), 0);
		if (i == PUNCHPATH_A)
		{
			PeerAddrSetV4(&t->Addr, 192, 168, 1, 2, PUNCHPATH_HOST_PORT);
		}
		else
		{
			PeerAddrSetV4(&t->Addr, 10, 0, 0, 2, PUNCHPATH_HOST_PORT);
		}
		if (t->Nat != NULL)
		{
			NatSimSetAllocation(t->Nat, NATSIM_ALLOC_SEQUENTIAL, ctx->Seed * 2 + i + 1);
		}
		t->Host = (t->Nat != NULL ? NatSimAddHost(ctx->Sim, t->Nat, &t->Addr) : NULL);
		ok = (t->Host != NULL) && ok;
	}

	// The path between the NATs is cut from the start, until the attempts before the backoff failed (step d)
	if (ok)
	{
		NatSimCut(ctx->Sim, ctx->Nodes[PUNCHPATH_A].Nat, true);
	}

	InitializeSRWLock(&ctx->RelayLock);
	PeerDefaultConfig(&ctx->RelayConfig);
	ctx->RelayConfig.Relay = true;
	for (UINT r = 0;r < PUNCHPATH_NUM_RELAYS;r++)
	{
		PeerAddrSetV4(&ctx->RelayAddrs[r], 198, 51, 100, (UCHAR)(1 + r), PUNCHPATH_RELAY_PORT);
		ctx->RelayHosts[r] = NatSimAddHost(ctx->Sim, NULL, &ctx->RelayAddrs[r]);
		ok = ok && ctx->RelayHosts[r] != NULL;
	}
	ctx->Started = true;
	ok = ok && PunchPathRelayStart(ctx);
	ctx->Ticker = (ok ? CreateThread(NULL, 0, PunchPathTicker, ctx, 0, NULL) : NULL);
	if (PunchPathCheck(ctx, ok && ctx->Ticker != NULL, "The hosts of the network behind two symmetric NATs, and relay-1 and relay-2, the peer layers of two relay roles on the public side",
		"a host or a relay could not start") == false)
	{
		return false;
	}

	// The peer layer of the agents: ICE and the punch on, with the limits of the punch of a Node, and the timers of a test
	PeerDefaultConfig(&ctx->PathConfig);
	ctx->PathConfig.Ice = true;
	ctx->PathConfig.Punch = true;
	ctx->PathConfig.BindInterval = PUNCHPATH_BIND;
	ctx->PathConfig.BindRetry = PUNCHPATH_BIND_RETRY;
	ctx->PathConfig.PunchRetry = PUNCHPATH_RETRY;
	ctx->PathConfig.PunchAttempts = PUNCHPATH_ATTEMPTS;
	ctx->PathConfig.PunchBackoff = PUNCHPATH_BACKOFF;
	ctx->PathConfig.PunchConsent = PUNCHPATH_CONSENT;

	// The transports, and the stand-in of the Controller, which listens on the bound one
	ctx->Data = TransportLoopbackNew("loopback", 0, false);
	ctx->Control = TransportLoopbackNew("control", 0, true);
	ctx->Listener = (ctx->Control != NULL ? TransportListen(ctx->Control, PUNCHPATH_CONTROLLER) : NULL);
	for (UINT i = 0;i < PUNCHPATH_NUM_NODES;i++)
	{
		ctx->Links[i].Out = ControlNewSignals();
		ok = (ctx->Links[i].Out != NULL) && ok;
	}
	ctx->Acceptor = (ok && ctx->Data != NULL && ctx->Listener != NULL ? CreateThread(NULL, 0, PunchPathAccept, ctx, 0, NULL) : NULL);
	if (PunchPathCheck(ctx, ctx->Acceptor != NULL, "The stand-in of the Controller listens on the bound loopback transport of the control streams", "it could not start") == false)
	{
		return false;
	}

	return PunchPathStartNode(ctx, PUNCHPATH_A) && PunchPathStartNode(ctx, PUNCHPATH_B);
}

// Stop the world: the Nodes first, which close their control streams and leave the network, then the stand-in, the relays
// and the network, and delete what the test made
static void PunchPathStop(PUNCHPATH_CTX *ctx)
{
	for (UINT i = 0;i < PUNCHPATH_NUM_NODES;i++)
	{
		PUNCHPATH_NODE *t = &ctx->Nodes[i];
		wchar_t log_dir[MAX_PATH];

		if (t->Node != NULL)
		{
			NodeReaderUnregister(t->Node, &t->Reader);
			NodeStop(t->Node);
			FreeNode(t->Node);
			t->Node = NULL;
			ConbinePathW(log_dir, sizeof(log_dir), t->Dir, NODE_LOG_DIR_NAME);
			PunchPathDeleteFiles(log_dir);
			PunchPathDeleteFiles(t->Dir);
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
		PUNCHPATH_STREAM *t = ctx->Streams[i];

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
	for (UINT i = 0;i < PUNCHPATH_NUM_NODES;i++)
	{
		ControlFreeSignals(ctx->Links[i].Out);
	}

	if (ctx->Ticker != NULL)
	{
		WaitForSingleObject(ctx->Ticker, INFINITE);
		CloseHandle(ctx->Ticker);
	}
	for (UINT r = 0;r < PUNCHPATH_NUM_RELAYS;r++)
	{
		if (ctx->RelayHosts[r] != NULL)
		{
			NatSimAttach(ctx->RelayHosts[r], NULL);
		}
		PeerFree(ctx->Relays[r]);
		ctx->Relays[r] = NULL;
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
}

// Close the static keys, once the seeds of step g used them too
static void PunchPathCloseKeys(PUNCHPATH_CTX *ctx)
{
	for (UINT i = 0;i < PUNCHPATH_NUM_NODES;i++)
	{
		PeerKeyClose(&ctx->Nodes[i].Key);
	}
	for (UINT r = 0;r < PUNCHPATH_NUM_RELAYS;r++)
	{
		PeerKeyClose(&ctx->RelayKeys[r]);
	}
	PeerKeyClose(&ctx->ControllerKey);
}

// punchpath: a pair of Nodes behind two symmetric NATs, which ICE leaves on the Relay, gets a direct path by punching
RANZ_TEST_TAGS("punchpath", punchpath_test, "core", "Punch path of the new core (CORE-S5-7): a pair of Nodes behind two symmetric NATs of the simulator, which ICE leaves on the Relay, gets a direct path by port prediction and birthday punching in the same peer session; the probes are authenticated, limited per second and per attempt, and wait out a backoff after the attempts that met nothing; a probe that names an address the peer does not own sets no path; a punched path whose peer goes silent falls back to the Relay; each Node exports its punches; and the success rate over seeds of the other subscribers of the NATs. vpntest punchpath [seed]");
void punchpath_test(UINT num, char **arg)
{
	PUNCHPATH_CTX *ctx = ZeroMalloc(sizeof(PUNCHPATH_CTX));
	HANDLE done = CreateEventW(NULL, TRUE, FALSE, NULL);
	HANDLE watchdog = (done != NULL ? CreateThread(NULL, 0, PunchPathWatchdog, done, 0, NULL) : NULL);
	UINT64 third = 0;

	ctx->Seed = (num >= 1 && ToInt(arg[0]) != 0 ? ToInt(arg[0]) : PUNCHPATH_SEED);
	Print("Punch path test: a pair of Nodes behind two symmetric NATs, which ICE leaves on the Relay, gets a direct path by punching (seed %u)\n", ctx->Seed);

	if (PunchPathCheck(ctx, CryptoInit(), "The crypto module of the new core runs on CNG", "CryptoInit failed") && PunchPathStart(ctx) && PunchPathBringUp(ctx) &&
		PunchPathIceFails(ctx) && PunchPathLimits(ctx, &third))
	{
		if (PunchPathMeet(ctx, third))
		{
			PunchPathFallback(ctx);
		}
		PunchPathExport(ctx);
	}

	PunchPathStop(ctx);

	// The seeds run on networks of their own, with the keys and the addresses of the world
	if (ctx->Started)
	{
		PunchPathSeeds(ctx);
	}
	PunchPathCloseKeys(ctx);

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
		Print("PUNCHPATH TEST OK\n");
	}
	else
	{
		Print("PUNCHPATH TEST FAILED (%u of %u checks failed)\n", ctx->NumFailed, ctx->NumChecks);
	}

	Free(ctx);
}
