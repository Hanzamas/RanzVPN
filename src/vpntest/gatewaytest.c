// gatewaytest.c
// Named gateway HA and hub-and-spoke tests of vpntest ("gateway", "hubspoke" and "gatewaypath" commands, SDN-19 #195)
//
// The gateway HA and the hub-and-spoke topology of the overlay of a node (Cedar/NodeGateway.c), in process, as seam 2 of #45
// runs the data plane: in-process nodes over the loopback transport, each through a data transport of the test whose
// streams the test can freeze, so that a node goes silent while its Noise sessions stay open, and whose dials to node-z,
// a host that does not answer, hold the thread that dials, and a fake adapter for the host of each node. The test compiles
// the state of each node as the controller does (controller/internal/desired/topology.go).
//
// gateway: node-a and three gateways of VRF corp, gw-1, gw-2 and gw-3, which all announce the LAN 192.168.1.0/24.
// - Standby: the first gateway in name order carries every flow to the LAN, the others stand by.
// - A dial that blocks (SDN-19-R1, #507): node-a gets the peer node-z, which it cannot reach, and each of its dials holds the
//   thread of the overlay of node-a for 1200 ms, back to back. The gateways answered meanwhile: none goes down, and gw-1 keeps
//   every flow. gw-2, which freezes while the dials go on, is still found down after the dial in which it stopped answering.
// - The controller's health data: with gw-1 reported down, gw-2 carries every flow; with all three reported down, the probes
//   alone decide, and gw-1 carries them again. node-a takes these states from the wire, through the decoder of the control
//   module (ControlInput), which gives back whether the controller reports each gateway down, the hub and the ECMP of each VRF
//   and the LAN subnets behind node-a (SDN-19-R1, #507).
// - ECMP: 32 flows spread over the three gateways by their flow hash, each flow on one gateway, the state from the wire too;
//   and a reply from the LAN comes back to node-a through each of the three gateways (NodeGatewayFrom).
// - Silent failure: gw-1 freezes, so its Noise session to node-a stays open and goes silent. node-a finds it down with its
//   probes inside that session in under one second (no BFD), and the flows of gw-1 move to the other two within that time,
//   while the flows of the other two stay where they are.
// - Stop: with ECMP off, gw-2 carries every flow; its overlay stops, its Noise session to node-a closes, and the traffic moves
//   to gw-3 within the probe interval (#195).
// - Recovery: gw-1 thaws and answers the probes that waited for it at once; it is up again only after the answers to fresh
//   probes in a row, which the node sent after it answered again, at least two probe intervals later (SDN-19-R1, #507), and
//   carries the flows again.
// - Standby: with ECMP off gw-1 carries every flow and gw-3 stands by. gw-1 freezes again; node-a finds it down with its probes
//   and the traffic moves to gw-3, the standby gateway, each in under one second (#195).
// Print "GATEWAY TEST OK" only when every check passes.
//
// hubspoke: VRF branch of topology hub-and-spoke with the hub node-h and the spokes node-a, node-b and node-c, and the LAN
// 192.168.9.0/24 behind node-b. The spokes have no session to each other. A packet of one spoke to another, or to the LAN
// behind it, passes the hub, which counts it, and arrives as it was sent, and so do the replies; the hub reaches each spoke
// directly. A Mirror of the VRF at the hub copies each packet that it sends on to a sensor of the test, a UDP socket on
// 127.0.0.1, as an inspection appliance at the hub sees the traffic between two sites (ADR-0029 decision 8). A hub whose
// state names no hub drops what one spoke sends the other, and its Mirror copies nothing of it.
// The hub is where the policy of branch decides the traffic between two spokes (SDN-19-R2, #508): it judges each packet that
// it sends on by the rules of branch, with the spoke that sent it and the spoke of its next hop as its two ends.
// - With branch-to-hub and hub-to-branch alone, each spoke reaches the hub and the hub each spoke, and a packet of one spoke to
//   another is dropped at the hub, which counts it with the drops of its policy, though the spoke let it out.
// - With site-a-to-site-b, from the tag of node-a to the tag of node-b, node-a reaches node-b and the LAN behind it, and the
//   replies come back; node-c reaches neither, and node-a does not reach node-c.
// - With a-to-lan-b, from the address of node-a to the LAN behind node-b, node-a reaches that LAN, node-c does not, node-a does
//   not reach node-c, and the flow that the tag rule allowed ends at the hub.
// Each packet that the policy lets through, the Mirror of the hub copies as it was sent, and none that it drops.
// The hub never sends a packet back to the spoke that sent it (SDN-19-R1, #507): when node-h has the Generation in which the LAN
// behind node-b moved to node-a, and node-a still has the one before, which leads the LAN to node-h, node-h drops what node-a
// sends to the LAN, sends nothing on and copies nothing.
// Print "HUBSPOKE TEST OK" only when every check passes.
//
// gatewaypath: node-a, node-h and the gateways gw-1 and gw-2 of the LAN 192.168.30.0/24 in VRF sites, none of which has an
// endpoint, so no two of them dial each other and every pair takes the datagram path of the peer agent (Cedar/NodeAgent.c)
// on the network of the NAT simulator, with no Noise session. The states name a Relay that no host runs: the test gives each
// pair a direct path by hand, as ICE finds one (SDN-19-R1, #507).
// - Generation 1, a full mesh: node-a reaches gw-1 and gw-2 by datagram alone, and each is up once it answered the probes of
//   node-a on the datagram path. The flows of node-a to the LAN go to gw-1 and arrive as they were sent, a reply comes back
//   through gw-2, and when gw-1 loses its datagrams node-a finds it down in under one second and its traffic moves to gw-2.
//   gw-1 is up again after the answers to fresh probes, at least two probe intervals after its datagrams come back.
// - Generation 2, hub-and-spoke with the hub node-h: the hub reaches the spokes by datagram alone and probes gw-1 and gw-2 there.
//   Its own packets to the LAN go to gw-1, and so does the packet of node-a to the LAN that it sends on; the reply of the LAN
//   comes back to node-a through it. When gw-1 loses its datagrams, the hub moves both to gw-2 in under one second.
// Print "GATEWAYPATH TEST OK" only when every check passes.

#include "testlist.h"

#include "Cedar/ConfigStore.h"
#include "Cedar/Node.h"
#include "Cedar/NodeAgent.h"
#include "Cedar/NodeGateway.h"

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
#include "Core/Vxlan.h"

#include "natsim.h"

#include <pb_encode.h>

#include "ranz/control/v1/control.pb.h"

#include <WS2tcpip.h>

#include <stdio.h>

#define	GATEWAYTEST_BUDGET			120000		// A whole test ends within this time, or the watchdog ends the process (ms)
#define	GATEWAYTEST_BOUND			10000		// A bounded wait on observable state (ms)
#define	GATEWAYTEST_POLL			10			// Poll interval of observable state, and of the packets of a failover (ms)
#define	GATEWAYTEST_QUIET			300			// ms that a packet that goes nowhere is waited for
#define	GATEWAYTEST_DATA			16			// The data of a test datagram after its UDP header: its marker, then test bytes
#define	GATEWAYTEST_PACKET			(20 + 8 + GATEWAYTEST_DATA)	// The bytes of a test packet
#define	GATEWAYTEST_FLOWS			32			// The flows of the ECMP case, each from its own source port
#define	GATEWAYTEST_PORT			40000		// The source port of the first flow
#define	GATEWAYTEST_FAILOVER		1000		// ms in which a failed gateway is found and its traffic moves (#195)
#define	GATEWAYTEST_NONE			INFINITE	// No node
#define	GATEWAYTEST_UNREACHABLE		"node-z"	// The node of a host that does not answer: a dial to it holds the thread that dials
#define	GATEWAYTEST_WIRE_SIZE		65536		// The bytes of a ControlMessage that the test encodes at most
#define	GATEWAYTEST_WIRE_PEERS		8			// The peers of a state from the wire that the test keeps

// The checks of a test, and the marker of the next test packet
typedef struct GATEWAYTEST_CTX
{
	UINT NumChecks;
	UINT NumFailed;
	UINT Marker;
} GATEWAYTEST_CTX;

// The data transport of one node: the loopback transport of the test, whose streams the test can freeze. A frozen stream
// reads nothing and drops what it writes, as the sessions of a node that hangs or whose path went down: they stay open. A
// dial to node-z (GATEWAYTEST_UNREACHABLE) holds the thread that dials for Stall ms and fails, as the race of a real
// transport does for a host that does not answer (the client race and the handshake take up to 5 s each, NodeOverlay.c);
// over loopback it would fail at once.
typedef struct GATEWAYTEST_LINK
{
	TRANSPORT Transport;				// The data transport of the node's overlay
	TRANSPORT *Loopback;				// The loopback transport under it
	volatile LONG Frozen;				// Its streams are frozen
	volatile LONG Stall;				// ms that a dial to node-z holds the thread that dials, 0 for none
	volatile LONG Stalled;				// The dials that held it so far
} GATEWAYTEST_LINK;

// A stream or a listener of the data transport of a node: one of the loopback transport
typedef struct GATEWAYTEST_STREAM
{
	GATEWAYTEST_LINK *Link;
	TRANSPORT_STREAM *Stream;
	TRANSPORT_LISTENER *Listener;
} GATEWAYTEST_STREAM;

// A packet that the fake adapter of a host took
typedef struct GATEWAYTEST_TAKEN
{
	UINT VrfId;
	UINT Marker;						// The marker in its data, 0 for a packet of another size
	UINT Size;
	UCHAR Data[GATEWAYTEST_PACKET];
} GATEWAYTEST_TAKEN;

// One node of a test and the fake adapter of its host
typedef struct GATEWAYTEST_NODE
{
	char *Name;
	char *Address;						// Its address in the VRF of the test
	wchar_t Dir[MAX_PATH];				// Its data directory
	PEER_KEY Key;						// Its static key
	NODE *Node;
	NODE_READER Reader;					// The test thread as a reader of the node's forwarding tables, online while it sends
	GATEWAYTEST_LINK *Link;				// Its data transport
	SRWLOCK Lock;						// Taken
	LIST *Taken;						// What its adapter took (GATEWAYTEST_TAKEN)
	PEER_ADDR Addr;						// gatewaypath: the address of its host on the network of the simulator ...
	NATSIM_HOST *Host;					// ... the host there ...
	PEER_AGENT *Agent;					// ... and the peer layer of its peer agent on it, NULL before a state named a Relay
} GATEWAYTEST_NODE;

// The client of the control module through which a node takes its states from the wire (ControlInput), as its control stream
// would: the test encodes each state as the Update of a full state, and the client decodes it and hands it to the overlay of
// the node. What the client decoded last stays for the checks.
typedef struct GATEWAYTEST_WIRE
{
	CONTROL_CLIENT *Client;
	GATEWAYTEST_NODE *Node;				// The node that takes the states
	ranz_control_v1_ControlMessage *Message;	// The message that the test encodes ...
	UCHAR *Buf;							// ... and its bytes
	UINT NumStates;						// The states that the client handed over ...
	bool Applied;						// ... and whether the overlay of the node took the last one
	UINT64 Generation;					// The last one: its Generation ...
	UINT NumVrfs;						// ... its VRFs ...
	CONTROL_VRF Vrfs[CONTROL_MAX_VRFS];
	UINT NumPeers;						// ... its peers ...
	CONTROL_PEER Peers[GATEWAYTEST_WIRE_PEERS];
	UINT NumLanSubnets;					// ... and the LAN subnets behind the node
	CONTROL_ROUTE LanSubnets[CONTROL_MAX_ROUTES];
} GATEWAYTEST_WIRE;

static bool GatewayTestCheck(GATEWAYTEST_CTX *ctx, bool ok, char *what, char *fmt, ...) RANZ_PRINTF_FORMAT(4, 5);
static bool GatewayTestCheck(GATEWAYTEST_CTX *ctx, bool ok, char *what, char *fmt, ...)
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
// step. Its parameter is the event that the test sets when it ends; the name of the test is in the event's thread.
typedef struct GATEWAYTEST_WATCH
{
	HANDLE Done;
	char *Name;
} GATEWAYTEST_WATCH;

static DWORD WINAPI GatewayTestWatchdog(LPVOID param)
{
	GATEWAYTEST_WATCH *w = (GATEWAYTEST_WATCH *)param;
	char msg[MAX_SIZE];
	DWORD written = 0;

	if (WaitForSingleObject(w->Done, GATEWAYTEST_BUDGET) != WAIT_TIMEOUT)
	{
		return 0;
	}

	int len = snprintf(msg, sizeof(msg), "%s TEST FAILED (did not finish within %u ms)\n", w->Name, GATEWAYTEST_BUDGET);
	if (len > 0)
	{
		WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), msg, (DWORD)MIN((UINT)len, (UINT)sizeof(msg) - 1), &written, NULL);
	}

	TerminateProcess(GetCurrentProcess(), 1);

	return 0;
}

//
// The data transport of a node
//

static GATEWAYTEST_STREAM *GatewayTestWrap(GATEWAYTEST_LINK *l, TRANSPORT_STREAM *s, TRANSPORT_LISTENER *listener)
{
	GATEWAYTEST_STREAM *w = ZeroMalloc(sizeof(GATEWAYTEST_STREAM));

	w->Link = l;
	w->Stream = s;
	w->Listener = listener;

	return w;
}

static bool GatewayTestDial(void *param, const char *address, HANDLE cancel, void **stream)
{
	GATEWAYTEST_LINK *l = (GATEWAYTEST_LINK *)param;
	UINT stall = (UINT)ReadAcquire(&l->Stall);

	// A host that does not answer: the dial holds the thread that dials until the race of the transport gives up
	if (stall != 0 && StrCmp(address, GATEWAYTEST_UNREACHABLE) == 0)
	{
		SleepThread(stall);
		InterlockedIncrement(&l->Stalled);
		*stream = NULL;
		return false;
	}

	TRANSPORT_STREAM *s = TransportDial(l->Loopback, address, cancel);

	*stream = (s != NULL ? GatewayTestWrap(l, s, NULL) : NULL);

	return (s != NULL);
}

static bool GatewayTestListen(void *param, const char *address, void **listener)
{
	GATEWAYTEST_LINK *l = (GATEWAYTEST_LINK *)param;
	TRANSPORT_LISTENER *t = TransportListen(l->Loopback, address);

	*listener = (t != NULL ? GatewayTestWrap(l, NULL, t) : NULL);

	return (t != NULL);
}

static bool GatewayTestAccept(void *listener, UINT timeout, void **stream)
{
	GATEWAYTEST_STREAM *w = (GATEWAYTEST_STREAM *)listener;
	TRANSPORT_STREAM *s = TransportAccept(w->Listener, timeout);

	*stream = (s != NULL ? GatewayTestWrap(w->Link, s, NULL) : NULL);

	return (s != NULL);
}

static void GatewayTestCloseListener(void *listener)
{
	GATEWAYTEST_STREAM *w = (GATEWAYTEST_STREAM *)listener;

	TransportCloseListener(w->Listener);
	Free(w);
}

static UINT GatewayTestRead(void *stream, void *buf, UINT size, UINT timeout)
{
	GATEWAYTEST_STREAM *w = (GATEWAYTEST_STREAM *)stream;

	if (ReadAcquire(&w->Link->Frozen) != 0)
	{
		if (timeout != 0)
		{
			SleepThread(MIN(timeout, (UINT)GATEWAYTEST_POLL));
		}
		return TRANSPORT_LATER;
	}

	return TransportRead(w->Stream, buf, size, timeout);
}

static bool GatewayTestWrite(void *stream, const void *buf, UINT size)
{
	GATEWAYTEST_STREAM *w = (GATEWAYTEST_STREAM *)stream;

	if (ReadAcquire(&w->Link->Frozen) != 0)
	{
		return true;
	}

	return TransportWrite(w->Stream, buf, size);
}

static void GatewayTestClose(void *stream)
{
	GATEWAYTEST_STREAM *w = (GATEWAYTEST_STREAM *)stream;

	TransportClose(w->Stream);
	Free(w);
}

static UINT GatewayTestBinding(void *stream, UCHAR *binding, UINT max, UINT *size)
{
	return TransportBinding(((GATEWAYTEST_STREAM *)stream)->Stream, binding, max, size);
}

// The data transport of a node over the loopback transport loopback
static GATEWAYTEST_LINK *GatewayTestNewLink(TRANSPORT *loopback)
{
	GATEWAYTEST_LINK *l = ZeroMalloc(sizeof(GATEWAYTEST_LINK));

	l->Loopback = loopback;
	StrCpy(l->Transport.Name, sizeof(l->Transport.Name), "loopback");
	l->Transport.Param = l;
	l->Transport.Dial = GatewayTestDial;
	l->Transport.Listen = GatewayTestListen;
	l->Transport.Accept = GatewayTestAccept;
	l->Transport.CloseListener = GatewayTestCloseListener;
	l->Transport.Read = GatewayTestRead;
	l->Transport.Write = GatewayTestWrite;
	l->Transport.Close = GatewayTestClose;
	l->Transport.Binding = GatewayTestBinding;
	l->Transport.Rekey = NULL;
	l->Transport.Queue = TRANSPORT_QUEUE_NONE;

	return l;
}

//
// The nodes
//

// A new empty data directory under the temp directory of the process, with a configuration store that runs no role on one
// worker
static void GatewayTestNewDir(wchar_t *dir, UINT size, char *name)
{
	wchar_t tmp[MAX_PATH];
	wchar_t path[MAX_PATH];

	UniFormat(tmp, sizeof(tmp), L"gatewaytest_%S_%u", name, Rand32());
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

// Delete the files of a directory, then the directory, which holds no subdirectory
static void GatewayTestDeleteFiles(wchar_t *dir)
{
	DIRLIST *d = EnumDirW(dir);

	for (UINT i = 0;d != NULL && i < d->NumFiles;i++)
	{
		wchar_t path[MAX_PATH];

		if (d->File[i]->Folder)
		{
			continue;
		}
		ConbinePathW(path, sizeof(path), dir, d->File[i]->FileNameW);
		FileDeleteW(path);
	}

	FreeDir(d);
	DeleteDirW(dir);
}

// The fake adapter of a host: it keeps each packet, with its marker
static void GatewayTestAdapter(NODE *n, void *param, UINT vrf_id, const UCHAR *packet, UINT size)
{
	GATEWAYTEST_NODE *t = (GATEWAYTEST_NODE *)param;
	GATEWAYTEST_TAKEN *p = ZeroMalloc(sizeof(GATEWAYTEST_TAKEN));

	p->VrfId = vrf_id;
	p->Size = MIN(size, (UINT)sizeof(p->Data));
	Copy(p->Data, packet, p->Size);
	if (size == GATEWAYTEST_PACKET)
	{
		p->Marker = READ_UINT(packet + 28);
	}

	AcquireSRWLockExclusive(&t->Lock);
	Add(t->Taken, p);
	ReleaseSRWLockExclusive(&t->Lock);
}

// Whether the host of t took a packet with the marker, and a copy of it into p when p is not NULL
static bool GatewayTestTook(GATEWAYTEST_NODE *t, UINT marker, GATEWAYTEST_TAKEN *p)
{
	bool found = false;

	AcquireSRWLockShared(&t->Lock);
	for (UINT i = LIST_NUM(t->Taken);i > 0 && found == false;i--)
	{
		GATEWAYTEST_TAKEN *e = LIST_DATA(t->Taken, i - 1);

		if (e->Marker == marker)
		{
			found = true;
			if (p != NULL)
			{
				Copy(p, e, sizeof(GATEWAYTEST_TAKEN));
			}
		}
	}
	ReleaseSRWLockShared(&t->Lock);

	return found;
}

// The IPv4 address of a text into addr (4 bytes): false for anything else
static bool GatewayTestAddress(UCHAR *addr, char *str)
{
	IP ip;

	Zero(addr, 4);
	if (str == NULL || StrToIP(&ip, str) == false || IsIP4(&ip) == false)
	{
		return false;
	}

	Copy(addr, IPV4(ip.address), 4);
	return true;
}

// A UDP datagram of IPv4 from src to dst into buf (GATEWAYTEST_PACKET bytes), from the source port sport to the port dport,
// with the marker in the first 4 bytes of its data: its size, 0 when an address is not IPv4. The header has no options, TTL
// 64, identification 0 and Don't Fragment.
static UINT GatewayTestDatagram(UCHAR *buf, char *src, char *dst, USHORT sport, USHORT dport, UINT marker)
{
	UCHAR *udp = buf + 20;
	UINT s, d;
	USHORT sum;

	Zero(buf, GATEWAYTEST_PACKET);
	if (GatewayTestAddress(buf + 12, src) == false || GatewayTestAddress(buf + 16, dst) == false)
	{
		return 0;
	}

	buf[0] = 0x45;
	WRITE_USHORT(buf + 2, GATEWAYTEST_PACKET);
	WRITE_USHORT(buf + 6, 0x4000);
	buf[8] = 64;
	buf[9] = IP_PROTO_UDP;
	sum = IpChecksum(buf, 20);
	Copy(buf + 10, &sum, 2);

	WRITE_USHORT(udp, sport);
	WRITE_USHORT(udp + 2, dport);
	WRITE_USHORT(udp + 4, 8 + GATEWAYTEST_DATA);
	WRITE_UINT(udp + 8, marker);
	for (UINT i = 4;i < GATEWAYTEST_DATA;i++)
	{
		udp[8 + i] = (UCHAR)('A' + i);
	}
	Copy(&s, buf + 12, 4);
	Copy(&d, buf + 16, 4);
	sum = CalcChecksumForIPv4(s, d, IP_PROTO_UDP, udp, 8 + GATEWAYTEST_DATA, 0);
	if (sum == 0)
	{
		sum = 0xFFFF;
	}
	Copy(udp + 6, &sum, 2);

	return GATEWAYTEST_PACKET;
}

// A test datagram from the source port sport to port 53 (GatewayTestDatagram)
static UINT GatewayTestPacket(UCHAR *buf, char *src, char *dst, USHORT sport, UINT marker)
{
	return GatewayTestDatagram(buf, src, dst, sport, 53, marker);
}

// A state of the node t at generation gen in the VRF vrf_id of the name vrf, of topology hub-and-spoke with the hub hub when
// hub is not NULL, with ECMP when ecmp is set: the address of t in the Network of the VRF, a /24. Its peers come after.
static CONTROL_STATE *GatewayTestState(GATEWAYTEST_NODE *t, UINT64 gen, UINT vrf_id, char *vrf, char *hub, bool ecmp, UINT max_peers)
{
	CONTROL_STATE *st = ZeroMalloc(sizeof(CONTROL_STATE));

	st->Generation = gen;
	StrCpy(st->Name, sizeof(st->Name), t->Name);
	st->NumAddresses = 1;
	StrCpy(st->Addresses[0].Network, sizeof(st->Addresses[0].Network), vrf);
	st->Addresses[0].VrfId = vrf_id;
	st->Addresses[0].AddressSize = (GatewayTestAddress(st->Addresses[0].Address, t->Address) ? 4 : 0);
	st->Addresses[0].Length = 24;
	st->NumVrfs = 1;
	StrCpy(st->Vrfs[0].Name, sizeof(st->Vrfs[0].Name), vrf);
	st->Vrfs[0].Id = vrf_id;
	st->Vrfs[0].Mtu = 1280;
	st->Vrfs[0].Ecmp = ecmp;
	if (hub != NULL)
	{
		StrCpy(st->Vrfs[0].Hub, sizeof(st->Vrfs[0].Hub), hub);
	}
	st->Peers = ZeroMalloc(sizeof(CONTROL_PEER) * MAX(max_peers, 1));

	return st;
}

static void GatewayTestFreeState(CONTROL_STATE *st)
{
	if (st != NULL)
	{
		Free(st->Peers);
		Free(st->Rules);
		Free(st);
	}
}

// Add the route of the prefix address/length in the VRF vrf_id to the routes of p, or of the LAN subnets of st when p is NULL
static void GatewayTestRoute(CONTROL_STATE *st, CONTROL_PEER *p, UINT vrf_id, char *address, UINT length)
{
	UINT *num = (p != NULL ? &p->NumRoutes : &st->NumLanSubnets);
	CONTROL_ROUTE *routes = (p != NULL ? p->Routes : st->LanSubnets);

	if (*num >= CONTROL_MAX_ROUTES)
	{
		return;
	}

	CONTROL_ROUTE *r = &routes[(*num)++];
	Zero(r, sizeof(CONTROL_ROUTE));
	r->VrfId = vrf_id;
	r->AddressSize = (GatewayTestAddress(r->Address, address) ? 4 : 0);
	r->Length = length;
}

// Add the node o as a peer of the state st in the VRF vrf_id, with its address there: the new Peer
static CONTROL_PEER *GatewayTestPeer(CONTROL_STATE *st, GATEWAYTEST_NODE *o, UINT vrf_id, char *vrf)
{
	CONTROL_PEER *p = &st->Peers[st->NumPeers++];

	Zero(p, sizeof(CONTROL_PEER));
	StrCpy(p->Name, sizeof(p->Name), o->Name);
	Copy(p->Key, o->Key.Public, PEER_KEY_SIZE);
	p->NumVrfs = 1;
	p->VrfIds[0] = vrf_id;
	p->NumAddresses = 1;
	StrCpy(p->Addresses[0].Network, sizeof(p->Addresses[0].Network), vrf);
	p->Addresses[0].VrfId = vrf_id;
	p->Addresses[0].AddressSize = (GatewayTestAddress(p->Addresses[0].Address, o->Address) ? 4 : 0);
	p->Addresses[0].Length = 24;

	return p;
}

//
// The states from the wire
//

// The prefix of size bytes at address and of the length length into p
static void GatewayTestPrefix(ranz_control_v1_Prefix *p, const UCHAR *address, UINT size, UINT length)
{
	p->address.size = (pb_size_t)size;
	Copy(p->address.bytes, address, size);
	p->length = length;
}

// The routes of a state into the routes of a message, as the controller sends them
static pb_size_t GatewayTestRoutes(ranz_control_v1_Route *dst, const CONTROL_ROUTE *src, UINT num)
{
	pb_size_t count = 0;

	for (UINT i = 0;i < num && i < CONTROL_MAX_ROUTES;i++)
	{
		ranz_control_v1_Route *r = &dst[count++];

		r->vrf_id = src[i].VrfId;
		r->has_prefix = true;
		GatewayTestPrefix(&r->prefix, src[i].Address, src[i].AddressSize, src[i].Length);
		r->peer_vrf_id = src[i].PeerVrfId;
	}

	return count;
}

// The addresses of a state into the addresses of a message
static pb_size_t GatewayTestAddresses(ranz_control_v1_Address *dst, const CONTROL_ADDRESS *src, UINT num)
{
	pb_size_t count = 0;

	for (UINT i = 0;i < num && i < CONTROL_MAX_ADDRESSES;i++)
	{
		ranz_control_v1_Address *a = &dst[count++];

		StrCpy(a->network, sizeof(a->network), src[i].Network);
		a->vrf_id = src[i].VrfId;
		a->has_prefix = true;
		GatewayTestPrefix(&a->prefix, src[i].Address, src[i].AddressSize, src[i].Length);
	}

	return count;
}

// The state st as the Update of a full state, as the controller sends it (controller/internal/desired), into m: the NodeConfig
// with the name, the tags, the addresses and the LAN subnets of the node; a Vrf object of each VRF with its id, its MTU, its
// policy, its hub and its ECMP; and a Peer object of each peer with its key, its VRFs, its addresses, its routes, its tags and
// whether the controller reports it down. False for a state of more objects than an Update holds.
static bool GatewayTestEncode(const CONTROL_STATE *st, ranz_control_v1_ControlMessage *m)
{
	Zero(m, sizeof(ranz_control_v1_ControlMessage));
	m->which_body = ranz_control_v1_ControlMessage_update_tag;

	ranz_control_v1_Update *u = &m->body.update;
	if (1 + st->NumVrfs + st->NumPeers > sizeof(u->set) / sizeof(u->set[0]))
	{
		return false;
	}
	u->generation = st->Generation;

	ranz_control_v1_Object *o = &u->set[u->set_count++];
	ranz_control_v1_NodeConfig *node = &o->kind.node;
	o->which_kind = ranz_control_v1_Object_node_tag;
	StrCpy(node->name, sizeof(node->name), st->Name);
	for (UINT i = 0;i < st->NumTags && i < CONTROL_MAX_TAGS;i++)
	{
		StrCpy(node->tags[node->tags_count++], sizeof(node->tags[0]), st->Tags[i]);
	}
	node->addresses_count = GatewayTestAddresses(node->addresses, st->Addresses, st->NumAddresses);
	node->lan_subnets_count = GatewayTestRoutes(node->lan_subnets, st->LanSubnets, st->NumLanSubnets);

	for (UINT i = 0;i < st->NumVrfs && i < CONTROL_MAX_VRFS;i++)
	{
		const CONTROL_VRF *src = &st->Vrfs[i];
		ranz_control_v1_Vrf *v = &u->set[u->set_count].kind.vrf;

		u->set[u->set_count++].which_kind = ranz_control_v1_Object_vrf_tag;
		StrCpy(v->name, sizeof(v->name), src->Name);
		v->id = src->Id;
		v->mtu = src->Mtu;
		v->has_policy = src->Policy;
		StrCpy(v->hub, sizeof(v->hub), src->Hub);
		v->ecmp = src->Ecmp;
	}

	for (UINT i = 0;i < st->NumPeers;i++)
	{
		const CONTROL_PEER *src = &st->Peers[i];
		ranz_control_v1_Peer *p = &u->set[u->set_count].kind.peer;

		u->set[u->set_count++].which_kind = ranz_control_v1_Object_peer_tag;
		StrCpy(p->name, sizeof(p->name), src->Name);
		p->public_key.size = PEER_KEY_SIZE;
		Copy(p->public_key.bytes, src->Key, PEER_KEY_SIZE);
		for (UINT j = 0;j < src->NumVrfs && j < CONTROL_MAX_VRFS;j++)
		{
			p->vrf_ids[p->vrf_ids_count++] = src->VrfIds[j];
		}
		p->addresses_count = GatewayTestAddresses(p->addresses, src->Addresses, src->NumAddresses);
		p->routes_count = GatewayTestRoutes(p->routes, src->Routes, src->NumRoutes);
		for (UINT j = 0;j < src->NumTags && j < CONTROL_MAX_TAGS;j++)
		{
			StrCpy(p->tags[p->tags_count++], sizeof(p->tags[0]), src->Tags[j]);
		}
		p->down = src->Down;
	}

	return true;
}

// The owner of the client of a wire (CONTROL_STATE_PROC): it keeps what the client decoded, and the node applies the state
static void GatewayTestWireProc(void *param, const CONTROL_STATE *st)
{
	GATEWAYTEST_WIRE *w = (GATEWAYTEST_WIRE *)param;

	w->NumStates++;
	w->Generation = st->Generation;
	w->NumVrfs = MIN(st->NumVrfs, CONTROL_MAX_VRFS);
	Copy(w->Vrfs, st->Vrfs, sizeof(CONTROL_VRF) * w->NumVrfs);
	w->NumPeers = MIN(st->NumPeers, GATEWAYTEST_WIRE_PEERS);
	Copy(w->Peers, st->Peers, sizeof(CONTROL_PEER) * w->NumPeers);
	w->NumLanSubnets = MIN(st->NumLanSubnets, CONTROL_MAX_ROUTES);
	Copy(w->LanSubnets, st->LanSubnets, sizeof(CONTROL_ROUTE) * w->NumLanSubnets);

	w->Applied = NodeOverlayApply(w->Node->Node, st);
}

// A wire to the node t: a client of the control module without its thread and its stream (ControlNew), whose owner is the
// overlay of t. NULL when the client cannot be made.
static GATEWAYTEST_WIRE *GatewayTestNewWire(GATEWAYTEST_NODE *t)
{
	static TRANSPORT transport = {"gatewaytest"};
	CONTROL_CONFIG cfg;
	GATEWAYTEST_WIRE *w = ZeroMalloc(sizeof(GATEWAYTEST_WIRE));

	w->Node = t;
	w->Message = ZeroMalloc(sizeof(ranz_control_v1_ControlMessage));
	w->Buf = ZeroMalloc(GATEWAYTEST_WIRE_SIZE);

	Zero(&cfg, sizeof(cfg));
	cfg.Transport = &transport;
	StrCpy(cfg.Address, sizeof(cfg.Address), "controller");
	cfg.StaticKey = t->Key.Private;
	cfg.Proc = GatewayTestWireProc;
	cfg.Param = w;
	w->Client = ControlNew(&cfg);
	if (w->Client == NULL)
	{
		Free(w->Message);
		Free(w->Buf);
		Free(w);
		return NULL;
	}

	return w;
}

static void GatewayTestFreeWire(GATEWAYTEST_WIRE *w)
{
	if (w != NULL)
	{
		ControlFree(w->Client);
		Free(w->Message);
		Free(w->Buf);
		Free(w);
	}
}

// Send the state st over the wire w, as the control stream sends the frame of an Update: the client decodes it with the code
// that nanopb generates from control.proto (Core/Control.c, Core/ControlGateway.c) and the overlay of its node applies what
// it decoded. False when the state was not encoded, decoded or applied.
static bool GatewayTestSendWire(GATEWAYTEST_WIRE *w, const CONTROL_STATE *st)
{
	pb_ostream_t os = pb_ostream_from_buffer(w->Buf, GATEWAYTEST_WIRE_SIZE);
	UINT before = w->NumStates;

	if (GatewayTestEncode(st, w->Message) == false || pb_encode(&os, ranz_control_v1_ControlMessage_fields, w->Message) == false)
	{
		return false;
	}

	w->Applied = false;

	return ControlInput(w->Client, w->Buf, (UINT)os.bytes_written) && w->NumStates == before + 1 && w->Applied;
}

// The network of the simulator takes the peer layer of the agent of a node, and NULL before it stops (NODE_PATH_ATTACH_PROC)
static void GatewayTestAttach(NODE *n, void *param, PEER_AGENT *agent)
{
	GATEWAYTEST_NODE *t = (GATEWAYTEST_NODE *)param;

	t->Agent = agent;
	NatSimAttach(t->Host, agent);
}

// The data transport dials a peer only at an endpoint, and no node of the datagram path names one: no stream session comes up
static bool GatewayTestDialable(NODE *n, void *param, const char *name, const struct CONTROL_ENDPOINT *endpoints, UINT num)
{
	return (num != 0);
}

// Start the nodes and their overlays without a control stream, each over its own data transport on loopback, with the fake
// adapter of its host. With sim, the peer agent of each node runs on the network of the simulator, from its host there, with
// the configuration path, and its overlay dials no peer.
static bool GatewayTestStart(GATEWAYTEST_CTX *ctx, GATEWAYTEST_NODE *nodes, UINT num, TRANSPORT *loopback, NATSIM *sim, PEER_CONFIG *path)
{
	char what[MAX_SIZE];
	bool started = (loopback != NULL);

	for (UINT i = 0;i < num && started;i++)
	{
		GATEWAYTEST_NODE *t = &nodes[i];
		NODE_OVERLAY_CONFIG c;

		GatewayTestNewDir(t->Dir, sizeof(t->Dir), t->Name);
		t->Node = NewNode(t->Dir);
		NodeStart(t->Node);
		NodeReaderRegister(t->Node, &t->Reader);
		NodeReaderOffline(&t->Reader);
		t->Link = GatewayTestNewLink(loopback);

		Zero(&c, sizeof(c));
		c.Data = &t->Link->Transport;
		c.Key = &t->Key;
		c.Adapter = GatewayTestAdapter;
		c.AdapterParam = t;
		if (sim != NULL)
		{
			t->Host = NatSimAddHost(sim, NULL, &t->Addr);
			c.Dialable = GatewayTestDialable;
			c.PathSend = NatSimSend;
			c.PathSendParam = t->Host;
			c.PathAttach = GatewayTestAttach;
			c.PathConfig = path;
		}
		Format(what, sizeof(what), "%s: its overlay runs without a control stream%s", t->Name, sim != NULL ? ", and its peer agent on the network of the simulator" : "");
		started = GatewayTestCheck(ctx, (sim == NULL || t->Host != NULL) && NodeOverlayStart(t->Node, &c), what, "NodeOverlayStart failed");
	}

	return started;
}

// Whether the overlay of t runs its Generation gen with peers peers and a session to links of them
static bool GatewayTestApplied(GATEWAYTEST_NODE *t, UINT64 gen, UINT peers, UINT links)
{
	NODE_OVERLAY_STATUS st;

	NodeOverlayGetStatus(t->Node, &st);

	return (st.Generation == gen && st.NumPeers == peers && st.NumLinks == links);
}

// Wait until the overlay of each node whose want is not GATEWAYTEST_NONE runs the Generation gen with sessions to want[i]
// peers, which it has, and more[i] peers besides them that it has no session to (more NULL for none)
static bool GatewayTestWaitApplied(GATEWAYTEST_NODE *nodes, UINT num, UINT64 gen, UINT *want, UINT *more)
{
	for (UINT64 end = Tick64() + GATEWAYTEST_BOUND;;)
	{
		bool all = true;

		for (UINT i = 0;i < num;i++)
		{
			if (want[i] != GATEWAYTEST_NONE && GatewayTestApplied(&nodes[i], gen, want[i] + (more != NULL ? more[i] : 0), want[i]) == false)
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
		SleepThread(GATEWAYTEST_POLL);
	}
}

// Send one packet of the host of the node from in the VRF vrf_id from src to dst, from the source port sport, with the next
// marker: the marker, 0 when the packet could not be built
static UINT GatewayTestSend(GATEWAYTEST_CTX *ctx, GATEWAYTEST_NODE *from, UINT vrf_id, char *src, char *dst, USHORT sport)
{
	UCHAR packet[GATEWAYTEST_PACKET];
	UINT marker = ++ctx->Marker;
	UINT size = GatewayTestPacket(packet, src, dst, sport, marker);

	if (size == 0)
	{
		return 0;
	}

	NodeReaderOnline(from->Node, &from->Reader);
	NodeOverlayInput(from->Node, vrf_id, packet, size);
	NodeReaderOffline(&from->Reader);

	return marker;
}

// The node of nodes whose host took the packet of the marker, within bound ms: its index, GATEWAYTEST_NONE when none did.
// p takes the packet.
static UINT GatewayTestWhere(GATEWAYTEST_NODE *nodes, UINT num, UINT marker, UINT bound, GATEWAYTEST_TAKEN *p)
{
	for (UINT64 end = Tick64() + bound;marker != 0;)
	{
		for (UINT i = 0;i < num;i++)
		{
			if (GatewayTestTook(&nodes[i], marker, p))
			{
				return i;
			}
		}

		if (Tick64() >= end)
		{
			break;
		}
		SleepThread(1);
	}

	return GATEWAYTEST_NONE;
}

// The name of the node of the index i, "no host" for GATEWAYTEST_NONE
static char *GatewayTestName(GATEWAYTEST_NODE *nodes, UINT num, UINT i)
{
	return (i < num ? nodes[i].Name : "no host");
}

// Free the nodes, their data transports and what their hosts took
static void GatewayTestFree(GATEWAYTEST_NODE *nodes, UINT num)
{
	for (UINT i = 0;i < num;i++)
	{
		GATEWAYTEST_NODE *t = &nodes[i];
		wchar_t log_dir[MAX_PATH];

		if (t->Node != NULL)
		{
			NodeReaderUnregister(t->Node, &t->Reader);
			NodeStop(t->Node);
			FreeNode(t->Node);
			ConbinePathW(log_dir, sizeof(log_dir), t->Dir, NODE_LOG_DIR_NAME);
			GatewayTestDeleteFiles(log_dir);
			GatewayTestDeleteFiles(t->Dir);
		}
		Free(t->Link);
		PeerKeyClose(&t->Key);

		for (UINT k = 0;k < LIST_NUM(t->Taken);k++)
		{
			Free(LIST_DATA(t->Taken, k));
		}
		ReleaseList(t->Taken);
	}
}

// The nodes of a test with their names, addresses and static keys: false when a key could not be made
static bool GatewayTestKeys(GATEWAYTEST_NODE *nodes, UINT num, char **names, char **addresses, UINT seed)
{
	UCHAR scalar[PEER_KEY_SIZE];
	bool ok = true;

	for (UINT i = 0;i < num;i++)
	{
		GATEWAYTEST_NODE *t = &nodes[i];

		t->Name = names[i];
		t->Address = addresses[i];
		InitializeSRWLock(&t->Lock);
		t->Taken = NewListFast(NULL);
		for (UINT j = 0;j < PEER_KEY_SIZE;j++)
		{
			scalar[j] = (UCHAR)(seed + PEER_KEY_SIZE * i + j);
		}
		ok = PeerKeyFromScalar(&t->Key, scalar) && ok;
	}
	Zero(scalar, sizeof(scalar));

	return ok;
}

//
// gateway
//

#define	GATEWAY_A				0
#define	GATEWAY_GW1				1
#define	GATEWAY_GW2				2
#define	GATEWAY_GW3				3
#define	GATEWAY_NUM_NODES		4
#define	GATEWAY_VRF_ID			10
#define	GATEWAY_VRF				"corp"
#define	GATEWAY_LAN				"192.168.1.0"
#define	GATEWAY_LAN_LENGTH		24
#define	GATEWAY_LAN_HOST		"192.168.1.7"
#define	GATEWAY_Z_ADDRESS		"10.10.0.26"	// The address of node-z, which node-a cannot reach
#define	GATEWAY_STALL			1200		// ms that each dial of node-a to node-z holds the thread of its overlay: above
											// NODE_GATEWAY_DEAD, and above NODE_OVERLAY_REDIAL, so the dials go back to back
#define	GATEWAY_STALLS			3			// The dials of node-a to node-z that the gateways are watched through
#define	GATEWAY_OWN_LAN			"192.168.50.0"	// node-a's own LAN subnet in the states from the wire ...
#define	GATEWAY_OWN_LAN6		"fd00:50::"		// ... and its IPv6 one
#define	GATEWAY_HUB_VRF_ID		20			// The VRF of topology hub-and-spoke of the states from the wire ...
#define	GATEWAY_HUB_VRF			"branch"	// ... its name ...
#define	GATEWAY_HUB				"node-h"	// ... and its hub

static char *gateway_names[GATEWAY_NUM_NODES] = {"node-a", "gw-1", "gw-2", "gw-3"};
static char *gateway_addresses[GATEWAY_NUM_NODES] = {"10.10.0.1", "10.10.0.11", "10.10.0.12", "10.10.0.13"};

// The state of node i at generation gen, as the controller compiles it: VRF corp with ECMP when ecmp is set. node-a has the
// three gateways as peers, each with the LAN as its route and, when the bit of the gateway (1 << i) is in down, reported
// down by the controller, and z as a peer of corp besides them when z is not NULL. A gateway has the LAN as a LAN subnet of
// its own and every other node as a peer; the LAN of the other gateways is no route of it, as the controller gives no node a
// prefix that it announces itself. With wire, node-a has what the decoder of the control module is checked on besides: its
// own LAN subnets 192.168.50.0/24 and fd00:50::/64 in corp, and VRF branch, of topology hub-and-spoke with the hub node-h.
static CONTROL_STATE *GatewayState(GATEWAYTEST_NODE *nodes, UINT i, UINT64 gen, bool ecmp, UINT down, GATEWAYTEST_NODE *z, bool wire)
{
	CONTROL_STATE *st = GatewayTestState(&nodes[i], gen, GATEWAY_VRF_ID, GATEWAY_VRF, NULL, ecmp, GATEWAY_NUM_NODES + 1);

	if (i != GATEWAY_A)
	{
		GatewayTestRoute(st, NULL, GATEWAY_VRF_ID, GATEWAY_LAN, GATEWAY_LAN_LENGTH);
	}

	for (UINT j = 0;j < GATEWAY_NUM_NODES;j++)
	{
		if (j == i)
		{
			continue;
		}

		CONTROL_PEER *p = GatewayTestPeer(st, &nodes[j], GATEWAY_VRF_ID, GATEWAY_VRF);
		if (i == GATEWAY_A)
		{
			GatewayTestRoute(st, p, GATEWAY_VRF_ID, GATEWAY_LAN, GATEWAY_LAN_LENGTH);
			p->Down = ((down & (1U << j)) != 0);
		}
	}

	// node-z comes after the gateways in name order
	if (i == GATEWAY_A && z != NULL)
	{
		GatewayTestPeer(st, z, GATEWAY_VRF_ID, GATEWAY_VRF);
	}

	if (i == GATEWAY_A && wire)
	{
		IP ip6;
		CONTROL_ROUTE *r;
		CONTROL_VRF *v;

		// The VRFs in name order: branch before corp
		Copy(&st->Vrfs[1], &st->Vrfs[0], sizeof(CONTROL_VRF));
		v = &st->Vrfs[0];
		Zero(v, sizeof(CONTROL_VRF));
		StrCpy(v->Name, sizeof(v->Name), GATEWAY_HUB_VRF);
		v->Id = GATEWAY_HUB_VRF_ID;
		v->Mtu = 1280;
		StrCpy(v->Hub, sizeof(v->Hub), GATEWAY_HUB);
		st->NumVrfs = 2;

		GatewayTestRoute(st, NULL, GATEWAY_VRF_ID, GATEWAY_OWN_LAN, 24);
		Zero(&ip6, sizeof(ip6));
		r = &st->LanSubnets[st->NumLanSubnets++];
		Zero(r, sizeof(CONTROL_ROUTE));
		r->VrfId = GATEWAY_VRF_ID;
		r->AddressSize = (StrToIP(&ip6, GATEWAY_OWN_LAN6) && IsIP4(&ip6) == false ? 16 : 0);
		Copy(r->Address, ip6.address, r->AddressSize);
		r->Length = 64;
	}

	return st;
}

// Apply the states of a Generation to every node whose overlay runs (want[i] not GATEWAYTEST_NONE), and wait until each runs it
// with its sessions: node-a with the peer z besides the gateways when z is not NULL, which it has no session to, and its state
// from the wire w, through the decoder of the control module, when w is not NULL
static bool GatewayApply(GATEWAYTEST_NODE *nodes, UINT64 gen, bool ecmp, UINT down, UINT *want, GATEWAYTEST_NODE *z, GATEWAYTEST_WIRE *w)
{
	UINT more[GATEWAY_NUM_NODES] = {z != NULL ? 1 : 0, 0, 0, 0};
	bool applied = true;

	for (UINT i = 0;i < GATEWAY_NUM_NODES;i++)
	{
		if (want[i] == GATEWAYTEST_NONE)
		{
			continue;
		}

		CONTROL_STATE *st = GatewayState(nodes, i, gen, ecmp, down, z, i == GATEWAY_A && w != NULL);
		if (i == GATEWAY_A && w != NULL)
		{
			applied = GatewayTestSendWire(w, st) && applied;
		}
		else
		{
			applied = NodeOverlayApply(nodes[i].Node, st) && applied;
		}
		GatewayTestFreeState(st);
	}

	return applied && GatewayTestWaitApplied(nodes, GATEWAY_NUM_NODES, gen, want, more);
}

// node-z, the peer of node-a that it cannot reach, with a static key above the one of node-a, so that node-a dials it (the
// node of the lower key dials, CORE-S3-1): false when no such key was made
static bool GatewayUnreachable(GATEWAYTEST_NODE *z, GATEWAYTEST_NODE *a)
{
	UCHAR scalar[PEER_KEY_SIZE];
	bool ok = false;

	z->Name = GATEWAYTEST_UNREACHABLE;
	z->Address = GATEWAY_Z_ADDRESS;
	InitializeSRWLock(&z->Lock);
	z->Taken = NewListFast(NULL);

	for (UINT seed = 0;seed < 64 && ok == false;seed++)
	{
		for (UINT j = 0;j < PEER_KEY_SIZE;j++)
		{
			scalar[j] = (UCHAR)(0xA0 + seed + 3 * j);
		}
		ok = PeerKeyFromScalar(&z->Key, scalar) && Cmp(a->Key.Public, z->Key.Public, PEER_KEY_SIZE) < 0;
		if (ok == false)
		{
			PeerKeyClose(&z->Key);
		}
	}
	Zero(scalar, sizeof(scalar));

	return ok;
}

// The gateway whose host takes a packet of the flow of the source port sport of node-a to the LAN, within GATEWAYTEST_BOUND:
// its index, GATEWAYTEST_NONE when none takes it or what it takes is not the packet sent
static UINT GatewayFlow(GATEWAYTEST_CTX *ctx, GATEWAYTEST_NODE *nodes, USHORT sport)
{
	GATEWAYTEST_TAKEN p;
	UCHAR want[GATEWAYTEST_PACKET];
	UINT marker = GatewayTestSend(ctx, &nodes[GATEWAY_A], GATEWAY_VRF_ID, gateway_addresses[GATEWAY_A], GATEWAY_LAN_HOST, sport);
	UINT i = GatewayTestWhere(nodes, GATEWAY_NUM_NODES, marker, GATEWAYTEST_BOUND, &p);

	GatewayTestPacket(want, gateway_addresses[GATEWAY_A], GATEWAY_LAN_HOST, sport, marker);
	if (i == GATEWAYTEST_NONE || i == GATEWAY_A || p.Size != GATEWAYTEST_PACKET || Cmp(p.Data, want, GATEWAYTEST_PACKET) != 0 || p.VrfId != GATEWAY_VRF_ID)
	{
		return GATEWAYTEST_NONE;
	}

	return i;
}

// Send num flows of node-a to the LAN and check that the gateway want takes each, as it was sent
static void GatewayFlows(GATEWAYTEST_CTX *ctx, GATEWAYTEST_NODE *nodes, UINT num, UINT want, char *what)
{
	UINT got = GATEWAYTEST_NONE;
	UINT k;

	for (k = 0;k < num;k++)
	{
		got = GatewayFlow(ctx, nodes, (USHORT)(GATEWAYTEST_PORT + k));
		if (got != want)
		{
			break;
		}
	}

	GatewayTestCheck(ctx, k == num, what, "flow %u went to %s", k, GatewayTestName(nodes, GATEWAY_NUM_NODES, got));
}

// What node-a knows of the gateway of index i
static NODE_GATEWAY_PEER_STATUS GatewayPeer(GATEWAYTEST_NODE *nodes, UINT i)
{
	NODE_GATEWAY_PEER_STATUS st;

	NodeGatewayGetPeer(nodes[GATEWAY_A].Node, nodes[i].Name, &st);

	return st;
}

// Wait until node-a knows the gateway i to be up (up) or down: the ms it took, INFINITE when it did not within GATEWAYTEST_BOUND
static UINT GatewayWaitPeer(GATEWAYTEST_NODE *nodes, UINT i, bool up, UINT64 start)
{
	for (UINT64 end = start + GATEWAYTEST_BOUND;;)
	{
		NODE_GATEWAY_PEER_STATUS st = GatewayPeer(nodes, i);
		UINT64 now = Tick64();

		if (st.Probed && st.Up == up)
		{
			return (UINT)(now - start);
		}
		if (now >= end)
		{
			return INFINITE;
		}
		SleepThread(1);
	}
}

// Send a packet of the flow sport of node-a to the LAN every GATEWAYTEST_POLL ms from start until a gateway other than gone
// takes one: the ms from start to the send of the last packet, INFINITE when none went on within GATEWAYTEST_BOUND. to takes
// the gateway.
static UINT GatewayFailover(GATEWAYTEST_CTX *ctx, GATEWAYTEST_NODE *nodes, USHORT sport, UINT gone, UINT64 start, UINT *to)
{
	UINT first = ctx->Marker + 1;

	*to = GATEWAYTEST_NONE;

	for (UINT64 end = start + GATEWAYTEST_BOUND;Tick64() < end;)
	{
		UINT64 sent = Tick64();
		UINT marker = GatewayTestSend(ctx, &nodes[GATEWAY_A], GATEWAY_VRF_ID, gateway_addresses[GATEWAY_A], GATEWAY_LAN_HOST, sport);

		SleepThread(GATEWAYTEST_POLL);

		// A packet sent before the last one may arrive now: the time counts to the send of the last one, never less
		for (UINT m = first;m <= marker;m++)
		{
			UINT i = GatewayTestWhere(nodes, GATEWAY_NUM_NODES, m, 0, NULL);

			if (i != GATEWAYTEST_NONE && i != gone && i != GATEWAY_A)
			{
				*to = i;
				return (UINT)(sent - start);
			}
		}
	}

	return INFINITE;
}

// The ECMP case: each of the flows of node-a to the LAN, sent twice, goes to one gateway both times, and every gateway carries
// some of them. flows takes the gateway of each flow.
static bool GatewayEcmp(GATEWAYTEST_CTX *ctx, GATEWAYTEST_NODE *nodes, UINT *flows)
{
	UINT count[GATEWAY_NUM_NODES];
	bool same = true;
	UINT k;

	Zero(count, sizeof(count));
	for (k = 0;k < GATEWAYTEST_FLOWS && same;k++)
	{
		flows[k] = GatewayFlow(ctx, nodes, (USHORT)(GATEWAYTEST_PORT + k));
		same = (flows[k] != GATEWAYTEST_NONE && GatewayFlow(ctx, nodes, (USHORT)(GATEWAYTEST_PORT + k)) == flows[k]);
		if (flows[k] < GATEWAY_NUM_NODES)
		{
			count[flows[k]]++;
		}
	}

	bool ok = GatewayTestCheck(ctx, same, "ECMP: each of 32 flows to the LAN, sent twice, goes to one gateway both times",
		"flow %u did not", k - 1);
	ok = GatewayTestCheck(ctx, same && count[GATEWAY_GW1] != 0 && count[GATEWAY_GW2] != 0 && count[GATEWAY_GW3] != 0,
		"ECMP: the flows spread over the three gateways by their flow hash",
		"gw-1 took %u flows, gw-2 %u and gw-3 %u", count[GATEWAY_GW1], count[GATEWAY_GW2], count[GATEWAY_GW3]) && ok;
	Print("  ECMP: gw-1 %u flows, gw-2 %u, gw-3 %u\n", count[GATEWAY_GW1], count[GATEWAY_GW2], count[GATEWAY_GW3]);

	return ok;
}

// Whether node-a has its Noise session to the peer name up
static bool GatewaySessionUp(GATEWAYTEST_NODE *nodes, char *name)
{
	NODE_OVERLAY_SESSION list[GATEWAY_NUM_NODES];
	UINT num = NodeOverlayGetSessions(nodes[GATEWAY_A].Node, list, GATEWAY_NUM_NODES, NULL, 0);

	for (UINT i = 0;i < num && i < GATEWAY_NUM_NODES;i++)
	{
		if (StrCmp(list[i].Name, name) == 0)
		{
			return list[i].Up;
		}
	}

	return false;
}

// A reply from the LAN through the gateway via: its host sends a packet of the LAN host to node-a, and node-a takes it as it was
// sent. node-a's table leads the source to the group of the LAN, and the packet comes from the gateway of the group that sent it
// (NodeGatewayFrom).
static void GatewayReply(GATEWAYTEST_CTX *ctx, GATEWAYTEST_NODE *nodes, UINT via)
{
	GATEWAYTEST_TAKEN p;
	UCHAR want[GATEWAYTEST_PACKET];
	char what[MAX_SIZE];
	UINT marker = GatewayTestSend(ctx, &nodes[via], GATEWAY_VRF_ID, GATEWAY_LAN_HOST, gateway_addresses[GATEWAY_A], 53);
	UINT got = GatewayTestWhere(nodes, GATEWAY_NUM_NODES, marker, GATEWAYTEST_BOUND, &p);

	GatewayTestPacket(want, GATEWAY_LAN_HOST, gateway_addresses[GATEWAY_A], 53, marker);
	Format(what, sizeof(what), "A reply from the LAN comes back through %s: node-a takes it as it was sent, from the gateway of the group of the LAN that sent it", nodes[via].Name);
	GatewayTestCheck(ctx, marker != 0 && got == GATEWAY_A && p.Size == GATEWAYTEST_PACKET && Cmp(p.Data, want, GATEWAYTEST_PACKET) == 0 && p.VrfId == GATEWAY_VRF_ID, what,
		"taken by %s", GatewayTestName(nodes, GATEWAY_NUM_NODES, got));
}

// What node-a took from the wire w in Generation gen, through the decoder of the control module (ControlInput, ControlGateway.c):
// VRF branch with its hub node-h and corp with its ECMP as ecmp, each gateway reported down as the bit of down says, and the
// LAN subnets behind node-a, as GatewayState sent them
static void GatewayWireCheck(GATEWAYTEST_CTX *ctx, GATEWAYTEST_NODE *nodes, GATEWAYTEST_WIRE *w, UINT64 gen, bool ecmp, UINT down)
{
	char what[MAX_SIZE];
	UCHAR lan[4];
	IP ip6;

	bool vrfs = (w->NumVrfs == 2 && StrCmp(w->Vrfs[0].Name, GATEWAY_HUB_VRF) == 0 && StrCmp(w->Vrfs[0].Hub, GATEWAY_HUB) == 0 && w->Vrfs[0].Ecmp == false &&
		StrCmp(w->Vrfs[1].Name, GATEWAY_VRF) == 0 && IsEmptyStr(w->Vrfs[1].Hub) && w->Vrfs[1].Ecmp == ecmp);

	bool peers = (w->NumPeers == 3);
	for (UINT j = 0;peers && j < 3;j++)
	{
		peers = (StrCmp(w->Peers[j].Name, nodes[GATEWAY_GW1 + j].Name) == 0 && w->Peers[j].Down == ((down & (1U << (GATEWAY_GW1 + j))) != 0));
	}

	Zero(&ip6, sizeof(ip6));
	bool parsed = GatewayTestAddress(lan, GATEWAY_OWN_LAN) && StrToIP(&ip6, GATEWAY_OWN_LAN6);
	bool subnets = (parsed && w->NumLanSubnets == 2 && w->LanSubnets[0].VrfId == GATEWAY_VRF_ID && w->LanSubnets[0].AddressSize == 4 && Cmp(w->LanSubnets[0].Address, lan, 4) == 0 &&
		w->LanSubnets[0].Length == 24 && w->LanSubnets[1].VrfId == GATEWAY_VRF_ID && w->LanSubnets[1].AddressSize == 16 && Cmp(w->LanSubnets[1].Address, ip6.address, 16) == 0 &&
		w->LanSubnets[1].Length == 64);

	Format(what, sizeof(what), "Generation %I64u from the wire: the decoder gives node-a Vrf.hub, Vrf.ecmp, Peer.down and NodeConfig.lan_subnets as they were sent", gen);
	GatewayTestCheck(ctx, w->Generation == gen && vrfs && peers && subnets, what, "Generation %I64u; the VRFs %s, the peers %s, the LAN subnets %s (%u)", w->Generation,
		vrfs ? "as sent" : "not as sent", peers ? "as sent" : "not as sent", subnets ? "as sent" : "not as sent", w->NumLanSubnets);
}

// A dial that blocks (SDN-19-R1, #507). Generation *gen + 1 gives node-a the peer node-z, which it dials and cannot reach, and
// each dial holds the thread of the overlay of node-a for GATEWAY_STALL ms, back to back: the thread neither sends the probes
// that are due nor takes the answers that come meanwhile. The gateways answered: none goes down, and gw-1 keeps every flow,
// through GATEWAY_STALLS dials. gw-2 freezes while the dials go on, and the thread finds it down at its first look after the
// dial in which gw-2 stopped answering. Generation *gen + 2 takes node-z away, and gw-2 thaws and comes up again.
static void GatewayStall(GATEWAYTEST_CTX *ctx, GATEWAYTEST_NODE *nodes, GATEWAYTEST_NODE *z, UINT *want, UINT64 *gen)
{
	GATEWAYTEST_LINK *link = nodes[GATEWAY_A].Link;
	NODE_GATEWAY_STATUS before, after;
	char what[MAX_SIZE];
	UINT down = GATEWAYTEST_NONE, flows = 0, others = 0;

	NodeGatewayGetStatus(nodes[GATEWAY_A].Node, &before);
	LONG stalled = ReadAcquire(&link->Stalled);
	InterlockedExchange(&link->Stall, GATEWAY_STALL);

	Format(what, sizeof(what), "Generation %I64u: node-a gets the peer node-z, which it dials and cannot reach", *gen + 1);
	if (GatewayTestCheck(ctx, GatewayApply(nodes, ++*gen, false, 0, want, z, NULL), what, "not applied") == false)
	{
		InterlockedExchange(&link->Stall, 0);
		return;
	}

	// Each gateway is up at every look of the test, and each flow goes to gw-1, through GATEWAY_STALLS dials
	for (UINT64 end = Tick64() + GATEWAYTEST_BOUND + GATEWAY_STALLS * GATEWAY_STALL;Tick64() < end && ReadAcquire(&link->Stalled) < stalled + GATEWAY_STALLS;SleepThread(GATEWAYTEST_POLL))
	{
		for (UINT i = GATEWAY_GW1;i <= GATEWAY_GW3 && down == GATEWAYTEST_NONE;i++)
		{
			if (GatewayPeer(nodes, i).Up == false)
			{
				down = i;
			}
		}
		if (GatewayFlow(ctx, nodes, GATEWAYTEST_PORT) != GATEWAY_GW1)
		{
			others++;
		}
		flows++;
	}
	NodeGatewayGetStatus(nodes[GATEWAY_A].Node, &after);
	UINT dials = (UINT)(ReadAcquire(&link->Stalled) - stalled);

	Format(what, sizeof(what), "A dial that blocks: %u dials of node-a to node-z hold the thread of its overlay for %u ms each, back to back; no gateway goes down meanwhile, and gw-1 carries every flow",
		GATEWAY_STALLS, GATEWAY_STALL);
	GatewayTestCheck(ctx, dials >= GATEWAY_STALLS && down == GATEWAYTEST_NONE && flows != 0 && others == 0 && after.Failovers == before.Failovers, what,
		"%u dials held it, %s went down, %u of %u flows went elsewhere, %I64u times a gateway went down", dials, GatewayTestName(nodes, GATEWAY_NUM_NODES, down), others,
		flows, after.Failovers - before.Failovers);
	Print("  %u dials held the thread of node-a for %u ms each: it sent %I64u probes and took %I64u answers meanwhile\n", dials, GATEWAY_STALL, after.Probes - before.Probes,
		after.Answers - before.Answers);

	// gw-2 freezes while the dials go on: its last probe waits a whole dial for its answer
	UINT64 start = Tick64();
	InterlockedExchange(&nodes[GATEWAY_GW2].Link->Frozen, 1);
	UINT found = GatewayWaitPeer(nodes, GATEWAY_GW2, false, start);
	bool up = (GatewayPeer(nodes, GATEWAY_GW1).Up && GatewayPeer(nodes, GATEWAY_GW3).Up);
	Format(what, sizeof(what), "While the dials go on, gw-2 freezes: node-a finds it down at its first look after the dial in which gw-2 stopped answering, within %u ms, and gw-1 and gw-3 stay up",
		2 * GATEWAY_STALL + NODE_GATEWAY_PROBE);
	GatewayTestCheck(ctx, found <= 2 * GATEWAY_STALL + NODE_GATEWAY_PROBE && up, what, "found down after %u ms, gw-1 and gw-3 %s", found, up ? "up" : "not both up");
	Print("  gw-2 froze while the dials went on: found down after %u ms\n", found);

	// node-z goes, the dials stop, and gw-2 thaws
	InterlockedExchange(&link->Stall, 0);
	Format(what, sizeof(what), "Generation %I64u: node-z goes", *gen + 1);
	bool applied = GatewayTestCheck(ctx, GatewayApply(nodes, ++*gen, false, 0, want, NULL, NULL), what, "not applied");
	InterlockedExchange(&nodes[GATEWAY_GW2].Link->Frozen, 0);
	UINT back = GatewayWaitPeer(nodes, GATEWAY_GW2, true, Tick64());
	GatewayTestCheck(ctx, applied && back != INFINITE, "With node-z gone, gw-2 thaws and is up again", "not within %u ms", GATEWAYTEST_BOUND);
}

// The steps of the gateway test, with node-z, which node-a cannot reach, and the wire through which node-a takes some states
static void GatewayOverlay(GATEWAYTEST_CTX *ctx, GATEWAYTEST_NODE *nodes, GATEWAYTEST_NODE *z, GATEWAYTEST_WIRE *wire, TRANSPORT *loopback)
{
	// Every node of corp has a session to each of the other three
	UINT want[GATEWAY_NUM_NODES] = {3, 3, 3, 3};
	UINT flows[GATEWAYTEST_FLOWS];
	NODE_GATEWAY_STATUS gs;
	char what[MAX_SIZE];
	UINT to = GATEWAYTEST_NONE;
	UINT64 gen = 1;

	if (GatewayTestStart(ctx, nodes, GATEWAY_NUM_NODES, loopback, NULL, NULL) == false ||
		GatewayTestCheck(ctx, GatewayApply(nodes, gen, false, 0, want, NULL, NULL), "The four nodes of corp apply their states, and each has a session to the other three",
		"the states or the sessions did not come up") == false)
	{
		return;
	}

	// node-a probes the three gateways, and each answers
	bool up = true;
	for (UINT i = GATEWAY_GW1;i <= GATEWAY_GW3;i++)
	{
		up = (GatewayWaitPeer(nodes, i, true, Tick64()) != INFINITE) && up;
	}
	NodeGatewayGetStatus(nodes[GATEWAY_A].Node, &gs);
	GatewayTestCheck(ctx, up && gs.NumProbed == 3 && gs.NumUp == 3, "node-a probes the three gateways of the LAN, and all three are up",
		"%u probed, %u up", gs.NumProbed, gs.NumUp);
	for (UINT64 end = Tick64() + GATEWAYTEST_BOUND;Tick64() < end;SleepThread(GATEWAYTEST_POLL))
	{
		NodeGatewayGetStatus(nodes[GATEWAY_GW1].Node, &gs);
		if (gs.Answered != 0)
		{
			break;
		}
	}
	GatewayTestCheck(ctx, gs.Answered != 0 && gs.NumProbed == 0, "gw-1 answers the probes of node-a inside their Noise session, and probes no gateway: it announces the LAN itself",
		"it answered %I64u probes and probes %u gateways", gs.Answered, gs.NumProbed);

	// Standby: gw-1, the first in name order, carries every flow
	GatewayFlows(ctx, nodes, 4, GATEWAY_GW1, "Standby: gw-1, the first gateway in name order, carries every flow of node-a to the LAN as it was sent");

	// A dial that blocks holds the thread of the overlay of node-a, and no gateway that answered goes down (SDN-19-R1, #507)
	GatewayStall(ctx, nodes, z, want, &gen);

	// The controller's health data: gw-1 reported down gives its flows to gw-2; all three reported down leave the probes alone.
	// node-a takes these states from the wire.
	UINT all = (1U << GATEWAY_GW1) | (1U << GATEWAY_GW2) | (1U << GATEWAY_GW3);
	Format(what, sizeof(what), "Generation %I64u from the wire: the controller reports gw-1 down", gen + 1);
	if (GatewayTestCheck(ctx, GatewayApply(nodes, ++gen, false, 1U << GATEWAY_GW1, want, NULL, wire), what, "not applied"))
	{
		GatewayWireCheck(ctx, nodes, wire, gen, false, 1U << GATEWAY_GW1);
		GatewayFlows(ctx, nodes, 4, GATEWAY_GW2, "The controller's health data: with gw-1 reported down, gw-2 carries every flow, though gw-1 answers its probes");
		GatewayReply(ctx, nodes, GATEWAY_GW2);
	}
	Format(what, sizeof(what), "Generation %I64u from the wire: the controller reports all three gateways down", gen + 1);
	if (GatewayTestCheck(ctx, GatewayApply(nodes, ++gen, false, all, want, NULL, wire), what, "not applied"))
	{
		GatewayWireCheck(ctx, nodes, wire, gen, false, all);
		GatewayFlows(ctx, nodes, 4, GATEWAY_GW1, "With all three reported down the probes decide alone: gw-1, which answers them, carries every flow");
	}

	// ECMP: the flows spread over the three gateways, and a reply from the LAN comes back through each of them
	Format(what, sizeof(what), "Generation %I64u from the wire: corp spreads its flows over its gateways (ECMP)", gen + 1);
	if (GatewayTestCheck(ctx, GatewayApply(nodes, ++gen, true, 0, want, NULL, wire), what, "not applied") == false)
	{
		return;
	}
	GatewayWireCheck(ctx, nodes, wire, gen, true, 0);
	if (GatewayEcmp(ctx, nodes, flows) == false)
	{
		return;
	}
	for (UINT i = GATEWAY_GW1;i <= GATEWAY_GW3;i++)
	{
		GatewayReply(ctx, nodes, i);
	}

	// Silent failure: gw-1 freezes. Its session to node-a stays open; node-a finds it down with its probes in under a second, and
	// its flows move to the other two in that time
	UINT moved = GATEWAYTEST_FLOWS;
	for (UINT k = 0;k < GATEWAYTEST_FLOWS;k++)
	{
		if (flows[k] == GATEWAY_GW1)
		{
			moved = k;
			break;
		}
	}
	UINT64 start = Tick64();
	InterlockedExchange(&nodes[GATEWAY_GW1].Link->Frozen, 1);
	UINT failover = GatewayFailover(ctx, nodes, (USHORT)(GATEWAYTEST_PORT + moved), GATEWAY_GW1, start, &to);
	UINT found = GatewayWaitPeer(nodes, GATEWAY_GW1, false, start);
	bool open = GatewaySessionUp(nodes, "gw-1");
	Format(what, sizeof(what), "Silent failure: gw-1 freezes with its Noise session open; node-a finds it down with its probes in under %u ms", GATEWAYTEST_FAILOVER);
	GatewayTestCheck(ctx, found < GATEWAYTEST_FAILOVER && open, what, "found down after %u ms, the session %s", found, open ? "open" : "closed");
	Format(what, sizeof(what), "Silent failure: the flow of gw-1 moves to another gateway in under %u ms", GATEWAYTEST_FAILOVER);
	GatewayTestCheck(ctx, moved < GATEWAYTEST_FLOWS && failover < GATEWAYTEST_FAILOVER && (to == GATEWAY_GW2 || to == GATEWAY_GW3), what,
		"%u ms, to %s", failover, GatewayTestName(nodes, GATEWAY_NUM_NODES, to));
	Print("  silent failure of gw-1: found down after %u ms, its flow moved after %u ms\n", found, failover);

	// Only the flows of gw-1 move: the others keep their gateway
	UINT k;
	UINT got = GATEWAYTEST_NONE;
	for (k = 0;k < GATEWAYTEST_FLOWS;k++)
	{
		got = GatewayFlow(ctx, nodes, (USHORT)(GATEWAYTEST_PORT + k));
		if ((flows[k] == GATEWAY_GW1 && got != GATEWAY_GW2 && got != GATEWAY_GW3) || (flows[k] != GATEWAY_GW1 && got != flows[k]))
		{
			break;
		}
	}
	GatewayTestCheck(ctx, k == GATEWAYTEST_FLOWS, "With gw-1 down, its flows go to gw-2 and gw-3 and every other flow keeps its gateway",
		"flow %u of %s went to %s", k, GatewayTestName(nodes, GATEWAY_NUM_NODES, k < GATEWAYTEST_FLOWS ? flows[k] : GATEWAYTEST_NONE),
		GatewayTestName(nodes, GATEWAY_NUM_NODES, got));

	// Stop: with ECMP off gw-2 carries every flow, gw-1 being down; its overlay stops, and the traffic moves to gw-3 within the
	// probe interval, as its Noise session closes
	Format(what, sizeof(what), "Generation %I64u: ECMP off, gw-1 still frozen", gen + 1);
	if (GatewayTestCheck(ctx, GatewayApply(nodes, ++gen, false, 0, want, NULL, NULL), what, "not applied") == false)
	{
		return;
	}
	GatewayFlows(ctx, nodes, 4, GATEWAY_GW2, "With gw-1 down and ECMP off, gw-2 carries every flow");
	start = Tick64();
	NodeOverlayStop(nodes[GATEWAY_GW2].Node);
	failover = GatewayFailover(ctx, nodes, GATEWAYTEST_PORT, GATEWAY_GW2, start, &to);
	Format(what, sizeof(what), "Stop: the overlay of gw-2 stops, and its traffic moves to gw-3 within %u ms, the probe interval: its Noise session closes, so it is down at once",
		NODE_GATEWAY_PROBE);
	GatewayTestCheck(ctx, failover <= NODE_GATEWAY_PROBE && to == GATEWAY_GW3, what, "%u ms, to %s", failover, GatewayTestName(nodes, GATEWAY_NUM_NODES, to));
	Print("  stop of gw-2: its traffic moved after %u ms\n", failover);
	want[GATEWAY_GW2] = GATEWAYTEST_NONE;

	// Recovery: gw-1 thaws and answers at once the probes that waited for it while it was frozen, which bring it up no more; it
	// is up again once it answered fresh probes in a row, which node-a sent after it answered again: two probe intervals at
	// least (SDN-19-R1, #507). Then it carries the flows again.
	NodeGatewayGetStatus(nodes[GATEWAY_A].Node, &gs);
	UINT64 answers = gs.Answers;
	start = Tick64();
	InterlockedExchange(&nodes[GATEWAY_GW1].Link->Frozen, 0);
	UINT back = GatewayWaitPeer(nodes, GATEWAY_GW1, true, start);
	NodeGatewayGetStatus(nodes[GATEWAY_A].Node, &gs);
	Format(what, sizeof(what), "Recovery: gw-1 thaws and answers the probes that waited for it, and is up again only after %u answers in a row to fresh probes, in %u ms or more: two probe intervals",
		NODE_GATEWAY_RISE, 2 * NODE_GATEWAY_PROBE);
	GatewayTestCheck(ctx, back != INFINITE && back >= 2 * NODE_GATEWAY_PROBE, what, "up again after %u ms", back);
	Print("  recovery of gw-1: up again after %u ms; node-a took %I64u answers of it meanwhile\n", back, gs.Answers - answers);
	GatewayFlows(ctx, nodes, 4, GATEWAY_GW1, "With gw-1 up again, it carries every flow");

	// Standby: with ECMP off gw-1 carries every flow and gw-3 stands by, gw-2 being stopped. gw-1 freezes again with its Noise
	// session open; node-a finds it down with its probes in under a second, and the traffic moves to gw-3, the standby gateway,
	// within that time (#195). gw-1 thaws again afterwards.
	start = Tick64();
	InterlockedExchange(&nodes[GATEWAY_GW1].Link->Frozen, 1);
	failover = GatewayFailover(ctx, nodes, GATEWAYTEST_PORT, GATEWAY_GW1, start, &to);
	found = GatewayWaitPeer(nodes, GATEWAY_GW1, false, start);
	open = GatewaySessionUp(nodes, "gw-1");
	InterlockedExchange(&nodes[GATEWAY_GW1].Link->Frozen, 0);
	Format(what, sizeof(what), "Standby: gw-1 freezes again with its Noise session open; node-a finds it down with its probes in under %u ms", GATEWAYTEST_FAILOVER);
	GatewayTestCheck(ctx, found < GATEWAYTEST_FAILOVER && open, what, "found down after %u ms, the session %s", found, open ? "open" : "closed");
	Format(what, sizeof(what), "Standby: the traffic of gw-1 moves to gw-3, the standby gateway, in under %u ms", GATEWAYTEST_FAILOVER);
	GatewayTestCheck(ctx, failover < GATEWAYTEST_FAILOVER && to == GATEWAY_GW3, what, "%u ms, to %s", failover, GatewayTestName(nodes, GATEWAY_NUM_NODES, to));
	Print("  standby failover from gw-1: found down after %u ms, its traffic moved to gw-3 after %u ms\n", found, failover);

	NodeGatewayGetStatus(nodes[GATEWAY_A].Node, &gs);
	GatewayTestCheck(ctx, gs.Failovers >= 2 && gs.Recoveries >= 1 && gs.Probes != 0 && gs.Answers != 0,
		"node-a counts the gateways that went down and came up again", "%I64u down, %I64u up again", gs.Failovers, gs.Recoveries);
	Print("  node-a: %I64u probes, %I64u answers, %I64u gateways down, %I64u up again\n", gs.Probes, gs.Answers, gs.Failovers, gs.Recoveries);
}

// gateway: gateway HA in the data plane
RANZ_TEST("gateway", gateway_test, "Gateway HA: of three gateways of one LAN the first stands in for all, the controller's health data moves it, ECMP spreads the flows by their hash, the replies of the LAN come back through each, a gateway that goes silent is found by the probes inside its Noise session and left in under a second, a stopped one at once, one that answers again comes back after fresh probes, and a dial that blocks the thread of the overlay downs none that answered. Some states come from the wire, through the decoder of the control module.");
void gateway_test(UINT num, char **arg)
{
	GATEWAYTEST_CTX ctx;
	GATEWAYTEST_WATCH watch;
	GATEWAYTEST_NODE *nodes = ZeroMalloc(sizeof(GATEWAYTEST_NODE) * GATEWAY_NUM_NODES);
	GATEWAYTEST_NODE *z = ZeroMalloc(sizeof(GATEWAYTEST_NODE));
	GATEWAYTEST_WIRE *wire = NULL;
	// Bound: the records go in clear, so a stream that drops what it writes while frozen keeps its session after it thaws
	TRANSPORT *loopback = TransportLoopbackNew("loopback", 0, true);
	HANDLE watchdog;

	Zero(&ctx, sizeof(ctx));
	watch.Done = CreateEventW(NULL, TRUE, FALSE, NULL);
	watch.Name = "GATEWAY";
	watchdog = (watch.Done != NULL ? CreateThread(NULL, 0, GatewayTestWatchdog, &watch, 0, NULL) : NULL);

	Print("GATEWAY test: gateway HA of the node's data plane over the overlay of in-process nodes\n");

	bool keys = GatewayTestKeys(nodes, GATEWAY_NUM_NODES, gateway_names, gateway_addresses, 11);
	keys = GatewayUnreachable(z, &nodes[GATEWAY_A]) && keys;
	keys = GatewayTestCheck(&ctx, keys, "The static keys of the four nodes, and of node-z above the one of node-a", "PeerKeyFromScalar failed");
	// node-a takes some of its states from the wire, through the decoder of the control module
	wire = (keys ? GatewayTestNewWire(&nodes[GATEWAY_A]) : NULL);
	if (keys && GatewayTestCheck(&ctx, wire != NULL, "A client of the control module without its thread decodes the states of node-a from the wire", "ControlNew failed"))
	{
		GatewayOverlay(&ctx, nodes, z, wire, loopback);
	}

	for (UINT i = 0;i < GATEWAY_NUM_NODES;i++)
	{
		NODE_OVERLAY_STATUS st;

		if (nodes[i].Node != NULL)
		{
			NodeOverlayGetStatus(nodes[i].Node, &st);
			Print("  %s: forwarded %I64u, delivered %I64u, dropped %I64u, dials %I64u\n", nodes[i].Name, st.Forwarded, st.Delivered, st.Dropped, st.Dials);
		}
	}

	GatewayTestFree(nodes, GATEWAY_NUM_NODES);
	GatewayTestFree(z, 1);
	GatewayTestFreeWire(wire);
	TransportLoopbackFree(loopback);
	Free(nodes);
	Free(z);

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
		Print("GATEWAY TEST OK\n");
	}
	else
	{
		Print("GATEWAY TEST FAILED (%u of %u checks failed)\n", ctx.NumFailed, ctx.NumChecks);
	}
}

//
// hubspoke
//

#define	HUBSPOKE_H				0
#define	HUBSPOKE_A				1
#define	HUBSPOKE_B				2
#define	HUBSPOKE_C				3
#define	HUBSPOKE_NUM_NODES		4
#define	HUBSPOKE_VRF_ID			20
#define	HUBSPOKE_VRF			"branch"
#define	HUBSPOKE_POOL			"10.20.0.0"
#define	HUBSPOKE_LAN			"192.168.9.0"
#define	HUBSPOKE_LAN_HOST		"192.168.9.5"
#define	HUBSPOKE_COPY			(VXLAN_HEADER_SIZE + NODE_MIRROR_ETHER + GATEWAYTEST_PACKET)	// The datagram of the copy of a test packet
#define	HUBSPOKE_DRAIN			100			// The datagrams that the sensor reads at most before a packet is sent

// The policy of branch in a Generation (SDN-19-R2, #508)
#define	HUBSPOKE_NO_POLICY		0			// None: branch forwards as the starter rule does
#define	HUBSPOKE_TWO_RULES		1			// branch-to-hub and hub-to-branch alone, under the default deny of branch
#define	HUBSPOKE_TAG_RULE		2			// ... and site-a-to-site-b, from the tag site-a to the tag site-b
#define	HUBSPOKE_PREFIX_RULE	3			// ... and a-to-lan-b, from the address of node-a to the LAN behind node-b, in its place

static char *hubspoke_names[HUBSPOKE_NUM_NODES] = {"node-h", "node-a", "node-b", "node-c"};
static char *hubspoke_addresses[HUBSPOKE_NUM_NODES] = {"10.20.0.1", "10.20.0.2", "10.20.0.3", "10.20.0.4"};

// The sensor of the Mirror of node-h: a UDP socket on 127.0.0.1 and a port that the system picks, and the datagram that it
// read last
typedef struct HUBSPOKE_SENSOR
{
	SOCKET Socket;
	USHORT Port;
	UCHAR Datagram[VXLAN_MAX_DATAGRAM + 1];
} HUBSPOKE_SENSOR;

// Open the sensor t: false when its socket could not be bound
static bool HubSpokeOpenSensor(HUBSPOKE_SENSOR *t)
{
	struct sockaddr_in sa;
	int sa_size = sizeof(sa);

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

	t->Port = ntohs(sa.sin_port);

	return true;
}

// The next datagram that the sensor t reads within timeout ms, into its Datagram: its size, 0 for none
static UINT HubSpokeRead(HUBSPOKE_SENSOR *t, UINT timeout)
{
	WSAPOLLFD p;

	Zero(&p, sizeof(p));
	p.fd = t->Socket;
	p.events = POLLRDNORM;
	if (t->Socket == INVALID_SOCKET || WSAPoll(&p, 1, (INT)timeout) != 1)
	{
		return 0;
	}

	int n = recv(t->Socket, (char *)t->Datagram, (int)sizeof(t->Datagram), 0);

	return (n > 0 ? (UINT)n : 0);
}

// Read what the sensor t holds now: the copies of the packets that the host of node-h sent or took before
static void HubSpokeDrain(HUBSPOKE_SENSOR *t)
{
	UINT n = 0;

	while (n < HUBSPOKE_DRAIN && HubSpokeRead(t, 0) != 0)
	{
		n++;
	}
}

// Whether the datagram of size bytes that the sensor t read last is the copy of the test packet packet on the VNI of the VRF
// id of branch: the VXLAN header with the I flag, an Ethernet header, then the packet as it was sent
static bool HubSpokeCopyOf(HUBSPOKE_SENSOR *t, UINT size, const UCHAR *packet)
{
	const UCHAR *d = t->Datagram;
	UINT vni = ((UINT)d[4] << 16) | ((UINT)d[5] << 8) | (UINT)d[6];

	return (size == HUBSPOKE_COPY && d[0] == 0x08 && vni == HUBSPOKE_VRF_ID &&
		Cmp(d + VXLAN_HEADER_SIZE + NODE_MIRROR_ETHER, packet, GATEWAYTEST_PACKET) == 0);
}

// The tags of node i into tags, sorted, which identify it to the rules of branch: hub for node-h, branch for a spoke, and site-a
// and site-b for node-a and node-b. Their number.
static UINT HubSpokeTags(UINT i, char (*tags)[CONTROL_NAME_SIZE])
{
	UINT num = 0;

	StrCpy(tags[num++], CONTROL_NAME_SIZE, i == HUBSPOKE_H ? "hub" : "branch");
	if (i == HUBSPOKE_A || i == HUBSPOKE_B)
	{
		StrCpy(tags[num++], CONTROL_NAME_SIZE, i == HUBSPOKE_A ? "site-a" : "site-b");
	}

	return num;
}

// A rule of branch in the state st, of the name name and the default priority, which allows the flows that it matches
static CONTROL_RULE *HubSpokeRule(CONTROL_STATE *st, char *name)
{
	CONTROL_RULE *r = &st->Rules[st->NumRules++];

	StrCpy(r->Name, sizeof(r->Name), name);
	r->VrfId = HUBSPOKE_VRF_ID;
	r->Priority = 1000;

	return r;
}

// A tag of an end of a rule
static void HubSpokeRuleTag(CONTROL_RULE_END *e, char *tag)
{
	StrCpy(e->Tags[e->NumTags], sizeof(e->Tags[e->NumTags]), tag);
	e->NumTags++;
}

// An IPv4 prefix of an end of a rule
static void HubSpokeRulePrefix(CONTROL_RULE_END *e, char *address, UINT length)
{
	CONTROL_PREFIX *p = &e->Prefixes[e->NumPrefixes++];

	p->AddressSize = (GatewayTestAddress(p->Address, address) ? 4 : 0);
	p->Length = length;
}

// The rules of branch that node i enforces under the policy policy, in name order, as the controller compiles them
// (controller/internal/desired/policy.go): branch-to-hub and hub-to-branch for every node, as one end of each names a tag of
// it; site-a-to-site-b for node-a and node-b, whose tags its ends name, and for node-h, the hub, which gets every rule of its
// VRF as it judges the flows between two spokes (SDN-19-R2, #508), but not for node-c; a-to-lan-b, whose ends name no tag,
// for every node.
static void HubSpokeRules(CONTROL_STATE *st, UINT i, UINT policy)
{
	CONTROL_RULE *r;

	st->Rules = ZeroMalloc(sizeof(CONTROL_RULE) * 3);

	if (policy == HUBSPOKE_PREFIX_RULE)
	{
		r = HubSpokeRule(st, "a-to-lan-b");
		HubSpokeRulePrefix(&r->From, hubspoke_addresses[HUBSPOKE_A], 32);
		HubSpokeRulePrefix(&r->To, HUBSPOKE_LAN, 24);
	}

	r = HubSpokeRule(st, "branch-to-hub");
	HubSpokeRuleTag(&r->From, "branch");
	HubSpokeRuleTag(&r->To, "hub");

	r = HubSpokeRule(st, "hub-to-branch");
	HubSpokeRuleTag(&r->From, "hub");
	HubSpokeRuleTag(&r->To, "branch");

	if (policy == HUBSPOKE_TAG_RULE && i != HUBSPOKE_C)
	{
		r = HubSpokeRule(st, "site-a-to-site-b");
		HubSpokeRuleTag(&r->From, "site-a");
		HubSpokeRuleTag(&r->To, "site-b");
	}
}

// The state of node i at generation gen, as the controller compiles it for VRF branch of topology hub-and-spoke with the hub
// node-h; with hub not set, the state of node-h names no hub. node-h has the spokes as its peers, node-b with its LAN as its
// route; each spoke has node-h as its only peer, with the pool of the VRF and the LAN subnets of the other nodes as routes of
// node-h. node-b has its LAN as a LAN subnet of its own. node-h has a Mirror of every packet of the VRF to the sensor on
// 127.0.0.1 and the port sensor, on the VNI of the VRF id. Under a policy other than HUBSPOKE_NO_POLICY, branch has its
// policy and its rules (HubSpokeRules). Each node and each Peer has its tags. With moved, the state of node-h is the one of a
// Generation in which the LAN moved from node-b to node-a: node-a has it as its route there, and the other states stay as
// they were.
static CONTROL_STATE *HubSpokeState(GATEWAYTEST_NODE *nodes, UINT i, UINT64 gen, bool hub, UINT policy, USHORT sensor, bool moved)
{
	CONTROL_STATE *st = GatewayTestState(&nodes[i], gen, HUBSPOKE_VRF_ID, HUBSPOKE_VRF, (i != HUBSPOKE_H || hub) ? "node-h" : NULL, false, HUBSPOKE_NUM_NODES);

	st->NumTags = HubSpokeTags(i, st->Tags);
	if (policy != HUBSPOKE_NO_POLICY)
	{
		st->Vrfs[0].Policy = true;
		HubSpokeRules(st, i, policy);
	}

	if (i == HUBSPOKE_H)
	{
		CONTROL_MIRROR *m = &st->Mirrors[st->NumMirrors++];

		StrCpy(m->Name, sizeof(m->Name), "inspect");
		m->VrfId = HUBSPOKE_VRF_ID;
		m->SensorSize = (GatewayTestAddress(m->Sensor, "127.0.0.1") ? 4 : 0);
		m->SensorPort = sensor;

		for (UINT j = HUBSPOKE_A;j < HUBSPOKE_NUM_NODES;j++)
		{
			CONTROL_PEER *p = GatewayTestPeer(st, &nodes[j], HUBSPOKE_VRF_ID, HUBSPOKE_VRF);

			p->NumTags = HubSpokeTags(j, p->Tags);
			if (j == (moved ? HUBSPOKE_A : HUBSPOKE_B))
			{
				GatewayTestRoute(st, p, HUBSPOKE_VRF_ID, HUBSPOKE_LAN, 24);
			}
		}
		return st;
	}

	CONTROL_PEER *h = GatewayTestPeer(st, &nodes[HUBSPOKE_H], HUBSPOKE_VRF_ID, HUBSPOKE_VRF);
	h->NumTags = HubSpokeTags(HUBSPOKE_H, h->Tags);
	GatewayTestRoute(st, h, HUBSPOKE_VRF_ID, HUBSPOKE_POOL, 24);
	if (i != HUBSPOKE_B)
	{
		GatewayTestRoute(st, h, HUBSPOKE_VRF_ID, HUBSPOKE_LAN, 24);
	}
	else
	{
		GatewayTestRoute(st, NULL, HUBSPOKE_VRF_ID, HUBSPOKE_LAN, 24);
	}

	return st;
}

// Apply the states of a Generation to the four nodes, under the policy policy of branch, with the Mirror of node-h to the sensor
// on the port sensor, and, with moved, the LAN behind node-b moved to node-a in the state of node-h; and wait until each runs it
// with its sessions
static bool HubSpokeApply(GATEWAYTEST_NODE *nodes, UINT64 gen, bool hub, UINT policy, USHORT sensor, bool moved)
{
	// node-h has a session to each spoke, a spoke to node-h alone
	UINT want[HUBSPOKE_NUM_NODES] = {3, 1, 1, 1};
	bool applied = true;

	for (UINT i = 0;i < HUBSPOKE_NUM_NODES;i++)
	{
		CONTROL_STATE *st = HubSpokeState(nodes, i, gen, hub, policy, sensor, moved);

		applied = NodeOverlayApply(nodes[i].Node, st) && applied;
		GatewayTestFreeState(st);
	}

	return applied && GatewayTestWaitApplied(nodes, HUBSPOKE_NUM_NODES, gen, want, NULL);
}

// The packets that the hub sent on from one spoke to another
static UINT64 HubSpokeTransit(GATEWAYTEST_NODE *nodes)
{
	NODE_GATEWAY_STATUS st;

	NodeGatewayGetStatus(nodes[HUBSPOKE_H].Node, &st);

	return st.Transit;
}

// The packets that the hub sent on from one spoke to another and the packets that it dropped since transit_before and
// dropped_before, once they reach want_transit and want_dropped or GATEWAYTEST_BOUND ms passed. The hub counts a packet on the
// thread that took it from the spoke, after it sent it on (NodeGatewayTransit) or dropped it, so the other spoke can take the
// packet before the hub counted it.
static void HubSpokeCounts(GATEWAYTEST_NODE *nodes, UINT64 transit_before, UINT64 dropped_before, UINT64 want_transit, UINT64 want_dropped,
	UINT64 *transit, UINT64 *dropped)
{
	for (UINT64 end = Tick64() + GATEWAYTEST_BOUND;;)
	{
		NODE_OVERLAY_STATUS hub;

		NodeOverlayGetStatus(nodes[HUBSPOKE_H].Node, &hub);
		*transit = HubSpokeTransit(nodes) - transit_before;
		*dropped = hub.Dropped - dropped_before;

		if ((*transit >= want_transit && *dropped >= want_dropped) || Tick64() >= end)
		{
			return;
		}
		SleepThread(GATEWAYTEST_POLL);
	}
}

// One packet of the host of from, from src to dst: it reaches the host of to as it was sent, and when via_hub is set the hub
// sent it on and its Mirror copied it to the sensor as it was sent; with to GATEWAYTEST_NONE, no host takes it, the hub drops
// it and its Mirror copies nothing
static void HubSpokeSend(GATEWAYTEST_CTX *ctx, GATEWAYTEST_NODE *nodes, HUBSPOKE_SENSOR *sensor, UINT from, char *src, char *dst, UINT to, bool via_hub)
{
	GATEWAYTEST_TAKEN p;
	UCHAR want[GATEWAYTEST_PACKET];
	NODE_OVERLAY_STATUS hub;
	char what[MAX_SIZE];

	HubSpokeDrain(sensor);
	NodeOverlayGetStatus(nodes[HUBSPOKE_H].Node, &hub);
	UINT64 transit_before = HubSpokeTransit(nodes);
	UINT64 dropped_before = hub.Dropped;
	UINT marker = GatewayTestSend(ctx, &nodes[from], HUBSPOKE_VRF_ID, src, dst, GATEWAYTEST_PORT);
	UINT got = GatewayTestWhere(nodes, HUBSPOKE_NUM_NODES, marker, to == GATEWAYTEST_NONE ? GATEWAYTEST_QUIET : GATEWAYTEST_BOUND, &p);
	UINT64 transit, dropped;

	// The hub counts the packet after it sent it on or dropped it: wait for its counters
	HubSpokeCounts(nodes, transit_before, dropped_before, via_hub ? 1 : 0, to == GATEWAYTEST_NONE ? 1 : 0, &transit, &dropped);
	GatewayTestPacket(want, src, dst, GATEWAYTEST_PORT, marker);

	if (to == GATEWAYTEST_NONE)
	{
		UINT copy = HubSpokeRead(sensor, GATEWAYTEST_POLL);

		Format(what, sizeof(what), "%s sends %s > %s; node-h, which is no hub in its state, drops it, and its Mirror copies nothing", nodes[from].Name, src, dst);
		GatewayTestCheck(ctx, marker != 0 && got == GATEWAYTEST_NONE && transit == 0 && dropped != 0 && copy == 0, what,
			"taken by %s, %I64u sent on, %I64u dropped, the sensor read %u bytes", GatewayTestName(nodes, HUBSPOKE_NUM_NODES, got), transit,
			dropped, copy);
		return;
	}

	Format(what, sizeof(what), "%s sends %s > %s; %s takes it as it was sent, %s", nodes[from].Name, src, dst, nodes[to].Name,
		via_hub ? "and node-h, the hub, sent it on" : "and the hub sent nothing on");
	GatewayTestCheck(ctx, marker != 0 && got == to && p.Size == GATEWAYTEST_PACKET && Cmp(p.Data, want, GATEWAYTEST_PACKET) == 0 &&
		p.VrfId == HUBSPOKE_VRF_ID && transit == (via_hub ? 1 : 0), what,
		"taken by %s, %I64u sent on by the hub", GatewayTestName(nodes, HUBSPOKE_NUM_NODES, got), transit);

	// What the hub sends on from one spoke to another, its Mirror copies (ADR-0029 decision 8)
	if (via_hub)
	{
		UINT copy = HubSpokeRead(sensor, GATEWAYTEST_BOUND);

		Format(what, sizeof(what), "%s sends %s > %s; the Mirror of %s at node-h copies it to its sensor as it was sent, on VNI %u", nodes[from].Name, src, dst,
			HUBSPOKE_VRF, HUBSPOKE_VRF_ID);
		GatewayTestCheck(ctx, marker != 0 && HubSpokeCopyOf(sensor, copy, want), what, "the sensor read %u bytes", copy);
	}
}

// The packets that the policy of node i dropped, of any VRF (NodePolicyGetVrf): 0 while the rules in force there hold no VRF
// branch
static UINT64 HubSpokePolicyDrops(GATEWAYTEST_NODE *nodes, UINT i)
{
	NODE_POLICY_VRF_STATUS st;

	return (NodePolicyGetVrf(nodes[i].Node, HUBSPOKE_VRF, &st) ? st.Dropped : 0);
}

// One packet of the host of the spoke from, from src and the port sport to dst and the port dport, which the forwarding table
// of the spoke leads to node-h, under the policy of branch; why names the rule that decides it at node-h. With to a node: the
// host of to takes it as it was sent, node-h let it through by its policy and sent it on, and its Mirror copied it as it was
// sent. With to GATEWAYTEST_NONE: the spoke sent it to node-h, which dropped it by its policy and counted it with the drops of
// its policy; no host takes it, node-h sent nothing on and its Mirror copied nothing.
static void HubSpokeJudged(GATEWAYTEST_CTX *ctx, GATEWAYTEST_NODE *nodes, HUBSPOKE_SENSOR *sensor, UINT from, char *src, USHORT sport, char *dst,
	USHORT dport, UINT to, char *why)
{
	GATEWAYTEST_TAKEN p;
	UCHAR packet[GATEWAYTEST_PACKET];
	NODE_OVERLAY_STATUS st;
	char what[MAX_SIZE];
	UINT64 transit, dropped;

	HubSpokeDrain(sensor);
	NodeOverlayGetStatus(nodes[from].Node, &st);
	UINT64 forwarded_before = st.Forwarded;
	NodeOverlayGetStatus(nodes[HUBSPOKE_H].Node, &st);
	UINT64 dropped_before = st.Dropped;
	UINT64 transit_before = HubSpokeTransit(nodes);
	UINT64 policy_before = HubSpokePolicyDrops(nodes, HUBSPOKE_H);
	UINT marker = ++ctx->Marker;
	UINT size = GatewayTestDatagram(packet, src, dst, sport, dport, marker);

	if (size != 0)
	{
		NodeReaderOnline(nodes[from].Node, &nodes[from].Reader);
		NodeOverlayInput(nodes[from].Node, HUBSPOKE_VRF_ID, packet, size);
		NodeReaderOffline(&nodes[from].Reader);
	}

	UINT got = GatewayTestWhere(nodes, HUBSPOKE_NUM_NODES, marker, to == GATEWAYTEST_NONE ? GATEWAYTEST_QUIET : GATEWAYTEST_BOUND, &p);

	// The hub counts the packet after it sent it on or dropped it, and the drop of its policy before the drop of its overlay:
	// wait for its counters
	HubSpokeCounts(nodes, transit_before, dropped_before, to == GATEWAYTEST_NONE ? 0 : 1, to == GATEWAYTEST_NONE ? 1 : 0, &transit, &dropped);
	UINT64 policy = HubSpokePolicyDrops(nodes, HUBSPOKE_H) - policy_before;
	NodeOverlayGetStatus(nodes[from].Node, &st);
	UINT64 forwarded = st.Forwarded - forwarded_before;

	if (to == GATEWAYTEST_NONE)
	{
		UINT copy = HubSpokeRead(sensor, GATEWAYTEST_POLL);

		Format(what, sizeof(what), "%s: %s sends %s:%u > %s:%u to node-h, which drops it by the policy of %s and counts it with the drops of its policy; no host takes it, and the Mirror of node-h copies nothing",
			why, nodes[from].Name, src, (UINT)sport, dst, (UINT)dport, HUBSPOKE_VRF);
		GatewayTestCheck(ctx, size != 0 && forwarded == 1 && got == GATEWAYTEST_NONE && transit == 0 && policy == 1 && copy == 0, what,
			"%s sent %I64u packets to node-h, taken by %s, %I64u sent on by node-h, %I64u dropped by its policy, the sensor read %u bytes",
			nodes[from].Name, forwarded, GatewayTestName(nodes, HUBSPOKE_NUM_NODES, got), transit, policy, copy);
		return;
	}

	Format(what, sizeof(what), "%s: %s sends %s:%u > %s:%u; node-h lets it through by the policy of %s and sends it on, and %s takes it as it was sent",
		why, nodes[from].Name, src, (UINT)sport, dst, (UINT)dport, HUBSPOKE_VRF, nodes[to].Name);
	GatewayTestCheck(ctx, size != 0 && got == to && p.Size == GATEWAYTEST_PACKET && Cmp(p.Data, packet, GATEWAYTEST_PACKET) == 0 &&
		p.VrfId == HUBSPOKE_VRF_ID && transit == 1 && policy == 0, what, "taken by %s, %I64u sent on by node-h, %I64u dropped by its policy",
		GatewayTestName(nodes, HUBSPOKE_NUM_NODES, got), transit, policy);

	// The Mirror of the VRF at the hub sees what the policy let through
	UINT copy = HubSpokeRead(sensor, GATEWAYTEST_BOUND);

	Format(what, sizeof(what), "%s: the Mirror of %s at node-h copies %s:%u > %s:%u to its sensor as it was sent, as the policy let it through",
		why, HUBSPOKE_VRF, src, (UINT)sport, dst, (UINT)dport);
	GatewayTestCheck(ctx, size != 0 && HubSpokeCopyOf(sensor, copy, packet), what, "the sensor read %u bytes", copy);
}

// The policy of branch decides at node-h, the hub, what one spoke sends another (SDN-19-R2, #508), by the rules of branch with
// the spoke that sent a packet and the spoke of its next hop as its two ends, which only the hub sees. The packets of one
// Generation that must be the first of their flow at node-h come from a source port of their own.
static void HubSpokePolicy(GATEWAYTEST_CTX *ctx, GATEWAYTEST_NODE *nodes, HUBSPOKE_SENSOR *sensor)
{
	char *h = hubspoke_addresses[HUBSPOKE_H];
	char *a = hubspoke_addresses[HUBSPOKE_A];
	char *b = hubspoke_addresses[HUBSPOKE_B];
	char *c = hubspoke_addresses[HUBSPOKE_C];
	USHORT port = GATEWAYTEST_PORT;

	// The usual two rules alone: each spoke reaches the hub and the hub each spoke, and no rule lets one spoke reach another
	if (GatewayTestCheck(ctx, HubSpokeApply(nodes, 3, true, HUBSPOKE_TWO_RULES, sensor->Port, false),
		"Generation 3: branch has its policy, with branch-to-hub and hub-to-branch and no rule between two spokes", "not applied"))
	{
		HubSpokeSend(ctx, nodes, sensor, HUBSPOKE_A, a, h, HUBSPOKE_H, false);
		HubSpokeSend(ctx, nodes, sensor, HUBSPOKE_H, h, b, HUBSPOKE_B, false);
		HubSpokeJudged(ctx, nodes, sensor, HUBSPOKE_A, a, port, b, 53, GATEWAYTEST_NONE, "No rule between two spokes");
		HubSpokeJudged(ctx, nodes, sensor, HUBSPOKE_A, a, port, HUBSPOKE_LAN_HOST, 53, GATEWAYTEST_NONE, "No rule between two spokes, to the LAN behind node-b");
	}

	// A rule from the tag of node-a to the tag of node-b: the tags of the Peer that sent a packet and of the Peer of its next hop
	// decide at the hub
	if (GatewayTestCheck(ctx, HubSpokeApply(nodes, 4, true, HUBSPOKE_TAG_RULE, sensor->Port, false),
		"Generation 4: and site-a-to-site-b, from the tag site-a of node-a to the tag site-b of node-b", "not applied"))
	{
		HubSpokeJudged(ctx, nodes, sensor, HUBSPOKE_A, a, port, b, 53, HUBSPOKE_B, "site-a-to-site-b");
		HubSpokeJudged(ctx, nodes, sensor, HUBSPOKE_B, b, 53, a, port, HUBSPOKE_A, "The reply on the flow that site-a-to-site-b allowed");
		HubSpokeJudged(ctx, nodes, sensor, HUBSPOKE_A, a, port, HUBSPOKE_LAN_HOST, 53, HUBSPOKE_B, "site-a-to-site-b, to the LAN behind node-b, the Peer of its next hop");
		HubSpokeJudged(ctx, nodes, sensor, HUBSPOKE_C, c, port, b, 53, GATEWAYTEST_NONE, "site-a-to-site-b, from node-c, which has no tag site-a");
		HubSpokeJudged(ctx, nodes, sensor, HUBSPOKE_A, a, port, c, 53, GATEWAYTEST_NONE, "site-a-to-site-b, to node-c, which has no tag site-b");
	}

	// A rule from the address of node-a to the LAN behind node-b in its place: the addresses of the packet that the Peer sent decide
	// at the hub. The flow that the tag rule allowed ends at the hub when the next packet of node-a meets the rules without it.
	port++;
	if (GatewayTestCheck(ctx, HubSpokeApply(nodes, 5, true, HUBSPOKE_PREFIX_RULE, sensor->Port, false),
		"Generation 5: a-to-lan-b, from the address of node-a to the LAN behind node-b, in place of site-a-to-site-b", "not applied"))
	{
		HubSpokeJudged(ctx, nodes, sensor, HUBSPOKE_A, a, port, HUBSPOKE_LAN_HOST, 53, HUBSPOKE_B, "a-to-lan-b");
		HubSpokeJudged(ctx, nodes, sensor, HUBSPOKE_C, c, port, HUBSPOKE_LAN_HOST, 53, GATEWAYTEST_NONE, "a-to-lan-b, from node-c, whose address it does not name");
		HubSpokeJudged(ctx, nodes, sensor, HUBSPOKE_A, a, port, c, 53, GATEWAYTEST_NONE, "a-to-lan-b, to node-c, outside the LAN behind node-b");
		HubSpokeJudged(ctx, nodes, sensor, HUBSPOKE_A, a, GATEWAYTEST_PORT, b, 53, GATEWAYTEST_NONE, "The flow of node-a to node-b without site-a-to-site-b, which allowed it");
	}

	Print("  node-h dropped %I64u packets by the policy of %s\n", HubSpokePolicyDrops(nodes, HUBSPOKE_H), HUBSPOKE_VRF);
}

// The hub never sends a packet back to the spoke that sent it (SDN-19-R1, #507). In Generation 6 node-h has the state in which
// the LAN behind node-b moved to node-a, and node-a still has the one before, whose route of the LAN leads to node-h, as while
// a Generation reaches the nodes one by one. A packet of node-a to the LAN goes to node-h, whose table leads it back to node-a:
// node-h drops it, sends nothing on and copies nothing to the sensor, and no host takes it, node-a's own neither.
static void HubSpokeBack(GATEWAYTEST_CTX *ctx, GATEWAYTEST_NODE *nodes, HUBSPOKE_SENSOR *sensor)
{
	NODE_OVERLAY_STATUS hub, a;
	UINT64 transit, dropped;

	if (GatewayTestCheck(ctx, HubSpokeApply(nodes, 6, true, HUBSPOKE_NO_POLICY, sensor->Port, true),
		"Generation 6: in the state of node-h the LAN behind node-b moved to node-a, whose state still leads the LAN to node-h", "not applied") == false)
	{
		return;
	}

	HubSpokeDrain(sensor);
	NodeOverlayGetStatus(nodes[HUBSPOKE_H].Node, &hub);
	NodeOverlayGetStatus(nodes[HUBSPOKE_A].Node, &a);
	UINT64 transit_before = HubSpokeTransit(nodes);
	UINT64 dropped_before = hub.Dropped;
	UINT64 forwarded_before = a.Forwarded;
	UINT64 back_before = a.Delivered + a.Dropped;
	UINT marker = GatewayTestSend(ctx, &nodes[HUBSPOKE_A], HUBSPOKE_VRF_ID, hubspoke_addresses[HUBSPOKE_A], HUBSPOKE_LAN_HOST, GATEWAYTEST_PORT);
	UINT got = GatewayTestWhere(nodes, HUBSPOKE_NUM_NODES, marker, GATEWAYTEST_QUIET, NULL);

	// The hub counts the packet after it dropped it: wait for its counters
	HubSpokeCounts(nodes, transit_before, dropped_before, 0, 1, &transit, &dropped);
	UINT copy = HubSpokeRead(sensor, GATEWAYTEST_POLL);
	NodeOverlayGetStatus(nodes[HUBSPOKE_A].Node, &a);

	GatewayTestCheck(ctx, marker != 0 && a.Forwarded - forwarded_before == 1 && got == GATEWAYTEST_NONE && transit == 0 && dropped == 1 && copy == 0 &&
		a.Delivered + a.Dropped == back_before,
		"The hub never sends a packet back to the spoke that sent it: node-a sends to the LAN, node-h drops the packet that its table leads back to node-a, sends nothing on and copies nothing, and no host takes it",
		"node-a sent %I64u packets, taken by %s, node-h sent on %I64u and dropped %I64u, the sensor read %u bytes, node-a took %I64u back", a.Forwarded - forwarded_before,
		GatewayTestName(nodes, HUBSPOKE_NUM_NODES, got), transit, dropped, copy, a.Delivered + a.Dropped - back_before);
}

static void HubSpokeOverlay(GATEWAYTEST_CTX *ctx, GATEWAYTEST_NODE *nodes, TRANSPORT *loopback, HUBSPOKE_SENSOR *sensor)
{
	NODE_MIRROR_STATUS ms;

	if (GatewayTestStart(ctx, nodes, HUBSPOKE_NUM_NODES, loopback, NULL, NULL) == false ||
		GatewayTestCheck(ctx, HubSpokeApply(nodes, 1, true, HUBSPOKE_NO_POLICY, sensor->Port, false),
		"The four nodes of branch apply their states: node-h has a session to each spoke, and the spokes none to each other",
		"the states or the sessions did not come up") == false)
	{
		return;
	}

	// One spoke reaches the other, and the LAN behind it, through the hub, and the replies come back through it
	HubSpokeSend(ctx, nodes, sensor, HUBSPOKE_A, "10.20.0.2", "10.20.0.3", HUBSPOKE_B, true);
	HubSpokeSend(ctx, nodes, sensor, HUBSPOKE_B, "10.20.0.3", "10.20.0.2", HUBSPOKE_A, true);
	HubSpokeSend(ctx, nodes, sensor, HUBSPOKE_A, "10.20.0.2", HUBSPOKE_LAN_HOST, HUBSPOKE_B, true);
	HubSpokeSend(ctx, nodes, sensor, HUBSPOKE_B, HUBSPOKE_LAN_HOST, "10.20.0.2", HUBSPOKE_A, true);
	// The hub reaches each spoke, and each spoke the hub, directly
	HubSpokeSend(ctx, nodes, sensor, HUBSPOKE_A, "10.20.0.2", "10.20.0.1", HUBSPOKE_H, false);
	HubSpokeSend(ctx, nodes, sensor, HUBSPOKE_H, "10.20.0.1", "10.20.0.3", HUBSPOKE_B, false);

	// A node whose state names no hub sends nothing on from one spoke to another
	if (GatewayTestCheck(ctx, HubSpokeApply(nodes, 2, false, HUBSPOKE_NO_POLICY, sensor->Port, false), "Generation 2: the state of node-h names no hub", "not applied"))
	{
		HubSpokeSend(ctx, nodes, sensor, HUBSPOKE_A, "10.20.0.2", "10.20.0.3", GATEWAYTEST_NONE, false);
	}

	// The hub decides by the policy of the VRF what one spoke sends another (SDN-19-R2, #508)
	HubSpokePolicy(ctx, nodes, sensor);

	// ... and never sends a packet back to the spoke that sent it (SDN-19-R1, #507)
	HubSpokeBack(ctx, nodes, sensor);

	NodeMirrorGetStatus(nodes[HUBSPOKE_H].Node, &ms);
	Print("  node-h sent on %I64u packets from one spoke to another, and its Mirror sent %I64u copies\n", HubSpokeTransit(nodes), ms.Copied);
}

// hubspoke: the hub of a VRF of topology hub-and-spoke in the data plane
RANZ_TEST("hubspoke", hubspoke_test, "Hub-and-spoke: the spokes of a VRF have no session to each other, a packet of one spoke to another or to the LAN behind it passes the hub, which sends it on as it came and copies it to the sensor of its Mirror, and the replies too; a node that is no hub sends nothing on. The hub judges each such packet by the policy of the VRF with the two spokes as its ends, and drops what no rule between them allows, which its Mirror does not see.");
void hubspoke_test(UINT num, char **arg)
{
	GATEWAYTEST_CTX ctx;
	GATEWAYTEST_WATCH watch;
	GATEWAYTEST_NODE *nodes = ZeroMalloc(sizeof(GATEWAYTEST_NODE) * HUBSPOKE_NUM_NODES);
	HUBSPOKE_SENSOR *sensor = ZeroMalloc(sizeof(HUBSPOKE_SENSOR));
	TRANSPORT *loopback = TransportLoopbackNew("loopback", 0, true);
	HANDLE watchdog;

	Zero(&ctx, sizeof(ctx));
	sensor->Socket = INVALID_SOCKET;
	watch.Done = CreateEventW(NULL, TRUE, FALSE, NULL);
	watch.Name = "HUBSPOKE";
	watchdog = (watch.Done != NULL ? CreateThread(NULL, 0, GatewayTestWatchdog, &watch, 0, NULL) : NULL);

	Print("HUBSPOKE test: the hub of a VRF of topology hub-and-spoke in the node's data plane, over the overlay of in-process nodes\n");

	bool keys = GatewayTestCheck(&ctx, GatewayTestKeys(nodes, HUBSPOKE_NUM_NODES, hubspoke_names, hubspoke_addresses, 151), "The static keys of the four nodes",
		"PeerKeyFromScalar failed");
	bool open = HubSpokeOpenSensor(sensor);
	open = GatewayTestCheck(&ctx, open, "The sensor of the Mirror of node-h: a UDP socket on 127.0.0.1", "error %u", (UINT)WSAGetLastError());
	if (keys && open)
	{
		HubSpokeOverlay(&ctx, nodes, loopback, sensor);
	}

	GatewayTestFree(nodes, HUBSPOKE_NUM_NODES);
	TransportLoopbackFree(loopback);
	Free(nodes);
	if (sensor->Socket != INVALID_SOCKET)
	{
		closesocket(sensor->Socket);
	}
	Free(sensor);

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
		Print("HUBSPOKE TEST OK\n");
	}
	else
	{
		Print("HUBSPOKE TEST FAILED (%u of %u checks failed)\n", ctx.NumFailed, ctx.NumChecks);
	}
}

//
// gatewaypath
//

#define	GATEWAYPATH_H			0			// node-h, the hub of Generation 2
#define	GATEWAYPATH_A			1			// node-a, a laptop
#define	GATEWAYPATH_GW1			2			// gw-1 and gw-2, the gateways of the LAN
#define	GATEWAYPATH_GW2			3
#define	GATEWAYPATH_NUM_NODES	4
#define	GATEWAYPATH_VRF_ID		30
#define	GATEWAYPATH_VRF			"sites"
#define	GATEWAYPATH_POOL		"10.30.0.0"
#define	GATEWAYPATH_LAN			"192.168.30.0"
#define	GATEWAYPATH_LAN_HOST	"192.168.30.9"
#define	GATEWAYPATH_RELAY		"relay-1"	// The Relay of every state, which no host of the network runs
#define	GATEWAYPATH_PORT		51820		// The UDP port of the peer agent of each node on the network of the simulator

static char *gatewaypath_names[GATEWAYPATH_NUM_NODES] = {"node-h", "node-a", "gw-1", "gw-2"};
static char *gatewaypath_addresses[GATEWAYPATH_NUM_NODES] = {"10.30.0.1", "10.30.0.2", "10.30.0.11", "10.30.0.12"};
// The nodes in name order, the order of the peers of a state
static UINT gatewaypath_order[GATEWAYPATH_NUM_NODES] = {GATEWAYPATH_GW1, GATEWAYPATH_GW2, GATEWAYPATH_A, GATEWAYPATH_H};

// The world of the test: the network of the simulator, which carries the datagrams of the peer agents, the node whose
// datagrams it loses, and the configuration of the peer layers
typedef struct GATEWAYPATH_WORLD
{
	NATSIM *Sim;
	GATEWAYTEST_NODE *Nodes;
	volatile LONG Cut;					// The index of the node whose datagrams the network loses both ways, plus 1; 0 for none
	PEER_CONFIG Path;					// The peer layer of each agent: no ICE, no port mapping, no punch
} GATEWAYPATH_WORLD;

// The tap of the network (NATSIM_TAP): it loses every datagram from and to the host of the node that the world cut
static bool GatewayPathTap(void *param, NATSIM_HOST *from, const PEER_ADDR *dst, const UCHAR *data, UINT size)
{
	GATEWAYPATH_WORLD *w = (GATEWAYPATH_WORLD *)param;
	LONG cut = ReadAcquire(&w->Cut);

	if (cut == 0)
	{
		return true;
	}

	GATEWAYTEST_NODE *t = &w->Nodes[cut - 1];

	return (from != t->Host && PeerAddrEqual(dst, &t->Addr) == false);
}

// The state of node i at generation gen, as the controller compiles it: VRF sites, of topology hub-and-spoke with the hub node-h
// when hub is set, relay-1, and no endpoint, so that no node dials another and each pair takes the datagram path. gw-1 and gw-2
// have the LAN as a LAN subnet of their own. In a full mesh every other node is a peer, gw-1 and gw-2 with the LAN as their
// route, as the controller gives no node a prefix that it announces itself. With the hub, node-h has the spokes as its peers,
// gw-1 and gw-2 with the LAN as their route, and each spoke has node-h as its only peer, with the pool of the VRF and the LAN
// as its routes, but a LAN that it announces itself.
static CONTROL_STATE *GatewayPathState(GATEWAYTEST_NODE *nodes, UINT i, UINT64 gen, bool hub)
{
	CONTROL_STATE *st = GatewayTestState(&nodes[i], gen, GATEWAYPATH_VRF_ID, GATEWAYPATH_VRF, hub ? gatewaypath_names[GATEWAYPATH_H] : NULL, false, GATEWAYPATH_NUM_NODES);
	bool gateway = (i == GATEWAYPATH_GW1 || i == GATEWAYPATH_GW2);
	CONTROL_RELAY *r = &st->Relays[st->NumRelays++];

	// relay-1 starts the peer agent of the node, and keeps its overlay from dialling a peer (NodeAgentDatagramOnly)
	StrCpy(r->Name, sizeof(r->Name), GATEWAYPATH_RELAY);
	for (UINT k = 0;k < NOISE_KEY_SIZE;k++)
	{
		r->Key[k] = (UCHAR)(0x52 + k);
	}
	r->AddressSize = 4;
	r->Address[0] = 198;
	r->Address[1] = 51;
	r->Address[2] = 100;
	r->Address[3] = 200;
	r->Port = 3478;

	if (gateway)
	{
		GatewayTestRoute(st, NULL, GATEWAYPATH_VRF_ID, GATEWAYPATH_LAN, 24);
	}

	for (UINT k = 0;k < GATEWAYPATH_NUM_NODES;k++)
	{
		UINT j = gatewaypath_order[k];

		if (j == i || (hub && i != GATEWAYPATH_H && j != GATEWAYPATH_H))
		{
			continue;
		}

		CONTROL_PEER *p = GatewayTestPeer(st, &nodes[j], GATEWAYPATH_VRF_ID, GATEWAYPATH_VRF);
		if ((j == GATEWAYPATH_GW1 || j == GATEWAYPATH_GW2) && gateway == false)
		{
			GatewayTestRoute(st, p, GATEWAYPATH_VRF_ID, GATEWAYPATH_LAN, 24);
		}
		if (hub && j == GATEWAYPATH_H)
		{
			GatewayTestRoute(st, p, GATEWAYPATH_VRF_ID, GATEWAYPATH_POOL, 24);
			if (gateway == false)
			{
				GatewayTestRoute(st, p, GATEWAYPATH_VRF_ID, GATEWAYPATH_LAN, 24);
			}
		}
	}

	return st;
}

// Apply the states of a Generation, a full mesh or hub-and-spoke, and wait until each node runs it with its peers and no Noise
// session; then give each pair of peers a direct path, by hand, as ICE finds one: each peer layer sends to the host of the
// other on the network of the simulator, and takes its datagrams from there. A pair keeps its path across the Generations
// that keep it a pair.
static bool GatewayPathApply(GATEWAYTEST_NODE *nodes, UINT64 gen, bool hub)
{
	UINT none[GATEWAYPATH_NUM_NODES] = {0, 0, 0, 0};
	UINT peers[GATEWAYPATH_NUM_NODES] = {3, 3, 3, 3};
	bool applied = true;

	if (hub)
	{
		peers[GATEWAYPATH_A] = peers[GATEWAYPATH_GW1] = peers[GATEWAYPATH_GW2] = 1;
	}

	for (UINT i = 0;i < GATEWAYPATH_NUM_NODES;i++)
	{
		CONTROL_STATE *st = GatewayPathState(nodes, i, gen, hub);

		applied = NodeOverlayApply(nodes[i].Node, st) && applied;
		GatewayTestFreeState(st);
	}

	for (UINT i = 0;i < GATEWAYPATH_NUM_NODES;i++)
	{
		// The peer layer of the agent started with the first state that named relay-1, on the thread that applied it
		applied = (nodes[i].Agent != NULL) && applied;
		for (UINT j = 0;j < GATEWAYPATH_NUM_NODES && nodes[i].Agent != NULL;j++)
		{
			if (j != i)
			{
				PeerSetDirect(nodes[i].Agent, nodes[j].Key.Public, &nodes[j].Addr);
			}
		}
	}

	return applied && GatewayTestWaitApplied(nodes, GATEWAYPATH_NUM_NODES, gen, none, peers);
}

// What the node at knows of the gateway i
static NODE_GATEWAY_PEER_STATUS GatewayPathPeer(GATEWAYTEST_NODE *nodes, UINT at, UINT i)
{
	NODE_GATEWAY_PEER_STATUS st;

	NodeGatewayGetPeer(nodes[at].Node, nodes[i].Name, &st);

	return st;
}

// Wait until the node at knows the gateway i to be up (up) or down: the ms it took from start, INFINITE when it did not within
// GATEWAYTEST_BOUND
static UINT GatewayPathWait(GATEWAYTEST_NODE *nodes, UINT at, UINT i, bool up, UINT64 start)
{
	for (UINT64 end = start + GATEWAYTEST_BOUND;;)
	{
		NODE_GATEWAY_PEER_STATUS st = GatewayPathPeer(nodes, at, i);
		UINT64 now = Tick64();

		if (st.Probed && st.Up == up)
		{
			return (UINT)(now - start);
		}
		if (now >= end)
		{
			return INFINITE;
		}
		SleepThread(1);
	}
}

// The node whose host takes a packet of the flow of the source port sport of the host of from to the LAN, as it was sent, within
// GATEWAYTEST_BOUND: its index, GATEWAYTEST_NONE when none does
static UINT GatewayPathFlow(GATEWAYTEST_CTX *ctx, GATEWAYTEST_NODE *nodes, UINT from, USHORT sport)
{
	GATEWAYTEST_TAKEN p;
	UCHAR want[GATEWAYTEST_PACKET];
	UINT marker = GatewayTestSend(ctx, &nodes[from], GATEWAYPATH_VRF_ID, gatewaypath_addresses[from], GATEWAYPATH_LAN_HOST, sport);
	UINT i = GatewayTestWhere(nodes, GATEWAYPATH_NUM_NODES, marker, GATEWAYTEST_BOUND, &p);

	GatewayTestPacket(want, gatewaypath_addresses[from], GATEWAYPATH_LAN_HOST, sport, marker);
	if (i == GATEWAYTEST_NONE || p.Size != GATEWAYTEST_PACKET || Cmp(p.Data, want, GATEWAYTEST_PACKET) != 0 || p.VrfId != GATEWAYPATH_VRF_ID)
	{
		return GATEWAYTEST_NONE;
	}

	return i;
}

// Send num flows of the host of from to the LAN and check that the host of the gateway want takes each, as it was sent
static void GatewayPathFlows(GATEWAYTEST_CTX *ctx, GATEWAYTEST_NODE *nodes, UINT from, UINT num, UINT want, char *what)
{
	UINT got = GATEWAYTEST_NONE;
	UINT k;

	for (k = 0;k < num;k++)
	{
		got = GatewayPathFlow(ctx, nodes, from, (USHORT)(GATEWAYTEST_PORT + k));
		if (got != want)
		{
			break;
		}
	}

	GatewayTestCheck(ctx, k == num, what, "flow %u went to %s", k, GatewayTestName(nodes, GATEWAYPATH_NUM_NODES, got));
}

// A reply from the LAN through the gateway via to the host of to, which takes it as it was sent
static void GatewayPathReply(GATEWAYTEST_CTX *ctx, GATEWAYTEST_NODE *nodes, UINT via, UINT to, char *what)
{
	GATEWAYTEST_TAKEN p;
	UCHAR want[GATEWAYTEST_PACKET];
	UINT marker = GatewayTestSend(ctx, &nodes[via], GATEWAYPATH_VRF_ID, GATEWAYPATH_LAN_HOST, gatewaypath_addresses[to], 53);
	UINT got = GatewayTestWhere(nodes, GATEWAYPATH_NUM_NODES, marker, GATEWAYTEST_BOUND, &p);

	GatewayTestPacket(want, GATEWAYPATH_LAN_HOST, gatewaypath_addresses[to], 53, marker);
	GatewayTestCheck(ctx, marker != 0 && got == to && p.Size == GATEWAYTEST_PACKET && Cmp(p.Data, want, GATEWAYTEST_PACKET) == 0 && p.VrfId == GATEWAYPATH_VRF_ID, what,
		"taken by %s", GatewayTestName(nodes, GATEWAYPATH_NUM_NODES, got));
}

// Send a packet of the flow sport of the host of from to the LAN every GATEWAYTEST_POLL ms from start until a gateway other than
// gone takes one: the ms from start to the send of the last packet, INFINITE when none went on within GATEWAYTEST_BOUND. to takes
// the gateway.
static UINT GatewayPathFailover(GATEWAYTEST_CTX *ctx, GATEWAYTEST_NODE *nodes, UINT from, USHORT sport, UINT gone, UINT64 start, UINT *to)
{
	UINT first = ctx->Marker + 1;

	*to = GATEWAYTEST_NONE;

	for (UINT64 end = start + GATEWAYTEST_BOUND;Tick64() < end;)
	{
		UINT64 sent = Tick64();
		UINT marker = GatewayTestSend(ctx, &nodes[from], GATEWAYPATH_VRF_ID, gatewaypath_addresses[from], GATEWAYPATH_LAN_HOST, sport);

		SleepThread(GATEWAYTEST_POLL);

		// A packet sent before the last one may arrive now: the time counts to the send of the last one, never less
		for (UINT m = first;m <= marker;m++)
		{
			UINT i = GatewayTestWhere(nodes, GATEWAYPATH_NUM_NODES, m, 0, NULL);

			if ((i == GATEWAYPATH_GW1 || i == GATEWAYPATH_GW2) && i != gone)
			{
				*to = i;
				return (UINT)(sent - start);
			}
		}
	}

	return INFINITE;
}

// The datagrams of gw-1 are lost, both ways: the node at, which probes gw-1 on the datagram path, finds it down in under one
// second, and the traffic of the host of from to the LAN, which passes at, moves to gw-2 within that time. When the datagrams
// come back, gw-1 is up again at at once it answered fresh probes in a row, two probe intervals at least after it answers
// again, and carries the traffic again.
static void GatewayPathCut(GATEWAYTEST_CTX *ctx, GATEWAYPATH_WORLD *w, UINT at, UINT from)
{
	GATEWAYTEST_NODE *nodes = w->Nodes;
	char what[MAX_SIZE];
	UINT to = GATEWAYTEST_NONE;

	UINT64 start = Tick64();
	InterlockedExchange(&w->Cut, GATEWAYPATH_GW1 + 1);
	UINT failover = GatewayPathFailover(ctx, nodes, from, GATEWAYTEST_PORT, GATEWAYPATH_GW1, start, &to);
	UINT found = GatewayPathWait(nodes, at, GATEWAYPATH_GW1, false, start);
	Format(what, sizeof(what), "gw-1 loses its datagrams: %s finds it down with its probes on the datagram path in under %u ms", nodes[at].Name, GATEWAYTEST_FAILOVER);
	GatewayTestCheck(ctx, found < GATEWAYTEST_FAILOVER, what, "found down after %u ms", found);
	Format(what, sizeof(what), "The traffic of %s to the LAN moves to gw-2 in under %u ms", nodes[from].Name, GATEWAYTEST_FAILOVER);
	GatewayTestCheck(ctx, failover < GATEWAYTEST_FAILOVER && to == GATEWAYPATH_GW2, what, "%u ms, to %s", failover, GatewayTestName(nodes, GATEWAYPATH_NUM_NODES, to));
	Print("  datagrams of gw-1 lost: %s found it down after %u ms, the traffic of %s moved after %u ms\n", nodes[at].Name, found, nodes[from].Name, failover);

	start = Tick64();
	InterlockedExchange(&w->Cut, 0);
	UINT back = GatewayPathWait(nodes, at, GATEWAYPATH_GW1, true, start);
	Format(what, sizeof(what), "The datagrams of gw-1 come back: %s finds it up again after fresh probes in a row, in %u ms or more", nodes[at].Name, 2 * NODE_GATEWAY_PROBE);
	GatewayTestCheck(ctx, back != INFINITE && back >= 2 * NODE_GATEWAY_PROBE, what, "up again after %u ms", back);
	Print("  datagrams of gw-1 back: %s found it up again after %u ms\n", nodes[at].Name, back);
	Format(what, sizeof(what), "With gw-1 up again, it carries the traffic of %s to the LAN again", nodes[from].Name);
	GatewayPathFlows(ctx, nodes, from, 4, GATEWAYPATH_GW1, what);
}

static void GatewayPathOverlay(GATEWAYTEST_CTX *ctx, GATEWAYPATH_WORLD *w, TRANSPORT *loopback)
{
	GATEWAYTEST_NODE *nodes = w->Nodes;
	NODE_GATEWAY_STATUS gs, gw;
	NODE_OVERLAY_STATUS os;

	if (GatewayTestStart(ctx, nodes, GATEWAYPATH_NUM_NODES, loopback, w->Sim, &w->Path) == false ||
		GatewayTestCheck(ctx, GatewayPathApply(nodes, 1, false), "Generation 1, a full mesh of sites: the four nodes apply their states, with no endpoint and no Noise session, and each pair takes the datagram path",
		"the states or the paths did not come up") == false)
	{
		return;
	}

	// Generation 1: node-a reaches gw-1 and gw-2 by datagram alone, and each is up once it answered the probes of node-a there
	bool up = (GatewayPathWait(nodes, GATEWAYPATH_A, GATEWAYPATH_GW1, true, Tick64()) != INFINITE);
	up = (GatewayPathWait(nodes, GATEWAYPATH_A, GATEWAYPATH_GW2, true, Tick64()) != INFINITE) && up;
	NODE_GATEWAY_PEER_STATUS g1 = GatewayPathPeer(nodes, GATEWAYPATH_A, GATEWAYPATH_GW1);
	NODE_GATEWAY_PEER_STATUS g2 = GatewayPathPeer(nodes, GATEWAYPATH_A, GATEWAYPATH_GW2);
	NodeGatewayGetStatus(nodes[GATEWAYPATH_A].Node, &gs);
	NodeGatewayGetStatus(nodes[GATEWAYPATH_GW1].Node, &gw);
	NodeOverlayGetStatus(nodes[GATEWAYPATH_A].Node, &os);
	GatewayTestCheck(ctx, up && g1.Datagram && g2.Datagram && os.NumLinks == 0 && gs.PathProbes != 0 && gw.PathAnswered != 0,
		"node-a reaches gw-1 and gw-2 on the datagram path alone, with no Noise session, and each is up once it answered the probes of node-a there",
		"up %u, gw-1 by datagram %u, gw-2 by datagram %u, %u Noise sessions, %I64u probes on the datagram path, %I64u of them answered by gw-1", (UINT)up,
		(UINT)g1.Datagram, (UINT)g2.Datagram, os.NumLinks, gs.PathProbes, gw.PathAnswered);

	GatewayPathFlows(ctx, nodes, GATEWAYPATH_A, 4, GATEWAYPATH_GW1, "The flows of node-a to the LAN go to gw-1, the first gateway in name order, on the datagram path, and arrive as they were sent");
	GatewayPathReply(ctx, nodes, GATEWAYPATH_GW1, GATEWAYPATH_A, "A reply from the LAN comes back to node-a through gw-1 on the datagram path");
	GatewayPathReply(ctx, nodes, GATEWAYPATH_GW2, GATEWAYPATH_A, "A reply from the LAN comes back to node-a through gw-2 on the datagram path");
	GatewayPathCut(ctx, w, GATEWAYPATH_A, GATEWAYPATH_A);

	// Generation 2: node-h is the hub, which reaches the spokes on the datagram path alone and probes gw-1 and gw-2 there
	if (GatewayTestCheck(ctx, GatewayPathApply(nodes, 2, true), "Generation 2, hub-and-spoke with the hub node-h: each spoke has node-h as its only peer, on the datagram path",
		"the states or the paths did not come up") == false)
	{
		return;
	}
	up = (GatewayPathWait(nodes, GATEWAYPATH_H, GATEWAYPATH_GW1, true, Tick64()) != INFINITE);
	up = (GatewayPathWait(nodes, GATEWAYPATH_H, GATEWAYPATH_GW2, true, Tick64()) != INFINITE) && up;
	g1 = GatewayPathPeer(nodes, GATEWAYPATH_H, GATEWAYPATH_GW1);
	g2 = GatewayPathPeer(nodes, GATEWAYPATH_H, GATEWAYPATH_GW2);
	GatewayTestCheck(ctx, up && g1.Datagram && g2.Datagram, "node-h, the hub, reaches gw-1 and gw-2 on the datagram path alone, and each is up once it answered the probes of node-h there",
		"up %u, gw-1 by datagram %u, gw-2 by datagram %u", (UINT)up, (UINT)g1.Datagram, (UINT)g2.Datagram);

	// The LAN traffic of the hub and its transit of the LAN traffic of node-a use gw-1, and the reply comes back through the hub
	NodeGatewayGetStatus(nodes[GATEWAYPATH_H].Node, &gs);
	UINT64 transit = gs.Transit;
	GatewayPathFlows(ctx, nodes, GATEWAYPATH_H, 4, GATEWAYPATH_GW1, "The flows of node-h, the hub, to the LAN go to gw-1 on the datagram path");
	GatewayPathFlows(ctx, nodes, GATEWAYPATH_A, 4, GATEWAYPATH_GW1, "The flows of node-a to the LAN pass node-h, which sends them on to gw-1 on the datagram path");
	GatewayPathReply(ctx, nodes, GATEWAYPATH_GW1, GATEWAYPATH_A, "A reply from the LAN comes back to node-a through gw-1 and node-h, on the datagram path");
	NodeGatewayGetStatus(nodes[GATEWAYPATH_H].Node, &gs);
	GatewayTestCheck(ctx, gs.Transit - transit >= 5, "node-h sent the packets of node-a and the reply of the LAN on, from one spoke to another, on the datagram path",
		"it sent on %I64u packets", gs.Transit - transit);
	GatewayPathCut(ctx, w, GATEWAYPATH_H, GATEWAYPATH_A);

	NodeGatewayGetStatus(nodes[GATEWAYPATH_H].Node, &gs);
	Print("  node-h: %I64u probes, %I64u of them on the datagram path, %I64u answers, %I64u packets sent on from one spoke to another\n", gs.Probes, gs.PathProbes,
		gs.Answers, gs.Transit);
}

// gatewaypath: gateway HA and the hub of hub-and-spoke on the datagram path of the peer agent
RANZ_TEST("gatewaypath", gatewaypath_test, "Gateway HA on the datagram path (SDN-19-R1): a gateway that a node reaches by datagram alone, with no Noise session, is up while it answers the probes there, the traffic to the LAN and the transit of a hub use it, and one whose datagrams are lost is found down in under a second and comes back after fresh probes.");
void gatewaypath_test(UINT num, char **arg)
{
	GATEWAYTEST_CTX ctx;
	GATEWAYTEST_WATCH watch;
	GATEWAYPATH_WORLD *w = ZeroMalloc(sizeof(GATEWAYPATH_WORLD));
	TRANSPORT *loopback = TransportLoopbackNew("loopback", 0, true);
	HANDLE watchdog;

	Zero(&ctx, sizeof(ctx));
	watch.Done = CreateEventW(NULL, TRUE, FALSE, NULL);
	watch.Name = "GATEWAYPATH";
	watchdog = (watch.Done != NULL ? CreateThread(NULL, 0, GatewayTestWatchdog, &watch, 0, NULL) : NULL);

	Print("GATEWAYPATH test: gateway HA and the hub of hub-and-spoke on the datagram path of the peer agent, over the network of the NAT simulator\n");

	w->Nodes = ZeroMalloc(sizeof(GATEWAYTEST_NODE) * GATEWAYPATH_NUM_NODES);
	w->Sim = NatSimNew();
	PeerDefaultConfig(&w->Path);
	w->Path.Ice = false;
	w->Path.PortMap = false;
	w->Path.Punch = false;
	for (UINT i = 0;i < GATEWAYPATH_NUM_NODES;i++)
	{
		PeerAddrSetV4(&w->Nodes[i].Addr, 198, 51, 100, (UCHAR)(10 + i), GATEWAYPATH_PORT);
	}

	bool keys = GatewayTestCheck(&ctx, GatewayTestKeys(w->Nodes, GATEWAYPATH_NUM_NODES, gatewaypath_names, gatewaypath_addresses, 91), "The static keys of the four nodes",
		"PeerKeyFromScalar failed");
	if (keys && GatewayTestCheck(&ctx, w->Sim != NULL, "The network of the NAT simulator", "NatSimNew failed"))
	{
		NatSimSetTap(w->Sim, GatewayPathTap, w);
		GatewayPathOverlay(&ctx, w, loopback);
	}

	for (UINT i = 0;i < GATEWAYPATH_NUM_NODES;i++)
	{
		NODE_OVERLAY_STATUS st;

		if (w->Nodes[i].Node != NULL)
		{
			NodeOverlayGetStatus(w->Nodes[i].Node, &st);
			Print("  %s: forwarded %I64u, delivered %I64u, dropped %I64u\n", w->Nodes[i].Name, st.Forwarded, st.Delivered, st.Dropped);
		}
	}

	// The nodes leave the network before it goes
	GatewayTestFree(w->Nodes, GATEWAYPATH_NUM_NODES);
	NatSimFree(w->Sim);
	TransportLoopbackFree(loopback);
	Free(w->Nodes);
	Free(w);

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
		Print("GATEWAYPATH TEST OK\n");
	}
	else
	{
		Print("GATEWAYPATH TEST FAILED (%u of %u checks failed)\n", ctx.NumFailed, ctx.NumChecks);
	}
}
