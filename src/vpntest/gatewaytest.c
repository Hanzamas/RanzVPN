// gatewaytest.c
// Named gateway HA and hub-and-spoke tests of vpntest ("gateway" and "hubspoke" commands, SDN-19 #195)
//
// The gateway HA and the hub-and-spoke topology of the overlay of a node (Cedar/NodeGateway.c), in process, as seam 2 of #45
// runs the data plane: in-process nodes over the loopback transport, each through a data transport of the test whose
// streams the test can freeze, so that a node goes silent while its Noise sessions stay open, and a fake adapter for the
// host of each node. The test compiles the state of each node as the controller does
// (controller/internal/desired/topology.go).
//
// gateway: node-a and three gateways of VRF corp, gw-1, gw-2 and gw-3, which all announce the LAN 192.168.1.0/24.
// - Standby: the first gateway in name order carries every flow to the LAN, the others stand by.
// - The controller's health data: with gw-1 reported down, gw-2 carries every flow; with all three reported down, the probes
//   alone decide, and gw-1 carries them again.
// - ECMP: 32 flows spread over the three gateways by their flow hash, each flow on one gateway.
// - Silent failure: gw-1 freezes, so its Noise session to node-a stays open and goes silent. node-a finds it down with its
//   probes inside that session in under one second (no BFD), and the flows of gw-1 move to the other two within that time,
//   while the flows of the other two stay where they are.
// - Stop: with ECMP off, gw-2 carries every flow; its overlay stops, and the traffic moves to gw-3 within the time in which the
//   probes find a gateway down.
// - Recovery: gw-1 thaws, answers its probes in a row, and carries the flows again.
// Print "GATEWAY TEST OK" only when every check passes.
//
// hubspoke: VRF branch of topology hub-and-spoke with the hub node-h and the spokes node-a and node-b, and the LAN
// 192.168.9.0/24 behind node-b. The spokes have no session to each other. A packet of one spoke to the other, or to the LAN
// behind it, passes the hub, which counts it, and arrives as it was sent, and so do the replies; the hub reaches each spoke
// directly. A hub whose state names no hub drops what one spoke sends the other.
// Print "HUBSPOKE TEST OK" only when every check passes.

#include "harness_int.h"
#include "testlist.h"

#include "Cedar/ConfigStore.h"
#include "Cedar/Node.h"
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

// The checks of a test, and the marker of the next test packet
typedef struct GATEWAYTEST_CTX
{
	UINT NumChecks;
	UINT NumFailed;
	UINT Marker;
} GATEWAYTEST_CTX;

// The data transport of one node: the loopback transport of the test, whose streams the test can freeze. A frozen stream
// reads nothing and drops what it writes, as the sessions of a node that hangs or whose path went down: they stay open.
typedef struct GATEWAYTEST_LINK
{
	TRANSPORT Transport;				// The data transport of the node's overlay
	TRANSPORT *Loopback;				// The loopback transport under it
	volatile LONG Frozen;				// Its streams are frozen
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
} GATEWAYTEST_NODE;

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

// A UDP datagram of IPv4 from src to dst into buf (GATEWAYTEST_PACKET bytes), from the source port sport to port 53, with the
// marker in the first 4 bytes of its data: its size, 0 when an address is not IPv4. The header has no options, TTL 64,
// identification 0 and Don't Fragment.
static UINT GatewayTestPacket(UCHAR *buf, char *src, char *dst, USHORT sport, UINT marker)
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
	WRITE_USHORT(udp + 2, 53);
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

// Start the nodes and their overlays without a control stream, each over its own data transport on loopback, with the fake
// adapter of its host
static bool GatewayTestStart(GATEWAYTEST_CTX *ctx, GATEWAYTEST_NODE *nodes, UINT num, TRANSPORT *loopback)
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
		Format(what, sizeof(what), "%s: its overlay runs without a control stream", t->Name);
		started = GatewayTestCheck(ctx, NodeOverlayStart(t->Node, &c), what, "NodeOverlayStart failed");
	}

	return started;
}

// Whether the overlay of t runs its Generation gen with a session to each of its links peers, which it has
static bool GatewayTestApplied(GATEWAYTEST_NODE *t, UINT64 gen, UINT links)
{
	NODE_OVERLAY_STATUS st;

	NodeOverlayGetStatus(t->Node, &st);

	return (st.Generation == gen && st.NumPeers == links && st.NumLinks == links);
}

// Wait until the overlay of each node whose want is not GATEWAYTEST_NONE runs the Generation gen with sessions to want[i]
// peers, which it has
static bool GatewayTestWaitApplied(GATEWAYTEST_NODE *nodes, UINT num, UINT64 gen, UINT *want)
{
	for (UINT64 end = Tick64() + GATEWAYTEST_BOUND;;)
	{
		bool all = true;

		for (UINT i = 0;i < num;i++)
		{
			if (want[i] != GATEWAYTEST_NONE && GatewayTestApplied(&nodes[i], gen, want[i]) == false)
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

static char *gateway_names[GATEWAY_NUM_NODES] = {"node-a", "gw-1", "gw-2", "gw-3"};
static char *gateway_addresses[GATEWAY_NUM_NODES] = {"10.10.0.1", "10.10.0.11", "10.10.0.12", "10.10.0.13"};

// The state of node i at generation gen, as the controller compiles it: VRF corp with ECMP when ecmp is set. node-a has the
// three gateways as peers, each with the LAN as its route and, when the bit of the gateway (1 << i) is in down, reported
// down by the controller. A gateway has the LAN as a LAN subnet of its own and every other node as a peer; the LAN of the
// other gateways is no route of it, as the controller gives no node a prefix that it announces itself.
static CONTROL_STATE *GatewayState(GATEWAYTEST_NODE *nodes, UINT i, UINT64 gen, bool ecmp, UINT down)
{
	CONTROL_STATE *st = GatewayTestState(&nodes[i], gen, GATEWAY_VRF_ID, GATEWAY_VRF, NULL, ecmp, GATEWAY_NUM_NODES);

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

	return st;
}

// Apply the states of a Generation to every node whose overlay runs (want[i] not GATEWAYTEST_NONE), and wait until each runs it
// with its sessions
static bool GatewayApply(GATEWAYTEST_NODE *nodes, UINT64 gen, bool ecmp, UINT down, UINT *want)
{
	bool applied = true;

	for (UINT i = 0;i < GATEWAY_NUM_NODES;i++)
	{
		if (want[i] == GATEWAYTEST_NONE)
		{
			continue;
		}

		CONTROL_STATE *st = GatewayState(nodes, i, gen, ecmp, down);
		applied = NodeOverlayApply(nodes[i].Node, st) && applied;
		GatewayTestFreeState(st);
	}

	return applied && GatewayTestWaitApplied(nodes, GATEWAY_NUM_NODES, gen, want);
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

static void GatewayOverlay(GATEWAYTEST_CTX *ctx, GATEWAYTEST_NODE *nodes, TRANSPORT *loopback)
{
	// Every node of corp has a session to each of the other three
	UINT want[GATEWAY_NUM_NODES] = {3, 3, 3, 3};
	UINT flows[GATEWAYTEST_FLOWS];
	NODE_GATEWAY_STATUS gs;
	char what[MAX_SIZE];
	UINT to = GATEWAYTEST_NONE;
	UINT64 gen = 1;

	if (GatewayTestStart(ctx, nodes, GATEWAY_NUM_NODES, loopback) == false ||
		GatewayTestCheck(ctx, GatewayApply(nodes, gen, false, 0, want), "The four nodes of corp apply their states, and each has a session to the other three",
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

	// The controller's health data: gw-1 reported down gives its flows to gw-2; all three reported down leave the probes alone
	if (GatewayTestCheck(ctx, GatewayApply(nodes, ++gen, false, 1U << GATEWAY_GW1, want), "Generation 2: the controller reports gw-1 down", "not applied"))
	{
		GatewayFlows(ctx, nodes, 4, GATEWAY_GW2, "The controller's health data: with gw-1 reported down, gw-2 carries every flow, though gw-1 answers its probes");
	}
	if (GatewayTestCheck(ctx, GatewayApply(nodes, ++gen, false, (1U << GATEWAY_GW1) | (1U << GATEWAY_GW2) | (1U << GATEWAY_GW3), want),
		"Generation 3: the controller reports all three gateways down", "not applied"))
	{
		GatewayFlows(ctx, nodes, 4, GATEWAY_GW1, "With all three reported down the probes decide alone: gw-1, which answers them, carries every flow");
	}

	// ECMP: the flows spread over the three gateways
	if (GatewayTestCheck(ctx, GatewayApply(nodes, ++gen, true, 0, want), "Generation 4: corp spreads its flows over its gateways (ECMP)", "not applied") == false ||
		GatewayEcmp(ctx, nodes, flows) == false)
	{
		return;
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
	// time in which the probes find a gateway down
	if (GatewayTestCheck(ctx, GatewayApply(nodes, ++gen, false, 0, want), "Generation 5: ECMP off, gw-1 still frozen", "not applied") == false)
	{
		return;
	}
	GatewayFlows(ctx, nodes, 4, GATEWAY_GW2, "With gw-1 down and ECMP off, gw-2 carries every flow");
	start = Tick64();
	NodeOverlayStop(nodes[GATEWAY_GW2].Node);
	failover = GatewayFailover(ctx, nodes, GATEWAYTEST_PORT, GATEWAY_GW2, start, &to);
	Format(what, sizeof(what), "Stop: the overlay of gw-2 stops, and its traffic moves to gw-3 within %u ms, the time in which the probes find a gateway down",
		NODE_GATEWAY_DEAD);
	GatewayTestCheck(ctx, failover <= NODE_GATEWAY_DEAD && to == GATEWAY_GW3, what, "%u ms, to %s", failover, GatewayTestName(nodes, GATEWAY_NUM_NODES, to));
	Print("  stop of gw-2: its traffic moved after %u ms\n", failover);
	want[GATEWAY_GW2] = GATEWAYTEST_NONE;

	// Recovery: gw-1 thaws, answers its probes in a row, and carries the flows again
	start = Tick64();
	InterlockedExchange(&nodes[GATEWAY_GW1].Link->Frozen, 0);
	UINT back = GatewayWaitPeer(nodes, GATEWAY_GW1, true, start);
	Format(what, sizeof(what), "Recovery: gw-1 thaws and is up again once it answered %u probes in a row", NODE_GATEWAY_RISE);
	GatewayTestCheck(ctx, back != INFINITE, what, "not within %u ms", GATEWAYTEST_BOUND);
	Print("  recovery of gw-1: up again after %u ms\n", back);
	GatewayFlows(ctx, nodes, 4, GATEWAY_GW1, "With gw-1 up again, it carries every flow");

	NodeGatewayGetStatus(nodes[GATEWAY_A].Node, &gs);
	GatewayTestCheck(ctx, gs.Failovers >= 2 && gs.Recoveries >= 1 && gs.Probes != 0 && gs.Answers != 0,
		"node-a counts the gateways that went down and came up again", "%I64u down, %I64u up again", gs.Failovers, gs.Recoveries);
	Print("  node-a: %I64u probes, %I64u answers, %I64u gateways down, %I64u up again\n", gs.Probes, gs.Answers, gs.Failovers, gs.Recoveries);
}

// gateway: gateway HA in the data plane
RANZ_TEST("gateway", gateway_test, "Gateway HA: of three gateways of one LAN the first stands in for all, the controller's health data moves it, ECMP spreads the flows by their hash, a gateway that goes silent is found by the probes inside its Noise session and left in under a second, a stopped one at once, and one that answers again comes back.");
void gateway_test(UINT num, char **arg)
{
	GATEWAYTEST_CTX ctx;
	GATEWAYTEST_WATCH watch;
	GATEWAYTEST_NODE *nodes = ZeroMalloc(sizeof(GATEWAYTEST_NODE) * GATEWAY_NUM_NODES);
	// Bound: the records go in clear, so a stream that drops what it writes while frozen keeps its session after it thaws
	TRANSPORT *loopback = TransportLoopbackNew("loopback", 0, true);
	HANDLE watchdog;

	Zero(&ctx, sizeof(ctx));
	watch.Done = CreateEventW(NULL, TRUE, FALSE, NULL);
	watch.Name = "GATEWAY";
	watchdog = (watch.Done != NULL ? CreateThread(NULL, 0, GatewayTestWatchdog, &watch, 0, NULL) : NULL);

	Print("GATEWAY test: gateway HA of the node's data plane over the overlay of in-process nodes\n");

	if (GatewayTestCheck(&ctx, GatewayTestKeys(nodes, GATEWAY_NUM_NODES, gateway_names, gateway_addresses, 11), "The static keys of the four nodes",
		"PeerKeyFromScalar failed"))
	{
		GatewayOverlay(&ctx, nodes, loopback);
	}

	for (UINT i = 0;i < GATEWAY_NUM_NODES;i++)
	{
		NODE_OVERLAY_STATUS st;

		if (nodes[i].Node != NULL)
		{
			NodeOverlayGetStatus(nodes[i].Node, &st);
			Print("  %s: forwarded %I64u, delivered %I64u, dropped %I64u\n", nodes[i].Name, st.Forwarded, st.Delivered, st.Dropped);
		}
	}

	GatewayTestFree(nodes, GATEWAY_NUM_NODES);
	TransportLoopbackFree(loopback);
	Free(nodes);

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
#define	HUBSPOKE_NUM_NODES		3
#define	HUBSPOKE_VRF_ID			20
#define	HUBSPOKE_VRF			"branch"
#define	HUBSPOKE_POOL			"10.20.0.0"
#define	HUBSPOKE_LAN			"192.168.9.0"
#define	HUBSPOKE_LAN_HOST		"192.168.9.5"

static char *hubspoke_names[HUBSPOKE_NUM_NODES] = {"node-h", "node-a", "node-b"};
static char *hubspoke_addresses[HUBSPOKE_NUM_NODES] = {"10.20.0.1", "10.20.0.2", "10.20.0.3"};

// The state of node i at generation gen, as the controller compiles it for VRF branch of topology hub-and-spoke with the hub
// node-h; with hub not set, the state of node-h names no hub. node-h has both spokes as its peers, node-b with its LAN as its
// route; each spoke has node-h as its only peer, with the pool of the VRF and the LAN subnets of the other nodes as routes of
// node-h. node-b has its LAN as a LAN subnet of its own.
static CONTROL_STATE *HubSpokeState(GATEWAYTEST_NODE *nodes, UINT i, UINT64 gen, bool hub)
{
	CONTROL_STATE *st = GatewayTestState(&nodes[i], gen, HUBSPOKE_VRF_ID, HUBSPOKE_VRF, (i != HUBSPOKE_H || hub) ? "node-h" : NULL, false, HUBSPOKE_NUM_NODES);

	if (i == HUBSPOKE_H)
	{
		GatewayTestPeer(st, &nodes[HUBSPOKE_A], HUBSPOKE_VRF_ID, HUBSPOKE_VRF);
		CONTROL_PEER *b = GatewayTestPeer(st, &nodes[HUBSPOKE_B], HUBSPOKE_VRF_ID, HUBSPOKE_VRF);
		GatewayTestRoute(st, b, HUBSPOKE_VRF_ID, HUBSPOKE_LAN, 24);
		return st;
	}

	CONTROL_PEER *h = GatewayTestPeer(st, &nodes[HUBSPOKE_H], HUBSPOKE_VRF_ID, HUBSPOKE_VRF);
	GatewayTestRoute(st, h, HUBSPOKE_VRF_ID, HUBSPOKE_POOL, 24);
	if (i == HUBSPOKE_A)
	{
		GatewayTestRoute(st, h, HUBSPOKE_VRF_ID, HUBSPOKE_LAN, 24);
	}
	else
	{
		GatewayTestRoute(st, NULL, HUBSPOKE_VRF_ID, HUBSPOKE_LAN, 24);
	}

	return st;
}

// Apply the states of a Generation to the three nodes, and wait until each runs it with its sessions
static bool HubSpokeApply(GATEWAYTEST_NODE *nodes, UINT64 gen, bool hub)
{
	// node-h has a session to each spoke, a spoke to node-h alone
	UINT want[HUBSPOKE_NUM_NODES] = {2, 1, 1};
	bool applied = true;

	for (UINT i = 0;i < HUBSPOKE_NUM_NODES;i++)
	{
		CONTROL_STATE *st = HubSpokeState(nodes, i, gen, hub);

		applied = NodeOverlayApply(nodes[i].Node, st) && applied;
		GatewayTestFreeState(st);
	}

	return applied && GatewayTestWaitApplied(nodes, HUBSPOKE_NUM_NODES, gen, want);
}

// The packets that the hub sent on from one spoke to another
static UINT64 HubSpokeTransit(GATEWAYTEST_NODE *nodes)
{
	NODE_GATEWAY_STATUS st;

	NodeGatewayGetStatus(nodes[HUBSPOKE_H].Node, &st);

	return st.Transit;
}

// One packet of the host of from, from src to dst: it reaches the host of to as it was sent, and the hub sent it on when
// via_hub is set; with to GATEWAYTEST_NONE, no host takes it and the hub drops it
static void HubSpokeSend(GATEWAYTEST_CTX *ctx, GATEWAYTEST_NODE *nodes, UINT from, char *src, char *dst, UINT to, bool via_hub)
{
	GATEWAYTEST_TAKEN p;
	UCHAR want[GATEWAYTEST_PACKET];
	NODE_OVERLAY_STATUS hub;
	char what[MAX_SIZE];

	NodeOverlayGetStatus(nodes[HUBSPOKE_H].Node, &hub);
	UINT64 transit_before = HubSpokeTransit(nodes);
	UINT64 dropped_before = hub.Dropped;
	UINT marker = GatewayTestSend(ctx, &nodes[from], HUBSPOKE_VRF_ID, src, dst, GATEWAYTEST_PORT);
	UINT got = GatewayTestWhere(nodes, HUBSPOKE_NUM_NODES, marker, to == GATEWAYTEST_NONE ? GATEWAYTEST_QUIET : GATEWAYTEST_BOUND, &p);
	UINT64 transit = HubSpokeTransit(nodes) - transit_before;

	NodeOverlayGetStatus(nodes[HUBSPOKE_H].Node, &hub);
	GatewayTestPacket(want, src, dst, GATEWAYTEST_PORT, marker);

	if (to == GATEWAYTEST_NONE)
	{
		Format(what, sizeof(what), "%s sends %s > %s; node-h, which is no hub in its state, drops it", nodes[from].Name, src, dst);
		GatewayTestCheck(ctx, marker != 0 && got == GATEWAYTEST_NONE && transit == 0 && hub.Dropped > dropped_before, what,
			"taken by %s, %I64u sent on, %I64u dropped", GatewayTestName(nodes, HUBSPOKE_NUM_NODES, got), transit, hub.Dropped - dropped_before);
		return;
	}

	Format(what, sizeof(what), "%s sends %s > %s; %s takes it as it was sent, %s", nodes[from].Name, src, dst, nodes[to].Name,
		via_hub ? "and node-h, the hub, sent it on" : "and the hub sent nothing on");
	GatewayTestCheck(ctx, marker != 0 && got == to && p.Size == GATEWAYTEST_PACKET && Cmp(p.Data, want, GATEWAYTEST_PACKET) == 0 &&
		p.VrfId == HUBSPOKE_VRF_ID && transit == (via_hub ? 1 : 0), what,
		"taken by %s, %I64u sent on by the hub", GatewayTestName(nodes, HUBSPOKE_NUM_NODES, got), transit);
}

static void HubSpokeOverlay(GATEWAYTEST_CTX *ctx, GATEWAYTEST_NODE *nodes, TRANSPORT *loopback)
{
	if (GatewayTestStart(ctx, nodes, HUBSPOKE_NUM_NODES, loopback) == false ||
		GatewayTestCheck(ctx, HubSpokeApply(nodes, 1, true),
		"The three nodes of branch apply their states: node-h has a session to each spoke, and the spokes none to each other",
		"the states or the sessions did not come up") == false)
	{
		return;
	}

	// One spoke reaches the other, and the LAN behind it, through the hub, and the replies come back through it
	HubSpokeSend(ctx, nodes, HUBSPOKE_A, "10.20.0.2", "10.20.0.3", HUBSPOKE_B, true);
	HubSpokeSend(ctx, nodes, HUBSPOKE_B, "10.20.0.3", "10.20.0.2", HUBSPOKE_A, true);
	HubSpokeSend(ctx, nodes, HUBSPOKE_A, "10.20.0.2", HUBSPOKE_LAN_HOST, HUBSPOKE_B, true);
	HubSpokeSend(ctx, nodes, HUBSPOKE_B, HUBSPOKE_LAN_HOST, "10.20.0.2", HUBSPOKE_A, true);
	// The hub reaches each spoke, and each spoke the hub, directly
	HubSpokeSend(ctx, nodes, HUBSPOKE_A, "10.20.0.2", "10.20.0.1", HUBSPOKE_H, false);
	HubSpokeSend(ctx, nodes, HUBSPOKE_H, "10.20.0.1", "10.20.0.3", HUBSPOKE_B, false);

	// A node whose state names no hub sends nothing on from one spoke to another
	if (GatewayTestCheck(ctx, HubSpokeApply(nodes, 2, false), "Generation 2: the state of node-h names no hub", "not applied"))
	{
		HubSpokeSend(ctx, nodes, HUBSPOKE_A, "10.20.0.2", "10.20.0.3", GATEWAYTEST_NONE, false);
	}

	Print("  node-h sent on %I64u packets from one spoke to another\n", HubSpokeTransit(nodes));
}

// hubspoke: the hub of a VRF of topology hub-and-spoke in the data plane
RANZ_TEST("hubspoke", hubspoke_test, "Hub-and-spoke: the spokes of a VRF have no session to each other, a packet of one spoke to another or to the LAN behind it passes the hub, which sends it on as it came, and the replies too; a node that is no hub sends nothing on.");
void hubspoke_test(UINT num, char **arg)
{
	GATEWAYTEST_CTX ctx;
	GATEWAYTEST_WATCH watch;
	GATEWAYTEST_NODE *nodes = ZeroMalloc(sizeof(GATEWAYTEST_NODE) * HUBSPOKE_NUM_NODES);
	TRANSPORT *loopback = TransportLoopbackNew("loopback", 0, true);
	HANDLE watchdog;

	Zero(&ctx, sizeof(ctx));
	watch.Done = CreateEventW(NULL, TRUE, FALSE, NULL);
	watch.Name = "HUBSPOKE";
	watchdog = (watch.Done != NULL ? CreateThread(NULL, 0, GatewayTestWatchdog, &watch, 0, NULL) : NULL);

	Print("HUBSPOKE test: the hub of a VRF of topology hub-and-spoke in the node's data plane, over the overlay of in-process nodes\n");

	if (GatewayTestCheck(&ctx, GatewayTestKeys(nodes, HUBSPOKE_NUM_NODES, hubspoke_names, hubspoke_addresses, 151), "The static keys of the three nodes",
		"PeerKeyFromScalar failed"))
	{
		HubSpokeOverlay(&ctx, nodes, loopback);
	}

	GatewayTestFree(nodes, HUBSPOKE_NUM_NODES);
	TransportLoopbackFree(loopback);
	Free(nodes);

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
