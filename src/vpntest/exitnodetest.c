// exitnodetest.c
// Named exit node test of vpntest ("exitnode" command, SDN-55 #248; "exit" is the command that ends vpntest)
//
// The exit node of the client role (Cedar/NodeExit.c) as the tray drives it: node-c with the client role on a Wintun
// adapter, whose host is the runner itself as in the client test, and two server nodes in this process that hold the
// default route of VRF 1, each a server of node-c over TLS-443 on a test port of the loopback interface: gw4, whose Peer
// object has 0.0.0.0/0 alone, and gw6, which has 0.0.0.0/0 and ::/0. The host of each is a fake one that sends back the
// UDP datagrams to the test port and counts them by family. The nodes take their states from the test
// (NodeOverlayApply): node-c 100.64.0.2/10 and fd00:55::2/64 in VRF 1, gw4 100.64.0.4/10, gw6 100.64.0.6/10 and
// fd00:55::6/64, each exit with the LAN subnets of its default routes, which lead to its host. The test is the logged-in
// user: it sends the commands of ranz tray on the pipe of the role.
// - status lists gw4 (IPv4 only) and gw6 (both families) as the exit nodes of VRF 1, and none chosen; the adapter holds no
//   default route, and a datagram of node-c to an address of the internet does not enter it.
// - exit gw4: the adapter holds 0.0.0.0/0 and ::/0, and Windows takes it to an address of the internet of either family
//   before the default routes of the runner, so no IPv6 leaves by the physical interface. A datagram to an IPv4 address of
//   the internet reaches the host of gw4 and comes back; an IPv6 datagram enters the adapter and goes nowhere, since gw4
//   carries no IPv6: the overlay drops and counts it, and no host gets it. A server address that the runner reaches by its
//   default route keeps a host route through that route's interface.
// - exit gw6 1: both families reach the host of gw6 and come back. exit with a name of no exit node is refused, and the
//   choice stays.
// - down takes the default routes off the adapter, up brings them back.
// - exit none: the adapter holds no default route again, and the host route of the server address is gone.
// The default routes of the adapter take the traffic of the runner while an exit is chosen, so the steps between the
// first exit and exit none are short; the adapter goes with the process should it end there. Print "EXITNODE TEST OK"
// only when every check passes. Needs administrator rights and wintun.dll next to vpntest.

#include "testlist.h"

#include "Cedar/ConfigStore.h"
#include "Cedar/Node.h"

#include "Mayaqua/Encrypt.h"
#include "Mayaqua/FileIO.h"
#include "Mayaqua/Internat.h"
#include "Mayaqua/Kernel.h"
#include "Mayaqua/Memory.h"
#include "Mayaqua/Microsoft.h"
#include "Mayaqua/Object.h"
#include "Mayaqua/Str.h"
#include "Mayaqua/TcpIp.h"
#include "Mayaqua/Tick64.h"

#include "Core/Control.h"
#include "Core/Crypto.h"
#include "Core/Transport.h"

#include <iphlpapi.h>
#include <WS2tcpip.h>

#include <stdio.h>

#define	EXITNODETEST_BUDGET			300000		// The whole test ends within this time, or the watchdog ends the process (ms)
#define	EXITNODETEST_BOUND			20000		// A bounded wait on observable state (ms)
#define	EXITNODETEST_POLL			20			// Poll interval of observable state (ms)
#define	EXITNODETEST_REPLY			3000		// A datagram comes back within this (ms)
#define	EXITNODETEST_SILENCE		700			// ... and what must reach no host does not, within this (ms)
#define	EXITNODETEST_VRF			1			// The VRF of the test
#define	EXITNODETEST_VRF_NAME		"default"	// ... and its name
#define	EXITNODETEST_UDP_PORT		9855		// The UDP port whose datagrams the hosts of the exit nodes send back
#define	EXITNODETEST_CLIENT_PORT	47855		// The client end of the datagrams
#define	EXITNODETEST_CN				L"CN=localhost"
#define	EXITNODETEST_SAN			L"localhost"
#define	EXITNODETEST_NODE_C			"node-c"
#define	EXITNODETEST_GW4			"gw4"
#define	EXITNODETEST_GW6			"gw6"
#define	EXITNODETEST_SERVER			"192.0.2.10:443"	// A server address that the runner reaches through its default route (TEST-NET-1)
#define	EXITNODETEST_DATA_4			"ranz exit ipv4"
#define	EXITNODETEST_DATA_6			"ranz exit ipv6"
#define	EXITNODETEST_MAX_PACKET		2048

// The addresses of the test, in network byte order
static UCHAR exitnodetest_c4[4] = {100, 64, 0, 2};			// node-c in VRF 1
static UCHAR exitnodetest_c6[16] = {0xFD, 0x00, 0x00, 0x55, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x02};
static UCHAR exitnodetest_gw4[4] = {100, 64, 0, 4};			// gw4
static UCHAR exitnodetest_gw6[4] = {100, 64, 0, 6};			// gw6 ...
static UCHAR exitnodetest_gw6_6[16] = {0xFD, 0x00, 0x00, 0x55, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x06};
static UCHAR exitnodetest_net4[4] = {198, 51, 100, 77};		// An IPv4 address of the internet (TEST-NET-2)
static UCHAR exitnodetest_net6[16] = {0x20, 0x01, 0x0D, 0xB8, 0x00, 0x55, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x77};	// ... and an IPv6 one
static UCHAR exitnodetest_server[4] = {192, 0, 2, 10};		// The server address of EXITNODETEST_SERVER
static UCHAR exitnodetest_any[16];							// 0.0.0.0/0 and ::/0

// The checks of the test
typedef struct EXITNODETEST_CTX
{
	UINT NumChecks;
	UINT NumFailed;
} EXITNODETEST_CTX;

// The fake host of an exit node: it sends back each UDP datagram to EXITNODETEST_UDP_PORT, and counts them by family
typedef struct EXITNODETEST_HOST
{
	volatile LONG Got4;
	volatile LONG Got6;
} EXITNODETEST_HOST;

// The listener of an exit node: the TLS server transport on a port of 127.0.0.1 that the system picks, as the data
// transport of its overlay, whose Listen takes the node's name and gives the listener
typedef struct EXITNODETEST_SERVER
{
	TRANSPORT Transport;
	TRANSPORT *Tls;
	TRANSPORT_LISTENER *Listener;
	USHORT Port;
} EXITNODETEST_SERVER;

// One node of the test
typedef struct EXITNODETEST_NODE
{
	wchar_t Dir[MAX_PATH];				// Its data directory
	PEER_KEY Key;						// Its static key (the exit nodes)
	NODE *Node;
	EXITNODETEST_SERVER *Server;		// The exit nodes: the listener
	EXITNODETEST_HOST Host;				// ... and the host
} EXITNODETEST_NODE;

static bool ExitNodeTestCheck(EXITNODETEST_CTX *ctx, bool ok, char *what, char *fmt, ...) RANZ_PRINTF_FORMAT(4, 5);
static bool ExitNodeTestCheck(EXITNODETEST_CTX *ctx, bool ok, char *what, char *fmt, ...)
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

// The watchdog: a native thread that ends a run that hangs, so that a lost packet is a failed test instead of a hung CI step
static DWORD WINAPI ExitNodeTestWatchdog(LPVOID param)
{
	char msg[MAX_SIZE];
	DWORD written = 0;

	if (WaitForSingleObject((HANDLE)param, EXITNODETEST_BUDGET) != WAIT_TIMEOUT)
	{
		return 0;
	}

	int len = snprintf(msg, sizeof(msg), "EXITNODE TEST FAILED (did not finish within %u ms)\n", EXITNODETEST_BUDGET);
	if (len > 0)
	{
		WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), msg, (DWORD)MIN((UINT)len, (UINT)sizeof(msg) - 1), &written, NULL);
	}

	TerminateProcess(GetCurrentProcess(), 1);

	return 0;
}

//
// The exit nodes
//

// The host of an exit node: a UDP datagram of either family to EXITNODETEST_UDP_PORT goes back with its addresses and its
// ports swapped, which leaves its checksums as they are, and is counted by family. On the thread of the overlay of the exit
// node, an online reader of its tables.
static void ExitNodeTestHost(NODE *n, void *param, UINT vrf_id, const UCHAR *packet, UINT size)
{
	EXITNODETEST_HOST *h = (EXITNODETEST_HOST *)param;
	UCHAR reply[EXITNODETEST_MAX_PACKET];
	UINT l4 = 0;
	UINT addr = 0;
	UINT addr_size = 0;

	if (packet == NULL || size < 28 || size > sizeof(reply))
	{
		return;
	}

	if ((packet[0] >> 4) == 4 && packet[9] == IP_PROTO_UDP)
	{
		l4 = (packet[0] & 0x0F) * 4;
		addr = 12;
		addr_size = 4;
	}
	else if ((packet[0] >> 4) == 6 && size >= 48 && packet[6] == IP_PROTO_UDP)
	{
		l4 = 40;
		addr = 8;
		addr_size = 16;
	}

	if (addr_size == 0 || l4 < 20 || l4 + 8 > size || (((UINT)packet[l4 + 2] << 8) | packet[l4 + 3]) != EXITNODETEST_UDP_PORT)
	{
		return;
	}

	InterlockedIncrement(addr_size == 4 ? &h->Got4 : &h->Got6);

	Copy(reply, packet, size);
	Copy(reply + addr, packet + addr + addr_size, addr_size);
	Copy(reply + addr + addr_size, packet + addr, addr_size);
	Copy(reply + l4, packet + l4 + 2, 2);
	Copy(reply + l4 + 2, packet + l4, 2);

	NodeOverlayInput(n, vrf_id, reply, size);
}

static bool ExitNodeTestServerDial(void *param, const char *address, HANDLE cancel, void **stream)
{
	// An exit node dials no client: the clients dial it
	*stream = NULL;
	return false;
}

static bool ExitNodeTestServerListen(void *param, const char *address, void **listener)
{
	*listener = param;
	return true;
}

static bool ExitNodeTestServerAccept(void *listener, UINT timeout, void **stream)
{
	EXITNODETEST_SERVER *srv = (EXITNODETEST_SERVER *)listener;

	*stream = TransportAccept(srv->Listener, timeout);

	return (*stream != NULL);
}

static void ExitNodeTestServerCloseListener(void *listener)
{
	// The test closes the TLS listener once the overlay of the exit node stopped
	return;
}

static UINT ExitNodeTestServerRead(void *stream, void *buf, UINT size, UINT timeout)
{
	return TransportRead((TRANSPORT_STREAM *)stream, buf, size, timeout);
}

static bool ExitNodeTestServerWrite(void *stream, const void *buf, UINT size)
{
	return TransportWrite((TRANSPORT_STREAM *)stream, buf, size);
}

static void ExitNodeTestServerClose(void *stream)
{
	TransportClose((TRANSPORT_STREAM *)stream);
}

static UINT ExitNodeTestServerBinding(void *stream, UCHAR *binding, UINT max, UINT *size)
{
	return TransportBinding((TRANSPORT_STREAM *)stream, binding, max, size);
}

static bool ExitNodeTestServerRekey(void *stream)
{
	return TransportRekey((TRANSPORT_STREAM *)stream);
}

// The listener of an exit node with the certificate of thumbprint
static EXITNODETEST_SERVER *ExitNodeTestServerNew(char *thumbprint)
{
	EXITNODETEST_SERVER *srv = ZeroMalloc(sizeof(EXITNODETEST_SERVER));
	TRANSPORT_TLS_CONFIG tc;

	TransportTlsDefaultConfig(&tc, thumbprint, false);
	srv->Tls = TransportTlsServerNew(&tc);
	srv->Listener = (srv->Tls != NULL ? TransportListen(srv->Tls, "127.0.0.1:0") : NULL);
	srv->Port = (srv->Listener != NULL ? TransportTlsBoundPort(srv->Tls) : 0);

	StrCpy(srv->Transport.Name, sizeof(srv->Transport.Name), "exit server");
	srv->Transport.Param = srv;
	srv->Transport.Dial = ExitNodeTestServerDial;
	srv->Transport.Listen = ExitNodeTestServerListen;
	srv->Transport.Accept = ExitNodeTestServerAccept;
	srv->Transport.CloseListener = ExitNodeTestServerCloseListener;
	srv->Transport.Read = ExitNodeTestServerRead;
	srv->Transport.Write = ExitNodeTestServerWrite;
	srv->Transport.Close = ExitNodeTestServerClose;
	srv->Transport.Binding = ExitNodeTestServerBinding;
	srv->Transport.Rekey = ExitNodeTestServerRekey;
	srv->Transport.Queue = TRANSPORT_QUEUE_NONE;

	return srv;
}

// Close the listener and the transport, once the overlay of the exit node stopped and closed every stream
static void ExitNodeTestServerFree(EXITNODETEST_SERVER *srv)
{
	if (srv == NULL)
	{
		return;
	}

	TransportCloseListener(srv->Listener);
	TransportTlsFree(srv->Tls);
	Free(srv);
}

//
// The nodes
//

// A new empty data directory under the temp directory of the process, with a configuration store: the roles, one worker,
// and the identity key and the Client setting when they are not NULL
static void ExitNodeTestNewDir(wchar_t *dir, UINT size, char *name, char *roles, char *identity, char *client)
{
	wchar_t tmp[MAX_PATH];
	wchar_t path[MAX_PATH];

	UniFormat(tmp, sizeof(tmp), L"exitnodetest_%S_%u", name, Rand32());
	ConbinePathW(dir, size, MsGetMyTempDirW(), tmp);
	MakeDirExW(dir);

	ConbinePathW(path, sizeof(path), dir, CS_FILE_NAME);
	CONFIG_STORE *s = CsOpen(path);
	if (s != NULL)
	{
		CsSetSetting(s, NODE_SETTING_ROLES, roles);
		CsSetSetting(s, NODE_SETTING_WORKERS, "1");
		if (identity != NULL)
		{
			CsSetSetting(s, NODE_SETTING_IDENTITY_KEY, identity);
		}
		if (client != NULL)
		{
			CsSetSetting(s, NODE_SETTING_CLIENT, client);
		}
		CsClose(s);
	}
}

// Delete the files of a directory, then the directory (it holds no subdirectory)
static void ExitNodeTestDeleteDir(wchar_t *dir)
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

// Stop and free a node of the test, then its listener, and delete its data directory with its node log
static void ExitNodeTestFreeNode(EXITNODETEST_NODE *t)
{
	wchar_t log_dir[MAX_PATH];

	if (t->Node != NULL)
	{
		NodeStop(t->Node);
		FreeNode(t->Node);
		t->Node = NULL;

		ConbinePathW(log_dir, sizeof(log_dir), t->Dir, NODE_LOG_DIR_NAME);
		ExitNodeTestDeleteDir(log_dir);
		ExitNodeTestDeleteDir(t->Dir);
	}

	ExitNodeTestServerFree(t->Server);
	t->Server = NULL;
	PeerKeyClose(&t->Key);
}

// An address of a node in VRF 1: 4 bytes for IPv4, 16 for IPv6
static void ExitNodeTestAddress(CONTROL_ADDRESS *a, char *network, const UCHAR *addr, UINT size, UINT length)
{
	Zero(a, sizeof(CONTROL_ADDRESS));
	StrCpy(a->Network, sizeof(a->Network), network);
	a->VrfId = EXITNODETEST_VRF;
	Copy(a->Address, addr, size);
	a->AddressSize = size;
	a->Length = length;
}

// The default route of a family in VRF 1: 0.0.0.0/0 for size 4, ::/0 for size 16
static void ExitNodeTestDefault(CONTROL_ROUTE *r, UINT size)
{
	Zero(r, sizeof(CONTROL_ROUTE));
	r->VrfId = EXITNODETEST_VRF;
	r->AddressSize = size;
	r->Length = 0;
}

// A peer of a state in VRF 1, with its static key
static void ExitNodeTestPeer(CONTROL_PEER *p, char *name, const UCHAR *key)
{
	Zero(p, sizeof(CONTROL_PEER));
	StrCpy(p->Name, sizeof(p->Name), name);
	Copy(p->Key, key, PEER_KEY_SIZE);
	p->NumVrfs = 1;
	p->VrfIds[0] = EXITNODETEST_VRF;
}

// The common part of a state: Generation 1, the name of the node and VRF 1
static void ExitNodeTestState(CONTROL_STATE *st, char *name)
{
	Zero(st, sizeof(CONTROL_STATE));
	st->Generation = 1;
	StrCpy(st->Name, sizeof(st->Name), name);
	StrCpy(st->Vrfs[0].Name, sizeof(st->Vrfs[0].Name), EXITNODETEST_VRF_NAME);
	st->Vrfs[0].Id = EXITNODETEST_VRF;
	st->NumVrfs = 1;
}

// The state of node-c: its addresses of both families, and gw4 and gw6 as its peers, in name order, with the default routes
// of each in their Peer objects
static bool ExitNodeTestApplyClient(EXITNODETEST_NODE *c, EXITNODETEST_NODE *gw4, EXITNODETEST_NODE *gw6)
{
	CONTROL_STATE st;
	CONTROL_PEER peers[2];

	ExitNodeTestState(&st, EXITNODETEST_NODE_C);
	ExitNodeTestAddress(&st.Addresses[0], "default", exitnodetest_c4, 4, 10);
	ExitNodeTestAddress(&st.Addresses[1], "default6", exitnodetest_c6, 16, 64);
	st.NumAddresses = 2;

	ExitNodeTestPeer(&peers[0], EXITNODETEST_GW4, gw4->Key.Public);
	ExitNodeTestAddress(&peers[0].Addresses[0], "default", exitnodetest_gw4, 4, 10);
	peers[0].NumAddresses = 1;
	ExitNodeTestDefault(&peers[0].Routes[0], 4);
	peers[0].NumRoutes = 1;

	ExitNodeTestPeer(&peers[1], EXITNODETEST_GW6, gw6->Key.Public);
	ExitNodeTestAddress(&peers[1].Addresses[0], "default", exitnodetest_gw6, 4, 10);
	ExitNodeTestAddress(&peers[1].Addresses[1], "default6", exitnodetest_gw6_6, 16, 64);
	peers[1].NumAddresses = 2;
	ExitNodeTestDefault(&peers[1].Routes[0], 4);
	ExitNodeTestDefault(&peers[1].Routes[1], 16);
	peers[1].NumRoutes = 2;

	st.Peers = peers;
	st.NumPeers = 2;

	return NodeOverlayApply(c->Node, &st);
}

// The state of an exit node: its addresses, node-c as its peer, and the LAN subnets of its default routes, which lead to its
// host
static bool ExitNodeTestApplyExit(EXITNODETEST_NODE *gw, char *name, bool ipv6, const UCHAR *client_key)
{
	CONTROL_STATE st;
	CONTROL_PEER peer;

	ExitNodeTestState(&st, name);
	ExitNodeTestAddress(&st.Addresses[0], "default", ipv6 ? exitnodetest_gw6 : exitnodetest_gw4, 4, 10);
	st.NumAddresses = 1;
	ExitNodeTestDefault(&st.LanSubnets[0], 4);
	st.NumLanSubnets = 1;
	if (ipv6)
	{
		ExitNodeTestAddress(&st.Addresses[1], "default6", exitnodetest_gw6_6, 16, 64);
		st.NumAddresses = 2;
		ExitNodeTestDefault(&st.LanSubnets[1], 16);
		st.NumLanSubnets = 2;
	}

	ExitNodeTestPeer(&peer, EXITNODETEST_NODE_C, client_key);
	ExitNodeTestAddress(&peer.Addresses[0], "default", exitnodetest_c4, 4, 10);
	ExitNodeTestAddress(&peer.Addresses[1], "default6", exitnodetest_c6, 16, 64);
	peer.NumAddresses = 2;

	st.Peers = &peer;
	st.NumPeers = 1;

	return NodeOverlayApply(gw->Node, &st);
}

// An exit node with its listener, its static key from the scalar bytes first + i, its fake host and its state
static bool ExitNodeTestExitStart(EXITNODETEST_NODE *gw, char *name, bool ipv6, UCHAR first, char *thumbprint, const UCHAR *client_key)
{
	NODE_OVERLAY_CONFIG cfg;
	UCHAR scalar[PEER_KEY_SIZE];

	for (UINT i = 0;i < PEER_KEY_SIZE;i++)
	{
		scalar[i] = (UCHAR)(first + i);
	}
	bool ok = PeerKeyFromScalar(&gw->Key, scalar);
	Zero(scalar, sizeof(scalar));

	gw->Server = ExitNodeTestServerNew(thumbprint);
	ok = ok && gw->Server->Listener != NULL;

	ExitNodeTestNewDir(gw->Dir, sizeof(gw->Dir), name, "none", NULL, NULL);
	gw->Node = NewNode(gw->Dir);
	NodeStart(gw->Node);

	Zero(&cfg, sizeof(cfg));
	cfg.Data = &gw->Server->Transport;
	cfg.Key = &gw->Key;
	cfg.Adapter = ExitNodeTestHost;
	cfg.AdapterParam = &gw->Host;

	return ok && NodeOverlayStart(gw->Node, &cfg) && ExitNodeTestApplyExit(gw, name, ipv6, client_key);
}

// The number of Noise sessions of the overlay of a node
static UINT ExitNodeTestLinks(EXITNODETEST_NODE *t)
{
	NODE_OVERLAY_STATUS st;

	NodeOverlayGetStatus(t->Node, &st);

	return st.NumLinks;
}

// Whether node-c has its sessions to both exit nodes, and its addresses on its adapter, within EXITNODETEST_BOUND
static bool ExitNodeTestWaitUp(EXITNODETEST_NODE *c)
{
	for (UINT64 end = Tick64() + EXITNODETEST_BOUND;Tick64() < end;SleepThread(EXITNODETEST_POLL))
	{
		NODE_CLIENT_STATUS cs;
		MIB_UNICASTIPADDRESS_ROW v4, v6;

		NodeClientGetStatus(c->Node, &cs);
		InitializeUnicastIpAddressEntry(&v4);
		v4.InterfaceLuid.Value = cs.InterfaceLuid;
		v4.Address.si_family = AF_INET;
		Copy(&v4.Address.Ipv4.sin_addr, exitnodetest_c4, 4);
		InitializeUnicastIpAddressEntry(&v6);
		v6.InterfaceLuid.Value = cs.InterfaceLuid;
		v6.Address.si_family = AF_INET6;
		Copy(&v6.Address.Ipv6.sin6_addr, exitnodetest_c6, 16);

		if (cs.Running && cs.InterfaceLuid != 0 && ExitNodeTestLinks(c) == 2 &&
			GetUnicastIpAddressEntry(&v4) == NO_ERROR && v4.DadState == IpDadStatePreferred &&
			GetUnicastIpAddressEntry(&v6) == NO_ERROR && v6.DadState == IpDadStatePreferred)
		{
			return true;
		}
	}

	return false;
}

//
// The logged-in user
//

// One command through the pipe of the client role, as ranz tray sends it: the line of the answer into reply. False when the
// pipe cannot be opened or does not answer.
static bool ExitNodeTestPipe(wchar_t *pipe, char *command, char *reply, UINT size)
{
	char line[MAX_SIZE];
	DWORD n = 0;
	UINT used = 0;
	HANDLE h = INVALID_HANDLE_VALUE;

	StrCpy(reply, size, "");

	for (UINT64 end = Tick64() + EXITNODETEST_REPLY;;)
	{
		h = CreateFileW(pipe, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
		if (h != INVALID_HANDLE_VALUE)
		{
			break;
		}

		if (GetLastError() != ERROR_PIPE_BUSY || Tick64() >= end)
		{
			return false;
		}
		WaitNamedPipeW(pipe, 200);
	}

	Format(line, sizeof(line), "%s\n", command);
	bool ok = (WriteFile(h, line, StrLen(line), &n, NULL) && n == StrLen(line));

	while (ok && used + 1 < size)
	{
		char ch = 0;

		ok = (ReadFile(h, &ch, 1, &n, NULL) && n == 1);
		if (ok == false || ch == '\n')
		{
			break;
		}
		reply[used++] = ch;
	}
	reply[used] = 0;

	CloseHandle(h);

	return ok;
}

//
// The routes of the runner
//

// The address bytes of a SOCKADDR_INET whose address has size bytes
static UCHAR *ExitNodeTestSockBytes(SOCKADDR_INET *s, UINT size)
{
	return (size == 4 ? (UCHAR *)&s->Ipv4.sin_addr : (UCHAR *)&s->Ipv6.sin6_addr);
}

// Whether the interface of luid holds the route of the prefix of length bits at prefix, of size bytes
static bool ExitNodeTestRouteOn(UINT64 luid, const UCHAR *prefix, UINT size, UINT length)
{
	MIB_IPFORWARD_TABLE2 *table = NULL;
	bool found = false;

	if (GetIpForwardTable2((ADDRESS_FAMILY)(size == 4 ? AF_INET : AF_INET6), &table) != NO_ERROR)
	{
		return false;
	}

	for (ULONG i = 0;i < table->NumEntries && found == false;i++)
	{
		MIB_IPFORWARD_ROW2 *r = &table->Table[i];

		found = (r->InterfaceLuid.Value == luid && r->DestinationPrefix.PrefixLength == length &&
			Cmp(ExitNodeTestSockBytes(&r->DestinationPrefix.Prefix, size), prefix, size) == 0);
	}

	FreeMibTable(table);

	return found;
}

// The route that Windows takes to dst, of size bytes, for an application that names no source: its interface and its
// prefix length into *luid and *length, and a line for the log into detail. False when there is none.
static bool ExitNodeTestBest(const UCHAR *dst, UINT size, UINT64 *luid, UINT *length, char *detail, UINT detail_size)
{
	SOCKADDR_INET d;
	SOCKADDR_INET src;
	MIB_IPFORWARD_ROW2 best;
	char text[64];

	Zero(&d, sizeof(d));
	Zero(&src, sizeof(src));
	Zero(&best, sizeof(best));
	d.si_family = (ADDRESS_FAMILY)(size == 4 ? AF_INET : AF_INET6);
	Copy(ExitNodeTestSockBytes(&d, size), dst, size);

	DWORD err = GetBestRoute2(NULL, 0, NULL, &d, 0, &best, &src);
	*luid = (err == NO_ERROR ? best.InterfaceLuid.Value : 0);
	*length = (err == NO_ERROR ? best.DestinationPrefix.PrefixLength : 0);

	if (inet_ntop(size == 4 ? AF_INET : AF_INET6, dst, text, sizeof(text)) == NULL)
	{
		StrCpy(text, sizeof(text), "?");
	}
	Format(detail, detail_size, "GetBestRoute2 to %s: error %u, interface LUID %I64u, prefix length %u", text, (UINT)err, *luid, *length);

	return (err == NO_ERROR);
}

// A datagram from the runner's stack, from the address of node-c of the family of size and EXITNODETEST_CLIENT_PORT to dst
// and EXITNODETEST_UDP_PORT. *sent: whether the stack took it, which it does only through a route of the adapter that holds
// the source. With expect_reply, whether the same data came back from dst within EXITNODETEST_REPLY; without, whether nothing
// came within EXITNODETEST_SILENCE.
static bool ExitNodeTestDatagram(const UCHAR *dst, UINT size, char *data, bool expect_reply, bool *sent)
{
	SOCKADDR_INET local, remote, from;
	int from_len = sizeof(from);
	int addr_len = (size == 4 ? (int)sizeof(SOCKADDR_IN) : (int)sizeof(SOCKADDR_IN6));
	DWORD timeout = (expect_reply ? EXITNODETEST_REPLY : EXITNODETEST_SILENCE);
	BOOL exclusive = TRUE;
	char buf[256];
	bool ok = false;

	*sent = false;

	SOCKET s = socket(size == 4 ? AF_INET : AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
	if (s == INVALID_SOCKET)
	{
		return false;
	}

	Zero(&local, sizeof(local));
	Zero(&remote, sizeof(remote));
	Zero(&from, sizeof(from));
	local.si_family = (ADDRESS_FAMILY)(size == 4 ? AF_INET : AF_INET6);
	remote.si_family = local.si_family;
	Copy(ExitNodeTestSockBytes(&local, size), size == 4 ? exitnodetest_c4 : exitnodetest_c6, size);
	Copy(ExitNodeTestSockBytes(&remote, size), dst, size);
	if (size == 4)
	{
		local.Ipv4.sin_port = htons(EXITNODETEST_CLIENT_PORT);
		remote.Ipv4.sin_port = htons(EXITNODETEST_UDP_PORT);
	}
	else
	{
		local.Ipv6.sin6_port = htons(EXITNODETEST_CLIENT_PORT);
		remote.Ipv6.sin6_port = htons(EXITNODETEST_UDP_PORT);
	}

	setsockopt(s, SOL_SOCKET, SO_EXCLUSIVEADDRUSE, (char *)&exclusive, sizeof(exclusive));
	setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout, sizeof(timeout));

	int len = (int)StrLen(data);
	if (bind(s, (struct sockaddr *)&local, addr_len) == 0 && sendto(s, data, len, 0, (struct sockaddr *)&remote, addr_len) == len)
	{
		*sent = true;

		int n = recvfrom(s, buf, sizeof(buf), 0, (struct sockaddr *)&from, &from_len);
		if (expect_reply)
		{
			ok = (n == len && Cmp(buf, data, (UINT)n) == 0 && Cmp(ExitNodeTestSockBytes(&from, size), dst, size) == 0);
		}
		else
		{
			ok = (n == SOCKET_ERROR && WSAGetLastError() == WSAETIMEDOUT);
		}
	}

	closesocket(s);

	return ok;
}

//
// The steps
//

// The exit nodes of the status, and none chosen: no default route on the adapter, and no datagram enters it to the internet
static void ExitNodeTestNone(EXITNODETEST_CTX *ctx, wchar_t *pipe, UINT64 luid, char *what)
{
	char reply[NODE_CLIENT_REPLY];
	bool sent = false;

	bool ok = ExitNodeTestPipe(pipe, "status", reply, sizeof(reply));
	Print("  [INFO] status: %s\n", reply);
	ExitNodeTestCheck(ctx, ok && InStr(reply, "\"exit\":null") &&
		InStr(reply, "{\"name\":\"" EXITNODETEST_GW4 "\",\"vrf\":1,\"vrfName\":\"" EXITNODETEST_VRF_NAME "\",\"ipv4\":true,\"ipv6\":false}") &&
		InStr(reply, "{\"name\":\"" EXITNODETEST_GW6 "\",\"vrf\":1,\"vrfName\":\"" EXITNODETEST_VRF_NAME "\",\"ipv4\":true,\"ipv6\":true}"),
		what, "answer %s", reply);

	ExitNodeTestCheck(ctx, ExitNodeTestRouteOn(luid, exitnodetest_any, 4, 0) == false && ExitNodeTestRouteOn(luid, exitnodetest_any, 16, 0) == false,
		"no exit chosen: the adapter holds no default route of either family", "the adapter holds one");

	bool silent = ExitNodeTestDatagram(exitnodetest_net4, 4, EXITNODETEST_DATA_4, false, &sent);
	ExitNodeTestCheck(ctx, sent == false || silent, "no exit chosen: a datagram of node-c to an address of the internet does not enter the adapter",
		"the stack took it, and an answer came");
}

// exit gw4: the default routes of both families on the adapter, IPv4 through gw4, IPv6 into the adapter and nowhere further
static void ExitNodeTestGw4(EXITNODETEST_CTX *ctx, wchar_t *pipe, EXITNODETEST_NODE *c, EXITNODETEST_NODE *gw4, EXITNODETEST_NODE *gw6, UINT64 luid,
	UINT64 server_luid, UINT server_length)
{
	char reply[NODE_CLIENT_REPLY];
	char detail[MAX_SIZE];
	NODE_CLIENT_STATUS before, after;
	UINT64 best = 0;
	UINT length = 0;
	bool sent = false;

	bool ok = ExitNodeTestPipe(pipe, "exit " EXITNODETEST_GW4, reply, sizeof(reply));
	Print("  [INFO] exit " EXITNODETEST_GW4 ": %s\n", reply);
	ExitNodeTestCheck(ctx, ok && InStr(reply, "\"exit\":{\"name\":\"" EXITNODETEST_GW4 "\",\"vrf\":1,\"active\":true,\"available\":true}"),
		"exit gw4: the logged-in user chooses the exit node gw4, which the node takes, with the default routes active", "answer %s", reply);

	ExitNodeTestCheck(ctx, ExitNodeTestRouteOn(luid, exitnodetest_any, 4, 0) && ExitNodeTestRouteOn(luid, exitnodetest_any, 16, 0),
		"exit gw4: the adapter of VRF 1 holds 0.0.0.0/0 and ::/0, though gw4 carries no IPv6", "the adapter lacks one");

	ExitNodeTestBest(exitnodetest_net4, 4, &best, &length, detail, sizeof(detail));
	ExitNodeTestCheck(ctx, best == luid && length == 0, "exit gw4: Windows takes the adapter to an IPv4 address of the internet, before the default route of the runner",
		"%s, the adapter's %I64u", detail, luid);
	ExitNodeTestBest(exitnodetest_net6, 16, &best, &length, detail, sizeof(detail));
	ExitNodeTestCheck(ctx, best == luid && length == 0, "exit gw4: Windows takes the adapter to an IPv6 address of the internet, so no IPv6 leaves by the physical interface",
		"%s, the adapter's %I64u", detail, luid);

	LONG got4 = ReadAcquire(&gw4->Host.Got4);
	bool back = ExitNodeTestDatagram(exitnodetest_net4, 4, EXITNODETEST_DATA_4, true, &sent);
	ExitNodeTestCheck(ctx, back && ReadAcquire(&gw4->Host.Got4) == got4 + 1, "exit gw4: a datagram to an IPv4 address of the internet reaches the host of gw4 and comes back",
		"sent %u, back %u, gw4 got %d before and %d now", (UINT)sent, (UINT)back, (int)got4, (int)ReadAcquire(&gw4->Host.Got4));

	NodeClientGetStatus(c->Node, &before);
	LONG got6 = ReadAcquire(&gw4->Host.Got6) + ReadAcquire(&gw6->Host.Got6);
	bool silent = ExitNodeTestDatagram(exitnodetest_net6, 16, EXITNODETEST_DATA_6, false, &sent);
	NodeClientGetStatus(c->Node, &after);
	ExitNodeTestCheck(ctx, sent && silent && after.ExitDropped6 > before.ExitDropped6 && after.FromHost > before.FromHost &&
		ReadAcquire(&gw4->Host.Got6) + ReadAcquire(&gw6->Host.Got6) == got6,
		"exit gw4: an IPv6 datagram enters the adapter, and the overlay drops it, since gw4 carries no IPv6: no host gets it",
		"sent %u, silent %u, IPv6 dropped %I64u before and %I64u after, packets of the host %I64u before and %I64u after", (UINT)sent, (UINT)silent,
		before.ExitDropped6, after.ExitDropped6, before.FromHost, after.FromHost);

	// The server address that the runner reaches through its default route keeps a host route through that interface
	if (server_luid != 0 && server_length == 0)
	{
		ExitNodeTestBest(exitnodetest_server, 4, &best, &length, detail, sizeof(detail));
		ExitNodeTestCheck(ctx, best == server_luid && length == 32 && after.NumBypass == 1,
			"exit gw4: the server address 192.0.2.10 keeps off the adapter, by a host route through the interface of the default route of the runner",
			"%s, the interface of the default route %I64u, %u bypass routes", detail, server_luid, after.NumBypass);
	}
	else
	{
		Print("  [INFO] the runner reaches 192.0.2.10 by no default route (interface LUID %I64u, prefix length %u): no bypass route to check\n", server_luid, server_length);
	}
}

// exit gw6 1: both families through gw6; exit with a name of no exit node is refused, and the choice stays
static void ExitNodeTestGw6(EXITNODETEST_CTX *ctx, wchar_t *pipe, EXITNODETEST_NODE *c, EXITNODETEST_NODE *gw6)
{
	char reply[NODE_CLIENT_REPLY];
	NODE_CLIENT_STATUS cs;
	bool sent4 = false, sent6 = false;

	bool ok = ExitNodeTestPipe(pipe, "exit " EXITNODETEST_GW6 " 1", reply, sizeof(reply));
	Print("  [INFO] exit " EXITNODETEST_GW6 " 1: %s\n", reply);
	ExitNodeTestCheck(ctx, ok && InStr(reply, "\"exit\":{\"name\":\"" EXITNODETEST_GW6 "\",\"vrf\":1,\"active\":true,\"available\":true}"),
		"exit gw6 1: the logged-in user chooses gw6 in VRF 1, which the node takes", "answer %s", reply);

	LONG got4 = ReadAcquire(&gw6->Host.Got4);
	LONG got6 = ReadAcquire(&gw6->Host.Got6);
	bool back4 = ExitNodeTestDatagram(exitnodetest_net4, 4, EXITNODETEST_DATA_4, true, &sent4);
	bool back6 = ExitNodeTestDatagram(exitnodetest_net6, 16, EXITNODETEST_DATA_6, true, &sent6);
	ExitNodeTestCheck(ctx, back4 && back6 && ReadAcquire(&gw6->Host.Got4) == got4 + 1 && ReadAcquire(&gw6->Host.Got6) == got6 + 1,
		"exit gw6: a datagram of each family to an address of the internet reaches the host of gw6 and comes back",
		"IPv4 sent %u back %u, IPv6 sent %u back %u, gw6 got %d and %d before, %d and %d now", (UINT)sent4, (UINT)back4, (UINT)sent6, (UINT)back6,
		(int)got4, (int)got6, (int)ReadAcquire(&gw6->Host.Got4), (int)ReadAcquire(&gw6->Host.Got6));

	ok = ExitNodeTestPipe(pipe, "exit nosuch", reply, sizeof(reply));
	NodeClientGetStatus(c->Node, &cs);
	ExitNodeTestCheck(ctx, ok && InStr(reply, "\"error\":\"no exit node named nosuch") && cs.ExitChosen && StrCmp(cs.Exit, EXITNODETEST_GW6) == 0 && cs.ExitActive,
		"exit nosuch: the node refuses a name of no exit node, and gw6 stays chosen", "answer %s, chosen %u %s, active %u", reply, (UINT)cs.ExitChosen, cs.Exit,
		(UINT)cs.ExitActive);
}

// down takes the default routes off the adapter, up brings them back
static void ExitNodeTestDownUp(EXITNODETEST_CTX *ctx, wchar_t *pipe, UINT64 luid)
{
	char reply[NODE_CLIENT_REPLY];

	bool ok = ExitNodeTestPipe(pipe, "down", reply, sizeof(reply));
	ExitNodeTestCheck(ctx, ok && InStr(reply, "\"state\":\"down\"") && ExitNodeTestRouteOn(luid, exitnodetest_any, 4, 0) == false &&
		ExitNodeTestRouteOn(luid, exitnodetest_any, 16, 0) == false,
		"down: the role is down, and the default routes of the exit node leave the adapter", "answer %s", reply);

	ok = ExitNodeTestPipe(pipe, "up", reply, sizeof(reply));
	ExitNodeTestCheck(ctx, ok && InStr(reply, "\"exit\":{\"name\":\"" EXITNODETEST_GW6 "\"") && ExitNodeTestRouteOn(luid, exitnodetest_any, 4, 0) &&
		ExitNodeTestRouteOn(luid, exitnodetest_any, 16, 0),
		"up: the role is up again, and the default routes of gw6 are back on the adapter", "answer %s", reply);
}

// exit none: no default route on the adapter, and the host route of the server address gone
static void ExitNodeTestClear(EXITNODETEST_CTX *ctx, wchar_t *pipe, EXITNODETEST_NODE *c, UINT64 luid, UINT64 server_luid, UINT server_length)
{
	char reply[NODE_CLIENT_REPLY];
	char detail[MAX_SIZE];
	NODE_CLIENT_STATUS cs;
	UINT64 best = 0;
	UINT length = 0;

	bool ok = ExitNodeTestPipe(pipe, "exit none", reply, sizeof(reply));
	NodeClientGetStatus(c->Node, &cs);
	ExitNodeTestCheck(ctx, ok && InStr(reply, "\"exit\":null") && cs.ExitChosen == false && cs.NumBypass == 0 &&
		ExitNodeTestRouteOn(luid, exitnodetest_any, 4, 0) == false && ExitNodeTestRouteOn(luid, exitnodetest_any, 16, 0) == false,
		"exit none: the node takes no exit node, the adapter holds no default route, and no host route of a server address is left",
		"answer %s, chosen %u, %u bypass routes", reply, (UINT)cs.ExitChosen, cs.NumBypass);

	ExitNodeTestBest(exitnodetest_net4, 4, &best, &length, detail, sizeof(detail));
	ExitNodeTestCheck(ctx, best != luid, "exit none: Windows takes the adapter to the internet no more", "%s", detail);

	if (server_luid != 0 && server_length == 0)
	{
		ExitNodeTestBest(exitnodetest_server, 4, &best, &length, detail, sizeof(detail));
		ExitNodeTestCheck(ctx, best == server_luid && length == 0, "exit none: the runner reaches the server address by its default route again", "%s", detail);
	}
}

// The test on node-c, gw4 and gw6
static void ExitNodeTestRun(EXITNODETEST_CTX *ctx)
{
	EXITNODETEST_NODE *c = ZeroMalloc(sizeof(EXITNODETEST_NODE));
	EXITNODETEST_NODE *gw4 = ZeroMalloc(sizeof(EXITNODETEST_NODE));
	EXITNODETEST_NODE *gw6 = ZeroMalloc(sizeof(EXITNODETEST_NODE));
	NODE_CLIENT_STATUS cs;
	PEER_KEY key;
	UCHAR client_key[PEER_KEY_SIZE];
	char thumbprint[MAX_SIZE];
	char identity[MAX_SIZE];
	wchar_t identity_w[MAX_SIZE];
	char adapter[MAX_SIZE];
	char pipe[MAX_SIZE];
	wchar_t pipe_w[MAX_PATH];
	char detail[MAX_SIZE];
	char *setting = ZeroMalloc(NODE_CLIENT_MAX_SETTING);
	UINT scope = 0;
	UINT r = Rand32() & 0xFFFF;
	UINT64 server_luid = 0;
	UINT server_length = 0;

	Zero(&key, sizeof(key));
	Format(identity, sizeof(identity), "Ranz exitnodetest %u", r);
	StrToUni(identity_w, sizeof(identity_w), identity);
	Format(adapter, sizeof(adapter), "RanzX%04x", r);
	Format(pipe, sizeof(pipe), "ranz-exitnodetest-%u", r);
	UniFormat(pipe_w, sizeof(pipe_w), L"\\\\.\\pipe\\%S", pipe);

	// The certificate of the exit nodes, which node-c pins
	StrCpy(thumbprint, sizeof(thumbprint), "");
	PCCERT_CONTEXT cert = CryptoCertCreateSelfSigned(EXITNODETEST_CN, EXITNODETEST_SAN, NULL, 30, scope);
	bool ok = ExitNodeTestCheck(ctx, cert != NULL && CryptoCertThumbprintStr(cert, thumbprint, sizeof(thumbprint)) && CryptoCertAddToStore(cert, NULL, scope),
		"the exit nodes: a self-signed ECDSA P-256 certificate in the My store, by its thumbprint", "CryptoCertCreateSelfSigned or the store failed");

	// The static key of node-c: its identity key in the key storage provider, which its role opens
	ok = ok && ExitNodeTestCheck(ctx, PeerKeyOpen(&key, identity_w), "node-c: its identity key in the software key storage provider", "PeerKeyOpen failed");
	Copy(client_key, key.Public, PEER_KEY_SIZE);
	PeerKeyClose(&key);

	if (ok)
	{
		bool up4 = ExitNodeTestExitStart(gw4, EXITNODETEST_GW4, false, 0x40, thumbprint, client_key);
		bool up6 = ExitNodeTestExitStart(gw6, EXITNODETEST_GW6, true, 0x50, thumbprint, client_key);
		ok = ExitNodeTestCheck(ctx, up4 && up6, "gw4 and gw6: their overlays run on their listeners of TLS-443 and apply their states, with their default routes as LAN subnets",
			"gw4 %u (port %u), gw6 %u (port %u)", (UINT)up4, (UINT)gw4->Server->Port, (UINT)up6, (UINT)gw6->Server->Port);
	}

	// node-c with the client role, both exit nodes its servers
	if (ok)
	{
		Format(setting, NODE_CLIENT_MAX_SETTING,
			"{\"adapter\":\"%s\",\"pipe\":\"%s\",\"servers\":[{\"name\":\"" EXITNODETEST_GW4 "\",\"thumbprint\":\"%s\",\"dial\":\"tls:127.0.0.1:%u\"},"
			"{\"name\":\"" EXITNODETEST_GW6 "\",\"thumbprint\":\"%s\",\"dial\":\"tls:127.0.0.1:%u\"}]}",
			adapter, pipe, thumbprint, (UINT)gw4->Server->Port, thumbprint, (UINT)gw6->Server->Port);

		ExitNodeTestNewDir(c->Dir, sizeof(c->Dir), "nodec", "client", identity, setting);
		c->Node = NewNode(c->Dir);
		NodeStart(c->Node);
		ok = ExitNodeTestApplyClient(c, gw4, gw6) && ExitNodeTestWaitUp(c);
		NodeClientGetStatus(c->Node, &cs);
		ExitNodeTestCheck(ctx, ok, "node-c: the client role runs on a Wintun adapter with both addresses of VRF 1 and a session to each exit node",
			"applied and up %u, interface %u, %I64u dials, transport %s", (UINT)ok, cs.InterfaceIndex, cs.NumDials, cs.Transport);
	}

	if (ok)
	{
		UINT64 luid = cs.InterfaceLuid;

		Print("[the exit nodes of the status, none chosen]\n");
		ExitNodeTestNone(ctx, pipe_w, luid, "status: gw4 (IPv4 only) and gw6 (both families) are the exit nodes of VRF 1, and none is chosen");

		// The server address that the runner reaches by its default route, as a stream of the role gives one
		ExitNodeTestBest(exitnodetest_server, 4, &server_luid, &server_length, detail, sizeof(detail));
		Print("  [INFO] before an exit: %s\n", detail);
		NodeClientServerAddress(c->Node, EXITNODETEST_SERVER);

		// From here until exit none the default routes of the adapter take the traffic of the runner: the steps are short
		Print("[exit gw4: an exit node that carries no IPv6]\n");
		ExitNodeTestGw4(ctx, pipe_w, c, gw4, gw6, luid, server_luid, server_length);

		Print("[exit gw6 1: an exit node that carries both families]\n");
		ExitNodeTestGw6(ctx, pipe_w, c, gw6);

		Print("[down and up]\n");
		ExitNodeTestDownUp(ctx, pipe_w, luid);

		Print("[exit none]\n");
		ExitNodeTestClear(ctx, pipe_w, c, luid, server_luid, server_length);
	}

	ExitNodeTestFreeNode(c);
	ExitNodeTestFreeNode(gw4);
	ExitNodeTestFreeNode(gw6);
	PeerKeyDelete(identity_w);

	if (cert != NULL)
	{
		CryptoCertRemoveFromStore(thumbprint, NULL, scope);
		CryptoCertDeleteKey(cert);
		CryptoCertFree(cert);
	}

	Free(setting);
	Free(c);
	Free(gw4);
	Free(gw6);
}

RANZ_TEST("exitnode", exitnode_test, "Exit node of the client role (SDN-55): the tray chooses an exit node through the pipe, the adapter takes 0.0.0.0/0 and ::/0, IPv4 goes through the exit, IPv6 to an exit without it enters the adapter and goes nowhere, and exit none takes it all back (administrator rights, wintun.dll).");
void exitnode_test(UINT num, char **arg)
{
	EXITNODETEST_CTX ctx;
	UINT error = 0;
	HANDLE done = CreateEventW(NULL, TRUE, FALSE, NULL);
	HANDLE watchdog = (done != NULL ? CreateThread(NULL, 0, ExitNodeTestWatchdog, done, 0, NULL) : NULL);

	Zero(&ctx, sizeof(ctx));

	Print("Exit node test: node-c on a Wintun adapter chooses gw4 and gw6 as its exit node through the pipe of its logged-in user\n");

	bool ready = ExitNodeTestCheck(&ctx, CryptoInit(), "the crypto module of the new core runs on CNG", "CryptoInit failed");
	ready = ExitNodeTestCheck(&ctx, NodeWintunAvailable(&error), "wintun.dll is next to vpntest and has the API of wintun.h", "error %u", error) && ready;

	if (ready)
	{
		ExitNodeTestRun(&ctx);
	}

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
		Print("EXITNODE TEST OK\n");
	}
	else
	{
		Print("EXITNODE TEST FAILED (%u of %u checks failed)\n", ctx.NumFailed, ctx.NumChecks);
	}
}
