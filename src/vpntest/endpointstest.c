// endpointstest.c
// Named endpoints test of vpntest ("endpoints" command, SDN-93 #410)
//
// The endpoints of a Node (Core/ControlEndpoint.c, Cedar/NodeEndpoints.c): the addresses under which the Controller says that
// each peer of a Node is reached, which the Peer object of its desired state carries. A Node dials a peer through them with
// the race of the fallback list, and the data transport of the client role turns the name of a peer into the entries of that
// race (Cedar/NodeClient.c).
// - The rules, which need no process: which of two Nodes dials (NodeEndpointsDials: the order of the static keys decides as
//   it did, a client dials every peer, a Node without endpoints always dials, and a peer without endpoints is not dialled),
//   and which endpoints make the entries of the fallback list (NodeEndpointsTargets: those of the transports that run here,
//   in their order).
// - The dial, with the real production data transport and listeners on the loopback interface. node-s is the hub: its
//   Listener of the desired state listens on test ports of every address, the front door on TCP and QUIC on UDP where
//   msquic.dll is present, with a certificate of the LocalMachine\My store, and its data transport listens nowhere, as that
//   of a Node service does. node-c is the client role on a Wintun adapter, whose Client setting names node-s and the
//   thumbprint of its certificate, and no fallback list. Both take their states from the test (NodeOverlayApply), as the
//   control stream gives them: VRF 1, node-c 100.64.0.2/10 and node-s 100.64.0.1/10, and the Peer object of node-s in the
//   state of node-c carries the endpoints of the step.
//   a. No endpoints: node-c does not dial, and does not retry in a loop.
//   b. Endpoints of a transport that does not run here only: the same.
//   c. The endpoints of the Listener, QUIC first: node-c dials, the first entry that connects wins, and the Noise session
//      comes up on both nodes, node-s taking the stream from its Listener.
//   d. The first entry reaches nothing: node-c sleeps and wakes, and the race goes on to TLS and the session comes up again.
// Print "ENDPOINTS TEST OK" only when every check passes. Needs administrator rights (the LocalMachine\My store, the Wintun
// adapter) and wintun.dll next to vpntest (.github/scripts/fetch-wintun.ps1).

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
#include "Mayaqua/Tick64.h"

#include "Core/Control.h"
#include "Core/Crypto.h"
#include "Core/Transport.h"

#include <WS2tcpip.h>

#include <stdio.h>

#define	ENDPOINTSTEST_WATCHDOG	240000		// The test process is aborted after this (ms)
#define	ENDPOINTSTEST_BOUND		20000		// A bounded wait on observable state (ms)
#define	ENDPOINTSTEST_POLL		20			// Poll interval of observable state (ms)
#define	ENDPOINTSTEST_QUIET		2200		// A node that must not dial is watched this long: two redial intervals of the overlay and more (ms)
#define	ENDPOINTSTEST_VRF		1			// The VRF of the test
#define	ENDPOINTSTEST_NODE_S	"node-s"	// The hub, whose Listener takes the dials
#define	ENDPOINTSTEST_NODE_C	"node-c"	// The client role, which dials it
#define	ENDPOINTSTEST_CN		L"CN=localhost"		// The subject of the certificate of node-s
#define	ENDPOINTSTEST_SAN		L"localhost"		// ... and its subject alternative name

// One node of the test
typedef struct ENDPOINTSTEST_NODE
{
	wchar_t Dir[MAX_PATH];				// Its data directory
	NODE *Node;
} ENDPOINTSTEST_NODE;

// The state of the test
typedef struct ENDPOINTSTEST_CTX
{
	UINT NumChecks;
	UINT NumFailed;
	ENDPOINTSTEST_NODE S;				// node-s, the hub
	ENDPOINTSTEST_NODE C;				// node-c, the client role
	PEER_KEY KeyS;						// The static key of node-s
	UCHAR KeyC[PEER_KEY_SIZE];			// ... and the one of node-c, its identity key
	wchar_t Identity[MAX_SIZE];			// The name of the identity key of node-c
	char Thumbprint[MAX_SIZE];			// The certificate of node-s, by its thumbprint
	PCCERT_CONTEXT Cert;				// ... in the LocalMachine\My store
	TRANSPORT None;						// The data transport of node-s: nowhere
	UINT64 GenS;						// The Generation of the last state applied to each node
	UINT64 GenC;
} ENDPOINTSTEST_CTX;

// A row of the rule that decides which of two nodes dials
typedef struct ENDPOINTSTEST_ROW
{
	bool ByName;						// The data transport finds a peer by its node name, as that of the harness does
	bool Dialler;						// The node is a client
	bool Lower;							// Its static key is the lower of the two
	UINT Own;							// The endpoints of the node itself
	bool Dialable;						// The data transport can dial the peer: it has an endpoint that runs here
	bool Dials;							// What the rule answers
	char *Why;
} ENDPOINTSTEST_ROW;

static bool EndpointsTestCheck(ENDPOINTSTEST_CTX *ctx, bool ok, char *what, char *fmt, ...) RANZ_PRINTF_FORMAT(4, 5);
static bool EndpointsTestCheck(ENDPOINTSTEST_CTX *ctx, bool ok, char *what, char *fmt, ...)
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

// The watchdog: a test that hangs ends the process
static DWORD WINAPI EndpointsTestWatchdog(LPVOID param)
{
	if (WaitForSingleObject((HANDLE)param, ENDPOINTSTEST_WATCHDOG) == WAIT_TIMEOUT)
	{
		Print("ENDPOINTS TEST FAILED (the watchdog ended it after %u ms)\n", ENDPOINTSTEST_WATCHDOG);
		fflush(stdout);
		ExitProcess(1);
	}

	return 0;
}

//
// The rules
//

// The rule that decides which of two nodes dials, for the data transport that finds a peer by its node name and for the one that
// dials through endpoints
static void EndpointsTestRules(ENDPOINTSTEST_CTX *ctx)
{
	static const ENDPOINTSTEST_ROW rows[] =
	{
		// By name, as the in-process transport of the harness does: the order of the keys decides, a client dials every peer,
		// and the endpoints change nothing
		{true, false, true, 0, false, true, "by name, the node with the lower key dials"},
		{true, false, false, 0, false, false, "by name, the node with the higher key accepts"},
		{true, true, false, 0, false, true, "by name, a client dials whatever the keys"},
		{true, false, true, 2, true, true, "by name, endpoints of both change nothing for the lower key"},
		{true, false, false, 2, true, false, "by name, endpoints of both change nothing for the higher key"},
		// Through endpoints: a peer without any that runs here is not dialled, not even by a client
		{false, false, true, 0, false, false, "a peer without endpoints is not dialled by the lower key"},
		{false, false, false, 0, false, false, "a peer without endpoints is not dialled by the higher key"},
		{false, true, true, 0, false, false, "a peer without endpoints is not dialled by a client"},
		// ... a peer with some is dialled by a node without endpoints and by a client, whatever the keys
		{false, false, false, 0, true, true, "a node without endpoints dials, also with the higher key"},
		{false, false, true, 0, true, true, "a node without endpoints dials, also with the lower key"},
		{false, true, false, 2, true, true, "a client dials, also with endpoints and the higher key"},
		// ... and of two nodes that both have endpoints exactly one dials, the one with the lower key
		{false, false, true, 2, true, true, "of two nodes with endpoints the lower key dials"},
		{false, false, false, 2, true, false, "of two nodes with endpoints the higher key accepts"},
	};
	UCHAR low[PEER_KEY_SIZE];
	UCHAR high[PEER_KEY_SIZE];
	UINT bad = 0;
	char *first = "";

	Print("[the rule that decides which of two nodes dials]\n");

	Zero(low, sizeof(low));
	Zero(high, sizeof(high));
	low[0] = 1;
	high[0] = 2;

	for (UINT i = 0;i < sizeof(rows) / sizeof(rows[0]);i++)
	{
		const ENDPOINTSTEST_ROW *r = &rows[i];
		bool dials = NodeEndpointsDials(r->ByName, r->Dialler, r->Lower ? low : high, r->Lower ? high : low, r->Own, r->Dialable);

		if (dials != r->Dials)
		{
			if (bad == 0)
			{
				first = r->Why;
			}
			bad++;
		}
	}

	EndpointsTestCheck(ctx, bad == 0, "the rule of the order of the keys stays, a client dials every peer, a node without endpoints always dials, and a peer without endpoints is not dialled",
		"%u rows differ, the first is \"%s\"", bad, first);
}

// An endpoint of transport at address
static void EndpointsTestListed(CONTROL_ENDPOINT *e, char *transport, char *address)
{
	Zero(e, sizeof(CONTROL_ENDPOINT));
	StrCpy(e->Transport, sizeof(e->Transport), transport);
	StrCpy(e->Address, sizeof(e->Address), address);
}

// The entries of the fallback list that endpoints make
static void EndpointsTestTargets(ENDPOINTSTEST_CTX *ctx)
{
	TRANSPORT quic;
	TRANSPORT tls;
	TRANSPORT *known[2];
	TRANSPORT *without_quic[2];
	TRANSPORT_TARGET targets[TRANSPORT_MAX_TARGETS];
	CONTROL_ENDPOINT e[4];

	Print("[the entries of the fallback list that the endpoints make]\n");

	Zero(&quic, sizeof(quic));
	Zero(&tls, sizeof(tls));
	StrCpy(quic.Name, sizeof(quic.Name), "quic");
	StrCpy(tls.Name, sizeof(tls.Name), "tls");
	known[0] = &quic;
	known[1] = &tls;
	// msquic.dll is missing: QUIC cannot run here
	without_quic[0] = NULL;
	without_quic[1] = &tls;

	EndpointsTestListed(&e[0], "tls", "hub.example.com:443");
	EndpointsTestListed(&e[1], "mimic", "hub.example.com:8443");
	EndpointsTestListed(&e[2], "quic", "198.51.100.7:443");
	EndpointsTestListed(&e[3], "quic", "[2001:db8::1]:443");

	UINT num = NodeEndpointsTargets(e, 4, known, 2, targets, TRANSPORT_MAX_TARGETS);
	EndpointsTestCheck(ctx, num == 3 && targets[0].Transport == &tls && StrCmp(targets[0].Address, "hub.example.com:443") == 0 &&
		targets[1].Transport == &quic && StrCmp(targets[1].Address, "198.51.100.7:443") == 0 &&
		targets[2].Transport == &quic && StrCmp(targets[2].Address, "[2001:db8::1]:443") == 0,
		"the endpoints make the entries of the list in their order, and one of a transport that does not run here is left out", "%u entries", num);

	EndpointsTestCheck(ctx, NodeEndpointsTargets(e, 4, known, 2, NULL, 0) == 3, "without a list the entries are only counted", "not 3");

	num = NodeEndpointsTargets(e, 4, known, 2, targets, 2);
	EndpointsTestCheck(ctx, num == 2 && targets[1].Transport == &quic && StrCmp(targets[1].Address, "198.51.100.7:443") == 0,
		"the list holds at most max entries, the first ones", "%u entries", num);

	num = NodeEndpointsTargets(e, 4, without_quic, 2, targets, TRANSPORT_MAX_TARGETS);
	EndpointsTestCheck(ctx, num == 1 && targets[0].Transport == &tls && StrCmp(targets[0].Address, "hub.example.com:443") == 0,
		"without QUIC here the QUIC endpoints are left out and the others still dial", "%u entries", num);

	EndpointsTestCheck(ctx, NodeEndpointsTargets(e, 4, known, 0, targets, TRANSPORT_MAX_TARGETS) == 0 && NodeEndpointsTargets(NULL, 0, known, 2, targets, TRANSPORT_MAX_TARGETS) == 0,
		"no transport, or no endpoint, makes no entry", "an entry came out");
}

//
// The nodes
//

// The data transport of node-s, as that of a Node service has it: it dials no peer and listens nowhere, so the streams of
// node-s are those that its Listener takes
static bool EndpointsTestNoDial(void *param, const char *address, HANDLE cancel, void **stream)
{
	*stream = NULL;
	return false;
}

static bool EndpointsTestNoListen(void *param, const char *address, void **listener)
{
	*listener = NULL;
	return false;
}

static bool EndpointsTestNoAccept(void *listener, UINT timeout, void **stream)
{
	*stream = NULL;
	return false;
}

static void EndpointsTestNoCloseListener(void *listener)
{
	return;
}

static UINT EndpointsTestNoRead(void *stream, void *buf, UINT size, UINT timeout)
{
	return 0;
}

static bool EndpointsTestNoWrite(void *stream, const void *buf, UINT size)
{
	return false;
}

static void EndpointsTestNoClose(void *stream)
{
	return;
}

// A new empty data directory under the temp directory of the process, with a configuration store: the roles, one worker, and
// the identity key and the Client setting when they are not NULL
static void EndpointsTestNewDir(wchar_t *dir, UINT size, char *name, char *roles, char *identity, char *client)
{
	wchar_t tmp[MAX_PATH];
	wchar_t path[MAX_PATH];

	UniFormat(tmp, sizeof(tmp), L"endpointstest_%S_%u", name, Rand32());
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

// Delete the files of a directory, then the directory
static void EndpointsTestDeleteDir(wchar_t *dir)
{
	DIRLIST *d = EnumDirW(dir);

	for (UINT i = 0;d != NULL && i < d->NumFiles;i++)
	{
		DIRENT *e = d->File[i];
		wchar_t path[MAX_PATH];

		ConbinePathW(path, sizeof(path), dir, e->FileNameW);
		if (e->Folder)
		{
			EndpointsTestDeleteDir(path);
		}
		else
		{
			FileDeleteW(path);
		}
	}

	FreeDir(d);
	DeleteDirW(dir);
}

// The address 100.64.0.last/10 of the Network default in VRF 1
static void EndpointsTestAddress(CONTROL_ADDRESS *a, UCHAR last)
{
	UCHAR address[4] = {100, 64, 0, 0};

	address[3] = last;

	Zero(a, sizeof(CONTROL_ADDRESS));
	StrCpy(a->Network, sizeof(a->Network), "default");
	a->VrfId = ENDPOINTSTEST_VRF;
	Copy(a->Address, address, 4);
	a->AddressSize = 4;
	a->Length = 10;
}

// Apply a state of node-s to its overlay, as the control stream does: its address, node-c as its peer, and the Listener l
static bool EndpointsTestApplyS(ENDPOINTSTEST_CTX *ctx, CONTROL_LISTENER *l)
{
	CONTROL_STATE st;
	CONTROL_PEER peer;

	Zero(&st, sizeof(st));
	Zero(&peer, sizeof(peer));

	st.Generation = ++ctx->GenS;
	StrCpy(st.Name, sizeof(st.Name), ENDPOINTSTEST_NODE_S);
	EndpointsTestAddress(&st.Addresses[0], 1);
	st.NumAddresses = 1;

	StrCpy(peer.Name, sizeof(peer.Name), ENDPOINTSTEST_NODE_C);
	Copy(peer.Key, ctx->KeyC, PEER_KEY_SIZE);
	peer.NumVrfs = 1;
	peer.VrfIds[0] = ENDPOINTSTEST_VRF;
	EndpointsTestAddress(&peer.Addresses[0], 2);
	peer.NumAddresses = 1;
	st.Peers = &peer;
	st.NumPeers = 1;

	st.Listener = l;

	return NodeOverlayApply(ctx->S.Node, &st);
}

// Apply a state of node-c to its overlay: its address, and node-s as its peer, with the num endpoints in its Peer object
static bool EndpointsTestApplyC(ENDPOINTSTEST_CTX *ctx, const CONTROL_ENDPOINT *e, UINT num)
{
	CONTROL_STATE st;
	CONTROL_PEER peer;

	Zero(&st, sizeof(st));
	Zero(&peer, sizeof(peer));

	st.Generation = ++ctx->GenC;
	StrCpy(st.Name, sizeof(st.Name), ENDPOINTSTEST_NODE_C);
	EndpointsTestAddress(&st.Addresses[0], 2);
	st.NumAddresses = 1;

	StrCpy(peer.Name, sizeof(peer.Name), ENDPOINTSTEST_NODE_S);
	Copy(peer.Key, ctx->KeyS.Public, PEER_KEY_SIZE);
	peer.NumVrfs = 1;
	peer.VrfIds[0] = ENDPOINTSTEST_VRF;
	EndpointsTestAddress(&peer.Addresses[0], 1);
	peer.NumAddresses = 1;
	if (num != 0)
	{
		Copy(peer.Endpoints, e, sizeof(CONTROL_ENDPOINT) * num);
		peer.NumEndpoints = num;
	}
	st.Peers = &peer;
	st.NumPeers = 1;

	return NodeOverlayApply(ctx->C.Node, &st);
}

// An endpoint of transport at the port of the loopback interface
static void EndpointsTestEndpoint(CONTROL_ENDPOINT *e, char *transport, UINT port)
{
	char address[MAX_SIZE];

	Format(address, sizeof(address), "127.0.0.1:%u", port);
	EndpointsTestListed(e, transport, address);
}

// A UDP port of 127.0.0.1 where nothing listens: one that the system gave a socket a moment ago
static USHORT EndpointsTestDeadPort()
{
	struct sockaddr_in a;
	int len = sizeof(a);
	USHORT port = 0;

	SOCKET s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (s == INVALID_SOCKET)
	{
		return 9;
	}

	Zero(&a, sizeof(a));
	a.sin_family = AF_INET;
	a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	if (bind(s, (struct sockaddr *)&a, sizeof(a)) == 0 && getsockname(s, (struct sockaddr *)&a, &len) == 0)
	{
		port = ntohs(a.sin_port);
	}

	closesocket(s);

	return (port != 0 ? port : 9);
}

// The number of Noise sessions of the overlay of a node
static UINT EndpointsTestLinks(NODE *n)
{
	NODE_OVERLAY_STATUS st;

	NodeOverlayGetStatus(n, &st);

	return st.NumLinks;
}

// Whether the session of node-c to node-s is up on both nodes within ENDPOINTSTEST_BOUND, with node-c having connected more
// streams than dials: a session that an earlier dial made does not count
static bool EndpointsTestWaitUp(ENDPOINTSTEST_CTX *ctx, UINT64 dials)
{
	for (UINT64 end = Tick64() + ENDPOINTSTEST_BOUND;Tick64() < end;SleepThread(ENDPOINTSTEST_POLL))
	{
		NODE_CLIENT_STATUS cs;

		NodeClientGetStatus(ctx->C.Node, &cs);
		if (cs.NumDials > dials && EndpointsTestLinks(ctx->C.Node) == 1 && EndpointsTestLinks(ctx->S.Node) == 1)
		{
			return true;
		}
	}

	return false;
}

// Whether node-c has no session within ENDPOINTSTEST_BOUND
static bool EndpointsTestWaitDown(ENDPOINTSTEST_CTX *ctx)
{
	for (UINT64 end = Tick64() + ENDPOINTSTEST_BOUND;Tick64() < end;SleepThread(ENDPOINTSTEST_POLL))
	{
		if (EndpointsTestLinks(ctx->C.Node) == 0)
		{
			return true;
		}
	}

	return false;
}

// Whether node-c dials nothing while ENDPOINTSTEST_QUIET passes: its overlay starts no dial, its role connects no stream, it
// has no session, and the Listener of node-s takes no stream. What it saw into detail.
static bool EndpointsTestQuiet(ENDPOINTSTEST_CTX *ctx, char *detail, UINT size)
{
	NODE_OVERLAY_STATUS os;
	NODE_CLIENT_STATUS cs;
	NODE_LISTENER_STATUS ls;

	SleepThread(ENDPOINTSTEST_QUIET);

	NodeOverlayGetStatus(ctx->C.Node, &os);
	NodeClientGetStatus(ctx->C.Node, &cs);
	NodeListenerGetStatus(ctx->S.Node, &ls);
	Format(detail, size, "%I64u dials of the overlay, %I64u streams of the role, %u sessions, %I64u streams that node-s took", os.Dials, cs.NumDials, os.NumLinks, ls.Accepted);

	return (os.Dials == 0 && cs.NumDials == 0 && os.NumLinks == 0 && ls.Accepted == 0);
}

// The keys of both nodes and the certificate of node-s: its static key, the identity key of node-c in the software key storage
// provider, which the role opens, and a self-signed ECDSA P-256 certificate of the LocalMachine\My store
static bool EndpointsTestKeys(ENDPOINTSTEST_CTX *ctx, UINT id)
{
	PEER_KEY key;
	UCHAR scalar[PEER_KEY_SIZE];
	char identity[MAX_SIZE];

	Zero(&key, sizeof(key));
	StrCpy(ctx->Thumbprint, sizeof(ctx->Thumbprint), "");

	ctx->Cert = CryptoCertCreateSelfSigned(ENDPOINTSTEST_CN, ENDPOINTSTEST_SAN, NULL, 30, CRYPTO_MACHINE);
	bool ok = EndpointsTestCheck(ctx, ctx->Cert != NULL && CryptoCertThumbprintStr(ctx->Cert, ctx->Thumbprint, sizeof(ctx->Thumbprint)) &&
		CryptoCertAddToStore(ctx->Cert, NULL, CRYPTO_MACHINE),
		"node-s: a self-signed ECDSA P-256 certificate in the LocalMachine\\My store, by its thumbprint", "CryptoCertCreateSelfSigned or the store failed");

	for (UINT i = 0;i < PEER_KEY_SIZE;i++)
	{
		scalar[i] = (UCHAR)(0x91 + i);
	}
	ok = EndpointsTestCheck(ctx, PeerKeyFromScalar(&ctx->KeyS, scalar), "node-s: its static key", "PeerKeyFromScalar failed") && ok;
	Zero(scalar, sizeof(scalar));

	Format(identity, sizeof(identity), "Ranz endpointstest %u", id);
	StrToUni(ctx->Identity, sizeof(ctx->Identity), identity);
	ok = EndpointsTestCheck(ctx, PeerKeyOpen(&key, ctx->Identity), "node-c: its identity key in the software key storage provider", "PeerKeyOpen failed") && ok;
	Copy(ctx->KeyC, key.Public, PEER_KEY_SIZE);
	PeerKeyClose(&key);

	return ok;
}

// node-s: its overlay over a data transport that listens nowhere, and the state with the Listener of the certificate, which
// binds test ports: the ports into ctx are read from its status by the steps
static bool EndpointsTestStartS(ENDPOINTSTEST_CTX *ctx)
{
	NODE_OVERLAY_CONFIG cfg;
	CONTROL_LISTENER listener;
	NODE_LISTENER_STATUS ls;

	EndpointsTestNewDir(ctx->S.Dir, sizeof(ctx->S.Dir), "s", "none", NULL, NULL);
	ctx->S.Node = NewNode(ctx->S.Dir);
	NodeStart(ctx->S.Node);

	Zero(&ctx->None, sizeof(ctx->None));
	StrCpy(ctx->None.Name, sizeof(ctx->None.Name), "none");
	ctx->None.Dial = EndpointsTestNoDial;
	ctx->None.Listen = EndpointsTestNoListen;
	ctx->None.Accept = EndpointsTestNoAccept;
	ctx->None.CloseListener = EndpointsTestNoCloseListener;
	ctx->None.Read = EndpointsTestNoRead;
	ctx->None.Write = EndpointsTestNoWrite;
	ctx->None.Close = EndpointsTestNoClose;

	Zero(&cfg, sizeof(cfg));
	cfg.Data = &ctx->None;
	cfg.Key = &ctx->KeyS;
	bool ok = NodeOverlayStart(ctx->S.Node, &cfg);

	// Ports 0, which the node binds as ports that the system picks: test ports of every address, never 443
	Zero(&listener, sizeof(listener));
	StrCpy(listener.Name, sizeof(listener.Name), "edge");
	listener.Source = CONTROL_CERT_KSP;
	StrCpy(listener.Thumbprint, sizeof(listener.Thumbprint), ctx->Thumbprint);
	bool applied = (ok && EndpointsTestApplyS(ctx, &listener));
	NodeListenerGetStatus(ctx->S.Node, &ls);

	return EndpointsTestCheck(ctx, applied && ls.Running && ls.Port != 0 && StrCmp(ls.Thumbprint, ctx->Thumbprint) == 0,
		"node-s: its overlay runs over a data transport that listens nowhere, and its Listener listens with the certificate",
		"overlay %u, state applied %u, running %u, port %u, certificate %s, error %s", (UINT)ok, (UINT)applied, (UINT)ls.Running, ls.Port, ls.Thumbprint, ls.Error);
}

// node-c: the client role, whose Client setting names node-s with the thumbprint of its certificate and no fallback list
static bool EndpointsTestStartC(ENDPOINTSTEST_CTX *ctx, UINT id)
{
	NODE_CLIENT_STATUS cs;
	char identity[MAX_SIZE];
	char pipe[MAX_SIZE];
	char setting[MAX_SIZE * 4];

	UniToStr(identity, sizeof(identity), ctx->Identity);
	Format(pipe, sizeof(pipe), "ranz-endpointstest-%u", id);
	Format(setting, sizeof(setting), "{\"adapter\":\"RanzE%u\",\"pipe\":\"%s\",\"servers\":[{\"name\":\"" ENDPOINTSTEST_NODE_S "\",\"thumbprint\":\"%s\"}]}",
		id, pipe, ctx->Thumbprint);

	EndpointsTestNewDir(ctx->C.Dir, sizeof(ctx->C.Dir), "c", "client", identity, setting);
	ctx->C.Node = NewNode(ctx->C.Dir);
	NodeStart(ctx->C.Node);
	NodeClientGetStatus(ctx->C.Node, &cs);

	return EndpointsTestCheck(ctx, cs.Running && Cmp(cs.Key, ctx->KeyC, PEER_KEY_SIZE) == 0 && cs.NumServers == 1,
		"node-c: the client role runs on its identity key, with node-s in its Client setting and no fallback list", "running %u, %u servers", (UINT)cs.Running, cs.NumServers);
}

// Stop the nodes, node-c first, and delete what the test made
static void EndpointsTestStop(ENDPOINTSTEST_CTX *ctx)
{
	if (ctx->C.Node != NULL)
	{
		NodeStop(ctx->C.Node);
		FreeNode(ctx->C.Node);
		ctx->C.Node = NULL;
		EndpointsTestDeleteDir(ctx->C.Dir);
	}
	PeerKeyDelete(ctx->Identity);

	if (ctx->S.Node != NULL)
	{
		NodeOverlayStop(ctx->S.Node);
		NodeStop(ctx->S.Node);
		FreeNode(ctx->S.Node);
		ctx->S.Node = NULL;
		EndpointsTestDeleteDir(ctx->S.Dir);
	}
	PeerKeyClose(&ctx->KeyS);

	if (ctx->Cert != NULL)
	{
		CryptoCertRemoveFromStore(ctx->Thumbprint, NULL, CRYPTO_MACHINE);
		CryptoCertDeleteKey(ctx->Cert);
		CryptoCertFree(ctx->Cert);
		ctx->Cert = NULL;
	}
}

//
// The dial
//

// The steps, with both nodes running
static void EndpointsTestSteps(ENDPOINTSTEST_CTX *ctx)
{
	NODE_LISTENER_STATUS ls;
	NODE_CLIENT_STATUS cs;
	NODE_OVERLAY_STATUS os;
	CONTROL_ENDPOINT e[2];
	char detail[MAX_SIZE * 2];
	UINT n = 0;

	NodeListenerGetStatus(ctx->S.Node, &ls);
	UINT port = ls.Port;
	UINT quic_port = (TransportQuicAvailable() ? ls.QuicPort : 0);
	Print("  [INFO] node-s listens on TCP port %u and QUIC port %u (msquic.dll %s)\n", port, quic_port, TransportQuicAvailable() ? "present" : "missing");

	// No endpoints: nothing to dial
	Print("[a peer without endpoints]\n");
	bool applied = EndpointsTestApplyC(ctx, NULL, 0);
	bool quiet = EndpointsTestQuiet(ctx, detail, sizeof(detail));
	EndpointsTestCheck(ctx, applied && quiet, "node-c does not dial a peer without endpoints, and does not retry in a loop", "applied %u, %s", (UINT)applied, detail);

	// Endpoints that no transport here can dial
	Print("[a peer whose endpoints are of a transport that does not run here]\n");
	EndpointsTestEndpoint(&e[0], "nosuch", port);
	applied = EndpointsTestApplyC(ctx, e, 1);
	quiet = EndpointsTestQuiet(ctx, detail, sizeof(detail));
	EndpointsTestCheck(ctx, applied && quiet, "node-c does not dial a peer whose endpoints no transport here can dial, and does not retry in a loop", "applied %u, %s", (UINT)applied, detail);

	// The endpoints of the Listener of node-s: QUIC first where it runs, then TLS
	Print("[the endpoints of the Listener of node-s, QUIC first]\n");
	if (quic_port != 0)
	{
		EndpointsTestEndpoint(&e[n++], "quic", quic_port);
	}
	EndpointsTestEndpoint(&e[n++], "tls", port);
	applied = EndpointsTestApplyC(ctx, e, n);
	bool up = (applied && EndpointsTestWaitUp(ctx, 0));
	NodeClientGetStatus(ctx->C.Node, &cs);
	NodeOverlayGetStatus(ctx->C.Node, &os);
	NodeListenerGetStatus(ctx->S.Node, &ls);
	EndpointsTestCheck(ctx, up, "node-c dials node-s at its endpoints through the race of the fallback list, and the Noise session comes up on both nodes",
		"applied %u, up %u, %I64u streams connected, transport %s", (UINT)applied, (UINT)up, cs.NumDials, cs.Transport);
	EndpointsTestCheck(ctx, up && StrCmp(cs.Transport, quic_port != 0 ? "quic" : "tls") == 0, "the first entry of the list that connects wins", "transport %s, want %s", cs.Transport,
		quic_port != 0 ? "quic" : "tls");
	EndpointsTestCheck(ctx, up && os.Dials >= 1 && ls.Accepted >= 1, "node-s took the stream from its Listener, though its data transport listens nowhere",
		"%I64u dials, %I64u streams that node-s took", os.Dials, ls.Accepted);

	// The first entry reaches nothing: the race goes on to TLS once node-c dials again
	Print("[the first entry of the list reaches nothing]\n");
	EndpointsTestEndpoint(&e[0], "quic", (UINT)EndpointsTestDeadPort());
	EndpointsTestEndpoint(&e[1], "tls", port);
	applied = EndpointsTestApplyC(ctx, e, 2);
	UINT64 dials = cs.NumDials;
	NodeClientPower(ctx->C.Node, PBT_APMSUSPEND);
	bool down = EndpointsTestWaitDown(ctx);
	NodeClientPower(ctx->C.Node, PBT_APMRESUMEAUTOMATIC);
	up = (applied && down && EndpointsTestWaitUp(ctx, dials));
	NodeClientGetStatus(ctx->C.Node, &cs);
	EndpointsTestCheck(ctx, up && StrCmp(cs.Transport, "tls") == 0, "the race goes on to TLS when the QUIC endpoint reaches nothing, and the session comes up again",
		"applied %u, down %u, up %u, %I64u streams connected, transport %s", (UINT)applied, (UINT)down, (UINT)up, cs.NumDials, cs.Transport);
}

RANZ_TEST("endpoints", endpoints_test, "Endpoints of a Node (SDN-93): which of two Nodes dials and which endpoints make the entries of the fallback list, and the client role on a Wintun adapter dials the endpoints of the Peer object of a hub whose Listener takes the stream over QUIC and TLS, not a peer without endpoints and not in a loop (administrator rights, wintun.dll).");
void endpoints_test(UINT num, char **arg)
{
	ENDPOINTSTEST_CTX *ctx = ZeroMalloc(sizeof(ENDPOINTSTEST_CTX));
	HANDLE done = CreateEventW(NULL, TRUE, FALSE, NULL);
	HANDLE watchdog = (done != NULL ? CreateThread(NULL, 0, EndpointsTestWatchdog, done, 0, NULL) : NULL);
	UINT error = 0;
	UINT id = Rand32() & 0xFFFF;

	Print("Endpoints test: which Node dials, the entries of the fallback list, and the client role dialling the endpoints of a hub\n");

	EndpointsTestRules(ctx);
	EndpointsTestTargets(ctx);

	Print("[the client role dials the endpoints of the Peer object of a hub]\n");
	bool ready = EndpointsTestCheck(ctx, CryptoInit(), "the crypto module of the new core runs on CNG", "CryptoInit failed");
	ready = EndpointsTestCheck(ctx, NodeWintunAvailable(&error), "wintun.dll is next to vpntest and has the API of wintun.h", "error %u", error) && ready;

	if (ready)
	{
		bool ok = EndpointsTestKeys(ctx, id);

		ok = ok && EndpointsTestStartS(ctx);
		ok = ok && EndpointsTestStartC(ctx, id);
		if (ok)
		{
			EndpointsTestSteps(ctx);
		}

		EndpointsTestStop(ctx);
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

	if (ctx->NumFailed == 0)
	{
		Print("ENDPOINTS TEST OK\n");
	}
	else
	{
		Print("ENDPOINTS TEST FAILED (%u of %u checks failed)\n", ctx->NumFailed, ctx->NumChecks);
	}

	Free(ctx);
}
