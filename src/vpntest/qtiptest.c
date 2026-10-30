// qtiptest.c
// Named QTIP test of vpntest ("qtip" command, CORE-S7-2 #83)
//
// The XDP datapath of msquic and QTIP (Core/TransportQuicXdp.c, Cedar/NodeQtip.c; ADR-0018 decisions 2 and 5) on the
// official signed msquic.dll. Without an argument, in one process (the smoke loop, the coverage job, and the XDP job of
// windows.yml once ranz install put the XDP runtime on the runner, .github/scripts/qtip.ps1):
// - the rule: the XDP datapath and QTIP run on Windows Server x64 only (TransportQuicXdpAllowed), and what this host is;
// - which msquic release ships QTIP: the msquic.dll that vpntest loads must be 2.5 or later, where QTIPEnabled and
//   XdpEnabled are settings of QUIC_SETTINGS (2.3 and 2.4 had them as flags of the execution config of the process), up to
//   the pinned 2.6, and the configuration of a transport takes QTIPEnabled, as msquic reads it back;
// - default off: a QUIC configuration asks for neither, its transport asks msquic for the normal datapath and its
//   configuration names both settings off, and the global settings of msquic ask no listener for XDP or QTIP;
// - opt-in, and the normal datapath as before: on Windows Server x64 a transport with Xdp asks for the XDP datapath, its
//   listener starts with the global settings for it, which are back at once, and a session over it comes up (msquic
//   carries loopback traffic on Winsock in any case); a default transport after it asks for the normal datapath, and a
//   session over it comes up. Elsewhere a transport with Xdp keeps the normal datapath, and one with Qtip is not made.
// - QTIP: where the XDP runtime is installed (the Capability xdp), a QTIP listener on TRANSPORT_QUIC_QTIP_PORT holds both
//   the TCP and the UDP port, which no other socket can bind until it closes. msquic takes the packets of a QTIP listener
//   from XDP only: it starts no receive on the OS sockets that reserve its ports (datapath_winuser.c of msquic 2.6.2), and
//   the loopback does not cross XDP, so plain QUIC over the loopback does not reach it, while from the network its rules
//   on every XDP interface take QUIC over UDP as well as over TCP. Without the runtime the listener does not listen, since
//   QTIP has no normal datapath;
// - the node: node-s with QuicXdp and Qtip on, whose overlay runs without a control stream and applies a state with a
//   Listener (Cedar/NodeListener.c), runs the QUIC of its Listener on the datapath of the host and QTIP where the XDP
//   runtime is there, or says why not, node-c's session over the QUIC of the Listener comes up, and the ports of QTIP are
//   free again once node-s stopped; without the settings its QUIC asks for the normal datapath and no QTIP listener runs.
// With the argument "serve STOPFILE" or "dial THUMBPRINT ADDRESS", the test is one of the two server node processes of the
// XDP job (ADR-0002 amendment of 2026-10-21: two node processes on one runner, each on its own KM-TEST adapter, with a wire
// of the runner as the physical side): node-s brings up its KM-TEST adapter with the L2 adapter on XDP (198.18.83.1) and
// its Listener with QTIP on port 8443, prints "QTIP SERVE READY" with the thumbprint of its certificate, and runs until the
// file STOPFILE is there; node-c brings up its own KM-TEST adapter with XDP (198.18.84.1), checks from its process that
// TCP 8443 and UDP 8443 are held and that plain QUIC over the loopback does not reach the QTIP listener of node-s, and
// dials node-s over QTIP at ADDRESS:8443, the address of node-s on the wire, where the link must come up: the Noise
// session of node-c with the static key of node-s, which only node-s holds. It prints "QTIP LINK UP" or "QTIP LINK DOWN"
// for the job summary. The wire is the job's (.github/scripts/qtip.ps1): an internal Hyper-V switch with a host vNIC for
// each node, since XDP sends the frames of an AF_XDP socket down to the miniport, below its own hooks, and a KM-TEST
// adapter sends nowhere what reaches it (send.c of the XDP LWF of xdp-for-windows 1.4.0). ADDRESS is no address of the
// host: the stack of the host would carry a packet to one of its own addresses on the loopback, never on the wire. So
// node-c's msquic takes the route to it out of the vNIC of node-c, to the MAC of the vNIC of node-s, which the job gives
// it as a neighbour of that vNIC (RawResolveRoute of datapath_raw_socket_win.c of msquic 2.6.2), and node-s's msquic
// takes the frames with its rule on the port of its listener, whatever their address, and answers on the route that they
// came on (datapath_raw_socket.c).
// Print "QTIP TEST OK" only when every check passes; skip, passing, where msquic.dll is not present. Needs administrator
// rights: the LocalMachine\My store and its key storage provider, and the KM-TEST adapters of serve and dial.

#include "testlist.h"

#include "Cedar/ConfigStore.h"
#include "Cedar/Node.h"
#include "Cedar/NodeCaps.h"
#include "Cedar/NodeL2.h"

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

#include <iphlpapi.h>

#include <stdio.h>
#include <string.h>

#define	QTIPTEST_WATCHDOG		240000		// The test process is aborted after this (ms) ...
#define	QTIPTEST_SERVE_WATCHDOG	600000		// ... node-s of serve, which waits for node-c
#define	QTIPTEST_TIMEOUT		15000		// A handshake, an accept or a record within this time (ms)
#define	QTIPTEST_BOUND			20000		// A bounded wait on observable state (ms)
#define	QTIPTEST_POLL			20			// Poll interval of observable state (ms)
#define	QTIPTEST_REFUSED		5000		// A dial that must not come up is given this long (ms): one over the loopback comes up in far less
#define	QTIPTEST_LISTEN			"127.0.0.1:0"	// A listener of the transport checks binds an ephemeral port on the loopback
#define	QTIPTEST_CN				L"CN=localhost"	// The subject of the certificate
#define	QTIPTEST_SAN			L"localhost"	// ... and its subject alternative name
#define	QTIPTEST_VRF			1			// The VRF of the states of node-s
#define	QTIPTEST_NODE			"node-s"	// The node that listens
#define	QTIPTEST_PEER			"node-c"	// Its peer, which dials it
#define	QTIPTEST_SERVE_NETWORK	83			// The Network of the KM-TEST adapter of node-s: 198.18.83.1/24 ...
#define	QTIPTEST_DIAL_NETWORK	84			// ... and of node-c: 198.18.84.1/24
#define	QTIPTEST_LENGTH			24			// The prefix length of the address of an adapter

// The state of the test
typedef struct QTIPTEST_CTX
{
	UINT NumChecks;
	UINT NumFailed;
	bool Host;							// The XDP datapath and QTIP run on this host (TransportQuicXdpHost)
	bool Runtime;						// The XDP runtime of ranz install is on this host (the Capability xdp)
	char Thumbprint[MAX_SIZE];			// The certificate of the LocalMachine\My store that every server presents
	PEER_KEY Key;						// The static key of node-s
	UCHAR PeerScalar[PEER_KEY_SIZE];	// The static key of node-c ...
	UCHAR PeerPublic[PEER_KEY_SIZE];	// ... and its public half
	UINT64 Generation;					// The Generation of the last state applied to node-s
} QTIPTEST_CTX;

// The server end of one session of the transport checks, on a thread of its own: it accepts one stream, runs the
// responder, takes the first control record as a Login would come and echoes every record until the client closes
typedef struct QTIPTEST_ECHO
{
	TRANSPORT_LISTENER *Listener;
	UCHAR Key[NOISE_KEY_SIZE];
	bool Accepted;
} QTIPTEST_ECHO;

// A KM-TEST adapter of serve or dial with the L2 adapter of the node on it
typedef struct QTIPTEST_ADAPTER
{
	NODE_KMTEST *KmTest;
	NODE_L2 *L2;
	UINT IfIndex;
	UINT64 Luid;
	UCHAR Mac[6];
	UINT Address;					// Its IPv4 address: 198.18.<Network>.1
	volatile LONG64 Frames;			// Frames of the host that the L2 adapter took
} QTIPTEST_ADAPTER;

// The lines of the transport log that say that the XDP datapath or QTIP does not run on this host
static volatile LONG qtiptest_log_lines = 0;

static bool QtipTestCheck(QTIPTEST_CTX *ctx, bool ok, char *what, char *fmt, ...) RANZ_PRINTF_FORMAT(4, 5);
static bool QtipTestCheck(QTIPTEST_CTX *ctx, bool ok, char *what, char *fmt, ...)
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

// The watchdog: a test that hangs ends the process once its time budget (ms) is over, so a lost wake-up is a failed test
// instead of a hung CI step
typedef struct QTIPTEST_WATCH
{
	HANDLE Done;
	DWORD Budget;
} QTIPTEST_WATCH;

static DWORD WINAPI QtipTestWatch(LPVOID param)
{
	QTIPTEST_WATCH *w = (QTIPTEST_WATCH *)param;

	if (WaitForSingleObject(w->Done, w->Budget) == WAIT_TIMEOUT)
	{
		Print("QTIP TEST FAILED (the watchdog ended it after %u ms)\n", (UINT)w->Budget);
		fflush(stdout);
		ExitProcess(1);
	}

	return 0;
}

// A line of the transport log, on any thread: the ones that say the datapath does not run here are counted
static void QtipTestLogLine(void *param, const char *line)
{
	UNREFERENCED_PARAMETER(param);

	if (strstr(line, "runs on Windows Server x64 only") != NULL)
	{
		InterlockedIncrement(&qtiptest_log_lines);
	}
	Print("  [LOG] %s\n", line);
}

// The Noise configuration of one end: the static key, the peer's where it is known, short timers
static void QtipTestNoise(NOISE_SESSION_CONFIG *c, UCHAR *key, UCHAR *remote)
{
	Zero(c, sizeof(NOISE_SESSION_CONFIG));
	c->Suite = NOISE_SUITE_IK;
	c->StaticKey = key;
	c->RemoteStatic = remote;
	c->KeepaliveInterval = 2000;
	c->DeadTimeout = QTIPTEST_TIMEOUT;
	c->RekeyInterval = 60000;
}

// The server end of a session of the transport checks
static void QtipTestEchoThread(THREAD *thread, void *param)
{
	QTIPTEST_ECHO *e = (QTIPTEST_ECHO *)param;
	TRANSPORT_NOISE *n = ZeroMalloc(sizeof(TRANSPORT_NOISE));
	UCHAR *buf = ZeroMalloc(NOISE_MAX_PAYLOAD);
	TRANSPORT_STREAM *s = TransportAccept(e->Listener, QTIPTEST_TIMEOUT);
	NOISE_SESSION_CONFIG sc;
	bool open = false;

	UNREFERENCED_PARAMETER(thread);

	QtipTestNoise(&sc, e->Key, NULL);
	e->Accepted = (s != NULL && TransportNoiseAccept(n, s, &sc, QTIPTEST_TIMEOUT));

	while (e->Accepted)
	{
		UINT size = 0;
		UINT ret = TransportNoiseReceive(n, buf, NOISE_MAX_PAYLOAD, &size, QTIPTEST_TIMEOUT);

		if (ret != NOISE_RECEIVE_CONTROL && ret != NOISE_RECEIVE_DATA)
		{
			break;
		}

		// The first control record stands for the Login: the data stream opens after it
		if (ret == NOISE_RECEIVE_CONTROL && open == false)
		{
			TransportNoiseAcceptLogin(n);
			open = true;
		}
		TransportNoiseSend(n, (ret == NOISE_RECEIVE_DATA ? NOISE_RECORD_DATA : NOISE_RECORD_CONTROL), buf, size);
	}

	TransportNoiseClose(n);
	Free(buf);
	Free(n);
}

// A session of the client transport over the stream s, to a server of the static key server_pub: the handshake, a control
// record each way and then a data record each way. False when any of it did not come back.
static bool QtipTestExchange(TRANSPORT_STREAM *s, UCHAR *client_key, UCHAR *server_pub)
{
	TRANSPORT_NOISE *n = ZeroMalloc(sizeof(TRANSPORT_NOISE));
	UCHAR *buf = ZeroMalloc(NOISE_MAX_PAYLOAD);
	NOISE_SESSION_CONFIG cc;
	UINT size = 0;
	bool ok = false;

	QtipTestNoise(&cc, client_key, server_pub);
	if (s != NULL && TransportNoiseConnect(n, s, &cc, QTIPTEST_TIMEOUT))
	{
		ok = TransportNoiseSend(n, NOISE_RECORD_CONTROL, "hello", 5) &&
			TransportNoiseReceive(n, buf, NOISE_MAX_PAYLOAD, &size, QTIPTEST_TIMEOUT) == NOISE_RECEIVE_CONTROL && size == 5 && Cmp(buf, "hello", 5) == 0 &&
			TransportNoiseSend(n, NOISE_RECORD_DATA, "frame", 5) &&
			TransportNoiseReceive(n, buf, NOISE_MAX_PAYLOAD, &size, QTIPTEST_TIMEOUT) == NOISE_RECEIVE_DATA && size == 5 && Cmp(buf, "frame", 5) == 0;
	}

	TransportNoiseClose(n);
	Free(buf);
	Free(n);

	return ok;
}

// One session from the client transport to a listener of the server transport on the loopback: the listener starts, a
// session comes up over it and carries records both ways, and the listener closes. *listened tells whether the listener
// started, and *during, which may be NULL, what msquic held for the server transport while it listened.
static bool QtipTestSession(TRANSPORT *server, TRANSPORT *client, bool *listened, TRANSPORT_QUIC_XDP_STATUS *during)
{
	UCHAR client_key[NOISE_KEY_SIZE], client_pub[NOISE_KEY_SIZE];
	UCHAR server_pub[NOISE_KEY_SIZE];
	char address[TRANSPORT_ADDRESS_SIZE];
	QTIPTEST_ECHO *e = ZeroMalloc(sizeof(QTIPTEST_ECHO));
	bool ok = false;

	CryptoX25519GenerateKey(client_key, client_pub);
	CryptoX25519GenerateKey(e->Key, server_pub);

	e->Listener = TransportListen(server, QTIPTEST_LISTEN);
	*listened = (e->Listener != NULL);
	if (during != NULL)
	{
		TransportQuicGetXdpStatus(server, during);
	}

	if (e->Listener != NULL)
	{
		THREAD *thread = NewThread(QtipTestEchoThread, e);

		Format(address, sizeof(address), "127.0.0.1:%u", (UINT)TransportQuicBoundPort(server));
		TRANSPORT_STREAM *s = TransportDial(client, address, NULL);
		ok = QtipTestExchange(s, client_key, server_pub) && e->Accepted;

		WaitThread(thread, INFINITE);
		ReleaseThread(thread);
		TransportCloseListener(e->Listener);
	}

	Zero(client_key, sizeof(client_key));
	Zero(e->Key, sizeof(e->Key));
	Free(e);

	return ok;
}

// Whether a socket of type and protocol binds port on every address of both families ([::], dual mode), as a QTIP listener
// of msquic binds it
static bool QtipTestBinds(int type, int protocol, USHORT port)
{
	struct sockaddr_in6 a;
	DWORD v6only = 0;

	SOCKET s = socket(AF_INET6, type, protocol);
	if (s == INVALID_SOCKET)
	{
		return false;
	}

	setsockopt(s, IPPROTO_IPV6, IPV6_V6ONLY, (char *)&v6only, sizeof(v6only));
	Zero(&a, sizeof(a));
	a.sin6_family = AF_INET6;
	a.sin6_port = htons(port);
	bool bound = (bind(s, (struct sockaddr *)&a, sizeof(a)) == 0);
	closesocket(s);

	return bound;
}

// Whether both the TCP and the UDP port are held: no socket of this process binds either
static bool QtipTestHeld(USHORT port)
{
	return (QtipTestBinds(SOCK_STREAM, IPPROTO_TCP, port) == false && QtipTestBinds(SOCK_DGRAM, IPPROTO_UDP, port) == false);
}

// ... and whether both are free
static bool QtipTestFree(USHORT port)
{
	return (QtipTestBinds(SOCK_STREAM, IPPROTO_TCP, port) && QtipTestBinds(SOCK_DGRAM, IPPROTO_UDP, port));
}

// Whether both are free within QTIPTEST_BOUND: msquic lets go of the sockets of a listener that closed on a thread of its own
static bool QtipTestWaitFree(USHORT port)
{
	for (UINT64 end = Tick64() + QTIPTEST_BOUND;Tick64() < end;SleepThread(QTIPTEST_POLL))
	{
		if (QtipTestFree(port))
		{
			return true;
		}
	}

	return false;
}

// Whether this host runs a server edition of Windows, as the test asks it for itself: its product type
static bool QtipTestServerEdition()
{
	OSVERSIONINFOEXW os;

	Zero(&os, sizeof(os));
	os.dwOSVersionInfoSize = sizeof(os);
	os.wProductType = VER_NT_WORKSTATION;

	return (VerifyVersionInfoW(&os, VER_PRODUCT_TYPE, VerSetConditionMask(0, VER_PRODUCT_TYPE, VER_EQUAL)) == FALSE);
}

// A QUIC configuration of the test: the certificate of the store, which a server presents and a client pins
static void QtipTestConfig(QTIPTEST_CTX *ctx, TRANSPORT_QUIC_CONFIG *cfg, bool xdp, bool qtip)
{
	TransportQuicDefaultConfig(cfg, ctx->Thumbprint, true);
	cfg->Xdp = xdp;
	cfg->Qtip = qtip;
}

// A dial of plain QUIC over the loopback to port that gives up after QTIPTEST_REFUSED ms: whether it ran, and in *up
// whether it came up. A stream that came up closes again.
static bool QtipTestLoopbackDial(QTIPTEST_CTX *ctx, USHORT port, bool *up)
{
	TRANSPORT_QUIC_CONFIG cfg;
	char address[TRANSPORT_ADDRESS_SIZE];
	LARGE_INTEGER due;

	*up = false;
	QtipTestConfig(ctx, &cfg, false, false);
	TRANSPORT *plain = TransportQuicClientNew(&cfg);
	if (plain == NULL)
	{
		return false;
	}

	// A waitable timer is the cancel of the dial; without one msquic ends it at its handshake idle timeout
	HANDLE timer = CreateWaitableTimerW(NULL, TRUE, NULL);
	due.QuadPart = -10000LL * QTIPTEST_REFUSED;
	if (timer != NULL)
	{
		SetWaitableTimer(timer, &due, 0, NULL, NULL, FALSE);
	}

	Format(address, sizeof(address), "127.0.0.1:%u", (UINT)port);
	TRANSPORT_STREAM *s = TransportDial(plain, address, timer);
	*up = (s != NULL);
	if (s != NULL)
	{
		TransportClose(s);
	}

	if (timer != NULL)
	{
		CloseHandle(timer);
	}
	TransportQuicFree(plain);

	return true;
}

// The name of a datapath
static char *QtipTestDatapath(UINT datapath)
{
	switch (datapath)
	{
	case TRANSPORT_QUIC_DATAPATH_NORMAL:
		return "the normal datapath";
	case TRANSPORT_QUIC_DATAPATH_XDP:
		return "the XDP datapath";
	case TRANSPORT_QUIC_DATAPATH_QTIP:
		return "QTIP";
	default:
		return "an unknown datapath";
	}
}

//
// The checks of one process
//

// The rule, this host, and which msquic release ships QTIP
static void QtipTestRule(QTIPTEST_CTX *ctx)
{
	SYSTEM_INFO info;
	TRANSPORT_QUIC_CONFIG cfg;
	TRANSPORT_QUIC_XDP_STATUS xs;
	UINT v24[4] = {2, 4, 8, 0}, v25[4] = {2, 5, 0, 0}, v262[4] = {2, 6, 2, 0}, v27[4] = {2, 7, 0, 0}, v30[4] = {3, 0, 0, 0};

	Print("[the rule: Windows Server x64 only]\n");
	QtipTestCheck(ctx, TransportQuicXdpAllowed(true, PROCESSOR_ARCHITECTURE_AMD64), "Windows Server on x64 takes the XDP datapath and QTIP", "refused");
	QtipTestCheck(ctx, TransportQuicXdpAllowed(false, PROCESSOR_ARCHITECTURE_AMD64) == false, "a client edition of Windows on x64 does not", "allowed");
	QtipTestCheck(ctx, TransportQuicXdpAllowed(true, PROCESSOR_ARCHITECTURE_ARM64) == false, "Windows Server on arm64 does not: the XDP runtime is x64 only", "allowed");
	QtipTestCheck(ctx, TransportQuicXdpAllowed(false, PROCESSOR_ARCHITECTURE_ARM64) == false, "a client edition of Windows on arm64 does not", "allowed");
	QtipTestCheck(ctx, TransportQuicXdpAllowed(true, PROCESSOR_ARCHITECTURE_INTEL) == false, "Windows Server on x86 does not", "allowed");

	Zero(&info, sizeof(info));
	GetNativeSystemInfo(&info);
	bool server = QtipTestServerEdition();
	bool x64 = (info.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64);
	ctx->Host = TransportQuicXdpHost();
	Print("  this host: %s on %s: the XDP datapath and QTIP %s here\n", server ? "Windows Server" : "a client edition of Windows",
		x64 ? "x64" : (info.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_ARM64 ? "arm64" : "another architecture"), ctx->Host ? "run" : "do not run");
	QtipTestCheck(ctx, ctx->Host == (server && x64), "TransportQuicXdpHost answers the rule for this host", "it answers %u for a %s host", (UINT)ctx->Host,
		(server && x64) ? "Windows Server x64" : "another");

	Print("[which msquic release ships QTIP]\n");
	QtipTestCheck(ctx, TransportQuicXdpRelease(v24) == false && TransportQuicXdpRelease(v25) && TransportQuicXdpRelease(v262) &&
		TransportQuicXdpRelease(v27) == false && TransportQuicXdpRelease(v30) == false,
		"QTIP and XDP are settings of msquic from 2.5 on, which this build sets up to the pinned 2.6: not on 2.4, 2.7 or 3.0", "the release check answers otherwise");

	Zero(&xs, sizeof(xs));
	QtipTestConfig(ctx, &cfg, false, false);
	TRANSPORT *t = TransportQuicServerNew(&cfg);
	bool got = (t != NULL && TransportQuicGetXdpStatus(t, &xs));
	Print("  the msquic.dll of vpntest is %u.%u.%u: QTIPEnabled and XdpEnabled of its QUIC_SETTINGS %s\n", xs.Version[0], xs.Version[1], xs.Version[2],
		xs.Release ? "are where this build sets them" : "are not where this build sets them");
	QtipTestCheck(ctx, got && xs.Release && xs.Named,
		"the msquic of vpntest ships QTIP: it is 2.5 or later, and the configuration of a transport takes QTIPEnabled and XdpEnabled, as msquic reads them back",
		"status %u, msquic %u.%u.%u, release %u, named %u", (UINT)got, xs.Version[0], xs.Version[1], xs.Version[2], (UINT)xs.Release, (UINT)xs.Named);

	Print("[default off]\n");
	QtipTestCheck(ctx, cfg.Xdp == false && cfg.Qtip == false, "a QUIC configuration asks for neither the XDP datapath nor QTIP by default", "Xdp %u, Qtip %u",
		(UINT)cfg.Xdp, (UINT)cfg.Qtip);
	QtipTestCheck(ctx, got && xs.Datapath == TRANSPORT_QUIC_DATAPATH_NORMAL && xs.Named && xs.Xdp == false && xs.Qtip == false,
		"a transport of it asks msquic for the normal datapath, and its configuration names both settings off, so it takes neither from the global ones",
		"%s, named %u, XdpEnabled %u, QTIPEnabled %u", QtipTestDatapath(xs.Datapath), (UINT)xs.Named, (UINT)xs.Xdp, (UINT)xs.Qtip);
	QtipTestCheck(ctx, got && xs.GlobalXdp == false && xs.GlobalQtip == false, "the global settings of msquic ask no listener for XDP or QTIP",
		"XdpEnabled %u, QTIPEnabled %u", (UINT)xs.GlobalXdp, (UINT)xs.GlobalQtip);

	TransportQuicFree(t);
}

// Opt-in, and the normal datapath as before
static void QtipTestOptIn(QTIPTEST_CTX *ctx)
{
	TRANSPORT_QUIC_CONFIG cfg;
	TRANSPORT_QUIC_XDP_STATUS xs, during;
	bool listened = false;

	Zero(&xs, sizeof(xs));
	Print("[the normal datapath]\n");
	QtipTestConfig(ctx, &cfg, false, false);
	TRANSPORT *server = TransportQuicServerNew(&cfg);
	TRANSPORT *client = TransportQuicClientNew(&cfg);
	bool up = (server != NULL && client != NULL && QtipTestSession(server, client, &listened, NULL));
	QtipTestCheck(ctx, up, "a Noise session over the default transports comes up and carries records both ways", "listened %u, up %u", (UINT)listened, (UINT)up);
	TransportQuicFree(client);
	TransportQuicFree(server);

	Print("[opt-in: the XDP datapath]\n");
	InterlockedExchange(&qtiptest_log_lines, 0);
	QtipTestConfig(ctx, &cfg, true, false);
	server = TransportQuicServerNew(&cfg);
	client = TransportQuicClientNew(&cfg);
	bool got = (server != NULL && TransportQuicGetXdpStatus(server, &xs));
	if (ctx->Host)
	{
		QtipTestCheck(ctx, got && xs.Datapath == TRANSPORT_QUIC_DATAPATH_XDP && xs.Named && xs.Xdp && xs.Qtip == false,
			"on Windows Server x64 a transport with Xdp asks msquic for the XDP datapath: its configuration has XdpEnabled",
			"status %u, %s, XdpEnabled %u, QTIPEnabled %u", (UINT)got, QtipTestDatapath(xs.Datapath), (UINT)xs.Xdp, (UINT)xs.Qtip);
	}
	else
	{
		QtipTestCheck(ctx, got && xs.Datapath == TRANSPORT_QUIC_DATAPATH_NORMAL && xs.Xdp == false && qtiptest_log_lines >= 1,
			"off Windows Server x64 a transport with Xdp keeps the normal datapath, and the transport log says why",
			"status %u, %s, XdpEnabled %u, %u lines of the log", (UINT)got, QtipTestDatapath(xs.Datapath), (UINT)xs.Xdp, (UINT)qtiptest_log_lines);
	}

	Zero(&during, sizeof(during));
	up = (server != NULL && client != NULL && QtipTestSession(server, client, &listened, &during));
	QtipTestCheck(ctx, listened && during.GlobalXdp == false && during.GlobalQtip == false,
		"its listener starts, and the global settings of msquic are back off once it started",
		"listened %u, global XdpEnabled %u, QTIPEnabled %u", (UINT)listened, (UINT)during.GlobalXdp, (UINT)during.GlobalQtip);
	QtipTestCheck(ctx, up, "a session over it comes up and carries records both ways (msquic carries loopback traffic on Winsock)", "up %u", (UINT)up);
	TransportQuicFree(client);
	TransportQuicFree(server);

	// A default transport after the one with Xdp, in the same process
	QtipTestConfig(ctx, &cfg, false, false);
	server = TransportQuicServerNew(&cfg);
	client = TransportQuicClientNew(&cfg);
	got = (server != NULL && TransportQuicGetXdpStatus(server, &xs));
	up = (server != NULL && client != NULL && QtipTestSession(server, client, &listened, NULL));
	QtipTestCheck(ctx, got && xs.Datapath == TRANSPORT_QUIC_DATAPATH_NORMAL && xs.Named && xs.Xdp == false && up,
		"a default transport after it still asks for the normal datapath, and a session over it comes up as before",
		"status %u, %s, XdpEnabled %u, up %u", (UINT)got, QtipTestDatapath(xs.Datapath), (UINT)xs.Xdp, (UINT)up);
	TransportQuicFree(client);
	TransportQuicFree(server);
}

// A QTIP listener on TRANSPORT_QUIC_QTIP_PORT
static void QtipTestQtip(QTIPTEST_CTX *ctx)
{
	TRANSPORT_QUIC_CONFIG cfg;
	TRANSPORT_QUIC_XDP_STATUS xs;
	char address[TRANSPORT_ADDRESS_SIZE];
	USHORT port = TRANSPORT_QUIC_QTIP_PORT;

	Zero(&xs, sizeof(xs));
	Print("[opt-in: QTIP on port %u]\n", (UINT)port);
	InterlockedExchange(&qtiptest_log_lines, 0);
	QtipTestConfig(ctx, &cfg, false, true);
	TRANSPORT *qtip = TransportQuicServerNew(&cfg);

	if (ctx->Host == false)
	{
		QtipTestCheck(ctx, qtip == NULL && qtiptest_log_lines >= 1, "off Windows Server x64 a transport with Qtip is not made, since QTIP has no normal datapath, and the log says why",
			"%s, %u lines of the log", qtip != NULL ? "made" : "not made", (UINT)qtiptest_log_lines);
		TransportQuicFree(qtip);
		return;
	}

	bool got = (qtip != NULL && TransportQuicGetXdpStatus(qtip, &xs));
	QtipTestCheck(ctx, got && xs.Datapath == TRANSPORT_QUIC_DATAPATH_QTIP && xs.Xdp && xs.Qtip,
		"a transport with Qtip asks msquic for QTIP: its configuration has XdpEnabled and QTIPEnabled", "status %u, %s, XdpEnabled %u, QTIPEnabled %u", (UINT)got,
		QtipTestDatapath(xs.Datapath), (UINT)xs.Xdp, (UINT)xs.Qtip);

	bool free_before = QtipTestFree(port);
	Print("  TCP %u and UDP %u are %s before the QTIP listener starts\n", (UINT)port, (UINT)port, free_before ? "free" : "taken");
	Format(address, sizeof(address), ":%u", (UINT)port);
	TRANSPORT_LISTENER *l = (qtip != NULL ? TransportListen(qtip, address) : NULL);
	got = (qtip != NULL && TransportQuicGetXdpStatus(qtip, &xs));
	QtipTestCheck(ctx, got && xs.GlobalXdp == false && xs.GlobalQtip == false, "the global settings of msquic are back off once the QTIP listener started, or failed to",
		"XdpEnabled %u, QTIPEnabled %u", (UINT)xs.GlobalXdp, (UINT)xs.GlobalQtip);

	if (ctx->Runtime)
	{
		QtipTestCheck(ctx, l != NULL, "with the XDP runtime of ranz install, the QTIP listener listens on its port", "it does not listen");
		QtipTestCheck(ctx, free_before && l != NULL && QtipTestHeld(port), "it holds both the TCP and the UDP port: no other socket binds either",
			"free before %u, held %u", (UINT)free_before, (UINT)(l != NULL && QtipTestHeld(port)));

		if (l != NULL)
		{
			// msquic takes the packets of a QTIP listener from XDP only: it starts no receive on the OS sockets that reserve
			// its ports, and the loopback does not cross XDP. So plain QUIC over the loopback reaches no QTIP listener, while
			// from the network the rules of the listener on every XDP interface take QUIC over UDP as well as over TCP.
			bool up = false;
			bool ran = QtipTestLoopbackDial(ctx, port, &up);
			QtipTestCheck(ctx, ran && up == false,
				"plain QUIC over the loopback does not reach it: msquic takes the packets of a QTIP listener from XDP only, which the loopback does not cross",
				"the dial %s", ran ? "came up" : "did not run");

			TransportCloseListener(l);
			l = NULL;
			QtipTestCheck(ctx, QtipTestWaitFree(port), "once it closed, both ports are free again", "a port is still taken");
		}
	}
	else
	{
		QtipTestCheck(ctx, l == NULL, "without the XDP runtime, the QTIP listener does not listen: QTIP has no normal datapath", "it listens");
	}

	if (l != NULL)
	{
		TransportCloseListener(l);
	}
	TransportQuicFree(qtip);

	// The client side: a QTIP transport that dials
	QtipTestConfig(ctx, &cfg, false, true);
	TRANSPORT *dialler = TransportQuicClientNew(&cfg);
	got = (dialler != NULL && TransportQuicGetXdpStatus(dialler, &xs));
	QtipTestCheck(ctx, got && xs.Datapath == TRANSPORT_QUIC_DATAPATH_QTIP && xs.Xdp && xs.Qtip, "a client transport with Qtip asks msquic for QTIP for its connections too",
		"status %u, %s", (UINT)got, QtipTestDatapath(xs.Datapath));
	TransportQuicFree(dialler);
}

//
// The node
//

// A new empty data directory with the configuration store of a node: the roles, one worker, and QuicXdp and Qtip on with qtip
static void QtipTestNewDir(wchar_t *dir, UINT size, char *roles, bool qtip)
{
	wchar_t tmp[MAX_PATH];
	wchar_t path[MAX_PATH];
	char port[MAX_SIZE];

	UniFormat(tmp, sizeof(tmp), L"qtiptest_%u", Rand32());
	ConbinePathW(dir, size, MsGetMyTempDirW(), tmp);
	MakeDirExW(dir);

	ConbinePathW(path, sizeof(path), dir, CS_FILE_NAME);
	CONFIG_STORE *s = CsOpen(path);
	if (s == NULL)
	{
		return;
	}

	CsSetSetting(s, NODE_SETTING_ROLES, roles);
	CsSetSetting(s, NODE_SETTING_WORKERS, "1");
	if (qtip)
	{
		Format(port, sizeof(port), "%u", (UINT)TRANSPORT_QUIC_QTIP_PORT);
		CsSetSetting(s, NODE_SETTING_QUIC_XDP, "on");
		CsSetSetting(s, NODE_SETTING_QTIP, "on");
		CsSetSetting(s, NODE_SETTING_QTIP_PORT, port);
	}
	CsClose(s);
}

// Delete the files of a directory and its folders, then the directory
static void QtipTestDeleteDir(wchar_t *dir)
{
	DIRLIST *d = EnumDirW(dir);

	for (UINT i = 0;d != NULL && i < d->NumFiles;i++)
	{
		DIRENT *e = d->File[i];
		wchar_t path[MAX_PATH];

		ConbinePathW(path, sizeof(path), dir, e->FileNameW);
		if (e->Folder)
		{
			QtipTestDeleteDir(path);
		}
		else
		{
			FileDeleteW(path);
		}
	}

	FreeDir(d);
	DeleteDirW(dir);
}

// The lines of the node log of the data directory dir about the KM-TEST adapter and the L2 adapter on it, where
// NodeKmTestNew and NodeL2New say why one did not come up
static void QtipTestPrintLog(wchar_t *dir)
{
	wchar_t log_dir[MAX_PATH];

	ConbinePathW(log_dir, sizeof(log_dir), dir, NODE_LOG_DIR_NAME);
	DIRLIST *d = EnumDirW(log_dir);

	for (UINT i = 0;d != NULL && i < d->NumFiles;i++)
	{
		DIRENT *e = d->File[i];
		wchar_t path[MAX_PATH];

		if (e->Folder)
		{
			continue;
		}

		ConbinePathW(path, sizeof(path), log_dir, e->FileNameW);
		BUF *b = ReadDumpW(path);
		if (b == NULL)
		{
			continue;
		}

		char *text = ZeroMalloc(b->Size + 1);
		Copy(text, b->Buf, b->Size);
		TOKEN_LIST *t = ParseToken(text, "\r\n");
		for (UINT j = 0;j < t->NumTokens;j++)
		{
			if (InStr(t->Token[j], "KM-TEST") || InStr(t->Token[j], "L2 adapter"))
			{
				Print("  [LOG] %s\n", t->Token[j]);
			}
		}
		FreeToken(t);
		Free(text);
		FreeBuf(b);
	}

	FreeDir(d);
}

// Apply a state of node-s to its overlay, as the control stream does: its address in VRF 1, node-c as its peer, and its
// Listener on ports that the system picks, with the certificate of the store
static bool QtipTestApply(QTIPTEST_CTX *ctx, NODE *n)
{
	CONTROL_STATE st;
	CONTROL_PEER peer;
	CONTROL_LISTENER l;
	UCHAR self[4] = {100, 64, 0, 1};
	UCHAR other[4] = {100, 64, 0, 2};

	Zero(&st, sizeof(st));
	Zero(&peer, sizeof(peer));
	Zero(&l, sizeof(l));

	st.Generation = ++ctx->Generation;
	StrCpy(st.Name, sizeof(st.Name), QTIPTEST_NODE);
	StrCpy(st.Addresses[0].Network, sizeof(st.Addresses[0].Network), "default");
	st.Addresses[0].VrfId = QTIPTEST_VRF;
	Copy(st.Addresses[0].Address, self, 4);
	st.Addresses[0].AddressSize = 4;
	st.Addresses[0].Length = 10;
	st.NumAddresses = 1;

	StrCpy(peer.Name, sizeof(peer.Name), QTIPTEST_PEER);
	Copy(peer.Key, ctx->PeerPublic, PEER_KEY_SIZE);
	peer.NumVrfs = 1;
	peer.VrfIds[0] = QTIPTEST_VRF;
	StrCpy(peer.Addresses[0].Network, sizeof(peer.Addresses[0].Network), "default");
	peer.Addresses[0].VrfId = QTIPTEST_VRF;
	Copy(peer.Addresses[0].Address, other, 4);
	peer.Addresses[0].AddressSize = 4;
	peer.Addresses[0].Length = 10;
	peer.NumAddresses = 1;
	st.Peers = &peer;
	st.NumPeers = 1;

	StrCpy(l.Name, sizeof(l.Name), "edge");
	l.Source = CONTROL_CERT_KSP;
	StrCpy(l.Thumbprint, sizeof(l.Thumbprint), ctx->Thumbprint);
	st.Listener = &l;

	return NodeOverlayApply(n, &st);
}

// Whether the overlay of n has links sessions within QTIPTEST_BOUND
static bool QtipTestWaitLinks(NODE *n, UINT links)
{
	NODE_OVERLAY_STATUS st;

	for (UINT64 end = Tick64() + QTIPTEST_BOUND;Tick64() < end;SleepThread(QTIPTEST_POLL))
	{
		NodeOverlayGetStatus(n, &st);
		if (st.NumLinks == links)
		{
			return true;
		}
	}

	return false;
}

// node-c: dial address over the client transport t, until cancel (NULL for none) is set, and open the Noise session with
// the static key of node-s; whether the overlay of node-s, n, took it as the session of its peer. The session closes
// again. n may be NULL, for a node-s of another process: then only the handshake counts.
static bool QtipTestNodeSession(QTIPTEST_CTX *ctx, NODE *n, TRANSPORT *t, char *address, HANDLE cancel)
{
	NOISE_SESSION_CONFIG cfg;
	bool ok = false;

	TRANSPORT_STREAM *s = TransportDial(t, address, cancel);
	if (s == NULL)
	{
		return false;
	}

	TRANSPORT_NOISE *noise = ZeroMalloc(sizeof(TRANSPORT_NOISE));
	QtipTestNoise(&cfg, ctx->PeerScalar, ctx->Key.Public);
	if (TransportNoiseConnect(noise, s, &cfg, QTIPTEST_TIMEOUT))
	{
		ok = (n == NULL || QtipTestWaitLinks(n, 1));
		TransportNoiseClose(noise);
		ok = (n == NULL || QtipTestWaitLinks(n, 0)) && ok;
	}
	Free(noise);

	return ok;
}

// A node, with the overlay of node-s, which runs without a control stream, where overlay asks for it (NULL for none);
// NULL when it does not start
static NODE *QtipTestNodeStart(QTIPTEST_CTX *ctx, wchar_t *dir, TRANSPORT *overlay)
{
	NODE_OVERLAY_CONFIG cfg;

	NODE *n = NewNode(dir);
	if (n == NULL)
	{
		return NULL;
	}
	NodeStart(n);

	if (overlay == NULL)
	{
		return n;
	}

	Zero(&cfg, sizeof(cfg));
	cfg.Data = overlay;
	cfg.Key = &ctx->Key;
	if (NodeOverlayStart(n, &cfg) == false)
	{
		NodeStop(n);
		FreeNode(n);
		return NULL;
	}

	return n;
}

// ... and its end
static void QtipTestNodeStop(NODE *n)
{
	if (n != NULL)
	{
		NodeOverlayStop(n);
		NodeStop(n);
		FreeNode(n);
	}
}

// node-s with QuicXdp and Qtip on, then without them
static void QtipTestNode(QTIPTEST_CTX *ctx, TRANSPORT *loopback)
{
	NODE_LISTENER_STATUS st;
	TRANSPORT_QUIC_CONFIG cfg;
	wchar_t dir[MAX_PATH];
	char address[TRANSPORT_ADDRESS_SIZE];
	UINT want = (ctx->Host ? TRANSPORT_QUIC_DATAPATH_XDP : TRANSPORT_QUIC_DATAPATH_NORMAL);
	bool qtip = (ctx->Host && ctx->Runtime);
	bool listened = false;

	Print("[the node: QuicXdp and Qtip on]\n");
	QtipTestNewDir(dir, sizeof(dir), "none", true);
	NODE *n = QtipTestNodeStart(ctx, dir, loopback);
	if (QtipTestCheck(ctx, n != NULL, "node-s runs its overlay without a control stream", "it does not start"))
	{
		bool applied = QtipTestApply(ctx, n);
		NodeListenerGetStatus(n, &st);
		QtipTestCheck(ctx, applied && st.Running && st.QuicPort != 0 && st.QuicDatapath == want,
			"the QUIC of the Listener of node-s listens on the datapath that the host gives: XDP on Windows Server x64, the normal one elsewhere",
			"applied %u, running %u, QUIC port %u, %s, error %s", (UINT)applied, (UINT)st.Running, st.QuicPort, QtipTestDatapath(st.QuicDatapath), st.Error);
		if (qtip)
		{
			listened = (st.QtipPort == TRANSPORT_QUIC_QTIP_PORT && IsEmptyStr(st.QtipError) && QtipTestHeld(TRANSPORT_QUIC_QTIP_PORT));
			QtipTestCheck(ctx, listened, "QTIP listens beside it on its own port and holds both the TCP and the UDP port", "QTIP port %u, error %s", st.QtipPort,
				st.QtipError);
		}
		else
		{
			QtipTestCheck(ctx, st.QtipPort == 0 && IsEmptyStr(st.QtipError) == false, "QTIP does not listen without Windows Server x64 and the XDP runtime, and the status says why",
				"QTIP port %u, error %s", st.QtipPort, st.QtipError);
		}

		QtipTestConfig(ctx, &cfg, false, false);
		TRANSPORT *quic = TransportQuicClientNew(&cfg);
		Format(address, sizeof(address), "127.0.0.1:%u", st.QuicPort);
		bool up = (quic != NULL && st.QuicPort != 0 && QtipTestNodeSession(ctx, n, quic, address, NULL));
		QtipTestCheck(ctx, up, "node-c's session over the QUIC of the Listener comes up, and the overlay of node-s takes it as its peer's", "up %u", (UINT)up);
		TransportQuicFree(quic);
	}
	QtipTestNodeStop(n);
	QtipTestDeleteDir(dir);

	// The QTIP listener goes with the Listener of the node (NodeQtipDown, NodeQtipFree), and msquic lets go of its ports
	if (listened)
	{
		QtipTestCheck(ctx, QtipTestWaitFree(TRANSPORT_QUIC_QTIP_PORT), "once node-s stopped, TCP 8443 and UDP 8443 are free again: its QTIP listener went with its Listener",
			"a port is still taken");
	}

	Print("[the node: without the settings]\n");
	QtipTestNewDir(dir, sizeof(dir), "none", false);
	n = QtipTestNodeStart(ctx, dir, loopback);
	if (QtipTestCheck(ctx, n != NULL, "node-s runs its overlay without a control stream", "it does not start"))
	{
		bool applied = QtipTestApply(ctx, n);
		NodeListenerGetStatus(n, &st);
		QtipTestCheck(ctx, applied && st.Running && st.QuicPort != 0 && st.QuicDatapath == TRANSPORT_QUIC_DATAPATH_NORMAL && st.QtipPort == 0 && IsEmptyStr(st.QtipError),
			"its QUIC asks for the normal datapath and no QTIP listener runs: both are off by default", "applied %u, QUIC port %u, %s, QTIP port %u, error %s", (UINT)applied,
			st.QuicPort, QtipTestDatapath(st.QuicDatapath), st.QtipPort, st.QtipError);
	}
	QtipTestNodeStop(n);
	QtipTestDeleteDir(dir);
}

//
// The two server node processes of the XDP job
//

// The owner of the L2 adapter of serve and dial: it counts the frames of the host
static void QtipTestOwner(NODE_L2 *a, void *param, const UCHAR *frame, UINT size)
{
	QTIPTEST_ADAPTER *x = (QTIPTEST_ADAPTER *)param;

	UNREFERENCED_PARAMETER(a);
	UNREFERENCED_PARAMETER(frame);
	UNREFERENCED_PARAMETER(size);

	InterlockedIncrement64(&x->Frames);
}

// The KM-TEST adapter of the Network network of the node n, whose static key is key, with its IPv4 address
// 198.18.<network>.1, and the L2 adapter of the node on it with the backend of the host, which must be XDP. NodeKmTestNew
// returns the adapter once the IPv4 stack of the host has its interface, so the address is not refused for an interface
// that the stack does not know yet.
static bool QtipTestAdapter(QTIPTEST_CTX *ctx, QTIPTEST_ADAPTER *x, NODE *n, const UCHAR *key, UINT network)
{
	MIB_UNICASTIPADDRESS_ROW row;
	NODE_L2_CONFIG cfg;
	NODE_L2_STATUS st;
	NET_LUID luid;

	Zero(x, sizeof(QTIPTEST_ADAPTER));
	NodeL2Mac(x->Mac, key, network);
	x->Address = htonl((198u << 24) | (18u << 16) | (network << 8) | 1u);

	x->KmTest = NodeKmTestNew(n, x->Mac);
	x->IfIndex = NodeKmTestIndex(x->KmTest);
	if (QtipTestCheck(ctx, x->KmTest != NULL && ConvertInterfaceIndexToLuid(x->IfIndex, &luid) == NO_ERROR, "the node brings up its own KM-TEST adapter",
		"adapter %s, interface %u", x->KmTest != NULL ? "created" : "not created", x->IfIndex) == false)
	{
		return false;
	}
	x->Luid = luid.Value;

	InitializeUnicastIpAddressEntry(&row);
	row.InterfaceLuid.Value = x->Luid;
	row.Address.Ipv4.sin_family = AF_INET;
	row.Address.Ipv4.sin_addr.s_addr = x->Address;
	row.OnLinkPrefixLength = QTIPTEST_LENGTH;
	row.DadState = IpDadStatePreferred;
	DWORD err = CreateUnicastIpAddressEntry(&row);
	bool preferred = false;
	for (UINT64 end = GetTickCount64() + QTIPTEST_BOUND;(err == NO_ERROR || err == ERROR_OBJECT_ALREADY_EXISTS) && preferred == false && GetTickCount64() < end;Sleep(100))
	{
		MIB_UNICASTIPADDRESS_ROW r;

		InitializeUnicastIpAddressEntry(&r);
		r.InterfaceLuid.Value = x->Luid;
		r.Address.Ipv4.sin_family = AF_INET;
		r.Address.Ipv4.sin_addr.s_addr = x->Address;
		preferred = (GetUnicastIpAddressEntry(&r) == NO_ERROR && r.DadState == IpDadStatePreferred);
	}
	Print("  KM-TEST adapter of Network %u: interface %u, MAC %02X-%02X-%02X-%02X-%02X-%02X, 198.18.%u.1/%u\n", network, x->IfIndex, (UINT)x->Mac[0], (UINT)x->Mac[1],
		(UINT)x->Mac[2], (UINT)x->Mac[3], (UINT)x->Mac[4], (UINT)x->Mac[5], network, (UINT)QTIPTEST_LENGTH);
	if (QtipTestCheck(ctx, preferred, "the adapter takes its IPv4 address", "CreateUnicastIpAddressEntry: error %u%s", (UINT)err,
		(err == NO_ERROR || err == ERROR_OBJECT_ALREADY_EXISTS) ? ", but the address did not become preferred in time" : "") == false)
	{
		return false;
	}

	Zero(&cfg, sizeof(cfg));
	cfg.IfIndex = x->IfIndex;
	cfg.Proc = QtipTestOwner;
	cfg.Param = x;
	cfg.Reset = NodeKmTestReset;
	cfg.ResetParam = x->KmTest;
	x->L2 = NodeL2New(n, &cfg);
	NodeL2GetStatus(x->L2, &st);

	return QtipTestCheck(ctx, x->L2 != NULL && StrCmpi(st.Backend, "xdp") == 0, "the L2 adapter of the node runs on it with XDP", "%s, backend '%s'",
		x->L2 != NULL ? "an adapter" : "no adapter", st.Backend);
}

// ... and its end: the L2 adapter goes, and the KM-TEST adapter is removed
static void QtipTestAdapterFree(QTIPTEST_ADAPTER *x)
{
	NodeL2Free(x->L2);
	x->L2 = NULL;
	NodeKmTestFree(x->KmTest, true);
	x->KmTest = NULL;
}

// serve: node-s, a server node on its own KM-TEST adapter, which listens with QTIP on 8443, on every XDP interface of the
// host and so on its vNIC of the wire too, until the file stop is there
static void QtipTestServe(QTIPTEST_CTX *ctx, TRANSPORT *loopback, char *stop)
{
	NODE_LISTENER_STATUS st;
	QTIPTEST_ADAPTER x;
	wchar_t dir[MAX_PATH];
	wchar_t stop_file[MAX_PATH];

	Zero(&x, sizeof(x));
	Utf8ToUni(stop_file, sizeof(stop_file), stop, StrLen(stop));
	Print("[serve: node-s, a server node with QTIP on its own KM-TEST adapter]\n");

	QtipTestNewDir(dir, sizeof(dir), "server", true);
	NODE *n = QtipTestNodeStart(ctx, dir, loopback);
	if (QtipTestCheck(ctx, n != NULL, "node-s, a server node, runs its overlay", "it does not start") && QtipTestAdapter(ctx, &x, n, ctx->Key.Public, QTIPTEST_SERVE_NETWORK))
	{
		bool applied = QtipTestApply(ctx, n);
		NodeListenerGetStatus(n, &st);
		QtipTestCheck(ctx, applied && st.QuicDatapath == TRANSPORT_QUIC_DATAPATH_XDP, "the QUIC of the Listener of node-s asks msquic for the XDP datapath", "%s, error %s",
			QtipTestDatapath(st.QuicDatapath), st.Error);
		bool listens = QtipTestCheck(ctx, st.QtipPort == TRANSPORT_QUIC_QTIP_PORT && QtipTestHeld((USHORT)st.QtipPort),
			"QTIP listens on port 8443 and holds both the TCP and the UDP port", "QTIP port %u, error %s", st.QtipPort, st.QtipError);

		if (listens)
		{
			Print("QTIP SERVE READY %s\n", ctx->Thumbprint);
			fflush(stdout);

			for (UINT64 end = GetTickCount64() + QTIPTEST_SERVE_WATCHDOG - 60000;IsFileExistsW(stop_file) == false && GetTickCount64() < end;Sleep(100))
			{
			}
			NodeListenerGetStatus(n, &st);
			Print("  node-s: the overlay took %I64u streams from the listeners; the L2 adapter took %I64u frames of the host\n", st.Accepted, (UINT64)x.Frames);
		}
		else
		{
			Print("QTIP SERVE NOT READY: %s\n", st.QtipError);
			fflush(stdout);
		}
	}
	QtipTestAdapterFree(&x);
	QtipTestNodeStop(n);
	if (ctx->NumFailed != 0)
	{
		QtipTestPrintLog(dir);
	}
	QtipTestDeleteDir(dir);
}

// dial: node-c, a server node on its own KM-TEST adapter, which dials node-s at wire, its address on the wire of the job,
// the certificate of node-s by its thumbprint
static void QtipTestDial(QTIPTEST_CTX *ctx, char *thumbprint, char *wire)
{
	TRANSPORT_QUIC_CONFIG cfg;
	TRANSPORT_QUIC_XDP_STATUS xs;
	QTIPTEST_ADAPTER x;
	wchar_t dir[MAX_PATH];
	char address[TRANSPORT_ADDRESS_SIZE];

	Zero(&x, sizeof(x));
	Zero(&xs, sizeof(xs));
	StrCpy(ctx->Thumbprint, sizeof(ctx->Thumbprint), thumbprint);
	Print("[dial: node-c, a server node on its own KM-TEST adapter, to node-s at %s on the wire]\n", wire);

	QtipTestNewDir(dir, sizeof(dir), "server", false);
	NODE *n = QtipTestNodeStart(ctx, dir, NULL);
	if (QtipTestCheck(ctx, n != NULL, "node-c, a server node, runs", "it does not start") && QtipTestAdapter(ctx, &x, n, ctx->PeerPublic, QTIPTEST_DIAL_NETWORK))
	{
		QtipTestCheck(ctx, QtipTestHeld(TRANSPORT_QUIC_QTIP_PORT), "from the process of node-c, TCP 8443 and UDP 8443 are held: no socket binds either",
			"a port binds");

		// msquic takes the packets of the QTIP listener of node-s from XDP only, so plain QUIC over the loopback does not reach
		// it from this process either
		bool up = false;
		bool ran = QtipTestLoopbackDial(ctx, TRANSPORT_QUIC_QTIP_PORT, &up);
		QtipTestCheck(ctx, ran && up == false,
			"from the process of node-c, plain QUIC over the loopback does not reach the QTIP listener of node-s: msquic takes its packets from XDP only",
			"the dial %s", ran ? "came up" : "did not run");

		// The link of QUIC with a TCP header between the two server nodes, across the wire: a QTIP transport as the Client
		// role makes one for an entry qtip:host:port (NodeQtipClientNew)
		QtipTestConfig(ctx, &cfg, false, true);
		TRANSPORT *qtip = TransportQuicClientNew(&cfg);
		bool got = (qtip != NULL && TransportQuicGetXdpStatus(qtip, &xs));
		QtipTestCheck(ctx, got && xs.Datapath == TRANSPORT_QUIC_DATAPATH_QTIP && xs.Qtip, "node-c's QTIP transport asks msquic for QTIP", "status %u, %s", (UINT)got,
			QtipTestDatapath(xs.Datapath));
		Format(address, sizeof(address), "%s:%u", wire, (UINT)TRANSPORT_QUIC_QTIP_PORT);
		// The dial gives up at QTIPTEST_TIMEOUT: a waitable timer is its cancel
		HANDLE timer = CreateWaitableTimerW(NULL, TRUE, NULL);
		LARGE_INTEGER due;
		due.QuadPart = -10000LL * QTIPTEST_TIMEOUT;
		if (timer != NULL)
		{
			SetWaitableTimer(timer, &due, 0, NULL, NULL, FALSE);
		}
		UINT64 t0 = Tick64();
		bool link = (qtip != NULL && QtipTestNodeSession(ctx, NULL, qtip, address, timer));
		UINT64 took = Tick64() - t0;
		if (timer != NULL)
		{
			CloseHandle(timer);
		}
		QtipTestCheck(ctx, link, "node-c's Noise session over QTIP reaches node-s on port 8443 across the wire, with the static key that only node-s holds",
			"the dial to %s did not come up within %I64u ms", address, took);
		if (link)
		{
			Print("QTIP LINK UP: node-c's Noise session over QTIP to node-s at %s came up in %I64u ms\n", address, took);
		}
		else
		{
			Print("QTIP LINK DOWN: node-c's QTIP dial to node-s at %s did not come up within %I64u ms\n", address, took);
		}
		TransportQuicFree(qtip);
	}
	QtipTestAdapterFree(&x);
	QtipTestNodeStop(n);
	if (ctx->NumFailed != 0)
	{
		QtipTestPrintLog(dir);
	}
	QtipTestDeleteDir(dir);
}

RANZ_TEST_TAGS("qtip", qtip_test, "core", "The XDP datapath of msquic and QTIP (CORE-S7-2): default off, Windows Server x64 only, opt-in, the normal datapath as before, the msquic release that ships QTIP, a QTIP listener on 8443 and the node's QuicXdp and Qtip; with serve STOPFILE or dial THUMBPRINT ADDRESS, one of the two server node processes of the XDP job (administrator rights).");
void qtip_test(UINT num, char **arg)
{
	QTIPTEST_CTX *ctx = ZeroMalloc(sizeof(QTIPTEST_CTX));
	bool serve = (num >= 2 && StrCmpi(arg[0], "serve") == 0);
	bool dial = (num >= 2 && StrCmpi(arg[0], "dial") == 0);
	char *wire = (dial && num >= 3 ? arg[2] : NULL);
	QTIPTEST_WATCH watch;
	NODE_CAPS_HOST host;
	CONTROL_CAPS caps;
	UCHAR scalar[PEER_KEY_SIZE];

	Zero(&watch, sizeof(watch));
	watch.Done = CreateEventW(NULL, TRUE, FALSE, NULL);
	watch.Budget = (serve ? QTIPTEST_SERVE_WATCHDOG : QTIPTEST_WATCHDOG);
	HANDLE watchdog = (watch.Done != NULL ? CreateThread(NULL, 0, QtipTestWatch, &watch, 0, NULL) : NULL);
	TRANSPORT *loopback = TransportLoopbackNew("loopback", 0, false);

	Print("QTIP test: the XDP datapath of msquic and QTIP%s\n", serve ? ", node-s of the two server node processes" : (dial ? ", node-c of the two server node processes" : ""));

	if (CryptoInit() == false || TransportQuicAvailable() == false || loopback == NULL)
	{
		Print("  msquic.dll is not present: the QUIC transport cannot run; the test is skipped\n");
	}
	else
	{
		// The static keys of node-s and node-c, the same in serve and dial
		for (UINT i = 0;i < PEER_KEY_SIZE;i++)
		{
			scalar[i] = (UCHAR)(0x31 + i);
			ctx->PeerScalar[i] = (UCHAR)(0x71 + i);
		}
		bool keys = PeerKeyFromScalar(&ctx->Key, scalar) && CryptoX25519PublicKey(ctx->PeerPublic, ctx->PeerScalar);
		Zero(scalar, sizeof(scalar));

		NodeCapsReadHost(&host);
		NodeCapsDecide(&host, &caps);
		ctx->Host = TransportQuicXdpHost();
		ctx->Runtime = caps.Xdp;
		Print("  the XDP runtime of ranz install is %s on this host\n", ctx->Runtime ? "installed" : "not installed");

		if (dial)
		{
			if (QtipTestCheck(ctx, keys, "the static keys of node-s and node-c", "a key could not be made") &&
				QtipTestCheck(ctx, IsEmptyStr(wire) == false, "dial names the address of node-s on the wire", "dial THUMBPRINT ADDRESS: no ADDRESS"))
			{
				QtipTestDial(ctx, arg[1], wire);
			}
		}
		else
		{
			// The certificate of the store: a self-signed ECDSA P-256 certificate of the LocalMachine\My store, its key in the KSP
			PCCERT_CONTEXT cert = (keys ? CryptoCertCreateSelfSigned(QTIPTEST_CN, QTIPTEST_SAN, NULL, 30, CRYPTO_MACHINE) : NULL);
			bool have = (cert != NULL && CryptoCertThumbprintStr(cert, ctx->Thumbprint, sizeof(ctx->Thumbprint)) && CryptoCertAddToStore(cert, NULL, CRYPTO_MACHINE));

			if (QtipTestCheck(ctx, have, "a certificate of the LocalMachine\\My store with its key in the key storage provider of the machine", "the certificate could not be made"))
			{
				if (serve)
				{
					QtipTestServe(ctx, loopback, arg[1]);
				}
				else
				{
					TransportSetLog(QtipTestLogLine, NULL);
					QtipTestRule(ctx);
					QtipTestOptIn(ctx);
					QtipTestQtip(ctx);
					TransportSetLog(NULL, NULL);
					QtipTestNode(ctx, loopback);
				}
			}

			if (cert != NULL)
			{
				CryptoCertRemoveFromStore(ctx->Thumbprint, NULL, CRYPTO_MACHINE);
				CryptoCertDeleteKey(cert);
				CryptoCertFree(cert);
			}
		}

		PeerKeyClose(&ctx->Key);
		Zero(ctx->PeerScalar, sizeof(ctx->PeerScalar));
	}

	TransportLoopbackFree(loopback);

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

	if (ctx->NumFailed == 0)
	{
		Print("QTIP TEST OK\n");
	}
	else
	{
		Print("QTIP TEST FAILED (%u of %u checks failed)\n", ctx->NumFailed, ctx->NumChecks);
	}

	Free(ctx);
}
