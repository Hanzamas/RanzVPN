// listenerdecoytest.c
// Named Listener decoy test of vpntest ("listenerdecoy" command, AUD1-DT-4 #452)
//
// The decoy of the Listener of a node (Cedar/NodeListener.c, Core/TransportDecoy.c): the Listener of the desired state names
// a loopback address and port, which the node passes to the TLS transport of the new protocol, so that a prober meets a
// website where it met a closed connection. The node runs its overlay in this process without a control stream and takes its
// states from the test (NodeOverlayApply), as the control stream gives them; the Listener of the test names port 0, a test
// port of every address, never 443, and a decoy website on a test port of the loopback interface. The checks:
// - with a decoy, a prober that completes the TLS handshake with the front door and sends a first frame that does not open
//   under the static key of the node (a well-formed handshake frame made for another key, or an HTTP request) reads the
//   answer of the decoy website byte for byte, and the website reads its bytes byte for byte; the overlay of the node takes
//   no stream of it. A real peer, whose first frame opens under the static key, still connects, and the website sees none of
//   its bytes;
// - without a decoy the Listener behaves as before: a prober reads no answer, the website is not asked, a real peer connects;
// - a decoy that is not a loopback address starts nothing and the Listener says why: the node refuses it whoever sent it.
// Print "LISTENERDECOY TEST OK" only when every check passes. Needs administrator rights: the LocalMachine\My store and the
// key storage provider of the machine.

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

#define	LDECOY_WATCHDOG		240000		// The test process is aborted after this (ms)
#define	LDECOY_BOUND		20000		// A bounded wait on observable state (ms)
#define	LDECOY_POLL			20			// Poll interval of observable state (ms)
#define	LDECOY_TIMEOUT		15000		// A Noise handshake within this time (ms)
#define	LDECOY_SHORT		5000		// A proxied answer shows within this time (ms)
#define	LDECOY_SITE_POLL	50			// Poll interval of the decoy website (ms)
#define	LDECOY_CAP			16384		// Bytes of a request or an answer at most
#define	LDECOY_VRF			1			// The VRF of the test
#define	LDECOY_NODE			"node-s"	// The node that listens
#define	LDECOY_PEER			"node-c"	// Its peer, the real client of the new protocol
#define	LDECOY_CN			L"CN=localhost"		// The subject of the certificate
#define	LDECOY_SAN			L"localhost"		// ... and its subject alternative name
#define	LDECOY_PROBE		"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n"	// What the HTTP prober sends after the TLS handshake

// The answer of the decoy website, which a prober must read byte for byte; the body ends at the close
static const char ldecoy_page[] =
	"HTTP/1.1 200 OK\r\n"
	"Server: nginx\r\n"
	"Content-Type: text/html; charset=utf-8\r\n"
	"Connection: close\r\n"
	"\r\n"
	"<!doctype html><html><head><title>Welcome</title></head><body><h1>It works</h1></body></html>\n";

// The decoy website on the loopback interface: it accepts a connection, reads the request, writes the page and closes
typedef struct LDECOY_SITE
{
	SOCKET Listen;						// Its listening socket
	USHORT Port;						// The port it bound
	volatile LONG Stop;					// The test asks it to stop
	volatile LONG NumServed;			// The connections it served
	UCHAR Request[LDECOY_CAP];			// The bytes it read on the last connection ...
	UINT RequestSize;					// ... and their number
} LDECOY_SITE;

// The state of the test
typedef struct LDECOY_CTX
{
	UINT NumChecks;
	UINT NumFailed;
	wchar_t Dir[MAX_PATH];				// The data directory of node-s
	NODE *Node;							// node-s
	PEER_KEY Key;						// Its static key
	UCHAR PeerScalar[PEER_KEY_SIZE];	// The static key of node-c
	UCHAR PeerPublic[PEER_KEY_SIZE];	// ... and its public half
	UINT64 Generation;					// The Generation of the last state applied
	LDECOY_SITE Site;					// The decoy website
} LDECOY_CTX;

static bool ListenerDecoyCheck(LDECOY_CTX *ctx, bool ok, char *what, char *fmt, ...) RANZ_PRINTF_FORMAT(4, 5);
static bool ListenerDecoyCheck(LDECOY_CTX *ctx, bool ok, char *what, char *fmt, ...)
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
static DWORD WINAPI ListenerDecoyWatchdog(LPVOID param)
{
	if (WaitForSingleObject((HANDLE)param, LDECOY_WATCHDOG) == WAIT_TIMEOUT)
	{
		Print("LISTENERDECOY TEST FAILED (the watchdog ended it after %u ms)\n", LDECOY_WATCHDOG);
		fflush(stdout);
		ExitProcess(1);
	}

	return 0;
}

//
// The decoy website
//

// Whether a read holds a blank line (the end of the headers of an HTTP request)
static bool ListenerDecoyHasBlankLine(const UCHAR *buf, UINT size)
{
	for (UINT i = 0; i + 3 < size; i++)
	{
		if (buf[i] == '\r' && buf[i + 1] == '\n' && buf[i + 2] == '\r' && buf[i + 3] == '\n')
		{
			return true;
		}
	}

	return false;
}

// The website's thread: accept a connection, read the request, write the page and close, until it is stopped
static void ListenerDecoySiteThread(THREAD *thread, void *param)
{
	LDECOY_SITE *site = (LDECOY_SITE *)param;

	while (InterlockedCompareExchange(&site->Stop, 0, 0) == 0)
	{
		WSAPOLLFD p;

		Zero(&p, sizeof(p));
		p.fd = site->Listen;
		p.events = POLLRDNORM;
		if (WSAPoll(&p, 1, LDECOY_SITE_POLL) <= 0)
		{
			continue;
		}

		SOCKET c = accept(site->Listen, NULL, NULL);
		if (c == INVALID_SOCKET)
		{
			continue;
		}

		// The request: what comes up to the blank line of an HTTP request, or up to a pause once some bytes came
		UINT size = 0;
		UINT64 end = Tick64() + LDECOY_SHORT;
		while (size < sizeof(site->Request) && Tick64() < end)
		{
			Zero(&p, sizeof(p));
			p.fd = c;
			p.events = POLLRDNORM;
			if (WSAPoll(&p, 1, LDECOY_SITE_POLL) <= 0)
			{
				if (size != 0)
				{
					break;
				}
				continue;
			}
			int n = recv(c, (char *)site->Request + size, (int)(sizeof(site->Request) - size), 0);
			if (n <= 0)
			{
				break;
			}
			size += (UINT)n;
			if (ListenerDecoyHasBlankLine(site->Request, size))
			{
				break;
			}
		}
		site->RequestSize = size;
		InterlockedIncrement(&site->NumServed);

		send(c, ldecoy_page, (int)(sizeof(ldecoy_page) - 1), 0);
		shutdown(c, SD_SEND);
		closesocket(c);
	}
}

// Start the decoy website on an ephemeral port of the loopback interface; NULL with the port 0 when it cannot listen
static THREAD *ListenerDecoySiteStart(LDECOY_SITE *site)
{
	struct sockaddr_in sa;
	int sa_size = sizeof(sa);
	DWORD on = 1;

	site->Port = 0;
	site->Listen = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (site->Listen == INVALID_SOCKET)
	{
		return NULL;
	}
	setsockopt(site->Listen, SOL_SOCKET, SO_EXCLUSIVEADDRUSE, (const char *)&on, sizeof(on));

	Zero(&sa, sizeof(sa));
	sa.sin_family = AF_INET;
	sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	if (bind(site->Listen, (struct sockaddr *)&sa, sizeof(sa)) != 0 || listen(site->Listen, SOMAXCONN) != 0 ||
		getsockname(site->Listen, (struct sockaddr *)&sa, &sa_size) != 0)
	{
		closesocket(site->Listen);
		site->Listen = INVALID_SOCKET;
		return NULL;
	}
	site->Port = ntohs(sa.sin_port);

	return NewThread(ListenerDecoySiteThread, site);
}

// Stop the decoy website and close its listener
static void ListenerDecoySiteStop(LDECOY_SITE *site, THREAD *thread)
{
	InterlockedExchange(&site->Stop, 1);
	if (thread != NULL)
	{
		WaitThread(thread, INFINITE);
		ReleaseThread(thread);
	}
	if (site->Listen != INVALID_SOCKET)
	{
		closesocket(site->Listen);
		site->Listen = INVALID_SOCKET;
	}
}

//
// The node and its Listener
//

// Apply a state of node-s to its overlay, as the control stream does: its address in VRF 1, node-c as its peer, and the
// Listener l, NULL for none
static bool ListenerDecoyApply(LDECOY_CTX *ctx, CONTROL_LISTENER *l)
{
	CONTROL_STATE st;
	CONTROL_PEER peer;
	UCHAR self[4] = {100, 64, 0, 1};
	UCHAR other[4] = {100, 64, 0, 2};

	Zero(&st, sizeof(st));
	Zero(&peer, sizeof(peer));

	st.Generation = ++ctx->Generation;
	StrCpy(st.Name, sizeof(st.Name), LDECOY_NODE);
	StrCpy(st.Addresses[0].Network, sizeof(st.Addresses[0].Network), "default");
	st.Addresses[0].VrfId = LDECOY_VRF;
	Copy(st.Addresses[0].Address, self, 4);
	st.Addresses[0].AddressSize = 4;
	st.Addresses[0].Length = 10;
	st.NumAddresses = 1;

	StrCpy(peer.Name, sizeof(peer.Name), LDECOY_PEER);
	Copy(peer.Key, ctx->PeerPublic, PEER_KEY_SIZE);
	peer.NumVrfs = 1;
	peer.VrfIds[0] = LDECOY_VRF;
	StrCpy(peer.Addresses[0].Network, sizeof(peer.Addresses[0].Network), "default");
	peer.Addresses[0].VrfId = LDECOY_VRF;
	Copy(peer.Addresses[0].Address, other, 4);
	peer.Addresses[0].AddressSize = 4;
	peer.Addresses[0].Length = 10;
	peer.NumAddresses = 1;
	st.Peers = &peer;
	st.NumPeers = 1;

	st.Listener = l;

	return NodeOverlayApply(ctx->Node, &st);
}

// A Listener of the test with the certificate thumb of the store and the decoy decoy ("" for none): port 0 for TCP and UDP,
// which the node binds as ports that the system picks
static void ListenerDecoyListener(CONTROL_LISTENER *l, char *thumb, char *decoy)
{
	Zero(l, sizeof(CONTROL_LISTENER));
	StrCpy(l->Name, sizeof(l->Name), "edge");
	l->Source = CONTROL_CERT_KSP;
	StrCpy(l->Thumbprint, sizeof(l->Thumbprint), thumb);
	StrCpy(l->Decoy, sizeof(l->Decoy), decoy);
}

// The number of Noise sessions of the overlay of node-s
static UINT ListenerDecoyLinks(LDECOY_CTX *ctx)
{
	NODE_OVERLAY_STATUS st;

	NodeOverlayGetStatus(ctx->Node, &st);

	return st.NumLinks;
}

// Whether the overlay of node-s has links sessions within LDECOY_BOUND
static bool ListenerDecoyWaitLinks(LDECOY_CTX *ctx, UINT links)
{
	for (UINT64 end = Tick64() + LDECOY_BOUND;Tick64() < end;SleepThread(LDECOY_POLL))
	{
		if (ListenerDecoyLinks(ctx) == links)
		{
			return true;
		}
	}

	return false;
}

// The client transport of the test, pinned to the certificate thumb: it dials the front door of node-s
static TRANSPORT *ListenerDecoyClient(char *thumb)
{
	TRANSPORT_TLS_CONFIG cfg;

	TransportTlsDefaultConfig(&cfg, thumb, false);
	cfg.SetGroups = false;

	return TransportTlsClientNew(&cfg);
}

// node-c, the real client: dial the port of node-s over the client transport t and open the Noise session with the static
// key of node-s; whether the overlay of node-s took it as the session of its peer. The session closes again, and the overlay
// sees it go.
static bool ListenerDecoySession(LDECOY_CTX *ctx, TRANSPORT *t, UINT port)
{
	char address[MAX_SIZE];
	NOISE_SESSION_CONFIG cfg;
	bool ok = false;

	Format(address, sizeof(address), "127.0.0.1:%u", port);
	TRANSPORT_STREAM *s = TransportDial(t, address, NULL);
	if (s == NULL)
	{
		return false;
	}

	TRANSPORT_NOISE *n = ZeroMalloc(sizeof(TRANSPORT_NOISE));
	Zero(&cfg, sizeof(cfg));
	cfg.Suite = NOISE_SUITE_IK;
	cfg.StaticKey = ctx->PeerScalar;
	cfg.RemoteStatic = ctx->Key.Public;
	if (TransportNoiseConnect(n, s, &cfg, LDECOY_TIMEOUT))
	{
		ok = ListenerDecoyWaitLinks(ctx, 1);
		TransportNoiseClose(n);
		ok = ListenerDecoyWaitLinks(ctx, 0) && ok;
	}
	Free(n);

	return ok;
}

//
// The prober
//

// The first handshake frame of a Ranz client to the server whose static key is server_pub, bound by binding (its type and
// binding_size bytes), as the session layer writes one: the 4-byte length, then the record. Its bytes into buf (max at most);
// its size, 0 when it cannot be made.
static UINT ListenerDecoyFrame(UCHAR *buf, UINT max, UCHAR *server_pub, UINT binding_type, UCHAR *binding, UINT binding_size)
{
	UCHAR key[NOISE_KEY_SIZE], pub[NOISE_KEY_SIZE];
	NOISE_SESSION_CONFIG c;
	NOISE_SESSION *s = ZeroMalloc(sizeof(NOISE_SESSION));
	UINT record_size = 0, size = 0;

	CryptoX25519GenerateKey(key, pub);
	Zero(&c, sizeof(c));
	c.Suite = NOISE_SUITE_IK;
	c.StaticKey = key;
	c.RemoteStatic = server_pub;
	c.BindingType = binding_type;
	c.Binding = binding;
	c.BindingSize = binding_size;

	if (max > TRANSPORT_FRAME_HEADER &&
		NoiseSessionConnect(s, &c, Tick64(), buf + TRANSPORT_FRAME_HEADER, max - TRANSPORT_FRAME_HEADER, &record_size))
	{
		buf[0] = (UCHAR)(record_size >> 24);
		buf[1] = (UCHAR)(record_size >> 16);
		buf[2] = (UCHAR)(record_size >> 8);
		buf[3] = (UCHAR)record_size;
		size = TRANSPORT_FRAME_HEADER + record_size;
	}

	NoiseSessionFree(s);
	Free(s);
	Zero(key, sizeof(key));

	return size;
}

// Read an answer until the server closes the stream or LDECOY_SHORT passes: the bytes into buf (max bytes), their number in *size
static void ListenerDecoyReadAnswer(TRANSPORT_STREAM *s, UCHAR *buf, UINT max, UINT *size)
{
	UINT64 end = Tick64() + LDECOY_SHORT;

	*size = 0;
	while (*size < max && Tick64() < end)
	{
		UINT n = TransportRead(s, buf + *size, max - *size, 100);

		if (n == 0)
		{
			break;
		}
		if (n != TRANSPORT_LATER)
		{
			*size += n;
		}
	}
}

// One prober: it completes the TLS handshake with the front door at port, sends its first bytes and reads what comes back until
// the server closes. With handshake its first bytes are a well-formed first handshake frame of a Ranz client that does not know
// the static key of node-s (it is made for another key), bound to the prober's own TLS session as a real client binds it, so
// only its authentication fails; else they are an HTTP request. With decoy it must read the page of the decoy website byte for
// byte, and the website must read its first bytes byte for byte, and the overlay of node-s must take no stream of it; without
// one it reads nothing and the website is not asked.
static void ListenerDecoyProber(LDECOY_CTX *ctx, TRANSPORT *prober, UINT port, bool handshake, bool decoy)
{
	UCHAR other[NOISE_KEY_SIZE], other_pub[NOISE_KEY_SIZE], binding[NOISE_MAX_BINDING];
	UCHAR *sent = ZeroMalloc(LDECOY_CAP);
	UCHAR *answer = ZeroMalloc(LDECOY_CAP);
	UINT sent_size = 0, answer_size = 0, binding_size = 0;
	UINT page = (UINT)(sizeof(ldecoy_page) - 1);
	LONG served = InterlockedCompareExchange(&ctx->Site.NumServed, 0, 0);
	NODE_LISTENER_STATUS st;
	char address[MAX_SIZE];
	char *kind = (handshake ? "a first frame that does not open under the key of the node" : "an HTTP request");
	char what[MAX_SIZE];

	NodeListenerGetStatus(ctx->Node, &st);
	UINT64 accepted = st.Accepted;

	Format(address, sizeof(address), "127.0.0.1:%u", port);
	TRANSPORT_STREAM *p = TransportDial(prober, address, NULL);
	bool dialled = (p != NULL);
	if (p != NULL && handshake)
	{
		CryptoX25519GenerateKey(other, other_pub);
		UINT binding_type = TransportBinding(p, binding, sizeof(binding), &binding_size);
		sent_size = ListenerDecoyFrame(sent, LDECOY_CAP, other_pub, binding_type, binding, binding_size);
		Zero(other, sizeof(other));
	}
	else if (p != NULL)
	{
		sent_size = StrLen(LDECOY_PROBE);
		Copy(sent, LDECOY_PROBE, sent_size);
	}
	bool wrote = (sent_size != 0 && TransportWrite(p, sent, sent_size));
	if (wrote)
	{
		ListenerDecoyReadAnswer(p, answer, LDECOY_CAP, &answer_size);
	}
	TransportClose(p);

	Format(what, sizeof(what), "a prober completes the TLS handshake with the front door and sends %s", kind);
	ListenerDecoyCheck(ctx, wrote, what, "dialled %u, made %u bytes", (UINT)dialled, sent_size);

	LONG now = InterlockedCompareExchange(&ctx->Site.NumServed, 0, 0);
	NodeListenerGetStatus(ctx->Node, &st);
	if (decoy)
	{
		Format(what, sizeof(what), "the prober that sent %s reads the page of the decoy over its own TLS session, byte for byte", kind);
		ListenerDecoyCheck(ctx, answer_size == page && Cmp(answer, ldecoy_page, page) == 0, what, "read %u of %u bytes", answer_size, page);
		Format(what, sizeof(what), "the decoy website reads the bytes of the prober that sent %s byte for byte", kind);
		ListenerDecoyCheck(ctx, now == served + 1 && ctx->Site.RequestSize == sent_size && Cmp(ctx->Site.Request, sent, sent_size) == 0, what,
			"%d connections, read %u of %u bytes", (int)(now - served), ctx->Site.RequestSize, sent_size);
		Format(what, sizeof(what), "the overlay of node-s takes no stream of the prober that sent %s", kind);
		ListenerDecoyCheck(ctx, st.Accepted == accepted && ListenerDecoyLinks(ctx) == 0, what, "it took %I64u streams", st.Accepted - accepted);
	}
	else
	{
		Format(what, sizeof(what), "with no decoy the prober that sent %s reads no answer and the website is not asked", kind);
		ListenerDecoyCheck(ctx, answer_size == 0 && now == served, what, "read %u bytes, the website served %d", answer_size, (int)(now - served));
	}

	Free(answer);
	Free(sent);
}

// Delete the files of a directory, then the directory
static void ListenerDecoyDeleteDir(wchar_t *dir)
{
	DIRLIST *d = EnumDirW(dir);

	for (UINT i = 0;d != NULL && i < d->NumFiles;i++)
	{
		DIRENT *e = d->File[i];
		wchar_t path[MAX_PATH];

		ConbinePathW(path, sizeof(path), dir, e->FileNameW);
		if (e->Folder)
		{
			ListenerDecoyDeleteDir(path);
		}
		else
		{
			FileDeleteW(path);
		}
	}

	FreeDir(d);
	DeleteDirW(dir);
}

//
// The steps
//

// The steps of the test on node-s, whose overlay runs; cert is the thumbprint of the certificate of the store
static void ListenerDecoySteps(LDECOY_CTX *ctx, char *cert)
{
	CONTROL_LISTENER l;
	NODE_LISTENER_STATUS st;
	char decoy[MAX_SIZE];

	Format(decoy, sizeof(decoy), "127.0.0.1:%u", (UINT)ctx->Site.Port);

	TRANSPORT *client = ListenerDecoyClient(cert);
	TRANSPORT *prober = ListenerDecoyClient(cert);
	if (ListenerDecoyCheck(ctx, client != NULL && prober != NULL, "a client of the real peer and a prober open, pinned to the certificate of the store", "a transport could not open") == false)
	{
		TransportTlsFree(client);
		TransportTlsFree(prober);
		return;
	}

	// With a decoy
	Print("[a Listener with a decoy on the loopback interface]\n");
	ListenerDecoyListener(&l, cert, decoy);
	bool applied = ListenerDecoyApply(ctx, &l);
	NodeListenerGetStatus(ctx->Node, &st);
	ListenerDecoyCheck(ctx, applied && st.Running && st.Port != 0 && StrCmp(st.Decoy, decoy) == 0, "the front door listens and the Listener reports its decoy",
		"applied %u, running %u, port %u, decoy %s, error %s", (UINT)applied, (UINT)st.Running, st.Port, st.Decoy, st.Error);
	UINT port = st.Port;

	ListenerDecoyProber(ctx, prober, port, true, true);
	ListenerDecoyProber(ctx, prober, port, false, true);

	LONG served = InterlockedCompareExchange(&ctx->Site.NumServed, 0, 0);
	bool up = ListenerDecoySession(ctx, client, port);
	ListenerDecoyCheck(ctx, up && InterlockedCompareExchange(&ctx->Site.NumServed, 0, 0) == served,
		"a real peer, whose first frame opens under the static key of the node, still connects, and the website sees none of its bytes", "up %u, the website served %d more",
		(UINT)up, (int)(InterlockedCompareExchange(&ctx->Site.NumServed, 0, 0) - served));

	// Without a decoy: the Listener behaves as before
	Print("[a Listener without a decoy]\n");
	ListenerDecoyListener(&l, cert, "");
	applied = ListenerDecoyApply(ctx, &l);
	NodeListenerGetStatus(ctx->Node, &st);
	ListenerDecoyCheck(ctx, applied && st.Running && st.Port != 0 && IsEmptyStr(st.Decoy), "the front door listens and the Listener reports no decoy",
		"applied %u, running %u, port %u, decoy %s, error %s", (UINT)applied, (UINT)st.Running, st.Port, st.Decoy, st.Error);
	port = st.Port;

	ListenerDecoyProber(ctx, prober, port, true, false);
	ListenerDecoyProber(ctx, prober, port, false, false);

	up = ListenerDecoySession(ctx, client, port);
	ListenerDecoyCheck(ctx, up, "a real peer connects", "it did not");

	// A decoy that is not a loopback address: the node refuses it, whoever sent it
	Print("[a decoy that is not a loopback address]\n");
	for (UINT i = 0;i < 3;i++)
	{
		char *bad[3] = {"192.0.2.10:8080", "localhost:8080", "127.0.0.1:0"};

		ListenerDecoyListener(&l, cert, bad[i]);
		applied = ListenerDecoyApply(ctx, &l);
		NodeListenerGetStatus(ctx->Node, &st);
		ListenerDecoyCheck(ctx, applied && st.Running == false && st.Port == 0 && InStr(st.Error, "is not a loopback address"),
			"the decoy is refused: nothing listens and the Listener says why", "decoy %s, running %u, port %u, error %s", bad[i], (UINT)st.Running, st.Port, st.Error);
	}

	TransportTlsFree(prober);
	TransportTlsFree(client);
}

RANZ_TEST("listenerdecoy", listenerdecoy_test, "The decoy of the Listener of a node (AUD1-DT-4): a prober whose first frame does not open under the static key of the node reads the decoy website, a real peer still connects, without a decoy the Listener behaves as before, and a decoy that is not a loopback address is refused (administrator rights).");
void listenerdecoy_test(UINT num, char **arg)
{
	LDECOY_CTX *ctx = ZeroMalloc(sizeof(LDECOY_CTX));
	HANDLE done = CreateEventW(NULL, TRUE, FALSE, NULL);
	HANDLE watchdog = (done != NULL ? CreateThread(NULL, 0, ListenerDecoyWatchdog, done, 0, NULL) : NULL);
	TRANSPORT *loopback = TransportLoopbackNew("loopback", 0, false);
	NODE_OVERLAY_CONFIG cfg;
	UCHAR scalar[PEER_KEY_SIZE];
	wchar_t tmp[MAX_PATH];
	wchar_t path[MAX_PATH];
	char cert_thumbprint[MAX_SIZE];
	WSADATA wsa;

	Print("Listener decoy test: a prober of the TLS of the new protocol meets the decoy that the Listener names (AUD1-DT-4)\n");

	Zero(&wsa, sizeof(wsa));
	WSAStartup(MAKEWORD(2, 2), &wsa);
	StrCpy(cert_thumbprint, sizeof(cert_thumbprint), "");
	ctx->Site.Listen = INVALID_SOCKET;

	// The keys of node-s and node-c
	bool ok = (loopback != NULL && CryptoInit());
	for (UINT i = 0;i < PEER_KEY_SIZE;i++)
	{
		scalar[i] = (UCHAR)(0x31 + i);
		ctx->PeerScalar[i] = (UCHAR)(0x71 + i);
	}
	ok = ok && PeerKeyFromScalar(&ctx->Key, scalar) && CryptoX25519PublicKey(ctx->PeerPublic, ctx->PeerScalar);
	Zero(scalar, sizeof(scalar));

	// The certificate of the store: a self-signed ECDSA P-256 certificate of the LocalMachine\My store, its key in the KSP
	PCCERT_CONTEXT cert = (ok ? CryptoCertCreateSelfSigned(LDECOY_CN, LDECOY_SAN, NULL, 30, CRYPTO_MACHINE) : NULL);
	bool have = (cert != NULL && CryptoCertThumbprintStr(cert, cert_thumbprint, sizeof(cert_thumbprint)) && CryptoCertAddToStore(cert, NULL, CRYPTO_MACHINE));
	ListenerDecoyCheck(ctx, have, "a certificate of the LocalMachine\\My store with its key in the key storage provider of the machine", "the certificate could not be made");

	THREAD *site_thread = (have ? ListenerDecoySiteStart(&ctx->Site) : NULL);
	if (have)
	{
		ListenerDecoyCheck(ctx, site_thread != NULL, "the decoy website listens on the loopback interface", "it could not listen");
	}

	if (site_thread != NULL)
	{
		// node-s, with the overlay that applies the states of the test
		UniFormat(tmp, sizeof(tmp), L"listenerdecoytest_%u", Rand32());
		ConbinePathW(ctx->Dir, sizeof(ctx->Dir), MsGetMyTempDirW(), tmp);
		MakeDirExW(ctx->Dir);
		ConbinePathW(path, sizeof(path), ctx->Dir, CS_FILE_NAME);
		CONFIG_STORE *s = CsOpen(path);
		if (s != NULL)
		{
			CsSetSetting(s, NODE_SETTING_ROLES, "none");
			CsSetSetting(s, NODE_SETTING_WORKERS, "1");
			CsClose(s);
		}

		ctx->Node = NewNode(ctx->Dir);
		NodeStart(ctx->Node);

		Zero(&cfg, sizeof(cfg));
		cfg.Data = loopback;
		cfg.Key = &ctx->Key;
		if (ListenerDecoyCheck(ctx, NodeOverlayStart(ctx->Node, &cfg), "the overlay of node-s runs without a control stream", "NodeOverlayStart failed"))
		{
			ListenerDecoySteps(ctx, cert_thumbprint);
			NodeOverlayStop(ctx->Node);
		}

		NodeStop(ctx->Node);
		FreeNode(ctx->Node);
		ctx->Node = NULL;
		ListenerDecoyDeleteDir(ctx->Dir);
	}

	ListenerDecoySiteStop(&ctx->Site, site_thread);

	if (cert != NULL)
	{
		CryptoCertRemoveFromStore(cert_thumbprint, NULL, CRYPTO_MACHINE);
		CryptoCertDeleteKey(cert);
		CryptoCertFree(cert);
	}
	PeerKeyClose(&ctx->Key);
	Zero(ctx->PeerScalar, sizeof(ctx->PeerScalar));
	TransportLoopbackFree(loopback);

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

	WSACleanup();

	if (ctx->NumFailed == 0)
	{
		Print("LISTENERDECOY TEST OK\n");
	}
	else
	{
		Print("LISTENERDECOY TEST FAILED (%u of %u checks failed)\n", ctx->NumFailed, ctx->NumChecks);
	}

	Free(ctx);
}
