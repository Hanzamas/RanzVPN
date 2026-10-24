// trojantest.c
// Named Trojan-posture test of vpntest ("trojan" command, CORE-S2-2 #70)
//
// The own-decoy reverse proxy and the client ClientHello posture of the TLS transport of the new core
// (src/Core/TransportTls.c, src/Core/TransportDecoy.c, src/Core/TransportHello.c), over TLS on a test port of the
// loopback interface, never 443, with the server certificate read from the store by its thumbprint. The checks:
// - the own-decoy reverse proxy: a server with a decoy configured reverse-proxies a prober, one whose first bytes after
//   the TLS handshake do not authenticate, to a website the test runs on the loopback interface, so the prober reads that
//   website's bytes byte for byte over its own TLS session and the website reads the prober's bytes byte for byte. One
//   prober sends an HTTP request, another a well-formed first handshake frame of a Ranz client that does not know the
//   server's key, which fails authentication. A valid Ranz client, over the same server, reaches the Noise session and
//   carries records; a server with a decoy and no static key to authenticate with does not open;
// - the classifier on its own (TransportDecoyIsHandshake): a real first handshake frame is taken, an HTTP request and
//   other first bytes are not; the authentication on its own (TransportDecoyAuthenticate): the first handshake frame
//   of a client that knows the server's key authenticates, and not with another key, another binding or cut short;
// - the ClientHello split: with the split toggle on, the client's ClientHello crosses two TCP segments (a capture
//   listener records the segments as they come) and no segment holds the whole server name; with it off, one segment;
// - the SNI omission: with the toggle on, the ClientHello carries no server_name extension; with it off, it carries the
//   server name.
// The test needs no administrator rights: it does not set the machine's Schannel group list (the server and client
// transports are opened with the groups left as they are). It prints "TROJAN TEST OK" only when every check passes.

#include "testlist.h"

#include "Mayaqua/Internat.h"
#include "Mayaqua/Kernel.h"
#include "Mayaqua/Memory.h"
#include "Mayaqua/Str.h"
#include "Mayaqua/Tick64.h"

#include "Core/Transport.h"

#include <WS2tcpip.h>

#include <stdio.h>

#define	TROJAN_WATCHDOG		180000				// The test process is aborted after this (ms)
#define	TROJAN_TIMEOUT		15000				// A handshake, an accept or a record within this time (ms)
#define	TROJAN_SHORT		5000				// A proxied answer or a captured ClientHello shows within this time (ms)
#define	TROJAN_LISTEN		"127.0.0.1:0"		// A listener binds an ephemeral port of the loopback interface: a test port, never 443
#define	TROJAN_CN			L"CN=localhost"		// The subject of the server certificate
#define	TROJAN_SAN			L"localhost"		// Its subject alternative name
#define	TROJAN_HOST			"localhost"			// The server name the client dials, which becomes the SNI when it is not omitted
#define	TROJAN_PROBE		"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n"	// What the prober sends after the TLS handshake
#define	TROJAN_POLL			50					// Poll interval of the capture listener and the decoy website (ms)
#define	TROJAN_CAP			16384				// Bytes of a captured ClientHello or a proxied answer at most
#define	TROJAN_RECORD_HEADER	5				// A TLS record header: the type (1), the version (2) and the length (2)
#define	TROJAN_SEGMENTS		8					// The segments of a captured ClientHello whose bounds the test keeps

// The website's answer, which the prober must read byte for byte; the body ends at the close (Connection: close)
static const char trojan_decoy_page[] =
	"HTTP/1.1 200 OK\r\n"
	"Server: nginx\r\n"
	"Content-Type: text/html; charset=utf-8\r\n"
	"Connection: close\r\n"
	"\r\n"
	"<!doctype html><html><head><title>Welcome</title></head><body><h1>It works</h1></body></html>\n";

// The state of the test
typedef struct TROJAN_CTX
{
	UINT NumChecks;
	UINT NumFailed;
} TROJAN_CTX;

// The decoy website on the loopback interface: it accepts a connection, reads the request, writes the page and closes,
// until the test stops it
typedef struct TROJAN_SITE
{
	SOCKET Listen;						// Its listening socket
	USHORT Port;						// The port it bound
	volatile LONG Stop;					// The test asks it to stop
	UINT NumServed;						// The connections it served
	UCHAR Request[TROJAN_CAP];			// The bytes it read on the last connection ...
	UINT RequestSize;					// ... and their number
} TROJAN_SITE;

// The server of the decoy case: its listener accepts valid Ranz streams only, because a prober is reverse-proxied before
// it becomes a stream the listener gives out
typedef struct TROJAN_SERVER
{
	TRANSPORT_LISTENER *Listener;		// It accepts streams here
	UCHAR Key[NOISE_KEY_SIZE];			// The responder's static key
	UCHAR Pub[NOISE_KEY_SIZE];			// ... and its public half, which the valid client knows in advance
	volatile LONG Stop;					// The test asks the accept loop to stop
	UINT NumSessions;					// The valid Noise sessions it accepted
} TROJAN_SERVER;

// The capture listener of the ClientHello cases: a plain TCP listener that records the segments of a client's first
// flight, so the split shows as two segments and the omission as no server_name
typedef struct TROJAN_DIAL
{
	TRANSPORT *Client;					// The client transport that dials
	USHORT Port;						// The port it dials (the capture listener's)
	bool Done;							// The dial returned
} TROJAN_DIAL;

static bool TrojanCheck(TROJAN_CTX *ctx, bool ok, char *what, char *fmt, ...) RANZ_PRINTF_FORMAT(4, 5);
static bool TrojanCheck(TROJAN_CTX *ctx, bool ok, char *what, char *fmt, ...)
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

// The watchdog: a native thread that ends a run that hangs, so a lost wake-up is a failed test instead of a hung CI step
static DWORD WINAPI TrojanWatchdog(LPVOID param)
{
	char msg[MAX_SIZE];
	DWORD written = 0;

	if (WaitForSingleObject((HANDLE)param, TROJAN_WATCHDOG) != WAIT_TIMEOUT)
	{
		return 0;
	}

	int len = snprintf(msg, sizeof(msg), "TROJAN TEST FAILED (did not finish within %u ms)\n", TROJAN_WATCHDOG);
	if (len > 0)
	{
		WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), msg, (DWORD)MIN((UINT)len, (UINT)sizeof(msg) - 1), &written, NULL);
	}

	TerminateProcess(GetCurrentProcess(), 1);

	return 0;
}

// The configuration of an end of a test session: short timers, so that the session comes up and carries records at once
static void TrojanConfig(NOISE_SESSION_CONFIG *c, UCHAR *key, UCHAR *remote)
{
	Zero(c, sizeof(NOISE_SESSION_CONFIG));
	c->Suite = NOISE_SUITE_IK;
	c->StaticKey = key;
	c->RemoteStatic = remote;
	c->KeepaliveInterval = 1000;
	c->DeadTimeout = TROJAN_TIMEOUT;
	c->RekeyInterval = TROJAN_TIMEOUT;
}

//
// The classifier on its own
//

// A first handshake frame, as the session layer writes one: the 4-byte length, then a handshake record (the type
// NOISE_RECORD_HANDSHAKE, the suite, and size - 2 more bytes). Its size.
static UINT TrojanHandshakeFrame(UCHAR *buf, UINT suite, UINT record_size)
{
	UINT frame = TRANSPORT_FRAME_HEADER + record_size;

	buf[0] = (UCHAR)(record_size >> 24);
	buf[1] = (UCHAR)(record_size >> 16);
	buf[2] = (UCHAR)(record_size >> 8);
	buf[3] = (UCHAR)record_size;
	buf[TRANSPORT_FRAME_HEADER] = NOISE_RECORD_HANDSHAKE;
	buf[TRANSPORT_FRAME_HEADER + 1] = (UCHAR)suite;
	for (UINT i = 2; i < record_size; i++)
	{
		buf[TRANSPORT_FRAME_HEADER + i] = (UCHAR)(i * 7 + 1);
	}

	return frame;
}

// The classifier (TransportDecoyIsHandshake): a real first handshake frame is taken, an HTTP request, a frame whose
// length is no record's, one cut short and one whose record is of another type or an unknown suite are not
static void TrojanClassifier(TROJAN_CTX *ctx)
{
	UCHAR buf[256];
	UINT size;

	Print("[the classifier: a valid first frame against a prober's first bytes]\n");

	// A real IK first handshake frame (an empty payload: 2 + NOISE_IK_MESSAGE1_SIZE bytes of record)
	size = TrojanHandshakeFrame(buf, NOISE_SUITE_IK, 2 + NOISE_IK_MESSAGE1_SIZE);
	TrojanCheck(ctx, TransportDecoyIsHandshake(buf, size), "  a first handshake frame of the IK suite is taken as a valid Ranz session", "it was not");

	// An HTTP request, as a prober sends: its first four bytes are a length no record has
	TrojanCheck(ctx, TransportDecoyIsHandshake((const UCHAR *)TROJAN_PROBE, (UINT)StrLen(TROJAN_PROBE)) == false,
		"  an HTTP request is not taken for a handshake", "it was");

	// A frame whose record is not a handshake record
	size = TrojanHandshakeFrame(buf, NOISE_SUITE_IK, 2 + NOISE_IK_MESSAGE1_SIZE);
	buf[TRANSPORT_FRAME_HEADER] = 0x01;
	TrojanCheck(ctx, TransportDecoyIsHandshake(buf, size) == false, "  a frame whose record is not a handshake record is not taken", "it was");

	// A frame whose record names a suite the node does not run
	size = TrojanHandshakeFrame(buf, 0x7F, 2 + NOISE_IK_MESSAGE1_SIZE);
	TrojanCheck(ctx, TransportDecoyIsHandshake(buf, size) == false, "  a frame of an unknown suite is not taken", "it was");

	// A frame cut short, no whole record behind its length, and no bytes at all
	size = TrojanHandshakeFrame(buf, NOISE_SUITE_IK, 2 + NOISE_IK_MESSAGE1_SIZE);
	TrojanCheck(ctx, TransportDecoyIsHandshake(buf, size - 1) == false && TransportDecoyIsHandshake(buf, 3) == false &&
		TransportDecoyIsHandshake(NULL, 0) == false, "  a frame cut short, too few bytes and no bytes are not taken", "one was");
}

// The first handshake frame of a Ranz client to the server whose static key is server_pub, bound by binding (its type and
// binding_size bytes), as the session layer writes one: the 4-byte length, then the record. Its bytes into buf (max at
// most); its size, 0 when it cannot be made.
static UINT TrojanFrame(UCHAR *buf, UINT max, UCHAR *server_pub, UINT binding_type, UCHAR *binding, UINT binding_size)
{
	UCHAR key[NOISE_KEY_SIZE], pub[NOISE_KEY_SIZE];
	NOISE_SESSION_CONFIG c;
	NOISE_SESSION *s = ZeroMalloc(sizeof(NOISE_SESSION));
	UINT record_size = 0, size = 0;

	CryptoX25519GenerateKey(key, pub);
	TrojanConfig(&c, key, server_pub);
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

// The authentication (TransportDecoyAuthenticate): the first handshake frame of a client that knows the server's key and
// binds the session authenticates; read with another server's key, with another binding (a replay into another TLS
// session) or cut short, it does not, and neither does an HTTP request
static void TrojanAuthenticate(TROJAN_CTX *ctx)
{
	UCHAR server[NOISE_KEY_SIZE], server_pub[NOISE_KEY_SIZE], other[NOISE_KEY_SIZE], other_pub[NOISE_KEY_SIZE];
	UCHAR binding[NOISE_EXPORTER_SIZE], moved[NOISE_EXPORTER_SIZE];
	UCHAR *frame = ZeroMalloc(TROJAN_CAP);

	Print("[the authentication: the first handshake message read with the server's key and the binding of the stream]\n");

	CryptoX25519GenerateKey(server, server_pub);
	CryptoX25519GenerateKey(other, other_pub);
	for (UINT i = 0; i < NOISE_EXPORTER_SIZE; i++)
	{
		binding[i] = (UCHAR)(i + 1);
		moved[i] = (UCHAR)(i + 2);
	}

	UINT size = TrojanFrame(frame, TROJAN_CAP, server_pub, NOISE_BINDING_EXPORTER, binding, NOISE_EXPORTER_SIZE);
	TrojanCheck(ctx, size != 0 && TransportDecoyAuthenticate(frame, size, server, NULL, NOISE_BINDING_EXPORTER, binding, NOISE_EXPORTER_SIZE),
		"  the first handshake frame of a client that knows the server's key authenticates", "it did not (%u bytes)", size);
	TrojanCheck(ctx, size != 0 && TransportDecoyAuthenticate(frame, size, other, NULL, NOISE_BINDING_EXPORTER, binding, NOISE_EXPORTER_SIZE) == false,
		"  read with another server's key, it does not", "it did");
	TrojanCheck(ctx, size != 0 && TransportDecoyAuthenticate(frame, size, server, NULL, NOISE_BINDING_EXPORTER, moved, NOISE_EXPORTER_SIZE) == false,
		"  read with another binding, as a replay into another TLS session, it does not", "it did");
	TrojanCheck(ctx, size != 0 && TransportDecoyAuthenticate(frame, size - 1, server, NULL, NOISE_BINDING_EXPORTER, binding, NOISE_EXPORTER_SIZE) == false &&
		TransportDecoyAuthenticate((const UCHAR *)TROJAN_PROBE, (UINT)StrLen(TROJAN_PROBE), server, NULL, NOISE_BINDING_EXPORTER, binding,
		NOISE_EXPORTER_SIZE) == false, "  cut short it does not, and an HTTP request does not", "one did");

	Zero(server, sizeof(server));
	Zero(other, sizeof(other));
	Free(frame);
}

//
// The decoy website
//

// Whether a read holds a blank line (the end of an HTTP request's headers)
static bool TrojanHasBlankLine(const UCHAR *buf, UINT size)
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

// The decoy website's thread: accept a connection, read the request, write the page and close, until it is stopped
static void TrojanSiteThread(THREAD *thread, void *param)
{
	TROJAN_SITE *site = (TROJAN_SITE *)param;

	while (InterlockedCompareExchange(&site->Stop, 0, 0) == 0)
	{
		WSAPOLLFD p;

		Zero(&p, sizeof(p));
		p.fd = site->Listen;
		p.events = POLLRDNORM;
		if (WSAPoll(&p, 1, TROJAN_POLL) <= 0)
		{
			continue;
		}

		SOCKET c = accept(site->Listen, NULL, NULL);
		if (c == INVALID_SOCKET)
		{
			continue;
		}

		// The request: what comes up to the blank line of an HTTP request, or up to a pause once some bytes came, as a
		// website answers a request it cannot parse; then the page, then the close
		UINT size = 0;
		UINT64 end = Tick64() + TROJAN_SHORT;
		while (size < sizeof(site->Request) && Tick64() < end)
		{
			Zero(&p, sizeof(p));
			p.fd = c;
			p.events = POLLRDNORM;
			if (WSAPoll(&p, 1, TROJAN_POLL) <= 0)
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
			if (TrojanHasBlankLine(site->Request, size))
			{
				break;
			}
		}
		site->RequestSize = size;
		site->NumServed++;

		send(c, trojan_decoy_page, (int)(sizeof(trojan_decoy_page) - 1), 0);
		shutdown(c, SD_SEND);
		closesocket(c);
	}
}

// Start the decoy website on an ephemeral port of the loopback interface; NULL with the port 0 when it cannot listen
static THREAD *TrojanSiteStart(TROJAN_SITE *site)
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

	return NewThread(TrojanSiteThread, site);
}

// Stop the decoy website and close its listener
static void TrojanSiteStop(TROJAN_SITE *site, THREAD *thread)
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
// The decoy server and its valid client
//

// The server's accept loop: it accepts streams (valid Ranz streams only, the probers reverse-proxied before), runs the
// responder, opens the data stream and echoes records until the client closes, until it is stopped
static void TrojanServerThread(THREAD *thread, void *param)
{
	TROJAN_SERVER *srv = (TROJAN_SERVER *)param;
	UCHAR *buf = ZeroMalloc(NOISE_MAX_PAYLOAD);

	while (InterlockedCompareExchange(&srv->Stop, 0, 0) == 0)
	{
		TRANSPORT_STREAM *s = TransportAccept(srv->Listener, TROJAN_POLL);
		if (s == NULL)
		{
			continue;
		}

		TRANSPORT_NOISE *n = ZeroMalloc(sizeof(TRANSPORT_NOISE));
		NOISE_SESSION_CONFIG c;

		TrojanConfig(&c, srv->Key, NULL);
		if (TransportNoiseAccept(n, s, &c, TROJAN_TIMEOUT))
		{
			srv->NumSessions++;
			TransportNoiseAcceptLogin(n);
			while (true)
			{
				UINT size = 0;
				UINT ret = TransportNoiseReceive(n, buf, NOISE_MAX_PAYLOAD, &size, TROJAN_TIMEOUT);

				if (ret != NOISE_RECEIVE_DATA && ret != NOISE_RECEIVE_CONTROL)
				{
					break;
				}
				TransportNoiseSend(n, (ret == NOISE_RECEIVE_DATA ? NOISE_RECORD_DATA : NOISE_RECORD_CONTROL), buf, size);
			}
		}
		TransportNoiseClose(n);
		Free(n);
	}

	Free(buf);
}

// The valid client's end of a session over stream s against the server whose public key is server_pub: the Noise
// session comes up, bound to the TLS exporter, and a data record goes to the server and comes back. The session takes
// s.
static void TrojanValidSession(TROJAN_CTX *ctx, TRANSPORT_STREAM *s, UCHAR *server_pub)
{
	UCHAR key[NOISE_KEY_SIZE], pub[NOISE_KEY_SIZE];
	NOISE_SESSION_CONFIG c;
	TRANSPORT_NOISE *n = ZeroMalloc(sizeof(TRANSPORT_NOISE));
	UCHAR *buf = ZeroMalloc(NOISE_MAX_PAYLOAD);
	UINT size = 0;

	CryptoX25519GenerateKey(key, pub);
	TrojanConfig(&c, key, server_pub);

	bool connected = (s != NULL && TransportNoiseConnect(n, s, &c, TROJAN_TIMEOUT));
	bool bound = (connected && (n->Session.Flags & NOISE_SESSION_ENCRYPT) == 0);
	bool echoed = false;
	if (connected)
	{
		echoed = TransportNoiseSend(n, NOISE_RECORD_DATA, "frame", 5) &&
			TransportNoiseReceive(n, buf, NOISE_MAX_PAYLOAD, &size, TROJAN_TIMEOUT) == NOISE_RECEIVE_DATA && size == 5 && Cmp(buf, "frame", 5) == 0;
	}

	TrojanCheck(ctx, connected && bound && echoed, "  a valid Ranz client reaches the Noise session over the same server and carries a record",
		"connected %u, bound %u, echoed %u", (UINT)connected, (UINT)bound, (UINT)echoed);

	TransportNoiseClose(n);
	Zero(key, sizeof(key));
	Free(buf);
	Free(n);
}

// Read a proxied answer until the server closes the stream or TROJAN_SHORT passes: the bytes into buf (max bytes), their
// number in *size
static void TrojanReadAnswer(TRANSPORT_STREAM *s, UCHAR *buf, UINT max, UINT *size)
{
	UINT64 end = Tick64() + TROJAN_SHORT;

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

// One prober of the decoy case: it completes the TLS handshake with the server at address, sends its first bytes and
// reads what comes back until the server closes. With handshake its first bytes are a well-formed first handshake frame
// of a Ranz client that does not know this server's key (it is made for another server), bound to the prober's own TLS
// session as a real client binds it, so only its authentication fails; else they are an HTTP request. It must read the
// decoy website's bytes byte for byte, and the website must read its first bytes byte for byte.
static void TrojanProber(TROJAN_CTX *ctx, TRANSPORT *prober, char *address, TROJAN_SITE *site, bool handshake)
{
	UCHAR other[NOISE_KEY_SIZE], other_pub[NOISE_KEY_SIZE], binding[NOISE_MAX_BINDING];
	UCHAR *sent = ZeroMalloc(TROJAN_CAP);
	UCHAR *answer = ZeroMalloc(TROJAN_CAP);
	UINT sent_size = 0, answer_size = 0, binding_size = 0;
	UINT page = (UINT)(sizeof(trojan_decoy_page) - 1);
	UINT served = site->NumServed;
	char *kind = (handshake ? "a handshake frame that fails authentication" : "an HTTP request");
	char what[MAX_SIZE];

	TRANSPORT_STREAM *p = TransportDial(prober, address, NULL);
	bool dialled = (p != NULL);
	if (p != NULL && handshake)
	{
		CryptoX25519GenerateKey(other, other_pub);
		UINT binding_type = TransportBinding(p, binding, sizeof(binding), &binding_size);
		sent_size = TrojanFrame(sent, TROJAN_CAP, other_pub, binding_type, binding, binding_size);
		Zero(other, sizeof(other));
	}
	else if (p != NULL)
	{
		sent_size = StrLen(TROJAN_PROBE);
		Copy(sent, TROJAN_PROBE, sent_size);
	}
	bool wrote = (sent_size != 0 && TransportWrite(p, sent, sent_size));
	if (wrote)
	{
		TrojanReadAnswer(p, answer, TROJAN_CAP, &answer_size);
	}
	TransportClose(p);

	Format(what, sizeof(what), "  a prober completes the TLS handshake and sends %s", kind);
	TrojanCheck(ctx, wrote, what, "dialled %u, made %u bytes", (UINT)dialled, sent_size);
	Format(what, sizeof(what), "  the prober that sent %s reads the decoy website's bytes byte for byte over its own TLS session", kind);
	TrojanCheck(ctx, answer_size == page && Cmp(answer, trojan_decoy_page, page) == 0, what, "read %u of %u bytes", answer_size, page);
	Format(what, sizeof(what), "  the decoy website reads the bytes of the prober that sent %s byte for byte", kind);
	TrojanCheck(ctx, site->NumServed == served + 1 && site->RequestSize == sent_size && Cmp(site->Request, sent, sent_size) == 0, what,
		"%u connections, read %u of %u bytes", site->NumServed - served, site->RequestSize, sent_size);

	Free(answer);
	Free(sent);
}

// The own-decoy reverse proxy: a prober whose first bytes after the TLS handshake do not authenticate reads the decoy
// website's bytes byte for byte over its own TLS session; a valid Ranz client over the same server reaches the Noise
// session
static void TrojanDecoy(TROJAN_CTX *ctx, char *thumbprint)
{
	TROJAN_SITE *site = ZeroMalloc(sizeof(TROJAN_SITE));
	TROJAN_SERVER srv;
	TRANSPORT_TLS_CONFIG server_cfg, client_cfg, prober_cfg;
	char address[TRANSPORT_ADDRESS_SIZE];

	Print("[the own-decoy reverse proxy]\n");

	Zero(&srv, sizeof(srv));
	THREAD *site_thread = TrojanSiteStart(site);
	if (TrojanCheck(ctx, site_thread != NULL, "  the decoy website listens on the loopback interface", "it could not listen") == false)
	{
		Free(site);
		return;
	}

	// The server with the decoy, which authenticates the first handshake message with the static key of its sessions,
	// and a valid client and a prober that both pin its certificate
	CryptoX25519GenerateKey(srv.Key, srv.Pub);
	TransportTlsDefaultConfig(&server_cfg, thumbprint, false);
	server_cfg.SetGroups = false;
	Format(server_cfg.Decoy, sizeof(server_cfg.Decoy), "127.0.0.1:%u", (UINT)site->Port);
	TransportTlsDefaultConfig(&client_cfg, thumbprint, false);
	client_cfg.SetGroups = false;
	TransportTlsDefaultConfig(&prober_cfg, thumbprint, false);
	prober_cfg.SetGroups = false;

	// Without a static key, a server with a decoy does not open
	TRANSPORT *keyless = TransportTlsServerNew(&server_cfg);
	TrojanCheck(ctx, keyless == NULL, "  a server with a decoy and no static key to authenticate with does not open", "it opened");
	TransportTlsFree(keyless);

	server_cfg.DecoyKey = srv.Key;
	TRANSPORT *server = TransportTlsServerNew(&server_cfg);
	TRANSPORT *client = TransportTlsClientNew(&client_cfg);
	TRANSPORT *prober = TransportTlsClientNew(&prober_cfg);

	srv.Listener = (server != NULL ? TransportListen(server, TROJAN_LISTEN) : NULL);
	THREAD *srv_thread = (srv.Listener != NULL ? NewThread(TrojanServerThread, &srv) : NULL);

	if (TrojanCheck(ctx, server != NULL && client != NULL && prober != NULL && srv.Listener != NULL && srv_thread != NULL,
		"  the server (with a decoy), a valid client and a prober open", "a transport or the listener could not open"))
	{
		Format(address, sizeof(address), "127.0.0.1:%u", (UINT)TransportTlsBoundPort(server));

		// The valid client first: the Noise session comes up over the server
		TRANSPORT_STREAM *valid = TransportDial(client, address, NULL);
		TrojanCheck(ctx, valid != NULL, "  the valid client completes the TLS handshake", "it did not");
		TrojanValidSession(ctx, valid, srv.Pub);

		// The probers: an HTTP request, then a handshake frame that fails authentication
		TrojanProber(ctx, prober, address, site, false);
		TrojanProber(ctx, prober, address, site, true);

		TrojanCheck(ctx, srv.NumSessions == 1 && site->NumServed == 2,
			"  one valid session reached the server and both probers reached the website: no prober became a session",
			"%u sessions, %u served", srv.NumSessions, site->NumServed);
	}

	InterlockedExchange(&srv.Stop, 1);
	if (srv_thread != NULL)
	{
		WaitThread(srv_thread, INFINITE);
		ReleaseThread(srv_thread);
	}
	TransportCloseListener(srv.Listener);
	TransportTlsFree(prober);
	TransportTlsFree(client);
	TransportTlsFree(server);
	TrojanSiteStop(site, site_thread);
	Zero(srv.Key, sizeof(srv.Key));
	Free(site);
}

//
// The ClientHello split and the SNI omission
//

// The client's dial thread: it dials the capture listener, which reads its ClientHello and closes, so the dial fails
// once it read the server's answer; the test asserts on the captured bytes, not on the dial
static void TrojanDialThread(THREAD *thread, void *param)
{
	TROJAN_DIAL *d = (TROJAN_DIAL *)param;
	char address[TRANSPORT_ADDRESS_SIZE];

	Format(address, sizeof(address), "127.0.0.1:%u", (UINT)d->Port);
	TRANSPORT_STREAM *s = TransportDial(d->Client, address, NULL);
	TransportClose(s);
	d->Done = true;
}

// The length of the ClientHello TLS record from its first bytes: 0 before the 5-byte header is there
static UINT TrojanRecordLength(const UCHAR *buf, UINT size)
{
	if (size < TROJAN_RECORD_HEADER)
	{
		return 0;
	}

	return TROJAN_RECORD_HEADER + (((UINT)buf[3] << 8) | buf[4]);
}

// Whether the captured ClientHello has a server_name extension, and the host it names into host (host_max bytes). It
// walks the record, the handshake message and the extensions with bounds at every step.
static bool TrojanClientHelloSni(const UCHAR *buf, UINT size, char *host, UINT host_max)
{
	UINT pos, hs_len, body, ext_total, ext_end;

	if (host != NULL && host_max != 0)
	{
		host[0] = 0;
	}

	// The record: handshake (0x16), version, length; the handshake message: ClientHello (0x01), length
	if (size < TROJAN_RECORD_HEADER + 4 || buf[0] != 0x16 || buf[TROJAN_RECORD_HEADER] != 0x01)
	{
		return false;
	}
	hs_len = ((UINT)buf[TROJAN_RECORD_HEADER + 1] << 16) | ((UINT)buf[TROJAN_RECORD_HEADER + 2] << 8) | buf[TROJAN_RECORD_HEADER + 3];
	body = TROJAN_RECORD_HEADER + 4;
	if ((UINT64)body + hs_len > size)
	{
		return false;
	}

	// version (2), random (32), legacy_session_id (1 + len), cipher_suites (2 + len), compression (1 + len)
	pos = body + 2 + 32;
	if (pos + 1 > size)
	{
		return false;
	}
	pos += 1 + buf[pos];
	if (pos + 2 > size)
	{
		return false;
	}
	pos += 2 + (((UINT)buf[pos] << 8) | buf[pos + 1]);
	if (pos + 1 > size)
	{
		return false;
	}
	pos += 1 + buf[pos];
	if (pos + 2 > size)
	{
		return false;
	}

	// The extensions
	ext_total = ((UINT)buf[pos] << 8) | buf[pos + 1];
	pos += 2;
	ext_end = pos + ext_total;
	if (ext_end > size)
	{
		return false;
	}

	while (pos + 4 <= ext_end)
	{
		UINT type = ((UINT)buf[pos] << 8) | buf[pos + 1];
		UINT len = ((UINT)buf[pos + 2] << 8) | buf[pos + 3];

		pos += 4;
		if (pos + len > ext_end)
		{
			return false;
		}

		// server_name (0x0000): server_name_list (2), name_type (1), host_name (2 + len)
		if (type == 0x0000)
		{
			if (len >= 5 && buf[pos + 2] == 0x00)
			{
				UINT name_len = ((UINT)buf[pos + 3] << 8) | buf[pos + 4];

				if (host != NULL && pos + 5 + name_len <= ext_end && name_len < host_max)
				{
					Copy(host, (void *)(buf + pos + 5), name_len);
					host[name_len] = 0;
				}
			}
			return true;
		}
		pos += len;
	}

	return false;
}

// The first segment of a captured flight (total bytes in buf, num segments that start at starts) that holds the whole
// server name TROJAN_HOST; INFINITE when none does
static UINT TrojanNameHolder(const UCHAR *buf, UINT total, const UINT *starts, UINT num)
{
	UINT len = StrLen(TROJAN_HOST);

	for (UINT i = 0; i < num && i < TROJAN_SEGMENTS; i++)
	{
		UINT end = (i + 1 < num && i + 1 < TROJAN_SEGMENTS ? starts[i + 1] : total);

		for (UINT pos = starts[i]; pos + len <= end; pos++)
		{
			if (Cmp(buf + pos, TROJAN_HOST, len) == 0)
			{
				return i;
			}
		}
	}

	return INFINITE;
}

// One ClientHello case: a client with the split and the omission toggles as given dials the capture listener; the
// listener records the segments of the first flight and keeps the bytes of the ClientHello record
static void TrojanHelloCase(TROJAN_CTX *ctx, char *thumbprint, bool split, bool omit)
{
	TRANSPORT_TLS_CONFIG cfg;
	TROJAN_DIAL dial;
	struct sockaddr_in sa;
	int sa_size = sizeof(sa);
	UCHAR *buf = ZeroMalloc(TROJAN_CAP);
	char host[256];
	DWORD on = 1;
	UINT total = 0, segments = 0, record = 0;
	UINT starts[TROJAN_SEGMENTS];

	Zero(starts, sizeof(starts));

	Print("[the ClientHello: split %s, SNI %s]\n", split ? "on" : "off", omit ? "omitted" : "sent");

	TransportTlsDefaultConfig(&cfg, thumbprint, false);
	cfg.SetGroups = false;
	cfg.SplitClientHello = split;
	cfg.OmitSni = omit;
	TRANSPORT *client = TransportTlsClientNew(&cfg);

	// The capture listener: a plain TCP listener on an ephemeral port
	SOCKET l = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	bool ok = (client != NULL && l != INVALID_SOCKET);
	if (ok)
	{
		setsockopt(l, SOL_SOCKET, SO_EXCLUSIVEADDRUSE, (const char *)&on, sizeof(on));
		Zero(&sa, sizeof(sa));
		sa.sin_family = AF_INET;
		sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
		ok = (bind(l, (struct sockaddr *)&sa, sizeof(sa)) == 0 && listen(l, SOMAXCONN) == 0 && getsockname(l, (struct sockaddr *)&sa, &sa_size) == 0);
	}
	if (TrojanCheck(ctx, ok, "  the capture listener and the client open", "they did not") == false)
	{
		if (l != INVALID_SOCKET)
		{
			closesocket(l);
		}
		TransportTlsFree(client);
		Free(buf);
		return;
	}

	// The dial on its own thread; the capture listener accepts it and reads its first flight
	Zero(&dial, sizeof(dial));
	dial.Client = client;
	dial.Port = ntohs(sa.sin_port);
	THREAD *dial_thread = NewThread(TrojanDialThread, &dial);

	SOCKET c = INVALID_SOCKET;
	UINT64 end = Tick64() + TROJAN_SHORT;
	while (c == INVALID_SOCKET && Tick64() < end)
	{
		WSAPOLLFD p;

		Zero(&p, sizeof(p));
		p.fd = l;
		p.events = POLLRDNORM;
		if (WSAPoll(&p, 1, TROJAN_POLL) > 0)
		{
			c = accept(l, NULL, NULL);
		}
	}

	// Each recv that returns data is one TCP segment of the first flight; stop once the ClientHello record is whole
	while (c != INVALID_SOCKET && total < TROJAN_CAP && Tick64() < end)
	{
		WSAPOLLFD p;

		Zero(&p, sizeof(p));
		p.fd = c;
		p.events = POLLRDNORM;
		if (WSAPoll(&p, 1, TROJAN_POLL) <= 0)
		{
			continue;
		}

		int n = recv(c, (char *)buf + total, (int)(TROJAN_CAP - total), 0);
		if (n <= 0)
		{
			break;
		}
		if (segments < TROJAN_SEGMENTS)
		{
			starts[segments] = total;
		}
		segments++;
		total += (UINT)n;

		if (record == 0)
		{
			record = TrojanRecordLength(buf, total);
		}
		if (record != 0 && total >= record)
		{
			break;
		}
	}

	// The capture listener closes, so the client's handshake fails and its dial returns
	if (c != INVALID_SOCKET)
	{
		closesocket(c);
	}
	closesocket(l);
	if (dial_thread != NULL)
	{
		WaitThread(dial_thread, INFINITE);
		ReleaseThread(dial_thread);
	}
	TransportTlsFree(client);

	bool whole = (record != 0 && total >= record);
	Print("  the ClientHello record is %u bytes, read in %u segment%s\n", record, segments, segments == 1 ? "" : "s");
	if (TrojanCheck(ctx, whole, "  the capture listener read the whole ClientHello record", "record %u, read %u", record, total))
	{
		if (split)
		{
			TrojanCheck(ctx, segments >= 2, "  with the split toggle on, the ClientHello crosses two TCP segments", "it came in %u segment(s)", segments);
		}
		if (split && omit == false)
		{
			UINT holder = TrojanNameHolder(buf, total, starts, segments);
			TrojanCheck(ctx, holder == INFINITE, "  with the split toggle on, no segment holds the whole server name", "segment %u holds it", holder + 1);
		}
		else
		{
			TrojanCheck(ctx, segments == 1, "  with the split toggle off, the ClientHello is one TCP segment", "it came in %u segments", segments);
		}

		host[0] = 0;
		bool sni = TrojanClientHelloSni(buf, total, host, sizeof(host));
		if (omit)
		{
			TrojanCheck(ctx, sni == false, "  with SNI omitted, the ClientHello carries no server_name extension", "it names %s", host);
		}
		else
		{
			TrojanCheck(ctx, sni && StrCmp(host, TROJAN_HOST) == 0, "  with SNI sent, the ClientHello names the server in a server_name extension", "found %u, host %s",
				(UINT)sni, host);
		}
	}

	Free(buf);
}

RANZ_TEST_TAGS("trojan", trojan_test, "core", "Trojan posture: a server reverse-proxies a prober whose first bytes do not authenticate to an own decoy website (byte for byte), a valid client reaches the session; the client splits its ClientHello into two TCP segments, the cut in the server name, and omits the SNI to our own servers.");
void trojan_test(UINT num, char **arg)
{
	TROJAN_CTX *ctx = ZeroMalloc(sizeof(TROJAN_CTX));
	HANDLE done = CreateEventW(NULL, TRUE, FALSE, NULL);
	HANDLE watchdog = (done != NULL ? CreateThread(NULL, 0, TrojanWatchdog, done, 0, NULL) : NULL);
	WSADATA wsa;
	char thumbprint[MAX_SIZE];
	UINT scope = 0;

	Print("Trojan test: the own-decoy reverse proxy and the client ClientHello posture of the TLS transport of the new core (CORE-S2-2)\n");

	Zero(&wsa, sizeof(wsa));
	WSAStartup(MAKEWORD(2, 2), &wsa);

	if (TrojanCheck(ctx, CryptoInit(), "the crypto module of the new core runs on CNG", "CryptoInit failed"))
	{
		TrojanClassifier(ctx);
		TrojanAuthenticate(ctx);

		// The server certificate: a self-signed ECDSA P-256 certificate in the current user's My store, its key in the
		// KSP, read by its thumbprint, which the server loads and the clients pin
		StrCpy(thumbprint, sizeof(thumbprint), "");
		PCCERT_CONTEXT cert = CryptoCertCreateSelfSigned(TROJAN_CN, TROJAN_SAN, NULL, 30, scope);
		bool have = (cert != NULL && CryptoCertThumbprintStr(cert, thumbprint, sizeof(thumbprint)) && CryptoCertAddToStore(cert, NULL, scope));
		if (TrojanCheck(ctx, have, "the server certificate is made and read from the store by its thumbprint", "it could not be made"))
		{
			TrojanDecoy(ctx, thumbprint);
			TrojanHelloCase(ctx, thumbprint, false, false);
			TrojanHelloCase(ctx, thumbprint, true, false);
			TrojanHelloCase(ctx, thumbprint, false, true);
			TrojanHelloCase(ctx, thumbprint, true, true);
		}

		if (cert != NULL)
		{
			CryptoCertRemoveFromStore(thumbprint, NULL, scope);
			CryptoCertDeleteKey(cert);
			CryptoCertFree(cert);
		}
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

	WSACleanup();

	if (ctx->NumFailed == 0)
	{
		Print("TROJAN TEST OK\n");
	}
	else
	{
		Print("TROJAN TEST FAILED (%u of %u checks failed)\n", ctx->NumFailed, ctx->NumChecks);
	}

	Free(ctx);
}
