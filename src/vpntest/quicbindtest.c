// quicbindtest.c
// Named test of vpntest ("quicbind" command, CORE-H5 #408)
//
// The binding of a QUIC session to its connection. The QUIC transport binds the Noise handshake to the TLS exporter of
// the QUIC connection (NOISE_BINDING_EXPORTER, src/Core/TransportQuicExporter.c), where the build before CORE-H5 bound
// the tls-server-end-point of the certificate, which is the same for every connection to it (finding F1 of
// docs/formal-model.md). The test runs the middlebox of F1: a QUIC listener with the certificate of the server, and so
// its key, that takes the stream of a client and relays it, byte for byte, over a QUIC connection of its own to the
// server. It checks that the handshake of the client fails, that the server takes no session and that the middlebox
// never sees the Login; that message 1, sent again on a new connection, opens no session; and, as the control that
// shows the middlebox is real, that both succeed against the binding of the old build (EndPointBinding). A node of the
// old build and a node of this one are refused cleanly, both ways: the handshake fails at once, with no session. Last
// it measures the cost: the throughput and the CPU time of the process for the data records of a session bound to the
// exporter against one bound to the certificate, on the same loopback. Print "QUICBIND TEST OK" only when every check
// passes; it fails where msquic.dll is not present, since nothing of the binding is tested there (CORE-H5-R, #443).

#include "testlist.h"

#include "Mayaqua/Encrypt.h"
#include "Mayaqua/Kernel.h"
#include "Mayaqua/Memory.h"
#include "Mayaqua/Microsoft.h"
#include "Mayaqua/Str.h"
#include "Mayaqua/Tick64.h"

#include "Core/Transport.h"

#include <stdio.h>

#define	QUICBIND_HUB		"QUICBIND"				// The hub of the Login
#define	QUICBIND_USER		"buser"					// Its user
#define	QUICBIND_PASSWORD	"Quic-Bind-Secret-7"	// Its password, which the middlebox must not read
#define	QUICBIND_END		"end"					// The control record after the data records
#define	QUICBIND_WATCHDOG	300000					// The test process is aborted after this (ms)
#define	QUICBIND_TIMEOUT	15000					// A handshake, an accept or a record within this time (ms)
#define	QUICBIND_REFUSED	5000					// A refused handshake fails within this time (ms)
#define	QUICBIND_POLL		200						// How often a pump of the middlebox looks at the other one (ms)
#define	QUICBIND_LINGER		2000					// A pump goes on this long after the other one ended (ms)
#define	QUICBIND_SEEN		65536					// The bytes from the client that the middlebox keeps
#define	QUICBIND_LISTEN		"127.0.0.1:0"			// The listeners bind an ephemeral port on the loopback
#define	QUICBIND_CN			L"CN=localhost"			// The subject of the server certificate
#define	QUICBIND_SAN		L"localhost"			// Its subject alternative name
#define	QUICBIND_RECORDS	10000					// The data records of a measured session
#define	QUICBIND_RECORD		1400					// The bytes of each: a full-size frame
#define	QUICBIND_ROUNDS		3						// Measured sessions of each binding: the best counts

// The state of the test
typedef struct QUICBIND_CTX
{
	UINT NumChecks;
	UINT NumFailed;
} QUICBIND_CTX;

// The server end of one session, on a thread of its own: it accepts one stream, runs the responder, opens the data
// stream at the first control record, echoes every control record and counts the data records
typedef struct QUICBIND_SERVER
{
	TRANSPORT_LISTENER *Listener;	// It accepts one stream here
	UCHAR Key[NOISE_KEY_SIZE];		// The responder's static key
	bool Accepted;					// The handshake completed
	bool GotControl;				// A control record came: the Login
	UINT64 Records;					// The data records that came
	UINT64 Bytes;					// ... and their bytes
} QUICBIND_SERVER;

// One way of the middlebox: it reads one stream and writes what it read to the other
typedef struct QUICBIND_PUMP
{
	TRANSPORT_STREAM *From;			// It reads here
	TRANSPORT_STREAM *To;			// ... and writes here
	UCHAR *Seen;					// The bytes that went this way, or NULL
	UINT SeenSize;					// ... their number, QUICBIND_SEEN at most
	volatile LONG *Stop;			// Set by the way that ended first
} QUICBIND_PUMP;

// The middlebox: a QUIC listener with the certificate of the server, and a QUIC client that dials the server
typedef struct QUICBIND_RELAY
{
	TRANSPORT_LISTENER *Listener;			// The client dials it here
	TRANSPORT *Dialer;						// ... and it dials the server with this
	char Server[TRANSPORT_ADDRESS_SIZE];	// ... at this address
	bool Relayed;							// It had both connections
	UCHAR *Seen;							// The bytes that the client sent, QUICBIND_SEEN at most
	UINT SeenSize;							// ... their number
} QUICBIND_RELAY;

// What one session gave
typedef struct QUICBIND_RUN
{
	bool Connected;					// The handshake of the client completed
	UINT Binding;					// The binding type of its stream
	bool Echoed;					// The server echoed the Login and the end of the data
	UINT64 HandshakeUs;				// The dial and the handshake (us)
	UINT64 DataUs;					// The data records, from the first to the echo of the end (us)
	UINT64 CpuUs;					// The CPU time of the process over the data records (us)
	QUICBIND_SERVER Server;			// What the server saw
} QUICBIND_RUN;

static bool QuicBindCheck(QUICBIND_CTX *ctx, bool ok, char *what, char *fmt, ...) RANZ_PRINTF_FORMAT(4, 5);
static bool QuicBindCheck(QUICBIND_CTX *ctx, bool ok, char *what, char *fmt, ...)
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

// The watchdog: a native thread that ends a run that hangs, so a lost wake-up is a failed test instead of a hung CI
// step
static DWORD WINAPI QuicBindWatchdog(LPVOID param)
{
	char msg[MAX_SIZE];
	DWORD written = 0;

	if (WaitForSingleObject((HANDLE)param, QUICBIND_WATCHDOG) != WAIT_TIMEOUT)
	{
		return 0;
	}

	int len = snprintf(msg, sizeof(msg), "QUICBIND TEST FAILED (did not finish within %u ms)\n", QUICBIND_WATCHDOG);
	if (len > 0)
	{
		WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), msg, (DWORD)MIN((UINT)len, (UINT)sizeof(msg) - 1), &written, NULL);
	}

	TerminateProcess(GetCurrentProcess(), 1);

	return 0;
}

// Microseconds of the performance counter
static UINT64 QuicBindNowUs()
{
	LARGE_INTEGER now, freq;

	QueryPerformanceCounter(&now);
	QueryPerformanceFrequency(&freq);

	return (UINT64)(now.QuadPart / freq.QuadPart) * 1000000 + (UINT64)(now.QuadPart % freq.QuadPart) * 1000000 / (UINT64)freq.QuadPart;
}

// The CPU time of the process, user and kernel, in microseconds
static UINT64 QuicBindCpuUs()
{
	FILETIME created, exited, kernel, user;
	ULARGE_INTEGER k, u;

	if (GetProcessTimes(GetCurrentProcess(), &created, &exited, &kernel, &user) == false)
	{
		return 0;
	}
	k.LowPart = kernel.dwLowDateTime;
	k.HighPart = kernel.dwHighDateTime;
	u.LowPart = user.dwLowDateTime;
	u.HighPart = user.dwHighDateTime;

	return (k.QuadPart + u.QuadPart) / 10;
}

// Whether size bytes at data hold the string s
static bool QuicBindHas(const UCHAR *data, UINT size, char *s)
{
	UINT len = StrLen(s);

	for (UINT i = 0; len != 0 && i + len <= size; i++)
	{
		if (Cmp((void *)(data + i), s, len) == 0)
		{
			return true;
		}
	}

	return false;
}

// The configuration of both ends: the static key, the expected key of the responder, short timers
static void QuicBindConfig(NOISE_SESSION_CONFIG *c, UCHAR *key, UCHAR *remote)
{
	Zero(c, sizeof(NOISE_SESSION_CONFIG));
	c->Suite = NOISE_SUITE_IK;
	c->StaticKey = key;
	c->RemoteStatic = remote;
	c->KeepaliveInterval = 2000;
	c->DeadTimeout = QUICBIND_TIMEOUT;
	c->RekeyInterval = 60000;
}

// The server thread: accept one stream and run the responder; the first control record opens the data stream, every
// control record goes back, and the data records are counted, until the client closes
static void QuicBindServerThread(THREAD *thread, void *param)
{
	QUICBIND_SERVER *srv = (QUICBIND_SERVER *)param;
	TRANSPORT_NOISE *n = ZeroMalloc(sizeof(TRANSPORT_NOISE));
	UCHAR *buf = ZeroMalloc(NOISE_MAX_PAYLOAD);
	TRANSPORT_STREAM *s = TransportAccept(srv->Listener, QUICBIND_TIMEOUT);
	NOISE_SESSION_CONFIG sc;

	QuicBindConfig(&sc, srv->Key, NULL);
	srv->Accepted = (s != NULL && TransportNoiseAccept(n, s, &sc, QUICBIND_TIMEOUT));

	while (srv->Accepted)
	{
		UINT size = 0;
		UINT ret = TransportNoiseReceive(n, buf, NOISE_MAX_PAYLOAD, &size, QUICBIND_TIMEOUT);

		if (ret == NOISE_RECEIVE_CONTROL)
		{
			if (srv->GotControl == false)
			{
				TransportNoiseAcceptLogin(n);
				srv->GotControl = true;
			}
			TransportNoiseSend(n, NOISE_RECORD_CONTROL, buf, size);
		}
		else if (ret == NOISE_RECEIVE_DATA)
		{
			srv->Records++;
			srv->Bytes += size;
		}
		else if (ret != NOISE_RECEIVE_NONE)
		{
			break;
		}
	}

	TransportNoiseClose(n);
	Free(buf);
	Free(n);
}

// One way of the middlebox, until its stream ends, or the other way ended and nothing came for QUICBIND_LINGER
static void QuicBindPump(QUICBIND_PUMP *p)
{
	UCHAR buf[4096];
	UINT64 end = 0;
	UINT64 last = Tick64();

	while (true)
	{
		UINT n = TransportRead(p->From, buf, sizeof(buf), QUICBIND_POLL);

		if (n == TRANSPORT_LATER)
		{
			// A way that stays quiet for a whole timeout has ended, whatever its stream says
			if (Tick64() - last >= QUICBIND_TIMEOUT)
			{
				break;
			}
			if (InterlockedCompareExchange(p->Stop, 0, 0) != 0)
			{
				if (end == 0)
				{
					end = Tick64() + QUICBIND_LINGER;
				}
				else if (Tick64() >= end)
				{
					break;
				}
			}
			continue;
		}
		if (n == 0)
		{
			break;
		}
		last = Tick64();
		if (p->Seen != NULL && p->SeenSize < QUICBIND_SEEN)
		{
			UINT take = MIN(n, QUICBIND_SEEN - p->SeenSize);
			Copy(p->Seen + p->SeenSize, buf, take);
			p->SeenSize += take;
		}
		if (TransportWrite(p->To, buf, n) == false)
		{
			break;
		}
	}

	InterlockedExchange(p->Stop, 1);
}

static void QuicBindPumpThread(THREAD *thread, void *param)
{
	QuicBindPump((QUICBIND_PUMP *)param);
}

// The middlebox thread: take the stream of the client, dial the server, and relay both ways, keeping what the client
// sent
static void QuicBindRelayThread(THREAD *thread, void *param)
{
	QUICBIND_RELAY *r = (QUICBIND_RELAY *)param;
	TRANSPORT_STREAM *in = TransportAccept(r->Listener, QUICBIND_TIMEOUT);
	TRANSPORT_STREAM *out = (in != NULL ? TransportDial(r->Dialer, r->Server, NULL) : NULL);

	if (in != NULL && out != NULL)
	{
		volatile LONG stop = 0;
		QUICBIND_PUMP up, down;

		Zero(&up, sizeof(up));
		Zero(&down, sizeof(down));
		up.From = in;
		up.To = out;
		up.Seen = r->Seen;
		up.Stop = &stop;
		down.From = out;
		down.To = in;
		down.Stop = &stop;
		r->Relayed = true;

		THREAD *t = NewThread(QuicBindPumpThread, &up);
		QuicBindPump(&down);
		WaitThread(t, INFINITE);
		ReleaseThread(t);
		r->SeenSize = up.SeenSize;
	}

	if (out != NULL)
	{
		TransportClose(out);
	}
	if (in != NULL)
	{
		TransportClose(in);
	}
}

// Receive the next control record on the client side: whether it is the one of size bytes at data
static bool QuicBindEcho(TRANSPORT_NOISE *n, UCHAR *buf, const void *data, UINT size)
{
	UINT got = 0;

	return TransportNoiseReceive(n, buf, NOISE_MAX_PAYLOAD, &got, QUICBIND_TIMEOUT) == NOISE_RECEIVE_CONTROL && got == size &&
		Cmp(buf, (void *)data, size) == 0;
}

// One session of a client with its own static key against the server with server_key: straight to the server, or
// through the middlebox relay when it is not NULL. The client sends its Login, then records data records and the end,
// each acknowledged by the echo of the server, and closes.
static void QuicBindSession(TRANSPORT *server, TRANSPORT *client, QUICBIND_RELAY *relay, TRANSPORT *relay_server,
	UCHAR *server_key, UCHAR *server_pub, UCHAR *client_key, UINT records, QUICBIND_RUN *run)
{
	NOISE_SESSION_CONFIG cc;
	NOISE_LOGIN login;
	char address[TRANSPORT_ADDRESS_SIZE];
	TRANSPORT_NOISE *n = ZeroMalloc(sizeof(TRANSPORT_NOISE));
	UCHAR *buf = ZeroMalloc(NOISE_MAX_PAYLOAD);
	THREAD *relay_thread = NULL;
	UINT size = 0;

	Zero(run, sizeof(QUICBIND_RUN));
	run->Binding = NOISE_BINDING_NONE;

	run->Server.Listener = TransportListen(server, QUICBIND_LISTEN);
	Copy(run->Server.Key, server_key, NOISE_KEY_SIZE);
	Format(address, sizeof(address), "127.0.0.1:%u", (UINT)TransportQuicBoundPort(server));
	THREAD *server_thread = NewThread(QuicBindServerThread, &run->Server);

	// The middlebox listens with the certificate of the server and dials the server's address
	if (relay != NULL)
	{
		relay->Listener = TransportListen(relay_server, QUICBIND_LISTEN);
		StrCpy(relay->Server, sizeof(relay->Server), address);
		Format(address, sizeof(address), "127.0.0.1:%u", (UINT)TransportQuicBoundPort(relay_server));
		relay_thread = NewThread(QuicBindRelayThread, relay);
	}

	QuicBindConfig(&cc, client_key, server_pub);
	UINT64 start = QuicBindNowUs();
	TRANSPORT_STREAM *stream = TransportDial(client, address, NULL);
	run->Connected = (stream != NULL && TransportNoiseConnect(n, stream, &cc, QUICBIND_TIMEOUT));
	run->HandshakeUs = QuicBindNowUs() - start;

	if (run->Connected)
	{
		UCHAR binding[NOISE_MAX_BINDING];
		UINT binding_size = 0;

		run->Binding = (n->Session.Flags & NOISE_SESSION_ENCRYPT) != 0 ? NOISE_BINDING_NONE : TransportBinding(stream, binding, sizeof(binding), &binding_size);

		Zero(&login, sizeof(login));
		login.Method = NOISE_LOGIN_PASSWORD;
		StrCpy(login.HubName, sizeof(login.HubName), QUICBIND_HUB);
		StrCpy(login.UserName, sizeof(login.UserName), QUICBIND_USER);
		StrCpy(login.Password, sizeof(login.Password), QUICBIND_PASSWORD);

		UCHAR *login_record = ZeroMalloc(NOISE_MAX_PAYLOAD);
		bool echoed = NoiseLoginEncode(&login, login_record, NOISE_MAX_PAYLOAD, &size) && TransportNoiseSend(n, NOISE_RECORD_CONTROL, login_record, size) &&
			QuicBindEcho(n, buf, login_record, size);
		Zero(&login, sizeof(login));
		Zero(login_record, NOISE_MAX_PAYLOAD);
		Free(login_record);

		if (echoed)
		{
			UCHAR *record = ZeroMalloc(QUICBIND_RECORD);
			UINT64 data_start = QuicBindNowUs();
			UINT64 cpu_start = QuicBindCpuUs();

			for (UINT i = 0; echoed && i < records; i++)
			{
				WRITE_UINT(record, i);
				echoed = TransportNoiseSend(n, NOISE_RECORD_DATA, record, QUICBIND_RECORD);
			}
			// The end comes after every data record on the stream, so its echo says the server took them all
			echoed = echoed && TransportNoiseSend(n, NOISE_RECORD_CONTROL, QUICBIND_END, StrLen(QUICBIND_END)) && QuicBindEcho(n, buf, QUICBIND_END, StrLen(QUICBIND_END));
			run->DataUs = QuicBindNowUs() - data_start;
			run->CpuUs = QuicBindCpuUs() - cpu_start;
			Free(record);
		}
		run->Echoed = echoed;
	}

	TransportNoiseClose(n);
	WaitThread(server_thread, INFINITE);
	ReleaseThread(server_thread);
	TransportCloseListener(run->Server.Listener);
	run->Server.Listener = NULL;

	if (relay_thread != NULL)
	{
		WaitThread(relay_thread, INFINITE);
		ReleaseThread(relay_thread);
		TransportCloseListener(relay->Listener);
		relay->Listener = NULL;
	}

	Free(buf);
	Free(n);
}

// Send size bytes that a middlebox kept to the server again, on a new QUIC connection of its own: what the server takes
static void QuicBindReplay(TRANSPORT *server, TRANSPORT *client, UCHAR *server_key, const UCHAR *bytes, UINT size, QUICBIND_SERVER *srv)
{
	char address[TRANSPORT_ADDRESS_SIZE];

	Zero(srv, sizeof(QUICBIND_SERVER));
	srv->Listener = TransportListen(server, QUICBIND_LISTEN);
	Copy(srv->Key, server_key, NOISE_KEY_SIZE);
	Format(address, sizeof(address), "127.0.0.1:%u", (UINT)TransportQuicBoundPort(server));
	THREAD *thread = NewThread(QuicBindServerThread, srv);

	TRANSPORT_STREAM *stream = TransportDial(client, address, NULL);
	if (stream != NULL)
	{
		TransportWrite(stream, bytes, size);
	}

	// The stream stays open until the server is done with what it got
	WaitThread(thread, INFINITE);
	ReleaseThread(thread);
	if (stream != NULL)
	{
		TransportClose(stream);
	}
	TransportCloseListener(srv->Listener);
	srv->Listener = NULL;
}

// The best of QUICBIND_ROUNDS measured sessions of a client against a server: the highest throughput, and the CPU
// time of that session. false when a session did not carry every record.
static bool QuicBindMeasure(TRANSPORT *server, TRANSPORT *client, UCHAR *server_key, UCHAR *server_pub, UCHAR *client_key,
	UINT *binding, double *mbps, double *cpu_per_mb, double *handshake_ms)
{
	bool ok = true;
	double mb = (double)QUICBIND_RECORDS * QUICBIND_RECORD / 1000000.0;
	QUICBIND_RUN *run = ZeroMalloc(sizeof(QUICBIND_RUN));

	*mbps = 0;
	*cpu_per_mb = 0;
	*handshake_ms = 0;
	*binding = NOISE_BINDING_NONE;

	for (UINT i = 0; i < QUICBIND_ROUNDS; i++)
	{
		QuicBindSession(server, client, NULL, NULL, server_key, server_pub, client_key, QUICBIND_RECORDS, run);
		if (run->Echoed == false || run->Server.Records != QUICBIND_RECORDS || run->DataUs == 0)
		{
			ok = false;
			continue;
		}

		double rate = mb / ((double)run->DataUs / 1000000.0);
		if (rate > *mbps)
		{
			*mbps = rate;
			*cpu_per_mb = ((double)run->CpuUs / 1000.0) / mb;
			*handshake_ms = (double)run->HandshakeUs / 1000.0;
			*binding = run->Binding;
		}
	}

	Free(run);

	return ok;
}

RANZ_TEST_TAGS("quicbind", quicbind_test, "core", "QUIC binding (CORE-H5): a middlebox with the key of the certificate cannot relay a session, a replayed message 1 opens none, an old node is refused cleanly, and the cost against the old binding.");
void quicbind_test(UINT num, char **arg)
{
	QUICBIND_CTX *ctx = ZeroMalloc(sizeof(QUICBIND_CTX));
	char thumbprint[MAX_SIZE];
	HANDLE done = CreateEventW(NULL, TRUE, FALSE, NULL);
	HANDLE watchdog = (done != NULL ? CreateThread(NULL, 0, QuicBindWatchdog, done, 0, NULL) : NULL);

	Print("QUICBIND test: the binding of a QUIC session to the exporter of its connection (CORE-H5)\n");

	if (CryptoInit() == false || TransportQuicAvailable() == false)
	{
		// The binding is not tested where QUIC cannot run, so the test fails there rather than pass on nothing (CORE-H5-R,
		// #443): every job that runs it fetches msquic.dll next to vpntest
		Print("  msquic.dll is not present: the QUIC transport cannot run, so the binding is not tested\n");
		Print("QUICBIND TEST FAILED (msquic.dll is not present)\n");
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
		Free(ctx);
		return;
	}

	// The certificate of the server, in the current user's My store: the server and the middlebox both present it, so
	// the middlebox holds its key, and every client pins its thumbprint
	UINT scope = 0;
	PCCERT_CONTEXT cert = CryptoCertCreateSelfSigned(QUICBIND_CN, QUICBIND_SAN, NULL, 30, scope);
	bool have_cert = (cert != NULL && CryptoCertThumbprintStr(cert, thumbprint, sizeof(thumbprint)) && CryptoCertAddToStore(cert, NULL, scope));
	QuicBindCheck(ctx, have_cert, "a self-signed certificate in the My store, which the server and the middlebox both hold", "CryptoCertCreateSelfSigned or the store failed");

	if (have_cert)
	{
		// The transports: the server and the client of this build, the server and the client of the old one
		// (EndPointBinding), and the middlebox, a server with the same certificate and a client that dials the server
		TRANSPORT_QUIC_CONFIG server_cfg, client_cfg, old_server_cfg, old_client_cfg;
		TransportQuicDefaultConfig(&server_cfg, thumbprint, false);
		TransportQuicDefaultConfig(&client_cfg, thumbprint, false);
		TransportQuicDefaultConfig(&old_server_cfg, thumbprint, false);
		TransportQuicDefaultConfig(&old_client_cfg, thumbprint, false);
		old_server_cfg.EndPointBinding = true;
		old_client_cfg.EndPointBinding = true;

		TRANSPORT *server = TransportQuicServerNew(&server_cfg);
		TRANSPORT *client = TransportQuicClientNew(&client_cfg);
		TRANSPORT *old_server = TransportQuicServerNew(&old_server_cfg);
		TRANSPORT *old_client = TransportQuicClientNew(&old_client_cfg);
		TRANSPORT *mb_server = TransportQuicServerNew(&server_cfg);
		TRANSPORT *mb_client = TransportQuicClientNew(&client_cfg);

		if (QuicBindCheck(ctx, server != NULL && client != NULL && old_server != NULL && old_client != NULL && mb_server != NULL && mb_client != NULL,
			"the QUIC transports open on msquic", "a transport could not open"))
		{
			UCHAR server_key[NOISE_KEY_SIZE], server_pub[NOISE_KEY_SIZE];
			UCHAR client_key[NOISE_KEY_SIZE], client_pub[NOISE_KEY_SIZE];
			QUICBIND_RUN *run = ZeroMalloc(sizeof(QUICBIND_RUN));
			QUICBIND_RELAY *relay = ZeroMalloc(sizeof(QUICBIND_RELAY));
			QUICBIND_SERVER *srv = ZeroMalloc(sizeof(QUICBIND_SERVER));
			UCHAR *seen_new = ZeroMalloc(QUICBIND_SEEN);
			UCHAR *seen_old = ZeroMalloc(QUICBIND_SEEN);
			UINT seen_new_size = 0, seen_old_size = 0;

			CryptoX25519GenerateKey(server_key, server_pub);
			CryptoX25519GenerateKey(client_key, client_pub);

			// A session straight to the server: bound to the exporter of its connection
			Print("[a client of this build logs in straight to the server]\n");
			QuicBindSession(server, client, NULL, NULL, server_key, server_pub, client_key, 1, run);
			QuicBindCheck(ctx, run->Connected && run->Echoed && run->Server.GotControl && run->Server.Records == 1, "  the session comes up and carries the Login and a data record",
				"connected %u, echoed %u, login %u, records %u", (UINT)run->Connected, (UINT)run->Echoed, (UINT)run->Server.GotControl, (UINT)run->Server.Records);
			QuicBindCheck(ctx, run->Binding == NOISE_BINDING_EXPORTER, "  the session is bound to the TLS exporter of its QUIC connection", "binding type %u", run->Binding);

			// The middlebox of F1 between a client and a server of this build
			Print("[the middlebox with the key of the certificate relays a client of this build to the server]\n");
			Zero(relay, sizeof(QUICBIND_RELAY));
			relay->Dialer = mb_client;
			relay->Seen = seen_new;
			QuicBindSession(server, client, relay, mb_server, server_key, server_pub, client_key, 1, run);
			seen_new_size = relay->SeenSize;
			QuicBindCheck(ctx, relay->Relayed && seen_new_size != 0, "  the middlebox presents the pinned certificate to the client and has a connection of its own to the server",
				"relayed %u, bytes of the client %u", (UINT)relay->Relayed, seen_new_size);
			QuicBindCheck(ctx, run->Connected == false, "  the handshake of the client fails: the two connections have two exporters", "the client connected");
			QuicBindCheck(ctx, run->Server.Accepted == false && run->Server.GotControl == false && run->Server.Records == 0, "  the server takes no session, no Login and no record",
				"accepted %u, login %u, records %u", (UINT)run->Server.Accepted, (UINT)run->Server.GotControl, (UINT)run->Server.Records);
			QuicBindCheck(ctx, QuicBindHas(seen_new, seen_new_size, QUICBIND_PASSWORD) == false && QuicBindHas(seen_new, seen_new_size, QUICBIND_USER) == false,
				"  the middlebox never sees the Login", "the password or the user name went through the middlebox");

			// Message 1 that the middlebox kept, sent to the server again on a new connection
			Print("[message 1 that the middlebox kept, sent again on a new QUIC connection]\n");
			QuicBindReplay(server, mb_client, server_key, seen_new, seen_new_size, srv);
			QuicBindCheck(ctx, srv->Accepted == false && srv->GotControl == false, "  the replayed message 1 opens no session",
				"accepted %u, login %u", (UINT)srv->Accepted, (UINT)srv->GotControl);

			// The control: the same middlebox against the binding of the old build, the tls-server-end-point, which is the
			// same on both of its connections
			Print("[control: the same middlebox between a client and a server of the old build (tls-server-end-point)]\n");
			Zero(relay, sizeof(QUICBIND_RELAY));
			relay->Dialer = mb_client;
			relay->Seen = seen_old;
			QuicBindSession(old_server, old_client, relay, mb_server, server_key, server_pub, client_key, 1, run);
			seen_old_size = relay->SeenSize;
			QuicBindCheck(ctx, run->Connected && run->Echoed && run->Server.GotControl && run->Binding == NOISE_BINDING_SERVER_END_POINT,
				"  the old binding lets the middlebox relay the session: the server takes the Login (F1)", "connected %u, echoed %u, login %u, binding %u",
				(UINT)run->Connected, (UINT)run->Echoed, (UINT)run->Server.GotControl, run->Binding);
			QuicBindCheck(ctx, QuicBindHas(seen_old, seen_old_size, QUICBIND_PASSWORD), "  ... and it reads the password of the Login in the clear (F1)", "the password did not show");

			QuicBindReplay(old_server, mb_client, server_key, seen_old, seen_old_size, srv);
			QuicBindCheck(ctx, srv->Accepted && srv->GotControl, "  ... and the session that it kept, sent again on a new connection, is taken again with its Login (F1)",
				"accepted %u, login %u", (UINT)srv->Accepted, (UINT)srv->GotControl);

			// A node of the old build and a node of this one: the prologues differ, so the handshake fails at once
			Print("[a node of the old build and a node of this build]\n");
			QuicBindSession(server, old_client, NULL, NULL, server_key, server_pub, client_key, 1, run);
			QuicBindCheck(ctx, run->Connected == false && run->Server.Accepted == false && run->HandshakeUs < (UINT64)QUICBIND_REFUSED * 1000,
				"  a client of the old build is refused cleanly by a server of this build", "connected %u, accepted %u, in %u ms",
				(UINT)run->Connected, (UINT)run->Server.Accepted, (UINT)(run->HandshakeUs / 1000));
			QuicBindSession(old_server, client, NULL, NULL, server_key, server_pub, client_key, 1, run);
			QuicBindCheck(ctx, run->Connected == false && run->Server.Accepted == false && run->HandshakeUs < (UINT64)QUICBIND_REFUSED * 1000,
				"  a client of this build is refused cleanly by a server of the old build", "connected %u, accepted %u, in %u ms",
				(UINT)run->Connected, (UINT)run->Server.Accepted, (UINT)(run->HandshakeUs / 1000));

			// The cost: the data records of a session bound to the exporter against one bound to the certificate
			Print("[the cost: %u data records of %u bytes, bound to the exporter and bound to the certificate]\n", QUICBIND_RECORDS, QUICBIND_RECORD);
			UINT new_binding = 0, old_binding = 0;
			double new_mbps = 0, new_cpu = 0, new_hs = 0, old_mbps = 0, old_cpu = 0, old_hs = 0;
			bool new_ok = QuicBindMeasure(server, client, server_key, server_pub, client_key, &new_binding, &new_mbps, &new_cpu, &new_hs);
			bool old_ok = QuicBindMeasure(old_server, old_client, server_key, server_pub, client_key, &old_binding, &old_mbps, &old_cpu, &old_hs);
			QuicBindCheck(ctx, new_ok && old_ok && new_binding == NOISE_BINDING_EXPORTER && old_binding == NOISE_BINDING_SERVER_END_POINT,
				"  every measured session carries every record", "exporter %u (binding %u), certificate %u (binding %u)", (UINT)new_ok, new_binding, (UINT)old_ok, old_binding);
			Print("QUICBIND COST exporter: %.1f MB/s, %.2f ms CPU per MB, handshake %.1f ms\n", new_mbps, new_cpu, new_hs);
			Print("QUICBIND COST certificate: %.1f MB/s, %.2f ms CPU per MB, handshake %.1f ms\n", old_mbps, old_cpu, old_hs);
			if (old_mbps > 0 && old_cpu > 0)
			{
				Print("QUICBIND COST ratio: throughput %.3f, CPU per MB %.3f (exporter / certificate)\n", new_mbps / old_mbps, new_cpu / old_cpu);
			}

			Zero(server_key, sizeof(server_key));
			Zero(client_key, sizeof(client_key));
			Zero(seen_new, QUICBIND_SEEN);
			Zero(seen_old, QUICBIND_SEEN);
			Free(seen_new);
			Free(seen_old);
			Free(srv);
			Free(relay);
			Free(run);
		}

		TransportQuicFree(mb_client);
		TransportQuicFree(mb_server);
		TransportQuicFree(old_client);
		TransportQuicFree(old_server);
		TransportQuicFree(client);
		TransportQuicFree(server);
	}

	if (cert != NULL)
	{
		CryptoCertRemoveFromStore(thumbprint, NULL, scope);
		CryptoCertDeleteKey(cert);
		CryptoCertFree(cert);
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
		Print("QUICBIND TEST OK\n");
	}
	else
	{
		Print("QUICBIND TEST FAILED (%u of %u checks failed)\n", ctx->NumFailed, ctx->NumChecks);
	}

	Free(ctx);
}
