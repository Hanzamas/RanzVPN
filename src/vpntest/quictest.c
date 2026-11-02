// quictest.c
// Named QUIC transport test of vpntest ("quic" command, CORE-S1-1 #67)
//
// The QUIC transport of the new core (src/Core/TransportQuic.c) on the official signed msquic.dll:
// a client completes the QUIC handshake against a listener that presents as an HTTP/3 server (the
// ALPN "h3", a real certificate), the Noise session comes up over one reliable stream of the
// connection, and the node checks the Login through the existing Sam. A valid credential logs in
// and an invalid one does not, matching the node's Account/Sam result; on the first login the
// client's Noise static key is pinned to the user, and a later connection of the same user with a
// different key is refused even with the right password (trust on first use). The channel binding
// is the TLS exporter of the QUIC connection (CORE-H5, #408): a client that computes a different
// binding, as a middlebox that terminated the TLS would, cannot complete the handshake.
// The legacy SE-VPN listener is untouched: this test adds a transport beside it and changes no
// file of the oracle. Print "QUIC TEST OK" only when every check passes; skip, passing, where
// msquic.dll is not present (a build without the runtime fetched), so the suite still runs.

#include "testlist.h"

#include "Cedar/Account.h"
#include "Cedar/Cedar.h"
#include "Cedar/ConfigStore.h"
#include "Cedar/Hub.h"
#include "Cedar/Node.h"
#include "Cedar/Sam.h"

#include "Mayaqua/Encrypt.h"
#include "Mayaqua/FileIO.h"
#include "Mayaqua/Internat.h"
#include "Mayaqua/Kernel.h"
#include "Mayaqua/Memory.h"
#include "Mayaqua/Microsoft.h"
#include "Mayaqua/Str.h"
#include "Mayaqua/Tick64.h"

#include "Core/Transport.h"

#include <stdio.h>

#define	QUICTEST_HUB		"QUICTEST"			// The hub of the node and its one password user
#define	QUICTEST_USER		"quser"				// The password user
#define	QUICTEST_PASSWORD	"Quic-Test-Pass-1"	// Its password
#define	QUICTEST_WRONG		"Quic-Test-Wrong-1"	// No user's password
#define	QUICTEST_WELCOME	"welcome"			// The server's control message after the Login
#define	QUICTEST_WATCHDOG	120000				// The test process is aborted after this (ms)
#define	QUICTEST_TIMEOUT	15000				// A handshake, an accept or a record within this time (ms)
#define	QUICTEST_LISTEN		"127.0.0.1:0"		// The listener binds an ephemeral port on the loopback
#define	QUICTEST_CN			L"CN=localhost"		// The subject of the server certificate
#define	QUICTEST_SAN		L"localhost"		// Its subject alternative name

// The state of the test
typedef struct QUICTEST_CTX
{
	UINT NumChecks;
	UINT NumFailed;
} QUICTEST_CTX;

// The server end of one connection, on a thread of its own: it accepts one stream, runs the
// responder, and checks the Login that the first control record carries
typedef struct QUICTEST_SERVER
{
	TRANSPORT_LISTENER *Listener;	// It accepts one stream here
	NODE *Node;						// The node whose Sam checks the Login and whose store pins the key
	UCHAR ServerKey[NOISE_KEY_SIZE];// The responder's static key
	bool Accepted;					// The handshake completed
	bool LoggedIn;					// The Login passed Sam and the key pin
	UINT LoginError;				// The error of NodeLoginPinned
	bool HasRemote;					// The stream that it accepted tells the address of its client (AUD1-DT-11, #459) ...
	char Remote[TRANSPORT_ADDRESS_SIZE];	// ... this one
} QUICTEST_SERVER;

static bool QuicTestCheck(QUICTEST_CTX *ctx, bool ok, char *what, char *fmt, ...) RANZ_PRINTF_FORMAT(4, 5);
static bool QuicTestCheck(QUICTEST_CTX *ctx, bool ok, char *what, char *fmt, ...)
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

// The watchdog: a native thread that ends a run that hangs, so a lost wake-up is a failed test
// instead of a hung CI step
static DWORD WINAPI QuicTestWatchdog(LPVOID param)
{
	char msg[MAX_SIZE];
	DWORD written = 0;

	if (WaitForSingleObject((HANDLE)param, QUICTEST_WATCHDOG) != WAIT_TIMEOUT)
	{
		return 0;
	}

	int len = snprintf(msg, sizeof(msg), "QUIC TEST FAILED (did not finish within %u ms)\n", QUICTEST_WATCHDOG);
	if (len > 0)
	{
		WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), msg, (DWORD)MIN((UINT)len, (UINT)sizeof(msg) - 1), &written, NULL);
	}

	TerminateProcess(GetCurrentProcess(), 1);

	return 0;
}

// The responder's configuration: the static key, short timers so a record never waits long
static void QuicTestConfig(NOISE_SESSION_CONFIG *c, UCHAR *key, UCHAR *remote)
{
	Zero(c, sizeof(NOISE_SESSION_CONFIG));
	c->Suite = NOISE_SUITE_IK;
	c->StaticKey = key;
	c->RemoteStatic = remote;
	c->KeepaliveInterval = 2000;
	c->DeadTimeout = QUICTEST_TIMEOUT;
	c->RekeyInterval = 60000;
}

// The server thread: accept one stream, run the responder, take the Login of the first control
// record and check it through NodeLoginPinned (Sam plus the key pin). A Login that passes opens the
// data stream and the server sends its welcome; one that fails closes the session.
static void QuicTestServerThread(THREAD *thread, void *param)
{
	QUICTEST_SERVER *srv = (QUICTEST_SERVER *)param;
	TRANSPORT_NOISE *n = ZeroMalloc(sizeof(TRANSPORT_NOISE));
	UCHAR *buf = ZeroMalloc(NOISE_MAX_PAYLOAD);
	TRANSPORT_STREAM *s = TransportAccept(srv->Listener, QUICTEST_TIMEOUT);
	NOISE_SESSION_CONFIG sc;

	QuicTestConfig(&sc, srv->ServerKey, NULL);
	// Before the session takes the stream
	srv->HasRemote = (s != NULL && TransportRemote(s, srv->Remote, sizeof(srv->Remote)));
	srv->Accepted = TransportNoiseAccept(n, s, &sc, QUICTEST_TIMEOUT);

	if (srv->Accepted)
	{
		UINT size = 0;
		UINT ret = TransportNoiseReceive(n, buf, NOISE_MAX_PAYLOAD, &size, QUICTEST_TIMEOUT);

		if (ret == NOISE_RECEIVE_CONTROL)
		{
			NOISE_LOGIN login;

			if (NoiseLoginParse(&login, buf, size))
			{
				UCHAR challenge[NOISE_LOGIN_CHALLENGE_SIZE];
				AUTH_RESULT res;

				Zero(&res, sizeof(res));
				NoiseSessionChallenge(&n->Session, challenge, sizeof(challenge));
				srv->LoggedIn = NodeLoginPinned(srv->Node, &login, challenge, n->Session.RemoteStatic, &res);
				srv->LoginError = res.Error;

				Free(res.Policy);
				FreeX(res.ClientX);
			}
			Zero(&login, sizeof(login));
		}
	}

	if (srv->LoggedIn)
	{
		TransportNoiseAcceptLogin(n);
		TransportNoiseSend(n, NOISE_RECORD_CONTROL, QUICTEST_WELCOME, StrLen(QUICTEST_WELCOME));

		// Echo until the client closes
		while (true)
		{
			UINT size = 0;
			UINT ret = TransportNoiseReceive(n, buf, NOISE_MAX_PAYLOAD, &size, QUICTEST_TIMEOUT);

			if (ret != NOISE_RECEIVE_CONTROL && ret != NOISE_RECEIVE_DATA)
			{
				break;
			}
			TransportNoiseSend(n, (ret == NOISE_RECEIVE_DATA ? NOISE_RECORD_DATA : NOISE_RECORD_CONTROL), buf, size);
		}
	}
	else if (srv->Accepted)
	{
		// Refuse: close the session so the client sees the Login fail
		TransportNoiseSend(n, NOISE_RECORD_CLOSE, NULL, 0);
	}

	TransportNoiseClose(n);
	Free(buf);
	Free(n);
}

// One case: a client with its own static key logs in against the node, over its own stream of the
// transport. expect_connect: the QUIC handshake and the Noise handshake complete. expect_login: the
// Login is accepted. *bound: the channel binding type of the session that came up.
static void QuicTestCase(QUICTEST_CTX *ctx, char *what, TRANSPORT *server, TRANSPORT *client, NODE *node, USHORT port,
	UCHAR *client_key, bool expect_connect, bool expect_login, UINT *bound)
{
	UCHAR server_key[NOISE_KEY_SIZE], server_pub[NOISE_KEY_SIZE];
	NOISE_SESSION_CONFIG cc;
	NOISE_LOGIN login;
	char address[TRANSPORT_ADDRESS_SIZE];
	QUICTEST_SERVER *srv = ZeroMalloc(sizeof(QUICTEST_SERVER));
	TRANSPORT_NOISE *n = ZeroMalloc(sizeof(TRANSPORT_NOISE));
	UCHAR *buf = ZeroMalloc(NOISE_MAX_PAYLOAD);
	UINT size = 0;
	bool connected, logged_in;

	Print("[%s]\n", what);
	*bound = NOISE_BINDING_NONE;

	// The server's static key, which the client knows in advance (the Noise IK responder key)
	CryptoX25519GenerateKey(server_key, server_pub);

	srv->Listener = TransportListen(server, QUICTEST_LISTEN);
	// The listener bound a port on the loopback; take the ephemeral one
	USHORT bound_port = TransportQuicBoundPort(server);
	if (bound_port == 0)
	{
		bound_port = port;
	}
	Copy(srv->ServerKey, server_key, NOISE_KEY_SIZE);
	srv->Node = node;

	THREAD *thread = NewThread(QuicTestServerThread, srv);

	Format(address, sizeof(address), "127.0.0.1:%u", (UINT)bound_port);
	QuicTestConfig(&cc, client_key, server_pub);
	TRANSPORT_STREAM *stream = TransportDial(client, address, NULL);

	connected = (stream != NULL && TransportNoiseConnect(n, stream, &cc, QUICTEST_TIMEOUT));
	logged_in = false;

	if (connected)
	{
		UCHAR binding[NOISE_MAX_BINDING];
		UINT binding_size = 0;
		char client_remote[TRANSPORT_ADDRESS_SIZE];

		// The client's end of the connection tells the address that it dialled (AUD1-DT-11, #459)
		bool client_tells = TransportRemote(stream, client_remote, sizeof(client_remote));
		QuicTestCheck(ctx, client_tells && StrCmp(client_remote, address) == 0, "  the client's end of the connection tells the address that it dialled", "%s: \"%s\"",
			client_tells ? "gave" : "gave none", client_tells ? client_remote : "");

		*bound = (n->Session.Flags & NOISE_SESSION_ENCRYPT) != 0 ? NOISE_BINDING_NONE : TransportBinding(stream, binding, sizeof(binding), &binding_size);

		Zero(&login, sizeof(login));
		login.Method = NOISE_LOGIN_PASSWORD;
		StrCpy(login.HubName, sizeof(login.HubName), QUICTEST_HUB);
		StrCpy(login.UserName, sizeof(login.UserName), QUICTEST_USER);
		StrCpy(login.Password, sizeof(login.Password), expect_login ? QUICTEST_PASSWORD : QUICTEST_WRONG);

		bool sent = NoiseLoginEncode(&login, buf, NOISE_MAX_PAYLOAD, &size) && TransportNoiseSend(n, NOISE_RECORD_CONTROL, buf, size);
		UINT ret = TransportNoiseReceive(n, buf, NOISE_MAX_PAYLOAD, &size, QUICTEST_TIMEOUT);
		logged_in = (sent && ret == NOISE_RECEIVE_CONTROL && size == StrLen(QUICTEST_WELCOME) && Cmp(buf, QUICTEST_WELCOME, size) == 0);
		Zero(&login, sizeof(login));

		if (logged_in)
		{
			// The session carries a data record after the Login
			UINT got = 0;
			bool echo = TransportNoiseSend(n, NOISE_RECORD_DATA, "frame", 5) &&
				TransportNoiseReceive(n, buf, NOISE_MAX_PAYLOAD, &got, QUICTEST_TIMEOUT) == NOISE_RECEIVE_DATA && got == 5 && Cmp(buf, "frame", 5) == 0;
			QuicTestCheck(ctx, echo, "  the session carries a data record both ways", "the echo did not return");
		}
	}

	TransportNoiseClose(n);
	WaitThread(thread, INFINITE);
	ReleaseThread(thread);
	TransportCloseListener(srv->Listener);

	QuicTestCheck(ctx, connected == expect_connect, expect_connect ? "  the QUIC handshake and the Noise session come up" : "  the connection does not come up",
		"connected %u, expected %u", (UINT)connected, (UINT)expect_connect);
	if (expect_connect)
	{
		// The server's end tells the address of its client, on the loopback interface with a port of its own (AUD1-DT-11, #459)
		QuicTestCheck(ctx, srv->HasRemote && StartWith(srv->Remote, "127.0.0.1:") && StrCmp(srv->Remote, address) != 0, "  the server's end of the connection tells the address of its client",
			"%s: \"%s\"", srv->HasRemote ? "gave" : "gave none", srv->HasRemote ? srv->Remote : "");
		QuicTestCheck(ctx, logged_in == expect_login, expect_login ? "  the Login is accepted, matching the node's Sam" : "  the Login is refused, matching the node's Sam",
			"client logged in %u, server logged in %u, server error %u, expected %u", (UINT)logged_in, (UINT)srv->LoggedIn, srv->LoginError, (UINT)expect_login);
	}

	Zero(server_key, sizeof(server_key));
	Free(buf);
	Free(n);
	Free(srv);
}

// A new empty data directory with the configuration store of the server role: one worker, the hub
// as an online L2 network, and the password user in the store so a login can be pinned
static void QuicTestNewDir(wchar_t *dir, UINT size)
{
	wchar_t tmp[MAX_PATH];
	wchar_t path[MAX_PATH];

	UniFormat(tmp, sizeof(tmp), L"quic_test_%u", Rand32());
	ConbinePathW(dir, size, MsGetMyTempDirW(), tmp);
	MakeDirExW(dir);

	ConbinePathW(path, sizeof(path), dir, CS_FILE_NAME);
	CONFIG_STORE *s = CsOpen(path);
	if (s == NULL)
	{
		Print("  configuration store %S cannot be opened\n", path);
		return;
	}

	CsSetSetting(s, NODE_SETTING_ROLES, "server");
	CsSetSetting(s, NODE_SETTING_WORKERS, "1");
	CsAddNetwork(s, QUICTEST_HUB, CS_MODE_L2, true);

	CS_USER u;
	Zero(&u, sizeof(u));
	StrCpy(u.Network, sizeof(u.Network), QUICTEST_HUB);
	StrCpy(u.Name, sizeof(u.Name), QUICTEST_USER);
	u.AuthType = AUTHTYPE_PASSWORD;
	CsAddUser(s, &u);

	CsClose(s);
}

// Delete the files of a directory, then the directory (it holds no subdirectory)
static void QuicTestDeleteFiles(wchar_t *dir)
{
	DIRLIST *d = EnumDirW(dir);

	for (UINT i = 0; d != NULL && i < d->NumFiles; i++)
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

RANZ_TEST_TAGS("quic", quic_test, "core", "QUIC: a client completes the QUIC handshake against the HTTP/3 listener on msquic, the Noise session comes up, Sam checks the Login, and the client's static key is pinned on first login (trust on first use).");
void quic_test(UINT num, char **arg)
{
	QUICTEST_CTX *ctx = ZeroMalloc(sizeof(QUICTEST_CTX));
	wchar_t dir[MAX_PATH];
	char thumbprint[MAX_SIZE];
	HANDLE done = CreateEventW(NULL, TRUE, FALSE, NULL);
	HANDLE watchdog = (done != NULL ? CreateThread(NULL, 0, QuicTestWatchdog, done, 0, NULL) : NULL);
	UINT bound = 0;

	Print("QUIC test: the QUIC transport of the new core, its Noise session, Sam and the key pinning\n");

	if (CryptoInit() == false || TransportQuicAvailable() == false)
	{
		Print("  msquic.dll is not present: the QUIC transport cannot run; the test is skipped\n");
		Print("QUIC TEST OK\n");
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

	// A real certificate: a self-signed ECDSA P-256 certificate in the current user's My store, read
	// by its thumbprint, which both the listener and the client (the pin) name
	UINT scope = 0;
	PCCERT_CONTEXT cert = CryptoCertCreateSelfSigned(QUICTEST_CN, QUICTEST_SAN, NULL, 30, scope);
	bool have_cert = (cert != NULL && CryptoCertThumbprintStr(cert, thumbprint, sizeof(thumbprint)) && CryptoCertAddToStore(cert, NULL, scope));
	QuicTestCheck(ctx, have_cert, "a self-signed ECDSA P-256 certificate in the My store, by its thumbprint", "CryptoCertCreateSelfSigned or the store failed");

	if (have_cert)
	{
		// The node: the server role, the hub and the password user in the store
		QuicTestNewDir(dir, sizeof(dir));
		NODE *node = NewNode(dir);
		NodeStart(node);
		HUB *hub = NodeGetHub(node, QUICTEST_HUB);

		if (QuicTestCheck(ctx, hub != NULL, "the server role of the node runs the hub", "NodeGetHub failed"))
		{
			// The password user in the running hub, which Sam checks
			USER *u = NewUser(QUICTEST_USER, L"", L"", AUTHTYPE_PASSWORD, NewPasswordAuthData(QUICTEST_USER, QUICTEST_PASSWORD));
			AcLock(hub);
			AcAddUser(hub, u);
			AcUnlock(hub);
			ReleaseUser(u);
			ReleaseHub(hub);

			// The transports: a server (the certificate) and the clients (the pin)
			TRANSPORT_QUIC_CONFIG server_cfg, client_cfg, break_cfg;
			TransportQuicDefaultConfig(&server_cfg, thumbprint, false);
			TransportQuicDefaultConfig(&client_cfg, thumbprint, false);
			TransportQuicDefaultConfig(&break_cfg, thumbprint, false);
			break_cfg.BreakBinding = true;

			TRANSPORT *server = TransportQuicServerNew(&server_cfg);
			TRANSPORT *client = TransportQuicClientNew(&client_cfg);
			TRANSPORT *breaker = TransportQuicClientNew(&break_cfg);

			if (QuicTestCheck(ctx, server != NULL && client != NULL && breaker != NULL, "the QUIC server and client transports open on msquic", "a transport could not open"))
			{
				UCHAR key_a[NOISE_KEY_SIZE], key_a_pub[NOISE_KEY_SIZE];
				UCHAR key_b[NOISE_KEY_SIZE], key_b_pub[NOISE_KEY_SIZE];

				CryptoX25519GenerateKey(key_a, key_a_pub);
				CryptoX25519GenerateKey(key_b, key_b_pub);

				// A valid password logs in; the session is bound to the TLS exporter of its QUIC
				// connection (NOISE_BINDING_EXPORTER, CORE-H5), which the handshake with the ALPN "h3"
				// and the pinned certificate gave both ends
				QuicTestCase(ctx, "a valid password logs in, the client's key is pinned", server, client, node, 0, key_a, true, true, &bound);
				QuicTestCheck(ctx, bound == NOISE_BINDING_EXPORTER, "  the session is bound to the exporter of its QUIC connection (HTTP/3 posture, the pinned certificate)", "binding type %u", bound);

				// A wrong password is refused, matching Sam
				QuicTestCase(ctx, "a wrong password is refused", server, client, node, 0, key_a, true, false, &bound);

				// Trust on first use: the same user with a different Noise static key is refused even
				// with the right password, because key A was pinned above
				QuicTestCase(ctx, "a different Noise static key is refused (trust on first use)", server, client, node, 0, key_b, true, false, &bound);

				// A mismatched channel binding closes the connection: the client computes a binding of
				// its own, as a middlebox that terminated the TLS would, so the two prologues differ
				QuicTestCase(ctx, "a mismatched channel binding closes the connection", server, breaker, node, 0, key_a, false, false, &bound);

				Zero(key_a, sizeof(key_a));
				Zero(key_b, sizeof(key_b));
			}

			TransportQuicFree(breaker);
			TransportQuicFree(client);
			TransportQuicFree(server);
		}

		NodeStop(node);
		FreeNode(node);
		QuicTestDeleteFiles(dir);
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
		Print("QUIC TEST OK\n");
	}
	else
	{
		Print("QUIC TEST FAILED (%u of %u checks failed)\n", ctx->NumFailed, ctx->NumChecks);
	}

	Free(ctx);
}
