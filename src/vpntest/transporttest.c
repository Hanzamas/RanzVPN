// transporttest.c
// Named transport test of vpntest ("transport" command, CORE-F4 #64)
//
// The transport interface of the new core and the session layer on it (src/Core/Transport.h). A Noise session runs
// end to end over the in-process loopback transport, once on a stream without a channel binding, where the session
// encrypts its records, and once on a bound stream, whose random binding stands in for the exporter of a TLS or QUIC
// session: the handshake, the Login as the first control message, control and data both ways, a data record of the
// largest payload, keepalives and the rekey of an idle session, and the close. A client's fallback list, read from
// its configured text, is raced happy-eyeballs style over loopback transports of different speeds: the first
// transport to connect wins, an entry starts the attempt delay after the one before it or at once after a failure,
// the attempts still dialling are cancelled and leave no stream behind, and a list that nothing answers fails. The
// same session then runs over the winner of a race, and over the winner of a race against a second transport that
// this file adds and the module does not know, TCP on 127.0.0.1 through Winsock: the session layer takes it as it is.
// Print "TRANSPORT TEST OK" only when every check passes.

#include "Mayaqua/Encrypt.h"
#include "Mayaqua/Kernel.h"
#include "Mayaqua/Memory.h"
#include "Mayaqua/Str.h"

#include "Core/Transport.h"

#include <WS2tcpip.h>

#include <stdio.h>

#define	TRANSPORTTEST_BUDGET		120000		// The whole test ends within this time, or the watchdog ends the process (ms)
#define	TRANSPORTTEST_TIMEOUT		10000		// A handshake, an accept or a record within this time (ms)
#define	TRANSPORTTEST_KEEPALIVE		100			// The keepalive interval of the test sessions (ms)
#define	TRANSPORTTEST_REKEY			300			// Their rekey interval (ms)
#define	TRANSPORTTEST_DEAD			5000		// Their dead-peer timeout (ms)
#define	TRANSPORTTEST_IDLE			1000		// The idle wait in which keepalives and a rekey must pass (ms)
#define	TRANSPORTTEST_DELAY			500			// The attempt delay of the races (ms)
#define	TRANSPORTTEST_SLOW			3000		// The dial delay of the slow loopback transport (ms)
#define	TRANSPORTTEST_RACE_TIMEOUT	800			// The timeout of the race that nothing wins (ms)
#define	TRANSPORTTEST_LINGER		1000		// A TCP close waits this long for the peer's end (ms)
#define	TRANSPORTTEST_ADDRESS		"node-a"	// The address of the loopback listeners
#define	TRANSPORTTEST_HUB			"TRANSPORT"
#define	TRANSPORTTEST_USER			"tester"
#define	TRANSPORTTEST_PASSWORD		"Transport-Pass-1"
#define	TRANSPORTTEST_WELCOME		"welcome"	// The server's control message after the Login

// The transports of the test, in the order of TRANSPORTTEST_NET.Known
#define	TRANSPORTTEST_LOOPBACK		0			// "loopback": connects at once
#define	TRANSPORTTEST_BOUND			1			// "bound": connects at once; its streams have a channel binding
#define	TRANSPORTTEST_SLOW_ONE		2			// "slow": connects after TRANSPORTTEST_SLOW
#define	TRANSPORTTEST_HANG			3			// "hang": never connects; only a cancel ends its dial
#define	TRANSPORTTEST_TCP			4			// "tcp": TCP on 127.0.0.1, the transport of this file
#define	TRANSPORTTEST_NUM			5

// The checks of the test
typedef struct TRANSPORTTEST_CTX
{
	UINT NumChecks;						// Checks run so far
	UINT NumFailed;						// Checks failed so far
} TRANSPORTTEST_CTX;

// The state of the TCP transport: the port that its listener took
typedef struct TRANSPORTTEST_TCP_STATE
{
	UINT Port;
} TRANSPORTTEST_TCP_STATE;

// A socket of the TCP transport: a stream or a listener
typedef struct TRANSPORTTEST_SOCKET
{
	SOCKET Socket;
} TRANSPORTTEST_SOCKET;

// The transports of the test and their listeners
typedef struct TRANSPORTTEST_NET
{
	TRANSPORT *Known[TRANSPORTTEST_NUM];				// The known transports of the fallback lists
	TRANSPORT_LISTENER *Listeners[TRANSPORTTEST_NUM];	// The listener of each
	TRANSPORT Tcp;										// The TCP transport
	TRANSPORTTEST_TCP_STATE TcpState;					// ... and its state
} TRANSPORTTEST_NET;

// The server end of a test session, on a thread of its own
typedef struct TRANSPORTTEST_SERVER
{
	TRANSPORT_LISTENER *Listener;		// It accepts one stream here
	NOISE_SESSION_CONFIG Config;		// The responder's configuration
	bool Accepted;						// The handshake completed
	bool LoggedIn;						// The first control record was the Login of the test user
	UINT NumEchoed;						// Control and data records sent back
	UINT LastReceive;					// What the last receive gave: NOISE_RECEIVE_CLOSE once the client closed
	UCHAR RemoteStatic[NOISE_KEY_SIZE];	// The client's static key, learnt in the handshake
	UCHAR HandshakeHash[NOISE_KEY_SIZE];// The handshake hash
	UINT64 NumPeerRekeys;				// The keys that it saw the client take
} TRANSPORTTEST_SERVER;

static bool TransportTestCheck(TRANSPORTTEST_CTX *ctx, bool ok, char *what, char *fmt, ...) RANZ_PRINTF_FORMAT(4, 5);
static bool TransportTestCheck(TRANSPORTTEST_CTX *ctx, bool ok, char *what, char *fmt, ...)
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

// The watchdog: a native thread that ends a run that hangs, so that a lost wake-up of the transport is a failed test
// instead of a hung CI step
static DWORD WINAPI TransportTestWatchdog(LPVOID param)
{
	char msg[MAX_SIZE];
	DWORD written = 0;

	if (WaitForSingleObject((HANDLE)param, TRANSPORTTEST_BUDGET) != WAIT_TIMEOUT)
	{
		return 0;
	}

	int len = snprintf(msg, sizeof(msg), "TRANSPORT TEST FAILED (did not finish within %u ms)\n", TRANSPORTTEST_BUDGET);
	if (len > 0)
	{
		WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), msg, (DWORD)MIN((UINT)len, (UINT)sizeof(msg) - 1), &written, NULL);
	}

	TerminateProcess(GetCurrentProcess(), 1);

	return 0;
}

//
// The second transport: TCP on 127.0.0.1 through Winsock, which this file adds and the module does not know. An
// address is a port; the listener takes the port that its address names, 0 for one that the system picks, and
// keeps it in the transport's state. Its streams have no channel binding.
//

static TRANSPORTTEST_SOCKET *TransportTestTcpNew(SOCKET s)
{
	TRANSPORTTEST_SOCKET *t = ZeroMalloc(sizeof(TRANSPORTTEST_SOCKET));
	BOOL nodelay = TRUE;

	// One frame is one send: no wait for the acknowledgement of the one before
	setsockopt(s, IPPROTO_TCP, TCP_NODELAY, (char *)&nodelay, sizeof(nodelay));
	t->Socket = s;

	return t;
}

// Wait until the socket has bytes, its end or a connection: 1; 0 when the timeout passed; -1 on an error
static int TransportTestTcpWait(SOCKET s, UINT timeout)
{
	WSAPOLLFD p;

	Zero(&p, sizeof(p));
	p.fd = s;
	p.events = POLLRDNORM;

	return WSAPoll(&p, 1, (timeout == INFINITE ? -1 : (INT)timeout));
}

// The socket address of 127.0.0.1 and the port of an address
static void TransportTestTcpAddress(struct sockaddr_in *sa, const char *address)
{
	Zero(sa, sizeof(struct sockaddr_in));
	sa->sin_family = AF_INET;
	sa->sin_port = htons((USHORT)ToInt(address));
	sa->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
}

static bool TransportTestTcpDial(void *param, const char *address, HANDLE cancel, void **stream)
{
	struct sockaddr_in sa;

	*stream = NULL;
	if (cancel != NULL && WaitForSingleObject(cancel, 0) != WAIT_TIMEOUT)
	{
		return false;
	}

	SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (s == INVALID_SOCKET)
	{
		return false;
	}

	TransportTestTcpAddress(&sa, address);
	if (connect(s, (struct sockaddr *)&sa, sizeof(sa)) != 0)
	{
		closesocket(s);
		return false;
	}

	*stream = TransportTestTcpNew(s);
	return true;
}

static bool TransportTestTcpListen(void *param, const char *address, void **listener)
{
	TRANSPORTTEST_TCP_STATE *state = (TRANSPORTTEST_TCP_STATE *)param;
	struct sockaddr_in sa;
	int sa_size = sizeof(sa);

	*listener = NULL;

	SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (s == INVALID_SOCKET)
	{
		return false;
	}

	TransportTestTcpAddress(&sa, address);
	if (bind(s, (struct sockaddr *)&sa, sizeof(sa)) != 0 || listen(s, SOMAXCONN) != 0 || getsockname(s, (struct sockaddr *)&sa, &sa_size) != 0)
	{
		closesocket(s);
		return false;
	}

	state->Port = ntohs(sa.sin_port);
	*listener = TransportTestTcpNew(s);
	return true;
}

static bool TransportTestTcpAccept(void *listener, UINT timeout, void **stream)
{
	TRANSPORTTEST_SOCKET *l = (TRANSPORTTEST_SOCKET *)listener;

	*stream = NULL;
	if (TransportTestTcpWait(l->Socket, timeout) != 1)
	{
		return false;
	}

	SOCKET s = accept(l->Socket, NULL, NULL);
	if (s == INVALID_SOCKET)
	{
		return false;
	}

	*stream = TransportTestTcpNew(s);
	return true;
}

static void TransportTestTcpCloseListener(void *listener)
{
	TRANSPORTTEST_SOCKET *l = (TRANSPORTTEST_SOCKET *)listener;

	closesocket(l->Socket);
	Free(l);
}

static UINT TransportTestTcpRead(void *stream, void *buf, UINT size, UINT timeout)
{
	TRANSPORTTEST_SOCKET *s = (TRANSPORTTEST_SOCKET *)stream;
	int ready = TransportTestTcpWait(s->Socket, timeout);

	if (ready == 0)
	{
		return TRANSPORT_LATER;
	}
	if (ready < 0)
	{
		return 0;
	}

	int n = recv(s->Socket, (char *)buf, (int)MIN(size, 65536), 0);

	return (n > 0 ? (UINT)n : 0);
}

static bool TransportTestTcpWrite(void *stream, const void *buf, UINT size)
{
	TRANSPORTTEST_SOCKET *s = (TRANSPORTTEST_SOCKET *)stream;
	const char *p = (const char *)buf;

	while (size != 0)
	{
		int n = send(s->Socket, p, (int)MIN(size, 65536), 0);
		if (n <= 0)
		{
			return false;
		}

		p += n;
		size -= (UINT)n;
	}

	return true;
}

// A graceful close: the end of the stream to the peer, then the peer's bytes up to its own end, so that no unread
// byte turns the close into a reset that could overtake the last record
static void TransportTestTcpClose(void *stream)
{
	TRANSPORTTEST_SOCKET *s = (TRANSPORTTEST_SOCKET *)stream;
	char drain[1024];

	shutdown(s->Socket, SD_SEND);
	while (TransportTestTcpWait(s->Socket, TRANSPORTTEST_LINGER) == 1 && recv(s->Socket, drain, sizeof(drain), 0) > 0)
	{
	}

	closesocket(s->Socket);
	Free(s);
}

//
// The sessions
//

// The configuration of an end of a test session: short timers, so that keepalives and a rekey pass while the test
// waits. The session layer adds the binding of the stream.
static void TransportTestConfig(NOISE_SESSION_CONFIG *c, UCHAR *key, UCHAR *remote)
{
	Zero(c, sizeof(NOISE_SESSION_CONFIG));
	c->Suite = NOISE_SUITE_IK;
	c->StaticKey = key;
	c->RemoteStatic = remote;
	c->KeepaliveInterval = TRANSPORTTEST_KEEPALIVE;
	c->DeadTimeout = TRANSPORTTEST_DEAD;
	c->RekeyInterval = TRANSPORTTEST_REKEY;
}

// The server end of a test session: it accepts one stream and runs the responder. The first control record must be
// the Login of the test user, which opens the data stream; every later control and data record goes back as it
// came, until the client closes.
static void TransportTestServerThread(THREAD *thread, void *param)
{
	TRANSPORTTEST_SERVER *srv = (TRANSPORTTEST_SERVER *)param;
	TRANSPORT_NOISE *n = ZeroMalloc(sizeof(TRANSPORT_NOISE));
	UCHAR *buf = ZeroMalloc(NOISE_MAX_PAYLOAD);
	TRANSPORT_STREAM *s = TransportAccept(srv->Listener, TRANSPORTTEST_TIMEOUT);

	srv->Accepted = TransportNoiseAccept(n, s, &srv->Config, TRANSPORTTEST_TIMEOUT);
	if (srv->Accepted)
	{
		Copy(srv->RemoteStatic, n->Session.RemoteStatic, NOISE_KEY_SIZE);
		Copy(srv->HandshakeHash, n->Session.HandshakeHash, NOISE_KEY_SIZE);
	}

	while (srv->Accepted)
	{
		UINT size = 0;
		UINT ret = TransportNoiseReceive(n, buf, NOISE_MAX_PAYLOAD, &size, TRANSPORTTEST_TIMEOUT);

		srv->LastReceive = ret;
		if (ret != NOISE_RECEIVE_CONTROL && ret != NOISE_RECEIVE_DATA)
		{
			break;
		}
		srv->NumPeerRekeys = n->Session.NumPeerRekeys;

		if (srv->LoggedIn == false)
		{
			NOISE_LOGIN login;

			srv->LoggedIn = (ret == NOISE_RECEIVE_CONTROL && NoiseLoginParse(&login, buf, size) && login.Method == NOISE_LOGIN_PASSWORD &&
				StrCmp(login.HubName, TRANSPORTTEST_HUB) == 0 && StrCmp(login.UserName, TRANSPORTTEST_USER) == 0 &&
				StrCmp(login.Password, TRANSPORTTEST_PASSWORD) == 0);
			Zero(&login, sizeof(login));
			if (srv->LoggedIn == false)
			{
				break;
			}

			TransportNoiseAcceptLogin(n);
			TransportNoiseSend(n, NOISE_RECORD_CONTROL, TRANSPORTTEST_WELCOME, StrLen(TRANSPORTTEST_WELCOME));
			continue;
		}

		if (TransportNoiseSend(n, (ret == NOISE_RECEIVE_DATA ? NOISE_RECORD_DATA : NOISE_RECORD_CONTROL), buf, size))
		{
			srv->NumEchoed++;
		}
	}

	TransportNoiseClose(n);
	Free(buf);
	Free(n);
}

// Send a record of a stream; the server sends the same record back on the same stream
static bool TransportTestEcho(TRANSPORTTEST_CTX *ctx, TRANSPORT_NOISE *n, UINT type, const void *data, UINT size, char *what)
{
	UCHAR *buf = ZeroMalloc(NOISE_MAX_PAYLOAD);
	UINT got = 0;
	bool sent = TransportNoiseSend(n, type, data, size);
	UINT ret = TransportNoiseReceive(n, buf, NOISE_MAX_PAYLOAD, &got, TRANSPORTTEST_TIMEOUT);
	UINT expect = (type == NOISE_RECORD_DATA ? NOISE_RECEIVE_DATA : NOISE_RECEIVE_CONTROL);

	bool ok = TransportTestCheck(ctx, sent && ret == expect && got == size && Cmp(buf, data, size) == 0, what,
		"sent %u, receive %u, %u of %u bytes", (UINT)sent, ret, got, size);

	Free(buf);

	return ok;
}

// A Noise session over the client's stream s, against the server thread on the listener l: the handshake, the Login,
// control and data both ways, a data record of the largest payload, an idle wait with keepalives and the rekey, data
// after it, and the close. encrypted: the stream has no channel binding, so the session encrypts its records.
static void TransportTestSession(TRANSPORTTEST_CTX *ctx, char *what, TRANSPORT_LISTENER *l, TRANSPORT_STREAM *s, bool encrypted)
{
	UCHAR client_key[NOISE_KEY_SIZE], client_pub[NOISE_KEY_SIZE], server_key[NOISE_KEY_SIZE], server_pub[NOISE_KEY_SIZE];
	UCHAR hash[NOISE_KEY_SIZE];
	NOISE_SESSION_CONFIG cc;
	NOISE_LOGIN login;
	TRANSPORTTEST_SERVER *srv = ZeroMalloc(sizeof(TRANSPORTTEST_SERVER));
	TRANSPORT_NOISE *n = ZeroMalloc(sizeof(TRANSPORT_NOISE));
	UCHAR *buf = ZeroMalloc(NOISE_MAX_PAYLOAD);
	UCHAR *big = ZeroMalloc(NOISE_MAX_PAYLOAD);
	UINT size = 0;

	Print("[%s]\n", what);
	Zero(hash, sizeof(hash));

	CryptoX25519GenerateKey(client_key, client_pub);
	CryptoX25519GenerateKey(server_key, server_pub);
	TransportTestConfig(&cc, client_key, server_pub);
	TransportTestConfig(&srv->Config, server_key, NULL);
	srv->Listener = l;
	THREAD *thread = NewThread(TransportTestServerThread, srv);

	bool ok = TransportTestCheck(ctx, TransportNoiseConnect(n, s, &cc, TRANSPORTTEST_TIMEOUT), "  the Noise_IK handshake over the stream",
		"TransportNoiseConnect failed");
	if (ok)
	{
		Copy(hash, n->Session.HandshakeHash, NOISE_KEY_SIZE);
		TransportTestCheck(ctx, ((n->Session.Flags & NOISE_SESSION_ENCRYPT) != 0) == encrypted,
			(encrypted ? "  no channel binding: the session encrypts its records" : "  the channel binding of the stream: the session is bound and sends its records in clear"),
			"flags 0x%x", n->Session.Flags);

		// The Login, the first control message, and the server's answer on the control stream
		Zero(&login, sizeof(login));
		login.Method = NOISE_LOGIN_PASSWORD;
		StrCpy(login.HubName, sizeof(login.HubName), TRANSPORTTEST_HUB);
		StrCpy(login.UserName, sizeof(login.UserName), TRANSPORTTEST_USER);
		StrCpy(login.Password, sizeof(login.Password), TRANSPORTTEST_PASSWORD);
		bool sent = NoiseLoginEncode(&login, buf, NOISE_MAX_PAYLOAD, &size) && TransportNoiseSend(n, NOISE_RECORD_CONTROL, buf, size);
		UINT ret = TransportNoiseReceive(n, buf, NOISE_MAX_PAYLOAD, &size, TRANSPORTTEST_TIMEOUT);
		TransportTestCheck(ctx, sent && ret == NOISE_RECEIVE_CONTROL && size == StrLen(TRANSPORTTEST_WELCOME) && Cmp(buf, TRANSPORTTEST_WELCOME, size) == 0,
			"  the Login goes as the first control message, the server answers on the control stream", "sent %u, receive %u, %u bytes", (UINT)sent, ret, size);
		Zero(&login, sizeof(login));

		// Control and data both ways
		TransportTestEcho(ctx, n, NOISE_RECORD_CONTROL, "status", 6, "  a control message both ways");
		TransportTestEcho(ctx, n, NOISE_RECORD_DATA, "frame", 5, "  a data record both ways");
		Rand(big, NOISE_MAX_PAYLOAD);
		TransportTestEcho(ctx, n, NOISE_RECORD_DATA, big, NOISE_MAX_PAYLOAD, "  a data record of the largest payload both ways");

		// Idle: the keepalives of the server keep the session open, and the keys change on schedule
		UINT64 received = n->NumReceived;
		ret = TransportNoiseReceive(n, buf, NOISE_MAX_PAYLOAD, &size, TRANSPORTTEST_IDLE);
		TransportTestCheck(ctx, ret == NOISE_RECEIVE_NONE && n->Session.State == NOISE_STATE_OPEN && n->NumReceived >= received + 2,
			"  an idle session stays open on keepalives", "receive %u, state %u, %I64u records", ret, n->Session.State, n->NumReceived - received);
		TransportTestCheck(ctx, n->Session.NumRekeys != 0 && (encrypted == false || n->Session.NumPeerRekeys != 0),
			(encrypted ? "  both ends took their next keys on schedule" : "  the session asked for the outer keys to be updated on schedule"),
			"%I64u rekeys, %I64u of the peer", n->Session.NumRekeys, n->Session.NumPeerRekeys);
		TransportTestEcho(ctx, n, NOISE_RECORD_DATA, "after", 5, "  a data record after the rekey");
	}

	// The close: the server gets the close record
	TransportNoiseClose(n);
	WaitThread(thread, INFINITE);
	ReleaseThread(thread);

	TransportTestCheck(ctx, srv->Accepted && srv->LoggedIn && Cmp(srv->RemoteStatic, client_pub, NOISE_KEY_SIZE) == 0 && Cmp(srv->HandshakeHash, hash, NOISE_KEY_SIZE) == 0,
		"  the server learnt the client's static key with the same handshake hash, and took the Login", "accepted %u, logged in %u", (UINT)srv->Accepted, (UINT)srv->LoggedIn);
	TransportTestCheck(ctx, srv->NumEchoed == 4 && srv->LastReceive == NOISE_RECEIVE_CLOSE && (encrypted == false || srv->NumPeerRekeys != 0),
		"  the server sent every record back and got the close", "%u sent back, last receive %u, %I64u rekeys of the client", srv->NumEchoed, srv->LastReceive, srv->NumPeerRekeys);

	Zero(client_key, sizeof(client_key));
	Zero(server_key, sizeof(server_key));
	Free(big);
	Free(buf);
	Free(n);
	Free(srv);
}

//
// The transports, the fallback list and the races
//

// The transports of the test, and a listener on each
static void TransportTestOpen(TRANSPORTTEST_CTX *ctx, TRANSPORTTEST_NET *net)
{
	bool ok = true;

	Print("[the transports]\n");

	net->Known[TRANSPORTTEST_LOOPBACK] = TransportLoopbackNew("loopback", 0, false);
	net->Known[TRANSPORTTEST_BOUND] = TransportLoopbackNew("bound", 0, true);
	net->Known[TRANSPORTTEST_SLOW_ONE] = TransportLoopbackNew("slow", TRANSPORTTEST_SLOW, false);
	net->Known[TRANSPORTTEST_HANG] = TransportLoopbackNew("hang", INFINITE, false);

	StrCpy(net->Tcp.Name, sizeof(net->Tcp.Name), "tcp");
	net->Tcp.Param = &net->TcpState;
	net->Tcp.Dial = TransportTestTcpDial;
	net->Tcp.Listen = TransportTestTcpListen;
	net->Tcp.Accept = TransportTestTcpAccept;
	net->Tcp.CloseListener = TransportTestTcpCloseListener;
	net->Tcp.Read = TransportTestTcpRead;
	net->Tcp.Write = TransportTestTcpWrite;
	net->Tcp.Close = TransportTestTcpClose;
	net->Known[TRANSPORTTEST_TCP] = &net->Tcp;

	for (UINT i = 0;i < TRANSPORTTEST_NUM;i++)
	{
		net->Listeners[i] = TransportListen(net->Known[i], (i == TRANSPORTTEST_TCP ? "0" : TRANSPORTTEST_ADDRESS));
		ok = ok && net->Listeners[i] != NULL;
	}
	TransportTestCheck(ctx, ok, "  four loopback transports listen on " TRANSPORTTEST_ADDRESS " of their own networks, the TCP transport on 127.0.0.1",
		"TransportLoopbackNew or TransportListen failed");

	TRANSPORT_LISTENER *again = TransportListen(net->Known[TRANSPORTTEST_LOOPBACK], TRANSPORTTEST_ADDRESS);
	TransportTestCheck(ctx, again == NULL, "  a loopback address has one listener", "a second listener on " TRANSPORTTEST_ADDRESS);
	TransportCloseListener(again);
}

static void TransportTestClose(TRANSPORTTEST_NET *net)
{
	for (UINT i = 0;i < TRANSPORTTEST_NUM;i++)
	{
		TransportCloseListener(net->Listeners[i]);
		net->Listeners[i] = NULL;
	}

	for (UINT i = 0;i < TRANSPORTTEST_TCP;i++)
	{
		TransportLoopbackFree(net->Known[i]);
		net->Known[i] = NULL;
	}
}

// The configured fallback list: entries in order, malformed lists refused
static void TransportTestParse(TRANSPORTTEST_CTX *ctx, TRANSPORTTEST_NET *net)
{
	TRANSPORT_TARGET t[TRANSPORT_MAX_TARGETS];
	char *bad[] =
	{
		"udp:node-a",
		"loopback",
		"loopback:",
		":node-a",
		"loopback:node-a,,bound:node-a",
		"loopback:node-a,",
		"",
		"loopback:a,loopback:b,loopback:c,loopback:d,loopback:e,loopback:f,loopback:g,loopback:h,loopback:i",
	};

	Print("[the configured fallback list]\n");

	UINT num = TransportParseList("  slow:node-a ,loopback:vpn.example:443", net->Known, TRANSPORTTEST_NUM, t, TRANSPORT_MAX_TARGETS);
	TransportTestCheck(ctx, num == 2 && t[0].Transport == net->Known[TRANSPORTTEST_SLOW_ONE] && StrCmp(t[0].Address, "node-a") == 0 &&
		t[1].Transport == net->Known[TRANSPORTTEST_LOOPBACK] && StrCmp(t[1].Address, "vpn.example:443") == 0,
		"  the entries in order, each a known transport and its address, the spaces around an entry ignored", "%u entries", num);

	for (UINT i = 0;i < sizeof(bad) / sizeof(bad[0]);i++)
	{
		char what[MAX_SIZE];

		Format(what, sizeof(what), "  refused: \"%s\"", bad[i]);
		num = TransportParseList(bad[i], net->Known, TRANSPORTTEST_NUM, t, TRANSPORT_MAX_TARGETS);
		TransportTestCheck(ctx, num == 0, what, "%u entries", num);
	}
}

// The listener of a transport of the test
static TRANSPORT_LISTENER *TransportTestListenerOf(TRANSPORTTEST_NET *net, TRANSPORT *t)
{
	for (UINT i = 0;i < TRANSPORTTEST_NUM;i++)
	{
		if (t != NULL && net->Known[i] == t)
		{
			return net->Listeners[i];
		}
	}

	return NULL;
}

// Whether every listener is empty: a cancelled attempt left no stream behind
static bool TransportTestNoStray(TRANSPORTTEST_NET *net)
{
	bool ok = true;

	for (UINT i = 0;i < TRANSPORTTEST_NUM;i++)
	{
		TRANSPORT_STREAM *s = TransportAccept(net->Listeners[i], 0);

		if (s != NULL)
		{
			ok = false;
			TransportClose(s);
		}
	}

	return ok;
}

// One race of a configured list, whose winner must be the entry expect (INFINITE: none): the winner's stream
static TRANSPORT_STREAM *TransportTestRace(TRANSPORTTEST_CTX *ctx, TRANSPORTTEST_NET *net, char *list, UINT timeout, UINT expect, TRANSPORT_RACE *race)
{
	TRANSPORT_TARGET targets[TRANSPORT_MAX_TARGETS];
	char what[MAX_SIZE];

	Print("[race \"%s\"]\n", list);

	UINT num = TransportParseList(list, net->Known, TRANSPORTTEST_NUM, targets, TRANSPORT_MAX_TARGETS);
	TRANSPORT_STREAM *s = TransportRace(targets, num, TRANSPORTTEST_DELAY, timeout, race);

	if (expect < num)
	{
		Format(what, sizeof(what), "  %s wins: the first transport to connect", targets[expect].Transport->Name);
	}
	else
	{
		Format(what, sizeof(what), "  no transport connects: the race fails");
	}
	TransportTestCheck(ctx, num != 0 && (s != NULL) == (expect != INFINITE) && race->Winner == expect, what,
		"%u entries, winner %u, %s", num, race->Winner, (s != NULL ? "a stream" : "no stream"));

	return s;
}

// The end of a race without a session: the winner's listener has its stream, and no listener holds another
static void TransportTestEndRace(TRANSPORTTEST_CTX *ctx, TRANSPORTTEST_NET *net, TRANSPORT_STREAM *s)
{
	if (s != NULL)
	{
		TRANSPORT_STREAM *peer = TransportAccept(TransportTestListenerOf(net, TransportOf(s)), TRANSPORTTEST_TIMEOUT);

		TransportTestCheck(ctx, peer != NULL, "  the winner's listener has its stream", "no stream to accept");
		TransportClose(peer);
		TransportClose(s);
	}

	TransportTestCheck(ctx, TransportTestNoStray(net), "  no other stream reached a listener: the other attempts were cancelled", "a stray stream");
}

static void TransportTestRaces(TRANSPORTTEST_CTX *ctx, TRANSPORTTEST_NET *net)
{
	TRANSPORT_RACE race;
	TRANSPORT_STREAM *s;
	char list[MAX_SIZE];

	// The slow first entry loses to the second, which starts the attempt delay later and connects first
	s = TransportTestRace(ctx, net, "slow:node-a, loopback:node-a", INFINITE, 1, &race);
	TransportTestCheck(ctx, race.NumStarted == 2 && race.NumFailed == 0 && race.Elapsed >= TRANSPORTTEST_DELAY && race.Elapsed < TRANSPORTTEST_SLOW,
		"  the second entry started the attempt delay after the first, and the race did not wait for the slow one",
		"%u started, %u failed, %I64u ms", race.NumStarted, race.NumFailed, race.Elapsed);
	if (s != NULL)
	{
		TransportTestSession(ctx, "a Noise session over the winner of the race", TransportTestListenerOf(net, TransportOf(s)), s, true);
	}
	TransportTestEndRace(ctx, net, NULL);

	// The first entry connects within the attempt delay: the second never starts
	s = TransportTestRace(ctx, net, "loopback:node-a, slow:node-a", INFINITE, 0, &race);
	TransportTestCheck(ctx, race.NumStarted == 1 && race.Elapsed < TRANSPORTTEST_DELAY,
		"  the first entry connected within the attempt delay, so the second never started", "%u started, %I64u ms", race.NumStarted, race.Elapsed);
	TransportTestEndRace(ctx, net, s);

	// A failure starts the next entry at once
	s = TransportTestRace(ctx, net, "loopback:nowhere, bound:node-a", INFINITE, 1, &race);
	TransportTestCheck(ctx, race.NumStarted == 2 && race.NumFailed == 1 && race.Elapsed < TRANSPORTTEST_DELAY,
		"  the failure of the first entry started the second at once", "%u started, %u failed, %I64u ms", race.NumStarted, race.NumFailed, race.Elapsed);
	TransportTestEndRace(ctx, net, s);

	// A dial that never connects is cancelled once the race is won
	s = TransportTestRace(ctx, net, "hang:node-a, loopback:node-a", INFINITE, 1, &race);
	TransportTestCheck(ctx, race.NumStarted == 2 && race.NumFailed == 0 && race.Elapsed >= TRANSPORTTEST_DELAY && race.Elapsed < TRANSPORTTEST_SLOW,
		"  the dial that never connects was cancelled when the race was won", "%u started, %u failed, %I64u ms", race.NumStarted, race.NumFailed, race.Elapsed);
	TransportTestEndRace(ctx, net, s);

	// Nothing answers: every entry fails, each starting at once after the one before
	s = TransportTestRace(ctx, net, "loopback:nowhere, bound:nowhere", INFINITE, INFINITE, &race);
	TransportTestCheck(ctx, race.NumStarted == 2 && race.NumFailed == 2 && race.Elapsed < TRANSPORTTEST_DELAY,
		"  every entry failed, the second starting at once after the first", "%u started, %u failed, %I64u ms", race.NumStarted, race.NumFailed, race.Elapsed);
	TransportTestEndRace(ctx, net, s);

	// The timeout ends a race that nothing wins, and cancels its dial
	s = TransportTestRace(ctx, net, "hang:node-a", TRANSPORTTEST_RACE_TIMEOUT, INFINITE, &race);
	TransportTestCheck(ctx, race.NumStarted == 1 && race.NumFailed == 0 && race.Elapsed >= TRANSPORTTEST_RACE_TIMEOUT && race.Elapsed < TRANSPORTTEST_SLOW,
		"  the race ended at its timeout and cancelled the dial", "%u started, %u failed, %I64u ms", race.NumStarted, race.NumFailed, race.Elapsed);
	TransportTestEndRace(ctx, net, s);

	// The transport of this file joins a fallback list and carries the session, with no change to the session layer
	Format(list, sizeof(list), "slow:node-a, tcp:%u", net->TcpState.Port);
	s = TransportTestRace(ctx, net, list, INFINITE, 1, &race);
	TransportTestCheck(ctx, race.NumStarted == 2 && race.Elapsed >= TRANSPORTTEST_DELAY && race.Elapsed < TRANSPORTTEST_SLOW,
		"  the TCP transport of this test, which the module does not know, raced as an entry of the list", "%u started, %I64u ms", race.NumStarted, race.Elapsed);
	if (s != NULL)
	{
		TransportTestSession(ctx, "a Noise session over the TCP transport of this test, on the same session layer", TransportTestListenerOf(net, TransportOf(s)), s, true);
	}
	TransportTestEndRace(ctx, net, NULL);
}

void transport_test(UINT num, char **arg)
{
	TRANSPORTTEST_CTX *ctx = ZeroMalloc(sizeof(TRANSPORTTEST_CTX));
	TRANSPORTTEST_NET *net = ZeroMalloc(sizeof(TRANSPORTTEST_NET));
	HANDLE done = CreateEventW(NULL, TRUE, FALSE, NULL);
	HANDLE watchdog = (done != NULL ? CreateThread(NULL, 0, TransportTestWatchdog, done, 0, NULL) : NULL);

	Print("Transport test: the session layer of the new core on the transport interface, and the race of a fallback list\n");

	TransportTestOpen(ctx, net);
	TransportTestParse(ctx, net);

	// A Noise session over the loopback transport, unbound and bound
	TransportTestSession(ctx, "a Noise session over the loopback transport, without a channel binding", net->Listeners[TRANSPORTTEST_LOOPBACK],
		TransportDial(net->Known[TRANSPORTTEST_LOOPBACK], TRANSPORTTEST_ADDRESS, NULL), true);
	TransportTestSession(ctx, "a Noise session over the loopback transport, bound", net->Listeners[TRANSPORTTEST_BOUND],
		TransportDial(net->Known[TRANSPORTTEST_BOUND], TRANSPORTTEST_ADDRESS, NULL), false);

	TransportTestRaces(ctx, net);
	TransportTestClose(net);

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
		Print("TRANSPORT TEST OK\n");
	}
	else
	{
		Print("TRANSPORT TEST FAILED (%u of %u checks failed)\n", ctx->NumFailed, ctx->NumChecks);
	}

	Free(net);
	Free(ctx);
}
