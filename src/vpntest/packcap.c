// packcap.c
// Named client Pack size cap test of vpntest ("packcap" command, SEC-4 #96)
//
// Before the authentication the server side reads a Pack of at most HTTP_PACK_MAX_SIZE
// (HttpServerRecv). The client side read whatever the server announced in Content-Length, up to
// MAX_PACK_SIZE (512 MiB), allocated it at once and parsed it: a hostile server, or the target of a
// cascade Link that retries every few seconds, made the client allocate and parse hundreds of MiB
// per attempt. A loopback peer in the test plays the server: it answers one connection with one
// Pack through HttpServerSend, as ServerAccept does. Checks:
// - ClientDownloadHello accepts a hello Pack of normal size;
// - ClientDownloadHello refuses a valid hello Pack of PACKCAP_BIG_SIZE with an error (the old code
//   read and accepted it);
// - the longest welcome Pack that ServerAccept can send (a hub message of HUB_MAXMSG_LEN characters
//   of 3 bytes in UTF-8 and the notices) is larger than HTTP_PACK_MAX_SIZE, and the client still
//   reads it with the welcome cap of ClientConnect (CLIENT_WELCOME_PACK_MAX_SIZE);
// - the welcome cap refuses a welcome Pack padded by PACKCAP_BIG_SIZE.
// Prints "PACKCAP TEST OK" only when every check passes, and frees everything it allocates.

#include "Cedar/Cedar.h"
#include "Cedar/Account.h"
#include "Cedar/Connection.h"
#include "Cedar/Protocol.h"

#include "Mayaqua/Encrypt.h"
#include "Mayaqua/HTTP.h"
#include "Mayaqua/Kernel.h"
#include "Mayaqua/Memory.h"
#include "Mayaqua/Network.h"
#include "Mayaqua/Pack.h"
#include "Mayaqua/Str.h"

#include <stdarg.h>

#define	PACKCAP_PORT			39561				// Loopback listener of the peer
#define	PACKCAP_TIMEOUT			(10 * 1000)			// Send and receive timeout of both ends (ms)
#define	PACKCAP_BIG_SIZE		(1024 * 1024)		// Padding of an oversized Pack: 1 MiB
#define	PACKCAP_SERVER_STR		"PACKCAP test peer"	// "hello" string of the peer
#define	PACKCAP_SERVER_VER		444					// "version" of the peer
#define	PACKCAP_SERVER_BUILD	9999				// "build" of the peer
#define	PACKCAP_WINVER_MSG_LEN	3800				// Characters of each Windows version notice of ServerAccept (its buffer)

// Run state of the test
typedef struct PACKCAP_TEST
{
	UINT NumChecks;						// Checks run so far
	UINT NumFailed;						// Checks failed so far
	SOCK *Listen;						// Listening socket of the peer on 127.0.0.1:PACKCAP_PORT
} PACKCAP_TEST;

// One connection of the peer
typedef struct PACKCAP_PEER
{
	SOCK *Listen;						// Listening socket (of PACKCAP_TEST)
	PACK *Pack;							// Pack the peer answers with
	SOCK *Sock;							// Accepted connection, set by the peer thread
	THREAD *Thread;						// Peer thread
} PACKCAP_PEER;

// Record one check: print [PASS], or [FAIL] with the formatted detail
static void PackCapCheck(PACKCAP_TEST *t, bool ok, char *what, char *detail_fmt, ...)
{
	char detail[MAX_SIZE];
	va_list args;

	t->NumChecks++;

	if (ok)
	{
		Print("  [PASS] %s\n", what);
		return;
	}

	va_start(args, detail_fmt);
	FormatArgs(detail, sizeof(detail), detail_fmt, args);
	va_end(args);

	Print("  [FAIL] %s (%s)\n", what, detail);

	t->NumFailed++;
}

// Peer thread: accept one connection and answer it with the Pack, as a server does
static void PackCapPeerThread(THREAD *thread, void *param)
{
	PACKCAP_PEER *peer = (PACKCAP_PEER *)param;
	SOCK *s = Accept(peer->Listen);

	if (s == NULL)
	{
		return;
	}

	SetTimeout(s, PACKCAP_TIMEOUT);

	// Fails when the client closes the connection before it has read the whole Pack
	HttpServerSend(s, peer->Pack);

	peer->Sock = s;
}

// Start the peer for one connection that it answers with p, and connect to it. Returns the client
// end, or NULL when the connection fails. PackCapEnd frees p.
static SOCK *PackCapStart(PACKCAP_TEST *t, PACKCAP_PEER *peer, PACK *p)
{
	SOCK *s;

	Zero(peer, sizeof(PACKCAP_PEER));
	peer->Listen = t->Listen;
	peer->Pack = p;
	peer->Thread = NewThread(PackCapPeerThread, peer);

	s = Connect("127.0.0.1", PACKCAP_PORT);
	if (s != NULL)
	{
		SetTimeout(s, PACKCAP_TIMEOUT);
	}

	return s;
}

// Close the client end, which also ends a send of the peer that the client did not read, wait for
// the peer thread and free the connection
static void PackCapEnd(PACKCAP_TEST *t, PACKCAP_PEER *peer, SOCK *s)
{
	if (s != NULL)
	{
		Disconnect(s);
		ReleaseSock(s);
	}
	else
	{
		// No connection reached the peer: end its Accept by closing the listener (later cases fail)
		Disconnect(t->Listen);
	}

	WaitThread(peer->Thread, INFINITE);
	ReleaseThread(peer->Thread);

	if (peer->Sock != NULL)
	{
		Disconnect(peer->Sock);
		ReleaseSock(peer->Sock);
	}

	FreePack(peer->Pack);
}

// Hello Pack as ServerUploadHello sends it, with pad_size bytes of padding when pad_size is not 0
static PACK *PackCapHello(UINT pad_size)
{
	UCHAR random[SHA1_SIZE];
	PACK *p;

	Rand(random, sizeof(random));
	p = PackHello(random, PACKCAP_SERVER_VER, PACKCAP_SERVER_BUILD, PACKCAP_SERVER_STR);

	if (pad_size != 0)
	{
		void *pad = ZeroMalloc(pad_size);

		PackAddData(p, "packcap_pad", pad, pad_size);
		Free(pad);
	}

	return p;
}

// Welcome Pack with the elements of PackWelcome and the longest "Msg" that ServerAccept can make:
// both Windows version notices and a hub message of HUB_MAXMSG_LEN characters, each character 3 bytes
// in UTF-8. *msg_size gets the size of "Msg". pad_size bytes of
// padding are added when pad_size is not 0.
static PACK *PackCapWelcome(UINT pad_size, UINT *msg_size)
{
	PACK *p = NewPack();
	POLICY *policy = ZeroMalloc(sizeof(POLICY));
	BUF *msg = NewBuf();
	UCHAR session_key[SHA1_SIZE];

	PackAddStr(p, "session_name", "SID-PACKCAP-1");
	PackAddStr(p, "connection_name", "CID-PACKCAP-1");
	PackAddInt(p, "max_connection", 1);
	PackAddInt(p, "use_encrypt", 1);
	PackAddInt(p, "use_compress", 0);
	PackAddInt(p, "half_connection", 0);
	PackAddInt(p, "timeout", TIMEOUT_DEFAULT);
	PackAddInt(p, "qos", 0);
	Rand(session_key, sizeof(session_key));
	PackAddData(p, "session_key", session_key, sizeof(session_key));
	PackAddInt(p, "session_key_32", Rand32());
	PackAddPolicy(p, policy);
	PackAddInt(p, "vlan_id", 0);

	for (UINT i = 0;i < PACKCAP_WINVER_MSG_LEN * 2 + HUB_MAXMSG_LEN;i++)
	{
		// U+3042 HIRAGANA LETTER A
		WriteBuf(msg, "\xE3\x81\x82", 3);
	}

	PackAddData(p, "Msg", msg->Buf, msg->Size);
	*msg_size = msg->Size;

	if (pad_size != 0)
	{
		void *pad = ZeroMalloc(pad_size);

		PackAddData(p, "packcap_pad", pad, pad_size);
		Free(pad);
	}

	FreeBuf(msg);
	Free(policy);

	return p;
}

// ClientDownloadHello on a connection that the peer answers with p. *err gets the error of the
// connection and *ver the server version that the client read.
static bool PackCapDownloadHello(PACKCAP_TEST *t, PACK *p, UINT *err, UINT *ver)
{
	PACKCAP_PEER peer;
	CONNECTION *c = ZeroMalloc(sizeof(CONNECTION));
	SOCK *s = PackCapStart(t, &peer, p);
	bool ret = false;

	if (s != NULL)
	{
		ret = ClientDownloadHello(c, s);
	}

	*err = c->Err;
	*ver = c->ServerVer;

	PackCapEnd(t, &peer, s);
	Free(c);

	return ret;
}

// The welcome Pack as ClientConnect reads it (HttpClientRecvEx with CLIENT_WELCOME_PACK_MAX_SIZE) on a
// connection that the peer answers with p. Returns the Pack that the client read, or NULL.
static PACK *PackCapRecvWelcome(PACKCAP_TEST *t, PACK *p)
{
	PACKCAP_PEER peer;
	SOCK *s = PackCapStart(t, &peer, p);
	PACK *ret = NULL;

	if (s != NULL)
	{
		ret = HttpClientRecvEx(s, CLIENT_WELCOME_PACK_MAX_SIZE);
	}

	PackCapEnd(t, &peer, s);

	return ret;
}

// packcap: the client reads no Pack beyond its cap from the server
void packcap_test(UINT num, char **arg)
{
	PACKCAP_TEST t;
	bool ok;
	UINT err;
	UINT ver;
	UINT msg_size;
	UINT pack_size;
	PACK *p;
	PACK *w;
	BUF *b;
	IP loopback;

	Zero(&t, sizeof(t));

	Print("Client Pack size cap test (ClientDownloadHello, the welcome Pack of ClientConnect)\n");

	GetLocalHostIP4(&loopback);
	t.Listen = Listen(PACKCAP_PORT, &loopback, false);
	PackCapCheck(&t, t.Listen != NULL, "The peer listens on 127.0.0.1", "cannot listen on TCP %u", PACKCAP_PORT);

	if (t.Listen != NULL)
	{
		ok = PackCapDownloadHello(&t, PackCapHello(0), &err, &ver);
		PackCapCheck(&t, ok && err == 0 && ver == PACKCAP_SERVER_VER, "ClientDownloadHello accepts a hello Pack of normal size",
			"result %s, error %u, version %u", ok ? "true" : "false", err, ver);

		ok = PackCapDownloadHello(&t, PackCapHello(PACKCAP_BIG_SIZE), &err, &ver);
		PackCapCheck(&t, ok == false && err != 0,
			"ClientDownloadHello refuses a valid hello Pack of 1 MiB with an error (the old client read up to MAX_PACK_SIZE)",
			"result %s, error %u", ok ? "true" : "false", err);

		// The longest welcome Pack of a conformant server needs more than the cap before the authentication
		p = PackCapWelcome(0, &msg_size);
		b = PackToBuf(p);
		pack_size = b->Size;
		FreeBuf(b);
		PackCapCheck(&t, pack_size > HTTP_PACK_MAX_SIZE, "The longest welcome Pack is larger than HTTP_PACK_MAX_SIZE",
			"%u bytes, of them %u bytes of Msg", pack_size, msg_size);

		w = PackCapRecvWelcome(&t, p);
		PackCapCheck(&t, w != NULL && PackGetDataSize(w, "Msg") == msg_size && PackGetInt(w, "timeout") == TIMEOUT_DEFAULT,
			"The welcome cap of ClientConnect reads the longest welcome Pack intact",
			"%s, Msg of %u bytes (sent %u)", w == NULL ? "refused" : "read", PackGetDataSize(w, "Msg"), msg_size);
		FreePack(w);

		w = PackCapRecvWelcome(&t, PackCapWelcome(PACKCAP_BIG_SIZE, &msg_size));
		PackCapCheck(&t, w == NULL, "The welcome cap of ClientConnect refuses a welcome Pack padded by 1 MiB", "the client read it");
		FreePack(w);

		Disconnect(t.Listen);
		ReleaseSock(t.Listen);
	}

	if (t.NumFailed == 0)
	{
		Print("PACKCAP TEST OK\n");
	}
	else
	{
		Print("PACKCAP TEST FAILED (%u of %u checks failed)\n", t.NumFailed, t.NumChecks);
	}
}
