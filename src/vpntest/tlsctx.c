// tlsctx.c
// Named shared server SSL_CTX test of vpntest ("tlsctx" command, FND-140 #145)
//
// A Cedar holds one server SSL_CTX for all accepted connections (GetCedarServerSslCtx): certificate, key, chain,
// cipher list and SslAcceptSettings are applied when it is built, and each connection takes it by reference
// (StartSSLServer). The test accepts loopback connections the way ConnectionAccept does and checks:
// - connections with an unchanged configuration share one context and present the same certificate;
// - SetCedarCertAndChain: the next connection presents the new certificate;
// - SetCedarCipherList: the next connection negotiates the new cipher (TLS 1.2: TLS 1.3 is switched off in
//   SslAcceptSettings, which is itself a change that has to reach the next connection);
// - SslAcceptSettings changed in place (TLS 1.3 on again): the next connection negotiates TLS 1.3.
// Then it prints the accept rate of a context per connection against the shared context (informational).
// Prints "TLSCTX TEST OK" only when every check passes, and frees everything it allocates.

#include "Cedar/Cedar.h"

#include "Mayaqua/Memory.h"
#include "Mayaqua/Str.h"
#include "Mayaqua/Tick64.h"

#include <stdarg.h>

#define	TLSCTX_PORT				39570			// Loopback listener
#define	TLSCTX_TIMEOUT			10000			// Milliseconds a socket of the test waits
#define	TLSCTX_SAME				10				// Connections run with an unchanged configuration
#define	TLSCTX_BENCH_CONNS		40				// Connections of each accept-rate run
#define	TLSCTX_CIPHER_128		"ECDHE-RSA-AES128-GCM-SHA256"
#define	TLSCTX_CIPHER_256		"ECDHE-RSA-AES256-GCM-SHA384"

// Run state of the test
typedef struct TLSCTX_TEST
{
	UINT NumChecks;						// Checks run so far
	UINT NumFailed;						// Checks failed so far
} TLSCTX_TEST;

// What a client saw of one connection
typedef struct TLSCTX_RESULT
{
	bool Ok;							// The handshake succeeded
	UCHAR Digest[SHA1_SIZE];			// SHA-1 of the certificate of the server
	char Cipher[64];					// Negotiated cipher
	char Version[16];					// Negotiated protocol version
} TLSCTX_RESULT;

// The accepting side: Count connections, each with the context of the Cedar or one of its own
typedef struct TLSCTX_SERVER
{
	CEDAR *Cedar;
	SOCK *Listen;
	UINT Count;							// Connections to accept
	bool Shared;						// true: the shared context of the Cedar, false: a context per connection
	X *Cert;							// Certificate and key of a context per connection
	K *Key;
	UINT NumOk;							// Handshakes that succeeded
	void *FirstCtx;						// Context of the first connection (compared, never used)
	bool SameCtx;						// Every connection had the context of the first one
} TLSCTX_SERVER;

// Record one check: print [PASS], or [FAIL] with the formatted detail
static void TlsCtxCheck(TLSCTX_TEST *t, bool ok, char *what, char *detail_fmt, ...)
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

// Accept the connections as ConnectionAccept does: the Cedar's context by reference, or a context per connection
static void TlsCtxServerThread(THREAD *thread, void *param)
{
	TLSCTX_SERVER *srv = (TLSCTX_SERVER *)param;
	UINT i;

	srv->SameCtx = true;

	for (i = 0;i < srv->Count;i++)
	{
		SOCK *s = Accept(srv->Listen);
		UINT ssl_err = 0;
		bool ok;

		if (s == NULL)
		{
			break;
		}

		SetTimeout(s, TLSCTX_TIMEOUT);

		if (srv->Shared)
		{
			struct ssl_ctx_st *ctx = GetCedarServerSslCtx(srv->Cedar);

			if (i == 0)
			{
				srv->FirstCtx = ctx;
			}
			else if (ctx != srv->FirstCtx)
			{
				srv->SameCtx = false;
			}

			ok = StartSSLServer(s, ctx, &ssl_err);

			FreeSSLCtx(ctx);
		}
		else
		{
			ok = StartSSLEx3(s, srv->Cert, srv->Key, NULL, NULL, NULL, &ssl_err);
		}

		if (ok)
		{
			srv->NumOk++;
		}

		Disconnect(s);
		ReleaseSock(s);
	}
}

// One client connection to the loopback listener: the certificate, cipher and version it was given
static void TlsCtxClient(TLSCTX_RESULT *r)
{
	SOCK *s;

	Zero(r, sizeof(TLSCTX_RESULT));

	s = Connect("127.0.0.1", TLSCTX_PORT);
	if (s == NULL)
	{
		return;
	}

	SetTimeout(s, TLSCTX_TIMEOUT);

	if (StartSSL(s, NULL, NULL) && s->RemoteX != NULL)
	{
		UCHAR buf[64];

		r->Ok = true;
		GetXDigest(s->RemoteX, r->Digest, true);
		StrCpy(r->Cipher, sizeof(r->Cipher), s->CipherName);
		StrCpy(r->Version, sizeof(r->Version), (char *)s->SslVersion);

		// Wait for the server to close: a TLS 1.3 server writes its session tickets after the client is done,
		// and a client that closes first resets the socket under that write and fails the accept
		while (Recv(s, buf, sizeof(buf), true) != 0)
		{
		}
	}

	Disconnect(s);
	ReleaseSock(s);
}

// Run count connections against a server thread. result (count entries) gets what each client saw
static void TlsCtxRun(TLSCTX_SERVER *srv, TLSCTX_RESULT *result, UINT count)
{
	THREAD *thread;
	UINT i;

	srv->Count = count;
	srv->NumOk = 0;
	srv->FirstCtx = NULL;
	srv->SameCtx = true;

	thread = NewThread(TlsCtxServerThread, srv);

	for (i = 0;i < count;i++)
	{
		TlsCtxClient(&result[i]);
	}

	if (WaitThread(thread, TLSCTX_TIMEOUT) == false)
	{
		// A failed client left an Accept waiting: close the listener, it is opened again by the next run
		Disconnect(srv->Listen);
		WaitThread(thread, INFINITE);
		ReleaseSock(srv->Listen);
		srv->Listen = NULL;
	}

	ReleaseThread(thread);
}

// Open the loopback listener unless it is open
static bool TlsCtxListen(TLSCTX_SERVER *srv)
{
	if (srv->Listen == NULL)
	{
		srv->Listen = ListenEx(TLSCTX_PORT, true);
	}

	return (srv->Listen != NULL);
}

// One connection with the shared context: what the client saw
static bool TlsCtxOne(TLSCTX_SERVER *srv, TLSCTX_RESULT *r)
{
	srv->Shared = true;

	if (TlsCtxListen(srv) == false)
	{
		Zero(r, sizeof(TLSCTX_RESULT));
		return false;
	}

	TlsCtxRun(srv, r, 1);

	return (srv->NumOk == 1 && r->Ok);
}

// Milliseconds of count connections with a context per connection or with the shared context. 0 on a failure
static UINT64 TlsCtxBench(TLSCTX_SERVER *srv, bool shared)
{
	TLSCTX_RESULT *result = ZeroMalloc(sizeof(TLSCTX_RESULT) * TLSCTX_BENCH_CONNS);
	UINT64 start, ret;
	UINT i;
	bool ok = true;

	srv->Shared = shared;

	if (TlsCtxListen(srv) == false)
	{
		Free(result);
		return 0;
	}

	start = Tick64();
	TlsCtxRun(srv, result, TLSCTX_BENCH_CONNS);
	ret = Tick64() - start;

	for (i = 0;i < TLSCTX_BENCH_CONNS;i++)
	{
		if (result[i].Ok == false)
		{
			ok = false;
		}
	}

	Free(result);

	if (ok == false || srv->NumOk != TLSCTX_BENCH_CONNS)
	{
		return 0;
	}

	return MAX(ret, 1);
}

// A root certificate of its own key, for the test
static X *TlsCtxNewCert(wchar_t *name, K **priv)
{
	K *pub = NULL;
	NAME *n;
	X *x = NULL;

	*priv = NULL;

	if (RsaGen(priv, &pub, 2048))
	{
		n = NewName(name, NULL, NULL, NULL, NULL, NULL);
		x = NewRootX(pub, *priv, n, 365, NULL);
		FreeName(n);
	}

	FreeK(pub);

	return x;
}

// tlsctx: certificate, cipher and settings changes reach the next connection of the one shared server context
void tlsctx_test(UINT num, char **arg)
{
	TLSCTX_TEST t;
	TLSCTX_SERVER srv;
	TLSCTX_RESULT r;
	TLSCTX_RESULT same[TLSCTX_SAME];
	UCHAR digest_a[SHA1_SIZE], digest_b[SHA1_SIZE];
	K *priv_a, *priv_b;
	X *x_a, *x_b;
	CEDAR *cedar;
	UINT i;
	UINT num_same;
	UINT64 ms_each, ms_shared;

	Zero(&t, sizeof(t));
	Zero(&srv, sizeof(srv));

	Print("Shared server SSL_CTX test (GetCedarServerSslCtx, StartSSLServer)\n");

	x_a = TlsCtxNewCert(L"Ranz VPN tlsctx test A", &priv_a);
	x_b = TlsCtxNewCert(L"Ranz VPN tlsctx test B", &priv_b);
	TlsCtxCheck(&t, x_a != NULL && x_b != NULL, "two certificates are made", "RsaGen or NewRootX failed");

	if (x_a == NULL || x_b == NULL)
	{
		FreeX(x_a);
		FreeX(x_b);
		FreeK(priv_a);
		FreeK(priv_b);
		Print("TLSCTX TEST FAILED (%u of %u checks failed)\n", t.NumFailed, t.NumChecks);
		return;
	}

	GetXDigest(x_a, digest_a, true);
	GetXDigest(x_b, digest_b, true);

	// TLS 1.2 with one cipher, so that both are seen in the result
	cedar = NewCedar(x_a, priv_a);
	cedar->SslAcceptSettings.Tls_Disable1_3 = true;
	SetCedarCipherList(cedar, TLSCTX_CIPHER_128);

	srv.Cedar = cedar;
	srv.Shared = true;
	srv.Cert = x_a;
	srv.Key = priv_a;

	// Connections with an unchanged configuration
	num_same = 0;
	if (TlsCtxListen(&srv))
	{
		TlsCtxRun(&srv, same, TLSCTX_SAME);

		for (i = 0;i < TLSCTX_SAME;i++)
		{
			if (same[i].Ok && Cmp(same[i].Digest, digest_a, SHA1_SIZE) == 0 &&
				StrCmp(same[i].Cipher, TLSCTX_CIPHER_128) == 0 && StrCmp(same[i].Version, "TLSv1.2") == 0)
			{
				num_same++;
			}
		}
	}
	TlsCtxCheck(&t, num_same == TLSCTX_SAME && srv.NumOk == TLSCTX_SAME,
		"unchanged configuration: every connection presents the certificate, TLS 1.2 and the cipher",
		"%u of %u connections as configured, %u handshakes", num_same, TLSCTX_SAME, srv.NumOk);
	TlsCtxCheck(&t, srv.SameCtx, "unchanged configuration: every connection has the same context", "the context was built again");

	// SetCedarCertAndChain
	SetCedarCertAndChain(cedar, x_b, priv_b, NULL);
	TlsCtxCheck(&t, TlsCtxOne(&srv, &r) && Cmp(r.Digest, digest_b, SHA1_SIZE) == 0,
		"SetCedarCertAndChain: the next connection presents the new certificate", "old certificate or failed handshake");

	// SetCedarCipherList
	SetCedarCipherList(cedar, TLSCTX_CIPHER_256);
	TlsCtxCheck(&t, TlsCtxOne(&srv, &r) && StrCmp(r.Cipher, TLSCTX_CIPHER_256) == 0,
		"SetCedarCipherList: the next connection negotiates the new cipher", "cipher %s", r.Cipher);

	// SslAcceptSettings changed in place
	cedar->SslAcceptSettings.Tls_Disable1_3 = false;
	TlsCtxCheck(&t, TlsCtxOne(&srv, &r) && StrCmp(r.Version, "TLSv1.3") == 0,
		"SslAcceptSettings: the next connection negotiates TLS 1.3 after it was switched on", "version %s", r.Version);

	// The accept rate of a context per connection against the shared one (informational)
	ms_each = TlsCtxBench(&srv, false);
	ms_shared = TlsCtxBench(&srv, true);
	TlsCtxCheck(&t, ms_each != 0 && ms_shared != 0, "accept rate: both runs completed", "%u ms and %u ms", (UINT)ms_each, (UINT)ms_shared);

	if (ms_each != 0 && ms_shared != 0)
	{
		Print("BENCH tlsctx_accept_ctx_per_connection %u connections %I64u ms %u per second\n",
			TLSCTX_BENCH_CONNS, ms_each, (UINT)(TLSCTX_BENCH_CONNS * 1000ULL / ms_each));
		Print("BENCH tlsctx_accept_shared_ctx %u connections %I64u ms %u per second\n",
			TLSCTX_BENCH_CONNS, ms_shared, (UINT)(TLSCTX_BENCH_CONNS * 1000ULL / ms_shared));
	}

	if (srv.Listen != NULL)
	{
		Disconnect(srv.Listen);
		ReleaseSock(srv.Listen);
	}

	ReleaseCedar(cedar);
	FreeX(x_a);
	FreeX(x_b);
	FreeK(priv_a);
	FreeK(priv_b);

	if (t.NumFailed == 0)
	{
		Print("TLSCTX TEST OK\n");
	}
	else
	{
		Print("TLSCTX TEST FAILED (%u of %u checks failed)\n", t.NumFailed, t.NumChecks);
	}
}
