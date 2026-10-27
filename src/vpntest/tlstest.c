// tlstest.c
// Named TLS transport test of vpntest ("tls" command, CORE-S2-1 #69)
//
// The TLS transport of the new core (src/Core/TransportTls.c) on Schannel: TLS over TCP on a test port of the loopback
// interface, never 443, with the server certificate read from the store by its thumbprint. A client completes the TLS
// handshake, and the Noise session comes up over the stream, bound to it by the TLS exporter, and carries records both
// ways while keepalives and the updates of the outer keys pass. The checks:
// - the key exchange groups: the transport puts X25519MLKEM768 first in the machine's Schannel group list where the OS
//   has ML-KEM, then X25519 (TransportTlsSetGroups), and the ServerHello on the wire carries the group 0x11EC where the
//   OS has ML-KEM, 0x001D where it has not;
// - TLS 1.3 with an AES-GCM suite, with the server's key in the CNG key storage provider, for a certificate made in the
//   store and for one that a PFX brought (imported into the KSP); TLS 1.2 with an AES-GCM suite for a client that
//   offers TLS 1.2 only;
// - the server key: a certificate whose key sits in a legacy CryptoAPI provider (CSP) is refused, so the question of
//   Schannel and a CSP key does not arise; so are a thumbprint that is in no store and a malformed one;
// - the pin and the binding: a certificate that the client did not pin is refused, and a client that computes another
//   binding, as a middlebox that terminated the TLS would, cannot complete the Noise handshake;
// - the listener and the dialler: a peer that speaks no TLS is dropped, one that sends nothing holds no other client
//   back, many records' worth of bytes go through, the close_notify ends a stream, a stream that nobody accepted goes
//   with its listener, and a dial where nothing listens, a cancelled one and malformed addresses fail;
// - the fallback: of a client's list with a QUIC entry that never connects (UDP blocked) and the TLS entry, TLS wins
//   the race and carries the session;
// - the ingress queue (the TCP-over-TCP amendment of ADR-0022): the data records of a session over TLS-443 wait in a
//   queue that CoDel runs. While the server reads nothing, the records stand in the queue and Send does not wait for
//   the stream; while it reads slowly, CoDel drops records at the head; every record that the queue lets out reaches
//   the server, in order;
// - the ServerHello parser on records made here: TLS 1.3, after a ChangeCipherSpec, a HelloRetryRequest, TLS 1.2, and
//   records that are cut short or are no ServerHello.
// The group list is the machine's: the test needs administrator rights, and an ECC Curve Order policy must not override
// the list (CI takes the runner image's off, .github/scripts/vpntest.ps1). Print "TLS TEST OK" only when every check
// passes.

#include "testlist.h"

#include "Mayaqua/Internat.h"
#include "Mayaqua/Kernel.h"
#include "Mayaqua/Memory.h"
#include "Mayaqua/Str.h"
#include "Mayaqua/Tick64.h"

#include "Core/Transport.h"

#include <WS2tcpip.h>
#include <ncrypt.h>

#include <stdio.h>

#define	TLSTEST_WATCHDOG	180000				// The test process is aborted after this (ms)
#define	TLSTEST_TIMEOUT		15000				// A handshake, an accept or a record within this time (ms)
#define	TLSTEST_SHORT		5000				// A closed or dropped connection shows within this time (ms)
#define	TLSTEST_IDLE		1000				// The idle wait in which keepalives and the updates of the outer keys pass (ms)
#define	TLSTEST_LISTEN		"127.0.0.1:0"		// The listener binds an ephemeral port of the loopback interface: a test port, never 443
#define	TLSTEST_CN			L"CN=localhost"		// The subject of the server certificates
#define	TLSTEST_SAN			L"localhost"		// Their subject alternative name
#define	TLSTEST_OTHER		"00112233445566778899AABBCCDDEEFF00112233"	// A thumbprint that no certificate of the test has
#define	TLSTEST_CSP			L"Ranz-TlsTest-Csp"	// The key container of the certificate whose key sits in a legacy CSP
#define	TLSTEST_PFX_KEY		L"Ranz-TlsTest-Pfx"	// The exportable KSP key of the certificate that goes into a PFX
#define	TLSTEST_PFX_PASS	L"Ranz-TlsTest-1"	// The password of that PFX
#define	TLSTEST_PROBE		"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n"	// What a peer that speaks no TLS sends
#define	TLSTEST_BULK		100000				// Bytes of the write of many records
#define	TLSTEST_GROUPS_KEY	L"SYSTEM\\CurrentControlSet\\Control\\Cryptography\\Configuration\\Local\\SSL\\00010002"
#define	TLSTEST_POLICY_KEY	L"SOFTWARE\\Policies\\Microsoft\\Cryptography\\Configuration\\SSL\\00010002"
#define	TLSTEST_GROUPS_SIZE	2048				// Characters of a group list
#define	TLSTEST_QUEUE_RECORD	4096			// Bytes of a data record of the queue case
#define	TLSTEST_FILL		10000				// The queue case fills the buffers of the stream within this time (ms) ...
#define	TLSTEST_SLOW_PHASE	1000				// ... then the server reads slowly for this long (ms) ...
#define	TLSTEST_SLOW_READ	5					// ... at most a record every this many ms
#define	TLSTEST_STANDING	100					// Records that stand in the queue once the stream stalled
#define	TLSTEST_SEND_MAX	250					// A Send never takes this long (ms): it does not wait for the stream

// How the server of the queue case reads
#define	TLSTEST_PAUSE		0					// Nothing
#define	TLSTEST_SLOW		1					// At most a record every TLSTEST_SLOW_READ ms
#define	TLSTEST_FAST		2					// As fast as the records come

// The state of the test
typedef struct TLSTEST_CTX
{
	UINT NumChecks;
	UINT NumFailed;
} TLSTEST_CTX;

// The server end of one connection, on a thread of its own: it accepts one stream, runs the responder of the Noise
// session, opens its data stream and echoes the records until the client closes
typedef struct TLSTEST_SERVER
{
	TRANSPORT_LISTENER *Listener;		// It accepts one stream here
	UCHAR Key[NOISE_KEY_SIZE];			// The responder's static key
	UCHAR Pub[NOISE_KEY_SIZE];			// ... and its public half, which the client knows in advance
	bool Accepted;						// The Noise handshake completed
} TLSTEST_SERVER;

// How one connection went
typedef struct TLSTEST_RESULT
{
	bool Dialled;						// The TLS handshake completed: the client has a stream
	bool Connected;						// The Noise session came up over it
	bool Bound;							// ... bound to the TLS exporter of the stream: no Noise encryption of its own
	bool Echoed;						// A control and a data record went to the server and came back
	bool Rekeyed;						// The session had the stream update its outer keys while it waited idle
	bool ServerAccepted;				// The server's end of the Noise session came up
	TRANSPORT_TLS_INFO Client;			// What the client's handshake gave
	TRANSPORT_TLS_INFO Server;			// ... and the server's
} TLSTEST_RESULT;

// The server end of the queue case, on a thread of its own: it accepts one stream, runs the responder, opens the data
// stream and reads the client's data records as the client tells it (Pace), until the client closes
typedef struct TLSTEST_QUEUE_SERVER
{
	TRANSPORT_LISTENER *Listener;		// It accepts one stream here
	UCHAR Key[NOISE_KEY_SIZE];			// The responder's static key
	UCHAR Pub[NOISE_KEY_SIZE];			// ... and its public half
	volatile LONG Pace;					// TLSTEST_PAUSE, TLSTEST_SLOW or TLSTEST_FAST
	bool Accepted;						// The Noise handshake completed
	UINT64 NumReceived;					// The data records it received ...
	bool InOrder;						// ... each of the size the client sends, with a number above the one before
	bool Closed;						// The client's close record came
} TLSTEST_QUEUE_SERVER;

static bool TlsTestCheck(TLSTEST_CTX *ctx, bool ok, char *what, char *fmt, ...) RANZ_PRINTF_FORMAT(4, 5);
static bool TlsTestCheck(TLSTEST_CTX *ctx, bool ok, char *what, char *fmt, ...)
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
static DWORD WINAPI TlsTestWatchdog(LPVOID param)
{
	char msg[MAX_SIZE];
	DWORD written = 0;

	if (WaitForSingleObject((HANDLE)param, TLSTEST_WATCHDOG) != WAIT_TIMEOUT)
	{
		return 0;
	}

	int len = snprintf(msg, sizeof(msg), "TLS TEST FAILED (did not finish within %u ms)\n", TLSTEST_WATCHDOG);
	if (len > 0)
	{
		WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), msg, (DWORD)MIN((UINT)len, (UINT)sizeof(msg) - 1), &written, NULL);
	}

	TerminateProcess(GetCurrentProcess(), 1);

	return 0;
}

// The configuration of an end of a test session: short timers, so that keepalives and the updates of the outer keys
// pass while the test waits. The session layer adds the binding of the stream.
static void TlsTestConfig(NOISE_SESSION_CONFIG *c, UCHAR *key, UCHAR *remote)
{
	Zero(c, sizeof(NOISE_SESSION_CONFIG));
	c->Suite = NOISE_SUITE_IK;
	c->StaticKey = key;
	c->RemoteStatic = remote;
	c->KeepaliveInterval = 200;
	c->DeadTimeout = TLSTEST_TIMEOUT;
	c->RekeyInterval = 300;
}

// The name of a TLS version of TRANSPORT_TLS_INFO
static char *TlsTestVersion(UINT version)
{
	if (version == TRANSPORT_TLS_13)
	{
		return "TLS 1.3";
	}
	if (version == TRANSPORT_TLS_12)
	{
		return "TLS 1.2";
	}

	return "no TLS version";
}

// Whether a cipher suite is one of AES-GCM: of TLS 1.3, or of TLS 1.2 with an ECDHE key exchange
static bool TlsTestGcm(UINT suite, UINT version)
{
	if (version == TRANSPORT_TLS_13)
	{
		// TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384
		return suite == 0x1301 || suite == 0x1302;
	}

	// TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 and _256_GCM_SHA384, TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 and
	// _256_GCM_SHA384
	return suite == 0xC02B || suite == 0xC02C || suite == 0xC02F || suite == 0xC030;
}

//
// The sessions
//

// The server thread: accept one stream, run the responder, open the data stream (the Login of these sessions is not
// the subject here: noisehub and quic check it) and echo every control and data record until the client closes
static void TlsTestServerThread(THREAD *thread, void *param)
{
	TLSTEST_SERVER *srv = (TLSTEST_SERVER *)param;
	TRANSPORT_NOISE *n = ZeroMalloc(sizeof(TRANSPORT_NOISE));
	UCHAR *buf = ZeroMalloc(NOISE_MAX_PAYLOAD);
	NOISE_SESSION_CONFIG c;

	TlsTestConfig(&c, srv->Key, NULL);
	srv->Accepted = TransportNoiseAccept(n, TransportAccept(srv->Listener, TLSTEST_TIMEOUT), &c, TLSTEST_TIMEOUT);
	if (srv->Accepted)
	{
		TransportNoiseAcceptLogin(n);
	}

	while (srv->Accepted)
	{
		UINT size = 0;
		UINT ret = TransportNoiseReceive(n, buf, NOISE_MAX_PAYLOAD, &size, TLSTEST_TIMEOUT);

		if (ret != NOISE_RECEIVE_DATA && ret != NOISE_RECEIVE_CONTROL)
		{
			break;
		}
		TransportNoiseSend(n, (ret == NOISE_RECEIVE_DATA ? NOISE_RECORD_DATA : NOISE_RECORD_CONTROL), buf, size);
	}

	TransportNoiseClose(n);
	Free(buf);
	Free(n);
}

// A listener of the server transport on a test port, and the server thread that accepts one stream there; NULL, with
// the port 0, when it cannot listen
static THREAD *TlsTestServe(TRANSPORT *server, TLSTEST_SERVER *srv, USHORT *port)
{
	*port = 0;
	CryptoX25519GenerateKey(srv->Key, srv->Pub);

	srv->Listener = TransportListen(server, TLSTEST_LISTEN);
	if (srv->Listener == NULL)
	{
		return NULL;
	}
	*port = TransportTlsBoundPort(server);

	return NewThread(TlsTestServerThread, srv);
}

// The end of a server thread and its listener
static void TlsTestServeEnd(TLSTEST_SERVER *srv, THREAD *thread)
{
	if (thread != NULL)
	{
		WaitThread(thread, INFINITE);
		ReleaseThread(thread);
	}

	TransportCloseListener(srv->Listener);
	srv->Listener = NULL;
	Zero(srv->Key, sizeof(srv->Key));
}

// The client's end of a session over stream s against a server thread whose public key is server_pub: the Noise
// session comes up, a control and a data record go to the server and come back; idle: then the session waits idle,
// in which keepalives and the updates of the outer keys pass. The session takes s.
static void TlsTestSession(TRANSPORT_STREAM *s, UCHAR *server_pub, bool idle, TLSTEST_RESULT *r)
{
	UCHAR key[NOISE_KEY_SIZE], pub[NOISE_KEY_SIZE];
	NOISE_SESSION_CONFIG c;
	TRANSPORT_NOISE *n = ZeroMalloc(sizeof(TRANSPORT_NOISE));
	UCHAR *buf = ZeroMalloc(NOISE_MAX_PAYLOAD);
	UINT size = 0;

	CryptoX25519GenerateKey(key, pub);
	TlsTestConfig(&c, key, server_pub);

	r->Connected = (s != NULL && TransportNoiseConnect(n, s, &c, TLSTEST_TIMEOUT));
	if (r->Connected)
	{
		r->Bound = ((n->Session.Flags & NOISE_SESSION_ENCRYPT) == 0);

		bool control = TransportNoiseSend(n, NOISE_RECORD_CONTROL, "hello", 5) &&
			TransportNoiseReceive(n, buf, NOISE_MAX_PAYLOAD, &size, TLSTEST_TIMEOUT) == NOISE_RECEIVE_CONTROL && size == 5 && Cmp(buf, "hello", 5) == 0;
		bool data = TransportNoiseSend(n, NOISE_RECORD_DATA, "frame", 5) &&
			TransportNoiseReceive(n, buf, NOISE_MAX_PAYLOAD, &size, TLSTEST_TIMEOUT) == NOISE_RECEIVE_DATA && size == 5 && Cmp(buf, "frame", 5) == 0;
		r->Echoed = (control && data);

		// Idle: nothing for the owner comes, and the session stays open
		if (idle && r->Echoed)
		{
			r->Echoed = (TransportNoiseReceive(n, buf, NOISE_MAX_PAYLOAD, &size, TLSTEST_IDLE) == NOISE_RECEIVE_NONE);
		}
		r->Rekeyed = (n->Session.NumRekeys != 0);
	}

	TransportNoiseClose(n);
	Zero(key, sizeof(key));
	Free(buf);
	Free(n);
}

// One connection: the client dials the listener of the server transport and the session runs over the stream
static void TlsTestRun(TRANSPORT *server, TRANSPORT *client, bool idle, TLSTEST_RESULT *r)
{
	TLSTEST_SERVER *srv = ZeroMalloc(sizeof(TLSTEST_SERVER));
	char address[TRANSPORT_ADDRESS_SIZE];
	USHORT port = 0;

	Zero(r, sizeof(TLSTEST_RESULT));

	THREAD *thread = TlsTestServe(server, srv, &port);
	if (thread != NULL)
	{
		Format(address, sizeof(address), "127.0.0.1:%u", (UINT)port);

		TRANSPORT_STREAM *s = TransportDial(client, address, NULL);
		r->Dialled = (s != NULL);
		if (r->Dialled)
		{
			TransportTlsLastHandshake(client, &r->Client);
		}
		TlsTestSession(s, srv->Pub, idle, r);
	}

	TlsTestServeEnd(srv, thread);
	r->ServerAccepted = srv->Accepted;
	TransportTlsLastHandshake(server, &r->Server);

	Free(srv);
}

// Read exactly size bytes of a stream within TLSTEST_TIMEOUT
static bool TlsTestReadAll(TRANSPORT_STREAM *s, UCHAR *buf, UINT size)
{
	UINT64 end = Tick64() + TLSTEST_TIMEOUT;
	UINT got = 0;

	while (got < size && Tick64() < end)
	{
		UINT n = TransportRead(s, buf + got, size - got, 100);

		if (n == 0)
		{
			return false;
		}
		if (n != TRANSPORT_LATER)
		{
			got += n;
		}
	}

	return (got == size);
}

//
// The key exchange groups
//

// The machine's group list (the policy's where key is the policy key) as text, entries separated by commas, into text;
// false when the machine has none
static bool TlsTestGroupList(wchar_t *key, wchar_t *text, UINT size, wchar_t *first, wchar_t *second, UINT entry_size)
{
	wchar_t *list = ZeroMalloc(TLSTEST_GROUPS_SIZE * sizeof(wchar_t));
	DWORD list_size = (TLSTEST_GROUPS_SIZE - 2) * sizeof(wchar_t);
	UINT num = 0;

	UniStrCpy(text, size, L"");
	UniStrCpy(first, entry_size, L"");
	UniStrCpy(second, entry_size, L"");

	bool ok = (RegGetValueW(HKEY_LOCAL_MACHINE, key, L"EccCurves", RRF_RT_REG_MULTI_SZ, NULL, list, &list_size) == ERROR_SUCCESS);
	for (wchar_t *g = list; ok && *g != 0; g += UniStrLen(g) + 1)
	{
		if (num == 0)
		{
			UniStrCpy(first, entry_size, g);
		}
		else if (num == 1)
		{
			UniStrCpy(second, entry_size, g);
		}
		if (num != 0)
		{
			UniStrCat(text, size, L", ");
		}
		UniStrCat(text, size, g);
		num++;
	}

	Free(list);

	return ok;
}

// The transport puts its groups first in the machine's Schannel list: X25519MLKEM768 where the OS has ML-KEM, then
// X25519; a second call finds the list set
static void TlsTestGroups(TLSTEST_CTX *ctx)
{
	wchar_t text[MAX_SIZE], first[64], second[64];
	wchar_t build[64];
	DWORD ubr = 0, ubr_size = sizeof(ubr), build_size = sizeof(build);
	bool mlkem = CryptoMlKemAvailable();

	Print("[the key exchange groups of the machine's Schannel list]\n");

	// The Windows build and its update revision: the hybrid groups of Schannel came with the updates of July 2026
	UniStrCpy(build, sizeof(build), L"?");
	RegGetValueW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", L"CurrentBuild", RRF_RT_REG_SZ, NULL, build, &build_size);
	RegGetValueW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", L"UBR", RRF_RT_REG_DWORD, NULL, &ubr, &ubr_size);
	Print("  Windows build %S.%u; ML-KEM in CNG: %s\n", build, (UINT)ubr, mlkem ? "yes" : "no");

	if (TlsTestGroupList(TLSTEST_POLICY_KEY, text, sizeof(text), first, second, sizeof(first)))
	{
		Print("  an ECC Curve Order policy sets the list: %S\n", text);
	}

	UINT ret = TransportTlsSetGroups();
	TlsTestCheck(ctx, ret == TRANSPORT_TLS_GROUPS_SET, "  the transport sets the machine's group list", "%s",
		ret == TRANSPORT_TLS_GROUPS_POLICY ? "an ECC Curve Order policy overrides the list" : "the list could not be read or written (administrator rights)");

	bool listed = TlsTestGroupList(TLSTEST_GROUPS_KEY, text, sizeof(text), first, second, sizeof(first));
	Print("  the machine's list: %S\n", text);
	if (mlkem)
	{
		TlsTestCheck(ctx, listed && UniStrCmpi(first, L"x25519_mlkem768") == 0 && UniStrCmpi(second, L"curve25519") == 0,
			"  X25519MLKEM768 first, X25519 as the fallback (the OS has ML-KEM)", "the list is %S", text);
	}
	else
	{
		TlsTestCheck(ctx, listed && UniStrCmpi(first, L"curve25519") == 0, "  X25519 first (the OS has no ML-KEM: no hybrid)", "the list is %S", text);
	}

	TlsTestCheck(ctx, TransportTlsSetGroups() == TRANSPORT_TLS_GROUPS_SET, "  a second call finds the list set", "it did not");
}

//
// The ServerHello parser
//

// Put a 16-bit value at p, big-endian
static void TlsTestPut16(UCHAR *p, UINT v)
{
	p[0] = (UCHAR)(v >> 8);
	p[1] = (UCHAR)v;
}

// A ServerHello record into buf, as a server sends it: TLS 1.3 (supported_versions 0x0304, and a key_share of group
// with a key of 32 bytes; of the group only for a HelloRetryRequest, retry) or TLS 1.2 (no extensions), with suite,
// after a ChangeCipherSpec record where ccs. Its size.
static UINT TlsTestHelloRecord(UCHAR *buf, bool tls13, bool retry, UINT suite, UINT group, bool ccs)
{
	static UCHAR retry_random[32] = {0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11, 0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91,
		0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E, 0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C};
	UINT p = 0;

	if (ccs)
	{
		buf[p++] = 20;
		TlsTestPut16(buf + p, 0x0303);
		TlsTestPut16(buf + p + 2, 1);
		buf[p + 4] = 1;
		p += 5;
	}

	// The record header and the handshake header, their lengths filled in at the end
	UINT record = p;
	buf[p] = 22;
	TlsTestPut16(buf + p + 1, 0x0303);
	p += 5;
	UINT handshake = p;
	buf[p] = 2;
	p += 4;
	UINT body = p;

	TlsTestPut16(buf + p, 0x0303);
	p += 2;
	if (retry)
	{
		Copy(buf + p, retry_random, 32);
	}
	else
	{
		Zero(buf + p, 32);
		buf[p] = 0x5A;
	}
	p += 32;
	buf[p++] = 0;					// legacy_session_id_echo: empty
	TlsTestPut16(buf + p, suite);
	p += 2;
	buf[p++] = 0;					// legacy_compression_method

	if (tls13)
	{
		UINT extensions = p;
		p += 2;

		TlsTestPut16(buf + p, 0x002B);	// supported_versions: TLS 1.3
		TlsTestPut16(buf + p + 2, 2);
		TlsTestPut16(buf + p + 4, 0x0304);
		p += 6;

		TlsTestPut16(buf + p, 0x0033);	// key_share
		if (retry)
		{
			TlsTestPut16(buf + p + 2, 2);
			TlsTestPut16(buf + p + 4, group);
			p += 6;
		}
		else
		{
			TlsTestPut16(buf + p + 2, 2 + 2 + 32);
			TlsTestPut16(buf + p + 4, group);
			TlsTestPut16(buf + p + 6, 32);
			Zero(buf + p + 8, 32);
			p += 8 + 32;
		}

		TlsTestPut16(buf + extensions, p - extensions - 2);
	}

	buf[handshake + 1] = 0;
	TlsTestPut16(buf + handshake + 2, p - body);
	TlsTestPut16(buf + record + 3, p - handshake);

	return p;
}

// The parser on records made here: what it reads from each ServerHello, and that it takes none of the others
static void TlsTestHello(TLSTEST_CTX *ctx)
{
	UCHAR buf[256];
	TRANSPORT_TLS_INFO info;
	UINT size;

	Print("[the ServerHello parser]\n");

	size = TlsTestHelloRecord(buf, true, false, 0x1302, CRYPTO_GROUP_X25519MLKEM768, false);
	TlsTestCheck(ctx, TransportTlsParseHello(buf, size, &info) && info.Version == TRANSPORT_TLS_13 && info.CipherSuite == 0x1302 &&
		info.Group == CRYPTO_GROUP_X25519MLKEM768 && info.Retried == false, "  a TLS 1.3 ServerHello: the version of supported_versions, the suite, the group 0x11EC of key_share",
		"version %u, suite 0x%04X, group 0x%04X, retried %u", info.Version, info.CipherSuite, info.Group, (UINT)info.Retried);

	size = TlsTestHelloRecord(buf, true, false, 0x1301, CRYPTO_GROUP_X25519, true);
	TlsTestCheck(ctx, TransportTlsParseHello(buf, size, &info) && info.Version == TRANSPORT_TLS_13 && info.CipherSuite == 0x1301 && info.Group == CRYPTO_GROUP_X25519,
		"  after a ChangeCipherSpec record of the middlebox compatibility mode", "version %u, suite 0x%04X, group 0x%04X", info.Version, info.CipherSuite, info.Group);

	size = TlsTestHelloRecord(buf, true, true, 0x1302, CRYPTO_GROUP_X25519, false);
	TlsTestCheck(ctx, TransportTlsParseHello(buf, size, &info) && info.Retried && info.Group == CRYPTO_GROUP_X25519,
		"  a HelloRetryRequest: its group, and that it asks for another key share", "group 0x%04X, retried %u", info.Group, (UINT)info.Retried);

	size = TlsTestHelloRecord(buf, false, false, 0xC02C, 0, false);
	TlsTestCheck(ctx, TransportTlsParseHello(buf, size, &info) && info.Version == TRANSPORT_TLS_12 && info.CipherSuite == 0xC02C && info.Group == 0,
		"  a TLS 1.2 ServerHello without extensions: TLS 1.2, its suite, no group", "version %u, suite 0x%04X, group 0x%04X", info.Version, info.CipherSuite, info.Group);

	// Cut short anywhere, it is not taken; nor is a record of another type, a message of another type, or nothing
	size = TlsTestHelloRecord(buf, true, false, 0x1302, CRYPTO_GROUP_X25519MLKEM768, true);
	bool cut = true;
	for (UINT i = 0; i < size; i++)
	{
		cut = cut && TransportTlsParseHello(buf, i, &info) == false;
	}
	TlsTestCheck(ctx, cut, "  a record cut short at any byte is not taken", "one was");

	size = TlsTestHelloRecord(buf, true, false, 0x1302, CRYPTO_GROUP_X25519MLKEM768, false);
	buf[0] = 21;
	bool alert = (TransportTlsParseHello(buf, size, &info) == false);
	buf[0] = 22;
	buf[5] = 1;
	bool client_hello = (TransportTlsParseHello(buf, size, &info) == false);
	TlsTestCheck(ctx, alert && client_hello && TransportTlsParseHello(NULL, 0, &info) == false,
		"  an alert record, a ClientHello and no bytes are no ServerHello", "alert %u, ClientHello %u", (UINT)alert, (UINT)client_hello);
}

//
// The certificates
//

// Delete the key container of the CSP certificate; CRYPT_DELETEKEYSET leaves no handle
static void TlsTestCspDelete()
{
	HCRYPTPROV prov = 0;

	CryptAcquireContextW(&prov, TLSTEST_CSP, MS_ENH_RSA_AES_PROV_W, PROV_RSA_AES, CRYPT_DELETEKEYSET);
}

// A self-signed certificate whose key sits in a legacy CryptoAPI provider (CSP): an RSA key of the Microsoft Enhanced
// RSA and AES Cryptographic Provider in the container TLSTEST_CSP; NULL when it cannot be made
static PCCERT_CONTEXT TlsTestCspCert()
{
	HCRYPTPROV prov = 0;
	HCRYPTKEY key = 0;
	CERT_NAME_BLOB subject;
	CRYPT_KEY_PROV_INFO info;
	BYTE name[256];
	PCCERT_CONTEXT cert = NULL;

	// A container that an earlier run left goes first
	TlsTestCspDelete();
	if (CryptAcquireContextW(&prov, TLSTEST_CSP, MS_ENH_RSA_AES_PROV_W, PROV_RSA_AES, CRYPT_NEWKEYSET) == false)
	{
		return NULL;
	}

	subject.cbData = sizeof(name);
	subject.pbData = name;
	if (CryptGenKey(prov, AT_KEYEXCHANGE, 2048 << 16, &key) &&
		CertStrToNameW(X509_ASN_ENCODING, L"CN=csp.tlstest", CERT_X500_NAME_STR, NULL, name, &subject.cbData, NULL))
	{
		Zero(&info, sizeof(info));
		info.pwszContainerName = TLSTEST_CSP;
		info.pwszProvName = (LPWSTR)MS_ENH_RSA_AES_PROV_W;
		info.dwProvType = PROV_RSA_AES;
		info.dwKeySpec = AT_KEYEXCHANGE;
		cert = CertCreateSelfSignCertificate(prov, &subject, 0, &info, NULL, NULL, NULL, NULL);
	}

	if (key != 0)
	{
		CryptDestroyKey(key);
	}
	CryptReleaseContext(prov, 0);

	return cert;
}

// A PFX made as an operator's tool makes one: a self-signed ECDSA P-256 certificate whose key in the software KSP may be
// exported, and its PFX under TLSTEST_PFX_PASS; the key and the certificate go again. The PFX, NULL when it cannot be
// made.
static BUF *TlsTestPfx()
{
	NCRYPT_PROV_HANDLE prov = 0;
	NCRYPT_KEY_HANDLE key = 0;
	DWORD policy = NCRYPT_ALLOW_EXPORT_FLAG | NCRYPT_ALLOW_PLAINTEXT_EXPORT_FLAG;
	CERT_NAME_BLOB subject;
	CRYPT_KEY_PROV_INFO info;
	CRYPT_ALGORITHM_IDENTIFIER alg;
	CRYPT_DATA_BLOB pfx;
	BYTE name[256];
	PCCERT_CONTEXT cert = NULL;
	BUF *ret = NULL;

	if (NCryptOpenStorageProvider(&prov, MS_KEY_STORAGE_PROVIDER, 0) != ERROR_SUCCESS)
	{
		return NULL;
	}

	subject.cbData = sizeof(name);
	subject.pbData = name;
	if (NCryptCreatePersistedKey(prov, &key, NCRYPT_ECDSA_P256_ALGORITHM, TLSTEST_PFX_KEY, 0, NCRYPT_OVERWRITE_KEY_FLAG) == ERROR_SUCCESS &&
		NCryptSetProperty(key, NCRYPT_EXPORT_POLICY_PROPERTY, (PBYTE)&policy, sizeof(policy), NCRYPT_PERSIST_FLAG) == ERROR_SUCCESS &&
		NCryptFinalizeKey(key, NCRYPT_SILENT_FLAG) == ERROR_SUCCESS &&
		CertStrToNameW(X509_ASN_ENCODING, TLSTEST_CN, CERT_X500_NAME_STR, NULL, name, &subject.cbData, NULL))
	{
		Zero(&info, sizeof(info));
		info.pwszContainerName = TLSTEST_PFX_KEY;
		info.pwszProvName = (LPWSTR)MS_KEY_STORAGE_PROVIDER;
		Zero(&alg, sizeof(alg));
		alg.pszObjId = szOID_ECDSA_SHA256;
		cert = CertCreateSelfSignCertificate(key, &subject, 0, &info, &alg, NULL, NULL, NULL);
	}

	if (cert != NULL)
	{
		HCERTSTORE store = CertOpenStore(CERT_STORE_PROV_MEMORY, 0, 0, 0, NULL);

		Zero(&pfx, sizeof(pfx));
		if (store != NULL && CertAddCertificateContextToStore(store, cert, CERT_STORE_ADD_ALWAYS, NULL) &&
			PFXExportCertStoreEx(store, &pfx, TLSTEST_PFX_PASS, NULL, EXPORT_PRIVATE_KEYS | REPORT_NOT_ABLE_TO_EXPORT_PRIVATE_KEY) && pfx.cbData != 0)
		{
			pfx.pbData = ZeroMalloc(pfx.cbData);
			if (PFXExportCertStoreEx(store, &pfx, TLSTEST_PFX_PASS, NULL, EXPORT_PRIVATE_KEYS | REPORT_NOT_ABLE_TO_EXPORT_PRIVATE_KEY))
			{
				ret = NewBuf();
				WriteBuf(ret, pfx.pbData, pfx.cbData);
			}
			Free(pfx.pbData);
		}
		if (store != NULL)
		{
			CertCloseStore(store, 0);
		}
		CertFreeCertificateContext(cert);
	}

	// The key of the export goes; the import makes a key of its own
	if (key != 0 && NCryptDeleteKey(key, NCRYPT_SILENT_FLAG) != ERROR_SUCCESS)
	{
		NCryptFreeObject(key);
	}
	NCryptFreeObject(prov);

	return ret;
}

// The provider type of a certificate's key: that of its CSP, 0 for a key of a KSP, INFINITE without key provider
// information
static UINT TlsTestProvType(PCCERT_CONTEXT cert)
{
	DWORD size = 0;
	UINT type = INFINITE;

	if (cert != NULL && CertGetCertificateContextProperty(cert, CERT_KEY_PROV_INFO_PROP_ID, NULL, &size) && size >= sizeof(CRYPT_KEY_PROV_INFO))
	{
		CRYPT_KEY_PROV_INFO *info = ZeroMalloc(size);

		if (CertGetCertificateContextProperty(cert, CERT_KEY_PROV_INFO_PROP_ID, info, &size))
		{
			type = info->dwProvType;
		}
		Free(info);
	}

	return type;
}

// The server certificate's key: one in a legacy CSP is refused, so the question of Schannel and a CSP key does not
// arise; so are a thumbprint that is in no store, a malformed one and no configuration
static void TlsTestServerKeys(TLSTEST_CTX *ctx)
{
	TRANSPORT_TLS_CONFIG cfg;
	char thumbprint[MAX_SIZE];
	UINT scope = 0;

	Print("[the server's certificate key]\n");

	StrCpy(thumbprint, sizeof(thumbprint), "");
	PCCERT_CONTEXT cert = TlsTestCspCert();
	bool have = (cert != NULL && CryptoCertThumbprintStr(cert, thumbprint, sizeof(thumbprint)) && CryptoCertAddToStore(cert, NULL, scope));
	UINT type = TlsTestProvType(cert);
	TlsTestCheck(ctx, have && type == PROV_RSA_AES, "  a certificate in the My store whose key sits in a legacy CSP (the Microsoft Enhanced RSA and AES provider)",
		"made %u, provider type %u", (UINT)have, type);
	if (TlsTestCheck(ctx, have && CryptoCertHasKspKey(cert) == false, "  the crypto module does not take its key for a key of a KSP", "it does"))
	{
		TransportTlsDefaultConfig(&cfg, thumbprint, false);
		TRANSPORT *t = TransportTlsServerNew(&cfg);
		TlsTestCheck(ctx, t == NULL, "  a server transport refuses it: Schannel never meets a CSP key", "the transport opened");
		TransportTlsFree(t);
	}
	if (cert != NULL)
	{
		CryptoCertRemoveFromStore(thumbprint, NULL, scope);
		CryptoCertFree(cert);
	}
	TlsTestCspDelete();

	TransportTlsDefaultConfig(&cfg, TLSTEST_OTHER, false);
	TRANSPORT *missing = TransportTlsServerNew(&cfg);
	TransportTlsDefaultConfig(&cfg, "not a thumbprint", false);
	TRANSPORT *server = TransportTlsServerNew(&cfg);
	TRANSPORT *client = TransportTlsClientNew(&cfg);
	TRANSPORT *none = TransportTlsServerNew(NULL);
	TlsTestCheck(ctx, missing == NULL && server == NULL && client == NULL && none == NULL,
		"  a thumbprint that is in no store, a malformed thumbprint and no configuration are refused", "a transport opened");
	TransportTlsFree(missing);
	TransportTlsFree(server);
	TransportTlsFree(client);
	TransportTlsFree(none);
}

//
// The cases
//

// TLS 1.3 and TLS 1.2: the session comes up bound to the exporter and carries records; the version, the AES-GCM suite
// and, for TLS 1.3, the group that the ServerHello carries
static void TlsTestVersions(TLSTEST_CTX *ctx, TRANSPORT *server, TRANSPORT *client, TRANSPORT *client12, char *what)
{
	TLSTEST_RESULT *r = ZeroMalloc(sizeof(TLSTEST_RESULT));
	UINT group = (CryptoMlKemAvailable() ? CRYPTO_GROUP_X25519MLKEM768 : CRYPTO_GROUP_X25519);
	char tmp[MAX_SIZE];

	Print("[%s: TLS 1.3]\n", what);
	TlsTestRun(server, client, true, r);
	Print("  client: %s, cipher suite 0x%04X, key exchange group 0x%04X%s; server: %s, cipher suite 0x%04X, key exchange group 0x%04X\n",
		TlsTestVersion(r->Client.Version), r->Client.CipherSuite, r->Client.Group, r->Client.Retried ? " after a HelloRetryRequest" : "",
		TlsTestVersion(r->Server.Version), r->Server.CipherSuite, r->Server.Group);
	TlsTestCheck(ctx, r->Dialled && r->Connected && r->ServerAccepted, "  the TLS handshake and the Noise session come up", "dialled %u, connected %u, server %u",
		(UINT)r->Dialled, (UINT)r->Connected, (UINT)r->ServerAccepted);
	TlsTestCheck(ctx, r->Bound, "  the session is bound to the TLS exporter of the stream: no Noise encryption of its own", "it encrypts");
	TlsTestCheck(ctx, r->Echoed && r->Rekeyed, "  records go both ways, and the session updates the outer keys on its schedule while idle", "echoed %u, rekeyed %u",
		(UINT)r->Echoed, (UINT)r->Rekeyed);
	TlsTestCheck(ctx, r->Client.Version == TRANSPORT_TLS_13 && r->Server.Version == TRANSPORT_TLS_13, "  TLS 1.3 on both ends", "client %s, server %s",
		TlsTestVersion(r->Client.Version), TlsTestVersion(r->Server.Version));
	TlsTestCheck(ctx, TlsTestGcm(r->Client.CipherSuite, TRANSPORT_TLS_13) && r->Server.CipherSuite == r->Client.CipherSuite, "  an AES-GCM cipher suite",
		"client 0x%04X, server 0x%04X", r->Client.CipherSuite, r->Server.CipherSuite);
	Format(tmp, sizeof(tmp), "  the ServerHello carries the key exchange group 0x%04X (%s)", group,
		group == CRYPTO_GROUP_X25519MLKEM768 ? "X25519MLKEM768: the OS has ML-KEM" : "X25519: the OS has no ML-KEM");
	TlsTestCheck(ctx, r->Client.Group == group && r->Server.Group == group, tmp, "the client read 0x%04X, the server 0x%04X", r->Client.Group, r->Server.Group);

	if (client12 != NULL)
	{
		Print("[%s: TLS 1.2, for a client that offers it only]\n", what);
		TlsTestRun(server, client12, false, r);
		Print("  client: %s, cipher suite 0x%04X; server: %s, cipher suite 0x%04X\n", TlsTestVersion(r->Client.Version), r->Client.CipherSuite,
			TlsTestVersion(r->Server.Version), r->Server.CipherSuite);
		TlsTestCheck(ctx, r->Dialled && r->Connected && r->Bound && r->Echoed, "  the TLS handshake and the Noise session come up, bound to the exporter, and carry records",
			"dialled %u, connected %u, bound %u, echoed %u", (UINT)r->Dialled, (UINT)r->Connected, (UINT)r->Bound, (UINT)r->Echoed);
		TlsTestCheck(ctx, r->Client.Version == TRANSPORT_TLS_12 && r->Server.Version == TRANSPORT_TLS_12 && TlsTestGcm(r->Client.CipherSuite, TRANSPORT_TLS_12) &&
			r->Server.CipherSuite == r->Client.CipherSuite, "  TLS 1.2 with an AES-GCM suite (ECDHE)", "client %s 0x%04X, server %s 0x%04X",
			TlsTestVersion(r->Client.Version), r->Client.CipherSuite, TlsTestVersion(r->Server.Version), r->Server.CipherSuite);
	}

	Free(r);
}

// The pin and the binding: a client that pins another certificate does not get a stream, and one that computes another
// binding gets one but no Noise session
static void TlsTestPin(TLSTEST_CTX *ctx, TRANSPORT *server, TRANSPORT *pinner, TRANSPORT *breaker)
{
	TLSTEST_RESULT *r = ZeroMalloc(sizeof(TLSTEST_RESULT));

	Print("[the pin and the channel binding]\n");

	TlsTestRun(server, pinner, false, r);
	TlsTestCheck(ctx, r->Dialled == false && r->Connected == false, "  a certificate that the client did not pin is refused", "dialled %u", (UINT)r->Dialled);

	TlsTestRun(server, breaker, false, r);
	TlsTestCheck(ctx, r->Dialled && r->Connected == false && r->ServerAccepted == false,
		"  a mismatched channel binding closes the connection: the TLS handshake completes, the Noise handshake does not", "dialled %u, connected %u, server %u",
		(UINT)r->Dialled, (UINT)r->Connected, (UINT)r->ServerAccepted);

	Free(r);
}

// A TCP connection to a listener of the loopback interface, of a peer that speaks no TLS
static SOCKET TlsTestProber(USHORT port)
{
	struct sockaddr_in sa;
	SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

	if (s == INVALID_SOCKET)
	{
		return INVALID_SOCKET;
	}

	Zero(&sa, sizeof(sa));
	sa.sin_family = AF_INET;
	sa.sin_port = htons(port);
	sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	if (connect(s, (struct sockaddr *)&sa, sizeof(sa)) != 0)
	{
		closesocket(s);
		return INVALID_SOCKET;
	}

	return s;
}

// Whether the server closed a connection within TLSTEST_SHORT: its end, or a reset
static bool TlsTestDropped(SOCKET s)
{
	UINT64 end = Tick64() + TLSTEST_SHORT;
	char buf[256];

	while (Tick64() < end)
	{
		WSAPOLLFD p;

		Zero(&p, sizeof(p));
		p.fd = s;
		p.events = POLLRDNORM;
		if (WSAPoll(&p, 1, 100) > 0 && recv(s, buf, sizeof(buf), 0) <= 0)
		{
			return true;
		}
	}

	return false;
}

// Whether a listen gives no listener; one that it gives is closed
static bool TlsTestNoListener(TRANSPORT *t, char *address)
{
	TRANSPORT_LISTENER *l = TransportListen(t, address);

	TransportCloseListener(l);

	return (l == NULL);
}

// Whether a dial gives no stream; one that it gives is closed
static bool TlsTestNoStream(TRANSPORT *t, char *address, HANDLE cancel)
{
	TRANSPORT_STREAM *s = TransportDial(t, address, cancel);

	TransportClose(s);

	return (s == NULL);
}

// The listener and the dialler on their own, without a Noise session
static void TlsTestListener(TLSTEST_CTX *ctx, TRANSPORT *server, TRANSPORT *client)
{
	char address[TRANSPORT_ADDRESS_SIZE];
	UCHAR *out = ZeroMalloc(TLSTEST_BULK);
	UCHAR *in = ZeroMalloc(TLSTEST_BULK);
	UCHAR byte = 0;

	Print("[the listener and the dialler]\n");

	TRANSPORT_LISTENER *l = TransportListen(server, TLSTEST_LISTEN);
	USHORT port = TransportTlsBoundPort(server);
	if (TlsTestCheck(ctx, l != NULL && port != 0, "  the listener takes an ephemeral port of the loopback interface", "TransportListen failed") == false)
	{
		Free(out);
		Free(in);
		return;
	}
	Format(address, sizeof(address), "127.0.0.1:%u", (UINT)port);

	// Nothing dialled: an Accept returns once its timeout passed
	UINT64 start = Tick64();
	TRANSPORT_STREAM *none = TransportAccept(l, 300);
	TlsTestCheck(ctx, none == NULL && Tick64() - start >= 250, "  an Accept that no client dials returns once its timeout passed", "it returned a stream, or early");
	TransportClose(none);

	// Two peers that speak no TLS: one sends an HTTP request, the other nothing at all. The listener drops the first,
	// and a TLS client that comes while the second still waits connects and is accepted.
	SOCKET http = TlsTestProber(port);
	SOCKET silent = TlsTestProber(port);
	bool sent = (http != INVALID_SOCKET && send(http, TLSTEST_PROBE, StrLen(TLSTEST_PROBE), 0) == (int)StrLen(TLSTEST_PROBE));
	TRANSPORT_STREAM *s = TransportDial(client, address, NULL);
	TRANSPORT_STREAM *a = (s != NULL ? TransportAccept(l, TLSTEST_TIMEOUT) : NULL);
	TlsTestCheck(ctx, silent != INVALID_SOCKET && s != NULL && a != NULL,
		"  a TLS client connects while a peer that sends nothing holds a connection: each handshake runs on its own", "silent %u, dialled %u, accepted %u",
		(UINT)(silent != INVALID_SOCKET), (UINT)(s != NULL), (UINT)(a != NULL));
	TlsTestCheck(ctx, sent && TlsTestDropped(http), "  a peer that sends no TLS (an HTTP request) is dropped", "sent %u", (UINT)sent);

	// The address of the other end of a stream (AUD1-DT-11, #459): the accepted end tells the address that its client came from, which
	// is on the loopback interface and has a port of its own, and the client's end the address that it dialled
	char remote[TRANSPORT_ADDRESS_SIZE];
	bool tells = (a != NULL && TransportRemote(a, remote, sizeof(remote)));
	TlsTestCheck(ctx, tells && StartWith(remote, "127.0.0.1:") && StrCmp(remote, address) != 0,
		"  the accepted end of a connection tells the address of its client, on the loopback interface with a port of its own", "%s: \"%s\"", tells ? "gave" : "gave none", tells ? remote : "");
	tells = (s != NULL && TransportRemote(s, remote, sizeof(remote)));
	TlsTestCheck(ctx, tells && StrCmp(remote, address) == 0, "  the end that dialled tells the address that it dialled", "%s: \"%s\"", tells ? "gave" : "gave none", tells ? remote : "");

	// Many records' worth of bytes in one write, and back
	for (UINT i = 0; i < TLSTEST_BULK; i++)
	{
		out[i] = (UCHAR)(i * 7 + 3);
	}
	bool there = (s != NULL && a != NULL && TransportWrite(s, out, TLSTEST_BULK) && TlsTestReadAll(a, in, TLSTEST_BULK) && Cmp(in, out, TLSTEST_BULK) == 0);
	Zero(in, TLSTEST_BULK);
	bool back = (there && TransportWrite(a, out, TLSTEST_BULK) && TlsTestReadAll(s, in, TLSTEST_BULK) && Cmp(in, out, TLSTEST_BULK) == 0);
	TlsTestCheck(ctx, there && back, "  100000 bytes in one write go through as many records, both ways", "there %u, back %u", (UINT)there, (UINT)back);
	TlsTestCheck(ctx, s != NULL && TransportRekey(s), "  an update of the outer keys does not fail the stream", "it failed");

	// The client closes: the server's end reads the end (the close_notify)
	TransportClose(s);
	UINT got = (a != NULL ? TransportRead(a, &byte, 1, TLSTEST_SHORT) : TRANSPORT_LATER);
	TlsTestCheck(ctx, got == 0, "  the server's end reads the end once the client closed (the close_notify)", "the read gave %u", got);
	TransportClose(a);
	if (http != INVALID_SOCKET)
	{
		closesocket(http);
	}
	if (silent != INVALID_SOCKET)
	{
		closesocket(silent);
	}

	// A stream that nobody accepted goes with its listener: the client reads its end
	s = TransportDial(client, address, NULL);
	SleepThread(300);
	TransportCloseListener(l);
	got = (s != NULL ? TransportRead(s, &byte, 1, TLSTEST_SHORT) : TRANSPORT_LATER);
	TlsTestCheck(ctx, s != NULL && got == 0, "  a stream that nobody accepted goes with its listener: the client reads its end", "dialled %u, the read gave %u",
		(UINT)(s != NULL), got);
	TransportClose(s);

	// Nothing listens on the port any more; a cancelled dial returns at once
	TlsTestCheck(ctx, TlsTestNoStream(client, address, NULL), "  a dial where nothing listens fails", "it gave a stream");
	HANDLE cancel = CreateEventW(NULL, TRUE, TRUE, NULL);
	start = Tick64();
	TlsTestCheck(ctx, cancel != NULL && TlsTestNoStream(client, address, cancel) && Tick64() - start < TLSTEST_SHORT, "  a dial whose cancel is set returns at once",
		"it gave a stream, or it took %I64u ms", Tick64() - start);
	if (cancel != NULL)
	{
		CloseHandle(cancel);
	}

	// Malformed addresses; a client transport does not listen, a server transport does not dial
	TlsTestCheck(ctx, TlsTestNoListener(server, "no-port") && TlsTestNoListener(server, "127.0.0.1:65536") && TlsTestNoListener(server, "127.0.0.1:x") &&
		TlsTestNoListener(client, TLSTEST_LISTEN) && TlsTestNoStream(client, ":443", NULL) && TlsTestNoStream(client, "127.0.0.1:", NULL) &&
		TlsTestNoStream(server, address, NULL), "  malformed addresses, a listen of a client transport and a dial of a server transport fail", "one did not");

	Free(out);
	Free(in);
}

// The fallback list of a client on a network that blocks UDP: its QUIC entry never connects (a loopback transport
// whose dial waits until it is cancelled stands in for it), and the TLS entry connects, wins the race after the
// attempt delay and carries the session
static void TlsTestFallback(TLSTEST_CTX *ctx, TRANSPORT *server, TRANSPORT *client)
{
	TLSTEST_SERVER *srv = ZeroMalloc(sizeof(TLSTEST_SERVER));
	TLSTEST_RESULT *r = ZeroMalloc(sizeof(TLSTEST_RESULT));
	TRANSPORT *blocked = TransportLoopbackNew("quic", INFINITE, false);
	TRANSPORT *known[2] = {blocked, client};
	TRANSPORT_TARGET targets[TRANSPORT_MAX_TARGETS];
	TRANSPORT_RACE race;
	char list[MAX_SIZE];
	USHORT port = 0;

	Print("[the fallback: QUIC blocked, TLS-443 wins]\n");

	Zero(&race, sizeof(race));
	THREAD *thread = TlsTestServe(server, srv, &port);
	Format(list, sizeof(list), "quic:127.0.0.1:%u, tls:127.0.0.1:%u", (UINT)port, (UINT)port);
	UINT num = TransportParseList(list, known, 2, targets, TRANSPORT_MAX_TARGETS);
	TRANSPORT_STREAM *s = (thread != NULL && num == 2 ? TransportRace(targets, num, TRANSPORT_RACE_DELAY, TLSTEST_TIMEOUT, &race) : NULL);
	TlsTestCheck(ctx, s != NULL && race.Winner == 1 && TransportOf(s) == client && race.NumStarted == 2,
		"  of \"quic, tls\" with UDP blocked, the TLS entry wins the race after the attempt delay", "%u entries, winner %u of %u started, %I64u ms", num, race.Winner,
		race.NumStarted, race.Elapsed);

	TlsTestSession(s, srv->Pub, false, r);
	TlsTestCheck(ctx, r->Connected && r->Bound && r->Echoed, "  the session runs over the stream that won", "connected %u, bound %u, echoed %u", (UINT)r->Connected,
		(UINT)r->Bound, (UINT)r->Echoed);

	TlsTestServeEnd(srv, thread);
	TransportLoopbackFree(blocked);
	Free(r);
	Free(srv);
}

// The server thread of the queue case: it reads nothing while the client says so, then a record every TLSTEST_SLOW_READ
// ms at most, then as fast as they come, until the close record
static void TlsTestQueueServerThread(THREAD *thread, void *param)
{
	TLSTEST_QUEUE_SERVER *srv = (TLSTEST_QUEUE_SERVER *)param;
	TRANSPORT_NOISE *n = ZeroMalloc(sizeof(TRANSPORT_NOISE));
	UCHAR *buf = ZeroMalloc(NOISE_MAX_PAYLOAD);
	NOISE_SESSION_CONFIG c;
	UINT last = 0;

	TlsTestConfig(&c, srv->Key, NULL);
	srv->InOrder = true;
	srv->Accepted = TransportNoiseAccept(n, TransportAccept(srv->Listener, TLSTEST_TIMEOUT), &c, TLSTEST_TIMEOUT);
	if (srv->Accepted)
	{
		TransportNoiseAcceptLogin(n);
	}

	while (srv->Accepted)
	{
		LONG pace = InterlockedCompareExchange(&srv->Pace, 0, 0);
		UINT size = 0, seq = 0;

		if (pace == TLSTEST_PAUSE)
		{
			SleepThread(10);
			continue;
		}

		UINT ret = TransportNoiseReceive(n, buf, NOISE_MAX_PAYLOAD, &size, TLSTEST_TIMEOUT);
		if (ret == NOISE_RECEIVE_CLOSE)
		{
			srv->Closed = true;
		}
		if (ret != NOISE_RECEIVE_DATA)
		{
			break;
		}

		Copy(&seq, buf, sizeof(seq));
		if (size != TLSTEST_QUEUE_RECORD || (srv->NumReceived != 0 && seq <= last))
		{
			srv->InOrder = false;
		}
		last = seq;
		srv->NumReceived++;

		if (pace == TLSTEST_SLOW)
		{
			SleepThread(TLSTEST_SLOW_READ);
		}
	}

	TransportNoiseClose(n);
	Free(buf);
	Free(n);
}

// Send data record seq of the queue case, and keep the longest time a Send took (us)
static void TlsTestQueueSend(TRANSPORT_NOISE *n, UCHAR *record, UINT seq, UINT64 *longest)
{
	Copy(record, &seq, sizeof(seq));

	UINT64 start = TransportQueueNow();
	TransportNoiseSend(n, NOISE_RECORD_DATA, record, TLSTEST_QUEUE_RECORD);
	UINT64 took = TransportQueueNow() - start;

	if (took > *longest)
	{
		*longest = took;
	}
}

// The ingress queue of a session over TLS-443 (the TCP-over-TCP amendment of ADR-0022): the server first reads nothing,
// so the stream stalls once its buffers are full and the client's records stand in the queue, while Send keeps
// returning at once; then it reads slowly, so the records that leave the queue waited far longer than the target of
// CoDel, which drops records at the head; then it reads as fast as they come, so the queue empties. Every record that
// the queue let out reaches the server, in order, and every record sent is one that left, one that CoDel dropped or
// one dropped at the limit of the queue.
static void TlsTestQueue(TLSTEST_CTX *ctx, TRANSPORT *server, TRANSPORT *client)
{
	TLSTEST_QUEUE_SERVER *srv = ZeroMalloc(sizeof(TLSTEST_QUEUE_SERVER));
	TRANSPORT_NOISE *n = ZeroMalloc(sizeof(TRANSPORT_NOISE));
	UCHAR *record = ZeroMalloc(TLSTEST_QUEUE_RECORD);
	UCHAR key[NOISE_KEY_SIZE], pub[NOISE_KEY_SIZE];
	char address[TRANSPORT_ADDRESS_SIZE];
	NOISE_SESSION_CONFIG c;
	TRANSPORT_QUEUE_STATUS st;
	UINT64 longest = 0, dropped = 0;
	UINT seq = 0;

	Print("[the ingress queue on TLS-443: a server that reads slower than the client sends]\n");

	Zero(&st, sizeof(st));
	CryptoX25519GenerateKey(srv->Key, srv->Pub);
	CryptoX25519GenerateKey(key, pub);
	TlsTestConfig(&c, key, srv->Pub);
	srv->Pace = TLSTEST_PAUSE;
	srv->Listener = TransportListen(server, TLSTEST_LISTEN);
	THREAD *thread = (srv->Listener != NULL ? NewThread(TlsTestQueueServerThread, srv) : NULL);
	Format(address, sizeof(address), "127.0.0.1:%u", (UINT)TransportTlsBoundPort(server));

	bool connected = (thread != NULL && TransportNoiseConnect(n, TransportDial(client, address, NULL), &c, TLSTEST_TIMEOUT));
	bool queued = (connected && TransportNoiseQueueStatus(n, &st));
	if (TlsTestCheck(ctx, connected && queued, "  the session over TLS-443 has an ingress queue", "connected %u, queue %u", (UINT)connected, (UINT)queued))
	{
		// The server reads nothing: the buffers of the stream fill, and the records stand in the queue
		UINT64 end = Tick64() + TLSTEST_FILL;
		bool standing = false;
		while (standing == false && Tick64() < end)
		{
			TlsTestQueueSend(n, record, seq++, &longest);
			if (seq % 16 == 0)
			{
				SleepThread(1);
				TransportNoiseQueueStatus(n, &st);
				standing = (st.NumRecords >= TLSTEST_STANDING);
			}
		}
		TlsTestCheck(ctx, standing, "  while the server reads nothing, the records stand in the queue and Send keeps returning", "%u records wait after %u sent",
			st.NumRecords, seq);

		// The server reads slowly: the records leave far later than the target, and CoDel drops some at the head
		InterlockedExchange(&srv->Pace, TLSTEST_SLOW);
		end = Tick64() + TLSTEST_SLOW_PHASE;
		while (Tick64() < end)
		{
			TlsTestQueueSend(n, record, seq++, &longest);
			if (seq % 16 == 0)
			{
				SleepThread(1);
			}
		}
		TransportNoiseQueueStatus(n, &st);
		dropped = st.NumDropped;

		// The server reads as fast as the records come: the queue empties
		InterlockedExchange(&srv->Pace, TLSTEST_FAST);
		end = Tick64() + TLSTEST_TIMEOUT;
		do
		{
			SleepThread(10);
			TransportNoiseQueueStatus(n, &st);
		}
		while (st.NumRecords != 0 && Tick64() < end);

		Print("  %u records sent: %I64u left the queue, %I64u dropped by CoDel (%I64u of them while the server read slowly), %I64u at the limit; "
			"the longest Send took %I64u us\n", seq, st.NumPopped, st.NumDropped, dropped, st.NumOverflow, longest);
		TlsTestCheck(ctx, dropped != 0, "  while the server reads slowly, CoDel drops records at the head of the queue", "none dropped");
		TlsTestCheck(ctx, longest < (UINT64)TLSTEST_SEND_MAX * 1000, "  Send never waits for the stream", "the longest took %I64u us", longest);
		TlsTestCheck(ctx, st.NumRecords == 0 && st.NumPushed == seq && st.NumPushed == st.NumPopped + st.NumDropped + st.NumOverflow,
			"  every record sent left the queue, was dropped by CoDel or was dropped at the limit", "%u wait, %I64u pushed", st.NumRecords, st.NumPushed);
	}

	// The close record comes after the records that wait; the server reads it whatever happened before
	InterlockedExchange(&srv->Pace, TLSTEST_FAST);
	TransportNoiseClose(n);
	if (thread != NULL)
	{
		WaitThread(thread, INFINITE);
		ReleaseThread(thread);
	}
	TransportCloseListener(srv->Listener);

	if (connected && queued)
	{
		TlsTestCheck(ctx, srv->Accepted && srv->Closed && srv->InOrder && srv->NumReceived == st.NumPopped,
			"  every record that left the queue reached the server, in order, and the close record after them", "received %I64u of %I64u, in order %u, closed %u",
			srv->NumReceived, st.NumPopped, (UINT)srv->InOrder, (UINT)srv->Closed);
	}

	Zero(key, sizeof(key));
	Zero(srv->Key, sizeof(srv->Key));
	Free(record);
	Free(n);
	Free(srv);
}

// A certificate that a PFX brought: imported into the KSP (CryptoCertImportPfx), put in the store, and served with
// TLS 1.3
static void TlsTestPfxServer(TLSTEST_CTX *ctx)
{
	TRANSPORT_TLS_CONFIG server_cfg, client_cfg;
	TLSTEST_RESULT *r = ZeroMalloc(sizeof(TLSTEST_RESULT));
	char thumbprint[MAX_SIZE];
	UINT scope = 0;

	Print("[a certificate that a PFX brought]\n");

	StrCpy(thumbprint, sizeof(thumbprint), "");
	BUF *pfx = TlsTestPfx();
	PCCERT_CONTEXT cert = (pfx != NULL ? CryptoCertImportPfx(pfx->Buf, pfx->Size, TLSTEST_PFX_PASS, scope) : NULL);
	bool have = (cert != NULL && CryptoCertHasKspKey(cert) && CryptoCertThumbprintStr(cert, thumbprint, sizeof(thumbprint)) && CryptoCertAddToStore(cert, NULL, scope));
	if (TlsTestCheck(ctx, have, "  the PFX is imported, its key into the CNG key storage provider, and the certificate put in the store",
		"pfx %u, imported %u", (UINT)(pfx != NULL), (UINT)(cert != NULL)))
	{
		TransportTlsDefaultConfig(&server_cfg, thumbprint, false);
		TransportTlsDefaultConfig(&client_cfg, thumbprint, false);
		TRANSPORT *server = TransportTlsServerNew(&server_cfg);
		TRANSPORT *client = TransportTlsClientNew(&client_cfg);

		if (TlsTestCheck(ctx, server != NULL && client != NULL, "  the server and client transports open with it", "a transport could not open"))
		{
			TlsTestRun(server, client, false, r);
			TlsTestCheck(ctx, r->Dialled && r->Connected && r->Echoed && r->Client.Version == TRANSPORT_TLS_13 && TlsTestGcm(r->Client.CipherSuite, TRANSPORT_TLS_13),
				"  TLS 1.3 with the KSP key of the PFX, and the session over it", "dialled %u, connected %u, echoed %u, %s 0x%04X", (UINT)r->Dialled,
				(UINT)r->Connected, (UINT)r->Echoed, TlsTestVersion(r->Client.Version), r->Client.CipherSuite);
		}

		TransportTlsFree(client);
		TransportTlsFree(server);
	}

	if (cert != NULL)
	{
		CryptoCertRemoveFromStore(thumbprint, NULL, scope);
		CryptoCertDeleteKey(cert);
		CryptoCertFree(cert);
	}
	FreeBuf(pfx);
	Free(r);
}

RANZ_TEST_TAGS("tls", tls_test, "core", "TLS-443: a client completes a Schannel TLS 1.3 handshake on a test port, the Noise session comes up bound to the TLS exporter; X25519MLKEM768 first where the OS has ML-KEM, AES-GCM only, the server key in the KSP, the pin, the fallback when UDP is blocked (administrator rights).");
void tls_test(UINT num, char **arg)
{
	TLSTEST_CTX *ctx = ZeroMalloc(sizeof(TLSTEST_CTX));
	HANDLE done = CreateEventW(NULL, TRUE, FALSE, NULL);
	HANDLE watchdog = (done != NULL ? CreateThread(NULL, 0, TlsTestWatchdog, done, 0, NULL) : NULL);
	char thumbprint[MAX_SIZE];
	UINT scope = 0;

	Print("TLS test: the TLS transport of the new core on Schannel, its key exchange groups, the Noise session over it, the pin and the binding\n");

	TlsTestHello(ctx);

	if (TlsTestCheck(ctx, CryptoInit(), "the crypto module of the new core runs on CNG", "CryptoInit failed"))
	{
		TlsTestGroups(ctx);
		TlsTestServerKeys(ctx);

		// The server certificate: a self-signed ECDSA P-256 certificate in the current user's My store, its key in the
		// KSP, read by its thumbprint, which the server loads and the clients pin
		StrCpy(thumbprint, sizeof(thumbprint), "");
		PCCERT_CONTEXT cert = CryptoCertCreateSelfSigned(TLSTEST_CN, TLSTEST_SAN, NULL, 30, scope);
		bool have = (cert != NULL && CryptoCertThumbprintStr(cert, thumbprint, sizeof(thumbprint)) && CryptoCertAddToStore(cert, NULL, scope));
		PCCERT_CONTEXT found = (have ? CryptoCertFindByThumbprint(thumbprint, NULL, scope) : NULL);
		TlsTestCheck(ctx, found != NULL && CryptoCertHasKspKey(found), "the server certificate is read from the store by its thumbprint, its key in the CNG key storage provider",
			"CryptoCertCreateSelfSigned, the store or the key failed");
		CryptoCertFree(found);

		if (have)
		{
			TRANSPORT_TLS_CONFIG server_cfg, client_cfg, client12_cfg, pinner_cfg, breaker_cfg;

			TransportTlsDefaultConfig(&server_cfg, thumbprint, false);
			TransportTlsDefaultConfig(&client_cfg, thumbprint, false);
			TransportTlsDefaultConfig(&client12_cfg, thumbprint, false);
			client12_cfg.Versions = TRANSPORT_TLS_12;
			TransportTlsDefaultConfig(&pinner_cfg, TLSTEST_OTHER, false);
			TransportTlsDefaultConfig(&breaker_cfg, thumbprint, false);
			breaker_cfg.BreakBinding = true;

			TRANSPORT *server = TransportTlsServerNew(&server_cfg);
			TRANSPORT *client = TransportTlsClientNew(&client_cfg);
			TRANSPORT *client12 = TransportTlsClientNew(&client12_cfg);
			TRANSPORT *pinner = TransportTlsClientNew(&pinner_cfg);
			TRANSPORT *breaker = TransportTlsClientNew(&breaker_cfg);

			if (TlsTestCheck(ctx, server != NULL && client != NULL && client12 != NULL && pinner != NULL && breaker != NULL,
				"the TLS server and client transports open on Schannel", "a transport could not open"))
			{
				TlsTestVersions(ctx, server, client, client12, "the certificate of the store");
				TlsTestPin(ctx, server, pinner, breaker);
				TlsTestListener(ctx, server, client);
				TlsTestFallback(ctx, server, client);
				TlsTestQueue(ctx, server, client);
				TlsTestPfxServer(ctx);
			}

			TransportTlsFree(breaker);
			TransportTlsFree(pinner);
			TransportTlsFree(client12);
			TransportTlsFree(client);
			TransportTlsFree(server);
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

	if (ctx->NumFailed == 0)
	{
		Print("TLS TEST OK\n");
	}
	else
	{
		Print("TLS TEST FAILED (%u of %u checks failed)\n", ctx->NumFailed, ctx->NumChecks);
	}

	Free(ctx);
}
