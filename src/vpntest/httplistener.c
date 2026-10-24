// httplistener.c
// Named HTTP listener test of REL-6 (#51): the redirect to HTTPS and ACME HTTP-01 on a test port
//
// - One fresh in-process server of the harness (HarnessOpenServer): its test listener on TCP 39555 (HARNESS_PORT) is
//   the only enabled VPN listener, so a redirect names :39555. The HTTP listener runs on HTTPLISTENER_PORT, never on 80.
// - The checks read admin RPC results (GetHttpListener, SetHttpListener, ListenerCreate), the bytes of the HTTP answers on
//   the wire and connect success or failure. The one log check is the line of a served challenge in the server log file,
//   which is the contract with the operator.
// - The test opens many connections from 127.0.0.1 in a short time, so it turns the per-source DoS guard of the listeners
//   off after every server start (DisableDosProtect); the start turns it on again.
// - The pure responder (HttpListenerRespond) also gets direct cases for the port of the redirect.
// It prints "HTTPLISTENER TEST OK" only when every check passes.

#include "harness_int.h"
#include "testlist.h"

#include "Cedar/Admin.h"
#include "Cedar/Cedar.h"
#include "Cedar/Connection.h"
#include "Cedar/HttpListener.h"
#include "Cedar/Listener.h"
#include "Cedar/Server.h"

#include "Mayaqua/Encrypt.h"
#include "Mayaqua/FileIO.h"
#include "Mayaqua/HTTP.h"
#include "Mayaqua/Internat.h"
#include "Mayaqua/Kernel.h"
#include "Mayaqua/Memory.h"
#include "Mayaqua/Network.h"
#include "Mayaqua/Str.h"
#include "Mayaqua/Tick64.h"

#define	HTTPLISTENER_PORT			39570				// The HTTP listener of the test
#define	HTTPLISTENER_PORT_HELD		39571				// Held by the test with the server's own bind: the server cannot bind it
#define	HTTPLISTENER_PORT_VPN_OFF	39572				// A disabled VPN listener
#define	HTTPLISTENER_HOST			"example.test"		// Host header of the requests
#define	HTTPLISTENER_PATH			"/some/path?x=1&y=2"	// Target of the redirect requests: a path with a query
#define	HTTPLISTENER_RECV_TIMEOUT	15000				// Receive timeout of a test connection (ms), over HTTP_LISTENER_TIMEOUT
#define	HTTPLISTENER_IDLE_MIN		8000				// The server closes a connection without a request not before this (ms)
#define	HTTPLISTENER_BIND_TIMEOUT	(LISTEN_RETRY_TIME * 3)	// A listener binds a free port, or lets one go, within this (ms)
#define	HTTPLISTENER_LOG_TIMEOUT	10000				// The line of a served challenge reaches the server log file within this (ms)
#define	HTTPLISTENER_POLL			50					// Poll interval (ms)
#define	HTTPLISTENER_WATCHDOG_LIMIT	180000				// "httplistener" process aborted after this (ms)

// State of the test
typedef struct HTTPLISTENER_TEST
{
	HARNESS *H;
	UINT NumAnswers;			// HTTP answers read
	UINT NumNamed;				// Answers that name the product
	char Token[64];				// Token of the challenge file
	char Content[128];			// First content of the challenge file
} HTTPLISTENER_TEST;

// A TLS 1.2 ClientHello with one cipher suite and no extension; no byte is a line feed
static UCHAR httplistener_client_hello[] =
{
	0x16, 0x03, 0x01, 0x00, 0x2f,		// Record: handshake, TLS 1.0, 47 bytes
	0x01, 0x00, 0x00, 0x2b,				// ClientHello, 43 bytes
	0x03, 0x03,							// TLS 1.2
	0x01, 0x08, 0x0f, 0x16, 0x1d, 0x24, 0x2b, 0x32,		// Random
	0x39, 0x40, 0x47, 0x4e, 0x55, 0x5c, 0x63, 0x6a,
	0x71, 0x78, 0x7f, 0x86, 0x8d, 0x94, 0x9b, 0xa2,
	0xa9, 0xb0, 0xb7, 0xbe, 0xc5, 0xcc, 0xd3, 0xda,
	0x00,								// No session ID
	0x00, 0x02, 0x13, 0x01,				// One cipher suite: TLS_AES_128_GCM_SHA256
	0x01, 0x00,							// Null compression
	0x00, 0x00,							// No extension
};

// Random hex digits: they cannot spell the product name
static void HttpTestRandomHex(char *str, UINT size, UINT num_bytes)
{
	UCHAR bytes[32];

	num_bytes = MIN(num_bytes, (UINT)sizeof(bytes));
	Rand(bytes, num_bytes);
	BinToStr(str, size, bytes, num_bytes);
}

// Connect to the HTTP listener and send data; NULL when the connect fails
static SOCK *HttpTestOpen(char *addr, UINT port, void *data, UINT size)
{
	SOCK *s = Connect(addr, port);

	if (s == NULL)
	{
		return NULL;
	}

	SetTimeout(s, HTTPLISTENER_RECV_TIMEOUT);

	if (size != 0)
	{
		SendAll(s, data, size, false);
	}

	return s;
}

// Read an answer until the server closes the connection or the receive timeout ends, and close the socket. *closed
// tells that the server closed it before the timeout, *elapsed the time from start (ms)
static BUF *HttpTestReadAll(SOCK *s, UINT64 start, bool *closed, UINT64 *elapsed)
{
	BUF *b = NewBuf();
	UCHAR tmp[4096];

	while (true)
	{
		UINT size = Recv(s, tmp, sizeof(tmp), false);

		if (size == 0 || size == SOCK_LATER)
		{
			break;
		}

		WriteBuf(b, tmp, size);
	}

	*elapsed = Tick64() - start;
	*closed = (*elapsed < HTTPLISTENER_RECV_TIMEOUT);

	Disconnect(s);
	ReleaseSock(s);

	SeekBufToBegin(b);

	return b;
}

// Whether an answer names the product (CEDAR_PRODUCT_STR or SoftEther, in any case); counted for the final check
static void HttpTestCountNamed(HTTPLISTENER_TEST *t, BUF *b)
{
	t->NumAnswers++;

	if (SearchAsciiInBinary(b->Buf, b->Size, CEDAR_PRODUCT_STR, false) != INFINITE ||
		SearchAsciiInBinary(b->Buf, b->Size, "SoftEther", false) != INFINITE)
	{
		t->NumNamed++;
	}
}

// Send a request (its whole text) to the HTTP listener at addr and read the answer; NULL when the connect fails
static BUF *HttpTestExchange(HTTPLISTENER_TEST *t, char *addr, UINT port, char *request)
{
	bool closed;
	UINT64 elapsed;
	UINT64 start = Tick64();

	SOCK *s = HttpTestOpen(addr, port, request, StrLen(request));
	if (s == NULL)
	{
		return NULL;
	}

	BUF *b = HttpTestReadAll(s, start, &closed, &elapsed);
	HttpTestCountNamed(t, b);

	return b;
}

// The status code of an answer: 0 when it does not begin with an HTTP/1.1 status line
static UINT HttpTestStatus(BUF *b)
{
	char tmp[16];

	if (b == NULL || b->Size < 12 || Cmp(b->Buf, "HTTP/1.1 ", 9) != 0)
	{
		return 0;
	}

	Copy(tmp, (UCHAR *)b->Buf + 9, 3);
	tmp[3] = 0;

	return ToInt(tmp);
}

// The length of the header part of an answer, its blank line included; 0 when it has none
static UINT HttpTestHeaderSize(BUF *b)
{
	if (b == NULL)
	{
		return 0;
	}

	UINT pos = SearchAsciiInBinary(b->Buf, b->Size, "\r\n\r\n", true);

	return (pos == INFINITE ? 0 : pos + 4);
}

// The value of the header name in an answer, into value; false when the answer has no such header
static bool HttpTestHeader(BUF *b, char *name, char *value, UINT size)
{
	UINT header_size = HttpTestHeaderSize(b);
	char line_start[MAX_SIZE];
	bool ret = false;

	if (header_size == 0)
	{
		return false;
	}

	char *text = ZeroMalloc(header_size + 1);
	Copy(text, b->Buf, header_size);

	Format(line_start, sizeof(line_start), "\r\n%s: ", name);
	UINT pos = SearchStrEx(text, line_start, 0, false);

	if (pos != INFINITE)
	{
		char *v = text + pos + StrLen(line_start);
		UINT end = SearchStrEx(v, "\r\n", 0, true);

		if (end != INFINITE)
		{
			v[end] = 0;
			StrCpy(value, size, v);
			ret = true;
		}
	}

	Free(text);

	return ret;
}

// Whether the body of an answer is exactly size bytes of data
static bool HttpTestBodyIs(BUF *b, void *data, UINT size)
{
	UINT header_size = HttpTestHeaderSize(b);

	return (header_size != 0 && b->Size - header_size == size && Cmp((UCHAR *)b->Buf + header_size, data, size) == 0);
}

// One request on IPv4 loopback and the checks of its answer: the status, the Location (when location is not NULL) and,
// for any status but 200, Content-Length 0 and no body
static void HttpTestExpect(HTTPLISTENER_TEST *t, char *what, char *request, UINT status, char *location)
{
	char tmp[MAX_SIZE * 2];
	char value[MAX_SIZE];

	BUF *b = HttpTestExchange(t, "127.0.0.1", HTTPLISTENER_PORT, request);
	UINT got = HttpTestStatus(b);

	Format(tmp, sizeof(tmp), "%s: status %u (expected %u)", what, got, status);
	bool ok = HarnessCheck(t->H, got == status, tmp);

	if (ok && location != NULL)
	{
		value[0] = 0;
		HttpTestHeader(b, "Location", value, sizeof(value));
		Format(tmp, sizeof(tmp), "%s: Location %s (expected %s)", what, value, location);
		HarnessCheck(t->H, StrCmp(value, location) == 0, tmp);
	}

	if (ok && status != 200)
	{
		value[0] = 0;
		HttpTestHeader(b, "Content-Length", value, sizeof(value));
		Format(tmp, sizeof(tmp), "%s: Content-Length 0 and no body", what);
		HarnessCheck(t->H, StrCmp(value, "0") == 0 && HttpTestBodyIs(b, NULL, 0), tmp);
	}

	FreeBuf(b);
}

// Read the HTTP listener setting through GetHttpListener
static bool HttpTestGet(HTTPLISTENER_TEST *t, RPC_HTTP_LISTENER *g)
{
	Zero(g, sizeof(RPC_HTTP_LISTENER));

	return (ScGetHttpListener(t->H->Rpc, g) == ERR_NO_ERROR);
}

// SetHttpListener: on (port 0: the saved port) or off
static UINT HttpTestSet(HTTPLISTENER_TEST *t, bool enabled, UINT port)
{
	RPC_HTTP_LISTENER s;

	Zero(&s, sizeof(s));
	s.Enabled = enabled;
	s.Port = port;

	return ScSetHttpListener(t->H->Rpc, &s);
}

// Check the setting that GetHttpListener reports; with listening, wait until it reports it within the bind time
static void HttpTestExpectGet(HTTPLISTENER_TEST *t, char *what, bool enabled, UINT port, bool listening)
{
	RPC_HTTP_LISTENER g;
	UINT64 end = Tick64() + (UINT64)HTTPLISTENER_BIND_TIMEOUT;
	bool ok;
	char tmp[MAX_SIZE];

	while (true)
	{
		ok = HttpTestGet(t, &g);

		if (ok == false || listening == false || g.Listening || Tick64() >= end)
		{
			break;
		}

		SleepThread(HTTPLISTENER_POLL);
	}

	Format(tmp, sizeof(tmp), "%s: GetHttpListener reports %s, port %u, %s (got %s, port %u, %s)", what,
		enabled ? "on" : "off", port, listening ? "listening" : "not listening",
		g.Enabled ? "on" : "off", g.Port, g.Listening ? "listening" : "not listening");
	HarnessCheck(t->H, ok && g.Enabled == enabled && g.Port == port && g.Listening == listening, tmp);
}

// Whether a TCP connect to port on 127.0.0.1 succeeds
static bool HttpTestCanConnect(UINT port)
{
	SOCK *s = Connect("127.0.0.1", port);

	if (s == NULL)
	{
		return false;
	}

	Disconnect(s);
	ReleaseSock(s);

	return true;
}

// The path of a challenge file of the webroot
static void HttpTestChallengePath(char *path, UINT size, char *token)
{
	Format(path, size, "%s/%s", HTTP_LISTENER_CHALLENGE_DIR, token);
}

// Write a challenge file of the webroot
static bool HttpTestWriteChallenge(HTTPLISTENER_TEST *t, char *token, void *data, UINT size)
{
	char path[MAX_PATH];
	char tmp[MAX_SIZE];

	HttpTestChallengePath(path, sizeof(path), token);

	BUF *b = NewBufFromMemory(data, size);
	bool ok = DumpBuf(b, path);
	FreeBuf(b);

	Format(tmp, sizeof(tmp), "challenge file of %u bytes written into the webroot", size);

	return HarnessCheck(t->H, ok, tmp);
}

// A GET and a HEAD of a challenge: 200, its bytes, Content-Type text/plain and its Content-Length, no body for HEAD
static void HttpTestExpectChallenge(HTTPLISTENER_TEST *t, char *what, char *token, char *query, char *content)
{
	char request[MAX_SIZE];
	char tmp[MAX_SIZE * 2];
	char value[MAX_SIZE];
	UINT len = StrLen(content);

	Format(request, sizeof(request), "GET %s%s%s HTTP/1.1\r\nHost: " HTTPLISTENER_HOST "\r\n\r\n",
		HTTP_LISTENER_CHALLENGE_PREFIX, token, query);
	BUF *b = HttpTestExchange(t, "127.0.0.1", HTTPLISTENER_PORT, request);

	Format(tmp, sizeof(tmp), "%s: GET gives 200 and the exact bytes of the file", what);
	HarnessCheck(t->H, HttpTestStatus(b) == 200 && HttpTestBodyIs(b, content, len), tmp);

	value[0] = 0;
	HttpTestHeader(b, "Content-Type", value, sizeof(value));
	Format(tmp, sizeof(tmp), "%s: Content-Type text/plain (got %s)", what, value);
	HarnessCheck(t->H, StrCmp(value, "text/plain") == 0, tmp);
	FreeBuf(b);

	Format(request, sizeof(request), "HEAD %s%s%s HTTP/1.1\r\nHost: " HTTPLISTENER_HOST "\r\n\r\n",
		HTTP_LISTENER_CHALLENGE_PREFIX, token, query);
	b = HttpTestExchange(t, "127.0.0.1", HTTPLISTENER_PORT, request);

	value[0] = 0;
	HttpTestHeader(b, "Content-Length", value, sizeof(value));
	Format(tmp, sizeof(tmp), "%s: HEAD gives 200, Content-Length %u (got %s) and no body", what, len, value);
	HarnessCheck(t->H, HttpTestStatus(b) == 200 && ToInt(value) == len && IsNum(value) && HttpTestBodyIs(b, NULL, 0),
		tmp);
	FreeBuf(b);
}

// A GET under the challenge prefix with the token token: 404, never a redirect
static void HttpTestExpectNoChallenge(HTTPLISTENER_TEST *t, char *what, char *token)
{
	char request[MAX_SIZE * 2];

	Format(request, sizeof(request), "GET %s%s HTTP/1.1\r\nHost: " HTTPLISTENER_HOST "\r\n\r\n",
		HTTP_LISTENER_CHALLENGE_PREFIX, token);
	HttpTestExpect(t, what, request, 404, NULL);
}

// The line of the server log files that holds str, into line; false when no file has it yet
static bool HttpTestFindLogLine(char *str, char *line, UINT size)
{
	char exe_dir[MAX_PATH];
	char dir[MAX_PATH];
	char path[MAX_PATH];
	bool ret = false;

	GetExeDir(exe_dir, sizeof(exe_dir));
	Format(dir, sizeof(dir), "%s/%s", exe_dir, SERVER_LOG_DIR);

	DIRLIST *d = EnumDir(dir);
	if (d == NULL)
	{
		return false;
	}

	for (UINT i = 0;i < d->NumFiles && ret == false;i++)
	{
		DIRENT *e = d->File[i];

		if (e->Folder || StartWith(e->FileName, SERVER_LOG_PERFIX) == false)
		{
			continue;
		}

		// The log writer keeps the file open for writing: read it without the read lock
		Format(path, sizeof(path), "%s/%s", dir, e->FileName);
		wchar_t *path_w = CopyStrToUni(path);
		BUF *b = ReadDumpExW(path_w, false, 0);
		Free(path_w);
		if (b == NULL)
		{
			continue;
		}

		char *text = ZeroMalloc(b->Size + 1);
		Copy(text, b->Buf, b->Size);

		UINT pos = SearchStrEx(text, str, 0, true);
		if (pos != INFINITE)
		{
			UINT start = pos;
			UINT end = pos;

			while (start > 0 && text[start - 1] != '\n')
			{
				start--;
			}
			while (text[end] != 0 && text[end] != '\r' && text[end] != '\n')
			{
				end++;
			}

			text[end] = 0;
			StrCpy(line, size, text + start);
			ret = true;
		}

		Free(text);
		FreeBuf(b);
	}

	FreeDir(d);

	return ret;
}

// Defaults and the start on the test port: IPv4 and IPv6 loopback connect
static void HttpTestStart(HTTPLISTENER_TEST *t)
{
	char request[MAX_SIZE];
	char tmp[MAX_SIZE];

	Print("[defaults]\n");
	HarnessSetPhase("httplistener", "defaults");
	HttpTestExpectGet(t, "a fresh server", false, HTTP_LISTENER_DEFAULT_PORT, false);
	HarnessCheck(t->H, HttpTestCanConnect(HTTPLISTENER_PORT) == false, "nothing listens on the test port");

	Print("[enable on TCP %u]\n", HTTPLISTENER_PORT);
	HarnessSetPhase("httplistener", "enable");
	HarnessCheckErr(t->H, HttpTestSet(t, true, HTTPLISTENER_PORT), "SetHttpListener on the test port");
	HttpTestExpectGet(t, "after the enable", true, HTTPLISTENER_PORT, true);

	Format(request, sizeof(request), "GET / HTTP/1.1\r\nHost: " HTTPLISTENER_HOST "\r\n\r\n");

	BUF *b = HttpTestExchange(t, "127.0.0.1", HTTPLISTENER_PORT, request);
	Format(tmp, sizeof(tmp), "a request over IPv4 loopback (127.0.0.1:%u) gets an HTTP answer", HTTPLISTENER_PORT);
	HarnessCheck(t->H, HttpTestStatus(b) == 301, tmp);
	FreeBuf(b);

	b = HttpTestExchange(t, "::1", HTTPLISTENER_PORT, request);
	Format(tmp, sizeof(tmp), "a request over IPv6 loopback ([::1]:%u) gets an HTTP answer", HTTPLISTENER_PORT);
	HarnessCheck(t->H, HttpTestStatus(b) == 301, tmp);
	FreeBuf(b);
}

// The port of a redirect, as the pure responder computes it from the enabled VPN listener ports
static void HttpTestRedirectPortCase(HTTPLISTENER_TEST *t, char *what, UINT *ports, UINT num_ports, char *expected)
{
	char tmp[MAX_SIZE * 2];
	HTTP_HEADER *h = NewHttpHeader("GET", "/a?b", "HTTP/1.1");

	AddHttpValue(h, NewHttpValue("Host", HTTPLISTENER_HOST ":8080"));

	HTTP_LISTENER_RESPONSE *r = HttpListenerRespond(h, NULL, NULL, ports, num_ports);

	Format(tmp, sizeof(tmp), "responder, %s: 301 to %s (got %u, %s)", what, expected, r->Status,
		r->Location == NULL ? "no Location" : r->Location);
	HarnessCheck(t->H, r->Status == 301 && StrCmp(r->Location, expected) == 0, tmp);

	FreeHttpListenerResponse(r);
	FreeHttpHeader(h);
}

// Redirects: path and query kept, the port of the VPN listener, the Host port dropped, IPv6 brackets kept, HEAD, a VPN
// listener on 443
static void HttpTestRedirects(HTTPLISTENER_TEST *t)
{
	RPC_LISTENER d;
	UINT ports_5555[] = {39555, 5555};
	UINT ports_443[] = {39555, 443};
	char location[MAX_SIZE];

	Print("[redirect]\n");
	HarnessSetPhase("httplistener", "redirect");

	Format(location, sizeof(location), "https://" HTTPLISTENER_HOST ":%u" HTTPLISTENER_PATH, HARNESS_PORT);
	HttpTestExpect(t, "GET with a query", "GET " HTTPLISTENER_PATH " HTTP/1.1\r\nHost: " HTTPLISTENER_HOST "\r\n\r\n",
		301, location);
	HttpTestExpect(t, "GET, Host with a port",
		"GET " HTTPLISTENER_PATH " HTTP/1.1\r\nHost: " HTTPLISTENER_HOST ":8080\r\n\r\n", 301, location);
	HttpTestExpect(t, "HEAD", "HEAD " HTTPLISTENER_PATH " HTTP/1.1\r\nHost: " HTTPLISTENER_HOST "\r\n\r\n", 301,
		location);
	HttpTestExpect(t, "HTTP/1.0 GET", "GET " HTTPLISTENER_PATH " HTTP/1.0\r\nHost: " HTTPLISTENER_HOST "\r\n\r\n", 301,
		location);

	Format(location, sizeof(location), "https://[2001:db8::1]:%u" HTTPLISTENER_PATH, HARNESS_PORT);
	HttpTestExpect(t, "GET, IPv6 literal Host with a port",
		"GET " HTTPLISTENER_PATH " HTTP/1.1\r\nHost: [2001:db8::1]:8080\r\n\r\n", 301, location);
	HttpTestExpect(t, "GET, IPv6 literal Host", "GET " HTTPLISTENER_PATH " HTTP/1.1\r\nHost: [2001:db8::1]\r\n\r\n",
		301, location);

	Format(location, sizeof(location), "https://192.0.2.1:%u/", HARNESS_PORT);
	HttpTestExpect(t, "GET, IPv4 literal Host", "GET / HTTP/1.1\r\nHost: 192.0.2.1\r\n\r\n", 301, location);

	// A VPN listener entry on 443: the redirect names no port, whether the server could bind 443 or not
	Zero(&d, sizeof(d));
	d.Port = HTTP_LISTENER_HTTPS_PORT;
	d.Enable = true;
	UINT err = ScCreateListener(t->H->Rpc, &d);
	if (HarnessCheck(t->H, err == ERR_NO_ERROR || err == ERR_LISTENER_BIND_FAILED, "ListenerCreate 443"))
	{
		HttpTestExpect(t, "GET with a VPN listener on 443",
			"GET " HTTPLISTENER_PATH " HTTP/1.1\r\nHost: " HTTPLISTENER_HOST "\r\n\r\n", 301,
			"https://" HTTPLISTENER_HOST HTTPLISTENER_PATH);

		Zero(&d, sizeof(d));
		d.Port = HTTP_LISTENER_HTTPS_PORT;
		HarnessCheckErr(t->H, ScDeleteListener(t->H->Rpc, &d), "ListenerDelete 443");
	}

	HttpTestRedirectPortCase(t, "VPN listeners on 39555 and 5555", ports_5555, 2,
		"https://" HTTPLISTENER_HOST ":5555/a?b");
	HttpTestRedirectPortCase(t, "VPN listeners on 39555 and 443", ports_443, 2, "https://" HTTPLISTENER_HOST "/a?b");
	HttpTestRedirectPortCase(t, "no enabled VPN listener", NULL, 0, "https://" HTTPLISTENER_HOST "/a?b");
}

// ACME HTTP-01: a challenge served with its bytes, HEAD, a query, tokens that never reach a file, the size limit, a
// changed file, and the log line of a served challenge
static void HttpTestAcme(HTTPLISTENER_TEST *t)
{
	char token2[64];
	char token3[64];
	char content2[MAX_SIZE];
	char long_token[HTTP_LISTENER_TOKEN_MAX_LEN + 2];
	char path[MAX_PATH];
	char line[MAX_SIZE * 2];
	char tmp[MAX_SIZE * 3];
	char rand_part[64];
	UCHAR big[HTTP_LISTENER_CHALLENGE_MAX_SIZE + 1];

	Print("[ACME HTTP-01]\n");
	HarnessSetPhase("httplistener", "acme");

	HttpTestRandomHex(t->Token, sizeof(t->Token), 21);
	HttpTestRandomHex(rand_part, sizeof(rand_part), 21);
	Format(t->Content, sizeof(t->Content), "%s.%s", t->Token, rand_part);

	if (HttpTestWriteChallenge(t, t->Token, t->Content, StrLen(t->Content)))
	{
		HttpTestExpectChallenge(t, "challenge", t->Token, "", t->Content);
		HttpTestExpectChallenge(t, "challenge with a query", t->Token, "?x=1", t->Content);

		// The log line of a served challenge: its token and the source address
		UINT64 end = Tick64() + (UINT64)HTTPLISTENER_LOG_TIMEOUT;
		bool found;
		while ((found = HttpTestFindLogLine(t->Token, line, sizeof(line))) == false && Tick64() < end)
		{
			SleepThread(HTTPLISTENER_POLL);
		}
		Format(tmp, sizeof(tmp), "the server log has a line with the token and the source address 127.0.0.1 (%s)",
			found ? line : "no line");
		HarnessCheck(t->H, found && InStr(line, "127.0.0.1"), tmp);

		// A file changed between two requests is served with its new content
		Format(content2, sizeof(content2), "%s.changed-%s", t->Token, rand_part);
		if (HttpTestWriteChallenge(t, t->Token, content2, StrLen(content2)))
		{
			HttpTestExpectChallenge(t, "changed challenge", t->Token, "", content2);
		}
	}

	HttpTestRandomHex(token2, sizeof(token2), 21);
	HttpTestExpectNoChallenge(t, "unknown token", token2);
	HttpTestExpectNoChallenge(t, "token ..", "..");
	HttpTestExpectNoChallenge(t, "token %2e%2e", "%2e%2e");
	Format(tmp, sizeof(tmp), "%s/x", t->Token);
	HttpTestExpectNoChallenge(t, "token with a slash", tmp);
	Format(tmp, sizeof(tmp), "%s\\x", t->Token);
	HttpTestExpectNoChallenge(t, "token with a backslash", tmp);
	HttpTestExpectNoChallenge(t, "empty token", "");
	HttpTestExpectNoChallenge(t, "device name token NUL", "NUL");
	Zero(long_token, sizeof(long_token));
	for (UINT i = 0;i < HTTP_LISTENER_TOKEN_MAX_LEN + 1;i++)
	{
		long_token[i] = 'a';
	}
	HttpTestExpectNoChallenge(t, "token of 256 characters", long_token);

	// The size limit: a file of HTTP_LISTENER_CHALLENGE_MAX_SIZE bytes is served, one byte more is not
	HttpTestRandomHex(token3, sizeof(token3), 21);
	for (UINT i = 0;i < sizeof(big);i++)
	{
		big[i] = 'a' + (i % 26);
	}
	big[sizeof(big) - 1] = 0;
	if (HttpTestWriteChallenge(t, token3, big, HTTP_LISTENER_CHALLENGE_MAX_SIZE))
	{
		HttpTestExpectChallenge(t, "challenge of 1 KiB", token3, "", (char *)big);
	}
	big[sizeof(big) - 1] = 'z';
	if (HttpTestWriteChallenge(t, token3, big, sizeof(big)))
	{
		HttpTestExpectNoChallenge(t, "challenge file over 1 KiB", token3);
	}

	HttpTestChallengePath(path, sizeof(path), token3);
	FileDelete(path);
}

// Requests that get 405 or 400
static void HttpTestErrors(HTTPLISTENER_TEST *t)
{
	char value[MAX_SIZE];
	char tmp[MAX_SIZE * 2];

	Print("[errors]\n");
	HarnessSetPhase("httplistener", "errors");

	BUF *b = HttpTestExchange(t, "127.0.0.1", HTTPLISTENER_PORT,
		"POST / HTTP/1.1\r\nHost: " HTTPLISTENER_HOST "\r\nContent-Length: 0\r\n\r\n");
	value[0] = 0;
	HttpTestHeader(b, "Allow", value, sizeof(value));
	Format(tmp, sizeof(tmp), "POST: 405 with an Allow header listing GET and HEAD (got %u, Allow %s)",
		HttpTestStatus(b), value);
	HarnessCheck(t->H, HttpTestStatus(b) == 405 && InStrEx(value, "GET", true) && InStrEx(value, "HEAD", true), tmp);
	FreeBuf(b);

	HttpTestExpect(t, "request line without a version", "GET /\r\nHost: " HTTPLISTENER_HOST "\r\n\r\n", 400, NULL);
	HttpTestExpect(t, "request line with a fourth word",
		"GET / HTTP/1.1 more\r\nHost: " HTTPLISTENER_HOST "\r\n\r\n", 400, NULL);
	HttpTestExpect(t, "request line with another version", "GET / FTP/1.1\r\nHost: " HTTPLISTENER_HOST "\r\n\r\n",
		400, NULL);
	HttpTestExpect(t, "missing Host", "GET / HTTP/1.1\r\nAccept: */*\r\n\r\n", 400, NULL);
	HttpTestExpect(t, "repeated Host",
		"GET / HTTP/1.1\r\nHost: " HTTPLISTENER_HOST "\r\nHost: other.test\r\n\r\n", 400, NULL);
	HttpTestExpect(t, "Host with @", "GET / HTTP/1.1\r\nHost: user@" HTTPLISTENER_HOST "\r\n\r\n", 400, NULL);
	HttpTestExpect(t, "Host with /", "GET / HTTP/1.1\r\nHost: " HTTPLISTENER_HOST "/x\r\n\r\n", 400, NULL);
	HttpTestExpect(t, "Host with a control character", "GET / HTTP/1.1\r\nHost: exa\x01mple.test\r\n\r\n", 400, NULL);
	HttpTestExpect(t, "Host with a bad port", "GET / HTTP/1.1\r\nHost: " HTTPLISTENER_HOST ":8x\r\n\r\n", 400, NULL);
	HttpTestExpect(t, "absolute-form target",
		"GET http://" HTTPLISTENER_HOST "/ HTTP/1.1\r\nHost: " HTTPLISTENER_HOST "\r\n\r\n", 400, NULL);
}

// A connection without a request is closed after the request timeout; TLS ClientHello bytes get 400 or a close, never a
// TLS answer. Both connections wait at the same time
static void HttpTestSilent(HTTPLISTENER_TEST *t)
{
	char tmp[MAX_SIZE];
	bool closed;
	UINT64 elapsed;

	Print("[no request, TLS ClientHello]\n");
	HarnessSetPhase("httplistener", "no request");

	UINT64 start = Tick64();
	SOCK *idle = HttpTestOpen("127.0.0.1", HTTPLISTENER_PORT, NULL, 0);
	SOCK *tls = HttpTestOpen("127.0.0.1", HTTPLISTENER_PORT, httplistener_client_hello, sizeof(httplistener_client_hello));

	if (HarnessCheck(t->H, idle != NULL, "connect without a request") == false)
	{
		if (tls != NULL)
		{
			Disconnect(tls);
			ReleaseSock(tls);
		}
		return;
	}

	BUF *b = HttpTestReadAll(idle, start, &closed, &elapsed);
	HttpTestCountNamed(t, b);
	Format(tmp, sizeof(tmp), "no request within %u ms: the server closes the connection without an answer (after %I64u ms)",
		HTTP_LISTENER_TIMEOUT, elapsed);
	HarnessCheck(t->H, closed && b->Size == 0 && elapsed >= HTTPLISTENER_IDLE_MIN, tmp);
	FreeBuf(b);

	if (HarnessCheck(t->H, tls != NULL, "connect with TLS ClientHello bytes"))
	{
		b = HttpTestReadAll(tls, start, &closed, &elapsed);
		HttpTestCountNamed(t, b);
		Format(tmp, sizeof(tmp), "TLS ClientHello bytes get 400 or a close, never a TLS answer (%u bytes, status %u)",
			b->Size, HttpTestStatus(b));
		HarnessCheck(t->H, closed && (b->Size == 0 || HttpTestStatus(b) == 400), tmp);
		FreeBuf(b);
	}
}

// The HTTP port is not a VPN port: an admin RPC connection to it fails
static void HttpTestNotVpn(HTTPLISTENER_TEST *t)
{
	CLIENT_OPTION o;
	UCHAR hashed_password[SHA1_SIZE];
	UINT err = ERR_NO_ERROR;
	char tmp[MAX_SIZE];

	Print("[not a VPN port]\n");
	HarnessSetPhase("httplistener", "not a VPN port");

	Zero(&o, sizeof(o));
	UniStrCpy(o.AccountName, sizeof(o.AccountName), L"HTTPLISTENER_ADMIN");
	StrCpy(o.Hostname, sizeof(o.Hostname), "127.0.0.1");
	o.Port = HTTPLISTENER_PORT;
	o.ProxyType = PROXY_DIRECT;
	Sha0(hashed_password, "", 0);

	RPC *rpc = AdminConnectEx(t->H->ClientCedar, &o, NULL, hashed_password, &err, NULL);

	Format(tmp, sizeof(tmp), "an admin RPC connection to the HTTP listener port fails (error %u)", err);
	HarnessCheck(t->H, rpc == NULL && err != ERR_NO_ERROR, tmp);

	if (rpc != NULL)
	{
		AdminDisconnect(rpc);
	}
}

// Port conflicts with the VPN listeners, both ways
static void HttpTestConflicts(HTTPLISTENER_TEST *t)
{
	RPC_LISTENER d;

	Print("[conflicts]\n");
	HarnessSetPhase("httplistener", "conflicts");

	HarnessCheck(t->H, HttpTestSet(t, true, HARNESS_PORT) == ERR_LISTENER_ALREADY_EXISTS,
		"SetHttpListener on the port of the enabled test VPN listener: listener already exists");

	Zero(&d, sizeof(d));
	d.Port = HTTPLISTENER_PORT_VPN_OFF;
	d.Enable = false;
	if (HarnessCheckErr(t->H, ScCreateListener(t->H->Rpc, &d), "ListenerCreate of a disabled VPN listener"))
	{
		HarnessCheck(t->H, HttpTestSet(t, true, HTTPLISTENER_PORT_VPN_OFF) == ERR_LISTENER_ALREADY_EXISTS,
			"SetHttpListener on the port of a disabled VPN listener: listener already exists");

		Zero(&d, sizeof(d));
		d.Port = HTTPLISTENER_PORT_VPN_OFF;
		HarnessCheckErr(t->H, ScDeleteListener(t->H->Rpc, &d), "ListenerDelete of the disabled VPN listener");
	}

	Zero(&d, sizeof(d));
	d.Port = HTTPLISTENER_PORT;
	d.Enable = true;
	HarnessCheck(t->H, ScCreateListener(t->H->Rpc, &d) == ERR_LISTENER_ALREADY_EXISTS,
		"ListenerCreate on the port of the enabled HTTP listener: listener already exists");

	HttpTestExpectGet(t, "after the refused calls", true, HTTPLISTENER_PORT, true);
}

// The setting survives the configuration round trip; a disable lets the port go
static void HttpTestPersistence(HTTPLISTENER_TEST *t)
{
	char tmp[MAX_SIZE];

	Print("[configuration round trip, disable]\n");
	HarnessSetPhase("httplistener", "restart");

	if (HarnessRestartServer(t->H) == false)
	{
		return;
	}
	DisableDosProtect();

	HttpTestExpectGet(t, "after the configuration round trip", true, HTTPLISTENER_PORT, true);
	HttpTestExpect(t, "GET after the restart", "GET / HTTP/1.1\r\nHost: " HTTPLISTENER_HOST "\r\n\r\n", 301, NULL);

	HarnessSetPhase("httplistener", "disable");
	HarnessCheckErr(t->H, HttpTestSet(t, false, 0), "SetHttpListener off");

	UINT64 end = Tick64() + (UINT64)HTTPLISTENER_BIND_TIMEOUT;
	bool accepts;
	while ((accepts = HttpTestCanConnect(HTTPLISTENER_PORT)) && Tick64() < end)
	{
		SleepThread(HTTPLISTENER_POLL);
	}
	Format(tmp, sizeof(tmp), "after the disable the test port stops accepting within %u ms", HTTPLISTENER_BIND_TIMEOUT);
	HarnessCheck(t->H, accepts == false, tmp);

	HttpTestExpectGet(t, "after the disable", false, HTTPLISTENER_PORT, false);
}

// The HTTP listener on a port that another socket holds: on and not listening, then listening once the port is free
static void HttpTestPortTaken(HTTPLISTENER_TEST *t)
{
	char tmp[MAX_SIZE];

	Print("[port taken: TCP %u]\n", HTTPLISTENER_PORT_HELD);
	HarnessSetPhase("httplistener", "port taken");

	// The bind of the server's listener (any address, no address reuse): the server cannot bind the port while this
	// socket is open
	SOCK *held = Listen(HTTPLISTENER_PORT_HELD, NULL, false);
	Format(tmp, sizeof(tmp), "the test holds TCP %u", HTTPLISTENER_PORT_HELD);
	if (HarnessCheck(t->H, held != NULL, tmp) == false)
	{
		return;
	}

	HarnessCheckErr(t->H, HttpTestSet(t, true, HTTPLISTENER_PORT_HELD), "SetHttpListener on the held port succeeds");
	HttpTestExpectGet(t, "on the held port", true, HTTPLISTENER_PORT_HELD, false);

	Disconnect(held);
	ReleaseSock(held);

	HttpTestExpectGet(t, "after the port was released", true, HTTPLISTENER_PORT_HELD, true);

	HarnessCheckErr(t->H, HttpTestSet(t, false, 0), "SetHttpListener off (cleanup)");
}

// "httplistener": the HTTP listener on a test port, REL-6 (#51)
RANZ_TEST("httplistener", httplistener_test, "HTTP listener on a test port: the redirect to HTTPS, ACME HTTP-01 challenges, the errors, port conflicts, the configuration round trip, a held port.");
void httplistener_test(UINT num, char **arg)
{
	HTTPLISTENER_TEST t;
	char path[MAX_PATH];
	char tmp[MAX_SIZE];
	bool ok;

	Zero(&t, sizeof(t));

	Print("Ranz httplistener: the HTTP listener on TCP %u, VPN listener on TCP %u\n", HTTPLISTENER_PORT, HARNESS_PORT);

	t.H = HarnessOpenServer("HTTPLISTENER", HTTPLISTENER_WATCHDOG_LIMIT, NULL, NULL, &ok);

	if (ok)
	{
		DisableDosProtect();

		HttpTestStart(&t);
		HttpTestRedirects(&t);
		HttpTestAcme(&t);
		HttpTestErrors(&t);
		HttpTestSilent(&t);
		HttpTestNotVpn(&t);
		HttpTestConflicts(&t);
		HttpTestPersistence(&t);
		HttpTestPortTaken(&t);

		Format(tmp, sizeof(tmp), "no answer names the product or SoftEther (%u answers, %u name it)", t.NumAnswers,
			t.NumNamed);
		HarnessCheck(t.H, t.NumAnswers != 0 && t.NumNamed == 0, tmp);
	}

	if (IsEmptyStr(t.Token) == false)
	{
		HttpTestChallengePath(path, sizeof(path), t.Token);
		FileDelete(path);
	}

	EnableDosProtect();

	UINT num_fail = HarnessCloseServer(t.H);

	if (num_fail == 0)
	{
		Print("HTTPLISTENER TEST OK\n");
	}
	else
	{
		Print("HTTPLISTENER TEST FAILED (%u failed checks)\n", num_fail);
	}
}
