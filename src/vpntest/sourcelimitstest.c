// sourcelimitstest.c
// Named test of vpntest ("sourcelimits" command, AUD1-DT-3 #451)
//
// The limits for a source of the new core's listeners (src/Core/SourceLimit.c; NS-10, TR-5, FD-1, FD-6 of
// docs/threat-model.md): the caps on the connections that have not finished their handshake, in all and for one source,
// the rates of the new connections and of the handshake attempts of a source, QUIC retry under load, and the counters of
// what was refused. The checks:
// - the table of sources, on a clock that the test sets: the caps in all and for one source, the IPv6 /64 and the
//   IPv4-mapped address as one source, the two token buckets, the bound of the table, the defaults;
// - the front door (src/Core/FrontDoor.c) on a port of the loopback interface, never 443: a flood of new TCP connections
//   from one source that say nothing is cut at the cap of the source, the connections that it closed are the excess, and a
//   connection from another loopback address, which is another source, is served while the flood holds its places, and
//   the source is served again when the flood ends; a source over the rate of its connections or of its TLS handshakes
//   has the excess closed; and 1000 Nodes behind one address connect with the default limits, none of them refused;
// - the QUIC listener (src/Core/TransportQuic.c): the setting of retry is read back from msquic, a source over the rate of
//   its connections is refused by the listener and counted, and under a flood of Initial packets msquic answers with
//   retries and tells the listener so (its DoS mode), the connections that it holds, the memory and the CPU of the
//   process stay bounded, and an honest client connects after the flood. The honest client closes at once and the
//   listener closes right after, before the server may have seen the client's stream: the transport must still free.
// Print "SOURCELIMITS TEST OK" only when every check passes. It fails where msquic.dll is not present, since the QUIC
// listener is not tested there.

#include "testlist.h"

#include "Mayaqua/Encrypt.h"
#include "Mayaqua/Kernel.h"
#include "Mayaqua/Memory.h"
#include "Mayaqua/Microsoft.h"
#include "Mayaqua/Str.h"
#include "Mayaqua/Tick64.h"

#include "Core/Crypto.h"
#include "Core/FrontDoor.h"
#include "Core/SourceLimit.h"
#include "Core/Transport.h"

#include <ws2tcpip.h>

#include <psapi.h>
#include <stdio.h>

#define	SLTEST_WATCHDOG		150000			// The test process is aborted after this (ms)
#define	SLTEST_WAIT			15000			// A bounded wait on observable state (ms)
#define	SLTEST_POLL			10				// How often it looks (ms)
#define	SLTEST_FLOOD		40				// The connections of a flood at the front door
#define	SLTEST_CAP			8				// The cap of a source at the front door in the flood test
#define	SLTEST_NODES		1000			// The Nodes behind one address
#define	SLTEST_WORKERS		100				// ... and how many of them connect at once
#define	SLTEST_ATTEMPTS		20				// A Node that is closed without service asks again this many times
#define	SLTEST_SOURCE_A		"127.0.0.1"		// The sources of the front door test: two loopback addresses
#define	SLTEST_SOURCE_B		"127.0.0.2"
#define	SLTEST_CN			L"CN=localhost"	// The subject of the QUIC server certificate
#define	SLTEST_SAN			L"localhost"	// ... and its subject alternative name
#define	SLTEST_QUIC_DIALS	12				// The dials of a client against a listener with a rate of 4 connections
#define	SLTEST_INITIALS		6000			// The Initial packets of the flood at the QUIC listener
#define	SLTEST_INITIAL_SIZE	1200			// ... each of the least size that QUIC allows for one
#define	SLTEST_MEMORY		(256ULL << 20)	// The private bytes that the flood may add to the process
#define	SLTEST_CPU			20000			// The CPU time that the flood may take (ms)

// The state of the test
typedef struct SLTEST_CTX
{
	UINT NumChecks;
	UINT NumFailed;
} SLTEST_CTX;

// The owner of the front door in this test: it takes each connection, reads what the client sent, answers 'T' and closes
typedef struct SLTEST_OWNER
{
	volatile LONG Taken;			// The connections that it took
} SLTEST_OWNER;

// The Nodes behind one address of the front door test: workers take the next one, connect, and ask again when closed
typedef struct SLTEST_NODES_RUN
{
	USHORT Port;					// The port of the front door
	volatile LONG Next;				// The next Node to connect
	volatile LONG Connected;		// The Nodes served
	volatile LONG Retries;			// The connections that were closed without service
	volatile LONG Failed;			// The Nodes that gave up
} SLTEST_NODES_RUN;

static bool SlCheck(SLTEST_CTX *ctx, bool ok, char *what, char *fmt, ...) RANZ_PRINTF_FORMAT(4, 5);
static bool SlCheck(SLTEST_CTX *ctx, bool ok, char *what, char *fmt, ...)
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

// What the test does now, which the watchdog names when it ends the run
static const char *volatile g_sl_phase = "start";

// A dial of client to address that gives up after 20 s, so that a connection that never comes up fails the check
static VOID CALLBACK SlCancelTimer(PVOID param, BOOLEAN fired)
{
	UNREFERENCED_PARAMETER(fired);
	SetEvent((HANDLE)param);
}

static TRANSPORT_STREAM *SlDial(TRANSPORT *client, char *address)
{
	HANDLE cancel = CreateEventW(NULL, TRUE, FALSE, NULL);
	HANDLE timer = NULL;

	CreateTimerQueueTimer(&timer, NULL, SlCancelTimer, cancel, 20000, 0, WT_EXECUTEONLYONCE);
	TRANSPORT_STREAM *s = TransportDial(client, address, cancel);
	DeleteTimerQueueTimer(NULL, timer, INVALID_HANDLE_VALUE);
	CloseHandle(cancel);

	return s;
}

// The watchdog: a native thread that ends a run that hangs, so a lost wake-up is a failed test instead of a hung CI step
static DWORD WINAPI SlWatchdog(LPVOID param)
{
	char msg[MAX_SIZE];
	DWORD written = 0;

	if (WaitForSingleObject((HANDLE)param, SLTEST_WATCHDOG) != WAIT_TIMEOUT)
	{
		return 0;
	}

	int len = snprintf(msg, sizeof(msg), "SOURCELIMITS TEST FAILED (did not finish within %u ms, in: %s)\n", SLTEST_WATCHDOG, g_sl_phase);
	if (len > 0)
	{
		WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), msg, (DWORD)MIN((UINT)len, (UINT)sizeof(msg) - 1), &written, NULL);
	}
	TerminateProcess(GetCurrentProcess(), 1);

	return 0;
}

// The private bytes of the process
static UINT64 SlPrivateBytes()
{
	PROCESS_MEMORY_COUNTERS_EX pmc;

	Zero(&pmc, sizeof(pmc));
	pmc.cb = sizeof(pmc);
	if (GetProcessMemoryInfo(GetCurrentProcess(), (PROCESS_MEMORY_COUNTERS *)&pmc, sizeof(pmc)) == false)
	{
		return 0;
	}

	return pmc.PrivateUsage;
}

// The CPU time of the process, user and kernel, in milliseconds
static UINT64 SlCpuMs()
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

	return (k.QuadPart + u.QuadPart) / 10000;
}

//
// The table of sources
//

// The source of a peer address in text: an IPv4 or an IPv6 address
static SOURCE_KEY SlKey(char *text)
{
	SOCKADDR_IN a4;
	SOCKADDR_IN6 a6;
	SOURCE_KEY key;

	Zero(&a4, sizeof(a4));
	Zero(&a6, sizeof(a6));
	if (inet_pton(AF_INET, text, &a4.sin_addr) == 1)
	{
		a4.sin_family = AF_INET;
		SourceLimitsKey((const struct sockaddr *)&a4, &key);
	}
	else
	{
		inet_pton(AF_INET6, text, &a6.sin6_addr);
		a6.sin6_family = AF_INET6;
		SourceLimitsKey((const struct sockaddr *)&a6, &key);
	}

	return key;
}

// The table of sources on a clock that the test sets
static void SlUnit(SLTEST_CTX *ctx)
{
	SOURCE_LIMIT_CONFIG cfg;
	SOURCE_LIMIT_STATS st;
	SOURCE_LIMITS *l;
	SOURCE_KEY a = SlKey("192.0.2.1"), b = SlKey("192.0.2.2"), c = SlKey("192.0.2.3"), d = SlKey("192.0.2.4");
	UINT64 now = 1000000;

	Print("[the table of sources]\n");

	// The defaults
	l = SourceLimitsNew(NULL);
	SourceLimitsGetConfig(l, &cfg);
	SlCheck(ctx, cfg.MaxPending == SOURCE_LIMIT_MAX_PENDING && cfg.MaxPendingPerSource == SOURCE_LIMIT_PER_SOURCE && cfg.ConnectRate == SOURCE_LIMIT_RATE &&
		cfg.ConnectBurst == SOURCE_LIMIT_BURST && cfg.HandshakeRate == SOURCE_LIMIT_RATE && cfg.HandshakeBurst == SOURCE_LIMIT_BURST,
		"  a configuration of zeros takes the defaults", "%u %u %u %u %u %u", cfg.MaxPending, cfg.MaxPendingPerSource, cfg.ConnectRate, cfg.ConnectBurst, cfg.HandshakeRate, cfg.HandshakeBurst);
	SourceLimitsFree(l);

	// The caps in all and for one source
	Zero(&cfg, sizeof(cfg));
	cfg.MaxPending = 5;
	cfg.MaxPendingPerSource = 2;
	l = SourceLimitsNew(&cfg);
	bool ok = (SourceLimitsEnter(l, &a, now) == SOURCE_LIMIT_ADMIT && SourceLimitsEnter(l, &a, now) == SOURCE_LIMIT_ADMIT);
	SlCheck(ctx, ok && SourceLimitsEnter(l, &a, now) == SOURCE_LIMIT_SOURCE, "  the third connection of a source with a cap of 2 is refused for the cap of the source", "ok %u", (UINT)ok);
	ok = (SourceLimitsEnter(l, &b, now) == SOURCE_LIMIT_ADMIT && SourceLimitsEnter(l, &b, now) == SOURCE_LIMIT_ADMIT && SourceLimitsEnter(l, &c, now) == SOURCE_LIMIT_ADMIT);
	SlCheck(ctx, ok && SourceLimitsEnter(l, &d, now) == SOURCE_LIMIT_FULL, "  the sixth connection with a cap of 5 in all is refused for the cap in all", "ok %u", (UINT)ok);
	SourceLimitsLeave(l, &a);
	SlCheck(ctx, SourceLimitsEnter(l, &a, now) == SOURCE_LIMIT_ADMIT, "  a place that a connection gave back is taken again", "refused");
	SourceLimitsGetStats(l, &st);
	SlCheck(ctx, st.Pending == 5 && st.Sources == 3 && st.Admitted == 6 && st.RefusedFull == 1 && st.RefusedSource == 1 && st.RefusedRate == 0,
		"  the counters add up", "pending %u, sources %u, admitted %llu, full %llu, source %llu, rate %llu", st.Pending, st.Sources, st.Admitted, st.RefusedFull, st.RefusedSource, st.RefusedRate);
	SourceLimitsFree(l);

	// A source is an IPv4 address or the /64 of an IPv6 address; an IPv4-mapped address is its IPv4 address
	Zero(&cfg, sizeof(cfg));
	cfg.MaxPendingPerSource = 1;
	l = SourceLimitsNew(&cfg);
	SOURCE_KEY v6a = SlKey("2001:db8:1:2::1"), v6b = SlKey("2001:db8:1:2:ffff::9"), v6c = SlKey("2001:db8:1:3::1"), mapped = SlKey("::ffff:192.0.2.1");
	ok = (SourceLimitsEnter(l, &v6a, now) == SOURCE_LIMIT_ADMIT && SourceLimitsEnter(l, &v6c, now) == SOURCE_LIMIT_ADMIT && SourceLimitsEnter(l, &a, now) == SOURCE_LIMIT_ADMIT);
	SlCheck(ctx, ok && SourceLimitsEnter(l, &v6b, now) == SOURCE_LIMIT_SOURCE, "  two addresses of one IPv6 /64 are one source, another /64 is another", "ok %u", (UINT)ok);
	SlCheck(ctx, SourceLimitsEnter(l, &mapped, now) == SOURCE_LIMIT_SOURCE && v6a.Family == 6 && a.Family == 4 && mapped.Family == 4,
		"  an IPv4-mapped IPv6 address is its IPv4 address", "family %u, %u, %u", v6a.Family, a.Family, mapped.Family);
	SourceLimitsFree(l);

	// The rate of the new connections and the rate of the handshake attempts: each a bucket with a burst and a rate
	Zero(&cfg, sizeof(cfg));
	cfg.ConnectRate = 2;
	cfg.ConnectBurst = 3;
	cfg.HandshakeRate = 1;
	cfg.HandshakeBurst = 2;
	l = SourceLimitsNew(&cfg);
	ok = true;
	for (UINT i = 0; i < 3; i++)
	{
		ok = (ok && SourceLimitsEnter(l, &a, now) == SOURCE_LIMIT_ADMIT);
		SourceLimitsLeave(l, &a);
	}
	SlCheck(ctx, ok && SourceLimitsEnter(l, &a, now) == SOURCE_LIMIT_RATE_NEW, "  the fourth connection in the same instant of a bucket of 3 is refused for the rate", "ok %u", (UINT)ok);
	SlCheck(ctx, SourceLimitsEnter(l, &b, now) == SOURCE_LIMIT_ADMIT, "  another source has a bucket of its own", "refused");
	now += 500;
	SlCheck(ctx, SourceLimitsEnter(l, &a, now) == SOURCE_LIMIT_ADMIT && SourceLimitsEnter(l, &a, now) == SOURCE_LIMIT_RATE_NEW,
		"  half a second at 2 a second gives one token back", "refused or admitted wrongly");
	ok = (SourceLimitsHandshake(l, &a, now) == SOURCE_LIMIT_ADMIT && SourceLimitsHandshake(l, &a, now) == SOURCE_LIMIT_ADMIT);
	SlCheck(ctx, ok && SourceLimitsHandshake(l, &a, now) == SOURCE_LIMIT_RATE_HAND, "  the third handshake in the same instant of a bucket of 2 is refused for the rate", "ok %u", (UINT)ok);
	SlCheck(ctx, SourceLimitsHandshake(l, &b, now) == SOURCE_LIMIT_ADMIT, "  another source has a handshake bucket of its own", "refused");
	now += 1000;
	SlCheck(ctx, SourceLimitsHandshake(l, &a, now) == SOURCE_LIMIT_ADMIT, "  a second at 1 a second gives a handshake back", "refused");
	SourceLimitsGetStats(l, &st);
	SlCheck(ctx, st.RefusedRate == 2 && st.RefusedHandshake == 1, "  the refusals are counted by their reason", "rate %llu, handshake %llu", st.RefusedRate, st.RefusedHandshake);
	SourceLimitsFree(l);

	// The table is bounded: sources that have spent a token fill it, then it refuses a new source as full, until the
	// buckets of the others are full again and they are forgotten
	l = SourceLimitsNew(NULL);
	ok = true;
	for (UINT i = 0; i < SOURCE_LIMIT_MAX_SOURCES && ok; i++)
	{
		SOCKADDR_IN a4;
		SOURCE_KEY k;

		Zero(&a4, sizeof(a4));
		a4.sin_family = AF_INET;
		a4.sin_addr.S_un.S_addr = htonl(0x0A000000 + i);
		SourceLimitsKey((const struct sockaddr *)&a4, &k);
		ok = (SourceLimitsEnter(l, &k, now) == SOURCE_LIMIT_ADMIT);
		SourceLimitsLeave(l, &k);
	}
	SlCheck(ctx, ok && SourceLimitsEnter(l, &d, now) == SOURCE_LIMIT_FULL, "  a table full of sources that have spent a token refuses a new source", "ok %u", (UINT)ok);
	now += 3600000;
	SlCheck(ctx, SourceLimitsEnter(l, &d, now) == SOURCE_LIMIT_ADMIT, "  the sources whose buckets are full again are forgotten", "refused");
	SourceLimitsGetStats(l, &st);
	SlCheck(ctx, st.Sources == 1, "  only the source that holds a connection stays", "%u sources", st.Sources);
	SourceLimitsFree(l);
}

//
// The front door
//

// The owner: it reads what the client sent, so that a close does not reset the connection and lose its answer, answers
// 'T' and closes the socket, which the front door hands over blocking
static bool SlTake(void *param, SOCKET s)
{
	SLTEST_OWNER *o = (SLTEST_OWNER *)param;
	char buf[256];
	DWORD timeout = 5000;

	setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char *)&timeout, sizeof(timeout));
	(void)recv(s, buf, sizeof(buf), 0);
	InterlockedIncrement(&o->Taken);
	(void)send(s, "T", 1, 0);
	shutdown(s, SD_SEND);
	closesocket(s);

	return true;
}

// A ClientHello of TLS 1.2 with no extensions, in one record: the front door takes it for the TLS owner that takes any
// server name and any protocol. Its size.
static UINT SlHello(UCHAR *buf)
{
	UINT p = 0;

	buf[p++] = 22;	// A handshake record, 45 bytes
	buf[p++] = 3;
	buf[p++] = 1;
	buf[p++] = 0;
	buf[p++] = 45;
	buf[p++] = 1;	// A ClientHello, 41 bytes
	buf[p++] = 0;
	buf[p++] = 0;
	buf[p++] = 41;
	buf[p++] = 3;	// Its version
	buf[p++] = 3;
	for (UINT i = 0; i < 32; i++)
	{
		buf[p++] = (UCHAR)(0xA0 + i);
	}
	buf[p++] = 0;	// No session id
	buf[p++] = 0;	// One cipher suite
	buf[p++] = 2;
	buf[p++] = 0x13;
	buf[p++] = 0x01;
	buf[p++] = 1;	// One compression method
	buf[p++] = 0;

	return p;
}

// A TCP connection from the loopback address source to the same address at port; INVALID_SOCKET when it fails. A
// loopback address is a source of its own, as an address of a site's NAT is.
static SOCKET SlConnect(char *source, USHORT port)
{
	SOCKADDR_IN local;
	SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

	if (s == INVALID_SOCKET)
	{
		return INVALID_SOCKET;
	}

	Zero(&local, sizeof(local));
	local.sin_family = AF_INET;
	inet_pton(AF_INET, source, &local.sin_addr);
	if (bind(s, (const SOCKADDR *)&local, sizeof(local)) != 0)
	{
		closesocket(s);
		return INVALID_SOCKET;
	}

	local.sin_port = htons(port);
	if (connect(s, (const SOCKADDR *)&local, sizeof(local)) != 0)
	{
		closesocket(s);
		return INVALID_SOCKET;
	}

	return s;
}

// A Node of source says its ClientHello and waits for the owner's answer: true when the front door handed it over, false
// when it closed the connection without service
static bool SlServed(char *source, USHORT port)
{
	UCHAR hello[64];
	char answer = 0;
	DWORD timeout = 5000;
	SOCKET s = SlConnect(source, port);

	if (s == INVALID_SOCKET)
	{
		return false;
	}

	setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char *)&timeout, sizeof(timeout));
	UINT size = SlHello(hello);
	bool served = (send(s, (const char *)hello, (int)size, 0) == (int)size && recv(s, &answer, 1, 0) == 1 && answer == 'T');
	closesocket(s);

	return served;
}

// A front door on a test port of every IPv4 address, so that each loopback address is a source of its own, with one TLS
// owner that takes every ClientHello
static FRONT_DOOR *SlFrontDoor(SLTEST_OWNER *owner, FRONT_DOOR_OWNER *table, SOURCE_LIMIT_CONFIG *limits, UINT peek_timeout)
{
	FRONT_DOOR_CONFIG fc;

	Zero(table, sizeof(FRONT_DOOR_OWNER));
	StrCpy(table->Name, sizeof(table->Name), "node");
	table->Kind = FRONT_DOOR_TLS;
	table->Take = SlTake;
	table->Param = owner;

	Zero(&fc, sizeof(fc));
	StrCpy(fc.Address, sizeof(fc.Address), "0.0.0.0:0");
	fc.Owners = table;
	fc.NumOwners = 1;
	fc.PeekTimeout = peek_timeout;
	if (limits != NULL)
	{
		fc.Limits = *limits;
	}

	return FrontDoorStart(&fc);
}

// Wait until the front door has accepted at least num connections
static bool SlWaitAccepted(FRONT_DOOR *fd, UINT64 num, FRONT_DOOR_STATS *st)
{
	UINT64 end = GetTickCount64() + SLTEST_WAIT;

	while (true)
	{
		FrontDoorGetStats(fd, st);
		if (st->Accepted >= num)
		{
			return true;
		}
		if (GetTickCount64() >= end)
		{
			return false;
		}
		Sleep(SLTEST_POLL);
	}
}

// Whether the connection s is closed by its peer: it reads the end, or a reset; one that is open has nothing to read
static bool SlClosed(SOCKET s)
{
	char c;
	u_long nonblocking = 1;

	ioctlsocket(s, FIONBIO, &nonblocking);
	int n = recv(s, &c, 1, 0);

	return (n == 0 || (n == SOCKET_ERROR && WSAGetLastError() != WSAEWOULDBLOCK));
}

// A flood of connections from one source that say nothing, at a front door with a cap of SLTEST_CAP for a source
static void SlFlood(SLTEST_CTX *ctx)
{
	SLTEST_OWNER owner;
	FRONT_DOOR_OWNER table;
	SOURCE_LIMIT_CONFIG limits;
	FRONT_DOOR_STATS st;
	SOCKET flood[SLTEST_FLOOD];

	Print("[the front door: a flood of new TCP connections from one source]\n");
	Zero(&owner, sizeof(owner));
	Zero(&limits, sizeof(limits));
	limits.MaxPending = 64;
	limits.MaxPendingPerSource = SLTEST_CAP;

	// The connections of the flood wait for their first bytes for 60 s: they hold their places for the whole test
	FRONT_DOOR *fd = SlFrontDoor(&owner, &table, &limits, 60000);
	if (SlCheck(ctx, fd != NULL, "  the front door listens on a test port with a cap of 8 for a source", "FrontDoorStart failed") == false)
	{
		return;
	}
	USHORT port = FrontDoorPort(fd);

	for (UINT i = 0; i < SLTEST_FLOOD; i++)
	{
		flood[i] = SlConnect(SLTEST_SOURCE_A, port);
	}
	bool ok = SlWaitAccepted(fd, SLTEST_FLOOD, &st);
	SlCheck(ctx, ok, "  the front door accepts every connection of the flood", "%llu of %u accepted", st.Accepted, (UINT)SLTEST_FLOOD);

	// The flood is cut at the cap of its source: SLTEST_CAP wait, the rest were closed and counted
	UINT64 end = GetTickCount64() + SLTEST_WAIT;
	while (GetTickCount64() < end)
	{
		FrontDoorGetStats(fd, &st);
		if (st.Limits.Pending == SLTEST_CAP && st.Limits.RefusedSource == SLTEST_FLOOD - SLTEST_CAP)
		{
			break;
		}
		Sleep(SLTEST_POLL);
	}
	SlCheck(ctx, st.Limits.Pending == SLTEST_CAP && st.Limits.RefusedSource == SLTEST_FLOOD - SLTEST_CAP && st.Limits.RefusedFull == 0,
		"  the flood is cut at the cap of its source, and counted", "pending %u, refused for the source %llu, for all %llu", st.Limits.Pending, st.Limits.RefusedSource, st.Limits.RefusedFull);

	UINT closed = 0;
	end = GetTickCount64() + SLTEST_WAIT;
	while (GetTickCount64() < end)
	{
		closed = 0;
		for (UINT i = 0; i < SLTEST_FLOOD; i++)
		{
			if (flood[i] != INVALID_SOCKET && SlClosed(flood[i]))
			{
				closed++;
			}
		}
		if (closed == SLTEST_FLOOD - SLTEST_CAP)
		{
			break;
		}
		Sleep(SLTEST_POLL);
	}
	SlCheck(ctx, closed == SLTEST_FLOOD - SLTEST_CAP, "  the connections over the cap are closed by the front door and the others wait", "%u of %u closed", closed, (UINT)(SLTEST_FLOOD - SLTEST_CAP));

	// A connection from another source is served while the flood holds its places
	SlCheck(ctx, SlServed(SLTEST_SOURCE_B, port) && owner.Taken == 1, "  a connection from another source is served while the flood holds its places", "taken %ld", owner.Taken);

	// The flood ends: its places come back, and its source is served again
	for (UINT i = 0; i < SLTEST_FLOOD; i++)
	{
		if (flood[i] != INVALID_SOCKET)
		{
			closesocket(flood[i]);
		}
	}
	end = GetTickCount64() + SLTEST_WAIT;
	do
	{
		FrontDoorGetStats(fd, &st);
		Sleep(SLTEST_POLL);
	}
	while (st.Limits.Pending != 0 && GetTickCount64() < end);
	SlCheck(ctx, st.Limits.Pending == 0 && SlServed(SLTEST_SOURCE_A, port) && owner.Taken == 2, "  the places come back when the flood ends, and its source is served again", "pending %u, taken %ld", st.Limits.Pending, owner.Taken);

	FrontDoorStop(fd);
}

// A source over the rate of its connections, and one over the rate of its TLS handshakes
static void SlRates(SLTEST_CTX *ctx)
{
	SLTEST_OWNER owner;
	FRONT_DOOR_OWNER table;
	SOURCE_LIMIT_CONFIG limits;
	FRONT_DOOR_STATS st;

	Print("[the front door: the rates of the connections and of the handshakes of a source]\n");
	Zero(&owner, sizeof(owner));
	Zero(&limits, sizeof(limits));
	limits.ConnectRate = 1;
	limits.ConnectBurst = 5;
	limits.HandshakeRate = 1;
	limits.HandshakeBurst = 3;

	FRONT_DOOR *fd = SlFrontDoor(&owner, &table, &limits, 0);
	if (SlCheck(ctx, fd != NULL, "  the front door listens with a burst of 5 connections and 3 handshakes", "FrontDoorStart failed") == false)
	{
		return;
	}
	USHORT port = FrontDoorPort(fd);

	// Eight Nodes from one source in a moment: 5 connections are within the burst of the connections, and of them 3 within
	// the burst of the handshakes. A token may come back in the time that this takes, so the counts may differ by one.
	UINT served = 0;
	for (UINT i = 0; i < 8; i++)
	{
		if (SlServed(SLTEST_SOURCE_A, port))
		{
			served++;
		}
	}
	FrontDoorGetStats(fd, &st);
	SlCheck(ctx, served >= 3 && served <= 5 && st.Limits.RefusedRate >= 2 && st.Limits.RefusedHandshake >= 1 && served + st.Limits.RefusedRate + st.Limits.RefusedHandshake == 8,
		"  the connections over the rate of their source, and the handshakes over its rate, are closed and counted", "served %u, refused for the rate of connections %llu, of handshakes %llu",
		served, st.Limits.RefusedRate, st.Limits.RefusedHandshake);
	SlCheck(ctx, SlServed(SLTEST_SOURCE_B, port), "  another source is served meanwhile", "closed");

	FrontDoorStop(fd);
}

// A worker of the Nodes: it takes the next Node, connects, and asks again when the front door closes the connection
static DWORD WINAPI SlNodesWorker(LPVOID param)
{
	SLTEST_NODES_RUN *run = (SLTEST_NODES_RUN *)param;

	while ((UINT)InterlockedIncrement(&run->Next) <= SLTEST_NODES)
	{
		bool served = false;

		for (UINT attempt = 0; attempt < SLTEST_ATTEMPTS && served == false; attempt++)
		{
			served = SlServed(SLTEST_SOURCE_A, run->Port);
			if (served == false)
			{
				InterlockedIncrement(&run->Retries);
				Sleep(50);
			}
		}
		InterlockedIncrement(served ? &run->Connected : &run->Failed);
	}

	return 0;
}

// 1000 Nodes behind one address, with the default limits
static void SlNodes(SLTEST_CTX *ctx)
{
	SLTEST_OWNER owner;
	FRONT_DOOR_OWNER table;
	FRONT_DOOR_STATS st;
	SLTEST_NODES_RUN run;
	HANDLE workers[SLTEST_WORKERS];

	Print("[the front door: %u Nodes behind one address connect with the default limits]\n", (UINT)SLTEST_NODES);
	Zero(&owner, sizeof(owner));
	Zero(&run, sizeof(run));

	FRONT_DOOR *fd = SlFrontDoor(&owner, &table, NULL, 0);
	if (SlCheck(ctx, fd != NULL, "  the front door listens with the default limits", "FrontDoorStart failed") == false)
	{
		return;
	}
	run.Port = FrontDoorPort(fd);

	for (UINT i = 0; i < SLTEST_WORKERS; i++)
	{
		workers[i] = CreateThread(NULL, 0, SlNodesWorker, &run, 0, NULL);
	}
	for (UINT i = 0; i < SLTEST_WORKERS; i++)
	{
		if (workers[i] != NULL)
		{
			WaitForSingleObject(workers[i], INFINITE);
			CloseHandle(workers[i]);
		}
	}

	FrontDoorGetStats(fd, &st);
	SlCheck(ctx, run.Connected == SLTEST_NODES && run.Failed == 0 && owner.Taken == SLTEST_NODES, "  every Node is served", "%ld served, %ld gave up, the owner took %ld", run.Connected, run.Failed, owner.Taken);
	SlCheck(ctx, st.Limits.RefusedFull + st.Limits.RefusedSource + st.Limits.RefusedRate + st.Limits.RefusedHandshake == 0 && run.Retries == 0 && st.Limits.Admitted == SLTEST_NODES,
		"  the limits refuse none of them", "refused: all %llu, source %llu, rate %llu, handshake %llu; %ld Nodes asked again", st.Limits.RefusedFull, st.Limits.RefusedSource,
		st.Limits.RefusedRate, st.Limits.RefusedHandshake, run.Retries);

	FrontDoorStop(fd);
}

//
// The QUIC listener
//

// An Initial packet of QUIC version 1 of size bytes, with a connection id of its own and a payload that no key opens:
// the packet that a flood of them is made of. msquic must read its header and give it a connection until its retry
// takes over.
static void SlInitial(UCHAR *buf, UINT size)
{
	UINT n = 0;
	UINT length;

	Rand(buf, size);
	buf[n++] = 0xC0;	// A long header, the fixed bit, an Initial packet
	buf[n++] = 0;		// Version 1
	buf[n++] = 0;
	buf[n++] = 0;
	buf[n++] = 1;
	buf[n++] = 8;		// A destination connection id of 8 bytes, random as the client chooses it ...
	n += 8;
	buf[n++] = 8;		// ... and a source connection id of 8 bytes
	n += 8;
	buf[n++] = 0;		// No token
	length = size - n - 2;
	buf[n++] = (UCHAR)(0x40 | (length >> 8));
	buf[n++] = (UCHAR)(length & 0xFF);
}

// The QUIC listener
static void SlQuic(SLTEST_CTX *ctx)
{
	char thumbprint[MAX_SIZE];
	UINT scope = 0;

	Print("[the QUIC listener]\n");

	if (CryptoInit() == false || TransportQuicAvailable() == false)
	{
		// The listener is not tested where QUIC cannot run, so the test fails there rather than pass on nothing: every job
		// that runs it fetches msquic.dll next to vpntest
		SlCheck(ctx, false, "  msquic.dll is present", "msquic.dll is not present: the QUIC listener cannot run, so its limits are not tested");
		return;
	}

	PCCERT_CONTEXT cert = CryptoCertCreateSelfSigned(SLTEST_CN, SLTEST_SAN, NULL, 30, scope);
	bool have_cert = (cert != NULL && CryptoCertThumbprintStr(cert, thumbprint, sizeof(thumbprint)) && CryptoCertAddToStore(cert, NULL, scope));
	SlCheck(ctx, have_cert, "  a self-signed certificate in the My store", "CryptoCertCreateSelfSigned or the store failed");

	if (have_cert)
	{
		TRANSPORT_QUIC_STATS st;
		TRANSPORT_QUIC_CONFIG cfg;
		char address[TRANSPORT_ADDRESS_SIZE];

		TransportQuicDefaultConfig(&cfg, thumbprint, false);
		TRANSPORT *client = TransportQuicClientNew(&cfg);

		// The setting of retry: msquic holds the one that the listener set, which the test reads back from it
		TRANSPORT *server = TransportQuicServerNew(&cfg);
		bool ok = (server != NULL && client != NULL && TransportQuicGetStats(server, &st));
		SlCheck(ctx, ok && st.RetryMemoryLimit == TRANSPORT_QUIC_RETRY_DEFAULT, "  the retry setting that msquic holds is the default of the listener, read back from msquic", "ok %u, the setting is %u, want %u",
			(UINT)ok, ok ? st.RetryMemoryLimit : 0, (UINT)TRANSPORT_QUIC_RETRY_DEFAULT);
		TransportQuicFree(server);

		TransportQuicDefaultConfig(&cfg, thumbprint, false);
		cfg.RetryMemoryLimit = 7;
		server = TransportQuicServerNew(&cfg);
		ok = (server != NULL && TransportQuicGetStats(server, &st));
		SlCheck(ctx, ok && st.RetryMemoryLimit == 7, "  a setting in the configuration is the one that msquic holds", "ok %u, the setting is %u", (UINT)ok, ok ? st.RetryMemoryLimit : 0);
		TransportQuicFree(server);

		// A source over the rate of its connections is refused by the listener and counted
		TransportQuicDefaultConfig(&cfg, thumbprint, false);
		cfg.Limits.ConnectRate = 1;
		cfg.Limits.ConnectBurst = 4;
		server = TransportQuicServerNew(&cfg);
		TRANSPORT_LISTENER *listener = (server != NULL ? TransportListen(server, "127.0.0.1:0") : NULL);
		if (SlCheck(ctx, listener != NULL && client != NULL, "  a QUIC listener with a burst of 4 connections for a source listens on a test port", "the listener did not start"))
		{
			UINT served = 0;

			Format(address, sizeof(address), "127.0.0.1:%u", (UINT)TransportQuicBoundPort(server));
			for (UINT i = 0; i < SLTEST_QUIC_DIALS; i++)
			{
				TRANSPORT_STREAM *s = SlDial(client, address);

				if (s != NULL)
				{
					served++;
					TransportClose(s);
				}
			}
			ok = TransportQuicGetStats(server, &st);
			SlCheck(ctx, ok && served >= 4 && served <= 6 && st.Limits.RefusedRate == SLTEST_QUIC_DIALS - served && st.Limits.Admitted == served,
				"  the connections of a source over its rate are refused by the listener and counted", "served %u of %u, admitted %llu, refused for the rate %llu", served, (UINT)SLTEST_QUIC_DIALS,
				ok ? st.Limits.Admitted : 0, ok ? st.Limits.RefusedRate : 0);
		}
		g_sl_phase = "the QUIC listener: freeing the transport of the rate test";
		TransportCloseListener(listener);
		TransportQuicFree(server);
		g_sl_phase = "the QUIC listener: the flood";

		// A flood of Initial packets at a listener whose retry setting is the least: msquic answers with retries, and the
		// connections that it holds, the memory and the CPU of the process stay bounded
		TransportQuicDefaultConfig(&cfg, thumbprint, false);
		cfg.RetryMemoryLimit = 1;
		server = TransportQuicServerNew(&cfg);
		listener = (server != NULL ? TransportListen(server, "127.0.0.1:0") : NULL);
		if (SlCheck(ctx, listener != NULL, "  a QUIC listener with the least retry limit listens on a test port", "the listener did not start"))
		{
			SOCKADDR_IN to;
			SOCKET udp = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
			UCHAR packet[SLTEST_INITIAL_SIZE];
			UINT sent = 0;
			UINT64 memory = SlPrivateBytes(), cpu = SlCpuMs();
			UINT64 retries_before = 0;

			if (TransportQuicGetStats(server, &st))
			{
				retries_before = st.Retries;
			}

			Zero(&to, sizeof(to));
			to.sin_family = AF_INET;
			inet_pton(AF_INET, "127.0.0.1", &to.sin_addr);
			to.sin_port = htons(TransportQuicBoundPort(server));

			for (UINT i = 0; i < SLTEST_INITIALS && udp != INVALID_SOCKET; i++)
			{
				SlInitial(packet, sizeof(packet));
				if (sendto(udp, (const char *)packet, sizeof(packet), 0, (const SOCKADDR *)&to, sizeof(to)) == (int)sizeof(packet))
				{
					sent++;
				}
			}
			closesocket(udp);
			Sleep(3000);

			ok = TransportQuicGetStats(server, &st);
			Print("SOURCELIMITS QUIC FLOOD: %u Initial packets sent, %llu retries, %llu connections held, retry %s after %llu changes, setting %u\n", sent,
				ok ? st.Retries : 0, ok ? st.ActiveConnections : 0, (ok && st.DosMode) ? "on" : "off", ok ? st.DosModeChanges : 0, ok ? st.RetryMemoryLimit : 0);
			SlCheck(ctx, ok && sent >= SLTEST_INITIALS / 2 && st.RetryMemoryLimit == 1, "  the flood is sent, and the setting that msquic holds is the one of the listener", "sent %u, the setting is %u", sent, ok ? st.RetryMemoryLimit : 0);
			SlCheck(ctx, ok && st.Retries > retries_before, "  msquic answers the flood of Initial packets with retries", "no retry packet was sent");
			// msquic sends a retry only while the handshakes hold more than the limit, which is when it tells the listeners
			// that it answers new connections with a retry (its DoS mode), so the state of the node shows it
			SlCheck(ctx, ok && st.DosModeChanges > 0, "  msquic tells the listener that it answers new connections with a retry", "no change of the DoS mode was told");
			SlCheck(ctx, ok && st.ActiveConnections < SLTEST_INITIALS / 2, "  the connections that msquic holds stay bounded under the flood", "%llu connections for %u packets", ok ? st.ActiveConnections : 0, sent);
			UINT64 grown = SlPrivateBytes() - memory, used = SlCpuMs() - cpu;
			SlCheck(ctx, SlPrivateBytes() < memory + SLTEST_MEMORY && used < SLTEST_CPU, "  the memory and the CPU of the process stay bounded", "%llu bytes more private memory, %llu ms of CPU", grown, used);

			// An honest client connects after the flood, through the retry
			Format(address, sizeof(address), "127.0.0.1:%u", (UINT)TransportQuicBoundPort(server));
			TRANSPORT_STREAM *s = (client != NULL ? SlDial(client, address) : NULL);
			SlCheck(ctx, s != NULL, "  an honest client connects to the listener after the flood", "the dial failed");
			TransportClose(s);
		}
		g_sl_phase = "the QUIC listener: closing the listener of the flood";
		TransportCloseListener(listener);
		g_sl_phase = "the QUIC listener: freeing the transport of the flood";
		TransportQuicFree(server);
		g_sl_phase = "the QUIC listener: freeing the client";
		TransportQuicFree(client);
	}

	g_sl_phase = "the QUIC listener: removing the certificate";
	if (cert != NULL)
	{
		CryptoCertRemoveFromStore(thumbprint, NULL, scope);
		CryptoCertDeleteKey(cert);
		CryptoCertFree(cert);
	}
}

RANZ_TEST_TAGS("sourcelimits", sourcelimits_test, "core", "Limits for a source (AUD1-DT-3): the caps and the rates of a source, the front door cut at the cap of a flood while another source is served, 1000 Nodes behind one address, and QUIC retry under a flood of Initial packets.");
void sourcelimits_test(UINT num, char **arg)
{
	SLTEST_CTX *ctx = ZeroMalloc(sizeof(SLTEST_CTX));
	HANDLE done = CreateEventW(NULL, TRUE, FALSE, NULL);
	HANDLE watchdog = (done != NULL ? CreateThread(NULL, 0, SlWatchdog, done, 0, NULL) : NULL);

	Print("SOURCELIMITS test: the limits for a source of the front door and of the QUIC listener (AUD1-DT-3)\n");

	UINT64 t0 = GetTickCount64();

	g_sl_phase = "the table of sources";
	SlUnit(ctx);
	g_sl_phase = "the front door flood";
	SlFlood(ctx);
	Print("SOURCELIMITS TIME flood done at %llu ms\n", GetTickCount64() - t0);
	g_sl_phase = "the front door rates";
	SlRates(ctx);
	Print("SOURCELIMITS TIME rates done at %llu ms\n", GetTickCount64() - t0);
	g_sl_phase = "the front door Nodes";
	SlNodes(ctx);
	Print("SOURCELIMITS TIME Nodes done at %llu ms\n", GetTickCount64() - t0);
	g_sl_phase = "the QUIC listener";
	SlQuic(ctx);
	Print("SOURCELIMITS TIME QUIC done at %llu ms\n", GetTickCount64() - t0);

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
		Print("SOURCELIMITS TEST OK\n");
	}
	else
	{
		Print("SOURCELIMITS TEST FAILED (%u of %u checks failed)\n", ctx->NumFailed, ctx->NumChecks);
	}

	Free(ctx);
}
