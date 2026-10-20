// udpaccel.c
// Named UDP Acceleration receive test of vpntest ("udpaccel" command, FIX-1 #97)
//
// Pins the bounded receive loop of UdpAccelPoll(): one call reads at most
// UDP_ACCELERATION_MAX_RECV_PER_POLL datagrams and the calls of one tick at most
// UDP_ACCELERATION_MAX_RECV_PER_TICK; the rest stays in the socket for the next call, so a valid
// packet behind a flood is still received. The old loop read until the socket was empty, so the
// flood checks fail on it. Also pins the header check before decryption (a datagram shorter than
// the smallest packet of the format is dropped, the smallest valid packet is still accepted), the
// drop counters and the rate limit of their log entry. Runs on loopback sockets in plain text,
// version 1 (RC4) and version 2 (ChaCha20-Poly1305) mode. Also pins the cookie pair of a new
// UDP_ACCEL: YourCookie is never 0 and never MyCookie (FND-60). Prints "UDPACCEL TEST OK" only when
// every check passes, and frees everything it allocates.

#include "Cedar/Cedar.h"
#include "Cedar/Connection.h"
#include "Cedar/UdpAccel.h"

#include "Mayaqua/Encrypt.h"
#include "Mayaqua/Internat.h"
#include "Mayaqua/Kernel.h"
#include "Mayaqua/Memory.h"
#include "Mayaqua/Network.h"
#include "Mayaqua/Str.h"
#include "Mayaqua/Table.h"
#include "Mayaqua/Tick64.h"

#include <stdarg.h>

#define	UDPACCEL_TEST_WAIT			100		// Milliseconds for loopback datagrams to reach the receiving socket
#define	UDPACCEL_TEST_HEADER_SIZE	23		// Cookie 4, my tick 8, your tick 8, data size 2, flag 1
#define	UDPACCEL_TEST_DATA_SIZE		100		// Data bytes of a valid data packet
#define	UDPACCEL_TEST_JUNK_SIZE		100		// Bytes of a flood datagram
#define	UDPACCEL_TEST_EXTRA			10		// Flood datagrams beyond the whole budgets

// Run state of the test
typedef struct UDPACCEL_TEST
{
	UINT NumChecks;						// Checks run so far
	UINT NumFailed;						// Checks failed so far
	CEDAR *Cedar;						// Owner of the UDP_ACCEL objects
	IP Localhost;						// 127.0.0.1
	UDP_ACCEL *Recv;					// Receiving end: the test polls it
	UDP_ACCEL *Peer;					// Sending end of the valid packets
	SOCK *Flood;						// Plain UDP socket that sends the datagrams that are no packets of Recv
	UINT64 PeerTick;					// Tick of the last packet of Peer
} UDPACCEL_TEST;

// Record one check: print [PASS], or [FAIL] with the formatted detail
static bool UdpAccelTestCheck(UDPACCEL_TEST *t, bool ok, char *what, char *detail_fmt, ...)
{
	char detail[MAX_SIZE];
	va_list args;

	t->NumChecks++;

	if (ok)
	{
		Print("  [PASS] %s\n", what);
		return true;
	}

	va_start(args, detail_fmt);
	FormatArgs(detail, sizeof(detail), detail_fmt, args);
	va_end(args);

	Print("  [FAIL] %s (%s)\n", what, detail);

	t->NumFailed++;

	return false;
}

// Datagrams that Recv has dropped so far
static UINT64 UdpAccelTestDrops(UDPACCEL_TEST *t)
{
	return t->Recv->NumDropShort + t->Recv->NumDropInvalid;
}

// Free the two ends and the flood socket
static void UdpAccelTestClose(UDPACCEL_TEST *t)
{
	FreeUdpAccel(t->Recv);
	FreeUdpAccel(t->Peer);
	ReleaseSock(t->Flood);

	t->Recv = NULL;
	t->Peer = NULL;
	t->Flood = NULL;
}

// Open both ends in the given mode as the session setup of Protocol.c does (Peer in the server
// role, Recv in the client role) and the flood socket. Returns false when a socket cannot be opened.
static bool UdpAccelTestOpen(UDPACCEL_TEST *t, UINT version, bool plain_text)
{
	SOCKSET set;

	t->Recv = NewUdpAccel(t->Cedar, &t->Localhost, true, true);
	t->Peer = NewUdpAccel(t->Cedar, &t->Localhost, true, true);
	t->Flood = NewUDPEx3(0, &t->Localhost);
	if (t->Recv == NULL || t->Peer == NULL || t->Flood == NULL)
	{
		return false;
	}

	t->Recv->Version = version;
	t->Peer->Version = version;

	if (UdpAccelInitServer(t->Peer, version > 1 ? t->Recv->MyKey_V2 : t->Recv->MyKey,
		&t->Localhost, &t->Localhost, t->Recv->MyPort) == false)
	{
		return false;
	}

	if (UdpAccelInitClient(t->Recv, version > 1 ? t->Peer->MyKey_V2 : t->Peer->MyKey,
		&t->Localhost, &t->Localhost, t->Peer->MyPort, t->Peer->MyCookie, t->Peer->YourCookie) == false)
	{
		return false;
	}

	t->Recv->PlainTextMode = plain_text;
	t->Peer->PlainTextMode = plain_text;

	// Select() puts the socket in non-blocking mode, as in the session loop; with a timeout of 0 it returns at once
	InitSockSet(&set);
	AddSockSet(&set, t->Recv->UdpSock);
	Select(&set, 0, NULL, NULL);

	t->PeerTick = Tick64();

	return true;
}

// Send one valid packet from Peer to Recv: data_size bytes of data, padded to at most max_size bytes
static void UdpAccelTestSendValid(UDPACCEL_TEST *t, UCHAR *data, UINT data_size, UINT max_size)
{
	t->PeerTick++;
	UdpAccelSetTick(t->Peer, t->PeerTick);
	UdpAccelSend(t->Peer, data, data_size, 0, max_size);
}

// Send num datagrams of size bytes that are no packets of Recv from the flood socket
static void UdpAccelTestSendJunk(UDPACCEL_TEST *t, UINT num, UINT size)
{
	UCHAR buf[UDP_ACCELERATION_TMP_BUF_SIZE];
	UINT i;

	Rand(buf, sizeof(buf));

	// The cookie leads a plain text packet: never the cookie of Recv
	buf[0] = (UCHAR)((t->Recv->MyCookie >> 24) ^ 0xff);

	for (i = 0; i < num; i++)
	{
		SendTo(t->Flood, &t->Localhost, t->Recv->MyPort, buf, size);
	}
}

// Let the datagrams arrive, then poll Recv once at the given tick
static void UdpAccelTestPoll(UDPACCEL_TEST *t, UINT64 tick)
{
	SleepThread(UDPACCEL_TEST_WAIT);

	UdpAccelSetTick(t->Recv, tick);
	UdpAccelPoll(t->Recv);
}

// The checks of one packet format: the smallest valid packet, a data packet and the two kinds of drop
static void UdpAccelTestFormat(UDPACCEL_TEST *t, char *mode, UINT version, bool plain_text, UINT min_size)
{
	UCHAR data[UDPACCEL_TEST_DATA_SIZE];
	char what[MAX_SIZE];
	UINT64 drop_short, drop_invalid;
	BLOCK *b;

	if (UdpAccelTestOpen(t, version, plain_text) == false)
	{
		Format(what, sizeof(what), "%s: loopback sockets open", mode);
		UdpAccelTestCheck(t, false, what, "NewUdpAccel, UdpAccelInit or NewUDPEx3 failed");
		UdpAccelTestClose(t);
		return;
	}

	// (1) The smallest valid packet (no data, and no padding because max_size is its size) is accepted
	UdpAccelTestSendValid(t, NULL, 0, min_size);
	UdpAccelTestPoll(t, Tick64());
	Format(what, sizeof(what), "%s: the smallest valid packet (%u bytes) is accepted", mode, min_size);
	UdpAccelTestCheck(t, UdpAccelTestDrops(t) == 0 && t->Recv->LastRecvYourTick == t->PeerTick, what,
		"%I64u dropped, last tick %I64u, expected %I64u", UdpAccelTestDrops(t), t->Recv->LastRecvYourTick, t->PeerTick);

	// (2) A data packet with padding arrives with its data
	Rand(data, sizeof(data));
	UdpAccelTestSendValid(t, data, sizeof(data), t->Peer->MaxUdpPacketSize);
	UdpAccelTestPoll(t, Tick64());
	b = GetNext(t->Recv->RecvBlockQueue);
	Format(what, sizeof(what), "%s: a data packet arrives with its data", mode);
	UdpAccelTestCheck(t, b != NULL && b->Size == sizeof(data) && Cmp(b->Buf, data, sizeof(data)) == 0 &&
		UdpAccelTestDrops(t) == 0, what, "block %s, size %u, %I64u dropped",
		b == NULL ? "missing" : "present", b == NULL ? 0 : b->Size, UdpAccelTestDrops(t));
	FreeBlock(b);

	// (3) One byte shorter than the smallest packet: dropped by the header check before decryption
	drop_short = t->Recv->NumDropShort;
	drop_invalid = t->Recv->NumDropInvalid;
	UdpAccelTestSendJunk(t, 1, min_size - 1);
	UdpAccelTestPoll(t, Tick64());
	Format(what, sizeof(what), "%s: a datagram of %u bytes is dropped before decryption (NumDropShort)", mode, min_size - 1);
	UdpAccelTestCheck(t, t->Recv->NumDropShort == drop_short + 1 && t->Recv->NumDropInvalid == drop_invalid, what,
		"NumDropShort +%I64u, NumDropInvalid +%I64u", t->Recv->NumDropShort - drop_short, t->Recv->NumDropInvalid - drop_invalid);

	// (4) As long as the smallest packet but not one: dropped after decryption or the cookie check
	drop_short = t->Recv->NumDropShort;
	drop_invalid = t->Recv->NumDropInvalid;
	UdpAccelTestSendJunk(t, 1, min_size);
	UdpAccelTestPoll(t, Tick64());
	Format(what, sizeof(what), "%s: an invalid datagram of %u bytes is dropped (NumDropInvalid)", mode, min_size);
	UdpAccelTestCheck(t, t->Recv->NumDropShort == drop_short && t->Recv->NumDropInvalid == drop_invalid + 1, what,
		"NumDropShort +%I64u, NumDropInvalid +%I64u", t->Recv->NumDropShort - drop_short, t->Recv->NumDropInvalid - drop_invalid);

	UdpAccelTestClose(t);
}

// The receive budget per poll and per tick, and the log entry of the drop counters (version 2)
static void UdpAccelTestFlood(UDPACCEL_TEST *t)
{
	UINT per_poll = UDP_ACCELERATION_MAX_RECV_PER_POLL;
	UINT per_tick = UDP_ACCELERATION_MAX_RECV_PER_TICK;
	UCHAR data[UDPACCEL_TEST_DATA_SIZE];
	wchar_t log[MAX_SIZE];
	UINT64 drops, limit, tick;
	BLOCK *b;
	UINT i;

	if (UdpAccelTestOpen(t, 2, false) == false)
	{
		UdpAccelTestCheck(t, false, "flood: loopback sockets open", "NewUdpAccel, UdpAccelInit or NewUDPEx3 failed");
		UdpAccelTestClose(t);
		return;
	}

	// (1) Two budgets and a bit of invalid datagrams, then a valid packet behind them
	UdpAccelTestSendJunk(t, per_poll * 2 + UDPACCEL_TEST_EXTRA, UDPACCEL_TEST_JUNK_SIZE);
	Rand(data, sizeof(data));
	UdpAccelTestSendValid(t, data, sizeof(data), t->Peer->MaxUdpPacketSize);

	drops = UdpAccelTestDrops(t);
	limit = t->Recv->NumRecvLimit;
	tick = Tick64();

	UdpAccelTestPoll(t, tick);
	UdpAccelTestCheck(t, UdpAccelTestDrops(t) - drops == per_poll && t->Recv->NumRecvLimit - limit == 1 &&
		t->Recv->RecvBlockQueue->num_item == 0,
		"flood: one poll reads UDP_ACCELERATION_MAX_RECV_PER_POLL datagrams and stops (the old loop read the whole flood)",
		"%I64u read of %u, NumRecvLimit +%I64u, %u blocks", UdpAccelTestDrops(t) - drops, per_poll * 2 + UDPACCEL_TEST_EXTRA + 1,
		t->Recv->NumRecvLimit - limit, t->Recv->RecvBlockQueue->num_item);

	UdpAccelTestPoll(t, tick);
	UdpAccelTestCheck(t, UdpAccelTestDrops(t) - drops == per_poll * 2 && t->Recv->NumRecvLimit - limit == 2,
		"flood: the next poll reads the next UDP_ACCELERATION_MAX_RECV_PER_POLL datagrams",
		"%I64u read, NumRecvLimit +%I64u", UdpAccelTestDrops(t) - drops, t->Recv->NumRecvLimit - limit);

	UdpAccelTestPoll(t, tick);
	b = GetNext(t->Recv->RecvBlockQueue);
	UdpAccelTestCheck(t, UdpAccelTestDrops(t) - drops == per_poll * 2 + UDPACCEL_TEST_EXTRA && t->Recv->NumRecvLimit - limit == 2 &&
		b != NULL && b->Size == sizeof(data) && Cmp(b->Buf, data, sizeof(data)) == 0,
		"flood: the poll that empties the socket stops below the budget and the valid packet behind the flood arrives",
		"%I64u dropped, NumRecvLimit +%I64u, block %s", UdpAccelTestDrops(t) - drops, t->Recv->NumRecvLimit - limit,
		b == NULL ? "missing" : "present");
	FreeBlock(b);

	// (2) More than one tick's budget: the polls of one tick stop at it, the next tick reads on
	UdpAccelTestSendJunk(t, per_tick + UDPACCEL_TEST_EXTRA, UDPACCEL_TEST_JUNK_SIZE);

	drops = UdpAccelTestDrops(t);
	limit = t->Recv->NumRecvLimit;
	tick += 1000;

	UdpAccelTestPoll(t, tick);
	for (i = 0; i < per_tick / per_poll + 3; i++)
	{
		UdpAccelPoll(t->Recv);
	}
	UdpAccelTestCheck(t, UdpAccelTestDrops(t) - drops == per_tick && t->Recv->NumRecvLimit - limit >= per_tick / per_poll &&
		UdpAccelIsRecvBudgetSpent(t->Recv),
		"flood: the polls of one tick read UDP_ACCELERATION_MAX_RECV_PER_TICK datagrams (the old loop read the whole flood)",
		"%I64u read of %u, NumRecvLimit +%I64u", UdpAccelTestDrops(t) - drops, per_tick + UDPACCEL_TEST_EXTRA,
		t->Recv->NumRecvLimit - limit);

	tick++;
	UdpAccelTestPoll(t, tick);
	UdpAccelTestCheck(t, UdpAccelTestDrops(t) - drops == per_tick + UDPACCEL_TEST_EXTRA &&
		UdpAccelIsRecvBudgetSpent(t->Recv) == false,
		"flood: the next tick reads the rest",
		"%I64u read of %u", UdpAccelTestDrops(t) - drops, per_tick + UDPACCEL_TEST_EXTRA);

	// (3) The log entry of the drop counters: at once for the first drops, then at most once per interval
	tick++;
	UdpAccelSetTick(t->Recv, tick);
	UdpAccelTestCheck(t, UdpAccelLogDrops(t->Recv, NULL, "UDPACCEL_TEST", false),
		"log: the first drops are written at once", "no entry");
	UdpAccelTestCheck(t, UdpAccelLogDrops(t->Recv, NULL, "UDPACCEL_TEST", false) == false &&
		UdpAccelLogDrops(t->Recv, NULL, "UDPACCEL_TEST", true) == false,
		"log: no entry without new drops, also not at the end of the session", "entry written");

	UdpAccelTestSendJunk(t, 1, 1);
	UdpAccelTestPoll(t, tick + 1);
	UdpAccelTestCheck(t, UdpAccelLogDrops(t->Recv, NULL, "UDPACCEL_TEST", false) == false,
		"log: new drops within UDP_ACCELERATION_DROP_LOG_INTERVAL wait", "entry written");

	UdpAccelSetTick(t->Recv, tick + UDP_ACCELERATION_DROP_LOG_INTERVAL);
	UdpAccelTestCheck(t, UdpAccelLogDrops(t->Recv, NULL, "UDPACCEL_TEST", false),
		"log: new drops are written after UDP_ACCELERATION_DROP_LOG_INTERVAL", "no entry");

	UdpAccelTestSendJunk(t, 1, 1);
	UdpAccelTestPoll(t, tick + UDP_ACCELERATION_DROP_LOG_INTERVAL + 1);
	UdpAccelTestCheck(t, UdpAccelLogDrops(t->Recv, NULL, "UDPACCEL_TEST", true),
		"log: at the end of the session new drops are written without waiting", "no entry");

	// The string of the entry carries the session name and the three counters
	UniFormat(log, sizeof(log), _UU("LH_UDP_ACCEL_DROP"), "UDPACCEL_TEST", (UINT64)111, (UINT64)222, (UINT64)333);
	UdpAccelTestCheck(t, UniSearchStr(log, L"UDPACCEL_TEST", 0) != INFINITE && UniSearchStr(log, L"111", 0) != INFINITE &&
		UniSearchStr(log, L"222", 0) != INFINITE && UniSearchStr(log, L"333", 0) != INFINITE,
		"log: the string LH_UDP_ACCEL_DROP holds the session name and the counters", "string missing or incomplete");

	UdpAccelTestClose(t);
}

// Stub random source of the cookie check: 5, then 0 and 5 that UdpAccelNewCookies must skip, then 7
static UINT udpaccel_test_rand_index = 0;
static UINT UdpAccelTestRand32(void)
{
	static const UINT seq[] = {5, 0, 5, 7};

	return seq[udpaccel_test_rand_index++ % (sizeof(seq) / sizeof(seq[0]))];
}

// The cookie pair: YourCookie is never 0 and never MyCookie (FND-60; the old loop tested MyCookie twice)
static void UdpAccelTestCookies(UDPACCEL_TEST *t)
{
	UINT my_cookie, your_cookie;

	udpaccel_test_rand_index = 0;
	UdpAccelNewCookies(&my_cookie, &your_cookie, UdpAccelTestRand32);
	UdpAccelTestCheck(t, my_cookie == 5 && your_cookie == 7,
		"cookies: a drawn 0 or MyCookie is skipped for YourCookie", "MyCookie %u, YourCookie %u", my_cookie, your_cookie);
}

// udpaccel: bounded receive loop and drop counters of the UDP Acceleration
void udpaccel_test(UINT num, char **arg)
{
	UDPACCEL_TEST t;

	Zero(&t, sizeof(t));

	Print("UDP Acceleration receive test\n");

	UdpAccelTestCookies(&t);

	t.Cedar = NewCedar(NULL, NULL);
	SetIP(&t.Localhost, 127, 0, 0, 1);

	UdpAccelTestFormat(&t, "plain text", 1, true, UDPACCEL_TEST_HEADER_SIZE);
	UdpAccelTestFormat(&t, "version 1", 1, false,
		UDP_ACCELERATION_PACKET_IV_SIZE_V1 + UDPACCEL_TEST_HEADER_SIZE + UDP_ACCELERATION_PACKET_IV_SIZE_V1);
	UdpAccelTestFormat(&t, "version 2", 2, false,
		UDP_ACCELERATION_PACKET_IV_SIZE_V2 + UDPACCEL_TEST_HEADER_SIZE + UDP_ACCELERATION_PACKET_MAC_SIZE_V2);
	UdpAccelTestFlood(&t);

	ReleaseCedar(t.Cedar);

	if (t.NumFailed == 0)
	{
		Print("UDPACCEL TEST OK\n");
	}
	else
	{
		Print("UDPACCEL TEST FAILED (%u of %u checks failed)\n", t.NumFailed, t.NumChecks);
	}
}
