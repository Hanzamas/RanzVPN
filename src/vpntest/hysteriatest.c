// hysteriatest.c
// Named Hysteria mode test of vpntest ("hysteria" command, CORE-P2-4 #95)
//
// hysteria: the Hysteria mode of the mimic transport (ADR-0023 amendment of 2026-10-15), the mode of the sidecar ranz mimic
// for a link that loses many packets (controller/internal/mimic/hysteria.go), against the QUIC transport of the core, msquic
// with BBR, on the same lossy link, with the real ranz.exe next to vpntest.exe as the mimic test runs it.
// - The lossy link is a UDP relay on 127.0.0.1 between the clients that send to its port and one server: a bottleneck of
//   HYSTERIATEST_RATE whose queue drops at its tail what would wait longer than HYSTERIATEST_QUEUE, HYSTERIATEST_DELAY of
//   delay in each direction (a round trip of 150 ms), and HYSTERIATEST_LOSS of the datagrams lost at random in each
//   direction. Each transport gets a link of its own, with the same settings and the same generator of the losses.
// - msquic with BBR: a client of the QUIC transport dials a QUIC listener through the link and writes into one stream.
// - The Hysteria mode: a server node whose MimicServer setting has a hysteria part with Salamander, and an own decoy whose
//   certificate ranz cert made; a client node whose MimicClient link dials that listener through the link, with the pin of
//   the certificate and Brutal at the rate that the link carries. Both nodes use the mimic transport as it is, so the core
//   has no code of its own for the mode. A Noise session of the two nodes over a stream of the transport: the handshake,
//   with the same binding at both ends, the SHA-256 of the certificate, and a control record both ways.
// - The goodput of each: the client writes into one stream for HYSTERIATEST_RUN ms, at most HYSTERIATEST_WINDOW bytes ahead
//   of what the server read, and the goodput is what the server read after HYSTERIATEST_WARMUP. The Hysteria mode must
//   carry at least HYSTERIATEST_FACTOR percent of the goodput of msquic with BBR.
// Print "HYSTERIA TEST OK" only when every check passes.

#include "testlist.h"

#include "Cedar/Cedar.h"
#include "Cedar/ConfigStore.h"
#include "Cedar/Node.h"

#include "Mayaqua/Encrypt.h"
#include "Mayaqua/FileIO.h"
#include "Mayaqua/Internat.h"
#include "Mayaqua/Kernel.h"
#include "Mayaqua/Memory.h"
#include "Mayaqua/Microsoft.h"
#include "Mayaqua/Str.h"
#include "Mayaqua/Tick64.h"

#include "Core/Crypto.h"
#include "Core/Transport.h"

#include <WS2tcpip.h>

#include <stdio.h>

#define	HYSTERIATEST_BUDGET		300000		// The whole test ends within this time, or the watchdog ends the process (ms)
#define	HYSTERIATEST_BOUND		90000		// A bounded wait on observable state: a server sidecar first probes its decoy (ms)
#define	HYSTERIATEST_TIMEOUT	30000		// A dial, an accept, a handshake or a record within this time, over the lossy link (ms)
#define	HYSTERIATEST_RUN_WAIT	120000		// A command that the test runs ends within this time (ms)
#define	HYSTERIATEST_DIALS		3			// The dials of a stream at most: a handshake over the lossy link may lose its packets
#define	HYSTERIATEST_RATE		20000000	// The rate of the bottleneck of the link (bit/s)
#define	HYSTERIATEST_DELAY		75000		// The delay of each direction (us): a round trip of 150 ms
#define	HYSTERIATEST_LOSS		1000		// The datagrams that the link loses at random in each direction, in 1/10000: 10%
#define	HYSTERIATEST_QUEUE		50000		// The queue of the bottleneck, in us at its rate: what would wait longer is dropped
#define	HYSTERIATEST_SEED		0x2545F491	// The generator of the losses
#define	HYSTERIATEST_BRUTAL		18			// The rate of Brutal of the link (Mbit/s): what the link delivers, 20 Mbit/s less 10%
#define	HYSTERIATEST_WARMUP		5000		// The bulk write runs this long before its goodput counts (ms) ...
#define	HYSTERIATEST_RUN		25000		// ... and this long in all (ms)
#define	HYSTERIATEST_WINDOW		(8 * 1024 * 1024)	// The bytes that the writer is ahead of the reader at most
#define	HYSTERIATEST_CHUNK		65536		// One write and one read (bytes)
#define	HYSTERIATEST_FACTOR		150			// The goodput of the Hysteria mode at least, in percent of the goodput of msquic
#define	HYSTERIATEST_DATAGRAM	2048		// The largest datagram that the link carries (bytes)
#define	HYSTERIATEST_SLOTS		1024		// The datagrams that one direction of the link holds at most
#define	HYSTERIATEST_LOSS_MIN	80			// The losses that the link measured in a run, in 1/1000 of what its bottleneck sent ...
#define	HYSTERIATEST_LOSS_MAX	120			// ... at most
#define	HYSTERIATEST_NAME		"hysteria.test"
#define	HYSTERIATEST_PAGE		"ranz mimic decoy page of the Hysteria test of the vpntest harness"
#define	HYSTERIATEST_QUIC_CN	L"CN=hysteria-quic.test"	// The certificate of the QUIC listener
#define	HYSTERIATEST_QUIC_SAN	L"hysteria-quic.test"

// The secret of the client and the key of Salamander of the mode, and the REALITY key pair of the server role that the mode
// runs beside: the key pair of Alice of RFC 7748 section 6.1, as in the mimic test
#define	HYSTERIATEST_SECRET		"5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a"
#define	HYSTERIATEST_SALAMANDER	"c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3"
#define	HYSTERIATEST_PRIVATE	"77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"

// The checks of the test
typedef struct HYSTERIATEST_CTX
{
	UINT NumChecks;						// Checks run so far
	UINT NumFailed;						// Checks failed so far
} HYSTERIATEST_CTX;

// A datagram on its way through one direction of the link
typedef struct HYSTERIATEST_PACKET
{
	UINT64 Due;							// When it reaches the other end (us of TransportQueueNow)
	UINT Size;							// Its bytes ...
	UCHAR Data[HYSTERIATEST_DATAGRAM];
} HYSTERIATEST_PACKET;

// One direction of the link
typedef struct HYSTERIATEST_WAY
{
	HYSTERIATEST_PACKET *Ring;			// The datagrams on their way, oldest first ...
	UINT Head;							// ... from this slot
	UINT Num;							// ... this many
	UINT64 LinkFree;					// When the bottleneck has sent what it took (us)
	UINT Rand;							// The generator of the losses (xorshift32)
	UINT64 NumIn;						// Datagrams that came ...
	UINT64 NumDropped;					// ... that the queue of the bottleneck dropped at its tail
	UINT64 NumLost;						// ... that the link lost at random after the bottleneck sent them
	UINT64 NumOut;						// ... that reached the other end
} HYSTERIATEST_WAY;

// The lossy link: a UDP relay on 127.0.0.1 between the clients that send to its port and one server
typedef struct HYSTERIATEST_LINK
{
	SOCKET Outside;						// 127.0.0.1:Port, which the client sends to
	SOCKET Inside;						// The socket that sends to the server
	WSAEVENT OutsideEvent;				// The sockets have datagrams to read
	WSAEVENT InsideEvent;
	HANDLE Timer;						// The next datagram is due
	HANDLE Stop;						// Ends the thread
	SOCKADDR_IN Server;					// The server
	SOCKADDR_IN Client;					// The client that sent last, which the answers of the server go to
	bool HaveClient;
	USHORT Port;						// The port of Outside
	HYSTERIATEST_WAY Up;				// Client to server
	HYSTERIATEST_WAY Down;				// Server to client
	THREAD *Thread;						// Carries the datagrams
} HYSTERIATEST_LINK;

// A bulk write of the client and the reads of the server
typedef struct HYSTERIATEST_BULK
{
	TRANSPORT_STREAM *Stream;			// The stream of the client
	volatile LONG64 Written;			// The bytes that the client wrote ...
	volatile LONG64 Read;				// ... and those that the server read
	volatile LONG Stop;					// The writer stops
	bool Failed;						// A write failed
} HYSTERIATEST_BULK;

// The server end of the Noise session, on a thread of its own
typedef struct HYSTERIATEST_SERVER
{
	TRANSPORT_LISTENER *Listener;		// It accepts one stream here
	NOISE_SESSION_CONFIG Config;		// The responder's configuration
	bool Got;							// A stream came
	UINT BindingType;					// The channel binding of the stream
	UCHAR Binding[NOISE_MAX_BINDING];
	UINT BindingSize;
	bool Accepted;						// The handshake completed
	bool Echoed;						// The control record of the client went back
} HYSTERIATEST_SERVER;

static bool HysteriaTestCheck(HYSTERIATEST_CTX *ctx, bool ok, char *what, char *fmt, ...) RANZ_PRINTF_FORMAT(4, 5);
static bool HysteriaTestCheck(HYSTERIATEST_CTX *ctx, bool ok, char *what, char *fmt, ...)
{
	char detail[MAX_SIZE * 4];
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

// The watchdog: a native thread that ends a run that hangs
static DWORD WINAPI HysteriaTestWatchdog(LPVOID param)
{
	char msg[MAX_SIZE];
	DWORD written = 0;

	if (WaitForSingleObject((HANDLE)param, HYSTERIATEST_BUDGET) != WAIT_TIMEOUT)
	{
		return 0;
	}

	int len = snprintf(msg, sizeof(msg), "HYSTERIA TEST FAILED (did not finish within %u ms)\n", HYSTERIATEST_BUDGET);
	if (len > 0)
	{
		WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), msg, (DWORD)MIN((UINT)len, (UINT)sizeof(msg) - 1), &written, NULL);
	}

	TerminateProcess(GetCurrentProcess(), 1);

	return 0;
}

//
// The data directories and the processes
//

// A new empty data directory under the temp directory of the process
static void HysteriaTestNewDir(wchar_t *dir, UINT size, char *name)
{
	wchar_t tmp[MAX_PATH];

	UniFormat(tmp, sizeof(tmp), L"hysteria_%S_%u", name, (UINT)Tick64());
	ConbinePathW(dir, size, MsGetMyTempDirW(), tmp);
	MakeDirExW(dir);
}

// Delete a directory with everything in it
static void HysteriaTestDeleteTree(wchar_t *dir)
{
	DIRLIST *d = EnumDirW(dir);

	for (UINT i = 0;d != NULL && i < d->NumFiles;i++)
	{
		DIRENT *e = d->File[i];
		wchar_t path[MAX_PATH];

		ConbinePathW(path, sizeof(path), dir, e->FileNameW);
		if (e->Folder)
		{
			HysteriaTestDeleteTree(path);
		}
		else
		{
			FileDeleteW(path);
		}
	}

	FreeDir(d);
	DeleteDirW(dir);
}

// Write the configuration store of a data directory: no role, and the mimic settings (none for NULL)
static void HysteriaTestWriteConfig(wchar_t *dir, char *server, char *client)
{
	wchar_t path[MAX_PATH];

	ConbinePathW(path, sizeof(path), dir, CS_FILE_NAME);
	CONFIG_STORE *s = CsOpen(path);

	if (s == NULL)
	{
		Print("  configuration store %S cannot be opened\n", path);
		return;
	}

	CsSetSetting(s, NODE_SETTING_ROLES, "none");
	if (server != NULL)
	{
		CsSetSetting(s, NODE_SETTING_MIMIC_SERVER, server);
	}
	if (client != NULL)
	{
		CsSetSetting(s, NODE_SETTING_MIMIC_CLIENT, client);
	}

	CsClose(s);
}

// Run a command line and wait for it; its exit code, or INFINITE when it could not start or did not end in time
static UINT HysteriaTestRun(wchar_t *cmd)
{
	STARTUPINFOW si;
	PROCESS_INFORMATION pi;
	DWORD code = INFINITE;

	Zero(&si, sizeof(si));
	si.cb = sizeof(si);
	Zero(&pi, sizeof(pi));

	if (CreateProcessW(NULL, cmd, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi) == FALSE)
	{
		return INFINITE;
	}

	if (WaitForSingleObject(pi.hProcess, HYSTERIATEST_RUN_WAIT) == WAIT_OBJECT_0)
	{
		GetExitCodeProcess(pi.hProcess, &code);
	}
	else
	{
		TerminateProcess(pi.hProcess, 1);
	}

	CloseHandle(pi.hThread);
	CloseHandle(pi.hProcess);

	return (UINT)code;
}

// A path of the test as JSON takes it without escapes: its backslashes as slashes, which Windows takes as well
static void HysteriaTestJsonPath(char *dst, UINT size, wchar_t *path)
{
	UniToStr(dst, size, path);
	for (UINT i = 0;dst[i] != 0;i++)
	{
		if (dst[i] == '\\')
		{
			dst[i] = '/';
		}
	}
}

// The pin of the certificate in a PEM file: the SHA-256 of its DER, as bytes and as hex digits. False when the file holds
// no certificate.
static bool HysteriaTestPin(wchar_t *path, UCHAR *pin, char *hex, UINT hex_size)
{
	BUF *b = ReadDumpW(path);
	DWORD der_size = 0;
	bool ret = false;

	if (b == NULL)
	{
		return false;
	}

	// CryptStringToBinaryA reads the base64 between the lines of the PEM header and footer
	if (CryptStringToBinaryA((char *)b->Buf, b->Size, CRYPT_STRING_BASE64HEADER, NULL, &der_size, NULL, NULL) && der_size != 0)
	{
		UCHAR *der = Malloc(der_size);

		if (CryptStringToBinaryA((char *)b->Buf, b->Size, CRYPT_STRING_BASE64HEADER, der, &der_size, NULL, NULL) && CryptoSha256(pin, der, der_size))
		{
			BinToStr(hex, hex_size, pin, CRYPTO_SHA256_SIZE);
			ret = true;
		}
		Free(der);
	}

	FreeBuf(b);

	return ret;
}

// A UDP port of 127.0.0.1 that nothing holds now; 0 when there is none
static USHORT HysteriaTestFreePort()
{
	SOCKET s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	SOCKADDR_IN sa;
	int sa_size = sizeof(sa);
	USHORT port = 0;

	Zero(&sa, sizeof(sa));
	sa.sin_family = AF_INET;
	sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

	if (s != INVALID_SOCKET && bind(s, (SOCKADDR *)&sa, sizeof(sa)) == 0 && getsockname(s, (SOCKADDR *)&sa, &sa_size) == 0)
	{
		port = ntohs(sa.sin_port);
	}
	if (s != INVALID_SOCKET)
	{
		closesocket(s);
	}

	return port;
}

//
// The lossy link
//

// The next number of the generator of a direction
static UINT HysteriaTestRand(HYSTERIATEST_WAY *w)
{
	UINT x = w->Rand;

	x ^= x << 13;
	x ^= x >> 17;
	x ^= x << 5;
	w->Rand = x;

	return x;
}

// A datagram that came at now goes its way: the bottleneck sends one datagram after the other at its rate and drops at the
// tail of its queue, then the link loses some of what the bottleneck sent, and the rest arrives a delay later
static void HysteriaTestLinkPut(HYSTERIATEST_WAY *w, const UCHAR *data, UINT size, UINT64 now)
{
	UINT64 start = MAX(now, w->LinkFree);

	w->NumIn++;

	if (size > HYSTERIATEST_DATAGRAM || start - now > HYSTERIATEST_QUEUE || w->Num >= HYSTERIATEST_SLOTS)
	{
		w->NumDropped++;
		return;
	}
	w->LinkFree = start + (UINT64)size * 8 * 1000000 / HYSTERIATEST_RATE;

	if (HysteriaTestRand(w) % 10000 < HYSTERIATEST_LOSS)
	{
		w->NumLost++;
		return;
	}

	HYSTERIATEST_PACKET *p = &w->Ring[(w->Head + w->Num) % HYSTERIATEST_SLOTS];
	p->Due = w->LinkFree + HYSTERIATEST_DELAY;
	p->Size = size;
	Copy(p->Data, data, size);
	w->Num++;
}

// The datagrams of a direction that are due at now leave on socket s for to; nowhere while there is no to
static void HysteriaTestLinkSend(HYSTERIATEST_WAY *w, SOCKET s, const SOCKADDR_IN *to, bool have_to, UINT64 now)
{
	while (w->Num != 0 && w->Ring[w->Head].Due <= now)
	{
		HYSTERIATEST_PACKET *p = &w->Ring[w->Head];

		if (have_to)
		{
			sendto(s, (const char *)p->Data, (int)p->Size, 0, (const SOCKADDR *)to, sizeof(SOCKADDR_IN));
			w->NumOut++;
		}
		w->Head = (w->Head + 1) % HYSTERIATEST_SLOTS;
		w->Num--;
	}
}

// The datagrams that wait on socket s go their way w. What comes from the outside comes from the client, whose address the
// answers of the server go to.
static void HysteriaTestLinkTake(HYSTERIATEST_LINK *k, SOCKET s, WSAEVENT e, HYSTERIATEST_WAY *w, bool outside, UCHAR *buf)
{
	WSAResetEvent(e);

	while (true)
	{
		SOCKADDR_IN from;
		int from_size = sizeof(from);
		int n = recvfrom(s, (char *)buf, HYSTERIATEST_DATAGRAM, 0, (SOCKADDR *)&from, &from_size);

		if (n < 0)
		{
			int err = WSAGetLastError();

			// A datagram larger than the link takes is dropped, and so is the report of a port that nothing held
			if (err == WSAEMSGSIZE || err == WSAECONNRESET)
			{
				continue;
			}
			return;
		}

		if (outside)
		{
			Copy(&k->Client, &from, sizeof(SOCKADDR_IN));
			k->HaveClient = true;
		}
		HysteriaTestLinkPut(w, buf, (UINT)n, TransportQueueNow());
	}
}

// The thread of the link: it takes the datagrams of both sockets as they come, and lets each out when it is due
static void HysteriaTestLinkThread(THREAD *thread, void *param)
{
	HYSTERIATEST_LINK *k = (HYSTERIATEST_LINK *)param;
	HANDLE waits[4] = {k->Stop, k->OutsideEvent, k->InsideEvent, k->Timer};
	UCHAR *buf = Malloc(HYSTERIATEST_DATAGRAM);

	while (true)
	{
		UINT64 now = TransportQueueNow();
		UINT64 next = 0;

		HysteriaTestLinkSend(&k->Up, k->Inside, &k->Server, true, now);
		HysteriaTestLinkSend(&k->Down, k->Outside, &k->Client, k->HaveClient, now);

		// The timer goes off when the next datagram is due
		if (k->Up.Num != 0)
		{
			next = k->Up.Ring[k->Up.Head].Due;
		}
		if (k->Down.Num != 0 && (next == 0 || k->Down.Ring[k->Down.Head].Due < next))
		{
			next = k->Down.Ring[k->Down.Head].Due;
		}
		if (next != 0)
		{
			LARGE_INTEGER due;

			// A time relative to now, in units of 100 ns
			due.QuadPart = -(LONGLONG)((MAX(next, now + 1) - now) * 10);
			SetWaitableTimer(k->Timer, &due, 0, NULL, NULL, FALSE);
		}

		if (WaitForMultipleObjects(4, waits, FALSE, (next != 0 ? INFINITE : 1000)) == WAIT_OBJECT_0)
		{
			break;
		}

		HysteriaTestLinkTake(k, k->Outside, k->OutsideEvent, &k->Up, true, buf);
		HysteriaTestLinkTake(k, k->Inside, k->InsideEvent, &k->Down, false, buf);
	}

	Free(buf);
}

// Free a link whose thread stopped
static void HysteriaTestLinkFree(HYSTERIATEST_LINK *k)
{
	if (k->Outside != INVALID_SOCKET)
	{
		closesocket(k->Outside);
	}
	if (k->Inside != INVALID_SOCKET)
	{
		closesocket(k->Inside);
	}
	if (k->OutsideEvent != WSA_INVALID_EVENT)
	{
		WSACloseEvent(k->OutsideEvent);
	}
	if (k->InsideEvent != WSA_INVALID_EVENT)
	{
		WSACloseEvent(k->InsideEvent);
	}
	if (k->Timer != NULL)
	{
		CloseHandle(k->Timer);
	}
	if (k->Stop != NULL)
	{
		CloseHandle(k->Stop);
	}
	Free(k->Up.Ring);
	Free(k->Down.Ring);
	Free(k);
}

// Start a lossy link to the server at 127.0.0.1:server_port; NULL when its sockets cannot be made
static HYSTERIATEST_LINK *HysteriaTestLinkStart(USHORT server_port)
{
	HYSTERIATEST_LINK *k = ZeroMalloc(sizeof(HYSTERIATEST_LINK));
	SOCKADDR_IN sa;
	int sa_size = sizeof(sa);
	int buffer = 4 * 1024 * 1024;

	k->Outside = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	k->Inside = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	k->OutsideEvent = WSACreateEvent();
	k->InsideEvent = WSACreateEvent();
	k->Stop = CreateEventW(NULL, TRUE, FALSE, NULL);
	// A timer of high resolution, so that a datagram leaves within a ms of its time
	k->Timer = CreateWaitableTimerExW(NULL, NULL, CREATE_WAITABLE_TIMER_HIGH_RESOLUTION, TIMER_ALL_ACCESS);
	if (k->Timer == NULL)
	{
		k->Timer = CreateWaitableTimerW(NULL, FALSE, NULL);
	}
	k->Up.Ring = ZeroMalloc(sizeof(HYSTERIATEST_PACKET) * HYSTERIATEST_SLOTS);
	k->Down.Ring = ZeroMalloc(sizeof(HYSTERIATEST_PACKET) * HYSTERIATEST_SLOTS);
	k->Up.Rand = HYSTERIATEST_SEED;
	k->Down.Rand = HYSTERIATEST_SEED ^ 0x5BD1E995;

	k->Server.sin_family = AF_INET;
	k->Server.sin_port = htons(server_port);
	k->Server.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

	Zero(&sa, sizeof(sa));
	sa.sin_family = AF_INET;
	sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

	bool ok = (k->Outside != INVALID_SOCKET && k->Inside != INVALID_SOCKET && k->OutsideEvent != WSA_INVALID_EVENT && k->InsideEvent != WSA_INVALID_EVENT &&
		k->Stop != NULL && k->Timer != NULL);
	if (ok)
	{
		// The buffers of the sockets hold a burst, so that the link and not the relay decides what is lost
		setsockopt(k->Outside, SOL_SOCKET, SO_RCVBUF, (char *)&buffer, sizeof(buffer));
		setsockopt(k->Inside, SOL_SOCKET, SO_RCVBUF, (char *)&buffer, sizeof(buffer));
		ok = (bind(k->Inside, (SOCKADDR *)&sa, sizeof(sa)) == 0 && bind(k->Outside, (SOCKADDR *)&sa, sizeof(sa)) == 0 &&
			getsockname(k->Outside, (SOCKADDR *)&sa, &sa_size) == 0 &&
			WSAEventSelect(k->Outside, k->OutsideEvent, FD_READ) == 0 && WSAEventSelect(k->Inside, k->InsideEvent, FD_READ) == 0);
	}
	if (ok == false)
	{
		HysteriaTestLinkFree(k);
		return NULL;
	}

	k->Port = ntohs(sa.sin_port);
	k->Thread = NewThread(HysteriaTestLinkThread, k);

	return k;
}

// Stop a link, say what it carried and check that it lost what it is set to lose
static void HysteriaTestLinkEnd(HYSTERIATEST_CTX *ctx, HYSTERIATEST_LINK *k)
{
	if (k == NULL)
	{
		return;
	}

	SetEvent(k->Stop);
	WaitThread(k->Thread, INFINITE);
	ReleaseThread(k->Thread);

	HYSTERIATEST_WAY *u = &k->Up;
	HYSTERIATEST_WAY *d = &k->Down;
	Print("  the link, client to server: %I64u datagrams came, %I64u dropped at the queue, %I64u lost, %I64u delivered; server to client: %I64u, %I64u, %I64u, %I64u\n",
		u->NumIn, u->NumDropped, u->NumLost, u->NumOut, d->NumIn, d->NumDropped, d->NumLost, d->NumOut);

	UINT64 sent = u->NumIn - u->NumDropped;
	UINT64 lost = (sent != 0 ? u->NumLost * 1000 / sent : 0);
	HysteriaTestCheck(ctx, sent >= 1000 && lost >= HYSTERIATEST_LOSS_MIN && lost <= HYSTERIATEST_LOSS_MAX,
		"  the link lost about 10% of the datagrams that its bottleneck sent to the server", "%I64u of %I64u, %I64u in 1000", u->NumLost, sent, lost);

	HysteriaTestLinkFree(k);
}

//
// The goodput
//

// The writer of a bulk write: as fast as the stream takes, and at most a window ahead of the reader
static void HysteriaTestWriterThread(THREAD *thread, void *param)
{
	HYSTERIATEST_BULK *b = (HYSTERIATEST_BULK *)param;
	UCHAR *chunk = Malloc(HYSTERIATEST_CHUNK);

	Rand(chunk, HYSTERIATEST_CHUNK);

	while (InterlockedCompareExchange(&b->Stop, 0, 0) == 0)
	{
		// The write of QUIC never waits for room, so the window keeps what waits in it bounded
		if (InterlockedAdd64(&b->Written, 0) - InterlockedAdd64(&b->Read, 0) >= HYSTERIATEST_WINDOW)
		{
			SleepThread(1);
			continue;
		}
		if (TransportWrite(b->Stream, chunk, HYSTERIATEST_CHUNK) == false)
		{
			b->Failed = true;
			break;
		}
		InterlockedAdd64(&b->Written, HYSTERIATEST_CHUNK);
	}

	Free(chunk);
}

// The goodput from the client's stream s to the listener l, in bit/s: the client writes for HYSTERIATEST_RUN ms and the
// server reads what comes; the goodput is what the server read after HYSTERIATEST_WARMUP, over the time after it. 0 when the
// server took no stream, or the stream ended.
static UINT64 HysteriaTestGoodput(HYSTERIATEST_CTX *ctx, TRANSPORT_LISTENER *l, TRANSPORT_STREAM *s, char *what)
{
	HYSTERIATEST_BULK *b = ZeroMalloc(sizeof(HYSTERIATEST_BULK));
	UCHAR *buf = Malloc(HYSTERIATEST_CHUNK);
	UINT64 ret = 0;
	char check[MAX_SIZE];

	b->Stream = s;
	THREAD *t = NewThread(HysteriaTestWriterThread, b);

	// The stream reaches the server with the first bytes of the client
	TRANSPORT_STREAM *peer = TransportAccept(l, HYSTERIATEST_TIMEOUT);
	Format(check, sizeof(check), "  %s: the server takes the stream of the client", what);
	HysteriaTestCheck(ctx, peer != NULL, check, "%s", "TransportAccept gave none");

	if (peer != NULL)
	{
		UINT64 start = Tick64();
		UINT64 warm_at = 0;
		LONG64 warm_read = 0;
		bool ended = false;

		while (Tick64() - start < HYSTERIATEST_RUN)
		{
			UINT n = TransportRead(peer, buf, HYSTERIATEST_CHUNK, 500);

			if (n == 0)
			{
				ended = true;
				break;
			}
			if (n != TRANSPORT_LATER)
			{
				InterlockedAdd64(&b->Read, n);
			}
			if (warm_at == 0 && Tick64() - start >= HYSTERIATEST_WARMUP)
			{
				warm_at = Tick64();
				warm_read = InterlockedAdd64(&b->Read, 0);
			}
		}

		UINT64 end = Tick64();
		LONG64 read = InterlockedAdd64(&b->Read, 0);
		if (ended == false && warm_at != 0 && end > warm_at)
		{
			ret = (UINT64)(read - warm_read) * 8 * 1000 / (end - warm_at);
		}

		Print("  %s: the server read %I64u bytes in %I64u ms, %I64u kbit/s after the first %u ms\n", what, (UINT64)read, end - start, ret / 1000,
			(UINT)HYSTERIATEST_WARMUP);
		Format(check, sizeof(check), "  %s: the stream carries the bulk write for the whole run", what);
		HysteriaTestCheck(ctx, ended == false && b->Failed == false && ret != 0, check, "ended %u, a write failed %u, %I64u bit/s", (UINT)ended,
			(UINT)b->Failed, ret);
	}

	// The writer stops; the server reads on until it did, so that a write that waits for room ends
	InterlockedExchange(&b->Stop, 1);
	while (WaitThread(t, 0) == false)
	{
		if (peer == NULL || TransportRead(peer, buf, HYSTERIATEST_CHUNK, 100) == 0)
		{
			SleepThread(100);
		}
	}
	ReleaseThread(t);

	TransportClose(peer);
	Free(buf);
	Free(b);

	return ret;
}

// Dial address with t, a few times: a handshake over the lossy link may lose its packets
static TRANSPORT_STREAM *HysteriaTestDial(TRANSPORT *t, char *address)
{
	for (UINT i = 0;i < HYSTERIATEST_DIALS;i++)
	{
		TRANSPORT_STREAM *s = TransportDial(t, address, NULL);

		if (s != NULL)
		{
			return s;
		}
	}

	return NULL;
}

//
// msquic with BBR
//

// The goodput of the QUIC transport of the core over a lossy link, in bit/s; 0 when it did not run
static UINT64 HysteriaTestQuic(HYSTERIATEST_CTX *ctx)
{
	char thumbprint[MAX_SIZE];
	char address[MAX_SIZE];
	TRANSPORT_QUIC_CONFIG cfg;
	UINT64 ret = 0;

	Print("[msquic with BBR over the lossy link]\n");

	if (HysteriaTestCheck(ctx, TransportQuicAvailable(), "msquic.dll is next to vpntest.exe", "%s", "TransportQuicAvailable is false") == false)
	{
		return 0;
	}

	// A self-signed ECDSA P-256 certificate in the current user's My store, which the listener presents and the client pins
	PCCERT_CONTEXT cert = CryptoCertCreateSelfSigned(HYSTERIATEST_QUIC_CN, HYSTERIATEST_QUIC_SAN, NULL, 30, 0);
	bool have_cert = (cert != NULL && CryptoCertThumbprintStr(cert, thumbprint, sizeof(thumbprint)) && CryptoCertAddToStore(cert, NULL, 0));
	if (HysteriaTestCheck(ctx, have_cert, "the certificate of the QUIC listener in the My store", "%s", "CryptoCertCreateSelfSigned or the store failed"))
	{
		TransportQuicDefaultConfig(&cfg, thumbprint, false);
		TRANSPORT *server = TransportQuicServerNew(&cfg);
		TRANSPORT *client = TransportQuicClientNew(&cfg);
		TRANSPORT_LISTENER *l = (server != NULL ? TransportListen(server, "127.0.0.1:0") : NULL);
		HYSTERIATEST_LINK *link = (l != NULL ? HysteriaTestLinkStart(TransportQuicBoundPort(server)) : NULL);

		HysteriaTestCheck(ctx, cfg.Bbr && client != NULL && l != NULL && link != NULL, "  the QUIC transport asks msquic for BBR and listens behind the lossy link",
			"BBR %u, client %u, listener %u, link %u", (UINT)cfg.Bbr, (UINT)(client != NULL), (UINT)(l != NULL), (UINT)(link != NULL));

		if (client != NULL && link != NULL)
		{
			Format(address, sizeof(address), "127.0.0.1:%u", (UINT)link->Port);
			TRANSPORT_STREAM *s = HysteriaTestDial(client, address);

			if (HysteriaTestCheck(ctx, s != NULL, "  the QUIC client dials the listener through the link", "TransportDial of %s failed", address))
			{
				ret = HysteriaTestGoodput(ctx, l, s, "msquic with BBR");
			}
			TransportClose(s);
		}

		HysteriaTestLinkEnd(ctx, link);
		if (l != NULL)
		{
			TransportCloseListener(l);
		}
		if (client != NULL)
		{
			TransportQuicFree(client);
		}
		if (server != NULL)
		{
			TransportQuicFree(server);
		}
	}

	if (cert != NULL)
	{
		CryptoCertRemoveFromStore(thumbprint, NULL, 0);
		CryptoCertDeleteKey(cert);
		CryptoCertFree(cert);
	}

	return ret;
}

//
// The Hysteria mode
//

// The configuration of an end of the Noise session
static void HysteriaTestConfig(NOISE_SESSION_CONFIG *c, UCHAR *key, UCHAR *remote)
{
	Zero(c, sizeof(NOISE_SESSION_CONFIG));
	c->Suite = NOISE_SUITE_IK;
	c->StaticKey = key;
	c->RemoteStatic = remote;
	c->KeepaliveInterval = 1000;
	c->DeadTimeout = HYSTERIATEST_TIMEOUT;
	c->RekeyInterval = HYSTERIATEST_RUN;
}

// The server end of the Noise session: it accepts one stream, runs the responder, sends the first control record back and
// waits for the close
static void HysteriaTestServerThread(THREAD *thread, void *param)
{
	HYSTERIATEST_SERVER *srv = (HYSTERIATEST_SERVER *)param;
	TRANSPORT_NOISE *n = ZeroMalloc(sizeof(TRANSPORT_NOISE));
	UCHAR *buf = ZeroMalloc(NOISE_MAX_PAYLOAD);
	UINT size = 0;
	TRANSPORT_STREAM *s = TransportAccept(srv->Listener, HYSTERIATEST_TIMEOUT);

	srv->Got = (s != NULL);
	if (s != NULL)
	{
		srv->BindingType = TransportBinding(s, srv->Binding, sizeof(srv->Binding), &srv->BindingSize);
		srv->Accepted = TransportNoiseAccept(n, s, &srv->Config, HYSTERIATEST_TIMEOUT);
	}

	if (srv->Accepted)
	{
		UINT ret = TransportNoiseReceive(n, buf, NOISE_MAX_PAYLOAD, &size, HYSTERIATEST_TIMEOUT);

		srv->Echoed = (ret == NOISE_RECEIVE_CONTROL && TransportNoiseSend(n, NOISE_RECORD_CONTROL, buf, size));
		TransportNoiseReceive(n, buf, NOISE_MAX_PAYLOAD, &size, HYSTERIATEST_TIMEOUT);
	}

	TransportNoiseClose(n);
	Free(buf);
	Free(n);
}

// A Noise session of the two nodes over a stream of the mimic transport, which the client node dials through its sidecar in
// the Hysteria mode: both ends have the same binding, the pin of the certificate of the server, and a control record goes
// both ways
static void HysteriaTestSession(HYSTERIATEST_CTX *ctx, TRANSPORT *client, TRANSPORT_LISTENER *l, char *address, UCHAR *pin)
{
	HYSTERIATEST_SERVER *srv = ZeroMalloc(sizeof(HYSTERIATEST_SERVER));
	TRANSPORT_NOISE *n = ZeroMalloc(sizeof(TRANSPORT_NOISE));
	UCHAR *buf = ZeroMalloc(NOISE_MAX_PAYLOAD);
	UCHAR client_key[NOISE_KEY_SIZE], client_pub[NOISE_KEY_SIZE];
	UCHAR server_key[NOISE_KEY_SIZE], server_pub[NOISE_KEY_SIZE];
	UCHAR binding[NOISE_MAX_BINDING];
	UINT binding_size = 0;
	UINT binding_type = NOISE_BINDING_NONE;
	NOISE_SESSION_CONFIG cc;
	UINT size = 0;
	bool echoed = false;

	Print("[a Noise session of the two nodes over the Hysteria mode]\n");

	CryptoX25519GenerateKey(client_key, client_pub);
	CryptoX25519GenerateKey(server_key, server_pub);
	HysteriaTestConfig(&cc, client_key, server_pub);
	HysteriaTestConfig(&srv->Config, server_key, NULL);
	srv->Listener = l;
	THREAD *t = NewThread(HysteriaTestServerThread, srv);

	TRANSPORT_STREAM *s = HysteriaTestDial(client, address);
	HysteriaTestCheck(ctx, s != NULL && StrCmp(TransportOf(s)->Name, NODE_MIMIC_TRANSPORT) == 0,
		"  the client node dials the server node through its sidecar, over the mimic transport", "TransportDial of %s failed", address);
	if (s != NULL)
	{
		binding_type = TransportBinding(s, binding, sizeof(binding), &binding_size);
	}

	bool connected = (s != NULL && TransportNoiseConnect(n, s, &cc, HYSTERIATEST_TIMEOUT));
	if (connected)
	{
		bool sent = TransportNoiseSend(n, NOISE_RECORD_CONTROL, "hysteria", 8);
		UINT ret = TransportNoiseReceive(n, buf, NOISE_MAX_PAYLOAD, &size, HYSTERIATEST_TIMEOUT);

		echoed = (sent && ret == NOISE_RECEIVE_CONTROL && size == 8 && Cmp(buf, "hysteria", 8) == 0);
	}
	TransportNoiseClose(n);
	WaitThread(t, INFINITE);
	ReleaseThread(t);

	HysteriaTestCheck(ctx, connected && srv->Got && srv->Accepted, "  the Noise_IK handshake of the two nodes completes over the stream",
		"connected %u, the server got a stream %u, accepted %u", (UINT)connected, (UINT)srv->Got, (UINT)srv->Accepted);
	HysteriaTestCheck(ctx, binding_type == NOISE_BINDING_EXPORTER && binding_size == NODE_MIMIC_BINDING && srv->BindingType == binding_type &&
		srv->BindingSize == binding_size && Cmp(srv->Binding, binding, binding_size) == 0 && Cmp(binding, pin, CRYPTO_SHA256_SIZE) == 0,
		"  both ends have the same binding from their sidecars: the SHA-256 of the certificate of the server", "client type %u of %u bytes, server type %u of %u bytes",
		binding_type, binding_size, srv->BindingType, srv->BindingSize);
	HysteriaTestCheck(ctx, echoed && srv->Echoed, "  a control record goes both ways", "client %u, server %u", (UINT)echoed, (UINT)srv->Echoed);

	Zero(client_key, sizeof(client_key));
	Zero(server_key, sizeof(server_key));
	Free(buf);
	Free(n);
	Free(srv);
}

// The Hysteria mode between two nodes over a lossy link: the Noise session, then the goodput, in bit/s; 0 when it did not run
static UINT64 HysteriaTestMode(HYSTERIATEST_CTX *ctx)
{
	wchar_t work[MAX_PATH], server_dir[MAX_PATH], client_dir[MAX_PATH];
	wchar_t ranz[MAX_PATH], cert_path[MAX_PATH], key_path[MAX_PATH];
	wchar_t cmd[MAX_PATH * 4];
	char cert_json[MAX_PATH], key_json[MAX_PATH];
	char *settings = ZeroMalloc(NODE_MIMIC_MAX_SETTING);
	char address[MAX_SIZE];
	char pin_hex[MAX_SIZE];
	UCHAR pin[CRYPTO_SHA256_SIZE];
	NODE_STATUS st;
	UINT64 ret = 0;

	Print("[the Hysteria mode over the lossy link]\n");

	GetExeDirW(ranz, sizeof(ranz));
	ConbinePathW(ranz, sizeof(ranz), ranz, NODE_BGP_EXE_NAME);
	if (HysteriaTestCheck(ctx, IsFileExistsW(ranz), "ranz.exe is next to vpntest.exe", "%S is missing", ranz) == false)
	{
		Free(settings);
		return 0;
	}

	// The certificate of the own decoy, which the listener of the mode presents, made by ranz cert, and its pin
	HysteriaTestNewDir(work, sizeof(work), "work");
	ConbinePathW(cert_path, sizeof(cert_path), work, L"cert.pem");
	ConbinePathW(key_path, sizeof(key_path), work, L"key.pem");
	UniFormat(cmd, sizeof(cmd), L"\"%s\" cert -cn %S -savecert \"%s\" -savekey \"%s\"", ranz, HYSTERIATEST_NAME, cert_path, key_path);
	UINT code = HysteriaTestRun(cmd);
	bool pinned = (code == 0 && HysteriaTestPin(cert_path, pin, pin_hex, sizeof(pin_hex)));
	HysteriaTestCheck(ctx, pinned, "  ranz cert makes the certificate of the own decoy, and the test computes its pin", "exit code %u", code);

	USHORT port = HysteriaTestFreePort();
	HYSTERIATEST_LINK *link = (pinned && port != 0 ? HysteriaTestLinkStart(port) : NULL);
	HysteriaTestCheck(ctx, link != NULL, "  the lossy link to the UDP port of the listener of the mode", "port %u", (UINT)port);

	if (link != NULL)
	{
		// The server node: REALITY on 127.0.0.1 and the mode beside it, with the own decoy as its masquerade and Salamander
		HysteriaTestNewDir(server_dir, sizeof(server_dir), "server");
		HysteriaTestJsonPath(cert_json, sizeof(cert_json), cert_path);
		HysteriaTestJsonPath(key_json, sizeof(key_json), key_path);
		Format(settings, NODE_MIMIC_MAX_SETTING, "{\"listen\":\"127.0.0.1:0\",\"private_key\":\"%s\",\"short_ids\":[\"a1b2\"],\"server_names\":[\"%s\"],"
			"\"decoy\":{\"mode\":\"own\",\"page\":\"<html>%s</html>\",\"cert_file\":\"%s\",\"key_file\":\"%s\"},"
			"\"hysteria\":{\"listen\":\"127.0.0.1:%u\",\"secrets\":[\"%s\"],\"salamander\":\"%s\"}}",
			HYSTERIATEST_PRIVATE, HYSTERIATEST_NAME, HYSTERIATEST_PAGE, cert_json, key_json, (UINT)port, HYSTERIATEST_SECRET, HYSTERIATEST_SALAMANDER);
		HysteriaTestWriteConfig(server_dir, settings, NULL);

		NODE *server = NewNode(server_dir);
		NodeStart(server);
		TRANSPORT *ts = NodeMimicTransport(server);
		TRANSPORT_LISTENER *l = (ts != NULL ? TransportListen(ts, "") : NULL);
		NodeGetStatus(server, &st);
		HysteriaTestCheck(ctx, l != NULL && st.Mimic[NODE_MIMIC_ROLE_SERVER].Running, "  the server node listens: its sidecar runs REALITY and the mode",
			"listener %u, running %u, error \"%s\"", (UINT)(l != NULL), (UINT)st.Mimic[NODE_MIMIC_ROLE_SERVER].Running, st.Mimic[NODE_MIMIC_ROLE_SERVER].Error);

		// The client node: a link of the mode through the lossy link, with the pin, Salamander and Brutal at the rate that
		// the link carries
		HysteriaTestNewDir(client_dir, sizeof(client_dir), "client");
		Format(address, sizeof(address), "127.0.0.1:%u", (UINT)link->Port);
		Format(settings, NODE_MIMIC_MAX_SETTING, "{\"links\":[{\"address\":\"%s\",\"server_name\":\"%s\",\"hysteria\":{\"secret\":\"%s\",\"pin_sha256\":\"%s\","
			"\"salamander\":\"%s\",\"brutal\":{\"up_mbps\":%u,\"down_mbps\":%u}}}]}",
			address, HYSTERIATEST_NAME, HYSTERIATEST_SECRET, pin_hex, HYSTERIATEST_SALAMANDER, (UINT)HYSTERIATEST_BRUTAL, (UINT)HYSTERIATEST_BRUTAL);
		HysteriaTestWriteConfig(client_dir, NULL, settings);

		NODE *client_node = NewNode(client_dir);
		NodeStart(client_node);
		TRANSPORT *tc = NodeMimicTransport(client_node);
		UINT64 end = Tick64() + HYSTERIATEST_BOUND;
		NodeGetStatus(client_node, &st);
		while (st.Mimic[NODE_MIMIC_ROLE_CLIENT].Running == false && Tick64() < end)
		{
			SleepThread(100);
			NodeGetStatus(client_node, &st);
		}
		HysteriaTestCheck(ctx, tc != NULL && st.Mimic[NODE_MIMIC_ROLE_CLIENT].Running, "  the client node starts its sidecar with the link of the mode",
			"transport %u, running %u, error \"%s\"", (UINT)(tc != NULL), (UINT)st.Mimic[NODE_MIMIC_ROLE_CLIENT].Running, st.Mimic[NODE_MIMIC_ROLE_CLIENT].Error);

		if (l != NULL && tc != NULL && st.Mimic[NODE_MIMIC_ROLE_CLIENT].Running)
		{
			HysteriaTestSession(ctx, tc, l, address, pin);

			Print("[the goodput of the Hysteria mode]\n");
			TRANSPORT_STREAM *s = HysteriaTestDial(tc, address);
			if (HysteriaTestCheck(ctx, s != NULL, "  the client node dials a stream for the bulk write", "TransportDial of %s failed", address))
			{
				ret = HysteriaTestGoodput(ctx, l, s, "the Hysteria mode with Brutal at 18 Mbit/s and Salamander");
			}
			TransportClose(s);

			NodeGetStatus(server, &st);
			HysteriaTestCheck(ctx, st.Mimic[NODE_MIMIC_ROLE_SERVER].Accepted >= 1 && st.Mimic[NODE_MIMIC_ROLE_SERVER].Streams >= 2,
				"  the server node counts the client of the mode and its streams", "%I64u clients, %I64u streams", st.Mimic[NODE_MIMIC_ROLE_SERVER].Accepted,
				st.Mimic[NODE_MIMIC_ROLE_SERVER].Streams);
		}

		if (l != NULL)
		{
			TransportCloseListener(l);
		}
		NodeStop(client_node);
		NodeStop(server);
		FreeNode(client_node);
		FreeNode(server);
		HysteriaTestDeleteTree(client_dir);
		HysteriaTestDeleteTree(server_dir);
	}

	HysteriaTestLinkEnd(ctx, link);
	HysteriaTestDeleteTree(work);
	Free(settings);

	return ret;
}

// hysteria: the Hysteria mode of the mimic transport against msquic with BBR on a lossy link
RANZ_TEST("hysteria", hysteria_test, "Hysteria mode: two nodes over the Hysteria mode of ranz mimic (next to vpntest) with Brutal and Salamander on a link of 10% loss and 150 ms round trip, a Noise session with the binding of the certificate, and its goodput against msquic with BBR on the same link.");
void hysteria_test(UINT num, char **arg)
{
	HYSTERIATEST_CTX *ctx = ZeroMalloc(sizeof(HYSTERIATEST_CTX));
	HANDLE done = CreateEventW(NULL, TRUE, FALSE, NULL);
	HANDLE watchdog = (done != NULL ? CreateThread(NULL, 0, HysteriaTestWatchdog, done, 0, NULL) : NULL);

	Print("Hysteria test: the Hysteria mode of ranz mimic against msquic with BBR, on a link of %u Mbit/s, %u ms round trip and %u%% loss each way\n",
		(UINT)(HYSTERIATEST_RATE / 1000000), (UINT)(2 * HYSTERIATEST_DELAY / 1000), (UINT)(HYSTERIATEST_LOSS / 100));

	UINT64 quic = HysteriaTestQuic(ctx);
	UINT64 hysteria = HysteriaTestMode(ctx);

	Print("[the goodput on the lossy link]\n");
	Print("  msquic with BBR: %I64u kbit/s; the Hysteria mode with Brutal: %I64u kbit/s (%I64u%% of msquic)\n", quic / 1000, hysteria / 1000,
		quic != 0 ? hysteria * 100 / quic : 0);
	HysteriaTestCheck(ctx, quic != 0 && hysteria != 0 && hysteria * 100 >= quic * HYSTERIATEST_FACTOR,
		"  the Hysteria mode clearly beats msquic with BBR: at least 150% of its goodput", "%I64u and %I64u bit/s", hysteria, quic);

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
		Print("HYSTERIA TEST OK\n");
	}
	else
	{
		Print("HYSTERIA TEST FAILED (%u of %u checks failed)\n", ctx->NumFailed, ctx->NumChecks);
	}

	Free(ctx);
}
