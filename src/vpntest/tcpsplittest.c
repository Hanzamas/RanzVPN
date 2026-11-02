// tcpsplittest.c
// TCP splitting test of vpntest ("tcpsplit" command, CORE-P2-3 #94)
//
// TCP splitting of an L3 Network (Cedar/NodeSplit.c; the ADR-0022 amendment of 2026-11-01) between two nodes of VRF corp (401)
// on the in-process loopback transport. node-c, the client, has a Wintun adapter of the runner for corp (Cedar/NodeVrfAdapter.c),
// so the TCP connections of the runner's own stack from its address in corp are the inner TCP connections, and the runner's
// TCP stack terminates them on the listener of node-c. node-s, the server, has a fake host, which counts the packets that the
// overlay delivers to it, and opens each split connection with an ordinary socket to its real destination: a plain Winsock
// server of the test, the unmodified TCP peer of the far side. Both nodes share the runner, so node-s dials the far side on
// 127.0.0.1 in place of its own address in corp (NodeSplitSetDial). corp has two L3 Networks: fast, which splits TCP, and
// plain, which does not.
// - Connect, data and half-close: from its address in fast the runner connects to node-s's address there, sends 128 KiB, shuts
//   its sending side and reads the echo until its end; the far side read them and the end, and shut its own side. The tunnel
//   carried no TCP segment of the runner: the fake host of node-s got none from the runner's address in fast.
// - Refused: a destination whose port has no listener at the far side refuses the runner's connect.
// - A reset of the far side resets the runner's connection, and a reset of the runner's end resets the far side's.
// - Timeout: a destination that does not answer (a listener with conditional accept that takes no connection) leaves the
//   runner's connect waiting, neither taken by the listener of node-c nor refused, and node-c counts the flow as failed.
// - Untouched: a UDP datagram of the runner from its address in fast, and the SYN of a TCP connection from its address in
//   plain, reach the fake host of node-s as packets.
// - Off: once a Generation turns splitting off in fast, the SYN of a new connection reaches the fake host as a packet, and
//   node-c splits nothing more.
// First, without the nodes: the split Networks of a desired state as a client of the control module takes them from the wire
// (Network.tcp_split, Core/ControlSplit.c), where an L3 Network with tcp_split is one, and an L3 Network without it and an L2
// Network with it are none; and the Capability tcpSplit that the node reports in its Hello (NodeCapsProc), without which the
// controller refuses it as a member of a VRF that splits TCP.
// Print "TCPSPLIT TEST OK" only when every check passes. Needs administrator rights and wintun.dll next to vpntest
// (.github/scripts/fetch-wintun.ps1).

#include "testlist.h"

#include "Cedar/ConfigStore.h"
#include "Cedar/Node.h"
#include "Cedar/NodeCaps.h"
#include "Cedar/NodeSplit.h"

#include "Mayaqua/Encrypt.h"
#include "Mayaqua/FileIO.h"
#include "Mayaqua/Internat.h"
#include "Mayaqua/Kernel.h"
#include "Mayaqua/Memory.h"
#include "Mayaqua/Microsoft.h"
#include "Mayaqua/Object.h"
#include "Mayaqua/Str.h"
#include "Mayaqua/Tick64.h"

#include "Core/Control.h"
#include "Core/Transport.h"

#include <stdio.h>

#define	SPLITTEST_BUDGET		180000		// The whole test ends within this time, or the watchdog ends the process (ms)
#define	SPLITTEST_BOUND			20000		// A bounded wait on observable state (ms)
#define	SPLITTEST_POLL			20			// Poll interval of observable state (ms)
#define	SPLITTEST_IO			10000		// ms that a read or a write of a test socket waits at most
#define	SPLITTEST_DIAL			3000		// ms that node-s waits for its dial to the far side
#define	SPLITTEST_PENDING		6000		// ms that the runner's connect to a destination that does not answer waits in the test
#define	SPLITTEST_VRF			401			// VRF corp
#define	SPLITTEST_LENGTH		24			// The prefix length of the Networks
#define	SPLITTEST_DATA			(128 * 1024)	// Bytes that the runner sends the echo
#define	SPLITTEST_PORT_ECHO		7001		// The ports of node-s's address in fast that the far side answers: the echo ...
#define	SPLITTEST_PORT_CLOSED	7002		// ... a port without a listener ...
#define	SPLITTEST_PORT_RESET	7003		// ... a server that resets each connection once it read a byte ...
#define	SPLITTEST_PORT_WATCH	7004		// ... one that tells whether its connection was reset ...
#define	SPLITTEST_PORT_SILENT	7005		// ... and a destination that does not answer
#define	SPLITTEST_PORT_UDP		7009		// The UDP port of node-s's address that the runner sends a datagram to
#define	SPLITTEST_NODE_C		"node-c"
#define	SPLITTEST_NODE_S		"node-s"

// The addresses of the test, in network byte order
static UINT splittest_c_fast;		// node-c in fast: 198.19.81.2
static UINT splittest_s_fast;		// node-s in fast: 198.19.81.1
static UINT splittest_c_plain;		// node-c in plain: 198.19.82.2
static UINT splittest_s_plain;		// node-s in plain: 198.19.82.1

// The checks of the test
typedef struct SPLITTEST_CTX
{
	UINT NumChecks;
	UINT NumFailed;
} SPLITTEST_CTX;

// The fake host of node-s: what the overlay delivered to it
typedef struct SPLITTEST_HOST
{
	volatile LONG TcpFast;				// TCP segments from the runner's address in fast
	volatile LONG SynFast;				// ... of them SYNs
	volatile LONG SynPlain;				// TCP SYNs from the runner's address in plain
	volatile LONG Udp;					// UDP datagrams from the runner's address in fast to SPLITTEST_PORT_UDP
} SPLITTEST_HOST;

// The far side: plain Winsock servers on 127.0.0.1, which node-s dials in place of its own address in fast
typedef struct SPLITTEST_FAR
{
	SOCKET Echo;						// The echo: it sends back what it reads, and shuts its side once it read the end
	SOCKET Reset;						// Resets each connection once it read a byte
	SOCKET Watch;						// Tells whether its connection was reset
	SOCKET Silent;						// A listener with conditional accept that takes no connection: its SYNs get no answer
	UINT EchoPort;
	UINT ResetPort;
	UINT WatchPort;
	UINT SilentPort;
	UINT ClosedPort;					// A port of 127.0.0.1 without a listener
	volatile LONG Stop;					// Ends the thread
	HANDLE Thread;
	volatile LONG EchoBytes;			// Bytes that the echo read
	volatile LONG EchoEnd;				// The echo read the end and shut its side
	volatile LONG ResetSent;			// Connections that the reset server reset
	volatile LONG WatchAccepted;		// Connections that the watch server took
	volatile LONG WatchReset;			// ... and that were reset
} SPLITTEST_FAR;

// What the watchdog of the test waits for
typedef struct SPLITTEST_WATCH
{
	HANDLE Done;
} SPLITTEST_WATCH;

// The owner of a client of the control module: the split Networks of the state that it took last
typedef struct SPLITTEST_STATE
{
	UINT NumStates;
	UINT NumSplits;
	CONTROL_SPLIT Splits[CONTROL_MAX_SPLITS];
} SPLITTEST_STATE;

static bool SplitTestCheck(SPLITTEST_CTX *ctx, bool ok, char *what, char *fmt, ...) RANZ_PRINTF_FORMAT(4, 5);
static bool SplitTestCheck(SPLITTEST_CTX *ctx, bool ok, char *what, char *fmt, ...)
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

// The watchdog: a native thread that ends a run that hangs, so that a lost segment is a failed test instead of a hung CI step
static DWORD WINAPI SplitTestWatchdog(LPVOID param)
{
	SPLITTEST_WATCH *w = (SPLITTEST_WATCH *)param;
	char msg[MAX_SIZE];
	DWORD written = 0;

	if (WaitForSingleObject(w->Done, SPLITTEST_BUDGET) != WAIT_TIMEOUT)
	{
		return 0;
	}

	int len = snprintf(msg, sizeof(msg), "TCPSPLIT TEST FAILED (did not finish within %u ms)\n", (UINT)SPLITTEST_BUDGET);
	if (len > 0)
	{
		WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), msg, (DWORD)MIN((UINT)len, (UINT)sizeof(msg) - 1), &written, NULL);
	}

	TerminateProcess(GetCurrentProcess(), 1);

	return 0;
}

// An IPv4 address of four bytes, in network byte order
static UINT SplitTestAddr(UCHAR a, UCHAR b, UCHAR c, UCHAR d)
{
	UCHAR x[4];
	UINT ret = 0;

	x[0] = a;
	x[1] = b;
	x[2] = c;
	x[3] = d;
	Copy(&ret, x, 4);

	return ret;
}

// Wait until *v reaches want, within SPLITTEST_BOUND: whether it did
static bool SplitTestWait(volatile LONG *v, LONG want)
{
	for (UINT64 end = Tick64() + SPLITTEST_BOUND;ReadAcquire(v) < want && Tick64() < end;SleepThread(SPLITTEST_POLL))
	{
	}

	return (ReadAcquire(v) >= want);
}

//
// The control stream
//

// A varint of the protobuf wire format into b
static void SplitTestVarint(BUF *b, UINT64 v)
{
	UCHAR c;

	for (;v >= 0x80;v >>= 7)
	{
		c = (UCHAR)(v | 0x80);
		WriteBuf(b, &c, 1);
	}
	c = (UCHAR)v;
	WriteBuf(b, &c, 1);
}

// The field field of the varint v, or of the size bytes at data when data is not NULL: a string or a message
static void SplitTestField(BUF *b, UINT field, UINT64 v, const void *data)
{
	if (data == NULL)
	{
		SplitTestVarint(b, (UINT64)field << 3);
		SplitTestVarint(b, v);
		return;
	}

	SplitTestVarint(b, ((UINT64)field << 3) | 2);
	SplitTestVarint(b, v);
	WriteBuf(b, data, (UINT)v);
}

// The field field of the message m, which it frees
static void SplitTestMessage(BUF *b, UINT field, BUF *m)
{
	SplitTestField(b, field, m->Size, m->Buf);
	FreeBuf(m);
}

// An Object of the Network name of corp and of the mode mode (NetworkMode: 1 for L3, 2 for L2), with tcp_split (field 9) when
// split
static BUF *SplitTestNetworkObject(const char *name, UINT mode, bool split)
{
	BUF *nw = NewBuf();
	BUF *o = NewBuf();

	SplitTestField(nw, 1, StrLen(name), name);
	SplitTestField(nw, 2, SPLITTEST_VRF, NULL);
	SplitTestField(nw, 3, mode, NULL);
	if (split)
	{
		SplitTestField(nw, 9, 1, NULL);
	}
	SplitTestMessage(o, 3, nw);

	return o;
}

// A ControlMessage with the Update to the Generation gen from base (0 for a full state) that sets the num objects of set, which
// it frees
static BUF *SplitTestUpdate(UINT64 gen, UINT64 base, BUF **set, UINT num)
{
	BUF *u = NewBuf();
	BUF *m = NewBuf();

	SplitTestField(u, 1, gen, NULL);
	if (base != 0)
	{
		SplitTestField(u, 2, base, NULL);
	}
	for (UINT i = 0;i < num;i++)
	{
		SplitTestMessage(u, 3, set[i]);
	}
	SplitTestMessage(m, 2, u);

	return m;
}

// The owner of the client (CONTROL_STATE_PROC): it keeps the split Networks of the state
static void SplitTestStateProc(void *param, const CONTROL_STATE *state)
{
	SPLITTEST_STATE *st = (SPLITTEST_STATE *)param;

	st->NumStates++;
	st->NumSplits = MIN(state->NumSplits, CONTROL_MAX_SPLITS);
	Copy(st->Splits, state->Splits, sizeof(CONTROL_SPLIT) * st->NumSplits);
}

// Whether the split Networks of st are the names, num of them, each of corp, in that order
static bool SplitTestSplitsAre(const SPLITTEST_STATE *st, const char *const *names, UINT num)
{
	if (st->NumSplits != num)
	{
		return false;
	}

	for (UINT i = 0;i < num;i++)
	{
		if (StrCmp(st->Splits[i].Network, names[i]) != 0 || st->Splits[i].VrfId != SPLITTEST_VRF)
		{
			return false;
		}
	}

	return true;
}

// Give the client the Update to the Generation gen from base that sets the num objects of set, which it frees: whether the
// client took it
static bool SplitTestInput(CONTROL_CLIENT *c, UINT64 gen, UINT64 base, BUF **set, UINT num)
{
	BUF *m = SplitTestUpdate(gen, base, set, num);
	bool ok = ControlInput(c, m->Buf, m->Size);

	FreeBuf(m);

	return ok;
}

// The split Networks of a desired state, as a client of the control module takes them from the wire, and the Capability
// tcpSplit that the node reports in its Hello
static void SplitTestControl(SPLITTEST_CTX *ctx)
{
	static const UCHAR key[NOISE_KEY_SIZE] = {0x01};
	static TRANSPORT transport = {"tcpsplit"};
	static const char *const fast[] = {"fast"};
	static const char *const both[] = {"bulk", "fast"};
	static const char *const bulk[] = {"bulk"};
	SPLITTEST_STATE *st = ZeroMalloc(sizeof(SPLITTEST_STATE));
	CONTROL_CONFIG cfg;
	CONTROL_CAPS caps;
	BUF *set[3];

	Print("[control: the Networks that split TCP in a desired state, from the wire]\n");

	Zero(&cfg, sizeof(cfg));
	cfg.Transport = &transport;
	StrCpy(cfg.Address, sizeof(cfg.Address), "controller");
	cfg.StaticKey = key;
	cfg.Proc = SplitTestStateProc;
	cfg.Param = st;

	CONTROL_CLIENT *c = ControlNew(&cfg);
	if (SplitTestCheck(ctx, c != NULL, "control: ControlNew makes a client without its thread", "it refused a complete configuration") == false)
	{
		Free(st);
		return;
	}

	// Generation 1: the L3 Network fast with tcp_split, the L3 Network lan without it, and the L2 Network dmz with it, which
	// the node leaves out
	set[0] = SplitTestNetworkObject("dmz", 2, true);
	set[1] = SplitTestNetworkObject("fast", 1, true);
	set[2] = SplitTestNetworkObject("lan", 1, false);
	bool ok = SplitTestInput(c, 1, 0, set, 3);
	SplitTestCheck(ctx, ok && st->NumStates == 1 && SplitTestSplitsAre(st, fast, 1),
		"control: an L3 Network with tcp_split splits TCP; an L3 Network without it, the default, and an L2 Network with it do not",
		"the client took it: %s, %u states, %u split Networks", ok ? "yes" : "no", st->NumStates, st->NumSplits);

	// Generation 2, a delta: bulk splits TCP too, and the split Networks are in Network name order
	set[0] = SplitTestNetworkObject("bulk", 1, true);
	ok = SplitTestInput(c, 2, 1, set, 1);
	SplitTestCheck(ctx, ok && st->NumStates == 2 && SplitTestSplitsAre(st, both, 2),
		"control: a delta that turns splitting on in another L3 Network adds it, in Network name order", "the client took it: %s, %u split Networks",
		ok ? "yes" : "no", st->NumSplits);

	// Generation 3, a delta: fast without tcp_split
	set[0] = SplitTestNetworkObject("fast", 1, false);
	ok = SplitTestInput(c, 3, 2, set, 1);
	SplitTestCheck(ctx, ok && st->NumStates == 3 && SplitTestSplitsAre(st, bulk, 1),
		"control: a delta that leaves tcp_split out of a Network turns its splitting off and leaves the others", "the client took it: %s, %u split Networks",
		ok ? "yes" : "no", st->NumSplits);

	ControlFree(c);
	Free(st);

	// The Hello of the node reports the Capability, as the control client asks NodeCapsProc for each Hello
	Zero(&caps, sizeof(caps));
	NodeCapsProc(NULL, &caps);
	SplitTestCheck(ctx, caps.TcpSplit, "the Capability tcpSplit: the node reports it in its Hello, so the controller lets it into a VRF that splits TCP",
		"NodeCapsProc reports no tcpSplit");
}

//
// The far side
//

// A TCP listener on 127.0.0.1 on a port that the system picks, its port into port; with conditional accept, the stack answers
// no SYN until the listener takes the connection, which it never does
static SOCKET SplitTestListen(UINT *port, bool conditional)
{
	SOCKADDR_IN a;
	int size = sizeof(a);
	BOOL on = TRUE;

	SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (s == INVALID_SOCKET)
	{
		return INVALID_SOCKET;
	}

	if (conditional)
	{
		setsockopt(s, SOL_SOCKET, SO_CONDITIONAL_ACCEPT, (const char *)&on, sizeof(on));
	}

	Zero(&a, sizeof(a));
	a.sin_family = AF_INET;
	a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	if (bind(s, (SOCKADDR *)&a, sizeof(a)) != 0 || listen(s, SOMAXCONN) != 0 || getsockname(s, (SOCKADDR *)&a, &size) != 0)
	{
		closesocket(s);
		return INVALID_SOCKET;
	}

	*port = ntohs(a.sin_port);

	return s;
}

// A connection of the echo: what it reads goes back, and once it read the end it shuts its sending side
static void SplitTestEcho(SPLITTEST_FAR *f, SOCKET c)
{
	char buf[16384];

	while (true)
	{
		int r = recv(c, buf, sizeof(buf), 0);

		if (r <= 0)
		{
			if (r == 0)
			{
				shutdown(c, SD_SEND);
				InterlockedExchange(&f->EchoEnd, 1);
			}
			return;
		}

		InterlockedAdd(&f->EchoBytes, r);
		for (int sent = 0;sent < r;)
		{
			int w = send(c, buf + sent, r - sent, 0);

			if (w <= 0)
			{
				return;
			}
			sent += w;
		}
	}
}

// The thread of the far side: one connection at a time of each server
static DWORD WINAPI SplitTestFarThread(LPVOID param)
{
	SPLITTEST_FAR *f = (SPLITTEST_FAR *)param;

	while (ReadAcquire(&f->Stop) == 0)
	{
		WSAPOLLFD fds[3];
		DWORD timeout = SPLITTEST_IO;
		char buf[64];

		Zero(fds, sizeof(fds));
		fds[0].fd = f->Echo;
		fds[1].fd = f->Reset;
		fds[2].fd = f->Watch;
		for (UINT i = 0;i < 3;i++)
		{
			fds[i].events = POLLRDNORM;
		}
		if (WSAPoll(fds, 3, 100) <= 0)
		{
			continue;
		}

		for (UINT i = 0;i < 3;i++)
		{
			if (fds[i].revents == 0)
			{
				continue;
			}

			SOCKET c = accept(fds[i].fd, NULL, NULL);
			if (c == INVALID_SOCKET)
			{
				continue;
			}
			setsockopt(c, SOL_SOCKET, SO_RCVTIMEO, (const char *)&timeout, sizeof(timeout));
			setsockopt(c, SOL_SOCKET, SO_SNDTIMEO, (const char *)&timeout, sizeof(timeout));

			if (i == 0)
			{
				SplitTestEcho(f, c);
				closesocket(c);
			}
			else if (i == 1)
			{
				struct linger l;

				recv(c, buf, sizeof(buf), 0);
				l.l_onoff = 1;
				l.l_linger = 0;
				setsockopt(c, SOL_SOCKET, SO_LINGER, (const char *)&l, sizeof(l));
				closesocket(c);
				InterlockedIncrement(&f->ResetSent);
			}
			else
			{
				InterlockedIncrement(&f->WatchAccepted);
				while (true)
				{
					int r = recv(c, buf, sizeof(buf), 0);

					if (r > 0)
					{
						continue;
					}
					if (r < 0 && WSAGetLastError() == WSAECONNRESET)
					{
						InterlockedIncrement(&f->WatchReset);
					}
					break;
				}
				closesocket(c);
			}
		}
	}

	return 0;
}

// Start the far side: false when a socket or the thread cannot be had
static bool SplitTestFarStart(SPLITTEST_FAR *f)
{
	UINT port = 0;

	Zero(f, sizeof(SPLITTEST_FAR));
	f->Echo = SplitTestListen(&f->EchoPort, false);
	f->Reset = SplitTestListen(&f->ResetPort, false);
	f->Watch = SplitTestListen(&f->WatchPort, false);
	f->Silent = SplitTestListen(&f->SilentPort, true);

	// A port that a listener held and that no socket holds any more: a connect to it is refused
	SOCKET closed = SplitTestListen(&port, false);
	if (closed != INVALID_SOCKET)
	{
		closesocket(closed);
		f->ClosedPort = port;
	}

	if (f->Echo == INVALID_SOCKET || f->Reset == INVALID_SOCKET || f->Watch == INVALID_SOCKET || f->Silent == INVALID_SOCKET || f->ClosedPort == 0)
	{
		return false;
	}

	f->Thread = CreateThread(NULL, 0, SplitTestFarThread, f, 0, NULL);

	return (f->Thread != NULL);
}

// Stop the far side
static void SplitTestFarStop(SPLITTEST_FAR *f)
{
	InterlockedExchange(&f->Stop, 1);
	if (f->Thread != NULL)
	{
		WaitForSingleObject(f->Thread, INFINITE);
		CloseHandle(f->Thread);
	}

	SOCKET all[4] = {f->Echo, f->Reset, f->Watch, f->Silent};
	for (UINT i = 0;i < 4;i++)
	{
		if (all[i] != INVALID_SOCKET)
		{
			closesocket(all[i]);
		}
	}
}

// Where node-s dials the real destination of a split connection: node-s's own address in fast stands for the far side, on
// 127.0.0.1, by its port
static void SplitTestDial(void *param, UCHAR *address, UINT *port)
{
	SPLITTEST_FAR *f = (SPLITTEST_FAR *)param;
	UINT a = 0;

	Copy(&a, address, 4);
	if (a != splittest_s_fast)
	{
		return;
	}

	switch (*port)
	{
	case SPLITTEST_PORT_ECHO:
		*port = f->EchoPort;
		break;
	case SPLITTEST_PORT_CLOSED:
		*port = f->ClosedPort;
		break;
	case SPLITTEST_PORT_RESET:
		*port = f->ResetPort;
		break;
	case SPLITTEST_PORT_WATCH:
		*port = f->WatchPort;
		break;
	case SPLITTEST_PORT_SILENT:
		*port = f->SilentPort;
		break;
	default:
		return;
	}

	a = htonl(INADDR_LOOPBACK);
	Copy(address, &a, 4);
}

//
// The nodes
//

// A new empty data directory under the temp directory of the process, with a configuration store: no role, one worker
static void SplitTestNewDir(wchar_t *dir, UINT size, char *name)
{
	wchar_t tmp[MAX_PATH];
	wchar_t path[MAX_PATH];

	UniFormat(tmp, sizeof(tmp), L"tcpsplittest_%S_%u", name, Rand32());
	ConbinePathW(dir, size, MsGetMyTempDirW(), tmp);
	MakeDirExW(dir);

	ConbinePathW(path, sizeof(path), dir, CS_FILE_NAME);
	CONFIG_STORE *s = CsOpen(path);
	if (s != NULL)
	{
		CsSetSetting(s, NODE_SETTING_ROLES, "none");
		CsSetSetting(s, NODE_SETTING_WORKERS, "1");
		CsClose(s);
	}
}

// Delete the files of a directory, then the directory (it holds no subdirectory)
static void SplitTestDeleteDir(wchar_t *dir)
{
	DIRLIST *d = EnumDirW(dir);

	for (UINT i = 0;d != NULL && i < d->NumFiles;i++)
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

// The lines of the node log in a data directory that tell about TCP splitting, the adapters and the overlay, for a test that
// failed
static void SplitTestPrintLog(wchar_t *dir)
{
	wchar_t log_dir[MAX_PATH];

	ConbinePathW(log_dir, sizeof(log_dir), dir, NODE_LOG_DIR_NAME);
	DIRLIST *d = EnumDirW(log_dir);

	for (UINT i = 0;d != NULL && i < d->NumFiles;i++)
	{
		DIRENT *e = d->File[i];
		wchar_t path[MAX_PATH];

		if (e->Folder)
		{
			continue;
		}

		ConbinePathW(path, sizeof(path), log_dir, e->FileNameW);
		BUF *b = ReadDumpW(path);
		if (b == NULL)
		{
			continue;
		}

		char *text = ZeroMalloc(b->Size + 1);
		Copy(text, b->Buf, b->Size);
		TOKEN_LIST *t = ParseToken(text, "\r\n");
		for (UINT j = 0;j < t->NumTokens;j++)
		{
			if (InStr(t->Token[j], "TCP splitting") || InStr(t->Token[j], "Wintun") || InStr(t->Token[j], "VRF adapters") || InStr(t->Token[j], "Overlay"))
			{
				Print("  [LOG] %s\n", t->Token[j]);
			}
		}
		FreeToken(t);
		Free(text);
		FreeBuf(b);
	}

	FreeDir(d);
}

// Stop and free a node of the test, and delete its data directory, whose log lines are printed first with print_log
static void SplitTestFreeNode(NODE *n, wchar_t *dir, bool print_log)
{
	wchar_t log_dir[MAX_PATH];

	if (n == NULL)
	{
		return;
	}

	NodeStop(n);
	FreeNode(n);

	if (print_log)
	{
		SplitTestPrintLog(dir);
	}

	ConbinePathW(log_dir, sizeof(log_dir), dir, NODE_LOG_DIR_NAME);
	SplitTestDeleteDir(log_dir);
	SplitTestDeleteDir(dir);
}

// The address addr of a node in the Network network of corp
static void SplitTestAddress(CONTROL_ADDRESS *a, char *network, UINT addr)
{
	Zero(a, sizeof(CONTROL_ADDRESS));
	StrCpy(a->Network, sizeof(a->Network), network);
	a->VrfId = SPLITTEST_VRF;
	Copy(a->Address, &addr, 4);
	a->AddressSize = 4;
	a->Length = SPLITTEST_LENGTH;
}

// The desired state of a node of the test in corp with the other as its peer: node-s when server, else node-c. With split,
// the Network fast splits TCP. In the order of the protocol: the addresses by Network name.
static void SplitTestState(CONTROL_STATE *st, CONTROL_PEER *peer, UINT64 generation, bool server, const UCHAR *peer_key, bool split)
{
	Zero(st, sizeof(CONTROL_STATE));
	Zero(peer, sizeof(CONTROL_PEER));

	st->Generation = generation;
	StrCpy(st->Name, sizeof(st->Name), server ? SPLITTEST_NODE_S : SPLITTEST_NODE_C);
	SplitTestAddress(&st->Addresses[0], "fast", server ? splittest_s_fast : splittest_c_fast);
	SplitTestAddress(&st->Addresses[1], "plain", server ? splittest_s_plain : splittest_c_plain);
	st->NumAddresses = 2;
	StrCpy(st->Vrfs[0].Name, sizeof(st->Vrfs[0].Name), "corp");
	st->Vrfs[0].Id = SPLITTEST_VRF;
	st->NumVrfs = 1;
	if (split)
	{
		StrCpy(st->Splits[0].Network, sizeof(st->Splits[0].Network), "fast");
		st->Splits[0].VrfId = SPLITTEST_VRF;
		st->NumSplits = 1;
	}

	StrCpy(peer->Name, sizeof(peer->Name), server ? SPLITTEST_NODE_C : SPLITTEST_NODE_S);
	Copy(peer->Key, peer_key, PEER_KEY_SIZE);
	peer->VrfIds[0] = SPLITTEST_VRF;
	peer->NumVrfs = 1;
	SplitTestAddress(&peer->Addresses[0], "fast", server ? splittest_c_fast : splittest_s_fast);
	SplitTestAddress(&peer->Addresses[1], "plain", server ? splittest_c_plain : splittest_s_plain);
	peer->NumAddresses = 2;
	st->Peers = peer;
	st->NumPeers = 1;
}

// Apply the states of a Generation to node-s and node-c, as the control stream does, with fast splitting TCP when split
static bool SplitTestApply(NODE *s, NODE *c, UINT64 generation, const UCHAR *s_key, const UCHAR *c_key, bool split)
{
	CONTROL_STATE *st = ZeroMalloc(sizeof(CONTROL_STATE));
	CONTROL_PEER *peer = ZeroMalloc(sizeof(CONTROL_PEER));

	SplitTestState(st, peer, generation, true, c_key, split);
	bool ok = NodeOverlayApply(s, st);
	SplitTestState(st, peer, generation, false, s_key, split);
	ok = NodeOverlayApply(c, st) && ok;

	Free(peer);
	Free(st);

	return ok;
}

// The number of Noise sessions of the overlay of a node
static UINT SplitTestLinks(NODE *n)
{
	NODE_OVERLAY_STATUS st;

	NodeOverlayGetStatus(n, &st);

	return st.NumLinks;
}

// The host of node-c: its adapters of the VRFs, which the test plugs into its overlay as the client role does
static void SplitTestToHost(NODE *n, void *param, UINT vrf_id, const UCHAR *packet, UINT size)
{
	NodeVrfAdaptersSend((NODE_VRF_ADAPTERS *)param, vrf_id, packet, size);
}

static void SplitTestApplied(NODE *n, void *param, const CONTROL_STATE *st)
{
	NodeVrfAdaptersApply((NODE_VRF_ADAPTERS *)param, st);
}

static void SplitTestHalt(NODE *n, void *param)
{
	NodeVrfAdaptersHalt((NODE_VRF_ADAPTERS *)param);
}

// The fake host of node-s, on the thread of its overlay: it counts what came from the runner
static void SplitTestServerHost(NODE *n, void *param, UINT vrf_id, const UCHAR *packet, UINT size)
{
	SPLITTEST_HOST *h = (SPLITTEST_HOST *)param;
	UINT src = 0;

	if (vrf_id != SPLITTEST_VRF || size < 20 || (packet[0] >> 4) != 4)
	{
		return;
	}

	UINT header = (UINT)(packet[0] & 0x0F) * 4;
	Copy(&src, packet + 12, 4);
	if (packet[9] == IPPROTO_TCP && size >= header + 14)
	{
		bool syn = ((packet[header + 13] & 0x12) == 0x02);

		if (src == splittest_c_fast)
		{
			InterlockedIncrement(&h->TcpFast);
			if (syn)
			{
				InterlockedIncrement(&h->SynFast);
			}
		}
		else if (src == splittest_c_plain && syn)
		{
			InterlockedIncrement(&h->SynPlain);
		}
	}
	else if (packet[9] == IPPROTO_UDP && size >= header + 8 && src == splittest_c_fast && READ_USHORT(packet + header + 2) == SPLITTEST_PORT_UDP)
	{
		InterlockedIncrement(&h->Udp);
	}
}

//
// The runner's end
//

// A TCP connection of the runner to addr:port, which waits wait ms at most: the socket, blocking with the timeouts of the
// test, or INVALID_SOCKET with the error of the connect in *err (WSAETIMEDOUT when it did not end within wait). With pending,
// a connect that did not end within wait gives its socket back into *pending, still connecting.
static SOCKET SplitTestConnect(UINT addr, UINT port, UINT wait, int *err, SOCKET *pending)
{
	SOCKADDR_IN to;
	u_long mode = 1;
	DWORD timeout = SPLITTEST_IO;
	WSAPOLLFD fd;

	*err = 0;
	if (pending != NULL)
	{
		*pending = INVALID_SOCKET;
	}

	SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (s == INVALID_SOCKET)
	{
		*err = WSAGetLastError();
		return INVALID_SOCKET;
	}

	Zero(&to, sizeof(to));
	to.sin_family = AF_INET;
	Copy(&to.sin_addr, &addr, 4);
	to.sin_port = htons((u_short)port);
	ioctlsocket(s, FIONBIO, &mode);
	if (connect(s, (SOCKADDR *)&to, sizeof(to)) != 0 && WSAGetLastError() != WSAEWOULDBLOCK)
	{
		*err = WSAGetLastError();
		closesocket(s);
		return INVALID_SOCKET;
	}

	fd.fd = s;
	fd.events = POLLWRNORM;
	fd.revents = 0;
	int ret = WSAPoll(&fd, 1, (INT)wait);
	if (ret == 0)
	{
		*err = WSAETIMEDOUT;
		if (pending != NULL)
		{
			*pending = s;
		}
		else
		{
			closesocket(s);
		}
		return INVALID_SOCKET;
	}
	if (ret < 0 || (fd.revents & (POLLERR | POLLHUP)) != 0)
	{
		int len = sizeof(*err);

		getsockopt(s, SOL_SOCKET, SO_ERROR, (char *)err, &len);
		closesocket(s);
		return INVALID_SOCKET;
	}

	mode = 0;
	ioctlsocket(s, FIONBIO, &mode);
	setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char *)&timeout, sizeof(timeout));
	setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, (const char *)&timeout, sizeof(timeout));

	return s;
}

// Connect, data and half-close: 128 KiB to the echo, the runner's sending side shut, and the echo read back to its end
static void SplitTestEchoCase(SPLITTEST_CTX *ctx, NODE *c, NODE *s, SPLITTEST_HOST *host, SPLITTEST_FAR *side)
{
	NODE_SPLIT_STATUS cs, ss;
	int err = 0;
	UCHAR *out = Malloc(SPLITTEST_DATA);
	UCHAR *in = ZeroMalloc(SPLITTEST_DATA);
	UINT got = 0;
	bool end = false;

	for (UINT i = 0;i < SPLITTEST_DATA;i++)
	{
		out[i] = (UCHAR)(i * 7 + (i >> 9));
	}

	SOCKET k = SplitTestConnect(splittest_s_fast, SPLITTEST_PORT_ECHO, SPLITTEST_IO, &err, NULL);
	SplitTestCheck(ctx, k != INVALID_SOCKET, "connect: the runner connects from its address in fast to node-s's address there, and the far side takes it",
		"error %d", err);

	if (k != INVALID_SOCKET)
	{
		bool sent = true;

		for (UINT done = 0;sent && done < SPLITTEST_DATA;)
		{
			int w = send(k, (const char *)out + done, (int)MIN((UINT)16384, SPLITTEST_DATA - done), 0);

			sent = (w > 0);
			done += (sent ? (UINT)w : 0);
		}
		shutdown(k, SD_SEND);

		while (got <= SPLITTEST_DATA)
		{
			int r = recv(k, (char *)in + got, (int)(SPLITTEST_DATA - got + (got == SPLITTEST_DATA ? 1 : 0)), 0);

			if (r <= 0)
			{
				end = (r == 0);
				break;
			}
			got += (UINT)r;
			if (got > SPLITTEST_DATA)
			{
				break;
			}
		}
		closesocket(k);

		SplitTestCheck(ctx, sent && got == SPLITTEST_DATA && Cmp(in, out, SPLITTEST_DATA) == 0,
			"data: the 128 KiB that the runner sent come back from the far side, byte for byte", "sent %u, %u bytes back", (UINT)sent, got);
		SplitTestWait(&side->EchoEnd, 1);
		SplitTestCheck(ctx, end && ReadAcquire(&side->EchoEnd) == 1 && (UINT)ReadAcquire(&side->EchoBytes) >= SPLITTEST_DATA,
			"half-close: the far side read the end of the runner's stream after its bytes, and the runner read the end of the far side's",
			"runner read the end %u, far side read the end %u after %u bytes", (UINT)end, (UINT)ReadAcquire(&side->EchoEnd), (UINT)ReadAcquire(&side->EchoBytes));
	}

	NodeSplitGetStatus(c, &cs);
	NodeSplitGetStatus(s, &ss);
	SplitTestCheck(ctx, ReadAcquire(&host->TcpFast) == 0 && cs.Opened >= 1 && cs.Connected >= 1 && ss.Served >= 1 && cs.BytesOut >= SPLITTEST_DATA &&
		cs.BytesIn >= SPLITTEST_DATA && cs.Fins >= 1 && ss.Fins >= 1,
		"the tunnel carried the byte stream alone: node-s's host got no TCP segment of the runner, node-c split the connection and node-s opened it",
		"%u segments to node-s's host; node-c opened %I64u, connected %I64u, %I64u bytes out and %I64u in, %I64u half-closes; node-s served %I64u, %I64u half-closes",
		(UINT)ReadAcquire(&host->TcpFast), cs.Opened, cs.Connected, cs.BytesOut, cs.BytesIn, cs.Fins, ss.Served, ss.Fins);

	Free(out);
	Free(in);
}

// Refused, the resets of either end, and a destination that does not answer
static void SplitTestEnds(SPLITTEST_CTX *ctx, NODE *c, SPLITTEST_FAR *side)
{
	NODE_SPLIT_STATUS before, after;
	SOCKET pending = INVALID_SOCKET;
	int err = 0;
	char buf[16];

	// Refused: the far side has no listener on the port
	SOCKET k = SplitTestConnect(splittest_s_fast, SPLITTEST_PORT_CLOSED, 15000, &err, NULL);
	if (k != INVALID_SOCKET)
	{
		closesocket(k);
	}
	SplitTestCheck(ctx, k == INVALID_SOCKET && err == WSAECONNREFUSED, "refused: the far side refuses the destination, and the runner's connect is refused",
		"connected %u, error %d", (UINT)(k != INVALID_SOCKET), err);

	// A reset of the far side resets the runner's connection
	k = SplitTestConnect(splittest_s_fast, SPLITTEST_PORT_RESET, SPLITTEST_IO, &err, NULL);
	if (k != INVALID_SOCKET)
	{
		send(k, "x", 1, 0);
		int r = recv(k, buf, sizeof(buf), 0);
		err = (r < 0 ? WSAGetLastError() : 0);
		closesocket(k);
	}
	SplitTestCheck(ctx, k != INVALID_SOCKET && err == WSAECONNRESET && ReadAcquire(&side->ResetSent) >= 1,
		"reset of the far side: once the far side resets its connection, the runner's connection is reset", "connected %u, error %d, %u resets sent",
		(UINT)(k != INVALID_SOCKET), err, (UINT)ReadAcquire(&side->ResetSent));

	// A reset of the runner's end resets the far side's connection
	k = SplitTestConnect(splittest_s_fast, SPLITTEST_PORT_WATCH, SPLITTEST_IO, &err, NULL);
	if (k != INVALID_SOCKET)
	{
		struct linger l;

		send(k, "x", 1, 0);
		SplitTestWait(&side->WatchAccepted, 1);
		l.l_onoff = 1;
		l.l_linger = 0;
		setsockopt(k, SOL_SOCKET, SO_LINGER, (const char *)&l, sizeof(l));
		closesocket(k);
	}
	SplitTestWait(&side->WatchReset, 1);
	SplitTestCheck(ctx, k != INVALID_SOCKET && ReadAcquire(&side->WatchReset) == 1, "reset of the runner's end: the far side's connection is reset",
		"connected %u, %u resets seen", (UINT)(k != INVALID_SOCKET), (UINT)ReadAcquire(&side->WatchReset));

	// Timeout: a destination that does not answer leaves the runner's connect waiting, and node-c counts the flow as failed
	NodeSplitGetStatus(c, &before);
	k = SplitTestConnect(splittest_s_fast, SPLITTEST_PORT_SILENT, SPLITTEST_PENDING, &err, &pending);
	NodeSplitGetStatus(c, &after);
	if (k != INVALID_SOCKET)
	{
		closesocket(k);
	}
	if (pending != INVALID_SOCKET)
	{
		closesocket(pending);
	}
	SplitTestCheck(ctx, k == INVALID_SOCKET && pending != INVALID_SOCKET && after.Failed > before.Failed && after.Refused == before.Refused,
		"timeout: a far side that does not answer leaves the runner's connect waiting, neither taken nor refused, and node-c counts the flow as failed",
		"connected %u, still connecting %u, error %d, failed %I64u to %I64u, refused %I64u to %I64u", (UINT)(k != INVALID_SOCKET),
		(UINT)(pending != INVALID_SOCKET), err, before.Failed, after.Failed, before.Refused, after.Refused);
}

// Untouched: a UDP datagram from the runner's address in fast and the SYN of a connection from its address in plain reach
// node-s's host as packets
static void SplitTestUntouched(SPLITTEST_CTX *ctx, SPLITTEST_HOST *host)
{
	SOCKADDR_IN to;
	SOCKET pending = INVALID_SOCKET;
	int err = 0;

	SOCKET u = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	Zero(&to, sizeof(to));
	to.sin_family = AF_INET;
	Copy(&to.sin_addr, &splittest_s_fast, 4);
	to.sin_port = htons(SPLITTEST_PORT_UDP);
	if (u != INVALID_SOCKET)
	{
		sendto(u, "ranz split udp", 14, 0, (SOCKADDR *)&to, sizeof(to));
		closesocket(u);
	}
	SplitTestWait(&host->Udp, 1);
	SplitTestCheck(ctx, ReadAcquire(&host->Udp) >= 1, "untouched: a UDP datagram of the runner from its address in fast reaches node-s's host as a packet",
		"%u datagrams", (UINT)ReadAcquire(&host->Udp));

	SOCKET k = SplitTestConnect(splittest_s_plain, SPLITTEST_PORT_ECHO, 1000, &err, &pending);
	SplitTestWait(&host->SynPlain, 1);
	if (k != INVALID_SOCKET)
	{
		closesocket(k);
	}
	if (pending != INVALID_SOCKET)
	{
		closesocket(pending);
	}
	SplitTestCheck(ctx, ReadAcquire(&host->SynPlain) >= 1,
		"untouched: the SYN of a connection of the runner from its address in plain, which does not split TCP, reaches node-s's host as a packet", "%u SYNs",
		(UINT)ReadAcquire(&host->SynPlain));
}

static void SplitTestRun(SPLITTEST_CTX *ctx)
{
	NODE *s = NULL;
	NODE *c = NULL;
	wchar_t s_dir[MAX_PATH];
	wchar_t c_dir[MAX_PATH];
	wchar_t name[MAX_SIZE];
	UCHAR scalar[PEER_KEY_SIZE];
	PEER_KEY s_key;
	PEER_KEY c_key;
	NODE_OVERLAY_CONFIG cfg;
	NODE_SPLIT_STATUS st;
	SPLITTEST_FAR side;
	NODE_VRF_ADAPTERS *set = NULL;
	SPLITTEST_HOST *host = ZeroMalloc(sizeof(SPLITTEST_HOST));
	TRANSPORT *loopback = TransportLoopbackNew("loopback", 0, false);
	UINT failed = ctx->NumFailed;
	bool far_up = false;

	Zero(&s_key, sizeof(s_key));
	Zero(&c_key, sizeof(c_key));
	UniFormat(name, sizeof(name), L"RanzS%04x", Rand32() & 0xFFFF);

	// The static keys of the two nodes: random scalars, so the adapter of a run has a GUID of its own
	Rand(scalar, sizeof(scalar));
	bool ok = PeerKeyFromScalar(&s_key, scalar);
	Rand(scalar, sizeof(scalar));
	ok = PeerKeyFromScalar(&c_key, scalar) && ok;
	Zero(scalar, sizeof(scalar));

	far_up = (ok && loopback != NULL && SplitTestFarStart(&side));
	ok = SplitTestCheck(ctx, far_up, "node-s and node-c: their static keys and the in-process loopback transport, and the servers of the far side on 127.0.0.1",
		"a key, the transport or a server failed");

	if (ok)
	{
		// node-s: its fake host is the test, and it dials the far side on 127.0.0.1
		SplitTestNewDir(s_dir, sizeof(s_dir), "nodes");
		s = NewNode(s_dir);
		NodeStart(s);
		Zero(&cfg, sizeof(cfg));
		cfg.Data = loopback;
		cfg.Key = &s_key;
		cfg.Adapter = SplitTestServerHost;
		cfg.AdapterParam = host;
		ok = NodeOverlayStart(s, &cfg);
		NodeSplitSetDial(s, SplitTestDial, &side, SPLITTEST_DIAL);

		// node-c: its adapter of corp is a Wintun adapter of the runner, whose TCP stack terminates the connections
		SplitTestNewDir(c_dir, sizeof(c_dir), "nodec");
		c = NewNode(c_dir);
		NodeStart(c);
		set = NodeVrfAdaptersNew(c, name, c_key.Public, false);
		Zero(&cfg, sizeof(cfg));
		cfg.Data = loopback;
		cfg.Key = &c_key;
		cfg.Adapter = SplitTestToHost;
		cfg.AdapterParam = set;
		cfg.AdapterStop = SplitTestHalt;
		cfg.State = SplitTestApplied;
		ok = (set != NULL && NodeOverlayStart(c, &cfg)) && ok;

		ok = SplitTestCheck(ctx, ok, "node-s and node-c: their overlays run, node-c with its adapter of corp as its host", "NodeVrfAdaptersNew or NodeOverlayStart failed");
	}

	// Splitting is off by default: the first Generation has none, and node-c listens nowhere
	if (ok)
	{
		bool applied = SplitTestApply(s, c, 1, s_key.Public, c_key.Public, false);
		bool up = false;

		for (UINT64 end = Tick64() + SPLITTEST_BOUND;applied && up == false && Tick64() < end;SleepThread(SPLITTEST_POLL))
		{
			up = (SplitTestLinks(s) == 1 && SplitTestLinks(c) == 1);
		}

		NodeSplitGetStatus(c, &st);
		ok = SplitTestCheck(ctx, applied && up && st.NumNetworks == 0 && st.NumAddresses == 0,
			"off by default: node-s and node-c apply a Generation that splits nothing, their session is up, and node-c holds no listener",
			"applied %u, sessions %u and %u, %u Networks, %u addresses", (UINT)applied, SplitTestLinks(s), SplitTestLinks(c), st.NumNetworks, st.NumAddresses);
	}

	// The Network fast splits TCP: node-c listens on its address there once its adapter holds it
	if (ok)
	{
		bool applied = SplitTestApply(s, c, 2, s_key.Public, c_key.Public, true);
		bool ready = false;

		for (UINT64 end = Tick64() + SPLITTEST_BOUND;applied && ready == false && Tick64() < end;SleepThread(SPLITTEST_POLL))
		{
			NodeSplitGetStatus(c, &st);
			ready = (st.NumNetworks == 1 && st.NumAddresses == 1 && st.NumReady == 1);
		}

		ok = SplitTestCheck(ctx, ready, "per L3 Network: once fast splits TCP, node-c listens on its address in fast alone, which its adapter holds",
			"applied %u, %u Networks, %u addresses, %u ready", (UINT)applied, st.NumNetworks, st.NumAddresses, st.NumReady);
	}

	if (ok)
	{
		Print("[connect, data and half-close]\n");
		SplitTestEchoCase(ctx, c, s, host, &side);

		Print("[refused, resets and timeout]\n");
		SplitTestEnds(ctx, c, &side);

		Print("[untouched]\n");
		SplitTestUntouched(ctx, host);
	}

	// Off again: the SYN of a new connection from fast reaches node-s's host as a packet, and node-c splits nothing more
	if (ok)
	{
		NODE_SPLIT_STATUS before;
		SOCKET pending = INVALID_SOCKET;
		int err = 0;

		NodeSplitGetStatus(c, &before);
		bool applied = SplitTestApply(s, c, 3, s_key.Public, c_key.Public, false);
		LONG syns = ReadAcquire(&host->SynFast);
		SOCKET k = SplitTestConnect(splittest_s_fast, SPLITTEST_PORT_ECHO, 1000, &err, &pending);
		SplitTestWait(&host->SynFast, syns + 1);
		if (k != INVALID_SOCKET)
		{
			closesocket(k);
		}
		if (pending != INVALID_SOCKET)
		{
			closesocket(pending);
		}

		NodeSplitGetStatus(c, &st);
		SplitTestCheck(ctx, applied && ReadAcquire(&host->SynFast) > syns && st.Opened == before.Opened && st.NumNetworks == 0,
			"off again: once fast no longer splits TCP, the SYN of a new connection from fast reaches node-s's host as a packet, and node-c splits nothing",
			"applied %u, %u SYNs (%u before), opened %I64u (%I64u before), %u Networks", (UINT)applied, (UINT)ReadAcquire(&host->SynFast), (UINT)syns, st.Opened,
			before.Opened, st.NumNetworks);
	}

	if (c != NULL)
	{
		NodeSplitGetStatus(c, &st);
		Print("  [INFO] node-c: opened %I64u, connected %I64u, refused %I64u, failed %I64u, %I64u bytes out, %I64u in, %I64u half-closes, %I64u resets, %I64u dropped\n",
			st.Opened, st.Connected, st.Refused, st.Failed, st.BytesOut, st.BytesIn, st.Fins, st.Resets, st.Dropped);
	}
	if (s != NULL)
	{
		NodeSplitGetStatus(s, &st);
		Print("  [INFO] node-s: served %I64u, denied %I64u, %I64u bytes out, %I64u in, %I64u half-closes, %I64u resets, %I64u dropped\n", st.Served, st.Denied,
			st.BytesOut, st.BytesIn, st.Fins, st.Resets, st.Dropped);
	}

	// The overlays stop, node-c's halting its adapter first, then the adapter, the far side and the nodes go
	if (c != NULL)
	{
		NodeOverlayStop(c);
	}
	if (s != NULL)
	{
		NodeOverlayStop(s);
	}
	if (set != NULL)
	{
		NodeVrfAdaptersFree(set);
	}
	if (far_up)
	{
		SplitTestFarStop(&side);
	}

	bool print_log = (ctx->NumFailed != failed);
	SplitTestFreeNode(c, c_dir, print_log);
	SplitTestFreeNode(s, s_dir, print_log);
	if (loopback != NULL)
	{
		TransportLoopbackFree(loopback);
	}
	Free(host);
}

RANZ_TEST("tcpsplit", tcpsplit_test, "TCP splitting of an L3 Network (CORE-P2-3): the split Networks of a desired state from the wire and the Capability tcpSplit; the runner's TCP stack terminates its connections from its address in a Network that splits TCP, node-s opens them to the far side, an unmodified TCP server, and connect, data, half-close, refused, the resets of either end and timeout map to the far side; UDP and a Network without splitting take the packet path, and splitting is off by default (administrator rights, wintun.dll).");
void tcpsplit_test(UINT num, char **arg)
{
	SPLITTEST_CTX *ctx = ZeroMalloc(sizeof(SPLITTEST_CTX));
	SPLITTEST_WATCH w;

	splittest_c_fast = SplitTestAddr(198, 19, 81, 2);
	splittest_s_fast = SplitTestAddr(198, 19, 81, 1);
	splittest_c_plain = SplitTestAddr(198, 19, 82, 2);
	splittest_s_plain = SplitTestAddr(198, 19, 82, 1);

	Zero(&w, sizeof(w));
	w.Done = CreateEventW(NULL, TRUE, FALSE, NULL);
	HANDLE watchdog = CreateThread(NULL, 0, SplitTestWatchdog, &w, 0, NULL);

	Print("TCP splitting test: a Network that splits TCP between a node on a Wintun adapter of the runner and a node that opens its connections to the far side\n");

	SplitTestControl(ctx);
	SplitTestRun(ctx);

	SetEvent(w.Done);
	if (watchdog != NULL)
	{
		WaitForSingleObject(watchdog, INFINITE);
		CloseHandle(watchdog);
	}
	CloseHandle(w.Done);

	if (ctx->NumFailed == 0)
	{
		Print("TCPSPLIT TEST OK\n");
	}
	else
	{
		Print("TCPSPLIT TEST FAILED (%u of %u checks failed)\n", ctx->NumFailed, ctx->NumChecks);
	}

	Free(ctx);
}
