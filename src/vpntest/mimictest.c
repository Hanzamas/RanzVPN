// mimictest.c
// Named mimic transport test of vpntest ("mimic" command, CORE-P2-6 #406)
//
// mimic: the mimic transport of a node over its mimicry sidecar, the subcommand mimic of ranz.exe (Cedar/NodeMimic.c,
// Cedar/NodeMimicTransport.c, controller/internal/mimic), with the real ranz.exe next to vpntest.exe, as the BGP test
// runs it. A node without a mimic setting has no transport; a node without ranz.exe next to it has none and says why,
// and runs on; a setting that the sidecar refuses is logged, and the role stays unavailable. Then a node with the server
// role listens, which starts its sidecar as a server with a REALITY listener on 127.0.0.1 and an own decoy; the first
// start of that sidecar meets another client on its control pipe, which the node refuses, and the node starts the
// sidecar again after the delay. A node with the client role dials it through its own sidecar:
// - the transport conformance of the transport test: a Noise session over the stream (the handshake, the Login, control
//   and data both ways, the largest payload, keepalives and the outer rekey, the close), both ends with the same channel
//   binding, the race of a fallback list, and a dial that a cancel ends;
// - a client that changes the binding it computes fails the handshake;
// - a prober that is a plain TLS client (the TLS transport of the core, which checks no certificate) is spliced to the
//   decoy and gets its page; the node counts one probe and writes no log line for it;
// - the sidecar of the client role, killed, is started again after the delay: the session over it ends, and a new
//   dial works;
// - the counters in the status structure of each node match what the test did;
// - the listener closes and the node stops: each sidecar exits;
// - the REALITY private key of the settings is in no log line, in no command line of a sidecar and in no file of the
//   diagnostics bundle (ranz doctor -bundle, unpacked by the tar of Windows).
// Print "MIMIC TEST OK" only when every check passes.

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

#include "Core/Transport.h"

#include <stdio.h>

#define	MIMICTEST_BUDGET		300000		// The whole test ends within this time, or the watchdog ends the process (ms)
#define	MIMICTEST_BOUND			90000		// A bounded wait on observable state: a server sidecar first probes its decoy (ms)
#define	MIMICTEST_TIMEOUT		15000		// A handshake, an accept or a record within this time (ms)
#define	MIMICTEST_SETTLE		3000		// How long the test waits before it checks that something did not happen (ms)
#define	MIMICTEST_KEEPALIVE		100			// The keepalive interval of the test sessions (ms)
#define	MIMICTEST_REKEY			300			// Their rekey interval (ms)
#define	MIMICTEST_DEAD			5000		// Their dead-peer timeout (ms)
#define	MIMICTEST_IDLE			1000		// The idle wait in which keepalives and a rekey must pass (ms)
#define	MIMICTEST_CANCEL		500			// When the test cancels a dial that hangs (ms)
#define	MIMICTEST_PROMPT		3000		// A cancelled dial returns within this time after the cancel (ms)
#define	MIMICTEST_RUN_WAIT		120000		// A command that the test runs ends within this time (ms)
#define	MIMICTEST_HUB			"MIMIC"
#define	MIMICTEST_USER			"tester"
#define	MIMICTEST_PASSWORD		"Mimic-Pass-1"
#define	MIMICTEST_WELCOME		"welcome"
#define	MIMICTEST_NAME			"decoy.test"
#define	MIMICTEST_PAGE			"ranz mimic decoy page of the vpntest harness"
#define	MIMICTEST_HANG			"192.0.2.1:443"	// A link whose server never answers (TEST-NET-1)

// The REALITY key pair of the server: the key pair of Alice of RFC 7748 section 6.1, the private key planted in the
// settings, which must reach the sidecar only over its control pipe
#define	MIMICTEST_PRIVATE		"77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"
#define	MIMICTEST_PUBLIC		"8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"

#define	MIMICTEST_SERVER_SETTINGS	"{\"listen\":\"127.0.0.1:0\",\"private_key\":\"" MIMICTEST_PRIVATE "\",\"short_ids\":[\"a1b2\"]," \
									"\"server_names\":[\"" MIMICTEST_NAME "\"],\"decoy\":{\"mode\":\"own\",\"page\":\"<html>" MIMICTEST_PAGE "</html>\",\"self_signed\":true}}"

// The checks of the test
typedef struct MIMICTEST_CTX
{
	UINT NumChecks;						// Checks run so far
	UINT NumFailed;						// Checks failed so far
	UINT64 NumStreams;					// The streams that the client dialled and the server's sidecar carried
} MIMICTEST_CTX;

// The server end of a test session, on a thread of its own
typedef struct MIMICTEST_SERVER
{
	TRANSPORT_LISTENER *Listener;		// It accepts one stream here
	NOISE_SESSION_CONFIG Config;		// The responder's configuration
	bool Got;							// A stream came
	UINT BindingType;					// The channel binding of the stream
	UCHAR Binding[NOISE_MAX_BINDING];
	UINT BindingSize;
	bool Accepted;						// The handshake completed
	bool LoggedIn;						// The first control record was the Login of the test user
	UINT NumEchoed;						// Control and data records sent back
	UINT LastReceive;					// What the last receive gave
	UCHAR HandshakeHash[NOISE_KEY_SIZE];// The handshake hash
} MIMICTEST_SERVER;

// The client's half of a session over a stream, with its server thread
typedef struct MIMICTEST_SESSION
{
	MIMICTEST_SERVER *Server;
	THREAD *Thread;
	TRANSPORT_NOISE *Noise;
	bool Connected;
	UCHAR ClientKey[NOISE_KEY_SIZE];
	UCHAR ServerKey[NOISE_KEY_SIZE];
} MIMICTEST_SESSION;

// What the hook of the server node did: it connects to the control pipe of the first sidecar before the sidecar starts
typedef struct MIMICTEST_IMPOSTOR
{
	UINT NumCalls;
	HANDLE Pipe;
} MIMICTEST_IMPOSTOR;

// A UNICODE_STRING of ntdll, as NtQueryInformationProcess gives the command line of a process
typedef struct MIMICTEST_UNICODE
{
	USHORT Length;						// Bytes of the string, without a NUL
	USHORT MaximumLength;
	wchar_t *Buffer;
} MIMICTEST_UNICODE;

// The cancel of a dial that hangs, set from a thread of its own
typedef struct MIMICTEST_CANCEL_AT
{
	HANDLE Event;
	UINT Delay;
} MIMICTEST_CANCEL_AT;

// The Binding procedure of the client's transport, which the transport with a changed binding calls first
static TRANSPORT_BINDING_PROC *mimictest_binding = NULL;

static bool MimicTestCheck(MIMICTEST_CTX *ctx, bool ok, char *what, char *fmt, ...) RANZ_PRINTF_FORMAT(4, 5);
static bool MimicTestCheck(MIMICTEST_CTX *ctx, bool ok, char *what, char *fmt, ...)
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
static DWORD WINAPI MimicTestWatchdog(LPVOID param)
{
	char msg[MAX_SIZE];
	DWORD written = 0;

	if (WaitForSingleObject((HANDLE)param, MIMICTEST_BUDGET) != WAIT_TIMEOUT)
	{
		return 0;
	}

	int len = snprintf(msg, sizeof(msg), "MIMIC TEST FAILED (did not finish within %u ms)\n", MIMICTEST_BUDGET);
	if (len > 0)
	{
		WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), msg, (DWORD)MIN((UINT)len, (UINT)sizeof(msg) - 1), &written, NULL);
	}

	TerminateProcess(GetCurrentProcess(), 1);

	return 0;
}

//
// The data directories, the logs and the processes
//

// A new empty data directory under the temp directory of the process
static void MimicTestNewDir(wchar_t *dir, UINT size, char *name)
{
	wchar_t tmp[MAX_PATH];

	UniFormat(tmp, sizeof(tmp), L"mimic_%S_%u", name, (UINT)Tick64());
	ConbinePathW(dir, size, MsGetMyTempDirW(), tmp);
	MakeDirExW(dir);
}

// Delete a directory with everything in it
static void MimicTestDeleteTree(wchar_t *dir)
{
	DIRLIST *d = EnumDirW(dir);

	for (UINT i = 0;d != NULL && i < d->NumFiles;i++)
	{
		DIRENT *e = d->File[i];
		wchar_t path[MAX_PATH];

		ConbinePathW(path, sizeof(path), dir, e->FileNameW);
		if (e->Folder)
		{
			MimicTestDeleteTree(path);
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
static void MimicTestWriteConfig(wchar_t *dir, char *server, char *client)
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

// Append the text of every file under dir, and of its directories, to b
static void MimicTestReadTree(BUF *b, wchar_t *dir)
{
	DIRLIST *d = EnumDirW(dir);

	for (UINT i = 0;d != NULL && i < d->NumFiles;i++)
	{
		DIRENT *e = d->File[i];
		wchar_t path[MAX_PATH];

		ConbinePathW(path, sizeof(path), dir, e->FileNameW);
		if (e->Folder)
		{
			MimicTestReadTree(b, path);
			continue;
		}

		BUF *f = ReadDumpW(path);
		if (f != NULL)
		{
			WriteBuf(b, f->Buf, f->Size);
			WriteBuf(b, "\n", 1);
			FreeBuf(f);
		}
	}

	FreeDir(d);
}

// The text of a file of the node log directory of dir, or of every file there for NULL; "" when there is none. The
// caller frees it.
static char *MimicTestReadLog(wchar_t *dir, wchar_t *name)
{
	wchar_t log_dir[MAX_PATH];
	BUF *b = NewBuf();

	ConbinePathW(log_dir, sizeof(log_dir), dir, NODE_LOG_DIR_NAME);

	if (name == NULL)
	{
		MimicTestReadTree(b, log_dir);
	}
	else
	{
		wchar_t path[MAX_PATH];

		ConbinePathW(path, sizeof(path), log_dir, name);
		BUF *f = ReadDumpW(path);
		if (f != NULL)
		{
			WriteBuf(b, f->Buf, f->Size);
			FreeBuf(f);
		}
	}

	char *ret = ZeroMalloc(b->Size + 1);
	Copy(ret, b->Buf, b->Size);
	FreeBuf(b);

	return ret;
}

// The text of the node log of dir alone, its files node_*.log in their order, without the logs of the sidecars; the
// caller frees it
static char *MimicTestReadNodeLog(wchar_t *dir)
{
	wchar_t log_dir[MAX_PATH];
	BUF *b = NewBuf();

	ConbinePathW(log_dir, sizeof(log_dir), dir, NODE_LOG_DIR_NAME);

	DIRLIST *d = EnumDirW(log_dir);
	for (UINT i = 0;d != NULL && i < d->NumFiles;i++)
	{
		DIRENT *e = d->File[i];
		wchar_t path[MAX_PATH];

		if (e->Folder || UniStartWith(e->FileNameW, L"node_") == false)
		{
			continue;
		}

		ConbinePathW(path, sizeof(path), log_dir, e->FileNameW);
		BUF *f = ReadDumpW(path);
		if (f != NULL)
		{
			WriteBuf(b, f->Buf, f->Size);
			FreeBuf(f);
		}
	}
	FreeDir(d);

	char *ret = ZeroMalloc(b->Size + 1);
	Copy(ret, b->Buf, b->Size);
	FreeBuf(b);

	return ret;
}

// Whether the text holds part, case ignored
static bool MimicTestHas(char *text, char *part)
{
	return (text != NULL && SearchStrEx(text, part, 0, false) != INFINITE);
}

// The command line of the process pid, as Windows keeps it; "" when it cannot be read
static void MimicTestCommandLine(UINT pid, char *out, UINT size)
{
	typedef LONG (NTAPI MIMICTEST_QUERY)(HANDLE, UINT, PVOID, ULONG, PULONG);
	MIMICTEST_QUERY *query = (MIMICTEST_QUERY *)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQueryInformationProcess");
	ULONG len = 0;

	StrCpy(out, size, "");

	HANDLE p = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
	if (p == NULL || query == NULL)
	{
		if (p != NULL)
		{
			CloseHandle(p);
		}
		return;
	}

	// ProcessCommandLineInformation (60): a UNICODE_STRING and the characters after it
	UCHAR *buf = ZeroMalloc(65536);
	if (query(p, 60, buf, 65536, &len) >= 0)
	{
		MIMICTEST_UNICODE *s = (MIMICTEST_UNICODE *)buf;
		wchar_t *tmp = ZeroMalloc(s->Length + sizeof(wchar_t));

		Copy(tmp, s->Buffer, s->Length);
		UniToStr(out, size, tmp);
		Free(tmp);
	}
	Free(buf);
	CloseHandle(p);
}

// Whether the process pid has exited, or never was
static bool MimicTestExited(UINT pid)
{
	HANDLE p = OpenProcess(SYNCHRONIZE, FALSE, pid);
	bool exited = (p == NULL || WaitForSingleObject(p, MIMICTEST_SETTLE) == WAIT_OBJECT_0);

	if (p != NULL)
	{
		CloseHandle(p);
	}

	return exited;
}

// Run a command line and wait for it; its exit code, or INFINITE when it could not start or did not end in time
static UINT MimicTestRun(wchar_t *cmd)
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

	if (WaitForSingleObject(pi.hProcess, MIMICTEST_RUN_WAIT) == WAIT_OBJECT_0)
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

// Wait until the status of a role of the node says that its sidecar runs, with another process than not_pid; false
// when it did not within MIMICTEST_BOUND
static bool MimicTestWaitRunning(NODE *n, UINT role, UINT not_pid, NODE_STATUS *st)
{
	UINT64 end = Tick64() + MIMICTEST_BOUND;

	while (true)
	{
		NodeGetStatus(n, st);

		if (st->Mimic[role].Running && st->Mimic[role].ProcessId != not_pid)
		{
			return true;
		}

		if (Tick64() >= end)
		{
			return false;
		}
		SleepThread(100);
	}
}

// Wait until the counters of a role in the status of the node are these; false when they were not within
// MIMICTEST_BOUND
static bool MimicTestWaitCounters(NODE *n, UINT role, UINT64 accepted, UINT64 probes, UINT64 streams, NODE_STATUS *st)
{
	UINT64 end = Tick64() + MIMICTEST_BOUND;

	while (true)
	{
		NodeGetStatus(n, st);

		NODE_MIMIC_STATUS *m = &st->Mimic[role];
		if (m->Accepted == accepted && m->Probes == probes && m->Streams == streams)
		{
			return true;
		}

		if (Tick64() >= end)
		{
			return false;
		}
		SleepThread(100);
	}
}

//
// The sessions
//

// The configuration of an end of a test session: short timers, so that keepalives and a rekey pass while the test waits
static void MimicTestConfig(NOISE_SESSION_CONFIG *c, UCHAR *key, UCHAR *remote)
{
	Zero(c, sizeof(NOISE_SESSION_CONFIG));
	c->Suite = NOISE_SUITE_IK;
	c->StaticKey = key;
	c->RemoteStatic = remote;
	c->KeepaliveInterval = MIMICTEST_KEEPALIVE;
	c->DeadTimeout = MIMICTEST_DEAD;
	c->RekeyInterval = MIMICTEST_REKEY;
}

// The server end of a test session: it accepts one stream and runs the responder. The first control record must be
// the Login of the test user; every later control and data record goes back as it came, until the session ends.
static void MimicTestServerThread(THREAD *thread, void *param)
{
	MIMICTEST_SERVER *srv = (MIMICTEST_SERVER *)param;
	TRANSPORT_NOISE *n = ZeroMalloc(sizeof(TRANSPORT_NOISE));
	UCHAR *buf = ZeroMalloc(NOISE_MAX_PAYLOAD);
	TRANSPORT_STREAM *s = TransportAccept(srv->Listener, MIMICTEST_TIMEOUT);

	srv->Got = (s != NULL);
	srv->BindingType = TransportBinding(s, srv->Binding, sizeof(srv->Binding), &srv->BindingSize);
	srv->Accepted = (s != NULL && TransportNoiseAccept(n, s, &srv->Config, MIMICTEST_TIMEOUT));
	if (srv->Accepted)
	{
		Copy(srv->HandshakeHash, n->Session.HandshakeHash, NOISE_KEY_SIZE);
	}

	while (srv->Accepted)
	{
		UINT size = 0;
		UINT ret = TransportNoiseReceive(n, buf, NOISE_MAX_PAYLOAD, &size, MIMICTEST_BOUND);

		srv->LastReceive = ret;
		if (ret != NOISE_RECEIVE_CONTROL && ret != NOISE_RECEIVE_DATA)
		{
			break;
		}

		if (srv->LoggedIn == false)
		{
			NOISE_LOGIN login;

			srv->LoggedIn = (ret == NOISE_RECEIVE_CONTROL && NoiseLoginParse(&login, buf, size) && login.Method == NOISE_LOGIN_PASSWORD &&
				StrCmp(login.HubName, MIMICTEST_HUB) == 0 && StrCmp(login.UserName, MIMICTEST_USER) == 0 &&
				StrCmp(login.Password, MIMICTEST_PASSWORD) == 0);
			Zero(&login, sizeof(login));
			if (srv->LoggedIn == false)
			{
				break;
			}

			TransportNoiseAcceptLogin(n);
			TransportNoiseSend(n, NOISE_RECORD_CONTROL, MIMICTEST_WELCOME, StrLen(MIMICTEST_WELCOME));
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
static bool MimicTestEcho(MIMICTEST_CTX *ctx, TRANSPORT_NOISE *n, UINT type, const void *data, UINT size, char *what)
{
	UCHAR *buf = ZeroMalloc(NOISE_MAX_PAYLOAD);
	UINT got = 0;
	bool sent = TransportNoiseSend(n, type, data, size);
	UINT ret = TransportNoiseReceive(n, buf, NOISE_MAX_PAYLOAD, &got, MIMICTEST_TIMEOUT);
	UINT expect = (type == NOISE_RECORD_DATA ? NOISE_RECEIVE_DATA : NOISE_RECEIVE_CONTROL);

	bool ok = MimicTestCheck(ctx, sent && ret == expect && got == size && Cmp(buf, (void *)data, size) == 0, what,
		"sent %u, receive %u, %u of %u bytes", (UINT)sent, ret, got, size);

	Free(buf);

	return ok;
}

// Open a session over the client's stream s against a server thread on the listener l: the handshake and the Login.
// The caller ends it with MimicTestEndSession.
static MIMICTEST_SESSION *MimicTestOpenSession(MIMICTEST_CTX *ctx, TRANSPORT_LISTENER *l, TRANSPORT_STREAM *s, bool expect)
{
	MIMICTEST_SESSION *t = ZeroMalloc(sizeof(MIMICTEST_SESSION));
	UCHAR client_pub[NOISE_KEY_SIZE], server_pub[NOISE_KEY_SIZE];
	NOISE_SESSION_CONFIG cc;
	NOISE_LOGIN login;
	UINT size = 0;

	t->Server = ZeroMalloc(sizeof(MIMICTEST_SERVER));
	t->Noise = ZeroMalloc(sizeof(TRANSPORT_NOISE));

	CryptoX25519GenerateKey(t->ClientKey, client_pub);
	CryptoX25519GenerateKey(t->ServerKey, server_pub);
	MimicTestConfig(&cc, t->ClientKey, server_pub);
	MimicTestConfig(&t->Server->Config, t->ServerKey, NULL);
	t->Server->Listener = l;
	t->Thread = NewThread(MimicTestServerThread, t->Server);

	t->Connected = (s != NULL && TransportNoiseConnect(t->Noise, s, &cc, MIMICTEST_TIMEOUT));

	if (t->Connected && expect)
	{
		UCHAR *buf = ZeroMalloc(NOISE_MAX_PAYLOAD);

		Zero(&login, sizeof(login));
		login.Method = NOISE_LOGIN_PASSWORD;
		StrCpy(login.HubName, sizeof(login.HubName), MIMICTEST_HUB);
		StrCpy(login.UserName, sizeof(login.UserName), MIMICTEST_USER);
		StrCpy(login.Password, sizeof(login.Password), MIMICTEST_PASSWORD);
		bool sent = NoiseLoginEncode(&login, buf, NOISE_MAX_PAYLOAD, &size) && TransportNoiseSend(t->Noise, NOISE_RECORD_CONTROL, buf, size);
		UINT ret = TransportNoiseReceive(t->Noise, buf, NOISE_MAX_PAYLOAD, &size, MIMICTEST_TIMEOUT);
		MimicTestCheck(ctx, sent && ret == NOISE_RECEIVE_CONTROL && size == StrLen(MIMICTEST_WELCOME) && Cmp(buf, MIMICTEST_WELCOME, size) == 0,
			"  the Login goes as the first control message, the server answers on the control stream", "sent %u, receive %u, %u bytes", (UINT)sent, ret, size);
		Zero(&login, sizeof(login));
		Free(buf);
	}

	return t;
}

// Close the client's end of a session and wait for the server thread
static void MimicTestEndSession(MIMICTEST_SESSION *t)
{
	TransportNoiseClose(t->Noise);
	WaitThread(t->Thread, INFINITE);
	ReleaseThread(t->Thread);

	Zero(t->ClientKey, sizeof(t->ClientKey));
	Zero(t->ServerKey, sizeof(t->ServerKey));
	Free(t->Noise);
	Free(t->Server);
	Free(t);
}

// The conformance of the transport, as the transport test runs it over the loopback transport: a Noise session over a
// stream that the client dialled, bound to the outer TLS session of the sidecars, with the same binding at both ends
static void MimicTestConformance(MIMICTEST_CTX *ctx, TRANSPORT *client, TRANSPORT_LISTENER *l, char *address)
{
	UCHAR binding[NOISE_MAX_BINDING];
	UINT binding_size = 0;
	UCHAR *buf = ZeroMalloc(NOISE_MAX_PAYLOAD);
	UCHAR *big = ZeroMalloc(NOISE_MAX_PAYLOAD);
	UINT size = 0;

	Print("[a Noise session over the mimic transport]\n");

	TRANSPORT_STREAM *s = TransportDial(client, address, NULL);
	MimicTestCheck(ctx, s != NULL && TransportOf(s) == client, "  the client node dials the server node through its sidecar", "TransportDial of %s failed", address);
	UINT binding_type = TransportBinding(s, binding, sizeof(binding), &binding_size);
	if (s != NULL)
	{
		ctx->NumStreams++;
	}

	MIMICTEST_SESSION *t = MimicTestOpenSession(ctx, l, s, true);
	MimicTestCheck(ctx, t->Connected, "  the Noise_IK handshake over the stream", "%s", "TransportNoiseConnect failed");

	if (t->Connected)
	{
		TRANSPORT_NOISE *n = t->Noise;

		MimicTestCheck(ctx, binding_type == NOISE_BINDING_EXPORTER && binding_size == NODE_MIMIC_BINDING && (n->Session.Flags & NOISE_SESSION_ENCRYPT) == 0,
			"  the stream carries the TLS exporter of the outer session: the session is bound and sends its records in clear",
			"binding type %u of %u bytes, flags 0x%x", binding_type, binding_size, n->Session.Flags);

		MimicTestEcho(ctx, n, NOISE_RECORD_CONTROL, "status", 6, "  a control message both ways");
		MimicTestEcho(ctx, n, NOISE_RECORD_DATA, "frame", 5, "  a data record both ways");
		Rand(big, NOISE_MAX_PAYLOAD);
		MimicTestEcho(ctx, n, NOISE_RECORD_DATA, big, NOISE_MAX_PAYLOAD, "  a data record of the largest payload both ways");

		// Idle: the keepalives of the server keep the session open, and the session asks for its outer keys on schedule
		UINT64 received = n->NumReceived;
		UINT ret = TransportNoiseReceive(n, buf, NOISE_MAX_PAYLOAD, &size, MIMICTEST_IDLE);
		MimicTestCheck(ctx, ret == NOISE_RECEIVE_NONE && n->Session.State == NOISE_STATE_OPEN && n->NumReceived >= received + 2,
			"  an idle session stays open on keepalives", "receive %u, state %u, %I64u records", ret, n->Session.State, n->NumReceived - received);
		MimicTestCheck(ctx, n->Session.NumRekeys != 0, "  the session asked for the outer keys on schedule, which the sidecar's TLS session keeps",
			"%I64u rekeys", n->Session.NumRekeys);
		MimicTestEcho(ctx, n, NOISE_RECORD_DATA, "after", 5, "  a data record after the rekey");
	}

	// The close: the server gets the close record
	MimicTestEndSession(t);

	Free(big);
	Free(buf);
}

// The conformance checks that need the server's end after the close: kept apart so that the session above reads as
// the one of the transport test
static void MimicTestConformanceServer(MIMICTEST_CTX *ctx, TRANSPORT *client, TRANSPORT_LISTENER *l, char *address)
{
	UCHAR binding[NOISE_MAX_BINDING];
	UINT binding_size = 0;
	UCHAR hash[NOISE_KEY_SIZE];

	Print("[both ends of a session over the mimic transport]\n");

	TRANSPORT_STREAM *s = TransportDial(client, address, NULL);
	UINT binding_type = TransportBinding(s, binding, sizeof(binding), &binding_size);
	if (s != NULL)
	{
		ctx->NumStreams++;
	}

	MIMICTEST_SESSION *t = MimicTestOpenSession(ctx, l, s, true);
	if (t->Connected)
	{
		MimicTestEcho(ctx, t->Noise, NOISE_RECORD_DATA, "both", 4, "  a data record both ways");
	}
	Copy(hash, t->Noise->Session.HandshakeHash, NOISE_KEY_SIZE);

	TransportNoiseClose(t->Noise);
	WaitThread(t->Thread, INFINITE);
	ReleaseThread(t->Thread);

	MIMICTEST_SERVER *srv = t->Server;
	MimicTestCheck(ctx, t->Connected && srv->Accepted && srv->LoggedIn && Cmp(srv->HandshakeHash, hash, NOISE_KEY_SIZE) == 0,
		"  the server node accepted the stream and the session, with the same handshake hash, and took the Login", "connected %u, accepted %u, logged in %u",
		(UINT)t->Connected, (UINT)srv->Accepted, (UINT)srv->LoggedIn);
	MimicTestCheck(ctx, srv->BindingType == binding_type && binding_type == NOISE_BINDING_EXPORTER && srv->BindingSize == binding_size &&
		Cmp(srv->Binding, binding, binding_size) == 0,
		"  both ends got the same channel binding from their sidecars", "client type %u of %u bytes, server type %u of %u bytes", binding_type, binding_size,
		srv->BindingType, srv->BindingSize);
	MimicTestCheck(ctx, srv->NumEchoed == 1 && srv->LastReceive == NOISE_RECEIVE_CLOSE, "  the server sent the record back and got the close",
		"%u sent back, last receive %u", srv->NumEchoed, srv->LastReceive);

	Zero(t->ClientKey, sizeof(t->ClientKey));
	Zero(t->ServerKey, sizeof(t->ServerKey));
	Free(t->Noise);
	Free(t->Server);
	Free(t);
}

// The binding of a client that computes a binding of its own, as a middlebox that terminated the TLS would
static UINT MimicTestBrokenBinding(void *stream, UCHAR *binding, UINT max, UINT *size)
{
	UINT type = mimictest_binding(stream, binding, max, size);

	if (type != NOISE_BINDING_NONE && *size != 0)
	{
		binding[0] ^= 0xFF;
	}

	return type;
}

// A client that changes the binding it computes fails the handshake
static void MimicTestBrokenSession(MIMICTEST_CTX *ctx, TRANSPORT *client, TRANSPORT_LISTENER *l, char *address)
{
	TRANSPORT broken;

	Print("[a client that changes the binding it computes]\n");

	Copy(&broken, client, sizeof(TRANSPORT));
	mimictest_binding = client->Binding;
	broken.Binding = MimicTestBrokenBinding;

	TRANSPORT_STREAM *s = TransportDial(&broken, address, NULL);
	if (s != NULL)
	{
		ctx->NumStreams++;
	}

	MIMICTEST_SESSION *t = MimicTestOpenSession(ctx, l, s, false);
	bool connected = t->Connected;
	TransportNoiseClose(t->Noise);
	WaitThread(t->Thread, INFINITE);
	ReleaseThread(t->Thread);

	MimicTestCheck(ctx, s != NULL && t->Server->Got && connected == false && t->Server->Accepted == false,
		"  the stream connects, but the handshake fails at both ends: the prologues differ", "stream %u, the server got one %u, connected %u, accepted %u",
		(UINT)(s != NULL), (UINT)t->Server->Got, (UINT)connected, (UINT)t->Server->Accepted);

	Zero(t->ClientKey, sizeof(t->ClientKey));
	Zero(t->ServerKey, sizeof(t->ServerKey));
	Free(t->Noise);
	Free(t->Server);
	Free(t);
}

// Set the cancel of a dial after its delay
static void MimicTestCancelThread(THREAD *thread, void *param)
{
	MIMICTEST_CANCEL_AT *c = (MIMICTEST_CANCEL_AT *)param;

	SleepThread(c->Delay);
	SetEvent(c->Event);
}

// A dial that a cancel ends returns promptly, and the race of a fallback list takes the link that answers
static void MimicTestCancelAndRace(MIMICTEST_CTX *ctx, TRANSPORT *client, TRANSPORT_LISTENER *l, char *address)
{
	MIMICTEST_CANCEL_AT c;
	TRANSPORT_TARGET targets[TRANSPORT_MAX_TARGETS];
	TRANSPORT_RACE race;
	char list[MAX_SIZE];

	Print("[cancel and race]\n");
	Zero(&c, sizeof(c));

	// A cancel that is set already: the dial does not start
	c.Event = CreateEventW(NULL, TRUE, TRUE, NULL);
	UINT64 start = Tick64();
	TRANSPORT_STREAM *s = TransportDial(client, MIMICTEST_HANG, c.Event);
	MimicTestCheck(ctx, s == NULL && Tick64() - start < MIMICTEST_PROMPT, "  a dial whose cancel is set returns at once, without a stream",
		"stream %u after %I64u ms", (UINT)(s != NULL), Tick64() - start);
	TransportClose(s);

	// A dial to a link whose server never answers, cancelled while the sidecar waits for it
	ResetEvent(c.Event);
	c.Delay = MIMICTEST_CANCEL;
	THREAD *t = NewThread(MimicTestCancelThread, &c);
	start = Tick64();
	s = TransportDial(client, MIMICTEST_HANG, c.Event);
	UINT64 took = Tick64() - start;
	WaitThread(t, INFINITE);
	ReleaseThread(t);
	MimicTestCheck(ctx, s == NULL && took < MIMICTEST_CANCEL + MIMICTEST_PROMPT, "  a dial that hangs returns promptly once its cancel is set",
		"stream %u after %I64u ms", (UINT)(s != NULL), took);
	TransportClose(s);
	CloseHandle(c.Event);

	// The race: the link that hangs first, the link of the server after it
	Format(list, sizeof(list), "%s:%s, %s:%s", NODE_MIMIC_TRANSPORT, MIMICTEST_HANG, NODE_MIMIC_TRANSPORT, address);
	UINT num = TransportParseList(list, &client, 1, targets, TRANSPORT_MAX_TARGETS);
	s = TransportRace(targets, num, TRANSPORT_RACE_DELAY, MIMICTEST_BOUND, &race);
	MimicTestCheck(ctx, num == 2 && s != NULL && race.Winner == 1, "  the race of a fallback list of two mimic links: the one that answers wins",
		"%u entries, winner %u, %s", num, race.Winner, s != NULL ? "a stream" : "no stream");

	if (s != NULL)
	{
		ctx->NumStreams++;

		TRANSPORT_STREAM *peer = TransportAccept(l, MIMICTEST_TIMEOUT);
		bool sent = TransportWrite(s, "race", 4);
		char got[8];
		UINT n = (peer != NULL ? TransportRead(peer, got, sizeof(got), MIMICTEST_TIMEOUT) : 0);
		MimicTestCheck(ctx, peer != NULL && sent && n == 4 && Cmp(got, "race", 4) == 0, "  the winner's stream reaches the listener: bytes written are read",
			"accepted %u, sent %u, read %u", (UINT)(peer != NULL), (UINT)sent, n);

		// The close: the peer reads the end
		TransportClose(s);
		n = (peer != NULL ? TransportRead(peer, got, sizeof(got), MIMICTEST_TIMEOUT) : 1);
		MimicTestCheck(ctx, n == 0, "  a closed stream ends at the peer", "the read gave %u", n);
		TransportClose(peer);
	}
}

// The verification of a prober's TLS client: any certificate, as a prober takes the decoy's
static bool MimicTestAnyCert(void *param, const struct _CERT_CONTEXT *cert)
{
	UNREFERENCED_PARAMETER(param);
	UNREFERENCED_PARAMETER(cert);

	return true;
}

// A prober that is a plain TLS client: it is spliced to the decoy and sees its page; the node counts one probe and
// writes no log line for it
static void MimicTestProber(MIMICTEST_CTX *ctx, NODE *server, wchar_t *dir, char *address)
{
	TRANSPORT_TLS_CONFIG cfg;
	NODE_STATUS st;
	char request[MAX_SIZE];
	BUF *page = NewBuf();

	Print("[a prober]\n");

	// The counters before it: every stream so far, and no probe
	UINT64 accepted = ctx->NumStreams;
	UINT64 streams = ctx->NumStreams;
	UINT64 probes = 0;
	bool counted = MimicTestWaitCounters(server, NODE_MIMIC_ROLE_SERVER, accepted, probes, streams, &st);
	MimicTestCheck(ctx, counted, "  before the prober, the server node counted every stream as a client that proved the key", "%I64u accepted, %I64u probes, %I64u streams; %I64u dialled",
		st.Mimic[NODE_MIMIC_ROLE_SERVER].Accepted, st.Mimic[NODE_MIMIC_ROLE_SERVER].Probes, st.Mimic[NODE_MIMIC_ROLE_SERVER].Streams, ctx->NumStreams);
	char *before = MimicTestReadNodeLog(dir);

	TransportTlsDefaultConfig(&cfg, "", false);
	cfg.SetGroups = false;
	cfg.Verify = MimicTestAnyCert;
	TRANSPORT *tls = TransportTlsClientNew(&cfg);
	TRANSPORT_STREAM *s = (tls != NULL ? TransportDial(tls, address, NULL) : NULL);
	MimicTestCheck(ctx, s != NULL, "  a plain TLS client completes a handshake on the REALITY listener", "transport %u, stream %u", (UINT)(tls != NULL), (UINT)(s != NULL));

	if (s != NULL)
	{
		Format(request, sizeof(request), "GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", MIMICTEST_NAME);
		TransportWrite(s, request, StrLen(request));

		UINT64 end = Tick64() + MIMICTEST_TIMEOUT;
		while (Tick64() < end)
		{
			char buf[4096];
			UINT n = TransportRead(s, buf, sizeof(buf), 1000);

			if (n == 0)
			{
				break;
			}
			if (n != TRANSPORT_LATER)
			{
				WriteBuf(page, buf, n);
			}
		}
		WriteBuf(page, "", 1);
		TransportClose(s);
	}
	MimicTestCheck(ctx, MimicTestHas((char *)page->Buf, "200 OK") && MimicTestHas((char *)page->Buf, MIMICTEST_PAGE), "  the prober is spliced to the decoy and gets its page",
		"the answer has %u bytes", page->Size);
	FreeBuf(page);
	if (tls != NULL)
	{
		TransportTlsFree(tls);
	}

	counted = MimicTestWaitCounters(server, NODE_MIMIC_ROLE_SERVER, accepted, probes + 1, streams, &st);
	MimicTestCheck(ctx, counted, "  the node counts one probe, and no client", "%I64u accepted, %I64u probes, %I64u streams before; %I64u, %I64u, %I64u now",
		accepted, probes, streams, st.Mimic[NODE_MIMIC_ROLE_SERVER].Accepted, st.Mimic[NODE_MIMIC_ROLE_SERVER].Probes, st.Mimic[NODE_MIMIC_ROLE_SERVER].Streams);

	// The node log has no line of its own for the probe: every new line that names a probe is the line of the counters
	SleepThread(MIMICTEST_SETTLE);
	char *after = MimicTestReadNodeLog(dir);
	char *added = after + MIN(StrLen(before), StrLen(after));
	bool quiet = true;
	for (UINT i = SearchStrEx(added, "probe", 0, false);i != INFINITE;i = SearchStrEx(added, "probe", i + 1, false))
	{
		if (added[i + 5] != 's')
		{
			quiet = false;
		}
	}
	MimicTestCheck(ctx, quiet && MimicTestHas(added, "127.0.0.1:") == false, "  the node writes no log line for the probe", "the node log gained:\n%s", added);

	Free(after);
	Free(before);
}

// The sidecar of the client role, killed: the session over it ends, the node starts it again after the delay, and a
// new dial works
static void MimicTestRestart(MIMICTEST_CTX *ctx, NODE *client_node, TRANSPORT *client, TRANSPORT_LISTENER *l, char *address, wchar_t *dir)
{
	NODE_STATUS st;
	UCHAR *buf = ZeroMalloc(NOISE_MAX_PAYLOAD);
	UINT size = 0;

	Print("[the sidecar of the client role, killed]\n");

	NodeGetStatus(client_node, &st);
	UINT pid = st.Mimic[NODE_MIMIC_ROLE_CLIENT].ProcessId;
	UINT restarts = st.Mimic[NODE_MIMIC_ROLE_CLIENT].NumRestarts;

	TRANSPORT_STREAM *s = TransportDial(client, address, NULL);
	if (s != NULL)
	{
		ctx->NumStreams++;
	}
	MIMICTEST_SESSION *t = MimicTestOpenSession(ctx, l, s, true);
	MimicTestCheck(ctx, t->Connected, "  a session over the sidecar", "%s", "TransportNoiseConnect failed");

	// The counters of the sidecar before it dies: the node keeps what the last stats told
	bool counted = MimicTestWaitCounters(client_node, NODE_MIMIC_ROLE_CLIENT, 0, 0, ctx->NumStreams, &st);
	MimicTestCheck(ctx, counted, "  the client node counted every stream that its sidecar carried", "%I64u streams, %I64u dialled", st.Mimic[NODE_MIMIC_ROLE_CLIENT].Streams,
		ctx->NumStreams);

	HANDLE p = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
	bool killed = (p != NULL && TerminateProcess(p, 1));
	if (p != NULL)
	{
		CloseHandle(p);
	}
	UINT64 killed_at = Tick64();
	MimicTestCheck(ctx, killed, "  the sidecar of the client role is killed", "process %u", pid);

	UINT ret = (t->Connected ? TransportNoiseReceive(t->Noise, buf, NOISE_MAX_PAYLOAD, &size, MIMICTEST_TIMEOUT) : NOISE_RECEIVE_ERROR);
	MimicTestCheck(ctx, ret == NOISE_RECEIVE_ERROR, "  the session over it ends at the client", "receive %u", ret);
	TransportNoiseClose(t->Noise);
	WaitThread(t->Thread, INFINITE);
	ReleaseThread(t->Thread);
	MimicTestCheck(ctx, t->Server->LastReceive == NOISE_RECEIVE_ERROR, "  ... and at the server", "the server's last receive %u", t->Server->LastReceive);
	Zero(t->ClientKey, sizeof(t->ClientKey));
	Zero(t->ServerKey, sizeof(t->ServerKey));
	Free(t->Noise);
	Free(t->Server);
	Free(t);

	bool again = MimicTestWaitRunning(client_node, NODE_MIMIC_ROLE_CLIENT, pid, &st);
	UINT64 took = Tick64() - killed_at;
	MimicTestCheck(ctx, again && took >= NODE_MIMIC_RESTART_FIRST && st.Mimic[NODE_MIMIC_ROLE_CLIENT].NumRestarts == restarts + 1,
		"  the node starts the sidecar again after the delay, as another process", "running %u, process %u, %u restarts, after %I64u ms", (UINT)again,
		st.Mimic[NODE_MIMIC_ROLE_CLIENT].ProcessId, st.Mimic[NODE_MIMIC_ROLE_CLIENT].NumRestarts, took);

	char *log = MimicTestReadLog(dir, NULL);
	MimicTestCheck(ctx, MimicTestHas(log, "Mimic client sidecar ended by itself (exit code 1): started again in 1000 ms"),
		"  the node log says that the sidecar ended and when it starts again", "%s", "the line is missing");
	Free(log);

	// A new dial works
	MimicTestConformanceServer(ctx, client, l, address);

	Free(buf);
}

// Without a mimic setting a node has no mimic transport; without ranz.exe next to it it has none and says why, and
// runs on; a setting that the sidecar refuses is logged, and the role stays unavailable
static void MimicTestUnavailable(MIMICTEST_CTX *ctx)
{
	struct
	{
		char *Name;					// What the case is
		char *Client;				// The MimicClient setting, NULL for none
		bool Missing;				// ranz.exe is not next to the node
		char *LogLine;				// What the node log must say, NULL for nothing of the transport
		char *Error;				// What the status of the client role says, NULL for nothing
	} cases[] =
	{
		{"no mimic setting", NULL, false, NULL, NULL},
		{"a node without ranz.exe", "{\"links\":[{\"address\":\"127.0.0.1:1\",\"server_name\":\"" MIMICTEST_NAME "\",\"public_key\":\"" MIMICTEST_PUBLIC "\"}]}", true,
			"Mimic transport unavailable: ranz.exe, which holds the sidecar, is not installed at", "is not installed at"},
		{"a setting with a field the sidecar does not know", "{\"links\":[{\"address\":\"127.0.0.1:1\",\"server_name\":\"" MIMICTEST_NAME "\",\"public_key\":\"" MIMICTEST_PUBLIC "\"}],\"misspelt\":1}", false,
			"Mimic client sidecar refused the MimicClient setting, the role stays unavailable", "refused the settings"},
		{"a setting that is not JSON", "links=127.0.0.1:1", false, "Mimic client sidecar not started, the role stays unavailable: the setting is not a JSON object",
			"is not a JSON object"},
	};
	char what[MAX_SIZE];
	NODE_STATUS st;

	for (UINT i = 0;i < sizeof(cases) / sizeof(cases[0]);i++)
	{
		wchar_t dir[MAX_PATH];

		Print("[%s]\n", cases[i].Name);

		MimicTestNewDir(dir, sizeof(dir), "none");
		MimicTestWriteConfig(dir, NULL, cases[i].Client);

		NODE *n = NewNode(dir);
		if (cases[i].Missing)
		{
			ConbinePathW(n->MimicSidecar, sizeof(n->MimicSidecar), dir, NODE_BGP_EXE_NAME);
		}

		bool started = NodeStart(n);
		TRANSPORT *t = NodeMimicTransport(n);

		// A sidecar that refuses its settings ends, and is not started again
		UINT64 end = Tick64() + MIMICTEST_BOUND;
		NodeGetStatus(n, &st);
		while (cases[i].Error != NULL && IsEmptyStr(st.Mimic[NODE_MIMIC_ROLE_CLIENT].Error) && Tick64() < end)
		{
			SleepThread(100);
			NodeGetStatus(n, &st);
		}
		SleepThread(cases[i].Client != NULL && cases[i].Missing == false ? MIMICTEST_SETTLE : 0);
		NodeGetStatus(n, &st);

		TRANSPORT_STREAM *s = (t != NULL ? TransportDial(t, "127.0.0.1:1", NULL) : NULL);
		NODE_MIMIC_STATUS *m = &st.Mimic[NODE_MIMIC_ROLE_CLIENT];

		Format(what, sizeof(what), "  the node runs, and its mimic transport is unavailable: %s", cases[i].Error != NULL ? cases[i].Error : "no transport");
		MimicTestCheck(ctx, started && st.Running && s == NULL && m->Running == false && m->ProcessId == 0 && m->NumRestarts == 0 &&
			(cases[i].Error != NULL ? MimicTestHas(m->Error, cases[i].Error) : t == NULL), what,
			"started %u, running %u, transport %u, stream %u, sidecar running %u, process %u, %u restarts, error \"%s\"", (UINT)started, (UINT)st.Running,
			(UINT)(t != NULL), (UINT)(s != NULL), (UINT)m->Running, m->ProcessId, m->NumRestarts, m->Error);
		TransportClose(s);

		NodeStop(n);
		FreeNode(n);

		char *log = MimicTestReadLog(dir, NULL);
		bool ok = (cases[i].LogLine != NULL ? MimicTestHas(log, cases[i].LogLine) : MimicTestHas(log, "Mimic") == false);
		MimicTestCheck(ctx, ok, "  the node log says why, or nothing of the transport without a setting", "the node log %s \"%s\"",
			cases[i].LogLine != NULL ? "lacks" : "has", cases[i].LogLine != NULL ? cases[i].LogLine : "Mimic");
		Free(log);

		MimicTestDeleteTree(dir);
	}
}

// The hook of the server node: before the first start of its sidecar, another client connects to the control pipe
static void MimicTestImpostor(void *param, const wchar_t *pipe)
{
	MIMICTEST_IMPOSTOR *i = (MIMICTEST_IMPOSTOR *)param;

	if (i->NumCalls++ != 0)
	{
		return;
	}

	i->Pipe = CreateFileW(pipe, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
}

// Whether the key is in none of the files of the diagnostics bundle of the node's data directory: ranz doctor -bundle
// writes it, and the tar of Windows unpacks it
static bool MimicTestBundleClean(MIMICTEST_CTX *ctx, wchar_t *ranz, wchar_t *dir)
{
	wchar_t work[MAX_PATH];
	wchar_t zip[MAX_PATH];
	wchar_t out[MAX_PATH];
	wchar_t empty[MAX_PATH];
	wchar_t tar[MAX_PATH];
	wchar_t cmd[MAX_PATH * 4];

	MimicTestNewDir(work, sizeof(work), "bundle");
	ConbinePathW(zip, sizeof(zip), work, L"bundle.zip");
	ConbinePathW(out, sizeof(out), work, L"out");
	ConbinePathW(empty, sizeof(empty), work, L"controller");
	MakeDirExW(out);
	MakeDirExW(empty);

	UniFormat(cmd, sizeof(cmd), L"\"%s\" doctor -bundle -o \"%s\" -node-dir \"%s\" -controller-dir \"%s\"", ranz, zip, dir, empty);
	UINT code = MimicTestRun(cmd);

	GetSystemDirectoryW(tar, MAX_PATH);
	ConbinePathW(tar, sizeof(tar), tar, L"tar.exe");
	UniFormat(cmd, sizeof(cmd), L"\"%s\" -xf \"%s\" -C \"%s\"", tar, zip, out);
	UINT unpacked = (IsFileExistsW(zip) ? MimicTestRun(cmd) : INFINITE);

	BUF *b = NewBuf();
	MimicTestReadTree(b, out);
	WriteBuf(b, "", 1);

	bool clean = (MimicTestHas(b->Buf, MIMICTEST_PRIVATE) == false);
	MimicTestCheck(ctx, (code == 0 || code == 1) && unpacked == 0 && MimicTestHas(b->Buf, "MimicServer") && MimicTestHas(b->Buf, "Mimic server sidecar ready") && clean,
		"  the diagnostics bundle carries the settings and the logs of the node, and not the key", "ranz doctor exit code %u, tar exit code %u, %u bytes unpacked, key %s",
		code, unpacked, b->Size, clean ? "absent" : "PRESENT");

	FreeBuf(b);
	MimicTestDeleteTree(work);

	return clean;
}

// The server node and the client node over the mimic transport
static void MimicTestNodes(MIMICTEST_CTX *ctx)
{
	wchar_t server_dir[MAX_PATH];
	wchar_t client_dir[MAX_PATH];
	char client_settings[MAX_SIZE * 2];
	char address[MAX_SIZE];
	char cmdline[MAX_SIZE * 4];
	MIMICTEST_IMPOSTOR impostor;
	NODE_STATUS st;

	Print("[the server node]\n");

	MimicTestNewDir(server_dir, sizeof(server_dir), "server");
	MimicTestWriteConfig(server_dir, MIMICTEST_SERVER_SETTINGS, NULL);

	NODE *server = NewNode(server_dir);
	wchar_t ranz[MAX_PATH];
	UniStrCpy(ranz, sizeof(ranz), server->MimicSidecar);
	bool installed = IsFileExistsW(ranz);
	MimicTestCheck(ctx, installed, "ranz.exe is next to vpntest.exe", "%S is missing", ranz);
	if (installed == false)
	{
		FreeNode(server);
		MimicTestDeleteTree(server_dir);
		return;
	}

	Zero(&impostor, sizeof(impostor));
	impostor.Pipe = INVALID_HANDLE_VALUE;
	server->MimicTest.BeforeLaunch = MimicTestImpostor;
	server->MimicTest.Param = &impostor;

	NodeStart(server);
	TRANSPORT *ts = NodeMimicTransport(server);
	NodeGetStatus(server, &st);
	MimicTestCheck(ctx, ts != NULL && StrCmp(ts->Name, NODE_MIMIC_TRANSPORT) == 0 && st.Mimic[NODE_MIMIC_ROLE_SERVER].Configured && st.Mimic[NODE_MIMIC_ROLE_SERVER].ProcessId == 0,
		"  the node has the mimic transport, and its server role starts no sidecar before it listens", "transport %u, configured %u, process %u", (UINT)(ts != NULL),
		(UINT)st.Mimic[NODE_MIMIC_ROLE_SERVER].Configured, st.Mimic[NODE_MIMIC_ROLE_SERVER].ProcessId);

	TRANSPORT_LISTENER *l = (ts != NULL ? TransportListen(ts, "") : NULL);
	NodeGetStatus(server, &st);
	NODE_MIMIC_STATUS *ms = &st.Mimic[NODE_MIMIC_ROLE_SERVER];
	MimicTestCheck(ctx, l != NULL && ms->Running && StartWith(ms->Listen, "127.0.0.1:") && MimicTestHas(ms->Version, "ranz mimic"),
		"  Listen starts the sidecar as a server: it reports ready with its REALITY listener", "listener %u, running %u, listen \"%s\", version \"%s\", error \"%s\"",
		(UINT)(l != NULL), (UINT)ms->Running, ms->Listen, ms->Version, ms->Error);
	MimicTestCheck(ctx, StrCmp(ms->PipeAcl, "D:P(A;;FA;;;OW)") == 0 || StrCmp(ms->PipeAcl, "D:P(A;;GA;;;OW)") == 0,
		"  the control pipe has the strict DACL: protected, full access for the account of the node (OWNER RIGHTS) alone", "DACL \"%s\"", ms->PipeAcl);

	// The client that came first on the control pipe was refused, and the node started the sidecar again
	char *log = MimicTestReadLog(server_dir, NULL);
	MimicTestCheck(ctx, impostor.Pipe != INVALID_HANDLE_VALUE && MimicTestHas(log, "connected to the pipe, not the sidecar") && ms->NumStarts == 1 && ms->NumRestarts == 1,
		"  the control pipe refuses a client that is not the sidecar the node started, and the node starts the sidecar again",
		"the other client connected %u, %u starts, %u restarts", (UINT)(impostor.Pipe != INVALID_HANDLE_VALUE), ms->NumStarts, ms->NumRestarts);
	Free(log);
	if (impostor.Pipe != INVALID_HANDLE_VALUE)
	{
		CloseHandle(impostor.Pipe);
	}

	// The command line of the sidecar names its pipe and its log, and never the key
	UINT server_pid = ms->ProcessId;
	MimicTestCommandLine(server_pid, cmdline, sizeof(cmdline));
	MimicTestCheck(ctx, MimicTestHas(cmdline, "ranz.exe\" mimic -pipe \\\\.\\pipe\\ranz-mimic-control-") && MimicTestHas(cmdline, MIMICTEST_PRIVATE) == false,
		"  the command line of the server's sidecar is ranz.exe mimic with its pipe, and holds no key", "command line \"%s\"", cmdline);

	StrCpy(address, sizeof(address), ms->Listen);

	Print("[the client node]\n");

	MimicTestNewDir(client_dir, sizeof(client_dir), "client");
	Format(client_settings, sizeof(client_settings), "{\"links\":[{\"address\":\"%s\",\"server_name\":\"%s\",\"public_key\":\"%s\",\"short_id\":\"a1b2\"},"
		"{\"address\":\"%s\",\"server_name\":\"%s\",\"public_key\":\"%s\",\"short_id\":\"a1b2\"}]}",
		address, MIMICTEST_NAME, MIMICTEST_PUBLIC, MIMICTEST_HANG, MIMICTEST_NAME, MIMICTEST_PUBLIC);
	MimicTestWriteConfig(client_dir, NULL, client_settings);

	NODE *client_node = NewNode(client_dir);
	NodeStart(client_node);
	TRANSPORT *tc = NodeMimicTransport(client_node);
	bool running = MimicTestWaitRunning(client_node, NODE_MIMIC_ROLE_CLIENT, 0, &st);
	MimicTestCheck(ctx, tc != NULL && running && st.Mimic[NODE_MIMIC_ROLE_CLIENT].NumStarts == 1,
		"  the client role starts its sidecar with the node", "transport %u, running %u, error \"%s\"", (UINT)(tc != NULL), (UINT)running, st.Mimic[NODE_MIMIC_ROLE_CLIENT].Error);
	UINT client_pid = st.Mimic[NODE_MIMIC_ROLE_CLIENT].ProcessId;
	MimicTestCommandLine(client_pid, cmdline, sizeof(cmdline));
	MimicTestCheck(ctx, MimicTestHas(cmdline, "ranz.exe\" mimic -pipe ") && MimicTestHas(cmdline, MIMICTEST_PUBLIC) == false,
		"  the command line of the client's sidecar is ranz.exe mimic with its pipe, and holds none of the settings", "command line \"%s\"", cmdline);

	if (l != NULL && tc != NULL && running)
	{
		MimicTestConformance(ctx, tc, l, address);
		MimicTestConformanceServer(ctx, tc, l, address);
		MimicTestBrokenSession(ctx, tc, l, address);
		MimicTestCancelAndRace(ctx, tc, l, address);
		MimicTestProber(ctx, server, server_dir, address);
		MimicTestRestart(ctx, client_node, tc, l, address, client_dir);

		// The counters of both nodes match what the test did: every stream that the client dialled reached the server's
		// sidecar as a client that proved the key, and one prober came
		Print("[the counters]\n");
		bool server_ok = MimicTestWaitCounters(server, NODE_MIMIC_ROLE_SERVER, ctx->NumStreams, 1, ctx->NumStreams, &st);
		ms = &st.Mimic[NODE_MIMIC_ROLE_SERVER];
		MimicTestCheck(ctx, server_ok && ms->Dropped == 0, "  the status of the server node: one accepted client and one stream for each dial, one probe",
			"%I64u accepted, %I64u probes, %I64u streams, %I64u dropped; %I64u dialled", ms->Accepted, ms->Probes, ms->Streams, ms->Dropped, ctx->NumStreams);
		bool client_ok = MimicTestWaitCounters(client_node, NODE_MIMIC_ROLE_CLIENT, 0, 0, ctx->NumStreams, &st);
		NODE_MIMIC_STATUS *mc = &st.Mimic[NODE_MIMIC_ROLE_CLIENT];
		MimicTestCheck(ctx, client_ok, "  the status of the client node: one stream for each dial, over both of its sidecars", "%I64u streams; %I64u dialled", mc->Streams,
			ctx->NumStreams);
	}

	// The listener closes: the sidecar of the server role exits. The node stops: the sidecar of the client role exits.
	Print("[the end]\n");
	TransportCloseListener(l);
	NodeGetStatus(server, &st);
	MimicTestCheck(ctx, MimicTestExited(server_pid) && st.Mimic[NODE_MIMIC_ROLE_SERVER].ProcessId == 0, "  closing the listener ends the sidecar of the server role",
		"process %u, status process %u", server_pid, st.Mimic[NODE_MIMIC_ROLE_SERVER].ProcessId);

	NodeGetStatus(client_node, &st);
	client_pid = st.Mimic[NODE_MIMIC_ROLE_CLIENT].ProcessId;
	NodeStop(client_node);
	MimicTestCheck(ctx, client_pid != 0 && MimicTestExited(client_pid), "  when the node stops, its sidecar exits with it", "process %u", client_pid);
	NodeStop(server);
	FreeNode(client_node);
	FreeNode(server);

	// The logs tell the story, with the counters and without the key
	Print("[the logs and the key]\n");
	char *server_log = MimicTestReadLog(server_dir, NULL);
	char *client_log = MimicTestReadLog(client_dir, NULL);
	Format(cmdline, sizeof(cmdline), "Mimic server sidecar counters: %I64u accepted, 1 probes, %I64u streams, 0 dropped", ctx->NumStreams, ctx->NumStreams);
	MimicTestCheck(ctx, MimicTestHas(server_log, cmdline) && MimicTestHas(server_log, "Mimic server sidecar stopped") && MimicTestHas(client_log, "Mimic client sidecar stopped"),
		"  the node logs have the counters of the sidecar and its stop", "missing \"%s\" or a stop", cmdline);
	char *sidecar_log = MimicTestReadLog(server_dir, L"ranz-mimic-server.log");
	MimicTestCheck(ctx, MimicTestHas(sidecar_log, "mimic -pipe") && MimicTestHas(sidecar_log, "a connection that is no client") == false,
		"  the log of the sidecar shows its command line, ranz.exe mimic -pipe, and no line for the probe", "%s", sidecar_log);
	MimicTestCheck(ctx, MimicTestHas(server_log, MIMICTEST_PRIVATE) == false && MimicTestHas(client_log, MIMICTEST_PRIVATE) == false,
		"  the REALITY private key is in no log line of either node or of their sidecars", "%s", "the key is in a log");
	Free(sidecar_log);
	Free(client_log);
	Free(server_log);

	MimicTestBundleClean(ctx, ranz, server_dir);

	MimicTestDeleteTree(client_dir);
	MimicTestDeleteTree(server_dir);
}

// mimic: the mimic transport of a node over its mimicry sidecar
RANZ_TEST("mimic", mimic_test, "Mimic transport: the mimicry sidecar ranz mimic (next to vpntest) started by a node, a Noise session over REALITY between a server node and a client node, the binding, a prober spliced to the decoy, the restart, the counters and the key that stays out of logs, command lines and the bundle.");
void mimic_test(UINT num, char **arg)
{
	MIMICTEST_CTX *ctx = ZeroMalloc(sizeof(MIMICTEST_CTX));
	HANDLE done = CreateEventW(NULL, TRUE, FALSE, NULL);
	HANDLE watchdog = (done != NULL ? CreateThread(NULL, 0, MimicTestWatchdog, done, 0, NULL) : NULL);

	Print("Mimic test: the mimic transport of a node over its sidecar ranz mimic (REALITY)\n");

	MimicTestUnavailable(ctx);
	MimicTestNodes(ctx);

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
		Print("MIMIC TEST OK\n");
	}
	else
	{
		Print("MIMIC TEST FAILED (%u of %u checks failed)\n", ctx->NumFailed, ctx->NumChecks);
	}

	Free(ctx);
}
