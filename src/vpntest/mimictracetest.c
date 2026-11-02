// mimictracetest.c
// Named mimic tracer of vpntest ("mimictrace" command, CORE-P2-7 #424)
//
// The mimic servers and their clients end to end, with a real ranz controller (SDN-94, #423) and the real ranz.exe next to
// vpntest.exe, which each node starts as its mimicry sidecar (Cedar/NodeMimicState.c, Core/ControlMimic.c, Cedar/NodeMimic.c).
// The operator declares the mimic server in the Intent and types nothing on a node: .github/scripts/mimic-tracer.ps1 runs
// the controller with its rqlited, applies the Node resources mimic-server, with a mimic endpoint, and mimic-client, with the
// static keys of this test, and the Listener of mimic-server with a mimic section, and runs "vpntest mimictrace <address>
// <key> <folder>": the address of the controller's TLS port, its static key in base64, and the folder of the script, in which
// the test and the script take turns by files.
// - mimic-server and mimic-client open their control streams to the controller and apply their states. The server makes the
//   key of its mimic server, writes its MimicServer setting, reports the public key and listens with the server role of its
//   sidecar; once the controller has the key, the client gets a link and writes its MimicClient setting, which starts the
//   client role of its sidecar. The data transport of the overlay of each node is the dialler of this test: it dials a peer at
//   the mimic endpoints of its Peer object through the mimic transport of the node, which dials the link of that address (the
//   data transport of the Node service dials nowhere: Gap 3 of docs/first-test.md). The Noise session of the client comes up
//   over the mimic transport, and both ends have the same channel binding. The command lines of the sidecars hold no key. The
//   test writes the file "up", which holds the public key of the server.
// - mimic-prober, a node without a control stream, applies a link to the mimic server whose short id the test changed: its
//   dial is spliced to the decoy and fails, and the server counts one probe.
// - The script applies the Intent with another address of the mimic server and writes "changed": the sidecar of each role
//   restarts with its new setting, the key stays, and the session comes up again at the new address.
// - mimic-server restarts: it reports the same key, which its store holds, before it applies a state, and the session comes up
//   again. The text dump of the store that it wrote at its start (node_config.txt) and its diagnostics bundle hold its
//   MimicServer setting without the private key. The test writes "restarted".
// - The script applies the Intent without the mimic section and writes "removed": the sidecars stop, and the settings and the
//   key are gone. The test writes "gone".
// - The script stops the controller and writes "stopped": the private key of the mimic server is in no file of the folder of
//   the script, which holds the store and the log of the controller, and in no line of the logs of the nodes and their
//   sidecars.
// Print "MIMICTRACE TEST OK" only when every check passes.

#include "controltls.h"
#include "testlist.h"

#include "Cedar/ConfigStore.h"
#include "Cedar/Node.h"

#include "Mayaqua/FileIO.h"
#include "Mayaqua/Internat.h"
#include "Mayaqua/Kernel.h"
#include "Mayaqua/Memory.h"
#include "Mayaqua/Microsoft.h"
#include "Mayaqua/Str.h"
#include "Mayaqua/Tick64.h"

#include "Core/Control.h"
#include "Core/Crypto.h"
#include "Core/Transport.h"

#include <stdio.h>
#include <string.h>

#define	MIMICTRACE_BUDGET		600000				// The whole test ends within this time, or the watchdog ends the process (ms)
#define	MIMICTRACE_BOUND		120000				// A bounded wait on observable state: a state, a sidecar, a session (ms)
#define	MIMICTRACE_SCRIPT		180000				// The script writes its next file within this time (ms)
#define	MIMICTRACE_POLL			100					// Poll interval of observable state (ms)
#define	MIMICTRACE_DIAL			15000				// A dial of the dialler connects within this time (ms)
#define	MIMICTRACE_RUN_WAIT		120000				// A command that the test runs ends within this time (ms)
#define	MIMICTRACE_SETTLE		3000				// How long a process that should be gone may take to exit (ms)
#define	MIMICTRACE_SERVER		"mimic-server"		// The Node of the mimic server ...
#define	MIMICTRACE_CLIENT		"mimic-client"		// ... and the Node of its client, in the Intent of the script
#define	MIMICTRACE_PROBER		"mimic-prober"		// The node of the prober, in no Intent
#define	MIMICTRACE_NAME			"decoy.test"		// The server name of the mimic section
#define	MIMICTRACE_FIRST		"127.0.0.1:39845"	// The address of the mimic server in the first Intent ...
#define	MIMICTRACE_SECOND		"127.0.0.1:39846"	// ... and in the second (mimic-tracer.ps1)
#define	MIMICTRACE_VRF			1					// The VRF of the state of the prober
#define	MIMICTRACE_TEXT			65536				// Bytes of a setting that the test reads at most
#define	MIMICTRACE_HEX			(CRYPTO_X25519_SIZE * 2 + 1)	// A key as hexadecimal digits, with the NUL
#define	MIMICTRACE_SESSIONS		4					// The sessions of a node that the test reads at most

// The static keys of mimic-server and mimic-client: the X25519 public keys of the scalars 1 to 32 and 33 to 64, which the
// script puts into their Node resources
static char *mimictrace_keys[2] = {"B6N8vBQgk8i3VdwbEOhstCY3StFqqFPtC9/AsrhtHHw=", "WGmv9FBUlzLLqu1eXfmzCm2jHLDldCutWtShp2jxpns="};

// One node of the test
typedef struct MIMICTRACE_NODE
{
	char *Name;
	wchar_t Dir[MAX_PATH];				// Its data directory
	PEER_KEY Key;						// Its static key
	NODE *Node;
	TRANSPORT Dialler;					// The data transport of its overlay
	SRWLOCK Lock;						// Winner
	char Winner[TRANSPORT_NAME_SIZE];	// The transport of the stream that the dialler connected last, "" before the first
	volatile LONG64 NumDials;			// The streams that the dialler connected
} MIMICTRACE_NODE;

// The state of the test
typedef struct MIMICTRACE_CTX
{
	UINT NumChecks;
	UINT NumFailed;
	char Controller[MAX_SIZE];			// The address of the controller's TLS port ...
	UCHAR ControllerKey[PEER_KEY_SIZE];	// ... and its static key
	wchar_t Folder[MAX_PATH];			// The folder of the script
	TRANSPORT *Tls;						// The transport of the control streams
	MIMICTRACE_NODE Server;				// mimic-server, the mimic server
	MIMICTRACE_NODE Client;				// mimic-client, its client
	MIMICTRACE_NODE Prober;				// mimic-prober, a client with a wrong short id
	char Private[MIMICTRACE_HEX];		// The private key of the mimic server as its setting holds it, "" before the test read it
	char Public[MIMICTRACE_HEX];		// ... its public key
	char ShortId[CONTROL_MIMIC_SHORT_ID * 2 + 1];	// The short id of the server, as the link of the client holds it
} MIMICTRACE_CTX;

// A UNICODE_STRING of ntdll, as NtQueryInformationProcess gives the command line of a process
typedef struct MIMICTRACE_UNICODE
{
	USHORT Length;						// Bytes of the string, without a NUL
	USHORT MaximumLength;
	wchar_t *Buffer;
} MIMICTRACE_UNICODE;

static bool MimicTraceCheck(MIMICTRACE_CTX *ctx, bool ok, char *what, char *fmt, ...) RANZ_PRINTF_FORMAT(4, 5);
static bool MimicTraceCheck(MIMICTRACE_CTX *ctx, bool ok, char *what, char *fmt, ...)
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

// The watchdog: a native thread that ends a run that hangs, so that a sidecar or a session that never comes is a failed test
// instead of a hung CI step
static DWORD WINAPI MimicTraceWatchdog(LPVOID param)
{
	char msg[MAX_SIZE];
	DWORD written = 0;

	if (WaitForSingleObject((HANDLE)param, MIMICTRACE_BUDGET) != WAIT_TIMEOUT)
	{
		return 0;
	}

	int len = snprintf(msg, sizeof(msg), "MIMICTRACE TEST FAILED (did not finish within %u ms)\n", MIMICTRACE_BUDGET);
	if (len > 0)
	{
		WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), msg, (DWORD)MIN((UINT)len, (UINT)sizeof(msg) - 1), &written, NULL);
	}

	TerminateProcess(GetCurrentProcess(), 1);

	return 0;
}

//
// Keys, texts and files
//

// size bytes as lower-case hexadecimal digits into str, which holds size * 2 + 1 bytes
static void MimicTraceHex(char *str, const UCHAR *data, UINT size)
{
	static const char digits[] = "0123456789abcdef";

	for (UINT i = 0;i < size;i++)
	{
		str[i * 2] = digits[data[i] >> 4];
		str[i * 2 + 1] = digits[data[i] & 0x0F];
	}
	str[size * 2] = 0;
}

// The value of the lower-case hexadecimal digit c, or -1
static int MimicTraceDigit(char c)
{
	if (c >= '0' && c <= '9')
	{
		return c - '0';
	}
	if (c >= 'a' && c <= 'f')
	{
		return c - 'a' + 10;
	}

	return -1;
}

// The size bytes that the hexadecimal digits of hex give into data: false when hex is not 2 * size such digits
static bool MimicTraceUnhex(char *hex, UCHAR *data, UINT size)
{
	if (hex == NULL || StrLen(hex) != size * 2)
	{
		return false;
	}

	for (UINT i = 0;i < size;i++)
	{
		int hi = MimicTraceDigit(hex[i * 2]);
		int lo = MimicTraceDigit(hex[i * 2 + 1]);

		if (hi < 0 || lo < 0)
		{
			return false;
		}
		data[i] = (UCHAR)(hi * 16 + lo);
	}

	return true;
}

// The string value of the field name of a JSON text as the node writes it ("name":"value"), at most size - 1 bytes, into
// value; false when the text has no such field
static bool MimicTraceField(char *text, char *name, char *value, UINT size)
{
	char field[MAX_SIZE];

	StrCpy(value, size, "");
	Format(field, sizeof(field), "\"%s\":\"", name);

	UINT i = SearchStrEx(text, field, 0, true);
	if (i == INFINITE)
	{
		return false;
	}

	char *start = text + i + StrLen(field);
	char *quote = strchr(start, '"');
	if (quote == NULL || (UINT)(quote - start) >= size)
	{
		return false;
	}

	Copy(value, start, (UINT)(quote - start));
	value[quote - start] = 0;

	return true;
}

// The text of the setting name of the Configuration store of a node, "" when it has none; the caller wipes and frees it
static char *MimicTraceSetting(NODE *n, char *name)
{
	char *text = ZeroMalloc(MIMICTRACE_TEXT);

	if (n == NULL || n->Store == NULL || CsGetSetting(n->Store, name, text, MIMICTRACE_TEXT) == false)
	{
		StrCpy(text, MIMICTRACE_TEXT, "");
	}

	return text;
}

// Wipe and free a text that may hold the private key
static void MimicTraceDrop(char *text)
{
	if (text != NULL)
	{
		Zero(text, StrLen(text));
		Free(text);
	}
}

// The ASCII letter c in lower case, any other byte as it is
static UCHAR MimicTraceLower(UCHAR c)
{
	return (UCHAR)(c >= 'A' && c <= 'Z' ? c + ('a' - 'A') : c);
}

// Whether the size bytes of data hold the what_size bytes of what, an ASCII letter in either case when nocase. The bytes
// are any bytes: a file of the store of the controller holds zeros.
static bool MimicTraceFind(const UCHAR *data, UINT size, const UCHAR *what, UINT what_size, bool nocase)
{
	if (data == NULL || what == NULL || what_size == 0 || size < what_size)
	{
		return false;
	}

	for (UINT i = 0;i + what_size <= size;i++)
	{
		UINT j = 0;

		while (j < what_size && (data[i + j] == what[j] || (nocase && MimicTraceLower(data[i + j]) == MimicTraceLower(what[j]))))
		{
			j++;
		}
		if (j == what_size)
		{
			return true;
		}
	}

	return false;
}

// Whether the bytes of b hold the text, case ignored
static bool MimicTraceHas(BUF *b, char *text)
{
	return (b != NULL && MimicTraceFind(b->Buf, b->Size, (UCHAR *)text, StrLen(text), true));
}

// Whether the bytes of b hold the private key of the mimic server: as the hexadecimal digits of its setting, in either case,
// in base64, or as its bytes
static bool MimicTraceHasKey(MIMICTRACE_CTX *ctx, BUF *b)
{
	UCHAR priv[CRYPTO_X25519_SIZE];
	UINT size = 0;

	if (b == NULL || MimicTraceUnhex(ctx->Private, priv, CRYPTO_X25519_SIZE) == false)
	{
		return false;
	}

	char *base64 = Base64FromBin(&size, priv, CRYPTO_X25519_SIZE);
	bool found = MimicTraceHas(b, ctx->Private) || (base64 != NULL && MimicTraceFind(b->Buf, b->Size, (UCHAR *)base64, StrLen(base64), false)) ||
		MimicTraceFind(b->Buf, b->Size, priv, CRYPTO_X25519_SIZE, false);

	if (base64 != NULL)
	{
		Zero(base64, StrLen(base64));
		Free(base64);
	}
	Zero(priv, sizeof(priv));

	return found;
}

// Append the bytes of every file under dir, and of its directories, to b. A node that runs, its sidecars and the processes of
// the script hold their files open for writing, so the files are read without the read lock.
static void MimicTraceReadTree(BUF *b, wchar_t *dir)
{
	DIRLIST *d = EnumDirW(dir);

	for (UINT i = 0;d != NULL && i < d->NumFiles;i++)
	{
		DIRENT *e = d->File[i];
		wchar_t path[MAX_PATH];

		ConbinePathW(path, sizeof(path), dir, e->FileNameW);
		if (e->Folder)
		{
			MimicTraceReadTree(b, path);
			continue;
		}

		BUF *f = ReadDumpExW(path, false, 0);
		if (f != NULL)
		{
			WriteBuf(b, f->Buf, f->Size);
			WriteBuf(b, "\n", 1);
			FreeBuf(f);
		}
	}

	FreeDir(d);
}

// The bytes of the node log directory of dir, the logs of the node and of its sidecars; the caller frees them
static BUF *MimicTraceReadLogs(wchar_t *dir)
{
	wchar_t log_dir[MAX_PATH];
	BUF *b = NewBuf();

	ConbinePathW(log_dir, sizeof(log_dir), dir, NODE_LOG_DIR_NAME);
	MimicTraceReadTree(b, log_dir);

	return b;
}

// A new empty data directory under the temp directory of the process, with a configuration store that runs no role on one
// worker
static void MimicTraceNewDir(wchar_t *dir, UINT size, char *name)
{
	wchar_t tmp[MAX_PATH];
	wchar_t path[MAX_PATH];

	UniFormat(tmp, sizeof(tmp), L"mimictrace_%S_%u", name, (UINT)Tick64());
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

// Delete a directory with everything in it
static void MimicTraceDeleteTree(wchar_t *dir)
{
	DIRLIST *d = EnumDirW(dir);

	for (UINT i = 0;d != NULL && i < d->NumFiles;i++)
	{
		DIRENT *e = d->File[i];
		wchar_t path[MAX_PATH];

		ConbinePathW(path, sizeof(path), dir, e->FileNameW);
		if (e->Folder)
		{
			MimicTraceDeleteTree(path);
		}
		else
		{
			FileDeleteW(path);
		}
	}

	FreeDir(d);
	DeleteDirW(dir);
}

// Write the file name into the folder of the script, which holds text: under another name first, so that the script never
// reads it half written
static bool MimicTraceWriteFile(MIMICTRACE_CTX *ctx, char *name, char *text)
{
	wchar_t wname[MAX_PATH];
	wchar_t tmp[MAX_PATH];
	wchar_t path[MAX_PATH];

	StrToUni(wname, sizeof(wname), name);
	ConbinePathW(path, sizeof(path), ctx->Folder, wname);
	UniFormat(tmp, sizeof(tmp), L"%s.tmp", path);

	return DumpDataW(text, StrLen(text), tmp) && FileRenameW(tmp, path);
}

// Whether the script wrote the file name into its folder within MIMICTRACE_SCRIPT
static bool MimicTraceWaitFile(MIMICTRACE_CTX *ctx, char *name)
{
	wchar_t wname[MAX_PATH];
	wchar_t path[MAX_PATH];

	StrToUni(wname, sizeof(wname), name);
	ConbinePathW(path, sizeof(path), ctx->Folder, wname);

	for (UINT64 end = Tick64() + MIMICTRACE_SCRIPT;;SleepThread(MIMICTRACE_POLL))
	{
		bool there = IsFileExistsW(path);

		if (there || Tick64() >= end)
		{
			return there;
		}
	}
}

//
// The processes
//

// The command line of the process pid, as Windows keeps it; "" when it cannot be read
static void MimicTraceCommandLine(UINT pid, char *out, UINT size)
{
	typedef LONG (NTAPI MIMICTRACE_QUERY)(HANDLE, UINT, PVOID, ULONG, PULONG);
	MIMICTRACE_QUERY *query = (MIMICTRACE_QUERY *)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQueryInformationProcess");
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
		MIMICTRACE_UNICODE *s = (MIMICTRACE_UNICODE *)buf;
		wchar_t *tmp = ZeroMalloc(s->Length + sizeof(wchar_t));

		Copy(tmp, s->Buffer, s->Length);
		UniToStr(out, size, tmp);
		Free(tmp);
	}
	Free(buf);
	CloseHandle(p);
}

// Whether the process pid has exited, or never was
static bool MimicTraceExited(UINT pid)
{
	HANDLE p = (pid != 0 ? OpenProcess(SYNCHRONIZE, FALSE, pid) : NULL);
	bool exited = (p == NULL || WaitForSingleObject(p, MIMICTRACE_SETTLE) == WAIT_OBJECT_0);

	if (p != NULL)
	{
		CloseHandle(p);
	}

	return exited;
}

// Run a command line and wait for it; its exit code, or INFINITE when it could not start or did not end in time
static UINT MimicTraceRun(wchar_t *cmd)
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

	if (WaitForSingleObject(pi.hProcess, MIMICTRACE_RUN_WAIT) == WAIT_OBJECT_0)
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

//
// The dialler: the data transport of the overlay of a node of the test. It dials a peer at the mimic endpoints of its Peer
// object, as the race of the fallback list of the client role does at the endpoints of QUIC and TLS (NodeEndpoints.c), with
// the mimic transport of the node, whose client role dials the link of that address; it listens nowhere. Its stream is the
// stream of the mimic transport, whose binding the Noise session takes.
//

static bool MimicTraceDial(void *param, const char *address, HANDLE cancel, void **stream)
{
	MIMICTRACE_NODE *t = (MIMICTRACE_NODE *)param;
	CONTROL_ENDPOINT endpoints[CONTROL_MAX_ENDPOINTS];
	TRANSPORT_TARGET targets[TRANSPORT_MAX_TARGETS];
	TRANSPORT_RACE race;
	TRANSPORT *known[1];

	*stream = NULL;

	// The mimic transport while the node has the settings of a role, NULL before
	known[0] = NodeMimicTransport(t->Node);
	UINT num = NodeOverlayEndpoints(t->Node, address, endpoints, CONTROL_MAX_ENDPOINTS);
	num = NodeEndpointsTargets(endpoints, num, known, 1, targets, TRANSPORT_MAX_TARGETS);
	if (num == 0)
	{
		return false;
	}

	TRANSPORT_STREAM *s = TransportRace(targets, num, TRANSPORT_RACE_DELAY, MIMICTRACE_DIAL, &race);
	if (s == NULL)
	{
		return false;
	}

	AcquireSRWLockExclusive(&t->Lock);
	StrCpy(t->Winner, sizeof(t->Winner), targets[race.Winner].Transport->Name);
	ReleaseSRWLockExclusive(&t->Lock);
	InterlockedIncrement64(&t->NumDials);

	*stream = s;
	return true;
}

// The dialler listens nowhere: a stream of a client reaches the mimic server through its sidecar (NodeMimicAcceptServed)
static bool MimicTraceListen(void *param, const char *address, void **listener)
{
	*listener = NULL;
	return false;
}

static bool MimicTraceAccept(void *listener, UINT timeout, void **stream)
{
	*stream = NULL;
	return false;
}

static void MimicTraceCloseListener(void *listener)
{
	// No listener
	return;
}

static UINT MimicTraceRead(void *stream, void *buf, UINT size, UINT timeout)
{
	return TransportRead((TRANSPORT_STREAM *)stream, buf, size, timeout);
}

static bool MimicTraceWrite(void *stream, const void *buf, UINT size)
{
	return TransportWrite((TRANSPORT_STREAM *)stream, buf, size);
}

static void MimicTraceClose(void *stream)
{
	TransportClose((TRANSPORT_STREAM *)stream);
}

// The binding of the outer TLS session of the sidecar, which the Noise session takes
static UINT MimicTraceBinding(void *stream, UCHAR *binding, UINT max, UINT *size)
{
	return TransportBinding((TRANSPORT_STREAM *)stream, binding, max, size);
}

static bool MimicTraceRemote(void *stream, char *address, UINT size)
{
	return TransportRemote((TRANSPORT_STREAM *)stream, address, size);
}

// Whether the dialler dials the peer: its Peer object has a mimic endpoint. The overlay asks under its own lock, so this takes no
// lock of the node.
static bool MimicTraceDialable(NODE *n, void *param, const char *name, const CONTROL_ENDPOINT *endpoints, UINT num)
{
	for (UINT i = 0;endpoints != NULL && i < num;i++)
	{
		if (StrCmp(endpoints[i].Transport, NODE_MIMIC_TRANSPORT) == 0)
		{
			return true;
		}
	}

	return false;
}

static void MimicTraceDiallerInit(MIMICTRACE_NODE *t)
{
	TRANSPORT *d = &t->Dialler;

	Zero(d, sizeof(TRANSPORT));
	StrCpy(d->Name, sizeof(d->Name), "endpoints");
	d->Param = t;
	d->Dial = MimicTraceDial;
	d->Listen = MimicTraceListen;
	d->Accept = MimicTraceAccept;
	d->CloseListener = MimicTraceCloseListener;
	d->Read = MimicTraceRead;
	d->Write = MimicTraceWrite;
	d->Close = MimicTraceClose;
	d->Binding = MimicTraceBinding;
	// The outer connection of the sidecar is TCP, as the mimic transport says
	d->Queue = TRANSPORT_QUEUE_CODEL;
	d->Remote = MimicTraceRemote;

	InitializeSRWLock(&t->Lock);
}

//
// The nodes
//

// Make the node of t in its data directory and start it: at its start a node reads the settings of its roles, and reports the
// key of the mimic server that its store holds
static bool MimicTraceStartNode(MIMICTRACE_NODE *t)
{
	t->Node = NewNode(t->Dir);

	return NodeStart(t->Node);
}

// Start the overlay of the node of t, with the dialler as its data transport and, for a node of the Intent, its control stream
// to the controller
static bool MimicTraceOverlay(MIMICTRACE_CTX *ctx, MIMICTRACE_NODE *t, bool controlled)
{
	NODE_OVERLAY_CONFIG c;

	Zero(&c, sizeof(c));
	if (controlled)
	{
		c.Control = ctx->Tls;
		StrCpy(c.Controller, sizeof(c.Controller), ctx->Controller);
		Copy(c.ControllerKey, ctx->ControllerKey, PEER_KEY_SIZE);
	}
	c.Data = &t->Dialler;
	c.Key = &t->Key;
	c.AdapterParam = t;
	c.Dialable = MimicTraceDialable;

	return NodeOverlayStart(t->Node, &c);
}

// Stop and free the node of t, with its overlay and its sidecars
static void MimicTraceStop(MIMICTRACE_NODE *t)
{
	if (t->Node == NULL)
	{
		return;
	}

	NodeStop(t->Node);
	FreeNode(t->Node);
	t->Node = NULL;
}

// The address 100.64.0.last/10 of the Network default in the VRF of the prober
static void MimicTraceAddress(CONTROL_ADDRESS *a, UCHAR last)
{
	UCHAR address[4] = {100, 64, 0, 0};

	address[3] = last;

	Zero(a, sizeof(CONTROL_ADDRESS));
	StrCpy(a->Network, sizeof(a->Network), "default");
	a->VrfId = MIMICTRACE_VRF;
	Copy(a->Address, address, 4);
	a->AddressSize = 4;
	a->Length = 10;
}

// The session of the node of t with the peer name: whether it is up, with what the overlay reports of it into s
static bool MimicTraceSession(MIMICTRACE_NODE *t, char *name, NODE_OVERLAY_SESSION *s)
{
	NODE_OVERLAY_SESSION list[MIMICTRACE_SESSIONS];
	char listener[MAX_SIZE];

	Zero(s, sizeof(NODE_OVERLAY_SESSION));
	Zero(list, sizeof(list));
	if (t->Node == NULL)
	{
		return false;
	}

	UINT num = NodeOverlayGetSessions(t->Node, list, MIMICTRACE_SESSIONS, listener, sizeof(listener));
	for (UINT i = 0;i < MIN(num, MIMICTRACE_SESSIONS);i++)
	{
		if (StrCmp(list[i].Name, name) == 0)
		{
			Copy(s, &list[i], sizeof(NODE_OVERLAY_SESSION));
			return list[i].Up;
		}
	}

	return false;
}

// What the test reports of a node while it waits: its control stream, its Generation, the session with its peer and its sidecars
static void MimicTraceShow(MIMICTRACE_NODE *t, char *peer)
{
	NODE_OVERLAY_STATUS os;
	NODE_OVERLAY_SESSION s;
	NODE_STATUS st;

	if (t->Node == NULL)
	{
		return;
	}

	NodeOverlayGetStatus(t->Node, &os);
	MimicTraceSession(t, peer, &s);
	NodeGetStatus(t->Node, &st);

	Print("  [INFO] %s: control stream %s, generation %I64u, session with %s %s over \"%s\", %I64d dials; server role: configured %u, running %u, "
		"listen \"%s\", %I64u accepted, %I64u probes, error \"%s\"; client role: configured %u, running %u, %u starts, error \"%s\"\n",
		t->Name, os.Connected ? "open" : "down", os.Generation, peer, s.Up ? "up" : "down", s.Transport, (INT64)ReadAcquire64(&t->NumDials),
		(UINT)st.Mimic[NODE_MIMIC_ROLE_SERVER].Configured, (UINT)st.Mimic[NODE_MIMIC_ROLE_SERVER].Running, st.Mimic[NODE_MIMIC_ROLE_SERVER].Listen,
		st.Mimic[NODE_MIMIC_ROLE_SERVER].Accepted, st.Mimic[NODE_MIMIC_ROLE_SERVER].Probes, st.Mimic[NODE_MIMIC_ROLE_SERVER].Error,
		(UINT)st.Mimic[NODE_MIMIC_ROLE_CLIENT].Configured, (UINT)st.Mimic[NODE_MIMIC_ROLE_CLIENT].Running, st.Mimic[NODE_MIMIC_ROLE_CLIENT].NumStarts,
		st.Mimic[NODE_MIMIC_ROLE_CLIENT].Error);
}

// Wait until the server role of mimic-server runs at address, with another process than not_pid; its status into st. False
// when it did not within MIMICTRACE_BOUND.
static bool MimicTraceWaitServer(MIMICTRACE_CTX *ctx, char *address, UINT not_pid, NODE_STATUS *st)
{
	for (UINT64 end = Tick64() + MIMICTRACE_BOUND;;SleepThread(MIMICTRACE_POLL))
	{
		NodeGetStatus(ctx->Server.Node, st);

		NODE_MIMIC_STATUS *m = &st->Mimic[NODE_MIMIC_ROLE_SERVER];
		bool runs = (m->Running && m->ProcessId != 0 && m->ProcessId != not_pid && StrCmp(m->Listen, address) == 0);
		if (runs || Tick64() >= end)
		{
			return runs;
		}
	}
}

// Wait until the MimicClient setting of the node of t holds a link to address and the client role runs, a start of its sidecar
// after the starts before; its status into st. False when it did not within MIMICTRACE_BOUND.
static bool MimicTraceWaitLink(MIMICTRACE_NODE *t, char *address, UINT starts, NODE_STATUS *st)
{
	char want[MAX_SIZE];

	Format(want, sizeof(want), "\"address\":\"%s\"", address);

	for (UINT64 end = Tick64() + MIMICTRACE_BOUND;;SleepThread(MIMICTRACE_POLL))
	{
		char *text = MimicTraceSetting(t->Node, NODE_SETTING_MIMIC_CLIENT);
		bool linked = InStr(text, want);

		Free(text);
		NodeGetStatus(t->Node, st);

		NODE_MIMIC_STATUS *m = &st->Mimic[NODE_MIMIC_ROLE_CLIENT];
		bool runs = (linked && m->Running && m->ProcessId != 0 && m->NumStarts > starts);
		if (runs || Tick64() >= end)
		{
			return runs;
		}
	}
}

// Wait until the Noise session of mimic-client with mimic-server is up at both ends, the server's over the mimic transport, the
// client's over its dialler, whose last stream the mimic transport gave, and opened after since (the GetTickCount64 of the
// session of the client before, 0 for none); what the client reports of it into s. False when it was not within
// MIMICTRACE_BOUND.
static bool MimicTraceWaitSession(MIMICTRACE_CTX *ctx, UINT64 since, NODE_OVERLAY_SESSION *s)
{
	NODE_OVERLAY_SESSION at_server;
	char winner[TRANSPORT_NAME_SIZE];

	for (UINT64 end = Tick64() + MIMICTRACE_BOUND;;SleepThread(MIMICTRACE_POLL))
	{
		AcquireSRWLockShared(&ctx->Client.Lock);
		StrCpy(winner, sizeof(winner), ctx->Client.Winner);
		ReleaseSRWLockShared(&ctx->Client.Lock);

		bool up = (MimicTraceSession(&ctx->Client, MIMICTRACE_SERVER, s) && s->Since > since && StrCmp(s->Transport, ctx->Client.Dialler.Name) == 0 &&
			StrCmp(winner, NODE_MIMIC_TRANSPORT) == 0 && MimicTraceSession(&ctx->Server, MIMICTRACE_CLIENT, &at_server) &&
			StrCmp(at_server.Transport, NODE_MIMIC_TRANSPORT) == 0);
		if (up || Tick64() >= end)
		{
			return up;
		}
	}
}

// Wait until the channel binding of the last stream that the server role of mimic-server accepted is the one of the last
// stream that the client role of mimic-client dialled, into binding. False when it was not within MIMICTRACE_BOUND.
static bool MimicTraceWaitBinding(MIMICTRACE_CTX *ctx, UCHAR *binding)
{
	NODE_STATUS ss, cs;

	for (UINT64 end = Tick64() + MIMICTRACE_BOUND;;SleepThread(MIMICTRACE_POLL))
	{
		NodeGetStatus(ctx->Server.Node, &ss);
		NodeGetStatus(ctx->Client.Node, &cs);

		NODE_MIMIC_STATUS *a = &ss.Mimic[NODE_MIMIC_ROLE_SERVER];
		NODE_MIMIC_STATUS *b = &cs.Mimic[NODE_MIMIC_ROLE_CLIENT];
		bool same = (a->BindingSize == NODE_MIMIC_BINDING && b->BindingSize == NODE_MIMIC_BINDING && Cmp(a->Binding, b->Binding, NODE_MIMIC_BINDING) == 0);
		if (same)
		{
			Copy(binding, a->Binding, NODE_MIMIC_BINDING);
		}
		if (same || Tick64() >= end)
		{
			return same;
		}
	}
}

// Wait until the server role of mimic-server counted probes probes at least; its status into st. False when it did not within
// MIMICTRACE_BOUND.
static bool MimicTraceWaitProbes(MIMICTRACE_CTX *ctx, UINT64 probes, NODE_STATUS *st)
{
	for (UINT64 end = Tick64() + MIMICTRACE_BOUND;;SleepThread(MIMICTRACE_POLL))
	{
		NodeGetStatus(ctx->Server.Node, st);

		bool counted = (st->Mimic[NODE_MIMIC_ROLE_SERVER].Probes >= probes);
		if (counted || Tick64() >= end)
		{
			return counted;
		}
	}
}

// The key of the server: whether its MimicServer setting holds the private key ctx->Private and the node reports its public key
// ctx->Public
static bool MimicTraceSameKey(MIMICTRACE_CTX *ctx)
{
	UCHAR report[CONTROL_MIMIC_KEY_SIZE];
	char hex[MIMICTRACE_HEX];
	char now[MIMICTRACE_HEX];

	char *text = MimicTraceSetting(ctx->Server.Node, NODE_SETTING_MIMIC_SERVER);
	bool kept = MimicTraceField(text, "private_key", now, sizeof(now)) && StrCmp(now, ctx->Private) == 0;
	MimicTraceDrop(text);
	Zero(now, sizeof(now));

	bool reported = ControlGetMimicKey(ctx->Server.Node->MimicKeys, report);
	MimicTraceHex(hex, report, sizeof(report));

	return kept && reported && StrCmp(hex, ctx->Public) == 0;
}

// Whether the key is in none of the files of the diagnostics bundle of the data directory of mimic-server, which holds its
// settings: ranz doctor -bundle writes it, and the tar of Windows unpacks it
static void MimicTraceBundle(MIMICTRACE_CTX *ctx)
{
	wchar_t ranz[MAX_PATH];
	wchar_t work[MAX_PATH];
	wchar_t zip[MAX_PATH];
	wchar_t out[MAX_PATH];
	wchar_t empty[MAX_PATH];
	wchar_t tar[MAX_PATH];
	wchar_t cmd[MAX_PATH * 4];

	UniStrCpy(ranz, sizeof(ranz), ctx->Server.Node->MimicSidecar);
	MimicTraceNewDir(work, sizeof(work), "bundle");
	ConbinePathW(zip, sizeof(zip), work, L"bundle.zip");
	ConbinePathW(out, sizeof(out), work, L"out");
	ConbinePathW(empty, sizeof(empty), work, L"controller");
	MakeDirExW(out);
	MakeDirExW(empty);

	UniFormat(cmd, sizeof(cmd), L"\"%s\" doctor -bundle -o \"%s\" -node-dir \"%s\" -controller-dir \"%s\"", ranz, zip, ctx->Server.Dir, empty);
	UINT code = MimicTraceRun(cmd);

	GetSystemDirectoryW(tar, MAX_PATH);
	ConbinePathW(tar, sizeof(tar), tar, L"tar.exe");
	UniFormat(cmd, sizeof(cmd), L"\"%s\" -xf \"%s\" -C \"%s\"", tar, zip, out);
	UINT unpacked = (IsFileExistsW(zip) ? MimicTraceRun(cmd) : INFINITE);

	BUF *b = NewBuf();
	MimicTraceReadTree(b, out);

	bool clean = (MimicTraceHasKey(ctx, b) == false);
	MimicTraceCheck(ctx, (code == 0 || code == 1) && unpacked == 0 && MimicTraceHas(b, NODE_SETTING_MIMIC_SERVER) && clean,
		"the diagnostics bundle of mimic-server carries its MimicServer setting, and not the private key", "ranz doctor exit code %u, tar exit code %u, %u bytes unpacked, key %s",
		code, unpacked, b->Size, clean ? "absent" : "PRESENT");

	FreeBuf(b);
	MimicTraceDeleteTree(work);
}

//
// The steps
//

// mimic-server and mimic-client join the controller and apply their states: the server makes the key of its mimic server,
// writes its MimicServer setting, reports the public key and listens with the server role of its sidecar; the client gets its
// link and starts the client role of its sidecar; the Noise session of the client comes up over the mimic transport, with the
// same channel binding at both ends. The binding and when the session of the client came up into binding and since.
static bool MimicTraceJoin(MIMICTRACE_CTX *ctx, UCHAR *binding, UINT64 *since)
{
	UCHAR priv[CRYPTO_X25519_SIZE];
	UCHAR pub[CRYPTO_X25519_SIZE];
	UCHAR report[CONTROL_MIMIC_KEY_SIZE];
	char cmdline[MAX_SIZE * 4];
	char want[MAX_SIZE];
	NODE_OVERLAY_SESSION s;
	NODE_STATUS st;

	Print("[mimic-server and mimic-client join the controller]\n");

	bool started = (MimicTraceStartNode(&ctx->Server) && MimicTraceOverlay(ctx, &ctx->Server, true) && MimicTraceStartNode(&ctx->Client) &&
		MimicTraceOverlay(ctx, &ctx->Client, true));
	bool installed = (ctx->Server.Node != NULL && IsFileExistsW(ctx->Server.Node->MimicSidecar));
	if (MimicTraceCheck(ctx, started && installed, "mimic-server and mimic-client run their overlays, with their control streams to the controller, and ranz.exe is next to vpntest.exe",
		"started %u, ranz.exe there %u", (UINT)started, (UINT)installed) == false)
	{
		return false;
	}

	// The server role of the sidecar of mimic-server runs at the address of the mimic section of its Listener
	bool served = MimicTraceWaitServer(ctx, MIMICTRACE_FIRST, 0, &st);
	NODE_MIMIC_STATUS *ms = &st.Mimic[NODE_MIMIC_ROLE_SERVER];
	UINT server_pid = ms->ProcessId;
	if (MimicTraceCheck(ctx, served, "mimic-server applies its state: the server role of its sidecar runs at the address of the mimic section of its Listener",
		"running %u, listen \"%s\", error \"%s\"", (UINT)ms->Running, ms->Listen, ms->Error) == false)
	{
		MimicTraceShow(&ctx->Server, MIMICTRACE_CLIENT);
		return false;
	}

	// Its MimicServer setting: the mimic section with the short id that the controller made, and the private key that the node
	// made, whose public key it reports
	char *server = MimicTraceSetting(ctx->Server.Node, NODE_SETTING_MIMIC_SERVER);
	bool settings = (InStr(server, "\"listen\":\"" MIMICTRACE_FIRST "\"") && InStr(server, "\"server_names\":[\"" MIMICTRACE_NAME "\"]") &&
		InStr(server, "\"self_signed\":true") && InStr(server, "\"short_ids\":[\""));
	bool has = (MimicTraceField(server, "private_key", ctx->Private, sizeof(ctx->Private)) && MimicTraceUnhex(ctx->Private, priv, CRYPTO_X25519_SIZE));
	bool reported = (has && CryptoX25519PublicKey(pub, priv) && ControlGetMimicKey(ctx->Server.Node->MimicKeys, report) && Cmp(pub, report, CRYPTO_X25519_SIZE) == 0);
	Zero(priv, sizeof(priv));
	if (reported)
	{
		MimicTraceHex(ctx->Public, pub, CRYPTO_X25519_SIZE);
	}
	MimicTraceCheck(ctx, settings && has && reported,
		"its MimicServer setting holds the mimic section with the short id of the controller and the private key that the node made, and the node reports its public key",
		"settings %u, a private key %u, its public key reported %u", (UINT)settings, (UINT)has, (UINT)reported);

	// mimic-client: once the controller has the key, the link to the server in its MimicClient setting, and the client role of
	// its sidecar
	bool linked = MimicTraceWaitLink(&ctx->Client, MIMICTRACE_FIRST, 0, &st);
	UINT client_pid = st.Mimic[NODE_MIMIC_ROLE_CLIENT].ProcessId;
	char *client = MimicTraceSetting(ctx->Client.Node, NODE_SETTING_MIMIC_CLIENT);
	bool short_id = (MimicTraceField(client, "short_id", ctx->ShortId, sizeof(ctx->ShortId)) && IsEmptyStr(ctx->ShortId) == false);
	Format(want, sizeof(want), "\"short_ids\":[\"%s\"]", ctx->ShortId);
	bool link = (linked && reported && short_id && InStr(client, "\"server_name\":\"" MIMICTRACE_NAME "\"") && InStr(client, ctx->Public) && InStr(server, want));
	MimicTraceCheck(ctx, link,
		"mimic-client gets its link once the controller has the key: the address of the mimic endpoint, the server name, the public key that the server reported and the short id of the server, and its client role runs",
		"linked and running %u, short id \"%s\", MimicClient \"%s\", error \"%s\"", (UINT)linked, ctx->ShortId, client, st.Mimic[NODE_MIMIC_ROLE_CLIENT].Error);
	Free(client);
	MimicTraceDrop(server);

	if (linked == false)
	{
		MimicTraceShow(&ctx->Server, MIMICTRACE_CLIENT);
		MimicTraceShow(&ctx->Client, MIMICTRACE_SERVER);
		return false;
	}

	// The Noise session of the client over the mimic transport, with the same binding at both ends
	bool up = MimicTraceWaitSession(ctx, 0, &s);
	*since = s.Since;
	MimicTraceShow(&ctx->Server, MIMICTRACE_CLIENT);
	MimicTraceShow(&ctx->Client, MIMICTRACE_SERVER);
	MimicTraceCheck(ctx, up, "the Noise session of mimic-client with mimic-server comes up over the mimic transport: the client dialled the link through its sidecar, and the server took the stream from its own",
		"%s", "not within the bound");
	bool bound = (up && MimicTraceWaitBinding(ctx, binding));
	MimicTraceCheck(ctx, bound, "both ends of the session have the same channel binding: the last stream that the server accepted and the last that the client dialled", "%s",
		"the bindings differ, or a role has none");

	// The private key reaches the sidecar over its control pipe only: the command lines of the sidecars hold no key and no link
	MimicTraceCommandLine(server_pid, cmdline, sizeof(cmdline));
	bool server_line = (InStr(cmdline, "mimic -pipe ") && InStrEx(cmdline, ctx->Private, false) == false);
	MimicTraceCommandLine(client_pid, cmdline, sizeof(cmdline));
	bool client_line = (InStr(cmdline, "mimic -pipe ") && InStrEx(cmdline, ctx->Public, false) == false);
	MimicTraceCheck(ctx, has && server_line && client_line, "the command line of each sidecar is ranz.exe mimic with its pipe: no key, and no link", "server %u, client %u, the last \"%s\"",
		(UINT)server_line, (UINT)client_line, cmdline);

	if (up == false || bound == false || reported == false)
	{
		return false;
	}

	// The public key of the server, which the script finds in the API of the controller
	Format(want, sizeof(want), "%s\n", ctx->Public);
	return MimicTraceCheck(ctx, MimicTraceWriteFile(ctx, "up", want), "the test wrote the file up, with the public key of the mimic server, for the script", "%s",
		"the file cannot be written");
}

// mimic-prober, a node without a control stream, applies a state with a link to the mimic server whose short id the test
// changed, as the link of mimic-client holds it otherwise: its dial is spliced to the decoy and fails, and the server counts one
// probe
static void MimicTraceProbe(MIMICTRACE_CTX *ctx)
{
	CONTROL_STATE st;
	CONTROL_PEER peer;
	NODE_STATUS ns;
	CONTROL_MIMIC *m = ZeroMalloc(sizeof(CONTROL_MIMIC));

	Print("[a link with a wrong short id]\n");

	Zero(&ns, sizeof(ns));
	bool started = (MimicTraceStartNode(&ctx->Prober) && MimicTraceOverlay(ctx, &ctx->Prober, false));

	CONTROL_MIMIC_LINK *l = &m->Links[0];
	StrCpy(l->Peer, sizeof(l->Peer), MIMICTRACE_SERVER);
	StrCpy(l->Address, sizeof(l->Address), MIMICTRACE_FIRST);
	StrCpy(l->ServerName, sizeof(l->ServerName), MIMICTRACE_NAME);
	bool keyed = MimicTraceUnhex(ctx->Public, l->PublicKey, CONTROL_MIMIC_KEY_SIZE);
	l->ShortIdSize = StrLen(ctx->ShortId) / 2;
	bool shorted = (l->ShortIdSize != 0 && l->ShortIdSize <= CONTROL_MIMIC_SHORT_ID && MimicTraceUnhex(ctx->ShortId, l->ShortId, l->ShortIdSize));
	// The short id of the server with its first byte changed
	l->ShortId[0] ^= 0xFF;
	m->NumLinks = 1;

	// A state with an address and mimic-server as its peer, which it does not dial: the peer has no endpoint here
	Zero(&st, sizeof(st));
	Zero(&peer, sizeof(peer));
	st.Generation = 1;
	StrCpy(st.Name, sizeof(st.Name), MIMICTRACE_PROBER);
	MimicTraceAddress(&st.Addresses[0], 9);
	st.NumAddresses = 1;
	StrCpy(peer.Name, sizeof(peer.Name), MIMICTRACE_SERVER);
	Copy(peer.Key, ctx->Server.Key.Public, PEER_KEY_SIZE);
	peer.NumVrfs = 1;
	peer.VrfIds[0] = MIMICTRACE_VRF;
	MimicTraceAddress(&peer.Addresses[0], 1);
	peer.NumAddresses = 1;
	st.Peers = &peer;
	st.NumPeers = 1;
	st.Mimic = m;

	bool applied = (started && keyed && shorted && NodeOverlayApply(ctx->Prober.Node, &st));
	bool running = (applied && MimicTraceWaitLink(&ctx->Prober, MIMICTRACE_FIRST, 0, &ns));
	MimicTraceCheck(ctx, running, "mimic-prober, a node without a control stream, applies a link to the mimic server whose short id the test changed, and its client role runs",
		"started %u, key %u, short id %u, applied %u, error \"%s\"", (UINT)started, (UINT)keyed, (UINT)shorted, (UINT)applied, ns.Mimic[NODE_MIMIC_ROLE_CLIENT].Error);

	NodeGetStatus(ctx->Server.Node, &ns);
	UINT64 probes = ns.Mimic[NODE_MIMIC_ROLE_SERVER].Probes;

	TRANSPORT *t = (running ? NodeMimicTransport(ctx->Prober.Node) : NULL);
	TRANSPORT_STREAM *s = (t != NULL ? TransportDial(t, MIMICTRACE_FIRST, NULL) : NULL);
	MimicTraceCheck(ctx, t != NULL && s == NULL, "its dial fails: the server spliced it to the decoy, which did not prove the key of the server", "transport %u, stream %u",
		(UINT)(t != NULL), (UINT)(s != NULL));
	if (s != NULL)
	{
		TransportClose(s);
	}

	bool counted = (t != NULL && MimicTraceWaitProbes(ctx, probes + 1, &ns));
	MimicTraceCheck(ctx, counted && ns.Mimic[NODE_MIMIC_ROLE_SERVER].Probes == probes + 1, "the server counts one probe", "%I64u probes, %I64u before",
		ns.Mimic[NODE_MIMIC_ROLE_SERVER].Probes, probes);

	MimicTraceStop(&ctx->Prober);
	Free(m);
}

// The script gives the mimic server another address: the sidecar of each role restarts with its new setting, the server keeps
// its key, and the session of the client comes up again at the new address, with a new binding
static bool MimicTraceChange(MIMICTRACE_CTX *ctx, UCHAR *binding, UINT64 *since)
{
	UCHAR again[NODE_MIMIC_BINDING];
	NODE_OVERLAY_SESSION s;
	NODE_STATUS st;

	Print("[the Intent gives the mimic server another address]\n");

	Zero(again, sizeof(again));
	Zero(&s, sizeof(s));
	NodeGetStatus(ctx->Server.Node, &st);
	UINT server_pid = st.Mimic[NODE_MIMIC_ROLE_SERVER].ProcessId;
	NodeGetStatus(ctx->Client.Node, &st);
	UINT client_pid = st.Mimic[NODE_MIMIC_ROLE_CLIENT].ProcessId;
	UINT client_starts = st.Mimic[NODE_MIMIC_ROLE_CLIENT].NumStarts;

	if (MimicTraceCheck(ctx, MimicTraceWaitFile(ctx, "changed"), "the script applied the Intent with another address of the mimic server", "no file changed within %u ms",
		MIMICTRACE_SCRIPT) == false)
	{
		return false;
	}

	bool served = MimicTraceWaitServer(ctx, MIMICTRACE_SECOND, server_pid, &st);
	bool exited = MimicTraceExited(server_pid);
	bool kept = MimicTraceSameKey(ctx);
	MimicTraceCheck(ctx, served && exited && kept,
		"the server role of mimic-server restarts with its new setting, at the new address, and the node keeps its key and reports it",
		"running %u, listen \"%s\", the process before gone %u, the same key %u", (UINT)served, st.Mimic[NODE_MIMIC_ROLE_SERVER].Listen, (UINT)exited, (UINT)kept);

	bool linked = MimicTraceWaitLink(&ctx->Client, MIMICTRACE_SECOND, client_starts, &st);
	char *client = MimicTraceSetting(ctx->Client.Node, NODE_SETTING_MIMIC_CLIENT);
	bool moved = (linked && InStr(client, MIMICTRACE_FIRST) == false && InStr(client, ctx->Public));
	exited = MimicTraceExited(client_pid);
	MimicTraceCheck(ctx, moved && st.Mimic[NODE_MIMIC_ROLE_CLIENT].ProcessId != client_pid && exited,
		"the change of its link restarts the client role of mimic-client: a new process of its sidecar, with the link to the new address",
		"linked %u, the process before gone %u, MimicClient \"%s\"", (UINT)linked, (UINT)exited, client);
	Free(client);

	bool up = MimicTraceWaitSession(ctx, *since, &s);
	bool bound = (up && MimicTraceWaitBinding(ctx, again) && Cmp(again, binding, NODE_MIMIC_BINDING) != 0);
	MimicTraceShow(&ctx->Server, MIMICTRACE_CLIENT);
	MimicTraceShow(&ctx->Client, MIMICTRACE_SERVER);
	MimicTraceCheck(ctx, up && bound, "the session of mimic-client comes up again over the mimic transport, at the new address, with a new binding that both ends have",
		"up %u, the same new binding at both ends %u", (UINT)up, (UINT)bound);

	*since = s.Since;
	Copy(binding, again, NODE_MIMIC_BINDING);

	return (served && linked && up);
}

// mimic-server restarts: it reports the key that its store holds before it applies a state, and the session comes up again
static bool MimicTraceRestart(MIMICTRACE_CTX *ctx, UCHAR *binding, UINT64 *since)
{
	UCHAR report[CONTROL_MIMIC_KEY_SIZE];
	UCHAR again[NODE_MIMIC_BINDING];
	char hex[MIMICTRACE_HEX];
	NODE_OVERLAY_SESSION s;
	NODE_STATUS st;

	Print("[mimic-server restarts]\n");

	Zero(report, sizeof(report));
	Zero(again, sizeof(again));
	Zero(&s, sizeof(s));
	Zero(&st, sizeof(st));
	MimicTraceStop(&ctx->Server);
	bool started = MimicTraceStartNode(&ctx->Server);
	bool early = (started && ControlGetMimicKey(ctx->Server.Node->MimicKeys, report));
	MimicTraceHex(hex, report, sizeof(report));
	MimicTraceCheck(ctx, early && StrCmp(hex, ctx->Public) == 0, "after a restart mimic-server reports the same key, which its store holds, before it applies a state",
		"started %u, a key reported %u (%s)", (UINT)started, (UINT)early, hex);

	// The text dump of its store that the node wrote at its start, which the diagnostics bundle carries: the MimicServer setting,
	// without the private key
	wchar_t path[MAX_PATH];
	ConbinePathW(path, sizeof(path), ctx->Server.Dir, NODE_CONFIG_DUMP_NAME);
	BUF *dump = ReadDumpExW(path, false, 0);
	bool blank = (dump != NULL && MimicTraceHas(dump, NODE_SETTING_MIMIC_SERVER) && MimicTraceHasKey(ctx, dump) == false);
	MimicTraceCheck(ctx, blank, "the text dump of its store that the node wrote at its start, node_config.txt, holds the MimicServer setting and not the private key", "%s",
		dump == NULL ? "no dump" : "the setting is missing, or the key is in it");
	if (dump != NULL)
	{
		FreeBuf(dump);
	}

	bool overlay = (started && MimicTraceOverlay(ctx, &ctx->Server, true));
	bool served = (overlay && MimicTraceWaitServer(ctx, MIMICTRACE_SECOND, 0, &st));
	MimicTraceCheck(ctx, served && MimicTraceSameKey(ctx), "it applies its state again: the server role of its sidecar runs with the same setting and the same key",
		"overlay %u, running %u, error \"%s\"", (UINT)overlay, (UINT)served, st.Mimic[NODE_MIMIC_ROLE_SERVER].Error);

	bool up = (served && MimicTraceWaitSession(ctx, *since, &s));
	bool bound = (up && MimicTraceWaitBinding(ctx, again) && Cmp(again, binding, NODE_MIMIC_BINDING) != 0);
	MimicTraceShow(&ctx->Server, MIMICTRACE_CLIENT);
	MimicTraceShow(&ctx->Client, MIMICTRACE_SERVER);
	MimicTraceCheck(ctx, up && bound, "the session of mimic-client comes up again over the mimic transport, with a new binding that both ends have", "up %u, the same new binding %u",
		(UINT)up, (UINT)bound);

	*since = s.Since;
	Copy(binding, again, NODE_MIMIC_BINDING);

	// The diagnostics bundle of the server, whose text dump of the store holds the MimicServer setting now
	if (started)
	{
		MimicTraceBundle(ctx);
	}

	MimicTraceCheck(ctx, MimicTraceWriteFile(ctx, "restarted", "ok\n"), "the test wrote the file restarted for the script", "%s", "the file cannot be written");

	return up;
}

// The script takes the mimic section out of the Intent: both sidecars stop, and the settings and the key are gone
static bool MimicTraceRemove(MIMICTRACE_CTX *ctx)
{
	UCHAR report[CONTROL_MIMIC_KEY_SIZE];
	NODE_STATUS ss, cs;
	bool gone = false;

	Print("[the Intent takes the mimic section out]\n");

	NodeGetStatus(ctx->Server.Node, &ss);
	UINT server_pid = ss.Mimic[NODE_MIMIC_ROLE_SERVER].ProcessId;
	NodeGetStatus(ctx->Client.Node, &cs);
	UINT client_pid = cs.Mimic[NODE_MIMIC_ROLE_CLIENT].ProcessId;

	if (MimicTraceCheck(ctx, MimicTraceWaitFile(ctx, "removed"), "the script applied the Intent without the mimic section", "no file removed within %u ms",
		MIMICTRACE_SCRIPT) == false)
	{
		return false;
	}

	for (UINT64 end = Tick64() + MIMICTRACE_BOUND;gone == false && Tick64() < end;SleepThread(MIMICTRACE_POLL))
	{
		char *server = MimicTraceSetting(ctx->Server.Node, NODE_SETTING_MIMIC_SERVER);
		char *client = MimicTraceSetting(ctx->Client.Node, NODE_SETTING_MIMIC_CLIENT);
		bool texts = (IsEmptyStr(server) && IsEmptyStr(client));

		MimicTraceDrop(server);
		Free(client);
		NodeGetStatus(ctx->Server.Node, &ss);
		NodeGetStatus(ctx->Client.Node, &cs);

		NODE_MIMIC_STATUS *a = &ss.Mimic[NODE_MIMIC_ROLE_SERVER];
		NODE_MIMIC_STATUS *b = &cs.Mimic[NODE_MIMIC_ROLE_CLIENT];
		gone = (texts && ControlGetMimicKey(ctx->Server.Node->MimicKeys, report) == false && a->Configured == false && a->ProcessId == 0 &&
			b->Configured == false && b->ProcessId == 0);
	}

	MimicTraceShow(&ctx->Server, MIMICTRACE_CLIENT);
	MimicTraceShow(&ctx->Client, MIMICTRACE_SERVER);
	bool server_exited = MimicTraceExited(server_pid);
	bool client_exited = MimicTraceExited(client_pid);
	MimicTraceCheck(ctx, gone && server_exited && client_exited,
		"a state without the mimic part stops the sidecar of each role and takes the MimicServer and MimicClient settings out, and the key of the server with them: the server reports none",
		"gone %u, the server's sidecar exited %u, the client's %u", (UINT)gone, (UINT)server_exited, (UINT)client_exited);

	MimicTraceCheck(ctx, MimicTraceWriteFile(ctx, "gone", "ok\n"), "the test wrote the file gone for the script", "%s", "the file cannot be written");

	return gone;
}

// The private key of the mimic server is in no file of the folder of the script, once the script stopped the controller: its
// store, its log and the answers of its API that the script kept
static void MimicTraceController(MIMICTRACE_CTX *ctx)
{
	Print("[the controller and the key]\n");

	if (MimicTraceCheck(ctx, MimicTraceWaitFile(ctx, "stopped"), "the script stopped the controller", "no file stopped within %u ms", MIMICTRACE_SCRIPT) == false)
	{
		return;
	}

	BUF *b = NewBuf();
	MimicTraceReadTree(b, ctx->Folder);
	// The folder holds the public key: the file up, and the store of the controller, which kept the report of the node
	bool read = MimicTraceHas(b, ctx->Public);
	bool clean = (MimicTraceHasKey(ctx, b) == false);
	MimicTraceCheck(ctx, read && clean, "the private key is in nothing that the controller holds: no file of its folder, its store and its log, holds it",
		"%u bytes read, the public key found %u, the private key %s", b->Size, (UINT)read, clean ? "absent" : "PRESENT");
	FreeBuf(b);
}

// The private key of the mimic server is in no line of the logs of the nodes and their sidecars, which they wrote until they
// stopped; the log of the server says that it made the key, with its public key
static void MimicTraceLogs(MIMICTRACE_CTX *ctx)
{
	Print("[the logs and the key]\n");

	BUF *server = MimicTraceReadLogs(ctx->Server.Dir);
	BUF *client = MimicTraceReadLogs(ctx->Client.Dir);
	BUF *prober = MimicTraceReadLogs(ctx->Prober.Dir);

	bool told = (MimicTraceHas(server, "so the node made the key of the server: it reports its public key") && MimicTraceHas(server, ctx->Public));
	bool clean = (MimicTraceHasKey(ctx, server) == false && MimicTraceHasKey(ctx, client) == false && MimicTraceHasKey(ctx, prober) == false);
	MimicTraceCheck(ctx, told && clean, "the private key is in no line of the logs of the three nodes and of their sidecars, and the log of mimic-server says that it made the key",
		"the line of the key %u, the private key %s", (UINT)told, clean ? "absent" : "PRESENT");

	FreeBuf(server);
	FreeBuf(client);
	FreeBuf(prober);
}

// The arguments: the address of the controller, its static key in base64, the folder of the script
static bool MimicTraceInit(MIMICTRACE_CTX *ctx, UINT num, char **arg)
{
	UCHAR scalar[PEER_KEY_SIZE];
	UINT size = 0;
	bool ok = true;

	if (num < 3)
	{
		return false;
	}

	StrCpy(ctx->Controller, sizeof(ctx->Controller), arg[0]);
	void *key = Base64ToBin(&size, arg[1], StrLen(arg[1]));
	ok = (key != NULL && size == PEER_KEY_SIZE);
	if (ok)
	{
		Copy(ctx->ControllerKey, key, PEER_KEY_SIZE);
	}
	Free(key);
	StrToUni(ctx->Folder, sizeof(ctx->Folder), arg[2]);

	// The static keys of the three nodes: those of the Node resources of the script, and one of no resource for the prober
	MIMICTRACE_NODE *nodes[3] = {&ctx->Server, &ctx->Client, &ctx->Prober};
	char *names[3] = {MIMICTRACE_SERVER, MIMICTRACE_CLIENT, MIMICTRACE_PROBER};
	for (UINT n = 0;n < 3;n++)
	{
		MIMICTRACE_NODE *t = nodes[n];

		t->Name = names[n];
		for (UINT i = 0;i < PEER_KEY_SIZE;i++)
		{
			scalar[i] = (UCHAR)(1 + PEER_KEY_SIZE * n + i);
		}
		ok = PeerKeyFromScalar(&t->Key, scalar) && ok;
		MimicTraceDiallerInit(t);
		MimicTraceNewDir(t->Dir, sizeof(t->Dir), t->Name);
	}
	Zero(scalar, sizeof(scalar));

	for (UINT n = 0;n < 2 && ok;n++)
	{
		void *pub = Base64ToBin(&size, mimictrace_keys[n], StrLen(mimictrace_keys[n]));

		ok = (pub != NULL && size == PEER_KEY_SIZE && Cmp(pub, nodes[n]->Key.Public, PEER_KEY_SIZE) == 0);
		Free(pub);
	}

	ctx->Tls = ZeroMalloc(sizeof(TRANSPORT));
	SdnTraceTlsInit(ctx->Tls);

	// The folder of the script is a directory, which IsFileExistsW does not take
	DWORD attributes = GetFileAttributesW(ctx->Folder);

	return ok && attributes != INVALID_FILE_ATTRIBUTES && (attributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
}

// mimictrace: the mimic servers and their clients end to end, with a real ranz controller
RANZ_TEST("mimictrace", mimictrace_test, "Mimic tracer: mimictrace <host:port> <key> <folder>: a mimic server and its client from the Intent of a running ranz controller, with ranz next to vpntest: the key of the server made, reported and kept, the link of the client, its Noise session over the mimic transport with one binding at both ends, a wrong short id spliced and counted, a change, a restart and a removal, and the private key in no log, command line, bundle or file of the controller (.github/scripts/mimic-tracer.ps1).");
void mimictrace_test(UINT num, char **arg)
{
	MIMICTRACE_CTX *ctx = ZeroMalloc(sizeof(MIMICTRACE_CTX));
	HANDLE done = CreateEventW(NULL, TRUE, FALSE, NULL);
	HANDLE watchdog = (done != NULL ? CreateThread(NULL, 0, MimicTraceWatchdog, done, 0, NULL) : NULL);
	UCHAR binding[NODE_MIMIC_BINDING];
	UINT64 since = 0;

	Print("Mimic tracer: a mimic server and its client from the Intent of the controller, over the sidecars of ranz.exe\n");

	Zero(binding, sizeof(binding));
	bool ok = MimicTraceInit(ctx, num, arg);
	if (MimicTraceCheck(ctx, ok, "the controller: its address and its static key, the folder of the script, and the static keys of the Node resources",
		"%s", "usage: mimictrace <host:port of the controller> <its static key in base64> <the folder of the script>"))
	{
		// Each step needs the one before; the controller is checked once the script went through to its end
		bool through = (MimicTraceJoin(ctx, binding, &since));
		if (through)
		{
			MimicTraceProbe(ctx);
			through = (MimicTraceChange(ctx, binding, &since) && MimicTraceRestart(ctx, binding, &since) && MimicTraceRemove(ctx));
		}
		if (through)
		{
			MimicTraceController(ctx);
		}
	}

	MimicTraceStop(&ctx->Prober);
	MimicTraceStop(&ctx->Client);
	MimicTraceStop(&ctx->Server);
	if (IsEmptyStr(ctx->Private) == false)
	{
		MimicTraceLogs(ctx);
	}

	MIMICTRACE_NODE *nodes[3] = {&ctx->Server, &ctx->Client, &ctx->Prober};
	for (UINT n = 0;n < 3;n++)
	{
		PeerKeyClose(&nodes[n]->Key);
		if (UniIsEmptyStr(nodes[n]->Dir) == false)
		{
			MimicTraceDeleteTree(nodes[n]->Dir);
		}
	}
	Zero(ctx->Private, sizeof(ctx->Private));
	Free(ctx->Tls);

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
		Print("MIMICTRACE TEST OK\n");
	}
	else
	{
		Print("MIMICTRACE TEST FAILED (%u of %u checks failed)\n", ctx->NumFailed, ctx->NumChecks);
	}

	Free(ctx);
}
