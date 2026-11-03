// mimicstatetest.c
// Named mimic state test of vpntest ("mimicstate" command, CORE-P2-7 #424)
//
// The mimic part of the state of a node (Cedar/NodeMimicState.c, Core/ControlMimic.c) without a controller and without
// ranz.exe: node-x takes the states that the test makes through its overlay without a control stream (NodeOverlayApply), as
// the control stream hands them over, and no ranz.exe is next to it, so its mimicry sidecar cannot start. node-y is its peer
// over the in-process loopback transport.
// - A state with a mimic server and a link: the node writes the MimicServer and MimicClient settings into its Configuration
//   store, the text of the server with a private key that it made, and reports the public key of that private key. The
//   Generation is applied, the Noise session with node-y comes up over the loopback transport, and the node says why the mimic
//   transport is unavailable, in its log and in the status of each role, and runs no sidecar.
// - A state with another clock tolerance and another link: both texts change, the key stays, and the session over the
//   loopback transport stays as it was.
// - The node restarts: it reports the same key, from its store, before any state, and the state again changes no text.
// - A state without the mimic part: the texts and the key are gone, the report holds no key, and the roles are not configured.
// - A state that asks for a mimic server again: a new key.
// - No private key is in a line of the node log.
// Print "MIMICSTATE TEST OK" only when every check passes.

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

#define	MIMICSTATE_WATCHDOG		180000				// The test process is aborted after this (ms)
#define	MIMICSTATE_BOUND		20000				// A bounded wait on observable state (ms)
#define	MIMICSTATE_POLL			50					// Poll interval of observable state (ms)
#define	MIMICSTATE_VRF			1					// The VRF of the test
#define	MIMICSTATE_NODE_X		"mimic-x"			// The node of the mimic part, without ranz.exe next to it
#define	MIMICSTATE_NODE_Y		"mimic-y"			// Its peer over the loopback transport
#define	MIMICSTATE_NAME			"decoy.test"		// The server name of the mimic server and of the link
#define	MIMICSTATE_LISTEN		"127.0.0.1:39990"	// The address of the sidecar of the server, which never starts
#define	MIMICSTATE_LINK_1		"127.0.0.1:39991"	// The address of the link of the first state ...
#define	MIMICSTATE_LINK_2		"127.0.0.1:39992"	// ... and of the second
#define	MIMICSTATE_TEXT			65536				// Bytes of a setting that the test reads at most
#define	MIMICSTATE_HEX			(CRYPTO_X25519_SIZE * 2 + 1)	// A key as hexadecimal digits, with the NUL

// One node of the test
typedef struct MIMICSTATE_NODE
{
	char *Name;
	wchar_t Dir[MAX_PATH];				// Its data directory
	PEER_KEY Key;						// Its static key
	NODE *Node;
	UINT64 Gen;							// The Generation of the last state applied to it
} MIMICSTATE_NODE;

// The state of the test
typedef struct MIMICSTATE_CTX
{
	UINT NumChecks;
	UINT NumFailed;
	MIMICSTATE_NODE X;					// node-x, with the mimic part
	MIMICSTATE_NODE Y;					// node-y, its peer
	TRANSPORT *Loop;					// The loopback transport of their session
} MIMICSTATE_CTX;

static bool MimicStateCheck(MIMICSTATE_CTX *ctx, bool ok, char *what, char *fmt, ...) RANZ_PRINTF_FORMAT(4, 5);
static bool MimicStateCheck(MIMICSTATE_CTX *ctx, bool ok, char *what, char *fmt, ...)
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

// The watchdog: a test that hangs ends the process
static DWORD WINAPI MimicStateWatchdog(LPVOID param)
{
	if (WaitForSingleObject((HANDLE)param, MIMICSTATE_WATCHDOG) == WAIT_TIMEOUT)
	{
		Print("MIMICSTATE TEST FAILED (the watchdog ended it after %u ms)\n", MIMICSTATE_WATCHDOG);
		fflush(stdout);
		ExitProcess(1);
	}

	return 0;
}

// size bytes as lower-case hexadecimal digits into str, which holds size * 2 + 1 bytes
static void MimicStateHex(char *str, const UCHAR *data, UINT size)
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
static int MimicStateDigit(char c)
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

// The private key that a text of the server role holds, as 64 hexadecimal digits into hex and as bytes into priv; false for a
// text without one
static bool MimicStateKeyOf(char *text, char *hex, UCHAR *priv)
{
	static const char field[] = "\"private_key\":\"";
	UINT i = SearchStrEx(text, field, 0, true);
	bool ok = true;

	StrCpy(hex, MIMICSTATE_HEX, "");
	Zero(priv, CRYPTO_X25519_SIZE);
	if (i == INFINITE || StrLen(text) < i + StrLen(field) + CRYPTO_X25519_SIZE * 2)
	{
		return false;
	}

	Copy(hex, text + i + StrLen(field), CRYPTO_X25519_SIZE * 2);
	hex[CRYPTO_X25519_SIZE * 2] = 0;

	for (UINT j = 0;j < CRYPTO_X25519_SIZE;j++)
	{
		int hi = MimicStateDigit(hex[j * 2]);
		int lo = MimicStateDigit(hex[j * 2 + 1]);

		ok = ok && hi >= 0 && lo >= 0;
		priv[j] = (UCHAR)(ok ? hi * 16 + lo : 0);
	}

	return ok;
}

// The text of the setting name of the Configuration store of a node, "" when it has none; the caller frees it
static char *MimicStateSetting(NODE *n, char *name)
{
	char *text = ZeroMalloc(MIMICSTATE_TEXT);

	if (n->Store == NULL || CsGetSetting(n->Store, name, text, MIMICSTATE_TEXT) == false)
	{
		StrCpy(text, MIMICSTATE_TEXT, "");
	}

	return text;
}

// The text of the node log of the node in dir, every file of its log directory, read without the read lock as its writer holds
// them open; the caller frees it
static char *MimicStateLog(wchar_t *dir)
{
	wchar_t log_dir[MAX_PATH];
	BUF *b = NewBuf();

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
		BUF *f = ReadDumpExW(path, false, 0);
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

// Whether the node log of the node in dir says part within MIMICSTATE_BOUND: the log has a writer thread
static bool MimicStateWaitLog(wchar_t *dir, char *part)
{
	for (UINT64 end = Tick64() + MIMICSTATE_BOUND;;SleepThread(MIMICSTATE_POLL))
	{
		char *log = MimicStateLog(dir);
		bool found = InStr(log, part);

		Free(log);
		if (found || Tick64() >= end)
		{
			return found;
		}
	}
}

// A new empty data directory under the temp directory of the process, with a configuration store that runs no role on one
// worker
static void MimicStateNewDir(wchar_t *dir, UINT size, char *name)
{
	wchar_t tmp[MAX_PATH];
	wchar_t path[MAX_PATH];

	UniFormat(tmp, sizeof(tmp), L"mimicstate_%S_%u", name, (UINT)Tick64());
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
static void MimicStateDeleteDir(wchar_t *dir)
{
	DIRLIST *d = EnumDirW(dir);

	for (UINT i = 0;d != NULL && i < d->NumFiles;i++)
	{
		DIRENT *e = d->File[i];
		wchar_t path[MAX_PATH];

		ConbinePathW(path, sizeof(path), dir, e->FileNameW);
		if (e->Folder)
		{
			MimicStateDeleteDir(path);
		}
		else
		{
			FileDeleteW(path);
		}
	}

	FreeDir(d);
	DeleteDirW(dir);
}

// Start a node of the test: a node of its data directory, and its overlay without a control stream over the loopback transport.
// node-x has no ranz.exe next to it.
static bool MimicStateStart(MIMICSTATE_CTX *ctx, MIMICSTATE_NODE *t, bool without_ranz)
{
	NODE_OVERLAY_CONFIG cfg;

	t->Node = NewNode(t->Dir);
	if (without_ranz)
	{
		ConbinePathW(t->Node->MimicSidecar, sizeof(t->Node->MimicSidecar), t->Dir, NODE_BGP_EXE_NAME);
	}
	bool started = NodeStart(t->Node);

	Zero(&cfg, sizeof(cfg));
	cfg.Data = ctx->Loop;
	cfg.Key = &t->Key;

	return started && NodeOverlayStart(t->Node, &cfg);
}

// Stop a node of the test, with its overlay
static void MimicStateStop(MIMICSTATE_NODE *t)
{
	if (t->Node == NULL)
	{
		return;
	}

	NodeStop(t->Node);
	FreeNode(t->Node);
	t->Node = NULL;
}

// The address 100.64.0.last/10 of the Network default in the VRF of the test
static void MimicStateAddress(CONTROL_ADDRESS *a, UCHAR last)
{
	UCHAR address[4] = {100, 64, 0, 0};

	address[3] = last;

	Zero(a, sizeof(CONTROL_ADDRESS));
	StrCpy(a->Network, sizeof(a->Network), "default");
	a->VrfId = MIMICSTATE_VRF;
	Copy(a->Address, address, 4);
	a->AddressSize = 4;
	a->Length = 10;
}

// The mimic part of node-x, as the Controller sends it: a mimic server with the clock tolerance max_time_diff and its short id,
// and a link to a server of node-y at the address link
static void MimicStatePart(CONTROL_MIMIC *m, UINT max_time_diff, char *link)
{
	Zero(m, sizeof(CONTROL_MIMIC));

	m->HasServer = true;
	StrCpy(m->Server.Listen, sizeof(m->Server.Listen), MIMICSTATE_LISTEN);
	StrCpy(m->Server.ServerNames[0], sizeof(m->Server.ServerNames[0]), MIMICSTATE_NAME);
	m->Server.NumServerNames = 1;
	m->Server.MaxTimeDiffMs = max_time_diff;
	m->Server.DecoyMode = CONTROL_MIMIC_DECOY_OWN;
	m->Server.SelfSigned = true;
	m->Server.ShortIdSize = CONTROL_MIMIC_SHORT_ID;
	for (UINT i = 0;i < CONTROL_MIMIC_SHORT_ID;i++)
	{
		m->Server.ShortId[i] = (UCHAR)(0xA0 + i);
	}

	CONTROL_MIMIC_LINK *l = &m->Links[0];
	StrCpy(l->Peer, sizeof(l->Peer), MIMICSTATE_NODE_Y);
	StrCpy(l->Address, sizeof(l->Address), link);
	StrCpy(l->ServerName, sizeof(l->ServerName), MIMICSTATE_NAME);
	for (UINT i = 0;i < CONTROL_MIMIC_KEY_SIZE;i++)
	{
		l->PublicKey[i] = (UCHAR)(0x40 + i);
	}
	l->ShortIdSize = CONTROL_MIMIC_SHORT_ID;
	for (UINT i = 0;i < CONTROL_MIMIC_SHORT_ID;i++)
	{
		l->ShortId[i] = (UCHAR)(0xB0 + i);
	}
	m->NumLinks = 1;
}

// Apply a state of the node t to its overlay, as the control stream does: its address 100.64.0.last, the other node of the test
// as its peer, and the mimic part m, NULL for none
static bool MimicStateApply(MIMICSTATE_CTX *ctx, MIMICSTATE_NODE *t, UCHAR last, CONTROL_MIMIC *m)
{
	MIMICSTATE_NODE *other = (t == &ctx->X ? &ctx->Y : &ctx->X);
	CONTROL_STATE st;
	CONTROL_PEER peer;

	Zero(&st, sizeof(st));
	Zero(&peer, sizeof(peer));

	st.Generation = ++t->Gen;
	StrCpy(st.Name, sizeof(st.Name), t->Name);
	MimicStateAddress(&st.Addresses[0], last);
	st.NumAddresses = 1;

	StrCpy(peer.Name, sizeof(peer.Name), other->Name);
	Copy(peer.Key, other->Key.Public, PEER_KEY_SIZE);
	peer.NumVrfs = 1;
	peer.VrfIds[0] = MIMICSTATE_VRF;
	MimicStateAddress(&peer.Addresses[0], (UCHAR)(last == 1 ? 2 : 1));
	peer.NumAddresses = 1;
	st.Peers = &peer;
	st.NumPeers = 1;

	st.Mimic = m;

	return NodeOverlayApply(t->Node, &st);
}

// The session of node-x with node-y: whether it is up on both nodes over the loopback transport within MIMICSTATE_BOUND, and
// since when on node-x
static bool MimicStateSessionUp(MIMICSTATE_CTX *ctx, UINT64 *since)
{
	NODE_OVERLAY_SESSION sx, sy;
	char listener[MAX_SIZE];

	*since = 0;

	for (UINT64 end = Tick64() + MIMICSTATE_BOUND;Tick64() < end;SleepThread(MIMICSTATE_POLL))
	{
		Zero(&sx, sizeof(sx));
		Zero(&sy, sizeof(sy));
		UINT nx = NodeOverlayGetSessions(ctx->X.Node, &sx, 1, listener, sizeof(listener));
		UINT ny = NodeOverlayGetSessions(ctx->Y.Node, &sy, 1, listener, sizeof(listener));

		if (nx == 1 && ny == 1 && sx.Up && sy.Up && StrCmp(sx.Transport, "loopback") == 0 && StrCmp(sy.Transport, "loopback") == 0)
		{
			*since = sx.Since;
			return true;
		}
	}

	return false;
}

// The texts of node-x and what it reports: the private key of its server text into hex, false when the store has no such text,
// and whether the report holds the public key of that private key
static bool MimicStateKey(MIMICSTATE_CTX *ctx, char *hex, bool *reported)
{
	UCHAR priv[CRYPTO_X25519_SIZE];
	UCHAR pub[CRYPTO_X25519_SIZE];
	UCHAR report[CONTROL_MIMIC_KEY_SIZE];
	char *server = MimicStateSetting(ctx->X.Node, NODE_SETTING_MIMIC_SERVER);
	bool ok = MimicStateKeyOf(server, hex, priv);

	*reported = (ok && CryptoX25519PublicKey(pub, priv) && ControlGetMimicKey(ctx->X.Node->MimicKeys, report) && Cmp(pub, report, CRYPTO_X25519_SIZE) == 0);

	Zero(priv, sizeof(priv));
	Zero(server, StrLen(server));
	Free(server);

	return ok;
}

// The first state of the mimic part: the texts, the key and its report, the session over the loopback transport, and why the
// transport is unavailable
static void MimicStateFirst(MIMICSTATE_CTX *ctx, CONTROL_MIMIC *m, char *key, UINT64 *since)
{
	NODE_OVERLAY_STATUS os;
	NODE_STATUS st;
	char id[CONTROL_MIMIC_SHORT_ID * 2 + 1];
	char link_key[CONTROL_MIMIC_KEY_SIZE * 2 + 1];
	bool reported = false;

	Print("[a state with a mimic server and a link]\n");

	MimicStatePart(m, 120000, MIMICSTATE_LINK_1);
	bool applied = MimicStateApply(ctx, &ctx->Y, 2, NULL) && MimicStateApply(ctx, &ctx->X, 1, m);
	NodeOverlayGetStatus(ctx->X.Node, &os);
	MimicStateCheck(ctx, applied && os.Generation == ctx->X.Gen, "node-x applies the state: its Generation is in force", "applied %u, generation %I64u of %I64u",
		(UINT)applied, os.Generation, ctx->X.Gen);

	char *server = MimicStateSetting(ctx->X.Node, NODE_SETTING_MIMIC_SERVER);
	char *client = MimicStateSetting(ctx->X.Node, NODE_SETTING_MIMIC_CLIENT);
	MimicStateHex(id, m->Server.ShortId, m->Server.ShortIdSize);
	bool server_ok = (InStr(server, "\"listen\":\"" MIMICSTATE_LISTEN "\"") && InStr(server, "\"server_names\":[\"" MIMICSTATE_NAME "\"]") &&
		InStr(server, "\"max_time_diff_ms\":120000") && InStr(server, "\"self_signed\":true") && InStr(server, id));
	MimicStateHex(link_key, m->Links[0].PublicKey, CONTROL_MIMIC_KEY_SIZE);
	MimicStateHex(id, m->Links[0].ShortId, m->Links[0].ShortIdSize);
	bool client_ok = (InStr(client, "\"address\":\"" MIMICSTATE_LINK_1 "\"") && InStr(client, "\"server_name\":\"" MIMICSTATE_NAME "\"") && InStr(client, link_key) && InStr(client, id));
	MimicStateCheck(ctx, server_ok && client_ok, "the store holds the MimicServer setting, the server of the state with its short id, and the MimicClient setting, its link",
		"MimicServer %u bytes, as expected %u; MimicClient \"%s\"", StrLen(server), (UINT)server_ok, client);
	Zero(server, StrLen(server));
	Free(server);
	Free(client);

	bool has = MimicStateKey(ctx, key, &reported);
	MimicStateCheck(ctx, has && reported, "the node made the key of its mimic server: the text holds the private key, and the node reports its public key",
		"private key in the text %u, its public key reported %u", (UINT)has, (UINT)reported);

	bool up = MimicStateSessionUp(ctx, since);
	MimicStateCheck(ctx, up, "nothing else of the node is affected: its Noise session with node-y comes up over the loopback transport", "%s",
		"no session within the bound");

	NodeGetStatus(ctx->X.Node, &st);
	bool unavailable = true;
	for (UINT i = 0;i < NODE_MIMIC_NUM_ROLES;i++)
	{
		NODE_MIMIC_STATUS *r = &st.Mimic[i];

		unavailable = unavailable && r->Configured && r->Running == false && r->ProcessId == 0 && r->NumStarts == 0 && InStr(r->Error, "is not installed at");
	}
	MimicStateCheck(ctx, unavailable, "without ranz.exe next to the node, each role is configured, runs no sidecar and says why it is unavailable",
		"server: configured %u, running %u, process %u, error \"%s\"; client: configured %u, running %u, process %u, error \"%s\"",
		(UINT)st.Mimic[0].Configured, (UINT)st.Mimic[0].Running, st.Mimic[0].ProcessId, st.Mimic[0].Error,
		(UINT)st.Mimic[1].Configured, (UINT)st.Mimic[1].Running, st.Mimic[1].ProcessId, st.Mimic[1].Error);
	MimicStateCheck(ctx, MimicStateWaitLog(ctx->X.Dir, "Mimic transport unavailable: ranz.exe, which holds the sidecar, is not installed at"),
		"the node log says why the mimic transport is unavailable", "%s", "the line is missing");
}

// A state with another clock tolerance and another link: both texts change, the key stays, and the session over the loopback
// transport stays as it was
static void MimicStateChange(MIMICSTATE_CTX *ctx, CONTROL_MIMIC *m, char *key, UINT64 since)
{
	char now[MIMICSTATE_HEX];
	bool reported = false;
	UINT64 still = 0;

	Print("[a state with another clock tolerance and another link]\n");

	MimicStatePart(m, 60000, MIMICSTATE_LINK_2);
	bool applied = MimicStateApply(ctx, &ctx->X, 1, m);

	char *server = MimicStateSetting(ctx->X.Node, NODE_SETTING_MIMIC_SERVER);
	char *client = MimicStateSetting(ctx->X.Node, NODE_SETTING_MIMIC_CLIENT);
	bool changed = (InStr(server, "\"max_time_diff_ms\":60000") && InStr(client, "\"address\":\"" MIMICSTATE_LINK_2 "\"") && InStr(client, MIMICSTATE_LINK_1) == false);
	Zero(server, StrLen(server));
	Free(server);
	Free(client);

	bool has = MimicStateKey(ctx, now, &reported);
	MimicStateCheck(ctx, applied && changed && has && reported && StrCmp(now, key) == 0, "the texts change with the state, and the node keeps the key of its server",
		"applied %u, texts changed %u, key in the text %u, reported %u, the same key %u", (UINT)applied, (UINT)changed, (UINT)has, (UINT)reported, (UINT)(StrCmp(now, key) == 0));
	Zero(now, sizeof(now));

	bool up = MimicStateSessionUp(ctx, &still);
	MimicStateCheck(ctx, up && still == since, "the other transports are not touched: the session with node-y over the loopback transport stays as it was",
		"up %u, since %I64u, before %I64u", (UINT)up, still, since);
}

// node-x restarts: it reports the same key from its store before any state, and the state again changes no text
static void MimicStateRestart(MIMICSTATE_CTX *ctx, CONTROL_MIMIC *m, char *key)
{
	UCHAR report[CONTROL_MIMIC_KEY_SIZE];
	char hex[CONTROL_MIMIC_KEY_SIZE * 2 + 1];
	char now[MIMICSTATE_HEX];
	bool reported = false;
	UINT64 since = 0;

	Print("[node-x restarts]\n");

	char *before = MimicStateSetting(ctx->X.Node, NODE_SETTING_MIMIC_SERVER);
	MimicStateStop(&ctx->X);
	bool started = MimicStateStart(ctx, &ctx->X, true);

	// The report of the key of the store, before any state: the one that the text holds
	bool early = ControlGetMimicKey(ctx->X.Node->MimicKeys, report);
	MimicStateHex(hex, report, sizeof(report));
	bool has = MimicStateKey(ctx, now, &reported);
	MimicStateCheck(ctx, started && early && has && reported && StrCmp(now, key) == 0,
		"after a restart the node reports the same key, which its store holds, before it applies a state",
		"started %u, a key reported %u (%s), the key in the text %u, the same %u", (UINT)started, (UINT)early, hex, (UINT)has, (UINT)(StrCmp(now, key) == 0));
	Zero(now, sizeof(now));

	bool applied = MimicStateApply(ctx, &ctx->X, 1, m);
	char *after = MimicStateSetting(ctx->X.Node, NODE_SETTING_MIMIC_SERVER);
	MimicStateCheck(ctx, applied && StrCmp(before, after) == 0, "the same state after the restart changes no text of the server", "applied %u, the text %s",
		(UINT)applied, StrCmp(before, after) == 0 ? "is the same" : "changed");
	MimicStateCheck(ctx, MimicStateSessionUp(ctx, &since), "the session with node-y comes up again over the loopback transport", "%s", "no session within the bound");

	Zero(before, StrLen(before));
	Zero(after, StrLen(after));
	Free(before);
	Free(after);
}

// A state without the mimic part: the texts and the key are gone, the report holds no key and the roles are not configured; then
// a state that asks for a mimic server again gets a new key
static void MimicStateRemove(MIMICSTATE_CTX *ctx, CONTROL_MIMIC *m, char *key, char *second)
{
	UCHAR report[CONTROL_MIMIC_KEY_SIZE];
	char text[MAX_SIZE];
	NODE_STATUS st;
	bool reported = false;

	Print("[a state without the mimic part]\n");

	bool applied = MimicStateApply(ctx, &ctx->X, 1, NULL);
	bool server = CsGetSetting(ctx->X.Node->Store, NODE_SETTING_MIMIC_SERVER, text, sizeof(text));
	bool client = CsGetSetting(ctx->X.Node->Store, NODE_SETTING_MIMIC_CLIENT, text, sizeof(text));
	bool early = ControlGetMimicKey(ctx->X.Node->MimicKeys, report);
	NodeGetStatus(ctx->X.Node, &st);
	bool idle = (st.Mimic[0].Configured == false && st.Mimic[1].Configured == false && st.Mimic[0].ProcessId == 0 && st.Mimic[1].ProcessId == 0 &&
		IsEmptyStr(st.Mimic[0].Error) && IsEmptyStr(st.Mimic[1].Error));
	MimicStateCheck(ctx, applied && server == false && client == false && early == false && idle,
		"the node takes the MimicServer and MimicClient settings out, and the key with them, and reports none",
		"applied %u, MimicServer %u, MimicClient %u, a key reported %u, the roles idle %u", (UINT)applied, (UINT)server, (UINT)client, (UINT)early, (UINT)idle);
	MimicStateCheck(ctx, MimicStateWaitLog(ctx->X.Dir, "has none, so its sidecar stopped, and the MimicServer setting and the key of the server are gone") &&
		MimicStateWaitLog(ctx->X.Dir, "has no link, so its sidecar stopped and the MimicClient setting is gone"), "the node log says that the roles went",
		"%s", "a line is missing");
	Zero(text, sizeof(text));

	Print("[a state that asks for a mimic server again]\n");

	MimicStatePart(m, 120000, MIMICSTATE_LINK_1);
	applied = MimicStateApply(ctx, &ctx->X, 1, m);
	bool has = MimicStateKey(ctx, second, &reported);
	MimicStateCheck(ctx, applied && has && reported && StrCmp(second, key) != 0, "the node makes a new key, and reports its public key",
		"applied %u, a key in the text %u, reported %u, another key %u", (UINT)applied, (UINT)has, (UINT)reported, (UINT)(StrCmp(second, key) != 0));
}

// mimicstate: the mimic part of the state of a node, without a controller and without ranz.exe
RANZ_TEST("mimicstate", mimicstate_test, "Mimic part of the state of a node (CORE-P2-7): the settings of its mimic server and its links written to its store from the states that it applies, the key of the server made on first use, reported and kept over a restart, and a node without ranz.exe that applies the state and says why the mimic transport is unavailable.");
void mimicstate_test(UINT num, char **arg)
{
	MIMICSTATE_CTX *ctx = ZeroMalloc(sizeof(MIMICSTATE_CTX));
	CONTROL_MIMIC *m = ZeroMalloc(sizeof(CONTROL_MIMIC));
	HANDLE done = CreateEventW(NULL, TRUE, FALSE, NULL);
	HANDLE watchdog = (done != NULL ? CreateThread(NULL, 0, MimicStateWatchdog, done, 0, NULL) : NULL);
	UCHAR scalar[PEER_KEY_SIZE];
	char key[MIMICSTATE_HEX];
	char second[MIMICSTATE_HEX];
	UINT64 since = 0;

	Print("Mimic state test: the mimic part of the state of a node, without a controller and without ranz.exe\n");

	ctx->X.Name = MIMICSTATE_NODE_X;
	ctx->Y.Name = MIMICSTATE_NODE_Y;
	StrCpy(key, sizeof(key), "");
	StrCpy(second, sizeof(second), "");

	// The static keys of the two nodes, and the loopback transport of their session
	bool keyed = true;
	for (UINT n = 0;n < 2;n++)
	{
		for (UINT i = 0;i < PEER_KEY_SIZE;i++)
		{
			scalar[i] = (UCHAR)((n == 0 ? 0x31 : 0x61) + i);
		}
		keyed = PeerKeyFromScalar(n == 0 ? &ctx->X.Key : &ctx->Y.Key, scalar) && keyed;
	}
	Zero(scalar, sizeof(scalar));
	ctx->Loop = TransportLoopbackNew("loopback", 0, false);

	MimicStateNewDir(ctx->X.Dir, sizeof(ctx->X.Dir), "x");
	MimicStateNewDir(ctx->Y.Dir, sizeof(ctx->Y.Dir), "y");
	bool started = (keyed && ctx->Loop != NULL && MimicStateStart(ctx, &ctx->X, true) && MimicStateStart(ctx, &ctx->Y, false));

	if (MimicStateCheck(ctx, started, "node-x, without ranz.exe next to it, and node-y run their overlays over the loopback transport",
		"keys %u, transport %u", (UINT)keyed, (UINT)(ctx->Loop != NULL)))
	{
		MimicStateFirst(ctx, m, key, &since);
		MimicStateChange(ctx, m, key, since);
		MimicStateRestart(ctx, m, key);
		MimicStateRemove(ctx, m, key, second);
	}

	MimicStateStop(&ctx->X);
	MimicStateStop(&ctx->Y);

	// The node log, once the node is freed, has none of the private keys
	Print("[the node log and the keys]\n");
	char *log = MimicStateLog(ctx->X.Dir);
	MimicStateCheck(ctx, IsEmptyStr(key) == false && InStrEx(log, key, false) == false && (IsEmptyStr(second) || InStrEx(log, second, false) == false),
		"no private key of the mimic server is in a line of the node log", "%s", "a key is in the log, or none was made");
	Free(log);

	Zero(key, sizeof(key));
	Zero(second, sizeof(second));
	if (ctx->Loop != NULL)
	{
		TransportLoopbackFree(ctx->Loop);
	}
	PeerKeyClose(&ctx->X.Key);
	PeerKeyClose(&ctx->Y.Key);
	MimicStateDeleteDir(ctx->X.Dir);
	MimicStateDeleteDir(ctx->Y.Dir);

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
		Print("MIMICSTATE TEST OK\n");
	}
	else
	{
		Print("MIMICSTATE TEST FAILED (%u of %u checks failed)\n", ctx->NumFailed, ctx->NumChecks);
	}

	Free(m);
	Free(ctx);
}
