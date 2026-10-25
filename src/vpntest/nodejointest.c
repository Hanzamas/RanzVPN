// nodejointest.c
// Named node join test of vpntest ("nodejoin" command, SDN-90 #395): the Controller settings of a Node, its admin pipe and
// the static key that ranz node prints, with no controller. The first-test job (.github/scripts/first-test.ps1) joins the
// Node service of its runner to a real Controller; this test checks what needs none:
// - A node without Controller settings starts, says once in its log that it has no Controller and opens no stream.
// - Its admin pipe lets SYSTEM and the Administrators in and no one else, and answers the commands of ranz node: key gives
//   the public half of the static key of the node, made first by the first need; a key of the wrong length, a malformed
//   fingerprint or an address without a port is refused with a message that says which; controller set and controller
//   clear write and remove the settings, which the node takes at its next start.
// - With settings that name a TLS port whose certificate has another TLS fingerprint, the node starts its overlay with the
//   control stream, takes no state, says in its log that the fingerprint check failed, and dials again after a delay that
//   doubles with each attempt that fails. With the fingerprint of that certificate the check passes, and the TLS session
//   still fails: its server did not select the ALPN protocol of the control stream.
// - The private half of the static key, which the test put into the key storage provider itself, is in no answer and in
//   no line of the node log.
// Print "NODEJOIN TEST OK" only when every check passes. Needs the rights to write a machine key, as an elevated window has.

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
#include "Core/Peer.h"
#include "Core/Transport.h"

#include <string.h>

#define	NODEJOIN_WAIT		20000		// What the node does is in its status or its log within this time (ms)
#define	NODEJOIN_POLL		50			// Poll interval of the status and the log (ms)
#define	NODEJOIN_REPLY		4096		// Bytes of an answer of the admin pipe at most

// The checks of the test
typedef struct NODEJOIN_CTX
{
	UINT NumChecks;
	UINT NumFailed;
} NODEJOIN_CTX;

static bool NodeJoinCheck(NODEJOIN_CTX *ctx, bool ok, char *what, char *fmt, ...) RANZ_PRINTF_FORMAT(4, 5);
static bool NodeJoinCheck(NODEJOIN_CTX *ctx, bool ok, char *what, char *fmt, ...)
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

// The key set of the identity keys of a node in this process: the machine's when the process holds the rights of a local
// administrator, as PeerKeyOpen chooses
static UINT NodeJoinScope()
{
	BYTE sid[SECURITY_MAX_SID_SIZE];
	DWORD size = sizeof(sid);
	BOOL member = FALSE;

	if (CreateWellKnownSid(WinBuiltinAdministratorsSid, NULL, sid, &size) == FALSE || CheckTokenMembership(NULL, sid, &member) == FALSE)
	{
		return 0;
	}

	return (member ? CRYPTO_MACHINE : 0);
}

// A new empty data directory under the temp directory of the process, with a configuration store that runs no role on
// one worker and names the identity key
static void NodeJoinNewDir(wchar_t *dir, UINT size, char *name, char *identity)
{
	wchar_t tmp[MAX_PATH];
	wchar_t path[MAX_PATH];

	UniFormat(tmp, sizeof(tmp), L"nodejoin_%S_%u", name, Rand32());
	ConbinePathW(dir, size, MsGetMyTempDirW(), tmp);
	MakeDirExW(dir);

	ConbinePathW(path, sizeof(path), dir, CS_FILE_NAME);
	CONFIG_STORE *s = CsOpen(path);
	if (s != NULL)
	{
		CsSetSetting(s, NODE_SETTING_ROLES, "none");
		CsSetSetting(s, NODE_SETTING_WORKERS, "1");
		CsSetSetting(s, NODE_SETTING_IDENTITY_KEY, identity);
		CsClose(s);
	}
}

// A node on dir with the admin pipe pipe, started
static NODE *NodeJoinStart(wchar_t *dir, wchar_t *pipe)
{
	NODE *n = NewNode(dir);

	UniStrCpy(n->AdminPipe, sizeof(n->AdminPipe), pipe);
	NodeStart(n);

	return n;
}

// One command on the admin pipe, as ranz node sends it, and its answer line into reply, without its newline
static bool NodeJoinAsk(wchar_t *pipe, char *command, char *reply, UINT size)
{
	wchar_t path[MAX_PATH];
	char line[MAX_SIZE];
	DWORD n = 0;
	UINT used = 0;
	HANDLE h = INVALID_HANDLE_VALUE;

	StrCpy(reply, size, "");
	UniFormat(path, sizeof(path), L"\\\\.\\pipe\\%s", pipe);

	for (UINT64 end = Tick64() + NODEJOIN_WAIT;h == INVALID_HANDLE_VALUE && Tick64() < end;)
	{
		h = CreateFileW(path, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
		if (h == INVALID_HANDLE_VALUE && GetLastError() != ERROR_PIPE_BUSY)
		{
			return false;
		}
		if (h == INVALID_HANDLE_VALUE)
		{
			WaitNamedPipeW(path, NODEJOIN_POLL);
		}
	}
	if (h == INVALID_HANDLE_VALUE)
	{
		return false;
	}

	Format(line, sizeof(line), "%s\n", command);
	bool ok = (WriteFile(h, line, StrLen(line), &n, NULL) && n == StrLen(line));
	while (ok && used < size - 1 && InStr(reply, "\n") == false)
	{
		ok = (ReadFile(h, reply + used, size - 1 - used, &n, NULL) && n != 0);
		used += (ok ? n : 0);
		reply[used] = 0;
	}
	CloseHandle(h);

	TrimCrlf(reply);
	return (ok && IsEmptyStr(reply) == false);
}

// The text of every file of the node log of dir, NUL-terminated
static char *NodeJoinLog(wchar_t *dir)
{
	wchar_t log_dir[MAX_PATH];
	BUF *all = NewBuf();

	ConbinePathW(log_dir, sizeof(log_dir), dir, NODE_LOG_DIR_NAME);
	DIRLIST *d = EnumDirW(log_dir);

	for (UINT i = 0;d != NULL && i < d->NumFiles;i++)
	{
		wchar_t path[MAX_PATH];

		if (d->File[i]->Folder)
		{
			continue;
		}

		ConbinePathW(path, sizeof(path), log_dir, d->File[i]->FileNameW);
		BUF *b = ReadDumpW(path);
		if (b != NULL)
		{
			WriteBuf(all, b->Buf, b->Size);
			FreeBuf(b);
		}
	}
	FreeDir(d);

	char *text = ZeroMalloc(all->Size + 1);
	Copy(text, all->Buf, all->Size);
	FreeBuf(all);

	return text;
}

// The number of times that what is in text
static UINT NodeJoinCount(char *text, char *what)
{
	UINT num = 0;

	for (char *p = strstr(text, what);p != NULL;p = strstr(p + 1, what))
	{
		num++;
	}

	return num;
}

// Whether the node log of dir says what within NODEJOIN_WAIT
static bool NodeJoinWaitLog(wchar_t *dir, char *what)
{
	for (UINT64 end = Tick64() + NODEJOIN_WAIT;Tick64() < end;SleepThread(NODEJOIN_POLL))
	{
		char *text = NodeJoinLog(dir);
		bool found = InStr(text, what);

		Free(text);
		if (found)
		{
			return true;
		}
	}

	return false;
}

// Delete the files of the node log and of a data directory, then both directories
static void NodeJoinDeleteDir(wchar_t *dir)
{
	wchar_t log_dir[MAX_PATH];

	ConbinePathW(log_dir, sizeof(log_dir), dir, NODE_LOG_DIR_NAME);
	for (UINT k = 0;k < 2;k++)
	{
		wchar_t *d_path = (k == 0 ? log_dir : dir);
		DIRLIST *d = EnumDirW(d_path);

		for (UINT i = 0;d != NULL && i < d->NumFiles;i++)
		{
			wchar_t path[MAX_PATH];

			if (d->File[i]->Folder == false)
			{
				ConbinePathW(path, sizeof(path), d_path, d->File[i]->FileNameW);
				FileDeleteW(path);
			}
		}
		FreeDir(d);
		DeleteDirW(d_path);
	}
}

// The TLS fingerprint of a certificate as the Controller prints it: the SHA-256 of its SubjectPublicKeyInfo in lower case hex
static bool NodeJoinFingerprint(PCCERT_CONTEXT cert, char *fp, UINT size)
{
	UCHAR hash[CRYPTO_SHA256_SIZE];
	BYTE *der = NULL;
	DWORD der_size = 0;

	if (CryptEncodeObjectEx(X509_ASN_ENCODING, X509_PUBLIC_KEY_INFO, &cert->pCertInfo->SubjectPublicKeyInfo, CRYPT_ENCODE_ALLOC_FLAG, NULL, &der, &der_size) == FALSE)
	{
		return false;
	}
	bool ok = CryptoSha256(hash, der, der_size);
	LocalFree(der);

	BinToStr(fp, size, hash, sizeof(hash));
	StrLower(fp);

	return ok;
}

RANZ_TEST_TAGS("nodejoin", nodejoin_test, "core", "Controller settings, admin pipe and static key of a Node without a controller (SDN-90): ranz node's commands, a TLS fingerprint that fails, the delay that grows, no private key in any answer or log.");
void nodejoin_test(UINT num, char **arg)
{
	NODEJOIN_CTX *ctx = ZeroMalloc(sizeof(NODEJOIN_CTX));
	NODE_CONTROLLER_STATUS st;
	PEER_KEY soft;
	CRYPTO_IDENTITY id;
	TRANSPORT_TLS_CONFIG tc;
	TRANSPORT *server = NULL;
	TRANSPORT_LISTENER *listener = NULL;
	UCHAR scalar[PEER_KEY_SIZE];
	UCHAR controller_key[PEER_KEY_SIZE];
	UCHAR pub[PEER_KEY_SIZE];
	char identity[MAX_SIZE], fresh[MAX_SIZE];
	wchar_t identity_w[MAX_SIZE], fresh_w[MAX_SIZE], pipe[MAX_SIZE];
	wchar_t dir[MAX_PATH] = {0};
	wchar_t dir_fresh[MAX_PATH] = {0};
	char priv_hex[2 * PEER_KEY_SIZE + 1], priv_lower[2 * PEER_KEY_SIZE + 1];
	char thumbprint[MAX_SIZE] = "", fingerprint[MAX_SIZE] = "", address[MAX_SIZE] = "";
	char command[MAX_SIZE * 2], want[MAX_SIZE];
	char *reply = ZeroMalloc(NODEJOIN_REPLY);
	char *answers = ZeroMalloc(NODEJOIN_REPLY * 4);
	char *priv_b64 = NULL, *pub_b64 = NULL, *ctrl_b64 = NULL, *fresh_b64 = NULL, *text = NULL;
	PCCERT_CONTEXT cert = NULL;
	UINT seen[4] = {0, 0, 0, 0};
	UINT size = 0;
	UINT scope = NodeJoinScope();
	UINT r = Rand32() & 0xFFFF;
	NODE *n = NULL;

	Zero(&soft, sizeof(soft));

	Print("Node join: the Controller settings, the admin pipe and the static key of a Node, with no controller\n");

	Format(identity, sizeof(identity), "Ranz nodejoin %u", r);
	Format(fresh, sizeof(fresh), "Ranz nodejoin fresh %u", r);
	StrToUni(identity_w, sizeof(identity_w), identity);
	StrToUni(fresh_w, sizeof(fresh_w), fresh);
	UniFormat(pipe, sizeof(pipe), L"ranz-nodejoin-%u", r);

	// The static key of the node, with a private half that the test knows, in the key storage provider under the name of its
	// IdentityKey setting
	for (UINT i = 0;i < PEER_KEY_SIZE;i++)
	{
		scalar[i] = (UCHAR)(0x40 + i);
		controller_key[i] = (UCHAR)(0x90 + i);
	}
	BinToStr(priv_hex, sizeof(priv_hex), scalar, sizeof(scalar));
	StrCpy(priv_lower, sizeof(priv_lower), priv_hex);
	StrLower(priv_lower);
	priv_b64 = Base64FromBin(&size, scalar, sizeof(scalar));
	bool keyed = PeerKeyFromScalar(&soft, scalar) && CryptoIdentityImport(&id, identity_w, scalar, scope);
	if (keyed)
	{
		CryptoIdentityClose(&id);
	}
	pub_b64 = Base64FromBin(&size, soft.Public, PEER_KEY_SIZE);
	ctrl_b64 = Base64FromBin(&size, controller_key, PEER_KEY_SIZE);
	Zero(scalar, sizeof(scalar));
	if (NodeJoinCheck(ctx, keyed && priv_b64 != NULL && pub_b64 != NULL && ctrl_b64 != NULL, "the static key of the node in the key storage provider", "CryptoIdentityImport \"%s\" failed", identity) == false)
	{
		goto END;
	}

	// A node without Controller settings
	NodeJoinNewDir(dir, sizeof(dir), "node", identity);
	n = NodeJoinStart(dir, pipe);
	NodeControllerGetStatus(n, &st);
	NodeJoinCheck(ctx, st.Set == false && st.Overlay == false && n->Overlay == NULL, "without Controller settings the node starts no overlay and opens no stream", "set %u, overlay %u", (UINT)st.Set, (UINT)st.Overlay);
	NodeJoinCheck(ctx, InStr(st.PipeAcl, ";;;SY)") && InStr(st.PipeAcl, ";;;BA)") && InStr(st.PipeAcl, ";;;WD)") == false && InStr(st.PipeAcl, ";;;BU)") == false &&
		InStr(st.PipeAcl, ";;;IU)") == false && InStr(st.PipeAcl, ";;;AU)") == false && InStr(st.PipeAcl, ";;;AN)") == false,
		"the admin pipe lets SYSTEM and the Administrators in, and no one else", "its DACL is %s", st.PipeAcl);

	// key: the public half of the static key, as the publicKey of a Node resource takes it, and nothing else
	Format(want, sizeof(want), "{\"publicKey\":\"%s\"}", pub_b64);
	NodeJoinCheck(ctx, NodeJoinAsk(pipe, "key", reply, NODEJOIN_REPLY) && StrCmp(reply, want) == 0, "key: the public half of the static key of the node", "the answer is %s, want %s", reply, want);
	StrCat(answers, NODEJOIN_REPLY * 4, reply);

	// A wrong value is refused with a message that says which
	for (UINT i = 0;i < 4;i++)
	{
		char *says = (i == 0 ? "has no port" : i == 1 ? "is 3 bytes long, not 32" : i == 2 ? "not 64 hex digits" : "unknown command");
		char what[MAX_SIZE];

		if (i == 0)
		{
			Format(command, sizeof(command), "controller set 127.0.0.1 %s %s", ctrl_b64, "0000000000000000000000000000000000000000000000000000000000000000");
		}
		else if (i == 1)
		{
			Format(command, sizeof(command), "controller set 127.0.0.1:443 AAAA %s", "0000000000000000000000000000000000000000000000000000000000000000");
		}
		else if (i == 2)
		{
			Format(command, sizeof(command), "controller set 127.0.0.1:443 %s 0123", ctrl_b64);
		}
		else
		{
			StrCpy(command, sizeof(command), "controller clean");
		}
		Format(what, sizeof(what), "a wrong command is refused with a message that says \"%s\"", says);
		NodeJoinCheck(ctx, NodeJoinAsk(pipe, command, reply, NODEJOIN_REPLY) && InStr(reply, "\"error\"") && InStr(reply, says), what, "%s: %s", command, reply);
	}

	// A TLS port whose certificate has another TLS fingerprint than the settings name
	cert = CryptoCertCreateSelfSigned(L"nodejoin", L"nodejoin.test", NULL, 30, 0);
	bool have_cert = (cert != NULL && CryptoCertThumbprintStr(cert, thumbprint, sizeof(thumbprint)) && CryptoCertAddToStore(cert, NULL, 0) && NodeJoinFingerprint(cert, fingerprint, sizeof(fingerprint)));
	if (have_cert)
	{
		TransportTlsDefaultConfig(&tc, thumbprint, false);
		tc.SetGroups = false;
		server = TransportTlsServerNew(&tc);
		listener = (server != NULL ? TransportListen(server, "127.0.0.1:0") : NULL);
	}
	Format(address, sizeof(address), "127.0.0.1:%u", (listener != NULL ? (UINT)TransportTlsBoundPort(server) : 0));
	if (NodeJoinCheck(ctx, listener != NULL, "a TLS port on the loopback interface with a self-signed certificate", "the certificate or the TLS listener failed") == false)
	{
		goto END;
	}

	Format(command, sizeof(command), "controller set %s %s %s", address, ctrl_b64, "abababababababababababababababababababababababababababababababab");
	Format(want, sizeof(want), "\"address\":\"%s\"", address);
	NodeJoinCheck(ctx, NodeJoinAsk(pipe, command, reply, NODEJOIN_REPLY) && InStr(reply, want) && InStr(reply, "\"error\"") == false, "controller set writes the settings", "%s", reply);
	StrCat(answers, NODEJOIN_REPLY * 4, reply);

	// The node takes them at its next start: the overlay with the control stream, no state, and the log says which check failed
	FreeNode(n);
	n = NodeJoinStart(dir, pipe);
	NodeControllerGetStatus(n, &st);
	NodeJoinCheck(ctx, st.Set && st.Overlay && StrCmp(st.Address, address) == 0 && Cmp(st.Key, controller_key, PEER_KEY_SIZE) == 0,
		"at its next start the node runs its overlay with the control stream of the settings", "set %u, overlay %u, address %s", (UINT)st.Set, (UINT)st.Overlay, st.Address);
	NodeJoinCheck(ctx, NodeJoinWaitLog(dir, "the TLS fingerprint check failed: the certificate of the Controller has the TLS fingerprint"),
		"a wrong TLS fingerprint fails closed, and the log says that the fingerprint check failed", "not within %u ms", NODEJOIN_WAIT);

	// The delay before the next attempt doubles with each attempt that fails: 1, 2 and 4 s after the first three
	for (UINT64 end = Tick64() + NODEJOIN_WAIT;seen[3] == 0 && Tick64() < end;SleepThread(NODEJOIN_POLL))
	{
		NodeControllerGetStatus(n, &st);
		if (st.NumEnds >= 1 && st.NumEnds <= 3 && seen[st.NumEnds] == 0)
		{
			seen[st.NumEnds] = st.NextRetry;
		}
	}
	NodeJoinCheck(ctx, seen[1] == CONTROL_RETRY && seen[2] == 2 * CONTROL_RETRY && seen[3] == 4 * CONTROL_RETRY && st.LastEnd == CONTROL_END_DIAL && st.Connected == false && st.Generation == 0,
		"each attempt that fails doubles the delay before the next one, and no state comes", "delays %u, %u, %u ms, last end %u, generation %I64u", seen[1], seen[2], seen[3], st.LastEnd, st.Generation);

	// With the fingerprint of the certificate the check passes, and the session still fails: no ALPN protocol of the control stream
	Format(command, sizeof(command), "controller set %s %s %s", address, ctrl_b64, fingerprint);
	NodeJoinCheck(ctx, NodeJoinAsk(pipe, command, reply, NODEJOIN_REPLY) && InStr(reply, fingerprint), "controller set takes the fingerprint of the certificate", "%s", reply);
	StrCat(answers, NODEJOIN_REPLY * 4, reply);
	FreeNode(n);
	n = NodeJoinStart(dir, pipe);
	NodeJoinCheck(ctx, NodeJoinWaitLog(dir, "no Controller answered there, or its TLS session failed"),
		"the certificate of the fingerprint passes its check, and a server that selects no ALPN protocol fails the session", "not within %u ms", NODEJOIN_WAIT);
	NodeControllerGetStatus(n, &st);
	NodeJoinCheck(ctx, st.Mismatch == false && st.Generation == 0, "no state comes from a server that is not the Controller", "mismatch %u, generation %I64u", (UINT)st.Mismatch, st.Generation);

	// controller shows the settings; clear takes them out, and at the next start the node has no Controller again
	NodeJoinCheck(ctx, NodeJoinAsk(pipe, "controller", reply, NODEJOIN_REPLY) && InStr(reply, want) && InStr(reply, "\"connected\":false"), "controller shows the settings and the state of the stream", "%s", reply);
	StrCat(answers, NODEJOIN_REPLY * 4, reply);
	NodeJoinCheck(ctx, NodeJoinAsk(pipe, "controller clear", reply, NODEJOIN_REPLY) && InStr(reply, "\"controller\":null"), "controller clear takes the settings out", "%s", reply);
	FreeNode(n);
	n = NodeJoinStart(dir, pipe);
	NodeControllerGetStatus(n, &st);
	bool none = (st.Set == false && n->Overlay == NULL);
	// The node log is written whole once the node is freed
	FreeNode(n);
	n = NULL;
	text = NodeJoinLog(dir);
	NodeJoinCheck(ctx, none && NodeJoinCount(text, "Controller: none") == 2,
		"each start without Controller settings says once that the node has no Controller, and opens no stream", "set %u, %u lines", (UINT)st.Set, NodeJoinCount(text, "Controller: none"));
	Free(text);
	text = NULL;

	// key makes the static key when no role needed it yet
	NodeJoinNewDir(dir_fresh, sizeof(dir_fresh), "fresh", fresh);
	n = NodeJoinStart(dir_fresh, pipe);
	bool made = NodeJoinAsk(pipe, "key", reply, NODEJOIN_REPLY);
	StrCat(answers, NODEJOIN_REPLY * 4, reply);
	bool opened = CryptoIdentityOpen(&id, fresh_w, scope);
	if (opened)
	{
		opened = CryptoIdentityPublicKey(&id, pub);
		CryptoIdentityClose(&id);
		fresh_b64 = (opened ? Base64FromBin(&size, pub, PEER_KEY_SIZE) : NULL);
	}
	NodeJoinCheck(ctx, made && fresh_b64 != NULL && InStr(reply, fresh_b64), "key makes the static key of a node whose roles never needed it, and prints its public half", "%s", reply);
	PeerKeyDelete(fresh_w);
	FreeNode(n);
	n = NULL;

	// The private half that the test put into the key storage provider is in no answer and no line of the log
	text = NodeJoinLog(dir);
	NodeJoinCheck(ctx, InStr(answers, priv_hex) == false && InStr(answers, priv_lower) == false && InStr(answers, priv_b64) == false &&
		InStr(text, priv_hex) == false && InStr(text, priv_lower) == false && InStr(text, priv_b64) == false && InStr(text, pub_b64),
		"the private half of the static key is in no answer and no line of the node log, which names the public half", "an answer or the log holds it");
	Free(text);

END:
	if (n != NULL)
	{
		FreeNode(n);
	}
	if (listener != NULL)
	{
		TransportCloseListener(listener);
	}
	TransportTlsFree(server);
	if (cert != NULL)
	{
		CryptoCertRemoveFromStore(thumbprint, NULL, 0);
		CryptoCertDeleteKey(cert);
		CryptoCertFree(cert);
	}
	PeerKeyDelete(identity_w);
	PeerKeyClose(&soft);
	if (UniIsEmptyStr(dir) == false)
	{
		NodeJoinDeleteDir(dir);
	}
	if (UniIsEmptyStr(dir_fresh) == false)
	{
		NodeJoinDeleteDir(dir_fresh);
	}
	Free(priv_b64);
	Free(pub_b64);
	Free(ctrl_b64);
	Free(fresh_b64);
	Free(answers);
	Free(reply);

	if (ctx->NumFailed == 0)
	{
		Print("NODEJOIN TEST OK\n");
	}
	else
	{
		Print("NODEJOIN TEST FAILED (%u of %u checks failed)\n", ctx->NumFailed, ctx->NumChecks);
	}
	Free(ctx);
}
