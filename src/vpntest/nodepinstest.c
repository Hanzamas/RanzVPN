// nodepinstest.c
// Named node pins test of vpntest ("nodepins" command, SDN-92 #397): the TLS fingerprints of the certificate of the Controller
// that the Controller sends a Node in its state, with no controller. A Node that pinned the fingerprint of the certificate in
// use must still reach the Controller once it serves another: the Controller sends the fingerprint of the next certificate with
// the one in use, waits until the Node acknowledged the state, and only then serves the next certificate. The first-test job
// (.github/scripts/first-test.ps1) replaces the certificate of a real Controller under the Node service of its runner; this test
// checks what needs none, with a TLS port of the loopback interface in the place of the Controller and the state that the
// Controller would send built by hand:
// - With only the fingerprint of its settings, a node that dials a certificate of another key fails the fingerprint check.
// - A state that names two fingerprints, the one of the settings and the one of that certificate, makes the node accept both: the
//   next attempt passes the check (the session then fails for want of the ALPN protocol, as the TLS port is no Controller), and
//   the Controller setting of the store holds both, the first as tlsFingerprint and all as tlsFingerprints, with the Controller
//   and its key as they were.
// - The node that starts again takes them from the store, and passes the check at once; the state that names the fingerprint of the
//   new certificate alone makes it forget the other, in memory and in the store.
// - A state that names none, and a state whose fingerprints are no 64 hex digits, change nothing.
// - An Administrator who wrote the settings of another Controller meanwhile keeps them: the fingerprints that the old Controller
//   sends are accepted until the next start and are not written over them.
// Print "NODEPINS TEST OK" only when every check passes. Needs the rights to write a machine key, as an elevated window has.

#include "testlist.h"

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

#include "Core/Control.h"
#include "Core/Crypto.h"
#include "Core/Peer.h"
#include "Core/Transport.h"

#define	NODEPINS_WAIT		20000		// What the node does is in its status within this time (ms)
#define	NODEPINS_POLL		50			// Poll interval of the status (ms)
#define	NODEPINS_SETTING	4096		// Bytes of a setting that the test reads at most

// The checks of the test
typedef struct NODEPINS_CTX
{
	UINT NumChecks;
	UINT NumFailed;
} NODEPINS_CTX;

static bool NodePinsCheck(NODEPINS_CTX *ctx, bool ok, char *what, char *fmt, ...) RANZ_PRINTF_FORMAT(4, 5);
static bool NodePinsCheck(NODEPINS_CTX *ctx, bool ok, char *what, char *fmt, ...)
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

// A new empty data directory under the temp directory of the process, with a configuration store that runs no role on one worker,
// names the identity key and holds the Controller settings of address, key and fingerprint
static void NodePinsNewDir(wchar_t *dir, UINT size, char *identity, char *address, char *key, char *fingerprint)
{
	wchar_t tmp[MAX_PATH];
	wchar_t path[MAX_PATH];
	char setting[MAX_SIZE * 2];

	UniFormat(tmp, sizeof(tmp), L"nodepins_%u", Rand32());
	ConbinePathW(dir, size, MsGetMyTempDirW(), tmp);
	MakeDirExW(dir);

	Format(setting, sizeof(setting), "{\"address\":\"%s\",\"publicKey\":\"%s\",\"tlsFingerprint\":\"%s\"}", address, key, fingerprint);

	ConbinePathW(path, sizeof(path), dir, CS_FILE_NAME);
	CONFIG_STORE *s = CsOpen(path);
	if (s != NULL)
	{
		CsSetSetting(s, NODE_SETTING_ROLES, "none");
		CsSetSetting(s, NODE_SETTING_WORKERS, "1");
		CsSetSetting(s, NODE_SETTING_IDENTITY_KEY, identity);
		CsSetSetting(s, NODE_SETTING_CONTROLLER, setting);
		CsClose(s);
	}
}

// The Controller setting that the store of dir holds, as another connection to the file reads it: "" for none
static void NodePinsStored(wchar_t *dir, char *setting, UINT size)
{
	wchar_t path[MAX_PATH];

	StrCpy(setting, size, "");
	ConbinePathW(path, sizeof(path), dir, CS_FILE_NAME);
	CONFIG_STORE *s = CsOpen(path);
	if (s != NULL)
	{
		CsGetSetting(s, NODE_SETTING_CONTROLLER, setting, size);
		CsClose(s);
	}
}

// Delete the files of the node log and of a data directory, then both directories
static void NodePinsDeleteDir(wchar_t *dir)
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
static bool NodePinsFingerprint(PCCERT_CONTEXT cert, char *fp, UINT size)
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

// Whether the last attempt of the node to dial passed the fingerprint check (pass) or failed it (not pass) with the certificate of
// the fingerprint fp, within NODEPINS_WAIT: the status says so once the attempt ended
static bool NodePinsWait(NODE *n, char *fp, bool pass)
{
	NODE_CONTROLLER_STATUS st;

	for (UINT64 end = Tick64() + NODEPINS_WAIT;Tick64() < end;SleepThread(NODEPINS_POLL))
	{
		NodeControllerGetStatus(n, &st);
		if (st.Mismatch == (pass == false) && StrCmp(st.Seen, fp) == 0)
		{
			return true;
		}
	}

	return false;
}

// Whether the node accepts exactly the num fingerprints pins, as its status says
static bool NodePinsAre(NODE *n, UINT num, char *a, char *b)
{
	NODE_CONTROLLER_STATUS st;

	NodeControllerGetStatus(n, &st);

	return (st.NumPins == num && (num < 1 || StrCmp(st.Pins[0], a) == 0) && (num < 2 || StrCmp(st.Pins[1], b) == 0));
}

// The state of a Controller that names the fingerprints a and b (none for NULL), as the control stream hands it to the node
static void NodePinsState(CONTROL_STATE *st, char *a, char *b)
{
	Zero(st, sizeof(CONTROL_STATE));

	if (a != NULL)
	{
		StrCpy(st->TlsPins[st->NumTlsPins++], sizeof(st->TlsPins[0]), a);
	}
	if (b != NULL)
	{
		StrCpy(st->TlsPins[st->NumTlsPins++], sizeof(st->TlsPins[0]), b);
	}
}

RANZ_TEST_TAGS("nodepins", nodepins_test, "core", "TLS fingerprints that the Controller sends a Node (SDN-92): accepted in place of the one of the settings, kept in the Controller setting across a restart, and not written over the settings of another Controller.");
void nodepins_test(UINT num, char **arg)
{
	NODEPINS_CTX *ctx = ZeroMalloc(sizeof(NODEPINS_CTX));
	CONTROL_STATE *state = ZeroMalloc(sizeof(CONTROL_STATE));
	TRANSPORT_TLS_CONFIG tc;
	TRANSPORT *server = NULL;
	TRANSPORT_LISTENER *listener = NULL;
	UCHAR controller_key[PEER_KEY_SIZE];
	char identity[MAX_SIZE];
	wchar_t identity_w[MAX_SIZE];
	wchar_t dir[MAX_PATH] = {0};
	char thumbprint[MAX_SIZE] = "", fingerprint[MAX_SIZE] = "", address[MAX_SIZE] = "";
	char want[MAX_SIZE * 4];
	char shown[MAX_SIZE * 2];
	char *stored = ZeroMalloc(NODEPINS_SETTING);
	char *reply = ZeroMalloc(NODEPINS_SETTING);
	char *ctrl_b64 = NULL;
	// The TLS fingerprints that no certificate of the test has
	char *old = "abababababababababababababababababababababababababababababababab";
	char *other = "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd";
	char *invalid = "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz";
	PCCERT_CONTEXT cert = NULL;
	UINT size = 0;
	NODE *n = NULL;

	Print("Node pins: the TLS fingerprints that the Controller sends a Node, with no controller\n");

	Format(identity, sizeof(identity), "Ranz nodepins %u", Rand32() & 0xFFFF);
	StrToUni(identity_w, sizeof(identity_w), identity);
	for (UINT i = 0;i < PEER_KEY_SIZE;i++)
	{
		controller_key[i] = (UCHAR)(0x90 + i);
	}
	ctrl_b64 = Base64FromBin(&size, controller_key, sizeof(controller_key));

	// A TLS port of the loopback interface with a self-signed certificate, which the settings do not name
	cert = CryptoCertCreateSelfSigned(L"CN=nodepins.test", L"nodepins.test", NULL, 30, 0);
	bool have_cert = (cert != NULL && CryptoCertThumbprintStr(cert, thumbprint, sizeof(thumbprint)) && CryptoCertAddToStore(cert, NULL, 0) && NodePinsFingerprint(cert, fingerprint, sizeof(fingerprint)));
	if (have_cert)
	{
		TransportTlsDefaultConfig(&tc, thumbprint, false);
		tc.SetGroups = false;
		server = TransportTlsServerNew(&tc);
		listener = (server != NULL ? TransportListen(server, "127.0.0.1:0") : NULL);
	}
	Format(address, sizeof(address), "127.0.0.1:%u", (listener != NULL ? (UINT)TransportTlsBoundPort(server) : 0));
	if (NodePinsCheck(ctx, listener != NULL && ctrl_b64 != NULL, "a TLS port on the loopback interface with a self-signed certificate", "the certificate or the TLS listener failed") == false)
	{
		goto END;
	}

	// The node whose settings name another fingerprint: the certificate of the TLS port fails the check
	NodePinsNewDir(dir, sizeof(dir), identity, address, ctrl_b64, old);
	n = NewNode(dir);
	NodeStart(n);
	NODE_CONTROLLER_STATUS st;
	NodeControllerGetStatus(n, &st);
	NodePinsCheck(ctx, st.Set && StrCmp(st.Address, address) == 0 && st.NumPins == 0, "the node has the Controller settings and no fingerprint of the Controller yet", "set %u, address %s, %u fingerprints", (UINT)st.Set, st.Address, st.NumPins);
	bool failed = NodePinsWait(n, fingerprint, false);
	NodePinsCheck(ctx, failed, "with only the fingerprint of its settings the node fails the check of a certificate of another key", "the status does not say it within %u ms", NODEPINS_WAIT);

	// The state that the Controller sends first: the fingerprint in use and the one of the next certificate
	NodePinsState(state, old, fingerprint);
	NodeControllerPins(n, state);
	NodePinsCheck(ctx, NodePinsAre(n, 2, old, fingerprint), "a state with two fingerprints makes the node accept both", "the node accepts another set");
	bool passed = NodePinsWait(n, fingerprint, true);
	NodePinsCheck(ctx, passed, "the next attempt passes the check of the certificate whose fingerprint came in the state", "the status does not say it within %u ms", NODEPINS_WAIT);

	// ... and writes them into the Controller setting before it acknowledges the state
	Format(want, sizeof(want), "{\"address\":\"%s\",\"publicKey\":\"%s\",\"tlsFingerprint\":\"%s\",\"tlsFingerprints\":[\"%s\",\"%s\"]}", address, ctrl_b64, old, old, fingerprint);
	NodePinsStored(dir, stored, NODEPINS_SETTING);
	NodePinsCheck(ctx, StrCmp(stored, want) == 0, "the Controller setting of the store holds both, with the Controller and its key as they were", "it holds %s, want %s", stored, want);
	NodeAdminCommand(n, "controller", reply, NODEPINS_SETTING);
	NodePinsCheck(ctx, InStr(reply, "\"tlsFingerprints\":[") && InStr(reply, fingerprint) && InStr(reply, "\"error\"") == false, "the admin pipe shows the fingerprints that the node accepts", "%s", reply);

	// The node that starts again takes them from the store
	FreeNode(n);
	n = NewNode(dir);
	NodeStart(n);
	NodePinsCheck(ctx, NodePinsAre(n, 2, old, fingerprint), "after a restart the node accepts both again, from the store", "the node accepts another set");
	passed = NodePinsWait(n, fingerprint, true);
	NodePinsCheck(ctx, passed, "after a restart the first attempt passes the check of the new certificate", "the status does not say it within %u ms", NODEPINS_WAIT);

	// The final state: the new fingerprint alone, and the old one is forgotten, in memory and in the store
	NodePinsState(state, fingerprint, NULL);
	NodeControllerPins(n, state);
	Format(want, sizeof(want), "{\"address\":\"%s\",\"publicKey\":\"%s\",\"tlsFingerprint\":\"%s\",\"tlsFingerprints\":[\"%s\"]}", address, ctrl_b64, fingerprint, fingerprint);
	NodePinsStored(dir, stored, NODEPINS_SETTING);
	NodePinsCheck(ctx, NodePinsAre(n, 1, fingerprint, NULL) && StrCmp(stored, want) == 0, "a state with the new fingerprint alone makes the node forget the old one, in memory and in the store", "the store holds %s, want %s", stored, want);
	NodeAdminCommand(n, "controller", reply, NODEPINS_SETTING);
	Format(shown, sizeof(shown), "\"tlsFingerprint\":\"%s\",\"tlsFingerprints\":[\"%s\"]}", fingerprint, fingerprint);
	NodePinsCheck(ctx, InStr(reply, shown), "the admin pipe shows the fingerprint of the certificate in use as the one of the settings, before any restart", "%s", reply);

	// A state that names none, and one whose fingerprints are no 64 hex digits, change nothing
	NodePinsState(state, NULL, NULL);
	NodeControllerPins(n, state);
	NodePinsState(state, invalid, "abcd");
	NodeControllerPins(n, state);
	NodePinsStored(dir, stored, NODEPINS_SETTING);
	NodePinsCheck(ctx, NodePinsAre(n, 1, fingerprint, NULL) && StrCmp(stored, want) == 0, "a state with no fingerprint, and one with fingerprints that are no 64 hex digits, change nothing", "the store holds %s", stored);

	// An Administrator who wrote the settings of another Controller keeps them: what the old Controller sends is not written over them
	Format(want, sizeof(want), "controller set 127.0.0.1:1 %s %s", ctrl_b64, other);
	NodeAdminCommand(n, want, reply, NODEPINS_SETTING);
	NodePinsCheck(ctx, InStr(reply, "\"error\"") == false, "controller set writes the settings of another Controller", "%s", reply);
	NodePinsState(state, fingerprint, old);
	NodeControllerPins(n, state);
	NodePinsStored(dir, stored, NODEPINS_SETTING);
	Format(want, sizeof(want), "\"address\":\"127.0.0.1:1\"");
	NodePinsCheck(ctx, NodePinsAre(n, 2, fingerprint, old) && InStr(stored, want) && InStr(stored, other) && InStr(stored, "tlsFingerprints") == false,
		"the fingerprints of the Controller that runs are accepted, and the settings of the other Controller are not written over", "the store holds %s", stored);

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
	// The static key that the node made for its overlay, which the overlay needs to dial
	PeerKeyDelete(identity_w);
	if (UniIsEmptyStr(dir) == false)
	{
		NodePinsDeleteDir(dir);
	}
	Free(ctrl_b64);
	Free(stored);
	Free(reply);
	Free(state);

	if (ctx->NumFailed == 0)
	{
		Print("NODEPINS TEST OK\n");
	}
	else
	{
		Print("NODEPINS TEST FAILED (%u of %u checks failed)\n", ctx->NumFailed, ctx->NumChecks);
	}
	Free(ctx);
}
