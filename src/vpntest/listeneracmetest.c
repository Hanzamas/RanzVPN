// listeneracmetest.c
// Named Listener ACME test of vpntest ("listeneracme" command, SDN-45 #238)
//
// The ACME source of the Listener of a node (Cedar/NodeListener.c) against a test ACME server: Pebble, the one of Let's
// Encrypt, which .github/scripts/listener-acme.ps1 runs on this machine and names on the command line: the URL of its
// directory, the PEM of the roots of its HTTPS and the TCP port where it validates the HTTP-01 challenge. The node runs
// its overlay in this process, takes its states from the test (NodeOverlayApply) and starts the ACME sidecar,
// ranz.exe acme next to vpntest. The Listener names localhost and renews 3650 days before the end, which a certificate
// of Pebble (90 days) always is within, so each run of the sidecar renews. The checks:
// - ACME issues: the first run gets the certificate into the LocalMachine\My store, the front door listens with it, and
//   the Noise session of node-c comes up over TLS 1.3 pinned to it;
// - ACME renews: the next run (NodeListenerRenew) gets a new certificate, the listeners start again with it, node-c's
//   session comes up pinned to it, a client pinned to the certificate before is refused, and that one left the store;
// - a state without a Listener stops the sidecar's thread and the listeners.
// Print "LISTENERACME TEST OK" only when every check passes. Needs administrator rights, ranz.exe next to vpntest and
// the test ACME server.

#include "testlist.h"

#include "Cedar/ConfigStore.h"
#include "Cedar/Node.h"

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
#include "Core/Crypto.h"
#include "Core/Transport.h"

#include <stdio.h>

#define	ACMETEST_WATCHDOG	420000		// The test process is aborted after this (ms)
#define	ACMETEST_BOUND		200000		// A run of the sidecar within this time (ms): its own limit is 180 s
#define	ACMETEST_POLL		100			// Poll interval of observable state (ms)
#define	ACMETEST_TIMEOUT	15000		// A Noise handshake within this time (ms)
#define	ACMETEST_VRF		1			// The VRF of the test
#define	ACMETEST_NAME		"localhost"	// The DNS name of the certificate
#define	ACMETEST_RENEW		3650		// The days of renewal: each run renews a certificate of Pebble

// The state of the test
typedef struct ACMETEST_CTX
{
	UINT NumChecks;
	UINT NumFailed;
	wchar_t Dir[MAX_PATH];				// The data directory of node-s
	NODE *Node;							// node-s
	PEER_KEY Key;						// Its static key
	UCHAR PeerScalar[PEER_KEY_SIZE];	// The static key of node-c
	UCHAR PeerPublic[PEER_KEY_SIZE];	// ... and its public half
	UINT64 Generation;					// The Generation of the last state applied
} ACMETEST_CTX;

static bool AcmeTestCheck(ACMETEST_CTX *ctx, bool ok, char *what, char *fmt, ...) RANZ_PRINTF_FORMAT(4, 5);
static bool AcmeTestCheck(ACMETEST_CTX *ctx, bool ok, char *what, char *fmt, ...)
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
static DWORD WINAPI AcmeTestWatchdog(LPVOID param)
{
	if (WaitForSingleObject((HANDLE)param, ACMETEST_WATCHDOG) == WAIT_TIMEOUT)
	{
		Print("LISTENERACME TEST FAILED (the watchdog ended it after %u ms)\n", ACMETEST_WATCHDOG);
		fflush(stdout);
		ExitProcess(1);
	}

	return 0;
}

// Apply a state of node-s to its overlay: its address in VRF 1, node-c as its peer, and the Listener l, NULL for none
static bool AcmeTestApply(ACMETEST_CTX *ctx, CONTROL_LISTENER *l)
{
	CONTROL_STATE st;
	CONTROL_PEER peer;
	UCHAR self[4] = {100, 64, 0, 1};
	UCHAR other[4] = {100, 64, 0, 2};

	Zero(&st, sizeof(st));
	Zero(&peer, sizeof(peer));

	st.Generation = ++ctx->Generation;
	StrCpy(st.Name, sizeof(st.Name), "node-s");
	StrCpy(st.Addresses[0].Network, sizeof(st.Addresses[0].Network), "default");
	st.Addresses[0].VrfId = ACMETEST_VRF;
	Copy(st.Addresses[0].Address, self, 4);
	st.Addresses[0].AddressSize = 4;
	st.Addresses[0].Length = 10;
	st.NumAddresses = 1;

	StrCpy(peer.Name, sizeof(peer.Name), "node-c");
	Copy(peer.Key, ctx->PeerPublic, PEER_KEY_SIZE);
	peer.NumVrfs = 1;
	peer.VrfIds[0] = ACMETEST_VRF;
	StrCpy(peer.Addresses[0].Network, sizeof(peer.Addresses[0].Network), "default");
	peer.Addresses[0].VrfId = ACMETEST_VRF;
	Copy(peer.Addresses[0].Address, other, 4);
	peer.Addresses[0].AddressSize = 4;
	peer.Addresses[0].Length = 10;
	peer.NumAddresses = 1;
	st.Peers = &peer;
	st.NumPeers = 1;

	st.Listener = l;

	return NodeOverlayApply(ctx->Node, &st);
}

// Whether the overlay of node-s has links sessions within ACMETEST_TIMEOUT
static bool AcmeTestWaitLinks(ACMETEST_CTX *ctx, UINT links)
{
	for (UINT64 end = Tick64() + ACMETEST_TIMEOUT;Tick64() < end;SleepThread(ACMETEST_POLL))
	{
		NODE_OVERLAY_STATUS st;

		NodeOverlayGetStatus(ctx->Node, &st);
		if (st.NumLinks == links)
		{
			return true;
		}
	}

	return false;
}

// node-c: dial the front door of node-s over TLS pinned to thumbprint and open the Noise session with the static key of
// node-s; whether the overlay of node-s took it and the handshake was TLS 1.3. The session closes again.
static bool AcmeTestSession(ACMETEST_CTX *ctx, char *thumbprint, UINT port)
{
	TRANSPORT_TLS_CONFIG tc;
	TRANSPORT_TLS_INFO info;
	NOISE_SESSION_CONFIG cfg;
	char address[MAX_SIZE];
	bool ok = false;

	TransportTlsDefaultConfig(&tc, thumbprint, false);
	tc.SetGroups = false;
	TRANSPORT *t = TransportTlsClientNew(&tc);
	if (t == NULL)
	{
		return false;
	}

	Format(address, sizeof(address), "127.0.0.1:%u", port);
	TRANSPORT_STREAM *s = TransportDial(t, address, NULL);
	if (s != NULL)
	{
		TRANSPORT_NOISE *n = ZeroMalloc(sizeof(TRANSPORT_NOISE));

		Zero(&info, sizeof(info));
		TransportTlsLastHandshake(t, &info);
		Zero(&cfg, sizeof(cfg));
		cfg.Suite = NOISE_SUITE_IK;
		cfg.StaticKey = ctx->PeerScalar;
		cfg.RemoteStatic = ctx->Key.Public;
		if (TransportNoiseConnect(n, s, &cfg, ACMETEST_TIMEOUT))
		{
			ok = AcmeTestWaitLinks(ctx, 1) && info.Version == TRANSPORT_TLS_13;
			TransportNoiseClose(n);
			ok = AcmeTestWaitLinks(ctx, 0) && ok;
		}
		Free(n);
	}

	TransportTlsFree(t);

	return ok;
}

// The status of the Listener of node-s once the sidecar gave issued certificates, within ACMETEST_BOUND
static bool AcmeTestWaitIssued(ACMETEST_CTX *ctx, UINT64 issued, NODE_LISTENER_STATUS *st)
{
	for (UINT64 end = Tick64() + ACMETEST_BOUND;Tick64() < end;SleepThread(ACMETEST_POLL))
	{
		NodeListenerGetStatus(ctx->Node, st);
		if (st->AcmeIssued >= issued && st->Running)
		{
			return true;
		}
	}

	return false;
}

// Delete the files of a directory and of the directories in it, then the directory
static void AcmeTestDeleteDir(wchar_t *dir)
{
	DIRLIST *d = EnumDirW(dir);

	for (UINT i = 0;d != NULL && i < d->NumFiles;i++)
	{
		DIRENT *e = d->File[i];
		wchar_t path[MAX_PATH];

		ConbinePathW(path, sizeof(path), dir, e->FileNameW);
		if (e->Folder)
		{
			AcmeTestDeleteDir(path);
		}
		else
		{
			FileDeleteW(path);
		}
	}

	FreeDir(d);
	DeleteDirW(dir);
}

// The steps of the test on node-s, whose overlay runs
static void AcmeTestSteps(ACMETEST_CTX *ctx, char *directory, char *ca, UINT http_port)
{
	CONTROL_LISTENER l;
	NODE_LISTENER_STATUS st;
	char first[MAX_SIZE];

	Zero(&l, sizeof(l));
	StrCpy(l.Name, sizeof(l.Name), "edge");
	l.Source = CONTROL_CERT_ACME;
	StrCpy(l.Directory, sizeof(l.Directory), directory);
	StrCpy(l.Names[0], sizeof(l.Names[0]), ACMETEST_NAME);
	l.NumNames = 1;
	l.HttpPort = http_port;
	StrCpy(l.CaFile, sizeof(l.CaFile), ca);
	l.RenewDays = ACMETEST_RENEW;

	// ACME issues
	Print("[ACME issues the certificate of the Listener]\n");
	bool applied = AcmeTestApply(ctx, &l);
	bool issued = applied && AcmeTestWaitIssued(ctx, 1, &st);
	AcmeTestCheck(ctx, issued && st.Source == CONTROL_CERT_ACME && StrLen(st.Thumbprint) == 2 * CRYPTO_THUMBPRINT_SIZE,
		"the sidecar gets the certificate from the ACME service, and the front door listens with it", "applied %u, issued %I64u, runs %I64u, running %u, certificate %s, error %s",
		(UINT)applied, st.AcmeIssued, st.AcmeRuns, (UINT)st.Running, st.Thumbprint, st.Error);
	StrCpy(first, sizeof(first), st.Thumbprint);
	if (issued == false)
	{
		return;
	}

	PCCERT_CONTEXT cert = CryptoCertFindByThumbprint(first, NULL, CRYPTO_MACHINE);
	AcmeTestCheck(ctx, cert != NULL && CryptoCertHasKspKey(cert), "the certificate is in the LocalMachine\\My store with its key in the key storage provider",
		"the store does not hold it with its key");
	CryptoCertFree(cert);
	AcmeTestCheck(ctx, AcmeTestSession(ctx, first, st.Port), "node-c's Noise session comes up over TLS 1.3 pinned to the certificate of ACME", "no session");

	// ACME renews
	Print("[ACME renews the certificate of the Listener]\n");
	NodeListenerRenew(ctx->Node);
	bool renewed = AcmeTestWaitIssued(ctx, 2, &st);
	AcmeTestCheck(ctx, renewed && StrLen(st.Thumbprint) == 2 * CRYPTO_THUMBPRINT_SIZE && StrCmp(st.Thumbprint, first) != 0,
		"the next run renews the certificate, and the front door listens with the new one", "issued %I64u, runs %I64u, certificate %s, before %s, error %s", st.AcmeIssued,
		st.AcmeRuns, st.Thumbprint, first, st.Error);
	if (renewed)
	{
		AcmeTestCheck(ctx, AcmeTestSession(ctx, st.Thumbprint, st.Port), "node-c's session comes up pinned to the renewed certificate", "no session");
		AcmeTestCheck(ctx, AcmeTestSession(ctx, first, st.Port) == false, "a client pinned to the certificate before is refused", "it got a session");
		cert = CryptoCertFindByThumbprint(first, NULL, CRYPTO_MACHINE);
		AcmeTestCheck(ctx, cert == NULL, "the certificate before left the store", "the store still holds it");
		CryptoCertFree(cert);
	}

	// No Listener: the sidecar's thread and the listeners stop; the certificate of ACME goes from the store here
	char last[MAX_SIZE];
	StrCpy(last, sizeof(last), st.Thumbprint);
	applied = AcmeTestApply(ctx, NULL);
	NodeListenerGetStatus(ctx->Node, &st);
	AcmeTestCheck(ctx, applied && st.Running == false && st.Port == 0, "a state without a Listener stops the listeners", "running %u, port %u", (UINT)st.Running, st.Port);

	cert = CryptoCertFindByThumbprint(last, NULL, CRYPTO_MACHINE);
	if (cert != NULL)
	{
		CryptoCertDeleteKey(cert);
		CryptoCertFree(cert);
		CryptoCertRemoveFromStore(last, NULL, CRYPTO_MACHINE);
	}
}

RANZ_TEST("listeneracme", listeneracme_test, "The ACME source of the Listener of a node (SDN-45): ranz.exe acme gets the certificate from a test ACME server and renews it, and the front door listens with it; arguments: the directory URL, the PEM of its roots and its HTTP-01 port (.github/scripts/listener-acme.ps1 runs it).");
void listeneracme_test(UINT num, char **arg)
{
	ACMETEST_CTX *ctx = ZeroMalloc(sizeof(ACMETEST_CTX));
	HANDLE done = CreateEventW(NULL, TRUE, FALSE, NULL);
	HANDLE watchdog = (done != NULL ? CreateThread(NULL, 0, AcmeTestWatchdog, done, 0, NULL) : NULL);
	TRANSPORT *loopback = TransportLoopbackNew("loopback", 0, false);
	NODE_OVERLAY_CONFIG cfg;
	UCHAR scalar[PEER_KEY_SIZE];
	wchar_t tmp[MAX_PATH];
	wchar_t path[MAX_PATH];

	Print("Listener ACME test: the certificate of a Listener from a test ACME server, issued and renewed\n");

	bool ok = AcmeTestCheck(ctx, num >= 3, "the test ACME server is named: its directory, the PEM of its roots and its HTTP-01 port",
		"usage: vpntest listeneracme <directory URL> <roots PEM> <HTTP-01 port>");
	ok = ok && loopback != NULL && CryptoInit();
	for (UINT i = 0;i < PEER_KEY_SIZE;i++)
	{
		scalar[i] = (UCHAR)(0x41 + i);
		ctx->PeerScalar[i] = (UCHAR)(0x81 + i);
	}
	ok = ok && PeerKeyFromScalar(&ctx->Key, scalar) && CryptoX25519PublicKey(ctx->PeerPublic, ctx->PeerScalar);
	Zero(scalar, sizeof(scalar));

	if (ok)
	{
		UniFormat(tmp, sizeof(tmp), L"listeneracmetest_%u", Rand32());
		ConbinePathW(ctx->Dir, sizeof(ctx->Dir), MsGetMyTempDirW(), tmp);
		MakeDirExW(ctx->Dir);
		ConbinePathW(path, sizeof(path), ctx->Dir, CS_FILE_NAME);
		CONFIG_STORE *s = CsOpen(path);
		if (s != NULL)
		{
			CsSetSetting(s, NODE_SETTING_ROLES, "none");
			CsSetSetting(s, NODE_SETTING_WORKERS, "1");
			CsClose(s);
		}

		ctx->Node = NewNode(ctx->Dir);
		NodeStart(ctx->Node);

		Zero(&cfg, sizeof(cfg));
		cfg.Data = loopback;
		cfg.Key = &ctx->Key;
		if (AcmeTestCheck(ctx, NodeOverlayStart(ctx->Node, &cfg), "the overlay of node-s runs without a control stream", "NodeOverlayStart failed"))
		{
			AcmeTestSteps(ctx, arg[0], arg[1], ToInt(arg[2]));
			NodeOverlayStop(ctx->Node);
		}

		NodeStop(ctx->Node);
		FreeNode(ctx->Node);
		ctx->Node = NULL;
		AcmeTestDeleteDir(ctx->Dir);
	}

	PeerKeyClose(&ctx->Key);
	Zero(ctx->PeerScalar, sizeof(ctx->PeerScalar));
	TransportLoopbackFree(loopback);

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
		Print("LISTENERACME TEST OK\n");
	}
	else
	{
		Print("LISTENERACME TEST FAILED (%u of %u checks failed)\n", ctx->NumFailed, ctx->NumChecks);
	}

	Free(ctx);
}
