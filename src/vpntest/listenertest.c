// listenertest.c
// Named Listener test of vpntest ("listener" command, SDN-45 #238)
//
// The Listener of a node (Cedar/NodeListener.c): where a node listens, from the Listener of its desired state. The
// node runs its overlay in this process without a control stream and takes its states from the test
// (NodeOverlayApply), as the control stream gives them: its name node-s, an address in VRF 1, its peer node-c, and the
// Listener of the step. The Listeners of the test name port 0, which the node binds as a port that the system picks: a
// test port of every address, never 443. node-c is a client of the new protocol in this process: it dials the port of
// the front door over TLS, or QUIC, pinned to the certificate of the Listener, and opens a Noise session with the static
// key of node-s, which the overlay of node-s takes as the session of its peer. The checks:
// - ports and certificates apply: a Listener whose certificate is in the LocalMachine\My store (KSP) starts the front
//   door on TCP and QUIC on UDP, where msquic.dll is present, with that certificate, and node-c's session comes up over
//   each; a Listener whose certificate is a PKCS #12 file with the file of its password takes the place of the first:
//   the node imports the file and listens with its certificate, and a client pinned to the certificate before is
//   refused; a state without a Listener stops the listeners; a certificate that the store does not hold starts nothing
//   and says why;
// - the TLS policy of the new protocol: a client that offers TLS 1.3 gets TLS 1.3, and one that offers TLS 1.2 only is
//   refused.
// Print "LISTENER TEST OK" only when every check passes. Needs administrator rights: the LocalMachine\My store and the
// key storage provider of the machine.

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

#include <ncrypt.h>

#include <stdio.h>

#define	LISTENERTEST_WATCHDOG	240000		// The test process is aborted after this (ms)
#define	LISTENERTEST_BOUND		20000		// A bounded wait on observable state (ms)
#define	LISTENERTEST_POLL		20			// Poll interval of observable state (ms)
#define	LISTENERTEST_TIMEOUT	15000		// A Noise handshake within this time (ms)
#define	LISTENERTEST_VRF		1			// The VRF of the test
#define	LISTENERTEST_NODE		"node-s"	// The node that listens
#define	LISTENERTEST_PEER		"node-c"	// Its peer, the client of the new protocol
#define	LISTENERTEST_CN			L"CN=localhost"		// The subject of the certificates
#define	LISTENERTEST_SAN		L"localhost"		// ... and their subject alternative name
#define	LISTENERTEST_PFX_KEY	L"Ranz-ListenerTest-Pfx"	// The exportable key of the certificate that goes into the PKCS #12 file
#define	LISTENERTEST_PASSWORD	"Ranz-ListenerTest-1"		// The password of the file
#define	LISTENERTEST_OTHER		"00112233445566778899AABBCCDDEEFF00112233"	// A thumbprint that no certificate of the store has

// The state of the test
typedef struct LISTENERTEST_CTX
{
	UINT NumChecks;
	UINT NumFailed;
	wchar_t Dir[MAX_PATH];				// The data directory of node-s
	NODE *Node;							// node-s
	PEER_KEY Key;						// Its static key
	UCHAR PeerScalar[PEER_KEY_SIZE];	// The static key of node-c
	UCHAR PeerPublic[PEER_KEY_SIZE];	// ... and its public half
	UINT64 Generation;					// The Generation of the last state applied
} LISTENERTEST_CTX;

static bool ListenerTestCheck(LISTENERTEST_CTX *ctx, bool ok, char *what, char *fmt, ...) RANZ_PRINTF_FORMAT(4, 5);
static bool ListenerTestCheck(LISTENERTEST_CTX *ctx, bool ok, char *what, char *fmt, ...)
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
static DWORD WINAPI ListenerTestWatchdog(LPVOID param)
{
	if (WaitForSingleObject((HANDLE)param, LISTENERTEST_WATCHDOG) == WAIT_TIMEOUT)
	{
		Print("LISTENER TEST FAILED (the watchdog ended it after %u ms)\n", LISTENERTEST_WATCHDOG);
		fflush(stdout);
		ExitProcess(1);
	}

	return 0;
}

// Apply a state of node-s to its overlay, as the control stream does: its address in VRF 1, node-c as its peer, and the
// Listener l, NULL for none
static bool ListenerTestApply(LISTENERTEST_CTX *ctx, CONTROL_LISTENER *l)
{
	CONTROL_STATE st;
	CONTROL_PEER peer;
	UCHAR self[4] = {100, 64, 0, 1};
	UCHAR other[4] = {100, 64, 0, 2};

	Zero(&st, sizeof(st));
	Zero(&peer, sizeof(peer));

	st.Generation = ++ctx->Generation;
	StrCpy(st.Name, sizeof(st.Name), LISTENERTEST_NODE);
	StrCpy(st.Addresses[0].Network, sizeof(st.Addresses[0].Network), "default");
	st.Addresses[0].VrfId = LISTENERTEST_VRF;
	Copy(st.Addresses[0].Address, self, 4);
	st.Addresses[0].AddressSize = 4;
	st.Addresses[0].Length = 10;
	st.NumAddresses = 1;

	StrCpy(peer.Name, sizeof(peer.Name), LISTENERTEST_PEER);
	Copy(peer.Key, ctx->PeerPublic, PEER_KEY_SIZE);
	peer.NumVrfs = 1;
	peer.VrfIds[0] = LISTENERTEST_VRF;
	StrCpy(peer.Addresses[0].Network, sizeof(peer.Addresses[0].Network), "default");
	peer.Addresses[0].VrfId = LISTENERTEST_VRF;
	Copy(peer.Addresses[0].Address, other, 4);
	peer.Addresses[0].AddressSize = 4;
	peer.Addresses[0].Length = 10;
	peer.NumAddresses = 1;
	st.Peers = &peer;
	st.NumPeers = 1;

	st.Listener = l;

	return NodeOverlayApply(ctx->Node, &st);
}

// A Listener of the test: port 0 for TCP and UDP, which the node binds as ports that the system picks
static void ListenerTestListener(CONTROL_LISTENER *l, char *name, UINT source)
{
	Zero(l, sizeof(CONTROL_LISTENER));
	StrCpy(l->Name, sizeof(l->Name), name);
	l->Source = source;
}

// The number of Noise sessions of the overlay of node-s
static UINT ListenerTestLinks(LISTENERTEST_CTX *ctx)
{
	NODE_OVERLAY_STATUS st;

	NodeOverlayGetStatus(ctx->Node, &st);

	return st.NumLinks;
}

// Whether the overlay of node-s has links sessions within LISTENERTEST_BOUND
static bool ListenerTestWaitLinks(LISTENERTEST_CTX *ctx, UINT links)
{
	for (UINT64 end = Tick64() + LISTENERTEST_BOUND;Tick64() < end;SleepThread(LISTENERTEST_POLL))
	{
		if (ListenerTestLinks(ctx) == links)
		{
			return true;
		}
	}

	return false;
}

// node-c: dial the port of node-s over the client transport t and open the Noise session with the static key of node-s;
// whether the overlay of node-s took it as the session of its peer. The session closes again, and the overlay sees it
// go. info, which may be NULL, gets what the TLS handshake gave.
static bool ListenerTestSession(LISTENERTEST_CTX *ctx, TRANSPORT *t, UINT port, TRANSPORT_TLS_INFO *info)
{
	char address[MAX_SIZE];
	NOISE_SESSION_CONFIG cfg;
	bool ok = false;

	Format(address, sizeof(address), "127.0.0.1:%u", port);
	TRANSPORT_STREAM *s = TransportDial(t, address, NULL);
	if (s == NULL)
	{
		return false;
	}

	if (info != NULL)
	{
		Zero(info, sizeof(TRANSPORT_TLS_INFO));
		TransportTlsLastHandshake(t, info);
	}

	TRANSPORT_NOISE *n = ZeroMalloc(sizeof(TRANSPORT_NOISE));
	Zero(&cfg, sizeof(cfg));
	cfg.Suite = NOISE_SUITE_IK;
	cfg.StaticKey = ctx->PeerScalar;
	cfg.RemoteStatic = ctx->Key.Public;
	if (TransportNoiseConnect(n, s, &cfg, LISTENERTEST_TIMEOUT))
	{
		ok = ListenerTestWaitLinks(ctx, 1);
		TransportNoiseClose(n);
		ok = ListenerTestWaitLinks(ctx, 0) && ok;
	}
	Free(n);

	return ok;
}

// Whether a TLS client pinned to thumbprint, of the versions given (TRANSPORT_TLS_*), completes a TLS handshake on port
// of node-s: a stream that dials is closed again at once
static bool ListenerTestDials(char *thumbprint, UINT versions, UINT port)
{
	TRANSPORT_TLS_CONFIG cfg;
	char address[MAX_SIZE];

	TransportTlsDefaultConfig(&cfg, thumbprint, false);
	cfg.Versions = versions;
	cfg.SetGroups = false;
	TRANSPORT *t = TransportTlsClientNew(&cfg);
	if (t == NULL)
	{
		return false;
	}

	Format(address, sizeof(address), "127.0.0.1:%u", port);
	TRANSPORT_STREAM *s = TransportDial(t, address, NULL);
	TransportClose(s);
	TransportTlsFree(t);

	return (s != NULL);
}

// What the Listener of node-s reports
static void ListenerTestStatus(LISTENERTEST_CTX *ctx, NODE_LISTENER_STATUS *st)
{
	NodeListenerGetStatus(ctx->Node, st);
}

// A PKCS #12 file as an operator's tool writes one, into path, with the file of its password beside it, into
// password_path: a self-signed ECDSA P-256 certificate whose key may be exported, which goes again once it is in the
// file. The thumbprint of the certificate into thumbprint; false when the file cannot be made.
static bool ListenerTestPfx(wchar_t *path, wchar_t *password_path, char *thumbprint, UINT size)
{
	NCRYPT_PROV_HANDLE prov = 0;
	NCRYPT_KEY_HANDLE key = 0;
	DWORD policy = NCRYPT_ALLOW_EXPORT_FLAG | NCRYPT_ALLOW_PLAINTEXT_EXPORT_FLAG;
	CERT_NAME_BLOB subject;
	CRYPT_KEY_PROV_INFO info;
	CRYPT_ALGORITHM_IDENTIFIER alg;
	CRYPT_DATA_BLOB pfx;
	BYTE name[256];
	wchar_t password[MAX_SIZE];
	PCCERT_CONTEXT cert = NULL;
	bool ok = false;

	StrCpy(thumbprint, size, "");
	StrToUni(password, sizeof(password), LISTENERTEST_PASSWORD);

	if (NCryptOpenStorageProvider(&prov, MS_KEY_STORAGE_PROVIDER, 0) != ERROR_SUCCESS)
	{
		return false;
	}

	subject.cbData = sizeof(name);
	subject.pbData = name;
	if (NCryptCreatePersistedKey(prov, &key, NCRYPT_ECDSA_P256_ALGORITHM, LISTENERTEST_PFX_KEY, 0, NCRYPT_OVERWRITE_KEY_FLAG) == ERROR_SUCCESS &&
		NCryptSetProperty(key, NCRYPT_EXPORT_POLICY_PROPERTY, (PBYTE)&policy, sizeof(policy), NCRYPT_PERSIST_FLAG) == ERROR_SUCCESS &&
		NCryptFinalizeKey(key, NCRYPT_SILENT_FLAG) == ERROR_SUCCESS &&
		CertStrToNameW(X509_ASN_ENCODING, LISTENERTEST_CN, CERT_X500_NAME_STR, NULL, name, &subject.cbData, NULL))
	{
		Zero(&info, sizeof(info));
		info.pwszContainerName = LISTENERTEST_PFX_KEY;
		info.pwszProvName = (LPWSTR)MS_KEY_STORAGE_PROVIDER;
		Zero(&alg, sizeof(alg));
		alg.pszObjId = szOID_ECDSA_SHA256;
		cert = CertCreateSelfSignCertificate(key, &subject, 0, &info, &alg, NULL, NULL, NULL);
	}

	if (cert != NULL && CryptoCertThumbprintStr(cert, thumbprint, size))
	{
		HCERTSTORE store = CertOpenStore(CERT_STORE_PROV_MEMORY, 0, 0, 0, NULL);

		Zero(&pfx, sizeof(pfx));
		if (store != NULL && CertAddCertificateContextToStore(store, cert, CERT_STORE_ADD_ALWAYS, NULL) &&
			PFXExportCertStoreEx(store, &pfx, password, NULL, EXPORT_PRIVATE_KEYS | REPORT_NOT_ABLE_TO_EXPORT_PRIVATE_KEY) && pfx.cbData != 0)
		{
			pfx.pbData = ZeroMalloc(pfx.cbData);
			if (PFXExportCertStoreEx(store, &pfx, password, NULL, EXPORT_PRIVATE_KEYS | REPORT_NOT_ABLE_TO_EXPORT_PRIVATE_KEY))
			{
				BUF *file = NewBufFromMemory(pfx.pbData, pfx.cbData);
				BUF *pass = NewBuf();

				WriteBufStr(pass, LISTENERTEST_PASSWORD);
				WriteBufStr(pass, "\r\n");
				ok = DumpBufW(file, path) && DumpBufW(pass, password_path);
				FreeBuf(file);
				FreeBuf(pass);
			}
			Free(pfx.pbData);
		}
		if (store != NULL)
		{
			CertCloseStore(store, 0);
		}
	}
	if (cert != NULL)
	{
		CertFreeCertificateContext(cert);
	}

	// The key of the export goes; the node makes a key of its own when it imports the file
	if (key != 0 && NCryptDeleteKey(key, NCRYPT_SILENT_FLAG) != ERROR_SUCCESS)
	{
		NCryptFreeObject(key);
	}
	NCryptFreeObject(prov);
	Zero(password, sizeof(password));

	return ok;
}

// Take a certificate out of the LocalMachine\My store, with its key
static void ListenerTestRemove(char *thumbprint)
{
	PCCERT_CONTEXT cert = (IsEmptyStr(thumbprint) ? NULL : CryptoCertFindByThumbprint(thumbprint, NULL, CRYPTO_MACHINE));

	if (cert != NULL)
	{
		CryptoCertDeleteKey(cert);
		CryptoCertFree(cert);
		CryptoCertRemoveFromStore(thumbprint, NULL, CRYPTO_MACHINE);
	}
}

// Delete the files of a directory, then the directory
static void ListenerTestDeleteDir(wchar_t *dir)
{
	DIRLIST *d = EnumDirW(dir);

	for (UINT i = 0;d != NULL && i < d->NumFiles;i++)
	{
		DIRENT *e = d->File[i];
		wchar_t path[MAX_PATH];

		ConbinePathW(path, sizeof(path), dir, e->FileNameW);
		if (e->Folder)
		{
			ListenerTestDeleteDir(path);
		}
		else
		{
			FileDeleteW(path);
		}
	}

	FreeDir(d);
	DeleteDirW(dir);
}

// The steps of the test on node-s, whose overlay runs; cert is the thumbprint of the certificate of the store
static void ListenerTestSteps(LISTENERTEST_CTX *ctx, char *cert)
{
	CONTROL_LISTENER l;
	NODE_LISTENER_STATUS st;
	TRANSPORT_TLS_INFO info;
	TRANSPORT_TLS_CONFIG tls_cfg;
	TRANSPORT_QUIC_CONFIG quic_cfg;
	wchar_t tmp[MAX_PATH];
	wchar_t pfx_path[MAX_PATH];
	wchar_t password_path[MAX_PATH];
	char pfx_thumbprint[MAX_SIZE];

	// The certificate of the store, by its thumbprint
	Print("[a Listener whose certificate is in the LocalMachine\\My store]\n");
	ListenerTestListener(&l, "edge", CONTROL_CERT_KSP);
	StrCpy(l.Thumbprint, sizeof(l.Thumbprint), cert);
	bool applied = ListenerTestApply(ctx, &l);
	ListenerTestStatus(ctx, &st);
	ListenerTestCheck(ctx, applied && st.Running && st.Port != 0 && StrCmp(st.Thumbprint, cert) == 0 && st.Source == CONTROL_CERT_KSP && StrCmp(st.Name, "edge") == 0,
		"the front door listens on its port with the certificate of the store", "applied %u, running %u, port %u, certificate %s, error %s", (UINT)applied,
		(UINT)st.Running, st.Port, st.Thumbprint, st.Error);
	UINT ksp_port = st.Port;

	TransportTlsDefaultConfig(&tls_cfg, cert, false);
	tls_cfg.SetGroups = false;
	TRANSPORT *tls = TransportTlsClientNew(&tls_cfg);
	bool up = (tls != NULL && ListenerTestSession(ctx, tls, ksp_port, &info));
	ListenerTestCheck(ctx, up && info.Version == TRANSPORT_TLS_13,
		"node-c's Noise session comes up over TLS 1.3 through the front door, and the overlay takes it as its peer's", "up %u, TLS version 0x%x", (UINT)up, info.Version);
	TransportTlsFree(tls);

	ListenerTestCheck(ctx, ListenerTestDials(cert, TRANSPORT_TLS_12, ksp_port) == false,
		"a client that offers TLS 1.2 only is refused: the new protocol takes TLS 1.3 only", "the TLS 1.2 handshake completed");
	ListenerTestCheck(ctx, ListenerTestDials(LISTENERTEST_OTHER, TRANSPORT_TLS_13, ksp_port) == false,
		"a client that pinned another certificate is refused", "the handshake completed");

	if (TransportQuicAvailable())
	{
		TransportQuicDefaultConfig(&quic_cfg, cert, false);
		TRANSPORT *quic = TransportQuicClientNew(&quic_cfg);
		ListenerTestStatus(ctx, &st);
		up = (quic != NULL && st.QuicPort != 0 && ListenerTestSession(ctx, quic, st.QuicPort, NULL));
		ListenerTestCheck(ctx, up, "QUIC listens on its UDP port with the same certificate, and node-c's session comes up over it", "QUIC port %u, up %u",
			st.QuicPort, (UINT)up);
		TransportQuicFree(quic);
	}
	else
	{
		Print("  msquic.dll is not next to vpntest: QUIC is not checked\n");
	}

	// The PKCS #12 file and the file of its password
	Print("[a Listener whose certificate is a PKCS #12 file on the node]\n");
	UniFormat(tmp, sizeof(tmp), L"listenertest_%u.pfx", Rand32());
	ConbinePathW(pfx_path, sizeof(pfx_path), MsGetMyTempDirW(), tmp);
	UniFormat(password_path, sizeof(password_path), L"%s.txt", pfx_path);
	bool made = ListenerTestPfx(pfx_path, password_path, pfx_thumbprint, sizeof(pfx_thumbprint));
	if (ListenerTestCheck(ctx, made, "a PKCS #12 file and the file of its password are made", "the file could not be made"))
	{
		ListenerTestListener(&l, "edge", CONTROL_CERT_FILE);
		UniToUtf8(l.Path, sizeof(l.Path), pfx_path);
		UniToUtf8(l.PasswordFile, sizeof(l.PasswordFile), password_path);
		applied = ListenerTestApply(ctx, &l);
		ListenerTestStatus(ctx, &st);
		ListenerTestCheck(ctx, applied && st.Running && st.Port != 0 && StrCmp(st.Thumbprint, pfx_thumbprint) == 0 && st.Source == CONTROL_CERT_FILE,
			"the node imports the file and the front door listens with its certificate", "running %u, port %u, certificate %s, want %s, error %s", (UINT)st.Running,
			st.Port, st.Thumbprint, pfx_thumbprint, st.Error);

		TransportTlsDefaultConfig(&tls_cfg, pfx_thumbprint, false);
		tls_cfg.SetGroups = false;
		tls = TransportTlsClientNew(&tls_cfg);
		up = (tls != NULL && ListenerTestSession(ctx, tls, st.Port, &info));
		ListenerTestCheck(ctx, up && info.Version == TRANSPORT_TLS_13, "node-c's session comes up with the certificate of the file", "up %u, TLS version 0x%x", (UINT)up,
			info.Version);
		TransportTlsFree(tls);
		ListenerTestCheck(ctx, ListenerTestDials(cert, TRANSPORT_TLS_13, ksp_port) == false && ListenerTestDials(cert, TRANSPORT_TLS_13, st.Port) == false,
			"a client pinned to the certificate before is refused: the listeners of the Listener before are gone", "a handshake completed");
		UINT file_port = st.Port;

		// No Listener: nothing listens
		Print("[a state without a Listener]\n");
		applied = ListenerTestApply(ctx, NULL);
		ListenerTestStatus(ctx, &st);
		ListenerTestCheck(ctx, applied && st.Running == false && st.Port == 0 && IsEmptyStr(st.Name) && ListenerTestDials(pfx_thumbprint, TRANSPORT_TLS_13, file_port) == false,
			"the listeners stop: the node listens on no port of its own", "running %u, port %u, name %s", (UINT)st.Running, st.Port, st.Name);
	}

	ListenerTestRemove(pfx_thumbprint);
	FileDeleteW(pfx_path);
	FileDeleteW(password_path);

	// A certificate that the store does not hold
	Print("[a Listener whose certificate the store does not hold]\n");
	ListenerTestListener(&l, "missing", CONTROL_CERT_KSP);
	StrCpy(l.Thumbprint, sizeof(l.Thumbprint), LISTENERTEST_OTHER);
	applied = ListenerTestApply(ctx, &l);
	ListenerTestStatus(ctx, &st);
	ListenerTestCheck(ctx, applied && st.Running == false && st.Port == 0 && InStr(st.Error, "is not in the LocalMachine\\My store"),
		"the Listener starts nothing and says why", "running %u, error %s", (UINT)st.Running, st.Error);
}

RANZ_TEST("listener", listener_test, "The Listener of a node (SDN-45): the front door and QUIC start on the ports of the Listener of the desired state with the certificate of the store or of a PKCS #12 file, a client of the new protocol gets TLS 1.3 and one of TLS 1.2 only is refused, and a state without a Listener stops them (administrator rights).");
void listener_test(UINT num, char **arg)
{
	LISTENERTEST_CTX *ctx = ZeroMalloc(sizeof(LISTENERTEST_CTX));
	HANDLE done = CreateEventW(NULL, TRUE, FALSE, NULL);
	HANDLE watchdog = (done != NULL ? CreateThread(NULL, 0, ListenerTestWatchdog, done, 0, NULL) : NULL);
	TRANSPORT *loopback = TransportLoopbackNew("loopback", 0, false);
	NODE_OVERLAY_CONFIG cfg;
	UCHAR scalar[PEER_KEY_SIZE];
	wchar_t tmp[MAX_PATH];
	wchar_t path[MAX_PATH];
	char cert_thumbprint[MAX_SIZE];

	Print("Listener test: where a node listens, from the Listener of its desired state, with the certificate of its source\n");

	StrCpy(cert_thumbprint, sizeof(cert_thumbprint), "");

	// The keys of node-s and node-c
	bool ok = (loopback != NULL && CryptoInit());
	for (UINT i = 0;i < PEER_KEY_SIZE;i++)
	{
		scalar[i] = (UCHAR)(0x31 + i);
		ctx->PeerScalar[i] = (UCHAR)(0x71 + i);
	}
	ok = ok && PeerKeyFromScalar(&ctx->Key, scalar) && CryptoX25519PublicKey(ctx->PeerPublic, ctx->PeerScalar);
	Zero(scalar, sizeof(scalar));

	// The certificate of the store: a self-signed ECDSA P-256 certificate of the LocalMachine\My store, its key in the KSP
	PCCERT_CONTEXT cert = (ok ? CryptoCertCreateSelfSigned(LISTENERTEST_CN, LISTENERTEST_SAN, NULL, 30, CRYPTO_MACHINE) : NULL);
	bool have = (cert != NULL && CryptoCertThumbprintStr(cert, cert_thumbprint, sizeof(cert_thumbprint)) && CryptoCertAddToStore(cert, NULL, CRYPTO_MACHINE));
	ListenerTestCheck(ctx, have, "a certificate of the LocalMachine\\My store with its key in the key storage provider of the machine", "the certificate could not be made");

	if (have)
	{
		// node-s, with the overlay that applies the states of the test
		UniFormat(tmp, sizeof(tmp), L"listenertest_%u", Rand32());
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
		if (ListenerTestCheck(ctx, NodeOverlayStart(ctx->Node, &cfg), "the overlay of node-s runs without a control stream", "NodeOverlayStart failed"))
		{
			ListenerTestSteps(ctx, cert_thumbprint);
			NodeOverlayStop(ctx->Node);
		}

		NodeStop(ctx->Node);
		FreeNode(ctx->Node);
		ctx->Node = NULL;
		ListenerTestDeleteDir(ctx->Dir);
	}

	if (cert != NULL)
	{
		CryptoCertRemoveFromStore(cert_thumbprint, NULL, CRYPTO_MACHINE);
		CryptoCertDeleteKey(cert);
		CryptoCertFree(cert);
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
		Print("LISTENER TEST OK\n");
	}
	else
	{
		Print("LISTENER TEST FAILED (%u of %u checks failed)\n", ctx->NumFailed, ctx->NumChecks);
	}

	Free(ctx);
}
