// NodeListener.c
// The Listener of a node (SDN-45, #238; ADR-0035): where the node listens, from the Listener of the desired state that
// its overlay applies (CONTROL_STATE.Listener; Core/Control.h). The front door (Core/FrontDoor.h; SDN-29, #205) listens
// on the TCP port and hands each TLS connection to the node's TLS transport (CORE-S2-1, #69), which takes TLS 1.3 only,
// the fixed policy of the new protocol; QUIC (CORE-S1-1, #67) listens on the UDP port where msquic.dll is present. Both
// present the certificate of the source of the Listener:
// - a PKCS #12 file on the node, which the node imports into the software key storage provider of the machine and puts
//   in the LocalMachine\My store (CryptoCertImportPfx), with the password that a file beside it holds;
// - a certificate of the LocalMachine\My store whose key is in a key storage provider, by its thumbprint;
// - a certificate that an ACME service issues (RFC 8555): the ACME sidecar, ranz.exe acme next to the node as ranz.exe
//   bgp is, answers the HTTP-01 challenge, installs the certificate in the store with its key in the software key
//   storage provider and gives its thumbprint; a thread of the Listener runs it again every NODE_LISTENER_ACME_CHECK, and
//   it renews the certificate RenewDays before its end. A new certificate starts the listeners again with it.
// The Listener may name a decoy (AUD1-DT-4, #452): the loopback address and port of a site on the node. The TLS of the new
// protocol then reads the first frame of each stream with the static key of the node, and passes a prober, one whose first
// frame does not open under it, to the site byte for byte (Core/TransportDecoy.c); without a decoy it closes the stream.
// The overlay takes the streams of both listeners as those of its own (NodeListenerAccept): a peer of the desired state
// opens its Noise session on one, and the static key of the handshake names the peer. A state without a Listener stops
// the listeners: the node listens on no port of its own. When TCP 443 is taken, the front door listens on
// NODE_LISTENER_FALLBACK instead and logs it (the amendment of ADR-0035 of 2026-10-21).
//
// The front door hands the TLS connections of the web UI, the API and the control stream (ALPN h2, http/1.1 and
// ranz-control/1) to a Controller on the same host, through its handoff pipe (FRONT_DOOR_CONTROLLER_PIPE; SDN-73, #352:
// controller/internal/port), and every other TLS connection to the node.

#include "Node.h"

#include "Mayaqua/FileIO.h"
#include "Mayaqua/Internat.h"
#include "Mayaqua/Memory.h"
#include "Mayaqua/Object.h"
#include "Mayaqua/Str.h"

#include "Core/Control.h"
#include "Core/Crypto.h"
#include "Core/FrontDoor.h"

#include "NodeInternal.h"

#include <ws2tcpip.h>

#include <string.h>

// The Listener of a node: the one of the state applied last, and the listeners that run for it
struct NODE_LISTENER {
	NODE *Node;
	// The static key of the node, which outlives the Listener: the TLS of the new protocol opens the first frame of a
	// stream with it to tell a prober from a peer (the decoy; AUD1-DT-4, #452)
	PEER_KEY *Key;
	// The fields below: NodeListenerAccept holds it shared, a change of the listeners exclusive
	SRWLOCK Lock;
	// The Listener applied last, and whether there is one
	CONTROL_LISTENER Config;
	bool HasConfig;
	// The certificate of the listeners that run, by its thumbprint; "" while none runs
	char Thumbprint[CONTROL_THUMBPRINT_SIZE];
	// The TLS transport of the new protocol, TLS 1.3 only, and its listener on no socket of its own: the front door hands
	// it the connections
	TRANSPORT *Tls;
	TRANSPORT_LISTENER *TlsListener;
	// The front door on the TCP port, and the port it bound: NODE_LISTENER_FALLBACK when 443 was taken
	FRONT_DOOR *FrontDoor;
	USHORT Port;
	bool Fallback;
	// QUIC on the UDP port, NULL where msquic.dll is missing, and the port it bound
	TRANSPORT *Quic;
	TRANSPORT_LISTENER *QuicListener;
	USHORT QuicPort;
	// The transports whose listeners closed: the overlay may still hold their streams, so they go with the Listener of the
	// node, once its overlay closed every session
	LIST *RetiredTls;
	LIST *RetiredQuic;
	// Why no listener runs, "" while they run or no Listener asks for them
	char Error[MAX_SIZE];
	// The streams that the overlay took from the listeners
	volatile LONG64 Accepted;
	// The thread that runs the ACME sidecar, its halt (manual reset) and its run now (auto reset), the runs of the sidecar
	// and the certificates that it gave the listeners
	HANDLE AcmeThread;
	HANDLE AcmeHalt;
	HANDLE AcmeNow;
	volatile LONG64 AcmeRuns;
	volatile LONG64 AcmeIssued;
};

// Whether two Listeners are the same
static bool NodeListenerSame(const CONTROL_LISTENER *a, const CONTROL_LISTENER *b) {
	if (StrCmp(a->Name, b->Name) != 0 || a->Port != b->Port || a->QuicPort != b->QuicPort || a->Source != b->Source)
		return false;
	if (StrCmp(a->Decoy, b->Decoy) != 0)
		return false;
	if (StrCmp(a->Path, b->Path) != 0 || StrCmp(a->PasswordFile, b->PasswordFile) != 0 || StrCmp(a->Thumbprint, b->Thumbprint) != 0)
		return false;
	if (StrCmp(a->Directory, b->Directory) != 0 || StrCmp(a->Email, b->Email) != 0 || StrCmp(a->CaFile, b->CaFile) != 0)
		return false;
	if (a->NumNames != b->NumNames || a->HttpPort != b->HttpPort || a->RenewDays != b->RenewDays)
		return false;

	for (UINT i = 0; i < a->NumNames && i < CONTROL_ACME_NAMES; i++)
		if (StrCmp(a->Names[i], b->Names[i]) != 0)
			return false;

	return true;
}

// Whether decoy is a loopback address and a port: "127.x.y.z:port" or "[::1]:port", the address in numbers and the port 1 to
// 65535. A decoy is a site on the node, so the node refuses any other address, a name included, whoever sent it.
static bool NodeListenerDecoyIsLoopback(const char *decoy) {
	char host[TRANSPORT_ADDRESS_SIZE];
	struct in_addr v4;
	struct in6_addr v6;

	const char *colon = (decoy != NULL ? strrchr(decoy, ':') : NULL);
	if (colon == NULL || colon == decoy)
		return false;

	UINT len = (UINT)(colon - decoy);
	const char *h = decoy;
	bool bracket = (decoy[0] == '[');
	if (bracket) {
		if (len < 3 || colon[-1] != ']')
			return false;
		h++;
		len -= 2;
	}
	if (len == 0 || len >= sizeof(host))
		return false;
	Copy(host, (void *)h, len);
	host[len] = 0;

	const char *port = colon + 1;
	UINT digits = StrLen(port);
	if (digits == 0 || digits > 5)
		return false;
	UINT number = 0;
	for (UINT i = 0; i < digits; i++) {
		if (port[i] < '0' || port[i] > '9')
			return false;
		number = number * 10 + (UINT)(port[i] - '0');
	}
	if (number == 0 || number > 65535)
		return false;

	if (bracket)
		return (inet_pton(AF_INET6, host, &v6) == 1 && IN6_IS_ADDR_LOOPBACK(&v6));

	return (inet_pton(AF_INET, host, &v4) == 1 && (ntohl(v4.s_addr) >> 24) == 127);
}

// The owner of the front door: the TLS listener of the new protocol takes every TLS connection (TransportTake)
static bool NodeListenerTake(void *param, SOCKET s) {
	return TransportTake((TRANSPORT_LISTENER *)param, (UINT_PTR)s);
}

// Stop the listeners that run: the front door first, so that no connection reaches the TLS listener once it closes, then
// the listeners. Their transports retire, since the overlay may still hold their streams. The caller holds the lock
// exclusive.
static void NodeListenerDown(NODE_LISTENER *l) {
	if (l->FrontDoor != NULL)
		FrontDoorStop(l->FrontDoor);
	l->FrontDoor = NULL;

	if (l->TlsListener != NULL)
		TransportCloseListener(l->TlsListener);
	l->TlsListener = NULL;
	if (l->QuicListener != NULL)
		TransportCloseListener(l->QuicListener);
	l->QuicListener = NULL;

	if (l->Tls != NULL)
		Add(l->RetiredTls, l->Tls);
	l->Tls = NULL;
	if (l->Quic != NULL)
		Add(l->RetiredQuic, l->Quic);
	l->Quic = NULL;

	l->Port = 0;
	l->QuicPort = 0;
	l->Fallback = false;
	StrCpy(l->Thumbprint, sizeof(l->Thumbprint), "");
}

// Start the listeners of the Listener with the certificate thumb: the TLS of the new protocol, TLS 1.3 only, behind the
// front door on the TCP port, and QUIC on the UDP port where msquic.dll is present. The caller holds the lock exclusive,
// and no listener runs. False, with the reason in the error of the Listener, when the front door cannot run.
static bool NodeListenerUp(NODE_LISTENER *l, const char *thumb) {
	NODE *n = l->Node;
	const CONTROL_LISTENER *c = &l->Config;
	TRANSPORT_TLS_CONFIG tc;
	TRANSPORT_QUIC_CONFIG qc;
	FRONT_DOOR_OWNER owners[2];
	FRONT_DOOR_CONFIG fc;
	char address[TRANSPORT_ADDRESS_SIZE];

	// The TLS of the new protocol: TLS 1.3 alone, the fixed policy of the surface
	TransportTlsDefaultConfig(&tc, thumb, true);
	tc.Versions = TRANSPORT_TLS_13;

	// The decoy (AUD1-DT-4, #452): a prober, one whose first frame does not open under the static key of the node, is passed
	// to the site on the loopback interface that the Listener names. Without one, as before, it meets a closed connection.
	if (IsEmptyStr(c->Decoy) == false) {
		if (NodeListenerDecoyIsLoopback(c->Decoy) == false || l->Key == NULL) {
			Format(l->Error, sizeof(l->Error), "the decoy %s is not a loopback address and a port, such as 127.0.0.1:8080", c->Decoy);
			return false;
		}
		StrCpy(tc.Decoy, sizeof(tc.Decoy), c->Decoy);
		if (l->Key->Identity != NULL)
			tc.DecoyIdentity = l->Key->Identity;
		else
			tc.DecoyKey = l->Key->Private;
	}

	l->Tls = TransportTlsServerNew(&tc);
	l->TlsListener = (l->Tls != NULL ? TransportListen(l->Tls, "") : NULL);
	if (l->TlsListener == NULL) {
		NodeListenerDown(l);
		Format(l->Error, sizeof(l->Error), "the TLS of the new protocol does not start with the certificate %s: it must be in the LocalMachine\\My store with its key in a key storage provider", thumb);
		return false;
	}

	// The front door hands the TLS connections of a Controller's ALPN protocols to the Controller on this host, through
	// its handoff pipe (SDN-73, #352), and every other TLS connection to the node, on the port of the Listener or, when
	// 443 is taken, on the fallback. Without a Controller on the host, its connections are closed.
	Zero(owners, sizeof(owners));
	StrCpy(owners[0].Name, sizeof(owners[0].Name), "controller");
	owners[0].Kind = FRONT_DOOR_TLS;
	StrCpy(owners[0].Protocols, sizeof(owners[0].Protocols), FRONT_DOOR_CONTROLLER_PROTOCOLS);
	UniStrCpy(owners[0].Pipe, sizeof(owners[0].Pipe), FRONT_DOOR_CONTROLLER_PIPE);
	StrCpy(owners[1].Name, sizeof(owners[1].Name), "node");
	owners[1].Kind = FRONT_DOOR_TLS;
	owners[1].Take = NodeListenerTake;
	owners[1].Param = l->TlsListener;

	Zero(&fc, sizeof(fc));
	fc.Owners = owners;
	fc.NumOwners = 2;
	Format(fc.Address, sizeof(fc.Address), ":%u", c->Port);
	l->FrontDoor = FrontDoorStart(&fc);
	if (l->FrontDoor == NULL && c->Port == FRONT_DOOR_PORT) {
		Format(fc.Address, sizeof(fc.Address), ":%u", (UINT)NODE_LISTENER_FALLBACK);
		l->FrontDoor = FrontDoorStart(&fc);
		l->Fallback = (l->FrontDoor != NULL);
	}
	if (l->FrontDoor == NULL) {
		NodeListenerDown(l);
		Format(l->Error, sizeof(l->Error), "the front door cannot listen on TCP port %u", c->Port);
		return false;
	}
	l->Port = FrontDoorPort(l->FrontDoor);

	// QUIC where msquic.dll is present; without it the front door carries the new protocol alone
	if (TransportQuicAvailable()) {
		TransportQuicDefaultConfig(&qc, thumb, true);
		l->Quic = TransportQuicServerNew(&qc);
		Format(address, sizeof(address), ":%u", c->QuicPort);
		l->QuicListener = (l->Quic != NULL ? TransportListen(l->Quic, address) : NULL);
		l->QuicPort = (l->QuicListener != NULL ? TransportQuicBoundPort(l->Quic) : 0);
		if (l->QuicListener == NULL)
			NodeLog(n, "Listener %s: QUIC cannot listen on UDP port %u, so the front door carries the new protocol alone", c->Name, c->QuicPort);
	} else {
		NodeLog(n, "Listener %s: msquic.dll is not there, so the front door carries the new protocol alone", c->Name);
	}

	StrCpy(l->Thumbprint, sizeof(l->Thumbprint), thumb);
	StrCpy(l->Error, sizeof(l->Error), "");

	if (l->Fallback)
		NodeLog(n, "Listener %s: TCP port 443 is taken, so the front door listens on TCP port %u instead (the fallback of ADR-0035)", c->Name, (UINT)l->Port);
	NodeLog(n, "Listener %s: the front door listens on TCP port %u and QUIC on UDP port %u, with the certificate %s; the new protocol takes TLS 1.3 only",
	        c->Name, (UINT)l->Port, (UINT)l->QuicPort, thumb);
	if (IsEmptyStr(c->Decoy) == false)
		NodeLog(n, "Listener %s: a prober of the TLS of the new protocol is passed to the decoy %s", c->Name, c->Decoy);
	else
		NodeLog(n, "Listener %s: no decoy, so a prober of the TLS of the new protocol meets a closed connection", c->Name);

	return true;
}

// The first line of a file of the node, whose path is UTF-8, into line (size bytes); false when it cannot be read
static bool NodeListenerReadLine(const char *path, char *line, UINT size) {
	wchar_t name[MAX_PATH];

	if (size == 0)
		return false;

	Zero(name, sizeof(name));
	Utf8ToUni(name, sizeof(name), path, StrLen(path));
	BUF *b = ReadDumpW(name);
	if (b == NULL)
		return false;

	UINT len = MIN(b->Size, size - 1);
	Copy(line, b->Buf, len);
	line[len] = 0;
	for (UINT i = 0; i < len; i++) {
		if (line[i] == '\r' || line[i] == '\n') {
			line[i] = 0;
			break;
		}
	}

	Zero(b->Buf, b->Size);
	FreeBuf(b);

	return true;
}

// The certificate of a Listener whose source is a file or the store: its thumbprint into thumb, false with the reason in
// the error of the Listener. A PKCS #12 file is imported into the software key storage provider of the machine and its
// certificate put in the LocalMachine\My store; a certificate of the store must have its key in a key storage provider
// (ADR-0022). The caller holds the lock exclusive.
static bool NodeListenerCertificate(NODE_LISTENER *l, char *thumb, UINT size) {
	const CONTROL_LISTENER *c = &l->Config;
	wchar_t path[MAX_PATH];
	wchar_t password[MAX_SIZE];
	char text[MAX_SIZE];

	StrCpy(thumb, size, "");

	if (c->Source == CONTROL_CERT_KSP) {
		PCCERT_CONTEXT cert = CryptoCertFindByThumbprint(c->Thumbprint, NULL, CRYPTO_MACHINE);
		bool ok = (cert != NULL && CryptoCertHasKspKey(cert));

		CryptoCertFree(cert);
		if (ok == false) {
			Format(l->Error, sizeof(l->Error), "the certificate %s is not in the LocalMachine\\My store with its key in a key storage provider", c->Thumbprint);
			return false;
		}

		StrCpy(thumb, size, c->Thumbprint);
		return true;
	}

	if (c->Source != CONTROL_CERT_FILE) {
		Format(l->Error, sizeof(l->Error), "the Listener names no source of a certificate");
		return false;
	}

	// The password is the first line of its file, which stays on the node
	Zero(password, sizeof(password));
	Zero(text, sizeof(text));
	if (IsEmptyStr(c->PasswordFile) == false) {
		if (NodeListenerReadLine(c->PasswordFile, text, sizeof(text)) == false) {
			Format(l->Error, sizeof(l->Error), "the password file %s cannot be read", c->PasswordFile);
			return false;
		}
		Utf8ToUni(password, sizeof(password), text, StrLen(text));
		Zero(text, sizeof(text));
	}

	Zero(path, sizeof(path));
	Utf8ToUni(path, sizeof(path), c->Path, StrLen(c->Path));
	BUF *pfx = ReadDumpW(path);
	if (pfx == NULL) {
		SecureZeroMemory(password, sizeof(password));
		Format(l->Error, sizeof(l->Error), "the PKCS #12 file %s cannot be read", c->Path);
		return false;
	}

	// Each step says why it failed: the import, the key of the certificate, the store. The thumbprint comes last, so it
	// is there only when every step passed.
	PCCERT_CONTEXT cert = CryptoCertImportPfx(pfx->Buf, pfx->Size, password, CRYPTO_MACHINE);
	UINT error = (cert == NULL ? (UINT)GetLastError() : 0);
	SecureZeroMemory(password, sizeof(password));
	FreeBuf(pfx);

	if (cert == NULL)
		Format(l->Error, sizeof(l->Error), "the PKCS #12 file %s does not import into the key storage provider of the machine (error 0x%x): is its password the one of the password file?", c->Path, error);
	else if (CryptoCertHasKspKey(cert) == false)
		Format(l->Error, sizeof(l->Error), "the key of the certificate of the PKCS #12 file %s is not in a key storage provider", c->Path);
	else if (CryptoCertAddToStore(cert, NULL, CRYPTO_MACHINE) == false)
		Format(l->Error, sizeof(l->Error), "the certificate of the PKCS #12 file %s cannot go into the LocalMachine\\My store (error 0x%x)", c->Path, (UINT)GetLastError());
	else if (CryptoCertThumbprintStr(cert, thumb, size) == false)
		Format(l->Error, sizeof(l->Error), "the certificate of the PKCS #12 file %s has no thumbprint", c->Path);

	CryptoCertFree(cert);

	return (IsEmptyStr(thumb) == false);
}

//
// ACME
//

// One run of the ACME sidecar for the Listener c: ranz.exe acme gets the certificate of the names of c from its
// directory, or renews it when it is due, installs it in the LocalMachine\My store with its key in the software key
// storage provider, and writes its thumbprint into its answer file. The thumbprint into thumb (size bytes); false, with
// the reason in why (why_size bytes), when the run failed or the Listener stops.
static bool NodeListenerAcmeRun(NODE_LISTENER *l, const CONTROL_LISTENER *c, char *thumb, UINT size, char *why, UINT why_size) {
	NODE *n = l->Node;
	wchar_t dir[MAX_PATH];
	wchar_t name[MAX_SIZE];
	wchar_t state[MAX_PATH];
	wchar_t out[MAX_PATH];
	wchar_t directory[CONTROL_URL_SIZE];
	wchar_t email[CONTROL_EMAIL_SIZE];
	wchar_t ca[MAX_PATH];
	char names[CONTROL_ACME_NAMES * CONTROL_ACME_NAME_SIZE];
	wchar_t wnames[CONTROL_ACME_NAMES * CONTROL_ACME_NAME_SIZE];
	char answer[NODE_LISTENER_ACME_OUT];
	STARTUPINFOW si;
	PROCESS_INFORMATION pi;
	UINT cmd_size = NODE_LISTENER_ACME_CMD * sizeof(wchar_t);
	bool ok = false;

	StrCpy(thumb, size, "");

	// The state of the Listener and the answer of the run, in the data directory of the node
	ConbinePathW(dir, sizeof(dir), n->DataDir, NODE_LISTENER_ACME_DIR);
	MakeDirExW(dir);
	StrToUni(name, sizeof(name), c->Name);
	ConbinePathW(state, sizeof(state), dir, name);
	UniFormat(out, sizeof(out), L"%s.out", state);
	FileDeleteW(out);

	StrCpy(names, sizeof(names), "");
	for (UINT i = 0; i < c->NumNames && i < CONTROL_ACME_NAMES; i++) {
		if (i != 0)
			StrCat(names, sizeof(names), ",");
		StrCat(names, sizeof(names), c->Names[i]);
	}
	Utf8ToUni(wnames, sizeof(wnames), names, StrLen(names));
	Utf8ToUni(directory, sizeof(directory), c->Directory, StrLen(c->Directory));
	Utf8ToUni(email, sizeof(email), c->Email, StrLen(c->Email));
	Utf8ToUni(ca, sizeof(ca), c->CaFile, StrLen(c->CaFile));

	if (IsFileExistsW(n->BgpSidecar) == false) {
		Format(why, why_size, "ranz.exe, which holds the ACME sidecar, is not installed at %S", n->BgpSidecar);
		return false;
	}

	wchar_t *cmd = ZeroMalloc(cmd_size);
	UniFormat(cmd, cmd_size, L"\"%s\" acme -directory \"%s\" -names \"%s\" -email \"%s\" -ca \"%s\" -http-port %u -renew-days %u -state \"%s\" -out \"%s\" -machine",
	          n->BgpSidecar, directory, wnames, email, ca, c->HttpPort, c->RenewDays, state, out);

	Zero(&si, sizeof(si));
	si.cb = sizeof(si);
	Zero(&pi, sizeof(pi));

	if (CreateProcessW(n->BgpSidecar, cmd, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi) == FALSE) {
		Format(why, why_size, "%S cannot be started (error %u)", n->BgpSidecar, (UINT)GetLastError());
		Free(cmd);
		return false;
	}
	Free(cmd);

	// The run ends by itself, or with the Listener, or at its time limit
	HANDLE waits[2] = {pi.hProcess, l->AcmeHalt};
	DWORD w = WaitForMultipleObjects(2, waits, FALSE, NODE_LISTENER_ACME_WAIT);
	if (w != WAIT_OBJECT_0) {
		TerminateProcess(pi.hProcess, 1);
		WaitForSingleObject(pi.hProcess, INFINITE);
	}
	CloseHandle(pi.hThread);
	CloseHandle(pi.hProcess);

	if (w == WAIT_OBJECT_0 + 1) {
		Format(why, why_size, "the Listener stops");
		return false;
	}

	// The answer: "thumbprint <40 hex digits>", or "error <why>", on a line of its own. Trim takes spaces and tabs only, so
	// the line end goes first.
	BUF *b = ReadDumpW(out);
	Zero(answer, sizeof(answer));
	if (b != NULL) {
		Copy(answer, b->Buf, MIN(b->Size, (UINT)sizeof(answer) - 1));
		FreeBuf(b);
	}
	TrimCrlf(answer);
	Trim(answer);

	if (w != WAIT_OBJECT_0) {
		Format(why, why_size, "the sidecar did not answer within %u s", (UINT)(NODE_LISTENER_ACME_WAIT / 1000));
	} else if (StrLen(answer) == 11 + 2 * CRYPTO_THUMBPRINT_SIZE && Cmp(answer, "thumbprint ", 11) == 0 && size > 2 * CRYPTO_THUMBPRINT_SIZE) {
		StrCpy(thumb, size, answer + 11);
		ok = true;
	} else {
		StrCpy(why, why_size, IsEmptyStr(answer) ? "the sidecar gave no answer" : answer);
	}

	return ok;
}

// The thread of ACME of the Listener that it started for: it runs the sidecar at once and then every
// NODE_LISTENER_ACME_CHECK, or NODE_LISTENER_ACME_RETRY after a run that failed, or when NodeListenerRenew asks; each
// certificate that the sidecar gives that the listeners do not have yet starts them again with it
static DWORD WINAPI NodeListenerAcmeThread(LPVOID param) {
	NODE_LISTENER *l = (NODE_LISTENER *)param;
	CONTROL_LISTENER *c = ZeroMalloc(sizeof(CONTROL_LISTENER));
	char thumb[CONTROL_THUMBPRINT_SIZE];
	char why[MAX_SIZE];

	AcquireSRWLockShared(&l->Lock);
	Copy(c, &l->Config, sizeof(CONTROL_LISTENER));
	ReleaseSRWLockShared(&l->Lock);

	while (true) {
		StrCpy(why, sizeof(why), "");
		bool ok = NodeListenerAcmeRun(l, c, thumb, sizeof(thumb), why, sizeof(why));

		InterlockedIncrement64(&l->AcmeRuns);
		AcquireSRWLockExclusive(&l->Lock);
		if (ok == false) {
			// The listeners keep the certificate before, where they have one; the status says why the run failed
			Format(l->Error, sizeof(l->Error), "ACME: %s", why);
		} else if (StrCmp(thumb, l->Thumbprint) != 0) {
			// A new certificate: the listeners start again with it, and a session that runs keeps its own stream
			NodeListenerDown(l);
			if (NodeListenerUp(l, thumb))
				InterlockedIncrement64(&l->AcmeIssued);
			else
				NodeLog(l->Node, "Listener %s not started: %s", c->Name, l->Error);
		} else {
			// The certificate stays, and the reason of a run before that failed goes
			StrCpy(l->Error, sizeof(l->Error), "");
		}
		ReleaseSRWLockExclusive(&l->Lock);
		if (ok == false)
			NodeLog(l->Node, "Listener %s: ACME failed: %s", c->Name, why);

		HANDLE waits[2] = {l->AcmeHalt, l->AcmeNow};
		if (WaitForMultipleObjects(2, waits, FALSE, ok ? NODE_LISTENER_ACME_CHECK : NODE_LISTENER_ACME_RETRY) == WAIT_OBJECT_0)
			break;
	}

	Free(c);

	return 0;
}

// Start the thread of ACME of the Listener applied last
static void NodeListenerAcmeStart(NODE_LISTENER *l) {
	DWORD id = 0;

	ResetEvent(l->AcmeHalt);
	l->AcmeThread = CreateThread(NULL, 0, NodeListenerAcmeThread, l, 0, &id);
	if (l->AcmeThread == NULL)
		NodeLog(l->Node, "Listener %s: the thread of ACME cannot start (error %u)", l->Config.Name, (UINT)GetLastError());
}

// Stop the thread of ACME, and a run of the sidecar that it waits for
static void NodeListenerAcmeStop(NODE_LISTENER *l) {
	if (l->AcmeThread == NULL)
		return;

	SetEvent(l->AcmeHalt);
	WaitForSingleObject(l->AcmeThread, INFINITE);
	CloseHandle(l->AcmeThread);
	l->AcmeThread = NULL;
}

//
// The Listener
//

// Start the Listener of a node with its overlay: it listens on nothing until a state names a Listener
void NodeListenerStart(NODE *n, PEER_KEY *key) {
	if (n == NULL || n->Listener != NULL)
		return;

	NODE_LISTENER *l = ZeroMalloc(sizeof(NODE_LISTENER));
	l->Node = n;
	l->Key = key;
	InitializeSRWLock(&l->Lock);
	l->RetiredTls = NewListFast(NULL);
	l->RetiredQuic = NewListFast(NULL);
	l->AcmeHalt = CreateEventW(NULL, TRUE, FALSE, NULL);
	l->AcmeNow = CreateEventW(NULL, FALSE, FALSE, NULL);
	n->Listener = l;
}

// Stop the Listener of a node once its overlay stopped, whose thread closed every session: the thread of ACME, the
// listeners, and every transport they had
void NodeListenerStop(NODE *n) {
	NODE_LISTENER *l = (n != NULL ? n->Listener : NULL);

	if (l == NULL)
		return;

	NodeListenerAcmeStop(l);

	AcquireSRWLockExclusive(&l->Lock);
	bool had = l->HasConfig;
	NodeListenerDown(l);
	ReleaseSRWLockExclusive(&l->Lock);

	for (UINT i = 0; i < LIST_NUM(l->RetiredTls); i++)
		TransportTlsFree((TRANSPORT *)LIST_DATA(l->RetiredTls, i));
	for (UINT i = 0; i < LIST_NUM(l->RetiredQuic); i++)
		TransportQuicFree((TRANSPORT *)LIST_DATA(l->RetiredQuic, i));
	ReleaseList(l->RetiredTls);
	ReleaseList(l->RetiredQuic);
	if (l->AcmeHalt != NULL)
		CloseHandle(l->AcmeHalt);
	if (l->AcmeNow != NULL)
		CloseHandle(l->AcmeNow);

	n->Listener = NULL;
	Free(l);

	if (had)
		NodeLog(n, "Listener stopped: the node listens on no port of its own");
}

// The Listener of a state that the overlay applied: the listeners start with the certificate of its source, again when
// it changed, and stop when the state has none. A certificate of ACME comes from the thread of ACME. It runs on the
// thread that applied the state.
void NodeListenerApplied(NODE *n, const CONTROL_STATE *st) {
	NODE_LISTENER *l = (n != NULL ? n->Listener : NULL);
	char thumb[CONTROL_THUMBPRINT_SIZE];
	char error[MAX_SIZE];
	bool up = false;

	if (l == NULL || st == NULL)
		return;

	const CONTROL_LISTENER *want = st->Listener;

	AcquireSRWLockShared(&l->Lock);
	bool same = (want == NULL ? l->HasConfig == false : (l->HasConfig && NodeListenerSame(&l->Config, want)));
	ReleaseSRWLockShared(&l->Lock);
	if (same)
		return;

	// The thread of ACME of the Listener before changes the listeners too: it stops first
	NodeListenerAcmeStop(l);

	AcquireSRWLockExclusive(&l->Lock);
	{
		NodeListenerDown(l);
		StrCpy(l->Error, sizeof(l->Error), "");
		l->HasConfig = (want != NULL);
		if (want != NULL)
			Copy(&l->Config, want, sizeof(CONTROL_LISTENER));
		else
			Zero(&l->Config, sizeof(CONTROL_LISTENER));

		if (want != NULL && want->Source != CONTROL_CERT_ACME && NodeListenerCertificate(l, thumb, sizeof(thumb)))
			up = NodeListenerUp(l, thumb);
		StrCpy(error, sizeof(error), l->Error);
	}
	ReleaseSRWLockExclusive(&l->Lock);

	if (want == NULL) {
		NodeLog(n, "Listener: generation %I64u has none, so the node listens on no port of its own", st->Generation);
	} else if (want->Source == CONTROL_CERT_ACME) {
		NodeLog(n, "Listener %s: the certificate of %s comes from the ACME service %s", want->Name, want->Names[0], want->Directory);
		NodeListenerAcmeStart(l);
	} else if (up == false) {
		NodeLog(n, "Listener %s not started: %s", want->Name, error);
	}
}

// The next stream that a listener of the Listener took, NULL for none: the overlay runs the responder of a Noise session
// on it, as on a stream of its own listener
TRANSPORT_STREAM *NodeListenerAccept(NODE *n) {
	NODE_LISTENER *l = (n != NULL ? n->Listener : NULL);
	TRANSPORT_STREAM *s = NULL;

	if (l == NULL)
		return NULL;

	AcquireSRWLockShared(&l->Lock);
	if (l->TlsListener != NULL)
		s = TransportAccept(l->TlsListener, 0);
	if (s == NULL && l->QuicListener != NULL)
		s = TransportAccept(l->QuicListener, 0);
	ReleaseSRWLockShared(&l->Lock);

	if (s != NULL)
		InterlockedIncrement64(&l->Accepted);

	return s;
}

// Ask the thread of ACME to run the sidecar now: it renews the certificate when it is due
void NodeListenerRenew(NODE *n) {
	NODE_LISTENER *l = (n != NULL ? n->Listener : NULL);

	if (l != NULL && l->AcmeNow != NULL)
		SetEvent(l->AcmeNow);
}

// The state of the Listener of a node
void NodeListenerGetStatus(NODE *n, NODE_LISTENER_STATUS *st) {
	if (st == NULL)
		return;

	Zero(st, sizeof(NODE_LISTENER_STATUS));
	NODE_LISTENER *l = (n != NULL ? n->Listener : NULL);
	if (l == NULL)
		return;

	AcquireSRWLockShared(&l->Lock);
	{
		if (l->HasConfig) {
			StrCpy(st->Name, sizeof(st->Name), l->Config.Name);
			st->Source = l->Config.Source;
		}
		st->Running = (l->FrontDoor != NULL);
		if (st->Running)
			StrCpy(st->Decoy, sizeof(st->Decoy), l->Config.Decoy);
		st->Port = l->Port;
		st->QuicPort = l->QuicPort;
		st->Fallback = l->Fallback;
		StrCpy(st->Thumbprint, sizeof(st->Thumbprint), l->Thumbprint);
		StrCpy(st->Error, sizeof(st->Error), l->Error);
	}
	ReleaseSRWLockShared(&l->Lock);

	st->Accepted = (UINT64)ReadAcquire64(&l->Accepted);
	st->AcmeRuns = (UINT64)ReadAcquire64(&l->AcmeRuns);
	st->AcmeIssued = (UINT64)ReadAcquire64(&l->AcmeIssued);
}
