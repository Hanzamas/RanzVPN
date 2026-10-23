// TransportTls.c
// The TLS transport of the new core (CORE-S2-1, #69): a listener and a dialler of TLS 1.3 and 1.2
// over TCP on Schannel, through SSPI, for a client that cannot use UDP (TLS-443 in a fallback list,
// ADR-0005). The path stays on the Windows TCP stack. The session layer runs the Noise session over
// a stream unchanged (TransportNoise.c): the handshake, the Login and the data stream whose frames
// enter the Hub (CORE-S1-2, #68). A stream is a TCP socket and the Schannel context of its TLS
// session: a write encrypts the bytes into records of at most the largest message of the session, a
// read decrypts the records that came. The channel binding of a stream is the TLS exporter of its
// session, which Schannel gives through SECPKG_ATTR_KEYING_MATERIAL. The client pins the server
// certificate and does not trust the system root store (ADR-0023).
//
// A listener accepts on a wait of the Windows thread pool and runs each TLS handshake on a callback
// of the pool, so that a peer that never completes its handshake holds no other back; a stream whose
// handshake completed waits in the backlog for Accept. A dial connects and runs the client's
// handshake on the caller's thread, and returns as soon as it can once its cancel is set.
//
// Schannel takes no list of key exchange groups per credential, and the hybrid X25519MLKEM768 is
// not in the default list of builds 26100 and 26200: TransportTlsSetGroups sets the machine's list,
// the one Schannel reads, and a transport sets it when it opens.

#include <winsock2.h>
#include <ws2tcpip.h>

#include "Core/Transport.h"

#include <winternl.h>

#define SECURITY_WIN32
#include <security.h>

#define SCHANNEL_USE_BLACKLISTS
#include <schannel.h>

#include <stdlib.h>
#include <string.h>
#include <wchar.h>

#define TLS_RECORD_HEADER 5                                  // A TLS record: its type, version and length, then its bytes
#define TLS_RECORD_MAX    (TLS_RECORD_HEADER + 16384 + 2048) // The largest record a peer may send (RFC 5246 section 6.2.3)
#define TLS_IN_SIZE       (2 * TLS_RECORD_MAX)               // Bytes of records that a stream holds before it decrypts them
#define TLS_BACKLOG       16                                 // Streams a listener holds before it closes a new one
#define TLS_POLL          50                                 // How often a dial or a handshake looks at its cancel while it waits (ms)
#define TLS_HANDSHAKE     10000                              // A TLS handshake completes within this time (ms)
#define TLS_LINGER        1000                               // A close waits this long for the peer's end (ms)
#define TLS_SEND_TIMEOUT  30000                              // A send that the peer does not take within this time fails (ms)

// What the ServerHello parser reads (RFC 8446 section 4.1.3)
#define TLS_CONTENT_CCS       20     // A ChangeCipherSpec record
#define TLS_CONTENT_HANDSHAKE 22     // A handshake record
#define TLS_SERVER_HELLO      2      // The ServerHello message
#define TLS_RANDOM_SIZE       32     // The random of a ServerHello
#define TLS_EXT_VERSIONS      0x002B // The extension supported_versions
#define TLS_EXT_KEY_SHARE     0x0033 // The extension key_share
#define TLS_VERSION_12        0x0303
#define TLS_VERSION_13        0x0304

// What the decryption of the next record gave (TlsDecrypt)
#define TLS_RECORD_DATA 0 // A record was taken: its bytes, if any, wait in Plain
#define TLS_RECORD_MORE 1 // In holds no whole record
#define TLS_RECORD_END  2 // The peer closed the session, or the stream failed

// The context requirements of the two ends: a stream of records, encrypted, in order and once each;
// Schannel allocates the tokens. The client checks the server certificate itself (the pin).
#define TLS_ISC_FLAGS (ISC_REQ_SEQUENCE_DETECT | ISC_REQ_REPLAY_DETECT | ISC_REQ_CONFIDENTIALITY | ISC_REQ_ALLOCATE_MEMORY | ISC_REQ_STREAM | ISC_REQ_MANUAL_CRED_VALIDATION)
#define TLS_ASC_FLAGS (ASC_REQ_SEQUENCE_DETECT | ASC_REQ_REPLAY_DETECT | ASC_REQ_CONFIDENTIALITY | ASC_REQ_ALLOCATE_MEMORY | ASC_REQ_STREAM)

// ChaCha20-Poly1305, which the credentials refuse, by its CNG name for a header that does not have it
#ifndef BCRYPT_CHACHA20_POLY1305_ALGORITHM
#define BCRYPT_CHACHA20_POLY1305_ALGORITHM L"CHACHA20_POLY1305"
#endif

// The machine's Schannel group list (the Supported Groups, once "ECC curves"), which
// Enable-TlsEccCurve writes and Schannel reads, and the ECC Curve Order policy that overrides it
#define TLS_GROUPS_KEY    L"SYSTEM\\CurrentControlSet\\Control\\Cryptography\\Configuration\\Local\\SSL\\00010002"
#define TLS_GROUPS_POLICY L"SOFTWARE\\Policies\\Microsoft\\Cryptography\\Configuration\\SSL\\00010002"
#define TLS_GROUPS_VALUE  L"EccCurves"
#define TLS_GROUPS_SIZE   2048               // Characters of a group list
#define TLS_GROUP_HYBRID  L"x25519_mlkem768" // X25519MLKEM768 by its Schannel name
#define TLS_GROUP_X25519  L"curve25519"      // X25519

// The list of Windows 11 24H2 and Windows Server 2025 where the machine has none of its own, as a
// REG_MULTI_SZ: each group with its NUL, then the NUL that ends the list
static const wchar_t tls_default_groups[] = L"curve25519\0NistP256\0NistP384\0";

// The random of a HelloRetryRequest (RFC 8446 section 4.1.3): the SHA-256 of "HelloRetryRequest"
static const UCHAR tls_retry_random[TLS_RANDOM_SIZE] = {
    0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11, 0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91,
    0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E, 0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C};

// A TLS transport: its configuration, its Schannel credential and, for a server, its certificate
typedef struct TLS_NET {
	TRANSPORT_TLS_CONFIG Cfg;                 // The configuration, with the thumbprint
	bool Server;                              // A listener (the certificate) or a dialler (the pin)
	UCHAR Thumbprint[CRYPTO_THUMBPRINT_SIZE]; // The server certificate's thumbprint, parsed from Cfg
	PCCERT_CONTEXT Cert;                      // The server certificate, its key in a KSP (server only)
	CredHandle Cred;                          // The Schannel credential of every stream of the transport
	bool HaveCred;                            // ... acquired
	bool HaveWinsock;                         // WSAStartup succeeded
	volatile LONG BoundPort;                  // The port the last listener bound (a listener on port 0)
	SRWLOCK Lock;                             // Last and HaveLast
	TRANSPORT_TLS_INFO Last;                  // What the last handshake that completed gave
	bool HaveLast;                            // ... there was one
} TLS_NET;

// A stream: a TCP connection and the Schannel context of its TLS session. One thread may read it
// while another writes it: the records on the socket go out under SendLock, and every call on the
// context runs under CtxLock, taken after SendLock where a call needs both.
typedef struct TLS_STREAM {
	TLS_NET *Net;                           // The transport
	SOCKET Socket;                          // The TCP connection
	CtxtHandle Ctx;                         // The Schannel context of its TLS session
	bool HaveCtx;                           // ... made
	bool Open;                              // The handshake completed: a close sends the close_notify
	wchar_t Target[TRANSPORT_ADDRESS_SIZE]; // The client's name of the server, the host of the address
	SecPkgContext_StreamSizes Sizes;        // The sizes of the records of the session
	SRWLOCK SendLock;                       // A write, or the answer to a post-handshake message
	SRWLOCK CtxLock;                        // One call on the context at a time
	UCHAR *In;                              // TLS_IN_SIZE bytes: the records received and not decrypted yet ...
	UINT InSize;                            // ... their number
	UCHAR *Plain;                           // TLS_RECORD_MAX bytes: the bytes of the last record decrypted ...
	UINT PlainStart;                        // ... the first not read yet
	UINT PlainSize;                         // ... their number
	UCHAR *Out;                             // A record being written: its header, its bytes and its trailer ...
	UINT OutSize;                           // ... the size of the largest
	bool Ended;                             // The peer closed or the stream failed: a read gives the end
	TRANSPORT_TLS_INFO Info;                // What the handshake gave
	UCHAR Binding[NOISE_EXPORTER_SIZE];     // The TLS exporter of the session, the channel binding
} TLS_STREAM;

// A listener: its socket, the wait of the pool on its connections, its handshakes in progress and
// the backlog of the streams whose handshake completed
typedef struct TLS_LISTENER {
	TLS_NET *Net;                   // The transport
	SOCKET Socket;                  // The listening socket
	WSAEVENT Event;                 // Set while a connection waits to be accepted
	HANDLE Closing;                 // Set once CloseListener runs: the handshakes in progress stop
	PTP_WAIT Wait;                  // The wait of the pool on Event
	TP_CALLBACK_ENVIRON Env;        // The environment of the wait and the handshakes ...
	PTP_CLEANUP_GROUP Group;        // ... and their cleanup group, which waits for every callback
	SRWLOCK Lock;                   // The fields below
	CONDITION_VARIABLE Changed;     // A stream was queued, an Accept returned, or the listener closed
	TLS_STREAM *Queue[TLS_BACKLOG]; // The streams whose handshake completed, not accepted yet, oldest first
	UINT NumQueued;                 // ... their number
	UINT NumWaiting;                // The Accept calls that wait
	bool Closed;                    // CloseListener runs
} TLS_LISTENER;

// A connection that the listener took, for the callback that runs its handshake
typedef struct TLS_ACCEPTED {
	TLS_LISTENER *Listener; // The listener
	SOCKET Socket;          // The connection
} TLS_ACCEPTED;

// A reader of the bytes of a TLS message: Pos stays at most Size, and a read past Size fails
typedef struct TLS_READER {
	const UCHAR *Data;
	UINT Size;
	UINT Pos;
} TLS_READER;

//
// Memory, names and addresses
//

static void *TlsAlloc(UINT size) {
	return HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, size);
}

// Wipe and free size bytes at p, which may be NULL
static void TlsRelease(void *p, UINT size) {
	if (p == NULL)
		return;

	SecureZeroMemory(p, size);
	HeapFree(GetProcessHeap(), 0, p);
}

// One hex digit, or -1
static int TlsHexDigit(char c) {
	if (c >= '0' && c <= '9')
		return c - '0';
	if (c >= 'a' && c <= 'f')
		return c - 'a' + 10;
	if (c >= 'A' && c <= 'F')
		return c - 'A' + 10;
	return -1;
}

// The thumbprint of the configuration: exactly CRYPTO_THUMBPRINT_SIZE bytes (40 hex digits), spaces
// and colons between them ignored; false for anything else
static bool TlsParseThumbprint(const char *str, UCHAR *out) {
	UINT n = 0;

	for (const char *p = str; *p != 0; p++) {
		int v = TlsHexDigit(*p);

		if (*p == ' ' || *p == ':')
			continue;
		if (v < 0 || n >= 2 * CRYPTO_THUMBPRINT_SIZE)
			return false;

		if (n % 2 == 0)
			out[n / 2] = (UCHAR)(v << 4);
		else
			out[n / 2] |= (UCHAR)v;
		n++;
	}

	return (n == 2 * CRYPTO_THUMBPRINT_SIZE);
}

// Split "host:port" at the last colon into host (max bytes, with its NUL; the brackets of
// "[v6]:port" taken off) and port (port_max bytes, with its NUL): digits, at most 65535. false for
// anything else. An empty host is every address of a listener.
static bool TlsSplitAddress(const char *address, char *host, UINT max, char *port, UINT port_max) {
	const char *colon = strrchr(address, ':');
	const char *h = address;
	UINT len, digits;

	if (colon == NULL)
		return false;

	len = (UINT)(colon - address);
	if (len >= 2 && address[0] == '[' && colon[-1] == ']') {
		h = address + 1;
		len -= 2;
	}

	digits = (UINT)strlen(colon + 1);
	if (len >= max || digits == 0 || digits > 5 || digits >= port_max)
		return false;
	for (UINT i = 0; i < digits; i++)
		if (colon[1 + i] < '0' || colon[1 + i] > '9')
			return false;
	if (strtoul(colon + 1, NULL, 10) > 65535)
		return false;

	CopyMemory(host, h, len);
	host[len] = 0;
	CopyMemory(port, colon + 1, digits + 1);

	return true;
}

// A UNICODE_STRING of a CNG name, a literal that stays in the binary
static void TlsCngString(UNICODE_STRING *u, const wchar_t *name) {
	u->Length = (USHORT)(wcslen(name) * sizeof(wchar_t));
	u->MaximumLength = (USHORT)(u->Length + sizeof(wchar_t));
	u->Buffer = (PWSTR)name;
}

//
// The key exchange groups of the machine
//

// Add a group to a REG_MULTI_SZ list being built, if it fits with the NUL that ends the list
static void TlsAddGroup(wchar_t *list, UINT *pos, const wchar_t *group) {
	UINT len = (UINT)wcslen(group);

	if (*pos + len + 2 > TLS_GROUPS_SIZE)
		return;

	CopyMemory(list + *pos, group, (len + 1) * sizeof(wchar_t));
	*pos += len + 1;
}

UINT TransportTlsSetGroups() {
	wchar_t old[TLS_GROUPS_SIZE];
	wchar_t list[TLS_GROUPS_SIZE];
	DWORD size = sizeof(old) - 2 * sizeof(wchar_t);
	DWORD policy_size = 0;
	UINT pos = 0;
	HKEY key = NULL;
	LSTATUS r;

	// An ECC Curve Order policy overrides the machine's list: it stays as the administrator set it
	if (RegGetValueW(HKEY_LOCAL_MACHINE, TLS_GROUPS_POLICY, TLS_GROUPS_VALUE, RRF_RT_ANY, NULL, NULL, &policy_size) == ERROR_SUCCESS)
		return TRANSPORT_TLS_GROUPS_POLICY;

	// The machine's list, or the default one where it has none of its own. The last two characters of
	// the buffer stay NUL, so a list without its last NUL still ends.
	ZeroMemory(old, sizeof(old));
	r = RegGetValueW(HKEY_LOCAL_MACHINE, TLS_GROUPS_KEY, TLS_GROUPS_VALUE, RRF_RT_REG_MULTI_SZ, NULL, old, &size);
	if (r == ERROR_FILE_NOT_FOUND) {
		CopyMemory(old, tls_default_groups, sizeof(tls_default_groups));
		size = 0;
	} else if (r != ERROR_SUCCESS) {
		return TRANSPORT_TLS_GROUPS_FAILED;
	}

	// The transport's groups first, the hybrid only where the OS has ML-KEM; the others after them
	ZeroMemory(list, sizeof(list));
	if (CryptoMlKemAvailable())
		TlsAddGroup(list, &pos, TLS_GROUP_HYBRID);
	TlsAddGroup(list, &pos, TLS_GROUP_X25519);
	for (const wchar_t *g = old; *g != 0; g += wcslen(g) + 1)
		if (_wcsicmp(g, TLS_GROUP_HYBRID) != 0 && _wcsicmp(g, TLS_GROUP_X25519) != 0)
			TlsAddGroup(list, &pos, g);

	// Each group with its NUL, and the NUL that ends the list; a list that has it already stays
	DWORD list_size = (DWORD)((pos + 1) * sizeof(wchar_t));
	if (list_size > sizeof(list))
		return TRANSPORT_TLS_GROUPS_FAILED;
	if (list_size == size && memcmp(list, old, list_size) == 0)
		return TRANSPORT_TLS_GROUPS_SET;

	r = RegCreateKeyExW(HKEY_LOCAL_MACHINE, TLS_GROUPS_KEY, 0, NULL, 0, KEY_SET_VALUE, NULL, &key, NULL);
	if (r == ERROR_SUCCESS) {
		r = RegSetValueExW(key, TLS_GROUPS_VALUE, 0, REG_MULTI_SZ, (const BYTE *)list, list_size);
		RegCloseKey(key);
	}

	return (r == ERROR_SUCCESS ? TRANSPORT_TLS_GROUPS_SET : TRANSPORT_TLS_GROUPS_FAILED);
}

//
// The ServerHello
//

// A big-endian value of n bytes (1 to 3) into *value; false when the message has fewer left
static bool TlsGet(TLS_READER *r, UINT n, UINT *value) {
	UINT v = 0;

	if (n > r->Size - r->Pos)
		return false;

	for (UINT i = 0; i < n; i++)
		v = (v << 8) | r->Data[r->Pos + i];
	r->Pos += n;
	*value = v;

	return true;
}

// Step over n bytes; false when the message has fewer left
static bool TlsSkip(TLS_READER *r, UINT n) {
	if (n > r->Size - r->Pos)
		return false;

	r->Pos += n;
	return true;
}

// The extensions of a ServerHello: the version of supported_versions and the group of key_share,
// which a ServerHello has with its key and a HelloRetryRequest without
static bool TlsParseExtensions(TLS_READER *b, UINT *version, UINT *group) {
	UINT total = 0;

	if (TlsGet(b, 2, &total) == false || total != b->Size - b->Pos)
		return false;

	while (b->Pos < b->Size) {
		UINT type = 0, len = 0;

		if (TlsGet(b, 2, &type) == false || TlsGet(b, 2, &len) == false || len > b->Size - b->Pos)
			return false;

		TLS_READER e = {b->Data + b->Pos, len, 0};
		if (type == TLS_EXT_VERSIONS && TlsGet(&e, 2, version) == false)
			return false;
		if (type == TLS_EXT_KEY_SHARE && TlsGet(&e, 2, group) == false)
			return false;
		b->Pos += len;
	}

	return true;
}

bool TransportTlsParseHello(const UCHAR *data, UINT size, TRANSPORT_TLS_INFO *info) {
	TRANSPORT_TLS_INFO h;
	UINT type = 0, length = 0, msg_type = 0, msg_size = 0;
	UINT version = 0, session_id = 0, suite = 0, compression = 0, group = 0;

	if (data == NULL || info == NULL)
		return false;

	// The ChangeCipherSpec records of the middlebox compatibility mode, then a handshake record
	TLS_READER r = {data, size, 0};
	while (true) {
		if (TlsGet(&r, 1, &type) == false || TlsSkip(&r, 2) == false || TlsGet(&r, 2, &length) == false)
			return false;
		if (type != TLS_CONTENT_CCS)
			break;
		if (TlsSkip(&r, length) == false)
			return false;
	}
	if (type != TLS_CONTENT_HANDSHAKE || length > r.Size - r.Pos)
		return false;

	// The record starts with the whole ServerHello
	TLS_READER m = {data + r.Pos, length, 0};
	if (TlsGet(&m, 1, &msg_type) == false || msg_type != TLS_SERVER_HELLO || TlsGet(&m, 3, &msg_size) == false || msg_size > m.Size - m.Pos)
		return false;

	TLS_READER b = {m.Data + m.Pos, msg_size, 0};
	ZeroMemory(&h, sizeof(h));
	if (TlsGet(&b, 2, &version) == false || b.Size - b.Pos < TLS_RANDOM_SIZE)
		return false;
	h.Retried = (memcmp(b.Data + b.Pos, tls_retry_random, TLS_RANDOM_SIZE) == 0);
	if (TlsSkip(&b, TLS_RANDOM_SIZE) == false || TlsGet(&b, 1, &session_id) == false || TlsSkip(&b, session_id) == false ||
	    TlsGet(&b, 2, &suite) == false || TlsGet(&b, 1, &compression) == false)
		return false;

	// A TLS 1.2 ServerHello may have no extensions; TLS 1.3 names its version in supported_versions
	if (b.Pos < b.Size && TlsParseExtensions(&b, &version, &group) == false)
		return false;
	if (version == TLS_VERSION_13)
		h.Version = TRANSPORT_TLS_13;
	else if (version == TLS_VERSION_12)
		h.Version = TRANSPORT_TLS_12;
	else
		return false;

	h.CipherSuite = suite;
	h.Group = (h.Version == TRANSPORT_TLS_13 ? group : 0);
	*info = h;

	return true;
}

//
// The sockets
//

// The options of a stream's socket: blocking, one write is one send (no wait for the
// acknowledgement of the one before), and a send that the peer does not take in time fails
static bool TlsSocketReady(SOCKET s) {
	u_long blocking = 0;
	BOOL nodelay = TRUE;
	DWORD timeout = TLS_SEND_TIMEOUT;

	return (ioctlsocket(s, FIONBIO, &blocking) == 0 && setsockopt(s, IPPROTO_TCP, TCP_NODELAY, (const char *)&nodelay, sizeof(nodelay)) == 0 &&
	        setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, (const char *)&timeout, sizeof(timeout)) == 0);
}

// Send size bytes; false when the connection failed
static bool TlsSend(SOCKET s, const void *buf, UINT size) {
	const char *p = (const char *)buf;

	while (size != 0) {
		int n = send(s, p, (int)(size < 65536 ? size : 65536), 0);

		if (n <= 0)
			return false;
		p += n;
		size -= (UINT)n;
	}

	return true;
}

// Wait until the socket has bytes or its end: 1; 0 once end passed or cancel (which may be NULL) was
// set, which is looked at every TLS_POLL ms; -1 on an error. The socket is looked at once at least.
static int TlsWait(SOCKET s, HANDLE cancel, UINT64 end) {
	while (true) {
		UINT64 now = GetTickCount64();
		UINT64 left = (now < end ? end - now : 0);
		WSAPOLLFD p;

		if (cancel != NULL && WaitForSingleObject(cancel, 0) == WAIT_OBJECT_0)
			return 0;
		if (cancel != NULL && left > TLS_POLL)
			left = TLS_POLL;
		if (left > MAXINT)
			left = MAXINT;

		ZeroMemory(&p, sizeof(p));
		p.fd = s;
		p.events = POLLRDNORM;
		int r = WSAPoll(&p, 1, (INT)left);
		if (r != 0)
			return (r > 0 ? 1 : -1);
		if (GetTickCount64() >= end)
			return 0;
	}
}

// Wait until a connect completes: true when it did, false when it failed or cancel was set. A
// connect that failed shows in SO_ERROR while the socket is not writable.
static bool TlsConnectWait(SOCKET s, HANDLE cancel) {
	while (true) {
		WSAPOLLFD p;
		int error = 0, error_size = sizeof(error);

		if (cancel != NULL && WaitForSingleObject(cancel, 0) == WAIT_OBJECT_0)
			return false;

		ZeroMemory(&p, sizeof(p));
		p.fd = s;
		p.events = POLLWRNORM;
		int r = WSAPoll(&p, 1, TLS_POLL);
		if (r < 0 || (r > 0 && (p.revents & (POLLERR | POLLHUP)) != 0))
			return false;
		if (getsockopt(s, SOL_SOCKET, SO_ERROR, (char *)&error, &error_size) != 0 || error != 0)
			return false;
		if (r > 0)
			return true;
	}
}

// A TCP connection to one address, connected without blocking so that cancel is seen
static SOCKET TlsConnectOne(const struct addrinfo *a, HANDLE cancel) {
	u_long nonblocking = 1;
	SOCKET s = socket(a->ai_family, a->ai_socktype, a->ai_protocol);

	if (s == INVALID_SOCKET)
		return INVALID_SOCKET;

	bool ok = (ioctlsocket(s, FIONBIO, &nonblocking) == 0);
	if (ok && connect(s, a->ai_addr, (int)a->ai_addrlen) != 0)
		ok = (WSAGetLastError() == WSAEWOULDBLOCK && TlsConnectWait(s, cancel));
	if (ok)
		ok = TlsSocketReady(s);

	if (ok == false) {
		closesocket(s);
		return INVALID_SOCKET;
	}

	return s;
}

// A TCP connection to host and port, the addresses of the host in turn; INVALID_SOCKET when none
// answers or cancel was set
static SOCKET TlsConnect(const char *host, const char *port, HANDLE cancel) {
	struct addrinfo hints, *res = NULL;
	SOCKET s = INVALID_SOCKET;

	ZeroMemory(&hints, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;
	if (getaddrinfo(host, port, &hints, &res) != 0)
		return INVALID_SOCKET;

	for (const struct addrinfo *a = res; a != NULL && s == INVALID_SOCKET; a = a->ai_next)
		s = TlsConnectOne(a, cancel);
	freeaddrinfo(res);

	return s;
}

// A listening socket on host and port: every address of both families where host is empty. It is
// held exclusively, as the harness holds its ports, and the port it bound goes to the transport.
static SOCKET TlsListenSocket(TLS_NET *net, const char *host, const char *port) {
	struct addrinfo hints, *res = NULL;
	struct sockaddr_storage local;
	int local_size = sizeof(local);
	DWORD on = 1, off = 0;

	ZeroMemory(&hints, sizeof(hints));
	hints.ai_family = (host[0] == 0 ? AF_INET6 : AF_UNSPEC);
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;
	hints.ai_flags = AI_PASSIVE;
	if (getaddrinfo(host[0] == 0 ? NULL : host, port, &hints, &res) != 0)
		return INVALID_SOCKET;

	SOCKET s = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
	bool ok = (s != INVALID_SOCKET && setsockopt(s, SOL_SOCKET, SO_EXCLUSIVEADDRUSE, (const char *)&on, sizeof(on)) == 0);
	// Every address: the IPv6 socket takes IPv4 as well
	if (ok && host[0] == 0)
		ok = (setsockopt(s, IPPROTO_IPV6, IPV6_V6ONLY, (const char *)&off, sizeof(off)) == 0);
	ZeroMemory(&local, sizeof(local));
	if (ok)
		ok = (bind(s, res->ai_addr, (int)res->ai_addrlen) == 0 && listen(s, SOMAXCONN) == 0 && getsockname(s, (struct sockaddr *)&local, &local_size) == 0);
	freeaddrinfo(res);

	if (ok == false) {
		if (s != INVALID_SOCKET)
			closesocket(s);
		return INVALID_SOCKET;
	}

	USHORT bound = (local.ss_family == AF_INET6 ? ((struct sockaddr_in6 *)&local)->sin6_port : ((struct sockaddr_in *)&local)->sin_port);
	InterlockedExchange(&net->BoundPort, ntohs(bound));

	return s;
}

//
// The streams
//

// Free a stream: its context, its socket and its buffers, wiped
static void TlsStreamFree(TLS_STREAM *s) {
	if (s == NULL)
		return;

	if (s->HaveCtx)
		DeleteSecurityContext(&s->Ctx);
	if (s->Socket != INVALID_SOCKET)
		closesocket(s->Socket);
	TlsRelease(s->In, TLS_IN_SIZE);
	TlsRelease(s->Plain, TLS_RECORD_MAX);
	TlsRelease(s->Out, s->OutSize);
	TlsRelease(s, sizeof(TLS_STREAM));
}

// A new stream of a transport on a connected socket, which it takes: NULL, with the socket closed,
// when there is no memory
static TLS_STREAM *TlsStreamNew(TLS_NET *net, SOCKET sock) {
	TLS_STREAM *s = (TLS_STREAM *)TlsAlloc(sizeof(TLS_STREAM));

	if (s == NULL) {
		closesocket(sock);
		return NULL;
	}

	s->Net = net;
	s->Socket = sock;
	InitializeSRWLock(&s->SendLock);
	InitializeSRWLock(&s->CtxLock);
	s->In = (UCHAR *)TlsAlloc(TLS_IN_SIZE);
	s->Plain = (UCHAR *)TlsAlloc(TLS_RECORD_MAX);
	if (s->In == NULL || s->Plain == NULL) {
		TlsStreamFree(s);
		return NULL;
	}

	return s;
}

// Keep the last extra bytes of In, the ones that a call on the context did not take
static void TlsKeep(TLS_STREAM *s, UINT extra) {
	if (extra == 0 || extra > s->InSize) {
		s->InSize = 0;
		return;
	}

	MoveMemory(s->In, s->In + s->InSize - extra, extra);
	s->InSize = extra;
}

// Read what came on the socket into In: the number of bytes; 0 when the stream ended or In has no
// room; TRANSPORT_LATER when nothing came before end or cancel
static UINT TlsReceive(TLS_STREAM *s, HANDLE cancel, UINT64 end) {
	int ready = TlsWait(s->Socket, cancel, end);

	if (ready == 0)
		return TRANSPORT_LATER;
	if (ready < 0 || s->InSize >= TLS_IN_SIZE)
		return 0;

	int n = recv(s->Socket, (char *)s->In + s->InSize, (int)(TLS_IN_SIZE - s->InSize), 0);
	if (n <= 0)
		return 0;

	s->InSize += (UINT)n;
	return (UINT)n;
}

// What the server chose, from a ServerHello at the start of data. A HelloRetryRequest comes first
// and the ServerHello after it, which keeps that there was a retry.
static void TlsHello(TLS_STREAM *s, const UCHAR *data, UINT size) {
	TRANSPORT_TLS_INFO hello;

	ZeroMemory(&hello, sizeof(hello));
	if (TransportTlsParseHello(data, size, &hello) == false)
		return;

	if (s->Info.Retried)
		hello.Retried = true;
	s->Info = hello;
}

// One InitializeSecurityContext (the client) or AcceptSecurityContext (the server) on the records
// that In holds, none for the client's first: its token goes to the peer, and In keeps the bytes the
// context did not take. The client reads what the server chose from the ServerHello among the
// server's records, the server from its own.
static SECURITY_STATUS TlsStep(TLS_STREAM *s, bool input) {
	TLS_NET *net = s->Net;
	SecBuffer in[2], out[1];
	SecBufferDesc in_desc, out_desc;
	ULONG attr = 0;
	TimeStamp expiry;
	SECURITY_STATUS r;

	in[0].BufferType = SECBUFFER_TOKEN;
	in[0].cbBuffer = s->InSize;
	in[0].pvBuffer = s->In;
	in[1].BufferType = SECBUFFER_EMPTY;
	in[1].cbBuffer = 0;
	in[1].pvBuffer = NULL;
	in_desc.ulVersion = SECBUFFER_VERSION;
	in_desc.cBuffers = 2;
	in_desc.pBuffers = in;

	out[0].BufferType = SECBUFFER_TOKEN;
	out[0].cbBuffer = 0;
	out[0].pvBuffer = NULL;
	out_desc.ulVersion = SECBUFFER_VERSION;
	out_desc.cBuffers = 1;
	out_desc.pBuffers = out;

	if (net->Server == false && input)
		TlsHello(s, s->In, s->InSize);

	if (net->Server)
		r = AcceptSecurityContext(&net->Cred, s->HaveCtx ? &s->Ctx : NULL, &in_desc, TLS_ASC_FLAGS, 0, &s->Ctx, &out_desc, &attr, &expiry);
	else
		r = InitializeSecurityContextW(&net->Cred, s->HaveCtx ? &s->Ctx : NULL, s->Target, TLS_ISC_FLAGS, 0, 0, input ? &in_desc : NULL, 0, &s->Ctx, &out_desc, &attr, &expiry);

	if (r == SEC_E_OK || r == SEC_I_CONTINUE_NEEDED)
		s->HaveCtx = true;

	if (out[0].pvBuffer != NULL) {
		if (net->Server)
			TlsHello(s, (const UCHAR *)out[0].pvBuffer, out[0].cbBuffer);
		if (out[0].cbBuffer != 0 && TlsSend(s->Socket, out[0].pvBuffer, out[0].cbBuffer) == false && (r == SEC_E_OK || r == SEC_I_CONTINUE_NEEDED))
			r = SEC_E_INTERNAL_ERROR;
		FreeContextBuffer(out[0].pvBuffer);
	}

	if (r == SEC_E_OK || r == SEC_I_CONTINUE_NEEDED)
		TlsKeep(s, in[1].BufferType == SECBUFFER_EXTRA ? in[1].cbBuffer : 0);

	return r;
}

// The client's pin: the certificate that the server presented is the configured one
static bool TlsCheckPin(TLS_STREAM *s) {
	PCCERT_CONTEXT cert = NULL;
	UCHAR thumbprint[CRYPTO_THUMBPRINT_SIZE];

	ZeroMemory(thumbprint, sizeof(thumbprint));
	bool ok = (QueryContextAttributesW(&s->Ctx, SECPKG_ATTR_REMOTE_CERT_CONTEXT, (void *)&cert) == SEC_E_OK && cert != NULL &&
	           CryptoCertThumbprint(cert, thumbprint) && memcmp(thumbprint, s->Net->Thumbprint, CRYPTO_THUMBPRINT_SIZE) == 0);

	CryptoCertFree(cert);
	return ok;
}

// The TLS exporter of the session, the channel binding of the stream: NOISE_EXPORTER_LABEL, no
// context, NOISE_EXPORTER_SIZE bytes (RFC 8446 section 7.5, RFC 5705 for TLS 1.2). The label's
// length counts its NUL, which Schannel takes off.
static bool TlsExporter(TLS_STREAM *s) {
	SecPkgContext_KeyingMaterialInfo info;
	SecPkgContext_KeyingMaterial material;

	ZeroMemory(&info, sizeof(info));
	ZeroMemory(&material, sizeof(material));
	info.cbLabel = (WORD)sizeof(NOISE_EXPORTER_LABEL);
	info.pszLabel = (LPSTR)NOISE_EXPORTER_LABEL;
	info.cbKeyingMaterial = NOISE_EXPORTER_SIZE;

	bool ok = (SetContextAttributesW(&s->Ctx, SECPKG_ATTR_KEYING_MATERIAL_INFO, &info, sizeof(info)) == SEC_E_OK &&
	           QueryContextAttributesW(&s->Ctx, SECPKG_ATTR_KEYING_MATERIAL, &material) == SEC_E_OK && material.pbKeyingMaterial != NULL &&
	           material.cbKeyingMaterial == NOISE_EXPORTER_SIZE);
	if (ok)
		CopyMemory(s->Binding, material.pbKeyingMaterial, NOISE_EXPORTER_SIZE);

	if (material.pbKeyingMaterial != NULL) {
		SecureZeroMemory(material.pbKeyingMaterial, material.cbKeyingMaterial);
		FreeContextBuffer(material.pbKeyingMaterial);
	}

	return ok;
}

// The session of a stream whose handshake completed: its record sizes and the buffer of a record
// being written, its version and suite, and the exporter that binds the Noise session to it. The
// transport keeps what the handshake gave as its last.
static bool TlsOpen(TLS_STREAM *s) {
	TLS_NET *net = s->Net;
	SecPkgContext_ConnectionInfo conn;
	SecPkgContext_CipherInfo cipher;

	ZeroMemory(&conn, sizeof(conn));
	ZeroMemory(&cipher, sizeof(cipher));
	if (QueryContextAttributesW(&s->Ctx, SECPKG_ATTR_STREAM_SIZES, &s->Sizes) != SEC_E_OK || s->Sizes.cbMaximumMessage == 0 ||
	    QueryContextAttributesW(&s->Ctx, SECPKG_ATTR_CONNECTION_INFO, &conn) != SEC_E_OK)
		return false;

	if ((conn.dwProtocol & SP_PROT_TLS1_3) != 0)
		s->Info.Version = TRANSPORT_TLS_13;
	else if ((conn.dwProtocol & SP_PROT_TLS1_2) != 0)
		s->Info.Version = TRANSPORT_TLS_12;
	else
		return false;
	if (QueryContextAttributesW(&s->Ctx, SECPKG_ATTR_CIPHER_INFO, &cipher) == SEC_E_OK)
		s->Info.CipherSuite = cipher.dwCipherSuite;
	// TLS 1.2 chooses its group in the ServerKeyExchange, which the transport does not read
	if (s->Info.Version == TRANSPORT_TLS_12)
		s->Info.Group = 0;

	s->OutSize = s->Sizes.cbHeader + s->Sizes.cbMaximumMessage + s->Sizes.cbTrailer;
	s->Out = (UCHAR *)TlsAlloc(s->OutSize);
	if (s->Out == NULL || TlsExporter(s) == false)
		return false;

	s->Open = true;

	AcquireSRWLockExclusive(&net->Lock);
	net->Last = s->Info;
	net->HaveLast = true;
	ReleaseSRWLockExclusive(&net->Lock);

	return true;
}

// The TLS handshake of a new stream within TLS_HANDSHAKE: the client speaks first, the server
// answers its ClientHello, and a client checks its pin. cancel, which may be NULL, stops it.
static bool TlsHandshake(TLS_STREAM *s, HANDLE cancel) {
	UINT64 end = GetTickCount64() + TLS_HANDSHAKE;
	SECURITY_STATUS r = (s->Net->Server ? SEC_E_INCOMPLETE_MESSAGE : TlsStep(s, false));

	while (r == SEC_I_CONTINUE_NEEDED || r == SEC_E_INCOMPLETE_MESSAGE) {
		// More of the peer's records, unless In holds some that the context did not look at yet
		if (r == SEC_E_INCOMPLETE_MESSAGE || s->InSize == 0) {
			UINT got = TlsReceive(s, cancel, end);
			if (got == 0 || got == TRANSPORT_LATER)
				return false;
		}
		r = TlsStep(s, true);
	}

	return (r == SEC_E_OK && (s->Net->Server || TlsCheckPin(s)) && TlsOpen(s));
}

// The context takes the post-handshake message that In starts with (a KeyUpdate, a
// NewSessionTicket), and its answer, if any, goes out before the record of any later write
static bool TlsPostHandshake(TLS_STREAM *s) {
	AcquireSRWLockExclusive(&s->SendLock);
	AcquireSRWLockExclusive(&s->CtxLock);
	SECURITY_STATUS r = TlsStep(s, true);
	ReleaseSRWLockExclusive(&s->CtxLock);
	ReleaseSRWLockExclusive(&s->SendLock);

	return (r == SEC_E_OK);
}

// Decrypt the next record that In holds into Plain: TLS_RECORD_DATA, TLS_RECORD_MORE or
// TLS_RECORD_END. A record is decrypted in place, and its bytes are copied out before In keeps the
// records after it. A post-handshake message of TLS 1.3 comes back with its record as the extra
// bytes, which the context then takes (SEC_I_RENEGOTIATE); the close_notify (SEC_I_CONTEXT_EXPIRED)
// and every error end the stream.
static UINT TlsDecrypt(TLS_STREAM *s) {
	SecBuffer b[4];
	SecBufferDesc desc;
	const SecBuffer *data = NULL;
	UINT extra = 0;

	if (s->InSize == 0)
		return TLS_RECORD_MORE;

	b[0].BufferType = SECBUFFER_DATA;
	b[0].cbBuffer = s->InSize;
	b[0].pvBuffer = s->In;
	for (UINT i = 1; i < 4; i++) {
		b[i].BufferType = SECBUFFER_EMPTY;
		b[i].cbBuffer = 0;
		b[i].pvBuffer = NULL;
	}
	desc.ulVersion = SECBUFFER_VERSION;
	desc.cBuffers = 4;
	desc.pBuffers = b;

	AcquireSRWLockExclusive(&s->CtxLock);
	SECURITY_STATUS r = DecryptMessage(&s->Ctx, &desc, 0, NULL);
	ReleaseSRWLockExclusive(&s->CtxLock);

	for (UINT i = 0; i < 4; i++) {
		if (b[i].BufferType == SECBUFFER_DATA && data == NULL)
			data = &b[i];
		else if (b[i].BufferType == SECBUFFER_EXTRA)
			extra = b[i].cbBuffer;
	}

	if (r == SEC_E_INCOMPLETE_MESSAGE)
		return TLS_RECORD_MORE;

	if (r == SEC_E_OK) {
		if (data != NULL && data->cbBuffer != 0) {
			if (data->cbBuffer > TLS_RECORD_MAX)
				return TLS_RECORD_END;
			CopyMemory(s->Plain, data->pvBuffer, data->cbBuffer);
			s->PlainStart = 0;
			s->PlainSize = data->cbBuffer;
		}
		TlsKeep(s, extra);
		return TLS_RECORD_DATA;
	}

	if (r == SEC_I_RENEGOTIATE) {
		TlsKeep(s, extra);
		return (TlsPostHandshake(s) ? TLS_RECORD_DATA : TLS_RECORD_END);
	}

	return TLS_RECORD_END;
}

static UINT TlsStreamRead(void *stream, void *buf, UINT size, UINT timeout) {
	TLS_STREAM *s = (TLS_STREAM *)stream;
	UINT64 end = (timeout == INFINITE ? MAXUINT64 : GetTickCount64() + timeout);

	while (true) {
		// The bytes of a record decrypted before
		if (s->PlainSize != 0) {
			UINT n = (size < s->PlainSize ? size : s->PlainSize);

			CopyMemory(buf, s->Plain + s->PlainStart, n);
			SecureZeroMemory(s->Plain + s->PlainStart, n);
			s->PlainStart += n;
			s->PlainSize -= n;
			return n;
		}
		if (s->Ended)
			return 0;

		UINT r = TlsDecrypt(s);
		if (r == TLS_RECORD_END)
			s->Ended = true;
		if (r != TLS_RECORD_MORE)
			continue;

		// The rest of a record, within the timeout
		UINT got = TlsReceive(s, NULL, end);
		if (got == TRANSPORT_LATER)
			return TRANSPORT_LATER;
		if (got == 0)
			s->Ended = true;
	}
}

// Encrypt n bytes into one record in Out and send it, under SendLock
static bool TlsWriteRecord(TLS_STREAM *s, const UCHAR *data, UINT n) {
	SecBuffer b[4];
	SecBufferDesc desc;
	WSABUF w[3];
	DWORD sent = 0;

	CopyMemory(s->Out + s->Sizes.cbHeader, data, n);
	b[0].BufferType = SECBUFFER_STREAM_HEADER;
	b[0].cbBuffer = s->Sizes.cbHeader;
	b[0].pvBuffer = s->Out;
	b[1].BufferType = SECBUFFER_DATA;
	b[1].cbBuffer = n;
	b[1].pvBuffer = s->Out + s->Sizes.cbHeader;
	b[2].BufferType = SECBUFFER_STREAM_TRAILER;
	b[2].cbBuffer = s->Sizes.cbTrailer;
	b[2].pvBuffer = s->Out + s->Sizes.cbHeader + n;
	b[3].BufferType = SECBUFFER_EMPTY;
	b[3].cbBuffer = 0;
	b[3].pvBuffer = NULL;
	desc.ulVersion = SECBUFFER_VERSION;
	desc.cBuffers = 4;
	desc.pBuffers = b;

	AcquireSRWLockExclusive(&s->CtxLock);
	SECURITY_STATUS r = EncryptMessage(&s->Ctx, 0, &desc, 0);
	ReleaseSRWLockExclusive(&s->CtxLock);
	if (r != SEC_E_OK)
		return false;

	// The header, the bytes and the trailer as they came out: a trailer may be shorter than its
	// largest size
	UINT total = 0;
	for (UINT i = 0; i < 3; i++) {
		w[i].len = b[i].cbBuffer;
		w[i].buf = (char *)b[i].pvBuffer;
		total += b[i].cbBuffer;
	}

	return (WSASend(s->Socket, w, 3, &sent, 0, NULL, NULL) == 0 && sent == total);
}

static bool TlsStreamWrite(void *stream, const void *buf, UINT size) {
	TLS_STREAM *s = (TLS_STREAM *)stream;
	const UCHAR *p = (const UCHAR *)buf;
	bool ok = true;

	AcquireSRWLockExclusive(&s->SendLock);
	while (ok && size != 0) {
		UINT n = (size < s->Sizes.cbMaximumMessage ? size : (UINT)s->Sizes.cbMaximumMessage);

		ok = TlsWriteRecord(s, p, n);
		p += n;
		size -= n;
	}
	ReleaseSRWLockExclusive(&s->SendLock);

	return ok;
}

// The close_notify of the session, which the context makes once the shutdown token is applied
static void TlsShutdown(TLS_STREAM *s) {
	TLS_NET *net = s->Net;
	DWORD type = SCHANNEL_SHUTDOWN;
	SecBuffer token, out;
	SecBufferDesc token_desc, out_desc;
	ULONG attr = 0;
	TimeStamp expiry;
	SECURITY_STATUS r;

	token.BufferType = SECBUFFER_TOKEN;
	token.cbBuffer = sizeof(type);
	token.pvBuffer = &type;
	token_desc.ulVersion = SECBUFFER_VERSION;
	token_desc.cBuffers = 1;
	token_desc.pBuffers = &token;
	if (ApplyControlToken(&s->Ctx, &token_desc) != SEC_E_OK)
		return;

	out.BufferType = SECBUFFER_TOKEN;
	out.cbBuffer = 0;
	out.pvBuffer = NULL;
	out_desc.ulVersion = SECBUFFER_VERSION;
	out_desc.cBuffers = 1;
	out_desc.pBuffers = &out;

	if (net->Server)
		r = AcceptSecurityContext(&net->Cred, &s->Ctx, NULL, TLS_ASC_FLAGS, 0, NULL, &out_desc, &attr, &expiry);
	else
		r = InitializeSecurityContextW(&net->Cred, &s->Ctx, s->Target, TLS_ISC_FLAGS, 0, 0, NULL, 0, &s->Ctx, &out_desc, &attr, &expiry);

	if (out.pvBuffer != NULL) {
		if (r >= 0 && out.cbBuffer != 0)
			(void)TlsSend(s->Socket, out.pvBuffer, out.cbBuffer);
		FreeContextBuffer(out.pvBuffer);
	}
}

static void TlsStreamClose(void *stream) {
	TLS_STREAM *s = (TLS_STREAM *)stream;
	char drain[1024];

	if (s == NULL)
		return;

	// The close_notify while the session is open, then the end of the stream; then the peer's bytes
	// up to its own end, so that no unread byte turns the close into a reset that could overtake the
	// last record
	if (s->Open)
		TlsShutdown(s);
	shutdown(s->Socket, SD_SEND);

	UINT64 end = GetTickCount64() + TLS_LINGER;
	while (TlsWait(s->Socket, NULL, end) == 1) {
		if (recv(s->Socket, drain, sizeof(drain), 0) <= 0)
			break;
	}

	TlsStreamFree(s);
}

static UINT TlsStreamBinding(void *stream, UCHAR *binding, UINT max, UINT *size) {
	TLS_STREAM *s = (TLS_STREAM *)stream;

	*size = 0;
	if (max < NOISE_EXPORTER_SIZE)
		return NOISE_BINDING_NONE;

	CopyMemory(binding, s->Binding, NOISE_EXPORTER_SIZE);
	*size = NOISE_EXPORTER_SIZE;

	// The mismatch test: a client that computes a binding of its own, as a middlebox that
	// terminated the TLS would, so the two prologues differ and the handshake is closed
	if (s->Net->Server == false && s->Net->Cfg.BreakBinding)
		binding[0] ^= 0xFF;

	return NOISE_BINDING_EXPORTER;
}

static bool TlsStreamRekey(void *stream) {
	// Schannel takes and answers the peer's KeyUpdate (a post-handshake message of a read), but SSPI
	// has no call that sends one. The session asks for the update of the outer keys on its schedule,
	// and an update that is not sent does not fail the session.
	UNREFERENCED_PARAMETER(stream);
	return true;
}

//
// The listener
//

// Free a listener whose wait is not set any more: close the members of the cleanup group, which
// waits for every callback that runs, then the socket and the events
static void TlsListenerFree(TLS_LISTENER *l) {
	if (l->Group != NULL) {
		CloseThreadpoolCleanupGroupMembers(l->Group, FALSE, NULL);
		CloseThreadpoolCleanupGroup(l->Group);
	}
	DestroyThreadpoolEnvironment(&l->Env);

	if (l->Socket != INVALID_SOCKET)
		closesocket(l->Socket);
	if (l->Event != WSA_INVALID_EVENT)
		WSACloseEvent(l->Event);
	if (l->Closing != NULL)
		CloseHandle(l->Closing);

	TlsRelease(l, sizeof(TLS_LISTENER));
}

// The handshake of a connection that the listener took, on a callback of the pool: a stream whose
// handshake completed goes to the backlog
static void CALLBACK TlsHandshakeCallback(PTP_CALLBACK_INSTANCE instance, void *param) {
	TLS_ACCEPTED *a = (TLS_ACCEPTED *)param;
	TLS_LISTENER *l = a->Listener;
	TLS_STREAM *s = TlsStreamNew(l->Net, a->Socket);

	// It waits for the peer: the pool starts another thread for the next callback
	(void)CallbackMayRunLong(instance);
	TlsRelease(a, sizeof(TLS_ACCEPTED));

	if (s == NULL)
		return;
	if (TlsHandshake(s, l->Closing) == false) {
		TlsStreamFree(s);
		return;
	}

	AcquireSRWLockExclusive(&l->Lock);
	if (l->Closed == false && l->NumQueued < TLS_BACKLOG) {
		l->Queue[l->NumQueued++] = s;
		s = NULL;
		WakeAllConditionVariable(&l->Changed);
	}
	ReleaseSRWLockExclusive(&l->Lock);

	// The backlog was full, or the listener closes
	if (s != NULL)
		TlsStreamClose(s);
}

// Run the handshake of a connection that the listener took on a callback of the pool; the socket is
// closed when it cannot start. The connection takes none of the listener's event selection and
// blocks, as a dialled one.
static void TlsStartHandshake(TLS_LISTENER *l, SOCKET s) {
	TLS_ACCEPTED *a = (TLS_ACCEPTED *)TlsAlloc(sizeof(TLS_ACCEPTED));

	if (a == NULL || WSAEventSelect(s, NULL, 0) != 0 || TlsSocketReady(s) == false) {
		closesocket(s);
		TlsRelease(a, sizeof(TLS_ACCEPTED));
		return;
	}

	a->Listener = l;
	a->Socket = s;
	if (TrySubmitThreadpoolCallback(TlsHandshakeCallback, a, &l->Env) == false) {
		closesocket(s);
		TlsRelease(a, sizeof(TLS_ACCEPTED));
	}
}

// The wait of the pool on the listener's event: every connection that waits starts its handshake,
// and the wait is set again unless the listener closes
static void CALLBACK TlsAcceptCallback(PTP_CALLBACK_INSTANCE instance, void *param, PTP_WAIT wait, TP_WAIT_RESULT result) {
	TLS_LISTENER *l = (TLS_LISTENER *)param;
	WSANETWORKEVENTS events;

	UNREFERENCED_PARAMETER(instance);
	UNREFERENCED_PARAMETER(result);

	// Reset the event, then take the connections; one that its peer reset before it was taken is
	// skipped
	ZeroMemory(&events, sizeof(events));
	if (WSAEnumNetworkEvents(l->Socket, l->Event, &events) == 0) {
		while (true) {
			SOCKET s = accept(l->Socket, NULL, NULL);

			if (s != INVALID_SOCKET)
				TlsStartHandshake(l, s);
			else if (WSAGetLastError() != WSAECONNRESET)
				break;
		}
	}

	AcquireSRWLockExclusive(&l->Lock);
	if (l->Closed == false)
		SetThreadpoolWait(wait, l->Event, NULL);
	ReleaseSRWLockExclusive(&l->Lock);
}

static bool TlsListen(void *param, const char *address, void **listener) {
	TLS_NET *net = (TLS_NET *)param;
	char host[TRANSPORT_ADDRESS_SIZE];
	char port[8];

	*listener = NULL;
	if (net->Server == false || TlsSplitAddress(address, host, sizeof(host), port, sizeof(port)) == false)
		return false;

	TLS_LISTENER *l = (TLS_LISTENER *)TlsAlloc(sizeof(TLS_LISTENER));
	if (l == NULL)
		return false;
	l->Net = net;
	InitializeSRWLock(&l->Lock);
	InitializeConditionVariable(&l->Changed);
	InitializeThreadpoolEnvironment(&l->Env);

	l->Socket = TlsListenSocket(net, host, port);
	l->Event = WSACreateEvent();
	l->Closing = CreateEventW(NULL, TRUE, FALSE, NULL);
	l->Group = CreateThreadpoolCleanupGroup();
	bool ok = (l->Socket != INVALID_SOCKET && l->Event != WSA_INVALID_EVENT && l->Closing != NULL && l->Group != NULL);
	if (ok) {
		SetThreadpoolCallbackCleanupGroup(&l->Env, l->Group, NULL);
		l->Wait = CreateThreadpoolWait(TlsAcceptCallback, l, &l->Env);
		ok = (l->Wait != NULL && WSAEventSelect(l->Socket, l->Event, FD_ACCEPT) == 0);
	}
	if (ok == false) {
		TlsListenerFree(l);
		return false;
	}

	SetThreadpoolWait(l->Wait, l->Event, NULL);

	*listener = l;
	return true;
}

static bool TlsAccept(void *listener, UINT timeout, void **stream) {
	TLS_LISTENER *l = (TLS_LISTENER *)listener;
	UINT64 end = GetTickCount64() + timeout;

	*stream = NULL;

	AcquireSRWLockExclusive(&l->Lock);
	l->NumWaiting++;
	while (l->NumQueued == 0 && l->Closed == false) {
		DWORD wait = INFINITE;

		if (timeout != INFINITE) {
			UINT64 now = GetTickCount64();
			if (now >= end)
				break;
			wait = (DWORD)(end - now);
		}
		SleepConditionVariableSRW(&l->Changed, &l->Lock, wait, 0);
	}

	if (l->NumQueued != 0 && l->Closed == false) {
		*stream = l->Queue[0];
		l->NumQueued--;
		MoveMemory(l->Queue, l->Queue + 1, sizeof(TLS_STREAM *) * l->NumQueued);
	}
	l->NumWaiting--;
	WakeAllConditionVariable(&l->Changed);
	ReleaseSRWLockExclusive(&l->Lock);

	return (*stream != NULL);
}

static void TlsCloseListener(void *listener) {
	TLS_LISTENER *l = (TLS_LISTENER *)listener;
	TLS_STREAM *drop[TLS_BACKLOG] = {NULL};
	UINT num;

	// No wait is set again once Closed is: the one that is set is taken back, and its callback, if
	// one runs, returns first. The handshakes in progress see Closing, and queue nothing more.
	AcquireSRWLockExclusive(&l->Lock);
	l->Closed = true;
	WakeAllConditionVariable(&l->Changed);
	ReleaseSRWLockExclusive(&l->Lock);
	SetEvent(l->Closing);
	SetThreadpoolWait(l->Wait, NULL, NULL);
	WaitForThreadpoolWaitCallbacks(l->Wait, FALSE);

	// The streams that nobody accepted, once the Accept calls that wait returned
	AcquireSRWLockExclusive(&l->Lock);
	num = l->NumQueued;
	for (UINT i = 0; i < num; i++)
		drop[i] = l->Queue[i];
	l->NumQueued = 0;
	while (l->NumWaiting != 0)
		SleepConditionVariableSRW(&l->Changed, &l->Lock, INFINITE, 0);
	ReleaseSRWLockExclusive(&l->Lock);

	for (UINT i = 0; i < num; i++)
		TlsStreamClose(drop[i]);

	TlsListenerFree(l);
}

//
// The dialler
//

static bool TlsDial(void *param, const char *address, HANDLE cancel, void **stream) {
	TLS_NET *net = (TLS_NET *)param;
	char host[TRANSPORT_ADDRESS_SIZE];
	char port[8];

	*stream = NULL;
	if (net->Server || TlsSplitAddress(address, host, sizeof(host), port, sizeof(port)) == false || host[0] == 0)
		return false;

	SOCKET sock = TlsConnect(host, port, cancel);
	if (sock == INVALID_SOCKET)
		return false;

	TLS_STREAM *s = TlsStreamNew(net, sock);
	if (s == NULL)
		return false;

	// The server's name in the handshake is the host of the address
	if (MultiByteToWideChar(CP_UTF8, 0, host, -1, s->Target, TRANSPORT_ADDRESS_SIZE) == 0 || TlsHandshake(s, cancel) == false) {
		TlsStreamFree(s);
		return false;
	}

	*stream = s;
	return true;
}

//
// The transport
//

// The credential of the transport: TLS 1.3 and 1.2, or the versions of the configuration; AES-GCM
// only (no ChaCha20-Poly1305, no AES in CBC or CCM mode, no 3DES) and an ephemeral key exchange only
// (no static RSA, no finite-field DHE). The server presents its certificate and keeps no session for
// a later resumption, so every handshake is a full one with a fresh key exchange; the client checks
// the certificate itself (the pin) and presents none.
static bool TlsAcquireCredential(TLS_NET *net) {
	SCH_CREDENTIALS cred;
	TLS_PARAMETERS params;
	CRYPTO_SETTINGS crypto[5];
	UNICODE_STRING modes[2];
	TimeStamp expiry;
	DWORD versions = 0;

	ZeroMemory(&cred, sizeof(cred));
	ZeroMemory(&params, sizeof(params));
	ZeroMemory(crypto, sizeof(crypto));
	ZeroMemory(modes, sizeof(modes));

	if ((net->Cfg.Versions & TRANSPORT_TLS_12) != 0)
		versions |= (net->Server ? SP_PROT_TLS1_2_SERVER : SP_PROT_TLS1_2_CLIENT);
	if ((net->Cfg.Versions & TRANSPORT_TLS_13) != 0)
		versions |= (net->Server ? SP_PROT_TLS1_3_SERVER : SP_PROT_TLS1_3_CLIENT);

	TlsCngString(&modes[0], BCRYPT_CHAIN_MODE_CBC);
	TlsCngString(&modes[1], BCRYPT_CHAIN_MODE_CCM);
	crypto[0].eAlgorithmUsage = TlsParametersCngAlgUsageCipher;
	TlsCngString(&crypto[0].strCngAlgId, BCRYPT_CHACHA20_POLY1305_ALGORITHM);
	crypto[1].eAlgorithmUsage = TlsParametersCngAlgUsageCipher;
	TlsCngString(&crypto[1].strCngAlgId, BCRYPT_AES_ALGORITHM);
	crypto[1].cChainingModes = 2;
	crypto[1].rgstrChainingModes = modes;
	crypto[2].eAlgorithmUsage = TlsParametersCngAlgUsageCipher;
	TlsCngString(&crypto[2].strCngAlgId, BCRYPT_3DES_ALGORITHM);
	crypto[3].eAlgorithmUsage = TlsParametersCngAlgUsageKeyExchange;
	TlsCngString(&crypto[3].strCngAlgId, BCRYPT_RSA_ALGORITHM);
	crypto[4].eAlgorithmUsage = TlsParametersCngAlgUsageKeyExchange;
	TlsCngString(&crypto[4].strCngAlgId, BCRYPT_DH_ALGORITHM);

	params.grbitDisabledProtocols = ~versions;
	params.cDisabledCrypto = sizeof(crypto) / sizeof(crypto[0]);
	params.pDisabledCrypto = crypto;

	cred.dwVersion = SCH_CREDENTIALS_VERSION;
	cred.dwFlags = SCH_USE_STRONG_CRYPTO;
	cred.cTlsParameters = 1;
	cred.pTlsParameters = &params;
	if (net->Server) {
		cred.cCreds = 1;
		cred.paCred = &net->Cert;
		cred.dwFlags |= SCH_CRED_DISABLE_RECONNECTS;
	} else {
		cred.dwFlags |= SCH_CRED_MANUAL_CRED_VALIDATION | SCH_CRED_NO_DEFAULT_CREDS | SCH_CRED_NO_SERVERNAME_CHECK;
	}

	net->HaveCred = (AcquireCredentialsHandleW(NULL, (LPWSTR)UNISP_NAME_W, net->Server ? SECPKG_CRED_INBOUND : SECPKG_CRED_OUTBOUND, NULL, &cred, NULL, NULL,
	                                           &net->Cred, &expiry) == SEC_E_OK);
	return net->HaveCred;
}

// The procedures of a TLS transport into the TRANSPORT of a server or a client
static void TlsFill(TRANSPORT *t, TLS_NET *net) {
	strcpy_s(t->Name, sizeof(t->Name), net->Cfg.Name);
	t->Param = net;
	t->Dial = TlsDial;
	t->Listen = TlsListen;
	t->Accept = TlsAccept;
	t->CloseListener = TlsCloseListener;
	t->Read = TlsStreamRead;
	t->Write = TlsStreamWrite;
	t->Close = TlsStreamClose;
	t->Binding = TlsStreamBinding;
	t->Rekey = TlsStreamRekey;
}

void TransportTlsDefaultConfig(TRANSPORT_TLS_CONFIG *cfg, const char *thumbprint, bool machine_store) {
	if (cfg == NULL)
		return;

	ZeroMemory(cfg, sizeof(TRANSPORT_TLS_CONFIG));
	strcpy_s(cfg->Name, sizeof(cfg->Name), "tls");
	// A thumbprint too long for the field is cut, which New then refuses
	if (thumbprint != NULL)
		strncpy_s(cfg->Thumbprint, sizeof(cfg->Thumbprint), thumbprint, _TRUNCATE);
	cfg->MachineStore = machine_store;
	cfg->Versions = TRANSPORT_TLS_12 | TRANSPORT_TLS_13;
	cfg->SetGroups = true;
}

// A server or a client transport. The server loads its certificate, whose key must be in a CNG key
// storage provider (ADR-0022): a certificate whose key sits in a legacy CryptoAPI provider (CSP) is
// refused, so Schannel never meets one. The client only parses the thumbprint it pins.
static TRANSPORT *TransportTlsNew(const TRANSPORT_TLS_CONFIG *cfg, bool server) {
	WSADATA wsa;

	if (cfg == NULL)
		return NULL;

	TLS_NET *net = (TLS_NET *)TlsAlloc(sizeof(TLS_NET));
	TRANSPORT *t = (TRANSPORT *)TlsAlloc(sizeof(TRANSPORT));
	if (net == NULL || t == NULL) {
		TlsRelease(net, sizeof(TLS_NET));
		TlsRelease(t, sizeof(TRANSPORT));
		return NULL;
	}

	CopyMemory(&net->Cfg, cfg, sizeof(TRANSPORT_TLS_CONFIG));
	net->Cfg.Name[sizeof(net->Cfg.Name) - 1] = 0;
	net->Cfg.Thumbprint[sizeof(net->Cfg.Thumbprint) - 1] = 0;
	if (net->Cfg.Name[0] == 0)
		strcpy_s(net->Cfg.Name, sizeof(net->Cfg.Name), "tls");
	if ((net->Cfg.Versions & (TRANSPORT_TLS_12 | TRANSPORT_TLS_13)) == 0)
		net->Cfg.Versions = TRANSPORT_TLS_12 | TRANSPORT_TLS_13;
	net->Server = server;
	InitializeSRWLock(&net->Lock);

	// The transport owns net from here, so a failure below is cleaned up by TransportTlsFree
	t->Param = net;

	ZeroMemory(&wsa, sizeof(wsa));
	net->HaveWinsock = (WSAStartup(MAKEWORD(2, 2), &wsa) == 0);

	// The thumbprint of the server certificate: the server loads it, the client pins it
	bool ok = (net->HaveWinsock && TlsParseThumbprint(net->Cfg.Thumbprint, net->Thumbprint));

	if (ok && server) {
		net->Cert = CryptoCertFindByThumbprint(net->Cfg.Thumbprint, NULL, net->Cfg.MachineStore ? CRYPTO_MACHINE : 0);
		ok = (net->Cert != NULL && CryptoCertHasKspKey(net->Cert));
	}

	// The key exchange groups, before the credential that the handshakes use
	if (ok && net->Cfg.SetGroups)
		(void)TransportTlsSetGroups();
	if (ok)
		ok = TlsAcquireCredential(net);

	if (ok == false) {
		TransportTlsFree(t);
		return NULL;
	}

	TlsFill(t, net);

	return t;
}

TRANSPORT *TransportTlsServerNew(const TRANSPORT_TLS_CONFIG *cfg) {
	return TransportTlsNew(cfg, true);
}

TRANSPORT *TransportTlsClientNew(const TRANSPORT_TLS_CONFIG *cfg) {
	return TransportTlsNew(cfg, false);
}

USHORT TransportTlsBoundPort(TRANSPORT *t) {
	if (t == NULL || t->Param == NULL)
		return 0;

	return (USHORT)InterlockedCompareExchange(&((TLS_NET *)t->Param)->BoundPort, 0, 0);
}

bool TransportTlsLastHandshake(TRANSPORT *t, TRANSPORT_TLS_INFO *info) {
	bool ok;

	if (info != NULL)
		ZeroMemory(info, sizeof(TRANSPORT_TLS_INFO));
	if (t == NULL || t->Param == NULL || info == NULL)
		return false;

	TLS_NET *net = (TLS_NET *)t->Param;
	AcquireSRWLockShared(&net->Lock);
	ok = net->HaveLast;
	*info = net->Last;
	ReleaseSRWLockShared(&net->Lock);

	return ok;
}

void TransportTlsFree(TRANSPORT *t) {
	TLS_NET *net;

	if (t == NULL)
		return;

	net = (TLS_NET *)t->Param;
	if (net != NULL) {
		if (net->HaveCred)
			FreeCredentialsHandle(&net->Cred);
		CryptoCertFree(net->Cert);
		if (net->HaveWinsock)
			WSACleanup();
		TlsRelease(net, sizeof(TLS_NET));
	}

	TlsRelease(t, sizeof(TRANSPORT));
}
