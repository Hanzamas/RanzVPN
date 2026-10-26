// TransportQuic.c
// The QUIC transport of the new core (CORE-S1-1, #67): a listener and a dialler on the official
// signed msquic.dll (the Schannel build). A listener presents as an HTTP/3 server, the ALPN "h3",
// a real certificate and BBR where the build has it, so its posture equals ordinary Windows
// HTTP/3. One reliable bidirectional stream of a connection carries the session layer, so the
// Noise session (TransportNoise.c) runs over it unchanged: the handshake, the Login, the control
// stream and the data stream, whose frames enter the Hub (CORE-S1-2, #68). The connection
// advertises the QUIC DATAGRAM frames here, which no data path takes yet. The channel binding of
// a stream is the TLS exporter of its connection (NOISE_BINDING_EXPORTER, TransportQuicExporter.c;
// CORE-H5, #408), which both ends take when the handshake completes, so that a middlebox that holds
// the key of the certificate cannot relay a session; a connection that gives no exporter leaves its
// streams unbound, and their sessions encrypted. The client pins the server certificate and refuses
// any other, and the system root store is not trusted (ADR-0023).
//
// msquic.dll is loaded at the first QUIC call through LoadLibrary and MsQuicOpenVersion, so a
// program that never dials or listens over QUIC needs neither the DLL nor the import library, and
// a missing DLL is a clean "not available" rather than a load failure. An async msquic stream
// becomes a synchronous byte stream through a ring that the receive callback fills and the reader
// drains, as the loopback transport does; a send keeps its buffer until msquic completes it.

#include <winsock2.h>
#include <ws2tcpip.h>

#include "Core/TransportInternal.h"

#include <msquic.h>

#include <stdlib.h>
#include <string.h>

#define QUIC_RING_SIZE   262144 // Bytes one stream buffers before it holds msquic's receives back
#define QUIC_BACKLOG     16     // Accepted streams a listener holds before it drops the oldest
#define QUIC_DIAL_POLL   50     // How often a dial checks its cancel while it waits to connect (ms)
#define QUIC_PEER_STREAM 4      // Bidirectional streams the peer may open on a connection

// The msquic API, opened once per process through LoadLibrary and ref-counted over the transports
static SRWLOCK g_quic_lock = SRWLOCK_INIT;
static const QUIC_API_TABLE *g_quic = NULL;
static HMODULE g_quic_module = NULL;
static MsQuicCloseFn g_quic_close = NULL;
static UINT g_quic_refs = 0;

// A QUIC transport: its registration and its configuration, the server certificate's end-point
// binding, and the port its last listener bound
typedef struct QUIC_NET {
	TRANSPORT_QUIC_CONFIG Cfg;                // The configuration, with the ALPN and the thumbprint
	bool Server;                              // A listener (the certificate) or a dialler (the pin)
	HQUIC Registration;                       // The msquic registration of the transport
	HQUIC Configuration;                      // ... and its configuration, with the credentials loaded
	QUIC_BUFFER Alpn;                         // The ALPN buffer, into Cfg.Alpn
	UCHAR Thumbprint[CRYPTO_THUMBPRINT_SIZE]; // The server certificate's thumbprint, parsed from Cfg
	UCHAR Binding[NOISE_MAX_BINDING];         // The server's tls-server-end-point, computed at New
	UINT BindingSize;                         // ... its size (server only; a client learns it per connection)
	volatile LONG BoundPort;                  // The port the last listener bound (a listener on port 0)
} QUIC_NET;

// A listener: its backlog of accepted streams, each the control stream of one connection
typedef struct QUIC_LISTENER {
	QUIC_NET *Net;                           // The transport
	HQUIC Listener;                          // The msquic listener
	SRWLOCK Lock;                            // The queue below
	CONDITION_VARIABLE Changed;              // A stream was queued, or the listener closed
	struct QUIC_STREAM *Queue[QUIC_BACKLOG]; // The control streams dialled and not accepted, oldest first
	UINT NumQueued;                          // ... their number
	bool Closed;                             // CloseListener runs
} QUIC_LISTENER;

// A connection: the handle, and the control stream the session layer runs over
typedef struct QUIC_CONN {
	QUIC_NET *Net;                       // The transport
	HQUIC Connection;                    // The msquic connection
	QUIC_LISTENER *Listener;             // The listener that accepted it (server), or NULL (client)
	volatile LONG Refs;                  // The callback plus every stream that points here
	HANDLE Ready;                        // Set when the connection is up (client) or failed
	volatile LONG Connected;             // The handshake completed
	volatile LONG Failed;                // The connection failed before it came up, or shut down
	UCHAR Binding[NOISE_MAX_BINDING];    // The tls-server-end-point of the certificate msquic presented
	UINT BindingSize;                    // ... its size, 0 until the certificate arrived
	bool BindingBad;                     // A client that pinned another certificate: the binding is wrong
	UCHAR Exporter[NOISE_EXPORTER_SIZE]; // The TLS exporter of the connection, the binding of its streams
	bool Exported;                       // ... taken when the handshake completed
} QUIC_CONN;

// A stream: the TRANSPORT stream object, a synchronous byte stream over an async msquic stream
typedef struct QUIC_STREAM {
	QUIC_CONN *Conn;            // The connection the stream belongs to
	HQUIC Stream;               // The msquic stream
	volatile LONG Refs;         // The app plus msquic
	SRWLOCK Lock;               // The ring below
	CONDITION_VARIABLE Changed; // Bytes came, the peer closed, or the stream aborted
	UCHAR *Ring;                // QUIC_RING_SIZE bytes, the received bytes not read yet
	UINT Start;                 // ... the first byte not read
	UINT Used;                  // ... their number
	bool Disabled;              // A partial receive held msquic back: the reader re-enables it
	bool PeerClosed;            // The peer shut its send side: the reader takes the bytes left, then the end
	bool Aborted;               // The stream or its connection failed
} QUIC_STREAM;

//
// The msquic API, loaded on demand
//

// Open the msquic API if it is not open, under the lock; count one more user. false when the DLL is
// missing or the API cannot be opened.
static bool QuicApiOpen() {
	bool ok = false;

	AcquireSRWLockExclusive(&g_quic_lock);
	if (g_quic != NULL) {
		g_quic_refs++;
		ok = true;
	} else {
		HMODULE module = LoadLibraryExW(L"msquic.dll", NULL, LOAD_LIBRARY_SEARCH_DEFAULT_DIRS | LOAD_LIBRARY_SEARCH_APPLICATION_DIR);
		if (module == NULL)
			module = LoadLibraryW(L"msquic.dll");

		if (module != NULL) {
			MsQuicOpenVersionFn open = (MsQuicOpenVersionFn)(void *)GetProcAddress(module, "MsQuicOpenVersion");
			MsQuicCloseFn close = (MsQuicCloseFn)(void *)GetProcAddress(module, "MsQuicClose");
			const QUIC_API_TABLE *api = NULL;

			if (open != NULL && close != NULL && QUIC_SUCCEEDED(open(QUIC_API_VERSION_2, (const void **)&api)) && api != NULL) {
				g_quic = api;
				g_quic_close = close;
				g_quic_module = module;
				g_quic_refs = 1;
				ok = true;
			} else {
				FreeLibrary(module);
			}
		}
	}
	ReleaseSRWLockExclusive(&g_quic_lock);

	return ok;
}

// Count one fewer user; close the API and free the DLL when the last transport is gone
static void QuicApiClose() {
	AcquireSRWLockExclusive(&g_quic_lock);
	bool last = false;

	if (g_quic_refs != 0) {
		g_quic_refs--;
		last = (g_quic_refs == 0);
	}
	if (last) {
		g_quic_close(g_quic);
		FreeLibrary(g_quic_module);
		g_quic = NULL;
		g_quic_close = NULL;
		g_quic_module = NULL;
	}
	ReleaseSRWLockExclusive(&g_quic_lock);
}

bool TransportQuicAvailable() {
	if (QuicApiOpen() == false)
		return false;

	QuicApiClose();
	return true;
}

//
// Addresses and certificates
//

// One hex digit, or -1
static int QuicHexDigit(char c) {
	if (c >= '0' && c <= '9')
		return c - '0';
	if (c >= 'a' && c <= 'f')
		return c - 'a' + 10;
	if (c >= 'A' && c <= 'F')
		return c - 'A' + 10;
	return -1;
}

// Parse a thumbprint of exactly CRYPTO_THUMBPRINT_SIZE bytes (40 hex digits), spaces and colons
// ignored; false for anything else
static bool QuicParseThumbprint(const char *str, UCHAR *out) {
	UINT n = 0;

	while (*str != 0 && n < CRYPTO_THUMBPRINT_SIZE) {
		if (*str == ' ' || *str == ':') {
			str++;
			continue;
		}

		int hi = QuicHexDigit(str[0]);
		int lo = (str[0] != 0 ? QuicHexDigit(str[1]) : -1);
		if (hi < 0 || lo < 0)
			return false;

		out[n++] = (UCHAR)(hi * 16 + lo);
		str += 2;
	}

	while (*str == ' ' || *str == ':')
		str++;

	return (n == CRYPTO_THUMBPRINT_SIZE && *str == 0);
}

// Split "host:port" at the last colon into host (max bytes, with its NUL) and the port; false when
// there is no port. An empty host listens on every address.
static bool QuicParseAddress(const char *address, char *host, UINT max, USHORT *port) {
	const char *colon = strrchr(address, ':');
	UINT len;
	long value;

	if (colon == NULL || colon[1] == 0)
		return false;

	len = (UINT)(colon - address);
	if (len >= max)
		return false;
	CopyMemory(host, address, len);
	host[len] = 0;

	value = strtol(colon + 1, NULL, 10);
	if (value < 0 || value > 65535)
		return false;
	*port = (USHORT)value;

	return true;
}

// The QUIC_ADDR of a host and a port: a literal IPv4 or IPv6 address, or every address for an empty
// host. Winsock parses the literal (no ntdll string helpers), so the module links ws2_32 only.
static void QuicMakeAddr(const char *host, USHORT port, QUIC_ADDR *addr) {
	IN_ADDR v4;
	IN6_ADDR v6;

	ZeroMemory(addr, sizeof(QUIC_ADDR));

	if (host[0] != 0 && inet_pton(AF_INET, host, &v4) == 1) {
		addr->Ipv4.sin_family = AF_INET;
		addr->Ipv4.sin_addr = v4;
		addr->Ipv4.sin_port = htons(port);
	} else if (host[0] != 0 && inet_pton(AF_INET6, host, &v6) == 1) {
		addr->Ipv6.sin6_family = AF_INET6;
		addr->Ipv6.sin6_addr = v6;
		addr->Ipv6.sin6_port = htons(port);
	} else {
		addr->si_family = AF_UNSPEC;
		addr->Ipv4.sin_port = htons(port);
	}
}

// The host-order port of a bound local address, whichever family it is
static USHORT QuicAddrPort(const QUIC_ADDR *addr) {
	return ntohs(addr->si_family == AF_INET6 ? addr->Ipv6.sin6_port : addr->Ipv4.sin_port);
}

// The tls-server-end-point binding of a certificate context into binding (NOISE_MAX_BINDING bytes),
// *size its length; false when it cannot be computed
static bool QuicCertBinding(PCCERT_CONTEXT cert, UCHAR *binding, UINT *size) {
	UINT n = 0;

	*size = 0;
	if (cert == NULL || CryptoCertEndPoint(cert, binding, &n) == false || n == 0 || n > NOISE_MAX_BINDING)
		return false;

	*size = n;
	return true;
}

//
// The settings and the configuration
//

// Fill a QUIC_SETTINGS for the transport: the idle timeout, the peer stream limit so the client may
// open the control stream, the datagram receive that the connection advertises, and BBR when bbr
// is set. The CongestionControlAlgorithm field takes the BBR value (1) directly, so no preview build
// of the header is needed; a msquic without BBR fails the open, and the caller retries without it.
static void QuicMakeSettings(QUIC_NET *net, bool bbr, QUIC_SETTINGS *settings) {
	UINT idle = (net->Cfg.IdleTimeoutMs != 0 ? net->Cfg.IdleTimeoutMs : TRANSPORT_QUIC_IDLE_DEFAULT);

	ZeroMemory(settings, sizeof(QUIC_SETTINGS));

	settings->IsSet.IdleTimeoutMs = 1;
	settings->IdleTimeoutMs = idle;
	settings->IsSet.PeerBidiStreamCount = 1;
	settings->PeerBidiStreamCount = QUIC_PEER_STREAM;
	settings->IsSet.DatagramReceiveEnabled = 1;
	settings->DatagramReceiveEnabled = 1;

	if (bbr) {
		// QUIC_CONGESTION_CONTROL_ALGORITHM_BBR, which the stable header does not name (it is behind
		// the preview flag), is the value 1 (CUBIC is 0)
		settings->IsSet.CongestionControlAlgorithm = 1;
		settings->CongestionControlAlgorithm = 1;
	}
}

// Load the server's certificate credentials (by thumbprint in the store) or the client's (pin the
// server certificate, do not trust the root store), synchronously
static bool QuicLoadCredential(QUIC_NET *net) {
	QUIC_CREDENTIAL_CONFIG cred;
	QUIC_CERTIFICATE_HASH_STORE hash_store;

	ZeroMemory(&cred, sizeof(cred));

	if (net->Server) {
		ZeroMemory(&hash_store, sizeof(hash_store));
		hash_store.Flags = net->Cfg.MachineStore ? QUIC_CERTIFICATE_HASH_STORE_FLAG_MACHINE_STORE : QUIC_CERTIFICATE_HASH_STORE_FLAG_NONE;
		CopyMemory(hash_store.ShaHash, net->Thumbprint, sizeof(hash_store.ShaHash));
		strcpy_s(hash_store.StoreName, sizeof(hash_store.StoreName), "My");

		cred.Type = QUIC_CREDENTIAL_TYPE_CERTIFICATE_HASH_STORE;
		cred.CertificateHashStore = &hash_store;
		cred.Flags = QUIC_CREDENTIAL_FLAG_NONE;
	} else {
		cred.Type = QUIC_CREDENTIAL_TYPE_NONE;
		// The client checks the server certificate itself (the pin, not the root store), and asks
		// for it so that it can compute the channel binding and compare the pin
		cred.Flags = QUIC_CREDENTIAL_FLAG_CLIENT | QUIC_CREDENTIAL_FLAG_NO_CERTIFICATE_VALIDATION | QUIC_CREDENTIAL_FLAG_INDICATE_CERTIFICATE_RECEIVED;
	}

	return QUIC_SUCCEEDED(g_quic->ConfigurationLoadCredential(net->Configuration, &cred));
}

// Open the registration and the configuration of the transport, with the credentials loaded. BBR is
// tried first; a msquic that has no BBR fails the configuration open, so it is retried with the
// default congestion control.
static bool QuicOpenConfiguration(QUIC_NET *net) {
	QUIC_REGISTRATION_CONFIG reg;
	QUIC_SETTINGS settings;

	ZeroMemory(&reg, sizeof(reg));
	reg.AppName = "ranz";
	reg.ExecutionProfile = QUIC_EXECUTION_PROFILE_LOW_LATENCY;
	if (QUIC_FAILED(g_quic->RegistrationOpen(&reg, &net->Registration)))
		return false;

	QuicMakeSettings(net, net->Cfg.Bbr, &settings);
	if (QUIC_FAILED(g_quic->ConfigurationOpen(net->Registration, &net->Alpn, 1, &settings, sizeof(settings), NULL, &net->Configuration))) {
		// A msquic build without BBR: the default congestion control
		QuicMakeSettings(net, false, &settings);
		if (QUIC_FAILED(g_quic->ConfigurationOpen(net->Registration, &net->Alpn, 1, &settings, sizeof(settings), NULL, &net->Configuration)))
			return false;
	}

	return QuicLoadCredential(net);
}

//
// The streams
//

// Wipe and free size bytes at p, which may be NULL
static void QuicRelease(void *p, UINT size) {
	if (p == NULL)
		return;

	SecureZeroMemory(p, size);
	HeapFree(GetProcessHeap(), 0, p);
}

static void QuicConnRelease(QUIC_CONN *c);

// Release one reference of a stream: close the handle, free the ring, release the connection and free the stream once
// the app and msquic are both gone
static void QuicStreamRelease(QUIC_STREAM *s) {
	if (s == NULL || InterlockedDecrement(&s->Refs) != 0)
		return;

	// Both the app and msquic are done with the stream: the handle is closed last, so that no call of
	// the app, QuicStreamWrite and QuicStreamClose among them, ever meets a handle that msquic closed
	if (s->Stream != NULL)
		g_quic->StreamClose(s->Stream);
	QuicRelease(s->Ring, QUIC_RING_SIZE);
	QuicConnRelease(s->Conn);
	QuicRelease(s, sizeof(QUIC_STREAM));
}

// Take size bytes out of the ring that holds them
static void QuicRingTake(QUIC_STREAM *s, UCHAR *dst, UINT size) {
	UINT first = QUIC_RING_SIZE - s->Start;

	if (first > size)
		first = size;
	CopyMemory(dst, s->Ring + s->Start, first);
	CopyMemory(dst + first, s->Ring, size - first);
	SecureZeroMemory(s->Ring + s->Start, first);
	SecureZeroMemory(s->Ring, size - first);

	s->Start = (s->Start + size) % QUIC_RING_SIZE;
	s->Used -= size;
}

// Put size bytes into the ring that has the room; the caller holds the lock
static void QuicRingPut(QUIC_STREAM *s, const UCHAR *src, UINT size) {
	UINT pos = (s->Start + s->Used) % QUIC_RING_SIZE;
	UINT first = QUIC_RING_SIZE - pos;

	if (first > size)
		first = size;
	CopyMemory(s->Ring + pos, src, first);
	CopyMemory(s->Ring, src + first, size - first);

	s->Used += size;
}

// The stream callback: it fills the ring from the received buffers, frees a completed send, and
// marks the end or the abort of the stream. A partial receive holds msquic back until the reader
// drains the ring and re-enables it.
static _Function_class_(QUIC_STREAM_CALLBACK) QUIC_STATUS QUIC_API QuicStreamCallback(HQUIC stream, void *context, QUIC_STREAM_EVENT *event) {
	QUIC_STREAM *s = (QUIC_STREAM *)context;

	UNREFERENCED_PARAMETER(stream);

	switch (event->Type) {
	case QUIC_STREAM_EVENT_RECEIVE: {
		UINT taken = 0;

		AcquireSRWLockExclusive(&s->Lock);
		for (UINT i = 0; i < event->RECEIVE.BufferCount; i++) {
			const QUIC_BUFFER *b = &event->RECEIVE.Buffers[i];
			UINT room = QUIC_RING_SIZE - s->Used;
			UINT n = (b->Length < room ? b->Length : room);

			if (n == 0)
				break;
			QuicRingPut(s, b->Buffer, n);
			taken += n;
		}
		// The bytes that did not fit stay with msquic, which stops delivering until the reader has
		// room again and re-enables the receive
		if (taken < event->RECEIVE.TotalBufferLength)
			s->Disabled = true;
		WakeAllConditionVariable(&s->Changed);
		ReleaseSRWLockExclusive(&s->Lock);

		event->RECEIVE.TotalBufferLength = taken;
		return QUIC_STATUS_SUCCESS;
	}

	case QUIC_STREAM_EVENT_SEND_COMPLETE:
		// The buffer of QuicStreamWrite, kept until msquic was done with it
		QuicRelease(event->SEND_COMPLETE.ClientContext, 0);
		return QUIC_STATUS_SUCCESS;

	case QUIC_STREAM_EVENT_PEER_SEND_SHUTDOWN:
		AcquireSRWLockExclusive(&s->Lock);
		s->PeerClosed = true;
		WakeAllConditionVariable(&s->Changed);
		ReleaseSRWLockExclusive(&s->Lock);
		return QUIC_STATUS_SUCCESS;

	case QUIC_STREAM_EVENT_PEER_SEND_ABORTED:
	case QUIC_STREAM_EVENT_PEER_RECEIVE_ABORTED:
		AcquireSRWLockExclusive(&s->Lock);
		s->Aborted = true;
		WakeAllConditionVariable(&s->Changed);
		ReleaseSRWLockExclusive(&s->Lock);
		return QUIC_STATUS_SUCCESS;

	case QUIC_STREAM_EVENT_SHUTDOWN_COMPLETE:
		// msquic is done with the stream: let go of its reference; the handle is closed with the last one
		QuicStreamRelease(s);
		return QUIC_STATUS_SUCCESS;

	default:
		return QUIC_STATUS_SUCCESS;
	}
}

// A new stream wrapper for an msquic stream, with two references: the app and msquic. NULL when
// there is no memory, with the handle left to the caller.
static QUIC_STREAM *QuicStreamNew(QUIC_CONN *conn, HQUIC stream) {
	QUIC_STREAM *s = (QUIC_STREAM *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(QUIC_STREAM));

	if (s != NULL) {
		s->Ring = (UCHAR *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, QUIC_RING_SIZE);
		if (s->Ring == NULL) {
			QuicRelease(s, sizeof(QUIC_STREAM));
			return NULL;
		}
	}
	if (s == NULL)
		return NULL;

	InitializeSRWLock(&s->Lock);
	InitializeConditionVariable(&s->Changed);
	s->Conn = conn;
	s->Stream = stream;
	s->Refs = 2;
	InterlockedIncrement(&conn->Refs);

	return s;
}

static UINT QuicStreamRead(void *stream, void *buf, UINT size, UINT timeout) {
	QUIC_STREAM *s = (QUIC_STREAM *)stream;
	UINT64 end = GetTickCount64() + timeout;
	UINT ret = TRANSPORT_LATER;
	bool reenable = false;

	AcquireSRWLockExclusive(&s->Lock);
	while (s->Used == 0 && s->PeerClosed == false && s->Aborted == false) {
		DWORD wait = INFINITE;

		if (timeout != INFINITE) {
			UINT64 now = GetTickCount64();
			if (now >= end)
				break;
			wait = (DWORD)(end - now);
		}
		SleepConditionVariableSRW(&s->Changed, &s->Lock, wait, 0);
	}

	if (s->Used != 0) {
		ret = (size < s->Used ? size : s->Used);
		QuicRingTake(s, (UCHAR *)buf, ret);
		if (s->Disabled && s->Used < QUIC_RING_SIZE) {
			s->Disabled = false;
			reenable = true;
		}
	} else if (s->Aborted || s->PeerClosed) {
		ret = 0;
	}
	ReleaseSRWLockExclusive(&s->Lock);

	// Re-enable the receive outside the lock: the callback it may run takes the same lock
	if (reenable)
		g_quic->StreamReceiveSetEnabled(s->Stream, TRUE);

	return ret;
}

static bool QuicStreamWrite(void *stream, const void *buf, UINT size) {
	QUIC_STREAM *s = (QUIC_STREAM *)stream;
	QUIC_BUFFER *send;

	if (size == 0)
		return true;

	// The buffer stays with msquic until the send completes: the QUIC_BUFFER and its bytes in one
	// allocation, freed by the SEND_COMPLETE event
	send = (QUIC_BUFFER *)HeapAlloc(GetProcessHeap(), 0, sizeof(QUIC_BUFFER) + size);
	if (send == NULL)
		return false;
	send->Length = size;
	send->Buffer = (uint8_t *)(send + 1);
	CopyMemory(send->Buffer, buf, size);

	if (QUIC_FAILED(g_quic->StreamSend(s->Stream, send, 1, QUIC_SEND_FLAG_NONE, send))) {
		HeapFree(GetProcessHeap(), 0, send);
		return false;
	}

	return true;
}

static void QuicStreamClose(void *stream) {
	QUIC_STREAM *s = (QUIC_STREAM *)stream;

	if (s == NULL)
		return;

	// The last record (the Noise close) is already queued: flush it and the FIN with a graceful
	// stream shutdown, then close the connection. The stream and connection callbacks free the
	// wrappers once msquic is done with their handles.
	if (s->Stream != NULL)
		g_quic->StreamShutdown(s->Stream, QUIC_STREAM_SHUTDOWN_FLAG_GRACEFUL, 0);
	g_quic->ConnectionShutdown(s->Conn->Connection, QUIC_CONNECTION_SHUTDOWN_FLAG_NONE, 0);

	// Let go of the app's reference; msquic releases its own in SHUTDOWN_COMPLETE
	QuicStreamRelease(s);
}

// Free a stream synchronously, before msquic ever drives its lifetime (a dial that failed before
// the connection started): close the handle it has, and let go of both references
static void QuicStreamFreeNow(QUIC_STREAM *s) {
	if (s == NULL)
		return;

	if (s->Stream != NULL) {
		g_quic->StreamClose(s->Stream);
		s->Stream = NULL;
	}
	QuicStreamRelease(s);
	QuicStreamRelease(s);
}

// Close a connection synchronously, before it started (a dial that failed early): close the handle
// it has, and let go of the callback reference
static void QuicConnCloseNow(QUIC_CONN *c) {
	if (c == NULL)
		return;

	if (c->Connection != NULL) {
		g_quic->ConnectionClose(c->Connection);
		c->Connection = NULL;
	}
	QuicConnRelease(c);
}

static UINT QuicStreamBinding(void *stream, UCHAR *binding, UINT max, UINT *size) {
	QUIC_STREAM *s = (QUIC_STREAM *)stream;
	QUIC_CONN *c = s->Conn;
	QUIC_NET *net = c->Net;
	const UCHAR *bind = c->Exporter;
	UINT bind_size = (c->Exported ? NOISE_EXPORTER_SIZE : 0);
	UINT type = NOISE_BINDING_EXPORTER;

	*size = 0;

	// A client that got no certificate checked no pin: its stream has no binding, so its session is
	// encrypted, and its handshake with a bound server fails
	if (net->Server == false && c->BindingSize == 0)
		return NOISE_BINDING_NONE;

	// The binding of the build before CORE-H5, for the test of an old node: the tls-server-end-point,
	// which the server knows from its own certificate and the client learnt from the handshake
	if (net->Cfg.EndPointBinding) {
		bind = (net->Server ? net->Binding : c->Binding);
		bind_size = (net->Server ? net->BindingSize : c->BindingSize);
		type = NOISE_BINDING_SERVER_END_POINT;
	}

	// The TLS exporter of the connection: none, from an msquic without one, leaves the stream unbound
	if (bind_size == 0 || bind_size > max)
		return NOISE_BINDING_NONE;
	CopyMemory(binding, bind, bind_size);
	*size = bind_size;

	// The mismatch test: a client that computes a binding of its own, as a middlebox that terminated
	// the TLS would, so the two prologues differ and the handshake is closed
	if (net->Server == false && net->Cfg.BreakBinding)
		binding[0] ^= 0xFF;

	return type;
}

static bool QuicStreamRekey(void *stream) {
	// QUIC holds the keys; the outer key update is QUIC_PARAM_CONN_FORCE_KEY_UPDATE of the private
	// header, which this transport does not set yet. The session asks for it on its schedule, and
	// a missing update does not fail the session here.
	UNREFERENCED_PARAMETER(stream);
	return true;
}

//
// The connections
//

// Release one reference of a connection: free it once the callback and every stream are gone
static void QuicConnRelease(QUIC_CONN *c) {
	if (c == NULL || InterlockedDecrement(&c->Refs) != 0)
		return;

	if (c->Ready != NULL)
		CloseHandle(c->Ready);
	// The handle is closed with the last reference, once the callback and every stream are done with it
	if (c->Connection != NULL)
		g_quic->ConnectionClose(c->Connection);
	QuicRelease(c, sizeof(QUIC_CONN));
}

// The connection callback: it records the certificate's binding and the exporter of the connection,
// wakes a waiting dial on connect or failure, and closes the connection on shutdown
static _Function_class_(QUIC_CONNECTION_CALLBACK) QUIC_STATUS QUIC_API QuicConnCallback(HQUIC connection, void *context, QUIC_CONNECTION_EVENT *event) {
	QUIC_CONN *c = (QUIC_CONN *)context;

	switch (event->Type) {
	case QUIC_CONNECTION_EVENT_CONNECTED:
		// The exporter now, while msquic still holds the TLS state, which a server lets go of once the
		// client acknowledged its handshake; the streams of the connection take it as their binding
		c->Exported = TransportQuicExporter(g_quic, connection, c->Exporter);
		InterlockedExchange(&c->Connected, 1);
		if (c->Ready != NULL)
			SetEvent(c->Ready);
		return QUIC_STATUS_SUCCESS;

	case QUIC_CONNECTION_EVENT_PEER_CERTIFICATE_RECEIVED: {
		// The client pins the server certificate: compute its tls-server-end-point for the channel
		// binding, and refuse a certificate whose thumbprint is not the pinned one
		PCCERT_CONTEXT cert = (PCCERT_CONTEXT)event->PEER_CERTIFICATE_RECEIVED.Certificate;
		UCHAR thumbprint[CRYPTO_THUMBPRINT_SIZE];

		if (QuicCertBinding(cert, c->Binding, &c->BindingSize) == false)
			c->BindingBad = true;
		if (cert == NULL || CryptoCertThumbprint(cert, thumbprint) == false || memcmp(thumbprint, c->Net->Thumbprint, CRYPTO_THUMBPRINT_SIZE) != 0) {
			c->BindingBad = true;
			return QUIC_STATUS_BAD_CERTIFICATE;
		}
		return QUIC_STATUS_SUCCESS;
	}

	case QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_TRANSPORT:
	case QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_PEER:
		InterlockedExchange(&c->Failed, 1);
		if (c->Ready != NULL)
			SetEvent(c->Ready);
		return QUIC_STATUS_SUCCESS;

	case QUIC_CONNECTION_EVENT_PEER_STREAM_STARTED: {
		// The server side: the client's control stream. Give it its callback and queue it for Accept.
		QUIC_STREAM *s = QuicStreamNew(c, event->PEER_STREAM_STARTED.Stream);
		QUIC_LISTENER *l = c->Listener;

		if (s == NULL || l == NULL)
			return QUIC_STATUS_SUCCESS;

		g_quic->SetCallbackHandler(event->PEER_STREAM_STARTED.Stream, (void *)QuicStreamCallback, s);

		AcquireSRWLockExclusive(&l->Lock);
		if (l->Closed == false && l->NumQueued < QUIC_BACKLOG) {
			l->Queue[l->NumQueued++] = s;
			s = NULL;
			WakeAllConditionVariable(&l->Changed);
		}
		ReleaseSRWLockExclusive(&l->Lock);

		// The backlog was full or the listener closed: abort this stream and drop its app reference,
		// so its SHUTDOWN_COMPLETE releases the msquic reference
		if (s != NULL) {
			g_quic->StreamShutdown(s->Stream, QUIC_STREAM_SHUTDOWN_FLAG_ABORT, 0);
			QuicStreamRelease(s);
		}
		return QUIC_STATUS_SUCCESS;
	}

	case QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE:
		InterlockedExchange(&c->Failed, 1);
		if (c->Ready != NULL)
			SetEvent(c->Ready);
		QuicConnRelease(c);
		return QUIC_STATUS_SUCCESS;

	default:
		return QUIC_STATUS_SUCCESS;
	}
}

// A new connection wrapper, with one reference for the callback. NULL when there is no memory.
static QUIC_CONN *QuicConnNew(QUIC_NET *net, QUIC_LISTENER *listener, bool want_ready) {
	QUIC_CONN *c = (QUIC_CONN *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(QUIC_CONN));

	if (c == NULL)
		return NULL;

	c->Net = net;
	c->Listener = listener;
	c->Refs = 1;
	if (want_ready) {
		c->Ready = CreateEventW(NULL, TRUE, FALSE, NULL);
		if (c->Ready == NULL) {
			QuicRelease(c, sizeof(QUIC_CONN));
			return NULL;
		}
	}

	return c;
}

//
// The listener
//

static _Function_class_(QUIC_LISTENER_CALLBACK) QUIC_STATUS QUIC_API QuicListenerCallback(HQUIC listener, void *context, QUIC_LISTENER_EVENT *event) {
	QUIC_LISTENER *l = (QUIC_LISTENER *)context;

	UNREFERENCED_PARAMETER(listener);

	if (event->Type != QUIC_LISTENER_EVENT_NEW_CONNECTION)
		return QUIC_STATUS_SUCCESS;

	// A new connection: give it its callback and its configuration, which proceeds with the handshake
	QUIC_CONN *c = QuicConnNew(l->Net, l, false);
	if (c == NULL)
		return QUIC_STATUS_OUT_OF_MEMORY;

	c->Connection = event->NEW_CONNECTION.Connection;
	g_quic->SetCallbackHandler(event->NEW_CONNECTION.Connection, (void *)QuicConnCallback, c);
	if (QUIC_FAILED(g_quic->ConnectionSetConfiguration(event->NEW_CONNECTION.Connection, l->Net->Configuration))) {
		c->Connection = NULL; // msquic closes a connection whose acceptance failed
		QuicConnRelease(c);
		return QUIC_STATUS_INTERNAL_ERROR;
	}

	return QUIC_STATUS_SUCCESS;
}

static bool QuicListen(void *param, const char *address, void **listener) {
	QUIC_NET *net = (QUIC_NET *)param;
	char host[TRANSPORT_ADDRESS_SIZE];
	USHORT port = 0;
	QUIC_ADDR addr;

	*listener = NULL;
	if (QuicParseAddress(address, host, sizeof(host), &port) == false)
		return false;

	QUIC_LISTENER *l = (QUIC_LISTENER *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(QUIC_LISTENER));
	if (l == NULL)
		return false;
	l->Net = net;
	InitializeSRWLock(&l->Lock);
	InitializeConditionVariable(&l->Changed);

	if (QUIC_FAILED(g_quic->ListenerOpen(net->Registration, QuicListenerCallback, l, &l->Listener))) {
		QuicRelease(l, sizeof(QUIC_LISTENER));
		return false;
	}

	QuicMakeAddr(host, port, &addr);
	if (QUIC_FAILED(g_quic->ListenerStart(l->Listener, &net->Alpn, 1, &addr))) {
		g_quic->ListenerClose(l->Listener);
		QuicRelease(l, sizeof(QUIC_LISTENER));
		return false;
	}

	// The port the listener bound, for a listener on port 0
	QUIC_ADDR local;
	UINT32 local_size = sizeof(local);
	if (QUIC_SUCCEEDED(g_quic->GetParam(l->Listener, QUIC_PARAM_LISTENER_LOCAL_ADDRESS, &local_size, &local)))
		InterlockedExchange(&net->BoundPort, QuicAddrPort(&local));

	*listener = l;
	return true;
}

static bool QuicAccept(void *listener, UINT timeout, void **stream) {
	QUIC_LISTENER *l = (QUIC_LISTENER *)listener;
	UINT64 end = GetTickCount64() + timeout;

	*stream = NULL;

	AcquireSRWLockExclusive(&l->Lock);
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
		MoveMemory(l->Queue, l->Queue + 1, sizeof(QUIC_STREAM *) * l->NumQueued);
	}
	ReleaseSRWLockExclusive(&l->Lock);

	return (*stream != NULL);
}

static void QuicCloseListener(void *listener) {
	QUIC_LISTENER *l = (QUIC_LISTENER *)listener;

	// Stop accepting; msquic stops the listener synchronously enough for the queue below
	g_quic->ListenerStop(l->Listener);

	AcquireSRWLockExclusive(&l->Lock);
	l->Closed = true;
	WakeAllConditionVariable(&l->Changed);
	UINT num = l->NumQueued;
	QUIC_STREAM *drop[QUIC_BACKLOG];
	for (UINT i = 0; i < num; i++)
		drop[i] = l->Queue[i];
	l->NumQueued = 0;
	ReleaseSRWLockExclusive(&l->Lock);

	// The streams that nobody accepted: let go of their app reference and shut them down
	for (UINT i = 0; i < num; i++) {
		g_quic->ConnectionShutdown(drop[i]->Conn->Connection, QUIC_CONNECTION_SHUTDOWN_FLAG_NONE, 0);
		QuicStreamRelease(drop[i]);
	}

	g_quic->ListenerClose(l->Listener);
	QuicRelease(l, sizeof(QUIC_LISTENER));
}

//
// The dialler
//

static bool QuicDial(void *param, const char *address, HANDLE cancel, void **stream) {
	QUIC_NET *net = (QUIC_NET *)param;
	char host[TRANSPORT_ADDRESS_SIZE];
	USHORT port = 0;

	*stream = NULL;
	if (QuicParseAddress(address, host, sizeof(host), &port) == false)
		return false;

	QUIC_CONN *c = QuicConnNew(net, NULL, true);
	if (c == NULL)
		return false;

	if (QUIC_FAILED(g_quic->ConnectionOpen(net->Registration, QuicConnCallback, c, &c->Connection))) {
		QuicConnCloseNow(c);
		return false;
	}

	// The control stream, opened before the connection starts so its first record goes once the
	// handshake completes. Every failure before ConnectionStart frees the handles synchronously,
	// because msquic has not begun to drive their lifetime.
	QUIC_STREAM *s = QuicStreamNew(c, NULL);
	if (s == NULL) {
		QuicConnCloseNow(c);
		return false;
	}
	if (QUIC_FAILED(g_quic->StreamOpen(c->Connection, QUIC_STREAM_OPEN_FLAG_NONE, QuicStreamCallback, s, &s->Stream)) ||
	    QUIC_FAILED(g_quic->StreamStart(s->Stream, QUIC_STREAM_START_FLAG_IMMEDIATE))) {
		QuicStreamFreeNow(s);
		QuicConnCloseNow(c);
		return false;
	}

	// Set the remote address for a literal host, so the dial does not depend on msquic resolving it,
	// and still pass the host as the server name for the SNI
	QUIC_ADDR remote;
	QuicMakeAddr(host, port, &remote);
	if (remote.si_family != AF_UNSPEC)
		g_quic->SetParam(c->Connection, QUIC_PARAM_CONN_REMOTE_ADDRESS, sizeof(remote), &remote);

	if (QUIC_FAILED(g_quic->ConnectionStart(c->Connection, net->Configuration, QUIC_ADDRESS_FAMILY_UNSPEC, host, port))) {
		QuicStreamFreeNow(s);
		QuicConnCloseNow(c);
		return false;
	}

	// Wait until the connection comes up, fails, or the dial is cancelled
	while (true) {
		DWORD wait = (cancel != NULL ? QUIC_DIAL_POLL : INFINITE);

		if (WaitForSingleObject(c->Ready, wait) == WAIT_OBJECT_0)
			break;
		if (cancel != NULL && WaitForSingleObject(cancel, 0) == WAIT_OBJECT_0) {
			QuicStreamClose(s);
			return false;
		}
	}

	if (InterlockedCompareExchange(&c->Connected, 1, 1) != 1 || c->BindingBad) {
		QuicStreamClose(s);
		return false;
	}

	*stream = s;
	return true;
}

//
// The transport
//

// The procedures of a QUIC transport into the TRANSPORT of a server or a client
static void QuicFill(TRANSPORT *t, QUIC_NET *net) {
	strcpy_s(t->Name, sizeof(t->Name), net->Cfg.Name);
	t->Param = net;
	t->Dial = QuicDial;
	t->Listen = QuicListen;
	t->Accept = QuicAccept;
	t->CloseListener = QuicCloseListener;
	t->Read = QuicStreamRead;
	t->Write = QuicStreamWrite;
	t->Close = QuicStreamClose;
	t->Binding = QuicStreamBinding;
	t->Rekey = QuicStreamRekey;
}

void TransportQuicDefaultConfig(TRANSPORT_QUIC_CONFIG *cfg, const char *thumbprint, bool machine_store) {
	if (cfg == NULL)
		return;

	ZeroMemory(cfg, sizeof(TRANSPORT_QUIC_CONFIG));
	strcpy_s(cfg->Name, sizeof(cfg->Name), "quic");
	strcpy_s(cfg->Alpn, sizeof(cfg->Alpn), TRANSPORT_QUIC_ALPN);
	if (thumbprint != NULL)
		strcpy_s(cfg->Thumbprint, sizeof(cfg->Thumbprint), thumbprint);
	cfg->MachineStore = machine_store;
	cfg->Bbr = true;
	cfg->IdleTimeoutMs = TRANSPORT_QUIC_IDLE_DEFAULT;
}

// A server or a client transport. want_cert: the server, which loads its certificate and computes
// its binding; the client only parses the thumbprint it pins.
static TRANSPORT *TransportQuicNew(const TRANSPORT_QUIC_CONFIG *cfg, bool server) {
	if (cfg == NULL || QuicApiOpen() == false)
		return NULL;

	QUIC_NET *net = (QUIC_NET *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(QUIC_NET));
	TRANSPORT *t = (TRANSPORT *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(TRANSPORT));
	if (net == NULL || t == NULL) {
		QuicRelease(net, sizeof(QUIC_NET));
		QuicRelease(t, sizeof(TRANSPORT));
		QuicApiClose();
		return NULL;
	}

	CopyMemory(&net->Cfg, cfg, sizeof(TRANSPORT_QUIC_CONFIG));
	if (net->Cfg.Alpn[0] == 0)
		strcpy_s(net->Cfg.Alpn, sizeof(net->Cfg.Alpn), TRANSPORT_QUIC_ALPN);
	if (net->Cfg.Name[0] == 0)
		strcpy_s(net->Cfg.Name, sizeof(net->Cfg.Name), "quic");
	net->Server = server;
	net->Alpn.Length = (UINT)strlen(net->Cfg.Alpn);
	net->Alpn.Buffer = (uint8_t *)net->Cfg.Alpn;
	net->BoundPort = 0;

	// The transport owns net from here, so a failure below is cleaned up by TransportQuicFree
	t->Param = net;

	// The thumbprint of the server certificate: the server loads it, the client pins it
	bool ok = QuicParseThumbprint(net->Cfg.Thumbprint, net->Thumbprint);

	if (ok && server) {
		UINT scope = net->Cfg.MachineStore ? CRYPTO_MACHINE : 0;
		PCCERT_CONTEXT cert = CryptoCertFindByThumbprint(net->Cfg.Thumbprint, NULL, scope);

		ok = (cert != NULL && QuicCertBinding(cert, net->Binding, &net->BindingSize));
		CryptoCertFree(cert);
	}

	if (ok)
		ok = QuicOpenConfiguration(net);

	if (ok == false) {
		TransportQuicFree(t);
		return NULL;
	}

	QuicFill(t, net);

	return t;
}

TRANSPORT *TransportQuicServerNew(const TRANSPORT_QUIC_CONFIG *cfg) {
	return TransportQuicNew(cfg, true);
}

TRANSPORT *TransportQuicClientNew(const TRANSPORT_QUIC_CONFIG *cfg) {
	return TransportQuicNew(cfg, false);
}

USHORT TransportQuicBoundPort(TRANSPORT *t) {
	if (t == NULL || t->Param == NULL)
		return 0;

	return (USHORT)InterlockedCompareExchange(&((QUIC_NET *)t->Param)->BoundPort, 0, 0);
}

void TransportQuicFree(TRANSPORT *t) {
	QUIC_NET *net;

	if (t == NULL)
		return;

	net = (QUIC_NET *)t->Param;
	if (net != NULL) {
		// Close the configuration and the registration; the registration close waits for every
		// connection of the transport to finish, so no callback runs after it
		if (net->Configuration != NULL)
			g_quic->ConfigurationClose(net->Configuration);
		if (net->Registration != NULL)
			g_quic->RegistrationClose(net->Registration);
		SecureZeroMemory(net->Binding, sizeof(net->Binding));
		QuicRelease(net, sizeof(QUIC_NET));
		QuicApiClose();
	}

	QuicRelease(t, sizeof(TRANSPORT));
}
