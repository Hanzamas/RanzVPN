// Transport.h
// The transport module of the new core (ADR-0005, ADR-0023 decision 2; CORE-F4, #64), on the
// session module (Core/Noise.h). It has four parts:
// - The transport interface (Transport.c): a transport (TRANSPORT) is a name and a set of
//   procedures over its own stream and listener objects: dial, listen, accept, stream read and
//   write, close, and for a transport that encrypts, the channel binding of a stream and the update
//   of its keys. QUIC, TLS-443 and the transports of phase 2 (the mimicry sidecar's named pipe, the
//   CDN path) each fill one in; the session layer and the race stay as they are.
// - The session layer (TransportNoise.c): a Noise session over a stream of any transport. Each
//   record goes as a frame, its size in 4 bytes (big-endian) and then the record, as on the
//   control stream. The stream's channel binding goes into the handshake; a stream that nothing
//   binds gets an encrypted session (NOISE_SESSION_ENCRYPT). On a transport over TCP the data
//   records wait in the ingress queue of the session (TransportQueue.c), which CoDel runs.
// - The race (Transport.c): a client dials the transports of its fallback list (QUIC, then TLS-443,
//   then the CDN path, ADR-0005) happy-eyeballs style, after RFC 8305: an attempt starts the attempt
//   delay after the one before it, or at once when every attempt so far failed; the first stream
//   to connect wins, and the attempts still dialling are cancelled.
// - The loopback transport (TransportLoopback.c): streams in memory between a dialler and a
//   listener of the same process, for the vpntest harness and the nodes it runs in one process.
//
// The module links the session module and the crypto module only. A stream and a listener belong
// to the caller, which serialises the calls on each, except that one thread may read a stream
// while another writes it. Timeouts are milliseconds; INFINITE waits without a limit.

#ifndef CORE_TRANSPORT_H
#define CORE_TRANSPORT_H

#include "Core/Noise.h"

#define TRANSPORT_NAME_SIZE    32  // A transport name with its terminating NUL
#define TRANSPORT_ADDRESS_SIZE 256 // An address with its terminating NUL: a host and a port, a URL, a pipe name
#define TRANSPORT_MAX_TARGETS  8   // The entries of a fallback list at most
#define TRANSPORT_RACE_DELAY   250 // The attempt delay (ms) that RFC 8305 section 8 recommends

// What a read gives when nothing came within its timeout: the stream stays open
#define TRANSPORT_LATER 0xFFFFFFFF

// A stream and a listener: the object of the transport, and the transport (Transport.c)
typedef struct TRANSPORT_STREAM TRANSPORT_STREAM;
typedef struct TRANSPORT_LISTENER TRANSPORT_LISTENER;

// The procedures of a transport, on its own stream and listener objects; param is the transport's
// Param. Dial connects to address and gives the stream; it fails when nothing answers there, and
// returns as soon as it can once cancel (a manual-reset event, or NULL for none) is set. Listen
// opens a listener on address. Accept gives the next stream that dialled the listener within
// timeout; it fails when none came or the listener closed. CloseListener closes a listener and
// the streams it did not give yet, also while an Accept waits. Read gives up to size bytes within
// timeout: their number, at least 1; 0 when the stream ended (the peer closed it, or it failed);
// TRANSPORT_LATER when nothing came. Write writes all size bytes; after the peer closed, they may
// go nowhere, as on TCP, and the next read shows the end. Close closes a stream: the peer reads
// the bytes it had not read yet, then the end. Binding gives the channel binding of the
// outer TLS or QUIC session that encrypts the stream (NOISE_BINDING_*, the binding in binding,
// max bytes at most, and its size), or NOISE_BINDING_NONE for a stream that nothing encrypts.
// Rekey updates the keys of that outer session (TLS 1.3 KeyUpdate, the QUIC key update). Binding
// and Rekey may be NULL: no binding, and no keys to update.
typedef bool(TRANSPORT_DIAL_PROC)(void *param, const char *address, HANDLE cancel, void **stream);
typedef bool(TRANSPORT_LISTEN_PROC)(void *param, const char *address, void **listener);
typedef bool(TRANSPORT_ACCEPT_PROC)(void *listener, UINT timeout, void **stream);
typedef void(TRANSPORT_CLOSE_LISTENER_PROC)(void *listener);
typedef UINT(TRANSPORT_READ_PROC)(void *stream, void *buf, UINT size, UINT timeout);
typedef bool(TRANSPORT_WRITE_PROC)(void *stream, const void *buf, UINT size);
typedef void(TRANSPORT_CLOSE_PROC)(void *stream);
typedef UINT(TRANSPORT_BINDING_PROC)(void *stream, UCHAR *binding, UINT max, UINT *size);
typedef bool(TRANSPORT_REKEY_PROC)(void *stream);

// One transport: its name in a fallback list, its state and its procedures
typedef struct TRANSPORT {
	char Name[TRANSPORT_NAME_SIZE];               // "quic", "tls", "loopback": the name in a fallback list
	void *Param;                                  // The transport's own state, the first parameter of Dial and Listen
	TRANSPORT_DIAL_PROC *Dial;                    // Connect to an address
	TRANSPORT_LISTEN_PROC *Listen;                // Listen on an address
	TRANSPORT_ACCEPT_PROC *Accept;                // Take the next stream of a listener
	TRANSPORT_CLOSE_LISTENER_PROC *CloseListener; // Close a listener
	TRANSPORT_READ_PROC *Read;                    // Read a stream
	TRANSPORT_WRITE_PROC *Write;                  // Write a stream
	TRANSPORT_CLOSE_PROC *Close;                  // Close a stream
	TRANSPORT_BINDING_PROC *Binding;              // The channel binding of a stream, or NULL
	TRANSPORT_REKEY_PROC *Rekey;                  // Update the outer keys of a stream, or NULL
	UINT Queue;                                   // TRANSPORT_QUEUE_*: the ingress queue of the sessions over it, NONE for none
} TRANSPORT;

// One entry of a fallback list: a transport and the address it dials
typedef struct TRANSPORT_TARGET {
	TRANSPORT *Transport;                 // The transport
	char Address[TRANSPORT_ADDRESS_SIZE]; // The address it dials
} TRANSPORT_TARGET;

// How a race went (TransportRace)
typedef struct TRANSPORT_RACE {
	UINT Winner;     // The index of the entry whose stream won, INFINITE when none connected
	UINT NumStarted; // The attempts started: an entry starts only while no stream connected
	UINT NumFailed;  // The attempts that failed before the race was over; a cancelled one did not
	UINT64 Elapsed;  // ms from the start to the winner's connect, or to the end of a race that none won
} TRANSPORT_RACE;

// The ingress queue (TransportQueue.c; CORE-S2-1 #69, the ADR-0022 amendment of 2026-10-15 on the
// TCP-over-TCP meltdown). On a transport over TCP (TLS-443) an outer segment that the network lost
// holds up every byte behind it until the outer TCP sends it again, so an inner TCP flow that
// waits behind it times out and sends again into the same stalled stream. The data records of a
// session over such a transport (TRANSPORT.Queue) wait in a queue in front of the stream instead:
// Send queues a data record and returns, and a writer on the Windows thread pool writes the
// records that the queue lets out. CoDel (RFC 8289) runs the queue: once the records waited longer
// than the target for an interval, it drops records at the head, at a rate that grows while they
// still wait too long, so that an inner TCP flow backs off at the first drop instead of filling a
// buffer. A FIFO queue drops only at its limit, at the tail, as a full buffer does. Control,
// keepalive and close records never wait in it. Times are microseconds (TransportQueueNow).
#define TRANSPORT_QUEUE_NONE  0 // Send writes each record to the stream at once: QUIC, the loopback transport
#define TRANSPORT_QUEUE_FIFO  1 // The data records wait in a queue that drops only at its limit
#define TRANSPORT_QUEUE_CODEL 2 // ... which CoDel runs

#define TRANSPORT_QUEUE_TARGET   5000   // The target of the time a record waits (us), as RFC 8289 recommends
#define TRANSPORT_QUEUE_INTERVAL 100000 // The interval (us), as RFC 8289 recommends
#define TRANSPORT_QUEUE_LIMIT    1000   // Records that wait at most: the limit of the Linux codel queue discipline

// An ingress queue: the records that wait, oldest first, the state of CoDel and the counters
typedef struct TRANSPORT_QUEUE_ITEM TRANSPORT_QUEUE_ITEM;
typedef struct TRANSPORT_QUEUE {
	UINT Mode;                  // TRANSPORT_QUEUE_FIFO or TRANSPORT_QUEUE_CODEL
	UINT Limit;                 // Records that wait at most: one pushed above it is dropped
	UINT64 Target;              // CoDel: the target of the sojourn time (us)
	UINT64 Interval;            // CoDel: the interval (us)
	TRANSPORT_QUEUE_ITEM *Head; // The oldest record ...
	TRANSPORT_QUEUE_ITEM *Tail; // ... and the newest
	UINT NumRecords;            // The records that wait ...
	UINT64 Bytes;               // ... and their bytes
	UINT MaxRecord;             // The largest record pushed: CoDel drops nothing while no more bytes wait
	UINT64 FirstAbove;          // CoDel: when the sojourn time will have stayed above the target for an interval, 0 below it
	UINT64 DropNext;            // CoDel, dropping: when the next record is dropped
	UINT Count;                 // CoDel: the records dropped since the dropping state began ...
	UINT LastCount;             // ... and their number when it began
	bool Dropping;              // CoDel: the dropping state
	UINT64 NumPushed;           // Records pushed
	UINT64 NumPopped;           // ... that left to be written
	UINT64 NumDropped;          // ... that CoDel dropped at the head
	UINT64 NumOverflow;         // ... dropped at the tail: pushed while the queue was at its limit
} TRANSPORT_QUEUE;

// What the ingress queue of a session did (TransportNoiseQueueStatus)
typedef struct TRANSPORT_QUEUE_STATUS {
	UINT NumRecords;    // Records that wait
	UINT64 NumPushed;   // Records pushed
	UINT64 NumPopped;   // ... written
	UINT64 NumDropped;  // ... dropped by CoDel
	UINT64 NumOverflow; // ... dropped at the limit
} TRANSPORT_QUEUE_STATUS;

// The frame of a record on a stream: the size of the record (4 bytes, big-endian), then the record
#define TRANSPORT_FRAME_HEADER 4
#define TRANSPORT_MAX_FRAME    (TRANSPORT_FRAME_HEADER + NOISE_MAX_RECORD)

// A Noise session over a stream of a transport
typedef struct TRANSPORT_NOISE {
	TRANSPORT_STREAM *Stream;   // The stream: NULL before Connect or Accept, and after Close
	NOISE_SESSION Session;      // The Noise session
	SRWLOCK Lock;               // Serialises the session and the writes of the stream, so that Send runs beside Receive
	UCHAR *In;                  // The frame being read, TRANSPORT_MAX_FRAME bytes ...
	UINT InSize;                // ... and its bytes read so far
	UCHAR *Out;                 // The frame being written, under Lock
	UINT64 NumSent;             // Records written to the stream
	UINT64 NumReceived;         // Records read from it
	TRANSPORT_QUEUE *Queue;     // The ingress queue of the data records (TRANSPORT.Queue), NULL for none
	SRWLOCK QueueLock;          // The queue and the writer's flags below
	CONDITION_VARIABLE Written; // The writer stopped
	PTP_WORK Writer;            // The writer: a work of the Windows thread pool
	UCHAR *Pending;             // The record that the writer writes, NOISE_MAX_PAYLOAD bytes
	bool Writing;               // The writer was submitted and did not stop yet
	bool Closing;               // Close runs: the queue takes no record any more
	bool Failed;                // The session closed or its stream failed: the queue takes no record any more
} TRANSPORT_NOISE;

// The transport interface (Transport.c): each call goes to the procedure of the transport of the
// stream or the listener, with the meaning above. Dial and Listen take the transport and an
// address, Accept a timeout, Read a timeout. Close and CloseListener free the object. TransportOf
// gives the transport of a stream.
TRANSPORT_STREAM *TransportDial(TRANSPORT *t, const char *address, HANDLE cancel);
TRANSPORT_LISTENER *TransportListen(TRANSPORT *t, const char *address);
TRANSPORT_STREAM *TransportAccept(TRANSPORT_LISTENER *l, UINT timeout);
void TransportCloseListener(TRANSPORT_LISTENER *l);
UINT TransportRead(TRANSPORT_STREAM *s, void *buf, UINT size, UINT timeout);
bool TransportWrite(TRANSPORT_STREAM *s, const void *buf, UINT size);
void TransportClose(TRANSPORT_STREAM *s);
UINT TransportBinding(TRANSPORT_STREAM *s, UCHAR *binding, UINT max, UINT *size);
bool TransportRekey(TRANSPORT_STREAM *s);
TRANSPORT *TransportOf(TRANSPORT_STREAM *s);

// The fallback list (Transport.c). ParseList reads a configured list: its entries, at most max,
// separated by commas, each the name of one of the known transports, a colon and the address,
// spaces around an entry ignored ("quic:vpn.example:443, tls:vpn.example:443"). It gives the number
// of entries, or 0 when an entry is empty or malformed or names no known transport, or the list
// holds more than max. Race dials the entries of a list in order: an attempt starts delay ms after
// the one before it (TRANSPORT_RACE_DELAY), or at once when every attempt so far failed, each on a
// thread of the Windows thread pool. The first stream to connect wins: Race cancels the other
// attempts, closes a stream that connects after the winner's, and gives the winner's stream once
// every attempt returned. It gives NULL when every attempt failed, or none connected within
// timeout. race, which may be NULL, tells how it went.
UINT TransportParseList(const char *list, TRANSPORT **transports, UINT num_transports, TRANSPORT_TARGET *targets, UINT max);
TRANSPORT_STREAM *TransportRace(const TRANSPORT_TARGET *targets, UINT num, UINT delay, UINT timeout, TRANSPORT_RACE *race);

// The session layer (TransportNoise.c). Connect runs the initiator of a Noise session on a stream,
// Accept the responder; each takes the stream, with cfg as for NoiseSessionConnect and
// NoiseSessionAccept but for the binding, which comes from the stream, and the flag
// NOISE_SESSION_ENCRYPT, which a stream without a binding sets. When the handshake fails within
// timeout, they close the stream and the session is closed. Send writes one record of a stream
// (NOISE_RECORD_DATA or NOISE_RECORD_CONTROL) or a NOISE_RECORD_CLOSE. Receive waits timeout at
// most for a record for the owner and gives NOISE_RECEIVE_DATA, CONTROL or CLOSE with its payload
// in data (max bytes; NOISE_MAX_PAYLOAD takes any), NOISE_RECEIVE_NONE when nothing came for the
// owner, or NOISE_RECEIVE_ERROR when the stream ended or the session failed, closed or died; while
// it waits, it sends the keepalives, takes the next keys and updates the outer keys of a bound
// stream on schedule, so an open session needs a Receive at least once per keepalive interval.
// Send may run on one thread while Receive runs on another. AcceptLogin opens the data stream
// after the owner checked the Login (NoiseSessionAcceptLogin). Close sends the close record while
// the session is open, closes the stream and wipes the session, once no other call runs on it.
// On a transport with an ingress queue, Send queues a data record for the writer and returns: it
// fails when the session took its last record (it is closing, closed or its stream failed) or the
// queue dropped the record at its limit; Close lets the writer write the records that wait first.
// QueueStatus tells what the ingress queue did, false for a session without one.
bool TransportNoiseConnect(TRANSPORT_NOISE *n, TRANSPORT_STREAM *s, const NOISE_SESSION_CONFIG *cfg, UINT timeout);
bool TransportNoiseAccept(TRANSPORT_NOISE *n, TRANSPORT_STREAM *s, const NOISE_SESSION_CONFIG *cfg, UINT timeout);
bool TransportNoiseSend(TRANSPORT_NOISE *n, UINT type, const void *data, UINT size);
UINT TransportNoiseReceive(TRANSPORT_NOISE *n, void *data, UINT max, UINT *size, UINT timeout);
void TransportNoiseAcceptLogin(TRANSPORT_NOISE *n);
void TransportNoiseClose(TRANSPORT_NOISE *n);
bool TransportNoiseQueueStatus(TRANSPORT_NOISE *n, TRANSPORT_QUEUE_STATUS *st);

// The ingress queue (TransportQueue.c), on its own: the session layer serialises its calls. Init
// makes an empty queue of a mode (TRANSPORT_QUEUE_FIFO or TRANSPORT_QUEUE_CODEL) with the target,
// the interval and the limit above. Push queues a copy of size bytes that came at now: false, with
// the record dropped, while the queue is at its limit. Pop gives the next record that leaves at now
// into data (max bytes) and *size, false when none waits; the records that CoDel drops on the way
// are gone, as is one larger than max. Free drops every record that waits. Now gives the time of
// the queue, microseconds of QueryPerformanceCounter.
void TransportQueueInit(TRANSPORT_QUEUE *q, UINT mode);
bool TransportQueuePush(TRANSPORT_QUEUE *q, UINT64 now, const void *data, UINT size);
bool TransportQueuePop(TRANSPORT_QUEUE *q, UINT64 now, void *data, UINT max, UINT *size);
void TransportQueueFree(TRANSPORT_QUEUE *q);
UINT64 TransportQueueNow();

// The loopback transport (TransportLoopback.c). New makes one, with a network of its own: its
// listeners take any name as their address, and its dialler finds them by it. A dial waits
// dial_delay ms first (INFINITE: until it is cancelled), which stands in for the round trips of a
// real transport, so that the harness races transports of different speeds. Its streams have no
// channel binding, unless bound: each stream then has a random binding that both of its ends
// give, which stands in for the exporter of a TLS or QUIC session. Free frees the transport once
// its listeners are closed.
TRANSPORT *TransportLoopbackNew(const char *name, UINT dial_delay, bool bound);
void TransportLoopbackFree(TRANSPORT *t);

// The QUIC transport (TransportQuic.c, CORE-S1-1 #67), on the official signed msquic.dll (the
// Schannel build, pinned, x64 and arm64). A listener presents as an HTTP/3 server: the ALPN "h3", a
// real certificate read from the Windows certificate store by its thumbprint, and BBR where the
// msquic build has it, so its posture equals ordinary Windows HTTP/3. The session layer runs the
// Noise session over one reliable bidirectional stream of the connection (the handshake, the Login,
// the control stream and the data stream, whose L2 frames enter the existing Hub as the Session of a
// Tunnel, CORE-S1-2 #68). The connection advertises QUIC DATAGRAM frames, which no data path takes
// yet. The channel binding of a
// stream is the tls-server-end-point of the pinned server certificate (RFC 5929, NOISE_BINDING_
// SERVER_END_POINT): both ends compute it from the certificate msquic presents, because Schannel
// exposes no RFC 8446 exporter to msquic yet (the CORE-S1-1 spike of ADR-0022, amendment of
// 2026-10-15). The client pins the server certificate: a connection whose certificate does not
// match the configured thumbprint is refused, and the system root store is not trusted (ADR-0023).
//
// The module links the official import library msquic.lib and loads msquic.dll at the first QUIC
// call (the link is delay-loaded, so a program that never dials or listens over QUIC needs no DLL).
// TransportQuicAvailable opens the msquic API once and reports whether the DLL is present.
#define TRANSPORT_QUIC_ALPN "h3" // The default ALPN: the HTTP/3 posture

// How a QUIC transport is configured
typedef struct TRANSPORT_QUIC_CONFIG {
	char Name[TRANSPORT_NAME_SIZE];                  // The transport name in a fallback list ("quic")
	char Alpn[TRANSPORT_NAME_SIZE];                  // The ALPN it offers; TRANSPORT_QUIC_ALPN for HTTP/3
	char Thumbprint[2 * CRYPTO_THUMBPRINT_SIZE + 1]; // The server certificate in the store, by its SHA-1 thumbprint
	bool MachineStore;                               // The LocalMachine\My store (the service); else the current user's
	bool Bbr;                                        // Ask msquic for BBR; the default congestion control where it has none
	UINT IdleTimeoutMs;                              // The QUIC idle timeout, 0 for TRANSPORT_QUIC_IDLE_DEFAULT
	bool BreakBinding;                               // A client that changes the binding it computes: for the mismatch test
} TRANSPORT_QUIC_CONFIG;

#define TRANSPORT_QUIC_IDLE_DEFAULT 30000 // The QUIC idle timeout without one in the configuration (ms)

// Fill cfg with the defaults: the name "quic", the ALPN "h3", the thumbprint of the server
// certificate (upper-case hex, spaces and colons ignored) and the store it is in
void TransportQuicDefaultConfig(TRANSPORT_QUIC_CONFIG *cfg, const char *thumbprint, bool machine_store);

// Whether msquic.dll is present and its API opened: false when the DLL is missing, so a caller
// tells a configuration error from a transport that cannot run
bool TransportQuicAvailable();

// A server transport that listens with the certificate cfg names, or a client transport that dials
// and pins that certificate. Each opens its own msquic registration and configuration. New returns
// NULL when msquic is absent or the certificate cannot be loaded. The address of Listen and Dial is
// a host and a port ("vpn.example:443", ":443" to listen on every address); TransportQuicBoundPort
// gives the port the last listener of a server transport bound, for a listener on port 0. Free
// closes the transport once its listeners and streams are closed.
TRANSPORT *TransportQuicServerNew(const TRANSPORT_QUIC_CONFIG *cfg);
TRANSPORT *TransportQuicClientNew(const TRANSPORT_QUIC_CONFIG *cfg);
USHORT TransportQuicBoundPort(TRANSPORT *t);
void TransportQuicFree(TRANSPORT *t);

// The TLS transport (TransportTls.c, CORE-S2-1 #69), on Schannel through SSPI: TLS 1.3 and 1.2 over
// TCP on the Windows TCP stack, for a client that cannot use UDP (TLS-443 in a fallback list,
// ADR-0005). The server credential (SCH_CREDENTIALS) presents a certificate read from the Windows
// certificate store by its thumbprint, whose private key must be in a CNG key storage provider: a
// PFX is imported into the KSP (CryptoCertImportPfx), and a certificate whose key sits in a legacy
// CryptoAPI provider (CSP) is refused, so Schannel never meets one (ADR-0022, amendment of
// 2026-10-21). Both ends allow AES-GCM only (no ChaCha20-Poly1305, no CBC or CCM) and an ephemeral
// key exchange only (no static RSA, no finite-field DHE). The session layer runs the Noise session
// over a stream unchanged: the handshake, the Login and the data stream whose L2 frames enter the
// Hub (CORE-S1-2 #68). The channel binding of a stream is the TLS exporter of its session (RFC 8446
// section 7.5, RFC 5705 for TLS 1.2; NOISE_BINDING_EXPORTER), which Schannel gives through
// SECPKG_ATTR_KEYING_MATERIAL. The client pins the server certificate: a certificate whose
// thumbprint is not the configured one is refused, and the system root store is not trusted
// (ADR-0023). Every handshake is a full one: the server keeps no session for a resumption. The data
// records of a session over the transport wait in its ingress queue, which CoDel runs by default.
//
// The key exchange groups: X25519MLKEM768 first where the OS has ML-KEM, X25519 as the fallback.
// Schannel takes no list of groups per credential (SCH_CREDENTIALS and TLS_PARAMETERS can only
// disable algorithms), and builds 26100 and 26200 do not offer the hybrid by default, so
// TransportTlsSetGroups sets the machine's Schannel group list, the one that Enable-TlsEccCurve
// writes and Schannel reads: the value EccCurves of the key
// HKLM\SYSTEM\CurrentControlSet\Control\Cryptography\Configuration\Local\SSL\00010002, with the
// transport's groups first and the groups the list had after them. An ECC Curve Order group policy
// overrides that list where one is set; the transport leaves it as the administrator set it.
//
// The Trojan posture (CORE-S2-2, #70): a server with a decoy configured (Decoy) reads the first
// application bytes after the TLS handshake and reverse-proxies a prober, one whose first handshake
// message does not authenticate there, to a website the operator runs on the loopback interface, so
// the prober meets an ordinary HTTPS site byte for byte (the decoy module, TransportDecoy.c, below).
// A client may split its ClientHello into two TCP segments (SplitClientHello), the cut in the middle
// of the server name, and omit the server name (OmitSni), so a DPI engine that matches an SNI
// keyword in one segment sees neither the whole name nor, to our own servers, any name at all.
#define TRANSPORT_TLS_12 0x00000001 // TLS 1.2
#define TRANSPORT_TLS_13 0x00000002 // TLS 1.3

// What TransportTlsSetGroups did
#define TRANSPORT_TLS_GROUPS_SET    0 // The machine's list starts with the transport's groups
#define TRANSPORT_TLS_GROUPS_POLICY 1 // An ECC Curve Order policy governs the list, which stays as it is
#define TRANSPORT_TLS_GROUPS_FAILED 2 // The list could not be read or written (administrator rights)

// How a TLS transport is configured
typedef struct TRANSPORT_TLS_CONFIG {
	char Name[TRANSPORT_NAME_SIZE];              // The transport name in a fallback list ("tls")
	char Thumbprint[3 * CRYPTO_THUMBPRINT_SIZE]; // The server certificate in the store, by its SHA-1 thumbprint
	bool MachineStore;                           // The LocalMachine\My store (the service); else the current user's
	UINT Versions;                               // TRANSPORT_TLS_12, TRANSPORT_TLS_13 or both: the versions it negotiates
	bool SetGroups;                              // New sets the key exchange groups of the machine (TransportTlsSetGroups)
	bool BreakBinding;                           // A client that changes the binding it computes: for the mismatch test
	UINT Queue;                                  // TRANSPORT_QUEUE_*: the ingress queue of the sessions over it (CODEL)
	char Decoy[TRANSPORT_ADDRESS_SIZE];          // The own-decoy backend a prober is reverse-proxied to ("127.0.0.1:port"); empty for none (server)
	const UCHAR *DecoyKey;                       // With a decoy: the static key of the sessions over the server, a scalar ...
	CRYPTO_IDENTITY *DecoyIdentity;              // ... or the node identity in the KSP, exactly one, kept by the owner while the transport lives
	bool SplitClientHello;                       // The client splits its ClientHello into two TCP segments (client)
	bool OmitSni;                                // The client omits the server name from its ClientHello (client)
} TRANSPORT_TLS_CONFIG;

// What a TLS handshake gave: the version, the cipher suite and the key exchange group that the
// server chose. The group is the one of the ServerHello on the wire (TransportTlsParseHello), which
// the client reads among the server's records and the server among its own.
typedef struct TRANSPORT_TLS_INFO {
	UINT Version;     // TRANSPORT_TLS_12 or TRANSPORT_TLS_13
	UINT CipherSuite; // The TLS cipher suite (0x1302 TLS_AES_256_GCM_SHA384, ...)
	UINT Group;       // The key exchange group of TLS 1.3 (CRYPTO_GROUP_*), 0 for TLS 1.2
	bool Retried;     // The server asked for a key share of another group first (a HelloRetryRequest)
} TRANSPORT_TLS_INFO;

// Fill cfg with the defaults: the name "tls", TLS 1.2 and 1.3, the groups set, the ingress queue
// that CoDel runs, the thumbprint of the server certificate (hex, spaces and colons ignored) and the
// store it is in
void TransportTlsDefaultConfig(TRANSPORT_TLS_CONFIG *cfg, const char *thumbprint, bool machine_store);

// A server transport that listens with the certificate cfg names, or a client transport that dials
// and pins that certificate; each acquires its own Schannel credential. New returns NULL when the
// thumbprint is malformed, or the server's certificate is not in the store or has no key in a KSP,
// or a server has a decoy without exactly one of DecoyKey and DecoyIdentity.
// The address of Listen and Dial is a host and a port ("vpn.example:443", "[::1]:443", ":443" to
// listen on every address of both families); TransportTlsBoundPort gives the port the last listener
// of a server transport bound, for a listener on port 0. LastHandshake gives what the last handshake
// that completed on the transport gave, false before there was one. Free closes the transport once
// its listeners and streams are closed.
TRANSPORT *TransportTlsServerNew(const TRANSPORT_TLS_CONFIG *cfg);
TRANSPORT *TransportTlsClientNew(const TRANSPORT_TLS_CONFIG *cfg);
USHORT TransportTlsBoundPort(TRANSPORT *t);
bool TransportTlsLastHandshake(TRANSPORT *t, TRANSPORT_TLS_INFO *info);
void TransportTlsFree(TRANSPORT *t);

// Put the transport's key exchange groups first in the machine's Schannel group list:
// X25519MLKEM768 where the OS has ML-KEM (CryptoMlKemAvailable), then X25519, then the other groups
// of the list in their order (the list of Windows 11 24H2 where the machine has none of its own). It
// needs administrator rights and gives TRANSPORT_TLS_GROUPS_*.
UINT TransportTlsSetGroups();

// Read the first ServerHello, or HelloRetryRequest, of data: size bytes of the TLS records a server
// sends, ChangeCipherSpec records before it skipped. It fills info with the version (that of
// supported_versions where it is there), the cipher suite, the group of key_share (TLS 1.3) and
// whether it is a HelloRetryRequest; false, with info untouched, when data does not start with a
// whole record holding a whole ServerHello.
bool TransportTlsParseHello(const UCHAR *data, UINT size, TRANSPORT_TLS_INFO *info);

// The own-decoy reverse proxy (TransportDecoy.c, CORE-S2-2 #70): the Trojan posture of the TLS
// transport. After the TLS handshake a server reads the first application bytes of a stream. A
// client that opens a valid Ranz session sends the first Noise handshake frame there, which
// authenticates it (TransportDecoyAuthenticate); a prober that sends anything else, or a handshake
// message that does not authenticate, is reverse-proxied to a website the operator runs on the
// loopback interface (TransportDecoyProxy), so it meets an ordinary HTTPS site byte for byte over
// the same TLS session it opened. The TLS transport keeps the decoy out of its own path: it reads
// the first frame and calls these with a small hook, giving the session the bytes it read on a
// valid frame and the stream to the proxy on anything else. The proxy opens its own TCP connection
// to the backend on the Windows TCP stack.

// The encrypted side of a reverse-proxied stream, the prober's: the TLS transport's own stream read
// and write, so the decoy module reaches the prober without the Schannel context
typedef UINT(TRANSPORT_DECOY_READ)(void *stream, void *buf, UINT size, UINT timeout);
typedef bool(TRANSPORT_DECOY_WRITE)(void *stream, const void *buf, UINT size);
typedef struct TRANSPORT_DECOY_IO {
	void *Stream;                 // The prober's stream (a TLS_STREAM of TransportTls.c)
	TRANSPORT_DECOY_READ *Read;   // Read the prober's decrypted bytes
	TRANSPORT_DECOY_WRITE *Write; // Write bytes to the prober, which its TLS session encrypts
} TRANSPORT_DECOY_IO;

// Whether the first bytes of a stream are a valid Ranz handshake frame: at least a frame header and
// a record type and suite, a length that is a record's (2..NOISE_MAX_RECORD) and no longer than the
// bytes read, and a record that is a handshake record (NOISE_RECORD_HANDSHAKE) of a suite the node
// runs (NoiseSuiteAvailable). It reads no further than size bytes, so the caller may give it as few
// bytes as came. This is the structural test the session layer makes before it reads the handshake.
bool TransportDecoyIsHandshake(const UCHAR *first, UINT size);

// Whether the first bytes of a stream authenticate a client of this server: a valid handshake frame
// (TransportDecoyIsHandshake) whose Noise message the responder reads as the session layer will,
// with the server's static key (key, a scalar, or identity, the node identity in the KSP: exactly
// one) and the channel binding of the stream in the prologue (binding_type, binding_size bytes of
// binding). The first message of IK decrypts only for an initiator that knows the server's static
// key and made it for this outer session, so a prober that guesses the shape, or replays a message
// of another session, fails. The handshake it reads is wiped; the session layer reads the message
// again for the session. A prober that fails is reverse-proxied to the decoy.
bool TransportDecoyAuthenticate(const UCHAR *first, UINT size, const UCHAR *key, CRYPTO_IDENTITY *identity, UINT binding_type,
                                const UCHAR *binding, UINT binding_size);

// Reverse-proxy the prober of io to the decoy backend that address names ("host:port" on the
// loopback interface): open a TCP connection to it, send the first size bytes (what the prober
// already sent) to it, and then carry bytes both ways until either side ends or cancel (which may be
// NULL) is set. false when the backend cannot be reached, so the caller closes the stream; true once
// the proxy ran. The prober sees the backend's bytes byte for byte over its own TLS session.
bool TransportDecoyProxy(const TRANSPORT_DECOY_IO *io, const char *address, const UCHAR *first, UINT size, HANDLE cancel);

// Where the server name lies in a ClientHello (TransportHello.c, CORE-S2-2 #70): hello holds size
// bytes of a TLS handshake record that starts with a ClientHello, as Schannel writes a client's first
// token. It gives the offset of the host name of the server_name extension in hello and its length
// (at least 1); false when the ClientHello has no server_name or hello holds no whole one. It reads
// no further than size bytes. A client that splits its ClientHello cuts it in the middle of that
// name, so that neither TCP segment holds the whole name.
bool TransportTlsHelloName(const UCHAR *hello, UINT size, UINT *offset, UINT *length);

#endif // CORE_TRANSPORT_H
