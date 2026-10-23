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
//   binds gets an encrypted session (NOISE_SESSION_ENCRYPT).
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

// The frame of a record on a stream: the size of the record (4 bytes, big-endian), then the record
#define TRANSPORT_FRAME_HEADER 4
#define TRANSPORT_MAX_FRAME    (TRANSPORT_FRAME_HEADER + NOISE_MAX_RECORD)

// A Noise session over a stream of a transport
typedef struct TRANSPORT_NOISE {
	TRANSPORT_STREAM *Stream; // The stream: NULL before Connect or Accept, and after Close
	NOISE_SESSION Session;    // The Noise session
	SRWLOCK Lock;             // Serialises the session and the writes of the stream, so that Send runs beside Receive
	UCHAR *In;                // The frame being read, TRANSPORT_MAX_FRAME bytes ...
	UINT InSize;              // ... and its bytes read so far
	UCHAR *Out;               // The frame being written, under Lock
	UINT64 NumSent;           // Records written to the stream
	UINT64 NumReceived;       // Records read from it
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
bool TransportNoiseConnect(TRANSPORT_NOISE *n, TRANSPORT_STREAM *s, const NOISE_SESSION_CONFIG *cfg, UINT timeout);
bool TransportNoiseAccept(TRANSPORT_NOISE *n, TRANSPORT_STREAM *s, const NOISE_SESSION_CONFIG *cfg, UINT timeout);
bool TransportNoiseSend(TRANSPORT_NOISE *n, UINT type, const void *data, UINT size);
UINT TransportNoiseReceive(TRANSPORT_NOISE *n, void *data, UINT max, UINT *size, UINT timeout);
void TransportNoiseAcceptLogin(TRANSPORT_NOISE *n);
void TransportNoiseClose(TRANSPORT_NOISE *n);

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

#endif // CORE_TRANSPORT_H
