// FrontDoor.h
// The front door of the new core (SDN-29, #205; ADR-0035): the TCP listener of a node, on 443 in a deployment, that
// reads the first bytes of each connection with MSG_PEEK, so it consumes none of them, routes the connection to the
// process that owns its protocol, and hands the socket to that process. A TLS connection is routed by the server name
// (SNI) and the ALPN protocols of its ClientHello, any other connection by its first bytes.
//
// The owner table is data (FRONT_DOOR_OWNER), tried in order: the first owner that takes a connection gets it. An owner
// in the front door's own process, the node's TLS for the new protocol, takes the socket through its procedure (the TLS
// transport takes it with TransportTake). An owner in another process, the Controller with the web UI and the API (ALPN
// h2 and http/1.1), takes it through its handoff pipe: the front door duplicates the socket into the owner process with
// WSADuplicateSocketW, writes the WSAPROTOCOL_INFOW to the pipe in a handoff message, the owner makes its own socket of
// it (FrontDoorPipeAccept) and answers, and the front door closes its handle. No byte passes through the front door
// after the handoff: the owner reads the first bytes from the socket itself, and the connection outlives the front
// door's process. UDP 443 stays QUIC only (TransportQuic.c): the front door listens on TCP alone.
//
// The address and the owner table are plain parameters, which the Listener resource (SDN-45, #238) will set; so will
// the fallback to 5555 when 443 is taken (the amendment of ADR-0035), which is a second start on the other address.
// The certificate of the new protocol's TLS is the one of the TLS transport that takes the node's connections.
//
// A connection that starts like a TLS handshake record (the bytes 22 and 3) is TLS: it goes to the first TLS owner whose
// server names and protocols take what its ClientHello names, and to none when the ClientHello is malformed, larger
// than FRONT_DOOR_MAX_HELLO or not complete within the peek timeout. A ClientHello may come in several TCP segments and
// several TLS records (ADR-0023: the fragmentation of the ClientHello is a client toggle). Any other connection goes to
// the first byte owner whose prefix it starts with; while an earlier owner's longer prefix may still match, the front
// door waits for more bytes. A connection that no owner takes is closed.

#ifndef CORE_FRONT_DOOR_H
#define CORE_FRONT_DOOR_H

#include <winsock2.h>
#include <windows.h>

#include <stdbool.h>

#define FRONT_DOOR_PORT 443 // The port of the front door in a deployment (ADR-0035 decision 1)

// The limits of the owner table
#define FRONT_DOOR_MAX_OWNERS   16  // Owners of one front door at most
#define FRONT_DOOR_NAME_SIZE    32  // An owner's name, its terminator included
#define FRONT_DOOR_LIST_SIZE    256 // A list of server names or ALPN protocols, its terminator included
#define FRONT_DOOR_PREFIX_SIZE  32  // The first bytes of a byte owner at most
#define FRONT_DOOR_PIPE_SIZE    128 // Characters of a pipe name, its terminator included
#define FRONT_DOOR_ADDRESS_SIZE 256 // The address of a front door, its terminator included

// What the front door reads of a connection before it hands it over
#define FRONT_DOOR_MAX_HELLO     16384 // The largest ClientHello it reads: the handshake message, its header included
#define FRONT_DOOR_MAX_PEEK      32768 // Bytes it peeks at most: the ClientHello in records, or the first bytes
#define FRONT_DOOR_MAX_NAME      255   // Bytes of a server name at most (RFC 6066 section 3)
#define FRONT_DOOR_MAX_PROTOCOLS 16    // ALPN protocols of a ClientHello that it keeps
#define FRONT_DOOR_MAX_PROTOCOL  255   // Bytes of an ALPN protocol at most (RFC 7301 section 3.1)

// The timers of a connection
#define FRONT_DOOR_PEEK_TIMEOUT    10000 // The first bytes decide the owner within this time, or the connection closes (ms)
#define FRONT_DOOR_HANDOFF_TIMEOUT 5000  // An owner process answers a handoff within this time (ms)
#define FRONT_DOOR_PEEK_POLL       10    // How often the front door peeks again while the bytes so far decide nothing (ms)

// How an owner's connections are told apart (FRONT_DOOR_OWNER.Kind)
#define FRONT_DOOR_TLS   1 // TLS: by the server name and the ALPN protocols of the ClientHello
#define FRONT_DOOR_BYTES 2 // Anything else: by the first bytes

// What FrontDoorRoute decides, besides the index of an owner
#define FRONT_DOOR_MORE 0xFFFFFFFE // The bytes so far decide nothing: peek again once more came
#define FRONT_DOOR_NONE 0xFFFFFFFF // No owner takes the connection: it is closed

// What FrontDoorParseHello read
#define FRONT_DOOR_HELLO_DONE 0 // A whole ClientHello: the hello holds what it names
#define FRONT_DOOR_HELLO_MORE 1 // The bytes so far are the start of one
#define FRONT_DOOR_HELLO_NONE 2 // No ClientHello: no TLS handshake record, malformed, or larger than FRONT_DOOR_MAX_HELLO

// The handoff message, which the front door writes to the pipe of an owner process, and the answer, one byte
#define FRONT_DOOR_HANDOFF_MAGIC 0x31444652 // "RFD1": the first four bytes of a handoff message, little-endian
#define FRONT_DOOR_TAKEN         1          // The answer: the owner made its socket of the message
#define FRONT_DOOR_NOT_TAKEN     0          // ... it did not, so the front door closes the connection

// The procedure of an owner in the front door's process: it takes the socket, blocking, without its event selection,
// and closes it in time; false when it does not take it, so the front door closes it
typedef bool(FRONT_DOOR_TAKE_PROC)(void *param, SOCKET s);

// One owner of the table
typedef struct FRONT_DOOR_OWNER {
	char Name[FRONT_DOOR_NAME_SIZE];        // "node", "controller": for the counters and the log
	UINT Kind;                              // FRONT_DOOR_TLS or FRONT_DOOR_BYTES
	char ServerNames[FRONT_DOOR_LIST_SIZE]; // TLS: the server names it takes, separated by commas, without case; "*.example" takes every name under example; empty takes any, and a ClientHello without one
	char Protocols[FRONT_DOOR_LIST_SIZE];   // TLS: the ALPN protocols it takes, separated by commas: one of them offered; empty takes any, and a ClientHello without ALPN
	UCHAR Prefix[FRONT_DOOR_PREFIX_SIZE];   // BYTES: the first bytes of its connections ...
	UINT PrefixSize;                        // ... their number, 1 to FRONT_DOOR_PREFIX_SIZE
	wchar_t Pipe[FRONT_DOOR_PIPE_SIZE];     // The handoff pipe of the owner process ("\\.\pipe\..."); empty for an owner in this process
	FRONT_DOOR_TAKE_PROC *Take;             // An owner in this process: takes the socket
	void *Param;                            // ... with this parameter
} FRONT_DOOR_OWNER;

// How a front door runs
typedef struct FRONT_DOOR_CONFIG {
	char Address[FRONT_DOOR_ADDRESS_SIZE]; // Where it listens: a host and a port, ":443" on every address of both families, "127.0.0.1:0" on a test port
	const FRONT_DOOR_OWNER *Owners;        // The owner table, in order; the front door keeps a copy
	UINT NumOwners;                        // ... its owners, 1 to FRONT_DOOR_MAX_OWNERS
	UINT PeekTimeout;                      // ms the first bytes may take to decide the owner; 0 for FRONT_DOOR_PEEK_TIMEOUT
	UINT HandoffTimeout;                   // ms an owner process may take to answer; 0 for FRONT_DOOR_HANDOFF_TIMEOUT
} FRONT_DOOR_CONFIG;

// What a front door did (FrontDoorGetStats)
typedef struct FRONT_DOOR_STATS {
	UINT64 Accepted;                      // Connections accepted
	UINT64 Handed[FRONT_DOOR_MAX_OWNERS]; // ... handed to each owner, by its index in the table
	UINT64 Unrouted;                      // ... closed because no owner takes them
	UINT64 Refused;                       // ... closed because their owner did not take them: no pipe, no answer, or a refusal
} FRONT_DOOR_STATS;

// What the ClientHello of a TLS connection names (FrontDoorParseHello). The names point into Message, so a hello is
// read where it was parsed, never copied.
typedef struct FRONT_DOOR_HELLO {
	UCHAR Message[FRONT_DOOR_MAX_HELLO];              // The ClientHello message, its header included, put together from its records ...
	UINT MessageSize;                                 // ... its bytes
	UINT RecordsSize;                                 // The bytes of the records up to its end, their headers included
	const UCHAR *ServerName;                          // The host_name of server_name, NULL without one ...
	UINT ServerNameSize;                              // ... its bytes, 1 to FRONT_DOOR_MAX_NAME
	UINT NumProtocols;                                // The ALPN protocols offered, of which the first FRONT_DOOR_MAX_PROTOCOLS are kept ...
	const UCHAR *Protocols[FRONT_DOOR_MAX_PROTOCOLS]; // ... each one
	UINT ProtocolSizes[FRONT_DOOR_MAX_PROTOCOLS];     // ... and its bytes, 1 to FRONT_DOOR_MAX_PROTOCOL
} FRONT_DOOR_HELLO;

// The handoff message: the socket, duplicated into the owner process
typedef struct FRONT_DOOR_HANDOFF {
	UINT Magic;             // FRONT_DOOR_HANDOFF_MAGIC
	UINT Size;              // sizeof(FRONT_DOOR_HANDOFF): the version of the message
	WSAPROTOCOL_INFOW Info; // What WSADuplicateSocketW gave for the owner process
} FRONT_DOOR_HANDOFF;

// The front door, FrontDoor.c
typedef struct FRONT_DOOR FRONT_DOOR;
// The handoff pipe of an owner process, FrontDoorPipe.c
typedef struct FRONT_DOOR_PIPE FRONT_DOOR_PIPE;

// The first bytes of a connection, FrontDoorHello.c. ParseHello reads the ClientHello at the start of data, size bytes
// of TLS records, and gives FRONT_DOOR_HELLO_*: the server name and the ALPN protocols go into hello for a whole one.
// Route decides the owner of a connection whose first size bytes are data: the index of an owner of the table owners
// (num owners), FRONT_DOOR_MORE while the bytes decide nothing, or FRONT_DOOR_NONE; with last, no more bytes will
// come (the peer ended, the peek timed out or the bytes fill FRONT_DOOR_MAX_PEEK), so it gives no FRONT_DOOR_MORE.
// HandoffDecode reads a handoff message of size bytes, as an owner process received it from its pipe: false, with info
// untouched, when it is not one of this version.
UINT FrontDoorParseHello(const UCHAR *data, UINT size, FRONT_DOOR_HELLO *hello);
UINT FrontDoorRoute(const FRONT_DOOR_OWNER *owners, UINT num, const UCHAR *data, UINT size, bool last);
bool FrontDoorHandoffDecode(const void *data, UINT size, WSAPROTOCOL_INFOW *info);

// The front door, FrontDoor.c. Start listens on the address of cfg and routes every connection it accepts on a
// callback of the Windows thread pool, so a peer that sends nothing holds no other back; NULL when the configuration is
// not valid or the address cannot be bound (443 taken: the caller starts again on 5555). Port gives the port it bound,
// for a front door on port 0. GetStats gives its counters. Stop closes the listener, waits for the connections being
// routed, which end at once, and frees the front door; a connection that it handed over stays with its owner.
FRONT_DOOR *FrontDoorStart(const FRONT_DOOR_CONFIG *cfg);
USHORT FrontDoorPort(FRONT_DOOR *fd);
void FrontDoorGetStats(FRONT_DOOR *fd, FRONT_DOOR_STATS *st);
void FrontDoorStop(FRONT_DOOR *fd);

// The handoff pipe of an owner process, FrontDoorPipe.c. New makes the pipe of that name, the first instance of it, so
// a process that took the name first makes it fail, and serves it on a thread of its own; sddl is the security
// descriptor of the pipe, which must let the front door's account write (the node's service account), NULL for the
// default one (SYSTEM, the Administrators and the owner's own account); WSADuplicateSocketW duplicates the socket into
// the owner process, so an owner that runs under another account than the front door's lets that account duplicate
// handles into it (PROCESS_DUP_HANDLE). Accept gives the next socket that the front
// door handed over within timeout ms (INFINITE waits), blocking, which the caller closes; INVALID_SOCKET when none came
// or the pipe is freed. Free closes the pipe and the sockets that nobody accepted, once no Accept waits.
FRONT_DOOR_PIPE *FrontDoorPipeNew(const wchar_t *name, const wchar_t *sddl);
SOCKET FrontDoorPipeAccept(FRONT_DOOR_PIPE *p, UINT timeout);
void FrontDoorPipeFree(FRONT_DOOR_PIPE *p);

#endif // CORE_FRONT_DOOR_H
