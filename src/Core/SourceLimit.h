// SourceLimit.h
// The limits for a source of the new core's listeners (AUD1-DT-3, #451; NS-10, TR-5, FD-1, FD-6 of docs/threat-model.md):
// the front door on TCP and the msquic listener on UDP accept from anywhere, and a stranger costs each of them a thread,
// a socket or a handshake before any key or token stands behind it. A SOURCE_LIMITS holds, for one listener:
// - a cap on the connections that have not finished their handshake, in all (MaxPending) and for one source
//   (MaxPendingPerSource); a connection counts from the moment it is accepted until its owner has it or it is closed;
// - a rate limit on the new connections of a source (Connect) and a rate limit on its handshake attempts (Handshake),
//   each a token bucket: Rate tokens a second, at most Burst in the bucket, one token for each connection or attempt;
// - the counters of what it refused, for the status of the Node.
// A source is an IPv4 address or the /64 that an IPv6 address is in, as the Controller counts one (CS-4,
// control.Waiting); an IPv4-mapped IPv6 address is its IPv4 address. A source that holds nothing and has all its tokens
// is forgotten, and the table of sources has a size limit of its own (SOURCE_LIMIT_MAX_SOURCES), so a flood from many
// addresses cannot grow it without end.
//
// The defaults are what an honest site does not meet: a site with 1000 Nodes behind one NAT address that all connect in
// the same second is admitted (a burst of SOURCE_LIMIT_BURST tokens, and SOURCE_LIMIT_PER_SOURCE connections at the
// same moment), where a source that opens connections and holds them is cut at its cap. The caller passes the time in
// milliseconds, so the module has no clock of its own and a test sets it.

#ifndef CORE_SOURCE_LIMIT_H
#define CORE_SOURCE_LIMIT_H

// It includes windows.h alone, as Crypto.h does, and declares the address that it reads without Winsock, so a file that
// includes it after windows.h is no worse off: a file that calls Winsock includes winsock2.h before it.
#include <windows.h>

#include <stdbool.h>

struct sockaddr;

// The defaults of a zero field of SOURCE_LIMIT_CONFIG
#define SOURCE_LIMIT_MAX_PENDING 1024 // Connections that have not finished their handshake, in all
#define SOURCE_LIMIT_PER_SOURCE  256  // ... and for one source
#define SOURCE_LIMIT_RATE        200  // New connections, and handshake attempts, a second for one source, sustained
#define SOURCE_LIMIT_BURST       2000 // ... and the most that a source may make at once, from a full bucket

#define SOURCE_LIMIT_MAX_SOURCES 8192 // Sources that the table holds at most

// What Enter and Handshake decide
#define SOURCE_LIMIT_ADMIT     0 // The connection or the attempt may go on
#define SOURCE_LIMIT_FULL      1 // Too many connections that have not finished their handshake wait in all
#define SOURCE_LIMIT_SOURCE    2 // ... or for this source
#define SOURCE_LIMIT_RATE_NEW  3 // The source opens connections faster than its rate allows
#define SOURCE_LIMIT_RATE_HAND 4 // The source starts handshakes faster than its rate allows

// How a SOURCE_LIMITS limits; a field of 0 takes its default
typedef struct SOURCE_LIMIT_CONFIG {
	UINT MaxPending;          // Connections that have not finished their handshake, in all
	UINT MaxPendingPerSource; // ... for one source
	UINT ConnectRate;         // New connections a second for one source
	UINT ConnectBurst;        // ... and the bucket that they come from
	UINT HandshakeRate;       // Handshake attempts a second for one source
	UINT HandshakeBurst;      // ... and the bucket that they come from
} SOURCE_LIMIT_CONFIG;

// A source: the IPv4 address, or the first 8 bytes of the IPv6 address (the /64), and which of them it is
typedef struct SOURCE_KEY {
	UCHAR Family;   // 4, 6, or 0 for an address that is neither
	UCHAR Bytes[8]; // The address, zero beyond its length
} SOURCE_KEY;

// What a SOURCE_LIMITS did (SourceLimitsGetStats)
typedef struct SOURCE_LIMIT_STATS {
	UINT Pending;            // The connections that have not finished their handshake now
	UINT Sources;            // The sources that the table holds now
	UINT64 Admitted;         // The connections it admitted
	UINT64 RefusedFull;      // ... refused for the cap in all (SOURCE_LIMIT_FULL)
	UINT64 RefusedSource;    // ... for the cap of the source (SOURCE_LIMIT_SOURCE)
	UINT64 RefusedRate;      // ... for the rate of new connections (SOURCE_LIMIT_RATE_NEW)
	UINT64 RefusedHandshake; // The handshake attempts it refused for their rate (SOURCE_LIMIT_RATE_HAND)
} SOURCE_LIMIT_STATS;

// The limits of one listener, SourceLimit.c
typedef struct SOURCE_LIMITS SOURCE_LIMITS;

// A limits object with cfg, whose zero fields are the defaults; cfg NULL is all defaults. NULL when there is no memory.
// Free frees it once nobody calls it.
SOURCE_LIMITS *SourceLimitsNew(const SOURCE_LIMIT_CONFIG *cfg);
void SourceLimitsFree(SOURCE_LIMITS *l);

// The configuration in force, with the defaults filled in
void SourceLimitsGetConfig(SOURCE_LIMITS *l, SOURCE_LIMIT_CONFIG *cfg);

// The source of a peer address, a SOCKADDR_IN or a SOCKADDR_IN6 (a QUIC_ADDR is one): its IPv4 address, or the /64 of
// its IPv6 address; an IPv4-mapped IPv6 address is its IPv4 address. An address of another family, or none, is the
// source of family 0, one source for all of them.
void SourceLimitsKey(const struct sockaddr *addr, SOURCE_KEY *key);

// A connection of source key that was just accepted, now ms on the caller's clock. SOURCE_LIMIT_ADMIT counts it as one
// that has not finished its handshake, and the caller calls Leave once for it, when its owner has it or it is closed;
// any other answer counts the refusal and counts nothing else, and the caller closes the connection.
UINT SourceLimitsEnter(SOURCE_LIMITS *l, const SOURCE_KEY *key, UINT64 now);

// A handshake attempt of source key that starts now: SOURCE_LIMIT_ADMIT, or SOURCE_LIMIT_RATE_HAND, counted
UINT SourceLimitsHandshake(SOURCE_LIMITS *l, const SOURCE_KEY *key, UINT64 now);

// A connection that Enter admitted no longer waits
void SourceLimitsLeave(SOURCE_LIMITS *l, const SOURCE_KEY *key);

// The counters, at this moment
void SourceLimitsGetStats(SOURCE_LIMITS *l, SOURCE_LIMIT_STATS *st);

#endif // CORE_SOURCE_LIMIT_H
