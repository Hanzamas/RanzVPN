// PeerInternal.h
// Module-internal declarations of the Peer module: the state of a node's peer layer, which Peer.c, PeerSignal.c
// and PeerUdp.c share. Only the Peer files include this header.

#ifndef CORE_PEER_INTERNAL_H
#define CORE_PEER_INTERNAL_H

#include "Core/Peer.h"

#include "Core/Crypto.h"

// The payload of a bind: PEER_VERSION and the sequence
#define PEER_VERSION   1
#define PEER_BIND_SIZE 9
// ... of a bound: PEER_VERSION, the sequence of the bind it answers, the address the relay saw the bind from
#define PEER_BOUND_SIZE 27
// ... of a signal: PEER_VERSION, the type, the sequence, the relay key, address and port, the number of
// candidates, then each candidate: its type, address and port
#define PEER_SIGNAL_FIXED  61
#define PEER_CANDIDATE_LEN 19
#define PEER_MAX_SIGNAL    (PEER_SIGNAL_FIXED + PEER_MAX_CANDIDATES * PEER_CANDIDATE_LEN)

// The path of a data datagram at the ingress: the PEER_PATH_* values, and a node bound to the relay role
#define PEER_PATH_BOUND 3

// One peer in the peer table, kept across PeerSetPeers while the peer stays
typedef struct PEER {
	PEER_INFO Info;                                 // From the control plane
	UINT64 Sequence;                                // The sequence of its last signal taken, 0 for none
	bool HasRelay;                                  // Its last signal named a relay
	UCHAR RelayKey[PEER_KEY_SIZE];                  // ... this one
	UINT NumCandidates;                             // The candidates of its last signal
	PEER_CANDIDATE Candidates[PEER_MAX_CANDIDATES]; // ... their types and addresses
	bool HasDirect;                                 // ICE validated a direct path (PeerSetDirect)
	PEER_ADDR Direct;                               // ... to this address
} PEER;

// One relay that the node may use, and its binding to it
typedef struct PEER_RELAY {
	PEER_RELAY_INFO Info; // From the control plane
	bool Wanted;          // The home relay, or the relay of a peer: the node keeps a binding to it
	bool Binding;         // A bind was sent
	bool Bound;           // The relay answered the last bind
	UINT64 BindSequence;  // The sequence of the last bind
	UINT64 BindTick;      // When the last bind was sent (ms)
	PEER_ADDR Observed;   // The address that the relay saw the node at: its server reflexive candidate
} PEER_RELAY;

// One node bound to the relay role. A binding is soft state: the node renews it, and the relay drops it when it
// was not renewed in time, so a relay holds nothing that a restart loses for good and no state per peer pair.
typedef struct PEER_BINDING {
	UCHAR Key[PEER_KEY_SIZE]; // The static key of the node
	PEER_ADDR Addr;           // The address its last bind came from
	UINT64 Sequence;          // The sequence of that bind
	UINT64 Tick;              // When it came (ms)
	volatile LONG64 Tat;      // The rate limit: the theoretical arrival time of GCRA, in performance counter ticks
} PEER_BINDING;

// The peer layer of one node
struct PEER_AGENT {
	PEER_KEY Key;                            // The node's static key; an identity key stays owned by the caller
	SRWLOCK KeyLock;                         // Serialises the use of an identity key
	PEER_CONFIG Config;                      // The configuration
	PEER_SEND_PROC *Send;                    // Sends a datagram
	void *SendParam;                         // ... its first parameter
	PEER_RECV_PROC *Recv;                    // Takes a data datagram for the node, or NULL
	void *RecvParam;                         // ... its second parameter
	SRWLOCK Lock;                            // The tables below: shared on the data path, exclusive for changes
	PEER *Peers;                             // The peer table, sorted by key
	UINT NumPeers;                           // ... its size
	PEER_RELAY Relays[PEER_MAX_RELAYS];      // The relays that the node may use, the home relay first
	UINT NumRelays;                          // ... their number
	PEER_ADDR Hosts[PEER_MAX_CANDIDATES];    // The host candidates
	UINT NumHosts;                           // ... their number
	PEER_BINDING *Bindings;                  // The nodes bound to the relay role, sorted by key
	UINT NumBindings;                        // ... their number
	UINT MaxBindings;                        // ... the room allocated for them
	volatile LONG64 Sequence;                // The last sequence of a bind or a signal of the node
	LONG64 RateInterval;                     // GCRA: performance counter ticks between two datagrams at RelayRate
	LONG64 RateTolerance;                    // ... and the burst tolerance
	volatile LONG64 Counters[6];             // Sent, Delivered, DeliveredRelay, Forwarded, Binds, Signals
	volatile LONG64 Drops[PEER_NUM_REASONS]; // What the layer dropped, by reason
};

// The counters of a PEER_AGENT
#define PEER_COUNT_SENT            0
#define PEER_COUNT_DELIVERED       1
#define PEER_COUNT_DELIVERED_RELAY 2
#define PEER_COUNT_FORWARDED       3
#define PEER_COUNT_BINDS           4
#define PEER_COUNT_SIGNALS         5

// Peer.c
void PeerCount(PEER_AGENT *a, UINT counter);
void PeerDrop(PEER_AGENT *a, UINT reason);
UINT64 PeerNextSequence(PEER_AGENT *a);
void PeerPutUint64(UCHAR *p, UINT64 v);
UINT64 PeerGetUint64(const UCHAR *p);
void PeerPutUint16(UCHAR *p, USHORT v);
USHORT PeerGetUint16(const UCHAR *p);

// PeerSignal.c
UINT PeerSeal(PEER_AGENT *a, const UCHAR *peer, UINT kind, const void *payload, UINT payload_size, UCHAR *buf, UINT size);
bool PeerOpen(PEER_AGENT *a, const UCHAR *env, UINT size, UCHAR *sender, void *payload, UINT payload_size, UINT *payload_len);

#endif // CORE_PEER_INTERNAL_H
