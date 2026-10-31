// PeerInternal.h
// Module-internal declarations of the Peer module: the state of a node's peer layer, which Peer.c, PeerSignal.c,
// PeerUdp.c, PeerIce.c, PeerPortMap.c, PeerPunch.c, PeerSession.c and PeerChallenge.c share. Only the Peer files
// include this header.

#ifndef CORE_PEER_INTERNAL_H
#define CORE_PEER_INTERNAL_H

#include "Core/Peer.h"

#include "Core/Crypto.h"
#include "Core/Noise.h"

// The payload of a bind: PEER_VERSION and the sequence, then the cookie of the relay's bind challenge, if the node
// has one for that relay
#define PEER_VERSION     1
#define PEER_BIND_SIZE   9
#define PEER_COOKIE_SIZE 16
#define PEER_BIND_MAX    (PEER_BIND_SIZE + PEER_COOKIE_SIZE)
// ... of a bind challenge: PEER_VERSION, the sequence of the bind it answers, the cookie
#define PEER_CHALLENGE_SIZE (PEER_BIND_SIZE + PEER_COOKIE_SIZE)
// A cookie is good for the period it was made in and the one after it (PeerChallenge.c)
#define PEER_COOKIE_PERIOD 120000
// ... of a bound: PEER_VERSION, the sequence of the bind it answers, the address the relay saw the bind from
#define PEER_BOUND_SIZE 27
// ... of a signal: PEER_VERSION, the type, the sequence, the relay key, address and port, the number of
// candidates, then each candidate: its type, address and port; then, from a node with ICE on, the length and the
// characters of the username fragment of its ICE session, and the length and the characters of its password. A punch
// offer or a punch answer ends with the NAT of its sender (PEER_NAT_*), one byte, in their place.
#define PEER_SIGNAL_FIXED  61
#define PEER_CANDIDATE_LEN 19
#define PEER_ICE_ATTRS_MAX (2 + PEER_ICE_UFRAG_SIZE - 1 + PEER_ICE_PWD_SIZE - 1)
#define PEER_MAX_SIGNAL    (PEER_SIGNAL_FIXED + PEER_MAX_CANDIDATES * PEER_CANDIDATE_LEN + PEER_ICE_ATTRS_MAX)

// The path of a data datagram at the ingress: the PEER_PATH_* values, and a node bound to the relay role
#define PEER_PATH_BOUND 3

// The target addresses one attempt of a punch probes: the one port of a peer behind a cone, or the range around the
// predicted port of a sequential NAT (PeerPunch.c)
#define PEER_PUNCH_MAX_TARGETS 64
// The nonces of a punch that wait for their echo, each with the address it went to (PeerPunch.c)
#define PEER_PUNCH_NONCES     4
#define PEER_PUNCH_NONCE_SIZE 16
// The destinations of the node that a NAT maps, which the punch counts to predict the next mapping, and the punch messages
// whose times the rate of the punch holds (PeerPunch.c)
#define PEER_PUNCH_DESTS    1024
#define PEER_PUNCH_RATE_MAX 256

// A peer session (PeerSession.c): the sizes of its handshake messages. An initiation is its kind, the source key,
// the destination key and the sender's index, then the first message of Noise_IK with the payload of
// PEER_INIT_PAYLOAD bytes (the timestamp, the sender's index); a response is its kind, the keys, the sender's
// index and the receiver's, then the second message with the payload of PEER_RESPONSE_PAYLOAD bytes (the two
// indices).
#define PEER_INIT_HEADER      69
#define PEER_INIT_PAYLOAD     12
#define PEER_INIT_SIZE        (PEER_INIT_HEADER + NOISE_IK_MESSAGE1_SIZE + PEER_INIT_PAYLOAD)
#define PEER_RESPONSE_HEADER  73
#define PEER_RESPONSE_PAYLOAD 8
#define PEER_RESPONSE_SIZE    (PEER_RESPONSE_HEADER + NOISE_IK_MESSAGE2_SIZE + PEER_RESPONSE_PAYLOAD)
#define PEER_SESSION_QUEUE    8    // Datagrams that wait for a handshake, per peer
#define PEER_SESSION_RETRY    1000 // ms before an initiation that had no answer is sent again
#define PEER_SESSION_TRIES    10   // ... how many times, before the queue is dropped
#define PEER_WINDOW_BITS      256  // The sliding window of the counters of the records under one key
#define PEER_WINDOW_WORDS     (PEER_WINDOW_BITS / 64)

// The keys of a peer session: one handshake's
typedef struct PEER_KEYPAIR {
	bool Valid;                       // It holds keys
	bool Initiator;                   // This node started the handshake of the keys
	bool Confirmed;                   // The peer has the keys: this node is their initiator, or took a record under them
	UINT LocalIndex;                  // The index that the records to this node carry
	UINT RemoteIndex;                 // The index that this node's records carry
	NOISE_CIPHER Send;                // The key of the records this node sends; its nonce is the next counter
	NOISE_CIPHER Recv;                // The key of the records it receives
	bool RecvAny;                     // A record was taken under the keys
	UINT64 RecvMax;                   // ... the highest counter taken
	UINT64 Window[PEER_WINDOW_WORDS]; // ... and which of the PEER_WINDOW_BITS counters below it were taken
	UINT64 Created;                   // When the handshake completed (ms)
	UCHAR Id[PEER_SESSION_ID_SIZE];   // The start of the handshake hash, the same at both ends
} PEER_KEYPAIR;

// The peer session of a node with one peer, which the PEER holds while the peer stays. Its lock comes after the
// lock of the layer, and before KeyLock.
typedef struct PEER_SESSION {
	SRWLOCK Lock;                                      // Everything below
	PEER_KEYPAIR Current;                              // The keys that records go under
	PEER_KEYPAIR Previous;                             // The keys before them, for the records still on their way
	PEER_KEYPAIR Next;                                 // A responder's new keys, until the initiator's first record under them
	bool Pending;                                      // This node's initiation is on its way
	NOISE_HANDSHAKE Handshake;                         // ... its handshake
	UINT PendingIndex;                                 // ... its index
	UINT64 PendingTick;                                // ... when it was sent (ms)
	UINT PendingTries;                                 // ... and how many times
	UINT64 LastInit;                                   // The timestamp of the last initiation taken from the peer
	UINT64 LastSent;                                   // When the node last sent a record (ms)
	UINT64 LastReceived;                               // When it last took one
	UINT64 LastData;                                   // ... and one with a payload, which a keepalive answers
	UINT64 SentUnderKey;                               // Records sent under the current keys
	UINT64 Handshakes;                                 // Handshakes that completed with the peer
	UINT QueueNum;                                     // The datagrams that wait for the handshake
	UINT QueueSize[PEER_SESSION_QUEUE];                // ... their sizes
	UCHAR Queue[PEER_SESSION_QUEUE][PEER_MAX_PAYLOAD]; // ... and their bytes
} PEER_SESSION;

// What one input of a peer session gives the layer: a datagram to send back to the peer, the queue to send now, and
// a payload to deliver to the node
typedef struct PEER_SESSION_OUT {
	UINT ReplySize;                  // The response to an initiation, 0 for none
	UCHAR Reply[PEER_MAX_DATAGRAM];  // ... its bytes
	bool Flush;                      // New keys are up: the queue goes now (PeerSessionFlush)
	bool Keepalive;                  // ... and a keepalive when it is empty: the node's own handshake completed
	bool Deliver;                    // A payload for the node
	UINT DeliverSize;                // ... its size
	UCHAR Payload[PEER_MAX_PAYLOAD]; // ... and its bytes
} PEER_SESSION_OUT;

// The agent of libjuice (juice/juice.h) in its peer mode, on the socket of the layer (juice-peer.h), which only
// PeerIce.c calls
#include "juice-peer.h"

// The ICE session of a node with one peer (PeerIce.c): an agent of libjuice in the peer mode, on the socket of the
// layer, which checks the candidate pairs in the background while the peer stays on the relay. PeerIce.c creates and
// destroys it under IceLock, never under the lock of the layer; the PEER that holds it changes under the lock of the
// layer.
typedef struct PEER_ICE {
	juice_peer_io_t Io;                    // First: the I/O of the agent on the socket of the layer, at its user_ptr
	PEER_AGENT *Agent;                     // The peer layer
	UCHAR Key[PEER_KEY_SIZE];              // The peer
	juice_agent_t *Juice;                  // The agent of libjuice
	bool Controlling;                      // The node offered: its agent nominates the pair (IceLock)
	bool Mapped;                           // The node had the public port of its home gateway when it made the session
	UINT64 Started;                        // When the node made it (PeerNow): an offer waits for its answer from then on
	char Ufrag[PEER_ICE_UFRAG_SIZE];       // The credentials of the session, which the node's signals to the peer carry
	char Pwd[PEER_ICE_PWD_SIZE];           // ...
	char RemoteUfrag[PEER_ICE_UFRAG_SIZE]; // The peer's username fragment, empty before its signal (IceLock)
	volatile LONG State;                   // PEER_ICE_*
	volatile LONG Upgraded;                // 1 once a direct path validated, 2 once it failed after that
	PEER_ADDR Selected;                    // The peer's address on the direct path (the lock of the layer)
} PEER_ICE;

// The symmetric-NAT hole punch of a node with one peer (PeerPunch.c; CORE-S5-4, CORE-S5-7): the probes it sends to the
// ports it predicts of the peer, on the peer layer's own socket, while the peer stays on the relay. A punch offer and a
// punch answer of the control plane begin an attempt at each end; a validated probe sets HasDirect below, like
// PeerSetDirect does, and the keepalives of the two ends hold the punched path while the peer answers.
typedef struct PEER_PUNCH {
	UINT State;                                             // PEER_PUNCH_*
	bool IceFailed;                                         // An ICE session of the pair failed since ICE last had its direct path up
	UINT PeerNat;                                           // The NAT of the peer, from its last punch signal (PEER_NAT_*)
	PEER_ADDR Own;                                          // The node's predicted port when its probes began, which its punch answer names
	UINT Budget;                                            // Probes left of the attempt
	UINT Failures;                                          // Attempts in a row that met nothing, the one under way among them
	UINT64 NextAttempt;                                     // When the next attempt may begin (PeerNow): PunchRetry after the end of one, or PunchBackoff after the last one
	UINT64 Offered;                                         // When the node sealed its last punch offer, 0 for none or once it was answered
	bool Answer;                                            // The last punch offer of the peer began an attempt: its punch answer is due
	UINT64 LastProbe;                                       // When the last probe of the attempt went: it fails PEER_PUNCH_LINGER after, once its budget is spent
	UINT64 LastSent;                                        // When the node last sent a keepalive on the punched path
	volatile LONG64 LastHeard;                              // When the peer was last heard on the punched path (PeerNow): a punch message or a record that opened
	UINT64 LastSeq;                                         // The last punch sequence taken from the peer, for anti-replay
	UINT NumTargets;                                        // The addresses the probes go to, in the order of the sweep
	UINT Next;                                              // The next target of the round over them, so one tick sends a bounded burst
	PEER_ADDR Targets[PEER_PUNCH_MAX_TARGETS];              // ...
	UINT NextNonce;                                         // The next slot of the nonces below, round robin
	PEER_ADDR NonceTo[PEER_PUNCH_NONCES];                   // The addresses that a nonce of the node went to, sealed to the peer
	UCHAR Nonces[PEER_PUNCH_NONCES][PEER_PUNCH_NONCE_SIZE]; // ... and those nonces, which the peer echoes from there
} PEER_PUNCH;

// A destination of the node that a NAT maps (PeerPunch.c): a relay that it binds, an address that its ICE sessions check,
// an address that its punches probe. A symmetric NAT makes a mapping for each new one, on the next port.
typedef struct PEER_PUNCH_DEST {
	PEER_ADDR Addr; // The address
	UINT Index;     // The number of its mapping, in the order of the destinations of the node; 0 for a free slot
	UINT Gen;       // The generation of the destinations it belongs to: one of an older generation is gone
} PEER_PUNCH_DEST;

// One peer in the peer table, kept across PeerSetPeers while the peer stays
typedef struct PEER {
	PEER_INFO Info;                                 // From the control plane
	UINT64 Sequence;                                // The sequence of its last signal taken, 0 for none
	bool HasRelay;                                  // Its last signal named a relay
	UCHAR RelayKey[PEER_KEY_SIZE];                  // ... this one
	UINT NumCandidates;                             // The candidates of its last signal
	PEER_CANDIDATE Candidates[PEER_MAX_CANDIDATES]; // ... their types and addresses
	bool HasDirect;                                 // A direct path set by hand (PeerSetDirect) or won by a punch
	PEER_ADDR Direct;                               // ... to this address
	PEER_ICE *Ice;                                  // The ICE session with the peer, NULL for none
	PEER_PUNCH Punch;                               // The symmetric-NAT hole punch with the peer (PeerPunch.c)
	PEER_SESSION *Session;                          // The peer session with the peer (PeerSession.c), NULL when out of memory
	UINT64 Floor;                                   // The clock (PeerWallClock) when the entry was made: every sequence of
	                                                // the peer must be above it, so a restart or a new entry takes no replay
	UINT64 BindSequence;                            // The relay role: the sequence of the last bind taken from the peer
} PEER;

// The port mapping of a node behind a home gateway (PeerPortMap.c), with Config.PortMap
typedef struct PEER_ICE_NODE {
	USHORT Port; // The port of the socket of the layer that it maps, 0 before the host candidates named it
	int PortMap; // The libplum mapping of that port on the home gateway, -1 for none
} PEER_ICE_NODE;

// One relay that the node may use, and its binding to it
typedef struct PEER_RELAY {
	PEER_RELAY_INFO Info;           // From the control plane
	bool Wanted;                    // The home relay, or the relay of a peer: the node keeps a binding to it
	bool Binding;                   // A bind was sent
	bool Bound;                     // The relay answered the last bind
	UINT64 BindSequence;            // The sequence of the last bind
	UINT64 BindTick;                // When the last bind was sent (ms)
	PEER_ADDR Observed;             // The address that the relay saw the node at: its server reflexive candidate
	UINT Mapping;                   // With punching, the number of the node's mapping towards the relay (PeerPunchDestination)
	bool HasCookie;                 // The relay sent a bind challenge: its cookie goes in the next binds
	bool Answered;                  // The last bind answered a challenge, so the next challenge waits for a new bind
	UCHAR Cookie[PEER_COOKIE_SIZE]; // ... the cookie
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
	volatile LONG64 Counters[14];            // Sent, Delivered, DeliveredRelay, Forwarded, Binds, Signals, Upgrades, Fallbacks, PunchAttempts, PunchSuccesses, Handshakes, Challenges, PunchFailures, PunchProbes
	volatile LONG64 Drops[PEER_NUM_REASONS]; // What the layer dropped, by reason
	SRWLOCK IceLock;                         // Serialises the start, the remote side and the end of the ICE sessions
	PEER_ICE_NODE Ice;                       // The port mapping of the socket, with Config.PortMap
	volatile LONG64 StunMessages;            // The STUN messages that came to the socket, each read once (PeerIceInput)
	UCHAR CookieSecret[CRYPTO_SHA256_SIZE];  // The relay role: the key of its bind challenges, new at every start
	SRWLOCK PunchLock;                       // With punching, the destinations and the times below; it comes after the lock of the layer
	PEER_PUNCH_DEST Dests[PEER_PUNCH_DESTS]; // The destinations of the node that a NAT maps, the oldest replaced first (PeerPunch.c)
	UINT NextDest;                           // ... the slot of the next new one
	UINT DestGen;                            // ... their generation: a relay that saw the node at a new address begins a new one
	UINT Mappings;                           // ... the mappings that they made, counted
	UINT64 RateTimes[PEER_PUNCH_RATE_MAX];   // When the last punch messages of the node went (PeerNow), round robin
	UINT RateNext;                           // ... the slot of the next one
};

// The counters of a PEER_AGENT
#define PEER_COUNT_SENT            0
#define PEER_COUNT_DELIVERED       1
#define PEER_COUNT_DELIVERED_RELAY 2
#define PEER_COUNT_FORWARDED       3
#define PEER_COUNT_BINDS           4
#define PEER_COUNT_SIGNALS         5
#define PEER_COUNT_UPGRADES        6
#define PEER_COUNT_FALLBACKS       7
#define PEER_COUNT_PUNCH_ATTEMPTS  8
#define PEER_COUNT_PUNCH_SUCCESSES 9
#define PEER_COUNT_HANDSHAKES      10
#define PEER_COUNT_CHALLENGES      11
#define PEER_COUNT_PUNCH_FAILURES  12
#define PEER_COUNT_PUNCH_PROBES    13

// Peer.c
void PeerCount(PEER_AGENT *a, UINT counter);
void PeerDrop(PEER_AGENT *a, UINT reason);
UINT64 PeerNow();
UINT64 PeerWallClock();
UINT64 PeerNextSequence(PEER_AGENT *a);
UINT64 PeerFloorOf(const PEER *p, UINT64 last);
void PeerPutUint64(UCHAR *p, UINT64 v);
UINT64 PeerGetUint64(const UCHAR *p);
void PeerPutUint16(UCHAR *p, USHORT v);
USHORT PeerGetUint16(const UCHAR *p);
PEER *PeerFind(PEER_AGENT *a, const UCHAR *key);
bool PeerSendRaw(PEER_AGENT *a, const PEER_ADDR *to, const void *data, UINT size);
void PeerBind(PEER_AGENT *a, const UCHAR *relay_key, bool answer);

// PeerSession.c
PEER_SESSION *PeerSessionNew();
void PeerSessionFree(PEER_SESSION *s);
UINT PeerSessionSeal(PEER_AGENT *a, PEER *p, const void *data, UINT size, UCHAR *buf, bool *queued, bool *rekey);
UINT PeerSessionInitiate(PEER_AGENT *a, PEER *p, UCHAR *buf);
UINT PeerSessionInput(PEER_AGENT *a, PEER *p, const PEER_RECORD_INFO *r, const UCHAR *data, UINT size, PEER_SESSION_OUT *o);
UINT PeerSessionFlush(PEER_AGENT *a, PEER *p, bool first, UCHAR *buf);
UINT PeerSessionTick(PEER_AGENT *a, PEER *p, UCHAR *buf);
void PeerSessionStatus(PEER *p, PEER_STATUS *st);

// PeerChallenge.c
bool PeerCookieCheck(PEER_AGENT *a, const UCHAR *key, const PEER_ADDR *from, const UCHAR *cookie);
void PeerChallengeSend(PEER_AGENT *a, const UCHAR *key, const PEER_ADDR *from, UINT64 seq);
void PeerInputChallenge(PEER_AGENT *a, const PEER_ADDR *from, const UCHAR *data, UINT size);

// PeerSignal.c
UINT PeerSeal(PEER_AGENT *a, const UCHAR *peer, UINT kind, const void *payload, UINT payload_size, UCHAR *buf, UINT size);
bool PeerOpen(PEER_AGENT *a, const UCHAR *env, UINT size, UCHAR *sender, void *payload, UINT payload_size, UINT *payload_len);

// PeerIce.c
void PeerIceStop(PEER_AGENT *a);
void PeerIceOffer(PEER_AGENT *a, const UCHAR *key);
void PeerIceRemote(PEER_AGENT *a, const UCHAR *key, const PEER_SIGNAL *s);
void PeerIceRetire(PEER *peers, UINT num);
void PeerIceTick(PEER_AGENT *a);
bool PeerIceValid(PEER_ICE *ice);
bool PeerIceUp(PEER_ICE *ice);
bool PeerIceIsStun(const UCHAR *data, UINT size);
void PeerIceInput(PEER_AGENT *a, const PEER_ADDR *from, const UCHAR *data, UINT size);
UINT PeerIceCandidates(PEER_AGENT *a, PEER_CANDIDATE *c, UINT max);
bool PeerAddrFromHost(PEER_ADDR *a, const char *host, USHORT port);

// PeerPortMap.c
void PeerPortMapStart(PEER_AGENT *a, USHORT port);
void PeerPortMapStop(PEER_AGENT *a);
bool PeerPortMapGet(PEER_AGENT *a, PEER_ADDR *addr);
UINT PeerPortMapState(PEER_AGENT *a);

// PeerPunch.c
UINT PeerPunchDestination(PEER_AGENT *a, const PEER_ADDR *to);
void PeerPunchRemap(PEER_AGENT *a, PEER_RELAY *r);
UINT PeerPunchSealSignal(PEER_AGENT *a, const UCHAR *key, UINT type, UCHAR *buf, UINT size);
void PeerPunchStart(PEER_AGENT *a, const UCHAR *key, const PEER_SIGNAL *s);
void PeerPunchInput(PEER_AGENT *a, const PEER_ADDR *from, const UCHAR *data, UINT size);
void PeerPunchHeard(PEER *p, const PEER_ADDR *from);
void PeerPunchTick(PEER_AGENT *a);
void PeerPunchStats(PEER_AGENT *a, PEER_STATS *st);

#endif // CORE_PEER_INTERNAL_H
