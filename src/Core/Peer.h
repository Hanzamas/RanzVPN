// Peer.h
// The peer module of the new core (ADR-0015): the peers of a node and the paths to them, and the relay role.
//
// A node reaches a peer over a path. The relay path goes through a relay, a node with the relay role that both
// ends are bound to; it is up as soon as the two have exchanged one signal each through the control plane, so a
// new peer pair comes up in one round trip (relay-first). The direct path is the one that ICE validates later, in
// the background (PeerIce.c, CORE-S5-3 #79, CORE-S5-6 #412): the pair moves to it once a candidate pair validates,
// with no datagram held back (an Upgrade), and back to the relay when consent freshness (RFC 7675) finds it dead (a
// Fallback). ICE runs on the socket of the layer, so its candidates are the host addresses of that socket and the
// address that the home relay saw the node at, and no STUN server is needed. A node behind a home gateway may ask it
// for a public port with PCP, NAT-PMP or UPnP (PeerPortMap.c), which then goes first among its candidates.
// PeerSetDirect sets a direct path by hand. Every datagram a node receives goes through one ingress, PeerInput,
// whichever path it came on: a datagram for the node itself is delivered, one for another node is forwarded when
// the node has the relay role and both ends are bound to it. The same policy check runs in both cases: the source
// is a peer, and the destination is the node itself or a peer that shares a VRF with the source. The control
// plane sets the peers (the Peer objects of the desired state, PeerSetPeers) and the relays a node may use (its
// Relay objects, PeerSetRelays).
//
// Signals and binds (PeerSignal.c) are envelopes sealed by the sending node's static key to the receiving
// node's, with the Noise one-way pattern K (Noise_K_25519_AESGCM_SHA256): only the receiver can open one, and
// only a holder of the sender's private key can make one, so the controller that carries a signal can neither
// forge, alter nor redirect it, and a relay binds no node that does not hold its key. A signal carries the relay
// assignment of its sender (the relay it is bound to), its ICE candidates and, with ICE on, the credentials of
// its ICE session with the receiver. A sequence that grows with the wall clock, as the timestamp of a WireGuard
// handshake initiation does, makes every replay fail.
//
// A relay binds a node only from the address that its bind came from and only with a cookie that the relay sent
// to that address, sealed to the node (a bind challenge, PeerChallenge.c), so the same bind sent from another
// address does not move the binding. A punch moves a peer to the direct path only at an address that proved, by
// echoing a nonce sealed to the peer, that the peer receives there (PeerPunch.c).
//
// A pair that ICE leaves on the relay because a node of it sits behind a symmetric NAT tries a punch (PeerPunch.c,
// CORE-S5-7 #413): a node tells its NAT is symmetric from the answers of the binds to its first two relays, predicts the
// port of its next mapping, and the two nodes exchange a punch offer and a punch answer, signals that carry the NAT and
// the prediction of each, upon which both send authenticated probes to the ports that the predictions name and to a
// range of ports around them. The punch messages, probes and answers together, are limited per second and per attempt,
// and after PunchAttempts attempts that met nothing the pair stays on the relay for PunchBackoff.
//
// Every data datagram between two nodes goes in a peer session (PeerSession.c, CORE-H2 #399): Noise_IK between
// the static keys of the two nodes, in the manner of WireGuard. The first datagram to a peer starts the
// handshake on the path in use; the datagrams that wait for it are queued, so none is lost. A datagram keeps a
// clear header that a relay forwards by, its kind, the source key, the destination key and a session index; the
// rest is an AES-GCM record under the keys of the session, with a counter that a sliding window checks. The
// session belongs to the pair of nodes, not to the path, so an Upgrade or a Fallback keeps it. Its keys are
// replaced on a schedule and after a number of datagrams, and a session whose peer is silent is dropped.
//
// The datagrams travel over a send procedure that the caller gives (PEER_SEND_PROC) and come back through
// PeerInput: a UDP socket (PeerUdp.c) or the harness network of coretest. The checks of ICE and their answers, STUN
// messages, go the same way. The socket stands in for the QUIC datagrams of CORE-S1-1 (#67) until the transport
// interface of CORE-F4 (#64) carries them; the relay then shares the QUIC listener on UDP 443 (ADR-0035).

#ifndef CORE_PEER_H
#define CORE_PEER_H

#include <windows.h>

#include <stdbool.h>

#define PEER_KEY_SIZE         32   // A Noise static key (X25519)
#define PEER_NAME_SIZE        64   // A node name with its terminating NUL (control.options)
#define PEER_MAX_VRFS         16   // VRFs that a peer shares with the node (Peer.vrf_ids of control.options)
#define PEER_MAX_RELAYS       8    // Relays that a node may use
#define PEER_MAX_CANDIDATES   8    // ICE candidates of one signal
#define PEER_MAX_DATAGRAM     2048 // The largest datagram of the peer layer
#define PEER_DATA_HEADER_SIZE 65   // A datagram between two nodes starts with its kind, the source key, the destination key
#define PEER_RECORD_HEADER    77   // A record: that, the session index of the receiver and the counter (big-endian)
#define PEER_RECORD_TAG       16   // ... then the ciphertext of the payload and the AES-GCM tag
#define PEER_MAX_PAYLOAD      (PEER_MAX_DATAGRAM - PEER_RECORD_HEADER - PEER_RECORD_TAG)
#define PEER_SESSION_ID_SIZE  8    // The id of a peer session that PEER_STATUS shows: the start of its handshake hash
#define PEER_ENVELOPE_HEADER  65   // An envelope: its kind, the sender's static key, the ephemeral key
#define PEER_ENVELOPE_TAG     16   // ... then the ciphertext and the AES-GCM tag
#define PEER_MAX_ENVELOPE     1024 // The largest envelope (Signal.envelope of control.options)
#define PEER_HOST_SIZE        64   // An address of the configuration as text, with its terminating NUL
#define PEER_ICE_UFRAG_SIZE   17   // An ICE username fragment of a signal, 4 to 16 ice-chars (RFC 8839 section 5.4), and its NUL
#define PEER_ICE_PWD_SIZE     33   // An ICE password of a signal, 22 to 32 ice-chars, and its NUL

// The first byte of a datagram or an envelope
#define PEER_MSG_DATA      1 // The old clear data datagram, which every node and relay drops (PEER_DROP_CLEAR)
#define PEER_MSG_BIND      2 // Envelope and datagram: a node binds to a relay
#define PEER_MSG_BOUND     3 // Envelope and datagram: the relay's answer, with the address it sees the node at
#define PEER_MSG_SIGNAL    4 // Envelope: a signal from a node to a peer, through the control plane only
#define PEER_MSG_PUNCH     5 // Envelope and datagram: a hole-punch message straight to a predicted address of a peer
#define PEER_MSG_CHALLENGE 6 // Envelope and datagram: the relay's cookie for a bind from an address it has not seen the node at
#define PEER_MSG_INIT      7 // Datagram: the first message of the handshake of a peer session (Noise_IK)
#define PEER_MSG_RESPONSE  8 // Datagram: its second message
#define PEER_MSG_RECORD    9 // Datagram: a record of a peer session, a frame from a node to a node or a keepalive

// The type of a signal
#define PEER_SIGNAL_OFFER        1 // Sent to a new peer
#define PEER_SIGNAL_ANSWER       2 // Sent back for an offer
#define PEER_SIGNAL_PUNCH_OFFER  3 // Asks a peer on the relay, whose ICE failed, for a punch now: the NAT and the prediction of the sender (PeerPunch.c)
#define PEER_SIGNAL_PUNCH_ANSWER 4 // Sent back for a punch offer that the receiver took: its probes go already

// The NAT of a node, as the answers of the binds to its first two relays show it (PEER_STATS; PeerPunch.c)
#define PEER_NAT_UNKNOWN    0 // Fewer than two answers: the node cannot tell
#define PEER_NAT_CONE       1 // The two relays saw the same port: one mapping for every destination
#define PEER_NAT_SEQUENTIAL 2 // Symmetric, a new port for each destination, a small step on from the last: the next one can be predicted
#define PEER_NAT_RANDOM     3 // Symmetric, the ports far apart: the next one cannot be predicted

// The type of an ICE candidate (RFC 8445 section 5.1.1)
#define PEER_CANDIDATE_HOST      1 // An address of the node itself
#define PEER_CANDIDATE_SRFLX     2 // Server reflexive: the address that its home relay saw it at, in the answer of its bind
#define PEER_CANDIDATE_MAPPED    3 // A public port that the node's home gateway granted (PCP, NAT-PMP or UPnP)
#define PEER_CANDIDATE_PREDICTED 4 // The public port the node's own NAT will give its next mapping (PeerPunch.c, CORE-S5-4)
#define PEER_CANDIDATE_TOWARD    5 // A punch signal: the public port of the sender's mapping towards the receiver's reflexive address (CORE-S5-7)

// The ICE session of a node with a peer (PEER_STATUS)
#define PEER_ICE_NONE      0 // None: ICE is off, or no signal of the session yet
#define PEER_ICE_CHECKING  1 // Checking candidate pairs, while the peer stays on the relay
#define PEER_ICE_CONNECTED 2 // A candidate pair validated: the node takes the peer's records from its address there
#define PEER_ICE_COMPLETED 3 // ... and the controlling end nominated it: the direct path is up, the same pair at both ends
#define PEER_ICE_FAILED    4 // No pair validated, no answer came to the node's offer, or the direct path lost consent: the peer is on the relay

// ms that a session of the node's offer waits for the answer of the peer before it fails (PeerIce.c): libjuice starts the
// 39.5 s that it gives the checks of a session only once it has the credentials of the peer, which the answer brings
#define PEER_ICE_ANSWER_TIMEOUT 40000

// The symmetric-NAT hole punch of a node with a peer (PEER_STATUS; PeerPunch.c, CORE-S5-4 and CORE-S5-7). It runs on
// the peer layer's own socket, not libjuice, so the simulated NATs of the harness carry it.
#define PEER_PUNCH_NONE      0 // Off, no punch signal of the peer yet, or a punched path that lost its consent
#define PEER_PUNCH_PROBING   1 // Sending probes to the predicted ports while the peer stays on the relay
#define PEER_PUNCH_CONNECTED 2 // A probe met one of the peer's: the direct path is up
#define PEER_PUNCH_FAILED    3 // The probe budget ran out with no meeting: the peer stays on the relay

// How a node reaches a peer (PEER_STATUS) and how a delivered datagram came (PEER_RECV_PROC)
#define PEER_PATH_NONE   0 // No path: no signal of the peer yet
#define PEER_PATH_RELAY  1 // Through a relay
#define PEER_PATH_DIRECT 2 // Directly, on the path that ICE validated

// The peer session of a node with a peer (PEER_STATUS; PeerSession.c)
#define PEER_SESSION_NONE      0 // None: the next datagram to the peer starts a handshake
#define PEER_SESSION_HANDSHAKE 1 // A handshake is on its way and no keys are up yet: datagrams wait in the queue
#define PEER_SESSION_UP        2 // Records go both ways

// ms before an initiation of a peer session that had no answer is sent again, and how many times it goes before the
// datagrams that wait for it are dropped (PeerSession.c)
#define PEER_SESSION_RETRY 1000
#define PEER_SESSION_TRIES 10

// What PeerOpenSignal returns, and why the peer layer dropped a datagram, an envelope or a signal
#define PEER_OK             0  // Taken
#define PEER_DROP_MALFORMED 1  // Too short, too long, of no known kind or with a bad payload
#define PEER_DROP_FORGED    2  // The envelope does not open: forged, altered, or for another node
#define PEER_DROP_REPLAY    3  // The sequence is not above the last one taken from that node
#define PEER_DROP_POLICY    4  // The source is no peer, or the two ends share no VRF
#define PEER_DROP_SOURCE    5  // A data datagram from an address that is no path of its source
#define PEER_DROP_NOT_RELAY 6  // A bind to, or a datagram to forward through, a node without the relay role
#define PEER_DROP_NOT_BOUND 7  // A datagram to forward to a node that is not bound to the relay
#define PEER_DROP_RATE      8  // Over a rate: of the relay for its source, or of the punch messages of the node (PunchRate, PunchBudget)
#define PEER_DROP_RELAY     9  // A signal or a bound from a relay that the control plane did not assign
#define PEER_DROP_SEND      10 // The send procedure failed
#define PEER_DROP_CLEAR     11 // A data datagram of the old clear form (PEER_MSG_DATA): there is no downgrade to it
#define PEER_DROP_SESSION   12 // A record or a handshake answer under no session of its source: an unknown index, or another node's
#define PEER_DROP_ICE       13 // A STUN message that no ICE session of the node takes: of a session that ended or failed, a check before the answer of the peer, or none
#define PEER_NUM_REASONS    14

// The port mapping of a node behind a home gateway (PEER_STATS; PeerPortMap.c)
#define PEER_PORTMAP_OFF     0 // Off: the node asks no gateway, and no request leaves it
#define PEER_PORTMAP_PENDING 1 // Asking: libplum looks for a gateway that answers PCP, NAT-PMP or UPnP
#define PEER_PORTMAP_MAPPED  2 // The gateway granted a public port, which goes first among the candidates
#define PEER_PORTMAP_FAILED  3 // No gateway granted one

// A transport address: an IPv4 address as an IPv4-mapped IPv6 address (RFC 4291 section 2.5.5.2), and a port
typedef struct PEER_ADDR {
	UCHAR Ip[16];
	USHORT Port; // Host order
} PEER_ADDR;

// The static key of a node: its identity key in a key storage provider, or a scalar in memory (the harness)
typedef struct PEER_KEY {
	struct CRYPTO_IDENTITY *Identity; // The identity key; NULL when Private holds the scalar
	UCHAR Private[PEER_KEY_SIZE];     // The scalar, without an identity key
	UCHAR Public[PEER_KEY_SIZE];      // The public key
} PEER_KEY;

// One peer of the node, from the Peer objects of the desired state: another node that shares a VRF with it
typedef struct PEER_INFO {
	char Name[PEER_NAME_SIZE];  // The node name
	UCHAR Key[PEER_KEY_SIZE];   // Its static key
	UINT NumVrfs;               // The VRFs it shares with this node
	UINT VrfIds[PEER_MAX_VRFS]; // ... their ids
} PEER_INFO;

// A relay that the node may use, from the Relay objects of the desired state. The first is its home relay.
typedef struct PEER_RELAY_INFO {
	char Name[PEER_NAME_SIZE]; // The node name of the relay
	UCHAR Key[PEER_KEY_SIZE];  // Its static key
	PEER_ADDR Addr;            // The address its relay role listens on
} PEER_RELAY_INFO;

// An ICE candidate
typedef struct PEER_CANDIDATE {
	UINT Type;      // PEER_CANDIDATE_*
	PEER_ADDR Addr; // Its address
} PEER_CANDIDATE;

// The content of a signal
typedef struct PEER_SIGNAL {
	UINT Type;                                      // PEER_SIGNAL_*
	UINT64 Sequence;                                // Grows with every signal and bind of the sender
	UCHAR Sender[PEER_KEY_SIZE];                    // The sender's static key, set by PeerOpenSignal
	UCHAR RelayKey[PEER_KEY_SIZE];                  // The relay assignment: the static key of the sender's relay, zero for none
	PEER_ADDR Relay;                                // ... and the address of that relay
	UINT NumCandidates;                             // The sender's ICE candidates
	PEER_CANDIDATE Candidates[PEER_MAX_CANDIDATES]; // ... and their types and addresses
	char IceUfrag[PEER_ICE_UFRAG_SIZE];             // The username fragment of the sender's ICE session with the receiver, empty without
	char IcePwd[PEER_ICE_PWD_SIZE];                 // ... and its password
	UINT Nat;                                       // A punch offer or answer: the NAT of the sender (PEER_NAT_*), 0 in the others
} PEER_SIGNAL;

// How a node reaches one peer (PeerGetStatus)
typedef struct PEER_STATUS {
	UINT Path;                             // PEER_PATH_*: the path that PeerSend takes now
	UCHAR RelayKey[PEER_KEY_SIZE];         // The relay of the peer's last signal, zero for none
	UINT NumCandidates;                    // The candidates of its last signal
	UINT64 Sequence;                       // The sequence of its last signal
	UINT Ice;                              // PEER_ICE_*: the ICE session with the peer
	UINT Punch;                            // PEER_PUNCH_*: the symmetric-NAT hole punch with the peer
	PEER_ADDR Direct;                      // The peer's address on the direct path, while the peer is on it
	UINT Session;                          // PEER_SESSION_*: the peer session with the peer
	UCHAR SessionId[PEER_SESSION_ID_SIZE]; // ... the id of its keys now, the same at both ends, zero for none
	UINT64 Handshakes;                     // ... the handshakes that completed with the peer: the first keys, then each rekey
} PEER_STATUS;

// The counters of the peer layer of a node (PeerGetStats)
typedef struct PEER_STATS {
	UINT64 Sent;                    // Datagrams sent
	UINT64 Delivered;               // Data datagrams delivered to the node
	UINT64 DeliveredRelay;          // ... of them through a relay
	UINT64 Forwarded;               // Data datagrams that the relay role forwarded
	UINT64 Binds;                   // Binds that the relay role took
	UINT64 Signals;                 // Signals taken
	UINT64 Upgrades;                // Peers that moved off the relay to a direct path that ICE validated or a punch met
	UINT64 Fallbacks;               // ... of them whose direct path failed later, its consent lost: peers back on the relay
	UINT64 PunchAttempts;           // Symmetric-NAT hole punches whose probes began, one for each attempt with a peer
	UINT64 PunchSuccesses;          // ... of them that reached a direct path by port prediction or birthday punching
	UINT64 PunchFailures;           // ... of them that spent their probes and met nothing: failures of the prediction
	UINT64 PunchProbes;             // Probes that the punches sent
	UINT64 Handshakes;              // Handshakes of peer sessions that completed, as initiator or responder
	UINT64 Challenges;              // Bind challenges that the relay role sent: binds from an address it had no cookie for
	UINT64 StunMessages;            // STUN messages that came to the socket with ICE on, each read once whatever the number of ICE sessions
	UINT NumBindings;               // Nodes bound to the relay role now
	UINT NumBound;                  // Relays that the node is bound to now
	UINT NumIce;                    // ICE sessions now
	UINT PortMap;                   // PEER_PORTMAP_*: the port mapping of the home gateway
	PEER_ADDR Mapped;               // ... the public address and port that it granted, zero for none
	UINT Nat;                       // PEER_NAT_*: the NAT of the node, from the answers of the binds to its first two relays
	PEER_ADDR Predicted;            // ... the public address and port of its next mapping, zero when it cannot be predicted
	UINT64 Drops[PEER_NUM_REASONS]; // What the peer layer dropped, by reason (PEER_DROP_*)
} PEER_STATS;

// The configuration of the peer layer of a node (PeerDefaultConfig). With Ice, every ICE session of the node runs on
// the socket of the layer, the ICE socket, so that one mapping of a NAT or a home gateway serves the relay and all of
// its peers.
typedef struct PEER_CONFIG {
	bool Relay;                   // The relay role: take binds and forward between the nodes bound to it
	UINT RelayRate;               // Data datagrams per second that one bound node may send through the relay
	UINT RelayBurst;              // ... of them in one burst
	UINT BindInterval;            // ms between two binds of the node to a relay: the keepalive of its binding
	UINT BindRetry;               // ms before a bind that had no answer is sent again
	UINT BindExpiry;              // ms after which the relay role drops a binding that was not renewed
	bool Ice;                     // Move each peer from the relay to a direct path that ICE validates (libjuice)
	bool PortMap;                 // With Ice, ask the home gateway for a public port of the socket (libplum)
	UINT PortMapTimeout;          // ms that the port mapping waits for a gateway, per protocol; 0 for 10 s
	bool Punch;                   // Try port prediction and birthday punching for a symmetric-NAT peer (PeerPunch.c)
	UINT PunchBudget;             // The most punch messages one attempt of a punch may send, its probes and its answers; 0 for the default
	UINT PunchPorts;              // The ports above a predicted one that the birthday range covers; 0 for the default
	UINT PunchRate;               // The most punch messages the node sends in any second, across its peers; 0 for the default
	UINT PunchAttempts;           // Attempts in a row that met nothing, after which the pair stays on the relay for PunchBackoff; 0 for the default
	UINT PunchRetry;              // ms from the end of an attempt to the next one with the same peer; 0 for the default
	UINT PunchBackoff;            // ms that the pair stays on the relay after the end of PunchAttempts failed attempts; 0 for the default
	UINT PunchConsent;            // ms without a word of the peer on a punched path, after which the pair falls back to the relay; 0 for the default
	UINT SessionRekeyTime;        // ms after which the initiator of a peer session's keys replaces them; 0 for the default
	UINT64 SessionRekeyDatagrams; // Records sent under one key after which the sender replaces it; 0 for the default
	UINT SessionTimeout;          // ms without a record from the peer after which its session is dropped; 0 for the default
	UINT SessionKeepalive;        // ms after a record received with none sent, when a keepalive answers it; 0 for the default
} PEER_CONFIG;

#define PEER_DEFAULT_RELAY_RATE  20000
#define PEER_DEFAULT_RELAY_BURST 2000
#define PEER_DEFAULT_BIND        25000 // Below the 30 s UDP mapping timeout of common NATs (RFC 4787 REQ-5 asks 2 min)
#define PEER_DEFAULT_BIND_RETRY  1000
#define PEER_DEFAULT_BIND_EXPIRY 90000
// The limits of the punch (ADR-0015 item 2; CORE-S5-7 #413), so that its probes do not look like a scan: 128 punch
// messages an attempt at most, its probes and its answers together, 64 punch messages a second at most, and after 3
// attempts in a row that met nothing the pair stays on the relay for 30 min. A punched path whose peer said nothing for
// 30 s falls back to the relay.
#define PEER_DEFAULT_PUNCH_BUDGET   128     // Punch messages of an attempt, its probes and its answers: then the peer stays on the relay
#define PEER_DEFAULT_PUNCH_PORTS    12      // The birthday range: the next port of a sequential NAT within 12 above the predicted one
#define PEER_DEFAULT_PUNCH_RATE     64      // Punch messages per second, probes and answers
#define PEER_DEFAULT_PUNCH_ATTEMPTS 3       // Attempts that meet nothing before the backoff
#define PEER_DEFAULT_PUNCH_RETRY    20000   // ms from the end of one attempt to the next
#define PEER_DEFAULT_PUNCH_BACKOFF  1800000 // ms on the relay after the attempts
#define PEER_DEFAULT_PUNCH_CONSENT  30000   // ms of silence that end a punched path, as consent freshness ends one of ICE
// The timers of a peer session, those of the Noise session (Noise.h): rekey after 2 min or 2^24 records under one
// key, which keeps AES-GCM within the limit of RFC 8446 section 5.5; a keepalive 10 s after a record that had no
// answer; the session dropped after 45 s without a record from the peer
#define PEER_DEFAULT_REKEY_TIME      120000
#define PEER_DEFAULT_REKEY_DATAGRAMS (1ULL << 24)
#define PEER_DEFAULT_SESSION_TIMEOUT 45000
#define PEER_DEFAULT_KEEPALIVE       10000

// The peer layer of one node, Peer.c
typedef struct PEER_AGENT PEER_AGENT;
// A UDP socket of the peer layer and its receive thread, PeerUdp.c
typedef struct PEER_UDP PEER_UDP;

// Sends one datagram to dst; false when it could not be sent
typedef bool(PEER_SEND_PROC)(void *param, const PEER_ADDR *dst, const void *data, UINT size);
// Takes one data datagram for the node from the peer src, which came on path (PEER_PATH_RELAY or
// PEER_PATH_DIRECT). It runs on the thread that called PeerInput, and may call PeerSend and nothing else of the
// peer layer.
typedef void(PEER_RECV_PROC)(PEER_AGENT *a, void *param, const UCHAR *src, UINT path, const void *data, UINT size);

// Peer.c
void PeerDefaultConfig(PEER_CONFIG *c);
PEER_AGENT *PeerNew(PEER_KEY *key, PEER_CONFIG *c, PEER_SEND_PROC *send, void *send_param, PEER_RECV_PROC *recv, void *recv_param);
void PeerFree(PEER_AGENT *a);
void PeerSetPeers(PEER_AGENT *a, PEER_INFO *peers, UINT num);
void PeerSetRelays(PEER_AGENT *a, PEER_RELAY_INFO *relays, UINT num);
void PeerSetHostCandidates(PEER_AGENT *a, PEER_ADDR *addrs, UINT num);
bool PeerSetDirect(PEER_AGENT *a, const UCHAR *key, const PEER_ADDR *addr);
UINT PeerSealSignal(PEER_AGENT *a, const UCHAR *peer, UINT type, UCHAR *buf, UINT size);
UINT PeerOpenSignal(PEER_AGENT *a, const UCHAR *env, UINT size, PEER_SIGNAL *sig);
void PeerInput(PEER_AGENT *a, const PEER_ADDR *from, const UCHAR *data, UINT size);
bool PeerSend(PEER_AGENT *a, const UCHAR *dst, const void *data, UINT size);
void PeerTick(PEER_AGENT *a);
bool PeerGetStatus(PEER_AGENT *a, const UCHAR *key, PEER_STATUS *st);
void PeerGetStats(PEER_AGENT *a, PEER_STATS *st);
UINT PeerGetCandidates(PEER_AGENT *a, PEER_CANDIDATE *c, UINT max);
bool PeerHomeBound(PEER_AGENT *a);
const UCHAR *PeerPublicKey(PEER_AGENT *a);
void PeerAddrSetV4(PEER_ADDR *a, UCHAR b0, UCHAR b1, UCHAR b2, UCHAR b3, USHORT port);
bool PeerAddrEqual(const PEER_ADDR *a, const PEER_ADDR *b);
const char *PeerReasonName(UINT reason);

// PeerIce.c: the timer of the ICE sessions at a clock that the caller gives (ms, the clock of PeerTick), for a test of a
// session that started after the clock of a tick
void PeerIceTickAt(PEER_AGENT *a, UINT64 now);

// Peer.c: the timers of the peer sessions at a clock that the caller gives (ms, the clock of PeerTick), for a test of a
// tick whose clock is older than an initiation that was sent or keys that were made after the tick read it
void PeerSessionTickAt(PEER_AGENT *a, UINT64 now);

// Peer.c: the timers of the binds, the bindings that the relay role drops and the binds that the node renews or retries,
// at a clock that the caller gives (ms, the clock of PeerTick), for a test of a tick whose clock is older than a bind that
// was sent or taken after the tick read it
void PeerTickAt(PEER_AGENT *a, UINT64 now);

// PeerSignal.c
bool PeerKeyFromScalar(PEER_KEY *k, const UCHAR *priv);
bool PeerKeyOpen(PEER_KEY *k, const wchar_t *name);
void PeerKeyClose(PEER_KEY *k);
bool PeerKeyDelete(const wchar_t *name);
UINT PeerEnvelopeSeal(PEER_KEY *key, const UCHAR *peer, UINT kind, const UCHAR *ephemeral, const void *payload, UINT payload_size, UCHAR *buf, UINT size);
bool PeerEnvelopeOpen(PEER_KEY *key, const UCHAR *env, UINT size, UCHAR *sender, void *payload, UINT payload_size, UINT *payload_len);
UINT PeerSignalEncode(const PEER_SIGNAL *s, UCHAR *buf, UINT size);
bool PeerSignalDecode(const UCHAR *buf, UINT size, PEER_SIGNAL *s);

// The clear header of a datagram between two nodes (PeerRecordParse): a handshake message or a record
typedef struct PEER_RECORD_INFO {
	UINT Kind;        // PEER_MSG_INIT, PEER_MSG_RESPONSE or PEER_MSG_RECORD
	const UCHAR *Src; // The source key, in the datagram
	const UCHAR *Dst; // The destination key, in the datagram
	UINT Sender;      // The session index of the sender (a handshake message)
	UINT Receiver;    // The session index of the receiver (a response or a record)
	UINT64 Counter;   // The counter of a record
	UINT HeaderSize;  // The bytes before the Noise message or the ciphertext
} PEER_RECORD_INFO;

// The payload of a handshake message of a peer session (PeerHandshakeParse)
typedef struct PEER_HANDSHAKE_INFO {
	UINT64 Timestamp; // The initiation: the sequence of the initiator, which grows with the clock (PeerNextSequence)
	UINT Sender;      // The session index of the side that wrote the message
	UINT Receiver;    // The response: the index of the initiator
} PEER_HANDSHAKE_INFO;

// PeerSession.c
bool PeerRecordParse(const UCHAR *data, UINT size, PEER_RECORD_INFO *r);
bool PeerHandshakeParse(UINT kind, const UCHAR *payload, UINT size, PEER_HANDSHAKE_INFO *h);

// The payload of a punch message (PeerPunchParse): a probe, a message of the exchange of nonces that proves the address
// at which two probes met, or a keepalive on the punched path
typedef struct PEER_PUNCH_INFO {
	UINT64 Sequence;    // The sequence of the sender, which grows with the clock (PeerNextSequence)
	UINT Type;          // The type of the message: a probe, a challenge, a response, a proof or a keepalive (PeerPunch.c)
	const UCHAR *Nonce; // A nonce of the sender, in the payload: that of a challenge or of a response
	const UCHAR *Echo;  // The echo of a nonce of the receiver, in the payload: that of a response or of a proof
} PEER_PUNCH_INFO;

// PeerPunch.c
bool PeerPunchDue(PEER_AGENT *a, const UCHAR *key);
bool PeerPunchParse(const UCHAR *payload, UINT size, PEER_PUNCH_INFO *m);

// PeerUdp.c
PEER_UDP *PeerUdpNew(USHORT port);
USHORT PeerUdpPort(PEER_UDP *u);
bool PeerUdpSend(void *param, const PEER_ADDR *dst, const void *data, UINT size);
bool PeerUdpStart(PEER_UDP *u, PEER_AGENT *a);
void PeerUdpStop(PEER_UDP *u);
void PeerUdpFree(PEER_UDP *u);
UINT PeerUdpHosts(PEER_UDP *u, PEER_ADDR *addrs, UINT max);
void PeerAddrToStr(char *str, UINT size, const PEER_ADDR *a);

#endif // CORE_PEER_H
