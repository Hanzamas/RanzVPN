// Peer.h
// The peer module of the new core (ADR-0015): the peers of a node and the paths to them, and the relay role.
//
// A node reaches a peer over a path. The relay path goes through a relay, a node with the relay role that both
// ends are bound to; it is up as soon as the two have exchanged one signal each through the control plane, so a
// new peer pair comes up in one round trip (relay-first). The direct path is the one that ICE validates later
// (CORE-S5-3, #79), PeerSetDirect. Every datagram a node receives goes through one ingress, PeerInput, whichever
// path it came on: a datagram for the node itself is delivered, one for another node is forwarded when the node
// has the relay role and both ends are bound to it. The same policy check runs in both cases: the source is a
// peer, and the destination is the node itself or a peer that shares a VRF with the source. The control plane
// sets the peers (the Peer objects of the desired state, PeerSetPeers) and the relays a node may use (its Relay
// objects, PeerSetRelays).
//
// Signals and binds (PeerSignal.c) are envelopes sealed by the sending node's static key to the receiving
// node's, with the Noise one-way pattern K (Noise_K_25519_AESGCM_SHA256): only the receiver can open one, and
// only a holder of the sender's private key can make one, so the controller that carries a signal can neither
// forge, alter nor redirect it, and a relay binds no node that does not hold its key. A signal carries the relay
// assignment of its sender (the relay it is bound to) and its ICE candidates. A sequence that grows with the
// wall clock, as the timestamp of a WireGuard handshake initiation does, makes every replay fail.
//
// The datagrams travel over a send procedure that the caller gives (PEER_SEND_PROC) and come back through
// PeerInput: a UDP socket (PeerUdp.c) or the harness network of coretest. The socket stands in for the QUIC
// datagrams of CORE-S1-1 (#67) until the transport interface of CORE-F4 (#64) carries them; the relay then
// shares the QUIC listener on UDP 443 (ADR-0035).

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
#define PEER_DATA_HEADER_SIZE 65   // A data datagram: PEER_MSG_DATA, the source key, the destination key
#define PEER_MAX_PAYLOAD      (PEER_MAX_DATAGRAM - PEER_DATA_HEADER_SIZE)
#define PEER_ENVELOPE_HEADER  65   // An envelope: its kind, the sender's static key, the ephemeral key
#define PEER_ENVELOPE_TAG     16   // ... then the ciphertext and the AES-GCM tag
#define PEER_MAX_ENVELOPE     1024 // The largest envelope (Signal.envelope of control.options)

// The first byte of a datagram or an envelope
#define PEER_MSG_DATA   1 // Datagram: a frame from a node to a node
#define PEER_MSG_BIND   2 // Envelope and datagram: a node binds to a relay
#define PEER_MSG_BOUND  3 // Envelope and datagram: the relay's answer, with the address it sees the node at
#define PEER_MSG_SIGNAL 4 // Envelope: a signal from a node to a peer, through the control plane only

// The type of a signal
#define PEER_SIGNAL_OFFER  1 // Sent to a new peer
#define PEER_SIGNAL_ANSWER 2 // Sent back for an offer

// The type of an ICE candidate (RFC 8445 section 5.1.1)
#define PEER_CANDIDATE_HOST  1 // An address of the node itself
#define PEER_CANDIDATE_SRFLX 2 // Server reflexive: the address that its relay sees it at

// How a node reaches a peer (PEER_STATUS) and how a delivered datagram came (PEER_RECV_PROC)
#define PEER_PATH_NONE   0 // No path: no signal of the peer yet
#define PEER_PATH_RELAY  1 // Through a relay
#define PEER_PATH_DIRECT 2 // Directly, on the path that ICE validated

// What PeerOpenSignal returns, and why the peer layer dropped a datagram, an envelope or a signal
#define PEER_OK             0  // Taken
#define PEER_DROP_MALFORMED 1  // Too short, too long, of no known kind or with a bad payload
#define PEER_DROP_FORGED    2  // The envelope does not open: forged, altered, or for another node
#define PEER_DROP_REPLAY    3  // The sequence is not above the last one taken from that node
#define PEER_DROP_POLICY    4  // The source is no peer, or the two ends share no VRF
#define PEER_DROP_SOURCE    5  // A data datagram from an address that is no path of its source
#define PEER_DROP_NOT_RELAY 6  // A bind to, or a datagram to forward through, a node without the relay role
#define PEER_DROP_NOT_BOUND 7  // A datagram to forward to a node that is not bound to the relay
#define PEER_DROP_RATE      8  // Over the rate of the relay for its source
#define PEER_DROP_RELAY     9  // A signal or a bound from a relay that the control plane did not assign
#define PEER_DROP_SEND      10 // The send procedure failed
#define PEER_NUM_REASONS    11

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
} PEER_SIGNAL;

// How a node reaches one peer (PeerGetStatus)
typedef struct PEER_STATUS {
	UINT Path;                     // PEER_PATH_*: the path that PeerSend takes now
	UCHAR RelayKey[PEER_KEY_SIZE]; // The relay of the peer's last signal, zero for none
	UINT NumCandidates;            // The candidates of its last signal
	UINT64 Sequence;               // The sequence of its last signal
} PEER_STATUS;

// The counters of the peer layer of a node (PeerGetStats)
typedef struct PEER_STATS {
	UINT64 Sent;                    // Datagrams sent
	UINT64 Delivered;               // Data datagrams delivered to the node
	UINT64 DeliveredRelay;          // ... of them through a relay
	UINT64 Forwarded;               // Data datagrams that the relay role forwarded
	UINT64 Binds;                   // Binds that the relay role took
	UINT64 Signals;                 // Signals taken
	UINT NumBindings;               // Nodes bound to the relay role now
	UINT NumBound;                  // Relays that the node is bound to now
	UINT64 Drops[PEER_NUM_REASONS]; // What the peer layer dropped, by reason (PEER_DROP_*)
} PEER_STATS;

// The configuration of the peer layer of a node (PeerDefaultConfig)
typedef struct PEER_CONFIG {
	bool Relay;        // The relay role: take binds and forward between the nodes bound to it
	UINT RelayRate;    // Data datagrams per second that one bound node may send through the relay
	UINT RelayBurst;   // ... of them in one burst
	UINT BindInterval; // ms between two binds of the node to a relay: the keepalive of its binding
	UINT BindRetry;    // ms before a bind that had no answer is sent again
	UINT BindExpiry;   // ms after which the relay role drops a binding that was not renewed
} PEER_CONFIG;

#define PEER_DEFAULT_RELAY_RATE  20000
#define PEER_DEFAULT_RELAY_BURST 2000
#define PEER_DEFAULT_BIND        25000 // Below the 30 s UDP mapping timeout of common NATs (RFC 4787 REQ-5 asks 2 min)
#define PEER_DEFAULT_BIND_RETRY  1000
#define PEER_DEFAULT_BIND_EXPIRY 90000

// The peer layer of one node, Peer.c
typedef struct PEER_AGENT PEER_AGENT;
// A UDP socket of the peer layer and its receive thread, PeerUdp.c
typedef struct PEER_UDP PEER_UDP;

// Sends one datagram to dst; false when it could not be sent
typedef bool(PEER_SEND_PROC)(void *param, const PEER_ADDR *dst, const void *data, UINT size);
// Takes one data datagram for the node from the peer src, which came on path (PEER_PATH_RELAY or
// PEER_PATH_DIRECT). It runs on the thread that called PeerInput and may call PeerSend.
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
const UCHAR *PeerPublicKey(PEER_AGENT *a);
void PeerAddrSetV4(PEER_ADDR *a, UCHAR b0, UCHAR b1, UCHAR b2, UCHAR b3, USHORT port);
bool PeerAddrEqual(const PEER_ADDR *a, const PEER_ADDR *b);
const char *PeerReasonName(UINT reason);

// PeerSignal.c
bool PeerKeyFromScalar(PEER_KEY *k, const UCHAR *priv);
bool PeerKeyOpen(PEER_KEY *k, const wchar_t *name);
void PeerKeyClose(PEER_KEY *k);
bool PeerKeyDelete(const wchar_t *name);
UINT PeerEnvelopeSeal(PEER_KEY *key, const UCHAR *peer, UINT kind, const UCHAR *ephemeral, const void *payload, UINT payload_size, UCHAR *buf, UINT size);
bool PeerEnvelopeOpen(PEER_KEY *key, const UCHAR *env, UINT size, UCHAR *sender, void *payload, UINT payload_size, UINT *payload_len);
UINT PeerSignalEncode(const PEER_SIGNAL *s, UCHAR *buf, UINT size);
bool PeerSignalDecode(const UCHAR *buf, UINT size, PEER_SIGNAL *s);

// PeerUdp.c
PEER_UDP *PeerUdpNew(USHORT port);
USHORT PeerUdpPort(PEER_UDP *u);
bool PeerUdpSend(void *param, const PEER_ADDR *dst, const void *data, UINT size);
bool PeerUdpStart(PEER_UDP *u, PEER_AGENT *a);
void PeerUdpFree(PEER_UDP *u);
void PeerAddrToStr(char *str, UINT size, const PEER_ADDR *a);

#endif // CORE_PEER_H
