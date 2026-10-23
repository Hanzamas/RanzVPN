// Control.h
// The control module of the new core (SDN-3, #179): the node's end of the control stream to the
// controller (#176 "Control protocol", ADR-0027). A client opens a stream to the controller over a
// transport whose streams are TLS sessions with the ALPN protocol CONTROL_ALPN and whose channel
// binding is their TLS exporter CONTROL_EXPORTER_LABEL, runs the Noise_IK handshake of the node's
// static key with the controller's, bound to that exporter, and says Hello with the Generation it
// applied last. It applies each Update to the desired state it holds, hands that state to its
// owner and acknowledges the Generation. The frames are the messages that nanopb generates from
// proto/ranz/control/v1/control.proto, the one schema of the node and the controller (ADR-0027
// decision 1), each after its size in 4 bytes (big-endian), as controller/internal/control sends
// them. With no controller reachable the state stays the one applied last, and the client opens
// the stream again until a controller answers.
//
// The module links the transport, session and crypto modules and nanopb only. One thread per
// client runs its stream; the owner's procedure runs on it.

#ifndef CORE_CONTROL_H
#define CORE_CONTROL_H

#include "Core/Transport.h"

#define CONTROL_ALPN           "ranz-control/1"              // The ALPN protocol of the control stream on the controller's port
#define CONTROL_EXPORTER_LABEL "EXPORTER-ranz-control-noise" // The TLS exporter in the prologue of its handshake ...
#define CONTROL_EXPORTER_SIZE  32                            // ... and its size, with no context
#define CONTROL_PROLOGUE_LABEL "ranz control stream 1"       // The prologue of the handshake, before the exporter
#define CONTROL_NAME_SIZE      64                            // A name with its terminating NUL (control.options)
#define CONTROL_MAX_VRFS       16                            // The VRFs of a node and of a peer (Peer.vrf_ids of control.options)
#define CONTROL_MAX_ADDRESSES  16                            // The addresses of a node (NodeConfig.addresses, Peer.addresses)
#define CONTROL_MAX_FRAME      (1 << 20)                     // The largest frame the client reads
#define CONTROL_TIMEOUT        10000                         // ms for the handshake, and for a frame to come whole
#define CONTROL_RETRY          1000                          // ms between two attempts to open the stream

// An address of a node in an L3 Network of one of its VRFs (Address of the control protocol)
typedef struct CONTROL_ADDRESS {
	char Network[CONTROL_NAME_SIZE]; // The Network
	UINT VrfId;                      // ... and its VRF
	UCHAR Address[16];               // The address: 4 bytes for IPv4, 16 for IPv6
	UINT AddressSize;                // ... their number
	UINT Length;                     // The prefix length of the pool of the Network
} CONTROL_ADDRESS;

// A peer of the node: another node that shares a VRF with it (Peer of the control protocol)
typedef struct CONTROL_PEER {
	char Name[CONTROL_NAME_SIZE];                     // Its node name
	UCHAR Key[NOISE_KEY_SIZE];                        // Its static key
	UINT NumVrfs;                                     // The VRFs it shares with the node
	UINT VrfIds[CONTROL_MAX_VRFS];                    // ... their ids
	UINT NumAddresses;                                // Its addresses in the Networks of those VRFs
	CONTROL_ADDRESS Addresses[CONTROL_MAX_ADDRESSES]; // ... ordered by Network name
} CONTROL_PEER;

// A VRF that the node is a member of (Vrf of the control protocol): the MTU and the rate limit of
// the overlay in it (SDN-20, #196)
typedef struct CONTROL_VRF {
	char Name[CONTROL_NAME_SIZE]; // Its name
	UINT Id;                      // Its id
	UINT Mtu;                     // Its MTU
	UINT64 RateLimit;             // Bits per second that each node sends in it, 0 for no limit
} CONTROL_VRF;

// The desired state that the client applied, as its owner takes it (CONTROL_STATE_PROC). The
// Networks and Relays of the state stay in the client until a module of the node needs them.
typedef struct CONTROL_STATE {
	UINT64 Generation;                                // The Generation of the state
	char Name[CONTROL_NAME_SIZE];                     // The node's name in the intent
	UINT NumAddresses;                                // Its addresses in the L3 Networks of its VRFs
	CONTROL_ADDRESS Addresses[CONTROL_MAX_ADDRESSES]; // ... ordered by Network name
	UINT64 RateLimit;                                 // Bits per second that it sends into the overlay, 0 for no limit
	UINT NumVrfs;                                     // The VRFs it is a member of
	CONTROL_VRF Vrfs[CONTROL_MAX_VRFS];               // ... in name order
	UINT NumPeers;                                    // Its peers
	CONTROL_PEER *Peers;                              // ... in name order
} CONTROL_STATE;

// Takes each state that the client applied, before the client acknowledges its Generation. It runs
// on the client's thread; state is valid until it returns.
typedef void(CONTROL_STATE_PROC)(void *param, const CONTROL_STATE *state);

// How a client runs
typedef struct CONTROL_CONFIG {
	TRANSPORT *Transport;                 // The transport of the stream (see above)
	char Address[TRANSPORT_ADDRESS_SIZE]; // The controller's address on it
	UCHAR ControllerKey[NOISE_KEY_SIZE];  // The controller's static key
	const UCHAR *StaticKey;               // The node's static key: a scalar, which the client copies ...
	CRYPTO_IDENTITY *Identity;            // ... or the node identity in the key storage provider, which must outlive the client
	CONTROL_STATE_PROC *Proc;             // Takes each state applied
	void *Param;                          // The first parameter of Proc
} CONTROL_CONFIG;

// How a client stands (ControlGetStatus)
typedef struct CONTROL_STATUS {
	bool Connected;        // A stream is open: the handshake passed and the Hello went out
	UINT64 Applied;        // The Generation applied last, 0 before the first
	UINT64 NumStreams;     // Streams whose handshake passed so far
	UINT64 NumUpdates;     // Updates applied so far
	UINT LastRefuse;       // The reason of the last Refuse (RefuseReason of the control protocol), 0 for none
	char LastMessage[256]; // ... and its message
} CONTROL_STATUS;

// The client of one node, Control.c
typedef struct CONTROL_CLIENT CONTROL_CLIENT;

// Start starts a client on a thread of its own, which opens the stream at once: NULL when the
// configuration is not complete or the thread cannot start. Stop ends the stream and the thread
// and frees the client. GetStatus tells how the client stands.
CONTROL_CLIENT *ControlStart(const CONTROL_CONFIG *cfg);
void ControlStop(CONTROL_CLIENT *c);
void ControlGetStatus(CONTROL_CLIENT *c, CONTROL_STATUS *st);

#endif // CORE_CONTROL_H
