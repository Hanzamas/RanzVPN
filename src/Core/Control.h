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
#define CONTROL_MAX_NATS       16                            // The 1:1 NAT rules of a node (NodeConfig.nat of control.options)
#define CONTROL_MAX_ROUTES     16                            // The routes of a peer (Peer.routes of control.options)
#define CONTROL_MAX_DHCPS      16                            // The DHCP responders of a node, one per L2 Network (SDN-43, #236)
#define CONTROL_MAX_DNS        4                             // The DNS servers of a responder (Dhcp.dns of control.options)
#define CONTROL_MAX_RESERVED   16                            // The reservations of its pool (Dhcp.reserved of control.options)
#define CONTROL_MAX_LEASES     1024                          // The leases of one responder that one Leases message holds (control.options)
#define CONTROL_HOST_NAME_SIZE 64                            // The host name of a lease with its terminating NUL (Lease.host_name)
#define CONTROL_MAX_FRAME      (1 << 20)                     // The largest frame the client reads
#define CONTROL_TIMEOUT        10000                         // ms for the handshake, and for a frame to come whole
#define CONTROL_RETRY          1000                          // ms between two attempts to open the stream
#define CONTROL_MAX_MIRRORS    16                            // The Mirrors of a node (NodeConfig.mirrors of control.options)

// A Mirror that the node applies (Mirror of the control protocol; SDN-23, #199): the node copies the packets of the
// overlay that match it to the sensor, in VXLAN
typedef struct CONTROL_MIRROR {
	char Name[CONTROL_NAME_SIZE]; // Its name
	UINT VrfId;                   // The VRF of the packets, 0 for every VRF of the node
	UINT Protocol;                // Their IP protocol, 0 for any; 1 (ICMP) takes ICMPv6 in IPv6 packets
	UINT Port;                    // Their source or destination port, of TCP or UDP; 0 for any
	UCHAR Sensor[16];             // The sensor's address: 4 bytes for IPv4, 16 for IPv6
	UINT SensorSize;              // ... their number
	UINT SensorPort;              // ... and its UDP port
	UINT Vni;                     // The VNI of the copies, 0 for the VRF id of each packet
	UINT64 RateLimit;             // Bits per second of VXLAN datagrams that the node sends the sensor at most, 0 for no limit
} CONTROL_MIRROR;

// An address of a node in an L3 Network of one of its VRFs (Address of the control protocol)
typedef struct CONTROL_ADDRESS {
	char Network[CONTROL_NAME_SIZE]; // The Network
	UINT VrfId;                      // ... and its VRF
	UCHAR Address[16];               // The address: 4 bytes for IPv4, 16 for IPv6
	UINT AddressSize;                // ... their number
	UINT Length;                     // The prefix length of the pool of the Network
} CONTROL_ADDRESS;

// A 1:1 NAT rule of the node in one of its VRFs (Nat of the control protocol; SDN-6, #182): its host sees the
// addresses of Inside, the VRF those of Outside, one for one. Two prefixes of one family and length, or the 4via6 of
// the VRF: an IPv6 /96 inside and the IPv4 0.0.0.0/0 outside.
typedef struct CONTROL_NAT {
	UINT VrfId;         // The VRF
	UCHAR Inside[16];   // The prefix that the host sees: 4 bytes for IPv4, 16 for IPv6
	UINT InsideSize;    // ... their number
	UINT InsideLength;  // ... and its length
	UCHAR Outside[16];  // The prefix that the VRF sees
	UINT OutsideSize;   // ... the number of its bytes
	UINT OutsideLength; // ... and its length
} CONTROL_NAT;

// A prefix of a VRF that leads to a peer besides its addresses (Route of the control protocol): the outside prefix
// of a 1:1 NAT rule of the peer, or a route that a VRF of the peer leaks into the VRF (SDN-7, #183)
typedef struct CONTROL_ROUTE {
	UINT VrfId;        // The VRF
	UCHAR Address[16]; // The prefix: 4 bytes for IPv4, 16 for IPv6
	UINT AddressSize;  // ... their number
	UINT Length;       // ... and its length
	UINT PeerVrfId;    // The VRF of the peer that a packet on the route goes into, 0 for VrfId itself
} CONTROL_ROUTE;

// A peer of the node: another node that shares a VRF with it (Peer of the control protocol)
typedef struct CONTROL_PEER {
	char Name[CONTROL_NAME_SIZE];                     // Its node name
	UCHAR Key[NOISE_KEY_SIZE];                        // Its static key
	UINT NumVrfs;                                     // The VRFs it shares with the node
	UINT VrfIds[CONTROL_MAX_VRFS];                    // ... their ids
	UINT NumAddresses;                                // Its addresses in the Networks of those VRFs
	CONTROL_ADDRESS Addresses[CONTROL_MAX_ADDRESSES]; // ... ordered by Network name
	UINT NumRoutes;                                   // The prefixes of those VRFs that lead to it besides its addresses
	CONTROL_ROUTE Routes[CONTROL_MAX_ROUTES];         // ... ordered by VRF id
} CONTROL_PEER;

// A VRF that the node is a member of (Vrf of the control protocol): the MTU and the rate limit of
// the overlay in it (SDN-20, #196)
typedef struct CONTROL_VRF {
	char Name[CONTROL_NAME_SIZE]; // Its name
	UINT Id;                      // Its id
	UINT Mtu;                     // Its MTU
	UINT64 RateLimit;             // Bits per second that each node sends in it, 0 for no limit
} CONTROL_VRF;

// A reservation of the pool of a DHCP responder: an IPv4 prefix (Prefix of Dhcp.reserved)
typedef struct CONTROL_RESERVED {
	UCHAR Address[4]; // The prefix, in network byte order
	UINT Length;      // ... and its length
} CONTROL_RESERVED;

// The DHCP responder of an L2 Network that the node answers DHCP for (Network.dhcp of the control protocol; SDN-43, #236):
// only a Network object whose Dhcp is in the mode pool carries one. The addresses are IPv4, in network byte order.
typedef struct CONTROL_DHCP {
	char Network[CONTROL_NAME_SIZE];                 // The L2 Network
	UINT VrfId;                                      // ... and its VRF
	UCHAR Pool[4];                                   // The IPv4 pool of the Network ...
	UINT PoolLength;                                 // ... and its length
	UCHAR Address[4];                                // The responder's own address in the pool: its server identifier
	UCHAR Gateway[4];                                // The router of the clients, 0.0.0.0 for none
	UINT NumDns;                                     // The DNS servers of the clients
	UCHAR Dns[CONTROL_MAX_DNS][4];                   // ...
	UINT LeaseTime;                                  // The lease time, in seconds
	UINT NumReserved;                                // The reservations of the Network in the pool
	CONTROL_RESERVED Reserved[CONTROL_MAX_RESERVED]; // ...
} CONTROL_DHCP;

// One lease of a DHCP responder as the node reports it (Lease of the control protocol)
typedef struct CONTROL_LEASE {
	UCHAR Mac[6];                          // The client's MAC address
	UCHAR Address[4];                      // Its address, in network byte order
	UINT64 Expires;                        // When the lease ends: Unix time in ms
	char HostName[CONTROL_HOST_NAME_SIZE]; // The host name that the client sent (DHCP option 12), "" for none
} CONTROL_LEASE;

// The leases that a client reports to the controller (CONTROL_CONFIG.Leases), ControlDhcp.c
typedef struct CONTROL_LEASES CONTROL_LEASES;

// The desired state that the client applied, as its owner takes it (CONTROL_STATE_PROC). The
// Networks and Relays of the state stay in the client until a module of the node needs them: the
// DHCP responders of the Networks are the first (SDN-43, #236).
typedef struct CONTROL_STATE {
	UINT64 Generation;                                // The Generation of the state
	char Name[CONTROL_NAME_SIZE];                     // The node's name in the intent
	UINT NumAddresses;                                // Its addresses in the L3 Networks of its VRFs
	CONTROL_ADDRESS Addresses[CONTROL_MAX_ADDRESSES]; // ... ordered by Network name
	UINT64 RateLimit;                                 // Bits per second that it sends into the overlay, 0 for no limit
	UINT NumNats;                                     // The 1:1 NAT rules that it applies, its 4via6 among them
	CONTROL_NAT Nats[CONTROL_MAX_NATS];               // ... ordered by VRF id
	UINT NumVrfs;                                     // The VRFs it is a member of
	CONTROL_VRF Vrfs[CONTROL_MAX_VRFS];               // ... in name order
	UINT NumPeers;                                    // Its peers
	CONTROL_PEER *Peers;                              // ... in name order
	UINT NumMirrors;                                  // The Mirrors that it applies (SDN-23, #199)
	CONTROL_MIRROR Mirrors[CONTROL_MAX_MIRRORS];      // ... in name order
	UINT NumDhcps;                                    // The DHCP responders that it runs (SDN-43, #236)
	CONTROL_DHCP Dhcps[CONTROL_MAX_DHCPS];            // ... in Network name order
} CONTROL_STATE;

// Takes each state that the client applied, before the client acknowledges its Generation. It runs
// on the client's thread; state is valid until it returns.
typedef void(CONTROL_STATE_PROC)(void *param, const CONTROL_STATE *state);

// The architectures of the Capabilities (Architecture of the control protocol)
#define CONTROL_ARCHITECTURE_UNSPECIFIED 0
#define CONTROL_ARCHITECTURE_X64         1
#define CONTROL_ARCHITECTURE_ARM64       2

// The Capabilities that a node reports in its Hello (Capabilities of the control protocol, ADR-0033; ONE-3,
// #312): the facts about its host that its owner can tell. A Capability that the owner leaves out counts as
// missing for the controller.
typedef struct CONTROL_CAPS {
	// The architecture of the host (CONTROL_ARCHITECTURE_*)
	UINT Architecture;
	// The SeLow driver is installed (x64 only)
	bool SeLow;
	// The XDP for Windows runtime is installed and works
	bool Xdp;
} CONTROL_CAPS;

// Fills caps, which is zeroed, with the Capabilities of the node. The client calls it for each Hello, so a node
// whose Capabilities changed tells the controller by its next stream. It runs on the client's thread.
typedef void(CONTROL_CAPS_PROC)(void *param, CONTROL_CAPS *caps);

// How a client runs
typedef struct CONTROL_CONFIG {
	TRANSPORT *Transport;                 // The transport of the stream (see above)
	char Address[TRANSPORT_ADDRESS_SIZE]; // The controller's address on it
	UCHAR ControllerKey[NOISE_KEY_SIZE];  // The controller's static key
	const UCHAR *StaticKey;               // The node's static key: a scalar, which the client copies ...
	CRYPTO_IDENTITY *Identity;            // ... or the node identity in the key storage provider, which must outlive the client
	CONTROL_STATE_PROC *Proc;             // Takes each state applied
	void *Param;                          // The first parameter of Proc
	CONTROL_LEASES *Leases;               // The leases that the client reports after each Hello and whenever they change, NULL for none: the owner's, which must outlive the client

	// Tells the Capabilities of the node for each Hello, NULL for none: the Hello then holds none
	CONTROL_CAPS_PROC *CapsProc;
	// The first parameter of CapsProc
	void *CapsParam;
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

// The leases of the DHCP responders of a node (SDN-43, #236), ControlDhcp.c. NewLeases makes the reports that a client
// sends (CONTROL_CONFIG.Leases), FreeLeases frees them once no client uses them. SetLeases puts the leases of one L2
// Network in place of the ones before, and the client sends them as one Leases message after each Hello and whenever
// they change: at most CONTROL_MAX_LEASES of them, for CONTROL_MAX_DHCPS Networks at most. With leases NULL the Network
// has no responder any more: its report goes and nothing is sent for it. WriteLeases writes each report that a stream
// does not have yet as one frame, as the client does on its stream.
CONTROL_LEASES *ControlNewLeases();
void ControlFreeLeases(CONTROL_LEASES *l);
bool ControlSetLeases(CONTROL_LEASES *l, const char *network, const CONTROL_LEASE *leases, UINT num);
bool ControlWriteLeases(CONTROL_LEASES *l, TRANSPORT_STREAM *s);

#endif // CORE_CONTROL_H
