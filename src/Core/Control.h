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
#define CONTROL_MAX_TAGS       16                            // The tags of a node and of a peer (NodeConfig.tags, Peer.tags)
#define CONTROL_RULE_VALUES    16                            // The tags and the prefixes of an end of a rule, and its port ranges
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
#define CONTROL_RETRY          1000                          // ms before the stream opens again after it was open (ControlRetry.c) ...
#define CONTROL_RETRY_MAX      60000                         // ... and at most, as the delay doubles after each attempt that failed
#define CONTROL_MAX_MIRRORS    16                            // The Mirrors of a node (NodeConfig.mirrors of control.options)

// The zones of overlay DNS (SDN-11, #187)
#define CONTROL_DNS_NAME_SIZE     128 // A suffix or a name of a zone with its terminating NUL (DnsZone.suffix, DnsRecord.name)
#define CONTROL_MAX_DNS_RECORDS   16  // The records of a zone (DnsZone.records of control.options)
#define CONTROL_MAX_DNS_ADDRESSES 8   // The addresses of a record (DnsRecord.addresses of control.options)

// The WireGuard Devices (SDN-80, #375)
#define CONTROL_MAX_DEVICES      64   // The Devices of a gateway (Telemetry.devices of control.options)
#define CONTROL_DEVICE_ADDRESSES 2    // The addresses of a Device: IPv4 and IPv6 (Device.addresses of control.options)
#define CONTROL_DEVICE_REPORT    5000 // ms between two reports of the counters of the Devices of a gateway

// The endpoints of a node and of its peers (SDN-93, #410)
#define CONTROL_MAX_ENDPOINTS 8 // The endpoints of a node and of a peer (NodeConfig.endpoints, Peer.endpoints of control.options)

// The relays of a node and the Signals of its peers (CORE-S5-5, #411)
#define CONTROL_MAX_RELAYS   8    // The Relay objects of a state that the node takes, the first by name (PEER_MAX_RELAYS of Core/Peer.h)
#define CONTROL_MAX_ENVELOPE 1024 // The envelope of a Signal (Signal.envelope of control.options; PEER_MAX_ENVELOPE)
#define CONTROL_MAX_SIGNALS  64   // The Signals that wait for the stream at most; the oldest goes first, as at the controller

// The TLS fingerprints of the certificate of the Controller that a state names (SDN-92, #397)
#define CONTROL_TLS_PINS     4  // The fingerprints of a state (NodeConfig.controller_tls of control.options)
#define CONTROL_TLS_PIN_SIZE 65 // A fingerprint: 64 hex digits and the terminating NUL

// The Listener of a node (SDN-45, #238): the source of its certificate, and the sizes of its fields (control.options)
#define CONTROL_CERT_NONE       0   // No source: the node listens on no port of its own
#define CONTROL_CERT_FILE       1   // A PKCS #12 file on the node (CertificateFile)
#define CONTROL_CERT_KSP        2   // A certificate of the LocalMachine\My store by its thumbprint (Listener.ksp)
#define CONTROL_CERT_ACME       3   // A certificate that an ACME service issues (CertificateAcme)
#define CONTROL_PATH_SIZE       260 // A path of a file of the node with its terminating NUL (CertificateFile.path)
#define CONTROL_URL_SIZE        256 // The URL of an ACME directory with its terminating NUL (CertificateAcme.directory)
#define CONTROL_EMAIL_SIZE      128 // The contact of an ACME account with its terminating NUL (CertificateAcme.email)
#define CONTROL_ACME_NAMES      4   // The DNS names of a certificate of ACME (CertificateAcme.names) ...
#define CONTROL_ACME_NAME_SIZE  254 // ... each with its terminating NUL
#define CONTROL_THUMBPRINT_SIZE 41  // A thumbprint of 40 hex digits with its terminating NUL (Listener.ksp)

// The Listener of the node (Listener of the control protocol; SDN-45, #238; ADR-0035): the front door on the TCP port,
// which hands each connection of the new protocol to the node's TLS, and QUIC on the UDP port, both with the certificate
// of the source. The TLS policy of each surface is fixed in the node: TLS 1.3 for the new protocol.
typedef struct CONTROL_LISTENER {
	// The Listener resource
	char Name[CONTROL_NAME_SIZE];
	// The TCP port of the front door and the UDP port of QUIC
	UINT Port;
	UINT QuicPort;
	// The source of the certificate (CONTROL_CERT_*)
	UINT Source;
	// FILE: the PKCS #12 file, and the file that holds its password, "" for none
	char Path[CONTROL_PATH_SIZE];
	char PasswordFile[CONTROL_PATH_SIZE];
	// KSP: the thumbprint of the certificate in the LocalMachine\My store
	char Thumbprint[CONTROL_THUMBPRINT_SIZE];
	// ACME: the URL of the directory, the contact of the account ("" for none) and the DNS names of the certificate
	char Directory[CONTROL_URL_SIZE];
	char Email[CONTROL_EMAIL_SIZE];
	UINT NumNames;
	char Names[CONTROL_ACME_NAMES][CONTROL_ACME_NAME_SIZE];
	// ... the TCP port of the HTTP-01 challenge, the roots of a private service ("" for the system's), and the days before
	// its end at which the node renews the certificate
	UINT HttpPort;
	char CaFile[CONTROL_PATH_SIZE];
	UINT RenewDays;
} CONTROL_LISTENER;

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

// An IP prefix of a rule (Prefix of the control protocol)
typedef struct CONTROL_PREFIX {
	UCHAR Address[16]; // The prefix: 4 bytes for IPv4, 16 for IPv6
	UINT AddressSize;  // ... their number
	UINT Length;       // ... and its length
} CONTROL_PREFIX;

// An end of the flows of a rule (RuleEnd of the control protocol): a node or a peer with one of the tags, any without
// one, whose address is in one of the prefixes, any without one
typedef struct CONTROL_RULE_END {
	UINT NumTags;                                      // The tags
	char Tags[CONTROL_RULE_VALUES][CONTROL_NAME_SIZE]; // ...
	UINT NumPrefixes;                                  // The prefixes
	CONTROL_PREFIX Prefixes[CONTROL_RULE_VALUES];      // ...
} CONTROL_RULE_END;

// A rule of the policy of a VRF that the node enforces (Rule of the control protocol; SDN-8, #184): it matches the flows
// from its From end to its To end, of its protocol, to one of its ports
typedef struct CONTROL_RULE {
	char Name[CONTROL_NAME_SIZE];        // Its name, the Policy of the intent
	UINT VrfId;                          // Its VRF
	UINT Priority;                       // Its priority: the lowest is judged first
	bool Deny;                           // It denies the flows it matches; else it allows them
	CONTROL_RULE_END From;               // The end that opens a flow
	CONTROL_RULE_END To;                 // ... and the other end
	UINT Protocol;                       // The IP protocol, 0 for any; 1 (ICMP) takes ICMPv6 in IPv6 packets
	UINT NumPorts;                       // The destination ports of TCP or UDP, none for any ...
	UINT FirstPort[CONTROL_RULE_VALUES]; // ... the first of each range
	UINT LastPort[CONTROL_RULE_VALUES];  // ... and the last
} CONTROL_RULE;

// A prefix of a VRF that leads to a peer besides its addresses (Route of the control protocol): the outside prefix
// of a 1:1 NAT rule of the peer, or a route that a VRF of the peer leaks into the VRF (SDN-7, #183)
typedef struct CONTROL_ROUTE {
	UINT VrfId;        // The VRF
	UCHAR Address[16]; // The prefix: 4 bytes for IPv4, 16 for IPv6
	UINT AddressSize;  // ... their number
	UINT Length;       // ... and its length
	UINT PeerVrfId;    // The VRF of the peer that a packet on the route goes into, 0 for VrfId itself
} CONTROL_ROUTE;

// An endpoint of a node or of a peer (Endpoint of the control protocol; SDN-93, #410): an address under which the other
// nodes reach it, over one transport
typedef struct CONTROL_ENDPOINT {
	// The transport, as a fallback list names it: quic, tls or mimic (the names of the transports in Core/Transport.h)
	char Transport[TRANSPORT_NAME_SIZE];
	// The address that the transport dials: host:port, with an IPv6 host in brackets
	char Address[TRANSPORT_ADDRESS_SIZE];
} CONTROL_ENDPOINT;

// A relay that the node may use (Relay of the control protocol; CORE-S5-5, #411): another node with the relay role that
// shares a VRF with it, which binds the node and forwards its datagrams to the peers bound to it (ADR-0015)
typedef struct CONTROL_RELAY {
	char Name[CONTROL_NAME_SIZE]; // Its node name
	UCHAR Key[NOISE_KEY_SIZE];    // Its static key
	UCHAR Address[16];            // The address that its relay role listens on: 4 bytes for IPv4, 16 for IPv6
	UINT AddressSize;             // ... their number
	UINT Port;                    // ... and its UDP port
} CONTROL_RELAY;

// The kinds of a link between the nodes of a VRF (LinkKind of the control protocol; SDN-76, #356)
#define CONTROL_LINK_NOISE  0 // The Noise session over QUIC or TLS
#define CONTROL_LINK_VXLAN  1 // Plain VXLAN between the tunnel endpoints of two nodes, on a network that the operator trusts
#define CONTROL_LINK_GENEVE 2 // ... or plain Geneve

// The tunnel endpoint of a node or of a peer for the links of kind vxlan and geneve (Vtep of the control protocol;
// SDN-76, #356)
typedef struct CONTROL_VTEP {
	UCHAR Address[16]; // Its address: 4 bytes for IPv4, 16 for IPv6
	UINT AddressSize;  // ... their number, 0 for none: the node itself, or a peer that shares no such VRF
	UINT VxlanPort;    // The UDP port of VXLAN, 0 for the default (VXLAN_PORT of Core/Vxlan.h)
	UINT GenevePort;   // The UDP port of Geneve, 0 for the default (GENEVE_PORT)
} CONTROL_VTEP;

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
	UINT NumTags;                                     // Its tags, which identify it to the rules (SDN-8, #184)
	char Tags[CONTROL_MAX_TAGS][CONTROL_NAME_SIZE];   // ... sorted

	// The endpoints that the node dials the peer at (SDN-93, #410), in the order of the peer's Node resource, which is the
	// order of the race: none for a peer that the node does not dial
	UINT NumEndpoints;
	CONTROL_ENDPOINT Endpoints[CONTROL_MAX_ENDPOINTS];

	// Its tunnel endpoint (SDN-76, #356): the only address that the node takes the datagrams of a link of kind vxlan or
	// geneve of a shared VRF from
	CONTROL_VTEP Vtep;
} CONTROL_PEER;

// A name of the zone of a VRF and the addresses that it answers (DnsRecord of the control protocol; SDN-11, #187)
typedef struct CONTROL_DNS_RECORD {
	char Name[CONTROL_DNS_NAME_SIZE];               // The name, relative to the suffix of the zone
	UINT NumAddresses;                              // Its addresses
	UCHAR Addresses[CONTROL_MAX_DNS_ADDRESSES][16]; // ... 4 bytes for IPv4, 16 for IPv6
	UINT AddressSizes[CONTROL_MAX_DNS_ADDRESSES];   // ... the number of the bytes of each
} CONTROL_DNS_RECORD;

// The zone of overlay DNS of a VRF (DnsZone of the control protocol; SDN-11, #187): its suffix and the DnsRecord
// resources of the VRF. The name of each node of the VRF answers that node's addresses there, which the state holds.
typedef struct CONTROL_DNS_ZONE {
	char Suffix[CONTROL_DNS_NAME_SIZE];                  // The suffix, without a dot at either end
	UINT NumRecords;                                     // The records
	CONTROL_DNS_RECORD Records[CONTROL_MAX_DNS_RECORDS]; // ... in name order
} CONTROL_DNS_ZONE;

// A VRF that the node is a member of (Vrf of the control protocol): the MTU and the rate limit of
// the overlay in it (SDN-20, #196)
typedef struct CONTROL_VRF {
	char Name[CONTROL_NAME_SIZE]; // Its name
	UINT Id;                      // Its id
	UINT Mtu;                     // Its MTU
	UINT64 RateLimit;             // Bits per second that each node sends in it, 0 for no limit
	bool Policy;                  // It has its policy (SDN-8, #184): the node enforces its rules, default deny
	UINT MaxFlows;                // ... its conntrack quota, 0 for the default of the node
	UINT TcpEstablished;          // ... and the timeouts of its flows in s, 0 for the default of the node: TCP after
	UINT TcpTransitory;           // ... the handshake, TCP while it opens or closes,
	UINT Udp;                     // ... UDP,
	UINT Icmp;                    // ... an ICMP echo
	UINT Other;                   // ... and another IP protocol
	CONTROL_DNS_ZONE *Dns;        // Its zone of overlay DNS (SDN-11, #187), NULL while overlay DNS is off in it; valid as the state is
	UINT Link;                    // The kind of the links between its nodes (CONTROL_LINK_*; SDN-76, #356) ...
	UINT Vni;                     // ... and the VNI of a link of kind vxlan or geneve
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

// A WireGuard Device of a VRF of the node (Device of the control protocol; SDN-80, #375): a phone, a laptop or a router
// that joins one Network over standard WireGuard through its gateway node. Its addresses and its tags identify it to the
// rules; a packet to one of its addresses goes to its gateway, and the gateway delivers it to its host, where its
// WireGuard interface takes it. HasKey: the state is the one of its gateway, which terminates it with Key.
typedef struct CONTROL_DEVICE {
	// Its name, and the VRF of its Network
	char Name[CONTROL_NAME_SIZE];
	UINT VrfId;
	// Its addresses in its Network: IPv4, then IPv6, each with the length of a host
	UINT NumAddresses;
	CONTROL_ADDRESS Addresses[CONTROL_DEVICE_ADDRESSES];
	// Its tags, sorted, which identify it to the rules
	UINT NumTags;
	char Tags[CONTROL_MAX_TAGS][CONTROL_NAME_SIZE];
	// The node that terminates it
	char Gateway[CONTROL_NAME_SIZE];
	// The node is its gateway, and Key is its WireGuard public key
	bool HasKey;
	UCHAR Key[NOISE_KEY_SIZE];
} CONTROL_DEVICE;

// The WireGuard end of one Device at its gateway, as the gateway reports it (DeviceCounters of the control protocol):
// its last handshake in Unix time in ms (0 before the first), the bytes that the gateway sent it and the bytes that the
// gateway received from it
typedef struct CONTROL_DEVICE_COUNTERS {
	char Name[CONTROL_NAME_SIZE];
	UINT64 LastHandshake;
	UINT64 TxBytes;
	UINT64 RxBytes;
} CONTROL_DEVICE_COUNTERS;

// The counters of the Devices that a client reports to the controller (CONTROL_CONFIG.Devices), ControlDevice.c
typedef struct CONTROL_DEVICES CONTROL_DEVICES;

// Takes a Signal that the controller carried from the peer of the node name peer (CORE-S5-5, #411): its envelope of size
// bytes, sealed to the node, which only the node's peer layer opens. It runs on the client's thread; the envelope is
// valid until it returns.
typedef void(CONTROL_SIGNAL_PROC)(void *param, const char *peer, const UCHAR *envelope, UINT size);

// The Signals that a client sends to the controller for the peers of the node (CONTROL_CONFIG.Signals), ControlSignal.c
typedef struct CONTROL_SIGNALS CONTROL_SIGNALS;

// The desired state that the client applied, as its owner takes it (CONTROL_STATE_PROC). The
// Networks of the state stay in the client until a module of the node needs them: the DHCP
// responders of the Networks are the first (SDN-43, #236). The Relays go to the peer agent of the
// node (CORE-S5-5, #411).
typedef struct CONTROL_STATE {
	UINT64 Generation;                                // The Generation of the state
	char Name[CONTROL_NAME_SIZE];                     // The node's name in the intent
	UINT NumAddresses;                                // Its addresses in the L3 Networks of its VRFs
	CONTROL_ADDRESS Addresses[CONTROL_MAX_ADDRESSES]; // ... ordered by Network name
	UINT64 RateLimit;                                 // Bits per second that it sends into the overlay, 0 for no limit
	UINT NumNats;                                     // The 1:1 NAT rules that it applies, its 4via6 among them
	CONTROL_NAT Nats[CONTROL_MAX_NATS];               // ... ordered by VRF id
	UINT NumTags;                                     // Its tags, which identify it to the rules (SDN-8, #184)
	char Tags[CONTROL_MAX_TAGS][CONTROL_NAME_SIZE];   // ... sorted
	UINT NumRules;                                    // The rules of the policy of its VRFs that it enforces
	CONTROL_RULE *Rules;                              // ... in name order
	UINT NumVrfs;                                     // The VRFs it is a member of
	CONTROL_VRF Vrfs[CONTROL_MAX_VRFS];               // ... in name order
	UINT NumPeers;                                    // Its peers
	CONTROL_PEER *Peers;                              // ... in name order
	UINT NumMirrors;                                  // The Mirrors that it applies (SDN-23, #199)
	CONTROL_MIRROR Mirrors[CONTROL_MAX_MIRRORS];      // ... in name order
	UINT NumDhcps;                                    // The DHCP responders that it runs (SDN-43, #236)
	CONTROL_DHCP Dhcps[CONTROL_MAX_DHCPS];            // ... in Network name order

	// Its Listener (SDN-45, #238), NULL for none: then it listens on no port of its own. Valid as the state is.
	CONTROL_LISTENER *Listener;

	// The UDP port of its WireGuard interface, 0 when it is the gateway of no Device, and the WireGuard Devices of its
	// VRFs in name order (SDN-80, #375)
	UINT WireGuardPort;
	UINT NumDevices;
	CONTROL_DEVICE *Devices;

	// Its own endpoints (SDN-93, #410), in the order of its Node resource: none when it names none, so that no peer can dial
	// it and it dials them
	UINT NumEndpoints;
	CONTROL_ENDPOINT Endpoints[CONTROL_MAX_ENDPOINTS];

	// The TLS fingerprints of the certificate of the Controller that the node accepts (SDN-92, #397), as the Controller sent
	// them: 64 hex digits each, in lower case, the certificate in use first. There are none while the Controller sent none:
	// the node then keeps the fingerprint it has. Valid as the state is.
	UINT NumTlsPins;
	char TlsPins[CONTROL_TLS_PINS][CONTROL_TLS_PIN_SIZE];

	// Its tunnel endpoint for the links of kind vxlan and geneve (SDN-76, #356): the ports it listens on
	CONTROL_VTEP Vtep;

	// The relays that it may use (CORE-S5-5, #411), in name order: the first is its home relay. None while no node with the
	// relay role shares a VRF with it.
	UINT NumRelays;
	CONTROL_RELAY Relays[CONTROL_MAX_RELAYS];
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
	// wireguard.dll of WireGuardNT loads, so the node can be the gateway of WireGuard Devices (SDN-80, #375) ...
	bool WireGuard;
	// ... and the public key of its WireGuard interface
	UCHAR WireGuardKey[NOISE_KEY_SIZE];
	// The node runs the links of kind vxlan and geneve (SDN-76, #356)
	bool PlainLinks;
} CONTROL_CAPS;

// Fills caps, which is zeroed, with the Capabilities of the node. The client calls it for each Hello, so a node
// whose Capabilities changed tells the controller by its next stream. It runs on the client's thread.
typedef void(CONTROL_CAPS_PROC)(void *param, CONTROL_CAPS *caps);

// How the last stream of a client ended, or why it did not open (CONTROL_STATUS.LastEnd; SDN-90, #395)
#define CONTROL_END_NONE      0 // No stream ended yet
#define CONTROL_END_DIAL      1 // The transport did not connect: no controller answered, or its TLS session or certificate failed
#define CONTROL_END_HANDSHAKE 2 // The Noise handshake failed: the controller does not hold the static key the node knows
#define CONTROL_END_REFUSED   3 // The controller refused the node (LastRefuse, LastMessage)
#define CONTROL_END_CLOSED    4 // The stream ended after it was open: the controller or the network went

// Takes how a stream ended or why it did not open (LastEnd) and the delay before the next attempt (NextRetry), on the
// client's thread; a client that halts calls it no more
struct CONTROL_STATUS;
typedef void(CONTROL_END_PROC)(void *param, const struct CONTROL_STATUS *st);

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
	CONTROL_END_PROC *EndProc;            // Takes the end of each stream, NULL for none (SDN-90, #395) ...
	void *EndParam;                       // ... and its first parameter

	// Tells the Capabilities of the node for each Hello, NULL for none: the Hello then holds none
	CONTROL_CAPS_PROC *CapsProc;
	// The first parameter of CapsProc
	void *CapsParam;

	// The counters of the WireGuard Devices that the client reports, NULL for none: the owner's, which must outlive the
	// client (SDN-80, #375)
	CONTROL_DEVICES *Devices;

	// Takes each Signal that the controller carried from a peer, NULL to drop them (CORE-S5-5, #411) ...
	CONTROL_SIGNAL_PROC *SignalProc;
	// ... and its first parameter
	void *SignalParam;
	// The Signals that the client sends to the controller for the peers of the node, NULL for none: the owner's, which must
	// outlive the client
	CONTROL_SIGNALS *Signals;
} CONTROL_CONFIG;

// How a client stands (ControlGetStatus)
typedef struct CONTROL_STATUS {
	bool Connected;        // A stream is open: the handshake passed and the Hello went out ...
	UINT64 Since;          // ... since this GetTickCount64, or the last one was (SDN-91, #396)
	UINT64 Applied;        // The Generation applied last, 0 before the first
	UINT64 NumStreams;     // Streams whose handshake passed so far
	UINT64 NumUpdates;     // Updates applied so far
	UINT LastRefuse;       // The reason of the last Refuse (RefuseReason of the control protocol), 0 for none
	char LastMessage[256]; // ... and its message
	UINT LastEnd;          // How the last stream ended or why it did not open (CONTROL_END_*)
	UINT NextRetry;        // ms before the next attempt after it: the delay grows while the attempts fail (ControlRetry.c)
} CONTROL_STATUS;

// The client of one node, Control.c
typedef struct CONTROL_CLIENT CONTROL_CLIENT;

// Start starts a client on a thread of its own, which opens the stream at once: NULL when the
// configuration is not complete or the thread cannot start. Stop ends the stream and the thread
// and frees the client. GetStatus tells how the client stands.
CONTROL_CLIENT *ControlStart(const CONTROL_CONFIG *cfg);
void ControlStop(CONTROL_CLIENT *c);
void ControlGetStatus(CONTROL_CLIENT *c, CONTROL_STATUS *st);

// A client without its thread and its stream, for the fuzz target of the control stream (src/fuzz/fuzz_control.c;
// AUD1-DT-12, #460). New makes a client as Start does but starts no thread: NULL when the configuration is not complete.
// Input takes the message of one frame of the controller, size bytes at data after the size of the frame, as the stream
// of the client takes it, but sends no Ack: the client decodes it with nanopb, applies an Update to the objects that it
// holds and hands them to the owner (Proc), and notes a Refuse in its status. It gives false for a message that ends the
// stream: a Refuse, a message that does not decode or does not apply, and one that only a node sends. Free frees a
// client of New.
CONTROL_CLIENT *ControlNew(const CONTROL_CONFIG *cfg);
bool ControlInput(CONTROL_CLIENT *c, const UCHAR *data, UINT size);
void ControlFree(CONTROL_CLIENT *c);

// The delay before a client opens its stream again (ControlRetry.c; SDN-90, #395), from the delay before and how the last
// stream ended (CONTROL_END_*): CONTROL_RETRY after a stream that was open and not refused, else twice the delay before,
// from CONTROL_RETRY up to CONTROL_RETRY_MAX
UINT ControlRetryNext(UINT delay, UINT end);

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

// The counters of the WireGuard Devices of a gateway (SDN-80, #375), ControlDevice.c. NewDevices makes the report that a
// client sends (CONTROL_CONFIG.Devices), FreeDevices frees it once no client uses it. SetDevices puts the counters of num
// Devices, CONTROL_MAX_DEVICES at most, in place of the ones before, and the client sends them in one Telemetry message
// after each Hello and whenever they changed, at most every CONTROL_DEVICE_REPORT ms. WriteDevices writes that message
// when it is due, as the client does on its stream.
CONTROL_DEVICES *ControlNewDevices();
void ControlFreeDevices(CONTROL_DEVICES *d);
void ControlSetDevices(CONTROL_DEVICES *d, const CONTROL_DEVICE_COUNTERS *counters, UINT num);
bool ControlWriteDevices(CONTROL_DEVICES *d, TRANSPORT_STREAM *s);

// The Signals of a node (CORE-S5-5, #411), ControlSignal.c. NewSignals makes the queue that a client sends
// (CONTROL_CONFIG.Signals), FreeSignals frees it once no client uses it. SendSignal queues a Signal for the peer of the
// node name peer, with its envelope of 1 to CONTROL_MAX_ENVELOPE bytes: the client writes it on its stream at once while
// one is open, else on the next one, and at most CONTROL_MAX_SIGNALS wait, a full queue dropping its oldest. WriteSignals
// writes the Signals that wait, each as one frame, as the client does on its stream.
CONTROL_SIGNALS *ControlNewSignals();
void ControlFreeSignals(CONTROL_SIGNALS *q);
bool ControlSendSignal(CONTROL_SIGNALS *q, const char *peer, const UCHAR *envelope, UINT size);
bool ControlWriteSignals(CONTROL_SIGNALS *q, TRANSPORT_STREAM *s);

#endif // CORE_CONTROL_H
