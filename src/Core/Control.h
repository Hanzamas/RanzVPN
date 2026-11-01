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

// The Paths of the peer agent of a node (CORE-S5-6, #412)
#define CONTROL_PATH_REPORT  1000  // ms between two reports of the Upgrades and the Fallbacks of the Paths of a node, at least ...
#define CONTROL_PATH_REFRESH 15000 // ... and at most, while they stay the same: the controller drops a counter that its node does not report again

// The EVPN of a gateway (SDN-25-R3, #571)
#define CONTROL_EVPN_REPORT  CONTROL_PATH_REPORT  // ms between two reports of the counters of the EVPN of a gateway, at least ...
#define CONTROL_EVPN_REFRESH CONTROL_PATH_REFRESH // ... and at most, while they stay the same, as for the Paths

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
#define CONTROL_DECOY_SIZE      48  // The decoy of a Listener, a loopback address and a port, with its terminating NUL (NodeConfig.listener_decoy)

// The Listener of the node (Listener of the control protocol; SDN-45, #238; ADR-0035): the front door on the TCP port,
// which hands each connection of the new protocol to the node's TLS, and QUIC on the UDP port, both with the certificate
// of the source. The TLS policy of each surface is fixed in the node: TLS 1.3 for the new protocol.
typedef struct CONTROL_LISTENER {
	// The Listener resource
	char Name[CONTROL_NAME_SIZE];
	// The TCP port of the front door and the UDP port of QUIC
	UINT Port;
	UINT QuicPort;
	// The decoy of the TLS of the new protocol (AUD1-DT-4, #452): the loopback address and port of a site on the node, "" for none
	char Decoy[CONTROL_DECOY_SIZE];
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

// The BGP peering of the standard mode (SDN-77, #357): the sizes of control.options
#define CONTROL_MAX_ANNOUNCE       16   // The LAN subnets that a node announces (NodePeering.announce)
#define CONTROL_MAX_ACCEPT         32   // What a peer may announce: its addresses and its LAN subnets (PeerPeering.accept)
#define CONTROL_MAX_PEERING_PEERS  64   // The peers of the sidecar of a node that one report holds (PeeringReport.peers)
#define CONTROL_MAX_LEARNED        32   // The prefixes learned from one peer that a report holds (PeeringPeer.learned)
#define CONTROL_PEERING_STATE_SIZE 16   // The state of a session with its NUL (PeeringPeer.state)
#define CONTROL_PEERING_INTERVAL   1000 // ms between two reports of the peering of a node at least

// The BGP peering of a node (NodePeering of the control protocol; SDN-77, #357): the settings of its sidecar ranz bgp, which
// listens on TCP 179 of Address and connects from it, and the LAN subnets that the node announces besides its addresses in
// the VRFs that peer by BGP (CONTROL_VRF.Peering)
typedef struct CONTROL_PEERING {
	UINT Asn;                                     // The AS of the overlay, one for every node: the sessions are internal BGP
	UCHAR RouterId[4];                            // Its BGP identifier
	UCHAR Address[16];                            // Its address on the network that the operator trusts: 4 bytes for IPv4, 16 for IPv6
	UINT AddressSize;                             // ... their number
	UINT NumAnnounce;                             // The LAN subnets that it announces
	CONTROL_ROUTE Announce[CONTROL_MAX_ANNOUNCE]; // ... ordered by VRF id, then prefix
} CONTROL_PEERING;

// The BGP peering with a peer (PeerPeering of the control protocol; SDN-77, #357) in the VRFs that the two share and that peer
// by BGP: the address of the sidecar of the peer, the only address that the sidecar of the node takes a session from, and what
// the peer may announce there, with their more specific ones
typedef struct CONTROL_PEER_PEERING {
	UCHAR Address[16];                        // The address of the sidecar of the peer: 4 bytes for IPv4, 16 for IPv6
	UINT AddressSize;                         // ... their number
	UINT HoldTime;                            // The BGP hold time of the session in seconds, 0 for 90
	UINT NumVrfs;                             // The VRFs of the session
	UINT VrfIds[CONTROL_MAX_VRFS];            // ... ascending
	UINT NumAccept;                           // What the peer may announce in them: its addresses and its LAN subnets
	CONTROL_ROUTE Accept[CONTROL_MAX_ACCEPT]; // ... ordered by VRF id, then prefix
} CONTROL_PEER_PEERING;

// One peer of the sidecar of a node, as the node reports it (PeeringPeer of the control protocol; SDN-77, #357)
typedef struct CONTROL_PEERING_PEER {
	UCHAR Address[16];                          // The address of the sidecar of the peer: 4 bytes for IPv4, 16 for IPv6
	UINT AddressSize;                           // ... their number
	char State[CONTROL_PEERING_STATE_SIZE];     // The state of the session: idle, connect, active, opensent, openconfirm or established
	UINT NumLearned;                            // The prefixes that the node learned from it
	CONTROL_ROUTE Learned[CONTROL_MAX_LEARNED]; // ... each with its VRF, ordered by VRF id, then prefix
} CONTROL_PEERING_PEER;

// The report of the BGP peering of a node that a client sends to the controller (CONTROL_CONFIG.Peering), ControlPeering.c
typedef struct CONTROL_PEERING_REPORT CONTROL_PEERING_REPORT;

// The session profile of a device (SessionProfile of the control protocol; SDN-40, #233): the limits of the sessions of the
// devices of a User, the effective SessionProfile of the User that owns the node. A node enforces the profile of a peer on
// its session with the peer, and the flags of its own profile on itself (Cedar/NodeProfile.c). A limit of 0 is none.
typedef struct CONTROL_PROFILE {
	bool Set;                     // The device runs under a profile, which the fields below hold; else they are 0
	char Name[CONTROL_NAME_SIZE]; // The SessionProfile
	char User[CONTROL_NAME_SIZE]; // The User that owns the device: the sessions of its devices count together
	UINT64 UploadLimit;           // Bits per second that a node takes from the session of the device at most ...
	UINT64 DownloadLimit;         // ... and that it sends to it at most
	UINT MaxSessions;             // The sessions of the devices of the User that a node holds at once
	UINT MaxMacs;                 // The MAC addresses that one session sends from in an L2 Network
	UINT MaxIpv4;                 // The IPv4 addresses that one session sends from in each VRF ...
	UINT MaxIpv6;                 // ... and the IPv6 addresses
	UINT IdleTimeout;             // s without a packet in either direction after which a node ends the session
	UINT AutoDisconnect;          // s after the session came up after which a node ends it
	bool NoBridge;                // One MAC address in an L2 Network: the first that the session sends from
	bool NoRouting;               // The device sends from and takes at its own addresses only, IPv4 and IPv6
	bool NoServer;                // No TCP connection to the device, IPv4 and IPv6: no SYN to it, no SYN-ACK from it
	bool PrivacyFilter;           // No packet between two devices whose profiles both have it
} CONTROL_PROFILE;

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

	// The controller reports it down (SDN-19, #195): it is a gateway of a prefix that another gateway announces too, and it
	// has had no control stream for a while, so the node gives that prefix to another gateway that answers its probes
	bool Down;

	// The BGP peering with it (SDN-77, #357), NULL while no VRF that it shares with the node peers by BGP. Valid as the
	// state is.
	CONTROL_PEER_PEERING *Peering;

	// The session profile that it runs under as a device of a User (SDN-40, #233), which the node enforces on its session
	// with it; not Set for none
	CONTROL_PROFILE Profile;
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
	char Hub[CONTROL_NAME_SIZE];  // The hub node of a VRF of topology hub-and-spoke (SDN-19, #195), "" for a full mesh
	bool Ecmp;                    // The flows to a prefix of several gateways spread over the healthy ones (SDN-19, #195)
	bool Peering;                 // Its nodes exchange their routes by BGP (SDN-77, #357)
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

// The security of the L2 Networks (SDN-41, #234)
#define CONTROL_MAX_SECURITIES 16 // The L2 Networks of a node that have one
#define CONTROL_MAX_GATEWAYS   8  // The gateways of one (L2Security.gateways of control.options)

// The security of an L2 Network of the node (L2Security of the control protocol; SDN-41, #234): the protections that the
// switch of the Network applies to the frames of its clients (Core/SwitchSecurity.h), and the nodes of its gateways, whose
// ports are no clients. Every node of the VRF of the Network has it.
typedef struct CONTROL_SECURITY {
	char Network[CONTROL_NAME_SIZE];                        // The L2 Network
	UINT VrfId;                                             // ... and its VRF
	bool CheckMac;                                          // A client sends from MAC addresses of its own only ...
	bool CheckIp;                                           // ... and from IP addresses of its own only
	UINT MaxMacs;                                           // The MAC addresses that a client owns under CheckMac, 0 while it is off
	UINT MaxIps;                                            // ... and the IP addresses under CheckIp
	bool ArpDhcpOnly;                                       // Frames of a client to a group address and to it from one: ARP, DHCP and neighbour discovery only
	bool DhcpGuard;                                         // No DHCP or DHCPv6 server messages from a client
	bool RaGuard;                                           // No IPv6 router advertisements from a client
	UINT NumGateways;                                       // The nodes of the gateways
	char Gateways[CONTROL_MAX_GATEWAYS][CONTROL_NAME_SIZE]; // ... in name order
} CONTROL_SECURITY;

// A WireGuard Device of a VRF of the node (Device of the control protocol; SDN-80, #375): a phone, a laptop or a router
// that joins one Network over standard WireGuard through its gateway node. Its addresses and its tags identify it to the
// rules; a packet to one of its addresses goes to its gateway, and the gateway delivers it to its host, where its
// WireGuard interface takes it. HasKey: the state is the one of its gateway, which terminates it with Key, and with
// Preshared when HasPreshared (the PresharedKey of the Device, SDN-82 #377).
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
	// The Device has a PresharedKey, a secret that the gateway hands to its WireGuard interface and never logs
	bool HasPreshared;
	UCHAR Preshared[NOISE_KEY_SIZE];
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

// The events of the node itself that a client reports to the controller (NodeEvent of the control protocol, ADR-0030 decision
// 5; AUD1-DT-11, #459), ControlEvent.c. The types are the values of NodeEventType: a node reports one only for a type that
// it names here, and a controller that does not know a type skips it
#define CONTROL_EVENT_SESSION_FLAP 2   // Two holders of one key replace the session of a peer again and again (NS-12)
#define CONTROL_EVENT_SUBJECT_SIZE 64  // The subject of an event with its NUL (NodeEvent.subject of control.options)
#define CONTROL_EVENT_MESSAGE_SIZE 256 // ... and its message (NodeEvent.message)
#define CONTROL_MAX_EVENTS         8   // The events that one Telemetry message holds (Telemetry.events of control.options)
#define CONTROL_EVENT_QUEUE        64  // The events that wait for a stream at most: a new one takes the place of the oldest

typedef struct CONTROL_EVENT {
	UINT Type;                                // CONTROL_EVENT_*
	char Subject[CONTROL_EVENT_SUBJECT_SIZE]; // What it is about: the peer of a session flap
	char Message[CONTROL_EVENT_MESSAGE_SIZE]; // What happened, in words for the operator
} CONTROL_EVENT;

// The events that wait for the controller (CONTROL_CONFIG.Events), ControlEvent.c
typedef struct CONTROL_EVENTS CONTROL_EVENTS;

// Takes a Signal that the controller carried from the peer of the node name peer (CORE-S5-5, #411): its envelope of size
// bytes, sealed to the node, which only the node's peer layer opens. It runs on the client's thread; the envelope is
// valid until it returns.
typedef void(CONTROL_SIGNAL_PROC)(void *param, const char *peer, const UCHAR *envelope, UINT size);

// The Signals that a client sends to the controller for the peers of the node (CONTROL_CONFIG.Signals), ControlSignal.c
typedef struct CONTROL_SIGNALS CONTROL_SIGNALS;

// The Upgrades and the Fallbacks of the Paths of the peer agent that a client reports to the controller (CONTROL_CONFIG.Paths;
// CORE-S5-6, #412), ControlPath.c
typedef struct CONTROL_PATHS CONTROL_PATHS;

// The counters of the EVPN of a gateway that a client reports to the controller (CONTROL_CONFIG.Evpn; SDN-25-R3, #571),
// ControlEvpn.c
typedef struct CONTROL_EVPN CONTROL_EVPN;

// The frames of the EVPN of a gateway with the fabric since its sidecar started, as NODE_EVPN_STATUS of Cedar/NodeEvpn.h counts
// them (EvpnCounters of the control protocol)
typedef struct CONTROL_EVPN_COUNTERS {
	UINT64 Sent;        // Packets of the overlay sent to a VTEP of the fabric
	UINT64 Failed;      // ... that could not go
	UINT64 Delivered;   // Packets of the fabric that the overlay took
	UINT64 Undelivered; // ... that it did not take
	UINT64 UnknownVtep; // Frames of an L3 VNI from an address that is no VTEP that the gateway knows for their VRF
	UINT64 Strangers;   // Packets of a known VTEP from a source that no IP prefix route of their VRF holds
	UINT64 NotOurs;     // Frames of a known VTEP to another MAC address than the router MAC of the gateway
	UINT64 UnknownVni;  // Datagrams on a VNI of no EVPN VRF, from any address
	UINT64 Malformed;   // Datagrams of no VXLAN frame, from any address, and frames of a known VTEP without an IP packet
} CONTROL_EVPN_COUNTERS;

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

	// The security of its L2 Networks (SDN-41, #234), in Network name order: a Network without one has none. Valid as the
	// state is.
	UINT NumSecurities;
	CONTROL_SECURITY *Securities;

	// The relays that it may use (CORE-S5-5, #411), in name order: the first is its home relay. None while no node with the
	// relay role shares a VRF with it.
	UINT NumRelays;
	CONTROL_RELAY Relays[CONTROL_MAX_RELAYS];

	// The LAN subnets behind it, which it advertises as a gateway in its VRFs (SDN-19, #195): routes that lead to its host,
	// ordered by VRF id
	UINT NumLanSubnets;
	CONTROL_ROUTE LanSubnets[CONTROL_MAX_ROUTES];

	// Its BGP peering (SDN-77, #357), NULL while no VRF of the node peers by BGP. Valid as the state is.
	CONTROL_PEERING *Peering;

	// The session profile that it runs under as a device of a User (SDN-40, #233), whose flags it enforces on itself; not
	// Set for none
	CONTROL_PROFILE Profile;

	// The VRFs whose internet exit it is (SDN-12, #188), by id, in the order of its NodeConfig: none while it is the exit
	// of no VRF
	UINT NumEgress;
	UINT EgressVrfIds[CONTROL_MAX_VRFS];
} CONTROL_STATE;

// A copy of a state that holds its own memory, for an owner that applies the state again later (the BGP peering of the node,
// SDN-77, #357), and its free, ControlCopy.c. Each field of CONTROL_STATE that points at memory of its own is copied there, so
// a new such field is copied there too. NULL when there is no memory.
CONTROL_STATE *ControlCopyState(const CONTROL_STATE *st);
void ControlFreeStateCopy(CONTROL_STATE *st);

// Takes each state that the client applied, before the client acknowledges its Generation. It runs
// on the client's thread; state is valid until it returns.
typedef void(CONTROL_STATE_PROC)(void *param, const CONTROL_STATE *state);

// The architectures of the Capabilities (Architecture of the control protocol)
#define CONTROL_ARCHITECTURE_UNSPECIFIED 0
#define CONTROL_ARCHITECTURE_X64         1
#define CONTROL_ARCHITECTURE_ARM64       2

// The Windows editions of the Capabilities (Sku of the control protocol; SDN-12, #188)
#define CONTROL_SKU_UNSPECIFIED 0
#define CONTROL_SKU_HOME        1
#define CONTROL_SKU_PRO         2 // also Pro for Workstations and Pro Education
#define CONTROL_SKU_ENTERPRISE  3 // also Education and IoT Enterprise
#define CONTROL_SKU_SERVER      4

// The Egress tiers of the Capabilities (EgressTier of the control protocol; SDN-12, #188): how a node that is the internet
// exit of a VRF takes its traffic to the outside, the first that its host supports
#define CONTROL_EGRESS_NONE   0 // No tier reported
#define CONTROL_EGRESS_RRAS   1 // Tier 1: RRAS NAT on Windows Server
#define CONTROL_EGRESS_WINNAT 2 // Tier 2: WinNAT, where Hyper-V is present and no NetNat exists
#define CONTROL_EGRESS_PROXY  3 // Tier 3: a proxy on the Windows TCP/IP stack

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
	// The node runs the BGP peering of the standard mode: ranz.exe, which holds its sidecar, is next to it (SDN-77-R2, #532)
	bool BgpPeering;
	// The Windows edition of the host (CONTROL_SKU_*), whether Hyper-V is present on it, and the Egress tier that the host
	// gives the node as the internet exit of a VRF (CONTROL_EGRESS_*; SDN-12, #188)
	UINT Sku;
	bool HyperV;
	UINT EgressTier;
	// The node can be the gateway of a Stretch of an L2 Network (SDN-63, #290): its host is a Windows Server, and its VXLAN
	// module runs
	bool Evpn;
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

// The live operations of an operator on the tables of the L2 Networks (Operation and OperationResult of the control protocol;
// SDN-50-N, #492; ADR-0027 amendment of 2026-10-27), ControlOperation.c. The kinds are the values of OperationKind, the
// statuses those of OperationStatus.
#define CONTROL_OPERATION_MAC_TABLE       1   // Read the MAC table of the Network
#define CONTROL_OPERATION_CLEAR_MAC_TABLE 2   // ... clear it, or the entries of one MAC address
#define CONTROL_OPERATION_IP_TABLE        3   // Read the IP table of the Network
#define CONTROL_OPERATION_CLEAR_IP_TABLE  4   // ... clear it, or the entries of one address
#define CONTROL_OPERATION_OK              1   // The node did it
#define CONTROL_OPERATION_NO_NETWORK      2   // The node holds no L2 Network of that name
#define CONTROL_OPERATION_FAILED          3   // The node could not do it, and the message says why
#define CONTROL_MAX_ENTRIES               512 // The entries of a table that one answer lists (OperationResult.entries of control.options)
#define CONTROL_OPERATION_MESSAGE_SIZE    256 // Why an operation failed, with its terminating NUL (OperationResult.message)

// One live operation, as the client hands it to its owner
typedef struct CONTROL_OPERATION {
	UINT64 Id;                       // The id that the Controller gave it, which its answer carries
	UINT Kind;                       // What it asks: CONTROL_OPERATION_MAC_TABLE to CONTROL_OPERATION_CLEAR_IP_TABLE
	char Network[CONTROL_NAME_SIZE]; // The L2 Network, which the desired state gives the node
	bool HasMac;                     // A clear of the MAC table takes the entries of Mac alone, in every VLAN ...
	UCHAR Mac[6];                    // ...
	UINT AddressSize;                // ... and a clear of the IP table those of Address alone: 4 for IPv4, 16 for IPv6, 0 for every entry
	UCHAR Address[16];               // ...
} CONTROL_OPERATION;

// One entry of a table that the answer lists (TableEntry of the control protocol)
typedef struct CONTROL_TABLE_ENTRY {
	UINT Vlan;                      // Its VLAN
	UCHAR Mac[6];                   // Its MAC address
	UINT AddressSize;               // The IP table: its address, 4 bytes for IPv4 and 16 for IPv6 ...
	UCHAR Address[16];              // ...
	char Member[CONTROL_NAME_SIZE]; // The member of the Network that it belongs to: a peer, a session or a port; "" for none
	UINT64 LastSeen;                // The time of the last frame from it: Unix time in ms, 0 for none
} CONTROL_TABLE_ENTRY;

// The answer of the owner to one live operation
typedef struct CONTROL_OPERATION_RESULT {
	UINT Status;                                  // CONTROL_OPERATION_OK, CONTROL_OPERATION_NO_NETWORK or CONTROL_OPERATION_FAILED
	char Message[CONTROL_OPERATION_MESSAGE_SIZE]; // Why it failed, or a note on the answer; "" for none
	UINT Total;                                   // A read: the entries that the table holds; a clear: the entries that it took out
	UINT NumEntries;                              // A read: the first entries of the table by VLAN, then by address ...
	CONTROL_TABLE_ENTRY Entries[CONTROL_MAX_ENTRIES];
} CONTROL_OPERATION_RESULT;

// Does the live operation op on the L2 Network that it names, which the desired state that the client applied gives the node
// as an L2 Network, and puts its answer into res, which is zeroed. It runs on the client's thread, which answers the Operation
// when it returns: the Controller waits 10 s for it.
typedef void(CONTROL_OPERATION_PROC)(void *param, const CONTROL_OPERATION *op, CONTROL_OPERATION_RESULT *res);

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

	// The events of the node that the client reports, NULL for none: the owner's, which must outlive the client
	// (AUD1-DT-11, #459)
	CONTROL_EVENTS *Events;

	// Takes each Signal that the controller carried from a peer, NULL to drop them (CORE-S5-5, #411) ...
	CONTROL_SIGNAL_PROC *SignalProc;
	// ... and its first parameter
	void *SignalParam;
	// The Signals that the client sends to the controller for the peers of the node, NULL for none: the owner's, which must
	// outlive the client
	CONTROL_SIGNALS *Signals;

	// The report of the BGP peering of the node that the client sends, NULL for none: the owner's, which must outlive the
	// client (SDN-77, #357)
	CONTROL_PEERING_REPORT *Peering;

	// The Upgrades and the Fallbacks of the Paths of the peer agent that the client reports, NULL for none: the owner's, which
	// must outlive the client (CORE-S5-6, #412)
	CONTROL_PATHS *Paths;

	// The counters of the EVPN of a gateway that the client reports, NULL for none: the owner's, which must outlive the client
	// (SDN-25-R3, #571)
	CONTROL_EVPN *Evpn;

	// Does the live operations of the Controller on the tables of the L2 Networks, NULL for none: the Hello then reports no
	// Capability operations (SDN-50-N, #492) ...
	CONTROL_OPERATION_PROC *OperationProc;
	// ... and its first parameter
	void *OperationParam;
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
// holds and hands them to the owner (Proc), and notes a Refuse in its status. An Operation it does through the owner
// (OperationProc) and answers, but writes no answer either (SDN-50-N, #492). It gives false for a message that ends the
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

// The events of the node (AUD1-DT-11, #459), ControlEvent.c. NewEvents makes the queue that a client sends
// (CONTROL_CONFIG.Events), FreeEvents frees it once no client uses it. RaiseEvent puts one event of a type (CONTROL_EVENT_*)
// into it, with the subject and the message cut to their fields: false for no queue or no type. The client writes the
// events that wait as Telemetry messages of CONTROL_MAX_EVENTS each, on the stream that is open and after the Hello of the
// next stream when none is, so a node that was cut off from its controller reports what it saw once it is back; an event
// leaves the queue once its write succeeded. At most CONTROL_EVENT_QUEUE wait, and a new event above that takes the place of
// the oldest. GetEvents copies the events that wait, at most max, into list: their number. WriteEvents writes the first
// events that wait as one Telemetry message, as the client does on its stream.
CONTROL_EVENTS *ControlNewEvents();
void ControlFreeEvents(CONTROL_EVENTS *e);
bool ControlRaiseEvent(CONTROL_EVENTS *e, UINT type, const char *subject, const char *message);
UINT ControlGetEvents(CONTROL_EVENTS *e, CONTROL_EVENT *list, UINT max);
bool ControlWriteEvents(CONTROL_EVENTS *e, TRANSPORT_STREAM *s);

// The Signals of a node (CORE-S5-5, #411), ControlSignal.c. NewSignals makes the queue that a client sends
// (CONTROL_CONFIG.Signals), FreeSignals frees it once no client uses it. SendSignal queues a Signal for the peer of the
// node name peer, with its envelope of 1 to CONTROL_MAX_ENVELOPE bytes: the client writes it on its stream at once while
// one is open, else on the next one, and at most CONTROL_MAX_SIGNALS wait, a full queue dropping its oldest. WriteSignals
// writes the Signals that wait, each as one frame, as the client does on its stream.
CONTROL_SIGNALS *ControlNewSignals();
void ControlFreeSignals(CONTROL_SIGNALS *q);
bool ControlSendSignal(CONTROL_SIGNALS *q, const char *peer, const UCHAR *envelope, UINT size);
bool ControlWriteSignals(CONTROL_SIGNALS *q, TRANSPORT_STREAM *s);

// The report of the BGP peering of a node (SDN-77, #357), ControlPeering.c. NewPeeringReport makes the report that a client
// sends (CONTROL_CONFIG.Peering), FreePeeringReport frees it once no client uses it. SetPeeringReport puts the peers of the
// sidecar of the node, CONTROL_MAX_PEERING_PEERS at most, and the sessions that it refused since the node started, in place
// of the ones before, and the client sends them as the peering of one Telemetry message after each Hello and whenever they
// changed, at most every CONTROL_PEERING_INTERVAL ms. GetPeeringReport copies the peers that it holds, at most max, into list,
// and the refused sessions into refused: the number of the peers. WritePeeringReport writes that message when it is due, as
// the client does on its stream.
CONTROL_PEERING_REPORT *ControlNewPeeringReport();
void ControlFreePeeringReport(CONTROL_PEERING_REPORT *r);
void ControlSetPeeringReport(CONTROL_PEERING_REPORT *r, const CONTROL_PEERING_PEER *peers, UINT num, UINT64 refused);
UINT ControlGetPeeringReport(CONTROL_PEERING_REPORT *r, CONTROL_PEERING_PEER *list, UINT max, UINT64 *refused);
bool ControlWritePeeringReport(CONTROL_PEERING_REPORT *r, TRANSPORT_STREAM *s);

// The Paths of the peer agent of a node (CORE-S5-6, #412), ControlPath.c. NewPaths makes the report that a client sends
// (CONTROL_CONFIG.Paths), FreePaths frees it once no client uses it. SetPaths puts the Upgrades and the Fallbacks of the
// Paths of the node since it started in place of the ones before: the client sends them in one Telemetry message after
// each Hello once they were set, whenever they changed, at most every CONTROL_PATH_REPORT ms, and again every
// CONTROL_PATH_REFRESH ms while they stay the same, as the controller drops a counter that its node did not report for a
// while (5 minutes). WritePaths writes that message when it is due, as the client does on its stream. SetPunches puts the
// punches of the node since it started in the same message (CORE-S5-7, #413): its attempts at a direct path to a peer
// behind a symmetric NAT, the ones that met, and the ones whose prediction failed.
CONTROL_PATHS *ControlNewPaths();
void ControlFreePaths(CONTROL_PATHS *p);
void ControlSetPaths(CONTROL_PATHS *p, UINT64 upgrades, UINT64 fallbacks);
void ControlSetPunches(CONTROL_PATHS *p, UINT64 attempts, UINT64 successes, UINT64 failures);
bool ControlWritePaths(CONTROL_PATHS *p, TRANSPORT_STREAM *s);

// The EVPN of a gateway (SDN-25-R3, #571), ControlEvpn.c. NewEvpn makes the report that a client sends (CONTROL_CONFIG.Evpn),
// FreeEvpn frees it once no client uses it. SetEvpn puts the counters of the EVPN of the node in place of the ones before, or
// none for NULL while no EVPN runs: the client sends them in one Telemetry message after each Hello while they are set,
// whenever they changed, at most every CONTROL_EVPN_REPORT ms, and again every CONTROL_EVPN_REFRESH ms while they stay the
// same, as the controller drops a counter that its node did not report for a while (5 minutes). GetEvpn copies the counters
// that are set into c: false while none are. WriteEvpn writes that message when it is due, as the client does on its stream.
CONTROL_EVPN *ControlNewEvpn();
void ControlFreeEvpn(CONTROL_EVPN *e);
void ControlSetEvpn(CONTROL_EVPN *e, const CONTROL_EVPN_COUNTERS *c);
bool ControlGetEvpn(CONTROL_EVPN *e, CONTROL_EVPN_COUNTERS *c);
bool ControlWriteEvpn(CONTROL_EVPN *e, TRANSPORT_STREAM *s);

#endif // CORE_CONTROL_H
