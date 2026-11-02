// Node.h
// Header of the Node module (Node.c, NodeBgp.c, NodeClient.c, NodeController.c, NodeDhcp.c, NodeDns.c, NodeEndpoints.c, NodeFlap.c, NodeHarden.c, NodeLeak.c, NodeListener.c, NodeMirror.c, NodeNat.c, NodeOverlay.c, NodePolicy.c, NodeSession.c, NodeShape.c, NodeState.c, NodeTable.c, NodeVrf.c, NodeVrfAdapter.c, NodeWintun.c, NodeWorker.c): the node of the new core

#ifndef NODE_H
#define NODE_H

#include "CedarType.h"
#include "LogWriter.h"

#include "Mayaqua/MayaType.h"

#include "Core/Peer.h"
#include "Core/Transport.h"
#include "Core/Vxlan.h"

// The roles of a node (ADR-0011, ADR-0022). A node runs any set of them, chosen by the configuration
// and later by the control plane (NodeSetRoles). The controller is not a role: it left the node with #176.
#define NODE_ROLE_SERVER 0x01 // Hosts the Hubs that the sessions of strangler steps 1 and 2 end in
#define NODE_ROLE_CLIENT 0x02 // Client and cascade: dials other nodes (CORE-S3-1, #71)
#define NODE_ROLE_BRIDGE 0x04 // Joins an L2 segment to a physical NIC or a Hyper-V network (CORE-S3-3, #73)
#define NODE_ROLE_RELAY  0x08 // Relays between peers without a direct path (CORE-S5-2, #78)
#define NODE_ROLE_ALL    0x0F

// The roles of a node without a Roles item in its configuration
#define NODE_DEFAULT_ROLES NODE_ROLE_SERVER

// The files of a node in its data directory, besides the configuration store (CS_FILE_NAME)
#define NODE_LOG_DIR_NAME     L"node_log"
#define NODE_LOG_PREFIX       "node"
#define NODE_IMPORT_FILE_NAME L"ranz_server.config" // A fork configuration that NewNode imports once into an empty store
#define NODE_IMPORTED_SUFFIX  L".imported"          // ... and then renames with this suffix
#define NODE_CONFIG_DUMP_NAME L"node_config.txt"    // The text dump of the configuration store that NewNode writes, for ranz doctor --bundle (SDN-54, #247)

// The settings of a node in its configuration store
#define NODE_SETTING_ROLES        "Roles"       // A list of role names; without it NODE_DEFAULT_ROLES, "none" for no role
#define NODE_SETTING_WORKERS      "NumWorkers"  // The number of workers; without it, or 0, one per core
#define NODE_SETTING_RELAY_PORT   "RelayPort"   // The UDP port of the relay role; without it, or 0, one that the system picks
#define NODE_SETTING_IDENTITY_KEY "IdentityKey" // The name of the node identity key; without it NODE_IDENTITY_KEY_NAME
#define NODE_SETTING_BGP          "Bgp"         // The BGP settings, one JSON object (NodeBgpStart); without it no BGP sidecar
#define NODE_SETTING_CLIENT       "Client"      // The settings of the client role, one JSON object (NodeClient.c); without it the role holds nothing
#define NODE_SETTING_CONTROLLER   "Controller"  // The Controller settings, one JSON object (NodeController.c); without it the node opens no control stream
#define NODE_SETTING_LOG_DAYS     "LogDays"     // The age limit of the node log in days: older files of the log are deleted; without it NODE_LOG_DEFAULT_DAYS, 0 for no limit
#define NODE_SETTING_LOG_MB       "LogMB"       // The disk limit of the node log in megabytes: its files never take more together; without it NODE_LOG_DEFAULT_MB, 0 for no limit
#define NODE_SETTING_PORT_MAPPING "PortMapping" // 1: the peer agent asks the home gateway for a public port with PCP, NAT-PMP or UPnP (NodeAgent.c); without it, or 0, no request leaves the node

// The XDP datapath of msquic and QTIP on the Listener (NodeQtip.c; CORE-S7-2, #83; ADR-0018 decisions 2 and 5), both off by
// default and on Windows Server x64 only
#define NODE_SETTING_QUIC_XDP  "QuicXdp"  // "on": the QUIC of the Listener runs on the XDP datapath of msquic; without it on Winsock
#define NODE_SETTING_QTIP      "Qtip"     // "on": a QTIP listener beside it, for the links between server nodes; without it none
#define NODE_SETTING_QTIP_PORT "QtipPort" // The port of the QTIP listener, TCP and UDP; without it, or 0, TRANSPORT_QUIC_QTIP_PORT
#define NODE_QTIP_TRANSPORT    "qtip"     // The name of the QTIP transport in a fallback list

// The limits of the node log (SDN-54, #247) without the settings above, and the most that a setting may name
#define NODE_LOG_DEFAULT_DAYS 30
#define NODE_LOG_DEFAULT_MB   256
#define NODE_LOG_MAX_DAYS     36500
#define NODE_LOG_MAX_MB       1048576

// The node identity key in the software key storage provider (ADR-0022) without the IdentityKey setting
#define NODE_IDENTITY_KEY_NAME "Ranz Node"

// The account of the ranzvpnserver service: its virtual account, not LocalSystem (ADR-0039 decision 3). The SID is
// the one Windows derives from the service name (the SHA-1 of its upper-case UTF-16 form, as sc showsid prints it),
// so the DACL of the data directory can name it before the service exists.
#define NODE_SERVICE_ACCOUNT L"NT SERVICE\\ranzvpnserver"
#define NODE_SERVICE_SID     L"S-1-5-80-2319880895-1939077415-1550474732-530486738-250906376"

// The BGP sidecar, the subcommand bgp of ranz.exe (NodeBgp.c; ADR-0010, CORE-S7-1 #82, ONE-1 #310)
#define NODE_BGP_EXE_NAME     L"ranz.exe"     // The executable that holds the sidecar, next to the executable of the node; the node starts it as ranz.exe bgp
#define NODE_BGP_LOG_NAME     L"ranz-bgp.log" // Its log, in the node log directory
#define NODE_BGP_MAX_LINE     65536           // Bytes of one message of the pipe at most, with its newline (sidecar.MaxLine)
#define NODE_BGP_MAX_ROUTES   65536           // Learned routes that a node installs at most
#define NODE_BGP_ROUTE_METRIC 256             // The route metric of a learned route: the default RouteMetric of New-NetRoute

// The mimicry sidecar, the subcommand mimic of ranz.exe (NODE_BGP_EXE_NAME), and the mimic transport over it (NodeMimic.c,
// NodeMimicTransport.c; ADR-0023, CORE-P2-1 #85, CORE-P2-6 #406)
#define NODE_SETTING_MIMIC_SERVER "MimicServer" // The settings of the server role of the sidecar, one JSON text that the node forwards unread; without it no server role
#define NODE_SETTING_MIMIC_CLIENT "MimicClient" // ... of the client role; without it no client role
#define NODE_MIMIC_TRANSPORT      "mimic"       // The name of the transport in a fallback list
#define NODE_MIMIC_ROLE_SERVER    0             // The roles of a sidecar: the index of its status
#define NODE_MIMIC_ROLE_CLIENT    1
#define NODE_MIMIC_NUM_ROLES      2
#define NODE_MIMIC_MAX_LINE       65536 // Bytes of one message of the control pipe at most, with its newline (mimic.MaxLine)
#define NODE_MIMIC_MAX_SETTING    61440 // Bytes of a setting at most: it goes into the start message, within NODE_MIMIC_MAX_LINE
#define NODE_MIMIC_DATA_LINE      1024  // Bytes of the line in front of a stream of a data pipe at most, with its newline
#define NODE_MIMIC_BINDING        32    // Bytes of the channel binding of a stream (mimic.BindingSize)
#define NODE_MIMIC_RESTART_FIRST  1000  // ms before a sidecar that ended by itself starts again, the first time ...
#define NODE_MIMIC_RESTART_MAX    60000 // ... and at most: the delay doubles each time it ends again
#define NODE_MIMIC_STATS          1000  // ms between two stats messages to a running sidecar
#define NODE_MIMIC_LOG_STATS      60000 // ms between two lines of the counters in the node log, while they change

// What the client role of the sidecar answered a dial (NodeMimicParseAnswer)
#define NODE_MIMIC_ANSWER_OK    0 // ok and the binding: the stream starts
#define NODE_MIMIC_ANSWER_ERROR 1 // error and the reason: the link failed
#define NODE_MIMIC_ANSWER_BAD   2 // No answer of the protocol

#define NODE_MAX_WORKERS       256      // Workers of one node at most, whatever the number of cores
#define NODE_WORKER_BATCH      64       // Completions that a worker takes from its port in one wait
#define NODE_TABLE_KEY_SIZE    16       // Bytes of a table key: an IPv6 address; a shorter key is zero-padded
#define NODE_TABLE_MAX_ENTRIES 0x400000 // Entries of one table at most

// The overlay of a node (NodeOverlay.c; SDN-3, #179)
#define NODE_OVERLAY_MAX_ADDRESSES 16   // Addresses of a node or a peer (CONTROL_MAX_ADDRESSES of Core/Control.h)
#define NODE_OVERLAY_HANDSHAKE     5000 // ms for the handshake of a Noise session to a peer
#define NODE_OVERLAY_REDIAL        1000 // ms before a peer is dialled again
#define NODE_OVERLAY_IDLE          10   // ms that the thread of the overlay sleeps when it found nothing to do
#define NODE_OVERLAY_BATCH         64   // Records that the thread takes from one session in one pass
#define NODE_OVERLAY_VRF_TAG       4    // Bytes of a data record before its IP packet: the VRF id, big-endian (SDN-4, #180)
#define NODE_OVERLAY_RECORD        2048 // Bytes of a data record that NodeOverlayInput builds on its stack; a larger one is allocated

// The handshakes of the streams that the overlay accepts (NodeHandshake.c; AUD1-DT-1, #449)
#define NODE_OVERLAY_HANDSHAKES        64 // Handshakes in flight at most, without MaxHandshakes in the configuration
#define NODE_OVERLAY_HANDSHAKE_WORKERS 16 // Threads of the pool that runs them, one handshake each at a time

// The session flap (NodeFlap.c; AUD1-DT-11, #459)
#define NODE_FLAP_LIMIT  5     // Replacements of the session of one peer in the window above which the overlay reports it, without FlapLimit in the configuration
#define NODE_FLAP_WINDOW 60000 // ms of that window, without FlapWindow in the configuration

// How the overlay of a node reaches a peer (NODE_OVERLAY_SESSION.Path; NodeAgent.c, CORE-S5-5 #411)
#define NODE_PATH_NONE   0 // Not yet: no stream session and no datagram path
#define NODE_PATH_STREAM 1 // Its stream session (QUIC, TLS or mimic): the Noise session of its Tunnel
#define NODE_PATH_RELAY  2 // The datagram path of the peer agent, through a Relay
#define NODE_PATH_DIRECT 3 // The datagram path of the peer agent, on a direct path (ICE or a punch, CORE-S5-3 and CORE-S5-4)

// The Mirrors of a node (NodeMirror.c; SDN-23, #199)
#define NODE_MIRROR_ETHER     14                 // Bytes of the Ethernet header in front of the IP packet of a copy
#define NODE_MIRROR_BURST     50                 // ms of its rate that the token bucket of a Mirror holds ...
#define NODE_MIRROR_MIN_BURST VXLAN_MAX_DATAGRAM // ... and bytes at least: the largest datagram of the VXLAN module

// The client role (NodeClient.c; CORE-S3-1, #71)
#define NODE_CLIENT_ADAPTER     "Ranz"             // The name of its Wintun adapter without one in the Client setting
#define NODE_CLIENT_PIPE        "ranz-node-client" // The pipe of the logged-in user (\\.\pipe\...) without one in the Client setting
#define NODE_CLIENT_MAX_SETTING 8192               // Bytes of the Client setting at most
#define NODE_CLIENT_MAX_SERVERS 8                  // Servers of the Client setting at most
#define NODE_CLIENT_DIAL        5000               // ms that the race of the fallback list of a server takes at most
#define NODE_CLIENT_SLICE       50                 // ms that a read of a stream waits at most before it looks at whether the role closed it
#define NODE_CLIENT_SETTLE      500                // ms without an address change before the role takes the network as roamed
#define NODE_CLIENT_LINE        512                // Bytes of a command line of the pipe at most: enrol and the three Controller settings (SDN-55, #248)
#define NODE_CLIENT_REPLY       16384              // Bytes of an answer of the pipe at most: the status with its exit nodes (SDN-55, #248)
#define NODE_CLIENT_PIPE_IDLE   30000              // ms that the pipe waits for the next command of a connected user

// The Controller of a node and its admin pipe (NodeController.c; SDN-90, #395)
#define NODE_ADMIN_PIPE             "ranz-node-admin" // The admin pipe (\\.\pipe\...) without another in NODE.AdminPipe
#define NODE_ADMIN_LINE             1024              // Bytes of a command line of the admin pipe at most
#define NODE_ADMIN_REPLY            65536             // Bytes of an answer of the admin pipe at most: the state of a node (NodeState.c; SDN-91, #396) is the longest
#define NODE_STATE_MAX_SESSIONS     128               // Noise sessions that the state of a node names at most, so that it fits an answer
#define NODE_ADMIN_IDLE             10000             // ms that the admin pipe waits for the command of a connected Administrator
#define NODE_CONTROLLER_MAX_SETTING 2048              // Bytes of the Controller setting at most
#define NODE_CONTROLLER_FINGERPRINT 65                // The TLS fingerprint of a Controller: 64 hex digits and the NUL
#define NODE_CONTROLLER_PINS        4                 // The TLS fingerprints that a node accepts at once, once its Controller sent them (SDN-92, #397)
#define NODE_CONTROLLER_KEEPALIVE   10                // s without a segment on the control stream before TCP keepalive probes its path

// A TLS fingerprint of a Controller as text, in lower case, with its NUL
typedef char NODE_FINGERPRINT[NODE_CONTROLLER_FINGERPRINT];

// The Wintun adapters of a node (NodeWintun.c; CORE-S3-1, #71)
#define NODE_WINTUN_DLL           L"wintun.dll" // Next to the executable: the pinned release of THIRD_PARTY.TXT
#define NODE_WINTUN_TYPE          L"Ranz"       // The tunnel type of the adapters of the node
#define NODE_WINTUN_RING          0x400000      // Bytes of each ring of a session: 4 MiB, between the 128 KiB and 64 MiB of wintun.h
#define NODE_WINTUN_BATCH         256           // Packets of the host that the I/O thread takes in one run
#define NODE_WINTUN_MAX_PACKET    0xFFFF        // Bytes of a packet at most (WINTUN_MAX_IP_PACKET_SIZE)
#define NODE_WINTUN_MAX_ADDRESSES 16            // Addresses of one adapter at most
#define NODE_WINTUN_MAX_ROUTES    64            // Routes through one adapter at most
#define NODE_WINTUN_CREATE_WAIT   5000          // ms that the node waits for an adapter of the same name to go before it creates one
#define NODE_WINTUN_CREATE_RETRY  250           // ms between two attempts to create it

// The Wintun adapters of the VRFs of a node (NodeVrfAdapter.c; SDN-5, #181)
#define NODE_VRF_MAX_ADAPTERS  16                 // Adapters of one node at most: one per VRF (CONTROL_MAX_VRFS of Core/Control.h)
#define NODE_VRF_ADAPTER_NAME  128                // Characters of the name of an adapter at most, with its NUL (MAX_ADAPTER_NAME of wintun.h)
#define NODE_VRF_ADAPTER_LABEL "ranz vrf adapter" // What the name of the GUID of an adapter begins with, before the node's static key and the VRF id

// The WireGuard Devices of a gateway (NodeWireGuard.c; SDN-80, #375)
#define NODE_WIREGUARD_DLL        L"wireguard.dll"             // Next to the executable: the pinned WireGuardNT SDK of THIRD_PARTY.TXT
#define NODE_WIREGUARD_ADAPTER    L"Ranz WireGuard"            // What the name of the WireGuard interface begins with, before the node's name
#define NODE_WIREGUARD_LABEL      "ranz wireguard gateway key" // The label of the derivation of the WireGuard key pair of a node
#define NODE_WIREGUARD_KEY_SIZE   32                           // A WireGuard key (X25519)
#define NODE_WIREGUARD_COUNT      1000                         // ms between two reads of the counters of the Devices
#define NODE_WIREGUARD_UNIX_EPOCH 116444736000000000ULL        // The FILETIME of 1970-01-01, in 100 ns intervals since 1601

// The forwarding tables of the VRFs of a node (NodeVrf.c; SDN-4, #180)
#define NODE_VRF_LOCAL      0x3FFFFFFF // The next hop of an address of the node itself: the host
#define NODE_VRF_NONE       0xFFFFFFFF // What a lookup gives for an address that no route of the VRF holds
#define NODE_VRF_MAX_ROUTES 65536      // Routes of the tables of one Generation at most
#define NODE_VRF_MAX_HOPS   65536      // Next hops of those tables at most

// 1:1 NAT and 4via6 (NodeNat.c; SDN-6, #182)
#define NODE_NAT_GROWTH 40 // Bytes that the translation of a packet of a peer adds at most: from IPv4 to IPv6, 20 to its header and 20 to the one that an ICMP error quotes

// The MTU, the MSS clamp and the rate limits of the overlay of a node (NodeShape.c; SDN-20, #196)
#define NODE_SHAPE_DEFAULT_MTU 1280  // The MTU of a VRF that the desired state gives none, the least that IPv6 allows (ADR-0025 decision 16)
#define NODE_SHAPE_MAX_MTU     65535 // The largest MTU of a VRF (MaxMTU of the controller's intent)
#define NODE_SHAPE_MSS_HEADERS 40    // Bytes of the IPv4 and TCP headers between the MTU of a VRF and the MSS of a TCP SYN in it
#define NODE_SHAPE_BURST       50    // ms of its rate that a token bucket holds ...
#define NODE_SHAPE_MIN_BURST   65536 // ... and bytes at least: more than the largest IP packet

// The DHCP responder of an L2 Network (NodeDhcp.c; SDN-43, #236)
#define NODE_DHCP_MAX_DNS      4      // DNS servers of the clients at most (Dhcp.dns of control.options)
#define NODE_DHCP_MAX_RESERVED 16     // Reservations of the pool at most (Dhcp.reserved of control.options)
#define NODE_DHCP_MAX_LEASES   1024   // Entries of the lease table at most, and leases reported (Leases.leases of control.options)
#define NODE_DHCP_MIN_POOL     16     // The shortest IPv4 pool that a responder serves: a /16 ...
#define NODE_DHCP_MAX_POOL     30     // ... and the longest, a /30: the responder and one client
#define NODE_DHCP_OFFER_TIME   60000  // ms that an offered address stays the client's without its request
#define NODE_DHCP_DECLINE_TIME 600000 // ms that an address that a client declined stays out of use
#define NODE_DHCP_PROBE_TIME   300000 // ms between two probes for a DHCP server of the LAN
#define NODE_DHCP_PROBE_WAIT   2000   // ms that the responder waits for the answers to its first probe before it answers a client
#define NODE_DHCP_LAN_HOLD     900000 // ms that the responder stays silent after a DHCP server of the LAN answered
#define NODE_DHCP_MAX_QUEUE    64     // Frames that wait to be sent at most
#define NODE_DHCP_MAX_FRAME    1514   // Bytes of a frame that the responder takes or sends at most
#define NODE_DHCP_TICK         50     // ms between two runs of the thread of the responders of a node when no frame wakes it

// Overlay DNS of a node (NodeDns.c; SDN-11, #187)
#define NODE_DNS_NAME_SIZE      128        // A suffix or a name of a zone with its terminating NUL (CONTROL_DNS_NAME_SIZE of Core/Control.h)
#define NODE_DNS_MAX_ADDRESSES  8          // Addresses that a name of a zone answers at most (CONTROL_MAX_DNS_ADDRESSES), so an answer fits ...
#define NODE_DNS_MAX_ANSWER     512        // ... the bytes of an answer at most: the stub resolver takes no EDNS (RFC 1035 4.2.1)
#define NODE_DNS_PORT           53         // The UDP port of the stub resolver on each address of the node in a VRF
#define NODE_DNS_TTL            60         // s that a client may keep an answer with addresses ...
#define NODE_DNS_NEGATIVE_TTL   30         // ... and one without (RFC 2308): the MINIMUM of the SOA of a zone
#define NODE_DNS_POLL           250        // ms that the thread of the stub resolver waits for a query, between two looks at its addresses
#define NODE_DNS_RULE_LABEL     "RanzVPN-" // What the name of the key of an NRPT rule of a node begins with (NodeDnsRuleName)
#define NODE_DNS_RULE_NAME_SIZE 64         // Characters of that name at most, with its NUL
#define NODE_DNS_RCODE_NOERROR  0          // What NodeDnsAnswer answers: a name of the zone, with its addresses or none (NODATA) ...
#define NODE_DNS_RCODE_FORMERR  1          // ... a query that does not parse
#define NODE_DNS_RCODE_NXDOMAIN 3          // ... a name under the suffix that the zone does not have
#define NODE_DNS_RCODE_NOTIMP   4          // ... an opcode other than QUERY
#define NODE_DNS_RCODE_REFUSED  5          // ... a name outside the suffix, or a class other than IN

// The Listener of a node (NodeListener.c; SDN-45, #238)
#define NODE_LISTENER_FALLBACK   5555     // The TCP port of the front door when 443 is taken (the amendment of ADR-0035 of 2026-10-21)
#define NODE_LISTENER_ACME_DIR   L"acme"  // The folder of the ACME sidecar in the data directory: the state of each Listener
#define NODE_LISTENER_ACME_WAIT  180000   // ms that one run of the ACME sidecar takes at most
#define NODE_LISTENER_ACME_CHECK 43200000 // ms between two runs, which renew the certificate when it is due: 12 hours
#define NODE_LISTENER_ACME_RETRY 600000   // ms before a run that failed runs again
#define NODE_LISTENER_ACME_OUT   1024     // Bytes of the answer of a run at most
#define NODE_LISTENER_ACME_CMD   4096     // Characters of the command line of a run at most

// Runs one work item on a worker, to completion (NodePost)
typedef void(NODE_WORK_PROC)(NODE_WORKER *w, void *param);
// Drains an adapter queue on its I/O thread, to completion (NodeAddQueue)
typedef void(NODE_QUEUE_PROC)(NODE_QUEUE *q, void *param);
// Takes an IP packet of the overlay for the host in the VRF vrf_id (NodeOverlayStart), on the thread of the overlay
typedef void(NODE_ADAPTER_PROC)(NODE *n, void *param, UINT vrf_id, const UCHAR *packet, UINT size);
// Takes the MTU of the VRF vrf_id for the host's adapter of that VRF (NodeOverlayStart), on the thread that applied
// the Generation
typedef void(NODE_ADAPTER_MTU_PROC)(NODE *n, void *param, UINT vrf_id, UINT mtu);
// Stops the packets of the host into the overlay, first thing in NodeOverlayStop (NodeOverlayStart)
typedef void(NODE_ADAPTER_STOP_PROC)(NODE *n, void *param);
// Takes a desired state that the overlay applied, once its forwarding tables are in (NodeOverlayStart)
struct CONTROL_STATE;
typedef void(NODE_STATE_PROC)(NODE *n, void *param, const struct CONTROL_STATE *st);
// Takes how each stream of the control stream ended or why it did not open (NodeOverlayStart; CONTROL_END_PROC of
// Core/Control.h), on the thread of the control stream
struct CONTROL_STATUS;
// The Capabilities that the Hello of the control stream reports (NODE_OVERLAY_CONFIG.Caps; CONTROL_CAPS of Core/Control.h)
struct CONTROL_CAPS;
typedef void(NODE_CONTROL_END_PROC)(void *param, const struct CONTROL_STATUS *st);
// Takes an IP packet of the host's own stack from the ring of a Wintun adapter, on the I/O thread of its adapter queue
typedef void(NODE_WINTUN_PROC)(NODE_WINTUN *w, void *param, const UCHAR *packet, UINT size);
// Tells the time in ms of the flows of the policy of the overlay (NodeOverlayStart), on the thread of a packet
typedef UINT64(NODE_CLOCK_PROC)(NODE *n, void *param);
// Tells whether the data transport dials the peer name, whose Peer object lists the num endpoints (SDN-93, #410), as the
// overlay asks for each peer that has no session (NodeOverlayStart): under the lock of the overlay, so it takes no lock
struct CONTROL_ENDPOINT;
typedef bool(NODE_DIALABLE_PROC)(NODE *n, void *param, const char *name, const struct CONTROL_ENDPOINT *endpoints, UINT num);
// Takes the peer name whose Noise handshake failed on a stream that the data transport dialled (CORE-H5-R, #443), on the
// thread of the overlay and outside its lock, so that the next dial of the peer races the next transport of its list
typedef void(NODE_REFUSED_PROC)(NODE *n, void *param, const char *name);
// Runs once the control pipe of a mimicry sidecar exists and before the sidecar starts, with the name of the pipe: a
// test that connects another client to it (NODE_MIMIC_TEST)
typedef void(NODE_MIMIC_LAUNCH_PROC)(void *param, const wchar_t *pipe);
// Takes the peer layer of the peer agent of the overlay once it starts, and NULL before it stops (NodeOverlayStart; NodeAgent.c,
// CORE-S5-5 #411), so that the network of a test hands it the datagrams for the node; after NULL the network hands it none
typedef void(NODE_PATH_ATTACH_PROC)(NODE *n, void *param, PEER_AGENT *agent);

// What a test changes in the way a node starts its mimicry sidecars (NODE.MimicTest; NodeMimic.c)
struct NODE_MIMIC_TEST {
	NODE_MIMIC_LAUNCH_PROC *BeforeLaunch; // Runs before each start of a sidecar, NULL for nothing
	void *Param;                          // Its parameter
};

// What NodeMimicGetStatus reports of the sidecar of one role (NODE_MIMIC_ROLE_*), and NodeGetStatus in Mimic. The
// counters are those of the sidecar (its stats messages), added up over every process of the role since the node started.
struct NODE_MIMIC_STATUS {
	bool Configured;        // The configuration has the settings of the role
	bool Running;           // The sidecar runs with them: it sent ready, and the transport of the role is available
	UINT ProcessId;         // The process of the sidecar, 0 when none runs
	UINT NumStarts;         // The processes of the sidecar that started and connected to their control pipe
	UINT NumRestarts;       // ... of which after one ended by itself
	UINT NumErrors;         // Error messages of the sidecar
	UINT64 Accepted;        // The server role: clients that proved the key of the server
	UINT64 Probes;          // ... connections that were no Ranz client, spliced to the decoy
	UINT64 Streams;         // The inner streams that the sidecar carried to or from the node
	UINT64 Dropped;         // The events that did not fit the queue of the control pipe of the sidecar
	char Listen[MAX_SIZE];  // The server role: the address of the REALITY listener that ready named
	char Version[MAX_SIZE]; // What the sidecar named in ready: ranz mimic and its libraries
	char PipeAcl[MAX_SIZE]; // The DACL of the control pipe as the system holds it, in SDDL
	char Error[MAX_SIZE];   // Why the transport of the role is not available, "" while it is or the role has no settings
};

// One message of a mimicry sidecar on its control pipe, as NodeMimicParseMessage reads it: the fields of the protocol of
// controller/internal/mimic/control.go that the node reads, "" or 0 for a field the message does not have
struct NODE_MIMIC_MESSAGE {
	char Type[32];          // ready, accepted, probe, stats or error
	char Version[MAX_SIZE]; // ready
	UINT Protocol;
	char Listen[MAX_SIZE];
	char Decoy[MAX_SIZE];
	char Peer[MAX_SIZE];   // accepted, probe, error
	char Reason[MAX_SIZE]; // probe
	UINT64 Accepted;       // stats
	UINT64 Probes;
	UINT64 Streams;
	UINT64 Dropped;
	char Error[MAX_SIZE]; // error
};

// A thread that reads the table snapshot: a worker, the I/O thread of an adapter queue, or a thread that
// registered itself. It holds a snapshot only between two quiescent points and none while it is offline,
// so a swap waits for at most one pass of each online reader before it frees the old snapshot.
struct NODE_READER {
	volatile LONG64 Seen; // The table epoch at the last quiescent point; 0 while offline
	UINT ThreadId;        // The thread that registered the reader
};

// One entry of a read-mostly table
struct NODE_TABLE_ENTRY {
	UCHAR Key[NODE_TABLE_KEY_SIZE]; // The exact-match key, zero-padded
	UINT64 Value;                   // What the key maps to: a port, a next hop or a rule
};

// A read-mostly table: built once, sorted by key, never changed while a snapshot holds it
struct NODE_TABLE {
	UINT NumEntries;           // Number of entries
	NODE_TABLE_ENTRY *Entries; // The entries, sorted by key
};

// The table snapshot of a node: the MAC, route and policy tables and the forwarding tables of the VRFs that the data
// path reads without a lock. A new snapshot is built off the data path; NodeSwapTables installs it by pointer, and
// NodeSwapVrfs installs one with new forwarding tables of the VRFs and the other tables of the current one.
struct NODE_TABLES {
	UINT64 Generation;     // Set by NodeSwapTables and NodeSwapVrfs: one more than the snapshot it replaced
	NODE_TABLE *Mac;       // The VLAN-aware MAC table: key NodeMacKey, value the port
	NODE_TABLE *Route;     // The route table; its compiled form comes with the routed networks (CORE-S6-1, #80)
	NODE_TABLE *Policy;    // The policy table; its compiled form comes with the policy engine (CORE-S4-2, #75)
	NODE_VRF_TABLES *Vrfs; // The forwarding tables of the VRFs (NodeVrf.c; SDN-4, #180), NULL for none
	// The IP prefix routes of the fabric of an EVPN gateway (NodeEvpn.c; SDN-25, #201), NULL for none: NodeSwapEvpn replaces
	// them, and the other swaps carry them over
	struct NODE_EVPN_TABLE *Evpn;
};

// One route of the forwarding tables of the VRFs (NodeNewVrfTables)
struct NODE_VRF_ROUTE {
	UINT VrfId;        // The VRF
	UCHAR Address[16]; // The prefix: 4 bytes for IPv4, 16 for IPv6, in network byte order; its host bits are ignored
	UINT AddressSize;  // ... their number
	UINT Length;       // The prefix length: 0 to 32 for IPv4, 0 to 128 for IPv6
	UINT NextHop;      // What it leads to: an index of the next hops, or NODE_VRF_LOCAL for the host
};

// The forwarding tables of the VRFs of a node for one Generation of its desired state (NodeVrf.c; SDN-4, #180): one
// immutable longest-prefix-match table per VRF, DIR-24-8 for IPv4 and a trie for IPv6, built beside the live ones and
// installed with them by NodeSwapVrfs. A route leads to the host or to one of the next hops, objects that the builder
// owns and keeps until the tables are freed.
struct NODE_VRF_TABLES {
	UINT64 Generation;     // The Generation of the desired state they were built from
	UINT NumVrfs;          // Number of VRFs
	NODE_VRF_TABLE **Vrfs; // The table of each, by VRF id
	UINT NumHops;          // Number of next hops
	void **Hops;           // The next hops: what next hop i of a route leads to
	NODE_NAT *Nat;         // The 1:1 NAT rules of the same Generation (NodeNat.c; SDN-6, #182), NULL for none
	// The MTU and the rate limits of the VRFs of the same Generation (NodeShape.c; SDN-20, #196), NULL for the defaults
	NODE_SHAPE_TABLE *Shape;
	// The VRF of the peer that a packet to each next hop goes into, 0 for the VRF of its route: a next hop of a route
	// that a VRF of the peer leaks (NodeLeak.c; SDN-7, #183). NULL when no route is leaked.
	UINT *HopVrfs;
	// The Mirrors of the same Generation (NodeMirror.c; SDN-23, #199), NULL for none
	NODE_MIRROR_TABLE *Mirror;
	// The members of the policy of the VRFs of the same Generation (NodePolicy.c; SDN-8, #184), NULL for no policy
	NODE_POLICY_TABLE *Policy;
	// The links of kind vxlan and geneve of the same Generation (NodeLink.c; SDN-76, #356), NULL for none
	struct NODE_LINK_TABLE *Link;
	// The groups of gateways and the hubs of the same Generation (NodeGateway.c; SDN-19, #195): the next hop of each group
	// comes after those of the peers and of the leaked routes. NULL for neither.
	struct NODE_GATEWAY_TABLE *Gateway;
	// The session profiles of the peers and of the node of the same Generation (NodeProfile.c; SDN-40, #233), NULL for none
	struct NODE_PROFILE_TABLE *Profile;
	// The source groups of the same Generation (NodeSourceGroup.c; SDN-87, #386), NULL for none
	struct NODE_SOURCE_GROUP_TABLE *SourceGroups;
	// The VRFs whose internet exit the node is in the same Generation (NodeEgress.c; SDN-12, #188), NULL for none
	struct NODE_EGRESS_TABLE *Egress;
	// The exit nodes of the same Generation and the one that the user of the client role chose (NodeExit.c; SDN-55, #248), NULL
	// for the tables of a node without the client role
	struct NODE_EXIT_TABLE *Exit;
};

// A per-core run-to-completion loop: one thread bound to one core takes work items from its I/O completion
// port and runs each to completion; it passes a quiescent point after every batch
struct NODE_WORKER {
	NODE *Node;                 // The node of the worker
	UINT Index;                 // Its index among the workers of the node
	PROCESSOR_NUMBER Processor; // The core that the thread is bound to
	HANDLE Port;                // The I/O completion port of the loop
	HANDLE Thread;              // The worker thread
	UINT ThreadId;              // Its thread id
	NODE_READER Reader;         // The worker as a reader of the table snapshot
	volatile LONG64 NumItems;   // Work items run so far
};

// An adapter queue (the Wintun ring, the AF_XDP queue of a KM-TEST adapter) with its own I/O thread.
// The thread waits for Event and calls Proc, which drains the queue to completion.
struct NODE_QUEUE {
	NODE *Node;              // The node of the queue
	char Name[MAX_SIZE];     // The name of the queue, for the node log
	HANDLE Event;            // Signalled by the adapter while the queue holds frames
	NODE_QUEUE_PROC *Proc;   // Drains the queue on the I/O thread
	void *Param;             // The second parameter of Proc
	HANDLE StopEvent;        // Ends the I/O thread
	HANDLE Thread;           // The I/O thread
	UINT ThreadId;           // Its thread id
	NODE_READER Reader;      // The I/O thread as a reader of the table snapshot
	volatile LONG64 NumRuns; // Calls of Proc so far
};

// A node of the new core: the roles of its configuration, one worker per core, one I/O thread per adapter
// queue and the table snapshot (ADR-0011; ADR-0022, Threading). There is no hub-wide forwarding lock: the
// data path reads the snapshot, and Lock serialises only start, stop and role changes.
struct NODE {
	LOCK *Lock;                   // Start, stop and role changes; never taken on the data path
	wchar_t DataDir[MAX_PATH];    // The data directory: the configuration store and the node log
	LOG *Log;                     // The node log (LogWriter)
	CEDAR *Cedar;                 // The Cedar of the Hubs of the server role
	CONFIG_STORE *Store;          // The configuration store (ConfigStore), NULL when it cannot be opened
	UINT ConfigRoles;             // The roles that the configuration selects (NODE_ROLE_*)
	UINT ConfigWorkers;           // The workers that the configuration asks for, 0 for one per core
	bool Running;                 // Between NodeStart and NodeStop
	UINT Roles;                   // The running roles (NODE_ROLE_*)
	LIST *HubList;                // The Hubs of the server role, each referenced
	UINT NumWorkers;              // Number of running workers
	NODE_WORKER **Workers;        // The running workers
	LIST *QueueList;              // The attached adapter queues (NODE_QUEUE)
	LOCK *TableLock;              // Table writers and the reader list
	LIST *ReaderList;             // The registered table readers (NODE_READER)
	NODE_TABLES *volatile Tables; // The current table snapshot, NULL while stopped
	volatile LONG64 Epoch;        // The table epoch: one more at each swap
	volatile LONG64 Generation;   // The generation of the current snapshot, 0 while stopped
	UINT64 LastGeneration;        // The generation of the last snapshot installed, under TableLock

	// The peers and the relay role (CORE-S5-2, #78), under Lock
	UINT ConfigRelayPort;       // The UDP port of the relay role (RelayPort), 0 for one that the system picks
	char IdentityKey[MAX_SIZE]; // The name of the identity key (IdentityKey), NODE_IDENTITY_KEY_NAME without the setting
	PEER_INFO *Peers;           // The peers that the control plane set (NodeSetPeers)
	UINT NumPeers;              // ... their number
	PEER_KEY RelayKey;          // The identity key, while the relay role runs
	PEER_UDP *RelayUdp;         // The UDP socket of the relay role, NULL while it does not run
	PEER_AGENT *Relay;          // The peer layer of the relay role, NULL while it does not run

	// The client role (NodeClient.c; CORE-S3-1, #71), under Lock: NULL while the role holds nothing
	NODE_CLIENT *Client;

	// The Controller of the node and its admin pipe (NodeController.c; SDN-90, #395), under Lock: NULL while the node
	// does not run. The admin pipe is NODE_ADMIN_PIPE unless a test names another before NodeStart.
	NODE_CONTROLLER *Controller;
	wchar_t AdminPipe[MAX_PATH];

	// The BGP sidecar (CORE-S7-1, #82), under Lock
	char *ConfigBgp;              // The BGP settings of the configuration (NODE_SETTING_BGP), NULL for none
	wchar_t BgpSidecar[MAX_PATH]; // The executable that holds the sidecar: NODE_BGP_EXE_NAME next to the executable; a test may name another before NodeStart
	NODE_BGP *Bgp;                // The running BGP sidecar (NodeBgp.c), NULL when none runs
	// The counters of the EVPN of a gateway that the control stream reports (Core/ControlEvpn.c; SDN-25-R3, #571): set while
	// an EVPN runs (NodeEvpn.c), from NewNode to FreeNode
	struct CONTROL_EVPN *EvpnReport;
	// The EVPN of a gateway (NodeEvpn.c; SDN-25, #201): the VTEP and the routes of the fabric of a sidecar whose Bgp setting
	// has an evpn object, from the start of the sidecar to its stop; NULL without one
	struct NODE_EVPN *Evpn;
	// The stretch of a gateway (NodeStretch.c; SDN-64, #291): the switches of the L2 Networks that the L2 data path attached and the
	// stretches of the running sidecar; NULL until the first of them, kept until FreeNode
	struct NODE_STRETCH *volatile Stretch;

	// The mimicry sidecar and the mimic transport (NodeMimic.c; CORE-P2-6, #406), under Lock. A test may name another
	// executable and set MimicTest before NodeStart.
	wchar_t MimicSidecar[MAX_PATH]; // The executable that holds the sidecar: NODE_BGP_EXE_NAME next to the executable
	NODE_MIMIC_TEST MimicTest;      // What a test changes in the way the node starts a sidecar
	NODE_MIMIC *Mimic;              // The sidecars and the transport, NULL while the node does not run

	// The overlay (NodeOverlay.c; SDN-3, #179), NULL while it does not run
	NODE_OVERLAY *Overlay;

	// The policy of the VRFs of the overlay (NodePolicy.c; SDN-8, #184), NULL while it does not run
	NODE_POLICY *Policy;

	// The MTU, the MSS clamp and the rate limits of the overlay (NodeShape.c; SDN-20, #196), NULL while it does not run
	NODE_SHAPE *Shape;

	// The VXLAN module that sends the copies of the Mirrors (NodeMirror.c; SDN-23, #199), NULL until a Generation of
	// the overlay has a Mirror
	NODE_MIRROR *volatile Mirror;

	// The VXLAN module of the links of kind vxlan and geneve (NodeLink.c; SDN-76, #356), NULL until a Generation of the
	// overlay has one
	struct NODE_LINK *volatile Link;

	// The DHCP responders of the L2 Networks (NodeDhcp.c; SDN-43, #236), NULL while the overlay does not run
	NODE_DHCPS *Dhcp;

	// The Listener of the node (NodeListener.c; SDN-45, #238): where it listens, NULL while the overlay does not run
	NODE_LISTENER *Listener;

	// The WireGuard end of a gateway of WireGuard Devices (NodeWireGuard.c; SDN-80, #375), NULL while the overlay does not
	// run
	NODE_WIREGUARD *WireGuard;

	// The throttle of the Login (NodeThrottle.c; AUD1-DT-5, #453), from NewNode to FreeNode
	struct NODE_THROTTLE *LoginThrottle;

	// The source groups of the overlay (NodeSourceGroup.c; SDN-87, #386): the counters by tag mode, NULL while the overlay
	// does not run
	struct NODE_SOURCE_GROUPS *SourceGroups;

	// The peer agent of the overlay (NodeAgent.c; CORE-S5-5, #411): the datagram path to the peers that the node reaches on no
	// stream session, NULL while the overlay does not run
	struct NODE_AGENT *volatile Agent;

	// The gateway HA of the overlay (NodeGateway.c; SDN-19, #195): the gateways of its groups and their probes, NULL while
	// the overlay does not run
	struct NODE_GATEWAY *Gateway;

	// The BGP peering of the standard mode (NodePeering.c; SDN-77, #357): the sidecar of the VRFs whose nodes exchange their
	// routes by BGP, NULL while the overlay does not run
	struct NODE_PEERING *Peering;

	// The session profiles of the peers and of the node (NodeProfile.c; SDN-40, #233), NULL while the overlay does not run
	struct NODE_PROFILE *Profile;

	// The internet exit of the VRFs of the overlay (NodeEgress.c; SDN-12, #188): its proxy and the interfaces that carry the
	// egress, NULL while the overlay does not run
	struct NODE_EGRESS *Egress;

	// The switches of the L2 Networks, whose tables the live operations of the Controller read and clear (NodeOperation.c;
	// SDN-50-N, #492), NULL while the overlay does not run
	struct NODE_OPERATIONS *Operations;
};

// How the overlay of a node runs (NodeOverlayStart)
struct NODE_OVERLAY_CONFIG {
	TRANSPORT *Control;                      // The transport of the control stream to the controller (Core/Control.h), NULL for none: NodeOverlayApply then applies the states
	char Controller[TRANSPORT_ADDRESS_SIZE]; // The controller's address on it
	UCHAR ControllerKey[PEER_KEY_SIZE];      // ... and its static key
	NODE_CONTROL_END_PROC *ControlEnd;       // Takes the end of each stream of the control stream, NULL for none (SDN-90, #395) ...
	void *ControlEndParam;                   // ... and its first parameter
	TRANSPORT *Data;                         // The transport of the Noise sessions to the peers, which finds a peer by its node name
	PEER_KEY *Key;                           // The node's static key, which must outlive the overlay
	NODE_ADAPTER_PROC *Adapter;              // Takes the packets for the host, NULL for none
	void *AdapterParam;                      // ... and its second parameter, which AdapterStop and State take too
	NODE_ADAPTER_MTU_PROC *AdapterMtu;       // Takes the MTU of each VRF for the host's adapter of the VRF, NULL for none; with AdapterParam
	NODE_ADAPTER_STOP_PROC *AdapterStop;     // Stops the packets of the host first thing in NodeOverlayStop, NULL when the caller stops them before
	NODE_STATE_PROC *State;                  // Takes each state applied, once its forwarding tables are in, NULL for none
	bool Dialler;                            // The node dials every peer, whatever the order of the keys, as a client does (CORE-S3-1)
	NODE_CLOCK_PROC *Clock;                  // Tells the time of the flows of the policy (NodePolicy.c), NULL for GetTickCount64; with AdapterParam

	// Tells whether the data transport dials a peer, which has endpoints in its Peer object (SDN-93, #410); with AdapterParam.
	// The overlay then dials a peer only when it does, and a node that has no endpoints itself dials every such peer, whatever
	// the order of the keys, while two nodes that both have endpoints follow it (NodeEndpointsDials). NULL: the data transport
	// finds a peer by its node name, and the order of the keys decides alone, as the in-process transport of the vpntest
	// harness does.
	NODE_DIALABLE_PROC *Dialable;

	// The handshakes of the streams that the overlay accepts that are in flight at most, 0 for NODE_OVERLAY_HANDSHAKES: the
	// stream after them is refused at the accept (NodeHandshake.c; AUD1-DT-1, #449)
	UINT MaxHandshakes;

	// Takes the peer whose handshake failed on a stream that the overlay dialled (CORE-H5-R, #443), NULL for none; with
	// AdapterParam
	NODE_REFUSED_PROC *Refused;

	// The session flap (NodeFlap.c; AUD1-DT-11, #459): the replacements of the session of one peer in FlapWindow ms above
	// which the overlay reports it as an Event, 0 for NODE_FLAP_LIMIT, and the window, 0 for NODE_FLAP_WINDOW
	UINT FlapLimit;
	UINT FlapWindow;

	// The network of the datagram path of the peer agent (NodeAgent.c; CORE-S5-5, #411), NULL for a UDP socket of its own, as a
	// Node service has it: the send procedure of its datagrams with its first parameter, and the procedure that hands the
	// network its peer layer, with AdapterParam (the NAT simulator of the vpntest harness)
	PEER_SEND_PROC *PathSend;
	void *PathSendParam;
	NODE_PATH_ATTACH_PROC *PathAttach;
	// The configuration of the peer layer of the agent, NULL for PeerDefaultConfig: the shorter timers of a test
	const PEER_CONFIG *PathConfig;

	// The Egress tier that the node uses as the internet exit of a VRF (CONTROL_EGRESS_* of Core/Control.h; NodeEgress.c, SDN-12
	// #188), 0 for the one of its Capabilities, the first that its host supports (NodeCaps.c): the tier that a test checks
	UINT EgressTier;

	// Tells the Capabilities that the Hello of the control stream reports in place of the ones of the host (NodeCaps.c), NULL
	// for those; with AdapterParam. A test whose own switch is the L2 data path of the node reports the L2 backend that the
	// switch stands in for, which the Controller asks of a node that holds an L2 Network (SDN-50-N, #492).
	void (*Caps)(void *param, struct CONTROL_CAPS *caps);

	// The exit node of the client role (NodeExit.c; SDN-55, #248), NULL for an overlay without it: the overlay then takes no
	// default route of a peer but through the exit node that the user chose, which must outlive the overlay
	struct NODE_EXIT *Exit;
};

// What NodeOverlayGetStatus reports
struct NODE_OVERLAY_STATUS {
	bool Connected;                             // The control stream is open ...
	UINT64 Since;                               // ... since this GetTickCount64 (SDN-91, #396)
	UINT64 Generation;                          // The Generation of the desired state that the overlay runs, 0 before the first
	char Name[PEER_NAME_SIZE];                  // The node's name in the intent
	UINT NumAddresses;                          // Its IPv4 addresses in the L3 Networks of its VRFs
	UINT Addresses[NODE_OVERLAY_MAX_ADDRESSES]; // ... in network byte order
	UINT VrfIds[NODE_OVERLAY_MAX_ADDRESSES];    // ... and the VRF of each
	UINT NumVrfs;                               // The VRFs of its forwarding tables
	UINT NumPeers;                              // Its peers
	UINT NumLinks;                              // ... with a Noise session up
	UINT64 Forwarded;                           // Packets of the host sent to a peer
	UINT64 Delivered;                           // Packets of the peers delivered to the host
	UINT64 Dropped;                             // Packets of either side that the overlay dropped

	// The dials that the overlay started, whatever they gave: a peer that the node does not dial, one without endpoints for
	// one, adds none (SDN-93, #410)
	UINT64 Dials;

	// The handshakes of the streams that the overlay accepted, which run off its thread (NodeHandshake.c; AUD1-DT-1, #449)
	UINT MaxHandshakes;        // In flight at most
	UINT HandshakesInFlight;   // Waiting for a thread of the pool or running on one
	UINT64 HandshakesTimedOut; // Closed because they did not finish in NODE_OVERLAY_HANDSHAKE
	UINT64 HandshakesFailed;   // Closed because they failed within it
	UINT64 HandshakesRefused;  // Streams refused at the accept, because MaxHandshakes were in flight

	// The sessions that a new handshake of the key of a peer replaced, and the session flaps that the overlay reported as
	// Events (NodeFlap.c; AUD1-DT-11, #459)
	UINT64 SessionsReplaced;
	UINT64 SessionFlaps;
};

// One peer of the overlay and its Noise session, as NodeOverlayGetSessions reports it (SDN-91, #396)
struct NODE_OVERLAY_SESSION {
	char Name[PEER_NAME_SIZE];           // The node name of the peer
	bool Up;                             // Its Noise session is up ...
	char Transport[TRANSPORT_NAME_SIZE]; // ... over this transport ...
	UINT64 Since;                        // ... since this GetTickCount64

	// How the overlay reaches the peer now (NODE_PATH_*), and the records of the overlay that went to it and came from it on its
	// datagram path (NodeAgent.c; CORE-S5-5, #411)
	UINT Path;
	UINT64 DatagramsOut;
	UINT64 DatagramsIn;
};

// What NodePolicyGetVrf reports of the policy of a VRF of a node: its Network in the policy engine (Core/Policy.h)
struct NODE_POLICY_VRF_STATUS {
	UINT NumRules;   // The rules of the VRF
	UINT NumMembers; // Its members: the host, the end outside the VRF and the peers in it
	UINT Flows;      // The flows of its conntrack table
	UINT MaxFlows;   // ... at most: its conntrack quota
	UINT64 Tracked;  // Flows that the table took
	UINT64 Evicted;  // ... that left it as the least recently used of a full table
	UINT64 Expired;  // ... that left it after their timeout
	UINT64 Dropped;  // Packets of any VRF that the policy of the node dropped
};

// An address or a route prefix of a Wintun adapter (NodeWintun.c)
struct NODE_PREFIX {
	UCHAR Address[16]; // 4 bytes for IPv4, 16 for IPv6, in network byte order
	UINT AddressSize;  // ... their number
	UINT Length;       // The prefix length: 0 to 32 for IPv4, 0 to 128 for IPv6
};

// What NodeClientGetStatus reports
struct NODE_CLIENT_STATUS {
	bool Running;                        // The role runs with a Client setting
	bool Down;                           // The logged-in user took it down
	bool Asleep;                         // Between a suspend and a resume
	wchar_t Adapter[MAX_SIZE];           // The name of its Wintun adapter of VrfId (one per VRF, SDN-5), the one of the Client setting before the first state
	UINT InterfaceIndex;                 // ... the index of its interface
	UINT64 InterfaceLuid;                // ... and the LUID of that interface
	wchar_t Pipe[MAX_PATH];              // The pipe of the logged-in user
	UCHAR Key[PEER_KEY_SIZE];            // The node's static key, which its servers know
	UINT VrfId;                          // The VRF of the adapter: the VRF of the node's first address
	UINT NumServers;                     // The servers that it dials
	char Transport[TRANSPORT_NAME_SIZE]; // The transport of the stream that connected last, empty before the first
	UINT64 NumDials;                     // Streams that connected
	UINT64 NumResets;                    // Times it closed its streams: suspend, resume, roaming, down
	UINT64 NumRoams;                     // Settled address changes on other interfaces
	UINT64 FromHost;                     // Packets of the host taken from its adapters
	UINT64 ToHost;                       // Packets put into its adapters for the host

	// The exit node that the logged-in user chose (NodeExit.c; SDN-55, #248)
	bool ExitChosen;           // The user chose one ...
	char Exit[PEER_NAME_SIZE]; // ... this peer ...
	UINT ExitVrf;              // ... in this VRF
	bool ExitAvailable;        // The forwarding tables in place hold it
	bool ExitActive;           // The default routes of both families go through the adapter of its VRF
	UINT NumExits;             // The exit nodes of the forwarding tables in place
	UINT NumBypass;            // The host routes of server addresses through the interface of a default route of the host
	UINT64 ExitDropped4;       // Packets of the host to the exit that it does not carry: IPv4 ...
	UINT64 ExitDropped6;       // ... and IPv6
};

// What NodeControllerGetStatus reports (NodeController.c; SDN-90, #395)
struct NODE_CONTROLLER_STATUS {
	bool Set;                                      // The node has Controller settings
	char Address[TRANSPORT_ADDRESS_SIZE];          // The address of the Controller's TLS port ...
	UCHAR Key[PEER_KEY_SIZE];                      // ... its static key ...
	char Fingerprint[NODE_CONTROLLER_FINGERPRINT]; // ... and the TLS fingerprint of its certificate, in lower case
	bool Overlay;                                  // The node started the overlay for the control stream, without the client role
	bool Connected;                                // The control stream is open
	UINT64 Generation;                             // The Generation of the desired state that the overlay runs
	UINT64 NumEnds;                                // Streams that ended or did not open
	UINT LastEnd;                                  // How the last one ended (CONTROL_END_*)
	UINT NextRetry;                                // ms before the next attempt after it
	bool Mismatch;                                 // The certificate of the last dial that reached the fingerprint check failed it ...
	char Seen[NODE_CONTROLLER_FINGERPRINT];        // ... and had this TLS fingerprint, "" before the first
	char PipeAcl[MAX_SIZE];                        // The DACL of the admin pipe as the system holds it, in SDDL; "" when it does not run
	char Why[MAX_SIZE * 2];                        // Why the last stream ended or did not open, as the node log says it; "" before the first (SDN-91, #396)
	UINT NumPins;                                  // The TLS fingerprints that the node accepts once the Controller sent them (SDN-92, #397), 0 before: Fingerprint alone ...
	NODE_FINGERPRINT Pins[NODE_CONTROLLER_PINS];   // ... in lower case, the certificate in use first
};

// One Wintun adapter of a VRF, as NodeVrfAdaptersGetStatus and NodeClientGetAdapters report it
struct NODE_VRF_ADAPTER_STATUS {
	UINT VrfId;                          // The VRF
	wchar_t Name[NODE_VRF_ADAPTER_NAME]; // The name of the adapter
	GUID Guid;                           // The GUID that the node asked for (NodeVrfAdapterGuid), which Windows gives the interface
	UINT InterfaceIndex;                 // The index of the interface
	UINT64 InterfaceLuid;                // ... and its LUID
	UINT64 FromHost;                     // Packets of the host taken from the adapter
	UINT64 ToHost;                       // Packets put into it for the host
	UINT64 Dropped;                      // Packets for the host that found its ring full
};

// What NodeShapeGetStatus reports
struct NODE_SHAPE_STATUS {
	UINT64 Clamped; // TCP SYNs of the host that left with their MSS clamped to the MTU of their VRF
	UINT64 Limited; // Packets of the host that a rate limit dropped
};

// How the DHCP responder of an L2 Network runs (NodeDhcpNew, NodeDhcpSetConfig): the Dhcp object of the Network in the
// desired state of the node that answers DHCP for it (Core/Control.h). The addresses are IPv4 in host byte order:
// 10.20.0.1 is 0x0A140001.
struct NODE_DHCP_CONFIG {
	bool Serve;                                   // The mode is pool: the responder answers while no DHCP server of the LAN answers
	UCHAR Mac[6];                                 // The MAC address of the responder, the source of its frames
	UINT Pool;                                    // The IPv4 pool of the Network ...
	UINT PoolLength;                              // ... and its length, NODE_DHCP_MIN_POOL to NODE_DHCP_MAX_POOL
	UINT Address;                                 // The responder's own address, a host address of the pool: its server identifier
	UINT Gateway;                                 // The router of the clients, 0 for none
	UINT NumDns;                                  // The DNS servers of the clients
	UINT Dns[NODE_DHCP_MAX_DNS];                  // ...
	UINT LeaseTime;                               // The lease time, in seconds
	UINT NumReserved;                             // The reservations of the Network in the pool
	UINT ReservedAddress[NODE_DHCP_MAX_RESERVED]; // ... their prefixes
	UINT ReservedLength[NODE_DHCP_MAX_RESERVED];  // ... and their lengths
};

// One lease of a DHCP responder (NodeDhcpGetLeases)
struct NODE_DHCP_LEASE {
	UCHAR Mac[6];      // The client's MAC address
	UINT Address;      // Its address, in host byte order
	UINT64 Expires;    // The time at which the lease ends, in the ms of the responder's caller
	char HostName[64]; // The host name that the client sent (option 12), printable ASCII; "" for none
};

// What NodeDhcpGetStatus reports
struct NODE_DHCP_STATUS {
	bool Serving;      // The responder answers clients: its mode is pool, its first probe had its answers and no DHCP server of the LAN answers
	bool LanServer;    // A DHCP server of the LAN answered within NODE_DHCP_LAN_HOLD
	UINT NumLeases;    // Its leases
	UINT64 Probes;     // The probes it sent
	UINT64 Offers;     // The DHCPOFFERs ...
	UINT64 Acks;       // ... the DHCPACKs ...
	UINT64 Naks;       // ... and the DHCPNAKs it sent
	UINT64 Arps;       // The ARP replies it sent for its own address
	UINT64 Ignored;    // The DHCP messages of clients it took and did not answer
	UINT64 LanAnswers; // The answers of a DHCP server of the LAN that it saw
	UINT64 Changes;    // The changes of its leases: one for each lease that began, was renewed, moved or ended
};

// A name of the zone of a VRF and the addresses that it answers (NodeDns.c)
struct NODE_DNS_NAME {
	char Name[NODE_DNS_NAME_SIZE];               // The name, relative to the suffix of the zone, in lower case
	UINT NumAddresses;                           // Its addresses
	UCHAR Addresses[NODE_DNS_MAX_ADDRESSES][16]; // ... 4 bytes for IPv4, 16 for IPv6
	UINT AddressSizes[NODE_DNS_MAX_ADDRESSES];   // ... the number of the bytes of each
};

// The zone of a VRF as the stub resolver answers it (NodeDnsAnswer): the records of the zone that the desired state
// carries, then the name of the node and of each of its peers with their addresses in the VRF
struct NODE_DNS_ZONE {
	UINT VrfId;                      // The VRF
	char Suffix[NODE_DNS_NAME_SIZE]; // Its suffix, in lower case, without a dot at either end
	UINT Serial;                     // The serial of its SOA: the Generation of the state
	bool Via6;                       // The host reaches the IPv4 of the VRF through 4via6 (ADR-0025 decision 4) ...
	UCHAR Via6Prefix[12];            // ... in this /96: an IPv4 address of a name answers in an AAAA record, after it
	UINT NumNames;                   // The names
	NODE_DNS_NAME *Names;            // ...
};

// What NodeDnsGetStatus reports
struct NODE_DNS_STATUS {
	UINT NumZones;      // The zones of the state applied last
	UINT NumAddresses;  // The addresses of the node in their VRFs that the stub resolver listens on ...
	UINT NumListening;  // ... those it listens on now
	bool Ready;         // ... and it listens on every one of them, of the state applied last
	UINT NumRules;      // The NRPT rules that the node wrote: one per zone that it holds an address in
	bool GroupPolicy;   // The NRPT of Group Policy holds rules, so the node writes its rules there too
	UINT64 Queries;     // The queries that it answered from a zone ...
	UINT64 NameErrors;  // ... of them with NXDOMAIN
	UINT64 Refused;     // The queries for a name outside the suffix of the zone of their address, which it refused
	UINT64 Dropped;     // The datagrams that it answered from no zone: no query, one that does not parse, or one too large
	UINT LastBindError; // The error of the last bind of an address that failed, 0 for none
};

// What NodeListenerGetStatus reports (SDN-45, #238)
struct NODE_LISTENER_STATUS {
	// The Listener of the state applied last, "" for none, and the source of its certificate (CONTROL_CERT_*)
	char Name[MAX_SIZE];
	UINT Source;
	// The front door listens on the TCP port Port, and QUIC on the UDP port QuicPort: 0 where msquic.dll is missing
	bool Running;
	UINT Port;
	UINT QuicPort;
	// TCP 443 was taken, so the front door listens on NODE_LISTENER_FALLBACK
	bool Fallback;
	// The certificate of both, by its thumbprint, "" while none runs
	char Thumbprint[MAX_SIZE];
	// The decoy that the TLS of the new protocol runs with (AUD1-DT-4, #452), "" for none
	char Decoy[MAX_SIZE];
	// Why the listeners do not run, "" while they do or no Listener asks for them
	char Error[MAX_SIZE];
	// The streams that the overlay took from the listeners
	UINT64 Accepted;
	// The runs of the ACME sidecar, and the certificates of ACME that the listeners took
	UINT64 AcmeRuns;
	UINT64 AcmeIssued;
	// What the limits for a source of the two listeners refused, since the node started (AUD1-DT-3, #451): the front door
	// on TCP, QUIC on UDP, where msquic.dll is present (HasQuic), and what msquic does about a flood of Initial packets
	SOURCE_LIMIT_STATS FrontDoorLimits;
	bool HasQuic;
	SOURCE_LIMIT_STATS QuicLimits;
	UINT QuicRetryMemoryLimit; // The retry setting of msquic, read back from it
	bool QuicRetrying;         // msquic answers new connections with a retry now
	UINT64 QuicRetries;        // The retry packets that msquic sent
	// The XDP datapath of msquic and QTIP (NodeQtip.c; CORE-S7-2, #83): the datapath that the QUIC of the Listener asks msquic
	// for (TRANSPORT_QUIC_DATAPATH_*), the port of the QTIP listener, TCP and UDP, 0 while it does not listen, and why it does
	// not while the Qtip setting asks for it, "" otherwise
	UINT QuicDatapath;
	UINT QtipPort;
	char QtipError[MAX_SIZE];
};

// What NodeGetStatus reports
struct NODE_STATUS {
	bool Running;      // Between NodeStart and NodeStop
	UINT Roles;        // The running roles (NODE_ROLE_*)
	UINT NumWorkers;   // Running workers
	UINT NumQueues;    // Attached adapter queues
	UINT NumReaders;   // Registered table readers
	UINT NumHubs;      // Hubs of the server role
	UINT64 Generation; // The generation of the current table snapshot, 0 when there is none

	// The relay role
	USHORT RelayPort;              // Its UDP port, 0 while it does not run
	UCHAR RelayKey[PEER_KEY_SIZE]; // Its static key: the public half of the identity key
	UINT RelayBindings;            // The nodes bound to it
	UINT64 RelayBinds;             // The binds it took
	UINT64 RelayForwarded;         // The datagrams it forwarded

	// The mimicry sidecars of the mimic transport (NodeMimic.c; CORE-P2-6, #406), by role (NODE_MIMIC_ROLE_*)
	NODE_MIMIC_STATUS Mimic[NODE_MIMIC_NUM_ROLES];
};

// The Login of a Noise session of the new core (Core/Noise.h)
struct NOISE_LOGIN;

// A desired state of a node as the control stream applies it (Core/Control.h)
struct CONTROL_STATE;

// What NodeBgpGetStatus reports
struct NODE_BGP_STATUS {
	bool Running;           // The sidecar runs and BGP started (it sent ready)
	UINT ProcessId;         // The process of the sidecar, 0 when none runs
	UINT NumPeers;          // The peers of the settings
	UINT NumEstablished;    // ... whose session is established
	UINT NumAnnounced;      // The prefixes the node announces
	UINT NumRoutes;         // The learned routes installed through IP Helper
	UINT NumErrors;         // Error messages of the sidecar so far
	char Version[MAX_SIZE]; // What the sidecar named in ready: ranz bgp and its GoBGP
	char PipeAcl[MAX_SIZE]; // The DACL of the pipe to the sidecar as the system holds it, in SDDL
};

// One process mitigation of the node (NodeHarden.c; ADR-0039 decision 2)
struct NODE_MITIGATION {
	char *Name;  // Its name in the node log
	UINT Policy; // The PROCESS_MITIGATION_POLICY of SetProcessMitigationPolicy
	UINT Flags;  // The bits of the policy structure that the node sets
	char *Off;   // NULL when the node sets it; else why a feature of the node cannot run under it
};

// What NodeWireGuardGetStatus reports (SDN-80, #375)
struct NODE_WIREGUARD_STATUS {
	// wireguard.dll loads
	bool Available;
	// The node has its WireGuard key pair, and Key is its public key, which its Hello reports
	bool HasKey;
	UCHAR Key[NODE_WIREGUARD_KEY_SIZE];
	// Its WireGuard interface is up, on the UDP port Port, with the index and the LUID of its interface
	bool Up;
	UINT Port;
	UINT InterfaceIndex;
	UINT64 InterfaceLuid;
	// The Devices that the interface terminates, and the routes of their addresses through it
	UINT NumDevices;
	UINT NumRoutes;
	// Windows does not forward between two Devices on the interface (NodeWireGuardFilter.c) but for the pairs of Devices
	// that the policy lets meet, NumPairs of them
	bool Isolated;
	UINT NumPairs;
};

// What NodeMirrorGetStatus reports: the copies of the Mirrors since the first Generation of the overlay that had one
struct NODE_MIRROR_STATUS {
	UINT64 Copied;  // Copies that went to a sensor
	UINT64 Limited; // Copies that the rate limit of their Mirror dropped
	UINT64 Failed;  // Copies that could not go: a packet too large for a VXLAN frame, a VNI of more than 24 bits, a failed send
};

// Node.c
NODE *NewNode(wchar_t *data_dir);
void FreeNode(NODE *n);
bool NodeStart(NODE *n);
void NodeStop(NODE *n);
UINT NodeSetRoles(NODE *n, UINT roles);
void NodeGetStatus(NODE *n, NODE_STATUS *st);
HUB *NodeGetHub(NODE *n, char *name);
bool NodeAuthenticate(NODE *n, char *hubname, AUTH_REQUEST *req, AUTH_RESULT *ret);
bool NodeLogin(NODE *n, struct NOISE_LOGIN *login, UCHAR *challenge, AUTH_RESULT *ret);
bool NodeLoginPinned(NODE *n, struct NOISE_LOGIN *login, UCHAR *challenge, UCHAR *static_key, AUTH_RESULT *ret);
void NodeSetPeers(NODE *n, PEER_INFO *peers, UINT num);
void NodeGetLogLimits(NODE *n, UINT *days, UINT *mb);
UINT NodeParseRoles(char *str, char *unknown, UINT unknown_size);
void NodeRolesToStr(char *str, UINT size, UINT roles);
void NodeDefaultDataDir(wchar_t *dir, UINT size);
bool NodeMakeDataDir(wchar_t *dir);

// NodeWorker.c
bool NodePost(NODE *n, UINT index, NODE_WORK_PROC *proc, void *param);
NODE_QUEUE *NodeAddQueue(NODE *n, char *name, HANDLE event, NODE_QUEUE_PROC *proc, void *param);
void NodeDelQueue(NODE *n, NODE_QUEUE *q);

// NodeTable.c
NODE_TABLE *NodeNewTable(NODE_TABLE_ENTRY *entries, UINT num);
void NodeFreeTable(NODE_TABLE *t);
NODE_TABLE_ENTRY *NodeTableLookup(NODE_TABLE *t, UCHAR *key);
void NodeMacKey(UCHAR *key, UINT vlan_id, UCHAR *mac);
NODE_TABLES *NodeNewTables(NODE_TABLE *mac, NODE_TABLE *route, NODE_TABLE *policy);
void NodeFreeTables(NODE_TABLES *t);
NODE_TABLES *NodeGetTables(NODE *n);
bool NodeSwapTables(NODE *n, NODE_TABLES *t);
bool NodeSwapVrfs(NODE *n, NODE_VRF_TABLES *v);
void NodeReaderRegister(NODE *n, NODE_READER *r);
void NodeReaderUnregister(NODE *n, NODE_READER *r);
void NodeReaderQuiescent(NODE *n, NODE_READER *r);
void NodeReaderOffline(NODE_READER *r);
void NodeReaderOnline(NODE *n, NODE_READER *r);

// NodeBgp.c
bool NodeBgpAnnounce(NODE *n, char *prefix, char *next_hop);
bool NodeBgpWithdraw(NODE *n, char *prefix);
bool NodeBgpAnnounceVrf(NODE *n, UINT vrf_id, char *prefix);
bool NodeBgpWithdrawVrf(NODE *n, UINT vrf_id, char *prefix);
void NodeBgpGetStatus(NODE *n, NODE_BGP_STATUS *st);
bool NodeBgpRestart(NODE *n);

// NodeMimic.c, NodeMimicTransport.c
TRANSPORT *NodeMimicTransport(NODE *n);
void NodeMimicGetStatus(NODE *n, UINT role, NODE_MIMIC_STATUS *st);
bool NodeMimicParseMessage(const char *line, NODE_MIMIC_MESSAGE *m);
bool NodeMimicParseBind(const char *line, UCHAR *binding, UINT *size);
UINT NodeMimicParseAnswer(const char *line, UCHAR *binding, UINT *size, char *reason, UINT reason_size);

// NodeDhcp.c
struct CONTROL_DHCP;
struct SWITCH;
NODE_DHCP *NodeDhcpNew(const NODE_DHCP_CONFIG *cfg, UINT64 now);
void NodeDhcpFree(NODE_DHCP *d);
void NodeDhcpSetConfig(NODE_DHCP *d, const NODE_DHCP_CONFIG *cfg, UINT64 now);
void NodeDhcpInput(NODE_DHCP *d, UINT64 now, const UCHAR *frame, UINT size);
UINT NodeDhcpOutput(NODE_DHCP *d, UINT64 now, UCHAR *buf, UINT size);
UINT NodeDhcpGetLeases(NODE_DHCP *d, UINT64 now, NODE_DHCP_LEASE *leases, UINT max);
void NodeDhcpGetStatus(NODE_DHCP *d, UINT64 now, NODE_DHCP_STATUS *st);
void NodeDhcpConfigOf(NODE_DHCP_CONFIG *cfg, const struct CONTROL_DHCP *c, const UCHAR *mac);
bool NodeDhcpAttach(NODE *n, const char *network, struct SWITCH *sw, UINT vlan);
void NodeDhcpDetach(NODE *n, const char *network);
bool NodeDhcpGetNetwork(NODE *n, const char *network, NODE_DHCP_STATUS *st);

// NodeDns.c
NODE_DNS *NodeDnsNew(NODE *n, const UCHAR *key);
void NodeDnsFree(NODE_DNS *d);
void NodeDnsApply(NODE_DNS *d, const struct CONTROL_STATE *st);
void NodeDnsGetStatus(NODE_DNS *d, NODE_DNS_STATUS *st);
UINT NodeDnsAnswer(const NODE_DNS_ZONE *z, const UCHAR *query, UINT size, UCHAR *answer, UINT max, UINT *rcode, char *name, UINT name_size);
bool NodeDnsVia6(const struct CONTROL_STATE *st, UINT vrf_id, UCHAR *prefix);
void NodeDnsRuleName(wchar_t *name, UINT size, const UCHAR *key, UINT vrf_id);

// NodeHarden.c
void NodeHarden();
const NODE_MITIGATION *NodeGetMitigations(UINT *num);

// NodeMirror.c
NODE_MIRROR *NodeNewMirror(VXLAN_SEND_PROC *send, void *send_param);
void NodeFreeMirror(NODE_MIRROR *m);
NODE_MIRROR_TABLE *NodeNewMirrorTable(NODE_MIRROR *m, const struct CONTROL_STATE *st);
void NodeFreeMirrorTable(NODE_MIRROR_TABLE *t);
void NodeMirrorCopy(NODE_VRF_TABLES *v, UINT vrf_id, const UCHAR *packet, UINT size, bool from_host);
void NodeMirrorGetStatus(NODE *n, NODE_MIRROR_STATUS *st);

// NodeVrf.c
NODE_VRF_TABLES *NodeNewVrfTables(UINT64 generation, const NODE_VRF_ROUTE *routes, UINT num, void **hops, UINT num_hops);
void NodeFreeVrfTables(NODE_VRF_TABLES *v);
NODE_VRF_TABLE *NodeGetVrfTable(NODE_VRF_TABLES *v, UINT vrf_id);
UINT NodeVrfLookup(NODE_VRF_TABLE *t, const UCHAR *addr, UINT size);
bool NodeVrfDefault(NODE_VRF_TABLE *t, const UCHAR *addr, UINT size);

// NodeLeak.c
UINT NodeLeakRoutes(const struct CONTROL_STATE *st, NODE_VRF_ROUTE *routes);
NODE_VRF_TABLES *NodeLeakNewTables(const struct CONTROL_STATE *st, const NODE_VRF_ROUTE *routes, UINT num, void **hops);
UINT NodeLeakVrf(NODE_VRF_TABLES *v, UINT hop, UINT vrf_id);

// NodeNat.c
NODE_NAT *NodeNewNat(const struct CONTROL_STATE *st);
void NodeFreeNat(NODE_NAT *nat);
UINT NodeNatRoutes(const struct CONTROL_STATE *st, NODE_VRF_ROUTE *routes);
bool NodeNatEnds(NODE_VRF_TABLES *v, UINT vrf_id, const UCHAR *packet, UINT size, UCHAR *src, UCHAR *dst, UINT *addr_size);
UINT NodeNatCopy(NODE_VRF_TABLES *v, UINT vrf_id, UCHAR *dst, const UCHAR *packet, UINT size);
bool NodeNatInbound(NODE_VRF_TABLES *v, UINT vrf_id, const UCHAR **packet, UINT *size, UCHAR *buf, UINT buf_size);

// NodeOverlay.c
bool NodeOverlayStart(NODE *n, NODE_OVERLAY_CONFIG *cfg);
void NodeOverlayStop(NODE *n);
bool NodeOverlayApply(NODE *n, const struct CONTROL_STATE *st);
bool NodeOverlayInput(NODE *n, UINT vrf_id, const UCHAR *packet, UINT size);
void NodeOverlayGetStatus(NODE *n, NODE_OVERLAY_STATUS *st);
UINT NodeOverlayGetSessions(NODE *n, NODE_OVERLAY_SESSION *list, UINT max, char *listener, UINT listener_size);
UINT NodeOverlayEndpoints(NODE *n, const char *name, struct CONTROL_ENDPOINT *out, UINT max);
struct CONTROL_EVENT;
UINT NodeOverlayGetEvents(NODE *n, struct CONTROL_EVENT *list, UINT max);

// NodeEndpoints.c
UINT NodeEndpointsTargets(const struct CONTROL_ENDPOINT *endpoints, UINT num, TRANSPORT **known, UINT num_known, TRANSPORT_TARGET *targets, UINT max);
bool NodeEndpointsDials(bool by_name, bool dialler, const UCHAR *key, const UCHAR *peer_key, UINT endpoints, bool dialable);

// NodeSession.c
UINT NodeAcceptSession(NODE *n, TRANSPORT_NOISE *s, UINT timeout);

// NodeListener.c
void NodeListenerGetStatus(NODE *n, NODE_LISTENER_STATUS *st);
void NodeListenerRenew(NODE *n);

// NodeClient.c
void NodeClientGetStatus(NODE *n, NODE_CLIENT_STATUS *st);
void NodeClientPower(NODE *n, UINT event);
UINT NodeClientGetAdapters(NODE *n, NODE_VRF_ADAPTER_STATUS *list, UINT max);
void NodeClientServerAddress(NODE *n, const char *address);

// NodeController.c
void NodeControllerGetStatus(NODE *n, NODE_CONTROLLER_STATUS *st);
void NodeControllerPins(NODE *n, const struct CONTROL_STATE *st);
void NodeAdminCommand(NODE *n, char *line, char *reply, UINT size);

// NodeVrfAdapter.c
void NodeVrfAdapterGuid(GUID *guid, const UCHAR *key, UINT vrf_id);
NODE_VRF_ADAPTERS *NodeVrfAdaptersNew(NODE *n, const wchar_t *name, const UCHAR *key, bool forwarding);
void NodeVrfAdaptersFree(NODE_VRF_ADAPTERS *a);
void NodeVrfAdaptersHalt(NODE_VRF_ADAPTERS *a);
void NodeVrfAdaptersSetDns(NODE_VRF_ADAPTERS *a, const char *servers, const char *suffix);
bool NodeVrfAdaptersApply(NODE_VRF_ADAPTERS *a, const struct CONTROL_STATE *st);
bool NodeVrfAdaptersSend(NODE_VRF_ADAPTERS *a, UINT vrf_id, const UCHAR *packet, UINT size);
bool NodeVrfAdaptersHas(NODE_VRF_ADAPTERS *a, UINT64 luid);
UINT NodeVrfAdaptersGetStatus(NODE_VRF_ADAPTERS *a, NODE_VRF_ADAPTER_STATUS *list, UINT max);
NODE_DNS *NodeVrfAdaptersDns(NODE_VRF_ADAPTERS *a);

// NodeWintun.c
bool NodeWintunAvailable(UINT *error);
UINT NodeWintunDriverVersion();
NODE_WINTUN *NodeWintunNew(NODE *n, const wchar_t *name, NODE_WINTUN_PROC *proc, void *param);
NODE_WINTUN *NodeWintunNewGuid(NODE *n, const wchar_t *name, const GUID *requested, NODE_WINTUN_PROC *proc, void *param);
bool NodeWintunSetForwarding(NODE_WINTUN *w, bool on);
void NodeWintunHalt(NODE_WINTUN *w);
void NodeWintunFree(NODE_WINTUN *w);
bool NodeWintunSend(NODE_WINTUN *w, const UCHAR *packet, UINT size);
UINT NodeWintunIndex(NODE_WINTUN *w);
UINT64 NodeWintunLuid(NODE_WINTUN *w);
void NodeWintunCounters(NODE_WINTUN *w, UINT64 *from_host, UINT64 *to_host, UINT64 *dropped);
bool NodeWintunSetAddresses(NODE_WINTUN *w, const NODE_PREFIX *addrs, UINT num);
bool NodeWintunSetRoutes(NODE_WINTUN *w, const NODE_PREFIX *routes, UINT num);
bool NodeWintunSetDns(NODE_WINTUN *w, const char *servers, const char *suffix);

// NodeShape.c
void NodeShapeFreeTable(NODE_SHAPE_TABLE *t);
void NodeShapeGetStatus(NODE *n, NODE_SHAPE_STATUS *st);

// NodePolicy.c
void NodePolicyFreeTable(NODE_POLICY_TABLE *t);
char *NodePolicyDocument(const struct CONTROL_STATE *st);
char *NodePolicyCountersText(NODE *n);
bool NodePolicyGetVrf(NODE *n, const char *vrf, NODE_POLICY_VRF_STATUS *st);

// NodeWireGuard.c
bool NodeWireGuardAvailable(UINT *error);
bool NodeWireGuardKey(const PEER_KEY *key, UCHAR *priv, UCHAR *pub);
void NodeWireGuardGetStatus(NODE *n, NODE_WIREGUARD_STATUS *st);
UINT NodeDeviceRoutes(const struct CONTROL_STATE *st, NODE_VRF_ROUTE *routes);

// NodeOperation.c (SDN-50-N, #492): the L2 data path attaches the switch of an L2 Network, whose MAC table and IP table the
// live operations of the Controller read and clear, and detaches it before it frees it. The procedure of an attached switch
// takes the name of the member of the port port into name of size bytes, "" for none, which the entries of that port carry;
// it runs on the thread of the control stream, while the switch cannot be detached.
typedef void(NODE_PORT_NAME_PROC)(void *param, UINT port, char *name, UINT size);
bool NodeOperationAttach(NODE *n, const char *network, struct SWITCH *sw, NODE_PORT_NAME_PROC *name, void *param);
void NodeOperationDetach(NODE *n, const char *network);

#endif // NODE_H
