// Node.h
// Header of the Node module (Node.c, NodeBgp.c, NodeHarden.c, NodeNat.c, NodeOverlay.c, NodeSession.c, NodeTable.c, NodeVrf.c, NodeWorker.c): the node of the new core

#ifndef NODE_H
#define NODE_H

#include "CedarType.h"
#include "LogWriter.h"

#include "Mayaqua/MayaType.h"

#include "Core/Peer.h"
#include "Core/Transport.h"

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

// The settings of a node in its configuration store
#define NODE_SETTING_ROLES        "Roles"       // A list of role names; without it NODE_DEFAULT_ROLES, "none" for no role
#define NODE_SETTING_WORKERS      "NumWorkers"  // The number of workers; without it, or 0, one per core
#define NODE_SETTING_RELAY_PORT   "RelayPort"   // The UDP port of the relay role; without it, or 0, one that the system picks
#define NODE_SETTING_IDENTITY_KEY "IdentityKey" // The name of the node identity key; without it NODE_IDENTITY_KEY_NAME
#define NODE_SETTING_BGP          "Bgp"         // The BGP settings, one JSON object (NodeBgpStart); without it no BGP sidecar

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

// The forwarding tables of the VRFs of a node (NodeVrf.c; SDN-4, #180)
#define NODE_VRF_LOCAL      0x3FFFFFFF // The next hop of an address of the node itself: the host
#define NODE_VRF_NONE       0xFFFFFFFF // What a lookup gives for an address that no route of the VRF holds
#define NODE_VRF_MAX_ROUTES 65536      // Routes of the tables of one Generation at most
#define NODE_VRF_MAX_HOPS   65536      // Next hops of those tables at most

// 1:1 NAT and 4via6 (NodeNat.c; SDN-6, #182)
#define NODE_NAT_GROWTH 40 // Bytes that the translation of a packet of a peer adds at most: from IPv4 to IPv6, 20 to its header and 20 to the one that an ICMP error quotes

// Runs one work item on a worker, to completion (NodePost)
typedef void(NODE_WORK_PROC)(NODE_WORKER *w, void *param);
// Drains an adapter queue on its I/O thread, to completion (NodeAddQueue)
typedef void(NODE_QUEUE_PROC)(NODE_QUEUE *q, void *param);
// Takes an IP packet of the overlay for the host in the VRF vrf_id (NodeOverlayStart), on the thread of the overlay
typedef void(NODE_ADAPTER_PROC)(NODE *n, void *param, UINT vrf_id, const UCHAR *packet, UINT size);

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

	// The BGP sidecar (CORE-S7-1, #82), under Lock
	char *ConfigBgp;              // The BGP settings of the configuration (NODE_SETTING_BGP), NULL for none
	wchar_t BgpSidecar[MAX_PATH]; // The executable that holds the sidecar: NODE_BGP_EXE_NAME next to the executable; a test may name another before NodeStart
	NODE_BGP *Bgp;                // The running BGP sidecar (NodeBgp.c), NULL when none runs

	// The overlay (NodeOverlay.c; SDN-3, #179), NULL while it does not run
	NODE_OVERLAY *Overlay;
};

// How the overlay of a node runs (NodeOverlayStart)
struct NODE_OVERLAY_CONFIG {
	TRANSPORT *Control;                      // The transport of the control stream to the controller (Core/Control.h), NULL for none: NodeOverlayApply then applies the states
	char Controller[TRANSPORT_ADDRESS_SIZE]; // The controller's address on it
	UCHAR ControllerKey[PEER_KEY_SIZE];      // ... and its static key
	TRANSPORT *Data;                         // The transport of the Noise sessions to the peers, which finds a peer by its node name
	PEER_KEY *Key;                           // The node's static key, which must outlive the overlay
	NODE_ADAPTER_PROC *Adapter;              // Takes the packets for the host, NULL for none
	void *AdapterParam;                      // ... and its second parameter
};

// What NodeOverlayGetStatus reports
struct NODE_OVERLAY_STATUS {
	bool Connected;                             // The control stream is open
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
void NodeBgpGetStatus(NODE *n, NODE_BGP_STATUS *st);

// NodeHarden.c
void NodeHarden();
const NODE_MITIGATION *NodeGetMitigations(UINT *num);

// NodeVrf.c
NODE_VRF_TABLES *NodeNewVrfTables(UINT64 generation, const NODE_VRF_ROUTE *routes, UINT num, void **hops, UINT num_hops);
void NodeFreeVrfTables(NODE_VRF_TABLES *v);
NODE_VRF_TABLE *NodeGetVrfTable(NODE_VRF_TABLES *v, UINT vrf_id);
UINT NodeVrfLookup(NODE_VRF_TABLE *t, const UCHAR *addr, UINT size);

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

// NodeSession.c
UINT NodeAcceptSession(NODE *n, TRANSPORT_NOISE *s, UINT timeout);

#endif // NODE_H
