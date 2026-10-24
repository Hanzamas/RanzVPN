// NodeL2.h
// The L2 adapter of a node (NodeL2.c, NodeL2Xdp.c, NodeL2SeLow.c, NodeKmTest.c; CORE-S3-2, #72): the frames of an L2
// Network on a Microsoft KM-TEST Loopback Adapter (ADR-0018 decision 4), carried between the host's own stack and the
// node by a backend.
//
// - The KM-TEST adapter (NodeKmTest.c): one per Network, with a locally administered MAC address that NodeL2Mac derives
//   from the node's static key and the Network id, so that two adapters on one segment never share one (ADR-0022, KM-TEST
//   details). The node finds the adapter of that address again at its next start, and creates one otherwise.
// - The backend: the driver that carries the frames, behind the small interface NODE_L2_BACKEND (attach, inject, health,
//   detach). XDP for Windows (NodeL2Xdp.c) through its rule API, no eBPF: a program on the TX inspect hook redirects each
//   frame that the host sends out of the adapter to an AF_XDP socket, and a second socket injects on the RX path
//   (ADR-0018 amendment of 2026-10-13). SeLow (NodeL2SeLow.c) is the fallback where XDP is not installed or cannot bind,
//   found at run time (ADR-0022 amendment of 2026-10-15, ADR-0002 amendment of 2026-10-21). A test may give a backend of
//   its own.
// - Two bounded rings. A backend drains what the host sends on a thread of its own, which waits for nothing but its
//   driver, takes no lock, allocates nothing and does no other I/O, into the capture ring (NodeL2Capture); the adapter
//   queue (NodeAddQueue) empties that ring to the owner. A frame that finds the ring full is dropped and counted, never
//   pushed back into the driver, so a lagging owner cannot block the senders of the host (#72, risk R1). What the owner
//   sends (NodeL2Send) goes into the send ring, which one injector thread hands to the backend in batches: once Batch
//   frames are there, or once the flush time passed after the first (ADR-0022 amendment of 2026-10-19).
// - Health (#72, risk R3): once a second the injector asks the backend whether its binding works, and probes the
//   receive path of the host with a Neighbor Solicitation of its own: the host must learn the address of the probe within
//   NODE_L2_STALL ms. A failure detaches the backend and attaches it again; after NODE_L2_RESETS failed attempts in a row
//   the owner resets the adapter (NODE_L2_RESET_PROC). Each recovery goes to the node log, the Event Log and the ETW
//   provider of Debug(), with the counters.
// - Shutdown, each step within NODE_L2_STOP_WAIT (#72, risk R2): the injector stops, the backend waits for what it
//   injected to complete, closes its program and sockets and joins its drain thread, then the adapter queue goes. The
//   node never unbinds a driver: ranz uninstall does.
// - arm64 is L3 only: there is no production-signed XDP runtime and no SeLow package for it (ADR-0022 amendment of
//   2026-10-21), so no L2 adapter is offered there (NodeL2Offered).

#ifndef NODE_L2_H
#define NODE_L2_H

#include "CedarType.h"

#include "Mayaqua/MayaType.h"

// Bytes of a frame at most, without the FCS: 1500 bytes of payload with a VLAN tag, the largest frame that SeLow takes
// (SL_MAX_PACKET_SIZE)
#define NODE_L2_MAX_FRAME 1600
// Bytes of the shortest frame: the two MAC addresses and the EtherType
#define NODE_L2_MIN_FRAME 14
// Frames of each ring of an adapter without NODE_L2_CONFIG.Slots
#define NODE_L2_SLOTS 2048
// Frames that the injector hands the backend at once without NODE_L2_CONFIG.Batch, and at most
#define NODE_L2_BATCH     64
#define NODE_L2_MAX_BATCH 256
// Microseconds that the injector waits for a batch to fill without NODE_L2_CONFIG.FlushUs
#define NODE_L2_FLUSH_US 20
// NODE_L2_CONFIG.FlushUs for an injector that never waits for a batch to fill
#define NODE_L2_NO_FLUSH 0xFFFFFFFF
// Frames that the adapter queue hands the owner in one run, before a quiescent point
#define NODE_L2_DELIVER 256
// ms between two health checks of the backend
#define NODE_L2_HEALTH 1000
// ms without progress that is a stall: of the completions of injected frames, or of the answer to a probe
#define NODE_L2_STALL 2000
// ms between two probes of the receive path of the host
#define NODE_L2_PROBE 5000
// Failed attaches in a row after which the owner resets the adapter
#define NODE_L2_RESETS 2
// ms that each step of a shutdown or a detach waits at most
#define NODE_L2_STOP_WAIT 5000
// Backends that an adapter tries at most
#define NODE_L2_MAX_BACKENDS 4
// What the name that NodeL2Mac hashes begins with, before the node's static key and the Network id
#define NODE_L2_MAC_LABEL "ranz l2 adapter"
// The Event Log source and the event id of a recovery: after the MS_EVENT_* ids of the service (Mayaqua/Microsoft.h)
#define NODE_L2_EVENT_SOURCE   "ranzvpnserver"
#define NODE_L2_EVENT_RECOVERY 10

// The types of the L2 adapter. NODE_L2_RING, a ring of frames, and NODE_KMTEST, a KM-TEST adapter, are their files' own.
typedef struct NODE_L2 NODE_L2;
typedef struct NODE_L2_BACKEND NODE_L2_BACKEND;
typedef struct NODE_L2_CONFIG NODE_L2_CONFIG;
typedef struct NODE_L2_STATUS NODE_L2_STATUS;
typedef struct NODE_L2_RING NODE_L2_RING;
typedef struct NODE_KMTEST NODE_KMTEST;

// Takes a frame that the host sent out of the adapter, on the I/O thread of the adapter queue. The frame stays valid
// during the call only; the procedure may call NodeL2Send.
typedef void(NODE_L2_PROC)(NODE_L2 *a, void *param, const UCHAR *frame, UINT size);
// Resets the KM-TEST adapter after failed attaches, and gives the index of its interface afterwards; false when it could not
typedef bool(NODE_L2_RESET_PROC)(void *param, UINT *if_index);

// The procedures of a backend. Attach binds to the adapter (NODE_L2.IfIndex, Luid, Guid) and starts the drain thread
// that hands each frame that the host sends to NodeL2Capture; false, with why in error, when it cannot bind. Inject
// hands num frames to the host as frames received on the adapter, on the injector thread only, and returns how many it
// took. Healthy tells whether the binding works, on the injector thread. Detach waits up to timeout ms for what it
// injected to complete, closes the binding and joins the drain thread; false when a step did not finish in time.
typedef bool(NODE_L2_ATTACH_PROC)(NODE_L2 *a, char *error, UINT error_size);
typedef UINT(NODE_L2_INJECT_PROC)(NODE_L2 *a, const UCHAR **frames, const UINT *sizes, UINT num);
typedef bool(NODE_L2_HEALTHY_PROC)(NODE_L2 *a);
typedef bool(NODE_L2_DETACH_PROC)(NODE_L2 *a, UINT timeout);

// A backend of the L2 adapter: XDP (NodeL2XdpBackend) or SeLow (NodeL2SeLowBackend), or one of a test. Its state is
// NODE_L2.BackendState, which Attach sets and Detach frees.
struct NODE_L2_BACKEND {
	// Its name in the node log and in the status: "xdp" or "selow"
	char *Name;
	NODE_L2_ATTACH_PROC *Attach;
	NODE_L2_INJECT_PROC *Inject;
	NODE_L2_HEALTHY_PROC *Healthy;
	NODE_L2_DETACH_PROC *Detach;
};

// How an L2 adapter runs (NodeL2New); a value of 0 or NULL takes the default
struct NODE_L2_CONFIG {
	// The interface index of the KM-TEST adapter (NodeKmTestIndex); 0 for none, with a backend of a test
	UINT IfIndex;
	// Takes each frame that the host sends, with its second parameter
	NODE_L2_PROC *Proc;
	void *Param;
	// Resets the adapter after NODE_L2_RESETS failed attaches (NodeKmTestReset with the KM-TEST adapter), with its first
	// parameter; NULL for an adapter that cannot be reset
	NODE_L2_RESET_PROC *Reset;
	void *ResetParam;
	// The backends to try, in this order, until one binds; NULL for XDP, then SeLow
	const NODE_L2_BACKEND *const *Backends;
	UINT NumBackends;
	// Frames of each ring, a power of two from NODE_L2_MAX_BATCH on; 0 for NODE_L2_SLOTS
	UINT Slots;
	// Frames that the injector hands the backend at once, up to NODE_L2_MAX_BATCH; 0 for NODE_L2_BATCH
	UINT Batch;
	// Microseconds that the injector waits for a batch to fill; 0 for NODE_L2_FLUSH_US, NODE_L2_NO_FLUSH for none
	UINT FlushUs;
	// Entries of each ring of the driver (the AF_XDP rings of XDP), a power of two; 0 for the backend's own
	UINT BackendRing;
	// No probe of the receive path of the host: for a backend of a test, whose frames reach no host
	bool NoProbe;
};

// An L2 adapter: a KM-TEST adapter, the backend that carries its frames, and the two rings between them and the owner
struct NODE_L2 {
	NODE *Node;
	// The interface of the adapter: its index, LUID, GUID and MAC address, as Windows reports them
	UINT IfIndex;
	UINT64 Luid;
	GUID Guid;
	UCHAR Mac[6];
	// The owner: NODE_L2_CONFIG.Proc, Param, Reset and ResetParam
	NODE_L2_PROC *Proc;
	void *Param;
	NODE_L2_RESET_PROC *Reset;
	void *ResetParam;
	// The backends to try and the one attached (NULL while none is), with its state
	const NODE_L2_BACKEND *Backends[NODE_L2_MAX_BACKENDS];
	UINT NumBackends;
	const NODE_L2_BACKEND *Backend;
	void *BackendState;
	// The settings of the configuration, with the defaults filled in
	UINT Batch;
	UINT FlushUs;
	UINT BackendRing;
	bool NoProbe;
	// The capture ring, from the backend to the owner, and the adapter queue that empties it; its event is auto-reset
	NODE_L2_RING *Captures;
	HANDLE CaptureEvent;
	NODE_QUEUE *Queue;
	// The send ring, from the owner to the backend, and the injector thread that empties it; its event is auto-reset, and
	// SendIdle is 1 while the injector waits for it
	NODE_L2_RING *Sends;
	HANDLE SendEvent;
	volatile LONG SendIdle;
	HANDLE Injector;
	volatile LONG Halt;
	// A recovery that NodeL2Recover asked the injector for, and the event that it signals once it ran
	volatile LONG RecoverAsked;
	volatile LONG RecoverResult;
	HANDLE RecoverDone;
	// The injector's own: failed attaches in a row, and the probe of the receive path (NodeL2.c)
	UINT Failures;
	UINT ProbeNumber;
	UINT64 ProbeSent;
	UINT64 NextProbe;
	UCHAR ProbeMac[6];
	volatile LONG ProbeOutstanding;
	// The counters (NODE_L2_STATUS)
	volatile LONG64 Captured;
	volatile LONG64 CaptureDrops;
	volatile LONG64 Delivered;
	volatile LONG64 Sent;
	volatile LONG64 SendDrops;
	volatile LONG64 Injected;
	volatile LONG64 InjectDrops;
	volatile LONG64 Batches;
	volatile LONG64 Oversize;
	volatile LONG64 Probes;
	volatile LONG64 ProbeFailures;
	volatile LONG64 Reattaches;
	volatile LONG64 Resets;
};

// What NodeL2GetStatus reports
struct NODE_L2_STATUS {
	// The backend attached ("xdp", "selow"), empty while none is
	char Backend[16];
	UINT IfIndex;
	UCHAR Mac[6];
	// Frames of the host that the backend captured into the ring, and that found the ring full
	UINT64 Captured;
	UINT64 CaptureDrops;
	// ... that the adapter queue handed the owner
	UINT64 Delivered;
	// Frames that the owner sent into the ring, and that found the ring full
	UINT64 Sent;
	UINT64 SendDrops;
	// ... that the backend took for the host, and that it refused
	UINT64 Injected;
	UINT64 InjectDrops;
	// The batches that the injector handed the backend
	UINT64 Batches;
	// Frames longer than NODE_L2_MAX_FRAME or shorter than NODE_L2_MIN_FRAME, dropped
	UINT64 Oversize;
	// Probes of the receive path of the host, and the ones that the host did not take within NODE_L2_STALL
	UINT64 Probes;
	UINT64 ProbeFailures;
	// Times that the backend was detached and attached again, and that the adapter was reset
	UINT64 Reattaches;
	UINT64 Resets;
};

// NodeL2.c
bool NodeL2Offered(UINT machine);
void NodeL2Mac(UCHAR *mac, const UCHAR *key, UINT network_id);
NODE_L2 *NodeL2New(NODE *n, const NODE_L2_CONFIG *cfg);
bool NodeL2Free(NODE_L2 *a);
bool NodeL2Send(NODE_L2 *a, const UCHAR *frame, UINT size);
bool NodeL2Capture(NODE_L2 *a, const UCHAR *frame, UINT size);
void NodeL2CaptureDone(NODE_L2 *a);
bool NodeL2Recover(NODE_L2 *a);
void NodeL2GetStatus(NODE_L2 *a, NODE_L2_STATUS *st);

// NodeL2Xdp.c
const NODE_L2_BACKEND *NodeL2XdpBackend();
UINT NodeL2XdpQueues(UINT if_index, UINT max, char *error, UINT error_size);

// NodeL2SeLow.c
const NODE_L2_BACKEND *NodeL2SeLowBackend();

// NodeKmTest.c
NODE_KMTEST *NodeKmTestNew(NODE *n, const UCHAR *mac);
void NodeKmTestFree(NODE_KMTEST *k, bool remove);
UINT NodeKmTestIndex(NODE_KMTEST *k);
bool NodeKmTestReset(void *param, UINT *if_index);

#endif // NODE_L2_H
