// NodePeering.h
// The BGP peering of the standard mode of a node (NodePeering.c; SDN-77, #357): the declarations that the overlay and the
// tests use

#ifndef NODE_PEERING_H
#define NODE_PEERING_H

#include "Node.h"

#define NODE_PEERING_LOG_NAME L"ranz-bgp-peering.log" // The log of the sidecar of the peering, in the node log directory
#define NODE_PEERING_RESTART  5000                    // ms before a sidecar that ended, or did not start, starts again
#define NODE_PEERING_PING     5000                    // ms after the last answer of the sidecar before the node asks it again whether it runs
#define NODE_PEERING_ANSWER   10000                   // ms within which the sidecar answers that question, or it hangs and the node ends it
#define NODE_PEERING_PROTOCOL 4                       // The protocol of the pipe that the node needs from its sidecar, and ends one of an older protocol (SDN-77-R3, #570)

typedef struct NODE_PEERING NODE_PEERING;

// What NodePeeringGetStatus reports
typedef struct NODE_PEERING_STATUS {
	bool Configured;        // The Generation in force has a BGP peering of the node
	bool Running;           // Its sidecar runs and BGP started: it sent ready
	UINT ProcessId;         // The process of the sidecar, 0 when none runs
	UINT NumStarts;         // The sidecars that started since the overlay did
	UINT NumPeers;          // The peers of the sidecar
	UINT NumEstablished;    // ... whose session is established
	UINT NumNamed;          // ... whose session the sidecar named a state of: the peers that the sidecar has
	UINT NumAnnounced;      // The prefixes that the node announces
	UINT NumLearned;        // The routes that it learned
	UINT NumRebuilds;       // The forwarding tables built anew with the routes that it learned
	UINT NumDeferred;       // ... rebuilds that met an apply of the overlay, counted at once: they wait for it, or take the Generation that it puts in force
	UINT NumFailed;         // ... rebuilds that failed, for no copy of the Generation in force or no tables: each goes again after a while
	UINT NumSettleFailed;   // The settles of the sidecar on a Generation that failed, for no copy of it: each goes again after a while (SDN-77-R3, #570)
	UINT NumUnsent;         // The sidecars that the node ended because a message did not reach them
	UINT NumHung;           // The sidecars that the node ended because they did not answer whether they run
	UINT NumOld;            // The sidecars that the node ended because their protocol is older than NODE_PEERING_PROTOCOL
	UINT64 Refused;         // The sessions that the sidecar refused, from an address that no peer has
	UINT NumErrors;         // Error messages of the sidecar
	char Version[MAX_SIZE]; // What the sidecar named in ready: ranz bgp and its GoBGP
	char PipeAcl[MAX_SIZE]; // The DACL of the pipe to the sidecar as the system holds it, in SDDL
} NODE_PEERING_STATUS;

// What NodeOverlayRebuild did
#define NODE_REBUILD_DONE   0 // The tables of the state went in
#define NODE_REBUILD_BUSY   1 // An apply runs: nothing went in, and the rebuild may try again once it is done
#define NODE_REBUILD_STALE  2 // Another Generation is in force: nothing went in, and the apply of it woke the peering
#define NODE_REBUILD_FAILED 3 // The tables could not be built or installed

struct CONTROL_PEERING_PEER;
struct CONTROL_PEERING_REPORT;
struct CONTROL_STATE;

// NodePeering.c
struct CONTROL_PEERING_REPORT *NodePeeringStart(NODE *n);
void NodePeeringHalt(NODE *n);
void NodePeeringFree(NODE *n);
const struct CONTROL_STATE *NodePeeringWith(NODE *n, const struct CONTROL_STATE *st);
void NodePeeringDone(const struct CONTROL_STATE *with, const struct CONTROL_STATE *st);
void NodePeeringApplied(NODE *n, const struct CONTROL_STATE *st, bool swapped);
void NodePeeringGetStatus(NODE *n, NODE_PEERING_STATUS *st);
UINT NodePeeringGetPeers(NODE *n, struct CONTROL_PEERING_PEER *list, UINT max);
struct CONTROL_PEERING_REPORT *NodePeeringGetReport(NODE *n);
void NodePeeringFailNext(NODE *n, UINT copies, UINT rebuilds, UINT settles);
void NodePeeringFeed(NODE *n, const char *line);

// NodeOverlay.c
UINT NodeOverlayRebuild(NODE *n, const struct CONTROL_STATE *with);

#endif // NODE_PEERING_H
