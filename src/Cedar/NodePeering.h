// NodePeering.h
// The BGP peering of the standard mode of a node (NodePeering.c; SDN-77, #357): the declarations that the overlay and the
// tests use

#ifndef NODE_PEERING_H
#define NODE_PEERING_H

#include "Node.h"

#define NODE_PEERING_LOG_NAME   L"ranz-bgp-peering.log" // The log of the sidecar of the peering, in the node log directory
#define NODE_PEERING_MAX_ROUTES 4096                    // Learned routes that a node holds at most: 32 of each of 64 peers, twice over
#define NODE_PEERING_RESTART    5000                    // ms before a sidecar that ended by itself, or did not start, starts again

typedef struct NODE_PEERING NODE_PEERING;

// What NodePeeringGetStatus reports
typedef struct NODE_PEERING_STATUS {
	bool Configured;        // The Generation in force has a BGP peering of the node
	bool Running;           // Its sidecar runs and BGP started: it sent ready
	UINT ProcessId;         // The process of the sidecar, 0 when none runs
	UINT NumStarts;         // The sidecars that started since the overlay did
	UINT NumPeers;          // The peers of the sidecar
	UINT NumEstablished;    // ... whose session is established
	UINT NumAnnounced;      // The prefixes that the node announces
	UINT NumLearned;        // The routes that it learned
	UINT NumRebuilds;       // The forwarding tables built anew with the routes that it learned
	UINT64 Refused;         // The sessions that the sidecar refused, from an address that no peer has
	UINT NumErrors;         // Error messages of the sidecar
	char Version[MAX_SIZE]; // What the sidecar named in ready: ranz bgp and its GoBGP
	char PipeAcl[MAX_SIZE]; // The DACL of the pipe to the sidecar as the system holds it, in SDDL
} NODE_PEERING_STATUS;

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
UINT NodePeeringRoutes(const struct CONTROL_STATE *st, NODE_VRF_ROUTE *routes);
void NodePeeringGetStatus(NODE *n, NODE_PEERING_STATUS *st);
UINT NodePeeringGetPeers(NODE *n, struct CONTROL_PEERING_PEER *list, UINT max);

// NodeOverlay.c
bool NodeOverlayRebuild(NODE *n, const struct CONTROL_STATE *st);

#endif // NODE_PEERING_H
