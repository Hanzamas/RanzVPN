// NodeExit.h
// The exit node of the client role (NodeExit.c; SDN-55, #248): the declarations that the overlay, the forwarding tables, the
// client role and the tests use

#ifndef NODE_EXIT_H
#define NODE_EXIT_H

#include "Node.h"

#define NODE_EXIT_MAX       32 // Exit nodes that the tables of one Generation hold at most: the peers with a default route in a VRF
#define NODE_EXIT_NAME_SIZE 64 // The name of a VRF with its NUL (CONTROL_NAME_SIZE of Core/Control.h)
#define NODE_EXIT_SERVERS   16 // Addresses of the servers of the role that it keeps a bypass route for at most

typedef struct NODE_EXIT NODE_EXIT;
typedef struct NODE_EXIT_TABLE NODE_EXIT_TABLE;

// An exit node of a state: a peer that holds the default route of a VRF
typedef struct NODE_EXIT_ENTRY {
	char Name[PEER_NAME_SIZE];         // The node name of the peer
	UINT VrfId;                        // The VRF ...
	char VrfName[NODE_EXIT_NAME_SIZE]; // ... and its name in the state, "" for none
	UINT Hop;                          // The next hop of the peer in the forwarding tables of the state
	bool Ipv4;                         // It holds 0.0.0.0/0 in the VRF ...
	bool Ipv6;                         // ... and ::/0
} NODE_EXIT_ENTRY;

// What the overlay keeps of one state for the exit nodes while it applies it (NodeExitFilter): its exit nodes, and the copy
// of the state without the default routes of the peers that the overlay applies in its place
typedef struct NODE_EXIT_STATE {
	UINT NumExits;
	NODE_EXIT_ENTRY Exits[NODE_EXIT_MAX];
	struct CONTROL_STATE *Copy; // NULL when the state holds no default route of a peer
	struct CONTROL_PEER *Peers; // ... and the peers of the copy
} NODE_EXIT_STATE;

// NodeExit.c
NODE_EXIT *NodeExitNew(NODE *n, NODE_VRF_ADAPTERS *adapters);
void NodeExitFree(NODE_EXIT *e);
NODE_EXIT_STATE *NodeExitFilter(NODE_EXIT *e, const struct CONTROL_STATE **st);
void NodeExitFreeState(NODE_EXIT_STATE *x);
void NodeExitAttach(NODE_EXIT *e, NODE_VRF_TABLES *v, const NODE_EXIT_STATE *x);
void NodeExitFreeTable(NODE_EXIT_TABLE *t);
UINT NodeExitHop(NODE_VRF_TABLES *v, UINT vrf_id, UINT hop, const UCHAR *addr, UINT addr_size, bool from_host);
void NodeExitApplied(NODE_EXIT *e);
bool NodeExitChoose(NODE_EXIT *e, const char *name, UINT vrf_id, bool any_vrf, char *error, UINT error_size);
void NodeExitClear(NODE_EXIT *e);
void NodeExitSetDown(NODE_EXIT *e, bool down);
void NodeExitAddServer(NODE_EXIT *e, const char *address);
void NodeExitDial(NODE_EXIT *e);
void NodeExitRoam(NODE_EXIT *e);
struct cJSON;
void NodeExitJson(NODE_EXIT *e, struct cJSON *o);
void NodeExitGetStatus(NODE_EXIT *e, NODE_CLIENT_STATUS *st);

#endif // NODE_EXIT_H
