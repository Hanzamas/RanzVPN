// NodeAgent.h
// The peer agent of the overlay of a node (NodeAgent.c; CORE-S5-5, #411; CORE-S5-6, #412): the declarations that the overlay,
// the state of the node and the tests use

#ifndef NODE_AGENT_H
#define NODE_AGENT_H

#include "Node.h"

#define NODE_AGENT_TICK       100   // ms between two runs of the thread of the agent: the timers of its peer layer and its offers
#define NODE_AGENT_SIGNAL     2000  // ms before the agent offers a Signal again to a peer that did not answer the first ...
#define NODE_AGENT_SIGNAL_MAX 60000 // ... and at most: the delay doubles after each offer without an answer
#define NODE_AGENT_THREADS    2     // The receive threads that hand the agent its datagrams: its socket's, or the network's of a test
#define NODE_AGENT_HOSTS      30000 // ms between two reads of the host addresses of its UDP socket: its host candidates with ICE

// With ICE, ms from the failure of the session of a pair on the Relay to the offer that starts a new one, as after a Fallback ...
#define NODE_AGENT_ICE_RETRY 20000
// ... and at most: the delay doubles while the new sessions fail too, and is NODE_AGENT_ICE_RETRY again once one is up
#define NODE_AGENT_ICE_RETRY_MAX 1800000
// With punching, ms between two looks of the thread for a punch that is due (CORE-S5-7, #413)
#define NODE_AGENT_PUNCH 1000

typedef struct NODE_AGENT NODE_AGENT;

// What NodeAgentGetStatus reports
typedef struct NODE_AGENT_STATUS {
	bool Running;          // The peer layer runs: a desired state named a Relay
	bool Ice;              // ICE moves the peers of the datagram path to a direct path once it validates one (CORE-S5-6, #412)
	USHORT Port;           // The UDP port of its socket, 0 on the network of a test
	UINT NumRelays;        // The Relays of the state applied last
	UINT64 SignalsSent;    // The Signals that the agent gave the control stream: offers and answers
	UINT64 SignalsTaken;   // The Signals of peers that it took
	UINT64 SignalsDropped; // ... and that it dropped: forged or altered, replayed, of no peer, or with no peer layer to take them
	UINT64 Delivered;      // The records of peers that it handed to the overlay
	PEER_STATS Peer;       // The counters of its peer layer
} NODE_AGENT_STATUS;

// NodeAgent.c
struct CONTROL_SIGNALS *NodeAgentStart(NODE *n, const NODE_OVERLAY_CONFIG *cfg);
void NodeAgentStop(NODE *n);
void NodeAgentApply(NODE *n, const struct CONTROL_STATE *st);
void NodeAgentSignal(void *param, const char *peer, const UCHAR *envelope, UINT size);
bool NodeAgentDatagramOnly(NODE *n, UINT own, UINT peer);
void NodeAgentDialFailed(NODE *n, const UCHAR *key);
bool NodeAgentHasPath(NODE *n, const UCHAR *key);
bool NodeAgentSend(NODE *n, const UCHAR *key, const UCHAR *record, UINT size);
void NodeAgentSessions(NODE *n, NODE_OVERLAY_SESSION *list, UINT num);
void NodeAgentGetStatus(NODE *n, NODE_AGENT_STATUS *st);
const char *NodeAgentPathName(UINT path);
struct CONTROL_PATHS *NodeAgentPaths(NODE *n);
const char *NodeAgentPortMapName(UINT state);

// NodeOverlay.c
void NodeOverlayAgentDeliver(NODE *n, const UCHAR *key, const UCHAR *record, UINT size, UCHAR *nat_buf);

#endif // NODE_AGENT_H
