// NodeGateway.h
// Gateway HA and hub-and-spoke in the overlay of a node (NodeGateway.c; SDN-19, #195): the declarations that the overlay,
// the forwarding tables, the tests and the fuzz target use

#ifndef NODE_GATEWAY_H
#define NODE_GATEWAY_H

#include "Node.h"

#define NODE_GATEWAY_PROBE      100 // ms between two probes of a gateway, on its Noise session or on the datagram path
#define NODE_GATEWAY_DEAD       500 // ms that a probe waits for its answer before its gateway is down: under one second (#195)
#define NODE_GATEWAY_RISE       3   // Answers in a row to fresh probes that bring a gateway that is down and that the node reaches up
#define NODE_GATEWAY_MAX_GROUP  16  // Gateways of one prefix at most, in the order of the peers
#define NODE_GATEWAY_PROBE_SIZE 13  // Bytes of a probe and of its answer: the kind, the sequence and the time of the prober

// The kinds of the control records between two peers that the probes are: the first byte of the record
#define NODE_GATEWAY_PROBE_ASK    1 // A probe, which the peer answers at once
#define NODE_GATEWAY_PROBE_ANSWER 2 // The answer to a probe, with its sequence and its time

// A control record on the datagram path of the peer agent, which has no kinds of records (NodeAgent.c; SDN-19-R1, #507): the
// VRF tag of no VRF, 0, which no data record has, then this kind, then the control record
#define NODE_GATEWAY_DATAGRAM      0xFF
#define NODE_GATEWAY_DATAGRAM_SIZE (NODE_OVERLAY_VRF_TAG + 1 + NODE_GATEWAY_PROBE_SIZE) // ... of a probe or its answer

typedef struct NODE_GATEWAY NODE_GATEWAY;
typedef struct NODE_GATEWAY_TABLE NODE_GATEWAY_TABLE;

// A probe or its answer as NodeGatewayParseProbe reads it
typedef struct NODE_GATEWAY_PROBE_MSG {
	UINT Kind;     // NODE_GATEWAY_PROBE_ASK or NODE_GATEWAY_PROBE_ANSWER
	UINT Sequence; // The number of the probe
	UINT64 Time;   // When the prober sent it, in its own ms
} NODE_GATEWAY_PROBE_MSG;

// What NodeGatewayGetStatus reports: the gateways since the overlay started
typedef struct NODE_GATEWAY_STATUS {
	UINT NumProbed;      // The gateways that the node probes: those of a group of the tables that hold them
	UINT NumUp;          // ... of them up
	UINT64 Probes;       // Probes sent
	UINT64 PathProbes;   // ... of them on the datagram path of the peer agent (SDN-19-R1, #507)
	UINT64 Answers;      // Answers to them taken
	UINT64 Answered;     // Probes of the peers answered
	UINT64 PathAnswered; // ... of them on the datagram path
	UINT64 Failovers;    // Times a gateway went down: its traffic moved to another one of its groups
	UINT64 Recoveries;   // Times one came up again
	UINT64 Transit;      // Packets of one spoke that the node, the hub of their VRF, sent on to another
} NODE_GATEWAY_STATUS;

// What NodeGatewayGetPeer reports of one gateway
typedef struct NODE_GATEWAY_PEER_STATUS {
	bool Probed;       // It is a gateway of a group of the tables that hold it, so the node probes it
	bool Up;           // The node reaches it and it answers its probes
	bool Datagram;     // The node reaches it on the datagram path of the peer agent alone, without a Noise session
	UINT64 LastAnswer; // When it answered last, or its session came up (GetTickCount64)
	UINT64 DownSince;  // When it went down last, 0 before
	UINT64 Failovers;  // The times it went down
	UINT64 Picked;     // The packets of the host that its groups gave it
} NODE_GATEWAY_PEER_STATUS;

// NodeGateway.c
UINT NodeGatewayRoutes(const struct CONTROL_STATE *st, NODE_VRF_ROUTE *routes);
UINT NodeGatewayGroups(const struct CONTROL_STATE *st, void **peers, void **hops);
void NodeGatewayGroupRoutes(const struct CONTROL_STATE *st, NODE_VRF_ROUTE *routes, UINT num);
void NodeGatewayStart(NODE *n);
void NodeGatewayStop(NODE *n);
void NodeGatewayAttach(NODE *n, NODE_VRF_TABLES *v, const struct CONTROL_STATE *st);
void NodeFreeGatewayTable(NODE_GATEWAY_TABLE *t);
UINT NodeGatewayPick(NODE_VRF_TABLES *v, UINT hop, const UCHAR *packet, UINT size);
UINT NodeGatewayFrom(NODE_VRF_TABLES *v, UINT from, const void *peer);
bool NodeGatewayHub(NODE_VRF_TABLES *v, UINT vrf_id);
bool NodeGatewayTransit(NODE *n, NODE_VRF_TABLES *v, UINT vrf_id, UINT from, UINT to, UINT source_group, const UCHAR *record, UINT size);
void NodeGatewayProbe(NODE *n);
void NodeGatewayControl(NODE *n, void *peer, const UCHAR *data, UINT size);
bool NodeGatewayDatagram(NODE *n, const UCHAR *key, const UCHAR *record, UINT size);
void NodeGatewayForget(NODE *n, void *peer);
UINT NodeGatewayFlowHash(const UCHAR *packet, UINT size);
UINT NodeGatewayWriteProbe(UCHAR *buf, UINT kind, UINT sequence, UINT64 time);
bool NodeGatewayParseProbe(const UCHAR *data, UINT size, NODE_GATEWAY_PROBE_MSG *m);
UINT NodeGatewayWriteDatagram(UCHAR *buf, UINT kind, UINT sequence, UINT64 time);
bool NodeGatewayParseDatagram(const UCHAR *record, UINT size, NODE_GATEWAY_PROBE_MSG *m);
void NodeGatewayGetStatus(NODE *n, NODE_GATEWAY_STATUS *st);
bool NodeGatewayGetPeer(NODE *n, const char *name, NODE_GATEWAY_PEER_STATUS *st);

// NodeOverlay.c
bool NodeOverlayPeerUp(void *peer);
bool NodeOverlaySendControl(NODE *n, void *peer, const UCHAR *data, UINT size);
bool NodeOverlaySendRecord(NODE *n, NODE_VRF_TABLES *v, UINT hop, const UCHAR *record, UINT size);

#endif // NODE_GATEWAY_H
