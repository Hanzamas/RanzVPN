// NodeTrace.h
// The trace of a packet through the nodes (NodeTrace.c; SDN-89, #388): the declarations that the overlay, the links, the
// forwarding tables and the tests use

#ifndef NODE_TRACE_H
#define NODE_TRACE_H

#include "Node.h"
#include "NodeSourceGroup.h"

#include "Core/Control.h"
#include "Core/Vxlan.h"

// The trace option in the header of a record of frame version 1 of a Noise session (NodeTraceWrite, NodeTraceParse): its
// type NODE_FRAME_TRACE (NodeSourceGroup.h), whose critical bit is clear, the length of its data in 4-byte words, two
// reserved bytes, then the trace ID, big-endian, and the first VXLAN_TRACE_INGRESS bytes of the static key of the ingress
// node
#define NODE_FRAME_TRACE_DATA   12                          // The data of the option: the trace ID and the ingress node
#define NODE_FRAME_TRACE_OPTION (4 + NODE_FRAME_TRACE_DATA) // The option with its header

// The room before the data record of a packet of the host that its record of frame version 1 takes at most: the header,
// the option of the source group and the trace option
#define NODE_TRACE_ROOM (NODE_FRAME_ROOM + NODE_FRAME_TRACE_OPTION)

#define NODE_TRACE_INTERVAL 100 // ms between two packets of one VRF that a node traces as their ingress node, at least

// What NodeTraceGetStatus reports: the packets that a node traced as their ingress node and the records that it made,
// since its overlay started, and the records that wait for its control stream
typedef struct NODE_TRACE_STATUS {
	UINT64 Traced;                               // The packets that the node traced as their ingress node
	UINT64 Recorded;                             // The records of traced packets that it made, as their ingress node and as a node that they reached
	UINT NumRecords;                             // The records that wait for the control stream ...
	CONTROL_TRACE Records[CONTROL_TRACE_QUEUE];  // ... oldest first
} NODE_TRACE_STATUS;

typedef struct NODE_TRACE_TABLE NODE_TRACE_TABLE;
typedef struct NODE_TRACES NODE_TRACES;

// NodeTrace.c
UINT NodeTraceWrite(UCHAR *option, const VXLAN_TRACE *trace);
bool NodeTraceParse(const UCHAR *record, UINT size, VXLAN_TRACE *trace);
const UCHAR *NodeTraceWrap(UCHAR *record, const UCHAR *frame, UINT *frame_size, UINT max, const VXLAN_TRACE *trace);
CONTROL_TRACES *NodeTraceStart(NODE *n, const UCHAR *key);
void NodeTraceStop(NODE *n);
void NodeTraceAttach(NODE *n, NODE_VRF_TABLES *v, const CONTROL_STATE *st);
void NodeFreeTraceTable(NODE_TRACE_TABLE *t);
const UCHAR *NodeTraceOutbound(NODE *n, NODE_VRF_TABLES *v, UINT hop, UINT vrf_id, UCHAR *record, UINT size, const UCHAR *frame, UINT *frame_size, UINT max, bool allowed, bool plain, VXLAN_TRACE *trace);
void NodeTraceInbound(NODE *n, NODE_VRF_TABLES *v, UINT vrf_id, const UCHAR *header, UINT header_size, const NODE_SOURCE_CLAIM *claim, const UCHAR *packet, UINT size, bool ok);
void NodeTraceGetStatus(NODE *n, NODE_TRACE_STATUS *st);

#endif // NODE_TRACE_H
