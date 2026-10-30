// NodeSourceGroup.h
// The source groups of the overlay of a node (NodeSourceGroup.c; SDN-87, #386): the declarations that the overlay, the
// links, the forwarding tables and the tests use

#ifndef NODE_SOURCE_GROUP_H
#define NODE_SOURCE_GROUP_H

#include "Node.h"

#include "Core/Control.h"

// The record of frame version 1 of a Noise session (NodeFrameWrite, NodeFrameParse). No frame version is 0xFF: after the
// VRF tag of no VRF, it marks a control record of the datagram path of the peer agent (NODE_GATEWAY_DATAGRAM; SDN-19-R1,
// #507), which the node takes before it reads the frame version (NodeOverlayAgentDeliver)
#define NODE_FRAME_VERSION    1    // The frame version of a record that carries the source group of its packet
#define NODE_FRAME_HEADER     8    // Bytes of its header before its options: the VRF tag of no VRF, the version, the length of the options and two reserved bytes
#define NODE_FRAME_CRITICAL   0x80 // The critical bit of the type of an option: a node that does not know the option drops the record
#define NODE_FRAME_GROUP      1    // The type of the option of the source group, whose critical bit is clear
#define NODE_FRAME_GROUP_DATA 16   // The data of that option: the group ID, two reserved bytes, the tag set and the group generation

// Bytes of the header of a record of frame version 1 with the option of the source group, before the data record of frame
// version 0
#define NODE_FRAME_ROOM (NODE_FRAME_HEADER + 4 + NODE_FRAME_GROUP_DATA)

// What carried the source group of a packet of a peer (NODE_SOURCE_CLAIM.Carrier)
#define NODE_CARRIER_SESSION 0 // A record of a Noise session, which authenticated it
#define NODE_CARRIER_VXLAN   1 // A datagram of a link of kind vxlan: the group policy extension of VXLAN, the group ID alone
#define NODE_CARRIER_GENEVE  2 // A datagram of a link of kind geneve: the option of the source group of Geneve

#define NODE_SOURCE_GROUP_LOG 10000 // ms between two lines of the node log about the claims that a node refused, at least

// The source group that a packet of a peer carried, as the node that takes the packet reads it
typedef struct NODE_SOURCE_CLAIM {
	UINT Carrier;       // What carried the packet (NODE_CARRIER_*)
	bool Carried;       // The packet carried a source group ...
	bool HasTags;       // ... with its tag set ...
	bool HasGeneration; // ... and the group generation of the peer, which the group policy extension of VXLAN has no room for
	UINT Group;         // The group ID
	UINT64 Tags;        // The tag set
	UINT Generation;    // The group generation, its 32 low bits: the Generation of the state of the peer that the claim was made on
} NODE_SOURCE_CLAIM;

// What NodeSourceGroupGetStatus reports: the packets of the peers of a node by the tag mode in which it judged them
// (CONTROL_TAG_MODE_*), since its overlay started, and the lines of its node log about the claims that it refused
typedef struct NODE_SOURCE_GROUP_STATUS {
	CONTROL_GROUP_COUNTERS Modes[CONTROL_TAG_MODES];
	UINT64 Logged;       // The lines of the node log about refused claims ...
	char Last[MAX_SIZE]; // ... and the last of them, "" before the first
} NODE_SOURCE_GROUP_STATUS;

typedef struct NODE_SOURCE_GROUP_TABLE NODE_SOURCE_GROUP_TABLE;
typedef struct NODE_SOURCE_GROUPS NODE_SOURCE_GROUPS;

// NodeSourceGroup.c
UINT NodeFrameWrite(UCHAR *room, UINT group, UINT64 tags, UINT generation);
bool NodeFrameParse(const UCHAR *record, UINT size, NODE_SOURCE_CLAIM *claim, UINT *header);
void NodeSourceGroupClaim(NODE_SOURCE_CLAIM *claim, UINT carrier, const VXLAN_GROUP *group);
CONTROL_SOURCE_GROUPS *NodeSourceGroupStart(NODE *n);
void NodeSourceGroupStop(NODE *n);
void NodeSourceGroupAttach(NODE *n, NODE_VRF_TABLES *v, const CONTROL_STATE *st);
void NodeFreeSourceGroupTable(NODE_SOURCE_GROUP_TABLE *t);
const UCHAR *NodeSourceGroupWrap(NODE_VRF_TABLES *v, UINT hop, UINT vrf_id, UCHAR *record, UINT *size, UINT max);
bool NodeSourceGroupStamp(NODE_VRF_TABLES *v, UINT vrf_id, const UCHAR *packet, UINT size, VXLAN_GROUP *group);
bool NodeSourceGroupInbound(NODE *n, NODE_VRF_TABLES *v, UINT vrf_id, UINT hop, const NODE_SOURCE_CLAIM *claim, const UCHAR *packet, UINT size);
bool NodeSourceGroupTransit(NODE *n, NODE_VRF_TABLES *v, UINT vrf_id, UINT hop, const NODE_SOURCE_CLAIM *claim, UINT *group);
void NodeSourceGroupGetStatus(NODE *n, NODE_SOURCE_GROUP_STATUS *st);

#endif // NODE_SOURCE_GROUP_H
