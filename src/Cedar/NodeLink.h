// NodeLink.h
// The links of kind vxlan and geneve of the overlay of a node (NodeLink.c; SDN-76, #356): the declarations that the overlay,
// the forwarding tables and the tests use

#ifndef NODE_LINK_H
#define NODE_LINK_H

#include "Node.h"

#define NODE_LINK_ETHER   14 // Bytes of the Ethernet header in front of the IP packet of a frame of a link
#define NODE_LINK_THREADS 2  // The receive threads of the module: one for its socket of VXLAN, one for that of Geneve

typedef struct NODE_LINK NODE_LINK;
typedef struct NODE_LINK_TABLE NODE_LINK_TABLE;

// What NodeLinkGetStatus reports: the frames of the links of kind vxlan and geneve since the first Generation of the overlay
// that had one, all 0 before
typedef struct NODE_LINK_STATUS {
	bool Running;      // The VXLAN module of the links runs
	USHORT VxlanPort;  // The UDP port of its socket of VXLAN, 0 for none
	USHORT GenevePort; // ... and of its socket of Geneve
	UINT NumVnis;      // The VNIs that it carries
	UINT64 Sent;       // Packets of the host sent to the tunnel endpoint of a peer
	UINT64 Delivered;  // Frames of a named peer on the VNI of a VRF that it shares, handed to the overlay
	UINT64 Strangers;  // Datagrams from an address that the Controller did not name for the VRF of their VNI: dropped
	UINT64 UnknownVni; // Datagrams on a VNI of no VRF of the node whose link has their encapsulation: dropped
	UINT64 Malformed;  // Datagrams of no VXLAN or Geneve of the module, or without an IP packet behind their Ethernet header: dropped
	UINT64 Failed;     // Packets that could not go: no tunnel endpoint of the peer, too large for a frame, or a failed send
} NODE_LINK_STATUS;

// NodeLink.c
UINT NodeLinkKind(NODE_VRF_TABLES *v, UINT hop, UINT vrf_id);
bool NodeLinkSend(NODE_VRF_TABLES *v, UINT hop, const UCHAR *record, UINT size, bool host);
void NodeLinkAttach(NODE *n, NODE_VRF_TABLES *v, const struct CONTROL_STATE *st);
void NodeLinkApplied(NODE *n, bool swapped);
void NodeFreeLinkTable(NODE_LINK_TABLE *t);
void NodeLinkStop(NODE *n);
void NodeLinkGetStatus(NODE *n, NODE_LINK_STATUS *st);

// NodeOverlay.c
struct NODE_SOURCE_CLAIM;
void NodeOverlayLinkDeliver(NODE *n, void *hop, const UCHAR *record, UINT size, UCHAR *nat_buf, const struct NODE_SOURCE_CLAIM *claim);

#endif // NODE_LINK_H
