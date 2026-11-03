// NodeTagMac.h
// The tag mode hmac of the overlay of a node (NodeTagMac.c; SDN-88, #387): the declarations that the source groups, the
// tests and the fuzz targets use

#ifndef NODE_TAG_MAC_H
#define NODE_TAG_MAC_H

#include "NodeSourceGroup.h"

#define NODE_TAG_MAC_WINDOW     30 // s between the timestamp of a MAC and the clock of the node at most, either way
#define NODE_TAG_MAC_FIELDS     24 // Bytes of the fields that the MAC covers before the headers: the VNI, the group ID, the ID of the key, the tag set, the group generation and the timestamp
#define NODE_TAG_MAC_EXTENSIONS 8  // The extension headers of IPv6 that the MAC covers at most before the L4 header

// The keys of the VRFs of a Generation in the tag mode hmac, which go in with its forwarding tables
typedef struct NODE_TAG_MAC_TABLE NODE_TAG_MAC_TABLE;

// NodeTagMac.c
NODE_TAG_MAC_TABLE *NodeTagMacNew(const CONTROL_STATE *st);
void NodeTagMacFree(NODE_TAG_MAC_TABLE *m);
UINT NodeTagMacNow();
UINT NodeTagMacHeaders(const UCHAR *packet, UINT size);
bool NodeTagMacCompute(const UCHAR *key, UINT vni, const VXLAN_GROUP *g, const UCHAR *packet, UINT size, UCHAR *mac);
bool NodeTagMacSign(const NODE_TAG_MAC_TABLE *m, UINT vrf_id, const UCHAR *packet, UINT size, UINT now, VXLAN_GROUP *group);
void NodeTagMacCheck(const NODE_TAG_MAC_TABLE *m, UINT vrf_id, const UCHAR *packet, UINT size, UINT now, NODE_SOURCE_CLAIM *claim);

#endif // NODE_TAG_MAC_H
