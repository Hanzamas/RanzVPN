// NodeProfile.h
// The session profiles of the overlay of a node (NodeProfile.c; SDN-40, #233): the declarations that the overlay, the
// forwarding tables, the fuzz target and the tests use

#ifndef NODE_PROFILE_H
#define NODE_PROFILE_H

#include "Node.h"

#include "Core/Control.h"
#include "Core/Policy.h"

#define NODE_PROFILE_MAX_ADDRESSES 64    // The addresses of one family that a session sends from in one VRF at most, whatever its profile says (MaxProfileAddresses of the intent)
#define NODE_PROFILE_BURST         50    // ms of its rate that the bucket of an upload or a download limit holds ...
#define NODE_PROFILE_MIN_BURST     65536 // ... and bytes at least: more than the largest IP packet
#define NODE_PROFILE_MAX_HEADERS   8     // The IPv6 extension headers that the node follows to the TCP header of a packet at most

// What NodeProfileExpired finds of a session
#define NODE_PROFILE_LIVE 0 // It goes on
#define NODE_PROFILE_IDLE 1 // It carried no packet in either direction for the idle timeout of the profile of its peer
#define NODE_PROFILE_AUTO 2 // It came up the automatic disconnect of the profile of its peer ago

typedef struct NODE_PROFILE NODE_PROFILE;
typedef struct NODE_PROFILE_TABLE NODE_PROFILE_TABLE;

// What NodeProfileGetStatus reports: what the session profiles did since the overlay started, all 0 before
typedef struct NODE_PROFILE_STATUS {
	CONTROL_PROFILE Own; // The profile that the node itself runs under in the state attached last; not Set for none
	UINT NumPeers;       // The peers of that state that run under a profile
	UINT64 Upload;       // Packets of a peer that the upload limit of its profile dropped
	UINT64 Download;     // Packets to a peer that the download limit of its profile dropped
	UINT64 Addresses;    // Packets of a peer from one address more than its profile lets its session send from
	UINT64 Routing;      // Packets that no-routing dropped: from or to an address that is no address of the device itself
	UINT64 Server;       // Packets that no-server dropped: a TCP SYN to the device, a SYN-ACK from it
	UINT64 Isolated;     // Packets that the privacy filter dropped: between two devices whose profiles both have it
	UINT64 Refused;      // Sessions of a peer that the most sessions of the devices of its User refused
	UINT64 Idle;         // Sessions that the idle timeout of the profile of their peer ended
	UINT64 Disconnected; // ... and that its automatic disconnect ended
} NODE_PROFILE_STATUS;

// NodeProfile.c
void NodeProfileStart(NODE *n);
void NodeProfileStop(NODE *n);
void NodeProfileAttach(NODE *n, NODE_VRF_TABLES *v, const CONTROL_STATE *st);
void NodeProfileFreeTable(NODE_PROFILE_TABLE *t);
bool NodeProfileOutbound(NODE *n, NODE_VRF_TABLES *v, UINT vrf_id, UINT hop, const UCHAR *packet, UINT size);
bool NodeProfileInbound(NODE *n, NODE_VRF_TABLES *v, UINT vrf_id, UINT hop, const UCHAR *packet, UINT size);
bool NodeProfileTransit(NODE *n, NODE_VRF_TABLES *v, UINT vrf_id, UINT from, UINT to, const UCHAR *packet, UINT size);
bool NodeProfileUp(NODE *n, const char *name, const UCHAR *key);
void NodeProfileDown(NODE *n, const char *name, const UCHAR *key);
UINT NodeProfileExpired(NODE *n, const char *name, const UCHAR *key, UINT64 since, UINT64 now);
void NodeProfileMember(const CONTROL_PROFILE *p, POLICY_MEMBER_CONFIG *m);
void NodeProfileGetStatus(NODE *n, NODE_PROFILE_STATUS *st);

#endif // NODE_PROFILE_H
