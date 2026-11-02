// NodeRouted.h
// The routed networks of the server role of a node (NodeRouted.c; CORE-S6-1, #80; ADR-0010 decision 1): the L3 Networks of
// the configuration store, routed between each other by the Windows IP stack. The declarations that the server role, the
// tests and the fuzz target use.

#ifndef NODE_ROUTED_H
#define NODE_ROUTED_H

#include "Cedar.h"
#include "Node.h"
#include "NodeL2.h"

// The gateway addresses and the NAT of the routed networks in the configuration store: one JSON object (NodeRoutedParseSetting).
// An L3 Network that it does not name stays down.
#define NODE_SETTING_ROUTED "Routed"

#define NODE_ROUTED_MAX_GATEWAYS 4     // Gateway addresses of a routed network at most
#define NODE_ROUTED_MAX_SETTING  65536 // Bytes of the Routed setting at most
#define NODE_ROUTED_WAIT         15000 // ms that a routed network waits for its interfaces and its gateway addresses
#define NODE_ROUTED_POLL         100   // ms between two looks at them
#define NODE_ROUTED_ETHER        14    // Bytes of the Ethernet header in front of an IP packet
#define NODE_ROUTED_NA_SIZE      86    // Bytes of a Neighbor Advertisement of the port, with its target link-layer address option
#define NODE_ROUTED_PREFIX       64    // Characters of a prefix as WinNAT names it, "255.255.255.255/32" and room

// What the name that NodeRoutedMac hashes begins with, before the node's static key and the name of the Network
#define NODE_ROUTED_MAC_LABEL "ranz routed network"

// What a frame that the host sent out of the adapter of a routed network is (NodeRoutedParseFrame)
#define NODE_ROUTED_FRAME_OTHER 0 // Anything else, which the port takes no further
#define NODE_ROUTED_FRAME_IP    1 // An IPv4 or IPv6 packet to the member side of the port, which goes to the members
#define NODE_ROUTED_FRAME_ARP   2 // An ARP request for an IPv4 address of the member side, which the port answers
#define NODE_ROUTED_FRAME_NS    3 // A Neighbor Solicitation for an IPv6 address of the member side, which the port answers

typedef struct NODE_ROUTED NODE_ROUTED;
typedef struct NODE_ROUTED_SET NODE_ROUTED_SET;

// A gateway address of a routed network: the address of the host in the network, and the length of the prefix of the network
typedef struct NODE_ROUTED_GATEWAY {
	UINT Size;         // 4 for IPv4, 16 for IPv6
	UCHAR Address[16]; // The address, in network byte order
	UINT Length;       // The prefix length
} NODE_ROUTED_GATEWAY;

// What NodeRoutedParseFrame read of a frame that the host sent out of the adapter
typedef struct NODE_ROUTED_FRAME {
	UINT Kind;         // NODE_ROUTED_FRAME_*
	UINT Offset;       // IP: the offset of the packet in the frame ...
	UINT Size;         // ... and its bytes
	UINT TargetSize;   // ARP and NS: 4 or 16 ...
	UCHAR Target[16];  // ... the address that the host asks for ...
	UCHAR Asker[16];   // ... the address that it asks from ...
	UCHAR AskerMac[6]; // ... and the MAC address that the answer goes to
} NODE_ROUTED_FRAME;

// Takes an IP packet that the kernel routed to a member of the routed network, on the I/O thread of its adapter queue. The
// packet stays valid during the call only; the procedure may call NodeRoutedSend.
typedef void(NODE_ROUTED_PROC)(NODE_ROUTED *r, void *param, const UCHAR *packet, UINT size);

// How a routed network runs (NodeRoutedNew)
typedef struct NODE_ROUTED_CONFIG {
	char Name[MAX_HUBNAME_LEN + 1];                         // The name of its L3 Network
	UCHAR Key[PEER_KEY_SIZE];                               // The static key of the node, which the MAC address of its adapter derives from
	UINT NumGateways;                                       // Its gateway addresses ...
	NODE_ROUTED_GATEWAY Gateways[NODE_ROUTED_MAX_GATEWAYS]; // ...
	bool Nat;                                               // Its packets to the internet go through the NAT network of WinNAT of the node
	const NODE_L2_BACKEND *const *Backends;                 // The backends of its L2 adapter to try, NULL for XDP, then SeLow ...
	UINT NumBackends;                                       // ... and their number
} NODE_ROUTED_CONFIG;

// What NodeRoutedGetStatus reports of a routed network
typedef struct NODE_ROUTED_STATUS {
	UINT IfIndex;       // The interface of its KM-TEST adapter
	UCHAR Mac[6];       // The MAC address of the adapter ...
	UCHAR MemberMac[6]; // ... and of the member side of its port
	bool Forwarding4;   // The kernel forwards what its IPv4 interface receives, as GetIpInterfaceEntry reads it back ...
	bool Forwarding6;   // ... and its IPv6 interface
	bool Nat;           // It goes through the NAT network of WinNAT of the node
	char Backend[16];   // The backend of its L2 adapter
	UINT64 FromMembers; // IP packets of the members that went into the host
	UINT64 ToMembers;   // IP packets that the kernel routed to the members, which went to the owner of the member side
	UINT64 Answers;     // ARP requests and Neighbor Solicitations of the host that the port answered
	UINT64 Refused;     // Packets of the members that the port refused: no IP packet, too long, or from an address outside the network
	UINT64 Ignored;     // Frames of the host that are no packet to the member side: broadcasts, multicasts and the frames of the probes
	UINT64 Unowned;     // IP packets to the member side while no owner took them
} NODE_ROUTED_STATUS;

// NodeRouted.c
bool NodeRoutedParseSetting(const char *json, const char *name, NODE_ROUTED_GATEWAY *gw, UINT *num, bool *nat);
UINT NodeRoutedParseFrame(const UCHAR *frame, UINT size, const UCHAR *member_mac, const NODE_ROUTED_GATEWAY *gw, UINT num, NODE_ROUTED_FRAME *f);
UINT NodeRoutedAnswer(UCHAR *buf, UINT size, const NODE_ROUTED_FRAME *f, const UCHAR *member_mac);
UINT NodeRoutedFrame(UCHAR *buf, UINT size, const UCHAR *packet, UINT packet_size, const UCHAR *adapter_mac, const UCHAR *member_mac, const NODE_ROUTED_GATEWAY *gw, UINT num);
UINT NodeRoutedSupernet(const NODE_ROUTED_GATEWAY *gw, UINT num, UCHAR *address);
void NodeRoutedMac(UCHAR *mac, const UCHAR *key, const char *name);
NODE_ROUTED *NodeRoutedNew(NODE *n, const NODE_ROUTED_CONFIG *cfg);
void NodeRoutedFree(NODE_ROUTED *r);
bool NodeRoutedSend(NODE_ROUTED *r, const UCHAR *packet, UINT size);
void NodeRoutedSetProc(NODE_ROUTED *r, NODE_ROUTED_PROC *proc, void *param);
bool NodeRoutedSetForwarding(NODE_ROUTED *r, bool on);
void NodeRoutedGetStatus(NODE_ROUTED *r, NODE_ROUTED_STATUS *st);
bool NodeRoutedStart(NODE *n);
void NodeRoutedStop(NODE *n);
NODE_ROUTED *NodeRoutedFind(NODE *n, const char *name);

#endif // NODE_ROUTED_H
