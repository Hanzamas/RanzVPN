// NodeEgress.h
// The internet exit of a VRF in the overlay of a node (NodeEgress.c; SDN-12, #188), with its tiers on the NAT of Windows
// (NodeEgressNat.c): the declarations that the overlay, the forwarding tables, the Capabilities, the tests and the fuzz
// target use

#ifndef NODE_EGRESS_H
#define NODE_EGRESS_H

#include "Node.h"

#define NODE_EGRESS_MAX_FLOWS   16384 // TCP and UDP flows of the proxy at most: a new flow past them is dropped
#define NODE_EGRESS_BUCKETS     4096  // Buckets of each hash of the flows
#define NODE_EGRESS_BUFFER      16384 // Bytes of each direction of a TCP flow that the proxy holds at most
#define NODE_EGRESS_TCP_OPEN    30000 // ms that a TCP flow waits for the host to take its SYN, and for its dial
#define NODE_EGRESS_TCP_LINGER  30000 // ms that a TCP flow stays once its sockets closed, for the last segments of the host
#define NODE_EGRESS_UDP_IDLE    60000 // ms that a UDP flow stays without a datagram
#define NODE_EGRESS_MAX_PINGS   64    // Echo requests of the proxy that wait for their reply at most
#define NODE_EGRESS_PING_WAIT   2000  // ms that an echo request of the proxy waits for its reply
#define NODE_EGRESS_MAX_ECHO    1472  // Bytes of the data of an echo request that the proxy carries at most
#define NODE_EGRESS_POLL        50    // ms that the thread of the proxy waits for its sockets at most
#define NODE_EGRESS_BIND        250   // ms between two attempts to bind the listeners of a VRF whose address is not up yet
#define NODE_EGRESS_SCAN        1000  // ms between two looks at the interfaces that carry the egress
#define NODE_EGRESS_MAX_UPLINKS 64    // Interfaces that carry the egress that the node changes at most
#define NODE_EGRESS_STACK       2048  // Bytes of a packet that the proxy rewrites on the stack; a larger one is allocated
#define NODE_EGRESS_NAT_SCAN    5000  // ms between two reconciles of the NAT of Windows of tiers 1 and 2
#define NODE_EGRESS_NAT_TRIES   3     // Reconciles in a row that fail before the Egress falls back to the proxy
#define NODE_EGRESS_SUPERNET    8     // The shortest supernet that tier 2 gives WinNAT: VRFs whose prefixes span more take the proxy
#define NODE_EGRESS_MAX_PRIVATE 16    // The adapters of the VRFs whose exit the node is (CONTROL_MAX_VRFS)

// The name of the NAT network of WinNAT that the node creates for tier 2 (NodeEgressNat.c): one per host, as WinNAT allows. A
// NAT network of another name is never the node's.
#define NODE_EGRESS_NETNAT_NAME L"RanzVPN-Egress"

// The flags of the NAT of RRAS on an interface (IP_NAT_INTERFACE_FLAGS_* of MS-RRASM 2.2.1.2.197): a private interface has
// none, a public one is a boundary with address and port translation
#define NODE_EGRESS_RRAS_BOUNDARY 0x00000001
#define NODE_EGRESS_RRAS_NAPT     0x00000002
#define NODE_EGRESS_RRAS_PUBLIC   (NODE_EGRESS_RRAS_BOUNDARY | NODE_EGRESS_RRAS_NAPT)

// The upper-layer protocols that the Egress carries
#define NODE_EGRESS_ICMP 1
#define NODE_EGRESS_TCP  6
#define NODE_EGRESS_UDP  17

// The ICMP types of an echo
#define NODE_EGRESS_ECHO_REPLY   0
#define NODE_EGRESS_ECHO_REQUEST 8

// The TCP flags that the proxy reads
#define NODE_EGRESS_FIN 0x01
#define NODE_EGRESS_SYN 0x02
#define NODE_EGRESS_RST 0x04
#define NODE_EGRESS_ACK 0x10

typedef struct NODE_EGRESS NODE_EGRESS;
typedef struct NODE_EGRESS_TABLE NODE_EGRESS_TABLE;
typedef struct NODE_EGRESS_NAT NODE_EGRESS_NAT;

// What the NAT of Windows of tiers 1 and 2 takes from the VRFs whose exit the node is (NodeEgressNatApply)
typedef struct NODE_EGRESS_NAT_WANT {
	UINT NumPrivate;                         // RRAS: the private interfaces, the adapters of those VRFs ...
	UINT64 Private[NODE_EGRESS_MAX_PRIVATE]; // ... by their LUIDs
	UINT NumPublic;                          // ... and the public ones, the interfaces that carry the egress
	UINT64 Public[NODE_EGRESS_MAX_UPLINKS];  // ...
	UCHAR Supernet[4];                       // WinNAT: the supernet that holds every IPv4 prefix of those VRFs ...
	UINT Length;                             // ... and its length, 0 for none
} NODE_EGRESS_NAT_WANT;

// One IPv4 packet of TCP, UDP or ICMP as the Egress reads it (NodeEgressParse)
typedef struct NODE_EGRESS_PACKET {
	UINT HeaderSize; // The bytes of its IPv4 header
	UINT Total;      // Its total length, no more than the bytes that hold it
	UINT Protocol;   // NODE_EGRESS_TCP, NODE_EGRESS_UDP or NODE_EGRESS_ICMP
	UCHAR Src[4];    // Its source ...
	UCHAR Dst[4];    // ... and its destination
	UINT SrcPort;    // TCP and UDP: the source port ...
	UINT DstPort;    // ... and the destination port
	UINT TcpFlags;   // TCP: the flags
	UINT IcmpType;   // ICMP: the type ...
	UINT IcmpCode;   // ... the code ...
	UINT EchoId;     // ... and of an echo, the identifier ...
	UINT EchoSeq;    // ... and the sequence number
	UINT Payload;    // The offset of what the upper layer carries: the data of TCP or UDP, or of the echo
} NODE_EGRESS_PACKET;

// What NodeEgressGetStatus reports of the internet exit of a node
typedef struct NODE_EGRESS_STATUS {
	UINT Tier;          // The Egress tier that the node uses as an exit (CONTROL_EGRESS_*)
	UINT NumVrfs;       // The VRFs whose exit the node is, in the Generation applied last
	UINT NumReady;      // ... of them whose proxy listens on the address of the node in the VRF
	UINT NumUplinks;    // The interfaces that carry the egress, with Forwarding, WeakHostSend and WeakHostReceive on
	UINT NumFlows;      // The TCP and UDP flows of the proxy now
	UINT64 Tcp;         // TCP connections of the peers that the proxy dialled out
	UINT64 Udp;         // UDP flows of the peers that the proxy carried out
	UINT64 Echoes;      // Echo requests of the peers that the proxy sent out ...
	UINT64 EchoReplies; // ... and their replies, which went back into the overlay
	UINT64 Refused;     // Packets to a destination that the Egress refuses: the loopback, link-local, multicast or a VRF of the node
	UINT64 Dropped;     // Other packets that the Egress took and could not carry
	bool NatReady;      // Tiers 1 and 2: the NAT of Windows holds what the VRFs of the Generation applied last want
	UINT64 Restored;    // Tiers 1 and 2: the times that the node set the NAT of Windows again after something else changed it
	UINT Fallback;      // The tier that the Egress fell back to the proxy from (CONTROL_EGRESS_*), 0 for none
} NODE_EGRESS_STATUS;

// NodeEgress.c
UINT NodeEgressRoutes(const struct CONTROL_STATE *st, NODE_VRF_ROUTE *routes);
void NodeEgressStart(NODE *n, UINT tier);
void NodeEgressStop(NODE *n);
void NodeEgressAttach(NODE *n, NODE_VRF_TABLES *v, const struct CONTROL_STATE *st);
void NodeFreeEgressTable(NODE_EGRESS_TABLE *t);
void NodeEgressApplied(NODE *n, const struct CONTROL_STATE *st);
bool NodeEgressDeliver(NODE *n, NODE_VRF_TABLES *v, UINT vrf_id, const UCHAR *packet, UINT size, NODE_ADAPTER_PROC *adapter, void *param);
void NodeEgressFromHost(NODE *n, NODE_VRF_TABLES *v, UINT vrf_id, UCHAR *packet, UINT size);
bool NodeEgressParse(const UCHAR *packet, UINT size, NODE_EGRESS_PACKET *p);
void NodeEgressRewrite(UCHAR *packet, const NODE_EGRESS_PACKET *p, const UCHAR *src, UINT src_port, const UCHAR *dst, UINT dst_port);
UINT NodeEgressEchoReply(UCHAR *buf, UINT size, const UCHAR *src, const UCHAR *dst, UINT id, UINT seq, const UCHAR *data, UINT data_size);
bool NodeEgressRefuses(const UCHAR *dst);
void NodeEgressGetStatus(NODE *n, NODE_EGRESS_STATUS *st);

// NodeEgressNat.c
bool NodeEgressRrasRouter(void);
bool NodeEgressForeignNetNat(void);
NODE_EGRESS_NAT *NodeEgressNatNew(NODE *n, UINT tier);
bool NodeEgressNatApply(NODE_EGRESS_NAT *nat, const NODE_EGRESS_NAT_WANT *want, UINT *restored);
bool NodeEgressNatForeign(const NODE_EGRESS_NAT *nat);
void NodeEgressNatFree(NODE_EGRESS_NAT *nat);
bool NodeEgressNetNatPrefix(const wchar_t *name, wchar_t *prefix, UINT size);
bool NodeEgressNetNatAdd(const wchar_t *name, const wchar_t *prefix);
bool NodeEgressNetNatRemove(const wchar_t *name);
bool NodeEgressRrasFlags(UINT64 luid, UINT *flags);
bool NodeEgressRrasProtocolHeld(void);
bool NodeEgressRrasRemove(UINT64 luid);

#endif // NODE_EGRESS_H
