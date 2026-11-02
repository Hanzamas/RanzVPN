// NodeEvpn.h
// The EVPN of a gateway node (NodeEvpn.c; SDN-25, #201): the declarations that the BGP sidecar, the overlay, the table
// snapshot, the fuzz target and the tests use

#ifndef NODE_EVPN_H
#define NODE_EVPN_H

#include "Node.h"

#define NODE_EVPN_ROUTER_MAC "02:52:5a:00:00:05" // The router MAC of a gateway whose evpn object names none (DefaultRouterMAC of ranz-bgp/internal/sidecar)
#define NODE_EVPN_ETHER      14                  // Bytes of the Ethernet header in front of the IP packet of a frame of the fabric
#define NODE_EVPN_MAX_VRFS   16                  // The VRFs of an evpn object at most (CONTROL_MAX_VRFS)
#define NODE_EVPN_MAX_ROUTES 65536               // The IP prefix routes of the fabric that a gateway holds at most (NODE_VRF_MAX_HOPS)
#define NODE_EVPN_MAX_OFFERS 16                  // The vteps of a learned message at most (maxEVPNVTEPs of ranz-bgp/internal/sidecar)
#define NODE_EVPN_TEXT       64                  // A prefix, an address or a MAC address as text, with its NUL
#define NODE_EVPN_LOG_WAIT   10000               // ms between two lines of the node log that name a frame of an unknown VTEP, at least
#define NODE_EVPN_REPORT     1000                // ms between two reads of the counters for the report of the control stream (CONTROL_EVPN_REPORT)

// What NodeEvpnParseRoute finds in a message of the sidecar
#define NODE_EVPN_NO_ROUTE  0 // No message of an IP prefix route of an EVPN VRF: one without a vni
#define NODE_EVPN_LEARNED   1 // learned: the route of the prefix in the VRF is now the one of the message
#define NODE_EVPN_WITHDRAWN 2 // withdrawn: no peer offers the prefix in the VRF any more
#define NODE_EVPN_BAD       3 // A learned or withdrawn message with a vni that the node cannot take

// What NodeEvpnParseFrame finds in a frame of the fabric
#define NODE_EVPN_FRAME_OK        0 // An IP packet to the router MAC of the gateway
#define NODE_EVPN_FRAME_NOT_OURS  1 // A frame to another MAC address
#define NODE_EVPN_FRAME_MALFORMED 2 // A frame too short, tagged, or without an IP packet of the version of its EtherType

typedef struct NODE_EVPN NODE_EVPN;
typedef struct NODE_EVPN_TABLE NODE_EVPN_TABLE;

// An IP prefix route of the fabric in an EVPN VRF, as a learned or withdrawn message of the sidecar names it
// (NodeEvpnParseRoute) and as the gateway holds it (NodeEvpnGetRoutes). A withdrawn message names no next hop, no router
// MAC and no vteps.
typedef struct NODE_EVPN_ROUTE {
	UINT VrfId;                            // The EVPN VRF
	char Prefix[NODE_EVPN_TEXT];           // The prefix, as the sidecar names it
	UCHAR Address[16];                     // ... 4 bytes for IPv4, 16 for IPv6, in network byte order
	UINT AddressSize;                      // ... their number
	UINT Length;                           // ... and its length
	char NextHop[NODE_EVPN_TEXT];          // The VTEP of the fabric, the next hop of the route
	UCHAR Vtep[16];                        // ... as an IPv4-mapped or an IPv6 address
	UINT NumVteps;                         // The vteps of the message: the next hops of every route that the peers offer for the prefix ...
	UCHAR Vteps[NODE_EVPN_MAX_OFFERS][16]; // ... each as an IPv4-mapped or an IPv6 address (SDN-25-R3, #571)
	UINT Vni;                              // The VNI of the route: its label, the L3 VNI of the VRF of the fabric
	UCHAR RouterMac[6];                    // The router MAC of the fabric: the inner destination of the frames of the route
	char Peer[NODE_EVPN_TEXT];             // The BGP peer that the route came from
} NODE_EVPN_ROUTE;

// A VTEP of the fabric that a gateway knows for one of its EVPN VRFs: the VTEP of an IP prefix route of the VRF that it learned,
// or the next hop of another route that a peer offers for the prefix of one (the vteps of its learned message; SDN-25-R3,
// #571), as the table snapshot holds it (NodeEvpnSortVteps), the only address that the gateway takes a frame of the VRF from
// (NodeEvpnHasVtep; SDN-25-R1, #549)
typedef struct NODE_EVPN_VTEP {
	UINT VrfId;   // The EVPN VRF
	UCHAR Ip[16]; // The address of the VTEP, an IPv4 address as an IPv4-mapped one, as VXLAN_ADDR holds the source of a datagram
} NODE_EVPN_VTEP;

// The IP packet of a frame of the fabric (NodeEvpnParseFrame)
typedef struct NODE_EVPN_FRAME {
	const UCHAR *Packet; // The packet, inside the frame
	UINT Size;           // ... its bytes: the rest of the frame
	UCHAR Src[16];       // Its source ...
	UCHAR Dst[16];       // ... and its destination: 4 bytes for IPv4, 16 for IPv6
	UINT AddrSize;       // ... their number
} NODE_EVPN_FRAME;

// What NodeEvpnGetStatus reports: the frames of the EVPN of the gateway since its sidecar started, all 0 without one. The
// module reads the VXLAN header of every datagram first, whatever its source (VxlanInput), so UnknownVni and the datagrams of
// Malformed come from any address; then the gateway checks the outer source of a frame of an L3 VNI (UnknownVtep), and
// Strangers, NotOurs, Delivered, Undelivered and the frames of Malformed count the frames of known VTEPs alone.
typedef struct NODE_EVPN_STATUS {
	bool Running;       // The EVPN of the gateway runs: the Bgp setting has an evpn object, and the socket of its VTEP is open
	USHORT Port;        // The UDP port of the VTEP of the gateway
	USHORT FabricPort;  // ... and of the VTEPs of the fabric
	UINT NumVrfs;       // The EVPN VRFs
	UINT NumRoutes;     // The IP prefix routes of the fabric that the gateway holds
	UINT64 Sent;        // Packets of the overlay sent to a VTEP of the fabric
	UINT64 Failed;      // Packets for the fabric that could not go: a frame too large, or a failed send
	UINT64 Delivered;   // Packets of the fabric that the overlay took, for the host or a peer
	UINT64 Undelivered; // ... that it did not take: no route of the VRF to their destination, the policy, or a failed send
	UINT64 UnknownVtep; // Frames of an L3 VNI from an address that is no VTEP that the gateway knows for their VRF (NodeEvpnHasVtep): dropped, whatever they hold
	UINT64 Strangers;   // Packets of a known VTEP from a source that no IP prefix route of their VRF holds: dropped
	UINT64 NotOurs;     // Frames of a known VTEP to another MAC address than the router MAC of the gateway: dropped
	UINT64 UnknownVni;  // Datagrams on a VNI of no EVPN VRF, from any address: dropped by the module, before the source check
	UINT64 Malformed;   // Datagrams of no VXLAN frame, from any address (the module, before the source check), and frames of a known VTEP without an IP packet: dropped
} NODE_EVPN_STATUS;

// The stretch of a gateway (NodeStretch.c; SDN-64, #291; ADR-0032 amendment of 2026-10-22): the L2 Networks that it extends into
// the fabric, each on its own L2 VNI, with EVPN route types 2 and 3 through the sidecar
#define NODE_STRETCH_MAX        16         // The stretches of an evpn object at most
#define NODE_STRETCH_NAME       64         // A Network name with its NUL (CONTROL_NAME_SIZE of Core/Control.h)
#define NODE_STRETCH_MAX_ROUTES 500        // The routes of one stretch message at most, either way (MaxStretchRoutes of the sidecar)
#define NODE_STRETCH_MAX_REMOTE 65536      // The routes of the fabric that a gateway holds at most
#define NODE_STRETCH_MAX_LOCAL  16384      // The routes of its own that a gateway announces at most: entries of the MAC and IP tables
#define NODE_STRETCH_NO_MESSAGE 0xFFFFFFFF // What NodeStretchParseRoutes returns for a message that is no stretch message

typedef struct NODE_STRETCH NODE_STRETCH;

// One stretch of the evpn object of the Bgp setting: the L2 Network and its L2 VNI. The sidecar reads the same object, with the
// route distinguisher and the route targets of each.
typedef struct NODE_STRETCH_SETTING {
	char Network[NODE_STRETCH_NAME]; // The L2 Network
	UINT Vni;                        // Its L2 VNI
} NODE_STRETCH_SETTING;

// A route of the fabric on the L2 VNI of a stretch, as a stretch message of the sidecar names it (NodeStretchParseRoutes) and as
// the gateway holds it (NodeStretchGetRoutes): a MAC/IP advertisement route (type 2), MAC only or MAC plus IP, or an inclusive
// multicast Ethernet tag route (type 3), which puts its VTEP into the flood list of the VNI
typedef struct NODE_STRETCH_ROUTE {
	UINT Vni;       // The L2 VNI
	bool Imet;      // A type-3 route, whose VTEP is all of its key; else a type-2 route
	UCHAR Mac[6];   // A type-2 route: the MAC address of one host ...
	UCHAR Ip[16];   // ... and in the MAC plus IP form its IP address: 4 bytes for IPv4, 16 for IPv6 ...
	UINT IpSize;    // ... their number, 0 for MAC only
	UCHAR Vtep[16]; // The VTEP of the fabric, the next hop of the route, an IPv4 address as an IPv4-mapped one
	bool Withdraw;  // In a message: the route went
} NODE_STRETCH_ROUTE;

// What NodeStretchGetStatus reports: the stretch of the gateway since the node started, all 0 without one
typedef struct NODE_STRETCH_STATUS {
	UINT NumStretches;  // The stretches of the running sidecar
	UINT NumAttached;   // ... whose switch the L2 data path attached, with the port of the fabric on it
	UINT NumMacs;       // The type-2 routes of the fabric that the gateway holds
	UINT NumVteps;      // ... and its type-3 routes: the VTEPs of the flood lists
	UINT NumAnnounced;  // The type-2 routes of the gateway that its sidecar announces
	UINT64 Resyncs;     // The full resyncs that the gateway sent: one after each start of a sidecar
	UINT64 Unicast;     // Frames of the overlay sent to the VTEP of the type-2 route of their destination
	UINT64 Flooded;     // Frames of the overlay sent to each VTEP of the flood list once: broadcast, multicast, unknown unicast
	UINT64 Failed;      // Frames of the overlay for the fabric that could not go: no flood list, too large, or a failed send
	UINT64 Delivered;   // Frames of the fabric that the switch of their Network delivered to a port
	UINT64 Undelivered; // ... that it delivered to none, or that came while the fabric was on no switch
	UINT64 UnknownVtep; // Frames of an L2 VNI from an address that is the VTEP of no route of the VNI (NodeStretchInput): dropped, whatever they hold
	UINT64 Refused;     // Routes of the fabric that the gateway did not take: none that it can take, of no stretch, or one too many
} NODE_STRETCH_STATUS;

// NodeEvpn.c
UINT NodeEvpnParseRoute(const char *line, NODE_EVPN_ROUTE *r);
bool NodeEvpnParseMac(const char *str, UCHAR *mac);
UINT NodeEvpnParseAddr(const char *str, DWORD types, UCHAR *addr, UINT *prefix_len);
void NodeEvpnMacText(char *str, UINT size, const UCHAR *mac);
UINT NodeEvpnParseFrame(const UCHAR *frame, UINT size, const UCHAR *router_mac, NODE_EVPN_FRAME *f);
bool NodeEvpnEnds(const UCHAR *packet, UINT size, UCHAR *src, UCHAR *dst, UINT *addr_size);
UINT NodeEvpnSortVteps(NODE_EVPN_VTEP *vteps, UINT num);
bool NodeEvpnHasVtep(const NODE_EVPN_VTEP *vteps, UINT num, UINT vrf_id, const UCHAR *ip);
struct cJSON;
void NodeEvpnStart(NODE *n, struct cJSON *cfg);
void NodeEvpnStop(NODE *n);
bool NodeEvpnRoute(NODE *n, const char *line);
void NodeEvpnCommit(NODE *n);
UINT NodeEvpnFlush(NODE *n);
void NodeEvpnFreeTable(NODE_EVPN_TABLE *t);
bool NodeEvpnOutput(NODE *n, NODE_VRF_TABLES *v, UINT vrf_id, const UCHAR *packet, UINT size);
struct NODE_SOURCE_CLAIM;
bool NodeEvpnTransit(NODE *n, NODE_VRF_TABLES *v, UINT vrf_id, UINT from, const struct NODE_SOURCE_CLAIM *claim, const UCHAR *packet, UINT size);
void NodeEvpnGetStatus(NODE *n, NODE_EVPN_STATUS *st);
UINT NodeEvpnGetRoutes(NODE *n, NODE_EVPN_ROUTE *list, UINT max);

// NodeStretch.c (SDN-64, #291)
struct SWITCH;
UINT NodeStretchParseRoutes(const char *line, NODE_STRETCH_ROUTE *list, UINT max, UINT *bad);
UINT NodeStretchSettings(struct cJSON *stretches, const UINT *l3_vnis, UINT num_l3, NODE_STRETCH_SETTING *list, char *error, UINT error_size);
void NodeStretchBind(NODE *n, VXLAN *vxlan, USHORT fabric_port, const NODE_STRETCH_SETTING *list, UINT num);
void NodeStretchUnbind(NODE *n);
bool NodeStretchInput(NODE *n, UINT vni, const VXLAN_ADDR *from, const UCHAR *frame, UINT size);
void NodeStretchMessage(NODE *n, const char *line);
void NodeStretchCommit(NODE *n);
UINT NodeStretchFlush(NODE *n);
void NodeStretchRun(NODE *n, NODE_BGP *b);
void NodeStretchHalt(NODE *n);
void NodeStretchFree(NODE *n);
bool NodeStretchAttach(NODE *n, const char *network, struct SWITCH *sw, UINT vlan);
void NodeStretchDetach(NODE *n, const char *network);
void NodeStretchGetStatus(NODE *n, NODE_STRETCH_STATUS *st);
UINT NodeStretchGetRoutes(NODE *n, NODE_STRETCH_ROUTE *list, UINT max);

// NodeBgp.c: one message to the sidecar, from the node lock or from the thread of the stretch, which NodeBgpStop joins first
bool NodeBgpSend(NODE_BGP *b, struct cJSON *m);

// NodeTable.c
bool NodeSwapEvpn(NODE *n, NODE_EVPN_TABLE *e);

// NodeOverlay.c
bool NodeOverlayFabricInput(NODE *n, UINT vrf_id, const UCHAR *packet, UINT size, UCHAR *nat_buf);

// NodeState.c: the EVPN of the gateway in the answer of the admin pipe to state, which ranz node state prints (SDN-25-R3, #571)
void NodeEvpnState(NODE *n, struct cJSON *o);

#endif // NODE_EVPN_H
