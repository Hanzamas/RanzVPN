// NodeStretch.c
// The stretch of a gateway node (SDN-64, #291; ADR-0032 amendment of 2026-10-22): the gateway extends L2 Networks of the overlay
// into a data-centre fabric, each on its own L2 VNI, with EVPN route types 2 and 3 (RFC 7432) through its BGP sidecar (NodeBgp.c;
// ranz bgp, ranz-bgp/internal/sidecar/stretch.go) and VXLAN as their encapsulation (RFC 8365), on the VTEP and in the VXLAN
// module of its EVPN (NodeEvpn.c). The stretches of the evpn object of the Bgp setting name each Network and its L2 VNI, the
// sidecar reads the route distinguisher and the route targets of each, and the module carries each L2 VNI beside the L3 VNIs.
//
// The L2 data path attaches the switch of a Network (Core/Switch.h), as it attaches it for the DHCP responder and the live
// operations (NodeStretchAttach). While a sidecar with a stretch of that Network runs, the fabric is a member of the switch: an
// access port of the VLAN of the Network that subscribes to every group, as a bridge to a LAN does. The attachment outlives the
// sidecar, so the sidecar that starts next finds the switch of each Network.
//
// Into the fabric: a frame that the switch hands the port of the fabric goes to the VTEP of the type-2 route of its destination,
// one datagram; any other frame, broadcast, multicast or to an address of no route, goes to each VTEP of the flood list of the VNI
// once (ingress replication, VxlanSend), as the underlay has no multicast. Inside the overlay a frame keeps the group subscription
// of the switch (ADR-0014): the fabric gets the frames of every group, and a member of the overlay only those of the groups that
// it subscribes to, so the overlay is not flooded across the WAN; and a frame never goes back to the port it came from, so a
// frame of the fabric never goes back into the fabric.
//
// Out of the fabric: a frame of an L2 VNI enters the switch of its Network at the port of the fabric when it comes from a VTEP
// that the gateway knows for the VNI, the VTEP of a type-3 or a type-2 route of the VNI, as the gateway takes the frames of an L3
// VNI only from a VTEP of a route of its VRF (SDN-25-R1, #549); any other is dropped and counted. The switch learns its source at
// the port of the fabric and delivers it as it delivers the frame of any member.
//
// The routes of the fabric: the sidecar names the type-2 and type-3 routes of each VNI in stretch messages of
// NODE_STRETCH_MAX_ROUTES routes at most, as learned or, with withdraw, as gone (NodeStretchParseRoutes). The node holds them, and
// builds from them once for each read of the pipe (NodeStretchCommit) the flood list of each VNI, which the module takes, the VTEP
// of each MAC address and the VTEPs that it knows. The MAC address of a type-2 route enters the MAC table of the switch at the
// port of the fabric, a remote MAC through this gateway (SwitchLearnAt), so a frame of the overlay to it goes to the fabric alone
// and floods nowhere; an address that the switch has at another port stays there, as what a member sends wins over what a
// route says.
//
// The routes of the gateway: the thread of the stretch (NodeStretchRun) reads the MAC table and the IP table of the switch of each
// stretched Network once a NODE_STRETCH_ROUND, and the sidecar announces a type-2 route for each MAC address that a member of the
// overlay sends from, MAC only, and for each IP address that it sends from, MAC plus IP, so that the fabric can suppress ARP and
// ND for a known host of the overlay. A route that went is withdrawn. The first round after the start of a sidecar is a full
// resync: every route in stretch messages of NODE_STRETCH_MAX_ROUTES routes at most, the first with full and each but the last
// with more, after which the sidecar withdraws what it announced before and the resync did not name. When the pipe closes the
// routes of the fabric go, and the sidecar that starts next learns them again from the fabric: the full resync of the other way.
//
// MAC mobility, the MAC import limit, the stale timer and their events are SDN-65 (#292); the BUM rate limit and the drop of BPDUs
// are SDN-66 (#293).
//
// The locks. Config serialises what calls the switches: the attach and the detach of a switch, the start and the stop of a sidecar
// (NodeStretchBind, NodeStretchUnbind) and the rounds of the thread; the data path never takes it. Lock, a slim reader/writer
// lock, guards the rest: the data path holds it shared to read the tables, a change holds it exclusive, and no thread holds it
// while it calls a switch or waits, as the switch calls the port of the fabric under the locks of its ports (NodeStretchSend). A
// frame of the fabric counts itself in the Inputs of its Network while it is in the switch, outside Lock, and the port of the
// fabric leaves a switch once no frame is (NodeStretchUnplug).

#include "NodeEvpn.h"

#include "Mayaqua/Memory.h"
#include "Mayaqua/Object.h"
#include "Mayaqua/Str.h"

#include "Core/Switch.h"

#include "NodeInternal.h"

#include <WinDNS.h>
#include <iphlpapi.h>
#include <stdlib.h>
#include <ws2tcpip.h>

#include <cjson/cJSON.h>

#define NODE_STRETCH_ROUND 500  // ms between two rounds of the thread of the stretch
#define NODE_STRETCH_CHUNK 1024 // The MAC addresses of the fabric that a round copies at once, to put them into a switch

// A MAC address of the fabric and the VTEP of its type-2 route, as the port of the fabric looks it up
typedef struct NODE_STRETCH_MAC {
	UCHAR Mac[6];    // The address
	VXLAN_ADDR Vtep; // The VTEP of the fabric, on the UDP port of the VTEPs of the fabric
} NODE_STRETCH_MAC;

// The address of a VTEP that the gateway knows for a VNI: an IPv4 address as an IPv4-mapped one
typedef struct NODE_STRETCH_VTEP {
	UCHAR Ip[16];
} NODE_STRETCH_VTEP;

// A type-2 route of the gateway: a MAC address of a Network on its VNI, and an IP address of it for the MAC plus IP form
typedef struct NODE_STRETCH_LOCAL {
	UINT Vni;     // The L2 VNI
	UCHAR Mac[6]; // The MAC address
	UCHAR Ip[16]; // The IP address: 4 bytes for IPv4, 16 for IPv6 ...
	UINT IpSize;  // ... their number, 0 for MAC only
} NODE_STRETCH_LOCAL;

// A Network that a stretch of the running sidecar names, or whose switch the L2 data path attached
typedef struct NODE_STRETCH_NET {
	NODE_STRETCH *Owner;             // The stretch of the node
	char Network[NODE_STRETCH_NAME]; // The L2 Network
	UINT Vni;                        // Its L2 VNI while a sidecar with a stretch of it runs, 0 otherwise
	SWITCH *Switch;                  // The switch that the L2 data path attached, NULL for none ...
	UINT Vlan;                       // ... the VLAN of the Network on it ...
	UINT Port;                       // ... and the port of the fabric on it, SWITCH_PORT_NONE while it has none
	volatile LONG Inputs;            // Frames of the fabric in the switch now (NodeStretchInput)
	NODE_STRETCH_MAC *Macs;          // The MAC address of each type-2 route of the VNI with its VTEP, by address, each once ...
	UINT NumMacs;                    // ... their number
	NODE_STRETCH_VTEP *Known;        // The VTEPs of the routes of the VNI, which the gateway takes its frames from, sorted ...
	UINT NumKnown;                   // ... their number
	VXLAN_ADDR *Flood;               // The flood list: the VTEPs of the type-3 routes of the VNI ...
	UINT NumFlood;                   // ... their number
} NODE_STRETCH_NET;

// What the thread of the stretch keeps from the start of a sidecar to its stop
typedef struct NODE_STRETCH_RUN {
	NODE_STRETCH *Stretch;                             // The stretch of the node
	NODE_BGP *Bgp;                                     // The sidecar that the routes of the gateway go to
	bool Resync;                                       // The next round is a full resync
	bool Full;                                         // The switches gave more routes than NODE_STRETCH_MAX_LOCAL, which the node log said
	SWITCH_MAC_ENTRY *Macs;                            // The MAC table of a switch, whole (NodeStretchGetMacs) ...
	UINT MaxMacs;                                      // ... in this many entries, which grow until the table fits them
	SWITCH_IP_ENTRY *Ips;                              // ... and its IP table (NodeStretchGetIps) ...
	UINT MaxIps;                                       // ... in this many entries
	NODE_STRETCH_MAC *Remote;                          // NODE_STRETCH_CHUNK MAC addresses of the fabric, for the switch of their Network
	NODE_STRETCH_LOCAL *Want;                          // The routes of the gateway that the switches give this round ...
	UINT NumWant;                                      // ... their number, NODE_STRETCH_MAX_LOCAL at most
	NODE_STRETCH_LOCAL *Have;                          // The routes that the sidecar announces ...
	UINT NumHave;                                      // ... their number
	NODE_STRETCH_LOCAL Batch[NODE_STRETCH_MAX_ROUTES]; // The routes of the next stretch message ...
	bool BatchWithdraw[NODE_STRETCH_MAX_ROUTES];       // ... whether each goes ...
	UINT NumBatch;                                     // ... and their number
} NODE_STRETCH_RUN;

// The stretch of a gateway, from the first attach of a switch or start of a sidecar with a stretch to FreeNode
struct NODE_STRETCH {
	NODE *Node;              // The node
	LOCK *Config;            // Serialises what calls the switches; never taken on the data path
	SRWLOCK Lock;            // What follows: shared on the data path, exclusive for a change, never held while calling a switch
	LIST *Nets;              // The Networks (NODE_STRETCH_NET), which only NodeStretchFree frees
	UINT NumStretches;       // The stretches of the running sidecar
	VXLAN *Vxlan;            // The module of its EVPN, which carries their L2 VNIs; NULL while none runs
	USHORT FabricPort;       // The UDP port of the VTEPs of the fabric
	LIST *Remote;            // The routes of the fabric (NODE_STRETCH_ROUTE), in the order of NodeStretchCompareRoute
	bool Dirty;              // They changed since the tables of the Networks were built
	HANDLE Halt;             // Ends the thread (manual reset)
	HANDLE Wake;             // The routes of the fabric changed: the thread puts them into the switches (auto-reset)
	HANDLE Thread;           // The thread while a sidecar with a stretch runs, under the node lock ...
	NODE_STRETCH_RUN *Run;   // ... and what it keeps
	volatile LONG Announced; // The counters of NODE_STRETCH_STATUS
	volatile LONG64 Resyncs;
	volatile LONG64 Unicast;
	volatile LONG64 Flooded;
	volatile LONG64 Failed;
	volatile LONG64 Delivered;
	volatile LONG64 Undelivered;
	volatile LONG64 UnknownVtep;
	volatile LONG64 Refused;
};

//
// The text of the sidecar and of the evpn object
//

// The whole number of the JSON item into *value when it is a VNI of 24 bits, 1 to VXLAN_MAX_VNI; false for any other item
static bool NodeStretchJsonVni(const cJSON *item, UINT *value) {
	if (cJSON_IsNumber(item) == false || (item->valuedouble >= 1 && item->valuedouble <= (double)VXLAN_MAX_VNI) == false)
		return false;

	UINT vni = (UINT)item->valuedouble;
	if ((double)vni != item->valuedouble)
		return false;

	*value = vni;
	return true;
}

// The string member name of a JSON object into *str, NULL when it has none; false when it has one that is no string
static bool NodeStretchJsonText(const cJSON *o, const char *name, const char **str) {
	const cJSON *item = cJSON_GetObjectItemCaseSensitive(o, name);

	*str = cJSON_GetStringValue(item);

	return (item == NULL || *str != NULL);
}

// Whether mac is the MAC address of one host: no group address, and not all zero
static bool NodeStretchHostMac(const UCHAR *mac) {
	static const UCHAR zero[6] = {0};

	return ((mac[0] & 0x01) == 0 && Cmp(mac, zero, sizeof(zero)) != 0);
}

// Whether the IP address of size bytes is the address of one host, which the sidecar takes in the MAC plus IP form: not
// unspecified and no loopback, multicast or broadcast address, an IPv4-mapped one judged as its IPv4 address
static bool NodeStretchHostIp(const UCHAR *ip, UINT size) {
	static const UCHAR mapped[12] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF};
	static const UCHAR zero[16] = {0};

	if (size == 16 && Cmp(ip, mapped, sizeof(mapped)) == 0) {
		ip += 12;
		size = 4;
	}
	if (size == 4)
		return (ip[0] != 0 && ip[0] != 127 && ip[0] < 224);
	if (size != 16 || ip[0] == 0xFF || Cmp(ip, zero, sizeof(zero)) == 0)
		return false;

	// ::1
	return (Cmp(ip, zero, 15) != 0 || ip[15] != 1);
}

// The text of the IP address of size bytes, 4 for IPv4 and 16 for IPv6, into str of str_size bytes: false when it has none
static bool NodeStretchIpText(char *str, UINT str_size, const UCHAR *ip, UINT size) {
	return (inet_ntop(size == 4 ? AF_INET : AF_INET6, ip, str, str_size) != NULL);
}

// The VTEP of a text into vtep, 16 bytes, an IPv4 address as an IPv4-mapped one, as VXLAN_ADDR holds the source of a datagram;
// false when the text is no address
static bool NodeStretchVtepOf(const char *str, UCHAR *vtep) {
	UCHAR addr[16];
	UINT size = NodeEvpnParseAddr(str, NET_STRING_IP_ADDRESS_NO_SCOPE, addr, NULL);

	Zero(vtep, 16);
	if (size == 4) {
		vtep[10] = 0xFF;
		vtep[11] = 0xFF;
		Copy(vtep + 12, addr, 4);
	} else if (size == 16) {
		Copy(vtep, addr, 16);
	}

	return (size != 0);
}

// One route of a stretch message of the sidecar into r: false for one that the node cannot take (NodeStretchParseRoutes)
static bool NodeStretchRouteOf(const cJSON *o, NODE_STRETCH_ROUTE *r) {
	const cJSON *withdraw = cJSON_GetObjectItemCaseSensitive(o, "withdraw");
	const char *mac = NULL;
	const char *ip = NULL;
	const char *next_hop = NULL;

	Zero(r, sizeof(NODE_STRETCH_ROUTE));
	if (cJSON_IsObject(o) == false || NodeStretchJsonVni(cJSON_GetObjectItemCaseSensitive(o, "vni"), &r->Vni) == false)
		return false;
	if ((withdraw != NULL && cJSON_IsBool(withdraw) == false) || NodeStretchJsonText(o, "mac", &mac) == false ||
	    NodeStretchJsonText(o, "ip", &ip) == false || NodeStretchJsonText(o, "next_hop", &next_hop) == false)
		return false;

	// The VTEP of the fabric: the next hop of a type-2 route, and the VTEP of the flood list of a type-3 route
	r->Withdraw = (cJSON_IsTrue(withdraw) != false);
	if (NodeStretchVtepOf(next_hop, r->Vtep) == false)
		return false;

	// A type-3 route has no MAC address, and so no IP address
	if (mac == NULL) {
		r->Imet = true;
		return (ip == NULL);
	}

	if (NodeEvpnParseMac(mac, r->Mac) == false || NodeStretchHostMac(r->Mac) == false)
		return false;
	if (ip != NULL) {
		r->IpSize = NodeEvpnParseAddr(ip, NET_STRING_IP_ADDRESS_NO_SCOPE, r->Ip, NULL);
		if (r->IpSize == 0)
			return false;
	}

	return true;
}

// Read one message of the sidecar, a JSON object on one line, as a stretch message (ranz-bgp/internal/sidecar/stretch.go): its
// routes, max of them at most, into list, and into *bad the number of the routes of the message that the node cannot take or
// that are beyond max. A route has a VNI of 24 bits (vni) and the VTEP of the fabric as its next hop (next_hop): a type-2 route
// has the MAC address of one host (mac) and, in the MAC plus IP form, an IP address (ip), a type-3 route neither; withdraw says
// that it went. The number of the routes in list; NODE_STRETCH_NO_MESSAGE for any other message, and for one whose routes are
// no array.
UINT NodeStretchParseRoutes(const char *line, NODE_STRETCH_ROUTE *list, UINT max, UINT *bad) {
	UINT num = 0;
	UINT refused = 0;

	if (bad != NULL)
		*bad = 0;
	if (line == NULL || (list == NULL && max != 0))
		return NODE_STRETCH_NO_MESSAGE;

	cJSON *m = cJSON_Parse(line);
	const cJSON *routes = cJSON_GetObjectItemCaseSensitive(m, "routes");
	const char *type = cJSON_GetStringValue(cJSON_GetObjectItemCaseSensitive(m, "type"));

	if (cJSON_IsObject(m) == false || type == NULL || StrCmp(type, "stretch") != 0 || (routes != NULL && cJSON_IsArray(routes) == false)) {
		cJSON_Delete(m);
		return NODE_STRETCH_NO_MESSAGE;
	}

	for (const cJSON *o = (routes != NULL ? routes->child : NULL); o != NULL; o = o->next) {
		if (num < max && NodeStretchRouteOf(o, &list[num]))
			num++;
		else
			refused++;
	}

	cJSON_Delete(m);

	if (bad != NULL)
		*bad = refused;

	return num;
}

// The stretches of the array stretches of an evpn object into list, NODE_STRETCH_MAX at most, each with its L2 Network (network)
// and its L2 VNI (vni), which is none of the num_l3 L3 VNIs of l3_vnis: their number. 0 with why into error for more than
// NODE_STRETCH_MAX, for a stretch without a Network or without a VNI of 24 bits, for a Network or a VNI that comes twice and for
// the L3 VNI of a VRF; 0 with error left as it was for no stretches.
UINT NodeStretchSettings(cJSON *stretches, const UINT *l3_vnis, UINT num_l3, NODE_STRETCH_SETTING *list, char *error, UINT error_size) {
	UINT num = 0;

	if (stretches == NULL || list == NULL || error == NULL)
		return 0;
	if (cJSON_IsArray(stretches) == false || cJSON_GetArraySize(stretches) > NODE_STRETCH_MAX) {
		Format(error, error_size, "stretches is no array of %u stretches at most", (UINT)NODE_STRETCH_MAX);
		return 0;
	}

	for (const cJSON *o = stretches->child; o != NULL; o = o->next) {
		const char *network = cJSON_GetStringValue(cJSON_GetObjectItemCaseSensitive(o, "network"));
		UINT vni = 0;

		if (IsEmptyStr(network) || StrLen(network) >= NODE_STRETCH_NAME || NodeStretchJsonVni(cJSON_GetObjectItemCaseSensitive(o, "vni"), &vni) == false) {
			StrCpy(error, error_size, "a stretch of stretches has no network, or no VNI of 24 bits");
			return 0;
		}
		for (UINT i = 0; i < num; i++) {
			if (StrCmp(list[i].Network, network) == 0 || list[i].Vni == vni) {
				Format(error, error_size, "the L2 Network %s or its VNI %u comes twice in stretches", network, vni);
				return 0;
			}
		}
		for (UINT i = 0; l3_vnis != NULL && i < num_l3; i++) {
			if (l3_vnis[i] == vni) {
				Format(error, error_size, "the VNI %u of the stretch of the L2 Network %s is the L3 VNI of a VRF", vni, network);
				return 0;
			}
		}

		StrCpy(list[num].Network, sizeof(list[num].Network), network);
		list[num].Vni = vni;
		num++;
	}

	return num;
}

//
// The tables
//

// The order of the routes of the fabric: by VNI, the type-2 routes first, by MAC address, IP address size and IP address, and the
// type-3 routes by VTEP. A COMPARE of the list of the routes, whose items are pointers to them.
static int NodeStretchCompareRoute(void *p1, void *p2) {
	const NODE_STRETCH_ROUTE *a = *(const NODE_STRETCH_ROUTE **)p1;
	const NODE_STRETCH_ROUTE *b = *(const NODE_STRETCH_ROUTE **)p2;

	if (a->Vni != b->Vni)
		return (a->Vni < b->Vni ? -1 : 1);
	if (a->Imet != b->Imet)
		return (a->Imet ? 1 : -1);
	if (a->Imet)
		return Cmp(a->Vtep, b->Vtep, sizeof(a->Vtep));

	int c = Cmp(a->Mac, b->Mac, sizeof(a->Mac));
	if (c != 0)
		return c;
	if (a->IpSize != b->IpSize)
		return (a->IpSize < b->IpSize ? -1 : 1);

	return Cmp(a->Ip, b->Ip, sizeof(a->Ip));
}

// The order of the MAC addresses of a Network, for qsort and bsearch
static int NodeStretchCompareMac(const void *p1, const void *p2) {
	return Cmp(((const NODE_STRETCH_MAC *)p1)->Mac, ((const NODE_STRETCH_MAC *)p2)->Mac, 6);
}

// The order of the VTEPs that the gateway knows for a VNI, for qsort and bsearch
static int NodeStretchCompareVtep(const void *p1, const void *p2) {
	return Cmp(((const NODE_STRETCH_VTEP *)p1)->Ip, ((const NODE_STRETCH_VTEP *)p2)->Ip, 16);
}

// The order of the routes of the gateway: by VNI, MAC address, IP address size and IP address, for qsort
static int NodeStretchCompareLocal(const void *p1, const void *p2) {
	const NODE_STRETCH_LOCAL *a = (const NODE_STRETCH_LOCAL *)p1;
	const NODE_STRETCH_LOCAL *b = (const NODE_STRETCH_LOCAL *)p2;

	if (a->Vni != b->Vni)
		return (a->Vni < b->Vni ? -1 : 1);

	int c = Cmp(a->Mac, b->Mac, sizeof(a->Mac));
	if (c != 0)
		return c;
	if (a->IpSize != b->IpSize)
		return (a->IpSize < b->IpSize ? -1 : 1);

	return Cmp(a->Ip, b->Ip, sizeof(a->Ip));
}

// The tables of the Network net from the routes of the fabric of its VNI, which come in order: the MAC address of each type-2
// route with its VTEP, each address once, the VTEPs that the gateway knows for the VNI, and the flood list, the VTEPs of the
// type-3 routes, which the module takes after (NodeStretchCommit). The caller holds Lock exclusive.
static void NodeStretchBuild(NODE_STRETCH *s, NODE_STRETCH_NET *net) {
	UINT num = 0;

	Free(net->Macs);
	Free(net->Known);
	Free(net->Flood);
	net->Macs = NULL;
	net->Known = NULL;
	net->Flood = NULL;
	net->NumMacs = 0;
	net->NumKnown = 0;
	net->NumFlood = 0;

	for (UINT i = 0; net->Vni != 0 && i < LIST_NUM(s->Remote); i++) {
		const NODE_STRETCH_ROUTE *r = LIST_DATA(s->Remote, i);

		if (r->Vni == net->Vni)
			num++;
	}
	if (num == 0)
		return;

	net->Macs = ZeroMalloc(sizeof(NODE_STRETCH_MAC) * num);
	net->Known = ZeroMalloc(sizeof(NODE_STRETCH_VTEP) * num);
	net->Flood = ZeroMalloc(sizeof(VXLAN_ADDR) * num);

	for (UINT i = 0; i < LIST_NUM(s->Remote); i++) {
		const NODE_STRETCH_ROUTE *r = LIST_DATA(s->Remote, i);
		VXLAN_ADDR vtep;

		if (r->Vni != net->Vni)
			continue;

		Zero(&vtep, sizeof(vtep));
		Copy(vtep.Ip, r->Vtep, sizeof(vtep.Ip));
		vtep.Port = s->FabricPort;
		vtep.Encap = VXLAN_ENCAP_VXLAN;
		Copy(net->Known[net->NumKnown++].Ip, r->Vtep, sizeof(r->Vtep));

		if (r->Imet) {
			if (net->NumFlood < VXLAN_MAX_VTEPS)
				net->Flood[net->NumFlood++] = vtep;
		} else if (net->NumMacs == 0 || Cmp(net->Macs[net->NumMacs - 1].Mac, r->Mac, sizeof(r->Mac)) != 0) {
			// The MAC only form of an address comes before its MAC plus IP forms: one entry for each address
			Copy(net->Macs[net->NumMacs].Mac, r->Mac, sizeof(r->Mac));
			net->Macs[net->NumMacs].Vtep = vtep;
			net->NumMacs++;
		}
	}

	// Each VTEP once, as NodeStretchKnows looks them up
	UINT known = 0;
	qsort(net->Known, net->NumKnown, sizeof(NODE_STRETCH_VTEP), NodeStretchCompareVtep);
	for (UINT i = 0; i < net->NumKnown; i++) {
		if (known == 0 || NodeStretchCompareVtep(&net->Known[known - 1], &net->Known[i]) != 0)
			net->Known[known++] = net->Known[i];
	}
	net->NumKnown = known;
}

// Forget every route of the fabric: their number. The caller holds Lock exclusive, or is the last user of s.
static UINT NodeStretchForget(NODE_STRETCH *s) {
	UINT num = LIST_NUM(s->Remote);

	for (UINT i = 0; i < num; i++)
		Free(LIST_DATA(s->Remote, i));
	DeleteAll(s->Remote);
	s->Dirty = true;

	return num;
}

// The type-2 route of the fabric of the destination mac of a frame in the tables of net, NULL for none; the caller holds Lock
static const NODE_STRETCH_MAC *NodeStretchFindMac(const NODE_STRETCH_NET *net, const UCHAR *mac) {
	NODE_STRETCH_MAC key;

	if (net->NumMacs == 0)
		return NULL;

	Zero(&key, sizeof(key));
	Copy(key.Mac, mac, sizeof(key.Mac));

	return (const NODE_STRETCH_MAC *)bsearch(&key, net->Macs, net->NumMacs, sizeof(NODE_STRETCH_MAC), NodeStretchCompareMac);
}

// Whether the address ip, 16 bytes with an IPv4 address as an IPv4-mapped one, is a VTEP that the gateway knows for the VNI of net;
// the caller holds Lock
static bool NodeStretchKnows(const NODE_STRETCH_NET *net, const UCHAR *ip) {
	NODE_STRETCH_VTEP key;

	if (net->NumKnown == 0)
		return false;

	Copy(key.Ip, ip, sizeof(key.Ip));

	return (bsearch(&key, net->Known, net->NumKnown, sizeof(NODE_STRETCH_VTEP), NodeStretchCompareVtep) != NULL);
}

//
// The stretch of a node and its Networks
//

// The stretch of the node, NULL before its first attach of a switch or sidecar with a stretch
static NODE_STRETCH *NodeStretchOf(NODE *n) {
	return (n != NULL ? (NODE_STRETCH *)ReadPointerAcquire((PVOID const volatile *)&n->Stretch) : NULL);
}

// Free a stretch that no thread reaches any more: its Networks and their tables, the routes of the fabric and its events
static void NodeStretchRelease(NODE_STRETCH *s) {
	for (UINT i = 0; i < LIST_NUM(s->Nets); i++) {
		NODE_STRETCH_NET *net = LIST_DATA(s->Nets, i);

		Free(net->Macs);
		Free(net->Known);
		Free(net->Flood);
		Free(net);
	}
	ReleaseList(s->Nets);

	NodeStretchForget(s);
	ReleaseList(s->Remote);

	if (s->Halt != NULL)
		CloseHandle(s->Halt);
	if (s->Wake != NULL)
		CloseHandle(s->Wake);
	DeleteLock(s->Config);
	Free(s);
}

// The stretch of the node, made at its first use: the attach of a switch or the start of a sidecar with a stretch
static NODE_STRETCH *NodeStretchMake(NODE *n) {
	NODE_STRETCH *s = NodeStretchOf(n);

	if (s != NULL)
		return s;

	NODE_STRETCH *fresh = ZeroMalloc(sizeof(NODE_STRETCH));
	fresh->Node = n;
	fresh->Config = NewLock();
	InitializeSRWLock(&fresh->Lock);
	fresh->Nets = NewListFast(NULL);
	fresh->Remote = NewListFast(NodeStretchCompareRoute);
	fresh->Halt = CreateEventW(NULL, TRUE, FALSE, NULL);
	fresh->Wake = CreateEventW(NULL, FALSE, FALSE, NULL);

	// Another thread may have made it first
	s = (NODE_STRETCH *)InterlockedCompareExchangePointer((PVOID volatile *)&n->Stretch, fresh, NULL);
	if (s != NULL) {
		NodeStretchRelease(fresh);
		return s;
	}

	return fresh;
}

// The Network name among the Networks of s, which is made when make is true; NULL for none. The caller holds Config, and a new
// Network joins the list under Lock, as the data path reads the list.
static NODE_STRETCH_NET *NodeStretchNet(NODE_STRETCH *s, const char *name, bool make) {
	for (UINT i = 0; i < LIST_NUM(s->Nets); i++) {
		NODE_STRETCH_NET *net = LIST_DATA(s->Nets, i);

		if (StrCmp(net->Network, name) == 0)
			return net;
	}
	if (make == false)
		return NULL;

	NODE_STRETCH_NET *net = ZeroMalloc(sizeof(NODE_STRETCH_NET));
	net->Owner = s;
	StrCpy(net->Network, sizeof(net->Network), name);
	net->Port = SWITCH_PORT_NONE;

	AcquireSRWLockExclusive(&s->Lock);
	Add(s->Nets, net);
	ReleaseSRWLockExclusive(&s->Lock);

	return net;
}

// The Network of the L2 VNI vni, NULL for none; the caller holds Lock
static NODE_STRETCH_NET *NodeStretchNetOf(NODE_STRETCH *s, UINT vni) {
	for (UINT i = 0; vni != 0 && i < LIST_NUM(s->Nets); i++) {
		NODE_STRETCH_NET *net = LIST_DATA(s->Nets, i);

		if (net->Vni == vni)
			return net;
	}

	return NULL;
}

//
// The port of the fabric
//

// The port of the fabric (SWITCH_SEND_PROC): a frame that the switch of the Network of param hands the fabric, on the thread of
// SwitchInput, under the locks of its ports. It goes to the VTEP of the type-2 route of its destination, one datagram, or to each
// VTEP of the flood list of the VNI once.
static void NodeStretchSend(void *param, UINT port, const UCHAR *frame, UINT size) {
	NODE_STRETCH_NET *net = (NODE_STRETCH_NET *)param;
	NODE_STRETCH *s = net->Owner;
	volatile LONG64 *count = &s->Failed;

	UNREFERENCED_PARAMETER(port);

	AcquireSRWLockShared(&s->Lock);
	if (s->Vxlan != NULL && net->Vni != 0) {
		const NODE_STRETCH_MAC *m = ((frame[0] & 0x01) == 0 ? NodeStretchFindMac(net, frame) : NULL);

		if (m != NULL)
			count = (VxlanSendTo(s->Vxlan, net->Vni, &m->Vtep, frame, size) ? &s->Unicast : &s->Failed);
		else
			count = (VxlanSend(s->Vxlan, net->Vni, frame, size) ? &s->Flooded : &s->Failed);
	}
	ReleaseSRWLockShared(&s->Lock);

	InterlockedIncrement64(count);
}

// Put the port of the fabric on the switch of net when a sidecar with a stretch of its Network runs: an access port of the VLAN
// of the Network that subscribes to every group, as a bridge to a LAN does. The caller holds Config and not Lock.
static void NodeStretchPlug(NODE_STRETCH *s, NODE_STRETCH_NET *net) {
	SWITCH_PORT_CONFIG pc;

	if (net->Switch == NULL || net->Vni == 0 || s->Vxlan == NULL || net->Port != SWITCH_PORT_NONE)
		return;

	Zero(&pc, sizeof(pc));
	pc.Mode = SWITCH_ACCESS;
	pc.Vlan = net->Vlan;
	pc.Send = NodeStretchSend;
	pc.Param = net;

	UINT port = SwitchAddPort(net->Switch, &pc);
	if (port != SWITCH_PORT_NONE && SwitchSubscribe(net->Switch, port, net->Vlan, NULL) == false) {
		SwitchDelPort(net->Switch, port);
		port = SWITCH_PORT_NONE;
	}

	AcquireSRWLockExclusive(&s->Lock);
	net->Port = port;
	ReleaseSRWLockExclusive(&s->Lock);

	if (port == SWITCH_PORT_NONE)
		NodeLog(s->Node, "EVPN stretch: the fabric could not join the switch of the L2 Network %s", net->Network);
	else
		NodeLog(s->Node, "EVPN stretch: the fabric is port %u of the switch of the L2 Network %s, VLAN %u, L2 VNI %u", port, net->Network, net->Vlan, net->Vni);
}

// Take the port of the fabric off the switch of net: once this returns no frame of the fabric is in the switch, and the switch
// calls the port no more. The caller holds Config and not Lock.
static void NodeStretchUnplug(NODE_STRETCH *s, NODE_STRETCH_NET *net) {
	UINT port = SWITCH_PORT_NONE;

	AcquireSRWLockExclusive(&s->Lock);
	port = net->Port;
	net->Port = SWITCH_PORT_NONE;
	ReleaseSRWLockExclusive(&s->Lock);

	// A frame of the fabric that found the port before goes on to its end
	while (InterlockedCompareExchange(&net->Inputs, 0, 0) != 0)
		Sleep(1);

	if (port != SWITCH_PORT_NONE) {
		SwitchDelPort(net->Switch, port);
		NodeLog(s->Node, "EVPN stretch: the fabric left the switch of the L2 Network %s", net->Network);
	}
}

// The L2 data path attaches the switch sw of the L2 Network network, whose VLAN on it is vlan: while a sidecar with a stretch of the
// Network runs, the fabric is a member of the switch. The attachment holds until NodeStretchDetach, also while no sidecar runs.
// False for a name or a switch that is none or a VLAN that is no VLAN id, and when the fabric could not join the switch.
bool NodeStretchAttach(NODE *n, const char *network, SWITCH *sw, UINT vlan) {
	bool ok = false;

	if (n == NULL || IsEmptyStr(network) || StrLen(network) >= NODE_STRETCH_NAME || sw == NULL || vlan < SWITCH_MIN_VLAN || vlan > SWITCH_MAX_VLAN)
		return false;

	NODE_STRETCH *s = NodeStretchMake(n);

	Lock(s->Config);
	{
		NODE_STRETCH_NET *net = NodeStretchNet(s, network, true);

		// The switch that the Network had goes first
		NodeStretchUnplug(s, net);

		AcquireSRWLockExclusive(&s->Lock);
		net->Switch = sw;
		net->Vlan = vlan;
		ReleaseSRWLockExclusive(&s->Lock);

		NodeStretchPlug(s, net);
		ok = (net->Vni == 0 || s->Vxlan == NULL || net->Port != SWITCH_PORT_NONE);
	}
	Unlock(s->Config);

	// The thread puts the MAC addresses of the fabric into the switch, and announces the addresses of its members
	SetEvent(s->Wake);

	return ok;
}

// The L2 data path detaches the switch of the L2 Network network before it frees it: the port of the fabric leaves the switch, and
// once this returns the stretch reaches the switch no more
void NodeStretchDetach(NODE *n, const char *network) {
	NODE_STRETCH *s = NodeStretchOf(n);

	if (s == NULL || network == NULL)
		return;

	Lock(s->Config);
	{
		NODE_STRETCH_NET *net = NodeStretchNet(s, network, false);

		if (net != NULL) {
			NodeStretchUnplug(s, net);

			AcquireSRWLockExclusive(&s->Lock);
			net->Switch = NULL;
			net->Vlan = 0;
			ReleaseSRWLockExclusive(&s->Lock);
		}
	}
	Unlock(s->Config);
}

// The EVPN of a gateway started with its sidecar (NodeEvpnStart): the num stretches of list run on its module vxlan, which carries
// their L2 VNIs, with the VTEPs of the fabric on fabric_port, and the fabric joins the switch of each of their Networks that the L2
// data path attached. The caller holds the node lock.
void NodeStretchBind(NODE *n, VXLAN *vxlan, USHORT fabric_port, const NODE_STRETCH_SETTING *list, UINT num) {
	if (n == NULL || vxlan == NULL || list == NULL || num == 0)
		return;

	NODE_STRETCH *s = NodeStretchMake(n);

	Lock(s->Config);
	{
		for (UINT i = 0; i < num; i++) {
			NODE_STRETCH_NET *net = NodeStretchNet(s, list[i].Network, true);

			AcquireSRWLockExclusive(&s->Lock);
			net->Vni = list[i].Vni;
			ReleaseSRWLockExclusive(&s->Lock);
		}

		AcquireSRWLockExclusive(&s->Lock);
		s->Vxlan = vxlan;
		s->FabricPort = fabric_port;
		s->NumStretches = num;
		ReleaseSRWLockExclusive(&s->Lock);

		for (UINT i = 0; i < LIST_NUM(s->Nets); i++)
			NodeStretchPlug(s, LIST_DATA(s->Nets, i));
	}
	Unlock(s->Config);

	NodeLog(n, "EVPN stretch: %u L2 Networks stretched into the fabric, the VTEPs of the fabric on UDP port %u", num, (UINT)fabric_port);
}

// The EVPN of the gateway stops with its sidecar (NodeEvpnStop), before its module goes: the fabric leaves the switch of each
// Network, and the routes of the fabric go. Once this returns the stretch reaches the module no more. The caller holds the node
// lock, and the thread of the stretch has ended (NodeStretchHalt).
void NodeStretchUnbind(NODE *n) {
	NODE_STRETCH *s = NodeStretchOf(n);
	UINT num = 0;

	if (s == NULL)
		return;

	Lock(s->Config);
	{
		for (UINT i = 0; i < LIST_NUM(s->Nets); i++)
			NodeStretchUnplug(s, LIST_DATA(s->Nets, i));

		AcquireSRWLockExclusive(&s->Lock);
		s->Vxlan = NULL;
		s->NumStretches = 0;
		num = NodeStretchForget(s);
		for (UINT i = 0; i < LIST_NUM(s->Nets); i++) {
			NODE_STRETCH_NET *net = LIST_DATA(s->Nets, i);

			net->Vni = 0;
			NodeStretchBuild(s, net);
		}
		s->Dirty = false;
		ReleaseSRWLockExclusive(&s->Lock);
	}
	Unlock(s->Config);

	NodeLog(n, "EVPN stretch stopped: %u routes of the fabric removed", num);
}

// Free the stretch of a node that stopped (FreeNode), whose switches the L2 data path detached or frees itself
void NodeStretchFree(NODE *n) {
	NODE_STRETCH *s = (n != NULL ? (NODE_STRETCH *)InterlockedExchangePointer((PVOID volatile *)&n->Stretch, NULL) : NULL);

	if (s != NULL)
		NodeStretchRelease(s);
}

//
// The data path out of the fabric
//

// A frame of the fabric on the VNI vni from the VTEP from, on the receive thread of the socket of the EVPN (NodeEvpnReceive). When
// vni is the L2 VNI of a stretch, the frame enters the switch of its Network at the port of the fabric if from is a VTEP that the
// gateway knows for the VNI (the address alone, as a VTEP sends from any source port), and is dropped and counted otherwise. True
// for a frame of an L2 VNI, which the EVPN of the VRFs then leaves alone; false for any other.
bool NodeStretchInput(NODE *n, UINT vni, const VXLAN_ADDR *from, const UCHAR *frame, UINT size) {
	NODE_STRETCH *s = NodeStretchOf(n);
	NODE_STRETCH_NET *net = NULL;
	SWITCH *sw = NULL;
	UINT port = SWITCH_PORT_NONE;
	bool known = false;

	if (s == NULL || from == NULL || frame == NULL)
		return false;

	AcquireSRWLockShared(&s->Lock);
	net = NodeStretchNetOf(s, vni);
	if (net != NULL) {
		known = NodeStretchKnows(net, from->Ip);
		if (known && net->Port != SWITCH_PORT_NONE) {
			sw = net->Switch;
			port = net->Port;
			InterlockedIncrement(&net->Inputs);
		}
	}
	ReleaseSRWLockShared(&s->Lock);

	if (net == NULL)
		return false;

	if (known == false) {
		InterlockedIncrement64(&s->UnknownVtep);
	} else if (sw == NULL) {
		InterlockedIncrement64(&s->Undelivered);
	} else {
		UINT num = SwitchInput(sw, GetTickCount64(), port, frame, size);

		InterlockedDecrement(&net->Inputs);
		InterlockedIncrement64(num != 0 ? &s->Delivered : &s->Undelivered);
	}

	return true;
}

//
// The routes of the fabric
//

// A message of the sidecar on one line (NodeBgp.c): the routes of a stretch message go into the routes of the fabric, a learned
// route in place of the route of its key that the gateway had, a route with withdraw out of them; NodeStretchCommit then builds
// them into the tables of the Networks. A route of no stretch, and a route beyond NODE_STRETCH_MAX_REMOTE, is not taken.
void NodeStretchMessage(NODE *n, const char *line) {
	NODE_STRETCH *s = NodeStretchOf(n);
	NODE_STRETCH_ROUTE *list = ZeroMalloc(sizeof(NODE_STRETCH_ROUTE) * NODE_STRETCH_MAX_ROUTES);
	UINT refused = 0;
	UINT learned = 0;
	UINT withdrawn = 0;
	UINT num = NodeStretchParseRoutes(line, list, NODE_STRETCH_MAX_ROUTES, &refused);

	if (num == NODE_STRETCH_NO_MESSAGE) {
		NodeLog(n, "EVPN stretch: a stretch message of the sidecar that is none, ignored");
		Free(list);
		return;
	}

	if (s == NULL) {
		refused += num;
		num = 0;
	}

	if (num != 0) {
		AcquireSRWLockExclusive(&s->Lock);
		for (UINT i = 0; i < num; i++) {
			NODE_STRETCH_ROUTE *r = &list[i];
			NODE_STRETCH_ROUTE *old = NULL;

			if (NodeStretchNetOf(s, r->Vni) == NULL) {
				refused++;
				continue;
			}

			old = Search(s->Remote, r);
			if (r->Withdraw) {
				if (old != NULL) {
					Delete(s->Remote, old);
					Free(old);
					withdrawn++;
					s->Dirty = true;
				}
			} else if (old != NULL) {
				// The same route from another VTEP: the MAC address moved, or the VTEP announces it again
				Copy(old->Vtep, r->Vtep, sizeof(old->Vtep));
				learned++;
				s->Dirty = true;
			} else if (LIST_NUM(s->Remote) < NODE_STRETCH_MAX_REMOTE) {
				NODE_STRETCH_ROUTE *copy = ZeroMalloc(sizeof(NODE_STRETCH_ROUTE));

				Copy(copy, r, sizeof(NODE_STRETCH_ROUTE));
				copy->Withdraw = false;
				Insert(s->Remote, copy);
				learned++;
				s->Dirty = true;
			} else {
				refused++;
			}
		}
		ReleaseSRWLockExclusive(&s->Lock);
	}

	if (s != NULL)
		InterlockedExchangeAdd64(&s->Refused, (LONG64)refused);
	NodeLog(n, "EVPN stretch: %u routes of the fabric learned, %u withdrawn, %u not taken", learned, withdrawn, refused);

	Free(list);
}

// Build the tables of each Network from the routes of the fabric when they changed, and give the module the flood list of each
// L2 VNI. The reader thread of the sidecar calls it after each read of the pipe, so that the routes of one read go in together,
// and wakes the thread of the stretch, which puts the MAC addresses of the fabric into the switches.
void NodeStretchCommit(NODE *n) {
	NODE_STRETCH *s = NodeStretchOf(n);
	bool dirty = false;

	if (s == NULL)
		return;

	AcquireSRWLockExclusive(&s->Lock);
	dirty = s->Dirty;
	if (dirty) {
		for (UINT i = 0; i < LIST_NUM(s->Nets); i++)
			NodeStretchBuild(s, LIST_DATA(s->Nets, i));
		s->Dirty = false;
	}
	ReleaseSRWLockExclusive(&s->Lock);

	if (dirty == false)
		return;

	// Only the reader thread changes the flood lists; the module takes each one under a lock of its own
	AcquireSRWLockShared(&s->Lock);
	for (UINT i = 0; s->Vxlan != NULL && i < LIST_NUM(s->Nets); i++) {
		NODE_STRETCH_NET *net = LIST_DATA(s->Nets, i);

		if (net->Vni != 0 && VxlanSetVni(s->Vxlan, net->Vni, net->Flood, net->NumFlood) == false)
			NodeLog(n, "EVPN stretch: the flood list of the L2 VNI %u did not go to the VXLAN module", net->Vni);
	}
	ReleaseSRWLockShared(&s->Lock);

	SetEvent(s->Wake);
}

// Forget every route of the fabric, as the sidecar closed the pipe (NodeBgp.c): the number of the routes that went, with the
// tables of the Networks and the flood lists
UINT NodeStretchFlush(NODE *n) {
	NODE_STRETCH *s = NodeStretchOf(n);
	UINT num = 0;

	if (s == NULL)
		return 0;

	AcquireSRWLockExclusive(&s->Lock);
	num = NodeStretchForget(s);
	ReleaseSRWLockExclusive(&s->Lock);

	NodeStretchCommit(n);

	return num;
}

//
// The routes of the gateway
//

// Add the route of the MAC address mac on vni, with the IP address ip of ip_size bytes for the MAC plus IP form (0 for MAC only),
// to the routes of the gateway of this round, while they are fewer than NODE_STRETCH_MAX_LOCAL
static void NodeStretchWant(NODE_STRETCH_RUN *r, UINT vni, const UCHAR *mac, const UCHAR *ip, UINT ip_size) {
	if (r->NumWant >= NODE_STRETCH_MAX_LOCAL) {
		if (r->Full == false)
			NodeLog(r->Stretch->Node, "EVPN stretch: the L2 Networks have more than %u MAC and IP addresses, the most that the gateway announces", (UINT)NODE_STRETCH_MAX_LOCAL);
		r->Full = true;
		return;
	}

	NODE_STRETCH_LOCAL *l = &r->Want[r->NumWant++];

	Zero(l, sizeof(NODE_STRETCH_LOCAL));
	l->Vni = vni;
	Copy(l->Mac, mac, sizeof(l->Mac));
	if (ip != NULL && ip_size <= sizeof(l->Ip)) {
		Copy(l->Ip, ip, ip_size);
		l->IpSize = ip_size;
	}
}

// The MAC table of the switch sw, whole, into the entries of r, which grow until the table fits them: their number. SwitchGetMacs
// gives the first entries of a table by VLAN and address, so a part of it would leave out the members whose addresses come after
// the addresses of the fabric at its port and those of other VLANs, and the gateway would withdraw their routes.
static UINT NodeStretchGetMacs(NODE_STRETCH_RUN *r, SWITCH *sw) {
	UINT num = SwitchGetMacs(sw, r->Macs, r->MaxMacs);

	while (num == r->MaxMacs && r->MaxMacs < SWITCH_MAX_MACS) {
		r->MaxMacs = MIN(r->MaxMacs * 2, (UINT)SWITCH_MAX_MACS);
		r->Macs = ReAlloc(r->Macs, sizeof(SWITCH_MAC_ENTRY) * r->MaxMacs);
		num = SwitchGetMacs(sw, r->Macs, r->MaxMacs);
	}

	return num;
}

// The IP table of the switch sw, whole, into the entries of r, which grow as those of the MAC table do (NodeStretchGetMacs): their
// number
static UINT NodeStretchGetIps(NODE_STRETCH_RUN *r, SWITCH *sw) {
	UINT num = SwitchGetIps(sw, r->Ips, r->MaxIps);

	while (num == r->MaxIps && r->MaxIps < SWITCH_MAX_IPS) {
		r->MaxIps = MIN(r->MaxIps * 2, (UINT)SWITCH_MAX_IPS);
		r->Ips = ReAlloc(r->Ips, sizeof(SWITCH_IP_ENTRY) * r->MaxIps);
		num = SwitchGetIps(sw, r->Ips, r->MaxIps);
	}

	return num;
}

// The switch of the Network net in a round: the MAC addresses of the type-2 routes of the fabric go into it at the port of the
// fabric (SwitchLearnAt), which refreshes them as frames would, and the routes of the gateway come from it: each MAC address that a
// member of the overlay sends from in the VLAN of the Network, MAC only, and each IP address that it sends from, MAC plus IP. The
// addresses at the port of the fabric are the fabric's. The caller holds Config.
static void NodeStretchScan(NODE_STRETCH_RUN *r, NODE_STRETCH_NET *net, UINT64 now) {
	NODE_STRETCH *s = r->Stretch;
	UINT done = 0;

	while (true) {
		UINT num = 0;

		AcquireSRWLockShared(&s->Lock);
		if (done < net->NumMacs) {
			num = MIN(net->NumMacs - done, NODE_STRETCH_CHUNK);
			Copy(r->Remote, net->Macs + done, sizeof(NODE_STRETCH_MAC) * num);
		}
		ReleaseSRWLockShared(&s->Lock);

		if (num == 0)
			break;

		for (UINT i = 0; i < num; i++)
			SwitchLearnAt(net->Switch, now, net->Port, net->Vlan, r->Remote[i].Mac);
		done += num;
	}

	UINT num_macs = NodeStretchGetMacs(r, net->Switch);
	for (UINT i = 0; i < num_macs; i++) {
		const SWITCH_MAC_ENTRY *e = &r->Macs[i];

		if (e->Vlan == net->Vlan && e->Port != net->Port && NodeStretchHostMac(e->Mac))
			NodeStretchWant(r, net->Vni, e->Mac, NULL, 0);
	}

	UINT num_ips = NodeStretchGetIps(r, net->Switch);
	for (UINT i = 0; i < num_ips; i++) {
		const SWITCH_IP_ENTRY *e = &r->Ips[i];

		if (e->Vlan == net->Vlan && e->Port != net->Port && NodeStretchHostMac(e->Mac) && NodeStretchHostIp(e->Address, e->AddressSize))
			NodeStretchWant(r, net->Vni, e->Mac, e->Address, e->AddressSize);
	}
}

// Add the route l to the batch of the next stretch message, with withdraw when it goes
static void NodeStretchBatch(NODE_STRETCH_RUN *r, const NODE_STRETCH_LOCAL *l, bool withdraw) {
	r->Batch[r->NumBatch] = *l;
	r->BatchWithdraw[r->NumBatch] = withdraw;
	r->NumBatch++;
}

// The routes of the batch in one stretch message to the sidecar, with full and more as given: true when it reached the sidecar.
// The batch is empty afterwards.
static bool NodeStretchSendBatch(NODE_STRETCH_RUN *r, bool full, bool more) {
	char mac[NODE_EVPN_TEXT];
	char ip[NODE_EVPN_TEXT];
	cJSON *m = cJSON_CreateObject();
	cJSON *routes = cJSON_CreateArray();

	cJSON_AddStringToObject(m, "type", "stretch");
	if (full)
		cJSON_AddBoolToObject(m, "full", true);
	if (more)
		cJSON_AddBoolToObject(m, "more", true);

	for (UINT i = 0; i < r->NumBatch; i++) {
		const NODE_STRETCH_LOCAL *l = &r->Batch[i];

		if (l->IpSize != 0 && NodeStretchIpText(ip, sizeof(ip), l->Ip, l->IpSize) == false)
			continue;

		cJSON *o = cJSON_CreateObject();
		NodeEvpnMacText(mac, sizeof(mac), l->Mac);
		cJSON_AddNumberToObject(o, "vni", (double)l->Vni);
		cJSON_AddStringToObject(o, "mac", mac);
		if (l->IpSize != 0)
			cJSON_AddStringToObject(o, "ip", ip);
		if (r->BatchWithdraw[i])
			cJSON_AddBoolToObject(o, "withdraw", true);
		cJSON_AddItemToArray(routes, o);
	}
	cJSON_AddItemToObject(m, "routes", routes);

	bool ok = NodeBgpSend(r->Bgp, m);

	cJSON_Delete(m);
	r->NumBatch = 0;

	return ok;
}

// A full resync: every route of the gateway in stretch messages of NODE_STRETCH_MAX_ROUTES routes at most, the first with full and
// each but the last with more, after which the sidecar withdraws what it announced before and the resync did not name. True when
// every message reached the sidecar.
static bool NodeStretchResync(NODE_STRETCH_RUN *r) {
	UINT done = 0;
	bool ok = true;

	do {
		UINT num = MIN(r->NumWant - done, NODE_STRETCH_MAX_ROUTES);

		for (UINT i = 0; i < num; i++)
			NodeStretchBatch(r, &r->Want[done + i], false);
		ok = NodeStretchSendBatch(r, done == 0, done + num < r->NumWant);
		done += num;
	} while (ok && done < r->NumWant);

	if (ok) {
		r->Resync = false;
		InterlockedIncrement64(&r->Stretch->Resyncs);
		NodeLog(r->Stretch->Node, "EVPN stretch: a full resync of %u routes of the gateway went to the sidecar", r->NumWant);
	}

	return ok;
}

// The routes of the gateway that changed since the last round, in stretch messages of NODE_STRETCH_MAX_ROUTES routes at most: one
// that went with withdraw, and a new one. True when every message reached the sidecar.
static bool NodeStretchDelta(NODE_STRETCH_RUN *r) {
	UINT i = 0;
	UINT j = 0;
	UINT withdrawn = 0;
	UINT announced = 0;
	bool ok = true;

	// Both lists are in order: a route of Have that Want does not hold went, a route of Want that Have does not hold came
	while (ok && (i < r->NumHave || j < r->NumWant)) {
		int c = (i >= r->NumHave ? 1 : (j >= r->NumWant ? -1 : NodeStretchCompareLocal(&r->Have[i], &r->Want[j])));

		if (c < 0) {
			NodeStretchBatch(r, &r->Have[i++], true);
			withdrawn++;
		} else if (c > 0) {
			NodeStretchBatch(r, &r->Want[j++], false);
			announced++;
		} else {
			i++;
			j++;
		}

		if (r->NumBatch == NODE_STRETCH_MAX_ROUTES)
			ok = NodeStretchSendBatch(r, false, false);
	}
	if (ok && r->NumBatch != 0)
		ok = NodeStretchSendBatch(r, false, false);
	r->NumBatch = 0;

	if (ok && (withdrawn != 0 || announced != 0))
		NodeLog(r->Stretch->Node, "EVPN stretch: %u routes of the gateway announced, %u withdrawn", announced, withdrawn);

	return ok;
}

// One round of the thread: the routes of the gateway from the switch of each stretched Network, and what changed of them to the
// sidecar, or all of them in a full resync
static void NodeStretchRound(NODE_STRETCH_RUN *r) {
	NODE_STRETCH *s = r->Stretch;
	UINT64 now = GetTickCount64();
	UINT num = 0;

	r->NumWant = 0;
	Lock(s->Config);
	{
		for (UINT i = 0; i < LIST_NUM(s->Nets); i++) {
			NODE_STRETCH_NET *net = LIST_DATA(s->Nets, i);

			if (net->Vni != 0 && net->Switch != NULL && net->Port != SWITCH_PORT_NONE)
				NodeStretchScan(r, net, now);
		}
	}
	Unlock(s->Config);

	// In order, each route once
	if (r->NumWant > 1)
		qsort(r->Want, r->NumWant, sizeof(NODE_STRETCH_LOCAL), NodeStretchCompareLocal);
	for (UINT i = 0; i < r->NumWant; i++) {
		if (num == 0 || NodeStretchCompareLocal(&r->Want[num - 1], &r->Want[i]) != 0)
			r->Want[num++] = r->Want[i];
	}
	r->NumWant = num;

	if (r->Resync ? NodeStretchResync(r) : NodeStretchDelta(r)) {
		Copy(r->Have, r->Want, sizeof(NODE_STRETCH_LOCAL) * r->NumWant);
		r->NumHave = r->NumWant;
	} else {
		// The sidecar did not get every message: the next round tells it everything again
		r->Resync = true;
	}

	InterlockedExchange(&s->Announced, (LONG)r->NumHave);
}

// The thread of the stretch: a round at its start, once a NODE_STRETCH_ROUND and when the routes of the fabric changed, until Halt
static DWORD WINAPI NodeStretchThread(void *param) {
	NODE_STRETCH_RUN *r = (NODE_STRETCH_RUN *)param;
	HANDLE events[2];

	// Halt first: WaitForMultipleObjects reports the lowest signalled index
	events[0] = r->Stretch->Halt;
	events[1] = r->Stretch->Wake;

	while (true) {
		NodeStretchRound(r);

		DWORD w = WaitForMultipleObjects(2, events, FALSE, NODE_STRETCH_ROUND);
		if (w != WAIT_OBJECT_0 + 1 && w != WAIT_TIMEOUT)
			break;
	}

	return 0;
}

// Free what a thread of the stretch kept
static void NodeStretchFreeRun(NODE_STRETCH_RUN *r) {
	if (r == NULL)
		return;

	Free(r->Macs);
	Free(r->Ips);
	Free(r->Remote);
	Free(r->Want);
	Free(r->Have);
	Free(r);
}

// Start the thread of the stretch with the sidecar b (NodeBgpStart), when the EVPN of the gateway runs with a stretch: its first
// round is a full resync. The caller holds the node lock.
void NodeStretchRun(NODE *n, NODE_BGP *b) {
	NODE_STRETCH *s = NodeStretchOf(n);
	UINT stretches = 0;

	if (s == NULL || b == NULL || s->Thread != NULL)
		return;

	AcquireSRWLockShared(&s->Lock);
	stretches = s->NumStretches;
	ReleaseSRWLockShared(&s->Lock);
	if (stretches == 0)
		return;

	NODE_STRETCH_RUN *r = ZeroMalloc(sizeof(NODE_STRETCH_RUN));
	r->Stretch = s;
	r->Bgp = b;
	r->Resync = true;
	r->MaxMacs = NODE_STRETCH_MAX_LOCAL;
	r->Macs = ZeroMalloc(sizeof(SWITCH_MAC_ENTRY) * r->MaxMacs);
	r->MaxIps = NODE_STRETCH_MAX_LOCAL;
	r->Ips = ZeroMalloc(sizeof(SWITCH_IP_ENTRY) * r->MaxIps);
	r->Remote = ZeroMalloc(sizeof(NODE_STRETCH_MAC) * NODE_STRETCH_CHUNK);
	r->Want = ZeroMalloc(sizeof(NODE_STRETCH_LOCAL) * NODE_STRETCH_MAX_LOCAL);
	r->Have = ZeroMalloc(sizeof(NODE_STRETCH_LOCAL) * NODE_STRETCH_MAX_LOCAL);

	ResetEvent(s->Halt);
	s->Run = r;
	s->Thread = CreateThread(NULL, 0, NodeStretchThread, r, 0, NULL);
	if (s->Thread == NULL) {
		NodeLog(n, "EVPN stretch: no thread for the routes of the gateway (error %u)", (UINT)GetLastError());
		NodeStretchFreeRun(r);
		s->Run = NULL;
	}
}

// Stop the thread of the stretch, before the pipe of its sidecar closes (NodeBgpStop). The caller holds the node lock.
void NodeStretchHalt(NODE *n) {
	NODE_STRETCH *s = NodeStretchOf(n);

	if (s == NULL || s->Thread == NULL)
		return;

	SetEvent(s->Halt);
	WaitForSingleObject(s->Thread, INFINITE);
	CloseHandle(s->Thread);
	s->Thread = NULL;

	NodeStretchFreeRun(s->Run);
	s->Run = NULL;
	InterlockedExchange(&s->Announced, 0);
}

//
// The state
//

// The state of the stretch of the node
void NodeStretchGetStatus(NODE *n, NODE_STRETCH_STATUS *st) {
	NODE_STRETCH *s = NodeStretchOf(n);

	if (st == NULL)
		return;

	Zero(st, sizeof(NODE_STRETCH_STATUS));
	if (s == NULL)
		return;

	AcquireSRWLockShared(&s->Lock);
	{
		st->NumStretches = s->NumStretches;
		for (UINT i = 0; i < LIST_NUM(s->Nets); i++) {
			const NODE_STRETCH_NET *net = LIST_DATA(s->Nets, i);

			if (net->Vni != 0 && net->Port != SWITCH_PORT_NONE)
				st->NumAttached++;
		}
		for (UINT i = 0; i < LIST_NUM(s->Remote); i++) {
			const NODE_STRETCH_ROUTE *r = LIST_DATA(s->Remote, i);

			if (r->Imet)
				st->NumVteps++;
			else
				st->NumMacs++;
		}
	}
	ReleaseSRWLockShared(&s->Lock);

	st->NumAnnounced = (UINT)InterlockedCompareExchange(&s->Announced, 0, 0);
	st->Resyncs = (UINT64)ReadAcquire64(&s->Resyncs);
	st->Unicast = (UINT64)ReadAcquire64(&s->Unicast);
	st->Flooded = (UINT64)ReadAcquire64(&s->Flooded);
	st->Failed = (UINT64)ReadAcquire64(&s->Failed);
	st->Delivered = (UINT64)ReadAcquire64(&s->Delivered);
	st->Undelivered = (UINT64)ReadAcquire64(&s->Undelivered);
	st->UnknownVtep = (UINT64)ReadAcquire64(&s->UnknownVtep);
	st->Refused = (UINT64)ReadAcquire64(&s->Refused);
}

// The routes of the fabric that the gateway holds, at most max of them into list, in the order of their VNI, kind and address:
// their number, which may be more than max
UINT NodeStretchGetRoutes(NODE *n, NODE_STRETCH_ROUTE *list, UINT max) {
	NODE_STRETCH *s = NodeStretchOf(n);
	UINT num = 0;

	if (s == NULL)
		return 0;

	AcquireSRWLockShared(&s->Lock);
	{
		num = LIST_NUM(s->Remote);
		for (UINT i = 0; list != NULL && i < num && i < max; i++)
			Copy(&list[i], LIST_DATA(s->Remote, i), sizeof(NODE_STRETCH_ROUTE));
	}
	ReleaseSRWLockShared(&s->Lock);

	return num;
}
