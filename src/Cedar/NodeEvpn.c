// NodeEvpn.c
// The EVPN of a gateway node (SDN-25, #201; ADR-0032 decisions 1 to 3, the ADR-0010 amendment of 2026-10-20): the node hands
// VRFs of the overlay to a data-centre fabric, and the fabric hands its VRFs to the overlay, as IP prefix routes, EVPN route
// type 5 (RFC 9136), with VXLAN as their encapsulation (RFC 8365). The routes go through the BGP sidecar of the node
// (NodeBgp.c; ranz bgp, ranz-bgp/internal/sidecar/evpn.go): the evpn object of the Bgp setting names the VTEP of the gateway,
// its router MAC and its EVPN VRFs, each with its L3 VNI and its route targets, and a prefix that the node announces with the
// vrf of such a VRF is an IP prefix route of that VRF. The node does the VXLAN itself, in user space, because Windows has no
// VXLAN interface for applications: the VXLAN module of the new core (Core/Vxlan.h) on a UDP socket of its own, on the port
// of the evpn object (VXLAN_PORT without one). Overlap-safe handoff is EVPN only: a route of the fabric never reaches the
// single Windows routing table, so two VRFs hand over the same prefixes, each on its own L3 VNI.
//
// The routes of the fabric: a learned message of the sidecar with a vni is the route of a prefix in an EVPN VRF, via a VTEP of
// the fabric (next_hop), with the VNI and the router MAC of the fabric, and a withdrawn message with a vni takes it away
// (NodeEvpnParseRoute). The node holds them in a list and builds them into one longest-prefix-match table per EVPN VRF
// (NodeVrf.c), which goes into the table snapshot of the node by pointer (NodeSwapEvpn) once for each read of the pipe that
// changed a route (NodeEvpnCommit), so the data path reads them without a lock, as it reads the forwarding tables of the VRFs.
//
// Into the fabric: the routes of the overlay come first, so a packet goes to the fabric only to a destination that no route of
// its VRF holds and an IP prefix route of the fabric does: a packet of the host of the gateway (NodeOverlayInput,
// NodeEvpnOutput), as the overlay sees it after the 1:1 NAT rules, and a packet of a peer that the gateway forwards
// (NodeOverlayDeliver, NodeEvpnTransit). It goes behind an Ethernet header from the router MAC of the gateway to the router
// MAC of the route, untagged, with the EtherType of IPv4 or IPv6, on the VNI of the route, to the VTEP of the route on the UDP
// port of the VTEPs of the fabric (fabric_port, VXLAN_PORT without one): the interface-less model of RFC 9136 section 4.4.1,
// as RFC 8365 section 5.1.3 carries it.
//
// Out of the fabric: the module carries the L3 VNI of each EVPN VRF and drops a datagram on any other VNI. A frame of an L3 VNI
// goes into its VRF when it comes from a VTEP that the gateway knows for the VRF, the VTEP of an IP prefix route of the VRF that
// it learned (NodeEvpnHasVtep; SDN-25-R1, #549): the address alone names a VTEP, which sends from any source port (RFC 7348
// section 5), and a frame from any other address has no honest reason to exist, so whoever can send to the UDP port of the VTEP
// of the gateway cannot forge one. A host that sends with the address of a VTEP of the fabric is that VTEP to the gateway: the
// source-address validation of the underlay answers it, which the operator provides (docs/threat-model.md, SM-11). The frame
// must then be addressed to the router MAC of the gateway, untagged, and hold an IP packet of the version of its EtherType
// (NodeEvpnParseFrame), and an IP prefix route of the fabric in the VRF must hold the source of the packet: the fabric speaks
// only for the prefixes that it announced there. Any VTEP that the gateway knows for the VRF may send it, as any leaf of a
// fabric routes the subnets of its VRFs. The overlay takes it to the host or on to a peer, as the table of the VRF routes its
// destination (NodeOverlayFabricInput). Any other frame is dropped and counted.
//
// At the gateway the fabric stands where the LAN of a gateway stands: the session profile of the peer and the policy of the VRF
// judge a packet between a peer and the fabric as one between the peer and the host of the gateway, and a Mirror of the VRF
// copies it, as they do with the packet of a peer to a LAN subnet behind a gateway; a packet between the host of the gateway
// and the fabric they judge not at all, as Windows forwards it without the overlay.

#include "NodeEvpn.h"

#include "Mayaqua/Internat.h"
#include "Mayaqua/Memory.h"
#include "Mayaqua/Object.h"
#include "Mayaqua/Str.h"
#include "Mayaqua/TcpIp.h"

#include "NodeInternal.h"
#include "NodeProfile.h"
#include "NodeSourceGroup.h"

#include <WinDNS.h>
#include <iphlpapi.h>
#include <stdlib.h>

#include <cjson/cJSON.h>

// The VTEP, the VNI and the router MAC of an IP prefix route of the fabric: a next hop of a table of the fabric
typedef struct NODE_EVPN_HOP {
	VXLAN_ADDR Vtep; // The VTEP of the fabric, on the UDP port of the VTEPs of the fabric
	UINT Vni;        // The VNI of the route
	UCHAR Mac[6];    // The router MAC of the fabric
} NODE_EVPN_HOP;

// The IP prefix routes of the fabric as the table snapshot of the node holds them (NodeSwapEvpn): one longest-prefix-match
// table per EVPN VRF, whose next hop i is Hops[i], and the VTEPs of the routes, which are the VTEPs that the gateway knows
struct NODE_EVPN_TABLE {
	NODE_EVPN *Evpn;         // The EVPN of the gateway, whose module sends the packets of the routes
	NODE_VRF_TABLES *Routes; // The tables
	UINT NumHops;            // The routes ...
	NODE_EVPN_HOP *Hops;     // ... and their next hops
	UINT NumVteps;           // The VTEP of each route with its VRF, once for each VRF ...
	NODE_EVPN_VTEP *Vteps;   // ... sorted (NodeEvpnSortVteps), in room for one per route
};

// The EVPN of a gateway, from the start of its BGP sidecar to its stop (NodeBgp.c)
struct NODE_EVPN {
	NODE *Node;                      // The node
	LOCK *Lock;                      // Routes and Dirty
	UCHAR RouterMac[6];              // The router MAC of the gateway
	char Vtep[NODE_EVPN_TEXT];       // The VTEP of the gateway, as the evpn object names it
	USHORT FabricPort;               // The UDP port of the VTEPs of the fabric
	UINT NumVrfs;                    // The EVPN VRFs ...
	UINT VrfIds[NODE_EVPN_MAX_VRFS]; // ... their ids
	UINT Vnis[NODE_EVPN_MAX_VRFS];   // ... and their L3 VNIs
	VXLAN_UDP *Udp;                  // The UDP socket of the VTEP of the gateway
	VXLAN *Vxlan;                    // The VXLAN module, which carries the L3 VNIs
	LIST *Routes;                    // The IP prefix routes of the fabric (NODE_EVPN_ROUTE)
	bool Dirty;                      // The routes changed since the table that went in last
	NODE_READER Reader;              // The receive thread of the socket as a reader of the tables, online while it delivers
	bool Registered;                 // ... once it registered
	UCHAR *NatBuf;                   // A packet of the fabric as the host sees it, when a 1:1 NAT rule translates it
	volatile LONG64 Sent;            // The counters of NODE_EVPN_STATUS
	volatile LONG64 Failed;
	volatile LONG64 Delivered;
	volatile LONG64 Undelivered;
	volatile LONG64 UnknownVtep;
	volatile LONG64 Strangers;
	volatile LONG64 NotOurs;
	volatile LONG64 Malformed;
};

//
// The text of the sidecar and of the evpn object
//

// The value of a hexadecimal digit, 16 for another character
static UINT NodeEvpnHex(char c) {
	if (c >= '0' && c <= '9')
		return (UINT)(c - '0');
	if (c >= 'a' && c <= 'f')
		return (UINT)(c - 'a' + 10);
	if (c >= 'A' && c <= 'F')
		return (UINT)(c - 'A' + 10);

	return 16;
}

// The six bytes of the MAC address of one host (its group bit clear) of text in the form 02:52:5a:00:00:05, with a colon or a
// dash between the bytes; false for anything else
static bool NodeEvpnParseMac(const char *str, UCHAR *mac) {
	if (str == NULL || StrLen(str) != 17)
		return false;

	for (UINT i = 0; i < 6; i++) {
		UINT hi = NodeEvpnHex(str[i * 3]);
		UINT lo = NodeEvpnHex(str[i * 3 + 1]);

		if (hi > 15 || lo > 15 || (i < 5 && str[i * 3 + 2] != ':' && str[i * 3 + 2] != '-'))
			return false;

		mac[i] = (UCHAR)((hi << 4) | lo);
	}

	return (mac[0] & 0x01) == 0;
}

// The text of a MAC address, 02:52:5a:00:00:05, into str of size bytes
static void NodeEvpnMacText(char *str, UINT size, const UCHAR *mac) {
	Format(str, size, "%02x:%02x:%02x:%02x:%02x:%02x", (UINT)mac[0], (UINT)mac[1], (UINT)mac[2], (UINT)mac[3], (UINT)mac[4], (UINT)mac[5]);
}

// An IPv4 or IPv6 address, or with types NET_STRING_IP_NETWORK a prefix and its length into *prefix_len, of text that the
// sidecar or the evpn object names: its bytes into addr (4 for IPv4, 16 for IPv6, in network byte order) and their number; 0
// when it is none, or longer than NODE_EVPN_TEXT
static UINT NodeEvpnParseAddr(const char *str, DWORD types, UCHAR *addr, UINT *prefix_len) {
	wchar_t tmp[NODE_EVPN_TEXT];
	NET_ADDRESS_INFO info;
	BYTE len = 0;

	Zero(addr, 16);
	if (str == NULL || IsEmptyStr(str) || StrLen(str) >= NODE_EVPN_TEXT)
		return 0;

	StrToUni(tmp, sizeof(tmp), str);
	Zero(&info, sizeof(info));
	if (ParseNetworkString(tmp, types, &info, NULL, prefix_len != NULL ? &len : NULL) != ERROR_SUCCESS)
		return 0;

	if (prefix_len != NULL)
		*prefix_len = len;

	if (info.Format == NET_ADDRESS_IPV4) {
		Copy(addr, &info.Ipv4Address.sin_addr, 4);
		return 4;
	}
	if (info.Format == NET_ADDRESS_IPV6) {
		Copy(addr, &info.Ipv6Address.sin6_addr, 16);
		return 16;
	}

	return 0;
}

// The string member name of a JSON object, NULL when it has none
static const char *NodeEvpnJsonStr(cJSON *o, const char *name) {
	return cJSON_GetStringValue(cJSON_GetObjectItemCaseSensitive(o, name));
}

// The number member name of a JSON object into *value when it is a whole number of 0 to max; false for a member that is no
// such number, or none
static bool NodeEvpnJsonUint(cJSON *o, const char *name, UINT max, UINT *value) {
	cJSON *item = cJSON_GetObjectItemCaseSensitive(o, name);

	if (cJSON_IsNumber(item) == false || item->valuedouble < 0 || item->valuedouble > (double)max || item->valuedouble != (double)(UINT)item->valuedouble)
		return false;

	*value = (UINT)item->valuedouble;
	return true;
}

// The members of a learned (learned) or withdrawn message m of an IP prefix route into r: false when one of them is missing
// or is none
static bool NodeEvpnRouteOf(cJSON *m, bool learned, NODE_EVPN_ROUTE *r) {
	const char *prefix = NodeEvpnJsonStr(m, "prefix");
	const char *next_hop = NodeEvpnJsonStr(m, "next_hop");
	const char *mac = NodeEvpnJsonStr(m, "router_mac");
	const char *peer = NodeEvpnJsonStr(m, "peer");
	UCHAR vtep[16];

	if (NodeEvpnJsonUint(m, "vrf", 0xFFFFFFFF, &r->VrfId) == false || r->VrfId == 0)
		return false;
	if (NodeEvpnJsonUint(m, "vni", VXLAN_MAX_VNI, &r->Vni) == false || r->Vni == 0)
		return false;
	if (peer != NULL && StrLen(peer) >= sizeof(r->Peer))
		return false;

	r->AddressSize = NodeEvpnParseAddr(prefix, NET_STRING_IP_NETWORK, r->Address, &r->Length);
	if (r->AddressSize == 0)
		return false;

	StrCpy(r->Prefix, sizeof(r->Prefix), prefix);
	StrCpy(r->Peer, sizeof(r->Peer), peer != NULL ? peer : "");

	if (learned == false)
		return true;

	// The VTEP of the fabric, an IPv4 address as an IPv4-mapped one, and the router MAC of the fabric
	UINT size = NodeEvpnParseAddr(next_hop, NET_STRING_IP_ADDRESS_NO_SCOPE, vtep, NULL);
	if (size == 0 || NodeEvpnParseMac(mac, r->RouterMac) == false)
		return false;

	if (size == 4) {
		r->Vtep[10] = 0xFF;
		r->Vtep[11] = 0xFF;
		Copy(r->Vtep + 12, vtep, 4);
	} else {
		Copy(r->Vtep, vtep, 16);
	}
	StrCpy(r->NextHop, sizeof(r->NextHop), next_hop);

	return true;
}

// Read one message of the sidecar, a JSON object on one line, as an IP prefix route of an EVPN VRF: a learned or withdrawn
// message with a vni (ranz-bgp/internal/sidecar/evpn.go). NODE_EVPN_NO_ROUTE for any other message; NODE_EVPN_LEARNED or
// NODE_EVPN_WITHDRAWN with r filled in; NODE_EVPN_BAD, with r empty, for one with a vni that the node cannot take: a vrf of 0,
// a VNI of 0 or of more than 24 bits, or a prefix, a next hop or a router MAC that is none.
UINT NodeEvpnParseRoute(const char *line, NODE_EVPN_ROUTE *r) {
	UINT ret = NODE_EVPN_NO_ROUTE;

	if (r == NULL)
		return NODE_EVPN_NO_ROUTE;

	Zero(r, sizeof(NODE_EVPN_ROUTE));
	if (line == NULL)
		return NODE_EVPN_NO_ROUTE;

	cJSON *m = cJSON_Parse(line);
	const char *type = NodeEvpnJsonStr(m, "type");

	if (cJSON_IsObject(m) && type != NULL && cJSON_GetObjectItemCaseSensitive(m, "vni") != NULL) {
		if (StrCmp(type, "learned") == 0)
			ret = NODE_EVPN_LEARNED;
		else if (StrCmp(type, "withdrawn") == 0)
			ret = NODE_EVPN_WITHDRAWN;
	}

	if (ret != NODE_EVPN_NO_ROUTE && NodeEvpnRouteOf(m, ret == NODE_EVPN_LEARNED, r) == false) {
		Zero(r, sizeof(NODE_EVPN_ROUTE));
		ret = NODE_EVPN_BAD;
	}

	cJSON_Delete(m);

	return ret;
}

//
// The packets
//

// The source and the destination of the IP packet of size bytes, 4 bytes each for IPv4 and 16 for IPv6, and their size:
// false for anything else, and for an IPv4 packet that does not hold its whole header
bool NodeEvpnEnds(const UCHAR *packet, UINT size, UCHAR *src, UCHAR *dst, UINT *addr_size) {
	if (packet == NULL || size < 20)
		return false;

	switch (packet[0] >> 4) {
	case 4:
		if ((packet[0] & 0x0F) < 5 || (UINT)(packet[0] & 0x0F) * 4 > size)
			return false;

		*addr_size = 4;
		Copy(src, packet + 12, 4);
		Copy(dst, packet + 16, 4);
		return true;
	case 6:
		if (size < 40)
			return false;

		*addr_size = 16;
		Copy(src, packet + 8, 16);
		Copy(dst, packet + 24, 16);
		return true;
	default:
		return false;
	}
}

// Read a frame of the fabric, size bytes, on the L3 VNI of an EVPN VRF (RFC 9136 section 4.4.1, RFC 8365 section 5.1.3): an
// Ethernet header to router_mac, the router MAC of the gateway, untagged, with the EtherType of IPv4 or IPv6, and then an IP
// packet of that version. NODE_EVPN_FRAME_OK with f set to the packet and its two ends, NODE_EVPN_FRAME_NOT_OURS for a frame to
// another MAC address, or NODE_EVPN_FRAME_MALFORMED.
UINT NodeEvpnParseFrame(const UCHAR *frame, UINT size, const UCHAR *router_mac, NODE_EVPN_FRAME *f) {
	if (f == NULL)
		return NODE_EVPN_FRAME_MALFORMED;

	Zero(f, sizeof(NODE_EVPN_FRAME));
	if (frame == NULL || router_mac == NULL || size < NODE_EVPN_ETHER)
		return NODE_EVPN_FRAME_MALFORMED;

	if (Cmp(frame, router_mac, 6) != 0)
		return NODE_EVPN_FRAME_NOT_OURS;

	USHORT ether = READ_USHORT(frame + 12);
	const UCHAR *packet = frame + NODE_EVPN_ETHER;
	UINT packet_size = size - NODE_EVPN_ETHER;
	UINT version = (ether == MAC_PROTO_IPV4 ? 4 : (ether == MAC_PROTO_IPV6 ? 6 : 0));

	if (version == 0 || packet_size == 0 || (UINT)(packet[0] >> 4) != version)
		return NODE_EVPN_FRAME_MALFORMED;
	if (NodeEvpnEnds(packet, packet_size, f->Src, f->Dst, &f->AddrSize) == false)
		return NODE_EVPN_FRAME_MALFORMED;

	f->Packet = packet;
	f->Size = packet_size;

	return NODE_EVPN_FRAME_OK;
}

// The next hop of the IP prefix route of the table t of the fabric that holds the address addr (size bytes) in the VRF
// vrf_id, NULL for none
static const NODE_EVPN_HOP *NodeEvpnFind(NODE_EVPN_TABLE *t, UINT vrf_id, const UCHAR *addr, UINT size) {
	if (t == NULL)
		return NULL;

	UINT i = NodeVrfLookup(NodeGetVrfTable(t->Routes, vrf_id), addr, size);

	return (i < t->NumHops ? &t->Hops[i] : NULL);
}

// Send the IP packet of size bytes of the VRF vrf_id to the fabric by the route of the table t whose next hop is hop: a packet
// of the host (host) as the overlay sees it, through the 1:1 NAT rules of the forwarding tables v, a packet of a peer as it
// came. It goes behind an Ethernet header from the router MAC of the gateway to the router MAC of the route, untagged, with
// the EtherType of its IP version, on the VNI of the route to its VTEP. False, and counted, when the frame is larger than the
// module takes or the datagram could not be sent.
static bool NodeEvpnSend(NODE_EVPN_TABLE *t, const NODE_EVPN_HOP *hop, NODE_VRF_TABLES *v, UINT vrf_id, const UCHAR *packet, UINT size, bool host) {
	UCHAR frame[VXLAN_MAX_FRAME];
	NODE_EVPN *e = t->Evpn;
	UINT len = size;

	if (size == 0 || size > VXLAN_MAX_FRAME - NODE_EVPN_ETHER) {
		InterlockedIncrement64(&e->Failed);
		return false;
	}

	if (host)
		len = NodeNatCopy(v, vrf_id, frame + NODE_EVPN_ETHER, packet, size);
	else
		Copy(frame + NODE_EVPN_ETHER, packet, size);

	if (len == 0) {
		InterlockedIncrement64(&e->Failed);
		return false;
	}

	Copy(frame, hop->Mac, 6);
	Copy(frame + 6, e->RouterMac, 6);
	WRITE_USHORT(frame + 12, (frame[NODE_EVPN_ETHER] >> 4) == 6 ? MAC_PROTO_IPV6 : MAC_PROTO_IPV4);

	bool ok = VxlanSendTo(e->Vxlan, hop->Vni, &hop->Vtep, frame, NODE_EVPN_ETHER + len);
	InterlockedIncrement64(ok ? &e->Sent : &e->Failed);

	return ok;
}

// A packet of the host in the VRF vrf_id that the forwarding tables v route to no peer (NodeOverlayInput): it goes to the
// fabric when its source is an address of the node, no route of the VRF holds its destination and an IP prefix route of the
// fabric does, all as the overlay sees the packet after the 1:1 NAT rules. False when it went nowhere. The caller is an online
// reader of the node's table snapshot, which holds v.
bool NodeEvpnOutput(NODE *n, NODE_VRF_TABLES *v, UINT vrf_id, const UCHAR *packet, UINT size) {
	UCHAR src[16], dst[16];
	UINT addr_size = 0;
	NODE_TABLES *t = NodeGetTables(n);
	NODE_EVPN_TABLE *et = (t != NULL ? t->Evpn : NULL);
	NODE_VRF_TABLE *vt = NodeGetVrfTable(v, vrf_id);

	if (et == NULL || vt == NULL || NodeNatEnds(v, vrf_id, packet, size, src, dst, &addr_size) == false)
		return false;
	if (NodeVrfLookup(vt, src, addr_size) != NODE_VRF_LOCAL || NodeVrfLookup(vt, dst, addr_size) != NODE_VRF_NONE)
		return false;

	const NODE_EVPN_HOP *hop = NodeEvpnFind(et, vrf_id, dst, addr_size);

	return (hop != NULL && NodeEvpnSend(et, hop, v, vrf_id, packet, size, true));
}

// A packet of the peer of the next hop from of the forwarding tables v in the VRF vrf_id, with the source group that it
// carried as claim tells, which the gateway forwards to the fabric when no route of the VRF holds its destination and an IP
// prefix route of the fabric does (NodeOverlayDeliver). The session profile of the peer and the node's own, then the policy
// of the VRF by the source group that the gateway takes from the claim, judge it as a packet of the peer to the host, and a
// Mirror of the VRF copies the packet that went, as they do with the packet of a peer to a LAN subnet behind a gateway. True
// when the fabric took the packet, whether it went or the profile, the policy or the send dropped it; false when it is no
// packet for the fabric, and the overlay goes on with it. The caller is an online reader of the node's table snapshot, which
// holds v.
bool NodeEvpnTransit(NODE *n, NODE_VRF_TABLES *v, UINT vrf_id, UINT from, const NODE_SOURCE_CLAIM *claim, const UCHAR *packet, UINT size) {
	UCHAR src[16], dst[16];
	UINT addr_size = 0;
	NODE_TABLES *t = NodeGetTables(n);
	NODE_EVPN_TABLE *et = (t != NULL ? t->Evpn : NULL);
	NODE_VRF_TABLE *vt = NodeGetVrfTable(v, vrf_id);

	if (et == NULL || vt == NULL || NodeEvpnEnds(packet, size, src, dst, &addr_size) == false || NodeVrfLookup(vt, dst, addr_size) != NODE_VRF_NONE)
		return false;

	const NODE_EVPN_HOP *hop = NodeEvpnFind(et, vrf_id, dst, addr_size);
	if (hop == NULL)
		return false;

	// The session profiles (NodeProfile.c; SDN-40, #233) and the policy judge it as NodeOverlayDeliver judges the packet of a peer
	// to the host: the gateway is the destination of the source group that the packet carried, so a claim that the peer may
	// not assert is dropped, counted and logged (NodeSourceGroup.c; SDN-87, #386). A Mirror copies it as the peer sent it
	// (NodeMirror.c)
	if (NodeProfileInbound(n, v, vrf_id, from, packet, size) && NodeSourceGroupInbound(n, v, vrf_id, from, claim, packet, size) && NodeEvpnSend(et, hop, v, vrf_id, packet, size, false))
		NodeMirrorCopy(v, vrf_id, packet, size, false);

	return true;
}

// The EVPN VRF whose L3 VNI is vni, 0 for none
static UINT NodeEvpnVrfOf(const NODE_EVPN *e, UINT vni) {
	for (UINT i = 0; i < e->NumVrfs; i++)
		if (e->Vnis[i] == vni)
			return e->VrfIds[i];

	return 0;
}

// Whether vrf_id is an EVPN VRF of e
static bool NodeEvpnHasVrf(const NODE_EVPN *e, UINT vrf_id) {
	for (UINT i = 0; i < e->NumVrfs; i++)
		if (e->VrfIds[i] == vrf_id)
			return true;

	return false;
}

// The order of two VTEPs that a gateway knows: by VRF, then by address
static int NodeEvpnCompareVtep(const void *p1, const void *p2) {
	const NODE_EVPN_VTEP *a = (const NODE_EVPN_VTEP *)p1;
	const NODE_EVPN_VTEP *b = (const NODE_EVPN_VTEP *)p2;

	if (a->VrfId != b->VrfId)
		return (a->VrfId < b->VrfId ? -1 : 1);

	return Cmp(a->Ip, b->Ip, sizeof(a->Ip));
}

// Sort the num VTEPs of vteps by VRF and address, each VTEP of a VRF once, as NodeEvpnHasVtep looks them up: the number of them,
// which are the first of vteps; the rest of the array holds what the duplicates left
UINT NodeEvpnSortVteps(NODE_EVPN_VTEP *vteps, UINT num) {
	UINT n = 0;

	if (vteps == NULL || num == 0)
		return 0;

	qsort(vteps, num, sizeof(NODE_EVPN_VTEP), NodeEvpnCompareVtep);

	for (UINT i = 0; i < num; i++)
		if (n == 0 || NodeEvpnCompareVtep(&vteps[n - 1], &vteps[i]) != 0)
			vteps[n++] = vteps[i];

	return n;
}

// Whether the address ip, 16 bytes with an IPv4 address as an IPv4-mapped one, is a VTEP of the VRF vrf_id among the num VTEPs of
// vteps, which NodeEvpnSortVteps sorted: one binary search
bool NodeEvpnHasVtep(const NODE_EVPN_VTEP *vteps, UINT num, UINT vrf_id, const UCHAR *ip) {
	NODE_EVPN_VTEP key;

	if (vteps == NULL || num == 0 || ip == NULL)
		return false;

	key.VrfId = vrf_id;
	Copy(key.Ip, ip, sizeof(key.Ip));

	return (bsearch(&key, vteps, num, sizeof(NODE_EVPN_VTEP), NodeEvpnCompareVtep) != NULL);
}

// The receiver of the module: a frame of the L3 VNI vni from the address from, on the receive thread of the socket, which
// registers itself as a reader of the tables of the node with its first frame. It goes into the VRF of the VNI when from is a
// VTEP that the gateway knows for the VRF, the VTEP of an IP prefix route of the VRF (NodeEvpnHasVtep), NodeEvpnParseFrame takes
// it and an IP prefix route of the fabric in the VRF holds the source of its packet. Any other frame is dropped and counted, one
// from another address as such, whatever it holds.
static void NodeEvpnReceive(VXLAN *x, void *param, UINT vni, const VXLAN_ADDR *from, const UCHAR *frame, UINT size) {
	NODE_EVPN *e = (NODE_EVPN *)param;
	NODE_EVPN_FRAME f;
	UINT vrf_id = NodeEvpnVrfOf(e, vni);
	UINT parsed = NodeEvpnParseFrame(frame, size, e->RouterMac, &f);

	if (vrf_id == 0) {
		InterlockedIncrement64(&e->Malformed);
		return;
	}

	if (e->Registered == false) {
		NodeReaderRegister(e->Node, &e->Reader);
		NodeReaderOffline(&e->Reader);
		e->Registered = true;
	}

	NodeReaderOnline(e->Node, &e->Reader);
	{
		NODE_TABLES *t = NodeGetTables(e->Node);
		NODE_EVPN_TABLE *et = (t != NULL ? t->Evpn : NULL);

		// The address alone names the VTEP: a VTEP sends from any source port (RFC 7348 section 5)
		if (et == NULL || NodeEvpnHasVtep(et->Vteps, et->NumVteps, vrf_id, from->Ip) == false)
			InterlockedIncrement64(&e->UnknownVtep);
		else if (parsed == NODE_EVPN_FRAME_MALFORMED)
			InterlockedIncrement64(&e->Malformed);
		else if (parsed == NODE_EVPN_FRAME_NOT_OURS)
			InterlockedIncrement64(&e->NotOurs);
		else if (NodeEvpnFind(et, vrf_id, f.Src, f.AddrSize) == NULL)
			InterlockedIncrement64(&e->Strangers);
		else if (NodeOverlayFabricInput(e->Node, vrf_id, f.Packet, f.Size, e->NatBuf))
			InterlockedIncrement64(&e->Delivered);
		else
			InterlockedIncrement64(&e->Undelivered);
	}
	NodeReaderOffline(&e->Reader);
}

//
// The routes
//

// The route of the prefix of r in its VRF among the routes of e, NULL for none; the caller holds the lock
static NODE_EVPN_ROUTE *NodeEvpnFindRoute(NODE_EVPN *e, const NODE_EVPN_ROUTE *r) {
	for (UINT i = 0; i < LIST_NUM(e->Routes); i++) {
		NODE_EVPN_ROUTE *o = LIST_DATA(e->Routes, i);

		if (o->VrfId == r->VrfId && o->AddressSize == r->AddressSize && o->Length == r->Length && Cmp(o->Address, r->Address, r->AddressSize) == 0)
			return o;
	}

	return NULL;
}

// Free the routes of the fabric of a table snapshot, wiped first as NodeFreeTable does; the EVPN that they belong to stays
void NodeEvpnFreeTable(NODE_EVPN_TABLE *t) {
	if (t == NULL)
		return;

	NodeFreeVrfTables(t->Routes);
	Zero(t->Hops, sizeof(NODE_EVPN_HOP) * t->NumHops);
	Free(t->Hops);
	Zero(t->Vteps, sizeof(NODE_EVPN_VTEP) * t->NumVteps);
	Free(t->Vteps);

	Zero(t, sizeof(NODE_EVPN_TABLE));
	Free(t);
}

// The routes of e as a table of the snapshot, NULL for none; the caller holds the lock. Routes that do not fit into tables
// (NodeNewVrfTables) are none, and the node log says so.
static NODE_EVPN_TABLE *NodeEvpnBuild(NODE_EVPN *e) {
	UINT num = LIST_NUM(e->Routes);

	if (num == 0)
		return NULL;

	NODE_EVPN_TABLE *t = ZeroMalloc(sizeof(NODE_EVPN_TABLE));
	NODE_VRF_ROUTE *routes = ZeroMalloc(sizeof(NODE_VRF_ROUTE) * num);
	void **hops = ZeroMalloc(sizeof(void *) * num);

	t->Evpn = e;
	t->NumHops = num;
	t->Hops = ZeroMalloc(sizeof(NODE_EVPN_HOP) * num);
	t->Vteps = ZeroMalloc(sizeof(NODE_EVPN_VTEP) * num);

	// Each route has a next hop of its own, and its VTEP is one that the gateway knows for its VRF (NodeEvpnReceive)
	for (UINT i = 0; i < num; i++) {
		const NODE_EVPN_ROUTE *r = LIST_DATA(e->Routes, i);
		NODE_EVPN_HOP *h = &t->Hops[i];

		Copy(h->Vtep.Ip, r->Vtep, sizeof(h->Vtep.Ip));
		h->Vtep.Port = e->FabricPort;
		h->Vtep.Encap = VXLAN_ENCAP_VXLAN;
		h->Vni = r->Vni;
		Copy(h->Mac, r->RouterMac, 6);
		hops[i] = h;

		routes[i].VrfId = r->VrfId;
		Copy(routes[i].Address, r->Address, sizeof(routes[i].Address));
		routes[i].AddressSize = r->AddressSize;
		routes[i].Length = r->Length;
		routes[i].NextHop = i;

		t->Vteps[i].VrfId = r->VrfId;
		Copy(t->Vteps[i].Ip, r->Vtep, sizeof(t->Vteps[i].Ip));
	}
	t->NumVteps = NodeEvpnSortVteps(t->Vteps, num);

	t->Routes = NodeNewVrfTables(0, routes, num, hops, num);
	Free(hops);
	Free(routes);

	if (t->Routes == NULL) {
		NodeLog(e->Node, "EVPN: the %u routes of the fabric do not fit into tables, so the gateway sends nothing to the fabric until they change", num);
		NodeEvpnFreeTable(t);
		return NULL;
	}

	return t;
}

// A message of the sidecar on one line (NodeBgp.c): when it is a learned or withdrawn message of an IP prefix route of an EVPN
// VRF, the route of its prefix in the VRF is now the one of the message, or none, in the list of the routes, which
// NodeEvpnCommit puts into the table snapshot. True for such a message, which never reaches the Windows routing table, also
// when the node cannot take it; false for any other message.
bool NodeEvpnRoute(NODE *n, const char *line) {
	NODE_EVPN_ROUTE r;
	char mac[NODE_EVPN_TEXT];
	UINT what = NodeEvpnParseRoute(line, &r);
	NODE_EVPN *e = (n != NULL ? n->Evpn : NULL);
	bool full = false;

	if (what == NODE_EVPN_NO_ROUTE)
		return false;

	if (what == NODE_EVPN_BAD) {
		NodeLog(n, "EVPN: a message of the sidecar with a vni that is no IP prefix route of an EVPN VRF, ignored");
		return true;
	}

	if (e == NULL || NodeEvpnHasVrf(e, r.VrfId) == false) {
		NodeLog(n, "EVPN route %s of VRF %u from %s ignored: the gateway hands no such VRF to the fabric", r.Prefix, r.VrfId, r.Peer);
		return true;
	}

	Lock(e->Lock);
	{
		NODE_EVPN_ROUTE *old = NodeEvpnFindRoute(e, &r);

		if (what == NODE_EVPN_WITHDRAWN) {
			if (old != NULL) {
				Delete(e->Routes, old);
				Free(old);
				e->Dirty = true;
			}
		} else if (old != NULL) {
			Copy(old, &r, sizeof(NODE_EVPN_ROUTE));
			e->Dirty = true;
		} else if (LIST_NUM(e->Routes) < NODE_EVPN_MAX_ROUTES) {
			NODE_EVPN_ROUTE *copy = ZeroMalloc(sizeof(NODE_EVPN_ROUTE));

			Copy(copy, &r, sizeof(NODE_EVPN_ROUTE));
			Add(e->Routes, copy);
			e->Dirty = true;
		} else {
			full = true;
		}
	}
	Unlock(e->Lock);

	NodeEvpnMacText(mac, sizeof(mac), r.RouterMac);
	if (what == NODE_EVPN_WITHDRAWN)
		NodeLog(n, "EVPN route %s of VRF %u withdrawn by %s", r.Prefix, r.VrfId, r.Peer);
	else if (full)
		NodeLog(n, "EVPN route %s of VRF %u from %s not taken: the gateway holds %u routes of the fabric, the most it takes", r.Prefix, r.VrfId, r.Peer, (UINT)NODE_EVPN_MAX_ROUTES);
	else
		NodeLog(n, "EVPN route %s of VRF %u learned: via the VTEP %s, VNI %u, router MAC %s, from %s", r.Prefix, r.VrfId, r.NextHop, r.Vni, mac, r.Peer);

	return true;
}

// Put the routes of the fabric into the table snapshot of the node when they changed (NodeSwapEvpn). The reader thread of the
// sidecar calls it after each read of the pipe, so that the routes of one read go in together.
void NodeEvpnCommit(NODE *n) {
	NODE_EVPN *e = (n != NULL ? n->Evpn : NULL);
	NODE_EVPN_TABLE *t = NULL;
	bool dirty = false;

	if (e == NULL)
		return;

	Lock(e->Lock);
	{
		dirty = e->Dirty;
		if (dirty)
			t = NodeEvpnBuild(e);
		e->Dirty = false;
	}
	Unlock(e->Lock);

	if (dirty && NodeSwapEvpn(n, t) == false)
		NodeEvpnFreeTable(t);
}

// Forget every route of the fabric and take them out of the table snapshot, as the sidecar closed the pipe (NodeBgp.c): the
// number of the routes that went
UINT NodeEvpnFlush(NODE *n) {
	NODE_EVPN *e = (n != NULL ? n->Evpn : NULL);
	UINT num = 0;

	if (e == NULL)
		return 0;

	Lock(e->Lock);
	{
		num = LIST_NUM(e->Routes);

		while (LIST_NUM(e->Routes) != 0) {
			NODE_EVPN_ROUTE *r = LIST_DATA(e->Routes, 0);

			Delete(e->Routes, r);
			Free(r);
		}
		e->Dirty = true;
	}
	Unlock(e->Lock);

	NodeEvpnCommit(n);

	return num;
}

//
// The EVPN of the gateway
//

// Free the EVPN of a gateway that no table snapshot holds: its socket first, which joins its receive thread, then the reader of
// that thread, then the module
static void NodeEvpnFree(NODE_EVPN *e) {
	if (e == NULL)
		return;

	VxlanUdpFree(e->Udp);
	if (e->Registered)
		NodeReaderUnregister(e->Node, &e->Reader);
	VxlanFree(e->Vxlan);

	for (UINT i = 0; i < LIST_NUM(e->Routes); i++)
		Free(LIST_DATA(e->Routes, i));
	ReleaseList(e->Routes);

	if (e->Lock != NULL)
		DeleteLock(e->Lock);
	Free(e->NatBuf);
	Free(e);
}

// The EVPN VRFs of the array vrfs of an evpn object into e, each with its id (vrf) and its L3 VNI (vni). False, with why into
// error, for a VRF without its id or without a VNI of 24 bits, and for a VRF or a VNI that comes twice.
static bool NodeEvpnVrfs(NODE_EVPN *e, cJSON *vrfs, char *error, UINT error_size) {
	for (cJSON *v = vrfs->child; v != NULL && e->NumVrfs < NODE_EVPN_MAX_VRFS; v = v->next) {
		UINT id = 0, vni = 0;

		if (NodeEvpnJsonUint(v, "vrf", 0xFFFFFFFF, &id) == false || id == 0 || NodeEvpnJsonUint(v, "vni", VXLAN_MAX_VNI, &vni) == false || vni == 0) {
			StrCpy(error, error_size, "a VRF of vrfs has no id, or no VNI of 24 bits");
			return false;
		}
		if (NodeEvpnHasVrf(e, id) || NodeEvpnVrfOf(e, vni) != 0) {
			Format(error, error_size, "VRF %u or its VNI %u comes twice", id, vni);
			return false;
		}

		e->VrfIds[e->NumVrfs] = id;
		e->Vnis[e->NumVrfs] = vni;
		e->NumVrfs++;
	}

	return true;
}

// Start the EVPN of a gateway with its BGP sidecar (NodeBgpStart), before the first message of the sidecar, when the Bgp
// setting cfg has an evpn object: the VTEP of the gateway (vtep), its router MAC (router_mac, NODE_EVPN_ROUTER_MAC without
// one), the UDP port of its VTEP (port) and of the VTEPs of the fabric (fabric_port), VXLAN_PORT without them, and its EVPN
// VRFs (vrfs), each with its id (vrf) and its L3 VNI (vni). The sidecar reads the same object, with the route distinguisher,
// the route targets and the accept list of each VRF. A node whose evpn object is not one runs without EVPN, and the node log
// says why; the sidecar refuses such an object too. The caller holds the node lock.
void NodeEvpnStart(NODE *n, struct cJSON *cfg) {
	cJSON *o = cJSON_GetObjectItemCaseSensitive(cfg, "evpn");
	cJSON *vrfs = cJSON_GetObjectItemCaseSensitive(o, "vrfs");
	const char *vtep = NodeEvpnJsonStr(o, "vtep");
	const char *mac = NodeEvpnJsonStr(o, "router_mac");
	UINT port = VXLAN_PORT;
	UINT fabric_port = VXLAN_PORT;
	UCHAR addr[16];
	char error[MAX_SIZE];
	char mac_text[NODE_EVPN_TEXT];

	if (n == NULL || n->Evpn != NULL || cJSON_IsObject(o) == false)
		return;

	NODE_EVPN *e = ZeroMalloc(sizeof(NODE_EVPN));
	e->Node = n;
	e->Lock = NewLock();
	e->Routes = NewListFast(NULL);
	e->NatBuf = Malloc(NOISE_MAX_PAYLOAD + NODE_NAT_GROWTH);
	StrCpy(error, sizeof(error), "");

	if (NodeEvpnParseAddr(vtep, NET_STRING_IP_ADDRESS_NO_SCOPE, addr, NULL) == 0)
		Format(error, sizeof(error), "vtep \"%s\" is not the IP address of a VTEP", vtep != NULL ? vtep : "");
	else if (NodeEvpnParseMac(mac != NULL ? mac : NODE_EVPN_ROUTER_MAC, e->RouterMac) == false)
		Format(error, sizeof(error), "router_mac \"%s\" is not the MAC address of one host", mac != NULL ? mac : "");
	else if (cJSON_GetObjectItemCaseSensitive(o, "port") != NULL && (NodeEvpnJsonUint(o, "port", 65535, &port) == false || port == 0))
		StrCpy(error, sizeof(error), "port is not a UDP port");
	else if (cJSON_GetObjectItemCaseSensitive(o, "fabric_port") != NULL && (NodeEvpnJsonUint(o, "fabric_port", 65535, &fabric_port) == false || fabric_port == 0))
		StrCpy(error, sizeof(error), "fabric_port is not a UDP port");
	else if (cJSON_IsArray(vrfs) == false || cJSON_GetArraySize(vrfs) == 0 || cJSON_GetArraySize(vrfs) > NODE_EVPN_MAX_VRFS)
		Format(error, sizeof(error), "vrfs names no VRF, or more than %u", (UINT)NODE_EVPN_MAX_VRFS);
	else
		NodeEvpnVrfs(e, vrfs, error, sizeof(error));

	if (IsEmptyStr(error)) {
		StrCpy(e->Vtep, sizeof(e->Vtep), vtep);
		e->FabricPort = (USHORT)fabric_port;
		e->Udp = VxlanUdpNew((USHORT)port);
		if (e->Udp == NULL)
			Format(error, sizeof(error), "the UDP port %u of its VTEP cannot be opened", port);
	}

	// The module carries the L3 VNI of each VRF, with no flood list: the gateway sends each frame to the VTEP of its route
	if (IsEmptyStr(error)) {
		e->Vxlan = VxlanNew(VxlanUdpSend, e->Udp, NodeEvpnReceive, e);

		bool carried = (e->Vxlan != NULL);
		for (UINT i = 0; carried && i < e->NumVrfs; i++)
			carried = VxlanSetVni(e->Vxlan, e->Vnis[i], NULL, 0);

		if (carried == false || VxlanUdpStart(e->Udp, e->Vxlan) == false)
			StrCpy(error, sizeof(error), "the VXLAN module of its VTEP could not start");
	}

	if (IsEmptyStr(error) == false) {
		NodeLog(n, "EVPN not started: %s", error);
		NodeEvpnFree(e);
		return;
	}

	n->Evpn = e;
	NodeEvpnMacText(mac_text, sizeof(mac_text), e->RouterMac);
	NodeLog(n, "EVPN started: the VTEP %s on UDP port %u, router MAC %s, %u VRFs, the VTEPs of the fabric on UDP port %u", e->Vtep, (UINT)VxlanUdpPort(e->Udp), mac_text, e->NumVrfs, (UINT)e->FabricPort);
}

// Stop the EVPN of the gateway with its sidecar (NodeBgpStop), once the reader thread of the sidecar ended: the routes of the
// fabric leave the table snapshot, then the socket closes, which joins the receive thread, and the module goes. The caller
// holds the node lock and is no online reader of the table snapshot.
void NodeEvpnStop(NODE *n) {
	NODE_EVPN *e = (n != NULL ? n->Evpn : NULL);

	if (e == NULL)
		return;

	// No reader reaches the module once the snapshot holds no route of it
	NodeSwapEvpn(n, NULL);
	n->Evpn = NULL;

	NodeLog(n, "EVPN stopped: %u routes of the fabric removed; %I64u packets sent to the fabric, %I64u of the fabric delivered", LIST_NUM(e->Routes), (UINT64)ReadAcquire64(&e->Sent), (UINT64)ReadAcquire64(&e->Delivered));
	NodeEvpnFree(e);
}

// The state of the EVPN of the node
void NodeEvpnGetStatus(NODE *n, NODE_EVPN_STATUS *st) {
	VXLAN_STATS vs;

	if (st == NULL)
		return;

	Zero(st, sizeof(NODE_EVPN_STATUS));
	if (n == NULL)
		return;

	Lock(n->Lock);
	{
		NODE_EVPN *e = n->Evpn;

		if (e != NULL) {
			VxlanGetStats(e->Vxlan, &vs);
			st->Running = true;
			st->Port = VxlanUdpPort(e->Udp);
			st->FabricPort = e->FabricPort;
			st->NumVrfs = e->NumVrfs;

			Lock(e->Lock);
			{
				st->NumRoutes = LIST_NUM(e->Routes);
			}
			Unlock(e->Lock);

			st->Sent = (UINT64)ReadAcquire64(&e->Sent);
			st->Failed = (UINT64)ReadAcquire64(&e->Failed);
			st->Delivered = (UINT64)ReadAcquire64(&e->Delivered);
			st->Undelivered = (UINT64)ReadAcquire64(&e->Undelivered);
			st->UnknownVtep = (UINT64)ReadAcquire64(&e->UnknownVtep);
			st->Strangers = (UINT64)ReadAcquire64(&e->Strangers);
			st->NotOurs = (UINT64)ReadAcquire64(&e->NotOurs);
			st->UnknownVni = vs.Drops[VXLAN_DROP_VNI];
			st->Malformed = (UINT64)ReadAcquire64(&e->Malformed) + vs.Drops[VXLAN_DROP_MALFORMED];
		}
	}
	Unlock(n->Lock);
}

// The IP prefix routes of the fabric that the gateway holds, at most max of them into list, in the order they came: their
// number, which may be more than max
UINT NodeEvpnGetRoutes(NODE *n, NODE_EVPN_ROUTE *list, UINT max) {
	UINT num = 0;

	if (n == NULL)
		return 0;

	Lock(n->Lock);
	{
		NODE_EVPN *e = n->Evpn;

		if (e != NULL) {
			Lock(e->Lock);
			{
				num = LIST_NUM(e->Routes);
				for (UINT i = 0; list != NULL && i < num && i < max; i++)
					Copy(&list[i], LIST_DATA(e->Routes, i), sizeof(NODE_EVPN_ROUTE));
			}
			Unlock(e->Lock);
		}
	}
	Unlock(n->Lock);

	return num;
}
