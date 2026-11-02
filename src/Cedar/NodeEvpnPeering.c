// NodeEvpnPeering.c
// The EVPN peering of the standard mode (SDN-78, #358; ADR-0032, ADR-0010 amendment of 2026-10-29). In a VRF whose links are of
// kind vxlan and whose peering is evpn, the nodes exchange their MAC addresses, IP addresses and prefixes by EVPN, as two leaves of
// a fabric do, with the machinery of the EVPN edge toward a fabric (NodeEvpn.c, NodeStretch.c; SDN-25, #201, and SDN-64, #291) in
// the sidecar of the BGP peering (NodePeering.c; SDN-77, #357): IP prefix routes (type 5) with the VNI of the VRF as its L3 VNI, and
// the MAC/IP advertisement routes (type 2, with MAC mobility) and the inclusive multicast Ethernet tag routes (type 3, which fill
// the flood list) of each L2 Network of the VRF on its L2 VNI. The fabric of a node is the other nodes of the VRF, which the
// Controller names. The Controller writes the configuration of the peers alone: it gives no route of a peer and no tunnel endpoint
// of a peer for such a VRF, so the VRF does not also use the routes and the flood list that the Controller fills for a link of kind
// vxlan. NodeLink.c leaves such a VRF out, and NodeOverlay.c takes no address of a peer there as a route: its packets to a peer go
// by the IP prefix routes of the peers, in plain VXLAN from VTEP to VTEP (NodeEvpnOutput).
//
// The start of the sidecar of the peering names an evpn object (NodeEvpnPeeringObject), which the node runs as the EVPN of a
// gateway runs the one of its Bgp setting (NodeEvpnOpen): its VTEP is the tunnel endpoint of the node, the address of its peering,
// on the port of VXLAN of the node, and the VTEPs of the peers are on the same port, which the nodes of such a VRF share
// (controller/internal/intent/evpnpeering.go). Each VRF that peers by EVPN is an EVPN VRF with the VNI of its link as its L3 VNI, a
// route distinguisher of the router id of the node, and the route target 0:ID of its id, which every node gives it alike; each L2
// Network of such a VRF is a stretch on its L2 VNI (CONTROL_STATE.L2Vnis), with a route distinguisher of the router id and the
// route target 1:VNI. The VRFs name no accept list: the sidecar takes an IP prefix route of a peer only when it is exactly a prefix
// that the peer may announce there, its accept list of the peering (ranz-bgp/internal/sidecar/evpnpeering.go). The node announces
// its addresses and its LAN subnets in such a VRF as in one that peers by BGP, and the sidecar sends them as IP prefix routes; the
// thread of the stretch announces the MAC addresses of the members of the switches of its L2 Networks (NodeStretchRunWith).
//
// A node runs one EVPN at a time (NODE.EvpnTaken): a node whose Bgp setting runs an EVPN toward a fabric runs none for the peering,
// and its node log says so. A change of the VRFs that peer by EVPN, of their L3 VNIs or of their L2 Networks starts the sidecar of
// the peering anew with the new evpn object (NodePeering.c).

#include "NodePeering.h"

#include "Mayaqua/Memory.h"
#include "Mayaqua/Str.h"

#include "Core/Control.h"
#include "Core/Vxlan.h"

#include <cjson/cJSON.h>

#define NODE_EVPN_PEERING_RD_VRF     1  // The assigned number of the route distinguisher of the first EVPN VRF of a node ...
#define NODE_EVPN_PEERING_RD_STRETCH 17 // ... and of its first stretch: CONTROL_MAX_VRFS VRFs come below it

// Whether the VRF vrf_id of the state st peers by EVPN
bool NodeEvpnPeeringVrf(const CONTROL_STATE *st, UINT vrf_id) {
	for (UINT i = 0; st != NULL && i < st->NumVrfs && i < CONTROL_MAX_VRFS; i++)
		if (st->Vrfs[i].Id == vrf_id)
			return st->Vrfs[i].PeeringEvpn;

	return false;
}

// An array of one string, str
static cJSON *NodeEvpnPeeringOne(const char *str) {
	cJSON *a = cJSON_CreateArray();

	cJSON_AddItemToArray(a, cJSON_CreateString(str));

	return a;
}

// The evpn object of the start of the sidecar of the peering for the state st, whose peering names the node by the address vtep
// and the router id router_id, as the start names them: NULL while no VRF of st peers by EVPN. fabric_port is the UDP port of the
// VTEPs of the peers, 0 for the port of VXLAN of the node: a test names another, as the nodes of one host need ports of their own
// (NodePeeringSetFabricPort).
cJSON *NodeEvpnPeeringObject(const CONTROL_STATE *st, const char *vtep, const char *router_id, UINT fabric_port) {
	char text[MAX_SIZE];
	UINT num_vrfs = 0;
	UINT num_stretches = 0;

	if (st == NULL || st->Peering == NULL || IsEmptyStr(vtep) || IsEmptyStr(router_id))
		return NULL;

	UINT port = (st->Vtep.VxlanPort != 0 ? st->Vtep.VxlanPort : VXLAN_PORT);
	cJSON *o = cJSON_CreateObject();
	cJSON *vrfs = cJSON_CreateArray();
	cJSON *stretches = cJSON_CreateArray();

	cJSON_AddStringToObject(o, "vtep", vtep);
	cJSON_AddNumberToObject(o, "port", port);
	cJSON_AddNumberToObject(o, "fabric_port", fabric_port != 0 ? fabric_port : port);

	// Each VRF that peers by EVPN, with the VNI of its link as its L3 VNI
	for (UINT i = 0; i < st->NumVrfs && i < CONTROL_MAX_VRFS; i++) {
		const CONTROL_VRF *v = &st->Vrfs[i];

		if (v->PeeringEvpn == false || v->Vni == 0)
			continue;

		cJSON *e = cJSON_CreateObject();
		cJSON_AddNumberToObject(e, "vrf", v->Id);
		cJSON_AddNumberToObject(e, "vni", v->Vni);
		Format(text, sizeof(text), "%s:%u", router_id, NODE_EVPN_PEERING_RD_VRF + num_vrfs);
		cJSON_AddStringToObject(e, "rd", text);
		Format(text, sizeof(text), "0:%u", v->Id);
		cJSON_AddItemToObject(e, "import", NodeEvpnPeeringOne(text));
		cJSON_AddItemToObject(e, "export", NodeEvpnPeeringOne(text));
		cJSON_AddItemToArray(vrfs, e);
		num_vrfs++;
	}

	// ... and each L2 Network of such a VRF on its L2 VNI
	for (UINT i = 0; i < st->NumL2Vnis && i < CONTROL_MAX_L2VNIS; i++) {
		const CONTROL_L2VNI *l = &st->L2Vnis[i];

		if (NodeEvpnPeeringVrf(st, l->VrfId) == false || IsEmptyStr(l->Network))
			continue;

		cJSON *s = cJSON_CreateObject();
		cJSON_AddStringToObject(s, "network", l->Network);
		cJSON_AddNumberToObject(s, "vni", l->Vni);
		Format(text, sizeof(text), "%s:%u", router_id, NODE_EVPN_PEERING_RD_STRETCH + num_stretches);
		cJSON_AddStringToObject(s, "rd", text);
		Format(text, sizeof(text), "1:%u", l->Vni);
		cJSON_AddItemToObject(s, "route_targets", NodeEvpnPeeringOne(text));
		cJSON_AddItemToArray(stretches, s);
		num_stretches++;
	}

	if (num_vrfs == 0) {
		cJSON_Delete(vrfs);
		cJSON_Delete(stretches);
		cJSON_Delete(o);
		return NULL;
	}

	cJSON_AddItemToObject(o, "vrfs", vrfs);
	if (num_stretches != 0)
		cJSON_AddItemToObject(o, "stretches", stretches);
	else
		cJSON_Delete(stretches);

	return o;
}
