// ControlGateway.c
// The topology of the VRFs and their gateways on the control stream (SDN-19, #195; Core/Control.h). Each Vrf object of a
// state carries the hub node of a VRF of topology hub-and-spoke and whether the flows of the VRF spread over its gateways
// (CONTROL_VRF.Hub, CONTROL_VRF.Ecmp), the NodeConfig the LAN subnets behind the node (CONTROL_STATE.LanSubnets), and each
// Peer object whether the controller reports the peer down (CONTROL_PEER.Down). They go with the state, as the owner takes
// it (ControlCopyGateways).

#include "Core/ControlInternal.h"

#include <string.h>

// The LAN subnets of the NodeConfig node into the state, after the ones it holds: a route whose prefix is neither IPv4 nor
// IPv6, or longer than its address, is left out
static void ControlCopyLanSubnets(CONTROL_STATE *st, const ranz_control_v1_NodeConfig *node) {
	for (pb_size_t i = 0; i < node->lan_subnets_count && st->NumLanSubnets < CONTROL_MAX_ROUTES; i++) {
		const ranz_control_v1_Route *src = &node->lan_subnets[i];
		const ranz_control_v1_Prefix *p = &src->prefix;
		CONTROL_ROUTE *r = &st->LanSubnets[st->NumLanSubnets];

		if (src->has_prefix == false || (p->address.size != 4 && p->address.size != 16) || p->length > (uint32_t)p->address.size * 8)
			continue;

		ZeroMemory(r, sizeof(CONTROL_ROUTE));
		r->VrfId = src->vrf_id;
		CopyMemory(r->Address, p->address.bytes, p->address.size);
		r->AddressSize = p->address.size;
		r->Length = p->length;
		st->NumLanSubnets++;
	}
}

// The hub and the ECMP of the Vrf objects, the LAN subnets of the NodeConfig and the health data of the Peer objects among
// num objects into the state, which holds the VRFs and the peers that the client took from them already
void ControlCopyGateways(CONTROL_STATE *st, const ranz_control_v1_Object *objects, UINT num) {
	st->NumLanSubnets = 0;

	for (UINT i = 0; i < num; i++) {
		const ranz_control_v1_Object *o = &objects[i];

		if (o->which_kind == ranz_control_v1_Object_vrf_tag) {
			for (UINT j = 0; j < st->NumVrfs; j++) {
				CONTROL_VRF *v = &st->Vrfs[j];

				if (strcmp(v->Name, o->kind.vrf.name) != 0)
					continue;

				strncpy_s(v->Hub, sizeof(v->Hub), o->kind.vrf.hub, _TRUNCATE);
				v->Ecmp = o->kind.vrf.ecmp;
			}
		} else if (o->which_kind == ranz_control_v1_Object_node_tag) {
			ControlCopyLanSubnets(st, &o->kind.node);
		} else if (o->which_kind == ranz_control_v1_Object_peer_tag) {
			for (UINT j = 0; j < st->NumPeers; j++) {
				CONTROL_PEER *p = &st->Peers[j];

				if (strcmp(p->Name, o->kind.peer.name) == 0)
					p->Down = o->kind.peer.down;
			}
		}
	}
}
