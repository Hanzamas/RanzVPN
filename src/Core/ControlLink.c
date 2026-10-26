// ControlLink.c
// The links of kind vxlan and geneve on the control stream (SDN-76, #356; Core/Control.h). Each Vrf object of a state
// carries the kind of the links between the nodes of the VRF and its VNI (CONTROL_VRF.Link, CONTROL_VRF.Vni), the
// NodeConfig the ports of the tunnel endpoint of the node (CONTROL_STATE.Vtep), and each Peer object the tunnel endpoint
// of the peer (CONTROL_PEER.Vtep), the only address that the node takes the datagrams of such a link from. They go with
// the state, as the owner takes it (ControlCopyLinks).

#include "Core/ControlInternal.h"

#include <string.h>

// The kind of a link as the state holds it; a kind that this node does not know is noise
static UINT ControlLinkKind(ranz_control_v1_LinkKind kind) {
	switch (kind) {
	case ranz_control_v1_LinkKind_LINK_KIND_VXLAN:
		return CONTROL_LINK_VXLAN;
	case ranz_control_v1_LinkKind_LINK_KIND_GENEVE:
		return CONTROL_LINK_GENEVE;
	default:
		return CONTROL_LINK_NOISE;
	}
}

// The tunnel endpoint src into dst: an address that is neither IPv4 nor IPv6 is left out, and so is a port above 65535
static void ControlCopyVtep(CONTROL_VTEP *dst, const ranz_control_v1_Vtep *src) {
	ZeroMemory(dst, sizeof(CONTROL_VTEP));

	if (src->address.size == 4 || src->address.size == 16) {
		CopyMemory(dst->Address, src->address.bytes, src->address.size);
		dst->AddressSize = src->address.size;
	}
	if (src->vxlan_port <= 0xFFFF)
		dst->VxlanPort = src->vxlan_port;
	if (src->geneve_port <= 0xFFFF)
		dst->GenevePort = src->geneve_port;
}

// The kinds of the links of the Vrf objects, the tunnel endpoint of the NodeConfig and those of the Peer objects among num
// objects into the state, which holds the VRFs and the peers that the client took from them already. A VNI of more than 24
// bits makes the link of its VRF noise: no VXLAN or Geneve header carries it.
void ControlCopyLinks(CONTROL_STATE *st, const ranz_control_v1_Object *objects, UINT num) {
	ZeroMemory(&st->Vtep, sizeof(st->Vtep));

	for (UINT i = 0; i < num; i++) {
		const ranz_control_v1_Object *o = &objects[i];

		if (o->which_kind == ranz_control_v1_Object_vrf_tag) {
			for (UINT j = 0; j < st->NumVrfs; j++) {
				CONTROL_VRF *v = &st->Vrfs[j];

				if (strcmp(v->Name, o->kind.vrf.name) != 0)
					continue;

				v->Link = ControlLinkKind(o->kind.vrf.link);
				v->Vni = o->kind.vrf.vni;
				if (v->Vni > 0xFFFFFF)
					v->Link = CONTROL_LINK_NOISE;
				if (v->Link == CONTROL_LINK_NOISE)
					v->Vni = 0;
			}
		} else if (o->which_kind == ranz_control_v1_Object_node_tag && o->kind.node.has_vtep) {
			ControlCopyVtep(&st->Vtep, &o->kind.node.vtep);
		} else if (o->which_kind == ranz_control_v1_Object_peer_tag && o->kind.peer.has_vtep) {
			for (UINT j = 0; j < st->NumPeers; j++) {
				CONTROL_PEER *p = &st->Peers[j];

				if (strcmp(p->Name, o->kind.peer.name) == 0)
					ControlCopyVtep(&p->Vtep, &o->kind.peer.vtep);
			}
		}
	}
}
