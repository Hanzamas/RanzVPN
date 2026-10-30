// ControlEgress.c
// The internet exit of a node on the control stream (SDN-12, #188; Core/Control.h). The NodeConfig of a state names the
// VRFs whose exit the node is (CONTROL_STATE.EgressVrfIds), which go with the state as the owner takes it
// (ControlCopyEgress); the Peer object of the exit of a VRF carries the default route of the VRF as one of its routes,
// which Control.c copies with the others.

#include "Core/ControlInternal.h"

// The ids of the VRFs whose internet exit the node is, from the NodeConfig among num objects, into the state: at most
// CONTROL_MAX_VRFS, in the order of the NodeConfig. The id 0, which names no VRF, and an id that comes twice are left out.
void ControlCopyEgress(CONTROL_STATE *st, const ranz_control_v1_Object *objects, UINT num) {
	st->NumEgress = 0;

	for (UINT i = 0; i < num; i++) {
		const ranz_control_v1_Object *o = &objects[i];

		if (o->which_kind != ranz_control_v1_Object_node_tag)
			continue;

		for (pb_size_t j = 0; j < o->kind.node.egress_vrf_ids_count && j < ARRAYSIZE(o->kind.node.egress_vrf_ids) && st->NumEgress < CONTROL_MAX_VRFS; j++) {
			UINT id = o->kind.node.egress_vrf_ids[j];
			bool seen = (id == 0);

			for (UINT k = 0; k < st->NumEgress && seen == false; k++)
				seen = (st->EgressVrfIds[k] == id);

			if (seen == false)
				st->EgressVrfIds[st->NumEgress++] = id;
		}
	}
}
