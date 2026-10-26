// ControlEndpoint.c
// The endpoints of a node and of its peers on the control stream (SDN-93, #410; Core/Control.h). The NodeConfig of a state
// carries the endpoints of the node itself (CONTROL_STATE.Endpoints), and each Peer object those of the peer that the node
// dials at them (CONTROL_PEER.Endpoints), in the order of the Node resource of that node, which is the order of the race of
// the fallback list. They go with the state, as the owner takes it (ControlCopyEndpoints).

#include "Core/ControlInternal.h"

#include <string.h>

// The name that a fallback list gives the transport of an endpoint; NULL for one that this node does not know
static const char *ControlEndpointTransport(ranz_control_v1_Transport transport) {
	switch (transport) {
	case ranz_control_v1_Transport_TRANSPORT_QUIC:
		return "quic";
	case ranz_control_v1_Transport_TRANSPORT_TLS:
		return "tls";
	case ranz_control_v1_Transport_TRANSPORT_MIMIC:
		return "mimic";
	default:
		return NULL;
	}
}

// The count endpoints of src into dst, CONTROL_MAX_ENDPOINTS at most, in their order: an endpoint of a transport that this
// node does not know, or without an address, is left out
static void ControlCopyEndpointList(CONTROL_ENDPOINT *dst, UINT *num, const ranz_control_v1_Endpoint *src, pb_size_t count) {
	*num = 0;

	for (pb_size_t i = 0; i < count && *num < CONTROL_MAX_ENDPOINTS; i++) {
		const char *transport = ControlEndpointTransport(src[i].transport);

		if (transport == NULL || src[i].address[0] == 0)
			continue;

		CONTROL_ENDPOINT *e = &dst[*num];

		ZeroMemory(e, sizeof(CONTROL_ENDPOINT));
		strncpy_s(e->Transport, sizeof(e->Transport), transport, _TRUNCATE);
		strncpy_s(e->Address, sizeof(e->Address), src[i].address, _TRUNCATE);
		(*num)++;
	}
}

// The endpoints of the NodeConfig and of each Peer object among num objects into the state, which holds the peers that the
// client took from them already: the endpoints of the node into the state, those of a Peer object into the peer of its name
void ControlCopyEndpoints(CONTROL_STATE *st, const ranz_control_v1_Object *objects, UINT num) {
	st->NumEndpoints = 0;

	for (UINT i = 0; i < num; i++) {
		const ranz_control_v1_Object *o = &objects[i];

		if (o->which_kind == ranz_control_v1_Object_node_tag) {
			ControlCopyEndpointList(st->Endpoints, &st->NumEndpoints, o->kind.node.endpoints, o->kind.node.endpoints_count);
		} else if (o->which_kind == ranz_control_v1_Object_peer_tag) {
			for (UINT j = 0; j < st->NumPeers; j++) {
				CONTROL_PEER *p = &st->Peers[j];

				if (strcmp(p->Name, o->kind.peer.name) == 0)
					ControlCopyEndpointList(p->Endpoints, &p->NumEndpoints, o->kind.peer.endpoints, o->kind.peer.endpoints_count);
			}
		}
	}
}
