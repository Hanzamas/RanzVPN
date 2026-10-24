// NodeLeak.c
// Route leaking in the data plane of a node (SDN-7, #183; ADR-0025 decisions 7 to 9). A VRF imports the route targets
// that other VRFs export, as a VRF of BGP L3VPN and EVPN does, and the controller compiles the routes that a VRF of a
// peer leaks into a VRF of the node as routes of that Peer with the VRF of the peer that a packet on the route goes
// into (CONTROL_ROUTE.PeerVrfId). Each such route gets a next hop of its own in the forwarding tables of its
// Generation, after the next hops of the peers: the peer, as for any route to it, and that VRF of the peer
// (NODE_VRF_TABLES.HopVrfs), so the tables of the leaked routes are built and swapped in with the other tables of the
// Generation (NodeOverlay.c). A packet of the host on a leaked route goes to the peer with the id of that VRF in its
// record (NodeLeakVrf), not the id of the VRF that it came from, and the peer takes it in the VRF that leaked the
// route as it takes the traffic of that VRF itself: when the table of that VRF routes the source back to the node,
// which takes a leak the other way, and the destination to the host, then through its 1:1 NAT rules and its policy.
// So no route leaks without an export that an import matches, and the destination VRF decides what passes.

#include "Node.h"

#include "Mayaqua/Memory.h"

#include "Core/Control.h"

// Whether the route c of a peer is one that a VRF of the peer leaks into a VRF of the node
static bool NodeLeakIs(const CONTROL_ROUTE *c) {
	return (c->PeerVrfId != 0 && c->PeerVrfId != c->VrfId);
}

// Put the route of the leaked route c into routes[num] when routes is not NULL, with next hop next_hop: 1 for a prefix
// of IPv4 or IPv6, else 0
static UINT NodeLeakRoute(NODE_VRF_ROUTE *routes, UINT num, const CONTROL_ROUTE *c, UINT next_hop) {
	if ((c->AddressSize != 4 && c->AddressSize != 16) || c->Length > c->AddressSize * 8)
		return 0;

	if (routes != NULL) {
		NODE_VRF_ROUTE *r = &routes[num];

		Zero(r, sizeof(NODE_VRF_ROUTE));
		r->VrfId = c->VrfId;
		Copy(r->Address, c->Address, c->AddressSize);
		r->AddressSize = c->AddressSize;
		r->Length = c->Length;
		r->NextHop = next_hop;
	}

	return 1;
}

// The routes that the VRFs of the peers of the state st leak into the VRFs of the node, into routes, or their number
// when routes is NULL: the k-th of them, in the order of the peers and of their routes, leads to next hop
// st->NumPeers + k, which NodeLeakNewTables gives its peer and its VRF. Their number.
UINT NodeLeakRoutes(const CONTROL_STATE *st, NODE_VRF_ROUTE *routes) {
	UINT num = 0;

	for (UINT i = 0; st != NULL && i < st->NumPeers; i++) {
		for (UINT j = 0; j < st->Peers[i].NumRoutes && j < CONTROL_MAX_ROUTES; j++) {
			const CONTROL_ROUTE *c = &st->Peers[i].Routes[j];

			if (NodeLeakIs(c))
				num += NodeLeakRoute(routes, num, c, st->NumPeers + num);
		}
	}

	return num;
}

// The forwarding tables of the state st from its num routes, as NodeNewVrfTables builds them, with the next hops of
// the leaked routes of NodeLeakRoutes after hops, the peers of st->Peers: next hop st->NumPeers + k is the peer of the
// k-th leaked route, and the VRF of the peer that the route goes into is its entry of HopVrfs. NULL when they cannot
// be built.
NODE_VRF_TABLES *NodeLeakNewTables(const CONTROL_STATE *st, const NODE_VRF_ROUTE *routes, UINT num, void **hops) {
	UINT num_leaks = NodeLeakRoutes(st, NULL);
	UINT num_hops = st->NumPeers + num_leaks;
	void **all = ZeroMalloc(sizeof(void *) * MAX(num_hops, 1));
	UINT *vrfs = ZeroMalloc(sizeof(UINT) * MAX(num_hops, 1));
	UINT k = st->NumPeers;

	if (st->NumPeers != 0)
		Copy(all, hops, sizeof(void *) * st->NumPeers);

	for (UINT i = 0; i < st->NumPeers; i++) {
		for (UINT j = 0; j < st->Peers[i].NumRoutes && j < CONTROL_MAX_ROUTES; j++) {
			const CONTROL_ROUTE *c = &st->Peers[i].Routes[j];

			if (NodeLeakIs(c) && NodeLeakRoute(NULL, 0, c, 0) != 0 && k < num_hops) {
				all[k] = hops[i];
				vrfs[k++] = c->PeerVrfId;
			}
		}
	}

	NODE_VRF_TABLES *v = NodeNewVrfTables(st->Generation, routes, num, all, num_hops);
	Free(all);

	if (v != NULL && num_leaks != 0)
		v->HopVrfs = vrfs;
	else
		Free(vrfs);

	return v;
}

// The id of the VRF that a packet of the VRF vrf_id carries in its record to next hop hop of the tables v: the VRF of
// the peer that a leaked route goes into, else vrf_id itself
UINT NodeLeakVrf(NODE_VRF_TABLES *v, UINT hop, UINT vrf_id) {
	if (v == NULL || v->HopVrfs == NULL || hop >= v->NumHops || v->HopVrfs[hop] == 0)
		return vrf_id;

	return v->HopVrfs[hop];
}
