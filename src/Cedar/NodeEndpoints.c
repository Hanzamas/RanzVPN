// NodeEndpoints.c
// The endpoints of the peers of a node (SDN-93, #410): the addresses under which the Controller says that each peer is
// reached, one list for each Peer object of the desired state (CONTROL_PEER.Endpoints), and the list of the node itself
// (CONTROL_STATE.Endpoints). A node dials a peer through the endpoints of its Peer object with the race of the fallback
// list: an endpoint is an entry of it, a transport and the address that it dials, and the first transport that connects
// wins (TransportRace). The data transport of the client role turns the name of a peer, a server of its Client setting
// that names no fallback list of its own, into those entries (NodeClient.c).
// - NodeEndpointsTargets makes the entries of the fallback list of the endpoints of a peer, from the transports that can
//   dial here.
// - NodeEndpointsDials decides whether a node dials a peer. The rule that decides which of two nodes dials stays as it
//   was (CORE-S3-1): the node with the lower static key does, and a client dials every peer. A peer that has no endpoints
//   is not dialled: it dials, or the pair uses the datagram path of the peer layer (CORE-S5-5). A node without endpoints
//   is always the one that dials, since no peer can dial it.

#include "Node.h"

#include "Mayaqua/Memory.h"
#include "Mayaqua/Str.h"

#include "Core/Control.h"

// The entries of a fallback list that the num endpoints make: each endpoint whose transport is one of the num_known
// transports, which are the ones that can dial here, in the order of the endpoints, at most max of them into targets. An
// endpoint of a transport that cannot run here (mimic without its sidecar, QUIC without msquic.dll) is left out, so the
// others still dial. Their number; with targets NULL, how many there would be, which max does not limit.
UINT NodeEndpointsTargets(const CONTROL_ENDPOINT *endpoints, UINT num, TRANSPORT **known, UINT num_known, TRANSPORT_TARGET *targets, UINT max) {
	UINT n = 0;

	if (targets != NULL)
		Zero(targets, sizeof(TRANSPORT_TARGET) * max);
	if (endpoints == NULL || known == NULL)
		return 0;

	for (UINT i = 0; i < num && (targets == NULL || n < max); i++) {
		for (UINT j = 0; j < num_known; j++) {
			if (known[j] == NULL || StrCmp(known[j]->Name, endpoints[i].Transport) != 0)
				continue;

			if (targets != NULL) {
				targets[n].Transport = known[j];
				StrCpy(targets[n].Address, sizeof(targets[n].Address), endpoints[i].Address);
			}
			n++;
			break;
		}
	}

	return n;
}

// Whether a node dials a peer that has no session, given their static keys key and peer_key. A data transport that finds a
// peer by its node name (by_name) leaves the order of the keys alone to decide: the lower key dials, and a dialler, which
// is the client role, dials every peer. One that dials through endpoints dials a peer only when it can (dialable), and
// then a dialler does, and so does a node that has no endpoints (endpoints, its own number), whatever the order of the
// keys, since no peer can dial either of them, while two nodes that both have endpoints follow the order of the keys, so
// that exactly one of them dials.
bool NodeEndpointsDials(bool by_name, bool dialler, const UCHAR *key, const UCHAR *peer_key, UINT endpoints, bool dialable) {
	if (by_name)
		return (dialler || Cmp(key, peer_key, PEER_KEY_SIZE) < 0);

	return (dialable && (dialler || endpoints == 0 || Cmp(key, peer_key, PEER_KEY_SIZE) < 0));
}
