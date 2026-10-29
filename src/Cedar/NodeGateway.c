// NodeGateway.c
// Gateway HA and hub-and-spoke in the overlay of a node (SDN-19, #195; ADR-0025 decisions 11 and 12).
//
// Gateway HA. Several gateways may announce one LAN subnet of a VRF: the controller gives every node of the VRF the prefix
// as a route of the Peer of each gateway, and each gateway the prefix as one of the LAN subnets behind it
// (CONTROL_STATE.LanSubnets), which lead to its host (NodeGatewayRoutes). A prefix that two peers or more announce in a VRF
// of the node gets a next hop of its own in the forwarding tables of the Generation, after the next hops of the peers and
// of the leaked routes (NodeLeakNewTables): the next hop of its group of gateways. A packet of the host that the table of its
// VRF leads to a group goes to the gateway that the group picks (NodeGatewayPick): the first in the order of the peers,
// which is name order, that is up and that the controller does not report down (CONTROL_PEER.Down); when the controller
// reports down every gateway that is up, the first that is up; none when no gateway of the group is up. A VRF with ECMP
// (CONTROL_VRF.Ecmp) gives each flow one of the same gateways by its flow hash (NodeGatewayFlowHash) and rendezvous
// hashing, so a flow keeps its gateway while that one stays up, and only the flows of a gateway that goes down move. A
// packet whose source a group holds comes from whichever gateway of the group sent it (NodeGatewayFrom).
//
// A gateway is up while it has its Noise session and answers the probes of the node. The thread of the overlay sends each
// gateway of a group of the tables in force a probe every NODE_GATEWAY_PROBE ms as a control record of its Noise session,
// which the gateway answers at once on the same session (NodeGatewayControl). A gateway whose answers stop for
// NODE_GATEWAY_DEAD ms goes down, and one whose session closes goes down at once: its groups give its traffic to the next
// gateway, so the node finds a failed gateway and leaves it in under a second, with probes of its own and no BFD
// (maintainer decision of 2026-10-24). A gateway that went down while its session stayed up is up again after
// NODE_GATEWAY_RISE answers in a row; one whose session comes back is up with it. What the node knows of a gateway stays
// across the Generations, kept by its peer (NODE_GATEWAY_PEER), and the group tables of each Generation hold it until they
// are freed, so the data path reads it without a lock.
//
// Hub-and-spoke. The controller gives each spoke of a VRF of topology hub-and-spoke the hub as its only peer in the VRF,
// with the prefixes of the VRF as routes of the hub: the pools of its L3 Networks, the LAN subnets that the other nodes
// advertise there and the outside prefixes of their 1:1 NAT rules. A packet of one spoke to another goes to the hub, and
// the hub, which has every spoke as its peer, sends it on (NodeGatewayTransit): the traffic between two sites passes the
// hub, where a Mirror of the VRF copies it to a sensor, and two spokes never talk directly. A node that is not the hub of
// the VRF drops such a packet, as the overlay did before.

#include "Node.h"

#include "Mayaqua/Memory.h"
#include "Mayaqua/Object.h"
#include "Mayaqua/Str.h"

#include "Core/Control.h"

#include <stdlib.h>
#include <string.h>

#include "NodeGateway.h"
#include "NodeInternal.h"
#include "NodeProfile.h"

#define NODE_GATEWAY_TICK 10 // ms between two looks of the thread of the overlay at the gateways

// What the node knows of one gateway: a peer of the overlay that is a gateway of a group of some tables, from the first
// Generation that made it one until the overlay forgets the peer
typedef struct NODE_GATEWAY_PEER {
	void *Peer;                   // The peer of the overlay (NodeOverlay.c), which the overlay keeps until NodeGatewayForget
	char Name[CONTROL_NAME_SIZE]; // Its name, for the node log
	UINT Refs;                    // The group tables that hold it: the node probes it while one does
	volatile LONG Up;             // It has its session and answers its probes: what the data path reads
	bool Session;                 // The thread of the overlay saw its session at its last look
	UINT64 LastAnswer;            // When it answered a probe in time last, or its session came up
	UINT64 NextProbe;             // When its next probe goes
	UINT Sequence;                // The number of its last probe
	UINT Rise;                    // Its answers in a row while it is down with its session up
	UINT64 DownSince;             // When it went down last, 0 before
	UINT64 Failovers;             // The times it went down
	volatile LONG64 Picked;       // The packets of the host that its groups gave it
} NODE_GATEWAY_PEER;

// The gateway HA of the overlay of a node, while the overlay runs
struct NODE_GATEWAY {
	LOCK *Lock;                 // Peers and what each holds
	LIST *Peers;                // The gateways (NODE_GATEWAY_PEER)
	UINT64 NextPass;            // When the thread of the overlay looks at them next
	volatile LONG64 Probes;     // Probes sent
	volatile LONG64 Answers;    // Answers to them taken in time
	volatile LONG64 Answered;   // Probes of the peers answered
	volatile LONG64 Failovers;  // Gateways that went down
	volatile LONG64 Recoveries; // Gateways that came up again
	volatile LONG64 Transit;    // Packets of one spoke that the node, their hub, sent on to another
};

// One gateway of a group
typedef struct NODE_GATEWAY_MEMBER {
	UINT Hop;                   // Its next hop: the index of its peer in the state
	UINT Seed;                  // Its weight in the flow hash: the first bytes of its static key
	bool Down;                  // The controller reports it down
	NODE_GATEWAY_PEER *Gateway; // What the node knows of it, which the table holds
} NODE_GATEWAY_MEMBER;

// A group of gateways: the peers that announce one prefix in one VRF, in the order of the peers
typedef struct NODE_GATEWAY_GROUP {
	UINT VrfId;                                          // The VRF
	bool Ecmp;                                           // It spreads its flows over its gateways that are up
	UINT NumMembers;                                     // The gateways
	NODE_GATEWAY_MEMBER Members[NODE_GATEWAY_MAX_GROUP]; // ...
} NODE_GATEWAY_GROUP;

// The groups of gateways and the hubs of one Generation, on its forwarding tables (NODE_VRF_TABLES)
struct NODE_GATEWAY_TABLE {
	NODE_GATEWAY *Gateway;       // The gateway HA of the node, which outlives its tables
	UINT NumPeers;               // The peers of the Generation: the next hops 0 to NumPeers - 1
	UINT Base;                   // The next hop of the first group
	UINT NumGroups;              // The groups ...
	NODE_GATEWAY_GROUP *Groups;  // ... in the order of NodeGatewayCompare
	UINT NumHubs;                // The VRFs whose hub the node is
	UINT Hubs[CONTROL_MAX_VRFS]; // ...
};

// A route of a peer as the groups see it: its prefix, masked, and the index of the peer in the state
typedef struct NODE_GATEWAY_ROUTE {
	UINT VrfId;
	UCHAR Address[16];
	UINT AddressSize;
	UINT Length;
	UINT Peer;
} NODE_GATEWAY_ROUTE;

//
// The groups
//

// The prefix of a route as a group sees it, with the address of size bytes masked to its length: false for a prefix that
// is neither IPv4 nor IPv6, or longer than its address
static bool NodeGatewayPrefix(NODE_GATEWAY_ROUTE *r, UINT vrf_id, const UCHAR *address, UINT size, UINT length, UINT peer) {
	if ((size != 4 && size != 16) || length > size * 8)
		return false;

	Zero(r, sizeof(NODE_GATEWAY_ROUTE));
	r->VrfId = vrf_id;
	Copy(r->Address, address, size);
	r->AddressSize = size;
	r->Length = length;
	r->Peer = peer;

	for (UINT i = 0; i < size; i++) {
		UINT bits = (length > i * 8 ? length - i * 8 : 0);

		if (bits < 8)
			r->Address[i] &= (UCHAR)(0xFF00 >> bits);
	}

	return true;
}

// The order of the routes: by VRF, family, length and address, then by peer
static int NodeGatewayCompare(const void *p1, const void *p2) {
	const NODE_GATEWAY_ROUTE *a = (const NODE_GATEWAY_ROUTE *)p1;
	const NODE_GATEWAY_ROUTE *b = (const NODE_GATEWAY_ROUTE *)p2;

	if (a->VrfId != b->VrfId)
		return (a->VrfId < b->VrfId ? -1 : 1);
	if (a->AddressSize != b->AddressSize)
		return (a->AddressSize < b->AddressSize ? -1 : 1);
	if (a->Length != b->Length)
		return (a->Length < b->Length ? -1 : 1);

	int c = memcmp(a->Address, b->Address, a->AddressSize);
	if (c != 0)
		return c;

	if (a->Peer == b->Peer)
		return 0;

	return (a->Peer < b->Peer ? -1 : 1);
}

// Whether two routes have one prefix
static bool NodeGatewaySame(const NODE_GATEWAY_ROUTE *a, const NODE_GATEWAY_ROUTE *b) {
	return (a->VrfId == b->VrfId && a->AddressSize == b->AddressSize && a->Length == b->Length && Cmp(a->Address, b->Address, a->AddressSize) == 0);
}

// The routes of the peers of the state st that the groups look at, sorted by NodeGatewayCompare, their number into num:
// each route of a peer that no VRF of the peer leaks, as a leaked route has a next hop of its own (NodeLeak.c). NULL for
// none; Free frees it.
static NODE_GATEWAY_ROUTE *NodeGatewaySorted(const CONTROL_STATE *st, UINT *num) {
	UINT max = 0;

	*num = 0;
	for (UINT i = 0; st != NULL && i < st->NumPeers; i++)
		max += MIN(st->Peers[i].NumRoutes, CONTROL_MAX_ROUTES);
	if (max == 0)
		return NULL;

	NODE_GATEWAY_ROUTE *list = ZeroMalloc(sizeof(NODE_GATEWAY_ROUTE) * max);

	for (UINT i = 0; i < st->NumPeers; i++) {
		for (UINT j = 0; j < st->Peers[i].NumRoutes && j < CONTROL_MAX_ROUTES; j++) {
			const CONTROL_ROUTE *c = &st->Peers[i].Routes[j];

			if (c->PeerVrfId != 0 && c->PeerVrfId != c->VrfId)
				continue;
			if (NodeGatewayPrefix(&list[*num], c->VrfId, c->Address, c->AddressSize, c->Length, i))
				(*num)++;
		}
	}

	if (*num == 0) {
		Free(list);
		return NULL;
	}

	qsort(list, *num, sizeof(NODE_GATEWAY_ROUTE), NodeGatewayCompare);

	return list;
}

// The end of the run of the routes of one prefix that starts at start, among the num routes of list
static UINT NodeGatewayRun(const NODE_GATEWAY_ROUTE *list, UINT num, UINT start) {
	UINT end = start + 1;

	while (end < num && NodeGatewaySame(&list[start], &list[end]))
		end++;

	return end;
}

// Whether the node announces the prefix of r itself: a LAN subnet behind the node leads to its host, whoever else announces it
static bool NodeGatewayOwn(const CONTROL_STATE *st, const NODE_GATEWAY_ROUTE *r) {
	for (UINT i = 0; i < st->NumLanSubnets && i < CONTROL_MAX_ROUTES; i++) {
		const CONTROL_ROUTE *c = &st->LanSubnets[i];
		NODE_GATEWAY_ROUTE own;

		if (NodeGatewayPrefix(&own, c->VrfId, c->Address, c->AddressSize, c->Length, 0) && NodeGatewaySame(&own, r))
			return true;
	}

	return false;
}

// Whether the run of the routes of one prefix from start to end is a group: two peers or more announce it, and the node
// does not. The run is in the order of the peers, so it has a second peer when its last route is of another peer than its
// first.
static bool NodeGatewayIsGroup(const CONTROL_STATE *st, const NODE_GATEWAY_ROUTE *list, UINT start, UINT end) {
	return (list[end - 1].Peer != list[start].Peer && NodeGatewayOwn(st, &list[start]) == false);
}

// Whether the VRF vrf_id of the state st spreads its flows over its gateways
static bool NodeGatewayEcmp(const CONTROL_STATE *st, UINT vrf_id) {
	for (UINT i = 0; i < st->NumVrfs && i < CONTROL_MAX_VRFS; i++)
		if (st->Vrfs[i].Id == vrf_id)
			return st->Vrfs[i].Ecmp;

	return false;
}

// The routes of the LAN subnets behind the node of the state st, into routes, or their number when routes is NULL: each
// leads to the host. Their number.
UINT NodeGatewayRoutes(const CONTROL_STATE *st, NODE_VRF_ROUTE *routes) {
	UINT num = 0;

	for (UINT i = 0; st != NULL && i < st->NumLanSubnets && i < CONTROL_MAX_ROUTES; i++) {
		const CONTROL_ROUTE *c = &st->LanSubnets[i];

		if ((c->AddressSize != 4 && c->AddressSize != 16) || c->Length > c->AddressSize * 8)
			continue;

		if (routes != NULL) {
			NODE_VRF_ROUTE *r = &routes[num];

			Zero(r, sizeof(NODE_VRF_ROUTE));
			r->VrfId = c->VrfId;
			Copy(r->Address, c->Address, c->AddressSize);
			r->AddressSize = c->AddressSize;
			r->Length = c->Length;
			r->NextHop = NODE_VRF_LOCAL;
		}
		num++;
	}

	return num;
}

// The groups of gateways of the state st: the prefixes of its VRFs that two peers or more announce and that the node does
// not announce itself, in the order of NodeGatewayCompare. With hops, hops[g] is the next hop of the first gateway of group
// g among peers, the next hops of the peers of st, which the forwarding tables give the group until it picks one for a
// packet. Their number.
UINT NodeGatewayGroups(const CONTROL_STATE *st, void **peers, void **hops) {
	UINT num = 0, count = 0;
	NODE_GATEWAY_ROUTE *list = NodeGatewaySorted(st, &num);

	for (UINT i = 0; i < num;) {
		UINT end = NodeGatewayRun(list, num, i);

		if (NodeGatewayIsGroup(st, list, i, end)) {
			if (peers != NULL && hops != NULL)
				hops[count] = peers[list[i].Peer];
			count++;
		}
		i = end;
	}

	Free(list);

	return count;
}

// Lead the routes of the gateways of each group of the state st to the next hop of the group: of the num routes of the
// forwarding tables of the Generation, whose next hop i is the peer of st->Peers[i], each route of the prefix of a group to
// one of its gateways. Group g has the next hop after those of the peers and of the leaked routes (NodeLeakNewTables).
void NodeGatewayGroupRoutes(const CONTROL_STATE *st, NODE_VRF_ROUTE *routes, UINT num) {
	UINT num_list = 0, group = 0;
	NODE_GATEWAY_ROUTE *list = NodeGatewaySorted(st, &num_list);

	if (list == NULL || routes == NULL) {
		Free(list);
		return;
	}

	UINT base = st->NumPeers + NodeLeakRoutes(st, NULL);

	for (UINT i = 0; i < num_list;) {
		UINT end = NodeGatewayRun(list, num_list, i);

		if (NodeGatewayIsGroup(st, list, i, end)) {
			for (UINT k = 0; k < num; k++) {
				NODE_VRF_ROUTE *r = &routes[k];
				NODE_GATEWAY_ROUTE p;

				if (r->NextHop >= st->NumPeers || NodeGatewayPrefix(&p, r->VrfId, r->Address, r->AddressSize, r->Length, r->NextHop) == false || NodeGatewaySame(&p, &list[i]) == false)
					continue;

				// A route of the prefix of a peer that announces it: the run holds each of them
				for (UINT j = i; j < end; j++) {
					if (list[j].Peer == r->NextHop) {
						r->NextHop = base + group;
						break;
					}
				}
			}
			group++;
		}
		i = end;
	}

	Free(list);
}

//
// The gateways
//

// What the node knows of the gateway peer, NULL for nothing. The caller holds the lock.
static NODE_GATEWAY_PEER *NodeGatewayFind(NODE_GATEWAY *g, const void *peer) {
	for (UINT i = 0; i < LIST_NUM(g->Peers); i++) {
		NODE_GATEWAY_PEER *e = LIST_DATA(g->Peers, i);

		if (e->Peer == peer)
			return e;
	}

	return NULL;
}

// What the node knows of the gateway peer of the name, which a group table that is built holds from now on: what it knew, or
// a new gateway, up while the peer has its session. The caller holds the lock.
static NODE_GATEWAY_PEER *NodeGatewayHold(NODE_GATEWAY *g, void *peer, const char *name) {
	NODE_GATEWAY_PEER *e = NodeGatewayFind(g, peer);

	if (e == NULL) {
		UINT64 now = GetTickCount64();

		e = ZeroMalloc(sizeof(NODE_GATEWAY_PEER));
		e->Peer = peer;
		StrCpy(e->Name, sizeof(e->Name), name);
		e->Session = NodeOverlayPeerUp(peer);
		e->Up = (e->Session ? 1 : 0);
		e->LastAnswer = now;
		e->NextProbe = now;
		Add(g->Peers, e);
	}

	e->Refs++;

	return e;
}

// The gateway e goes down at now. The caller holds the lock.
static void NodeGatewayDown(NODE_GATEWAY *g, NODE_GATEWAY_PEER *e, UINT64 now) {
	InterlockedExchange(&e->Up, 0);
	e->DownSince = now;
	e->Failovers++;
	e->Rise = 0;
	InterlockedIncrement64(&g->Failovers);
}

// The gateway e comes up. The caller holds the lock.
static void NodeGatewayUp(NODE_GATEWAY *g, NODE_GATEWAY_PEER *e) {
	InterlockedExchange(&e->Up, 1);
	e->Rise = 0;
	if (e->DownSince != 0)
		InterlockedIncrement64(&g->Recoveries);
}

// Start the gateway HA of the overlay of a node (NodeOverlayStart)
void NodeGatewayStart(NODE *n) {
	if (n == NULL || n->Gateway != NULL)
		return;

	NODE_GATEWAY *g = ZeroMalloc(sizeof(NODE_GATEWAY));
	g->Lock = NewLock();
	g->Peers = NewListFast(NULL);

	n->Gateway = g;
}

// Stop the gateway HA of the overlay of a node (NodeOverlayStop), once no forwarding tables are left whose group tables hold
// its gateways and the thread of the overlay forgot their peers
void NodeGatewayStop(NODE *n) {
	NODE_GATEWAY *g = (n != NULL ? n->Gateway : NULL);

	if (g == NULL)
		return;

	n->Gateway = NULL;

	for (UINT i = 0; i < LIST_NUM(g->Peers); i++)
		Free(LIST_DATA(g->Peers, i));
	ReleaseList(g->Peers);
	DeleteLock(g->Lock);
	Free(g);
}

// The group table of the Generation of st onto its forwarding tables v, before they go in: each group of gateways with its
// gateways in the order of the peers, what the node knows of each, which the table holds, and whether its VRF spreads its
// flows; and the VRFs whose hub the node is. The tables get none when the Generation has neither.
void NodeGatewayAttach(NODE *n, NODE_VRF_TABLES *v, const CONTROL_STATE *st) {
	NODE_GATEWAY *g = (n != NULL ? n->Gateway : NULL);
	UINT num = 0;

	if (g == NULL || v == NULL || st == NULL)
		return;

	NODE_GATEWAY_TABLE *t = ZeroMalloc(sizeof(NODE_GATEWAY_TABLE));
	t->Gateway = g;
	t->NumPeers = st->NumPeers;
	t->Base = st->NumPeers + NodeLeakRoutes(st, NULL);

	for (UINT i = 0; i < st->NumVrfs && i < CONTROL_MAX_VRFS; i++)
		if (IsEmptyStr(st->Vrfs[i].Hub) == false && StrCmp(st->Vrfs[i].Hub, st->Name) == 0)
			t->Hubs[t->NumHubs++] = st->Vrfs[i].Id;

	NODE_GATEWAY_ROUTE *list = NodeGatewaySorted(st, &num);
	t->Groups = ZeroMalloc(sizeof(NODE_GATEWAY_GROUP) * MAX(NodeGatewayGroups(st, NULL, NULL), 1));

	Lock(g->Lock);
	{
		for (UINT i = 0; i < num;) {
			UINT end = NodeGatewayRun(list, num, i);

			if (NodeGatewayIsGroup(st, list, i, end)) {
				NODE_GATEWAY_GROUP *e = &t->Groups[t->NumGroups++];

				e->VrfId = list[i].VrfId;
				e->Ecmp = NodeGatewayEcmp(st, e->VrfId);
				for (UINT j = i; j < end && e->NumMembers < NODE_GATEWAY_MAX_GROUP; j++) {
					UINT p = list[j].Peer;

					// A peer that announces the prefix twice is one gateway
					if ((j > i && list[j - 1].Peer == p) || p >= v->NumHops)
						continue;

					NODE_GATEWAY_MEMBER *m = &e->Members[e->NumMembers++];
					m->Hop = p;
					m->Seed = READ_UINT(st->Peers[p].Key);
					m->Down = st->Peers[p].Down;
					m->Gateway = NodeGatewayHold(g, v->Hops[p], st->Peers[p].Name);
				}
			}
			i = end;
		}
	}
	Unlock(g->Lock);

	Free(list);

	if (t->NumGroups == 0 && t->NumHubs == 0) {
		NodeFreeGatewayTable(t);
		t = NULL;
	}

	NodeFreeGatewayTable(v->Gateway);
	v->Gateway = t;
}

// Free a group table: the node probes its gateways while another table holds them
void NodeFreeGatewayTable(NODE_GATEWAY_TABLE *t) {
	if (t == NULL)
		return;

	NODE_GATEWAY *g = t->Gateway;

	Lock(g->Lock);
	for (UINT i = 0; i < t->NumGroups; i++)
		for (UINT j = 0; j < t->Groups[i].NumMembers; j++)
			t->Groups[i].Members[j].Gateway->Refs--;
	Unlock(g->Lock);

	Free(t->Groups);
	Zero(t, sizeof(NODE_GATEWAY_TABLE));
	Free(t);
}

//
// The packets
//

// FNV-1a over size bytes at data, from h
static UINT NodeGatewayFnv(UINT h, const UCHAR *data, UINT size) {
	for (UINT i = 0; i < size; i++) {
		h ^= data[i];
		h *= 16777619U;
	}

	return h;
}

// The flow hash of an IP packet (NodeGatewayPick): FNV-1a over its addresses, its protocol and, for TCP, UDP and SCTP, its
// ports, and for IPv6 its flow label, mixed as MurmurHash3 finishes. The packets of one flow get one hash, so they take one
// gateway. A fragment of IPv4 hashes without the ports, which only the first fragment of a datagram has, so every fragment
// takes the gateway of the others; an IPv6 packet whose next header is an extension header hashes without them too. 0 for
// a packet that is neither IPv4 nor IPv6.
UINT NodeGatewayFlowHash(const UCHAR *packet, UINT size) {
	UINT h = 2166136261U;
	UINT header = 0, ports = 0;
	UCHAR protocol = 0;

	if (packet == NULL || size < 20)
		return 0;

	switch (packet[0] >> 4) {
	case 4:
		header = (packet[0] & 0x0F) * 4;
		if (header < 20 || header > size)
			return 0;
		protocol = packet[9];
		h = NodeGatewayFnv(h, packet + 12, 8);
		// Neither a fragment offset nor the flag More Fragments: no fragment
		if ((READ_USHORT(packet + 6) & 0x3FFF) == 0)
			ports = header;
		break;
	case 6: {
		UCHAR label[3];

		if (size < 40)
			return 0;
		protocol = packet[6];
		h = NodeGatewayFnv(h, packet + 8, 32);
		label[0] = packet[1] & 0x0F;
		label[1] = packet[2];
		label[2] = packet[3];
		h = NodeGatewayFnv(h, label, sizeof(label));
		ports = 40;
		break;
	}
	default:
		return 0;
	}

	h = NodeGatewayFnv(h, &protocol, 1);
	// TCP, UDP and SCTP: the source and the destination port
	if (ports != 0 && (protocol == 6 || protocol == 17 || protocol == 132) && ports + 4 <= size)
		h = NodeGatewayFnv(h, packet + ports, 4);

	h ^= h >> 16;
	h *= 0x85EBCA6BU;
	h ^= h >> 13;
	h *= 0xC2B2AE35U;
	h ^= h >> 16;

	return h;
}

// The score of a gateway of the seed for a flow of the hash in rendezvous hashing: of the gateways that are up, the one of
// the highest score carries the flow
static UINT NodeGatewayScore(UINT hash, UINT seed) {
	UINT x = hash ^ (seed * 0x9E3779B1U);

	x ^= x >> 16;
	x *= 0x85EBCA6BU;
	x ^= x >> 13;
	x *= 0xC2B2AE35U;
	x ^= x >> 16;

	return x;
}

// The gateway of the group e, by its index, that carries a packet of a flow of the hash: among the gateways that are up, and
// that the controller does not report down when controller is set, the first, or with ECMP the one of the highest score.
// NODE_VRF_NONE when there is none.
static UINT NodeGatewayChoose(const NODE_GATEWAY_GROUP *e, UINT hash, bool controller) {
	UINT best = NODE_VRF_NONE, best_score = 0;

	for (UINT i = 0; i < e->NumMembers; i++) {
		const NODE_GATEWAY_MEMBER *m = &e->Members[i];

		if (ReadAcquire(&m->Gateway->Up) == 0 || (controller && m->Down))
			continue;
		if (e->Ecmp == false)
			return i;

		UINT score = NodeGatewayScore(hash, m->Seed);
		if (best == NODE_VRF_NONE || score > best_score) {
			best = i;
			best_score = score;
		}
	}

	return best;
}

// The next hop of a packet of the host whose destination the forwarding table of its VRF leads to hop: for the next hop of a
// group of gateways, the next hop of the gateway that the group picks for the packet, NODE_VRF_NONE when no gateway of the
// group is up; any other next hop as it is. The controller's health data counts while a gateway that it does not report
// down is up; when it reports down every gateway that is up, the node's own probes decide alone. The caller is an online
// reader of the node's table snapshot, which holds v.
UINT NodeGatewayPick(NODE_VRF_TABLES *v, UINT hop, const UCHAR *packet, UINT size) {
	const NODE_GATEWAY_TABLE *t = (v != NULL ? v->Gateway : NULL);

	if (t == NULL || hop < t->Base || hop - t->Base >= t->NumGroups)
		return hop;

	const NODE_GATEWAY_GROUP *e = &t->Groups[hop - t->Base];
	UINT hash = (e->Ecmp ? NodeGatewayFlowHash(packet, size) : 0);
	UINT i = NodeGatewayChoose(e, hash, true);

	if (i == NODE_VRF_NONE)
		i = NodeGatewayChoose(e, hash, false);
	if (i == NODE_VRF_NONE)
		return NODE_VRF_NONE;

	InterlockedIncrement64(&e->Members[i].Gateway->Picked);

	return e->Members[i].Hop;
}

// The next hop of the peer that sent a packet whose source the forwarding table of its VRF leads to from: the next hop of the
// gateway that sent it when from is the next hop of a group of gateways and peer one of them, from as it is otherwise.
// The caller is an online reader of the node's table snapshot, which holds v.
UINT NodeGatewayFrom(NODE_VRF_TABLES *v, UINT from, const void *peer) {
	const NODE_GATEWAY_TABLE *t = (v != NULL ? v->Gateway : NULL);

	if (t == NULL || from < t->Base || from - t->Base >= t->NumGroups)
		return from;

	const NODE_GATEWAY_GROUP *e = &t->Groups[from - t->Base];
	for (UINT i = 0; i < e->NumMembers; i++)
		if (e->Members[i].Hop < v->NumHops && v->Hops[e->Members[i].Hop] == peer)
			return e->Members[i].Hop;

	return from;
}

// Whether the node is the hub of the VRF vrf_id in the Generation of the tables v
bool NodeGatewayHub(NODE_VRF_TABLES *v, UINT vrf_id) {
	const NODE_GATEWAY_TABLE *t = (v != NULL ? v->Gateway : NULL);

	for (UINT i = 0; t != NULL && i < t->NumHubs; i++)
		if (t->Hubs[i] == vrf_id)
			return true;

	return false;
}

// A packet of a peer in the VRF vrf_id, the data record of size bytes, which came from the next hop from and whose
// destination the forwarding table of the VRF leads to the next hop to, not to the host: when the node is the hub of the VRF,
// it sends the record on to that next hop, or to the gateway that the group of to picks, and a Mirror of the VRF copies the
// packet there, as an inspection appliance at the hub sees the traffic between two spokes. True when the packet went on;
// false when the node is no hub of the VRF, or the packet goes nowhere: never back to the peer that sent it, nor along a
// leaked route. The caller is an online reader of the node's table snapshot, which holds v.
bool NodeGatewayTransit(NODE *n, NODE_VRF_TABLES *v, UINT vrf_id, UINT from, UINT to, const UCHAR *record, UINT size) {
	NODE_GATEWAY *g = (n != NULL ? n->Gateway : NULL);
	const NODE_GATEWAY_TABLE *t = (v != NULL ? v->Gateway : NULL);

	if (g == NULL || t == NULL || record == NULL || size < NODE_OVERLAY_VRF_TAG || NodeGatewayHub(v, vrf_id) == false)
		return false;

	const UCHAR *packet = record + NODE_OVERLAY_VRF_TAG;
	UINT packet_size = size - NODE_OVERLAY_VRF_TAG;

	to = NodeGatewayPick(v, to, packet, packet_size);
	if (to >= t->NumPeers || from >= v->NumHops || v->Hops[to] == v->Hops[from])
		return false;
	// The session profiles of the two peers judge the packet as it passes the node (NodeProfile.c; SDN-40, #233)
	if (NodeProfileTransit(n, v, vrf_id, from, to, packet, packet_size) == false || NodeOverlaySendRecord(n, v, to, record, size) == false)
		return false;

	NodeMirrorCopy(v, vrf_id, packet, packet_size, false);
	InterlockedIncrement64(&g->Transit);

	return true;
}

//
// The probes
//

// Write a probe or its answer into buf, NODE_GATEWAY_PROBE_SIZE bytes: the kind, then the sequence and the time of the prober,
// big-endian. Its size.
UINT NodeGatewayWriteProbe(UCHAR *buf, UINT kind, UINT sequence, UINT64 time) {
	buf[0] = (UCHAR)kind;
	WRITE_UINT(buf + 1, sequence);
	WRITE_UINT64(buf + 5, time);

	return NODE_GATEWAY_PROBE_SIZE;
}

// Read a control record of the Noise session between two peers as a probe or its answer: false for any other record, which
// has another size or kind
bool NodeGatewayParseProbe(const UCHAR *data, UINT size, NODE_GATEWAY_PROBE_MSG *m) {
	if (data == NULL || m == NULL || size != NODE_GATEWAY_PROBE_SIZE || (data[0] != NODE_GATEWAY_PROBE_ASK && data[0] != NODE_GATEWAY_PROBE_ANSWER))
		return false;

	Zero(m, sizeof(NODE_GATEWAY_PROBE_MSG));
	m->Kind = data[0];
	m->Sequence = READ_UINT(data + 1);
	m->Time = READ_UINT64(data + 5);

	return true;
}

// What happened to a gateway at a look of the thread of the overlay, for the node log
#define NODE_GATEWAY_CLOSED 0 // It went down: its session closed
#define NODE_GATEWAY_SILENT 1 // It went down: it answered no probe for NODE_GATEWAY_DEAD ms
#define NODE_GATEWAY_BACK   2 // It came up again with its session

// The gateways, at each pass of the thread of the overlay and every NODE_GATEWAY_TICK ms at most: a gateway whose session
// closed goes down at once, one that answered no probe for NODE_GATEWAY_DEAD ms goes down, one whose session came up is up
// with it, and each gateway of a group of the tables in force gets its next probe on its Noise session when it is due
void NodeGatewayProbe(NODE *n) {
	NODE_GATEWAY *g = (n != NULL ? n->Gateway : NULL);
	NODE_GATEWAY_PEER *due[NODE_GATEWAY_BATCH];
	UINT sequences[NODE_GATEWAY_BATCH];
	char names[NODE_GATEWAY_BATCH][CONTROL_NAME_SIZE];
	UINT events[NODE_GATEWAY_BATCH];
	UINT num_due = 0, num_events = 0;
	UINT64 now = GetTickCount64();

	if (g == NULL || now < g->NextPass)
		return;

	g->NextPass = now + NODE_GATEWAY_TICK;

	Lock(g->Lock);
	{
		for (UINT i = 0; i < LIST_NUM(g->Peers); i++) {
			NODE_GATEWAY_PEER *e = LIST_DATA(g->Peers, i);
			bool session = (e->Refs != 0 && NodeOverlayPeerUp(e->Peer));
			UINT event = INFINITE;

			if (session == false) {
				// A gateway whose session closed goes down at once; one that no table holds is no longer probed
				if (e->Refs != 0 && ReadAcquire(&e->Up) != 0) {
					NodeGatewayDown(g, e, now);
					event = NODE_GATEWAY_CLOSED;
				}
				e->Session = false;
			} else {
				// Its session came up, or a table holds it again: it is up with its session
				if (e->Session == false) {
					e->Session = true;
					e->LastAnswer = now;
					e->NextProbe = now;
					if (ReadAcquire(&e->Up) == 0) {
						if (e->DownSince != 0)
							event = NODE_GATEWAY_BACK;
						NodeGatewayUp(g, e);
					}
				}

				// The answers stopped: down after NODE_GATEWAY_DEAD ms, and a gap in the answers starts the count of the ones
				// in a row again
				if (now - e->LastAnswer > NODE_GATEWAY_DEAD) {
					if (ReadAcquire(&e->Up) != 0) {
						NodeGatewayDown(g, e, now);
						event = NODE_GATEWAY_SILENT;
					}
					e->Rise = 0;
				}

				if (now >= e->NextProbe && num_due < NODE_GATEWAY_BATCH) {
					e->Sequence++;
					e->NextProbe = now + NODE_GATEWAY_PROBE;
					due[num_due] = e;
					sequences[num_due++] = e->Sequence;
				}
			}

			if (event != INFINITE && num_events < NODE_GATEWAY_BATCH) {
				StrCpy(names[num_events], sizeof(names[num_events]), e->Name);
				events[num_events++] = event;
			}
		}
	}
	Unlock(g->Lock);

	// Only this thread forgets a gateway, so the ones due stay valid without the lock
	for (UINT i = 0; i < num_due; i++) {
		UCHAR buf[NODE_GATEWAY_PROBE_SIZE];

		NodeGatewayWriteProbe(buf, NODE_GATEWAY_PROBE_ASK, sequences[i], now);
		if (NodeOverlaySendControl(n, due[i]->Peer, buf, sizeof(buf)))
			InterlockedIncrement64(&g->Probes);
	}

	for (UINT i = 0; i < num_events; i++) {
		if (events[i] == NODE_GATEWAY_CLOSED)
			NodeLog(n, "Gateway HA: the gateway %s is down: its Noise session closed, so its groups move its traffic to their next gateway", names[i]);
		else if (events[i] == NODE_GATEWAY_SILENT)
			NodeLog(n, "Gateway HA: the gateway %s is down: it answered no probe for %u ms, so its groups move its traffic to their next gateway", names[i], (UINT)NODE_GATEWAY_DEAD);
		else
			NodeLog(n, "Gateway HA: the gateway %s is up again: its Noise session came up", names[i]);
	}
}

// A control record of the Noise session of the peer: a probe, which the node answers at once on the same session, or the
// answer to a probe of the node, which keeps the gateway up while it comes in time and brings one that went down without its
// session up again after NODE_GATEWAY_RISE answers in a row. A record that is neither is no control record that the node
// knows, and it is left alone. On the thread of the overlay.
void NodeGatewayControl(NODE *n, void *peer, const UCHAR *data, UINT size) {
	NODE_GATEWAY *g = (n != NULL ? n->Gateway : NULL);
	NODE_GATEWAY_PROBE_MSG m;
	char name[CONTROL_NAME_SIZE];
	bool rose = false;

	if (g == NULL || peer == NULL || NodeGatewayParseProbe(data, size, &m) == false)
		return;

	if (m.Kind == NODE_GATEWAY_PROBE_ASK) {
		UCHAR buf[NODE_GATEWAY_PROBE_SIZE];

		NodeGatewayWriteProbe(buf, NODE_GATEWAY_PROBE_ANSWER, m.Sequence, m.Time);
		if (NodeOverlaySendControl(n, peer, buf, sizeof(buf)))
			InterlockedIncrement64(&g->Answered);
		return;
	}

	UINT64 now = GetTickCount64();

	Lock(g->Lock);
	{
		NODE_GATEWAY_PEER *e = NodeGatewayFind(g, peer);

		// Only the answer to a probe of the last NODE_GATEWAY_DEAD ms counts: a late one tells nothing of the gateway now
		if (e != NULL && e->Refs != 0 && m.Sequence <= e->Sequence && m.Time <= now && now - m.Time <= NODE_GATEWAY_DEAD) {
			InterlockedIncrement64(&g->Answers);
			e->LastAnswer = now;
			if (ReadAcquire(&e->Up) == 0 && e->Session && ++e->Rise >= NODE_GATEWAY_RISE) {
				NodeGatewayUp(g, e);
				StrCpy(name, sizeof(name), e->Name);
				rose = true;
			}
		}
	}
	Unlock(g->Lock);

	if (rose)
		NodeLog(n, "Gateway HA: the gateway %s is up again: it answered %u probes in a row", name, (UINT)NODE_GATEWAY_RISE);
}

// The overlay frees the peer (NodeOverlayReap): what the node knows of it goes with it. No group table holds it any more then:
// the overlay frees a peer only once no forwarding table leads to it.
void NodeGatewayForget(NODE *n, void *peer) {
	NODE_GATEWAY *g = (n != NULL ? n->Gateway : NULL);
	NODE_GATEWAY_PEER *e;

	if (g == NULL || peer == NULL)
		return;

	Lock(g->Lock);
	{
		e = NodeGatewayFind(g, peer);
		if (e != NULL)
			Delete(g->Peers, e);
	}
	Unlock(g->Lock);

	Free(e);
}

//
// The state
//

// The gateways of the overlay of a node, and the packets that it sent on as a hub
void NodeGatewayGetStatus(NODE *n, NODE_GATEWAY_STATUS *st) {
	NODE_GATEWAY *g = (n != NULL ? n->Gateway : NULL);

	if (st == NULL)
		return;

	Zero(st, sizeof(NODE_GATEWAY_STATUS));
	if (g == NULL)
		return;

	Lock(g->Lock);
	for (UINT i = 0; i < LIST_NUM(g->Peers); i++) {
		NODE_GATEWAY_PEER *e = LIST_DATA(g->Peers, i);

		if (e->Refs == 0)
			continue;
		st->NumProbed++;
		if (ReadAcquire(&e->Up) != 0)
			st->NumUp++;
	}
	Unlock(g->Lock);

	st->Probes = (UINT64)ReadAcquire64(&g->Probes);
	st->Answers = (UINT64)ReadAcquire64(&g->Answers);
	st->Answered = (UINT64)ReadAcquire64(&g->Answered);
	st->Failovers = (UINT64)ReadAcquire64(&g->Failovers);
	st->Recoveries = (UINT64)ReadAcquire64(&g->Recoveries);
	st->Transit = (UINT64)ReadAcquire64(&g->Transit);
}

// What the overlay of a node knows of the gateway of the name: false when it is the gateway of no group of any tables. Of two
// peers of the name, the one that a table holds counts.
bool NodeGatewayGetPeer(NODE *n, const char *name, NODE_GATEWAY_PEER_STATUS *st) {
	NODE_GATEWAY *g = (n != NULL ? n->Gateway : NULL);
	bool found = false;

	if (st == NULL)
		return false;

	Zero(st, sizeof(NODE_GATEWAY_PEER_STATUS));
	if (g == NULL || name == NULL)
		return false;

	Lock(g->Lock);
	for (UINT i = 0; i < LIST_NUM(g->Peers); i++) {
		NODE_GATEWAY_PEER *e = LIST_DATA(g->Peers, i);

		if (StrCmp(e->Name, name) != 0 || (found && e->Refs == 0))
			continue;

		found = true;
		st->Probed = (e->Refs != 0);
		st->Up = (ReadAcquire(&e->Up) != 0);
		st->LastAnswer = e->LastAnswer;
		st->DownSince = e->DownSince;
		st->Failovers = e->Failovers;
		st->Picked = (UINT64)ReadAcquire64(&e->Picked);
	}
	Unlock(g->Lock);

	return found;
}
