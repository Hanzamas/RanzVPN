// NodeOverlay.c
// The overlay of a node (SDN-3, #179): the node's end of the control stream to the controller (Core/Control.h),
// the addresses and the peers of the desired state that it applies, and a Noise session to each peer over a data
// transport, which carries the IP packets of the host. Each Generation that it applies becomes the forwarding tables
// of the node's VRFs (NodeVrf.c; SDN-4, #180), built beside the live ones and swapped in (NodeSwapVrfs): in each VRF a
// host route to each address of the node, which leads to the host, and to each address of a peer, which leads to that
// peer. A packet of the host in a VRF (NodeOverlayInput) goes, when its source is an address of the node, to the peer
// that the table of the VRF routes its destination to; a data record carries the VRF id before the packet
// (NODE_OVERLAY_VRF_TAG). A packet of a peer goes to the host (NODE_ADAPTER_PROC) when the table of its VRF routes its
// source to that peer and its destination to the host. So two VRFs may use the same range, and no packet crosses from
// one into the other. The rules of each VRF, which the controller compiles from the intent, judge each flow at both
// ends, default deny (NodePolicy.c; SDN-8, #184). With no controller reachable, the overlay keeps
// the state it applied last and forwards on it (ADR-0027 decision 6). An overlay without a control stream takes its
// states from NodeOverlayApply, as the vpntest harness gives them. The Mirrors of a Generation go in with its tables,
// and copy the packets that the overlay sends to a peer and delivers to the host to a sensor (NodeMirror.c; SDN-23,
// #199).
//
// The host is a fake adapter in the vpntest harness, until one Wintun adapter per VRF comes with SDN-5 (#181). The
// data transport finds a peer by its node name, as the in-process loopback transport of the harness does, until the
// QUIC transport (CORE-S1-1, #67) carries the sessions on the paths of the peer module. Of two peers, the one with the
// lower static key dials and the other accepts; the static key of the handshake is a peer's identity, so a session
// has no Login. The endpoints of a Peer object (SDN-93, #410) are where a data transport that dials through them reaches the
// peer: such a node dials only a peer that has some, and a node that has none of its own always dials (NodeEndpoints.c). A pair
// that cannot dial each other, as neither has an endpoint, and a pair whose dial failed carry their records on the datagram
// path of the peer agent, through a Relay, in place of a session (NodeAgent.c; CORE-S5-5, #411). One
// thread of the overlay accepts, dials and reads the sessions, and a pool runs the handshakes of the streams that it accepts
// (NodeHandshake.c; AUD1-DT-1, #449); the thread alone closes the sessions, and a sender
// counts itself on the peer while it sends, so a session is never closed under a send. The forwarding reads the
// tables without a lock, as a reader of the table snapshot, so a peer that a Generation drops goes only once no
// table leads to it any more.

#include "Node.h"

#include "Mayaqua/Memory.h"
#include "Mayaqua/Object.h"
#include "Mayaqua/Str.h"

#include "Core/Control.h"

#include "NodeAgent.h"
#include "NodeCaps.h"
#include "NodeEgress.h"
#include "NodeEvpn.h"
#include "NodeExit.h"
#include "NodeGateway.h"
#include "NodeInternal.h"
#include "NodeLink.h"
#include "NodePeering.h"
#include "NodeProfile.h"

// One peer of the overlay, from a Peer object of the desired state: a next hop of the forwarding tables
typedef struct NODE_OVERLAY_PEER {
	char Name[PEER_NAME_SIZE];          // Its node name: its address on the data transport
	UCHAR Key[PEER_KEY_SIZE];           // Its static key
	TRANSPORT_NOISE *volatile Session;  // The Noise session to it, NULL while there is none
	volatile LONG Senders;              // Calls of NodeOverlayInput that send on Session now
	UINT64 NextDial;                    // When the node dials it next
	bool Gone;                          // The desired state dropped it and no table leads to it: the thread closes its session and frees it
	UINT64 Since;                       // When Session came up, for the state of the node (SDN-91, #396) ...
	TRANSPORT *Transport;               // ... and the transport that it runs over
	char Source[NODE_FLAP_SOURCE_SIZE]; // The address that Session came from, "" when the transport told none (NodeFlap.c; AUD1-DT-11, #459)

	// The endpoints that its Peer object lists (SDN-93, #410), which the node dials it at, in the order of the race
	UINT NumEndpoints;
	CONTROL_ENDPOINT Endpoints[CONTROL_MAX_ENDPOINTS];
} NODE_OVERLAY_PEER;

// The overlay of a node
struct NODE_OVERLAY {
	NODE *Node;                                 // The node
	NODE_OVERLAY_CONFIG Config;                 // How it runs
	CONTROL_CLIENT *Control;                    // The control stream, NULL without one
	LOCK *Lock;                                 // Name, Generation, Addresses, NumVrfs and Peers
	char Name[PEER_NAME_SIZE];                  // The node's name in the desired state, empty before the first
	UINT64 Generation;                          // The Generation that the overlay runs: its forwarding tables are in
	UINT NumAddresses;                          // The node's IPv4 addresses
	UINT Addresses[NODE_OVERLAY_MAX_ADDRESSES]; // ... in network byte order
	UINT VrfIds[NODE_OVERLAY_MAX_ADDRESSES];    // ... and the VRF of each
	UINT NumVrfs;                               // The VRFs of its forwarding tables
	LIST *Peers;                                // The peers (NODE_OVERLAY_PEER)
	TRANSPORT_LISTENER *Listener;               // Listens on the data transport at Name; the thread's
	HANDLE Thread;                              // The thread of the overlay
	NODE_READER Reader;                         // The thread as a reader of the forwarding tables, online while it delivers
	volatile bool Halt;                         // Ends the thread
	UCHAR *Buf;                                 // The record that the thread reads
	UCHAR *NatBuf;                              // Its packet as the host sees it, when a 1:1 NAT rule translates it (NodeNat.c)
	volatile LONG64 Forwarded;                  // Packets of the host sent to a peer
	volatile LONG64 Delivered;                  // Packets of the peers delivered to the host
	volatile LONG64 Dropped;                    // Packets that the overlay dropped

	// The number of the endpoints of the node itself (SDN-93, #410), under Lock: a node that has none is dialled by no peer
	UINT NumEndpoints;
	// The dials that the overlay started
	volatile LONG64 Dials;
	// The pool that runs the handshakes of the streams that the thread accepts (NodeHandshake.c; AUD1-DT-1, #449)
	NODE_HANDSHAKES *Handshakes;
	// The events of the node that wait for the controller, and the count of the replacements of the session of each peer,
	// which raises one when two holders of a key replace it again and again (NodeFlap.c; AUD1-DT-11, #459)
	CONTROL_EVENTS *Events;
	NODE_FLAP *Flap;
	// The applies of the states and the forwarding tables that the BGP peering builds anew, one at a time (NodePeering.c;
	// SDN-77, #357): a rebuild only tries it, so the worker of the peering never waits for an apply (SDN-77-R1, #531)
	SRWLOCK ApplyLock;
};

// The IPv4 addresses of a CONTROL_ADDRESS list, in network byte order, and the VRF of each; the forwarding tables take
// the IPv6 ones as well
static UINT NodeOverlayIpv4(UINT *dst, UINT *vrfs, const CONTROL_ADDRESS *src, UINT num) {
	UINT ret = 0;

	for (UINT i = 0; i < num && ret < NODE_OVERLAY_MAX_ADDRESSES; i++) {
		if (src[i].AddressSize == 4) {
			vrfs[ret] = src[i].VrfId;
			Copy(&dst[ret++], src[i].Address, 4);
		}
	}

	return ret;
}

// The source and the destination of an IP packet, 4 bytes each for IPv4 and 16 for IPv6, and their size; false for
// anything else
static bool NodeOverlayEnds(const UCHAR *packet, UINT size, UCHAR *src, UCHAR *dst, UINT *addr_size) {
	if (packet == NULL || size < 20)
		return false;

	switch (packet[0] >> 4) {
	case 4:
		if ((packet[0] & 0x0F) < 5)
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

// The peer of name and key that the desired state still holds, NULL for none. The caller holds the lock.
static NODE_OVERLAY_PEER *NodeOverlayPeer(NODE_OVERLAY *ov, const char *name, const UCHAR *key) {
	for (UINT i = 0; i < LIST_NUM(ov->Peers); i++) {
		NODE_OVERLAY_PEER *p = LIST_DATA(ov->Peers, i);

		if (p->Gone == false && (name == NULL || StrCmp(p->Name, name) == 0) && Cmp(p->Key, key, PEER_KEY_SIZE) == 0)
			return p;
	}

	return NULL;
}

// The host route of an address of a state, which leads to next_hop; false for an address that is neither IPv4 nor
// IPv6
static bool NodeOverlayRoute(NODE_VRF_ROUTE *r, const CONTROL_ADDRESS *a, UINT next_hop) {
	if (a->AddressSize != 4 && a->AddressSize != 16)
		return false;

	Zero(r, sizeof(NODE_VRF_ROUTE));
	r->VrfId = a->VrfId;
	Copy(r->Address, a->Address, a->AddressSize);
	r->AddressSize = a->AddressSize;
	r->Length = a->AddressSize * 8;
	r->NextHop = next_hop;

	return true;
}

// The forwarding tables of a state: in each VRF a host route to each address of the node, which leads to the host,
// and to each address of a peer, which leads to that peer; next hop i is hops[i], the peer of st->Peers[i]. NULL when
// they cannot be built.
static NODE_VRF_TABLES *NodeOverlayTables(const CONTROL_STATE *st, NODE_OVERLAY_PEER **hops) {
	UINT max_routes = st->NumAddresses, num = 0;

	for (UINT i = 0; i < st->NumPeers; i++)
		max_routes += st->Peers[i].NumAddresses;

	// 1:1 NAT (NodeNat.c; SDN-6, #182): the outside prefixes of the node's rules lead to the host, the routes of a peer to it
	max_routes += NodeNatRoutes(st, NULL);
	// Route leaking (NodeLeak.c; SDN-7, #183): the routes that the VRFs of the peers leak into the node's VRFs
	max_routes += NodeLeakRoutes(st, NULL);
	// The WireGuard Devices (NodeWireGuard.c; SDN-80, #375): the addresses of each lead to its gateway
	max_routes += NodeDeviceRoutes(st, NULL);
	// Gateway HA (NodeGateway.c; SDN-19, #195): the LAN subnets behind the node lead to its host
	max_routes += NodeGatewayRoutes(st, NULL);
	// The internet exits (NodeEgress.c; SDN-12, #188): the default route of each VRF whose exit the node is leads to its host
	max_routes += NodeEgressRoutes(st, NULL);

	NODE_VRF_ROUTE *routes = ZeroMalloc(sizeof(NODE_VRF_ROUTE) * MAX(max_routes, 1));

	for (UINT i = 0; i < st->NumAddresses; i++)
		if (NodeOverlayRoute(&routes[num], &st->Addresses[i], NODE_VRF_LOCAL))
			num++;

	for (UINT i = 0; i < st->NumPeers; i++)
		for (UINT j = 0; j < st->Peers[i].NumAddresses; j++)
			if (NodeOverlayRoute(&routes[num], &st->Peers[i].Addresses[j], i))
				num++;

	num += NodeNatRoutes(st, routes + num);
	num += NodeLeakRoutes(st, routes + num);
	num += NodeDeviceRoutes(st, routes + num);
	num += NodeGatewayRoutes(st, routes + num);
	num += NodeEgressRoutes(st, routes + num);
	// ... and a prefix that several peers announce leads to the next hop of their group of gateways
	NodeGatewayGroupRoutes(st, routes, num);

	NODE_VRF_TABLES *v = NodeLeakNewTables(st, routes, num, (void **)hops);
	Free(routes);

	// The rules of the Generation, installed with its tables
	if (v != NULL)
		v->Nat = NodeNewNat(st);

	return v;
}

// The forwarding tables of the state st with what goes in with them, built beside the live ones and swapped in; next hop i
// is hops[i], the peer of st->Peers[i]. exits are the exit nodes of the state of a client (NodeExitFilter), NULL for none.
// Whether they went in, and the number of their VRFs into num_vrfs.
static bool NodeOverlaySwapTables(NODE_OVERLAY *ov, const CONTROL_STATE *st, const NODE_EXIT_STATE *exits, NODE_OVERLAY_PEER **hops, UINT *num_vrfs) {
	// Built beside the live tables, then in their place: the swap returns once no reader holds the tables before
	NODE_VRF_TABLES *v = NodeOverlayTables(st, hops);
	// The rules of the policy of the VRFs of the Generation go in with its tables (NodePolicy.c)
	NodePolicyAttach(ov->Node, v, st);
	// The MTU and the rate limits of the Generation go in with its tables (NodeShape.c)
	NodeShapeAttach(ov->Node, v, st);
	// The Mirrors of the Generation go in with its tables (NodeMirror.c)
	NodeMirrorAttach(ov->Node, v, st);
	// The links of kind vxlan and geneve of the Generation go in with its tables (NodeLink.c; SDN-76, #356)
	NodeLinkAttach(ov->Node, v, st);
	// The groups of gateways and the hubs of the Generation go in with its tables (NodeGateway.c; SDN-19, #195)
	NodeGatewayAttach(ov->Node, v, st);
	// The session profiles of the peers and of the node go in with its tables (NodeProfile.c; SDN-40, #233)
	NodeProfileAttach(ov->Node, v, st);
	// The VRFs whose internet exit the node is go in with its tables (NodeEgress.c; SDN-12, #188)
	NodeEgressAttach(ov->Node, v, st);
	// The exit nodes of the Generation go in with its tables (NodeExit.c; SDN-55, #248)
	NodeExitAttach(ov->Config.Exit, v, exits);
	*num_vrfs = (v != NULL ? v->NumVrfs : 0);
	bool swapped = (v != NULL && NodeSwapVrfs(ov->Node, v));
	NodePolicyApplied(ov->Node, swapped);
	NodeLinkApplied(ov->Node, swapped);
	if (v != NULL && swapped == false)
		NodeFreeVrfTables(v);

	return swapped;
}

// The state that the control stream applied: the node's name and addresses, its peers, and the forwarding tables of
// its VRFs, built beside the live ones and swapped in. A peer that stays keeps its session; one that the state drops
// goes only once the new tables are in, when no reader can find it any more. The relay role gets the peers too
// (NodeSetPeers). It runs on the thread of the control stream, or on the caller's of NodeOverlayApply.
static void NodeOverlayState(void *param, const CONTROL_STATE *state) {
	NODE_OVERLAY *ov = (NODE_OVERLAY *)param;
	// One state or rebuild of the forwarding tables at a time, and the routes that the BGP peering learned go in with the state
	// (NodePeering.c; SDN-77, #357)
	AcquireSRWLockExclusive(&ov->ApplyLock);
	const CONTROL_STATE *with = NodePeeringWith(ov->Node, state);
	// A client takes the default route of a peer only from the exit node that its user chose: the state without them (NodeExit.c;
	// SDN-55, #248)
	const CONTROL_STATE *st = with;
	NODE_EXIT_STATE *exits = NodeExitFilter(ov->Config.Exit, &st);
	PEER_INFO *infos = ZeroMalloc(sizeof(PEER_INFO) * MAX(st->NumPeers, 1));
	NODE_OVERLAY_PEER **hops = ZeroMalloc(sizeof(NODE_OVERLAY_PEER *) * MAX(st->NumPeers, 1));
	LIST *dropped = NewListFast(NULL);

	// The TLS fingerprints of the certificate of the Controller that the state names, accepted before anything else of the
	// state is applied and before the control stream acknowledges it (NodeController.c; SDN-92, #397)
	NodeControllerPins(ov->Node, st);

	Lock(ov->Lock);
	{
		if (IsEmptyStr(ov->Name))
			StrCpy(ov->Name, sizeof(ov->Name), st->Name);
		// Whether a peer can dial the node is the endpoints that it has (SDN-93, #410)
		ov->NumEndpoints = st->NumEndpoints;

		for (UINT i = 0; i < LIST_NUM(ov->Peers); i++) {
			NODE_OVERLAY_PEER *p = LIST_DATA(ov->Peers, i);
			bool stays = false;

			for (UINT j = 0; j < st->NumPeers && stays == false && p->Gone == false; j++) {
				const CONTROL_PEER *cp = &st->Peers[j];

				if (StrCmp(p->Name, cp->Name) == 0 && Cmp(p->Key, cp->Key, PEER_KEY_SIZE) == 0)
					stays = true;
			}
			if (stays == false && p->Gone == false)
				Add(dropped, p);
		}

		// Next hop i of the tables is the peer of st->Peers[i]
		for (UINT i = 0; i < st->NumPeers; i++) {
			const CONTROL_PEER *cp = &st->Peers[i];
			NODE_OVERLAY_PEER *p = NodeOverlayPeer(ov, cp->Name, cp->Key);

			if (p == NULL) {
				p = ZeroMalloc(sizeof(NODE_OVERLAY_PEER));

				StrCpy(p->Name, sizeof(p->Name), cp->Name);
				Copy(p->Key, cp->Key, PEER_KEY_SIZE);
				Add(ov->Peers, p);
			}
			hops[i] = p;
			// The endpoints that the node dials the peer at: a change of them reaches the next dial (SDN-93, #410)
			p->NumEndpoints = cp->NumEndpoints;
			Copy(p->Endpoints, cp->Endpoints, sizeof(CONTROL_ENDPOINT) * cp->NumEndpoints);
		}
	}
	Unlock(ov->Lock);

	// The forwarding tables of the Generation, and what goes in with them
	UINT num_vrfs = 0;
	bool swapped = NodeOverlaySwapTables(ov, st, exits, hops, &num_vrfs);

	// The host's adapter of each VRF takes the MTU of the Generation that went in, before the overlay reports it
	if (swapped)
		NodeShapeApplied(ov->Node, st);
	// The DHCP responders of the L2 Networks of the Generation (NodeDhcp.c; SDN-43, #236)
	if (swapped)
		NodeDhcpApplied(ov->Node, st);
	// Where the node listens: the Listener of the Generation (NodeListener.c; SDN-45, #238)
	if (swapped)
		NodeListenerApplied(ov->Node, st);

	Lock(ov->Lock);
	{
		if (swapped) {
			ov->Generation = st->Generation;
			ov->NumAddresses = NodeOverlayIpv4(ov->Addresses, ov->VrfIds, st->Addresses, st->NumAddresses);
			ov->NumVrfs = num_vrfs;

			// No table leads to the dropped peers any more: the thread closes their sessions and frees them
			for (UINT i = 0; i < LIST_NUM(dropped); i++)
				((NODE_OVERLAY_PEER *)LIST_DATA(dropped, i))->Gone = true;
		}
	}
	Unlock(ov->Lock);

	ReleaseList(dropped);
	Free(hops);

	for (UINT i = 0; i < st->NumPeers; i++) {
		StrCpy(infos[i].Name, sizeof(infos[i].Name), st->Peers[i].Name);
		Copy(infos[i].Key, st->Peers[i].Key, PEER_KEY_SIZE);
		infos[i].NumVrfs = MIN(st->Peers[i].NumVrfs, PEER_MAX_VRFS);
		Copy(infos[i].VrfIds, st->Peers[i].VrfIds, sizeof(UINT) * infos[i].NumVrfs);
	}
	NodeSetPeers(ov->Node, infos, st->NumPeers);
	Free(infos);
	// The peer agent takes the peers and the Relays: the datagram path of the pairs that cannot dial each other (NodeAgent.c;
	// CORE-S5-5, #411)
	NodeAgentApply(ov->Node, st);

	if (swapped)
		NodeLog(ov->Node, "Overlay: generation %I64u applied: node %s, %u addresses, %u peers, the forwarding tables of %u VRFs", st->Generation, st->Name, st->NumAddresses, st->NumPeers, num_vrfs);
	else
		NodeLog(ov->Node, "Overlay: generation %I64u not applied: its forwarding tables could not be built or installed, so the node forwards on the tables before", st->Generation);

	// The adapter of the host takes the state too: the addresses and routes of the client role (CORE-S3-1)
	if (swapped && ov->Config.State != NULL)
		ov->Config.State(ov->Node, ov->Config.AdapterParam, st);
	// The WireGuard interface of a gateway, after the adapters of its VRFs (NodeWireGuard.c; SDN-80, #375)
	if (swapped)
		NodeWireGuardApplied(ov->Node, st);
	// The proxy of the internet exit listens on the addresses of the adapters of its VRFs (NodeEgress.c; SDN-12, #188)
	if (swapped)
		NodeEgressApplied(ov->Node, st);
	// The sidecar of the BGP peering takes the Generation that went in (NodePeering.c; SDN-77, #357)
	NodePeeringApplied(ov->Node, state, swapped);
	NodeExitFreeState(exits);
	NodePeeringDone(with, state);
	ReleaseSRWLockExclusive(&ov->ApplyLock);
}

// Build the forwarding tables of the state with anew and swap them in, as the BGP peering does when the routes that its sidecar
// learned change (NodePeering.c; SDN-77, #357): with is the Generation in force, with those routes among the routes of its peers,
// and the adapters of the host take it too. It never waits for an apply that runs: NODE_REBUILD_BUSY then, and NODE_REBUILD_STALE
// when another Generation went in meanwhile, whose apply took the routes of its own time and woke the peering, so that it builds
// the tables anew with that one (SDN-77-R1, #531). NODE_REBUILD_FAILED when the tables could not be built or installed.
UINT NodeOverlayRebuild(NODE *n, const CONTROL_STATE *with) {
	NODE_OVERLAY *ov = (n != NULL ? n->Overlay : NULL);
	UINT ret = NODE_REBUILD_FAILED;

	if (ov == NULL || with == NULL)
		return NODE_REBUILD_FAILED;

	if (TryAcquireSRWLockExclusive(&ov->ApplyLock) == FALSE)
		return NODE_REBUILD_BUSY;
	{
		// The tables of a client take the default route of a peer only from the exit node that its user chose here too (NodeExit.c;
		// SDN-55, #248)
		const CONTROL_STATE *st = with;
		NODE_EXIT_STATE *exits = NodeExitFilter(ov->Config.Exit, &st);
		NODE_OVERLAY_PEER **hops = ZeroMalloc(sizeof(NODE_OVERLAY_PEER *) * MAX(st->NumPeers, 1));
		bool current = false;
		bool found = true;
		UINT num_vrfs = 0;

		// Next hop i of the tables is the peer of st->Peers[i], which the Generation in force holds
		Lock(ov->Lock);
		{
			current = (ov->Generation == st->Generation);
			for (UINT i = 0; i < st->NumPeers && current && found; i++) {
				hops[i] = NodeOverlayPeer(ov, st->Peers[i].Name, st->Peers[i].Key);
				found = (hops[i] != NULL);
			}
		}
		Unlock(ov->Lock);

		if (current == false)
			ret = NODE_REBUILD_STALE;
		else if (found && NodeOverlaySwapTables(ov, st, exits, hops, &num_vrfs))
			ret = NODE_REBUILD_DONE;
		Free(hops);

		// The host's adapter of each VRF takes the routes too
		if (ret == NODE_REBUILD_DONE && ov->Config.State != NULL)
			ov->Config.State(ov->Node, ov->Config.AdapterParam, st);
		NodeExitFreeState(exits);
	}
	ReleaseSRWLockExclusive(&ov->ApplyLock);

	return ret;
}

//
// The sessions
//

// The configuration of a session with the node's static key; remote is the peer's key when the node dials
static void NodeOverlaySessionConfig(NODE_OVERLAY *ov, NOISE_SESSION_CONFIG *c, const UCHAR *remote) {
	Zero(c, sizeof(NOISE_SESSION_CONFIG));
	c->Suite = NOISE_SUITE_IK;
	if (ov->Config.Key->Identity != NULL)
		c->Identity = ov->Config.Key->Identity;
	else
		c->StaticKey = ov->Config.Key->Private;
	c->RemoteStatic = remote;
}

// Close the session of p, once no send runs on it any more. Only the thread of the overlay closes sessions.
static void NodeOverlayClose(NODE_OVERLAY *ov, NODE_OVERLAY_PEER *p) {
	TRANSPORT_NOISE *s;

	// The exchange is a full barrier, as the count of a sender is: either the sender reads no session, or the wait
	// below sees it counted and waits for its send
	Lock(ov->Lock);
	{
		s = InterlockedExchangePointer((PVOID volatile *)&p->Session, NULL);
		p->NextDial = GetTickCount64();
	}
	Unlock(ov->Lock);

	if (s == NULL)
		return;

	// The session counts towards the most sessions of the User of the peer no more (NodeProfile.c; SDN-40, #233)
	NodeProfileDown(ov->Node, p->Name, p->Key);

	while (ReadAcquire(&p->Senders) != 0)
		Sleep(1);

	TransportNoiseClose(s);
	Free(s);
	NodeLog(ov->Node, "Overlay: the session to %s closed", p->Name);
}

// Give the open session s to the peer of key, which has none: false when the desired state holds no such peer, and s
// is closed
static bool NodeOverlayAttach(NODE_OVERLAY *ov, const UCHAR *key, TRANSPORT_NOISE *s) {
	char name[PEER_NAME_SIZE];
	bool ok = false;

	Lock(ov->Lock);
	{
		NODE_OVERLAY_PEER *p = NodeOverlayPeer(ov, NULL, key);

		// The session profile of the peer refuses the session of one device more of its User (NodeProfile.c; SDN-40, #233)
		if (p != NULL && p->Session == NULL && NodeProfileUp(ov->Node, p->Name, key)) {
			InterlockedExchangePointer((PVOID volatile *)&p->Session, s);
			StrCpy(name, sizeof(name), p->Name);
			p->Since = GetTickCount64();
			p->Transport = TransportOf(s->Stream);
			// Where it came from, for the count of the replacements of the session (NodeFlap.c; AUD1-DT-11, #459)
			TransportRemote(s->Stream, p->Source, sizeof(p->Source));
			ok = true;
		}
	}
	Unlock(ov->Lock);

	if (ok == false) {
		TransportNoiseClose(s);
		Free(s);
		return false;
	}

	NodeLog(ov->Node, "Overlay: the session to %s is up", name);
	return true;
}

// Listen on the data transport at the node's name once the desired state named it
static bool NodeOverlayListen(NODE_OVERLAY *ov) {
	char name[PEER_NAME_SIZE];

	if (ov->Listener != NULL)
		return false;

	Lock(ov->Lock);
	StrCpy(name, sizeof(name), ov->Name);
	Unlock(ov->Lock);

	if (IsEmptyStr(name))
		return false;

	ov->Listener = TransportListen(ov->Config.Data, name);
	if (ov->Listener != NULL)
		NodeLog(ov->Node, "Overlay: listening on %s of the data transport %s", name, ov->Config.Data->Name);

	return (ov->Listener != NULL);
}

// Close the session that the peer of key has: it dialled again on another path, with the session of incoming. Only the
// thread of the overlay closes. The replacement counts towards the session flap of the peer, with the addresses that the two
// sessions came from (NodeFlap.c; AUD1-DT-11, #459).
static void NodeOverlayReplace(NODE_OVERLAY *ov, const UCHAR *key, TRANSPORT_NOISE *incoming) {
	NODE_OVERLAY_PEER *p;
	char name[PEER_NAME_SIZE];
	char closed[NODE_FLAP_SOURCE_SIZE];

	Lock(ov->Lock);
	{
		p = NodeOverlayPeer(ov, NULL, key);
		if (p != NULL && p->Session == NULL)
			p = NULL;
		if (p != NULL) {
			StrCpy(name, sizeof(name), p->Name);
			StrCpy(closed, sizeof(closed), p->Source);
		}
	}
	Unlock(ov->Lock);

	if (p == NULL)
		return;

	NodeOverlayClose(ov, p);

	char opened[NODE_FLAP_SOURCE_SIZE];

	TransportRemote(incoming->Stream, opened, sizeof(opened));
	NodeFlapReplaced(ov->Flap, name, closed, opened);
}

// Take a stream that a peer dialled: the responder of a session, whose initiator must be a peer of the desired state. Its
// handshake runs in the pool of the handshakes, never on this thread, which reads no stream that has proved no key and
// takes only a session whose handshake finished (NodeHandshake.c; AUD1-DT-1, #449).
static bool NodeOverlayAccept(NODE_OVERLAY *ov) {
	TRANSPORT_STREAM *stream = (ov->Listener != NULL ? TransportAccept(ov->Listener, 0) : NULL);
	// Else a stream that the front door or QUIC of the node's Listener took (NodeListener.c; SDN-45, #238), also when the data
	// transport listens nowhere, as that of the client role and the one of a node without it do (SDN-93, #410)
	if (stream == NULL)
		stream = NodeListenerAccept(ov->Node);
	if (stream != NULL)
		NodeHandshakeSubmit(ov->Handshakes, stream);

	TRANSPORT_NOISE *s = NodeHandshakeTake(ov->Handshakes);
	if (s == NULL)
		return (stream != NULL);

	// The peer's static key names the peer: a session between two peers has no Login. A peer that dials again, after it
	// roamed or woke from sleep, replaces the session that its old path left (CORE-S3-1).
	TransportNoiseAcceptLogin(s);
	NodeOverlayReplace(ov, s->Session.RemoteStatic, s);
	NodeOverlayAttach(ov, s->Session.RemoteStatic, s);

	return true;
}

// Dial the first peer that this node dials and that has no session: the node with the lower static key dials
static bool NodeOverlayDial(NODE_OVERLAY *ov) {
	NOISE_SESSION_CONFIG c;
	char name[PEER_NAME_SIZE];
	UCHAR key[PEER_KEY_SIZE];
	bool found = false;
	UINT64 now = GetTickCount64();

	Lock(ov->Lock);
	{
		for (UINT i = 0; i < LIST_NUM(ov->Peers) && found == false; i++) {
			NODE_OVERLAY_PEER *p = LIST_DATA(ov->Peers, i);

			if (p->Gone || p->Session != NULL || now < p->NextDial)
				continue;
			// A pair that cannot dial each other takes the datagram path of the peer agent (NodeAgent.c; CORE-S5-5, #411)
			if (NodeAgentDatagramOnly(ov->Node, ov->NumEndpoints, p->NumEndpoints))
				continue;

			// A client dials its peers whatever the order of the keys: they cannot dial it (CORE-S3-1). A data transport that
			// dials through endpoints dials a peer that has some, and a node without endpoints always dials (NodeEndpoints.c;
			// SDN-93, #410)
			bool dialable = (ov->Config.Dialable != NULL && ov->Config.Dialable(ov->Node, ov->Config.AdapterParam, p->Name, p->Endpoints, p->NumEndpoints));
			if (NodeEndpointsDials(ov->Config.Dialable == NULL, ov->Config.Dialler, ov->Config.Key->Public, p->Key, ov->NumEndpoints, dialable) == false)
				continue;

			StrCpy(name, sizeof(name), p->Name);
			Copy(key, p->Key, PEER_KEY_SIZE);
			p->NextDial = now + NODE_OVERLAY_REDIAL;
			found = true;
		}
	}
	Unlock(ov->Lock);

	if (found == false)
		return false;

	InterlockedIncrement64(&ov->Dials);
	TRANSPORT_STREAM *stream = TransportDial(ov->Config.Data, name, NULL);
	if (stream == NULL) {
		// The peer agent offers the peer the datagram path, while the node dials it again (NodeAgent.c; CORE-S5-5, #411)
		NodeAgentDialFailed(ov->Node, key);
		return true;
	}

	TRANSPORT_NOISE *s = ZeroMalloc(sizeof(TRANSPORT_NOISE));
	NodeOverlaySessionConfig(ov, &c, key);
	if (TransportNoiseConnect(s, stream, &c, NODE_OVERLAY_HANDSHAKE) == false) {
		Free(s);
		NodeAgentDialFailed(ov->Node, key);
		// The data transport races the next transport of the peer's list at the next dial (CORE-H5-R, #443)
		if (ov->Config.Refused != NULL)
			ov->Config.Refused(ov->Node, ov->Config.AdapterParam, name);
		return true;
	}

	NodeOverlayAttach(ov, key, s);
	return true;
}

// A data record of the peer p: the VRF id, then an IP packet, which goes to the host in that VRF when its table routes
// the source to p and the destination to the host, and on to another peer when the node is the hub of the VRF and its
// table routes the destination there (NodeGatewayTransit); nat_buf takes the packet that a 1:1 NAT rule translates. The
// thread of the overlay, or the receive thread of a link (NodeOverlayLinkDeliver), reads the tables as an online reader.
static void NodeOverlayDeliver(NODE_OVERLAY *ov, NODE_OVERLAY_PEER *p, const UCHAR *record, UINT size, UCHAR *nat_buf) {
	UCHAR src[16], dst[16];
	UINT addr_size = 0;
	bool ok = false;
	UINT vrf_id = (size >= NODE_OVERLAY_VRF_TAG ? READ_UINT(record) : 0);
	const UCHAR *packet = record + NODE_OVERLAY_VRF_TAG;
	UINT packet_size = (size >= NODE_OVERLAY_VRF_TAG ? size - NODE_OVERLAY_VRF_TAG : 0);
	NODE_TABLES *t = NodeGetTables(ov->Node);
	NODE_VRF_TABLES *v = (t != NULL ? t->Vrfs : NULL);
	NODE_VRF_TABLE *vt = NodeGetVrfTable(v, vrf_id);

	if (vt != NULL && NodeOverlayEnds(packet, packet_size, src, dst, &addr_size)) {
		// A source behind a group of gateways comes from the gateway of the group that sent it (NodeGateway.c; SDN-19, #195), and
		// a source of no route from the exit node that the user of a client chose (NodeExit.c; SDN-55, #248)
		UINT from = NodeGatewayFrom(v, NodeExitHop(v, vrf_id, NodeVrfLookup(vt, src, addr_size), src, addr_size, false), p);
		UINT to = NodeVrfLookup(vt, dst, addr_size);

		// A packet of the peer to the fabric of an EVPN gateway: no route of the VRF holds its destination, or only its default
		// route, as in a VRF with an internet exit, and an IP prefix route of the fabric does (NodeEvpn.c; SDN-25, #201;
		// SDN-25-R2, #550)
		if (from < v->NumHops && v->Hops[from] == p && (to == NODE_VRF_NONE || (t->Evpn != NULL && NodeVrfDefault(vt, dst, addr_size))) && NodeEvpnTransit(ov->Node, v, vrf_id, from, packet, packet_size))
			return;

		// The hub of a VRF of topology hub-and-spoke sends the packet of one spoke on to another (NodeGateway.c)
		if (from < v->NumHops && v->Hops[from] == p && to != NODE_VRF_LOCAL && NodeGatewayTransit(ov->Node, v, vrf_id, from, to, record, size))
			return;

		ok = (from < v->NumHops && v->Hops[from] == p && to == NODE_VRF_LOCAL);
		// The session profile of the peer, and the node's own, judge it as the peer sent it (NodeProfile.c; SDN-40, #233)
		ok = ok && NodeProfileInbound(ov->Node, v, vrf_id, from, packet, packet_size);
		// The policy of the VRF judges the packet as the peer sent it, before a 1:1 NAT rule translates it (NodePolicy.c)
		ok = ok && NodePolicyInbound(ov->Node, v, vrf_id, from, packet, packet_size);
	}

	// A Mirror copies the packet as the peer sent it, before a 1:1 NAT rule translates it (NodeMirror.c)
	if (ok)
		NodeMirrorCopy(v, vrf_id, packet, packet_size, false);

	// 1:1 NAT and 4via6 (NodeNat.c; SDN-6, #182): the host takes the packet as it sees it
	ok = ok && NodeNatInbound(v, vrf_id, &packet, &packet_size, nat_buf, NOISE_MAX_PAYLOAD + NODE_NAT_GROWTH);

	if (ok == false || ov->Config.Adapter == NULL) {
		InterlockedIncrement64(&ov->Dropped);
		return;
	}

	InterlockedIncrement64(&ov->Delivered);
	// The internet exit takes a packet to an address outside the VRF, and puts what the host should see of it into the adapter
	// itself (NodeEgress.c; SDN-12, #188)
	if (NodeEgressDeliver(ov->Node, v, vrf_id, packet, packet_size, ov->Config.Adapter, ov->Config.AdapterParam))
		return;
	ov->Config.Adapter(ov->Node, ov->Config.AdapterParam, vrf_id, packet, packet_size);
}

// A data record that a link of kind vxlan or geneve carried from the next hop hop (NodeLink.c; SDN-76, #356), which goes to
// the host as a record of a session does, with nat_buf of NOISE_MAX_PAYLOAD + NODE_NAT_GROWTH bytes for its translation.
// The caller is an online reader of the node's table snapshot, and hop is a next hop of its tables.
void NodeOverlayLinkDeliver(NODE *n, void *hop, const UCHAR *record, UINT size, UCHAR *nat_buf) {
	NODE_OVERLAY *ov = (n != NULL ? n->Overlay : NULL);

	if (ov != NULL)
		NodeOverlayDeliver(ov, (NODE_OVERLAY_PEER *)hop, record, size, nat_buf);
}

// A data record that the datagram path of the peer agent carried from the peer of key (NodeAgent.c; CORE-S5-5, #411), which
// goes to the host as a record of a session does, with nat_buf of NOISE_MAX_PAYLOAD + NODE_NAT_GROWTH bytes for its
// translation. The caller is an online reader of the node's table snapshot: the peer is the next hop of its tables that holds
// key, and the record of a peer that no table leads to is dropped.
void NodeOverlayAgentDeliver(NODE *n, const UCHAR *key, const UCHAR *record, UINT size, UCHAR *nat_buf) {
	NODE_OVERLAY *ov = (n != NULL ? n->Overlay : NULL);
	NODE_TABLES *t = NodeGetTables(n);
	NODE_VRF_TABLES *v = (t != NULL ? t->Vrfs : NULL);

	if (ov == NULL || key == NULL)
		return;
	// A probe of gateway HA or its answer, which the datagram path carries in place of a Noise session (NodeGateway.c;
	// SDN-19-R1, #507)
	if (NodeGatewayDatagram(n, key, record, size))
		return;

	for (UINT i = 0; v != NULL && i < v->NumHops; i++) {
		NODE_OVERLAY_PEER *p = (NODE_OVERLAY_PEER *)v->Hops[i];

		if (p != NULL && Cmp(p->Key, key, PEER_KEY_SIZE) == 0) {
			NodeOverlayDeliver(ov, p, record, size, nat_buf);
			return;
		}
	}

	InterlockedIncrement64(&ov->Dropped);
}

// Read the records of every session: the data records go to the host, keepalives keep the session open, and a session
// that ended or failed is closed
static bool NodeOverlayReceive(NODE_OVERLAY *ov) {
	NODE_OVERLAY_PEER **peers;
	UINT num = 0;
	bool busy = false;

	// The thread alone closes and frees, so the peers and their sessions stay valid without the lock
	Lock(ov->Lock);
	{
		peers = ZeroMalloc(sizeof(NODE_OVERLAY_PEER *) * MAX(LIST_NUM(ov->Peers), 1));
		for (UINT i = 0; i < LIST_NUM(ov->Peers); i++) {
			NODE_OVERLAY_PEER *p = LIST_DATA(ov->Peers, i);

			if (p->Session != NULL)
				peers[num++] = p;
		}
	}
	Unlock(ov->Lock);

	for (UINT i = 0; i < num; i++) {
		NODE_OVERLAY_PEER *p = peers[i];

		for (UINT j = 0; j < NODE_OVERLAY_BATCH; j++) {
			UINT size = 0;
			UINT ret = TransportNoiseReceive(p->Session, ov->Buf, NOISE_MAX_PAYLOAD, &size, 0);

			if (ret == NOISE_RECEIVE_NONE)
				break;

			busy = true;
			if (ret == NOISE_RECEIVE_DATA) {
				NodeOverlayDeliver(ov, p, ov->Buf, size, ov->NatBuf);
			} else if (ret == NOISE_RECEIVE_CONTROL) {
				// A probe of a gateway, or the answer to one (NodeGateway.c; SDN-19, #195)
				NodeGatewayControl(ov->Node, p, ov->Buf, size);
			} else {
				NodeOverlayClose(ov, p);
				break;
			}
		}

		// The session profile of the peer ends a session that idled or that came to its automatic disconnect (NodeProfile.c)
		if (p->Session != NULL && NodeProfileExpired(ov->Node, p->Name, p->Key, p->Since, GetTickCount64()) != NODE_PROFILE_LIVE)
			NodeOverlayClose(ov, p);
	}

	Free(peers);

	return busy;
}

// Free the peers that the desired state dropped, with their sessions
static void NodeOverlayReap(NODE_OVERLAY *ov) {
	while (true) {
		NODE_OVERLAY_PEER *gone = NULL;

		Lock(ov->Lock);
		{
			for (UINT i = 0; i < LIST_NUM(ov->Peers) && gone == NULL; i++) {
				NODE_OVERLAY_PEER *p = LIST_DATA(ov->Peers, i);

				if (p->Gone)
					gone = p;
			}
			if (gone != NULL)
				Delete(ov->Peers, gone);
		}
		Unlock(ov->Lock);

		if (gone == NULL)
			return;

		NodeOverlayClose(ov, gone);
		// What the gateway HA knows of the peer goes with it (NodeGateway.c; SDN-19, #195)
		NodeGatewayForget(ov->Node, gone);
		Free(gone);
	}
}

static DWORD WINAPI NodeOverlayThread(LPVOID param) {
	NODE_OVERLAY *ov = (NODE_OVERLAY *)param;

	// A reader of the forwarding tables, online only while it delivers: a dial or an accept waits for a handshake
	NodeReaderRegister(ov->Node, &ov->Reader);
	NodeReaderOffline(&ov->Reader);

	while (ov->Halt == false) {
		bool busy = NodeOverlayListen(ov);

		if (NodeOverlayAccept(ov))
			busy = true;
		if (NodeOverlayDial(ov))
			busy = true;

		NodeReaderOnline(ov->Node, &ov->Reader);
		if (NodeOverlayReceive(ov))
			busy = true;
		NodeReaderOffline(&ov->Reader);

		NodeOverlayReap(ov);
		// The probes of the gateways that are due, and the gateways that stopped answering them (NodeGateway.c; SDN-19, #195)
		NodeGatewayProbe(ov->Node);

		if (busy == false)
			Sleep(NODE_OVERLAY_IDLE);
	}

	// The end: every session closes and every peer goes
	Lock(ov->Lock);
	for (UINT i = 0; i < LIST_NUM(ov->Peers); i++)
		((NODE_OVERLAY_PEER *)LIST_DATA(ov->Peers, i))->Gone = true;
	Unlock(ov->Lock);
	NodeOverlayReap(ov);

	// The handshakes end before the listeners of their streams, and the sessions that the thread did not take close
	NodeHandshakeStop(ov->Handshakes);

	TransportCloseListener(ov->Listener);
	ov->Listener = NULL;

	NodeReaderUnregister(ov->Node, &ov->Reader);

	return 0;
}

//
// The overlay
//

// Start the overlay of a node: the control stream to the controller, and the thread that runs the sessions to the
// peers of the desired state that it applies. Without a control stream in the configuration, NodeOverlayApply gives
// the states. False when the configuration is not complete, the overlay runs, or the control stream cannot start.
bool NodeOverlayStart(NODE *n, NODE_OVERLAY_CONFIG *cfg) {
	CONTROL_CONFIG cc;
	NOISE_SESSION_CONFIG hc;
	DWORD thread_id = 0;

	if (n == NULL || cfg == NULL || cfg->Data == NULL || cfg->Key == NULL || n->Overlay != NULL)
		return false;

	NODE_OVERLAY *ov = ZeroMalloc(sizeof(NODE_OVERLAY));
	ov->Node = n;
	Copy(&ov->Config, cfg, sizeof(NODE_OVERLAY_CONFIG));
	ov->Lock = NewLock();
	InitializeSRWLock(&ov->ApplyLock);
	ov->Peers = NewListFast(NULL);
	ov->Buf = Malloc(NOISE_MAX_PAYLOAD);
	ov->NatBuf = Malloc(NOISE_MAX_PAYLOAD + NODE_NAT_GROWTH);
	// The pool of the handshakes of the streams that the thread accepts, as their responder (NodeHandshake.c; AUD1-DT-1, #449)
	NodeOverlaySessionConfig(ov, &hc, NULL);
	ov->Handshakes = NodeHandshakeStart(&hc, cfg->MaxHandshakes);
	// The events for the controller, and the count of the replacements of the session of each peer (NodeFlap.c; AUD1-DT-11, #459)
	ov->Events = ControlNewEvents();
	ov->Flap = NodeFlapStart(n, cfg->FlapLimit, cfg->FlapWindow, ov->Events);
	NodeShapeStart(n, cfg);
	NodePolicyStart(n, cfg);
	// The gateway HA, whose gateways the states name (NodeGateway.c; SDN-19, #195)
	NodeGatewayStart(n);
	// The session profiles of the peers and of the node (NodeProfile.c; SDN-40, #233)
	NodeProfileStart(n);
	// The internet exit, whose VRFs the states name (NodeEgress.c; SDN-12, #188)
	NodeEgressStart(n, cfg->EgressTier);
	// The Listener, which listens where a state says (NodeListener.c; SDN-45, #238)
	NodeListenerStart(n, cfg->Key);
	n->Overlay = ov;

	Zero(&cc, sizeof(cc));
	cc.Transport = cfg->Control;
	StrCpy(cc.Address, sizeof(cc.Address), cfg->Controller);
	Copy(cc.ControllerKey, cfg->ControllerKey, PEER_KEY_SIZE);
	// The owner hears how each stream ended (NodeController.c; SDN-90, #395)
	cc.EndProc = cfg->ControlEnd;
	cc.EndParam = cfg->ControlEndParam;
	if (cfg->Key->Identity != NULL)
		cc.Identity = cfg->Key->Identity;
	else
		cc.StaticKey = cfg->Key->Private;
	cc.Proc = NodeOverlayState;
	cc.Param = ov;
	// The leases of the DHCP responders go on the control stream (NodeDhcp.c; SDN-43, #236)
	cc.Leases = NodeDhcpStart(n);
	// The Hello of each stream carries the Capabilities of the host (NodeCaps.c; ONE-3, #312), with WireGuardNT and the key of
	// the WireGuard interface, and the counters of the Devices of a gateway go on the stream (NodeWireGuard.c; SDN-80, #375)
	cc.CapsProc = NodeWireGuardCaps;
	cc.CapsParam = n;
	cc.Devices = NodeWireGuardStart(n, cfg);
	// The events of the node go on the control stream too (ControlEvent.c; AUD1-DT-11, #459)
	cc.Events = ov->Events;
	// The peer agent, the datagram path to the peers that the node reaches on no stream session: its Signals go on the control
	// stream, both ways (NodeAgent.c; CORE-S5-5, #411)
	cc.Signals = NodeAgentStart(n, cfg);
	cc.SignalProc = NodeAgentSignal;
	cc.SignalParam = n;
	// ... and the Upgrades and the Fallbacks of its Paths, which the Controller exports (NodeAgent.c; CORE-S5-6, #412)
	cc.Paths = NodeAgentPaths(n);
	// The counters of the EVPN of a gateway, which the Controller exports too (NodeEvpn.c; SDN-25-R3, #571)
	cc.Evpn = n->EvpnReport;
	// The BGP peering of the standard mode, whose report goes on the control stream (NodePeering.c; SDN-77, #357)
	cc.Peering = NodePeeringStart(n);
	// The live operations of the Controller read and clear the tables of the switches of the L2 Networks, and the Hello reports
	// them (NodeOperation.c; SDN-50-N, #492); a test may tell Capabilities of its own
	NodeOperationStart(n);
	cc.OperationProc = NodeOperationProc;
	cc.OperationParam = n;
	if (cfg->Caps != NULL) {
		cc.CapsProc = cfg->Caps;
		cc.CapsParam = cfg->AdapterParam;
	}

	ov->Thread = (ov->Handshakes != NULL ? CreateThread(NULL, 0, NodeOverlayThread, ov, 0, &thread_id) : NULL);
	ov->Control = (ov->Thread != NULL && cfg->Control != NULL ? ControlStart(&cc) : NULL);
	if (ov->Thread == NULL || (cfg->Control != NULL && ov->Control == NULL)) {
		if (ov->Handshakes == NULL)
			NodeLog(n, "Overlay not started: the pool of the handshakes could not start");
		else
			NodeLog(n, "Overlay not started: the control stream to %s could not start", cfg->Controller);
		NodeOverlayStop(n);
		return false;
	}

	if (cfg->Control == NULL)
		NodeLog(n, "Overlay started without a control stream: the states come from NodeOverlayApply, the peers over %s", cfg->Data->Name);
	else
		NodeLog(n, "Overlay started: the control stream to %s over the transport %s, the peers over %s", cfg->Controller, cfg->Control->Name, cfg->Data->Name);
	return true;
}

// Stop the overlay of a node: the control stream first, which calls into the overlay, then its forwarding tables,
// then the thread, which closes every session. Stop the packets of the host (NodeOverlayInput) before, and never stop
// it from an online reader: the tables go only once no reader holds them, before the peers that they lead to.
void NodeOverlayStop(NODE *n) {
	NODE_OVERLAY *ov = (n != NULL ? n->Overlay : NULL);

	if (ov == NULL)
		return;

	// The BGP peering halts before anything of the overlay stops: its sidecar ends, and it builds no tables any more and calls
	// no adapter (NodePeering.c; SDN-77, #357)
	NodePeeringHalt(n);
	// The packets of the host stop first where the overlay stops them, as for the client role (CORE-S3-1)
	if (ov->Config.AdapterStop != NULL)
		ov->Config.AdapterStop(n, ov->Config.AdapterParam);

	ControlStop(ov->Control);
	// The WireGuard interface goes once the control stream that reported its counters stopped (NodeWireGuard.c)
	NodeWireGuardStop(n);
	NodeSwapVrfs(n, NULL);
	// No table holds a member of the policy any more: its engine goes (NodePolicy.c)
	NodePolicyStop(n);
	NodeShapeStop(n);
	// No table holds a Mirror any more: the VXLAN module of the Mirrors goes (NodeMirror.c)
	NodeMirrorStop(n);
	// No table holds a link any more: the VXLAN module of the links goes, with its receive threads (NodeLink.c)
	NodeLinkStop(n);
	NodeDhcpStop(n);
	// The control stream that handed them the Operations stopped (NodeOperation.c)
	NodeOperationStop(n);
	ov->Halt = true;
	if (ov->Thread != NULL) {
		WaitForSingleObject(ov->Thread, INFINITE);
		CloseHandle(ov->Thread);
	}
	// The peer agent goes once the control stream that carried its Signals and the thread that dialled its peers stopped
	// (NodeAgent.c; CORE-S5-5, #411)
	NodeAgentStop(n);
	// No packet of a peer or of the host reaches the internet exit any more: its proxy goes (NodeEgress.c; SDN-12, #188)
	NodeEgressStop(n);
	// The thread closed every session, the ones over the streams of the Listener too (NodeListener.c; SDN-45, #238)
	NodeListenerStop(n);
	// No table holds a gateway any more, and the thread forgot every peer: the gateway HA goes (NodeGateway.c; SDN-19, #195)
	NodeGatewayStop(n);
	// The thread stopped the pool of the handshakes; a thread that did not start leaves it to stop here
	NodeHandshakeFree(ov->Handshakes);
	// The thread that counted the replacements and the control stream that sent the events are done
	NodeFlapFree(ov->Flap);
	ControlFreeEvents(ov->Events);
	// ... and so is the control stream that sent the report of the BGP peering (NodePeering.c; SDN-77, #357)
	NodePeeringFree(n);
	// No table holds a session profile any more, and the thread that asked about the sessions ended (NodeProfile.c)
	NodeProfileStop(n);

	n->Overlay = NULL;
	ReleaseList(ov->Peers);
	DeleteLock(ov->Lock);
	Free(ov->Buf);
	Free(ov->NatBuf);
	Free(ov);

	NodeLog(n, "Overlay stopped");
}

// Apply a desired state as the control stream does, to an overlay that runs without one (the vpntest harness). False
// when no such overlay runs. From an online reader of the node's table snapshot the forwarding tables stay as they
// are: their swap would wait for that reader.
bool NodeOverlayApply(NODE *n, const CONTROL_STATE *st) {
	NODE_OVERLAY *ov = (n != NULL ? n->Overlay : NULL);

	if (ov == NULL || ov->Control != NULL || st == NULL)
		return false;

	NodeOverlayState(ov, st);
	return true;
}

// A packet of the host in the VRF vrf_id: when its source is an address of the node in that VRF, it goes after the
// VRF id to the peer that the table of the VRF routes its destination to, over its session. False when it went
// nowhere. The caller is an online reader of the node's table snapshot: a worker, the I/O thread of an adapter queue,
// or a thread that registered itself.
static bool NodeOverlayForward(NODE *n, UINT vrf_id, const UCHAR *packet, UINT size, bool fabric) {
	NODE_OVERLAY *ov = (n != NULL ? n->Overlay : NULL);
	UCHAR src[16], dst[16];
	UCHAR buf[NODE_OVERLAY_RECORD];
	UINT addr_size = 0;
	UINT hop = NODE_VRF_NONE;

	if (ov == NULL)
		return false;

	NODE_TABLES *t = NodeGetTables(n);
	NODE_VRF_TABLES *v = (t != NULL ? t->Vrfs : NULL);
	NODE_VRF_TABLE *vt = NodeGetVrfTable(v, vrf_id);

	// 1:1 NAT and 4via6 (NodeNat.c; SDN-6, #182): the tables route the packet as the overlay sees it, and a destination of no
	// route of a packet of the host goes to the exit node that the user of a client chose (NodeExit.c; SDN-55, #248)
	if (vt != NULL && size <= NOISE_MAX_PAYLOAD - NODE_OVERLAY_VRF_TAG && NodeNatEnds(v, vrf_id, packet, size, src, dst, &addr_size) && (fabric || NodeVrfLookup(vt, src, addr_size) == NODE_VRF_LOCAL)) {
		hop = NodeVrfLookup(vt, dst, addr_size);
		if (fabric == false)
			hop = NodeExitHop(v, vrf_id, hop, dst, addr_size, true);
	}
	// A prefix that several gateways announce goes to the gateway that their group picks (NodeGateway.c; SDN-19, #195)
	hop = NodeGatewayPick(v, hop, packet, size);

	// An IP prefix route of the fabric of an EVPN gateway takes a packet of the host to an address of no route, or of the
	// default route of the VRF alone, as in a VRF with an internet exit (NodeEvpn.c; SDN-25, #201; SDN-25-R2, #550)
	bool evpn = (fabric == false && (hop == NODE_VRF_NONE || (t->Evpn != NULL && NodeVrfDefault(vt, dst, addr_size))) && NodeEvpnOutput(n, v, vrf_id, packet, size));

	// Only to a peer: the host's own addresses and the addresses of no route stay here
	if (evpn || vt == NULL || hop >= v->NumHops) {
		InterlockedIncrement64(evpn ? &ov->Forwarded : &ov->Dropped);
		return evpn;
	}

	NODE_OVERLAY_PEER *peer = (NODE_OVERLAY_PEER *)v->Hops[hop];
	UCHAR *record = (size + NODE_OVERLAY_VRF_TAG <= sizeof(buf) ? buf : Malloc(size + NODE_OVERLAY_VRF_TAG));

	// A route that a VRF of the peer leaks takes the packet into that VRF (NodeLeak.c; SDN-7, #183)
	WRITE_UINT(record, NodeLeakVrf(v, hop, vrf_id));
	size = NodeNatCopy(v, vrf_id, record + NODE_OVERLAY_VRF_TAG, packet, size);
	// What the host answers from the proxy of the internet exit goes from the address outside the VRF that the peer reached
	// (NodeEgress.c; SDN-12, #188)
	NodeEgressFromHost(n, v, vrf_id, record + NODE_OVERLAY_VRF_TAG, size);
	// The session profile of the peer and the node's own, then the policy of the VRF, judge the packet as the overlay sees it,
	// after the 1:1 NAT rules (NodeProfile.c; SDN-40, #233; NodePolicy.c; SDN-8, #184)
	bool allowed = NodeProfileOutbound(n, v, vrf_id, hop, record + NODE_OVERLAY_VRF_TAG, size) && NodePolicyOutbound(n, v, vrf_id, hop, record + NODE_OVERLAY_VRF_TAG, size);

	// Counted on the peer before it reads the session, so the thread does not close the session under the send
	InterlockedIncrement(&peer->Senders);
	TRANSPORT_NOISE *s = ReadPointerAcquire((PVOID const volatile *)&peer->Session);
	// A link of kind vxlan or geneve of the VRF of the record carries it in place of the session (NodeLink.c; SDN-76, #356)
	bool plain = (NodeLinkKind(v, hop, READ_UINT(record)) != CONTROL_LINK_NOISE);
	// The datagram path of the peer agent carries it while the peer has no session (NodeAgent.c; CORE-S5-5, #411)
	bool datagram = (allowed && s == NULL && plain == false && NodeAgentHasPath(n, peer->Key));
	// The MTU of the VRF clamps the MSS of a TCP SYN as the overlay sees it, after the 1:1 NAT rules, and the rate limits
	// of the VRF and the node may drop it (NodeShape.c)
	bool ok = (allowed && (s != NULL || plain || datagram) && NodeShapeOutput(n, v, vrf_id, record + NODE_OVERLAY_VRF_TAG, size) && (plain ? NodeLinkSend(v, hop, record, size) : (datagram ? NodeAgentSend(n, peer->Key, record, size + NODE_OVERLAY_VRF_TAG) : TransportNoiseSend(s, NOISE_RECORD_DATA, record, size + NODE_OVERLAY_VRF_TAG))));
	InterlockedDecrement(&peer->Senders);

	// A Mirror copies the packet as it went to the peer (NodeMirror.c)
	if (ok)
		NodeMirrorCopy(v, vrf_id, record + NODE_OVERLAY_VRF_TAG, size, true);

	if (record != buf)
		Free(record);

	InterlockedIncrement64(ok ? &ov->Forwarded : &ov->Dropped);
	return ok;
}

// A packet of the host in the VRF vrf_id (NodeOverlayForward)
bool NodeOverlayInput(NODE *n, UINT vrf_id, const UCHAR *packet, UINT size) {
	return NodeOverlayForward(n, vrf_id, packet, size, false);
}

// A packet that came into the VRF vrf_id from the fabric of an EVPN gateway (NodeEvpn.c; SDN-25, #201), from a source that
// the gateway checked: to the host when the table of the VRF routes its destination to the host, through the 1:1 NAT rules
// as the packet of a peer goes, with nat_buf of NOISE_MAX_PAYLOAD + NODE_NAT_GROWTH bytes for its translation; else on to the
// peer that the table routes it to, as the packet of the host goes (NodeOverlayForward). At the gateway the fabric stands
// where the LAN of a gateway stands: the policy of the VRF judges the packet to a peer as one of the host, and the packet to
// the host not at all. False when it went nowhere. The caller is an online reader of the node's table snapshot; once the
// overlay took its forwarding tables away (NodeOverlayStop), a packet goes nowhere.
bool NodeOverlayFabricInput(NODE *n, UINT vrf_id, const UCHAR *packet, UINT size, UCHAR *nat_buf) {
	NODE_OVERLAY *ov = (n != NULL ? n->Overlay : NULL);
	UCHAR src[16], dst[16];
	UINT addr_size = 0;
	NODE_TABLES *t = NodeGetTables(n);
	NODE_VRF_TABLES *v = (t != NULL ? t->Vrfs : NULL);
	NODE_VRF_TABLE *vt = NodeGetVrfTable(v, vrf_id);

	if (ov == NULL || vt == NULL)
		return false;

	if (NodeOverlayEnds(packet, size, src, dst, &addr_size) == false || NodeVrfLookup(vt, dst, addr_size) != NODE_VRF_LOCAL)
		return NodeOverlayForward(n, vrf_id, packet, size, true);

	bool ok = (ov->Config.Adapter != NULL && NodeNatInbound(v, vrf_id, &packet, &size, nat_buf, NOISE_MAX_PAYLOAD + NODE_NAT_GROWTH));

	InterlockedIncrement64(ok ? &ov->Delivered : &ov->Dropped);
	if (ok)
		ov->Config.Adapter(n, ov->Config.AdapterParam, vrf_id, packet, size);

	return ok;
}

// The state of the overlay of a node
void NodeOverlayGetStatus(NODE *n, NODE_OVERLAY_STATUS *st) {
	CONTROL_STATUS cs;

	if (st == NULL)
		return;

	Zero(st, sizeof(NODE_OVERLAY_STATUS));
	NODE_OVERLAY *ov = (n != NULL ? n->Overlay : NULL);
	if (ov == NULL)
		return;

	ControlGetStatus(ov->Control, &cs);
	st->Connected = cs.Connected;
	st->Since = cs.Since;

	Lock(ov->Lock);
	{
		st->Generation = ov->Generation;
		StrCpy(st->Name, sizeof(st->Name), ov->Name);
		st->NumAddresses = ov->NumAddresses;
		Copy(st->Addresses, ov->Addresses, sizeof(ov->Addresses));
		Copy(st->VrfIds, ov->VrfIds, sizeof(ov->VrfIds));
		st->NumVrfs = ov->NumVrfs;
		for (UINT i = 0; i < LIST_NUM(ov->Peers); i++) {
			NODE_OVERLAY_PEER *p = LIST_DATA(ov->Peers, i);

			if (p->Gone)
				continue;
			st->NumPeers++;
			if (p->Session != NULL)
				st->NumLinks++;
		}
	}
	Unlock(ov->Lock);

	st->Forwarded = (UINT64)ReadAcquire64(&ov->Forwarded);
	st->Delivered = (UINT64)ReadAcquire64(&ov->Delivered);
	st->Dropped = (UINT64)ReadAcquire64(&ov->Dropped);
	st->Dials = (UINT64)ReadAcquire64(&ov->Dials);
	NodeHandshakeGetStatus(ov->Handshakes, st);
	NodeFlapGetStatus(ov->Flap, st);
}

// The events of the node that wait for the controller, at most max of them into list: their number. A node with a control
// stream hands them over as soon as it can, so it holds few; one without a control stream, as in the vpntest harness, holds
// them (AUD1-DT-11, #459).
UINT NodeOverlayGetEvents(NODE *n, CONTROL_EVENT *list, UINT max) {
	NODE_OVERLAY *ov = (n != NULL ? n->Overlay : NULL);

	return (ov != NULL ? ControlGetEvents(ov->Events, list, max) : 0);
}

// The endpoints that the Peer object of the peer name lists, at most max of them into out: their number, 0 for a peer that
// the desired state does not hold and for one that has none (SDN-93, #410). The data transport of the client role asks for
// them when it dials a server, on the thread of the overlay, which holds no lock then.
UINT NodeOverlayEndpoints(NODE *n, const char *name, CONTROL_ENDPOINT *out, UINT max) {
	NODE_OVERLAY *ov = (n != NULL ? n->Overlay : NULL);
	UINT num = 0;

	if (ov == NULL || name == NULL || out == NULL)
		return 0;

	Lock(ov->Lock);
	{
		for (UINT i = 0; i < LIST_NUM(ov->Peers) && num == 0; i++) {
			NODE_OVERLAY_PEER *p = LIST_DATA(ov->Peers, i);

			if (p->Gone == false && StrCmp(p->Name, name) == 0) {
				num = MIN(p->NumEndpoints, max);
				Copy(out, p->Endpoints, sizeof(CONTROL_ENDPOINT) * num);
			}
		}
	}
	Unlock(ov->Lock);

	return num;
}

// The peers of the overlay of a node and their Noise sessions, into list, at most max of them, and into listener the name of
// the data transport that the overlay listens on, "" for none: the number of the peers, which may be more than max (the
// state of a node, NodeState.c; SDN-91, #396)
UINT NodeOverlayGetSessions(NODE *n, NODE_OVERLAY_SESSION *list, UINT max, char *listener, UINT listener_size) {
	UINT num = 0;

	if (listener != NULL)
		StrCpy(listener, listener_size, "");

	NODE_OVERLAY *ov = (n != NULL ? n->Overlay : NULL);
	if (ov == NULL)
		return 0;

	if (listener != NULL && ov->Listener != NULL)
		StrCpy(listener, listener_size, ov->Config.Data->Name);

	Lock(ov->Lock);
	{
		for (UINT i = 0; i < LIST_NUM(ov->Peers); i++) {
			NODE_OVERLAY_PEER *p = LIST_DATA(ov->Peers, i);

			if (p->Gone)
				continue;
			if (list != NULL && num < max) {
				NODE_OVERLAY_SESSION *s = &list[num];

				Zero(s, sizeof(NODE_OVERLAY_SESSION));
				StrCpy(s->Name, sizeof(s->Name), p->Name);
				s->Up = (p->Session != NULL);
				if (s->Up && p->Transport != NULL)
					StrCpy(s->Transport, sizeof(s->Transport), p->Transport->Name);
				s->Since = (s->Up ? p->Since : 0);
			}
			num++;
		}
	}
	Unlock(ov->Lock);

	// How the overlay reaches each peer, and the records of its datagram path (NodeAgent.c; CORE-S5-5, #411)
	NodeAgentSessions(n, list, MIN(num, max));

	return num;
}

// Whether the peer of the overlay, a next hop of the tables, has its Noise session now (NodeGateway.c; SDN-19, #195)
bool NodeOverlayPeerUp(void *peer) {
	NODE_OVERLAY_PEER *p = (NODE_OVERLAY_PEER *)peer;

	return (p != NULL && ReadPointerAcquire((PVOID const volatile *)&p->Session) != NULL);
}

// Send a control record of size bytes to the peer of the overlay, a next hop of the tables, on its Noise session: a probe of
// gateway HA or the answer to one (NodeGateway.c; SDN-19, #195). False when the peer has no session, or the send failed.
bool NodeOverlaySendControl(NODE *n, void *peer, const UCHAR *data, UINT size) {
	NODE_OVERLAY_PEER *p = (NODE_OVERLAY_PEER *)peer;

	if (n == NULL || n->Overlay == NULL || p == NULL)
		return false;

	// Counted on the peer before it reads the session, so the thread does not close the session under the send
	InterlockedIncrement(&p->Senders);
	TRANSPORT_NOISE *s = ReadPointerAcquire((PVOID const volatile *)&p->Session);
	bool ok = (s != NULL && TransportNoiseSend(s, NOISE_RECORD_CONTROL, data, size));
	InterlockedDecrement(&p->Senders);

	return ok;
}

// Send the data record of size bytes, the VRF id and then an IP packet, to the next hop hop of the tables v, over its
// session, its link of kind vxlan or geneve, or the datagram path of the peer agent while it has no session (SDN-19-R1,
// #507): the packet of one spoke that the hub of their VRF sends on to another (NodeGateway.c; SDN-19, #195). False when
// it went nowhere. The caller is an online reader of the node's table snapshot, which holds v.
bool NodeOverlaySendRecord(NODE *n, NODE_VRF_TABLES *v, UINT hop, const UCHAR *record, UINT size) {
	if (n == NULL || n->Overlay == NULL || v == NULL || hop >= v->NumHops || record == NULL || size < NODE_OVERLAY_VRF_TAG)
		return false;

	NODE_OVERLAY_PEER *peer = (NODE_OVERLAY_PEER *)v->Hops[hop];

	InterlockedIncrement(&peer->Senders);
	TRANSPORT_NOISE *s = ReadPointerAcquire((PVOID const volatile *)&peer->Session);
	bool plain = (NodeLinkKind(v, hop, READ_UINT(record)) != CONTROL_LINK_NOISE);
	bool ok = (plain ? NodeLinkSend(v, hop, record, size - NODE_OVERLAY_VRF_TAG) : (s != NULL && TransportNoiseSend(s, NOISE_RECORD_DATA, record, size)));
	InterlockedDecrement(&peer->Senders);

	// The datagram path of the peer agent carries it to a peer that has no Noise session (NodeAgent.c; SDN-19-R1, #507)
	if (plain == false && s == NULL)
		ok = NodeAgentSend(n, peer->Key, record, size);

	return ok;
}
