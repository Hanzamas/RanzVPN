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
// has no Login. One thread of the overlay accepts, dials and reads the sessions; it alone closes them, and a sender
// counts itself on the peer while it sends, so a session is never closed under a send. The forwarding reads the
// tables without a lock, as a reader of the table snapshot, so a peer that a Generation drops goes only once no
// table leads to it any more.

#include "Node.h"

#include "Mayaqua/Memory.h"
#include "Mayaqua/Object.h"
#include "Mayaqua/Str.h"

#include "Core/Control.h"

#include "NodeCaps.h"
#include "NodeInternal.h"

// One peer of the overlay, from a Peer object of the desired state: a next hop of the forwarding tables
typedef struct NODE_OVERLAY_PEER {
	char Name[PEER_NAME_SIZE];         // Its node name: its address on the data transport
	UCHAR Key[PEER_KEY_SIZE];          // Its static key
	TRANSPORT_NOISE *volatile Session; // The Noise session to it, NULL while there is none
	volatile LONG Senders;             // Calls of NodeOverlayInput that send on Session now
	UINT64 NextDial;                   // When the node dials it next
	bool Gone;                         // The desired state dropped it and no table leads to it: the thread closes its session and frees it
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

	NODE_VRF_TABLES *v = NodeLeakNewTables(st, routes, num, (void **)hops);
	Free(routes);

	// The rules of the Generation, installed with its tables
	if (v != NULL)
		v->Nat = NodeNewNat(st);

	return v;
}

// The state that the control stream applied: the node's name and addresses, its peers, and the forwarding tables of
// its VRFs, built beside the live ones and swapped in. A peer that stays keeps its session; one that the state drops
// goes only once the new tables are in, when no reader can find it any more. The relay role gets the peers too
// (NodeSetPeers). It runs on the thread of the control stream, or on the caller's of NodeOverlayApply.
static void NodeOverlayState(void *param, const CONTROL_STATE *st) {
	NODE_OVERLAY *ov = (NODE_OVERLAY *)param;
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
		}
	}
	Unlock(ov->Lock);

	// Built beside the live tables, then in their place: the swap returns once no reader holds the tables before
	NODE_VRF_TABLES *v = NodeOverlayTables(st, hops);
	// The rules of the policy of the VRFs of the Generation go in with its tables (NodePolicy.c)
	NodePolicyAttach(ov->Node, v, st);
	// The MTU and the rate limits of the Generation go in with its tables (NodeShape.c)
	NodeShapeAttach(ov->Node, v, st);
	// The Mirrors of the Generation go in with its tables (NodeMirror.c)
	NodeMirrorAttach(ov->Node, v, st);
	UINT num_vrfs = (v != NULL ? v->NumVrfs : 0);
	bool swapped = (v != NULL && NodeSwapVrfs(ov->Node, v));
	NodePolicyApplied(ov->Node, swapped);
	if (v != NULL && swapped == false)
		NodeFreeVrfTables(v);

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

		if (p != NULL && p->Session == NULL) {
			InterlockedExchangePointer((PVOID volatile *)&p->Session, s);
			StrCpy(name, sizeof(name), p->Name);
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

// Close the session that the peer of key has: it dialled again on another path. Only the thread of the overlay closes.
static void NodeOverlayReplace(NODE_OVERLAY *ov, const UCHAR *key) {
	NODE_OVERLAY_PEER *p;

	Lock(ov->Lock);
	{
		p = NodeOverlayPeer(ov, NULL, key);
		if (p != NULL && p->Session == NULL)
			p = NULL;
	}
	Unlock(ov->Lock);

	if (p != NULL)
		NodeOverlayClose(ov, p);
}

// Take a stream that a peer dialled: the responder of a session, whose initiator must be a peer of the desired state
static bool NodeOverlayAccept(NODE_OVERLAY *ov) {
	NOISE_SESSION_CONFIG c;

	if (ov->Listener == NULL)
		return false;

	TRANSPORT_STREAM *stream = TransportAccept(ov->Listener, 0);
	// Else a stream that the front door or QUIC of the node's Listener took (NodeListener.c; SDN-45, #238)
	if (stream == NULL)
		stream = NodeListenerAccept(ov->Node);
	if (stream == NULL)
		return false;

	TRANSPORT_NOISE *s = ZeroMalloc(sizeof(TRANSPORT_NOISE));
	NodeOverlaySessionConfig(ov, &c, NULL);
	if (TransportNoiseAccept(s, stream, &c, NODE_OVERLAY_HANDSHAKE) == false) {
		Free(s);
		return true;
	}

	// The peer's static key names the peer: a session between two peers has no Login. A peer that dials again, after it
	// roamed or woke from sleep, replaces the session that its old path left (CORE-S3-1).
	TransportNoiseAcceptLogin(s);
	NodeOverlayReplace(ov, s->Session.RemoteStatic);
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

			// A client dials its peers whatever the order of the keys: they cannot dial it (CORE-S3-1)
			if (p->Gone || p->Session != NULL || now < p->NextDial || (ov->Config.Dialler == false && Cmp(ov->Config.Key->Public, p->Key, PEER_KEY_SIZE) >= 0))
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

	TRANSPORT_STREAM *stream = TransportDial(ov->Config.Data, name, NULL);
	if (stream == NULL)
		return true;

	TRANSPORT_NOISE *s = ZeroMalloc(sizeof(TRANSPORT_NOISE));
	NodeOverlaySessionConfig(ov, &c, key);
	if (TransportNoiseConnect(s, stream, &c, NODE_OVERLAY_HANDSHAKE) == false) {
		Free(s);
		return true;
	}

	NodeOverlayAttach(ov, key, s);
	return true;
}

// A data record of the peer p: the VRF id, then an IP packet, which goes to the host in that VRF when its table routes
// the source to p and the destination to the host. The thread of the overlay reads the tables as an online reader.
static void NodeOverlayDeliver(NODE_OVERLAY *ov, NODE_OVERLAY_PEER *p, const UCHAR *record, UINT size) {
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
		UINT from = NodeVrfLookup(vt, src, addr_size);

		ok = (from < v->NumHops && v->Hops[from] == p && NodeVrfLookup(vt, dst, addr_size) == NODE_VRF_LOCAL);
		// The policy of the VRF judges the packet as the peer sent it, before a 1:1 NAT rule translates it (NodePolicy.c)
		ok = ok && NodePolicyInbound(ov->Node, v, vrf_id, from, packet, packet_size);
	}

	// A Mirror copies the packet as the peer sent it, before a 1:1 NAT rule translates it (NodeMirror.c)
	if (ok)
		NodeMirrorCopy(v, vrf_id, packet, packet_size, false);

	// 1:1 NAT and 4via6 (NodeNat.c; SDN-6, #182): the host takes the packet as it sees it
	ok = ok && NodeNatInbound(v, vrf_id, &packet, &packet_size, ov->NatBuf, NOISE_MAX_PAYLOAD + NODE_NAT_GROWTH);

	if (ok == false || ov->Config.Adapter == NULL) {
		InterlockedIncrement64(&ov->Dropped);
		return;
	}

	InterlockedIncrement64(&ov->Delivered);
	ov->Config.Adapter(ov->Node, ov->Config.AdapterParam, vrf_id, packet, packet_size);
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
				NodeOverlayDeliver(ov, p, ov->Buf, size);
			} else if (ret != NOISE_RECEIVE_CONTROL) {
				NodeOverlayClose(ov, p);
				break;
			}
		}
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

		if (busy == false)
			Sleep(NODE_OVERLAY_IDLE);
	}

	// The end: every session closes and every peer goes
	Lock(ov->Lock);
	for (UINT i = 0; i < LIST_NUM(ov->Peers); i++)
		((NODE_OVERLAY_PEER *)LIST_DATA(ov->Peers, i))->Gone = true;
	Unlock(ov->Lock);
	NodeOverlayReap(ov);

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
	DWORD thread_id = 0;

	if (n == NULL || cfg == NULL || cfg->Data == NULL || cfg->Key == NULL || n->Overlay != NULL)
		return false;

	NODE_OVERLAY *ov = ZeroMalloc(sizeof(NODE_OVERLAY));
	ov->Node = n;
	Copy(&ov->Config, cfg, sizeof(NODE_OVERLAY_CONFIG));
	ov->Lock = NewLock();
	ov->Peers = NewListFast(NULL);
	ov->Buf = Malloc(NOISE_MAX_PAYLOAD);
	ov->NatBuf = Malloc(NOISE_MAX_PAYLOAD + NODE_NAT_GROWTH);
	NodeShapeStart(n, cfg);
	NodePolicyStart(n, cfg);
	// The Listener, which listens where a state says (NodeListener.c; SDN-45, #238)
	NodeListenerStart(n);
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

	ov->Thread = CreateThread(NULL, 0, NodeOverlayThread, ov, 0, &thread_id);
	ov->Control = (ov->Thread != NULL && cfg->Control != NULL ? ControlStart(&cc) : NULL);
	if (ov->Thread == NULL || (cfg->Control != NULL && ov->Control == NULL)) {
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
	NodeDhcpStop(n);
	ov->Halt = true;
	if (ov->Thread != NULL) {
		WaitForSingleObject(ov->Thread, INFINITE);
		CloseHandle(ov->Thread);
	}
	// The thread closed every session, the ones over the streams of the Listener too (NodeListener.c; SDN-45, #238)
	NodeListenerStop(n);

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
bool NodeOverlayInput(NODE *n, UINT vrf_id, const UCHAR *packet, UINT size) {
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

	// 1:1 NAT and 4via6 (NodeNat.c; SDN-6, #182): the tables route the packet as the overlay sees it
	if (vt != NULL && size <= NOISE_MAX_PAYLOAD - NODE_OVERLAY_VRF_TAG && NodeNatEnds(v, vrf_id, packet, size, src, dst, &addr_size) && NodeVrfLookup(vt, src, addr_size) == NODE_VRF_LOCAL)
		hop = NodeVrfLookup(vt, dst, addr_size);

	// Only to a peer: the host's own addresses and the addresses of no route stay here
	if (vt == NULL || hop >= v->NumHops) {
		InterlockedIncrement64(&ov->Dropped);
		return false;
	}

	NODE_OVERLAY_PEER *peer = (NODE_OVERLAY_PEER *)v->Hops[hop];
	UCHAR *record = (size + NODE_OVERLAY_VRF_TAG <= sizeof(buf) ? buf : Malloc(size + NODE_OVERLAY_VRF_TAG));

	// A route that a VRF of the peer leaks takes the packet into that VRF (NodeLeak.c; SDN-7, #183)
	WRITE_UINT(record, NodeLeakVrf(v, hop, vrf_id));
	size = NodeNatCopy(v, vrf_id, record + NODE_OVERLAY_VRF_TAG, packet, size);
	// The policy of the VRF judges the packet as the overlay sees it, after the 1:1 NAT rules (NodePolicy.c; SDN-8, #184)
	bool allowed = NodePolicyOutbound(n, v, vrf_id, hop, record + NODE_OVERLAY_VRF_TAG, size);

	// Counted on the peer before it reads the session, so the thread does not close the session under the send
	InterlockedIncrement(&peer->Senders);
	TRANSPORT_NOISE *s = ReadPointerAcquire((PVOID const volatile *)&peer->Session);
	// The MTU of the VRF clamps the MSS of a TCP SYN as the overlay sees it, after the 1:1 NAT rules, and the rate limits
	// of the VRF and the node may drop it (NodeShape.c)
	bool ok = (allowed && s != NULL && NodeShapeOutput(n, v, vrf_id, record + NODE_OVERLAY_VRF_TAG, size) && TransportNoiseSend(s, NOISE_RECORD_DATA, record, size + NODE_OVERLAY_VRF_TAG));
	InterlockedDecrement(&peer->Senders);

	// A Mirror copies the packet as it went to the peer (NodeMirror.c)
	if (ok)
		NodeMirrorCopy(v, vrf_id, record + NODE_OVERLAY_VRF_TAG, size, true);

	if (record != buf)
		Free(record);

	InterlockedIncrement64(ok ? &ov->Forwarded : &ov->Dropped);
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
}
