// NodeLink.c
// The links of kind vxlan and geneve of the overlay of a node (SDN-76, #356; ADR-0032). The Intent gives each VRF the
// kind of the links between its nodes: noise, the Noise session over QUIC or TLS for any underlay, or vxlan or geneve
// between two nodes that reach each other on a network that the operator trusts, a LAN, an intranet, a data center or a
// private WAN. Such a link is plain by decision of the maintainer (2026-10-24): no Noise and no IPsec of ours; the
// operator may put IPsec or MACsec under it, outside the product.
//
// Windows has no VXLAN or Geneve interface for applications (ADR-0032), so the VXLAN module of the new core (Core/Vxlan.h;
// SDN-62, #289, and SDN-71, #347) carries the links in user space, on UDP sockets of its own over Winsock: one of VXLAN
// and one of Geneve, each on the port of the tunnel endpoint of the node in its desired state, which open with the first
// Generation that has a link of their encapsulation. A packet of the host in such a VRF goes as it goes over a session,
// through the forwarding table, the policy, the 1:1 NAT rules and the shaping of the VRF (NodeOverlayInput), and then
// behind an Ethernet header, from and to 02:52:5a:00:00:03, with the EtherType of IPv4 or IPv6, on the VNI of the VRF to
// the tunnel endpoint of the peer of its route (NodeLinkSend) in place of the session. A frame that the module takes
// goes as a data record of a session goes, through the same checks of the forwarding table, the policy and the 1:1 NAT
// rules, to the host (NodeOverlayLinkDeliver), on the receive thread of the socket, which is a reader of the tables of
// the node of its own; the adapter of the host takes it there, as the Wintun ring allows any thread.
//
// The only guard is configuration: the node takes a frame only on the VNI of a VRF whose link has the encapsulation of
// the socket that it came in on, and only from the address of the tunnel endpoint of a peer that shares that VRF, as the
// Controller named it; nothing is learned from the wire. Any other datagram is dropped and counted: from an address
// that the Controller did not name (Strangers), on a VNI of no such VRF (UnknownVni), or not a frame of an IP packet
// (Malformed). The Controller gives the flood list of each VNI too, the tunnel endpoints of the peers that share the VRF,
// which the module holds for the frames of an L2 Network to come; the packets of an L3 Network go to the one peer of
// their route.
//
// The links of a Generation are built from its desired state into the forwarding tables of the VRFs of that Generation,
// and go in and out with them (NodeSwapVrfs, NodeFreeVrfTables), so the data path reads them as it reads the tables,
// without a lock, and a change of the kind of a link between noise and vxlan or geneve is one Generation. The module
// carries the VNIs of the Generation that goes in from before its tables go in, and stops carrying the VNIs of the one
// before once they are in (NodeLinkApplied), so it loses no more than the frames in flight. A frame that a session
// carries in a VRF whose link changed is still delivered: only its datagrams are judged by the kind of the link.

#include "NodeLink.h"

#include "Mayaqua/Memory.h"
#include "Mayaqua/Object.h"
#include "Mayaqua/TcpIp.h"

#include "Core/Control.h"

#include "NodeInternal.h"
#include "NodeSourceGroup.h"

// The MAC address of both ends of the Ethernet header of a frame of a link, locally administered
static const UCHAR node_link_mac[6] = {0x02, 0x52, 0x5A, 0x00, 0x00, 0x03};

// A receive thread of the module as a reader of the tables of the node, with the buffers of the records that it delivers
typedef struct NODE_LINK_THREAD {
	volatile LONG ThreadId; // The thread, 0 while the slot is free
	NODE_READER Reader;     // ... as a reader of the tables, online while it delivers
	bool Registered;        // The reader is registered
	UCHAR *Record;          // The data record of a frame: the VRF id, then the IP packet
	UCHAR *Nat;             // Its packet as the host sees it, when a 1:1 NAT rule translates it
} NODE_LINK_THREAD;

// The VXLAN module of the links of a node, its sockets, and what became of the frames
struct NODE_LINK {
	NODE *Node;
	LOCK *Lock;                    // The opening of the sockets and the VNIs that the module carries
	VXLAN *Vxlan;                  // The module
	VXLAN_UDP *volatile Udp;       // Its socket of VXLAN, NULL until a Generation has a link of kind vxlan
	VXLAN_UDP *volatile GeneveUdp; // ... and of Geneve
	UINT NumCarried;               // The VNIs that the module carries, under Lock
	UINT Carried[CONTROL_MAX_VRFS * 2];
	UINT NumCurrent; // ... of them, those of the Generation in the tables
	UINT Current[CONTROL_MAX_VRFS];
	UINT NumNext; // ... and those of the Generation that goes in
	UINT Next[CONTROL_MAX_VRFS];
	NODE_LINK_THREAD Threads[NODE_LINK_THREADS];
	volatile LONG64 Sent;
	volatile LONG64 Delivered;
	volatile LONG64 Strangers;
	volatile LONG64 UnknownVni;
	volatile LONG64 Malformed;
	volatile LONG64 Failed;
};

// A VRF of a Generation whose link is of kind vxlan or geneve
typedef struct NODE_LINK_VRF {
	UINT VrfId;
	UINT Kind; // CONTROL_LINK_VXLAN or CONTROL_LINK_GENEVE
	UINT Vni;
} NODE_LINK_VRF;

// The tunnel endpoint of a peer of a Generation, and the VRFs that it shares with the node
typedef struct NODE_LINK_PEER {
	bool HasVtep;      // The Controller named its tunnel endpoint
	VXLAN_ADDR Vxlan;  // ... for VXLAN
	VXLAN_ADDR Geneve; // ... and for Geneve
	UINT NumVrfs;
	UINT VrfIds[CONTROL_MAX_VRFS];
} NODE_LINK_PEER;

// The links of one Generation, which go in with its forwarding tables: next hop i of the tables below NumPeers is peer i
struct NODE_LINK_TABLE {
	NODE_LINK *Link; // The module that carries them
	UINT NumVrfs;
	NODE_LINK_VRF Vrfs[CONTROL_MAX_VRFS];
	UINT NumPeers;
	NODE_LINK_PEER *Peers;
};

// Whether the num VNIs of list hold vni
static bool NodeLinkHas(const UINT *list, UINT num, UINT vni) {
	for (UINT i = 0; i < num; i++)
		if (list[i] == vni)
			return true;

	return false;
}

// The VRF vrf_id among the VRFs with a link of kind vxlan or geneve of the table t, NULL for one of kind noise
static const NODE_LINK_VRF *NodeLinkVrf(const NODE_LINK_TABLE *t, UINT vrf_id) {
	for (UINT i = 0; t != NULL && i < t->NumVrfs; i++)
		if (t->Vrfs[i].VrfId == vrf_id)
			return &t->Vrfs[i];

	return NULL;
}

// The peer of the next hop hop of the tables v, NULL for none: a next hop of a leaked route leads to a peer below
static const NODE_LINK_PEER *NodeLinkPeer(NODE_VRF_TABLES *v, UINT hop) {
	NODE_LINK_TABLE *t = (v != NULL ? v->Link : NULL);

	if (t == NULL || hop >= v->NumHops)
		return NULL;
	if (hop < t->NumPeers)
		return &t->Peers[hop];

	for (UINT i = 0; i < t->NumPeers && i < v->NumHops; i++)
		if (v->Hops[i] == v->Hops[hop])
			return &t->Peers[i];

	return NULL;
}

// The VXLAN_ADDR of the tunnel endpoint c on port, in the encapsulation encap
static void NodeLinkAddr(VXLAN_ADDR *a, const CONTROL_VTEP *c, UINT port, USHORT encap) {
	if (c->AddressSize == 4) {
		VxlanAddrSetV4(a, c->Address[0], c->Address[1], c->Address[2], c->Address[3], (USHORT)port);
	} else {
		Zero(a, sizeof(VXLAN_ADDR));
		Copy(a->Ip, c->Address, sizeof(a->Ip));
		a->Port = (USHORT)port;
	}
	a->Encap = encap;
}

// The send procedure of the module: a datagram to a tunnel endpoint of Geneve goes from the socket of Geneve, any other
// from the socket of VXLAN, or from the other socket while that one is not open, since a tunnel endpoint takes datagrams
// from any source port
static bool NodeLinkUdpSend(void *param, const VXLAN_ADDR *dst, const void *data, UINT size) {
	NODE_LINK *l = (NODE_LINK *)param;
	VXLAN_UDP *vxlan = ReadPointerAcquire((PVOID const volatile *)&l->Udp);
	VXLAN_UDP *geneve = ReadPointerAcquire((PVOID const volatile *)&l->GeneveUdp);
	VXLAN_UDP *u = (dst->Encap == VXLAN_ENCAP_GENEVE ? geneve : vxlan);

	return VxlanUdpSend(u != NULL ? u : (vxlan != NULL ? vxlan : geneve), dst, data, size);
}

// The slot of the calling receive thread of the module, which it takes and registers as a reader of the tables of the node
// the first time; NULL when all are taken
static NODE_LINK_THREAD *NodeLinkThread(NODE_LINK *l) {
	LONG id = (LONG)GetCurrentThreadId();

	for (UINT i = 0; i < NODE_LINK_THREADS; i++)
		if (ReadAcquire(&l->Threads[i].ThreadId) == id)
			return &l->Threads[i];

	for (UINT i = 0; i < NODE_LINK_THREADS; i++) {
		NODE_LINK_THREAD *th = &l->Threads[i];

		if (InterlockedCompareExchange(&th->ThreadId, id, 0) != 0)
			continue;

		th->Record = Malloc(NODE_OVERLAY_VRF_TAG + VXLAN_MAX_FRAME);
		th->Nat = Malloc(NOISE_MAX_PAYLOAD + NODE_NAT_GROWTH);
		NodeReaderRegister(l->Node, &th->Reader);
		NodeReaderOffline(&th->Reader);
		th->Registered = true;
		return th;
	}

	return NULL;
}

// The receiver of the module: a frame of vni from the tunnel endpoint from, on the receive thread of a socket. It goes to
// the overlay when vni is the VNI of a VRF of the Generation in the tables whose link has the encapsulation of from, from
// is the tunnel endpoint of a peer that shares that VRF, and an IP packet follows its Ethernet header, with the source
// group that its datagram carried (SDN-87, #386); else it is dropped and counted.
static void NodeLinkReceive(VXLAN *x, void *param, UINT vni, const VXLAN_ADDR *from, const VXLAN_GROUP *group, const UCHAR *frame, UINT size) {
	NODE_LINK *l = (NODE_LINK *)param;
	NODE_LINK_THREAD *th = NodeLinkThread(l);
	UINT kind = (from->Encap == VXLAN_ENCAP_GENEVE ? CONTROL_LINK_GENEVE : CONTROL_LINK_VXLAN);

	if (th == NULL) {
		InterlockedIncrement64(&l->Failed);
		return;
	}

	NodeReaderOnline(l->Node, &th->Reader);
	{
		NODE_TABLES *t = NodeGetTables(l->Node);
		NODE_VRF_TABLES *v = (t != NULL ? t->Vrfs : NULL);
		NODE_LINK_TABLE *lt = (v != NULL ? v->Link : NULL);
		const NODE_LINK_VRF *lv = NULL;
		UINT peer = NODE_VRF_NONE;

		for (UINT i = 0; lt != NULL && i < lt->NumVrfs && lv == NULL; i++)
			if (lt->Vrfs[i].Vni == vni && lt->Vrfs[i].Kind == kind)
				lv = &lt->Vrfs[i];

		// The address alone names the peer: a tunnel endpoint sends from any source port
		for (UINT i = 0; lv != NULL && i < lt->NumPeers && i < v->NumHops && peer == NODE_VRF_NONE; i++) {
			const NODE_LINK_PEER *p = &lt->Peers[i];

			if (p->HasVtep && Cmp(p->Vxlan.Ip, from->Ip, sizeof(from->Ip)) == 0)
				for (UINT j = 0; j < p->NumVrfs; j++)
					if (p->VrfIds[j] == lv->VrfId)
						peer = i;
		}

		USHORT ether = (size >= NODE_LINK_ETHER ? READ_USHORT(frame + 12) : 0);

		if (lv == NULL) {
			InterlockedIncrement64(&l->UnknownVni);
		} else if (peer == NODE_VRF_NONE) {
			InterlockedIncrement64(&l->Strangers);
		} else if ((ether != MAC_PROTO_IPV4 && ether != MAC_PROTO_IPV6) || size - NODE_LINK_ETHER > VXLAN_MAX_FRAME) {
			InterlockedIncrement64(&l->Malformed);
		} else {
			NODE_SOURCE_CLAIM claim;

			// The source group of the datagram, which the tag mode of the VRF decides on (NodeSourceGroup.c; SDN-87, #386)
			NodeSourceGroupClaim(&claim, kind == CONTROL_LINK_GENEVE ? NODE_CARRIER_GENEVE : NODE_CARRIER_VXLAN, group);
			WRITE_UINT(th->Record, lv->VrfId);
			Copy(th->Record + NODE_OVERLAY_VRF_TAG, frame + NODE_LINK_ETHER, size - NODE_LINK_ETHER);
			InterlockedIncrement64(&l->Delivered);
			NodeOverlayLinkDeliver(l->Node, v->Hops[peer], th->Record, NODE_OVERLAY_VRF_TAG + size - NODE_LINK_ETHER, th->Nat, &claim);
		}
	}
	NodeReaderOffline(&th->Reader);
}

// The VXLAN module of the links of node n, without a socket yet; NULL when there is no memory
static NODE_LINK *NodeNewLink(NODE *n) {
	NODE_LINK *l = ZeroMalloc(sizeof(NODE_LINK));

	l->Node = n;
	l->Lock = NewLock();
	l->Vxlan = VxlanNew(NodeLinkUdpSend, l, NULL, l);
	if (l->Vxlan == NULL) {
		DeleteLock(l->Lock);
		Free(l);
		return NULL;
	}

	// The frames come with the source group of their datagram (SDN-87, #386)
	VxlanSetGroupReceiver(l->Vxlan, NodeLinkReceive);

	return l;
}

// Free the module of the links: its sockets first, which joins their receive threads, then the readers of those threads,
// then the module. No table may hold a link any more.
static void NodeFreeLink(NODE_LINK *l) {
	if (l == NULL)
		return;

	VxlanUdpFree(l->Udp);
	VxlanUdpFree(l->GeneveUdp);

	for (UINT i = 0; i < NODE_LINK_THREADS; i++) {
		NODE_LINK_THREAD *th = &l->Threads[i];

		if (th->Registered)
			NodeReaderUnregister(l->Node, &th->Reader);
		Free(th->Record);
		Free(th->Nat);
	}

	VxlanFree(l->Vxlan);
	DeleteLock(l->Lock);
	Free(l);
}

// Open the socket of the encapsulation geneve on port, unless it is open; the caller holds the lock
static void NodeLinkOpen(NODE_LINK *l, bool geneve, UINT port) {
	VXLAN_UDP *volatile *slot = (geneve ? &l->GeneveUdp : &l->Udp);
	const char *name = (geneve ? "Geneve" : "VXLAN");

	if (*slot != NULL) {
		if (VxlanUdpPort(*slot) != port)
			NodeLog(l->Node, "Link: the socket of %s stays on UDP port %u; port %u takes effect when the overlay starts again", name, (UINT)VxlanUdpPort(*slot), port);
		return;
	}

	VXLAN_UDP *u = (geneve ? VxlanUdpNewGeneve((USHORT)port) : VxlanUdpNew((USHORT)port));
	if (u == NULL) {
		NodeLog(l->Node, "Link: the socket of %s could not be opened on UDP port %u, so the links of kind %s carry nothing; the next Generation tries again", name, port, geneve ? "geneve" : "vxlan");
		return;
	}

	if (VxlanUdpStart(u, l->Vxlan) == false) {
		VxlanUdpFree(u);
		NodeLog(l->Node, "Link: the receive thread of the socket of %s could not start", name);
		return;
	}

	InterlockedExchangePointer((PVOID volatile *)slot, u);
	NodeLog(l->Node, "Link: the socket of %s listens on UDP port %u, plain on a network that the operator trusts", name, port);
}

// The links of the desired state st into the table t: the VRFs with a link of kind vxlan or geneve, and the tunnel
// endpoint of each peer, as next hop i of the tables is the peer of st->Peers[i]
static void NodeLinkBuild(NODE_LINK_TABLE *t, const CONTROL_STATE *st) {
	for (UINT i = 0; i < st->NumVrfs && i < CONTROL_MAX_VRFS; i++) {
		const CONTROL_VRF *c = &st->Vrfs[i];

		if (c->Link != CONTROL_LINK_VXLAN && c->Link != CONTROL_LINK_GENEVE)
			continue;

		NODE_LINK_VRF *lv = &t->Vrfs[t->NumVrfs++];
		lv->VrfId = c->Id;
		lv->Kind = c->Link;
		lv->Vni = c->Vni;
	}

	t->NumPeers = st->NumPeers;
	t->Peers = ZeroMalloc(sizeof(NODE_LINK_PEER) * MAX(st->NumPeers, 1));
	for (UINT i = 0; i < st->NumPeers; i++) {
		const CONTROL_PEER *c = &st->Peers[i];
		NODE_LINK_PEER *p = &t->Peers[i];

		p->NumVrfs = MIN(c->NumVrfs, CONTROL_MAX_VRFS);
		Copy(p->VrfIds, c->VrfIds, sizeof(UINT) * p->NumVrfs);
		if (c->Vtep.AddressSize != 4 && c->Vtep.AddressSize != 16)
			continue;

		p->HasVtep = true;
		NodeLinkAddr(&p->Vxlan, &c->Vtep, c->Vtep.VxlanPort != 0 ? c->Vtep.VxlanPort : VXLAN_PORT, VXLAN_ENCAP_VXLAN);
		NodeLinkAddr(&p->Geneve, &c->Vtep, c->Vtep.GenevePort != 0 ? c->Vtep.GenevePort : GENEVE_PORT, VXLAN_ENCAP_GENEVE);
	}
}

// Carry the VNI of each VRF of t in the module, with the flood list of the tunnel endpoints of the peers that share the
// VRF, before the tables of t go in; the caller holds the lock
static void NodeLinkCarry(NODE_LINK *l, const NODE_LINK_TABLE *t) {
	VXLAN_ADDR *vteps = ZeroMalloc(sizeof(VXLAN_ADDR) * MAX(t->NumPeers, 1));

	l->NumNext = 0;
	for (UINT i = 0; i < t->NumVrfs; i++) {
		const NODE_LINK_VRF *lv = &t->Vrfs[i];
		UINT num = 0;

		for (UINT j = 0; j < t->NumPeers && num < VXLAN_MAX_VTEPS; j++) {
			const NODE_LINK_PEER *p = &t->Peers[j];

			if (p->HasVtep && NodeLinkHas(p->VrfIds, p->NumVrfs, lv->VrfId))
				vteps[num++] = (lv->Kind == CONTROL_LINK_GENEVE ? p->Geneve : p->Vxlan);
		}

		if (VxlanSetVni(l->Vxlan, lv->Vni, vteps, num) == false) {
			NodeLog(l->Node, "Link: the VXLAN module does not carry VNI %u of VRF %u", lv->Vni, lv->VrfId);
			continue;
		}

		if (NodeLinkHas(l->Next, l->NumNext, lv->Vni) == false)
			l->Next[l->NumNext++] = lv->Vni;
		if (NodeLinkHas(l->Carried, l->NumCarried, lv->Vni) == false && l->NumCarried < CONTROL_MAX_VRFS * 2)
			l->Carried[l->NumCarried++] = lv->Vni;
	}

	Free(vteps);
}

// Build the links of the desired state st into the forwarding tables v of its Generation, with which they go in
// (NodeOverlay.c). The module opens with the first Generation that has a link of kind vxlan or geneve, and each of its
// sockets with the first that has a link of its encapsulation, on the port of the tunnel endpoint of the node; a socket
// that cannot open carries nothing, and the next Generation tries again.
void NodeLinkAttach(NODE *n, NODE_VRF_TABLES *v, const CONTROL_STATE *st) {
	if (n == NULL || v == NULL || st == NULL)
		return;

	NODE_LINK_TABLE *t = ZeroMalloc(sizeof(NODE_LINK_TABLE));
	NodeLinkBuild(t, st);

	NODE_LINK *l = ReadPointerAcquire((PVOID const volatile *)&n->Link);
	if (l == NULL && t->NumVrfs != 0) {
		NODE_LINK *fresh = NodeNewLink(n);

		// Of two states that are applied at once, one opens the module
		l = (fresh != NULL ? InterlockedCompareExchangePointer((PVOID volatile *)&n->Link, fresh, NULL) : NULL);
		if (l == NULL) {
			l = fresh;
		} else {
			NodeFreeLink(fresh);
		}
	}

	if (l == NULL) {
		NodeFreeLinkTable(t);
		return;
	}

	Lock(l->Lock);
	{
		bool vxlan = false, geneve = false;

		for (UINT i = 0; i < t->NumVrfs; i++) {
			vxlan = vxlan || t->Vrfs[i].Kind == CONTROL_LINK_VXLAN;
			geneve = geneve || t->Vrfs[i].Kind == CONTROL_LINK_GENEVE;
		}

		if (vxlan)
			NodeLinkOpen(l, false, st->Vtep.VxlanPort != 0 ? st->Vtep.VxlanPort : VXLAN_PORT);
		if (geneve)
			NodeLinkOpen(l, true, st->Vtep.GenevePort != 0 ? st->Vtep.GenevePort : GENEVE_PORT);

		NodeLinkCarry(l, t);
	}
	Unlock(l->Lock);

	t->Link = l;
	v->Link = t;
}

// The tables of the Generation that NodeLinkAttach built went in (swapped), or did not: the module stops carrying the
// VNIs that no Generation in the tables has any more
void NodeLinkApplied(NODE *n, bool swapped) {
	NODE_LINK *l = (n != NULL ? ReadPointerAcquire((PVOID const volatile *)&n->Link) : NULL);
	UINT kept = 0;

	if (l == NULL)
		return;

	Lock(l->Lock);
	{
		if (swapped) {
			l->NumCurrent = l->NumNext;
			Copy(l->Current, l->Next, sizeof(l->Current));
		}

		for (UINT i = 0; i < l->NumCarried; i++) {
			if (NodeLinkHas(l->Current, l->NumCurrent, l->Carried[i]))
				l->Carried[kept++] = l->Carried[i];
			else
				VxlanDelVni(l->Vxlan, l->Carried[i]);
		}
		l->NumCarried = kept;
		l->NumNext = 0;
	}
	Unlock(l->Lock);
}

// Free the links of a Generation; the module that carries them stays
void NodeFreeLinkTable(NODE_LINK_TABLE *t) {
	if (t == NULL)
		return;

	Free(t->Peers);
	Zero(t, sizeof(NODE_LINK_TABLE));
	Free(t);
}

// The kind of the link of the VRF vrf_id to the next hop hop of the tables v: CONTROL_LINK_NOISE, or CONTROL_LINK_VXLAN or
// CONTROL_LINK_GENEVE when the packet goes in VXLAN or Geneve (NodeLinkSend) in place of the session. The caller reads v
// as a reader of the table snapshot of the node.
UINT NodeLinkKind(NODE_VRF_TABLES *v, UINT hop, UINT vrf_id) {
	const NODE_LINK_VRF *lv = NodeLinkVrf(v != NULL ? v->Link : NULL, vrf_id);

	if (lv == NULL || NodeLinkPeer(v, hop) == NULL)
		return CONTROL_LINK_NOISE;

	return lv->Kind;
}

// Send the data record of size bytes of its IP packet, behind its VRF id, to the next hop hop of the tables v over the link
// of kind vxlan or geneve of the VRF: the packet behind an Ethernet header on the VNI of the VRF, to the tunnel endpoint
// of the peer in the encapsulation of the link. A packet of the host when host is set, which carries its source group in
// the tag mode trusted-underlay of the VRF; else the packet of a spoke that the node, the hub of the VRF, sends on to
// another, which carries none (NodeSourceGroup.c; SDN-87, #386). False when the peer has no tunnel endpoint, the frame is
// larger than the module takes, or the datagram could not be sent. The caller reads v as a reader of the table snapshot of
// the node.
bool NodeLinkSend(NODE_VRF_TABLES *v, UINT hop, const UCHAR *record, UINT size, bool host) {
	NODE_LINK_TABLE *t = (v != NULL ? v->Link : NULL);
	UCHAR frame[VXLAN_MAX_FRAME];

	if (t == NULL || record == NULL)
		return false;

	const NODE_LINK_VRF *lv = NodeLinkVrf(t, READ_UINT(record));
	const NODE_LINK_PEER *p = NodeLinkPeer(v, hop);
	const UCHAR *packet = record + NODE_OVERLAY_VRF_TAG;

	if (lv == NULL || p == NULL || p->HasVtep == false || size == 0 || size > VXLAN_MAX_FRAME - NODE_LINK_ETHER) {
		InterlockedIncrement64(&t->Link->Failed);
		return false;
	}

	Copy(frame, node_link_mac, 6);
	Copy(frame + 6, node_link_mac, 6);
	WRITE_USHORT(frame + 12, (packet[0] >> 4) == 6 ? MAC_PROTO_IPV6 : MAC_PROTO_IPV4);
	Copy(frame + NODE_LINK_ETHER, packet, size);

	// The source group of a packet of the host, in the tag mode trusted-underlay of the VRF (NodeSourceGroup.c; SDN-87, #386)
	VXLAN_GROUP group;
	Zero(&group, sizeof(group));
	if (host)
		NodeSourceGroupStamp(v, lv->VrfId, packet, size, &group);
	bool ok = VxlanSendToGroup(t->Link->Vxlan, lv->Vni, lv->Kind == CONTROL_LINK_GENEVE ? &p->Geneve : &p->Vxlan, &group, frame, NODE_LINK_ETHER + size);
	InterlockedIncrement64(ok ? &t->Link->Sent : &t->Link->Failed);

	return ok;
}

// Free the module of the links of a node, once no table holds a link any more: the overlay stops, and its tables went
// before (NodeOverlayStop)
void NodeLinkStop(NODE *n) {
	if (n == NULL)
		return;

	NodeFreeLink(InterlockedExchangePointer((PVOID volatile *)&n->Link, NULL));
}

// The frames of the links of a node since the first Generation of its overlay that had one; all 0 before. A datagram that
// the module itself dropped counts as UnknownVni or Malformed, as its reason says.
void NodeLinkGetStatus(NODE *n, NODE_LINK_STATUS *st) {
	VXLAN_STATS vs;

	if (st == NULL)
		return;

	Zero(st, sizeof(NODE_LINK_STATUS));
	NODE_LINK *l = (n != NULL ? ReadPointerAcquire((PVOID const volatile *)&n->Link) : NULL);
	if (l == NULL)
		return;

	VxlanGetStats(l->Vxlan, &vs);
	st->Running = true;
	st->VxlanPort = VxlanUdpPort(ReadPointerAcquire((PVOID const volatile *)&l->Udp));
	st->GenevePort = VxlanUdpPort(ReadPointerAcquire((PVOID const volatile *)&l->GeneveUdp));
	st->NumVnis = vs.NumVnis;
	st->Sent = (UINT64)ReadAcquire64(&l->Sent);
	st->Delivered = (UINT64)ReadAcquire64(&l->Delivered);
	st->Strangers = (UINT64)ReadAcquire64(&l->Strangers);
	st->UnknownVni = (UINT64)ReadAcquire64(&l->UnknownVni) + vs.Drops[VXLAN_DROP_VNI];
	st->Malformed = (UINT64)ReadAcquire64(&l->Malformed) + vs.Drops[VXLAN_DROP_MALFORMED] + vs.Drops[VXLAN_DROP_CRITICAL] + vs.Drops[VXLAN_DROP_CONTROL];
	st->Failed = (UINT64)ReadAcquire64(&l->Failed);
}
