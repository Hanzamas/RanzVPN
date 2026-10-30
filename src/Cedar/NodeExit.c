// NodeExit.c
// The exit node of the client role (SDN-55, #248; ADR-0011: the client role sets the default route through Wintun): the peer
// that the logged-in user chooses in the tray, through which the traffic of the host leaves for the internet. An exit node is
// a peer of the desired state that holds the default route of a VRF: a Route of its Peer object of the prefix 0.0.0.0/0, ::/0
// or both, as the Controller gives the internet exit of a VRF (SDN-12, #188). The client role lists the exit nodes in its
// status and takes the choice of its user through its pipe (NodeClient.c):
// - The overlay of a client builds the forwarding tables of each state from a copy of the state without the default routes
//   of the peers (NodeExitFilter): a client takes no default route of a peer by itself, so a packet of the host to an address
//   of no route goes nowhere, and no peer delivers the host a packet from any address that it likes (docs/threat-model.md
//   asks the same of a default route that a peer announces). A default route that a VRF of a peer leaks is left out too, and
//   is no exit node.
// - The exit nodes of the state go in with the forwarding tables of its Generation (NodeExitAttach): each peer with a default
//   route in a VRF, its next hop and the families that it carries, and a mark on the one that the user chose, which a choice
//   moves at once in the tables in place (NodeExitMark). A packet of the host in the VRF of the chosen exit to an address of no
//   route goes to the exit when it carries the family, and a packet of the exit from an address of no route comes from it
//   (NodeExitHop); a packet of the host of a family that the exit does not carry goes nowhere, and is counted.
// - The routes of the host: with an exit chosen and the role up, the adapter of its VRF holds 0.0.0.0/0 and ::/0, both
//   whatever the exit carries, at the metric 0 of the route and of its interface, so that Windows takes them before the
//   default routes of the other interfaces, as WireGuard for Windows sets the interface of a tunnel with a default route.
//   IPv6 so enters the adapter towards an exit that carries no IPv6 too: the overlay drops it, no IPv6 leaves outside the
//   tunnel, and the applications fall back to IPv4 (maintainer decision of 2026-10-24). A family that the host does not run
//   on the adapter has nothing to route. Without an exit, and while the role is down, the adapter holds neither, and its
//   interface takes its automatic metric again. While the exit has no session, what enters the adapter goes nowhere: the
//   traffic of the host does not fall back to the direct path behind the user's back.
// - The streams of the role must not enter the adapter that they carry. Each server address that the role reached, as its
//   streams connect, and the address of its Controller when the settings name one, gets a host route through the interface
//   of a default route of the host and its next hop while the default routes are on the adapter, when the host reaches the
//   address by a default route (the bypass routes). A roam makes them again on the new path, and a dial tries again for an
//   address that had none, as when the new default route came later than the new address.

#include "Node.h"

#include "Mayaqua/Memory.h"
#include "Mayaqua/Object.h"
#include "Mayaqua/Str.h"

#include "Core/Control.h"

#include "NodeExit.h"
#include "NodeInternal.h"

#include <iphlpapi.h>
#include <ws2tcpip.h>

#include <string.h>

#include <cjson/cJSON.h>

// A server address of the role, and the bypass route that the role installed for it
typedef struct NODE_EXIT_SERVER {
	UCHAR Address[16];        // 4 bytes for IPv4, 16 for IPv6
	UINT AddressSize;         // ... their number
	bool Routed;              // The role installed Route for it
	MIB_IPFORWARD_ROW2 Route; // ... a host route through the interface of a default route of the host and its next hop
} NODE_EXIT_SERVER;

// The exit node of the client role
struct NODE_EXIT {
	NODE *Node;                                  // The node
	NODE_VRF_ADAPTERS *Adapters;                 // The adapters of the role: the one of the VRF of the exit takes the default routes
	LOCK *Lock;                                  // Everything below but the counters
	bool Chosen;                                 // The user chose an exit node ...
	char Name[PEER_NAME_SIZE];                   // ... this peer ...
	UINT VrfId;                                  // ... in this VRF
	bool Down;                                   // The user took the role down: the host keeps no route of the exit
	UINT NumExits;                               // The exit nodes of the forwarding tables in place
	NODE_EXIT_ENTRY Exits[NODE_EXIT_MAX];        // ...
	UINT64 RoutesLuid;                           // The interface that holds the default routes, 0 for none
	bool Routes4;                                // ... 0.0.0.0/0 is on it
	bool Routes6;                                // ... ::/0 is on it, or the host runs no IPv6 there
	UINT NumServers;                             // The server addresses that the role reached
	NODE_EXIT_SERVER Servers[NODE_EXIT_SERVERS]; // ...
	volatile LONG64 Dropped4;                    // Packets of the host to the exit that it does not carry: IPv4 ...
	volatile LONG64 Dropped6;                    // ... and IPv6
};

// The exit nodes of the forwarding tables of one Generation, and the one that the user chose
struct NODE_EXIT_TABLE {
	NODE_EXIT *Owner;                     // The exit of the role, which outlives the tables: it counts the drops
	UINT NumExits;                        // The exit nodes of the state
	NODE_EXIT_ENTRY Exits[NODE_EXIT_MAX]; // ...
	volatile LONG Chosen;                 // The index of the chosen one among them, -1 for none
};

//
// The exit nodes of a state
//

// Whether the route c of a peer is a default route: the prefix 0.0.0.0/0 or ::/0
static bool NodeExitIsDefault(const CONTROL_ROUTE *c) {
	return ((c->AddressSize == 4 || c->AddressSize == 16) && c->Length == 0);
}

// Whether the route c of a peer is one that a VRF of the peer leaks into a VRF of the node (NodeLeak.c)
static bool NodeExitIsLeak(const CONTROL_ROUTE *c) {
	return (c->PeerVrfId != 0 && c->PeerVrfId != c->VrfId);
}

// The name of the VRF vrf_id in the state st, "" for none
static const char *NodeExitVrfName(const CONTROL_STATE *st, UINT vrf_id) {
	for (UINT i = 0; i < st->NumVrfs && i < CONTROL_MAX_VRFS; i++)
		if (st->Vrfs[i].Id == vrf_id)
			return st->Vrfs[i].Name;

	return "";
}

// Add the default route c of the peer name, the next hop hop of the tables, to the exit nodes of x: one entry for each peer
// and VRF, which takes the family of each of its default routes there
static void NodeExitAddEntry(NODE_EXIT_STATE *x, const CONTROL_STATE *st, const char *name, UINT hop, const CONTROL_ROUTE *c) {
	NODE_EXIT_ENTRY *e = NULL;

	for (UINT i = 0; i < x->NumExits && e == NULL; i++)
		if (x->Exits[i].Hop == hop && x->Exits[i].VrfId == c->VrfId)
			e = &x->Exits[i];

	if (e == NULL) {
		if (x->NumExits >= NODE_EXIT_MAX)
			return;

		e = &x->Exits[x->NumExits++];
		StrCpy(e->Name, sizeof(e->Name), name);
		e->VrfId = c->VrfId;
		StrCpy(e->VrfName, sizeof(e->VrfName), NodeExitVrfName(st, c->VrfId));
		e->Hop = hop;
	}

	if (c->AddressSize == 4)
		e->Ipv4 = true;
	else
		e->Ipv6 = true;
}

// The state that the overlay of a client applies in place of *st: a copy of it without the default routes of the peers, which a
// client takes only through the exit node that its user chose; *st stays when it holds none. The exit nodes of the state,
// each peer with a default route of its own in a VRF, go into what it returns, which NodeExitAttach takes and NodeExitFreeState
// frees once the overlay applied the state. NULL, and *st as it is, for an overlay that is no client's (e is NULL).
NODE_EXIT_STATE *NodeExitFilter(NODE_EXIT *e, const CONTROL_STATE **st) {
	if (e == NULL || st == NULL || *st == NULL)
		return NULL;

	const CONTROL_STATE *in = *st;
	NODE_EXIT_STATE *x = ZeroMalloc(sizeof(NODE_EXIT_STATE));
	bool any = false;

	for (UINT i = 0; i < in->NumPeers; i++) {
		const CONTROL_PEER *p = &in->Peers[i];

		for (UINT j = 0; j < p->NumRoutes && j < CONTROL_MAX_ROUTES; j++) {
			if (NodeExitIsDefault(&p->Routes[j]) == false)
				continue;

			any = true;
			if (NodeExitIsLeak(&p->Routes[j]) == false)
				NodeExitAddEntry(x, in, p->Name, i, &p->Routes[j]);
		}
	}

	if (any == false)
		return x;

	// The peers keep their order, so the next hop of each is its index still
	x->Copy = Clone(in, sizeof(CONTROL_STATE));
	x->Peers = Clone(in->Peers, sizeof(CONTROL_PEER) * in->NumPeers);
	for (UINT i = 0; i < in->NumPeers; i++) {
		CONTROL_PEER *p = &x->Peers[i];
		UINT num = 0;

		for (UINT j = 0; j < p->NumRoutes && j < CONTROL_MAX_ROUTES; j++)
			if (NodeExitIsDefault(&p->Routes[j]) == false)
				p->Routes[num++] = p->Routes[j];

		p->NumRoutes = num;
	}
	x->Copy->Peers = x->Peers;
	*st = x->Copy;

	return x;
}

// Free what NodeExitFilter returned
void NodeExitFreeState(NODE_EXIT_STATE *x) {
	if (x == NULL)
		return;

	Free(x->Peers);
	Free(x->Copy);
	Free(x);
}

// The index of the exit node that the user chose among the exit nodes of the tables x, -1 for none (e->Lock is held)
static LONG NodeExitIndex(NODE_EXIT *e, const NODE_EXIT_TABLE *x) {
	for (UINT i = 0; e->Chosen && i < x->NumExits; i++)
		if (x->Exits[i].VrfId == e->VrfId && StrCmp(x->Exits[i].Name, e->Name) == 0)
			return (LONG)i;

	return -1;
}

// The exit nodes of a state into the forwarding tables v built from it, which go in with them, with the mark of the one that
// the user chose (NodeOverlay.c; the overlay of a client only)
void NodeExitAttach(NODE_EXIT *e, NODE_VRF_TABLES *v, const NODE_EXIT_STATE *x) {
	if (e == NULL || v == NULL || x == NULL)
		return;

	NODE_EXIT_TABLE *t = ZeroMalloc(sizeof(NODE_EXIT_TABLE));
	t->Owner = e;
	t->NumExits = x->NumExits;
	Copy(t->Exits, x->Exits, sizeof(NODE_EXIT_ENTRY) * x->NumExits);

	Lock(e->Lock);
	t->Chosen = NodeExitIndex(e, t);
	Unlock(e->Lock);

	v->Exit = t;
}

// Free the exit nodes of forwarding tables, wiped first as NodeFreeTable does
void NodeExitFreeTable(NODE_EXIT_TABLE *t) {
	if (t == NULL)
		return;

	Zero(t, sizeof(NODE_EXIT_TABLE));
	Free(t);
}

// Whether a default route carries the address of size bytes: no multicast, broadcast, link-local, loopback or unspecified
// address, which never leaves the link of the host
static bool NodeExitRoutable(const UCHAR *addr, UINT size) {
	static const UCHAR zero[15] = {0};

	if (size == 4)
		return (addr[0] != 0 && addr[0] != 127 && (addr[0] != 169 || addr[1] != 254) && addr[0] < 0xE0);

	return (addr[0] != 0xFF && (addr[0] != 0xFE || (addr[1] & 0xC0) != 0x80) && (Cmp(addr, zero, sizeof(zero)) != 0 || addr[15] > 1));
}

// The next hop of a packet in the VRF vrf_id whose address addr, of addr_size bytes, the forwarding table of the VRF leads to
// hop: an address of no route (NODE_VRF_NONE) leads to the exit node that the user chose when it is in that VRF and carries the
// family, and when a default route carries the address; any other address leads to hop itself. A packet of the host
// (from_host) of a family that the exit does not carry is counted. The caller is an online reader of the node's table
// snapshot, which holds v.
UINT NodeExitHop(NODE_VRF_TABLES *v, UINT vrf_id, UINT hop, const UCHAR *addr, UINT addr_size, bool from_host) {
	NODE_EXIT_TABLE *t = (v != NULL ? v->Exit : NULL);

	if (hop != NODE_VRF_NONE || t == NULL || NodeExitRoutable(addr, addr_size) == false)
		return hop;

	LONG chosen = ReadAcquire(&t->Chosen);
	if (chosen < 0 || (UINT)chosen >= t->NumExits || t->Exits[chosen].VrfId != vrf_id)
		return hop;

	const NODE_EXIT_ENTRY *x = &t->Exits[chosen];
	if (addr_size == 4 ? x->Ipv4 : x->Ipv6)
		return x->Hop;

	if (from_host)
		InterlockedIncrement64(addr_size == 4 ? &t->Owner->Dropped4 : &t->Owner->Dropped6);

	return hop;
}

// Mark the exit node that the user chose in the forwarding tables in place, or none (e->Lock is held). The table lock keeps
// the tables from going under the mark.
static void NodeExitMark(NODE_EXIT *e) {
	NODE *n = e->Node;

	Lock(n->TableLock);
	{
		NODE_TABLES *t = NodeGetTables(n);
		NODE_EXIT_TABLE *x = (t != NULL && t->Vrfs != NULL ? t->Vrfs->Exit : NULL);

		if (x != NULL)
			InterlockedExchange(&x->Chosen, NodeExitIndex(e, x));
	}
	Unlock(n->TableLock);
}

//
// The routes of the host
//

// The address bytes of a SOCKADDR_INET whose address has size bytes
static UCHAR *NodeExitSockBytes(SOCKADDR_INET *s, UINT size) {
	return (size == 4 ? (UCHAR *)&s->Ipv4.sin_addr : (UCHAR *)&s->Ipv6.sin6_addr);
}

// The text of an address of size bytes
static void NodeExitAddressText(char *text, UINT text_size, const UCHAR *address, UINT size) {
	if (inet_ntop(size == 4 ? AF_INET : AF_INET6, address, text, text_size) == NULL)
		StrCpy(text, text_size, "?");
}

// The interface of the adapter of the VRF vrf_id of the role, 0 for none
static UINT64 NodeExitAdapter(NODE_EXIT *e, UINT vrf_id) {
	NODE_VRF_ADAPTER_STATUS *list = ZeroMalloc(sizeof(NODE_VRF_ADAPTER_STATUS) * NODE_VRF_MAX_ADAPTERS);
	UINT num = NodeVrfAdaptersGetStatus(e->Adapters, list, NODE_VRF_MAX_ADAPTERS);
	UINT64 luid = 0;

	for (UINT i = 0; i < num && luid == 0; i++)
		if (list[i].VrfId == vrf_id)
			luid = list[i].InterfaceLuid;

	Free(list);

	return luid;
}

// The interface of luid for the family of v6, as GetIpInterfaceEntry reads it: false when the host runs no such family there
static bool NodeExitInterface(MIB_IPINTERFACE_ROW *row, UINT64 luid, bool v6) {
	InitializeIpInterfaceEntry(row);
	row->Family = (ADDRESS_FAMILY)(v6 ? AF_INET6 : AF_INET);
	row->InterfaceLuid.Value = luid;

	return (GetIpInterfaceEntry(row) == NO_ERROR);
}

// The metric of the interface of luid of both families: 0, and no automatic metric, for the default routes of an exit; or the
// automatic metric again. A family that the host does not run there, and an interface that went, are left alone.
static void NodeExitMetric(NODE_EXIT *e, UINT64 luid, bool zero) {
	for (UINT i = 0; i < 2; i++) {
		MIB_IPINTERFACE_ROW row;

		if (NodeExitInterface(&row, luid, i == 1) == false)
			continue;
		if ((row.UseAutomaticMetric == FALSE) == zero && (zero == false || row.Metric == 0))
			continue;

		row.UseAutomaticMetric = (zero ? FALSE : TRUE);
		row.Metric = 0;
		// SetIpInterfaceEntry refuses the site prefix length that GetIpInterfaceEntry gives, as NodeWintunSetForwarding says
		row.SitePrefixLength = 0;
		DWORD err = SetIpInterfaceEntry(&row);
		if (err != NO_ERROR)
			NodeLog(e->Node, "Exit: the %s interface of the adapter cannot take %s (error %u)", i == 0 ? "IPv4" : "IPv6", zero ? "the metric 0" : "its automatic metric again", (UINT)err);
	}
}

// The row of a default route of the family of v6 through the interface of luid: on-link, at the metric 0
static void NodeExitDefaultRow(MIB_IPFORWARD_ROW2 *row, UINT64 luid, bool v6) {
	InitializeIpForwardEntry(row);
	row->InterfaceLuid.Value = luid;
	row->DestinationPrefix.Prefix.si_family = (ADDRESS_FAMILY)(v6 ? AF_INET6 : AF_INET);
	row->DestinationPrefix.PrefixLength = 0;
	row->NextHop.si_family = (ADDRESS_FAMILY)(v6 ? AF_INET6 : AF_INET);
	row->Metric = 0;
	row->Protocol = MIB_IPPROTO_NETMGMT;
}

// Put the default routes of both families on the interface of luid, the adapter of the VRF of the exit, at the metric 0 of the
// interface (e->Lock is held). They are put again with each state: an adapter that came again lost them.
static void NodeExitRoutesOn(NODE_EXIT *e, UINT64 luid) {
	bool fresh = (e->RoutesLuid != luid);
	bool ok[2] = {false, false};

	NodeExitMetric(e, luid, true);

	for (UINT i = 0; i < 2; i++) {
		MIB_IPINTERFACE_ROW iface;
		MIB_IPFORWARD_ROW2 row;
		bool v6 = (i == 1);

		// A family that the host does not run on the adapter has no default route to take over
		if (NodeExitInterface(&iface, luid, v6) == false) {
			ok[i] = true;
			continue;
		}

		NodeExitDefaultRow(&row, luid, v6);
		DWORD err = CreateIpForwardEntry2(&row);
		ok[i] = (err == NO_ERROR || err == ERROR_OBJECT_ALREADY_EXISTS);
		if (ok[i] == false)
			NodeLog(e->Node, "Exit %s: the default route %s cannot go through the adapter of VRF %u (error %u)", e->Name, v6 ? "::/0" : "0.0.0.0/0", e->VrfId, (UINT)err);
	}

	e->RoutesLuid = luid;
	e->Routes4 = ok[0];
	e->Routes6 = ok[1];

	if (fresh)
		NodeLog(e->Node, "Exit %s: the default routes 0.0.0.0/0 and ::/0 go through the adapter of VRF %u (interface LUID %I64u) at the metric 0%s", e->Name, e->VrfId, luid,
		        (ok[0] && ok[1]) ? "" : " (not both, see the lines before)");
}

// Take the default routes off the interface that holds them, which takes its automatic metric again (e->Lock is held)
static void NodeExitRoutesOff(NODE_EXIT *e) {
	UINT64 luid = e->RoutesLuid;

	if (luid == 0)
		return;

	for (UINT i = 0; i < 2; i++) {
		MIB_IPFORWARD_ROW2 row;

		NodeExitDefaultRow(&row, luid, i == 1);
		DWORD err = DeleteIpForwardEntry2(&row);
		if (err != NO_ERROR && err != ERROR_NOT_FOUND && err != ERROR_FILE_NOT_FOUND)
			NodeLog(e->Node, "Exit: the default route %s cannot leave the adapter (error %u)", i == 0 ? "0.0.0.0/0" : "::/0", (UINT)err);
	}

	NodeExitMetric(e, luid, false);

	e->RoutesLuid = 0;
	e->Routes4 = false;
	e->Routes6 = false;

	NodeLog(e->Node, "Exit: the default routes left the adapter (interface LUID %I64u)", luid);
}

// Whether the address of size bytes is in the prefix of length bits at prefix
static bool NodeExitInPrefix(const UCHAR *address, const UCHAR *prefix, UINT size, UINT length) {
	UINT bytes = length / 8;
	UINT bits = length % 8;

	if (length > size * 8 || Cmp(address, prefix, bytes) != 0)
		return false;
	if (bits == 0)
		return true;

	UCHAR mask = (UCHAR)(0xFF00 >> bits);

	return ((address[bytes] & mask) == (prefix[bytes] & mask));
}

// The route that the host takes to an address of size bytes without the adapters of the role: of the routes that hold it, the
// one of the longest prefix and of the lowest metric of the route and of its interface; false for none
static bool NodeExitUnderlay(NODE_EXIT *e, const UCHAR *address, UINT size, MIB_IPFORWARD_ROW2 *best) {
	MIB_IPFORWARD_TABLE2 *table = NULL;
	UINT best_metric = 0;
	bool found = false;

	if (GetIpForwardTable2((ADDRESS_FAMILY)(size == 4 ? AF_INET : AF_INET6), &table) != NO_ERROR)
		return false;

	for (ULONG i = 0; i < table->NumEntries; i++) {
		MIB_IPFORWARD_ROW2 *r = &table->Table[i];
		MIB_IPINTERFACE_ROW iface;
		UINT length = r->DestinationPrefix.PrefixLength;

		if (NodeExitInPrefix(address, NodeExitSockBytes(&r->DestinationPrefix.Prefix, size), size, length) == false ||
		    NodeVrfAdaptersHas(e->Adapters, r->InterfaceLuid.Value))
			continue;
		if (found && length < best->DestinationPrefix.PrefixLength)
			continue;

		UINT metric = r->Metric + (NodeExitInterface(&iface, r->InterfaceLuid.Value, size == 16) ? (UINT)iface.Metric : 0);
		if (found && length == best->DestinationPrefix.PrefixLength && metric >= best_metric)
			continue;

		Copy(best, r, sizeof(MIB_IPFORWARD_ROW2));
		best_metric = metric;
		found = true;
	}

	FreeMibTable(table);

	return found;
}

// The bypass routes (e->Lock is held): each server address without one that the host reaches through a default route of another
// interface gets a host route through that interface and its next hop, which the default routes of the adapter do not take over
static void NodeExitBypassOn(NODE_EXIT *e) {
	for (UINT i = 0; i < e->NumServers; i++) {
		NODE_EXIT_SERVER *s = &e->Servers[i];
		MIB_IPFORWARD_ROW2 best;
		char text[64];

		if (s->Routed || NodeExitUnderlay(e, s->Address, s->AddressSize, &best) == false || best.DestinationPrefix.PrefixLength != 0)
			continue;

		MIB_IPFORWARD_ROW2 *r = &s->Route;
		InitializeIpForwardEntry(r);
		r->InterfaceLuid = best.InterfaceLuid;
		r->DestinationPrefix.Prefix.si_family = best.DestinationPrefix.Prefix.si_family;
		Copy(NodeExitSockBytes(&r->DestinationPrefix.Prefix, s->AddressSize), s->Address, s->AddressSize);
		r->DestinationPrefix.PrefixLength = (UINT8)(s->AddressSize * 8);
		r->NextHop = best.NextHop;
		r->Metric = 0;
		r->Protocol = MIB_IPPROTO_NETMGMT;

		DWORD err = CreateIpForwardEntry2(r);
		s->Routed = (err == NO_ERROR);

		NodeExitAddressText(text, sizeof(text), s->Address, s->AddressSize);
		if (s->Routed)
			NodeLog(e->Node, "Exit: the server address %s keeps off the adapter: a host route through the interface LUID %I64u of the default route of the host", text, (UINT64)r->InterfaceLuid.Value);
		else if (err != ERROR_OBJECT_ALREADY_EXISTS)
			NodeLog(e->Node, "Exit: the server address %s has no host route off the adapter (error %u)", text, (UINT)err);
	}
}

// Take the bypass routes away (e->Lock is held)
static void NodeExitBypassOff(NODE_EXIT *e) {
	for (UINT i = 0; i < e->NumServers; i++) {
		NODE_EXIT_SERVER *s = &e->Servers[i];

		if (s->Routed == false)
			continue;

		DWORD err = DeleteIpForwardEntry2(&s->Route);
		if (err != NO_ERROR && err != ERROR_NOT_FOUND && err != ERROR_FILE_NOT_FOUND)
			NodeLog(e->Node, "Exit: a host route of a server address cannot leave (error %u)", (UINT)err);
		s->Routed = false;
	}
}

// Make the routes of the host follow the choice (e->Lock is held): with an exit chosen and the role up, the default routes of
// both families on the adapter of its VRF, after the bypass routes; else neither, and no bypass route
static void NodeExitRoutes(NODE_EXIT *e) {
	UINT64 luid = (e->Chosen && e->Down == false ? NodeExitAdapter(e, e->VrfId) : 0);

	// The interface that held them loses them when another takes them, or none
	if (e->RoutesLuid != 0 && e->RoutesLuid != luid)
		NodeExitRoutesOff(e);

	if (luid == 0) {
		NodeExitBypassOff(e);
		return;
	}

	// The servers keep off the adapter before the default routes come
	NodeExitBypassOn(e);
	NodeExitRoutesOn(e, luid);
}

//
// The exit node of the client role
//

// The exit node of the client role, whose adapters take its default routes; none chosen
NODE_EXIT *NodeExitNew(NODE *n, NODE_VRF_ADAPTERS *adapters) {
	if (n == NULL || adapters == NULL)
		return NULL;

	NODE_EXIT *e = ZeroMalloc(sizeof(NODE_EXIT));
	e->Node = n;
	e->Adapters = adapters;
	e->Lock = NewLock();

	return e;
}

// Free the exit node of the role, once its overlay stopped: the default routes and the bypass routes go first
void NodeExitFree(NODE_EXIT *e) {
	if (e == NULL)
		return;

	Lock(e->Lock);
	{
		NodeExitRoutesOff(e);
		NodeExitBypassOff(e);
	}
	Unlock(e->Lock);

	DeleteLock(e->Lock);
	Free(e);
}

// Take the forwarding tables that the overlay of the role put in place for a state (NodeClient.c calls it with each state, on
// the thread that applied it): their exit nodes are the ones that the role lists, the mark of the chosen one goes into them
// again, since a choice made while they were built marked the tables before them, and the routes of the host follow the
// adapters of the state
void NodeExitApplied(NODE_EXIT *e) {
	if (e == NULL)
		return;

	NODE *n = e->Node;

	Lock(e->Lock);
	{
		UINT before = e->NumExits;

		Lock(n->TableLock);
		{
			NODE_TABLES *t = NodeGetTables(n);
			NODE_EXIT_TABLE *x = (t != NULL && t->Vrfs != NULL ? t->Vrfs->Exit : NULL);

			e->NumExits = (x != NULL ? x->NumExits : 0);
			if (x != NULL) {
				Copy(e->Exits, x->Exits, sizeof(NODE_EXIT_ENTRY) * x->NumExits);
				InterlockedExchange(&x->Chosen, NodeExitIndex(e, x));
			}
		}
		Unlock(n->TableLock);

		if (e->NumExits != before)
			NodeLog(n, "Exit: the state lists %u exit nodes, peers with the default route of a VRF", e->NumExits);

		NodeExitRoutes(e);
	}
	Unlock(e->Lock);
}

// Choose the exit node name: in the VRF vrf_id, or in any VRF (any_vrf) when the forwarding tables in place hold it in one
// only. Its VRF takes the default routes of the host at once. False, with the reason in error, when the tables hold no such
// exit node, or one in several VRFs; the choice before stays.
bool NodeExitChoose(NODE_EXIT *e, const char *name, UINT vrf_id, bool any_vrf, char *error, UINT error_size) {
	UINT matches = 0;
	UINT vrf = 0;

	StrCpy(error, error_size, "");
	if (e == NULL) {
		StrCpy(error, error_size, "this node has no client role to choose an exit node for");
		return false;
	}

	Lock(e->Lock);
	{
		for (UINT i = 0; i < e->NumExits; i++) {
			const NODE_EXIT_ENTRY *x = &e->Exits[i];

			if (StrCmp(x->Name, name) == 0 && (any_vrf || x->VrfId == vrf_id)) {
				vrf = x->VrfId;
				matches++;
			}
		}

		if (matches == 1) {
			e->Chosen = true;
			StrCpy(e->Name, sizeof(e->Name), name);
			e->VrfId = vrf;
			NodeExitMark(e);
			NodeExitRoutes(e);
		}
	}
	Unlock(e->Lock);

	if (matches == 0 && any_vrf)
		Format(error, error_size, "no exit node named %s: an exit node is a peer with the default route of a VRF", name);
	else if (matches == 0)
		Format(error, error_size, "no exit node named %s in VRF %u", name, vrf_id);
	else if (matches > 1)
		Format(error, error_size, "the exit node %s is in %u VRFs: name the VRF too", name, matches);
	else
		NodeLog(e->Node, "Exit: the logged-in user chose the exit node %s in VRF %u", name, vrf);

	return (matches == 1);
}

// Choose no exit node: the traffic of the host leaves directly again
void NodeExitClear(NODE_EXIT *e) {
	bool was;

	if (e == NULL)
		return;

	Lock(e->Lock);
	{
		was = e->Chosen;
		e->Chosen = false;
		StrCpy(e->Name, sizeof(e->Name), "");
		e->VrfId = 0;
		NodeExitMark(e);
		NodeExitRoutes(e);
	}
	Unlock(e->Lock);

	if (was)
		NodeLog(e->Node, "Exit: the logged-in user chose no exit node: the traffic of the host leaves directly again");
}

// The role went down or came up: the routes of an exit leave the host while it is down, and come back once it is up
void NodeExitSetDown(NODE_EXIT *e, bool down) {
	if (e == NULL)
		return;

	Lock(e->Lock);
	{
		e->Down = down;
		NodeExitRoutes(e);
	}
	Unlock(e->Lock);
}

// The address of host:port, an IPv6 host in brackets, into bytes (16 at most) and size: false for a name, or anything else
static bool NodeExitAddress(const char *text, UCHAR *bytes, UINT *size) {
	char host[64];
	const char *start = text;
	const char *end;

	if (IsEmptyStr(text))
		return false;

	if (text[0] == '[') {
		start = text + 1;
		end = strchr(start, ']');
	} else {
		end = strrchr(text, ':');
	}

	UINT len = (end != NULL ? (UINT)(end - start) : StrLen(start));
	if (len == 0 || len >= sizeof(host))
		return false;

	Copy(host, start, len);
	host[len] = 0;

	if (inet_pton(AF_INET, host, bytes) == 1) {
		*size = 4;
		return true;
	}
	if (inet_pton(AF_INET6, host, bytes) == 1) {
		*size = 16;
		return true;
	}

	return false;
}

// A server address of the role: host:port, an IPv6 host in brackets, as TransportRemote writes the other end of a stream. The
// role keeps it, and while the default routes are on the adapter it gets its bypass route at once. A name is left out: the
// stream that connected to it gives its address.
void NodeExitAddServer(NODE_EXIT *e, const char *address) {
	UCHAR bytes[16];
	UINT size = 0;

	if (e == NULL || NodeExitAddress(address, bytes, &size) == false)
		return;

	Lock(e->Lock);
	{
		bool known = false;

		for (UINT i = 0; i < e->NumServers && known == false; i++)
			known = (e->Servers[i].AddressSize == size && Cmp(e->Servers[i].Address, bytes, size) == 0);

		if (known == false && e->NumServers < NODE_EXIT_SERVERS) {
			NODE_EXIT_SERVER *s = &e->Servers[e->NumServers++];

			Zero(s, sizeof(NODE_EXIT_SERVER));
			Copy(s->Address, bytes, size);
			s->AddressSize = size;

			if (e->RoutesLuid != 0)
				NodeExitBypassOn(e);
		}
	}
	Unlock(e->Lock);
}

// A dial of the role starts: a server address without its bypass route tries again for one while the default routes are on
// the adapter, as after a roam whose new default route came later than its address
void NodeExitDial(NODE_EXIT *e) {
	if (e == NULL)
		return;

	Lock(e->Lock);
	{
		if (e->RoutesLuid != 0)
			NodeExitBypassOn(e);
	}
	Unlock(e->Lock);
}

// The role roamed: the bypass routes go, and come again through the default route of the host on the new path
void NodeExitRoam(NODE_EXIT *e) {
	if (e == NULL)
		return;

	Lock(e->Lock);
	{
		if (e->RoutesLuid != 0) {
			NodeExitBypassOff(e);
			NodeExitBypassOn(e);
		}
	}
	Unlock(e->Lock);
}

// Whether the exit node that the user chose is one of the forwarding tables in place (e->Lock is held)
static bool NodeExitAvailable(NODE_EXIT *e) {
	for (UINT i = 0; e->Chosen && i < e->NumExits; i++)
		if (e->Exits[i].VrfId == e->VrfId && StrCmp(e->Exits[i].Name, e->Name) == 0)
			return true;

	return false;
}

// The number of the bypass routes that the role installed (e->Lock is held)
static UINT NodeExitNumBypass(NODE_EXIT *e) {
	UINT num = 0;

	for (UINT i = 0; i < e->NumServers; i++)
		if (e->Servers[i].Routed)
			num++;

	return num;
}

// The exit nodes in the status of the client role on the pipe of the logged-in user, into o: exits, each exit node of the
// forwarding tables in place with its VRF and the families that it carries; exit, the chosen one, whether the default routes
// of both families go through the adapter of its VRF (active) and whether the tables hold it (available), or null; the bypass
// routes and the packets of the host that the exit dropped, by family
void NodeExitJson(NODE_EXIT *e, cJSON *o) {
	cJSON *exits = cJSON_CreateArray();
	cJSON *chosen = NULL;
	UINT bypass = 0;

	if (e != NULL) {
		Lock(e->Lock);
		{
			for (UINT i = 0; i < e->NumExits; i++) {
				const NODE_EXIT_ENTRY *x = &e->Exits[i];
				cJSON *j = cJSON_CreateObject();

				cJSON_AddStringToObject(j, "name", x->Name);
				cJSON_AddNumberToObject(j, "vrf", x->VrfId);
				cJSON_AddStringToObject(j, "vrfName", x->VrfName);
				cJSON_AddBoolToObject(j, "ipv4", x->Ipv4);
				cJSON_AddBoolToObject(j, "ipv6", x->Ipv6);
				cJSON_AddItemToArray(exits, j);
			}

			if (e->Chosen) {
				chosen = cJSON_CreateObject();
				cJSON_AddStringToObject(chosen, "name", e->Name);
				cJSON_AddNumberToObject(chosen, "vrf", e->VrfId);
				cJSON_AddBoolToObject(chosen, "active", e->RoutesLuid != 0 && e->Routes4 && e->Routes6);
				cJSON_AddBoolToObject(chosen, "available", NodeExitAvailable(e));
			}

			bypass = NodeExitNumBypass(e);
		}
		Unlock(e->Lock);
	}

	cJSON_AddItemToObject(o, "exit", chosen != NULL ? chosen : cJSON_CreateNull());
	cJSON_AddItemToObject(o, "exits", exits);
	cJSON_AddNumberToObject(o, "bypassRoutes", bypass);
	cJSON_AddNumberToObject(o, "exitDropped4", (double)(e != NULL ? (UINT64)ReadAcquire64(&e->Dropped4) : 0));
	cJSON_AddNumberToObject(o, "exitDropped6", (double)(e != NULL ? (UINT64)ReadAcquire64(&e->Dropped6) : 0));
}

// The exit node into the status of the client role (NodeClientGetStatus)
void NodeExitGetStatus(NODE_EXIT *e, NODE_CLIENT_STATUS *st) {
	if (e == NULL || st == NULL)
		return;

	Lock(e->Lock);
	{
		st->ExitChosen = e->Chosen;
		StrCpy(st->Exit, sizeof(st->Exit), e->Name);
		st->ExitVrf = e->VrfId;
		st->ExitAvailable = NodeExitAvailable(e);
		st->ExitActive = (e->RoutesLuid != 0 && e->Routes4 && e->Routes6);
		st->NumExits = e->NumExits;
		st->NumBypass = NodeExitNumBypass(e);
	}
	Unlock(e->Lock);

	st->ExitDropped4 = (UINT64)ReadAcquire64(&e->Dropped4);
	st->ExitDropped6 = (UINT64)ReadAcquire64(&e->Dropped6);
}
