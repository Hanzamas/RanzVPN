// NodeVrfAdapter.c
// The Wintun adapters of the VRFs of a node (SDN-5, #181; ADR-0025 decision 3): one adapter for each VRF that the node
// joins, with a fixed requested GUID, the name-based GUID of the node's static key and the VRF id, so a VRF has the same
// interface on the host at every start and the network profile, the firewall rules and the NAT bindings of Windows stay
// attached to it. Each state that the overlay applies reconciles the adapters: a VRF that comes gets its adapter, a VRF
// that stays keeps its adapter with its addresses and routes as they are, and the adapter of a VRF that goes is
// removed. A tunnel restart closes no adapter: the sessions of the overlay come and go, and the adapters and their
// routes stay until their VRF leaves the desired state or their owner frees them.
// - Each adapter holds the node's addresses in its VRF as host addresses, and a route through it to the prefix of each
//   address of the node and of its peers in that VRF and to each route of a peer there, set through IP Helper per
//   adapter (NodeWintun.c). The DNS servers of the owner go on the adapter of the VRF of the node's first address.
// - In a VRF whose IPv4 the host reaches through 4via6, the adapter holds the 4via6 address of each IPv4 address of the
//   node there and a route to the /96 of the 4via6. The stub resolver of overlay DNS answers the zone of each VRF on the
//   addresses of its adapter, and the NRPT sends the names under the suffix of the zone to them (NodeDns.c; SDN-11).
// - The packets of the host's own stack on the adapter of a VRF go into the overlay in that VRF (NodeOverlayInput) on
//   the I/O thread of its adapter queue; a packet of a peer in a VRF goes into the adapter of that VRF
//   (NodeVrfAdaptersSend) on the thread of the overlay, which takes no lock: it counts itself on the place of the
//   adapter, as a sender of the overlay counts itself on a peer, and an adapter goes only once no send is counted.
// - A gateway or an exit forwards: each of its adapters has Forwarding, WeakHostSend and WeakHostReceive on, so the
//   Windows IP stack forwards between the adapter and the other interfaces of the host (ADR-0010 amendment of
//   2026-10-21: Windows IP forwarding only at a gateway's LAN edge, through the VRF's adapter). The adapters of any
//   other node have them off.

#include "Node.h"

#include "Mayaqua/Encrypt.h"
#include "Mayaqua/Internat.h"
#include "Mayaqua/Memory.h"
#include "Mayaqua/Object.h"
#include "Mayaqua/Str.h"

#include "Core/Control.h"

#include "NodeInternal.h"

#include <iphlpapi.h>

// The adapter of one VRF
typedef struct NODE_VRF_ADAPTER {
	NODE *Node;                          // The node
	UINT VrfId;                          // The VRF
	wchar_t Name[NODE_VRF_ADAPTER_NAME]; // The name of the adapter: the name of the set, then the name or the id of the VRF
	GUID Guid;                           // The GUID that the node asked for (NodeVrfAdapterGuid)
	NODE_WINTUN *Wintun;                 // The adapter
	bool Dns;                            // The DNS servers of the set are on it
} NODE_VRF_ADAPTER;

// A place of the set: the adapter of a VRF, one being created, or none. A place keeps the GUID and the LUID of the
// adapter that it held last, so an address change that Windows reports for an interface that goes is the node's own.
typedef struct NODE_VRF_SLOT {
	volatile UINT VrfId;                // The VRF of the adapter, which a send compares before it counts itself
	NODE_VRF_ADAPTER *volatile Adapter; // The adapter, NULL while the place holds none or one being created
	volatile LONG Senders;              // Calls of NodeVrfAdaptersSend that put a packet into the adapter now
	bool Used;                          // The place holds an adapter or one being created
	GUID Guid;                          // The GUID of that adapter
	UINT64 Luid;                        // The LUID of its interface, 0 while it is created
} NODE_VRF_SLOT;

// The adapters of the VRFs of a node
struct NODE_VRF_ADAPTERS {
	NODE *Node;                                 // The node
	wchar_t Name[MAX_SIZE];                     // What the name of each adapter begins with
	UCHAR Key[PEER_KEY_SIZE];                   // The node's static key, which names the GUID of each adapter with its VRF id
	bool Forwarding;                            // The node is a gateway or an exit
	char Dns[MAX_SIZE];                         // The DNS servers of the owner, comma-separated, empty for none
	char Suffix[MAX_SIZE];                      // ... and its DNS suffix, empty for none
	LOCK *Lock;                                 // States, Halt and Free, one at a time
	bool Halted;                                // The packets of the host stop: an adapter that comes carries none
	SRWLOCK InfoLock;                           // Used, Guid and Luid of the places, and the publication of an adapter
	NODE_VRF_SLOT Slots[NODE_VRF_MAX_ADAPTERS]; // The places
	NODE_DNS *Resolver;                         // Overlay DNS of the VRFs on the addresses of their adapters (NodeDns.c; SDN-11, #187)
};

// The GUID that the node of the static key key asks for the adapter of the VRF vrf_id: a name-based GUID (RFC 4122
// section 4.3) of the SHA-256 of NODE_VRF_ADAPTER_LABEL, the key and the VRF id (4 bytes, big-endian). The same node and
// VRF give the same interface on every start; another node or another VRF gives another.
void NodeVrfAdapterGuid(GUID *guid, const UCHAR *key, UINT vrf_id) {
	UCHAR name[sizeof(NODE_VRF_ADAPTER_LABEL) - 1 + PEER_KEY_SIZE + 4];
	UCHAR hash[SHA256_SIZE];
	UINT label = sizeof(NODE_VRF_ADAPTER_LABEL) - 1;

	Copy(name, NODE_VRF_ADAPTER_LABEL, label);
	Copy(name + label, key, PEER_KEY_SIZE);
	WRITE_UINT(name + label + PEER_KEY_SIZE, vrf_id);
	Sha2_256(hash, name, sizeof(name));

	Copy(guid, hash, sizeof(GUID));
	guid->Data3 = (USHORT)((guid->Data3 & 0x0FFF) | 0x5000);
	guid->Data4[0] = (UCHAR)((guid->Data4[0] & 0x3F) | 0x80);
}

// The adapters of the VRFs of a node, none before the first state: name is what the name of each begins with, key the
// node's static key, and forwarding whether the node is a gateway or an exit. NULL when wintun.dll is missing (the node
// log says why).
NODE_VRF_ADAPTERS *NodeVrfAdaptersNew(NODE *n, const wchar_t *name, const UCHAR *key, bool forwarding) {
	UINT error = 0;

	if (n == NULL || UniIsEmptyStr(name) || key == NULL)
		return NULL;

	if (NodeWintunAvailable(&error) == false) {
		NodeLog(n, "VRF adapters %S: none: %S cannot be loaded (error %u)", name, NODE_WINTUN_DLL, error);
		return NULL;
	}

	NODE_VRF_ADAPTERS *a = ZeroMalloc(sizeof(NODE_VRF_ADAPTERS));
	a->Node = n;
	UniStrCpy(a->Name, sizeof(a->Name), name);
	Copy(a->Key, key, PEER_KEY_SIZE);
	a->Forwarding = forwarding;
	a->Lock = NewLock();
	InitializeSRWLock(&a->InfoLock);
	a->Resolver = NodeDnsNew(n, key);

	NodeLog(n, "VRF adapters %S: one Wintun adapter per VRF of the state%s", name, forwarding ? ", forwarding as a gateway or an exit" : "");

	return a;
}

// Remove the adapter of a place: no reader of the places finds it any more, and once no send is counted on it, it goes
// with its addresses and routes. The caller holds the lock of the set.
static void NodeVrfAdapterRemove(NODE_VRF_ADAPTERS *a, NODE_VRF_SLOT *s) {
	AcquireSRWLockExclusive(&a->InfoLock);
	NODE_VRF_ADAPTER *v = (NODE_VRF_ADAPTER *)InterlockedExchangePointer((PVOID volatile *)&s->Adapter, NULL);
	s->Used = false;
	ReleaseSRWLockExclusive(&a->InfoLock);

	if (v == NULL)
		return;

	// The exchange is a full barrier, as the count of a sender is: either the sender reads no adapter, or the wait below
	// sees it counted and waits for its send
	while (ReadAcquire(&s->Senders) != 0)
		Sleep(1);

	NodeWintunFree(v->Wintun);
	Free(v);
}

// Remove every adapter. The overlay of the owner is stopped: no send comes any more.
void NodeVrfAdaptersFree(NODE_VRF_ADAPTERS *a) {
	UINT num = 0;

	if (a == NULL)
		return;

	// The stub resolver and the NRPT rules go before the addresses that they name
	NodeDnsFree(a->Resolver);

	Lock(a->Lock);
	{
		for (UINT i = 0; i < NODE_VRF_MAX_ADAPTERS; i++) {
			NODE_VRF_SLOT *s = &a->Slots[i];

			if (s->Adapter == NULL)
				continue;

			NodeVrfAdapterRemove(a, s);
			num++;
		}
	}
	Unlock(a->Lock);

	NodeLog(a->Node, "VRF adapters %S: %u removed", a->Name, num);

	DeleteLock(a->Lock);
	Free(a);
}

// Stop the packets of the host into the overlay: the adapter queue of each adapter is detached and its I/O thread
// joined, and an adapter that a later state brings up carries no packet. The adapters stay. The owner calls it first
// thing in NodeOverlayStop (NODE_ADAPTER_STOP_PROC).
void NodeVrfAdaptersHalt(NODE_VRF_ADAPTERS *a) {
	if (a == NULL)
		return;

	Lock(a->Lock);
	{
		a->Halted = true;

		for (UINT i = 0; i < NODE_VRF_MAX_ADAPTERS; i++) {
			NODE_VRF_ADAPTER *v = a->Slots[i].Adapter;

			if (v != NULL)
				NodeWintunHalt(v->Wintun);
		}
	}
	Unlock(a->Lock);
}

// The DNS servers (comma-separated, empty for none) and the DNS suffix that the adapter of the VRF of the node's first
// address takes (NodeWintunSetDns)
void NodeVrfAdaptersSetDns(NODE_VRF_ADAPTERS *a, const char *servers, const char *suffix) {
	if (a == NULL)
		return;

	Lock(a->Lock);
	{
		StrCpy(a->Dns, sizeof(a->Dns), servers != NULL ? servers : "");
		StrCpy(a->Suffix, sizeof(a->Suffix), suffix != NULL ? suffix : "");
	}
	Unlock(a->Lock);
}

// A packet of the host's own stack from the adapter of a VRF, on the I/O thread of its adapter queue: into the overlay
// in that VRF
static void NodeVrfAdapterFromHost(NODE_WINTUN *w, void *param, const UCHAR *packet, UINT size) {
	NODE_VRF_ADAPTER *v = (NODE_VRF_ADAPTER *)param;

	NodeOverlayInput(v->Node, v->VrfId, packet, size);
}

// Bring up the adapter of the VRF vrf_id (vrf_name: its name in the state, NULL for none) in a free place: its name,
// the GUID of the node and the VRF, the forwarding of the set, and the packets of the host into the overlay unless the
// set is halted. False when every place is taken or the adapter cannot come up.
static bool NodeVrfAdapterAdd(NODE_VRF_ADAPTERS *a, UINT vrf_id, const char *vrf_name) {
	NODE_VRF_SLOT *s = NULL;

	for (UINT i = 0; i < NODE_VRF_MAX_ADAPTERS && s == NULL; i++)
		if (a->Slots[i].Used == false)
			s = &a->Slots[i];

	if (s == NULL) {
		NodeLog(a->Node, "VRF adapters %S: no adapter for VRF %u: the node has %u already", a->Name, vrf_id, (UINT)NODE_VRF_MAX_ADAPTERS);
		return false;
	}

	NODE_VRF_ADAPTER *v = ZeroMalloc(sizeof(NODE_VRF_ADAPTER));
	v->Node = a->Node;
	v->VrfId = vrf_id;
	if (IsEmptyStr(vrf_name) == false)
		UniFormat(v->Name, sizeof(v->Name), L"%s %S", a->Name, vrf_name);
	else
		UniFormat(v->Name, sizeof(v->Name), L"%s %u", a->Name, vrf_id);
	NodeVrfAdapterGuid(&v->Guid, a->Key, vrf_id);

	// The GUID is known before the adapter: an address that Windows puts on the new interface is the node's own
	AcquireSRWLockExclusive(&a->InfoLock);
	s->Used = true;
	s->VrfId = vrf_id;
	s->Guid = v->Guid;
	s->Luid = 0;
	ReleaseSRWLockExclusive(&a->InfoLock);

	v->Wintun = NodeWintunNewGuid(a->Node, v->Name, &v->Guid, a->Halted ? NULL : NodeVrfAdapterFromHost, v);
	if (v->Wintun == NULL) {
		AcquireSRWLockExclusive(&a->InfoLock);
		s->Used = false;
		ReleaseSRWLockExclusive(&a->InfoLock);

		Free(v);
		return false;
	}

	NodeWintunSetForwarding(v->Wintun, a->Forwarding);

	AcquireSRWLockExclusive(&a->InfoLock);
	s->Luid = NodeWintunLuid(v->Wintun);
	InterlockedExchangePointer((PVOID volatile *)&s->Adapter, v);
	ReleaseSRWLockExclusive(&a->InfoLock);

	return true;
}

// The place of the adapter of the VRF vrf_id, NULL for none. The caller holds the lock of the set.
static NODE_VRF_SLOT *NodeVrfAdapterSlot(NODE_VRF_ADAPTERS *a, UINT vrf_id) {
	for (UINT i = 0; i < NODE_VRF_MAX_ADAPTERS; i++) {
		NODE_VRF_SLOT *s = &a->Slots[i];

		if (s->Adapter != NULL && s->Adapter->VrfId == vrf_id)
			return s;
	}

	return NULL;
}

// Add the VRF vrf_id to the num VRFs of a state, once, with its name (NULL for none, a later name of it fills it)
static void NodeVrfAdapterAddVrf(UINT *vrfs, const char **names, UINT *num, UINT vrf_id, const char *name) {
	for (UINT i = 0; i < *num; i++) {
		if (vrfs[i] == vrf_id) {
			if (names[i] == NULL)
				names[i] = name;
			return;
		}
	}

	if (*num >= NODE_VRF_MAX_ADAPTERS)
		return;

	vrfs[*num] = vrf_id;
	names[*num] = name;
	(*num)++;
}

// Whether vrf_id is one of the num VRFs
static bool NodeVrfAdapterIn(const UINT *vrfs, UINT num, UINT vrf_id) {
	for (UINT i = 0; i < num; i++)
		if (vrfs[i] == vrf_id)
			return true;

	return false;
}

// Add the prefix of length bits of the address of size bytes to the num routes of an adapter, its host bits cleared,
// once. A /0 is no route of a VRF: a default route through an adapter comes with the exit node of the tray (SDN-55,
// #248).
static void NodeVrfAdapterRoute(NODE_PREFIX *routes, UINT *num, const UCHAR *address, UINT size, UINT length) {
	NODE_PREFIX p;

	if ((size != 4 && size != 16) || length == 0 || length > size * 8 || *num >= NODE_WINTUN_MAX_ROUTES)
		return;

	Zero(&p, sizeof(p));
	Copy(p.Address, address, size);
	p.AddressSize = size;
	p.Length = length;
	for (UINT i = length / 8; i < size; i++)
		p.Address[i] &= (UCHAR)(i == length / 8 ? (0xFF00 >> (length % 8)) : 0);

	for (UINT i = 0; i < *num; i++)
		if (routes[i].AddressSize == p.AddressSize && routes[i].Length == p.Length && Cmp(routes[i].Address, p.Address, p.AddressSize) == 0)
			return;

	routes[(*num)++] = p;
}

// The 4via6 of the VRF vrf_id on its adapter (ADR-0025 decision 4; SDN-6, #182): when the state st gives the node the
// 4via6 of the VRF, the adapter holds the 4via6 address of each IPv4 address of the node there, which the host sends
// from and the stub resolver of overlay DNS listens on (NodeDns.c; SDN-11, #187) in place of an IPv4 address that
// another VRF of the host may hold too, and a route to the /96 of the 4via6
static void NodeVrfAdapterVia6(UINT vrf_id, const CONTROL_STATE *st, NODE_PREFIX *addrs, UINT *num_addrs, NODE_PREFIX *routes, UINT *num_routes) {
	UCHAR prefix[16];

	Zero(prefix, sizeof(prefix));
	if (NodeDnsVia6(st, vrf_id, prefix) == false)
		return;

	for (UINT i = 0; i < st->NumAddresses && *num_addrs < NODE_WINTUN_MAX_ADDRESSES; i++) {
		const CONTROL_ADDRESS *a = &st->Addresses[i];
		NODE_PREFIX *p = &addrs[*num_addrs];

		if (a->VrfId != vrf_id || a->AddressSize != 4)
			continue;

		Zero(p, sizeof(NODE_PREFIX));
		Copy(p->Address, prefix, 12);
		Copy(p->Address + 12, a->Address, 4);
		p->AddressSize = 16;
		p->Length = 128;
		(*num_addrs)++;
	}

	NodeVrfAdapterRoute(routes, num_routes, prefix, 16, 96);
}

// The addresses and the routes of the VRF of an adapter in a state on that adapter: the node's addresses in the VRF as
// host addresses, and a route to the prefix of each address of the node and of its peers in the VRF and to each route
// of a peer there. False when one could not be set.
static bool NodeVrfAdapterSet(NODE_VRF_ADAPTER *v, const CONTROL_STATE *st) {
	NODE_PREFIX addrs[NODE_WINTUN_MAX_ADDRESSES];
	NODE_PREFIX *routes = ZeroMalloc(sizeof(NODE_PREFIX) * NODE_WINTUN_MAX_ROUTES);
	UINT num_addrs = 0;
	UINT num_routes = 0;

	for (UINT i = 0; i < st->NumAddresses; i++) {
		const CONTROL_ADDRESS *a = &st->Addresses[i];

		if (a->VrfId != v->VrfId || (a->AddressSize != 4 && a->AddressSize != 16))
			continue;

		if (num_addrs < NODE_WINTUN_MAX_ADDRESSES) {
			Zero(&addrs[num_addrs], sizeof(NODE_PREFIX));
			Copy(addrs[num_addrs].Address, a->Address, a->AddressSize);
			addrs[num_addrs].AddressSize = a->AddressSize;
			addrs[num_addrs].Length = a->AddressSize * 8;
			num_addrs++;
		}

		NodeVrfAdapterRoute(routes, &num_routes, a->Address, a->AddressSize, a->Length);
	}

	for (UINT i = 0; i < st->NumPeers; i++) {
		const CONTROL_PEER *p = &st->Peers[i];

		for (UINT j = 0; j < p->NumAddresses; j++)
			if (p->Addresses[j].VrfId == v->VrfId)
				NodeVrfAdapterRoute(routes, &num_routes, p->Addresses[j].Address, p->Addresses[j].AddressSize, p->Addresses[j].Length);

		for (UINT j = 0; j < p->NumRoutes; j++)
			if (p->Routes[j].VrfId == v->VrfId)
				NodeVrfAdapterRoute(routes, &num_routes, p->Routes[j].Address, p->Routes[j].AddressSize, p->Routes[j].Length);
	}

	NodeVrfAdapterVia6(v->VrfId, st, addrs, &num_addrs, routes, &num_routes);

	bool ok = NodeWintunSetAddresses(v->Wintun, addrs, num_addrs);
	ok = NodeWintunSetRoutes(v->Wintun, routes, num_routes) && ok;
	Free(routes);

	return ok;
}

// Reconcile the adapters with a state that the overlay applied: one adapter for each VRF of the state (its Vrf objects
// and the VRFs of the node's addresses), with the addresses and the routes of its VRF. A VRF that stays keeps its
// adapter, whose addresses and routes change only as the state does; the adapter of a VRF that the state leaves out
// goes. The owner calls it from its NODE_STATE_PROC. False when an adapter could not come up or an address or a route
// could not be set; the node log says which, and the next state tries again.
bool NodeVrfAdaptersApply(NODE_VRF_ADAPTERS *a, const CONTROL_STATE *st) {
	UINT vrfs[NODE_VRF_MAX_ADAPTERS];
	const char *names[NODE_VRF_MAX_ADAPTERS];
	UINT num_vrfs = 0;
	UINT num_new = 0;
	UINT num_gone = 0;
	UINT num = 0;
	bool ok = true;

	if (a == NULL || st == NULL)
		return false;

	// The VRFs of the state: its Vrf objects, then the VRFs of the node's addresses that they leave out
	for (UINT i = 0; i < st->NumVrfs; i++)
		NodeVrfAdapterAddVrf(vrfs, names, &num_vrfs, st->Vrfs[i].Id, st->Vrfs[i].Name);
	for (UINT i = 0; i < st->NumAddresses; i++)
		NodeVrfAdapterAddVrf(vrfs, names, &num_vrfs, st->Addresses[i].VrfId, NULL);

	Lock(a->Lock);
	{
		// The adapters of the VRFs that the state left out go
		for (UINT i = 0; i < NODE_VRF_MAX_ADAPTERS; i++) {
			NODE_VRF_SLOT *s = &a->Slots[i];

			if (s->Adapter == NULL || NodeVrfAdapterIn(vrfs, num_vrfs, s->Adapter->VrfId))
				continue;

			NodeVrfAdapterRemove(a, s);
			num_gone++;
		}

		// A VRF without an adapter gets one
		for (UINT i = 0; i < num_vrfs; i++) {
			if (NodeVrfAdapterSlot(a, vrfs[i]) != NULL)
				continue;

			if (NodeVrfAdapterAdd(a, vrfs[i], names[i]))
				num_new++;
			else
				ok = false;
		}

		// Each adapter takes the addresses and the routes of its VRF
		for (UINT i = 0; i < NODE_VRF_MAX_ADAPTERS; i++) {
			NODE_VRF_ADAPTER *v = a->Slots[i].Adapter;

			if (v != NULL) {
				ok = NodeVrfAdapterSet(v, st) && ok;
				num++;
			}
		}

		// The DNS servers of the owner on the adapter of the VRF of the node's first address, once
		NODE_VRF_SLOT *first = (st->NumAddresses != 0 ? NodeVrfAdapterSlot(a, st->Addresses[0].VrfId) : NULL);
		if (first != NULL && first->Adapter->Dns == false && IsEmptyStr(a->Dns) == false) {
			first->Adapter->Dns = NodeWintunSetDns(first->Adapter->Wintun, a->Dns, a->Suffix);
			ok = first->Adapter->Dns && ok;
		}
	}
	Unlock(a->Lock);

	NodeLog(a->Node, "VRF adapters %S: generation %I64u: %u adapters, %u new, %u removed%s", a->Name, st->Generation, num, num_new, num_gone,
	        ok ? "" : " (not all of them set, see the lines before)");

	// Overlay DNS of the VRFs on the addresses of their adapters (NodeDns.c; SDN-11, #187)
	NodeDnsApply(a->Resolver, st);

	return ok;
}

// Put a packet of a peer in the VRF vrf_id into the adapter of that VRF, on the thread of the overlay
// (NODE_ADAPTER_PROC): false when the VRF has no adapter or its ring is full
bool NodeVrfAdaptersSend(NODE_VRF_ADAPTERS *a, UINT vrf_id, const UCHAR *packet, UINT size) {
	if (a == NULL)
		return false;

	for (UINT i = 0; i < NODE_VRF_MAX_ADAPTERS; i++) {
		NODE_VRF_SLOT *s = &a->Slots[i];

		if (s->VrfId != vrf_id || ReadPointerAcquire((PVOID const volatile *)&s->Adapter) == NULL)
			continue;

		// Counted on the place before it reads the adapter, so the adapter does not go under the send
		InterlockedIncrement(&s->Senders);
		NODE_VRF_ADAPTER *v = (NODE_VRF_ADAPTER *)ReadPointerAcquire((PVOID const volatile *)&s->Adapter);
		bool mine = (v != NULL && v->VrfId == vrf_id);
		bool sent = (mine && NodeWintunSend(v->Wintun, packet, size));
		InterlockedDecrement(&s->Senders);

		if (mine)
			return sent;
	}

	return false;
}

// Whether the interface of luid is an adapter of the set: one that is up, one being created or one that went a moment
// ago, by its LUID or by the GUID that the set asked for. The client role leaves the address changes of its own
// adapters out of roaming.
bool NodeVrfAdaptersHas(NODE_VRF_ADAPTERS *a, UINT64 luid) {
	NET_LUID l;
	GUID guid;
	bool has = false;

	if (a == NULL || luid == 0)
		return false;

	l.Value = luid;
	bool known = (ConvertInterfaceLuidToGuid(&l, &guid) == NO_ERROR);

	AcquireSRWLockShared(&a->InfoLock);
	for (UINT i = 0; i < NODE_VRF_MAX_ADAPTERS && has == false; i++) {
		NODE_VRF_SLOT *s = &a->Slots[i];

		has = (s->Luid == luid || (known && Cmp(&s->Guid, &guid, sizeof(GUID)) == 0));
	}
	ReleaseSRWLockShared(&a->InfoLock);

	return has;
}

// The adapters that are up, at most max of them, into list in the order of their VRF ids: their number
UINT NodeVrfAdaptersGetStatus(NODE_VRF_ADAPTERS *a, NODE_VRF_ADAPTER_STATUS *list, UINT max) {
	UINT num = 0;

	if (a == NULL || list == NULL)
		return 0;

	AcquireSRWLockShared(&a->InfoLock);
	for (UINT i = 0; i < NODE_VRF_MAX_ADAPTERS && num < max; i++) {
		NODE_VRF_ADAPTER *v = a->Slots[i].Adapter;
		UINT j = num;

		if (v == NULL)
			continue;

		for (; j > 0 && list[j - 1].VrfId > v->VrfId; j--)
			Copy(&list[j], &list[j - 1], sizeof(NODE_VRF_ADAPTER_STATUS));

		NODE_VRF_ADAPTER_STATUS *st = &list[j];
		Zero(st, sizeof(NODE_VRF_ADAPTER_STATUS));
		st->VrfId = v->VrfId;
		UniStrCpy(st->Name, sizeof(st->Name), v->Name);
		st->Guid = v->Guid;
		st->InterfaceIndex = NodeWintunIndex(v->Wintun);
		st->InterfaceLuid = NodeWintunLuid(v->Wintun);
		NodeWintunCounters(v->Wintun, &st->FromHost, &st->ToHost, &st->Dropped);
		num++;
	}
	ReleaseSRWLockShared(&a->InfoLock);

	return num;
}

// Overlay DNS of the VRFs of the set (NodeDns.c), NULL for none
NODE_DNS *NodeVrfAdaptersDns(NODE_VRF_ADAPTERS *a) {
	return (a != NULL ? a->Resolver : NULL);
}
