// NodePolicy.c
// The policy of the VRFs of a node (SDN-8, #184; ADR-0029): the rules that the controller compiles from the Policy
// resources of the intent, enforced by the policy engine of the new core (Core/Policy.h; CORE-S4-2, #75) on the packets
// of the overlay (NodeOverlay.c). The engine runs one Network for each VRF of the node, named after the VRF, with the
// conntrack quota and the timeouts of the VRF, so a VRF that fills its conntrack table takes no room of another. Its
// members are, in each VRF, the host of the node with the tags of the node, each peer in the VRF with the tags of the
// peer, and the end outside the VRF, which has no tag: a peer that is no member of the VRF, as a route that another VRF
// leaks leads to (ADR-0029 decision 6: a leak is reachability, not a firewall bypass).
//
// Each Generation that the overlay applies gets a document of rules (NodePolicyDocument), which the engine puts in
// force before the forwarding tables of the Generation go in, and a policy table, which rides on those tables
// (NodePolicyAttach): the members of the host and of each next hop in each VRF, which the data path reads without a
// lock. A member stays while a table holds it, so a peer that keeps its VRFs and its tags keeps its flows from one
// Generation to the next, and the new rules judge each of them again on its next packet, as the engine does after
// every document. When the swap of a Generation fails, the document of the tables in force goes back in force.
//
// A packet of the host on its way to a peer (NodePolicyOutbound) and a packet of a peer on its way to the host
// (NodePolicyInbound) are judged as the overlay sees them: after the 1:1 NAT rules on the way out, before them on the
// way in. So each end of a flow judges it on its first packet, default deny, and the replies of an allowed flow pass
// on the conntrack fast path at both ends. A VRF of a state without its policy (the controller sends one with every
// VRF; the vpntest harness may leave it out) forwards as the overlay did before SDN-8, as the starter rule does. When
// the engine refuses the document of a Generation, the VRFs with a policy drop every packet until a Generation whose
// document it takes: the policy fails closed.
//
// The hub of a VRF of topology hub-and-spoke is where the policy of the VRF decides the traffic between two spokes
// (NodePolicyTransit; SDN-19-R2, #508). A spoke sees the hub as the other end of every packet of another spoke, and the
// hub sees both real ends, as both are its peers: it judges each packet that it sends on from one spoke to another
// before it sends it, with the same engine and the same rules as a packet of its host, by the member of the peer that
// sent it and the member of the peer of its next hop. So with no rule between two spokes the default deny of the VRF
// keeps them apart at the hub, whatever the rules between the spokes and the hub let through, and the replies of an
// allowed flow pass on the conntrack fast path of the hub. The destination spoke judges such a packet as a packet of
// the hub, the trust anchor of the topology, whose policy it passed.

#include "Node.h"

#include "Mayaqua/IpAddr.h"
#include "Mayaqua/Memory.h"
#include "Mayaqua/Object.h"
#include "Mayaqua/Str.h"

#include "Core/Control.h"
#include "Core/Policy.h"

#include <cjson/cJSON.h>

#include <stdlib.h>

#include "NodeInternal.h"

#define NODE_POLICY_MEMBERS 8192 // Members of the engine of a node at most: the host, the end outside and the peers of each VRF

// The kinds of a member of the engine
#define NODE_POLICY_HOST    0 // The host of the node
#define NODE_POLICY_PEER    1 // A peer
#define NODE_POLICY_OUTSIDE 2 // The end outside the VRF: a peer that is no member of it

// The kind of the member of a WireGuard Device (SDN-80, #375): a member of its own in its VRF at every node, with its tags,
// found by its addresses, so a Device is never taken for the host of its gateway nor for the peer that is its gateway
#define NODE_POLICY_WIREGUARD 3

// The kind of the member of a source group (SDN-87, #386): one in a VRF for each group that a peer of the VRF may assert,
// with the tags of the group, which judges a packet that carried that group where the map of address to group gives
// another (NodeSourceGroup.c)
#define NODE_POLICY_GROUP 4

// A member of the engine in one VRF
typedef struct NODE_POLICY_MEMBER {
	UINT VrfId;                                     // The VRF
	char Vrf[CONTROL_NAME_SIZE];                    // ... and its name: the Network of the engine
	UINT Kind;                                      // NODE_POLICY_HOST, NODE_POLICY_PEER or NODE_POLICY_OUTSIDE
	char Peer[CONTROL_NAME_SIZE];                   // The peer, empty for another kind
	UCHAR Key[PEER_KEY_SIZE];                       // ... and its static key
	UINT NumTags;                                   // Its tags
	char Tags[CONTROL_MAX_TAGS][CONTROL_NAME_SIZE]; // ...
	UINT Member;                                    // Its number in the engine, POLICY_NO_MEMBER when the engine had no room
	UINT Refs;                                      // The policy tables that hold it
} NODE_POLICY_MEMBER;

// The policy of the overlay of a node, while the overlay runs
struct NODE_POLICY {
	LOCK *Lock;              // Members, Live and Pending
	POLICY_ENGINE *Engine;   // The engine, NULL when it could not start
	LIST *Members;           // Its members (NODE_POLICY_MEMBER)
	NODE_CLOCK_PROC *Clock;  // The time of the flows, NULL for GetTickCount64 ...
	void *ClockParam;        // ... and its second parameter
	char *Live;              // The document of the tables in force, NULL before the first
	char *Pending;           // The document that NodePolicyAttach put in force for a Generation that is not in yet
	volatile LONG64 Dropped; // Packets that the policy dropped
};

// One address of a WireGuard Device of a VRF of a policy table (SDN-80, #375): 4 bytes for IPv4, 16 for IPv6, the member
// of the Device, and whether the node is its gateway, where the Device is the end of a flow at the host
typedef struct NODE_POLICY_DEVICE {
	UCHAR Address[16];
	UINT Size;
	UINT Member;
	bool Local;
	UINT Group; // Its source group (SDN-87, #386), 0 for none
} NODE_POLICY_DEVICE;

// The member of one source group of a VRF of a policy table (SDN-87, #386)
typedef struct NODE_POLICY_GROUP_MEMBER {
	UINT Group;
	UINT Member;
} NODE_POLICY_GROUP_MEMBER;

// One VRF of a policy table
typedef struct NODE_POLICY_VRF {
	UINT VrfId;   // The VRF
	UINT Host;    // The member of the host
	UINT Outside; // The member of the end outside the VRF
	UINT *Hops;   // The member of each next hop: its peer in the VRF, or Outside

	// The WireGuard Devices of the VRF, one entry for each of their addresses
	UINT NumDevices;
	NODE_POLICY_DEVICE *Devices;

	// The source groups of the VRF (SDN-87, #386): the group of the peer of each next hop, 0 for none, and the member of
	// each group that a peer may assert
	UINT *HopGroups;
	UINT NumGroups;
	NODE_POLICY_GROUP_MEMBER *Groups;
} NODE_POLICY_VRF;

// The policy table of one Generation, on its forwarding tables (NODE_VRF_TABLES)
struct NODE_POLICY_TABLE {
	NODE_POLICY *Policy;                    // The policy of the node, which outlives its tables
	bool Closed;                            // The engine refused the document of the Generation: its VRFs drop every packet
	UINT NumHops;                           // The next hops of the Generation: the peers of its state
	UINT NumVrfs;                           // The VRFs with a policy ...
	NODE_POLICY_VRF Vrfs[CONTROL_MAX_VRFS]; // ... by VRF id
	UINT NumRefs;                           // The members that the table holds ...
	NODE_POLICY_MEMBER **Refs;              // ...
};

// The time of the flows of a policy
static UINT64 NodePolicyNow(NODE *n, NODE_POLICY *p) {
	return (p->Clock != NULL ? p->Clock(n, p->ClockParam) : GetTickCount64());
}

// Whether a member has the tags
static bool NodePolicySameTags(const NODE_POLICY_MEMBER *m, const char (*tags)[CONTROL_NAME_SIZE], UINT num) {
	if (m->NumTags != MIN(num, CONTROL_MAX_TAGS))
		return false;

	for (UINT i = 0; i < m->NumTags; i++)
		if (StrCmp(m->Tags[i], tags[i]) != 0)
			return false;

	return true;
}

// The number of the member of kind in the VRF cv, the peer cp for NODE_POLICY_PEER, with the tags, which the table that
// is built holds from now on (refs): the member that the policy has, or a new one. POLICY_NO_MEMBER when the engine has
// no room. The caller holds the lock.
static UINT NodePolicyHold(NODE_POLICY *p, LIST *refs, const CONTROL_VRF *cv, UINT kind, const CONTROL_PEER *cp, const char (*tags)[CONTROL_NAME_SIZE], UINT num_tags) {
	NODE_POLICY_MEMBER *m = NULL;

	for (UINT i = 0; i < LIST_NUM(p->Members) && m == NULL; i++) {
		NODE_POLICY_MEMBER *e = LIST_DATA(p->Members, i);

		if (e->VrfId == cv->Id && e->Kind == kind && StrCmp(e->Vrf, cv->Name) == 0 && NodePolicySameTags(e, tags, num_tags) &&
		    (cp == NULL || (StrCmp(e->Peer, cp->Name) == 0 && Cmp(e->Key, cp->Key, PEER_KEY_SIZE) == 0)))
			m = e;
	}

	if (m == NULL) {
		POLICY_MEMBER_CONFIG c;
		const char *ids[CONTROL_MAX_TAGS];

		m = ZeroMalloc(sizeof(NODE_POLICY_MEMBER));
		m->VrfId = cv->Id;
		StrCpy(m->Vrf, sizeof(m->Vrf), cv->Name);
		m->Kind = kind;
		if (cp != NULL) {
			StrCpy(m->Peer, sizeof(m->Peer), cp->Name);
			Copy(m->Key, cp->Key, PEER_KEY_SIZE);
		}
		m->NumTags = MIN(num_tags, CONTROL_MAX_TAGS);
		for (UINT i = 0; i < m->NumTags; i++) {
			StrCpy(m->Tags[i], sizeof(m->Tags[i]), tags[i]);
			ids[i] = m->Tags[i];
		}

		Zero(&c, sizeof(c));
		c.Network = m->Vrf;
		c.Tags = ids;
		c.NumTags = m->NumTags;
		m->Member = (p->Engine != NULL ? PolicyAddMember(p->Engine, &c) : POLICY_NO_MEMBER);
		Add(p->Members, m);
	}

	m->Refs++;
	Add(refs, m);

	return m->Member;
}

// Whether the peer cp shares the VRF vrf_id with the node
static bool NodePolicyShares(const CONTROL_PEER *cp, UINT vrf_id) {
	for (UINT i = 0; i < cp->NumVrfs && i < CONTROL_MAX_VRFS; i++)
		if (cp->VrfIds[i] == vrf_id)
			return true;

	return false;
}

static int NodePolicyCompareVrf(const void *p1, const void *p2) {
	const NODE_POLICY_VRF *v1 = (const NODE_POLICY_VRF *)p1;
	const NODE_POLICY_VRF *v2 = (const NODE_POLICY_VRF *)p2;

	if (v1->VrfId == v2->VrfId)
		return 0;

	return (v1->VrfId < v2->VrfId ? -1 : 1);
}

// The VRF vrf_id of a policy table, NULL when it holds none: the VRF has no policy
static const NODE_POLICY_VRF *NodePolicyFind(const NODE_POLICY_TABLE *t, UINT vrf_id) {
	if (t == NULL)
		return NULL;

	UINT low = 0, high = t->NumVrfs;
	while (low < high) {
		UINT mid = low + (high - low) / 2;
		const NODE_POLICY_VRF *e = &t->Vrfs[mid];

		if (e->VrfId == vrf_id)
			return e;

		if (e->VrfId < vrf_id)
			low = mid + 1;
		else
			high = mid;
	}

	return NULL;
}

// The VRF of a state with its policy by id, NULL for none; the first one of a repeated id counts
static const CONTROL_VRF *NodePolicyVrfOf(const CONTROL_STATE *st, UINT vrf_id) {
	for (UINT i = 0; i < st->NumVrfs && i < CONTROL_MAX_VRFS; i++)
		if (st->Vrfs[i].Id == vrf_id)
			return (st->Vrfs[i].Policy ? &st->Vrfs[i] : NULL);

	return NULL;
}

//
// The document of rules
//

// The order of the rules of a document: by priority, a deny rule before an allow rule of the same priority, then by name
static int NodePolicyCompareRules(const void *p1, const void *p2) {
	const CONTROL_RULE *r1 = *(const CONTROL_RULE *const *)p1;
	const CONTROL_RULE *r2 = *(const CONTROL_RULE *const *)p2;

	if (r1->Priority != r2->Priority)
		return (r1->Priority < r2->Priority ? -1 : 1);
	if (r1->Deny != r2->Deny)
		return (r1->Deny ? -1 : 1);

	return StrCmp(r1->Name, r2->Name);
}

// An end of a rule as an object of the document, NULL for an end that names nothing: any end
static cJSON *NodePolicyEnd(const CONTROL_RULE_END *e) {
	if (e->NumTags == 0 && e->NumPrefixes == 0)
		return NULL;

	cJSON *o = cJSON_CreateObject();
	cJSON *tags = (e->NumTags != 0 ? cJSON_AddArrayToObject(o, "tags") : NULL);
	cJSON *addresses = (e->NumPrefixes != 0 ? cJSON_AddArrayToObject(o, "addresses") : NULL);

	for (UINT i = 0; i < e->NumTags && i < CONTROL_RULE_VALUES; i++)
		cJSON_AddItemToArray(tags, cJSON_CreateString(e->Tags[i]));

	for (UINT i = 0; i < e->NumPrefixes && i < CONTROL_RULE_VALUES; i++) {
		const CONTROL_PREFIX *p = &e->Prefixes[i];
		char addr[MAX_SIZE], prefix[MAX_SIZE];
		IP ip;

		if (p->AddressSize == 4)
			SetIP(&ip, p->Address[0], p->Address[1], p->Address[2], p->Address[3]);
		else
			SetIP6(&ip, p->Address);
		IPToStr(addr, sizeof(addr), &ip);
		Format(prefix, sizeof(prefix), "%s/%u", addr, p->Length);
		cJSON_AddItemToArray(addresses, cJSON_CreateString(prefix));
	}

	return o;
}

// A rule of the VRF vrf as an object of the document
static cJSON *NodePolicyRule(const CONTROL_RULE *r, const char *vrf) {
	cJSON *o = cJSON_CreateObject();
	cJSON *from = NodePolicyEnd(&r->From);
	cJSON *to = NodePolicyEnd(&r->To);

	cJSON_AddStringToObject(o, "name", r->Name);
	cJSON_AddStringToObject(o, "action", r->Deny ? "deny" : "allow");
	cJSON_AddNumberToObject(o, "priority", MIN(r->Priority, 1000000));
	cJSON_AddItemToArray(cJSON_AddArrayToObject(o, "networks"), cJSON_CreateString(vrf));
	if (from != NULL)
		cJSON_AddItemToObject(o, "from", from);
	if (to != NULL)
		cJSON_AddItemToObject(o, "to", to);

	// ICMP is ICMP of the family of each packet, as the protocol 1 of a rule says
	if (r->Protocol == 1)
		cJSON_AddStringToObject(o, "protocol", "icmp");
	else if (r->Protocol != 0)
		cJSON_AddNumberToObject(o, "protocol", MIN(r->Protocol, 255));

	if (r->NumPorts != 0) {
		cJSON *ports = cJSON_AddArrayToObject(o, "ports");

		for (UINT i = 0; i < r->NumPorts && i < CONTROL_RULE_VALUES; i++) {
			char range[32];

			if (r->FirstPort[i] == r->LastPort[i]) {
				cJSON_AddItemToArray(ports, cJSON_CreateNumber(r->FirstPort[i]));
			} else {
				Format(range, sizeof(range), "%u-%u", r->FirstPort[i], r->LastPort[i]);
				cJSON_AddItemToArray(ports, cJSON_CreateString(range));
			}
		}
	}

	return o;
}

// The document of rules of the engine for the state st (Core/Policy.h): a Network for each VRF of the state that has its
// policy, named after it, with its conntrack quota and its timeouts, and the rules of those VRFs, by priority, a deny
// rule before an allow rule of the same priority, then by name. NULL when there is no memory; Free frees it.
char *NodePolicyDocument(const CONTROL_STATE *st) {
	static const char *const keys[] = {"tcpEstablished", "tcpTransitory", "udp", "icmp", "other"};
	char *ret = NULL;

	if (st == NULL)
		return NULL;

	cJSON *root = cJSON_CreateObject();
	cJSON *nets = cJSON_AddArrayToObject(root, "networks");
	cJSON *rules = cJSON_AddArrayToObject(root, "rules");

	for (UINT i = 0; i < st->NumVrfs && i < CONTROL_MAX_VRFS; i++) {
		const CONTROL_VRF *cv = &st->Vrfs[i];
		UINT timeouts[5] = {cv->TcpEstablished, cv->TcpTransitory, cv->Udp, cv->Icmp, cv->Other};

		if (NodePolicyVrfOf(st, cv->Id) != cv)
			continue;

		cJSON *o = cJSON_CreateObject();
		cJSON_AddStringToObject(o, "name", cv->Name);
		cJSON_AddStringToObject(o, "mode", "l3");
		if (cv->MaxFlows != 0)
			cJSON_AddNumberToObject(o, "maxFlows", MIN(cv->MaxFlows, POLICY_MAX_FLOWS));

		if (cv->TcpEstablished != 0 || cv->TcpTransitory != 0 || cv->Udp != 0 || cv->Icmp != 0 || cv->Other != 0) {
			cJSON *t = cJSON_AddObjectToObject(o, "timeouts");

			for (UINT k = 0; k < 5; k++)
				if (timeouts[k] != 0)
					cJSON_AddNumberToObject(t, keys[k], MIN(timeouts[k], 604800));
		}
		cJSON_AddItemToArray(nets, o);
	}

	// The rules of the VRFs with a policy, in the order that the engine keeps for rules of one priority
	const CONTROL_RULE **order = ZeroMalloc(sizeof(CONTROL_RULE *) * MAX(st->NumRules, 1));
	UINT num = 0;
	for (UINT i = 0; i < st->NumRules && st->Rules != NULL; i++)
		if (NodePolicyVrfOf(st, st->Rules[i].VrfId) != NULL)
			order[num++] = &st->Rules[i];
	if (num != 0)
		qsort((void *)order, num, sizeof(CONTROL_RULE *), NodePolicyCompareRules);

	for (UINT i = 0; i < num; i++) {
		const CONTROL_VRF *cv = NodePolicyVrfOf(st, order[i]->VrfId);

		if (cv != NULL)
			cJSON_AddItemToArray(rules, NodePolicyRule(order[i], cv->Name));
	}
	Free((void *)order);

	char *s = (nets != NULL && rules != NULL ? cJSON_PrintUnformatted(root) : NULL);
	if (s != NULL) {
		ret = CopyStr(s);
		cJSON_free(s);
	}
	cJSON_Delete(root);

	return ret;
}

//
// The Generations
//

// Start the policy of the overlay of a node (NodeOverlayStart): its engine, and the clock of the configuration
void NodePolicyStart(NODE *n, const NODE_OVERLAY_CONFIG *cfg) {
	if (n == NULL || cfg == NULL || n->Policy != NULL)
		return;

	NODE_POLICY *p = ZeroMalloc(sizeof(NODE_POLICY));
	p->Lock = NewLock();
	p->Members = NewListFast(NULL);
	p->Engine = PolicyNew(NODE_POLICY_MEMBERS);
	p->Clock = cfg->Clock;
	p->ClockParam = cfg->AdapterParam;

	n->Policy = p;

	if (p->Engine == NULL)
		NodeLog(n, "Policy: the engine could not start, so the VRFs with a policy drop every packet");
}

// Stop the policy of the overlay of a node (NodeOverlayStop), once no forwarding tables are left whose policy tables hold
// its members
void NodePolicyStop(NODE *n) {
	NODE_POLICY *p = (n != NULL ? n->Policy : NULL);

	if (p == NULL)
		return;

	n->Policy = NULL;

	for (UINT i = 0; i < LIST_NUM(p->Members); i++)
		Free(LIST_DATA(p->Members, i));
	ReleaseList(p->Members);
	PolicyFree(p->Engine);
	Free(p->Live);
	Free(p->Pending);
	DeleteLock(p->Lock);
	Free(p);
}

// The members of the WireGuard Devices of the VRF cv of the state st, which the table that is built holds from now on
// (refs): one entry for each address of each Device, its number in num, NULL for none. A Device is a member of its own,
// named after it, with its tags and, at its gateway, its key. The caller holds the lock.
static NODE_POLICY_DEVICE *NodePolicyDevices(NODE_POLICY *p, LIST *refs, const CONTROL_VRF *cv, const CONTROL_STATE *st, UINT *num) {
	NODE_POLICY_DEVICE *list = NULL;
	CONTROL_PEER *who = NULL;

	*num = 0;

	for (UINT i = 0; i < st->NumDevices && st->Devices != NULL; i++) {
		const CONTROL_DEVICE *d = &st->Devices[i];

		if (d->VrfId != cv->Id || d->NumAddresses == 0)
			continue;

		if (list == NULL) {
			list = ZeroMalloc(sizeof(NODE_POLICY_DEVICE) * CONTROL_DEVICE_ADDRESSES * st->NumDevices);
			who = ZeroMalloc(sizeof(CONTROL_PEER));
		}

		Zero(who, sizeof(CONTROL_PEER));
		StrCpy(who->Name, sizeof(who->Name), d->Name);
		if (d->HasKey)
			Copy(who->Key, d->Key, PEER_KEY_SIZE);
		UINT member = NodePolicyHold(p, refs, cv, NODE_POLICY_WIREGUARD, who, d->Tags, d->NumTags);

		for (UINT j = 0; j < d->NumAddresses && j < CONTROL_DEVICE_ADDRESSES; j++) {
			NODE_POLICY_DEVICE *e = &list[(*num)++];

			Copy(e->Address, d->Addresses[j].Address, d->Addresses[j].AddressSize);
			e->Size = d->Addresses[j].AddressSize;
			e->Member = member;
			e->Local = d->HasKey;
			e->Group = d->Group;
		}
	}

	if (who != NULL)
		Free(who);

	return list;
}

// The source group of the peer cp in the VRF vrf_id (SDN-87, #386), 0 for none
static UINT NodePolicyPeerGroup(const CONTROL_PEER *cp, UINT vrf_id) {
	for (UINT i = 0; i < cp->NumGroups && i < CONTROL_MAX_VRFS; i++)
		if (cp->Groups[i].VrfId == vrf_id)
			return cp->Groups[i].Group;

	return 0;
}

// The member of the source group group of the VRF cv, with the tags of the group, into the num groups of list, unless it
// holds that group already; the table that is built holds it from now on (refs). The caller holds the lock.
static void NodePolicyAddGroup(NODE_POLICY *p, LIST *refs, const CONTROL_VRF *cv, NODE_POLICY_GROUP_MEMBER *list, UINT *num, UINT group, const char (*tags)[CONTROL_NAME_SIZE], UINT num_tags) {
	for (UINT i = 0; i < *num; i++)
		if (list[i].Group == group)
			return;

	NODE_POLICY_GROUP_MEMBER *e = &list[(*num)++];
	e->Group = group;
	e->Member = NodePolicyHold(p, refs, cv, NODE_POLICY_GROUP, NULL, tags, num_tags);
}

// The source groups of the VRF cv of the state st into its entry e of the table that is built (SDN-87, #386): the group of
// the peer of each next hop, and a member for each group that a peer may assert, its own or that of a Device whose
// gateway it is, with the tags of the group. A group stands for one set of tags, so two endpoints of one group share its
// member. The caller holds the lock.
static void NodePolicyGroups(NODE_POLICY *p, LIST *refs, const CONTROL_VRF *cv, const CONTROL_STATE *st, NODE_POLICY_VRF *e) {
	UINT max = (st->Devices != NULL ? st->NumDevices : 0);

	e->HopGroups = ZeroMalloc(sizeof(UINT) * MAX(st->NumPeers, 1));
	for (UINT i = 0; i < st->NumPeers; i++) {
		e->HopGroups[i] = NodePolicyPeerGroup(&st->Peers[i], cv->Id);
		max += MIN(st->Peers[i].NumGroups, CONTROL_MAX_VRFS);
	}

	e->NumGroups = 0;
	e->Groups = ZeroMalloc(sizeof(NODE_POLICY_GROUP_MEMBER) * MAX(max, 1));
	for (UINT i = 0; i < st->NumPeers; i++) {
		const CONTROL_PEER *cp = &st->Peers[i];
		UINT group = e->HopGroups[i];

		if (group != 0)
			NodePolicyAddGroup(p, refs, cv, e->Groups, &e->NumGroups, group, cp->Tags, cp->NumTags);
	}
	for (UINT i = 0; i < st->NumDevices && st->Devices != NULL; i++) {
		const CONTROL_DEVICE *d = &st->Devices[i];

		if (d->VrfId == cv->Id && d->Group != 0)
			NodePolicyAddGroup(p, refs, cv, e->Groups, &e->NumGroups, d->Group, d->Tags, d->NumTags);
	}
}

// The member of the source group group of the VRF e, POLICY_NO_MEMBER for a group that no peer of the VRF may assert
static UINT NodePolicyGroupMember(const NODE_POLICY_VRF *e, UINT group) {
	for (UINT i = 0; i < e->NumGroups; i++)
		if (e->Groups[i].Group == group)
			return e->Groups[i].Member;

	return POLICY_NO_MEMBER;
}

// The policy table of the Generation of st onto its forwarding tables v, before they go in: in each VRF of the state that
// has its policy, the members of the host, of the end outside and of each next hop, which the table holds; and the
// document of rules of the state, put in force in the engine, under which the tables before go on until the swap
void NodePolicyAttach(NODE *n, NODE_VRF_TABLES *v, const CONTROL_STATE *st) {
	NODE_POLICY *p = (n != NULL ? n->Policy : NULL);
	char error[MAX_SIZE];

	if (p == NULL || v == NULL || st == NULL)
		return;

	NODE_POLICY_TABLE *t = ZeroMalloc(sizeof(NODE_POLICY_TABLE));
	LIST *refs = NewListFast(NULL);

	t->Policy = p;
	t->NumHops = st->NumPeers;

	Lock(p->Lock);
	{
		for (UINT i = 0; i < st->NumVrfs && i < CONTROL_MAX_VRFS; i++) {
			const CONTROL_VRF *cv = &st->Vrfs[i];

			if (NodePolicyVrfOf(st, cv->Id) != cv)
				continue;

			NODE_POLICY_VRF *e = &t->Vrfs[t->NumVrfs++];
			e->VrfId = cv->Id;
			e->Host = NodePolicyHold(p, refs, cv, NODE_POLICY_HOST, NULL, st->Tags, st->NumTags);
			e->Outside = NodePolicyHold(p, refs, cv, NODE_POLICY_OUTSIDE, NULL, NULL, 0);
			e->Hops = ZeroMalloc(sizeof(UINT) * MAX(st->NumPeers, 1));
			for (UINT j = 0; j < st->NumPeers; j++) {
				const CONTROL_PEER *cp = &st->Peers[j];

				e->Hops[j] = (NodePolicyShares(cp, cv->Id) ? NodePolicyHold(p, refs, cv, NODE_POLICY_PEER, cp, cp->Tags, cp->NumTags) : e->Outside);
			}
			// The WireGuard Devices of the VRF, by their addresses (SDN-80, #375)
			e->Devices = NodePolicyDevices(p, refs, cv, st, &e->NumDevices);
			// The source groups of the VRF (SDN-87, #386)
			NodePolicyGroups(p, refs, cv, st, e);
		}
	}
	Unlock(p->Lock);

	qsort(t->Vrfs, t->NumVrfs, sizeof(NODE_POLICY_VRF), NodePolicyCompareVrf);

	t->NumRefs = LIST_NUM(refs);
	t->Refs = (NODE_POLICY_MEMBER **)ToArray(refs);
	ReleaseList(refs);

	// The rules of the Generation, in force before its tables go in; a state without a VRF with a policy leaves the
	// engine as it is
	if (t->NumVrfs != 0) {
		char *json = NodePolicyDocument(st);
		bool ok = (p->Engine != NULL && json != NULL && PolicySetRules(p->Engine, json, StrLen(json), error, sizeof(error)));

		if (ok) {
			NodeLog(n, "Policy: generation %I64u: the rules of %u VRFs are in force, %u rules", st->Generation, t->NumVrfs, st->NumRules);
		} else {
			t->Closed = true;
			NodeLog(n, "Policy: generation %I64u: the engine refused its rules (%s), so its VRFs with a policy drop every packet", st->Generation,
			        (json == NULL || p->Engine == NULL) ? "no memory" : error);
			Free(json);
			json = NULL;
		}

		Lock(p->Lock);
		Free(p->Pending);
		p->Pending = json;
		Unlock(p->Lock);
	}

	NodePolicyFreeTable(v->Policy);
	v->Policy = t;
}

// The Generation that NodePolicyAttach went with went in (swapped), or its swap failed and the tables before stay: their
// document goes back in force
void NodePolicyApplied(NODE *n, bool swapped) {
	NODE_POLICY *p = (n != NULL ? n->Policy : NULL);
	char *again = NULL;

	if (p == NULL)
		return;

	Lock(p->Lock);
	{
		if (p->Pending != NULL && swapped) {
			Free(p->Live);
			p->Live = p->Pending;
		} else if (p->Pending != NULL) {
			Free(p->Pending);
			again = (p->Live != NULL ? CopyStr(p->Live) : NULL);
		}
		p->Pending = NULL;
	}
	Unlock(p->Lock);

	if (again != NULL && PolicySetRules(p->Engine, again, StrLen(again), NULL, 0) == false)
		NodeLog(n, "Policy: the rules of the tables in force could not go back in force");
	Free(again);
}

// Free a policy table: a member that no table holds any more leaves the engine, with its flows
void NodePolicyFreeTable(NODE_POLICY_TABLE *t) {
	if (t == NULL)
		return;

	NODE_POLICY *p = t->Policy;
	LIST *gone = NewListFast(NULL);

	Lock(p->Lock);
	{
		for (UINT i = 0; i < t->NumRefs; i++) {
			NODE_POLICY_MEMBER *m = t->Refs[i];

			if (--m->Refs == 0) {
				Delete(p->Members, m);
				Add(gone, m);
			}
		}
	}
	Unlock(p->Lock);

	for (UINT i = 0; i < LIST_NUM(gone); i++) {
		NODE_POLICY_MEMBER *m = LIST_DATA(gone, i);

		if (m->Member != POLICY_NO_MEMBER)
			PolicyDelMember(p->Engine, m->Member);
		Free(m);
	}
	ReleaseList(gone);

	for (UINT i = 0; i < t->NumVrfs; i++) {
		Free(t->Vrfs[i].Hops);
		if (t->Vrfs[i].Devices != NULL)
			Free(t->Vrfs[i].Devices);
		// The source groups (SDN-87, #386)
		Free(t->Vrfs[i].HopGroups);
		Free(t->Vrfs[i].Groups);
	}
	Free(t->Refs);

	Zero(t, sizeof(NODE_POLICY_TABLE));
	Free(t);
}

//
// The packets
//

// The ends of a packet of the VRF e from the host when out is set, whose source or destination is an address of a
// WireGuard Device (SDN-80, #375): a Device that the node terminates is the end at the host in place of the host, any
// other the end at the peer in place of the peer that is its gateway, and its source group the group of that end (SDN-87,
// #386)
static void NodePolicyDeviceEnds(const NODE_POLICY_VRF *e, const UCHAR *packet, UINT size, bool out, UINT *host, UINT *peer, UINT *peer_group) {
	const UCHAR *src, *dst;
	UINT addr_size;

	if (e->NumDevices == 0 || packet == NULL || size < 20)
		return;

	if ((packet[0] >> 4) == 4) {
		addr_size = 4;
		src = packet + 12;
		dst = packet + 16;
	} else if ((packet[0] >> 4) == 6 && size >= 40) {
		addr_size = 16;
		src = packet + 8;
		dst = packet + 24;
	} else {
		return;
	}

	for (UINT i = 0; i < e->NumDevices; i++) {
		const NODE_POLICY_DEVICE *d = &e->Devices[i];

		if (d->Size != addr_size || d->Member == POLICY_NO_MEMBER)
			continue;

		if (d->Local && Cmp(d->Address, out ? src : dst, addr_size) == 0) {
			*host = d->Member;
		} else if (d->Local == false && Cmp(d->Address, out ? dst : src, addr_size) == 0) {
			*peer = d->Member;
			*peer_group = d->Group;
		}
	}
}

// Judge a packet of the VRF vrf_id between the host and the next hop hop of the tables v, from the host when out is set,
// as the overlay sees it, with the source group group that a packet of a peer carried, 0 for none. True when it passes.
// The caller is an online reader of the node's table snapshot, which holds v.
static bool NodePolicyJudge(NODE *n, NODE_VRF_TABLES *v, UINT vrf_id, UINT hop, UINT group, const UCHAR *packet, UINT size, bool out) {
	const NODE_POLICY_TABLE *t = (v != NULL ? v->Policy : NULL);
	const NODE_POLICY_VRF *e = NodePolicyFind(t, vrf_id);

	// A VRF without its policy forwards as the overlay did before SDN-8
	if (e == NULL)
		return true;

	NODE_POLICY *p = t->Policy;
	bool ok = false;

	if (t->Closed == false && p->Engine != NULL) {
		UINT peer = (hop < t->NumHops ? e->Hops[hop] : e->Outside);
		UINT peer_group = (hop < t->NumHops ? e->HopGroups[hop] : 0);
		UINT host = e->Host;

		// A WireGuard Device is an end of its own, found by its address (SDN-80, #375)
		NodePolicyDeviceEnds(e, packet, size, out, &host, &peer, &peer_group);
		// The source group that the packet carried is the end at the peer, unless the map of address to group gives that
		// group already, whose member keeps the flows of the end (SDN-87, #386)
		if (out == false && group != 0 && group != peer_group)
			peer = NodePolicyGroupMember(e, group);
		ok = PolicyInput(p->Engine, NodePolicyNow(n, p), out ? host : peer, out ? peer : host, 0, packet, size, NULL);
	}
	if (ok == false)
		InterlockedIncrement64(&p->Dropped);

	return ok;
}

// A packet of the host in the VRF vrf_id on its way to the next hop hop of the tables v, after the 1:1 NAT rules: true when
// the policy of the VRF lets it through
bool NodePolicyOutbound(NODE *n, NODE_VRF_TABLES *v, UINT vrf_id, UINT hop, const UCHAR *packet, UINT size) {
	return NodePolicyJudge(n, v, vrf_id, hop, 0, packet, size, true);
}

// A packet of the next hop hop of the tables v in the VRF vrf_id on its way to the host, before the 1:1 NAT rules: true
// when the policy of the VRF lets it through
bool NodePolicyInbound(NODE *n, NODE_VRF_TABLES *v, UINT vrf_id, UINT hop, const UCHAR *packet, UINT size) {
	return NodePolicyJudge(n, v, vrf_id, hop, 0, packet, size, false);
}

// A packet of the next hop hop of the tables v in the VRF vrf_id on its way to the host that carried the source group
// group, which the peer may assert (NodeSourceGroup.c; SDN-87, #386), before the 1:1 NAT rules: true when the policy of
// the VRF lets it through, judged as from that group
bool NodePolicyInboundGroup(NODE *n, NODE_VRF_TABLES *v, UINT vrf_id, UINT hop, UINT group, const UCHAR *packet, UINT size) {
	return NodePolicyJudge(n, v, vrf_id, hop, group, packet, size, false);
}

// A packet of the VRF vrf_id that the node, the hub of the VRF, sends on from the next hop from of the tables v to the next
// hop to, a peer (NodeGatewayTransit), as the peer of from sent it: true when the policy of the VRF lets it through. The
// policy judges it by its two real ends, with the same engine and the same rules as a packet of the host: the member of
// the peer that sent it, the end outside the VRF for a route that a VRF of the peer leaks, and the member of the peer that
// it goes to; a WireGuard Device behind either peer is the end in place of its gateway (SDN-80, #375). The source group
// group that the packet carried, which the node took (NodeSourceGroupTransit; SDN-87, #386), 0 for none, is the end of
// the sender as at a destination. A dropped packet counts with the others that the policy dropped. The caller is an online
// reader of the node's table snapshot, which holds v.
bool NodePolicyTransit(NODE *n, NODE_VRF_TABLES *v, UINT vrf_id, UINT from, UINT to, UINT group, const UCHAR *packet, UINT size) {
	const NODE_POLICY_TABLE *t = (v != NULL ? v->Policy : NULL);
	const NODE_POLICY_VRF *e = NodePolicyFind(t, vrf_id);

	// A VRF without its policy forwards as the overlay did before SDN-8
	if (e == NULL)
		return true;

	NODE_POLICY *p = t->Policy;
	bool ok = false;

	if (t->Closed == false && p->Engine != NULL) {
		UINT sender = (from < t->NumHops ? e->Hops[from] : e->Outside);
		UINT receiver = (to < t->NumHops ? e->Hops[to] : e->Outside);
		UINT sender_group = (from < t->NumHops ? e->HopGroups[from] : 0);
		UINT receiver_group = 0;
		UINT host = e->Host;

		// A Device whose gateway sent the packet is its source, one whose gateway is the peer of its next hop its destination.
		// No Device of the node's own is either: the forwarding table leads their addresses to the host, so host stays.
		NodePolicyDeviceEnds(e, packet, size, false, &host, &sender, &sender_group);
		NodePolicyDeviceEnds(e, packet, size, true, &host, &receiver, &receiver_group);
		// The source group that the packet carried is the end of the sender, unless the map of address to group gives that
		// group already, whose member keeps the flows of the end (SDN-87, #386)
		if (group != 0 && group != sender_group)
			sender = NodePolicyGroupMember(e, group);
		ok = PolicyInput(p->Engine, NodePolicyNow(n, p), sender, receiver, 0, packet, size, NULL);
	}
	if (ok == false)
		InterlockedIncrement64(&p->Dropped);

	return ok;
}

//
// The state
//

// The counters of the rules of the policy of a node as the CLI shows them (PolicyCountersText): its Networks, one per VRF,
// with their conntrack tables, and each rule and default action with its flows, packets and bytes. NULL while the overlay
// does not run; Free frees it.
char *NodePolicyCountersText(NODE *n) {
	NODE_POLICY *p = (n != NULL ? n->Policy : NULL);

	if (p == NULL || p->Engine == NULL)
		return NULL;

	char *s = PolicyCountersText(p->Engine);
	if (s == NULL)
		return NULL;

	char *ret = CopyStr(s);
	PolicyFreeString(s);

	return ret;
}

// The policy of the VRF of the name vrf on a node: its rules, members and conntrack table, and the packets that the
// policy of the node dropped. False when the document in force has no such VRF.
bool NodePolicyGetVrf(NODE *n, const char *vrf, NODE_POLICY_VRF_STATUS *st) {
	NODE_POLICY *p = (n != NULL ? n->Policy : NULL);
	POLICY_NETWORK_STATS ns;

	if (st == NULL)
		return false;

	Zero(st, sizeof(NODE_POLICY_VRF_STATUS));
	if (p == NULL || p->Engine == NULL || vrf == NULL || PolicyGetNetworkStats(p->Engine, vrf, &ns) == false || ns.Defined == false)
		return false;

	st->NumRules = ns.NumRules;
	st->NumMembers = ns.NumMembers;
	st->Flows = ns.Flows;
	st->MaxFlows = ns.MaxFlows;
	st->Tracked = ns.Tracked;
	st->Evicted = ns.Evicted;
	st->Expired = ns.Expired;
	st->Dropped = (UINT64)ReadAcquire64(&p->Dropped);

	return true;
}
