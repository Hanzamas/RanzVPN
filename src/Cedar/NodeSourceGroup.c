// NodeSourceGroup.c
// The source groups of the overlay of a node (SDN-87, #386). A packet between two nodes can carry the identity of its
// source: its group ID of 16 bits and its tag set of 64 bits, which the controller numbers in each VRF from the tags of
// the endpoints of the VRF (controller/internal/desired/sourcegroup.go). The node at the destination judges the packet
// by the rules of its VRF for the group that it carried (NodePolicy.c), so a rule written by tag follows the source of a
// packet behind a gateway, as a WireGuard Device behind its gateway node. The controller gives a node that reports the
// Capability tags its own group in each of its VRFs, the group of each Device of them, and of each peer that reports it
// too the groups that the peer may assert: the peer's own group in each VRF that they share and the groups of the
// Devices whose gateway the peer is.
//
// The carriers. A record of a Noise session to a peer of frame version 1 (CONTROL_PEER.FrameVersion) carries the source
// group before the data record of frame version 0 (NodeFrameWrite), inside the session, which authenticates and encrypts
// it, so the node takes it whatever the tag mode; a node that takes a record reads both frame versions, by the VRF tag
// of no VRF that begins a record of frame version 1 (NodeFrameParse). A datagram of a link of kind vxlan carries the
// group ID alone in the group policy extension of VXLAN, and one of kind geneve the group ID and the tag set in the option
// of the source group of Geneve, whose critical bit is clear (Core/VxlanGroup.c): the tag mode of the VRF
// (CONTROL_VRF.TagMode) decides on them. In off the node sends none and ignores the one of a datagram; in
// trusted-underlay it sends one and takes the one of a datagram, as the operator vouches for the underlay, so whoever can
// send on the underlay as a peer can claim any group that the peer may assert, which is the limit of that mode.
//
// The source group that the node stamps on a packet of its host is the group of the WireGuard Device whose address is the
// source of the packet, when the node is the gateway of that Device, and the node's own group in the VRF of the packet
// otherwise. A packet of a route that a VRF of the peer leaks goes into a VRF of which the node has no group, and carries
// none. The relay role forwards the sealed datagrams of the peer layer as they are, and a node forwards no packet between
// two peers, so no node rewrites the source group of another.
//
// At the destination (NodeSourceGroupInbound) a claim that the node takes must be a group that the sending peer may assert
// in the VRF of the packet, with the tag set of that group where the claim carries one: the policy of the VRF then judges
// the packet by that group. Any other claim is an unknown group: the node drops the packet, counts it and logs it, at most
// one line every NODE_SOURCE_GROUP_LOG ms. The node judges the claims of a peer so only once it knows the groups that the
// peer may assert, which its state gives with the frame version 1 of the peer once both report the Capability tags. The
// controller gives both nodes their Generations at once, but each applies its own when it comes, and a node that the
// controller cannot reach forwards on the state that it applied last: so a peer can send its claims before the node knows
// its groups, and the node ignores them until it does, as the tag mode off ignores the claims of a link, instead of
// dropping every packet of the peer. A packet that carried no source group, or one that the node ignores, is judged by the
// map of address to group, as before SDN-87: the route of its source leads to the peer, whose own group it is, or to a
// Device of the peer, whose group it is; an address that no route of the VRF leads to the peer is no address of the map,
// and the overlay drops its packet. A claim gains nothing over that map, so ignoring one opens nothing. The node counts
// the packets of its peers by the tag mode in which it judged them, the records of its sessions as the mode session, and
// reports the counters on its control stream (Core/ControlSourceGroup.c).

#include "NodeSourceGroup.h"

#include "Mayaqua/Memory.h"
#include "Mayaqua/Object.h"
#include "Mayaqua/Str.h"

#include "NodeInternal.h"

// The results of a packet in a tag mode, as the node counts them
#define NODE_SOURCE_CARRIED 0 // It carried a source group that the node took
#define NODE_SOURCE_MISSING 1 // It carried none: the map of address to group judged it
#define NODE_SOURCE_IGNORED 2 // It carried one that the node ignores, in the tag mode off or of a peer whose groups it does not know: the map judged it
#define NODE_SOURCE_REFUSED 3 // It claimed a group that the sending peer may not assert: dropped
#define NODE_SOURCE_RESULTS 4

// One source group that a node knows: its VRF, its group ID and its tag set
typedef struct NODE_SOURCE_GROUP {
	UINT VrfId;
	UINT Group;
	UINT64 Tags;
} NODE_SOURCE_GROUP;

// One address of a WireGuard Device whose gateway the node is, and the source group that the node stamps on its packets
typedef struct NODE_SOURCE_DEVICE {
	UCHAR Address[16];
	UINT Size;
	NODE_SOURCE_GROUP Group;
} NODE_SOURCE_DEVICE;

// What the node knows of one peer: its name, the frame version of the records of the Noise session that the node sends
// it, and the groups that it may assert
typedef struct NODE_SOURCE_PEER {
	char Name[CONTROL_NAME_SIZE];
	UINT FrameVersion;
	UINT NumGroups;
	NODE_SOURCE_GROUP *Groups;
} NODE_SOURCE_PEER;

// The source groups of one Generation, which go in with its forwarding tables: peer i is next hop i of the tables
struct NODE_SOURCE_GROUP_TABLE {
	UINT NumVrfs;                            // The VRFs of the Generation ...
	UINT VrfIds[CONTROL_MAX_VRFS];           // ...
	UINT Modes[CONTROL_MAX_VRFS];            // ... and the tag mode of each (CONTROL_TAG_MODE_OFF or _TRUSTED)
	UINT NumOwn;                             // The node's own group in each of its VRFs
	NODE_SOURCE_GROUP Own[CONTROL_MAX_VRFS]; // ...
	UINT NumDevices;                         // The addresses of the Devices whose gateway the node is
	NODE_SOURCE_DEVICE *Devices;             // ...
	UINT NumPeers;                           // The peers
	NODE_SOURCE_PEER *Peers;                 // ...
};

// The source groups of the overlay of a node: the counters by tag mode and result, the report of them on the control
// stream, and the lines of the node log about refused claims
struct NODE_SOURCE_GROUPS {
	volatile LONG64 Counts[CONTROL_TAG_MODES][NODE_SOURCE_RESULTS];
	CONTROL_SOURCE_GROUPS *Report; // The report on the control stream, NULL when it could not be made
	LOCK *Lock;                    // The lines of the node log
	UINT64 LastLog;                // When the node logged a refused claim last, 0 for never
	UINT64 Unlogged;               // The refused claims since then that it did not log
	UINT64 Logged;                 // The lines that it logged
	char Last[MAX_SIZE];           // ... and the last of them
};

//
// The record of frame version 1
//

// Write the header of a record of frame version 1 with the source group group and its tag set tags into the
// NODE_FRAME_ROOM bytes at room, which the data record of frame version 0 follows: the VRF tag of no VRF, the frame
// version, the length of the options in 4-byte words, two reserved bytes, then the option of the source group, its type,
// the length of its data in 4-byte words and two reserved bytes, and its data: the group ID, two reserved bytes and the
// tag set, big-endian. Its size, NODE_FRAME_ROOM.
UINT NodeFrameWrite(UCHAR *room, UINT group, UINT64 tags) {
	Zero(room, NODE_FRAME_ROOM);
	room[4] = NODE_FRAME_VERSION;
	room[5] = (4 + NODE_FRAME_GROUP_DATA) / 4;
	room[NODE_FRAME_HEADER] = NODE_FRAME_GROUP;
	room[NODE_FRAME_HEADER + 1] = NODE_FRAME_GROUP_DATA / 4;
	WRITE_USHORT(room + NODE_FRAME_HEADER + 4, group);
	WRITE_UINT64(room + NODE_FRAME_HEADER + 8, tags);

	return NODE_FRAME_ROOM;
}

// Read the header of a record of a Noise session, size bytes, into *claim, and its size into *header, which the data
// record of frame version 0 follows. A record of frame version 0, whose VRF tag is the id of a VRF, has none and carries
// no source group: *header is 0. A record whose VRF tag is 0, the VRF tag of no VRF, is of a later frame version: false,
// with *header 0 and no claim, unless it is a record of frame version 1 whose options fill their length exactly, each a
// header of 4 bytes and its data, with no critical option but the ones that the node knows. The option of the source
// group gives the claim, the last one when there are several; an option that the node does not know and whose critical
// bit is clear is skipped.
bool NodeFrameParse(const UCHAR *record, UINT size, NODE_SOURCE_CLAIM *claim, UINT *header) {
	NODE_SOURCE_CLAIM c;

	if (claim == NULL || header == NULL)
		return false;

	Zero(claim, sizeof(NODE_SOURCE_CLAIM));
	claim->Carrier = NODE_CARRIER_SESSION;
	*header = 0;

	if (record == NULL || size < NODE_OVERLAY_VRF_TAG || READ_UINT(record) != 0)
		return true;

	if (size < NODE_FRAME_HEADER || record[4] != NODE_FRAME_VERSION)
		return false;

	UINT end = NODE_FRAME_HEADER + (UINT)record[5] * 4;
	if (end > size)
		return false;

	// The options fill whole words, so the header of one fits in what is left of them, and its data must fit after it. The
	// claim goes into *claim once every option is read, so that a record that the node drops leaves none, as one whose
	// option of the source group comes before an option that runs past the options
	Copy(&c, claim, sizeof(NODE_SOURCE_CLAIM));
	for (UINT pos = NODE_FRAME_HEADER; pos < end;) {
		UINT type = record[pos];
		UINT len = (UINT)record[pos + 1] * 4;

		if (len > end - pos - 4)
			return false;

		if (type == NODE_FRAME_GROUP && len == NODE_FRAME_GROUP_DATA) {
			c.Carried = true;
			c.HasTags = true;
			c.Group = READ_USHORT(record + pos + 4);
			c.Tags = READ_UINT64(record + pos + 8);
		} else if ((type & NODE_FRAME_CRITICAL) != 0) {
			return false;
		}

		pos += 4 + len;
	}

	Copy(claim, &c, sizeof(NODE_SOURCE_CLAIM));
	*header = end;
	return true;
}

// The claim of the source group group that a datagram of a link carried (Core/Vxlan.h), whose carrier is carrier
// (NODE_CARRIER_VXLAN or NODE_CARRIER_GENEVE)
void NodeSourceGroupClaim(NODE_SOURCE_CLAIM *claim, UINT carrier, const VXLAN_GROUP *group) {
	if (claim == NULL)
		return;

	Zero(claim, sizeof(NODE_SOURCE_CLAIM));
	claim->Carrier = carrier;
	if (group != NULL && group->Carried) {
		claim->Carried = true;
		claim->HasTags = group->HasTags;
		claim->Group = group->Group;
		claim->Tags = group->Tags;
	}
}

//
// The source groups of a Generation
//

// The tag mode of the VRF vrf_id of the table t: off for a VRF that it does not have
static UINT NodeSourceGroupMode(const NODE_SOURCE_GROUP_TABLE *t, UINT vrf_id) {
	for (UINT i = 0; t != NULL && i < t->NumVrfs; i++)
		if (t->VrfIds[i] == vrf_id)
			return t->Modes[i];

	return CONTROL_TAG_MODE_OFF;
}

// The source group of a WireGuard Device of the state as the table holds it
static void NodeSourceGroupOfDevice(NODE_SOURCE_GROUP *g, const CONTROL_DEVICE *d) {
	g->VrfId = d->VrfId;
	g->Group = d->Group;
	g->Tags = d->TagSet;
}

// The source groups of the Generation of st onto its forwarding tables v, before they go in: the tag mode of each VRF, the
// node's own groups, the addresses of the Devices whose gateway the node is with their groups, and of each peer the frame
// version of the records that the node sends it and the groups that it may assert: its own and those of the Devices whose
// gateway it is
void NodeSourceGroupAttach(NODE *n, NODE_VRF_TABLES *v, const CONTROL_STATE *st) {
	if (n == NULL || v == NULL || st == NULL)
		return;

	NODE_SOURCE_GROUP_TABLE *t = ZeroMalloc(sizeof(NODE_SOURCE_GROUP_TABLE));

	for (UINT i = 0; i < st->NumVrfs && i < CONTROL_MAX_VRFS; i++) {
		t->VrfIds[t->NumVrfs] = st->Vrfs[i].Id;
		t->Modes[t->NumVrfs] = (st->Vrfs[i].TagMode == CONTROL_TAG_MODE_TRUSTED ? CONTROL_TAG_MODE_TRUSTED : CONTROL_TAG_MODE_OFF);
		t->NumVrfs++;
	}

	for (UINT i = 0; i < st->NumGroups && i < CONTROL_MAX_VRFS; i++) {
		NODE_SOURCE_GROUP *g = &t->Own[t->NumOwn++];

		g->VrfId = st->Groups[i].VrfId;
		g->Group = st->Groups[i].Group;
		g->Tags = st->Groups[i].TagSet;
	}

	// The Devices whose gateway the node is, one entry for each of their addresses
	UINT num_devices = (st->Devices != NULL ? st->NumDevices : 0);
	t->Devices = ZeroMalloc(sizeof(NODE_SOURCE_DEVICE) * CONTROL_DEVICE_ADDRESSES * MAX(num_devices, 1));
	for (UINT i = 0; i < num_devices; i++) {
		const CONTROL_DEVICE *d = &st->Devices[i];

		if (d->HasKey == false || d->Group == 0 || StrCmp(d->Gateway, st->Name) != 0)
			continue;

		for (UINT j = 0; j < d->NumAddresses && j < CONTROL_DEVICE_ADDRESSES; j++) {
			const CONTROL_ADDRESS *a = &d->Addresses[j];

			if (a->AddressSize != 4 && a->AddressSize != 16)
				continue;

			NODE_SOURCE_DEVICE *e = &t->Devices[t->NumDevices++];
			Copy(e->Address, a->Address, a->AddressSize);
			e->Size = a->AddressSize;
			NodeSourceGroupOfDevice(&e->Group, d);
		}
	}

	// The peers, next hop i of the tables the peer of st->Peers[i]
	t->NumPeers = st->NumPeers;
	t->Peers = ZeroMalloc(sizeof(NODE_SOURCE_PEER) * MAX(st->NumPeers, 1));
	for (UINT i = 0; i < st->NumPeers; i++) {
		const CONTROL_PEER *cp = &st->Peers[i];
		NODE_SOURCE_PEER *p = &t->Peers[i];
		UINT max = MIN(cp->NumGroups, CONTROL_MAX_VRFS);

		for (UINT j = 0; j < num_devices; j++)
			if (st->Devices[j].Group != 0 && StrCmp(st->Devices[j].Gateway, cp->Name) == 0)
				max++;

		StrCpy(p->Name, sizeof(p->Name), cp->Name);
		p->FrameVersion = cp->FrameVersion;
		p->Groups = ZeroMalloc(sizeof(NODE_SOURCE_GROUP) * MAX(max, 1));

		for (UINT j = 0; j < cp->NumGroups && j < CONTROL_MAX_VRFS; j++) {
			NODE_SOURCE_GROUP *g = &p->Groups[p->NumGroups++];

			g->VrfId = cp->Groups[j].VrfId;
			g->Group = cp->Groups[j].Group;
			g->Tags = cp->Groups[j].TagSet;
		}
		for (UINT j = 0; j < num_devices; j++) {
			const CONTROL_DEVICE *d = &st->Devices[j];

			if (d->Group != 0 && StrCmp(d->Gateway, cp->Name) == 0)
				NodeSourceGroupOfDevice(&p->Groups[p->NumGroups++], d);
		}
	}

	NodeFreeSourceGroupTable(v->SourceGroups);
	v->SourceGroups = t;
}

// Free the source groups of a Generation
void NodeFreeSourceGroupTable(NODE_SOURCE_GROUP_TABLE *t) {
	if (t == NULL)
		return;

	for (UINT i = 0; i < t->NumPeers; i++)
		Free(t->Peers[i].Groups);
	Free(t->Peers);
	Free(t->Devices);

	Zero(t, sizeof(NODE_SOURCE_GROUP_TABLE));
	Free(t);
}

//
// The packets
//

// The source group of a packet of the host in the VRF vrf_id into *g: the group of the WireGuard Device whose address is
// the source of the packet, when the node is the gateway of that Device, else the node's own group in the VRF. False when
// the node has neither.
static bool NodeSourceGroupOf(const NODE_SOURCE_GROUP_TABLE *t, UINT vrf_id, const UCHAR *packet, UINT size, NODE_SOURCE_GROUP *g) {
	const UCHAR *src = NULL;
	UINT addr_size = 0;

	if (packet != NULL && size >= 20 && (packet[0] >> 4) == 4) {
		src = packet + 12;
		addr_size = 4;
	} else if (packet != NULL && size >= 40 && (packet[0] >> 4) == 6) {
		src = packet + 8;
		addr_size = 16;
	}

	for (UINT i = 0; src != NULL && i < t->NumDevices; i++) {
		const NODE_SOURCE_DEVICE *d = &t->Devices[i];

		if (d->Group.VrfId == vrf_id && d->Size == addr_size && Cmp(d->Address, src, addr_size) == 0) {
			*g = d->Group;
			return true;
		}
	}

	for (UINT i = 0; i < t->NumOwn; i++) {
		if (t->Own[i].VrfId == vrf_id) {
			*g = t->Own[i];
			return true;
		}
	}

	return false;
}

// The record of *size bytes at record, the VRF tag of its VRF and the packet of the host in the VRF vrf_id, as it goes to
// the peer of the next hop hop of the tables v over its Noise session: with the header of frame version 1 and the source
// group of the packet in the NODE_FRAME_ROOM bytes before record, which the caller holds, when the peer takes records of
// frame version 1, the record is of the VRF of the packet, as a record of a leaked route is not, and the node has a source
// group for the packet; the record as it is otherwise. Its start, with *size its size. The caller reads v as a reader of
// the table snapshot of the node.
const UCHAR *NodeSourceGroupWrap(NODE_VRF_TABLES *v, UINT hop, UINT vrf_id, UCHAR *record, UINT *size) {
	const NODE_SOURCE_GROUP_TABLE *t = (v != NULL ? v->SourceGroups : NULL);
	NODE_SOURCE_GROUP g;

	if (t == NULL || record == NULL || size == NULL || hop >= t->NumPeers || t->Peers[hop].FrameVersion != NODE_FRAME_VERSION ||
	    *size < NODE_OVERLAY_VRF_TAG || *size > NOISE_MAX_PAYLOAD - NODE_FRAME_ROOM || READ_UINT(record) != vrf_id ||
	    NodeSourceGroupOf(t, vrf_id, record + NODE_OVERLAY_VRF_TAG, *size - NODE_OVERLAY_VRF_TAG, &g) == false)
		return record;

	NodeFrameWrite(record - NODE_FRAME_ROOM, g.Group, g.Tags);
	*size += NODE_FRAME_ROOM;

	return record - NODE_FRAME_ROOM;
}

// The source group that a packet of the host in the VRF vrf_id carries over a link of kind vxlan or geneve, into *group:
// false, with *group empty, unless the tag mode of the VRF is trusted-underlay and the node has a source group for the
// packet. The caller reads v as a reader of the table snapshot of the node.
bool NodeSourceGroupStamp(NODE_VRF_TABLES *v, UINT vrf_id, const UCHAR *packet, UINT size, VXLAN_GROUP *group) {
	const NODE_SOURCE_GROUP_TABLE *t = (v != NULL ? v->SourceGroups : NULL);
	NODE_SOURCE_GROUP g;

	if (group == NULL)
		return false;

	Zero(group, sizeof(VXLAN_GROUP));
	if (t == NULL || NodeSourceGroupMode(t, vrf_id) != CONTROL_TAG_MODE_TRUSTED || NodeSourceGroupOf(t, vrf_id, packet, size, &g) == false)
		return false;

	group->Carried = true;
	group->HasTags = true;
	group->Group = (USHORT)g.Group;
	group->Tags = g.Tags;

	return true;
}

// Whether the node knows the groups that the peer of the next hop hop of the table t may assert: its state gives the peer
// the frame version 1, as the controller does with those groups once both report the Capability tags
static bool NodeSourceGroupKnows(const NODE_SOURCE_GROUP_TABLE *t, UINT hop) {
	return (t != NULL && hop < t->NumPeers && t->Peers[hop].FrameVersion == NODE_FRAME_VERSION);
}

// Whether the peer of the next hop hop of the table t may assert the claim in the VRF vrf_id: the group is one of its
// groups in the VRF, with the tag set of that group when the claim carries one
static bool NodeSourceGroupAllowed(const NODE_SOURCE_GROUP_TABLE *t, UINT hop, UINT vrf_id, const NODE_SOURCE_CLAIM *claim) {
	if (t == NULL || hop >= t->NumPeers || claim->Group == 0)
		return false;

	const NODE_SOURCE_PEER *p = &t->Peers[hop];
	for (UINT i = 0; i < p->NumGroups; i++) {
		const NODE_SOURCE_GROUP *g = &p->Groups[i];

		if (g->VrfId == vrf_id && g->Group == claim->Group && (claim->HasTags == false || g->Tags == claim->Tags))
			return true;
	}

	return false;
}

// Count a packet of a peer in the tag mode mode with the result (NODE_SOURCE_*)
static void NodeSourceGroupCount(NODE_SOURCE_GROUPS *g, UINT mode, UINT result) {
	if (g != NULL && mode < CONTROL_TAG_MODES && result < NODE_SOURCE_RESULTS)
		InterlockedIncrement64(&g->Counts[mode][result]);
}

// What carried a claim, as the node log names it
static const char *NodeSourceGroupCarrier(UINT carrier) {
	if (carrier == NODE_CARRIER_VXLAN)
		return "a datagram of vxlan";
	if (carrier == NODE_CARRIER_GENEVE)
		return "a datagram of geneve";

	return "a record of its Noise session";
}

// Log a claim that the node refused: the first one, then at most one line every NODE_SOURCE_GROUP_LOG ms, which counts the
// claims that the node refused since the line before and did not log
static void NodeSourceGroupLog(NODE *n, const NODE_SOURCE_GROUP_TABLE *t, UINT hop, UINT vrf_id, const NODE_SOURCE_CLAIM *claim) {
	NODE_SOURCE_GROUPS *g = n->SourceGroups;
	UINT64 now = GetTickCount64();
	UINT64 others = 0;
	bool log = false;
	char line[MAX_SIZE];
	char more[MAX_SIZE];

	if (g == NULL)
		return;

	Lock(g->Lock);
	{
		if (g->LastLog == 0 || now - g->LastLog >= NODE_SOURCE_GROUP_LOG) {
			log = true;
			others = g->Unlogged;
			g->Unlogged = 0;
			g->LastLog = now;
		} else {
			g->Unlogged++;
		}
	}
	Unlock(g->Lock);

	if (log == false)
		return;

	StrCpy(more, sizeof(more), "");
	if (others != 0)
		Format(more, sizeof(more), "; %I64u more claims that their peers may not assert were dropped since the line before", others);
	if (claim->HasTags)
		Format(line, sizeof(line), "Source group: %s claimed the group %u with the tag set 0x%016I64x in VRF %u in %s, which it may not assert: dropped as an unknown group%s",
		       (t != NULL && hop < t->NumPeers) ? t->Peers[hop].Name : "a peer", claim->Group, claim->Tags, vrf_id, NodeSourceGroupCarrier(claim->Carrier), more);
	else
		Format(line, sizeof(line), "Source group: %s claimed the group %u in VRF %u in %s, which it may not assert: dropped as an unknown group%s",
		       (t != NULL && hop < t->NumPeers) ? t->Peers[hop].Name : "a peer", claim->Group, vrf_id, NodeSourceGroupCarrier(claim->Carrier), more);

	NodeLog(n, "%s", line);

	Lock(g->Lock);
	{
		g->Logged++;
		StrCpy(g->Last, sizeof(g->Last), line);
	}
	Unlock(g->Lock);
}

// A packet of the next hop hop of the tables v in the VRF vrf_id on its way to the host, with the source group that it
// carried, as claim tells, before a 1:1 NAT rule translates it: true when it passes. A record of a Noise session carries
// a source group that the session authenticated, which the node takes whatever the tag mode; a datagram of a link of kind
// vxlan or geneve carries one that the tag mode of its VRF decides on: off ignores it, trusted-underlay takes it. The node
// takes the group of a peer whose groups it knows, and it must be one that the peer may assert: the policy of the VRF
// judges the packet by it. Any other is an unknown group, which the node drops, counts and logs. A packet that carried
// none, one that off ignores, or one of a peer whose groups the node does not know yet, is judged by the map of address
// to group. The caller is an online reader of the node's table snapshot, which holds v.
bool NodeSourceGroupInbound(NODE *n, NODE_VRF_TABLES *v, UINT vrf_id, UINT hop, const NODE_SOURCE_CLAIM *claim, const UCHAR *packet, UINT size) {
	NODE_SOURCE_GROUPS *g = (n != NULL ? n->SourceGroups : NULL);
	const NODE_SOURCE_GROUP_TABLE *t = (v != NULL ? v->SourceGroups : NULL);
	UINT mode = (claim == NULL || claim->Carrier == NODE_CARRIER_SESSION ? CONTROL_TAG_MODE_SESSION : NodeSourceGroupMode(t, vrf_id));

	if (claim == NULL || claim->Carried == false) {
		NodeSourceGroupCount(g, mode, NODE_SOURCE_MISSING);
		return NodePolicyInbound(n, v, vrf_id, hop, packet, size);
	}

	if (mode == CONTROL_TAG_MODE_OFF || NodeSourceGroupKnows(t, hop) == false) {
		NodeSourceGroupCount(g, mode, NODE_SOURCE_IGNORED);
		return NodePolicyInbound(n, v, vrf_id, hop, packet, size);
	}

	if (NodeSourceGroupAllowed(t, hop, vrf_id, claim) == false) {
		NodeSourceGroupCount(g, mode, NODE_SOURCE_REFUSED);
		NodeSourceGroupLog(n, t, hop, vrf_id, claim);
		return false;
	}

	NodeSourceGroupCount(g, mode, NODE_SOURCE_CARRIED);
	return NodePolicyInboundGroup(n, v, vrf_id, hop, claim->Group, packet, size);
}

//
// The overlay
//

// The counters of the source groups of the node of param by tag mode (CONTROL_GROUPS_PROC), which its control stream reports
static void NodeSourceGroupCounters(void *param, CONTROL_GROUP_COUNTERS *counters) {
	NODE *n = (NODE *)param;
	NODE_SOURCE_GROUPS *g = (n != NULL ? n->SourceGroups : NULL);

	if (g == NULL || counters == NULL)
		return;

	for (UINT i = 0; i < CONTROL_TAG_MODES; i++) {
		counters[i].Carried = (UINT64)ReadAcquire64(&g->Counts[i][NODE_SOURCE_CARRIED]);
		counters[i].Missing = (UINT64)ReadAcquire64(&g->Counts[i][NODE_SOURCE_MISSING]);
		counters[i].Ignored = (UINT64)ReadAcquire64(&g->Counts[i][NODE_SOURCE_IGNORED]);
		counters[i].Refused = (UINT64)ReadAcquire64(&g->Counts[i][NODE_SOURCE_REFUSED]);
	}
}

// Start the source groups of the overlay of a node (NodeOverlayStart): its counters, and the report of them that its
// control stream sends, which it returns, NULL when it could not be made
CONTROL_SOURCE_GROUPS *NodeSourceGroupStart(NODE *n) {
	if (n == NULL || n->SourceGroups != NULL)
		return NULL;

	NODE_SOURCE_GROUPS *g = ZeroMalloc(sizeof(NODE_SOURCE_GROUPS));
	g->Lock = NewLock();
	n->SourceGroups = g;
	g->Report = ControlNewSourceGroups(NodeSourceGroupCounters, n);

	return g->Report;
}

// Stop the source groups of the overlay of a node (NodeOverlayStop), once its control stream stopped and no table and
// no thread of the overlay reads them any more
void NodeSourceGroupStop(NODE *n) {
	NODE_SOURCE_GROUPS *g = (n != NULL ? n->SourceGroups : NULL);

	if (g == NULL)
		return;

	n->SourceGroups = NULL;
	ControlFreeSourceGroups(g->Report);
	DeleteLock(g->Lock);
	Free(g);
}

// The counters of the source groups of a node by tag mode since its overlay started, and the lines of its node log about
// refused claims; all 0 while the overlay does not run
void NodeSourceGroupGetStatus(NODE *n, NODE_SOURCE_GROUP_STATUS *st) {
	if (st == NULL)
		return;

	Zero(st, sizeof(NODE_SOURCE_GROUP_STATUS));
	NODE_SOURCE_GROUPS *g = (n != NULL ? n->SourceGroups : NULL);
	if (g == NULL)
		return;

	NodeSourceGroupCounters(n, st->Modes);

	Lock(g->Lock);
	{
		st->Logged = g->Logged;
		StrCpy(st->Last, sizeof(st->Last), g->Last);
	}
	Unlock(g->Lock);
}
