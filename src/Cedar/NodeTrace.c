// NodeTrace.c
// The trace of a packet through the nodes (SDN-89, #388). An operator follows one packet: the trace of a Network is off
// by default and switched on in the Intent (Network.trace), and every node of the VRF of the Network gets the pools of
// the Networks of its VRFs whose trace is on (CONTROL_STATE.Traced). A packet of the host whose source or destination is
// in such a pool is traced by the node where it enters the overlay, its ingress node, at most one packet of a VRF in
// each NODE_TRACE_INTERVAL ms, so that a trace costs the overlay a bounded number of records whatever its traffic: the
// node gives it a trace ID of 32 bits, never 0, from a counter that starts at a random number at the start of its
// overlay, and the trace option carries the trace ID and the ingress node, the first VXLAN_TRACE_INGRESS bytes of its
// static key, which the controller and the peers of the node know. The option carries nothing else of the packet: no
// address, no port, no payload and no timestamp, which waits for synchronised clocks.
//
// The carriers. A record of a Noise session, or of the datagram path of the peer agent, to a peer that takes records of
// frame version 1 (CONTROL_PEER.FrameVersion) carries the trace option in the header of frame version 1, after the
// option of the source group when the record carries one, and alone in a header of its own when it does not
// (NodeTraceWrap), inside the session, which authenticates and encrypts it. A datagram of a link of kind geneve carries
// it in the trace option of Geneve after the option of the source group (Core/VxlanTrace.c). A datagram of a link of kind
// vxlan carries none: the VXLAN header has no room for it, so the trace of a packet over such a link ends at its
// ingress node. So does the trace of a packet to a peer of frame version 0, a node of a release before SDN-87, and of a
// record that does not fit the payload of its path with the option, which goes without it, as the source group does. The
// critical bit of the option is clear in both headers, so a node that does not know it, as a node of a release before
// SDN-89, skips it and forwards the packet (NodeFrameParse, VxlanInput), and so does a tunnel endpoint of Geneve of
// another vendor.
//
// The records. The ingress node records the trace ID, itself, the VRF, the group that the packet carries, in the header
// of frame version 1 or in the header of the link, which the tag mode of the VRF decides on (NodeSourceGroupStamp), and
// the verdict of its policy on the packet, allowed or denied (NodeTraceOutbound). A node that takes a packet with the
// trace option, in a VRF of which the pool of a Network that traces holds its source or its destination, records the
// trace ID, the ingress node, the VRF, the group that the packet carried and its verdict on it: allowed when it goes to
// the host, denied when the node drops it, by its policy, the session profile of the peer or a claim of a group that
// the peer may not assert (NodeTraceInbound). A node whose state has no Network that traces records nothing and leaves
// the option where it is. A record waits in the queue of the control stream (Core/ControlTrace.c), which the controller
// takes and `ranz explain -trace` shows as the path of the packet: each node with the group and the verdict.
//
// What it costs. With the trace of no Network of a Generation on, its tables hold no trace table (NODE_VRF_TABLES.Trace
// NULL): the node sends no option and every packet keeps its size, and the data path tests one pointer for each packet.
// The hub of a VRF of topology hub-and-spoke and an EVPN gateway, which send the packet of a peer on, neither record it
// nor carry its option on (SDN-89 records the ingress node and the node that delivers the packet).

#include "NodeTrace.h"

#include "Mayaqua/Encrypt.h"
#include "Mayaqua/Memory.h"

// A record names the ingress node by as many bytes of its static key as the trace option does
_Static_assert(CONTROL_TRACE_INGRESS == VXLAN_TRACE_INGRESS, "a record names the ingress node as the trace option does");
_Static_assert(NODE_FRAME_TRACE_OPTION == GENEVE_TRACE_OPTION, "the trace option is as long in both carriers");

// The Networks of one Generation whose trace is on, which go in with its forwarding tables: peer i is next hop i of the
// tables
struct NODE_TRACE_TABLE {
	UINT NumPools;                           // The pools of the Networks that trace ...
	CONTROL_TRACED Pools[CONTROL_MAX_TRACED]; // ... each with its VRF
	UINT NumVrfs;                            // The VRFs of those Networks ...
	UINT VrfIds[CONTROL_MAX_VRFS];           // ...
	volatile LONG64 Last[CONTROL_MAX_VRFS];  // ... and when the node last traced a packet of each as its ingress node (GetTickCount64), 0 for never
	UINT NumPeers;                           // The peers ...
	bool *Versioned;                         // ... and whether each takes records of frame version 1
};

// The trace of the overlay of a node: the node as an ingress node, the trace ID of its last traced packet, its counters,
// and the queue of the records that its control stream sends
struct NODE_TRACES {
	UCHAR Ingress[CONTROL_TRACE_INGRESS]; // The first bytes of the static key of the node, which name it as the ingress node
	volatile LONG Next;                   // The trace ID of the last packet that it traced as their ingress node
	volatile LONG64 Traced;               // The packets that it traced as their ingress node
	volatile LONG64 Recorded;             // The records that it made
	CONTROL_TRACES *Report;               // The queue of the records that the control stream sends, NULL when it could not be made
};

//
// The trace option of a record of frame version 1
//

// Write the trace option of trace, NODE_FRAME_TRACE_OPTION bytes at option: its type, the length of its data in 4-byte
// words, two reserved bytes, the trace ID, big-endian, and the bytes of the ingress node. Its size.
UINT NodeTraceWrite(UCHAR *option, const VXLAN_TRACE *trace) {
	Zero(option, NODE_FRAME_TRACE_OPTION);
	option[0] = NODE_FRAME_TRACE;
	option[1] = NODE_FRAME_TRACE_DATA / 4;
	WRITE_UINT(option + 4, trace->Id);
	Copy(option + 8, trace->Ingress, VXLAN_TRACE_INGRESS);

	return NODE_FRAME_TRACE_OPTION;
}

// Read the trace option of the header of a record of a Noise session, size bytes, into *trace: true when the record is of
// frame version 1, whose VRF tag is 0, the VRF tag of no VRF, whose options fill their length within the record, each a
// header of 4 bytes and its data, with no critical option, and one of them is the trace option with a trace ID that is
// not 0, the first one when there are several. False, with *trace empty, for any other record: one of frame version 0, of
// a later frame version, or one that the node drops (NodeFrameParse). An option that is not the trace option is skipped.
bool NodeTraceParse(const UCHAR *record, UINT size, VXLAN_TRACE *trace) {
	if (trace == NULL)
		return false;

	Zero(trace, sizeof(VXLAN_TRACE));
	if (record == NULL || size < NODE_FRAME_HEADER || READ_UINT(record) != 0 || record[4] != NODE_FRAME_VERSION)
		return false;

	UINT end = NODE_FRAME_HEADER + (UINT)record[5] * 4;
	if (end > size)
		return false;

	// The options fill whole words, so the header of one fits in what is left of them, and its data must fit after it. The
	// trace goes into *trace once every option is read, so that a record that the node drops leaves none
	VXLAN_TRACE t;
	Zero(&t, sizeof(t));
	for (UINT pos = NODE_FRAME_HEADER; pos < end;) {
		UINT type = record[pos];
		UINT len = (UINT)record[pos + 1] * 4;

		if (len > end - pos - 4)
			return false;

		if (type == NODE_FRAME_TRACE && len == NODE_FRAME_TRACE_DATA) {
			if (t.Traced == false && READ_UINT(record + pos + 4) != 0) {
				t.Traced = true;
				t.Id = READ_UINT(record + pos + 4);
				Copy(t.Ingress, record + pos + 8, VXLAN_TRACE_INGRESS);
			}
		} else if ((type & NODE_FRAME_CRITICAL) != 0) {
			return false;
		}

		pos += 4 + len;
	}

	Copy(trace, &t, sizeof(VXLAN_TRACE));
	return trace->Traced;
}

// The trace option of trace in the frame that goes to a peer of frame version 1, *frame_size bytes at frame: the data
// record at record, of frame version 0, which becomes a record of frame version 1 with the trace option alone, or a
// record of frame version 1 whose header and options begin before record, which the trace option follows. The caller
// holds NODE_TRACE_ROOM bytes before record. The frame with the option goes when it fits max, the largest payload of its
// path; else the frame as it was. Its start, with *frame_size its size.
const UCHAR *NodeTraceWrap(UCHAR *record, const UCHAR *frame, UINT *frame_size, UINT max, const VXLAN_TRACE *trace) {
	UINT before = (UINT)(record - frame);
	UINT add = (before == 0 ? NODE_FRAME_HEADER + NODE_FRAME_TRACE_OPTION : NODE_FRAME_TRACE_OPTION);

	if (before > NODE_FRAME_ROOM || max < add || *frame_size > max - add)
		return frame;

	UCHAR *start = record - before - add;
	if (before == 0) {
		// The header of frame version 1: the VRF tag of no VRF, the version and no options yet
		Zero(start, NODE_FRAME_HEADER);
		start[4] = NODE_FRAME_VERSION;
	} else {
		// The header and the options of the record move to make room for the trace option after them
		Move(start, record - before, before);
	}
	start[5] = (UCHAR)(start[5] + NODE_FRAME_TRACE_OPTION / 4);
	NodeTraceWrite(record - NODE_FRAME_TRACE_OPTION, trace);
	*frame_size += add;

	return start;
}

//
// The Networks that trace in a Generation
//

// The slot of the VRF vrf_id among the VRFs of the table t in which a Network traces, t->NumVrfs for none
static UINT NodeTraceVrf(const NODE_TRACE_TABLE *t, UINT vrf_id) {
	for (UINT i = 0; i < t->NumVrfs; i++)
		if (t->VrfIds[i] == vrf_id)
			return i;

	return t->NumVrfs;
}

// Whether the address of size bytes is in the prefix p
static bool NodeTraceInPrefix(const UCHAR *address, UINT size, const CONTROL_PREFIX *p) {
	UINT bytes = p->Length / 8;
	UINT bits = p->Length % 8;

	if (p->AddressSize != size || p->Length > size * 8 || Cmp(address, p->Address, bytes) != 0)
		return false;
	if (bits == 0)
		return true;

	UCHAR mask = (UCHAR)(0xFF00 >> bits);

	return ((address[bytes] & mask) == (p->Address[bytes] & mask));
}

// Whether the IP packet of size bytes in the VRF vrf_id is a packet of a Network of the table t whose trace is on: its
// source or its destination is in a pool of such a Network of the VRF
static bool NodeTraceHolds(const NODE_TRACE_TABLE *t, UINT vrf_id, const UCHAR *packet, UINT size) {
	const UCHAR *src = NULL, *dst = NULL;
	UINT addr_size = 0;

	if (packet != NULL && size >= 20 && (packet[0] >> 4) == 4) {
		src = packet + 12;
		dst = packet + 16;
		addr_size = 4;
	} else if (packet != NULL && size >= 40 && (packet[0] >> 4) == 6) {
		src = packet + 8;
		dst = packet + 24;
		addr_size = 16;
	} else {
		return false;
	}

	for (UINT i = 0; i < t->NumPools; i++) {
		const CONTROL_TRACED *p = &t->Pools[i];

		if (p->VrfId == vrf_id && (NodeTraceInPrefix(src, addr_size, &p->Pool) || NodeTraceInPrefix(dst, addr_size, &p->Pool)))
			return true;
	}

	return false;
}

// The Networks of the state st whose trace is on onto its forwarding tables v, before they go in: their pools with their
// VRFs, and whether each peer takes records of frame version 1. A state without such a Network gives the tables no trace
// table, so that the data path tests one pointer.
void NodeTraceAttach(NODE *n, NODE_VRF_TABLES *v, const CONTROL_STATE *st) {
	if (n == NULL || v == NULL || st == NULL)
		return;

	NodeFreeTraceTable(v->Trace);
	v->Trace = NULL;
	if (st->NumTraced == 0)
		return;

	NODE_TRACE_TABLE *t = ZeroMalloc(sizeof(NODE_TRACE_TABLE));

	for (UINT i = 0; i < st->NumTraced && i < CONTROL_MAX_TRACED; i++) {
		const CONTROL_TRACED *c = &st->Traced[i];

		if (NodeTraceVrf(t, c->VrfId) == t->NumVrfs) {
			if (t->NumVrfs == CONTROL_MAX_VRFS)
				continue;
			t->VrfIds[t->NumVrfs++] = c->VrfId;
		}
		Copy(&t->Pools[t->NumPools++], c, sizeof(CONTROL_TRACED));
	}

	t->NumPeers = st->NumPeers;
	t->Versioned = ZeroMalloc(sizeof(bool) * MAX(st->NumPeers, 1));
	for (UINT i = 0; i < st->NumPeers; i++)
		t->Versioned[i] = (st->Peers[i].FrameVersion == NODE_FRAME_VERSION);

	v->Trace = t;
}

// Free the Networks that trace of a Generation
void NodeFreeTraceTable(NODE_TRACE_TABLE *t) {
	if (t == NULL)
		return;

	Free(t->Versioned);
	Zero(t, sizeof(NODE_TRACE_TABLE));
	Free(t);
}

//
// The packets
//

// Record the traced packet of trace in the VRF vrf_id, with the group ID that it carried, 0 for none, and the verdict of
// the node, in the queue of the control stream
static void NodeTraceRecord(NODE_TRACES *g, const VXLAN_TRACE *trace, UINT vrf_id, UINT group, bool allowed) {
	CONTROL_TRACE r;

	Zero(&r, sizeof(r));
	r.Id = trace->Id;
	Copy(r.Ingress, trace->Ingress, CONTROL_TRACE_INGRESS);
	r.VrfId = vrf_id;
	r.Group = group;
	r.Allowed = allowed;

	if (ControlAddTrace(g->Report, &r))
		InterlockedIncrement64(&g->Recorded);
}

// Whether the node traces the packet of the host of size bytes in the VRF vrf_id of the table t as its ingress node, with
// its trace in *trace: a packet of a Network whose trace is on, when the node traced no packet of the VRF in the last
// NODE_TRACE_INTERVAL ms. Of two threads at the same moment one takes it.
static bool NodeTraceTake(NODE_TRACES *g, NODE_TRACE_TABLE *t, UINT vrf_id, const UCHAR *packet, UINT size, VXLAN_TRACE *trace) {
	UINT slot = NodeTraceVrf(t, vrf_id);

	if (slot == t->NumVrfs || NodeTraceHolds(t, vrf_id, packet, size) == false)
		return false;

	UINT64 now = GetTickCount64();
	LONG64 last = ReadAcquire64(&t->Last[slot]);
	if ((last != 0 && now - (UINT64)last < NODE_TRACE_INTERVAL) || InterlockedCompareExchange64(&t->Last[slot], (LONG64)now, last) != last)
		return false;

	UINT id = (UINT)InterlockedIncrement(&g->Next);
	if (id == 0)
		id = (UINT)InterlockedIncrement(&g->Next);

	trace->Traced = true;
	trace->Id = id;
	Copy(trace->Ingress, g->Ingress, VXLAN_TRACE_INGRESS);
	InterlockedIncrement64(&g->Traced);

	return true;
}

// A packet of the host in the VRF vrf_id, size bytes after the VRF tag of its data record at record, which the node sends
// to the next hop hop of the tables v as the frame of *frame_size bytes at frame (NodeOverlayInput), and the verdict of
// its session profiles and its policy, allowed. When the node traces it as its ingress node (NodeTraceTake), it records
// it with the group that it carries and the verdict, and the trace option goes with it: in *trace, which the link of kind
// geneve of a plain path carries (NodeLinkSend), and on the session or the datagram path, whose payload is max bytes at
// most, in the header of frame version 1 of the frame to a peer that takes it, when it fits (NodeTraceWrap). *trace
// carries nothing for a packet that the node does not trace. The start of the frame, with *frame_size its size. The caller
// holds NODE_TRACE_ROOM bytes before record and reads v as a reader of the table snapshot of the node.
const UCHAR *NodeTraceOutbound(NODE *n, NODE_VRF_TABLES *v, UINT hop, UINT vrf_id, UCHAR *record, UINT size, const UCHAR *frame, UINT *frame_size, UINT max, bool allowed, bool plain, VXLAN_TRACE *trace) {
	NODE_TRACE_TABLE *t = (v != NULL ? v->Trace : NULL);
	NODE_TRACES *g = (n != NULL ? n->Trace : NULL);

	if (trace == NULL)
		return frame;

	// The trace of no Network of the Generation is on: the packet goes as it is
	trace->Traced = false;
	if (t == NULL || g == NULL || record == NULL || frame == NULL || frame_size == NULL)
		return frame;

	const UCHAR *packet = record + NODE_OVERLAY_VRF_TAG;
	if (NodeTraceTake(g, t, vrf_id, packet, size, trace) == false)
		return frame;

	// The group that the packet carries: in the header of the link, as the tag mode of its VRF decides, or in the header
	// of frame version 1 of the session or the datagram path
	UINT group = 0;
	if (plain) {
		VXLAN_GROUP stamp;

		if (NodeSourceGroupStamp(v, vrf_id, packet, size, &stamp))
			group = stamp.Group;
	} else if (frame != record) {
		NODE_SOURCE_CLAIM claim;
		UINT header = 0;

		if (NodeFrameParse(frame, *frame_size, &claim, &header) && claim.Carried)
			group = claim.Group;
	}
	NodeTraceRecord(g, trace, vrf_id, group, allowed);

	// A link carries the trace option in its own header; a packet that the node drops goes nowhere
	if (plain || allowed == false || hop >= t->NumPeers || t->Versioned[hop] == false)
		return frame;

	return NodeTraceWrap(record, frame, frame_size, max, trace);
}

// A packet of a peer in the VRF vrf_id, size bytes at packet, as the peer sent it, with the header of frame version 1 of
// its record, header_size bytes at header, 0 for a record of frame version 0 and for a datagram of a link, whose trace
// option claim carries with its source group, and the verdict of the node on it, ok: it goes to the host, or the node
// drops it. A traced packet in a VRF of which the pool of a Network that traces holds its source or its destination is
// recorded with the group that it carried. The caller is an online reader of the node's table snapshot, which holds v.
void NodeTraceInbound(NODE *n, NODE_VRF_TABLES *v, UINT vrf_id, const UCHAR *header, UINT header_size, const NODE_SOURCE_CLAIM *claim, const UCHAR *packet, UINT size, bool ok) {
	NODE_TRACE_TABLE *t = (v != NULL ? v->Trace : NULL);
	NODE_TRACES *g = (n != NULL ? n->Trace : NULL);
	VXLAN_TRACE trace;

	// The trace of no Network of the Generation is on: the node records nothing
	if (t == NULL || g == NULL)
		return;

	Zero(&trace, sizeof(trace));
	if (header != NULL && header_size != 0)
		NodeTraceParse(header, header_size, &trace);
	else if (claim != NULL)
		Copy(&trace, &claim->Trace, sizeof(trace));

	if (trace.Traced == false || trace.Id == 0 || NodeTraceVrf(t, vrf_id) == t->NumVrfs || NodeTraceHolds(t, vrf_id, packet, size) == false)
		return;

	NodeTraceRecord(g, &trace, vrf_id, (claim != NULL && claim->Carried) ? claim->Group : 0, ok);
}

//
// The overlay
//

// Start the trace of the overlay of a node (NodeOverlayStart), whose static key is key: the queue of its records, which it
// returns for its control stream, NULL when it could not be made
CONTROL_TRACES *NodeTraceStart(NODE *n, const UCHAR *key) {
	if (n == NULL || key == NULL || n->Trace != NULL)
		return NULL;

	NODE_TRACES *g = ZeroMalloc(sizeof(NODE_TRACES));
	Copy(g->Ingress, key, CONTROL_TRACE_INGRESS);
	g->Next = (LONG)Rand32();
	g->Report = ControlNewTraces();
	n->Trace = g;

	return g->Report;
}

// Stop the trace of the overlay of a node (NodeOverlayStop), once its control stream stopped and no table and no thread
// of the overlay reads it any more
void NodeTraceStop(NODE *n) {
	NODE_TRACES *g = (n != NULL ? n->Trace : NULL);

	if (g == NULL)
		return;

	n->Trace = NULL;
	ControlFreeTraces(g->Report);
	Free(g);
}

// The packets that a node traced as their ingress node and the records that it made since its overlay started, and the
// records that wait for its control stream; all 0 while the overlay does not run
void NodeTraceGetStatus(NODE *n, NODE_TRACE_STATUS *st) {
	if (st == NULL)
		return;

	Zero(st, sizeof(NODE_TRACE_STATUS));
	NODE_TRACES *g = (n != NULL ? n->Trace : NULL);
	if (g == NULL)
		return;

	st->Traced = (UINT64)ReadAcquire64(&g->Traced);
	st->Recorded = (UINT64)ReadAcquire64(&g->Recorded);
	st->NumRecords = ControlGetTraces(g->Report, st->Records, CONTROL_TRACE_QUEUE);
}
