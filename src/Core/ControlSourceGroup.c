// ControlSourceGroup.c
// The source groups on the control stream (SDN-87, #386; Core/Control.h). A packet between two nodes can carry the
// identity of its source, its group ID and its tag set. The NodeConfig of a state carries the node's own source group in
// each of its VRFs (CONTROL_STATE.Groups), held in a VRF in which it stamps none yet; each Peer object the source group of
// the peer in each VRF that they share and the frame version of the records of the Noise session that the node sends it
// (CONTROL_PEER.Groups, FrameVersion), each group with the group generation of its node in the VRF, which the claims of
// that node name; each Device object the source group of the Device (CONTROL_DEVICE.Group, TagSet); and each Vrf object
// how the node trusts the source group that a link of kind vxlan or geneve of the VRF carries (CONTROL_VRF.TagMode). They
// go with the state, as the owner takes it (ControlCopySourceGroups). The node reports the packets of its peers that it
// judged by their source group, by tag mode (ControlWriteSourceGroups): the client sends them in one Telemetry message
// after each Hello, whenever they changed, at most every CONTROL_GROUP_REPORT ms, and every CONTROL_GROUP_REFRESH ms, once
// they hold any.

#include "Core/ControlInternal.h"

#include <pb_encode.h>

#include <string.h>

#define CONTROL_SOURCE_GROUPS_HEADER 4 // The size of a frame, big-endian, before its message (as Control.c writes them)

// The counters of the source groups that a client reports. Only the thread of the client uses them.
struct CONTROL_SOURCE_GROUPS {
	// Gives the counters of the node, with its parameter
	CONTROL_GROUPS_PROC *Proc;
	void *Param;
	// The counters that the client sent last on the stream that runs, and when; Sent 0 for none
	CONTROL_GROUP_COUNTERS Last[CONTROL_TAG_MODES];
	UINT64 Sent;
	// When the client looked at the counters last
	UINT64 Looked;
	// The message that the thread of the client writes
	ranz_control_v1_Telemetry *Message;
};

static void *ControlSourceGroupAlloc(SIZE_T size) {
	return HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, size);
}

static void ControlSourceGroupFree(void *p) {
	if (p != NULL)
		HeapFree(GetProcessHeap(), 0, p);
}

//
// The source groups of a state
//

// The source groups of a NodeConfig or of a Peer object into dst, of CONTROL_MAX_VRFS: a group of the ID 0 or above 65535
// is left out
static void ControlCopyGroups(CONTROL_SOURCE_GROUP *dst, UINT *num, const ranz_control_v1_SourceGroup *src, pb_size_t count) {
	*num = 0;

	for (pb_size_t i = 0; i < count && i < CONTROL_MAX_VRFS && *num < CONTROL_MAX_VRFS; i++) {
		if (src[i].group == 0 || src[i].group > 0xFFFF)
			continue;

		CONTROL_SOURCE_GROUP *g = &dst[*num];
		g->VrfId = src[i].vrf_id;
		g->Group = src[i].group;
		g->TagSet = src[i].tag_set;
		g->Generation = src[i].generation;
		g->Held = src[i].held;
		(*num)++;
	}
}

// The tag mode of a Vrf object as the state holds it: trusted-underlay, or off for any other
static UINT ControlTagMode(ranz_control_v1_TagMode mode) {
	return (mode == ranz_control_v1_TagMode_TAG_MODE_TRUSTED_UNDERLAY ? CONTROL_TAG_MODE_TRUSTED : CONTROL_TAG_MODE_OFF);
}

// The source groups of the NodeConfig, the Peer objects and the Device objects, and the tag modes of the Vrf objects, among
// num objects into the state, which holds the VRFs, the peers and the Devices that the client took from them already
void ControlCopySourceGroups(CONTROL_STATE *st, const ranz_control_v1_Object *objects, UINT num) {
	st->NumGroups = 0;

	for (UINT i = 0; i < num; i++) {
		const ranz_control_v1_Object *o = &objects[i];

		if (o->which_kind == ranz_control_v1_Object_node_tag) {
			ControlCopyGroups(st->Groups, &st->NumGroups, o->kind.node.groups, o->kind.node.groups_count);
		} else if (o->which_kind == ranz_control_v1_Object_vrf_tag) {
			for (UINT j = 0; j < st->NumVrfs; j++)
				if (strcmp(st->Vrfs[j].Name, o->kind.vrf.name) == 0)
					st->Vrfs[j].TagMode = ControlTagMode(o->kind.vrf.tag_mode);
		} else if (o->which_kind == ranz_control_v1_Object_peer_tag) {
			for (UINT j = 0; j < st->NumPeers; j++) {
				CONTROL_PEER *p = &st->Peers[j];

				if (strcmp(p->Name, o->kind.peer.name) != 0)
					continue;
				ControlCopyGroups(p->Groups, &p->NumGroups, o->kind.peer.groups, o->kind.peer.groups_count);
				p->FrameVersion = o->kind.peer.frame_version;
			}
		} else if (o->which_kind == ranz_control_v1_Object_device_tag && o->kind.device.group <= 0xFFFF) {
			for (UINT j = 0; j < st->NumDevices && st->Devices != NULL; j++) {
				CONTROL_DEVICE *d = &st->Devices[j];

				if (strcmp(d->Name, o->kind.device.name) != 0)
					continue;
				d->Group = o->kind.device.group;
				d->TagSet = o->kind.device.tag_set;
			}
		}
	}
}

//
// The counters
//

CONTROL_SOURCE_GROUPS *ControlNewSourceGroups(CONTROL_GROUPS_PROC *proc, void *param) {
	if (proc == NULL)
		return NULL;

	CONTROL_SOURCE_GROUPS *g = ControlSourceGroupAlloc(sizeof(CONTROL_SOURCE_GROUPS));
	if (g == NULL)
		return NULL;

	g->Proc = proc;
	g->Param = param;
	g->Message = ControlSourceGroupAlloc(sizeof(ranz_control_v1_Telemetry));
	if (g->Message == NULL) {
		ControlSourceGroupFree(g);
		return NULL;
	}

	return g;
}

void ControlFreeSourceGroups(CONTROL_SOURCE_GROUPS *g) {
	if (g == NULL)
		return;

	ControlSourceGroupFree(g->Message);
	ControlSourceGroupFree(g);
}

// A new stream has none of the counters: the client looks at them at once and sends them when they hold any
void ControlSourceGroupsResend(CONTROL_SOURCE_GROUPS *g) {
	if (g == NULL)
		return;

	g->Sent = 0;
	g->Looked = 0;
	ZeroMemory(g->Last, sizeof(g->Last));
}

// The tag mode of the counters of the index mode (CONTROL_TAG_MODE_*) as the control protocol carries it
static ranz_control_v1_TagMode ControlCountersMode(UINT mode) {
	if (mode == CONTROL_TAG_MODE_SESSION)
		return ranz_control_v1_TagMode_TAG_MODE_SESSION;
	if (mode == CONTROL_TAG_MODE_TRUSTED)
		return ranz_control_v1_TagMode_TAG_MODE_TRUSTED_UNDERLAY;

	return ranz_control_v1_TagMode_TAG_MODE_OFF;
}

// Write m as the body Telemetry of a ControlMessage, in one frame
static bool ControlSourceGroupsSend(const ranz_control_v1_Telemetry *m, TRANSPORT_STREAM *s) {
	pb_ostream_t sizing = PB_OSTREAM_SIZING;

	if (pb_encode_tag(&sizing, PB_WT_STRING, ranz_control_v1_ControlMessage_telemetry_tag) == false || pb_encode_submessage(&sizing, ranz_control_v1_Telemetry_fields, m) == false)
		return false;

	UINT size = (UINT)sizing.bytes_written;
	UCHAR *frame = ControlSourceGroupAlloc(CONTROL_SOURCE_GROUPS_HEADER + (SIZE_T)size);
	if (frame == NULL)
		return false;

	pb_ostream_t os = pb_ostream_from_buffer(frame + CONTROL_SOURCE_GROUPS_HEADER, size);
	bool ok = (pb_encode_tag(&os, PB_WT_STRING, ranz_control_v1_ControlMessage_telemetry_tag) && pb_encode_submessage(&os, ranz_control_v1_Telemetry_fields, m) && os.bytes_written == size);
	if (ok) {
		frame[0] = (UCHAR)(size >> 24);
		frame[1] = (UCHAR)(size >> 16);
		frame[2] = (UCHAR)(size >> 8);
		frame[3] = (UCHAR)size;
		ok = TransportWrite(s, frame, CONTROL_SOURCE_GROUPS_HEADER + size);
	}

	ControlSourceGroupFree(frame);
	return ok;
}

// Write the counters of every tag mode as one Telemetry message when they are due, on the thread of the client: the client
// looks at them every CONTROL_GROUP_REPORT ms, and sends them when they hold any and differ from the ones it sent on the
// stream that runs, or CONTROL_GROUP_REFRESH ms passed since it sent them. False when the write failed, which ends the
// stream.
bool ControlWriteSourceGroups(CONTROL_SOURCE_GROUPS *g, TRANSPORT_STREAM *s) {
	CONTROL_GROUP_COUNTERS now[CONTROL_TAG_MODES];
	UINT64 tick = GetTickCount64();
	bool any = false;

	if (g == NULL || (g->Looked != 0 && tick - g->Looked < CONTROL_GROUP_REPORT))
		return true;
	g->Looked = tick;

	ZeroMemory(now, sizeof(now));
	g->Proc(g->Param, now);
	for (UINT i = 0; i < CONTROL_TAG_MODES; i++)
		any = any || now[i].Carried != 0 || now[i].Missing != 0 || now[i].Ignored != 0 || now[i].Refused != 0;

	if (any == false || (g->Sent != 0 && memcmp(now, g->Last, sizeof(now)) == 0 && tick - g->Sent < CONTROL_GROUP_REFRESH))
		return true;

	ranz_control_v1_Telemetry *m = g->Message;
	ZeroMemory(m, sizeof(ranz_control_v1_Telemetry));
	for (UINT i = 0; i < CONTROL_TAG_MODES && m->groups_count < ARRAYSIZE(m->groups); i++) {
		ranz_control_v1_SourceGroupCounters *c = &m->groups[m->groups_count++];

		c->mode = ControlCountersMode(i);
		c->carried = now[i].Carried;
		c->missing = now[i].Missing;
		c->ignored = now[i].Ignored;
		c->refused = now[i].Refused;
	}

	if (ControlSourceGroupsSend(m, s) == false)
		return false;

	CopyMemory(g->Last, now, sizeof(now));
	g->Sent = tick;
	return true;
}
