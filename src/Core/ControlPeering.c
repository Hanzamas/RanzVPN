// ControlPeering.c
// The BGP peering of the standard mode on the control stream (SDN-77, #357; Core/Control.h). The Vrf object of a VRF whose
// nodes exchange their routes by BGP says so (CONTROL_VRF.Peering), the NodeConfig carries the settings of the sidecar ranz bgp
// of the node and the LAN subnets that it announces (CONTROL_STATE.Peering), and the Peer object of each peer that shares such
// a VRF with the node carries the address of the sidecar of the peer, the hold time of their session, its VRFs and what the
// peer may announce there (CONTROL_PEER.Peering), with the role of the peer in each VRF of route reflectors (SDN-79, #359).
// They go with the state, as the owner takes it (ControlCopyPeerings). The controller writes nothing else: the routes go
// between the sidecars.
//
// The node reports the peers of its sidecar, the state of each session and the prefixes that it learned from each, with the
// sessions that the sidecar refused (ControlSetPeeringReport): the client sends them as the peering of a Telemetry message of
// their own after each Hello, so a controller that the node reaches anew has them, and whenever they changed, at most every
// CONTROL_PEERING_INTERVAL ms.

#include "Core/ControlInternal.h"

#include <pb_encode.h>

#include <string.h>

#define CONTROL_PEERING_HEADER 4 // The size of a frame, big-endian, before its message (as Control.c writes them)

// The state and the report hold what the schema holds
_Static_assert(CONTROL_MAX_ANNOUNCE == sizeof(((ranz_control_v1_NodePeering *)0)->announce) / sizeof(((ranz_control_v1_NodePeering *)0)->announce[0]), "a NodePeering holds CONTROL_MAX_ANNOUNCE LAN subnets");
_Static_assert(CONTROL_MAX_ACCEPT == sizeof(((ranz_control_v1_PeerPeering *)0)->accept) / sizeof(((ranz_control_v1_PeerPeering *)0)->accept[0]), "a PeerPeering holds CONTROL_MAX_ACCEPT prefixes");
_Static_assert(CONTROL_MAX_PEERING_PEERS == sizeof(((ranz_control_v1_PeeringReport *)0)->peers) / sizeof(((ranz_control_v1_PeeringReport *)0)->peers[0]), "a PeeringReport holds CONTROL_MAX_PEERING_PEERS peers");
_Static_assert(CONTROL_MAX_LEARNED == sizeof(((ranz_control_v1_PeeringPeer *)0)->learned) / sizeof(((ranz_control_v1_PeeringPeer *)0)->learned[0]), "a PeeringPeer holds CONTROL_MAX_LEARNED prefixes");
_Static_assert(CONTROL_PEERING_STATE_SIZE == sizeof(((ranz_control_v1_PeeringPeer *)0)->state), "the state of a PeeringPeer has CONTROL_PEERING_STATE_SIZE bytes");
_Static_assert(CONTROL_MAX_VRFS == sizeof(((ranz_control_v1_PeerPeering *)0)->reflector_vrf_ids) / sizeof(((ranz_control_v1_PeerPeering *)0)->reflector_vrf_ids[0]), "a PeerPeering names CONTROL_MAX_VRFS VRFs of each role");
_Static_assert(CONTROL_MAX_VRFS == sizeof(((ranz_control_v1_PeerPeering *)0)->client_vrf_ids) / sizeof(((ranz_control_v1_PeerPeering *)0)->client_vrf_ids[0]), "a PeerPeering names CONTROL_MAX_VRFS VRFs of each role");
_Static_assert(CONTROL_MAX_VRFS == sizeof(((ranz_control_v1_PeerPeering *)0)->reflected_vrf_ids) / sizeof(((ranz_control_v1_PeerPeering *)0)->reflected_vrf_ids[0]), "a PeerPeering names CONTROL_MAX_VRFS VRFs of each role");

// The report that a client sends
struct CONTROL_PEERING_REPORT {
	// The report and its state
	SRWLOCK Lock;
	// The owner set the report: before it the client sends none
	bool Set;
	// The peers of the sidecar of the node and the sessions that it refused, as the owner set them last
	UINT NumPeers;
	CONTROL_PEERING_PEER Peers[CONTROL_MAX_PEERING_PEERS];
	UINT64 Refused;
	// They changed since the client sent them
	bool Changed;
	// When the client sent them last, 0 for never on the stream that runs
	UINT64 Sent;
	// The message that the thread of the client writes
	ranz_control_v1_Telemetry *Message;
};

static void *ControlPeeringAlloc(SIZE_T size) {
	return HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, size);
}

static void ControlPeeringRelease(void *p) {
	if (p != NULL)
		HeapFree(GetProcessHeap(), 0, p);
}

//
// The peering of a state
//

// The route src into dst: false for one without a prefix that is IPv4 or IPv6 and no longer than its address
static bool ControlPeeringRoute(CONTROL_ROUTE *dst, const ranz_control_v1_Route *src) {
	ZeroMemory(dst, sizeof(CONTROL_ROUTE));

	if (src->has_prefix == false || (src->prefix.address.size != 4 && src->prefix.address.size != 16) || src->prefix.length > (uint32_t)src->prefix.address.size * 8)
		return false;

	dst->VrfId = src->vrf_id;
	CopyMemory(dst->Address, src->prefix.address.bytes, src->prefix.address.size);
	dst->AddressSize = src->prefix.address.size;
	dst->Length = src->prefix.length;

	return true;
}

// The address of a sidecar, size bytes at bytes, into dst (16 bytes): false for one that is neither IPv4 nor IPv6
static bool ControlPeeringAddress(UCHAR *dst, UINT *dst_size, const UCHAR *bytes, pb_size_t size) {
	if (size != 4 && size != 16)
		return false;

	ZeroMemory(dst, 16);
	CopyMemory(dst, bytes, size);
	*dst_size = size;

	return true;
}

// The BGP peering of the NodeConfig src: NULL for one without a router id of 4 bytes or an address that is IPv4 or IPv6, and
// when there is no memory. A LAN subnet that cannot be read is left out.
static CONTROL_PEERING *ControlNodePeering(const ranz_control_v1_NodePeering *src) {
	CONTROL_PEERING *p = ControlPeeringAlloc(sizeof(CONTROL_PEERING));

	if (p == NULL)
		return NULL;

	if (src->router_id.size != 4 || ControlPeeringAddress(p->Address, &p->AddressSize, src->address.bytes, src->address.size) == false) {
		ControlPeeringRelease(p);
		return NULL;
	}

	p->Asn = src->asn;
	CopyMemory(p->RouterId, src->router_id.bytes, 4);

	for (pb_size_t i = 0; i < src->announce_count && i < ARRAYSIZE(src->announce) && p->NumAnnounce < CONTROL_MAX_ANNOUNCE; i++)
		if (ControlPeeringRoute(&p->Announce[p->NumAnnounce], &src->announce[i]))
			p->NumAnnounce++;

	return p;
}

// The BGP peering with a peer of the Peer object src: NULL for one without an address that is IPv4 or IPv6 or without a VRF,
// and when there is no memory. A prefix that cannot be read is left out.
static CONTROL_PEER_PEERING *ControlPeerPeering(const ranz_control_v1_PeerPeering *src) {
	CONTROL_PEER_PEERING *p = ControlPeeringAlloc(sizeof(CONTROL_PEER_PEERING));

	if (p == NULL)
		return NULL;

	if (ControlPeeringAddress(p->Address, &p->AddressSize, src->address.bytes, src->address.size) == false || src->vrf_ids_count == 0) {
		ControlPeeringRelease(p);
		return NULL;
	}

	p->HoldTime = src->hold_time;

	for (pb_size_t i = 0; i < src->vrf_ids_count && i < ARRAYSIZE(src->vrf_ids) && p->NumVrfs < CONTROL_MAX_VRFS; i++)
		p->VrfIds[p->NumVrfs++] = src->vrf_ids[i];

	for (pb_size_t i = 0; i < src->accept_count && i < ARRAYSIZE(src->accept) && p->NumAccept < CONTROL_MAX_ACCEPT; i++)
		if (ControlPeeringRoute(&p->Accept[p->NumAccept], &src->accept[i]))
			p->NumAccept++;

	// The roles of the peer in the VRFs of route reflectors (SDN-79, #359)
	for (pb_size_t i = 0; i < src->reflector_vrf_ids_count && i < ARRAYSIZE(src->reflector_vrf_ids) && p->NumReflectorVrfs < CONTROL_MAX_VRFS; i++)
		p->ReflectorVrfIds[p->NumReflectorVrfs++] = src->reflector_vrf_ids[i];
	for (pb_size_t i = 0; i < src->client_vrf_ids_count && i < ARRAYSIZE(src->client_vrf_ids) && p->NumClientVrfs < CONTROL_MAX_VRFS; i++)
		p->ClientVrfIds[p->NumClientVrfs++] = src->client_vrf_ids[i];
	for (pb_size_t i = 0; i < src->reflected_vrf_ids_count && i < ARRAYSIZE(src->reflected_vrf_ids) && p->NumReflectedVrfs < CONTROL_MAX_VRFS; i++)
		p->ReflectedVrfIds[p->NumReflectedVrfs++] = src->reflected_vrf_ids[i];

	return p;
}

// The BGP peering of the Vrf objects, of the NodeConfig and of the Peer objects among num objects into the state, which holds
// the VRFs and the peers that the client took from them already. A peering that cannot be read whole is none.
void ControlCopyPeerings(CONTROL_STATE *st, const ranz_control_v1_Object *objects, UINT num) {
	st->Peering = NULL;

	for (UINT i = 0; i < num; i++) {
		const ranz_control_v1_Object *o = &objects[i];

		if (o->which_kind == ranz_control_v1_Object_vrf_tag) {
			for (UINT j = 0; j < st->NumVrfs; j++)
				if (strcmp(st->Vrfs[j].Name, o->kind.vrf.name) == 0)
					st->Vrfs[j].Peering = (o->kind.vrf.peering == ranz_control_v1_Peering_PEERING_BGP);
		} else if (o->which_kind == ranz_control_v1_Object_node_tag && o->kind.node.has_peering && st->Peering == NULL) {
			st->Peering = ControlNodePeering(&o->kind.node.peering);
		} else if (o->which_kind == ranz_control_v1_Object_peer_tag && o->kind.peer.has_peering) {
			for (UINT j = 0; j < st->NumPeers; j++) {
				CONTROL_PEER *p = &st->Peers[j];

				if (p->Peering == NULL && strcmp(p->Name, o->kind.peer.name) == 0)
					p->Peering = ControlPeerPeering(&o->kind.peer.peering);
			}
		}
	}
}

// Free the BGP peering that ControlCopyPeerings put into st
void ControlFreePeerings(CONTROL_STATE *st) {
	ControlPeeringRelease(st->Peering);
	st->Peering = NULL;

	for (UINT i = 0; st->Peers != NULL && i < st->NumPeers; i++) {
		ControlPeeringRelease(st->Peers[i].Peering);
		st->Peers[i].Peering = NULL;
	}
}

//
// The report
//

CONTROL_PEERING_REPORT *ControlNewPeeringReport() {
	CONTROL_PEERING_REPORT *r = ControlPeeringAlloc(sizeof(CONTROL_PEERING_REPORT));

	if (r == NULL)
		return NULL;

	InitializeSRWLock(&r->Lock);
	r->Message = ControlPeeringAlloc(sizeof(ranz_control_v1_Telemetry));
	if (r->Message == NULL) {
		ControlPeeringRelease(r);
		return NULL;
	}

	return r;
}

void ControlFreePeeringReport(CONTROL_PEERING_REPORT *r) {
	if (r == NULL)
		return;

	ControlPeeringRelease(r->Message);
	ControlPeeringRelease(r);
}

// Put the num peers, CONTROL_MAX_PEERING_PEERS at most, and the refused sessions in place of the ones before: the client sends
// them when they differ from the ones that it sent. The caller zeroes each peer before it fills it, so that two reports of the
// same peers have the same bytes.
void ControlSetPeeringReport(CONTROL_PEERING_REPORT *r, const CONTROL_PEERING_PEER *peers, UINT num, UINT64 refused) {
	if (r == NULL || (peers == NULL && num != 0))
		return;

	num = (num < CONTROL_MAX_PEERING_PEERS ? num : CONTROL_MAX_PEERING_PEERS);

	AcquireSRWLockExclusive(&r->Lock);
	if (r->Set == false || num != r->NumPeers || refused != r->Refused || (num != 0 && memcmp(r->Peers, peers, sizeof(CONTROL_PEERING_PEER) * num) != 0)) {
		if (num != 0)
			CopyMemory(r->Peers, peers, sizeof(CONTROL_PEERING_PEER) * num);
		r->NumPeers = num;
		r->Refused = refused;
		r->Set = true;
		r->Changed = true;
	}
	ReleaseSRWLockExclusive(&r->Lock);
}

UINT ControlGetPeeringReport(CONTROL_PEERING_REPORT *r, CONTROL_PEERING_PEER *list, UINT max, UINT64 *refused) {
	UINT num = 0;

	if (refused != NULL)
		*refused = 0;
	if (r == NULL || list == NULL)
		return 0;

	AcquireSRWLockShared(&r->Lock);
	num = (r->NumPeers < max ? r->NumPeers : max);
	if (num != 0)
		CopyMemory(list, r->Peers, sizeof(CONTROL_PEERING_PEER) * num);
	if (refused != NULL)
		*refused = r->Refused;
	ReleaseSRWLockShared(&r->Lock);

	return num;
}

// A new stream has no report yet: the client sends the one that the owner set
void ControlPeeringResend(CONTROL_PEERING_REPORT *r) {
	if (r == NULL)
		return;

	AcquireSRWLockExclusive(&r->Lock);
	r->Changed = r->Set;
	r->Sent = 0;
	ReleaseSRWLockExclusive(&r->Lock);
}

// The route src into the Route dst of the schema
static void ControlPeeringRouteOut(ranz_control_v1_Route *dst, const CONTROL_ROUTE *src) {
	UINT size = (src->AddressSize == 4 ? 4 : 16);

	dst->vrf_id = src->VrfId;
	dst->has_prefix = true;
	dst->prefix.address.size = (pb_size_t)size;
	CopyMemory(dst->prefix.address.bytes, src->Address, size);
	dst->prefix.length = src->Length;
}

// Fill the message with the report. The caller holds the lock.
static void ControlPeeringFill(CONTROL_PEERING_REPORT *r) {
	ranz_control_v1_Telemetry *m = r->Message;

	ZeroMemory(m, sizeof(ranz_control_v1_Telemetry));
	m->has_peering = true;
	m->peering.refused = r->Refused;

	for (UINT i = 0; i < r->NumPeers && i < ARRAYSIZE(m->peering.peers); i++) {
		const CONTROL_PEERING_PEER *p = &r->Peers[i];
		ranz_control_v1_PeeringPeer *out = &m->peering.peers[m->peering.peers_count++];
		UINT size = (p->AddressSize == 4 ? 4 : 16);

		out->address.size = (pb_size_t)size;
		CopyMemory(out->address.bytes, p->Address, size);
		strncpy_s(out->state, sizeof(out->state), p->State, _TRUNCATE);

		for (UINT j = 0; j < p->NumLearned && j < CONTROL_MAX_LEARNED && j < ARRAYSIZE(out->learned); j++)
			ControlPeeringRouteOut(&out->learned[out->learned_count++], &p->Learned[j]);
	}
}

// Write m as the body Telemetry of a ControlMessage, in one frame
static bool ControlPeeringSend(const ranz_control_v1_Telemetry *m, TRANSPORT_STREAM *s) {
	pb_ostream_t sizing = PB_OSTREAM_SIZING;

	if (pb_encode_tag(&sizing, PB_WT_STRING, ranz_control_v1_ControlMessage_telemetry_tag) == false || pb_encode_submessage(&sizing, ranz_control_v1_Telemetry_fields, m) == false)
		return false;

	UINT size = (UINT)sizing.bytes_written;
	UCHAR *frame = ControlPeeringAlloc(CONTROL_PEERING_HEADER + (SIZE_T)size);
	if (frame == NULL)
		return false;

	pb_ostream_t os = pb_ostream_from_buffer(frame + CONTROL_PEERING_HEADER, size);
	bool ok = pb_encode_tag(&os, PB_WT_STRING, ranz_control_v1_ControlMessage_telemetry_tag) && pb_encode_submessage(&os, ranz_control_v1_Telemetry_fields, m) && os.bytes_written == size;
	if (ok) {
		frame[0] = (UCHAR)(size >> 24);
		frame[1] = (UCHAR)(size >> 16);
		frame[2] = (UCHAR)(size >> 8);
		frame[3] = (UCHAR)size;
		ok = TransportWrite(s, frame, CONTROL_PEERING_HEADER + size);
	}

	ControlPeeringRelease(frame);
	return ok;
}

// Write the report as one Telemetry message when it changed since the client sent it and CONTROL_PEERING_INTERVAL ms passed
// since then, on the thread of the client: false when the write failed, which ends the stream
bool ControlWritePeeringReport(CONTROL_PEERING_REPORT *r, TRANSPORT_STREAM *s) {
	bool due = false;
	UINT64 now = GetTickCount64();

	if (r == NULL)
		return true;

	AcquireSRWLockExclusive(&r->Lock);
	if (r->Changed && (r->Sent == 0 || now - r->Sent >= CONTROL_PEERING_INTERVAL)) {
		ControlPeeringFill(r);
		r->Changed = false;
		r->Sent = now;
		due = true;
	}
	ReleaseSRWLockExclusive(&r->Lock);

	// Only the thread of the client uses the message
	return (due == false || ControlPeeringSend(r->Message, s));
}
