// Control.c
// The node's end of the control stream (Core/Control.h). The thread of a client opens the stream,
// runs the handshake, says Hello, and then reads the frames of the controller: it applies each
// Update to the objects it holds, hands the state to its owner and acknowledges the Generation.
// A Refuse, a frame it cannot take, a failed write or the end of the stream close the stream, and
// the thread opens it again after a delay that grows while the attempts fail (ControlRetry.c). The
// objects stay as they were applied last.

#include "Core/Control.h"

#include <pb_decode.h>
#include <pb_encode.h>

#include "ranz/control/v1/control.pb.h"
#include "Core/ControlPolicy.h"

#include "Core/ControlInternal.h"

#include <stdlib.h>
#include <string.h>

#define CONTROL_FRAME_HEADER 4    // The size of a frame, big-endian, before its message
#define CONTROL_OUT_SIZE     1024 // The frames the client writes: the handshake, the Hello and the Acks
#define CONTROL_POLL         100  // ms that one read waits, between two looks at the halt event

// What a read of a frame gave
#define CONTROL_FRAME_DONE  0 // A whole frame is in Frame
#define CONTROL_FRAME_LATER 1 // Not within the timeout: the bytes read so far stay in Frame
#define CONTROL_FRAME_END   2 // The stream ended, or its next frame is larger than allowed

// The client of one node
struct CONTROL_CLIENT {
	CONTROL_CONFIG Config;                   // Its configuration; StaticKey points at Key
	UCHAR Key[NOISE_KEY_SIZE];               // The node's static scalar, when the configuration gives one
	HANDLE Thread;                           // The thread of the client
	HANDLE Halt;                             // Set by ControlStop (a manual-reset event)
	SRWLOCK Lock;                            // Status
	CONTROL_STATUS Status;                   // How the client stands
	ranz_control_v1_Object *Objects;         // The desired state at Status.Applied: its objects, one per kind and name
	UINT NumObjects;                         // ... their number
	ranz_control_v1_ControlMessage *Message; // The message that was read last, or that is written
	UCHAR *Frame;                            // The frame being read: its size, then its message
	UINT FrameSize;                          // ... its bytes read so far
	UCHAR *Out;                              // The frame being written
};

static void *ControlAlloc(SIZE_T size) {
	return HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, size);
}

// Wipe and free size bytes at p, which may be NULL
static void ControlRelease(void *p, SIZE_T size) {
	if (p == NULL)
		return;

	SecureZeroMemory(p, size);
	HeapFree(GetProcessHeap(), 0, p);
}

// Free a client whose thread does not run: one that ControlNew made, or one whose thread ended
void ControlFree(CONTROL_CLIENT *c) {
	if (c == NULL)
		return;

	if (c->Halt != NULL)
		CloseHandle(c->Halt);
	ControlRelease(c->Objects, sizeof(ranz_control_v1_Object) * (c->NumObjects != 0 ? c->NumObjects : 1));
	ControlRelease(c->Message, sizeof(ranz_control_v1_ControlMessage));
	ControlRelease(c->Frame, CONTROL_FRAME_HEADER + CONTROL_MAX_FRAME);
	ControlRelease(c->Out, CONTROL_OUT_SIZE);
	ControlRelease(c, sizeof(CONTROL_CLIENT));
}

static bool ControlHalted(CONTROL_CLIENT *c) {
	return WaitForSingleObject(c->Halt, 0) != WAIT_TIMEOUT;
}

//
// The frames
//

// Write size bytes at Out after the frame header, as one frame
static bool ControlWriteFrame(CONTROL_CLIENT *c, TRANSPORT_STREAM *s, UINT size) {
	c->Out[0] = (UCHAR)(size >> 24);
	c->Out[1] = (UCHAR)(size >> 16);
	c->Out[2] = (UCHAR)(size >> 8);
	c->Out[3] = (UCHAR)size;

	return TransportWrite(s, c->Out, CONTROL_FRAME_HEADER + size);
}

// Write Message as one frame
static bool ControlWrite(CONTROL_CLIENT *c, TRANSPORT_STREAM *s) {
	pb_ostream_t os = pb_ostream_from_buffer(c->Out + CONTROL_FRAME_HEADER, CONTROL_OUT_SIZE - CONTROL_FRAME_HEADER);

	if (pb_encode(&os, ranz_control_v1_ControlMessage_fields, c->Message) == false)
		return false;

	return ControlWriteFrame(c, s, (UINT)os.bytes_written);
}

// Read the next frame, of max bytes at most, into Frame within timeout. A frame that the timeout
// cut short stays in Frame for the next read; the caller empties Frame (FrameSize = 0) once it took
// a whole frame.
static UINT ControlRead(CONTROL_CLIENT *c, TRANSPORT_STREAM *s, UINT max, UINT timeout) {
	UINT64 end = GetTickCount64() + timeout;

	while (true) {
		UINT need = CONTROL_FRAME_HEADER;

		if (c->FrameSize >= CONTROL_FRAME_HEADER) {
			UINT size = ((UINT)c->Frame[0] << 24) | ((UINT)c->Frame[1] << 16) | ((UINT)c->Frame[2] << 8) | c->Frame[3];
			if (size == 0 || size > max)
				return CONTROL_FRAME_END;
			need += size;
			if (c->FrameSize == need)
				return CONTROL_FRAME_DONE;
		}

		UINT64 now = GetTickCount64();
		UINT got = TransportRead(s, c->Frame + c->FrameSize, need - c->FrameSize, (now >= end ? 0 : (UINT)(end - now)));
		if (got == TRANSPORT_LATER)
			return CONTROL_FRAME_LATER;
		if (got == 0 || got > need - c->FrameSize)
			return CONTROL_FRAME_END;
		c->FrameSize += got;
	}
}

// Read a whole frame of max bytes at most within timeout, unless the client halts first
static bool ControlReadWhole(CONTROL_CLIENT *c, TRANSPORT_STREAM *s, UINT max, UINT timeout) {
	UINT64 end = GetTickCount64() + timeout;

	while (ControlHalted(c) == false && GetTickCount64() < end) {
		UINT r = ControlRead(c, s, max, CONTROL_POLL);
		if (r == CONTROL_FRAME_DONE)
			return true;
		if (r == CONTROL_FRAME_END)
			return false;
	}

	return false;
}

//
// The desired state
//

// The name of an object, NULL for an object of no kind the client knows
static const char *ControlObjectName(const ranz_control_v1_Object *o) {
	switch (o->which_kind) {
	case ranz_control_v1_Object_node_tag:
		return o->kind.node.name;
	case ranz_control_v1_Object_vrf_tag:
		return o->kind.vrf.name;
	case ranz_control_v1_Object_network_tag:
		return o->kind.network.name;
	case ranz_control_v1_Object_peer_tag:
		return o->kind.peer.name;
	case ranz_control_v1_Object_relay_tag:
		return o->kind.relay.name;
	case ranz_control_v1_Object_rule_tag:
		return o->kind.rule.name;
	case ranz_control_v1_Object_device_tag:
		return o->kind.device.name;
	default:
		break;
	}

	return NULL;
}

// The index of the object of kind and name among num objects, num when there is none. The tags of
// the kinds of an Object are the values of Kind (control.proto).
static UINT ControlFind(const ranz_control_v1_Object *objects, UINT num, UINT kind, const char *name) {
	for (UINT i = 0; i < num; i++)
		if (objects[i].which_kind == kind && strcmp(ControlObjectName(&objects[i]), name) == 0)
			return i;

	return num;
}

// Apply u to the objects: a full state replaces them, a delta from the Generation applied last
// takes its removed objects away and sets the others. false for an Update that does not apply,
// which leaves the objects as they were.
bool ControlApply(CONTROL_CLIENT *c, const ranz_control_v1_Update *u) {
	bool delta = (u->base_generation != 0);
	UINT num = 0;

	if (u->generation == 0 || (delta && u->base_generation != c->Status.Applied))
		return false;

	UINT max = (delta ? c->NumObjects : 0) + u->set_count;
	ranz_control_v1_Object *next = ControlAlloc(sizeof(ranz_control_v1_Object) * (max != 0 ? max : 1));
	if (next == NULL)
		return false;

	for (UINT i = 0; delta && i < c->NumObjects; i++) {
		const ranz_control_v1_Object *o = &c->Objects[i];
		bool removed = false;

		for (UINT j = 0; j < u->remove_count && removed == false; j++)
			removed = ((UINT)u->remove[j].kind == o->which_kind && strcmp(u->remove[j].name, ControlObjectName(o)) == 0);
		if (removed == false)
			CopyMemory(&next[num++], o, sizeof(ranz_control_v1_Object));
	}

	for (UINT i = 0; i < u->set_count; i++) {
		const ranz_control_v1_Object *o = &u->set[i];
		const char *name = ControlObjectName(o);

		if (name == NULL) {
			ControlRelease(next, sizeof(ranz_control_v1_Object) * (max != 0 ? max : 1));
			return false;
		}

		UINT k = ControlFind(next, num, o->which_kind, name);
		CopyMemory(&next[k], o, sizeof(ranz_control_v1_Object));
		if (k == num)
			num++;
	}

	// The allocation of the objects is their number from here on
	ranz_control_v1_Object *objects = ControlAlloc(sizeof(ranz_control_v1_Object) * (num != 0 ? num : 1));
	if (objects == NULL) {
		ControlRelease(next, sizeof(ranz_control_v1_Object) * (max != 0 ? max : 1));
		return false;
	}
	CopyMemory(objects, next, sizeof(ranz_control_v1_Object) * num);
	ControlRelease(next, sizeof(ranz_control_v1_Object) * (max != 0 ? max : 1));

	ControlRelease(c->Objects, sizeof(ranz_control_v1_Object) * (c->NumObjects != 0 ? c->NumObjects : 1));
	c->Objects = objects;
	c->NumObjects = num;

	return true;
}

// The Mirrors of the NodeConfig among num objects (SDN-23, #199); a Mirror whose sensor is neither an IPv4 nor an
// IPv6 address is left out
static void ControlCopyMirrors(CONTROL_STATE *st, const ranz_control_v1_Object *objects, UINT num) {
	st->NumMirrors = 0;

	for (UINT i = 0; i < num; i++) {
		if (objects[i].which_kind != ranz_control_v1_Object_node_tag)
			continue;

		const ranz_control_v1_NodeConfig *node = &objects[i].kind.node;

		for (pb_size_t j = 0; j < node->mirrors_count && st->NumMirrors < CONTROL_MAX_MIRRORS; j++) {
			const ranz_control_v1_Mirror *src = &node->mirrors[j];
			CONTROL_MIRROR *m = &st->Mirrors[st->NumMirrors];

			if (src->sensor.size != 4 && src->sensor.size != 16)
				continue;

			ZeroMemory(m, sizeof(CONTROL_MIRROR));
			strncpy_s(m->Name, sizeof(m->Name), src->name, _TRUNCATE);
			m->VrfId = src->vrf_id;
			m->Protocol = src->protocol;
			m->Port = src->port;
			CopyMemory(m->Sensor, src->sensor.bytes, src->sensor.size);
			m->SensorSize = src->sensor.size;
			m->SensorPort = src->sensor_port;
			m->Vni = src->vni;
			m->RateLimit = src->rate_limit;
			st->NumMirrors++;
		}
	}
}

static void ControlCopyAddresses(CONTROL_ADDRESS *dst, UINT *num, const ranz_control_v1_Address *src, pb_size_t count) {
	*num = 0;

	for (pb_size_t i = 0; i < count && *num < CONTROL_MAX_ADDRESSES; i++) {
		CONTROL_ADDRESS *a = &dst[*num];

		if (src[i].has_prefix == false || src[i].prefix.address.size > sizeof(a->Address))
			continue;

		ZeroMemory(a, sizeof(CONTROL_ADDRESS));
		strncpy_s(a->Network, sizeof(a->Network), src[i].network, _TRUNCATE);
		a->VrfId = src[i].vrf_id;
		CopyMemory(a->Address, src[i].prefix.address.bytes, src[i].prefix.address.size);
		a->AddressSize = src[i].prefix.address.size;
		a->Length = src[i].prefix.length;
		(*num)++;
	}
}

// Copy the prefix p into addr (16 bytes), with the number of its bytes and its length: false for a prefix that is
// neither IPv4 nor IPv6, or longer than its address
static bool ControlCopyPrefix(UCHAR *addr, UINT *size, UINT *length, const ranz_control_v1_Prefix *p) {
	if ((p->address.size != 4 && p->address.size != 16) || p->length > (uint32_t)p->address.size * 8)
		return false;

	ZeroMemory(addr, 16);
	CopyMemory(addr, p->address.bytes, p->address.size);
	*size = p->address.size;
	*length = p->length;

	return true;
}

// The 1:1 NAT rules of a NodeConfig (SDN-6, #182); a rule without both prefixes is left out
static void ControlCopyNats(CONTROL_NAT *dst, UINT *num, const ranz_control_v1_Nat *src, pb_size_t count) {
	*num = 0;

	for (pb_size_t i = 0; i < count && *num < CONTROL_MAX_NATS; i++) {
		CONTROL_NAT *n = &dst[*num];

		ZeroMemory(n, sizeof(CONTROL_NAT));
		n->VrfId = src[i].vrf_id;
		if (src[i].has_inside && src[i].has_outside && ControlCopyPrefix(n->Inside, &n->InsideSize, &n->InsideLength, &src[i].inside) && ControlCopyPrefix(n->Outside, &n->OutsideSize, &n->OutsideLength, &src[i].outside))
			(*num)++;
	}
}

// The routes of a Peer (SDN-6, #182); a route without a prefix is left out
static void ControlCopyRoutes(CONTROL_ROUTE *dst, UINT *num, const ranz_control_v1_Route *src, pb_size_t count) {
	*num = 0;

	for (pb_size_t i = 0; i < count && *num < CONTROL_MAX_ROUTES; i++) {
		CONTROL_ROUTE *r = &dst[*num];

		ZeroMemory(r, sizeof(CONTROL_ROUTE));
		r->VrfId = src[i].vrf_id;
		r->PeerVrfId = src[i].peer_vrf_id;
		if (src[i].has_prefix && ControlCopyPrefix(r->Address, &r->AddressSize, &r->Length, &src[i].prefix))
			(*num)++;
	}
}

static int ControlComparePeers(const void *a, const void *b) {
	return strcmp(((const CONTROL_PEER *)a)->Name, ((const CONTROL_PEER *)b)->Name);
}

static int ControlCompareVrfs(const void *a, const void *b) {
	return strcmp(((const CONTROL_VRF *)a)->Name, ((const CONTROL_VRF *)b)->Name);
}

// Hand the objects, which are at Generation gen, to the owner
static void ControlDeliver(CONTROL_CLIENT *c, UINT64 gen) {
	CONTROL_STATE st;
	UINT num_peers = 0;

	ZeroMemory(&st, sizeof(st));
	st.Generation = gen;

	for (UINT i = 0; i < c->NumObjects; i++)
		if (c->Objects[i].which_kind == ranz_control_v1_Object_peer_tag)
			num_peers++;

	st.Peers = ControlAlloc(sizeof(CONTROL_PEER) * (num_peers != 0 ? num_peers : 1));
	if (st.Peers == NULL)
		return;

	for (UINT i = 0; i < c->NumObjects; i++) {
		const ranz_control_v1_Object *o = &c->Objects[i];

		if (o->which_kind == ranz_control_v1_Object_node_tag) {
			strncpy_s(st.Name, sizeof(st.Name), o->kind.node.name, _TRUNCATE);
			ControlCopyAddresses(st.Addresses, &st.NumAddresses, o->kind.node.addresses, o->kind.node.addresses_count);
			st.RateLimit = o->kind.node.rate_limit;
			ControlCopyNats(st.Nats, &st.NumNats, o->kind.node.nat, o->kind.node.nat_count);
		} else if (o->which_kind == ranz_control_v1_Object_vrf_tag && st.NumVrfs < CONTROL_MAX_VRFS) {
			CONTROL_VRF *v = &st.Vrfs[st.NumVrfs++];

			strncpy_s(v->Name, sizeof(v->Name), o->kind.vrf.name, _TRUNCATE);
			v->Id = o->kind.vrf.id;
			v->Mtu = o->kind.vrf.mtu;
			v->RateLimit = o->kind.vrf.rate_limit;
		} else if (o->which_kind == ranz_control_v1_Object_peer_tag && o->kind.peer.public_key.size == NOISE_KEY_SIZE) {
			CONTROL_PEER *p = &st.Peers[st.NumPeers++];

			strncpy_s(p->Name, sizeof(p->Name), o->kind.peer.name, _TRUNCATE);
			CopyMemory(p->Key, o->kind.peer.public_key.bytes, NOISE_KEY_SIZE);
			for (pb_size_t j = 0; j < o->kind.peer.vrf_ids_count && p->NumVrfs < CONTROL_MAX_VRFS; j++)
				p->VrfIds[p->NumVrfs++] = o->kind.peer.vrf_ids[j];
			ControlCopyAddresses(p->Addresses, &p->NumAddresses, o->kind.peer.addresses, o->kind.peer.addresses_count);
			ControlCopyRoutes(p->Routes, &p->NumRoutes, o->kind.peer.routes, o->kind.peer.routes_count);
		}
	}

	// The policy of the VRFs, the tags of the node and its peers, and the rules (ControlPolicy.c; SDN-8, #184)
	ControlCopyPolicy(&st, c->Objects, c->NumObjects);

	// A delta appends the objects it adds, so the VRFs and the peers are sorted again
	qsort(st.Vrfs, st.NumVrfs, sizeof(CONTROL_VRF), ControlCompareVrfs);
	qsort(st.Peers, st.NumPeers, sizeof(CONTROL_PEER), ControlComparePeers);

	ControlCopyMirrors(&st, c->Objects, c->NumObjects);
	// The DHCP responders of the L2 Networks (ControlDhcp.c; SDN-43, #236)
	ControlCopyDhcps(&st, c->Objects, c->NumObjects);
	// The zones of overlay DNS of the VRFs (ControlDns.c; SDN-11, #187)
	ControlCopyZones(&st, c->Objects, c->NumObjects);
	// The Listener of the node (ControlListener.c; SDN-45, #238)
	ControlCopyListener(&st, c->Objects, c->NumObjects);
	// The TLS fingerprints of the certificate of the Controller (ControlPins.c; SDN-92, #397)
	ControlCopyTlsPins(&st, c->Objects, c->NumObjects);
	// The WireGuard Devices (ControlDevice.c; SDN-80, #375)
	ControlCopyDevices(&st, c->Objects, c->NumObjects);
	// The endpoints of the node and of its peers (ControlEndpoint.c; SDN-93, #410)
	ControlCopyEndpoints(&st, c->Objects, c->NumObjects);
	// The kinds of the links of the VRFs and the tunnel endpoints (ControlLink.c; SDN-76, #356)
	ControlCopyLinks(&st, c->Objects, c->NumObjects);
	// The security of the L2 Networks (ControlSecurity.c; SDN-41, #234)
	ControlCopySecurities(&st, c->Objects, c->NumObjects);
	// The relays that the node may use, its home relay first (ControlSignal.c; CORE-S5-5, #411)
	ControlCopyRelays(&st, c->Objects, c->NumObjects);
	// The hubs and the ECMP of the VRFs, the LAN subnets of the node and the gateways that are down (ControlGateway.c; SDN-19,
	// #195)
	ControlCopyGateways(&st, c->Objects, c->NumObjects);
	// The BGP peering of the node and of its peers (ControlPeering.c; SDN-77, #357)
	ControlCopyPeerings(&st, c->Objects, c->NumObjects);
	// The session profiles of the node and of its peers (ControlProfile.c; SDN-40, #233)
	ControlCopyProfiles(&st, c->Objects, c->NumObjects);
	// The VRFs whose internet exit the node is (ControlEgress.c; SDN-12, #188)
	ControlCopyEgress(&st, c->Objects, c->NumObjects);

	if (c->Config.Proc != NULL)
		c->Config.Proc(c->Config.Param, &st);

	ControlFreePeerings(&st);
	ControlFreeSecurities(&st);
	ControlFreeListener(&st);
	ControlFreeZones(&st);
	ControlRelease(st.Peers, sizeof(CONTROL_PEER) * (num_peers != 0 ? num_peers : 1));
	ControlFreePolicy(&st);
	ControlFreeStateDevices(&st);
}

//
// The stream
//

// Decode the message of a frame, size bytes at data after the size of the frame, into Message with the code that nanopb
// generates from the schema: false for bytes that are no ControlMessage of it
bool ControlDecode(CONTROL_CLIENT *c, const UCHAR *data, UINT size) {
	pb_istream_t is = pb_istream_from_buffer(data, size);

	ZeroMemory(c->Message, sizeof(ranz_control_v1_ControlMessage));
	return pb_decode(&is, ranz_control_v1_ControlMessage_fields, c->Message);
}

// Take the message of a frame of the controller, size bytes at data after the size of the frame: an Update is applied
// and handed to the owner; a Signal of a peer goes to the owner as it came; the members of a cluster come with the
// module that uses them; an Operation is done, and its answer takes its place. false ends the stream: a Refuse, a message
// that does not decode or does not apply, and one that only a node sends. The message stays in Message.
bool ControlInput(CONTROL_CLIENT *c, const UCHAR *data, UINT size) {
	ranz_control_v1_ControlMessage *m = c->Message;

	if (ControlDecode(c, data, size) == false)
		return false;

	switch (m->which_body) {
	case ranz_control_v1_ControlMessage_update_tag: {
		UINT64 gen = m->body.update.generation;

		if (ControlApply(c, &m->body.update) == false)
			return false;

		ControlDeliver(c, gen);

		AcquireSRWLockExclusive(&c->Lock);
		c->Status.Applied = gen;
		c->Status.NumUpdates++;
		ReleaseSRWLockExclusive(&c->Lock);
		return true;
	}

	case ranz_control_v1_ControlMessage_refuse_tag:
		AcquireSRWLockExclusive(&c->Lock);
		c->Status.LastRefuse = (UINT)m->body.refuse.reason;
		strncpy_s(c->Status.LastMessage, sizeof(c->Status.LastMessage), m->body.refuse.message, _TRUNCATE);
		ReleaseSRWLockExclusive(&c->Lock);
		return false;

	case ranz_control_v1_ControlMessage_controllers_tag:
		return true;

	case ranz_control_v1_ControlMessage_signal_tag:
		// The envelope stays sealed: only the peer layer of the node opens it (ControlSignal.c; CORE-S5-5, #411)
		ControlTakeSignal(&c->Config, &m->body.signal);
		return true;

	case ranz_control_v1_ControlMessage_operation_tag:
		// A live operation: the node does it at once, and its answer takes its place in the message (ControlOperation.c;
		// SDN-50-N, #492)
		return ControlTakeOperation(&c->Config, c->Objects, c->NumObjects, m);

	default:
		break;
	}

	// A Hello or an Ack goes from a node to the controller, never back
	return false;
}

// Take the frame that Frame holds (ControlInput), acknowledge an Update that it applied and answer an Operation. false ends
// the stream: a message that ControlInput does not take, or a failed write.
static bool ControlTake(CONTROL_CLIENT *c, TRANSPORT_STREAM *s) {
	ranz_control_v1_ControlMessage *m = c->Message;

	if (ControlInput(c, c->Frame + CONTROL_FRAME_HEADER, c->FrameSize - CONTROL_FRAME_HEADER) == false)
		return false;
	// The answer to an Operation, which ControlInput put in its place (ControlOperation.c; SDN-50-N, #492)
	if (m->which_body == ranz_control_v1_ControlMessage_operation_result_tag)
		return ControlWriteOperationResult(&m->body.operation_result, s);
	if (m->which_body != ranz_control_v1_ControlMessage_update_tag)
		return true;

	UINT64 gen = m->body.update.generation;

	ZeroMemory(m, sizeof(ranz_control_v1_ControlMessage));
	m->which_body = ranz_control_v1_ControlMessage_ack_tag;
	m->body.ack.generation = gen;
	return ControlWrite(c, s);
}

// Put the Capabilities of the node into hello, as its owner tells them (CONTROL_CAPS_PROC): the architecture, SeLow
// and XDP. An owner that gives no procedure leaves the Hello without any, and the controller counts every Capability
// as missing then.
static void ControlSetCaps(CONTROL_CLIENT *c, ranz_control_v1_Hello *hello) {
	CONTROL_CAPS caps;

	if (c->Config.CapsProc == NULL)
		return;

	ZeroMemory(&caps, sizeof(caps));
	c->Config.CapsProc(c->Config.CapsParam, &caps);

	hello->has_capabilities = true;
	hello->capabilities.architecture = (ranz_control_v1_Architecture)caps.Architecture;
	hello->capabilities.selow = caps.SeLow;
	hello->capabilities.xdp = caps.Xdp;
	// WireGuardNT and the key of the WireGuard interface of the node (SDN-80, #375)
	hello->capabilities.wireguard = caps.WireGuard;
	if (caps.WireGuard) {
		hello->capabilities.wireguard_key.size = NOISE_KEY_SIZE;
		CopyMemory(hello->capabilities.wireguard_key.bytes, caps.WireGuardKey, NOISE_KEY_SIZE);
	}
	// The links of kind vxlan and geneve (SDN-76, #356)
	hello->capabilities.plain_links = caps.PlainLinks;
	// The BGP peering of the standard mode (SDN-77-R2, #532)
	hello->capabilities.bgp_peering = caps.BgpPeering;
	// The Windows edition and Hyper-V of the host, and the Egress tier that they give the node (SDN-12, #188)
	hello->capabilities.sku = (ranz_control_v1_Sku)caps.Sku;
	hello->capabilities.hyper_v = caps.HyperV;
	hello->capabilities.egress_tier = (ranz_control_v1_EgressTier)caps.EgressTier;
	// The gateway of a Stretch (SDN-63, #290)
	hello->capabilities.evpn = caps.Evpn;
	// The live operations, which the client does when its owner gives it their procedure (ControlOperation.c; SDN-50-N, #492)
	hello->capabilities.operations = (c->Config.OperationProc != NULL);
}

// One stream: the dial, the handshake bound to the exporter of the TLS session, the Hello, then
// the frames of the controller until the stream ends or the client halts
static void ControlRun(CONTROL_CLIENT *c) {
	UCHAR prologue[sizeof(CONTROL_PROLOGUE_LABEL) - 1 + CONTROL_EXPORTER_SIZE];
	UCHAR binding[NOISE_MAX_BINDING];
	NOISE_HANDSHAKE hs;
	UINT size = 0;
	UINT payload_size = 0;

	TRANSPORT_STREAM *s = TransportDial(c->Config.Transport, c->Config.Address, c->Halt);
	if (s == NULL) {
		AcquireSRWLockExclusive(&c->Lock);
		c->Status.LastEnd = CONTROL_END_DIAL;
		ReleaseSRWLockExclusive(&c->Lock);
		return;
	}

	// The handshake messages go in frames of their own, as the controller reads them
	c->FrameSize = 0;
	bool ok = (TransportBinding(s, binding, sizeof(binding), &size) == NOISE_BINDING_EXPORTER && size == CONTROL_EXPORTER_SIZE);
	if (ok) {
		CopyMemory(prologue, CONTROL_PROLOGUE_LABEL, sizeof(CONTROL_PROLOGUE_LABEL) - 1);
		CopyMemory(prologue + sizeof(CONTROL_PROLOGUE_LABEL) - 1, binding, CONTROL_EXPORTER_SIZE);
		ok = NoiseHandshakeInit(&hs, NOISE_SUITE_IK, true, prologue, sizeof(prologue), c->Config.StaticKey, c->Config.Identity, c->Config.ControllerKey);
	} else {
		ZeroMemory(&hs, sizeof(hs));
	}
	if (ok)
		ok = NoiseHandshakeWrite(&hs, NULL, 0, c->Out + CONTROL_FRAME_HEADER, CONTROL_OUT_SIZE - CONTROL_FRAME_HEADER, &size) && ControlWriteFrame(c, s, size);
	if (ok)
		ok = ControlReadWhole(c, s, NOISE_MAX_MESSAGE, CONTROL_TIMEOUT) &&
		     NoiseHandshakeRead(&hs, c->Frame + CONTROL_FRAME_HEADER, c->FrameSize - CONTROL_FRAME_HEADER, NULL, 0, &payload_size);
	NoiseHandshakeFree(&hs);
	SecureZeroMemory(binding, sizeof(binding));
	SecureZeroMemory(prologue, sizeof(prologue));
	c->FrameSize = 0;

	// The Hello, with the Generation applied last
	if (ok) {
		ZeroMemory(c->Message, sizeof(ranz_control_v1_ControlMessage));
		c->Message->which_body = ranz_control_v1_ControlMessage_hello_tag;
		c->Message->body.hello.schema_version = ranz_control_v1_SchemaVersion_SCHEMA_VERSION_2;
		c->Message->body.hello.applied_generation = c->Status.Applied;
		ControlSetCaps(c, &c->Message->body.hello);
		ok = ControlWrite(c, s);
	}

	if (ok) {
		AcquireSRWLockExclusive(&c->Lock);
		c->Status.Connected = true;
		c->Status.Since = GetTickCount64();
		c->Status.NumStreams++;
		ReleaseSRWLockExclusive(&c->Lock);
	}
	bool opened = ok;

	// The leases of the DHCP responders go after the Hello, all of them, and then whenever they change (ControlDhcp.c)
	ControlLeasesResend(c->Config.Leases);
	// ... and so do the counters of the WireGuard Devices of a gateway (ControlDevice.c; SDN-80, #375)
	ControlDevicesResend(c->Config.Devices);
	// ... and the BGP peering of the node (ControlPeering.c; SDN-77, #357)
	ControlPeeringResend(c->Config.Peering);
	// ... and the Upgrades and the Fallbacks of the Paths of the peer agent (ControlPath.c; CORE-S5-6, #412)
	ControlPathsResend(c->Config.Paths);
	// ... and the counters of the EVPN of a gateway (ControlEvpn.c; SDN-25-R3, #571)
	ControlEvpnResend(c->Config.Evpn);

	while (ok && ControlHalted(c) == false) {
		ok = ControlWriteLeases(c->Config.Leases, s) && ControlWriteDevices(c->Config.Devices, s);
		// The events of the node that wait for the controller (ControlEvent.c; AUD1-DT-11, #459)
		ok = ok && ControlWriteEvents(c->Config.Events, s);
		// The BGP peering of the node when it changed (ControlPeering.c; SDN-77, #357)
		ok = ok && ControlWritePeeringReport(c->Config.Peering, s);
		// ... and the Signals of the node for its peers, as they come (ControlSignal.c; CORE-S5-5, #411)
		ok = ok && ControlWriteSignals(c->Config.Signals, s);
		// ... and the Upgrades and the Fallbacks of the Paths of its peer agent when they changed (ControlPath.c; CORE-S5-6, #412)
		ok = ok && ControlWritePaths(c->Config.Paths, s);
		// ... and the counters of the EVPN of a gateway when they changed (ControlEvpn.c; SDN-25-R3, #571)
		ok = ok && ControlWriteEvpn(c->Config.Evpn, s);
		if (ok == false)
			break;

		UINT r = ControlRead(c, s, CONTROL_MAX_FRAME, CONTROL_POLL);
		if (r == CONTROL_FRAME_END)
			break;
		if (r == CONTROL_FRAME_DONE) {
			ok = ControlTake(c, s);
			c->FrameSize = 0;
		}
	}

	AcquireSRWLockExclusive(&c->Lock);
	c->Status.Connected = false;
	// How it ended (SDN-90, #395): the handshake failed, or the stream was open and ended with a Refuse, or without one
	if (opened == false)
		c->Status.LastEnd = CONTROL_END_HANDSHAKE;
	else if (c->Message->which_body == ranz_control_v1_ControlMessage_refuse_tag)
		c->Status.LastEnd = CONTROL_END_REFUSED;
	else
		c->Status.LastEnd = CONTROL_END_CLOSED;
	ReleaseSRWLockExclusive(&c->Lock);

	TransportClose(s);
}

// After a stream ended or did not open: the delay before the next attempt, which grows while the attempts fail
// (ControlRetry.c), and the owner hears how it ended, unless the client halts (SDN-90, #395)
static UINT ControlRetry(CONTROL_CLIENT *c, UINT delay) {
	CONTROL_STATUS st;

	AcquireSRWLockExclusive(&c->Lock);
	c->Status.NextRetry = ControlRetryNext(delay, c->Status.LastEnd);
	CopyMemory(&st, &c->Status, sizeof(st));
	ReleaseSRWLockExclusive(&c->Lock);

	if (c->Config.EndProc != NULL && ControlHalted(c) == false)
		c->Config.EndProc(c->Config.EndParam, &st);

	return st.NextRetry;
}

static DWORD WINAPI ControlThread(LPVOID param) {
	CONTROL_CLIENT *c = (CONTROL_CLIENT *)param;
	UINT delay = 0;

	while (ControlHalted(c) == false) {
		ControlRun(c);
		delay = ControlRetry(c, delay);
		WaitForSingleObject(c->Halt, delay);
	}

	return 0;
}

//
// The client
//

// A client of cfg whose thread does not run: NULL when the configuration is not complete. ControlStart starts its
// thread; one that no thread runs takes the frames of a controller through ControlInput (fuzz_control).
CONTROL_CLIENT *ControlNew(const CONTROL_CONFIG *cfg) {
	if (cfg == NULL || cfg->Transport == NULL || cfg->Address[0] == 0 || (cfg->StaticKey == NULL) == (cfg->Identity == NULL))
		return NULL;

	CONTROL_CLIENT *c = ControlAlloc(sizeof(CONTROL_CLIENT));
	if (c == NULL)
		return NULL;

	CopyMemory(&c->Config, cfg, sizeof(CONTROL_CONFIG));
	c->Config.Address[TRANSPORT_ADDRESS_SIZE - 1] = 0;
	if (cfg->StaticKey != NULL) {
		CopyMemory(c->Key, cfg->StaticKey, NOISE_KEY_SIZE);
		c->Config.StaticKey = c->Key;
	}
	InitializeSRWLock(&c->Lock);

	c->Message = ControlAlloc(sizeof(ranz_control_v1_ControlMessage));
	c->Frame = ControlAlloc(CONTROL_FRAME_HEADER + CONTROL_MAX_FRAME);
	c->Out = ControlAlloc(CONTROL_OUT_SIZE);
	c->Halt = CreateEventW(NULL, TRUE, FALSE, NULL);
	if (c->Message == NULL || c->Frame == NULL || c->Out == NULL || c->Halt == NULL) {
		ControlFree(c);
		return NULL;
	}

	return c;
}

CONTROL_CLIENT *ControlStart(const CONTROL_CONFIG *cfg) {
	CONTROL_CLIENT *c = ControlNew(cfg);
	if (c == NULL)
		return NULL;

	c->Thread = CreateThread(NULL, 0, ControlThread, c, 0, NULL);
	if (c->Thread == NULL) {
		ControlFree(c);
		return NULL;
	}

	return c;
}

void ControlStop(CONTROL_CLIENT *c) {
	if (c == NULL)
		return;

	SetEvent(c->Halt);
	WaitForSingleObject(c->Thread, INFINITE);
	CloseHandle(c->Thread);
	ControlFree(c);
}

void ControlGetStatus(CONTROL_CLIENT *c, CONTROL_STATUS *st) {
	if (st == NULL)
		return;

	ZeroMemory(st, sizeof(CONTROL_STATUS));
	if (c == NULL)
		return;

	AcquireSRWLockShared(&c->Lock);
	CopyMemory(st, &c->Status, sizeof(CONTROL_STATUS));
	ReleaseSRWLockShared(&c->Lock);
}
