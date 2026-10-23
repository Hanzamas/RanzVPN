// NodeMirror.c
// The Mirrors of a node (SDN-23, #199; ADR-0029 decision 9). A Mirror copies the IP packets of the overlay that match
// it to a sensor, such as Zeek or Suricata, in VXLAN (RFC 7348), through the VXLAN module of the new core (Core/Vxlan.h;
// SDN-62, #289) on a UDP socket of its own, which the node opens with the first Generation that has a Mirror. The
// controller gives a node the Mirrors whose source selects it; on the node a Mirror takes a packet of its VRF, of its
// IP protocol, and with its port as the source or the destination port of TCP or UDP, each of them when the Mirror
// names one. Both ways are copied: a packet of the host that the overlay sent to a peer (NodeOverlayInput) and a
// packet of a peer that it delivered to the host (NodeOverlayDeliver).
//
// A copy is the IP packet behind an Ethernet header, since VXLAN carries Ethernet frames: from 02:52:5a:00:00:01, the
// host, to 02:52:5a:00:00:02, the overlay, for a packet of the host, and the other way for a packet of a peer, with
// the EtherType of IPv4 or IPv6. It goes on the VNI of the Mirror, or on the VRF id of the packet when the Mirror names
// none, so that the sensor tells apart the VRFs that use the same range. A packet whose copy does not fit in a VXLAN
// frame is not copied, and counted.
//
// The rate limit of a Mirror is a token bucket of NODE_MIRROR_BURST ms of its rate, and NODE_MIRROR_MIN_BURST bytes at
// least, kept as the generic cell rate algorithm (GCRA): one theoretical arrival time per Mirror on the performance
// counter, which the threads of the data path move on with a compare-exchange, without a lock. Over any span of time a
// Mirror sends its sensor at most its burst and its rate times the span, counted in the bytes of the VXLAN datagrams;
// a copy beyond that is dropped, and counted.
//
// The Mirrors of a Generation are built from its desired state into the forwarding tables of the VRFs of that
// Generation, and go in and out with them (NodeSwapVrfs, NodeFreeVrfTables), so the data path reads them as it reads
// the tables, without a lock. Each Generation starts the buckets of its Mirrors full.

#include "Node.h"

#include "Mayaqua/Memory.h"
#include "Mayaqua/Network.h"
#include "Mayaqua/TcpIp.h"

#include "Core/Control.h"

#include "NodeInternal.h"

#define NODE_MIRROR_MAX_HEADERS 8 // IPv6 extension headers that the classification of a packet passes at most

// The MAC addresses of the Ethernet header of a copy, locally administered: the host's and the overlay's
static const UCHAR node_mirror_host_mac[6] = {0x02, 0x52, 0x5A, 0x00, 0x00, 0x01};
static const UCHAR node_mirror_overlay_mac[6] = {0x02, 0x52, 0x5A, 0x00, 0x00, 0x02};

// The VXLAN module that sends the copies of the Mirrors of a node, and what became of the copies
struct NODE_MIRROR {
	VXLAN_UDP *Udp;          // The UDP socket of the module, NULL when the caller gave the send procedure
	VXLAN *Vxlan;            // The module
	volatile LONG64 Copied;  // Copies that went to a sensor
	volatile LONG64 Limited; // Copies that the rate limit of their Mirror dropped
	volatile LONG64 Failed;  // Copies that could not go
};

// One Mirror of a Generation
typedef struct NODE_MIRROR_RULE {
	UINT VrfId;          // The VRF of the packets, 0 for every VRF
	UINT Protocol;       // Their IP protocol, 0 for any
	UINT Port;           // Their source or destination port, 0 for any
	VXLAN_ADDR Sensor;   // The sensor
	UINT Vni;            // The VNI of the copies, 0 for the VRF id of each packet
	UINT64 Rate;         // The rate limit in bytes per second, 0 for none
	UINT64 Tolerance;    // The burst of the bucket: how far ahead of now the theoretical arrival time may run (ticks)
	volatile LONG64 Tat; // The theoretical arrival time of the bucket on the performance counter, 0 for a full bucket
} NODE_MIRROR_RULE;

// The Mirrors of one Generation, which go in with its forwarding tables
struct NODE_MIRROR_TABLE {
	NODE_MIRROR *Mirror;     // The VXLAN module that sends their copies
	UINT64 Frequency;        // The frequency of the performance counter
	UINT NumRules;           // The Mirrors ...
	NODE_MIRROR_RULE *Rules; // ... in the order of the desired state
};

// What the classification of a packet found
typedef struct NODE_MIRROR_FLOW {
	USHORT EtherType; // MAC_PROTO_IPV4 or MAC_PROTO_IPV6
	UINT Protocol;    // The IP protocol; for IPv6 the last header that the classification reached
	bool HasPorts;    // The packet holds the ports of TCP or UDP: it is no fragment after the first, and not cut short
	UINT SrcPort;     // The source port
	UINT DstPort;     // The destination port
} NODE_MIRROR_FLOW;

// The IP protocol and the ports of the IPv4 or IPv6 packet of size bytes; false for anything else. The extension
// headers of IPv6 are passed as far as the packet holds them: the protocol of a packet cut short in its headers is the
// last header that it names, and it has no ports.
static bool NodeMirrorClassify(const UCHAR *packet, UINT size, NODE_MIRROR_FLOW *f) {
	UINT offset = 0;
	bool first = true; // The packet is no fragment, or the first fragment of a datagram

	Zero(f, sizeof(NODE_MIRROR_FLOW));
	if (packet == NULL || size < 20)
		return false;

	switch (packet[0] >> 4) {
	case 4:
		offset = (packet[0] & 0x0F) * 4;
		if (offset < 20 || offset > size)
			return false;

		f->EtherType = MAC_PROTO_IPV4;
		f->Protocol = packet[9];
		first = (((((UINT)packet[6] & 0x1F) << 8) | packet[7]) == 0);
		break;
	case 6:
		if (size < 40)
			return false;

		f->EtherType = MAC_PROTO_IPV6;
		f->Protocol = packet[6];
		offset = 40;

		for (UINT i = 0; i < NODE_MIRROR_MAX_HEADERS; i++) {
			UINT length;

			if (f->Protocol != IPV6_HEADER_HOP && f->Protocol != IPV6_HEADER_ROUTING && f->Protocol != IPV6_HEADER_ENDPOINT && f->Protocol != IPV6_HEADER_FRAGMENT)
				break;

			// Every extension header has at least 8 bytes: the next header, then its length in units of 8 bytes past
			// the first 8, but a fragment header, which is 8 bytes and holds the offset of the fragment
			if (size - offset < 8)
				return true;

			if (f->Protocol == IPV6_HEADER_FRAGMENT) {
				length = 8;
				first = first && ((((UINT)packet[offset + 2] << 8) | packet[offset + 3]) & 0xFFF8) == 0;
			} else {
				length = ((UINT)packet[offset + 1] + 1) * 8;
			}

			if (length > size - offset)
				return true;

			f->Protocol = packet[offset];
			offset += length;
		}
		break;
	default:
		return false;
	}

	// The ports of TCP and UDP lead their header, in the first fragment of a datagram
	if (first && (f->Protocol == IP_PROTO_TCP || f->Protocol == IP_PROTO_UDP) && size - offset >= 4) {
		f->HasPorts = true;
		f->SrcPort = READ_USHORT(packet + offset);
		f->DstPort = READ_USHORT(packet + offset + 2);
	}

	return true;
}

// Whether the Mirror r takes a packet of the VRF vrf_id that the classification found to be f. A Mirror of ICMP
// takes ICMPv6 in an IPv6 packet.
static bool NodeMirrorMatch(const NODE_MIRROR_RULE *r, UINT vrf_id, const NODE_MIRROR_FLOW *f) {
	if (r->VrfId != 0 && r->VrfId != vrf_id)
		return false;

	if (r->Protocol != 0 && r->Protocol != f->Protocol && (r->Protocol != IP_PROTO_ICMPV4 || f->EtherType != MAC_PROTO_IPV6 || f->Protocol != IP_PROTO_ICMPV6))
		return false;

	return (r->Port == 0 || (f->HasPorts && (f->SrcPort == r->Port || f->DstPort == r->Port)));
}

// Whether the bucket of the Mirror r of the table t holds size bytes now, which it takes when it does. The bucket is
// the theoretical arrival time of GCRA: each datagram moves it on by the time that its bytes take at the rate, and a
// datagram that would move it more than the burst ahead of now does not go.
static bool NodeMirrorTake(NODE_MIRROR_TABLE *t, NODE_MIRROR_RULE *r, UINT size) {
	LARGE_INTEGER now;

	if (r->Rate == 0)
		return true;

	QueryPerformanceCounter(&now);

	// The time that size bytes take at the rate, rounded up, so that the copies never run above it
	UINT64 cost = ((UINT64)size * t->Frequency + r->Rate - 1) / r->Rate;

	while (true) {
		LONG64 old = ReadAcquire64(&r->Tat);
		UINT64 tat = MAX((UINT64)old, (UINT64)now.QuadPart);

		if (tat + cost - (UINT64)now.QuadPart > r->Tolerance)
			return false;

		if (InterlockedCompareExchange64(&r->Tat, (LONG64)(tat + cost), old) == old)
			return true;
	}
}

// The VXLAN module that sends the copies of Mirrors: on a UDP socket of its own, on a port that the system picks, when
// send is NULL; else through send, with send_param. NULL when the socket cannot be opened.
NODE_MIRROR *NodeNewMirror(VXLAN_SEND_PROC *send, void *send_param) {
	NODE_MIRROR *m = ZeroMalloc(sizeof(NODE_MIRROR));

	if (send == NULL) {
		m->Udp = VxlanUdpNew(0);
		if (m->Udp == NULL) {
			Free(m);
			return NULL;
		}

		send = VxlanUdpSend;
		send_param = m->Udp;
	}

	m->Vxlan = VxlanNew(send, send_param, NULL, NULL);
	if (m->Vxlan == NULL) {
		NodeFreeMirror(m);
		return NULL;
	}

	return m;
}

// Free the VXLAN module of Mirrors, which no table of Mirrors may hold any more
void NodeFreeMirror(NODE_MIRROR *m) {
	if (m == NULL)
		return;

	VxlanUdpFree(m->Udp);
	VxlanFree(m->Vxlan);
	Free(m);
}

// The Mirrors of the desired state st, whose copies m sends; NULL when st has none. A Mirror whose sensor is neither
// an IPv4 nor an IPv6 address is left out.
NODE_MIRROR_TABLE *NodeNewMirrorTable(NODE_MIRROR *m, const CONTROL_STATE *st) {
	LARGE_INTEGER frequency;

	if (m == NULL || st == NULL || st->NumMirrors == 0)
		return NULL;

	QueryPerformanceFrequency(&frequency);

	UINT num = MIN(st->NumMirrors, CONTROL_MAX_MIRRORS);
	NODE_MIRROR_TABLE *t = ZeroMalloc(sizeof(NODE_MIRROR_TABLE));
	t->Mirror = m;
	t->Frequency = (UINT64)frequency.QuadPart;
	t->Rules = ZeroMalloc(sizeof(NODE_MIRROR_RULE) * num);

	for (UINT i = 0; i < num; i++) {
		const CONTROL_MIRROR *c = &st->Mirrors[i];
		NODE_MIRROR_RULE *r = &t->Rules[t->NumRules];

		if (c->SensorSize == 4) {
			VxlanAddrSetV4(&r->Sensor, c->Sensor[0], c->Sensor[1], c->Sensor[2], c->Sensor[3], (USHORT)c->SensorPort);
		} else if (c->SensorSize == 16) {
			Copy(r->Sensor.Ip, c->Sensor, sizeof(r->Sensor.Ip));
			r->Sensor.Port = (USHORT)c->SensorPort;
		} else {
			continue;
		}

		r->VrfId = c->VrfId;
		r->Protocol = c->Protocol;
		r->Port = c->Port;
		r->Vni = c->Vni;

		// The rate in bytes per second, at least one; the burst in ticks of the performance counter
		r->Rate = (c->RateLimit != 0 ? MAX(c->RateLimit / 8, 1) : 0);
		if (r->Rate != 0)
			r->Tolerance = MAX(t->Frequency * NODE_MIRROR_BURST / 1000, ((UINT64)NODE_MIRROR_MIN_BURST * t->Frequency + r->Rate - 1) / r->Rate);

		t->NumRules++;
	}

	return t;
}

// Free the Mirrors of a Generation, wiped first as NodeFreeTable does; the VXLAN module that they send through stays
void NodeFreeMirrorTable(NODE_MIRROR_TABLE *t) {
	if (t == NULL)
		return;

	Zero(t->Rules, sizeof(NODE_MIRROR_RULE) * t->NumRules);
	Free(t->Rules);
	Zero(t, sizeof(NODE_MIRROR_TABLE));
	Free(t);
}

// Copy the IP packet of size bytes in the VRF vrf_id to the sensor of each Mirror of the tables v that takes it: a
// packet that the host sent into the overlay (from_host), or that a peer sent to the host. The copies of the packet
// share one frame. The caller reads v as a reader of the table snapshot of the node.
void NodeMirrorCopy(NODE_VRF_TABLES *v, UINT vrf_id, const UCHAR *packet, UINT size, bool from_host) {
	NODE_MIRROR_TABLE *t = (v != NULL ? v->Mirror : NULL);
	NODE_MIRROR_FLOW f;
	UCHAR frame[VXLAN_MAX_FRAME];
	bool built = false;

	if (t == NULL || t->NumRules == 0 || NodeMirrorClassify(packet, size, &f) == false)
		return;

	for (UINT i = 0; i < t->NumRules; i++) {
		NODE_MIRROR_RULE *r = &t->Rules[i];
		UINT vni = (r->Vni != 0 ? r->Vni : vrf_id);

		if (NodeMirrorMatch(r, vrf_id, &f) == false)
			continue;

		if (size > VXLAN_MAX_FRAME - NODE_MIRROR_ETHER || vni > VXLAN_MAX_VNI) {
			InterlockedIncrement64(&t->Mirror->Failed);
			continue;
		}

		if (NodeMirrorTake(t, r, VXLAN_HEADER_SIZE + NODE_MIRROR_ETHER + size) == false) {
			InterlockedIncrement64(&t->Mirror->Limited);
			continue;
		}

		if (built == false) {
			Copy(frame, from_host ? node_mirror_overlay_mac : node_mirror_host_mac, 6);
			Copy(frame + 6, from_host ? node_mirror_host_mac : node_mirror_overlay_mac, 6);
			WRITE_USHORT(frame + 12, f.EtherType);
			Copy(frame + NODE_MIRROR_ETHER, packet, size);
			built = true;
		}

		bool sent = VxlanSendTo(t->Mirror->Vxlan, vni, &r->Sensor, frame, NODE_MIRROR_ETHER + size);
		InterlockedIncrement64(sent ? &t->Mirror->Copied : &t->Mirror->Failed);
	}
}

// Build the Mirrors of the desired state st into the forwarding tables v of its Generation, with which they go in
// (NodeOverlay.c). The VXLAN module of the node opens with the first Generation that has a Mirror; while it cannot,
// the Mirrors copy nothing, and the next Generation tries again.
void NodeMirrorAttach(NODE *n, NODE_VRF_TABLES *v, const CONTROL_STATE *st) {
	if (n == NULL || v == NULL || st == NULL || st->NumMirrors == 0)
		return;

	NODE_MIRROR *m = ReadPointerAcquire((PVOID const volatile *)&n->Mirror);
	if (m == NULL) {
		NODE_MIRROR *fresh = NodeNewMirror(NULL, NULL);

		if (fresh == NULL) {
			NodeLog(n, "Mirror: the UDP socket of the VXLAN module could not be opened, so the %u Mirrors of generation %I64u copy nothing", st->NumMirrors, st->Generation);
			return;
		}

		// Of two states that are applied at once, one opens the module
		m = InterlockedCompareExchangePointer((PVOID volatile *)&n->Mirror, fresh, NULL);
		if (m == NULL) {
			m = fresh;
			NodeLog(n, "Mirror: the VXLAN module of the Mirrors sends from UDP port %u", (UINT)VxlanUdpPort(m->Udp));
		} else {
			NodeFreeMirror(fresh);
		}
	}

	v->Mirror = NodeNewMirrorTable(m, st);
}

// Free the VXLAN module of the Mirrors of a node, once no table holds a Mirror any more: the overlay stops, and its
// tables went before (NodeOverlayStop)
void NodeMirrorStop(NODE *n) {
	if (n == NULL)
		return;

	NodeFreeMirror(InterlockedExchangePointer((PVOID volatile *)&n->Mirror, NULL));
}

// The copies of the Mirrors of a node since the first Generation of its overlay that had a Mirror; all 0 before
void NodeMirrorGetStatus(NODE *n, NODE_MIRROR_STATUS *st) {
	if (st == NULL)
		return;

	Zero(st, sizeof(NODE_MIRROR_STATUS));
	NODE_MIRROR *m = (n != NULL ? ReadPointerAcquire((PVOID const volatile *)&n->Mirror) : NULL);
	if (m == NULL)
		return;

	st->Copied = (UINT64)ReadAcquire64(&m->Copied);
	st->Limited = (UINT64)ReadAcquire64(&m->Limited);
	st->Failed = (UINT64)ReadAcquire64(&m->Failed);
}
