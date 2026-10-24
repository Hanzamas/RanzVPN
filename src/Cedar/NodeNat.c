// NodeNat.c
// 1:1 NAT and 4via6 in the data plane of a node (SDN-6, #182; ADR-0025 decisions 4 and 5). A 1:1 NAT rule of a VRF
// (CONTROL_NAT, from the NodeConfig of the desired state) says that the host of the node sees the addresses of its
// inside prefix and the VRF the addresses of its outside prefix, one for one, the host bits kept. A packet of the host
// into the overlay (NodeNatEnds, NodeNatCopy) has every address of an inside prefix written as the one of the outside
// prefix, and a packet of a peer to the host (NodeNatInbound) every address of an outside prefix as the one of the
// inside prefix: its source and its destination, and those of the packet that an ICMP error quotes, with the
// checksums that cover them. A rule whose two prefixes are of one family rewrites the addresses. The 4via6 of a VRF
// is a rule from an IPv6 /96 at the start of the 4via6 /64 of the ULA of the VRF to the IPv4 0.0.0.0/0, which the
// controller gives a node in two VRFs whose IPv4 ranges overlap: it translates the packet from IPv6 to IPv4 and back
// (RFC 7915, the parts that a host needs), the IPv4 address of the VRF in the last 32 bits of the IPv6 address of the
// host, so 10.0.0.5 in one VRF and 10.0.0.5 in another are two addresses on the host. On the way into the overlay the
// 4via6 goes first and the other rules after it; on the way to the host the other way round, so a 1:1 NAT rule of
// IPv4 and the 4via6 of one VRF work together.
//
// The forwarding tables of the VRFs are tables of the overlay: the overlay checks a packet of the host after the rules
// and a packet of a peer before them. The outside prefix of a rule of one family leads to the host in the tables of
// the node and to the node in the tables of its peers (Peer.routes of the desired state; NodeNatRoutes). The rules are
// built with the forwarding tables of their Generation and installed with them (NODE_VRF_TABLES.Nat), so the data
// path reads them without a lock.
//
// Not translated between the families, so dropped: a fragment of IPv4, an IPv6 packet with an extension header, and
// an ICMP message that has no counterpart in the other family (a redirect, a parameter problem but an unknown next
// header, neighbour discovery and the like). Its IPv4 options do not go with a packet into IPv6. A packet that no rule
// holds goes on as it is.

#include "Node.h"

#include "Mayaqua/Memory.h"

#include "Core/Control.h"

#define NODE_NAT_ICMP4       1     // The upper-layer protocols that a translation reads: ICMP ...
#define NODE_NAT_TCP         6     // ... TCP ...
#define NODE_NAT_UDP         17    // ... UDP ...
#define NODE_NAT_ICMP6       58    // ... and ICMPv6
#define NODE_NAT_HOP_BY_HOP  0     // The IPv6 extension headers that a rewrite steps over: hop-by-hop options ...
#define NODE_NAT_ROUTING     43    // ... routing ...
#define NODE_NAT_FRAGMENT    44    // ... fragment ...
#define NODE_NAT_DESTINATION 60    // ... and destination options
#define NODE_NAT_ICMP_HEADER 8     // The bytes of an ICMP message before the packet that an error quotes
#define NODE_NAT_MIN_MTU     1280  // The MTU of the Packet Too Big that a Fragmentation Needed without an MTU becomes
#define NODE_NAT_MAX_LENGTH  65535 // The largest IPv4 total length and IPv6 payload length

// What NodeNatPlan finds for a packet
#define NODE_NAT_ASIS 0 // No rule holds its source or its destination: it goes as it is
#define NODE_NAT_GO   1 // A rule holds one: it goes translated
#define NODE_NAT_DROP 2 // It is no IP packet, or a rule holds one of its addresses and it cannot be translated

// One 1:1 NAT rule of a VRF of the node
typedef struct NODE_NAT_RULE {
	UINT VrfId;         // The VRF
	bool Family;        // The prefixes are of two families: the 4via6 of the VRF, IPv6 inside and IPv4 outside
	UCHAR Inside[16];   // The prefix that the host sees, its host bits zero
	UINT InsideSize;    // ... 4 bytes for IPv4, 16 for IPv6
	UINT InsideLength;  // ... and its length
	UCHAR Outside[16];  // The prefix that the VRF sees, its host bits zero
	UINT OutsideSize;   // ... the number of its bytes
	UINT OutsideLength; // ... and its length
	UINT HostBits;      // The bits of an address that the rule keeps, as many in both prefixes
} NODE_NAT_RULE;

// The 1:1 NAT rules of the node for one Generation of its desired state (NodeNewNat)
struct NODE_NAT {
	UINT NumRules;        // Number of rules
	NODE_NAT_RULE *Rules; // The rules, in the order of the state
};

// One IP packet as a translation reads it: a whole one, or the start of one that an ICMP error quotes
typedef struct NODE_NAT_IP {
	const UCHAR *Data; // Its first byte
	UINT Size;         // Its bytes: what its header gives for a whole one, what the error holds of a quoted one
	UINT Version;      // 4 or 6
	UINT HeaderSize;   // The bytes before its upper layer: the IPv4 header, or the IPv6 header and its extension headers
	UINT Protocol;     // Its upper-layer protocol
	UINT Length;       // The bytes of its upper layer that its header gives
	bool Extended;     // A fragment of IPv4, or IPv6 with an extension header: it keeps its family
	bool Later;        // A fragment that is not the first: no upper-layer header
	UCHAR Src[16];     // Its source as the other side sees it, once NodeNatPlan mapped it
	UCHAR Dst[16];     // ... and its destination
	UINT AddrSize;     // ... 4 or 16 bytes each
} NODE_NAT_IP;

// What a translation of one packet does (NodeNatPlan)
typedef struct NODE_NAT_PLAN {
	NODE_NAT_IP Ip;    // The packet
	bool Quoted;       // It is an ICMP error, and the packet that it quotes goes translated: Inner
	NODE_NAT_IP Inner; // The packet that the error quotes
	bool Icmp;         // It is an ICMP message that goes to the other family as Type, Code and Rest
	UCHAR Type;        // The type of the message in the other family ...
	UCHAR Code;        // ... its code ...
	UINT Rest;         // ... and the 4 bytes after its checksum
	UINT Size;         // The size of the translated packet
} NODE_NAT_PLAN;

//
// Checksums
//

// The sum of the bytes at data as big-endian 16-bit words, added to sum; an odd last byte is the high half of a word
static UINT NodeNatSum(UINT sum, const UCHAR *data, UINT size) {
	for (UINT i = 0; i + 1 < size; i += 2)
		sum += ((UINT)data[i] << 8) | data[i + 1];

	if (size % 2 != 0)
		sum += (UINT)data[size - 1] << 8;

	return sum;
}

// A sum folded into 16 bits, the carries added back (RFC 1071)
static USHORT NodeNatFold(UINT sum) {
	while ((sum >> 16) != 0)
		sum = (sum & 0xFFFF) + (sum >> 16);

	return (USHORT)sum;
}

// Write the checksum of the bytes whose sum is sum at field, which they hold as zero
static void NodeNatChecksum(UCHAR *field, UINT sum) {
	WRITE_USHORT(field, ~NodeNatFold(sum));
}

// Change the checksum at field for bytes that it covers whose sum went from old_sum to new_sum (RFC 1624, eqn. 3)
static void NodeNatAdjust(UCHAR *field, UINT old_sum, UINT new_sum) {
	UINT sum = (UINT)(USHORT)~READ_USHORT(field) + (USHORT)~NodeNatFold(old_sum) + NodeNatFold(new_sum);

	WRITE_USHORT(field, ~NodeNatFold(sum));
}

// The sum of the pseudo-header of IPv6 (RFC 8200 section 8.1) for the addresses src and dst, an upper layer of length
// bytes and the protocol
static UINT NodeNatPseudo6(const UCHAR *src, const UCHAR *dst, UINT length, UINT protocol) {
	return NodeNatSum(NodeNatSum(0, src, 16), dst, 16) + (length >> 16) + (length & 0xFFFF) + protocol;
}

// Write the checksum of the ICMP message at icmp, of size bytes, in a packet of the version whose addresses are src
// and dst: over the message, and in ICMPv6 over the pseudo-header too (RFC 4443 section 2.3)
static void NodeNatIcmpSum(UCHAR *icmp, UINT size, UINT version, const UCHAR *src, const UCHAR *dst) {
	UINT sum = (version == 6 ? NodeNatPseudo6(src, dst, size, NODE_NAT_ICMP6) : 0);

	WRITE_USHORT(icmp + 2, 0);
	NodeNatChecksum(icmp + 2, NodeNatSum(sum, icmp, size));
}

// Adjust the TCP or UDP checksum of the upper layer at l4, room bytes of it there, of a packet of the version for
// addresses whose sum went from old_sum to new_sum. A UDP datagram without a checksum keeps none, unless it is whole
// (all of it there) in IPv6, which has no UDP without one: it gets one over src and dst.
static void NodeNatTransport(UCHAR *l4, UINT room, UINT protocol, UINT version, bool whole, const UCHAR *src, const UCHAR *dst, UINT old_sum, UINT new_sum) {
	if (protocol == NODE_NAT_TCP && room >= 18)
		NodeNatAdjust(l4 + 16, old_sum, new_sum);

	if (protocol != NODE_NAT_UDP || room < 8)
		return;

	if (READ_USHORT(l4 + 6) != 0)
		NodeNatAdjust(l4 + 6, old_sum, new_sum);
	else if (version == 6 && whole)
		NodeNatChecksum(l4 + 6, NodeNatSum(NodeNatPseudo6(src, dst, room, NODE_NAT_UDP), l4, room));
	else
		return;

	// A UDP checksum of 0 is none: one that comes to 0 goes as 0xFFFF (RFC 768)
	if (READ_USHORT(l4 + 6) == 0)
		WRITE_USHORT(l4 + 6, 0xFFFF);
}

//
// Addresses and rules
//

// The source of the packet ip as it is, ...
static const UCHAR *NodeNatSrc(const NODE_NAT_IP *ip) {
	return ip->Data + (ip->Version == 4 ? 12 : 8);
}

// ... its destination, ...
static const UCHAR *NodeNatDst(const NODE_NAT_IP *ip) {
	return ip->Data + (ip->Version == 4 ? 16 : 24);
}

// ... and their size
static UINT NodeNatAddrSize(const NODE_NAT_IP *ip) {
	return (ip->Version == 4 ? 4 : 16);
}

// Copy the prefix of size bytes and length bits at prefix to dst (16 bytes), its host bits cleared
static void NodeNatMask(UCHAR *dst, const UCHAR *prefix, UINT size, UINT length) {
	Zero(dst, 16);

	for (UINT i = 0; i < size; i++) {
		UINT bits = (length > i * 8 ? length - i * 8 : 0);

		dst[i] = (bits >= 8 ? prefix[i] : (UCHAR)(prefix[i] & (0xFF00 >> bits)));
	}
}

// The rule of a CONTROL_NAT c of the state: false for one whose prefixes are not IPv4 or IPv6, not of as many host
// bits, or of two families but for IPv6 inside and IPv4 outside (the 4via6, by which a packet of the host never grows)
static bool NodeNatRule(NODE_NAT_RULE *r, const CONTROL_NAT *c) {
	if ((c->InsideSize != 4 && c->InsideSize != 16) || (c->OutsideSize != 4 && c->OutsideSize != 16) || c->InsideLength > c->InsideSize * 8 || c->OutsideLength > c->OutsideSize * 8)
		return false;

	UINT host_bits = c->InsideSize * 8 - c->InsideLength;
	if (host_bits != c->OutsideSize * 8 - c->OutsideLength || (c->InsideSize != c->OutsideSize && c->InsideSize != 16))
		return false;

	Zero(r, sizeof(NODE_NAT_RULE));
	r->VrfId = c->VrfId;
	r->Family = (c->InsideSize != c->OutsideSize);
	NodeNatMask(r->Inside, c->Inside, c->InsideSize, c->InsideLength);
	r->InsideSize = c->InsideSize;
	r->InsideLength = c->InsideLength;
	NodeNatMask(r->Outside, c->Outside, c->OutsideSize, c->OutsideLength);
	r->OutsideSize = c->OutsideSize;
	r->OutsideLength = c->OutsideLength;
	r->HostBits = host_bits;

	return true;
}

// Whether the address addr lies in the prefix of length bits at prefix, of as many bytes
static bool NodeNatHolds(const UCHAR *prefix, UINT length, const UCHAR *addr) {
	UINT bytes = length / 8, bits = length % 8;

	if (Cmp(prefix, addr, bytes) != 0)
		return false;

	return (bits == 0 || ((prefix[bytes] ^ addr[bytes]) & (UCHAR)(0xFF00 >> bits)) == 0);
}

// The address addr (size bytes) of a packet of the VRF vrf_id through the rules of one stage, the 4via6 (family) or the
// others: out (into the overlay) from an inside prefix to the outside one, else the other way, into to and its size.
// False when no rule of the stage holds it.
static bool NodeNatMapStage(const NODE_NAT *nat, UINT vrf_id, bool family, bool out, const UCHAR *addr, UINT size, UCHAR *to, UINT *to_size) {
	for (UINT i = 0; nat != NULL && i < nat->NumRules; i++) {
		const NODE_NAT_RULE *r = &nat->Rules[i];
		const UCHAR *from = (out ? r->Inside : r->Outside);
		UINT from_size = (out ? r->InsideSize : r->OutsideSize);
		UINT from_length = (out ? r->InsideLength : r->OutsideLength);

		if (r->VrfId != vrf_id || r->Family != family || from_size != size || NodeNatHolds(from, from_length, addr) == false)
			continue;

		// The prefix of the other side, with the host bits of addr
		UINT bytes = r->HostBits / 8, bits = r->HostBits % 8;
		*to_size = (out ? r->OutsideSize : r->InsideSize);
		Copy(to, (out ? r->Outside : r->Inside), *to_size);
		for (UINT j = 0; j < bytes; j++)
			to[*to_size - 1 - j] = addr[size - 1 - j];
		if (bits != 0)
			to[*to_size - 1 - bytes] |= (UCHAR)(addr[size - 1 - bytes] & ((1 << bits) - 1));

		return true;
	}

	return false;
}

// The address addr (size bytes) of a packet of the VRF vrf_id as the other side sees it, into to and its size: out,
// through the 4via6 of the VRF and then its other rules, in, the other way round. False when no rule holds it; to then
// holds addr itself.
static bool NodeNatMap(const NODE_NAT *nat, UINT vrf_id, bool out, const UCHAR *addr, UINT size, UCHAR *to, UINT *to_size) {
	UCHAR mid[16];
	UINT mid_size = size;

	bool first = NodeNatMapStage(nat, vrf_id, out, out, addr, size, mid, &mid_size);
	if (first == false)
		Copy(mid, addr, size);

	bool second = NodeNatMapStage(nat, vrf_id, out == false, out, mid, mid_size, to, to_size);
	if (second == false) {
		Copy(to, mid, mid_size);
		*to_size = mid_size;
	}

	return (first || second);
}

//
// Packets
//

// The source and the destination of an IP packet as NodeOverlayEnds reads them, and their size: false for anything but
// IPv4 or IPv6
static bool NodeNatEndsOf(const UCHAR *packet, UINT size, UCHAR *src, UCHAR *dst, UINT *addr_size) {
	if (packet == NULL || size < 20)
		return false;

	switch (packet[0] >> 4) {
	case 4:
		if ((packet[0] & 0x0F) < 5)
			return false;

		*addr_size = 4;
		Copy(src, packet + 12, 4);
		Copy(dst, packet + 16, 4);
		return true;
	case 6:
		if (size < 40)
			return false;

		*addr_size = 16;
		Copy(src, packet + 8, 16);
		Copy(dst, packet + 24, 16);
		return true;
	default:
		return false;
	}
}

// Read the IP packet at data, of size bytes: a whole one, whose header gives its size, or one that an ICMP error quotes,
// of which only the start may be there. False for anything but IPv4 or IPv6, or a header that the bytes do not hold.
static bool NodeNatParse(NODE_NAT_IP *ip, const UCHAR *data, UINT size, bool whole) {
	Zero(ip, sizeof(NODE_NAT_IP));
	ip->Data = data;

	if (data == NULL || size < 20)
		return false;

	if ((data[0] >> 4) == 4) {
		UINT ihl = (data[0] & 0x0F) * 4, total = READ_USHORT(data + 2), frag = READ_USHORT(data + 6);

		if (ihl < 20 || ihl > size || total < ihl || (whole && total > size))
			return false;

		ip->Version = 4;
		ip->Size = MIN(total, size);
		ip->HeaderSize = ihl;
		ip->Protocol = data[9];
		ip->Length = total - ihl;
		ip->Extended = ((frag & 0x3FFF) != 0);
		ip->Later = ((frag & 0x1FFF) != 0);
		return true;
	}

	if ((data[0] >> 4) != 6 || size < 40)
		return false;

	UINT end = 40 + READ_USHORT(data + 4), next = data[6], at = 40;
	if (whole && end > size)
		return false;

	ip->Version = 6;
	ip->Size = MIN(end, size);

	// The extension headers that a rewrite steps over to the upper layer; what follows a later fragment is data
	while ((next == NODE_NAT_HOP_BY_HOP || next == NODE_NAT_ROUTING || next == NODE_NAT_DESTINATION || next == NODE_NAT_FRAGMENT) && ip->Later == false) {
		if (at + 8 > ip->Size)
			return false;

		UINT length = (next == NODE_NAT_FRAGMENT ? 8 : ((UINT)data[at + 1] + 1) * 8);
		ip->Extended = true;
		if (next == NODE_NAT_FRAGMENT)
			ip->Later = ((READ_USHORT(data + at + 2) & 0xFFF8) != 0);
		next = data[at];
		at += length;
	}

	if (at > end)
		return false;

	ip->HeaderSize = at;
	ip->Protocol = next;
	ip->Length = end - at;
	return true;
}

// Whether an ICMP message of the version, of type, is an error that quotes a packet
static bool NodeNatIcmpError(UINT version, UINT type) {
	if (version == 4)
		return (type == 3 || type == 4 || type == 5 || type == 11 || type == 12);

	return (type >= 1 && type <= 4);
}

// The ICMPv6 message of the ICMP (IPv4) one at icmp (RFC 7915 section 4.2, the messages that a host needs): its type,
// code and the 4 bytes after its checksum; false for one that has none
static bool NodeNatIcmp4To6(const UCHAR *icmp, UCHAR *type, UCHAR *code, UINT *rest) {
	UINT c = icmp[1];

	*code = 0;
	*rest = 0;
	switch (icmp[0]) {
	case 8:
		// Echo Request
		*type = 128;
		*rest = READ_UINT(icmp + 4);
		return true;
	case 0:
		// Echo Reply
		*type = 129;
		*rest = READ_UINT(icmp + 4);
		return true;
	case 3:
		// Destination Unreachable: a Protocol Unreachable is a Parameter Problem at the next header, a Fragmentation
		// Needed a Packet Too Big with the MTU of IPv6
		*type = 1;
		if (c == 2) {
			*type = 4;
			*code = 1;
			*rest = 6;
		} else if (c == 3) {
			*code = 4;
		} else if (c == 4) {
			*type = 2;
			*rest = (READ_USHORT(icmp + 6) != 0 ? READ_USHORT(icmp + 6) + 20 : NODE_NAT_MIN_MTU);
		} else if (c == 9 || c == 10 || c == 13) {
			*code = 1;
		}
		return (c <= 13);
	case 11:
		// Time Exceeded
		*type = 3;
		*code = (UCHAR)c;
		return (c <= 1);
	default:
		return false;
	}
}

// The ICMP (IPv4) message of the ICMPv6 one at icmp (RFC 7915 section 5.2, the messages that a host needs): its type,
// code and the 4 bytes after its checksum; false for one that has none
static bool NodeNatIcmp6To4(const UCHAR *icmp, UCHAR *type, UCHAR *code, UINT *rest) {
	UINT c = icmp[1];

	*code = 0;
	*rest = 0;
	switch (icmp[0]) {
	case 128:
		// Echo Request
		*type = 8;
		*rest = READ_UINT(icmp + 4);
		return true;
	case 129:
		// Echo Reply
		*type = 0;
		*rest = READ_UINT(icmp + 4);
		return true;
	case 1:
		// Destination Unreachable: prohibited (1, 5, 6) is administratively prohibited, a port unreachable stays one,
		// the rest is a host unreachable
		*type = 3;
		*code = (c == 1 || c == 5 || c == 6 ? 10 : (c == 4 ? 3 : 1));
		return (c <= 6);
	case 2:
		// Packet Too Big: a Fragmentation Needed with the MTU of IPv4
		*type = 3;
		*code = 4;
		*rest = MIN(READ_UINT(icmp + 4) > 20 ? READ_UINT(icmp + 4) - 20 : 0, 0xFFFF);
		return true;
	case 3:
		// Time Exceeded
		*type = 11;
		*code = (UCHAR)c;
		return (c <= 1);
	case 4:
		// Parameter Problem: only an unknown next header, a Protocol Unreachable
		*type = 3;
		*code = 2;
		return (c == 1);
	default:
		return false;
	}
}

// Plan the translation of the packet of size bytes of the VRF vrf_id through the rules of nat, out (from the host into
// the overlay) or in: NODE_NAT_ASIS, with its addresses, when no rule holds its source or its destination; NODE_NAT_GO
// with the plan; NODE_NAT_DROP for a packet that is no IP packet, or that a rule holds and that cannot be translated
static UINT NodeNatPlan(const NODE_NAT *nat, UINT vrf_id, bool out, const UCHAR *packet, UINT size, NODE_NAT_PLAN *p) {
	NODE_NAT_IP *ip = &p->Ip;
	UCHAR from_src[16], from_dst[16], src[16], dst[16];
	UINT from_size = 0, src_size = 0, dst_size = 0;

	Zero(p, sizeof(NODE_NAT_PLAN));
	if (NodeNatEndsOf(packet, size, from_src, from_dst, &from_size) == false)
		return NODE_NAT_DROP;

	bool mapped = NodeNatMap(nat, vrf_id, out, from_src, from_size, src, &src_size);
	mapped = NodeNatMap(nat, vrf_id, out, from_dst, from_size, dst, &dst_size) || mapped;
	if (mapped == false) {
		Copy(ip->Src, from_src, from_size);
		Copy(ip->Dst, from_dst, from_size);
		ip->AddrSize = from_size;
		return NODE_NAT_ASIS;
	}

	// A packet that the rules take to another family must go there whole: both its addresses, no fragment
	if (src_size != dst_size || NodeNatParse(ip, packet, size, true) == false)
		return NODE_NAT_DROP;

	Copy(ip->Src, src, src_size);
	Copy(ip->Dst, dst, dst_size);
	ip->AddrSize = src_size;

	bool family = (ip->AddrSize != NodeNatAddrSize(ip));
	if (family && ip->Extended)
		return NODE_NAT_DROP;

	// An ICMP error quotes a packet that went the other way: its addresses map the same way as those of the error
	UINT icmp_protocol = (ip->Version == 4 ? NODE_NAT_ICMP4 : NODE_NAT_ICMP6);
	bool icmp = (ip->Protocol == icmp_protocol && ip->Later == false && ip->HeaderSize + NODE_NAT_ICMP_HEADER <= ip->Size);
	if (icmp && NodeNatIcmpError(ip->Version, packet[ip->HeaderSize])) {
		NODE_NAT_IP *q = &p->Inner;
		UINT q_src = 0, q_dst = 0;

		if (NodeNatParse(q, packet + ip->HeaderSize + NODE_NAT_ICMP_HEADER, ip->Size - ip->HeaderSize - NODE_NAT_ICMP_HEADER, false) && q->Version == ip->Version) {
			NodeNatMap(nat, vrf_id, out, NodeNatSrc(q), NodeNatAddrSize(q), q->Src, &q_src);
			NodeNatMap(nat, vrf_id, out, NodeNatDst(q), NodeNatAddrSize(q), q->Dst, &q_dst);
			q->AddrSize = q_src;
			p->Quoted = (q_src == q_dst && q_src == ip->AddrSize && (family == false || q->Extended == false));
		}

		if (family && p->Quoted == false)
			return NODE_NAT_DROP;
	}

	if (family && ip->Protocol == icmp_protocol) {
		if (icmp == false)
			return NODE_NAT_DROP;

		const UCHAR *message = packet + ip->HeaderSize;
		if ((ip->Version == 4 ? NodeNatIcmp4To6(message, &p->Type, &p->Code, &p->Rest) : NodeNatIcmp6To4(message, &p->Type, &p->Code, &p->Rest)) == false)
			return NODE_NAT_DROP;

		p->Icmp = true;
	}

	UINT header = (ip->AddrSize == 4 ? 20 : 40);
	if (family == false)
		p->Size = ip->Size;
	else if (p->Quoted)
		p->Size = header + NODE_NAT_ICMP_HEADER + header + (p->Inner.Size - p->Inner.HeaderSize);
	else
		p->Size = header + (ip->Size - ip->HeaderSize);

	// No packet of the host grows into the overlay, where its record has the room of the packet only
	if (p->Size > (header == 20 ? NODE_NAT_MAX_LENGTH : 40 + NODE_NAT_MAX_LENGTH) || (out && p->Size > size))
		return NODE_NAT_DROP;

	return NODE_NAT_GO;
}

// Rewrite the addresses of the packet at data, a copy of the one that ip reads, as ip maps them, in their own family,
// with the checksums that cover them: of the IPv4 header, of TCP and UDP, and of ICMPv6, which covers the
// pseudo-header. whole: the upper layer is all there.
static void NodeNatRewrite(UCHAR *data, const NODE_NAT_IP *ip, bool whole) {
	UINT a = NodeNatAddrSize(ip);
	UCHAR *src = data + (ip->Version == 4 ? 12 : 8);
	UINT old_sum = NodeNatSum(0, src, a * 2);
	UINT new_sum = NodeNatSum(NodeNatSum(0, ip->Src, a), ip->Dst, a);

	// The destination follows the source in both headers
	Copy(src, ip->Src, a);
	Copy(src + a, ip->Dst, a);
	if (ip->Version == 4) {
		WRITE_USHORT(data + 10, 0);
		NodeNatChecksum(data + 10, NodeNatSum(0, data, ip->HeaderSize));
	}

	if (ip->Later || ip->HeaderSize >= ip->Size)
		return;

	UCHAR *l4 = data + ip->HeaderSize;
	UINT room = ip->Size - ip->HeaderSize;

	NodeNatTransport(l4, room, ip->Protocol, ip->Version, whole, ip->Src, ip->Dst, old_sum, new_sum);
	if (ip->Version == 6 && ip->Protocol == NODE_NAT_ICMP6 && room >= 4)
		NodeNatAdjust(l4 + 2, old_sum, new_sum);
}

// The upper-layer protocol of the packet ip in the other family: ICMP and ICMPv6 trade places
static UINT NodeNatProtocol(const NODE_NAT_IP *ip) {
	if (ip->Version == 4 && ip->Protocol == NODE_NAT_ICMP4)
		return NODE_NAT_ICMP6;

	if (ip->Version == 6 && ip->Protocol == NODE_NAT_ICMP6)
		return NODE_NAT_ICMP4;

	return ip->Protocol;
}

// Write the IP header of the version, the other family, for the packet ip with its addresses as ip maps them and an
// upper layer of length bytes, at dst: its size. The traffic class and the hop limit go with it; IPv4 gets Don't
// Fragment, as from a host that discovers the path MTU (RFC 7915 section 5.1).
static UINT NodeNatHeader(UCHAR *dst, const NODE_NAT_IP *ip, UINT version, UINT length) {
	UINT tos = (ip->Version == 4 ? ip->Data[1] : (((ip->Data[0] & 0x0F) << 4) | (ip->Data[1] >> 4)));
	UINT ttl = ip->Data[ip->Version == 4 ? 8 : 7];

	if (version == 4) {
		Zero(dst, 20);
		dst[0] = 0x45;
		dst[1] = (UCHAR)tos;
		WRITE_USHORT(dst + 2, MIN(20 + length, NODE_NAT_MAX_LENGTH));
		WRITE_USHORT(dst + 6, 0x4000);
		dst[8] = (UCHAR)ttl;
		dst[9] = (UCHAR)NodeNatProtocol(ip);
		Copy(dst + 12, ip->Src, 4);
		Copy(dst + 16, ip->Dst, 4);
		NodeNatChecksum(dst + 10, NodeNatSum(0, dst, 20));
		return 20;
	}

	Zero(dst, 40);
	dst[0] = (UCHAR)(0x60 | (tos >> 4));
	dst[1] = (UCHAR)((tos & 0x0F) << 4);
	WRITE_USHORT(dst + 4, MIN(length, NODE_NAT_MAX_LENGTH));
	dst[6] = (UCHAR)NodeNatProtocol(ip);
	dst[7] = (UCHAR)ttl;
	Copy(dst + 8, ip->Src, 16);
	Copy(dst + 24, ip->Dst, 16);
	return 40;
}

// Turn the ICMP Echo at icmp of the quoted packet ip into the one of the version, the other family: its type, and its
// checksum, which covers the pseudo-header in ICMPv6 and no address in ICMP. Any other message stays as it is.
static void NodeNatEcho(UCHAR *icmp, const NODE_NAT_IP *ip, UINT version) {
	UINT old_word = READ_USHORT(icmp);

	if (ip->Version == 4 && (icmp[0] == 8 || icmp[0] == 0))
		icmp[0] = (icmp[0] == 8 ? 128 : 129);
	else if (ip->Version == 6 && (icmp[0] == 128 || icmp[0] == 129))
		icmp[0] = (icmp[0] == 128 ? 8 : 0);
	else
		return;

	UINT new_word = READ_USHORT(icmp);
	if (version == 6)
		NodeNatAdjust(icmp + 2, old_word, new_word + NodeNatPseudo6(ip->Src, ip->Dst, ip->Length, NODE_NAT_ICMP6));
	else
		NodeNatAdjust(icmp + 2, old_word + NodeNatPseudo6(NodeNatSrc(ip), NodeNatDst(ip), ip->Length, NODE_NAT_ICMP6), new_word);
}

// Write the packet ip that an ICMP error quotes at dst, translated to the version with its addresses as ip maps them:
// its size. Its TCP or UDP checksum follows the addresses where the bytes hold it, and an Echo becomes the one of the
// other family.
static UINT NodeNatWriteQuoted(UCHAR *dst, const NODE_NAT_IP *ip, UINT version) {
	UINT at = NodeNatHeader(dst, ip, version, ip->Length);
	UINT room = ip->Size - ip->HeaderSize;
	UCHAR *l4 = dst + at;

	Copy(l4, ip->Data + ip->HeaderSize, room);
	NodeNatTransport(l4, room, ip->Protocol, version, false, ip->Src, ip->Dst, NodeNatSum(0, NodeNatSrc(ip), NodeNatAddrSize(ip) * 2), NodeNatSum(NodeNatSum(0, ip->Src, ip->AddrSize), ip->Dst, ip->AddrSize));
	if (NodeNatProtocol(ip) != ip->Protocol && room >= 4)
		NodeNatEcho(l4, ip, version);

	return at + room;
}

// Write the translation that p plans at dst, which has room for p->Size bytes: that size
static UINT NodeNatWrite(const NODE_NAT_PLAN *p, UCHAR *dst) {
	const NODE_NAT_IP *ip = &p->Ip;
	UINT version = (ip->AddrSize == 4 ? 4 : 6);
	UINT room = ip->Size - ip->HeaderSize;

	// In its own family: the addresses, of the error and of the packet that it quotes, with their checksums
	if (version == ip->Version) {
		Copy(dst, ip->Data, ip->Size);
		NodeNatRewrite(dst, ip, true);
		if (p->Quoted) {
			NodeNatRewrite(dst + ip->HeaderSize + NODE_NAT_ICMP_HEADER, &p->Inner, false);
			NodeNatIcmpSum(dst + ip->HeaderSize, room, version, ip->Src, ip->Dst);
		}
		return ip->Size;
	}

	// In the other family: a new header, then the upper layer
	UINT at = NodeNatHeader(dst, ip, version, p->Size - (version == 4 ? 20 : 40));
	UCHAR *l4 = dst + at;

	if (p->Icmp) {
		l4[0] = p->Type;
		l4[1] = p->Code;
		WRITE_USHORT(l4 + 2, 0);
		WRITE_UINT(l4 + 4, p->Rest);
		if (p->Quoted)
			NodeNatWriteQuoted(l4 + NODE_NAT_ICMP_HEADER, &p->Inner, version);
		else
			Copy(l4 + NODE_NAT_ICMP_HEADER, ip->Data + ip->HeaderSize + NODE_NAT_ICMP_HEADER, room - NODE_NAT_ICMP_HEADER);
		NodeNatIcmpSum(l4, p->Size - at, version, ip->Src, ip->Dst);
		return p->Size;
	}

	Copy(l4, ip->Data + ip->HeaderSize, room);
	if (ip->Later == false)
		NodeNatTransport(l4, room, ip->Protocol, version, true, ip->Src, ip->Dst, NodeNatSum(0, NodeNatSrc(ip), NodeNatAddrSize(ip) * 2), NodeNatSum(NodeNatSum(0, ip->Src, ip->AddrSize), ip->Dst, ip->AddrSize));

	return p->Size;
}

//
// The rules of a Generation and the data path
//

// The 1:1 NAT rules of the state st that the node applies, its 4via6 among them; NULL when it holds none that is valid.
// A rule whose prefixes are not of as many host bits is left out, and so is one of two families but for IPv6 inside
// and IPv4 outside.
NODE_NAT *NodeNewNat(const CONTROL_STATE *st) {
	if (st == NULL || st->NumNats == 0)
		return NULL;

	NODE_NAT *nat = ZeroMalloc(sizeof(NODE_NAT));
	nat->Rules = ZeroMalloc(sizeof(NODE_NAT_RULE) * MIN(st->NumNats, CONTROL_MAX_NATS));

	for (UINT i = 0; i < st->NumNats && i < CONTROL_MAX_NATS; i++)
		if (NodeNatRule(&nat->Rules[nat->NumRules], &st->Nats[i]))
			nat->NumRules++;

	if (nat->NumRules == 0) {
		NodeFreeNat(nat);
		return NULL;
	}

	return nat;
}

// Free the rules of a Generation, wiped first as the forwarding tables are
void NodeFreeNat(NODE_NAT *nat) {
	if (nat == NULL)
		return;

	Zero(nat->Rules, sizeof(NODE_NAT_RULE) * nat->NumRules);
	Free(nat->Rules);
	Zero(nat, sizeof(NODE_NAT));
	Free(nat);
}

// Put the route of a prefix into routes[num] when routes is not NULL: 1 for a prefix of IPv4 or IPv6, else 0
static UINT NodeNatRoute(NODE_VRF_ROUTE *routes, UINT num, UINT vrf_id, const UCHAR *address, UINT size, UINT length, UINT next_hop) {
	if ((size != 4 && size != 16) || length > size * 8)
		return 0;

	if (routes != NULL) {
		NODE_VRF_ROUTE *r = &routes[num];

		Zero(r, sizeof(NODE_VRF_ROUTE));
		r->VrfId = vrf_id;
		Copy(r->Address, address, size);
		r->AddressSize = size;
		r->Length = length;
		r->NextHop = next_hop;
	}

	return 1;
}

// The routes that the 1:1 NAT rules of the state st add to the forwarding tables of its VRFs, into routes, or their
// number when routes is NULL: the outside prefix of each rule of one family of the node leads to the host, and each
// route of a peer to that peer, next hop i for the peer of st->Peers[i]. Their number.
UINT NodeNatRoutes(const CONTROL_STATE *st, NODE_VRF_ROUTE *routes) {
	UINT num = 0;

	for (UINT i = 0; i < st->NumNats && i < CONTROL_MAX_NATS; i++) {
		NODE_NAT_RULE r;

		if (NodeNatRule(&r, &st->Nats[i]) && r.Family == false)
			num += NodeNatRoute(routes, num, r.VrfId, r.Outside, r.OutsideSize, r.OutsideLength, NODE_VRF_LOCAL);
	}

	for (UINT i = 0; i < st->NumPeers; i++) {
		for (UINT j = 0; j < st->Peers[i].NumRoutes && j < CONTROL_MAX_ROUTES; j++) {
			const CONTROL_ROUTE *c = &st->Peers[i].Routes[j];

			// A route that a VRF of the peer leaks goes in with NodeLeakRoutes (NodeLeak.c; SDN-7, #183)
			if (c->PeerVrfId != 0 && c->PeerVrfId != c->VrfId)
				continue;
			num += NodeNatRoute(routes, num, c->VrfId, c->Address, c->AddressSize, c->Length, i);
		}
	}

	return num;
}

// The source and the destination of a packet of the host in the VRF vrf_id as the overlay sees them, through the
// rules of the tables v, and their size: what NodeOverlayEnds reads for a packet that no rule holds. False for a
// packet that is neither IPv4 nor IPv6, and for one that a rule holds and that cannot be translated.
bool NodeNatEnds(NODE_VRF_TABLES *v, UINT vrf_id, const UCHAR *packet, UINT size, UCHAR *src, UCHAR *dst, UINT *addr_size) {
	NODE_NAT_PLAN p;

	if (NodeNatPlan((v != NULL ? v->Nat : NULL), vrf_id, true, packet, size, &p) == NODE_NAT_DROP)
		return false;

	*addr_size = p.Ip.AddrSize;
	Copy(src, p.Ip.Src, p.Ip.AddrSize);
	Copy(dst, p.Ip.Dst, p.Ip.AddrSize);
	return true;
}

// Copy a packet of the host in the VRF vrf_id to dst as the overlay sees it, through the rules of the tables v: its
// size, never more than size, which dst has room for. A packet that no rule holds is copied as it is; 0 for one that
// NodeNatEnds does not take.
UINT NodeNatCopy(NODE_VRF_TABLES *v, UINT vrf_id, UCHAR *dst, const UCHAR *packet, UINT size) {
	NODE_NAT_PLAN p;

	switch (NodeNatPlan((v != NULL ? v->Nat : NULL), vrf_id, true, packet, size, &p)) {
	case NODE_NAT_GO:
		return NodeNatWrite(&p, dst);
	case NODE_NAT_ASIS:
		Copy(dst, packet, size);
		return size;
	default:
		return 0;
	}
}

// A packet of a peer in the VRF vrf_id as the host sees it, through the rules of the tables v: when a rule holds it,
// *packet and *size become its translation in buf, of buf_size bytes, which has room for *size + NODE_NAT_GROWTH;
// when none does they stay. False for a packet that a rule holds and that cannot be translated.
bool NodeNatInbound(NODE_VRF_TABLES *v, UINT vrf_id, const UCHAR **packet, UINT *size, UCHAR *buf, UINT buf_size) {
	NODE_NAT_PLAN p;

	switch (NodeNatPlan((v != NULL ? v->Nat : NULL), vrf_id, false, *packet, *size, &p)) {
	case NODE_NAT_ASIS:
		return true;
	case NODE_NAT_GO:
		if (buf == NULL || p.Size > buf_size)
			return false;

		*size = NodeNatWrite(&p, buf);
		*packet = buf;
		return true;
	default:
		return false;
	}
}
