// NodeTagMac.c
// The tag mode hmac of the overlay of a node (SDN-88, #387). On a link of kind vxlan or geneve the source group of a packet
// travels in the clear (NodeSourceGroup.c), so in the tag mode trusted-underlay whoever can send on the underlay as a peer
// can claim any group that the peer may assert. In the tag mode hmac a node of the VRF takes the source group of a datagram
// only with a MAC under a key of the VRF, which the controller makes, keeps sealed and gives each node of the VRF in the
// Vrf object of its Generation, over the authenticated control stream (CONTROL_VRF.TagKeys). The MAC is HMAC-SHA256 of the
// crypto module, on CNG, truncated to 64 bits, over the VNI, the group ID, the ID of the key, the tag set, the group
// generation and a timestamp of the sender, then the inner IP and L4 headers of the packet (NodeTagMacHeaders), so that a
// tag cannot be pasted onto another flow. It travels with the ID of its key and the timestamp in the option of the
// authenticated source group of Geneve (Core/Vxlan.h); the group policy extension of VXLAN has no room for it, so a node
// sends no source group on a link of kind vxlan in this mode, and the controller refuses the mode for a VRF of that kind.
//
// Two keys of a VRF are active at once, each with its ID. A node takes a MAC of either and computes its own with the one
// that the controller marks to send with. The controller rotates a key in two Generations: the first gives every node the
// new key besides the one in use, and once every node of the VRF acknowledged it, the second makes it the key to send with
// (controller/internal/controller/tagkeys.go). So whichever node gets its Generation first, no node sends with a key that
// another node does not hold, and no packet of an open flow loses its source group.
//
// A claim whose MAC is wrong, whose key the node does not hold, whose timestamp is more than NODE_TAG_MAC_WINDOW s from the
// clock of the node either way, or that carries no MAC, is not authentic: the node judges the packet as one without the
// option, by the map of address to group of its state and then default deny, and counts it as unauthenticated
// (NodeSourceGroupJudge). The limits of the mode: a datagram can be replayed inside the window; the payload is not
// encrypted, in this mode as in the others of a plain link; and the key is the VRF's, so every node of the VRF can claim
// any group of the VRF, which is what the membership of a VRF means. The clocks of the nodes must be within the window of
// each other, from an authenticated time source.

#include "NodeTagMac.h"

#include "Mayaqua/Memory.h"
#include "Mayaqua/Network.h"
#include "Mayaqua/TcpIp.h"

#include "Core/Crypto.h"

// One VRF of a Generation in the tag mode hmac: its VNI, the kind of its links and its keys
typedef struct NODE_TAG_MAC_VRF {
	UINT VrfId;
	UINT Vni;
	UINT Link; // CONTROL_LINK_*
	UINT NumKeys;
	CONTROL_TAG_KEY Keys[CONTROL_TAG_KEYS];
} NODE_TAG_MAC_VRF;

struct NODE_TAG_MAC_TABLE {
	UINT NumVrfs;
	NODE_TAG_MAC_VRF Vrfs[CONTROL_MAX_VRFS];
};

// The keys of the VRFs of the state st in the tag mode hmac, which go in with the forwarding tables of its Generation
// (NodeSourceGroupAttach); NULL when no VRF of st is in that mode
NODE_TAG_MAC_TABLE *NodeTagMacNew(const CONTROL_STATE *st) {
	NODE_TAG_MAC_TABLE *m = NULL;

	for (UINT i = 0; st != NULL && i < st->NumVrfs && i < CONTROL_MAX_VRFS; i++) {
		const CONTROL_VRF *c = &st->Vrfs[i];

		if (c->TagMode != CONTROL_TAG_MODE_HMAC)
			continue;
		if (m == NULL)
			m = ZeroMalloc(sizeof(NODE_TAG_MAC_TABLE));

		NODE_TAG_MAC_VRF *v = &m->Vrfs[m->NumVrfs++];
		v->VrfId = c->Id;
		v->Vni = c->Vni;
		v->Link = c->Link;
		v->NumKeys = MIN(c->NumTagKeys, CONTROL_TAG_KEYS);
		Copy(v->Keys, c->TagKeys, sizeof(CONTROL_TAG_KEY) * v->NumKeys);
	}

	return m;
}

// Free the keys of a Generation, zeroed first
void NodeTagMacFree(NODE_TAG_MAC_TABLE *m) {
	if (m == NULL)
		return;

	SecureZeroMemory(m, sizeof(NODE_TAG_MAC_TABLE));
	Free(m);
}

// The VRF vrf_id of the table m, NULL for one that is not in the tag mode hmac
static const NODE_TAG_MAC_VRF *NodeTagMacVrf(const NODE_TAG_MAC_TABLE *m, UINT vrf_id) {
	for (UINT i = 0; m != NULL && i < m->NumVrfs; i++)
		if (m->Vrfs[i].VrfId == vrf_id)
			return &m->Vrfs[i];

	return NULL;
}

// The clock of the timestamps: seconds since 1970-01-01 UTC, the 32 low bits
UINT NodeTagMacNow() {
	FILETIME ft;
	ULARGE_INTEGER t;

	GetSystemTimeAsFileTime(&ft);
	t.LowPart = ft.dwLowDateTime;
	t.HighPart = ft.dwHighDateTime;

	// 100 ns intervals since 1601-01-01, of which 11644473600 s lie before 1970-01-01
	return (UINT)((t.QuadPart - 116444736000000000ULL) / 10000000ULL);
}

// The bytes at the start of the IP packet of size bytes at packet that the MAC covers, its inner IP and L4 headers: the
// IPv4 header with its options, or the IPv6 header with its extension headers of hop-by-hop options, routing, fragment and
// destination options, NODE_TAG_MAC_EXTENSIONS at most; then the header of TCP, by its data offset, or the 8 bytes of the
// header of UDP, ICMP or ICMPv6. A later fragment, and any other protocol, has no L4 header. Never more than size: a
// packet that ends inside its headers gives all of its bytes, and a packet that is no IP packet none.
UINT NodeTagMacHeaders(const UCHAR *packet, UINT size) {
	UINT off;
	UINT next;
	bool later = false;

	if (packet == NULL || size == 0)
		return 0;

	if ((packet[0] >> 4) == 4) {
		UINT ihl = (packet[0] & 0x0F) * 4;

		if (size < 20 || ihl < 20 || ihl > size)
			return size;
		off = ihl;
		next = packet[9];
		later = ((READ_USHORT(packet + 6) & 0x1FFF) != 0);
	} else if ((packet[0] >> 4) == 6) {
		if (size < 40)
			return size;
		off = 40;
		next = packet[6];
		for (UINT n = 0; n < NODE_TAG_MAC_EXTENSIONS && later == false; n++) {
			if (next == 44) {
				if (size - off < 8)
					return size;
				later = ((READ_USHORT(packet + off + 2) & 0xFFF8) != 0);
				next = packet[off];
				off += 8;
			} else if (next == 0 || next == 43 || next == 60) {
				if (size - off < 2)
					return size;
				UINT len = ((UINT)packet[off + 1] + 1) * 8;
				if (len > size - off)
					return size;
				next = packet[off];
				off += len;
			} else {
				break;
			}
		}
	} else {
		return 0;
	}

	UINT l4 = 0;
	if (later == false && next == IP_PROTO_TCP) {
		l4 = 20;
		if (size - off > 12 && (UINT)(packet[off + 12] >> 4) * 4 > l4)
			l4 = (UINT)(packet[off + 12] >> 4) * 4;
	} else if (later == false && (next == IP_PROTO_UDP || next == IP_PROTO_ICMPV4 || next == IP_PROTO_ICMPV6)) {
		l4 = 8;
	}

	return (l4 > size - off ? size : off + l4);
}

// The MAC of the source group g of a datagram on the VNI vni under the key of CONTROL_TAG_KEY_SIZE bytes at key, into mac,
// GENEVE_GROUP_MAC_SIZE bytes: the first bytes of HMAC-SHA256 over NODE_TAG_MAC_FIELDS bytes, the VNI, the group ID, the 16
// low bits of the ID of the key, the tag set, the group generation and the timestamp, big-endian, then the inner IP and L4
// headers of the IP packet of size bytes at packet (NodeTagMacHeaders). False, with mac zeroed, when CNG fails.
bool NodeTagMacCompute(const UCHAR *key, UINT vni, const VXLAN_GROUP *g, const UCHAR *packet, UINT size, UCHAR *mac) {
	UCHAR fields[NODE_TAG_MAC_FIELDS];
	UCHAR full[CRYPTO_SHA256_SIZE];
	CRYPTO_SHA256 h;

	if (mac == NULL)
		return false;

	Zero(mac, GENEVE_GROUP_MAC_SIZE);
	if (key == NULL || g == NULL || (packet == NULL && size != 0))
		return false;

	WRITE_UINT(fields, vni);
	WRITE_USHORT(fields + 4, g->Group);
	WRITE_USHORT(fields + 6, g->KeyId);
	WRITE_UINT64(fields + 8, g->Tags);
	WRITE_UINT(fields + 16, g->Generation);
	WRITE_UINT(fields + 20, g->Time);

	// CryptoSha256End releases the hash that CryptoHmacSha256Begin made, also after a failed part, and fails for none
	bool ok = CryptoHmacSha256Begin(&h, key, CONTROL_TAG_KEY_SIZE) && CryptoSha256Update(&h, fields, sizeof(fields)) &&
	          CryptoSha256Update(&h, packet, NodeTagMacHeaders(packet, size));
	ok = CryptoSha256End(&h, full) && ok;
	if (ok)
		Copy(mac, full, GENEVE_GROUP_MAC_SIZE);

	SecureZeroMemory(full, sizeof(full));
	return ok;
}

// Give the source group group of a packet of the host in the VRF vrf_id of the table m, of size bytes at packet, which goes
// over the link of the VRF in the tag mode hmac, the ID of the key to send with, the timestamp now and the MAC: true when it
// can go with them. A link of kind vxlan has no room for the MAC and a VRF without a key to send with gives none, so the
// group is emptied then, and the packet goes without a source group, which its peer judges by the map of address to group.
bool NodeTagMacSign(const NODE_TAG_MAC_TABLE *m, UINT vrf_id, const UCHAR *packet, UINT size, UINT now, VXLAN_GROUP *group) {
	const NODE_TAG_MAC_VRF *v = NodeTagMacVrf(m, vrf_id);
	const CONTROL_TAG_KEY *k = NULL;

	if (group == NULL)
		return false;

	for (UINT i = 0; v != NULL && i < v->NumKeys; i++)
		if (v->Keys[i].Send)
			k = &v->Keys[i];

	if (group->Carried == false || v == NULL || v->Link != CONTROL_LINK_GENEVE || k == NULL) {
		Zero(group, sizeof(VXLAN_GROUP));
		return false;
	}

	group->HasMac = true;
	group->KeyId = (USHORT)k->Id;
	group->Time = now;
	if (NodeTagMacCompute(k->Key, v->Vni, group, packet, size, group->Mac) == false) {
		Zero(group, sizeof(VXLAN_GROUP));
		return false;
	}

	return true;
}

// Whether the claim of a datagram of the link of the VRF vrf_id of the table m in the tag mode hmac, with the IP packet of
// size bytes at packet, is authentic, into claim->Authentic: it carries a MAC under a key of the VRF whose ID it names, a
// timestamp at most NODE_TAG_MAC_WINDOW s from now either way, and the MAC is the one of its fields and of the inner IP and
// L4 headers of the packet, compared in a time that does not depend on its bytes. Any other claim is not authentic, and
// the node judges its packet as one without the option of the source group.
void NodeTagMacCheck(const NODE_TAG_MAC_TABLE *m, UINT vrf_id, const UCHAR *packet, UINT size, UINT now, NODE_SOURCE_CLAIM *claim) {
	const NODE_TAG_MAC_VRF *v = NodeTagMacVrf(m, vrf_id);
	const CONTROL_TAG_KEY *k = NULL;
	UCHAR mac[GENEVE_GROUP_MAC_SIZE];
	VXLAN_GROUP g;

	if (claim == NULL)
		return;

	claim->Authentic = false;
	if (claim->Carried == false || claim->HasMac == false || v == NULL)
		return;

	// The difference of the two clocks, of the 32 low bits of each, either way
	INT delta = (INT)(now - claim->Time);
	if (delta > NODE_TAG_MAC_WINDOW || delta < -NODE_TAG_MAC_WINDOW)
		return;

	for (UINT i = 0; i < v->NumKeys; i++)
		if ((v->Keys[i].Id & 0xFFFF) == claim->KeyId)
			k = &v->Keys[i];
	if (k == NULL)
		return;

	Zero(&g, sizeof(g));
	g.Group = (USHORT)claim->Group;
	g.KeyId = (USHORT)claim->KeyId;
	g.Tags = claim->Tags;
	g.Generation = claim->Generation;
	g.Time = claim->Time;
	if (NodeTagMacCompute(k->Key, v->Vni, &g, packet, size, mac) && CryptoEqual(mac, claim->Mac, GENEVE_GROUP_MAC_SIZE))
		claim->Authentic = true;
}
