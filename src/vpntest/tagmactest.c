// tagmactest.c
// Named tag MAC test of vpntest ("tagmac" command, SDN-88 #387)
//
// The MAC of the source group in the tag mode hmac (Cedar/NodeTagMac.c): HMAC-SHA256 of the crypto module, truncated to 64
// bits, under a key of the VRF, over the VNI, the group ID, the ID of the key, the tag set, the group generation and the
// timestamp of the sender, then the inner IP and L4 headers of the packet (NodeTagMacHeaders). For each of six packets, of
// UDP, of TCP with options, of an ICMP echo behind IPv4 options, of UDP behind an IPv6 hop-by-hop options header, a later
// fragment and a packet that ends inside its TCP header, the test prints the key, the fields, the bytes of the packet that
// the MAC covers and the MAC, then the option of the authenticated source group of Geneve as the VXLAN module sends it
// (VxlanSendToGroup) and what its ingress reads back (VxlanInput); the text matches the golden file
// tests/golden/tagmac/tagmac_vectors.txt (golden family "tagmac"). Then what a node takes (NodeTagMacSign, NodeTagMacCheck):
// a MAC of either key of the VRF with a timestamp within 30 s of its clock, either way; not a timestamp 31 s away, a key
// that the VRF does not have, a changed MAC, group, tag set, group generation or inner header, a claim without a MAC, or a
// claim of a VRF in another tag mode; a byte of the payload after the headers is no part of the MAC; a node sends no
// source group on a link of kind vxlan, which has no room for the MAC, nor in a VRF without a key to send with. Last, the
// cost of the MAC on each packet of a link: the signing and the check of the source group of a UDP packet of 100 bytes
// (BENCH tag_mac_sign_100 and tag_mac_check_100, in ops/s), cases of the performance gate of ADR-0040 item 5. Print
// "TAGMAC TEST OK" only when every check passes.

#include "harness_int.h"
#include "testlist.h"

#include "Cedar/Node.h"
#include "Cedar/NodeLink.h"
#include "Cedar/NodeTagMac.h"

#include "Mayaqua/FileIO.h"
#include "Mayaqua/Memory.h"
#include "Mayaqua/Network.h"
#include "Mayaqua/Str.h"
#include "Mayaqua/TcpIp.h"

#include "Core/Control.h"
#include "Core/Vxlan.h"

#define	TMTEST_VRF				101			// The VRF of the tag mode hmac, of the link geneve
#define	TMTEST_VNI				5101		// ... and its VNI
#define	TMTEST_VXLAN_VRF		103			// A VRF of the tag mode hmac whose link is vxlan
#define	TMTEST_UNSENT_VRF		104			// A VRF of the tag mode hmac whose one key is not the one to send with
#define	TMTEST_OFF_VRF			102			// A VRF of another tag mode
#define	TMTEST_NOW				0x65000000	// The clock of the node in the checks
#define	TMTEST_MAX_PACKET		128			// The largest packet of the vectors
#define	TMTEST_GOLDEN			"tagmac_vectors.txt"
#define	TMBENCH_RUNS			5			// Runs of a case of the benchmark: the BENCH line carries their median (an odd number)
#define	TMBENCH_SPAN			200			// ms of one run

// The packets of the vectors
#define	TMTEST_UDP4				0
#define	TMTEST_TCP4				1
#define	TMTEST_ICMP4			2
#define	TMTEST_UDP6				3
#define	TMTEST_FRAGMENT			4
#define	TMTEST_SHORT			5

// One vector: the first byte of its key, each byte one more than the one before, the fields of its source group and its
// packet
typedef struct TMTEST_VECTOR
{
	char *Name;
	char *What;
	UCHAR KeyByte;
	UINT Group;
	UINT KeyId;
	UINT64 Tags;
	UINT Generation;
	UINT Time;
	UINT Packet;
} TMTEST_VECTOR;

static TMTEST_VECTOR tmtest_vectors[] =
{
	{"udp4", "an IPv4 packet of UDP", 0x00, 1, 1, 0x1ULL, 1, 0x65000000, TMTEST_UDP4},
	{"tcp4", "an IPv4 packet of TCP with 12 bytes of options", 0x20, 3, 2, 0x4ULL, 7, 0x65000001, TMTEST_TCP4},
	{"icmp4", "an IPv4 packet with 4 bytes of options, of an ICMP echo", 0x40, 258, 7, 0x0102030405060708ULL, 0x01020304, 0x6500001E, TMTEST_ICMP4},
	{"udp6", "an IPv6 packet with a hop-by-hop options header, of UDP", 0x60, 2, 1, 0x2ULL, 1, 0x65000000, TMTEST_UDP6},
	{"fragment", "a later fragment of an IPv4 packet, which has no L4 header", 0x80, 65535, 65535, 0xFFFFFFFFFFFFFFFFULL, 0xFFFFFFFF, 0xFFFFFFFF, TMTEST_FRAGMENT},
	{"short", "an IPv4 packet of TCP that ends inside its TCP header", 0xA0, 5, 3, 0x9ULL, 4, 0x00000001, TMTEST_SHORT},
};

// The fields of the Geneve header and of the option of the authenticated source group, in bytes, 0 for the line between them
static UINT tmtest_geneve_fields[] = {1, 1, 2, 3, 1, 0, 2, 1, 1, 2, 2, 8, 4, 4, 8};
// ... and of the fields that the MAC covers before the headers
static UINT tmtest_mac_fields[] = {4, 2, 2, 8, 4, 4};

// The MAC address of both ends of the Ethernet header of a frame of a link
static const UCHAR tmtest_mac_address[6] = {0x02, 0x52, 0x5A, 0x00, 0x00, 0x03};

// The test
typedef struct TMTEST_CTX
{
	UINT NumChecks;
	UINT NumFailed;
	BUF *Text;								// The text of the golden file
	VXLAN *Sender;							// The module that sends: its send procedure keeps the last datagram
	VXLAN *Receiver;						// The module that takes the datagrams, on TMTEST_VNI
	UCHAR Datagram[VXLAN_MAX_DATAGRAM];		// The last datagram that the sender sent ...
	UINT DatagramSize;						// ... and its size
	bool Got;								// The receiver took a frame ...
	VXLAN_GROUP Group;						// ... with this source group ...
	UCHAR Frame[NODE_LINK_ETHER + TMTEST_MAX_PACKET];	// ... and this frame, as much as fits
	UINT FrameSize;
	NODE_TAG_MAC_TABLE *Table;				// The keys of the VRFs of the checks
} TMTEST_CTX;

static bool TmTestCheck(TMTEST_CTX *ctx, bool ok, char *what)
{
	ctx->NumChecks++;
	Print("  [%s] %s\n", ok ? "PASS" : "FAIL", what);
	if (ok == false)
	{
		ctx->NumFailed++;
	}

	return ok;
}

// One line of the golden text
static void TmTestLine(TMTEST_CTX *ctx, char *line)
{
	Print("  %s\n", line);
	WriteBuf(ctx->Text, line, StrLen(line));
	WriteBuf(ctx->Text, "\n", 1);
}

// The bytes of data as hexadecimal fields of the widths of fields, separated by spaces, a 0 width as a | between them
static void TmTestFields(char *out, UINT size, const UCHAR *data, UINT *fields, UINT num_fields)
{
	UINT pos = 0;

	StrCpy(out, size, "");
	for (UINT i = 0;i < num_fields;i++)
	{
		char hex[3];

		if (i != 0)
		{
			StrCat(out, size, " ");
		}
		if (fields[i] == 0)
		{
			StrCat(out, size, "|");
			continue;
		}
		for (UINT j = 0;j < fields[i];j++)
		{
			Format(hex, sizeof(hex), "%02x", (UINT)data[pos++]);
			StrCat(out, size, hex);
		}
	}
}

// The bytes of data as one hexadecimal field
static void TmTestHex(char *out, UINT size, const UCHAR *data, UINT data_size)
{
	UINT field = data_size;

	TmTestFields(out, size, data, &field, 1);
}

// The key of 32 bytes from first on, each byte one more than the one before
static void TmTestKey(UCHAR *key, UCHAR first)
{
	for (UINT i = 0;i < CONTROL_TAG_KEY_SIZE;i++)
	{
		key[i] = (UCHAR)(first + i);
	}
}

// The IPv4 header of total bytes with the id ident, the flags and the fragment offset frag, the protocol proto, from
// 10.0.0.1 to 10.0.0.2, and num_options bytes of the options options, at buf; its size
static UINT TmTestIpv4(UCHAR *buf, UINT total, UINT ident, UINT frag, UINT proto, const UCHAR *options, UINT num_options)
{
	Zero(buf, 20 + num_options);
	buf[0] = (UCHAR)(0x40 | ((20 + num_options) / 4));
	WRITE_USHORT(buf + 2, total);
	WRITE_USHORT(buf + 4, ident);
	WRITE_USHORT(buf + 6, frag);
	buf[8] = 64;
	buf[9] = (UCHAR)proto;
	buf[12] = 10;
	buf[15] = 1;
	buf[16] = 10;
	buf[19] = 2;
	Copy(buf + 20, options, num_options);

	return 20 + num_options;
}

// The packet of kind (TMTEST_*) into buf, of TMTEST_MAX_PACKET bytes at least; its size
static UINT TmTestPacket(UINT kind, UCHAR *buf)
{
	static const UCHAR ip_options[4] = {1, 1, 1, 0};
	static const UCHAR tcp_options[12] = {1, 1, 8, 10, 0, 0, 0, 1, 0, 0, 0, 0};
	UINT size = 0;

	Zero(buf, TMTEST_MAX_PACKET);
	switch (kind)
	{
	case TMTEST_UDP4:
		// UDP from port 20000 to 9000, and 72 bytes of payload
		TmTestIpv4(buf, 100, 1, 0x4000, IP_PROTO_UDP, NULL, 0);
		WRITE_USHORT(buf + 20, 20000);
		WRITE_USHORT(buf + 22, 9000);
		WRITE_USHORT(buf + 24, 80);
		for (UINT i = 28;i < 100;i++)
		{
			buf[i] = (UCHAR)(i * 13);
		}
		size = 100;
		break;

	case TMTEST_TCP4:
		// TCP from port 40000 to 443 with the data offset of 8 words, two NOPs and a timestamp option, and 28 bytes of payload
		TmTestIpv4(buf, 80, 2, 0x4000, IP_PROTO_TCP, NULL, 0);
		WRITE_USHORT(buf + 20, 40000);
		WRITE_USHORT(buf + 22, 443);
		WRITE_UINT(buf + 24, 0x01020304);
		buf[32] = 0x80;
		buf[33] = 0x18;
		WRITE_USHORT(buf + 34, 0xFFFF);
		Copy(buf + 40, tcp_options, sizeof(tcp_options));
		for (UINT i = 52;i < 80;i++)
		{
			buf[i] = (UCHAR)(i * 7);
		}
		size = 80;
		break;

	case TMTEST_ICMP4:
		// An ICMP echo of the id 0x1234 and the sequence 1 behind 4 bytes of IPv4 options, and 8 bytes of payload
		TmTestIpv4(buf, 40, 3, 0, IP_PROTO_ICMPV4, ip_options, sizeof(ip_options));
		buf[24] = 8;
		WRITE_USHORT(buf + 28, 0x1234);
		WRITE_USHORT(buf + 30, 1);
		Copy(buf + 32, "ranz-mac", 8);
		size = 40;
		break;

	case TMTEST_UDP6:
		// IPv6 from fd00::1 to fd00::2, a hop-by-hop options header with a PadN option, UDP from port 20001 to 9000, and 24
		// bytes of payload
		buf[0] = 0x60;
		WRITE_USHORT(buf + 4, 40);
		buf[6] = 0;
		buf[7] = 64;
		buf[8] = 0xFD;
		buf[23] = 1;
		buf[24] = 0xFD;
		buf[39] = 2;
		buf[40] = IP_PROTO_UDP;
		buf[42] = 1;
		buf[43] = 4;
		WRITE_USHORT(buf + 48, 20001);
		WRITE_USHORT(buf + 50, 9000);
		WRITE_USHORT(buf + 52, 32);
		for (UINT i = 56;i < 80;i++)
		{
			buf[i] = (UCHAR)(i * 5);
		}
		size = 80;
		break;

	case TMTEST_FRAGMENT:
		// A later fragment of UDP, at the offset 185 words, and 40 bytes of the packet
		TmTestIpv4(buf, 60, 4, 0x00B9, IP_PROTO_UDP, NULL, 0);
		for (UINT i = 20;i < 60;i++)
		{
			buf[i] = (UCHAR)(i * 3);
		}
		size = 60;
		break;

	case TMTEST_SHORT:
		// TCP from port 40001 to 443 that ends after its ports
		TmTestIpv4(buf, 24, 5, 0x4000, IP_PROTO_TCP, NULL, 0);
		WRITE_USHORT(buf + 20, 40001);
		WRITE_USHORT(buf + 22, 443);
		size = 24;
		break;
	}

	return size;
}

// The send procedure of the sender: it keeps the datagram
static bool TmTestSend(void *param, const VXLAN_ADDR *dst, const void *data, UINT size)
{
	TMTEST_CTX *ctx = (TMTEST_CTX *)param;

	ctx->DatagramSize = MIN(size, sizeof(ctx->Datagram));
	Copy(ctx->Datagram, data, ctx->DatagramSize);

	return true;
}

// The send procedure of the receiver, which sends nothing
static bool TmTestNoSend(void *param, const VXLAN_ADDR *dst, const void *data, UINT size)
{
	return false;
}

// The receiver: it keeps the frame and the source group of its datagram
static void TmTestReceive(VXLAN *v, void *param, UINT vni, const VXLAN_ADDR *from, const VXLAN_GROUP *group, const UCHAR *frame, UINT size)
{
	TMTEST_CTX *ctx = (TMTEST_CTX *)param;

	ctx->Got = true;
	Copy(&ctx->Group, group, sizeof(VXLAN_GROUP));
	ctx->FrameSize = MIN(size, sizeof(ctx->Frame));
	Copy(ctx->Frame, frame, ctx->FrameSize);
}

// The frame of a link of the packet of size bytes into frame: the Ethernet header of a link, then the packet; its size
static UINT TmTestFrame(UCHAR *frame, const UCHAR *packet, UINT size)
{
	Copy(frame, tmtest_mac_address, 6);
	Copy(frame + 6, tmtest_mac_address, 6);
	WRITE_USHORT(frame + 12, (packet[0] >> 4) == 6 ? MAC_PROTO_IPV6 : MAC_PROTO_IPV4);
	Copy(frame + NODE_LINK_ETHER, packet, size);

	return NODE_LINK_ETHER + size;
}

// The source group of the vector v, with its MAC under the key into *g
static bool TmTestGroup(const TMTEST_VECTOR *v, const UCHAR *key, const UCHAR *packet, UINT size, VXLAN_GROUP *g)
{
	Zero(g, sizeof(VXLAN_GROUP));
	g->Carried = true;
	g->HasTags = true;
	g->HasGeneration = true;
	g->Group = (USHORT)v->Group;
	g->Tags = v->Tags;
	g->Generation = v->Generation;
	g->HasMac = true;
	g->KeyId = (USHORT)v->KeyId;
	g->Time = v->Time;

	return NodeTagMacCompute(key, TMTEST_VNI, g, packet, size, g->Mac);
}

// The vectors: for each, the key, the fields, the bytes that the MAC covers and the MAC, then the datagram of Geneve that
// the module sends with it and what its ingress reads back
static void TmTestVectors(TMTEST_CTX *ctx)
{
	char line[MAX_SIZE * 2];
	char hex[MAX_SIZE];
	UCHAR packet[TMTEST_MAX_PACKET];
	UCHAR frame[NODE_LINK_ETHER + TMTEST_MAX_PACKET];
	UCHAR key[CONTROL_TAG_KEY_SIZE];
	UCHAR fields[NODE_TAG_MAC_FIELDS];
	VXLAN_ADDR vtep;
	VXLAN_GROUP g;

	VxlanAddrSetV4(&vtep, 192, 0, 2, 1, GENEVE_PORT);
	vtep.Encap = VXLAN_ENCAP_GENEVE;

	for (UINT i = 0;i < sizeof(tmtest_vectors) / sizeof(tmtest_vectors[0]);i++)
	{
		TMTEST_VECTOR *v = &tmtest_vectors[i];
		UINT size = TmTestPacket(v->Packet, packet);
		UINT frame_size = TmTestFrame(frame, packet, size);

		TmTestKey(key, v->KeyByte);
		bool computed = TmTestGroup(v, key, packet, size, &g);

		Format(line, sizeof(line), "[%s] %s", v->Name, v->What);
		TmTestLine(ctx, line);
		TmTestHex(hex, sizeof(hex), key, sizeof(key));
		Format(line, sizeof(line), "  key %s", hex);
		TmTestLine(ctx, line);
		WRITE_UINT(fields, TMTEST_VNI);
		WRITE_USHORT(fields + 4, v->Group);
		WRITE_USHORT(fields + 6, v->KeyId);
		WRITE_UINT64(fields + 8, v->Tags);
		WRITE_UINT(fields + 16, v->Generation);
		WRITE_UINT(fields + 20, v->Time);
		TmTestFields(hex, sizeof(hex), fields, tmtest_mac_fields, sizeof(tmtest_mac_fields) / sizeof(tmtest_mac_fields[0]));
		Format(line, sizeof(line), "  fields %s", hex);
		TmTestLine(ctx, line);
		Format(line, sizeof(line), "  the MAC covers the first %u of the %u bytes of the packet", NodeTagMacHeaders(packet, size), size);
		TmTestLine(ctx, line);
		TmTestHex(hex, sizeof(hex), g.Mac, sizeof(g.Mac));
		Format(line, sizeof(line), "  mac %s", hex);
		TmTestLine(ctx, line);
		Format(line, sizeof(line), "%s: the MAC is computed", v->Name);
		TmTestCheck(ctx, computed, line);

		// The datagram that the module sends with the option of the authenticated source group, and what its ingress reads
		ctx->DatagramSize = 0;
		bool sent = VxlanSendToGroup(ctx->Sender, TMTEST_VNI, &vtep, &g, frame, frame_size);
		TmTestFields(hex, sizeof(hex), ctx->Datagram, tmtest_geneve_fields, sizeof(tmtest_geneve_fields) / sizeof(tmtest_geneve_fields[0]));
		Format(line, sizeof(line), "  geneve %s", hex);
		TmTestLine(ctx, line);
		Format(line, sizeof(line), "%s: the datagram of %u bytes holds the Geneve header, the option of %u bytes whose critical bit is clear, and the frame", v->Name,
			ctx->DatagramSize, GENEVE_GROUP_MAC_OPTION);
		TmTestCheck(ctx, sent && ctx->DatagramSize == GENEVE_HEADER_SIZE + GENEVE_GROUP_MAC_OPTION + frame_size &&
			(ctx->Datagram[GENEVE_HEADER_SIZE + 2] & GENEVE_OPTION_CRITICAL) == 0 && (ctx->Datagram[1] & GENEVE_FLAG_CRITICAL) == 0, line);

		VxlanInput(ctx->Receiver, &vtep, ctx->Datagram, ctx->DatagramSize);
		if (ctx->Got && ctx->Group.Carried && ctx->Group.HasMac)
		{
			TmTestHex(hex, sizeof(hex), ctx->Group.Mac, sizeof(ctx->Group.Mac));
			Format(line, sizeof(line), "  read: group %u, key %u, tag set 0x%016I64x, group generation %u, timestamp 0x%08x, mac %s; the frame of %u bytes %s",
				(UINT)ctx->Group.Group, (UINT)ctx->Group.KeyId, ctx->Group.Tags, ctx->Group.Generation, ctx->Group.Time, hex, ctx->FrameSize,
				(ctx->FrameSize == frame_size && Cmp(ctx->Frame, frame, frame_size) == 0) ? "as it was sent" : "changed");
		}
		else
		{
			Format(line, sizeof(line), "  read: no option of the authenticated source group (got %u, carried %u)", (UINT)ctx->Got, (UINT)ctx->Group.Carried);
		}
		TmTestLine(ctx, line);
		ctx->Got = false;
		Zero(&ctx->Group, sizeof(ctx->Group));
	}
}

// The keys of the VRFs of the checks: TMTEST_VRF of the link geneve with the keys 1, from the byte 0x00, and 2, from 0x40,
// which the node sends with; TMTEST_VXLAN_VRF of the link vxlan and TMTEST_UNSENT_VRF, whose one key is not the one to send
// with, both in the tag mode hmac; and TMTEST_OFF_VRF in trusted-underlay, which has none
static NODE_TAG_MAC_TABLE *TmTestTable()
{
	CONTROL_STATE *st = ZeroMalloc(sizeof(CONTROL_STATE));
	UINT ids[4] = {TMTEST_VRF, TMTEST_OFF_VRF, TMTEST_VXLAN_VRF, TMTEST_UNSENT_VRF};

	st->NumVrfs = 4;
	for (UINT i = 0;i < 4;i++)
	{
		CONTROL_VRF *v = &st->Vrfs[i];

		v->Id = ids[i];
		v->Vni = TMTEST_VNI + i;
		v->Link = (ids[i] == TMTEST_VXLAN_VRF ? CONTROL_LINK_VXLAN : CONTROL_LINK_GENEVE);
		v->TagMode = (ids[i] == TMTEST_OFF_VRF ? CONTROL_TAG_MODE_TRUSTED : CONTROL_TAG_MODE_HMAC);
		v->NumTagKeys = (ids[i] == TMTEST_OFF_VRF ? 0 : 1);
		v->TagKeys[0].Id = 1;
		TmTestKey(v->TagKeys[0].Key, 0x00);
		v->TagKeys[0].Send = (ids[i] != TMTEST_UNSENT_VRF);
	}
	// The VRF of the checks has a second key, which the node sends with
	st->Vrfs[0].NumTagKeys = 2;
	st->Vrfs[0].TagKeys[0].Send = false;
	st->Vrfs[0].TagKeys[1].Id = 2;
	TmTestKey(st->Vrfs[0].TagKeys[1].Key, 0x40);
	st->Vrfs[0].TagKeys[1].Send = true;

	NODE_TAG_MAC_TABLE *t = NodeTagMacNew(st);
	Zero(st, sizeof(CONTROL_STATE));
	Free(st);

	return t;
}

// The claim of the group g as the link of a node makes it from a datagram of Geneve, checked at the clock now: whether it
// is authentic
static bool TmTestAuthentic(TMTEST_CTX *ctx, UINT vrf_id, const VXLAN_GROUP *g, const UCHAR *packet, UINT size, UINT now)
{
	NODE_SOURCE_CLAIM claim;

	NodeSourceGroupClaim(&claim, NODE_CARRIER_GENEVE, g);
	NodeTagMacCheck(ctx->Table, vrf_id, packet, size, now, &claim);

	return claim.Authentic;
}

// The group 3 with the tag set 0x4 and the group generation 5 under the key key_id at the time, with its MAC under the key
// from the byte key_byte, into *g
static void TmTestSigned(VXLAN_GROUP *g, UINT key_id, UCHAR key_byte, UINT time, const UCHAR *packet, UINT size)
{
	UCHAR key[CONTROL_TAG_KEY_SIZE];

	Zero(g, sizeof(VXLAN_GROUP));
	g->Carried = true;
	g->HasTags = true;
	g->HasGeneration = true;
	g->Group = 3;
	g->Tags = 0x4ULL;
	g->Generation = 5;
	g->HasMac = true;
	g->KeyId = (USHORT)key_id;
	g->Time = time;
	TmTestKey(key, key_byte);
	NodeTagMacCompute(key, TMTEST_VNI, g, packet, size, g->Mac);
}

// What a node takes and sends in the tag mode hmac
static void TmTestChecks(TMTEST_CTX *ctx)
{
	UCHAR packet[TMTEST_MAX_PACKET];
	UCHAR key[CONTROL_TAG_KEY_SIZE];
	UCHAR mac[GENEVE_GROUP_MAC_SIZE];
	UINT size = TmTestPacket(TMTEST_UDP4, packet);
	VXLAN_GROUP g, s;

	Print("[what a node takes and sends in the tag mode hmac, at its clock 0x%08x]\n", TMTEST_NOW);
	ctx->Table = TmTestTable();
	if (TmTestCheck(ctx, ctx->Table != NULL, "the keys of the VRFs of the tag mode hmac") == false)
	{
		return;
	}

	// The node signs with key 2, the one to send with, at its clock, and takes what it signed
	TmTestSigned(&s, 0, 0, 0, packet, size);
	s.HasMac = false;
	bool signed_ok = NodeTagMacSign(ctx->Table, TMTEST_VRF, packet, size, TMTEST_NOW, &s);
	TmTestKey(key, 0x40);
	bool same = NodeTagMacCompute(key, TMTEST_VNI, &s, packet, size, mac) && Cmp(mac, s.Mac, sizeof(mac)) == 0;
	TmTestCheck(ctx, signed_ok && s.HasMac && s.KeyId == 2 && s.Time == TMTEST_NOW && same,
		"a node signs the source group of a packet with key 2, the key to send with, at its clock, with the MAC of NodeTagMacCompute");
	TmTestCheck(ctx, TmTestAuthentic(ctx, TMTEST_VRF, &s, packet, size, TMTEST_NOW), "... which a node of the VRF takes as authentic");

	// Either key, and the window either way
	TmTestSigned(&g, 1, 0x00, TMTEST_NOW, packet, size);
	TmTestCheck(ctx, TmTestAuthentic(ctx, TMTEST_VRF, &g, packet, size, TMTEST_NOW), "a MAC under key 1, the other active key, is taken");
	TmTestSigned(&g, 2, 0x40, TMTEST_NOW - NODE_TAG_MAC_WINDOW, packet, size);
	bool behind = TmTestAuthentic(ctx, TMTEST_VRF, &g, packet, size, TMTEST_NOW);
	TmTestSigned(&g, 2, 0x40, TMTEST_NOW + NODE_TAG_MAC_WINDOW, packet, size);
	bool ahead = TmTestAuthentic(ctx, TMTEST_VRF, &g, packet, size, TMTEST_NOW);
	TmTestCheck(ctx, behind && ahead, "a timestamp 30 s behind the clock of the node, or 30 s ahead of it, is within the window: taken");
	TmTestSigned(&g, 2, 0x40, TMTEST_NOW - NODE_TAG_MAC_WINDOW - 1, packet, size);
	behind = TmTestAuthentic(ctx, TMTEST_VRF, &g, packet, size, TMTEST_NOW);
	TmTestSigned(&g, 2, 0x40, TMTEST_NOW + NODE_TAG_MAC_WINDOW + 1, packet, size);
	ahead = TmTestAuthentic(ctx, TMTEST_VRF, &g, packet, size, TMTEST_NOW);
	TmTestCheck(ctx, behind == false && ahead == false, "a timestamp 31 s behind or ahead, with its right MAC, is outside the window: not taken");

	// A key that the VRF does not have, and a key of the right ID that is not the VRF's
	TmTestSigned(&g, 3, 0x40, TMTEST_NOW, packet, size);
	TmTestCheck(ctx, TmTestAuthentic(ctx, TMTEST_VRF, &g, packet, size, TMTEST_NOW) == false, "a MAC under key 3, which the VRF does not have, is not taken");
	TmTestSigned(&g, 2, 0x99, TMTEST_NOW, packet, size);
	TmTestCheck(ctx, TmTestAuthentic(ctx, TMTEST_VRF, &g, packet, size, TMTEST_NOW) == false, "a MAC under another key that names the ID 2 is not taken");

	// What the MAC covers: a changed bit of the MAC, of the group, of the tag set, of the group generation, of an address or
	// a port of the inner headers; not a byte of the payload after them
	TmTestSigned(&g, 2, 0x40, TMTEST_NOW, packet, size);
	g.Mac[7] ^= 0x01;
	bool changed_mac = TmTestAuthentic(ctx, TMTEST_VRF, &g, packet, size, TMTEST_NOW);
	g.Mac[7] ^= 0x01;
	g.Group = 1;
	bool changed_group = TmTestAuthentic(ctx, TMTEST_VRF, &g, packet, size, TMTEST_NOW);
	g.Group = 3;
	g.Tags = 0x5ULL;
	bool changed_tags = TmTestAuthentic(ctx, TMTEST_VRF, &g, packet, size, TMTEST_NOW);
	g.Tags = 0x4ULL;
	g.Generation = 6;
	bool changed_generation = TmTestAuthentic(ctx, TMTEST_VRF, &g, packet, size, TMTEST_NOW);
	g.Generation = 5;
	TmTestCheck(ctx, changed_mac == false && changed_group == false && changed_tags == false && changed_generation == false,
		"a changed bit of the MAC, the group, the tag set or the group generation is not taken");
	packet[15] ^= 0x01;
	bool changed_source = TmTestAuthentic(ctx, TMTEST_VRF, &g, packet, size, TMTEST_NOW);
	packet[15] ^= 0x01;
	packet[23] ^= 0x01;
	bool changed_port = TmTestAuthentic(ctx, TMTEST_VRF, &g, packet, size, TMTEST_NOW);
	packet[23] ^= 0x01;
	packet[50] ^= 0xFF;
	bool changed_payload = TmTestAuthentic(ctx, TMTEST_VRF, &g, packet, size, TMTEST_NOW);
	packet[50] ^= 0xFF;
	TmTestCheck(ctx, changed_source == false && changed_port == false, "a changed source address or destination port of the inner headers is not taken: the tag cannot be pasted onto another flow");
	TmTestCheck(ctx, changed_payload, "a changed byte of the payload after the headers is taken: the MAC covers the headers, and the payload is not encrypted");
	TmTestCheck(ctx, TmTestAuthentic(ctx, TMTEST_VRF, &g, packet, size, TMTEST_NOW), "... and the same claim, unchanged, is taken");

	// No MAC, a VRF of another tag mode
	TmTestSigned(&g, 2, 0x40, TMTEST_NOW, packet, size);
	g.HasMac = false;
	TmTestCheck(ctx, TmTestAuthentic(ctx, TMTEST_VRF, &g, packet, size, TMTEST_NOW) == false, "a claim without a MAC, as the option of trusted-underlay carries it, is not taken");
	TmTestSigned(&g, 1, 0x00, TMTEST_NOW, packet, size);
	TmTestCheck(ctx, TmTestAuthentic(ctx, TMTEST_OFF_VRF, &g, packet, size, TMTEST_NOW) == false, "a claim of a VRF in another tag mode has no key to check it: not taken");

	// A link of kind vxlan has no room for the MAC, and a VRF without a key to send with sends none
	TmTestSigned(&s, 0, 0, 0, packet, size);
	s.HasMac = false;
	bool vxlan = NodeTagMacSign(ctx->Table, TMTEST_VXLAN_VRF, packet, size, TMTEST_NOW, &s);
	TmTestCheck(ctx, vxlan == false && s.Carried == false, "a node sends no source group on a link of kind vxlan in the tag mode hmac");
	TmTestSigned(&s, 0, 0, 0, packet, size);
	s.HasMac = false;
	bool unsent = NodeTagMacSign(ctx->Table, TMTEST_UNSENT_VRF, packet, size, TMTEST_NOW, &s);
	TmTestCheck(ctx, unsent == false && s.Carried == false, "... nor in a VRF whose keys hold none to send with");
}

// The time of QueryPerformanceCounter in seconds
static double TmBenchNow()
{
	LARGE_INTEGER c, f;

	QueryPerformanceCounter(&c);
	QueryPerformanceFrequency(&f);

	return (double)c.QuadPart / (double)f.QuadPart;
}

// One run of the case: the source group of the packet signed (check false) or checked (check true) for TMBENCH_SPAN ms;
// the operations per second
static UINT64 TmBenchRun(TMTEST_CTX *ctx, bool check, const UCHAR *packet, UINT size, const VXLAN_GROUP *signed_group)
{
	double start = TmBenchNow();
	double end = start + TMBENCH_SPAN / 1000.0;
	UINT64 ops = 0;
	double now = start;

	while (now < end)
	{
		for (UINT i = 0;i < 64;i++)
		{
			if (check)
			{
				TmTestAuthentic(ctx, TMTEST_VRF, signed_group, packet, size, TMTEST_NOW);
			}
			else
			{
				VXLAN_GROUP g;

				Copy(&g, signed_group, sizeof(g));
				g.HasMac = false;
				NodeTagMacSign(ctx->Table, TMTEST_VRF, packet, size, TMTEST_NOW, &g);
			}
		}
		ops += 64;
		now = TmBenchNow();
	}

	return (UINT64)((double)ops / (now - start));
}

// TMBENCH_RUNS runs of the case name: "BENCH <name> <median> ops/s" and "BENCH <name>_runs <run 1>,...,<run n> ops/s"
static void TmBenchCase(TMTEST_CTX *ctx, char *name, bool check, const UCHAR *packet, UINT size, const VXLAN_GROUP *signed_group)
{
	UINT64 runs[TMBENCH_RUNS];
	UINT64 sorted[TMBENCH_RUNS];
	char list[MAX_SIZE];

	for (UINT r = 0;r < TMBENCH_RUNS;r++)
	{
		runs[r] = TmBenchRun(ctx, check, packet, size, signed_group);
		sorted[r] = runs[r];
	}
	for (UINT i = 1;i < TMBENCH_RUNS;i++)
	{
		for (UINT j = i;j > 0 && sorted[j - 1] > sorted[j];j--)
		{
			UINT64 t = sorted[j];
			sorted[j] = sorted[j - 1];
			sorted[j - 1] = t;
		}
	}

	StrCpy(list, sizeof(list), "");
	for (UINT r = 0;r < TMBENCH_RUNS;r++)
	{
		char one[64];

		Format(one, sizeof(one), r == 0 ? "%I64u" : ",%I64u", runs[r]);
		StrCat(list, sizeof(list), one);
	}

	Print("BENCH %s %I64u ops/s\n", name, sorted[TMBENCH_RUNS / 2]);
	Print("BENCH %s_runs %s ops/s\n", name, list);
}

// The cost of the MAC on each packet of a link: the signing and the check of the source group of a UDP packet of 100 bytes
static void TmTestBench(TMTEST_CTX *ctx)
{
	UCHAR packet[TMTEST_MAX_PACKET];
	UINT size = TmTestPacket(TMTEST_UDP4, packet);
	VXLAN_GROUP g;

	if (ctx->Table == NULL)
	{
		return;
	}

	Print("[the cost of the MAC on a packet: the signing and the check of the source group of a UDP packet of %u bytes]\n", size);
	TmTestSigned(&g, 0, 0, 0, packet, size);
	g.HasMac = false;
	bool signed_ok = NodeTagMacSign(ctx->Table, TMTEST_VRF, packet, size, TMTEST_NOW, &g);
	if (TmTestCheck(ctx, signed_ok && TmTestAuthentic(ctx, TMTEST_VRF, &g, packet, size, TMTEST_NOW), "the source group that the benchmark checks is authentic"))
	{
		TmBenchCase(ctx, "tag_mac_sign_100", false, packet, size, &g);
		TmBenchCase(ctx, "tag_mac_check_100", true, packet, size, &g);
	}
}

// tagmac: the MAC of the source group in the tag mode hmac
RANZ_TEST_TAGS("tagmac", tagmac_test, "core", "Tag MAC (SDN-88): the MAC of the source group in the tag mode hmac, HMAC-SHA256 truncated to 64 bits over the VNI, the group, the ID of the key, the tag set, the group generation, a timestamp and the inner IP and L4 headers, for six packets, in the option of Geneve as it is sent and read back (golden family tagmac); what a node takes and sends; the cost of the MAC per packet (BENCH lines).");
void tagmac_test(UINT num, char **arg)
{
	TMTEST_CTX *ctx = ZeroMalloc(sizeof(TMTEST_CTX));
	char out_dir[MAX_SIZE];
	char golden_dir[MAX_SIZE];
	bool update;
	HARNESS h;

	Print("Tag MAC test: the MAC of the source group in the tag mode hmac\n");

	ctx->Text = NewBuf();
	ctx->Sender = VxlanNew(TmTestSend, ctx, NULL, NULL);
	ctx->Receiver = VxlanNew(TmTestNoSend, NULL, NULL, ctx);
	if (TmTestCheck(ctx, ctx->Sender != NULL && ctx->Receiver != NULL && VxlanSetVni(ctx->Receiver, TMTEST_VNI, NULL, 0), "Two VXLAN modules, one that sends and one that takes VNI 5101"))
	{
		VxlanSetGroupReceiver(ctx->Receiver, TmTestReceive);

		TmTestLine(ctx, "# SDN-88: the MAC of the source group in the tag mode hmac, HMAC-SHA256 truncated to 64 bits under the key of the VRF");
		TmTestLine(ctx, "# fields: the VNI, the group ID, the ID of the key, the tag set, the group generation, the timestamp");
		TmTestLine(ctx, "# option: the version and the length of the options, the flags O and C, the protocol, the VNI, reserved | the class, the type, the length, the group, the ID of the key, the tag set, the group generation, the timestamp, the MAC");
		TmTestVectors(ctx);
	}

	char *text = HarnessBufToStr(ctx->Text);

	HarnessGetFamilyDirs("tagmac", out_dir, sizeof(out_dir), golden_dir, sizeof(golden_dir), &update);
	MakeDirEx(out_dir);
	Print("[golden]\n");
	Print("TAGMAC GOLDEN MODE %s\n", update ? "update" : "compare");
	Print("  golden directory: %s\n", golden_dir);
	Zero(&h, sizeof(h));
	HarnessCompareGolden(&h, out_dir, golden_dir, TMTEST_GOLDEN, text, update);
	TmTestCheck(ctx, h.NumFail == 0, "The vectors match the golden file " TMTEST_GOLDEN);

	TmTestChecks(ctx);
	TmTestBench(ctx);

	Free(text);
	FreeBuf(ctx->Text);
	VxlanFree(ctx->Sender);
	VxlanFree(ctx->Receiver);
	NodeTagMacFree(ctx->Table);

	if (ctx->NumFailed == 0)
	{
		Print("TAGMAC TEST OK\n");
	}
	else
	{
		Print("TAGMAC TEST FAILED (%u of %u checks failed)\n", ctx->NumFailed, ctx->NumChecks);
	}

	Free(ctx);
}
