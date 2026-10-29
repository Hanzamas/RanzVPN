// sourcegrouptest.c
// Named source group carrier test of vpntest ("sourcegroup" command, SDN-87 #386)
//
// The encoding and the decoding of the source group of a packet, its group ID and its tag set, and of the group generation
// of its sender, in each of its carriers: the record of frame version 1 of a Noise session (Cedar/NodeSourceGroup.c:
// NodeFrameWrite, NodeFrameParse), and the group policy extension of VXLAN, which has room for the group ID alone, and
// the option of the source group of Geneve (Core/VxlanGroup.c), as the VXLAN module sends a frame with them
// (VxlanSendToGroup) and reads them at its one ingress (VxlanInput). For each of four groups the
// test prints the bytes of each carrier field by field and what a node reads back from them, then the records and the
// datagrams that a node does not take, or that carry options it does not know; the text matches the golden file
// tests/golden/sourcegroup/sourcegroup_carriers.txt (golden family "sourcegroup"). The critical bit of the option of
// Geneve is clear, and so is the C bit of its header, so that a tunnel endpoint that does not know the option skips it.
// Last, the sizes: a record or a frame that does not fit its path with the source group goes without it, so the source
// group costs no packet that went before it. Print "SOURCEGROUP TEST OK" only when every check passes.

#include "harness_int.h"
#include "testlist.h"

#include "Cedar/Node.h"
#include "Cedar/NodeSourceGroup.h"

#include "Mayaqua/FileIO.h"
#include "Mayaqua/Memory.h"
#include "Mayaqua/Str.h"

#include "Core/Vxlan.h"

#define	SGTEST_VRF				101			// The VRF of the records
#define	SGTEST_VNI				5101		// The VNI of the datagrams
#define	SGTEST_FRAME			64			// The frame of a datagram
#define	SGTEST_PACKET			20			// The packet of a record
#define	SGTEST_GOLDEN			"sourcegroup_carriers.txt"

// The groups of the test, their tag sets and the group generations of their senders
static UINT sgtest_groups[4] = {1, 3, 258, 65535};
static UINT64 sgtest_tags[4] = {0x1ULL, 0x4ULL, 0x0102030405060708ULL, 0xFFFFFFFFFFFFFFFFULL};
static UINT sgtest_generations[4] = {1, 7, 0x01020304, 0xFFFFFFFF};

// The fields of each carrier, in bytes, 0 for the line between the header and the option
static UINT sgtest_ranz_fields[] = {4, 1, 1, 2, 0, 1, 1, 2, 2, 2, 8, 4, 0, 4};
static UINT sgtest_vxlan_fields[] = {1, 1, 2, 3, 1};
static UINT sgtest_geneve_fields[] = {1, 1, 2, 3, 1, 0, 2, 1, 1, 2, 2, 8, 4};

// The test
typedef struct SGTEST_CTX
{
	UINT NumChecks;
	UINT NumFailed;
	BUF *Text;								// The text of the golden file
	VXLAN *Sender;							// The module that sends: its send procedure keeps the last datagram
	VXLAN *Receiver;						// The module that takes the datagrams, on SGTEST_VNI
	UCHAR Datagram[VXLAN_MAX_DATAGRAM];		// The last datagram that the sender sent ...
	UINT DatagramSize;						// ... and its size
	bool Got;								// The receiver took a frame ...
	VXLAN_GROUP Group;						// ... with this source group ...
	UCHAR Frame[SGTEST_FRAME];				// ... and this frame, as much as fits
	UINT FrameSize;
} SGTEST_CTX;

static bool SgTestCheck(SGTEST_CTX *ctx, bool ok, char *what)
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
static void SgTestLine(SGTEST_CTX *ctx, char *line)
{
	Print("  %s\n", line);
	WriteBuf(ctx->Text, line, StrLen(line));
	WriteBuf(ctx->Text, "\n", 1);
}

// The bytes of data as hexadecimal fields of the widths of fields, separated by spaces, a 0 width as a | between them
static void SgTestFields(char *out, UINT size, const UCHAR *data, UINT *fields, UINT num_fields)
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

// The send procedure of the sender: it keeps the datagram
static bool SgTestSend(void *param, const VXLAN_ADDR *dst, const void *data, UINT size)
{
	SGTEST_CTX *ctx = (SGTEST_CTX *)param;

	ctx->DatagramSize = MIN(size, sizeof(ctx->Datagram));
	Copy(ctx->Datagram, data, ctx->DatagramSize);

	return true;
}

// The send procedure of the receiver, which sends nothing
static bool SgTestNoSend(void *param, const VXLAN_ADDR *dst, const void *data, UINT size)
{
	return false;
}

// The receiver: it keeps the frame and the source group of its datagram
static void SgTestReceive(VXLAN *v, void *param, UINT vni, const VXLAN_ADDR *from, const VXLAN_GROUP *group, const UCHAR *frame, UINT size)
{
	SGTEST_CTX *ctx = (SGTEST_CTX *)param;

	ctx->Got = true;
	Copy(&ctx->Group, group, sizeof(VXLAN_GROUP));
	ctx->FrameSize = MIN(size, sizeof(ctx->Frame));
	Copy(ctx->Frame, frame, ctx->FrameSize);
}

// A tunnel endpoint of the encapsulation geneve
static void SgTestVtep(VXLAN_ADDR *a, bool geneve)
{
	VxlanAddrSetV4(a, 192, 0, 2, 1, geneve ? GENEVE_PORT : VXLAN_PORT);
	a->Encap = (geneve ? VXLAN_ENCAP_GENEVE : VXLAN_ENCAP_VXLAN);
}

// The frame of the datagrams: an Ethernet header and the bytes after it
static void SgTestFrame(UCHAR *frame)
{
	for (UINT i = 0;i < SGTEST_FRAME;i++)
	{
		frame[i] = (UCHAR)(i * 7 + 1);
	}
}

// Hand the datagram of size bytes to the ingress of the receiver, from a tunnel endpoint of the encapsulation geneve
static void SgTestInput(SGTEST_CTX *ctx, const UCHAR *datagram, UINT size, bool geneve)
{
	VXLAN_ADDR from;

	SgTestVtep(&from, geneve);
	ctx->Got = false;
	Zero(&ctx->Group, sizeof(ctx->Group));
	ctx->FrameSize = 0;
	VxlanInput(ctx->Receiver, &from, datagram, size);
}

// What the receiver read from the last datagram, as a line: the group, with its tag set and the group generation of its
// sender where it came with them, and the frame
static void SgTestRead(SGTEST_CTX *ctx, char *out, UINT size, const UCHAR *frame)
{
	if (ctx->Got == false)
	{
		StrCpy(out, size, "  read: nothing, the module dropped the datagram");
	}
	else if (ctx->Group.Carried == false)
	{
		Format(out, size, "  read: no source group; the frame of %u bytes %s", ctx->FrameSize,
			(ctx->FrameSize == SGTEST_FRAME && Cmp(ctx->Frame, frame, SGTEST_FRAME) == 0) ? "as it was sent" : "changed");
	}
	else if (ctx->Group.HasTags && ctx->Group.HasGeneration)
	{
		Format(out, size, "  read: group %u, tag set 0x%016I64x, group generation %u; the frame of %u bytes %s", (UINT)ctx->Group.Group, ctx->Group.Tags,
			ctx->Group.Generation, ctx->FrameSize, (ctx->FrameSize == SGTEST_FRAME && Cmp(ctx->Frame, frame, SGTEST_FRAME) == 0) ? "as it was sent" : "changed");
	}
	else
	{
		Format(out, size, "  read: group %u, no tag set and no group generation; the frame of %u bytes %s", (UINT)ctx->Group.Group, ctx->FrameSize,
			(ctx->FrameSize == SGTEST_FRAME && Cmp(ctx->Frame, frame, SGTEST_FRAME) == 0) ? "as it was sent" : "changed");
	}
}

// What NodeFrameParse read from a record, as a line. A record that the node drops leaves no header and no claim.
static void SgTestReadRecord(SGTEST_CTX *ctx, char *out, UINT size, const UCHAR *record, UINT record_size)
{
	NODE_SOURCE_CLAIM claim;
	UINT header = 0;

	if (NodeFrameParse(record, record_size, &claim, &header) == false)
	{
		StrCpy(out, size, "  read: not read, the node drops the record");
		SgTestCheck(ctx, header == 0 && claim.Carried == false && claim.Carrier == NODE_CARRIER_SESSION,
			"a record that the node drops leaves no header and no claim");
	}
	else if (claim.Carried == false)
	{
		Format(out, size, "  read: frame version 0, no source group; the data record of VRF %u", READ_UINT(record + header));
	}
	else
	{
		Format(out, size, "  read: group %u, tag set 0x%016I64x, group generation %u; a header of %u bytes, then the data record of VRF %u", claim.Group,
			claim.Tags, claim.Generation, header, READ_UINT(record + header));
	}
}

// The four groups in each carrier
static void SgTestGroups(SGTEST_CTX *ctx)
{
	UCHAR frame[SGTEST_FRAME];
	UCHAR record[NODE_FRAME_ROOM + NODE_OVERLAY_VRF_TAG + SGTEST_PACKET];
	char line[MAX_SIZE * 2];
	char fields[MAX_SIZE];

	SgTestFrame(frame);

	for (UINT i = 0;i < 4;i++)
	{
		VXLAN_GROUP group;
		VXLAN_ADDR vtep;
		char what[MAX_SIZE];

		Format(line, sizeof(line), "group %u, tag set 0x%016I64x, group generation %u", sgtest_groups[i], sgtest_tags[i], sgtest_generations[i]);
		SgTestLine(ctx, line);

		// The record of frame version 1: the header, then the data record of frame version 0
		Zero(record, sizeof(record));
		UINT header = NodeFrameWrite(record, sgtest_groups[i], sgtest_tags[i], sgtest_generations[i]);
		WRITE_UINT(record + header, SGTEST_VRF);
		SgTestFields(fields, sizeof(fields), record, sgtest_ranz_fields, sizeof(sgtest_ranz_fields) / sizeof(sgtest_ranz_fields[0]));
		Format(line, sizeof(line), "  ranz frame: %s", fields);
		SgTestLine(ctx, line);
		SgTestReadRecord(ctx, line, sizeof(line), record, sizeof(record));
		SgTestLine(ctx, line);

		Zero(&group, sizeof(group));
		group.Carried = true;
		group.HasTags = true;
		group.HasGeneration = true;
		group.Group = (USHORT)sgtest_groups[i];
		group.Tags = sgtest_tags[i];
		group.Generation = sgtest_generations[i];

		// VXLAN: the group ID alone
		SgTestVtep(&vtep, false);
		ctx->DatagramSize = 0;
		bool sent = VxlanSendToGroup(ctx->Sender, SGTEST_VNI, &vtep, &group, frame, SGTEST_FRAME);
		SgTestFields(fields, sizeof(fields), ctx->Datagram, sgtest_vxlan_fields, sizeof(sgtest_vxlan_fields) / sizeof(sgtest_vxlan_fields[0]));
		Format(line, sizeof(line), "  vxlan: %s", fields);
		SgTestLine(ctx, line);
		SgTestInput(ctx, ctx->Datagram, ctx->DatagramSize, false);
		SgTestRead(ctx, line, sizeof(line), frame);
		SgTestLine(ctx, line);
		Format(what, sizeof(what), "group %u: the module sent a datagram of VXLAN of %u bytes", sgtest_groups[i], VXLAN_HEADER_SIZE + SGTEST_FRAME);
		SgTestCheck(ctx, sent && ctx->DatagramSize == VXLAN_HEADER_SIZE + SGTEST_FRAME, what);

		// Geneve: the group ID, the tag set and the group generation in the option
		SgTestVtep(&vtep, true);
		ctx->DatagramSize = 0;
		sent = VxlanSendToGroup(ctx->Sender, SGTEST_VNI, &vtep, &group, frame, SGTEST_FRAME);
		SgTestFields(fields, sizeof(fields), ctx->Datagram, sgtest_geneve_fields, sizeof(sgtest_geneve_fields) / sizeof(sgtest_geneve_fields[0]));
		Format(line, sizeof(line), "  geneve: %s", fields);
		SgTestLine(ctx, line);
		SgTestInput(ctx, ctx->Datagram, ctx->DatagramSize, true);
		SgTestRead(ctx, line, sizeof(line), frame);
		SgTestLine(ctx, line);
		bool clear = ((ctx->Datagram[GENEVE_HEADER_SIZE + 2] & GENEVE_OPTION_CRITICAL) == 0 && (ctx->Datagram[1] & GENEVE_FLAG_CRITICAL) == 0);
		SgTestLine(ctx, clear ? "  the critical bit of the option of Geneve is clear, and so is the C bit of its header" : "  the critical bit of the option of Geneve or the C bit of its header is SET");
		Format(what, sizeof(what), "group %u: the module sent a datagram of Geneve of %u bytes, whose option has its critical bit clear", sgtest_groups[i],
			GENEVE_HEADER_SIZE + GENEVE_GROUP_OPTION + SGTEST_FRAME);
		SgTestCheck(ctx, sent && clear && ctx->DatagramSize == GENEVE_HEADER_SIZE + GENEVE_GROUP_OPTION + SGTEST_FRAME, what);
	}
}

// The records that a node does not take, or reads otherwise, and the datagrams of a peer that carry no source group, or
// options that the module does not know
static void SgTestOthers(SGTEST_CTX *ctx)
{
	UCHAR frame[SGTEST_FRAME];
	UCHAR record[64];
	UCHAR datagram[GENEVE_HEADER_SIZE + 8 + GENEVE_GROUP_OPTION + SGTEST_FRAME];
	char line[MAX_SIZE * 2];
	VXLAN_ADDR vtep;
	VXLAN_STATS before, after;

	SgTestFrame(frame);

	// A record of frame version 0
	Zero(record, sizeof(record));
	WRITE_UINT(record, SGTEST_VRF);
	SgTestLine(ctx, "a record of frame version 0, the data record of VRF 101");
	SgTestReadRecord(ctx, line, sizeof(line), record, NODE_OVERLAY_VRF_TAG + SGTEST_PACKET);
	SgTestLine(ctx, line);

	// Frame version 2
	Zero(record, sizeof(record));
	record[4] = 2;
	WRITE_UINT(record + NODE_FRAME_HEADER, SGTEST_VRF);
	SgTestLine(ctx, "a record of frame version 2, which no node knows yet");
	SgTestReadRecord(ctx, line, sizeof(line), record, NODE_FRAME_HEADER + NODE_OVERLAY_VRF_TAG + SGTEST_PACKET);
	SgTestLine(ctx, line);

	// Options that run past the record
	Zero(record, sizeof(record));
	record[4] = NODE_FRAME_VERSION;
	record[5] = 4;
	record[NODE_FRAME_HEADER] = NODE_FRAME_GROUP;
	record[NODE_FRAME_HEADER + 1] = NODE_FRAME_GROUP_DATA / 4;
	SgTestLine(ctx, "a record of frame version 1 whose options run past its end");
	SgTestReadRecord(ctx, line, sizeof(line), record, NODE_FRAME_HEADER + 4);
	SgTestLine(ctx, line);

	// The option of the source group, then an option whose data runs past the options: the record is dropped, and the
	// claim of the first option does not stay behind (a crash input of fuzz_frame)
	Zero(record, sizeof(record));
	record[4] = NODE_FRAME_VERSION;
	record[5] = 6;
	record[NODE_FRAME_HEADER] = NODE_FRAME_GROUP;
	record[NODE_FRAME_HEADER + 1] = NODE_FRAME_GROUP_DATA / 4;
	WRITE_USHORT(record + NODE_FRAME_HEADER + 4, 5);
	WRITE_UINT64(record + NODE_FRAME_HEADER + 8, 0x10);
	WRITE_UINT(record + NODE_FRAME_HEADER + 16, 9);
	record[NODE_FRAME_HEADER + 20] = 0x02;
	record[NODE_FRAME_HEADER + 21] = 4;
	WRITE_UINT(record + NODE_FRAME_HEADER + 24, SGTEST_VRF);
	SgTestLine(ctx, "a record of frame version 1 with the option of the source group, then an option whose data runs past the options");
	SgTestReadRecord(ctx, line, sizeof(line), record, NODE_FRAME_HEADER + 24 + NODE_OVERLAY_VRF_TAG + SGTEST_PACKET);
	SgTestLine(ctx, line);

	// An option that the node does not know, with its critical bit set
	Zero(record, sizeof(record));
	record[4] = NODE_FRAME_VERSION;
	record[5] = 1;
	record[NODE_FRAME_HEADER] = 0x82;
	WRITE_UINT(record + NODE_FRAME_HEADER + 4, SGTEST_VRF);
	SgTestLine(ctx, "a record of frame version 1 with an option of the type 0x82, critical, that the node does not know");
	SgTestReadRecord(ctx, line, sizeof(line), record, NODE_FRAME_HEADER + 4 + NODE_OVERLAY_VRF_TAG + SGTEST_PACKET);
	SgTestLine(ctx, line);

	// An option that the node does not know, with its critical bit clear and no data, before the option of the source group
	Zero(record, sizeof(record));
	record[4] = NODE_FRAME_VERSION;
	record[5] = 6;
	record[NODE_FRAME_HEADER] = 0x02;
	record[NODE_FRAME_HEADER + 4] = NODE_FRAME_GROUP;
	record[NODE_FRAME_HEADER + 5] = NODE_FRAME_GROUP_DATA / 4;
	WRITE_USHORT(record + NODE_FRAME_HEADER + 8, 7);
	WRITE_UINT64(record + NODE_FRAME_HEADER + 12, 0x80);
	WRITE_UINT(record + NODE_FRAME_HEADER + 20, 9);
	WRITE_UINT(record + NODE_FRAME_HEADER + 24, SGTEST_VRF);
	SgTestLine(ctx, "a record of frame version 1 with an option of the type 0x02 that the node does not know, then the option of the source group");
	SgTestReadRecord(ctx, line, sizeof(line), record, NODE_FRAME_HEADER + 24 + NODE_OVERLAY_VRF_TAG + SGTEST_PACKET);
	SgTestLine(ctx, line);

	// VXLAN without the G flag
	SgTestVtep(&vtep, false);
	ctx->DatagramSize = 0;
	VxlanSendTo(ctx->Sender, SGTEST_VNI, &vtep, frame, SGTEST_FRAME);
	SgTestLine(ctx, "a datagram of VXLAN without the G flag");
	SgTestInput(ctx, ctx->Datagram, ctx->DatagramSize, false);
	SgTestRead(ctx, line, sizeof(line), frame);
	SgTestLine(ctx, line);

	// Geneve with the option of the source group whose critical bit is set: an option that the module does not know
	Zero(datagram, sizeof(datagram));
	VxlanWriteGeneve(datagram, SGTEST_VNI);
	datagram[0] |= (UCHAR)(GENEVE_GROUP_OPTION / 4);
	VxlanWriteGroupOption(datagram + GENEVE_HEADER_SIZE, 7, 0x80, 9);
	datagram[GENEVE_HEADER_SIZE + 2] |= GENEVE_OPTION_CRITICAL;
	Copy(datagram + GENEVE_HEADER_SIZE + GENEVE_GROUP_OPTION, frame, SGTEST_FRAME);
	VxlanGetStats(ctx->Receiver, &before);
	SgTestLine(ctx, "a datagram of Geneve with the option of the source group whose critical bit is set");
	SgTestInput(ctx, datagram, GENEVE_HEADER_SIZE + GENEVE_GROUP_OPTION + SGTEST_FRAME, true);
	SgTestRead(ctx, line, sizeof(line), frame);
	SgTestLine(ctx, line);
	VxlanGetStats(ctx->Receiver, &after);
	SgTestCheck(ctx, ctx->Got == false && after.Drops[VXLAN_DROP_CRITICAL] == before.Drops[VXLAN_DROP_CRITICAL] + 1,
		"the datagram of Geneve whose option of the source group is critical is dropped as a critical option that the module does not know, and counted");

	// Geneve with an option of another class before the option of the source group
	Zero(datagram, sizeof(datagram));
	VxlanWriteGeneve(datagram, SGTEST_VNI);
	datagram[0] |= (UCHAR)((8 + GENEVE_GROUP_OPTION) / 4);
	datagram[GENEVE_HEADER_SIZE] = 0x01;
	datagram[GENEVE_HEADER_SIZE + 1] = 0x03;
	datagram[GENEVE_HEADER_SIZE + 2] = 0x05;
	datagram[GENEVE_HEADER_SIZE + 3] = 1;
	VxlanWriteGroupOption(datagram + GENEVE_HEADER_SIZE + 8, 7, 0x80, 9);
	Copy(datagram + GENEVE_HEADER_SIZE + 8 + GENEVE_GROUP_OPTION, frame, SGTEST_FRAME);
	SgTestLine(ctx, "a datagram of Geneve with an option of the class 0x0103, then the option of the source group");
	SgTestInput(ctx, datagram, sizeof(datagram), true);
	SgTestRead(ctx, line, sizeof(line), frame);
	SgTestLine(ctx, line);
}

// One size of a record and of the payload of its path, and whether the record goes with the header of frame version 1
typedef struct SGTEST_SIZE
{
	UINT Max;							// The largest payload of the path
	UINT Size;							// The record
	bool Wrapped;						// It goes with the header
	char *What;
} SGTEST_SIZE;

static SGTEST_SIZE sgtest_sizes[] =
{
	{PEER_MAX_PAYLOAD, PEER_MAX_PAYLOAD - NODE_FRAME_ROOM, true, "the datagram path of the peer agent: the largest record that fits its payload with the header goes with it"},
	{PEER_MAX_PAYLOAD, PEER_MAX_PAYLOAD - NODE_FRAME_ROOM + 1, false, "the datagram path: a record one byte larger goes as it is, of frame version 0, as it went before the source groups"},
	{PEER_MAX_PAYLOAD, PEER_MAX_PAYLOAD, false, "the datagram path: the largest record that fits its payload goes as it is"},
	{NOISE_MAX_PAYLOAD, PEER_MAX_PAYLOAD, true, "a Noise session: that record goes with the header, as the payload of a session is larger"},
	{NOISE_MAX_PAYLOAD, NOISE_MAX_PAYLOAD - NODE_FRAME_ROOM + 1, false, "a Noise session: a record that does not fit its payload with the header goes as it is"},
};

// The sizes: the source group costs no packet that went before it. A record that does not fit the payload of its path with
// the header of frame version 1 goes as it is (NodeSourceGroupWrap), and a frame that does not fit a datagram of Geneve
// with the option of the source group goes without it (VxlanSendToGroup); the peer judges either by the map of address to
// group. Checks only, which the golden file does not hold.
static void SgTestSizes(SGTEST_CTX *ctx)
{
	NODE *n = ZeroMalloc(sizeof(NODE));
	NODE_VRF_TABLES *v = ZeroMalloc(sizeof(NODE_VRF_TABLES));
	CONTROL_STATE *st = ZeroMalloc(sizeof(CONTROL_STATE));
	CONTROL_PEER *p = ZeroMalloc(sizeof(CONTROL_PEER));
	UCHAR *room = ZeroMalloc(NODE_FRAME_ROOM + NOISE_MAX_PAYLOAD);
	UCHAR *record = room + NODE_FRAME_ROOM;
	UCHAR *frame = ZeroMalloc(VXLAN_MAX_FRAME);
	char what[MAX_SIZE];
	VXLAN_GROUP group;
	VXLAN_ADDR vtep;

	// The source groups of a node whose own group in VRF 101 is 3, of the group generation 5, and whose one peer takes
	// records of frame version 1
	st->NumVrfs = 1;
	st->Vrfs[0].Id = SGTEST_VRF;
	st->NumGroups = 1;
	st->Groups[0].VrfId = SGTEST_VRF;
	st->Groups[0].Group = 3;
	st->Groups[0].TagSet = 0x4ULL;
	st->Groups[0].Generation = 5;
	StrCpy(p->Name, sizeof(p->Name), "node-b");
	p->FrameVersion = NODE_FRAME_VERSION;
	st->NumPeers = 1;
	st->Peers = p;
	NodeSourceGroupAttach(n, v, st);

	// The record of a packet of IPv4 of the host in VRF 101, after the room of the header
	WRITE_UINT(record, SGTEST_VRF);
	record[NODE_OVERLAY_VRF_TAG] = 0x45;
	for (UINT i = 0;i < sizeof(sgtest_sizes) / sizeof(sgtest_sizes[0]);i++)
	{
		SGTEST_SIZE *c = &sgtest_sizes[i];
		UINT size = c->Size;
		const UCHAR *start = NodeSourceGroupWrap(v, 0, SGTEST_VRF, record, &size, c->Max);
		bool ok = (c->Wrapped ? (start == room && size == c->Size + NODE_FRAME_ROOM && size <= c->Max) : (start == record && size == c->Size));

		Format(what, sizeof(what), "%s (a record of %u bytes, a payload of %u)", c->What, c->Size, c->Max);
		SgTestCheck(ctx, ok, what);
	}

	// The header names the group, the tag set and the group generation of the node
	NODE_SOURCE_CLAIM claim;
	UINT header = 0;
	UINT size = NODE_OVERLAY_VRF_TAG + SGTEST_PACKET;
	const UCHAR *start = NodeSourceGroupWrap(v, 0, SGTEST_VRF, record, &size, NOISE_MAX_PAYLOAD);
	SgTestCheck(ctx, NodeFrameParse(start, size, &claim, &header) && claim.Carried && claim.Group == 3 && claim.Tags == 0x4ULL && claim.HasGeneration &&
		claim.Generation == 5 && header == NODE_FRAME_ROOM, "the header of a record names the group 3, its tag set and the group generation 5 of the node");

	// Geneve: the largest frame that fits a datagram with the option goes with it, and the largest one that fits without the
	// option goes without it
	Zero(&group, sizeof(group));
	group.Carried = true;
	group.HasTags = true;
	group.Group = 3;
	group.Tags = 0x4ULL;
	SgTestVtep(&vtep, true);
	SgTestFrame(frame);

	UINT with = VXLAN_MAX_DATAGRAM - GENEVE_HEADER_SIZE - GENEVE_GROUP_OPTION;
	ctx->DatagramSize = 0;
	bool sent = VxlanSendToGroup(ctx->Sender, SGTEST_VNI, &vtep, &group, frame, with);
	SgTestInput(ctx, ctx->Datagram, ctx->DatagramSize, true);
	Format(what, sizeof(what), "geneve: the largest frame that fits a datagram with the option of the source group, %u bytes, goes with it", with);
	SgTestCheck(ctx, sent && ctx->DatagramSize == VXLAN_MAX_DATAGRAM && ctx->Got && ctx->Group.Carried && ctx->Group.Group == 3, what);

	ctx->DatagramSize = 0;
	sent = VxlanSendToGroup(ctx->Sender, SGTEST_VNI, &vtep, &group, frame, VXLAN_MAX_FRAME);
	SgTestInput(ctx, ctx->Datagram, ctx->DatagramSize, true);
	Format(what, sizeof(what), "geneve: a frame of %u bytes, the largest that a datagram takes without the option, goes without it, as it went before the source groups",
		VXLAN_MAX_FRAME);
	SgTestCheck(ctx, sent && ctx->DatagramSize == GENEVE_HEADER_SIZE + VXLAN_MAX_FRAME && (ctx->Datagram[0] & 0x3F) == 0 && ctx->Got && ctx->Group.Carried == false, what);

	NodeFreeSourceGroupTable(v->SourceGroups);
	Free(frame);
	Free(room);
	Free(p);
	Free(st);
	Free(v);
	Free(n);
}

// sourcegroup: the source group in each carrier
RANZ_TEST_TAGS("sourcegroup", sourcegroup_test, "core", "Source group carriers (SDN-87): the group ID and the tag set in the record of frame version 1 of a Noise session, the group policy extension of VXLAN and the option of Geneve, sent and read back (golden family sourcegroup); the critical bit of the option of Geneve is clear.");
void sourcegroup_test(UINT num, char **arg)
{
	SGTEST_CTX *ctx = ZeroMalloc(sizeof(SGTEST_CTX));
	char out_dir[MAX_SIZE];
	char golden_dir[MAX_SIZE];
	bool update;
	HARNESS h;

	Print("Source group carrier test: the group ID and the tag set of a packet in each of its carriers\n");

	ctx->Text = NewBuf();
	ctx->Sender = VxlanNew(SgTestSend, ctx, NULL, NULL);
	ctx->Receiver = VxlanNew(SgTestNoSend, NULL, NULL, ctx);
	if (SgTestCheck(ctx, ctx->Sender != NULL && ctx->Receiver != NULL && VxlanSetVni(ctx->Receiver, SGTEST_VNI, NULL, 0), "Two VXLAN modules, one that sends and one that takes VNI 5101"))
	{
		VxlanSetGroupReceiver(ctx->Receiver, SgTestReceive);

		SgTestLine(ctx, "# SDN-87: the source group in each carrier, as a node sends it and as a node reads it back");
		SgTestLine(ctx, "# ranz frame: the VRF tag 0, the version, the length of the options, reserved | the type, the length, reserved, the group, reserved, the tag set, the group generation | the VRF tag of the record");
		SgTestLine(ctx, "# vxlan: the flags, the flags D and A, the group, the VNI, reserved");
		SgTestLine(ctx, "# geneve: the version and the length of the options, the flags O and C, the protocol, the VNI, reserved | the class, the type, the length, the group, reserved, the tag set, the group generation");
		SgTestGroups(ctx);
		SgTestOthers(ctx);
		SgTestSizes(ctx);
	}

	char *text = HarnessBufToStr(ctx->Text);

	HarnessGetFamilyDirs("sourcegroup", out_dir, sizeof(out_dir), golden_dir, sizeof(golden_dir), &update);
	MakeDirEx(out_dir);
	Print("[golden]\n");
	Print("SOURCEGROUP GOLDEN MODE %s\n", update ? "update" : "compare");
	Print("  golden directory: %s\n", golden_dir);
	Zero(&h, sizeof(h));
	HarnessCompareGolden(&h, out_dir, golden_dir, SGTEST_GOLDEN, text, update);
	SgTestCheck(ctx, h.NumFail == 0, "The carriers match the golden file " SGTEST_GOLDEN);

	Free(text);
	FreeBuf(ctx->Text);
	VxlanFree(ctx->Sender);
	VxlanFree(ctx->Receiver);

	if (ctx->NumFailed == 0)
	{
		Print("SOURCEGROUP TEST OK\n");
	}
	else
	{
		Print("SOURCEGROUP TEST FAILED (%u of %u checks failed)\n", ctx->NumFailed, ctx->NumChecks);
	}

	Free(ctx);
}
