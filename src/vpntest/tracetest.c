// tracetest.c
// Named trace option carrier test of vpntest ("traceoption" command, SDN-89 #388; "trace" is the ETW test of runtime.c)
//
// The encoding and the decoding of the trace option, the trace ID of a packet and its ingress node, in each of its
// carriers: the header of a record of frame version 1 of a Noise session (Cedar/NodeTrace.c: NodeTraceWrite,
// NodeTraceWrap, NodeTraceParse), alone and after the option of the source group, and the trace option of Geneve, alone
// and after the option of the source group (Core/VxlanTrace.c), as the VXLAN module sends it (VxlanSendToGroup) and reads
// it at its one ingress (VxlanInput); the VXLAN header has no room for it, so a datagram of VXLAN goes without it. For each
// of three traces the test prints the bytes of each carrier field by field and what a node reads back from them, and what
// the parser of a node that does not know the option reads: NodeFrameParse, which knows the option of the source group
// alone, takes the record, and a VXLAN module takes a datagram whose option it does not know, as the critical bit of the
// option is clear. Then the records and the datagrams that a node drops or reads otherwise. Last, the trace of a Network
// on and off at the ingress node (NodeTraceOutbound): with the trace of no Network on, no option goes and the record keeps
// its size; with it on, a packet of the pools of the Network goes with the option, and the node records it. The text
// matches the golden file tests/golden/trace/trace_carriers.txt (golden family "trace"). Print "TRACEOPTION TEST OK" only
// when every check passes.

#include "harness_int.h"
#include "testlist.h"

#include "Cedar/Node.h"
#include "Cedar/NodeSourceGroup.h"
#include "Cedar/NodeTrace.h"

#include "Mayaqua/FileIO.h"
#include "Mayaqua/Memory.h"
#include "Mayaqua/Str.h"
#include "Mayaqua/Tick64.h"

#include "Core/Control.h"
#include "Core/Vxlan.h"

#define	TRTEST_VRF				101			// The VRF of the records
#define	TRTEST_VNI				5101		// The VNI of the datagrams
#define	TRTEST_FRAME			64			// The frame of a datagram
#define	TRTEST_PACKET			20			// The packet of a record: an IPv4 header
#define	TRTEST_GROUP			3			// The source group of the records and datagrams that carry one ...
#define	TRTEST_TAGS				0x4ULL		// ... its tag set ...
#define	TRTEST_GENERATION		5			// ... and the group generation of its sender
#define	TRTEST_GOLDEN			"trace_carriers.txt"
#define	TRTEST_RECORD			(NODE_OVERLAY_VRF_TAG + TRTEST_PACKET)

// The traces of the test: their trace IDs and their ingress nodes
static UINT trtest_ids[3] = {1, 0x2A, 0xFFFFFFFF};
static UCHAR trtest_ingress[3][VXLAN_TRACE_INGRESS] =
{
	{0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18},
	{0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7},
	{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF},
};

// The fields of each carrier, in bytes, 0 for the line between the header and an option
static UINT trtest_ranz_fields[] = {4, 1, 1, 2, 0, 1, 1, 2, 4, 8, 0, 4};
static UINT trtest_ranz_group_fields[] = {4, 1, 1, 2, 0, 1, 1, 2, 2, 2, 8, 4, 0, 1, 1, 2, 4, 8, 0, 4};
static UINT trtest_geneve_fields[] = {1, 1, 2, 3, 1, 0, 2, 1, 1, 4, 8};
static UINT trtest_geneve_group_fields[] = {1, 1, 2, 3, 1, 0, 2, 1, 1, 2, 2, 8, 4, 0, 2, 1, 1, 4, 8};
static UINT trtest_vxlan_fields[] = {1, 1, 2, 3, 1};

// The test
typedef struct TRTEST_CTX
{
	UINT NumChecks;
	UINT NumFailed;
	BUF *Text;								// The text of the golden file
	VXLAN *Sender;							// The module that sends: its send procedure keeps the last datagram
	VXLAN *Receiver;						// The module that takes the datagrams, on TRTEST_VNI
	UCHAR Datagram[VXLAN_MAX_DATAGRAM];		// The last datagram that the sender sent ...
	UINT DatagramSize;						// ... and its size
	bool Got;								// The receiver took a frame ...
	VXLAN_GROUP Group;						// ... with this source group and trace option ...
	UCHAR Frame[TRTEST_FRAME];				// ... and this frame, as much as fits
	UINT FrameSize;
} TRTEST_CTX;

static bool TrTestCheck(TRTEST_CTX *ctx, bool ok, char *what)
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
static void TrTestLine(TRTEST_CTX *ctx, char *line)
{
	Print("  %s\n", line);
	WriteBuf(ctx->Text, line, StrLen(line));
	WriteBuf(ctx->Text, "\n", 1);
}

// The bytes of data as hexadecimal fields of the widths of fields, separated by spaces, a 0 width as a | between them
static void TrTestFields(char *out, UINT size, const UCHAR *data, UINT *fields, UINT num_fields)
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

// The bytes of the ingress node of a trace as hexadecimal
static void TrTestIngress(char *out, UINT size, const UCHAR *ingress)
{
	StrCpy(out, size, "");
	for (UINT i = 0;i < VXLAN_TRACE_INGRESS;i++)
	{
		char hex[3];

		Format(hex, sizeof(hex), "%02x", (UINT)ingress[i]);
		StrCat(out, size, hex);
	}
}

// The send procedure of the sender: it keeps the datagram
static bool TrTestSend(void *param, const VXLAN_ADDR *dst, const void *data, UINT size)
{
	TRTEST_CTX *ctx = (TRTEST_CTX *)param;

	ctx->DatagramSize = MIN(size, sizeof(ctx->Datagram));
	Copy(ctx->Datagram, data, ctx->DatagramSize);

	return true;
}

// The send procedure of the receiver, which sends nothing
static bool TrTestNoSend(void *param, const VXLAN_ADDR *dst, const void *data, UINT size)
{
	return false;
}

// The receiver: it keeps the frame and the source group and the trace option of its datagram
static void TrTestReceive(VXLAN *v, void *param, UINT vni, const VXLAN_ADDR *from, const VXLAN_GROUP *group, const UCHAR *frame, UINT size)
{
	TRTEST_CTX *ctx = (TRTEST_CTX *)param;

	ctx->Got = true;
	Copy(&ctx->Group, group, sizeof(VXLAN_GROUP));
	ctx->FrameSize = MIN(size, sizeof(ctx->Frame));
	Copy(ctx->Frame, frame, ctx->FrameSize);
}

// A tunnel endpoint of the encapsulation geneve
static void TrTestVtep(VXLAN_ADDR *a, bool geneve)
{
	VxlanAddrSetV4(a, 192, 0, 2, 1, geneve ? GENEVE_PORT : VXLAN_PORT);
	a->Encap = (geneve ? VXLAN_ENCAP_GENEVE : VXLAN_ENCAP_VXLAN);
}

// The frame of the datagrams: an Ethernet header and the bytes after it
static void TrTestFrame(UCHAR *frame)
{
	for (UINT i = 0;i < TRTEST_FRAME;i++)
	{
		frame[i] = (UCHAR)(i * 7 + 1);
	}
}

// The data record of VRF TRTEST_VRF at record: the VRF tag and the IPv4 header of a packet from src to dst, 10.0.0.<src>
// to 10.0.0.<dst>, or from 192.168.1.<src> to 192.168.1.<dst> when outside is set, an address of no pool of the test
static void TrTestRecord(UCHAR *record, UCHAR src, UCHAR dst, bool outside)
{
	Zero(record, TRTEST_RECORD);
	WRITE_UINT(record, TRTEST_VRF);
	record[NODE_OVERLAY_VRF_TAG] = 0x45;
	record[NODE_OVERLAY_VRF_TAG + 9] = 17;
	record[NODE_OVERLAY_VRF_TAG + 12] = (outside ? 192 : 10);
	record[NODE_OVERLAY_VRF_TAG + 13] = (outside ? 168 : 0);
	record[NODE_OVERLAY_VRF_TAG + 14] = (outside ? 1 : 0);
	record[NODE_OVERLAY_VRF_TAG + 15] = src;
	record[NODE_OVERLAY_VRF_TAG + 16] = (outside ? 192 : 10);
	record[NODE_OVERLAY_VRF_TAG + 17] = (outside ? 168 : 0);
	record[NODE_OVERLAY_VRF_TAG + 18] = (outside ? 1 : 0);
	record[NODE_OVERLAY_VRF_TAG + 19] = dst;
}

// Hand the datagram of size bytes to the ingress of the receiver, from a tunnel endpoint of the encapsulation geneve
static void TrTestInput(TRTEST_CTX *ctx, const UCHAR *datagram, UINT size, bool geneve)
{
	VXLAN_ADDR from;

	TrTestVtep(&from, geneve);
	ctx->Got = false;
	Zero(&ctx->Group, sizeof(ctx->Group));
	ctx->FrameSize = 0;
	VxlanInput(ctx->Receiver, &from, datagram, size);
}

// What the receiver read from the last datagram, as a line: the trace option, the source group and the frame
static void TrTestRead(TRTEST_CTX *ctx, char *out, UINT size, const UCHAR *frame)
{
	char trace[MAX_SIZE];
	char group[MAX_SIZE];
	char ingress[VXLAN_TRACE_INGRESS * 2 + 1];

	if (ctx->Got == false)
	{
		StrCpy(out, size, "  read: nothing, the module dropped the datagram");
		return;
	}

	if (ctx->Group.Trace.Traced)
	{
		TrTestIngress(ingress, sizeof(ingress), ctx->Group.Trace.Ingress);
		Format(trace, sizeof(trace), "trace 0x%08x of the ingress node %s", ctx->Group.Trace.Id, ingress);
	}
	else
	{
		StrCpy(trace, sizeof(trace), "no trace option");
	}
	if (ctx->Group.Carried)
	{
		Format(group, sizeof(group), "group %u", (UINT)ctx->Group.Group);
	}
	else
	{
		StrCpy(group, sizeof(group), "no source group");
	}

	Format(out, size, "  read: %s, %s; the frame of %u bytes %s", trace, group, ctx->FrameSize,
		(ctx->FrameSize == TRTEST_FRAME && Cmp(ctx->Frame, frame, TRTEST_FRAME) == 0) ? "as it was sent" : "changed");
}

// What a node reads from a record of size bytes at record, as two lines: the trace option (NodeTraceParse), and what the
// parser of the header of a node reads (NodeFrameParse), which knows the option of the source group alone, as a node
// that does not know the trace option reads it
static void TrTestReadRecord(char *trace_line, char *frame_line, UINT size, const UCHAR *record, UINT record_size)
{
	NODE_SOURCE_CLAIM claim;
	VXLAN_TRACE trace;
	UINT header = 0;
	char ingress[VXLAN_TRACE_INGRESS * 2 + 1];
	bool taken = NodeFrameParse(record, record_size, &claim, &header);

	if (NodeTraceParse(record, record_size, &trace))
	{
		TrTestIngress(ingress, sizeof(ingress), trace.Ingress);
		Format(trace_line, size, "  read: trace 0x%08x of the ingress node %s; a header of %u bytes, then the data record of VRF %u", trace.Id, ingress, header,
			READ_UINT(record + header));
	}
	else
	{
		StrCpy(trace_line, size, "  read: no trace");
	}

	if (taken == false)
	{
		StrCpy(frame_line, size, "  a node that does not know the option drops the record");
	}
	else if (claim.Carried)
	{
		Format(frame_line, size, "  a node that does not know the option takes the record with the group %u; a header of %u bytes, then the data record of VRF %u",
			claim.Group, header, READ_UINT(record + header));
	}
	else
	{
		Format(frame_line, size, "  a node that does not know the option takes the record without a source group; a header of %u bytes, then the data record of VRF %u",
			header, READ_UINT(record + header));
	}
}

// The three traces in each carrier
static void TrTestTraces(TRTEST_CTX *ctx)
{
	UCHAR frame[TRTEST_FRAME];
	UCHAR buf[NODE_TRACE_ROOM + TRTEST_RECORD];
	UCHAR *record = buf + NODE_TRACE_ROOM;
	char line[MAX_SIZE * 2];
	char line2[MAX_SIZE * 2];
	char fields[MAX_SIZE];
	char ingress[VXLAN_TRACE_INGRESS * 2 + 1];
	char what[MAX_SIZE];

	TrTestFrame(frame);

	for (UINT i = 0;i < 3;i++)
	{
		VXLAN_TRACE trace;
		VXLAN_GROUP group;
		VXLAN_ADDR vtep;

		Zero(&trace, sizeof(trace));
		trace.Traced = true;
		trace.Id = trtest_ids[i];
		Copy(trace.Ingress, trtest_ingress[i], VXLAN_TRACE_INGRESS);
		TrTestIngress(ingress, sizeof(ingress), trace.Ingress);
		Format(line, sizeof(line), "trace 0x%08x of the ingress node %s", trace.Id, ingress);
		TrTestLine(ctx, line);

		// The record of frame version 0 becomes one of frame version 1 with the trace option alone
		Zero(buf, sizeof(buf));
		TrTestRecord(record, 1, 2, false);
		UINT size = TRTEST_RECORD;
		const UCHAR *start = NodeTraceWrap(record, record, &size, NOISE_MAX_PAYLOAD, &trace);
		TrTestFields(fields, sizeof(fields), start, trtest_ranz_fields, sizeof(trtest_ranz_fields) / sizeof(trtest_ranz_fields[0]));
		Format(line, sizeof(line), "  ranz frame: %s", fields);
		TrTestLine(ctx, line);
		TrTestReadRecord(line, line2, sizeof(line), start, size);
		TrTestLine(ctx, line);
		TrTestLine(ctx, line2);
		Format(what, sizeof(what), "trace %u: the record of frame version 0 goes with the header of frame version 1 and the trace option, %u bytes", trace.Id,
			TRTEST_RECORD + NODE_FRAME_HEADER + NODE_FRAME_TRACE_OPTION);
		TrTestCheck(ctx, start == record - NODE_FRAME_HEADER - NODE_FRAME_TRACE_OPTION && size == TRTEST_RECORD + NODE_FRAME_HEADER + NODE_FRAME_TRACE_OPTION, what);

		// The record of frame version 1 with the source group: the trace option follows the option of the source group
		Zero(buf, sizeof(buf));
		TrTestRecord(record, 1, 2, false);
		NodeFrameWrite(record - NODE_FRAME_ROOM, TRTEST_GROUP, TRTEST_TAGS, TRTEST_GENERATION);
		size = NODE_FRAME_ROOM + TRTEST_RECORD;
		start = NodeTraceWrap(record, record - NODE_FRAME_ROOM, &size, NOISE_MAX_PAYLOAD, &trace);
		TrTestFields(fields, sizeof(fields), start, trtest_ranz_group_fields, sizeof(trtest_ranz_group_fields) / sizeof(trtest_ranz_group_fields[0]));
		Format(line, sizeof(line), "  ranz frame with the source group: %s", fields);
		TrTestLine(ctx, line);
		TrTestReadRecord(line, line2, sizeof(line), start, size);
		TrTestLine(ctx, line);
		TrTestLine(ctx, line2);
		Format(what, sizeof(what), "trace %u: the record of frame version 1 with the source group goes with the trace option after it, %u bytes", trace.Id,
			TRTEST_RECORD + NODE_TRACE_ROOM);
		TrTestCheck(ctx, start == buf && size == TRTEST_RECORD + NODE_TRACE_ROOM, what);

		// Geneve: the trace option alone, then after the option of the source group
		Zero(&group, sizeof(group));
		Copy(&group.Trace, &trace, sizeof(VXLAN_TRACE));
		TrTestVtep(&vtep, true);
		ctx->DatagramSize = 0;
		bool sent = VxlanSendToGroup(ctx->Sender, TRTEST_VNI, &vtep, &group, frame, TRTEST_FRAME);
		TrTestFields(fields, sizeof(fields), ctx->Datagram, trtest_geneve_fields, sizeof(trtest_geneve_fields) / sizeof(trtest_geneve_fields[0]));
		Format(line, sizeof(line), "  geneve: %s", fields);
		TrTestLine(ctx, line);
		TrTestInput(ctx, ctx->Datagram, ctx->DatagramSize, true);
		TrTestRead(ctx, line, sizeof(line), frame);
		TrTestLine(ctx, line);
		Format(what, sizeof(what), "trace %u: the module sent a datagram of Geneve of %u bytes with the trace option alone", trace.Id,
			GENEVE_HEADER_SIZE + GENEVE_TRACE_OPTION + TRTEST_FRAME);
		TrTestCheck(ctx, sent && ctx->DatagramSize == GENEVE_HEADER_SIZE + GENEVE_TRACE_OPTION + TRTEST_FRAME && ctx->Got && ctx->Group.Trace.Traced &&
			ctx->Group.Trace.Id == trace.Id && Cmp(ctx->Group.Trace.Ingress, trace.Ingress, VXLAN_TRACE_INGRESS) == 0, what);

		group.Carried = true;
		group.HasTags = true;
		group.HasGeneration = true;
		group.Group = TRTEST_GROUP;
		group.Tags = TRTEST_TAGS;
		group.Generation = TRTEST_GENERATION;
		ctx->DatagramSize = 0;
		sent = VxlanSendToGroup(ctx->Sender, TRTEST_VNI, &vtep, &group, frame, TRTEST_FRAME);
		TrTestFields(fields, sizeof(fields), ctx->Datagram, trtest_geneve_group_fields, sizeof(trtest_geneve_group_fields) / sizeof(trtest_geneve_group_fields[0]));
		Format(line, sizeof(line), "  geneve with the source group: %s", fields);
		TrTestLine(ctx, line);
		TrTestInput(ctx, ctx->Datagram, ctx->DatagramSize, true);
		TrTestRead(ctx, line, sizeof(line), frame);
		TrTestLine(ctx, line);
		bool clear = ((ctx->Datagram[GENEVE_HEADER_SIZE + GENEVE_GROUP_OPTION + 2] & GENEVE_OPTION_CRITICAL) == 0 && (ctx->Datagram[1] & GENEVE_FLAG_CRITICAL) == 0);
		TrTestLine(ctx, clear ? "  the critical bit of the trace option of Geneve is clear, and so is the C bit of its header" : "  the critical bit of the trace option of Geneve or the C bit of its header is SET");
		Format(what, sizeof(what), "trace %u: the module sent a datagram of Geneve of %u bytes, the trace option after the option of the source group, its critical bit clear",
			trace.Id, GENEVE_HEADER_SIZE + GENEVE_GROUP_OPTION + GENEVE_TRACE_OPTION + TRTEST_FRAME);
		TrTestCheck(ctx, sent && clear && ctx->DatagramSize == GENEVE_HEADER_SIZE + GENEVE_GROUP_OPTION + GENEVE_TRACE_OPTION + TRTEST_FRAME && ctx->Got &&
			ctx->Group.Trace.Traced && ctx->Group.Trace.Id == trace.Id && ctx->Group.Carried && ctx->Group.Group == TRTEST_GROUP, what);

		// VXLAN: no room for the trace option, so the datagram carries the group ID alone, as without a trace
		TrTestVtep(&vtep, false);
		ctx->DatagramSize = 0;
		sent = VxlanSendToGroup(ctx->Sender, TRTEST_VNI, &vtep, &group, frame, TRTEST_FRAME);
		TrTestFields(fields, sizeof(fields), ctx->Datagram, trtest_vxlan_fields, sizeof(trtest_vxlan_fields) / sizeof(trtest_vxlan_fields[0]));
		Format(line, sizeof(line), "  vxlan with the source group: %s", fields);
		TrTestLine(ctx, line);
		TrTestInput(ctx, ctx->Datagram, ctx->DatagramSize, false);
		TrTestRead(ctx, line, sizeof(line), frame);
		TrTestLine(ctx, line);
		Format(what, sizeof(what), "trace %u: the module sent a datagram of VXLAN of %u bytes, without the trace option, which the VXLAN header has no room for", trace.Id,
			VXLAN_HEADER_SIZE + TRTEST_FRAME);
		TrTestCheck(ctx, sent && ctx->DatagramSize == VXLAN_HEADER_SIZE + TRTEST_FRAME && ctx->Got && ctx->Group.Trace.Traced == false, what);
	}
}

// The records and the datagrams that a node drops or reads otherwise
static void TrTestOthers(TRTEST_CTX *ctx)
{
	UCHAR frame[TRTEST_FRAME];
	UCHAR record[NODE_FRAME_HEADER + NODE_FRAME_TRACE_OPTION + TRTEST_RECORD];
	UCHAR datagram[GENEVE_HEADER_SIZE + GENEVE_TRACE_OPTION + TRTEST_FRAME];
	char line[MAX_SIZE * 2];
	char line2[MAX_SIZE * 2];
	VXLAN_TRACE trace;
	VXLAN_STATS before, after;

	TrTestFrame(frame);
	Zero(&trace, sizeof(trace));
	trace.Traced = true;
	trace.Id = 7;
	Copy(trace.Ingress, trtest_ingress[0], VXLAN_TRACE_INGRESS);

	// The trace option with its critical bit set
	Zero(record, sizeof(record));
	record[4] = NODE_FRAME_VERSION;
	record[5] = NODE_FRAME_TRACE_OPTION / 4;
	NodeTraceWrite(record + NODE_FRAME_HEADER, &trace);
	record[NODE_FRAME_HEADER] |= NODE_FRAME_CRITICAL;
	TrTestRecord(record + NODE_FRAME_HEADER + NODE_FRAME_TRACE_OPTION, 1, 2, false);
	TrTestLine(ctx, "a record of frame version 1 with the trace option whose critical bit is set");
	TrTestReadRecord(line, line2, sizeof(line), record, sizeof(record));
	TrTestLine(ctx, line);
	TrTestLine(ctx, line2);

	// The trace ID 0, which is no trace
	Zero(record, sizeof(record));
	record[4] = NODE_FRAME_VERSION;
	record[5] = NODE_FRAME_TRACE_OPTION / 4;
	trace.Id = 0;
	NodeTraceWrite(record + NODE_FRAME_HEADER, &trace);
	trace.Id = 7;
	TrTestRecord(record + NODE_FRAME_HEADER + NODE_FRAME_TRACE_OPTION, 1, 2, false);
	TrTestLine(ctx, "a record of frame version 1 with the trace option of the trace ID 0");
	TrTestReadRecord(line, line2, sizeof(line), record, sizeof(record));
	TrTestLine(ctx, line);
	TrTestLine(ctx, line2);

	// A record of frame version 0
	TrTestRecord(record, 1, 2, false);
	TrTestLine(ctx, "a record of frame version 0, the data record of VRF 101");
	TrTestReadRecord(line, line2, sizeof(line), record, TRTEST_RECORD);
	TrTestLine(ctx, line);
	TrTestLine(ctx, line2);

	// Geneve with the trace option whose critical bit is set: an option that the module does not know
	Zero(datagram, sizeof(datagram));
	VxlanWriteGeneve(datagram, TRTEST_VNI);
	datagram[0] |= (UCHAR)(GENEVE_TRACE_OPTION / 4);
	VxlanWriteTraceOption(datagram + GENEVE_HEADER_SIZE, &trace);
	datagram[GENEVE_HEADER_SIZE + 2] |= GENEVE_OPTION_CRITICAL;
	Copy(datagram + GENEVE_HEADER_SIZE + GENEVE_TRACE_OPTION, frame, TRTEST_FRAME);
	VxlanGetStats(ctx->Receiver, &before);
	TrTestLine(ctx, "a datagram of Geneve with the trace option whose critical bit is set");
	TrTestInput(ctx, datagram, sizeof(datagram), true);
	TrTestRead(ctx, line, sizeof(line), frame);
	TrTestLine(ctx, line);
	VxlanGetStats(ctx->Receiver, &after);
	TrTestCheck(ctx, ctx->Got == false && after.Drops[VXLAN_DROP_CRITICAL] == before.Drops[VXLAN_DROP_CRITICAL] + 1,
		"the datagram of Geneve whose trace option is critical is dropped as a critical option that the module does not know, and counted");

	// The bytes of the trace option under a type that the module does not know: as a tunnel endpoint that does not know the
	// trace option, the module skips it, since its critical bit is clear, and takes the frame
	datagram[GENEVE_HEADER_SIZE + 2] = 0x04;
	TrTestLine(ctx, "a datagram of Geneve with the bytes of the trace option under the type 0x04, an option that the module does not know");
	TrTestInput(ctx, datagram, sizeof(datagram), true);
	TrTestRead(ctx, line, sizeof(line), frame);
	TrTestLine(ctx, line);
	TrTestCheck(ctx, ctx->Got && ctx->Group.Trace.Traced == false && ctx->FrameSize == TRTEST_FRAME && Cmp(ctx->Frame, frame, TRTEST_FRAME) == 0,
		"a tunnel endpoint that does not know an option whose critical bit is clear forwards the frame without dropping it");

	// The trace option with data of another length, which is no trace option
	Zero(datagram, sizeof(datagram));
	VxlanWriteGeneve(datagram, TRTEST_VNI);
	datagram[0] |= 2;
	datagram[GENEVE_HEADER_SIZE] = (UCHAR)(GENEVE_CLASS_RANZ >> 8);
	datagram[GENEVE_HEADER_SIZE + 1] = (UCHAR)GENEVE_CLASS_RANZ;
	datagram[GENEVE_HEADER_SIZE + 2] = GENEVE_TYPE_TRACE;
	datagram[GENEVE_HEADER_SIZE + 3] = 1;
	datagram[GENEVE_HEADER_SIZE + 7] = 9;
	Copy(datagram + GENEVE_HEADER_SIZE + 8, frame, TRTEST_FRAME);
	TrTestLine(ctx, "a datagram of Geneve with the class and the type of the trace option and 4 bytes of data");
	TrTestInput(ctx, datagram, GENEVE_HEADER_SIZE + 8 + TRTEST_FRAME, true);
	TrTestRead(ctx, line, sizeof(line), frame);
	TrTestLine(ctx, line);
}

// The trace of a Network at the ingress node (NodeTraceOutbound), off and on: the node of the test, whose static key begins
// with the ingress node of the first trace, its own group 3 in VRF 101, and one peer, of frame version 1, or of frame
// version 0 for the last case
static void TrTestIngressNode(TRTEST_CTX *ctx)
{
	NODE *n = ZeroMalloc(sizeof(NODE));
	NODE_VRF_TABLES *v = ZeroMalloc(sizeof(NODE_VRF_TABLES));
	CONTROL_STATE *st = ZeroMalloc(sizeof(CONTROL_STATE));
	CONTROL_PEER *p = ZeroMalloc(sizeof(CONTROL_PEER));
	UCHAR key[PEER_KEY_SIZE];
	UCHAR buf[NODE_TRACE_ROOM + TRTEST_RECORD];
	UCHAR *record = buf + NODE_TRACE_ROOM;
	char line[MAX_SIZE * 2];
	NODE_TRACE_STATUS *status = ZeroMalloc(sizeof(NODE_TRACE_STATUS));
	VXLAN_TRACE trace, read;

	Zero(key, sizeof(key));
	Copy(key, trtest_ingress[0], VXLAN_TRACE_INGRESS);
	TrTestCheck(ctx, NodeTraceStart(n, key, NULL, NULL) != NULL, "the trace of a node starts with the queue of its records");

	st->NumVrfs = 1;
	st->Vrfs[0].Id = TRTEST_VRF;
	st->NumGroups = 1;
	st->Groups[0].VrfId = TRTEST_VRF;
	st->Groups[0].Group = TRTEST_GROUP;
	st->Groups[0].TagSet = TRTEST_TAGS;
	st->Groups[0].Generation = TRTEST_GENERATION;
	StrCpy(p->Name, sizeof(p->Name), "node-b");
	p->FrameVersion = NODE_FRAME_VERSION;
	st->NumPeers = 1;
	st->Peers = p;

	// No Network of the state traces: the tables hold no trace table, and every record goes as it went before SDN-89
	NodeSourceGroupAttach(n, v, st);
	NodeTraceAttach(n, v, st);
	TrTestLine(ctx, "the trace of no Network is on");
	for (UINT g = 0;g < 2;g++)
	{
		Zero(buf, sizeof(buf));
		TrTestRecord(record, 1, 2, false);
		UINT size = TRTEST_RECORD;
		const UCHAR *frame = (g == 0 ? record : NodeSourceGroupWrap(v, 0, TRTEST_VRF, record, &size, NOISE_MAX_PAYLOAD));
		UINT before = size;
		const UCHAR *start = NodeTraceOutbound(n, v, 0, TRTEST_VRF, record, TRTEST_PACKET, frame, &size, NOISE_MAX_PAYLOAD, true, false, &trace);
		bool same = (start == frame && size == before && trace.Traced == false && NodeTraceParse(start, size, &read) == false);

		Format(line, sizeof(line), "  the packet of 10.0.0.1 to 10.0.0.2%s goes as it went before the trace: %u bytes, no trace option", g == 0 ? "" : " with the source group", size);
		TrTestLine(ctx, line);
		TrTestCheck(ctx, same && v->Trace == NULL, g == 0 ? "tracing off: the record keeps its frame version 0 and its size" : "tracing off: the record with the source group keeps its size");
	}
	NodeTraceGetStatus(n, status);
	TrTestCheck(ctx, status->Traced == 0 && status->Recorded == 0 && status->NumRecords == 0, "tracing off: the node traces and records nothing");

	// The Network of the pool 10.0.0.0/24 in VRF 101 traces: a packet of the pool goes with the trace option of the node,
	// and the node records it; one outside the pools, and one within NODE_TRACE_INTERVAL ms of the last that the node
	// traced in the VRF, go as they are
	st->NumTraced = 1;
	st->Traced[0].VrfId = TRTEST_VRF;
	st->Traced[0].Pool.AddressSize = 4;
	st->Traced[0].Pool.Address[0] = 10;
	st->Traced[0].Pool.Length = 24;
	TrTestLine(ctx, "the trace of the Network of the pool 10.0.0.0/24 in VRF 101 is on");
	for (UINT c = 0;c < 4;c++)
	{
		bool outside = (c == 2);
		bool version0 = (c == 3);
		UINT group = (c == 1 ? TRTEST_GROUP : 0);
		char *what[4] = {"", " with the source group", "", " to a peer of frame version 0"};

		p->FrameVersion = (version0 ? 0 : NODE_FRAME_VERSION);
		NodeSourceGroupAttach(n, v, st);
		NodeTraceAttach(n, v, st);
		Zero(buf, sizeof(buf));
		TrTestRecord(record, 1, 2, outside);
		UINT size = TRTEST_RECORD;
		const UCHAR *frame = (c == 1 ? NodeSourceGroupWrap(v, 0, TRTEST_VRF, record, &size, NOISE_MAX_PAYLOAD) : record);
		NODE_TRACE_STATUS before;
		NodeTraceGetStatus(n, &before);
		const UCHAR *start = NodeTraceOutbound(n, v, 0, TRTEST_VRF, record, TRTEST_PACKET, frame, &size, NOISE_MAX_PAYLOAD, true, false, &trace);
		NodeTraceGetStatus(n, status);
		bool parsed = NodeTraceParse(start, size, &read);

		if (outside)
		{
			Format(line, sizeof(line), "  the packet of 192.168.1.1 to 192.168.1.2, outside the pools of the Network, goes as it is: %u bytes, no trace option", size);
			TrTestLine(ctx, line);
			TrTestCheck(ctx, start == frame && size == TRTEST_RECORD && trace.Traced == false && parsed == false && status->Recorded == before.Recorded,
				"tracing on: a packet outside the pools of the Network that traces is not traced");
		}
		else if (version0)
		{
			Format(line, sizeof(line), "  the packet of 10.0.0.1 to 10.0.0.2%s goes as it is: %u bytes, no trace option; the node records it", what[c], size);
			TrTestLine(ctx, line);
			TrTestCheck(ctx, start == frame && size == TRTEST_RECORD && trace.Traced && parsed == false && status->Recorded == before.Recorded + 1,
				"tracing on: a peer of frame version 0 gets the record as it is, and the trace ends at the ingress node, which records it");
		}
		else
		{
			const CONTROL_TRACE *r = (status->NumRecords != 0 ? &status->Records[status->NumRecords - 1] : NULL);
			bool recorded = (r != NULL && status->Recorded == before.Recorded + 1 && r->Id == trace.Id && Cmp(r->Ingress, key, CONTROL_TRACE_INGRESS) == 0 &&
				r->VrfId == TRTEST_VRF && r->Group == group && r->Allowed);

			Format(line, sizeof(line), "  the packet of 10.0.0.1 to 10.0.0.2%s goes with the trace option of the node: %u bytes; the node records it as allowed, with the group %u",
				what[c], size, group);
			TrTestLine(ctx, line);
			TrTestCheck(ctx, trace.Traced && trace.Id != 0 && parsed && read.Id == trace.Id && Cmp(read.Ingress, key, VXLAN_TRACE_INGRESS) == 0 &&
				size == TRTEST_RECORD + (c == 1 ? NODE_TRACE_ROOM : NODE_FRAME_HEADER + NODE_FRAME_TRACE_OPTION) && recorded,
				c == 1 ? "tracing on: the record with the source group goes with the trace option of the node, which records the group and its verdict" :
				"tracing on: the record goes with the trace option of the node, which records it with its verdict");

			// A second packet of the VRF within NODE_TRACE_INTERVAL ms is not traced
			UINT64 tick = Tick64();
			Zero(buf, sizeof(buf));
			TrTestRecord(record, 1, 2, false);
			size = TRTEST_RECORD;
			start = NodeTraceOutbound(n, v, 0, TRTEST_VRF, record, TRTEST_PACKET, record, &size, NOISE_MAX_PAYLOAD, true, false, &trace);
			if (Tick64() - tick < NODE_TRACE_INTERVAL)
			{
				TrTestCheck(ctx, start == record && size == TRTEST_RECORD && trace.Traced == false,
					"tracing on: the node traces one packet of a VRF in NODE_TRACE_INTERVAL ms at most");
			}
		}
	}

	NodeFreeSourceGroupTable(v->SourceGroups);
	NodeFreeTraceTable(v->Trace);
	NodeTraceStop(n);
	Free(status);
	Free(p);
	Free(st);
	Free(v);
	Free(n);
}

// traceoption: the trace option in each carrier
RANZ_TEST_TAGS("traceoption", traceoption_test, "core", "Trace option carriers (SDN-89): the trace ID and the ingress node in the header of a record of frame version 1 of a Noise session and in the trace option of Geneve, sent and read back (golden family trace); the critical bit of the option of Geneve is clear and a node that does not know the option takes the record; the VXLAN header has no room for it; with the trace of no Network on no option goes and a record keeps its size.");
void traceoption_test(UINT num, char **arg)
{
	TRTEST_CTX *ctx = ZeroMalloc(sizeof(TRTEST_CTX));
	char out_dir[MAX_SIZE];
	char golden_dir[MAX_SIZE];
	bool update;
	HARNESS h;

	Print("Trace option carrier test: the trace ID and the ingress node of a packet in each of its carriers\n");

	ctx->Text = NewBuf();
	ctx->Sender = VxlanNew(TrTestSend, ctx, NULL, NULL);
	ctx->Receiver = VxlanNew(TrTestNoSend, NULL, NULL, ctx);
	if (TrTestCheck(ctx, ctx->Sender != NULL && ctx->Receiver != NULL && VxlanSetVni(ctx->Receiver, TRTEST_VNI, NULL, 0), "Two VXLAN modules, one that sends and one that takes VNI 5101"))
	{
		VxlanSetGroupReceiver(ctx->Receiver, TrTestReceive);

		TrTestLine(ctx, "# SDN-89: the trace option in each carrier, as a node sends it and as a node reads it back");
		TrTestLine(ctx, "# ranz frame: the VRF tag 0, the version, the length of the options, reserved | the type, the length, reserved, the trace ID, the ingress node | the VRF tag of the record");
		TrTestLine(ctx, "# ranz frame with the source group: the header | the option of the source group | the trace option | the VRF tag of the record");
		TrTestLine(ctx, "# geneve: the version and the length of the options, the flags O and C, the protocol, the VNI, reserved | the class, the type, the length, the trace ID, the ingress node");
		TrTestLine(ctx, "# geneve with the source group: the header | the option of the source group | the trace option");
		TrTestLine(ctx, "# vxlan: the flags, the flags D and A, the group, the VNI, reserved");
		TrTestTraces(ctx);
		TrTestOthers(ctx);
		TrTestIngressNode(ctx);
	}

	char *text = HarnessBufToStr(ctx->Text);

	HarnessGetFamilyDirs("trace", out_dir, sizeof(out_dir), golden_dir, sizeof(golden_dir), &update);
	MakeDirEx(out_dir);
	Print("[golden]\n");
	Print("TRACE GOLDEN MODE %s\n", update ? "update" : "compare");
	Print("  golden directory: %s\n", golden_dir);
	Zero(&h, sizeof(h));
	HarnessCompareGolden(&h, out_dir, golden_dir, TRTEST_GOLDEN, text, update);
	TrTestCheck(ctx, h.NumFail == 0, "The carriers match the golden file " TRTEST_GOLDEN);

	Free(text);
	FreeBuf(ctx->Text);
	VxlanFree(ctx->Sender);
	VxlanFree(ctx->Receiver);

	if (ctx->NumFailed == 0)
	{
		Print("TRACEOPTION TEST OK\n");
	}
	else
	{
		Print("TRACEOPTION TEST FAILED (%u of %u checks failed)\n", ctx->NumFailed, ctx->NumChecks);
	}

	Free(ctx);
}
