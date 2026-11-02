// VxlanTrace.c
// The trace option in the datagrams of Geneve of the VXLAN module (SDN-89, #388; Core/Vxlan.h): the trace ID that the
// ingress node gave a traced packet and the first bytes of the static key of that node, as the module sends them after
// the option of the source group, or alone (VxlanSendToGroup), and as VxlanInput reads them. The option carries nothing
// else of the packet. Its critical bit is clear, so a tunnel endpoint that does not know it skips it instead of dropping
// the datagram (RFC 8926 section 3.5.1), and its class is the one of Experimental Use of the option of the source group
// until the vendor class of Ranz VPN is registered before the release. The VXLAN header has no room for it.
//
// The trace option, GENEVE_TRACE_OPTION bytes, the last of the options of the Geneve header:
//   bytes 0-1   the class GENEVE_CLASS_RANZ
//   byte 2      the type GENEVE_TYPE_TRACE, with the critical bit clear
//   byte 3      the length of the data in 4-byte words: GENEVE_TRACE_DATA / 4
//   bytes 4-7   the trace ID that the ingress node gave the packet, big-endian, never 0
//   bytes 8-15  the ingress node: the first VXLAN_TRACE_INGRESS bytes of its static key

#include "Core/Vxlan.h"

#include <string.h>

// Write the trace option of trace, GENEVE_TRACE_OPTION bytes at option: its class, its type with the critical bit clear
// and the length of its data, then the trace ID, big-endian, and the bytes of the ingress node
void VxlanWriteTraceOption(UCHAR *option, const VXLAN_TRACE *trace) {
	ZeroMemory(option, GENEVE_TRACE_OPTION);
	option[0] = (UCHAR)(GENEVE_CLASS_RANZ >> 8);
	option[1] = (UCHAR)GENEVE_CLASS_RANZ;
	option[2] = GENEVE_TYPE_TRACE;
	option[3] = GENEVE_TRACE_DATA / 4;
	for (UINT i = 0; i < 4; i++)
		option[4 + i] = (UCHAR)(trace->Id >> (24 - 8 * i));
	CopyMemory(option + 8, trace->Ingress, VXLAN_TRACE_INGRESS);
}

// Add the trace option of trace to the header of header bytes at buf, which a frame of size bytes follows in a datagram
// to the VTEP vtep: after the options of a Geneve header, whose length in byte 0 grows by the option, when trace has a
// trace ID and the header with the option and the frame fit a datagram. The bytes that it added, GENEVE_TRACE_OPTION, or
// 0 when the datagram goes without the option: the VXLAN header of a VTEP of VXLAN has no room for it.
UINT VxlanAddTraceOption(UCHAR *buf, UINT header, const VXLAN_ADDR *vtep, const VXLAN_TRACE *trace, UINT size) {
	if (buf == NULL || vtep == NULL || trace == NULL || trace->Traced == false || trace->Id == 0 || vtep->Encap != VXLAN_ENCAP_GENEVE)
		return 0;
	// The header ends with its options, and the option and the frame fit a datagram after it
	if (header != GENEVE_HEADER_SIZE + (buf[0] & 0x3F) * 4 || (buf[0] & 0x3F) + GENEVE_TRACE_OPTION / 4 > GENEVE_MAX_OPTIONS ||
	    header > VXLAN_MAX_DATAGRAM - GENEVE_TRACE_OPTION || size > VXLAN_MAX_DATAGRAM - GENEVE_TRACE_OPTION - header)
		return 0;

	VxlanWriteTraceOption(buf + header, trace);
	buf[0] = (UCHAR)((buf[0] & 0xC0) | ((buf[0] & 0x3F) + GENEVE_TRACE_OPTION / 4));
	return GENEVE_TRACE_OPTION;
}

// Read the option o of a Geneve header (VxlanParseGeneve) into *t when it is the trace option: its class and type, the
// critical bit clear, data of GENEVE_TRACE_DATA bytes and a trace ID that is not 0. False, with *t as it was, for any
// other option.
bool VxlanParseTraceOption(const GENEVE_OPTION *o, VXLAN_TRACE *t) {
	if (o == NULL || t == NULL || o->Data == NULL || o->Class != GENEVE_CLASS_RANZ || o->Type != GENEVE_TYPE_TRACE || o->Length != GENEVE_TRACE_DATA)
		return false;

	UINT id = 0;
	for (UINT i = 0; i < 4; i++)
		id = (id << 8) | o->Data[i];
	if (id == 0)
		return false;

	t->Traced = true;
	t->Id = id;
	CopyMemory(t->Ingress, o->Data + 4, VXLAN_TRACE_INGRESS);

	return true;
}
