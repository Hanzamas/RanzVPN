// VxlanTrace.c
// The trace option in the datagrams of Geneve of the VXLAN module (SDN-89, #388; Core/Vxlan.h): the trace ID that the
// ingress node gave a traced packet and the first bytes of the static key of that node, as the module sends them after
// the option of the source group (VxlanSendToGroup) and as VxlanInput reads them. The option carries nothing else of the
// packet. Its critical bit is clear, so a tunnel endpoint that does not know it skips it instead of dropping the datagram
// (RFC 8926 section 3.5.1), and its class is the one of Experimental Use of the option of the source group until the
// vendor class of Ranz VPN is registered before the release. The VXLAN header has no room for it.

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
