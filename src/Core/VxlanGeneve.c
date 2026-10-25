// VxlanGeneve.c
// The Geneve header of the VXLAN module (RFC 8926; SDN-71, #347): the one that the module sends in front of a frame to
// a VTEP of Geneve, and VxlanParseGeneve, which reads the header of a datagram from one with all of its options. An
// option is read whatever its class and type, as its class, its type with the critical bit, and its data; which of
// them the module knows is for VxlanInput (Vxlan.c) to say, and the source group of SDN-87 and the trace option of
// SDN-89 will be the first.

#include "Core/Vxlan.h"

#include <string.h>

// The Geneve header of a frame on the VNI vni in the first GENEVE_HEADER_SIZE bytes of buf: version 0, no options,
// neither the O nor the C bit, the protocol of an Ethernet frame, and the reserved bits zero (RFC 8926 section 3.4)
void VxlanWriteGeneve(UCHAR *buf, UINT vni) {
	ZeroMemory(buf, GENEVE_HEADER_SIZE);
	buf[2] = (UCHAR)(GENEVE_PROTOCOL_ETHERNET >> 8);
	buf[3] = (UCHAR)GENEVE_PROTOCOL_ETHERNET;
	buf[4] = (UCHAR)(vni >> 16);
	buf[5] = (UCHAR)(vni >> 8);
	buf[6] = (UCHAR)vni;
}

// Read the Geneve header at the start of the datagram data, size bytes, into *h: the fixed header (RFC 8926 section
// 3.4) and each of its options (section 3.5), in their order, the data of each pointing into data. The reserved bits,
// of the header and of the options, are not looked at. False, with *h undefined, when data holds no header of version
// 0 whose options fill its option length exactly: data is shorter than the fixed header or than the options, the
// version is another, which a tunnel endpoint drops (section 3.4), or an option runs past the end of the options, so
// that the lengths of all options differ from the option length, which makes the datagram one to drop (section 3.5).
bool VxlanParseGeneve(const UCHAR *data, UINT size, GENEVE_HEADER *h) {
	if (data == NULL || h == NULL || size < GENEVE_HEADER_SIZE || (data[0] >> 6) != GENEVE_VERSION)
		return false;

	// The option length: the six low bits of byte 0, in 4-byte words
	UINT end = GENEVE_HEADER_SIZE + (data[0] & 0x3F) * 4;
	if (end > size)
		return false;

	h->Size = end;
	h->Control = ((data[1] & GENEVE_FLAG_CONTROL) != 0);
	h->Critical = ((data[1] & GENEVE_FLAG_CRITICAL) != 0);
	h->Protocol = (USHORT)(((UINT)data[2] << 8) | data[3]);
	h->Vni = ((UINT)data[4] << 16) | ((UINT)data[5] << 8) | data[6];
	h->NumOptions = 0;

	// An option is a header of 4 bytes, then its data: the five low bits of the last byte of the header, in 4-byte
	// words. The options fill whole words, so a header always fits in what is left of them, and its data must fit in
	// what is left after it. GENEVE_MAX_OPTIONS headers alone fill the longest options, so the count never stops a
	// header that fits; it bounds the array.
	UINT pos = GENEVE_HEADER_SIZE;
	while (pos < end) {
		UINT len = (data[pos + 3] & 0x1F) * 4;

		if (h->NumOptions >= GENEVE_MAX_OPTIONS || len > end - pos - 4)
			return false;

		GENEVE_OPTION *o = &h->Options[h->NumOptions++];
		o->Class = (USHORT)(((UINT)data[pos] << 8) | data[pos + 1]);
		o->Type = data[pos + 2];
		o->Critical = ((data[pos + 2] & GENEVE_OPTION_CRITICAL) != 0);
		o->Length = len;
		o->Data = data + pos + 4;
		pos += 4 + len;
	}

	return true;
}
