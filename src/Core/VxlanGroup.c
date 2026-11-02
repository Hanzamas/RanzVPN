// VxlanGroup.c
// The source group in the datagrams of the VXLAN module (SDN-87, #386; Core/Vxlan.h): the group policy extension of
// VXLAN, the G flag and the group ID in the VXLAN header, and the option of the source group of Geneve, with the group
// ID, the tag set and the group generation of the sender, as the module sends them (VxlanSendToGroup) and as VxlanInput
// reads them. The critical bit of the option is clear, so a tunnel endpoint that does not know it skips it instead of
// dropping the datagram (RFC 8926 section 3.5.1), and the class is one of Experimental Use until the vendor class of Ranz
// VPN is registered before the release.

#include "Core/Vxlan.h"

#include <string.h>

// Set the G flag and the group ID of the group policy extension in the VXLAN header at header, which the module wrote.
// The flags D (don't learn) and A (policy applied) of the extension stay clear: a flag that says that the policy was
// applied at the source is easy to forge.
void VxlanWriteGroup(UCHAR *header, USHORT group) {
	header[0] |= VXLAN_FLAG_GROUP;
	header[2] = (UCHAR)(group >> 8);
	header[3] = (UCHAR)group;
}

// Write the option of the source group, GENEVE_GROUP_OPTION bytes at option: its class, its type with the critical bit
// clear and the length of its data, then the group ID, two reserved bytes, the tag set and the group generation of the
// sender, big-endian
void VxlanWriteGroupOption(UCHAR *option, USHORT group, UINT64 tags, UINT generation) {
	ZeroMemory(option, GENEVE_GROUP_OPTION);
	option[0] = (UCHAR)(GENEVE_CLASS_RANZ >> 8);
	option[1] = (UCHAR)GENEVE_CLASS_RANZ;
	option[2] = GENEVE_TYPE_GROUP;
	option[3] = GENEVE_GROUP_DATA / 4;
	option[4] = (UCHAR)(group >> 8);
	option[5] = (UCHAR)group;
	for (UINT i = 0; i < 8; i++)
		option[8 + i] = (UCHAR)(tags >> (56 - 8 * i));
	for (UINT i = 0; i < 4; i++)
		option[16 + i] = (UCHAR)(generation >> (24 - 8 * i));
}

// Read the group policy extension of the VXLAN header at the start of the datagram data, size bytes, into *g: true when
// its G flag is set, with the group ID; false, with *g empty, when it is clear or the header is not whole. The flags D
// and A are not looked at.
bool VxlanParseGroup(const UCHAR *data, UINT size, VXLAN_GROUP *g) {
	if (g == NULL)
		return false;

	ZeroMemory(g, sizeof(VXLAN_GROUP));
	if (data == NULL || size < VXLAN_HEADER_SIZE || (data[0] & VXLAN_FLAG_GROUP) == 0)
		return false;

	g->Carried = true;
	g->Group = (USHORT)(((UINT)data[2] << 8) | data[3]);

	return true;
}

// Read the option o of a Geneve header (VxlanParseGeneve) into *g when it is the option of the source group: its class
// and type, the critical bit clear, and data of GENEVE_GROUP_DATA bytes. False, with *g as it was, for any other option.
bool VxlanParseGroupOption(const GENEVE_OPTION *o, VXLAN_GROUP *g) {
	if (o == NULL || g == NULL || o->Data == NULL || o->Class != GENEVE_CLASS_RANZ || o->Type != GENEVE_TYPE_GROUP || o->Length != GENEVE_GROUP_DATA)
		return false;

	UINT64 tags = 0;
	for (UINT i = 0; i < 8; i++)
		tags = (tags << 8) | o->Data[4 + i];
	UINT generation = 0;
	for (UINT i = 0; i < 4; i++)
		generation = (generation << 8) | o->Data[12 + i];

	g->Carried = true;
	g->HasTags = true;
	g->HasGeneration = true;
	g->Group = (USHORT)(((UINT)o->Data[0] << 8) | o->Data[1]);
	g->Tags = tags;
	g->Generation = generation;

	return true;
}
