// ControlDns.c
// The zones of overlay DNS on the control stream (SDN-11, #187; ADR-0028 decisions 6 and 7; Core/Control.h). A Vrf object
// of a state that carries a DnsZone gives that VRF of the state its zone (CONTROL_VRF.Dns) while the owner takes the
// state (ControlCopyZones), and the zone goes with the state (ControlFreeZones). The stub resolver of the node answers
// the zone on the node's addresses in the VRF.

#include "Core/ControlInternal.h"

#include <string.h>

// The records of the zone src into z: a record whose name is empty is left out, and so is an address that is neither
// IPv4 nor IPv6
static void ControlCopyZone(CONTROL_DNS_ZONE *z, const ranz_control_v1_DnsZone *src) {
	strncpy_s(z->Suffix, sizeof(z->Suffix), src->suffix, _TRUNCATE);

	for (pb_size_t i = 0; i < src->records_count && z->NumRecords < CONTROL_MAX_DNS_RECORDS; i++) {
		const ranz_control_v1_DnsRecord *r = &src->records[i];
		CONTROL_DNS_RECORD *d = &z->Records[z->NumRecords];

		if (r->name[0] == 0)
			continue;

		ZeroMemory(d, sizeof(CONTROL_DNS_RECORD));
		strncpy_s(d->Name, sizeof(d->Name), r->name, _TRUNCATE);
		for (pb_size_t j = 0; j < r->addresses_count && d->NumAddresses < CONTROL_MAX_DNS_ADDRESSES; j++) {
			if (r->addresses[j].size != 4 && r->addresses[j].size != 16)
				continue;

			CopyMemory(d->Addresses[d->NumAddresses], r->addresses[j].bytes, r->addresses[j].size);
			d->AddressSizes[d->NumAddresses++] = r->addresses[j].size;
		}
		z->NumRecords++;
	}
}

// The zones of the Vrf objects among num objects into the VRFs of the state, which hold the VRFs of those objects: a
// Vrf object without a zone leaves its VRF without one. A zone that cannot be allocated is left out.
void ControlCopyZones(CONTROL_STATE *st, const ranz_control_v1_Object *objects, UINT num) {
	for (UINT i = 0; i < num; i++) {
		const ranz_control_v1_Object *o = &objects[i];

		if (o->which_kind != ranz_control_v1_Object_vrf_tag || o->kind.vrf.has_dns == false)
			continue;

		for (UINT j = 0; j < st->NumVrfs; j++) {
			CONTROL_VRF *v = &st->Vrfs[j];

			if (v->Id != o->kind.vrf.id || v->Dns != NULL || strcmp(v->Name, o->kind.vrf.name) != 0)
				continue;

			v->Dns = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(CONTROL_DNS_ZONE));
			if (v->Dns != NULL)
				ControlCopyZone(v->Dns, &o->kind.vrf.dns);
			break;
		}
	}
}

// Free the zones of the VRFs of a state, once its owner took it
void ControlFreeZones(CONTROL_STATE *st) {
	for (UINT i = 0; i < st->NumVrfs; i++) {
		if (st->Vrfs[i].Dns != NULL)
			HeapFree(GetProcessHeap(), 0, st->Vrfs[i].Dns);
		st->Vrfs[i].Dns = NULL;
	}
}
