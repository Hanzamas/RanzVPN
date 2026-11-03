// ControlSplit.c
// The TCP splitting of the L3 Networks on the control stream (CORE-P2-3, #94; Core/Control.h): the Network objects of a
// state that carry tcp_split, and are no L2 Network, become the split Networks of the state (ControlCopySplits), by name
// with their VRF. The node terminates the TCP connections that its host opens from its address in such a Network, and opens
// to their real destination the ones that a peer sends from its address in one (Cedar/NodeSplit.c). Every node of the VRF
// of a Network gets it.

#include "Core/ControlInternal.h"

#include <stdlib.h>
#include <string.h>

static int ControlCompareSplits(const void *a, const void *b) {
	return strcmp(((const CONTROL_SPLIT *)a)->Network, ((const CONTROL_SPLIT *)b)->Network);
}

// The split Networks among num objects into the state: each Network object with tcp_split that is no L2 Network, at most
// CONTROL_MAX_SPLITS, sorted by name
void ControlCopySplits(CONTROL_STATE *st, const ranz_control_v1_Object *objects, UINT num) {
	st->NumSplits = 0;

	for (UINT i = 0; i < num && st->NumSplits < CONTROL_MAX_SPLITS; i++) {
		const ranz_control_v1_Object *o = &objects[i];

		if (o->which_kind != ranz_control_v1_Object_network_tag || o->kind.network.tcp_split == false ||
		    o->kind.network.mode == ranz_control_v1_NetworkMode_NETWORK_MODE_L2)
			continue;

		CONTROL_SPLIT *s = &st->Splits[st->NumSplits++];

		ZeroMemory(s, sizeof(CONTROL_SPLIT));
		strncpy_s(s->Network, sizeof(s->Network), o->kind.network.name, _TRUNCATE);
		s->VrfId = o->kind.network.vrf_id;
	}

	// A delta appends the objects it adds, so the Networks are sorted here
	qsort(st->Splits, st->NumSplits, sizeof(CONTROL_SPLIT), ControlCompareSplits);
}
