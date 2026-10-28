// ControlSecurity.c
// The security of the L2 Networks on the control stream (SDN-41, #234; Core/Control.h): the Network objects of a state
// that carry an L2Security become the securities of the state (ControlCopySecurities), which the switch of each L2
// Network applies to the frames of its clients (Core/SwitchSecurity.h). Every node of the VRF of a Network gets its
// security, as each node judges the frames that come to its own switch; the gateways stay as the controller sent them.

#include "Core/ControlInternal.h"

#include <stdlib.h>
#include <string.h>

static int ControlCompareSecurities(const void *a, const void *b) {
	return strcmp(((const CONTROL_SECURITY *)a)->Network, ((const CONTROL_SECURITY *)b)->Network);
}

// Whether the object o is an L2 Network with a security
static bool ControlHasSecurity(const ranz_control_v1_Object *o) {
	return o->which_kind == ranz_control_v1_Object_network_tag && o->kind.network.has_security && o->kind.network.mode == ranz_control_v1_NetworkMode_NETWORK_MODE_L2;
}

// The securities of the Network objects among num objects into the state: an L2 Network that carries one, with
// CONTROL_MAX_GATEWAYS gateways at most. At most CONTROL_MAX_SECURITIES, sorted by Network name; none when there is no
// memory for them. ControlFreeSecurities frees them.
void ControlCopySecurities(CONTROL_STATE *st, const ranz_control_v1_Object *objects, UINT num) {
	UINT max = 0;

	st->NumSecurities = 0;
	st->Securities = NULL;

	for (UINT i = 0; i < num; i++)
		if (ControlHasSecurity(&objects[i]))
			max++;
	if (max == 0)
		return;
	if (max > CONTROL_MAX_SECURITIES)
		max = CONTROL_MAX_SECURITIES;

	st->Securities = (CONTROL_SECURITY *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(CONTROL_SECURITY) * max);
	if (st->Securities == NULL)
		return;

	for (UINT i = 0; i < num && st->NumSecurities < max; i++) {
		if (ControlHasSecurity(&objects[i]) == false)
			continue;

		const ranz_control_v1_Network *nw = &objects[i].kind.network;
		const ranz_control_v1_L2Security *src = &nw->security;
		CONTROL_SECURITY *s = &st->Securities[st->NumSecurities++];

		strncpy_s(s->Network, sizeof(s->Network), nw->name, _TRUNCATE);
		s->VrfId = nw->vrf_id;
		s->CheckMac = src->check_mac;
		s->CheckIp = src->check_ip;
		s->MaxMacs = src->max_macs;
		s->MaxIps = src->max_ips;
		s->ArpDhcpOnly = src->arp_dhcp_only;
		s->DhcpGuard = src->dhcp_guard;
		s->RaGuard = src->ra_guard;
		for (pb_size_t j = 0; j < src->gateways_count && s->NumGateways < CONTROL_MAX_GATEWAYS; j++)
			strncpy_s(s->Gateways[s->NumGateways++], CONTROL_NAME_SIZE, src->gateways[j], _TRUNCATE);
	}

	// A delta appends the objects it adds, so the securities are sorted here
	qsort(st->Securities, st->NumSecurities, sizeof(CONTROL_SECURITY), ControlCompareSecurities);
}

// Free the securities of a state
void ControlFreeSecurities(CONTROL_STATE *st) {
	if (st->Securities != NULL)
		HeapFree(GetProcessHeap(), 0, st->Securities);

	st->Securities = NULL;
	st->NumSecurities = 0;
}
