// ControlCopy.c
// The copy of a desired state that holds its own memory (Core/Control.h). The state that a client hands its owner is valid
// only while the owner's procedure runs; an owner that applies the state again later keeps a copy, as the BGP peering of a
// node does when the routes that it learned change (SDN-77, #357). The copy holds every field of the state, and each field
// that points at memory of its own points at a copy of that memory: the rules, the peers with their BGP peering, the zone of
// overlay DNS of each VRF, the Listener, the mimic part (CORE-P2-7, #424), the WireGuard Devices, the security of the L2
// Networks and the BGP peering of the node. A field of that kind that CONTROL_STATE gains is copied here too.

#include "Core/Control.h"

static void *ControlCopyAlloc(SIZE_T size) {
	return HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, size);
}

// Wipe and free size bytes at p, which may be NULL
static void ControlCopyRelease(void *p, SIZE_T size) {
	if (p == NULL)
		return;

	SecureZeroMemory(p, size);
	HeapFree(GetProcessHeap(), 0, p);
}

// A copy of the num items of size bytes each at src, with the memory of one item at least: NULL for src NULL, and when there
// is no memory, which *ok then says
static void *ControlCopyItems(const void *src, UINT num, SIZE_T size, bool *ok) {
	if (src == NULL)
		return NULL;

	void *p = ControlCopyAlloc(size * (num != 0 ? num : 1));
	if (p == NULL) {
		*ok = false;
		return NULL;
	}

	if (num != 0)
		CopyMemory(p, src, size * num);

	return p;
}

CONTROL_STATE *ControlCopyState(const CONTROL_STATE *st) {
	bool ok = true;

	if (st == NULL)
		return NULL;

	CONTROL_STATE *c = ControlCopyAlloc(sizeof(CONTROL_STATE));
	if (c == NULL)
		return NULL;

	// No pointer of the copy leads into the memory of st from here on, so a copy that fails half way frees only its own
	CopyMemory(c, st, sizeof(CONTROL_STATE));
	c->Rules = NULL;
	c->Peers = NULL;
	c->Listener = NULL;
	c->Mimic = NULL;
	c->Devices = NULL;
	c->Securities = NULL;
	c->Peering = NULL;
	for (UINT i = 0; i < CONTROL_MAX_VRFS; i++)
		c->Vrfs[i].Dns = NULL;

	c->Rules = ControlCopyItems(st->Rules, st->NumRules, sizeof(CONTROL_RULE), &ok);
	c->Peers = ControlCopyItems(st->Peers, st->NumPeers, sizeof(CONTROL_PEER), &ok);
	for (UINT i = 0; c->Peers != NULL && i < st->NumPeers; i++)
		c->Peers[i].Peering = ControlCopyItems(st->Peers[i].Peering, 1, sizeof(CONTROL_PEER_PEERING), &ok);
	for (UINT i = 0; i < st->NumVrfs && i < CONTROL_MAX_VRFS; i++)
		c->Vrfs[i].Dns = ControlCopyItems(st->Vrfs[i].Dns, 1, sizeof(CONTROL_DNS_ZONE), &ok);
	c->Listener = ControlCopyItems(st->Listener, 1, sizeof(CONTROL_LISTENER), &ok);
	c->Mimic = ControlCopyItems(st->Mimic, 1, sizeof(CONTROL_MIMIC), &ok);
	c->Devices = ControlCopyItems(st->Devices, st->NumDevices, sizeof(CONTROL_DEVICE), &ok);
	c->Securities = ControlCopyItems(st->Securities, st->NumSecurities, sizeof(CONTROL_SECURITY), &ok);
	c->Peering = ControlCopyItems(st->Peering, 1, sizeof(CONTROL_PEERING), &ok);

	if (ok == false) {
		ControlFreeStateCopy(c);
		return NULL;
	}

	return c;
}

void ControlFreeStateCopy(CONTROL_STATE *st) {
	if (st == NULL)
		return;

	ControlCopyRelease(st->Rules, sizeof(CONTROL_RULE) * (st->NumRules != 0 ? st->NumRules : 1));
	for (UINT i = 0; st->Peers != NULL && i < st->NumPeers; i++)
		ControlCopyRelease(st->Peers[i].Peering, sizeof(CONTROL_PEER_PEERING));
	ControlCopyRelease(st->Peers, sizeof(CONTROL_PEER) * (st->NumPeers != 0 ? st->NumPeers : 1));
	for (UINT i = 0; i < CONTROL_MAX_VRFS; i++)
		ControlCopyRelease(st->Vrfs[i].Dns, sizeof(CONTROL_DNS_ZONE));
	ControlCopyRelease(st->Listener, sizeof(CONTROL_LISTENER));
	ControlCopyRelease(st->Mimic, sizeof(CONTROL_MIMIC));
	ControlCopyRelease(st->Devices, sizeof(CONTROL_DEVICE) * (st->NumDevices != 0 ? st->NumDevices : 1));
	ControlCopyRelease(st->Securities, sizeof(CONTROL_SECURITY) * (st->NumSecurities != 0 ? st->NumSecurities : 1));
	ControlCopyRelease(st->Peering, sizeof(CONTROL_PEERING));
	ControlCopyRelease(st, sizeof(CONTROL_STATE));
}
