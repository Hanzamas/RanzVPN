// NodeWireGuardFilter.c
// Two WireGuard Devices of one gateway and the policy between them (SDN-80, #375; spec #374): a Device reaches another
// Device only when the policy of its VRF allows it, and the policy judges a packet in the overlay of a node
// (NodePolicy.c). A packet of one Device to another Device of the same gateway never reaches the overlay: Windows forwards
// it on the WireGuard interface that it came from, since the address of the other Device is a route through that
// interface (NodeWireGuard.c). So the gateway has the Windows Filtering Platform block that forwarding, a packet that
// arrived on its WireGuard interface and would leave on it again, of either family, and permit it between two Devices of
// one VRF whose every packet the rules of the state let through both ways. The filters of the forward layers see the
// interfaces and the addresses of a packet, and neither its protocol nor its ports, so a pair that a rule allows or
// denies only some flows of stays apart whole (ADR-0029 amendment of 2026-10-27). The filters are in a dynamic session of
// the filter engine, so they go when the session closes; each state that the gateway applies opens a new one before the
// old one closes.

#include "Node.h"

#include "Mayaqua/Memory.h"

#include "Core/Control.h"

#include "NodeInternal.h"

#include <stdlib.h>
#include <string.h>

// The GUIDs of the layers and of the conditions are defined here, where the filters are made
#include <initguid.h>
#include <fwpmu.h>

// The weights of the filters in their sublayer: a permit of a pair of Devices goes before the block of the interface
#define NODE_WG_FILTER_BLOCK  1
#define NODE_WG_FILTER_PERMIT 2

// The order in which the policy engine judges two rules: the lowest priority first, of one priority a deny rule before an
// allow rule, then by name
static int NodeWireGuardRuleOrder(const void *a, const void *b) {
	const CONTROL_RULE *x = *(const CONTROL_RULE *const *)a;
	const CONTROL_RULE *y = *(const CONTROL_RULE *const *)b;

	if (x->Priority != y->Priority)
		return (x->Priority < y->Priority ? -1 : 1);
	if (x->Deny != y->Deny)
		return (x->Deny ? -1 : 1);

	return strcmp(x->Name, y->Name);
}

// Whether the prefix p holds the address a
static bool NodeWireGuardPrefixHolds(const CONTROL_PREFIX *p, const CONTROL_ADDRESS *a) {
	UINT bytes = p->Length / 8;
	UINT bits = p->Length % 8;

	if (p->AddressSize != a->AddressSize || p->Length > a->AddressSize * 8 || memcmp(p->Address, a->Address, bytes) != 0)
		return false;
	if (bits == 0)
		return true;

	UCHAR mask = (UCHAR)(0xFF << (8 - bits));
	return ((p->Address[bytes] & mask) == (a->Address[bytes] & mask));
}

// Whether the end e of a rule holds the Device d with its address a: e names no tag or one of the tags of d, and no
// prefix or one that holds a
static bool NodeWireGuardEndHolds(const CONTROL_RULE_END *e, const CONTROL_DEVICE *d, const CONTROL_ADDRESS *a) {
	bool tag = (e->NumTags == 0);
	bool prefix = (e->NumPrefixes == 0);

	for (UINT i = 0; i < e->NumTags && tag == false; i++)
		for (UINT j = 0; j < d->NumTags && tag == false; j++)
			tag = (strcmp(e->Tags[i], d->Tags[j]) == 0);
	for (UINT i = 0; i < e->NumPrefixes && prefix == false; i++)
		prefix = NodeWireGuardPrefixHolds(&e->Prefixes[i], a);

	return (tag && prefix);
}

// Whether the rules, in the order of the engine, let every packet from the Device from at its address fa to the Device to
// at its address ta through: no rule of their VRF that holds both denies any of them, and one that allows every
// protocol and every port holds both before any rule that allows only some of them would leave the rest to the default
// deny
static bool NodeWireGuardAllowsAll(const CONTROL_RULE *const *rules, UINT num, const CONTROL_DEVICE *from, const CONTROL_ADDRESS *fa,
                                   const CONTROL_DEVICE *to, const CONTROL_ADDRESS *ta) {
	for (UINT i = 0; i < num; i++) {
		const CONTROL_RULE *r = rules[i];

		if (r->VrfId != from->VrfId || NodeWireGuardEndHolds(&r->From, from, fa) == false || NodeWireGuardEndHolds(&r->To, to, ta) == false)
			continue;
		if (r->Deny)
			return false;
		if (r->Protocol == 0 && r->NumPorts == 0)
			return true;
	}

	return false;
}

// Add a filter at the forward layer of the family of size (4 or 16) for the WireGuard interface of the index index: a
// block of every packet that would leave the interface it came in on, or, with from and to, a permit of the packets
// from the address from to the address to
static DWORD NodeWireGuardAddFilter(HANDLE engine, UINT size, UINT index, const UCHAR *from, const UCHAR *to) {
	FWPM_FILTER_CONDITION0 cond[4];
	FWPM_FILTER0 filter;
	FWP_BYTE_ARRAY16 from6, to6;
	UINT64 id = 0;
	UINT num = 2;

	Zero(cond, sizeof(cond));
	cond[0].fieldKey = FWPM_CONDITION_SOURCE_INTERFACE_INDEX;
	cond[0].matchType = FWP_MATCH_EQUAL;
	cond[0].conditionValue.type = FWP_UINT32;
	cond[0].conditionValue.uint32 = index;
	cond[1].fieldKey = FWPM_CONDITION_DESTINATION_INTERFACE_INDEX;
	cond[1].matchType = FWP_MATCH_EQUAL;
	cond[1].conditionValue.type = FWP_UINT32;
	cond[1].conditionValue.uint32 = index;

	if (from != NULL && to != NULL) {
		cond[2].fieldKey = FWPM_CONDITION_IP_SOURCE_ADDRESS;
		cond[2].matchType = FWP_MATCH_EQUAL;
		cond[3].fieldKey = FWPM_CONDITION_IP_DESTINATION_ADDRESS;
		cond[3].matchType = FWP_MATCH_EQUAL;
		if (size == 4) {
			// An IPv4 address of a condition is in host byte order
			cond[2].conditionValue.type = FWP_UINT32;
			cond[2].conditionValue.uint32 = ((UINT)from[0] << 24) | ((UINT)from[1] << 16) | ((UINT)from[2] << 8) | from[3];
			cond[3].conditionValue.type = FWP_UINT32;
			cond[3].conditionValue.uint32 = ((UINT)to[0] << 24) | ((UINT)to[1] << 16) | ((UINT)to[2] << 8) | to[3];
		} else {
			Copy(from6.byteArray16, from, 16);
			Copy(to6.byteArray16, to, 16);
			cond[2].conditionValue.type = FWP_BYTE_ARRAY16_TYPE;
			cond[2].conditionValue.byteArray16 = &from6;
			cond[3].conditionValue.type = FWP_BYTE_ARRAY16_TYPE;
			cond[3].conditionValue.byteArray16 = &to6;
		}
		num = 4;
	}

	Zero(&filter, sizeof(filter));
	filter.layerKey = (size == 4 ? FWPM_LAYER_IPFORWARD_V4 : FWPM_LAYER_IPFORWARD_V6);
	filter.displayData.name = (num == 2 ? L"Ranz VPN: no forwarding between two WireGuard Devices of a gateway" : L"Ranz VPN: two WireGuard Devices that the policy lets meet");
	filter.action.type = (num == 2 ? FWP_ACTION_BLOCK : FWP_ACTION_PERMIT);
	filter.weight.type = FWP_UINT8;
	filter.weight.uint8 = (num == 2 ? NODE_WG_FILTER_BLOCK : NODE_WG_FILTER_PERMIT);
	filter.numFilterConditions = num;
	filter.filterCondition = cond;

	return FwpmFilterAdd0(engine, &filter, NULL, &id);
}

// The filters of the WireGuard interface of the index index of the node n for its state st (see above), in a dynamic
// session: the engine that holds them, which NodeWireGuardRelease closes, or NULL when they could not be made (the node
// log says why). The pairs of Devices that may meet into pairs.
HANDLE NodeWireGuardIsolate(NODE *n, UINT index, const CONTROL_STATE *st, UINT *pairs) {
	FWPM_SESSION0 session;
	HANDLE engine = NULL;
	UINT num_rules = 0;

	*pairs = 0;

	Zero(&session, sizeof(session));
	session.flags = FWPM_SESSION_FLAG_DYNAMIC;
	session.displayData.name = L"Ranz VPN: the WireGuard Devices of a gateway";

	DWORD err = FwpmEngineOpen0(NULL, RPC_C_AUTHN_WINNT, NULL, &session, &engine);
	if (err != ERROR_SUCCESS) {
		NodeLog(n, "WireGuard: the filter engine could not be opened (error 0x%x): two Devices of this gateway are not kept apart", (UINT)err);
		return NULL;
	}

	// The rules of the state in the order of the policy engine
	const CONTROL_RULE **rules = ZeroMalloc(sizeof(CONTROL_RULE *) * MAX(st->NumRules, 1));
	for (UINT i = 0; i < st->NumRules && st->Rules != NULL; i++)
		rules[num_rules++] = &st->Rules[i];
	if (num_rules > 1)
		qsort((void *)rules, num_rules, sizeof(CONTROL_RULE *), NodeWireGuardRuleOrder);

	err = FwpmTransactionBegin0(engine, 0);
	for (UINT f = 0; f < 2 && err == ERROR_SUCCESS; f++)
		err = NodeWireGuardAddFilter(engine, f == 0 ? 4 : 16, index, NULL, NULL);

	// Each pair of Devices of the gateway in one VRF, in each family that both have an address of
	for (UINT i = 0; i < st->NumDevices && st->Devices != NULL && err == ERROR_SUCCESS; i++) {
		const CONTROL_DEVICE *a = &st->Devices[i];

		for (UINT j = i + 1; j < st->NumDevices && err == ERROR_SUCCESS && a->HasKey; j++) {
			const CONTROL_DEVICE *b = &st->Devices[j];
			bool met = false;

			if (b->HasKey == false || b->VrfId != a->VrfId)
				continue;

			for (UINT x = 0; x < a->NumAddresses && err == ERROR_SUCCESS; x++) {
				for (UINT y = 0; y < b->NumAddresses && err == ERROR_SUCCESS; y++) {
					const CONTROL_ADDRESS *aa = &a->Addresses[x];
					const CONTROL_ADDRESS *ba = &b->Addresses[y];

					if (aa->AddressSize != ba->AddressSize || NodeWireGuardAllowsAll(rules, num_rules, a, aa, b, ba) == false ||
					    NodeWireGuardAllowsAll(rules, num_rules, b, ba, a, aa) == false)
						continue;

					err = NodeWireGuardAddFilter(engine, aa->AddressSize, index, aa->Address, ba->Address);
					if (err == ERROR_SUCCESS)
						err = NodeWireGuardAddFilter(engine, aa->AddressSize, index, ba->Address, aa->Address);
					met = true;
				}
			}

			if (met)
				(*pairs)++;
		}
	}

	if (err == ERROR_SUCCESS)
		err = FwpmTransactionCommit0(engine);
	Free((void *)rules);

	if (err != ERROR_SUCCESS) {
		NodeLog(n, "WireGuard: the filters that keep two Devices of this gateway apart could not be added (error 0x%x)", (UINT)err);
		FwpmEngineClose0(engine);
		*pairs = 0;
		return NULL;
	}

	NodeLog(n, "WireGuard: the forwarding between two Devices on interface %u is blocked, but for %u pairs that the policy lets meet", index, *pairs);

	return engine;
}

// Close the engine of NodeWireGuardIsolate, which takes its filters away
void NodeWireGuardRelease(HANDLE engine) {
	if (engine != NULL)
		FwpmEngineClose0(engine);
}
