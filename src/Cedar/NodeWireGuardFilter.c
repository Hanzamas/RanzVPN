// NodeWireGuardFilter.c
// Two WireGuard Devices of one gateway kept apart (SDN-80, #375; spec #374): a Device reaches another Device only when the
// policy of its VRF allows it, and the policy judges a packet in the overlay of a node (NodePolicy.c). A packet of one
// Device to another Device of the same gateway never reaches the overlay: Windows forwards it on the WireGuard interface
// that it came from, since the address of the other Device is a route through that interface (NodeWireGuard.c). So the
// gateway has the Windows Filtering Platform block that forwarding: a packet that arrived on its WireGuard interface and
// would leave on it again, of either family. The filters are in a dynamic session of the filter engine, so they go when
// the session closes, with the interface or with the process. Two Devices of one gateway therefore never reach each
// other, also where the policy would allow it; Devices of two gateways reach each other through the overlay, which judges
// them by the policy.

#include "Node.h"

#include "Mayaqua/Memory.h"

#include "NodeInternal.h"

// The GUIDs of the layers and of the conditions are defined here, where the filters are made
#include <initguid.h>
#include <fwpmu.h>

// The layer of the forwarding of IPv4 and of IPv6: one filter in each
static const GUID *const node_wg_forward_layers[2] = {&FWPM_LAYER_IPFORWARD_V4, &FWPM_LAYER_IPFORWARD_V6};

// Block the forwarding between two Devices on the WireGuard interface of the index index, for the node n: the engine of the
// dynamic session that holds the filters, which NodeWireGuardRelease closes, or NULL when they could not be made (the node
// log says why)
HANDLE NodeWireGuardIsolate(NODE *n, UINT index) {
	FWPM_SESSION0 session;
	HANDLE engine = NULL;

	Zero(&session, sizeof(session));
	session.flags = FWPM_SESSION_FLAG_DYNAMIC;
	session.displayData.name = L"Ranz VPN: the WireGuard Devices of a gateway";

	DWORD err = FwpmEngineOpen0(NULL, RPC_C_AUTHN_WINNT, NULL, &session, &engine);
	if (err != ERROR_SUCCESS) {
		NodeLog(n, "WireGuard: the filter engine could not be opened (error 0x%x): two Devices of this gateway are not kept apart", (UINT)err);
		return NULL;
	}

	for (UINT i = 0; i < 2; i++) {
		FWPM_FILTER_CONDITION0 cond[2];
		FWPM_FILTER0 filter;
		UINT64 id = 0;

		// The packet arrived on the WireGuard interface, and Windows would forward it out of the same interface
		Zero(cond, sizeof(cond));
		cond[0].fieldKey = FWPM_CONDITION_SOURCE_INTERFACE_INDEX;
		cond[0].matchType = FWP_MATCH_EQUAL;
		cond[0].conditionValue.type = FWP_UINT32;
		cond[0].conditionValue.uint32 = index;
		cond[1].fieldKey = FWPM_CONDITION_DESTINATION_INTERFACE_INDEX;
		cond[1].matchType = FWP_MATCH_EQUAL;
		cond[1].conditionValue.type = FWP_UINT32;
		cond[1].conditionValue.uint32 = index;

		Zero(&filter, sizeof(filter));
		filter.layerKey = *node_wg_forward_layers[i];
		filter.displayData.name = L"Ranz VPN: no forwarding between two WireGuard Devices of a gateway";
		filter.action.type = FWP_ACTION_BLOCK;
		filter.weight.type = FWP_EMPTY;
		filter.numFilterConditions = 2;
		filter.filterCondition = cond;

		err = FwpmFilterAdd0(engine, &filter, NULL, &id);
		if (err != ERROR_SUCCESS) {
			NodeLog(n, "WireGuard: the %s filter that keeps two Devices of this gateway apart could not be added (error 0x%x)", i == 0 ? "IPv4" : "IPv6", (UINT)err);
			FwpmEngineClose0(engine);
			return NULL;
		}
	}

	NodeLog(n, "WireGuard: the forwarding between two Devices on interface %u is blocked", index);

	return engine;
}

// Close the engine of NodeWireGuardIsolate, which takes its filters away
void NodeWireGuardRelease(HANDLE engine) {
	if (engine != NULL)
		FwpmEngineClose0(engine);
}
