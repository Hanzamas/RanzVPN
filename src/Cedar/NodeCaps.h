// NodeCaps.h
// The Capabilities of a node (NodeCaps.c; ADR-0033; ONE-3, #312): what its host holds, as the node tells it to the
// controller in the Hello of its control stream and writes to its node log

#ifndef NODE_CAPS_H
#define NODE_CAPS_H

#include "CedarType.h"

#include "Core/Control.h"

// What a host holds that tells the Capabilities of a node: NodeCapsReadHost finds it on the host that the node runs on,
// and a test of the decision (NodeCapsDecide) gives it by hand
typedef struct NODE_CAPS_HOST {
	// The processor architecture of the host, PROCESSOR_ARCHITECTURE_AMD64 or PROCESSOR_ARCHITECTURE_ARM64 or another
	UINT Machine;
	// The service SeLow is registered
	bool SeLowService;
	// The driver of SeLow, drivers\SeLow_x64.sys of System32, is on the host
	bool SeLowDriver;
	// The service xdp is registered
	bool XdpService;
	// The driver of the XDP runtime, drivers\xdp.sys of System32, is on the host
	bool XdpDriver;
	// The API library of the XDP runtime, xdpapi.dll of System32, is on the host
	bool XdpApi;
} NODE_CAPS_HOST;

// Fill host with what the host that the node runs on holds
void NodeCapsReadHost(NODE_CAPS_HOST *host);

// Fill caps with the Capabilities that a host holding host gives a node: the architecture, and SeLow and the XDP
// runtime where they are all there. Neither exists for any architecture but x64, so another host has none.
void NodeCapsDecide(const NODE_CAPS_HOST *host, CONTROL_CAPS *caps);

// The procedure of the control client that tells the Capabilities of the node for each Hello (CONTROL_CAPS_PROC): they
// are found on the host again for each stream, so a driver that ranz install added reaches the controller with the next
// one. param is not used.
void NodeCapsProc(void *param, CONTROL_CAPS *caps);

// Write the Capabilities of the node to its node log, as the line "Capabilities: architecture x64, SeLow yes, XDP no":
// what ranz install put on the machine is read from there from outside (.github/scripts/install.ps1)
void NodeLogCaps(NODE *n);

#endif // NODE_CAPS_H
