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
	// The edition of Windows (SDN-12, #188): the product type of the version of the host (VER_NT_WORKSTATION, VER_NT_SERVER
	// or VER_NT_DOMAIN_CONTROLLER; 0 when it cannot be read) and the product that GetProductInfo gives (PRODUCT_*)
	UINT ProductType;
	UINT Product;
	// Hyper-V is present: the service of its Virtual Machine Management, vmms, is registered
	bool HyperV;
	// Routing and Remote Access runs as an IPv4 router of LAN interfaces, whose NAT the node can configure (NodeEgressNat.c)
	bool Rras;
	// The NAT of WinNAT is on the host: the service of its driver, WinNat, is registered
	bool WinNat;
	// A NAT network of WinNAT that is not the node's exists, which WinNAT allows one of per host and Ranz never touches
	// (NodeEgressNat.c), as the last look of the node at the NAT networks of WinNAT saw it; only where Hyper-V and WinNAT
	// are present
	bool NetNat;
} NODE_CAPS_HOST;

// Fill host with what the host that the node runs on holds
void NodeCapsReadHost(NODE_CAPS_HOST *host);

// Fill caps with the Capabilities that a host holding host gives a node: the architecture, and SeLow and the XDP
// runtime where they are all there. Neither exists for any architecture but x64, so another host has none. The Windows
// edition, Hyper-V, and the Egress tier that a node on the host uses as the internet exit of a VRF (SDN-12, #188), the
// first that the host supports: RRAS NAT on a Windows Server whose Routing and Remote Access runs as a LAN router, WinNAT
// where Hyper-V and WinNAT are present and no NAT network of WinNAT exists, and on every other host the proxy on the
// Windows TCP/IP stack (NodeEgress.c). Whether the node can be the gateway of a Stretch of an L2 Network, the Capability
// evpn (SDN-63, #290): a Windows Server does, a workstation does not.
void NodeCapsDecide(const NODE_CAPS_HOST *host, CONTROL_CAPS *caps);

// The procedure of the control client that tells the Capabilities of the node for each Hello (CONTROL_CAPS_PROC): they
// are found on the host again for each stream, so a driver that ranz install added reaches the controller with the next
// one. param is not used.
void NodeCapsProc(void *param, CONTROL_CAPS *caps);

// Set BgpPeering of caps: whether the node n runs the BGP peering of the standard mode (NodePeering.c), which its release has
// and which needs the sidecar, the executable that NODE.BgpSidecar names (ranz.exe next to the node). A node without that file
// never peers, as NodePeering.c only tries to start it again every 5 s, so it must not say that it does: the controller refuses
// to make a node that does not report it a member of a VRF whose peering is bgp (SDN-77-R2, #532), where it would lose the LAN
// routes of the VRF without an error. caps is left as it is when it is NULL, and a NULL node reports none. The file is looked for
// again for each Hello.
void NodeCapsPeering(NODE *n, CONTROL_CAPS *caps);

// Write the Capabilities of the node to its node log, as the line "Capabilities: architecture x64, SeLow yes, XDP no,
// SKU Server, Hyper-V no, egress tier proxy": what ranz install put on the machine is read from there from outside
// (.github/scripts/install.ps1)
void NodeLogCaps(NODE *n);

#endif // NODE_CAPS_H
