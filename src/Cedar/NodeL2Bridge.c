// NodeL2Bridge.c
// The bridge of the L2 adapter (NodeL2.h; CORE-S3-3, #73): an L2 Network joined to a physical NIC, or to a Hyper-V
// virtual network through the host vNIC of its virtual switch, through the same backend interface as the KM-TEST adapter
// (ADR-0018 decision 3, ADR-0022). The host keeps using the NIC: the bridge is one more user of its segment.
// - The backends of a bridge whose owner names none, in this order: SeLow, the bundled default, which sets the NIC
//   promiscuous itself when its device is opened; then Npcap, which the node uses only where the operator installed it,
//   as it is never bundled (NodeL2Npcap.c). XDP is the performance option that the owner names: it carries the frames,
//   and Npcap holds the NIC in promiscuous mode, which XDP cannot set (xdp-for-windows issue #44) (NodeL2Xdp.c).
// - A bridge sends no probe of the receive path, whose Neighbor Solicitations would go onto the LAN, and is never reset:
//   the NIC is the host's, and a restart of its device would cut the host off (NodeL2New).
// - Where a frame of the segment goes (NodeL2BridgeWay): a frame to the MAC address of the NIC is the host's own, a
//   broadcast or multicast frame is for the host and for the others on the segment, any other frame is for the others.
//   SeLow and Npcap see the whole segment, the host's own frames among it, as the protocol driver and the filter driver
//   that they are; the XDP backend takes what comes in from the wire and hands the host back the frames that are its own.
// - The interface of a bridge (NodeL2BridgeIndex): an Ethernet interface named by its alias ("Ethernet") or its GUID.
//   Wi-Fi is refused: an 802.11 station carries no frames of other MAC addresses. A Hyper-V virtual network is reached
//   through the host vNIC of its virtual switch, which Hyper-V names "vEthernet (<switch>)" (NodeL2HyperVIndex). Its
//   port on the switch must allow MAC address spoofing (Set-VMNetworkAdapter -ManagementOS -MacAddressSpoofing On), as
//   the port of any virtual machine that bridges must, or the switch drops the frames of the segment's other addresses;
//   the node cannot read that setting, so it is the operator's step, as it is for such a virtual machine.
// - The physical NIC of an external virtual switch is refused (NodeL2BridgeSwitched): the switch owns it. Hyper-V binds
//   its Hyper-V Extensible Virtual Switch protocol (vms_pp) to it, unbinds the host's own, and sets it promiscuous for
//   the ports of the switch, the host's vNIC among them. A bridge there would take the frames of every port, and an XDP
//   program there would redirect all of them, as the host's addresses are on its vNIC: a bridge attaches to that vNIC.
// - An L2 bridge (NodeL2BridgeNew) joins the segment to an L2 Network: the bridge is the member of a port of the
//   Network's switch (Core/Switch.h), which takes every group of each VLAN that it carries, as a port of a bridge to a
//   LAN does, so the Network's broadcast and multicast frames, and its frames to an address that it has not learnt,
//   reach the segment. The frames that the bridge takes from the segment enter the switch at that port, which learns the
//   addresses of the segment there, so the Network's frames to them go to the bridge alone.

// COBJMACROS: the INetCfg_* call macros of the SDK headers (the COM interfaces are C structs here), before any header
#define COBJMACROS

#include "Node.h"

#include "Mayaqua/Internat.h"
#include "Mayaqua/Memory.h"
#include "Mayaqua/Str.h"

#include "NodeInternal.h"
#include "NodeL2.h"

#include "Core/Switch.h"

#include <devguid.h>
#include <iphlpapi.h>
#include <netcfgx.h>
#include <objbase.h>

// The backends of a bridge whose owner names none, in order, into list, max of them at most: SeLow, the bundled default,
// then Npcap, which binds only where the operator installed it. Returns their number.
UINT NodeL2BridgeBackends(const NODE_L2_BACKEND **list, UINT max) {
	UINT num = 0;

	if (list == NULL)
		return 0;

	if (num < max)
		list[num++] = NodeL2SeLowBackend();
	if (num < max)
		list[num++] = NodeL2NpcapBackend();

	return num;
}

// Where a frame of size bytes on the segment of a bridge goes, whose NIC has the MAC address mac: NODE_L2_TO_HOST for a
// frame to that address, NODE_L2_TO_HOST | NODE_L2_TO_OTHERS for a broadcast or multicast frame (the group bit of its
// destination), NODE_L2_TO_OTHERS for any other. It reads the destination address alone, the first six bytes; a frame
// shorter than that goes to the others.
UINT NodeL2BridgeWay(const UCHAR *frame, UINT size, const UCHAR *mac) {
	if (frame == NULL || size < 6)
		return NODE_L2_TO_OTHERS;

	if ((frame[0] & 0x01) != 0)
		return NODE_L2_TO_HOST | NODE_L2_TO_OTHERS;

	if (mac != NULL && Cmp(frame, mac, 6) == 0)
		return NODE_L2_TO_HOST;

	return NODE_L2_TO_OTHERS;
}

// The unicast addresses of the host on the interface of the adapter a, IPv4 and IPv6, into list, max of them at most:
// the XDP backend of a bridge lets the packets to them pass to the host untouched. Returns their number.
UINT NodeL2BridgeAddresses(NODE_L2 *a, NODE_L2_ADDRESS *list, UINT max) {
	MIB_UNICASTIPADDRESS_TABLE *t = NULL;
	UINT num = 0;

	if (a == NULL || list == NULL || a->Luid == 0 || GetUnicastIpAddressTable(AF_UNSPEC, &t) != NO_ERROR)
		return 0;

	for (ULONG i = 0; i < t->NumEntries && num < max; i++) {
		MIB_UNICASTIPADDRESS_ROW *row = &t->Table[i];
		NODE_L2_ADDRESS *x = &list[num];

		if (row->InterfaceLuid.Value != a->Luid)
			continue;

		Zero(x, sizeof(NODE_L2_ADDRESS));
		if (row->Address.si_family == AF_INET) {
			x->Size = 4;
			Copy(x->Bytes, &row->Address.Ipv4.sin_addr, 4);
		} else if (row->Address.si_family == AF_INET6) {
			x->Size = 16;
			Copy(x->Bytes, &row->Address.Ipv6.sin6_addr, 16);
		} else {
			continue;
		}
		num++;
	}

	FreeMibTable(t);

	return num;
}

// Whether the interface of row can carry a bridge: an Ethernet interface with a MAC address of six bytes. False, with
// why in error, for any other.
static bool NodeL2BridgeUsable(const MIB_IF_ROW2 *row, char *error, UINT error_size) {
	if (row->Type == IF_TYPE_IEEE80211) {
		Format(error, error_size, "interface %u is Wi-Fi: a station of an 802.11 network carries no frames of other MAC addresses", (UINT)row->InterfaceIndex);
		return false;
	}

	if (row->Type != IF_TYPE_ETHERNET_CSMACD || row->PhysicalAddressLength != 6) {
		Format(error, error_size, "interface %u is not an Ethernet interface (type %u, an address of %u bytes)", (UINT)row->InterfaceIndex, (UINT)row->Type, (UINT)row->PhysicalAddressLength);
		return false;
	}

	return true;
}

// Whether an external Hyper-V virtual switch owns the NIC of the interface GUID guid: the network configuration, read
// through INetCfg without a lock, has the Hyper-V Extensible Virtual Switch protocol (vms_pp) bound to it. False on a
// host without that protocol, and where the configuration cannot be read.
static bool NodeL2BridgeSwitched(const GUID *guid) {
	INetCfg *cfg = NULL;
	INetCfgComponent *vms = NULL;
	INetCfgComponentBindings *bindings = NULL;
	IEnumNetCfgComponent *nics = NULL;
	INetCfgComponent *nic = NULL;
	GUID g;
	bool switched = false;

	HRESULT init = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);

	if (SUCCEEDED(CoCreateInstance(&CLSID_CNetCfg, NULL, CLSCTX_INPROC_SERVER, &IID_INetCfg, (void **)&cfg))) {
		if (SUCCEEDED(INetCfg_Initialize(cfg, NULL))) {
			if (INetCfg_FindComponent(cfg, L"vms_pp", &vms) == S_OK &&
			    SUCCEEDED(INetCfgComponent_QueryInterface(vms, &IID_INetCfgComponentBindings, (void **)&bindings)) &&
			    SUCCEEDED(INetCfg_EnumComponents(cfg, &GUID_DEVCLASS_NET, &nics))) {
				while (switched == false && IEnumNetCfgComponent_Next(nics, 1, &nic, NULL) == S_OK) {
					if (SUCCEEDED(INetCfgComponent_GetInstanceGuid(nic, &g)) && IsEqualGUID(&g, guid))
						switched = (INetCfgComponentBindings_IsBoundTo(bindings, nic) == S_OK);
					INetCfgComponent_Release(nic);
				}
			}

			if (nics != NULL)
				IEnumNetCfgComponent_Release(nics);
			if (bindings != NULL)
				INetCfgComponentBindings_Release(bindings);
			if (vms != NULL)
				INetCfgComponent_Release(vms);
			INetCfg_Uninitialize(cfg);
		}
		INetCfg_Release(cfg);
	}

	if (SUCCEEDED(init))
		CoUninitialize();

	return switched;
}

// The interface of a bridge named name (UTF-8): its alias as Windows shows it ("Ethernet", "vEthernet (Lab)"), or its
// GUID in braces. Its index, or 0, with why in error, when no interface has that name or it cannot carry a bridge.
UINT NodeL2BridgeIndex(const char *name, char *error, UINT error_size) {
	wchar_t wide[IF_MAX_STRING_SIZE + 1];
	MIB_IF_ROW2 row;
	NET_LUID luid;
	GUID guid;
	DWORD err;

	StrCpy(error, error_size, "");

	if (name == NULL || IsEmptyStr(name)) {
		StrCpy(error, error_size, "no interface is named");
		return 0;
	}

	Zero(wide, sizeof(wide));
	Utf8ToUni(wide, sizeof(wide), name, StrLen(name));
	Zero(&luid, sizeof(luid));
	if (name[0] == '{' && CLSIDFromString(wide, &guid) == NOERROR)
		err = ConvertInterfaceGuidToLuid(&guid, &luid);
	else
		err = ConvertInterfaceAliasToLuid(wide, &luid);
	if (err != NO_ERROR) {
		Format(error, error_size, "no interface is named %s (error %u)", name, (UINT)err);
		return 0;
	}

	Zero(&row, sizeof(row));
	row.InterfaceLuid = luid;
	err = GetIfEntry2(&row);
	if (err != NO_ERROR) {
		Format(error, error_size, "the interface %s cannot be read (error %u)", name, (UINT)err);
		return 0;
	}

	if (NodeL2BridgeUsable(&row, error, error_size) == false)
		return 0;

	if (NodeL2BridgeSwitched(&row.InterfaceGuid)) {
		Format(error, error_size, "interface %u is the NIC of an external Hyper-V virtual switch, which owns it: a bridge attaches to the host vNIC of that switch, vEthernet (<switch>)", (UINT)row.InterfaceIndex);
		return 0;
	}

	return (UINT)row.InterfaceIndex;
}

// The host vNIC of the Hyper-V virtual switch named name (UTF-8): the interface that Hyper-V names "vEthernet (<switch>)"
// when it gives the host a port on the switch, as it does for an internal switch and for an external one that the host
// shares. Its index, or 0, with why in error: a private switch, or an external one that the host does not share, gives
// the host no vNIC, and Add-VMNetworkAdapter -ManagementOS -SwitchName adds one.
UINT NodeL2HyperVIndex(const char *name, char *error, UINT error_size) {
	char alias[MAX_SIZE];
	char why[MAX_SIZE];

	StrCpy(error, error_size, "");

	if (name == NULL || IsEmptyStr(name)) {
		StrCpy(error, error_size, "no Hyper-V virtual switch is named");
		return 0;
	}

	Format(alias, sizeof(alias), "vEthernet (%s)", name);
	UINT index = NodeL2BridgeIndex(alias, why, sizeof(why));
	if (index == 0)
		Format(error, error_size, "the host has no vNIC of the Hyper-V virtual switch %s (%s): a private switch, or an external one that the host does not share, gives it none; Add-VMNetworkAdapter -ManagementOS -SwitchName adds one", name, why);

	return index;
}

// An L2 bridge: a bridge of the L2 adapter as the member of a port of the switch of an L2 Network (NodeL2BridgeNew)
struct NODE_L2_BRIDGE {
	NODE *Node;
	// The switch, and the port of the bridge on it
	SWITCH *Switch;
	UINT Port;
	// The L2 adapter in bridge mode, NULL once it goes, and the lock that keeps it from the deliveries of the switch
	SRWLOCK Lock;
	NODE_L2 *Adapter;
};

// A frame that the bridge took from the segment (NODE_L2_PROC), on the I/O thread of its adapter queue: into the switch at
// the port of the bridge, which learns its source there
static void NodeL2BridgeFromSegment(NODE_L2 *a, void *param, const UCHAR *frame, UINT size) {
	NODE_L2_BRIDGE *b = (NODE_L2_BRIDGE *)param;

	SwitchInput(b->Switch, GetTickCount64(), b->Port, frame, size);
}

// A frame that the switch hands the port of the bridge (SWITCH_SEND_PROC), on the thread of SwitchInput: onto the segment,
// through the send ring of the adapter, which never waits
static void NodeL2BridgeToSegment(void *param, UINT port, const UCHAR *frame, UINT size) {
	NODE_L2_BRIDGE *b = (NODE_L2_BRIDGE *)param;

	AcquireSRWLockShared(&b->Lock);
	if (b->Adapter != NULL)
		NodeL2Send(b->Adapter, frame, size);
	ReleaseSRWLockShared(&b->Lock);
}

// Subscribe the port of the bridge to every group of each VLAN of the membership pc: the VLAN of an access port, or the
// native VLAN and the allowed list of a trunk port. False when a subscription fails.
static bool NodeL2BridgeSubscribe(NODE_L2_BRIDGE *b, const SWITCH_PORT_CONFIG *pc) {
	if (pc->Mode != SWITCH_TRUNK)
		return SwitchSubscribe(b->Switch, b->Port, pc->Vlan, NULL);

	if (pc->Vlan != 0 && SwitchSubscribe(b->Switch, b->Port, pc->Vlan, NULL) == false)
		return false;
	for (UINT i = 0; i < pc->NumAllowed; i++)
		if (SwitchSubscribe(b->Switch, b->Port, pc->Allowed[i], NULL) == false)
			return false;

	return true;
}

// The L2 bridge of the L2 Network whose switch is sw, on the running node n (CORE-S3-3, #73): the L2 adapter of cfg in
// bridge mode, on its NIC or the host vNIC of a Hyper-V virtual switch (NodeL2BridgeIndex, NodeL2HyperVIndex), as the
// member of a port of the membership port, which takes every group of each VLAN that it carries. The procedures of the
// adapter (cfg->Proc, Param) and of the port (port->Send, Param) are the bridge's own. NULL when the switch gives no such
// port or no backend binds; the node log says why.
NODE_L2_BRIDGE *NodeL2BridgeNew(NODE *n, struct SWITCH *sw, const struct SWITCH_PORT_CONFIG *port, const NODE_L2_CONFIG *cfg) {
	SWITCH_PORT_CONFIG pc;
	NODE_L2_CONFIG c;

	if (n == NULL || sw == NULL || port == NULL || cfg == NULL)
		return NULL;

	NODE_L2_BRIDGE *b = ZeroMalloc(sizeof(NODE_L2_BRIDGE));
	b->Node = n;
	b->Switch = sw;
	InitializeSRWLock(&b->Lock);

	pc = *port;
	pc.Send = NodeL2BridgeToSegment;
	pc.Param = b;
	b->Port = SwitchAddPort(sw, &pc);
	if (b->Port == SWITCH_PORT_NONE || NodeL2BridgeSubscribe(b, &pc) == false) {
		NodeLog(n, "L2 bridge of interface %u not created: the switch gives it no port that takes every group of its VLANs", cfg->IfIndex);
		if (b->Port != SWITCH_PORT_NONE)
			SwitchDelPort(sw, b->Port);
		Free(b);
		return NULL;
	}

	c = *cfg;
	c.Bridge = true;
	c.Proc = NodeL2BridgeFromSegment;
	c.Param = b;
	NODE_L2 *a = NodeL2New(n, &c);
	if (a == NULL) {
		SwitchDelPort(sw, b->Port);
		Free(b);
		return NULL;
	}

	AcquireSRWLockExclusive(&b->Lock);
	b->Adapter = a;
	ReleaseSRWLockExclusive(&b->Lock);

	NodeLog(n, "L2 bridge of interface %u: the member of port %u of the switch of its Network, %s", cfg->IfIndex, b->Port, pc.Mode == SWITCH_TRUNK ? "a trunk port" : "an access port");

	return b;
}

// Take an L2 bridge off its switch and down: the switch hands it nothing more, its adapter goes (NodeL2Free), then its
// port. False when a step of the adapter did not finish in time: the bridge is then left as it is, holding its port, as a
// thread of its adapter may still run on it.
bool NodeL2BridgeFree(NODE_L2_BRIDGE *b) {
	if (b == NULL)
		return true;

	AcquireSRWLockExclusive(&b->Lock);
	NODE_L2 *a = b->Adapter;
	b->Adapter = NULL;
	ReleaseSRWLockExclusive(&b->Lock);

	if (NodeL2Free(a) == false)
		return false;

	SwitchDelPort(b->Switch, b->Port);
	Free(b);

	return true;
}

// The port of an L2 bridge on the switch of its Network, SWITCH_PORT_NONE for none
UINT NodeL2BridgePort(NODE_L2_BRIDGE *b) {
	return (b != NULL ? b->Port : SWITCH_PORT_NONE);
}

// The status of the adapter of an L2 bridge (NodeL2GetStatus)
void NodeL2BridgeGetStatus(NODE_L2_BRIDGE *b, NODE_L2_STATUS *st) {
	if (st == NULL)
		return;

	if (b == NULL) {
		Zero(st, sizeof(NODE_L2_STATUS));
		return;
	}

	AcquireSRWLockShared(&b->Lock);
	NodeL2GetStatus(b->Adapter, st);
	ReleaseSRWLockShared(&b->Lock);
}
