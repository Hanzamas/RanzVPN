// NodeOperation.c
// The live operations of the Controller on a node (SDN-50-N, #492; ADR-0027 and ADR-0031 amendments of 2026-10-27): an
// operator reads or clears the MAC table or the IP table of an L2 Network, and the Controller asks each node that holds the
// Network with an Operation on its control stream (Core/Control.h, ControlOperation.c), which answers no-network by itself
// for a Network that the desired state does not give the node as an L2 Network. The tables of a Network are the ones of its
// switch (Core/Switch.h), which the L2 data path of the node attaches while the overlay runs (NodeOperationAttach), with a
// procedure that names the member of each of its ports; the control stream hands each Operation to the node on its thread
// (NodeOperationProc), and the node reads or clears that switch:
// - a read gives the first CONTROL_MAX_ENTRIES entries of the table by VLAN, then by address, and how many the table holds:
//   each with its VLAN, its MAC address, for the IP table its address, the member of its port and the time of its last
//   frame in Unix time (the switch of a node runs on GetTickCount64, as SwitchInput takes it);
// - a clear takes out every entry of the table, or the entries of the MAC address or of the address that it names, in every
//   VLAN, and gives their number; the traffic that follows learns the entries again.
// A Network whose switch the L2 data path has not attached has no tables on the node: the answer says so, as failed. Each
// operation goes to the node log, with what it did.

#include "Node.h"

#include "Mayaqua/Memory.h"
#include "Mayaqua/Object.h"
#include "Mayaqua/Str.h"

#include "Core/Control.h"
#include "Core/Switch.h"

#include "NodeInternal.h"

// The switch of one L2 Network, as the L2 data path attached it
typedef struct NODE_OPERATION_NETWORK {
	char Name[CONTROL_NAME_SIZE]; // The L2 Network
	SWITCH *Switch;               // Its switch
	NODE_PORT_NAME_PROC *Member;  // Names the member of each of its ports, NULL for "port <number>" ...
	void *Param;                  // ... with this first parameter
} NODE_OPERATION_NETWORK;

// The switches of the L2 Networks of a node, while its overlay runs (NODE.Operations)
typedef struct NODE_OPERATIONS {
	LOCK *Lock;     // Networks, held while an operation reads or clears a switch, so that the L2 data path detaches none then
	LIST *Networks; // The Networks whose switch the L2 data path attached (NODE_OPERATION_NETWORK)
} NODE_OPERATIONS;

// The Unix time in ms
static UINT64 NodeOperationUnixNow() {
	FILETIME ft;

	GetSystemTimeAsFileTime(&ft);
	UINT64 t = ((UINT64)ft.dwHighDateTime << 32) | ft.dwLowDateTime;
	// 100 ns since 1601 to ms since 1970
	return (t - 116444736000000000ULL) / 10000;
}

// The Unix time in ms of the time at of a switch of the node, which runs on GetTickCount64, now being its time and unix_now
// the Unix time: 0 for none
static UINT64 NodeOperationTime(UINT64 at, UINT64 now, UINT64 unix_now) {
	if (at == 0)
		return 0;

	UINT64 ago = (now > at ? now - at : 0);
	return (ago < unix_now ? unix_now - ago : 0);
}

// The entry of the Network name, NULL for none. The caller holds the lock.
static NODE_OPERATION_NETWORK *NodeOperationNetwork(NODE_OPERATIONS *ops, const char *name) {
	for (UINT i = 0; i < LIST_NUM(ops->Networks); i++) {
		NODE_OPERATION_NETWORK *net = LIST_DATA(ops->Networks, i);

		if (StrCmp(net->Name, name) == 0)
			return net;
	}

	return NULL;
}

// The name of the member of port into name of size bytes: the one that the procedure of the Network gives, "" for none, or
// "port <number>" for a Network without one
static void NodeOperationMember(NODE_OPERATION_NETWORK *net, UINT port, char *name, UINT size) {
	name[0] = 0;
	if (net->Member != NULL)
		net->Member(net->Param, port, name, size);
	else
		Format(name, size, "port %u", port);
	name[size - 1] = 0;
}

// A read of the MAC table of the Network into res
static void NodeOperationMacs(NODE_OPERATION_NETWORK *net, CONTROL_OPERATION_RESULT *res) {
	SWITCH_MAC_ENTRY *list = Malloc(sizeof(SWITCH_MAC_ENTRY) * CONTROL_MAX_ENTRIES);
	SWITCH_STATS st;
	UINT64 now = GetTickCount64();
	UINT64 unix_now = NodeOperationUnixNow();

	UINT num = SwitchGetMacs(net->Switch, list, CONTROL_MAX_ENTRIES);
	SwitchGetStats(net->Switch, &st);

	for (UINT i = 0; i < num; i++) {
		CONTROL_TABLE_ENTRY *e = &res->Entries[i];

		e->Vlan = list[i].Vlan;
		Copy(e->Mac, list[i].Mac, sizeof(e->Mac));
		NodeOperationMember(net, list[i].Port, e->Member, sizeof(e->Member));
		e->LastSeen = NodeOperationTime(list[i].LastSeen, now, unix_now);
	}
	res->NumEntries = num;
	// The table may learn more while it is read: it holds at least the entries that the read gave
	res->Total = MAX(st.NumMacs, num);
	res->Status = CONTROL_OPERATION_OK;

	Free(list);
}

// A read of the IP table of the Network into res
static void NodeOperationIps(NODE_OPERATION_NETWORK *net, CONTROL_OPERATION_RESULT *res) {
	SWITCH_IP_ENTRY *list = Malloc(sizeof(SWITCH_IP_ENTRY) * CONTROL_MAX_ENTRIES);
	SWITCH_STATS st;
	UINT64 now = GetTickCount64();
	UINT64 unix_now = NodeOperationUnixNow();

	UINT num = SwitchGetIps(net->Switch, list, CONTROL_MAX_ENTRIES);
	SwitchGetStats(net->Switch, &st);

	for (UINT i = 0; i < num; i++) {
		CONTROL_TABLE_ENTRY *e = &res->Entries[i];

		e->Vlan = list[i].Vlan;
		Copy(e->Mac, list[i].Mac, sizeof(e->Mac));
		e->AddressSize = list[i].AddressSize;
		Copy(e->Address, list[i].Address, sizeof(e->Address));
		NodeOperationMember(net, list[i].Port, e->Member, sizeof(e->Member));
		e->LastSeen = NodeOperationTime(list[i].LastSeen, now, unix_now);
	}
	res->NumEntries = num;
	res->Total = MAX(st.NumIps, num);
	res->Status = CONTROL_OPERATION_OK;

	Free(list);
}

// What an operation does, as the node log says it
static const char *NodeOperationWhat(UINT kind) {
	switch (kind) {
	case CONTROL_OPERATION_MAC_TABLE:
		return "a read of the MAC table";
	case CONTROL_OPERATION_CLEAR_MAC_TABLE:
		return "a clear of the MAC table";
	case CONTROL_OPERATION_IP_TABLE:
		return "a read of the IP table";
	case CONTROL_OPERATION_CLEAR_IP_TABLE:
		return "a clear of the IP table";
	default:
		return "an operation of no kind";
	}
}

// Start the live operations with the overlay of a node: no switch is attached yet
void NodeOperationStart(NODE *n) {
	if (n == NULL || n->Operations != NULL)
		return;

	NODE_OPERATIONS *ops = ZeroMalloc(sizeof(NODE_OPERATIONS));
	ops->Lock = NewLock();
	ops->Networks = NewListFast(NULL);
	n->Operations = ops;
}

// Stop them once the control stream that hands them the Operations stopped: no switch is read any more
void NodeOperationStop(NODE *n) {
	NODE_OPERATIONS *ops = (n != NULL ? n->Operations : NULL);

	if (ops == NULL)
		return;

	n->Operations = NULL;
	for (UINT i = 0; i < LIST_NUM(ops->Networks); i++)
		Free(LIST_DATA(ops->Networks, i));
	ReleaseList(ops->Networks);
	DeleteLock(ops->Lock);
	Free(ops);
}

// The procedure of the control stream for each Operation of the Controller (CONTROL_OPERATION_PROC): the read or the clear of
// a table of the switch of the L2 Network that it names, which the desired state gives the node. param is the node.
void NodeOperationProc(void *param, const CONTROL_OPERATION *op, CONTROL_OPERATION_RESULT *res) {
	NODE *n = (NODE *)param;
	NODE_OPERATIONS *ops = (n != NULL ? n->Operations : NULL);

	if (op == NULL || res == NULL)
		return;

	if (ops == NULL) {
		res->Status = CONTROL_OPERATION_FAILED;
		StrCpy(res->Message, sizeof(res->Message), "the overlay of the node does not run");
		return;
	}

	Lock(ops->Lock);
	{
		NODE_OPERATION_NETWORK *net = NodeOperationNetwork(ops, op->Network);

		if (net == NULL) {
			res->Status = CONTROL_OPERATION_FAILED;
			StrCpy(res->Message, sizeof(res->Message), "the L2 data path of the node has not attached the switch of the Network, so the node holds no table of it yet");
		} else if (op->Kind == CONTROL_OPERATION_MAC_TABLE) {
			NodeOperationMacs(net, res);
		} else if (op->Kind == CONTROL_OPERATION_IP_TABLE) {
			NodeOperationIps(net, res);
		} else if (op->Kind == CONTROL_OPERATION_CLEAR_MAC_TABLE) {
			res->Total = (op->HasMac ? SwitchClearMac(net->Switch, op->Mac) : SwitchClearMacs(net->Switch));
			res->Status = CONTROL_OPERATION_OK;
		} else {
			res->Total = SwitchClearIps(net->Switch, (op->AddressSize != 0 ? op->Address : NULL), op->AddressSize);
			res->Status = CONTROL_OPERATION_OK;
		}
	}
	Unlock(ops->Lock);

	if (res->Status == CONTROL_OPERATION_OK)
		NodeLog(n, "Operation %I64u of the Controller: %s of the L2 Network %s, %u entries", op->Id, NodeOperationWhat(op->Kind), op->Network, res->Total);
	else
		NodeLog(n, "Operation %I64u of the Controller: %s of the L2 Network %s failed: %s", op->Id, NodeOperationWhat(op->Kind), op->Network, res->Message);
}

// The L2 data path attaches the switch sw of the L2 Network network, which the live operations then read and clear, naming
// the member of each of its ports by name with param (NULL for "port <number>"). It takes the place of a switch attached
// before. False when the overlay does not run.
bool NodeOperationAttach(NODE *n, const char *network, SWITCH *sw, NODE_PORT_NAME_PROC *name, void *param) {
	NODE_OPERATIONS *ops = (n != NULL ? n->Operations : NULL);

	if (ops == NULL || IsEmptyStr(network) || StrLen(network) >= CONTROL_NAME_SIZE || sw == NULL)
		return false;

	Lock(ops->Lock);
	{
		NODE_OPERATION_NETWORK *net = NodeOperationNetwork(ops, network);

		if (net == NULL) {
			net = ZeroMalloc(sizeof(NODE_OPERATION_NETWORK));
			StrCpy(net->Name, sizeof(net->Name), network);
			Add(ops->Networks, net);
		}
		net->Switch = sw;
		net->Member = name;
		net->Param = param;
	}
	Unlock(ops->Lock);

	return true;
}

// The L2 data path detaches the switch of the L2 Network network before it frees it: once this returns, no operation reads
// it
void NodeOperationDetach(NODE *n, const char *network) {
	NODE_OPERATIONS *ops = (n != NULL ? n->Operations : NULL);

	if (ops == NULL || network == NULL)
		return;

	Lock(ops->Lock);
	{
		NODE_OPERATION_NETWORK *net = NodeOperationNetwork(ops, network);

		if (net != NULL) {
			Delete(ops->Networks, net);
			Free(net);
		}
	}
	Unlock(ops->Lock);
}
