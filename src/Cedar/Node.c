// Node.c
// The node of the new core (ADR-0011): one process, the ranzvpnserver service of ranz-node, that runs the
// roles of its configuration over the per-core workers and adapter queues of NodeWorker.c and the table
// snapshot of NodeTable.c. It reuses the fork's Hub, Account, Sam, Logging and Cfg modules in-process.

#include "Node.h"

#include "Cedar.h"
#include "Hub.h"
#include "Sam.h"
#include "Server.h"

#include "Mayaqua/Cfg.h"
#include "Mayaqua/FileIO.h"
#include "Mayaqua/Internat.h"
#include "Mayaqua/Memory.h"
#include "Mayaqua/Object.h"
#include "Mayaqua/Str.h"

#include "NodeInternal.h"

// Starts a role while the node runs: false when it cannot run. The caller holds the node lock.
typedef bool(NODE_ROLE_START)(NODE *n);
// Stops a role and releases what its start took. The caller holds the node lock.
typedef void(NODE_ROLE_STOP)(NODE *n);

// One role: its bit, its name in the configuration and the node log, and how it starts and stops
typedef struct NODE_ROLE_DEF {
	UINT Role;              // NODE_ROLE_*
	char *Name;             // The name in the Roles item of the configuration
	NODE_ROLE_START *Start; // Starts the role
	NODE_ROLE_STOP *Stop;   // Stops the role
} NODE_ROLE_DEF;

static bool NodeServerStart(NODE *n);
static void NodeServerStop(NODE *n);
static bool NodeEmptyRoleStart(NODE *n);
static void NodeEmptyRoleStop(NODE *n);

// The roles in start order; they stop in the reverse order. The client, bridge and relay roles hold nothing
// yet: their adapter queues and transports come with CORE-S3-1 (#71), CORE-S3-3 (#73) and CORE-S5-2 (#78).
static NODE_ROLE_DEF node_roles[] =
    {
        {NODE_ROLE_SERVER, "server", NodeServerStart, NodeServerStop},
        {NODE_ROLE_CLIENT, "client", NodeEmptyRoleStart, NodeEmptyRoleStop},
        {NODE_ROLE_BRIDGE, "bridge", NodeEmptyRoleStart, NodeEmptyRoleStop},
        {NODE_ROLE_RELAY, "relay", NodeEmptyRoleStart, NodeEmptyRoleStop},
};

#define NODE_NUM_ROLES ((UINT)(sizeof(node_roles) / sizeof(node_roles[0])))

// Write a line to the node log
void NodeLog(NODE *n, const char *fmt, ...) {
	char tmp[MAX_SIZE * 2];
	va_list args;
	if (n == NULL || fmt == NULL)
		return;

	va_start(args, fmt);
	FormatArgs(tmp, sizeof(tmp), fmt, args);
	va_end(args);

	InsertStringRecord(n->Log, tmp);
}

// The bit of the role named name, compared without case; 0 when no role has that name
static UINT NodeRoleByName(char *name) {
	for (UINT i = 0; i < NODE_NUM_ROLES; i++)
		if (StrCmpi(name, node_roles[i].Name) == 0)
			return node_roles[i].Role;

	return 0;
}

// The roles of a list of role names, separated by commas or spaces and compared without case; "none" names no
// role (a Cfg file cannot hold an empty string). The names that are no role go to unknown, comma-separated, when
// it is not NULL.
UINT NodeParseRoles(char *str, char *unknown, UINT unknown_size) {
	UINT roles = 0;

	if (unknown != NULL)
		StrCpy(unknown, unknown_size, "");

	if (str == NULL)
		return 0;

	TOKEN_LIST *t = ParseToken(str, ", \t");

	for (UINT i = 0; i < t->NumTokens; i++) {
		UINT role = NodeRoleByName(t->Token[i]);

		if (role != 0) {
			roles |= role;
		} else if (StrCmpi(t->Token[i], "none") == 0) {
			continue;
		} else if (unknown != NULL) {
			if (IsEmptyStr(unknown) == false)
				StrCat(unknown, unknown_size, ",");
			StrCat(unknown, unknown_size, t->Token[i]);
		}
	}

	FreeToken(t);

	return roles;
}

// The names of the roles, comma-separated in start order; "none" for no role
void NodeRolesToStr(char *str, UINT size, UINT roles) {
	if (str == NULL)
		return;

	StrCpy(str, size, "");

	for (UINT i = 0; i < NODE_NUM_ROLES; i++) {
		if ((roles & node_roles[i].Role) == 0)
			continue;

		if (IsEmptyStr(str) == false)
			StrCat(str, size, ", ");
		StrCat(str, size, node_roles[i].Name);
	}

	if (IsEmptyStr(str))
		StrCpy(str, size, "none");
}

// The data directory of a node created without one: the directory of the executable, as for the fork's
// server, until the configuration module (CORE-F5, #65) moves new-core data to ProgramData
void NodeDefaultDataDir(wchar_t *dir, UINT size) {
	if (dir == NULL)
		return;

	GetExeDirW(dir, size);
}

// Log the names of the Roles item that are no role
static void NodeLogUnknownRoles(NODE *n, char *unknown) {
	TOKEN_LIST *t = ParseToken(unknown, ",");

	for (UINT i = 0; i < t->NumTokens; i++) {
		if (StrCmpi(t->Token[i], "controller") == 0)
			NodeLog(n, "Role controller ignored: the controller is the ranz-controller service, not a role of the node (#176)");
		else
			NodeLog(n, "Role %s ignored: no such role", t->Token[i]);
	}

	FreeToken(t);
}

// Read the configuration (NODE_CONFIG_FILE_NAME in the data directory, a Cfg text file): the Roles item, a
// list of role names (without the item NODE_DEFAULT_ROLES, "none" for no role), and NumWorkers, the number of
// workers (0 for one per core). The Hubs folder is read by the server role.
static void NodeLoadConfig(NODE *n) {
	wchar_t path[MAX_PATH];
	char roles[MAX_SIZE];
	char unknown[MAX_SIZE];

	ConbinePathW(path, sizeof(path), n->DataDir, NODE_CONFIG_FILE_NAME);

	n->Config = CfgReadW(path);
	n->ConfigRoles = NODE_DEFAULT_ROLES;
	n->ConfigWorkers = 0;

	if (n->Config == NULL) {
		NodeLog(n, "No configuration in %S: the default roles", path);
		return;
	}

	if (CfgIsItem(n->Config, "Roles")) {
		CfgGetStr(n->Config, "Roles", roles, sizeof(roles));
		n->ConfigRoles = NodeParseRoles(roles, unknown, sizeof(unknown));

		if (IsEmptyStr(unknown) == false)
			NodeLogUnknownRoles(n, unknown);
	}

	UINT num_workers = CfgGetInt(n->Config, "NumWorkers");
	n->ConfigWorkers = MIN(num_workers, NODE_MAX_WORKERS);

	NodeLog(n, "Configuration %S read", path);
}

// A node with its data directory (NULL for NodeDefaultDataDir). It opens the node log and reads the
// configuration, but starts nothing until NodeStart.
NODE *NewNode(wchar_t *data_dir) {
	wchar_t log_dir_w[MAX_PATH];
	char log_dir[MAX_PATH];

	NODE *n = ZeroMalloc(sizeof(NODE));
	n->Lock = NewLock();
	n->TableLock = NewLock();
	n->ReaderList = NewListFast(NULL);
	n->QueueList = NewListFast(NULL);
	n->HubList = NewListFast(NULL);

	// An online reader never publishes epoch 0, which means offline
	n->Epoch = 1;

	if (UniIsEmptyStr(data_dir))
		NodeDefaultDataDir(n->DataDir, sizeof(n->DataDir));
	else
		UniStrCpy(n->DataDir, sizeof(n->DataDir), data_dir);

	MakeDirExW(n->DataDir);

	ConbinePathW(log_dir_w, sizeof(log_dir_w), n->DataDir, NODE_LOG_DIR_NAME);
	UniToStr(log_dir, sizeof(log_dir), log_dir_w);
	n->Log = NewLog(log_dir, NODE_LOG_PREFIX, LOG_SWITCH_DAY, 0);

	n->Cedar = NewCedar(NULL, NULL);

	NodeLoadConfig(n);

	return n;
}

// Stop the node if it runs and free it
void FreeNode(NODE *n) {
	if (n == NULL)
		return;

	NodeStop(n);

	CfgDeleteFolder(n->Config);
	ReleaseCedar(n->Cedar);

	// The last lines of the node log are written before FreeLog returns
	FreeLog(n->Log);

	ReleaseList(n->HubList);
	ReleaseList(n->QueueList);
	ReleaseList(n->ReaderList);

	DeleteLock(n->TableLock);
	DeleteLock(n->Lock);

	Free(n);
}

// Stop the running roles that roles leaves out, last first, then start the roles that it adds, in order.
// The caller holds the node lock.
static void NodeApplyRoles(NODE *n, UINT roles) {
	for (UINT i = NODE_NUM_ROLES; i > 0; i--) {
		NODE_ROLE_DEF *d = &node_roles[i - 1];

		if ((n->Roles & d->Role) != 0 && (roles & d->Role) == 0) {
			d->Stop(n);
			n->Roles &= ~d->Role;
			NodeLog(n, "Role %s stopped", d->Name);
		}
	}

	for (UINT i = 0; i < NODE_NUM_ROLES; i++) {
		NODE_ROLE_DEF *d = &node_roles[i];

		if ((n->Roles & d->Role) == 0 && (roles & d->Role) != 0) {
			if (d->Start(n)) {
				n->Roles |= d->Role;
				NodeLog(n, "Role %s started", d->Name);
			} else {
				NodeLog(n, "Role %s could not start", d->Name);
			}
		}
	}
}

// Start the node: the table snapshot, the workers, then the roles of the configuration. False when it runs
// already or no worker could start.
bool NodeStart(NODE *n) {
	char roles[MAX_SIZE];
	bool ret = false;
	if (n == NULL)
		return false;

	Lock(n->Lock);
	{
		if (n->Running == false) {
			NodeTablesStart(n);

			if (NodeStartWorkers(n)) {
				n->Running = true;
				NodeLog(n, "Node started: data directory %S, %u workers", n->DataDir, n->NumWorkers);

				NodeApplyRoles(n, n->ConfigRoles);

				NodeRolesToStr(roles, sizeof(roles), n->Roles);
				NodeLog(n, "Node roles: %s", roles);

				ret = true;
			} else {
				NodeStopWorkers(n);
				NodeTablesStop(n);
				NodeLog(n, "Node not started: no worker could start");
			}
		}
	}
	Unlock(n->Lock);

	return ret;
}

// Stop the node: the roles, last first, the adapter queues that are still attached, the workers and the
// table snapshot. Every thread of the node is joined before it returns.
void NodeStop(NODE *n) {
	if (n == NULL)
		return;

	Lock(n->Lock);
	{
		if (n->Running) {
			UINT num_workers = n->NumWorkers;

			NodeApplyRoles(n, 0);

			UINT num_queues = NodeDelAllQueues(n);

			NodeStopWorkers(n);
			NodeTablesStop(n);

			n->Running = false;
			NodeLog(n, "Node stopped: %u workers joined, %u adapter queues detached", num_workers, num_queues);
		}
	}
	Unlock(n->Lock);
}

// Switch the running node to the role set roles, as the control plane does: the running roles that it leaves
// out stop, the new ones start. Returns the roles that run afterwards.
UINT NodeSetRoles(NODE *n, UINT roles) {
	char tmp[MAX_SIZE];
	UINT ret = 0;
	if (n == NULL)
		return 0;

	Lock(n->Lock);
	{
		if (n->Running) {
			NodeApplyRoles(n, roles & NODE_ROLE_ALL);

			NodeRolesToStr(tmp, sizeof(tmp), n->Roles);
			NodeLog(n, "Node roles: %s", tmp);
		}

		ret = n->Roles;
	}
	Unlock(n->Lock);

	return ret;
}

// The state of the node
void NodeGetStatus(NODE *n, NODE_STATUS *st) {
	if (st == NULL)
		return;

	Zero(st, sizeof(NODE_STATUS));

	if (n == NULL)
		return;

	Lock(n->Lock);
	{
		st->Running = n->Running;
		st->Roles = n->Roles;
		st->NumWorkers = n->NumWorkers;
		st->NumQueues = LIST_NUM(n->QueueList);
		st->NumHubs = LIST_NUM(n->HubList);
	}
	Unlock(n->Lock);

	// Read without the table lock, which a swap holds while it waits for its readers
	st->NumReaders = LIST_NUM(n->ReaderList);
	st->Generation = (UINT64)ReadAcquire64(&n->Generation);
}

// Bring the Hub name of the configuration online in the Cedar of the node: a fork Hub with the default options
// of a new hub. The caller holds the node lock.
static void NodeAddHub(NODE *n, char *name) {
	HUB_OPTION o;

	if (IsEmptyStr(name) || StrLen(name) > MAX_HUBNAME_LEN || IsSafeStr(name) == false || IsHub(n->Cedar, name)) {
		NodeLog(n, "Hub %s ignored: not a valid hub name, or a hub of that name runs", name);
		return;
	}

	Zero(&o, sizeof(o));
	SiSetDefaultHubOption(&o);

	HUB *h = NewHub(n->Cedar, name, &o);
	AddHub(n->Cedar, h);
	HubApplyInitialState(h, true);

	// The reference of NewHub stays in the list until the role stops
	Add(n->HubList, h);

	NodeLog(n, "Hub %s online", h->Name);
}

// The server role: the Hubs of the configuration, one folder each under Hubs, or the DEFAULT hub when the
// configuration names none. The sessions of the QUIC and TLS transports (CORE-S1-1 #67, CORE-S2-1 #69) end
// in them.
static bool NodeServerStart(NODE *n) {
	TOKEN_LIST *names = CfgEnumFolderToTokenList(CfgFindFolder(n->Config, "Hubs"));

	if (names == NULL || names->NumTokens == 0) {
		NodeAddHub(n, SERVER_DEFAULT_HUB_NAME);
	} else {
		for (UINT i = 0; i < names->NumTokens; i++)
			NodeAddHub(n, names->Token[i]);
	}

	FreeToken(names);

	return (LIST_NUM(n->HubList) != 0);
}

// Stop the Hubs of the server role and release them
static void NodeServerStop(NODE *n) {
	for (UINT i = 0; i < LIST_NUM(n->HubList); i++) {
		HUB *h = LIST_DATA(n->HubList, i);

		StopHub(h);
		DelHub(n->Cedar, h);

		NodeLog(n, "Hub %s stopped", h->Name);

		ReleaseHub(h);
	}

	DeleteAll(n->HubList);
}

// A role that holds nothing yet: it starts and stops at once
static bool NodeEmptyRoleStart(NODE *n) {
	return (n != NULL);
}

static void NodeEmptyRoleStop(NODE *n) {
	// Nothing to release
	return;
}

// The Hub name of the server role, referenced (ReleaseHub); NULL when the server role does not run it
HUB *NodeGetHub(NODE *n, char *name) {
	HUB *ret = NULL;
	if (n == NULL || name == NULL)
		return NULL;

	Lock(n->Lock);
	{
		for (UINT i = 0; i < LIST_NUM(n->HubList); i++) {
			HUB *h = LIST_DATA(n->HubList, i);

			if (StrCmpi(h->Name, name) == 0) {
				AddRef(h->ref);
				ret = h;
				break;
			}
		}
	}
	Unlock(n->Lock);

	return ret;
}

// The credential gate of the node: req checked against the users of the Hub hubname of the server role by the
// fork's Sam (SamAuthenticate). The session layer (CORE-F2, #62) passes the credentials of the first control
// message. ret->Error is ERR_HUB_NOT_FOUND when the server role does not run that hub.
bool NodeAuthenticate(NODE *n, char *hubname, AUTH_REQUEST *req, AUTH_RESULT *ret) {
	if (ret == NULL)
		return false;

	Zero(ret, sizeof(AUTH_RESULT));
	ret->Error = ERR_HUB_NOT_FOUND;

	HUB *h = NodeGetHub(n, hubname);
	if (h == NULL)
		return false;

	SamAuthenticate(h, req, ret);

	ReleaseHub(h);

	return ret->Ok;
}
