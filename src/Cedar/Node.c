// Node.c
// The node of the new core (ADR-0011): one process, the ranzvpnserver service of ranz-node, that runs the
// roles of its configuration over the per-core workers and adapter queues of NodeWorker.c and the table
// snapshot of NodeTable.c. Its configuration is the SQLite store of ConfigStore.c in its data directory under
// ProgramData (CORE-F5, #65). It reuses the fork's Hub, Account, Sam and Logging modules in-process, and Cfg
// for the one-time import of a fork configuration. It runs the relay role on the peer module of the new core
// (src/Core/Peer.c). A node whose configuration names BGP peers also runs the BGP sidecar of NodeBgp.c
// (CORE-S7-1, #82).

#include "Node.h"

#include "Cedar.h"
#include "ConfigStore.h"
#include "Hub.h"
#include "Sam.h"

#include "Mayaqua/Encrypt.h"
#include "Mayaqua/FileIO.h"
#include "Mayaqua/Internat.h"
#include "Mayaqua/Memory.h"
#include "Mayaqua/Object.h"
#include "Mayaqua/Str.h"

#include "Core/Control.h"
#include "Core/Noise.h"

#include "NodeCaps.h"
#include "NodeInternal.h"
#include "NodeThrottle.h"

#include <AclAPI.h>
#include <ShlObj.h>
#include <sddl.h>

// The DACL of the default data directory: full control for SYSTEM, the Administrators and the virtual account of the
// ranzvpnserver service (NODE_SERVICE_SID, ADR-0039 decision 3), inherited by the configuration store and the node
// log, and nothing for anyone else. It is protected, so the ACL of ProgramData, which lets every user create files
// and folders, is not inherited.
#define NODE_DATA_DIR_SDDL L"O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;" NODE_SERVICE_SID L")"

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
static bool NodeRelayStart(NODE *n);
static void NodeRelayStop(NODE *n);
static bool NodeEmptyRoleStart(NODE *n);
static void NodeEmptyRoleStop(NODE *n);

// The roles in start order; they stop in the reverse order. The client role is NodeClient.c (CORE-S3-1, #71); the
// bridge role holds nothing yet: its adapter queues come with CORE-S3-3 (#73).
static NODE_ROLE_DEF node_roles[] =
    {
        {NODE_ROLE_SERVER, "server", NodeServerStart, NodeServerStop},
        {NODE_ROLE_CLIENT, "client", NodeClientStart, NodeClientStop},
        {NODE_ROLE_BRIDGE, "bridge", NodeEmptyRoleStart, NodeEmptyRoleStop},
        {NODE_ROLE_RELAY, "relay", NodeRelayStart, NodeRelayStop},
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

// The data directory of a node created without one: %ProgramData%\Hanzcodes\Ranz VPN, named like the registry
// key of the product. ProgramData holds the data of the new core only; the fork keeps its data next to its
// executable (ADR-0020 decision 2). The directory of the executable when Windows names no ProgramData folder.
void NodeDefaultDataDir(wchar_t *dir, UINT size) {
	wchar_t *program_data = NULL;
	if (dir == NULL)
		return;

	if (SUCCEEDED(SHGetKnownFolderPath(&FOLDERID_ProgramData, 0, NULL, &program_data)))
		ConbinePathW(dir, size, program_data, L"" GC_REG_COMPANY_NAME);
	else
		GetExeDirW(dir, size);

	CoTaskMemFree(program_data);
}

// Create a data directory, or take over the one that exists, with the owner Administrators and the protected DACL
// NODE_DATA_DIR_SDDL, which also replaces the ACL of what the directory holds. A directory that a user created
// before the node so keeps no access for that user. Without the right to set the owner (a process that is not
// elevated, such as the service under its virtual account, which then owns the directory it created), only the
// DACL is set.
bool NodeMakeDataDir(wchar_t *dir) {
	PSECURITY_DESCRIPTOR sd = NULL;
	PSID owner = NULL;
	PACL dacl = NULL;
	BOOL present = FALSE;
	BOOL defaulted = FALSE;
	if (UniIsEmptyStr(dir))
		return false;

	MakeDirExW(dir);

	if (ConvertStringSecurityDescriptorToSecurityDescriptorW(NODE_DATA_DIR_SDDL, SDDL_REVISION_1, &sd, NULL) == FALSE)
		return false;

	GetSecurityDescriptorOwner(sd, &owner, &defaulted);
	GetSecurityDescriptorDacl(sd, &present, &dacl, &defaulted);

	DWORD err = SetNamedSecurityInfoW(dir, SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION, owner, NULL, dacl, NULL);
	if (err != ERROR_SUCCESS)
		err = SetNamedSecurityInfoW(dir, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION, NULL, NULL, dacl, NULL);

	LocalFree(sd);

	return (err == ERROR_SUCCESS);
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

// Import the fork configuration NODE_IMPORT_FILE_NAME of the data directory once, into an empty store, and rename
// the file with NODE_IMPORTED_SUFFIX, so the next start does not find it again
static void NodeImportForkConfig(NODE *n) {
	wchar_t path[MAX_PATH];
	wchar_t done[MAX_PATH];
	CS_IMPORT r;

	ConbinePathW(path, sizeof(path), n->DataDir, NODE_IMPORT_FILE_NAME);
	if (IsFileExistsW(path) == false)
		return;

	UINT err = CsImportForkConfig(n->Store, path, &r);
	if (err != ERR_NO_ERROR) {
		NodeLog(n, "Fork configuration %S not imported: error %u%s", path, err, err == ERR_OBJECT_EXISTS ? " (the configuration store is not empty)" : "");
		return;
	}

	NodeLog(n, "Fork configuration %S imported: %u networks, %u users, %u listeners, %u certificates, %u admins, %u skipped", path, r.NumNetworks, r.NumUsers, r.NumListeners, r.NumCerts, r.NumAdmins, r.NumSkipped);

	NodeLog(n, "Fork configuration policy (CORE-S4-3): %u groups, %u VLANs, %u access list entries as rules, %u of them inactive, %u that deny more than the fork did; %u delays and redirects and %u hub options left out",
	        r.NumGroups, r.NumVlans, r.NumEntries, r.NumEntriesInactive, r.NumEntriesWidened, r.NumEffectsDropped, r.NumOptionsDropped);

	if (r.NumPasswordsDropped != 0)
		NodeLog(n, "Fork configuration: %u SHA-0 passwords not carried over (ADR-0022): set those passwords again", r.NumPasswordsDropped);

	if (r.ServerKeyDropped)
		NodeLog(n, "Fork configuration: the server key not carried over: it belongs in a CNG key storage provider");

	UniFormat(done, sizeof(done), L"%s%s", path, NODE_IMPORTED_SUFFIX);
	FileDeleteW(done);
	FileRenameW(path, done);
}

// The age limit in days and the disk limit in megabytes of the logs of the node (SDN-54, #247): the LogDays and LogMB
// settings of the configuration store, NODE_LOG_DEFAULT_DAYS and NODE_LOG_DEFAULT_MB without them, 0 for no limit.
// The node log and the log of the BGP sidecar keep within them.
void NodeGetLogLimits(NODE *n, UINT *days, UINT *mb) {
	char value[MAX_SIZE];

	*days = NODE_LOG_DEFAULT_DAYS;
	*mb = NODE_LOG_DEFAULT_MB;

	if (n->Store != NULL) {
		if (CsGetSetting(n->Store, NODE_SETTING_LOG_DAYS, value, sizeof(value)) && IsEmptyStr(value) == false)
			*days = MIN(ToInt(value), NODE_LOG_MAX_DAYS);

		if (CsGetSetting(n->Store, NODE_SETTING_LOG_MB, value, sizeof(value)) && IsEmptyStr(value) == false)
			*mb = MIN(ToInt(value), NODE_LOG_MAX_MB);
	}
}

// Keep the node log within its limits (NodeGetLogLimits). The limits reach the files that earlier runs left in the node
// log directory as well.
static void NodeLoadLogLimits(NODE *n) {
	UINT days;
	UINT mb;

	NodeGetLogLimits(n, &days, &mb);

	SetLogLimits(n->Log, days, (UINT64)mb * 1024ULL * 1024ULL);
}

// Write the text dump of the configuration store (CsDump) to NODE_CONFIG_DUMP_NAME in the data directory, as it is
// at the start of the node, so that ranz doctor --bundle holds the configuration of the node (SDN-54, #247). The dump
// shows no password hash and no key.
static void NodeWriteConfigDump(NODE *n) {
	wchar_t path[MAX_PATH];

	if (n->Store == NULL)
		return;

	BUF *b = CsDump(n->Store);
	if (b == NULL)
		return;

	ConbinePathW(path, sizeof(path), n->DataDir, NODE_CONFIG_DUMP_NAME);
	DumpBufW(b, path);
	FreeBuf(b);
}

// Open the configuration store (CS_FILE_NAME in the data directory), import a fork configuration into it once,
// then read the settings: Roles (NODE_SETTING_ROLES; without it NODE_DEFAULT_ROLES, "none" for no role),
// NumWorkers (NODE_SETTING_WORKERS; 0 for one per core), RelayPort (NODE_SETTING_RELAY_PORT; without it, or 0, a
// port that the system picks), IdentityKey (NODE_SETTING_IDENTITY_KEY; without it NODE_IDENTITY_KEY_NAME) and Bgp
// (NODE_SETTING_BGP; none for no BGP sidecar). The networks are read by the server role. Last it sets the limits of
// the node log (NodeLoadLogLimits) and writes the text dump of the store (NodeWriteConfigDump).
static void NodeLoadConfig(NODE *n) {
	wchar_t path[MAX_PATH];
	char roles[MAX_SIZE];
	char unknown[MAX_SIZE];
	char workers[MAX_SIZE];
	char relay_port[MAX_SIZE];
	char *bgp;

	n->ConfigRoles = NODE_DEFAULT_ROLES;
	n->ConfigWorkers = 0;
	n->ConfigRelayPort = 0;
	StrCpy(n->IdentityKey, sizeof(n->IdentityKey), NODE_IDENTITY_KEY_NAME);

	ConbinePathW(path, sizeof(path), n->DataDir, CS_FILE_NAME);
	n->Store = CsOpen(path);

	if (n->Store == NULL) {
		NodeLog(n, "Configuration store %S cannot be opened: the default roles", path);
		NodeLoadLogLimits(n);
		return;
	}

	NodeLog(n, "Configuration store %S opened (winsqlite3 %s)", path, CsLibVersion());

	NodeImportForkConfig(n);

	if (CsGetSetting(n->Store, NODE_SETTING_ROLES, roles, sizeof(roles))) {
		n->ConfigRoles = NodeParseRoles(roles, unknown, sizeof(unknown));

		if (IsEmptyStr(unknown) == false)
			NodeLogUnknownRoles(n, unknown);
	}

	if (CsGetSetting(n->Store, NODE_SETTING_WORKERS, workers, sizeof(workers))) {
		UINT num_workers = ToInt(workers);
		n->ConfigWorkers = MIN(num_workers, NODE_MAX_WORKERS);
	}

	if (CsGetSetting(n->Store, NODE_SETTING_RELAY_PORT, relay_port, sizeof(relay_port))) {
		UINT port = ToInt(relay_port);
		n->ConfigRelayPort = (port <= 65535 ? port : 0);
	}

	if (CsGetSetting(n->Store, NODE_SETTING_IDENTITY_KEY, n->IdentityKey, sizeof(n->IdentityKey)) == false || IsEmptyStr(n->IdentityKey))
		StrCpy(n->IdentityKey, sizeof(n->IdentityKey), NODE_IDENTITY_KEY_NAME);

	bgp = ZeroMalloc(NODE_BGP_MAX_LINE);
	if (CsGetSetting(n->Store, NODE_SETTING_BGP, bgp, NODE_BGP_MAX_LINE) && IsEmptyStr(bgp) == false)
		n->ConfigBgp = bgp;
	else
		Free(bgp);

	NodeLoadLogLimits(n);
	NodeWriteConfigDump(n);
}

// A node with its data directory: NULL for NodeDefaultDataDir, which NodeMakeDataDir protects. It opens the node
// log and the configuration store and reads the configuration, but starts nothing until NodeStart.
NODE *NewNode(wchar_t *data_dir) {
	wchar_t log_dir_w[MAX_PATH];
	char log_dir[MAX_PATH];
	bool protect = UniIsEmptyStr(data_dir);

	NODE *n = ZeroMalloc(sizeof(NODE));
	n->Lock = NewLock();
	n->TableLock = NewLock();
	n->ReaderList = NewListFast(NULL);
	n->QueueList = NewListFast(NULL);
	n->HubList = NewListFast(NULL);
	n->LoginThrottle = NewNodeThrottle();
	// The counters of the EVPN of a gateway, which the control stream reports while an EVPN runs (NodeEvpn.c; SDN-25-R3, #571)
	n->EvpnReport = ControlNewEvpn();

	// An online reader never publishes epoch 0, which means offline
	n->Epoch = 1;

	if (protect)
		NodeDefaultDataDir(n->DataDir, sizeof(n->DataDir));
	else
		UniStrCpy(n->DataDir, sizeof(n->DataDir), data_dir);

	// The DACL is set before the store and the log exist, so both inherit it
	bool protected_dir = (protect ? NodeMakeDataDir(n->DataDir) : MakeDirExW(n->DataDir));

	ConbinePathW(log_dir_w, sizeof(log_dir_w), n->DataDir, NODE_LOG_DIR_NAME);
	UniToStr(log_dir, sizeof(log_dir), log_dir_w);
	n->Log = NewLog(log_dir, NODE_LOG_PREFIX, LOG_SWITCH_DAY, 0);

	if (protect)
		NodeLog(n, protected_dir ? "Data directory %S: SYSTEM, the Administrators and the service account only" : "Data directory %S: its DACL could not be set", n->DataDir);

	NodeLogMitigations(n);
	NodeLogCaps(n);

	n->Cedar = NewCedar(NULL, NULL);

	GetExeDirW(n->BgpSidecar, sizeof(n->BgpSidecar));
	ConbinePathW(n->BgpSidecar, sizeof(n->BgpSidecar), n->BgpSidecar, NODE_BGP_EXE_NAME);
	NodeBgpInit();
	NodeMimicInit(n);

	NodeLoadConfig(n);

	return n;
}

// Stop the node if it runs and free it
void FreeNode(NODE *n) {
	if (n == NULL)
		return;

	NodeStop(n);

	CsClose(n->Store);
	ReleaseCedar(n->Cedar);
	Free(n->ConfigBgp);

	// The last lines of the node log are written before FreeLog returns
	FreeLog(n->Log);

	ReleaseList(n->HubList);
	ReleaseList(n->QueueList);
	ReleaseList(n->ReaderList);
	Free(n->Peers);
	FreeNodeThrottle(n->LoginThrottle);
	ControlFreeEvpn(n->EvpnReport);

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

// Start the node: the table snapshot, the workers, the roles of the configuration, then the BGP sidecar when the
// configuration names BGP peers. False when it runs already or no worker could start.
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
				// The lines of the transport module, as a QUIC side without an exporter, into the node log (CORE-H5-R, #443)
				NodeTransportLogStart(n);

				NodeApplyRoles(n, n->ConfigRoles);

				NodeRolesToStr(roles, sizeof(roles), n->Roles);
				NodeLog(n, "Node roles: %s", roles);

				// The overlay with the control stream of the Controller settings, for every set of roles, and the admin pipe
				// (NodeController.c; SDN-90, #395)
				NodeControllerStart(n);

				NodeBgpStart(n);
				NodeMimicStart(n);

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

// Stop the node: the overlay, the BGP sidecar and its learned routes, the roles, last first, the adapter queues that
// are still attached, the workers and the table snapshot. Every thread of the node is joined before it returns. The
// overlay stops outside the node lock, which its control stream takes to set the peers (NodeSetPeers).
void NodeStop(NODE *n) {
	if (n == NULL)
		return;

	// The admin pipe, the overlay and the control stream of the Controller settings (NodeController.c; SDN-90, #395)
	NodeControllerStop(n);
	NodeOverlayStop(n);

	Lock(n->Lock);
	{
		if (n->Running) {
			UINT num_workers = n->NumWorkers;

			NodeMimicStop(n);
			NodeBgpStop(n);
			NodeApplyRoles(n, 0);

			UINT num_queues = NodeDelAllQueues(n);

			NodeStopWorkers(n);
			NodeTablesStop(n);
			NodeTransportLogStop(n);

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

		if (n->Relay != NULL) {
			PEER_STATS ps;

			PeerGetStats(n->Relay, &ps);
			st->RelayPort = PeerUdpPort(n->RelayUdp);
			Copy(st->RelayKey, PeerPublicKey(n->Relay), PEER_KEY_SIZE);
			st->RelayBindings = ps.NumBindings;
			st->RelayBinds = ps.Binds;
			st->RelayForwarded = ps.Forwarded;
		}
	}
	Unlock(n->Lock);

	// Read without the table lock, which a swap holds while it waits for its readers
	st->NumReaders = LIST_NUM(n->ReaderList);
	st->Generation = (UINT64)ReadAcquire64(&n->Generation);

	// The mimicry sidecars (NodeMimic.c; CORE-P2-6, #406)
	for (UINT i = 0; i < NODE_MIMIC_NUM_ROLES; i++)
		NodeMimicGetStatus(n, i, &st->Mimic[i]);
}

// Bring the Hub name of the configuration up in the Cedar of the node, online or offline: a fork Hub with the
// default options of a new hub. The caller holds the node lock.
static void NodeAddHub(NODE *n, char *name, bool online) {
	HUB_OPTION o;

	if (IsEmptyStr(name) || StrLen(name) > MAX_HUBNAME_LEN || IsSafeStr(name) == false || IsHub(n->Cedar, name)) {
		NodeLog(n, "Hub %s ignored: not a valid hub name, or a hub of that name runs", name);
		return;
	}

	Zero(&o, sizeof(o));
	SiSetDefaultHubOption(&o);

	HUB *h = NewHub(n->Cedar, name, &o);
	AddHub(n->Cedar, h);
	HubApplyInitialState(h, online);

	// The reference of NewHub stays in the list until the role stops
	Add(n->HubList, h);

	NodeLog(n, "Hub %s %s", h->Name, online ? "online" : "offline");
}

// The server role: a Hub for each L2 network of the configuration store, or the DEFAULT hub when the store has no
// network. The L3 networks come with the routed networks (CORE-S6-1, #80). The sessions of the QUIC and TLS
// transports (CORE-S1-1 #67, CORE-S2-1 #69) end in the Hubs, as Sessions of a Tunnel (NodeAcceptSession, CORE-S1-2 #68).
static bool NodeServerStart(NODE *n) {
	LIST *o = CsEnumNetworks(n->Store);

	if (LIST_NUM(o) == 0)
		NodeAddHub(n, SERVER_DEFAULT_HUB_NAME, true);

	for (UINT i = 0; i < LIST_NUM(o); i++) {
		CS_NETWORK *net = LIST_DATA(o, i);

		if (net->Mode == CS_MODE_L2)
			NodeAddHub(n, net->Name, net->Online);
		else
			NodeLog(n, "Network %s skipped: L3 networks come with CORE-S6-1 (#80)", net->Name);
	}

	CsFreeNetworkList(o);

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

// The relay role (ADR-0015, CORE-S5-2 #78): the peer layer of the node with the relay role, on a UDP socket of
// RelayPort, under the node identity key. It binds the nodes of its VRFs and forwards between two of them that
// share a VRF, by the peers that the control plane set (NodeSetPeers); it holds no state beyond the bindings that
// its nodes renew. The socket stands in for the QUIC listener of CORE-S1-1 (#67) on UDP 443. The caller holds the
// node lock.
static bool NodeRelayStart(NODE *n) {
	wchar_t name[MAX_SIZE];
	PEER_CONFIG c;

	StrToUni(name, sizeof(name), n->IdentityKey);
	if (PeerKeyOpen(&n->RelayKey, name) == false) {
		NodeLog(n, "Role relay: the identity key \"%s\" cannot be opened or created", n->IdentityKey);
		return false;
	}

	n->RelayUdp = PeerUdpNew((USHORT)n->ConfigRelayPort);
	if (n->RelayUdp == NULL) {
		NodeLog(n, "Role relay: UDP port %u cannot be bound", n->ConfigRelayPort);
		PeerKeyClose(&n->RelayKey);
		return false;
	}

	PeerDefaultConfig(&c);
	c.Relay = true;

	n->Relay = PeerNew(&n->RelayKey, &c, PeerUdpSend, n->RelayUdp, NULL, NULL);
	if (n->Relay != NULL)
		PeerSetPeers(n->Relay, n->Peers, n->NumPeers);

	if (n->Relay == NULL || PeerUdpStart(n->RelayUdp, n->Relay) == false) {
		NodeLog(n, "Role relay: its peer layer could not start");
		NodeRelayStop(n);
		return false;
	}

	NodeLog(n, "Relay listening on UDP port %u, %u peers", (UINT)PeerUdpPort(n->RelayUdp), n->NumPeers);

	return true;
}

// Stop the relay role: its receive thread first, which is what calls into its peer layer, then the layer and the
// key. The caller holds the node lock.
static void NodeRelayStop(NODE *n) {
	PeerUdpFree(n->RelayUdp);
	n->RelayUdp = NULL;

	PeerFree(n->Relay);
	n->Relay = NULL;

	PeerKeyClose(&n->RelayKey);
}

// Set the peers of the node, from the Peer objects of the desired state, as the control plane does: for the relay
// role, the nodes it binds and the VRFs it forwards between them in
void NodeSetPeers(NODE *n, PEER_INFO *peers, UINT num) {
	if (n == NULL || (peers == NULL && num != 0))
		return;

	Lock(n->Lock);
	{
		Free(n->Peers);
		n->Peers = (num != 0 ? Clone(peers, sizeof(PEER_INFO) * num) : NULL);
		n->NumPeers = num;

		if (n->Relay != NULL)
			PeerSetPeers(n->Relay, n->Peers, n->NumPeers);
	}
	Unlock(n->Lock);

	NodeLog(n, "Peers set: %u", num);
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
// message through NodeLogin. ret->Error is ERR_HUB_NOT_FOUND when the server role does not run that hub.
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

// The Login of a session of the new core (CORE-F2, #62): the credentials of the first control message of a
// Noise session, checked by NodeAuthenticate as the SE-VPN login has Sam check them. The password reaches the
// node inside the encrypted session, so it goes to Sam as a plain password, which Sam checks against a password
// user or, for a user of a Windows domain, with the domain; a certificate Login signed challenge, the
// NOISE_LOGIN_CHALLENGE_SIZE (SHA1_SIZE) bytes of NoiseSessionChallenge, where the SE-VPN login signs the random
// of its hello. ret->Error is ERR_AUTHTYPE_NOT_SUPPORTED for a join Login, which names a tunnel, not a user.
bool NodeLogin(NODE *n, NOISE_LOGIN *login, UCHAR *challenge, AUTH_RESULT *ret) {
	AUTH_REQUEST req;

	if (ret == NULL)
		return false;

	Zero(ret, sizeof(AUTH_RESULT));
	ret->Error = ERR_AUTH_FAILED;
	if (login == NULL || challenge == NULL)
		return false;

	Zero(&req, sizeof(req));
	req.Username = login->UserName;
	req.Random = challenge;

	switch (login->Method) {
	case NOISE_LOGIN_ANONYMOUS:
		req.AuthType = CLIENT_AUTHTYPE_ANONYMOUS;
		break;

	case NOISE_LOGIN_PASSWORD:
		req.AuthType = CLIENT_AUTHTYPE_PLAIN_PASSWORD;
		req.PlainPassword = login->Password;
		break;

	case NOISE_LOGIN_CERT: {
		BUF *b = NewBuf();
		WriteBuf(b, (void *)login->Cert, login->CertSize);
		req.AuthType = CLIENT_AUTHTYPE_CERT;
		req.Cert = BufToX(b, false);
		req.Sign = (UCHAR *)login->Sign;
		req.SignSize = login->SignSize;
		FreeBuf(b);
		break;
	}

	default:
		ret->Error = ERR_AUTHTYPE_NOT_SUPPORTED;
		return false;
	}

	bool ok = NodeAuthenticate(n, login->HubName, &req, ret);
	FreeX(req.Cert);

	return ok;
}

// The Login with trust on first use (CORE-S1-1, #67): NodeLogin checks the credentials through Sam,
// and then the client node's Noise static key (static_key, NOISE_KEY_SIZE bytes, learnt in the
// handshake as NOISE_SESSION.RemoteStatic) is pinned to the user on the first login and must be the
// same on every later login. A login whose credentials Sam accepts but whose key does not match the
// pinned one is refused (ret->Ok is cleared, ret->Error is ERR_AUTH_FAILED), so a stolen password
// alone does not let an attacker impersonate an enrolled node (ADR-0022, ADR-0023). A user that the
// configuration store does not keep (a domain account, an anonymous login) is not pinned. A store
// that fails to check the key refuses the login in the same way, so the client gets the answer of a
// wrong password, and the node log tells why: a failed store never skips the check (FIX-8).
bool NodeLoginPinned(NODE *n, NOISE_LOGIN *login, UCHAR *challenge, UCHAR *static_key, AUTH_RESULT *ret) {
	if (NodeLogin(n, login, challenge, ret) == false)
		return false;

	// Only a named user with a key pins one; a join or anonymous login names no user to pin to
	if (static_key == NULL || n->Store == NULL || login == NULL ||
	    (login->Method != NOISE_LOGIN_PASSWORD && login->Method != NOISE_LOGIN_CERT))
		return true;

	UINT pin = CsPinUserKey(n->Store, login->HubName, login->UserName, static_key);

	// CS_KEY_PINNED (the first login) and CS_KEY_MATCH (a later one) pass. CS_KEY_NO_USER is a user the
	// store does not keep, which the hub's Sam authenticated: it is not pinned here.
	if (pin == CS_KEY_PINNED || pin == CS_KEY_MATCH || pin == CS_KEY_NO_USER)
		return true;

	if (pin == CS_KEY_MISMATCH)
		NodeLog(n, "Login of %s on %s refused: the Noise static key is not the pinned one", login->UserName, login->HubName);
	else
		NodeLog(n, "Login of %s on %s refused: the configuration store failed to check the pinned key", login->UserName, login->HubName);

	ret->Ok = false;
	ret->Error = ERR_AUTH_FAILED;
	return false;
}
