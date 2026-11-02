// nodetest.c
// Named node tests of vpntest ("node" and "nodesvc" commands, CORE-F3 #63)
//
// node: the node of the new core in-process (Cedar/Node.c, NodeWorker.c, NodeTable.c). Each role, alone and
// all four together, is selected by a configuration file, starts, and stops with every thread joined; names
// that are no role (the controller among them) are ignored and logged; the control plane switches the roles
// of a running node. One worker per core runs its work items on its own core, in posting order; an adapter
// queue drains on one I/O thread of its own. A table swap is atomic under readers on every worker: no reader
// sees a torn, wiped or older snapshot; a swap waits while a reader still holds the old snapshot, and the
// other workers go on meanwhile. The check that every reader sees several generations while the swaps run
// waits for its swaps and its readers, within a bound, and does not count what fits in a fixed time, so a busy
// machine makes the test longer and does not fail it (#437); a second round, with a pause before each swap,
// makes the check wait in every run. The Hubs of the server role are fork Hubs, whose users (Account) the fork's
// Sam checks through NodeAuthenticate; the node writes its log through LogWriter and reads its configuration
// from its configuration store (ConfigStore, CORE-F5 #65).
// The relay role (CORE-S5-2 #78) listens on a UDP port under the node identity key: two peer layers of the new
// core (Core/Peer.h) on UDP sockets of their own bind to it, come up after one signal each way and reach each
// other through it, and it forwards nothing once the control plane takes their peers away.
// nodesvc: ranz-node installs as the ranzvpnserver service and, for each role of its configuration, runs it
// and stops cleanly: the service reports no error, the process exits with code 0, and the node log holds the
// start and the stop of that role alone. The first run starts without a configuration store: the service creates
// it under %ProgramData%\Hanzcodes\Ranz VPN, whose DACL is protected and gives SYSTEM, the Administrators and the
// service account alone access (CORE-F5 #65). The hardening of ADR-0039 (SEC-1 #279) on the running service: it
// runs as its virtual account NT SERVICE\ranzvpnserver, not LocalSystem; its process runs with every mitigation of
// NodeGetMitigations, or the node records why one is off; every DLL it loaded is in System32; and its node log
// says so. It needs administrator rights, enables SeDebugPrivilege to read the service process, and leaves an
// installed node alone.
// Both tests run the relay role under the identity key NODETEST_IDENTITY_KEY, not the one of an installed node,
// and delete it.
// Print "NODE TEST OK" and "NODESVC TEST OK" only when every check passes.

#include "testlist.h"

#include "Cedar/Account.h"
#include "Cedar/Cedar.h"
#include "Cedar/ConfigStore.h"
#include "Cedar/Hub.h"
#include "Cedar/Node.h"
#include "Cedar/Sam.h"

#include "Mayaqua/Encrypt.h"
#include "Mayaqua/FileIO.h"
#include "Mayaqua/Internat.h"
#include "Mayaqua/Kernel.h"
#include "Mayaqua/Memory.h"
#include "Mayaqua/Microsoft.h"
#include "Mayaqua/Str.h"
#include "Mayaqua/Table.h"
#include "Mayaqua/Tick64.h"

#include <AclAPI.h>
#include <psapi.h>
#include <sddl.h>

#define	NODETEST_BUDGET			300000		// The whole node test (ms): the watchdog ends a hung run
#define	NODETEST_BOUND			10000		// A bounded wait on observable state (ms)
#define	NODETEST_HOLD			300			// How long a swap must keep waiting for a reader that holds the old snapshot (ms)
#define	NODETEST_SWAP_TIME		1000		// Swaps of the atomicity case run at least this long (ms) ...
#define	NODETEST_SWAP_MAX		20000		// ... and stop at this many
#define	NODETEST_SWAP_MIN		10			// The generations check waits for this many swaps ...
#define	NODETEST_SWAP_BOUND		30000		// ... and for every reader to see two generations, this long at most (ms)
#define	NODETEST_SWAP_PAUSE		150			// The slow round waits this long before each swap (ms): a busy runner took about this long (#437)
#define	NODETEST_ROLE_WORKERS	2			// Workers of the role cases
#define	NODETEST_HUB			"NODETEST"	// Hub of the server role in the Sam case
#define	NODETEST_USER			"alice"
#define	NODETEST_PASSWORD		"node-test-password"
#define	NODETEST_MAC_ENTRIES	64			// Entries of the MAC table of a test snapshot
#define	NODETEST_ROUTE_ENTRIES	32			// ... of the route table
#define	NODETEST_POLICY_ENTRIES	16			// ... of the policy table
#define	NODETEST_QUEUE_FRAMES	20			// Frames per round of the queue case: 16 known MAC addresses, 4 unknown
#define	NODETEST_QUEUE_KNOWN	16
#define	NODETEST_IDENTITY_KEY	"Ranz Node Test"	// The identity key of the test nodes (IdentityKey)
#define	NODETEST_QUIET			500			// How long the relay case waits for a datagram that must not come (ms)

#define	NODESVC_START_WAIT		60000		// The service reaches a state within this time (ms)
#define	NODESVC_RUN_WAIT		120000		// A run of ranz-node.exe with a service argument ends within this time (ms)
#define	NODESVC_NAME			"ranzvpnserver"	// ADR-0020 decision 4

// The checks of one test
typedef struct NODETEST_CTX
{
	UINT NumChecks;					// Checks run so far
	UINT NumFailed;					// Checks failed so far
} NODETEST_CTX;

// Record one check: print [PASS] with what, or [FAIL] with what and the formatted detail
static bool NodeTestCheck(NODETEST_CTX *ctx, bool ok, char *what, char *fmt, ...) RANZ_PRINTF_FORMAT(4, 5);
static bool NodeTestCheck(NODETEST_CTX *ctx, bool ok, char *what, char *fmt, ...)
{
	char detail[MAX_SIZE * 2];
	va_list args;

	ctx->NumChecks++;

	if (ok)
	{
		Print("  [PASS] %s\n", what);
		return true;
	}

	va_start(args, fmt);
	FormatArgs(detail, sizeof(detail), fmt, args);
	va_end(args);

	Print("  [FAIL] %s: %s\n", what, detail);
	ctx->NumFailed++;

	return false;
}

// Watchdog of the node test: a native thread that ends a run that hangs, so that a lost wake-up of the node
// is a failed test instead of a hung CI step
typedef struct NODETEST_WATCHDOG
{
	HANDLE DoneEvent;				// Set when the test returns
	HANDLE Thread;					// The watchdog thread
	char *Name;						// The test it guards
} NODETEST_WATCHDOG;

static DWORD WINAPI NodeTestWatchdogThread(LPVOID param)
{
	NODETEST_WATCHDOG *w = (NODETEST_WATCHDOG *)param;
	char msg[MAX_SIZE];
	DWORD written = 0;

	if (WaitForSingleObject(w->DoneEvent, NODETEST_BUDGET) != WAIT_TIMEOUT)
	{
		return 0;
	}

	int len = snprintf(msg, sizeof(msg), "%s TEST FAILED (did not finish within %u ms)\n", w->Name, NODETEST_BUDGET);
	if (len > 0)
	{
		WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), msg, (DWORD)MIN((UINT)len, (UINT)sizeof(msg) - 1), &written, NULL);
	}

	TerminateProcess(GetCurrentProcess(), 1);

	return 0;
}

static void NodeTestWatchdogStart(NODETEST_WATCHDOG *w, char *name)
{
	w->Name = name;
	w->DoneEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
	w->Thread = (w->DoneEvent != NULL ? CreateThread(NULL, 0, NodeTestWatchdogThread, w, 0, NULL) : NULL);
}

static void NodeTestWatchdogStop(NODETEST_WATCHDOG *w)
{
	if (w->Thread != NULL)
	{
		SetEvent(w->DoneEvent);
		WaitForSingleObject(w->Thread, INFINITE);
		CloseHandle(w->Thread);
	}

	if (w->DoneEvent != NULL)
	{
		CloseHandle(w->DoneEvent);
	}
}

// Wait until *v reaches at least target or the bound passes; true when it did
static bool NodeTestWait(volatile LONG *v, LONG target, UINT timeout)
{
	UINT64 end = Tick64() + timeout;

	while (InterlockedCompareExchange(v, 0, 0) < target)
	{
		if (Tick64() >= end)
		{
			return false;
		}

		SleepThread(1);
	}

	return true;
}

// The active processors of the machine
static UINT NodeTestNumCores()
{
	UINT num = GetActiveProcessorCount(ALL_PROCESSOR_GROUPS);

	return MIN(MAX(num, 1), NODE_MAX_WORKERS);
}

// A new empty data directory under the temp directory of the process
static void NodeTestNewDir(wchar_t *dir, UINT size, char *name)
{
	wchar_t tmp[MAX_PATH];

	UniFormat(tmp, sizeof(tmp), L"node_%S_%u", name, Rand32());
	ConbinePathW(dir, size, MsGetMyTempDirW(), tmp);
	MakeDirExW(dir);
}

// Delete the files of a directory, then the directory (it holds no subdirectory)
static void NodeTestDeleteFiles(wchar_t *dir, bool delete_dir)
{
	DIRLIST *d = EnumDirW(dir);

	for (UINT i = 0;d != NULL && i < d->NumFiles;i++)
	{
		DIRENT *e = d->File[i];
		wchar_t path[MAX_PATH];

		if (e->Folder == false)
		{
			ConbinePathW(path, sizeof(path), dir, e->FileNameW);
			FileDeleteW(path);
		}
	}

	FreeDir(d);

	if (delete_dir)
	{
		DeleteDirW(dir);
	}
}

// Delete a data directory of the test: the node log, the configuration, the directory
static void NodeTestDeleteDir(wchar_t *dir)
{
	wchar_t log_dir[MAX_PATH];

	ConbinePathW(log_dir, sizeof(log_dir), dir, NODE_LOG_DIR_NAME);
	NodeTestDeleteFiles(log_dir, true);
	NodeTestDeleteFiles(dir, true);
}

// Write the configuration store of a data directory: the Roles setting (none for NULL), the NumWorkers setting
// (none for 0), one online L2 network (none for NULL), and the IdentityKey setting, the identity key of the test
// nodes
static void NodeTestWriteConfig(wchar_t *dir, char *roles, UINT num_workers, char *hub)
{
	wchar_t path[MAX_PATH];
	char workers[MAX_SIZE];

	ConbinePathW(path, sizeof(path), dir, CS_FILE_NAME);
	CONFIG_STORE *s = CsOpen(path);

	if (s == NULL)
	{
		Print("  configuration store %S cannot be opened\n", path);
		return;
	}

	CsSetSetting(s, NODE_SETTING_IDENTITY_KEY, NODETEST_IDENTITY_KEY);
	CsSetSetting(s, NODE_SETTING_ROLES, roles);

	ToStr(workers, num_workers);
	CsSetSetting(s, NODE_SETTING_WORKERS, num_workers != 0 ? workers : NULL);

	if (hub != NULL)
	{
		CsAddNetwork(s, hub, CS_MODE_L2, true);
	}

	CsClose(s);
}

// The text of every node log file of a data directory, NULL when there is none; the caller frees it
static char *NodeTestReadLog(wchar_t *dir)
{
	wchar_t log_dir[MAX_PATH];
	BUF *all = NewBuf();

	ConbinePathW(log_dir, sizeof(log_dir), dir, NODE_LOG_DIR_NAME);

	DIRLIST *d = EnumDirW(log_dir);
	for (UINT i = 0;d != NULL && i < d->NumFiles;i++)
	{
		DIRENT *e = d->File[i];
		wchar_t path[MAX_PATH];

		if (e->Folder == false)
		{
			ConbinePathW(path, sizeof(path), log_dir, e->FileNameW);

			BUF *b = ReadDumpW(path);
			if (b != NULL)
			{
				WriteBuf(all, b->Buf, b->Size);
				FreeBuf(b);
			}
		}
	}
	FreeDir(d);

	char *ret = NULL;
	if (all->Size != 0)
	{
		ret = ZeroMalloc(all->Size + 1);
		Copy(ret, all->Buf, all->Size);
	}
	FreeBuf(all);

	return ret;
}

// Whether the log text holds the line part
static bool NodeTestLogHas(char *log, char *part)
{
	return (log != NULL && SearchStrEx(log, part, 0, true) != INFINITE);
}

//
// Roles from the configuration
//

typedef struct NODETEST_ROLE_CASE
{
	char *Roles;					// The Roles item, NULL for none
	UINT Expect;					// The roles that must run
	char *Ignored;					// A name that must be logged as ignored, or NULL
} NODETEST_ROLE_CASE;

static NODETEST_ROLE_CASE nodetest_role_cases[] =
{
	{"server", NODE_ROLE_SERVER, NULL},
	{"client", NODE_ROLE_CLIENT, NULL},
	{"bridge", NODE_ROLE_BRIDGE, NULL},
	{"relay", NODE_ROLE_RELAY, NULL},
	{"server,client,bridge,relay", NODE_ROLE_ALL, NULL},
	{"Relay, SERVER ,controller,bogus", NODE_ROLE_SERVER | NODE_ROLE_RELAY, "controller"},
	{NULL, NODE_DEFAULT_ROLES, NULL},
	{"none", 0, NULL},
};

// The role names of the bits, as the node writes them
static char *nodetest_role_names[] = {"server", "client", "bridge", "relay"};

// One role case: start the node with the configuration, check what runs, stop it, check that every thread
// is gone, then check the node log
static void NodeTestRoleCase(NODETEST_CTX *ctx, NODETEST_ROLE_CASE *c)
{
	wchar_t dir[MAX_PATH];
	char expect_str[MAX_SIZE];
	char got_str[MAX_SIZE];
	char what[MAX_SIZE];
	char line[MAX_SIZE];
	NODE_STATUS st;
	UINT workers = MIN(NODETEST_ROLE_WORKERS, NodeTestNumCores());

	NodeRolesToStr(expect_str, sizeof(expect_str), c->Expect);
	NodeTestNewDir(dir, sizeof(dir), "roles");
	NodeTestWriteConfig(dir, c->Roles, NODETEST_ROLE_WORKERS, NULL);

	NODE *n = NewNode(dir);
	bool started = NodeStart(n);
	NodeGetStatus(n, &st);
	NodeRolesToStr(got_str, sizeof(got_str), st.Roles);

	Format(what, sizeof(what), "Roles \"%s\": the node starts with the roles %s, %u workers, each a table reader",
		c->Roles == NULL ? "(no item)" : c->Roles, expect_str, workers);
	NodeTestCheck(ctx, started && st.Running && st.Roles == c->Expect && st.NumWorkers == workers &&
		st.NumReaders == workers && st.Generation != 0, what,
		"started %u, running %u, roles %s, %u workers, %u readers, generation %I64u",
		(UINT)started, (UINT)st.Running, got_str, st.NumWorkers, st.NumReaders, st.Generation);

	HUB *h = NodeGetHub(n, SERVER_DEFAULT_HUB_NAME);
	bool server = ((c->Expect & NODE_ROLE_SERVER) != 0);
	Format(what, sizeof(what), "Roles \"%s\": the DEFAULT hub runs only with the server role",
		c->Roles == NULL ? "(no item)" : c->Roles);
	NodeTestCheck(ctx, (h != NULL) == server && st.NumHubs == (server ? 1 : 0), what,
		"hub %s, %u hubs", h != NULL ? "found" : "missing", st.NumHubs);
	ReleaseHub(h);

	NodeStop(n);
	NodeGetStatus(n, &st);
	Format(what, sizeof(what), "Roles \"%s\": after NodeStop no role, worker, queue, reader, hub or snapshot is left",
		c->Roles == NULL ? "(no item)" : c->Roles);
	NodeTestCheck(ctx, st.Running == false && st.Roles == 0 && st.NumWorkers == 0 && st.NumQueues == 0 &&
		st.NumReaders == 0 && st.NumHubs == 0 && st.Generation == 0, what,
		"running %u, roles 0x%x, %u workers, %u queues, %u readers, %u hubs, generation %I64u",
		(UINT)st.Running, st.Roles, st.NumWorkers, st.NumQueues, st.NumReaders, st.NumHubs, st.Generation);

	FreeNode(n);

	// The log is complete once FreeNode closed it
	char *log = NodeTestReadLog(dir);
	bool ok = (log != NULL);
	char missing[MAX_SIZE];
	StrCpy(missing, sizeof(missing), "");

	for (UINT i = 0;i < 4;i++)
	{
		bool expected = ((c->Expect & (1 << i)) != 0);

		Format(line, sizeof(line), "Role %s started", nodetest_role_names[i]);
		if (NodeTestLogHas(log, line) != expected)
		{
			ok = false;
			StrCat(missing, sizeof(missing), expected ? " no " : " unexpected ");
			StrCat(missing, sizeof(missing), line);
		}

		Format(line, sizeof(line), "Role %s stopped", nodetest_role_names[i]);
		if (NodeTestLogHas(log, line) != expected)
		{
			ok = false;
			StrCat(missing, sizeof(missing), expected ? " no " : " unexpected ");
			StrCat(missing, sizeof(missing), line);
		}
	}

	Format(line, sizeof(line), "Node stopped: %u workers joined, 0 adapter queues detached", workers);
	if (NodeTestLogHas(log, line) == false)
	{
		ok = false;
		StrCat(missing, sizeof(missing), " no ");
		StrCat(missing, sizeof(missing), line);
	}

	if (c->Ignored != NULL)
	{
		Format(line, sizeof(line), "Role %s ignored", c->Ignored);
		if (NodeTestLogHas(log, line) == false)
		{
			ok = false;
			StrCat(missing, sizeof(missing), " no ");
			StrCat(missing, sizeof(missing), line);
		}
	}

	Format(what, sizeof(what), "Roles \"%s\": the node log names each role that started and stopped, and the joined workers",
		c->Roles == NULL ? "(no item)" : c->Roles);
	NodeTestCheck(ctx, ok, what, "%s", log == NULL ? "no node log" : missing);

	Free(log);
	NodeTestDeleteDir(dir);
}

// The control plane switches the roles of a running node
static void NodeTestSetRoles(NODETEST_CTX *ctx)
{
	wchar_t dir[MAX_PATH];
	NODE_STATUS st;

	NodeTestNewDir(dir, sizeof(dir), "setroles");
	NodeTestWriteConfig(dir, "server", 1, NULL);

	NODE *n = NewNode(dir);
	NodeStart(n);

	UINT roles = NodeSetRoles(n, NODE_ROLE_CLIENT | NODE_ROLE_RELAY);
	NodeGetStatus(n, &st);
	HUB *h = NodeGetHub(n, SERVER_DEFAULT_HUB_NAME);
	NodeTestCheck(ctx, roles == (NODE_ROLE_CLIENT | NODE_ROLE_RELAY) && st.Roles == roles && st.NumHubs == 0 && h == NULL,
		"NodeSetRoles(client, relay) on a server node stops the server role and its hub, and starts client and relay",
		"returned 0x%x, status 0x%x, %u hubs", roles, st.Roles, st.NumHubs);
	ReleaseHub(h);

	roles = NodeSetRoles(n, 0xFFFFFFFF);
	h = NodeGetHub(n, SERVER_DEFAULT_HUB_NAME);
	NodeTestCheck(ctx, roles == NODE_ROLE_ALL && h != NULL,
		"NodeSetRoles with every bit set runs the four roles, the server role with its hub again",
		"returned 0x%x, hub %s", roles, h != NULL ? "found" : "missing");
	ReleaseHub(h);

	NodeStop(n);
	roles = NodeSetRoles(n, NODE_ROLE_SERVER);
	NodeTestCheck(ctx, roles == 0, "NodeSetRoles on a stopped node starts nothing", "returned 0x%x", roles);

	FreeNode(n);

	char *log = NodeTestReadLog(dir);
	NodeTestCheck(ctx, NodeTestLogHas(log, "Role server stopped") && NodeTestLogHas(log, "Node roles: client, relay") &&
		NodeTestLogHas(log, "Node roles: server, client, bridge, relay"),
		"The node log records each role change", "%s", log == NULL ? "no node log" : "a line is missing");
	Free(log);

	NodeTestDeleteDir(dir);
}

//
// The fork's Hub, Account and Sam in the node
//

static void NodeTestSam(NODETEST_CTX *ctx)
{
	wchar_t dir[MAX_PATH];
	UCHAR random[SHA1_SIZE];
	AUTH_REQUEST req;
	AUTH_RESULT res;

	NodeTestNewDir(dir, sizeof(dir), "sam");
	NodeTestWriteConfig(dir, "server", 1, NODETEST_HUB);

	NODE *n = NewNode(dir);
	NodeStart(n);

	HUB *h = NodeGetHub(n, NODETEST_HUB);
	HUB *fork_hub = GetHub(n->Cedar, NODETEST_HUB);
	NodeTestCheck(ctx, h != NULL && h == fork_hub && NodeGetHub(n, SERVER_DEFAULT_HUB_NAME) == NULL,
		"The server role runs the hub of the configuration, and only it, as a Hub of the node's Cedar",
		"node hub %p, Cedar hub %p", h, fork_hub);
	ReleaseHub(fork_hub);

	if (h != NULL)
	{
		USER *u = NewUser(NODETEST_USER, L"", L"", AUTHTYPE_PASSWORD, NewPasswordAuthData(NODETEST_USER, NODETEST_PASSWORD));

		AcLock(h);
		{
			AcAddUser(h, u);
		}
		AcUnlock(h);
		ReleaseUser(u);
		ReleaseHub(h);
	}

	Rand(random, sizeof(random));

	Zero(&req, sizeof(req));
	req.Username = NODETEST_USER;
	req.AuthType = CLIENT_AUTHTYPE_PLAIN_PASSWORD;
	req.PlainPassword = NODETEST_PASSWORD;
	req.Random = random;

	bool ok = NodeAuthenticate(n, NODETEST_HUB, &req, &res);
	NodeTestCheck(ctx, ok && res.Ok && res.Error == ERR_NO_ERROR,
		"Sam accepts the password of a user that Account added to the node's hub", "ok %u, error %u", (UINT)ok, res.Error);
	Free(res.Policy);
	FreeX(res.ClientX);

	req.PlainPassword = "wrong";
	ok = NodeAuthenticate(n, NODETEST_HUB, &req, &res);
	NodeTestCheck(ctx, ok == false && res.Ok == false && res.Error == ERR_AUTH_FAILED,
		"Sam refuses a wrong password", "ok %u, error %u", (UINT)ok, res.Error);
	Free(res.Policy);
	FreeX(res.ClientX);

	req.PlainPassword = NODETEST_PASSWORD;
	ok = NodeAuthenticate(n, "NOSUCHHUB", &req, &res);
	NodeTestCheck(ctx, ok == false && res.Error == ERR_HUB_NOT_FOUND,
		"A hub that the server role does not run gives ERR_HUB_NOT_FOUND", "ok %u, error %u", (UINT)ok, res.Error);

	NodeStop(n);
	ok = NodeAuthenticate(n, NODETEST_HUB, &req, &res);
	NodeTestCheck(ctx, ok == false && res.Error == ERR_HUB_NOT_FOUND,
		"A stopped node authenticates nobody", "ok %u, error %u", (UINT)ok, res.Error);

	FreeNode(n);

	char *log = NodeTestReadLog(dir);
	NodeTestCheck(ctx, NodeTestLogHas(log, "Hub " NODETEST_HUB " online") && NodeTestLogHas(log, "Hub " NODETEST_HUB " stopped"),
		"The node log (LogWriter) records the hub of the server role", "%s", log == NULL ? "no node log" : "a line is missing");
	Free(log);

	NodeTestDeleteDir(dir);
}

//
// Workers
//

// What a probe work item saw
typedef struct NODETEST_PROBE
{
	PROCESSOR_NUMBER Processor;		// The core it ran on
	UINT ThreadId;					// The thread it ran on
	UINT Index;						// The index of its worker
	volatile LONG *Done;			// Counted up when it ran
} NODETEST_PROBE;

static void NodeTestProbeItem(NODE_WORKER *w, void *param)
{
	NODETEST_PROBE *p = (NODETEST_PROBE *)param;

	GetCurrentProcessorNumberEx(&p->Processor);
	p->ThreadId = GetCurrentThreadId();
	p->Index = w->Index;

	InterlockedIncrement(p->Done);
}

// The order in which items of one worker ran
typedef struct NODETEST_ORDER
{
	UINT Next;						// The sequence number the next item must have
	UINT Wrong;						// Items that ran out of order
	volatile LONG Done;				// Items that ran
} NODETEST_ORDER;

static NODETEST_ORDER nodetest_order;

static void NodeTestOrderItem(NODE_WORKER *w, void *param)
{
	UINT seq = (UINT)(UINT_PTR)param;

	if (seq != nodetest_order.Next)
	{
		nodetest_order.Wrong++;
	}

	nodetest_order.Next = seq + 1;
	InterlockedIncrement(&nodetest_order.Done);
}

static void NodeTestWorkers(NODETEST_CTX *ctx)
{
	wchar_t dir[MAX_PATH];
	NODE_STATUS st;
	volatile LONG done = 0;
	UINT cores = NodeTestNumCores();

	NodeTestNewDir(dir, sizeof(dir), "workers");
	NodeTestWriteConfig(dir, "none", 0, NULL);

	NODE *n = NewNode(dir);
	NodeStart(n);
	NodeGetStatus(n, &st);
	NodeTestCheck(ctx, st.NumWorkers == cores && st.Roles == 0, "No NumWorkers item: one worker per active core; Roles none runs no role",
		"%u workers for %u cores, roles 0x%x", st.NumWorkers, cores, st.Roles);

	UINT num = st.NumWorkers;
	NODETEST_PROBE *probes = ZeroMalloc(sizeof(NODETEST_PROBE) * MAX(num, 1));
	for (UINT i = 0;i < num;i++)
	{
		probes[i].Done = &done;
		NodePost(n, i, NodeTestProbeItem, &probes[i]);
	}
	bool all = NodeTestWait(&done, (LONG)num, NODETEST_BOUND);

	UINT wrong_core = 0, wrong_index = 0, same_thread = 0;
	for (UINT i = 0;i < num && all;i++)
	{
		NODE_WORKER *w = n->Workers[i];

		if (probes[i].Processor.Group != w->Processor.Group || probes[i].Processor.Number != w->Processor.Number)
		{
			wrong_core++;
		}
		if (probes[i].Index != i || probes[i].ThreadId != w->ThreadId)
		{
			wrong_index++;
		}
		for (UINT j = 0;j < i;j++)
		{
			if (probes[j].ThreadId == probes[i].ThreadId)
			{
				same_thread++;
			}
		}
		if (probes[i].ThreadId == GetCurrentThreadId())
		{
			same_thread++;
		}
	}
	NodeTestCheck(ctx, all && wrong_core == 0 && wrong_index == 0 && same_thread == 0,
		"Each worker runs its work item on its own thread, bound to its own core",
		"%u of %u ran, %u on another core, %u on another worker, %u on a shared thread",
		(UINT)done, num, wrong_core, wrong_index, same_thread);
	Free(probes);

	Zero(&nodetest_order, sizeof(nodetest_order));
	for (UINT i = 0;i < 1000;i++)
	{
		NodePost(n, num - 1, NodeTestOrderItem, (void *)(UINT_PTR)i);
	}
	all = NodeTestWait(&nodetest_order.Done, 1000, NODETEST_BOUND);
	NodeTestCheck(ctx, all && nodetest_order.Wrong == 0, "1000 work items of one worker run in posting order",
		"%u ran, %u out of order", (UINT)nodetest_order.Done, nodetest_order.Wrong);

	NodeTestCheck(ctx, NodePost(n, num, NodeTestProbeItem, NULL) == false && NodePost(n, 0, NULL, NULL) == false,
		"NodePost refuses a worker that does not exist and a work item without a procedure", "accepted");

	NodeStop(n);
	NodeTestCheck(ctx, NodePost(n, 0, NodeTestProbeItem, NULL) == false, "NodePost refuses a stopped node", "accepted");

	FreeNode(n);
	NodeTestDeleteDir(dir);
}

//
// Adapter queues
//

// A fake adapter queue: frames counted in Pending, MAC addresses 02:00:00:00:00:<seq % 20>
typedef struct NODETEST_QUEUE
{
	HANDLE Event;					// Signalled when Pending grew
	volatile LONG Pending;			// Frames waiting
	UINT Seq;						// Frames drained so far (the I/O thread only)
	volatile LONG Hits;				// Frames whose MAC address the MAC table knows
	volatile LONG Misses;			// Frames whose MAC address it does not know
	volatile LONG Drained;			// Frames drained
	UINT FirstThread;				// The thread of the first drain
	UINT OtherThread;				// Drains on another thread
} NODETEST_QUEUE;

static void NodeTestMac(UCHAR *mac, UINT n)
{
	Zero(mac, 6);
	mac[0] = 0x02;
	mac[5] = (UCHAR)n;
}

static void NodeTestQueueProc(NODE_QUEUE *q, void *param)
{
	NODETEST_QUEUE *f = (NODETEST_QUEUE *)param;
	UCHAR key[NODE_TABLE_KEY_SIZE];
	UCHAR mac[6];
	LONG num = InterlockedExchange(&f->Pending, 0);

	if (f->FirstThread == 0)
	{
		f->FirstThread = GetCurrentThreadId();
	}
	else if (f->FirstThread != GetCurrentThreadId())
	{
		f->OtherThread++;
	}

	NODE_TABLES *t = NodeGetTables(q->Node);

	for (LONG i = 0;i < num;i++)
	{
		NodeTestMac(mac, f->Seq % NODETEST_QUEUE_FRAMES);
		NodeMacKey(key, 0, mac);

		if (t != NULL && NodeTableLookup(t->Mac, key) != NULL)
		{
			InterlockedIncrement(&f->Hits);
		}
		else
		{
			InterlockedIncrement(&f->Misses);
		}

		f->Seq++;
		InterlockedIncrement(&f->Drained);
	}
}

static void NodeTestQueues(NODETEST_CTX *ctx)
{
	wchar_t dir[MAX_PATH];
	NODE_STATUS st;
	NODETEST_QUEUE f, f2;
	NODE_TABLE_ENTRY e[NODETEST_QUEUE_KNOWN];

	NodeTestNewDir(dir, sizeof(dir), "queues");
	NodeTestWriteConfig(dir, "none", 1, NULL);

	NODE *n = NewNode(dir);
	NodeStart(n);

	// A MAC table of the 16 known addresses
	Zero(e, sizeof(e));
	for (UINT i = 0;i < NODETEST_QUEUE_KNOWN;i++)
	{
		UCHAR mac[6];

		NodeTestMac(mac, i);
		NodeMacKey(e[i].Key, 0, mac);
		e[i].Value = i;
	}
	NodeTestCheck(ctx, NodeSwapTables(n, NodeNewTables(NodeNewTable(e, NODETEST_QUEUE_KNOWN), NULL, NULL)),
		"NodeSwapTables installs a MAC table from a thread that is no reader", "refused");

	Zero(&f, sizeof(f));
	f.Event = CreateEventW(NULL, FALSE, FALSE, NULL);
	NODE_QUEUE *q = NodeAddQueue(n, "fake0", f.Event, NodeTestQueueProc, &f);
	NodeGetStatus(n, &st);
	NodeTestCheck(ctx, q != NULL && st.NumQueues == 1 && st.NumReaders == 2,
		"NodeAddQueue attaches a queue whose I/O thread is a table reader", "queue %p, %u queues, %u readers", q, st.NumQueues, st.NumReaders);

	bool ok = (q != NULL);
	for (UINT round = 1;round <= 3 && ok;round++)
	{
		InterlockedExchangeAdd(&f.Pending, NODETEST_QUEUE_FRAMES);
		SetEvent(f.Event);
		ok = NodeTestWait(&f.Drained, (LONG)(round * NODETEST_QUEUE_FRAMES), NODETEST_BOUND);
	}
	NodeTestCheck(ctx, ok && f.Hits == 3 * NODETEST_QUEUE_KNOWN && f.Misses == 3 * (NODETEST_QUEUE_FRAMES - NODETEST_QUEUE_KNOWN),
		"The I/O thread drains three rounds of 20 frames and looks each MAC address up in the snapshot: 48 known, 12 unknown",
		"%u drained, %u known, %u unknown", (UINT)f.Drained, (UINT)f.Hits, (UINT)f.Misses);
	NodeTestCheck(ctx, ok && f.OtherThread == 0 && f.FirstThread != 0 && f.FirstThread == q->ThreadId &&
		f.FirstThread != n->Workers[0]->ThreadId && f.FirstThread != GetCurrentThreadId(),
		"Every drain runs on the one I/O thread of the queue, which is no worker",
		"first thread %u, queue thread %u, %u drains elsewhere", f.FirstThread, q != NULL ? q->ThreadId : 0, f.OtherThread);

	NodeDelQueue(n, q);
	NodeGetStatus(n, &st);
	NodeTestCheck(ctx, st.NumQueues == 0 && st.NumReaders == 1, "NodeDelQueue joins the I/O thread and unregisters its reader",
		"%u queues, %u readers", st.NumQueues, st.NumReaders);

	// A queue left attached: NodeStop detaches it
	Zero(&f2, sizeof(f2));
	f2.Event = CreateEventW(NULL, FALSE, FALSE, NULL);
	NodeAddQueue(n, "fake1", f2.Event, NodeTestQueueProc, &f2);
	NodeStop(n);
	NodeGetStatus(n, &st);
	NodeTestCheck(ctx, st.NumQueues == 0 && st.NumReaders == 0 && NodeAddQueue(n, "late", f2.Event, NodeTestQueueProc, &f2) == NULL,
		"NodeStop detaches a queue left attached, and a stopped node attaches none", "%u queues, %u readers", st.NumQueues, st.NumReaders);

	FreeNode(n);

	char *log = NodeTestReadLog(dir);
	NodeTestCheck(ctx, NodeTestLogHas(log, "Adapter queue fake0 detached after") && NodeTestLogHas(log, "1 adapter queues detached"),
		"The node log records the queues", "%s", log == NULL ? "no node log" : "a line is missing");
	Free(log);

	CloseHandle(f.Event);
	CloseHandle(f2.Event);
	NodeTestDeleteDir(dir);
}

//
// The table snapshot
//

// One entry of table number x of a snapshot built for generation g: key x, then i big-endian, so the sorted
// order is i; value g in the high bits and i in the low 16 bits
static void NodeTestEntry(NODE_TABLE_ENTRY *e, UINT x, UINT i, UINT64 g)
{
	Zero(e, sizeof(NODE_TABLE_ENTRY));
	e->Key[0] = (UCHAR)x;
	e->Key[1] = (UCHAR)(i >> 8);
	e->Key[2] = (UCHAR)i;
	e->Value = (g << 16) | i;
}

static NODE_TABLE *NodeTestTable(UINT x, UINT num, UINT64 g)
{
	NODE_TABLE_ENTRY *e = ZeroMalloc(sizeof(NODE_TABLE_ENTRY) * num);

	for (UINT i = 0;i < num;i++)
	{
		// Written in reverse: NodeNewTable sorts
		NodeTestEntry(&e[i], x, num - 1 - i, g);
	}

	NODE_TABLE *t = NodeNewTable(e, num);
	Free(e);

	return t;
}

// A snapshot whose every entry carries generation g
static NODE_TABLES *NodeTestTables(UINT64 g)
{
	return NodeNewTables(NodeTestTable(1, NODETEST_MAC_ENTRIES, g), NodeTestTable(2, NODETEST_ROUTE_ENTRIES, g),
		NodeTestTable(3, NODETEST_POLICY_ENTRIES, g));
}

// Whether one table of a snapshot is whole: num entries in key order, each of generation g
static bool NodeTestTableIsWhole(NODE_TABLE *t, UINT x, UINT num, UINT64 g)
{
	if (t == NULL || t->NumEntries != num || t->Entries == NULL)
	{
		return false;
	}

	for (UINT i = 0;i < num;i++)
	{
		NODE_TABLE_ENTRY *e = &t->Entries[i];

		if (e->Key[0] != x || e->Key[1] != (UCHAR)(i >> 8) || e->Key[2] != (UCHAR)i || e->Value != ((g << 16) | i))
		{
			return false;
		}
	}

	return true;
}

// Whether a snapshot is whole: its generation is not 0 and every entry of its three tables carries it
static bool NodeTestTablesAreWhole(NODE_TABLES *t)
{
	if (t == NULL || t->Generation == 0)
	{
		return false;
	}

	return NodeTestTableIsWhole(t->Mac, 1, NODETEST_MAC_ENTRIES, t->Generation) &&
		NodeTestTableIsWhole(t->Route, 2, NODETEST_ROUTE_ENTRIES, t->Generation) &&
		NodeTestTableIsWhole(t->Policy, 3, NODETEST_POLICY_ENTRIES, t->Generation);
}

// The state of the swap case, shared by the reader items
typedef struct NODETEST_SWAP
{
	volatile LONG Stop;				// Set to end the reader items
	volatile LONG Done;				// Reader items that ended
	volatile LONG Changed;			// Reader items that saw the generation change: the swaps reached them
} NODETEST_SWAP;

static NODETEST_SWAP nodetest_swap;

// What the reader item of one worker saw
typedef struct NODETEST_READER
{
	UINT64 Passes;					// Snapshots read
	UINT64 Torn;					// Snapshots that were not whole
	UINT64 Backwards;				// Snapshots older than the one read before
	UINT64 Distinct;				// Changes of the generation between two passes
	UINT64 Last;					// The generation of the last pass
} NODETEST_READER;

// One pass of a reader: read the current snapshot, check it, then post the next pass to the same worker. The
// worker passes its quiescent point between two passes, as the data path does between two batches.
static void NodeTestReaderItem(NODE_WORKER *w, void *param)
{
	NODETEST_READER *r = (NODETEST_READER *)param;
	NODE_TABLES *t = NodeGetTables(w->Node);

	if (NodeTestTablesAreWhole(t) == false)
	{
		r->Torn++;
	}
	else
	{
		if (t->Generation < r->Last)
		{
			r->Backwards++;
		}
		if (t->Generation != r->Last)
		{
			r->Distinct++;

			// The second generation it sees: the first change, which the main thread waits for
			if (r->Distinct == 2)
			{
				InterlockedIncrement(&nodetest_swap.Changed);
			}
		}
		r->Last = t->Generation;
	}

	r->Passes++;

	if (InterlockedCompareExchange(&nodetest_swap.Stop, 0, 0) != 0 || NodePost(w->Node, w->Index, NodeTestReaderItem, r) == false)
	{
		InterlockedIncrement(&nodetest_swap.Done);
	}
}

// A reader that holds a snapshot until it is released
typedef struct NODETEST_SLOW
{
	HANDLE Holding;					// Set once it holds the snapshot
	HANDLE Release;					// Lets it go on
	UINT64 Generation;				// The generation it holds
	bool WholeAfter;				// The snapshot was still whole when it was released
	volatile LONG Done;				// It ended
} NODETEST_SLOW;

static void NodeTestSlowItem(NODE_WORKER *w, void *param)
{
	NODETEST_SLOW *s = (NODETEST_SLOW *)param;
	NODE_TABLES *t = NodeGetTables(w->Node);

	s->Generation = (t != NULL ? t->Generation : 0);
	SetEvent(s->Holding);

	WaitForSingleObject(s->Release, NODETEST_BOUND);

	s->WholeAfter = (NodeTestTablesAreWhole(t) && t->Generation == s->Generation);
	InterlockedIncrement(&s->Done);
}

// A swap from a worker: refused, because the worker is an online reader and would wait for itself
typedef struct NODETEST_SELF_SWAP
{
	bool Refused;					// NodeSwapTables returned false
	volatile LONG Done;				// The item ran
} NODETEST_SELF_SWAP;

static void NodeTestSelfSwapItem(NODE_WORKER *w, void *param)
{
	NODETEST_SELF_SWAP *s = (NODETEST_SELF_SWAP *)param;
	NODE_TABLES *t = NodeNewTables(NULL, NULL, NULL);

	s->Refused = (NodeSwapTables(w->Node, t) == false);
	if (s->Refused)
	{
		NodeFreeTables(t);
	}

	InterlockedIncrement(&s->Done);
}

// The swap of the grace period case, on a thread of its own
typedef struct NODETEST_SWAPPER
{
	NODE *Node;						// The node
	NODE_TABLES *Tables;			// The snapshot to install
	bool Ret;						// What NodeSwapTables returned
} NODETEST_SWAPPER;

static void NodeTestSwapperThread(THREAD *thread, void *param)
{
	NODETEST_SWAPPER *s = (NODETEST_SWAPPER *)param;

	s->Ret = NodeSwapTables(s->Node, s->Tables);
}

// What a round of swaps under the readers came to
typedef struct NODETEST_ROUND
{
	bool Ended;						// The reader items ended once they were told to
	UINT Swaps;						// Swaps the node took
	UINT Refused;					// Swaps it refused
	UINT Elapsed;					// How long the round took (ms)
	UINT64 Passes;					// Snapshots read, by all readers
	UINT64 Torn;					// ... that were not whole
	UINT64 Backwards;				// ... that were older than the one read before
	UINT Few;						// Readers that saw fewer than two generations
} NODETEST_ROUND;

// Fewer than NODETEST_SWAP_MIN swaps, each after a pause of NODETEST_SWAP_PAUSE, fit in NODETEST_SWAP_TIME: the slow
// round always waits for the condition of the generations check, which a busy machine makes the other round do now
// and then
_Static_assert(NODETEST_SWAP_TIME / NODETEST_SWAP_PAUSE + 1 < NODETEST_SWAP_MIN, "the slow round must not reach NODETEST_SWAP_MIN swaps within NODETEST_SWAP_TIME");

// Whether the generations check has what it waits for: its swaps, and the change of the generation seen by every reader
static bool NodeTestGenerationsSeen(UINT swaps, UINT readers)
{
	return (swaps >= NODETEST_SWAP_MIN && InterlockedCompareExchange(&nodetest_swap.Changed, 0, 0) >= (LONG)readers);
}

// A reader item on each of the num workers, then swaps under them, with a pause of pause ms (0 for none) before each.
// The swaps go on for NODETEST_SWAP_TIME at least, the load that the atomicity check needs, and after that until the
// generations check has what it waits for. How many swaps fit in a given time is up to the scheduler: a swap waits for
// every reader to run, and a busy machine runs them late. So the condition ends the round, and the bound of
// NODETEST_SWAP_BOUND when the condition never comes.
static void NodeTestSwapRound(NODE *n, UINT num, UINT pause, NODETEST_ROUND *r)
{
	NODE_STATUS st;

	Zero(r, sizeof(NODETEST_ROUND));
	Zero(&nodetest_swap, sizeof(nodetest_swap));

	NODETEST_READER *readers = ZeroMalloc(sizeof(NODETEST_READER) * MAX(num, 1));
	for (UINT i = 0;i < num;i++)
	{
		NodePost(n, i, NodeTestReaderItem, &readers[i]);
	}

	UINT64 start = Tick64();
	UINT64 now = start;
	while (r->Swaps < NODETEST_SWAP_MAX && now - start < NODETEST_SWAP_BOUND &&
		(now - start < NODETEST_SWAP_TIME || NodeTestGenerationsSeen(r->Swaps, num) == false))
	{
		if (pause != 0)
		{
			SleepThread(pause);
		}

		NodeGetStatus(n, &st);
		NODE_TABLES *t = NodeTestTables(st.Generation + 1);
		if (NodeSwapTables(n, t))
		{
			r->Swaps++;
		}
		else
		{
			NodeFreeTables(t);
			r->Refused++;
		}

		now = Tick64();
	}
	r->Elapsed = (UINT)(now - start);

	InterlockedExchange(&nodetest_swap.Stop, 1);
	r->Ended = NodeTestWait(&nodetest_swap.Done, (LONG)num, NODETEST_BOUND);

	for (UINT i = 0;i < num;i++)
	{
		r->Passes += readers[i].Passes;
		r->Torn += readers[i].Torn;
		r->Backwards += readers[i].Backwards;
		if (readers[i].Distinct < 2)
		{
			r->Few++;
		}
	}
	Free(readers);
}

static void NodeTestSwap(NODETEST_CTX *ctx)
{
	wchar_t dir[MAX_PATH];
	NODE_STATUS st;
	char what[MAX_SIZE];

	NodeTestNewDir(dir, sizeof(dir), "swap");
	NodeTestWriteConfig(dir, "none", 0, NULL);

	NODE *n = NewNode(dir);
	NodeStart(n);
	NodeGetStatus(n, &st);
	UINT num = st.NumWorkers;

	// A whole snapshot before the readers start: generation 2, after the empty one of NodeStart
	NODE_TABLES *t = NodeTestTables(st.Generation + 1);
	bool ok = NodeSwapTables(n, t);
	NodeGetStatus(n, &st);
	NodeTestCheck(ctx, ok && st.Generation == 2, "NodeSwapTables gives the snapshot the next generation",
		"returned %u, generation %I64u", (UINT)ok, st.Generation);

	// A reader on every worker, then swaps under them. What fits in NODETEST_SWAP_TIME is the load of the atomicity
	// check. The generations check does not count it: on a busy machine the round goes on until the swaps are done
	// and every reader has seen the generation change.
	NODETEST_ROUND fast, paused;

	NodeTestSwapRound(n, num, 0, &fast);
	Print("  %u swaps in %u ms under %u readers, %I64u reads\n", fast.Swaps, fast.Elapsed, num, fast.Passes);

	Format(what, sizeof(what), "Swaps under a reader on each of the %u workers: no reader sees a torn, wiped or older snapshot", num);
	NodeTestCheck(ctx, fast.Ended && fast.Refused == 0 && fast.Torn == 0 && fast.Backwards == 0, what,
		"readers ended %u, %u swaps refused, %I64u torn, %I64u older", (UINT)fast.Ended, fast.Refused, fast.Torn, fast.Backwards);
	NodeTestCheck(ctx, fast.Ended && fast.Swaps >= NODETEST_SWAP_MIN && fast.Few == 0, "Every reader sees several generations while the swaps run",
		"readers ended %u, %u swaps in %u ms, %u readers saw fewer than two generations", (UINT)fast.Ended, fast.Swaps, fast.Elapsed, fast.Few);

	// The same with a pause before each swap, so that fewer than NODETEST_SWAP_MIN fit in NODETEST_SWAP_TIME, as on a
	// busy machine: the generations check has to wait for its condition in every run, not only in a slow one
	NodeTestSwapRound(n, num, NODETEST_SWAP_PAUSE, &paused);
	Print("  %u swaps in %u ms under %u readers, a pause of %u ms before each, %I64u reads\n", paused.Swaps, paused.Elapsed, num,
		NODETEST_SWAP_PAUSE, paused.Passes);

	NodeTestCheck(ctx, paused.Ended && paused.Refused == 0 && paused.Torn == 0 && paused.Backwards == 0 && paused.Swaps >= NODETEST_SWAP_MIN &&
		paused.Few == 0, "Every reader sees several generations when the swaps are slow: the check waits for them, not for a time",
		"readers ended %u, %u swaps refused, %I64u torn, %I64u older, %u swaps in %u ms, %u readers saw fewer than two generations",
		(UINT)paused.Ended, paused.Refused, paused.Torn, paused.Backwards, paused.Swaps, paused.Elapsed, paused.Few);

	// A reader that holds a snapshot: the swap waits for it, the other workers go on
	NODETEST_SLOW s;
	NODETEST_SWAPPER sw;
	Zero(&s, sizeof(s));
	Zero(&sw, sizeof(sw));
	s.Holding = CreateEventW(NULL, TRUE, FALSE, NULL);
	s.Release = CreateEventW(NULL, TRUE, FALSE, NULL);

	NodePost(n, 0, NodeTestSlowItem, &s);
	bool holding = (WaitForSingleObject(s.Holding, NODETEST_BOUND) == WAIT_OBJECT_0);

	NodeGetStatus(n, &st);
	sw.Node = n;
	sw.Tables = NodeTestTables(st.Generation + 1);
	THREAD *thread = NewThread(NodeTestSwapperThread, &sw);

	bool waited = (WaitThread(thread, NODETEST_HOLD) == false);
	NodeTestCheck(ctx, holding && waited, "A swap does not return while a worker holds the old snapshot",
		"holding %u, the swap returned within %u ms", (UINT)holding, NODETEST_HOLD);

	if (num >= 2)
	{
		volatile LONG done = 0;
		NODETEST_PROBE p;

		Zero(&p, sizeof(p));
		p.Done = &done;
		NodePost(n, num - 1, NodeTestProbeItem, &p);
		bool ran = NodeTestWait(&done, 1, NODETEST_BOUND);
		NodeTestCheck(ctx, ran && WaitThread(thread, 0) == false, "Another worker runs its work items while the swap waits: no forwarding lock",
			"ran %u", (UINT)ran);
	}
	else
	{
		Print("  (one core: no other worker to run while the swap waits)\n");
	}

	SetEvent(s.Release);
	bool returned = WaitThread(thread, NODETEST_BOUND);
	NodeTestWait(&s.Done, 1, NODETEST_BOUND);
	NodeGetStatus(n, &st);
	NodeTestCheck(ctx, returned && sw.Ret && s.WholeAfter && st.Generation == s.Generation + 1,
		"Once the reader lets go, the swap returns; the reader's snapshot stayed whole until then",
		"returned %u, swapped %u, whole %u, generation %I64u after %I64u", (UINT)returned, (UINT)sw.Ret, (UINT)s.WholeAfter,
		st.Generation, s.Generation);
	ReleaseThread(thread);
	CloseHandle(s.Holding);
	CloseHandle(s.Release);

	NODETEST_SELF_SWAP self;
	Zero(&self, sizeof(self));
	NodePost(n, 0, NodeTestSelfSwapItem, &self);
	bool ran = NodeTestWait(&self.Done, 1, NODETEST_BOUND);
	NodeTestCheck(ctx, ran && self.Refused, "NodeSwapTables on a worker, an online reader, is refused instead of waiting for itself",
		"ran %u, refused %u", (UINT)ran, (UINT)self.Refused);

	// A thread that registers itself as a reader reads the snapshot, and may not swap while it is online
	NODE_READER r;
	Zero(&r, sizeof(r));
	NodeReaderRegister(n, &r);
	t = NodeNewTables(NULL, NULL, NULL);
	ok = NodeSwapTables(n, t);
	if (ok == false)
	{
		NodeFreeTables(t);
	}
	NodeTestCheck(ctx, NodeTestTablesAreWhole(NodeGetTables(n)) && ok == false && r.ThreadId == GetCurrentThreadId(),
		"A thread registered as a reader reads the whole snapshot, and its swap is refused while it is online", "swap %u", (UINT)ok);
	NodeReaderUnregister(n, &r);
	NodeGetStatus(n, &st);
	NodeTestCheck(ctx, st.NumReaders == num, "NodeReaderUnregister removes the reader", "%u readers for %u workers", st.NumReaders, num);

	NodeStop(n);
	NodeGetStatus(n, &st);
	t = NodeTestTables(1);
	ok = NodeSwapTables(n, t);
	if (ok == false)
	{
		NodeFreeTables(t);
	}
	NodeTestCheck(ctx, NodeGetTables(n) == NULL && st.Generation == 0 && ok == false,
		"A stopped node has no snapshot and refuses a swap", "snapshot %p, generation %I64u, swap %u", NodeGetTables(n), st.Generation, (UINT)ok);

	FreeNode(n);
	NodeTestDeleteDir(dir);
}

//
// The relay role
//

// One node of the relay case: a peer layer of the new core on a UDP socket of its own
typedef struct NODETEST_PEER
{
	PEER_KEY Key;					// Its static key
	PEER_UDP *Udp;					// Its socket
	PEER_AGENT *Agent;				// Its peer layer
	PEER_ADDR Addr;					// Its address on the loopback interface
	volatile LONG Received;			// Datagrams that reached it through the relay
	volatile LONG Echo;				// Answer "ping" with "pong"
	char Last[64];					// The payload of the last one, as text
} NODETEST_PEER;

static void NodeTestPeerRecv(PEER_AGENT *a, void *param, const UCHAR *src, UINT path, const void *data, UINT size)
{
	NODETEST_PEER *p = (NODETEST_PEER *)param;
	UINT len = MIN(size, (UINT)sizeof(p->Last) - 1);

	Copy(p->Last, data, len);
	p->Last[len] = 0;

	if (path == PEER_PATH_RELAY)
	{
		InterlockedIncrement(&p->Received);
	}

	if (InterlockedCompareExchange(&p->Echo, 0, 0) != 0 && size == 4 && Cmp(data, "ping", 4) == 0)
	{
		PeerSend(a, src, "pong", 4);
	}
}

// Start a peer layer with the fixed key of the scalar first, first + 1, ... on a socket of a port that the
// system picks; its host candidate is that port on the loopback address
static bool NodeTestPeerStart(NODETEST_PEER *p, UCHAR first)
{
	UCHAR priv[PEER_KEY_SIZE];

	Zero(p, sizeof(NODETEST_PEER));

	for (UINT i = 0;i < PEER_KEY_SIZE;i++)
	{
		priv[i] = (UCHAR)(first + i);
	}

	if (PeerKeyFromScalar(&p->Key, priv) == false)
	{
		return false;
	}

	p->Udp = PeerUdpNew(0);
	if (p->Udp == NULL)
	{
		return false;
	}

	p->Agent = PeerNew(&p->Key, NULL, PeerUdpSend, p->Udp, NodeTestPeerRecv, p);
	if (p->Agent == NULL || PeerUdpStart(p->Udp, p->Agent) == false)
	{
		return false;
	}

	PeerAddrSetV4(&p->Addr, 127, 0, 0, 1, PeerUdpPort(p->Udp));
	PeerSetHostCandidates(p->Agent, &p->Addr, 1);

	return true;
}

static void NodeTestPeerStop(NODETEST_PEER *p)
{
	PeerUdpFree(p->Udp);
	PeerFree(p->Agent);
	PeerKeyClose(&p->Key);
}

// A peer of a peer table: a node with the key key in one VRF
static void NodeTestPeerInfo(PEER_INFO *info, char *name, UCHAR *key, UINT vrf)
{
	Zero(info, sizeof(PEER_INFO));
	StrCpy(info->Name, sizeof(info->Name), name);
	Copy(info->Key, key, PEER_KEY_SIZE);
	info->NumVrfs = 1;
	info->VrfIds[0] = vrf;
}

// Wait until the peer layer is bound to its relay
static bool NodeTestWaitBound(NODETEST_PEER *p)
{
	UINT64 end = Tick64() + NODETEST_BOUND;
	PEER_STATS st;

	while (true)
	{
		PeerGetStats(p->Agent, &st);
		if (st.NumBound == 1)
		{
			return true;
		}

		if (Tick64() >= end)
		{
			return false;
		}

		SleepThread(10);
	}
}

static void NodeTestRelay(NODETEST_CTX *ctx)
{
	wchar_t dir[MAX_PATH];
	NODE_STATUS st;
	NODETEST_PEER a, b;
	PEER_INFO peers[2];
	PEER_INFO peer;
	PEER_RELAY_INFO relay;
	UCHAR env[PEER_MAX_ENVELOPE];

	NodeTestNewDir(dir, sizeof(dir), "relay");
	NodeTestWriteConfig(dir, "relay", 1, NULL);

	NODE *n = NewNode(dir);
	NodeStart(n);
	NodeGetStatus(n, &st);
	NodeTestCheck(ctx, st.Roles == NODE_ROLE_RELAY && st.RelayPort != 0 && IsZero(st.RelayKey, PEER_KEY_SIZE) == false,
		"The relay role listens on a UDP port, under the node identity key", "roles 0x%x, port %u", st.Roles, (UINT)st.RelayPort);

	bool ok = NodeTestPeerStart(&a, 1);
	ok = NodeTestPeerStart(&b, 33) && ok;
	NodeTestCheck(ctx, ok, "Two peer layers of the new core start on UDP sockets of their own", "one could not start");

	if (ok && st.RelayPort != 0)
	{
		// The Peer objects of the relay node, of a and of b, and the Relay object of a and b
		NodeTestPeerInfo(&peers[0], "a", a.Key.Public, 10);
		NodeTestPeerInfo(&peers[1], "b", b.Key.Public, 10);
		NodeSetPeers(n, peers, 2);

		Zero(&relay, sizeof(relay));
		StrCpy(relay.Name, sizeof(relay.Name), "relay");
		Copy(relay.Key, st.RelayKey, PEER_KEY_SIZE);
		PeerAddrSetV4(&relay.Addr, 127, 0, 0, 1, st.RelayPort);

		NodeTestPeerInfo(&peer, "b", b.Key.Public, 10);
		PeerSetPeers(a.Agent, &peer, 1);
		PeerSetRelays(a.Agent, &relay, 1);
		NodeTestPeerInfo(&peer, "a", a.Key.Public, 10);
		PeerSetPeers(b.Agent, &peer, 1);
		PeerSetRelays(b.Agent, &relay, 1);

		bool bound = NodeTestWaitBound(&a);
		bound = NodeTestWaitBound(&b) && bound;
		NodeGetStatus(n, &st);
		NodeTestCheck(ctx, bound && st.RelayBindings == 2 && st.RelayBinds >= 2, "Both bind to the relay role of the node, which answers each bind",
			"bound %u, %u bindings, %I64u binds", (UINT)bound, st.RelayBindings, st.RelayBinds);

		// One signal each way, which the control plane would carry
		UINT size = PeerSealSignal(a.Agent, b.Key.Public, PEER_SIGNAL_OFFER, env, sizeof(env));
		UINT offer = PeerOpenSignal(b.Agent, env, size, NULL);
		size = PeerSealSignal(b.Agent, a.Key.Public, PEER_SIGNAL_ANSWER, env, sizeof(env));
		UINT answer = PeerOpenSignal(a.Agent, env, size, NULL);
		NodeTestCheck(ctx, offer == PEER_OK && answer == PEER_OK, "Each takes the other's signal, which names the relay of the node",
			"offer: %s, answer: %s", PeerReasonName(offer), PeerReasonName(answer));

		InterlockedExchange(&b.Echo, 1);
		bool sent = PeerSend(a.Agent, b.Key.Public, "ping", 4);
		bool got = NodeTestWait(&a.Received, 1, NODETEST_BOUND);
		NodeGetStatus(n, &st);
		// Four forwarded: the handshake of the peer session that the ping starts (its initiation and response), the ping
		// and the pong
		NodeTestCheck(ctx, sent && got && b.Received == 1 && StrCmp(a.Last, "pong") == 0 && st.RelayForwarded == 4,
			"A ping and its pong go between the two through the relay role of the node, over UDP, in a peer session", "sent %u, received %u and %u, %I64u forwarded",
			(UINT)sent, (UINT)a.Received, (UINT)b.Received, st.RelayForwarded);

		// The control plane takes the peers of the relay away: it drops their bindings and forwards nothing
		NodeSetPeers(n, NULL, 0);
		PeerSend(a.Agent, b.Key.Public, "ping", 4);
		SleepThread(NODETEST_QUIET);
		NodeGetStatus(n, &st);
		NodeTestCheck(ctx, b.Received == 1 && st.RelayBindings == 0 && st.RelayForwarded == 4,
			"With no peers set, the relay role holds no binding and forwards nothing", "%u received, %u bindings, %I64u forwarded",
			(UINT)b.Received, st.RelayBindings, st.RelayForwarded);
	}

	NodeTestPeerStop(&a);
	NodeTestPeerStop(&b);

	NodeStop(n);
	NodeGetStatus(n, &st);
	NodeTestCheck(ctx, st.RelayPort == 0 && st.RelayBindings == 0, "NodeStop stops the relay role and closes its socket", "port %u, %u bindings",
		(UINT)st.RelayPort, st.RelayBindings);

	FreeNode(n);

	char *log = NodeTestReadLog(dir);
	NodeTestCheck(ctx, NodeTestLogHas(log, "Relay listening on UDP port") && NodeTestLogHas(log, "Peers set: 2") && NodeTestLogHas(log, "Role relay stopped"),
		"The node log records the relay role and the peers", "%s", log == NULL ? "no node log" : "a line is missing");
	Free(log);

	NodeTestDeleteDir(dir);
}

// node: the node in-process
RANZ_TEST("node", node_test, "Node: each role from the configuration starts and stops with every thread joined; per-core workers, adapter queues, atomic table swaps; fork Hub and Sam.");
void node_test(UINT num, char **arg)
{
	NODETEST_CTX ctx;
	NODETEST_WATCHDOG wd;

	Zero(&ctx, sizeof(ctx));
	NodeTestWatchdogStart(&wd, "NODE");

	Print("Node test: roles, workers, adapter queues and the table snapshot of the new core (%u cores)\n", NodeTestNumCores());

	char unknown[MAX_SIZE];
	char names[MAX_SIZE];
	UINT roles = NodeParseRoles(" server,,RELAY  Client,controller,None ", unknown, sizeof(unknown));
	NodeRolesToStr(names, sizeof(names), roles);
	NodeTestCheck(&ctx, roles == (NODE_ROLE_SERVER | NODE_ROLE_CLIENT | NODE_ROLE_RELAY) && StrCmp(unknown, "controller") == 0 &&
		StrCmp(names, "server, client, relay") == 0,
		"NodeParseRoles takes names without case, separated by commas or spaces, and keeps the ones that are no role",
		"roles 0x%x (%s), unknown \"%s\"", roles, names, unknown);
	roles = NodeParseRoles("none", unknown, sizeof(unknown));
	NodeRolesToStr(names, sizeof(names), roles);
	NodeTestCheck(&ctx, roles == 0 && IsEmptyStr(unknown) && StrCmp(names, "none") == 0 && NodeParseRoles("", NULL, 0) == 0,
		"\"none\" and an empty list name no role, and no role prints as \"none\"", "roles 0x%x, unknown \"%s\"", roles, unknown);

	for (UINT i = 0;i < sizeof(nodetest_role_cases) / sizeof(nodetest_role_cases[0]);i++)
	{
		NodeTestRoleCase(&ctx, &nodetest_role_cases[i]);
	}

	NodeTestSetRoles(&ctx);
	NodeTestSam(&ctx);
	NodeTestWorkers(&ctx);
	NodeTestQueues(&ctx);
	NodeTestSwap(&ctx);
	NodeTestRelay(&ctx);

	// The identity key that the relay role of the test nodes created
	PeerKeyDelete(L"" NODETEST_IDENTITY_KEY);

	NodeTestWatchdogStop(&wd);

	if (ctx.NumFailed == 0)
	{
		Print("NODE TEST OK\n");
	}
	else
	{
		Print("NODE TEST FAILED (%u of %u checks failed)\n", ctx.NumFailed, ctx.NumChecks);
	}
}

//
// The node as a service
//

// Run ranz-node.exe with one argument and wait for it to exit; true when it ran and exited in time
static bool NodeSvcRun(wchar_t *exe, char *arg)
{
	wchar_t cmd[MAX_PATH * 2];
	STARTUPINFOW si;
	PROCESS_INFORMATION pi;

	UniFormat(cmd, sizeof(cmd), L"\"%s\" %S", exe, arg);

	Zero(&si, sizeof(si));
	si.cb = sizeof(si);
	Zero(&pi, sizeof(pi));

	if (CreateProcessW(exe, cmd, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi) == false)
	{
		Print("  ranz-node.exe %s: CreateProcessW failed (error %u)\n", arg, (UINT)GetLastError());
		return false;
	}

	bool ret = (WaitForSingleObject(pi.hProcess, NODESVC_RUN_WAIT) == WAIT_OBJECT_0);

	CloseHandle(pi.hThread);
	CloseHandle(pi.hProcess);

	return ret;
}

// The status of the service, polled until it is in state or the bound passes; false when the service cannot
// be queried or never reaches the state
static bool NodeSvcWaitState(DWORD state, SERVICE_STATUS_PROCESS *ss)
{
	UINT64 end = Tick64() + NODESVC_START_WAIT;
	bool ret = false;

	Zero(ss, sizeof(SERVICE_STATUS_PROCESS));

	SC_HANDLE sc = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
	if (sc == NULL)
	{
		return false;
	}

	SC_HANDLE service = OpenServiceW(sc, L"" NODESVC_NAME, SERVICE_QUERY_STATUS);
	while (service != NULL)
	{
		DWORD size = 0;

		if (QueryServiceStatusEx(service, SC_STATUS_PROCESS_INFO, (BYTE *)ss, sizeof(SERVICE_STATUS_PROCESS), &size) &&
			ss->dwCurrentState == state)
		{
			ret = true;
			break;
		}

		if (Tick64() >= end)
		{
			break;
		}

		SleepThread(100);
	}

	if (service != NULL)
	{
		CloseServiceHandle(service);
	}
	CloseServiceHandle(sc);

	return ret;
}

// Wait until the service is gone (DeleteService completes once its last handle closed)
static bool NodeSvcWaitGone()
{
	UINT64 end = Tick64() + NODESVC_START_WAIT;

	while (MsIsServiceInstalled(NODESVC_NAME))
	{
		if (Tick64() >= end)
		{
			return false;
		}

		SleepThread(100);
	}

	return true;
}

// The service runs as its virtual account, not LocalSystem, with an unrestricted service SID, and Windows gives that
// account NODE_SERVICE_SID, the SID that the DACL of the data directory names (ADR-0039 decision 3)
static void NodeSvcAccountCase(NODETEST_CTX *ctx)
{
	BYTE sid_buf[SECURITY_MAX_SID_SIZE];
	wchar_t domain[MAX_SIZE];
	// 8 KB, the largest configuration QueryServiceConfigW returns
	QUERY_SERVICE_CONFIGW *config = ZeroMalloc(8192);
	SERVICE_SID_INFO sid_info;
	DWORD size = 0;
	DWORD sid_size = sizeof(sid_buf);
	DWORD domain_size = ARRAYSIZE(domain);
	SID_NAME_USE use;
	PSID expected = NULL;
	bool got_config = false;
	bool got_sid_type = false;

	Zero(&sid_info, sizeof(sid_info));

	SC_HANDLE sc = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
	SC_HANDLE service = (sc != NULL ? OpenServiceW(sc, L"" NODESVC_NAME, SERVICE_QUERY_CONFIG) : NULL);
	if (service != NULL)
	{
		got_config = QueryServiceConfigW(service, config, 8192, &size);
		got_sid_type = QueryServiceConfig2W(service, SERVICE_CONFIG_SERVICE_SID_INFO, (BYTE *)&sid_info, sizeof(sid_info), &size);
		CloseServiceHandle(service);
	}
	if (sc != NULL)
	{
		CloseServiceHandle(sc);
	}

	wchar_t *account = ((got_config && config->lpServiceStartName != NULL) ? config->lpServiceStartName : L"");
	NodeTestCheck(ctx, UniStrCmpi(account, NODE_SERVICE_ACCOUNT) == 0 && got_sid_type && sid_info.dwServiceSidType == SERVICE_SID_TYPE_UNRESTRICTED,
		"The service runs as its virtual account NT SERVICE\\" NODESVC_NAME ", not LocalSystem, with an unrestricted service SID",
		"account \"%S\", service SID type %u", account, (UINT)sid_info.dwServiceSidType);
	Free(config);

	bool looked_up = LookupAccountNameW(NULL, NODE_SERVICE_ACCOUNT, (PSID)sid_buf, &sid_size, domain, &domain_size, &use);
	DWORD err = GetLastError();
	bool same = (looked_up && ConvertStringSidToSidW(NODE_SERVICE_SID, &expected) && EqualSid((PSID)sid_buf, expected));
	NodeTestCheck(ctx, same, "Windows gives the virtual account NODE_SERVICE_SID, the SID that the DACL of the data directory names",
		"LookupAccountNameW %u (error %u)", (UINT)looked_up, (UINT)err);

	if (expected != NULL)
	{
		LocalFree(expected);
	}
}

// The process of the service runs with each mitigation of NodeGetMitigations that the node sets, and each one that
// is off has its reason recorded (ADR-0039 decision 2)
static void NodeSvcMitigationCase(NODETEST_CTX *ctx, HANDLE process, char *role_name)
{
	char what[MAX_SIZE];
	UINT num = 0;
	const NODE_MITIGATION *m = NodeGetMitigations(&num);

	for (UINT i = 0;i < num;i++)
	{
		DWORD flags = 0;
		bool got = (process != NULL && GetProcessMitigationPolicy(process, (PROCESS_MITIGATION_POLICY)m[i].Policy, &flags, sizeof(flags)));

		if (m[i].Off != NULL)
		{
			Format(what, sizeof(what), "Role %s: mitigation %s is off, with the reason recorded: %s", role_name, m[i].Name, m[i].Off);
			NodeTestCheck(ctx, IsEmptyStr(m[i].Off) == false, what, "no reason");
		}
		else
		{
			Format(what, sizeof(what), "Role %s: the service process runs with mitigation %s", role_name, m[i].Name);
			NodeTestCheck(ctx, got && (flags & m[i].Flags) == m[i].Flags, what, "GetProcessMitigationPolicy %u (error %u), flags 0x%x, expected 0x%x",
				(UINT)got, got ? 0 : (UINT)GetLastError(), (UINT)flags, m[i].Flags);
		}
	}
}

// Every module of the service process but its executable is in System32: the node loads DLLs from System32 only
// (ADR-0039 decision 3, FIX-4), whatever its role loaded
static void NodeSvcModulesCase(NODETEST_CTX *ctx, HANDLE process, wchar_t *exe, char *role_name)
{
	HMODULE mods[1024];
	wchar_t sys32[MAX_PATH];
	wchar_t path[MAX_PATH];
	char name[MAX_PATH];
	char what[MAX_SIZE];
	char others[MAX_SIZE];
	DWORD size = 0;
	UINT num_others = 0;

	StrCpy(others, sizeof(others), "");
	UINT len = GetSystemDirectoryW(sys32, ARRAYSIZE(sys32));
	UniStrCat(sys32, sizeof(sys32), L"\\");

	bool ok = (process != NULL && len != 0 && EnumProcessModulesEx(process, mods, sizeof(mods), &size, LIST_MODULES_ALL));
	UINT num = (ok ? MIN((UINT)(size / sizeof(HMODULE)), (UINT)ARRAYSIZE(mods)) : 0);

	for (UINT i = 0;i < num;i++)
	{
		if (GetModuleFileNameExW(process, mods[i], path, ARRAYSIZE(path)) == 0)
		{
			UniStrCpy(path, sizeof(path), L"(no name)");
		}
		else if (UniStrCmpi(path, exe) == 0 || UniStartWith(path, sys32))
		{
			continue;
		}

		num_others++;
		UniToStr(name, sizeof(name), path);
		StrCat(others, sizeof(others), " ");
		StrCat(others, sizeof(others), name);
	}

	Format(what, sizeof(what), "Role %s: every DLL of the service process is in System32", role_name);
	NodeTestCheck(ctx, ok && num > 1 && num_others == 0, what, "%u modules, %u from elsewhere:%s", num, num_others, others);
}

// One service run with the role role alone: install (which starts the service), stop, uninstall. Without a store
// (no_store) the service starts with the default roles and creates its configuration store. While it runs, the
// hardening of ADR-0039 on its process.
static void NodeSvcRoleCase(NODETEST_CTX *ctx, wchar_t *exe, wchar_t *data_dir, UINT role, bool no_store)
{
	wchar_t log_dir[MAX_PATH];
	char role_name[MAX_SIZE];
	char what[MAX_SIZE];
	char line[MAX_SIZE];
	SERVICE_STATUS_PROCESS ss;
	DWORD exit_code = STILL_ACTIVE;

	NodeRolesToStr(role_name, sizeof(role_name), role);

	// The node log of this run only
	ConbinePathW(log_dir, sizeof(log_dir), data_dir, NODE_LOG_DIR_NAME);
	NodeTestDeleteFiles(log_dir, false);

	if (no_store == false)
	{
		NodeTestWriteConfig(data_dir, role_name, NODETEST_ROLE_WORKERS, NULL);
	}

	NodeSvcRun(exe, "/install");
	bool running = NodeSvcWaitState(SERVICE_RUNNING, &ss);
	HANDLE process = (running ? OpenProcess(SYNCHRONIZE | PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, ss.dwProcessId) : NULL);
	Format(what, sizeof(what), "Role %s: /install installs the %s service and it runs", role_name, NODESVC_NAME);
	NodeTestCheck(ctx, running && process != NULL, what, "state %u, process %u", (UINT)ss.dwCurrentState, (UINT)ss.dwProcessId);

	// The hardening of ADR-0039 on the running service: its account, its mitigations and where its DLLs come from
	if (no_store)
	{
		NodeSvcAccountCase(ctx);
	}
	NodeSvcMitigationCase(ctx, process, role_name);
	NodeSvcModulesCase(ctx, process, exe, role_name);

	NodeSvcRun(exe, "/stop");
	bool stopped = NodeSvcWaitState(SERVICE_STOPPED, &ss);
	if (process != NULL)
	{
		if (WaitForSingleObject(process, NODESVC_START_WAIT) == WAIT_OBJECT_0)
		{
			GetExitCodeProcess(process, &exit_code);
		}
		CloseHandle(process);
	}
	Format(what, sizeof(what), "Role %s: /stop stops the service cleanly, with no service error and process exit code 0", role_name);
	NodeTestCheck(ctx, stopped && ss.dwWin32ExitCode == NO_ERROR && ss.dwServiceSpecificExitCode == 0 && exit_code == 0, what,
		"stopped %u, service exit code %u, process exit code %u", (UINT)stopped, (UINT)ss.dwWin32ExitCode, (UINT)exit_code);

	NodeSvcRun(exe, "/uninstall");
	Format(what, sizeof(what), "Role %s: /uninstall removes the service", role_name);
	NodeTestCheck(ctx, NodeSvcWaitGone(), what, "still installed after %u ms", NODESVC_START_WAIT);

	// The service wrote the node log in its data directory
	char *log = NodeTestReadLog(data_dir);
	bool ok = (log != NULL);
	char missing[MAX_SIZE];
	StrCpy(missing, sizeof(missing), "");

	for (UINT i = 0;i < 4;i++)
	{
		bool expected = (role == (UINT)(1 << i));

		Format(line, sizeof(line), "Role %s started", nodetest_role_names[i]);
		if (NodeTestLogHas(log, line) != expected)
		{
			ok = false;
			StrCat(missing, sizeof(missing), expected ? " no " : " unexpected ");
			StrCat(missing, sizeof(missing), line);
		}
	}

	Format(line, sizeof(line), "Role %s stopped", role_name);
	if (NodeTestLogHas(log, line) == false || NodeTestLogHas(log, "Node stopped: ") == false)
	{
		ok = false;
		StrCat(missing, sizeof(missing), " no stop lines");
	}

	Format(what, sizeof(what), "Role %s: the node log of the service holds the start and the stop of that role alone", role_name);
	if (NodeTestCheck(ctx, ok, what, "%s", log == NULL ? "no node log" : missing) == false && log != NULL)
	{
		// Why the role did not start, for the job log
		Print("  The node log of the service:\n%s\n", log);
	}

	// The node log records each mitigation, on or off with its reason, and the System32-only DLL search
	UINT num_mitigations = 0;
	const NODE_MITIGATION *m = NodeGetMitigations(&num_mitigations);
	ok = NodeTestLogHas(log, "DLLs load from System32 only");
	StrCpy(missing, sizeof(missing), ok ? "" : " no DLL search line");

	for (UINT i = 0;i < num_mitigations;i++)
	{
		if (m[i].Off != NULL)
		{
			Format(line, sizeof(line), "Mitigation %s off: %s", m[i].Name, m[i].Off);
		}
		else
		{
			Format(line, sizeof(line), "Mitigation %s on", m[i].Name);
		}

		if (NodeTestLogHas(log, line) == false)
		{
			ok = false;
			StrCat(missing, sizeof(missing), " no ");
			StrCat(missing, sizeof(missing), line);
		}
	}

	Format(what, sizeof(what), "Role %s: the node log records each mitigation, on or off with its reason, and the DLL search", role_name);
	NodeTestCheck(ctx, ok, what, "%s", log == NULL ? "no node log" : missing);

	if (no_store)
	{
		NodeTestCheck(ctx, NodeTestLogHas(log, "Configuration store ") && NodeTestLogHas(log, "ranz_node.db opened (winsqlite3 ") &&
			NodeTestLogHas(log, ": SYSTEM, the Administrators and the service account only"),
			"Without a store the service creates it (winsqlite3) in its data directory, which it protects first",
			"%s", log == NULL ? "no node log" : "a line is missing");
	}

	Free(log);
}

// Whether the DACL of path gives SYSTEM, the Administrators and the virtual account of the service (NODE_SERVICE_SID)
// full control and nobody else anything; for the data directory (dir) also that the DACL is protected, so nothing of
// ProgramData is inherited, and that no user owns it: SYSTEM, the Administrators or the service account, which owns
// the directory it created
static bool NodeSvcNodeOnly(wchar_t *path, bool dir, char *detail, UINT detail_size)
{
	PSECURITY_DESCRIPTOR sd = NULL;
	PACL dacl = NULL;
	PSID owner = NULL;
	PSID service_sid = NULL;
	SECURITY_DESCRIPTOR_CONTROL control = 0;
	DWORD revision = 0;
	bool system = false;
	bool admins = false;
	bool service = false;
	UINT others = 0;

	if (ConvertStringSidToSidW(NODE_SERVICE_SID, &service_sid) == FALSE)
	{
		Format(detail, detail_size, "ConvertStringSidToSidW: error %u", (UINT)GetLastError());
		return false;
	}

	DWORD err = GetNamedSecurityInfoW(path, SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION, &owner, NULL, &dacl, NULL, &sd);
	if (err != ERROR_SUCCESS)
	{
		Format(detail, detail_size, "GetNamedSecurityInfoW: error %u", (UINT)err);
		LocalFree(service_sid);
		return false;
	}

	GetSecurityDescriptorControl(sd, &control, &revision);

	for (DWORD i = 0;dacl != NULL && i < dacl->AceCount;i++)
	{
		ACCESS_ALLOWED_ACE *ace = NULL;

		if (GetAce(dacl, i, (LPVOID *)&ace) == FALSE || ace->Header.AceType != ACCESS_ALLOWED_ACE_TYPE)
		{
			others++;
			continue;
		}

		PSID sid = (PSID)&ace->SidStart;
		bool full = ((ace->Mask & FILE_ALL_ACCESS) == FILE_ALL_ACCESS);

		if (full && IsWellKnownSid(sid, WinLocalSystemSid))
		{
			system = true;
		}
		else if (full && IsWellKnownSid(sid, WinBuiltinAdministratorsSid))
		{
			admins = true;
		}
		else if (full && EqualSid(sid, service_sid))
		{
			service = true;
		}
		else
		{
			others++;
		}
	}

	bool is_protected = ((control & SE_DACL_PROTECTED) != 0);
	bool owned = (owner != NULL && (IsWellKnownSid(owner, WinBuiltinAdministratorsSid) || IsWellKnownSid(owner, WinLocalSystemSid) ||
		EqualSid(owner, service_sid)));

	LocalFree(sd);
	LocalFree(service_sid);

	Format(detail, detail_size, "SYSTEM %u, Administrators %u, service account %u, %u other ACEs, protected %u, owned by SYSTEM, the Administrators or the service account %u",
		(UINT)system, (UINT)admins, (UINT)service, others, (UINT)is_protected, (UINT)owned);

	return (system && admins && service && others == 0 && (dir == false || (is_protected && owned)));
}

// The data directory of the service and its configuration store: under ProgramData, and for SYSTEM, the
// Administrators and the service account only
static void NodeSvcDataDirCase(NODETEST_CTX *ctx, wchar_t *data_dir, wchar_t *store)
{
	char detail[MAX_SIZE];

	NodeTestCheck(ctx, IsFileExistsW(store), "The service created its configuration store in %ProgramData%\\Hanzcodes\\Ranz VPN",
		"%S is missing", store);

	bool ok = NodeSvcNodeOnly(data_dir, true, detail, sizeof(detail));
	NodeTestCheck(ctx, ok, "The data directory has a protected DACL: SYSTEM, the Administrators and the service account alone have access, and no user owns it",
		"%s", detail);

	ok = NodeSvcNodeOnly(store, false, detail, sizeof(detail));
	NodeTestCheck(ctx, ok, "The configuration store inherits it: SYSTEM, the Administrators and the service account alone have access", "%s", detail);
}

// Delete a configuration store with the write-ahead log files that a store left open would have
static void NodeSvcDeleteStore(wchar_t *store)
{
	wchar_t tmp[MAX_PATH];

	FileDeleteW(store);

	UniFormat(tmp, sizeof(tmp), L"%s-wal", store);
	FileDeleteW(tmp);

	UniFormat(tmp, sizeof(tmp), L"%s-shm", store);
	FileDeleteW(tmp);
}

// nodesvc: ranz-node as the ranzvpnserver service, once per role
RANZ_TEST("nodesvc", nodesvc_test, "Node service: ranz-node installs as ranzvpnserver, runs each role of its configuration and stops cleanly (administrator rights).");
void nodesvc_test(UINT num, char **arg)
{
	NODETEST_CTX ctx;
	NODETEST_WATCHDOG wd;
	wchar_t exe_dir[MAX_PATH];
	wchar_t exe[MAX_PATH];
	wchar_t data_dir[MAX_PATH];
	wchar_t store[MAX_PATH];
	wchar_t backup[MAX_PATH];

	Zero(&ctx, sizeof(ctx));
	NodeTestWatchdogStart(&wd, "NODESVC");

	Print("Node service test: ranz-node as the %s service, once per role\n", NODESVC_NAME);

	GetExeDirW(exe_dir, sizeof(exe_dir));
	ConbinePathW(exe, sizeof(exe), exe_dir, L"ranz-node.exe");
	NodeDefaultDataDir(data_dir, sizeof(data_dir));
	ConbinePathW(store, sizeof(store), data_dir, CS_FILE_NAME);
	UniFormat(backup, sizeof(backup), L"%s.nodesvc-backup", store);

	bool ready = NodeTestCheck(&ctx, IsFileExistsW(exe), "ranz-node.exe is next to vpntest.exe", "%S is missing", exe);
	ready = NodeTestCheck(&ctx, StrCmp(_SS("SVC_" GC_SVC_NAME_NODE "_NAME"), NODESVC_NAME) == 0,
		"The string table names the service of ranz-node " NODESVC_NAME, "it names \"%s\"", _SS("SVC_" GC_SVC_NAME_NODE "_NAME")) && ready;
	ready = NodeTestCheck(&ctx, MsIsAdmin(), "vpntest runs with administrator rights, which a service install needs", "not elevated") && ready;
	// The process of a service that runs as a virtual account gives the Administrators no right to read its
	// mitigations and modules: the debug privilege of the elevated token does
	ready = NodeTestCheck(&ctx, MsEnablePrivilege("SeDebugPrivilege", true), "vpntest enables SeDebugPrivilege to read the service process",
		"error %u", (UINT)GetLastError()) && ready;
	ready = NodeTestCheck(&ctx, MsIsServiceInstalled(NODESVC_NAME) == false, "No " NODESVC_NAME " service is installed yet",
		"one is installed: nodesvc leaves an installed node alone") && ready;

	if (ready)
	{
		// The configuration store of the data directory is set aside and put back afterwards
		bool had_store = IsFileExistsW(store);
		if (had_store)
		{
			FileDeleteW(backup);
			FileRenameW(store, backup);
		}

		// The first run has no store: the default roles (server), and the service creates the store
		NodeSvcDeleteStore(store);
		NodeSvcRoleCase(&ctx, exe, data_dir, NODE_ROLE_SERVER, true);
		NodeSvcDataDirCase(&ctx, data_dir, store);

		NodeSvcRoleCase(&ctx, exe, data_dir, NODE_ROLE_CLIENT, false);
		NodeSvcRoleCase(&ctx, exe, data_dir, NODE_ROLE_BRIDGE, false);
		NodeSvcRoleCase(&ctx, exe, data_dir, NODE_ROLE_RELAY, false);

		// Leave no service behind
		if (MsIsServiceInstalled(NODESVC_NAME))
		{
			NodeSvcRun(exe, "/uninstall");
		}

		NodeSvcDeleteStore(store);
		if (had_store)
		{
			FileRenameW(backup, store);
		}

		// The identity key of the test nodes in the machine key set. The relay role of the service keeps its own in
		// the key set of its virtual account, out of the reach of vpntest.
		PeerKeyDelete(L"" NODETEST_IDENTITY_KEY);
	}

	NodeTestWatchdogStop(&wd);

	if (ctx.NumFailed == 0)
	{
		Print("NODESVC TEST OK\n");
	}
	else
	{
		Print("NODESVC TEST FAILED (%u of %u checks failed)\n", ctx.NumFailed, ctx.NumChecks);
	}
}
