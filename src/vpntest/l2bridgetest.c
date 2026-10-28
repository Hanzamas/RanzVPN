// l2bridgetest.c
// Named L2 bridge test of vpntest ("l2bridge" command, CORE-S3-3 #73)
//
// The bridge of the L2 adapter of the node (Cedar/NodeL2Bridge.c, Cedar/NodeL2Npcap.c) on backends of the test and on
// what this runner holds, with no driver, so that it runs on every runner; the nicbridge test (nicbridgetest.c) runs a
// bridge on the runner's NIC and on a KM-TEST adapter standing in for a Hyper-V switch, with SeLow and XDP.
// - Where a frame of the segment goes (NodeL2BridgeWay): a frame to the MAC address of the NIC to the host only; a
//   broadcast, an IPv4 and an IPv6 multicast frame to the host and to the others; a frame to another unicast address
//   to the others only.
// - The backends of a bridge whose owner names none: SeLow first, the bundled default, then Npcap.
// - Npcap is used only where it is installed: on a runner without it NodeL2NpcapPresent says that it is not installed,
//   a bridge whose backends are Npcap and one of the test binds the latter, and the hold of promiscuous mode for the XDP
//   backend refuses.
// - A bridge is never reset: a backend of the test that reports itself broken and attaches no more is reattached by the
//   health check again and again, and the reset of the owner never runs.
// - The interface of a bridge: NodeL2BridgeIndex finds the runner's NIC (the interface of its route to 8.8.8.8), which no
//   external Hyper-V virtual switch owns, by its alias and by its GUID, and refuses a name that no interface has and the
//   loopback interface, which is no Ethernet;
//   NodeL2HyperVIndex refuses a virtual switch that the host does not have, and says how to give the host a vNIC of one.
// - arm64 is L3 only: no bridge either, whatever the backend.
// Prints "L2BRIDGE TEST OK" only when every check passes.

#include "harness_int.h"
#include "testlist.h"

#include "Cedar/ConfigStore.h"
#include "Cedar/Node.h"
#include "Cedar/NodeL2.h"

#include "Mayaqua/FileIO.h"
#include "Mayaqua/Internat.h"
#include "Mayaqua/Kernel.h"
#include "Mayaqua/Memory.h"
#include "Mayaqua/Microsoft.h"
#include "Mayaqua/Str.h"

#include <iphlpapi.h>

#include <stdio.h>

#define	L2BRIDGE_BUDGET			120000		// The whole test ends within this time, or the watchdog ends the process (ms)
#define	L2BRIDGE_BOUND			15000		// A bounded wait on observable state (ms)
#define	L2BRIDGE_POLL			10			// Poll interval of observable state (ms)
#define	L2BRIDGE_SLOTS			256			// Frames of each ring of the adapters of the test
#define	L2BRIDGE_SWITCH			"ranz-l2bridge-no-such-switch"	// A Hyper-V virtual switch that no host has

// The checks of the test
typedef struct L2BRIDGE_CTX
{
	UINT NumChecks;
	UINT NumFailed;
} L2BRIDGE_CTX;

// The backend of the test: binds unless it is told to fail, reports itself broken while it is told to, and counts
typedef struct L2BRIDGE_FAKE
{
	volatile LONG FailAttaches;		// Attaches fail while this is set
	volatile LONG Broken;			// The backend reports its binding broken while this is set
	volatile LONG Attaches;			// Attaches that succeeded
	volatile LONG Detaches;			// Detaches
	volatile LONG Resets;			// Times that the reset of the owner ran
} L2BRIDGE_FAKE;

static L2BRIDGE_FAKE l2bridge_fake;

static bool L2BridgeCheck(L2BRIDGE_CTX *ctx, bool ok, char *what, char *fmt, ...) RANZ_PRINTF_FORMAT(4, 5);
static bool L2BridgeCheck(L2BRIDGE_CTX *ctx, bool ok, char *what, char *fmt, ...)
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

// The watchdog: a native thread that ends a run that hangs, so that a stuck thread is a failed test instead of a hung CI step
static DWORD WINAPI L2BridgeWatchdog(LPVOID param)
{
	char msg[MAX_SIZE];
	DWORD written = 0;

	if (WaitForSingleObject((HANDLE)param, L2BRIDGE_BUDGET) != WAIT_TIMEOUT)
	{
		return 0;
	}

	int len = snprintf(msg, sizeof(msg), "L2BRIDGE TEST FAILED (did not finish within %u ms)\n", L2BRIDGE_BUDGET);
	if (len > 0)
	{
		WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), msg, (DWORD)MIN((UINT)len, (UINT)sizeof(msg) - 1), &written, NULL);
	}

	TerminateProcess(GetCurrentProcess(), 1);

	return 0;
}

static bool L2BridgeFakeAttach(NODE_L2 *a, char *error, UINT error_size)
{
	if (ReadAcquire(&l2bridge_fake.FailAttaches) != 0)
	{
		StrCpy(error, error_size, "the backend of the test refuses this attach on purpose");
		return false;
	}

	InterlockedIncrement(&l2bridge_fake.Attaches);
	a->BackendState = &l2bridge_fake;

	return true;
}

static UINT L2BridgeFakeInject(NODE_L2 *a, const UCHAR **frames, const UINT *sizes, UINT num)
{
	return num;
}

static bool L2BridgeFakeHealthy(NODE_L2 *a)
{
	return (ReadAcquire(&l2bridge_fake.Broken) == 0);
}

static bool L2BridgeFakeDetach(NODE_L2 *a, UINT timeout)
{
	if (a->BackendState != NULL)
	{
		a->BackendState = NULL;
		InterlockedIncrement(&l2bridge_fake.Detaches);
	}

	return true;
}

static const NODE_L2_BACKEND l2bridge_fake_backend = {"fake", L2BridgeFakeAttach, L2BridgeFakeInject, L2BridgeFakeHealthy, L2BridgeFakeDetach};

// The reset of the owner: counts; a bridge must never call it
static bool L2BridgeReset(void *param, UINT *if_index)
{
	InterlockedIncrement(&l2bridge_fake.Resets);
	return true;
}

// The owner: takes the frames and does nothing with them
static void L2BridgeOwnerProc(NODE_L2 *a, void *param, const UCHAR *frame, UINT size)
{
}

// A new empty data directory under the temp directory of the process, with a configuration store: no role, one worker
static void L2BridgeNewDir(wchar_t *dir, UINT size)
{
	wchar_t tmp[MAX_PATH];
	wchar_t path[MAX_PATH];

	UniFormat(tmp, sizeof(tmp), L"l2bridgetest_%u", Rand32());
	ConbinePathW(dir, size, MsGetMyTempDirW(), tmp);
	MakeDirExW(dir);

	ConbinePathW(path, sizeof(path), dir, CS_FILE_NAME);
	CONFIG_STORE *s = CsOpen(path);
	if (s != NULL)
	{
		CsSetSetting(s, NODE_SETTING_ROLES, "none");
		CsSetSetting(s, NODE_SETTING_WORKERS, "1");
		CsClose(s);
	}
}

// Delete the files of a directory, then the directory (it holds no subdirectory)
static void L2BridgeDeleteDir(wchar_t *dir)
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
	DeleteDirW(dir);
}

// The configuration of a bridge of the test on the backends of list
static void L2BridgeConfig(NODE_L2_CONFIG *cfg, const NODE_L2_BACKEND *const *list, UINT num)
{
	Zero(cfg, sizeof(NODE_L2_CONFIG));
	cfg->Proc = L2BridgeOwnerProc;
	cfg->Reset = L2BridgeReset;
	cfg->Backends = list;
	cfg->NumBackends = num;
	cfg->Slots = L2BRIDGE_SLOTS;
	cfg->Bridge = true;
}

// Where frames go on the segment of a bridge
static void L2BridgeWays(L2BRIDGE_CTX *ctx)
{
	static UCHAR mac[6] = {0x02, 0x00, 0x5E, 0x10, 0x73, 0x01};
	static UCHAR broadcast[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
	static UCHAR ipv4_group[6] = {0x01, 0x00, 0x5E, 0x00, 0x00, 0xFB};
	static UCHAR ipv6_group[6] = {0x33, 0x33, 0xFF, 0x10, 0x73, 0x01};
	static UCHAR other[6] = {0x02, 0x00, 0x5E, 0x10, 0x73, 0x02};
	UCHAR frame[60];

	Zero(frame, sizeof(frame));
	Copy(frame + 6, other, 6);

	Copy(frame, mac, 6);
	UINT to_mac = NodeL2BridgeWay(frame, sizeof(frame), mac);
	Copy(frame, broadcast, 6);
	UINT to_broadcast = NodeL2BridgeWay(frame, sizeof(frame), mac);
	Copy(frame, ipv4_group, 6);
	UINT to_ipv4_group = NodeL2BridgeWay(frame, sizeof(frame), mac);
	Copy(frame, ipv6_group, 6);
	UINT to_ipv6_group = NodeL2BridgeWay(frame, sizeof(frame), mac);
	Copy(frame, other, 6);
	UINT to_other = NodeL2BridgeWay(frame, sizeof(frame), mac);
	UINT short_frame = NodeL2BridgeWay(frame, 5, mac);

	L2BridgeCheck(ctx, to_mac == NODE_L2_TO_HOST, "a frame to the MAC address of the NIC goes to the host only", "way %u", to_mac);
	L2BridgeCheck(ctx, to_broadcast == (NODE_L2_TO_HOST | NODE_L2_TO_OTHERS) && to_ipv4_group == (NODE_L2_TO_HOST | NODE_L2_TO_OTHERS) && to_ipv6_group == (NODE_L2_TO_HOST | NODE_L2_TO_OTHERS),
		"a broadcast, an IPv4 multicast and an IPv6 multicast frame go to the host and to the others", "ways %u, %u, %u", to_broadcast, to_ipv4_group, to_ipv6_group);
	L2BridgeCheck(ctx, to_other == NODE_L2_TO_OTHERS && short_frame == NODE_L2_TO_OTHERS, "a frame to another unicast address goes to the others only, as does one shorter than an address",
		"ways %u, %u", to_other, short_frame);
}

// The backends of a bridge, and Npcap only where it is installed
static void L2BridgeBackends(L2BRIDGE_CTX *ctx, NODE *n)
{
	const NODE_L2_BACKEND *defaults[NODE_L2_MAX_BACKENDS];
	const NODE_L2_BACKEND *list[2];
	NODE_L2_CONFIG cfg;
	NODE_L2_STATUS st;
	char error[MAX_SIZE];

	Zero(defaults, sizeof(defaults));
	UINT num = NodeL2BridgeBackends(defaults, NODE_L2_MAX_BACKENDS);
	L2BridgeCheck(ctx, num == 2 && StrCmp(defaults[0]->Name, "selow") == 0 && StrCmp(defaults[1]->Name, "npcap") == 0,
		"a bridge whose owner names no backend takes SeLow first, the bundled default, then Npcap", "%u backends: %s, %s", num,
		num >= 1 ? defaults[0]->Name : "", num >= 2 ? defaults[1]->Name : "");

	bool present = NodeL2NpcapPresent(error, sizeof(error));
	Print("  Npcap on this runner: %s%s%s\n", present ? "installed" : "not installed", present ? "" : ", ", error);
	if (present)
	{
		Print("  Npcap is installed here: the checks of a host without it are left out\n");
		return;
	}

	L2BridgeCheck(ctx, InStr(error, "not installed") && InStr(error, "Npcap"), "without Npcap, NodeL2NpcapPresent says that it is not installed", "'%s'", error);

	// A bridge on Npcap and a backend of the test: Npcap does not bind where it is missing, so the other one does
	list[0] = NodeL2NpcapBackend();
	list[1] = &l2bridge_fake_backend;
	L2BridgeConfig(&cfg, list, 2);
	NODE_L2 *a = NodeL2New(n, &cfg);
	NodeL2GetStatus(a, &st);
	L2BridgeCheck(ctx, a != NULL && StrCmp(st.Backend, "fake") == 0 && st.Bridge, "a bridge uses Npcap only where it is installed: without it the next backend binds",
		"%s, backend '%s'", a != NULL ? "a bridge" : "no bridge", st.Backend);

	if (a != NULL)
	{
		void *hold = NULL;
		bool held = NodeL2NpcapHold(a, &hold, error, sizeof(error));
		L2BridgeCheck(ctx, held == false && hold == NULL && InStr(error, "not installed"),
			"without Npcap nothing holds a NIC in promiscuous mode for the XDP backend, which then does not bind", "%s: '%s'", held ? "held" : "not held", error);
		NodeL2NpcapLetGo(hold);
	}

	NodeL2Free(a);
}

// A bridge is never reset: a broken backend that attaches no more is reattached again and again, and the reset of the
// owner never runs
static void L2BridgeNoReset(L2BRIDGE_CTX *ctx, NODE *n)
{
	const NODE_L2_BACKEND *list[1];
	NODE_L2_CONFIG cfg;
	NODE_L2_STATUS st;

	list[0] = &l2bridge_fake_backend;
	L2BridgeConfig(&cfg, list, 1);
	NODE_L2 *a = NodeL2New(n, &cfg);
	if (L2BridgeCheck(ctx, a != NULL, "a bridge on a backend of the test comes up", "NodeL2New failed") == false)
	{
		return;
	}

	InterlockedExchange(&l2bridge_fake.FailAttaches, 1);
	InterlockedExchange(&l2bridge_fake.Broken, 1);
	UINT64 end = GetTickCount64() + L2BRIDGE_BOUND;
	NodeL2GetStatus(a, &st);
	while (st.Reattaches < NODE_L2_RESETS + 3 && GetTickCount64() < end)
	{
		Sleep(L2BRIDGE_POLL * 10);
		NodeL2GetStatus(a, &st);
	}
	L2BridgeCheck(ctx, st.Reattaches >= NODE_L2_RESETS + 3 && st.Resets == 0 && ReadAcquire(&l2bridge_fake.Resets) == 0,
		"a bridge whose backend stays broken is reattached, and its NIC, the host's, is never reset",
		"%I64u reattaches, %I64u resets counted, %d resets of the owner", st.Reattaches, st.Resets, (int)ReadAcquire(&l2bridge_fake.Resets));

	InterlockedExchange(&l2bridge_fake.FailAttaches, 0);
	InterlockedExchange(&l2bridge_fake.Broken, 0);
	NodeL2Free(a);
}

// The interface of the route of this runner to 8.8.8.8, 0 for none
static UINT L2BridgeRouteIndex()
{
	UCHAR dst[4] = {8, 8, 8, 8};
	DWORD index = 0;
	IPAddr addr = 0;

	Copy(&addr, dst, 4);
	if (GetBestInterface(addr, &index) != NO_ERROR)
	{
		return 0;
	}

	return (UINT)index;
}

// The interface of a bridge by its name
static void L2BridgeNames(L2BRIDGE_CTX *ctx)
{
	MIB_IF_TABLE2 *t = NULL;
	MIB_IF_ROW2 row;
	char alias[MAX_SIZE];
	char guid[64];
	char error[MAX_SIZE * 2];
	UINT index = L2BridgeRouteIndex();

	Zero(&row, sizeof(row));
	row.InterfaceIndex = index;
	if (L2BridgeCheck(ctx, index != 0 && GetIfEntry2(&row) == NO_ERROR, "this runner has a route to the internet through a NIC", "interface %u", index))
	{
		const GUID *g = &row.InterfaceGuid;

		Zero(alias, sizeof(alias));
		UniToUtf8((UCHAR *)alias, sizeof(alias) - 1, row.Alias);
		Format(guid, sizeof(guid), "{%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X}", (UINT)g->Data1, (UINT)g->Data2, (UINT)g->Data3, (UINT)g->Data4[0], (UINT)g->Data4[1],
			(UINT)g->Data4[2], (UINT)g->Data4[3], (UINT)g->Data4[4], (UINT)g->Data4[5], (UINT)g->Data4[6], (UINT)g->Data4[7]);
		Print("  the NIC of this runner: interface %u, '%s', %s, type %u\n", index, alias, guid, (UINT)row.Type);

		UINT by_alias = NodeL2BridgeIndex(alias, error, sizeof(error));
		L2BridgeCheck(ctx, by_alias == index, "NodeL2BridgeIndex finds the NIC by its alias", "interface %u: %s", by_alias, error);
		UINT by_guid = NodeL2BridgeIndex(guid, error, sizeof(error));
		L2BridgeCheck(ctx, by_guid == index, "NodeL2BridgeIndex finds the NIC by its GUID", "interface %u: %s", by_guid, error);
	}

	UINT none = NodeL2BridgeIndex("ranz no such interface", error, sizeof(error));
	L2BridgeCheck(ctx, none == 0 && InStr(error, "no interface is named"), "NodeL2BridgeIndex refuses a name that no interface has", "interface %u: '%s'", none, error);

	// The loopback interface: no Ethernet
	if (GetIfTable2(&t) == NO_ERROR)
	{
		bool found = false;

		for (ULONG i = 0;i < t->NumEntries && found == false;i++)
		{
			if (t->Table[i].Type != IF_TYPE_SOFTWARE_LOOPBACK)
			{
				continue;
			}

			found = true;
			Zero(alias, sizeof(alias));
			UniToUtf8((UCHAR *)alias, sizeof(alias) - 1, t->Table[i].Alias);
			UINT loopback = NodeL2BridgeIndex(alias, error, sizeof(error));
			L2BridgeCheck(ctx, loopback == 0 && InStr(error, "not an Ethernet interface"), "NodeL2BridgeIndex refuses the loopback interface, which is no Ethernet",
				"'%s': interface %u, '%s'", alias, loopback, error);
		}

		FreeMibTable(t);
	}

	UINT hyperv = NodeL2HyperVIndex(L2BRIDGE_SWITCH, error, sizeof(error));
	L2BridgeCheck(ctx, hyperv == 0 && InStr(error, "vEthernet (" L2BRIDGE_SWITCH ")") && InStr(error, "Add-VMNetworkAdapter -ManagementOS"),
		"NodeL2HyperVIndex refuses a virtual switch that the host has no vNIC of, and says how to add one", "interface %u: '%s'", hyperv, error);
}

// l2bridge: the bridge of the L2 adapter of the node on backends of the test (CORE-S3-3)
RANZ_TEST("l2bridge", l2bridge_test, "L2 bridge: the bridge of an L2 Network on a NIC or a Hyper-V switch on backends of the test: where a frame goes, SeLow the default and Npcap only where it is installed, no reset of the host's NIC, the interface by its alias, GUID or switch, arm64 L3 only.");
void l2bridge_test(UINT num, char **arg)
{
	L2BRIDGE_CTX ctx;
	SYSTEM_INFO info;
	HANDLE done = CreateEventW(NULL, TRUE, FALSE, NULL);
	HANDLE watchdog = (done != NULL ? CreateThread(NULL, 0, L2BridgeWatchdog, done, 0, NULL) : NULL);
	wchar_t dir[MAX_PATH];
	wchar_t log_dir[MAX_PATH];

	Zero(&ctx, sizeof(ctx));
	Zero(&l2bridge_fake, sizeof(l2bridge_fake));
	Zero(&info, sizeof(info));
	GetNativeSystemInfo(&info);

	Print("L2 bridge test: the bridge of an L2 Network on backends of the test\n");

	L2BridgeWays(&ctx);
	L2BridgeNames(&ctx);

	L2BridgeNewDir(dir, sizeof(dir));
	NODE *n = NewNode(dir);
	bool started = (n != NULL && NodeStart(n));

	if (L2BridgeCheck(&ctx, started, "a node without a role runs for the bridges", "NewNode or NodeStart failed"))
	{
		if (info.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64)
		{
			L2BridgeBackends(&ctx, n);
			L2BridgeNoReset(&ctx, n);
		}
		else
		{
			// This host is L3 only: not even a backend that would bind gives a bridge
			const NODE_L2_BACKEND *list[1];
			NODE_L2_CONFIG cfg;

			list[0] = &l2bridge_fake_backend;
			L2BridgeConfig(&cfg, list, 1);
			NODE_L2 *a = NodeL2New(n, &cfg);
			L2BridgeCheck(&ctx, a == NULL && l2bridge_fake.Attaches == 0, "on this host (architecture %u) no bridge is offered, whatever the backend",
				"a bridge with %d attaches", (int)l2bridge_fake.Attaches);
			NodeL2Free(a);
			Print("  architecture %u: L3 only, the bridge itself is not tested here\n", (UINT)info.wProcessorArchitecture);
		}
	}

	if (n != NULL)
	{
		NodeStop(n);
		FreeNode(n);
	}
	ConbinePathW(log_dir, sizeof(log_dir), dir, NODE_LOG_DIR_NAME);
	L2BridgeDeleteDir(log_dir);
	L2BridgeDeleteDir(dir);

	if (watchdog != NULL)
	{
		SetEvent(done);
		WaitForSingleObject(watchdog, INFINITE);
		CloseHandle(watchdog);
	}
	if (done != NULL)
	{
		CloseHandle(done);
	}

	if (ctx.NumFailed == 0)
	{
		Print("L2BRIDGE TEST OK\n");
	}
	else
	{
		Print("L2BRIDGE TEST FAILED (%u of %u checks failed)\n", ctx.NumFailed, ctx.NumChecks);
	}
}
