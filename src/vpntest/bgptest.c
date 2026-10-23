// bgptest.c
// Named BGP sidecar test of vpntest ("bgp" command, CORE-S7-1 #82)
//
// bgp: the node with its BGP sidecar, the subcommand bgp of ranz.exe (Cedar/NodeBgp.c, ranz-bgp/), the Windows spike
// of ADR-0010 (ONE-1, #310). A node whose configuration names no BGP peers starts no sidecar, and a node without
// ranz.exe next to it runs without one. The spike: the node starts ranz.exe bgp from the directory of vpntest, and the
// test reads from the sidecar's own log that its command line was ranz.exe bgp. The sidecar listens on TCP 179 of
// 127.0.0.1 and peers with a router of the operator: GoBGP's own daemon gobgpd, AS 65002, which dials 127.0.0.1:179
// (.github/scripts/bgp-spike.ps1 starts it). The prefix that the configuration announces reaches the router;
// the node withdraws it and the router loses it, announces it again and the router has it again. The router
// announces a prefix inside the accept list of the node via the default gateway of the machine, and the node
// installs the route into the Windows routing table through IP Helper, on the interface of that gateway; a prefix
// outside the list is never installed; the router withdraws the prefix and the route leaves the table. The sidecar
// has no FIB: the route is in the table only while the node holds it, and a stop of the node takes it out and ends
// the sidecar with exit code 0.
// RANZ_GOBGP names the gobgp command of the router (GoBGP's CLI on the gRPC API of gobgpd, 127.0.0.1:50051).
// Print "BGP TEST OK" only when every check passes. Needs administrator rights (CreateIpForwardEntry2).

#include "Cedar/Cedar.h"
#include "Cedar/ConfigStore.h"
#include "Cedar/Node.h"

#include "Mayaqua/FileIO.h"
#include "Mayaqua/Internat.h"
#include "Mayaqua/Kernel.h"
#include "Mayaqua/Memory.h"
#include "Mayaqua/Microsoft.h"
#include "Mayaqua/Str.h"
#include "Mayaqua/Tick64.h"

#include <WinDNS.h>
#include <iphlpapi.h>
#include <TlHelp32.h>
#include <WS2tcpip.h>

#define	BGPTEST_BOUND			60000		// A bounded wait on observable state (ms)
#define	BGPTEST_SETTLE			3000		// How long the test waits before it checks that something did not happen (ms)
#define	BGPTEST_RUN_WAIT		30000		// A run of the gobgp command ends within this time (ms)
#define	BGPTEST_PORT			179			// The BGP port of the sidecar
#define	BGPTEST_ROUTER_ASN		65002		// The AS of the router (.github/scripts/bgp-spike.ps1)
#define	BGPTEST_ANNOUNCE		"203.0.113.0/24"	// The prefix the node announces (TEST-NET-3)
#define	BGPTEST_LEARN			"198.51.100.0/24"	// The prefix the router announces inside accept (TEST-NET-2)
#define	BGPTEST_LEARN_ADDR		"198.51.100.0"
#define	BGPTEST_LEARN_LEN		24
#define	BGPTEST_REJECT			"192.0.2.128/25"	// ... and outside accept (TEST-NET-1)
#define	BGPTEST_REJECT_ADDR		"192.0.2.128"
#define	BGPTEST_REJECT_LEN		25

// The BGP settings of the spike: the router dials the sidecar, which listens on loopback only
#define	BGPTEST_SETTINGS		"{\"asn\":65001,\"router_id\":\"192.0.2.1\",\"listen_addresses\":[\"127.0.0.1\"]," \
								"\"peers\":[{\"address\":\"127.0.0.1\",\"asn\":65002,\"passive\":true}]," \
								"\"accept\":[\"198.51.100.0/24\"],\"announce\":[\"203.0.113.0/24\"]}"

// The checks of the test
typedef struct BGPTEST_CTX
{
	UINT NumChecks;					// Checks run so far
	UINT NumFailed;					// Checks failed so far
} BGPTEST_CTX;

// Record one check: print [PASS] with what, or [FAIL] with what and the formatted detail
static bool BgpTestCheck(BGPTEST_CTX *ctx, bool ok, char *what, char *fmt, ...) RANZ_PRINTF_FORMAT(4, 5);
static bool BgpTestCheck(BGPTEST_CTX *ctx, bool ok, char *what, char *fmt, ...)
{
	char detail[MAX_SIZE * 4];
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

// A new empty data directory under the temp directory of the process
static void BgpTestNewDir(wchar_t *dir, UINT size, char *name)
{
	wchar_t tmp[MAX_PATH];

	UniFormat(tmp, sizeof(tmp), L"bgp_%S_%u", name, (UINT)Tick64());
	ConbinePathW(dir, size, MsGetMyTempDirW(), tmp);
	MakeDirExW(dir);
}

// Delete the files of a directory, then the directory (it holds no subdirectory)
static void BgpTestDeleteFiles(wchar_t *dir)
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

// Delete a data directory of the test: the node log, the configuration, the directory
static void BgpTestDeleteDir(wchar_t *dir)
{
	wchar_t log_dir[MAX_PATH];

	ConbinePathW(log_dir, sizeof(log_dir), dir, NODE_LOG_DIR_NAME);
	BgpTestDeleteFiles(log_dir);
	BgpTestDeleteFiles(dir);
}

// Write the configuration store of a data directory: no role, and the Bgp setting (none for NULL)
static void BgpTestWriteConfig(wchar_t *dir, char *bgp)
{
	wchar_t path[MAX_PATH];

	ConbinePathW(path, sizeof(path), dir, CS_FILE_NAME);
	CONFIG_STORE *s = CsOpen(path);

	if (s == NULL)
	{
		Print("  configuration store %S cannot be opened\n", path);
		return;
	}

	CsSetSetting(s, NODE_SETTING_ROLES, "none");
	CsSetSetting(s, NODE_SETTING_BGP, bgp);

	CsClose(s);
}

// The text of a file of the node log directory, or of every file there for NULL; NULL when there is none. The
// caller frees it.
static char *BgpTestReadLog(wchar_t *dir, wchar_t *name)
{
	wchar_t log_dir[MAX_PATH];
	BUF *all = NewBuf();

	ConbinePathW(log_dir, sizeof(log_dir), dir, NODE_LOG_DIR_NAME);

	DIRLIST *d = EnumDirW(log_dir);
	for (UINT i = 0;d != NULL && i < d->NumFiles;i++)
	{
		DIRENT *e = d->File[i];
		wchar_t path[MAX_PATH];

		if (e->Folder || (name != NULL && UniStrCmpi(e->FileNameW, name) != 0))
		{
			continue;
		}

		ConbinePathW(path, sizeof(path), log_dir, e->FileNameW);

		BUF *b = ReadDumpW(path);
		if (b != NULL)
		{
			WriteBuf(all, b->Buf, b->Size);
			FreeBuf(b);
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

// Whether the text holds part
static bool BgpTestHas(char *text, char *part)
{
	return (text != NULL && SearchStrEx(text, part, 0, true) != INFINITE);
}

// The number of running ranz.exe processes, which hold the sidecar
static UINT BgpTestNumSidecars()
{
	PROCESSENTRY32W e;
	UINT num = 0;

	HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (snap == INVALID_HANDLE_VALUE)
	{
		return INFINITE;
	}

	Zero(&e, sizeof(e));
	e.dwSize = sizeof(e);

	for (BOOL ok = Process32FirstW(snap, &e);ok;ok = Process32NextW(snap, &e))
	{
		if (UniStrCmpi(e.szExeFile, NODE_BGP_EXE_NAME) == 0)
		{
			num++;
		}
	}

	CloseHandle(snap);

	return num;
}

// Whether the process pid listens on TCP port of 127.0.0.1
static bool BgpTestListens(UINT pid, UINT port)
{
	DWORD size = 0;
	bool ret = false;

	GetExtendedTcpTable(NULL, &size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_LISTENER, 0);
	if (size == 0)
	{
		return false;
	}

	MIB_TCPTABLE_OWNER_PID *t = ZeroMalloc(size);

	if (GetExtendedTcpTable(t, &size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_LISTENER, 0) == NO_ERROR)
	{
		for (DWORD i = 0;i < t->dwNumEntries;i++)
		{
			MIB_TCPROW_OWNER_PID *r = &t->table[i];

			if (r->dwOwningPid == pid && ntohs((USHORT)r->dwLocalPort) == port && r->dwLocalAddr == htonl(INADDR_LOOPBACK))
			{
				ret = true;
			}
		}
	}

	Free(t);

	return ret;
}

// Run the gobgp command of the router with args; its output goes to out. True when it ran and exited with 0.
static bool BgpTestGobgp(char *args, char *out, UINT out_size)
{
	wchar_t exe[MAX_PATH];
	wchar_t cmd[MAX_PATH * 2];
	STARTUPINFOW si;
	PROCESS_INFORMATION pi;
	SECURITY_ATTRIBUTES sa;
	HANDLE rd = NULL;
	HANDLE wr = NULL;
	DWORD code = 1;
	UINT len = 0;

	StrCpy(out, out_size, "");

	if (GetEnvironmentVariableW(L"RANZ_GOBGP", exe, MAX_PATH) == 0)
	{
		StrCpy(out, out_size, "RANZ_GOBGP is not set");
		return false;
	}

	UniFormat(cmd, sizeof(cmd), L"\"%s\" -u 127.0.0.1 -p 50051 %S", exe, args);

	Zero(&sa, sizeof(sa));
	sa.nLength = sizeof(sa);
	sa.bInheritHandle = TRUE;

	if (CreatePipe(&rd, &wr, &sa, 0) == FALSE)
	{
		return false;
	}
	SetHandleInformation(rd, HANDLE_FLAG_INHERIT, 0);

	Zero(&si, sizeof(si));
	si.cb = sizeof(si);
	si.dwFlags = STARTF_USESTDHANDLES;
	si.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
	si.hStdOutput = wr;
	si.hStdError = wr;
	Zero(&pi, sizeof(pi));

	BOOL started = CreateProcessW(exe, cmd, NULL, NULL, TRUE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi);
	CloseHandle(wr);

	if (started == FALSE)
	{
		Format(out, out_size, "%S cannot be started (error %u)", exe, (UINT)GetLastError());
		CloseHandle(rd);
		return false;
	}

	// The output until the command closes its end of the pipe
	while (true)
	{
		char buf[MAX_SIZE];
		DWORD got = 0;

		if (ReadFile(rd, buf, sizeof(buf), &got, NULL) == FALSE || got == 0)
		{
			break;
		}

		for (DWORD i = 0;i < got && len + 1 < out_size;i++)
		{
			out[len++] = buf[i];
		}
	}
	out[len] = 0;
	CloseHandle(rd);

	if (WaitForSingleObject(pi.hProcess, BGPTEST_RUN_WAIT) == WAIT_OBJECT_0)
	{
		GetExitCodeProcess(pi.hProcess, &code);
	}
	else
	{
		TerminateProcess(pi.hProcess, 1);
	}

	CloseHandle(pi.hThread);
	CloseHandle(pi.hProcess);

	return (code == 0);
}

// Whether the router has a route to prefix in its RIB (IPv4)
static bool BgpTestRouterHas(char *prefix)
{
	char out[MAX_SIZE * 16];

	return (BgpTestGobgp("global rib -a ipv4", out, sizeof(out)) && BgpTestHas(out, prefix));
}

// Wait until the router has a route to prefix, or has none; true when it came to that within BGPTEST_BOUND
static bool BgpTestWaitRouter(char *prefix, bool has)
{
	UINT64 end = Tick64() + BGPTEST_BOUND;

	while (BgpTestRouterHas(prefix) != has)
	{
		if (Tick64() >= end)
		{
			return false;
		}
		SleepThread(250);
	}

	return true;
}

// The route to addr/len in the Windows routing table that the node installed: via next_hop on the interface
// luid, protocol MIB_IPPROTO_NETMGMT and metric NODE_BGP_ROUTE_METRIC
static bool BgpTestHasRoute(char *addr, UINT len, SOCKADDR_INET *next_hop, NET_LUID *luid)
{
	MIB_IPFORWARD_TABLE2 *t = NULL;
	IN_ADDR dst;
	bool ret = false;

	if (InetPtonA(AF_INET, addr, &dst) != 1 || GetIpForwardTable2(AF_INET, &t) != NO_ERROR)
	{
		return false;
	}

	for (ULONG i = 0;i < t->NumEntries;i++)
	{
		MIB_IPFORWARD_ROW2 *r = &t->Table[i];

		if (r->DestinationPrefix.PrefixLength == len &&
			r->DestinationPrefix.Prefix.Ipv4.sin_addr.s_addr == dst.s_addr &&
			r->NextHop.Ipv4.sin_addr.s_addr == next_hop->Ipv4.sin_addr.s_addr &&
			r->InterfaceLuid.Value == luid->Value &&
			r->Protocol == MIB_IPPROTO_NETMGMT && r->Metric == NODE_BGP_ROUTE_METRIC)
		{
			ret = true;
		}
	}

	FreeMibTable(t);

	return ret;
}

// Wait until the route to addr/len is in the table, or is not; true when it came to that within BGPTEST_BOUND
static bool BgpTestWaitRoute(char *addr, UINT len, SOCKADDR_INET *next_hop, NET_LUID *luid, bool has)
{
	UINT64 end = Tick64() + BGPTEST_BOUND;

	while (BgpTestHasRoute(addr, len, next_hop, luid) != has)
	{
		if (Tick64() >= end)
		{
			return false;
		}
		SleepThread(250);
	}

	return true;
}

// Wait until the sidecar runs and its peer is established; false when it did not within BGPTEST_BOUND
static bool BgpTestWaitEstablished(NODE *n, NODE_BGP_STATUS *st)
{
	UINT64 end = Tick64() + BGPTEST_BOUND;

	while (true)
	{
		NodeBgpGetStatus(n, st);

		if (st->Running && st->NumEstablished == 1)
		{
			return true;
		}

		if (Tick64() >= end)
		{
			return false;
		}
		SleepThread(250);
	}
}

// Print the log of the sidecar, so that the job log shows the BGP session
static void BgpTestPrintSidecarLog(wchar_t *dir)
{
	char *log = BgpTestReadLog(dir, NODE_BGP_LOG_NAME);

	Print("  --- %S ---\n%s  ---\n", NODE_BGP_LOG_NAME, log == NULL ? "(none)\n" : log);

	Free(log);
}

// Without BGP peers in the configuration the node starts no sidecar; without the sidecar, or with settings that
// are not JSON, it runs without BGP
static void BgpTestNoSidecar(BGPTEST_CTX *ctx)
{
	struct
	{
		char *Name;					// What the case is
		char *Settings;				// The Bgp setting, NULL for none
		bool Missing;				// The sidecar is not installed
		char *LogLine;				// What the node log must say, NULL for nothing
	} cases[] =
	{
		{"no Bgp setting", NULL, false, NULL},
		{"a Bgp setting without peers", "{\"asn\":65001,\"router_id\":\"192.0.2.1\",\"peers\":[]}", false, "BGP not started: the Bgp setting names no peers"},
		{"a Bgp setting that is not JSON", "asn=65001", false, "BGP not started: the Bgp setting is not a JSON object"},
		{"a node without ranz.exe", BGPTEST_SETTINGS, true, "ranz.exe, which holds the sidecar, is not installed at"},
	};
	char what[MAX_SIZE];
	NODE_STATUS st;
	NODE_BGP_STATUS bst;

	for (UINT i = 0;i < sizeof(cases) / sizeof(cases[0]);i++)
	{
		wchar_t dir[MAX_PATH];
		UINT before = BgpTestNumSidecars();

		BgpTestNewDir(dir, sizeof(dir), "none");
		BgpTestWriteConfig(dir, cases[i].Settings);

		NODE *n = NewNode(dir);
		if (cases[i].Missing)
		{
			ConbinePathW(n->BgpSidecar, sizeof(n->BgpSidecar), dir, NODE_BGP_EXE_NAME);
		}

		bool started = NodeStart(n);
		NodeGetStatus(n, &st);
		NodeBgpGetStatus(n, &bst);
		UINT during = BgpTestNumSidecars();
		bool announced = NodeBgpAnnounce(n, BGPTEST_ANNOUNCE, NULL);

		Format(what, sizeof(what), "%s: the node runs, without a sidecar process, and announces nothing", cases[i].Name);
		BgpTestCheck(ctx, started && st.Running && bst.Running == false && bst.ProcessId == 0 && during == before && announced == false, what,
			"started %u, running %u, sidecar running %u, process %u, %u ranz.exe processes before and %u while it runs, announce %u",
			(UINT)started, (UINT)st.Running, (UINT)bst.Running, bst.ProcessId, before, during, (UINT)announced);

		NodeStop(n);
		FreeNode(n);

		char *log = BgpTestReadLog(dir, NULL);
		bool ok = (cases[i].LogLine != NULL ? BgpTestHas(log, cases[i].LogLine) : BgpTestHas(log, "BGP") == false);
		Format(what, sizeof(what), "%s: the node log says why no BGP runs, or says nothing of BGP without a setting", cases[i].Name);
		BgpTestCheck(ctx, ok, what, "the node log %s \"%s\"", cases[i].LogLine != NULL ? "lacks" : "has", cases[i].LogLine != NULL ? cases[i].LogLine : "BGP");

		Free(log);
		BgpTestDeleteDir(dir);
	}
}

// The spike: BGP on TCP 179 with a router of the operator, a prefix announced and withdrawn, a learned route
// installed through IP Helper
static void BgpTestSpike(BGPTEST_CTX *ctx)
{
	wchar_t dir[MAX_PATH];
	char what[MAX_SIZE];
	char out[MAX_SIZE * 16];
	char gateway[MAX_SIZE];
	char args[MAX_SIZE];
	char line[MAX_SIZE];
	SOCKADDR_INET dst;
	SOCKADDR_INET src;
	MIB_IPFORWARD_ROW2 best;
	NODE_BGP_STATUS bst;

	// The router answers on its API
	bool router = BgpTestGobgp("neighbor", out, sizeof(out));
	BgpTestCheck(ctx, router, "The router (gobgpd) answers on its API at 127.0.0.1:50051", "gobgp neighbor: %s", out);
	if (router == false)
	{
		return;
	}

	// The next hop of the learned route: the gateway of the default route, which reaches 198.51.100.0/24 today
	Zero(&dst, sizeof(dst));
	dst.si_family = AF_INET;
	InetPtonA(AF_INET, "198.51.100.1", &dst.Ipv4.sin_addr);
	Zero(&best, sizeof(best));
	DWORD err = GetBestRoute2(NULL, 0, NULL, &dst, 0, &best, &src);
	bool has_gateway = (err == NO_ERROR && best.NextHop.si_family == AF_INET && best.NextHop.Ipv4.sin_addr.s_addr != 0);
	InetNtopA(AF_INET, &best.NextHop.Ipv4.sin_addr, gateway, sizeof(gateway));
	BgpTestCheck(ctx, has_gateway, "The machine reaches 198.51.100.0/24 through a gateway, the next hop the router will give",
		"GetBestRoute2: error %u, next hop %s", (UINT)err, gateway);
	if (has_gateway == false)
	{
		return;
	}
	Print("  gateway %s on interface %u\n", gateway, (UINT)best.InterfaceIndex);

	BgpTestNewDir(dir, sizeof(dir), "spike");
	BgpTestWriteConfig(dir, BGPTEST_SETTINGS);

	NODE *n = NewNode(dir);
	BgpTestCheck(ctx, IsFileExistsW(n->BgpSidecar), "ranz.exe is next to vpntest.exe", "%S is missing", n->BgpSidecar);

	NodeStart(n);
	bool established = BgpTestWaitEstablished(n, &bst);
	BgpTestCheck(ctx, established && bst.NumPeers == 1 && bst.NumErrors == 0 && SearchStrEx(bst.Version, "GoBGP", 0, false) != INFINITE,
		"The node starts the sidecar, which reports ready and an established session with the router",
		"running %u, process %u, %u peers, %u established, %u errors, version \"%s\"",
		(UINT)bst.Running, bst.ProcessId, bst.NumPeers, bst.NumEstablished, bst.NumErrors, bst.Version);

	BgpTestCheck(ctx, BgpTestListens(bst.ProcessId, BGPTEST_PORT), "The sidecar listens on TCP 179 of 127.0.0.1",
		"no listener of process %u on 127.0.0.1:%u", bst.ProcessId, BGPTEST_PORT);

	// The strict DACL of ADR-0039 decision 3 (NODE_BGP_PIPE_SDDL), as the system holds it: GENERIC_ALL becomes the
	// file rights it maps to
	BgpTestCheck(ctx, StrCmp(bst.PipeAcl, "D:P(A;;FA;;;OW)") == 0 || StrCmp(bst.PipeAcl, "D:P(A;;GA;;;OW)") == 0,
		"The pipe to the sidecar has the strict DACL: protected, full access for the account of the node (OWNER RIGHTS) alone",
		"DACL \"%s\"", bst.PipeAcl);

	// The prefix of announce in the settings reaches the router, leaves it after a withdraw, and comes back
	BgpTestCheck(ctx, BgpTestWaitRouter(BGPTEST_ANNOUNCE, true), "The prefix the settings announce reaches the router",
		"the router has no %s", BGPTEST_ANNOUNCE);
	bool withdrawn = NodeBgpWithdraw(n, BGPTEST_ANNOUNCE);
	BgpTestCheck(ctx, withdrawn && BgpTestWaitRouter(BGPTEST_ANNOUNCE, false), "NodeBgpWithdraw: the router loses the prefix",
		"withdraw %u, the router still has %s", (UINT)withdrawn, BGPTEST_ANNOUNCE);
	bool announced = NodeBgpAnnounce(n, BGPTEST_ANNOUNCE, NULL);
	BgpTestCheck(ctx, announced && BgpTestWaitRouter(BGPTEST_ANNOUNCE, true), "NodeBgpAnnounce: the router has the prefix again",
		"announce %u, the router has no %s", (UINT)announced, BGPTEST_ANNOUNCE);
	BgpTestCheck(ctx, NodeBgpWithdraw(n, "198.18.0.0/15") == false && NodeBgpAnnounce(n, "not-a-prefix", NULL) == false,
		"A prefix the node does not announce cannot be withdrawn, and what is no prefix cannot be announced", "%s", "");

	// The router announces a prefix outside accept, then one inside it: only that one is installed
	Format(args, sizeof(args), "global rib add -a ipv4 %s nexthop %s", BGPTEST_REJECT, gateway);
	bool added = BgpTestGobgp(args, out, sizeof(out));
	Format(args, sizeof(args), "global rib add -a ipv4 %s nexthop %s", BGPTEST_LEARN, gateway);
	added = BgpTestGobgp(args, out, sizeof(out)) && added;
	BgpTestCheck(ctx, added, "The router announces 192.0.2.128/25 and 198.51.100.0/24", "gobgp: %s", out);

	bool installed = BgpTestWaitRoute(BGPTEST_LEARN_ADDR, BGPTEST_LEARN_LEN, &best.NextHop, &best.InterfaceLuid, true);
	NodeBgpGetStatus(n, &bst);
	Format(what, sizeof(what), "The learned route %s via %s is in the Windows routing table, on the interface of the gateway (IP Helper)", BGPTEST_LEARN, gateway);
	BgpTestCheck(ctx, installed && bst.NumRoutes == 1, what, "installed %u, the node holds %u routes", (UINT)installed, bst.NumRoutes);

	SleepThread(BGPTEST_SETTLE);
	BgpTestCheck(ctx, BgpTestHasRoute(BGPTEST_REJECT_ADDR, BGPTEST_REJECT_LEN, &best.NextHop, &best.InterfaceLuid) == false,
		"192.0.2.128/25 is outside accept: it is never installed", "%s", "the route is in the table");

	// The router withdraws the prefix: the route leaves the table
	Format(args, sizeof(args), "global rib del -a ipv4 %s", BGPTEST_LEARN);
	BgpTestGobgp(args, out, sizeof(out));
	bool removed = BgpTestWaitRoute(BGPTEST_LEARN_ADDR, BGPTEST_LEARN_LEN, &best.NextHop, &best.InterfaceLuid, false);
	NodeBgpGetStatus(n, &bst);
	BgpTestCheck(ctx, removed && bst.NumRoutes == 0, "The router withdraws 198.51.100.0/24: the route leaves the table",
		"removed %u, the node holds %u routes", (UINT)removed, bst.NumRoutes);

	// Announced again, then the node stops: the route goes with the node, and so does the sidecar
	Format(args, sizeof(args), "global rib add -a ipv4 %s nexthop %s", BGPTEST_LEARN, gateway);
	BgpTestGobgp(args, out, sizeof(out));
	installed = BgpTestWaitRoute(BGPTEST_LEARN_ADDR, BGPTEST_LEARN_LEN, &best.NextHop, &best.InterfaceLuid, true);
	BgpTestCheck(ctx, installed, "The route is installed again when the router announces it again", "%s", "not installed");

	UINT pid = bst.ProcessId;
	NodeStop(n);
	bool gone = (BgpTestHasRoute(BGPTEST_LEARN_ADDR, BGPTEST_LEARN_LEN, &best.NextHop, &best.InterfaceLuid) == false);
	HANDLE p = OpenProcess(SYNCHRONIZE, FALSE, pid);
	bool exited = (p == NULL || WaitForSingleObject(p, 0) == WAIT_OBJECT_0);
	if (p != NULL)
	{
		CloseHandle(p);
	}
	NodeBgpGetStatus(n, &bst);
	BgpTestCheck(ctx, gone && exited && bst.ProcessId == 0, "NodeStop takes the learned route out of the table and ends the sidecar",
		"route gone %u, sidecar %u exited %u, process %u", (UINT)gone, pid, (UINT)exited, bst.ProcessId);

	FreeNode(n);

	Format(args, sizeof(args), "global rib del -a ipv4 %s", BGPTEST_LEARN);
	BgpTestGobgp(args, out, sizeof(out));
	Format(args, sizeof(args), "global rib del -a ipv4 %s", BGPTEST_REJECT);
	BgpTestGobgp(args, out, sizeof(out));

	// The node log tells the story
	char *log = BgpTestReadLog(dir, NULL);
	char removed_line[MAX_SIZE];
	char *lines[] =
	{
		"BGP sidecar ready: ranz bgp, GoBGP",
		"BGP peer 127.0.0.1 (AS 65002): established",
		"BGP prefix 203.0.113.0/24 announced",
		"BGP prefix 203.0.113.0/24 withdrawn",
		NULL,
		NULL,
		"BGP stopped: the sidecar exited with code 0",
		"ranz.exe bgp started: process",
	};
	Format(line, sizeof(line), "BGP route %s via %s from 127.0.0.1 installed on interface %u", BGPTEST_LEARN, gateway, (UINT)best.InterfaceIndex);
	Format(removed_line, sizeof(removed_line), "BGP route %s via %s removed", BGPTEST_LEARN, gateway);
	lines[4] = line;
	lines[5] = removed_line;

	bool ok = true;
	char missing[MAX_SIZE * 2];
	StrCpy(missing, sizeof(missing), "");
	for (UINT i = 0;i < sizeof(lines) / sizeof(lines[0]);i++)
	{
		if (BgpTestHas(log, lines[i]) == false)
		{
			ok = false;
			StrCat(missing, sizeof(missing), " \"");
			StrCat(missing, sizeof(missing), lines[i]);
			StrCat(missing, sizeof(missing), "\"");
		}
	}
	BgpTestCheck(ctx, ok, "The node log names the sidecar, the session, the announcements, the installed route and the stop",
		"missing:%s", missing);
	Free(log);

	// The sidecar's own log says how its process was started: the node started ranz.exe bgp, the subcommand of the
	// one executable, with the pipe it made (ONE-1, #310)
	char *sidecar_log = BgpTestReadLog(dir, NODE_BGP_LOG_NAME);
	BgpTestCheck(ctx, BgpTestHas(sidecar_log, "ranz.exe bgp -pipe"), "The log of the sidecar itself shows its command line: ranz.exe bgp -pipe",
		"the log has no command line of ranz.exe bgp: %s", sidecar_log == NULL ? "there is no log" : "see the log below");
	Free(sidecar_log);

	BgpTestPrintSidecarLog(dir);
	BgpTestDeleteDir(dir);
}

// bgp: the node with its BGP sidecar
void bgp_test(UINT num, char **arg)
{
	BGPTEST_CTX ctx;

	Zero(&ctx, sizeof(ctx));

	Print("BGP test: the sidecar of the node (ranz bgp), BGP on TCP 179 with a router, learned routes through IP Helper\n");

	BgpTestNoSidecar(&ctx);
	BgpTestSpike(&ctx);

	if (ctx.NumFailed == 0)
	{
		Print("BGP TEST OK\n");
	}
	else
	{
		Print("BGP TEST FAILED (%u of %u checks failed)\n", ctx.NumFailed, ctx.NumChecks);
	}
}
