// harness.c
// In-process server harness for vpntest: hubs, cascade, frames, vpncmd golden outputs, benchmark
//
// Design notes:
// - The server listens only on TCP 39555 (HARNESS_PORT). The port is below the Windows dynamic port
//   range (49152-65535), which also holds Hyper-V/WinNAT excluded port blocks and ephemeral sockets.
// - The test sessions are TCP client sessions (NewClientSession + a test PACKET_ADAPTER, the client
//   half of Link.c), not in-process server sessions: the server half of Link.c needs a LINK object
//   (CONNECTION_HUB_LINK_SERVER, s->Link). A frame from test session A to test session B crosses
//   3 TLS connections (test session A, the cascade, test session B), so the "bench" frame rates
//   (BENCH cascade_path_*) measure that whole path, not the cascade alone. The test users tester_a
//   and tester_b and their sessions are part of the golden outputs.
// - A watchdog thread ends the process (exit code 1, "HARNESS TEST FAILED (watchdog: ...)" or
//   "BENCH TEST FAILED (watchdog: ...)") when a test does not complete in time: the admin RPC
//   sockets, StopSession and SiReleaseServer wait without a time limit.
// - The [PASS]/[FAIL] lines carry no timing values: timings are on "TIME <name> <n> ms" and
//   "BENCH <name> <value> <unit>" lines that a log diff can filter out.
//   "HARNESS GOLDEN MODE update|compare" tells whether the golden files were compared.
// - "bench" runs every case HARNESS_BENCH_RUNS times and prints "BENCH <name> <median> <unit>", then
//   "BENCH <name>_runs <run 1>,...,<run n> <unit>" in run order. Besides the cascade path it has in-process
//   cases without TLS, one per hot spot of spec #31: flood_fps_<n> (one session floods broadcast frames to
//   n sessions of hub HARNESS_FLOOD through the hub packet adapter, no SessionMain thread), parse_packet_<kind>
//   (ParsePacketEx4 as HubPaPutPacket calls it), pack_<encode|decode>_names_<n> (a Pack with n distinct element
//   names) and ip_table_expire_<n> (one DeleteExpiredIpTableEntry pass). A wrong result of these cases prints a
//   "BENCH WARNING" line and skips the case; it does not fail the test.
// - Files left after a run: the server_log, security_log and packet_log folders (as in the "s"
//   mode). The configuration file and its backup folder are deleted at the start and at the end.

#include "harness.h"

#include "Cedar/Account.h"
#include "Cedar/Admin.h"
#include "Cedar/Cedar.h"
#include "Cedar/Command.h"
#include "Cedar/Connection.h"
#include "Cedar/Hub.h"
#include "Cedar/Listener.h"
#include "Cedar/Server.h"
#include "Cedar/Session.h"

#include "Mayaqua/Cfg.h"
#include "Mayaqua/Encrypt.h"
#include "Mayaqua/FileIO.h"
#include "Mayaqua/Internat.h"
#include "Mayaqua/Kernel.h"
#include "Mayaqua/Memory.h"
#include "Mayaqua/Network.h"
#include "Mayaqua/Object.h"
#include "Mayaqua/Pack.h"
#include "Mayaqua/Str.h"
#include "Mayaqua/Table.h"
#include "Mayaqua/TcpIp.h"
#include "Mayaqua/Tick64.h"

#include <stdio.h>

// Fixed scenario
#define	HARNESS_PORT				39555				// Test listener (never 443; below the dynamic port range)
#define	HARNESS_HUB_A				"HARNESS_A"
#define	HARNESS_HUB_B				"HARNESS_B"
#define	HARNESS_HUB_FLOOD			"HARNESS_FLOOD"		// Hub of the in-process flood bench ("bench" only)
#define	HARNESS_LINK_NAME			L"HARNESS_CASCADE"
#define	HARNESS_LINK_USER			"harness_cascade"
#define	HARNESS_USER_A				"tester_a"
#define	HARNESS_USER_B				"tester_b"
#define	HARNESS_PASSWORD			"Harness-Pass-1"
#define	HARNESS_CONFIG_FILE			"$vpn_harness.config"
#define	HARNESS_CONFIG_BACKUP_DIR	L"$backup.vpn_harness.config"	// Named by BackupCfgWEx after HARNESS_CONFIG_FILE
#define	HARNESS_VPNCMD_OUT			"@harness_vpncmd.tmp"
#define	HARNESS_FRAME_SIZE			96
#define	HARNESS_ETHERTYPE_HI		0x88				// EtherType 0x88B5 (IEEE local experimental)
#define	HARNESS_ETHERTYPE_LO		0xB5
#define	HARNESS_BENCH_HOST			"www.example.invalid"	// Host name in the HTTP, TLS and DNS bench frames

// Time bounds (milliseconds)
#define	HARNESS_LISTEN_TIMEOUT		5000				// Test listener bound (the listener retries every 2 s)
#define	HARNESS_START_TIMEOUT		15000				// Admin RPC reachable after a server start
#define	HARNESS_LINK_TIMEOUT		20000				// Cascade reports connected
#define	HARNESS_SESSION_TIMEOUT		15000				// Test session established
#define	HARNESS_LISTED_TIMEOUT		5000				// Session visible through EnumSession
#define	HARNESS_FRAME_TIMEOUT		5000				// Frame delivery through the cascade
#define	HARNESS_SETTLE_TIME			300					// Quiet time to catch unexpected frames
#define	HARNESS_RUNTIME_BUDGET		60000				// Whole "harness" test
#define	HARNESS_BENCH_BUDGET		30000				// Whole "bench" test (warning only)
#define	HARNESS_BENCH_WARMUP		300					// Not measured
#define	HARNESS_BENCH_SPAN			400					// Measured window per run and frame size (cascade path)
#define	HARNESS_BENCH_DRAIN			1000				// Max wait for the send queue to drain
#define	HARNESS_BENCH_PACK_SPAN		200					// Per run of a Pack case
#define	HARNESS_BENCH_FLOOD_SPAN	200					// Per run of a flood case
#define	HARNESS_BENCH_MICRO_SPAN	100					// Per run of a ParsePacket case
#define	HARNESS_WATCHDOG_LIMIT		120000				// "harness" process aborted after this (product calls can block forever)
#define	HARNESS_BENCH_WATCHDOG		90000				// "bench" process aborted after this

// Limits
#define	HARNESS_QUEUE_HIGH			256					// Frames kept queued by the bench sender
#define	HARNESS_QUEUE_LOW			64					// Sender wakes up below this
#define	HARNESS_MAX_RECORD			64					// Recorded frames per test session
#define	HARNESS_MAX_COLUMNS			32					// Columns tracked by the CSV normaliser
#define	HARNESS_DIFF_MAX_LINES		1000				// Larger texts only report the first difference
#define	HARNESS_DIFF_CONTEXT		2					// Context lines around a difference
#define	HARNESS_PACK_ITEMS			32					// Sessions in the Pack benchmark struct
#define	HARNESS_BENCH_RUNS			5					// Runs per bench case: the median and every run are printed
#define	HARNESS_FLOOD_BATCH			32					// Frames the flood sender stores per receive loop
#define	HARNESS_PACK_NAMES			500					// Distinct element names of the many-names Pack case
#define	HARNESS_PARSE_FRAME_MAX		512					// Buffer of one ParsePacket bench frame
#define	HARNESS_NUM_PARSE_FRAMES	5					// ParsePacket bench frames: l2, tcp, http, tls, dns

// Time units of the high-resolution bench clock
#define	HARNESS_NS_PER_MS			1000000ULL
#define	HARNESS_NS_PER_S			1000000000ULL

// Normalised placeholders
#define	HARNESS_TAG_VOLATILE		"<VOLATILE>"
#define	HARNESS_TAG_DATETIME		"<DATETIME>"
#define	HARNESS_TAG_MAC				"<MAC>"
#define	HARNESS_TAG_NUMBER			"<N>"

#define	HARNESS_IS_DIGIT(c)			((c) >= '0' && (c) <= '9')

// Ethernet frame owned by the test packet adapter
typedef struct HARNESS_FRAME
{
	UCHAR *Data;
	UINT Size;
} HARNESS_FRAME;

// Test packet adapter: injects queued frames into a hub and records the frames the hub delivers
typedef struct HARNESS_PA
{
	char Name[64];
	LOCK *Lock;
	QUEUE *SendQueue;			// HARNESS_FRAME * waiting to be handed to the session
	LIST *RecvList;				// HARNESS_FRAME * received from the hub (when Record is true)
	EVENT *RecvEvent;			// Set after a batch of received frames
	EVENT *SpaceEvent;			// Set when the send queue drains
	bool Record;				// Keep received frames (false: count only)
	bool Pending;				// Frames received since the last RecvEvent
	volatile bool Ready;		// PA Init has been called: the session is established
	UINT64 NumRecv;				// Received frames
	UINT64 RecvBytes;			// Received bytes
	SESSION *Session;			// Client session using this adapter
} HARNESS_PA;

// One harness run
typedef struct HARNESS
{
	SERVER *Server;				// In-process server
	CEDAR *ClientCedar;			// Cedar of the admin RPC and of the test sessions
	RPC *Rpc;					// Admin RPC (same client API as vpncmd)
	HARNESS_PA *PaA;			// Test session on HARNESS_A
	HARNESS_PA *PaB;			// Test session on HARNESS_B
	char *OldConfigName;		// SERVER_CONFIG_FILE_NAME before the run
	UINT NumFail;				// Failed checks
} HARNESS;

// vpncmd command captured as a golden output
typedef struct HARNESS_VPNCMD
{
	char *Name;					// Output file is vpncmd_<Name>.txt
	char *Hub;					// NULL: server admin mode, otherwise /ADMINHUB
	char *Command;				// Command after /CMD
} HARNESS_VPNCMD;

// Normalisation rules resolved from the string table (UTF-8 titles)
typedef struct HARNESS_NORM
{
	LIST *VolatileColumns;		// Column titles whose cells are volatile
	LIST *VolatileRows;			// Row titles whose values are volatile
	LIST *DropRows;				// Row titles removed (environment dependent rows)
} HARNESS_NORM;

// Cells of one CSV line
typedef struct HARNESS_CELLS
{
	UINT Num;
	char **Cell;
} HARNESS_CELLS;

// Watchdog of one test: a deadlock in the code under test fails the test instead of hanging the CI job
typedef struct HARNESS_WATCHDOG
{
	char *TestName;				// Marker prefix: HARNESS or BENCH
	UINT Limit;					// Milliseconds before the process is aborted
	EVENT *Done;				// Set when the test completes
	THREAD *Thread;				// Watchdog thread
} HARNESS_WATCHDOG;

// One operation of a timed bench case: false means a wrong result and stops the case
typedef bool (HARNESS_BENCH_OP)(void *param);

// State of the Pack bench cases
typedef struct HARNESS_PACK_BENCH
{
	RPC_ENUM_SESSION *Struct;	// Encoded by pack_encode_enum_session
	BUF *Buf;					// Decoded by the decode case
	char **Names;				// HARNESS_PACK_NAMES distinct element names, not in sorted order
} HARNESS_PACK_BENCH;

// Frame of the ParsePacket bench cases
typedef struct HARNESS_PARSE_FRAME
{
	char *Kind;					// Case name: parse_packet_<Kind>
	UCHAR Data[HARNESS_PARSE_FRAME_MAX];
	UINT Size;
} HARNESS_PARSE_FRAME;

// State of the ParsePacket bench cases
typedef struct HARNESS_PARSE_BENCH
{
	HARNESS_PARSE_FRAME Frames[HARNESS_NUM_PARSE_FRAMES];
	UINT Current;				// Frame of a single-frame case
	UINT Next;					// Next frame of the mixed case
} HARNESS_PARSE_BENCH;

// Current phase of the test, read by the watchdog thread (static strings only)
static char *volatile harness_phase = "start";
static char *volatile harness_phase_detail = "";

// Fixed list of vpncmd /SERVER commands for the golden outputs
static HARNESS_VPNCMD harness_vpncmd_list[] =
{
	{"ServerInfoGet", NULL, "ServerInfoGet"},
	{"ServerStatusGet", NULL, "ServerStatusGet"},
	{"ListenerList", NULL, "ListenerList"},
	{"HubList", NULL, "HubList"},
	{"Caps", NULL, "Caps"},
	{"HARNESS_A_StatusGet", HARNESS_HUB_A, "StatusGet"},
	{"HARNESS_A_CascadeList", HARNESS_HUB_A, "CascadeList"},
	{"HARNESS_A_SessionList", HARNESS_HUB_A, "SessionList"},
	{"HARNESS_A_UserList", HARNESS_HUB_A, "UserList"},
	{"HARNESS_B_StatusGet", HARNESS_HUB_B, "StatusGet"},
	{"HARNESS_B_SessionList", HARNESS_HUB_B, "SessionList"},
	{"HARNESS_B_UserList", HARNESS_HUB_B, "UserList"},
};

// Columns whose cells depend on time or on traffic timing
static char *harness_volatile_columns[] =
{
	"SM_HUB_COLUMN_9",			// Num Logins (incremented 30 s after a login)
	"SM_HUB_COLUMN_10",			// Last Login
	"SM_HUB_COLUMN_11",			// Last Communication
	"SM_USER_COLUMN_6",			// Num Logins
	"SM_USER_COLUMN_7",			// Last Login
	"SM_SESS_COLUMN_4",			// Source Host Name (reverse lookup of 127.0.0.1)
	"SM_SESS_COLUMN_6",			// Transfer Bytes
	"SM_SESS_COLUMN_7",			// Transfer Packets
	"SM_LINK_COLUMN_3",			// Established at
};

// Item,Value rows whose values depend on the build, the machine, the time or traffic timing
static char *harness_volatile_rows[] =
{
	"SM_INFO_PRODUCT_NAME",
	"SM_INFO_VERSION",
	"SM_INFO_BUILD",
	"SM_INFO_HOSTNAME",
	"SM_OS_SYSTEM_NAME",
	"SM_OS_PRODUCT_NAME",
	"SM_OS_VENDER_NAME",
	"SM_OS_VERSION",
	"SM_OS_KERNEL_NAME",
	"SM_OS_KERNEL_VERSION",
	"SM_ST_NUM_TCP",
	"SM_ST_START_TIME",
	"SM_ST_CURRENT_TIME",
	"SM_ST_CURRENT_TICK",
	"SM_ST_TOTAL_MEMORY",
	"SM_ST_USED_MEMORY",
	"SM_ST_FREE_MEMORY",
	"SM_ST_TOTAL_PHYS",
	"SM_ST_USED_PHYS",
	"SM_ST_FREE_PHYS",
	"SM_ST_SEND_UCAST_NUM",
	"SM_ST_SEND_UCAST_SIZE",
	"SM_ST_SEND_BCAST_NUM",
	"SM_ST_SEND_BCAST_SIZE",
	"SM_ST_RECV_UCAST_NUM",
	"SM_ST_RECV_UCAST_SIZE",
	"SM_ST_RECV_BCAST_NUM",
	"SM_ST_RECV_BCAST_SIZE",
	"SM_HUB_NUM_LOGIN",
	"SM_HUB_LAST_LOGIN_TIME",
	"SM_HUB_LAST_COMM_TIME",
	"SM_HUB_CREATED_TIME",
};

// Rows that exist only on some machines
static char *harness_drop_rows[] =
{
	"SM_OS_SERVICE_PACK",
};

// Capabilities that depend on the machine, the CPU or the build flavour, or whose title names the product (rows removed)
static char *harness_drop_caps[] =
{
	"b_local_bridge",
	"b_tap_supported",
	"b_support_network_connection_name",
	"b_beta_version",
	"b_is_in_vm",
	"b_support_aes_ni",
	"b_using_selow_driver",
	"b_is_softether",			// Title names the product, changed by the Ranz rename of the string tables
};

// Configuration items that change on every save or depend on login timing
static char *harness_config_volatile_names[] =
{
	"ConfigRevision",
	"NumLogin",
	"BroadcastBytes",
	"BroadcastCount",
	"UnicastBytes",
	"UnicastCount",
};

// Locally administered MAC addresses of the two test sessions
static UCHAR harness_mac_a[6] = {0x02, 0x42, 0x55, 0x52, 0x00, 0x0A};
static UCHAR harness_mac_b[6] = {0x02, 0x42, 0x55, 0x52, 0x00, 0x0B};
static UCHAR harness_mac_broadcast[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

static bool HarnessCheck(HARNESS *h, bool ok, char *what);
static bool HarnessCheckErr(HARNESS *h, UINT err, char *what);
static void HarnessStep(HARNESS *h, UINT err, char *what, bool check);
static void HarnessSetPhase(char *phase, char *detail);
static void HarnessWatchdogThread(THREAD *thread, void *param);
static HARNESS_WATCHDOG *HarnessStartWatchdog(char *test_name, UINT limit);
static void HarnessStopWatchdog(HARNESS_WATCHDOG *w);
static char *HarnessUniToUtf8(wchar_t *s);
static char *HarnessBufToStr(BUF *b);
static char *HarnessSkipBom(char *s);
static LIST *HarnessSplitLines(char *text);
static void HarnessFreeLines(LIST *o);
static bool HarnessTextEqual(char *a, char *b);
static void HarnessPrintDiff(char *name, char *expected, char *actual);
static void HarnessBuildFrame(UCHAR *buf, UINT size, UCHAR *dst, UCHAR *src, UINT seq);
static bool HarnessPaInit(SESSION *s);
static CANCEL *HarnessPaGetCancel(SESSION *s);
static UINT HarnessPaGetNextPacket(SESSION *s, void **data);
static bool HarnessPaPutPacket(SESSION *s, void *data, UINT size);
static void HarnessPaFree(SESSION *s);
static HARNESS_PA *HarnessNewPa(char *name);
static void HarnessClearRecv(HARNESS_PA *p);
static void HarnessFreePa(HARNESS_PA *p);
static void HarnessPaSend(HARNESS_PA *p, UCHAR *frame, UINT size);
static bool HarnessPaWaitRecv(HARNESS_PA *p, UINT num, UINT timeout);
static UINT HarnessPaNumRecorded(HARNESS_PA *p);
static bool HarnessPaFrameIs(HARNESS_PA *p, UINT index, UCHAR *expected, UINT size);
static UINT64 HarnessPaGetNumRecv(HARNESS_PA *p);
static UINT HarnessPaQueued(HARNESS_PA *p);
static void HarnessPaDrain(HARNESS_PA *p, UINT timeout);
static UINT HarnessPaPurge(HARNESS_PA *p);
static bool HarnessStartSession(HARNESS *h, HARNESS_PA *p, char *hubname, char *username);
static void HarnessStopSession(HARNESS_PA *p);
static void HarnessStopSessions(HARNESS *h);
static bool HarnessWaitListener(HARNESS *h, UINT timeout);
static RPC *HarnessAdminConnect(CEDAR *cedar, UINT timeout, UINT *err);
static bool HarnessUseOnlyTestListener(HARNESS *h);
static bool HarnessCreateHub(HARNESS *h, char *name);
static bool HarnessCreateUser(HARNESS *h, char *hubname, char *username, wchar_t *realname);
static bool HarnessCreateLink(HARNESS *h);
static bool HarnessWaitLink(HARNESS *h, UINT timeout);
static bool HarnessFindSession(HARNESS *h, char *hubname, char *username, bool link_mode, char *name, UINT name_size);
static bool HarnessWaitSessionListed(HARNESS *h, char *hubname, char *username, bool link_mode, char *name, UINT name_size);
static bool HarnessWaitSession(HARNESS *h, HARNESS_PA *p, UINT timeout);
static bool HarnessSetup(HARNESS *h);
static bool HarnessCheckMac(HARNESS *h, char *hubname, UCHAR *mac, char *session_name);
static bool HarnessTeach(HARNESS *h);
static bool HarnessFrames(HARNESS *h);
static HARNESS_NORM *HarnessNewNorm();
static void HarnessFreeNorm(HARNESS_NORM *n);
static void HarnessAddLabel(LIST *o, wchar_t *label);
static void HarnessAddCapsLabel(LIST *o, char *caps_name);
static bool HarnessInList(LIST *o, char *str);
static HARNESS_CELLS *HarnessCsvSplit(char *line);
static char *HarnessCsvJoin(HARNESS_CELLS *c);
static void HarnessFreeCells(HARNESS_CELLS *c);
static void HarnessSetCell(HARNESS_CELLS *c, UINT index, char *str);
static bool HarnessIsDateTime(char *s);
static bool HarnessIsHexChar(char c);
static bool HarnessHasRandomMac(char *s);
static char *HarnessNormalizeCell(char *s);
static char *HarnessNormalizeVpncmd(HARNESS_NORM *n, BUF *raw);
static BUF *HarnessRunVpncmd(HARNESS *h, HARNESS_VPNCMD *v);
static bool HarnessDirHasFiles(char *dir);
static void HarnessGetDirs(char *out_dir, UINT out_size, char *golden_dir, UINT golden_size, bool *update);
static void HarnessCompareGolden(HARNESS *h, char *out_dir, char *golden_dir, char *file_name, char *actual, bool update);
static void HarnessCheckStaleGolden(HARNESS *h, char *golden_dir);
static void HarnessGolden(HARNESS *h);
static bool HarnessIsVolatileConfigName(char *name, bool is_uint64);
static char *HarnessNormalizeConfig(char *text);
static bool HarnessCompareConfig(HARNESS *h, char *what, char *text1, char *text2);
static void HarnessConfigApiRoundTrip(HARNESS *h);
static void HarnessReload(HARNESS *h);
static void HarnessDeleteObjects(HARNESS *h, bool check);
static void HarnessDeleteConfigFiles();
static void HarnessTeardown(HARNESS *h, bool check);
static HARNESS *HarnessNew();
static void HarnessFree(HARNESS *h);
static UINT64 HarnessNowNs();
static void HarnessBenchValue(char *str, UINT size, UINT64 value, bool centi);
static void HarnessBenchReport(char *name, UINT64 *runs, UINT num, char *unit, bool centi);
static bool HarnessBenchOps(char *name, HARNESS_BENCH_OP *op, void *param, UINT span, UINT check_every);
static void HarnessBenchFrames(HARNESS *h, UINT size);
static void HarnessFloodIdleThread(THREAD *thread, void *param);
static SESSION *HarnessNewFloodSession(HUB *hub, THREAD *thread, UINT index, bool sender);
static void HarnessFreeFloodSession(SESSION *s);
static UINT64 HarnessFloodBatch(SESSION *sender, SESSION **recv, UINT num_recv, UCHAR *frame, UINT size);
static void HarnessBenchFloodCase(HUB *hub, UINT num_recv);
static void HarnessBenchFlood(HARNESS *h);
static bool HarnessOpEncodeEnumSession(void *param);
static bool HarnessOpDecodeEnumSession(void *param);
static void HarnessBenchPack(HARNESS *h);
static PACK *HarnessNewNamesPack(HARNESS_PACK_BENCH *b);
static bool HarnessOpEncodeNames(void *param);
static bool HarnessOpDecodePack(void *param);
static void HarnessBenchPackNames();
static UINT HarnessBuildIpFrame(UCHAR *buf, UINT buf_size, UCHAR protocol, USHORT dst_port, UCHAR *payload, UINT payload_size);
static UINT HarnessBuildClientHello(UCHAR *buf, UINT buf_size, char *host);
static UINT HarnessBuildDnsQuery(UCHAR *buf, UINT buf_size, char *host);
static PKT *HarnessParseLikeHub(HARNESS_PARSE_FRAME *f);
static bool HarnessParsedAsBuilt(HARNESS_PARSE_FRAME *f, PKT *p);
static bool HarnessOpParseOne(void *param);
static bool HarnessOpParseMix(void *param);
static void HarnessBenchParse();
static void HarnessBenchIpTableExpire(UINT num);

////////////////////////////
// Reporting and text helpers

// Print a check result and count the failures
static bool HarnessCheck(HARNESS *h, bool ok, char *what)
{
	Print("  [%s] %s\n", ok ? "PASS" : "FAIL", what);

	if (ok == false)
	{
		h->NumFail++;
	}

	return ok;
}

// Check the result of an admin RPC call
static bool HarnessCheckErr(HARNESS *h, UINT err, char *what)
{
	char tmp[MAX_SIZE];

	if (err == ERR_NO_ERROR)
	{
		return HarnessCheck(h, true, what);
	}

	Format(tmp, sizeof(tmp), "%s: error %u (%S)", what, err, _E(err));

	return HarnessCheck(h, false, tmp);
}

// Teardown step: checked after a successful run, informational after a failed setup
static void HarnessStep(HARNESS *h, UINT err, char *what, bool check)
{
	if (check)
	{
		HarnessCheckErr(h, err, what);
	}
	else
	{
		Print("  [info] %s: error %u\n", what, err);
	}
}

////////////////////////////
// Watchdog

// Record the current phase for the watchdog message (phase and detail must be static strings)
static void HarnessSetPhase(char *phase, char *detail)
{
	harness_phase_detail = (detail != NULL ? detail : "");
	harness_phase = phase;
}

// Watchdog thread: abort the process when the test does not complete within the limit
static void HarnessWatchdogThread(THREAD *thread, void *param)
{
	HARNESS_WATCHDOG *w = (HARNESS_WATCHDOG *)param;
	char *phase;
	char *detail;

	if (w == NULL)
	{
		return;
	}

	if (Wait(w->Done, w->Limit))
	{
		return;
	}

	phase = harness_phase;
	detail = harness_phase_detail;

	Print("%s TEST FAILED (watchdog: no completion after %u ms in phase %s%s%s)\n",
		w->TestName, w->Limit, phase, IsEmptyStr(detail) ? "" : ": ", detail);
	fflush(stdout);

	// _exit(1) on Windows: no cleanup, the blocked threads cannot be stopped
	AbortExit();
}

// Start the watchdog of a test
static HARNESS_WATCHDOG *HarnessStartWatchdog(char *test_name, UINT limit)
{
	HARNESS_WATCHDOG *w = ZeroMalloc(sizeof(HARNESS_WATCHDOG));

	w->TestName = test_name;
	w->Limit = limit;
	w->Done = NewEvent();

	HarnessSetPhase("start", NULL);

	w->Thread = NewThread(HarnessWatchdogThread, w);

	return w;
}

// Stop the watchdog of a completed test and release it
static void HarnessStopWatchdog(HARNESS_WATCHDOG *w)
{
	if (w == NULL)
	{
		return;
	}

	Set(w->Done);
	WaitThread(w->Thread, INFINITE);
	ReleaseThread(w->Thread);
	ReleaseEvent(w->Done);

	Free(w);
}

// Convert a Unicode string into a newly allocated UTF-8 string
static char *HarnessUniToUtf8(wchar_t *s)
{
	UINT size;
	char *ret;

	if (s == NULL)
	{
		return CopyStr("");
	}

	size = CalcUniToUtf8(s);
	ret = ZeroMalloc(size + 1);
	UniToUtf8((BYTE *)ret, size + 1, s);

	return ret;
}

// Copy a buffer into a newly allocated NUL-terminated string
static char *HarnessBufToStr(BUF *b)
{
	char *ret;

	if (b == NULL)
	{
		return CopyStr("");
	}

	ret = ZeroMalloc(b->Size + 1);
	Copy(ret, b->Buf, b->Size);

	return ret;
}

// Skip a UTF-8 byte order mark
static char *HarnessSkipBom(char *s)
{
	if (s != NULL && (UCHAR)s[0] == 0xEF && (UCHAR)s[1] == 0xBB && (UCHAR)s[2] == 0xBF)
	{
		return s + 3;
	}

	return s;
}

// Split a text into lines (CR removed, no empty entry after the final LF)
static LIST *HarnessSplitLines(char *text)
{
	LIST *o = NewListFast(NULL);
	UINT len, i, start = 0;

	if (text == NULL)
	{
		return o;
	}

	len = StrLen(text);

	for (i = 0;i <= len;i++)
	{
		if (i == len || text[i] == '\n')
		{
			UINT n = i - start;
			char *line;

			if (i == len && n == 0)
			{
				break;
			}

			line = ZeroMalloc(n + 1);
			Copy(line, text + start, n);
			if (n >= 1 && line[n - 1] == '\r')
			{
				line[n - 1] = 0;
			}

			Add(o, line);
			start = i + 1;
		}
	}

	return o;
}

// Release a line list
static void HarnessFreeLines(LIST *o)
{
	UINT i;

	if (o == NULL)
	{
		return;
	}

	for (i = 0;i < LIST_NUM(o);i++)
	{
		Free(LIST_DATA(o, i));
	}

	ReleaseList(o);
}

// Compare two texts line by line (line endings and a final newline do not matter)
static bool HarnessTextEqual(char *a, char *b)
{
	LIST *la = HarnessSplitLines(HarnessSkipBom(a));
	LIST *lb = HarnessSplitLines(HarnessSkipBom(b));
	bool ret = true;
	UINT i;

	if (LIST_NUM(la) != LIST_NUM(lb))
	{
		ret = false;
	}
	else
	{
		for (i = 0;i < LIST_NUM(la);i++)
		{
			if (StrCmp(LIST_DATA(la, i), LIST_DATA(lb, i)) != 0)
			{
				ret = false;
				break;
			}
		}
	}

	HarnessFreeLines(la);
	HarnessFreeLines(lb);

	return ret;
}

// Print a unified-diff-like report (LCS based, with context lines)
static void HarnessPrintDiff(char *name, char *expected, char *actual)
{
	LIST *a = HarnessSplitLines(HarnessSkipBom(expected));
	LIST *b = HarnessSplitLines(HarnessSkipBom(actual));
	UINT n = LIST_NUM(a);
	UINT m = LIST_NUM(b);

	Print("--- golden/%s\n", name);
	Print("+++ actual/%s\n", name);

	if (n > HARNESS_DIFF_MAX_LINES || m > HARNESS_DIFF_MAX_LINES)
	{
		UINT i;

		// Too large for the LCS table: report the first difference only
		for (i = 0;i < MAX(n, m);i++)
		{
			char *x = (i < n) ? LIST_DATA(a, i) : NULL;
			char *y = (i < m) ? LIST_DATA(b, i) : NULL;

			if (x == NULL || y == NULL || StrCmp(x, y) != 0)
			{
				Print("@@ line %u @@\n", i + 1);
				if (x != NULL)
				{
					Print("-%s\n", x);
				}
				if (y != NULL)
				{
					Print("+%s\n", y);
				}
				break;
			}
		}
	}
	else
	{
		UINT w = m + 1;
		UINT *dp = ZeroMalloc(sizeof(UINT) * (n + 1) * w);
		UINT num_ops = 0;
		char *op_type = ZeroMalloc(n + m + 1);
		char **op_line = ZeroMalloc(sizeof(char *) * (n + m + 1));
		bool *visible = ZeroMalloc(sizeof(bool) * (n + m + 1));
		UINT i, j, k;
		bool gap = false;

		// dp[i][j] = length of the LCS of a[i..] and b[j..]
		for (i = n;i-- > 0;)
		{
			for (j = m;j-- > 0;)
			{
				if (StrCmp(LIST_DATA(a, i), LIST_DATA(b, j)) == 0)
				{
					dp[i * w + j] = dp[(i + 1) * w + (j + 1)] + 1;
				}
				else
				{
					dp[i * w + j] = MAX(dp[(i + 1) * w + j], dp[i * w + (j + 1)]);
				}
			}
		}

		i = 0;
		j = 0;
		while (i < n || j < m)
		{
			if (i < n && j < m && StrCmp(LIST_DATA(a, i), LIST_DATA(b, j)) == 0)
			{
				op_type[num_ops] = ' ';
				op_line[num_ops++] = LIST_DATA(a, i);
				i++;
				j++;
			}
			else if (j < m && (i >= n || dp[i * w + (j + 1)] >= dp[(i + 1) * w + j]))
			{
				op_type[num_ops] = '+';
				op_line[num_ops++] = LIST_DATA(b, j);
				j++;
			}
			else
			{
				op_type[num_ops] = '-';
				op_line[num_ops++] = LIST_DATA(a, i);
				i++;
			}
		}

		for (k = 0;k < num_ops;k++)
		{
			if (op_type[k] != ' ')
			{
				UINT from = (k >= HARNESS_DIFF_CONTEXT) ? (k - HARNESS_DIFF_CONTEXT) : 0;
				UINT to = MIN(k + HARNESS_DIFF_CONTEXT, num_ops - 1);
				UINT x;

				for (x = from;x <= to;x++)
				{
					visible[x] = true;
				}
			}
		}

		for (k = 0;k < num_ops;k++)
		{
			if (visible[k])
			{
				if (gap)
				{
					Print("@@ ... @@\n");
				}
				gap = false;
				Print("%c%s\n", op_type[k], op_line[k]);
			}
			else
			{
				gap = true;
			}
		}

		Free(visible);
		Free(op_line);
		Free(op_type);
		Free(dp);
	}

	HarnessFreeLines(a);
	HarnessFreeLines(b);
}

////////////////////////////
// Test packet adapter (the same PACKET_ADAPTER contract Link.c uses for a cascade client session)
// Test sessions are TCP client sessions, not in-process server sessions: bench = 3 TLS hops

// Build a deterministic test frame: dst, src, EtherType 0x88B5, sequence number, pattern
static void HarnessBuildFrame(UCHAR *buf, UINT size, UCHAR *dst, UCHAR *src, UINT seq)
{
	UINT i;

	Copy(buf, dst, 6);
	Copy(buf + 6, src, 6);
	buf[12] = HARNESS_ETHERTYPE_HI;
	buf[13] = HARNESS_ETHERTYPE_LO;
	buf[14] = (UCHAR)((seq >> 24) & 0xFF);
	buf[15] = (UCHAR)((seq >> 16) & 0xFF);
	buf[16] = (UCHAR)((seq >> 8) & 0xFF);
	buf[17] = (UCHAR)(seq & 0xFF);

	for (i = 18;i < size;i++)
	{
		buf[i] = (UCHAR)((i * 7 + seq * 13) & 0xFF);
	}
}

// Packet adapter: the session is established
static bool HarnessPaInit(SESSION *s)
{
	HARNESS_PA *p;

	if (s == NULL || s->PacketAdapter == NULL || (p = (HARNESS_PA *)s->PacketAdapter->Param) == NULL)
	{
		return false;
	}

	p->Ready = true;

	return true;
}

// Packet adapter: no cancel object, the harness cancels Cancel1 of the session (as Link.c does)
static CANCEL *HarnessPaGetCancel(SESSION *s)
{
	return NULL;
}

// Packet adapter: hand the next queued frame to the session
static UINT HarnessPaGetNextPacket(SESSION *s, void **data)
{
	HARNESS_PA *p;
	HARNESS_FRAME *f;
	UINT num;
	UINT ret = 0;

	if (s == NULL || data == NULL || s->PacketAdapter == NULL || (p = (HARNESS_PA *)s->PacketAdapter->Param) == NULL)
	{
		return INFINITE;
	}

	Lock(p->Lock);
	{
		f = (HARNESS_FRAME *)GetNext(p->SendQueue);
		num = p->SendQueue->num_item;
	}
	Unlock(p->Lock);

	if (f != NULL)
	{
		// The session owns the frame buffer from now on
		*data = f->Data;
		ret = f->Size;
		Free(f);
	}

	if (f == NULL || num == HARNESS_QUEUE_LOW)
	{
		Set(p->SpaceEvent);
	}

	return ret;
}

// Packet adapter: a frame arrived from the hub (data == NULL marks the end of a batch)
static bool HarnessPaPutPacket(SESSION *s, void *data, UINT size)
{
	HARNESS_PA *p;
	bool wake = false;

	if (s == NULL || s->PacketAdapter == NULL || (p = (HARNESS_PA *)s->PacketAdapter->Param) == NULL)
	{
		return false;
	}

	if (data == NULL)
	{
		Lock(p->Lock);
		{
			wake = p->Pending;
			p->Pending = false;
		}
		Unlock(p->Lock);

		if (wake)
		{
			Set(p->RecvEvent);
		}

		return true;
	}

	Lock(p->Lock);
	{
		p->NumRecv++;
		p->RecvBytes += (UINT64)size;
		p->Pending = true;

		if (p->Record && LIST_NUM(p->RecvList) < HARNESS_MAX_RECORD)
		{
			HARNESS_FRAME *f = ZeroMalloc(sizeof(HARNESS_FRAME));

			// The adapter owns the buffer after a successful PutPacket
			f->Data = data;
			f->Size = size;
			Add(p->RecvList, f);
			data = NULL;
		}
	}
	Unlock(p->Lock);

	if (data != NULL)
	{
		Free(data);
	}

	return true;
}

// Packet adapter: the session ended
static void HarnessPaFree(SESSION *s)
{
	HARNESS_PA *p;

	if (s == NULL || s->PacketAdapter == NULL || (p = (HARNESS_PA *)s->PacketAdapter->Param) == NULL)
	{
		return;
	}

	p->Ready = false;
}

// Create the state of a test packet adapter
static HARNESS_PA *HarnessNewPa(char *name)
{
	HARNESS_PA *p = ZeroMalloc(sizeof(HARNESS_PA));

	StrCpy(p->Name, sizeof(p->Name), name);
	p->Lock = NewLock();
	p->SendQueue = NewQueueFast();
	p->RecvList = NewListFast(NULL);
	p->RecvEvent = NewEvent();
	p->SpaceEvent = NewEvent();
	p->Record = true;

	return p;
}

// Discard the recorded frames and reset the counters
static void HarnessClearRecv(HARNESS_PA *p)
{
	UINT i;

	Lock(p->Lock);
	{
		for (i = 0;i < LIST_NUM(p->RecvList);i++)
		{
			HARNESS_FRAME *f = LIST_DATA(p->RecvList, i);

			Free(f->Data);
			Free(f);
		}
		DeleteAll(p->RecvList);

		p->NumRecv = 0;
		p->RecvBytes = 0;
		p->Pending = false;
	}
	Unlock(p->Lock);
}

// Release the state of a test packet adapter (its session must be released first)
static void HarnessFreePa(HARNESS_PA *p)
{
	if (p == NULL)
	{
		return;
	}

	HarnessPaPurge(p);
	ReleaseQueue(p->SendQueue);

	HarnessClearRecv(p);
	ReleaseList(p->RecvList);

	ReleaseEvent(p->RecvEvent);
	ReleaseEvent(p->SpaceEvent);
	DeleteLock(p->Lock);

	Free(p);
}

// Queue a frame for injection and wake up the session
static void HarnessPaSend(HARNESS_PA *p, UCHAR *frame, UINT size)
{
	HARNESS_FRAME *f = ZeroMalloc(sizeof(HARNESS_FRAME));

	f->Data = Malloc(size);
	Copy(f->Data, frame, size);
	f->Size = size;

	Lock(p->Lock);
	{
		InsertQueue(p->SendQueue, f);
	}
	Unlock(p->Lock);

	if (p->Session != NULL)
	{
		Cancel(p->Session->Cancel1);
	}
}

// Wait until at least num frames have been recorded
static bool HarnessPaWaitRecv(HARNESS_PA *p, UINT num, UINT timeout)
{
	UINT64 end = Tick64() + (UINT64)timeout;

	while (true)
	{
		UINT64 now;

		if (HarnessPaNumRecorded(p) >= num)
		{
			return true;
		}

		now = Tick64();
		if (now >= end)
		{
			return false;
		}

		Wait(p->RecvEvent, (UINT)MIN(end - now, 100));
	}
}

// Number of recorded frames
static UINT HarnessPaNumRecorded(HARNESS_PA *p)
{
	UINT ret;

	Lock(p->Lock);
	{
		ret = LIST_NUM(p->RecvList);
	}
	Unlock(p->Lock);

	return ret;
}

// Whether the recorded frame at index is byte-identical to the expected frame
static bool HarnessPaFrameIs(HARNESS_PA *p, UINT index, UCHAR *expected, UINT size)
{
	bool ret = false;

	Lock(p->Lock);
	{
		if (index < LIST_NUM(p->RecvList))
		{
			HARNESS_FRAME *f = LIST_DATA(p->RecvList, index);

			if (f->Size == size && Cmp(f->Data, expected, size) == 0)
			{
				ret = true;
			}
		}
	}
	Unlock(p->Lock);

	return ret;
}

// Number of received frames (recorded or counted)
static UINT64 HarnessPaGetNumRecv(HARNESS_PA *p)
{
	UINT64 ret;

	Lock(p->Lock);
	{
		ret = p->NumRecv;
	}
	Unlock(p->Lock);

	return ret;
}

// Number of frames waiting in the send queue
static UINT HarnessPaQueued(HARNESS_PA *p)
{
	UINT ret;

	Lock(p->Lock);
	{
		ret = p->SendQueue->num_item;
	}
	Unlock(p->Lock);

	return ret;
}

// Wait until the send queue is empty, then let in-flight frames arrive
static void HarnessPaDrain(HARNESS_PA *p, UINT timeout)
{
	UINT64 end = Tick64() + (UINT64)timeout;

	while (HarnessPaQueued(p) != 0 && Tick64() < end)
	{
		Wait(p->SpaceEvent, 20);
	}

	SleepThread(200);
}

// Discard the frames still waiting in the send queue and return their number
static UINT HarnessPaPurge(HARNESS_PA *p)
{
	HARNESS_FRAME *f;
	UINT ret = 0;

	Lock(p->Lock);
	{
		while ((f = (HARNESS_FRAME *)GetNext(p->SendQueue)) != NULL)
		{
			Free(f->Data);
			Free(f);
			ret++;
		}
	}
	Unlock(p->Lock);

	return ret;
}

// Connect a test session to a hub through the test listener (client session + test packet adapter)
static bool HarnessStartSession(HARNESS *h, HARNESS_PA *p, char *hubname, char *username)
{
	CLIENT_OPTION o;
	CLIENT_AUTH a;
	PACKET_ADAPTER *pa;

	Zero(&o, sizeof(o));
	UniFormat(o.AccountName, sizeof(o.AccountName), L"HARNESS_%S", username);
	StrCpy(o.Hostname, sizeof(o.Hostname), "127.0.0.1");
	o.Port = HARNESS_PORT;
	o.ProxyType = PROXY_DIRECT;
	StrCpy(o.HubName, sizeof(o.HubName), hubname);
	o.NumRetry = 1;
	o.RetryInterval = 5;
	o.MaxConnection = 1;
	o.UseEncrypt = true;
	o.NoRoutingTracking = true;
	o.AdditionalConnectionInterval = 1;
	o.RequireBridgeRoutingMode = true;
	o.DisableQoS = true;
	o.NoUdpAcceleration = true;

	Zero(&a, sizeof(a));
	a.AuthType = CLIENT_AUTHTYPE_PASSWORD;
	StrCpy(a.Username, sizeof(a.Username), username);
	HashPassword(a.HashedPassword, username, HARNESS_PASSWORD);

	pa = NewPacketAdapter(HarnessPaInit, HarnessPaGetCancel, HarnessPaGetNextPacket,
		HarnessPaPutPacket, HarnessPaFree);
	pa->Param = (void *)p;

	p->Session = NewClientSession(h->ClientCedar, &o, &a, pa);

	return (p->Session != NULL);
}

// Stop and release a test session
static void HarnessStopSession(HARNESS_PA *p)
{
	if (p == NULL || p->Session == NULL)
	{
		return;
	}

	StopSession(p->Session);
	ReleaseSession(p->Session);
	p->Session = NULL;
}

// Stop both test sessions
static void HarnessStopSessions(HARNESS *h)
{
	HarnessStopSession(h->PaA);
	HarnessStopSession(h->PaB);
}

////////////////////////////
// Server control through the admin RPC

// Wait until the test listener is bound: SiAddListenerEx returns true even when the bind fails
static bool HarnessWaitListener(HARNESS *h, UINT timeout)
{
	UINT64 end = Tick64() + (UINT64)timeout;
	bool listening = false;
	char tmp[MAX_SIZE];

	while (true)
	{
		UINT i;

		SiLockListenerList(h->Server);
		{
			for (i = 0;i < LIST_NUM(h->Server->ServerListenerList);i++)
			{
				SERVER_LISTENER *e = LIST_DATA(h->Server->ServerListenerList, i);

				// Status is written by the listener thread (ListenerTCPMainLoop) after a successful bind
				if (e->Port == HARNESS_PORT && e->Listener != NULL && e->Listener->Status == LISTENER_STATUS_LISTENING)
				{
					listening = true;
				}
			}
		}
		SiUnlockListenerList(h->Server);

		if (listening || Tick64() >= end)
		{
			break;
		}

		SleepThread(50);
	}

	if (listening)
	{
		Format(tmp, sizeof(tmp), "test listener bound on TCP %u", HARNESS_PORT);
	}
	else
	{
		Format(tmp, sizeof(tmp), "listener bind failed on TCP %u within %u ms (port in use or in an excluded port range)",
			HARNESS_PORT, timeout);
	}

	return HarnessCheck(h, listening, tmp);
}

// Connect the admin RPC as vpncmd does (empty password of a fresh configuration), retrying until timeout
static RPC *HarnessAdminConnect(CEDAR *cedar, UINT timeout, UINT *err)
{
	CLIENT_OPTION o;
	UCHAR hashed_password[SHA1_SIZE];
	UINT64 end = Tick64() + (UINT64)timeout;
	RPC *rpc;

	Zero(&o, sizeof(o));
	UniStrCpy(o.AccountName, sizeof(o.AccountName), L"HARNESS_ADMIN");
	StrCpy(o.Hostname, sizeof(o.Hostname), "127.0.0.1");
	o.Port = HARNESS_PORT;
	o.ProxyType = PROXY_DIRECT;

	Sha0(hashed_password, "", 0);

	while (true)
	{
		*err = ERR_NO_ERROR;
		rpc = AdminConnectEx(cedar, &o, NULL, hashed_password, err, NULL);
		if (rpc != NULL || Tick64() >= end)
		{
			break;
		}

		SleepThread(250);
	}

	return rpc;
}

// Delete every listener except the test listener, then verify the listener list
static bool HarnessUseOnlyTestListener(HARNESS *h)
{
	RPC_LISTENER_LIST t;
	UINT i, err;
	bool ok = true;
	char tmp[MAX_SIZE];

	Zero(&t, sizeof(t));
	err = ScEnumListener(h->Rpc, &t);
	if (HarnessCheckErr(h, err, "EnumListener") == false)
	{
		return false;
	}

	for (i = 0;i < t.NumPort;i++)
	{
		if (t.Ports[i] != HARNESS_PORT)
		{
			RPC_LISTENER d;

			Zero(&d, sizeof(d));
			d.Port = t.Ports[i];

			Format(tmp, sizeof(tmp), "DeleteListener %u (default listener, unused by the harness)", t.Ports[i]);
			if (HarnessCheckErr(h, ScDeleteListener(h->Rpc, &d), tmp) == false)
			{
				ok = false;
			}
		}
	}
	FreeRpcListenerList(&t);

	Zero(&t, sizeof(t));
	err = ScEnumListener(h->Rpc, &t);
	if (HarnessCheckErr(h, err, "EnumListener after the cleanup"))
	{
		bool only = (t.NumPort == 1 && t.Ports[0] == HARNESS_PORT && t.Enables[0] && t.Errors[0] == false);

		Format(tmp, sizeof(tmp), "only TCP %u is listening (%u listener(s))", HARNESS_PORT, t.NumPort);
		if (HarnessCheck(h, only, tmp) == false)
		{
			ok = false;
		}

		FreeRpcListenerList(&t);
	}
	else
	{
		ok = false;
	}

	return ok;
}

// Create an online Virtual Hub with the empty hub administrator password (as HubCreate does)
static bool HarnessCreateHub(HARNESS *h, char *name)
{
	RPC_CREATE_HUB t;
	char tmp[MAX_SIZE];

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), name);
	Sha0(t.HashedPassword, "", 0);
	HashPassword(t.SecurePassword, ADMINISTRATOR_USERNAME, "");
	t.Online = true;

	Format(tmp, sizeof(tmp), "CreateHub %s", name);

	return HarnessCheckErr(h, ScCreateHub(h->Rpc, &t), tmp);
}

// Create a password user
static bool HarnessCreateUser(HARNESS *h, char *hubname, char *username, wchar_t *realname)
{
	RPC_SET_USER t;
	UINT err;
	char tmp[MAX_SIZE];

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), hubname);
	StrCpy(t.Name, sizeof(t.Name), username);
	UniStrCpy(t.Realname, sizeof(t.Realname), realname);
	UniStrCpy(t.Note, sizeof(t.Note), L"ranz harness");
	t.AuthType = AUTHTYPE_PASSWORD;
	t.AuthData = NewPasswordAuthData(username, HARNESS_PASSWORD);

	err = ScCreateUser(h->Rpc, &t);
	if (err == ERR_NO_ERROR)
	{
		FreeRpcSetUser(&t);
	}

	Format(tmp, sizeof(tmp), "CreateUser %s on %s", username, hubname);

	return HarnessCheckErr(h, err, tmp);
}

// Create the cascade HARNESS_A -> 127.0.0.1:HARNESS_PORT hub HARNESS_B (offline)
static bool HarnessCreateLink(HARNESS *h)
{
	RPC_CREATE_LINK t;
	UINT err;

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), HARNESS_HUB_A);
	t.Online = false;
	Copy(&t.Policy, GetDefaultPolicy(), sizeof(POLICY));

	t.ClientOption = ZeroMalloc(sizeof(CLIENT_OPTION));
	UniStrCpy(t.ClientOption->AccountName, sizeof(t.ClientOption->AccountName), HARNESS_LINK_NAME);
	StrCpy(t.ClientOption->Hostname, sizeof(t.ClientOption->Hostname), "127.0.0.1");
	t.ClientOption->Port = HARNESS_PORT;
	t.ClientOption->ProxyType = PROXY_DIRECT;
	StrCpy(t.ClientOption->HubName, sizeof(t.ClientOption->HubName), HARNESS_HUB_B);
	t.ClientOption->NumRetry = INFINITE;
	t.ClientOption->RetryInterval = 5;
	t.ClientOption->MaxConnection = 1;
	t.ClientOption->UseEncrypt = true;
	t.ClientOption->AdditionalConnectionInterval = 1;
	t.ClientOption->RequireBridgeRoutingMode = true;
	t.ClientOption->DisableQoS = true;
	t.ClientOption->NoUdpAcceleration = true;

	t.ClientAuth = ZeroMalloc(sizeof(CLIENT_AUTH));
	t.ClientAuth->AuthType = CLIENT_AUTHTYPE_PASSWORD;
	StrCpy(t.ClientAuth->Username, sizeof(t.ClientAuth->Username), HARNESS_LINK_USER);
	HashPassword(t.ClientAuth->HashedPassword, HARNESS_LINK_USER, HARNESS_PASSWORD);

	err = ScCreateLink(h->Rpc, &t);
	if (err == ERR_NO_ERROR)
	{
		FreeRpcCreateLink(&t);
	}

	return HarnessCheckErr(h, err, "CreateLink HARNESS_CASCADE on " HARNESS_HUB_A " to " HARNESS_HUB_B);
}

// Set the cascade online and poll GetLinkStatus until it reports connected
static bool HarnessWaitLink(HARNESS *h, UINT timeout)
{
	RPC_LINK k;
	RPC_ENUM_LINK e;
	UINT64 start, end;
	UINT err;
	UINT i;
	char tmp[MAX_SIZE];

	Zero(&k, sizeof(k));
	StrCpy(k.HubName, sizeof(k.HubName), HARNESS_HUB_A);
	UniStrCpy(k.AccountName, sizeof(k.AccountName), HARNESS_LINK_NAME);

	if (HarnessCheckErr(h, ScSetLinkOnline(h->Rpc, &k), "SetLinkOnline HARNESS_CASCADE") == false)
	{
		return false;
	}

	start = Tick64();
	end = start + (UINT64)timeout;

	while (true)
	{
		RPC_LINK_STATUS st;
		bool connected = false;

		Zero(&st, sizeof(st));
		StrCpy(st.HubName, sizeof(st.HubName), HARNESS_HUB_A);
		UniStrCpy(st.AccountName, sizeof(st.AccountName), HARNESS_LINK_NAME);

		err = ScGetLinkStatus(h->Rpc, &st);
		if (err == ERR_NO_ERROR)
		{
			connected = st.Status.Connected;
			FreeRpcLinkStatus(&st);
		}

		if (connected)
		{
			// Constant check text, the timing on its own TIME line (filtered out of log diffs)
			UINT64 took = Tick64() - start;

			HarnessCheck(h, true, "cascade reports connected (GetLinkStatus)");
			Print("TIME link_connect %I64u ms\n", took);

			return true;
		}

		if (Tick64() >= end)
		{
			break;
		}

		SleepThread(200);
	}

	// Diagnostics: last error of the cascade
	Zero(&e, sizeof(e));
	StrCpy(e.HubName, sizeof(e.HubName), HARNESS_HUB_A);
	if (ScEnumLink(h->Rpc, &e) == ERR_NO_ERROR)
	{
		for (i = 0;i < e.NumLink;i++)
		{
			Print("  [info] cascade %S: online %u, connected %u, last error %u (%S)\n",
				e.Links[i].AccountName, e.Links[i].Online, e.Links[i].Connected,
				e.Links[i].LastError, _E(e.Links[i].LastError));
		}
		FreeRpcEnumLink(&e);
	}

	Format(tmp, sizeof(tmp), "cascade reports connected within %u ms", timeout);

	return HarnessCheck(h, false, tmp);
}

// Find a session through EnumSession: by user name, or the local cascade session (link_mode)
static bool HarnessFindSession(HARNESS *h, char *hubname, char *username, bool link_mode, char *name, UINT name_size)
{
	RPC_ENUM_SESSION t;
	UINT i;
	bool ret = false;

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), hubname);

	if (ScEnumSession(h->Rpc, &t) != ERR_NO_ERROR)
	{
		return false;
	}

	for (i = 0;i < t.NumSession;i++)
	{
		RPC_ENUM_SESSION_ITEM *e = &t.Sessions[i];

		if ((link_mode && e->LinkMode) ||
			(link_mode == false && e->LinkMode == false && StrCmpi(e->Username, username) == 0))
		{
			if (name != NULL)
			{
				StrCpy(name, name_size, e->Name);
			}
			ret = true;
			break;
		}
	}

	FreeRpcEnumSession(&t);

	return ret;
}

// Poll EnumSession until the session is listed
static bool HarnessWaitSessionListed(HARNESS *h, char *hubname, char *username, bool link_mode, char *name, UINT name_size)
{
	UINT64 end = Tick64() + (UINT64)HARNESS_LISTED_TIMEOUT;

	while (true)
	{
		if (HarnessFindSession(h, hubname, username, link_mode, name, name_size))
		{
			return true;
		}

		if (Tick64() >= end)
		{
			return false;
		}

		SleepThread(100);
	}
}

// Wait until a test session is established
static bool HarnessWaitSession(HARNESS *h, HARNESS_PA *p, UINT timeout)
{
	UINT64 start = Tick64();
	UINT64 end = start + (UINT64)timeout;
	char tmp[MAX_SIZE];

	while (true)
	{
		if (p->Ready && p->Session->ClientStatus == CLIENT_STATUS_ESTABLISHED)
		{
			UINT64 took = Tick64() - start;

			Format(tmp, sizeof(tmp), "test session %s established", p->Name);
			HarnessCheck(h, true, tmp);
			Print("TIME session_%s_established %I64u ms\n", p->Name, took);

			return true;
		}

		if (Tick64() >= end)
		{
			break;
		}

		SleepThread(50);
	}

	Format(tmp, sizeof(tmp), "test session %s established within %u ms (client status %u, error %u)",
		p->Name, timeout, p->Session->ClientStatus, p->Session->Err);

	return HarnessCheck(h, false, tmp);
}

// Start the server, the test listener, the admin RPC, the hubs, the users, the cascade and the test sessions
static bool HarnessSetup(HARNESS *h)
{
	UINT err = ERR_NO_ERROR;
	bool ok;
	char tmp[MAX_SIZE];
	char name[MAX_SESSION_NAME_LEN + 1];

	Print("[setup]\n");
	HarnessSetPhase("setup", "server start");

	// Isolated configuration file: always start from the default configuration
	h->OldConfigName = SERVER_CONFIG_FILE_NAME;
	SERVER_CONFIG_FILE_NAME = HARNESS_CONFIG_FILE;
	HarnessDeleteConfigFiles();

	h->ClientCedar = NewCedar(NULL, NULL);

	// Same server object as the "s" mode (StStartServer is a wrapper of SiNewServer)
	h->Server = SiNewServer(false);
	if (HarnessCheck(h, h->Server != NULL, "server started in-process from a fresh " HARNESS_CONFIG_FILE) == false)
	{
		return false;
	}

	// The admin RPC needs a listener: add the test listener through the server API.
	// DoS protection is off on it because the harness opens many local connections in a short time.
	SiLockListenerList(h->Server);
	{
		ok = SiAddListenerEx(h->Server, HARNESS_PORT, true, true);
	}
	SiUnlockListenerList(h->Server);

	Format(tmp, sizeof(tmp), "test listener TCP %u added (SiAddListenerEx)", HARNESS_PORT);
	if (HarnessCheck(h, ok, tmp) == false || HarnessWaitListener(h, HARNESS_LISTEN_TIMEOUT) == false)
	{
		return false;
	}

	HarnessSetPhase("setup", "admin RPC");
	h->Rpc = HarnessAdminConnect(h->ClientCedar, HARNESS_START_TIMEOUT, &err);
	Format(tmp, sizeof(tmp), "admin RPC connected to 127.0.0.1:%u with the empty password", HARNESS_PORT);
	if (HarnessCheckErr(h, (h->Rpc != NULL ? ERR_NO_ERROR : err), tmp) == false)
	{
		return false;
	}

	if (HarnessUseOnlyTestListener(h) == false)
	{
		return false;
	}

	HarnessSetPhase("setup", "hubs, users, cascade");
	ok = HarnessCreateHub(h, HARNESS_HUB_A) &&
		HarnessCreateHub(h, HARNESS_HUB_B) &&
		HarnessCreateUser(h, HARNESS_HUB_B, HARNESS_LINK_USER, L"Harness cascade") &&
		HarnessCreateUser(h, HARNESS_HUB_B, HARNESS_USER_B, L"Harness tester B") &&
		HarnessCreateUser(h, HARNESS_HUB_A, HARNESS_USER_A, L"Harness tester A") &&
		HarnessCreateLink(h) &&
		HarnessWaitLink(h, HARNESS_LINK_TIMEOUT);
	if (ok == false)
	{
		return false;
	}

	ok = HarnessCheck(h, HarnessWaitSessionListed(h, HARNESS_HUB_B, HARNESS_LINK_USER, false, name, sizeof(name)),
		"HARNESS_B lists the cascade session (EnumSession, user " HARNESS_LINK_USER ")");
	ok = HarnessCheck(h, HarnessWaitSessionListed(h, HARNESS_HUB_A, NULL, true, name, sizeof(name)),
		"HARNESS_A lists the local cascade session (EnumSession, LinkMode)") && ok;
	if (ok == false)
	{
		return false;
	}

	// One test session per hub, started one after the other for a deterministic session order
	HarnessSetPhase("setup", "test sessions");
	if (HarnessCheck(h, HarnessStartSession(h, h->PaA, HARNESS_HUB_A, HARNESS_USER_A), "test session A created") == false ||
		HarnessWaitSession(h, h->PaA, HARNESS_SESSION_TIMEOUT) == false)
	{
		return false;
	}
	if (HarnessCheck(h, HarnessStartSession(h, h->PaB, HARNESS_HUB_B, HARNESS_USER_B), "test session B created") == false ||
		HarnessWaitSession(h, h->PaB, HARNESS_SESSION_TIMEOUT) == false)
	{
		return false;
	}

	ok = HarnessCheck(h, HarnessWaitSessionListed(h, HARNESS_HUB_A, HARNESS_USER_A, false, name, sizeof(name)),
		"HARNESS_A lists test session A (EnumSession)");
	ok = HarnessCheck(h, HarnessWaitSessionListed(h, HARNESS_HUB_B, HARNESS_USER_B, false, name, sizeof(name)),
		"HARNESS_B lists test session B (EnumSession)") && ok;

	return ok;
}

////////////////////////////
// Frames through the cascade

// Check that the MAC table of a hub maps a MAC address to a session
static bool HarnessCheckMac(HARNESS *h, char *hubname, UCHAR *mac, char *session_name)
{
	RPC_ENUM_MAC_TABLE t;
	UINT i, err;
	bool found = false;
	char mac_str[64];
	char got[MAX_SESSION_NAME_LEN + 1];
	char tmp[MAX_SIZE];

	MacToStr(mac_str, sizeof(mac_str), mac);
	got[0] = 0;

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), hubname);

	err = ScEnumMacTable(h->Rpc, &t);
	if (err != ERR_NO_ERROR)
	{
		Format(tmp, sizeof(tmp), "EnumMacTable %s", hubname);
		return HarnessCheckErr(h, err, tmp);
	}

	for (i = 0;i < t.NumMacTable;i++)
	{
		RPC_ENUM_MAC_TABLE_ITEM *e = &t.MacTables[i];

		if (Cmp(e->MacAddress, mac, 6) == 0)
		{
			found = true;
			StrCpy(got, sizeof(got), e->SessionName);
			break;
		}
	}

	FreeRpcEnumMacTable(&t);

	Format(tmp, sizeof(tmp), "MAC table of %s maps %s to %s (EnumMacTable: %s)",
		hubname, mac_str, session_name, found ? got : "not learned");

	return HarnessCheck(h, found && StrCmpi(got, session_name) == 0, tmp);
}

// Teach both MAC addresses: a broadcast from B, then a broadcast from A
static bool HarnessTeach(HARNESS *h)
{
	UCHAR teach_b[HARNESS_FRAME_SIZE];
	UCHAR teach_a[HARNESS_FRAME_SIZE];
	bool ok;

	HarnessBuildFrame(teach_b, sizeof(teach_b), harness_mac_broadcast, harness_mac_b, 1);
	HarnessBuildFrame(teach_a, sizeof(teach_a), harness_mac_broadcast, harness_mac_a, 2);

	HarnessPaSend(h->PaB, teach_b, sizeof(teach_b));
	ok = HarnessCheck(h, HarnessPaWaitRecv(h->PaA, 1, HARNESS_FRAME_TIMEOUT) &&
		HarnessPaFrameIs(h->PaA, 0, teach_b, sizeof(teach_b)),
		"broadcast from HARNESS_B arrives byte-identical on HARNESS_A");

	HarnessPaSend(h->PaA, teach_a, sizeof(teach_a));
	ok = HarnessCheck(h, HarnessPaWaitRecv(h->PaB, 1, HARNESS_FRAME_TIMEOUT) &&
		HarnessPaFrameIs(h->PaB, 0, teach_a, sizeof(teach_a)),
		"broadcast from HARNESS_A (teaches the MAC table) arrives byte-identical on HARNESS_B") && ok;

	return ok;
}

// Unicast and broadcast frames from HARNESS_A to HARNESS_B, then the MAC tables
static bool HarnessFrames(HARNESS *h)
{
	UCHAR unicast[HARNESS_FRAME_SIZE];
	UCHAR bcast[HARNESS_FRAME_SIZE];
	char name_a[MAX_SESSION_NAME_LEN + 1];
	char name_b[MAX_SESSION_NAME_LEN + 1];
	char name_link_a[MAX_SESSION_NAME_LEN + 1];
	char name_link_b[MAX_SESSION_NAME_LEN + 1];
	char tmp[MAX_SIZE];
	UINT num_a, num_b;
	bool ok;

	Print("[frames]\n");

	ok = HarnessTeach(h);

	HarnessBuildFrame(unicast, sizeof(unicast), harness_mac_b, harness_mac_a, 3);
	HarnessBuildFrame(bcast, sizeof(bcast), harness_mac_broadcast, harness_mac_a, 4);

	HarnessPaSend(h->PaA, unicast, sizeof(unicast));
	ok = HarnessCheck(h, HarnessPaWaitRecv(h->PaB, 2, HARNESS_FRAME_TIMEOUT) &&
		HarnessPaFrameIs(h->PaB, 1, unicast, sizeof(unicast)),
		"unicast from HARNESS_A to the MAC of HARNESS_B arrives byte-identical") && ok;

	HarnessPaSend(h->PaA, bcast, sizeof(bcast));
	ok = HarnessCheck(h, HarnessPaWaitRecv(h->PaB, 3, HARNESS_FRAME_TIMEOUT) &&
		HarnessPaFrameIs(h->PaB, 2, bcast, sizeof(bcast)),
		"second broadcast from HARNESS_A arrives byte-identical") && ok;

	SleepThread(HARNESS_SETTLE_TIME);
	num_a = HarnessPaNumRecorded(h->PaA);
	num_b = HarnessPaNumRecorded(h->PaB);
	Format(tmp, sizeof(tmp), "no unexpected or echoed frames (A received %u of 1, B received %u of 3)", num_a, num_b);
	ok = HarnessCheck(h, num_a == 1 && num_b == 3, tmp) && ok;

	if (HarnessCheck(h, HarnessFindSession(h, HARNESS_HUB_A, HARNESS_USER_A, false, name_a, sizeof(name_a)) &&
		HarnessFindSession(h, HARNESS_HUB_A, NULL, true, name_link_a, sizeof(name_link_a)) &&
		HarnessFindSession(h, HARNESS_HUB_B, HARNESS_USER_B, false, name_b, sizeof(name_b)) &&
		HarnessFindSession(h, HARNESS_HUB_B, HARNESS_LINK_USER, false, name_link_b, sizeof(name_link_b)),
		"session names resolved through EnumSession") == false)
	{
		return false;
	}

	ok = HarnessCheckMac(h, HARNESS_HUB_A, harness_mac_a, name_a) && ok;
	ok = HarnessCheckMac(h, HARNESS_HUB_A, harness_mac_b, name_link_a) && ok;
	ok = HarnessCheckMac(h, HARNESS_HUB_B, harness_mac_b, name_b) && ok;
	ok = HarnessCheckMac(h, HARNESS_HUB_B, harness_mac_a, name_link_b) && ok;

	return ok;
}

////////////////////////////
// vpncmd golden outputs

// Resolve the normalisation rules from the string table
static HARNESS_NORM *HarnessNewNorm()
{
	HARNESS_NORM *n = ZeroMalloc(sizeof(HARNESS_NORM));
	UINT i;

	n->VolatileColumns = NewListFast(NULL);
	n->VolatileRows = NewListFast(NULL);
	n->DropRows = NewListFast(NULL);

	for (i = 0;i < sizeof(harness_volatile_columns) / sizeof(harness_volatile_columns[0]);i++)
	{
		HarnessAddLabel(n->VolatileColumns, _UU(harness_volatile_columns[i]));
	}

	for (i = 0;i < sizeof(harness_volatile_rows) / sizeof(harness_volatile_rows[0]);i++)
	{
		HarnessAddLabel(n->VolatileRows, _UU(harness_volatile_rows[i]));
	}

	for (i = 0;i < sizeof(harness_drop_rows) / sizeof(harness_drop_rows[0]);i++)
	{
		HarnessAddLabel(n->DropRows, _UU(harness_drop_rows[i]));
	}

	for (i = 0;i < sizeof(harness_drop_caps) / sizeof(harness_drop_caps[0]);i++)
	{
		HarnessAddCapsLabel(n->DropRows, harness_drop_caps[i]);
	}

	return n;
}

// Release the normalisation rules
static void HarnessFreeNorm(HARNESS_NORM *n)
{
	if (n == NULL)
	{
		return;
	}

	HarnessFreeLines(n->VolatileColumns);
	HarnessFreeLines(n->VolatileRows);
	HarnessFreeLines(n->DropRows);

	Free(n);
}

// Add a title (empty titles are ignored)
static void HarnessAddLabel(LIST *o, wchar_t *label)
{
	if (label == NULL || UniIsEmptyStr(label))
	{
		return;
	}

	Add(o, HarnessUniToUtf8(label));
}

// Add the title vpncmd Caps prints for a capability name
static void HarnessAddCapsLabel(LIST *o, char *caps_name)
{
	char name[MAX_SIZE];
	wchar_t title[MAX_SIZE];

	Format(name, sizeof(name), "CT_%s", caps_name);
	UniStrCpy(title, sizeof(title), _UU(name));

	if (UniIsEmptyStr(title))
	{
		UniFormat(title, sizeof(title), L"%S", (StrLen(caps_name) >= 2) ? caps_name + 2 : caps_name);
	}

	HarnessAddLabel(o, title);
}

// Exact string lookup
static bool HarnessInList(LIST *o, char *str)
{
	UINT i;

	for (i = 0;i < LIST_NUM(o);i++)
	{
		if (StrCmp(LIST_DATA(o, i), str) == 0)
		{
			return true;
		}
	}

	return false;
}

// Split a CSV line (quoted cells as written by vpncmd /CSV, lenient for plain text lines)
static HARNESS_CELLS *HarnessCsvSplit(char *line)
{
	HARNESS_CELLS *c = ZeroMalloc(sizeof(HARNESS_CELLS));
	UINT len = StrLen(line);
	UINT i = 0;

	c->Cell = ZeroMalloc(sizeof(char *) * (len + 1));

	while (true)
	{
		char *cell = ZeroMalloc(len + 1);
		UINT n = 0;

		if (i < len && line[i] == '"')
		{
			i++;
			while (i < len)
			{
				if (line[i] == '"')
				{
					if ((i + 1) < len && line[i + 1] == '"')
					{
						cell[n++] = '"';
						i += 2;
						continue;
					}

					i++;
					break;
				}

				cell[n++] = line[i++];
			}
		}

		while (i < len && line[i] != ',')
		{
			cell[n++] = line[i++];
		}

		c->Cell[c->Num++] = cell;

		if (i >= len)
		{
			break;
		}

		// Skip the comma
		i++;
	}

	return c;
}

// Join cells into a CSV line with the vpncmd escaping rules
static char *HarnessCsvJoin(HARNESS_CELLS *c)
{
	BUF *b = NewBuf();
	UINT i, j;
	char *ret;

	for (i = 0;i < c->Num;i++)
	{
		char *s = c->Cell[i];
		UINT len = StrLen(s);
		bool escape = false;

		if (i != 0)
		{
			WriteBuf(b, ",", 1);
		}

		for (j = 0;j < len;j++)
		{
			if (s[j] == ',' || s[j] == '"' || s[j] == '\n')
			{
				escape = true;
			}
		}

		if (escape == false)
		{
			WriteBuf(b, s, len);
		}
		else
		{
			WriteBuf(b, "\"", 1);
			for (j = 0;j < len;j++)
			{
				if (s[j] == '"')
				{
					WriteBuf(b, "\"", 1);
				}
				WriteBuf(b, &s[j], 1);
			}
			WriteBuf(b, "\"", 1);
		}
	}

	WriteBufChar(b, 0);
	ret = CopyStr((char *)b->Buf);
	FreeBuf(b);

	return ret;
}

// Release cells
static void HarnessFreeCells(HARNESS_CELLS *c)
{
	UINT i;

	if (c == NULL)
	{
		return;
	}

	for (i = 0;i < c->Num;i++)
	{
		Free(c->Cell[i]);
	}

	Free(c->Cell);
	Free(c);
}

// Replace a cell
static void HarnessSetCell(HARNESS_CELLS *c, UINT index, char *str)
{
	Free(c->Cell[index]);
	c->Cell[index] = CopyStr(str);
}

// Whether a cell contains a date (4-digit year, 1-2 digit month and day with any separators)
static bool HarnessIsDateTime(char *s)
{
	UINT len = StrLen(s);
	UINT i;

	for (i = 0;(i + 4) <= len;i++)
	{
		UINT j, n;

		if (i >= 1 && HARNESS_IS_DIGIT(s[i - 1]))
		{
			continue;
		}

		if (HARNESS_IS_DIGIT(s[i]) == false || HARNESS_IS_DIGIT(s[i + 1]) == false ||
			HARNESS_IS_DIGIT(s[i + 2]) == false || HARNESS_IS_DIGIT(s[i + 3]) == false)
		{
			continue;
		}

		j = i + 4;
		if (j < len && HARNESS_IS_DIGIT(s[j]))
		{
			continue;
		}

		// Separator (locale strings may be multi-byte)
		n = 0;
		while (j < len && HARNESS_IS_DIGIT(s[j]) == false && n < 6)
		{
			j++;
			n++;
		}
		if (n == 0 || j >= len || HARNESS_IS_DIGIT(s[j]) == false)
		{
			continue;
		}

		// Month
		n = 0;
		while (j < len && HARNESS_IS_DIGIT(s[j]))
		{
			j++;
			n++;
		}
		if (n > 2)
		{
			continue;
		}

		// Separator
		n = 0;
		while (j < len && HARNESS_IS_DIGIT(s[j]) == false && n < 6)
		{
			j++;
			n++;
		}
		if (n == 0 || j >= len || HARNESS_IS_DIGIT(s[j]) == false)
		{
			continue;
		}

		// Day
		n = 0;
		while (j < len && HARNESS_IS_DIGIT(s[j]))
		{
			j++;
			n++;
		}
		if (n > 2)
		{
			continue;
		}

		return true;
	}

	return false;
}

// Hexadecimal digit
static bool HarnessIsHexChar(char c)
{
	return (HARNESS_IS_DIGIT(c) || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'));
}

// Whether a cell contains a MAC address other than the fixed harness addresses
static bool HarnessHasRandomMac(char *s)
{
	UINT len = StrLen(s);
	UINT i;

	for (i = 0;(i + 17) <= len;i++)
	{
		UINT k;
		bool match = true;
		char sep = s[i + 2];

		if (sep != '-' && sep != ':')
		{
			continue;
		}

		for (k = 0;k < 17;k++)
		{
			char c = s[i + k];

			if ((k % 3) == 2)
			{
				if (c != sep)
				{
					match = false;
					break;
				}
			}
			else if (HarnessIsHexChar(c) == false)
			{
				match = false;
				break;
			}
		}

		if (match)
		{
			char found[18];
			char known_a[64];
			char known_b[64];

			StrCpy(found, sizeof(found), s + i);
			found[17] = 0;
			if (sep == ':')
			{
				for (k = 2;k < 17;k += 3)
				{
					found[k] = '-';
				}
			}

			MacToStr(known_a, sizeof(known_a), harness_mac_a);
			MacToStr(known_b, sizeof(known_b), harness_mac_b);

			if (StrCmpi(found, known_a) != 0 && StrCmpi(found, known_b) != 0)
			{
				return true;
			}
		}
	}

	return false;
}

// Generic cell rules; returns a new string when the cell changes, otherwise NULL
static char *HarnessNormalizeCell(char *s)
{
	UINT len = StrLen(s);

	if (HarnessIsDateTime(s))
	{
		return CopyStr(HARNESS_TAG_DATETIME);
	}

	if (HarnessHasRandomMac(s))
	{
		return CopyStr(HARNESS_TAG_MAC);
	}

	// Session names end with a per-hub counter: SID-<USER>-<n>
	if (len >= 6 && s[0] == 'S' && s[1] == 'I' && s[2] == 'D' && s[3] == '-' && HARNESS_IS_DIGIT(s[len - 1]))
	{
		UINT i = len;
		char *ret;

		while (i > 0 && HARNESS_IS_DIGIT(s[i - 1]))
		{
			i--;
		}

		if (i >= 5 && s[i - 1] == '-')
		{
			ret = ZeroMalloc(i + 2);
			Copy(ret, s, i);
			ret[i] = '#';

			return ret;
		}
	}

	return NULL;
}

// Normalise the CSV output of one vpncmd command
static char *HarnessNormalizeVpncmd(HARNESS_NORM *n, BUF *raw)
{
	char *text = HarnessBufToStr(raw);
	LIST *lines = HarnessSplitLines(HarnessSkipBom(text));
	LIST *out = NewListFast(NULL);
	bool volatile_col[HARNESS_MAX_COLUMNS];
	UINT num_header = 0;
	UINT i, j;
	BUF *b;
	char *ret;

	Zero(volatile_col, sizeof(volatile_col));

	for (i = 0;i < LIST_NUM(lines);i++)
	{
		char *line = LIST_DATA(lines, i);
		HARNESS_CELLS *c = HarnessCsvSplit(line);
		bool drop = false;
		bool row_rule = false;
		bool changed = false;

		if (HarnessInList(n->DropRows, c->Cell[0]))
		{
			drop = true;
		}
		else if (c->Num >= 2 && HarnessInList(n->VolatileRows, c->Cell[0]))
		{
			for (j = 1;j < c->Num;j++)
			{
				HarnessSetCell(c, j, HARNESS_TAG_VOLATILE);
			}
			row_rule = true;
			changed = true;
		}

		if (drop == false && row_rule == false && c->Num >= 3)
		{
			bool is_header = false;

			for (j = 0;j < c->Num;j++)
			{
				if (HarnessInList(n->VolatileColumns, c->Cell[j]))
				{
					is_header = true;
				}
			}

			if (is_header)
			{
				// Header of a multi-column table: remember the volatile columns
				Zero(volatile_col, sizeof(volatile_col));
				num_header = c->Num;
				for (j = 0;j < c->Num && j < HARNESS_MAX_COLUMNS;j++)
				{
					volatile_col[j] = HarnessInList(n->VolatileColumns, c->Cell[j]);
				}
			}
			else if (c->Num == num_header)
			{
				for (j = 0;j < c->Num && j < HARNESS_MAX_COLUMNS;j++)
				{
					if (volatile_col[j])
					{
						HarnessSetCell(c, j, HARNESS_TAG_VOLATILE);
						changed = true;
					}
				}
			}
		}

		if (drop == false)
		{
			for (j = 0;j < c->Num;j++)
			{
				char *s = HarnessNormalizeCell(c->Cell[j]);

				if (s != NULL)
				{
					Free(c->Cell[j]);
					c->Cell[j] = s;
					changed = true;
				}
			}

			Add(out, changed ? HarnessCsvJoin(c) : CopyStr(line));
		}

		HarnessFreeCells(c);
	}

	// No trailing empty lines
	while (LIST_NUM(out) >= 1 && StrLen(LIST_DATA(out, LIST_NUM(out) - 1)) == 0)
	{
		char *last = LIST_DATA(out, LIST_NUM(out) - 1);

		Delete(out, last);
		Free(last);
	}

	b = NewBuf();
	for (i = 0;i < LIST_NUM(out);i++)
	{
		char *s = LIST_DATA(out, i);

		WriteBuf(b, s, StrLen(s));
		WriteBuf(b, "\r\n", 2);
	}
	ret = HarnessBufToStr(b);
	FreeBuf(b);

	HarnessFreeLines(out);
	HarnessFreeLines(lines);
	Free(text);

	return ret;
}

// Run one vpncmd /SERVER command in-process through CommandMain and read its /OUT file
static BUF *HarnessRunVpncmd(HARNESS *h, HARNESS_VPNCMD *v)
{
	char cmdline[MAX_SIZE];
	char tmp[MAX_SIZE];
	wchar_t *w;
	UINT ret;
	BUF *b;

	FileDelete(HARNESS_VPNCMD_OUT);

	if (v->Hub == NULL)
	{
		Format(cmdline, sizeof(cmdline), "vpncmd 127.0.0.1:%u /SERVER /CSV /PROGRAMMING /OUT:%s /CMD %s",
			HARNESS_PORT, HARNESS_VPNCMD_OUT, v->Command);
	}
	else
	{
		Format(cmdline, sizeof(cmdline), "vpncmd 127.0.0.1:%u /SERVER /ADMINHUB:%s /CSV /PROGRAMMING /OUT:%s /CMD %s",
			HARNESS_PORT, v->Hub, HARNESS_VPNCMD_OUT, v->Command);
	}

	Print("  vpncmd: %s\n", cmdline);

	w = CopyStrToUni(cmdline);
	ret = CommandMain(w);
	Free(w);

	b = ReadDump(HARNESS_VPNCMD_OUT);
	FileDelete(HARNESS_VPNCMD_OUT);

	Format(tmp, sizeof(tmp), "vpncmd %s%s%s ran (return code %u, output %s)",
		v->Hub == NULL ? "" : v->Hub, v->Hub == NULL ? "" : " ", v->Command, ret,
		b == NULL ? "missing" : "captured");

	if (HarnessCheck(h, ret == ERR_NO_ERROR && b != NULL, tmp) == false && b != NULL)
	{
		FreeBuf(b);
		b = NULL;
	}

	return b;
}

// Whether a directory contains at least one file
static bool HarnessDirHasFiles(char *dir)
{
	DIRLIST *d = EnumDir(dir);
	UINT i;
	bool ret = false;

	if (d == NULL)
	{
		return false;
	}

	for (i = 0;i < d->NumFiles;i++)
	{
		if (d->File[i]->Folder == false)
		{
			ret = true;
			break;
		}
	}

	FreeDir(d);

	return ret;
}

// Output and golden directories, and the update mode
static void HarnessGetDirs(char *out_dir, UINT out_size, char *golden_dir, UINT golden_size, bool *update)
{
	char exe_dir[MAX_SIZE];
	char tmp[MAX_SIZE];

	GetExeDir(exe_dir, sizeof(exe_dir));

	// RANZ_HARNESS_OUT overrides <exe dir>/harness-out (build/harness-out in CI)
	if (GetEnv("RANZ_HARNESS_OUT", tmp, sizeof(tmp)) && IsEmptyStr(tmp) == false)
	{
		StrCpy(out_dir, out_size, tmp);
	}
	else
	{
		Format(out_dir, out_size, "%s/harness-out", exe_dir);
	}

	// RANZ_GOLDEN_DIR overrides <exe dir>/../tests/golden/harness (tests/golden/harness at the repository root)
	if (GetEnv("RANZ_GOLDEN_DIR", tmp, sizeof(tmp)) && IsEmptyStr(tmp) == false)
	{
		StrCpy(golden_dir, golden_size, tmp);
	}
	else
	{
		Format(tmp, sizeof(tmp), "%s/../tests/golden/harness", exe_dir);
		NormalizePath(golden_dir, golden_size, tmp);
	}

	*update = false;

	if (GetEnv("RANZ_UPDATE_GOLDEN", tmp, sizeof(tmp)) && StrCmp(tmp, "1") == 0)
	{
		*update = true;
	}

	if (HarnessDirHasFiles(golden_dir) == false)
	{
		*update = true;
	}
}

// Write the actual output, then compare it with the golden file (or print it in update mode)
static void HarnessCompareGolden(HARNESS *h, char *out_dir, char *golden_dir, char *file_name, char *actual, bool update)
{
	char path[MAX_SIZE];
	char tmp[MAX_SIZE];
	BUF *b = NewBuf();

	WriteBuf(b, actual, StrLen(actual));
	Format(path, sizeof(path), "%s/%s", out_dir, file_name);
	if (DumpBuf(b, path) == false)
	{
		Format(tmp, sizeof(tmp), "write %s", path);
		HarnessCheck(h, false, tmp);
	}
	FreeBuf(b);

	if (update)
	{
		LIST *lines = HarnessSplitLines(actual);
		UINT i;

		Print("=== BEGIN GOLDEN %s ===\n", file_name);
		for (i = 0;i < LIST_NUM(lines);i++)
		{
			Print("%s\n", (char *)LIST_DATA(lines, i));
		}
		Print("=== END GOLDEN %s ===\n", file_name);
		HarnessFreeLines(lines);

		Format(tmp, sizeof(tmp), "%s written (update mode, not compared)", file_name);
		HarnessCheck(h, true, tmp);
	}
	else
	{
		BUF *g;
		char *golden;

		Format(path, sizeof(path), "%s/%s", golden_dir, file_name);
		g = ReadDump(path);
		golden = HarnessBufToStr(g);

		Format(tmp, sizeof(tmp), "%s matches the golden file", file_name);
		if (g == NULL)
		{
			Format(tmp, sizeof(tmp), "%s matches the golden file (golden file missing: %s)", file_name, path);
			HarnessCheck(h, false, tmp);
		}
		else if (HarnessCheck(h, HarnessTextEqual(golden, actual), tmp) == false)
		{
			HarnessPrintDiff(file_name, golden, actual);
		}

		Free(golden);
		FreeBuf(g);
	}
}

// Run the fixed vpncmd command list, normalise and compare with the golden files
static void HarnessGolden(HARNESS *h)
{
	char out_dir[MAX_SIZE];
	char golden_dir[MAX_SIZE];
	bool update;
	HARNESS_NORM *n;
	UINT i;

	Print("[golden]\n");
	HarnessSetPhase("golden", NULL);

	HarnessGetDirs(out_dir, sizeof(out_dir), golden_dir, sizeof(golden_dir), &update);
	MakeDirEx(out_dir);

	// Fixed machine-readable mode line: CI can require compare mode once the golden files are committed
	Print("HARNESS GOLDEN MODE %s\n", update ? "update" : "compare");
	Print("  golden directory: %s (%s)\n", golden_dir,
		update ? "update mode: missing or empty, or RANZ_UPDATE_GOLDEN=1" : "compare mode");
	Print("  output directory: %s\n", out_dir);

	n = HarnessNewNorm();

	for (i = 0;i < sizeof(harness_vpncmd_list) / sizeof(harness_vpncmd_list[0]);i++)
	{
		HARNESS_VPNCMD *v = &harness_vpncmd_list[i];
		BUF *raw;

		HarnessSetPhase("golden", v->Name);
		raw = HarnessRunVpncmd(h, v);

		if (raw != NULL)
		{
			char file_name[MAX_SIZE];
			char *norm = HarnessNormalizeVpncmd(n, raw);

			Format(file_name, sizeof(file_name), "vpncmd_%s.txt", v->Name);
			HarnessCompareGolden(h, out_dir, golden_dir, file_name, norm, update);

			Free(norm);
			FreeBuf(raw);
		}
	}

	if (update == false)
	{
		HarnessCheckStaleGolden(h, golden_dir);
	}

	HarnessFreeNorm(n);
}

// Compare mode: fail on every vpncmd_*.txt golden file that no command of the list produces
static void HarnessCheckStaleGolden(HARNESS *h, char *golden_dir)
{
	DIRLIST *d = EnumDir(golden_dir);
	UINT i, j;
	UINT num_stale = 0;
	char expected[MAX_SIZE];
	char tmp[MAX_SIZE];

	if (d == NULL)
	{
		return;
	}

	for (i = 0;i < d->NumFiles;i++)
	{
		DIRENT *e = d->File[i];
		bool known = false;

		if (e->Folder || StartWith(e->FileName, "vpncmd_") == false || EndWith(e->FileName, ".txt") == false)
		{
			continue;
		}

		for (j = 0;j < sizeof(harness_vpncmd_list) / sizeof(harness_vpncmd_list[0]);j++)
		{
			Format(expected, sizeof(expected), "vpncmd_%s.txt", harness_vpncmd_list[j].Name);
			if (StrCmpi(e->FileName, expected) == 0)
			{
				known = true;
				break;
			}
		}

		if (known == false)
		{
			Format(tmp, sizeof(tmp), "stale golden file %s: no vpncmd command of the list produces it", e->FileName);
			HarnessCheck(h, false, tmp);
			num_stale++;
		}
	}

	FreeDir(d);

	if (num_stale == 0)
	{
		HarnessCheck(h, true, "no stale vpncmd_*.txt golden file");
	}
}

////////////////////////////
// Configuration round-trips

// Configuration items normalised before a comparison
static bool HarnessIsVolatileConfigName(char *name, bool is_uint64)
{
	UINT i;

	// Timestamps: CreatedTime, UpdatedTime, LastCommTime, LastLoginTime, ExpireTime
	if (is_uint64 && EndWith(name, "Time"))
	{
		return true;
	}

	for (i = 0;i < sizeof(harness_config_volatile_names) / sizeof(harness_config_volatile_names[0]);i++)
	{
		if (StrCmp(name, harness_config_volatile_names[i]) == 0)
		{
			return true;
		}
	}

	return false;
}

// Normalise a configuration text ("uint64 <Name>Time <v>", traffic counters, NumLogin, ConfigRevision)
static char *HarnessNormalizeConfig(char *text)
{
	LIST *lines = HarnessSplitLines(text);
	BUF *b = NewBuf();
	UINT i;
	char *ret;

	for (i = 0;i < LIST_NUM(lines);i++)
	{
		char *line = LIST_DATA(lines, i);
		UINT indent = 0;
		bool replaced = false;
		TOKEN_LIST *t;

		while (line[indent] == '\t' || line[indent] == ' ')
		{
			indent++;
		}

		t = ParseToken(line + indent, " \t");
		if (t != NULL)
		{
			if (t->NumTokens == 3 &&
				(StrCmp(t->Token[0], "uint") == 0 || StrCmp(t->Token[0], "uint64") == 0) &&
				HarnessIsVolatileConfigName(t->Token[1], StrCmp(t->Token[0], "uint64") == 0))
			{
				WriteBuf(b, line, indent);
				WriteBuf(b, t->Token[0], StrLen(t->Token[0]));
				WriteBuf(b, " ", 1);
				WriteBuf(b, t->Token[1], StrLen(t->Token[1]));
				WriteBuf(b, " " HARNESS_TAG_NUMBER, StrLen(" " HARNESS_TAG_NUMBER));
				replaced = true;
			}

			FreeToken(t);
		}

		if (replaced == false)
		{
			WriteBuf(b, line, StrLen(line));
		}

		WriteBuf(b, "\r\n", 2);
	}

	ret = HarnessBufToStr(b);
	FreeBuf(b);
	HarnessFreeLines(lines);

	return ret;
}

// Compare two configuration texts after normalisation
static bool HarnessCompareConfig(HARNESS *h, char *what, char *text1, char *text2)
{
	char *n1 = HarnessNormalizeConfig(text1);
	char *n2 = HarnessNormalizeConfig(text2);
	char tmp[MAX_SIZE];
	bool ok;

	Format(tmp, sizeof(tmp), "%s: normalised configuration texts are equal", what);
	ok = HarnessCheck(h, HarnessTextEqual(n1, n2), tmp);
	if (ok == false)
	{
		HarnessPrintDiff(what, n1, n2);
	}

	Free(n1);
	Free(n2);

	return ok;
}

// Save the configuration (GetConfig), re-parse it with the Cfg API, write it again and compare
static void HarnessConfigApiRoundTrip(HARNESS *h)
{
	RPC_CONFIG c;
	BUF *b;
	FOLDER *root;
	UINT err;

	Print("[config: Cfg API round-trip]\n");

	Zero(&c, sizeof(c));
	err = ScGetConfig(h->Rpc, &c);
	if (HarnessCheckErr(h, err, "GetConfig") == false)
	{
		return;
	}

	b = NewBuf();
	WriteBuf(b, c.FileData, StrLen(c.FileData));
	SeekBufToBegin(b);
	root = CfgBufTextToFolder(b);
	FreeBuf(b);

	if (HarnessCheck(h, root != NULL, "configuration text parsed by CfgBufTextToFolder"))
	{
		BUF *b2 = CfgFolderToBuf(root, true);
		char *text2 = HarnessBufToStr(b2);

		HarnessCompareConfig(h, "config_cfg_api_roundtrip", c.FileData, text2);

		Free(text2);
		FreeBuf(b2);
		CfgDeleteFolder(root);
	}

	FreeRpcConfig(&c);
}

// Save the configuration, restart the server from the saved file and compare the reloaded configuration
static void HarnessReload(HARNESS *h)
{
	RPC_CONFIG c;
	char *text1;
	UINT err = ERR_NO_ERROR;

	Print("[config: reload into a fresh server instance]\n");

	Zero(&c, sizeof(c));
	err = ScGetConfig(h->Rpc, &c);
	if (HarnessCheckErr(h, err, "GetConfig before the restart") == false)
	{
		return;
	}
	text1 = CopyStr(c.FileData);
	FreeRpcConfig(&c);

	// SiReleaseServer writes the configuration file, SiNewServer loads it again
	AdminDisconnect(h->Rpc);
	h->Rpc = NULL;
	SiReleaseServer(h->Server);
	h->Server = NULL;

	h->Server = SiNewServer(false);
	if (HarnessCheck(h, h->Server != NULL, "server restarted from the saved " HARNESS_CONFIG_FILE) &&
		HarnessWaitListener(h, HARNESS_LISTEN_TIMEOUT))
	{
		h->Rpc = HarnessAdminConnect(h->ClientCedar, HARNESS_START_TIMEOUT, &err);
		if (HarnessCheckErr(h, (h->Rpc != NULL ? ERR_NO_ERROR : err), "admin RPC reconnected after the restart"))
		{
			Zero(&c, sizeof(c));
			err = ScGetConfig(h->Rpc, &c);
			if (HarnessCheckErr(h, err, "GetConfig after the restart"))
			{
				HarnessCompareConfig(h, "config_reload_roundtrip", text1, c.FileData);
				FreeRpcConfig(&c);
			}
		}
	}

	Free(text1);
}

////////////////////////////
// Teardown

// Delete the cascade, the users and the hubs through the admin RPC, then verify the hub list
static void HarnessDeleteObjects(HARNESS *h, bool check)
{
	RPC_LINK k;
	RPC_DELETE_USER u;
	RPC_DELETE_HUB d;
	RPC_ENUM_HUB e;
	UINT err;
	UINT i;

	Print("[teardown]\n");

	Zero(&k, sizeof(k));
	StrCpy(k.HubName, sizeof(k.HubName), HARNESS_HUB_A);
	UniStrCpy(k.AccountName, sizeof(k.AccountName), HARNESS_LINK_NAME);
	HarnessStep(h, ScSetLinkOffline(h->Rpc, &k), "SetLinkOffline HARNESS_CASCADE", check);

	Zero(&k, sizeof(k));
	StrCpy(k.HubName, sizeof(k.HubName), HARNESS_HUB_A);
	UniStrCpy(k.AccountName, sizeof(k.AccountName), HARNESS_LINK_NAME);
	HarnessStep(h, ScDeleteLink(h->Rpc, &k), "DeleteLink HARNESS_CASCADE", check);

	Zero(&u, sizeof(u));
	StrCpy(u.HubName, sizeof(u.HubName), HARNESS_HUB_B);
	StrCpy(u.Name, sizeof(u.Name), HARNESS_LINK_USER);
	HarnessStep(h, ScDeleteUser(h->Rpc, &u), "DeleteUser " HARNESS_LINK_USER, check);

	Zero(&u, sizeof(u));
	StrCpy(u.HubName, sizeof(u.HubName), HARNESS_HUB_B);
	StrCpy(u.Name, sizeof(u.Name), HARNESS_USER_B);
	HarnessStep(h, ScDeleteUser(h->Rpc, &u), "DeleteUser " HARNESS_USER_B, check);

	Zero(&u, sizeof(u));
	StrCpy(u.HubName, sizeof(u.HubName), HARNESS_HUB_A);
	StrCpy(u.Name, sizeof(u.Name), HARNESS_USER_A);
	HarnessStep(h, ScDeleteUser(h->Rpc, &u), "DeleteUser " HARNESS_USER_A, check);

	Zero(&d, sizeof(d));
	StrCpy(d.HubName, sizeof(d.HubName), HARNESS_HUB_A);
	HarnessStep(h, ScDeleteHub(h->Rpc, &d), "DeleteHub " HARNESS_HUB_A, check);

	Zero(&d, sizeof(d));
	StrCpy(d.HubName, sizeof(d.HubName), HARNESS_HUB_B);
	HarnessStep(h, ScDeleteHub(h->Rpc, &d), "DeleteHub " HARNESS_HUB_B, check);

	if (check)
	{
		bool left = false;

		Zero(&e, sizeof(e));
		err = ScEnumHub(h->Rpc, &e);
		if (HarnessCheckErr(h, err, "EnumHub after the teardown"))
		{
			for (i = 0;i < e.NumHub;i++)
			{
				if (StartWith(e.Hubs[i].HubName, "HARNESS_"))
				{
					left = true;
				}
			}
			FreeRpcEnumHub(&e);

			HarnessCheck(h, left == false, "no HARNESS_ hub is left");
		}
	}
}

// Delete the configuration file and the backups the server writes on every save (DontBackupConfig is false)
static void HarnessDeleteConfigFiles()
{
	wchar_t dir[MAX_SIZE];
	wchar_t path[MAX_SIZE];
	DIRLIST *d;
	UINT i;

	FileDelete(HARNESS_CONFIG_FILE);

	// EnumDirW does not resolve the '$' prefix: use the full path
	InnerFilePathW(dir, sizeof(dir), HARNESS_CONFIG_BACKUP_DIR);

	d = EnumDirW(dir);
	if (d != NULL)
	{
		for (i = 0;i < d->NumFiles;i++)
		{
			if (d->File[i]->Folder == false)
			{
				CombinePathW(path, sizeof(path), dir, d->File[i]->FileNameW);
				FileDeleteW(path);
			}
		}

		FreeDir(d);
	}

	DeleteDirW(dir);
}

// Stop everything and release every object of the run
static void HarnessTeardown(HARNESS *h, bool check)
{
	HarnessStopSessions(h);

	if (h->Rpc != NULL)
	{
		HarnessDeleteObjects(h, check);

		AdminDisconnect(h->Rpc);
		h->Rpc = NULL;
	}

	if (h->Server != NULL)
	{
		SiReleaseServer(h->Server);
		h->Server = NULL;
	}

	if (h->OldConfigName != NULL)
	{
		SERVER_CONFIG_FILE_NAME = h->OldConfigName;
		h->OldConfigName = NULL;
		HarnessDeleteConfigFiles();
	}

	if (h->ClientCedar != NULL)
	{
		ReleaseCedar(h->ClientCedar);
		h->ClientCedar = NULL;
	}
}

// Create a run
static HARNESS *HarnessNew()
{
	HARNESS *h = ZeroMalloc(sizeof(HARNESS));

	h->PaA = HarnessNewPa("A");
	h->PaB = HarnessNewPa("B");

	return h;
}

// Release a run (after HarnessTeardown)
static void HarnessFree(HARNESS *h)
{
	HarnessFreePa(h->PaA);
	HarnessFreePa(h->PaB);

	Free(h);
}

////////////////////////////
// Benchmark

// Monotonic time in nanoseconds from the high-resolution counter (Tick64 steps in whole milliseconds)
static UINT64 HarnessNowNs()
{
	return TickHighresNano64(false);
}

// One bench value as text; centi: the value is in hundredths and gets two decimals
static void HarnessBenchValue(char *str, UINT size, UINT64 value, bool centi)
{
	if (centi)
	{
		Format(str, size, "%I64u.%02u", value / 100, (UINT)(value % 100));
	}
	else
	{
		Format(str, size, "%I64u", value);
	}
}

// Print one case: "BENCH <name> <median> <unit>", then "BENCH <name>_runs <run 1>,...,<run n> <unit>" in run order
static void HarnessBenchReport(char *name, UINT64 *runs, UINT num, char *unit, bool centi)
{
	UINT64 sorted[HARNESS_BENCH_RUNS];
	char list[MAX_SIZE];
	char value[64];
	UINT i, j;

	if (num == 0 || num > HARNESS_BENCH_RUNS)
	{
		return;
	}

	Copy(sorted, runs, sizeof(UINT64) * num);
	for (i = 1;i < num;i++)
	{
		UINT64 v = sorted[i];

		for (j = i;j > 0 && sorted[j - 1] > v;j--)
		{
			sorted[j] = sorted[j - 1];
		}
		sorted[j] = v;
	}

	list[0] = 0;
	for (i = 0;i < num;i++)
	{
		HarnessBenchValue(value, sizeof(value), runs[i], centi);
		if (i != 0)
		{
			StrCat(list, sizeof(list), ",");
		}
		StrCat(list, sizeof(list), value);
	}

	// HARNESS_BENCH_RUNS is odd: the median is the middle run
	HarnessBenchValue(value, sizeof(value), sorted[num / 2], centi);
	Print("BENCH %s %s %s\n", name, value, unit);
	Print("BENCH %s_runs %s %s\n", name, list, unit);
}

// Run one case HARNESS_BENCH_RUNS times for span milliseconds each and report the operations per second.
// The clock is read every check_every operations (1 for slow operations, more when the clock would cost too much)
static bool HarnessBenchOps(char *name, HARNESS_BENCH_OP *op, void *param, UINT span, UINT check_every)
{
	UINT64 runs[HARNESS_BENCH_RUNS];
	UINT64 span_ns = (UINT64)span * HARNESS_NS_PER_MS;
	UINT r;

	for (r = 0;r < HARNESS_BENCH_RUNS;r++)
	{
		UINT64 start = HarnessNowNs();
		UINT64 now = start;
		UINT64 ops = 0;

		while (true)
		{
			if (op(param) == false)
			{
				Print("BENCH WARNING %s: wrong result, case skipped\n", name);
				return false;
			}

			ops++;
			if ((ops % check_every) == 0)
			{
				now = HarnessNowNs();
				if ((now - start) >= span_ns)
				{
					break;
				}
			}
		}

		runs[r] = ops * HARNESS_NS_PER_S / (now - start);
	}

	HarnessBenchReport(name, runs, HARNESS_BENCH_RUNS, "ops/s", false);

	return true;
}

// Frames per second from session A to session B through the cascade for one frame size: a warm-up,
// then HARNESS_BENCH_RUNS back-to-back windows of one continuous stream
static void HarnessBenchFrames(HARNESS *h, UINT size)
{
	UCHAR *frame = Malloc(size);
	HARNESS_FRAME *batch[HARNESS_QUEUE_HIGH];
	UINT64 mark_ns[HARNESS_BENCH_RUNS + 1];		// Run boundaries: end of the warm-up, then end of each run
	UINT64 mark_recv[HARNESS_BENCH_RUNS + 1];	// Frames received by session B at each boundary
	UINT64 fps[HARNESS_BENCH_RUNS];
	UINT64 centi_mbps[HARNESS_BENCH_RUNS];
	UINT64 next_mark;
	UINT num_marks = 0;
	UINT num_unsent;
	UINT i;
	char name[MAX_SIZE];
	char tmp[MAX_SIZE];

	HarnessBuildFrame(frame, size, harness_mac_b, harness_mac_a, 0x10000 + size);

	HarnessClearRecv(h->PaB);
	Lock(h->PaB->Lock);
	{
		h->PaB->Record = false;
	}
	Unlock(h->PaB->Lock);

	next_mark = HarnessNowNs() + (UINT64)HARNESS_BENCH_WARMUP * HARNESS_NS_PER_MS;

	while (true)
	{
		UINT queued;
		UINT64 now = HarnessNowNs();

		if (now >= next_mark)
		{
			mark_ns[num_marks] = now;
			mark_recv[num_marks] = HarnessPaGetNumRecv(h->PaB);
			num_marks++;

			if (num_marks > HARNESS_BENCH_RUNS)
			{
				break;
			}

			next_mark = now + (UINT64)HARNESS_BENCH_SPAN * HARNESS_NS_PER_MS;
		}

		queued = HarnessPaQueued(h->PaA);
		if (queued < HARNESS_QUEUE_HIGH)
		{
			UINT num = HARNESS_QUEUE_HIGH - queued;

			for (i = 0;i < num;i++)
			{
				batch[i] = ZeroMalloc(sizeof(HARNESS_FRAME));
				batch[i]->Data = Malloc(size);
				Copy(batch[i]->Data, frame, size);
				batch[i]->Size = size;
			}

			Lock(h->PaA->Lock);
			{
				for (i = 0;i < num;i++)
				{
					InsertQueue(h->PaA->SendQueue, batch[i]);
				}
			}
			Unlock(h->PaA->Lock);

			Cancel(h->PaA->Session->Cancel1);
		}
		else
		{
			Wait(h->PaA->SpaceEvent, 10);
		}
	}

	HarnessPaDrain(h->PaA, HARNESS_BENCH_DRAIN);

	// Frames still queued after the drain would be counted in the next frame size: discard them
	num_unsent = HarnessPaPurge(h->PaA);

	for (i = 0;i < HARNESS_BENCH_RUNS;i++)
	{
		UINT64 elapsed = mark_ns[i + 1] - mark_ns[i];
		UINT64 delivered = mark_recv[i + 1] - mark_recv[i];

		if (elapsed == 0)
		{
			elapsed = 1;
		}

		fps[i] = delivered * HARNESS_NS_PER_S / elapsed;
		// Hundredths of Mbit/s: bits / (elapsed_ns / 10^9) / 10^6 * 100
		centi_mbps[i] = delivered * (UINT64)size * 8ULL * 100000ULL / elapsed;
	}

	// "cascade_path": test session A, the cascade and test session B (3 TLS connections)
	Format(name, sizeof(name), "cascade_path_fps_%u", size);
	HarnessBenchReport(name, fps, HARNESS_BENCH_RUNS, "frames/s", false);
	Format(name, sizeof(name), "cascade_path_mbps_%u", size);
	HarnessBenchReport(name, centi_mbps, HARNESS_BENCH_RUNS, "Mbit/s", true);
	Print("BENCH cascade_path_unsent_%u %u frames\n", size, num_unsent);

	// The numbers are informational, a dead data path is an error
	Format(tmp, sizeof(tmp), "bench %u: frames delivered during the measured windows", size);
	HarnessCheck(h, mark_recv[HARNESS_BENCH_RUNS] > mark_recv[0], tmp);

	Free(frame);
}

////////////////////////////
// Flood benchmark: in-process sessions on hub HARNESS_FLOOD, no transport and no TLS

// Owner of the flood session connections (a server CONNECTION holds a THREAD); it has nothing to run
static void HarnessFloodIdleThread(THREAD *thread, void *param)
{
}

// In-process server session on the flood hub, made like the server side of a cascade (Link.c): a CONNECTION
// without sockets and the hub packet adapter, but no SessionMain thread. The bench thread calls the packet
// adapter itself, so a frame goes through HubPaPutPacket, StorePacket and HubPaGetNextPacket only
static SESSION *HarnessNewFloodSession(HUB *hub, THREAD *thread, UINT index, bool sender)
{
	CONNECTION *c;
	SESSION *s;
	POLICY *policy = ClonePolicy(GetDefaultPolicy());
	char username[MAX_USERNAME_LEN + 1];

	Format(username, sizeof(username), "bench-flood-%u", index);

	if (sender)
	{
		// The single sender floods at full rate: the broadcast storm guard would drop most of its frames
		policy->NoBroadcastLimiter = true;
	}

	c = NewServerConnection(hub->Cedar, NULL, thread);
	s = NewServerSession(hub->Cedar, c, hub, username, policy);
	c->Session = s;
	ReleaseConnection(c);

	s->Username = CopyStr(username);

	// Joined the hub in NewServerSession; floods reach it from here on (HubPaInit always succeeds)
	s->PacketAdapter->Init(s);

	return s;
}

// Release a flood session in the order of the end of SessionMain: leave the hub, free the packet adapter, release
static void HarnessFreeFloodSession(SESSION *s)
{
	DelSession(s->Hub, s);
	s->PacketAdapter->Free(s);
	ReleaseSession(s);
}

// One receive loop of the sender: HARNESS_FLOOD_BATCH broadcast frames into the hub, the end-of-loop call that
// wakes the receivers (cancel list), then every receiver takes its queued frames as its SessionMain would.
// Returns the frames the receivers got
static UINT64 HarnessFloodBatch(SESSION *sender, SESSION **recv, UINT num_recv, UCHAR *frame, UINT size)
{
	PACKET_ADAPTER *pa = sender->PacketAdapter;
	UINT64 delivered = 0;
	UINT i;

	for (i = 0;i < HARNESS_FLOOD_BATCH;i++)
	{
		void *data = Malloc(size);

		Copy(data, frame, size);
		pa->PutPacket(sender, data, size);
	}

	pa->PutPacket(sender, NULL, 0);

	for (i = 0;i < num_recv;i++)
	{
		SESSION *s = recv[i];
		void *data;

		while (s->PacketAdapter->GetNextPacket(s, &data) != 0)
		{
			Free(data);
			delivered++;
		}
	}

	return delivered;
}

// flood_fps_<n>: broadcast frames per second that one session floods to n receiving sessions of the hub
static void HarnessBenchFloodCase(HUB *hub, UINT num_recv)
{
	UCHAR frame[HARNESS_FRAME_SIZE];
	UCHAR mac_sender[6] = {0x02, 0x42, 0x55, 0x52, 0x00, 0xF0};
	UINT64 runs[HARNESS_BENCH_RUNS];
	UINT64 span_ns = (UINT64)HARNESS_BENCH_FLOOD_SPAN * HARNESS_NS_PER_MS;
	UINT64 sent = 0;
	UINT64 delivered = 0;
	THREAD *thread;
	SESSION *sender;
	SESSION **recv;
	UINT i, r;
	char name[MAX_SIZE];

	Format(name, sizeof(name), "flood_fps_%u", num_recv);

	thread = NewThread(HarnessFloodIdleThread, NULL);
	sender = HarnessNewFloodSession(hub, thread, 0, true);
	recv = ZeroMalloc(sizeof(SESSION *) * num_recv);
	for (i = 0;i < num_recv;i++)
	{
		recv[i] = HarnessNewFloodSession(hub, thread, i + 1, false);
	}

	HarnessBuildFrame(frame, sizeof(frame), harness_mac_broadcast, mac_sender, 0x20000 + num_recv);

	// Warm-up: the hub learns the sender MAC address
	HarnessFloodBatch(sender, recv, num_recv, frame, sizeof(frame));

	for (r = 0;r < HARNESS_BENCH_RUNS;r++)
	{
		UINT64 start = HarnessNowNs();
		UINT64 now;
		UINT64 frames = 0;

		do
		{
			delivered += HarnessFloodBatch(sender, recv, num_recv, frame, sizeof(frame));
			frames += HARNESS_FLOOD_BATCH;
			now = HarnessNowNs();
		}
		while ((now - start) < span_ns);

		sent += frames;
		runs[r] = frames * HARNESS_NS_PER_S / (now - start);
	}

	HarnessBenchReport(name, runs, HARNESS_BENCH_RUNS, "frames/s", false);

	// Every frame reaches every receiver: fewer copies means the hub dropped frames and the number is no flood rate
	if (delivered < sent * (UINT64)num_recv)
	{
		Print("BENCH WARNING %s: %I64u of %I64u copies delivered\n", name, delivered, sent * (UINT64)num_recv);
	}

	for (i = 0;i < num_recv;i++)
	{
		HarnessFreeFloodSession(recv[i]);
	}
	Free(recv);
	HarnessFreeFloodSession(sender);

	ReleaseThread(thread);
}

// Flood cases on a hub of their own: the flood loop of StorePacket sends to every session of the hub
static void HarnessBenchFlood(HARNESS *h)
{
	RPC_DELETE_HUB d;
	HUB *hub;

	if (HarnessCreateHub(h, HARNESS_HUB_FLOOD) == false)
	{
		return;
	}

	hub = GetHub(h->Server->Cedar, HARNESS_HUB_FLOOD);
	if (HarnessCheck(h, hub != NULL, "GetHub " HARNESS_HUB_FLOOD))
	{
		HarnessSetPhase("bench_flood_8", NULL);
		HarnessBenchFloodCase(hub, 8);
		HarnessSetPhase("bench_flood_64", NULL);
		HarnessBenchFloodCase(hub, 64);

		ReleaseHub(hub);
	}

	Zero(&d, sizeof(d));
	StrCpy(d.HubName, sizeof(d.HubName), HARNESS_HUB_FLOOD);
	HarnessCheckErr(h, ScDeleteHub(h->Rpc, &d), "DeleteHub " HARNESS_HUB_FLOOD);
}

////////////////////////////
// Pack benchmark

// Encode RPC_ENUM_SESSION: struct -> PACK -> BUF
static bool HarnessOpEncodeEnumSession(void *param)
{
	HARNESS_PACK_BENCH *b = (HARNESS_PACK_BENCH *)param;
	PACK *p = NewPack();
	BUF *buf;

	OutRpcEnumSession(p, b->Struct);
	buf = PackToBuf(p);
	FreePack(p);
	FreeBuf(buf);

	return true;
}

// Decode RPC_ENUM_SESSION: BUF -> PACK -> struct
static bool HarnessOpDecodeEnumSession(void *param)
{
	HARNESS_PACK_BENCH *b = (HARNESS_PACK_BENCH *)param;
	RPC_ENUM_SESSION t;
	PACK *p;

	SeekBufToBegin(b->Buf);
	p = BufToPack(b->Buf);
	if (p == NULL)
	{
		return false;
	}

	InRpcEnumSession(&t, p);
	FreeRpcEnumSession(&t);
	FreePack(p);

	return true;
}

// Pack encode and decode operations per second for an admin RPC struct (RPC_ENUM_SESSION)
static void HarnessBenchPack(HARNESS *h)
{
	HARNESS_PACK_BENCH b;
	RPC_ENUM_SESSION t;
	RPC_ENUM_SESSION t2;
	PACK *p;
	UINT i;
	bool ok = false;

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), HARNESS_HUB_A);
	t.NumSession = HARNESS_PACK_ITEMS;
	t.Sessions = ZeroMalloc(sizeof(RPC_ENUM_SESSION_ITEM) * t.NumSession);

	for (i = 0;i < t.NumSession;i++)
	{
		RPC_ENUM_SESSION_ITEM *e = &t.Sessions[i];

		Format(e->Name, sizeof(e->Name), "SID-BENCH-USER-%u", i + 1);
		Format(e->Username, sizeof(e->Username), "bench-user-%u", i + 1);
		Format(e->Hostname, sizeof(e->Hostname), "host-%u.bench.invalid", i + 1);
		e->Ip = 0x0A000001 + i;
		e->MaxNumTcp = 8;
		e->CurrentNumTcp = 1 + (i % 8);
		e->PacketSize = (UINT64)i * 1500000;
		e->PacketNum = (UINT64)i * 1000;
		e->Client_BridgeMode = ((i % 2) == 0);
		e->UniqueId[i % 16] = (UCHAR)i;
		e->CreatedTime = 1700000000000ULL + (UINT64)i;
		e->LastCommTime = 1700000001000ULL + (UINT64)i;
	}

	Zero(&b, sizeof(b));
	b.Struct = &t;

	p = NewPack();
	OutRpcEnumSession(p, &t);
	b.Buf = PackToBuf(p);
	FreePack(p);

	Print("BENCH pack_enum_session_bytes %u bytes\n", b.Buf->Size);

	// The decoded struct is checked once, outside the measured runs
	SeekBufToBegin(b.Buf);
	p = BufToPack(b.Buf);
	if (p != NULL)
	{
		InRpcEnumSession(&t2, p);
		ok = (t2.NumSession == HARNESS_PACK_ITEMS && StrCmp(t2.Sessions[5].Name, t.Sessions[5].Name) == 0 &&
			t2.Sessions[5].PacketSize == t.Sessions[5].PacketSize);
		FreeRpcEnumSession(&t2);
		FreePack(p);
	}

	HarnessBenchOps("pack_encode_enum_session", HarnessOpEncodeEnumSession, &b, HARNESS_BENCH_PACK_SPAN, 16);
	if (ok)
	{
		HarnessBenchOps("pack_decode_enum_session", HarnessOpDecodeEnumSession, &b, HARNESS_BENCH_PACK_SPAN, 16);
	}
	HarnessCheck(h, ok, "Pack decode returns the encoded RPC_ENUM_SESSION");

	FreeBuf(b.Buf);
	FreeRpcEnumSession(&t);
}

// Pack with HARNESS_PACK_NAMES distinct element names (integers and strings), added in a non-sorted order
static PACK *HarnessNewNamesPack(HARNESS_PACK_BENCH *b)
{
	PACK *p = NewPack();
	UINT i;

	for (i = 0;i < HARNESS_PACK_NAMES;i++)
	{
		if ((i % 2) == 0)
		{
			PackAddInt(p, b->Names[i], i);
		}
		else
		{
			PackAddStr(p, b->Names[i], b->Names[i]);
		}
	}

	return p;
}

// Encode the many-names Pack: element adds -> BUF
static bool HarnessOpEncodeNames(void *param)
{
	HARNESS_PACK_BENCH *b = (HARNESS_PACK_BENCH *)param;
	PACK *p = HarnessNewNamesPack(b);
	BUF *buf = PackToBuf(p);

	FreePack(p);
	FreeBuf(buf);

	return true;
}

// Decode a Pack: BUF -> PACK
static bool HarnessOpDecodePack(void *param)
{
	HARNESS_PACK_BENCH *b = (HARNESS_PACK_BENCH *)param;
	PACK *p;

	SeekBufToBegin(b->Buf);
	p = BufToPack(b->Buf);
	if (p == NULL)
	{
		return false;
	}

	FreePack(p);

	return true;
}

// pack_<encode|decode>_names_<n>: a Pack with many distinct element names (every new name is looked up first)
static void HarnessBenchPackNames()
{
	HARNESS_PACK_BENCH b;
	PACK *p;
	UINT i;
	bool ok = false;
	char name[MAX_SIZE];

	Zero(&b, sizeof(b));
	b.Names = ZeroMalloc(sizeof(char *) * HARNESS_PACK_NAMES);
	for (i = 0;i < HARNESS_PACK_NAMES;i++)
	{
		char tmp[MAX_ELEMENT_NAME_LEN + 1];

		// 7919 is a prime: (i * 7919) % n takes every value below n once, in a non-sorted order
		Format(tmp, sizeof(tmp), "bench_item_%03u", (i * 7919) % HARNESS_PACK_NAMES);
		b.Names[i] = CopyStr(tmp);
	}

	p = HarnessNewNamesPack(&b);
	b.Buf = PackToBuf(p);
	FreePack(p);

	Print("BENCH pack_names_%u_bytes %u bytes\n", HARNESS_PACK_NAMES, b.Buf->Size);

	SeekBufToBegin(b.Buf);
	p = BufToPack(b.Buf);
	if (p != NULL)
	{
		ok = (LIST_NUM(p->elements) == HARNESS_PACK_NAMES && PackGetInt(p, b.Names[2]) == 2);
		FreePack(p);
	}

	Format(name, sizeof(name), "pack_encode_names_%u", HARNESS_PACK_NAMES);
	HarnessBenchOps(name, HarnessOpEncodeNames, &b, HARNESS_BENCH_PACK_SPAN, 1);

	Format(name, sizeof(name), "pack_decode_names_%u", HARNESS_PACK_NAMES);
	if (ok)
	{
		HarnessBenchOps(name, HarnessOpDecodePack, &b, HARNESS_BENCH_PACK_SPAN, 1);
	}
	else
	{
		Print("BENCH WARNING %s: the decoded Pack does not hold the encoded names, case skipped\n", name);
	}

	FreeBuf(b.Buf);
	for (i = 0;i < HARNESS_PACK_NAMES;i++)
	{
		Free(b.Names[i]);
	}
	Free(b.Names);
}

////////////////////////////
// ParsePacket and IP table benchmarks

// IPv4 frame from 10.0.0.1 (harness_mac_a) to 10.0.0.2 (harness_mac_b): a TCP header (PSH+ACK) or a UDP header
// from port 49152, then the payload, with valid IPv4, TCP and UDP checksums. Returns the size, 0 if it does not fit
static UINT HarnessBuildIpFrame(UCHAR *buf, UINT buf_size, UCHAR protocol, USHORT dst_port, UCHAR *payload, UINT payload_size)
{
	UINT l4_header = (protocol == IP_PROTO_TCP ? 20 : 8);
	UINT l4_size = l4_header + payload_size;
	UINT ip_size = 20 + l4_size;
	UINT size = 14 + ip_size;
	UCHAR *ip = buf + 14;
	UCHAR *l4 = ip + 20;
	UINT src_ip, dst_ip;
	USHORT sum;

	if (size > buf_size)
	{
		return 0;
	}

	Zero(buf, size);

	Copy(buf, harness_mac_b, 6);
	Copy(buf + 6, harness_mac_a, 6);
	buf[12] = 0x08;								// IPv4
	buf[13] = 0x00;

	ip[0] = 0x45;								// Version 4, 20-byte header
	ip[2] = (UCHAR)(ip_size >> 8);
	ip[3] = (UCHAR)(ip_size & 0xFF);
	ip[4] = 0x12;								// Identification
	ip[5] = 0x34;
	ip[6] = 0x40;								// Don't fragment
	ip[8] = 64;									// TTL
	ip[9] = protocol;
	ip[12] = 10;
	ip[15] = 1;
	ip[16] = 10;
	ip[19] = 2;
	sum = IpChecksum(ip, 20);
	Copy(ip + 10, &sum, sizeof(USHORT));

	l4[0] = 0xC0;								// Source port 49152
	l4[2] = (UCHAR)(dst_port >> 8);
	l4[3] = (UCHAR)(dst_port & 0xFF);

	if (protocol == IP_PROTO_TCP)
	{
		l4[5] = 0x01;							// Sequence number
		l4[9] = 0x02;							// Acknowledgment number
		l4[12] = 0x50;							// 20-byte header
		l4[13] = TCP_PSH | TCP_ACK;
		l4[14] = 0xFA;							// Window 64240
		l4[15] = 0xF0;
	}
	else
	{
		l4[4] = (UCHAR)(l4_size >> 8);
		l4[5] = (UCHAR)(l4_size & 0xFF);
	}

	Copy(l4 + l4_header, payload, payload_size);

	Copy(&src_ip, ip + 12, sizeof(UINT));
	Copy(&dst_ip, ip + 16, sizeof(UINT));
	sum = CalcChecksumForIPv4(src_ip, dst_ip, protocol, l4, l4_size, 0);
	Copy(l4 + (protocol == IP_PROTO_TCP ? 16 : 6), &sum, sizeof(USHORT));

	return size;
}

// TLS ClientHello with one cipher suite and only the server_name extension (the part GetSniNameFromSslPacket reads).
// Returns the size, 0 if it does not fit
static UINT HarnessBuildClientHello(UCHAR *buf, UINT buf_size, char *host)
{
	UINT name_len = StrLen(host);
	UINT ext_data = 2 + 1 + 2 + name_len;		// server_name_list length, name type, name length, name
	UINT ext_len = 4 + ext_data;				// Extension type and length, then its data
	UINT body = 43 + ext_len;					// Version 2, random 32, session id 1, ciphers 4, compression 2, extensions length 2
	UINT size = 5 + 4 + body;					// Record header, handshake header, ClientHello body
	UCHAR *p = buf;
	UINT i;

	if (size > buf_size)
	{
		return 0;
	}

	*p++ = 0x16;								// Handshake record, record version TLS 1.0
	*p++ = 0x03;
	*p++ = 0x01;
	*p++ = (UCHAR)((4 + body) >> 8);
	*p++ = (UCHAR)((4 + body) & 0xFF);
	*p++ = 0x01;								// ClientHello, 24-bit length
	*p++ = 0x00;
	*p++ = (UCHAR)(body >> 8);
	*p++ = (UCHAR)(body & 0xFF);
	*p++ = 0x03;								// Client version TLS 1.2
	*p++ = 0x03;
	for (i = 0;i < 32;i++)
	{
		*p++ = (UCHAR)(i * 11 + 1);				// Random
	}
	*p++ = 0x00;								// No session id
	*p++ = 0x00;								// One cipher suite: TLS_AES_128_GCM_SHA256
	*p++ = 0x02;
	*p++ = 0x13;
	*p++ = 0x01;
	*p++ = 0x01;								// Null compression only
	*p++ = 0x00;
	*p++ = (UCHAR)(ext_len >> 8);
	*p++ = (UCHAR)(ext_len & 0xFF);
	*p++ = 0x00;								// server_name extension
	*p++ = 0x00;
	*p++ = (UCHAR)(ext_data >> 8);
	*p++ = (UCHAR)(ext_data & 0xFF);
	*p++ = (UCHAR)((3 + name_len) >> 8);
	*p++ = (UCHAR)((3 + name_len) & 0xFF);
	*p++ = 0x00;								// host_name
	*p++ = (UCHAR)(name_len >> 8);
	*p++ = (UCHAR)(name_len & 0xFF);
	Copy(p, host, name_len);
	p += name_len;

	return (UINT)(p - buf);
}

// DNS query (recursion desired, one question, type A, class IN). Returns the size, 0 if it does not fit
static UINT HarnessBuildDnsQuery(UCHAR *buf, UINT buf_size, char *host)
{
	UINT len = StrLen(host);
	UINT start = 0;
	UINT i;
	UCHAR *p;

	if ((12 + len + 2 + 4) > buf_size)
	{
		return 0;
	}

	Zero(buf, 12);
	buf[0] = 0x52;								// Transaction id
	buf[1] = 0x41;
	buf[2] = 0x01;								// Recursion desired
	buf[5] = 0x01;								// One question

	p = buf + 12;
	for (i = 0;i <= len;i++)
	{
		if (i == len || host[i] == '.')
		{
			*p++ = (UCHAR)(i - start);
			Copy(p, host + start, i - start);
			p += i - start;
			start = i + 1;
		}
	}
	*p++ = 0x00;								// Root label
	*p++ = 0x00;								// Type A
	*p++ = 0x01;
	*p++ = 0x00;								// Class IN
	*p++ = 0x01;

	return (UINT)(p - buf);
}

// Parse a frame as HubPaPutPacket does with the default hub options: IP and HTTP parsing, BPDU bridge id,
// checksum correction (the frames have valid checksums, so the buffer is not changed)
static PKT *HarnessParseLikeHub(HARNESS_PARSE_FRAME *f)
{
	return ParsePacketEx4(f->Data, f->Size, false, 0, true, false, true);
}

// The parser reached the layer the frame was built for
static bool HarnessParsedAsBuilt(HARNESS_PARSE_FRAME *f, PKT *p)
{
	if (p == NULL)
	{
		return false;
	}

	if (StrCmp(f->Kind, "tcp") == 0)
	{
		return (p->TypeL4 == L4_TCP && p->HttpLog == NULL);
	}

	if (StrCmp(f->Kind, "http") == 0)
	{
		return (p->HttpLog != NULL && p->HttpLog->IsSsl == false && StrCmp(p->HttpLog->Hostname, HARNESS_BENCH_HOST) == 0);
	}

	if (StrCmp(f->Kind, "tls") == 0)
	{
		return (p->HttpLog != NULL && p->HttpLog->IsSsl && StrCmp(p->HttpLog->Hostname, HARNESS_BENCH_HOST) == 0);
	}

	if (StrCmp(f->Kind, "dns") == 0)
	{
		return (p->TypeL7 == L7_DNS && StrCmp(p->DnsQueryHost, HARNESS_BENCH_HOST) == 0);
	}

	return true;
}

// Parse the frame of a single-frame case
static bool HarnessOpParseOne(void *param)
{
	HARNESS_PARSE_BENCH *b = (HARNESS_PARSE_BENCH *)param;
	PKT *p = HarnessParseLikeHub(&b->Frames[b->Current]);

	if (p == NULL)
	{
		return false;
	}

	FreePacket(p);

	return true;
}

// Parse the next frame of the mix, in turn
static bool HarnessOpParseMix(void *param)
{
	HARNESS_PARSE_BENCH *b = (HARNESS_PARSE_BENCH *)param;
	PKT *p = HarnessParseLikeHub(&b->Frames[b->Next]);

	b->Next = (b->Next + 1) % HARNESS_NUM_PARSE_FRAMES;

	if (p == NULL)
	{
		return false;
	}

	FreePacket(p);

	return true;
}

// parse_packet_<kind>: ParsePacket per frame kind, then over the mix of all kinds in turn.
// l2: non-IP frame; tcp: TCP data without a layer 7 parser; http: request to TCP 80; tls: ClientHello with SNI
// to TCP 443; dns: query to UDP 53
static void HarnessBenchParse()
{
	HARNESS_PARSE_BENCH b;
	HARNESS_PARSE_FRAME *f;
	UCHAR payload[HARNESS_PARSE_FRAME_MAX];
	char *http = "GET /index.html HTTP/1.1\r\nHost: " HARNESS_BENCH_HOST "\r\nUser-Agent: ranz-bench/1.0\r\nAccept: */*\r\n\r\n";
	UINT i;
	UINT size;
	bool ok = true;
	char name[MAX_SIZE];

	Zero(&b, sizeof(b));

	f = &b.Frames[0];
	f->Kind = "l2";
	f->Size = HARNESS_FRAME_SIZE;
	HarnessBuildFrame(f->Data, f->Size, harness_mac_b, harness_mac_a, 1);

	f = &b.Frames[1];
	f->Kind = "tcp";
	for (i = 0;i < 64;i++)
	{
		payload[i] = (UCHAR)(i * 3);
	}
	f->Size = HarnessBuildIpFrame(f->Data, sizeof(f->Data), IP_PROTO_TCP, 5001, payload, 64);

	f = &b.Frames[2];
	f->Kind = "http";
	f->Size = HarnessBuildIpFrame(f->Data, sizeof(f->Data), IP_PROTO_TCP, 80, (UCHAR *)http, StrLen(http));

	f = &b.Frames[3];
	f->Kind = "tls";
	size = HarnessBuildClientHello(payload, sizeof(payload), HARNESS_BENCH_HOST);
	f->Size = HarnessBuildIpFrame(f->Data, sizeof(f->Data), IP_PROTO_TCP, 443, payload, size);

	f = &b.Frames[4];
	f->Kind = "dns";
	size = HarnessBuildDnsQuery(payload, sizeof(payload), HARNESS_BENCH_HOST);
	f->Size = HarnessBuildIpFrame(f->Data, sizeof(f->Data), IP_PROTO_UDP, 53, payload, size);

	for (i = 0;i < HARNESS_NUM_PARSE_FRAMES;i++)
	{
		PKT *p = NULL;

		f = &b.Frames[i];
		Format(name, sizeof(name), "parse_packet_%s", f->Kind);

		if (f->Size != 0)
		{
			p = HarnessParseLikeHub(f);
		}

		if (HarnessParsedAsBuilt(f, p))
		{
			b.Current = i;
			HarnessBenchOps(name, HarnessOpParseOne, &b, HARNESS_BENCH_MICRO_SPAN, 16);
		}
		else
		{
			Print("BENCH WARNING %s: the frame does not parse as built, case skipped\n", name);
			ok = false;
		}

		FreePacket(p);
	}

	if (ok)
	{
		HarnessBenchOps("parse_packet_mix", HarnessOpParseMix, &b, HARNESS_BENCH_MICRO_SPAN, 16);
	}
}

// ip_table_expire_<n>: microseconds of one DeleteExpiredIpTableEntry pass over an IP table of n entries,
// every second entry expired
static void HarnessBenchIpTableExpire(UINT num)
{
	UINT64 runs[HARNESS_BENCH_RUNS];
	UINT r, i;
	bool ok = true;
	char name[MAX_SIZE];

	Format(name, sizeof(name), "ip_table_expire_%u", num);

	for (r = 0;r < HARNESS_BENCH_RUNS;r++)
	{
		LIST *o = NewList(CompareIpTable);
		UINT64 now = Tick64();
		UINT64 start;

		for (i = 0;i < num;i++)
		{
			IP_TABLE_ENTRY *e = ZeroMalloc(sizeof(IP_TABLE_ENTRY));

			SetIP(&e->Ip, 10, (UCHAR)((i >> 16) & 0xFF), (UCHAR)((i >> 8) & 0xFF), (UCHAR)(i & 0xFF));
			e->MacAddress[0] = 0x02;
			e->MacAddress[4] = (UCHAR)((i >> 8) & 0xFF);
			e->MacAddress[5] = (UCHAR)(i & 0xFF);
			e->CreatedTime = now;
			// Expired entries were last updated more than IP_TABLE_EXPIRE_TIME ago. Unsigned arithmetic wraps
			// consistently, so this also holds when the machine has been up for less than that time
			e->UpdatedTime = ((i % 2) == 0 ? now - (UINT64)IP_TABLE_EXPIRE_TIME - 1000ULL : now);
			Insert(o, e);
		}

		start = HarnessNowNs();
		DeleteExpiredIpTableEntry(o);
		runs[r] = (HarnessNowNs() - start) / 1000ULL;

		if (LIST_NUM(o) != (num - (num + 1) / 2))
		{
			ok = false;
		}

		for (i = 0;i < LIST_NUM(o);i++)
		{
			Free(LIST_DATA(o, i));
		}
		ReleaseList(o);
	}

	HarnessBenchReport(name, runs, HARNESS_BENCH_RUNS, "us", false);

	if (ok == false)
	{
		Print("BENCH WARNING %s: the pass did not delete exactly the expired entries\n", name);
	}
}

////////////////////////////
// Entry points

// "harness": in-process server, two hubs, cascade, frames, vpncmd golden outputs and configuration round-trips
void harness_test(UINT num, char **arg)
{
	HARNESS *h = HarnessNew();
	HARNESS_WATCHDOG *wd = HarnessStartWatchdog("HARNESS", HARNESS_WATCHDOG_LIMIT);
	UINT64 start = Tick64();
	UINT64 elapsed;
	bool setup_ok;
	char tmp[MAX_SIZE];

	Print("Ranz harness: in-process server on TCP %u, hubs %s and %s, cascade, frames, golden outputs\n",
		HARNESS_PORT, HARNESS_HUB_A, HARNESS_HUB_B);

	setup_ok = HarnessSetup(h);

	if (setup_ok)
	{
		HarnessSetPhase("frames", NULL);
		HarnessFrames(h);
		HarnessGolden(h);
		HarnessSetPhase("config", NULL);
		HarnessConfigApiRoundTrip(h);
	}

	HarnessSetPhase("stop sessions", NULL);
	HarnessStopSessions(h);

	if (setup_ok)
	{
		HarnessSetPhase("reload", NULL);
		HarnessReload(h);
	}

	HarnessSetPhase("teardown", NULL);
	HarnessTeardown(h, setup_ok);

	elapsed = Tick64() - start;
	Format(tmp, sizeof(tmp), "runtime within the %u ms budget", HARNESS_RUNTIME_BUDGET);
	HarnessCheck(h, elapsed < HARNESS_RUNTIME_BUDGET, tmp);
	Print("TIME harness_runtime %I64u ms\n", elapsed);

	HarnessStopWatchdog(wd);

	if (h->NumFail == 0)
	{
		Print("HARNESS TEST OK\n");
	}
	else
	{
		Print("HARNESS TEST FAILED (%u failed checks)\n", h->NumFail);
	}

	HarnessFree(h);
}

// "bench": cascade path frames per second, in-process hub flood, Pack, ParsePacket and IP table expiry
// (informational, fails only on errors). Every case runs HARNESS_BENCH_RUNS times: the median, then every run
void bench_test(UINT num, char **arg)
{
	HARNESS *h = HarnessNew();
	HARNESS_WATCHDOG *wd = HarnessStartWatchdog("BENCH", HARNESS_BENCH_WATCHDOG);
	UINT64 start = Tick64();
	UINT64 elapsed;
	bool ok;

	Print("Ranz bench: %u runs per case (median, then every run); per run: cascade path %u ms per frame size, "
		"hub flood %u ms, Pack %u ms, ParsePacket %u ms, one IP table expiry pass\n",
		HARNESS_BENCH_RUNS, HARNESS_BENCH_SPAN, HARNESS_BENCH_FLOOD_SPAN, HARNESS_BENCH_PACK_SPAN,
		HARNESS_BENCH_MICRO_SPAN);

	ok = HarnessSetup(h);

	if (ok)
	{
		Print("[bench]\n");
		HarnessSetPhase("bench teach", NULL);
		ok = HarnessTeach(h);
	}

	if (ok)
	{
		HarnessSetPhase("bench_64", NULL);
		HarnessBenchFrames(h, 64);
		HarnessSetPhase("bench_512", NULL);
		HarnessBenchFrames(h, 512);
		HarnessSetPhase("bench_1500", NULL);
		HarnessBenchFrames(h, 1500);
		HarnessSetPhase("bench_flood", NULL);
		HarnessBenchFlood(h);
	}

	HarnessSetPhase("bench_pack", NULL);
	HarnessBenchPack(h);
	HarnessSetPhase("bench_pack_names", NULL);
	HarnessBenchPackNames();
	HarnessSetPhase("bench_parse", NULL);
	HarnessBenchParse();
	HarnessSetPhase("bench_ip_table", NULL);
	HarnessBenchIpTableExpire(1024);
	HarnessBenchIpTableExpire(4096);
	HarnessBenchIpTableExpire(16384);

	HarnessSetPhase("teardown", NULL);
	HarnessTeardown(h, ok);

	elapsed = Tick64() - start;
	Print("BENCH bench_runtime_ms %I64u ms\n", elapsed);

	// Informational like the numbers: the budget is reported, never failed
	if (elapsed >= HARNESS_BENCH_BUDGET)
	{
		Print("WARNING: bench runtime %I64u ms is over the %u ms budget\n", elapsed, HARNESS_BENCH_BUDGET);
	}

	HarnessStopWatchdog(wd);

	if (h->NumFail == 0)
	{
		Print("BENCH TEST OK\n");
	}
	else
	{
		Print("BENCH TEST FAILED (%u failed checks)\n", h->NumFail);
	}

	HarnessFree(h);
}
