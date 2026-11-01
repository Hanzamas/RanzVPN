// harness.c
// In-process server harness for vpntest: hubs, cascade, frames, golden outputs, benchmark
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
//   "HARNESS GOLDEN MODE update|compare" tells whether the golden file of the packet log was compared.
// - The admin RPC Pack goldens (golden family "pack", harness_pack.c) run right after the packet log
//   golden, while the sessions and the cascade are up. harness_int.h holds the shared types. They are the
//   golden outputs of the admin RPC since vpncmd and its golden outputs left with CORE-S8-1 (#84).
// - "bench" runs every case HARNESS_BENCH_RUNS times and prints "BENCH <name> <median> <unit>", then
//   "BENCH <name>_runs <run 1>,...,<run n> <unit>" in run order. Besides the cascade path it has in-process
//   cases without TLS, one per hot spot of spec #31: flood_fps_<n> (one session floods broadcast frames to
//   n sessions of hub HARNESS_FLOOD through the hub packet adapter, no SessionMain thread), flood_fps_logwait_<n>
//   (the same while another session of the hub waits for the log writer in the packet log back-pressure, CORE-F6),
//   parse_packet_<kind> (the parse of HubPaPutPacket; _nolog: hub packet log off), pack_<encode|decode>_names_<n> (a
//   Pack with n distinct element names), ip_table_expire_<n> (one DeleteExpiredIpTableEntry pass; ip_table_free_<n>:
//   freeing what it took out, which the hub does after its table lock since CORE-F6), ip_table_add_<n>
//   (frames from new source addresses into a hub IP table of n entries, CORE-F6) and accept_table_<n> (n first connections
//   from n distinct addresses to the DoS table of a listener, FND-127), fifo_cycle, queue_cycle and queue_burst_<n>
//   (a FIFO and a queue that never fully drain, a queue burst, FND-215). A wrong result of these cases prints a
//   "BENCH WARNING" line and skips the case; it does not fail the test.
// - Files left after a run: the server_log, security_log and packet_log folders (as in the "s"
//   mode). The configuration file and its backup folder are deleted at the start and at the end.
// - "listenerbind" (FIX-3 #99) adds listeners on TCP 39557 (held by the test) and 39558 through the admin
//   RPC and deletes them again; "certdl" runs its own loopback listener on TCP 39556.
// - "listeners" (REL-3 #48, listeners.c) keeps the default listener of the server, holds TCP 443 and 5555, and uses
//   TCP 39559 and 39560. Its case 6 (REL-4 #49) logs in to the test listener at an address of the machine that is not
//   loopback and puts back the $adminip.txt it changes.
// - Phase "zerokey" (SEC-6 #96) runs after the Pack goldens: CreateUser and SetUser refuse a password user
//   without a password hash, and the user it creates is deleted again before the configuration phases.
// - Phase "iptablelock" (SEC-6 #96, FND-11 #107) runs after "zerokey": while the test holds the MacHashTable lock of
//   hub HARNESS_HUB_A (the lock of the hub IP table), EnumIpTable and DeleteIpTable wait for it. Then session A sends
//   frames from new source addresses while the admin RPC lists and deletes the IP table entries, with MAX_IP_TABLES
//   lowered to HARNESS_IPTABLE_MAX. The entries left are deleted before the configuration phases.
//   The harness does not run under AddressSanitizer (fuzz-asan leaves it out for its time budgets): the lock-held
//   cases are the deterministic check, the stress loop runs in build_and_test.
// - Phase "setlink" (FND-13 #107) runs after "iptablelock": SetLink on an offline cascade HARNESS_SETLINK of hub
//   HARNESS_HUB_A refuses an unsupported authentication type and stores the cascade policy that NewLink stores. The
//   phase deletes the cascade again.
// - Phase "autodisconnect" (FND-221 #258) runs after "setlink": a user of hub HARNESS_HUB_A whose policy has
//   AutoDisconnect connects; the server session and the client session end at that time, and the client does not
//   reconnect. The phase deletes the user again.
// - Phase "adminreconnect" (FND-14 #107) runs after "setlink": a second admin RPC loses its connection
//   (DisconnectConnection through the first one), reconnects inside the next call and keeps no socket timeout.
//   The same phase calls AdminInvoke on a session that AdminOpen opened without a socket (FND-130 #142) and compares
//   its Pack with the one the admin RPC over the socket returns.
// - "adminaudit" (FND-10 #107) starts its own server with hub HARNESS_A and points the server's syslog (server log
//   and hub security log) at a loopback UDP receiver of the test. Each step is one admin RPC, then GetConfig, whose
//   LA_GET_CONFIG line ends the step: the lines before it are the audit lines of the call. The step also compares
//   ConfigRevision of the in-process server before and after.
// - The log cases of PKG-4 (#108) run after phase "adminreconnect" and restore every setting they change.
//   Syslog datagrams go to a loopback UDP socket of the test on an ephemeral port.

#include "harness_int.h"
#include "testlist.h"

#include "Cedar/Account.h"
#include "Cedar/Admin.h"
#include "Cedar/Cedar.h"
#include "Cedar/Connection.h"
#include "Cedar/Hub.h"
#include "Cedar/Listener.h"
#include "Cedar/HubLog.h"
#include "Cedar/LogWriter.h"
#include "Cedar/PacketLog.h"
#include "Cedar/Protocol.h"
#include "Cedar/Remote.h"
#include "Cedar/Sam.h"
#include "Cedar/Server.h"
#include "Cedar/Session.h"
#include "Cedar/Syslog.h"

#include "Mayaqua/Cfg.h"
#include "Mayaqua/Encrypt.h"
#include "Mayaqua/FileIO.h"
#include "Mayaqua/HTTP.h"
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

// Intermediate certificate download test ("certdl")
#define	CERTDL_PORT					39556				// Loopback listener named by the issuer URLs of the fixtures
#define	CERTDL_HOST					"127.0.0.1:39556"	// Host part of those URLs (CERTDL_PORT, not a scheme default)
#define	CERTDL_PATH					"/ranz-certdl/ca.cer"
#define	CERTDL_PATH_MOVED			"/ranz-certdl/moved.cer"	// Location of the redirect answer
#define	CERTDL_URL_HTTP				"http://" CERTDL_HOST CERTDL_PATH
#define	CERTDL_URL_HTTPS			"https://" CERTDL_HOST CERTDL_PATH
#define	CERTDL_MAX_BODY				65536				// CERT_HTTP_DOWNLOAD_MAXSIZE: body bytes the client reads at most
#define	CERTDL_BIG_LENGTH			1000000				// Content-Length of the over-cap answer
#define	CERTDL_TIMEOUT_MIN			9000				// CERT_HTTP_DOWNLOAD_TIMEOUT (10 s) less a margin
#define	CERTDL_QUICK_LIMIT			8000				// A run that never waits for the client timeout ends before this
#define	CERTDL_SLOW_LIMIT			25000				// A run that waits for the client timeout once ends before this
#define	CERTDL_CONN_TIMEOUT			30000				// Socket timeout of a listener connection
#define	CERTDL_WATCHDOG_LIMIT		120000				// "certdl" process aborted after this

// Answer of the certdl listener, one mode per run
#define	CERTDL_MODE_OK				0	// 200 with Content-Length and the issuer certificate in DER
#define	CERTDL_MODE_TLS				1	// TLS with a self-signed certificate that Windows does not trust, then as OK
#define	CERTDL_MODE_CONTINUE		2	// 100 Continue, then as OK
#define	CERTDL_MODE_REDIRECT		3	// 302 to CERTDL_PATH_MOVED; a later request of the run as OK
#define	CERTDL_MODE_NOT_FOUND		4	// 404
#define	CERTDL_MODE_AUTH			5	// 401 with Negotiate and NTLM challenges, to every request of the run
#define	CERTDL_MODE_NO_LENGTH		6	// 200 without Content-Length: the certificate, then close
#define	CERTDL_MODE_CHUNKED			7	// 200 with the certificate in one chunk
#define	CERTDL_MODE_OVER_CAP		8	// 200 with Content-Length CERTDL_BIG_LENGTH, then CERTDL_MAX_BODY bytes
										// (the certificate and zero padding) and nothing more
#define	CERTDL_MODE_SILENT			9	// No answer

// Bind status of ListenerCreate and ListenerEnable ("listenerbind", FIX-3 #99)
#define	LISTENBIND_PORT_HELD		39557				// Held by the test with the server's own bind: the server cannot bind it
#define	LISTENBIND_PORT_FREE		39558				// Free: the server binds it
#define	LISTENBIND_FORMER_SLEEP		250					// Fixed sleep of ListenerCreate and ListenerEnable before FIX-3
#define	LISTENBIND_CYCLES			3					// Disable and enable cycles on the free port (the fastest call is compared)
#define	LISTENBIND_RPC_LIMIT		(LISTENER_BIND_WAIT_TIME / 2)	// One listener RPC: a call that reaches the server's bind wait limit has missed the bind event
#define	LISTENBIND_RETRY_LIMIT		(LISTEN_RETRY_TIME * 3)	// A retrying listener binds a released port within this
#define	LISTENBIND_POLL				50					// ListenerList poll interval while waiting for that bind
#define	LISTENBIND_WATCHDOG_LIMIT	60000				// "listenerbind" process aborted after this

// Audit lines and configuration revision of the admin RPC handlers ("adminaudit", FND-10 #107)
#define	ADMINAUDIT_LOG_TIMEOUT		5000				// The GetConfig line that ends a step reaches the syslog receiver within this
#define	ADMINAUDIT_LINE_MAX			1024				// Longest syslog datagram (SendSysLog sends at most 1023 bytes)
#define	ADMINAUDIT_WATCHDOG_LIMIT	120000				// "adminaudit" process aborted after this
#define	ADMINAUDIT_USER				"audit_user"		// User that DeleteUser deletes
#define	ADMINAUDIT_NO_USER			"audit_nouser"		// No such user
#define	ADMINAUDIT_GROUP			"audit_group"		// Group that CreateGroup creates and DeleteGroup deletes
#define	ADMINAUDIT_GROUP2			"audit_group2"		// Group over the max_groups limit
#define	ADMINAUDIT_NO_SESSION		"AUDIT-NOSESSION"	// No such session
#define	ADMINAUDIT_NO_DEVICE		"audit_nodevice"	// No such Local Bridge device
#define	ADMINAUDIT_CRL_NAME			L"AUDITCRL"			// CommonName of the CRL entry
#define	ADMINAUDIT_CRL_NAME_A		"AUDITCRL"			// The same in the configuration file

// Limits
#define	HARNESS_QUEUE_HIGH			256					// Frames kept queued by the bench sender
#define	HARNESS_QUEUE_LOW			64					// Sender wakes up below this
#define	HARNESS_MAX_RECORD			64					// Recorded frames per test session
#define	HARNESS_DIFF_MAX_LINES		1000				// Larger texts only report the first difference
#define	HARNESS_DIFF_CONTEXT		2					// Context lines around a difference
#define	HARNESS_PACK_ITEMS			32					// Sessions in the Pack benchmark struct
#define	HARNESS_BENCH_RUNS			5					// Runs per bench case: the median and every run are printed
#define	HARNESS_FLOOD_BATCH			32					// Frames the flood sender stores per receive loop
#define	HARNESS_LOGWAIT_BACKLOG		PACKET_LOG_WAIT_RECORDS	// Queued packet log records of a session from which PacketLog makes it wait
#define	HARNESS_LOGWAIT_DELAY		20					// flood_fps_logwait floods this long (ms) into that wait of up to 250 ms
#define	HARNESS_IPTABLE_ADD_BATCH	1024				// New source addresses per run of an ip_table_add case
#define	HARNESS_PACK_NAMES			500					// Distinct element names of the many-names Pack case
#define	HARNESS_PARSE_FRAME_MAX		512					// Buffer of one ParsePacket bench frame
#define	HARNESS_NUM_PARSE_FRAMES	5					// ParsePacket bench frames: l2, tcp, http, tls, dns
#define	HARNESS_FIFO_BACKLOG		1000				// Standing bytes of the fifo_cycle case
#define	HARNESS_FIFO_CYCLE			3000				// Bytes written, then read, per fifo_cycle operation
#define	HARNESS_QUEUE_BACKLOG		1000				// Standing items of the queue_cycle case
#define	HARNESS_QUEUE_BURST			4096				// Items inserted, then taken, per queue_burst operation

// Time units of the high-resolution bench clock
#define	HARNESS_NS_PER_MS			1000000ULL
#define	HARNESS_NS_PER_S			1000000000ULL

// Normalised placeholder
#define	HARNESS_TAG_NUMBER			"<N>"

// User of phase "zerokey" on hub HARNESS_HUB_A (deleted again by the phase)
#define	HARNESS_ZEROKEY_USER		"zerokey"

// Phase "iptablelock" on hub HARNESS_HUB_A
#define	HARNESS_IPTABLE_HOLD		500					// A lock-held admin RPC must still wait after this (ms)
#define	HARNESS_IPTABLE_RETURN		5000				// It returns within this after the unlock (ms)
#define	HARNESS_IPTABLE_MAX			64					// MAX_IP_TABLES of the stress loop: the hub evicts on every new address
#define	HARNESS_IPTABLE_ROUNDS		20					// EnumIpTable and DeleteIpTable rounds of the stress loop
#define	HARNESS_IPTABLE_SPAN		3000				// The stress loop ends after this even with rounds left (ms)
#define	HARNESS_IPTABLE_PORT		9					// UDP destination port of the stress frames (discard)

// Phase "setlink" on hub HARNESS_HUB_A (the cascade is offline and deleted again by the phase)
#define	HARNESS_SETLINK_NAME		L"HARNESS_SETLINK"
#define	HARNESS_SETLINK_AUTHTYPE	99					// No CLIENT_AUTHTYPE_* value

// Phase "autodisconnect" on hub HARNESS_HUB_A (the user is deleted again by the phase)
#define	HARNESS_AUTODISC_USER		"autodisconnect"
#define	HARNESS_AUTODISC_SECONDS	2					// Policy AutoDisconnect of the user
#define	HARNESS_AUTODISC_LATE		3000				// The server session has ended within this after that time (ms)
#define	HARNESS_AUTODISC_IDLE		2000				// Then the client session has stopped within this (ms)
#define	HARNESS_AUTODISC_POLL		50					// EnumSession and client status poll interval (ms)

// Ethernet frame owned by the test packet adapter
typedef struct HARNESS_FRAME
{
	UCHAR *Data;
	UINT Size;
} HARNESS_FRAME;

// Watchdog of one test: a deadlock in the code under test fails the test instead of hanging the CI job
typedef struct HARNESS_WATCHDOG
{
	char *TestName;				// Marker prefix: HARNESS or BENCH
	UINT Limit;					// Milliseconds before the process is aborted
	EVENT *Done;				// Set when the test completes
	THREAD *Thread;				// Watchdog thread
} HARNESS_WATCHDOG;

// Loopback listener of "certdl": serves the issuer certificate that the fixture server certificates name
typedef struct CERTDL_SERVER
{
	SOCK *ListenSock;			// 127.0.0.1:CERTDL_PORT
	THREAD *AcceptThread;		// Accepts connections until ListenSock is disconnected
	LIST *ConnList;				// CERTDL_CONN *, joined when the listener stops
	BUF *CaDer;					// Issuer certificate served (DER)
	X *TlsCert;					// Certificate of CERTDL_MODE_TLS (not owned)
	K *TlsKey;					// Its private key (not owned)
	LOCK *Lock;					// Guards the fields below
	UINT Mode;					// CERTDL_MODE_* of the current run
	UINT NumRequests;			// Requests received in the current run
	char RequestLine[MAX_SIZE];	// Request line of the first request of the run
	char Host[MAX_SIZE];		// Host header of that request
	char UserAgent[MAX_SIZE];	// User-Agent header of that request
} CERTDL_SERVER;

// One connection accepted by the certdl listener
typedef struct CERTDL_CONN
{
	CERTDL_SERVER *Server;
	SOCK *Sock;
	THREAD *Thread;
} CERTDL_CONN;

// Outcome of one SetServerCert call
typedef struct CERTDL_RESULT
{
	UINT Err;					// Error code of the admin RPC
	UINT Flag1;					// 1: the server built the chain up to a root (0: SM_CERT_NEED_ROOT for an admin client)
	UINT64 Elapsed;				// Duration of the admin RPC (ms)
	UINT NumRequests;			// Requests the listener received
	char RequestLine[MAX_SIZE];	// Request line of the first request
	char Host[MAX_SIZE];		// Host header of the first request
	char UserAgent[MAX_SIZE];	// User-Agent header of the first request
	bool Saved;					// The server saved the downloaded issuer under chain_certs
} CERTDL_RESULT;

// One admin RPC of phase "iptablelock", run on a worker thread while the test may hold the MacHashTable lock
typedef struct HARNESS_IPTABLE_CALL
{
	HARNESS *H;
	UINT Which;					// 0: EnumIpTable, 1: DeleteIpTable of a key that does not exist
	UINT Err;					// Error code of the call
	EVENT *Done;				// Set when the call returned
} HARNESS_IPTABLE_CALL;

// Sender of the "iptablelock" stress loop: IPv4 frames of session A, each from a new source address
typedef struct HARNESS_IPTABLE_SENDER
{
	HARNESS_PA *Pa;				// Session A
	volatile bool Halt;			// Set by the test to stop the sender
} HARNESS_IPTABLE_SENDER;

// State of "adminaudit": the server sends its server log and the hub security logs to a syslog receiver of the test
typedef struct ADMINAUDIT
{
	HARNESS *H;
	SOCK *Udp;					// Syslog receiver on 127.0.0.1
	char *Marker;				// Text of LA_GET_CONFIG (UTF-8): the GetConfig call that ends a step logs it
	LIST *Lines;				// char *: the syslog lines of the current step (UTF-8)
	UINT Revision;				// ConfigRevision of the server when the step began
} ADMINAUDIT;

// Current phase of the test, read by the watchdog thread (static strings only)
static char *volatile harness_phase = "start";
static char *volatile harness_phase_detail = "";

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

static void HarnessStep(HARNESS *h, UINT err, char *what, bool check);
static bool HarnessExpectErr(HARNESS *h, UINT err, UINT expected, char *what);
static void HarnessWatchdogThread(THREAD *thread, void *param);
static HARNESS_WATCHDOG *HarnessStartWatchdog(char *test_name, UINT limit);
static void HarnessStopWatchdog(HARNESS_WATCHDOG *w);
static char *HarnessSkipBom(char *s);
static LIST *HarnessSplitLines(char *text);
static void HarnessFreeLines(LIST *o);
static bool HarnessTextEqual(char *a, char *b);
static void HarnessPrintDiff(char *name, char *expected, char *actual);
static void HarnessBuildFrame(UCHAR *buf, UINT size, const UCHAR *dst, const UCHAR *src, UINT seq);
static bool HarnessPaInit(SESSION *s);
static CANCEL *HarnessPaGetCancel(SESSION *s);
static UINT HarnessPaGetNextPacket(SESSION *s, void **data);
static bool HarnessPaPutPacket(SESSION *s, void *data, UINT size);
static void HarnessPaFree(SESSION *s);
static HARNESS_PA *HarnessNewPa(const char *name);
static void HarnessClearRecv(HARNESS_PA *p);
static void HarnessFreePa(HARNESS_PA *p);
static void HarnessPaSend(HARNESS_PA *p, const UCHAR *frame, UINT size);
static bool HarnessPaWaitRecv(HARNESS_PA *p, UINT num, UINT timeout);
static UINT HarnessPaNumRecorded(HARNESS_PA *p);
static bool HarnessPaFrameIs(HARNESS_PA *p, UINT index, const UCHAR *expected, UINT size);
static UINT64 HarnessPaGetNumRecv(HARNESS_PA *p);
static UINT HarnessPaQueued(HARNESS_PA *p);
static void HarnessPaDrain(HARNESS_PA *p, UINT timeout);
static UINT HarnessPaPurge(HARNESS_PA *p);
static bool HarnessStartSession(HARNESS *h, HARNESS_PA *p, const char *hubname, char *username);
static void HarnessStopSession(HARNESS_PA *p);
static void HarnessStopSessions(HARNESS *h);
static bool HarnessWaitListener(HARNESS *h, UINT timeout);
static RPC *HarnessAdminConnect(CEDAR *cedar, UINT timeout, UINT *err);
static bool HarnessUseOnlyTestListener(HARNESS *h);
static bool HarnessCreateHub(HARNESS *h, char *name);
static bool HarnessCreateUser(HARNESS *h, char *hubname, char *username, const wchar_t *realname);
static bool HarnessCreateLink(HARNESS *h);
static bool HarnessWaitLink(HARNESS *h, UINT timeout);
static bool HarnessWaitSessionListed(HARNESS *h, char *hubname, char *username, bool link_mode, char *name, UINT name_size);
static bool HarnessWaitSession(HARNESS *h, HARNESS_PA *p, UINT timeout);
static bool HarnessSetup(HARNESS *h);
static bool HarnessCheckMac(HARNESS *h, char *hubname, const UCHAR *mac, char *session_name);
static bool HarnessTeach(HARNESS *h);
static bool HarnessFrames(HARNESS *h);
static void HarnessGetDirs(char *out_dir, UINT out_size, char *golden_dir, UINT golden_size, bool *update);
static bool HarnessIsVolatileConfigName(const char *name, bool is_uint64);
static char *HarnessNormalizeConfig(char *text);
static bool HarnessCompareConfig(HARNESS *h, char *what, char *text1, char *text2);
static void HarnessConfigApiRoundTrip(HARNESS *h);
static void HarnessReload(HARNESS *h);
static void HarnessZeroKeyDelete(HARNESS *h, char *what);
static void HarnessZeroKeyUser(HARNESS *h);
static void HarnessIpTableLockThread(THREAD *thread, void *param);
static bool HarnessIpTableLockCase(HARNESS *h, HUB *hub, UINT which, UINT expected, char *what);
static void HarnessIpTableSendThread(THREAD *thread, void *param);
static bool HarnessIpTableRound(HARNESS *h, UINT *num_listed, UINT *num_deleted, UINT *bad_err);
static void HarnessIpTableLock(HARNESS *h);
static UINT HarnessSetLinkGet(HARNESS *h, RPC_CREATE_LINK *t);
static void HarnessSetLinkAuthType(HARNESS *h);
static void HarnessSetLinkPolicy(HARNESS *h);
static void HarnessSetLink(HARNESS *h);
static void HarnessAutoDisconnect(HARNESS *h);
static bool HarnessFindAdminConnection(HARNESS *h, UINT port, char *name, UINT name_size);
static void HarnessAdminReconnect(HARNESS *h);
static void HarnessAdminInvoke(HARNESS *h);
static void HarnessDeleteObjects(HARNESS *h, bool check);
static void HarnessDeleteConfigFiles();
static void HarnessTeardown(HARNESS *h, bool check);
static HARNESS *HarnessNew();
static void HarnessFree(HARNESS *h);
static UINT64 HarnessNowNs();
static void HarnessBenchValue(char *str, UINT size, UINT64 value, bool centi);
static void HarnessBenchReport(char *name, const UINT64 *runs, UINT num, char *unit, bool centi);
static bool HarnessBenchOps(char *name, HARNESS_BENCH_OP *op, void *param, UINT span, UINT check_every);
static void HarnessBenchFrames(HARNESS *h, UINT size);
static void HarnessFloodIdleThread(THREAD *thread, void *param);
static SESSION *HarnessNewFloodSession(HUB *hub, THREAD *thread, UINT index, bool sender);
static void HarnessFreeFloodSession(SESSION *s);
static UINT64 HarnessFloodBatch(SESSION *sender, SESSION **recv, UINT num_recv, const UCHAR *frame, UINT size);
static void HarnessBenchFloodCase(HUB *hub, UINT num_recv);
static void HarnessLogWaitThread(THREAD *thread, void *param);
static void HarnessBenchFloodLogWaitCase(HUB *hub, UINT num_recv);
static void HarnessIpTableAddFrame(SESSION *s, UCHAR *frame, UINT size, UINT index);
static void HarnessBenchIpTableAdd(HUB *hub, UINT num);
static void HarnessBenchFlood(HARNESS *h);
static bool HarnessOpEncodeEnumSession(void *param);
static bool HarnessOpDecodeEnumSession(void *param);
static void HarnessBenchPack(HARNESS *h);
static PACK *HarnessNewNamesPack(const HARNESS_PACK_BENCH *b);
static bool HarnessOpEncodeNames(void *param);
static bool HarnessOpDecodePack(void *param);
static void HarnessBenchPackNames();
static UINT HarnessBuildIpFrame(UCHAR *buf, UINT buf_size, UCHAR protocol, USHORT dst_port, UCHAR *payload, UINT payload_size);
static UINT HarnessBuildClientHello(UCHAR *buf, UINT buf_size, const char *host);
static UINT HarnessBuildDnsQuery(UCHAR *buf, UINT buf_size, char *host);
static PKT *HarnessParseLikeHub(HARNESS_PARSE_FRAME *f, bool no_log);
static bool HarnessParsedAsBuilt(const HARNESS_PARSE_FRAME *f, const PKT *p, bool no_log);
static bool HarnessOpParseOne(void *param);
static bool HarnessOpParseMix(void *param);
static void HarnessBenchParse();
static void HarnessBenchIpTableExpire(UINT num);
static void HarnessBenchAcceptTable(UINT num);
static bool HarnessOpFifoCycle(void *param);
static bool HarnessOpQueueCycle(void *param);
static bool HarnessOpQueueBurst(void *param);
static void HarnessBenchFifo();
static bool HarnessStartServer(HARNESS *h);
static void HarnessStopServer(HARNESS *h);
static X *CertDlPemToX(const char *pem);
static K *CertDlPemToK(const char *pem);
static void CertDlSavedPath(wchar_t *path, UINT size, X *issuer);
static UINT CertDlRecord(CERTDL_SERVER *srv, HTTP_HEADER *h);
static void CertDlWriteStr(BUF *b, const char *str);
static void CertDlWriteOk(const CERTDL_SERVER *srv, BUF *b);
static bool CertDlRespond(const CERTDL_SERVER *srv, SOCK *s, UINT mode, UINT num);
static void CertDlConnThread(THREAD *thread, void *param);
static void CertDlAcceptThread(THREAD *thread, void *param);
static CERTDL_SERVER *CertDlStartServer(X *issuer, X *tls_cert, K *tls_key);
static void CertDlStopServer(CERTDL_SERVER *srv);
static void CertDlRun(HARNESS *h, CERTDL_SERVER *srv, char *name, UINT mode, X *cert, K *key, wchar_t *saved_file,
	CERTDL_RESULT *r);
static bool CertDlCheckUint(HARNESS *h, char *what, UINT actual, UINT expected);
static bool CertDlCheckStr(HARNESS *h, char *what, char *actual, char *expected);
static void CertDlExpect(HARNESS *h, char *name, const CERTDL_RESULT *r, bool chain, bool waits);
static bool ListenBindState(HARNESS *h, UINT port, bool *enabled, bool *error);
static UINT ListenBindCall(HARNESS *h, bool create, UINT port, bool enable, UINT64 *elapsed);
static bool ListenBindExpect(HARNESS *h, char *name, char *what, UINT err, UINT expected, UINT64 elapsed);
static bool ListenBindIsListening(HARNESS *h, UINT port, char *what);
static bool AdminAuditCollect(ADMINAUDIT *a, UINT timeout);
static bool AdminAuditSync(ADMINAUDIT *a);
static void AdminAuditBegin(ADMINAUDIT *a);
static bool AdminAuditLogged(ADMINAUDIT *a, wchar_t *text);
static void AdminAuditEnd(ADMINAUDIT *a, char *what, UINT err, UINT expected, wchar_t *logged, wchar_t *not_logged,
	bool bumped);
static wchar_t *AdminAuditText(wchar_t *buf, UINT size, char *name, char *arg1, char *arg2);
static void AdminAuditFree(ADMINAUDIT *a);
static ADMINAUDIT *AdminAuditNew(HARNESS *h);
static void AdminAuditUsers(ADMINAUDIT *a);
static UINT AdminAuditCreateGroup(const ADMINAUDIT *a, const char *name);
static bool AdminAuditMaxGroups(ADMINAUDIT *a);
static void AdminAuditGroups(ADMINAUDIT *a);
static CRL *AdminAuditNewCrl();
static bool AdminAuditCrlKey(ADMINAUDIT *a, UINT *key);
static void AdminAuditCheckSaved(ADMINAUDIT *a, bool expected, char *what);
static void AdminAuditCrl(ADMINAUDIT *a);
static void AdminAuditSession(ADMINAUDIT *a, char *session);
static void AdminAuditBridge(ADMINAUDIT *a);
static void AdminAuditAddCa(ADMINAUDIT *a, X *x, char *what, bool added);
static void AdminAuditCa(ADMINAUDIT *a);

////////////////////////////
// Reporting and text helpers

// Check the result of an admin RPC call
bool HarnessCheckErr(HARNESS *h, UINT err, char *what)
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

// Check that an admin RPC call returned the expected error code
static bool HarnessExpectErr(HARNESS *h, UINT err, UINT expected, char *what)
{
	char tmp[MAX_SIZE];

	if (err == expected)
	{
		Format(tmp, sizeof(tmp), "%s: error %u", what, err);
	}
	else
	{
		Format(tmp, sizeof(tmp), "%s: error %u (%S), expected %u (%S)", what, err, _E(err), expected, _E(expected));
	}

	return HarnessCheck(h, err == expected, tmp);
}

////////////////////////////
// Watchdog

// Record the current phase for the watchdog message (phase and detail must be static strings)
void HarnessSetPhase(char *phase, char *detail)
{
	harness_phase_detail = (detail != NULL ? detail : "");
	harness_phase = phase;
}

// Watchdog thread: abort the process when the test does not complete within the limit
static void HarnessWatchdogThread(THREAD *thread, void *param)
{
	HARNESS_WATCHDOG *w = (HARNESS_WATCHDOG *)param;

	if (w == NULL)
	{
		return;
	}

	if (Wait(w->Done, w->Limit))
	{
		return;
	}

	char *phase = harness_phase;
	char *detail = harness_phase_detail;

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
char *HarnessUniToUtf8(wchar_t *s)
{
	if (s == NULL)
	{
		return CopyStr("");
	}

	UINT size = CalcUniToUtf8(s);
	char *ret = ZeroMalloc(size + 1);
	UniToUtf8((BYTE *)ret, size + 1, s);

	return ret;
}

////////////////////////////
// Test packet adapter (the same PACKET_ADAPTER contract Link.c uses for a cascade client session)
// Test sessions are TCP client sessions, not in-process server sessions: bench = 3 TLS hops

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
static HARNESS_PA *HarnessNewPa(const char *name)
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
	Lock(p->Lock);
	{
		for (UINT i = 0;i < LIST_NUM(p->RecvList);i++)
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
static void HarnessPaSend(HARNESS_PA *p, const UCHAR *frame, UINT size)
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
		if (HarnessPaNumRecorded(p) >= num)
		{
			return true;
		}

		UINT64 now = Tick64();
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
static bool HarnessPaFrameIs(HARNESS_PA *p, UINT index, const UCHAR *expected, UINT size)
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
static bool HarnessStartSession(HARNESS *h, HARNESS_PA *p, const char *hubname, char *username)
{
	CLIENT_OPTION o;
	CLIENT_AUTH a;

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

	PACKET_ADAPTER *pa = NewPacketAdapter(HarnessPaInit, HarnessPaGetCancel, HarnessPaGetNextPacket,
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
		SiLockListenerList(h->Server);
		{
			for (UINT i = 0;i < LIST_NUM(h->Server->ServerListenerList);i++)
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

// Connect the admin RPC as an admin client does (empty password of a fresh configuration), retrying until timeout
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
	bool ok = true;
	char tmp[MAX_SIZE];

	Zero(&t, sizeof(t));
	UINT err = ScEnumListener(h->Rpc, &t);
	if (HarnessCheckErr(h, err, "EnumListener") == false)
	{
		return false;
	}

	for (UINT i = 0;i < t.NumPort;i++)
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
static bool HarnessCreateUser(HARNESS *h, char *hubname, char *username, const wchar_t *realname)
{
	RPC_SET_USER t;
	char tmp[MAX_SIZE];

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), hubname);
	StrCpy(t.Name, sizeof(t.Name), username);
	UniStrCpy(t.Realname, sizeof(t.Realname), realname);
	UniStrCpy(t.Note, sizeof(t.Note), L"ranz harness");
	t.AuthType = AUTHTYPE_PASSWORD;
	t.AuthData = NewPasswordAuthData(username, HARNESS_PASSWORD);

	UINT err = ScCreateUser(h->Rpc, &t);
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

	UINT err = ScCreateLink(h->Rpc, &t);
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
	UINT err;
	char tmp[MAX_SIZE];

	Zero(&k, sizeof(k));
	StrCpy(k.HubName, sizeof(k.HubName), HARNESS_HUB_A);
	UniStrCpy(k.AccountName, sizeof(k.AccountName), HARNESS_LINK_NAME);

	if (HarnessCheckErr(h, ScSetLinkOnline(h->Rpc, &k), "SetLinkOnline HARNESS_CASCADE") == false)
	{
		return false;
	}

	UINT64 start = Tick64();
	UINT64 end = start + (UINT64)timeout;

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
		for (UINT i = 0;i < e.NumLink;i++)
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
bool HarnessFindSession(HARNESS *h, char *hubname, char *username, bool link_mode, char *name, UINT name_size)
{
	RPC_ENUM_SESSION t;
	bool ret = false;

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), hubname);

	if (ScEnumSession(h->Rpc, &t) != ERR_NO_ERROR)
	{
		return false;
	}

	for (UINT i = 0;i < t.NumSession;i++)
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

// Start the server from its configuration file HARNESS_CONFIG_FILE, deleted first when fresh is true, add the test
// listener unless the configuration lists it, and connect the admin RPC. The other listeners stay. A run that
// started the server this way stops it with HarnessStopServerKeep or HarnessStopServer.
bool HarnessStartServerKeep(HARNESS *h, bool fresh)
{
	UINT err = ERR_NO_ERROR;
	bool ok;
	char tmp[MAX_SIZE];

	HarnessSetPhase("setup", "server start");

	// Isolated configuration file; the name before the run is kept once, for HarnessStopServer
	if (h->OldConfigName == NULL)
	{
		h->OldConfigName = SERVER_CONFIG_FILE_NAME;
	}
	SERVER_CONFIG_FILE_NAME = HARNESS_CONFIG_FILE;
	if (fresh)
	{
		HarnessDeleteConfigFiles();
	}

	h->ClientCedar = NewCedar(NULL, NULL);

	// Same server object as the "s" mode (StStartServer is a wrapper of SiNewServer)
	h->Server = SiNewServer();
	if (HarnessCheck(h, h->Server != NULL, fresh ? "server started in-process from a fresh " HARNESS_CONFIG_FILE :
		"server started in-process from the saved " HARNESS_CONFIG_FILE) == false)
	{
		return false;
	}

	// The admin RPC needs a listener: add the test listener through the server API.
	// DoS protection is off on it because the harness opens many local connections in a short time.
	// A configuration that an earlier start of the run saved lists it already.
	SiLockListenerList(h->Server);
	{
		ok = (SiGetListener(h->Server, HARNESS_PORT) != NULL || SiAddListenerEx(h->Server, HARNESS_PORT, true, true));
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

	return HarnessCheckErr(h, (h->Rpc != NULL ? ERR_NO_ERROR : err), tmp);
}

// Start the server from a fresh configuration, add the test listener, connect the admin RPC and delete
// every other listener
static bool HarnessStartServer(HARNESS *h)
{
	return HarnessStartServerKeep(h, true) && HarnessUseOnlyTestListener(h);
}

// Start the server, the test listener, the admin RPC, the hubs, the users, the cascade and the test sessions
static bool HarnessSetup(HARNESS *h)
{
	char name[MAX_SESSION_NAME_LEN + 1];

	Print("[setup]\n");

	if (HarnessStartServer(h) == false)
	{
		return false;
	}

	HarnessSetPhase("setup", "hubs, users, cascade");
	bool ok = HarnessCreateHub(h, HARNESS_HUB_A) &&
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
static bool HarnessCheckMac(HARNESS *h, char *hubname, const UCHAR *mac, char *session_name)
{
	RPC_ENUM_MAC_TABLE t;
	bool found = false;
	char mac_str[64];
	char got[MAX_SESSION_NAME_LEN + 1];
	char tmp[MAX_SIZE];

	MacToStr(mac_str, sizeof(mac_str), mac);
	got[0] = 0;

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), hubname);

	UINT err = ScEnumMacTable(h->Rpc, &t);
	if (err != ERR_NO_ERROR)
	{
		Format(tmp, sizeof(tmp), "EnumMacTable %s", hubname);
		return HarnessCheckErr(h, err, tmp);
	}

	for (UINT i = 0;i < t.NumMacTable;i++)
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

	HarnessBuildFrame(teach_b, sizeof(teach_b), harness_mac_broadcast, harness_mac_b, 1);
	HarnessBuildFrame(teach_a, sizeof(teach_a), harness_mac_broadcast, harness_mac_a, 2);

	HarnessPaSend(h->PaB, teach_b, sizeof(teach_b));
	bool ok = HarnessCheck(h, HarnessPaWaitRecv(h->PaA, 1, HARNESS_FRAME_TIMEOUT) &&
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

	Print("[frames]\n");

	bool ok = HarnessTeach(h);

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
	UINT num_a = HarnessPaNumRecorded(h->PaA);
	UINT num_b = HarnessPaNumRecorded(h->PaB);
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
// Golden files

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

////////////////////////////
// Configuration round-trips

// Configuration items normalised before a comparison
static bool HarnessIsVolatileConfigName(const char *name, bool is_uint64)
{
	// Timestamps: CreatedTime, UpdatedTime, LastCommTime, LastLoginTime, ExpireTime
	if (is_uint64 && EndWith(name, "Time"))
	{
		return true;
	}

	for (UINT i = 0;i < sizeof(harness_config_volatile_names) / sizeof(harness_config_volatile_names[0]);i++)
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

	for (UINT i = 0;i < LIST_NUM(lines);i++)
	{
		char *line = LIST_DATA(lines, i);
		UINT indent = 0;
		bool replaced = false;

		while (line[indent] == '\t' || line[indent] == ' ')
		{
			indent++;
		}

		TOKEN_LIST *t = ParseToken(line + indent, " \t");
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

	char *ret = HarnessBufToStr(b);
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

	Format(tmp, sizeof(tmp), "%s: normalised configuration texts are equal", what);
	bool ok = HarnessCheck(h, HarnessTextEqual(n1, n2), tmp);
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

	Print("[config: Cfg API round-trip]\n");

	Zero(&c, sizeof(c));
	UINT err = ScGetConfig(h->Rpc, &c);
	if (HarnessCheckErr(h, err, "GetConfig") == false)
	{
		return;
	}

	BUF *b = NewBuf();
	WriteBuf(b, c.FileData, StrLen(c.FileData));
	SeekBufToBegin(b);
	FOLDER *root = CfgBufTextToFolder(b);
	FreeBuf(b);

	if (HarnessCheck(h, root != NULL, "configuration text parsed by CfgBufTextToFolder"))
	{
		BUF *b2 = CfgFolderToBuf(root);
		char *text2 = HarnessBufToStr(b2);

		HarnessCompareConfig(h, "config_cfg_api_roundtrip", c.FileData, text2);

		Free(text2);
		FreeBuf(b2);
		CfgDeleteFolder(root);
	}

	// SetConfig parses the upload with require_closed (FND-94): the saved text passes, a truncated copy
	// fails, and garbage gives ERR_INVALID_PARAMETER without a reboot
	b = NewBufFromMemory(c.FileData, StrLen(c.FileData));
	root = CfgBufToFolder(b, true);
	HarnessCheck(h, root != NULL, "saved configuration passes the SetConfig parse");
	CfgDeleteFolder(root);
	FreeBuf(b);
	b = NewBufFromMemory(c.FileData, StrLen(c.FileData) / 2);
	root = CfgBufToFolder(b, true);
	HarnessCheck(h, root == NULL, "truncated configuration fails the SetConfig parse");
	CfgDeleteFolder(root);
	FreeBuf(b);
	FreeRpcConfig(&c);

	Zero(&c, sizeof(c));
	c.FileData = CopyStr("garbage");
	HarnessExpectErr(h, ScSetConfig(h->Rpc, &c), ERR_INVALID_PARAMETER, "SetConfig of garbage");

	FreeRpcConfig(&c);
}

// The machine identity of the server and the MAC address and address of hub HARNESS_HUB_A (FIX-5, #101)
static bool HarnessGetMachineId(HARNESS *h, UCHAR *id, UCHAR *hub_mac, IP *hub_ip)
{
	GenerateMachineUniqueHash(h->Server->Cedar, id);

	HUB *hub = GetHub(h->Server->Cedar, HARNESS_HUB_A);
	if (hub == NULL)
	{
		return false;
	}

	Copy(hub_mac, hub->HubMacAddr, sizeof(hub->HubMacAddr));
	Copy(hub_ip, &hub->HubIp, sizeof(IP));

	ReleaseHub(hub);

	return true;
}

// HUBIP: the hub MAC address and address computed independently from the machine identity and the hub
// name; the address takes the last octet from the second hash byte (FND-145, #147)
static void HarnessCheckHubAddr(HARNESS *h, const UCHAR *id, const UCHAR *hub_mac, IP *hub_ip)
{
	char tmp[MAX_SIZE];
	UCHAR hash[SHA1_SIZE];
	UCHAR mac[6];
	IP ip;

	BinToStr(tmp, sizeof(tmp), id, SHA1_SIZE);
	StrCat(tmp, sizeof(tmp), HARNESS_HUB_A);
	StrUpper(tmp);
	Sha0(hash, tmp, StrLen(tmp));

	mac[0] = 0x00;
	mac[1] = SE_HUB_MAC_ADDR_SIGN;
	Copy(mac + 2, hash, 4);
	SetIP(&ip, 172, 31, hash[0] % 254 + 1, hash[1] % 254 + 1);

	HarnessCheck(h, Cmp(mac, hub_mac, sizeof(mac)) == 0, "HUBIP: hub MAC address from the name hash");
	HarnessCheck(h, CmpIpAddr(&ip, hub_ip) == 0, "HUBIP: hub address from the name hash, last octet from hash[1]");
}

// Save the configuration, restart the server from the saved file and compare the reloaded configuration
static void HarnessReload(HARNESS *h)
{
	RPC_CONFIG c;
	UINT err = ERR_NO_ERROR;
	UCHAR id1[SHA1_SIZE];
	UCHAR id2[SHA1_SIZE];
	UCHAR mac1[6];
	UCHAR mac2[6];
	IP ip1;
	IP ip2;

	Print("[config: reload into a fresh server instance]\n");

	Zero(&c, sizeof(c));
	err = ScGetConfig(h->Rpc, &c);
	if (HarnessCheckErr(h, err, "GetConfig before the restart") == false)
	{
		return;
	}
	char *text1 = CopyStr(c.FileData);
	FreeRpcConfig(&c);

	bool have_id1 = HarnessCheck(h, HarnessGetMachineId(h, id1, mac1, &ip1), "GetHub " HARNESS_HUB_A " before the restart");
	if (have_id1)
	{
		HarnessCheckHubAddr(h, id1, mac1, &ip1);
	}

	// SiReleaseServer writes the configuration file, SiNewServer loads it again
	AdminDisconnect(h->Rpc);
	h->Rpc = NULL;
	SiReleaseServer(h->Server);
	h->Server = NULL;

	h->Server = SiNewServer();
	if (HarnessCheck(h, h->Server != NULL, "server restarted from the saved " HARNESS_CONFIG_FILE) &&
		HarnessWaitListener(h, HARNESS_LISTEN_TIMEOUT))
	{
		// FIX-5: the salt in the configuration keeps the machine identity, and with it the hub MAC address
		// and address, across the restart
		if (have_id1 && HarnessCheck(h, HarnessGetMachineId(h, id2, mac2, &ip2), "GetHub " HARNESS_HUB_A " after the restart"))
		{
			HarnessCheck(h, Cmp(id1, id2, SHA1_SIZE) == 0, "machine identity kept by the restart (MachineIdSalt in the configuration)");
			HarnessCheck(h, Cmp(mac1, mac2, sizeof(mac1)) == 0 && CmpIpAddr(&ip1, &ip2) == 0,
				"hub MAC address and address kept by the restart");
		}

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
// Admin RPC checks of SEC-6 (#96)

// Delete user HARNESS_ZEROKEY_USER of hub HARNESS_HUB_A
static void HarnessZeroKeyDelete(HARNESS *h, char *what)
{
	RPC_DELETE_USER d;

	Zero(&d, sizeof(d));
	StrCpy(d.HubName, sizeof(d.HubName), HARNESS_HUB_A);
	StrCpy(d.Name, sizeof(d.Name), HARNESS_ZEROKEY_USER);

	HarnessCheckErr(h, ScDeleteUser(h->Rpc, &d), what);
}

// CreateUser and SetUser refuse a password user record whose password hash (HashedKey) is missing or all zero
// bytes: the server would store it as a user without a password. No login is attempted. A user that a call
// creates against the expectation is deleted, so the configuration phases see the same users as before.
static void HarnessZeroKeyUser(HARNESS *h)
{
	RPC_SET_USER t;

	Print("[zerokey: password user record without a password hash]\n");

	// All-zero HashedKey through the client API
	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), HARNESS_HUB_A);
	StrCpy(t.Name, sizeof(t.Name), HARNESS_ZEROKEY_USER);
	t.AuthType = AUTHTYPE_PASSWORD;
	t.AuthData = ZeroMalloc(sizeof(AUTHPASSWORD));
	UINT err = ScCreateUser(h->Rpc, &t);
	FreeRpcSetUser(&t);
	HarnessExpectErr(h, err, ERR_INVALID_PARAMETER, "CreateUser " HARNESS_ZEROKEY_USER " with an all-zero HashedKey");
	if (err == ERR_NO_ERROR)
	{
		HarnessZeroKeyDelete(h, "DeleteUser " HARNESS_ZEROKEY_USER " (created with an all-zero HashedKey)");
	}

	// Raw request Pack: AuthType password with neither HashedKey nor Auth_Password
	PACK *p = NewPack();
	PackAddStr(p, "HubName", HARNESS_HUB_A);
	PackAddStr(p, "Name", HARNESS_ZEROKEY_USER);
	PackAddInt(p, "AuthType", AUTHTYPE_PASSWORD);
	PACK *ret = AdminCall(h->Rpc, "CreateUser", p);
	err = GetErrorFromPack(ret);
	FreePack(ret);
	HarnessExpectErr(h, err, ERR_INVALID_PARAMETER, "CreateUser " HARNESS_ZEROKEY_USER " without HashedKey and Auth_Password");
	if (err == ERR_NO_ERROR)
	{
		HarnessZeroKeyDelete(h, "DeleteUser " HARNESS_ZEROKEY_USER " (created without a password hash)");
	}

	// A user with a password keeps its hash when SetUser sends an all-zero HashedKey
	if (HarnessCreateUser(h, HARNESS_HUB_A, HARNESS_ZEROKEY_USER, L"ranz zerokey"))
	{
		UCHAR expected[SHA1_SIZE];

		Zero(&t, sizeof(t));
		StrCpy(t.HubName, sizeof(t.HubName), HARNESS_HUB_A);
		StrCpy(t.Name, sizeof(t.Name), HARNESS_ZEROKEY_USER);
		t.AuthType = AUTHTYPE_PASSWORD;
		t.AuthData = ZeroMalloc(sizeof(AUTHPASSWORD));
		err = ScSetUser(h->Rpc, &t);
		FreeRpcSetUser(&t);
		HarnessExpectErr(h, err, ERR_INVALID_PARAMETER, "SetUser " HARNESS_ZEROKEY_USER " with an all-zero HashedKey");

		HashPassword(expected, HARNESS_ZEROKEY_USER, HARNESS_PASSWORD);

		Zero(&t, sizeof(t));
		StrCpy(t.HubName, sizeof(t.HubName), HARNESS_HUB_A);
		StrCpy(t.Name, sizeof(t.Name), HARNESS_ZEROKEY_USER);
		err = ScGetUser(h->Rpc, &t);
		if (HarnessCheckErr(h, err, "GetUser " HARNESS_ZEROKEY_USER))
		{
			AUTHPASSWORD *pw = (t.AuthType == AUTHTYPE_PASSWORD ? (AUTHPASSWORD *)t.AuthData : NULL);

			HarnessCheck(h, pw != NULL && Cmp(pw->HashedKey, expected, SHA1_SIZE) == 0,
				"GetUser " HARNESS_ZEROKEY_USER ": the password hash of CreateUser is kept");
		}
		FreeRpcSetUser(&t);

		HarnessZeroKeyDelete(h, "DeleteUser " HARNESS_ZEROKEY_USER);
	}
}

// Worker of HarnessIpTableLockCase: one admin RPC on hub HARNESS_HUB_A, then the Done event
static void HarnessIpTableLockThread(THREAD *thread, void *param)
{
	HARNESS_IPTABLE_CALL *c = (HARNESS_IPTABLE_CALL *)param;

	if (c == NULL)
	{
		return;
	}

	if (c->Which == 0)
	{
		RPC_ENUM_IP_TABLE t;

		Zero(&t, sizeof(t));
		StrCpy(t.HubName, sizeof(t.HubName), HARNESS_HUB_A);
		c->Err = ScEnumIpTable(c->H->Rpc, &t);
		FreeRpcEnumIpTable(&t);
	}
	else
	{
		RPC_DELETE_TABLE t;

		Zero(&t, sizeof(t));
		StrCpy(t.HubName, sizeof(t.HubName), HARNESS_HUB_A);
		t.Key = 1;
		c->Err = ScDeleteIpTable(c->H->Rpc, &t);
	}

	Set(c->Done);
}

// Run one admin RPC on a worker thread while the test holds the MacHashTable lock of the hub: the call waits for
// the lock and returns after the unlock with the expected error code. While it holds the lock, the test thread
// takes no other lock and makes no admin RPC call
static bool HarnessIpTableLockCase(HARNESS *h, HUB *hub, UINT which, UINT expected, char *what)
{
	HARNESS_IPTABLE_CALL c;
	char tmp[MAX_SIZE];

	// One event per case: a Mayaqua event resets itself when a Wait returns
	Zero(&c, sizeof(c));
	c.H = h;
	c.Which = which;
	c.Done = NewEvent();

	LockHashList(hub->MacHashTable);
	THREAD *t = NewThread(HarnessIpTableLockThread, &c);
	bool waits = (Wait(c.Done, HARNESS_IPTABLE_HOLD) == false);
	UnlockHashList(hub->MacHashTable);

	Format(tmp, sizeof(tmp), "%s waits for the MacHashTable lock", what);
	HarnessCheck(h, waits, tmp);

	if (waits)
	{
		Format(tmp, sizeof(tmp), "%s returns after the unlock", what);
		HarnessCheck(h, Wait(c.Done, HARNESS_IPTABLE_RETURN), tmp);
	}

	WaitThread(t, INFINITE);
	ReleaseThread(t);
	ReleaseEvent(c.Done);

	return HarnessExpectErr(h, c.Err, expected, what);
}

// Sender of the stress loop: UDP frames from session A to 10.0.0.2, each from a new source address in
// 10.128.0.0/9, with at most HARNESS_QUEUE_LOW frames queued
static void HarnessIpTableSendThread(THREAD *thread, void *param)
{
	HARNESS_IPTABLE_SENDER *s = (HARNESS_IPTABLE_SENDER *)param;
	UCHAR frame[128];
	UCHAR payload[8];
	UINT n = 0;
	USHORT sum;

	if (s == NULL)
	{
		return;
	}

	Zero(payload, sizeof(payload));
	UINT size = HarnessBuildIpFrame(frame, sizeof(frame), IP_PROTO_UDP, HARNESS_IPTABLE_PORT, payload, sizeof(payload));
	if (size == 0)
	{
		return;
	}

	while (s->Halt == false)
	{
		if (HarnessPaQueued(s->Pa) >= HARNESS_QUEUE_LOW)
		{
			Wait(s->Pa->SpaceEvent, 10);
			continue;
		}

		// Source address (frame bytes 26-29), then the IPv4 header checksum again. The UDP checksum covers the
		// source address: 0 (no checksum) instead
		n++;
		frame[26] = 10;
		frame[27] = (UCHAR)(0x80 | ((n >> 16) & 0x7F));
		frame[28] = (UCHAR)((n >> 8) & 0xFF);
		frame[29] = (UCHAR)(n & 0xFF);
		frame[24] = 0;
		frame[25] = 0;
		sum = IpChecksum(frame + 14, 20);
		Copy(frame + 24, &sum, sizeof(USHORT));
		frame[40] = 0;
		frame[41] = 0;

		HarnessPaSend(s->Pa, frame, size);
	}
}

// One EnumIpTable of hub HARNESS_HUB_A, then DeleteIpTable on each listed key. ERR_OBJECT_NOT_FOUND is expected
// for an entry that the hub evicted between the two calls. Adds the listed and the deleted entries to the counters;
// false, with the error code in bad_err, on any other error
static bool HarnessIpTableRound(HARNESS *h, UINT *num_listed, UINT *num_deleted, UINT *bad_err)
{
	RPC_ENUM_IP_TABLE t;
	bool ret = true;

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), HARNESS_HUB_A);
	UINT err = ScEnumIpTable(h->Rpc, &t);
	if (err != ERR_NO_ERROR)
	{
		*bad_err = err;
		ret = false;
	}
	else
	{
		*num_listed += t.NumIpTable;
	}

	for (UINT i = 0;ret && i < t.NumIpTable;i++)
	{
		RPC_DELETE_TABLE d;

		Zero(&d, sizeof(d));
		StrCpy(d.HubName, sizeof(d.HubName), HARNESS_HUB_A);
		d.Key = t.IpTables[i].Key;

		err = ScDeleteIpTable(h->Rpc, &d);
		if (err == ERR_NO_ERROR)
		{
			(*num_deleted)++;
		}
		else if (err != ERR_OBJECT_NOT_FOUND)
		{
			*bad_err = err;
			ret = false;
		}
	}

	FreeRpcEnumIpTable(&t);

	return ret;
}

// EnumIpTable and DeleteIpTable take the lock that guards the hub IP table: the MacHashTable lock, which the hub
// holds when it adds, updates and evicts entries. They took the lock of the IpTable list before, which the hub
// never takes, so an entry could be freed while the admin RPC read or freed it. No login is attempted
static void HarnessIpTableLock(HARNESS *h)
{
	RPC_ENUM_HUB e;
	HARNESS_IPTABLE_SENDER s;
	UINT rounds = 0;
	UINT num_listed = 0;
	UINT num_deleted = 0;
	UINT num_left = 0;
	UINT num_left_deleted = 0;
	UINT bad_err = ERR_NO_ERROR;
	bool ok = true;
	char tmp[MAX_SIZE];

	Print("[iptablelock: admin IP table RPCs and the MacHashTable lock of " HARNESS_HUB_A "]\n");

	HUB *hub = GetHub(h->Server->Cedar, HARNESS_HUB_A);
	if (HarnessCheck(h, hub != NULL, "GetHub " HARNESS_HUB_A " for the lock cases") == false)
	{
		return;
	}

	HarnessIpTableLockCase(h, hub, 0, ERR_NO_ERROR, "EnumIpTable " HARNESS_HUB_A);
	HarnessIpTableLockCase(h, hub, 1, ERR_OBJECT_NOT_FOUND, "DeleteIpTable " HARNESS_HUB_A " of key 1");

	ReleaseHub(hub);

	// EnumHub counts the IP table entries. It took the MacHashTable lock before the fix too, so a lock-held case
	// would not tell the two apart: a plain call
	Zero(&e, sizeof(e));
	HarnessCheckErr(h, ScEnumHub(h->Rpc, &e), "EnumHub after the lock cases");
	FreeRpcEnumHub(&e);

	// Stress: session A sends from new addresses, so the hub adds entries and evicts the oldest one at
	// HARNESS_IPTABLE_MAX, while the admin RPC lists the entries and deletes them. A round counts once it listed
	// entries; the loop ends after HARNESS_IPTABLE_ROUNDS rounds or HARNESS_IPTABLE_SPAN ms
	UINT old_max = vpn_global_parameters[GP_MAX_IP_TABLES];
	vpn_global_parameters[GP_MAX_IP_TABLES] = HARNESS_IPTABLE_MAX;

	Zero(&s, sizeof(s));
	s.Pa = h->PaA;
	THREAD *t = NewThread(HarnessIpTableSendThread, &s);

	UINT64 start = Tick64();
	while (ok && rounds < HARNESS_IPTABLE_ROUNDS && (Tick64() - start) < HARNESS_IPTABLE_SPAN)
	{
		UINT listed = 0;

		ok = HarnessIpTableRound(h, &listed, &num_deleted, &bad_err);
		num_listed += listed;

		if (listed != 0)
		{
			rounds++;
		}
	}

	s.Halt = true;
	WaitThread(t, INFINITE);
	ReleaseThread(t);

	// Let the queued frames reach the hub, then delete the entries left
	HarnessPaDrain(h->PaA, HARNESS_BENCH_DRAIN);
	if (ok)
	{
		ok = HarnessIpTableRound(h, &num_left, &num_left_deleted, &bad_err);
	}

	vpn_global_parameters[GP_MAX_IP_TABLES] = old_max;

	Print("TIME harness_iptablelock_stress %I64u ms\n", Tick64() - start);

	if (ok)
	{
		StrCpy(tmp, sizeof(tmp), "EnumIpTable and DeleteIpTable while session A adds addresses: no error but ERR_OBJECT_NOT_FOUND");
	}
	else
	{
		Format(tmp, sizeof(tmp), "EnumIpTable and DeleteIpTable while session A adds addresses: error %u (%S)", bad_err, _E(bad_err));
	}
	HarnessCheck(h, ok, tmp);
	HarnessCheck(h, num_listed != 0 && num_deleted != 0, "the stress loop listed and deleted IP table entries of session A");
}

////////////////////////////
// SetLink checks the authentication type and normalises the cascade policy (FND-13 #107)

// GetLink of cascade HARNESS_SETLINK_NAME on hub HARNESS_HUB_A; the caller frees t after ERR_NO_ERROR
static UINT HarnessSetLinkGet(HARNESS *h, RPC_CREATE_LINK *t)
{
	Zero(t, sizeof(RPC_CREATE_LINK));
	StrCpy(t->HubName, sizeof(t->HubName), HARNESS_HUB_A);
	t->ClientOption = ZeroMalloc(sizeof(CLIENT_OPTION));
	UniStrCpy(t->ClientOption->AccountName, sizeof(t->ClientOption->AccountName), HARNESS_SETLINK_NAME);

	return ScGetLink(h->Rpc, t);
}

// SetLinkRejectsBadAuthType: SetLink with an authentication type that NewLink refuses fails, and the cascade keeps
// its password authentication
static void HarnessSetLinkAuthType(HARNESS *h)
{
	RPC_CREATE_LINK t;
	char tmp[MAX_SIZE];

	UINT err = HarnessSetLinkGet(h, &t);
	if (HarnessCheckErr(h, err, "SetLinkRejectsBadAuthType: GetLink HARNESS_SETLINK") == false)
	{
		return;
	}

	t.ClientAuth->AuthType = HARNESS_SETLINK_AUTHTYPE;
	err = ScSetLink(h->Rpc, &t);
	if (err == ERR_NO_ERROR)
	{
		FreeRpcCreateLink(&t);
	}
	HarnessExpectErr(h, err, ERR_INVALID_PARAMETER, "SetLinkRejectsBadAuthType: SetLink HARNESS_SETLINK with AuthType 99");

	err = HarnessSetLinkGet(h, &t);
	if (HarnessCheckErr(h, err, "SetLinkRejectsBadAuthType: GetLink HARNESS_SETLINK after the SetLink"))
	{
		Format(tmp, sizeof(tmp), "SetLinkRejectsBadAuthType: GetLink still shows the password authentication of "
			HARNESS_LINK_USER " (AuthType %u, user %s)", t.ClientAuth->AuthType, t.ClientAuth->Username);
		HarnessCheck(h, t.ClientAuth->AuthType == CLIENT_AUTHTYPE_PASSWORD &&
			StrCmp(t.ClientAuth->Username, HARNESS_LINK_USER) == 0, tmp);
		FreeRpcCreateLink(&t);
	}
}

// SetLinkNormalisesPolicy: SetLink with a policy against the cascade invariants stores the policy that NewLink
// stores (Access, no NoBridge, MaxConnection 32, TimeOut 20)
static void HarnessSetLinkPolicy(HARNESS *h)
{
	RPC_CREATE_LINK t;
	char tmp[MAX_SIZE];

	UINT err = HarnessSetLinkGet(h, &t);
	if (HarnessCheckErr(h, err, "SetLinkNormalisesPolicy: GetLink HARNESS_SETLINK") == false)
	{
		return;
	}

	t.Policy.Access = false;
	t.Policy.NoBridge = true;
	t.Policy.MaxConnection = 1;
	t.Policy.TimeOut = 5;
	err = ScSetLink(h->Rpc, &t);
	if (err == ERR_NO_ERROR)
	{
		FreeRpcCreateLink(&t);
	}
	HarnessCheckErr(h, err, "SetLinkNormalisesPolicy: SetLink HARNESS_SETLINK with Access false, NoBridge true, "
		"MaxConnection 1, TimeOut 5");

	err = HarnessSetLinkGet(h, &t);
	if (HarnessCheckErr(h, err, "SetLinkNormalisesPolicy: GetLink HARNESS_SETLINK after the SetLink"))
	{
		Format(tmp, sizeof(tmp), "SetLinkNormalisesPolicy: GetLink shows Access %u, NoBridge %u, MaxConnection %u, "
			"TimeOut %u (expected 1, 0, 32, 20)", t.Policy.Access ? 1 : 0, t.Policy.NoBridge ? 1 : 0,
			t.Policy.MaxConnection, t.Policy.TimeOut);
		HarnessCheck(h, t.Policy.Access && t.Policy.NoBridge == false && t.Policy.MaxConnection == 32 &&
			t.Policy.TimeOut == 20, tmp);
		FreeRpcCreateLink(&t);
	}
}

// SetLink validates the authentication type and normalises the policy as NewLink does. The checks run on an offline
// cascade HARNESS_SETLINK of hub HARNESS_HUB_A that never connects; the phase deletes it again
static void HarnessSetLink(HARNESS *h)
{
	RPC_CREATE_LINK t;
	RPC_LINK k;

	Print("[setlink: SetLink checks the authentication type and normalises the cascade policy]\n");

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), HARNESS_HUB_A);
	t.Online = false;
	Copy(&t.Policy, GetDefaultPolicy(), sizeof(POLICY));

	t.ClientOption = ZeroMalloc(sizeof(CLIENT_OPTION));
	UniStrCpy(t.ClientOption->AccountName, sizeof(t.ClientOption->AccountName), HARNESS_SETLINK_NAME);
	StrCpy(t.ClientOption->Hostname, sizeof(t.ClientOption->Hostname), "127.0.0.1");
	t.ClientOption->Port = HARNESS_PORT;
	t.ClientOption->ProxyType = PROXY_DIRECT;
	StrCpy(t.ClientOption->HubName, sizeof(t.ClientOption->HubName), HARNESS_HUB_B);
	t.ClientOption->MaxConnection = 1;

	t.ClientAuth = ZeroMalloc(sizeof(CLIENT_AUTH));
	t.ClientAuth->AuthType = CLIENT_AUTHTYPE_PASSWORD;
	StrCpy(t.ClientAuth->Username, sizeof(t.ClientAuth->Username), HARNESS_LINK_USER);
	HashPassword(t.ClientAuth->HashedPassword, HARNESS_LINK_USER, HARNESS_PASSWORD);

	UINT err = ScCreateLink(h->Rpc, &t);
	if (err == ERR_NO_ERROR)
	{
		FreeRpcCreateLink(&t);
	}
	if (HarnessCheckErr(h, err, "CreateLink HARNESS_SETLINK on " HARNESS_HUB_A " (offline)") == false)
	{
		return;
	}

	HarnessSetLinkAuthType(h);
	HarnessSetLinkPolicy(h);

	Zero(&k, sizeof(k));
	StrCpy(k.HubName, sizeof(k.HubName), HARNESS_HUB_A);
	UniStrCpy(k.AccountName, sizeof(k.AccountName), HARNESS_SETLINK_NAME);
	HarnessCheckErr(h, ScDeleteLink(h->Rpc, &k), "DeleteLink HARNESS_SETLINK");
}

////////////////////////////
// Policy AutoDisconnect ends the session (FND-221 #258)

// A user whose policy has AutoDisconnect HARNESS_AUTODISC_SECONDS logs in to hub HARNESS_HUB_A with a test session.
// The server session ends at that time: not before it (both sessions were created after the test started) and long
// before the policy TimeOut (20 s), which would end it only after the client went away. The client session gets the
// policy in the welcome Pack, ends with ERR_AUTO_DISCONNECTED and does not wait for a reconnection (its NumRetry is 1,
// its retry interval 5 s). The user is deleted again, so the later phases see the same users as before
static void HarnessAutoDisconnect(HARNESS *h)
{
	RPC_SET_USER t;
	RPC_DELETE_USER d;
	HARNESS_PA *p;
	UINT64 started, established, ended = 0, stopped = 0, end;
	UINT err;
	bool listed;
	char tmp[MAX_SIZE];

	Print("[autodisconnect: policy AutoDisconnect ends the session at its time]\n");

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), HARNESS_HUB_A);
	StrCpy(t.Name, sizeof(t.Name), HARNESS_AUTODISC_USER);
	UniStrCpy(t.Note, sizeof(t.Note), L"ranz harness");
	t.AuthType = AUTHTYPE_PASSWORD;
	t.AuthData = NewPasswordAuthData(HARNESS_AUTODISC_USER, HARNESS_PASSWORD);
	t.Policy = ClonePolicy(GetDefaultPolicy());
	t.Policy->AutoDisconnect = HARNESS_AUTODISC_SECONDS;
	err = ScCreateUser(h->Rpc, &t);
	FreeRpcSetUser(&t);
	if (HarnessCheckErr(h, err, "CreateUser " HARNESS_AUTODISC_USER " on " HARNESS_HUB_A " with policy AutoDisconnect") == false)
	{
		return;
	}

	p = HarnessNewPa("autodisc");
	started = Tick64();

	if (HarnessCheck(h, HarnessStartSession(h, p, HARNESS_HUB_A, HARNESS_AUTODISC_USER), "test session autodisc started") &&
		HarnessWaitSession(h, p, HARNESS_SESSION_TIMEOUT))
	{
		established = Tick64();

		listed = HarnessWaitSessionListed(h, HARNESS_HUB_A, HARNESS_AUTODISC_USER, false, NULL, 0);
		HarnessCheck(h, listed, "the server lists the session of " HARNESS_AUTODISC_USER " (EnumSession)");

		// The server session ends
		end = established + (UINT64)HARNESS_AUTODISC_SECONDS * 1000 + HARNESS_AUTODISC_LATE;
		while (listed)
		{
			if (HarnessFindSession(h, HARNESS_HUB_A, HARNESS_AUTODISC_USER, false, NULL, 0) == false)
			{
				ended = Tick64();
				break;
			}

			if (Tick64() >= end)
			{
				break;
			}

			SleepThread(HARNESS_AUTODISC_POLL);
		}

		if (listed)
		{
			Format(tmp, sizeof(tmp), "the server session ends within %u ms after its AutoDisconnect time (%u s)",
				HARNESS_AUTODISC_LATE, HARNESS_AUTODISC_SECONDS);
			HarnessCheck(h, ended != 0, tmp);
			HarnessCheck(h, ended == 0 || ended - started >= (UINT64)HARNESS_AUTODISC_SECONDS * 1000,
				"the server session does not end before its AutoDisconnect time");
			if (ended != 0)
			{
				Print("TIME autodisconnect_session_end %I64u ms\n", ended - established);
			}
		}

		// The client session stops without a reconnection
		end = Tick64() + HARNESS_AUTODISC_IDLE;
		while (true)
		{
			if (p->Session->ClientStatus == CLIENT_STATUS_IDLE)
			{
				stopped = Tick64();
				break;
			}

			if (Tick64() >= end)
			{
				break;
			}

			SleepThread(HARNESS_AUTODISC_POLL);
		}

		Format(tmp, sizeof(tmp), "the client session stops within %u ms and does not reconnect (client status %u)",
			HARNESS_AUTODISC_IDLE, p->Session->ClientStatus);
		HarnessCheck(h, stopped != 0, tmp);
		HarnessExpectErr(h, p->Session->Err, ERR_AUTO_DISCONNECTED, "error of the client session");
	}

	HarnessStopSession(p);
	HarnessFreePa(p);

	Zero(&d, sizeof(d));
	StrCpy(d.HubName, sizeof(d.HubName), HARNESS_HUB_A);
	StrCpy(d.Name, sizeof(d.Name), HARNESS_AUTODISC_USER);
	HarnessCheckErr(h, ScDeleteUser(h->Rpc, &d), "DeleteUser " HARNESS_AUTODISC_USER);
}

////////////////////////////
// Admin RPC reconnect keeps the infinite socket timeout (FND-14 #107)

// Name of the server's admin RPC connection whose client port is port (EnumConnection); false when none is listed
static bool HarnessFindAdminConnection(HARNESS *h, UINT port, char *name, UINT name_size)
{
	RPC_ENUM_CONNECTION t;
	bool ret = false;

	Zero(&t, sizeof(t));
	if (ScEnumConnection(h->Rpc, &t) != ERR_NO_ERROR)
	{
		return false;
	}

	for (UINT i = 0;i < t.NumConnection;i++)
	{
		RPC_ENUM_CONNECTION_ITEM *e = &t.Connections[i];

		if (e->Type == CONNECTION_TYPE_ADMIN_RPC && e->Port == port)
		{
			StrCpy(name, name_size, e->Name);
			ret = true;
			break;
		}
	}

	FreeRpcEnumConnection(&t);

	return ret;
}

// AdminReconnectKeepsInfiniteTimeout: a second admin RPC (AdminConnectEx) loses its connection on the server side;
// the next call fails on it, RpcCall reconnects once through AdminReconnect and repeats the call, and the new
// socket has no timeout as the first one. With the connect timeout left on it, every call over 15 s on the new
// connection (SetConfig, a large EnumSession or EnumLogFile) timed out again
static void HarnessAdminReconnect(HARNESS *h)
{
	RPC_DISCONNECT_CONNECTION d;
	RPC_SERVER_INFO info;
	UINT err = ERR_NO_ERROR;
	char name[MAX_SIZE];
	char tmp[MAX_SIZE];

	Print("[adminreconnect: the admin RPC reconnects with no socket timeout]\n");

	RPC *rpc = HarnessAdminConnect(h->ClientCedar, HARNESS_START_TIMEOUT, &err);
	if (HarnessCheckErr(h, (rpc != NULL ? ERR_NO_ERROR : err),
		"AdminReconnectKeepsInfiniteTimeout: second admin RPC connected (AdminConnectEx)") == false)
	{
		return;
	}

	HarnessCheck(h, GetTimeout(rpc->Sock) == TIMEOUT_INFINITE,
		"AdminReconnectKeepsInfiniteTimeout: the first connection has no socket timeout");

	UINT old_port = rpc->Sock->LocalPort;

	if (HarnessCheck(h, HarnessFindAdminConnection(h, old_port, name, sizeof(name)),
		"AdminReconnectKeepsInfiniteTimeout: EnumConnection lists the admin connection of the second admin RPC"))
	{
		Zero(&d, sizeof(d));
		StrCpy(d.Name, sizeof(d.Name), name);
		HarnessCheckErr(h, ScDisconnectConnection(h->Rpc, &d),
			"AdminReconnectKeepsInfiniteTimeout: DisconnectConnection drops the server side of the second admin RPC");

		Zero(&info, sizeof(info));
		err = ScGetServerInfo(rpc, &info);
		if (err == ERR_NO_ERROR)
		{
			FreeRpcServerInfo(&info);
		}
		HarnessCheckErr(h, err, "AdminReconnectKeepsInfiniteTimeout: GetServerInfo on the second admin RPC succeeds "
			"through the reconnect");

		HarnessCheck(h, rpc->Sock != NULL && rpc->Sock->LocalPort != old_port,
			"AdminReconnectKeepsInfiniteTimeout: the second admin RPC uses a new connection");

		Format(tmp, sizeof(tmp), "AdminReconnectKeepsInfiniteTimeout: the new connection has no socket timeout "
			"(timeout %u ms)", GetTimeout(rpc->Sock));
		HarnessCheck(h, rpc->Sock != NULL && GetTimeout(rpc->Sock) == TIMEOUT_INFINITE, tmp);
	}

	AdminDisconnect(rpc);
}

// AdminInvoke: a session that AdminOpen opened from a login with no socket answers the GetCaps RPC with the same
// Pack as the admin RPC over the socket, and the session tag is RPC-n
static void HarnessAdminInvoke(HARNESS *h)
{
	ADMIN_LOGIN l;
	BUF *b1;
	BUF *b2;
	UCHAR hashed_password[SHA1_SIZE];
	UINT err = ERR_NO_ERROR;

	Print("[admininvoke: AdminInvoke on an admin session without a socket]\n");

	Zero(&l, sizeof(l));
	StrCpy(l.ConnName, sizeof(l.ConnName), "HARNESS_INVOKE");
	SetIP(&l.RemoteIP, 127, 0, 0, 1);
	l.Id = 4242;
	Rand(l.Random, sizeof(l.Random));
	l.AcceptEmptyPassword = true;
	Sha0(hashed_password, "", 0);
	SecurePassword(l.SecurePassword, hashed_password, l.Random);
	l.HasSecurePassword = true;

	ADMIN *a = AdminOpen(h->Server, &l, &err);
	if (HarnessCheckErr(h, (a != NULL ? ERR_NO_ERROR : err),
		"AdminInvoke: AdminOpen opens a server session without a socket") == false)
	{
		return;
	}

	HarnessCheck(h, a->ServerAdmin && a->HubName == NULL && StrCmp(a->Tag, "RPC-4242") == 0,
		"AdminInvoke: the session is a server session tagged RPC-n");

	PACK *req = NewPack();
	PACK *local = AdminInvoke(a, "GetCaps", req);
	FreePack(req);

	req = NewPack();
	PACK *remote = AdminCall(h->Rpc, "GetCaps", req);

	if (HarnessCheck(h, local != NULL && remote != NULL, "AdminInvoke: both calls return a Pack"))
	{
		b1 = PackToBuf(local);
		b2 = PackToBuf(remote);
		HarnessCheck(h, CompareBuf(b1, b2), "AdminInvoke: the Pack equals the Pack over the socket");
		FreeBuf(b1);
		FreeBuf(b2);
	}

	if (local != NULL)
	{
		FreePack(local);
	}
	if (remote != NULL)
	{
		FreePack(remote);
	}

	AdminClose(a);
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
			for (UINT i = 0;i < e.NumHub;i++)
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

	FileDelete(HARNESS_CONFIG_FILE);

	// EnumDirW does not resolve the '$' prefix: use the full path
	InnerFilePathW(dir, sizeof(dir), HARNESS_CONFIG_BACKUP_DIR);

	DIRLIST *d = EnumDirW(dir);
	if (d != NULL)
	{
		for (UINT i = 0;i < d->NumFiles;i++)
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
	}

	HarnessStopServer(h);
}

// Disconnect the admin RPC and stop the server. The server saves its configuration file as it stops, and the file
// stays for the next HarnessStartServerKeep of the run.
void HarnessStopServerKeep(HARNESS *h)
{
	if (h->Rpc != NULL)
	{
		AdminDisconnect(h->Rpc);
		h->Rpc = NULL;
	}

	if (h->Server != NULL)
	{
		SiReleaseServer(h->Server);
		h->Server = NULL;
	}

	if (h->ClientCedar != NULL)
	{
		ReleaseCedar(h->ClientCedar);
		h->ClientCedar = NULL;
	}
}

// Disconnect the admin RPC, stop the server and delete its configuration files
static void HarnessStopServer(HARNESS *h)
{
	HarnessStopServerKeep(h);

	if (h->OldConfigName != NULL)
	{
		SERVER_CONFIG_FILE_NAME = h->OldConfigName;
		h->OldConfigName = NULL;
		HarnessDeleteConfigFiles();
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
	UINT num_marks = 0;
	char name[MAX_SIZE];
	char tmp[MAX_SIZE];

	HarnessBuildFrame(frame, size, harness_mac_b, harness_mac_a, 0x10000 + size);

	HarnessClearRecv(h->PaB);
	Lock(h->PaB->Lock);
	{
		h->PaB->Record = false;
	}
	Unlock(h->PaB->Lock);

	UINT64 next_mark = HarnessNowNs() + (UINT64)HARNESS_BENCH_WARMUP * HARNESS_NS_PER_MS;

	while (true)
	{
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

		UINT queued = HarnessPaQueued(h->PaA);
		if (queued < HARNESS_QUEUE_HIGH)
		{
			UINT num = HARNESS_QUEUE_HIGH - queued;

			for (UINT i = 0;i < num;i++)
			{
				batch[i] = ZeroMalloc(sizeof(HARNESS_FRAME));
				batch[i]->Data = Malloc(size);
				Copy(batch[i]->Data, frame, size);
				batch[i]->Size = size;
			}

			Lock(h->PaA->Lock);
			{
				for (UINT i = 0;i < num;i++)
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
	UINT num_unsent = HarnessPaPurge(h->PaA);

	for (UINT i = 0;i < HARNESS_BENCH_RUNS;i++)
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

// Flood cases on a hub of their own: the flood loop of StorePacket sends to every session of the hub
static void HarnessBenchFlood(HARNESS *h)
{
	RPC_DELETE_HUB d;

	if (HarnessCreateHub(h, HARNESS_HUB_FLOOD) == false)
	{
		return;
	}

	HUB *hub = GetHub(h->Server->Cedar, HARNESS_HUB_FLOOD);
	if (HarnessCheck(h, hub != NULL, "GetHub " HARNESS_HUB_FLOOD))
	{
		HarnessSetPhase("bench_flood_8", NULL);
		HarnessBenchFloodCase(hub, 8);
		HarnessSetPhase("bench_flood_64", NULL);
		HarnessBenchFloodCase(hub, 64);
		HarnessSetPhase("bench_flood_logwait_8", NULL);
		HarnessBenchFloodLogWaitCase(hub, 8);

		// The IP table cases use the same hub, with one session
		HarnessSetPhase("bench_ip_table_add", NULL);
		HarnessBenchIpTableAdd(hub, 1024);
		HarnessBenchIpTableAdd(hub, 16384);

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

	OutRpcEnumSession(p, b->Struct);
	BUF *buf = PackToBuf(p);
	FreePack(p);
	FreeBuf(buf);

	return true;
}

// Decode RPC_ENUM_SESSION: BUF -> PACK -> struct
static bool HarnessOpDecodeEnumSession(void *param)
{
	HARNESS_PACK_BENCH *b = (HARNESS_PACK_BENCH *)param;
	RPC_ENUM_SESSION t;

	SeekBufToBegin(b->Buf);
	PACK *p = BufToPack(b->Buf);
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
	bool ok = false;

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), HARNESS_HUB_A);
	t.NumSession = HARNESS_PACK_ITEMS;
	t.Sessions = ZeroMalloc(sizeof(RPC_ENUM_SESSION_ITEM) * t.NumSession);

	for (UINT i = 0;i < t.NumSession;i++)
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

	PACK *p = NewPack();
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

// Parse a frame as HubPaPutPacket does with the default hub options: IP and HTTP parsing, BPDU bridge id,
// checksum correction (the frames have valid checksums, so the buffer is not changed). no_log: the hub packet
// log is off, so HTTP, TLS SNI and DNS are not parsed
static PKT *HarnessParseLikeHub(HARNESS_PARSE_FRAME *f, bool no_log)
{
	return ParsePacketEx5(f->Data, f->Size, false, 0, true, no_log, true, no_log);
}

// The parser reached the layer the frame was built for (no_log: and stopped before layer 7)
static bool HarnessParsedAsBuilt(const HARNESS_PARSE_FRAME *f, const PKT *p, bool no_log)
{
	if (p == NULL)
	{
		return false;
	}

	if (StrCmp(f->Kind, "tcp") == 0 || (no_log && (StrCmp(f->Kind, "http") == 0 || StrCmp(f->Kind, "tls") == 0)))
	{
		return (p->TypeL4 == L4_TCP && p->HttpLog == NULL);
	}

	if (no_log && StrCmp(f->Kind, "dns") == 0)
	{
		return (p->TypeL4 == L4_UDP && p->TypeL7 == L7_UNKNOWN);
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
	PKT *p = HarnessParseLikeHub(&b->Frames[b->Current], b->NoLog);

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
	PKT *p = HarnessParseLikeHub(&b->Frames[b->Next], b->NoLog);

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
// to TCP 443; dns: query to UDP 53. The _nolog cases parse the same frames as with the hub packet log off
static void HarnessBenchParse()
{
	HARNESS_PARSE_BENCH b;
	UCHAR payload[HARNESS_PARSE_FRAME_MAX];
	char *http = "GET /index.html HTTP/1.1\r\nHost: " HARNESS_BENCH_HOST "\r\nUser-Agent: ranz-bench/1.0\r\nAccept: */*\r\n\r\n";
	bool ok;
	char name[MAX_SIZE];

	Zero(&b, sizeof(b));

	HARNESS_PARSE_FRAME *f = &b.Frames[0];
	f->Kind = "l2";
	f->Size = HARNESS_FRAME_SIZE;
	HarnessBuildFrame(f->Data, f->Size, harness_mac_b, harness_mac_a, 1);

	f = &b.Frames[1];
	f->Kind = "tcp";
	for (UINT i = 0;i < 64;i++)
	{
		payload[i] = (UCHAR)(i * 3);
	}
	f->Size = HarnessBuildIpFrame(f->Data, sizeof(f->Data), IP_PROTO_TCP, 5001, payload, 64);

	f = &b.Frames[2];
	f->Kind = "http";
	f->Size = HarnessBuildIpFrame(f->Data, sizeof(f->Data), IP_PROTO_TCP, 80, (UCHAR *)http, StrLen(http));

	f = &b.Frames[3];
	f->Kind = "tls";
	UINT size = HarnessBuildClientHello(payload, sizeof(payload), HARNESS_BENCH_HOST);
	f->Size = HarnessBuildIpFrame(f->Data, sizeof(f->Data), IP_PROTO_TCP, 443, payload, size);

	f = &b.Frames[4];
	f->Kind = "dns";
	size = HarnessBuildDnsQuery(payload, sizeof(payload), HARNESS_BENCH_HOST);
	f->Size = HarnessBuildIpFrame(f->Data, sizeof(f->Data), IP_PROTO_UDP, 53, payload, size);

	for (UINT pass = 0;pass < 2;pass++)
	{
		char *suffix = (pass == 0 ? "" : "_nolog");

		b.NoLog = (pass != 0);
		b.Next = 0;
		ok = true;

		for (UINT i = 0;i < HARNESS_NUM_PARSE_FRAMES;i++)
		{
			PKT *p = NULL;

			f = &b.Frames[i];
			Format(name, sizeof(name), "parse_packet_%s%s", f->Kind, suffix);

			if (f->Size != 0)
			{
				p = HarnessParseLikeHub(f, b.NoLog);
			}

			if (HarnessParsedAsBuilt(f, p, b.NoLog))
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
			Format(name, sizeof(name), "parse_packet_mix%s", suffix);
			HarnessBenchOps(name, HarnessOpParseMix, &b, HARNESS_BENCH_MICRO_SPAN, 16);
		}
	}
}

// ip_table_expire_<n>: microseconds of one DeleteExpiredIpTableEntry pass over an IP table of n entries,
// every second entry expired: the part that the hub runs under its table lock. ip_table_free_<n>: microseconds to
// free the entries that the pass took out, which the hub does after the lock (FreeIpTableEntries, CORE-F6)
static void HarnessBenchIpTableExpire(UINT num)
{
	UINT64 runs[HARNESS_BENCH_RUNS];
	UINT64 free_runs[HARNESS_BENCH_RUNS];
	bool ok = true;
	char name[MAX_SIZE];
	char free_name[MAX_SIZE];

	Format(name, sizeof(name), "ip_table_expire_%u", num);
	Format(free_name, sizeof(free_name), "ip_table_free_%u", num);

	for (UINT r = 0;r < HARNESS_BENCH_RUNS;r++)
	{
		LIST *o = NewList(CompareIpTable);
		IP_TABLE_EXPIRY x;
		UINT num_expired = 0;
		UINT64 now = Tick64();

		IpTableExpiryInit(&x);

		for (UINT i = 0;i < num;i++)
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

		UINT64 start = HarnessNowNs();
		DeleteExpiredIpTableEntry(o, &x, Tick64());
		runs[r] = (HarnessNowNs() - start) / 1000ULL;

		for (IP_TABLE_ENTRY *e = x.Expired;e != NULL;e = e->NextExpired)
		{
			num_expired++;
		}

		if (LIST_NUM(o) != (num - (num + 1) / 2) || num_expired != (num + 1) / 2)
		{
			ok = false;
		}

		start = HarnessNowNs();
		FreeIpTableEntries(x.Expired);
		free_runs[r] = (HarnessNowNs() - start) / 1000ULL;

		for (UINT i = 0;i < LIST_NUM(o);i++)
		{
			Free(LIST_DATA(o, i));
		}
		ReleaseList(o);
	}

	HarnessBenchReport(name, runs, HARNESS_BENCH_RUNS, "us", false);
	HarnessBenchReport(free_name, free_runs, HARNESS_BENCH_RUNS, "us", false);

	if (ok == false)
	{
		Print("BENCH WARNING %s: the pass did not delete exactly the expired entries\n", name);
	}
}

// accept_table_<n>: microseconds for n first connections from n distinct source addresses to the DoS table of a
// listener (CheckDosAttack: expiry pass, search, insert), the addresses in scrambled order. Afterwards the table must
// hold the n entries in the order of a list built with Add and one Sort, and must not need a sort before a Search
static void HarnessBenchAcceptTable(UINT num)
{
	UINT64 runs[HARNESS_BENCH_RUNS];
	bool ok = true;
	char name[MAX_SIZE];
	LISTENER *l = ZeroMalloc(sizeof(LISTENER));
	SOCK *s = ZeroMalloc(sizeof(SOCK));

	Format(name, sizeof(name), "accept_table_%u", num);

	for (UINT r = 0;r < HARNESS_BENCH_RUNS;r++)
	{
		LIST *ref = NewListFast(CompareDos);

		l->DosList = NewList(CompareDos);
		l->DosListLastRefreshTime = 0;

		UINT64 start = HarnessNowNs();
		for (UINT i = 0;i < num;i++)
		{
			// An odd multiplier modulo 2^24 gives every i another address, in no particular order
			UINT v = (i * 2654435761U) & 0xFFFFFF;

			SetIP(&s->RemoteIP, 10, (UCHAR)(v >> 16), (UCHAR)(v >> 8), (UCHAR)v);

			if (CheckDosAttack(l, s) == false)
			{
				ok = false;
			}
		}
		runs[r] = (HarnessNowNs() - start) / 1000ULL;

		if (LIST_NUM(l->DosList) != num || l->DosList->sorted == false)
		{
			ok = false;
		}

		for (UINT i = 0;i < LIST_NUM(l->DosList);i++)
		{
			Add(ref, LIST_DATA(l->DosList, i));
		}
		Sort(ref);

		for (UINT i = 0;i < LIST_NUM(ref) && i < LIST_NUM(l->DosList);i++)
		{
			if (LIST_DATA(ref, i) != LIST_DATA(l->DosList, i))
			{
				ok = false;
			}
		}

		for (UINT i = 0;i < LIST_NUM(l->DosList);i++)
		{
			Free(LIST_DATA(l->DosList, i));
		}
		ReleaseList(l->DosList);
		l->DosList = NULL;
		ReleaseList(ref);
	}

	Free(s);
	Free(l);

	HarnessBenchReport(name, runs, HARNESS_BENCH_RUNS, "us", false);

	if (ok == false)
	{
		Print("BENCH WARNING %s: the table is not the n entries in sorted order\n", name);
	}
}

// One fifo_cycle operation: write HARNESS_FIFO_CYCLE bytes behind the backlog, then read as many from its front
static bool HarnessOpFifoCycle(void *param)
{
	HARNESS_FIFO_BENCH *b = (HARNESS_FIFO_BENCH *)param;

	WriteFifo(b->Fifo, b->Buf, HARNESS_FIFO_CYCLE);
	b->PeakMemSize = MAX(b->PeakMemSize, b->Fifo->memsize);

	if (ReadFifo(b->Fifo, b->Buf, HARNESS_FIFO_CYCLE) != HARNESS_FIFO_CYCLE)
	{
		return false;
	}

	return FifoSize(b->Fifo) == HARNESS_FIFO_BACKLOG;
}

// One queue_cycle operation: insert one item behind the backlog, then take the oldest one
static bool HarnessOpQueueCycle(void *param)
{
	HARNESS_FIFO_BENCH *b = (HARNESS_FIFO_BENCH *)param;

	InsertQueue(b->Queue, (void *)(UINT_PTR)b->NextInsert);
	b->NextInsert++;

	if (GetNext(b->Queue) != (void *)(UINT_PTR)b->NextGet)
	{
		return false;
	}
	b->NextGet++;

	return true;
}

// One queue_burst operation: insert HARNESS_QUEUE_BURST items into the empty queue, then take them all
static bool HarnessOpQueueBurst(void *param)
{
	HARNESS_FIFO_BENCH *b = (HARNESS_FIFO_BENCH *)param;
	bool ok = true;

	for (UINT i = 0;i < HARNESS_QUEUE_BURST;i++)
	{
		InsertQueue(b->Queue, (void *)(UINT_PTR)(i + 1));
	}

	for (UINT i = 0;i < HARNESS_QUEUE_BURST;i++)
	{
		if (GetNext(b->Queue) != (void *)(UINT_PTR)(i + 1))
		{
			ok = false;
		}
	}

	return ok && GetQueueNum(b->Queue) == 0;
}

// fifo_cycle: operations per second of write HARNESS_FIFO_CYCLE / read HARNESS_FIFO_CYCLE bytes over a standing
// backlog of HARNESS_FIFO_BACKLOG bytes, in one FIFO kept across the runs: a producer and a consumer that never
// fully drain it. fifo_cycle_peak_memsize is the largest buffer the FIFO reached. queue_cycle: insert one / take
// one item over a standing backlog of HARNESS_QUEUE_BACKLOG items; queue_burst_<n>: n items into an empty queue,
// then all of them out (FND-215)
static void HarnessBenchFifo()
{
	HARNESS_FIFO_BENCH *b = ZeroMalloc(sizeof(HARNESS_FIFO_BENCH));
	char name[MAX_SIZE];

	b->Fifo = NewFifo();
	WriteFifo(b->Fifo, b->Buf, HARNESS_FIFO_BACKLOG);
	b->PeakMemSize = b->Fifo->memsize;

	HarnessBenchOps("fifo_cycle", HarnessOpFifoCycle, b, HARNESS_BENCH_MICRO_SPAN, 16);
	Print("BENCH fifo_cycle_peak_memsize %u bytes\n", b->PeakMemSize);

	ReleaseFifo(b->Fifo);

	b->Queue = NewQueueFast();
	b->NextInsert = 1;
	b->NextGet = 1;
	for (UINT i = 0;i < HARNESS_QUEUE_BACKLOG;i++)
	{
		InsertQueue(b->Queue, (void *)(UINT_PTR)b->NextInsert);
		b->NextInsert++;
	}

	HarnessBenchOps("queue_cycle", HarnessOpQueueCycle, b, HARNESS_BENCH_MICRO_SPAN, 16);

	while (GetQueueNum(b->Queue) != 0)
	{
		GetNext(b->Queue);
	}

	Format(name, sizeof(name), "queue_burst_%u", HARNESS_QUEUE_BURST);
	HarnessBenchOps(name, HarnessOpQueueBurst, b, HARNESS_BENCH_MICRO_SPAN, 1);

	ReleaseQueue(b->Queue);
	Free(b);
}

////////////////////////////
// Intermediate certificate download ("certdl")
//
// DownloadCert (Cedar/Protocol.c) is the only outbound HTTP client. SetServerCert reaches it when the new
// server certificate is not a root and its issuer is in neither the root list nor chain_certs: the server
// downloads the "CA Issuers" URL of the Authority Information Access extension. The fixtures name a
// loopback listener of this test as that URL, so the test needs no network. Each run answers in one mode
// and pins one behaviour of the client: the request it sends, https without a trust check, an interim
// 100 Continue skipped, no redirect followed, no authentication tried, Content-Length required and capped
// at 64 KiB, and the 10 s receive timeout.

// Fixture certificates, committed for this test. Made with OpenSSL 3.2 "openssl ca" (RSA 2048, SHA-256,
// valid 2020-01-01 to 2049-12-31); the server certificates carry "authorityInfoAccess =
// caIssuers;URI:<issuer URL>", and the tls certificate is self-signed with the key below. The key of the
// issuer is not kept: the test never signs.

// Issuer: self-signed root "Ranz certdl test CA" (served as DER by the listener)
static char certdl_ca_pem[] =
	"-----BEGIN CERTIFICATE-----\n"
	"MIIC+jCCAeKgAwIBAgICEAAwDQYJKoZIhvcNAQELBQAwHjEcMBoGA1UEAwwTUmFu\n"
	"eiBjZXJ0ZGwgdGVzdCBDQTAeFw0yMDAxMDEwMDAwMDBaFw00OTEyMzEyMzU5NTla\n"
	"MB4xHDAaBgNVBAMME1JhbnogY2VydGRsIHRlc3QgQ0EwggEiMA0GCSqGSIb3DQEB\n"
	"AQUAA4IBDwAwggEKAoIBAQDkfEGcqde+uaYWr3NwtMSipiK/H0U5WNw027ASkoY2\n"
	"9C/0Xi7PVsQy5DiRm08CaBua09Q0ru/KbmVKWNLUnUcaPhh3jGXalRb3GRI9aduC\n"
	"VbL8FADOichPa91sPupfh0wYoXQ6dwj8UyZ/nflA69M5NivbJEsqySBls5VRUzfv\n"
	"QUX1emB9Cb7N8U4WNE5tZjlMPqSIxWWvfVOw13nm/pSmHftqwjACAM0rB9sp11yb\n"
	"0l/qcGJZvl/yscxf9Ze26CJYGC4sYEfUAOG1CHySpdjXlhwhsA8D+zxztQkZCzen\n"
	"pvaVacpn6dJ0yyuaFrXtZltU10f4NzMbp/p3Hy4qGwNfAgMBAAGjQjBAMA8GA1Ud\n"
	"EwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQDAgEGMB0GA1UdDgQWBBTTqL8XosGizAjv\n"
	"xnwcT3zyMGRxkTANBgkqhkiG9w0BAQsFAAOCAQEAO1V2NM/veCeX68R6m+gB++/H\n"
	"V5C74Bd4NAdFdskIITuc5uX30puvCno+utDfKVM3M3pUeWoUvOjwbAlmKV8tLntk\n"
	"y0CH60QFe+0HeD9XNKjRjb58sXdUgqiqNk4H+J5Ba8VNIpJJpaeqPwHK8WU0PMX7\n"
	"uWi+0a/JNwkhnGjY/oCC+YXgti7t4CeAOm1pZ20+tYbfrqmjIo7njLOXTUC2u52X\n"
	"wtgsu240p287YwvV+SkfdtfYoeP+FoZTy0MVcgJWjmRsDaqmYf+4uFPVcZznLONC\n"
	"/qpCFUeK5nCjO1W8XwG32Ic95ES0LjR/ifaTOvOjBadsbcjvAfUZRyN871EBdg==\n"
	"-----END CERTIFICATE-----\n";

// Server certificate "ranz-certdl-http", AIA caIssuers http://127.0.0.1:39556/ranz-certdl/ca.cer
static char certdl_http_pem[] =
	"-----BEGIN CERTIFICATE-----\n"
	"MIIDczCCAlugAwIBAgICEAEwDQYJKoZIhvcNAQELBQAwHjEcMBoGA1UEAwwTUmFu\n"
	"eiBjZXJ0ZGwgdGVzdCBDQTAeFw0yMDAxMDEwMDAwMDBaFw00OTEyMzEyMzU5NTla\n"
	"MBsxGTAXBgNVBAMMEHJhbnotY2VydGRsLWh0dHAwggEiMA0GCSqGSIb3DQEBAQUA\n"
	"A4IBDwAwggEKAoIBAQDH1GwSv5Io+5+pE/7H5V2v05Yh3PDrBR0u3Z7gIjifHF+1\n"
	"qCRTEAEW7fgZLOUAJj5HCwvMuTxre2fw6XEYh8b/ivjiN1zcWWu84+B8FK3fUeeZ\n"
	"8kZpxhtOx08veIt8mOZMtqsCOGkgVPg3GqrgJmw2IeOX7J4DqlA7QUK9u4ElOhSH\n"
	"9bEK6g7gJiEHsFtTFKuIsTiyUOih86047Jj+1VFH6miNVfLcCDnjx4ma9Uibb4R0\n"
	"TdDqaHUmykuNkr5ymn57BQaLq5Z2/b1pEbhDdAMivk21bFDrAItCxLt/eZOTaLZ/\n"
	"b3QOclGB7irw/9JMWm0eIPhxG1ymPkL570zqpU9DAgMBAAGjgb0wgbowDAYDVR0T\n"
	"AQH/BAIwADAOBgNVHQ8BAf8EBAMCBaAwEwYDVR0lBAwwCgYIKwYBBQUHAwEwHQYD\n"
	"VR0OBBYEFLBH+RH/luMwDKZX2NKfbzkBAPnkMB8GA1UdIwQYMBaAFNOovxeiwaLM\n"
	"CO/GfBxPfPIwZHGRMEUGCCsGAQUFBwEBBDkwNzA1BggrBgEFBQcwAoYpaHR0cDov\n"
	"LzEyNy4wLjAuMTozOTU1Ni9yYW56LWNlcnRkbC9jYS5jZXIwDQYJKoZIhvcNAQEL\n"
	"BQADggEBAGLJ0WbnfC24iyEcenRUENPaMmAize0vTrCkv0FsPouXewTXDK/arHpw\n"
	"bL6CTwiEKoQH1uITciFrJlNHZUaapRRMhhGa4xvj74ODEXEWjADC3NprVT9dZwLR\n"
	"o1FkDXZLRh0nKpgb0yKDPcVvoy2imtB6FZB9Mmy9iLAP3XWs2bQawWc/17vnIciY\n"
	"vhavbqh5i3qFzENXEECFGjYKyWPhOOTgd+txeLnHw9IQDec/A6j59RwH3GQsLA7t\n"
	"pSdRSBdkWLgntErlx9eFV07UgExJaS87ApB16D2nPt6cpwE6pwY8xIs51fZMDDd8\n"
	"5D6SkRVxXrL3MkMoUyOCbJHbtr4JieQ=\n"
	"-----END CERTIFICATE-----\n";

// Server certificate "ranz-certdl-https", AIA caIssuers https://127.0.0.1:39556/ranz-certdl/ca.cer
static char certdl_https_pem[] =
	"-----BEGIN CERTIFICATE-----\n"
	"MIIDdTCCAl2gAwIBAgICEAIwDQYJKoZIhvcNAQELBQAwHjEcMBoGA1UEAwwTUmFu\n"
	"eiBjZXJ0ZGwgdGVzdCBDQTAeFw0yMDAxMDEwMDAwMDBaFw00OTEyMzEyMzU5NTla\n"
	"MBwxGjAYBgNVBAMMEXJhbnotY2VydGRsLWh0dHBzMIIBIjANBgkqhkiG9w0BAQEF\n"
	"AAOCAQ8AMIIBCgKCAQEAx9RsEr+SKPufqRP+x+Vdr9OWIdzw6wUdLt2e4CI4nxxf\n"
	"tagkUxABFu34GSzlACY+RwsLzLk8a3tn8OlxGIfG/4r44jdc3FlrvOPgfBSt31Hn\n"
	"mfJGacYbTsdPL3iLfJjmTLarAjhpIFT4Nxqq4CZsNiHjl+yeA6pQO0FCvbuBJToU\n"
	"h/WxCuoO4CYhB7BbUxSriLE4slDoofOtOOyY/tVRR+pojVXy3Ag548eJmvVIm2+E\n"
	"dE3Q6mh1JspLjZK+cpp+ewUGi6uWdv29aRG4Q3QDIr5NtWxQ6wCLQsS7f3mTk2i2\n"
	"f290DnJRge4q8P/STFptHiD4cRtcpj5C+e9M6qVPQwIDAQABo4G+MIG7MAwGA1Ud\n"
	"EwEB/wQCMAAwDgYDVR0PAQH/BAQDAgWgMBMGA1UdJQQMMAoGCCsGAQUFBwMBMB0G\n"
	"A1UdDgQWBBSwR/kR/5bjMAymV9jSn285AQD55DAfBgNVHSMEGDAWgBTTqL8XosGi\n"
	"zAjvxnwcT3zyMGRxkTBGBggrBgEFBQcBAQQ6MDgwNgYIKwYBBQUHMAKGKmh0dHBz\n"
	"Oi8vMTI3LjAuMC4xOjM5NTU2L3JhbnotY2VydGRsL2NhLmNlcjANBgkqhkiG9w0B\n"
	"AQsFAAOCAQEA0+kpMDR49qA9OS4Q5QPtlfiHeHAQ7ftxT/UxSvX0N7UylMSGr5ch\n"
	"pyxCxVyymdEvv+Qtd4aK/EFACMzKkO55PLzjdyV6oyKCbcbsvTJQ6dZ0ZT5xYceX\n"
	"mg13jjZOn0iIK7I/XFfWC1vtpwTO91VlDYKwwMDfypr4MBYb+hc+YB5HaLgXu8r5\n"
	"V6sex/Tc824FU6DpyxCnQHwp1ZEcGkHkYLd6NloMGDxfLNjyC1AgoNxmiBOPxE0r\n"
	"DUdGkMPpq1V8/J1reZlL46x4BELptJzqy8ML/+6y+a39v9Y2UBH69173zGHA/o+7\n"
	"x1wdSvLRWbP+HGOtaAcBMO9U9ipN5Ow9DQ==\n"
	"-----END CERTIFICATE-----\n";

// TLS certificate of the listener: self-signed root "ranz-certdl-tls" (no AIA), not trusted by Windows
static char certdl_tls_pem[] =
	"-----BEGIN CERTIFICATE-----\n"
	"MIIDBzCCAe+gAwIBAgICEAQwDQYJKoZIhvcNAQELBQAwGjEYMBYGA1UEAwwPcmFu\n"
	"ei1jZXJ0ZGwtdGxzMB4XDTIwMDEwMTAwMDAwMFoXDTQ5MTIzMTIzNTk1OVowGjEY\n"
	"MBYGA1UEAwwPcmFuei1jZXJ0ZGwtdGxzMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A\n"
	"MIIBCgKCAQEAx9RsEr+SKPufqRP+x+Vdr9OWIdzw6wUdLt2e4CI4nxxftagkUxAB\n"
	"Fu34GSzlACY+RwsLzLk8a3tn8OlxGIfG/4r44jdc3FlrvOPgfBSt31HnmfJGacYb\n"
	"TsdPL3iLfJjmTLarAjhpIFT4Nxqq4CZsNiHjl+yeA6pQO0FCvbuBJToUh/WxCuoO\n"
	"4CYhB7BbUxSriLE4slDoofOtOOyY/tVRR+pojVXy3Ag548eJmvVIm2+EdE3Q6mh1\n"
	"JspLjZK+cpp+ewUGi6uWdv29aRG4Q3QDIr5NtWxQ6wCLQsS7f3mTk2i2f290DnJR\n"
	"ge4q8P/STFptHiD4cRtcpj5C+e9M6qVPQwIDAQABo1cwVTAPBgNVHRMBAf8EBTAD\n"
	"AQH/MA4GA1UdDwEB/wQEAwICpDATBgNVHSUEDDAKBggrBgEFBQcDATAdBgNVHQ4E\n"
	"FgQUsEf5Ef+W4zAMplfY0p9vOQEA+eQwDQYJKoZIhvcNAQELBQADggEBAFmmH0lQ\n"
	"qljBeCoxvELdgm91lTj7IB9aJKYNeFbAxgFr8HutgHWqY6KqWX+zQlNSaQCgNAIs\n"
	"n4uTiI63HScjA0BGilF12UzCAjKVLLlKBdCfuexhUHB3ESAd0XdfEdUpG6nNxYgT\n"
	"HLFZJ2Rtx1SlDYLJDz4DWEeNEsLpvN6aO77KCHCJ67qPLqkQtXYq1CLQVTEqbBzm\n"
	"vSCYl5yeZJtHMfVHg3Z5tHTwC/x+OVH63OkByjFM0pA8KNSxwrPolP+CEq7mDCZE\n"
	"siazwNaMg18O8A7gCX0QusQZUx9xULqRuikQUmCUrGOe79qovYNfu+WUIsizibJ7\n"
	"xB/MtwXoDxrmmJ8=\n"
	"-----END CERTIFICATE-----\n";

// Private key of the http, https and tls certificates (RSA 2048)
static char certdl_key_pem[] =
	"-----BEGIN PRIVATE KEY-----\n"
	"MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDH1GwSv5Io+5+p\n"
	"E/7H5V2v05Yh3PDrBR0u3Z7gIjifHF+1qCRTEAEW7fgZLOUAJj5HCwvMuTxre2fw\n"
	"6XEYh8b/ivjiN1zcWWu84+B8FK3fUeeZ8kZpxhtOx08veIt8mOZMtqsCOGkgVPg3\n"
	"GqrgJmw2IeOX7J4DqlA7QUK9u4ElOhSH9bEK6g7gJiEHsFtTFKuIsTiyUOih8604\n"
	"7Jj+1VFH6miNVfLcCDnjx4ma9Uibb4R0TdDqaHUmykuNkr5ymn57BQaLq5Z2/b1p\n"
	"EbhDdAMivk21bFDrAItCxLt/eZOTaLZ/b3QOclGB7irw/9JMWm0eIPhxG1ymPkL5\n"
	"70zqpU9DAgMBAAECggEAJldRJyW/pwJkh33xKCyPlcFcsIGibg2MpGXcanfWclzw\n"
	"1jt9QLy04M/nBvmQtL8huuLZMD4oZB0I+/Xmf8TpfzWMfGcP961mmRcGBvi2xb8C\n"
	"14xfS0M6ERr3zA1uggkaQwTXefUV4qC7AWOp/pkQsTA+aXN6fAyNGVlzs1DLPjd4\n"
	"TaYU+fBCIoZSFNMs54c44sn5sRRTVeYk5Ww8pN5Bk0SNgQLB64grW/gO3Q051tA8\n"
	"a8dEuujOrXQAJpCg0xpIaXDQLQyBQcFDqSunbYnQ8YAnhDyVjZCP+WobYlBUfEBm\n"
	"EHSrjP17uwBPnrqHVpyfkNgXFQdj5MhBF2tAF+gkJQKBgQDot7lfIEMt/cGiUcAN\n"
	"0jCEEGspn7O7eata6Ha2BU/aPRh7aGVbjnhwtQHOGVfTWEekrBsCoZqXhcpdpH2Q\n"
	"gCQiFVGDULbrP5sV5no68S9u7BCd4uhkHwgTQDJauBG1RyH2wayIt2siZxy+0MR6\n"
	"Jb+YjZZkDSHk4HSJlOvgGZBBLQKBgQDb0mLDyD2vCmNXsLtYXvDJ2aweA819PmcR\n"
	"Oe5RIh5ZeyLbTw56nJozmDjFwTF/kCFdYm6MUZaR4RMyWt8uLTHk+p7I/fe6AGqi\n"
	"+01SKDZMOApeiEu4EJZMbDDdOQ25aqTHewLA9ctdooH4YDyGFlbJvqFSYAkgEGEN\n"
	"fiEGvDW4LwKBgQDMllAaJ9PHh/GGENaFkAZk48ZCFos8wq75QaqzRKI520I9o76P\n"
	"qgWKGCcZGECUpWR+iWtJeebdVJpejrBwq6aYbCN4DSpyUD24GCHW1Zf8rP3Cv+vL\n"
	"sVg5DFP4Wx/+PSXHt+ZFXvKJkRq9Se2g8LSqmbbgCIeGnij1lv1yyyZ9lQKBgC24\n"
	"eYBdIq9IitcPVDgSLyTcmFb51YCqPQexM+c+IG/eE6bnr4xDDDOVAqHnB+OPV9Ez\n"
	"iui2g4m99Z8wlWDmV41XrzUA1cijE4rol/FxmbGKqmV1FcKn+IrWqecpWbhp/PHc\n"
	"nPsDZJQKG9xML+p3tP9rHeSjQuKfZYBH7piXBtlTAoGAJP6JlbzCq2EinqewhieW\n"
	"5hS9SJ6ds9qXcaExg6dLIU3SKn6A4MmfT4aGywNpkRTrnCEjMIi36DfAcPiuSK6P\n"
	"DjT6YifSen3zUSu5yPs0kF1Q2839JHs9eND+wrI9W0eYQjTcrqwYl5vmj9Jgqapp\n"
	"DYbULC42TGbpDpOCNOCapDY=\n"
	"-----END PRIVATE KEY-----\n";

// Load a PEM certificate
static X *CertDlPemToX(const char *pem)
{
	BUF *b = NewBuf();

	WriteBuf(b, pem, StrLen(pem));
	SeekBuf(b, 0, 0);
	X *x = BufToX(b, true);
	FreeBuf(b);

	return x;
}

// Load a PEM private key
static K *CertDlPemToK(const char *pem)
{
	BUF *b = NewBuf();

	WriteBuf(b, pem, StrLen(pem));
	SeekBuf(b, 0, 0);
	K *k = BufToK(b, true, true, NULL);
	FreeBuf(b);

	return k;
}

// File that TryGetRootCertChain saves a downloaded issuer to: chain_certs under the database directory
static void CertDlSavedPath(wchar_t *path, UINT size, X *issuer)
{
	wchar_t db_dir[MAX_SIZE];
	wchar_t dir[MAX_SIZE];
	wchar_t name[MAX_SIZE];
	wchar_t hex[128];
	char hex_a[128];
	UCHAR hash[SHA1_SIZE];

	GetXDigest(issuer, hash, true);
	BinToStr(hex_a, sizeof(hex_a), hash, SHA1_SIZE);
	StrToUni(hex, sizeof(hex), hex_a);

	UniStrCpy(name, sizeof(name), AUTO_DOWNLOAD_CERTS_PREFIX);
	UniStrCat(name, sizeof(name), hex);
	UniStrCat(name, sizeof(name), L".cer");

	GetExeDirW(db_dir, sizeof(db_dir));
	CombinePathW(dir, sizeof(dir), db_dir, L"chain_certs");
	CombinePathW(path, size, dir, name);
}

// Count one request received by the listener and record the first of the run; returns its number in the run
static UINT CertDlRecord(CERTDL_SERVER *srv, HTTP_HEADER *h)
{
	HTTP_VALUE *host = GetHttpValue(h, "Host");
	HTTP_VALUE *agent = GetHttpValue(h, "User-Agent");
	UINT num;

	Lock(srv->Lock);
	{
		num = ++srv->NumRequests;

		if (num == 1)
		{
			Format(srv->RequestLine, sizeof(srv->RequestLine), "%s %s %s", h->Method, h->Target, h->Version);
			StrCpy(srv->Host, sizeof(srv->Host), (host != NULL ? host->Data : ""));
			StrCpy(srv->UserAgent, sizeof(srv->UserAgent), (agent != NULL ? agent->Data : ""));
		}
	}
	Unlock(srv->Lock);

	return num;
}

// Append a string to an answer
static void CertDlWriteStr(BUF *b, const char *str)
{
	WriteBuf(b, str, StrLen(str));
}

// Append the 200 answer with Content-Length and the issuer certificate in DER
static void CertDlWriteOk(const CERTDL_SERVER *srv, BUF *b)
{
	char tmp[MAX_SIZE];

	Format(tmp, sizeof(tmp), "HTTP/1.1 200 OK\r\nContent-Type: application/pkix-cert\r\nContent-Length: %u\r\n\r\n",
		srv->CaDer->Size);
	CertDlWriteStr(b, tmp);
	WriteBuf(b, srv->CaDer->Buf, srv->CaDer->Size);
}

// Answer request number num of the run in the mode of the run; true closes the connection
static bool CertDlRespond(const CERTDL_SERVER *srv, SOCK *s, UINT mode, UINT num)
{
	BUF *b = NewBuf();
	bool close_now = false;
	void *pad;
	char tmp[MAX_SIZE];

	switch (mode)
	{
	case CERTDL_MODE_CONTINUE:
		CertDlWriteStr(b, "HTTP/1.1 100 Continue\r\n\r\n");
		CertDlWriteOk(srv, b);
		break;

	case CERTDL_MODE_REDIRECT:
		if (num == 1)
		{
			CertDlWriteStr(b, "HTTP/1.1 302 Found\r\nLocation: http://" CERTDL_HOST CERTDL_PATH_MOVED "\r\n"
				"Content-Length: 0\r\n\r\n");
		}
		else
		{
			CertDlWriteOk(srv, b);
		}
		break;

	case CERTDL_MODE_NOT_FOUND:
		CertDlWriteStr(b, "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n");
		break;

	case CERTDL_MODE_AUTH:
		CertDlWriteStr(b, "HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Negotiate\r\nWWW-Authenticate: NTLM\r\n"
			"Content-Length: 0\r\n\r\n");
		break;

	case CERTDL_MODE_NO_LENGTH:
		CertDlWriteStr(b, "HTTP/1.1 200 OK\r\nContent-Type: application/pkix-cert\r\nConnection: close\r\n\r\n");
		WriteBuf(b, srv->CaDer->Buf, srv->CaDer->Size);
		close_now = true;
		break;

	case CERTDL_MODE_CHUNKED:
		Format(tmp, sizeof(tmp), "HTTP/1.1 200 OK\r\nContent-Type: application/pkix-cert\r\n"
			"Transfer-Encoding: chunked\r\n\r\n%x\r\n", srv->CaDer->Size);
		CertDlWriteStr(b, tmp);
		WriteBuf(b, srv->CaDer->Buf, srv->CaDer->Size);
		CertDlWriteStr(b, "\r\n0\r\n\r\n");
		break;

	case CERTDL_MODE_OVER_CAP:
		// The connection stays open after the padding: a client that waits for the announced length runs
		// into its receive timeout
		Format(tmp, sizeof(tmp), "HTTP/1.1 200 OK\r\nContent-Type: application/pkix-cert\r\nContent-Length: %u\r\n\r\n",
			CERTDL_BIG_LENGTH);
		CertDlWriteStr(b, tmp);
		WriteBuf(b, srv->CaDer->Buf, srv->CaDer->Size);
		pad = ZeroMalloc(CERTDL_MAX_BODY - srv->CaDer->Size);
		WriteBuf(b, pad, CERTDL_MAX_BODY - srv->CaDer->Size);
		Free(pad);
		break;

	case CERTDL_MODE_SILENT:
		// No answer: the connection stays open until the client gives up
		break;

	default:
		// CERTDL_MODE_OK and CERTDL_MODE_TLS
		CertDlWriteOk(srv, b);
		break;
	}

	bool ok = (b->Size == 0 || SendAll(s, b->Buf, b->Size, s->SecureMode));
	FreeBuf(b);

	return (close_now || ok == false);
}

// One listener connection: answer requests until the client closes the connection
static void CertDlConnThread(THREAD *thread, void *param)
{
	CERTDL_CONN *c = (CERTDL_CONN *)param;
	CERTDL_SERVER *srv = c->Server;
	SOCK *s = c->Sock;
	UINT mode;

	Lock(srv->Lock);
	{
		mode = srv->Mode;
	}
	Unlock(srv->Lock);

	SetTimeout(s, CERTDL_CONN_TIMEOUT);

	if (mode == CERTDL_MODE_TLS && StartSSLEx(s, srv->TlsCert, srv->TlsKey, NULL) == false)
	{
		Disconnect(s);
		return;
	}

	while (true)
	{
		HTTP_HEADER *h = RecvHttpHeader(s);

		if (h == NULL)
		{
			break;
		}

		bool close_now = CertDlRespond(srv, s, mode, CertDlRecord(srv, h));
		FreeHttpHeader(h);

		if (close_now)
		{
			break;
		}
	}

	Disconnect(s);
}

// Accept connections until the listening socket is disconnected; one thread per connection
static void CertDlAcceptThread(THREAD *thread, void *param)
{
	CERTDL_SERVER *srv = (CERTDL_SERVER *)param;

	while (true)
	{
		SOCK *s = Accept(srv->ListenSock);

		if (s == NULL)
		{
			break;
		}

		CERTDL_CONN *c = ZeroMalloc(sizeof(CERTDL_CONN));
		c->Server = srv;
		c->Sock = s;

		LockList(srv->ConnList);
		{
			Add(srv->ConnList, c);
			c->Thread = NewThread(CertDlConnThread, c);
		}
		UnlockList(srv->ConnList);
	}
}

// Start the listener on 127.0.0.1:CERTDL_PORT; tls_cert and tls_key must outlive it
static CERTDL_SERVER *CertDlStartServer(X *issuer, X *tls_cert, K *tls_key)
{
	IP loopback;

	GetLocalHostIP4(&loopback);
	SOCK *s = Listen(CERTDL_PORT, &loopback, false);

	if (s == NULL)
	{
		return NULL;
	}

	CERTDL_SERVER *srv = ZeroMalloc(sizeof(CERTDL_SERVER));
	srv->ListenSock = s;
	srv->ConnList = NewList(NULL);
	srv->CaDer = XToBuf(issuer, false);
	srv->TlsCert = tls_cert;
	srv->TlsKey = tls_key;
	srv->Lock = NewLock();
	srv->Mode = CERTDL_MODE_OK;
	srv->AcceptThread = NewThread(CertDlAcceptThread, srv);

	return srv;
}

// Stop the listener and wait for its connection threads
static void CertDlStopServer(CERTDL_SERVER *srv)
{
	if (srv == NULL)
	{
		return;
	}

	Disconnect(srv->ListenSock);
	WaitThread(srv->AcceptThread, INFINITE);
	ReleaseThread(srv->AcceptThread);

	// The accept thread has ended: ConnList no longer changes
	for (UINT i = 0;i < LIST_NUM(srv->ConnList);i++)
	{
		CERTDL_CONN *c = LIST_DATA(srv->ConnList, i);

		Disconnect(c->Sock);
		WaitThread(c->Thread, INFINITE);
		ReleaseThread(c->Thread);
		ReleaseSock(c->Sock);
		Free(c);
	}
	ReleaseList(srv->ConnList);

	ReleaseSock(srv->ListenSock);
	FreeBuf(srv->CaDer);
	DeleteLock(srv->Lock);
	Free(srv);
}

// Set a server certificate through the admin RPC while the listener answers in one mode, and collect the outcome
static void CertDlRun(HARNESS *h, CERTDL_SERVER *srv, char *name, UINT mode, X *cert, K *key, wchar_t *saved_file,
	CERTDL_RESULT *r)
{
	RPC_KEY_PAIR t;

	Zero(r, sizeof(CERTDL_RESULT));

	Lock(srv->Lock);
	{
		srv->Mode = mode;
		srv->NumRequests = 0;
		srv->RequestLine[0] = 0;
		srv->Host[0] = 0;
		srv->UserAgent[0] = 0;
	}
	Unlock(srv->Lock);

	Zero(&t, sizeof(t));
	t.Cert = CloneX(cert);
	t.Key = CloneK(key);

	UINT64 start = Tick64();
	r->Err = ScSetServerCert(h->Rpc, &t);
	r->Elapsed = Tick64() - start;
	r->Flag1 = t.Flag1;
	FreeRpcKeyPair(&t);

	Print("TIME certdl_%s %I64u ms\n", name, r->Elapsed);

	// The listener records a request before it answers, and the RPC returns after the answer
	Lock(srv->Lock);
	{
		r->NumRequests = srv->NumRequests;
		StrCpy(r->RequestLine, sizeof(r->RequestLine), srv->RequestLine);
		StrCpy(r->Host, sizeof(r->Host), srv->Host);
		StrCpy(r->UserAgent, sizeof(r->UserAgent), srv->UserAgent);
	}
	Unlock(srv->Lock);

	// A saved issuer would satisfy the next run without a download
	r->Saved = IsFileExistsW(saved_file);
	FileDeleteW(saved_file);
}

// Check a number; a failure also prints the value seen
static bool CertDlCheckUint(HARNESS *h, char *what, UINT actual, UINT expected)
{
	bool ok = (actual == expected);

	if (HarnessCheck(h, ok, what) == false)
	{
		Print("    got %u, expected %u\n", actual, expected);
	}

	return ok;
}

// Check a string; a failure also prints the value seen
static bool CertDlCheckStr(HARNESS *h, char *what, char *actual, char *expected)
{
	bool ok = (StrCmp(actual, expected) == 0);

	if (HarnessCheck(h, ok, what) == false)
	{
		Print("    got \"%s\", expected \"%s\"\n", actual, expected);
	}

	return ok;
}

// Check the outcome of one run: the RPC succeeds, the listener gets one request, the server builds and saves the
// chain (chain) or reports no issuer, and the run waits for the client receive timeout (waits) or not
static void CertDlExpect(HARNESS *h, char *name, const CERTDL_RESULT *r, bool chain, bool waits)
{
	bool ok;
	char tmp[MAX_SIZE];

	Format(tmp, sizeof(tmp), "%s: SetServerCert", name);
	HarnessCheckErr(h, r->Err, tmp);

	Format(tmp, sizeof(tmp), "%s: the listener received one request", name);
	CertDlCheckUint(h, tmp, r->NumRequests, 1);

	if (chain)
	{
		Format(tmp, sizeof(tmp), "%s: the server built the chain with the downloaded issuer (Flag1)", name);
	}
	else
	{
		Format(tmp, sizeof(tmp), "%s: the server got no issuer (Flag1)", name);
	}
	CertDlCheckUint(h, tmp, r->Flag1, (chain ? 1 : 0));

	if (chain)
	{
		Format(tmp, sizeof(tmp), "%s: the server saved the issuer under chain_certs", name);
	}
	else
	{
		Format(tmp, sizeof(tmp), "%s: nothing saved under chain_certs", name);
	}
	HarnessCheck(h, r->Saved == chain, tmp);

	if (waits)
	{
		Format(tmp, sizeof(tmp), "%s: the server gave up after the receive timeout (%u to %u ms)", name,
			CERTDL_TIMEOUT_MIN, CERTDL_SLOW_LIMIT);
		ok = (r->Elapsed >= CERTDL_TIMEOUT_MIN && r->Elapsed < CERTDL_SLOW_LIMIT);
	}
	else
	{
		Format(tmp, sizeof(tmp), "%s: no wait for a timeout (under %u ms)", name, CERTDL_QUICK_LIMIT);
		ok = (r->Elapsed < CERTDL_QUICK_LIMIT);
	}

	if (HarnessCheck(h, ok, tmp) == false)
	{
		Print("    took %I64u ms\n", r->Elapsed);
	}
}

////////////////////////////
// Listener bind status ("listenerbind", FIX-3 #99)

// State of the listener on a port through EnumListener (what ListenerList shows); false when it is not listed
static bool ListenBindState(HARNESS *h, UINT port, bool *enabled, bool *error)
{
	RPC_LISTENER_LIST t;
	bool found = false;

	*enabled = false;
	*error = false;

	Zero(&t, sizeof(t));
	if (ScEnumListener(h->Rpc, &t) != ERR_NO_ERROR)
	{
		return false;
	}

	for (UINT i = 0;i < t.NumPort;i++)
	{
		if (t.Ports[i] == port)
		{
			found = true;
			*enabled = t.Enables[i];
			*error = t.Errors[i];
		}
	}

	FreeRpcListenerList(&t);

	return found;
}

// ListenerCreate (create true) or ListenerEnable / ListenerDisable of a port through the admin RPC, timed
static UINT ListenBindCall(HARNESS *h, bool create, UINT port, bool enable, UINT64 *elapsed)
{
	RPC_LISTENER t;

	Zero(&t, sizeof(t));
	t.Port = port;
	t.Enable = enable;

	UINT64 start = Tick64();
	UINT err = (create ? ScCreateListener(h->Rpc, &t) : ScEnableListener(h->Rpc, &t));
	*elapsed = Tick64() - start;

	return err;
}

// Check the error of a timed listener RPC and that it returned well before the server's bind wait limit,
// so the listener thread's bind event (failed or successful bind) ended the wait
static bool ListenBindExpect(HARNESS *h, char *name, char *what, UINT err, UINT expected, UINT64 elapsed)
{
	char tmp[MAX_SIZE];

	Print("TIME listenerbind_%s %I64u ms\n", name, elapsed);

	if (err == expected)
	{
		Format(tmp, sizeof(tmp), "%s: error %u", what, err);
	}
	else
	{
		Format(tmp, sizeof(tmp), "%s: error %u (%S), expected %u (%S)", what, err, _E(err), expected, _E(expected));
	}
	bool ok = HarnessCheck(h, err == expected, tmp);

	Format(tmp, sizeof(tmp), "%s: returned within %u ms", what, LISTENBIND_RPC_LIMIT);
	ok = HarnessCheck(h, elapsed < LISTENBIND_RPC_LIMIT, tmp) && ok;

	return ok;
}

// Check that ListenerList shows the listener on a port enabled and not in error state
static bool ListenBindIsListening(HARNESS *h, UINT port, char *what)
{
	bool enabled, error;
	bool listed = ListenBindState(h, port, &enabled, &error);

	return HarnessCheck(h, listed && enabled && error == false, what);
}

////////////////////////////
// Admin audit lines and configuration revision ("adminaudit", FND-10 #107)

// Read syslog datagrams until one holds the marker text or the timeout passes. The datagrams before the marker are
// lines of the current step (a->Lines). True when the marker arrived
static bool AdminAuditCollect(ADMINAUDIT *a, UINT timeout)
{
	UINT64 end = Tick64() + (UINT64)timeout;
	char buf[ADMINAUDIT_LINE_MAX + 1];

	while (true)
	{
		SOCKSET set;

		while (true)
		{
			IP src;
			UINT src_port;
			UINT size = RecvFrom(a->Udp, &src, &src_port, buf, ADMINAUDIT_LINE_MAX);

			if (size == 0 || size == SOCK_LATER)
			{
				break;
			}

			buf[size] = 0;
			if (InStr(buf, a->Marker))
			{
				return true;
			}

			Add(a->Lines, CopyStr(buf));
		}

		UINT64 now = Tick64();
		if (now >= end)
		{
			return false;
		}

		InitSockSet(&set);
		AddSockSet(&set, a->Udp);
		Select(&set, (UINT)(end - now), NULL, NULL);
	}
}

// GetConfig, then read the syslog lines up to its LA_GET_CONFIG line: every line an earlier call logged arrived
// before it (the server sends its syslog datagrams in order from one socket while it handles the call)
static bool AdminAuditSync(ADMINAUDIT *a)
{
	RPC_CONFIG c;

	Zero(&c, sizeof(c));
	if (ScGetConfig(a->H->Rpc, &c) != ERR_NO_ERROR)
	{
		return false;
	}
	FreeRpcConfig(&c);

	return AdminAuditCollect(a, ADMINAUDIT_LOG_TIMEOUT);
}

// Start a step: drop the lines of the last step and keep the configuration revision
static void AdminAuditBegin(ADMINAUDIT *a)
{
	for (UINT i = 0;i < LIST_NUM(a->Lines);i++)
	{
		Free(LIST_DATA(a->Lines, i));
	}
	DeleteAll(a->Lines);

	a->Revision = a->H->Server->ConfigRevision;
}

// A line of the current step holds the text
static bool AdminAuditLogged(ADMINAUDIT *a, wchar_t *text)
{
	char *s = HarnessUniToUtf8(text);
	bool ret = false;

	for (UINT i = 0;i < LIST_NUM(a->Lines);i++)
	{
		if (InStr(LIST_DATA(a->Lines, i), s))
		{
			ret = true;
			break;
		}
	}

	Free(s);

	return ret;
}

// End a step: the error code of its call, the audit line it must write (logged) or must not write (not_logged), and
// whether the configuration revision changed
static void AdminAuditEnd(ADMINAUDIT *a, char *what, UINT err, UINT expected, wchar_t *logged, wchar_t *not_logged,
	bool bumped)
{
	HARNESS *h = a->H;
	char tmp[MAX_SIZE];

	HarnessExpectErr(h, err, expected, what);

	if (AdminAuditSync(a) == false)
	{
		Format(tmp, sizeof(tmp), "%s: the GetConfig line reaches the syslog receiver within %u ms", what,
			ADMINAUDIT_LOG_TIMEOUT);
		HarnessCheck(h, false, tmp);
		return;
	}

	if (logged != NULL)
	{
		Format(tmp, sizeof(tmp), "%s: audit line \"%S\" written", what, logged);
		HarnessCheck(h, AdminAuditLogged(a, logged), tmp);
	}

	if (not_logged != NULL)
	{
		Format(tmp, sizeof(tmp), "%s: no audit line \"%S\"", what, not_logged);
		HarnessCheck(h, AdminAuditLogged(a, not_logged) == false, tmp);
	}

	bool changed = (h->Server->ConfigRevision != a->Revision);
	Format(tmp, sizeof(tmp), "%s: configuration revision %s", what, bumped ? "incremented" : "unchanged");
	HarnessCheck(h, changed == bumped, tmp);
}

// Text of a string table entry with up to two string arguments, as ALog formats it
static wchar_t *AdminAuditText(wchar_t *buf, UINT size, char *name, char *arg1, char *arg2)
{
	UniFormat(buf, size, _UU(name), arg1, arg2);

	return buf;
}

// Release the receiver (a may be NULL)
static void AdminAuditFree(ADMINAUDIT *a)
{
	if (a == NULL)
	{
		return;
	}

	for (UINT i = 0;i < LIST_NUM(a->Lines);i++)
	{
		Free(LIST_DATA(a->Lines, i));
	}
	ReleaseList(a->Lines);

	if (a->Udp != NULL)
	{
		ReleaseSock(a->Udp);
	}

	Free(a->Marker);
	Free(a);
}

// Open the syslog receiver on 127.0.0.1 and point the server log and the hub security log at it (SetSysLog). The
// lines of the setup are read up to a first GetConfig line. NULL on failure
static ADMINAUDIT *AdminAuditNew(HARNESS *h)
{
	ADMINAUDIT *a = ZeroMalloc(sizeof(ADMINAUDIT));
	SYSLOG_SETTING s;
	SOCKSET set;
	IP localhost;

	a->H = h;
	a->Lines = NewListFast(NULL);
	a->Marker = HarnessUniToUtf8(_UU("LA_GET_CONFIG"));

	SetIP(&localhost, 127, 0, 0, 1);
	a->Udp = NewUDPEx3(0, &localhost);
	bool ok = HarnessCheck(h, a->Udp != NULL, "syslog receiver bound on 127.0.0.1");

	if (ok)
	{
		// Select() puts the socket in non-blocking mode: RecvFrom then returns SOCK_LATER when no datagram is left
		InitSockSet(&set);
		AddSockSet(&set, a->Udp);
		Select(&set, 0, NULL, NULL);

		Zero(&s, sizeof(s));
		s.SaveType = SYSLOG_SERVER_AND_HUB_SECURITY_LOG;
		StrCpy(s.Hostname, sizeof(s.Hostname), "127.0.0.1");
		s.Port = a->Udp->LocalPort;
		ok = HarnessCheckErr(h, ScSetSysLog(h->Rpc, &s), "SetSysLog: server log and hub security log to the receiver");
	}

	if (ok)
	{
		AdminAuditBegin(a);
		ok = HarnessCheck(h, AdminAuditSync(a), "the GetConfig line of the setup reaches the syslog receiver");
	}

	if (ok == false)
	{
		AdminAuditFree(a);
		return NULL;
	}

	return a;
}

// EnumUser only reads; DeleteUser logs and changes the configuration only when it deleted a user
static void AdminAuditUsers(ADMINAUDIT *a)
{
	RPC_ENUM_USER e;
	RPC_DELETE_USER d;
	wchar_t text[MAX_SIZE];

	Print("[users]\n");

	Zero(&e, sizeof(e));
	StrCpy(e.HubName, sizeof(e.HubName), HARNESS_HUB_A);
	AdminAuditBegin(a);
	UINT err = ScEnumUser(a->H->Rpc, &e);
	if (err == ERR_NO_ERROR)
	{
		FreeRpcEnumUser(&e);
	}
	AdminAuditEnd(a, "EnumUser " HARNESS_HUB_A, err, ERR_NO_ERROR, NULL, NULL, false);

	AdminAuditText(text, sizeof(text), "LA_DELETE_USER", ADMINAUDIT_USER, NULL);
	Zero(&d, sizeof(d));
	StrCpy(d.HubName, sizeof(d.HubName), HARNESS_HUB_A);
	StrCpy(d.Name, sizeof(d.Name), ADMINAUDIT_USER);
	AdminAuditBegin(a);
	err = ScDeleteUser(a->H->Rpc, &d);
	AdminAuditEnd(a, "DeleteUser " ADMINAUDIT_USER, err, ERR_NO_ERROR, text, NULL, true);

	AdminAuditText(text, sizeof(text), "LA_DELETE_USER", ADMINAUDIT_NO_USER, NULL);
	Zero(&d, sizeof(d));
	StrCpy(d.HubName, sizeof(d.HubName), HARNESS_HUB_A);
	StrCpy(d.Name, sizeof(d.Name), ADMINAUDIT_NO_USER);
	AdminAuditBegin(a);
	err = ScDeleteUser(a->H->Rpc, &d);
	AdminAuditEnd(a, "DeleteUser " ADMINAUDIT_NO_USER " (no such user)", err, ERR_OBJECT_NOT_FOUND, NULL, text, false);
}

// CreateGroup of a group on hub HARNESS_HUB_A
static UINT AdminAuditCreateGroup(const ADMINAUDIT *a, const char *name)
{
	RPC_SET_GROUP t;

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), HARNESS_HUB_A);
	StrCpy(t.Name, sizeof(t.Name), name);

	UINT err = ScCreateGroup(a->H->Rpc, &t);
	if (err == ERR_NO_ERROR)
	{
		FreeRpcSetGroup(&t);
	}

	return err;
}

// Hub admin option max_groups 1 on hub HARNESS_HUB_A (the other options keep their defaults)
static bool AdminAuditMaxGroups(ADMINAUDIT *a)
{
	RPC_ADMIN_OPTION o;

	Zero(&o, sizeof(o));
	StrCpy(o.HubName, sizeof(o.HubName), HARNESS_HUB_A);
	o.NumItem = 1;
	o.Items = ZeroMalloc(sizeof(ADMIN_OPTION));
	StrCpy(o.Items[0].Name, sizeof(o.Items[0].Name), "max_groups");
	o.Items[0].Value = 1;

	UINT err = ScSetHubAdminOptions(a->H->Rpc, &o);
	if (err == ERR_NO_ERROR)
	{
		FreeRpcAdminOption(&o);
	}

	return HarnessCheckErr(a->H, err, "SetHubAdminOptions " HARNESS_HUB_A ": max_groups 1");
}

// CreateGroup and DeleteGroup log and change the configuration only when they created or deleted a group
static void AdminAuditGroups(ADMINAUDIT *a)
{
	RPC_DELETE_USER d;
	wchar_t text[MAX_SIZE];

	Print("[groups]\n");

	AdminAuditText(text, sizeof(text), "LA_CREATE_GROUP", ADMINAUDIT_GROUP, NULL);
	AdminAuditBegin(a);
	UINT err = AdminAuditCreateGroup(a, ADMINAUDIT_GROUP);
	AdminAuditEnd(a, "CreateGroup " ADMINAUDIT_GROUP, err, ERR_NO_ERROR, text, NULL, true);

	AdminAuditBegin(a);
	err = AdminAuditCreateGroup(a, ADMINAUDIT_GROUP);
	AdminAuditEnd(a, "CreateGroup " ADMINAUDIT_GROUP " again (exists)", err, ERR_GROUP_ALREADY_EXISTS, NULL, text, false);

	if (AdminAuditMaxGroups(a))
	{
		AdminAuditText(text, sizeof(text), "LA_CREATE_GROUP", ADMINAUDIT_GROUP2, NULL);
		AdminAuditBegin(a);
		err = AdminAuditCreateGroup(a, ADMINAUDIT_GROUP2);
		AdminAuditEnd(a, "CreateGroup " ADMINAUDIT_GROUP2 " (over max_groups 1)", err, ERR_TOO_MANY_GROUP, NULL, text,
			false);
	}

	AdminAuditText(text, sizeof(text), "LA_DELETE_GROUP", ADMINAUDIT_GROUP, NULL);
	Zero(&d, sizeof(d));
	StrCpy(d.HubName, sizeof(d.HubName), HARNESS_HUB_A);
	StrCpy(d.Name, sizeof(d.Name), ADMINAUDIT_GROUP);
	AdminAuditBegin(a);
	err = ScDeleteGroup(a->H->Rpc, &d);
	AdminAuditEnd(a, "DeleteGroup " ADMINAUDIT_GROUP, err, ERR_NO_ERROR, text, NULL, true);

	Zero(&d, sizeof(d));
	StrCpy(d.HubName, sizeof(d.HubName), HARNESS_HUB_A);
	StrCpy(d.Name, sizeof(d.Name), ADMINAUDIT_GROUP);
	AdminAuditBegin(a);
	err = ScDeleteGroup(a->H->Rpc, &d);
	AdminAuditEnd(a, "DeleteGroup " ADMINAUDIT_GROUP " again (no such group)", err, ERR_OBJECT_NOT_FOUND, NULL, text,
		false);
}

// CRL entry with the CommonName ADMINAUDIT_CRL_NAME
static CRL *AdminAuditNewCrl()
{
	CRL *crl = ZeroMalloc(sizeof(CRL));

	crl->Name = NewName(ADMINAUDIT_CRL_NAME, NULL, NULL, NULL, NULL, NULL);

	return crl;
}

// Key of the one CRL entry of hub HARNESS_HUB_A (EnumCrl)
static bool AdminAuditCrlKey(ADMINAUDIT *a, UINT *key)
{
	RPC_ENUM_CRL e;

	*key = 0;

	Zero(&e, sizeof(e));
	StrCpy(e.HubName, sizeof(e.HubName), HARNESS_HUB_A);
	UINT err = ScEnumCrl(a->H->Rpc, &e);
	if (err == ERR_NO_ERROR)
	{
		if (e.NumItem == 1)
		{
			*key = e.Items[0].Key;
		}
		FreeRpcEnumCrl(&e);
	}

	return HarnessCheck(a->H, err == ERR_NO_ERROR && *key != 0, "EnumCrl lists the one CRL entry of " HARNESS_HUB_A);
}

// Flush, then whether the saved configuration file holds the CRL entry
static void AdminAuditCheckSaved(ADMINAUDIT *a, bool expected, char *what)
{
	RPC_TEST t;

	Zero(&t, sizeof(t));
	if (HarnessCheckErr(a->H, ScFlush(a->H->Rpc, &t), "Flush (the server writes " HARNESS_CONFIG_FILE ")") == false)
	{
		return;
	}

	BUF *b = ReadDump(HARNESS_CONFIG_FILE);
	char *s = HarnessBufToStr(b);

	HarnessCheck(a->H, b != NULL && InStr(s, ADMINAUDIT_CRL_NAME_A) == expected, what);

	Free(s);
	FreeBuf(b);
}

// AddCrl writes "added"; DelCrl changes the configuration revision as AddCrl does
static void AdminAuditCrl(ADMINAUDIT *a)
{
	RPC_CRL t;
	wchar_t add_text[MAX_SIZE];
	wchar_t del_text[MAX_SIZE];
	UINT key;

	Print("[certificate revocation list]\n");

	AdminAuditText(add_text, sizeof(add_text), "LA_ADD_CRL", NULL, NULL);
	AdminAuditText(del_text, sizeof(del_text), "LA_DEL_CRL", NULL, NULL);

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), HARNESS_HUB_A);
	t.Crl = AdminAuditNewCrl();
	AdminAuditBegin(a);
	UINT err = ScAddCrl(a->H->Rpc, &t);
	if (err == ERR_NO_ERROR)
	{
		FreeRpcCrl(&t);
	}
	AdminAuditEnd(a, "AddCrl " ADMINAUDIT_CRL_NAME_A, err, ERR_NO_ERROR, add_text, NULL, true);

	AdminAuditCheckSaved(a, true, "the saved configuration holds the CRL entry " ADMINAUDIT_CRL_NAME_A);

	if (AdminAuditCrlKey(a, &key) == false)
	{
		return;
	}

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), HARNESS_HUB_A);
	t.Key = key;
	AdminAuditBegin(a);
	err = ScDelCrl(a->H->Rpc, &t);
	if (err == ERR_NO_ERROR)
	{
		FreeRpcCrl(&t);
	}
	AdminAuditEnd(a, "DelCrl " ADMINAUDIT_CRL_NAME_A, err, ERR_NO_ERROR, del_text, NULL, true);

	AdminAuditCheckSaved(a, false, "the saved configuration no longer holds the CRL entry " ADMINAUDIT_CRL_NAME_A);
}

// DeleteSession writes its line when it disconnected the session, not when it failed
static void AdminAuditSession(ADMINAUDIT *a, char *session)
{
	RPC_DELETE_SESSION t;
	wchar_t text[MAX_SIZE];

	Print("[sessions]\n");

	AdminAuditText(text, sizeof(text), "LA_DELETE_SESSION", ADMINAUDIT_NO_SESSION, NULL);
	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), HARNESS_HUB_A);
	StrCpy(t.Name, sizeof(t.Name), ADMINAUDIT_NO_SESSION);
	AdminAuditBegin(a);
	UINT err = ScDeleteSession(a->H->Rpc, &t);
	AdminAuditEnd(a, "DeleteSession " ADMINAUDIT_NO_SESSION " (no such session)", err, ERR_OBJECT_NOT_FOUND, NULL, text,
		false);

	AdminAuditText(text, sizeof(text), "LA_DELETE_SESSION", session, NULL);
	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), HARNESS_HUB_A);
	StrCpy(t.Name, sizeof(t.Name), session);
	AdminAuditBegin(a);
	err = ScDeleteSession(a->H->Rpc, &t);
	AdminAuditEnd(a, "DeleteSession of test session A", err, ERR_NO_ERROR, text, NULL, false);

	// The client would log in again after its retry interval
	HarnessStopSession(a->H->PaA);
}

// DeleteLocalBridge writes its line only when it deleted a Local Bridge
static void AdminAuditBridge(ADMINAUDIT *a)
{
	RPC_LOCALBRIDGE t;
	wchar_t text[MAX_SIZE];

	Print("[local bridge]\n");

	AdminAuditText(text, sizeof(text), "LA_DELETE_BRIDGE", HARNESS_HUB_A, ADMINAUDIT_NO_DEVICE);
	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), HARNESS_HUB_A);
	StrCpy(t.DeviceName, sizeof(t.DeviceName), ADMINAUDIT_NO_DEVICE);
	AdminAuditBegin(a);
	UINT err = ScDeleteLocalBridge(a->H->Rpc, &t);
	AdminAuditEnd(a, "DeleteLocalBridge " ADMINAUDIT_NO_DEVICE " (no such bridge)", err, ERR_OBJECT_NOT_FOUND, NULL,
		text, false);
}

// One AddCa of a certificate on hub HARNESS_HUB_A: the line and the revision change only when the hub added it
static void AdminAuditAddCa(ADMINAUDIT *a, X *x, char *what, bool added)
{
	RPC_HUB_ADD_CA t;
	wchar_t text[MAX_SIZE];

	AdminAuditText(text, sizeof(text), "LA_ADD_CA", NULL, NULL);

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), HARNESS_HUB_A);
	t.Cert = CloneX(x);
	AdminAuditBegin(a);
	UINT err = ScAddCa(a->H->Rpc, &t);
	if (err == ERR_NO_ERROR)
	{
		FreeRpcHubAddCa(&t);
	}
	AdminAuditEnd(a, what, err, ERR_NO_ERROR, added ? text : NULL, added ? NULL : text, added);
}

// AddCa logs and changes the configuration after the hub added the certificate; the hub ignores a certificate it
// already trusts, and the call still succeeds
static void AdminAuditCa(ADMINAUDIT *a)
{
	RPC_KEY_PAIR k;

	Print("[trusted CA certificates]\n");

	Zero(&k, sizeof(k));
	if (HarnessCheckErr(a->H, ScGetServerCert(a->H->Rpc, &k), "GetServerCert (the certificate AddCa registers)") == false)
	{
		return;
	}

	AdminAuditAddCa(a, k.Cert, "AddCa of the server certificate", true);
	AdminAuditAddCa(a, k.Cert, "AddCa of the same certificate again (already trusted)", false);

	FreeRpcKeyPair(&k);
}

////////////////////////////
// Log records of untrusted text (PKG-4, #108)

#define	HARNESS_LOG_TIMEOUT			5000				// A record reaches its log file or its syslog datagram

// Lines of a log text with the marker of a case and with its forged text (the text after an injected CR LF)
typedef struct HARNESS_LOG_SCAN
{
	UINT NumMarker;				// Lines with the marker
	UINT NumForged;				// Lines with the forged text
	UINT NumBoth;				// Lines with both
	UINT NumCr;					// Lines with either that still hold a CR
} HARNESS_LOG_SCAN;

// Text of every .log file in a log folder of the server (HUB_SECURITY_LOG_FILE_NAME or HUB_PACKET_LOG_FILE_NAME
// of a hub), joined. The server keeps its current file open, so the files are read with write sharing
static char *HarnessReadLogDir(const char *dir_fmt, char *hubname)
{
	char dir[MAX_PATH];
	wchar_t full[MAX_SIZE];
	wchar_t path[MAX_SIZE];
	BUF *b = NewBuf();

	Format(dir, sizeof(dir), dir_fmt, hubname);
	wchar_t *dir_w = CopyStrToUni(dir);
	InnerFilePathW(full, sizeof(full), dir_w);
	Free(dir_w);

	// EnumDirW does not resolve the '@' prefix: use the full path
	DIRLIST *d = EnumDirW(full);
	if (d != NULL)
	{
		for (UINT i = 0;i < d->NumFiles;i++)
		{
			DIRENT *e = d->File[i];

			if (e->Folder == false && UniEndWith(e->FileNameW, L".log"))
			{
				CombinePathW(path, sizeof(path), full, e->FileNameW);
				BUF *f = ReadDumpExW(path, false, 0);
				if (f != NULL)
				{
					WriteBuf(b, f->Buf, f->Size);
					WriteBuf(b, "\r\n", 2);
					FreeBuf(f);
				}
			}
		}

		FreeDir(d);
	}

	char *ret = HarnessBufToStr(b);
	FreeBuf(b);

	return ret;
}

// Whether a string holds a CR or an LF (InStr trims its keyword, so it cannot look for them)
static bool HarnessHasLineBreak(const char *s)
{
	for (;*s != 0;s++)
	{
		if (*s == '\r' || *s == '\n')
		{
			return true;
		}
	}

	return false;
}

// Count the lines of a log text with the marker and with the forged text
static void HarnessScanLog(char *text, const char *marker, const char *forged, HARNESS_LOG_SCAN *r)
{
	LIST *lines = HarnessSplitLines(text);

	Zero(r, sizeof(HARNESS_LOG_SCAN));

	for (UINT i = 0;i < LIST_NUM(lines);i++)
	{
		char *line = LIST_DATA(lines, i);
		bool has_marker = InStrEx(line, marker, true);
		bool has_forged = InStrEx(line, forged, true);

		if (has_marker)
		{
			r->NumMarker++;
		}
		if (has_forged)
		{
			r->NumForged++;
		}
		if (has_marker && has_forged)
		{
			r->NumBoth++;
		}
		if ((has_marker || has_forged) && HarnessHasLineBreak(line))
		{
			r->NumCr++;
		}
	}

	HarnessFreeLines(lines);
}

// Wait until a log folder of a hub holds a line with the marker (or HARNESS_LOG_TIMEOUT), then count its lines
static void HarnessWaitLog(const char *dir_fmt, char *hubname, const char *marker, const char *forged, HARNESS_LOG_SCAN *r)
{
	UINT64 end = Tick64() + HARNESS_LOG_TIMEOUT;

	while (true)
	{
		char *text = HarnessReadLogDir(dir_fmt, hubname);

		HarnessScanLog(text, marker, forged, r);
		Free(text);

		if (r->NumMarker != 0 || Tick64() >= end)
		{
			break;
		}

		SleepThread(100);
	}
}

// Next datagram on the syslog socket of the test as a string, NULL when none arrives within timeout ms
static char *HarnessRecvSyslog(SOCK *s, UINT timeout)
{
	UINT64 end = Tick64() + (UINT64)timeout;
	UCHAR buf[2048];

	while (true)
	{
		SOCKSET set;
		IP src_ip;
		UINT src_port;
		UINT64 now = Tick64();

		// Select() also puts the socket in non-blocking mode for RecvFrom()
		InitSockSet(&set);
		AddSockSet(&set, s);
		Select(&set, (UINT)(now < end ? MIN(end - now, 100) : 0), NULL, NULL);

		UINT size = RecvFrom(s, &src_ip, &src_port, buf, sizeof(buf) - 1);
		if (size != 0 && size != SOCK_LATER)
		{
			char *ret = ZeroMalloc(size + 1);

			Copy(ret, buf, size);

			return ret;
		}

		if (Tick64() >= end)
		{
			return NULL;
		}
	}
}

// Next syslog datagram with the marker (others are skipped), NULL when none arrives within HARNESS_LOG_TIMEOUT
static char *HarnessRecvSyslogWith(SOCK *s, const char *marker)
{
	UINT64 end = Tick64() + HARNESS_LOG_TIMEOUT;

	while (true)
	{
		UINT64 now = Tick64();

		if (now >= end)
		{
			return NULL;
		}

		char *d = HarnessRecvSyslog(s, (UINT)(end - now));
		if (d == NULL)
		{
			return NULL;
		}

		if (InStrEx(d, marker, true))
		{
			return d;
		}

		Free(d);
	}
}

// Send the syslog of the server to the loopback socket of the test with save_type; old gets the setting before
static bool HarnessSetSyslog(HARNESS *h, UINT save_type, UINT port, SYSLOG_SETTING *old)
{
	SYSLOG_SETTING t;

	Zero(old, sizeof(SYSLOG_SETTING));
	UINT err = ScGetSysLog(h->Rpc, old);
	if (HarnessCheckErr(h, err, "GetSysLog") == false)
	{
		return false;
	}

	Zero(&t, sizeof(t));
	t.SaveType = save_type;
	StrCpy(t.Hostname, sizeof(t.Hostname), "127.0.0.1");
	t.Port = port;

	err = ScSetSysLog(h->Rpc, &t);

	return HarnessCheckErr(h, err, "SetSysLog to the loopback socket of the test");
}

// Restore the syslog setting saved by HarnessSetSyslog
static void HarnessRestoreSyslog(HARNESS *h, SYSLOG_SETTING *old)
{
	HarnessCheckErr(h, ScSetSysLog(h->Rpc, old), "SetSysLog restores the setting");
}

// A login to hub HARNESS_HUB_A with a user name that does not exist: the hub logs the connection and the failed
// authentication, both with the user name. Stop it with HarnessStopSession and HarnessFreePa
static HARNESS_PA *HarnessStartLogin(HARNESS *h, char *username)
{
	HARNESS_PA *p = HarnessNewPa("login");

	HarnessStartSession(h, p, HARNESS_HUB_A, username);

	return p;
}

// LOGINJECT (FND-17): a login with a CR LF in the user name, and a DNS query with a CR LF in the query name. The
// security log, the packet log and the syslog datagram keep the forged text on the line of its record
static void HarnessLogInject(HARNESS *h)
{
	char tag[16];
	char marker[64];
	char forged[64];
	char text[MAX_SIZE];
	UCHAR query[256];
	UCHAR frame[512];
	HARNESS_LOG_SCAN scan;
	SYSLOG_SETTING old;
	IP localhost;
	char *d;

	Print("[logs: LOGINJECT]\n");

	// Security log file (syslog off): the user name of a login
	Format(tag, sizeof(tag), "%08X", Rand32());
	Format(marker, sizeof(marker), "inject%s", tag);
	Format(forged, sizeof(forged), "FORGED%s", tag);
	Format(text, sizeof(text), "%s\r\n%s", marker, forged);

	HARNESS_PA *login = HarnessStartLogin(h, text);
	HarnessWaitLog(HUB_SECURITY_LOG_FILE_NAME, HARNESS_HUB_A, marker, forged, &scan);
	HarnessStopSession(login);
	HarnessFreePa(login);

	HarnessCheck(h, scan.NumMarker >= 1 && scan.NumBoth >= 1 && scan.NumForged == scan.NumBoth && scan.NumCr == 0,
		"LOGINJECT: a CR LF in the user name of a login forges no line in the security log");

	// Packet log file: the query name of a DNS frame from test session A
	Format(marker, sizeof(marker), "dns%s", tag);
	Format(text, sizeof(text), "%s\r\n%s.example", marker, forged);
	UINT query_size = HarnessBuildDnsQuery(query, sizeof(query), text);
	UINT frame_size = HarnessBuildIpFrame(frame, sizeof(frame), IP_PROTO_UDP, 53, query, query_size);
	HarnessPaSend(h->PaA, frame, frame_size);

	HarnessWaitLog(HUB_PACKET_LOG_FILE_NAME, HARNESS_HUB_A, marker, forged, &scan);
	HarnessCheck(h, scan.NumMarker == 1 && scan.NumBoth == 1 && scan.NumForged == 1 && scan.NumCr == 0,
		"LOGINJECT: one CSV record in the packet log for a DNS frame with a CR LF in the query name");

	// Syslog datagram: the security log goes to the syslog socket of the test
	SetIP(&localhost, 127, 0, 0, 1);
	SOCK *s = NewUDPEx2(0, false, &localhost);
	if (HarnessCheck(h, s != NULL, "LOGINJECT: loopback UDP socket for the syslog datagrams") == false)
	{
		return;
	}

	if (HarnessSetSyslog(h, SYSLOG_SERVER_AND_HUB_SECURITY_LOG, s->LocalPort, &old))
	{
		Format(tag, sizeof(tag), "%08X", Rand32());
		Format(marker, sizeof(marker), "inject%s", tag);
		Format(forged, sizeof(forged), "FORGED%s", tag);
		Format(text, sizeof(text), "%s\r\n%s", marker, forged);

		login = HarnessStartLogin(h, text);
		d = HarnessRecvSyslogWith(s, marker);
		HarnessStopSession(login);
		HarnessFreePa(login);

		HarnessCheck(h, d != NULL && InStrEx(d, forged, true) && HarnessHasLineBreak(d) == false,
			"LOGINJECT: a CR LF in the user name of a login stays out of the syslog datagram");

		Free(d);

		HarnessRestoreSyslog(h, &old);
	}

	ReleaseSock(s);
}

#define	HARNESS_SELF_SRC_PORT		39611				// Source port of the frame to the syslog address
#define	HARNESS_OTHER_SRC_PORT		39612				// Source port of the frame to another port

// UDP frame of test session A from 10.0.0.1:src_port to 127.0.0.1:dst_port, 8 bytes of data (no UDP
// checksum). Returns its size
static UINT HarnessBuildLoopbackUdp(UCHAR *buf, USHORT src_port, USHORT dst_port)
{
	UCHAR *ip = buf + 14;
	UCHAR *udp = ip + 20;
	UINT udp_size = 8 + 8;
	UINT ip_size = 20 + udp_size;

	Zero(buf, 14 + ip_size);

	Copy(buf, harness_mac_b, 6);
	Copy(buf + 6, harness_mac_a, 6);
	buf[12] = 0x08;								// IPv4
	buf[13] = 0x00;

	ip[0] = 0x45;								// Version 4, 20-byte header
	ip[2] = (UCHAR)(ip_size >> 8);
	ip[3] = (UCHAR)(ip_size & 0xFF);
	ip[8] = 64;									// TTL
	ip[9] = IP_PROTO_UDP;
	ip[12] = 10;								// 10.0.0.1
	ip[15] = 1;
	ip[16] = 127;								// 127.0.0.1
	ip[19] = 1;
	USHORT sum = IpChecksum(ip, 20);
	Copy(ip + 10, &sum, sizeof(USHORT));

	udp[0] = (UCHAR)(src_port >> 8);
	udp[1] = (UCHAR)(src_port & 0xFF);
	udp[2] = (UCHAR)(dst_port >> 8);
	udp[3] = (UCHAR)(dst_port & 0xFF);
	udp[5] = (UCHAR)udp_size;					// Length

	for (UINT i = 0;i < 8;i++)
	{
		udp[8 + i] = (UCHAR)(0x50 + i);
	}

	return 14 + ip_size;
}

// Count the PACKET_LOG syslog datagrams of the two frames of SYSLOG_SELF that arrive within timeout ms; stop at
// the first one of the frame to the other port when stop_at_other is set
static void HarnessCountSelfDatagrams(SOCK *s, UINT timeout, bool stop_at_other, UINT *num_self, UINT *num_other)
{
	UINT64 end = Tick64() + (UINT64)timeout;
	char self_marker[32];
	char other_marker[32];

	Format(self_marker, sizeof(self_marker), ",%u,", HARNESS_SELF_SRC_PORT);
	Format(other_marker, sizeof(other_marker), ",%u,", HARNESS_OTHER_SRC_PORT);

	while (true)
	{
		UINT64 now = Tick64();
		bool other = false;

		if (now >= end)
		{
			return;
		}

		char *d = HarnessRecvSyslog(s, (UINT)(end - now));
		if (d == NULL)
		{
			return;
		}

		if (InStrEx(d, "<PACKET_LOG>", true))
		{
			if (InStrEx(d, self_marker, true))
			{
				(*num_self)++;
			}
			if (InStrEx(d, other_marker, true))
			{
				(*num_other)++;
				other = true;
			}
		}

		Free(d);

		if (other && stop_at_other)
		{
			return;
		}
	}
}

// SYSLOG_SELF (FND-19): every log goes to the syslog socket of the test, UDP packet logging is on in HARNESS_A.
// A frame to the syslog address and port is the server's own syslog traffic: it gives no PACKET_LOG datagram; a
// frame to another port gives one
static void HarnessSyslogSelf(HARNESS *h)
{
	RPC_HUB_LOG old_log;
	RPC_HUB_LOG t;
	SYSLOG_SETTING old_syslog;
	IP localhost;
	UCHAR frame[128];
	UINT frame_size;
	UINT num_self = 0;
	UINT num_other = 0;
	char tmp[MAX_SIZE];

	Print("[logs: SYSLOG_SELF]\n");

	Zero(&old_log, sizeof(old_log));
	StrCpy(old_log.HubName, sizeof(old_log.HubName), HARNESS_HUB_A);
	UINT err = ScGetHubLog(h->Rpc, &old_log);
	if (HarnessCheckErr(h, err, "SYSLOG_SELF: GetHubLog " HARNESS_HUB_A) == false)
	{
		return;
	}

	Copy(&t, &old_log, sizeof(t));
	t.LogSetting.SavePacketLog = true;
	t.LogSetting.PacketLogConfig[PACKET_LOG_UDP] = PACKET_LOG_HEADER;
	err = ScSetHubLog(h->Rpc, &t);
	if (HarnessCheckErr(h, err, "SYSLOG_SELF: SetHubLog " HARNESS_HUB_A " logs UDP packet headers") == false)
	{
		return;
	}

	SetIP(&localhost, 127, 0, 0, 1);
	SOCK *s = NewUDPEx2(0, false, &localhost);

	if (HarnessCheck(h, s != NULL, "SYSLOG_SELF: loopback UDP socket for the syslog datagrams") &&
		HarnessSetSyslog(h, SYSLOG_SERVER_AND_HUB_ALL_LOG, s->LocalPort, &old_syslog))
	{
		frame_size = HarnessBuildLoopbackUdp(frame, HARNESS_SELF_SRC_PORT, (USHORT)s->LocalPort);
		HarnessPaSend(h->PaA, frame, frame_size);

		frame_size = HarnessBuildLoopbackUdp(frame, HARNESS_OTHER_SRC_PORT, SYSLOG_PORT);
		HarnessPaSend(h->PaA, frame, frame_size);

		// The frames are logged in order: once the datagram of the second one is in, a datagram of the first one
		// would be too; then a quiet time catches late or doubled datagrams
		HarnessCountSelfDatagrams(s, HARNESS_LOG_TIMEOUT, true, &num_self, &num_other);
		HarnessCountSelfDatagrams(s, HARNESS_SETTLE_TIME, false, &num_self, &num_other);

		Format(tmp, sizeof(tmp), "SYSLOG_SELF: a frame to the syslog address and port gives no PACKET_LOG datagram, "
			"a frame to another port gives one (%u and %u)", num_self, num_other);
		HarnessCheck(h, num_self == 0 && num_other == 1, tmp);

		HarnessRestoreSyslog(h, &old_syslog);
	}

	ReleaseSock(s);

	HarnessCheckErr(h, ScSetHubLog(h->Rpc, &old_log), "SYSLOG_SELF: SetHubLog restores the log setting of " HARNESS_HUB_A);
}

// SYSLOG_TYPE (FND-221 #258): SetSysLog refuses a save type other than SYSLOG_NONE, SYSLOG_SERVER_AND_HUB_SECURITY_LOG
// and SYSLOG_SERVER_AND_HUB_ALL_LOG, such as the former type 1 (the server log only), and keeps the setting
static void HarnessSyslogType(HARNESS *h)
{
	static UINT refused[] = {1, 4};
	SYSLOG_SETTING old, t, now;
	UINT err;
	UINT i;
	char tmp[MAX_SIZE];

	Print("[logs: SYSLOG_TYPE]\n");

	Zero(&old, sizeof(old));
	if (HarnessCheckErr(h, ScGetSysLog(h->Rpc, &old), "SYSLOG_TYPE: GetSysLog") == false)
	{
		return;
	}

	for (i = 0;i < sizeof(refused) / sizeof(refused[0]);i++)
	{
		Zero(&t, sizeof(t));
		t.SaveType = refused[i];
		StrCpy(t.Hostname, sizeof(t.Hostname), "127.0.0.1");
		t.Port = SYSLOG_PORT;

		Format(tmp, sizeof(tmp), "SYSLOG_TYPE: SetSysLog with save type %u", refused[i]);
		HarnessExpectErr(h, ScSetSysLog(h->Rpc, &t), ERR_INVALID_PARAMETER, tmp);
	}

	Zero(&now, sizeof(now));
	err = ScGetSysLog(h->Rpc, &now);
	HarnessCheck(h, err == ERR_NO_ERROR && now.SaveType == old.SaveType && StrCmp(now.Hostname, old.Hostname) == 0 &&
		now.Port == old.Port, "SYSLOG_TYPE: a refused save type keeps the syslog setting");
}

////////////////////////////
// Entry points

// "harness": in-process server, two hubs, cascade, frames, golden outputs and configuration round-trips
RANZ_TEST("harness", harness_test, "In-process server: hubs, cascade, frames, golden outputs, config round-trip.");
void harness_test(UINT num, char **arg)
{
	HARNESS *h = HarnessNew();
	HARNESS_WATCHDOG *wd = HarnessStartWatchdog("HARNESS", HARNESS_WATCHDOG_LIMIT);
	UINT64 start = Tick64();
	char tmp[MAX_SIZE];

	Print("Ranz harness: in-process server on TCP %u, hubs %s and %s, cascade, frames, golden outputs\n",
		HARNESS_PORT, HARNESS_HUB_A, HARNESS_HUB_B);

	bool setup_ok = HarnessSetup(h);

	if (setup_ok)
	{
		HarnessSetPhase("frames", NULL);
		HarnessFrames(h);
		HarnessPacketLogGolden(h);
		HarnessLogRecordCheck(h);
		HarnessSetPhase("pack", NULL);
		HarnessPackGolden(h);
		HarnessSetPhase("zerokey", NULL);
		HarnessZeroKeyUser(h);
		HarnessSetPhase("iptablelock", NULL);
		HarnessIpTableLock(h);
		HarnessSetPhase("setlink", NULL);
		HarnessSetLink(h);
		HarnessSetPhase("autodisconnect", NULL);
		HarnessAutoDisconnect(h);
		HarnessSetPhase("adminreconnect", NULL);
		HarnessAdminReconnect(h);
		HarnessAdminInvoke(h);
		HarnessSetPhase("logs", NULL);
		HarnessLogInject(h);
		HarnessSyslogSelf(h);
		HarnessSyslogType(h);
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

	UINT64 elapsed = Tick64() - start;
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
RANZ_TEST("bench", bench_test, "Cascade frame throughput and Pack encode/decode benchmark (informational).");
void bench_test(UINT num, char **arg)
{
	HARNESS *h = HarnessNew();
	HARNESS_WATCHDOG *wd = HarnessStartWatchdog("BENCH", HARNESS_BENCH_WATCHDOG);
	UINT64 start = Tick64();

	Print("Ranz bench: %u runs per case (median, then every run); per run: cascade path %u ms per frame size, "
		"hub flood %u ms, Pack %u ms, ParsePacket %u ms, one IP table expiry pass\n",
		HARNESS_BENCH_RUNS, HARNESS_BENCH_SPAN, HARNESS_BENCH_FLOOD_SPAN, HARNESS_BENCH_PACK_SPAN,
		HARNESS_BENCH_MICRO_SPAN);

	bool ok = HarnessSetup(h);

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
	HarnessSetPhase("bench_accept_table", NULL);
	HarnessBenchAcceptTable(1024);
	HarnessBenchAcceptTable(4096);
	HarnessBenchAcceptTable(16384);
	HarnessSetPhase("bench_fifo", NULL);
	HarnessBenchFifo();

	HarnessSetPhase("teardown", NULL);
	HarnessTeardown(h, ok);

	UINT64 elapsed = Tick64() - start;
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

// "certdl": SetServerCert with server certificates whose issuer URL names a loopback listener of the test; the
// server downloads the issuer certificate from it (DownloadCert, spec #30 step 9), one listener answer per run
RANZ_TEST("certdl", certdl_test, "SetServerCert downloads the issuer certificate from a loopback listener (DownloadCert).");
void certdl_test(UINT num, char **arg)
{
	HARNESS *h = HarnessNew();
	HARNESS_WATCHDOG *wd = HarnessStartWatchdog("CERTDL", CERTDL_WATCHDOG_LIMIT);
	CERTDL_SERVER *srv = NULL;
	CERTDL_RESULT r;
	X *ca = CertDlPemToX(certdl_ca_pem);
	X *leaf_http = CertDlPemToX(certdl_http_pem);
	X *leaf_https = CertDlPemToX(certdl_https_pem);
	X *tls = CertDlPemToX(certdl_tls_pem);
	K *key = CertDlPemToK(certdl_key_pem);
	wchar_t saved_file[MAX_SIZE];
	char tmp[MAX_SIZE];

	Print("Ranz certdl: SetServerCert downloads the issuer certificate from a loopback listener on TCP %u\n",
		CERTDL_PORT);

	Print("[setup]\n");
	HarnessSetPhase("setup", "fixtures");
	bool ok = HarnessCheck(h, ca != NULL && ca->root_cert, "fixture issuer certificate loads as a root certificate");
	ok = HarnessCheck(h, leaf_http != NULL && leaf_https != NULL && tls != NULL && key != NULL &&
		CheckXandK(leaf_http, key) && CheckXandK(leaf_https, key) && CheckXandK(tls, key),
		"fixture server and TLS certificates load and match the fixture key") && ok;
	ok = HarnessCheck(h, leaf_http != NULL && StrCmp(leaf_http->issuer_url, CERTDL_URL_HTTP) == 0,
		"http fixture names " CERTDL_URL_HTTP " as its issuer URL") && ok;
	ok = HarnessCheck(h, leaf_https != NULL && StrCmp(leaf_https->issuer_url, CERTDL_URL_HTTPS) == 0,
		"https fixture names " CERTDL_URL_HTTPS " as its issuer URL") && ok;

	if (ok)
	{
		// A file left by an aborted run would give the server the issuer without a download
		CertDlSavedPath(saved_file, sizeof(saved_file), ca);
		FileDeleteW(saved_file);

		HarnessSetPhase("setup", "issuer listener");
		srv = CertDlStartServer(ca, tls, key);
		Format(tmp, sizeof(tmp), "issuer listener bound on 127.0.0.1:%u", CERTDL_PORT);
		ok = HarnessCheck(h, srv != NULL, tmp);
	}

	if (ok)
	{
		ok = HarnessStartServer(h);
	}

	if (ok)
	{
		// The request: path of the issuer URL, HTTP/1.1, host and port of the URL, the product User-Agent
		Print("[ok: 200 with Content-Length]\n");
		HarnessSetPhase("certdl", "ok");
		CertDlRun(h, srv, "ok", CERTDL_MODE_OK, leaf_http, key, saved_file, &r);
		CertDlExpect(h, "ok", &r, true, false);
		CertDlCheckStr(h, "ok: request line", r.RequestLine, "GET " CERTDL_PATH " HTTP/1.1");
		CertDlCheckStr(h, "ok: Host header", r.Host, CERTDL_HOST);
		CertDlCheckStr(h, "ok: User-Agent header", r.UserAgent, DEFAULT_USER_AGENT);

		// https issuer URL: the client does not check the certificate of the issuer server
		Print("[tls: https, listener certificate not trusted]\n");
		HarnessSetPhase("certdl", "tls");
		CertDlRun(h, srv, "tls", CERTDL_MODE_TLS, leaf_https, key, saved_file, &r);
		CertDlExpect(h, "tls", &r, true, false);
		CertDlCheckStr(h, "tls: request line", r.RequestLine, "GET " CERTDL_PATH " HTTP/1.1");
		CertDlCheckStr(h, "tls: Host header", r.Host, CERTDL_HOST);

		Print("[continue: 100 Continue before the 200]\n");
		HarnessSetPhase("certdl", "continue");
		CertDlRun(h, srv, "continue", CERTDL_MODE_CONTINUE, leaf_http, key, saved_file, &r);
		CertDlExpect(h, "continue", &r, true, false);

		// The redirect target would answer with the issuer: one request only means the client did not follow
		Print("[redirect: 302 not followed]\n");
		HarnessSetPhase("certdl", "redirect");
		CertDlRun(h, srv, "redirect", CERTDL_MODE_REDIRECT, leaf_http, key, saved_file, &r);
		CertDlExpect(h, "redirect", &r, false, false);

		Print("[not_found: 404]\n");
		HarnessSetPhase("certdl", "not_found");
		CertDlRun(h, srv, "not_found", CERTDL_MODE_NOT_FOUND, leaf_http, key, saved_file, &r);
		CertDlExpect(h, "not_found", &r, false, false);

		// One request only: the client neither answers the challenge nor sends credentials
		Print("[auth: 401 Negotiate and NTLM not answered]\n");
		HarnessSetPhase("certdl", "auth");
		CertDlRun(h, srv, "auth", CERTDL_MODE_AUTH, leaf_http, key, saved_file, &r);
		CertDlExpect(h, "auth", &r, false, false);

		// Without Content-Length the client reads no body, chunked or not
		Print("[no_length: 200 without Content-Length, then close]\n");
		HarnessSetPhase("certdl", "no_length");
		CertDlRun(h, srv, "no_length", CERTDL_MODE_NO_LENGTH, leaf_http, key, saved_file, &r);
		CertDlExpect(h, "no_length", &r, false, false);

		Print("[chunked: 200 with Transfer-Encoding chunked]\n");
		HarnessSetPhase("certdl", "chunked");
		CertDlRun(h, srv, "chunked", CERTDL_MODE_CHUNKED, leaf_http, key, saved_file, &r);
		CertDlExpect(h, "chunked", &r, false, false);

		// The client stops at 64 KiB and parses what it has: the certificate at its start
		Print("[over_cap: Content-Length 1000000, 64 KiB sent]\n");
		HarnessSetPhase("certdl", "over_cap");
		CertDlRun(h, srv, "over_cap", CERTDL_MODE_OVER_CAP, leaf_http, key, saved_file, &r);
		CertDlExpect(h, "over_cap", &r, true, false);

		Print("[silent: no answer]\n");
		HarnessSetPhase("certdl", "silent");
		CertDlRun(h, srv, "silent", CERTDL_MODE_SILENT, leaf_http, key, saved_file, &r);
		CertDlExpect(h, "silent", &r, false, true);
	}

	HarnessSetPhase("teardown", NULL);
	Print("[teardown]\n");
	HarnessStopServer(h);
	CertDlStopServer(srv);

	FreeX(ca);
	FreeX(leaf_http);
	FreeX(leaf_https);
	FreeX(tls);
	FreeK(key);

	HarnessStopWatchdog(wd);

	if (h->NumFail == 0)
	{
		Print("CERTDL TEST OK\n");
	}
	else
	{
		Print("CERTDL TEST FAILED (%u failed checks)\n", h->NumFail);
	}

	HarnessFree(h);
}

// "listenerbind": ListenerCreate and ListenerEnable wait for the bind attempt of the listener thread and report a
// port that cannot be bound (FIX-3 #99). Before FIX-3 both slept a fixed 250 ms and always returned ERR_NO_ERROR.
RANZ_TEST("listenerbind", listenerbind_test, "ListenerCreate and ListenerEnable wait for the bind and report a port that cannot be bound.");
void listenerbind_test(UINT num, char **arg)
{
	HARNESS *h = HarnessNew();
	HARNESS_WATCHDOG *wd = HarnessStartWatchdog("LISTENERBIND", LISTENBIND_WATCHDOG_LIMIT);
	RPC_LISTENER d;
	UINT64 elapsed, fastest, end;
	UINT err;
	bool enabled, error;
	char tmp[MAX_SIZE];

	Print("Ranz listenerbind: ListenerCreate and ListenerEnable report the bind status; TCP %u held by the test, "
		"TCP %u free\n", LISTENBIND_PORT_HELD, LISTENBIND_PORT_FREE);

	Print("[setup]\n");
	HarnessSetPhase("setup", "held port");
	// The bind of the server's listener (any address, no address reuse): the server cannot bind the port while
	// this socket is open
	SOCK *held = Listen(LISTENBIND_PORT_HELD, NULL, false);
	Format(tmp, sizeof(tmp), "the test holds TCP %u", LISTENBIND_PORT_HELD);
	bool ok = HarnessCheck(h, held != NULL, tmp);

	if (ok)
	{
		ok = HarnessStartServer(h);
	}

	if (ok)
	{
		// The listener stays registered and keeps retrying, as before FIX-3: only the result of the RPC changes
		Print("[held: ListenerCreate]\n");
		HarnessSetPhase("listenerbind", "create on the held port");
		err = ListenBindCall(h, true, LISTENBIND_PORT_HELD, true, &elapsed);
		ListenBindExpect(h, "create_held", "ListenerCreate on the held port reports the failed bind", err,
			ERR_LISTENER_BIND_FAILED, elapsed);
		ok = ListenBindState(h, LISTENBIND_PORT_HELD, &enabled, &error);
		HarnessCheck(h, ok && enabled && error,
			"ListenerList keeps the listener on the held port, enabled and in error state");

		Print("[held: ListenerDisable, ListenerEnable]\n");
		HarnessSetPhase("listenerbind", "enable on the held port");
		err = ListenBindCall(h, false, LISTENBIND_PORT_HELD, false, &elapsed);
		ListenBindExpect(h, "disable_held", "ListenerDisable on the held port", err, ERR_NO_ERROR, elapsed);
		err = ListenBindCall(h, false, LISTENBIND_PORT_HELD, true, &elapsed);
		ListenBindExpect(h, "enable_held", "ListenerEnable on the held port reports the failed bind", err,
			ERR_LISTENER_BIND_FAILED, elapsed);

		// The RPC returns once the port is bound. The fastest call is compared with the former fixed sleep, so one
		// slow RPC on a busy machine does not fail the test.
		Print("[free: ListenerCreate, %u disable and enable cycles]\n", LISTENBIND_CYCLES);
		HarnessSetPhase("listenerbind", "free port");
		err = ListenBindCall(h, true, LISTENBIND_PORT_FREE, true, &elapsed);
		ListenBindExpect(h, "create_free", "ListenerCreate on the free port", err, ERR_NO_ERROR, elapsed);
		ListenBindIsListening(h, LISTENBIND_PORT_FREE,
			"ListenerList shows the free port listening right after ListenerCreate");
		fastest = elapsed;

		for (UINT i = 0;i < LISTENBIND_CYCLES;i++)
		{
			err = ListenBindCall(h, false, LISTENBIND_PORT_FREE, false, &elapsed);
			ListenBindExpect(h, "disable_free", "ListenerDisable on the free port", err, ERR_NO_ERROR, elapsed);
			ok = ListenBindState(h, LISTENBIND_PORT_FREE, &enabled, &error);
			HarnessCheck(h, ok && enabled == false,
				"ListenerList shows the free port disabled right after ListenerDisable");

			err = ListenBindCall(h, false, LISTENBIND_PORT_FREE, true, &elapsed);
			ListenBindExpect(h, "enable_free", "ListenerEnable on the free port", err, ERR_NO_ERROR, elapsed);
			ListenBindIsListening(h, LISTENBIND_PORT_FREE,
				"ListenerList shows the free port listening right after ListenerEnable");
			fastest = MIN(fastest, elapsed);
		}

		Print("TIME listenerbind_fastest %I64u ms\n", fastest);
		Format(tmp, sizeof(tmp), "the fastest ListenerCreate or ListenerEnable on the free port returns before the "
			"former fixed %u ms sleep", LISTENBIND_FORMER_SLEEP);
		HarnessCheck(h, fastest < LISTENBIND_FORMER_SLEEP, tmp);

		// A disabled listener has no bind to wait for
		Print("[free: ListenerCreate disabled]\n");
		HarnessSetPhase("listenerbind", "create disabled");
		Zero(&d, sizeof(d));
		d.Port = LISTENBIND_PORT_FREE;
		HarnessCheckErr(h, ScDeleteListener(h->Rpc, &d), "ListenerDelete on the free port");
		err = ListenBindCall(h, true, LISTENBIND_PORT_FREE, false, &elapsed);
		ListenBindExpect(h, "create_disabled", "ListenerCreate of a disabled listener", err, ERR_NO_ERROR, elapsed);
		ok = ListenBindState(h, LISTENBIND_PORT_FREE, &enabled, &error);
		HarnessCheck(h, ok && enabled == false, "ListenerList shows the new listener disabled");

		// The listener on the released port binds by its own retry; ListenerEnable then reports the bound port
		Print("[released: retry, ListenerEnable]\n");
		HarnessSetPhase("listenerbind", "held port released");
		Disconnect(held);
		ReleaseSock(held);
		held = NULL;

		end = Tick64() + (UINT64)LISTENBIND_RETRY_LIMIT;
		while (true)
		{
			ok = ListenBindState(h, LISTENBIND_PORT_HELD, &enabled, &error);
			if ((ok && enabled && error == false) || Tick64() >= end)
			{
				break;
			}

			SleepThread(LISTENBIND_POLL);
		}
		Format(tmp, sizeof(tmp), "the listener binds the released port by its own retry within %u ms",
			LISTENBIND_RETRY_LIMIT);
		HarnessCheck(h, ok && enabled && error == false, tmp);

		err = ListenBindCall(h, false, LISTENBIND_PORT_HELD, true, &elapsed);
		ListenBindExpect(h, "enable_released", "ListenerEnable on the enabled listener reports the bound port", err,
			ERR_NO_ERROR, elapsed);

		Print("[cleanup]\n");
		HarnessSetPhase("listenerbind", "cleanup");
		Zero(&d, sizeof(d));
		d.Port = LISTENBIND_PORT_HELD;
		HarnessCheckErr(h, ScDeleteListener(h->Rpc, &d), "ListenerDelete on the released port");
		Zero(&d, sizeof(d));
		d.Port = LISTENBIND_PORT_FREE;
		HarnessCheckErr(h, ScDeleteListener(h->Rpc, &d), "ListenerDelete on the free port");
		ok = ListenBindState(h, LISTENBIND_PORT_HELD, &enabled, &error) ||
			ListenBindState(h, LISTENBIND_PORT_FREE, &enabled, &error);
		HarnessCheck(h, ok == false, "ListenerList no longer lists the test ports");
		ListenBindIsListening(h, HARNESS_PORT, "ListenerList still shows the harness listener listening");
	}

	HarnessSetPhase("teardown", NULL);
	Print("[teardown]\n");
	HarnessStopServer(h);

	if (held != NULL)
	{
		Disconnect(held);
		ReleaseSock(held);
	}

	HarnessStopWatchdog(wd);

	if (h->NumFail == 0)
	{
		Print("LISTENERBIND TEST OK\n");
	}
	else
	{
		Print("LISTENERBIND TEST FAILED (%u failed checks)\n", h->NumFail);
	}

	HarnessFree(h);
}

// "adminaudit": the admin RPC handlers write their audit line after an operation that succeeded, never after a
// failed one, with the right string table key, and change the configuration revision only when the configuration
// changed (FND-10 #107). The server's syslog goes to a loopback receiver of the test
RANZ_TEST("adminaudit", adminaudit_test, "Admin audit: audit lines only after a successful call and with the right key, the configuration revision only after a change.");
void adminaudit_test(UINT num, char **arg)
{
	HARNESS *h = HarnessNew();
	HARNESS_WATCHDOG *wd = HarnessStartWatchdog("ADMINAUDIT", ADMINAUDIT_WATCHDOG_LIMIT);
	ADMINAUDIT *a = NULL;
	char session[MAX_SESSION_NAME_LEN + 1];

	session[0] = 0;

	Print("Ranz adminaudit: audit lines and configuration revision of the admin RPC handlers, hub %s, syslog on a "
		"loopback receiver\n", HARNESS_HUB_A);

	Print("[setup]\n");
	bool ok = HarnessStartServer(h);

	if (ok)
	{
		HarnessSetPhase("setup", "hub, users, test session");
		ok = HarnessCreateHub(h, HARNESS_HUB_A) &&
			HarnessCreateUser(h, HARNESS_HUB_A, HARNESS_USER_A, L"Harness tester A") &&
			HarnessCreateUser(h, HARNESS_HUB_A, ADMINAUDIT_USER, L"Adminaudit user") &&
			HarnessCheck(h, HarnessStartSession(h, h->PaA, HARNESS_HUB_A, HARNESS_USER_A), "test session A created") &&
			HarnessWaitSession(h, h->PaA, HARNESS_SESSION_TIMEOUT) &&
			HarnessCheck(h, HarnessWaitSessionListed(h, HARNESS_HUB_A, HARNESS_USER_A, false, session, sizeof(session)),
				"HARNESS_A lists test session A (EnumSession)");
	}

	if (ok)
	{
		HarnessSetPhase("setup", "syslog receiver");
		a = AdminAuditNew(h);
		ok = (a != NULL);
	}

	if (ok)
	{
		HarnessSetPhase("adminaudit", "users");
		AdminAuditUsers(a);
		HarnessSetPhase("adminaudit", "groups");
		AdminAuditGroups(a);
		HarnessSetPhase("adminaudit", "crl");
		AdminAuditCrl(a);
		HarnessSetPhase("adminaudit", "sessions");
		AdminAuditSession(a, session);
		HarnessSetPhase("adminaudit", "local bridge");
		AdminAuditBridge(a);
		HarnessSetPhase("adminaudit", "ca");
		AdminAuditCa(a);
	}

	HarnessSetPhase("teardown", NULL);
	Print("[teardown]\n");
	AdminAuditFree(a);
	HarnessStopSessions(h);
	HarnessStopServer(h);

	HarnessStopWatchdog(wd);

	if (h->NumFail == 0)
	{
		Print("ADMINAUDIT TEST OK\n");
	}
	else
	{
		Print("ADMINAUDIT TEST FAILED (%u failed checks)\n", h->NumFail);
	}

	HarnessFree(h);
}

////////////////////////////
// In-process server of the named tests in other files (login.c)

// Watchdog of the run that HarnessOpenServer or HarnessOpenRun started (one test command runs at a time)
static HARNESS_WATCHDOG *harness_open_watchdog = NULL;

// Start a run of a named test in another file that starts and stops the server itself (HarnessStartServerKeep,
// HarnessStopServerKeep): only its watchdog (marker test_name, process aborted after limit ms). HarnessCloseServer
// ends the run and deletes the configuration files of the run.
HARNESS *HarnessOpenRun(char *test_name, UINT limit)
{
	HARNESS *h = HarnessNew();

	harness_open_watchdog = HarnessStartWatchdog(test_name, limit);

	return h;
}

// Start the server of a run from a fresh configuration with the test listener only and the admin RPC, then, unless
// hubname is NULL, the online hub hubname with the password user username (HARNESS_PASSWORD). False when a step
// failed. HarnessStopServerKeep or HarnessCloseServer stops it.
bool HarnessStartServerHub(HARNESS *h, char *hubname, char *username)
{
	bool ok = HarnessStartServer(h);

	if (ok && hubname != NULL)
	{
		// A server session then ends as soon as its last TCP connection is gone (Session.c, SessionMain), instead
		// of after the 20 s TimeOut of the default policy. Set after the server started, because loading its
		// configuration resets the flag
		SetGlobalServerFlag(GSF_DISABLE_SESSION_RECONNECT, 1);

		HarnessSetPhase("setup", "hub and user");
		ok = HarnessCreateHub(h, hubname) && HarnessCreateUser(h, hubname, username, L"Harness login tester");
	}

	return ok;
}

// Start a run of a named test in another file: its watchdog (marker test_name, process aborted after limit ms), the
// server from a fresh configuration with the test listener and the admin RPC, then, unless hubname is NULL, the online
// hub hubname with the password user username (HARNESS_PASSWORD). *ok is false when a step failed. HarnessCloseServer
// ends the run in every case.
HARNESS *HarnessOpenServer(char *test_name, UINT limit, char *hubname, char *username, bool *ok)
{
	HARNESS *h = HarnessOpenRun(test_name, limit);

	Print("[setup]\n");
	*ok = HarnessStartServerHub(h, hubname, username);

	return h;
}

// Stop the server and the watchdog of a run of HarnessOpenServer and release the run. Returns its failed checks.
UINT HarnessCloseServer(HARNESS *h)
{
	HarnessSetPhase("teardown", NULL);
	Print("[teardown]\n");
	HarnessStopServer(h);
	SetGlobalServerFlag(GSF_DISABLE_SESSION_RECONNECT, 0);

	HarnessStopWatchdog(harness_open_watchdog);
	harness_open_watchdog = NULL;

	UINT num_fail = h->NumFail;
	HarnessFree(h);

	return num_fail;
}

// The configuration round trip of a run of HarnessOpenServer: SiReleaseServer writes the configuration file, SiNewServer
// loads it again, then the test listener and the admin RPC are back. False when a step failed
bool HarnessRestartServer(HARNESS *h)
{
	UINT err = ERR_NO_ERROR;

	AdminDisconnect(h->Rpc);
	h->Rpc = NULL;
	SiReleaseServer(h->Server);
	h->Server = NULL;

	h->Server = SiNewServer();
	if (HarnessCheck(h, h->Server != NULL, "server restarted from the saved " HARNESS_CONFIG_FILE) == false ||
		HarnessWaitListener(h, HARNESS_LISTEN_TIMEOUT) == false)
	{
		return false;
	}

	h->Rpc = HarnessAdminConnect(h->ClientCedar, HARNESS_START_TIMEOUT, &err);

	return HarnessCheckErr(h, (h->Rpc != NULL ? ERR_NO_ERROR : err), "admin RPC reconnected after the restart");
}

// Add a passing access list entry with the note of the test to the test hub
static bool PtrKeyAddAccess(HARNESS *h, UINT priority)
{
	RPC_ADD_ACCESS t;
	char tmp[MAX_SIZE];

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), PTRKEY_HUB);
	UniStrCpy(t.Access.Note, sizeof(t.Access.Note), PTRKEY_NOTE);
	t.Access.Active = true;
	t.Access.Priority = priority;

	Format(tmp, sizeof(tmp), "AccessAdd " PTRKEY_HUB " priority %u", priority);

	return HarnessCheckErr(h, ScAddAccess(h->Rpc, &t), tmp);
}

// AccessList of the test hub: the UniqueId of the entry with this priority (0 when there is none) and the
// priorities in list order, comma separated
static UINT PtrKeyEnumAccess(HARNESS *h, UINT priority, char *priorities, UINT priorities_size)
{
	RPC_ENUM_ACCESS_LIST t;
	UINT ret = 0;

	StrCpy(priorities, priorities_size, "");

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), PTRKEY_HUB);
	if (HarnessCheckErr(h, ScEnumAccess(h->Rpc, &t), "AccessList " PTRKEY_HUB) == false)
	{
		return 0;
	}

	for (UINT i = 0;i < t.NumAccess;i++)
	{
		ACCESS *a = &t.Accesses[i];
		char tmp[MAX_SIZE];

		Format(tmp, sizeof(tmp), "%s%u", (i == 0 ? "" : ","), a->Priority);
		StrCat(priorities, priorities_size, tmp);

		if (a->Priority == priority)
		{
			ret = a->UniqueId;
		}
	}

	FreeRpcEnumAccessList(&t);

	return ret;
}

// AccessDelete by the UniqueId of an earlier AccessList, after an add renumbered the Ids
static void PtrKeyAccessList(HARNESS *h)
{
	RPC_DELETE_ACCESS d;
	RPC_DELETE_HUB dh;
	UINT id_20;
	char priorities[MAX_SIZE];
	char tmp[MAX_SIZE];

	if (HarnessCreateHub(h, PTRKEY_HUB) == false)
	{
		return;
	}

	// Priorities 10 and 20: Ids 1 and 2
	if (PtrKeyAddAccess(h, 10) && PtrKeyAddAccess(h, 20))
	{
		id_20 = PtrKeyEnumAccess(h, 20, priorities, sizeof(priorities));
		// AccessDelete takes an Id below MAX_ACCESSLISTS as the entry Id, from it as a UniqueId
		HarnessCheck(h, id_20 >= MAX_ACCESSLISTS, "AccessList gives the priority 20 entry a UniqueId from MAX_ACCESSLISTS up");

		// Priority 5 sorts first: the Ids become 1, 2 and 3 for priorities 5, 10 and 20
		if (PtrKeyAddAccess(h, 5))
		{
			HarnessCheck(h, PtrKeyEnumAccess(h, 20, priorities, sizeof(priorities)) == id_20,
				"the priority 20 entry keeps its UniqueId after an add renumbers the Ids");

			Zero(&d, sizeof(d));
			StrCpy(d.HubName, sizeof(d.HubName), PTRKEY_HUB);
			d.Id = id_20;
			HarnessCheckErr(h, ScDeleteAccess(h->Rpc, &d), "AccessDelete " PTRKEY_HUB " by the first UniqueId of priority 20");

			PtrKeyEnumAccess(h, 0, priorities, sizeof(priorities));
			Format(tmp, sizeof(tmp), "AccessDelete removed the priority 20 entry: priorities 5,10 left (left: %s)",
				priorities);
			HarnessCheck(h, StrCmp(priorities, "5,10") == 0, tmp);
		}
	}

	Zero(&dh, sizeof(dh));
	StrCpy(dh.HubName, sizeof(dh.HubName), PTRKEY_HUB);
	HarnessCheckErr(h, ScDeleteHub(h->Rpc, &dh), "DeleteHub " PTRKEY_HUB);
}

// "ptrkey": POINTER_TO_KEY keys a block by its address; access list delete by UniqueId
RANZ_TEST("ptrkey", ptrkey_test, "Pointer keys: POINTER_TO_KEY keys a block by its address; AccessDelete by UniqueId removes that entry after the Ids are renumbered.");
void ptrkey_test(UINT num, char **arg)
{
	HARNESS *h = HarnessNew();
	HARNESS_WATCHDOG *wd = HarnessStartWatchdog("PTRKEY", PTRKEY_WATCHDOG_LIMIT);

	Print("Ranz ptrkey: POINTER_TO_KEY keys a block by its address; AccessDelete by UniqueId after the Ids are "
		"renumbered, hub %s on TCP %u\n", PTRKEY_HUB, HARNESS_PORT);

	Print("[blocks]\n");
	HarnessSetPhase("ptrkey", "blocks");
	PtrKeyBlocks(h);

	Print("[setup]\n");
	if (HarnessStartServer(h))
	{
		Print("[access list]\n");
		HarnessSetPhase("ptrkey", "access list");
		PtrKeyAccessList(h);
	}

	HarnessSetPhase("teardown", NULL);
	Print("[teardown]\n");
	HarnessStopServer(h);

	HarnessStopWatchdog(wd);

	if (h->NumFail == 0)
	{
		Print("PTRKEY TEST OK\n");
	}
	else
	{
		Print("PTRKEY TEST FAILED (%u failed checks)\n", h->NumFail);
	}

	HarnessFree(h);
}
