// loginthrottle.c
// Named Login throttle test of vpntest ("loginthrottle" command, AUD1-DT-5 #453)
//
// The throttle of the Login of a node (Cedar/NodeThrottle.c; NS-15 and G-5 of docs/threat-model.md). First the throttle
// alone, with the times given by hand: the limit of a user from any source, of a source for any users, the end of the
// window, the name without case, the /64 of an IPv6 source, a Login that passed, Logins that are checked at the same
// time, and a full table that keeps the refused entries. Then the Login of the server role of a node through
// NodeLoginThrottled, against the time of one PBKDF2 derivation of CS_PBKDF2_ITERATIONS iterations, which a Login of a
// password of the configuration store costs:
// - After the limit of wrong passwords of one user, the right password of that user is refused from another source and
//   from an unknown one, in less time than one derivation.
// - After the limit of wrong passwords from one source across users, the source is refused for a user that it never
//   tried, and an honest source logs that user in.
// - An unknown user is throttled as a known one: both get the same answer, and the times of their refusals do not tell
//   them apart.
// - Every refusal is counted, the node log has one line for each, and the log holds no password.
// Print "LOGINTHROTTLE TEST OK" only when every check passes.

#include "testlist.h"

#include "Cedar/Account.h"
#include "Cedar/Cedar.h"
#include "Cedar/ConfigStore.h"
#include "Cedar/Hub.h"
#include "Cedar/Node.h"
#include "Cedar/NodeThrottle.h"
#include "Cedar/Sam.h"

#include "Mayaqua/Encrypt.h"
#include "Mayaqua/FileIO.h"
#include "Mayaqua/Internat.h"
#include "Mayaqua/IpAddr.h"
#include "Mayaqua/Kernel.h"
#include "Mayaqua/Memory.h"
#include "Mayaqua/Microsoft.h"
#include "Mayaqua/Object.h"
#include "Mayaqua/Str.h"

#include "Core/Noise.h"

#define	LT_HUB				"LOGINTHROTTLE"			// Hub of the node
#define	LT_PASSWORD			"LoginThrottle-Right-7"	// The password of every user of the hub
#define	LT_WRONG			"LoginThrottle-Wrong-7"	// No user's password
#define	LT_USER_LIMIT		3						// The limit of a user in this test
#define	LT_SOURCE_LIMIT		6						// ... of a source
#define	LT_WINDOW			1000					// The window of the throttle alone (ms)
#define	LT_NODE_WINDOW		600000					// The window of the node: no window ends while the test runs (ms)
#define	LT_TIMED			15						// Refusals timed for the known and for the unknown user each
#define	LT_KNOWN			"lt_carol"				// A user of the hub ...
#define	LT_UNKNOWN			"lt_nobody"				// ... and a name that the hub does not keep

// The state of the test
typedef struct LT_CTX
{
	UINT NumChecks;
	UINT NumFailed;
	UINT64 NumRefused;					// Logins that the throttle of the node refused, as the test counts them
	double Derivation;					// The time of one PBKDF2 derivation (ms)
} LT_CTX;

static bool LtCheck(LT_CTX *ctx, bool ok, char *what, char *fmt, ...) RANZ_PRINTF_FORMAT(4, 5);
static bool LtCheck(LT_CTX *ctx, bool ok, char *what, char *fmt, ...)
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

// The time since start (ms)
static double LtElapsed(LARGE_INTEGER *start)
{
	LARGE_INTEGER now, frequency;

	QueryPerformanceCounter(&now);
	QueryPerformanceFrequency(&frequency);

	return (double)(now.QuadPart - start->QuadPart) * 1000.0 / (double)frequency.QuadPart;
}

// The median of num times; the array is sorted
static double LtMedian(double *t, UINT num)
{
	for (UINT i = 1;i < num;i++)
	{
		double v = t[i];
		UINT j = i;

		while (j > 0 && t[j - 1] > v)
		{
			t[j] = t[j - 1];
			j--;
		}
		t[j] = v;
	}

	return (num == 0 ? 0.0 : t[num / 2]);
}

// An address of a source, by its text
static IP *LtIp(IP *ip, char *str)
{
	Zero(ip, sizeof(IP));
	StrToIP(ip, str);

	return ip;
}

//
// The throttle alone
//

// One Login of user from source (NULL for none) at now that the test ends at once with the result ok, when it passes:
// why the throttle refused it, NODE_THROTTLE_PASS when it did not
static UINT LtTry(NODE_THROTTLE *t, char *user, char *source, UINT64 now, bool ok)
{
	IP ip;
	IP *src = (source == NULL ? NULL : LtIp(&ip, source));

	UINT why = NodeThrottleBegin(t, LT_HUB, user, src, now);
	if (why == NODE_THROTTLE_PASS)
	{
		NodeThrottleEnd(t, LT_HUB, user, src, ok);
	}

	return why;
}

// Logins of user from source at now that all fail: whether the throttle passed each
static bool LtFail(NODE_THROTTLE *t, char *user, char *source, UINT64 now, UINT num)
{
	bool ret = true;

	for (UINT i = 0;i < num;i++)
	{
		ret = (LtTry(t, user, source, now, false) == NODE_THROTTLE_PASS) && ret;
	}

	return ret;
}

static void LtAlone(LT_CTX *ctx)
{
	NODE_THROTTLE_STATUS st;
	UINT64 now = 1000000;
	char name[MAX_SIZE], addr[MAX_SIZE];

	Print("[the throttle alone]\n");
	NODE_THROTTLE *t = NewNodeThrottle();
	NodeThrottleGetStatus(t, &st);
	LtCheck(ctx, st.UserFailures == NODE_THROTTLE_USER_FAILURES && st.SourceFailures == NODE_THROTTLE_SOURCE_FAILURES &&
		st.Window == NODE_THROTTLE_WINDOW && st.MaxEntries == NODE_THROTTLE_MAX_ENTRIES && st.NumEntries == 0 && st.NumRefused == 0,
		"a new throttle has the default limits and counts nothing", "user %u, source %u, window %I64u, max %u, entries %u, refused %I64u",
		st.UserFailures, st.SourceFailures, st.Window, st.MaxEntries, st.NumEntries, st.NumRefused);
	NodeThrottleSetLimits(t, LT_USER_LIMIT, LT_SOURCE_LIMIT, LT_WINDOW, 0);

	// The limit of a user, from any source, until the window ends
	bool passed = LtFail(t, "alice", "192.0.2.1", now, LT_USER_LIMIT);
	UINT other = LtTry(t, "alice", "192.0.2.2", now + 1, true);
	UINT none = LtTry(t, "alice", NULL, now + 1, true);
	UINT upper = LtTry(t, "ALICE", "192.0.2.3", now + 1, true);
	UINT later = LtTry(t, "alice", "192.0.2.2", now + LT_WINDOW, true);
	LtCheck(ctx, passed && other == NODE_THROTTLE_USER && none == NODE_THROTTLE_USER && upper == NODE_THROTTLE_USER && later == NODE_THROTTLE_PASS,
		"after the limit of failures of a user, its Logins from any source and in any case are refused until the window ends",
		"failures passed %u, another source %u, no source %u, upper case %u, after the window %u", (UINT)passed, other, none, upper, later);

	// The limit of a source across users, and an honest source
	now += 10 * LT_WINDOW;
	passed = true;
	for (UINT i = 0;i < LT_SOURCE_LIMIT;i++)
	{
		Format(name, sizeof(name), "spray%u", i);
		passed = LtFail(t, name, "198.51.100.7", now, 1) && passed;
	}
	UINT sprayer = LtTry(t, "bob", "198.51.100.7", now + 1, true);
	UINT honest = LtTry(t, "bob", "198.51.100.8", now + 1, true);
	later = LtTry(t, "bob", "198.51.100.7", now + LT_WINDOW, true);
	LtCheck(ctx, passed && sprayer == NODE_THROTTLE_SOURCE && honest == NODE_THROTTLE_PASS && later == NODE_THROTTLE_PASS,
		"after the limit of failures from a source across users, the source is refused for the window, an honest source is not",
		"failures passed %u, the source %u, an honest source %u, after the window %u", (UINT)passed, sprayer, honest, later);

	// An IPv6 source is its /64
	now += 10 * LT_WINDOW;
	passed = true;
	for (UINT i = 0;i < LT_SOURCE_LIMIT;i++)
	{
		Format(name, sizeof(name), "six%u", i);
		Format(addr, sizeof(addr), "2001:db8:1:2::%x", i + 1);
		passed = LtFail(t, name, addr, now, 1) && passed;
	}
	UINT same = LtTry(t, "carol", "2001:db8:1:2:ffff::1", now + 1, true);
	UINT next = LtTry(t, "carol", "2001:db8:1:3::1", now + 1, true);
	LtCheck(ctx, passed && same == NODE_THROTTLE_SOURCE && next == NODE_THROTTLE_PASS,
		"the addresses of one IPv6 /64 are one source, another /64 is another", "failures passed %u, the same /64 %u, another /64 %u",
		(UINT)passed, same, next);

	// A Login that passed clears the failures of its user
	now += 10 * LT_WINDOW;
	passed = LtFail(t, "dave", "192.0.2.10", now, LT_USER_LIMIT - 1);
	UINT right = LtTry(t, "dave", "192.0.2.10", now, true);
	bool again = LtFail(t, "dave", "192.0.2.10", now, LT_USER_LIMIT);
	UINT after = LtTry(t, "dave", "192.0.2.10", now, true);
	LtCheck(ctx, passed && right == NODE_THROTTLE_PASS && again && after == NODE_THROTTLE_USER,
		"a Login that passed clears the failures of its user, which then has its whole limit again",
		"failures passed %u, the right one %u, the limit again %u, then %u", (UINT)passed, right, (UINT)again, after);

	// Logins that are being checked count: they cannot pass the limit together
	now += 10 * LT_WINDOW;
	UINT begun = 0;
	for (UINT i = 0;i < LT_USER_LIMIT + 2;i++)
	{
		if (NodeThrottleBegin(t, LT_HUB, "erin", NULL, now) == NODE_THROTTLE_PASS)
		{
			begun++;
		}
	}
	LtCheck(ctx, begun == LT_USER_LIMIT, "Logins checked at the same time count before their result: no more than the limit pass",
		"%u of %u passed", begun, LT_USER_LIMIT + 2);

	NodeThrottleGetStatus(t, &st);
	LtCheck(ctx, st.NumRefused == st.NumRefusedUser + st.NumRefusedSource + st.NumRefusedFull && st.NumRefusedUser == 6 &&
		st.NumRefusedSource == 2 && st.NumRefusedFull == 0,
		"each refusal is counted by its reason", "refused %I64u: user %I64u, source %I64u, full %I64u",
		st.NumRefused, st.NumRefusedUser, st.NumRefusedSource, st.NumRefusedFull);
	FreeNodeThrottle(t);

	// A full table keeps the refused entries, and gives room once a window ended
	t = NewNodeThrottle();
	NodeThrottleSetLimits(t, 1, 100, LT_WINDOW, 4);
	now += 10 * LT_WINDOW;
	passed = true;
	for (UINT i = 0;i < 4;i++)
	{
		Format(name, sizeof(name), "full%u", i);
		passed = LtFail(t, name, NULL, now + i, 1) && passed;
	}
	UINT full = LtTry(t, "newcomer", NULL, now + 10, true);
	UINT kept = LtTry(t, "full0", NULL, now + 10, true);
	UINT room = LtTry(t, "newcomer", NULL, now + LT_WINDOW, true);
	NodeThrottleGetStatus(t, &st);
	LtCheck(ctx, passed && full == NODE_THROTTLE_FULL && kept == NODE_THROTTLE_USER && room == NODE_THROTTLE_PASS && st.NumEntries <= 4 &&
		st.NumRefusedFull == 1,
		"a full table of refused users refuses a new one and keeps them; once their window ended it has room",
		"failures passed %u, new %u, a refused one %u, after the window %u, entries %u, refused as full %I64u",
		(UINT)passed, full, kept, room, st.NumEntries, st.NumRefusedFull);

	// ... and makes room by the oldest entry that is not refused
	NodeThrottleSetLimits(t, 2, 0, 0, 0);
	now += 10 * LT_WINDOW;
	passed = true;
	for (UINT i = 0;i < 4;i++)
	{
		Format(name, sizeof(name), "half%u", i);
		passed = LtFail(t, name, NULL, now + i, (i == 0 ? 1 : 2)) && passed;
	}
	UINT evicted = LtTry(t, "newcomer2", NULL, now + 10, false);
	UINT blocked = LtTry(t, "half1", NULL, now + 10, true);
	NodeThrottleGetStatus(t, &st);
	LtCheck(ctx, passed && evicted == NODE_THROTTLE_PASS && blocked == NODE_THROTTLE_USER && st.NumEntries <= 4,
		"a full table makes room by the oldest user that is not refused, and keeps the refused ones",
		"failures passed %u, new %u, a refused one %u, entries %u", (UINT)passed, evicted, blocked, st.NumEntries);
	FreeNodeThrottle(t);
}

//
// The Login of a node
//

// One Login of user with password from source (NULL for none) through NodeLoginThrottled: whether it passed; *error:
// the error the client gets; *ms: its time
static bool LtLogin(NODE *n, char *user, char *password, char *source, UINT *error, double *ms)
{
	NOISE_LOGIN login;
	AUTH_RESULT res;
	UCHAR challenge[NOISE_LOGIN_CHALLENGE_SIZE];
	LARGE_INTEGER start;
	IP ip;

	Zero(&login, sizeof(login));
	login.Method = NOISE_LOGIN_PASSWORD;
	StrCpy(login.HubName, sizeof(login.HubName), LT_HUB);
	StrCpy(login.UserName, sizeof(login.UserName), user);
	StrCpy(login.Password, sizeof(login.Password), password);
	Rand(challenge, sizeof(challenge));
	Zero(&res, sizeof(res));

	QueryPerformanceCounter(&start);
	bool ok = NodeLoginThrottled(n, &login, challenge, NULL, source == NULL ? NULL : LtIp(&ip, source), &res);
	double elapsed = LtElapsed(&start);

	if (error != NULL)
	{
		*error = res.Error;
	}
	if (ms != NULL)
	{
		*ms = elapsed;
	}

	Free(res.Policy);
	FreeX(res.ClientX);
	Zero(&login, sizeof(login));

	return ok && res.Ok;
}

// Wrong passwords of user from source: whether each was refused as a wrong password
static bool LtWrong(NODE *n, char *user, char *source, UINT num)
{
	bool ret = true;

	for (UINT i = 0;i < num;i++)
	{
		UINT err = 0;

		ret = (LtLogin(n, user, LT_WRONG, source, &err, NULL) == false && err == ERR_AUTH_FAILED) && ret;
	}

	return ret;
}

static UINT64 LtRefused(NODE *n)
{
	NODE_THROTTLE_STATUS st;

	NodeThrottleGetStatus(n->LoginThrottle, &st);

	return st.NumRefused;
}

// The time of one PBKDF2 derivation of CS_PBKDF2_ITERATIONS iterations: the cost of a Login of a password of the store
static double LtDerivation()
{
	UCHAR hash[CS_HASH_SIZE], salt[CS_SALT_SIZE];
	LARGE_INTEGER start;

	Rand(salt, sizeof(salt));
	QueryPerformanceCounter(&start);
	CsPbkdf2(hash, sizeof(hash), LT_WRONG, salt, sizeof(salt), CS_PBKDF2_ITERATIONS);

	return LtElapsed(&start);
}

// The users of the hub, all with LT_PASSWORD
static void LtAddUsers(HUB *h)
{
	char *names[] = {"lt_alice", "lt_bob", LT_KNOWN};

	AcLock(h);
	{
		for (UINT i = 0;i < sizeof(names) / sizeof(names[0]);i++)
		{
			USER *u = NewUser(names[i], L"", L"", AUTHTYPE_PASSWORD, NewPasswordAuthData(names[i], LT_PASSWORD));
			AcAddUser(h, u);
			ReleaseUser(u);
		}
	}
	AcUnlock(h);
}

// The limit of a user: its right password is then refused from any source, faster than one derivation
static void LtUser(LT_CTX *ctx, NODE *n)
{
	UINT err_other = 0, err_none = 0;
	double ms_other = 0, ms_none = 0;

	Print("[the limit of a user]\n");
	UINT64 before = LtRefused(n);
	bool wrong = LtWrong(n, "lt_alice", "192.0.2.1", LT_USER_LIMIT);
	bool counted = (LtRefused(n) == before);
	bool other = LtLogin(n, "lt_alice", LT_PASSWORD, "192.0.2.99", &err_other, &ms_other);
	bool none = LtLogin(n, "lt_alice", LT_PASSWORD, NULL, &err_none, &ms_none);
	ctx->NumRefused += 2;
	UINT64 refused = LtRefused(n) - before;

	LtCheck(ctx, wrong && counted, "the wrong passwords of a user below its limit are checked and refused as wrong passwords",
		"refused as wrong %u, refused by the throttle %u", (UINT)wrong, (UINT)(counted == false));
	LtCheck(ctx, other == false && none == false && err_other == ERR_AUTH_FAILED && err_none == ERR_AUTH_FAILED && refused == 2,
		"then its right password is refused from another source and from an unknown one, as a wrong password",
		"another source %u (error %u), no source %u (error %u), refusals %I64u", (UINT)other, err_other, (UINT)none, err_none, refused);
	LtCheck(ctx, ms_other < ctx->Derivation && ms_none < ctx->Derivation,
		"  each refusal takes less time than one derivation", "%.3f ms and %.3f ms, a derivation %.3f ms", ms_other, ms_none, ctx->Derivation);
}

// The limit of a source across users, and an honest source
static void LtSource(LT_CTX *ctx, NODE *n)
{
	char name[MAX_SIZE];
	UINT err_sprayer = 0, err_honest = 0;
	double ms = 0;

	Print("[the limit of a source]\n");
	bool wrong = true;
	for (UINT i = 0;i < LT_SOURCE_LIMIT;i++)
	{
		Format(name, sizeof(name), "lt_spray%u", i);
		wrong = LtWrong(n, name, "198.51.100.7", 1) && wrong;
	}

	UINT64 before = LtRefused(n);
	bool sprayer = LtLogin(n, "lt_bob", LT_PASSWORD, "198.51.100.7", &err_sprayer, &ms);
	ctx->NumRefused++;
	bool honest = LtLogin(n, "lt_bob", LT_PASSWORD, "198.51.100.8", &err_honest, NULL);
	UINT64 refused = LtRefused(n) - before;

	LtCheck(ctx, wrong && sprayer == false && err_sprayer == ERR_AUTH_FAILED && refused == 1 && ms < ctx->Derivation,
		"after the limit of wrong passwords from a source across users, the source is refused for a user it never tried",
		"wrong passwords refused %u, the source logged in %u (error %u), refusals %I64u, %.3f ms", (UINT)wrong, (UINT)sprayer, err_sprayer, refused, ms);
	LtCheck(ctx, honest && err_honest == ERR_NO_ERROR, "  an honest source logs the same user in", "logged in %u, error %u", (UINT)honest, err_honest);
}

// An unknown user is throttled as a known one, and the times of their refusals do not tell them apart
static void LtUnknown(LT_CTX *ctx, NODE *n)
{
	double known[LT_TIMED], unknown[LT_TIMED];
	bool same = true, refused = true;

	Print("[an unknown user]\n");
	bool wrong = LtWrong(n, LT_KNOWN, "203.0.113.1", LT_USER_LIMIT) && LtWrong(n, LT_UNKNOWN, "203.0.113.2", LT_USER_LIMIT);

	UINT64 before = LtRefused(n);
	for (UINT i = 0;i < LT_TIMED;i++)
	{
		UINT err_known = 0, err_unknown = 0;

		bool a = LtLogin(n, LT_KNOWN, LT_PASSWORD, "203.0.113.3", &err_known, &known[i]);
		bool b = LtLogin(n, LT_UNKNOWN, LT_PASSWORD, "203.0.113.3", &err_unknown, &unknown[i]);
		refused = refused && a == false && b == false;
		same = same && err_known == ERR_AUTH_FAILED && err_unknown == err_known;
	}
	ctx->NumRefused += 2 * LT_TIMED;
	UINT64 num = LtRefused(n) - before;

	double median_known = LtMedian(known, LT_TIMED);
	double median_unknown = LtMedian(unknown, LT_TIMED);
	double diff = (median_known > median_unknown ? median_known - median_unknown : median_unknown - median_known);

	LtCheck(ctx, wrong && refused && same && num == 2 * LT_TIMED,
		"an unknown user is throttled as a known one: after the same limit both are refused with the same answer",
		"wrong passwords refused %u, all refused %u, same answer %u, refusals %I64u of %u", (UINT)wrong, (UINT)refused, (UINT)same, num, 2 * LT_TIMED);
	LtCheck(ctx, median_known < ctx->Derivation / 10 && median_unknown < ctx->Derivation / 10 && diff < ctx->Derivation / 100,
		"  the times of their refusals do not tell them apart, and are far below one derivation",
		"median %.4f ms known, %.4f ms unknown, a derivation %.3f ms", median_known, median_unknown, ctx->Derivation);
	Print("  [INFO] refusal median: known %.4f ms, unknown %.4f ms; one derivation %.3f ms\n", median_known, median_unknown, ctx->Derivation);
}

// A new empty data directory under the temp directory of the process, with the configuration store of the server
// role: one worker and the hub as an online L2 network
static void LtNewDir(wchar_t *dir, UINT size)
{
	wchar_t tmp[MAX_PATH];
	wchar_t path[MAX_PATH];

	UniFormat(tmp, sizeof(tmp), L"login_throttle_%u", Rand32());
	ConbinePathW(dir, size, MsGetMyTempDirW(), tmp);
	MakeDirExW(dir);

	ConbinePathW(path, sizeof(path), dir, CS_FILE_NAME);
	CONFIG_STORE *s = CsOpen(path);
	if (s == NULL)
	{
		Print("  configuration store %S cannot be opened\n", path);
		return;
	}

	CsSetSetting(s, NODE_SETTING_ROLES, "server");
	CsSetSetting(s, NODE_SETTING_WORKERS, "1");
	CsAddNetwork(s, LT_HUB, CS_MODE_L2, true);
	CsClose(s);
}

// Delete the files of a directory, then the directory (it holds no subdirectory)
static void LtDeleteFiles(wchar_t *dir)
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

// The text of every node log file of a data directory, NULL when there is none; the caller frees it
static char *LtReadLog(wchar_t *dir)
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

// The number of times part is in log
static UINT LtLogCount(char *log, char *part)
{
	UINT num = 0;
	UINT pos = 0;

	while (log != NULL)
	{
		UINT i = SearchStrEx(log, part, pos, true);
		if (i == INFINITE)
		{
			break;
		}
		num++;
		pos = i + StrLen(part);
	}

	return num;
}

RANZ_TEST("loginthrottle", loginthrottle_test, "Login throttle: the failures of a user or a source refuse further Logins without a check, an unknown user as a known one; each refusal is counted and logged without the password.");
void loginthrottle_test(UINT num, char **arg)
{
	LT_CTX *ctx = ZeroMalloc(sizeof(LT_CTX));
	wchar_t dir[MAX_PATH], log_dir[MAX_PATH];
	NODE_THROTTLE_STATUS st;

	Print("Login throttle test: the throttle of the Login of a node\n");

	LtAlone(ctx);

	Print("[the Login of a node]\n");
	ctx->Derivation = LtDerivation();
	Print("  [INFO] one PBKDF2 derivation of %u iterations: %.3f ms\n", CS_PBKDF2_ITERATIONS, ctx->Derivation);

	LtNewDir(dir, sizeof(dir));
	NODE *n = NewNode(dir);
	NodeStart(n);
	HUB *hub = NodeGetHub(n, LT_HUB);
	Zero(&st, sizeof(st));

	if (LtCheck(ctx, hub != NULL && n->LoginThrottle != NULL, "the server role of the node runs the hub, and the node has a throttle",
		"hub %p, throttle %p", hub, n->LoginThrottle))
	{
		LtAddUsers(hub);
		ReleaseHub(hub);
		NodeThrottleSetLimits(n->LoginThrottle, LT_USER_LIMIT, LT_SOURCE_LIMIT, LT_NODE_WINDOW, 0);

		UINT err = 0;
		bool right = LtLogin(n, "lt_alice", LT_PASSWORD, "192.0.2.1", &err, NULL);
		LtCheck(ctx, right && err == ERR_NO_ERROR, "the right password logs in through the throttle", "logged in %u, error %u", (UINT)right, err);

		LtUser(ctx, n);
		LtSource(ctx, n);
		LtUnknown(ctx, n);

		NodeThrottleGetStatus(n->LoginThrottle, &st);
		LtCheck(ctx, st.NumRefused == ctx->NumRefused && st.NumRefusedUser + st.NumRefusedSource == st.NumRefused && st.NumRefusedSource == 1,
			"every refusal is counted", "refused %I64u (user %I64u, source %I64u, full %I64u), the test made %I64u",
			st.NumRefused, st.NumRefusedUser, st.NumRefusedSource, st.NumRefusedFull, ctx->NumRefused);
	}

	NodeStop(n);
	FreeNode(n);

	// The node log, complete once the node is freed
	char *log = LtReadLog(dir);
	UINT lines = LtLogCount(log, "Login throttle: a Login of ");
	UINT unknown_lines = LtLogCount(log, "Login throttle: a Login of " LT_UNKNOWN " on " LT_HUB " from 203.0.113.3 refused without a check");
	UINT source_lines = LtLogCount(log, "Login throttle: a Login of lt_bob on " LT_HUB " from 198.51.100.7 refused without a check: the source");
	LtCheck(ctx, log != NULL && lines == ctx->NumRefused && unknown_lines == LT_TIMED && source_lines == 1,
		"the node log has one line for each refusal, with the user, the hub, the source and the reason",
		"%u lines of %I64u refusals, %u of the unknown user, %u of the source", lines, ctx->NumRefused, unknown_lines, source_lines);
	LtCheck(ctx, log != NULL && LtLogCount(log, LT_PASSWORD) == 0 && LtLogCount(log, LT_WRONG) == 0,
		"the node log holds no password", "%s", log == NULL ? "no node log" : "a password is in the log");
	Free(log);

	ConbinePathW(log_dir, sizeof(log_dir), dir, NODE_LOG_DIR_NAME);
	LtDeleteFiles(log_dir);
	LtDeleteFiles(dir);

	if (ctx->NumFailed == 0)
	{
		Print("LOGINTHROTTLE TEST OK\n");
	}
	else
	{
		Print("LOGINTHROTTLE TEST FAILED (%u of %u checks failed)\n", ctx->NumFailed, ctx->NumChecks);
	}

	Free(ctx);
}
