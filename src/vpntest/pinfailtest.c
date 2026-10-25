// pinfailtest.c
// Named pinned key failure test of vpntest ("pinfail" command, FIX-8 #407)
//
// The Login of a node with trust on first use (NodeLoginPinned, Cedar/Node.c) when the configuration store cannot
// check the pinned key (CsPinUserKey, Cedar/ConfigStore.c). The server role of a node runs one hub; its users are in
// the hub, which Sam checks, and the password users also in the store, which pins their Noise static keys:
// - A user that the store does not keep logs in without a pin: a user of the Windows domain (a local account that
//   the test creates, which LogonUser checks the way it checks a domain account; that needs administrator rights,
//   which CI has) and an anonymous Login. Both log in again with another key.
// - A store that fails refuses the Login. An authorizer on the connection of the store (sqlite3_set_authorizer)
//   makes one step of the pin fail at a time: the begin of the transaction, the read of the user, the write of the
//   pin and the commit. Each Login with the right password is refused with the answer of a wrong password, the node
//   log says that the store failed, and the user has no pin; once the store works the same Login passes.
// - A first Login whose commit failed left the user without a pin, so the next Login pins its key: a Login with
//   another key is then refused.
// - A Login with the right password and a key that is not the pinned one is still refused, with its line in the
//   node log.
// Print "PINFAIL TEST OK" only when every check passes.

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
#include "Mayaqua/Object.h"
#include "Mayaqua/Str.h"

#include "Core/Noise.h"

#include <lmcons.h>
#include <lmaccess.h>
#include <lmerr.h>

// The winsqlite3.h of the Windows SDK uses sqlite3_filename in every build but declares it only from NTDDI_WIN11_ZN
// on (as in Cedar/ConfigStore.c)
#if NTDDI_VERSION < NTDDI_WIN11_ZN
typedef const char *sqlite3_filename;
#endif

#include <winsqlite/winsqlite3.h>

#ifndef SQLITE_CALLBACK
#define	SQLITE_CALLBACK
#endif

#define	PINFAIL_HUB			"PINFAIL"			// The hub of the node and the network of the store
#define	PINFAIL_PASSWORD	"Pin-Fail-Pass-1"	// The password of every password user
#define	PINFAIL_WRONG		"Pin-Fail-Wrong-1"	// No user's password
#define	PINFAIL_PINNED		"pf_pinned"			// A password user whose key is pinned by its first Login
#define	PINFAIL_DOMAIN		"pf_domain"			// A user of the Windows domain: the local account of the test
#define	PINFAIL_ANONYMOUS	"pf_anonymous"		// An anonymous user

// The step of the pin that the authorizer makes fail
#define	PINFAIL_STEP_NONE	0
#define	PINFAIL_STEP_BEGIN	1					// BEGIN IMMEDIATE
#define	PINFAIL_STEP_READ	2					// The SELECT of the user and its pinned key
#define	PINFAIL_STEP_WRITE	3					// The UPDATE that writes the pin
#define	PINFAIL_STEP_COMMIT	4					// The COMMIT

// One step that fails, and the password user (in the hub and in the store, without a pin) that logs in while it does
typedef struct PINFAIL_STEP
{
	UINT Step;
	char *Name;
	char *User;
} PINFAIL_STEP;

static PINFAIL_STEP pinfail_steps[] =
{
	{PINFAIL_STEP_BEGIN, "begin", "pf_begin"},
	{PINFAIL_STEP_READ, "read", "pf_read"},
	{PINFAIL_STEP_WRITE, "write", "pf_write"},
	{PINFAIL_STEP_COMMIT, "commit", "pf_commit"},
};

// The state of the test
typedef struct PINFAIL_CTX
{
	UINT NumChecks;
	UINT NumFailed;
	wchar_t Account[32];				// The local account of the domain user
	char AccountPassword[64];			// Its password
	bool HaveAccount;
} PINFAIL_CTX;

static bool PinFailCheck(PINFAIL_CTX *ctx, bool ok, char *what, char *fmt, ...) RANZ_PRINTF_FORMAT(4, 5);
static bool PinFailCheck(PINFAIL_CTX *ctx, bool ok, char *what, char *fmt, ...)
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

// The authorizer of the connection of the store: SQLITE_DENY for the statement of the step param, which then fails
// to prepare, as a store that cannot begin, read, write or commit
static int SQLITE_CALLBACK PinFailAuthorizer(void *param, int action, const char *arg1, const char *arg2, const char *db, const char *trigger)
{
	UINT step = (UINT)(UINT_PTR)param;
	char *a1 = (char *)(arg1 != NULL ? arg1 : "");
	char *a2 = (char *)(arg2 != NULL ? arg2 : "");

	switch (step)
	{
	case PINFAIL_STEP_BEGIN:
		return (action == SQLITE_TRANSACTION && StrCmpi(a1, "BEGIN") == 0) ? SQLITE_DENY : SQLITE_OK;

	case PINFAIL_STEP_READ:
		return (action == SQLITE_READ && StrCmpi(a1, "users") == 0) ? SQLITE_DENY : SQLITE_OK;

	case PINFAIL_STEP_WRITE:
		return (action == SQLITE_UPDATE && StrCmpi(a1, "users") == 0 && StrCmpi(a2, "pinned_key") == 0) ? SQLITE_DENY : SQLITE_OK;

	case PINFAIL_STEP_COMMIT:
		return (action == SQLITE_TRANSACTION && StrCmpi(a1, "COMMIT") == 0) ? SQLITE_DENY : SQLITE_OK;
	}

	return SQLITE_OK;
}

// Make the step fail on the connection of the store of the node, or no step for PINFAIL_STEP_NONE
static void PinFailSetStep(NODE *n, UINT step)
{
	Lock(n->Store->Lock);
	{
		if (step == PINFAIL_STEP_NONE)
		{
			sqlite3_set_authorizer(n->Store->Db, NULL, NULL);
		}
		else
		{
			sqlite3_set_authorizer(n->Store->Db, PinFailAuthorizer, (void *)(UINT_PTR)step);
		}
	}
	Unlock(n->Store->Lock);
}

// One Login of user on the hub of the node, by password (or anonymous) with the Noise static key key, through
// NodeLoginPinned: whether it passed; *error: the error the client gets
static bool PinFailLogin(NODE *n, char *user, UINT method, char *password, UCHAR *key, UINT *error)
{
	NOISE_LOGIN login;
	AUTH_RESULT res;
	UCHAR challenge[NOISE_LOGIN_CHALLENGE_SIZE];

	Zero(&login, sizeof(login));
	login.Method = method;
	StrCpy(login.HubName, sizeof(login.HubName), PINFAIL_HUB);
	StrCpy(login.UserName, sizeof(login.UserName), user);
	if (password != NULL)
	{
		StrCpy(login.Password, sizeof(login.Password), password);
	}
	Rand(challenge, sizeof(challenge));
	Zero(&res, sizeof(res));

	bool ok = NodeLoginPinned(n, &login, challenge, key, &res);
	*error = res.Error;

	Free(res.Policy);
	FreeX(res.ClientX);
	Zero(&login, sizeof(login));

	return ok && res.Ok;
}

// Whether the store keeps the user, and whether a key is pinned to it
static bool PinFailHasKey(NODE *n, char *user, bool *kept)
{
	CS_USER u;

	Zero(&u, sizeof(u));
	*kept = CsGetUser(n->Store, PINFAIL_HUB, user, &u);

	return *kept && u.HasKey;
}

// A new Noise static key: the X25519 public key of a client node
static void PinFailNewKey(UCHAR *key)
{
	UCHAR priv[NOISE_KEY_SIZE];

	CryptoX25519GenerateKey(priv, key);
	Zero(priv, sizeof(priv));
}

// The local account that stands for a domain account, with a random name and a password that meets the default
// complexity policy of Windows Server
static bool PinFailAddAccount(PINFAIL_CTX *ctx)
{
	USER_INFO_1 ui;
	wchar_t password[64];
	DWORD parm_err = 0;
	UCHAR r[8];

	Rand(r, sizeof(r));
	UniFormat(ctx->Account, sizeof(ctx->Account), L"ranzpf%02x%02x", r[0], r[1]);
	Format(ctx->AccountPassword, sizeof(ctx->AccountPassword), "Rz#%02x%02x%02x%02x%02x%02x-Pf9", r[2], r[3], r[4], r[5], r[6], r[7]);
	StrToUni(password, sizeof(password), ctx->AccountPassword);

	Zero(&ui, sizeof(ui));
	ui.usri1_name = ctx->Account;
	ui.usri1_password = password;
	ui.usri1_priv = USER_PRIV_USER;
	ui.usri1_flags = UF_SCRIPT | UF_DONT_EXPIRE_PASSWD;

	NET_API_STATUS st = NetUserAdd(NULL, 1, (LPBYTE)&ui, &parm_err);
	ctx->HaveAccount = (st == NERR_Success);
	Zero(password, sizeof(password));

	return PinFailCheck(ctx, ctx->HaveAccount, "a local account stands for the domain user (administrator rights)",
		"NetUserAdd: status %lu (parameter %lu)", (unsigned long)st, (unsigned long)parm_err);
}

static void PinFailDeleteAccount(PINFAIL_CTX *ctx)
{
	if (ctx->HaveAccount)
	{
		NET_API_STATUS st = NetUserDel(NULL, ctx->Account);
		PinFailCheck(ctx, st == NERR_Success, "the local account is deleted", "NetUserDel: status %lu", (unsigned long)st);
		ctx->HaveAccount = false;
	}
}

// The users of the hub: the password users, the domain user and the anonymous user
static void PinFailAddUsers(PINFAIL_CTX *ctx, HUB *h)
{
	USER *u;

	AcLock(h);
	{
		u = NewUser(PINFAIL_PINNED, L"", L"", AUTHTYPE_PASSWORD, NewPasswordAuthData(PINFAIL_PINNED, PINFAIL_PASSWORD));
		AcAddUser(h, u);
		ReleaseUser(u);

		for (UINT i = 0;i < sizeof(pinfail_steps) / sizeof(pinfail_steps[0]);i++)
		{
			char *name = pinfail_steps[i].User;

			u = NewUser(name, L"", L"", AUTHTYPE_PASSWORD, NewPasswordAuthData(name, PINFAIL_PASSWORD));
			AcAddUser(h, u);
			ReleaseUser(u);
		}

		u = NewUser(PINFAIL_DOMAIN, L"", L"", AUTHTYPE_NT, NewNTAuthData(ctx->Account));
		AcAddUser(h, u);
		ReleaseUser(u);

		u = NewUser(PINFAIL_ANONYMOUS, L"", L"", AUTHTYPE_ANONYMOUS, NULL);
		AcAddUser(h, u);
		ReleaseUser(u);
	}
	AcUnlock(h);
}

// Add a password user without a pin to the store
static void PinFailAddStoreUser(CONFIG_STORE *s, char *name)
{
	CS_USER u;

	Zero(&u, sizeof(u));
	StrCpy(u.Network, sizeof(u.Network), PINFAIL_HUB);
	StrCpy(u.Name, sizeof(u.Name), name);
	u.AuthType = AUTHTYPE_PASSWORD;
	CsAddUser(s, &u);
}

// A new empty data directory under the temp directory of the process, with the configuration store of the server
// role: one worker, the hub as an online L2 network and the password users, so their keys can be pinned. The domain
// and the anonymous user are not in the store.
static void PinFailNewDir(wchar_t *dir, UINT size)
{
	wchar_t tmp[MAX_PATH];
	wchar_t path[MAX_PATH];

	UniFormat(tmp, sizeof(tmp), L"pin_fail_%u", Rand32());
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
	CsAddNetwork(s, PINFAIL_HUB, CS_MODE_L2, true);
	PinFailAddStoreUser(s, PINFAIL_PINNED);
	for (UINT i = 0;i < sizeof(pinfail_steps) / sizeof(pinfail_steps[0]);i++)
	{
		PinFailAddStoreUser(s, pinfail_steps[i].User);
	}

	CsClose(s);
}

// Delete the files of a directory, then the directory (it holds no subdirectory)
static void PinFailDeleteFiles(wchar_t *dir)
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
static char *PinFailReadLog(wchar_t *dir)
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

static bool PinFailLogHas(char *log, char *part)
{
	return (log != NULL && SearchStrEx(log, part, 0, true) != INFINITE);
}

// The users that the store does not keep: a domain user and an anonymous Login pass, and are not pinned
static void PinFailNotKept(PINFAIL_CTX *ctx, NODE *n)
{
	UCHAR key_a[NOISE_KEY_SIZE], key_b[NOISE_KEY_SIZE];
	UINT err_a = 0, err_b = 0;
	bool kept = false;

	Print("[a user that the store does not keep]\n");
	PinFailNewKey(key_a);
	PinFailNewKey(key_b);

	if (ctx->HaveAccount)
	{
		bool a = PinFailLogin(n, PINFAIL_DOMAIN, NOISE_LOGIN_PASSWORD, ctx->AccountPassword, key_a, &err_a);
		bool b = PinFailLogin(n, PINFAIL_DOMAIN, NOISE_LOGIN_PASSWORD, ctx->AccountPassword, key_b, &err_b);
		bool pinned = PinFailHasKey(n, PINFAIL_DOMAIN, &kept);
		PinFailCheck(ctx, a && b && kept == false && pinned == false,
			"a domain user logs in without a pin: the store does not keep it, a Login with another key passes too",
			"first Login %u (error %u), second %u (error %u), kept %u", (UINT)a, err_a, (UINT)b, err_b, (UINT)kept);
	}

	bool a = PinFailLogin(n, PINFAIL_ANONYMOUS, NOISE_LOGIN_ANONYMOUS, NULL, key_a, &err_a);
	bool b = PinFailLogin(n, PINFAIL_ANONYMOUS, NOISE_LOGIN_ANONYMOUS, NULL, key_b, &err_b);
	bool pinned = PinFailHasKey(n, PINFAIL_ANONYMOUS, &kept);
	PinFailCheck(ctx, a && b && kept == false && pinned == false,
		"an anonymous Login passes without a pin: the store does not keep the user, a Login with another key passes too",
		"first Login %u (error %u), second %u (error %u), kept %u", (UINT)a, err_a, (UINT)b, err_b, (UINT)kept);
}

// Each step of the pin fails in turn: the Login is refused with the answer of a wrong password and leaves no pin;
// once the store works the same Login passes and pins the key
static void PinFailSteps(PINFAIL_CTX *ctx, NODE *n, UINT wrong_err)
{
	for (UINT i = 0;i < sizeof(pinfail_steps) / sizeof(pinfail_steps[0]);i++)
	{
		PINFAIL_STEP *s = &pinfail_steps[i];
		UCHAR key[NOISE_KEY_SIZE], other[NOISE_KEY_SIZE];
		UINT err = 0, err_again = 0, err_other = 0;
		bool kept = false;
		char what[MAX_SIZE];

		Print("[the %s of the pin fails]\n", s->Name);
		PinFailNewKey(key);
		PinFailNewKey(other);

		PinFailSetStep(n, s->Step);
		bool ok = PinFailLogin(n, s->User, NOISE_LOGIN_PASSWORD, PINFAIL_PASSWORD, key, &err);
		PinFailSetStep(n, PINFAIL_STEP_NONE);

		Format(what, sizeof(what), "the right password is refused when the %s fails, with the answer of a wrong password", s->Name);
		PinFailCheck(ctx, ok == false && err == wrong_err, what, "Login %u, error %u, a wrong password gives %u", (UINT)ok, err, wrong_err);

		bool pinned = PinFailHasKey(n, s->User, &kept);
		Format(what, sizeof(what), "  the user has no pin after the failed %s", s->Name);
		PinFailCheck(ctx, kept && pinned == false, what, "kept %u, pinned %u", (UINT)kept, (UINT)pinned);

		// The store works again: the next Login pins the key, and another key is then refused
		bool again = PinFailLogin(n, s->User, NOISE_LOGIN_PASSWORD, PINFAIL_PASSWORD, key, &err_again);
		pinned = PinFailHasKey(n, s->User, &kept);
		bool other_ok = PinFailLogin(n, s->User, NOISE_LOGIN_PASSWORD, PINFAIL_PASSWORD, other, &err_other);
		PinFailCheck(ctx, again && pinned && other_ok == false && err_other == wrong_err,
			"  once the store works, the next Login pins its key and another key is refused",
			"next Login %u (error %u), pinned %u, another key %u (error %u)", (UINT)again, err_again, (UINT)pinned, (UINT)other_ok, err_other);
	}
}

RANZ_TEST("pinfail", pinfail_test, "Pinned key failure: a store that fails to begin, read, write or commit the pin refuses the Login as a wrong password; a user the store does not keep is not pinned (administrator rights).");
void pinfail_test(UINT num, char **arg)
{
	PINFAIL_CTX *ctx = ZeroMalloc(sizeof(PINFAIL_CTX));
	wchar_t dir[MAX_PATH], log_dir[MAX_PATH];

	Print("Pinned key failure test: the Login of a node when the configuration store cannot check the pinned key\n");

	PinFailAddAccount(ctx);
	PinFailCheck(ctx, CryptoInit(), "the crypto of the new core starts", "CryptoInit failed");

	PinFailNewDir(dir, sizeof(dir));
	NODE *n = NewNode(dir);
	NodeStart(n);
	HUB *hub = NodeGetHub(n, PINFAIL_HUB);

	if (PinFailCheck(ctx, hub != NULL && n->Store != NULL, "the server role of the node runs the hub on its configuration store", "hub %p, store %p", hub, n->Store))
	{
		UCHAR key_a[NOISE_KEY_SIZE], key_b[NOISE_KEY_SIZE];
		UINT err_a = 0, err_b = 0, wrong_err = 0;
		bool kept = false;

		PinFailAddUsers(ctx, hub);
		ReleaseHub(hub);

		PinFailNewKey(key_a);
		PinFailNewKey(key_b);

		// The answer of a wrong password, which every refused Login below must give too
		Print("[a wrong password]\n");
		bool wrong = PinFailLogin(n, PINFAIL_PINNED, NOISE_LOGIN_PASSWORD, PINFAIL_WRONG, key_a, &wrong_err);
		PinFailCheck(ctx, wrong == false && wrong_err == ERR_AUTH_FAILED, "a wrong password is refused with ERR_AUTH_FAILED",
			"Login %u, error %u", (UINT)wrong, wrong_err);

		PinFailNotKept(ctx, n);
		PinFailSteps(ctx, n, wrong_err);

		// Trust on first use: the right password with a key that is not the pinned one is still refused
		Print("[a key that is not the pinned one]\n");
		bool a = PinFailLogin(n, PINFAIL_PINNED, NOISE_LOGIN_PASSWORD, PINFAIL_PASSWORD, key_a, &err_a);
		bool pinned = PinFailHasKey(n, PINFAIL_PINNED, &kept);
		bool b = PinFailLogin(n, PINFAIL_PINNED, NOISE_LOGIN_PASSWORD, PINFAIL_PASSWORD, key_b, &err_b);
		bool again = PinFailLogin(n, PINFAIL_PINNED, NOISE_LOGIN_PASSWORD, PINFAIL_PASSWORD, key_a, &err_a);
		PinFailCheck(ctx, a && pinned && b == false && err_b == wrong_err && again,
			"the first Login pins its key; the right password with another key is refused as a wrong password, the pinned key logs in",
			"first Login %u, pinned %u, another key %u (error %u), the pinned key again %u (error %u)", (UINT)a, (UINT)pinned, (UINT)b, err_b, (UINT)again, err_a);

		Zero(key_a, sizeof(key_a));
		Zero(key_b, sizeof(key_b));
	}

	NodeStop(n);
	FreeNode(n);

	// The node log, complete once the node is freed
	char *log = PinFailReadLog(dir);
	for (UINT i = 0;i < sizeof(pinfail_steps) / sizeof(pinfail_steps[0]);i++)
	{
		char line[MAX_SIZE], what[MAX_SIZE];

		Format(line, sizeof(line), "Login of %s on %s refused: the configuration store failed to check the pinned key", pinfail_steps[i].User, PINFAIL_HUB);
		Format(what, sizeof(what), "the node log says why the Login was refused when the %s failed", pinfail_steps[i].Name);
		PinFailCheck(ctx, PinFailLogHas(log, line), what, "%s", log == NULL ? "no node log" : "the line is missing");
	}

	char line[MAX_SIZE];
	Format(line, sizeof(line), "Login of %s on %s refused: the Noise static key is not the pinned one", PINFAIL_PINNED, PINFAIL_HUB);
	PinFailCheck(ctx, PinFailLogHas(log, line), "the node log says why the Login with another key was refused", "%s", log == NULL ? "no node log" : "the line is missing");

	Format(line, sizeof(line), "Login of %s on %s refused", PINFAIL_DOMAIN, PINFAIL_HUB);
	bool domain_refused = PinFailLogHas(log, line);
	Format(line, sizeof(line), "Login of %s on %s refused", PINFAIL_ANONYMOUS, PINFAIL_HUB);
	PinFailCheck(ctx, domain_refused == false && PinFailLogHas(log, line) == false,
		"the node log refuses no Login of a user that the store does not keep", "domain user refused %u", (UINT)domain_refused);
	Free(log);

	ConbinePathW(log_dir, sizeof(log_dir), dir, NODE_LOG_DIR_NAME);
	PinFailDeleteFiles(log_dir);
	PinFailDeleteFiles(dir);

	PinFailDeleteAccount(ctx);

	if (ctx->NumFailed == 0)
	{
		Print("PINFAIL TEST OK\n");
	}
	else
	{
		Print("PINFAIL TEST FAILED (%u of %u checks failed)\n", ctx->NumFailed, ctx->NumChecks);
	}

	Zero(ctx->AccountPassword, sizeof(ctx->AccountPassword));
	Free(ctx);
}
