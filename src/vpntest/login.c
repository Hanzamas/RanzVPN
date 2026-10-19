// login.c
// Named login path tests of vpntest (PKG-6 #110)
//
// Every test runs the in-process server of the harness (HarnessOpenServer: TCP 39555, a fresh configuration, the hub
// LOGIN_HUB with the password user LOGIN_USER) and talks to it through the raw-pack client of harness_pack.c, which
// sends Packs that the client code never builds.
// - "authtype" (FND-26): a login with authtype 96, the former external authentication of the removed IPC client,
//   passed without a credential as any existing user. It must get ERR_AUTHTYPE_NOT_SUPPORTED and create no session,
//   like any other unknown authtype; authtypes 0 to 2 keep their results.
// - "acpassword" (FND-27): the access list of the hub (source IP address limit) applies to the 'password' method as
//   it does to a login. From a denied address the method gets ERR_IP_ADDRESS_DENIED before the old password is
//   checked, so it neither changes the password nor tells a right old password from a wrong one.
// A test prints "<NAME> TEST OK" only when every check passes.

#include "harness_int.h"

#include "Cedar/Account.h"
#include "Cedar/Admin.h"
#include "Cedar/Cedar.h"
#include "Cedar/Hub.h"
#include "Cedar/Sam.h"
#include "Cedar/Server.h"

#include "Mayaqua/Encrypt.h"
#include "Mayaqua/Kernel.h"
#include "Mayaqua/Memory.h"
#include "Mayaqua/Network.h"
#include "Mayaqua/Pack.h"
#include "Mayaqua/Str.h"
#include "Mayaqua/Tick64.h"

#define	LOGIN_HUB					"HARNESS_LOGIN"		// Hub of the login tests
#define	LOGIN_USER					"tester_login"		// Password user of LOGIN_HUB, password HARNESS_PASSWORD
#define	LOGIN_WRONG_PASSWORD		"Harness-Pass-2"	// Not the password of LOGIN_USER
#define	LOGIN_NEW_PASSWORD			"Harness-Pass-3"	// Password that "acpassword" sets through the 'password' method
#define	LOGIN_AUTHTYPE_96			96					// Former external authentication, sent only by the removed IPC client
#define	LOGIN_AUTHTYPE_UNKNOWN		97					// An authtype that never existed
#define	LOGIN_WATCHDOG_LIMIT		120000				// A login test process is aborted after this (ms)
#define	LOGIN_SESSION_TIMEOUT		10000				// The session of a login ends this soon after its client left (ms)
#define	LOGIN_POLL					50					// Poll interval of the session count (ms)

// Number of sessions of LOGIN_HUB through EnumSession, or INFINITE when the call fails
static UINT LoginNumSessions(HARNESS *h)
{
	RPC_ENUM_SESSION t;
	UINT num;

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), LOGIN_HUB);

	if (ScEnumSession(h->Rpc, &t) != ERR_NO_ERROR)
	{
		return INFINITE;
	}

	num = t.NumSession;
	FreeRpcEnumSession(&t);

	return num;
}

// Wait until LOGIN_HUB has no session: the session of a login that passed ends when its client disconnects
static bool LoginWaitNoSession(HARNESS *h)
{
	UINT64 end = Tick64() + (UINT64)LOGIN_SESSION_TIMEOUT;

	while (LoginNumSessions(h) != 0)
	{
		if (Tick64() >= end)
		{
			return false;
		}

		SleepThread(LOGIN_POLL);
	}

	return true;
}

// One login of LOGIN_USER with authtype on a raw connection; password (NULL: no credential) goes into
// "plain_password" for CLIENT_AUTHTYPE_PLAIN_PASSWORD, otherwise into "secure_password" as ClientUploadAuth sends it.
// Returns the error of the answer; *num_sessions gets the sessions of LOGIN_HUB while the connection is still open.
// The next login starts after the session of this one, if any, has ended.
static UINT LoginTry(HARNESS *h, UINT authtype, char *password, UINT *num_sessions)
{
	UCHAR random[SHA1_SIZE];
	UCHAR hashed_password[SHA1_SIZE];
	UCHAR secure_password[SHA1_SIZE];
	SOCK *s = HarnessRawConnect(random);
	PACK *p;
	UINT err;

	*num_sessions = INFINITE;

	if (s == NULL)
	{
		HarnessCheck(h, false, "raw connection to the test listener: TLS, signature and hello");
		return ERR_DISCONNECTED;
	}

	p = HarnessRawLoginPack(LOGIN_HUB, LOGIN_USER, authtype);

	if (password != NULL)
	{
		if (authtype == CLIENT_AUTHTYPE_PLAIN_PASSWORD)
		{
			PackAddStr(p, "plain_password", password);
		}
		else
		{
			HashPassword(hashed_password, LOGIN_USER, password);
			SecurePassword(secure_password, hashed_password, random);
			PackAddData(p, "secure_password", secure_password, SHA1_SIZE);
		}
	}

	err = HarnessRawRequest(s, p);
	FreePack(p);

	*num_sessions = LoginNumSessions(h);

	HarnessRawClose(s);

	if (LoginWaitNoSession(h) == false)
	{
		HarnessCheck(h, false, "the session of the login ends after its client disconnected");
	}

	return err;
}

// Check the error of a login and the sessions of LOGIN_HUB while its connection was open
static void LoginExpect(HARNESS *h, char *what, UINT err, UINT expected_err, UINT num_sessions, UINT expected_sessions)
{
	char tmp[MAX_SIZE];

	if (err == expected_err && num_sessions == expected_sessions)
	{
		HarnessCheck(h, true, what);
		return;
	}

	Format(tmp, sizeof(tmp), "%s (error %u, expected %u; %u session(s), expected %u)", what, err, expected_err,
		num_sessions, expected_sessions);
	HarnessCheck(h, false, tmp);
}

// Print the result line of a test from the failed checks that HarnessCloseServer returned
static void LoginReport(char *name, UINT num_fail)
{
	if (num_fail == 0)
	{
		Print("%s TEST OK\n", name);
	}
	else
	{
		Print("%s TEST FAILED (%u failed checks)\n", name, num_fail);
	}
}

// "authtype": the authentication types of a login (FND-26)
void authtype_test(UINT num, char **arg)
{
	HARNESS *h;
	bool ok;
	UINT err;
	UINT num_sessions;

	Print("Login authtype test: in-process server on TCP %u, hub %s, user %s\n", HARNESS_PORT, LOGIN_HUB, LOGIN_USER);

	h = HarnessOpenServer("AUTHTYPE", LOGIN_WATCHDOG_LIMIT, LOGIN_HUB, LOGIN_USER, &ok);

	if (HarnessCheck(h, ok, "server, hub " LOGIN_HUB " and user " LOGIN_USER " ready"))
	{
		Print("[unsupported authtypes]\n");
		HarnessSetPhase("authtype", "96");
		err = LoginTry(h, LOGIN_AUTHTYPE_96, NULL, &num_sessions);
		LoginExpect(h, "authtype 96 (the former external authentication) without a credential: ERR_AUTHTYPE_NOT_SUPPORTED, no session",
			err, ERR_AUTHTYPE_NOT_SUPPORTED, num_sessions, 0);

		HarnessSetPhase("authtype", "96 with the password");
		err = LoginTry(h, LOGIN_AUTHTYPE_96, HARNESS_PASSWORD, &num_sessions);
		LoginExpect(h, "authtype 96 with the secure password of the user: ERR_AUTHTYPE_NOT_SUPPORTED, no session",
			err, ERR_AUTHTYPE_NOT_SUPPORTED, num_sessions, 0);

		HarnessSetPhase("authtype", "97");
		err = LoginTry(h, LOGIN_AUTHTYPE_UNKNOWN, NULL, &num_sessions);
		LoginExpect(h, "authtype 97 (never defined): ERR_AUTHTYPE_NOT_SUPPORTED, no session",
			err, ERR_AUTHTYPE_NOT_SUPPORTED, num_sessions, 0);

		Print("[authtypes 0 to 2]\n");
		HarnessSetPhase("authtype", "0");
		err = LoginTry(h, CLIENT_AUTHTYPE_ANONYMOUS, NULL, &num_sessions);
		LoginExpect(h, "authtype 0 (anonymous) for a password user: ERR_AUTH_FAILED, no session",
			err, ERR_AUTH_FAILED, num_sessions, 0);

		HarnessSetPhase("authtype", "1");
		err = LoginTry(h, CLIENT_AUTHTYPE_PASSWORD, LOGIN_WRONG_PASSWORD, &num_sessions);
		LoginExpect(h, "authtype 1 (password) with a wrong password: ERR_AUTH_FAILED, no session",
			err, ERR_AUTH_FAILED, num_sessions, 0);

		err = LoginTry(h, CLIENT_AUTHTYPE_PASSWORD, HARNESS_PASSWORD, &num_sessions);
		LoginExpect(h, "authtype 1 (password) with the password: welcome Pack, one session",
			err, ERR_NO_ERROR, num_sessions, 1);

		HarnessSetPhase("authtype", "2");
		err = LoginTry(h, CLIENT_AUTHTYPE_PLAIN_PASSWORD, LOGIN_WRONG_PASSWORD, &num_sessions);
		LoginExpect(h, "authtype 2 (plain password) with a wrong password: ERR_AUTH_FAILED, no session",
			err, ERR_AUTH_FAILED, num_sessions, 0);

		err = LoginTry(h, CLIENT_AUTHTYPE_PLAIN_PASSWORD, HARNESS_PASSWORD, &num_sessions);
		LoginExpect(h, "authtype 2 (plain password) with the password: welcome Pack, one session",
			err, ERR_NO_ERROR, num_sessions, 1);
	}

	LoginReport("AUTHTYPE", HarnessCloseServer(h));
}

// Set the access list of LOGIN_HUB through the admin RPC: one rule that denies 127.0.0.1, the address of the raw
// connections (deny), or no rule
static UINT LoginSetDenyLocal(HARNESS *h, bool deny)
{
	RPC_AC_LIST t;
	AC ac;
	UINT err;

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), LOGIN_HUB);
	t.o = NewList(CmpAc);

	if (deny)
	{
		Zero(&ac, sizeof(ac));
		ac.Deny = true;
		ac.Priority = 1;
		SetIP(&ac.IpAddress, 127, 0, 0, 1);
		AddAc(t.o, &ac);
	}

	err = ScSetAcList(h->Rpc, &t);
	FreeRpcAcList(&t);

	return err;
}

// Whether the stored password hash of LOGIN_USER (GetUser) is the hash of password
static bool LoginHasPassword(HARNESS *h, char *password)
{
	RPC_SET_USER t;
	UCHAR hashed_password[SHA1_SIZE];
	bool ret = false;

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), LOGIN_HUB);
	StrCpy(t.Name, sizeof(t.Name), LOGIN_USER);

	if (ScGetUser(h->Rpc, &t) != ERR_NO_ERROR)
	{
		return false;
	}

	HashPassword(hashed_password, LOGIN_USER, password);

	if (t.AuthType == AUTHTYPE_PASSWORD && t.AuthData != NULL)
	{
		AUTHPASSWORD *pw = (AUTHPASSWORD *)t.AuthData;

		ret = (Cmp(pw->HashedKey, hashed_password, SHA1_SIZE) == 0);
	}

	FreeRpcSetUser(&t);

	return ret;
}

// One request of the 'password' method on a raw connection, as a client that changes the password of LOGIN_USER from
// old_password to new_password sends it. Returns the error of the answer.
static UINT LoginChangePassword(HARNESS *h, char *old_password, char *new_password)
{
	UCHAR random[SHA1_SIZE];
	UCHAR hashed_old_password[SHA1_SIZE];
	UCHAR secure_old_password[SHA1_SIZE];
	UCHAR new_password_hash[SHA1_SIZE];
	SOCK *s = HarnessRawConnect(random);
	PACK *p;
	UINT err;

	if (s == NULL)
	{
		HarnessCheck(h, false, "raw connection to the test listener: TLS, signature and hello");
		return ERR_DISCONNECTED;
	}

	HashPassword(hashed_old_password, LOGIN_USER, old_password);
	SecurePassword(secure_old_password, hashed_old_password, random);
	HashPassword(new_password_hash, LOGIN_USER, new_password);

	p = NewPack();
	PackAddStr(p, "method", "password");
	PackAddStr(p, "hubname", LOGIN_HUB);
	PackAddStr(p, "username", LOGIN_USER);
	PackAddData(p, "secure_old_password", secure_old_password, SHA1_SIZE);
	PackAddData(p, "new_password", new_password_hash, SHA1_SIZE);

	err = HarnessRawRequest(s, p);
	FreePack(p);

	HarnessRawClose(s);

	return err;
}

// Check the error of a 'password' request and which password LOGIN_USER has afterwards
static void LoginExpectPassword(HARNESS *h, char *what, UINT err, UINT expected_err, char *expected_password)
{
	bool has = LoginHasPassword(h, expected_password);
	char tmp[MAX_SIZE];

	if (err == expected_err && has)
	{
		HarnessCheck(h, true, what);
		return;
	}

	Format(tmp, sizeof(tmp), "%s (error %u, expected %u; the stored hash %s %s)", what, err, expected_err,
		has ? "is the one of" : "is not the one of", expected_password);
	HarnessCheck(h, false, tmp);
}

// "acpassword": the access list of the hub applies to the 'password' method (FND-27)
void acpassword_test(UINT num, char **arg)
{
	HARNESS *h;
	bool ok;
	UINT err;
	UINT num_sessions;

	Print("Access list on the 'password' method: in-process server on TCP %u, hub %s, user %s\n", HARNESS_PORT,
		LOGIN_HUB, LOGIN_USER);

	h = HarnessOpenServer("ACPASSWORD", LOGIN_WATCHDOG_LIMIT, LOGIN_HUB, LOGIN_USER, &ok);

	if (HarnessCheck(h, ok, "server, hub " LOGIN_HUB " and user " LOGIN_USER " ready"))
	{
		Print("[127.0.0.1 denied]\n");
		HarnessSetPhase("acpassword", "deny");
		HarnessCheckErr(h, LoginSetDenyLocal(h, true), "SetAcList: deny 127.0.0.1 on " LOGIN_HUB);

		err = LoginChangePassword(h, HARNESS_PASSWORD, LOGIN_NEW_PASSWORD);
		LoginExpectPassword(h, "'password' with the right old password: ERR_IP_ADDRESS_DENIED, password unchanged",
			err, ERR_IP_ADDRESS_DENIED, HARNESS_PASSWORD);

		err = LoginChangePassword(h, LOGIN_WRONG_PASSWORD, LOGIN_NEW_PASSWORD);
		LoginExpectPassword(h, "'password' with a wrong old password: ERR_IP_ADDRESS_DENIED, no old password check",
			err, ERR_IP_ADDRESS_DENIED, HARNESS_PASSWORD);

		err = LoginTry(h, CLIENT_AUTHTYPE_PASSWORD, HARNESS_PASSWORD, &num_sessions);
		LoginExpect(h, "login with the password: ERR_IP_ADDRESS_DENIED, no session",
			err, ERR_IP_ADDRESS_DENIED, num_sessions, 0);

		Print("[no access list]\n");
		HarnessSetPhase("acpassword", "allow");
		HarnessCheckErr(h, LoginSetDenyLocal(h, false), "SetAcList: no rule on " LOGIN_HUB);

		err = LoginChangePassword(h, LOGIN_WRONG_PASSWORD, LOGIN_NEW_PASSWORD);
		LoginExpectPassword(h, "'password' with a wrong old password: ERR_OLD_PASSWORD_WRONG, password unchanged",
			err, ERR_OLD_PASSWORD_WRONG, HARNESS_PASSWORD);

		err = LoginChangePassword(h, HARNESS_PASSWORD, LOGIN_NEW_PASSWORD);
		LoginExpectPassword(h, "'password' with the right old password: changed to the new password",
			err, ERR_NO_ERROR, LOGIN_NEW_PASSWORD);

		err = LoginTry(h, CLIENT_AUTHTYPE_PASSWORD, LOGIN_NEW_PASSWORD, &num_sessions);
		LoginExpect(h, "login with the new password: welcome Pack, one session",
			err, ERR_NO_ERROR, num_sessions, 1);
	}

	LoginReport("ACPASSWORD", HarnessCloseServer(h));
}
