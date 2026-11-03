// nodelogin.c
// Named node Login test of vpntest ("nodelogin" command, CORE-F2 #62)
//
// The Login of a Noise session of the new core (src/Core/Noise.h) against the login of the slim fork's SE-VPN
// protocol, the oracle that CORE-S8-3 (#577) retired. The users are set up on the hub of the server role of a node
// (Cedar/Node.c): a password user, a user with his own certificate, a user whose certificate a trusted root signs, and a
// user of the Windows domain. The domain user is a local account that the test creates, which LogonUser checks the way
// it checks a domain account; that needs administrator rights, which CI has, and the test deletes the account again.
// For each credential, right and wrong, the new core runs a Noise_IK session bound to a TLS exporter between a client
// node and the server node, the client sends its Login as the first control message, and the node checks it with
// NodeLogin. Its error must be the one that the SE-VPN login (raw Packs as ClientUploadAuth sent them, ServerAccept and
// Sam on the server) gave for the case at the last run against the oracle: the table of the cases with those errors is
// the golden file tests/golden/nodelogin/nodelogin_errors.txt (golden family "nodelogin"), which the errors of NodeLogin
// must match. The right credentials must log in and the wrong ones must not; a session whose Login passed carries data,
// one whose Login failed is closed. Print "NODELOGIN TEST OK" only when every check passes.

#include "golden.h"
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
#include "Mayaqua/Tick64.h"

#include "Core/Noise.h"

#include <lmcons.h>
#include <lmaccess.h>
#include <lmerr.h>

#define	NODELOGIN_HUB			"NODELOGIN"			// Hub of the node
#define	NODELOGIN_PASSWORD_USER	"nl_password"		// Password user, password NODELOGIN_PASSWORD
#define	NODELOGIN_PASSWORD		"NodeLogin-Pass-1"	// The password of the password user
#define	NODELOGIN_CERT_USER		"nl_usercert"		// User with his own certificate
#define	NODELOGIN_ROOT_USER		"nl_rootcert"		// User whose certificate a trusted root signs
#define	NODELOGIN_DOMAIN_USER	"nl_domain"			// User of the Windows domain: the local account of the test
#define	NODELOGIN_WRONG			"NodeLogin-Wrong-1"	// No user's password
#define	NODELOGIN_GOLDEN		"nodelogin_errors.txt"	// The golden file: the error of the SE-VPN login for each case

// How a case gives its credential
#define	NODELOGIN_SECRET_PASSWORD	0	// A password user's password
#define	NODELOGIN_SECRET_DOMAIN		1	// A domain user's password
#define	NODELOGIN_SECRET_CERT		2	// A certificate and the signature of the challenge by a key

// The certificates and keys of the test
typedef struct NODELOGIN_CERTS
{
	K *UserKey, *RootKey, *RootedKey, *StrangerKey;
	X *User;							// Self-signed, the certificate of NODELOGIN_CERT_USER
	X *Root;							// Self-signed, the trusted root of both hubs
	X *Rooted;							// Signed by Root
	X *Stranger;						// Self-signed, unknown to both hubs
} NODELOGIN_CERTS;

// One case: a credential of a user, and whether it must log in
typedef struct NODELOGIN_CASE
{
	char *What;							// Its name, which names its line in the golden file
	char *User;
	UINT Secret;						// NODELOGIN_SECRET_*
	bool RightPassword;					// Password cases: the user's password, else NODELOGIN_WRONG
	X **Cert;							// Certificate cases: the certificate ...
	K **Key;							// ... and the key that signs
	bool Expect;						// The credential logs the user in
} NODELOGIN_CASE;

// The state of the test
typedef struct NODELOGIN_CTX
{
	UINT NumChecks;
	UINT NumFailed;
	char OutDir[MAX_SIZE];				// The output and golden directories of the golden family "nodelogin"
	char GoldenDir[MAX_SIZE];
	bool Update;						// Update mode: the golden file is written, not compared
	NODELOGIN_CERTS Certs;
	wchar_t Account[32];				// The local account of the domain user
	char AccountPassword[64];			// Its password
	bool HaveAccount;
} NODELOGIN_CTX;

static bool NodeLoginCheck(NODELOGIN_CTX *ctx, bool ok, char *what, char *fmt, ...) RANZ_PRINTF_FORMAT(4, 5);
static bool NodeLoginCheck(NODELOGIN_CTX *ctx, bool ok, char *what, char *fmt, ...)
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

// A certificate of its own RSA-2048 key: self-signed, or signed by ca with ca_key
static X *NodeLoginNewCert(wchar_t *cn, K **key, X *ca, K *ca_key)
{
	K *pub = NULL;
	X *x = NULL;

	*key = NULL;
	if (RsaGen(key, &pub, 2048))
	{
		NAME *n = NewName(cn, L"Ranz VPN nodelogin test", NULL, NULL, NULL, NULL);
		x = (ca == NULL ? NewRootX(pub, *key, n, 30, NULL) : NewX(pub, ca_key, ca, n, 30, NULL));
		FreeName(n);
	}
	FreeK(pub);

	return x;
}

static bool NodeLoginNewCerts(NODELOGIN_CERTS *c)
{
	c->User = NodeLoginNewCert(L"nodelogin user", &c->UserKey, NULL, NULL);
	c->Root = NodeLoginNewCert(L"nodelogin root", &c->RootKey, NULL, NULL);
	c->Rooted = (c->Root != NULL ? NodeLoginNewCert(L"nodelogin rooted", &c->RootedKey, c->Root, c->RootKey) : NULL);
	c->Stranger = NodeLoginNewCert(L"nodelogin stranger", &c->StrangerKey, NULL, NULL);

	return c->User != NULL && c->Root != NULL && c->Rooted != NULL && c->Stranger != NULL;
}

static void NodeLoginFreeCerts(NODELOGIN_CERTS *c)
{
	FreeX(c->User);
	FreeX(c->Root);
	FreeX(c->Rooted);
	FreeX(c->Stranger);
	FreeK(c->UserKey);
	FreeK(c->RootKey);
	FreeK(c->RootedKey);
	FreeK(c->StrangerKey);
	Zero(c, sizeof(NODELOGIN_CERTS));
}

// The local account that stands for a domain account, with a random name and a password that meets the default
// complexity policy of Windows Server
static bool NodeLoginAddAccount(NODELOGIN_CTX *ctx)
{
	USER_INFO_1 ui;
	wchar_t password[64];
	DWORD parm_err = 0;
	UCHAR r[8];

	Rand(r, sizeof(r));
	UniFormat(ctx->Account, sizeof(ctx->Account), L"ranznl%02x%02x", r[0], r[1]);
	Format(ctx->AccountPassword, sizeof(ctx->AccountPassword), "Rz#%02x%02x%02x%02x%02x%02x-Nl9", r[2], r[3], r[4], r[5], r[6], r[7]);
	StrToUni(password, sizeof(password), ctx->AccountPassword);

	Zero(&ui, sizeof(ui));
	ui.usri1_name = ctx->Account;
	ui.usri1_password = password;
	ui.usri1_priv = USER_PRIV_USER;
	ui.usri1_flags = UF_SCRIPT | UF_DONT_EXPIRE_PASSWD;

	NET_API_STATUS st = NetUserAdd(NULL, 1, (LPBYTE)&ui, &parm_err);
	ctx->HaveAccount = (st == NERR_Success);

	return NodeLoginCheck(ctx, ctx->HaveAccount, "a local account stands for the domain user (administrator rights)",
		"NetUserAdd: status %lu (parameter %lu)", (unsigned long)st, (unsigned long)parm_err);
}

static void NodeLoginDeleteAccount(NODELOGIN_CTX *ctx)
{
	if (ctx->HaveAccount)
	{
		NET_API_STATUS st = NetUserDel(NULL, ctx->Account);
		NodeLoginCheck(ctx, st == NERR_Success, "the local account is deleted", "NetUserDel: status %lu", (unsigned long)st);
		ctx->HaveAccount = false;
	}
}

// The users of the test on a hub: the password user, the certificate user, the root certificate user with the trusted
// root, and the domain user
static void NodeLoginAddUsers(NODELOGIN_CTX *ctx, HUB *h)
{
	USER *u;

	AcLock(h);
	{
		u = NewUser(NODELOGIN_PASSWORD_USER, L"", L"", AUTHTYPE_PASSWORD, NewPasswordAuthData(NODELOGIN_PASSWORD_USER, NODELOGIN_PASSWORD));
		AcAddUser(h, u);
		ReleaseUser(u);

		u = NewUser(NODELOGIN_CERT_USER, L"", L"", AUTHTYPE_USERCERT, NewUserCertAuthData(ctx->Certs.User));
		AcAddUser(h, u);
		ReleaseUser(u);

		u = NewUser(NODELOGIN_ROOT_USER, L"", L"", AUTHTYPE_ROOTCERT, NewRootCertAuthData(NULL, NULL));
		AcAddUser(h, u);
		ReleaseUser(u);

		u = NewUser(NODELOGIN_DOMAIN_USER, L"", L"", AUTHTYPE_NT, NewNTAuthData(ctx->Account));
		AcAddUser(h, u);
		ReleaseUser(u);
	}
	AcUnlock(h);

	AddRootCert(h, ctx->Certs.Root);
}

// The password of a password or domain case
static char *NodeLoginPassword(NODELOGIN_CTX *ctx, NODELOGIN_CASE *c)
{
	if (c->RightPassword == false)
	{
		return NODELOGIN_WRONG;
	}

	return (c->Secret == NODELOGIN_SECRET_DOMAIN ? ctx->AccountPassword : NODELOGIN_PASSWORD);
}

//
// The new core: a Noise session and NodeLogin
//

// One Login of the case through a Noise session between a client node and the node n: the error of NodeLogin.
// *carried: the session then carried a data record (a Login that passed) or closed (one that failed).
static UINT NodeLoginNoise(NODELOGIN_CTX *ctx, NODE *n, NODELOGIN_CASE *c, bool *carried)
{
	NOISE_SESSION_CONFIG cc, sc;
	NOISE_LOGIN login, parsed;
	AUTH_RESULT res;
	UCHAR client_key[NOISE_KEY_SIZE], client_pub[NOISE_KEY_SIZE], server_key[NOISE_KEY_SIZE], server_pub[NOISE_KEY_SIZE];
	UCHAR exporter[NOISE_EXPORTER_SIZE];
	UCHAR challenge[NOISE_LOGIN_CHALLENGE_SIZE], server_challenge[NOISE_LOGIN_CHALLENGE_SIZE];
	UCHAR sign[4096 / 8];
	UINT size = 0, reply_size = 0, data_size = 0, login_size = 0;
	UINT64 now = Tick64();
	NOISE_SESSION *client = ZeroMalloc(sizeof(NOISE_SESSION));
	NOISE_SESSION *server = ZeroMalloc(sizeof(NOISE_SESSION));
	UCHAR *record = ZeroMalloc(NOISE_MAX_RECORD);
	UCHAR *reply = ZeroMalloc(NOISE_MAX_RECORD);
	UCHAR *data = ZeroMalloc(NOISE_MAX_RECORD);
	BUF *cert = NULL;
	UINT err = ERR_INTERNAL_ERROR;

	*carried = false;
	Zero(&res, sizeof(res));

	// The two nodes, and the exporter of the TLS session that would carry the Noise session
	CryptoX25519GenerateKey(client_key, client_pub);
	CryptoX25519GenerateKey(server_key, server_pub);
	CryptoRandom(exporter, sizeof(exporter));
	Zero(&cc, sizeof(cc));
	cc.Suite = NOISE_SUITE_IK;
	cc.StaticKey = client_key;
	cc.RemoteStatic = server_pub;
	cc.BindingType = NOISE_BINDING_EXPORTER;
	cc.Binding = exporter;
	cc.BindingSize = sizeof(exporter);
	Copy(&sc, &cc, sizeof(sc));
	sc.StaticKey = server_key;
	sc.RemoteStatic = NULL;

	if (NodeLoginCheck(ctx, NoiseSessionConnect(client, &cc, now, record, NOISE_MAX_RECORD, &size) &&
		NoiseSessionAccept(server, &sc, now, record, size, reply, NOISE_MAX_RECORD, &reply_size) &&
		NoiseSessionFinish(client, now, reply, reply_size), "Noise_IK session bound to the exporter", "handshake failed") == false)
	{
		goto END;
	}

	// The Login, the first control message of the client
	Zero(&login, sizeof(login));
	StrCpy(login.HubName, sizeof(login.HubName), NODELOGIN_HUB);
	StrCpy(login.UserName, sizeof(login.UserName), c->User);
	if (c->Secret == NODELOGIN_SECRET_CERT)
	{
		X *x = *c->Cert;

		NoiseSessionChallenge(client, challenge, sizeof(challenge));
		Zero(sign, sizeof(sign));
		RsaSignEx(sign, sizeof(sign), challenge, SHA1_SIZE, *c->Key);
		cert = XToBuf(x, false);
		login.Method = NOISE_LOGIN_CERT;
		login.Cert = cert->Buf;
		login.CertSize = cert->Size;
		login.Sign = sign;
		login.SignSize = x->bits / 8;
	}
	else
	{
		login.Method = NOISE_LOGIN_PASSWORD;
		StrCpy(login.Password, sizeof(login.Password), NodeLoginPassword(ctx, c));
	}

	if (NoiseLoginEncode(&login, data, NOISE_MAX_RECORD, &login_size) == false ||
		NoiseSessionSend(client, now, NOISE_RECORD_CONTROL, data, login_size, record, NOISE_MAX_RECORD, &size) == false ||
		NoiseSessionReceive(server, now, record, size, data, NOISE_MAX_RECORD, &data_size) != NOISE_RECEIVE_CONTROL ||
		NoiseLoginParse(&parsed, data, data_size) == false || NoiseSessionChallenge(server, server_challenge, sizeof(server_challenge)) == false)
	{
		NodeLoginCheck(ctx, false, "the Login reaches the server node", "encode, send, receive or parse failed");
		goto END;
	}

	NodeLogin(n, &parsed, server_challenge, &res);
	err = res.Error;

	// A Login that passed opens the data stream; one that failed closes the session
	if (res.Ok)
	{
		NoiseSessionAcceptLogin(server);
		*carried = NoiseSessionSend(client, now, NOISE_RECORD_DATA, "frame", 5, record, NOISE_MAX_RECORD, &size) &&
			NoiseSessionReceive(server, now, record, size, data, NOISE_MAX_RECORD, &data_size) == NOISE_RECEIVE_DATA;
	}
	else
	{
		*carried = NoiseSessionSend(server, now, NOISE_RECORD_CLOSE, NULL, 0, record, NOISE_MAX_RECORD, &size) &&
			NoiseSessionReceive(client, now, record, size, data, NOISE_MAX_RECORD, &data_size) == NOISE_RECEIVE_CLOSE &&
			client->State == NOISE_STATE_CLOSED;
	}

END:
	Free(res.Policy);
	FreeX(res.ClientX);
	FreeBuf(cert);
	NoiseSessionFree(client);
	NoiseSessionFree(server);
	Free(client);
	Free(server);
	Free(record);
	Free(reply);
	Free(data);
	Zero(client_key, sizeof(client_key));
	Zero(server_key, sizeof(server_key));

	return err;
}

//
// The node
//

// A new empty data directory under the temp directory of the process, with the configuration store of the server
// role (ConfigStore, CORE-F5 #65): one worker and the hub as an online L2 network
static void NodeLoginNewDir(wchar_t *dir, UINT size)
{
	wchar_t tmp[MAX_PATH];
	wchar_t path[MAX_PATH];

	UniFormat(tmp, sizeof(tmp), L"node_login_%u", Rand32());
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
	CsAddNetwork(s, NODELOGIN_HUB, CS_MODE_L2, true);
	CsClose(s);
}

// Delete the files of a directory, then the directory (it holds no subdirectory)
static void NodeLoginDeleteFiles(wchar_t *dir)
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

RANZ_TEST("nodelogin", nodelogin_test, "Node Login: password, certificate and domain credentials through a Noise session and NodeLogin give the SE-VPN login's error of each case, the golden file of the table of the cases (golden family nodelogin; administrator rights).");
void nodelogin_test(UINT num, char **arg)
{
	NODELOGIN_CTX *ctx = ZeroMalloc(sizeof(NODELOGIN_CTX));
	wchar_t dir[MAX_PATH], log_dir[MAX_PATH];

	Print("Node Login test: the Login of a Noise session against the results of the SE-VPN login of the slim fork\n");

	HarnessGetFamilyDirs("nodelogin", ctx->OutDir, sizeof(ctx->OutDir), ctx->GoldenDir, sizeof(ctx->GoldenDir), &ctx->Update);
	MakeDirEx(ctx->OutDir);
	Print("NODELOGIN GOLDEN MODE %s\n", ctx->Update ? "update" : "compare");
	Print("  golden directory: %s\n", ctx->GoldenDir);

	// The cases. The error that the SE-VPN login of the slim fork gave for each at the last run against the oracle (head
	// 1819f09d, CI run 41302403531, x64 and arm64; CORE-S8-3 #577) is the line of the case in the golden file.
	NODELOGIN_CASE cases[] =
	{
		{"password user, right password", NODELOGIN_PASSWORD_USER, NODELOGIN_SECRET_PASSWORD, true, NULL, NULL, true},
		{"password user, wrong password", NODELOGIN_PASSWORD_USER, NODELOGIN_SECRET_PASSWORD, false, NULL, NULL, false},
		{"unknown user", "nl_nobody", NODELOGIN_SECRET_PASSWORD, true, NULL, NULL, false},
		{"certificate user, his certificate and key", NODELOGIN_CERT_USER, NODELOGIN_SECRET_CERT, false, &ctx->Certs.User, &ctx->Certs.UserKey, true},
		{"certificate user, another certificate", NODELOGIN_CERT_USER, NODELOGIN_SECRET_CERT, false, &ctx->Certs.Stranger, &ctx->Certs.StrangerKey, false},
		{"certificate user, his certificate signed by another key", NODELOGIN_CERT_USER, NODELOGIN_SECRET_CERT, false, &ctx->Certs.User, &ctx->Certs.StrangerKey, false},
		{"root certificate user, a certificate of the trusted root", NODELOGIN_ROOT_USER, NODELOGIN_SECRET_CERT, false, &ctx->Certs.Rooted, &ctx->Certs.RootedKey, true},
		{"root certificate user, a certificate of no trusted root", NODELOGIN_ROOT_USER, NODELOGIN_SECRET_CERT, false, &ctx->Certs.Stranger, &ctx->Certs.StrangerKey, false},
		{"domain user, right password", NODELOGIN_DOMAIN_USER, NODELOGIN_SECRET_DOMAIN, true, NULL, NULL, true},
		{"domain user, wrong password", NODELOGIN_DOMAIN_USER, NODELOGIN_SECRET_DOMAIN, false, NULL, NULL, false},
	};
	UINT num_cases = sizeof(cases) / sizeof(cases[0]);

	NodeLoginAddAccount(ctx);
	NodeLoginCheck(ctx, NodeLoginNewCerts(&ctx->Certs), "the RSA-2048 certificates: a user's, a root, one it signed, a stranger's", "RsaGen, NewRootX or NewX failed");

	// The new core: the node's server role, the users, Noise sessions
	Print("[new core: the Login of a Noise session, checked by NodeLogin]\n");
	NodeLoginNewDir(dir, sizeof(dir));
	NODE *n = NewNode(dir);
	NodeStart(n);
	HUB *hub = NodeGetHub(n, NODELOGIN_HUB);
	if (NodeLoginCheck(ctx, hub != NULL, "the server role of the node runs the hub", "NodeGetHub failed"))
	{
		NodeLoginAddUsers(ctx, hub);
		ReleaseHub(hub);

		BUF *report = NewBuf();

		for (UINT i = 0;i < num_cases;i++)
		{
			NODELOGIN_CASE *c = &cases[i];
			bool carried = false;
			UINT err = NodeLoginNoise(ctx, n, c, &carried);
			char line[MAX_SIZE];

			Format(line, sizeof(line), "%s: %s", c->What, c->Expect ? "logs in" : "refused");
			NodeLoginCheck(ctx, (err == ERR_NO_ERROR) == c->Expect, line, "NodeLogin error %u", err);
			NodeLoginCheck(ctx, carried, c->Expect ? "  the session carries data" : "  the session is closed",
				"the session did not %s", c->Expect ? "carry the data record" : "close");

			// The line of the case in the golden file: its error, which must be the one of the SE-VPN login
			Format(line, sizeof(line), "%s: error %u\n", c->What, err);
			WriteBuf(report, line, StrLen(line));
		}

		// The errors of NodeLogin against the ones of the SE-VPN login (in update mode: written, not compared)
		char *text = HarnessBufToStr(report);
		HARNESS h;

		Zero(&h, sizeof(h));
		HarnessCompareGolden(&h, ctx->OutDir, ctx->GoldenDir, NODELOGIN_GOLDEN, text, ctx->Update);
		NodeLoginCheck(ctx, h.NumFail == 0, "each case gives the error of the SE-VPN login: the errors match the golden file " NODELOGIN_GOLDEN,
			"they differ from the golden file %s (the diff is above)", NODELOGIN_GOLDEN);
		Free(text);
		FreeBuf(report);

		// A join Login names a tunnel, not a user: Sam has nothing to check
		NOISE_LOGIN join;
		AUTH_RESULT res;
		UCHAR challenge[NOISE_LOGIN_CHALLENGE_SIZE];

		Zero(&join, sizeof(join));
		join.Method = NOISE_LOGIN_JOIN;
		StrCpy(join.HubName, sizeof(join.HubName), NODELOGIN_HUB);
		StrCpy(join.UserName, sizeof(join.UserName), NODELOGIN_PASSWORD_USER);
		Zero(challenge, sizeof(challenge));
		NodeLoginCheck(ctx, NodeLogin(n, &join, challenge, &res) == false && res.Error == ERR_AUTHTYPE_NOT_SUPPORTED,
			"a join Login is not a credential", "error %u", res.Error);
	}

	NodeStop(n);
	FreeNode(n);
	ConbinePathW(log_dir, sizeof(log_dir), dir, NODE_LOG_DIR_NAME);
	NodeLoginDeleteFiles(log_dir);
	NodeLoginDeleteFiles(dir);

	NodeLoginDeleteAccount(ctx);
	NodeLoginFreeCerts(&ctx->Certs);

	if (ctx->NumFailed == 0)
	{
		Print("NODELOGIN TEST OK\n");
	}
	else
	{
		Print("NODELOGIN TEST FAILED (%u of %u checks failed)\n", ctx->NumFailed, ctx->NumChecks);
	}

	Zero(ctx->AccountPassword, sizeof(ctx->AccountPassword));
	Free(ctx);
}
