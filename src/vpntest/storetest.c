// storetest.c
// Named configuration store test of vpntest ("store" command, CORE-F5 #65)
//
// The configuration store of the new core (Cedar/ConfigStore.c, ConfigStoreImport.c) and the node on it:
// - The store is a SQLite database that the winsqlite3.dll of System32 reads and writes (no other SQLite library
//   is loaded), with the schema CS_SCHEMA_VERSION and the write-ahead log: a reader is not held up while another
//   connection holds the write lock. A file that is no store, a database of another program and a store of a newer
//   schema are refused and left as they are; what a store holds is there after it is opened again. A store of schema 1
//   gets the tables of schema 2, the policy of the networks (CORE-S4-3 #76), when it is opened, and keeps its rows.
// - Settings, networks, users, listeners and certificates are added, read back, and refused when they are not
//   valid or not unique; deleting a network deletes its users, certificates and hub-admins.
// - Passwords are PBKDF2-HMAC-SHA256 hashes (BCryptDeriveKeyPBKDF2, checked against the RFC 7914 vectors) with a
//   random salt per password and CS_PBKDF2_ITERATIONS iterations; pinned keys follow trust on first use.
// - The named admin accounts carry the roles owner, hub-admin (of one network) and read-only.
// - The fork configuration tests/golden/store/fork_server.config imports into a store whose dump matches the golden
//   file store_import.txt (golden family "store"). A second import, a file that is no fork configuration and a
//   missing file are refused and leave the store as it was.
// - A node imports the ranz_server.config of its data directory once, renames it, and runs the imported hubs; the
//   default data directory of a node is %ProgramData%\Hanzcodes\Ranz VPN.
// Print "STORE TEST OK" only when every check passes.

#include "golden.h"
#include "testlist.h"

#include "Cedar/Cedar.h"
#include "Cedar/ConfigStore.h"
#include "Cedar/Hub.h"
#include "Cedar/Node.h"

#include "Mayaqua/Cfg.h"
#include "Mayaqua/Encrypt.h"
#include "Mayaqua/FileIO.h"
#include "Mayaqua/Internat.h"
#include "Mayaqua/Memory.h"
#include "Mayaqua/Microsoft.h"
#include "Mayaqua/Str.h"
#include "Mayaqua/Tick64.h"

#include <ShlObj.h>

// The winsqlite3.h of the Windows SDK uses sqlite3_filename in every build but declares it only from NTDDI_WIN11_ZN
// on (as in Cedar/ConfigStore.c)
#if NTDDI_VERSION < NTDDI_WIN11_ZN
typedef const char *sqlite3_filename;
#endif

#include <winsqlite/winsqlite3.h>

#define	STORETEST_NETWORK		"STORETEST"
#define	STORETEST_PASSWORD		"store-test-password"
#define	STORETEST_READ_BOUND	1000			// A read while another connection holds the write lock returns within this time (ms)
#define	STORETEST_GOLDEN		"store_import.txt"
#define	STORETEST_FIXTURE		"fork_server.config"

// The checks of the test
typedef struct STORETEST_CTX
{
	UINT NumChecks;						// Checks run so far
	UINT NumFailed;						// Checks failed so far
} STORETEST_CTX;

// Record one check: print [PASS] with what, or [FAIL] with what and the formatted detail
static bool StoreTestCheck(STORETEST_CTX *ctx, bool ok, char *what, char *fmt, ...) RANZ_PRINTF_FORMAT(4, 5);
static bool StoreTestCheck(STORETEST_CTX *ctx, bool ok, char *what, char *fmt, ...)
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

// A new empty directory under the temp directory of the process
static void StoreTestNewDir(wchar_t *dir, UINT size, char *name)
{
	wchar_t tmp[MAX_PATH];

	UniFormat(tmp, sizeof(tmp), L"store_%S_%u", name, Rand32());
	ConbinePathW(dir, size, MsGetMyTempDirW(), tmp);
	MakeDirExW(dir);
}

// Delete the files of a directory, then the directory (it holds no subdirectory)
static void StoreTestDeleteFiles(wchar_t *dir)
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

// Delete a directory of the test with the node log that a node wrote in it
static void StoreTestDeleteDir(wchar_t *dir)
{
	wchar_t log_dir[MAX_PATH];

	ConbinePathW(log_dir, sizeof(log_dir), dir, NODE_LOG_DIR_NAME);
	StoreTestDeleteFiles(log_dir);
	StoreTestDeleteFiles(dir);
}

// The path of the store file of a directory
static void StoreTestPath(wchar_t *path, UINT size, wchar_t *dir)
{
	ConbinePathW(path, size, dir, CS_FILE_NAME);
}

// Run statements on a connection of its own, without the store: true when they ran
static bool StoreTestRawExec(wchar_t *path, char *sql)
{
	char utf8[MAX_PATH * 3];
	sqlite3 *db = NULL;

	UniToUtf8(utf8, sizeof(utf8), path);
	bool ok = (sqlite3_open_v2(utf8, &db, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, NULL) == SQLITE_OK &&
		sqlite3_exec(db, sql, NULL, NULL, NULL) == SQLITE_OK);
	sqlite3_close(db);

	return ok;
}

// The text of the first column of the first row of a query on a connection of its own; "" when there is none
static void StoreTestRawText(wchar_t *path, char *sql, char *dst, UINT size)
{
	char utf8[MAX_PATH * 3];
	sqlite3 *db = NULL;
	sqlite3_stmt *st = NULL;

	StrCpy(dst, size, "");
	UniToUtf8(utf8, sizeof(utf8), path);

	// Read-write, so the connection can open the shared memory file of the write-ahead log
	if (sqlite3_open_v2(utf8, &db, SQLITE_OPEN_READWRITE, NULL) == SQLITE_OK &&
		sqlite3_prepare_v2(db, sql, -1, &st, NULL) == SQLITE_OK &&
		sqlite3_step(st) == SQLITE_ROW &&
		sqlite3_column_text(st, 0) != NULL)
	{
		StrCpy(dst, size, (char *)sqlite3_column_text(st, 0));
	}

	sqlite3_finalize(st);
	sqlite3_close(db);
}

// The dump of a store as a string; the caller frees it
static char *StoreTestDump(CONFIG_STORE *s)
{
	BUF *b = CsDump(s);
	char *ret = ZeroMalloc(b->Size + 1);

	Copy(ret, b->Buf, b->Size);
	FreeBuf(b);

	return ret;
}

// Whether the dump of a store has the line part (a whole line or a piece of one)
static bool StoreTestDumpHas(CONFIG_STORE *s, char *part)
{
	char *dump = StoreTestDump(s);
	bool ret = (SearchStrEx(dump, part, 0, true) != INFINITE);

	Free(dump);

	return ret;
}

// The DER bytes of a PEM certificate; the caller frees the BUF
static BUF *StoreTestPemToDer(char *pem)
{
	BUF *b = NewBuf();
	TOKEN_LIST *t = ParseToken(pem, "\r\n");

	for (UINT i = 0;i < t->NumTokens;i++)
	{
		if (StartWith(t->Token[i], "-----") == false)
		{
			WriteBuf(b, t->Token[i], StrLen(t->Token[i]));
		}
	}

	FreeToken(t);

	UINT size = 0;
	void *der = Base64ToBin(&size, b->Buf, b->Size);
	FreeBuf(b);

	BUF *ret = NewBuf();
	if (der != NULL)
	{
		WriteBuf(ret, der, size);
		Free(der);
	}

	return ret;
}

// A self-signed certificate "ranz-certdl-tls" (a fixture of the certdl test, which CORE-S8-3 retired with the legacy server)
static char storetest_cert_pem[] =
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

//
// The library, the schema and the file
//

static void StoreTestLibrary(STORETEST_CTX *ctx)
{
	wchar_t dir[MAX_PATH];
	wchar_t path[MAX_PATH];
	wchar_t module[MAX_PATH];
	wchar_t expect[MAX_PATH];
	char mode[MAX_SIZE];
	char value[MAX_SIZE];
	char schema[MAX_SIZE];

	StoreTestNewDir(dir, sizeof(dir), "library");
	StoreTestPath(path, sizeof(path), dir);

	CONFIG_STORE *s = CsOpen(path);
	if (StoreTestCheck(ctx, s != NULL && IsFileExistsW(path), "CsOpen creates a store in a new file", "CsOpen(%S) returned %p", path, s) == false)
	{
		StoreTestDeleteDir(dir);
		return;
	}

	HMODULE h = GetModuleHandleW(L"winsqlite3.dll");
	module[0] = 0;
	if (h != NULL)
	{
		GetModuleFileNameW(h, module, MAX_PATH);
	}
	ConbinePathW(expect, sizeof(expect), MsGetSystem32DirW(), L"winsqlite3.dll");
	StoreTestCheck(ctx, h != NULL && UniStrCmpi(module, expect) == 0, "The store reads and writes through the winsqlite3.dll of System32",
		"winsqlite3.dll loaded from \"%S\", expected \"%S\"", module, expect);
	StoreTestCheck(ctx, GetModuleHandleW(L"sqlite3.dll") == NULL, "No other SQLite library is loaded", "sqlite3.dll is loaded");
	Print("  winsqlite3.dll: SQLite %s\n", CsLibVersion());

	Format(schema, sizeof(schema), "schema %u\n", CS_SCHEMA_VERSION);
	StoreTestCheck(ctx, CsSetSetting(s, "Probe", "1") == ERR_NO_ERROR && StoreTestDumpHas(s, schema),
		"A new store has schema CS_SCHEMA_VERSION and takes a write", "the write or the schema line failed");

	CsClose(s);

	StoreTestRawText(path, "PRAGMA journal_mode", mode, sizeof(mode));
	StoreTestRawText(path, "PRAGMA user_version", value, sizeof(value));
	StoreTestCheck(ctx, StrCmpi(mode, "wal") == 0 && ToInt(value) == CS_SCHEMA_VERSION,
		"The file is a SQLite database in write-ahead log mode with user_version CS_SCHEMA_VERSION", "journal mode \"%s\", user_version \"%s\"", mode, value);

	// What the store holds is there after it is opened again
	s = CsOpen(path);
	CsSetSetting(s, "Kept", "yes");
	CsAddNetwork(s, STORETEST_NETWORK, CS_MODE_L2, true);
	CsClose(s);

	s = CsOpen(path);
	LIST *o = CsEnumNetworks(s);
	bool kept = CsGetSetting(s, "Kept", value, sizeof(value)) && StrCmp(value, "yes") == 0 && LIST_NUM(o) == 1;
	CsFreeNetworkList(o);
	StoreTestCheck(ctx, kept, "A store opened again holds its settings and networks", "setting \"%s\"", value);
	CsClose(s);

	StoreTestDeleteDir(dir);
}

// A store of schema 1, which a node made before the policy of the networks (CORE-S4-3 #76), gets the tables of the
// versions after its own when it is opened, keeps its rows, and its policy then takes rows as a new store's does
static void StoreTestUpgrade(STORETEST_CTX *ctx)
{
	wchar_t dir[MAX_PATH];
	wchar_t path[MAX_PATH];
	char version[MAX_SIZE];
	char tables[MAX_SIZE];
	char value[MAX_SIZE];
	char schema[MAX_SIZE];
	CS_RULE r;
	CS_PORT p;

	StoreTestNewDir(dir, sizeof(dir), "upgrade");
	StoreTestPath(path, sizeof(path), dir);

	// A new store with a setting and a network, without the tables of schema 2: a store of schema 1
	CONFIG_STORE *s = CsOpen(path);
	CsSetSetting(s, "Kept", "yes");
	CsAddNetwork(s, STORETEST_NETWORK, CS_MODE_L2, true);
	CsClose(s);

	bool made = StoreTestRawExec(path, "DROP TABLE rule_values; DROP TABLE rules; DROP TABLE network_vlans; DROP TABLE vlans; DROP TABLE user_groups; PRAGMA user_version = 1");
	StoreTestRawText(path, "PRAGMA user_version", version, sizeof(version));
	StoreTestRawText(path, "SELECT COUNT(*) FROM sqlite_master WHERE name IN ('user_groups', 'vlans', 'network_vlans', 'rules', 'rule_values')", tables, sizeof(tables));
	StoreTestCheck(ctx, made && StrCmp(version, "1") == 0 && StrCmp(tables, "0") == 0,
		"A store of schema 1 is made: a store with a setting and a network, without the tables of schema 2",
		"the statements ran %u, user_version \"%s\", %s tables of schema 2 left", (UINT)made, version, tables);

	s = CsOpen(path);
	if (StoreTestCheck(ctx, s != NULL, "CsOpen opens a store of schema 1", "CsOpen(%S) returned NULL", path) == false)
	{
		StoreTestDeleteDir(dir);
		return;
	}

	LIST *o = CsEnumNetworks(s);
	bool kept = CsGetSetting(s, "Kept", value, sizeof(value)) && StrCmp(value, "yes") == 0 && LIST_NUM(o) == 1;
	CsFreeNetworkList(o);
	Format(schema, sizeof(schema), "schema %u\n", CS_SCHEMA_VERSION);
	StoreTestCheck(ctx, kept && StoreTestDumpHas(s, schema), "The store of schema 1 opened has schema CS_SCHEMA_VERSION, its setting and its network",
		"setting \"%s\", or no line \"schema %u\" in the dump", value, (UINT)CS_SCHEMA_VERSION);

	// The tables of schema 2 take the VLAN settings of the network and a rule: the port of a member without a VLAN and the
	// document of the store then have them
	Zero(&r, sizeof(r));
	StrCpy(r.Network, sizeof(r.Network), STORETEST_NETWORK);
	StrCpy(r.Name, sizeof(r.Name), STORETEST_NETWORK ".upgraded");
	r.Priority = 10;
	r.Action = CS_ALLOW;
	r.Protocol = CS_PROTO_TCP;
	r.Active = true;
	CsAddRuleValue(&r, CS_KEY_PORTS, "443");

	UINT vlans_err = CsSetNetworkVlans(s, STORETEST_NETWORK, 0x88A8, 5);
	UINT rule_err = CsAddRule(s, &r);
	bool port = CsGetPort(s, STORETEST_NETWORK, "nobody", &p) && p.Mode == CS_PORT_TRUNK && p.Vlan == 5 && p.Tpid == 0x88A8;
	char *doc = CsPolicyDocument(s);
	bool in_doc = (doc != NULL && SearchStrEx(doc, "\"" STORETEST_NETWORK ".upgraded\"", 0, true) != INFINITE);
	StoreTestCheck(ctx, vlans_err == ERR_NO_ERROR && rule_err == ERR_NO_ERROR && port && in_doc,
		"The tables of schema 2 take the VLAN settings of the network and a rule, which the port and the document of the store then have",
		"CsSetNetworkVlans %u, CsAddRule %u, port %u (mode %u, vlan %u, tpid 0x%04x), document \"%s\"", vlans_err, rule_err, (UINT)port, p.Mode, p.Vlan,
		p.Tpid, doc != NULL ? doc : "(none)");
	Free(doc);
	CsClose(s);

	StoreTestRawText(path, "PRAGMA user_version", version, sizeof(version));
	StoreTestCheck(ctx, ToInt(version) == CS_SCHEMA_VERSION, "The file of the store has user_version CS_SCHEMA_VERSION after the upgrade",
		"user_version \"%s\"", version);

	StoreTestDeleteDir(dir);
}

// A file that is no store is refused and left as it is
static void StoreTestRefused(STORETEST_CTX *ctx, char *name, char *what, char *sql, char *text)
{
	wchar_t dir[MAX_PATH];
	wchar_t path[MAX_PATH];
	char check[MAX_SIZE];

	StoreTestNewDir(dir, sizeof(dir), name);
	StoreTestPath(path, sizeof(path), dir);

	if (text != NULL)
	{
		BUF *b = NewBuf();
		WriteBuf(b, text, StrLen(text));
		DumpBufW(b, path);
		FreeBuf(b);
	}
	else
	{
		StoreTestRawExec(path, sql);
	}

	BUF *before = ReadDumpW(path);
	CONFIG_STORE *s = CsOpen(path);
	BUF *after = ReadDumpW(path);

	bool same = (before != NULL && after != NULL && before->Size == after->Size && Cmp(before->Buf, after->Buf, before->Size) == 0);

	Format(check, sizeof(check), "CsOpen refuses %s and leaves the file as it is", what);
	StoreTestCheck(ctx, s == NULL && same, check, "store %p, file unchanged %u", s, (UINT)same);

	CsClose(s);
	FreeBuf(before);
	FreeBuf(after);
	StoreTestDeleteDir(dir);
}

// The default data directory of a node is under ProgramData
static void StoreTestDataDir(STORETEST_CTX *ctx)
{
	wchar_t dir[MAX_PATH];
	wchar_t expect[MAX_PATH];
	wchar_t *program_data = NULL;

	NodeDefaultDataDir(dir, sizeof(dir));

	expect[0] = 0;
	if (SUCCEEDED(SHGetKnownFolderPath(&FOLDERID_ProgramData, 0, NULL, &program_data)))
	{
		ConbinePathW(expect, sizeof(expect), program_data, L"Hanzcodes\\Ranz VPN");
	}
	CoTaskMemFree(program_data);

	StoreTestCheck(ctx, UniIsEmptyStr(expect) == false && UniStrCmpi(dir, expect) == 0,
		"The default data directory of a node, where its store and log are created, is %ProgramData%\\Hanzcodes\\Ranz VPN",
		"\"%S\", expected \"%S\"", dir, expect);
}

//
// Settings, networks, users, listeners and certificates
//

static void StoreTestRows(STORETEST_CTX *ctx, CONFIG_STORE *s)
{
	char value[MAX_SIZE];
	CS_USER u;
	CS_USER got;

	// Settings
	bool ok = CsSetSetting(s, "Roles", "server") == ERR_NO_ERROR && CsSetSetting(s, "roles", "relay") == ERR_NO_ERROR &&
		CsGetSetting(s, "ROLES", value, sizeof(value)) && StrCmp(value, "relay") == 0;
	bool removed = CsSetSetting(s, "Roles", NULL) == ERR_NO_ERROR && CsGetSetting(s, "Roles", value, sizeof(value)) == false;
	StoreTestCheck(ctx, ok && removed, "A setting is set, replaced and removed, by its name without case", "value \"%s\", removed %u", value, (UINT)removed);

	// Networks
	UINT e1 = CsAddNetwork(s, STORETEST_NETWORK, CS_MODE_L2, true);
	UINT e2 = CsAddNetwork(s, "storetest", CS_MODE_L2, true);
	UINT e3 = CsAddNetwork(s, "no/slash", CS_MODE_L2, true);
	UINT e4 = CsAddNetwork(s, "ROUTED", CS_MODE_L3, false);
	UINT e5 = CsAddNetwork(s, "BADMODE", 7, true);
	StoreTestCheck(ctx, e1 == ERR_NO_ERROR && e2 == ERR_OBJECT_EXISTS && e3 == ERR_INVALID_PARAMETER && e4 == ERR_NO_ERROR && e5 == ERR_INVALID_PARAMETER,
		"A network is added once, by its name without case; a name or mode that is not valid is refused",
		"errors %u, %u, %u, %u, %u", e1, e2, e3, e4, e5);

	LIST *o = CsEnumNetworks(s);
	CS_NETWORK *n1 = (LIST_NUM(o) >= 1 ? LIST_DATA(o, 0) : NULL);
	CS_NETWORK *n2 = (LIST_NUM(o) >= 2 ? LIST_DATA(o, 1) : NULL);
	StoreTestCheck(ctx, LIST_NUM(o) == 2 && StrCmp(n1->Name, STORETEST_NETWORK) == 0 && n1->Mode == CS_MODE_L2 && n1->Online &&
		StrCmp(n2->Name, "ROUTED") == 0 && n2->Mode == CS_MODE_L3 && n2->Online == false,
		"CsEnumNetworks lists the networks in the order they were added, with their mode and state", "%u networks", LIST_NUM(o));
	CsFreeNetworkList(o);

	// Users
	Zero(&u, sizeof(u));
	StrCpy(u.Network, sizeof(u.Network), "storetest");
	StrCpy(u.Name, sizeof(u.Name), "alice");
	UniStrCpy(u.RealName, sizeof(u.RealName), L"Al\x00efce J\x00fcrgens \x65e5\x672c");
	UniStrCpy(u.Note, sizeof(u.Note), L"a \"quoted\" note");
	StrCpy(u.Group, sizeof(u.Group), "staff");
	u.AuthType = AUTHTYPE_ROOTCERT;
	UniStrCpy(u.AuthName, sizeof(u.AuthName), L"alice.example");
	u.AuthSerial[0] = 0x10;
	u.AuthSerial[1] = 0x01;
	u.AuthSerialSize = 2;
	u.ExpireTime = 0x123456789AULL;

	UINT add = CsAddUser(s, &u);
	bool read = CsGetUser(s, STORETEST_NETWORK, "ALICE", &got);
	StoreTestCheck(ctx, add == ERR_NO_ERROR && read && StrCmp(got.Network, STORETEST_NETWORK) == 0 && StrCmp(got.Name, "alice") == 0 &&
		UniStrCmp(got.RealName, u.RealName) == 0 && UniStrCmp(got.Note, u.Note) == 0 && StrCmp(got.Group, "staff") == 0 &&
		got.AuthType == AUTHTYPE_ROOTCERT && UniStrCmp(got.AuthName, u.AuthName) == 0 && got.AuthSerialSize == 2 &&
		Cmp(got.AuthSerial, u.AuthSerial, 2) == 0 && got.ExpireTime == u.ExpireTime && got.HasPassword == false && got.HasKey == false,
		"A user is added to a network and read back with every field, Unicode text included", "add error %u, read %u", add, (UINT)read);

	UINT dup = CsAddUser(s, &u);
	StrCpy(u.Network, sizeof(u.Network), "NOSUCH");
	UINT no_network = CsAddUser(s, &u);
	StrCpy(u.Network, sizeof(u.Network), STORETEST_NETWORK);
	StrCpy(u.Name, sizeof(u.Name), "bob");
	u.AuthType = 4;
	UINT bad_auth = CsAddUser(s, &u);
	StrCpy(u.Name, sizeof(u.Name), "no/slash");
	u.AuthType = AUTHTYPE_PASSWORD;
	UINT bad_name = CsAddUser(s, &u);
	StoreTestCheck(ctx, dup == ERR_OBJECT_EXISTS && no_network == ERR_HUB_NOT_FOUND && bad_auth == ERR_INVALID_PARAMETER && bad_name == ERR_INVALID_PARAMETER,
		"A user is refused twice in one network, in a network that does not exist, with an authentication type or a name that is not valid",
		"errors %u, %u, %u, %u", dup, no_network, bad_auth, bad_name);

	// Listeners
	UINT l1 = CsAddListener(s, CS_TRANSPORT_QUIC, 443, true);
	UINT l2 = CsAddListener(s, CS_TRANSPORT_TLS, 443, true);
	UINT l3 = CsAddListener(s, CS_TRANSPORT_TLS, 443, false);
	UINT l4 = CsAddListener(s, CS_TRANSPORT_TLS, 0, true);
	UINT l5 = CsAddListener(s, CS_TRANSPORT_TLS, 65536, true);
	StoreTestCheck(ctx, l1 == ERR_NO_ERROR && l2 == ERR_NO_ERROR && l3 == ERR_OBJECT_EXISTS && l4 == ERR_INVALID_PARAMETER && l5 == ERR_INVALID_PARAMETER &&
		StoreTestDumpHas(s, "listener transport=\"quic\" port=443 enabled=1\n") && StoreTestDumpHas(s, "listener transport=\"tls\" port=443 enabled=1\n"),
		"A listener is added once per transport and port; a port that is not valid is refused", "errors %u, %u, %u, %u, %u", l1, l2, l3, l4, l5);

	// Certificates
	BUF *der = StoreTestPemToDer(storetest_cert_pem);
	UCHAR garbage[5] = {0, 1, 2, 3, 4};
	UINT c1 = CsAddCert(s, CS_CERT_SERVER, NULL, NULL, der->Buf, der->Size);
	UINT c2 = CsAddCert(s, CS_CERT_SERVER, NULL, NULL, der->Buf, der->Size);
	UINT c3 = CsAddCert(s, CS_CERT_CA, STORETEST_NETWORK, NULL, der->Buf, der->Size);
	UINT c4 = CsAddCert(s, CS_CERT_CA, NULL, NULL, der->Buf, der->Size);
	UINT c5 = CsAddCert(s, CS_CERT_USER, STORETEST_NETWORK, "alice", der->Buf, der->Size);
	UINT c6 = CsAddCert(s, CS_CERT_USER, STORETEST_NETWORK, "nobody", der->Buf, der->Size);
	UINT c7 = CsAddCert(s, CS_CERT_CHAIN, NULL, NULL, garbage, sizeof(garbage));
	UINT c8 = CsAddCert(s, CS_CERT_CHAIN, STORETEST_NETWORK, NULL, der->Buf, der->Size);
	FreeBuf(der);
	StoreTestCheck(ctx, c1 == ERR_NO_ERROR && c2 == ERR_OBJECT_EXISTS && c3 == ERR_NO_ERROR && c4 == ERR_INVALID_PARAMETER && c5 == ERR_NO_ERROR &&
		c6 == ERR_OBJECT_NOT_FOUND && c7 == ERR_INVALID_PARAMETER && c8 == ERR_INVALID_PARAMETER &&
		StoreTestDumpHas(s, "certificate usage=\"server\" network=none user=none subject=\"CN=ranz-certdl-tls\" thumbprint=\"3823F110343932548E74BAAE873D2BEED00F8E59\"\n"),
		"Certificates are read by CryptoAPI (subject, SHA-1 thumbprint): one server certificate, a CA of a network, a user certificate; the rest is refused",
		"errors %u, %u, %u, %u, %u, %u, %u, %u", c1, c2, c3, c4, c5, c6, c7, c8);

	// Deleting a network deletes what belongs to it
	CsAddAdmin(s, "storetest-admin", CS_ROLE_HUB_ADMIN, STORETEST_NETWORK, NULL);
	UINT del = CsDeleteNetwork(s, "StoreTest");
	UINT del2 = CsDeleteNetwork(s, STORETEST_NETWORK);
	CS_ADMIN a;
	char *dump = StoreTestDump(s);
	bool gone = CsGetUser(s, STORETEST_NETWORK, "alice", &got) == false && CsGetAdmin(s, "storetest-admin", &a) == false &&
		SearchStrEx(dump, "certificate usage=\"ca\"", 0, true) == INFINITE && SearchStrEx(dump, "certificate usage=\"user\"", 0, true) == INFINITE &&
		SearchStrEx(dump, "certificate usage=\"server\"", 0, true) != INFINITE;
	Free(dump);
	StoreTestCheck(ctx, del == ERR_NO_ERROR && del2 == ERR_HUB_NOT_FOUND && gone,
		"Deleting a network deletes its users, its certificates and its hub-admins, and nothing else", "errors %u, %u, gone %u", del, del2, (UINT)gone);
}

//
// Passwords and pinned keys
//

// One PBKDF2-HMAC-SHA256 vector of RFC 7914, section 11
static bool StoreTestPbkdf2Vector(char *password, char *salt, UINT iterations, char *hex)
{
	UCHAR got[64];
	BUF *expect = StrToBin(hex);

	bool ok = (expect != NULL && expect->Size == sizeof(got) && CsPbkdf2(got, sizeof(got), password, salt, StrLen(salt), iterations) &&
		Cmp(got, expect->Buf, sizeof(got)) == 0);

	FreeBuf(expect);

	return ok;
}

static void StoreTestPasswords(STORETEST_CTX *ctx, CONFIG_STORE *s, wchar_t *path)
{
	char iterations[MAX_SIZE];
	char salt_size[MAX_SIZE];
	char hash_size[MAX_SIZE];
	char distinct[MAX_SIZE];
	char hex[MAX_SIZE];
	CS_USER u;
	UCHAR key1[CS_KEY_SIZE];
	UCHAR key2[CS_KEY_SIZE];

	StoreTestCheck(ctx, StoreTestPbkdf2Vector("passwd", "salt", 1,
		"55AC046E56E3089FEC1691C22544B605F94185216DDE0465E68B9D57C20DACBC49CA9CCCF179B645991664B39D77EF317C71B845B1E30BD509112041D3A19783") &&
		StoreTestPbkdf2Vector("Password", "NaCl", 80000,
		"4DDCD8F60B98BE21830CEE5EF22701F9641A4418D04C0414AEFF08876B34AB56A1D425A1225833549ADB841B51C9B3176A272BDEBBA1D078478F62B397F33C8D"),
		"CsPbkdf2 (BCryptDeriveKeyPBKDF2) gives the PBKDF2-HMAC-SHA256 vectors of RFC 7914", "a vector differs");

	CsAddNetwork(s, STORETEST_NETWORK, CS_MODE_L2, true);

	Zero(&u, sizeof(u));
	StrCpy(u.Network, sizeof(u.Network), STORETEST_NETWORK);
	u.AuthType = AUTHTYPE_PASSWORD;
	StrCpy(u.Name, sizeof(u.Name), "carol");
	CsAddUser(s, &u);
	StrCpy(u.Name, sizeof(u.Name), "dave");
	CsAddUser(s, &u);

	UINT64 start = Tick64();
	UINT set = CsSetUserPassword(s, STORETEST_NETWORK, "carol", STORETEST_PASSWORD);
	UINT64 span = Tick64() - start;
	CsSetUserPassword(s, STORETEST_NETWORK, "dave", STORETEST_PASSWORD);
	UINT no_user = CsSetUserPassword(s, STORETEST_NETWORK, "nobody", STORETEST_PASSWORD);
	Print("  PBKDF2 with %u iterations: %I64u ms\n", CS_PBKDF2_ITERATIONS, span);

	bool good = CsCheckUserPassword(s, STORETEST_NETWORK, "CAROL", STORETEST_PASSWORD);
	bool wrong = CsCheckUserPassword(s, STORETEST_NETWORK, "carol", "store-test-passworD");
	bool unknown = CsCheckUserPassword(s, STORETEST_NETWORK, "nobody", STORETEST_PASSWORD);
	CsGetUser(s, STORETEST_NETWORK, "carol", &u);
	StoreTestCheck(ctx, set == ERR_NO_ERROR && no_user == ERR_OBJECT_NOT_FOUND && good && wrong == false && unknown == false && u.HasPassword,
		"A user password is set and checked: the right one passes, a wrong one or an unknown user does not",
		"set %u, no user %u, good %u, wrong %u, unknown %u", set, no_user, (UINT)good, (UINT)wrong, (UINT)unknown);

	// The stored hash: PBKDF2-HMAC-SHA256 with a random salt of its own per password
	StoreTestRawText(path, "SELECT password_iterations FROM users WHERE name = 'carol'", iterations, sizeof(iterations));
	StoreTestRawText(path, "SELECT length(password_salt) FROM users WHERE name = 'carol'", salt_size, sizeof(salt_size));
	StoreTestRawText(path, "SELECT length(password_hash) FROM users WHERE name = 'carol'", hash_size, sizeof(hash_size));
	StoreTestRawText(path, "SELECT COUNT(DISTINCT password_salt) || ',' || COUNT(DISTINCT password_hash) FROM users WHERE name IN ('carol', 'dave')", distinct, sizeof(distinct));
	StoreTestCheck(ctx, ToInt(iterations) == CS_PBKDF2_ITERATIONS && ToInt(salt_size) == CS_SALT_SIZE && ToInt(hash_size) == CS_HASH_SIZE && StrCmp(distinct, "2,2") == 0,
		"The store keeps a PBKDF2 hash, its salt and its iterations, and the same password of two users has two salts and two hashes",
		"iterations %s, salt %s bytes, hash %s bytes, distinct salts and hashes %s", iterations, salt_size, hash_size, distinct);

	StoreTestRawText(path, "SELECT hex(password_salt) FROM users WHERE name = 'carol'", hex, sizeof(hex));
	BUF *salt = StrToBin(hex);
	UCHAR expect[CS_HASH_SIZE];
	char expect_hex[MAX_SIZE];
	char got_hex[MAX_SIZE];
	CsPbkdf2(expect, sizeof(expect), STORETEST_PASSWORD, salt->Buf, salt->Size, CS_PBKDF2_ITERATIONS);
	FreeBuf(salt);
	BinToStr(expect_hex, sizeof(expect_hex), expect, sizeof(expect));
	StoreTestRawText(path, "SELECT hex(password_hash) FROM users WHERE name = 'carol'", got_hex, sizeof(got_hex));
	StoreTestCheck(ctx, StrCmp(expect_hex, got_hex) == 0, "The stored hash is PBKDF2-HMAC-SHA256 of the password and the stored salt",
		"stored %s, computed %s", got_hex, expect_hex);

	UINT cleared = CsSetUserPassword(s, STORETEST_NETWORK, "carol", NULL);
	CsGetUser(s, STORETEST_NETWORK, "carol", &u);
	StoreTestCheck(ctx, cleared == ERR_NO_ERROR && u.HasPassword == false && CsCheckUserPassword(s, STORETEST_NETWORK, "carol", STORETEST_PASSWORD) == false,
		"A password removed lets nobody in", "error %u", cleared);

	// Trust on first use
	Rand(key1, sizeof(key1));
	Rand(key2, sizeof(key2));
	UINT p1 = CsPinUserKey(s, STORETEST_NETWORK, "dave", key1);
	UINT p2 = CsPinUserKey(s, STORETEST_NETWORK, "dave", key1);
	UINT p3 = CsPinUserKey(s, STORETEST_NETWORK, "dave", key2);
	CsGetUser(s, STORETEST_NETWORK, "dave", &u);
	bool has_key = u.HasKey;
	UINT unpin = CsUnpinUserKey(s, STORETEST_NETWORK, "dave");
	UINT p4 = CsPinUserKey(s, STORETEST_NETWORK, "dave", key2);
	UINT p5 = CsPinUserKey(s, STORETEST_NETWORK, "nobody", key1);
	BinToStr(hex, sizeof(hex), key2, sizeof(key2));
	char line[MAX_SIZE];
	Format(line, sizeof(line), "pinned_key=%s\n", hex);
	StoreTestCheck(ctx, p1 == CS_KEY_PINNED && p2 == CS_KEY_MATCH && p3 == CS_KEY_MISMATCH && has_key && unpin == ERR_NO_ERROR && p4 == CS_KEY_PINNED &&
		p5 == CS_KEY_NO_USER && StoreTestDumpHas(s, line),
		"The first key of a user is pinned, the same key matches, another one does not; after an unpin the next key is pinned; a user that the store does not keep is no failure",
		"results %u, %u, %u, unpin %u, %u, unknown user %u", p1, p2, p3, unpin, p4, p5);
}

//
// Named admin accounts
//

static void StoreTestAdmins(STORETEST_CTX *ctx, CONFIG_STORE *s, wchar_t *path)
{
	CS_ADMIN owner;
	CS_ADMIN hub;
	CS_ADMIN reader;
	CS_ADMIN checked;

	CsAddNetwork(s, "SALES", CS_MODE_L2, true);

	UINT e1 = CsAddAdmin(s, "root", CS_ROLE_OWNER, NULL, STORETEST_PASSWORD);
	UINT e2 = CsAddAdmin(s, "sales-admin", CS_ROLE_HUB_ADMIN, "sales", STORETEST_PASSWORD);
	UINT e3 = CsAddAdmin(s, "auditor", CS_ROLE_READ_ONLY, NULL, NULL);
	bool read = CsGetAdmin(s, "ROOT", &owner) && CsGetAdmin(s, "sales-admin", &hub) && CsGetAdmin(s, "auditor", &reader);
	StoreTestCheck(ctx, e1 == ERR_NO_ERROR && e2 == ERR_NO_ERROR && e3 == ERR_NO_ERROR && read &&
		owner.Role == CS_ROLE_OWNER && IsEmptyStr(owner.Network) && owner.HasPassword &&
		hub.Role == CS_ROLE_HUB_ADMIN && StrCmp(hub.Network, "SALES") == 0 && hub.HasPassword &&
		reader.Role == CS_ROLE_READ_ONLY && IsEmptyStr(reader.Network) && reader.HasPassword == false,
		"Named admin accounts carry the roles owner, hub-admin (of one network) and read-only", "errors %u, %u, %u, read %u", e1, e2, e3, (UINT)read);

	StoreTestCheck(ctx, StoreTestDumpHas(s, "admin name=\"auditor\" role=\"read-only\" network=none password=\"unset\"\n") &&
		StoreTestDumpHas(s, "admin name=\"root\" role=\"owner\" network=none password=\"set\"\n") &&
		StoreTestDumpHas(s, "admin name=\"sales-admin\" role=\"hub-admin\" network=\"SALES\" password=\"set\"\n"),
		"The dump shows each admin with its role and network, and its password only as set or unset", "a line is missing");

	UINT r1 = CsAddAdmin(s, "Root", CS_ROLE_READ_ONLY, NULL, NULL);
	UINT r2 = CsAddAdmin(s, "nohub", CS_ROLE_HUB_ADMIN, NULL, NULL);
	UINT r3 = CsAddAdmin(s, "owner2", CS_ROLE_OWNER, "SALES", NULL);
	UINT r4 = CsAddAdmin(s, "lost", CS_ROLE_HUB_ADMIN, "NOSUCH", NULL);
	UINT r5 = CsAddAdmin(s, "superuser", 3, NULL, NULL);
	StoreTestCheck(ctx, r1 == ERR_OBJECT_EXISTS && r2 == ERR_INVALID_PARAMETER && r3 == ERR_INVALID_PARAMETER && r4 == ERR_HUB_NOT_FOUND && r5 == ERR_INVALID_PARAMETER,
		"An admin name is taken once without case; a hub-admin needs a network, an owner or read-only takes none, and there is no fourth role",
		"errors %u, %u, %u, %u, %u", r1, r2, r3, r4, r5);

	// The fork reserves "administrator" for the users of a hub, not for admin accounts
	CS_USER u;
	Zero(&u, sizeof(u));
	StrCpy(u.Network, sizeof(u.Network), "SALES");
	StrCpy(u.Name, sizeof(u.Name), ADMINISTRATOR_USERNAME);
	u.AuthType = AUTHTYPE_PASSWORD;
	UINT as_user = CsAddUser(s, &u);
	UINT as_admin = CsAddAdmin(s, ADMINISTRATOR_USERNAME, CS_ROLE_OWNER, NULL, NULL);
	StoreTestCheck(ctx, as_user == ERR_INVALID_PARAMETER && as_admin == ERR_NO_ERROR,
		"\"administrator\" is refused as the name of a user of a network and taken as the name of an admin account",
		"as a user %u, as an admin %u", as_user, as_admin);

	// The schema refuses an admin row that breaks the rule on its own, whatever writes it
	bool raw_hub = StoreTestRawExec(path, "INSERT INTO admins (name, role) VALUES ('raw1', 'hub-admin')");
	bool raw_role = StoreTestRawExec(path, "INSERT INTO admins (name, role) VALUES ('raw2', 'superuser')");
	StoreTestCheck(ctx, raw_hub == false && raw_role == false, "The schema itself refuses a hub-admin without a network and an unknown role",
		"hub-admin row %u, unknown role row %u", (UINT)raw_hub, (UINT)raw_role);

	bool good = CsCheckAdminPassword(s, "sales-admin", STORETEST_PASSWORD, &checked);
	bool wrong = CsCheckAdminPassword(s, "sales-admin", "wrong", NULL);
	bool none = CsCheckAdminPassword(s, "auditor", "", NULL);
	UINT set = CsSetAdminPassword(s, "auditor", "auditor-password");
	bool after = CsCheckAdminPassword(s, "auditor", "auditor-password", NULL);
	UINT missing = CsSetAdminPassword(s, "nobody", "x");
	StoreTestCheck(ctx, good && checked.Role == CS_ROLE_HUB_ADMIN && StrCmp(checked.Network, "SALES") == 0 && wrong == false && none == false &&
		set == ERR_NO_ERROR && after && missing == ERR_OBJECT_NOT_FOUND,
		"An admin password check gives the account and its role; a wrong password or an account without one gives nothing",
		"good %u, wrong %u, without a password %u, set %u, after %u, unknown %u", (UINT)good, (UINT)wrong, (UINT)none, set, (UINT)after, missing);
}

//
// Two connections: no single-file lock
//

static void StoreTestConcurrency(STORETEST_CTX *ctx, CONFIG_STORE *s, wchar_t *path)
{
	char utf8[MAX_PATH * 3];
	char value[MAX_SIZE];
	sqlite3 *db = NULL;

	CsSetSetting(s, "Shared", "old");

	UniToUtf8(utf8, sizeof(utf8), path);
	bool locked = (sqlite3_open_v2(utf8, &db, SQLITE_OPEN_READWRITE, NULL) == SQLITE_OK &&
		sqlite3_exec(db, "BEGIN IMMEDIATE; UPDATE settings SET value = 'new' WHERE name = 'Shared'", NULL, NULL, NULL) == SQLITE_OK);

	UINT64 start = Tick64();
	bool read = CsGetSetting(s, "Shared", value, sizeof(value));
	UINT64 span = Tick64() - start;
	StoreTestCheck(ctx, locked && read && StrCmp(value, "old") == 0 && span < STORETEST_READ_BOUND,
		"A read is not held up while another connection holds the write lock, and sees the last commit",
		"locked %u, read %u, value \"%s\", %I64u ms", (UINT)locked, (UINT)read, value, span);

	bool committed = (sqlite3_exec(db, "COMMIT", NULL, NULL, NULL) == SQLITE_OK);
	sqlite3_close(db);

	read = CsGetSetting(s, "Shared", value, sizeof(value));
	StoreTestCheck(ctx, committed && read && StrCmp(value, "new") == 0, "After the commit the store reads the new value", "value \"%s\"", value);
}

//
// The import of a fork configuration
//

// The fixture and golden directories of the golden family "store"
static void StoreTestGoldenDirs(char *out_dir, UINT out_size, char *golden_dir, UINT golden_size, bool *update, wchar_t *fixture, UINT fixture_size)
{
	char tmp[MAX_SIZE];

	HarnessGetFamilyDirs("store", out_dir, out_size, golden_dir, golden_size, update);
	MakeDirEx(out_dir);

	Format(tmp, sizeof(tmp), "%s/%s", golden_dir, STORETEST_FIXTURE);
	StrToUni(fixture, fixture_size, tmp);
}

static void StoreTestImport(STORETEST_CTX *ctx)
{
	wchar_t dir[MAX_PATH];
	wchar_t path[MAX_PATH];
	wchar_t fixture[MAX_PATH];
	wchar_t other[MAX_PATH];
	char out_dir[MAX_SIZE];
	char golden_dir[MAX_SIZE];
	bool update;
	CS_IMPORT r;
	HARNESS h;

	StoreTestGoldenDirs(out_dir, sizeof(out_dir), golden_dir, sizeof(golden_dir), &update, fixture, sizeof(fixture));
	Print("STORE GOLDEN MODE %s\n", update ? "update" : "compare");
	Print("  golden directory: %s\n", golden_dir);

	if (StoreTestCheck(ctx, IsFileExistsW(fixture), "The fork configuration fixture is there", "%S is missing", fixture) == false)
	{
		return;
	}

	StoreTestNewDir(dir, sizeof(dir), "import");
	StoreTestPath(path, sizeof(path), dir);
	CONFIG_STORE *s = CsOpen(path);

	// Refusals first: the store stays empty
	ConbinePathW(other, sizeof(other), dir, L"missing.config");
	UINT missing = CsImportForkConfig(s, other, &r);

	ConbinePathW(other, sizeof(other), dir, L"no_server.config");
	FOLDER *root = CfgCreateFolder(NULL, TAG_ROOT);
	CfgCreateFolder(CfgCreateFolder(root, "VirtualHUB"), "LOST");
	BUF *b = CfgFolderToBuf(root);
	DumpBufW(b, other);
	FreeBuf(b);
	CfgDeleteFolder(root);
	UINT not_fork = CsImportForkConfig(s, other, &r);
	FileDeleteW(other);

	StoreTestCheck(ctx, missing == ERR_OBJECT_NOT_FOUND && not_fork == ERR_INVALID_PARAMETER && CsIsEmpty(s),
		"A missing file and a file without ServerConfiguration are not imported, and the store stays empty", "errors %u, %u", missing, not_fork);

	UINT err = CsImportForkConfig(s, fixture, &r);
	StoreTestCheck(ctx, err == ERR_NO_ERROR, "The fork configuration imports into an empty store", "error %u", err);
	StoreTestCheck(ctx, r.NumNetworks == 2 && r.NumUsers == 6 && r.NumListeners == 2 && r.NumCerts == 4 && r.NumAdmins == 2 && r.NumSkipped == 5 &&
		r.NumPasswordsDropped == 4 && r.ServerKeyDropped,
		"The import reports 2 networks, 6 users, 2 listeners, 4 certificates and 2 admins, 5 rows skipped, 4 SHA-0 passwords and the server key left out",
		"%u networks, %u users, %u listeners, %u certificates, %u admins, %u skipped, %u passwords, server key %u",
		r.NumNetworks, r.NumUsers, r.NumListeners, r.NumCerts, r.NumAdmins, r.NumSkipped, r.NumPasswordsDropped, (UINT)r.ServerKeyDropped);

	// The golden dump: hubs, users, listeners, certificates and admin roles
	Zero(&h, sizeof(h));
	char *dump = StoreTestDump(s);
	HarnessCompareGolden(&h, out_dir, golden_dir, STORETEST_GOLDEN, dump, update);
	Free(dump);
	StoreTestCheck(ctx, h.NumFail == 0, "The imported store matches the golden dump " STORETEST_GOLDEN, "it differs");

	char *before = StoreTestDump(s);
	UINT again = CsImportForkConfig(s, fixture, &r);
	char *after = StoreTestDump(s);
	StoreTestCheck(ctx, again == ERR_OBJECT_EXISTS && r.NumNetworks == 0 && StrCmp(before, after) == 0,
		"A second import into the store is refused (one-time import) and changes nothing", "error %u", again);
	Free(before);
	Free(after);

	CsClose(s);
	StoreTestDeleteDir(dir);
}

// A node imports the ranz_server.config of its data directory once and runs its hubs
static void StoreTestNodeImport(STORETEST_CTX *ctx)
{
	wchar_t dir[MAX_PATH];
	wchar_t fixture[MAX_PATH];
	wchar_t config[MAX_PATH];
	wchar_t imported[MAX_PATH];
	wchar_t log_dir[MAX_PATH];
	char out_dir[MAX_SIZE];
	char golden_dir[MAX_SIZE];
	bool update;
	NODE_STATUS st;

	StoreTestGoldenDirs(out_dir, sizeof(out_dir), golden_dir, sizeof(golden_dir), &update, fixture, sizeof(fixture));

	StoreTestNewDir(dir, sizeof(dir), "node");
	ConbinePathW(config, sizeof(config), dir, NODE_IMPORT_FILE_NAME);
	UniFormat(imported, sizeof(imported), L"%s%s", config, NODE_IMPORTED_SUFFIX);
	FileCopyW(fixture, config);

	NODE *n = NewNode(dir);
	bool renamed = (IsFileExistsW(config) == false && IsFileExistsW(imported));
	CS_ADMIN a;
	bool admin = CsGetAdmin(n->Store, "administrator@SALES", &a) && a.Role == CS_ROLE_HUB_ADMIN;
	StoreTestCheck(ctx, n->Store != NULL && renamed && admin, "NewNode imports the ranz_server.config of its data directory into its store and renames the file",
		"store %p, renamed %u, hub-admin %u", n->Store, (UINT)renamed, (UINT)admin);

	NodeStart(n);
	NodeGetStatus(n, &st);
	HUB *def = NodeGetHub(n, "DEFAULT");
	HUB *sales = NodeGetHub(n, "SALES");
	bool hubs = (st.NumHubs == 2 && def != NULL && def->Offline == false && sales != NULL && sales->Offline);
	ReleaseHub(def);
	ReleaseHub(sales);
	StoreTestCheck(ctx, hubs, "The server role runs the imported hubs, DEFAULT online and SALES offline", "%u hubs", st.NumHubs);
	FreeNode(n);

	// A second node on the same directory finds a store that is not empty: nothing is imported
	FileCopyW(fixture, config);
	n = NewNode(dir);
	FreeNode(n);
	bool kept = IsFileExistsW(config);

	ConbinePathW(log_dir, sizeof(log_dir), dir, NODE_LOG_DIR_NAME);
	char *log = NULL;
	DIRLIST *d = EnumDirW(log_dir);
	BUF *all = NewBuf();
	for (UINT i = 0;d != NULL && i < d->NumFiles;i++)
	{
		wchar_t file[MAX_PATH];
		ConbinePathW(file, sizeof(file), log_dir, d->File[i]->FileNameW);
		BUF *b = ReadDumpW(file);
		if (b != NULL)
		{
			WriteBuf(all, b->Buf, b->Size);
			FreeBuf(b);
		}
	}
	FreeDir(d);
	log = HarnessBufToStr(all);
	FreeBuf(all);

	bool lines = SearchStrEx(log, "imported: 2 networks, 6 users, 2 listeners, 4 certificates, 2 admins, 5 skipped", 0, true) != INFINITE &&
		SearchStrEx(log, "4 SHA-0 passwords not carried over", 0, true) != INFINITE &&
		SearchStrEx(log, "not imported: error 112 (the configuration store is not empty)", 0, true) != INFINITE;
	StoreTestCheck(ctx, kept && lines, "The node log records the import and what it left out; a second node imports nothing and leaves the file",
		"file kept %u, log lines %u", (UINT)kept, (UINT)lines);
	Free(log);

	StoreTestDeleteDir(dir);
}

// store: the configuration store of the new core
RANZ_TEST("store", store_test, "Configuration store: SQLite through the winsqlite3.dll of System32, a fork configuration import matching its golden dump, named admin roles, PBKDF2 passwords.");
void store_test(UINT num, char **arg)
{
	STORETEST_CTX ctx;
	wchar_t dir[MAX_PATH];
	wchar_t path[MAX_PATH];

	Zero(&ctx, sizeof(ctx));

	Print("Configuration store test: SQLite through winsqlite3.dll, the fork configuration import, named admin roles\n");

	StoreTestLibrary(&ctx);
	StoreTestUpgrade(&ctx);
	StoreTestRefused(&ctx, "text", "a file that is no database", NULL, "declare root\r\n{\r\n}\r\n");
	StoreTestRefused(&ctx, "other", "a database of another program", "CREATE TABLE other (x INTEGER)", NULL);
	StoreTestRefused(&ctx, "newer", "a store of a newer schema", "PRAGMA user_version = 99", NULL);
	StoreTestDataDir(&ctx);

	StoreTestNewDir(dir, sizeof(dir), "rows");
	StoreTestPath(path, sizeof(path), dir);
	CONFIG_STORE *s = CsOpen(path);
	StoreTestRows(&ctx, s);
	StoreTestPasswords(&ctx, s, path);
	StoreTestAdmins(&ctx, s, path);
	StoreTestConcurrency(&ctx, s, path);
	CsClose(s);
	StoreTestDeleteDir(dir);

	StoreTestImport(&ctx);
	StoreTestNodeImport(&ctx);

	if (ctx.NumFailed == 0)
	{
		Print("STORE TEST OK\n");
	}
	else
	{
		Print("STORE TEST FAILED (%u of %u checks failed)\n", ctx.NumFailed, ctx.NumChecks);
	}
}
