// ConfigStore.c
// The configuration store of the new core (ADR-0022, Configuration store): the settings, networks, users with their
// password hashes and pinned keys, listeners, certificates and named admin accounts of a node in one SQLite database,
// read and written through the inbox winsqlite3.dll of System32 (no vendored library). It replaces the Cfg file for
// the new core instead of porting it: there is no single-file lock as in CFG_RW, and with the write-ahead log other
// connections read while one writes. Since schema 2 it also holds the policy of the networks (CORE-S4-3, #76): their
// groups, the VLANs of users and groups, the VLAN settings of each network and the rules of the policy engine of the new
// core, which it writes as the engine's document of rules (CsPolicyDocument).

#include "ConfigStore.h"

#include "Account.h"

#include "Mayaqua/Encrypt.h"
#include "Mayaqua/Internat.h"
#include "Mayaqua/Kernel.h"
#include "Mayaqua/Memory.h"
#include "Mayaqua/Object.h"
#include "Mayaqua/Str.h"

#include "Core/Policy.h"

#include "ConfigStoreInternal.h"

#include <bcrypt.h>
#include <wincrypt.h>

#include <cjson/cJSON.h>

// The winsqlite3.h of the Windows SDK uses the type sqlite3_filename in every build but declares it only from
// NTDDI_WIN11_ZN on, and the project builds for NTDDI_WIN10_RS1 (cmake/RanzOptions.cmake)
#if NTDDI_VERSION < NTDDI_WIN11_ZN
typedef const char *sqlite3_filename;
#endif

#include <winsqlite/winsqlite3.h>

#define CS_NUM(a) ((UINT)(sizeof(a) / sizeof(a[0])))

// The schema of CS_SCHEMA_VERSION. The CHECK constraints keep every row valid on its own: a hub-admin names its
// network and the other roles none, a CA or user certificate names its network, a user certificate its user, and
// there is one server certificate at most. Deleting a network deletes its users, certificates and hub-admins.
static char *cs_schema[] =
    {
        "CREATE TABLE settings (name TEXT PRIMARY KEY COLLATE NOCASE, value TEXT NOT NULL)",
        "CREATE TABLE networks (id INTEGER PRIMARY KEY, name TEXT NOT NULL UNIQUE COLLATE NOCASE, mode TEXT NOT NULL CHECK (mode IN ('l2', 'l3')), online INTEGER NOT NULL CHECK (online IN (0, 1)))",
        "CREATE TABLE users (id INTEGER PRIMARY KEY, network_id INTEGER NOT NULL REFERENCES networks (id) ON DELETE CASCADE, name TEXT NOT NULL COLLATE NOCASE, real_name TEXT NOT NULL, note TEXT NOT NULL, group_name TEXT NOT NULL, auth TEXT NOT NULL CHECK (auth IN ('anonymous', 'password', 'user-cert', 'root-cert', 'windows')), auth_name TEXT NOT NULL, auth_serial BLOB, expire_time INTEGER NOT NULL, password_hash BLOB, password_salt BLOB, password_iterations INTEGER NOT NULL DEFAULT 0, pinned_key BLOB, pinned_time INTEGER NOT NULL DEFAULT 0, UNIQUE (network_id, name))",
        "CREATE TABLE listeners (id INTEGER PRIMARY KEY, transport TEXT NOT NULL CHECK (transport IN ('quic', 'tls')), port INTEGER NOT NULL CHECK (port BETWEEN 1 AND 65535), enabled INTEGER NOT NULL CHECK (enabled IN (0, 1)), UNIQUE (transport, port))",
        "CREATE TABLE certificates (id INTEGER PRIMARY KEY, usage TEXT NOT NULL CHECK (usage IN ('server', 'chain', 'ca', 'user')), network_id INTEGER REFERENCES networks (id) ON DELETE CASCADE, user_id INTEGER REFERENCES users (id) ON DELETE CASCADE, subject TEXT NOT NULL, thumbprint TEXT NOT NULL, der BLOB NOT NULL, CHECK ((usage IN ('ca', 'user')) = (network_id IS NOT NULL)), CHECK ((usage = 'user') = (user_id IS NOT NULL)))",
        "CREATE TABLE admins (id INTEGER PRIMARY KEY, name TEXT NOT NULL UNIQUE COLLATE NOCASE, role TEXT NOT NULL CHECK (role IN ('owner', 'hub-admin', 'read-only')), network_id INTEGER REFERENCES networks (id) ON DELETE CASCADE, password_hash BLOB, password_salt BLOB, password_iterations INTEGER NOT NULL DEFAULT 0, CHECK ((role = 'hub-admin') = (network_id IS NOT NULL)))",
        "CREATE UNIQUE INDEX certificates_server ON certificates (usage) WHERE usage = 'server'",
        "CREATE INDEX certificates_network ON certificates (network_id)",
        "CREATE INDEX certificates_user ON certificates (user_id)",
        "CREATE INDEX admins_network ON admins (network_id)",
};

// The tables of schema 2: the policy of the networks (CORE-S4-3, #76). A group and a VLAN row belong to a network, a
// VLAN row is a user's or a group's and names it (the user or group may come later, as in the fork), a network has VLAN
// settings once, and a rule belongs to a network and has its values; deleting a network deletes its policy. A rule's
// name is unique in the store, as in a document of the policy engine; its position orders the rules of one priority.
static char *cs_schema_2[] =
    {
        "CREATE TABLE user_groups (id INTEGER PRIMARY KEY, network_id INTEGER NOT NULL REFERENCES networks (id) ON DELETE CASCADE, name TEXT NOT NULL COLLATE NOCASE, real_name TEXT NOT NULL, note TEXT NOT NULL, UNIQUE (network_id, name))",
        "CREATE TABLE vlans (id INTEGER PRIMARY KEY, network_id INTEGER NOT NULL REFERENCES networks (id) ON DELETE CASCADE, kind TEXT NOT NULL CHECK (kind IN ('user', 'group')), name TEXT NOT NULL COLLATE NOCASE, vlan INTEGER NOT NULL CHECK (vlan BETWEEN 0 AND 4094), UNIQUE (network_id, kind, name))",
        "CREATE TABLE network_vlans (network_id INTEGER PRIMARY KEY REFERENCES networks (id) ON DELETE CASCADE, tpid INTEGER NOT NULL CHECK (tpid BETWEEN 1536 AND 65535), untagged INTEGER NOT NULL CHECK (untagged BETWEEN 1 AND 4094))",
        "CREATE TABLE rules (id INTEGER PRIMARY KEY, network_id INTEGER NOT NULL REFERENCES networks (id) ON DELETE CASCADE, name TEXT NOT NULL UNIQUE, position INTEGER NOT NULL, priority INTEGER NOT NULL CHECK (priority BETWEEN 0 AND 1000000), action TEXT NOT NULL CHECK (action IN ('allow', 'deny')), protocol INTEGER NOT NULL CHECK (protocol BETWEEN 0 AND 258), direction TEXT NOT NULL CHECK (direction IN ('forward', 'both')), active INTEGER NOT NULL CHECK (active IN (0, 1)), note TEXT NOT NULL)",
        "CREATE TABLE rule_values (id INTEGER PRIMARY KEY, rule_id INTEGER NOT NULL REFERENCES rules (id) ON DELETE CASCADE, list TEXT NOT NULL CHECK (list IN ('from.users', 'from.groups', 'from.tags', 'from.addresses', 'to.users', 'to.groups', 'to.tags', 'to.addresses', 'ports', 'vlans')), value TEXT NOT NULL)",
        "CREATE INDEX rules_network ON rules (network_id, position)",
        "CREATE INDEX rule_values_rule ON rule_values (rule_id)",
};

// The statements of each version of the schema, those of version v at index v - 1: a new store runs them all, a store of
// an older version those of the versions after its own
typedef struct CS_SCHEMA_STEP {
	char **Sql; // The statements
	UINT Num;   // ... their number
} CS_SCHEMA_STEP;

static CS_SCHEMA_STEP cs_schema_steps[] =
    {
        {cs_schema, CS_NUM(cs_schema)},
        {cs_schema_2, CS_NUM(cs_schema_2)},
};

// The names of the CS_MODE_*, CS_TRANSPORT_*, CS_CERT_* and CS_ROLE_* values in the database
static char *cs_mode_names[] = {"l2", "l3"};
static char *cs_transport_names[] = {"quic", "tls"};
static char *cs_cert_names[] = {"server", "chain", "ca", "user"};
static char *cs_role_names[] = {"owner", "hub-admin", "read-only"};

// The names of the CS_VLAN_* kinds, the actions (CS_ALLOW, CS_DENY) and the lists of a rule (CS_KEY_*) in the database.
// The lists are the keys of a rule of the policy engine's document: an end, a dot and a list of the end, or a list of
// the rule.
static char *cs_vlan_kind_names[] = {"user", "group"};
static char *cs_action_names[] = {"allow", "deny"};
static char *cs_list_names[] = {"from.users", "from.groups", "from.tags", "from.addresses", "to.users", "to.groups", "to.tags", "to.addresses", "ports", "vlans"};

// The names of the fork's authentication types in the database
typedef struct CS_AUTH_NAME {
	UINT AuthType; // AUTHTYPE_*
	char *Name;    // The name in the auth column
} CS_AUTH_NAME;

static CS_AUTH_NAME cs_auth_names[] =
    {
        {AUTHTYPE_ANONYMOUS, "anonymous"},
        {AUTHTYPE_PASSWORD, "password"},
        {AUTHTYPE_USERCERT, "user-cert"},
        {AUTHTYPE_ROOTCERT, "root-cert"},
        {AUTHTYPE_NT, "windows"},
};

// The salt of the hash that a check of an unknown name computes, so that it takes as long as one of a known name
static UCHAR cs_dummy_salt[CS_SALT_SIZE];

// A stored password hash: the hash, its salt and its iterations
typedef struct CS_PASSWORD {
	bool Found;               // Whether the row exists
	UCHAR Hash[CS_HASH_SIZE]; // The PBKDF2 hash
	UINT HashSize;            // Its bytes, 0 when no password is set
	UCHAR Salt[CS_SALT_SIZE]; // The salt
	UINT SaltSize;            // Its bytes
	UINT Iterations;          // The PBKDF2 iterations of the hash
} CS_PASSWORD;

// The name of value in names, NULL when it is out of range
static char *CsName(char **names, UINT num, UINT value) {
	return (value < num ? names[value] : NULL);
}

// The value whose name is name, INFINITE when there is none
static UINT CsValue(char **names, UINT num, const char *name) {
	for (UINT i = 0; i < num; i++)
		if (name != NULL && StrCmp(names[i], name) == 0)
			return i;

	return INFINITE;
}

// The name of the authentication type auth_type, NULL for a type that the store does not keep
static char *CsAuthName(UINT auth_type) {
	for (UINT i = 0; i < CS_NUM(cs_auth_names); i++)
		if (cs_auth_names[i].AuthType == auth_type)
			return cs_auth_names[i].Name;

	return NULL;
}

// The authentication type of a name of the auth column, INFINITE when there is none
static UINT CsAuthType(const char *name) {
	for (UINT i = 0; i < CS_NUM(cs_auth_names); i++)
		if (name != NULL && StrCmp(cs_auth_names[i].Name, name) == 0)
			return cs_auth_names[i].AuthType;

	return INFINITE;
}

// A UTF-8 copy of a wide string, "" for NULL; the caller frees it
static char *CsUniToUtf8(wchar_t *str) {
	if (str == NULL)
		str = L"";

	UINT size = CalcUniToUtf8(str) + 1;
	char *ret = ZeroMalloc(size);
	UniToUtf8(ret, size, str);

	return ret;
}

// Whether name is a valid network name: the rule of the fork's hub names
static bool CsIsNetworkName(char *name) {
	return (IsEmptyStr(name) == false && StrLen(name) <= MAX_HUBNAME_LEN && IsSafeStr(name));
}

// Whether name is a valid user name: the rule of the fork's user names, which also reserves the names of the
// administrator, the cascade and the bridge of a hub
static bool CsIsUserName(char *name) {
	return (IsEmptyStr(name) == false && StrLen(name) <= MAX_USERNAME_LEN && IsUserName(name));
}

// Whether name is a valid admin name: the characters of the fork's user names. An admin is no user of a hub, so the
// names that the fork reserves for those are not reserved here: the import names its owner "administrator".
static bool CsIsAdminName(char *name) {
	if (IsEmptyStr(name) || StrLen(name) > MAX_USERNAME_LEN)
		return false;

	for (UINT i = 0; name[i] != 0; i++)
		if (IsSafeChar(name[i]) == false && name[i] != '@')
			return false;

	return true;
}

// Prepare a statement on the connection; NULL when it does not compile
static sqlite3_stmt *CsPrepare(CONFIG_STORE *s, char *sql) {
	sqlite3_stmt *st = NULL;

	if (sqlite3_prepare_v2(s->Db, sql, -1, &st, NULL) != SQLITE_OK) {
		Debug("ConfigStore: %s: %s\n", sqlite3_errmsg(s->Db), sql);
		sqlite3_finalize(st);
		return NULL;
	}

	return st;
}

// Run statements that take no parameter and whose rows are not needed
static bool CsExec(CONFIG_STORE *s, char *sql) {
	char *error = NULL;

	if (sqlite3_exec(s->Db, sql, NULL, NULL, &error) != SQLITE_OK) {
		Debug("ConfigStore: %s: %s\n", error != NULL ? error : sqlite3_errmsg(s->Db), sql);
		sqlite3_free(error);
		return false;
	}

	return true;
}

// The first column of the first row of a statement without parameters, fail when there is no row
static INT64 CsQueryInt(CONFIG_STORE *s, char *sql, INT64 fail) {
	INT64 ret = fail;

	sqlite3_stmt *st = CsPrepare(s, sql);
	if (st != NULL && sqlite3_step(st) == SQLITE_ROW)
		ret = sqlite3_column_int64(st, 0);

	sqlite3_finalize(st);

	return ret;
}

// The error of the last statement that failed: ERR_OBJECT_EXISTS for a name or key that is taken,
// ERR_INVALID_PARAMETER for a value that the schema refuses, ERR_INTERNAL_ERROR for anything else
static UINT CsLastError(CONFIG_STORE *s) {
	switch (sqlite3_extended_errcode(s->Db)) {
	case SQLITE_CONSTRAINT_UNIQUE:
	case SQLITE_CONSTRAINT_PRIMARYKEY:
		return ERR_OBJECT_EXISTS;

	case SQLITE_CONSTRAINT_CHECK:
	case SQLITE_CONSTRAINT_NOTNULL:
	case SQLITE_CONSTRAINT_FOREIGNKEY:
		return ERR_INVALID_PARAMETER;
	}

	Debug("ConfigStore: %s\n", sqlite3_errmsg(s->Db));

	return ERR_INTERNAL_ERROR;
}

// Run a statement that returns no row and finalize it: ERR_NO_ERROR, or the error of CsLastError
static UINT CsRun(CONFIG_STORE *s, sqlite3_stmt *st) {
	if (st == NULL)
		return ERR_INTERNAL_ERROR;

	UINT ret = (sqlite3_step(st) == SQLITE_DONE ? ERR_NO_ERROR : CsLastError(s));
	sqlite3_finalize(st);

	return ret;
}

static void CsBindStr(sqlite3_stmt *st, int index, char *str) {
	sqlite3_bind_text(st, index, str == NULL ? "" : str, -1, SQLITE_TRANSIENT);
}

static void CsBindUni(sqlite3_stmt *st, int index, wchar_t *str) {
	char *utf8 = CsUniToUtf8(str);
	sqlite3_bind_text(st, index, utf8, -1, SQLITE_TRANSIENT);
	Free(utf8);
}

// Bind a blob, or NULL for no data
static void CsBindBlob(sqlite3_stmt *st, int index, void *data, UINT size) {
	if (data == NULL || size == 0)
		sqlite3_bind_null(st, index);
	else
		sqlite3_bind_blob(st, index, data, (int)size, SQLITE_TRANSIENT);
}

// Bind a row id, or NULL for 0 (no row)
static void CsBindId(sqlite3_stmt *st, int index, INT64 id) {
	if (id == 0)
		sqlite3_bind_null(st, index);
	else
		sqlite3_bind_int64(st, index, id);
}

static void CsColumnStr(sqlite3_stmt *st, int index, char *dst, UINT size) {
	const char *text = (const char *)sqlite3_column_text(st, index);
	StrCpy(dst, size, text == NULL ? "" : text);
}

static void CsColumnUni(sqlite3_stmt *st, int index, wchar_t *dst, UINT size) {
	const char *text = (const char *)sqlite3_column_text(st, index);

	if (text == NULL || text[0] == 0)
		UniStrCpy(dst, size, L"");
	else
		Utf8ToUni(dst, size, text, StrLen(text));
}

// Copy a blob column into dst, at most size bytes; returns the bytes copied, 0 for NULL or a longer blob
static UINT CsColumnBlob(sqlite3_stmt *st, int index, void *dst, UINT size) {
	const void *data = sqlite3_column_blob(st, index);
	UINT data_size = (UINT)sqlite3_column_bytes(st, index);

	if (data == NULL || data_size == 0 || data_size > size)
		return 0;

	Copy(dst, data, data_size);

	return data_size;
}

// The id of the network name, 0 when there is none. The caller holds the lock.
static INT64 CsNetworkId(CONFIG_STORE *s, char *name) {
	INT64 ret = 0;

	sqlite3_stmt *st = CsPrepare(s, "SELECT id FROM networks WHERE name = ?1");
	if (st == NULL)
		return 0;

	CsBindStr(st, 1, name);
	if (sqlite3_step(st) == SQLITE_ROW)
		ret = sqlite3_column_int64(st, 0);

	sqlite3_finalize(st);

	return ret;
}

// The id of the user name of the network network, 0 when there is none. The caller holds the lock.
static INT64 CsUserId(CONFIG_STORE *s, char *network, char *name) {
	INT64 ret = 0;

	sqlite3_stmt *st = CsPrepare(s, "SELECT u.id FROM users u JOIN networks n ON n.id = u.network_id WHERE n.name = ?1 AND u.name = ?2");
	if (st == NULL)
		return 0;

	CsBindStr(st, 1, network);
	CsBindStr(st, 2, name);
	if (sqlite3_step(st) == SQLITE_ROW)
		ret = sqlite3_column_int64(st, 0);

	sqlite3_finalize(st);

	return ret;
}

// Start a write transaction: the write lock of the database is taken at once, so the statements up to CsCommit see
// no write of another connection. The caller holds the lock of the store until CsCommit or CsRollback.
bool CsBegin(CONFIG_STORE *s) {
	return CsExec(s, "BEGIN IMMEDIATE");
}

bool CsCommit(CONFIG_STORE *s) {
	if (CsExec(s, "COMMIT"))
		return true;

	CsRollback(s);

	return false;
}

void CsRollback(CONFIG_STORE *s) {
	CsExec(s, "ROLLBACK");
}

// Create the schema in a new database, check the schema of an existing one, or add the tables of the versions after
// its own to a store of an older schema, which keeps its rows. The version is read inside a write transaction, so two
// processes that open a new or older file at once change its schema once. False for a file that is not a database, a
// database of another program, or a store of a newer schema; such a file is left as it is.
static bool CsCheckSchema(CONFIG_STORE *s) {
	char tmp[MAX_SIZE];

	if (CsBegin(s) == false)
		return false;

	INT64 version = CsQueryInt(s, "PRAGMA user_version", -1);
	if (version == CS_SCHEMA_VERSION) {
		CsRollback(s);
		return true;
	}

	if (version < 0 || version > CS_SCHEMA_VERSION || (version == 0 && CsQueryInt(s, "SELECT COUNT(*) FROM sqlite_master", -1) != 0)) {
		Debug("ConfigStore: %S has schema %I64d, not %u: not opened\n", s->Path, version, CS_SCHEMA_VERSION);
		CsRollback(s);
		return false;
	}

	bool ok = true;
	for (UINT v = (UINT)version; ok && v < CS_SCHEMA_VERSION && v < CS_NUM(cs_schema_steps); v++)
		for (UINT i = 0; ok && i < cs_schema_steps[v].Num; i++)
			ok = CsExec(s, cs_schema_steps[v].Sql[i]);

	Format(tmp, sizeof(tmp), "PRAGMA user_version = %u", CS_SCHEMA_VERSION);
	if (ok)
		ok = CsExec(s, tmp);

	if (ok)
		return CsCommit(s);

	CsRollback(s);

	return false;
}

// Prepare a new connection: foreign keys, the schema, then the write-ahead log, which is set only on a store
static bool CsInitSchema(CONFIG_STORE *s) {
	return (CsExec(s, "PRAGMA foreign_keys = ON") && CsCheckSchema(s) && CsExec(s, "PRAGMA journal_mode = WAL"));
}

// Open the store in the database file path, or create it with the schema when the file does not exist. NULL when
// the file cannot be opened, is not a database or holds another schema.
CONFIG_STORE *CsOpen(wchar_t *path) {
	sqlite3 *db = NULL;
	if (UniIsEmptyStr(path))
		return NULL;

	char *utf8 = CsUniToUtf8(path);
	int rc = sqlite3_open_v2(utf8, &db, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX, NULL);
	Free(utf8);

	if (rc != SQLITE_OK) {
		Debug("ConfigStore: %S: %s\n", path, db != NULL ? sqlite3_errmsg(db) : sqlite3_errstr(rc));
		sqlite3_close(db);
		return NULL;
	}

	sqlite3_busy_timeout(db, CS_BUSY_TIMEOUT);

	CONFIG_STORE *s = ZeroMalloc(sizeof(CONFIG_STORE));
	s->Lock = NewLock();
	s->Db = db;
	UniStrCpy(s->Path, sizeof(s->Path), path);

	if (CsInitSchema(s) == false) {
		CsClose(s);
		return NULL;
	}

	return s;
}

// Close the store. Every statement of the store is finalized by the call that prepared it.
void CsClose(CONFIG_STORE *s) {
	if (s == NULL)
		return;

	sqlite3_close(s->Db);
	DeleteLock(s->Lock);

	Free(s);
}

// The version of the SQLite library that the store runs on: the one of winsqlite3.dll
char *CsLibVersion() {
	return (char *)sqlite3_libversion();
}

// Whether the store holds no network, listener, certificate or admin and no import, so that an import may fill it
bool CsIsEmpty(CONFIG_STORE *s) {
	INT64 num = -1;
	if (s == NULL)
		return false;

	Lock(s->Lock);
	{
		num = CsQueryInt(s, "SELECT (SELECT COUNT(*) FROM networks) + (SELECT COUNT(*) FROM listeners) + (SELECT COUNT(*) FROM certificates) + (SELECT COUNT(*) FROM admins) + (SELECT COUNT(*) FROM settings WHERE name = '" CS_SETTING_IMPORTED "')", -1);
	}
	Unlock(s->Lock);

	return (num == 0);
}

// The setting name in value; false when it is not set
bool CsGetSetting(CONFIG_STORE *s, char *name, char *value, UINT size) {
	bool ret = false;

	if (value != NULL)
		StrCpy(value, size, "");

	if (s == NULL || IsEmptyStr(name) || value == NULL)
		return false;

	Lock(s->Lock);
	{
		sqlite3_stmt *st = CsPrepare(s, "SELECT value FROM settings WHERE name = ?1");
		if (st != NULL) {
			CsBindStr(st, 1, name);

			if (sqlite3_step(st) == SQLITE_ROW) {
				CsColumnStr(st, 0, value, size);
				ret = true;
			}

			sqlite3_finalize(st);
		}
	}
	Unlock(s->Lock);

	return ret;
}

// Set the setting name to value, or remove it for NULL
UINT CsSetSetting(CONFIG_STORE *s, char *name, char *value) {
	UINT ret = ERR_INTERNAL_ERROR;
	if (s == NULL || IsEmptyStr(name))
		return ERR_INVALID_PARAMETER;

	Lock(s->Lock);
	{
		sqlite3_stmt *st;

		if (value == NULL) {
			st = CsPrepare(s, "DELETE FROM settings WHERE name = ?1");
		} else {
			st = CsPrepare(s, "INSERT OR REPLACE INTO settings (name, value) VALUES (?1, ?2)");
			if (st != NULL)
				CsBindStr(st, 2, value);
		}

		if (st != NULL)
			CsBindStr(st, 1, name);

		ret = CsRun(s, st);
	}
	Unlock(s->Lock);

	return ret;
}

// Add the network name: ERR_OBJECT_EXISTS when the name is taken, without case
UINT CsAddNetwork(CONFIG_STORE *s, char *name, UINT mode, bool online) {
	UINT ret = ERR_INTERNAL_ERROR;
	char *mode_name = CsName(cs_mode_names, CS_NUM(cs_mode_names), mode);
	if (s == NULL || CsIsNetworkName(name) == false || mode_name == NULL)
		return ERR_INVALID_PARAMETER;

	Lock(s->Lock);
	{
		sqlite3_stmt *st = CsPrepare(s, "INSERT INTO networks (name, mode, online) VALUES (?1, ?2, ?3)");
		if (st != NULL) {
			CsBindStr(st, 1, name);
			CsBindStr(st, 2, mode_name);
			sqlite3_bind_int(st, 3, online ? 1 : 0);
		}

		ret = CsRun(s, st);
	}
	Unlock(s->Lock);

	return ret;
}

// Delete the network name with its users, certificates and hub-admins
UINT CsDeleteNetwork(CONFIG_STORE *s, char *name) {
	UINT ret = ERR_INTERNAL_ERROR;
	if (s == NULL || IsEmptyStr(name))
		return ERR_INVALID_PARAMETER;

	Lock(s->Lock);
	{
		sqlite3_stmt *st = CsPrepare(s, "DELETE FROM networks WHERE name = ?1");
		if (st != NULL)
			CsBindStr(st, 1, name);

		ret = CsRun(s, st);

		if (ret == ERR_NO_ERROR && sqlite3_changes(s->Db) == 0)
			ret = ERR_HUB_NOT_FOUND;
	}
	Unlock(s->Lock);

	return ret;
}

// The networks of the store in the order they were added (CS_NETWORK); free the list with CsFreeNetworkList
LIST *CsEnumNetworks(CONFIG_STORE *s) {
	char mode[MAX_SIZE];
	LIST *o = NewListFast(NULL);
	if (s == NULL)
		return o;

	Lock(s->Lock);
	{
		sqlite3_stmt *st = CsPrepare(s, "SELECT name, mode, online FROM networks ORDER BY id");

		while (st != NULL && sqlite3_step(st) == SQLITE_ROW) {
			CS_NETWORK *n = ZeroMalloc(sizeof(CS_NETWORK));

			CsColumnStr(st, 0, n->Name, sizeof(n->Name));
			CsColumnStr(st, 1, mode, sizeof(mode));
			n->Mode = CsValue(cs_mode_names, CS_NUM(cs_mode_names), mode);
			n->Online = (sqlite3_column_int(st, 2) != 0);

			Add(o, n);
		}

		sqlite3_finalize(st);
	}
	Unlock(s->Lock);

	return o;
}

void CsFreeNetworkList(LIST *o) {
	if (o == NULL)
		return;

	for (UINT i = 0; i < LIST_NUM(o); i++)
		Free(LIST_DATA(o, i));

	ReleaseList(o);
}

// Add the user u->Name to the network u->Network, without a password or a pinned key: ERR_HUB_NOT_FOUND when there
// is no such network, ERR_OBJECT_EXISTS when the network has a user of that name
UINT CsAddUser(CONFIG_STORE *s, CS_USER *u) {
	UINT ret = ERR_INTERNAL_ERROR;
	if (s == NULL || u == NULL)
		return ERR_INVALID_PARAMETER;

	char *auth = CsAuthName(u->AuthType);
	if (auth == NULL || CsIsUserName(u->Name) == false || u->AuthSerialSize > sizeof(u->AuthSerial))
		return ERR_INVALID_PARAMETER;

	Lock(s->Lock);
	{
		INT64 network_id = CsNetworkId(s, u->Network);

		if (network_id == 0) {
			ret = ERR_HUB_NOT_FOUND;
		} else {
			sqlite3_stmt *st = CsPrepare(s, "INSERT INTO users (network_id, name, real_name, note, group_name, auth, auth_name, auth_serial, expire_time) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)");
			if (st != NULL) {
				sqlite3_bind_int64(st, 1, network_id);
				CsBindStr(st, 2, u->Name);
				CsBindUni(st, 3, u->RealName);
				CsBindUni(st, 4, u->Note);
				CsBindStr(st, 5, u->Group);
				CsBindStr(st, 6, auth);
				CsBindUni(st, 7, u->AuthName);
				CsBindBlob(st, 8, u->AuthSerial, u->AuthSerialSize);
				sqlite3_bind_int64(st, 9, (INT64)u->ExpireTime);
			}

			ret = CsRun(s, st);
		}
	}
	Unlock(s->Lock);

	return ret;
}

// The user name of the network network in u; false when there is none
bool CsGetUser(CONFIG_STORE *s, char *network, char *name, CS_USER *u) {
	char auth[MAX_SIZE];
	bool ret = false;

	if (u != NULL)
		Zero(u, sizeof(CS_USER));

	if (s == NULL || u == NULL)
		return false;

	Lock(s->Lock);
	{
		sqlite3_stmt *st = CsPrepare(s, "SELECT n.name, u.name, u.real_name, u.note, u.group_name, u.auth, u.auth_name, u.auth_serial, u.expire_time, u.password_hash IS NOT NULL, u.pinned_key IS NOT NULL FROM users u JOIN networks n ON n.id = u.network_id WHERE n.name = ?1 AND u.name = ?2");
		if (st != NULL) {
			CsBindStr(st, 1, network);
			CsBindStr(st, 2, name);

			if (sqlite3_step(st) == SQLITE_ROW) {
				CsColumnStr(st, 0, u->Network, sizeof(u->Network));
				CsColumnStr(st, 1, u->Name, sizeof(u->Name));
				CsColumnUni(st, 2, u->RealName, sizeof(u->RealName));
				CsColumnUni(st, 3, u->Note, sizeof(u->Note));
				CsColumnStr(st, 4, u->Group, sizeof(u->Group));
				CsColumnStr(st, 5, auth, sizeof(auth));
				u->AuthType = CsAuthType(auth);
				CsColumnUni(st, 6, u->AuthName, sizeof(u->AuthName));
				u->AuthSerialSize = CsColumnBlob(st, 7, u->AuthSerial, sizeof(u->AuthSerial));
				u->ExpireTime = (UINT64)sqlite3_column_int64(st, 8);
				u->HasPassword = (sqlite3_column_int(st, 9) != 0);
				u->HasKey = (sqlite3_column_int(st, 10) != 0);
				ret = true;
			}

			sqlite3_finalize(st);
		}
	}
	Unlock(s->Lock);

	return ret;
}

// PBKDF2-HMAC-SHA256 of password and salt (BCryptDeriveKeyPBKDF2): dst_size bytes in dst
bool CsPbkdf2(void *dst, UINT dst_size, char *password, void *salt, UINT salt_size, UINT iterations) {
	if (dst == NULL || dst_size == 0 || password == NULL || salt == NULL || iterations == 0)
		return false;

	NTSTATUS status = BCryptDeriveKeyPBKDF2(BCRYPT_HMAC_SHA256_ALG_HANDLE, (PUCHAR)password, StrLen(password), (PUCHAR)salt, salt_size, iterations, (PUCHAR)dst, dst_size, 0);

	return BCRYPT_SUCCESS(status);
}

// A new hash of password: a random salt and CS_PBKDF2_ITERATIONS iterations
static bool CsHashPassword(CS_PASSWORD *p, char *password) {
	Zero(p, sizeof(CS_PASSWORD));

	Rand(p->Salt, sizeof(p->Salt));
	p->SaltSize = sizeof(p->Salt);
	p->Iterations = CS_PBKDF2_ITERATIONS;
	p->HashSize = sizeof(p->Hash);

	return CsPbkdf2(p->Hash, p->HashSize, password, p->Salt, p->SaltSize, p->Iterations);
}

// Whether password gives the stored hash p, compared in constant time. A missing row or one without a password
// takes as long as a wrong password.
static bool CsVerifyPassword(CS_PASSWORD *p, char *password) {
	UCHAR hash[CS_HASH_SIZE];
	volatile UCHAR diff = 0;

	if (password == NULL)
		return false;

	if (p->Found == false || p->HashSize != sizeof(hash) || p->SaltSize == 0 || p->Iterations == 0) {
		CsPbkdf2(hash, sizeof(hash), password, cs_dummy_salt, sizeof(cs_dummy_salt), CS_PBKDF2_ITERATIONS);
		return false;
	}

	if (CsPbkdf2(hash, sizeof(hash), password, p->Salt, p->SaltSize, p->Iterations) == false)
		return false;

	for (UINT i = 0; i < sizeof(hash); i++)
		diff |= hash[i] ^ p->Hash[i];

	return (diff == 0);
}

// Read the password hash of the row of a statement with the columns hash, salt and iterations
static void CsReadPassword(sqlite3_stmt *st, CS_PASSWORD *p) {
	p->Found = true;
	p->HashSize = CsColumnBlob(st, 0, p->Hash, sizeof(p->Hash));
	p->SaltSize = CsColumnBlob(st, 1, p->Salt, sizeof(p->Salt));
	p->Iterations = (UINT)sqlite3_column_int(st, 2);
}

// Set the password of the user name of the network network, or remove it for NULL. The hash is computed before the
// lock is taken.
UINT CsSetUserPassword(CONFIG_STORE *s, char *network, char *name, char *password) {
	CS_PASSWORD p;
	UINT ret = ERR_INTERNAL_ERROR;
	if (s == NULL)
		return ERR_INVALID_PARAMETER;

	Zero(&p, sizeof(p));
	if (password != NULL && CsHashPassword(&p, password) == false)
		return ERR_INTERNAL_ERROR;

	Lock(s->Lock);
	{
		INT64 user_id = CsUserId(s, network, name);

		if (user_id == 0) {
			ret = ERR_OBJECT_NOT_FOUND;
		} else {
			sqlite3_stmt *st = CsPrepare(s, "UPDATE users SET password_hash = ?1, password_salt = ?2, password_iterations = ?3 WHERE id = ?4");
			if (st != NULL) {
				CsBindBlob(st, 1, p.Hash, p.HashSize);
				CsBindBlob(st, 2, p.Salt, p.SaltSize);
				sqlite3_bind_int(st, 3, (int)p.Iterations);
				sqlite3_bind_int64(st, 4, user_id);
			}

			ret = CsRun(s, st);
		}
	}
	Unlock(s->Lock);

	return ret;
}

// Whether password is the password of the user name of the network network. PBKDF2 runs after the lock is released.
bool CsCheckUserPassword(CONFIG_STORE *s, char *network, char *name, char *password) {
	CS_PASSWORD p;

	Zero(&p, sizeof(p));

	if (s != NULL) {
		Lock(s->Lock);
		{
			sqlite3_stmt *st = CsPrepare(s, "SELECT u.password_hash, u.password_salt, u.password_iterations FROM users u JOIN networks n ON n.id = u.network_id WHERE n.name = ?1 AND u.name = ?2");
			if (st != NULL) {
				CsBindStr(st, 1, network);
				CsBindStr(st, 2, name);

				if (sqlite3_step(st) == SQLITE_ROW)
					CsReadPassword(st, &p);

				sqlite3_finalize(st);
			}
		}
		Unlock(s->Lock);
	}

	return CsVerifyPassword(&p, password);
}

// Trust on first use of the Noise static key of the user name of the network network (ADR-0022, Enrollment): the
// first key is pinned, a later login must present the same one. The check and the pin are one transaction.
// CS_KEY_NO_USER when the store keeps no such user; CS_KEY_ERROR when the store fails to begin, to read the user, to
// write the pin or to commit it, which leaves the user as it was.
UINT CsPinUserKey(CONFIG_STORE *s, char *network, char *name, UCHAR *key) {
	UCHAR pinned[CS_KEY_SIZE];
	UINT ret = CS_KEY_ERROR;
	if (s == NULL || key == NULL)
		return CS_KEY_ERROR;

	Lock(s->Lock);
	{
		if (CsBegin(s)) {
			INT64 user_id = 0;
			UINT pinned_size = 0;
			int step = SQLITE_ERROR; // The read of the user: a row, none (SQLITE_DONE) or a failure

			sqlite3_stmt *st = CsPrepare(s, "SELECT u.id, u.pinned_key FROM users u JOIN networks n ON n.id = u.network_id WHERE n.name = ?1 AND u.name = ?2");
			if (st != NULL) {
				CsBindStr(st, 1, network);
				CsBindStr(st, 2, name);

				step = sqlite3_step(st);
				if (step == SQLITE_ROW) {
					user_id = sqlite3_column_int64(st, 0);
					pinned_size = CsColumnBlob(st, 1, pinned, sizeof(pinned));
				}

				sqlite3_finalize(st);
			}

			if (step != SQLITE_ROW && step != SQLITE_DONE) {
				ret = CS_KEY_ERROR;
			} else if (user_id == 0) {
				ret = CS_KEY_NO_USER;
			} else if (pinned_size == 0) {
				st = CsPrepare(s, "UPDATE users SET pinned_key = ?1, pinned_time = ?2 WHERE id = ?3");
				if (st != NULL) {
					CsBindBlob(st, 1, key, CS_KEY_SIZE);
					sqlite3_bind_int64(st, 2, (INT64)SystemTime64());
					sqlite3_bind_int64(st, 3, user_id);
				}

				if (CsRun(s, st) == ERR_NO_ERROR)
					ret = CS_KEY_PINNED;
			} else {
				ret = (pinned_size == CS_KEY_SIZE && Cmp(pinned, key, CS_KEY_SIZE) == 0) ? CS_KEY_MATCH : CS_KEY_MISMATCH;
			}

			if (ret == CS_KEY_PINNED) {
				if (CsCommit(s) == false)
					ret = CS_KEY_ERROR;
			} else {
				CsRollback(s);
			}
		}
	}
	Unlock(s->Lock);

	return ret;
}

// Remove the pinned key of the user name of the network network: its next login pins a key again
UINT CsUnpinUserKey(CONFIG_STORE *s, char *network, char *name) {
	UINT ret = ERR_INTERNAL_ERROR;
	if (s == NULL)
		return ERR_INVALID_PARAMETER;

	Lock(s->Lock);
	{
		INT64 user_id = CsUserId(s, network, name);

		if (user_id == 0) {
			ret = ERR_OBJECT_NOT_FOUND;
		} else {
			sqlite3_stmt *st = CsPrepare(s, "UPDATE users SET pinned_key = NULL, pinned_time = 0 WHERE id = ?1");
			if (st != NULL)
				sqlite3_bind_int64(st, 1, user_id);

			ret = CsRun(s, st);
		}
	}
	Unlock(s->Lock);

	return ret;
}

// Add a listener: ERR_OBJECT_EXISTS when the transport listens on that port already
UINT CsAddListener(CONFIG_STORE *s, UINT transport, UINT port, bool enabled) {
	UINT ret = ERR_INTERNAL_ERROR;
	char *transport_name = CsName(cs_transport_names, CS_NUM(cs_transport_names), transport);
	if (s == NULL || transport_name == NULL || port == 0 || port > 65535)
		return ERR_INVALID_PARAMETER;

	Lock(s->Lock);
	{
		sqlite3_stmt *st = CsPrepare(s, "INSERT INTO listeners (transport, port, enabled) VALUES (?1, ?2, ?3)");
		if (st != NULL) {
			CsBindStr(st, 1, transport_name);
			sqlite3_bind_int(st, 2, (int)port);
			sqlite3_bind_int(st, 3, enabled ? 1 : 0);
		}

		ret = CsRun(s, st);
	}
	Unlock(s->Lock);

	return ret;
}

// The subject (X.500 string) and the SHA-1 thumbprint (the key of the Windows certificate stores, upper-case hex) of
// a DER certificate, read by CryptoAPI; false when der is not a certificate
static bool CsCertInfo(void *der, UINT der_size, char *subject, UINT subject_size, char *thumbprint, UINT thumbprint_size) {
	UCHAR hash[SHA1_SIZE];
	DWORD hash_size = sizeof(hash);
	DWORD str_type = CERT_X500_NAME_STR;
	wchar_t name[MAX_SIZE];

	PCCERT_CONTEXT cert = CertCreateCertificateContext(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, (const BYTE *)der, der_size);
	if (cert == NULL)
		return false;

	bool ok = CertGetCertificateContextProperty(cert, CERT_SHA1_HASH_PROP_ID, hash, &hash_size) && hash_size == sizeof(hash);

	CertGetNameStringW(cert, CERT_NAME_RDN_TYPE, 0, &str_type, name, sizeof(name) / sizeof(name[0]));

	CertFreeCertificateContext(cert);

	if (ok == false)
		return false;

	BinToStr(thumbprint, thumbprint_size, hash, sizeof(hash));

	char *utf8 = CsUniToUtf8(name);
	StrCpy(subject, subject_size, utf8);
	Free(utf8);

	return true;
}

// Add a certificate (DER) for usage (CS_CERT_*): a CA names its network, a user certificate its network and user,
// the server certificate and the chain name neither. ERR_INVALID_PARAMETER when der is not a certificate.
UINT CsAddCert(CONFIG_STORE *s, UINT usage, char *network, char *user, void *der, UINT der_size) {
	char subject[MAX_SIZE * 2];
	char thumbprint[MAX_SIZE];
	UINT ret = ERR_INTERNAL_ERROR;
	char *usage_name = CsName(cs_cert_names, CS_NUM(cs_cert_names), usage);
	if (s == NULL || usage_name == NULL || der == NULL || der_size == 0)
		return ERR_INVALID_PARAMETER;

	bool with_network = (usage == CS_CERT_CA || usage == CS_CERT_USER);
	bool with_user = (usage == CS_CERT_USER);
	if (IsEmptyStr(network) == with_network || IsEmptyStr(user) == with_user)
		return ERR_INVALID_PARAMETER;

	if (CsCertInfo(der, der_size, subject, sizeof(subject), thumbprint, sizeof(thumbprint)) == false)
		return ERR_INVALID_PARAMETER;

	Lock(s->Lock);
	{
		INT64 network_id = (with_network ? CsNetworkId(s, network) : 0);
		INT64 user_id = (with_user ? CsUserId(s, network, user) : 0);

		if (with_network && network_id == 0) {
			ret = ERR_HUB_NOT_FOUND;
		} else if (with_user && user_id == 0) {
			ret = ERR_OBJECT_NOT_FOUND;
		} else {
			sqlite3_stmt *st = CsPrepare(s, "INSERT INTO certificates (usage, network_id, user_id, subject, thumbprint, der) VALUES (?1, ?2, ?3, ?4, ?5, ?6)");
			if (st != NULL) {
				CsBindStr(st, 1, usage_name);
				CsBindId(st, 2, network_id);
				CsBindId(st, 3, user_id);
				CsBindStr(st, 4, subject);
				CsBindStr(st, 5, thumbprint);
				CsBindBlob(st, 6, der, der_size);
			}

			ret = CsRun(s, st);
		}
	}
	Unlock(s->Lock);

	return ret;
}

// Add the named admin account name with role (CS_ROLE_*) and a password, none for NULL: a hub-admin names the
// network it administers, the other roles none. ERR_OBJECT_EXISTS when the name is taken, without case.
UINT CsAddAdmin(CONFIG_STORE *s, char *name, UINT role, char *network, char *password) {
	CS_PASSWORD p;
	UINT ret = ERR_INTERNAL_ERROR;
	char *role_name = CsName(cs_role_names, CS_NUM(cs_role_names), role);
	if (s == NULL || role_name == NULL || CsIsAdminName(name) == false)
		return ERR_INVALID_PARAMETER;

	bool with_network = (role == CS_ROLE_HUB_ADMIN);
	if (IsEmptyStr(network) == with_network)
		return ERR_INVALID_PARAMETER;

	Zero(&p, sizeof(p));
	if (password != NULL && CsHashPassword(&p, password) == false)
		return ERR_INTERNAL_ERROR;

	Lock(s->Lock);
	{
		INT64 network_id = (with_network ? CsNetworkId(s, network) : 0);

		if (with_network && network_id == 0) {
			ret = ERR_HUB_NOT_FOUND;
		} else {
			sqlite3_stmt *st = CsPrepare(s, "INSERT INTO admins (name, role, network_id, password_hash, password_salt, password_iterations) VALUES (?1, ?2, ?3, ?4, ?5, ?6)");
			if (st != NULL) {
				CsBindStr(st, 1, name);
				CsBindStr(st, 2, role_name);
				CsBindId(st, 3, network_id);
				CsBindBlob(st, 4, p.Hash, p.HashSize);
				CsBindBlob(st, 5, p.Salt, p.SaltSize);
				sqlite3_bind_int(st, 6, (int)p.Iterations);
			}

			ret = CsRun(s, st);
		}
	}
	Unlock(s->Lock);

	return ret;
}

// Read the admin of a row with the columns name, role, network name and whether a password is set
static void CsReadAdmin(sqlite3_stmt *st, int first, CS_ADMIN *a) {
	char role[MAX_SIZE];

	CsColumnStr(st, first, a->Name, sizeof(a->Name));
	CsColumnStr(st, first + 1, role, sizeof(role));
	a->Role = CsValue(cs_role_names, CS_NUM(cs_role_names), role);
	CsColumnStr(st, first + 2, a->Network, sizeof(a->Network));
	a->HasPassword = (sqlite3_column_int(st, first + 3) != 0);
}

// The named admin account name in a; false when there is none
bool CsGetAdmin(CONFIG_STORE *s, char *name, CS_ADMIN *a) {
	bool ret = false;

	if (a != NULL)
		Zero(a, sizeof(CS_ADMIN));

	if (s == NULL || a == NULL)
		return false;

	Lock(s->Lock);
	{
		sqlite3_stmt *st = CsPrepare(s, "SELECT a.name, a.role, IFNULL(n.name, ''), a.password_hash IS NOT NULL FROM admins a LEFT JOIN networks n ON n.id = a.network_id WHERE a.name = ?1");
		if (st != NULL) {
			CsBindStr(st, 1, name);

			if (sqlite3_step(st) == SQLITE_ROW) {
				CsReadAdmin(st, 0, a);
				ret = true;
			}

			sqlite3_finalize(st);
		}
	}
	Unlock(s->Lock);

	return ret;
}

// Set the password of the named admin account name, or remove it for NULL
UINT CsSetAdminPassword(CONFIG_STORE *s, char *name, char *password) {
	CS_PASSWORD p;
	UINT ret = ERR_INTERNAL_ERROR;
	if (s == NULL || IsEmptyStr(name))
		return ERR_INVALID_PARAMETER;

	Zero(&p, sizeof(p));
	if (password != NULL && CsHashPassword(&p, password) == false)
		return ERR_INTERNAL_ERROR;

	Lock(s->Lock);
	{
		sqlite3_stmt *st = CsPrepare(s, "UPDATE admins SET password_hash = ?1, password_salt = ?2, password_iterations = ?3 WHERE name = ?4");
		if (st != NULL) {
			CsBindBlob(st, 1, p.Hash, p.HashSize);
			CsBindBlob(st, 2, p.Salt, p.SaltSize);
			sqlite3_bind_int(st, 3, (int)p.Iterations);
			CsBindStr(st, 4, name);
		}

		ret = CsRun(s, st);

		if (ret == ERR_NO_ERROR && sqlite3_changes(s->Db) == 0)
			ret = ERR_OBJECT_NOT_FOUND;
	}
	Unlock(s->Lock);

	return ret;
}

// Whether password is the password of the named admin account name; its account in a when it is
bool CsCheckAdminPassword(CONFIG_STORE *s, char *name, char *password, CS_ADMIN *a) {
	CS_PASSWORD p;
	CS_ADMIN tmp;

	Zero(&p, sizeof(p));
	Zero(&tmp, sizeof(tmp));

	if (a != NULL)
		Zero(a, sizeof(CS_ADMIN));

	if (s != NULL) {
		Lock(s->Lock);
		{
			sqlite3_stmt *st = CsPrepare(s, "SELECT a.password_hash, a.password_salt, a.password_iterations, a.name, a.role, IFNULL(n.name, ''), a.password_hash IS NOT NULL FROM admins a LEFT JOIN networks n ON n.id = a.network_id WHERE a.name = ?1");
			if (st != NULL) {
				CsBindStr(st, 1, name);

				if (sqlite3_step(st) == SQLITE_ROW) {
					CsReadPassword(st, &p);
					CsReadAdmin(st, 3, &tmp);
				}

				sqlite3_finalize(st);
			}
		}
		Unlock(s->Lock);
	}

	if (CsVerifyPassword(&p, password) == false)
		return false;

	if (a != NULL)
		Copy(a, &tmp, sizeof(CS_ADMIN));

	return true;
}

//
// The policy of the networks (schema 2)
//

// Whether name is a valid group name: the characters of the fork's names of hubs, users and groups
static bool CsIsGroupName(char *name) {
	return (IsEmptyStr(name) == false && StrLen(name) <= MAX_USERNAME_LEN && IsSafeStr(name));
}

// Whether name is a name of the policy engine for a network or a rule: 1 to CS_MAX_RULE_NAME letters, digits, '.', '-'
// and '_' (PolicyNameOk of Core/PolicyRules.c)
static bool CsIsEngineName(char *name, UINT max) {
	UINT len = StrLen(name);
	if (len == 0 || len > max)
		return false;

	for (UINT i = 0; i < len; i++) {
		char c = name[i];

		if ((c >= 'a' && c <= 'z') == false && (c >= 'A' && c <= 'Z') == false && (c >= '0' && c <= '9') == false && c != '.' && c != '-' && c != '_')
			return false;
	}

	return true;
}

// Add the group g->Name to the network g->Network: ERR_HUB_NOT_FOUND when there is no such network, ERR_OBJECT_EXISTS
// when the network has a group of that name
UINT CsAddGroup(CONFIG_STORE *s, CS_GROUP *g) {
	UINT ret = ERR_INTERNAL_ERROR;
	if (s == NULL || g == NULL || CsIsGroupName(g->Name) == false)
		return ERR_INVALID_PARAMETER;

	Lock(s->Lock);
	{
		INT64 network_id = CsNetworkId(s, g->Network);

		if (network_id == 0) {
			ret = ERR_HUB_NOT_FOUND;
		} else {
			sqlite3_stmt *st = CsPrepare(s, "INSERT INTO user_groups (network_id, name, real_name, note) VALUES (?1, ?2, ?3, ?4)");
			if (st != NULL) {
				sqlite3_bind_int64(st, 1, network_id);
				CsBindStr(st, 2, g->Name);
				CsBindUni(st, 3, g->RealName);
				CsBindUni(st, 4, g->Note);
			}

			ret = CsRun(s, st);
		}
	}
	Unlock(s->Lock);

	return ret;
}

// The group name of the network network in g; false when there is none
bool CsGetGroup(CONFIG_STORE *s, char *network, char *name, CS_GROUP *g) {
	bool ret = false;

	if (g != NULL)
		Zero(g, sizeof(CS_GROUP));

	if (s == NULL || g == NULL)
		return false;

	Lock(s->Lock);
	{
		sqlite3_stmt *st = CsPrepare(s, "SELECT n.name, g.name, g.real_name, g.note FROM user_groups g JOIN networks n ON n.id = g.network_id WHERE n.name = ?1 AND g.name = ?2");
		if (st != NULL) {
			CsBindStr(st, 1, network);
			CsBindStr(st, 2, name);

			if (sqlite3_step(st) == SQLITE_ROW) {
				CsColumnStr(st, 0, g->Network, sizeof(g->Network));
				CsColumnStr(st, 1, g->Name, sizeof(g->Name));
				CsColumnUni(st, 2, g->RealName, sizeof(g->RealName));
				CsColumnUni(st, 3, g->Note, sizeof(g->Note));
				ret = true;
			}

			sqlite3_finalize(st);
		}
	}
	Unlock(s->Lock);

	return ret;
}

// Set the VLAN of the user or the group name (kind: CS_VLAN_USER or CS_VLAN_GROUP) of the network network: 1 to 4094,
// or 0 for none. A user's own VLAN, 0 included, wins over its group's. ERR_HUB_NOT_FOUND when there is no such network.
UINT CsSetVlan(CONFIG_STORE *s, char *network, UINT kind, char *name, UINT vlan) {
	UINT ret = ERR_INTERNAL_ERROR;
	char *kind_name = CsName(cs_vlan_kind_names, CS_NUM(cs_vlan_kind_names), kind);
	if (s == NULL || kind_name == NULL || IsEmptyStr(name) || StrLen(name) > MAX_USERNAME_LEN || vlan > 4094)
		return ERR_INVALID_PARAMETER;

	Lock(s->Lock);
	{
		INT64 network_id = CsNetworkId(s, network);

		if (network_id == 0) {
			ret = ERR_HUB_NOT_FOUND;
		} else {
			sqlite3_stmt *st = CsPrepare(s, "INSERT OR REPLACE INTO vlans (network_id, kind, name, vlan) VALUES (?1, ?2, ?3, ?4)");
			if (st != NULL) {
				sqlite3_bind_int64(st, 1, network_id);
				CsBindStr(st, 2, kind_name);
				CsBindStr(st, 3, name);
				sqlite3_bind_int(st, 4, (int)vlan);
			}

			ret = CsRun(s, st);
		}
	}
	Unlock(s->Lock);

	return ret;
}

// Set the VLAN settings of the network network: the TPID of its tags (0x0600 to 0xFFFF) and its untagged VLAN, the
// native VLAN of the trunk port of a member without a VLAN (1 to 4094). A network without them has CS_TPID_8021Q and
// CS_UNTAGGED_VLAN.
UINT CsSetNetworkVlans(CONFIG_STORE *s, char *network, UINT tpid, UINT untagged) {
	UINT ret = ERR_INTERNAL_ERROR;
	if (s == NULL || tpid < 0x0600 || tpid > 0xFFFF || untagged == 0 || untagged > 4094)
		return ERR_INVALID_PARAMETER;

	Lock(s->Lock);
	{
		INT64 network_id = CsNetworkId(s, network);

		if (network_id == 0) {
			ret = ERR_HUB_NOT_FOUND;
		} else {
			sqlite3_stmt *st = CsPrepare(s, "INSERT OR REPLACE INTO network_vlans (network_id, tpid, untagged) VALUES (?1, ?2, ?3)");
			if (st != NULL) {
				sqlite3_bind_int64(st, 1, network_id);
				sqlite3_bind_int(st, 2, (int)tpid);
				sqlite3_bind_int(st, 3, (int)untagged);
			}

			ret = CsRun(s, st);
		}
	}
	Unlock(s->Lock);

	return ret;
}

// The port of the member of the user user in the L2 network network on the switch of the new core, with the TPID of the
// network: an access port of the user's VLAN, its own or else its group's, or, for a user without one, a trunk port of
// every VLAN whose native VLAN is the untagged VLAN of the network, as a session of the fork without a VLAN gets the
// frames of every VLAN tagged and its own untagged. False when there is no such network.
bool CsGetPort(CONFIG_STORE *s, char *network, char *user, CS_PORT *p) {
	bool ret = false;

	if (p != NULL)
		Zero(p, sizeof(CS_PORT));

	if (s == NULL || p == NULL)
		return false;

	Lock(s->Lock);
	{
		sqlite3_stmt *st = CsPrepare(s, "SELECT COALESCE((SELECT v.vlan FROM vlans v WHERE v.network_id = n.id AND v.kind = 'user' AND v.name = ?2), "
		                                "(SELECT v.vlan FROM vlans v JOIN users u ON u.network_id = n.id AND v.name = u.group_name WHERE v.network_id = n.id AND v.kind = 'group' AND u.name = ?2), 0), "
		                                "IFNULL(t.tpid, ?3), IFNULL(t.untagged, ?4) FROM networks n LEFT JOIN network_vlans t ON t.network_id = n.id WHERE n.name = ?1");
		if (st != NULL) {
			CsBindStr(st, 1, network);
			CsBindStr(st, 2, user);
			sqlite3_bind_int(st, 3, CS_TPID_8021Q);
			sqlite3_bind_int(st, 4, CS_UNTAGGED_VLAN);

			if (sqlite3_step(st) == SQLITE_ROW) {
				UINT vlan = (UINT)sqlite3_column_int(st, 0);

				p->Mode = (vlan != 0 ? CS_PORT_ACCESS : CS_PORT_TRUNK);
				p->Vlan = (vlan != 0 ? vlan : (UINT)sqlite3_column_int(st, 2));
				p->Tpid = (UINT)sqlite3_column_int(st, 1);
				ret = true;
			}

			sqlite3_finalize(st);
		}
	}
	Unlock(s->Lock);

	return ret;
}

// Add a value to a list (CS_KEY_*) of the rule r: false when the rule has CS_MAX_VALUES values, or the value is empty or
// longer than CS_MAX_VALUE_LEN
bool CsAddRuleValue(CS_RULE *r, UINT key, char *value) {
	if (r == NULL || key >= CS_NUM_KEYS || IsEmptyStr(value) || StrLen(value) > CS_MAX_VALUE_LEN || r->NumValues >= CS_MAX_VALUES)
		return false;

	r->Values[r->NumValues].Key = key;
	StrCpy(r->Values[r->NumValues].Value, sizeof(r->Values[r->NumValues].Value), value);
	r->NumValues++;

	return true;
}

// The array name of the object o, made when it has none; NULL when there is no memory
static cJSON *CsJsonArray(cJSON *o, char *name) {
	cJSON *a = cJSON_GetObjectItemCaseSensitive(o, name);

	return (a != NULL ? a : cJSON_AddArrayToObject(o, name));
}

// The object name of the object o, made when it has none; NULL when there is no memory
static cJSON *CsJsonObject(cJSON *o, char *name) {
	cJSON *a = cJSON_GetObjectItemCaseSensitive(o, name);

	return (a != NULL ? a : cJSON_AddObjectToObject(o, name));
}

// The value v of a rule into the object of the rule o: a list of the rule, or of one of its ends, which is an object of
// its own. A VLAN is a number, every other value a string. False when there is no memory.
static bool CsJsonValue(cJSON *o, CS_RULE_VALUE *v) {
	char key[MAX_SIZE];
	char *list = key;
	cJSON *item = (v->Key == CS_KEY_VLANS ? cJSON_CreateNumber(ToInt(v->Value)) : cJSON_CreateString(v->Value));
	if (item == NULL)
		return false;

	StrCpy(key, sizeof(key), cs_list_names[v->Key]);

	// An end and its list, as from.users
	char *dot = strchr(key, '.');
	if (dot != NULL) {
		*dot = 0;
		list = dot + 1;
		o = CsJsonObject(o, key);
	}

	cJSON *array = (o != NULL ? CsJsonArray(o, list) : NULL);
	if (array == NULL || cJSON_AddItemToArray(array, item) == false) {
		cJSON_Delete(item);
		return false;
	}

	return true;
}

// The rule r as an object of the policy engine's document (Core/PolicyRules.c), of the network network in that document,
// or of every network for NULL; NULL when there is no memory
static cJSON *CsRuleJson(CS_RULE *r, char *network) {
	static const UINT protocols[] = {CS_PROTO_ANY, CS_PROTO_IP, CS_PROTO_ICMP, CS_PROTO_TCP, CS_PROTO_UDP};
	static char *protocol_names[] = {"any", "ip", "icmp", "tcp", "udp"};
	cJSON *o = cJSON_CreateObject();
	char *protocol = NULL;

	bool ok = (o != NULL && cJSON_AddStringToObject(o, "name", r->Name) != NULL &&
	           cJSON_AddStringToObject(o, "action", cs_action_names[r->Action == CS_DENY ? CS_DENY : CS_ALLOW]) != NULL &&
	           cJSON_AddNumberToObject(o, "priority", r->Priority) != NULL);

	if (ok && network != NULL) {
		cJSON *nets = CsJsonArray(o, "networks");
		cJSON *net = cJSON_CreateString(network);

		ok = (nets != NULL && net != NULL && cJSON_AddItemToArray(nets, net));
		if (ok == false)
			cJSON_Delete(net);
	}

	for (UINT i = 0; i < CS_NUM(protocols); i++)
		if (protocols[i] == r->Protocol)
			protocol = protocol_names[i];

	if (ok)
		ok = (protocol != NULL ? cJSON_AddStringToObject(o, "protocol", protocol) : cJSON_AddNumberToObject(o, "protocol", r->Protocol)) != NULL;

	for (UINT i = 0; ok && i < r->NumValues && i < CS_MAX_VALUES; i++)
		ok = (r->Values[i].Key < CS_NUM_KEYS && CsJsonValue(o, &r->Values[i]));

	if (ok && r->Both)
		ok = (cJSON_AddStringToObject(o, "direction", "both") != NULL);

	if (ok == false) {
		cJSON_Delete(o);
		return NULL;
	}

	return o;
}

// The text of a JSON item in the memory of Mayaqua; NULL when there is no memory. The item is not freed.
static char *CsJsonText(cJSON *item) {
	char *json = cJSON_PrintUnformatted(item);
	char *ret = (json != NULL ? CopyStr(json) : NULL);

	cJSON_free(json);

	return ret;
}

// Whether the policy engine takes the rule r in a document of its own (PolicyParseRules): the rule a store keeps is one
// that a document of the store can hold
static bool CsRuleOk(CS_RULE *r) {
	char error[MAX_SIZE];
	bool ok = false;
	cJSON *doc = cJSON_CreateObject();
	cJSON *nets = (doc != NULL ? cJSON_AddArrayToObject(doc, "networks") : NULL);
	cJSON *rules = (doc != NULL ? cJSON_AddArrayToObject(doc, "rules") : NULL);
	cJSON *net = cJSON_CreateObject();
	cJSON *rule = CsRuleJson(r, NULL);

	// The arrays own what they hold; what none holds is freed here
	bool net_in = (nets != NULL && net != NULL && cJSON_AddStringToObject(net, "name", "n") != NULL && cJSON_AddItemToArray(nets, net));
	if (net_in == false)
		cJSON_Delete(net);

	bool rule_in = (rules != NULL && rule != NULL && cJSON_AddItemToArray(rules, rule));
	if (rule_in == false)
		cJSON_Delete(rule);

	if (net_in && rule_in) {
		char *json = CsJsonText(doc);

		if (json != NULL) {
			ok = PolicyParseRules(json, StrLen(json), error, sizeof(error));
			if (ok == false)
				Debug("ConfigStore: rule %s: %s\n", r->Name, error);
		}

		Free(json);
	}

	cJSON_Delete(doc);

	return ok;
}

// Insert the rule r into the network network_id, after the rules of the network, with its values. The caller holds the
// lock, inside a savepoint.
static UINT CsInsertRule(CONFIG_STORE *s, INT64 network_id, CS_RULE *r) {
	sqlite3_stmt *st = CsPrepare(s, "INSERT INTO rules (network_id, name, position, priority, action, protocol, direction, active, note) "
	                                "VALUES (?1, ?2, (SELECT IFNULL(MAX(position), 0) + 1 FROM rules WHERE network_id = ?1), ?3, ?4, ?5, ?6, ?7, ?8)");
	if (st != NULL) {
		sqlite3_bind_int64(st, 1, network_id);
		CsBindStr(st, 2, r->Name);
		sqlite3_bind_int(st, 3, (int)r->Priority);
		CsBindStr(st, 4, cs_action_names[r->Action]);
		sqlite3_bind_int(st, 5, (int)r->Protocol);
		CsBindStr(st, 6, r->Both ? "both" : "forward");
		sqlite3_bind_int(st, 7, r->Active ? 1 : 0);
		CsBindUni(st, 8, r->Note);
	}

	UINT ret = CsRun(s, st);
	INT64 rule_id = sqlite3_last_insert_rowid(s->Db);

	for (UINT i = 0; ret == ERR_NO_ERROR && i < r->NumValues; i++) {
		st = CsPrepare(s, "INSERT INTO rule_values (rule_id, list, value) VALUES (?1, ?2, ?3)");
		if (st != NULL) {
			sqlite3_bind_int64(st, 1, rule_id);
			CsBindStr(st, 2, cs_list_names[r->Values[i].Key]);
			CsBindStr(st, 3, r->Values[i].Value);
		}

		ret = CsRun(s, st);
	}

	return ret;
}

// Add the rule r to the network r->Network, after its rules: ERR_INVALID_PARAMETER for a rule that the policy engine
// does not take, ERR_HUB_NOT_FOUND when there is no such network, ERR_OBJECT_EXISTS when the store has a rule of that
// name. The rule and its values are added together or not at all.
UINT CsAddRule(CONFIG_STORE *s, CS_RULE *r) {
	UINT ret = ERR_INTERNAL_ERROR;
	if (s == NULL || r == NULL || CsIsEngineName(r->Name, CS_MAX_RULE_NAME) == false || r->Action > CS_DENY || r->Priority > CS_MAX_PRIORITY ||
	    r->Protocol > CS_PROTO_ICMP || r->NumValues > CS_MAX_VALUES)
		return ERR_INVALID_PARAMETER;

	for (UINT i = 0; i < r->NumValues; i++)
		if (r->Values[i].Key >= CS_NUM_KEYS)
			return ERR_INVALID_PARAMETER;

	if (CsRuleOk(r) == false)
		return ERR_INVALID_PARAMETER;

	Lock(s->Lock);
	{
		INT64 network_id = CsNetworkId(s, r->Network);

		if (network_id == 0) {
			ret = ERR_HUB_NOT_FOUND;
		} else if (CsExec(s, "SAVEPOINT cs_rule")) {
			ret = CsInsertRule(s, network_id, r);

			if (ret != ERR_NO_ERROR)
				CsExec(s, "ROLLBACK TO cs_rule");

			if (CsExec(s, "RELEASE cs_rule") == false)
				ret = ERR_INTERNAL_ERROR;
		}
	}
	Unlock(s->Lock);

	return ret;
}

// The name of the network network in a document of the policy engine into name: its own name when it is a name of the
// engine of at most CS_POLICY_NAME_LEN bytes, which leaves room for the names of its rules after it, else network-<id>,
// so that every network has a name of its own there. The caller may hold the lock. False when there is no such network.
bool CsPolicyNetworkName(CONFIG_STORE *s, char *network, char *name, UINT size) {
	char stored[MAX_HUBNAME_LEN + 1];
	bool ret = false;

	if (name != NULL)
		StrCpy(name, size, "");

	if (s == NULL || name == NULL)
		return false;

	Lock(s->Lock);
	{
		sqlite3_stmt *st = CsPrepare(s, "SELECT id, name FROM networks WHERE name = ?1");
		if (st != NULL) {
			CsBindStr(st, 1, network);

			if (sqlite3_step(st) == SQLITE_ROW) {
				CsColumnStr(st, 1, stored, sizeof(stored));

				if (CsIsEngineName(stored, CS_POLICY_NAME_LEN))
					StrCpy(name, size, stored);
				else
					Format(name, size, "network-%I64d", (INT64)sqlite3_column_int64(st, 0));

				ret = true;
			}

			sqlite3_finalize(st);
		}
	}
	Unlock(s->Lock);

	return ret;
}

// Read the rule of the row of a statement with the columns id, name, priority, action, protocol, direction and active
// into r, with its values; its id. The caller holds the lock.
static INT64 CsReadRule(CONFIG_STORE *s, sqlite3_stmt *st, CS_RULE *r) {
	char tmp[MAX_SIZE];

	Zero(r, sizeof(CS_RULE));

	INT64 id = sqlite3_column_int64(st, 0);
	CsColumnStr(st, 1, r->Name, sizeof(r->Name));
	r->Priority = (UINT)sqlite3_column_int(st, 2);
	CsColumnStr(st, 3, tmp, sizeof(tmp));
	r->Action = (StrCmp(tmp, "deny") == 0 ? CS_DENY : CS_ALLOW);
	r->Protocol = (UINT)sqlite3_column_int(st, 4);
	CsColumnStr(st, 5, tmp, sizeof(tmp));
	r->Both = (StrCmp(tmp, "both") == 0);
	r->Active = (sqlite3_column_int(st, 6) != 0);

	sqlite3_stmt *vs = CsPrepare(s, "SELECT list, value FROM rule_values WHERE rule_id = ?1 ORDER BY id");
	if (vs != NULL) {
		sqlite3_bind_int64(vs, 1, id);

		while (sqlite3_step(vs) == SQLITE_ROW && r->NumValues < CS_MAX_VALUES) {
			CS_RULE_VALUE *v = &r->Values[r->NumValues];

			CsColumnStr(vs, 0, tmp, sizeof(tmp));
			v->Key = CsValue(cs_list_names, CS_NUM(cs_list_names), tmp);
			CsColumnStr(vs, 1, v->Value, sizeof(v->Value));

			if (v->Key < CS_NUM_KEYS)
				r->NumValues++;
		}

		sqlite3_finalize(vs);
	}

	return id;
}

// The document of rules of the policy engine (Core/PolicyRules.c) that the store holds: each network as a network of
// the engine, by the name that CsPolicyNetworkName gives it and of its mode, and the active rules of each in the order of
// their positions, which the engine orders by priority. Nothing in it sets a default action: it is deny for every
// network (ADR-0019 amendment of 2026-10-21). NULL when there is no memory or the store fails; free it with Free.
char *CsPolicyDocument(CONFIG_STORE *s) {
	char name[MAX_SIZE];
	char mode[MAX_SIZE];
	CS_RULE r;
	bool ok = false;
	char *ret = NULL;
	if (s == NULL)
		return NULL;

	cJSON *doc = cJSON_CreateObject();
	cJSON *nets = (doc != NULL ? cJSON_AddArrayToObject(doc, "networks") : NULL);
	cJSON *rules = (doc != NULL ? cJSON_AddArrayToObject(doc, "rules") : NULL);

	Lock(s->Lock);
	{
		sqlite3_stmt *st = CsPrepare(s, "SELECT name, mode FROM networks ORDER BY id");
		ok = (st != NULL && nets != NULL && rules != NULL);

		while (ok && sqlite3_step(st) == SQLITE_ROW) {
			char network[MAX_HUBNAME_LEN + 1];
			cJSON *net = cJSON_CreateObject();

			CsColumnStr(st, 0, network, sizeof(network));
			CsColumnStr(st, 1, mode, sizeof(mode));

			ok = (net != NULL && cJSON_AddItemToArray(nets, net));
			if (ok == false)
				cJSON_Delete(net);

			ok = ok && CsPolicyNetworkName(s, network, name, sizeof(name)) && cJSON_AddStringToObject(net, "name", name) != NULL &&
			     cJSON_AddStringToObject(net, "mode", mode) != NULL;
		}

		sqlite3_finalize(st);

		st = (ok ? CsPrepare(s, "SELECT r.id, r.name, r.priority, r.action, r.protocol, r.direction, r.active, n.name FROM rules r JOIN networks n ON n.id = r.network_id WHERE r.active = 1 ORDER BY n.id, r.position, r.id") : NULL);
		ok = (ok && st != NULL);

		while (ok && sqlite3_step(st) == SQLITE_ROW) {
			char network[MAX_HUBNAME_LEN + 1];

			CsReadRule(s, st, &r);
			CsColumnStr(st, 7, network, sizeof(network));

			cJSON *rule = (CsPolicyNetworkName(s, network, name, sizeof(name)) ? CsRuleJson(&r, name) : NULL);
			ok = (rule != NULL && cJSON_AddItemToArray(rules, rule));
			if (ok == false)
				cJSON_Delete(rule);
		}

		sqlite3_finalize(st);
	}
	Unlock(s->Lock);

	if (ok)
		ret = CsJsonText(doc);

	cJSON_Delete(doc);

	return ret;
}

// Write str in double quotes: a backslash before a quote or a backslash, \xNN for a control character
static void CsDumpQuoted(BUF *b, const char *str) {
	char tmp[8];

	WriteBuf(b, "\"", 1);

	for (UINT i = 0; str != NULL && str[i] != 0; i++) {
		UCHAR c = (UCHAR)str[i];

		if (c == '"' || c == '\\') {
			tmp[0] = '\\';
			tmp[1] = (char)c;
			WriteBuf(b, tmp, 2);
		} else if (c < 0x20 || c == 0x7F) {
			Format(tmp, sizeof(tmp), "\\x%02X", c);
			WriteBuf(b, tmp, StrLen(tmp));
		} else {
			WriteBuf(b, &c, 1);
		}
	}

	WriteBuf(b, "\"", 1);
}

// Write one line per row of the query sql: the word kind, then column=value for each column. Text is quoted, an
// integer printed in decimal, a blob in upper-case hex and NULL as none. The caller holds the lock.
static void CsDumpRows(CONFIG_STORE *s, BUF *b, char *kind, char *sql) {
	char tmp[MAX_SIZE];

	sqlite3_stmt *st = CsPrepare(s, sql);

	while (st != NULL && sqlite3_step(st) == SQLITE_ROW) {
		WriteBuf(b, kind, StrLen(kind));

		for (int i = 0; i < sqlite3_column_count(st); i++) {
			const char *column = sqlite3_column_name(st, i);

			WriteBuf(b, " ", 1);
			WriteBuf(b, column, StrLen(column));
			WriteBuf(b, "=", 1);

			switch (sqlite3_column_type(st, i)) {
			case SQLITE_INTEGER:
				Format(tmp, sizeof(tmp), "%I64d", (INT64)sqlite3_column_int64(st, i));
				WriteBuf(b, tmp, StrLen(tmp));
				break;

			case SQLITE_TEXT:
				CsDumpQuoted(b, (const char *)sqlite3_column_text(st, i));
				break;

			case SQLITE_BLOB: {
				UINT size = (UINT)sqlite3_column_bytes(st, i);
				char *hex = ZeroMalloc(size * 2 + 1);

				BinToStr(hex, size * 2 + 1, sqlite3_column_blob(st, i), size);
				WriteBuf(b, hex, StrLen(hex));
				Free(hex);
				break;
			}

			default:
				WriteBuf(b, "none", 4);
				break;
			}
		}

		WriteBuf(b, "\n", 1);
	}

	sqlite3_finalize(st);
}

// A text dump of the whole store, one line per row in a fixed order, for the harness goldens and for support. A
// password shows only as set or unset (never its hash or salt) and a certificate by its subject and thumbprint; the
// policy of the networks follows, a rule with its protocol by name and each of its values on a line of its own.
BUF *CsDump(CONFIG_STORE *s) {
	char tmp[MAX_SIZE];
	BUF *b = NewBuf();
	if (s == NULL)
		return b;

	Lock(s->Lock);
	{
		Format(tmp, sizeof(tmp), "schema %I64d\n", CsQueryInt(s, "PRAGMA user_version", -1));
		WriteBuf(b, tmp, StrLen(tmp));

		CsDumpRows(s, b, "setting", "SELECT name, value FROM settings ORDER BY name");
		CsDumpRows(s, b, "network", "SELECT name, mode, online FROM networks ORDER BY name");
		CsDumpRows(s, b, "user", "SELECT n.name AS network, u.name AS name, u.auth AS auth, u.group_name AS 'group', u.real_name AS real_name, u.note AS note, u.auth_name AS auth_name, u.auth_serial AS auth_serial, u.expire_time AS expire_time, CASE WHEN u.password_hash IS NULL THEN 'unset' ELSE 'set' END AS password, u.pinned_key AS pinned_key FROM users u JOIN networks n ON n.id = u.network_id ORDER BY n.name, u.name");
		CsDumpRows(s, b, "listener", "SELECT transport, port, enabled FROM listeners ORDER BY transport, port");
		CsDumpRows(s, b, "certificate", "SELECT c.usage AS usage, n.name AS network, u.name AS user, c.subject AS subject, c.thumbprint AS thumbprint FROM certificates c LEFT JOIN networks n ON n.id = c.network_id LEFT JOIN users u ON u.id = c.user_id ORDER BY c.usage, n.name, u.name, c.thumbprint");
		CsDumpRows(s, b, "admin", "SELECT a.name AS name, a.role AS role, n.name AS network, CASE WHEN a.password_hash IS NULL THEN 'unset' ELSE 'set' END AS password FROM admins a LEFT JOIN networks n ON n.id = a.network_id ORDER BY a.name");
		CsDumpRows(s, b, "group", "SELECT n.name AS network, g.name AS name, g.real_name AS real_name, g.note AS note FROM user_groups g JOIN networks n ON n.id = g.network_id ORDER BY n.name, g.name");
		CsDumpRows(s, b, "vlan", "SELECT n.name AS network, v.kind AS kind, v.name AS name, v.vlan AS vlan FROM vlans v JOIN networks n ON n.id = v.network_id ORDER BY n.name, v.kind, v.name");
		CsDumpRows(s, b, "network_vlans", "SELECT n.name AS network, printf('0x%04X', t.tpid) AS tpid, t.untagged AS untagged FROM network_vlans t JOIN networks n ON n.id = t.network_id ORDER BY n.name");
		CsDumpRows(s, b, "rule", "SELECT n.name AS network, r.position AS position, r.name AS name, r.priority AS priority, r.action AS action, "
		                         "CASE r.protocol WHEN 256 THEN 'any' WHEN 257 THEN 'ip' WHEN 258 THEN 'icmp' WHEN 6 THEN 'tcp' WHEN 17 THEN 'udp' ELSE r.protocol END AS protocol, "
		                         "r.direction AS direction, r.active AS active, r.note AS note FROM rules r JOIN networks n ON n.id = r.network_id ORDER BY n.name, r.position");
		CsDumpRows(s, b, "rule_value", "SELECT r.name AS rule, v.list AS list, v.value AS value FROM rule_values v JOIN rules r ON r.id = v.rule_id JOIN networks n ON n.id = r.network_id ORDER BY n.name, r.position, v.id");
	}
	Unlock(s->Lock);

	SeekBufToBegin(b);

	return b;
}
