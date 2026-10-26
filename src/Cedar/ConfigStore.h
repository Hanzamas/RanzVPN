// ConfigStore.h
// Header of the ConfigStore module (ConfigStore.c, ConfigStoreImport.c): the configuration store of the new core

#ifndef CONFIGSTORE_H
#define CONFIGSTORE_H

#include "Cedar.h"
#include "CedarType.h"

#include "Mayaqua/MayaType.h"

// The file of the configuration store in the data directory of a node: a SQLite database that the inbox
// winsqlite3.dll of System32 reads and writes (ADR-0022, Configuration store)
#define CS_FILE_NAME L"ranz_node.db"

// The schema of a new store (PRAGMA user_version). A store of a newer schema is refused, never changed.
#define CS_SCHEMA_VERSION 1

// The setting that records the import of a fork configuration: the name of the file imported
#define CS_SETTING_IMPORTED "ImportedFrom"

#define CS_BUSY_TIMEOUT      5000   // How long a statement waits for a write lock of another connection (ms)
#define CS_PBKDF2_ITERATIONS 600000 // HMAC-SHA256 iterations of a new password hash (PBKDF2, ADR-0022 2026-10-19)
#define CS_SALT_SIZE         16     // Bytes of the random salt of a password hash
#define CS_HASH_SIZE         32     // Bytes of a password hash
#define CS_KEY_SIZE          32     // Bytes of a pinned key: the X25519 public key of a Noise static key
#define CS_MAX_SERIAL_SIZE   64     // Bytes of a certificate serial number at most

// The mode of a network (ADR-0014): an L2 switched network (a Hub) or an L3 routed one
#define CS_MODE_L2 0
#define CS_MODE_L3 1

// The transport of a listener (ADR-0005)
#define CS_TRANSPORT_QUIC 0 // QUIC over UDP (msquic)
#define CS_TRANSPORT_TLS  1 // TLS 1.3 over TCP (Schannel)

// What a certificate is for
#define CS_CERT_SERVER 0 // The certificate of the listeners; its key is in a CNG KSP, never in the store
#define CS_CERT_CHAIN  1 // An intermediate certificate sent after the server certificate
#define CS_CERT_CA     2 // A CA whose certificates a network accepts for root-cert users
#define CS_CERT_USER   3 // The certificate of a user-cert user

// The role of a named admin account (ADR-0021 point 5)
#define CS_ROLE_OWNER     0 // Everything
#define CS_ROLE_HUB_ADMIN 1 // One network
#define CS_ROLE_READ_ONLY 2 // Reads everything, changes nothing

// What CsPinUserKey found (trust on first use, ADR-0022 Enrollment)
#define CS_KEY_PINNED   0 // The user had no key: this one is pinned now
#define CS_KEY_MATCH    1 // The key is the pinned one
#define CS_KEY_MISMATCH 2 // The user has another pinned key
#define CS_KEY_ERROR    3 // The store failed to begin, read, write or commit: no key is checked or pinned
#define CS_KEY_NO_USER  4 // The store keeps no such user (a domain account): no key is pinned

// The configuration store of a node: one connection to the database. Each call runs its statements under
// Lock; other connections to the same file (CsOpen again) read while one writes (write-ahead log).
struct CONFIG_STORE {
	LOCK *Lock;             // One call at a time on the connection
	struct sqlite3 *Db;     // The connection
	wchar_t Path[MAX_PATH]; // The database file
};

// A network: a Hub of the server role for CS_MODE_L2
struct CS_NETWORK {
	char Name[MAX_HUBNAME_LEN + 1]; // The name, unique without case
	UINT Mode;                      // CS_MODE_*
	bool Online;                    // Whether the server role runs it online
};

// A user of a network
struct CS_USER {
	char Network[MAX_HUBNAME_LEN + 1];    // The network of the user
	char Name[MAX_USERNAME_LEN + 1];      // The name, unique in the network without case
	wchar_t RealName[MAX_SIZE];           // The real name
	wchar_t Note[MAX_SIZE];               // The note
	char Group[MAX_USERNAME_LEN + 1];     // The group, empty for none; groups come with the policy engine (CORE-S4)
	UINT AuthType;                        // AUTHTYPE_*: how the user logs in
	wchar_t AuthName[MAX_SIZE];           // AUTHTYPE_NT: the Windows user name; AUTHTYPE_ROOTCERT: the common name
	UCHAR AuthSerial[CS_MAX_SERIAL_SIZE]; // AUTHTYPE_ROOTCERT: the serial number the certificate must have
	UINT AuthSerialSize;                  // Bytes of AuthSerial, 0 for any serial number
	UINT64 ExpireTime;                    // When the user expires (SystemTime64), 0 for never
	bool HasPassword;                     // Whether a password hash is set (CsGetUser)
	bool HasKey;                          // Whether a key is pinned (CsGetUser)
};

// A named admin account
struct CS_ADMIN {
	char Name[MAX_USERNAME_LEN + 1];   // The name, unique without case
	UINT Role;                         // CS_ROLE_*
	char Network[MAX_HUBNAME_LEN + 1]; // CS_ROLE_HUB_ADMIN: the network it administers; empty for the other roles
	bool HasPassword;                  // Whether a password hash is set
};

// What CsImportForkConfig carried from the fork's ranz_server.config into the store, and what it left out
struct CS_IMPORT {
	UINT NumNetworks;         // Hubs, as L2 networks
	UINT NumUsers;            // Users of the hubs
	UINT NumListeners;        // TCP listeners, as TLS listeners
	UINT NumCerts;            // The server certificate, its chain, the CAs of the hubs and the user certificates
	UINT NumAdmins;           // The server administrator (owner) and the hub administrators (hub-admin)
	UINT NumSkipped;          // Hubs, users, listeners and certificates that were not valid, or not unique
	UINT NumPasswordsDropped; // SHA-0 password hashes left out (ADR-0022 2026-10-19): those users and admins need a new password
	bool ServerKeyDropped;    // The server key was left out: it belongs in a CNG KSP, not in the store
};

// ConfigStore.c
CONFIG_STORE *CsOpen(wchar_t *path);
void CsClose(CONFIG_STORE *s);
char *CsLibVersion();
bool CsIsEmpty(CONFIG_STORE *s);
bool CsGetSetting(CONFIG_STORE *s, char *name, char *value, UINT size);
UINT CsSetSetting(CONFIG_STORE *s, char *name, char *value);
UINT CsAddNetwork(CONFIG_STORE *s, char *name, UINT mode, bool online);
UINT CsDeleteNetwork(CONFIG_STORE *s, char *name);
LIST *CsEnumNetworks(CONFIG_STORE *s);
void CsFreeNetworkList(LIST *o);
UINT CsAddUser(CONFIG_STORE *s, CS_USER *u);
bool CsGetUser(CONFIG_STORE *s, char *network, char *name, CS_USER *u);
UINT CsSetUserPassword(CONFIG_STORE *s, char *network, char *name, char *password);
bool CsCheckUserPassword(CONFIG_STORE *s, char *network, char *name, char *password);
UINT CsPinUserKey(CONFIG_STORE *s, char *network, char *name, UCHAR *key);
UINT CsUnpinUserKey(CONFIG_STORE *s, char *network, char *name);
UINT CsAddListener(CONFIG_STORE *s, UINT transport, UINT port, bool enabled);
UINT CsAddCert(CONFIG_STORE *s, UINT usage, char *network, char *user, void *der, UINT der_size);
UINT CsAddAdmin(CONFIG_STORE *s, char *name, UINT role, char *network, char *password);
bool CsGetAdmin(CONFIG_STORE *s, char *name, CS_ADMIN *a);
UINT CsSetAdminPassword(CONFIG_STORE *s, char *name, char *password);
bool CsCheckAdminPassword(CONFIG_STORE *s, char *name, char *password, CS_ADMIN *a);
BUF *CsDump(CONFIG_STORE *s);
bool CsPbkdf2(void *dst, UINT dst_size, char *password, void *salt, UINT salt_size, UINT iterations);

// ConfigStoreImport.c
UINT CsImportForkConfig(CONFIG_STORE *s, wchar_t *path, CS_IMPORT *ret);

#endif // CONFIGSTORE_H
