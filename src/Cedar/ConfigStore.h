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

// The schema of a new store (PRAGMA user_version). A store of a newer schema is refused, never changed; a store of an
// older one gets the tables of the versions after its own when it is opened. Version 2 adds the policy of the networks.
#define CS_SCHEMA_VERSION 2

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

// The policy of the networks (schema 2; CORE-S4-3, #76): the groups, the VLAN of users and groups, the VLAN settings of
// each network and the rules of the policy engine of the new core (Core/Policy.h), which CsPolicyDocument writes as the
// engine's document of rules. A rule is one of that document: the default action of every network is deny (ADR-0019
// amendment of 2026-10-21), so what a network lets through is what its allow rules let through.
#define CS_MAX_RULE_NAME   63      // Bytes of the name of a rule at most, as of a name of the policy engine
#define CS_MAX_VALUES      16      // Values of the lists of a rule (CS_RULE) at most
#define CS_MAX_VALUE_LEN   63      // Bytes of a value at most: a name, an address with its prefix length, a port range, a VLAN
#define CS_POLICY_NAME_LEN 48      // Bytes of a network name that the document of the policy engine keeps at most (CsPolicyNetworkName)
#define CS_MAX_PRIORITY    1000000 // The lowest priority of a rule
#define CS_TPID_8021Q      0x8100  // The TPID of a network that sets none
#define CS_UNTAGGED_VLAN   1       // The untagged VLAN of a network that sets none

// The action of a rule
#define CS_ALLOW 0
#define CS_DENY  1

// The protocol of a rule besides the IP protocol numbers 0 to 255, as the policy engine names them
#define CS_PROTO_TCP  6   // TCP
#define CS_PROTO_UDP  17  // UDP
#define CS_PROTO_ANY  256 // Any frame
#define CS_PROTO_IP   257 // Any IP packet
#define CS_PROTO_ICMP 258 // ICMP of the family of the packet: ICMP for IPv4, ICMPv6 for IPv6

// The lists of a rule (CS_RULE_VALUE): the keys of a rule of the policy engine's document, and the lists of its two ends
#define CS_KEY_FROM_USERS     0 // The users of the end that sends the first frame of a flow
#define CS_KEY_FROM_GROUPS    1 // ... its groups
#define CS_KEY_FROM_TAGS      2 // ... the tags of its node
#define CS_KEY_FROM_ADDRESSES 3 // ... its addresses: an IPv4 or IPv6 address, with /length for a prefix
#define CS_KEY_TO_USERS       4 // The users of the end that the first frame goes to
#define CS_KEY_TO_GROUPS      5 // ... its groups
#define CS_KEY_TO_TAGS        6 // ... the tags of its node
#define CS_KEY_TO_ADDRESSES   7 // ... its addresses
#define CS_KEY_PORTS          8 // The destination ports, of a rule of TCP or UDP: a port or "low-high"
#define CS_KEY_VLANS          9 // The VLANs of the frames, 1 to 4094
#define CS_NUM_KEYS           10

// Whose VLAN a VLAN row is (CsSetVlan)
#define CS_VLAN_USER  0 // A user's own: it wins over the VLAN of the user's group, as the fork's policy of a user does
#define CS_VLAN_GROUP 1 // A group's: the VLAN of the users of the group that have none of their own

// The port of a member of an L2 network (CsGetPort), as the switch of the new core has ports (Core/Switch.h)
#define CS_PORT_ACCESS 0 // An access port: one VLAN, untagged towards the member
#define CS_PORT_TRUNK  1 // A trunk port of every VLAN, with the untagged VLAN of the network as its native VLAN

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

// A group of a network: the identity that the rules of the policy engine name for the users of the group
struct CS_GROUP {
	char Network[MAX_HUBNAME_LEN + 1]; // The network of the group
	char Name[MAX_USERNAME_LEN + 1];   // The name, unique in the network without case
	wchar_t RealName[MAX_SIZE];        // The real name
	wchar_t Note[MAX_SIZE];            // The note
};

// One value of a list of a rule
struct CS_RULE_VALUE {
	UINT Key;                         // The list: CS_KEY_*
	char Value[CS_MAX_VALUE_LEN + 1]; // The value, as the document of the policy engine writes it
};

// A rule of the policy of a network: a rule of the policy engine's document (Core/PolicyRules.c), which names its network
struct CS_RULE {
	char Network[MAX_HUBNAME_LEN + 1];   // The network whose table takes the rule
	char Name[CS_MAX_RULE_NAME + 1];     // The name, unique in the store as in a document: letters, digits, '.', '-' and '_'
	UINT Priority;                       // 0 to CS_MAX_PRIORITY, the lowest first; rules of one priority in the order they were added
	UINT Action;                         // CS_ALLOW or CS_DENY
	UINT Protocol;                       // An IP protocol number, or CS_PROTO_*
	bool Both;                           // Direction both: the rule also matches from its to end to its from end
	bool Active;                         // In the document of the policy engine; an inactive rule is kept for the operator
	wchar_t Note[MAX_SIZE];              // Where the rule comes from, and what it leaves out
	UINT NumValues;                      // The values of its lists
	CS_RULE_VALUE Values[CS_MAX_VALUES]; // ...
};

// The port of a member of an L2 network on the switch of the new core (CsGetPort)
struct CS_PORT {
	UINT Mode; // CS_PORT_ACCESS or CS_PORT_TRUNK
	UINT Vlan; // The VLAN of an access port; the native VLAN of a trunk port, which is the untagged VLAN of the network
	UINT Tpid; // The TPID of the network's tags
};

// What CsImportForkConfig carried from the fork's ranz_server.config into the store, and what it left out
struct CS_IMPORT {
	UINT NumNetworks;         // Hubs, as L2 networks
	UINT NumUsers;            // Users of the hubs
	UINT NumListeners;        // TCP listeners, as TLS listeners
	UINT NumCerts;            // The server certificate, its chain, the CAs of the hubs and the user certificates
	UINT NumAdmins;           // The server administrator (owner) and the hub administrators (hub-admin)
	UINT NumSkipped;          // Hubs, users, groups, VLANs, listeners and certificates that were not valid, or not unique
	UINT NumPasswordsDropped; // SHA-0 password hashes left out (ADR-0022 2026-10-19): those users and admins need a new password
	bool ServerKeyDropped;    // The server key was left out: it belongs in a CNG KSP, not in the store
	UINT NumGroups;           // Groups of the hubs
	UINT NumVlans;            // VLANs of users and groups (the VLanId of their policy)
	UINT NumEntries;          // Entries of the access lists, carried as rules of the policy (an entry may make several rules)
	UINT NumEntriesInactive;  // ... carried inactive: inactive in the fork, matching nothing there, or allow entries with a match the engine lacks
	UINT NumEntriesWidened;   // ... deny entries carried without a match that the engine lacks: they deny more than the fork did, never less
	UINT NumEffectsDropped;   // Delays, jitter, losses and redirect URLs of entries left out
	UINT NumOptionsDropped;   // Hub options left out: NoManageVlanId and ApplyIPv4AccessListOnArpPacket where they were set
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
UINT CsAddGroup(CONFIG_STORE *s, CS_GROUP *g);
bool CsGetGroup(CONFIG_STORE *s, char *network, char *name, CS_GROUP *g);
UINT CsSetVlan(CONFIG_STORE *s, char *network, UINT kind, char *name, UINT vlan);
UINT CsSetNetworkVlans(CONFIG_STORE *s, char *network, UINT tpid, UINT untagged);
bool CsGetPort(CONFIG_STORE *s, char *network, char *user, CS_PORT *p);
UINT CsAddRule(CONFIG_STORE *s, CS_RULE *r);
bool CsAddRuleValue(CS_RULE *r, UINT key, char *value);
bool CsPolicyNetworkName(CONFIG_STORE *s, char *network, char *name, UINT size);
char *CsPolicyDocument(CONFIG_STORE *s);

// ConfigStoreImport.c
UINT CsImportForkConfig(CONFIG_STORE *s, wchar_t *path, CS_IMPORT *ret);

#endif // CONFIGSTORE_H
