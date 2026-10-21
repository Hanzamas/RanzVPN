// ConfigStoreImport.c
// The one-time import of the fork's Config file (ranz_server.config) into an empty configuration store (ADR-0022,
// Configuration store). Since the 2026-10-19 amendment there are no deployed configurations, so the import serves
// development and test configurations. It reads the file through Cfg and writes, in one transaction: the hubs as L2
// networks with their CAs and users (user certificates included), the TCP listeners as TLS listeners, the server
// certificate with its chain, and the server and hub administrators as owner and hub-admin accounts. It leaves out
// what the new core does not take: the SHA-0 password hashes (ADR-0022 2026-10-19: those accounts need a new
// password), the server key (it belongs in a CNG KSP), and the groups, policies, access lists and cascades, which
// come with the policy engine (CORE-S4) and the client role (CORE-S3).

#include "ConfigStore.h"

#include "Mayaqua/Cfg.h"
#include "Mayaqua/Encrypt.h"
#include "Mayaqua/FileIO.h"
#include "Mayaqua/Internat.h"
#include "Mayaqua/Memory.h"
#include "Mayaqua/Object.h"
#include "Mayaqua/Str.h"

#include "ConfigStoreInternal.h"

// Count the result of writing one row and tell whether the import goes on: a row that the store refuses (not
// valid, or not unique) is skipped, a failure of the store itself stops the import
static bool CsImportCount(CS_IMPORT *r, UINT err, UINT *num) {
	if (err == ERR_NO_ERROR) {
		(*num)++;
		return true;
	}

	if (err == ERR_INTERNAL_ERROR)
		return false;

	r->NumSkipped++;

	return true;
}

// Whether the administrator password item name of the fork (Sha0 of the password) holds a password: the item is
// there and is not the hash of the empty password, which the fork writes when no password is set
static bool CsImportHasPassword(FOLDER *f, char *name) {
	UCHAR hash[SHA1_SIZE];
	UCHAR empty[SHA1_SIZE];

	if (CfgGetByte(f, name, hash, sizeof(hash)) != sizeof(hash))
		return false;

	Sha0(empty, "", 0);

	return (Cmp(hash, empty, sizeof(hash)) != 0);
}

// The certificate item name of f (DER bytes) for usage
static bool CsImportCert(CONFIG_STORE *s, CS_IMPORT *r, UINT usage, char *network, char *user, FOLDER *f, char *name) {
	BUF *b = CfgGetBuf(f, name);
	if (b == NULL)
		return true;

	bool ret = CsImportCount(r, CsAddCert(s, usage, network, user, b->Buf, b->Size), &r->NumCerts);

	FreeBuf(b);

	return ret;
}

// Each certificate of a certificate list folder (CertList, ServerChain: Cert0, Cert1, ... with an X509 item)
static bool CsImportCertList(CONFIG_STORE *s, CS_IMPORT *r, UINT usage, char *network, FOLDER *f) {
	bool ok = true;

	TOKEN_LIST *t = CfgEnumFolderToTokenList(f);

	for (UINT i = 0; ok && t != NULL && i < t->NumTokens; i++)
		ok = CsImportCert(s, r, usage, network, NULL, CfgFindFolder(f, t->Token[i]), "X509");

	FreeToken(t);

	return ok;
}

// One user folder of a hub, with its user certificate
static bool CsImportUser(CONFIG_STORE *s, CS_IMPORT *r, char *network, FOLDER *f) {
	CS_USER u;
	if (f == NULL)
		return true;

	Zero(&u, sizeof(u));
	StrCpy(u.Network, sizeof(u.Network), network);
	StrCpy(u.Name, sizeof(u.Name), f->Name);
	CfgGetUniStr(f, "RealName", u.RealName, sizeof(u.RealName));
	CfgGetUniStr(f, "Note", u.Note, sizeof(u.Note));
	CfgGetStr(f, "GroupName", u.Group, sizeof(u.Group));
	u.ExpireTime = CfgGetInt64(f, "ExpireTime");
	u.AuthType = CfgGetInt(f, "AuthType");

	if (u.AuthType == AUTHTYPE_NT)
		CfgGetUniStr(f, "AuthNtUserName", u.AuthName, sizeof(u.AuthName));

	if (u.AuthType == AUTHTYPE_ROOTCERT) {
		CfgGetUniStr(f, "AuthCommonName", u.AuthName, sizeof(u.AuthName));

		// A serial number longer than the store keeps makes the user invalid, so it is skipped
		BUF *serial = CfgGetBuf(f, "AuthSerial");
		if (serial != NULL) {
			u.AuthSerialSize = serial->Size;
			if (serial->Size <= sizeof(u.AuthSerial))
				Copy(u.AuthSerial, serial->Buf, serial->Size);
			FreeBuf(serial);
		}
	}

	UINT num_users = r->NumUsers;
	if (CsImportCount(r, CsAddUser(s, &u), &r->NumUsers) == false)
		return false;

	if (r->NumUsers == num_users)
		return true;

	if (u.AuthType == AUTHTYPE_PASSWORD && CfgIsItem(f, "AuthPassword"))
		r->NumPasswordsDropped++;

	if (u.AuthType == AUTHTYPE_USERCERT)
		return CsImportCert(s, r, CS_CERT_USER, network, u.Name, f, "AuthUserCert");

	return true;
}

// One hub folder of VirtualHUB: the network, its CAs, its users and its administrator
static bool CsImportHub(CONFIG_STORE *s, CS_IMPORT *r, FOLDER *f) {
	char admin[MAX_SIZE];
	if (f == NULL)
		return true;

	char *name = f->Name;

	UINT num_networks = r->NumNetworks;
	if (CsImportCount(r, CsAddNetwork(s, name, CS_MODE_L2, CfgGetBool(f, "Online")), &r->NumNetworks) == false)
		return false;

	if (r->NumNetworks == num_networks)
		return true;

	FOLDER *db = CfgFindFolder(f, "SecurityAccountDatabase");

	if (CsImportCertList(s, r, CS_CERT_CA, name, CfgFindFolder(db, "CertList")) == false)
		return false;

	FOLDER *users = CfgFindFolder(db, "UserList");
	TOKEN_LIST *t = CfgEnumFolderToTokenList(users);
	bool ok = true;

	for (UINT i = 0; ok && t != NULL && i < t->NumTokens; i++)
		ok = CsImportUser(s, r, name, CfgFindFolder(users, t->Token[i]));

	FreeToken(t);

	if (ok == false)
		return false;

	// The hub administrator of the fork logs in as "administrator" on its hub; a named account takes the hub name
	if (CsImportHasPassword(f, "HashedPassword")) {
		Format(admin, sizeof(admin), "%s@%s", ADMINISTRATOR_USERNAME, name);

		UINT num_admins = r->NumAdmins;
		if (CsImportCount(r, CsAddAdmin(s, admin, CS_ROLE_HUB_ADMIN, name, NULL), &r->NumAdmins) == false)
			return false;

		if (r->NumAdmins != num_admins)
			r->NumPasswordsDropped++;
	}

	return true;
}

// The listener folders of ListenerList (Listener0, Listener1, ...): each TCP port becomes a TLS listener
static bool CsImportListeners(CONFIG_STORE *s, CS_IMPORT *r, FOLDER *f) {
	bool ok = true;

	TOKEN_LIST *t = CfgEnumFolderToTokenList(f);

	for (UINT i = 0; ok && t != NULL && i < t->NumTokens; i++) {
		FOLDER *ff = CfgFindFolder(f, t->Token[i]);
		UINT port = CfgGetInt(ff, "Port");

		// The fork skips a listener without a port as well
		if (port != 0)
			ok = CsImportCount(r, CsAddListener(s, CS_TRANSPORT_TLS, port, CfgGetBool(ff, "Enabled")), &r->NumListeners);
	}

	FreeToken(t);

	return ok;
}

// ServerConfiguration: the server certificate and its chain, and the server administrator as the owner account
static bool CsImportServer(CONFIG_STORE *s, CS_IMPORT *r, FOLDER *f) {
	if (CsImportCert(s, r, CS_CERT_SERVER, NULL, NULL, f, "ServerCert") == false)
		return false;

	if (CsImportCertList(s, r, CS_CERT_CHAIN, NULL, CfgFindFolder(f, "ServerChain")) == false)
		return false;

	r->ServerKeyDropped = CfgIsItem(f, "ServerKey");

	UINT num_admins = r->NumAdmins;
	if (CsImportCount(r, CsAddAdmin(s, ADMINISTRATOR_USERNAME, CS_ROLE_OWNER, NULL, NULL), &r->NumAdmins) == false)
		return false;

	if (r->NumAdmins != num_admins && CsImportHasPassword(f, "HashedPassword"))
		r->NumPasswordsDropped++;

	return true;
}

// The file name of a path, as UTF-8; the caller frees it
static char *CsImportFileName(wchar_t *path) {
	UINT start = 0;

	for (UINT i = 0; path[i] != 0; i++)
		if (path[i] == L'\\' || path[i] == L'/')
			start = i + 1;

	UINT size = CalcUniToUtf8(path + start) + 1;
	char *ret = ZeroMalloc(size);
	UniToUtf8(ret, size, path + start);

	return ret;
}

// Import the fork's Config file path into the store s, which must be empty (CsIsEmpty), in one transaction, and
// record the file name in the setting CS_SETTING_IMPORTED. What was carried and what was left out goes to ret.
// ERR_OBJECT_NOT_FOUND when the file does not exist, ERR_INVALID_PARAMETER when it is no fork configuration (no
// ServerConfiguration folder, as the fork's own start requires), ERR_OBJECT_EXISTS when the store is not empty,
// ERR_INTERNAL_ERROR when the store fails; the store is unchanged after an error.
UINT CsImportForkConfig(CONFIG_STORE *s, wchar_t *path, CS_IMPORT *ret) {
	CS_IMPORT r;
	UINT err = ERR_INTERNAL_ERROR;

	Zero(&r, sizeof(r));

	if (ret != NULL)
		Zero(ret, sizeof(CS_IMPORT));

	if (s == NULL || UniIsEmptyStr(path))
		return ERR_INVALID_PARAMETER;

	if (IsFileExistsW(path) == false)
		return ERR_OBJECT_NOT_FOUND;

	FOLDER *root = CfgReadW(path);
	FOLDER *server = CfgFindFolder(root, "ServerConfiguration");

	if (server == NULL) {
		CfgDeleteFolder(root);
		return ERR_INVALID_PARAMETER;
	}

	Lock(s->Lock);
	{
		if (CsIsEmpty(s) == false) {
			err = ERR_OBJECT_EXISTS;
		} else if (CsBegin(s)) {
			FOLDER *hubs = CfgFindFolder(root, "VirtualHUB");
			TOKEN_LIST *t = CfgEnumFolderToTokenList(hubs);
			bool ok = true;

			for (UINT i = 0; ok && t != NULL && i < t->NumTokens; i++)
				ok = CsImportHub(s, &r, CfgFindFolder(hubs, t->Token[i]));

			FreeToken(t);

			if (ok)
				ok = CsImportListeners(s, &r, CfgFindFolder(root, "ListenerList"));

			if (ok)
				ok = CsImportServer(s, &r, server);

			if (ok) {
				char *name = CsImportFileName(path);
				ok = (CsSetSetting(s, CS_SETTING_IMPORTED, name) == ERR_NO_ERROR);
				Free(name);
			}

			if (ok && CsCommit(s)) {
				err = ERR_NO_ERROR;
			} else {
				if (ok)
					Debug("ConfigStore: the import of %S did not commit\n", path);
				else
					CsRollback(s);

				Zero(&r, sizeof(r));
			}
		}
	}
	Unlock(s->Lock);

	CfgDeleteFolder(root);

	if (ret != NULL)
		Copy(ret, &r, sizeof(CS_IMPORT));

	return err;
}
