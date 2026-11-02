// Account.c
// Account Manager

#include "Account.h"

#include "Connection.h"
#include "Hub.h"

#include "Mayaqua/Cfg.h"
#include "Mayaqua/Encrypt.h"
#include "Mayaqua/Internat.h"
#include "Mayaqua/Kernel.h"
#include "Mayaqua/Memory.h"
#include "Mayaqua/Object.h"
#include "Mayaqua/Pack.h"
#include "Mayaqua/Str.h"
#include "Mayaqua/Table.h"
#include "Mayaqua/Tick64.h"

#define PASSWORD_CRYPT_KEY      "EncryptPassword"
#define PASSWORD_CRYPT_KEY_SIZE 8

static void CleanupUser(USER *u);
static void CleanupGroup(USERGROUP *g);
static char *DecryptPassword(BUF *b);
static BUF *EncryptPassword(char *password);

POLICY_ITEM policy_item[] =
    {
        //  ID,     Value,  Omittable, Min, Max, Default, Unit name, Offset, Name, Ver3, Cascade cmd, Cascade cfg
        // Cascade cmd: settable from the cascade commands. Cascade cfg: written to the config of a cascade connection.
        {0, false, false, 0, 0, 1, NULL, offsetof(POLICY, Access), "Access", false, false, false},
        {1, false, false, 0, 0, 0, NULL, offsetof(POLICY, DHCPFilter), "DHCPFilter", false, true, true},
        {2, false, false, 0, 0, 0, NULL, offsetof(POLICY, DHCPNoServer), "DHCPNoServer", false, true, true},
        {3, false, false, 0, 0, 0, NULL, offsetof(POLICY, DHCPForce), "DHCPForce", false, true, true},
        {4, false, false, 0, 0, 0, NULL, offsetof(POLICY, NoBridge), "NoBridge", false, false, false},
        {5, false, false, 0, 0, 0, NULL, offsetof(POLICY, NoRouting), "NoRouting", false, false, false},
        {6, false, false, 0, 0, 0, NULL, offsetof(POLICY, CheckMac), "CheckMac", false, true, true},
        {7, false, false, 0, 0, 0, NULL, offsetof(POLICY, CheckIP), "CheckIP", false, true, true},
        {8, false, false, 0, 0, 0, NULL, offsetof(POLICY, ArpDhcpOnly), "ArpDhcpOnly", false, true, true},
        {9, false, false, 0, 0, 0, NULL, offsetof(POLICY, PrivacyFilter), "PrivacyFilter", false, true, true},
        {10, false, false, 0, 0, 0, NULL, offsetof(POLICY, NoServer), "NoServer", false, true, true},
        {11, false, false, 0, 0, 0, NULL, offsetof(POLICY, NoBroadcastLimiter), "NoBroadcastLimiter", false, true, true},
        {12, false, false, 0, 0, 0, NULL, offsetof(POLICY, MonitorPort), "MonitorPort", false, false, false},
        {13, true, false, 1, 32, 32, "POL_INT_COUNT", offsetof(POLICY, MaxConnection), "MaxConnection", false, false, false},
        {14, true, false, 5, 60, 20, "POL_INT_SEC", offsetof(POLICY, TimeOut), "TimeOut", false, false, false},
        {15, true, true, 1, 65535, 0, "POL_INT_COUNT", offsetof(POLICY, MaxMac), "MaxMac", false, true, true},
        {16, true, true, 1, 65535, 0, "POL_INT_COUNT", offsetof(POLICY, MaxIP), "MaxIP", false, true, true},
        {17, true, true, 1, 4294967295UL, 0, "POL_INT_BPS", offsetof(POLICY, MaxUpload), "MaxUpload", false, true, true},
        {18, true, true, 1, 4294967295UL, 0, "POL_INT_BPS", offsetof(POLICY, MaxDownload), "MaxDownload", false, true, true},
        {19, false, false, 0, 0, 0, NULL, offsetof(POLICY, FixPassword), "FixPassword", false, false, false},
        {20, true, true, 1, 65535, 0, "POL_INT_COUNT", offsetof(POLICY, MultiLogins), "MultiLogins", false, false, false},
        {21, false, false, 0, 0, 0, NULL, offsetof(POLICY, NoQoS), "NoQoS", false, false, false},
        {22, false, false, 0, 0, 0, NULL, offsetof(POLICY, RSandRAFilter), "RSandRAFilter", true, true, true},
        {23, false, false, 0, 0, 0, NULL, offsetof(POLICY, RAFilter), "RAFilter", true, true, true},
        {24, false, false, 0, 0, 0, NULL, offsetof(POLICY, DHCPv6Filter), "DHCPv6Filter", true, true, true},
        {25, false, false, 0, 0, 0, NULL, offsetof(POLICY, DHCPv6NoServer), "DHCPv6NoServer", true, true, true},
        {26, false, false, 0, 0, 0, NULL, offsetof(POLICY, NoRoutingV6), "NoRoutingV6", true, false, false},
        {27, false, false, 0, 0, 0, NULL, offsetof(POLICY, CheckIPv6), "CheckIPv6", true, true, true},
        {28, false, false, 0, 0, 0, NULL, offsetof(POLICY, NoServerV6), "NoServerV6", true, true, true},
        {29, true, true, 1, 65535, 0, "POL_INT_COUNT", offsetof(POLICY, MaxIPv6), "MaxIPv6", true, true, true},
        {30, false, false, 0, 0, 0, NULL, offsetof(POLICY, NoSavePassword), "NoSavePassword", true, false, false},
        {31, true, true, 1, 4294967295UL, 0, "POL_INT_SEC", offsetof(POLICY, AutoDisconnect), "AutoDisconnect", true, false, false},
        {32, false, false, 0, 0, 0, NULL, offsetof(POLICY, FilterIPv4), "FilterIPv4", true, true, true},
        {33, false, false, 0, 0, 0, NULL, offsetof(POLICY, FilterIPv6), "FilterIPv6", true, true, true},
        {34, false, false, 0, 0, 0, NULL, offsetof(POLICY, FilterNonIP), "FilterNonIP", true, true, true},
        {35, false, false, 0, 0, 0, NULL, offsetof(POLICY, NoIPv6DefaultRouterInRA), "NoIPv6DefaultRouterInRA", true, true, true},
        {36, false, false, 0, 0, 0, NULL, offsetof(POLICY, NoIPv6DefaultRouterInRAWhenIPv6), "NoIPv6DefaultRouterInRAWhenIPv6", true, false, true},
        {37, true, true, 1, 4095, 0, "POL_INT_VLAN", offsetof(POLICY, VLanId), "VLanId", true, true, true},
};

// The table must have exactly NUM_POLICY_ITEM rows: a negative array size is a compile error
typedef char policy_item_count_check[(sizeof(policy_item) / sizeof(policy_item[0]) == NUM_POLICY_ITEM) ? 1 : -1];

void FormatPolicyValue(wchar_t *str, UINT size, UINT id, UINT value) {
	if (str == NULL)
		return;

	POLICY_ITEM *p = GetPolicyItem(id);

	if (p->TypeInt == false)
		if (value == 0)
			UniStrCpy(str, size, L"No");
		else
			UniStrCpy(str, size, L"Yes");
	else if (value == 0 && p->AllowZero)
		UniStrCpy(str, size, _UU("CMD_NO_SETTINGS"));
	else
		UniFormat(str, size, _UU(p->FormatStr), value);
}

void GetPolicyValueRangeStr(wchar_t *str, UINT size, UINT id) {
	if (str == NULL)
		return;

	POLICY_ITEM *p = GetPolicyItem(id);

	if (p->TypeInt == false) {
		UniStrCpy(str, size, _UU("CMD_PolicyList_Range_Bool"));
	} else {
		wchar_t *tag;
		wchar_t tmp1[256], tmp2[256];

		if (p->AllowZero)
			tag = _UU("CMD_PolicyList_Range_Int_2");
		else
			tag = _UU("CMD_PolicyList_Range_Int_1");

		UniFormat(tmp1, sizeof(tmp1), _UU(p->FormatStr), p->MinValue);
		UniFormat(tmp2, sizeof(tmp2), _UU(p->FormatStr), p->MaxValue);

		UniFormat(str, size, tag, tmp1, tmp2);
	}
}

POLICY_ITEM *GetPolicyItem(UINT id) {
	return &policy_item[id];
}

// Read one policy field by its table id; a bool field gives 0 or 1
UINT GetPolicyValue(POLICY *p, UINT id) {
	if (p == NULL || id >= NUM_POLICY_ITEM)
		return 0;

	POLICY_ITEM *item = &policy_item[id];
	UCHAR *field = (UCHAR *)p + item->Offset;

	if (item->TypeInt) {
		UINT value;

		Copy(&value, field, sizeof(UINT));

		return value;
	}

	return (*(bool *)field) ? 1 : 0;
}

// Write one policy field by its table id; a bool field takes any non-zero value as true
void SetPolicyValue(POLICY *p, UINT id, UINT value) {
	if (p == NULL || id >= NUM_POLICY_ITEM)
		return;

	POLICY_ITEM *item = &policy_item[id];
	UCHAR *field = (UCHAR *)p + item->Offset;

	if (item->TypeInt)
		Copy(field, &value, sizeof(UINT));
	else
		*(bool *)field = (value != 0);
}

bool PolicyIsSupportedForCascade(UINT i) {
	if (i >= NUM_POLICY_ITEM)
		return false;

	return policy_item[i].CascadeCmd;
}

char *PolicyIdToStr(UINT i) {
	if (i >= NUM_POLICY_ITEM)
		return NULL;

	return policy_item[i].Name;
}

UINT PolicyStrToId(char *name) {
	if (name == NULL)
		return INFINITE;

	for (UINT i = 0; i < NUM_POLICY_ITEM; i++)
		if (StartWith(PolicyIdToStr(i), name))
			return i;

	return INFINITE;
}

UINT PolicyNum() {
	return NUM_POLICY_ITEM;
}

bool IsUserName(char *name) {
	char tmp[MAX_SIZE];
	if (name == NULL)
		return false;

	StrCpy(tmp, sizeof(tmp), name);
	name = tmp;

	Trim(name);

	UINT len = StrLen(name);
	if (len == 0)
		return false;

	if (StrCmpi(name, "*") == 0)
		return true;

	for (UINT i = 0; i < len; i++)
		if (IsSafeChar(name[i]) == false && name[i] != '@')
			return false;

	if (StrCmpi(name, LINK_USER_NAME) == 0)
		return false;

	if (StrCmpi(name, LINK_USER_NAME_PRINT) == 0)
		return false;

	if (StrCmpi(name, BRIDGE_USER_NAME) == 0)
		return false;

	if (StrCmpi(name, BRIDGE_USER_NAME_PRINT) == 0)
		return false;

	if (StrCmpi(name, ADMINISTRATOR_USERNAME) == 0)
		return false;

	return true;
}

// Check the authentication data of a user the admin RPC creates or changes.
// Returns ERR_NO_ERROR, or the error code to send back
UINT CheckUserAuthData(UINT auth_type, void *auth_data) {
	if (auth_type == AUTHTYPE_USERCERT) {
		AUTHUSERCERT *c = auth_data;

		if (c != NULL && c->UserX != NULL &&
		    c->UserX->is_compatible_bit == false)
			return ERR_NOT_RSA_1024;
		if (c == NULL || c->UserX == NULL)
			return ERR_INVALID_PARAMETER;
	}

	// A password user needs a password hash: a missing or all-zero HashedKey is refused
	if (auth_type == AUTHTYPE_PASSWORD) {
		AUTHPASSWORD *pw = auth_data;

		if (pw == NULL || IsZero(pw->HashedKey, sizeof(pw->HashedKey)))
			return ERR_INVALID_PARAMETER;
	}

	return ERR_NO_ERROR;
}

POLICY *ClonePolicy(POLICY *policy) {
	if (policy == NULL)
		return NULL;

	POLICY *ret = ZeroMalloc(sizeof(POLICY));
	Copy(ret, policy, sizeof(POLICY));

	return ret;
}

// Overwrite policy values; data from an older version leaves the Ver 3.0 fields as they are
static void OverwritePolicy(POLICY **target, POLICY *p) {
	if (target == NULL)
		return;

	if (p == NULL) {
		if (*target != NULL) {
			Free(*target);
			*target = NULL;
		}
	} else if (p->Ver3) {
		if (*target != NULL) {
			Free(*target);
			*target = NULL;
		}

		*target = ClonePolicy(p);
	} else {
		if (*target == NULL)
			*target = ClonePolicy(p);
		else
			Copy(*target, p, POLICY_VER2_SIZE);
	}
}

void SetUserPolicy(USER *u, POLICY *policy) {
	if (u == NULL)
		return;

	Lock(u->lock);
	{
		OverwritePolicy(&u->Policy, policy);
	}
	Unlock(u->lock);
}

void SetGroupPolicy(USERGROUP *g, POLICY *policy) {
	if (g == NULL)
		return;

	Lock(g->lock);
	{
		OverwritePolicy(&g->Policy, policy);
	}
	Unlock(g->lock);
}

POLICY *GetGroupPolicy(USERGROUP *g) {
	POLICY *ret;
	if (g == NULL)
		return NULL;

	Lock(g->lock);
	{
		if (g->Policy == NULL)
			ret = NULL;
		else
			ret = ClonePolicy(g->Policy);
	}
	Unlock(g->lock);

	return ret;
}

POLICY *GetDefaultPolicy() {
	static POLICY def_policy;
	static bool ready = false;

	// Built from the policy table on first use; every caller computes the same bytes
	if (ready == false) {
		POLICY tmp;

		Zero(&tmp, sizeof(tmp));

		for (UINT i = 0; i < NUM_POLICY_ITEM; i++)
			SetPolicyValue(&tmp, i, policy_item[i].DefaultValue);

		Copy(&def_policy, &tmp, sizeof(POLICY));
		ready = true;
	}

	return &def_policy;
}

void *NewNTAuthData(wchar_t *username) {
	AUTHNT *a = ZeroMallocEx(sizeof(AUTHNT), true);
	a->NtUsername = CopyUniStr(username);

	return a;
}

void *NewRootCertAuthData(X_SERIAL *serial, wchar_t *common_name) {
	AUTHROOTCERT *a = ZeroMallocEx(sizeof(AUTHROOTCERT), true);
	if (common_name != NULL && UniIsEmptyStr(common_name) == false)
		a->CommonName = CopyUniStr(common_name);
	if (serial != NULL && serial->size >= 1)
		a->Serial = CloneXSerial(serial);

	return a;
}

void *NewUserCertAuthData(X *x) {
	AUTHUSERCERT *a = ZeroMalloc(sizeof(AUTHUSERCERT));
	a->UserX = CloneX(x);

	return a;
}

void HashPassword(void *dst, char *username, char *password) {
	if (dst == NULL || username == NULL || password == NULL)
		return;

	BUF *b = NewBuf();
	char *username_upper = CopyStr(username);
	StrUpper(username_upper);
	WriteBuf(b, password, StrLen(password));
	WriteBuf(b, username_upper, StrLen(username_upper));
	Sha0(dst, b->Buf, b->Size);

	FreeBuf(b);
	Free(username_upper);
}

void GenerateNtPasswordHash(UCHAR *dst, char *password) {
	if (dst == NULL || password == NULL)
		return;

	UINT len = StrLen(password);
	UINT tmp_size = len * 2;

	UCHAR *tmp = ZeroMalloc(tmp_size);

	for (UINT i = 0; i < len; i++)
		tmp[i * 2] = password[i];

	HashMd4(dst, tmp, tmp_size);

	Free(tmp);
}

void *NewPasswordAuthData(char *username, char *password) {
	if (username == NULL || password == NULL)
		return NULL;

	AUTHPASSWORD *pw = ZeroMalloc(sizeof(AUTHPASSWORD));
	HashPassword(pw->HashedKey, username, password);
	GenerateNtPasswordHash(pw->NtLmSecureHash, password);

	return pw;
}

void *NewPasswordAuthDataRaw(UCHAR *hashed_password, UCHAR *ntlm_secure_hash) {
	if (hashed_password == NULL)
		return NULL;

	AUTHPASSWORD *pw = ZeroMalloc(sizeof(AUTHPASSWORD));
	Copy(pw->HashedKey, hashed_password, SHA1_SIZE);

	if (ntlm_secure_hash != NULL)
		Copy(pw->NtLmSecureHash, ntlm_secure_hash, MD5_SIZE);

	return pw;
}

void *CopyAuthData(void *authdata, UINT authtype) {
	AUTHPASSWORD *pw = (AUTHPASSWORD *)authdata;
	AUTHUSERCERT *usercert = (AUTHUSERCERT *)authdata;
	AUTHROOTCERT *rootcert = (AUTHROOTCERT *)authdata;
	AUTHNT *nt = (AUTHNT *)authdata;
	if (authdata == NULL || authtype == AUTHTYPE_ANONYMOUS)
		return NULL;

	switch (authtype) {
	case AUTHTYPE_PASSWORD: {
		AUTHPASSWORD *ret = ZeroMalloc(sizeof(AUTHPASSWORD));
		Copy(ret, pw, sizeof(AUTHPASSWORD));
		return ret;
	} break;

	case AUTHTYPE_USERCERT: {
		AUTHUSERCERT *ret = ZeroMalloc(sizeof(AUTHUSERCERT));
		ret->UserX = CloneX(usercert->UserX);
		return ret;
	} break;

	case AUTHTYPE_ROOTCERT: {
		AUTHROOTCERT *ret = ZeroMalloc(sizeof(AUTHROOTCERT));
		ret->CommonName = CopyUniStr(rootcert->CommonName);
		ret->Serial = CloneXSerial(rootcert->Serial);
		return ret;
	} break;

	case AUTHTYPE_NT: {
		AUTHNT *ret = ZeroMalloc(sizeof(AUTHNT));
		ret->NtUsername = CopyUniStr(nt->NtUsername);
		return ret;
	} break;
	}

	return NULL;
}

void SetUserAuthData(USER *u, UINT authtype, void *authdata) {
	if (u == NULL)
		return;
	if (authtype != AUTHTYPE_ANONYMOUS && authdata == NULL)
		return;

	Lock(u->lock);
	{
		if (u->AuthType != AUTHTYPE_ANONYMOUS) {
			if (u->AuthType == AUTHTYPE_PASSWORD && authtype == AUTHTYPE_PASSWORD) {
				AUTHPASSWORD *pw_old = (AUTHPASSWORD *)u->AuthData;
				AUTHPASSWORD *pw_new = (AUTHPASSWORD *)authdata;

				// Keep the old NTLM hash if the password is unchanged and the admin tool sent no NTLM hash

				if (Cmp(pw_old->HashedKey, pw_new->HashedKey, SHA1_SIZE) == 0) {
					if (IsZero(pw_new->NtLmSecureHash, MD5_SIZE))
						Copy(pw_new->NtLmSecureHash, pw_old->NtLmSecureHash, MD5_SIZE);
				}
			}

			FreeAuthData(u->AuthType, u->AuthData);
		}
		u->AuthType = authtype;
		u->AuthData = authdata;
	}
	Unlock(u->lock);
}

// Replace a user's or group's traffic counters under its lock; NULL resets them
static void SetTrafficLocked(LOCK *lock, TRAFFIC *dst, const TRAFFIC *src) {
	Lock(lock);
	{
		if (src != NULL)
			Copy(dst, src, sizeof(TRAFFIC));
		else
			Zero(dst, sizeof(TRAFFIC));
	}
	Unlock(lock);
}

void SetGroupTraffic(USERGROUP *g, TRAFFIC *t) {
	if (g == NULL)
		return;

	SetTrafficLocked(g->lock, g->Traffic, t);
}

void SetUserTraffic(USER *u, TRAFFIC *t) {
	if (u == NULL)
		return;

	SetTrafficLocked(u->lock, u->Traffic, t);
}

void JoinUserToGroup(USER *u, USERGROUP *g) {
	if (u == NULL)
		return;

	Lock(u->lock);
	{
		if (u->Group != NULL) {
			ReleaseGroup(u->Group);
			u->Group = NULL;
			Free(u->GroupName);
			u->GroupName = NULL;
		}

		if (g != NULL) {
			Lock(g->lock);
			{
				u->GroupName = CopyStr(g->Name);
				u->Group = g;
				AddRef(g->ref);
			}
			Unlock(g->lock);
		}
	}
	Unlock(u->lock);
}

bool AcIsGroup(HUB *h, char *name) {
	if (h == NULL || name == NULL)
		return false;

	USERGROUP *g = AcGetGroup(h, name);
	if (g == NULL)
		return false;
	ReleaseGroup(g);

	return true;
}

bool AcIsUser(HUB *h, char *name) {
	if (h == NULL || name == NULL)
		return false;

	USER *u = AcGetUser(h, name);
	if (u == NULL)
		return false;
	ReleaseUser(u);

	return true;
}

USERGROUP *AcGetGroup(HUB *h, char *name) {
	USERGROUP t;
	if (h == NULL || name == NULL)
		return NULL;

	t.Name = name;
	USERGROUP *g = Search(h->HubDb->GroupList, &t);
	if (g == NULL)
		return NULL;
	AddRef(g->ref);

	return g;
}

USER *AcGetUser(HUB *h, char *name) {
	USER t;
	if (h == NULL || name == NULL)
		return NULL;

	t.Name = name;
	USER *u = Search(h->HubDb->UserList, &t);
	if (u == NULL)
		return NULL;
	AddRef(u->ref);

	return u;
}

bool AcDeleteUser(HUB *h, char *name) {
	if (h == NULL || name == NULL)
		return false;

	USER *u = AcGetUser(h, name);
	if (u == NULL)
		return false;

	if (Delete(h->HubDb->UserList, u))
		ReleaseUser(u);

	ReleaseUser(u);

	return true;
}

bool AcDeleteGroup(HUB *h, char *name) {
	if (h == NULL || name == NULL)
		return false;

	USERGROUP *g = AcGetGroup(h, name);
	if (g == NULL)
		return false;

	if (Delete(h->HubDb->GroupList, g))
		ReleaseGroup(g);

	for (UINT i = 0; i < LIST_NUM(h->HubDb->UserList); i++) {
		USER *u = LIST_DATA(h->HubDb->UserList, i);
		Lock(u->lock);
		{
			if (u->Group == g)
				JoinUserToGroup(u, NULL);
		}
		Unlock(u->lock);
	}

	ReleaseGroup(g);

	return true;
}

bool AcAddGroup(HUB *h, USERGROUP *g) {
	if (h == NULL || g == NULL)
		return false;

	if (LIST_NUM(h->HubDb->GroupList) >= MAX_GROUPS)
		return false;

	if (AcIsGroup(h, g->Name) != false)
		return false;

	Insert(h->HubDb->GroupList, g);
	AddRef(g->ref);

	return true;
}

bool AcAddUser(HUB *h, USER *u) {
	if (h == NULL || u == NULL)
		return false;

	if (LIST_NUM(h->HubDb->UserList) >= MAX_USERS)
		return false;

	if (AcIsUser(h, u->Name) != false)
		return false;

	Insert(h->HubDb->UserList, u);
	AddRef(u->ref);

	return true;
}

void ReleaseUser(USER *u) {
	if (u == NULL)
		return;

	if (Release(u->ref) == 0)
		CleanupUser(u);
}

static void CleanupUser(USER *u) {
	if (u == NULL)
		return;

	DeleteLock(u->lock);
	Free(u->Name);
	Free(u->RealName);
	Free(u->Note);
	Free(u->GroupName);
	if (u->Group != NULL)
		ReleaseGroup(u->Group);

	FreeAuthData(u->AuthType, u->AuthData);

	if (u->Policy)
		Free(u->Policy);

	FreeTraffic(u->Traffic);

	Free(u);
}

void FreeAuthData(UINT authtype, void *authdata) {
	AUTHUSERCERT *uc = (AUTHUSERCERT *)authdata;
	AUTHROOTCERT *rc = (AUTHROOTCERT *)authdata;
	AUTHNT *nt = (AUTHNT *)authdata;
	if (authtype == AUTHTYPE_ANONYMOUS || authdata == NULL)
		return;

	switch (authtype) {
	case AUTHTYPE_PASSWORD:
		break;

	case AUTHTYPE_USERCERT:
		FreeX(uc->UserX);
		break;

	case AUTHTYPE_ROOTCERT:
		if (rc->Serial != NULL)
			FreeXSerial(rc->Serial);
		if (rc->CommonName != NULL)
			Free(rc->CommonName);
		break;

	case AUTHTYPE_NT:
		Free(nt->NtUsername);
		break;
	}

	Free(authdata);
}

USER *NewUser(char *name, wchar_t *realname, wchar_t *note, UINT authtype, void *authdata) {
	if (name == NULL || realname == NULL || note == NULL)
		return NULL;
	if (authtype != AUTHTYPE_ANONYMOUS && authdata == NULL)
		return NULL;

	USER *u = ZeroMalloc(sizeof(USER));
	u->lock = NewLock();
	u->ref = NewRef();
	u->Name = CopyStr(name);
	u->RealName = CopyUniStr(realname);
	u->Note = CopyUniStr(note);
	u->GroupName = NULL;
	u->Group = NULL;
	u->AuthType = authtype;
	u->AuthData = authdata;
	u->CreatedTime = SystemTime64();
	u->UpdatedTime = SystemTime64();

	u->Policy = NULL;
	u->Traffic = NewTraffic();

	return u;
}

void ReleaseGroup(USERGROUP *g) {
	if (g == NULL)
		return;

	if (Release(g->ref) == 0)
		CleanupGroup(g);
}

static void CleanupGroup(USERGROUP *g) {
	if (g == NULL)
		return;

	Free(g->Name);
	Free(g->RealName);
	Free(g->Note);

	if (g->Policy)
		Free(g->Policy);


	FreeTraffic(g->Traffic);

	DeleteLock(g->lock);
	Free(g);
}

USERGROUP *NewGroup(char *name, wchar_t *realname, wchar_t *note) {
	if (name == NULL || realname == NULL || note == NULL)
		return NULL;

	USERGROUP *g = ZeroMalloc(sizeof(USERGROUP));
	g->lock = NewLock();
	g->ref = NewRef();
	g->Name = CopyStr(name);
	g->RealName = CopyUniStr(realname);
	g->Note = CopyUniStr(note);
	g->Policy = NULL;
	g->Traffic = NewTraffic();

	return g;
}

void AcLock(HUB *h) {
	if (h == NULL)
		return;
	LockList(h->HubDb->GroupList);
	LockList(h->HubDb->UserList);
}

void AcUnlock(HUB *h) {
	if (h == NULL)
		return;
	UnlockList(h->HubDb->UserList);
	UnlockList(h->HubDb->GroupList);
}

int CompareGroupName(void *p1, void *p2) {
	if (p1 == NULL || p2 == NULL)
		return 0;
	USERGROUP *g1 = *(USERGROUP **)p1;
	USERGROUP *g2 = *(USERGROUP **)p2;
	if (g1 == NULL || g2 == NULL)
		return 0;

	return StrCmpi(g1->Name, g2->Name);
}

int CompareUserName(void *p1, void *p2) {
	if (p1 == NULL || p2 == NULL)
		return 0;
	USER *u1 = *(USER **)p1;
	USER *u2 = *(USER **)p2;
	if (u1 == NULL || u2 == NULL)
		return 0;

	return StrCmpi(u1->Name, u2->Name);
}

void ClientAuthFree(CLIENT_AUTH *auth) {
	if (auth == NULL)
		return;

	if (auth->ClientX != NULL)
		FreeX(auth->ClientX);
	if (auth->ClientK != NULL)
		FreeK(auth->ClientK);

	Free(auth);
}

CLIENT_AUTH *ClientAuthClone(CLIENT_AUTH *a) {
	if (a == NULL)
		return NULL;

	CLIENT_AUTH *ret = ZeroMallocEx(sizeof(CLIENT_AUTH), true);

	ret->AuthType = a->AuthType;
	StrCpy(ret->Username, sizeof(ret->Username), a->Username);

	switch (a->AuthType) {
	case CLIENT_AUTHTYPE_ANONYMOUS:
		break;

	case CLIENT_AUTHTYPE_PASSWORD:
		Copy(ret->HashedPassword, a->HashedPassword, SHA1_SIZE);
		break;

	case CLIENT_AUTHTYPE_PLAIN_PASSWORD:
		StrCpy(ret->PlainPassword, sizeof(ret->PlainPassword), a->PlainPassword);
		break;

	case CLIENT_AUTHTYPE_CERT:
		ret->ClientX = CloneX(a->ClientX);
		ret->ClientK = CloneK(a->ClientK);
		break;
	}

	return ret;
}

CLIENT_OPTION *ClientOptionClone(CLIENT_OPTION *o) {
	if (o == NULL)
		return NULL;

	CLIENT_OPTION *ret = ZeroMalloc(sizeof(CLIENT_OPTION));
	Copy(ret, o, sizeof(CLIENT_OPTION));

	return ret;
}

CLIENT_AUTH *CiLoadClientAuth(FOLDER *f) {
	char *s;
	BUF *b;
	if (f == NULL)
		return NULL;

	CLIENT_AUTH *a = ZeroMalloc(sizeof(CLIENT_AUTH));

	a->AuthType = CfgGetInt(f, "AuthType");
	CfgGetStr(f, "Username", a->Username, sizeof(a->Username));

	switch (a->AuthType) {
	case CLIENT_AUTHTYPE_ANONYMOUS:
		break;

	case CLIENT_AUTHTYPE_PASSWORD:
		CfgGetByte(f, "HashedPassword", a->HashedPassword, SHA1_SIZE);
		break;

	case CLIENT_AUTHTYPE_PLAIN_PASSWORD:
		b = CfgGetBuf(f, "EncryptedPassword");
		if (b != NULL) {
			s = DecryptPassword(b);
			StrCpy(a->PlainPassword, sizeof(a->PlainPassword), s);
			Free(s);
			FreeBuf(b);
		}
		break;

	case CLIENT_AUTHTYPE_CERT:
		b = CfgGetBuf(f, "ClientCert");
		if (b != NULL)
			a->ClientX = BufToX(b, false);
		FreeBuf(b);
		b = CfgGetBuf(f, "ClientKey");
		if (b != NULL)
			a->ClientK = BufToK(b, true, false, NULL);
		FreeBuf(b);
		break;
	}

	return a;
}

CLIENT_OPTION *CiLoadClientOption(FOLDER *f) {
	if (f == NULL)
		return NULL;

	CLIENT_OPTION *o = ZeroMalloc(sizeof(CLIENT_OPTION));

	CfgGetUniStr(f, "AccountName", o->AccountName, sizeof(o->AccountName));
	CfgGetStr(f, "Hostname", o->Hostname, sizeof(o->Hostname));
	o->Port = CfgGetInt(f, "Port");
	o->ProxyType = CfgGetInt(f, "ProxyType");
	CfgGetStr(f, "ProxyName", o->ProxyName, sizeof(o->ProxyName));
	o->ProxyPort = CfgGetInt(f, "ProxyPort");
	CfgGetStr(f, "ProxyUsername", o->ProxyUsername, sizeof(o->ProxyUsername));
	BUF *b = CfgGetBuf(f, "ProxyPassword");
	char *s = DecryptPassword(b);
	StrCpy(o->ProxyPassword, sizeof(o->ProxyPassword), s);
	Free(s);
	FreeBuf(b);
	CfgGetStr(f, "CustomHttpHeader", o->CustomHttpHeader, sizeof(o->CustomHttpHeader));
	o->NumRetry = CfgGetInt(f, "NumRetry");
	o->RetryInterval = CfgGetInt(f, "RetryInterval");
	CfgGetStr(f, "HubName", o->HubName, sizeof(o->HubName));
	o->MaxConnection = CfgGetInt(f, "MaxConnection");
	o->UseEncrypt = CfgGetBool(f, "UseEncrypt");
	o->UseCompress = CfgGetBool(f, "UseCompress");
	o->HalfConnection = CfgGetBool(f, "HalfConnection");
	o->NoRoutingTracking = CfgGetBool(f, "NoRoutingTracking");
	CfgGetStr(f, "DeviceName", o->DeviceName, sizeof(o->DeviceName));
	o->AdditionalConnectionInterval = CfgGetInt(f, "AdditionalConnectionInterval");
	o->ConnectionDisconnectSpan = CfgGetInt(f, "ConnectionDisconnectSpan");
	o->RequireMonitorMode = CfgGetBool(f, "RequireMonitorMode");
	o->RequireBridgeRoutingMode = CfgGetBool(f, "RequireBridgeRoutingMode");
	o->DisableQoS = CfgGetBool(f, "DisableQoS");
	o->NoUdpAcceleration = CfgGetBool(f, "NoUdpAcceleration");
	CfgGetIp(f, "BindLocalIP", &o->BindLocalIP);
	o->BindLocalPort = CfgGetInt(f, "BindLocalPort");

	return o;
}

void CiWriteClientAuth(FOLDER *f, CLIENT_AUTH *a) {
	BUF *b;
	if (f == NULL || a == NULL)
		return;

	CfgAddInt(f, "AuthType", a->AuthType);
	CfgAddStr(f, "Username", a->Username);

	switch (a->AuthType) {
	case CLIENT_AUTHTYPE_ANONYMOUS:
		break;

	case CLIENT_AUTHTYPE_PASSWORD:
		CfgAddByte(f, "HashedPassword", a->HashedPassword, SHA1_SIZE);
		break;

	case CLIENT_AUTHTYPE_PLAIN_PASSWORD:
		b = EncryptPassword(a->PlainPassword);
		CfgAddByte(f, "EncryptedPassword", b->Buf, b->Size);
		FreeBuf(b);
		break;

	case CLIENT_AUTHTYPE_CERT:
		if (a->ClientK != NULL && a->ClientX != NULL) {
			b = XToBuf(a->ClientX, false);
			CfgAddByte(f, "ClientCert", b->Buf, b->Size);
			FreeBuf(b);

			b = KToBuf(a->ClientK, false, NULL);
			CfgAddByte(f, "ClientKey", b->Buf, b->Size);
			FreeBuf(b);
		}
		break;
	}
}

void CiWriteClientOption(FOLDER *f, CLIENT_OPTION *o) {
	if (f == NULL || o == NULL)
		return;

	CfgAddUniStr(f, "AccountName", o->AccountName);
	CfgAddStr(f, "Hostname", o->Hostname);
	CfgAddInt(f, "Port", o->Port);
	CfgAddInt(f, "ProxyType", o->ProxyType);
	CfgAddStr(f, "ProxyName", o->ProxyName);
	CfgAddInt(f, "ProxyPort", o->ProxyPort);
	CfgAddStr(f, "ProxyUsername", o->ProxyUsername);
	BUF *b = EncryptPassword(o->ProxyPassword);
	CfgAddByte(f, "ProxyPassword", b->Buf, b->Size);
	FreeBuf(b);
	CfgAddStr(f, "CustomHttpHeader", o->CustomHttpHeader);
	CfgAddInt(f, "NumRetry", o->NumRetry);
	CfgAddInt(f, "RetryInterval", o->RetryInterval);
	CfgAddStr(f, "HubName", o->HubName);
	CfgAddInt(f, "MaxConnection", o->MaxConnection);
	CfgAddBool(f, "UseEncrypt", o->UseEncrypt);
	CfgAddBool(f, "UseCompress", o->UseCompress);
	CfgAddBool(f, "HalfConnection", o->HalfConnection);
	CfgAddBool(f, "NoRoutingTracking", o->NoRoutingTracking);
	CfgAddStr(f, "DeviceName", o->DeviceName);
	CfgAddInt(f, "AdditionalConnectionInterval", o->AdditionalConnectionInterval);
	CfgAddInt(f, "ConnectionDisconnectSpan", o->ConnectionDisconnectSpan);
	CfgAddBool(f, "RequireMonitorMode", o->RequireMonitorMode);
	CfgAddBool(f, "RequireBridgeRoutingMode", o->RequireBridgeRoutingMode);
	CfgAddBool(f, "DisableQoS", o->DisableQoS);
	CfgAddBool(f, "NoUdpAcceleration", o->NoUdpAcceleration);
	CfgAddIp(f, "BindLocalIP", &o->BindLocalIP);
	CfgAddInt(f, "BindLocalPort", o->BindLocalPort);
}

// Only the first PASSWORD_CRYPT_KEY_SIZE bytes of the key are used, which is what the stored password blobs were
// written with: do not change
static CRYPT *NewPasswordCrypt() {
	return NewCrypt(PASSWORD_CRYPT_KEY, PASSWORD_CRYPT_KEY_SIZE);
}

static char *DecryptPassword(BUF *b) {
	if (b == NULL)
		return CopyStr("");

	char *str = ZeroMalloc(b->Size + 1);
	CRYPT *c = NewPasswordCrypt();
	Encrypt(c, str, b->Buf, b->Size);
	FreeCrypt(c);

	str[b->Size] = 0;

	return str;
}

static BUF *EncryptPassword(char *password) {
	if (password == NULL)
		password = "";

	UINT size = StrLen(password) + 1;
	UCHAR *tmp = ZeroMalloc(size);

	CRYPT *c = NewPasswordCrypt();
	Encrypt(c, tmp, password, size - 1);
	FreeCrypt(c);

	BUF *b = NewBuf();
	WriteBuf(b, tmp, size - 1);
	SeekBuf(b, 0, 0);
	Free(tmp);

	return b;
}

void SecurePassword(void *secure_password, void *password, void *random) {
	UCHAR tmp[2 * SHA1_SIZE];
	if (secure_password == NULL || password == NULL || random == NULL)
		return;

	Copy(tmp, password, SHA1_SIZE);
	Copy(tmp + SHA1_SIZE, random, SHA1_SIZE);
	Sha0(secure_password, tmp, sizeof(tmp));

	Zero(tmp, sizeof(tmp));
}
