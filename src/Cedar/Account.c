// SoftEther VPN Source Code - Developer Edition Master Branch
// Cedar Communication Module


// Account.c
// Account Manager

#include "Account.h"

#include "Connection.h"
#include "Hub.h"
#include "MsChapV2.h"
#include "Protocol.h"

#include "Mayaqua/Cfg.h"
#include "Mayaqua/Internat.h"
#include "Mayaqua/Kernel.h"
#include "Mayaqua/Memory.h"
#include "Mayaqua/Object.h"
#include "Mayaqua/Pack.h"
#include "Mayaqua/Str.h"
#include "Mayaqua/Table.h"
#include "Mayaqua/Tick64.h"

// Policy items
POLICY_ITEM policy_item[] =
    {
        //  ID,     Value,  Omittable, Min, Max, Default, Unit name, Offset
        // Ver 2.0
        {0, false, false, 0, 0, 0, NULL, offsetof(POLICY, Access)},                            // Access
        {1, false, false, 0, 0, 0, NULL, offsetof(POLICY, DHCPFilter)},                        // DHCPFilter
        {2, false, false, 0, 0, 0, NULL, offsetof(POLICY, DHCPNoServer)},                      // DHCPNoServer
        {3, false, false, 0, 0, 0, NULL, offsetof(POLICY, DHCPForce)},                         // DHCPForce
        {4, false, false, 0, 0, 0, NULL, offsetof(POLICY, NoBridge)},                          // NoBridge
        {5, false, false, 0, 0, 0, NULL, offsetof(POLICY, NoRouting)},                         // NoRouting
        {6, false, false, 0, 0, 0, NULL, offsetof(POLICY, CheckMac)},                          // CheckMac
        {7, false, false, 0, 0, 0, NULL, offsetof(POLICY, CheckIP)},                           // CheckIP
        {8, false, false, 0, 0, 0, NULL, offsetof(POLICY, ArpDhcpOnly)},                       // ArpDhcpOnly
        {9, false, false, 0, 0, 0, NULL, offsetof(POLICY, PrivacyFilter)},                     // PrivacyFilter
        {10, false, false, 0, 0, 0, NULL, offsetof(POLICY, NoServer)},                         // NoServer
        {11, false, false, 0, 0, 0, NULL, offsetof(POLICY, NoBroadcastLimiter)},               // NoBroadcastLimiter
        {12, false, false, 0, 0, 0, NULL, offsetof(POLICY, MonitorPort)},                      // MonitorPort
        {13, true, false, 1, 32, 32, "POL_INT_COUNT", offsetof(POLICY, MaxConnection)},        // MaxConnection
        {14, true, false, 5, 60, 20, "POL_INT_SEC", offsetof(POLICY, TimeOut)},                // TimeOut
        {15, true, true, 1, 65535, 0, "POL_INT_COUNT", offsetof(POLICY, MaxMac)},              // MaxMac
        {16, true, true, 1, 65535, 0, "POL_INT_COUNT", offsetof(POLICY, MaxIP)},               // MaxIP
        {17, true, true, 1, 4294967295UL, 0, "POL_INT_BPS", offsetof(POLICY, MaxUpload)},      // MaxUpload
        {18, true, true, 1, 4294967295UL, 0, "POL_INT_BPS", offsetof(POLICY, MaxDownload)},    // MaxDownload
        {19, false, false, 0, 0, 0, NULL, offsetof(POLICY, FixPassword)},                      // FixPassword
        {20, true, true, 1, 65535, 0, "POL_INT_COUNT", offsetof(POLICY, MultiLogins)},         // MultiLogins
        {21, false, false, 0, 0, 0, NULL, offsetof(POLICY, NoQoS)},                            // NoQoS
                                                                                               // Ver 3.0
        {22, false, false, 0, 0, 0, NULL, offsetof(POLICY, RSandRAFilter)},                    // RSandRAFilter
        {23, false, false, 0, 0, 0, NULL, offsetof(POLICY, RAFilter)},                         // RAFilter
        {24, false, false, 0, 0, 0, NULL, offsetof(POLICY, DHCPv6Filter)},                     // DHCPv6Filter
        {25, false, false, 0, 0, 0, NULL, offsetof(POLICY, DHCPv6NoServer)},                   // DHCPv6NoServer
        {26, false, false, 0, 0, 0, NULL, offsetof(POLICY, NoRoutingV6)},                      // NoRoutingV6
        {27, false, false, 0, 0, 0, NULL, offsetof(POLICY, CheckIPv6)},                        // CheckIPv6
        {28, false, false, 0, 0, 0, NULL, offsetof(POLICY, NoServerV6)},                       // NoServerV6
        {29, true, true, 1, 65535, 0, "POL_INT_COUNT", offsetof(POLICY, MaxIPv6)},             // MaxIPv6
        {30, false, false, 0, 0, 0, NULL, offsetof(POLICY, NoSavePassword)},                   // NoSavePassword
        {31, true, true, 1, 4294967295UL, 0, "POL_INT_SEC", offsetof(POLICY, AutoDisconnect)}, // AutoDisconnect
        {32, false, false, 0, 0, 0, NULL, offsetof(POLICY, FilterIPv4)},                       // FilterIPv4
        {33, false, false, 0, 0, 0, NULL, offsetof(POLICY, FilterIPv6)},                       // FilterIPv6
        {34, false, false, 0, 0, 0, NULL, offsetof(POLICY, FilterNonIP)},                      // FilterNonIP
        {35, false, false, 0, 0, 0, NULL, offsetof(POLICY, NoIPv6DefaultRouterInRA)},          // NoIPv6DefaultRouterInRA
        {36, false, false, 0, 0, 0, NULL, offsetof(POLICY, NoIPv6DefaultRouterInRAWhenIPv6)},  // NoIPv6DefaultRouterInRAWhenIPv6
        {37, true, true, 1, 4095, 0, "POL_INT_VLAN", offsetof(POLICY, VLanId)},                // VLanId
};

// Format policy value
void FormatPolicyValue(wchar_t *str, UINT size, UINT id, UINT value) {
	POLICY_ITEM *p;
	// Validate arguments
	if (str == NULL) {
		return;
	}

	p = GetPolicyItem(id);

	if (p->TypeInt == false) {
		// bool type
		if (value == 0) {
			UniStrCpy(str, size, L"No");
		} else {
			UniStrCpy(str, size, L"Yes");
		}
	} else {
		// int type
		if (value == 0 && p->AllowZero) {
			UniStrCpy(str, size, _UU("CMD_NO_SETTINGS"));
		} else {
			UniFormat(str, size, _UU(p->FormatStr), value);
		}
	}
}

// Get description string for range of the policy value
void GetPolicyValueRangeStr(wchar_t *str, UINT size, UINT id) {
	POLICY_ITEM *p;
	// Validate arguments
	if (str == NULL) {
		return;
	}

	p = GetPolicyItem(id);

	if (p->TypeInt == false) {
		// bool type
		UniStrCpy(str, size, _UU("CMD_PolicyList_Range_Bool"));
	} else {
		wchar_t *tag;
		wchar_t tmp1[256], tmp2[256];

		// int type
		if (p->AllowZero) {
			tag = _UU("CMD_PolicyList_Range_Int_2");
		} else {
			tag = _UU("CMD_PolicyList_Range_Int_1");
		}

		UniFormat(tmp1, sizeof(tmp1), _UU(p->FormatStr), p->MinValue);
		UniFormat(tmp2, sizeof(tmp2), _UU(p->FormatStr), p->MaxValue);

		UniFormat(str, size, tag, tmp1, tmp2);
	}
}

// Get a policy item for id
POLICY_ITEM *GetPolicyItem(UINT id) {
	return &policy_item[id];
}

// Does cascade connection support the specified policy?
bool PolicyIsSupportedForCascade(UINT i) {
	if (i == 0 || i == 4 || i == 5 || i == 12 || i == 13 ||
	    i == 14 || i == 19 || i == 20 || i == 21 || i == 26 || i == 30 || i == 31 || i == 36) {
		// These items are not supported by cascade connection.
		return false;
	}

	return true;
}

// Get policy name
char *PolicyIdToStr(UINT i) {
	switch (i) {
	// Ver 2.0
	case 0: return "Access";
	case 1: return "DHCPFilter";
	case 2: return "DHCPNoServer";
	case 3: return "DHCPForce";
	case 4: return "NoBridge";
	case 5: return "NoRouting";
	case 6: return "CheckMac";
	case 7: return "CheckIP";
	case 8: return "ArpDhcpOnly";
	case 9: return "PrivacyFilter";
	case 10: return "NoServer";
	case 11: return "NoBroadcastLimiter";
	case 12: return "MonitorPort";
	case 13: return "MaxConnection";
	case 14: return "TimeOut";
	case 15: return "MaxMac";
	case 16: return "MaxIP";
	case 17: return "MaxUpload";
	case 18: return "MaxDownload";
	case 19: return "FixPassword";
	case 20: return "MultiLogins";
	case 21: return "NoQoS";

	// Ver 3.0
	case 22: return "RSandRAFilter";
	case 23: return "RAFilter";
	case 24: return "DHCPv6Filter";
	case 25: return "DHCPv6NoServer";
	case 26: return "NoRoutingV6";
	case 27: return "CheckIPv6";
	case 28: return "NoServerV6";
	case 29: return "MaxIPv6";
	case 30: return "NoSavePassword";
	case 31: return "AutoDisconnect";
	case 32: return "FilterIPv4";
	case 33: return "FilterIPv6";
	case 34: return "FilterNonIP";
	case 35: return "NoIPv6DefaultRouterInRA";
	case 36: return "NoIPv6DefaultRouterInRAWhenIPv6";
	case 37: return "VLanId";
	}

	return NULL;
}

// Get policy id for name
UINT PolicyStrToId(char *name) {
	UINT i;
	// Validate arguments
	if (name == NULL) {
		return INFINITE;
	}

	for (i = 0; i < NUM_POLICY_ITEM; i++) {
		if (StartWith(PolicyIdToStr(i), name)) {
			return i;
		}
	}

	return INFINITE;
}

// Get number of policies
UINT PolicyNum() {
	return NUM_POLICY_ITEM;
}

// Check the name is valid for account name
bool IsUserName(char *name) {
	UINT i, len;
	char tmp[MAX_SIZE];
	// Validate arguments
	if (name == NULL) {
		return false;
	}

	StrCpy(tmp, sizeof(tmp), name);
	name = tmp;

	Trim(name);

	len = StrLen(name);
	if (len == 0) {
		return false;
	}

	if (StrCmpi(name, "*") == 0) {
		return true;
	}

	for (i = 0; i < len; i++) {
		if (IsSafeChar(name[i]) == false && name[i] != '@') {
			return false;
		}
	}

	if (StrCmpi(name, LINK_USER_NAME) == 0) {
		return false;
	}

	if (StrCmpi(name, LINK_USER_NAME_PRINT) == 0) {
		return false;
	}

	if (StrCmpi(name, BRIDGE_USER_NAME) == 0) {
		return false;
	}

	if (StrCmpi(name, BRIDGE_USER_NAME_PRINT) == 0) {
		return false;
	}

	if (StrCmpi(name, ADMINISTRATOR_USERNAME) == 0) {
		return false;
	}

	return true;
}

// Clone the policy value
POLICY *ClonePolicy(POLICY *policy) {
	POLICY *ret;
	// Validate arguments
	if (policy == NULL) {
		return NULL;
	}

	ret = ZeroMalloc(sizeof(POLICY));
	Copy(ret, policy, sizeof(POLICY));

	return ret;
}

// Overwrite policy value (If old version data overwrites new version, leave new version value as it is.)
void OverwritePolicy(POLICY **target, POLICY *p) {
	// Validate arguments
	if (target == NULL) {
		return;
	}

	if (p == NULL) {
		// Erase policy
		if (*target != NULL) {
			Free(*target);
			*target = NULL;
		}
	} else {
		if (p->Ver3) {
			// Ver 3
			if (*target != NULL) {
				Free(*target);
				*target = NULL;
			}

			*target = ClonePolicy(p);
		} else {
			// Ver 2
			if (*target == NULL) {
				*target = ClonePolicy(p);
			} else {
				Copy(*target, p, policy_item[NUM_POLICY_ITEM_FOR_VER2].Offset);
			}
		}
	}
}

// Set user policy
void SetUserPolicy(USER *u, POLICY *policy) {
	// Validate arguments
	if (u == NULL) {
		return;
	}

	Lock(u->lock);
	{
		OverwritePolicy(&u->Policy, policy);
	}
	Unlock(u->lock);
}

// Set group policy
void SetGroupPolicy(USERGROUP *g, POLICY *policy) {
	// Validate arguments
	if (g == NULL) {
		return;
	}

	Lock(g->lock);
	{
		OverwritePolicy(&g->Policy, policy);
	}
	Unlock(g->lock);
}

// Get group policy
POLICY *GetGroupPolicy(USERGROUP *g) {
	POLICY *ret;
	// Validate arguments
	if (g == NULL) {
		return NULL;
	}

	Lock(g->lock);
	{
		if (g->Policy == NULL) {
			ret = NULL;
		} else {
			ret = ClonePolicy(g->Policy);
		}
	}
	Unlock(g->lock);

	return ret;
}

// Get default policy template
POLICY *GetDefaultPolicy() {
	static POLICY def_policy =
	    {
	        true,
	        false,
	        false,
	        false,
	        false,
	        false,
	        false,
	        false,
	        false,
	        false,
	        false,
	        false,
	        false,
	        32,
	        20,
	        0,
	        0,
	        0,
	        0,
	        false,
	        0,
	        false,
	        false,
	        false,
	        false,
	        false,
	        false,
	        false,
	        false,
	        0,
	        false,
	        0,
	        false,
	        false,
	        false,
	        false,
	        false,
	    };

	return &def_policy;
}

// Create a NT authentication data
void *NewNTAuthData(wchar_t *username) {
	AUTHNT *a;
	// Validate arguments
	a = ZeroMallocEx(sizeof(AUTHNT), true);
	a->NtUsername = CopyUniStr(username);

	return a;
}

// Create a root certification authentication data
void *NewRootCertAuthData(X_SERIAL *serial, wchar_t *common_name) {
	AUTHROOTCERT *a;

	a = ZeroMallocEx(sizeof(AUTHROOTCERT), true);
	if (common_name != NULL && UniIsEmptyStr(common_name) == false) {
		a->CommonName = CopyUniStr(common_name);
	}
	if (serial != NULL && serial->size >= 1) {
		a->Serial = CloneXSerial(serial);
	}

	return a;
}

// Create an authentication data for user certification
void *NewUserCertAuthData(X *x) {
	AUTHUSERCERT *a;

	a = ZeroMalloc(sizeof(AUTHUSERCERT));
	a->UserX = CloneX(x);

	return a;
}

// Hash the password
void HashPassword(void *dst, char *username, char *password) {
	BUF *b;
	char *username_upper;
	// Validate arguments
	if (dst == NULL || username == NULL || password == NULL) {
		return;
	}

	b = NewBuf();
	username_upper = CopyStr(username);
	StrUpper(username_upper);
	WriteBuf(b, password, StrLen(password));
	WriteBuf(b, username_upper, StrLen(username_upper));
	Sha0(dst, b->Buf, b->Size);

	FreeBuf(b);
	Free(username_upper);
}

// Create a password authentication data
void *NewPasswordAuthData(char *username, char *password) {
	AUTHPASSWORD *pw;
	// Validate arguments
	if (username == NULL || password == NULL) {
		return NULL;
	}

	pw = ZeroMalloc(sizeof(AUTHPASSWORD));
	HashPassword(pw->HashedKey, username, password);
	GenerateNtPasswordHash(pw->NtLmSecureHash, password);

	return pw;
}

// Create a password authentication data for the hashed password
void *NewPasswordAuthDataRaw(UCHAR *hashed_password, UCHAR *ntlm_secure_hash) {
	AUTHPASSWORD *pw;
	// Validate arguments
	if (hashed_password == NULL) {
		return NULL;
	}

	pw = ZeroMalloc(sizeof(AUTHPASSWORD));
	Copy(pw->HashedKey, hashed_password, SHA1_SIZE);

	if (ntlm_secure_hash != NULL) {
		Copy(pw->NtLmSecureHash, ntlm_secure_hash, MD5_SIZE);
	}

	return pw;
}

// Clone authentication data
void *CopyAuthData(void *authdata, UINT authtype) {
	AUTHPASSWORD *pw = (AUTHPASSWORD *)authdata;
	AUTHUSERCERT *usercert = (AUTHUSERCERT *)authdata;
	AUTHROOTCERT *rootcert = (AUTHROOTCERT *)authdata;
	AUTHNT *nt = (AUTHNT *)authdata;
	// Validate arguments
	if (authdata == NULL || authtype == AUTHTYPE_ANONYMOUS) {
		return NULL;
	}

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
		ret->NtUsername = UniCopyStr(nt->NtUsername);
		return ret;
	} break;
	}

	return NULL;
}

// Set authentication data to the user
void SetUserAuthData(USER *u, UINT authtype, void *authdata) {
	// Validate arguments
	if (u == NULL) {
		return;
	}
	if (authtype != AUTHTYPE_ANONYMOUS && authdata == NULL) {
		return;
	}

	Lock(u->lock);
	{
		if (u->AuthType != AUTHTYPE_ANONYMOUS) {
			if (u->AuthType == AUTHTYPE_PASSWORD && authtype == AUTHTYPE_PASSWORD) {
				AUTHPASSWORD *pw_old = (AUTHPASSWORD *)u->AuthData;
				AUTHPASSWORD *pw_new = (AUTHPASSWORD *)authdata;

				// Copy NTLM hash for new password from old data, if the password is not changed
				// and management tool don't send NTLM hash.

				if (Cmp(pw_old->HashedKey, pw_new->HashedKey, SHA1_SIZE) == 0) {
					if (IsZero(pw_new->NtLmSecureHash, MD5_SIZE)) {
						Copy(pw_new->NtLmSecureHash, pw_old->NtLmSecureHash, MD5_SIZE);
					}
				}
			}

			// Free current authentication data
			FreeAuthData(u->AuthType, u->AuthData);
		}
		// Set new authentication data
		u->AuthType = authtype;
		u->AuthData = authdata;
	}
	Unlock(u->lock);
}

// Set traffic data for group
void SetGroupTraffic(USERGROUP *g, TRAFFIC *t) {
	// Validate arguments
	if (g == NULL) {
		return;
	}

	Lock(g->lock);
	{
		if (t != NULL) {
			Copy(g->Traffic, t, sizeof(TRAFFIC));
		} else {
			Zero(g->Traffic, sizeof(TRAFFIC));
		}
	}
	Unlock(g->lock);
}

// Set traffic data for user
void SetUserTraffic(USER *u, TRAFFIC *t) {
	// Validate arguments
	if (u == NULL) {
		return;
	}

	Lock(u->lock);
	{
		if (t != NULL) {
			Copy(u->Traffic, t, sizeof(TRAFFIC));
		} else {
			Zero(u->Traffic, sizeof(TRAFFIC));
		}
	}
	Unlock(u->lock);
}

// Join the user to the group
void JoinUserToGroup(USER *u, USERGROUP *g) {
	// Validate arguments
	if (u == NULL) {
		return;
	}

	if (g != NULL) {
		// Join
		Lock(u->lock);
		{
			Lock(g->lock);
			{
				if (u->Group != NULL) {
					// Remove the user from current group first
					//
					ReleaseGroup(u->Group);
					u->Group = NULL;
					Free(u->GroupName);
					u->GroupName = NULL;
				}
				// Join the user to the group
				u->GroupName = CopyStr(g->Name);
				u->Group = g;
				AddRef(g->ref);
			}
			Unlock(g->lock);
		}
		Unlock(u->lock);
	} else {
		// Withdrawal
		Lock(u->lock);
		{
			if (u->Group != NULL) {
				// Remove the user from current group
				ReleaseGroup(u->Group);
				u->Group = NULL;
				Free(u->GroupName);
				u->GroupName = NULL;
			}
		}
		Unlock(u->lock);
	}
}

// Validate group name
bool AcIsGroup(HUB *h, char *name) {
	USERGROUP *g;
	// Validate arguments
	if (h == NULL || name == NULL) {
		return false;
	}

	g = AcGetGroup(h, name);
	if (g == NULL) {
		return false;
	}
	ReleaseGroup(g);

	return true;
}

// Validate user name
bool AcIsUser(HUB *h, char *name) {
	USER *u;
	// Validate arguments
	if (h == NULL || name == NULL) {
		return false;
	}

	u = AcGetUser(h, name);
	if (u == NULL) {
		return false;
	}
	ReleaseUser(u);

	return true;
}

// Get group object
USERGROUP *AcGetGroup(HUB *h, char *name) {
	USERGROUP *g, t;
	// Validate arguments
	if (h == NULL || name == NULL) {
		return NULL;
	}

	t.Name = name;
	g = Search(h->HubDb->GroupList, &t);
	if (g == NULL) {
		return NULL;
	}
	AddRef(g->ref);

	return g;
}

// Get user object
USER *AcGetUser(HUB *h, char *name) {
	USER *u, t;
	// Validate arguments
	if (h == NULL || name == NULL) {
		return NULL;
	}

	t.Name = name;
	u = Search(h->HubDb->UserList, &t);
	if (u == NULL) {
		return NULL;
	}
	AddRef(u->ref);

	return u;
}

// Delete the user
bool AcDeleteUser(HUB *h, char *name) {
	USER *u;
	// Validate arguments
	if (h == NULL || name == NULL) {
		return false;
	}

	u = AcGetUser(h, name);
	if (u == NULL) {
		return false;
	}

	if (Delete(h->HubDb->UserList, u)) {
		ReleaseUser(u);
	}

	ReleaseUser(u);

	return true;
}

// Delete the group
bool AcDeleteGroup(HUB *h, char *name) {
	USERGROUP *g;
	UINT i;
	// Validate arguments
	if (h == NULL || name == NULL) {
		return false;
	}

	g = AcGetGroup(h, name);
	if (g == NULL) {
		return false;
	}

	if (Delete(h->HubDb->GroupList, g)) {
		ReleaseGroup(g);
	}

	for (i = 0; i < LIST_NUM(h->HubDb->UserList); i++) {
		USER *u = LIST_DATA(h->HubDb->UserList, i);
		Lock(u->lock);
		{
			if (u->Group == g) {
				JoinUserToGroup(u, NULL);
			}
		}
		Unlock(u->lock);
	}

	ReleaseGroup(g);

	return true;
}

// Add new group to the hub
bool AcAddGroup(HUB *h, USERGROUP *g) {
	// Validate arguments
	if (h == NULL || g == NULL) {
		return false;
	}

	if (LIST_NUM(h->HubDb->GroupList) >= MAX_GROUPS) {
		return false;
	}

	if (AcIsGroup(h, g->Name) != false) {
		return false;
	}

	Insert(h->HubDb->GroupList, g);
	AddRef(g->ref);

	return true;
}

// Add new user in the hub
bool AcAddUser(HUB *h, USER *u) {
	// Validate arguments
	if (h == NULL || u == NULL) {
		return false;
	}

	if (LIST_NUM(h->HubDb->UserList) >= MAX_USERS) {
		return false;
	}

	if (AcIsUser(h, u->Name) != false) {
		return false;
	}

	Insert(h->HubDb->UserList, u);
	AddRef(u->ref);

	return true;
}

// Release user object (decrease reference counter)
void ReleaseUser(USER *u) {
	// Validate arguments
	if (u == NULL) {
		return;
	}

	if (Release(u->ref) == 0) {
		CleanupUser(u);
	}
}

// Cleanup the user object
void CleanupUser(USER *u) {
	// Validate arguments
	if (u == NULL) {
		return;
	}

	DeleteLock(u->lock);
	Free(u->Name);
	Free(u->RealName);
	Free(u->Note);
	Free(u->GroupName);
	if (u->Group != NULL) {
		ReleaseGroup(u->Group);
	}

	// Free authentication data
	FreeAuthData(u->AuthType, u->AuthData);

	if (u->Policy) {
		// Free policy data
		Free(u->Policy);
	}

	FreeTraffic(u->Traffic);

	Free(u);
}

// Free authentication data
void FreeAuthData(UINT authtype, void *authdata) {
	AUTHPASSWORD *pw = (AUTHPASSWORD *)authdata;
	AUTHUSERCERT *uc = (AUTHUSERCERT *)authdata;
	AUTHROOTCERT *rc = (AUTHROOTCERT *)authdata;
	AUTHNT *nt = (AUTHNT *)authdata;
	// Validate arguments
	if (authtype == AUTHTYPE_ANONYMOUS || authdata == NULL) {
		return;
	}

	switch (authtype) {
	case AUTHTYPE_PASSWORD:
		// Password authentication
		// Nothing to free
		break;

	case AUTHTYPE_USERCERT:
		// User certification
		FreeX(uc->UserX);
		break;

	case AUTHTYPE_ROOTCERT:
		// Root certification
		if (rc->Serial != NULL) {
			FreeXSerial(rc->Serial);
		}
		if (rc->CommonName != NULL) {
			Free(rc->CommonName);
		}
		break;

	case AUTHTYPE_NT:
		// Windows NT authentication
		Free(nt->NtUsername);
		break;
	}

	Free(authdata);
}

// Create new user object
USER *NewUser(char *name, wchar_t *realname, wchar_t *note, UINT authtype, void *authdata) {
	USER *u;
	// Validate arguments
	if (name == NULL || realname == NULL || note == NULL) {
		return NULL;
	}
	if (authtype != AUTHTYPE_ANONYMOUS && authdata == NULL) {
		return NULL;
	}

	u = ZeroMalloc(sizeof(USER));
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

// Release group object (decrease reference counter)
void ReleaseGroup(USERGROUP *g) {
	// Validate arguments
	if (g == NULL) {
		return;
	}

	if (Release(g->ref) == 0) {
		CleanupGroup(g);
	}
}

// Cleanup the group object
void CleanupGroup(USERGROUP *g) {
	// Validate arguments
	if (g == NULL) {
		return;
	}

	Free(g->Name);
	Free(g->RealName);
	Free(g->Note);

	if (g->Policy) {
		// Free policy data
		Free(g->Policy);
	}


	FreeTraffic(g->Traffic);

	DeleteLock(g->lock);
	Free(g);
}

// Create new group object
USERGROUP *NewGroup(char *name, wchar_t *realname, wchar_t *note) {
	USERGROUP *g;
	// Validate arguments
	if (name == NULL || realname == NULL || note == NULL) {
		return NULL;
	}

	g = ZeroMalloc(sizeof(USERGROUP));
	g->lock = NewLock();
	g->ref = NewRef();
	g->Name = CopyStr(name);
	g->RealName = CopyUniStr(realname);
	g->Note = CopyUniStr(note);
	g->Policy = NULL;
	g->Traffic = NewTraffic();

	return g;
}

// Lock the account database for the hub
void AcLock(HUB *h) {
	// Validate arguments
	if (h == NULL) {
		return;
	}
	// Lock group list and user list
	LockList(h->HubDb->GroupList);
	LockList(h->HubDb->UserList);
}

// Unlock the account database for the hub
void AcUnlock(HUB *h) {
	// Validate arguments
	if (h == NULL) {
		return;
	}
	// Unlock group list and user list
	UnlockList(h->HubDb->UserList);
	UnlockList(h->HubDb->GroupList);
}

// Compare group names (for sort)
int CompareGroupName(void *p1, void *p2) {
	USERGROUP *g1, *g2;
	// Validate arguments
	if (p1 == NULL || p2 == NULL) {
		return 0;
	}
	g1 = *(USERGROUP **)p1;
	g2 = *(USERGROUP **)p2;
	if (g1 == NULL || g2 == NULL) {
		return 0;
	}

	return StrCmpi(g1->Name, g2->Name);
}

// Compare user names (for sort)
int CompareUserName(void *p1, void *p2) {
	USER *u1, *u2;
	// Validate arguments
	if (p1 == NULL || p2 == NULL) {
		return 0;
	}
	u1 = *(USER **)p1;
	u2 = *(USER **)p2;
	if (u1 == NULL || u2 == NULL) {
		return 0;
	}

	return StrCmpi(u1->Name, u2->Name);
}

// ----------------------------------------------------------------------
// Client-side account data (cascade connections)
//   Connection settings, authentication data and connection status of
//   the client side of a session. Used by cascade connections (Link),
//   their configuration and their administration RPCs.
// ----------------------------------------------------------------------

// TRAFFIC_EX
void InRpcTrafficEx(TRAFFIC *t, PACK *p, UINT i) {
	// Validate arguments
	if (t == NULL || p == NULL) {
		return;
	}

	Zero(t, sizeof(TRAFFIC));
	t->Recv.BroadcastBytes = PackGetInt64Ex(p, "Ex.Recv.BroadcastBytes", i);
	t->Recv.BroadcastCount = PackGetInt64Ex(p, "Ex.Recv.BroadcastCount", i);
	t->Recv.UnicastBytes = PackGetInt64Ex(p, "Ex.Recv.UnicastBytes", i);
	t->Recv.UnicastCount = PackGetInt64Ex(p, "Ex.Recv.UnicastCount", i);
	t->Send.BroadcastBytes = PackGetInt64Ex(p, "Ex.Send.BroadcastBytes", i);
	t->Send.BroadcastCount = PackGetInt64Ex(p, "Ex.Send.BroadcastCount", i);
	t->Send.UnicastBytes = PackGetInt64Ex(p, "Ex.Send.UnicastBytes", i);
	t->Send.UnicastCount = PackGetInt64Ex(p, "Ex.Send.UnicastCount", i);
}
void OutRpcTrafficEx(TRAFFIC *t, PACK *p, UINT i, UINT num) {
	// Validate arguments
	if (t == NULL || p == NULL) {
		return;
	}

	PackAddInt64Ex(p, "Ex.Recv.BroadcastBytes", t->Recv.BroadcastBytes, i, num);
	PackAddInt64Ex(p, "Ex.Recv.BroadcastCount", t->Recv.BroadcastCount, i, num);
	PackAddInt64Ex(p, "Ex.Recv.UnicastBytes", t->Recv.UnicastBytes, i, num);
	PackAddInt64Ex(p, "Ex.Recv.UnicastCount", t->Recv.UnicastCount, i, num);
	PackAddInt64Ex(p, "Ex.Send.BroadcastBytes", t->Send.BroadcastBytes, i, num);
	PackAddInt64Ex(p, "Ex.Send.BroadcastCount", t->Send.BroadcastCount, i, num);
	PackAddInt64Ex(p, "Ex.Send.UnicastBytes", t->Send.UnicastBytes, i, num);
	PackAddInt64Ex(p, "Ex.Send.UnicastCount", t->Send.UnicastCount, i, num);
}

// TRAFFIC
void InRpcTraffic(TRAFFIC *t, PACK *p) {
	// Validate arguments
	if (t == NULL || p == NULL) {
		return;
	}

	Zero(t, sizeof(TRAFFIC));
	t->Recv.BroadcastBytes = PackGetInt64(p, "Recv.BroadcastBytes");
	t->Recv.BroadcastCount = PackGetInt64(p, "Recv.BroadcastCount");
	t->Recv.UnicastBytes = PackGetInt64(p, "Recv.UnicastBytes");
	t->Recv.UnicastCount = PackGetInt64(p, "Recv.UnicastCount");
	t->Send.BroadcastBytes = PackGetInt64(p, "Send.BroadcastBytes");
	t->Send.BroadcastCount = PackGetInt64(p, "Send.BroadcastCount");
	t->Send.UnicastBytes = PackGetInt64(p, "Send.UnicastBytes");
	t->Send.UnicastCount = PackGetInt64(p, "Send.UnicastCount");
}
void OutRpcTraffic(PACK *p, TRAFFIC *t) {
	// Validate arguments
	if (t == NULL || p == NULL) {
		return;
	}

	PackAddInt64(p, "Recv.BroadcastBytes", t->Recv.BroadcastBytes);
	PackAddInt64(p, "Recv.BroadcastCount", t->Recv.BroadcastCount);
	PackAddInt64(p, "Recv.UnicastBytes", t->Recv.UnicastBytes);
	PackAddInt64(p, "Recv.UnicastCount", t->Recv.UnicastCount);
	PackAddInt64(p, "Send.BroadcastBytes", t->Send.BroadcastBytes);
	PackAddInt64(p, "Send.BroadcastCount", t->Send.BroadcastCount);
	PackAddInt64(p, "Send.UnicastBytes", t->Send.UnicastBytes);
	PackAddInt64(p, "Send.UnicastCount", t->Send.UnicastCount);
}

// CLIENT_OPTION
void InRpcClientOption(CLIENT_OPTION *c, PACK *p) {
	// Validate arguments
	if (c == NULL || p == NULL) {
		return;
	}

	Zero(c, sizeof(CLIENT_OPTION));

	PackGetUniStr(p, "AccountName", c->AccountName, sizeof(c->AccountName));
	PackGetStr(p, "Hostname", c->Hostname, sizeof(c->Hostname));
	c->Port = PackGetInt(p, "Port");
	c->PortUDP = PackGetInt(p, "PortUDP");
	c->ProxyType = PackGetInt(p, "ProxyType");
	c->ProxyPort = PackGetInt(p, "ProxyPort");
	c->NumRetry = PackGetInt(p, "NumRetry");
	c->RetryInterval = PackGetInt(p, "RetryInterval");
	c->MaxConnection = PackGetInt(p, "MaxConnection");
	c->AdditionalConnectionInterval = PackGetInt(p, "AdditionalConnectionInterval");
	c->ConnectionDisconnectSpan = PackGetInt(p, "ConnectionDisconnectSpan");
	c->HideStatusWindow = PackGetBool(p, "HideStatusWindow");
	c->HideNicInfoWindow = PackGetBool(p, "HideNicInfoWindow");
	c->DisableQoS = PackGetBool(p, "DisableQoS");
	PackGetStr(p, "ProxyName", c->ProxyName, sizeof(c->ProxyName));
	PackGetStr(p, "ProxyUsername", c->ProxyUsername, sizeof(c->ProxyUsername));
	PackGetStr(p, "ProxyPassword", c->ProxyPassword, sizeof(c->ProxyPassword));
	PackGetStr(p, "CustomHttpHeader", c->CustomHttpHeader, sizeof(c->CustomHttpHeader));
	PackGetStr(p, "HubName", c->HubName, sizeof(c->HubName));
	PackGetStr(p, "DeviceName", c->DeviceName, sizeof(c->DeviceName));
	PackGetIp(p, "BindLocalIP", &c->BindLocalIP);      // Source IP address for outgoing connection
	c->BindLocalPort = PackGetInt(p, "BindLocalPort"); // Source port nubmer for outgoing connection

	c->UseEncrypt = PackGetInt(p, "UseEncrypt") ? true : false;
	c->UseCompress = PackGetInt(p, "UseCompress") ? true : false;
	c->HalfConnection = PackGetInt(p, "HalfConnection") ? true : false;
	c->NoRoutingTracking = PackGetInt(p, "NoRoutingTracking") ? true : false;
	c->RequireMonitorMode = PackGetBool(p, "RequireMonitorMode");
	c->RequireBridgeRoutingMode = PackGetBool(p, "RequireBridgeRoutingMode");
	c->FromAdminPack = PackGetBool(p, "FromAdminPack");
	c->NoUdpAcceleration = PackGetBool(p, "NoUdpAcceleration");
	PackGetData2(p, "HostUniqueKey", c->HostUniqueKey, SHA1_SIZE);
}
void OutRpcClientOption(PACK *p, CLIENT_OPTION *c) {
	// Validate arguments
	if (c == NULL || p == NULL) {
		return;
	}

	PackAddUniStr(p, "AccountName", c->AccountName);
	PackAddStr(p, "Hostname", c->Hostname);
	PackAddStr(p, "ProxyName", c->ProxyName);
	PackAddStr(p, "ProxyUsername", c->ProxyUsername);
	PackAddStr(p, "ProxyPassword", c->ProxyPassword);
	PackAddStr(p, "CustomHttpHeader", c->CustomHttpHeader);
	PackAddStr(p, "HubName", c->HubName);
	PackAddStr(p, "DeviceName", c->DeviceName);
	PackAddInt(p, "Port", c->Port);
	PackAddInt(p, "PortUDP", c->PortUDP);
	PackAddInt(p, "ProxyType", c->ProxyType);
	PackAddInt(p, "ProxyPort", c->ProxyPort);
	PackAddInt(p, "NumRetry", c->NumRetry);
	PackAddInt(p, "RetryInterval", c->RetryInterval);
	PackAddInt(p, "MaxConnection", c->MaxConnection);
	PackAddBool(p, "UseEncrypt", c->UseEncrypt);
	PackAddBool(p, "UseCompress", c->UseCompress);
	PackAddBool(p, "HalfConnection", c->HalfConnection);
	PackAddBool(p, "NoRoutingTracking", c->NoRoutingTracking);
	PackAddInt(p, "AdditionalConnectionInterval", c->AdditionalConnectionInterval);
	PackAddInt(p, "ConnectionDisconnectSpan", c->ConnectionDisconnectSpan);
	PackAddBool(p, "HideStatusWindow", c->HideStatusWindow);
	PackAddBool(p, "HideNicInfoWindow", c->HideNicInfoWindow);
	PackAddBool(p, "RequireMonitorMode", c->RequireMonitorMode);
	PackAddBool(p, "RequireBridgeRoutingMode", c->RequireBridgeRoutingMode);
	PackAddBool(p, "DisableQoS", c->DisableQoS);
	PackAddBool(p, "FromAdminPack", c->FromAdminPack);
	PackAddBool(p, "NoUdpAcceleration", c->NoUdpAcceleration);
	PackAddData(p, "HostUniqueKey", c->HostUniqueKey, SHA1_SIZE);
	PackAddIp(p, "BindLocalIP", &c->BindLocalIP);     // Source IP address for outgoing connection
	PackAddInt(p, "BindLocalPort", c->BindLocalPort); // Source port number for outgoing connection
}

// CLIENT_AUTH
void InRpcClientAuth(CLIENT_AUTH *c, PACK *p) {
	BUF *b;
	// Validate arguments
	if (c == NULL || p == NULL) {
		return;
	}

	Zero(c, sizeof(CLIENT_AUTH));
	c->AuthType = PackGetInt(p, "AuthType");
	PackGetStr(p, "Username", c->Username, sizeof(c->Username));

	switch (c->AuthType) {
	case CLIENT_AUTHTYPE_ANONYMOUS:
		break;

	case CLIENT_AUTHTYPE_PASSWORD:
		if (PackGetDataSize(p, "HashedPassword") == SHA1_SIZE) {
			PackGetData(p, "HashedPassword", c->HashedPassword);
		}
		break;

	case CLIENT_AUTHTYPE_PLAIN_PASSWORD:
		PackGetStr(p, "PlainPassword", c->PlainPassword, sizeof(c->PlainPassword));
		break;

	case CLIENT_AUTHTYPE_CERT:
		b = PackGetBuf(p, "ClientX");
		if (b != NULL) {
			c->ClientX = BufToX(b, false);
			FreeBuf(b);
		}
		b = PackGetBuf(p, "ClientK");
		if (b != NULL) {
			c->ClientK = BufToK(b, true, false, NULL);
			FreeBuf(b);
		}
		break;

	case CLIENT_AUTHTYPE_OPENSSLENGINE:
		b = PackGetBuf(p, "ClientX");
		if (b != NULL) {
			c->ClientX = BufToX(b, false);
			FreeBuf(b);
		}
		PackGetStr(p, "OpensslEnginePrivateKeyName", c->OpensslEnginePrivateKeyName, sizeof(c->OpensslEnginePrivateKeyName));
		PackGetStr(p, "OpensslEngineName", c->OpensslEngineName, sizeof(c->OpensslEngineName));
		break;
	}
}
void OutRpcClientAuth(PACK *p, CLIENT_AUTH *c) {
	BUF *b;
	// Validate arguments
	if (c == NULL || p == NULL) {
		return;
	}

	PackAddInt(p, "AuthType", c->AuthType);
	PackAddStr(p, "Username", c->Username);

	switch (c->AuthType) {
	case CLIENT_AUTHTYPE_ANONYMOUS:
		break;

	case CLIENT_AUTHTYPE_PASSWORD:
		PackAddData(p, "HashedPassword", c->HashedPassword, SHA1_SIZE);
		break;

	case CLIENT_AUTHTYPE_PLAIN_PASSWORD:
		PackAddStr(p, "PlainPassword", c->PlainPassword);
		break;

	case CLIENT_AUTHTYPE_CERT:
		b = XToBuf(c->ClientX, false);
		if (b != NULL) {
			PackAddBuf(p, "ClientX", b);
			FreeBuf(b);
		}
		b = KToBuf(c->ClientK, false, NULL);
		if (b != NULL) {
			PackAddBuf(p, "ClientK", b);
			FreeBuf(b);
		}
		break;

	case CLIENT_AUTHTYPE_OPENSSLENGINE:
		b = XToBuf(c->ClientX, false);
		if (b != NULL) {
			PackAddBuf(p, "ClientX", b);
			FreeBuf(b);
		}
		PackAddStr(p, "OpensslEnginePrivateKeyName", c->OpensslEnginePrivateKeyName);
		PackAddStr(p, "OpensslEngineName", c->OpensslEngineName);
		break;
	}
}

// POLICY
void InRpcPolicy(POLICY *o, PACK *p) {
	POLICY *pol;
	// Validate arguments
	if (o == NULL || p == NULL) {
		return;
	}

	pol = PackGetPolicy(p);
	Copy(o, pol, sizeof(POLICY));
	Free(pol);
}
void OutRpcPolicy(PACK *p, POLICY *o) {
	// Validate arguments
	if (o == NULL || p == NULL) {
		return;
	}

	PackAddPolicy(p, o);
}

// RPC_CLIENT_GET_CONNECTION_STATUS
void InRpcClientGetConnectionStatus(RPC_CLIENT_GET_CONNECTION_STATUS *s, PACK *p) {
	BUF *b;
	// Validate arguments
	if (s == NULL || p == NULL) {
		return;
	}

	Zero(s, sizeof(RPC_CLIENT_GET_CONNECTION_STATUS));

	PackGetUniStr(p, "AccountName", s->AccountName, sizeof(s->AccountName));

	PackGetStr(p, "ServerName", s->ServerName, sizeof(s->ServerName));
	PackGetStr(p, "ServerProductName", s->ServerProductName, sizeof(s->ServerProductName));
	PackGetStr(p, "ProtocolVersion", s->ProtocolName, sizeof(s->ProtocolName));
	PackGetStr(p, "CipherName", s->CipherName, sizeof(s->CipherName));
	PackGetStr(p, "SessionName", s->SessionName, sizeof(s->SessionName));
	PackGetStr(p, "ConnectionName", s->ConnectionName, sizeof(s->ConnectionName));

	if (PackGetDataSize(p, "SessionKey") == SHA1_SIZE) {
		PackGetData(p, "SessionKey", s->SessionKey);
	}

	s->SessionStatus = PackGetInt(p, "SessionStatus");
	s->ServerPort = PackGetInt(p, "ServerPort");
	s->ServerProductVer = PackGetInt(p, "ServerProductVer");
	s->ServerProductBuild = PackGetInt(p, "ServerProductBuild");
	s->NumConnectionsEstablished = PackGetInt(p, "NumConnectionsEstablished");
	s->MaxTcpConnections = PackGetInt(p, "MaxTcpConnections");
	s->NumTcpConnections = PackGetInt(p, "NumTcpConnections");
	s->NumTcpConnectionsUpload = PackGetInt(p, "NumTcpConnectionsUpload");
	s->NumTcpConnectionsDownload = PackGetInt(p, "NumTcpConnectionsDownload");

	s->StartTime = PackGetInt64(p, "StartTime");
	/* !!! Do not correct the spelling to keep the backward protocol compatibility !!!  */
	s->FirstConnectionEstablisiedTime = PackGetInt64(p, "FirstConnectionEstablisiedTime");
	s->CurrentConnectionEstablishTime = PackGetInt64(p, "CurrentConnectionEstablishTime");
	s->TotalSendSize = PackGetInt64(p, "TotalSendSize");
	s->TotalRecvSize = PackGetInt64(p, "TotalRecvSize");
	s->TotalSendSizeReal = PackGetInt64(p, "TotalSendSizeReal");
	s->TotalRecvSizeReal = PackGetInt64(p, "TotalRecvSizeReal");

	s->Active = PackGetInt(p, "Active") ? true : false;
	s->Connected = PackGetInt(p, "Connected") ? true : false;
	s->HalfConnection = PackGetInt(p, "HalfConnection") ? true : false;
	s->QoS = PackGetInt(p, "QoS") ? true : false;
	s->UseEncrypt = PackGetInt(p, "UseEncrypt") ? true : false;
	s->UseCompress = PackGetInt(p, "UseCompress") ? true : false;
	PackGetStr(p, "UnderlayProtocol", s->UnderlayProtocol, sizeof(s->UnderlayProtocol));
	PackGetStr(p, "ProtocolDetails", s->ProtocolDetails, sizeof(s->ProtocolDetails));
	s->IsUdpAccelerationEnabled = PackGetInt(p, "IsUdpAccelerationEnabled") ? true : false;
	s->IsUsingUdpAcceleration = PackGetInt(p, "IsUsingUdpAcceleration") ? true : false;

	s->IsBridgeMode = PackGetBool(p, "IsBridgeMode");
	s->IsMonitorMode = PackGetBool(p, "IsMonitorMode");

	s->VLanId = PackGetInt(p, "VLanId");

	b = PackGetBuf(p, "ServerX");
	if (b != NULL) {
		s->ServerX = BufToX(b, false);
		FreeBuf(b);
	}

	b = PackGetBuf(p, "ClientX");
	if (b != NULL) {
		s->ClientX = BufToX(b, false);
		FreeBuf(b);
	}

	InRpcPolicy(&s->Policy, p);

	InRpcTraffic(&s->Traffic, p);
}
void OutRpcClientGetConnectionStatus(PACK *p, RPC_CLIENT_GET_CONNECTION_STATUS *c) {
	BUF *b;
	// Validate arguments
	if (p == NULL || c == NULL) {
		return;
	}

	PackAddUniStr(p, "AccountName", c->AccountName);

	PackAddStr(p, "ServerName", c->ServerName);
	PackAddStr(p, "ServerProductName", c->ServerProductName);
	PackAddStr(p, "ProtocolVersion", c->ProtocolName);
	PackAddStr(p, "CipherName", c->CipherName);
	PackAddStr(p, "SessionName", c->SessionName);
	PackAddStr(p, "ConnectionName", c->ConnectionName);

	PackAddData(p, "SessionKey", c->SessionKey, SHA1_SIZE);

	PackAddBool(p, "Active", c->Active);
	PackAddBool(p, "Connected", c->Connected);
	PackAddInt(p, "SessionStatus", c->SessionStatus);
	PackAddInt(p, "ServerPort", c->ServerPort);
	PackAddInt(p, "ServerProductVer", c->ServerProductVer);
	PackAddInt(p, "ServerProductBuild", c->ServerProductBuild);
	PackAddInt(p, "NumConnectionsEstablished", c->NumConnectionsEstablished);
	PackAddBool(p, "HalfConnection", c->HalfConnection);
	PackAddBool(p, "QoS", c->QoS);
	PackAddInt(p, "MaxTcpConnections", c->MaxTcpConnections);
	PackAddInt(p, "NumTcpConnections", c->NumTcpConnections);
	PackAddInt(p, "NumTcpConnectionsUpload", c->NumTcpConnectionsUpload);
	PackAddInt(p, "NumTcpConnectionsDownload", c->NumTcpConnectionsDownload);
	PackAddBool(p, "UseEncrypt", c->UseEncrypt);
	PackAddBool(p, "UseCompress", c->UseCompress);
	PackAddStr(p, "UnderlayProtocol", c->UnderlayProtocol);
	PackAddStr(p, "ProtocolDetails", c->ProtocolDetails);
	PackAddBool(p, "IsUdpAccelerationEnabled", c->IsUdpAccelerationEnabled);
	PackAddBool(p, "IsUsingUdpAcceleration", c->IsUsingUdpAcceleration);

	PackAddBool(p, "IsBridgeMode", c->IsBridgeMode);
	PackAddBool(p, "IsMonitorMode", c->IsMonitorMode);

	PackAddTime64(p, "StartTime", c->StartTime);
	PackAddTime64(p, "FirstConnectionEstablisiedTime", c->FirstConnectionEstablisiedTime);
	PackAddTime64(p, "CurrentConnectionEstablishTime", c->CurrentConnectionEstablishTime);
	PackAddInt64(p, "TotalSendSize", c->TotalSendSize);
	PackAddInt64(p, "TotalRecvSize", c->TotalRecvSize);
	PackAddInt64(p, "TotalSendSizeReal", c->TotalSendSizeReal);
	PackAddInt64(p, "TotalRecvSizeReal", c->TotalRecvSizeReal);

	PackAddInt(p, "VLanId", c->VLanId);

	OutRpcPolicy(p, &c->Policy);

	OutRpcTraffic(p, &c->Traffic);

	if (c->ServerX != NULL) {
		b = XToBuf(c->ServerX, false);
		PackAddBuf(p, "ServerX", b);
		FreeBuf(b);
	}

	if (c->ClientX != NULL) {
		b = XToBuf(c->ClientX, false);
		PackAddBuf(p, "ClientX", b);
		FreeBuf(b);
	}
}

// Get a RPC_CLIENT_GET_CONNECTION_STATUS from the session
void CiGetSessionStatus(RPC_CLIENT_GET_CONNECTION_STATUS *st, SESSION *s) {
	// Validate arguments
	if (st == NULL || s == NULL) {
		return;
	}

	Lock(s->lock);
	{
		// Operation flag
		st->Active = true;

		// Session status
		st->SessionStatus = s->ClientStatus;

		// Account name
		UniStrCpy(st->AccountName, sizeof(st->AccountName), s->ClientOption->AccountName);

		if (s->ClientStatus == CLIENT_STATUS_ESTABLISHED && s->Connection != NULL) {
			Lock(s->Connection->lock);
			{
				// Connected flag
				st->Connected = true;
				// Product name
				StrCpy(st->ServerProductName, sizeof(st->ServerProductName), s->Connection->ServerStr);
				// Version
				st->ServerProductVer = s->Connection->ServerVer;
				// Build Number
				st->ServerProductBuild = s->Connection->ServerBuild;
				// Server certificate
				st->ServerX = CloneX(s->Connection->ServerX);
				// Client certificate
				st->ClientX = CloneX(s->Connection->ClientX);
				// Connection completion time of this connection
				st->CurrentConnectionEstablishTime = TickToTime(s->CurrentConnectionEstablishTime);
				// Maximum number of the TCP connections
				st->MaxTcpConnections = s->MaxConnection;
				// Half-connection
				st->HalfConnection = s->HalfConnection;
				// VLAN
				st->VLanId = s->VLanId;
				// VoIP / QoS
				st->QoS = s->QoS;
				if (s->Connection->Protocol == CONNECTION_TCP) {
					UINT i;
					// Number of current TCP connections
					LockList(s->Connection->Tcp->TcpSockList);
					{
						st->NumTcpConnections = LIST_NUM(s->Connection->Tcp->TcpSockList);
						if (st->HalfConnection) {
							for (i = 0; i < st->NumTcpConnections; i++) {
								TCPSOCK *ts = LIST_DATA(s->Connection->Tcp->TcpSockList, i);
								if (ts->Direction & TCP_SERVER_TO_CLIENT) {
									st->NumTcpConnectionsDownload++;
								} else {
									st->NumTcpConnectionsUpload++;
								}
							}
						}
					}
					UnlockList(s->Connection->Tcp->TcpSockList);
				}
				// Use of encryption
				st->UseEncrypt = s->UseEncrypt;
				if (st->UseEncrypt) {
					StrCpy(st->CipherName, sizeof(st->CipherName), s->Connection->CipherName);
					StrCpy(st->ProtocolName, sizeof(st->ProtocolName), s->Connection->SslVersion);
				}
				// Use of compression
				st->UseCompress = s->UseCompress;
				// Physical communication protocol
				StrCpy(st->UnderlayProtocol, sizeof(st->UnderlayProtocol), s->UnderlayProtocol);
				// Protocol details
				StrCpy(st->ProtocolDetails, sizeof(st->ProtocolDetails), s->ProtocolDetails);
				Trim(st->ProtocolDetails);
				// UDP acceleration function
				st->IsUdpAccelerationEnabled = s->UseUdpAcceleration;
				st->IsUsingUdpAcceleration = s->IsUsingUdpAcceleration;
				// Session key
				Copy(st->SessionKey, s->SessionKey, SHA1_SIZE);
				// Policy
				Copy(&st->Policy, s->Policy, sizeof(POLICY));
				// Data size
				if (s->ServerMode == false) {
					st->TotalSendSize = s->TotalSendSize;
					st->TotalRecvSize = s->TotalRecvSize;
					st->TotalRecvSizeReal = s->TotalRecvSizeReal;
					st->TotalSendSizeReal = s->TotalSendSizeReal;
				} else {
					st->TotalSendSize = s->TotalRecvSize;
					st->TotalRecvSize = s->TotalSendSize;
					st->TotalRecvSizeReal = s->TotalSendSizeReal;
					st->TotalSendSizeReal = s->TotalRecvSizeReal;
				}
				// Session name
				StrCpy(st->SessionName, sizeof(st->SessionName), s->Name);
				// Connection name
				StrCpy(st->ConnectionName, sizeof(st->ConnectionName), s->Connection->Name);
				// Server name
				StrCpy(st->ServerName, sizeof(st->ServerName), s->Connection->ServerName);
				// Port number
				st->ServerPort = s->Connection->ServerPort;
				// Traffic data
				Lock(s->TrafficLock);
				{
					Copy(&st->Traffic, s->Traffic, sizeof(TRAFFIC));
				}
				Unlock(s->TrafficLock);

				st->IsBridgeMode = s->IsBridgeMode;
				st->IsMonitorMode = s->IsMonitorMode;
			}
			Unlock(s->Connection->lock);
		}
		// Connection start time
		st->StartTime = TickToTime(s->CreatedTime);
		// Connection completion time of the first connection
		/* !!! Do not correct the spelling to keep the backward protocol compatibility !!!  */
		st->FirstConnectionEstablisiedTime = TickToTime(s->FirstConnectionEstablisiedTime);
		// Number of connections have been established so far
		st->NumConnectionsEstablished = s->NumConnectionsEstablished;
	}
	Unlock(s->lock);
}

// Release the connection status
void CiFreeClientGetConnectionStatus(RPC_CLIENT_GET_CONNECTION_STATUS *st) {
	// Validate arguments
	if (st == NULL) {
		return;
	}

	if (st->ServerX != NULL) {
		FreeX(st->ServerX);
	}

	if (st->ClientX != NULL) {
		FreeX(st->ClientX);
	}
}

// Release the client authentication data
void CiFreeClientAuth(CLIENT_AUTH *auth) {
	// Validate arguments
	if (auth == NULL) {
		return;
	}

	if (auth->ClientX != NULL) {
		FreeX(auth->ClientX);
	}
	if (auth->ClientK != NULL) {
		FreeK(auth->ClientK);
	}

	Free(auth);
}

// Read the client authentication data
CLIENT_AUTH *CiLoadClientAuth(FOLDER *f) {
	CLIENT_AUTH *a;
	char *s;
	BUF *b;
	// Validate arguments
	if (f == NULL) {
		return NULL;
	}

	a = ZeroMalloc(sizeof(CLIENT_AUTH));

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
		if (b != NULL) {
			a->ClientX = BufToX(b, false);
		}
		FreeBuf(b);
		b = CfgGetBuf(f, "ClientKey");
		if (b != NULL) {
			a->ClientK = BufToK(b, true, false, NULL);
		}
		FreeBuf(b);
		break;

	case CLIENT_AUTHTYPE_OPENSSLENGINE:
		b = CfgGetBuf(f, "ClientCert");
		if (b != NULL) {
			a->ClientX = BufToX(b, false);
		}
		FreeBuf(b);
		if (CfgGetStr(f, "OpensslEnginePrivateKeyName", a->OpensslEnginePrivateKeyName, sizeof(a->OpensslEnginePrivateKeyName))) {
			a->ClientK = OpensslEngineToK(a->OpensslEnginePrivateKeyName, a->OpensslEngineName);
		}
		CfgGetStr(f, "OpensslEngineName", a->OpensslEngineName, sizeof(a->OpensslEngineName));
		break;
	}

	return a;
}

// Read the client option
CLIENT_OPTION *CiLoadClientOption(FOLDER *f) {
	CLIENT_OPTION *o;
	char *s;
	BUF *b;
	// Validate arguments
	if (f == NULL) {
		return NULL;
	}

	o = ZeroMalloc(sizeof(CLIENT_OPTION));

	CfgGetUniStr(f, "AccountName", o->AccountName, sizeof(o->AccountName));
	CfgGetStr(f, "Hostname", o->Hostname, sizeof(o->Hostname));
	o->Port = CfgGetInt(f, "Port");
	o->PortUDP = CfgGetInt(f, "PortUDP");
	o->ProxyType = CfgGetInt(f, "ProxyType");
	CfgGetStr(f, "ProxyName", o->ProxyName, sizeof(o->ProxyName));
	o->ProxyPort = CfgGetInt(f, "ProxyPort");
	CfgGetStr(f, "ProxyUsername", o->ProxyUsername, sizeof(o->ProxyUsername));
	b = CfgGetBuf(f, "ProxyPassword");
	s = DecryptPassword(b);
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
	o->HideStatusWindow = CfgGetBool(f, "HideStatusWindow");
	o->HideNicInfoWindow = CfgGetBool(f, "HideNicInfoWindow");
	o->ConnectionDisconnectSpan = CfgGetInt(f, "ConnectionDisconnectSpan");
	o->RequireMonitorMode = CfgGetBool(f, "RequireMonitorMode");
	o->RequireBridgeRoutingMode = CfgGetBool(f, "RequireBridgeRoutingMode");
	o->DisableQoS = CfgGetBool(f, "DisableQoS");
	o->FromAdminPack = CfgGetBool(f, "FromAdminPack");
	o->NoUdpAcceleration = CfgGetBool(f, "NoUdpAcceleration");
	CfgGetIp(f, "BindLocalIP", &o->BindLocalIP);      // Source IP address for outgoing connection
	o->BindLocalPort = CfgGetInt(f, "BindLocalPort"); // Source port number for outgoing connection

	b = CfgGetBuf(f, "HostUniqueKey");
	if (b != NULL) {
		if (b->Size == SHA1_SIZE) {
			Copy(o->HostUniqueKey, b->Buf, SHA1_SIZE);
		}

		FreeBuf(b);
	}

	return o;
}

// Write the client authentication data
void CiWriteClientAuth(FOLDER *f, CLIENT_AUTH *a) {
	BUF *b;
	// Validate arguments
	if (f == NULL || a == NULL) {
		return;
	}

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

	case CLIENT_AUTHTYPE_OPENSSLENGINE:
		if (a->ClientX != NULL) {
			b = XToBuf(a->ClientX, false);
			CfgAddByte(f, "ClientCert", b->Buf, b->Size);
			FreeBuf(b);
		}
		CfgAddStr(f, "OpensslEnginePrivateKeyName", a->OpensslEnginePrivateKeyName);
		CfgAddStr(f, "OpensslEngineName", a->OpensslEngineName);
		break;
	}
}

// Write the client option
void CiWriteClientOption(FOLDER *f, CLIENT_OPTION *o) {
	BUF *b;
	// Validate arguments
	if (f == NULL || o == NULL) {
		return;
	}

	CfgAddUniStr(f, "AccountName", o->AccountName);
	CfgAddStr(f, "Hostname", o->Hostname);
	CfgAddInt(f, "Port", o->Port);
	CfgAddInt(f, "PortUDP", o->PortUDP);
	CfgAddInt(f, "ProxyType", o->ProxyType);
	CfgAddStr(f, "ProxyName", o->ProxyName);
	CfgAddInt(f, "ProxyPort", o->ProxyPort);
	CfgAddStr(f, "ProxyUsername", o->ProxyUsername);
	b = EncryptPassword(o->ProxyPassword);
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
	CfgAddBool(f, "HideStatusWindow", o->HideStatusWindow);
	CfgAddBool(f, "HideNicInfoWindow", o->HideNicInfoWindow);
	CfgAddInt(f, "ConnectionDisconnectSpan", o->ConnectionDisconnectSpan);
	CfgAddBool(f, "RequireMonitorMode", o->RequireMonitorMode);
	CfgAddBool(f, "RequireBridgeRoutingMode", o->RequireBridgeRoutingMode);
	CfgAddBool(f, "DisableQoS", o->DisableQoS);
	CfgAddBool(f, "NoUdpAcceleration", o->NoUdpAcceleration);
	CfgAddIp(f, "BindLocalIP", &o->BindLocalIP);     // Source IP address for outgoing connection
	CfgAddInt(f, "BindLocalPort", o->BindLocalPort); // Source port number for outgoing connection

	if (o->FromAdminPack) {
		CfgAddBool(f, "FromAdminPack", o->FromAdminPack);
	}

	if (IsZero(o->HostUniqueKey, SHA1_SIZE) == false) {
		BUF *b = MemToBuf(o->HostUniqueKey, SHA1_SIZE);
		CfgAddBuf(f, "HostUniqueKey", b);
		FreeBuf(b);
	}
}

// Decrypt the password
char *DecryptPassword(BUF *b) {
	char *str;
	char *key = "EncryptPassword";
	CRYPT *c;
	// Validate arguments
	if (b == NULL) {
		return CopyStr("");
	}

	str = ZeroMalloc(b->Size + 1);
	c = NewCrypt(key, sizeof(key)); // NOTE by Daiyuu Nobori 2018-09-28: This is not a bug! Do not try to fix it!!
	Encrypt(c, str, b->Buf, b->Size);
	FreeCrypt(c);

	str[b->Size] = 0;

	return str;
}

// Encrypt the password
BUF *EncryptPassword(char *password) {
	UCHAR *tmp;
	UINT size;
	char *key = "EncryptPassword";
	CRYPT *c;
	BUF *b;
	// Validate arguments
	if (password == NULL) {
		password = "";
	}

	size = StrLen(password) + 1;
	tmp = ZeroMalloc(size);

	c = NewCrypt(key, sizeof(key)); // NOTE by Daiyuu Nobori 2018-09-28: This is not a bug! Do not try to fix it!!
	Encrypt(c, tmp, password, size - 1);
	FreeCrypt(c);

	b = NewBuf();
	WriteBuf(b, tmp, size - 1);
	SeekBuf(b, 0, 0);
	Free(tmp);

	return b;
}
