// Account.c
// Account Manager

#include "Account.h"

#include "Connection.h"
#include "Hub.h"
#include "MsChapV2.h"
#include "Protocol.h"
#include "RpcField.h"

#include "Mayaqua/Cfg.h"
#include "Mayaqua/Internat.h"
#include "Mayaqua/Kernel.h"
#include "Mayaqua/Memory.h"
#include "Mayaqua/Object.h"
#include "Mayaqua/Pack.h"
#include "Mayaqua/Str.h"
#include "Mayaqua/Table.h"
#include "Mayaqua/Tick64.h"

static void CleanupUser(USER *u);
static void CleanupGroup(USERGROUP *g);
static char *DecryptPassword(BUF *b);
static BUF *EncryptPassword(char *password);

POLICY_ITEM policy_item[] =
{
//  ID,     Value,  Omittable, Min, Max, Default, Unit name, Offset
	{0,		false,	false,	0,	0,	0,		NULL,		offsetof(POLICY, Access)},
	{1,		false,	false,	0,	0,	0,		NULL,		offsetof(POLICY, DHCPFilter)},
	{2,		false,	false,	0,	0,	0,		NULL,		offsetof(POLICY, DHCPNoServer)},
	{3,		false,	false,	0,	0,	0,		NULL,		offsetof(POLICY, DHCPForce)},
	{4,		false,	false,	0,	0,	0,		NULL,		offsetof(POLICY, NoBridge)},
	{5,		false,	false,	0,	0,	0,		NULL,		offsetof(POLICY, NoRouting)},
	{6,		false,	false,	0,	0,	0,		NULL,		offsetof(POLICY, CheckMac)},
	{7,		false,	false,	0,	0,	0,		NULL,		offsetof(POLICY, CheckIP)},
	{8,		false,	false,	0,	0,	0,		NULL,		offsetof(POLICY, ArpDhcpOnly)},
	{9,		false,	false,	0,	0,	0,		NULL,		offsetof(POLICY, PrivacyFilter)},
	{10,	false,	false,	0,	0,	0,		NULL,		offsetof(POLICY, NoServer)},
	{11,	false,	false,	0,	0,	0,		NULL,		offsetof(POLICY, NoBroadcastLimiter)},
	{12,	false,	false,	0,	0,	0,		NULL,		offsetof(POLICY, MonitorPort)},
	{13,	true,	false,	1,	32,	32,		"POL_INT_COUNT",		offsetof(POLICY, MaxConnection)},
	{14,	true,	false,	5,	60,	20,		"POL_INT_SEC",			offsetof(POLICY, TimeOut)},
	{15,	true,	true,	1,	65535,	0,	"POL_INT_COUNT",		offsetof(POLICY, MaxMac)},
	{16,	true,	true,	1,	65535,	0,	"POL_INT_COUNT",		offsetof(POLICY, MaxIP)},
	{17,	true,	true,	1,	4294967295UL,	0,	"POL_INT_BPS",	offsetof(POLICY, MaxUpload)},
	{18,	true,	true,	1,	4294967295UL,	0,	"POL_INT_BPS",	offsetof(POLICY, MaxDownload)},
	{19,	false,	false,	0,	0,	0,		NULL,		offsetof(POLICY, FixPassword)},
	{20,	true,	true,	1,	65535,	0,	"POL_INT_COUNT",		offsetof(POLICY, MultiLogins)},
	{21,	false,	false,	0,	0,	0,		NULL,		offsetof(POLICY, NoQoS)},
	{22,	false,	false,	0,	0,	0,		NULL,		offsetof(POLICY, RSandRAFilter)},
	{23,	false,	false,	0,	0,	0,		NULL,		offsetof(POLICY, RAFilter)},
	{24,	false,	false,	0,	0,	0,		NULL,		offsetof(POLICY, DHCPv6Filter)},
	{25,	false,	false,	0,	0,	0,		NULL,		offsetof(POLICY, DHCPv6NoServer)},
	{26,	false,	false,	0,	0,	0,		NULL,		offsetof(POLICY, NoRoutingV6)},
	{27,	false,	false,	0,	0,	0,		NULL,		offsetof(POLICY, CheckIPv6)},
	{28,	false,	false,	0,	0,	0,		NULL,		offsetof(POLICY, NoServerV6)},
	{29,	true,	true,	1,	65535,	0,	"POL_INT_COUNT",		offsetof(POLICY, MaxIPv6)},
	{30,	false,	false,	0,	0,	0,		NULL,		offsetof(POLICY, NoSavePassword)},
	{31,	true,	true,	1,	4294967295UL,	0,	"POL_INT_SEC",	offsetof(POLICY, AutoDisconnect)},
	{32,	false,	false,	0,	0,	0,		NULL,		offsetof(POLICY, FilterIPv4)},
	{33,	false,	false,	0,	0,	0,		NULL,		offsetof(POLICY, FilterIPv6)},
	{34,	false,	false,	0,	0,	0,		NULL,		offsetof(POLICY, FilterNonIP)},
	{35,	false,	false,	0,	0,	0,		NULL,		offsetof(POLICY, NoIPv6DefaultRouterInRA)},
	{36,	false,	false,	0,	0,	0,		NULL,		offsetof(POLICY, NoIPv6DefaultRouterInRAWhenIPv6)},
	{37,	true,	true,	1,	4095,	0,	"POL_INT_VLAN",			offsetof(POLICY, VLanId)},
};

void FormatPolicyValue(wchar_t *str, UINT size, UINT id, UINT value)
{
	POLICY_ITEM *p;
	if (str == NULL)
	{
		return;
	}

	p = GetPolicyItem(id);

	if (p->TypeInt == false)
	{
		if (value == 0)
		{
			UniStrCpy(str, size, L"No");
		}
		else
		{
			UniStrCpy(str, size, L"Yes");
		}
	}
	else
	{
		if (value == 0 && p->AllowZero)
		{
			UniStrCpy(str, size, _UU("CMD_NO_SETTINGS"));
		}
		else
		{
			UniFormat(str, size, _UU(p->FormatStr), value);
		}
	}
}

void GetPolicyValueRangeStr(wchar_t *str, UINT size, UINT id)
{
	POLICY_ITEM *p;
	if (str == NULL)
	{
		return;
	}

	p = GetPolicyItem(id);

	if (p->TypeInt == false)
	{
		UniStrCpy(str, size, _UU("CMD_PolicyList_Range_Bool"));
	}
	else
	{
		wchar_t *tag;
		wchar_t tmp1[256], tmp2[256];

		if (p->AllowZero)
		{
			tag = _UU("CMD_PolicyList_Range_Int_2");
		}
		else
		{
			tag = _UU("CMD_PolicyList_Range_Int_1");
		}

		UniFormat(tmp1, sizeof(tmp1), _UU(p->FormatStr), p->MinValue);
		UniFormat(tmp2, sizeof(tmp2), _UU(p->FormatStr), p->MaxValue);

		UniFormat(str, size, tag, tmp1, tmp2);
	}
}

POLICY_ITEM *GetPolicyItem(UINT id)
{
	return &policy_item[id];
}

bool PolicyIsSupportedForCascade(UINT i)
{
	if (i == 0 || i == 4 || i == 5 || i == 12 || i == 13 ||
		i == 14 || i == 19 || i == 20 || i == 21 || i == 26 || i == 30 || i == 31 || i == 36)
	{
		return false;
	}

	return true;
}

char *PolicyIdToStr(UINT i)
{
	switch (i)
	{
	case 0:		return "Access";
	case 1:		return "DHCPFilter";
	case 2:		return "DHCPNoServer";
	case 3:		return "DHCPForce";
	case 4:		return "NoBridge";
	case 5:		return "NoRouting";
	case 6:		return "CheckMac";
	case 7:		return "CheckIP";
	case 8:		return "ArpDhcpOnly";
	case 9:		return "PrivacyFilter";
	case 10:	return "NoServer";
	case 11:	return "NoBroadcastLimiter";
	case 12:	return "MonitorPort";
	case 13:	return "MaxConnection";
	case 14:	return "TimeOut";
	case 15:	return "MaxMac";
	case 16:	return "MaxIP";
	case 17:	return "MaxUpload";
	case 18:	return "MaxDownload";
	case 19:	return "FixPassword";
	case 20:	return "MultiLogins";
	case 21:	return "NoQoS";

	case 22:	return "RSandRAFilter";
	case 23:	return "RAFilter";
	case 24:	return "DHCPv6Filter";
	case 25:	return "DHCPv6NoServer";
	case 26:	return "NoRoutingV6";
	case 27:	return "CheckIPv6";
	case 28:	return "NoServerV6";
	case 29:	return "MaxIPv6";
	case 30:	return "NoSavePassword";
	case 31:	return "AutoDisconnect";
	case 32:	return "FilterIPv4";
	case 33:	return "FilterIPv6";
	case 34:	return "FilterNonIP";
	case 35:	return "NoIPv6DefaultRouterInRA";
	case 36:	return "NoIPv6DefaultRouterInRAWhenIPv6";
	case 37:	return "VLanId";
	}

	return NULL;
}

UINT PolicyStrToId(char *name)
{
	UINT i;
	if (name == NULL)
	{
		return INFINITE;
	}

	for (i = 0;i < NUM_POLICY_ITEM;i++)
	{
		if (StartWith(PolicyIdToStr(i), name))
		{
			return i;
		}
	}

	return INFINITE;
}

UINT PolicyNum()
{
	return NUM_POLICY_ITEM;
}

bool IsUserName(char *name)
{
	UINT i, len;
	char tmp[MAX_SIZE];
	if (name == NULL)
	{
		return false;
	}

	StrCpy(tmp, sizeof(tmp), name);
	name = tmp;

	Trim(name);

	len = StrLen(name);
	if (len == 0)
	{
		return false;
	}

	if (StrCmpi(name, "*") == 0)
	{
		return true;
	}

	for (i = 0; i < len; i++)
	{
		if (IsSafeChar(name[i]) == false && name[i] != '@')
		{
			return false;
		}
	}

	if (StrCmpi(name, LINK_USER_NAME) == 0)
	{
		return false;
	}

	if (StrCmpi(name, LINK_USER_NAME_PRINT) == 0)
	{
		return false;
	}

	if (StrCmpi(name, BRIDGE_USER_NAME) == 0)
	{
		return false;
	}

	if (StrCmpi(name, BRIDGE_USER_NAME_PRINT) == 0)
	{
		return false;
	}

	if (StrCmpi(name, ADMINISTRATOR_USERNAME) == 0)
	{
		return false;
	}

	return true;
}

POLICY *ClonePolicy(POLICY *policy)
{
	POLICY *ret;
	if (policy == NULL)
	{
		return NULL;
	}

	ret = ZeroMalloc(sizeof(POLICY));
	Copy(ret, policy, sizeof(POLICY));

	return ret;
}

// Overwrite policy values; data from an older version leaves the Ver 3.0 fields as they are
static void OverwritePolicy(POLICY **target, POLICY *p)
{
	if (target == NULL)
	{
		return;
	}

	if (p == NULL)
	{
		if (*target != NULL)
		{
			Free(*target);
			*target = NULL;
		}
	}
	else
	{
		if (p->Ver3)
		{
			if (*target != NULL)
			{
				Free(*target);
				*target = NULL;
			}

			*target = ClonePolicy(p);
		}
		else
		{
			if (*target == NULL)
			{
				*target = ClonePolicy(p);
			}
			else
			{
				Copy(*target, p, policy_item[NUM_POLICY_ITEM_FOR_VER2].Offset);
			}
		}
	}
}

void SetUserPolicy(USER *u, POLICY *policy)
{
	if (u == NULL)
	{
		return;
	}

	Lock(u->lock);
	{
		OverwritePolicy(&u->Policy, policy);
	}
	Unlock(u->lock);
}

void SetGroupPolicy(USERGROUP *g, POLICY *policy)
{
	if (g == NULL)
	{
		return;
	}

	Lock(g->lock);
	{
		OverwritePolicy(&g->Policy, policy);
	}
	Unlock(g->lock);
}

POLICY *GetGroupPolicy(USERGROUP *g)
{
	POLICY *ret;
	if (g == NULL)
	{
		return NULL;
	}

	Lock(g->lock);
	{
		if (g->Policy == NULL)
		{
			ret = NULL;
		}
		else
		{
			ret = ClonePolicy(g->Policy);
		}
	}
	Unlock(g->lock);

	return ret;
}

POLICY *GetDefaultPolicy()
{
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

void *NewNTAuthData(wchar_t *username)
{
	AUTHNT *a;
	a = ZeroMallocEx(sizeof(AUTHNT), true);
	a->NtUsername = CopyUniStr(username);

	return a;
}

void *NewRootCertAuthData(X_SERIAL *serial, wchar_t *common_name)
{
	AUTHROOTCERT *a;

	a = ZeroMallocEx(sizeof(AUTHROOTCERT), true);
	if (common_name != NULL && UniIsEmptyStr(common_name) == false)
	{
		a->CommonName = CopyUniStr(common_name);
	}
	if (serial != NULL && serial->size >= 1)
	{
		a->Serial = CloneXSerial(serial);
	}

	return a;
}

void *NewUserCertAuthData(X *x)
{
	AUTHUSERCERT *a;

	a = ZeroMalloc(sizeof(AUTHUSERCERT));
	a->UserX = CloneX(x);

	return a;
}

void HashPassword(void *dst, char *username, char *password)
{
	BUF *b;
	char *username_upper;
	if (dst == NULL || username == NULL || password == NULL)
	{
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

void *NewPasswordAuthData(char *username, char *password)
{
	AUTHPASSWORD *pw;
	if (username == NULL || password == NULL)
	{
		return NULL;
	}

	pw = ZeroMalloc(sizeof(AUTHPASSWORD));
	HashPassword(pw->HashedKey, username, password);
	GenerateNtPasswordHash(pw->NtLmSecureHash, password);

	return pw;
}

void *NewPasswordAuthDataRaw(UCHAR *hashed_password, UCHAR *ntlm_secure_hash)
{
	AUTHPASSWORD *pw;
	if (hashed_password == NULL)
	{
		return NULL;
	}

	pw = ZeroMalloc(sizeof(AUTHPASSWORD));
	Copy(pw->HashedKey, hashed_password, SHA1_SIZE);

	if (ntlm_secure_hash != NULL)
	{
		Copy(pw->NtLmSecureHash, ntlm_secure_hash, MD5_SIZE);
	}

	return pw;
}

void *CopyAuthData(void *authdata, UINT authtype)
{
	AUTHPASSWORD *pw = (AUTHPASSWORD *)authdata;
	AUTHUSERCERT *usercert = (AUTHUSERCERT *)authdata;
	AUTHROOTCERT *rootcert = (AUTHROOTCERT *)authdata;
	AUTHNT *nt = (AUTHNT *)authdata;
	if (authdata == NULL || authtype == AUTHTYPE_ANONYMOUS)
	{
		return NULL;
	}

	switch (authtype)
	{
	case AUTHTYPE_PASSWORD:
		{
			AUTHPASSWORD *ret = ZeroMalloc(sizeof(AUTHPASSWORD));
			Copy(ret, pw, sizeof(AUTHPASSWORD));
			return ret;
		}
		break;

	case AUTHTYPE_USERCERT:
		{
			AUTHUSERCERT *ret = ZeroMalloc(sizeof(AUTHUSERCERT));
			ret->UserX = CloneX(usercert->UserX);
			return ret;
		}
		break;

	case AUTHTYPE_ROOTCERT:
		{
			AUTHROOTCERT *ret = ZeroMalloc(sizeof(AUTHROOTCERT));
			ret->CommonName = CopyUniStr(rootcert->CommonName);
			ret->Serial = CloneXSerial(rootcert->Serial);
			return ret;
		}
		break;

	case AUTHTYPE_NT:
		{
			AUTHNT *ret = ZeroMalloc(sizeof(AUTHNT));
			ret->NtUsername = UniCopyStr(nt->NtUsername);
			return ret;
		}
		break;
	}

	return NULL;
}

void SetUserAuthData(USER *u, UINT authtype, void *authdata)
{
	if (u == NULL)
	{
		return;
	}
	if (authtype != AUTHTYPE_ANONYMOUS && authdata == NULL)
	{
		return;
	}

	Lock(u->lock);
	{
		if (u->AuthType != AUTHTYPE_ANONYMOUS)
		{
			if (u->AuthType == AUTHTYPE_PASSWORD && authtype == AUTHTYPE_PASSWORD)
			{
				AUTHPASSWORD *pw_old = (AUTHPASSWORD *)u->AuthData;
				AUTHPASSWORD *pw_new = (AUTHPASSWORD *)authdata;

				// Keep the old NTLM hash if the password is unchanged and the admin tool sent no NTLM hash

				if (Cmp(pw_old->HashedKey, pw_new->HashedKey, SHA1_SIZE) == 0)
				{
					if (IsZero(pw_new->NtLmSecureHash, MD5_SIZE))
					{
						Copy(pw_new->NtLmSecureHash, pw_old->NtLmSecureHash, MD5_SIZE);
					}
				}
			}

			FreeAuthData(u->AuthType, u->AuthData);
		}
		u->AuthType = authtype;
		u->AuthData = authdata;
	}
	Unlock(u->lock);
}

void SetGroupTraffic(USERGROUP *g, TRAFFIC *t)
{
	if (g == NULL)
	{
		return;
	}

	Lock(g->lock);
	{
		if (t != NULL)
		{
			Copy(g->Traffic, t, sizeof(TRAFFIC));
		}
		else
		{
			Zero(g->Traffic, sizeof(TRAFFIC));
		}
	}
	Unlock(g->lock);
}

void SetUserTraffic(USER *u, TRAFFIC *t)
{
	if (u == NULL)
	{
		return;
	}

	Lock(u->lock);
	{
		if (t != NULL)
		{
			Copy(u->Traffic, t, sizeof(TRAFFIC));
		}
		else
		{
			Zero(u->Traffic, sizeof(TRAFFIC));
		}
	}
	Unlock(u->lock);
}

void JoinUserToGroup(USER *u, USERGROUP *g)
{
	if (u == NULL)
	{
		return;
	}

	if (g != NULL)
	{
		Lock(u->lock);
		{
			Lock(g->lock);
			{
				if (u->Group != NULL)
				{
					ReleaseGroup(u->Group);
					u->Group = NULL;
					Free(u->GroupName);
					u->GroupName = NULL;
				}
				u->GroupName = CopyStr(g->Name);
				u->Group = g;
				AddRef(g->ref);
			}
			Unlock(g->lock);
		}
		Unlock(u->lock);
	}
	else
	{
		Lock(u->lock);
		{
			if (u->Group != NULL)
			{
				ReleaseGroup(u->Group);
				u->Group = NULL;
				Free(u->GroupName);
				u->GroupName = NULL;
			}
		}
		Unlock(u->lock);
	}
}

bool AcIsGroup(HUB *h, char *name)
{
	USERGROUP *g;
	if (h == NULL || name == NULL)
	{
		return false;
	}

	g = AcGetGroup(h, name);
	if (g == NULL)
	{
		return false;
	}
	ReleaseGroup(g);

	return true;
}

bool AcIsUser(HUB *h, char *name)
{
	USER *u;
	if (h == NULL || name == NULL)
	{
		return false;
	}

	u = AcGetUser(h, name);
	if (u == NULL)
	{
		return false;
	}
	ReleaseUser(u);

	return true;
}

USERGROUP *AcGetGroup(HUB *h, char *name)
{
	USERGROUP *g, t;
	if (h == NULL || name == NULL)
	{
		return NULL;
	}

	t.Name = name;
	g = Search(h->HubDb->GroupList, &t);
	if (g == NULL)
	{
		return NULL;
	}
	AddRef(g->ref);

	return g;
}

USER *AcGetUser(HUB *h, char *name)
{
	USER *u, t;
	if (h == NULL || name == NULL)
	{
		return NULL;
	}

	t.Name = name;
	u = Search(h->HubDb->UserList, &t);
	if (u == NULL)
	{
		return NULL;
	}
	AddRef(u->ref);

	return u;
}

bool AcDeleteUser(HUB *h, char *name)
{
	USER *u;
	if (h == NULL || name == NULL)
	{
		return false;
	}

	u = AcGetUser(h, name);
	if (u == NULL)
	{
		return false;
	}

	if (Delete(h->HubDb->UserList, u))
	{
		ReleaseUser(u);
	}

	ReleaseUser(u);

	return true;
}

bool AcDeleteGroup(HUB *h, char *name)
{
	USERGROUP *g;
	UINT i;
	if (h == NULL || name == NULL)
	{
		return false;
	}

	g = AcGetGroup(h, name);
	if (g == NULL)
	{
		return false;
	}

	if (Delete(h->HubDb->GroupList, g))
	{
		ReleaseGroup(g);
	}

	for (i = 0;i < LIST_NUM(h->HubDb->UserList);i++)
	{
		USER *u = LIST_DATA(h->HubDb->UserList, i);
		Lock(u->lock);
		{
			if (u->Group == g)
			{
				JoinUserToGroup(u, NULL);
			}
		}
		Unlock(u->lock);
	}

	ReleaseGroup(g);

	return true;
}

bool AcAddGroup(HUB *h, USERGROUP *g)
{
	if (h == NULL || g == NULL)
	{
		return false;
	}

	if (LIST_NUM(h->HubDb->GroupList) >= MAX_GROUPS)
	{
		return false;
	}

	if (AcIsGroup(h, g->Name) != false)
	{
		return false;
	}

	Insert(h->HubDb->GroupList, g);
	AddRef(g->ref);

	return true;
}

bool AcAddUser(HUB *h, USER *u)
{
	if (h == NULL || u == NULL)
	{
		return false;
	}

	if (LIST_NUM(h->HubDb->UserList) >= MAX_USERS)
	{
		return false;
	}

	if (AcIsUser(h, u->Name) != false)
	{
		return false;
	}

	Insert(h->HubDb->UserList, u);
	AddRef(u->ref);

	return true;
}

void ReleaseUser(USER *u)
{
	if (u == NULL)
	{
		return;
	}

	if (Release(u->ref) == 0)
	{
		CleanupUser(u);
	}
}

static void CleanupUser(USER *u)
{
	if (u == NULL)
	{
		return;
	}

	DeleteLock(u->lock);
	Free(u->Name);
	Free(u->RealName);
	Free(u->Note);
	Free(u->GroupName);
	if (u->Group != NULL)
	{
		ReleaseGroup(u->Group);
	}

	FreeAuthData(u->AuthType, u->AuthData);

	if (u->Policy)
	{
		Free(u->Policy);
	}

	FreeTraffic(u->Traffic);

	Free(u);
}

void FreeAuthData(UINT authtype, void *authdata)
{
	AUTHUSERCERT *uc = (AUTHUSERCERT *)authdata;
	AUTHROOTCERT *rc = (AUTHROOTCERT *)authdata;
	AUTHNT *nt = (AUTHNT *)authdata;
	if (authtype == AUTHTYPE_ANONYMOUS || authdata == NULL)
	{
		return;
	}

	switch (authtype)
	{
	case AUTHTYPE_PASSWORD:
		break;

	case AUTHTYPE_USERCERT:
		FreeX(uc->UserX);
		break;

	case AUTHTYPE_ROOTCERT:
		if (rc->Serial != NULL)
		{
			FreeXSerial(rc->Serial);
		}
		if (rc->CommonName != NULL)
		{
			Free(rc->CommonName);
		}
		break;

	case AUTHTYPE_NT:
		Free(nt->NtUsername);
		break;
	}

	Free(authdata);
}

USER *NewUser(char *name, wchar_t *realname, wchar_t *note, UINT authtype, void *authdata)
{
	USER *u;
	if (name == NULL || realname == NULL || note == NULL)
	{
		return NULL;
	}
	if (authtype != AUTHTYPE_ANONYMOUS && authdata == NULL)
	{
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

void ReleaseGroup(USERGROUP *g)
{
	if (g == NULL)
	{
		return;
	}

	if (Release(g->ref) == 0)
	{
		CleanupGroup(g);
	}
}

static void CleanupGroup(USERGROUP *g)
{
	if (g == NULL)
	{
		return;
	}

	Free(g->Name);
	Free(g->RealName);
	Free(g->Note);

	if (g->Policy)
	{
		Free(g->Policy);
	}


	FreeTraffic(g->Traffic);

	DeleteLock(g->lock);
	Free(g);
}

USERGROUP *NewGroup(char *name, wchar_t *realname, wchar_t *note)
{
	USERGROUP *g;
	if (name == NULL || realname == NULL || note == NULL)
	{
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

void AcLock(HUB *h)
{
	if (h == NULL)
	{
		return;
	}
	LockList(h->HubDb->GroupList);
	LockList(h->HubDb->UserList);
}

void AcUnlock(HUB *h)
{
	if (h == NULL)
	{
		return;
	}
	UnlockList(h->HubDb->UserList);
	UnlockList(h->HubDb->GroupList);
}

int CompareGroupName(void *p1, void *p2)
{
	USERGROUP *g1, *g2;
	if (p1 == NULL || p2 == NULL)
	{
		return 0;
	}
	g1 = *(USERGROUP **)p1;
	g2 = *(USERGROUP **)p2;
	if (g1 == NULL || g2 == NULL)
	{
		return 0;
	}

	return StrCmpi(g1->Name, g2->Name);
}

int CompareUserName(void *p1, void *p2)
{
	USER *u1, *u2;
	if (p1 == NULL || p2 == NULL)
	{
		return 0;
	}
	u1 = *(USER **)p1;
	u2 = *(USER **)p2;
	if (u1 == NULL || u2 == NULL)
	{
		return 0;
	}

	return StrCmpi(u1->Name, u2->Name);
}


static const RPC_FIELD rpc_traffic_ex_fields[] =
{
	RPC_ROW_INT64(TRAFFIC, Recv.BroadcastBytes, "Ex.Recv.BroadcastBytes"),
	RPC_ROW_INT64(TRAFFIC, Recv.BroadcastCount, "Ex.Recv.BroadcastCount"),
	RPC_ROW_INT64(TRAFFIC, Recv.UnicastBytes, "Ex.Recv.UnicastBytes"),
	RPC_ROW_INT64(TRAFFIC, Recv.UnicastCount, "Ex.Recv.UnicastCount"),
	RPC_ROW_INT64(TRAFFIC, Send.BroadcastBytes, "Ex.Send.BroadcastBytes"),
	RPC_ROW_INT64(TRAFFIC, Send.BroadcastCount, "Ex.Send.BroadcastCount"),
	RPC_ROW_INT64(TRAFFIC, Send.UnicastBytes, "Ex.Send.UnicastBytes"),
	RPC_ROW_INT64(TRAFFIC, Send.UnicastCount, "Ex.Send.UnicastCount"),
	RPC_ROW_END
};
RPC_TABLE_DEF(rpc_traffic_ex_table, TRAFFIC, rpc_traffic_ex_fields);

void InRpcTrafficEx(TRAFFIC *t, PACK *p, UINT i)
{
	RpcFieldInItem(&rpc_traffic_ex_table, t, p, i);
}
void OutRpcTrafficEx(TRAFFIC *t, PACK *p, UINT i, UINT num)
{
	RpcFieldOutItem(&rpc_traffic_ex_table, p, t, i, num);
}

static const RPC_FIELD rpc_traffic_fields[] =
{
	RPC_ROW_INT64(TRAFFIC, Recv.BroadcastBytes, "Recv.BroadcastBytes"),
	RPC_ROW_INT64(TRAFFIC, Recv.BroadcastCount, "Recv.BroadcastCount"),
	RPC_ROW_INT64(TRAFFIC, Recv.UnicastBytes, "Recv.UnicastBytes"),
	RPC_ROW_INT64(TRAFFIC, Recv.UnicastCount, "Recv.UnicastCount"),
	RPC_ROW_INT64(TRAFFIC, Send.BroadcastBytes, "Send.BroadcastBytes"),
	RPC_ROW_INT64(TRAFFIC, Send.BroadcastCount, "Send.BroadcastCount"),
	RPC_ROW_INT64(TRAFFIC, Send.UnicastBytes, "Send.UnicastBytes"),
	RPC_ROW_INT64(TRAFFIC, Send.UnicastCount, "Send.UnicastCount"),
	RPC_ROW_END
};
RPC_TABLE_DEF(rpc_traffic_table, TRAFFIC, rpc_traffic_fields);

void InRpcTraffic(TRAFFIC *t, PACK *p)
{
	RpcFieldIn(&rpc_traffic_table, t, p);
}
void OutRpcTraffic(PACK *p, TRAFFIC *t)
{
	RpcFieldOut(&rpc_traffic_table, p, t);
}

static const RPC_FIELD rpc_client_option_fields[] =
{
	RPC_ROW_UNISTR(CLIENT_OPTION, AccountName, "AccountName"),
	RPC_ROW_STR(CLIENT_OPTION, Hostname, "Hostname"),
	RPC_ROW_STR(CLIENT_OPTION, ProxyName, "ProxyName"),
	RPC_ROW_STR(CLIENT_OPTION, ProxyUsername, "ProxyUsername"),
	RPC_ROW_STR(CLIENT_OPTION, ProxyPassword, "ProxyPassword"),
	RPC_ROW_STR(CLIENT_OPTION, CustomHttpHeader, "CustomHttpHeader"),
	RPC_ROW_STR(CLIENT_OPTION, HubName, "HubName"),
	RPC_ROW_STR(CLIENT_OPTION, DeviceName, "DeviceName"),
	RPC_ROW_INT(CLIENT_OPTION, Port, "Port"),
	RPC_ROW_INT(CLIENT_OPTION, PortUDP, "PortUDP"),
	RPC_ROW_INT(CLIENT_OPTION, ProxyType, "ProxyType"),
	RPC_ROW_INT(CLIENT_OPTION, ProxyPort, "ProxyPort"),
	RPC_ROW_INT(CLIENT_OPTION, NumRetry, "NumRetry"),
	RPC_ROW_INT(CLIENT_OPTION, RetryInterval, "RetryInterval"),
	RPC_ROW_INT(CLIENT_OPTION, MaxConnection, "MaxConnection"),
	RPC_ROW_BOOL(CLIENT_OPTION, UseEncrypt, "UseEncrypt"),
	RPC_ROW_BOOL(CLIENT_OPTION, UseCompress, "UseCompress"),
	RPC_ROW_BOOL(CLIENT_OPTION, HalfConnection, "HalfConnection"),
	RPC_ROW_BOOL(CLIENT_OPTION, NoRoutingTracking, "NoRoutingTracking"),
	RPC_ROW_INT(CLIENT_OPTION, AdditionalConnectionInterval, "AdditionalConnectionInterval"),
	RPC_ROW_INT(CLIENT_OPTION, ConnectionDisconnectSpan, "ConnectionDisconnectSpan"),
	RPC_ROW_BOOL(CLIENT_OPTION, HideStatusWindow, "HideStatusWindow"),
	RPC_ROW_BOOL(CLIENT_OPTION, HideNicInfoWindow, "HideNicInfoWindow"),
	RPC_ROW_BOOL(CLIENT_OPTION, RequireMonitorMode, "RequireMonitorMode"),
	RPC_ROW_BOOL(CLIENT_OPTION, RequireBridgeRoutingMode, "RequireBridgeRoutingMode"),
	RPC_ROW_BOOL(CLIENT_OPTION, DisableQoS, "DisableQoS"),
	RPC_ROW_BOOL(CLIENT_OPTION, FromAdminPack, "FromAdminPack"),
	RPC_ROW_BOOL(CLIENT_OPTION, NoUdpAcceleration, "NoUdpAcceleration"),
	RPC_ROW_DATA(CLIENT_OPTION, HostUniqueKey, "HostUniqueKey"),
	RPC_ROW_IP(CLIENT_OPTION, BindLocalIP, "BindLocalIP"),// Source IP address for outgoing connection
	RPC_ROW_INT(CLIENT_OPTION, BindLocalPort, "BindLocalPort"),// Source port number for outgoing connection
	RPC_ROW_END
};
RPC_TABLE_DEF(rpc_client_option_table, CLIENT_OPTION, rpc_client_option_fields);

void InRpcClientOption(CLIENT_OPTION *c, PACK *p)
{
	RpcFieldIn(&rpc_client_option_table, c, p);
}
void OutRpcClientOption(PACK *p, CLIENT_OPTION *c)
{
	RpcFieldOut(&rpc_client_option_table, p, c);
}

void InRpcClientAuth(CLIENT_AUTH *c, PACK *p)
{
	BUF *b;
	if (c == NULL || p == NULL)
	{
		return;
	}

	Zero(c, sizeof(CLIENT_AUTH));
	c->AuthType = PackGetInt(p, "AuthType");
	PackGetStr(p, "Username", c->Username, sizeof(c->Username));

	switch (c->AuthType)
	{
	case CLIENT_AUTHTYPE_ANONYMOUS:
		break;

	case CLIENT_AUTHTYPE_PASSWORD:
		if (PackGetDataSize(p, "HashedPassword") == SHA1_SIZE)
		{
			PackGetData(p, "HashedPassword", c->HashedPassword);
		}
		break;

	case CLIENT_AUTHTYPE_PLAIN_PASSWORD:
		PackGetStr(p, "PlainPassword", c->PlainPassword, sizeof(c->PlainPassword));
		break;

	case CLIENT_AUTHTYPE_CERT:
		b = PackGetBuf(p, "ClientX");
		if (b != NULL)
		{
			c->ClientX = BufToX(b, false);
			FreeBuf(b);
		}
		b = PackGetBuf(p, "ClientK");
		if (b != NULL)
		{
			c->ClientK = BufToK(b, true, false, NULL);
			FreeBuf(b);
		}
		break;

  case CLIENT_AUTHTYPE_OPENSSLENGINE:
		b = PackGetBuf(p, "ClientX");
		if (b != NULL)
		{
			c->ClientX = BufToX(b, false);
			FreeBuf(b);
		}
    PackGetStr(p, "OpensslEnginePrivateKeyName", c->OpensslEnginePrivateKeyName, sizeof(c->OpensslEnginePrivateKeyName));
    PackGetStr(p, "OpensslEngineName", c->OpensslEngineName, sizeof(c->OpensslEngineName));
    break;
	}
}
void OutRpcClientAuth(PACK *p, CLIENT_AUTH *c)
{
	BUF *b;
	if (c == NULL || p == NULL)
	{
		return;
	}

	PackAddInt(p, "AuthType", c->AuthType);
	PackAddStr(p, "Username", c->Username);

	switch (c->AuthType)
	{
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
		if (b != NULL)
		{
			PackAddBuf(p, "ClientX", b);
			FreeBuf(b);
		}
		b = KToBuf(c->ClientK, false, NULL);
		if (b != NULL)
		{
			PackAddBuf(p, "ClientK", b);
			FreeBuf(b);
		}
		break;

	case CLIENT_AUTHTYPE_OPENSSLENGINE:
		b = XToBuf(c->ClientX, false);
		if (b != NULL)
		{
			PackAddBuf(p, "ClientX", b);
			FreeBuf(b);
		}
		PackAddStr(p, "OpensslEnginePrivateKeyName", c->OpensslEnginePrivateKeyName);
		PackAddStr(p, "OpensslEngineName", c->OpensslEngineName);
		break;
	}
}

void InRpcPolicy(POLICY *o, PACK *p)
{
	POLICY *pol;
	if (o == NULL || p == NULL)
	{
		return;
	}

	pol = PackGetPolicy(p);
	Copy(o, pol, sizeof(POLICY));
	Free(pol);
}
void OutRpcPolicy(PACK *p, POLICY *o)
{
	if (o == NULL || p == NULL)
	{
		return;
	}

	PackAddPolicy(p, o);
}

static void RpcClientGetConnectionStatusPolicyOut(const RPC_FIELD *f, PACK *p, void *base, UINT index, UINT total)
{
	OutRpcPolicy(p, (POLICY *)((UCHAR *)base + f->Offset));
}
static void RpcClientGetConnectionStatusPolicyIn(const RPC_FIELD *f, void *base, PACK *p, UINT index, UINT total)
{
	InRpcPolicy((POLICY *)((UCHAR *)base + f->Offset), p);
}
static const RPC_HOOK rpc_client_get_connection_status_policy_hook = {RpcClientGetConnectionStatusPolicyOut, RpcClientGetConnectionStatusPolicyIn, NULL};

static void RpcClientGetConnectionStatusTrafficOut(const RPC_FIELD *f, PACK *p, void *base, UINT index, UINT total)
{
	OutRpcTraffic(p, (TRAFFIC *)((UCHAR *)base + f->Offset));
}
static void RpcClientGetConnectionStatusTrafficIn(const RPC_FIELD *f, void *base, PACK *p, UINT index, UINT total)
{
	InRpcTraffic((TRAFFIC *)((UCHAR *)base + f->Offset), p);
}
static const RPC_HOOK rpc_client_get_connection_status_traffic_hook = {RpcClientGetConnectionStatusTrafficOut, RpcClientGetConnectionStatusTrafficIn, NULL};

// Certificate as DER data (read without the PEM fallback of PackGetX);
// CiFreeClientGetConnectionStatus releases it
static void RpcClientGetConnectionStatusXOut(const RPC_FIELD *f, PACK *p, void *base, UINT index, UINT total)
{
	X *x = *(X **)((UCHAR *)base + f->Offset);

	if (x != NULL)
	{
		BUF *b = XToBuf(x, false);
		PackAddBuf(p, f->Key, b);
		FreeBuf(b);
	}
}
static void RpcClientGetConnectionStatusXIn(const RPC_FIELD *f, void *base, PACK *p, UINT index, UINT total)
{
	BUF *b = PackGetBuf(p, f->Key);

	if (b != NULL)
	{
		*(X **)((UCHAR *)base + f->Offset) = BufToX(b, false);
		FreeBuf(b);
	}
}
static const RPC_HOOK rpc_client_get_connection_status_x_hook = {RpcClientGetConnectionStatusXOut, RpcClientGetConnectionStatusXIn, NULL};

static const RPC_FIELD rpc_client_get_connection_status_fields[] =
{
	RPC_ROW_UNISTR(RPC_CLIENT_GET_CONNECTION_STATUS, AccountName, "AccountName"),
	RPC_ROW_STR(RPC_CLIENT_GET_CONNECTION_STATUS, ServerName, "ServerName"),
	RPC_ROW_STR(RPC_CLIENT_GET_CONNECTION_STATUS, ServerProductName, "ServerProductName"),
	RPC_ROW_STR(RPC_CLIENT_GET_CONNECTION_STATUS, ProtocolName, "ProtocolVersion"),
	RPC_ROW_STR(RPC_CLIENT_GET_CONNECTION_STATUS, CipherName, "CipherName"),
	RPC_ROW_STR(RPC_CLIENT_GET_CONNECTION_STATUS, SessionName, "SessionName"),
	RPC_ROW_STR(RPC_CLIENT_GET_CONNECTION_STATUS, ConnectionName, "ConnectionName"),
	RPC_ROW_DATA(RPC_CLIENT_GET_CONNECTION_STATUS, SessionKey, "SessionKey"),
	RPC_ROW_BOOL(RPC_CLIENT_GET_CONNECTION_STATUS, Active, "Active"),
	RPC_ROW_BOOL(RPC_CLIENT_GET_CONNECTION_STATUS, Connected, "Connected"),
	RPC_ROW_INT(RPC_CLIENT_GET_CONNECTION_STATUS, SessionStatus, "SessionStatus"),
	RPC_ROW_INT(RPC_CLIENT_GET_CONNECTION_STATUS, ServerPort, "ServerPort"),
	RPC_ROW_INT(RPC_CLIENT_GET_CONNECTION_STATUS, ServerProductVer, "ServerProductVer"),
	RPC_ROW_INT(RPC_CLIENT_GET_CONNECTION_STATUS, ServerProductBuild, "ServerProductBuild"),
	RPC_ROW_INT(RPC_CLIENT_GET_CONNECTION_STATUS, NumConnectionsEstablished, "NumConnectionsEstablished"),
	RPC_ROW_BOOL(RPC_CLIENT_GET_CONNECTION_STATUS, HalfConnection, "HalfConnection"),
	RPC_ROW_BOOL(RPC_CLIENT_GET_CONNECTION_STATUS, QoS, "QoS"),
	RPC_ROW_INT(RPC_CLIENT_GET_CONNECTION_STATUS, MaxTcpConnections, "MaxTcpConnections"),
	RPC_ROW_INT(RPC_CLIENT_GET_CONNECTION_STATUS, NumTcpConnections, "NumTcpConnections"),
	RPC_ROW_INT(RPC_CLIENT_GET_CONNECTION_STATUS, NumTcpConnectionsUpload, "NumTcpConnectionsUpload"),
	RPC_ROW_INT(RPC_CLIENT_GET_CONNECTION_STATUS, NumTcpConnectionsDownload, "NumTcpConnectionsDownload"),
	RPC_ROW_BOOL(RPC_CLIENT_GET_CONNECTION_STATUS, UseEncrypt, "UseEncrypt"),
	RPC_ROW_BOOL(RPC_CLIENT_GET_CONNECTION_STATUS, UseCompress, "UseCompress"),
	RPC_ROW_STR(RPC_CLIENT_GET_CONNECTION_STATUS, UnderlayProtocol, "UnderlayProtocol"),
	RPC_ROW_STR(RPC_CLIENT_GET_CONNECTION_STATUS, ProtocolDetails, "ProtocolDetails"),
	RPC_ROW_BOOL(RPC_CLIENT_GET_CONNECTION_STATUS, IsUdpAccelerationEnabled, "IsUdpAccelerationEnabled"),
	RPC_ROW_BOOL(RPC_CLIENT_GET_CONNECTION_STATUS, IsUsingUdpAcceleration, "IsUsingUdpAcceleration"),
	RPC_ROW_BOOL(RPC_CLIENT_GET_CONNECTION_STATUS, IsBridgeMode, "IsBridgeMode"),
	RPC_ROW_BOOL(RPC_CLIENT_GET_CONNECTION_STATUS, IsMonitorMode, "IsMonitorMode"),
	RPC_ROW_TIME64(RPC_CLIENT_GET_CONNECTION_STATUS, StartTime, "StartTime"),
	/* !!! Do not correct the spelling to keep the backward protocol compatibility !!!  */
	RPC_ROW_TIME64(RPC_CLIENT_GET_CONNECTION_STATUS, FirstConnectionEstablisiedTime, "FirstConnectionEstablisiedTime"),
	RPC_ROW_TIME64(RPC_CLIENT_GET_CONNECTION_STATUS, CurrentConnectionEstablishTime, "CurrentConnectionEstablishTime"),
	RPC_ROW_INT64(RPC_CLIENT_GET_CONNECTION_STATUS, TotalSendSize, "TotalSendSize"),
	RPC_ROW_INT64(RPC_CLIENT_GET_CONNECTION_STATUS, TotalRecvSize, "TotalRecvSize"),
	RPC_ROW_INT64(RPC_CLIENT_GET_CONNECTION_STATUS, TotalSendSizeReal, "TotalSendSizeReal"),
	RPC_ROW_INT64(RPC_CLIENT_GET_CONNECTION_STATUS, TotalRecvSizeReal, "TotalRecvSizeReal"),
	RPC_ROW_INT(RPC_CLIENT_GET_CONNECTION_STATUS, VLanId, "VLanId"),
	RPC_ROW_HOOK(RPC_FT_STRUCT, RPC_CLIENT_GET_CONNECTION_STATUS, Policy, NULL, 0, &rpc_client_get_connection_status_policy_hook),
	RPC_ROW_HOOK(RPC_FT_STRUCT, RPC_CLIENT_GET_CONNECTION_STATUS, Traffic, NULL, 0, &rpc_client_get_connection_status_traffic_hook),
	RPC_ROW_HOOK(RPC_FT_X, RPC_CLIENT_GET_CONNECTION_STATUS, ServerX, "ServerX", 0, &rpc_client_get_connection_status_x_hook),
	RPC_ROW_HOOK(RPC_FT_X, RPC_CLIENT_GET_CONNECTION_STATUS, ClientX, "ClientX", 0, &rpc_client_get_connection_status_x_hook),
	RPC_ROW_END
};
RPC_TABLE_DEF(rpc_client_get_connection_status_table, RPC_CLIENT_GET_CONNECTION_STATUS, rpc_client_get_connection_status_fields);

void InRpcClientGetConnectionStatus(RPC_CLIENT_GET_CONNECTION_STATUS *s, PACK *p)
{
	RpcFieldIn(&rpc_client_get_connection_status_table, s, p);
}
void OutRpcClientGetConnectionStatus(PACK *p, RPC_CLIENT_GET_CONNECTION_STATUS *c)
{
	RpcFieldOut(&rpc_client_get_connection_status_table, p, c);
}

void CiGetSessionStatus(RPC_CLIENT_GET_CONNECTION_STATUS *st, SESSION *s)
{
	if (st == NULL || s == NULL)
	{
		return;
	}

	Lock(s->lock);
	{
		st->Active = true;

		st->SessionStatus = s->ClientStatus;

		UniStrCpy(st->AccountName, sizeof(st->AccountName), s->ClientOption->AccountName);

		if (s->ClientStatus == CLIENT_STATUS_ESTABLISHED && s->Connection != NULL)
		{
			Lock(s->Connection->lock);
			{
				st->Connected = true;
				StrCpy(st->ServerProductName, sizeof(st->ServerProductName), s->Connection->ServerStr);
				st->ServerProductVer = s->Connection->ServerVer;
				st->ServerProductBuild = s->Connection->ServerBuild;
				st->ServerX = CloneX(s->Connection->ServerX);
				st->ClientX = CloneX(s->Connection->ClientX);
				st->CurrentConnectionEstablishTime = Tick64ToTime64(s->CurrentConnectionEstablishTime);
				st->MaxTcpConnections = s->MaxConnection;
				st->HalfConnection = s->HalfConnection;
				st->VLanId = s->VLanId;
				st->QoS = s->QoS;
				if (s->Connection->Protocol == CONNECTION_TCP)
				{
					UINT i;
					LockList(s->Connection->Tcp->TcpSockList);
					{
						st->NumTcpConnections = LIST_NUM(s->Connection->Tcp->TcpSockList);
						if (st->HalfConnection)
						{
							for (i = 0;i < st->NumTcpConnections;i++)
							{
								TCPSOCK *ts = LIST_DATA(s->Connection->Tcp->TcpSockList, i);
								if (ts->Direction & TCP_SERVER_TO_CLIENT)
								{
									st->NumTcpConnectionsDownload++;
								}
								else
								{
									st->NumTcpConnectionsUpload++;
								}
							}
						}
					}
					UnlockList(s->Connection->Tcp->TcpSockList);
				}
				st->UseEncrypt = s->UseEncrypt;
				if (st->UseEncrypt)
				{
					StrCpy(st->CipherName, sizeof(st->CipherName), s->Connection->CipherName);
					StrCpy(st->ProtocolName, sizeof(st->ProtocolName), s->Connection->SslVersion);
				}
				st->UseCompress = s->UseCompress;
				StrCpy(st->UnderlayProtocol, sizeof(st->UnderlayProtocol), s->UnderlayProtocol);
				StrCpy(st->ProtocolDetails, sizeof(st->ProtocolDetails), s->ProtocolDetails);
				Trim(st->ProtocolDetails);
				st->IsUdpAccelerationEnabled = s->UseUdpAcceleration;
				st->IsUsingUdpAcceleration = s->IsUsingUdpAcceleration;
				Copy(st->SessionKey, s->SessionKey, SHA1_SIZE);
				Copy(&st->Policy, s->Policy, sizeof(POLICY));
				if (s->ServerMode == false)
				{
					st->TotalSendSize = s->TotalSendSize;
					st->TotalRecvSize = s->TotalRecvSize;
					st->TotalRecvSizeReal = s->TotalRecvSizeReal;
					st->TotalSendSizeReal = s->TotalSendSizeReal;
				}
				else
				{
					st->TotalSendSize = s->TotalRecvSize;
					st->TotalRecvSize = s->TotalSendSize;
					st->TotalRecvSizeReal = s->TotalSendSizeReal;
					st->TotalSendSizeReal = s->TotalRecvSizeReal;
				}
				StrCpy(st->SessionName, sizeof(st->SessionName), s->Name);
				StrCpy(st->ConnectionName, sizeof(st->ConnectionName), s->Connection->Name);
				StrCpy(st->ServerName, sizeof(st->ServerName), s->Connection->ServerName);
				st->ServerPort = s->Connection->ServerPort;
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
		st->StartTime = Tick64ToTime64(s->CreatedTime);
		/* !!! Do not correct the spelling to keep the backward protocol compatibility !!!  */
		st->FirstConnectionEstablisiedTime = Tick64ToTime64(s->FirstConnectionEstablisiedTime);
		st->NumConnectionsEstablished = s->NumConnectionsEstablished;
	}
	Unlock(s->lock);
}

void CiFreeClientGetConnectionStatus(RPC_CLIENT_GET_CONNECTION_STATUS *st)
{
	if (st == NULL)
	{
		return;
	}

	if (st->ServerX != NULL)
	{
		FreeX(st->ServerX);
	}

	if (st->ClientX != NULL)
	{
		FreeX(st->ClientX);
	}
}

void ClientAuthFree(CLIENT_AUTH *auth)
{
	if (auth == NULL)
	{
		return;
	}

	if (auth->ClientX != NULL)
	{
		FreeX(auth->ClientX);
	}
	if (auth->ClientK != NULL)
	{
		FreeK(auth->ClientK);
	}

	Free(auth);
}

CLIENT_AUTH *ClientAuthClone(CLIENT_AUTH *a)
{
	CLIENT_AUTH *ret;
	if (a == NULL)
	{
		return NULL;
	}

	ret = ZeroMallocEx(sizeof(CLIENT_AUTH), true);

	ret->AuthType = a->AuthType;
	StrCpy(ret->Username, sizeof(ret->Username), a->Username);
	ret->CheckCertProc = a->CheckCertProc;

	switch (a->AuthType)
	{
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

	case CLIENT_AUTHTYPE_OPENSSLENGINE:
		ret->ClientX = CloneX(a->ClientX);
		StrCpy(ret->OpensslEnginePrivateKeyName, sizeof(ret->OpensslEnginePrivateKeyName), a->OpensslEnginePrivateKeyName);
		StrCpy(ret->OpensslEngineName, sizeof(ret->OpensslEngineName), a->OpensslEngineName);
		ret->ClientK = OpensslEngineToK(ret->OpensslEnginePrivateKeyName, ret->OpensslEngineName);
		break;
	}

	return ret;
}

CLIENT_OPTION *ClientOptionClone(CLIENT_OPTION *o)
{
	CLIENT_OPTION *ret;
	if (o == NULL)
	{
		return NULL;
	}

	ret = ZeroMalloc(sizeof(CLIENT_OPTION));
	Copy(ret, o, sizeof(CLIENT_OPTION));

	return ret;
}

CLIENT_AUTH *CiLoadClientAuth(FOLDER *f)
{
	CLIENT_AUTH *a;
	char *s;
	BUF *b;
	if (f == NULL)
	{
		return NULL;
	}

	a = ZeroMalloc(sizeof(CLIENT_AUTH));

	a->AuthType = CfgGetInt(f, "AuthType");
	CfgGetStr(f, "Username", a->Username, sizeof(a->Username));

	switch (a->AuthType)
	{
	case CLIENT_AUTHTYPE_ANONYMOUS:
		break;

	case CLIENT_AUTHTYPE_PASSWORD:
		CfgGetByte(f, "HashedPassword", a->HashedPassword, SHA1_SIZE);
		break;

	case CLIENT_AUTHTYPE_PLAIN_PASSWORD:
		b = CfgGetBuf(f, "EncryptedPassword");
		if (b != NULL)
		{
			s = DecryptPassword(b);
			StrCpy(a->PlainPassword, sizeof(a->PlainPassword), s);
			Free(s);
			FreeBuf(b);
		}
		break;

	case CLIENT_AUTHTYPE_CERT:
		b = CfgGetBuf(f, "ClientCert");
		if (b != NULL)
		{
			a->ClientX = BufToX(b, false);
		}
		FreeBuf(b);
		b = CfgGetBuf(f, "ClientKey");
		if (b != NULL)
		{
			a->ClientK = BufToK(b, true, false, NULL);
		}
		FreeBuf(b);
		break;

	case CLIENT_AUTHTYPE_OPENSSLENGINE:
		b = CfgGetBuf(f, "ClientCert");
		if (b != NULL)
		{
			a->ClientX = BufToX(b, false);
		}
		FreeBuf(b);
		if (CfgGetStr(f, "OpensslEnginePrivateKeyName", a->OpensslEnginePrivateKeyName, sizeof(a->OpensslEnginePrivateKeyName)))
    {
        a->ClientK = OpensslEngineToK(a->OpensslEnginePrivateKeyName, a->OpensslEngineName);
    }
    CfgGetStr(f, "OpensslEngineName", a->OpensslEngineName, sizeof(a->OpensslEngineName));
		break;
	}

	return a;
}

CLIENT_OPTION *CiLoadClientOption(FOLDER *f)
{
	CLIENT_OPTION *o;
	char *s;
	BUF *b;
	if (f == NULL)
	{
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
	CfgGetIp(f, "BindLocalIP", &o->BindLocalIP);
	o->BindLocalPort = CfgGetInt(f, "BindLocalPort");

	b = CfgGetBuf(f, "HostUniqueKey");
	if (b != NULL)
	{
		if (b->Size == SHA1_SIZE)
		{
			Copy(o->HostUniqueKey, b->Buf, SHA1_SIZE);
		}

		FreeBuf(b);
	}

	return o;
}

void CiWriteClientAuth(FOLDER *f, CLIENT_AUTH *a)
{
	BUF *b;
	if (f == NULL || a == NULL)
	{
		return;
	}

	CfgAddInt(f, "AuthType", a->AuthType);
	CfgAddStr(f, "Username", a->Username);

	switch (a->AuthType)
	{
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
		if (a->ClientK != NULL && a->ClientX != NULL)
		{
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

void CiWriteClientOption(FOLDER *f, CLIENT_OPTION *o)
{
	BUF *b;
	if (f == NULL || o == NULL)
	{
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
	CfgAddIp(f, "BindLocalIP", &o->BindLocalIP);
	CfgAddInt(f, "BindLocalPort", o->BindLocalPort);

	if (o->FromAdminPack)
	{
		CfgAddBool(f, "FromAdminPack", o->FromAdminPack);
	}

	if (IsZero(o->HostUniqueKey, SHA1_SIZE) == false)
	{
		BUF *b = MemToBuf(o->HostUniqueKey, SHA1_SIZE);
		CfgAddBuf(f, "HostUniqueKey", b);
		FreeBuf(b);
	}
}

static char *DecryptPassword(BUF *b)
{
	char *str;
	char *key = "EncryptPassword";
	CRYPT *c;
	if (b == NULL)
	{
		return CopyStr("");
	}

	str = ZeroMalloc(b->Size + 1);
	c = NewCrypt(key, sizeof(key)); // Intentional (symmetric cipher), not a bug: do not change
	Encrypt(c, str, b->Buf, b->Size);
	FreeCrypt(c);

	str[b->Size] = 0;

	return str;
}

static BUF *EncryptPassword(char *password)
{
	UCHAR *tmp;
	UINT size;
	char *key = "EncryptPassword";
	CRYPT *c;
	BUF *b;
	if (password == NULL)
	{
		password = "";
	}

	size = StrLen(password) + 1;
	tmp = ZeroMalloc(size);

	c = NewCrypt(key, sizeof(key)); // Intentional, not a bug: do not change
	Encrypt(c, tmp, password, size - 1);
	FreeCrypt(c);

	b = NewBuf();
	WriteBuf(b, tmp, size - 1);
	SeekBuf(b, 0, 0);
	Free(tmp);

	return b;
}
