// Hub.c
// Virtual HUB module

#include "Hub.h"

#include "Admin.h"
#include "Bridge.h"
#include "Connection.h"
#include "Link.h"
#include "Protocol.h"
#include "Server.h"

#include "Mayaqua/Cfg.h"
#include "Mayaqua/DNS.h"
#include "Mayaqua/FileIO.h"
#include "Mayaqua/Internat.h"
#include "Mayaqua/Memory.h"
#include "Mayaqua/Object.h"
#include "Mayaqua/Str.h"
#include "Mayaqua/Table.h"
#include "Mayaqua/TcpIp.h"
#include "Mayaqua/Tick64.h"

#include <stdlib.h>
#include <string.h>

// These names must be shorter than 64 bytes
ADMIN_OPTION admin_options[] =
{
	{"allow_hub_admin_change_option", 0},
	{"max_users", 0},
	{"max_multilogins_per_user", 0},
	{"max_groups", 0},
	{"max_accesslists", 0},
	{"max_sessions_client_bridge_apply", 0},
	{"max_sessions", 0},
	{"max_sessions_client", 0},
	{"max_sessions_bridge", 0},
	{"max_bitrates_download", 0},
	{"max_bitrates_upload", 0},
	{"deny_empty_password", 0},
	{"deny_bridge", 0},
	{"deny_routing", 0},
	{"deny_qos", 0},
	{"deny_change_user_password", 0},
	{"no_change_users", 0},
	{"no_change_groups", 0},
	{"no_securenat", 0},
	{"no_securenat_enablenat", 0},
	{"no_securenat_enabledhcp", 0},
	{"no_cascade", 0},
	{"no_online", 0},
	{"no_offline", 0},
	{"no_change_log_config", 0},
	{"no_disconnect_session", 0},
	{"no_delete_iptable", 0},
	{"no_delete_mactable", 0},
	{"no_enum_session", 0},
	{"no_query_session", 0},
	{"no_change_admin_password", 0},
	{"no_change_log_switch_type", 0},
	{"no_change_access_list", 0},
	{"no_change_access_control_list", 0},
	{"no_change_cert_list", 0},
	{"no_change_crl_list", 0},
	{"no_read_log_file", 0},
	{"deny_hub_admin_change_ext_option", 0},
	{"no_delay_jitter_packet_loss", 0},
	{"no_change_msg", 0},
	{"no_access_list_include_file", 0},
};

UINT num_admin_options = sizeof(admin_options) / sizeof(ADMIN_OPTION);

// One row per HUB_OPTION member. The config file, the defaults of a new hub and the RPC admin option list all
// follow it; the rows with an admin name come in the order the admin option list has. Config names are those
// of the members, the admin names too unless they are given.
#define	HUB_OPTION_ROW(type, name, admin, def, flags)	\
	{#name, admin, offsetof(HUB_OPTION, name), type, def, flags}
#define	HUB_OPTION_CFG_ROW(type, name, def)				HUB_OPTION_ROW(type, name, NULL, def, 0)
#define	HUB_OPTION_BOOL_ROW(name, def)					HUB_OPTION_ROW(HUB_OPTION_BOOL, name, #name, def, 0)
#define	HUB_OPTION_UINT_ROW(name, def, flags)			HUB_OPTION_ROW(HUB_OPTION_UINT, name, #name, def, flags)

HUB_OPTION_FIELD hub_option_fields[] =
{
	HUB_OPTION_CFG_ROW(HUB_OPTION_UINT, MaxSession, 0),
	HUB_OPTION_CFG_ROW(HUB_OPTION_BOOL, NoEnum, 0),
	HUB_OPTION_ROW(HUB_OPTION_BOOL, NoArpPolling, "NoAddressPollingIPv4", 0, 0),
	HUB_OPTION_ROW(HUB_OPTION_BOOL, NoIPv6AddrPolling, "NoAddressPollingIPv6", 0, 0),
	HUB_OPTION_BOOL_ROW(NoIpTable, 0),
	HUB_OPTION_BOOL_ROW(NoMacAddressLog, 1),
	HUB_OPTION_BOOL_ROW(ManageOnlyPrivateIP, 1),
	HUB_OPTION_BOOL_ROW(ManageOnlyLocalUnicastIPv6, 1),
	HUB_OPTION_BOOL_ROW(DisableIPParsing, 0),
	HUB_OPTION_BOOL_ROW(YieldAfterStorePacket, 0),
	HUB_OPTION_BOOL_ROW(NoSpinLockForPacketDelay, 0),
	HUB_OPTION_UINT_ROW(BroadcastStormDetectionThreshold, 0, 0),
	HUB_OPTION_UINT_ROW(ClientMinimumRequiredBuild, 0, 0),
	HUB_OPTION_BOOL_ROW(FilterPPPoE, 0),
	HUB_OPTION_BOOL_ROW(FilterOSPF, 0),
	HUB_OPTION_BOOL_ROW(FilterIPv4, 0),
	HUB_OPTION_BOOL_ROW(FilterIPv6, 0),
	HUB_OPTION_BOOL_ROW(FilterNonIP, 0),
	HUB_OPTION_BOOL_ROW(NoIPv4PacketLog, 0),
	HUB_OPTION_BOOL_ROW(NoIPv6PacketLog, 0),
	HUB_OPTION_BOOL_ROW(FilterBPDU, 0),
	HUB_OPTION_BOOL_ROW(NoIPv6DefaultRouterInRAWhenIPv6, 0),
	HUB_OPTION_BOOL_ROW(NoLookBPDUBridgeId, 0),
	HUB_OPTION_BOOL_ROW(NoManageVlanId, 0),
	HUB_OPTION_ROW(HUB_OPTION_HEX, VlanTypeId, "VlanTypeId", MAC_PROTO_TAGVLAN, HUB_OPTION_ZERO_IS_DEFAULT),
	HUB_OPTION_ROW(HUB_OPTION_BOOL, FixForDLinkBPDU, "FixForDLinkBPDU", 0, HUB_OPTION_WRITE_IF_TRUE),
	HUB_OPTION_UINT_ROW(RequiredClientId, 0, 0),
	HUB_OPTION_UINT_ROW(AdjustTcpMssValue, 0, 0),
	HUB_OPTION_BOOL_ROW(DisableAdjustTcpMss, 0),
	HUB_OPTION_BOOL_ROW(NoDhcpPacketLogOutsideHub, 1),
	HUB_OPTION_BOOL_ROW(DisableHttpParsing, 0),
	HUB_OPTION_BOOL_ROW(DisableUdpAcceleration, 0),
	HUB_OPTION_BOOL_ROW(DisableUdpFilterForLocalBridgeNic, 0),
	HUB_OPTION_BOOL_ROW(ApplyIPv4AccessListOnArpPacket, 0),
	HUB_OPTION_BOOL_ROW(RemoveDefGwOnDhcpForLocalhost, 1),
	HUB_OPTION_UINT_ROW(AccessListIncludeFileCacheLifetime, ACCESS_LIST_INCLUDE_FILE_CACHE_LIFETIME, HUB_OPTION_ZERO_IS_DEFAULT),
	HUB_OPTION_BOOL_ROW(DisableCheckMacOnLocalBridge, 0),
	HUB_OPTION_BOOL_ROW(DisableCorrectIpOffloadChecksum, 0),
	HUB_OPTION_BOOL_ROW(BroadcastLimiterStrictMode, 0),
	HUB_OPTION_UINT_ROW(MaxLoggedPacketsPerMinute, 0, 0),
	HUB_OPTION_BOOL_ROW(DoNotSaveHeavySecurityLogs, 0),
	HUB_OPTION_BOOL_ROW(DropBroadcastsInPrivacyFilterMode, 1),
	HUB_OPTION_BOOL_ROW(DropArpInPrivacyFilterMode, 1),
	HUB_OPTION_BOOL_ROW(AllowSameUserInPrivacyFilterMode, 0),
	HUB_OPTION_BOOL_ROW(SuppressClientUpdateNotification, 0),
	HUB_OPTION_UINT_ROW(FloodingSendQueueBufferQuota, DEFAULT_FLOODING_QUEUE_LENGTH, 0),
	HUB_OPTION_UINT_ROW(DetectDormantSessionInterval, 0, 0),
	HUB_OPTION_BOOL_ROW(NoPhysicalIPOnPacketLog, 0),
	HUB_OPTION_BOOL_ROW(UseHubNameAsDhcpUserClassOption, 0),
	HUB_OPTION_BOOL_ROW(AllowEapMatchUserByCert, 0),
	HUB_OPTION_UINT_ROW(DhcpDiscoverTimeoutMs, DEFAULT_DHCP_DISCOVER_TIMEOUT, HUB_OPTION_ZERO_IS_DEFAULT),
};

UINT num_hub_option_fields = sizeof(hub_option_fields) / sizeof(HUB_OPTION_FIELD);

// Value of a HUB_OPTION member, a bool as 0 or 1
UINT GetHubOptionField(HUB_OPTION *o, HUB_OPTION_FIELD *f)
{
	UCHAR *p;
	if (o == NULL || f == NULL)
	{
		return 0;
	}

	p = ((UCHAR *)o) + f->Offset;

	if (f->Type == HUB_OPTION_BOOL)
	{
		return *((bool *)p) ? 1 : 0;
	}

	return *((UINT *)p);
}

void SetHubOptionField(HUB_OPTION *o, HUB_OPTION_FIELD *f, UINT value)
{
	UCHAR *p;
	if (o == NULL || f == NULL)
	{
		return;
	}

	p = ((UCHAR *)o) + f->Offset;

	if (f->Type == HUB_OPTION_BOOL)
	{
		*((bool *)p) = (value != 0);
	}
	else
	{
		*((UINT *)p) = value;
	}
}


static LIST *NewUserList()
{
	LIST *o = NewList(CompareUserList);

	return o;
}

static bool IsUserMatchInUserListWithCacheExpires(LIST *o, char *filename, UINT64 user_hash, UINT64 lifetime)
{
	bool ret = false;
	UINT64 now = Tick64();
	if (o == NULL || filename == NULL || user_hash == 0)
	{
		return false;
	}

	LockList(o);
	{
		if (lifetime != 0)
		{
			if (o->Param1 == 0 || (now >= (o->Param1 + lifetime)))
			{
				DeleteAllUserListCache(o);

				o->Param1 = now;
			}
		}

		ret = IsUserMatchInUserList(o, filename, user_hash);
	}
	UnlockList(o);

	return ret;
}
static bool IsUserMatchInUserListWithCacheExpiresAcl(LIST *o, char *name_in_acl, UINT64 user_hash, UINT64 lifetime)
{
	char tmp[16];
	bool exclude = false;
	char filename[MAX_SIZE];
	char filename2[MAX_SIZE];
	bool is_full_path = false;
	bool ret = false;
	if (o == NULL || name_in_acl == NULL || user_hash == 0 || StrLen(name_in_acl) < 9)
	{
		return false;
	}

	StrCpy(tmp, sizeof(tmp), name_in_acl);
	StrLower(tmp);

	tmp[8] = 0;

	if (Cmp(tmp, ACCESS_LIST_INCLUDED_PREFIX, 8) == 0)
	{
		exclude = false;
	}
	else
	{
		exclude = true;
	}

	StrCpy(filename, sizeof(filename), name_in_acl + 8);
	Trim(filename);

	if (filename[0] == '\\' || filename[0] == '/' || (filename[1] == ':' && filename[2] == '\\'))
	{
		is_full_path = true;
	}

	if (is_full_path == false)
	{
		StrCpy(filename2, sizeof(filename2), "@");
		StrCat(filename2, sizeof(filename2), filename);
		StrCpy(filename, sizeof(filename), filename2);
	}

	ret = IsUserMatchInUserListWithCacheExpires(o, filename, user_hash, lifetime);

	if (exclude)
	{
		ret = NEGATIVE_BOOL(ret);
	}

	return ret;
}

bool IsUserMatchInUserList(LIST *o, char *filename, UINT64 user_hash)
{
	USERLIST *u;
	bool ret = false;
	if (o == NULL || filename == NULL || user_hash == 0)
	{
		return false;
	}

	LockList(o);
	{
		u = FindUserList(o, filename);
		if (u == NULL)
		{
			u = LoadUserList(o, filename);
		}

		if (u != NULL)
		{
			ret = IsInt64InList(u->UserHashList, user_hash);
		}
	}
	UnlockList(o);

	return ret;
}

USERLIST *LoadUserList(LIST *o, char *filename)
{
	USERLIST *u;
	BUF *b;
	if (o == NULL || filename == NULL)
	{
		return NULL;
	}

	u = FindUserList(o, filename);

	if (u != NULL)
	{
		Delete(o, u);

		FreeUserListEntry(u);
	}

	u = ZeroMalloc(sizeof(USERLIST));

	StrCpy(u->Filename, sizeof(u->Filename), filename);

	u->UserHashList = NewInt64List();

	b = ReadDumpWithMaxSize(filename, ACCESS_LIST_INCLUDE_FILE_MAX_SIZE);
	if (b != NULL)
	{
		while (true)
		{
			char *line = CfgReadNextLine(b);
			UINT64 ui;
			if (line == NULL)
			{
				break;
			}

			Trim(line);

			if (IsEmptyStr(line) == false)
			{
				if (StartWith(line, "#") == false &&
					StartWith(line, "//") == false &&
					StartWith(line, ";") == false)
				{
					ui = UsernameToInt64(line);

					AddInt64Distinct(u->UserHashList, ui);
				}
			}

			Free(line);
		}

		FreeBuf(b);
	}

	Add(o, u);

	return u;
}

void FreeUserListEntry(USERLIST *u)
{
	if (u == NULL)
	{
		return;
	}

	ReleaseInt64List(u->UserHashList);

	Free(u);
}

USERLIST *FindUserList(LIST *o, char *filename)
{
	USERLIST t, *u;
	if (o == NULL || filename == NULL)
	{
		return NULL;
	}

	Zero(&t, sizeof(t));

	StrCpy(t.Filename, sizeof(t.Filename), filename);

	u = Search(o, &t);

	return u;
}

int CompareUserList(void *p1, void *p2)
{
	USERLIST *u1, *u2;
	if (p1 == NULL || p2 == NULL)
	{
		return 0;
	}
	u1 = *(USERLIST **)p1;
	u2 = *(USERLIST **)p2;
	if (u1 == NULL || u2 == NULL)
	{
		return 0;
	}

	return StrCmpi(u1->Filename, u2->Filename);
}

void DeleteAllUserListCache(LIST *o)
{
	UINT i;
	if (o == NULL)
	{
		return;
	}

	LockList(o);
	{
		for (i = 0;i < LIST_NUM(o);i++)
		{
			USERLIST *u = LIST_DATA(o, i);

			FreeUserListEntry(u);
		}

		DeleteAll(o);
	}
	UnlockList(o);
}

static void FreeUserList(LIST *o)
{
	UINT i;
	if (o == NULL)
	{
		return;
	}

	for (i = 0;i < LIST_NUM(o);i++)
	{
		USERLIST *u = LIST_DATA(o, i);

		FreeUserListEntry(u);
	}

	ReleaseList(o);
}

bool IsURLMsg(wchar_t *str, char *url, UINT url_size)
{
	UNI_TOKEN_LIST *t;
	bool ret = false;
	UINT i;
	UINT n = 0;
	if (str == NULL)
	{
		return false;
	}

	t = UniParseToken(str, L"\r\n");

	for (i = 0;i < t->NumTokens;i++)
	{
		wchar_t *str = t->Token[i];

		if (UniIsEmptyStr(str) == false)
		{
			n++;

			UniTrim(str);

			if (n == 1)
			{
				if (UniStartWith(str, L"http://") ||
					UniStartWith(str, L"https://") ||
					UniStartWith(str, L"ftp://"))
				{
					ret = true;

					UniToStr(url, url_size, str);
				}
			}
		}
	}

	if (n != 1)
	{
		ret = false;
	}

	UniFreeToken(t);

	return ret;
}

UINT GetHubAdminOptionData(RPC_ADMIN_OPTION *ao, char *name)
{
	UINT i;
	if (ao == NULL || name == NULL)
	{
		return INFINITE;
	}

	for (i = 0;i < ao->NumItem;i++)
	{
		ADMIN_OPTION *a = &ao->Items[i];

		if (StrCmpi(a->Name, name) == 0)
		{
			return a->Value;
		}
	}

	return INFINITE;
}

void DataToHubOptionStruct(HUB_OPTION *o, RPC_ADMIN_OPTION *ao)
{
	UINT i;
	if (o == NULL || ao == NULL)
	{
		return;
	}

	for (i = 0;i < num_hub_option_fields;i++)
	{
		HUB_OPTION_FIELD *f = &hub_option_fields[i];

		if (f->AdminName != NULL)
		{
			UINT value = GetHubAdminOptionData(ao, f->AdminName);

			if (value != INFINITE)
			{
				SetHubOptionField(o, f, value);
			}
		}
	}
}

void HubOptionStructToData(RPC_ADMIN_OPTION *ao, HUB_OPTION *o, char *hub_name)
{
	UINT i, num;
	if (ao == NULL || o == NULL || hub_name == NULL)
	{
		return;
	}

	Zero(ao, sizeof(RPC_ADMIN_OPTION));

	StrCpy(ao->HubName, sizeof(ao->HubName), hub_name);

	for (i = 0;i < num_hub_option_fields;i++)
	{
		if (hub_option_fields[i].AdminName != NULL)
		{
			ao->NumItem++;
		}
	}

	ao->Items = ZeroMalloc(sizeof(ADMIN_OPTION) * ao->NumItem);

	num = 0;

	for (i = 0;i < num_hub_option_fields;i++)
	{
		HUB_OPTION_FIELD *f = &hub_option_fields[i];

		if (f->AdminName != NULL)
		{
			ADMIN_OPTION *a = &ao->Items[num++];

			StrCpy(a->Name, sizeof(a->Name), f->AdminName);
			a->Value = GetHubOptionField(o, f);
			UniStrCpy(a->Descrption, sizeof(a->Descrption), GetHubAdminOptionHelpString(a->Name));
		}
	}
}

void SetAcList(LIST *o, LIST *src)
{
	UINT i;
	if (o == NULL || src == NULL)
	{
		return;
	}

	DelAllAc(o);

	for (i = 0;i < LIST_NUM(src);i++)
	{
		AC *ac = LIST_DATA(src, i);

		AddAc(o, ac);
	}
}

void DelAllAc(LIST *o)
{
	UINT i;
	if (o == NULL)
	{
		return;
	}

	for (i = 0;i < LIST_NUM(o);i++)
	{
		AC *ac = LIST_DATA(o, i);

		Free(ac);
	}

	DeleteAll(o);
}

void FreeAcList(LIST *o)
{
	UINT i;
	if (o == NULL)
	{
		return;
	}

	for (i = 0;i < LIST_NUM(o);i++)
	{
		AC *ac = LIST_DATA(o, i);

		Free(ac);
	}

	ReleaseList(o);
}

char *GenerateAcStr(AC *ac)
{
	char tmp[MAX_SIZE];
	char ip[64], mask[64];

	if (ac == NULL)
	{
		return NULL;
	}

	IPToStr(ip, sizeof(ip), &ac->IpAddress);
	MaskToStr(mask, sizeof(mask), &ac->SubnetMask);

	if (ac->Masked == false)
	{
		Format(tmp, sizeof(tmp), "%s", ip);
	}
	else
	{
		Format(tmp, sizeof(tmp), "%s/%s", ip, mask);
	}

	return CopyStr(tmp);
}

bool IsIpDeniedByAcList(IP *ip, LIST *o)
{
	UINT i;
	if (ip == NULL || o == NULL)
	{
		return false;
	}

	for (i = 0;i < LIST_NUM(o);i++)
	{
		AC *ac = LIST_DATA(o, i);

		if (IsIpMaskedByAc(ip, ac))
		{
			if (ac->Deny == false)
			{
				return false;
			}
			else
			{
				return true;
			}
		}
	}

	return false;
}

bool IsIpMaskedByAc(IP *ip, AC *ac)
{
	UINT uip, net, mask;
	if (ip == NULL || ac == NULL)
	{
		return false;
	}

	if (IsIP4(ip))
	{
		uip = IPToUINT(ip);
		net = IPToUINT(&ac->IpAddress);
		mask = IPToUINT(&ac->SubnetMask);

		if (ac->Masked == false)
		{
			if (uip == net)
			{
				return true;
			}
		}
		else
		{
			if ((uip & mask) == (net & mask))
			{
				return true;
			}
		}

		return false;
	}
	else
	{
		if (ac->Masked == false)
		{
			if (CmpIpAddr(ip, &ac->IpAddress) == 0)
			{
				return true;
			}
		}
		else
		{
			IP and1, and2;

			IPAnd6(&and1, ip, &ac->SubnetMask);
			IPAnd6(&and2, &ac->IpAddress, &ac->SubnetMask);

			if (CmpIpAddr(&and1, &and2) == 0)
			{
				return true;
			}
		}

		return false;
	}
}

void AddAc(LIST *o, AC *ac)
{
	if (o == NULL || ac == NULL)
	{
		return;
	}

	if (LIST_NUM(o) < MAX_HUB_ACS)
	{
		Insert(o, Clone(ac, sizeof(AC)));

		NormalizeAcList(o);
	}
}

void NormalizeAcList(LIST *o)
{
	UINT i;
	if (o == NULL)
	{
		return;
	}

	for (i = 0;i < LIST_NUM(o);i++)
	{
		AC *ac = LIST_DATA(o, i);

		if (IsIP6(&ac->IpAddress))
		{
			ac->IpAddress.ipv6_scope_id = 0;
		}

		ac->Id = (i + 1);
	}
}

int CmpAc(void *p1, void *p2)
{
	AC *a1, *a2;
	if (p1 == NULL || p2 == NULL)
	{
		return 0;
	}
	a1 = *(AC **)p1;
	a2 = *(AC **)p2;
	if (a1 == NULL || a2 == NULL)
	{
		return 0;
	}
	if (a1->Priority > a2->Priority)
	{
		return 1;
	}
	else if (a1->Priority < a2->Priority)
	{
		return -1;
	}
	else if (a1->Deny > a2->Deny)
	{
		return 1;
	}
	else if (a1->Deny < a2->Deny)
	{
		return -1;
	}
	else
	{
		return 0;
	}
}

CRL *CopyCrl(CRL *crl)
{
	CRL *ret;
	if (crl == NULL)
	{
		return NULL;
	}

	ret = ZeroMalloc(sizeof(CRL));

	if (crl->Serial != NULL)
	{
		ret->Serial = NewXSerial(crl->Serial->data, crl->Serial->size);
	}

	ret->Name = CopyName(crl->Name);

	Copy(ret->DigestMD5, crl->DigestMD5, MD5_SIZE);
	Copy(ret->DigestSHA1, crl->DigestSHA1, SHA1_SIZE);

	return ret;
}

void FreeCrl(CRL *crl)
{
	if (crl == NULL)
	{
		return;
	}

	if (crl->Serial != NULL)
	{
		FreeXSerial(crl->Serial);
	}

	if (crl->Name != NULL)
	{
		FreeName(crl->Name);
	}

	Free(crl);
}

bool IsValidCertInHub(HUB *h, X *x)
{
	bool ret;
	if (h == NULL || x == NULL)
	{
		return false;
	}

	LockList(h->HubDb->CrlList);
	{
		ret = IsCertMatchCrlList(x, h->HubDb->CrlList);
	}
	UnlockList(h->HubDb->CrlList);

	if (ret)
	{
		return false;
	}

	return true;
}

bool IsCertMatchCrlList(X *x, LIST *o)
{
	UINT i;
	if (x == NULL || o == NULL)
	{
		return false;
	}

	for (i = 0;i < LIST_NUM(o);i++)
	{
		CRL *crl = LIST_DATA(o, i);

		if (IsCertMatchCrl(x, crl))
		{
			return true;
		}
	}

	return false;
}

wchar_t *GenerateCrlStr(CRL *crl)
{
	wchar_t tmp[2048];
	if (crl == NULL)
	{
		return NULL;
	}

	UniStrCpy(tmp, sizeof(tmp), L"");

	if (crl->Name != NULL)
	{
		wchar_t name[MAX_SIZE];

		UniStrCat(tmp, sizeof(tmp), L"Subject=\"");

		GetAllNameFromName(name, sizeof(name), crl->Name);
		UniStrCat(tmp, sizeof(tmp), name);
		UniStrCat(tmp, sizeof(tmp), L"\", ");
	}

	if (crl->Serial != NULL)
	{
		char str[128];
		wchar_t uni[128];

		BinToStrEx(str, sizeof(str), crl->Serial->data, crl->Serial->size);
		StrToUni(uni, sizeof(uni), str);
		UniStrCat(tmp, sizeof(tmp), L"Serial=\"");
		UniStrCat(tmp, sizeof(tmp), uni);
		UniStrCat(tmp, sizeof(tmp), L"\", ");
	}

	if (IsZero(crl->DigestMD5, MD5_SIZE) == false)
	{
		char str[128];
		wchar_t uni[128];

		BinToStrEx(str, sizeof(str), crl->DigestMD5, MD5_SIZE);
		StrToUni(uni, sizeof(uni), str);
		UniStrCat(tmp, sizeof(tmp), L"MD5=\"");
		UniStrCat(tmp, sizeof(tmp), uni);
		UniStrCat(tmp, sizeof(tmp), L"\", ");
	}

	if (IsZero(crl->DigestSHA1, SHA1_SIZE) == false)
	{
		char str[128];
		wchar_t uni[128];

		BinToStrEx(str, sizeof(str), crl->DigestSHA1, SHA1_SIZE);
		StrToUni(uni, sizeof(uni), str);
		UniStrCat(tmp, sizeof(tmp), L"SHA1=\"");
		UniStrCat(tmp, sizeof(tmp), uni);
		UniStrCat(tmp, sizeof(tmp), L"\", ");
	}

	if (UniEndWith(tmp, L", "))
	{
		tmp[UniStrLen(tmp) - 2] = 0;
	}

	return CopyUniStr(tmp);
}

bool IsCertMatchCrl(X *x, CRL *crl)
{
	bool b = true;
	if (x == NULL || crl == NULL)
	{
		return false;
	}

	if (crl->Serial != NULL)
	{
		if (x->serial == NULL || CompareXSerial(x->serial, crl->Serial) == false)
		{
			b = false;
		}
	}

	if (IsZero(crl->DigestMD5, sizeof(crl->DigestMD5)) == false)
	{
		UCHAR test[MD5_SIZE];
		GetXDigest(x, test, false);

		if (Cmp(test, crl->DigestMD5, MD5_SIZE) != 0)
		{
			b = false;
		}
	}

	if (IsZero(crl->DigestSHA1, sizeof(crl->DigestSHA1)) == false)
	{
		UCHAR test[SHA1_SIZE];
		GetXDigest(x, test, true);

		if (Cmp(test, crl->DigestSHA1, SHA1_SIZE) != 0)
		{
			b = false;
		}
	}

	if (crl->Name != NULL)
	{
		NAME *xn, *cn;
		xn = x->subject_name;
		cn = crl->Name;

		if (cn->CommonName != NULL && (UniIsEmptyStr(cn->CommonName) == false))
		{
			if (xn->CommonName == NULL || UniSoftStrCmp(xn->CommonName, cn->CommonName) != 0)
			{
				b = false;
			}
		}

		if (cn->Organization != NULL && (UniIsEmptyStr(cn->Organization) == false))
		{
			if (xn->Organization == NULL || UniSoftStrCmp(xn->Organization, cn->Organization) != 0)
			{
				b = false;
			}
		}

		if (cn->Unit != NULL && (UniIsEmptyStr(cn->Unit) == false))
		{
			if (xn->Unit == NULL || UniSoftStrCmp(xn->Unit, cn->Unit) != 0)
			{
				b = false;
			}
		}

		if (cn->Country != NULL && (UniIsEmptyStr(cn->Country) == false))
		{
			if (xn->Country == NULL || UniSoftStrCmp(xn->Country, cn->Country) != 0)
			{
				b = false;
			}
		}

		if (cn->State != NULL && (UniIsEmptyStr(cn->State) == false))
		{
			if (xn->State == NULL || UniSoftStrCmp(xn->State, cn->State) != 0)
			{
				b = false;
			}
		}

		if (cn->Local != NULL && (UniIsEmptyStr(cn->Local) == false))
		{
			if (xn->Local == NULL || UniSoftStrCmp(xn->Local, cn->Local) != 0)
			{
				b = false;
			}
		}
	}

	return b;
}

wchar_t *GetHubAdminOptionHelpString(char *name)
{
	char tmp[MAX_SIZE];
	wchar_t *ret;
	if (name == NULL)
	{
		return L"";
	}

	Format(tmp, sizeof(tmp), "HUB_AO_%s", name);

	ret = _UU(tmp);
	if (UniIsEmptyStr(ret))
	{
		ret = _UU("HUB_AO_UNKNOWN");
	}

	return ret;
}

void AddHubAdminOptionsDefaults(HUB *h, bool lock)
{
	UINT i;
	if (h == NULL)
	{
		return;
	}

	if (lock)
	{
		LockList(h->AdminOptionList);
	}

	for (i = 0;i < num_admin_options;i++)
	{
		ADMIN_OPTION *e = &admin_options[i];
		ADMIN_OPTION t, *r;

		Zero(&t, sizeof(t));
		StrCpy(t.Name, sizeof(t.Name), e->Name);

		r = Search(h->AdminOptionList, &t);
		if (r == NULL)
		{
			ADMIN_OPTION *a = ZeroMalloc(sizeof(ADMIN_OPTION));

			StrCpy(a->Name, sizeof(a->Name), e->Name);
			a->Value = e->Value;

			Insert(h->AdminOptionList, a);
		}
	}

	if (lock)
	{
		UnlockList(h->AdminOptionList);
	}
}

void DeleteAllHubAdminOption(HUB *h, bool lock)
{
	UINT i;
	if (h == NULL)
	{
		return;
	}

	if (lock)
	{
		LockList(h->AdminOptionList);
	}

	for (i = 0;i < LIST_NUM(h->AdminOptionList);i++)
	{
		Free(LIST_DATA(h->AdminOptionList, i));
	}

	DeleteAll(h->AdminOptionList);

	if (lock)
	{
		UnlockList(h->AdminOptionList);
	}
}

UINT GetHubAdminOption(HUB *h, char *name)
{
	UINT ret = 0;
	if (h == NULL || name == NULL)
	{
		return 0;
	}

	LockList(h->AdminOptionList);
	{
		ADMIN_OPTION *a, t;

		Zero(&t, sizeof(t));
		StrCpy(t.Name, sizeof(t.Name), name);
		Trim(t.Name);

		a = Search(h->AdminOptionList, &t);

		if (a != NULL)
		{
			ret = a->Value;
		}
	}
	UnlockList(h->AdminOptionList);

	return ret;
}

static int CompareAdminOption(void *p1, void *p2)
{
	ADMIN_OPTION *a1, *a2;
	if (p1 == NULL || p2 == NULL)
	{
		return 0;
	}
	a1 = *(ADMIN_OPTION **)p1;
	a2 = *(ADMIN_OPTION **)p2;
	if (a1 == NULL || a2 == NULL)
	{
		return 0;
	}
	return StrCmpi(a1->Name, a2->Name);
}

static void StartHubWatchDog(HUB *h)
{
	THREAD *t;
	if (h == NULL)
	{
		return;
	}

	h->HaltWatchDog = false;
	h->WatchDogEvent = NewEvent();

	t = NewThread(HubWatchDogThread, h);
	WaitThreadInit(t);
	ReleaseThread(t);
}

static void StopHubWatchDog(HUB *h)
{
	if (h == NULL)
	{
		return;
	}

	h->HaltWatchDog = true;
	Set(h->WatchDogEvent);

	WaitThread(h->WatchDogThread, INFINITE);
	ReleaseThread(h->WatchDogThread);
	h->WatchDogThread = NULL;
	h->HaltWatchDog = false;

	ReleaseEvent(h->WatchDogEvent);
	h->WatchDogEvent = NULL;
}

void HubWatchDogThread(THREAD *t, void *param)
{
	UINT num_packets_v4 = 0;
	UINT num_packets_v6 = 0;
	HUB *hub;
	if (t == NULL || param == NULL)
	{
		return;
	}

	hub = (HUB *)param;

	hub->WatchDogThread = t;
	AddRef(t->ref);

	NoticeThreadInit(t);

	while (true)
	{
		LIST *o;
		LIST *o2;
		UINT i, num;
		UINT interval;
		UINT wait_time = 100;
		if (hub->HaltWatchDog)
		{
			break;
		}

		o = NewListFast(NULL);
		o2 = NewListFast(NULL);

		HubLockTables(hub);
		{
			num = HubIpTableNum(hub);
			for (i = 0;i < num;i++)
			{
				IP_TABLE_ENTRY *e = IpTableGet(hub, i);

				if (e == NULL) continue;

				if ((e->UpdatedTime + (UINT64)(IP_TABLE_EXPIRE_TIME)) > Tick64())
				{
					if (e->MacAddress[0] != 0xff || e->MacAddress[1] != 0xff || e->MacAddress[2] != 0xff ||
						e->MacAddress[3] != 0xff || e->MacAddress[4] != 0xff || e->MacAddress[5] != 0xff)
					{
						if (hub->Option->NoArpPolling == false)
						{
							if (IsIP4(&e->Ip))
							{
								MAC_HEADER *mac = ZeroMalloc(sizeof(MAC_HEADER) + sizeof(ARPV4_HEADER));
								ARPV4_HEADER *p = (ARPV4_HEADER *)(((UCHAR *)mac) + sizeof(MAC_HEADER));

								Copy(mac->DestAddress, e->MacAddress, 6);
								Copy(mac->SrcAddress, hub->HubMacAddr, 6);
								mac->Protocol = Endian16(MAC_PROTO_ARPV4);

								p->HardwareType = Endian16(ARP_HARDWARE_TYPE_ETHERNET);
								p->ProtocolType = Endian16(MAC_PROTO_IPV4);
								p->HardwareSize = 6;
								p->ProtocolSize = 4;
								p->Operation = Endian16(ARP_OPERATION_REQUEST);
								Copy(p->SrcAddress, hub->HubMacAddr, 6);
								p->SrcIP = IPToUINT(&hub->HubIp);
								p->TargetAddress[0] =
									p->TargetAddress[1] =
									p->TargetAddress[2] =
									p->TargetAddress[3] =
									p->TargetAddress[4] =
									p->TargetAddress[5] = 0x00;
								p->TargetIP = IPToUINT(&e->Ip);
								Insert(o, mac);
							}
						}

						if (hub->Option->NoIPv6AddrPolling == false)
						{
							if (IsIP6(&e->Ip))
							{
								BUF *buf;
								IPV6_ADDR ip6addr;

								if (IPToIPv6Addr(&ip6addr, &e->Ip))
								{
									buf = BuildNeighborSolicitation(&hub->HubIpV6, &ip6addr,
										hub->HubMacAddr);

									if (buf != NULL)
									{
										BUF *buf2 = NewBuf();
										MAC_HEADER mac;

										Zero(&mac, sizeof(mac));

										Copy(mac.DestAddress, e->MacAddress, 6);
										Copy(mac.SrcAddress, hub->HubMacAddr, 6);
										mac.Protocol = Endian16(MAC_PROTO_IPV6);

										WriteBuf(buf2, &mac, sizeof(MAC_HEADER));

										WriteBuf(buf2, buf->Buf, buf->Size);

										FreeBuf(buf);

										Insert(o2, buf2);
									}
								}
							}
						}
					}
				}
			}
		}
		HubUnlockTables(hub);

		if ((LIST_NUM(o) + LIST_NUM(o2)) != 0)
		{
			interval = HUB_ARP_SEND_INTERVAL / (LIST_NUM(o) + LIST_NUM(o2));
		}
		else
		{
			interval = HUB_ARP_SEND_INTERVAL;
		}

		for (i = 0;i < LIST_NUM(o);i++)
		{
			PKT *packet;
			void *p = LIST_DATA(o, i);

			Wait(hub->WatchDogEvent, interval);
			if (hub->HaltWatchDog)
			{
				for (;i < LIST_NUM(o);i++)
				{
					Free(LIST_DATA(o, i));
				}
				ReleaseList(o);

				for (i = 0;i < LIST_NUM(o2);i++)
				{
					FreeBuf(LIST_DATA(o2, i));
				}
				ReleaseList(o2);
				goto ESCAPE;
			}

			packet = ParsePacket((UCHAR *)p, sizeof(MAC_HEADER) + sizeof(ARPV4_HEADER));
			if (packet != NULL)
			{
				StorePacket(hub, NULL, packet);
				num_packets_v4++;
			}
			else
			{
				Free(p);
			}
		}

		for (i = 0;i < LIST_NUM(o2);i++)
		{
			PKT *packet;
			BUF *buf = LIST_DATA(o2, i);

			Wait(hub->WatchDogEvent, interval);
			if (hub->HaltWatchDog)
			{
				ReleaseList(o);

				for (;i < LIST_NUM(o2);i++)
				{
					FreeBuf(LIST_DATA(o2, i));
				}
				ReleaseList(o2);
				goto ESCAPE;
			}

			packet = ParsePacket(buf->Buf, buf->Size);
			if (packet != NULL)
			{
				StorePacket(hub, NULL, packet);
				num_packets_v6++;
			}
			else
			{
				Free(buf->Buf);
			}

			Free(buf);
		}

		ReleaseList(o);
		ReleaseList(o2);

		if (num == 0)
		{
			wait_time = HUB_ARP_SEND_INTERVAL;
		}

		Wait(hub->WatchDogEvent, wait_time);
	}
ESCAPE:
	return;
}

void GetAccessListStr(char *str, UINT size, ACCESS *a)
{
	char tmp[MAX_SIZE];
	char tmp1[MAX_SIZE];
	char tmp2[MAX_SIZE];
	bool l3 = false;
	bool asterisk = false;
	if (str == NULL || a == NULL)
	{
		return;
	}

	StrCpy(str, size, "");

	if (a->IsIPv6 == false)
	{
		if (a->SrcIpAddress != 0 || a->SrcSubnetMask != 0)
		{
			IPToStr32(tmp1, sizeof(tmp1), a->SrcIpAddress);
			MaskToStr32(tmp2, sizeof(tmp2), a->SrcSubnetMask);
			Format(tmp, sizeof(tmp), "SrcIPv4=%s/%s, ", tmp1, tmp2);
			StrCat(str, size, tmp);

			l3 = true;
		}

		if (a->DestIpAddress != 0 || a->DestSubnetMask != 0)
		{
			IPToStr32(tmp1, sizeof(tmp1), a->DestIpAddress);
			MaskToStr32(tmp2, sizeof(tmp2), a->DestSubnetMask);
			Format(tmp, sizeof(tmp), "DstIPv4=%s/%s, ", tmp1, tmp2);
			StrCat(str, size, tmp);

			l3 = true;
		}
	}
	else
	{
		if (IsZeroIP6Addr(&a->SrcIpAddress6) == false || IsZeroIP6Addr(&a->SrcSubnetMask6) == false)
		{
			IP6AddrToStr(tmp1, sizeof(tmp1), &a->SrcIpAddress6);
			Mask6AddrToStr(tmp2, sizeof(tmp2), &a->SrcSubnetMask6);
			Format(tmp, sizeof(tmp), "SrcIPv6=%s/%s, ", tmp1, tmp2);
			StrCat(str, size, tmp);

			l3 = true;
		}

		if (IsZeroIP6Addr(&a->DestIpAddress6) == false || IsZeroIP6Addr(&a->DestSubnetMask6) == false)
		{
			IP6AddrToStr(tmp1, sizeof(tmp1), &a->DestIpAddress6);
			Mask6AddrToStr(tmp2, sizeof(tmp2), &a->DestSubnetMask6);
			Format(tmp, sizeof(tmp), "DstIPv6=%s/%s, ", tmp1, tmp2);
			StrCat(str, size, tmp);

			l3 = true;
		}
	}

	if (a->Protocol != 0)
	{
		StrCpy(tmp1, sizeof(tmp1), "");
		switch (a->Protocol)
		{
		case 1:
			StrCpy(tmp1, sizeof(tmp1), "ICMPv4");
			break;
		case 3:
			StrCpy(tmp1, sizeof(tmp1), "GGP");
			break;
		case 6:
			StrCpy(tmp1, sizeof(tmp1), "TCP");
			break;
		case 8:
			StrCpy(tmp1, sizeof(tmp1), "EGP");
			break;
		case 12:
			StrCpy(tmp1, sizeof(tmp1), "PUP");
			break;
		case 17:
			StrCpy(tmp1, sizeof(tmp1), "UDP");
			break;
		case 20:
			StrCpy(tmp1, sizeof(tmp1), "HMP");
			break;
		case 22:
			StrCpy(tmp1, sizeof(tmp1), "XNS-IDP");
			break;
		case 27:
			StrCpy(tmp1, sizeof(tmp1), "RDP");
			break;
		case 58:
			StrCpy(tmp1, sizeof(tmp1), "ICMPv6");
			break;
		case 66:
			StrCpy(tmp1, sizeof(tmp1), "RVD");
			break;
		}

		if (IsEmptyStr(tmp1))
		{
			Format(tmp, sizeof(tmp), "Protocol=%s(%u), ", tmp1, a->Protocol);
		}
		else
		{
			Format(tmp, sizeof(tmp), "Protocol=%s, ", tmp1);
		}

		StrCat(str, size, tmp);

		l3 = true;
	}

	if (a->SrcPortStart != 0)
	{
		if (a->SrcPortEnd == a->SrcPortStart)
		{
			Format(tmp, sizeof(tmp), "SrcPort=%u, ", a->SrcPortStart);
			StrCat(str, size, tmp);
		}
		else
		{
			Format(tmp, sizeof(tmp), "SrcPort=%u-%u, ", a->SrcPortStart, a->SrcPortEnd);
			StrCat(str, size, tmp);
		}

		l3 = true;
	}

	if (a->DestPortStart != 0)
	{
		if (a->DestPortEnd == a->DestPortStart)
		{
			Format(tmp, sizeof(tmp), "DstPort=%u, ", a->DestPortStart);
			StrCat(str, size, tmp);
		}
		else
		{
			Format(tmp, sizeof(tmp), "DstPort=%u-%u, ", a->DestPortStart, a->DestPortEnd);
			StrCat(str, size, tmp);
		}

		l3 = true;
	}

	if (StrLen(a->SrcUsername) != 0)
	{
		Format(tmp, sizeof(tmp), "SrcUser=%s, ", a->SrcUsername);
		StrCat(str, size, tmp);
	}

	if (StrLen(a->DestUsername) != 0)
	{
		Format(tmp, sizeof(tmp), "DstUser=%s, ", a->DestUsername);
		StrCat(str, size, tmp);
	}

	if (a->CheckSrcMac != false)
	{
		char mac[MAX_SIZE], mask[MAX_SIZE];
		MacToStr(mac, sizeof(mac), a->SrcMacAddress);
		MacToStr(mask, sizeof(mask), a->SrcMacMask);
		Format(tmp, sizeof(tmp), "SrcMac=%s/%s, ", mac, mask);
		StrCat(str, size, tmp);
	}
	if (a->CheckDstMac != false)
	{
		char mac[MAX_SIZE], mask[MAX_SIZE];
		MacToStr(mac, sizeof(mac), a->DstMacAddress);
		MacToStr(mask, sizeof(mask), a->DstMacMask);
		Format(tmp, sizeof(tmp), "DstMac=%s/%s, ", mac, mask);
		StrCat(str, size, tmp);
	}

	if (a->CheckTcpState)
	{
		if(a->Established)
		{
			StrCat(str, size, "Established, ");
		}
		else
		{
			StrCat(str, size, "Unestablished, ");
		}

		l3 = true;
	}

	if (a->Discard == false)
	{
		if (a->Delay >= 1)
		{
			Format(tmp, sizeof(tmp), "Delay=%u, ", a->Delay);
			StrCat(str, size, tmp);
		}

		if (a->Jitter >= 1)
		{
			Format(tmp, sizeof(tmp), "Jitter=%u, ", a->Jitter);
			StrCat(str, size, tmp);
		}

		if (a->Loss >= 1)
		{
			Format(tmp, sizeof(tmp), "Loss=%u, " , a->Loss);
			StrCat(str, size, tmp);
		}
	}

	if (IsEmptyStr(a->RedirectUrl) == false)
	{
		Format(tmp, sizeof(tmp), "RedirectUrl=%s, ", a->RedirectUrl);
		StrCat(str, size, tmp);
	}

	if (StrLen(str) == 0)
	{
		asterisk = true;
	}

	if (l3)
	{
		if (a->IsIPv6)
		{
			StrCatLeft(str, size, "(ipv6) ");
		}
		else
		{
			StrCatLeft(str, size, "(ipv4) ");
		}
	}
	else
	{
		StrCatLeft(str, size, "(ether) ");
	}

	if (EndWith(str, ", "))
	{
		str[StrLen(str) - 2] = 0;
	}

	if (asterisk)
	{
		StrCat(str, size, "*");
	}
}

// Whether the IPv4 address in an Ethernet ARP packet (the target address when dest, else the sender) lies in addr/mask.
// False for an ARP of another kind, an unset or broadcast address, or a hub-internal address sent from a hub MAC
static bool ArpAddrMatches(PKT *p, bool dest, UINT addr, UINT mask)
{
	ARPV4_HEADER *arp = p->L3.ARPv4Header;
	UINT uint_ip;

	if (arp->HardwareSize != 6 ||
		Endian16(arp->HardwareType) != ARP_HARDWARE_TYPE_ETHERNET ||
		arp->ProtocolSize != 4 ||
		Endian16(arp->ProtocolType) != 0x0800)
	{
		return false;
	}

	uint_ip = dest ? arp->TargetIP : arp->SrcIP;

	if (uint_ip == 0 || uint_ip == 0xffffffff || (IsHubIpAddress32(uint_ip) && IsHubMacAddress(p->MacAddressSrc)))
	{
		return false;
	}

	return (uint_ip & mask) == (addr & mask);
}

// A port range with both ends 0 holds every port
static bool PortInRange(UINT port, UINT start, UINT end)
{
	if (start == 0 && end == 0)
	{
		return true;
	}

	return port >= start && port <= end;
}

// Whether a user (name_in_acl is an include: or exclude: list) matches for hub; never for an internal session.
// user_session is the session of that user, NULL when it is not known
static bool MatchIncludeExcludeUser(HUB *hub, SESSION *user_session, char *name_in_acl, UINT64 user_hash)
{
	if (user_session != NULL && user_session->NormalClient == false)
	{
		// exclude: and include: filters never match internal sessions
		return false;
	}

	return IsUserMatchInUserListWithCacheExpiresAcl(hub->UserList, name_in_acl, user_hash,
		hub->Option->AccessListIncludeFileCacheLifetime * 1000);
}

static bool IsPacketMaskedByAccessList(SESSION *s, PKT *p, ACCESS *a, UINT64 dest_username, UINT64 dest_groupname, SESSION *dest_session)
{
	UINT64 src_username;
	UINT64 src_groupname;
	HUB_PA *pa;
	IPV4_HEADER *ip = NULL;
	IPV6_HEADER *ip6 = NULL;
	bool is_ipv4_packet;
	bool is_ipv6_packet;
	bool is_arp_packet;
	if (s == NULL || p == NULL || a == NULL)
	{
		return false;
	}
	if (a->Active == false)
	{
		return false;
	}

	pa = (HUB_PA *)s->PacketAdapter->Param;

	src_username = pa->UsernameHash;
	src_groupname = pa->GroupnameHash;

	if (a->CheckSrcMac != false)
	{
		UINT i;
		for (i = 0; i < 6; i++)
		{
			if((a->SrcMacAddress[i] & a->SrcMacMask[i]) != (a->SrcMacMask[i] & p->MacAddressSrc[i]))
			{
				return false;
			}
		}
	}

	if (a->CheckDstMac != false)
	{
		UINT i;
		for (i = 0; i < 6; i++)
		{
			if ((a->DstMacAddress[i] & a->DstMacMask[i]) != (a->DstMacMask[i] & p->MacAddressDest[i]))
			{
				return false;
			}
		}
	}

	if (a->SrcUsernameHash != 0)
	{
		if (a->IsSrcUsernameIncludeOrExclude == false)
		{
			if ((a->SrcUsernameHash != src_username) && (a->SrcUsernameHash != src_groupname))
			{
				return false;
			}
		}
		else if (s->Hub != NULL && MatchIncludeExcludeUser(s->Hub, s, a->SrcUsername, src_username) == false)
		{
			return false;
		}
	}

	if (a->DestUsernameHash != 0)
	{
		if (a->IsDestUsernameIncludeOrExclude == false)
		{
			if ((a->DestUsernameHash != dest_username) && (a->DestUsernameHash != dest_groupname))
			{
				return false;
			}
		}
		else if (s->Hub != NULL && MatchIncludeExcludeUser(s->Hub, dest_session, a->DestUsername, dest_username) == false)
		{
			return false;
		}
	}

	is_ipv4_packet = (p->TypeL3 == L3_IPV4);
	is_ipv6_packet = (p->TypeL3 == L3_IPV6);
	is_arp_packet = (p->TypeL3 == L3_ARPV4);

	if (is_ipv4_packet)
	{
		ip = p->L3.IPv4Header;
	}

	if (is_ipv6_packet)
	{
		ip6 = p->L3.IPv6Header;
	}

	if (a->IsIPv6 == false)
	{

		if (a->SrcIpAddress != 0 || a->SrcSubnetMask != 0)
		{
			if (is_ipv4_packet == false)
			{
				if (is_arp_packet == false || ArpAddrMatches(p, false, a->SrcIpAddress, a->SrcSubnetMask) == false)
				{
					return false;
				}
			}
			else
			{
				if ((ip->SrcIP & a->SrcSubnetMask) != (a->SrcIpAddress & a->SrcSubnetMask))
				{
					return false;
				}
			}
		}

		if (a->DestIpAddress != 0 || a->DestSubnetMask != 0)
		{
			if (is_ipv4_packet == false)
			{
				if (is_arp_packet == false || ArpAddrMatches(p, true, a->DestIpAddress, a->DestSubnetMask) == false)
				{
					return false;
				}
			}
			else
			{
				if ((ip->DstIP & a->DestSubnetMask) != (a->DestIpAddress & a->DestSubnetMask))
				{
					return false;
				}
			}
		}
	}
	else
	{

		if (IsZeroIP6Addr(&a->SrcIpAddress6) == false ||
			IsZeroIP6Addr(&a->SrcSubnetMask6) == false)
		{
			if (is_ipv6_packet == false)
			{
				return false;
			}
			else
			{
				IP a_ip, a_subnet, p_ip;
				IP and1, and2;

				IPv6AddrToIP(&a_ip, &a->SrcIpAddress6);
				IPv6AddrToIP(&a_subnet, &a->SrcSubnetMask6);
				IPv6AddrToIP(&p_ip, &ip6->SrcAddress);

				IPAnd6(&and1, &a_ip, &a_subnet);
				IPAnd6(&and2, &p_ip, &a_subnet);

				if (CmpIpAddr(&and1, &and2) != 0)
				{
					return false;
				}
			}
		}

		if (IsZeroIP6Addr(&a->DestIpAddress6) == false ||
			IsZeroIP6Addr(&a->DestSubnetMask6) == false)
		{
			if (is_ipv6_packet == false)
			{
				return false;
			}
			else
			{
				IP a_ip, a_subnet, p_ip;
				IP and1, and2;

				IPv6AddrToIP(&a_ip, &a->DestIpAddress6);
				IPv6AddrToIP(&a_subnet, &a->DestSubnetMask6);
				IPv6AddrToIP(&p_ip, &ip6->DestAddress);

				IPAnd6(&and1, &a_ip, &a_subnet);
				IPAnd6(&and2, &p_ip, &a_subnet);

				if (CmpIpAddr(&and1, &and2) != 0)
				{
					return false;
				}
			}
		}
	}

	if (is_arp_packet && (s->Hub == NULL || s->Hub->Option->ApplyIPv4AccessListOnArpPacket == false))
	{
		return false;
	}

	if (a->Protocol != 0)
	{
		if (a->IsIPv6 == false)
		{
			if (is_ipv4_packet == false)
			{
				return false;
			}
			else
			{
				if (ip->Protocol != a->Protocol)
				{
					return false;
				}
			}
		}
		else
		{
			if (is_ipv6_packet == false)
			{
				return false;
			}
			else
			{
				if (p->IPv6HeaderPacketInfo.Protocol != a->Protocol)
				{
					return false;
				}
			}
		}
	}

	if (a->SrcPortStart != 0 || a->DestPortStart != 0 ||
		a->SrcPortEnd != 0 || a->DestPortEnd != 0)
	{
		if ((a->IsIPv6 == false && is_ipv4_packet == false) ||
			(a->IsIPv6 && is_ipv6_packet == false))
		{
			return false;
		}
		else
		{
			UINT src_port;
			UINT dest_port;

			if (p->TypeL4 == L4_TCP)
			{
				src_port = Endian16(p->L4.TCPHeader->SrcPort);
				dest_port = Endian16(p->L4.TCPHeader->DstPort);
			}
			else if (p->TypeL4 == L4_UDP)
			{
				src_port = Endian16(p->L4.UDPHeader->SrcPort);
				dest_port = Endian16(p->L4.UDPHeader->DstPort);
			}
			else
			{
				return false;
			}

			if (PortInRange(src_port, a->SrcPortStart, a->SrcPortEnd) == false ||
				PortInRange(dest_port, a->DestPortStart, a->DestPortEnd) == false)
			{
				return false;
			}
		}
	}

	if (a->CheckTcpState != false)
	{
		if ((a->IsIPv6 == false && is_ipv4_packet == false) ||
			(a->IsIPv6 && is_ipv6_packet == false))
		{
			return false;
		}
		else
		{
			if(p->TypeL4 == L4_TCP)
			{
				TCP_HEADER *tcp = p->L4.TCPHeader;
				bool est = true;

				if ((tcp->Flag & TCP_SYN) && (!(tcp->Flag & TCP_ACK)))
				{
					est = false;
				}

				if((INT_TO_BOOL(a->Established) ^ INT_TO_BOOL(est)))
				{
					return false;
				}
			}
			else
			{
				return false;
			}
		}
	}

	return true;
}

static bool ApplyAccessListToForwardPacket(HUB *hub, SESSION *src_session, SESSION *dest_session, PKT *p)
{
	UINT i;
	bool pass = true;
	bool skip = true;
	if (hub == NULL || src_session == NULL || p == NULL || dest_session == NULL)
	{
		return false;
	}

	if (p->AccessChecked)
	{
		return true;
	}

	LockList(hub->AccessList);
	{
		for (i = 0;i < LIST_NUM(hub->AccessList);i++)
		{
			ACCESS *a = LIST_DATA(hub->AccessList, i);

			if (a->DestUsernameHash != 0)
			{
				skip = false;
			}

			if (skip == false)
			{
				if (IsPacketMaskedByAccessList(src_session, p, a,
					((HUB_PA *)dest_session->PacketAdapter->Param)->UsernameHash,
					((HUB_PA *)dest_session->PacketAdapter->Param)->GroupnameHash,
					dest_session))
				{
					pass = a->Discard ? false : true;

					break;
				}
			}
		}
	}
	UnlockList(hub->AccessList);

	return pass;
}

// Percent-encode src into dst (RFC 3986): every byte but the unreserved A-Z a-z 0-9 - . _ ~ becomes %XX.
// Byte by byte, because the hash covers exactly the bytes sent and the names have no fixed code page
// (UrlEscapeW takes UTF-16). False when dst is too small
static bool HubUrlEncode(char *dst, UINT size, char *src)
{
	static char hex[] = "0123456789ABCDEF";
	UINT len = StrLen(src);
	UINT n = 0;
	UINT i;
	if (dst == NULL || size == 0)
	{
		return false;
	}

	for (i = 0;i < len;i++)
	{
		UCHAR c = (UCHAR)src[i];

		if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
			c == '-' || c == '.' || c == '_' || c == '~')
		{
			if (n + 1 >= size)
			{
				return false;
			}

			dst[n++] = (char)c;
		}
		else
		{
			if (n + 3 >= size)
			{
				return false;
			}

			dst[n++] = '%';
			dst[n++] = hex[c >> 4];
			dst[n++] = hex[c & 0x0F];
		}
	}

	dst[n] = 0;

	return true;
}

// Whether url can go into a Location header and an href as it is: not empty, no space, no control character
static bool IsRedirectUrlSafe(char *url)
{
	UINT len = StrLen(url);
	UINT i;

	if (len == 0)
	{
		return false;
	}

	for (i = 0;i < len;i++)
	{
		UCHAR c = (UCHAR)url[i];

		if (c <= 0x20 || c == 0x7F)
		{
			return false;
		}
	}

	return true;
}

// HTTP 302 to redirect_url, the payload of a reply forged for session s. When the URL ends in |secret, its
// <INFO> tag becomes user|session|client IP|time|hash, the user and session names percent-encoded and the hash
// the SHA-1 of the text before it and the secret. NULL when a name does not fit or the URL would still hold a
// space or a control character (CR and LF would end the Location line)
static BUF *BuildRedirectToUrlPayload(SESSION *s, char *redirect_url)
{
	char username[MAX_USERNAME_LEN * 3 + 1];
	char session_name[MAX_SESSION_NAME_LEN * 3 + 1];
	char info[sizeof(username) + sizeof(session_name) + MAX_SIZE];
	char redirect_url2[MAX_REDIRECT_URL_LEN + sizeof(info)];
	char html[sizeof(redirect_url2) + MAX_SIZE];
	char header[sizeof(redirect_url2) + MAX_SIZE];
	BUF *b;
	if (s == NULL || redirect_url == NULL)
	{
		return NULL;
	}

	StrCpy(redirect_url2, sizeof(redirect_url2), redirect_url);
	Trim(redirect_url2);

	if (InStr(redirect_url2, ACCESS_LIST_URL_INFO_TAG))
	{
		char secret[MAX_SIZE];
		char *sep;

		ClearStr(secret, sizeof(secret));

		// The secret follows the last '|'
		sep = strrchr(redirect_url2, '|');
		if (sep != NULL)
		{
			StrCpy(secret, sizeof(secret), sep + 1);
			*sep = 0;
		}

		// Without a secret the tag stays as it is
		if (IsEmptyStr(secret) == false)
		{
			UCHAR hash[SHA1_SIZE];
			char hash_str[MAX_SIZE];
			char client_ip[MAX_SIZE];
			SYSTEMTIME st;
			BUF *b2;

			// The client chooses its user name: encoded, it cannot end the URL or a header line, nor add a '|' field
			if (HubUrlEncode(username, sizeof(username), s->Username) == false ||
				HubUrlEncode(session_name, sizeof(session_name), s->Name) == false)
			{
				return NULL;
			}

			SystemTime(&st);
			IPToStr(client_ip, sizeof(client_ip), &s->Connection->ClientIp);

			Format(info, sizeof(info), "%s|%s|%s|%04u%02u%02u%02u%02u%02u|",
				username, session_name, client_ip,
				st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);

			b2 = NewBuf();
			WriteBuf(b2, info, StrLen(info));
			WriteBuf(b2, secret, StrLen(secret));

			Sha1(hash, b2->Buf, b2->Size);

			BinToStr(hash_str, sizeof(hash_str), hash, sizeof(hash));

			FreeBuf(b2);

			StrCat(info, sizeof(info), hash_str);

			ReplaceStrEx(redirect_url2, sizeof(redirect_url2), redirect_url2,
				ACCESS_LIST_URL_INFO_TAG, info, false);
		}
	}

	if (IsRedirectUrlSafe(redirect_url2) == false)
	{
		return NULL;
	}

	Format(html, sizeof(html),
		"<html><head><title>Object moved</title></head><body>\r\n<h2>Object moved to <a href=\"%s\">here</a>.</h2>\r\n</body></html>\r\n\r\n",
		redirect_url2);

	Format(header, sizeof(header),
		"HTTP/1.1 302 Found\r\nLocation: %s\r\nCache-Control: private\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: %u\r\n\r\n",
		redirect_url2, StrLen(html));

	b = NewBuf();

	WriteBuf(b, header, StrLen(header));
	WriteBuf(b, html, StrLen(html));

	return b;
}

static void ForceRedirectToUrl(SESSION *src_session, PKT *p, char *redirect_url)
{
	BUF *payload;
	UINT ip_header_size;
	UINT tcp_size;
	TCP_HEADER *tcp_data;
	TCP_HEADER *src_tcp;
	BUF *b;
	if (src_session == NULL || p == NULL || redirect_url == NULL)
	{
		return;
	}
	if (p->TypeL3 != L3_IPV4 && p->TypeL3 != L3_IPV6)
	{
		return;
	}
	if (p->TypeL4 != L4_TCP)
	{
		return;
	}

	src_tcp = p->L4.TCPHeader;
	if (src_tcp == NULL)
	{
		return;
	}

	payload = BuildRedirectToUrlPayload(src_session, redirect_url);
	if (payload == NULL)
	{
		return;
	}

	// The reply goes back as a single frame
	ip_header_size = (p->TypeL3 == L3_IPV4 ? sizeof(IPV4_HEADER) : sizeof(IPV6_HEADER));
	tcp_size = sizeof(TCP_HEADER) + payload->Size;
	if (sizeof(MAC_HEADER) + ip_header_size + tcp_size > MAX_PACKET_SIZE)
	{
		FreeBuf(payload);
		return;
	}

	tcp_data = (TCP_HEADER *)ZeroMalloc(tcp_size);
	tcp_data->SrcPort = src_tcp->DstPort;
	tcp_data->DstPort = src_tcp->SrcPort;
	tcp_data->SeqNumber = src_tcp->AckNumber;
	tcp_data->AckNumber = Endian32(Endian32(src_tcp->SeqNumber) + p->PayloadSize);
	TCP_SET_HEADER_SIZE(tcp_data, 5);
	tcp_data->Flag = TCP_ACK | TCP_PSH;
	tcp_data->WindowSize = Endian16(0xFFFF);
	Copy(((UCHAR *)tcp_data) + sizeof(TCP_HEADER), payload->Buf, payload->Size);

	if (p->TypeL3 == L3_IPV4)
	{
		tcp_data->Checksum = CalcChecksumForIPv4(p->L3.IPv4Header->DstIP, p->L3.IPv4Header->SrcIP, IP_PROTO_TCP,
			tcp_data, tcp_size, 0);
	}
	else
	{
		tcp_data->Checksum = CalcChecksumForIPv6(&p->IPv6HeaderPacketInfo.IPv6Header->DestAddress,
			&p->IPv6HeaderPacketInfo.IPv6Header->SrcAddress, IP_PROTO_TCP, tcp_data, tcp_size, 0);
	}

	b = NewBuf();

	WriteBuf(b, p->MacHeader->SrcAddress, 6);
	WriteBuf(b, p->MacHeader->DestAddress, 6);
	WriteBuf(b, &p->MacHeader->Protocol, 2);

	if (p->TypeL3 == L3_IPV4)
	{
		IPV4_HEADER v4;

		Zero(&v4, sizeof(v4));

		IPV4_SET_VERSION(&v4, 4);
		IPV4_SET_HEADER_LEN(&v4, 5);
		v4.TotalLength = Endian16((USHORT)(sizeof(IPV4_HEADER) + tcp_size));
		v4.Identification = Endian16(Rand16());
		IPV4_SET_FLAGS(&v4, 0x02);
		v4.TimeToLive = 128;
		v4.Protocol = IP_PROTO_TCP;
		v4.SrcIP = p->L3.IPv4Header->DstIP;
		v4.DstIP = p->L3.IPv4Header->SrcIP;
		v4.Checksum = IpChecksum(&v4, sizeof(v4));

		WriteBuf(b, &v4, sizeof(v4));
	}
	else
	{
		IPV6_HEADER v6;

		Zero(&v6, sizeof(v6));

		IPV6_SET_VERSION(&v6, 6);
		v6.PayloadLength = Endian16((USHORT)tcp_size);
		v6.NextHeader = IP_PROTO_TCP;
		v6.HopLimit = 64;

		Copy(&v6.SrcAddress, &p->IPv6HeaderPacketInfo.IPv6Header->DestAddress, sizeof(IPV6_ADDR));
		Copy(&v6.DestAddress, &p->IPv6HeaderPacketInfo.IPv6Header->SrcAddress, sizeof(IPV6_ADDR));

		WriteBuf(b, &v6, sizeof(v6));
	}

	WriteBuf(b, tcp_data, tcp_size);

	StorePacketToHubPa((HUB_PA *)src_session->PacketAdapter->Param,
		NULL, b->Buf, b->Size, NULL, false, false);

	Free(tcp_data);
	FreeBuf(payload);
	Free(b);
}

// DHCPv4: UDP over IPv4 that the parser knows as DHCP
static bool IsDhcpv4(PKT *p)
{
	return (p->TypeL3 == L3_IPV4 && p->TypeL4 == L4_UDP && p->TypeL7 == L7_DHCPV4);
}

// DHCPv6: UDP over IPv6 with a destination port of 546 or 547
static bool IsDhcpv6Port(PKT *p)
{
	if (p->TypeL3 == L3_IPV6 && p->TypeL4 == L4_UDP)
	{
		USHORT port = Endian16(p->L4.UDPHeader->DstPort);

		return (port == 546 || port == 547);
	}

	return false;
}

// EtherType of the MAC header is IPv4 or ARP (false without a MAC header)
static bool IsEtherTypeIPv4(PKT *p)
{
	if (p->MacHeader != NULL)
	{
		USHORT proto = Endian16(p->MacHeader->Protocol);

		return (proto == 0x0800 || proto == 0x0806);
	}

	return false;
}

// EtherType of the MAC header is IPv6 (false without a MAC header)
static bool IsEtherTypeIPv6(PKT *p)
{
	if (p->MacHeader != NULL)
	{
		return (Endian16(p->MacHeader->Protocol) == 0x86dd);
	}

	return false;
}

// EtherType of the MAC header is neither IPv4, ARP nor IPv6 (false without a MAC header)
static bool IsEtherTypeNonIP(PKT *p)
{
	return (p->MacHeader != NULL && IsEtherTypeIPv4(p) == false && IsEtherTypeIPv6(p) == false);
}

static bool ApplyAccessListToStoredPacket(HUB *hub, SESSION *s, PKT *p)
{
	UINT i;
	HUB_OPTION *opt;
	bool pass = true;
	bool use_redirect_url = false;
	char redirect_url[MAX_REDIRECT_URL_LEN + 1];
	if (hub == NULL || s == NULL || p == NULL)
	{
		return false;
	}

	opt = hub->Option;

	if (opt->FilterPPPoE)
	{
		if (p->MacHeader != NULL)
		{
			USHORT proto = Endian16(p->MacHeader->Protocol);
			if (proto == 0x8863 || proto == 0x8864)
			{
				return false;
			}
		}
	}

	if (opt->FilterOSPF)
	{
		if (p->TypeL3 == L3_IPV4)
		{
			if (p->L3.IPv4Header != NULL)
			{
				if (p->L3.IPv4Header->Protocol == 89)
				{
					return false;
				}
			}
		}
	}

	if (opt->FilterIPv4 && IsEtherTypeIPv4(p))
	{
		return false;
	}

	if (opt->FilterIPv6 && IsEtherTypeIPv6(p))
	{
		return false;
	}

	if (opt->FilterNonIP && IsEtherTypeNonIP(p))
	{
		return false;
	}

	if (opt->FilterBPDU)
	{
		if (p->MacHeader != NULL)
		{
			if (p->TypeL3 == L3_BPDU)
			{
				return false;
			}
		}
	}

	LockList(hub->AccessList);
	{
		for (i = 0;i < LIST_NUM(hub->AccessList);i++)
		{
			ACCESS *a = LIST_DATA(hub->AccessList, i);

			if (a->DestUsernameHash != 0)
			{
				break;
			}

			if (IsPacketMaskedByAccessList(s, p, a, 0, 0, NULL))
			{
				pass = a->Discard ? false : true;

				// Mark the packet so the access list skips it on the way out
				p->AccessChecked = true;

				p->Delay = a->Delay;
				p->Jitter = a->Jitter;
				p->Loss = a->Loss;

				if (a->RedirectUrl[0] != 0)
				{
					if ((p->TypeL3 == L3_IPV4 || p->TypeL3 == L3_IPV6) &&
						p->TypeL4 == L4_TCP)
					{
						TCP_HEADER *tcp = p->L4.TCPHeader;

						if (tcp != NULL)
						{
							if (tcp->Flag & TCP_ACK)
							{
								if ((tcp->Flag & TCP_SYN) == 0 &&
									(tcp->Flag & TCP_RST) == 0 &&
									(tcp->Flag & TCP_URG) == 0)
								{
									if (p->PayloadSize != 0)
									{
										use_redirect_url = true;
										StrCpy(redirect_url, sizeof(redirect_url), a->RedirectUrl);
									}
								}
							}
						}
					}
				}

				break;
			}
		}
	}
	UnlockList(hub->AccessList);

	if (use_redirect_url)
	{
		if (s->NormalClient)
		{
			// Normal VPN clients get the URL redirect; local bridges only drop the packet
			ForceRedirectToUrl(s, p, redirect_url);
		}

		pass = false;
	}

	return pass;
}

void AddAccessListEx(HUB *hub, ACCESS *a, bool no_sort, bool no_reassign_id)
{
	if (hub == NULL || a == NULL)
	{
		return;
	}

	LockList(hub->AccessList);
	{
		ACCESS *access;
		UINT i;

		if (LIST_NUM(hub->AccessList) >= MAX_ACCESSLISTS)
		{
			UnlockList(hub->AccessList);
			return;
		}

		access = Malloc(sizeof(ACCESS));
		Copy(access, a, sizeof(ACCESS));

		access->IsSrcUsernameIncludeOrExclude = false;
		access->IsDestUsernameIncludeOrExclude = false;

		if (IsEmptyStr(access->SrcUsername) == false)
		{
			if (StartWith(access->SrcUsername, ACCESS_LIST_INCLUDED_PREFIX) == false && StartWith(access->SrcUsername, ACCESS_LIST_EXCLUDED_PREFIX) == false)
			{
				MakeSimpleUsernameRemoveNtDomain(access->SrcUsername, sizeof(access->SrcUsername), access->SrcUsername);
			}
			else
			{
				access->IsSrcUsernameIncludeOrExclude = true;
			}
		}
		if (IsEmptyStr(access->DestUsername) == false)
		{
			if (StartWith(access->DestUsername, ACCESS_LIST_INCLUDED_PREFIX) == false && StartWith(access->DestUsername, ACCESS_LIST_EXCLUDED_PREFIX) == false)
			{
				MakeSimpleUsernameRemoveNtDomain(access->DestUsername, sizeof(access->DestUsername), access->DestUsername);
			}
			else
			{
				access->IsDestUsernameIncludeOrExclude = true;
			}
		}

		access->SrcUsernameHash = UsernameToInt64(access->SrcUsername);
		access->DestUsernameHash = UsernameToInt64(access->DestUsername);

		if (access->SrcPortStart != 0)
		{
			access->SrcPortEnd = MAX(access->SrcPortEnd, access->SrcPortStart);
		}
		if (access->DestPortStart != 0)
		{
			access->DestPortEnd = MAX(access->DestPortEnd, access->DestPortStart);
		}

		access->Delay = MAKESURE(access->Delay, 0, HUB_ACCESSLIST_DELAY_MAX);
		access->Jitter = MAKESURE(access->Jitter, 0, HUB_ACCESSLIST_JITTER_MAX);
		access->Loss = MAKESURE(access->Loss, 0, HUB_ACCESSLIST_LOSS_MAX);

		if (no_sort == false)
		{
			Insert(hub->AccessList, access);
		}
		else
		{
			Add(hub->AccessList, access);
		}

		if (no_reassign_id == false)
		{
			for (i = 0;i < LIST_NUM(hub->AccessList);i++)
			{
				ACCESS *a = LIST_DATA(hub->AccessList, i);
				a->Id = (i + 1);
			}
		}
	}
	UnlockList(hub->AccessList);
}

static void InitAccessList(HUB *hub)
{
	if (hub == NULL)
	{
		return;
	}

	hub->AccessList = NewList(CmpAccessList);
}

static void FreeAccessList(HUB *hub)
{
	UINT i;
	if (hub == NULL)
	{
		return;
	}

	for (i = 0;i < LIST_NUM(hub->AccessList);i++)
	{
		ACCESS *a = LIST_DATA(hub->AccessList, i);
		Free(a);
	}

	ReleaseList(hub->AccessList);
	hub->AccessList = NULL;
}

int CmpAccessList(void *p1, void *p2)
{
	ACCESS *a1, *a2;
	if (p1 == NULL || p2 == NULL)
	{
		return 0;
	}
	a1 = *(ACCESS **)p1;
	a2 = *(ACCESS **)p2;
	if (a1 == NULL || a2 == NULL)
	{
		return 0;
	}
	if (a1->Priority > a2->Priority)
	{
		return 1;
	}
	else if (a1->Priority < a2->Priority)
	{
		return -1;
	}
	else if (a1->Discard > a2->Discard)
	{
		return 1;
	}
	else if (a1->Discard < a2->Discard)
	{
		return -1;
	}
	else
	{
		UINT64 size64 = ((UINT64)(&a1->UniqueId) - (UINT64)(&a1->Active));
		UINT size32 = (UINT)size64;

		return Cmp(&a1->Active, &a2->Active, size32);
	}
}

void MakeSimpleUsernameRemoveNtDomain(char *dst, UINT dst_size, char *src)
{
	char tmp1[MAX_SIZE];
	char tmp2[MAX_SIZE];
	if (dst == NULL || src == NULL)
	{
		return;
	}

	ParseNtUsername(src, tmp1, sizeof(tmp1), tmp2, sizeof(tmp2), false);

	StrCpy(dst, dst_size, tmp1);
}

UINT64 UsernameToInt64(char *name)
{
	UCHAR hash[SHA1_SIZE];
	UINT64 ret;
	char tmp[MAX_USERNAME_LEN + 1];
	if (name == 0 || IsEmptyStr(name))
	{
		return 0;
	}

	if (StartWith(name, ACCESS_LIST_INCLUDED_PREFIX) || StartWith(name, ACCESS_LIST_EXCLUDED_PREFIX))
	{
		return Rand64();
	}

	MakeSimpleUsernameRemoveNtDomain(tmp, sizeof(tmp), name);
	Trim(tmp);
	StrUpper(tmp);

	if (StrLen(tmp) == 0)
	{
		return 0;
	}

	Sha0(hash, tmp, StrLen(tmp));
	Copy(&ret, hash, sizeof(ret));

	return ret;
}

SESSION *GetSessionByName(HUB *hub, char *name)
{
	if (hub == NULL || name == NULL)
	{
		return NULL;
	}

	LockList(hub->SessionList);
	{
		UINT i;
		for (i = 0;i < LIST_NUM(hub->SessionList);i++)
		{
			SESSION *s = LIST_DATA(hub->SessionList, i);
			if (StrCmpi(s->Name, name) == 0)
			{
				AddRef(s->ref);
				UnlockList(hub->SessionList);
				return s;
			}
		}
	}
	UnlockList(hub->SessionList);

	return NULL;
}

// Count the hub's sessions that count against the multi-login limit of username:
// not bridge, not cascade server side, at least one TCP connection, and a UniqueId
// that is zero or different from unique_id.
// Lock order: hub->lock, then SessionList, then s->lock, then the TcpSockList lock.
// The caller must not hold hub->lock (ServerAccept unlocks it around this call).
UINT HubCountUserSessions(HUB *h, char *username, UCHAR *unique_id)
{
	UINT num = 0;
	if (h == NULL || username == NULL || unique_id == NULL)
	{
		return 0;
	}

	LockList(h->SessionList);
	{
		UINT i;
		for (i = 0;i < LIST_NUM(h->SessionList);i++)
		{
			SESSION *s = LIST_DATA(h->SessionList, i);
			Lock(s->lock);
			{
				UINT num_tcp;
				LockList(s->Connection->Tcp->TcpSockList);
				{
					num_tcp = s->Connection->Tcp->TcpSockList->num_item;
				}
				UnlockList(s->Connection->Tcp->TcpSockList);

				if (s->BridgeMode == false && s->LinkModeServer == false && num_tcp != 0 &&
					StrCmpi(s->Username, username) == 0 &&
					(IsZero(s->NodeInfo.UniqueId, 16) || Cmp(s->NodeInfo.UniqueId, unique_id, 16) != 0))
				{
					num++;
				}
			}
			Unlock(s->lock);
		}
	}
	UnlockList(h->SessionList);

	return num;
}

static int CompareStormList(void *p1, void *p2)
{
	STORM *s1, *s2;
	UINT r;
	if (p1 == NULL || p2 == NULL)
	{
		return 0;
	}
	s1 = *(STORM **)p1;
	s2 = *(STORM **)p2;
	if (s1 == NULL || s2 == NULL)
	{
		return 0;
	}
	if (s1->StrictMode == false && s2->StrictMode == false)
	{
		r = CmpIpAddr(&s1->DestIp, &s2->DestIp);
		if (r != 0)
		{
			return r;
		}
		r = CmpIpAddr(&s1->SrcIp, &s2->SrcIp);
		if (r != 0)
		{
			return r;
		}
	}
	else
	{
		int r1, r2;
		r1 = CmpIpAddr(&s1->DestIp, &s2->DestIp);
		r2 = CmpIpAddr(&s1->SrcIp, &s2->SrcIp);
		// Strict mode: entries that share either address differ only by MAC address
		if (r1 != 0 && r2 != 0)
		{
			return r1;
		}
	}
	r = Cmp(s1->MacAddress, s2->MacAddress, 6);
	return r;
}

// The MAC table and the IP table of a hub. One lock guards both: the lock of MacHashTable. The functions below
// that take no lock themselves expect the caller to hold it (HubLockTables).
void HubLockTables(HUB *h)
{
	LockHashList(h->MacHashTable);
}

void HubUnlockTables(HUB *h)
{
	UnlockHashList(h->MacHashTable);
}

// Entry counts for status RPCs. Without the table lock the count may be stale, as it always was.
UINT HubMacTableNum(HUB *h)
{
	return HASH_LIST_NUM(h->MacHashTable);
}

UINT HubIpTableNum(HUB *h)
{
	return LIST_NUM(h->IpTable);
}

MAC_TABLE_ENTRY *MacTableLookup(HUB *h, UCHAR *mac, UINT vlan_id)
{
	MAC_TABLE_ENTRY t;

	Copy(t.MacAddress, mac, 6);
	t.VlanId = vlan_id;

	return SearchHash(h->MacHashTable, &t);
}

// Learn mac on vlan_id for session s, which has no entry for it yet. NULL when the table is full (MAX_MAC_TABLES)
MAC_TABLE_ENTRY *MacTableLearn(HUB *h, SESSION *s, UCHAR *mac, UINT vlan_id, UINT64 now)
{
	MAC_TABLE_ENTRY *e;

	if (HASH_LIST_NUM(h->MacHashTable) >= MAX_MAC_TABLES)
	{
		return NULL;
	}

	e = ZeroMalloc(sizeof(MAC_TABLE_ENTRY));
	e->HubPa = (HUB_PA *)s->PacketAdapter->Param;
	Copy(e->MacAddress, mac, 6);
	e->VlanId = vlan_id;
	e->Session = s;
	e->UpdatedTime = e->CreatedTime = now;

	AddHash(h->MacHashTable, e);

	return e;
}

static bool MacTableTakeSessionEntry(void *p, void *param)
{
	MAC_TABLE_ENTRY *e = (MAC_TABLE_ENTRY *)p;

	if (e->Session != (SESSION *)param)
	{
		return false;
	}

	Free(e);

	return true;
}

// Drop every MAC table entry of session s, in one walk over the hash buckets
void MacTableFlushSession(HUB *h, SESSION *s)
{
	DeleteHashIf(h->MacHashTable, MacTableTakeSessionEntry, s);
}

// All MAC table entries; Free() the array. The entries stay valid while the caller holds the table lock
MAC_TABLE_ENTRY **MacTableEnum(HUB *h, UINT *num)
{
	return (MAC_TABLE_ENTRY **)HashListToArray(h->MacHashTable, num);
}

// Drop the MAC table entry of an admin RPC key (POINTER_TO_KEY). Takes the table lock. False when no entry has it
bool MacTableDeleteByKey(HUB *h, UINT key)
{
	bool ret = false;

	HubLockTables(h);
	{
		if (IsInHashListKey(h->MacHashTable, key))
		{
			MAC_TABLE_ENTRY *e = HashListKeyToPointer(h->MacHashTable, key);
			DeleteHash(h->MacHashTable, e);
			Free(e);
			ret = true;
		}
	}
	HubUnlockTables(h);

	return ret;
}

IP_TABLE_ENTRY *IpTableLookup(HUB *h, IP *ip)
{
	IP_TABLE_ENTRY t;

	Copy(&t.Ip, ip, sizeof(IP));

	return Search(h->IpTable, &t);
}

// Entry index of the IP table, sorted by address (0 to HubIpTableNum - 1)
IP_TABLE_ENTRY *IpTableGet(HUB *h, UINT index)
{
	return LIST_DATA(h->IpTable, index);
}

static void IpTableSetEntry(IP_TABLE_ENTRY *e, SESSION *s, IP *ip, UCHAR *mac, bool dhcp_allocated, UINT64 now)
{
	e->CreatedTime = e->UpdatedTime = now;
	e->DhcpAllocated = dhcp_allocated;
	Copy(&e->Ip, ip, sizeof(IP));
	Copy(e->MacAddress, mac, 6);
	e->Session = s;
}

// The table is sorted by address, so the last entry has the highest one: the entry a full table evicts. O(1)
static void DeleteHighestIpTableEntry(LIST *o)
{
	IP_TABLE_ENTRY *e;

	if (LIST_NUM(o) == 0)
	{
		return;
	}

	e = LIST_DATA(o, LIST_NUM(o) - 1);
	o->num_item--;
	Free(e);
}

// The one place that creates an IP table entry: drop the expired entries, evict the highest address when the
// table is full (MAX_IP_TABLES), then insert the new entry for ip
void IpTableAddEntry(HUB *h, SESSION *s, IP *ip, UCHAR *mac, bool dhcp_allocated, UINT64 now)
{
	IP_TABLE_ENTRY *e = ZeroMalloc(sizeof(IP_TABLE_ENTRY));

	IpTableSetEntry(e, s, ip, mac, dhcp_allocated, now);

	DeleteExpiredIpTableEntry(h->IpTable);

	if (LIST_NUM(h->IpTable) >= MAX_IP_TABLES)
	{
		DeleteHighestIpTableEntry(h->IpTable);
	}

	Insert(h->IpTable, e);
}

// IPv6 (v6) or IPv4 addresses that session s holds in the IP table
UINT CountSessionIps(HUB *h, SESSION *s, bool v6)
{
	UINT i, num = 0;

	for (i = 0;i < LIST_NUM(h->IpTable);i++)
	{
		IP_TABLE_ENTRY *e = LIST_DATA(h->IpTable, i);

		if (e->Session == s && (v6 ? IsIP6(&e->Ip) : IsIP4(&e->Ip)))
		{
			num++;
		}
	}

	return num;
}

// True when session s may not learn one more IPv6 (v6) or IPv4 address: it holds the cap of its policy
// (NoRouting / NoRoutingV6, MaxIP / MaxIPv6). Logs LH_IP_LIMIT or LH_ROUTING_LIMIT for ip then. no_cap lifts the
// cap (DHCPv6 and router discovery packets).
static bool IpTableSessionAtLimit(HUB *h, SESSION *s, IP *ip, bool v6, bool no_cap, bool no_heavy)
{
	bool no_routing = v6 ? s->Policy->NoRoutingV6 : s->Policy->NoRouting;
	UINT max_ip = v6 ? s->Policy->MaxIPv6 : s->Policy->MaxIP;
	UINT num_ip_for_me;
	UINT limited_count = 0xffffffff;
	char tmp[64];

	if (no_routing == false && max_ip == 0)
	{
		return false;
	}

	num_ip_for_me = CountSessionIps(h, s, v6);

	if (no_routing)
	{
		limited_count = MIN(limited_count, v6 ? IP_LIMIT_WHEN_NO_ROUTING_V6 : IP_MIN_LIMIT_COUNT);
	}
	if (max_ip != 0)
	{
		limited_count = MIN(limited_count, max_ip);
	}
	limited_count = MAX(limited_count, v6 ? IP_MIN_LIMIT_COUNT_V6 : IP_MIN_LIMIT_COUNT);

	if (no_cap)
	{
		limited_count = 0xffffffff;
	}

	if (num_ip_for_me < limited_count)
	{
		return false;
	}

	if (no_heavy == false)
	{
		IPToStr(tmp, sizeof(tmp), ip);
		HLog(h, no_routing ? "LH_ROUTING_LIMIT" : "LH_IP_LIMIT", s->Name, tmp, num_ip_for_me, limited_count);
	}

	return true;
}

// Session s sent from ip while the IP table gives ip to the other session of entry e
void LogIpConflict(HUB *h, SESSION *s, IP *ip, IP_TABLE_ENTRY *e, UINT64 now)
{
	char ip_address[32];
	char mac_str[48];

	IPToStr(ip_address, sizeof(ip_address), ip);
	MacToStr(mac_str, sizeof(mac_str), e->MacAddress);

	HLog(h, "LH_IP_CONFLICT", s->Name, ip_address, e->Session->Name, mac_str,
		e->CreatedTime, e->UpdatedTime, e->DhcpAllocated, now);
}

// Drop every IP table entry of session s in one pass that keeps the order of the others
void IpTableFlushSession(HUB *h, SESSION *s)
{
	LIST *o = h->IpTable;
	UINT i, num_kept = 0;

	for (i = 0;i < LIST_NUM(o);i++)
	{
		IP_TABLE_ENTRY *e = LIST_DATA(o, i);

		if (e->Session == s)
		{
			Free(e);
		}
		else
		{
			o->p[num_kept++] = e;
		}
	}

	o->num_item = num_kept;
}

// Drop the IP table entry of an admin RPC key (POINTER_TO_KEY). Takes the table lock. False when no entry has it
bool IpTableDeleteByKey(HUB *h, UINT key)
{
	bool ret = false;

	HubLockTables(h);
	{
		IP_TABLE_ENTRY *e = ListKeyToPointer(h->IpTable, key);

		if (e != NULL)
		{
			Delete(h->IpTable, e);
			Free(e);
			ret = true;
		}
	}
	HubUnlockTables(h);

	return ret;
}

static bool HubPaInit(SESSION *s)
{
	HUB_PA *pa = ZeroMalloc(sizeof(HUB_PA));
	pa->Cancel = NewCancel();
	pa->PacketQueue = NewQueue();
	pa->Now = Tick64();
	pa->Session = s;
	pa->StormList = NewList(CompareStormList);
	pa->UsernameHash = UsernameToInt64(s->Username);
	pa->GroupnameHash = UsernameToInt64(s->GroupName);

	s->PacketAdapter->Param = pa;

	if (s->Policy->MonitorPort)
	{
		pa->MonitorPort = true;

		LockList(s->Hub->MonitorList);
		{
			Insert(s->Hub->MonitorList, s);
		}
		UnlockList(s->Hub->MonitorList);
	}

	return true;
}

static void HubPaFree(SESSION *s)
{
	HUB_PA *pa = (HUB_PA *)s->PacketAdapter->Param;
	HUB *hub = s->Hub;

	if (pa->MonitorPort)
	{
		LockList(s->Hub->MonitorList);
		{
			Delete(s->Hub->MonitorList, s);
		}
		UnlockList(s->Hub->MonitorList);
	}

	HubLockTables(hub);
	{
		MacTableFlushSession(hub, s);
		IpTableFlushSession(hub, s);
	}
	HubUnlockTables(hub);

	LockList(pa->StormList);
	{
		UINT i;
		for (i = 0;i < LIST_NUM(pa->StormList);i++)
		{
			STORM *s = (STORM *)LIST_DATA(pa->StormList, i);
			Free(s);
		}
		DeleteAll(pa->StormList);
	}
	UnlockList(pa->StormList);

	ReleaseList(pa->StormList);

	LockQueue(pa->PacketQueue);
	{
		BLOCK *b;

		while (b = GetNext(pa->PacketQueue))
		{
			if (b->IsFlooding)
			{
				CedarAddCurrentTcpQueueSize(s->Cedar, -((int)b->Size));
			}

			FreeBlock(b);
		}
	}
	UnlockQueue(pa->PacketQueue);

	ReleaseQueue(pa->PacketQueue);

	ReleaseCancel(pa->Cancel);

	Free(pa);
	s->PacketAdapter->Param = NULL;
}

static CANCEL *HubPaGetCancel(SESSION *s)
{
	HUB_PA *pa = (HUB_PA *)s->PacketAdapter->Param;

	AddRef(pa->Cancel->ref);
	return pa->Cancel;
}

static UINT HubPaGetNextPacket(SESSION *s, void **data)
{
	UINT ret = 0;
	HUB_PA *pa = (HUB_PA *)s->PacketAdapter->Param;

	LockQueue(pa->PacketQueue);
	{
		BLOCK *block = GetNext(pa->PacketQueue);
		if (block == NULL)
		{
			ret = 0;
		}
		else
		{
			if (block->IsFlooding)
			{
				CedarAddCurrentTcpQueueSize(s->Cedar, -((int)block->Size));
			}

			*data = block->Buf;
			ret = block->Size;
			Free(block);
		}
	}
	UnlockQueue(pa->PacketQueue);

	return ret;
}

static bool HubPaPutPacket(SESSION *s, void *data, UINT size)
{
	PKT *packet;
	HUB_PA *pa = (HUB_PA *)s->PacketAdapter->Param;
	HUB *hub = s->Hub;
	HUB_OPTION *opt = hub->Option;
	bool no_l3;
	bool no_http;
	LIST *o = NULL;
	UINT i;
	UINT vlan_type_id;
	bool no_look_bpdu_bridge_id;
	bool no_parse_dhcp = false;
	bool no_correct_checksum;
	bool no_l7 = false;

	pa->Now = Tick64();

	if (opt->DisableAdjustTcpMss == false)
	{
		UINT target_mss = (opt->AdjustTcpMssValue == 0 ? INFINITE : opt->AdjustTcpMssValue);
		UINT session_mss = (s->AdjustMss == 0 ? INFINITE : s->AdjustMss);

		target_mss = MIN(target_mss, session_mss);

		if (s->UseUdpAcceleration && s->UdpAccelMss != 0)
		{
			target_mss = MIN(target_mss, s->UdpAccelMss);
		}

		if (target_mss != INFINITE)
		{
			AdjustTcpMssL2(data, size, target_mss, opt->VlanTypeId);
		}
	}

	if (data == NULL)
	{
		o = NULL;
		LockList(s->DelayedPacketList);
		{
			UINT i;
			if (LIST_NUM(s->DelayedPacketList) >= 1)
			{
				UINT64 now = TickHighres64();
				for (i = 0;i < LIST_NUM(s->DelayedPacketList);i++)
				{
					PKT *p = LIST_DATA(s->DelayedPacketList, i);

					if (now >= p->DelayedForwardTick)
					{
						if (o == NULL)
						{
							o = NewListFast(NULL);
						}

						Add(o, p);
					}
				}
			}

			if (o != NULL)
			{
				for (i = 0;i < LIST_NUM(o);i++)
				{
					PKT *p = LIST_DATA(o, i);

					Delete(s->DelayedPacketList, p);
				}
			}
		}
		UnlockList(s->DelayedPacketList);

		if (o != NULL)
		{
			for (i = 0;i < LIST_NUM(o);i++)
			{
				PKT *p = LIST_DATA(o, i);

				StorePacket(s->Hub, s, p);
			}

			ReleaseList(o);
		}

		CancelList(s->CancelList);

		if (opt->YieldAfterStorePacket)
		{
			YieldCpu();
		}

		return true;
	}

	no_l3 = opt->DisableIPParsing;
	no_http = opt->DisableHttpParsing;
	vlan_type_id = opt->VlanTypeId;
	no_look_bpdu_bridge_id = opt->NoLookBPDUBridgeId;
	no_correct_checksum = opt->DisableCorrectIpOffloadChecksum;

	if (hub->LogSetting.SavePacketLog == false)
	{
		// Only PacketLog reads the HTTP, TLS SNI and DNS results, and it returns at once while the hub packet
		// log is off, so that parsing is skipped. The DHCP opcode is still parsed: IP learning reads it
		no_l7 = true;
	}

	if (s->VLanId != 0)
	{
		VLanInsertTag(&data, &size, s->VLanId, vlan_type_id);
	}

LABEL_TRY_AGAIN:
	packet = ParsePacketEx5(data, size, no_l3, vlan_type_id, !no_look_bpdu_bridge_id, no_http || no_l7, !no_correct_checksum, no_l7);

	if (packet != NULL)
	{
		if (packet->InvalidSourcePacket)
		{
			FreePacket(packet);
			packet = NULL;
		}
	}


	if (no_parse_dhcp == false && packet != NULL)
	{
		if (opt->RemoveDefGwOnDhcpForLocalhost)
		{
			if (packet->TypeL7 == L7_DHCPV4)
			{
				if (packet->TypeL3 == L3_IPV4)
				{
					if (packet->TypeL4 == L4_UDP)
					{
						if (packet->L7.DHCPv4Header != NULL)
						{
							DHCPV4_HEADER *dhcp = packet->L7.DHCPv4Header;

							if (dhcp->OpCode == 2)
							{
								if (IsMacAddressLocalFast(dhcp->ClientMacAddress))
								{
									BUF *new_buf;
									DHCP_MODIFY_OPTION m;

									Zero(&m, sizeof(m));
									m.RemoveDefaultGatewayOnReply = true;

									new_buf = DhcpModifyIPv4(&m, data, size);

									if (new_buf != NULL)
									{
										Free(data);

										data = new_buf->Buf;
										size = new_buf->Size;

										Free(new_buf);

										no_parse_dhcp = true;

										FreePacket(packet);

										goto LABEL_TRY_AGAIN;
									}
								}
							}
						}
					}
				}
			}
		}
	}

	if (packet != NULL)
	{
		StorePacket(s->Hub, s, packet);
	}
	else
	{
		Free(data);
	}

	return true;
}

// Broadcast storm guard: filter frequent broadcasts from a single endpoint
static bool CheckBroadcastStorm(HUB *hub, SESSION *s, PKT *p)
{
	IP src_ip, dest_ip;
	HUB_PA *pa;
	UINT64 now = Tick64();
	UINT limit_start_count;
	SESSION *sess = s;
	bool ret = true;
	bool strict;
	bool no_heavy;
	if (s == NULL || p == NULL || hub == NULL)
	{
		return false;
	}

	if (s->Policy->NoBroadcastLimiter)
	{
		return true;
	}

	strict = hub->Option->BroadcastLimiterStrictMode;
	no_heavy = hub->Option->DoNotSaveHeavySecurityLogs;

	pa = (HUB_PA *)s->PacketAdapter->Param;

	Zero(&src_ip, sizeof(IP));
	Zero(&dest_ip, sizeof(IP));

	if (p->TypeL3 == L3_IPV4)
	{
		UINTToIP(&src_ip, p->L3.IPv4Header->SrcIP);
		UINTToIP(&dest_ip, p->L3.IPv4Header->DstIP);
	}
	else if (p->TypeL3 == L3_ARPV4)
	{
		UINTToIP(&src_ip, p->L3.ARPv4Header->SrcIP);
		Zero(&dest_ip, sizeof(IP));
	}
	else if (p->TypeL3 == L3_IPV6)
	{
		IPv6AddrToIP(&src_ip, &p->L3.IPv6Header->SrcAddress);
		IPv6AddrToIP(&dest_ip, &p->L3.IPv6Header->DestAddress);
	}

	limit_start_count = 32;

	if (hub->Option->BroadcastStormDetectionThreshold != 0)
	{
		limit_start_count = hub->Option->BroadcastStormDetectionThreshold;
	}

	LockList(pa->StormList);
	{
		STORM *s;
		UINT num;
		s = SearchStormList(pa, p->MacAddressSrc, &src_ip, &dest_ip, strict);
		if (s == NULL)
		{
			s = AddStormList(pa, p->MacAddressSrc, &src_ip, &dest_ip, strict);
		}

		s->CurrentBroadcastNum++;

		if ((s->CheckStartTick + STORM_CHECK_SPAN) < now ||
			s->CheckStartTick == 0 || s->CheckStartTick > now)
		{
			UINT64 diff_time;
			if (s->CheckStartTick < now)
			{
				diff_time = now - s->CheckStartTick;
			}
			else
			{
				diff_time = 0;
			}
			s->CheckStartTick = now;
			num = (UINT)((UINT64)s->CurrentBroadcastNum * (UINT64)1000 / (UINT64)STORM_CHECK_SPAN);
			s->CurrentBroadcastNum = 0;
			if (num >= limit_start_count)
			{
				char ip1[64];
				char ip2[64];
				char mac[MAX_SIZE];
				IPToStr(ip1, sizeof(ip1), &src_ip);
				IPToStr(ip2, sizeof(ip2), &dest_ip);
				ret = false;
				if (s->DiscardValue < STORM_DISCARD_VALUE_END)
				{
					s->DiscardValue = MAX(s->DiscardValue, 1) * 2;
				}

				MacToStr(mac, sizeof(mac), p->MacAddressSrc);

				if (no_heavy == false)
				{
					HLog(sess->Hub, "LH_BCAST_STORM", sess->Name, mac, ip1, ip2, num);
				}
			}
			else
			{
				if (s->DiscardValue >= 1)
				{
					s->DiscardValue = (UINT)((UINT64)s->DiscardValue / MAX((UINT64)2, (UINT64)diff_time / (UINT64)STORM_CHECK_SPAN));
				}
			}
		}

		if (s->DiscardValue >= STORM_DISCARD_VALUE_START)
		{
			if (s->DiscardValue >= 128)
			{
				ret = false;
			}
			else if ((Rand32() % s->DiscardValue) != 0)
			{
				ret = false;
			}
		}

	}
	UnlockList(pa->StormList);

	return ret;
}

// D-Link switches send their spanning tree frames from these two source MACs (FixForDLinkBPDU)
static bool IsDLinkStpMac(UCHAR *mac)
{
	static UCHAR dlink_mac_1[6] = {0x00, 0x80, 0xc8, 0x00, 0x00, 0x00};
	static UCHAR dlink_mac_2[6] = {0x00, 0x0d, 0x88, 0x00, 0x00, 0x00};

	return (Cmp(mac, dlink_mac_1, 6) == 0 || Cmp(mac, dlink_mac_2, 6) == 0);
}

// Security log line for a MAC address that session s now owns in the MAC table
static void HubLogMacRegist(HUB *hub, SESSION *s, UCHAR *mac, UINT vlan_id)
{
	char mac_address[32];

	MacToStr(mac_address, sizeof(mac_address), mac);

	if (vlan_id == 0)
	{
		HLog(hub, "LH_MAC_REGIST", s->Name, mac_address);
	}
	else
	{
		HLog(hub, "LH_MAC_REGIST_VLAN", s->Name, mac_address, vlan_id);
	}
}

// Destination policy: true when the policy of the session a frame goes to drops it. The rule set of the
// unicast branch and of the flood loop of StorePacket (the source side is StorePacketFilterByPolicy)
static bool PolicyDropsPacket(POLICY *pol, PKT *p)
{
	if (pol->RSandRAFilter)
	{
		if (p->TypeL3 == L3_IPV6 &&
			p->TypeL4 == L4_ICMPV6 &&
			(p->ICMPv6HeaderPacketInfo.Type == ICMPV6_TYPE_ROUTER_SOLICIATION ||
			 p->ICMPv6HeaderPacketInfo.Type == ICMPV6_TYPE_ROUTER_ADVERTISEMENT))
		{
			return true;
		}
	}

	if (pol->DHCPFilter)
	{
		if (IsDhcpv4(p))
		{
			return true;
		}
	}

	if (pol->DHCPv6Filter)
	{
		if (IsDhcpv6Port(p))
		{
			return true;
		}
	}

	if (pol->ArpDhcpOnly)
	{
		if (p->BroadcastPacket)
		{
			bool b = true;

			if (IsDhcpv4(p))
			{
				b = false;
			}
			else if (p->TypeL3 == L3_ARPV4)
			{
				b = false;
			}
			else if (IsDhcpv6Port(p))
			{
				b = false;
			}
			else if (p->TypeL3 == L3_IPV6 &&
				p->TypeL4 == L4_ICMPV6)
			{
				b = false;
			}

			if (b)
			{
				return true;
			}
		}
	}

	if (pol->FilterIPv4)
	{
		if (p->TypeL3 == L3_IPV4 || p->TypeL3 == L3_ARPV4)
		{
			return true;
		}
	}

	if (pol->FilterIPv6)
	{
		if (p->TypeL3 == L3_IPV6)
		{
			return true;
		}
	}

	if (pol->FilterNonIP)
	{
		if (p->TypeL3 != L3_IPV4 && p->TypeL3 != L3_ARPV4 && p->TypeL3 != L3_IPV6)
		{
			return true;
		}
	}

	return false;
}

void StorePacket(HUB *hub, SESSION *s, PKT *packet)
{
	MAC_TABLE_ENTRY *entry = NULL;
	UINT vlan_id;
	void *data;
	UINT size;
	bool broadcast_mode;
	HUB_PA *dest_pa;
	SESSION *dest_session;
	UINT64 now = Tick64();
	bool no_heavy = false;
	bool drop_broadcast_packet_privacy = false;
	bool drop_arp_packet_privacy = false;
	bool allow_same_user_packet_privacy = false;
	UINT tcp_queue_quota = 0;
	UINT64 dormant_interval = 0;
	if (hub == NULL || packet == NULL)
	{
		return;
	}

	if (s != NULL)
	{
		if (((HUB_PA *)s->PacketAdapter->Param)->MonitorPort)
		{
			Free(packet->PacketData);
			FreePacket(packet);
			return;
		}
	}

	no_heavy = hub->Option->DoNotSaveHeavySecurityLogs;
	drop_broadcast_packet_privacy = hub->Option->DropBroadcastsInPrivacyFilterMode;
	drop_arp_packet_privacy = hub->Option->DropArpInPrivacyFilterMode;
	allow_same_user_packet_privacy = hub->Option->AllowSameUserInPrivacyFilterMode;
	tcp_queue_quota = hub->Option->FloodingSendQueueBufferQuota;
	if (hub->Option->DetectDormantSessionInterval != 0)
	{
		dormant_interval = (UINT64)hub->Option->DetectDormantSessionInterval * (UINT64)1000;
	}

	if (dormant_interval != 0)
	{
		if (s != NULL && s->NormalClient)
		{
			if (packet->MacAddressSrc != NULL)
			{
				if (IsHubMacAddress(packet->MacAddressSrc) == false)
				{
					s->LastCommTimeForDormant = now;
				}
			}
		}
	}

	HubLockTables(hub);
	{
		if (s != NULL && (packet->DelayedForwardTick == 0 && StorePacketFilter(s, packet) == false))
		{
DISCARD_PACKET:
			Free(packet->PacketData);
			FreePacket(packet);
		}
		else
		{
			bool forward_now = true;

			if (packet->Loss >= 1)
			{
				UINT r = Rand32() % 100;
				if ((packet->Loss >= 100) || (r < packet->Loss))
				{
					goto DISCARD_PACKET;
				}
			}

			if (packet->Delay >= 1)
			{
				// Jitter is a percentage of the delay, in whole ms: a span below 1 ms means no jitter, never a
				// modulo by zero (Delay 10 with Jitter 5 gave a span of 0)
				UINT jitter_span = (UINT)((UINT64)packet->Jitter * (UINT64)packet->Delay / 100);
				UINT jitter = 0;
				UINT delay_uint = packet->Delay;
				bool f = Rand1();
				if (jitter_span != 0)
				{
					jitter = Rand32() % jitter_span;
				}

				if (f)
				{
					delay_uint += jitter;
				}
				else
				{
					delay_uint = (jitter < delay_uint ? delay_uint - jitter : 0);
				}

				if (delay_uint >= 1)
				{
					forward_now = false;
					packet->Loss = packet->Jitter = packet->Delay = 0;
					packet->DelayedForwardTick = TickHighres64() + (UINT64)delay_uint;

					LockList(s->DelayedPacketList);
					{
						Add(s->DelayedPacketList, packet);
					}
					UnlockList(s->DelayedPacketList);
				}
			}

			if (forward_now)
			{
				if (Cmp(packet->MacAddressSrc, hub->HubMacAddr, 6) == 0)
				{
					if (s != NULL)
					{
						// A packet from this hub's own session came back in from outside
						goto DISCARD_PACKET;
					}
				}
				// With a session, a frame from the hub's own MAC address is gone by now
				if (s != NULL)
				{
					if (hub->Option->NoManageVlanId == false)
					{
						vlan_id = packet->VlanId;
					}
					else
					{
						vlan_id = 0;
					}
					entry = MacTableLookup(hub, packet->MacAddressSrc, vlan_id);

					if (entry == NULL)
					{
						if (hub->LastFlushTick == 0 || (hub->LastFlushTick + (UINT64)OLD_MAC_ADDRESS_ENTRY_FLUSH_INTERVAL) < now)
						{
							hub->LastFlushTick = now;

							DeleteExpiredMacTableEntry(hub->MacHashTable);
						}

						if (s->Policy->MaxMac != 0 || s->Policy->NoBridge)
						{
							UINT i, num_mac_for_me = 0;
							UINT limited_count;
							MAC_TABLE_ENTRY **pp;
							UINT num_pp;

							pp = (MAC_TABLE_ENTRY **)HashListToArray(hub->MacHashTable, &num_pp);

							for (i = 0;i < num_pp;i++)
							{
								MAC_TABLE_ENTRY *e = pp[i];
								if (e->Session == s)
								{
									num_mac_for_me++;
								}
							}

							Free(pp);

							limited_count = 0xffffffff;
							if (s->Policy->NoBridge)
							{
								limited_count = MIN(limited_count, MAC_MIN_LIMIT_COUNT);
							}
							if (s->Policy->MaxMac != 0)
							{
								limited_count = MIN(limited_count, s->Policy->MaxMac);
							}
							limited_count = MAX(limited_count, MAC_MIN_LIMIT_COUNT);

							if (num_mac_for_me >= limited_count)
							{
								char mac_str[64];

								MacToStr(mac_str, sizeof(mac_str), packet->MacAddressSrc);
								if (s->Policy->NoBridge)
								{
									if (no_heavy == false)
									{
										HLog(hub, "LH_BRIDGE_LIMIT", s->Name, mac_str, num_mac_for_me, limited_count);
									}
								}
								else
								{
									if (no_heavy == false)
									{
										HLog(hub, "LH_MAC_LIMIT", s->Name, mac_str, num_mac_for_me, limited_count);
									}
								}

								goto DISCARD_PACKET;
							}
						}

						entry = MacTableLearn(hub, s, packet->MacAddressSrc, vlan_id, now);
						if (entry == NULL)
						{
							goto DISCARD_PACKET;
						}

						if (hub->Option->NoMacAddressLog == false && no_heavy == false)
						{
							HubLogMacRegist(hub, s, packet->MacAddressSrc, packet->VlanId);
						}
					}
					else
					{
						if (entry->Session == s)
						{
							entry->UpdatedTime = now;
						}
						else
						{
							bool check_mac = s->Policy->CheckMac;

							if (check_mac == false)
							{
								if (s->BridgeMode)
								{
									check_mac = true;

									if (hub->Option->DisableCheckMacOnLocalBridge)
									{
										check_mac = false;
									}
								}
							}

							if (check_mac && ((entry->UpdatedTime + MAC_TABLE_EXCLUSIVE_TIME) >= now))
							{
								if (hub->Option->FixForDLinkBPDU && IsDLinkStpMac(packet->MacAddressSrc))
								{
									// D-Link sends spanning tree packets from these addresses. CheckMac on a local
									// bridge would break them, so they are handled separately.
									UCHAR hash[MD5_SIZE];
									UINT64 tick_diff = Tick64() - s->LastDLinkSTPPacketSendTick;

									Md5(hash, packet->PacketData, packet->PacketSize);

									if ((s->LastDLinkSTPPacketSendTick != 0) &&
										(tick_diff < 750ULL) &&
										(Cmp(hash, s->LastDLinkSTPPacketDataHash, MD5_SIZE) == 0))
									{
										// Drop a repeat of the same packet within 750 ms
										goto DISCARD_PACKET;
									}
									else
									{
										goto UPDATE_FDB;
									}
								}

								goto DISCARD_PACKET;
							}
							else
							{
UPDATE_FDB:
								entry->Session = s;
								entry->HubPa = (HUB_PA *)s->PacketAdapter->Param;
								entry->UpdatedTime = entry->CreatedTime = now;

								if (no_heavy == false)
								{
									HubLogMacRegist(hub, s, packet->MacHeader->SrcAddress, packet->VlanId);
								}
							}
						}
					}
				}

				broadcast_mode = false;
				dest_pa = NULL;
				dest_session = NULL;

				if (packet->BroadcastPacket)
				{
					broadcast_mode = true;
				}
				else
				{
					if (hub->Option->NoManageVlanId == false)
					{
						vlan_id = packet->VlanId;
					}
					else
					{
						vlan_id = 0;
					}
					entry = MacTableLookup(hub, packet->MacAddressDest, vlan_id);

					if (entry == NULL)
					{
						broadcast_mode = true;
					}
					else
					{
						if (entry->Session != s)
						{
							dest_pa = entry->HubPa;
							dest_session = entry->Session;
						}
						else
						{
							goto DISCARD_PACKET;
						}
					}
				}

				if (s != NULL && hub->Option->NoIpTable == false)
				{
					if (packet->TypeL3 == L3_IPV6)
					{
						IP ip;
						bool b = true;
						UINT ip_type;
						bool dhcp_or_ra = false;

						IPv6AddrToIP(&ip, &packet->L3.IPv6Header->SrcAddress);
						ip_type = GetIPv6AddrType(&packet->L3.IPv6Header->SrcAddress);

						if (!(ip_type & IPV6_ADDR_UNICAST))
						{
							b = false;
						}
						else if ((ip_type & IPV6_ADDR_LOOPBACK) || (ip_type & IPV6_ADDR_ZERO))
						{
							b = false;
						}

						if (packet->TypeL4 == L4_ICMPV6)
						{
							if (packet->ICMPv6HeaderPacketInfo.Type == 133 ||
								packet->ICMPv6HeaderPacketInfo.Type == 134)
							{
								dhcp_or_ra = true;
							}
						}
						else if (IsDhcpv6Port(packet))
						{
							dhcp_or_ra = true;
						}

						if (IsHubMacAddress(packet->MacAddressSrc) &&
							IsHubIpAddress64(&packet->L3.IPv6Header->SrcAddress))
						{
							b = false;
						}

						if (b)
						{
							IP_TABLE_ENTRY *e = IpTableLookup(hub, &ip);

							if (e == NULL)
							{
								if (IpTableSessionAtLimit(hub, s, &ip, true, dhcp_or_ra, no_heavy))
								{
									goto DISCARD_PACKET;
								}

								if (IsIPManagementTargetForHUB(&ip, hub))
								{
									IpTableAddEntry(hub, s, &ip, packet->MacAddressSrc, false, now);
								}
							}
							else
							{
								if (e->Session == s)
								{
									e->UpdatedTime = now;
									Copy(e->MacAddress, packet->MacAddressSrc, 6);
								}
								else
								{
									if ((s->Policy->CheckIPv6) &&
										((e->UpdatedTime + IP_TABLE_EXCLUSIVE_TIME) >= now))
									{
										if (no_heavy == false)
										{
											LogIpConflict(hub, s, &ip, e, now);
										}

										goto DISCARD_PACKET;
									}
								}
							}
						}
					}
				}

				if (
					(s != NULL) &&
					(hub->Option->NoIpTable == false) &&
					(
						(packet->TypeL3 == L3_IPV4 ||
							(packet->TypeL3 == L3_ARPV4 && packet->L3.ARPv4Header->HardwareSize == 6 &&
							Endian16(packet->L3.ARPv4Header->HardwareType) == ARP_HARDWARE_TYPE_ETHERNET &&
							packet->L3.ARPv4Header->ProtocolSize == 4 &&
							Endian16(packet->L3.ARPv4Header->ProtocolType) == 0x0800)
						) &&
						(packet->TypeL7 != L7_DHCPV4)
					)
					)
				{
					IP_TABLE_ENTRY *e;
					IP ip;
					UINT uint_ip = 0;

					if (packet->TypeL3 == L3_IPV4)
					{
						uint_ip = packet->L3.IPv4Header->SrcIP;
					}
					else if (packet->TypeL3 == L3_ARPV4)
					{
						uint_ip = packet->L3.ARPv4Header->SrcIP;
					}

					if (uint_ip != 0 && uint_ip != 0xffffffff && !(IsHubIpAddress32(uint_ip) && IsHubMacAddress(packet->MacAddressSrc)))
					{
						UINTToIP(&ip, uint_ip);

						e = IpTableLookup(hub, &ip);

						if (e == NULL)
						{
							if (s->Policy->DHCPForce)
							{
								char ipstr[MAX_SIZE];

								IPToStr32(ipstr, sizeof(ipstr), uint_ip);
								if (no_heavy == false)
								{
									HLog(hub, "LH_DHCP_FORCE", s->Name, ipstr);
								}
								goto DISCARD_PACKET;
							}

							if (IpTableSessionAtLimit(hub, s, &ip, false, false, no_heavy))
							{
								goto DISCARD_PACKET;
							}

							if (IsIPManagementTargetForHUB(&ip, hub))
							{
								IpTableAddEntry(hub, s, &ip, packet->MacAddressSrc, false, now);
							}
						}
						else
						{
							if (e->Session == s)
							{
								e->UpdatedTime = now;
								Copy(e->MacAddress, packet->MacAddressSrc, 6);
							}
							else
							{
								if ((s->Policy->CheckIP || s->Policy->DHCPForce) &&
									((e->UpdatedTime + IP_TABLE_EXCLUSIVE_TIME) >= now))
								{
									if (no_heavy == false)
									{
										LogIpConflict(hub, s, &ip, e, now);
									}

									goto DISCARD_PACKET;
								}

								if (s->Policy->DHCPForce)
								{
									if (e->DhcpAllocated == false)
									{
										char ipstr[MAX_SIZE];

										IPToStr32(ipstr, sizeof(ipstr), uint_ip);
										if (no_heavy == false)
										{
											HLog(hub, "LH_DHCP_FORCE", s->Name, ipstr);
										}
										goto DISCARD_PACKET;
									}
								}

								e->Session = s;
								e->UpdatedTime = now;
								Copy(e->MacAddress, packet->MacAddressSrc, 6);
							}
						}
					}
				}

				if (s != NULL && broadcast_mode)
				{
					if (CheckBroadcastStorm(hub, s, packet) == false)
					{
						goto DISCARD_PACKET;
					}
				}

				if (hub->MonitorList->num_item != 0)
				{
					LockList(hub->MonitorList);
					{
						UINT i;
						void *data;
						UINT size = packet->PacketSize;
						for (i = 0;i < LIST_NUM(hub->MonitorList);i++)
						{
							SESSION *monitor_session = (SESSION *)LIST_DATA(hub->MonitorList, i);

							if (monitor_session->PacketAdapter->Param != NULL)
							{
								data = Malloc(size);
								Copy(data, packet->PacketData, size);
								StorePacketToHubPa((HUB_PA *)monitor_session->PacketAdapter->Param,
									s, data, size, packet, false, false);
							}
						}
					}
					UnlockList(hub->MonitorList);
				}

				if (broadcast_mode == false)
				{
					if (dest_pa != NULL)
					{
						if (dest_session->Policy->NoIPv6DefaultRouterInRA ||
							(dest_session->Policy->NoIPv6DefaultRouterInRAWhenIPv6 && dest_session->IPv6Session) ||
							(hub->Option->NoIPv6DefaultRouterInRAWhenIPv6 && dest_session->IPv6Session))
						{
							DeleteIPv6DefaultRouterInRA(packet);
						}
						if (PolicyDropsPacket(dest_session->Policy, packet))
						{
							goto DISCARD_UNICAST_PACKET;
						}

						if (s != NULL &&
							((drop_broadcast_packet_privacy || packet->BroadcastPacket == false) &&
							s->Policy->PrivacyFilter &&
							dest_session->Policy->PrivacyFilter)
							)
						{
							if (drop_arp_packet_privacy || packet->TypeL3 != L3_ARPV4)
							{
								if (allow_same_user_packet_privacy == false || StrCmp(s->Username, dest_session->Username))
								{
									goto DISCARD_UNICAST_PACKET;
								}
							}
						}

						if (s != NULL)
						{
							if (Cmp(packet->MacAddressSrc, s->Hub->HubMacAddr, 6) == 0 ||
								Cmp(packet->MacAddressDest, s->Hub->HubMacAddr, 6) == 0)
							{
								goto DISCARD_UNICAST_PACKET;
							}
						}

						if (s != NULL)
						{
							if (PacketLog(s->Hub, s, dest_session, packet, now) == false)
							{
								goto DISCARD_UNICAST_PACKET;
							}
						}

						StorePacketToHubPa(dest_pa, s, packet->PacketData, packet->PacketSize, packet, false, false);
					}
					else
					{
DISCARD_UNICAST_PACKET:
						Free(packet->PacketData);
					}
				}
				else
				{
					UINT current_tcp_queue_size = 0;

					if (s != NULL)
					{
						if (PacketLog(s->Hub, s, NULL, packet, now) == false)
						{
							goto DISCARD_BROADCAST_PACKET;
						}
					}

					LockList(hub->SessionList);
					{
						UINT i, num = LIST_NUM(hub->SessionList);
						for (i = 0;i < num;i++)
						{
							SESSION *dest_session = LIST_DATA(hub->SessionList, i);
							HUB_PA *dest_pa = (HUB_PA *)dest_session->PacketAdapter->Param;
							bool discard = false;

							if (dest_session != s)
							{
								bool delete_default_router_in_ra = false;

								if (dest_session->IsMonitorMode)
								{
									discard = true;
								}

								if (dest_session->NormalClient)
								{
									if (dormant_interval != 0)
									{
										if (dest_session->LastCommTimeForDormant == 0 ||
											(dest_session->LastCommTimeForDormant + dormant_interval) < now)
										{
											discard = true;
										}
									}
								}

								if (tcp_queue_quota != 0)
								{
									current_tcp_queue_size = CedarGetCurrentTcpQueueSize(hub->Cedar);

									if (current_tcp_queue_size >= tcp_queue_quota)
									{
										if (dest_session->Connection != NULL &&
											dest_session->Connection->Protocol == CONNECTION_TCP)
										{
											discard = true;
										}

										if (dest_session->LinkModeServer)
										{
											discard = true;
										}
									}
								}

								if (dest_session->VLanId != 0 && packet->TypeL3 == L3_TAGVLAN &&
									packet->VlanId != dest_session->VLanId)
								{
									discard = true;
								}

								if (dest_session->Policy->NoIPv6DefaultRouterInRA ||
									(dest_session->Policy->NoIPv6DefaultRouterInRAWhenIPv6 && dest_session->IPv6Session) ||
									(hub->Option->NoIPv6DefaultRouterInRAWhenIPv6 && dest_session->IPv6Session))
								{
									if (packet->TypeL3 == L3_IPV6 && packet->TypeL4 == L4_ICMPV6 &&
										(packet->ICMPv6HeaderPacketInfo.Type == ICMPV6_TYPE_ROUTER_ADVERTISEMENT))
									{
										if (packet->ICMPv6HeaderPacketInfo.Headers.RouterAdvertisementHeader->Lifetime != 0)
										{
											delete_default_router_in_ra = true;
										}
									}
								}
								if (PolicyDropsPacket(dest_session->Policy, packet))
								{
									discard = true;
								}

								if (s != NULL &&
									((drop_broadcast_packet_privacy || packet->BroadcastPacket == false) &&
									s->Policy->PrivacyFilter &&
									dest_session->Policy->PrivacyFilter)
									)
								{
									if (drop_arp_packet_privacy || packet->TypeL3 != L3_ARPV4)
									{
										if (allow_same_user_packet_privacy == false || StrCmp(s->Username, dest_session->Username))
										{
											discard = true;
										}
									}
								}

								if (s != NULL)
								{
									if (Cmp(packet->MacAddressSrc, s->Hub->HubMacAddr, 6) == 0 ||
										Cmp(packet->MacAddressDest, s->Hub->HubMacAddr, 6) == 0)
									{
										discard = true;
									}
								}

								if (discard == false && dest_pa != NULL)
								{
									if (s == NULL ||
										ApplyAccessListToForwardPacket(s->Hub, s, dest_pa->Session, packet))
									{
										data = Malloc(packet->PacketSize);
										Copy(data, packet->PacketData, packet->PacketSize);
										size = packet->PacketSize;

										if (delete_default_router_in_ra)
										{
											PKT *pkt2 = ParsePacket(data, size);

											DeleteIPv6DefaultRouterInRA(pkt2);

											FreePacket(pkt2);
										}

										StorePacketToHubPa(dest_pa, s, data, size, packet, true, true);
									}
								}
							}
						}
					}
					UnlockList(hub->SessionList);

DISCARD_BROADCAST_PACKET:
					Free(packet->PacketData);
				}
				FreePacket(packet);
			}
		}
	}
	HubUnlockTables(hub);
}

bool CheckMaxLoggedPacketsPerMinute(SESSION *s, UINT max_packets, UINT64 now)
{
	UINT64 minute = 60 * 1000;
	if (s == NULL || max_packets == 0)
	{
		return true;
	}

	if ((s->Policy != NULL && s->Policy->NoBroadcastLimiter) ||
		s->BridgeMode || s->LinkModeServer || s->LinkModeClient)
	{
		return true;
	}

	if (s->MaxLoggedPacketsPerMinuteStartTick == 0 ||
		((s->MaxLoggedPacketsPerMinuteStartTick + minute) <= now))
	{
		s->MaxLoggedPacketsPerMinuteStartTick = now;
		s->CurrentNumPackets = 0;
	}

	s->CurrentNumPackets++;
	if (s->CurrentNumPackets > max_packets)
	{
		return false;
	}

	return true;
}

bool IsIPManagementTargetForHUB(IP *ip, HUB *hub)
{
	if (ip == NULL || hub == NULL)
	{
		return false;
	}

	if (IsIP4(ip))
	{
		if (hub->Option->ManageOnlyPrivateIP)
		{
			if (IsIPPrivate(ip) == false)
			{
				return false;
			}
		}
	}
	else
	{
		if (hub->Option->ManageOnlyLocalUnicastIPv6)
		{
			UINT ip_type = GetIPAddrType6(ip);

			if (!(ip_type & IPV6_ADDR_LOCAL_UNICAST))
			{
				return false;
			}
		}
	}

	return true;
}


// Drop the storm list entry whose check window started first: the flow that has been quiet the longest
static void DeleteOldestStorm(LIST *o)
{
	STORM *oldest = NULL;
	UINT i;

	for (i = 0;i < LIST_NUM(o);i++)
	{
		STORM *s = LIST_DATA(o, i);

		if (oldest == NULL || s->CheckStartTick < oldest->CheckStartTick)
		{
			oldest = s;
		}
	}

	if (oldest != NULL)
	{
		Delete(o, oldest);
		Free(oldest);
	}
}

STORM *AddStormList(HUB_PA *pa, UCHAR *mac_address, IP *src_ip, IP *dest_ip, bool strict)
{
	STORM *s;
	if (pa == NULL || mac_address == NULL)
	{
		return NULL;
	}

	// One entry per source MAC, source IP and destination IP: a session that varies its addresses would
	// grow the list without bound, so a full list makes room first
	if (LIST_NUM(pa->StormList) >= MAX_STORM_LIST_ENTRIES)
	{
		DeleteOldestStorm(pa->StormList);
	}

	s = ZeroMalloc(sizeof(STORM));
	if (src_ip != NULL)
	{
		Copy(&s->SrcIp, src_ip, sizeof(IP));
	}
	if (dest_ip != NULL)
	{
		Copy(&s->DestIp, dest_ip, sizeof(IP));
	}
	Copy(s->MacAddress, mac_address, 6);
	s->StrictMode = strict;

	Insert(pa->StormList, s);

	return s;
}

STORM *SearchStormList(HUB_PA *pa, UCHAR *mac_address, IP *src_ip, IP *dest_ip, bool strict)
{
	STORM t, *s;
	if (pa == NULL || mac_address == NULL)
	{
		return NULL;
	}

	Zero(&t, sizeof(t));
	if (src_ip != NULL)
	{
		Copy(&t.SrcIp, src_ip, sizeof(IP));
	}
	if (dest_ip != NULL)
	{
		Copy(&t.DestIp, dest_ip, sizeof(IP));
	}
	Copy(t.MacAddress, mac_address, 6);

	t.StrictMode = strict;

	s = Search(pa->StormList, &t);

	return s;
}

void StorePacketToHubPa(HUB_PA *dest, SESSION *src, void *data, UINT size, PKT *packet, bool is_flooding, bool no_check_acl)
{
	BLOCK *b;
	if (dest == NULL || data == NULL)
	{
		return;
	}

	if (size < 14)
	{
		Free(data);
		return;
	}

	if (no_check_acl == false)
	{
		if (src != NULL)
		{
			if (ApplyAccessListToForwardPacket(src->Hub, src, dest->Session, packet) == false)
			{
				Free(data);
				return;
			}
		}
	}

	if (src != NULL)
	{
		if (dest->Session->Policy->MaxDownload != 0)
		{
			if (packet != NULL && IsMostHighestPriorityPacket(dest->Session, packet) == false)
			{
				TRAFFIC_LIMITER *tr = &dest->DownloadLimiter;
				IntoTrafficLimiter(tr, packet);

				if ((tr->Value * (UINT64)1000 / (UINT64)LIMITER_SAMPLING_SPAN) > dest->Session->Policy->MaxDownload)
				{
					Free(data);
					return;
				}
			}
		}
	}

	if (packet != NULL && src != NULL && src->Hub != NULL && src->Hub->Option->FixForDLinkBPDU)
	{
		// Workaround for D-Link BPDUs sent from these source MACs
		if (IsDLinkStpMac(packet->MacAddressSrc))
		{
			SESSION *session = dest->Session;

			if (session != NULL)
			{
				if (session->Policy != NULL && session->Policy->CheckMac)
				{
					UCHAR hash[MD5_SIZE];
					Md5(hash, packet->PacketData, packet->PacketSize);

					Copy(session->LastDLinkSTPPacketDataHash, hash, MD5_SIZE);
					session->LastDLinkSTPPacketSendTick = Tick64();
				}
			}
		}
	}

	if (dest->Session != NULL && dest->Session->VLanId != 0)
	{
		UINT vlan_tpid = 0;
		if (src != NULL && src->Hub != NULL)
		{
			vlan_tpid = src->Hub->Option->VlanTypeId;
		}
		if (VLanRemoveTag(&data, &size, dest->Session->VLanId, vlan_tpid) == false)
		{
			Free(data);
			return;
		}
	}

	if (src != NULL && dest->Session != NULL && src->Hub != NULL)
	{
		if (dest->Session->AdjustMss != 0 ||
			(dest->Session->UseUdpAcceleration && dest->Session->UdpAccelMss != 0))
		{
			if (src->Hub->Option->DisableAdjustTcpMss == false)
			{
				UINT target_mss = INFINITE;
				
				if (dest->Session->AdjustMss != 0)
				{
					target_mss = MIN(target_mss, dest->Session->AdjustMss);
				}

				if (dest->Session->UseUdpAcceleration && dest->Session->UdpAccelMss != 0)
				{
					target_mss = MIN(target_mss, dest->Session->UdpAccelMss);
				}

				if (target_mss != INFINITE)
				{
					AdjustTcpMssL2(data, size, target_mss, src->Hub->Option->VlanTypeId);
				}
			}
		}
	}

	b = NewBlock(data, size, 0);

	LockQueue(dest->PacketQueue);
	{
		if (dest->PacketQueue->num_item < MAX_STORED_QUEUE_NUM)
		{
			InsertQueue(dest->PacketQueue, b);

			if (is_flooding)
			{
				if (src != NULL)
				{
					b->IsFlooding = true;
					CedarAddCurrentTcpQueueSize(src->Cedar, b->Size);
				}
			}
		}
		else
		{
			FreeBlock(b);
		}
	}
	UnlockQueue(dest->PacketQueue);

	if (src != NULL)
	{
		AddCancelList(src->CancelList, dest->Cancel);
	}
	else
	{
		Cancel(dest->Cancel);
	}
}

void DeleteIPv6DefaultRouterInRA(PKT *p)
{
	if (p->TypeL3 == L3_IPV6 && p->TypeL4 == L4_ICMPV6 &&
		(p->ICMPv6HeaderPacketInfo.Type == ICMPV6_TYPE_ROUTER_ADVERTISEMENT))
	{
		if (p->ICMPv6HeaderPacketInfo.Headers.RouterAdvertisementHeader->Lifetime != 0)
		{
			p->ICMPv6HeaderPacketInfo.Headers.RouterAdvertisementHeader->Lifetime = 0;

			p->L4.ICMPHeader->Checksum = 0;
			p->L4.ICMPHeader->Checksum =
				CalcChecksumForIPv6(&p->L3.IPv6Header->SrcAddress,
					&p->L3.IPv6Header->DestAddress, IP_PROTO_ICMPV6,
					p->L4.ICMPHeader, p->IPv6HeaderPacketInfo.PayloadSize, 0);
		}
	}
}

static bool StorePacketFilterByPolicy(SESSION *s, PKT *p)
{
	POLICY *pol;
	HUB *hub;
	bool no_heavy = false;
	if (s == NULL || p == NULL)
	{
		return false;
	}

	hub = s->Hub;

	if (hub != NULL)
	{
		no_heavy = hub->Option->DoNotSaveHeavySecurityLogs;
	}

	pol = s->Policy;

	if (pol->NoServer)
	{
		if (p->TypeL3 == L3_IPV4)
		{
			if (p->TypeL4 == L4_TCP)
			{
				UCHAR flag = p->L4.TCPHeader->Flag;
				if ((flag & TCP_SYN) && (flag & TCP_ACK))
				{
					char ip1[64], ip2[64];

					IPToStr32(ip1, sizeof(ip1), p->L3.IPv4Header->SrcIP);
					IPToStr32(ip2, sizeof(ip2), p->L3.IPv4Header->DstIP);

					if (no_heavy == false)
					{
						HLog(s->Hub, "LH_NO_SERVER", s->Name, ip2, Endian16(p->L4.TCPHeader->DstPort),
							ip1, Endian16(p->L4.TCPHeader->SrcPort));
					}

					return false;
				}
			}
		}
	}

	if (pol->NoServerV6)
	{
		if (p->TypeL3 == L3_IPV6)
		{
			if (p->TypeL4 == L4_TCP)
			{
				UCHAR flag = p->L4.TCPHeader->Flag;
				if ((flag & TCP_SYN) && (flag & TCP_ACK))
				{
					char ip1[128], ip2[128];

					IP6AddrToStr(ip1, sizeof(ip1), &p->IPv6HeaderPacketInfo.IPv6Header->SrcAddress);
					IP6AddrToStr(ip2, sizeof(ip2), &p->IPv6HeaderPacketInfo.IPv6Header->DestAddress);

					if (no_heavy == false)
					{
						HLog(s->Hub, "LH_NO_SERVER", s->Name, ip2, Endian16(p->L4.TCPHeader->DstPort),
							ip1, Endian16(p->L4.TCPHeader->SrcPort));
					}

					return false;
				}
			}
		}
	}

	if (pol->ArpDhcpOnly && p->BroadcastPacket)
	{
		bool ok = false;

		if (p->TypeL3 == L3_ARPV4)
		{
			ok = true;
		}
		if (IsDhcpv4(p))
		{
			ok = true;
		}
		if (p->TypeL3 == L3_IPV6)
		{
			if (p->TypeL4 == L4_ICMPV6)
			{
				ok = true;
			}
		}

		if (IsDhcpv6Port(p))
		{
			ok = true;
		}

		if (ok == false)
		{
			return false;
		}
	}

	if (pol->FilterIPv4)
	{
		if (IsEtherTypeIPv4(p))
		{
			return false;
		}
	}

	if (pol->FilterIPv6)
	{
		if (IsEtherTypeIPv6(p))
		{
			return false;
		}
	}

	if (pol->FilterNonIP)
	{
		if (IsEtherTypeNonIP(p))
		{
			return false;
		}
	}

	if (pol->DHCPFilter)
	{
		if (IsDhcpv4(p))
		{
			return false;
		}
	}

	if (pol->DHCPv6Filter)
	{
		if (IsDhcpv6Port(p))
		{
			return false;
		}
	}

	if (pol->DHCPNoServer)
	{
		if (IsDhcpv4(p))
		{
			DHCPV4_HEADER *h = p->L7.DHCPv4Header;
			if (h->OpCode == 2)
			{
				char ip1[64], ip2[64];

				IPToStr32(ip1, sizeof(ip1), p->L3.IPv4Header->SrcIP);
				IPToStr32(ip2, sizeof(ip2), p->L3.IPv4Header->DstIP);

				if (no_heavy == false)
				{
					HLog(s->Hub, "LH_NO_DHCP", s->Name, ip1, ip2);
				}

				return false;
			}
		}
	}

	if (pol->DHCPv6NoServer)
	{
		if (p->TypeL3 == L3_IPV6 &&
			p->TypeL4 == L4_UDP &&
			(Endian16(p->L4.UDPHeader->DstPort) == 546 || Endian16(p->L4.UDPHeader->SrcPort) == 547))
		{
			char ip1[128], ip2[128];

			IP6AddrToStr(ip1, sizeof(ip1), &p->L3.IPv6Header->SrcAddress);
			IP6AddrToStr(ip2, sizeof(ip2), &p->L3.IPv6Header->DestAddress);

			if (no_heavy == false)
			{
				HLog(s->Hub, "LH_NO_DHCP", s->Name, ip1, ip2);
			}

			return false;
		}
	}

	if (pol->RSandRAFilter)
	{
		if (p->TypeL3 == L3_IPV6 && p->TypeL4 == L4_ICMPV6 &&
			(p->ICMPv6HeaderPacketInfo.Type == ICMPV6_TYPE_ROUTER_SOLICIATION ||
			 p->ICMPv6HeaderPacketInfo.Type == ICMPV6_TYPE_ROUTER_ADVERTISEMENT))
		{
			return false;
		}
	}

	if (pol->RAFilter)
	{
		if (p->TypeL3 == L3_IPV6 && p->TypeL4 == L4_ICMPV6 &&
			p->ICMPv6HeaderPacketInfo.Type == ICMPV6_TYPE_ROUTER_ADVERTISEMENT)
		{
			return false;
		}
	}

	if (IsDhcpv4(p) &&
		(s->Hub != NULL && s->Hub->Option->NoIpTable == false))
	{
		DHCPV4_HEADER *h = p->L7.DHCPv4Header;
		if (h->OpCode == 2 && p->DhcpOpCode == DHCP_ACK)
		{
			if (h->HardwareType == ARP_HARDWARE_TYPE_ETHERNET)
			{
				if (h->HardwareAddressSize == 6)
				{
					if (h->YourIP != 0 && h->YourIP != 0xffffffff)
					{
						UINT ip_uint = h->YourIP;
						IP ip;
						IP_TABLE_ENTRY *e;
						MAC_TABLE_ENTRY *mac_table = MacTableLookup(hub, h->ClientMacAddress, 0);

						if (mac_table != NULL)
						{
							UINTToIP(&ip, ip_uint);

							e = IpTableLookup(hub, &ip);
							if (e != NULL)
							{
								// A lease the table holds already: the ACK gives it to this client again
								IpTableSetEntry(e, mac_table->Session, &ip, p->MacAddressDest, true, Tick64());
							}
							else
							{
								IpTableAddEntry(hub, mac_table->Session, &ip, p->MacAddressDest, true, Tick64());

								if ((hub->Option->NoDhcpPacketLogOutsideHub == false) || mac_table->Session != s)
								{
									char dhcp_mac_addr[64];
									char dest_mac_addr[64];
									char dest_ip_addr[64];
									char server_ip_addr[64];
									MacToStr(dhcp_mac_addr, sizeof(dhcp_mac_addr), p->MacAddressSrc);
									MacToStr(dest_mac_addr, sizeof(dest_mac_addr), h->ClientMacAddress);
									IPToStr(dest_ip_addr, sizeof(dest_ip_addr), &ip);
									IPToStr32(server_ip_addr, sizeof(server_ip_addr), p->L3.IPv4Header->SrcIP);

									if (no_heavy == false)
									{
										HLog(s->Hub, "LH_REGIST_DHCP", s->Name, dhcp_mac_addr, server_ip_addr,
											mac_table->Session->Name, dest_mac_addr, dest_ip_addr);
									}
								}
							}
						}
					}
				}
			}
		}
	}

	return true;
}

void DeleteExpiredMacTableEntry(HASH_LIST *h)
{
	LIST *o2;
	UINT i;
	MAC_TABLE_ENTRY **pp;
	UINT num;
	if (h == NULL)
	{
		return;
	}

	o2 = NewListFast(NULL);

	pp = (MAC_TABLE_ENTRY **)HashListToArray(h, &num);

	for (i = 0;i < num;i++)
	{
		MAC_TABLE_ENTRY *e = pp[i];
		if ((e->UpdatedTime + (UINT64)MAC_TABLE_EXPIRE_TIME) <= Tick64())
		{
			Add(o2, e);
		}
	}

	for (i = 0;i < LIST_NUM(o2);i++)
	{
		MAC_TABLE_ENTRY *e = LIST_DATA(o2, i);
		DeleteHash(h, e);
		Free(e);
	}

	ReleaseList(o2);

	Free(pp);
}

void DeleteExpiredIpTableEntry(LIST *o)
{
	UINT i, num_kept = 0;
	UINT64 now;
	if (o == NULL)
	{
		return;
	}

	// This runs on every new IP entry, under the hub-wide MacHashTable lock. Read the clock once (Tick64 takes
	// a global lock) and compact the array in one pass: a Delete per expired entry searched and shifted the
	// whole array each time, O(n * expired). The kept entries keep their order, so a sorted table stays sorted
	// and DeleteHighestIpTableEntry still evicts the same entry.
	now = Tick64();

	for (i = 0;i < LIST_NUM(o);i++)
	{
		IP_TABLE_ENTRY *e = LIST_DATA(o, i);
		if ((e->UpdatedTime + (UINT64)(e->DhcpAllocated ? IP_TABLE_EXPIRE_TIME_DHCP : IP_TABLE_EXPIRE_TIME)) <= now)
		{
			Free(e);
		}
		else
		{
			o->p[num_kept++] = e;
		}
	}

	o->num_item = num_kept;
}

bool IsMostHighestPriorityPacket(SESSION *s, PKT *p)
{
	if (s == NULL || p == NULL)
	{
		return false;
	}

	if (p->TypeL3 == L3_ARPV4)
	{
		return true;
	}

	if (p->TypeL3 == L3_IPV4)
	{
		if (p->TypeL4 == L4_ICMPV4)
		{
			return true;
		}

		if (p->TypeL4 == L4_TCP)
		{
			if ((p->L4.TCPHeader->Flag & TCP_SYN) || (p->L4.TCPHeader->Flag & TCP_FIN)
				|| (p->L4.TCPHeader->Flag & TCP_RST))
			{
				return true;
			}
		}

		if (IsDhcpv4(p))
		{
			return true;
		}
	}

	return false;
}

void IntoTrafficLimiter(TRAFFIC_LIMITER *tr, PKT *p)
{
	UINT64 now = Tick64();
	if (tr == NULL || p == NULL)
	{
		return;
	}

	if (tr->LastTime == 0 || tr->LastTime > now ||
		(tr->LastTime + LIMITER_SAMPLING_SPAN) < now)
	{
		tr->Value = 0;
		tr->LastTime = now;
	}

	tr->Value += (UINT64)p->PacketSize * (UINT64)8;
}

static bool StorePacketFilterByTrafficLimiter(SESSION *s, PKT *p)
{
	HUB_PA *pa;
	TRAFFIC_LIMITER *tr;
	if (s == NULL || p == NULL)
	{
		return false;
	}

	if (s->Policy->MaxUpload == 0)
	{
		return true;
	}

	pa = (HUB_PA *)s->PacketAdapter->Param;
	tr = &pa->UploadLimiter;

	if (IsMostHighestPriorityPacket(s, p))
	{
		return true;
	}

	IntoTrafficLimiter(tr, p);

	if ((tr->Value * (UINT64)1000 / (UINT64)LIMITER_SAMPLING_SPAN) > s->Policy->MaxUpload)
	{
		return false;
	}

	return true;
}

bool StorePacketFilter(SESSION *s, PKT *packet)
{
	if (s == NULL || packet == NULL)
	{
		return false;
	}

	if (StorePacketFilterByTrafficLimiter(s, packet) == false)
	{
		return false;
	}

	if (StorePacketFilterByPolicy(s, packet) == false)
	{
		return false;
	}

	if (ApplyAccessListToStoredPacket(s->Hub, s, packet) == false)
	{
		return false;
	}

	return true;
}

PACKET_ADAPTER *GetHubPacketAdapter()
{
	PACKET_ADAPTER *pa = NewPacketAdapter(HubPaInit,
		HubPaGetCancel, HubPaGetNextPacket, HubPaPutPacket, HubPaFree);

	return pa;
}

static void StopAllSession(HUB *h)
{
	SESSION **s;
	UINT i, num;
	if (h == NULL)
	{
		return;
	}

	LockList(h->SessionList);
	{
		num = LIST_NUM(h->SessionList);
		s = ToArray(h->SessionList);
		DeleteAll(h->SessionList);
	}
	UnlockList(h->SessionList);

	// Signal every session first so they all shut down in parallel, then wait for each one.
	for (i = 0;i < num;i++)
	{
		StopSessionEx(s[i], true);
	}

	for (i = 0;i < num;i++)
	{
		StopSession(s[i]);
		ReleaseSession(s[i]);
	}

	Free(s);
}

void DelSession(HUB *h, SESSION *s)
{
	if (h == NULL || s == NULL)
	{
		return;
	}

	LockList(h->SessionList);
	{
		if (Delete(h->SessionList, s))
		{
			ReleaseSession(s);
		}
	}
	UnlockList(h->SessionList);
}

void AddSession(HUB *h, SESSION *s)
{
	if (h == NULL || s == NULL)
	{
		return;
	}

	LockList(h->SessionList);
	{
		Insert(h->SessionList, s);
		AddRef(s->ref);
	}
	UnlockList(h->SessionList);
}

void StopHub(HUB *h)
{
	bool old_status = false;
	if (h == NULL)
	{
		return;
	}

	old_status = h->Offline;
	h->HubIsOnlineButHalting = true;

	SetHubOffline(h);

	if (h->Halt == false)
	{
		SLog(h->Cedar, "LS_HUB_STOP", h->Name);
		h->Halt = true;
	}

	h->Offline = old_status;
	h->HubIsOnlineButHalting = false;
}

void SetHubOnline(HUB *h)
{
	if (h == NULL)
	{
		return;
	}

	Lock(h->lock_online);
	{
		if (h->Offline == false)
		{
			Unlock(h->lock_online);
			return;
		}
		HLog(h, "LH_ONLINE");

		StartAllLink(h);

		LockList(h->Cedar->LocalBridgeList);
		{
			UINT i;
			for (i = 0;i < LIST_NUM(h->Cedar->LocalBridgeList);i++)
			{
				LOCALBRIDGE *br = LIST_DATA(h->Cedar->LocalBridgeList, i);

				if (StrCmpi(br->HubName, h->Name) == 0)
				{
					if (br->Bridge == NULL)
					{
						br->Bridge = BrNewBridge(h, br);
					}
				}
			}
		}
		UnlockList(h->Cedar->LocalBridgeList);

		h->Offline = false;
	}
	Unlock(h->lock_online);
}

void SetHubOffline(HUB *h)
{
	UINT i;
	if (h == NULL)
	{
		return;
	}

	Lock(h->lock_online);
	{
		if (h->Offline || h->Halt)
		{
			Unlock(h->lock_online);
			return;
		}

		HLog(h, "LH_OFFLINE");

		StopAllLink(h);

		LockList(h->Cedar->LocalBridgeList);
		{
			for (i = 0;i < LIST_NUM(h->Cedar->LocalBridgeList);i++)
			{
				LOCALBRIDGE *br = LIST_DATA(h->Cedar->LocalBridgeList, i);

				if (StrCmpi(br->HubName, h->Name) == 0)
				{
					BrFreeBridge(br->Bridge);
					br->Bridge = NULL;
				}
			}
		}
		UnlockList(h->Cedar->LocalBridgeList);

		h->Offline = true;

		StopAllSession(h);
	}
	Unlock(h->lock_online);
}

bool IsHub(CEDAR *cedar, char *name)
{
	HUB *h;
	if (cedar == NULL || name == NULL)
	{
		return false;
	}

	h = GetHub(cedar, name);
	if (h == NULL)
	{
		return false;
	}

	ReleaseHub(h);

	return true;
}

HUB *GetHub(CEDAR *cedar, char *name)
{
	HUB *h, t;
	if (cedar == NULL || name == NULL)
	{
		return NULL;
	}

	LockHubList(cedar);

	t.Name = name;
	h = Search(cedar->HubList, &t);
	if (h == NULL)
	{
		UnlockHubList(cedar);
		return NULL;
	}

	AddRef(h->ref);

	UnlockHubList(cedar);

	return h;
}

void LockHubList(CEDAR *cedar)
{
	if (cedar == NULL)
	{
		return;
	}

	LockList(cedar->HubList);
}

void UnlockHubList(CEDAR *cedar)
{
	if (cedar == NULL)
	{
		return;
	}

	UnlockList(cedar->HubList);
}

void ReleaseHub(HUB *h)
{
	if (h == NULL)
	{
		return;
	}

	if (Release(h->ref) == 0)
	{
		CleanupHub(h);
	}
}

void CleanupHub(HUB *h)
{
	UINT i;
	char name[MAX_SIZE];
	if (h == NULL)
	{
		return;
	}

	StrCpy(name, sizeof(name), h->Name);

	if (h->WatchDogStarted)
	{
		StopHubWatchDog(h);
	}

	FreeAccessList(h);

	ReleaseAllLink(h);
	DeleteHubDb(h->HubDb);
	ReleaseCedar(h->Cedar);
	DeleteLock(h->lock);
	DeleteLock(h->lock_online);
	Free(h->Name);
	ReleaseList(h->SessionList);
	ReleaseHashList(h->MacHashTable);
	ReleaseList(h->IpTable);
	ReleaseList(h->MonitorList);
	ReleaseList(h->LinkList);
	DeleteCounter(h->NumSessions);
	DeleteCounter(h->NumSessionsClient);
	DeleteCounter(h->NumSessionsBridge);
	DeleteCounter(h->SessionCounter);
	FreeTraffic(h->Traffic);
	Free(h->Option);

	DeleteLock(h->TrafficLock);

	FreeLog(h->PacketLogger);
	FreeLog(h->SecurityLogger);

	for (i = 0;i < LIST_NUM(h->AdminOptionList);i++)
	{
		Free(LIST_DATA(h->AdminOptionList, i));
	}
	ReleaseList(h->AdminOptionList);

	if (h->Msg != NULL)
	{
		Free(h->Msg);
	}

	FreeUserList(h->UserList);

	Free(h);
}

int CompareIpTable(void *p1, void *p2)
{
	IP_TABLE_ENTRY *e1, *e2;
	if (p1 == NULL || p2 == NULL)
	{
		return 0;
	}
	e1 = *(IP_TABLE_ENTRY **)p1;
	e2 = *(IP_TABLE_ENTRY **)p2;
	if (e1 == NULL || e2 == NULL)
	{
		return 0;
	}
	return CmpIpAddr(&e1->Ip, &e2->Ip);
}

static UINT GetHashOfMacTable(void *p)
{
	UINT v;
	MAC_TABLE_ENTRY *e = p;

	if (e == NULL)
	{
		return 0;
	}

	v = e->MacAddress[0] + e->MacAddress[1] + e->MacAddress[2] + 
		e->MacAddress[3] + e->MacAddress[4] + e->MacAddress[5] + 
		e->VlanId;

	return v;
}

static int CompareMacTable(void *p1, void *p2)
{
	int r;
	MAC_TABLE_ENTRY *e1, *e2;
	if (p1 == NULL || p2 == NULL)
	{
		return 0;
	}
	e1 = *(MAC_TABLE_ENTRY **)p1;
	e2 = *(MAC_TABLE_ENTRY **)p2;
	if (e1 == NULL || e2 == NULL)
	{
		return 0;
	}
	r = Cmp(e1->MacAddress, e2->MacAddress, 6);
	if (r != 0)
	{
		return r;
	}
	if (e1->VlanId > e2->VlanId)
	{
		return 1;
	}
	else if (e1->VlanId < e2->VlanId)
	{
		return -1;
	}
	return 0;
}

int CompareHub(void *p1, void *p2)
{
	HUB *h1, *h2;
	if (p1 == NULL || p2 == NULL)
	{
		return 0;
	}
	h1 = *(HUB **)p1;
	h2 = *(HUB **)p2;
	if (h1 == NULL || h2 == NULL)
	{
		return 0;
	}
	return StrCmpi(h1->Name, h2->Name);
}

bool IsHubMacAddress(UCHAR *mac)
{
	if (mac == NULL)
	{
		return false;
	}

	if (mac[0] == 0x00 && mac[1] == SE_HUB_MAC_ADDR_SIGN)
	{
		return true;
	}

	return false;
}

bool IsHubIpAddress32(UINT ip32)
{
	IP ip;

	UINTToIP(&ip, ip32);

	return IsHubIpAddress(&ip);
}
bool IsHubIpAddress(IP *ip)
{
	if (ip == NULL)
	{
		return false;
	}

	const BYTE *ipv4 = IPV4(ip->address);

	if (ipv4[0] == 172 && ipv4[1] == 31)
	{
		if (ipv4[2] >= 1 && ipv4[2] <= 254)
		{
			if (ipv4[3] >= 1 && ipv4[3] <= 254)
			{
				return true;
			}
		}
	}

	return false;
}
bool IsHubIpAddress64(IPV6_ADDR *addr)
{
	if (addr == NULL)
	{
		return false;
	}

	if (addr->Value[0] == 0xfe && addr->Value[1] == 0x80 &&
		addr->Value[2] == 0 &&
		addr->Value[3] == 0 &&
		addr->Value[4] == 0 &&
		addr->Value[5] == 0 &&
		addr->Value[6] == 0 &&
		addr->Value[7] == 0 &&
		addr->Value[8] == 0x02 && addr->Value[9] == 0xae && 
		addr->Value[11] == 0xff && addr->Value[12] == 0xfe)
	{
		return true;
	}

	return false;
}

static void GenHubIpAddress(IP *ip, UCHAR *machine_hash, char *name)
{
	char tmp1[MAX_SIZE];
	char tmp2[MAX_SIZE];
	UCHAR hash[SHA1_SIZE];
	if (ip == NULL || machine_hash == NULL || name == NULL)
	{
		return;
	}

	StrCpy(tmp1, sizeof(tmp1), name);
	Trim(tmp1);
	BinToStr(tmp2, sizeof(tmp2), machine_hash, SHA1_SIZE);
	StrCat(tmp2, sizeof(tmp2), tmp1);
	StrUpper(tmp2);

	Sha0(hash, tmp2, StrLen(tmp2));

	SetIP(ip, 172, 31, hash[0] % 254 + 1, hash[0] % 254 + 1);
}

static void GenHubMacAddress(UCHAR *mac, UCHAR *machine_hash, char *name)
{
	char tmp1[MAX_SIZE];
	char tmp2[MAX_SIZE];
	UCHAR hash[SHA1_SIZE];
	if (mac == NULL || machine_hash == NULL || name == NULL)
	{
		return;
	}

	StrCpy(tmp1, sizeof(tmp1), name);
	Trim(tmp1);
	BinToStr(tmp2, sizeof(tmp2), machine_hash, SHA1_SIZE);
	StrCat(tmp2, sizeof(tmp2), tmp1);
	StrUpper(tmp2);

	Sha0(hash, tmp2, StrLen(tmp2));

	mac[0] = 0x00;
	mac[1] = SE_HUB_MAC_ADDR_SIGN;
	mac[2] = hash[0];
	mac[3] = hash[1];
	mac[4] = hash[2];
	mac[5] = hash[3];
}

wchar_t *GetHubMsg(HUB *h)
{
	wchar_t *ret = NULL;
	if (h == NULL)
	{
		return NULL;
	}

	Lock(h->lock);
	{
		if (h->Msg != NULL)
		{
			ret = CopyUniStr(h->Msg);
		}
	}
	Unlock(h->lock);

	return ret;
}

void SetHubMsg(HUB *h, wchar_t *msg)
{
	if (h == NULL)
	{
		return;
	}

	Lock(h->lock);
	{
		if (h->Msg != NULL)
		{
			Free(h->Msg);
			h->Msg = NULL;
		}

		if (UniIsEmptyStr(msg) == false)
		{
			h->Msg = CopyUniStr(msg);
		}
	}
	Unlock(h->lock);
}

HUB *NewHub(CEDAR *cedar, char *HubName, HUB_OPTION *option)
{
	HUB *h;
	char packet_logger_name[MAX_SIZE];
	char tmp[MAX_SIZE];
	char safe_hub_name[MAX_HUBNAME_LEN + 1];
	UCHAR hash[SHA1_SIZE];
	IP ip6;
	if (cedar == NULL || option == NULL || HubName == NULL)
	{
		return NULL;
	}

	h = ZeroMalloc(sizeof(HUB));
	Sha0(h->HashedPassword, "", 0);
	HashPassword(h->SecurePassword, ADMINISTRATOR_USERNAME, "");
	h->lock = NewLock();
	h->lock_online = NewLock();
	h->ref = NewRef();
	h->Cedar = cedar;
	AddRef(h->Cedar->ref);

	ConvertSafeFileName(safe_hub_name, sizeof(safe_hub_name), HubName);
	h->Name = CopyStr(safe_hub_name);


	h->AdminOptionList = NewList(CompareAdminOption);
	AddHubAdminOptionsDefaults(h, true);

	h->LastCommTime = SystemTime64();
	h->LastLoginTime = SystemTime64();
	h->NumLogin = 0;

	h->TrafficLock = NewLock();

	h->HubDb = NewHubDb();

	h->SessionList = NewList(NULL);
	h->SessionCounter = NewCounter();
	h->NumSessions = NewCounter();
	h->NumSessionsClient = NewCounter();
	h->NumSessionsBridge = NewCounter();
	h->MacHashTable = NewHashList(GetHashOfMacTable, CompareMacTable, 8);
	h->IpTable = NewList(CompareIpTable);
	h->MonitorList = NewList(NULL);
	h->LinkList = NewList(NULL);

	h->Traffic = NewTraffic();

	h->Option = ZeroMalloc(sizeof(HUB_OPTION));
	Copy(h->Option, option, sizeof(HUB_OPTION));

	if (h->Option->VlanTypeId == 0)
	{
		h->Option->VlanTypeId = MAC_PROTO_TAGVLAN;
	}

	h->Option->DropBroadcastsInPrivacyFilterMode = true;
	h->Option->DropArpInPrivacyFilterMode = true;
	h->Option->AllowSameUserInPrivacyFilterMode = false;

	Rand(h->HubSignature, sizeof(h->HubSignature));

	GenerateMachineUniqueHash(cedar, hash);
	GenHubMacAddress(h->HubMacAddr, hash, h->Name);
	GenHubIpAddress(&h->HubIp, hash, h->Name);

	GenerateEui64LocalAddress(&ip6, h->HubMacAddr);
	IPToIPv6Addr(&h->HubIpV6, &ip6);

	InitAccessList(h);

	h->UserList = NewUserList();

	SetDefaultHubLog(&h->LogSetting);

	MakeDir(HUB_SECURITY_LOG_DIR_NAME);
	MakeDir(HUB_PACKET_LOG_DIR_NAME);

	Format(packet_logger_name, sizeof(packet_logger_name), HUB_PACKET_LOG_FILE_NAME, h->Name);
	h->PacketLogger = NewLog(packet_logger_name, HUB_PACKET_LOG_PREFIX, h->LogSetting.PacketLogSwitchType);

	Format(tmp, sizeof(tmp), HUB_SECURITY_LOG_FILE_NAME, h->Name);
	h->SecurityLogger = NewLog(tmp, HUB_SECURITY_LOG_PREFIX, h->LogSetting.SecurityLogSwitchType);

	SetHubOnline(h);

	if (h->Option->NoArpPolling == false && h->Option->NoIpTable == false)
	{
		StartHubWatchDog(h);
		h->WatchDogStarted = true;
	}

	SLog(h->Cedar, "LS_HUB_START", h->Name);

	MacToStr(tmp, sizeof(tmp), h->HubMacAddr);
	SLog(h->Cedar, "LS_HUB_MAC", h->Name, tmp);

	return h;
}

void DeleteHubDb(HUBDB *d)
{
	if (d == NULL)
	{
		return;
	}

	LockList(d->UserList);
	{
		LockList(d->GroupList);
		{
			UINT i;
			USER **users;
			USERGROUP **groups;

			users = ToArray(d->UserList);
			groups = ToArray(d->GroupList);

			for (i = 0;i < LIST_NUM(d->UserList);i++)
			{
				ReleaseUser(users[i]);
			}
			for (i = 0;i < LIST_NUM(d->GroupList);i++)
			{
				ReleaseGroup(groups[i]);
			}

			Free(users);
			Free(groups);
		}
		UnlockList(d->GroupList);
	}
	UnlockList(d->UserList);

	LockList(d->RootCertList);
	{
		UINT i;
		for (i = 0;i < LIST_NUM(d->RootCertList);i++)
		{
			X *x = LIST_DATA(d->RootCertList, i);
			FreeX(x);
		}
	}
	UnlockList(d->RootCertList);

	LockList(d->CrlList);
	{
		UINT i;
		for (i = 0;i < LIST_NUM(d->CrlList);i++)
		{
			CRL *crl = LIST_DATA(d->CrlList, i);
			FreeCrl(crl);
		}
	}
	UnlockList(d->CrlList);

	FreeAcList(d->AcList);

	ReleaseList(d->GroupList);
	ReleaseList(d->UserList);
	ReleaseList(d->RootCertList);
	ReleaseList(d->CrlList);
	Free(d);
}

void GetHubLogSetting(HUB *h, HUB_LOG *setting)
{
	if (setting == NULL || h == NULL)
	{
		return;
	}

	Copy(setting, &h->LogSetting, sizeof(HUB_LOG));
}

void SetHubLogSettingEx(HUB *h, HUB_LOG *setting, bool no_change_switch_type)
{
	UINT i1, i2;
	if (setting == NULL || h == NULL)
	{
		return;
	}

	i1 = h->LogSetting.PacketLogSwitchType;
	i2 = h->LogSetting.SecurityLogSwitchType;

	Copy(&h->LogSetting, setting, sizeof(HUB_LOG));

	if (no_change_switch_type)
	{
		h->LogSetting.PacketLogSwitchType = i1;
		h->LogSetting.SecurityLogSwitchType = i2;
	}

	SetLogSwitchType(h->PacketLogger, setting->PacketLogSwitchType);
	SetLogSwitchType(h->SecurityLogger, setting->SecurityLogSwitchType);
}

// Add a trusted root certificate to the hub; false when the hub already trusts it or holds MAX_HUB_CERTS
bool AddRootCert(HUB *hub, X *x)
{
	HUBDB *db;
	bool added = false;
	if (hub == NULL || x == NULL)
	{
		return false;
	}

	db = hub->HubDb;
	if (db != NULL)
	{
		LockList(db->RootCertList);
		{
			if (LIST_NUM(db->RootCertList) < MAX_HUB_CERTS)
			{
				UINT i;
				bool ok = true;

				for (i = 0;i < LIST_NUM(db->RootCertList);i++)
				{
					X *exist_x = LIST_DATA(db->RootCertList, i);
					if (CompareX(exist_x, x))
					{
						ok = false;
						break;
					}
				}

				if (ok)
				{
					Insert(db->RootCertList, CloneX(x));
					added = true;
				}
			}
		}
		UnlockList(db->RootCertList);
	}

	return added;
}

int CompareCert(void *p1, void *p2)
{
	X *x1, *x2;
	wchar_t tmp1[MAX_SIZE];
	wchar_t tmp2[MAX_SIZE];
	if (p1 == NULL || p2 == NULL)
	{
		return 0;
	}
	x1 = *(X **)p1;
	x2 = *(X **)p2;
	if (x1 == NULL || x2 == NULL)
	{
		return 0;
	}

	GetPrintNameFromX(tmp1, sizeof(tmp1), x1);
	GetPrintNameFromX(tmp2, sizeof(tmp2), x2);

	return UniStrCmpi(tmp1, tmp2);
}

HUBDB *NewHubDb()
{
	HUBDB *d = ZeroMalloc(sizeof(HUBDB));

	d->GroupList = NewList(CompareGroupName);
	d->UserList = NewList(CompareUserName);
	d->RootCertList = NewList(CompareCert);
	d->CrlList = NewList(NULL);
	d->AcList = NewList(CmpAc);

	return d;
}


