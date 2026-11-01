// HubOption.c
// Virtual Hub options: admin options (the exported admin_options array), the hub option field table, hub message and log settings

#include "Hub.h"

#include "Admin.h"
#include "Bridge.h"
#include "Connection.h"
#include "Link.h"
#include "Protocol.h"
#include "Server.h"

#include "Mayaqua/Cfg.h"
#include "Mayaqua/FileIO.h"
#include "Mayaqua/Internat.h"
#include "Mayaqua/Memory.h"
#include "Mayaqua/Object.h"
#include "Mayaqua/Str.h"
#include "Mayaqua/Table.h"
#include "Mayaqua/TcpIp.h"

#include <stdlib.h>
#include <string.h>
#include "HubInternal.h"

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
        {"no_access_list_include_file", 0},
};

UINT num_admin_options = sizeof(admin_options) / sizeof(ADMIN_OPTION);

// One row per HUB_OPTION member. The config file, the defaults of a new hub and the RPC admin option list all
// follow it; the rows with an admin name come in the order the admin option list has. Config names are those
// of the members, the admin names too unless they are given.
#define HUB_OPTION_ROW(type, name, admin, def, flags) \
	{#name, admin, offsetof(HUB_OPTION, name), type, def, flags}
#define HUB_OPTION_CFG_ROW(type, name, def)   HUB_OPTION_ROW(type, name, NULL, def, 0)
#define HUB_OPTION_BOOL_ROW(name, def)        HUB_OPTION_ROW(HUB_OPTION_BOOL, name, #name, def, 0)
#define HUB_OPTION_UINT_ROW(name, def, flags) HUB_OPTION_ROW(HUB_OPTION_UINT, name, #name, def, flags)

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
};

UINT num_hub_option_fields = sizeof(hub_option_fields) / sizeof(HUB_OPTION_FIELD);

// Value of a HUB_OPTION member, a bool as 0 or 1
UINT GetHubOptionField(HUB_OPTION *o, HUB_OPTION_FIELD *f) {
	if (o == NULL || f == NULL)
		return 0;

	UCHAR *p = ((UCHAR *)o) + f->Offset;

	if (f->Type == HUB_OPTION_BOOL)
		return *((bool *)p) ? 1 : 0;

	return *((UINT *)p);
}

void SetHubOptionField(HUB_OPTION *o, HUB_OPTION_FIELD *f, UINT value) {
	if (o == NULL || f == NULL)
		return;

	UCHAR *p = ((UCHAR *)o) + f->Offset;

	if (f->Type == HUB_OPTION_BOOL)
		*((bool *)p) = (value != 0);
	else
		*((UINT *)p) = value;
}

bool IsURLMsg(wchar_t *str, char *url, UINT url_size) {
	bool ret = false;
	UINT n = 0;
	if (str == NULL)
		return false;

	UNI_TOKEN_LIST *t = UniParseToken(str, L"\r\n");

	for (UINT i = 0; i < t->NumTokens; i++) {
		wchar_t *str = t->Token[i];

		if (UniIsEmptyStr(str) == false) {
			n++;

			UniTrim(str);

			if (n == 1) {
				if (UniStartWith(str, L"http://") ||
				    UniStartWith(str, L"https://") ||
				    UniStartWith(str, L"ftp://")) {
					ret = true;

					UniToStr(url, url_size, str);
				}
			}
		}
	}

	if (n != 1)
		ret = false;

	UniFreeToken(t);

	return ret;
}

UINT GetHubAdminOptionData(RPC_ADMIN_OPTION *ao, char *name) {
	if (ao == NULL || name == NULL)
		return INFINITE;

	for (UINT i = 0; i < ao->NumItem; i++) {
		ADMIN_OPTION *a = &ao->Items[i];

		if (StrCmpi(a->Name, name) == 0)
			return a->Value;
	}

	return INFINITE;
}

void DataToHubOptionStruct(HUB_OPTION *o, RPC_ADMIN_OPTION *ao) {
	if (o == NULL || ao == NULL)
		return;

	for (UINT i = 0; i < num_hub_option_fields; i++) {
		HUB_OPTION_FIELD *f = &hub_option_fields[i];

		if (f->AdminName != NULL) {
			UINT value = GetHubAdminOptionData(ao, f->AdminName);

			if (value != INFINITE)
				SetHubOptionField(o, f, value);
		}
	}
}

void HubOptionStructToData(RPC_ADMIN_OPTION *ao, HUB_OPTION *o, char *hub_name) {
	if (ao == NULL || o == NULL || hub_name == NULL)
		return;

	Zero(ao, sizeof(RPC_ADMIN_OPTION));

	StrCpy(ao->HubName, sizeof(ao->HubName), hub_name);

	for (UINT i = 0; i < num_hub_option_fields; i++)
		if (hub_option_fields[i].AdminName != NULL)
			ao->NumItem++;

	ao->Items = ZeroMalloc(sizeof(ADMIN_OPTION) * ao->NumItem);

	UINT num = 0;

	for (UINT i = 0; i < num_hub_option_fields; i++) {
		HUB_OPTION_FIELD *f = &hub_option_fields[i];

		if (f->AdminName != NULL) {
			ADMIN_OPTION *a = &ao->Items[num++];

			StrCpy(a->Name, sizeof(a->Name), f->AdminName);
			a->Value = GetHubOptionField(o, f);
			UniStrCpy(a->Descrption, sizeof(a->Descrption), GetHubAdminOptionHelpString(a->Name));
		}
	}
}

wchar_t *GetHubAdminOptionHelpString(char *name) {
	char tmp[MAX_SIZE];
	if (name == NULL)
		return L"";

	Format(tmp, sizeof(tmp), "HUB_AO_%s", name);

	wchar_t *ret = _UU(tmp);
	if (UniIsEmptyStr(ret))
		ret = _UU("HUB_AO_UNKNOWN");

	return ret;
}

void AddHubAdminOptionsDefaults(HUB *h, bool lock) {
	if (h == NULL)
		return;

	if (lock)
		LockList(h->AdminOptionList);

	for (UINT i = 0; i < num_admin_options; i++) {
		ADMIN_OPTION *e = &admin_options[i];
		ADMIN_OPTION t;

		Zero(&t, sizeof(t));
		StrCpy(t.Name, sizeof(t.Name), e->Name);

		ADMIN_OPTION *r = Search(h->AdminOptionList, &t);
		if (r == NULL) {
			ADMIN_OPTION *a = ZeroMalloc(sizeof(ADMIN_OPTION));

			StrCpy(a->Name, sizeof(a->Name), e->Name);
			a->Value = e->Value;

			Insert(h->AdminOptionList, a);
		}
	}

	if (lock)
		UnlockList(h->AdminOptionList);
}

void DeleteAllHubAdminOption(HUB *h) {
	if (h == NULL)
		return;

	for (UINT i = 0; i < LIST_NUM(h->AdminOptionList); i++)
		Free(LIST_DATA(h->AdminOptionList, i));

	DeleteAll(h->AdminOptionList);
}

UINT GetHubAdminOption(HUB *h, char *name) {
	UINT ret = 0;
	if (h == NULL || name == NULL)
		return 0;

	LockList(h->AdminOptionList);
	{
		ADMIN_OPTION t;

		Zero(&t, sizeof(t));
		StrCpy(t.Name, sizeof(t.Name), name);
		Trim(t.Name);

		ADMIN_OPTION *a = Search(h->AdminOptionList, &t);

		if (a != NULL)
			ret = a->Value;
	}
	UnlockList(h->AdminOptionList);

	return ret;
}

wchar_t *GetHubMsg(HUB *h) {
	wchar_t *ret = NULL;
	if (h == NULL)
		return NULL;

	Lock(h->lock);
	{
		if (h->Msg != NULL)
			ret = CopyUniStr(h->Msg);
	}
	Unlock(h->lock);

	return ret;
}

void SetHubMsg(HUB *h, wchar_t *msg) {
	if (h == NULL)
		return;

	Lock(h->lock);
	{
		if (h->Msg != NULL) {
			Free(h->Msg);
			h->Msg = NULL;
		}

		if (UniIsEmptyStr(msg) == false)
			h->Msg = CopyUniStr(msg);
	}
	Unlock(h->lock);
}

void GetHubLogSetting(HUB *h, HUB_LOG *setting) {
	if (setting == NULL || h == NULL)
		return;

	Copy(setting, &h->LogSetting, sizeof(HUB_LOG));
}

void SetHubLogSettingEx(HUB *h, HUB_LOG *setting, bool no_change_switch_type) {
	if (setting == NULL || h == NULL)
		return;

	UINT i1 = h->LogSetting.PacketLogSwitchType;
	UINT i2 = h->LogSetting.SecurityLogSwitchType;

	Copy(&h->LogSetting, setting, sizeof(HUB_LOG));

	if (no_change_switch_type) {
		h->LogSetting.PacketLogSwitchType = i1;
		h->LogSetting.SecurityLogSwitchType = i2;
	}

	SetLogSwitchType(h->PacketLogger, setting->PacketLogSwitchType);
	SetLogSwitchType(h->SecurityLogger, setting->SecurityLogSwitchType);
}

void SiSetDefaultHubOption(HUB_OPTION *o) {
	if (o == NULL)
		return;

	for (UINT i = 0; i < num_hub_option_fields; i++) {
		HUB_OPTION_FIELD *f = &hub_option_fields[i];

		if (f->Default != 0)
			SetHubOptionField(o, f, f->Default);
	}

	// A zero default is not applied (the caller may have set NoEnum), except MaxSession which is always reset
	o->MaxSession = 0;
}
