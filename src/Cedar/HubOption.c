// HubOption.c
// Virtual Hub options: admin options (the exported admin_options array), hub message and log settings

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
#include "HubInternal.h"

#define GetHubAdminOptionDataAndSet(ao, name, dest) \
	value = GetHubAdminOptionData(ao, name);        \
	if (value != INFINITE)                          \
	{                                               \
		dest = value;                               \
	}

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

		if (IsEmptyUniStr(str) == false)
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
	if (o == NULL || ao == NULL)
	{
		return;
	}

	UINT value;

	GetHubAdminOptionDataAndSet(ao, "NoAddressPollingIPv4", o->NoArpPolling);
	GetHubAdminOptionDataAndSet(ao, "NoAddressPollingIPv6", o->NoIPv6AddrPolling);
	GetHubAdminOptionDataAndSet(ao, "NoIpTable", o->NoIpTable);
	GetHubAdminOptionDataAndSet(ao, "NoMacAddressLog", o->NoMacAddressLog);
	GetHubAdminOptionDataAndSet(ao, "ManageOnlyPrivateIP", o->ManageOnlyPrivateIP);
	GetHubAdminOptionDataAndSet(ao, "ManageOnlyLocalUnicastIPv6", o->ManageOnlyLocalUnicastIPv6);
	GetHubAdminOptionDataAndSet(ao, "DisableIPParsing", o->DisableIPParsing);
	GetHubAdminOptionDataAndSet(ao, "YieldAfterStorePacket", o->YieldAfterStorePacket);
	GetHubAdminOptionDataAndSet(ao, "NoSpinLockForPacketDelay", o->NoSpinLockForPacketDelay);
	GetHubAdminOptionDataAndSet(ao, "BroadcastStormDetectionThreshold", o->BroadcastStormDetectionThreshold);
	GetHubAdminOptionDataAndSet(ao, "ClientMinimumRequiredBuild", o->ClientMinimumRequiredBuild);
	GetHubAdminOptionDataAndSet(ao, "FilterPPPoE", o->FilterPPPoE);
	GetHubAdminOptionDataAndSet(ao, "FilterOSPF", o->FilterOSPF);
	GetHubAdminOptionDataAndSet(ao, "FilterIPv4", o->FilterIPv4);
	GetHubAdminOptionDataAndSet(ao, "FilterIPv6", o->FilterIPv6);
	GetHubAdminOptionDataAndSet(ao, "FilterNonIP", o->FilterNonIP);
	GetHubAdminOptionDataAndSet(ao, "NoIPv4PacketLog", o->NoIPv4PacketLog);
	GetHubAdminOptionDataAndSet(ao, "NoIPv6PacketLog", o->NoIPv6PacketLog);
	GetHubAdminOptionDataAndSet(ao, "FilterBPDU", o->FilterBPDU);
	GetHubAdminOptionDataAndSet(ao, "NoIPv6DefaultRouterInRAWhenIPv6", o->NoIPv6DefaultRouterInRAWhenIPv6);
	GetHubAdminOptionDataAndSet(ao, "NoLookBPDUBridgeId", o->NoLookBPDUBridgeId);
	GetHubAdminOptionDataAndSet(ao, "NoManageVlanId", o->NoManageVlanId);
	GetHubAdminOptionDataAndSet(ao, "VlanTypeId", o->VlanTypeId);
	GetHubAdminOptionDataAndSet(ao, "FixForDLinkBPDU", o->FixForDLinkBPDU);
	GetHubAdminOptionDataAndSet(ao, "RequiredClientId", o->RequiredClientId);
	GetHubAdminOptionDataAndSet(ao, "AdjustTcpMssValue", o->AdjustTcpMssValue);
	GetHubAdminOptionDataAndSet(ao, "DisableAdjustTcpMss", o->DisableAdjustTcpMss);
	GetHubAdminOptionDataAndSet(ao, "NoDhcpPacketLogOutsideHub", o->NoDhcpPacketLogOutsideHub);
	GetHubAdminOptionDataAndSet(ao, "DisableHttpParsing", o->DisableHttpParsing);
	GetHubAdminOptionDataAndSet(ao, "DisableUdpAcceleration", o->DisableUdpAcceleration);
	GetHubAdminOptionDataAndSet(ao, "DisableUdpFilterForLocalBridgeNic", o->DisableUdpFilterForLocalBridgeNic);
	GetHubAdminOptionDataAndSet(ao, "ApplyIPv4AccessListOnArpPacket", o->ApplyIPv4AccessListOnArpPacket);
	GetHubAdminOptionDataAndSet(ao, "RemoveDefGwOnDhcpForLocalhost", o->RemoveDefGwOnDhcpForLocalhost);
	GetHubAdminOptionDataAndSet(ao, "AccessListIncludeFileCacheLifetime", o->AccessListIncludeFileCacheLifetime);
	GetHubAdminOptionDataAndSet(ao, "DisableCheckMacOnLocalBridge", o->DisableCheckMacOnLocalBridge);
	GetHubAdminOptionDataAndSet(ao, "DisableCorrectIpOffloadChecksum", o->DisableCorrectIpOffloadChecksum);
	GetHubAdminOptionDataAndSet(ao, "BroadcastLimiterStrictMode", o->BroadcastLimiterStrictMode);
	GetHubAdminOptionDataAndSet(ao, "MaxLoggedPacketsPerMinute", o->MaxLoggedPacketsPerMinute);
	GetHubAdminOptionDataAndSet(ao, "DoNotSaveHeavySecurityLogs", o->DoNotSaveHeavySecurityLogs);
	GetHubAdminOptionDataAndSet(ao, "DropBroadcastsInPrivacyFilterMode", o->DropBroadcastsInPrivacyFilterMode);
	GetHubAdminOptionDataAndSet(ao, "DropArpInPrivacyFilterMode", o->DropArpInPrivacyFilterMode);
	GetHubAdminOptionDataAndSet(ao, "AllowSameUserInPrivacyFilterMode", o->AllowSameUserInPrivacyFilterMode);
	GetHubAdminOptionDataAndSet(ao, "SuppressClientUpdateNotification", o->SuppressClientUpdateNotification);
	GetHubAdminOptionDataAndSet(ao, "FloodingSendQueueBufferQuota", o->FloodingSendQueueBufferQuota);
	GetHubAdminOptionDataAndSet(ao, "DetectDormantSessionInterval", o->DetectDormantSessionInterval);
	GetHubAdminOptionDataAndSet(ao, "NoPhysicalIPOnPacketLog", o->NoPhysicalIPOnPacketLog);
	GetHubAdminOptionDataAndSet(ao, "UseHubNameAsDhcpUserClassOption", o->UseHubNameAsDhcpUserClassOption);
	GetHubAdminOptionDataAndSet(ao, "AllowEapMatchUserByCert", o->AllowEapMatchUserByCert);
	GetHubAdminOptionDataAndSet(ao, "DhcpDiscoverTimeoutMs", o->DhcpDiscoverTimeoutMs);
}

void HubOptionStructToData(RPC_ADMIN_OPTION *ao, HUB_OPTION *o, char *hub_name)
{
	LIST *aol;
	UINT i;
	if (ao == NULL || o == NULL || hub_name == NULL)
	{
		return;
	}

	aol = NewListFast(NULL);

	Add(aol, NewAdminOption("NoAddressPollingIPv4", o->NoArpPolling));
	Add(aol, NewAdminOption("NoAddressPollingIPv6", o->NoIPv6AddrPolling));
	Add(aol, NewAdminOption("NoIpTable", o->NoIpTable));
	Add(aol, NewAdminOption("NoMacAddressLog", o->NoMacAddressLog));
	Add(aol, NewAdminOption("ManageOnlyPrivateIP", o->ManageOnlyPrivateIP));
	Add(aol, NewAdminOption("ManageOnlyLocalUnicastIPv6", o->ManageOnlyLocalUnicastIPv6));
	Add(aol, NewAdminOption("DisableIPParsing", o->DisableIPParsing));
	Add(aol, NewAdminOption("YieldAfterStorePacket", o->YieldAfterStorePacket));
	Add(aol, NewAdminOption("NoSpinLockForPacketDelay", o->NoSpinLockForPacketDelay));
	Add(aol, NewAdminOption("BroadcastStormDetectionThreshold", o->BroadcastStormDetectionThreshold));
	Add(aol, NewAdminOption("ClientMinimumRequiredBuild", o->ClientMinimumRequiredBuild));
	Add(aol, NewAdminOption("FilterPPPoE", o->FilterPPPoE));
	Add(aol, NewAdminOption("FilterOSPF", o->FilterOSPF));
	Add(aol, NewAdminOption("FilterIPv4", o->FilterIPv4));
	Add(aol, NewAdminOption("FilterIPv6", o->FilterIPv6));
	Add(aol, NewAdminOption("FilterNonIP", o->FilterNonIP));
	Add(aol, NewAdminOption("NoIPv4PacketLog", o->NoIPv4PacketLog));
	Add(aol, NewAdminOption("NoIPv6PacketLog", o->NoIPv6PacketLog));
	Add(aol, NewAdminOption("FilterBPDU", o->FilterBPDU));
	Add(aol, NewAdminOption("NoIPv6DefaultRouterInRAWhenIPv6", o->NoIPv6DefaultRouterInRAWhenIPv6));
	Add(aol, NewAdminOption("NoLookBPDUBridgeId", o->NoLookBPDUBridgeId));
	Add(aol, NewAdminOption("NoManageVlanId", o->NoManageVlanId));
	Add(aol, NewAdminOption("VlanTypeId", o->VlanTypeId));
	Add(aol, NewAdminOption("FixForDLinkBPDU", o->FixForDLinkBPDU));
	Add(aol, NewAdminOption("RequiredClientId", o->RequiredClientId));
	Add(aol, NewAdminOption("AdjustTcpMssValue", o->AdjustTcpMssValue));
	Add(aol, NewAdminOption("DisableAdjustTcpMss", o->DisableAdjustTcpMss));
	Add(aol, NewAdminOption("NoDhcpPacketLogOutsideHub", o->NoDhcpPacketLogOutsideHub));
	Add(aol, NewAdminOption("DisableHttpParsing", o->DisableHttpParsing));
	Add(aol, NewAdminOption("DisableUdpAcceleration", o->DisableUdpAcceleration));
	Add(aol, NewAdminOption("DisableUdpFilterForLocalBridgeNic", o->DisableUdpFilterForLocalBridgeNic));
	Add(aol, NewAdminOption("ApplyIPv4AccessListOnArpPacket", o->ApplyIPv4AccessListOnArpPacket));
	Add(aol, NewAdminOption("RemoveDefGwOnDhcpForLocalhost", o->RemoveDefGwOnDhcpForLocalhost));
	Add(aol, NewAdminOption("AccessListIncludeFileCacheLifetime", o->AccessListIncludeFileCacheLifetime));
	Add(aol, NewAdminOption("DisableCheckMacOnLocalBridge", o->DisableCheckMacOnLocalBridge));
	Add(aol, NewAdminOption("DisableCorrectIpOffloadChecksum", o->DisableCorrectIpOffloadChecksum));
	Add(aol, NewAdminOption("BroadcastLimiterStrictMode", o->BroadcastLimiterStrictMode));
	Add(aol, NewAdminOption("MaxLoggedPacketsPerMinute", o->MaxLoggedPacketsPerMinute));
	Add(aol, NewAdminOption("DoNotSaveHeavySecurityLogs", o->DoNotSaveHeavySecurityLogs));
	Add(aol, NewAdminOption("DropBroadcastsInPrivacyFilterMode", o->DropBroadcastsInPrivacyFilterMode));
	Add(aol, NewAdminOption("DropArpInPrivacyFilterMode", o->DropArpInPrivacyFilterMode));
	Add(aol, NewAdminOption("AllowSameUserInPrivacyFilterMode", o->AllowSameUserInPrivacyFilterMode));
	Add(aol, NewAdminOption("SuppressClientUpdateNotification", o->SuppressClientUpdateNotification));
	Add(aol, NewAdminOption("FloodingSendQueueBufferQuota", o->FloodingSendQueueBufferQuota));
	Add(aol, NewAdminOption("DetectDormantSessionInterval", o->DetectDormantSessionInterval));
	Add(aol, NewAdminOption("NoPhysicalIPOnPacketLog", o->NoPhysicalIPOnPacketLog));
	Add(aol, NewAdminOption("UseHubNameAsDhcpUserClassOption", o->UseHubNameAsDhcpUserClassOption));
	Add(aol, NewAdminOption("AllowEapMatchUserByCert", o->AllowEapMatchUserByCert));
	Add(aol, NewAdminOption("DhcpDiscoverTimeoutMs", o->DhcpDiscoverTimeoutMs));

	Zero(ao, sizeof(RPC_ADMIN_OPTION));

	StrCpy(ao->HubName, sizeof(ao->HubName), hub_name);

	ao->NumItem = LIST_NUM(aol);
	ao->Items = ZeroMalloc(sizeof(ADMIN_OPTION) * ao->NumItem);

	for (i = 0;i < LIST_NUM(aol);i++)
	{
		ADMIN_OPTION *a = LIST_DATA(aol, i);

		UniStrCpy(a->Descrption, sizeof(a->Descrption), GetHubAdminOptionHelpString(a->Name));

		Copy(&ao->Items[i], a, sizeof(ADMIN_OPTION));

		Free(a);
	}

	ReleaseList(aol);
}

ADMIN_OPTION *NewAdminOption(char *name, UINT value)
{
	ADMIN_OPTION *a;
	if (name == NULL)
	{
		return NULL;
	}

	a = ZeroMalloc(sizeof(ADMIN_OPTION));
	StrCpy(a->Name, sizeof(a->Name), name);
	a->Value = value;

	return a;
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

int CompareAdminOption(void *p1, void *p2)
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
			h->Msg = UniCopyStr(msg);
		}
	}
	Unlock(h->lock);
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
