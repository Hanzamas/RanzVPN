// AdminMessage.c
// Admin RPC area: hub and admin messages, maintenance (test, debug, flush, crash, reboot, certificate regeneration), Ethernet VLAN and license

#include "Admin.h"

#include "Account.h"
#include "BridgeWin32.h"
#include "Connection.h"
#include "Link.h"
#include "Listener.h"
#include "MsChapV2.h"
#include "Remote.h"
#include "Protocol.h"
#include "Sam.h"
#include "Server.h"
#include "Session.h"
#include "Wpc.h"

#include "Mayaqua/Cfg.h"
#include "Mayaqua/FileIO.h"
#include "Mayaqua/Internat.h"
#include "Mayaqua/HTTP.h"
#include "Mayaqua/Memory.h"
#include "Mayaqua/Microsoft.h"
#include "Mayaqua/Object.h"
#include "Mayaqua/Pack.h"
#include "Mayaqua/Str.h"
#include "Mayaqua/Table.h"
#include "Mayaqua/Tick64.h"
#include "AdminInternal.h"

UINT StRegenerateServerCert(ADMIN *a, RPC_TEST *t)
{
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;
	UINT ret = ERR_NO_ERROR;
	X *x;
	K *k;

	SERVER_ADMIN_ONLY;

	SiGenerateDefaultCertEx(&x, &k, t->StrValue);

	SetCedarCertAndChain(c, x, k, NULL);

	ALog(a, NULL, "LA_REGENERATE_SERVER_CERT", t->StrValue);

	IncrementServerConfigRevision(s);

	FreeX(x);
	FreeK(k);

	return ERR_NO_ERROR;
}

UINT StSetHubMsg(ADMIN *a, RPC_MSG *t)
{
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;
	HUB *h;
	UINT ret = ERR_NO_ERROR;
	char hubname[MAX_HUBNAME_LEN + 1];

	CHECK_RIGHT;
	NO_SUPPORT_FOR_BRIDGE;
	if (UniStrLen(t->Msg) > HUB_MAXMSG_LEN)
	{
		return ERR_MEMORY_NOT_ENOUGH;
	}

	StrCpy(hubname, sizeof(hubname), t->HubName);

	h = GetHub(c, hubname);

	if (h == NULL)
	{
		ret = ERR_HUB_NOT_FOUND;
	}
	else
	{
		if (a->ServerAdmin == false && GetHubAdminOption(h, "no_change_msg") != 0)
		{
			ret = ERR_NOT_ENOUGH_RIGHT;
		}
		else
		{
			SetHubMsg(h, t->Msg);
		}

		ReleaseHub(h);
	}

	IncrementServerConfigRevision(s);

	return ret;
}

UINT StGetHubMsg(ADMIN *a, RPC_MSG *t)
{
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;
	HUB *h;
	UINT ret = ERR_NO_ERROR;
	char hubname[MAX_HUBNAME_LEN + 1];

	CHECK_RIGHT;
	NO_SUPPORT_FOR_BRIDGE;
	if (UniStrLen(t->Msg) > HUB_MAXMSG_LEN)
	{
		return ERR_MEMORY_NOT_ENOUGH;
	}

	StrCpy(hubname, sizeof(hubname), t->HubName);

	h = GetHub(c, hubname);

	if (h == NULL)
	{
		ret = ERR_HUB_NOT_FOUND;
	}
	else
	{
		FreeRpcMsg(t);
		Zero(t, sizeof(RPC_MSG));

		t->Msg = GetHubMsg(h);

		ReleaseHub(h);
	}

	return ret;
}

UINT StDebug(ADMIN *a, RPC_TEST *t)
{
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;
	UINT ret = ERR_NO_ERROR;
	RPC_TEST t2;

	SERVER_ADMIN_ONLY;

	Zero(&t2, sizeof(t2));

	ret = SiDebug(s, &t2, t->IntValue, t->StrValue);

	if (ret == ERR_NO_ERROR)
	{
		Copy(t, &t2, sizeof(RPC_TEST));
	}
	else
	{
		Zero(t, sizeof(RPC_TEST));
	}

	return ret;
}

UINT StFlush(ADMIN *a, RPC_TEST *t)
{
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;
	UINT ret = ERR_NO_ERROR;
	UINT size;

	SERVER_ADMIN_ONLY;

	size = SiWriteConfigurationFile(s);

	t->IntValue = size;

	return ERR_NO_ERROR;
}

UINT StCrash(ADMIN *a, RPC_TEST *t)
{
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;
	UINT ret = ERR_NO_ERROR;

	SERVER_ADMIN_ONLY;

	MsSetEnableMinidump(false);

	CrashNow();

	return ERR_NO_ERROR;
}

UINT StGetAdminMsg(ADMIN *a, RPC_MSG *t)
{
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;
	UINT ret = ERR_NO_ERROR;
	RPC_WINVER server_ver;
	RPC_WINVER client_ver;
	wchar_t winver_msg_client[3800];
	wchar_t winver_msg_server[3800];
	UINT tmpsize;
	wchar_t *tmp;

	FreeRpcMsg(t);
	Zero(t, sizeof(RPC_MSG));

	GetWinVer(&server_ver);
	Copy(&client_ver, &a->ClientWinVer, sizeof(RPC_WINVER));

	Zero(winver_msg_client, sizeof(winver_msg_client));
	Zero(winver_msg_server, sizeof(winver_msg_server));

	if (IsSupportedWinVer(&client_ver) == false)
	{
		SYSTEMTIME st;

		LocalTime(&st);

		UniFormat(winver_msg_client, sizeof(winver_msg_client), _UU("WINVER_ERROR_FORMAT"),
			_UU("WINVER_ERROR_PC_LOCAL"),
			client_ver.Title,
			_UU("WINVER_ERROR_VPNSERVER"),
			SUPPORTED_WINDOWS_LIST,
			_UU("WINVER_ERROR_PC_LOCAL"),
			_UU("WINVER_ERROR_VPNSERVER"),
			_UU("WINVER_ERROR_VPNSERVER"),
			_UU("WINVER_ERROR_VPNSERVER"),
			st.wYear, st.wMonth);
	}

	if (IsSupportedWinVer(&server_ver) == false)
	{
		SYSTEMTIME st;

		LocalTime(&st);

		UniFormat(winver_msg_server, sizeof(winver_msg_server), _UU("WINVER_ERROR_FORMAT"),
			_UU("WINVER_ERROR_PC_REMOTE"),
			server_ver.Title,
			_UU("WINVER_ERROR_VPNSERVER"),
			SUPPORTED_WINDOWS_LIST,
			_UU("WINVER_ERROR_PC_REMOTE"),
			_UU("WINVER_ERROR_VPNSERVER"),
			_UU("WINVER_ERROR_VPNSERVER"),
			_UU("WINVER_ERROR_VPNSERVER"),
			st.wYear, st.wMonth);
	}

	tmpsize = UniStrSize(winver_msg_client) + UniStrSize(winver_msg_server) + 10000;

	tmp = ZeroMalloc(tmpsize);

	if (
		c->Bridge == false)
	{
		if (GetGlobalServerFlag(GSF_SHOW_OSS_MSG) != 0)
		{
			UniStrCat(tmp, tmpsize, _UU("OSS_MSG"));
		}
	}

	UniStrCat(tmp, tmpsize, winver_msg_client);
	UniStrCat(tmp, tmpsize, winver_msg_server);

	t->Msg = tmp;

	return ERR_NO_ERROR;
}

UINT StEnumEthVLan(ADMIN *a, RPC_ENUM_ETH_VLAN *t)
{
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;
	UINT ret = ERR_NO_ERROR;

	SERVER_ADMIN_ONLY;

	if (GetServerCapsBool(s, "b_support_eth_vlan") == false)
	{
		ret = ERR_NOT_SUPPORTED;
	}
	else
	{
		FreeRpcEnumEthVLan(t);
		Zero(t, sizeof(RPC_ENUM_ETH_VLAN));

		if (EnumEthVLanWin32(t) == false)
		{
			ret = ERR_INTERNAL_ERROR;
		}
	}

	return ret;
}

UINT StSetEnableEthVLan(ADMIN *a, RPC_TEST *t)
{
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;
	UINT ret = ERR_NO_ERROR;

	SERVER_ADMIN_ONLY;

	if (GetServerCapsBool(s, "b_support_eth_vlan") == false)
	{
		ret = ERR_NOT_SUPPORTED;
	}
	else if (MsIsAdmin() == false)
	{
		ret = ERR_NOT_ENOUGH_RIGHT;
	}
	else
	{
		if (SetVLanEnableStatus(t->StrValue, INT_TO_BOOL(t->IntValue)) == false)
		{
			ret = ERR_INTERNAL_ERROR;
		}
	}

	return ret;
}

UINT StGetLicenseStatus(ADMIN *a, RPC_LICENSE_STATUS *t)
{
	return ERR_NOT_SUPPORTED;
}

UINT StEnumLicenseKey(ADMIN *a, RPC_ENUM_LICENSE_KEY *t)
{
	return ERR_NOT_SUPPORTED;
}

UINT StAddLicenseKey(ADMIN *a, RPC_TEST *t)
{
	return ERR_NOT_SUPPORTED;
}

UINT StRebootServer(ADMIN *a, RPC_TEST *t)
{
	SERVER_ADMIN_ONLY;

	ALog(a, NULL, "LA_REBOOT_SERVER");

	SiRebootServerEx(a->Server->Cedar->Bridge, t->IntValue);

	return ERR_NO_ERROR;
}

UINT StTest(ADMIN *a, RPC_TEST *t)
{
	Format(t->StrValue, sizeof(t->StrValue), "%u", t->IntValue);

	return ERR_NO_ERROR;
}
