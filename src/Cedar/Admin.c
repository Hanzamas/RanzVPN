// Admin.c
// RPC Module for Management

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

#define	DECLARE_RPC_EX(rpc_name, data_type, function, in_rpc, out_rpc, free_rpc)		\
	else if (StrCmpi(name, rpc_name) == 0)								\
	{																	\
		data_type *t;													\
		t = ZeroMalloc(sizeof(data_type));								\
		in_rpc(t, p);													\
		err = function(a, t);											\
		if (err == ERR_NO_ERROR)										\
		{																\
			out_rpc(ret, t);											\
		}																\
		free_rpc(t);													\
		Free(t);														\
		ok = true;														\
	}
#define	DECLARE_RPC(rpc_name, data_type, function, in_rpc, out_rpc)		\
	else if (StrCmpi(name, rpc_name) == 0)								\
	{																	\
		data_type *t;													\
		t = ZeroMalloc(sizeof(data_type));								\
		in_rpc(t, p);													\
		err = function(a, t);											\
		if (err == ERR_NO_ERROR)										\
		{																\
			out_rpc(ret, t);											\
		}																\
		Free(t);														\
		ok = true;														\
	}
#define	DECLARE_SC_EX(rpc_name, data_type, function, in_rpc, out_rpc, free_rpc)	\
	UINT function(RPC *r, data_type *t)									\
	{																	\
		PACK *p, *ret;													\
		UINT err;														\
		if (r == NULL || t == NULL)										\
		{																\
			return ERR_INTERNAL_ERROR;									\
		}																\
		p = NewPack();													\
		out_rpc(p, t);													\
		free_rpc(t);													\
		Zero(t, sizeof(data_type));										\
		ret = AdminCall(r, rpc_name, p);								\
		err = GetErrorFromPack(ret);									\
		if (err == ERR_NO_ERROR)										\
		{																\
			in_rpc(t, ret);												\
		}																\
		FreePack(ret);													\
		return err;														\
	}
#define	DECLARE_SC(rpc_name, data_type, function, in_rpc, out_rpc)		\
	UINT function(RPC *r, data_type *t)									\
	{																	\
		PACK *p, *ret;													\
		UINT err;														\
		if (r == NULL || t == NULL)										\
		{																\
			return ERR_INTERNAL_ERROR;									\
		}																\
		p = NewPack();													\
		out_rpc(p, t);													\
		ret = AdminCall(r, rpc_name, p);								\
		err = GetErrorFromPack(ret);									\
		if (err == ERR_NO_ERROR)										\
		{																\
			in_rpc(t, ret);												\
		}																\
		FreePack(ret);													\
		return err;														\
	}

CAPSLIST *ScGetCapsEx(RPC *rpc)
{
	RPC_SERVER_INFO info;
	CAPSLIST *t;
	bool is_bridge = false;
	if (rpc == NULL)
	{
		return NULL;
	}

	Zero(&info, sizeof(info));
	ScGetServerInfo(rpc, &info);

	t = ZeroMalloc(sizeof(CAPSLIST));

	if (ScGetCaps(rpc, t) != ERR_NO_ERROR)
	{
		UINT build;

		Free(t);
		t = NewCapsList();

		// Caps RPC failed: fall back to guessing from the build number
		build = info.ServerBuildInt;

		is_bridge = (SearchStrEx(info.ServerProductName, "bridge", 0, false) == INFINITE) ? false : true;

		AddCapsInt(t, "i_max_packet_size", 1514);

		if (is_bridge == false)
		{
			AddCapsInt(t, "i_max_hubs", 4096);
			AddCapsInt(t, "i_max_sessions", 4096);

			AddCapsInt(t, "i_max_users_per_hub", 10000);
			AddCapsInt(t, "i_max_groups_per_hub", 10000);
			AddCapsInt(t, "i_max_access_lists", 4096);
		}
		else
		{
			AddCapsInt(t, "i_max_hubs", 0);
			AddCapsInt(t, "i_max_sessions", 0);
			AddCapsInt(t, "i_max_users_per_hub", 0);
			AddCapsInt(t, "i_max_groups_per_hub", 0);
			AddCapsInt(t, "i_max_access_lists", 0);
		}

		AddCapsInt(t, "i_max_mac_tables", 10000);
		AddCapsInt(t, "i_max_ip_tables", 10000);

		if (is_bridge)
		{
			AddCapsBool(t, "b_bridge", true);
		}
		else
		{
			AddCapsBool(t, "b_standalone", true);
		}

		AddCapsBool(t, "b_support_config_hub", is_bridge == false);

		AddCapsBool(t, "b_vpn_client_connect", is_bridge == false ? true : false);

		if (build >= 3600)
		{
			RPC_BRIDGE_SUPPORT b;
			Zero(&b, sizeof(b));
			if (ScGetBridgeSupport(rpc, &b) == ERR_NO_ERROR)
			{
				AddCapsBool(t, "b_local_bridge", b.IsBridgeSupportedOs);
			}
			else
			{
				AddCapsBool(t, "b_local_bridge", false);
			}
		}
		else
		{
			AddCapsBool(t, "b_local_bridge", false);
		}

		AddCapsBool(t, "b_tap_supported", false);

		AddCapsBool(t, "b_support_cascade", true);

		AddCapsBool(t, "b_support_cascade_cert", false);
		AddCapsBool(t, "b_support_config_log", true);
		AddCapsBool(t, "b_support_autodelete", false);
	}

	if (true)
	{
		TOKEN_LIST *names;

		// Caps the server did not report default to false
		names = GetTableNameStartWith("CT_b_");
		if (names != NULL)
		{
			UINT i;
			for (i = 0;i < names->NumTokens;i++)
			{
				char *name = names->Token[i] + 3;

				if (GetCaps(t, name) == NULL)
				{
					AddCapsBool(t, name, false);
				}
			}

			FreeToken(names);
		}
	}

	FreeRpcServerInfo(&info);

	return t;
}

PACK *AdminDispatch(RPC *rpc, char *name, PACK *p)
{
	ADMIN *a;
	PACK *ret;
	UINT err;
	SERVER *server = NULL;
	CEDAR *cedar = NULL;
	bool ok = false;
	if (rpc == NULL || name == NULL || p == NULL)
	{
		return NULL;
	}

	ret = NewPack();
	err = ERR_NO_ERROR;

	a = (ADMIN *)rpc->Param;
	if (a == NULL)
	{
		FreePack(ret);
		return NULL;
	}

	server = a->Server;

	if (server == NULL)
	{
		return NULL;
	}

	cedar = server->Cedar;
	Lock(cedar->CedarSuperLock);

	if (true)
	{
		char tmp[MAX_PATH];
		char ip[MAX_PATH];
		UINT rpc_id = 0;

		StrCpy(ip, sizeof(ip), "Unknown");

		if (rpc->Sock != NULL)
		{
			IPToStr(ip, sizeof(ip), &rpc->Sock->RemoteIP);
			rpc_id = rpc->Sock->socket;
		}

		Format(tmp, sizeof(tmp), "RPC: RPC-%u (%s): Entering RPC [%s]...",
			rpc_id, ip, name);

		SiDebugLog(a->Server, tmp);
	}

	if (0) {}

	DECLARE_RPC_EX("Test", RPC_TEST, StTest, InRpcTest, OutRpcTest, FreeRpcTest)
	DECLARE_RPC_EX("GetServerInfo", RPC_SERVER_INFO, StGetServerInfo, InRpcServerInfo, OutRpcServerInfo, FreeRpcServerInfo)
	DECLARE_RPC("GetServerStatus", RPC_SERVER_STATUS, StGetServerStatus, InRpcServerStatus, OutRpcServerStatus)
	DECLARE_RPC("CreateListener", RPC_LISTENER, StCreateListener, InRpcListener, OutRpcListener)
	DECLARE_RPC_EX("EnumListener", RPC_LISTENER_LIST, StEnumListener, InRpcListenerList, OutRpcListenerList, FreeRpcListenerList)
	DECLARE_RPC("DeleteListener", RPC_LISTENER, StDeleteListener, InRpcListener, OutRpcListener)
	DECLARE_RPC("EnableListener", RPC_LISTENER, StEnableListener, InRpcListener, OutRpcListener)
	DECLARE_RPC("SetServerPassword", RPC_SET_PASSWORD, StSetServerPassword, InRpcSetPassword, OutRpcSetPassword)
	DECLARE_RPC_EX("SetServerCert", RPC_KEY_PAIR, StSetServerCert, InRpcKeyPair, OutRpcKeyPair, FreeRpcKeyPair)
	DECLARE_RPC_EX("GetServerCert", RPC_KEY_PAIR, StGetServerCert, InRpcKeyPair, OutRpcKeyPair, FreeRpcKeyPair)
	DECLARE_RPC_EX("GetServerCipherList", RPC_STR, StGetServerCipherList, InRpcStr, OutRpcStr, FreeRpcStr)
	DECLARE_RPC_EX("GetServerCipher", RPC_STR, StGetServerCipher, InRpcStr, OutRpcStr, FreeRpcStr)
	DECLARE_RPC_EX("SetServerCipher", RPC_STR, StSetServerCipher, InRpcStr, OutRpcStr, FreeRpcStr)
	DECLARE_RPC("CreateHub", RPC_CREATE_HUB, StCreateHub, InRpcCreateHub, OutRpcCreateHub)
	DECLARE_RPC("SetHub", RPC_CREATE_HUB, StSetHub, InRpcCreateHub, OutRpcCreateHub)
	DECLARE_RPC("GetHub", RPC_CREATE_HUB, StGetHub, InRpcCreateHub, OutRpcCreateHub)
	DECLARE_RPC_EX("EnumHub", RPC_ENUM_HUB, StEnumHub, InRpcEnumHub, OutRpcEnumHub, FreeRpcEnumHub)
	DECLARE_RPC("DeleteHub", RPC_DELETE_HUB, StDeleteHub, InRpcDeleteHub, OutRpcDeleteHub)
	DECLARE_RPC_EX("EnumConnection", RPC_ENUM_CONNECTION, StEnumConnection, InRpcEnumConnection, OutRpcEnumConnection, FreeRpcEnumConnection)
	DECLARE_RPC("DisconnectConnection", RPC_DISCONNECT_CONNECTION, StDisconnectConnection, InRpcDisconnectConnection, OutRpcDisconnectConnection)
	DECLARE_RPC("GetConnectionInfo", RPC_CONNECTION_INFO, StGetConnectionInfo, InRpcConnectionInfo, OutRpcConnectionInfo)
	DECLARE_RPC("SetHubOnline", RPC_SET_HUB_ONLINE, StSetHubOnline, InRpcSetHubOnline, OutRpcSetHubOnline)
	DECLARE_RPC("GetHubStatus", RPC_HUB_STATUS, StGetHubStatus, InRpcHubStatus, OutRpcHubStatus)
	DECLARE_RPC("SetHubLog", RPC_HUB_LOG, StSetHubLog, InRpcHubLog, OutRpcHubLog)
	DECLARE_RPC("GetHubLog", RPC_HUB_LOG, StGetHubLog, InRpcHubLog, OutRpcHubLog)
	DECLARE_RPC_EX("AddCa", RPC_HUB_ADD_CA, StAddCa, InRpcHubAddCa, OutRpcHubAddCa, FreeRpcHubAddCa)
	DECLARE_RPC_EX("EnumCa", RPC_HUB_ENUM_CA, StEnumCa, InRpcHubEnumCa, OutRpcHubEnumCa, FreeRpcHubEnumCa)
	DECLARE_RPC_EX("GetCa", RPC_HUB_GET_CA, StGetCa, InRpcHubGetCa, OutRpcHubGetCa, FreeRpcHubGetCa)
	DECLARE_RPC("DeleteCa", RPC_HUB_DELETE_CA, StDeleteCa, InRpcHubDeleteCa, OutRpcHubDeleteCa)
	DECLARE_RPC("SetLinkOnline", RPC_LINK, StSetLinkOnline, InRpcLink, OutRpcLink)
	DECLARE_RPC("SetLinkOffline", RPC_LINK, StSetLinkOffline, InRpcLink, OutRpcLink)
	DECLARE_RPC("DeleteLink", RPC_LINK, StDeleteLink, InRpcLink, OutRpcLink)
	DECLARE_RPC("RenameLink", RPC_RENAME_LINK, StRenameLink, InRpcRenameLink, OutRpcRenameLink)
	DECLARE_RPC_EX("CreateLink", RPC_CREATE_LINK, StCreateLink, InRpcCreateLink, OutRpcCreateLink, FreeRpcCreateLink)
	DECLARE_RPC_EX("GetLink", RPC_CREATE_LINK, StGetLink, InRpcCreateLink, OutRpcCreateLink, FreeRpcCreateLink)
	DECLARE_RPC_EX("SetLink", RPC_CREATE_LINK, StSetLink, InRpcCreateLink, OutRpcCreateLink, FreeRpcCreateLink)
	DECLARE_RPC_EX("EnumLink", RPC_ENUM_LINK, StEnumLink, InRpcEnumLink, OutRpcEnumLink, FreeRpcEnumLink)
	DECLARE_RPC_EX("GetLinkStatus", RPC_LINK_STATUS, StGetLinkStatus, InRpcLinkStatus, OutRpcLinkStatus, FreeRpcLinkStatus)
	DECLARE_RPC("AddAccess", RPC_ADD_ACCESS, StAddAccess, InRpcAddAccess, OutRpcAddAccess)
	DECLARE_RPC("DeleteAccess", RPC_DELETE_ACCESS, StDeleteAccess, InRpcDeleteAccess, OutRpcDeleteAccess)
	DECLARE_RPC_EX("EnumAccess", RPC_ENUM_ACCESS_LIST, StEnumAccess, InRpcEnumAccessList, OutRpcEnumAccessList, FreeRpcEnumAccessList)
	DECLARE_RPC_EX("SetAccessList", RPC_ENUM_ACCESS_LIST, StSetAccessList, InRpcEnumAccessList, OutRpcEnumAccessList, FreeRpcEnumAccessList)
	DECLARE_RPC_EX("CreateUser", RPC_SET_USER, StCreateUser, InRpcSetUser, OutRpcSetUser, FreeRpcSetUser)
	DECLARE_RPC_EX("SetUser", RPC_SET_USER, StSetUser, InRpcSetUser, OutRpcSetUser, FreeRpcSetUser)
	DECLARE_RPC_EX("GetUser", RPC_SET_USER, StGetUser, InRpcSetUser, OutRpcSetUser, FreeRpcSetUser)
	DECLARE_RPC("DeleteUser", RPC_DELETE_USER, StDeleteUser, InRpcDeleteUser, OutRpcDeleteUser)
	DECLARE_RPC_EX("EnumUser", RPC_ENUM_USER, StEnumUser, InRpcEnumUser, OutRpcEnumUser, FreeRpcEnumUser)
	DECLARE_RPC_EX("CreateGroup", RPC_SET_GROUP, StCreateGroup, InRpcSetGroup, OutRpcSetGroup, FreeRpcSetGroup)
	DECLARE_RPC_EX("SetGroup", RPC_SET_GROUP, StSetGroup, InRpcSetGroup, OutRpcSetGroup, FreeRpcSetGroup)
	DECLARE_RPC_EX("GetGroup", RPC_SET_GROUP, StGetGroup, InRpcSetGroup, OutRpcSetGroup, FreeRpcSetGroup)
	DECLARE_RPC("DeleteGroup", RPC_DELETE_USER, StDeleteGroup, InRpcDeleteUser, OutRpcDeleteUser)
	DECLARE_RPC_EX("EnumGroup", RPC_ENUM_GROUP, StEnumGroup, InRpcEnumGroup, OutRpcEnumGroup, FreeRpcEnumGroup)
	DECLARE_RPC_EX("EnumSession", RPC_ENUM_SESSION, StEnumSession, InRpcEnumSession, OutRpcEnumSession, FreeRpcEnumSession)
	DECLARE_RPC_EX("GetSessionStatus", RPC_SESSION_STATUS, StGetSessionStatus, InRpcSessionStatus, OutRpcSessionStatus, FreeRpcSessionStatus)
	DECLARE_RPC("DeleteSession", RPC_DELETE_SESSION, StDeleteSession, InRpcDeleteSession, OutRpcDeleteSession)
	DECLARE_RPC_EX("EnumMacTable", RPC_ENUM_MAC_TABLE, StEnumMacTable, InRpcEnumMacTable, OutRpcEnumMacTable, FreeRpcEnumMacTable)
	DECLARE_RPC("DeleteMacTable", RPC_DELETE_TABLE, StDeleteMacTable, InRpcDeleteTable, OutRpcDeleteTable)
	DECLARE_RPC_EX("EnumIpTable", RPC_ENUM_IP_TABLE, StEnumIpTable, InRpcEnumIpTable, OutRpcEnumIpTable, FreeRpcEnumIpTable)
	DECLARE_RPC("DeleteIpTable", RPC_DELETE_TABLE, StDeleteIpTable, InRpcDeleteTable, OutRpcDeleteTable)
	DECLARE_RPC_EX("EnumEthernet", RPC_ENUM_ETH, StEnumEthernet, InRpcEnumEth, OutRpcEnumEth, FreeRpcEnumEth)
	DECLARE_RPC("AddLocalBridge", RPC_LOCALBRIDGE, StAddLocalBridge, InRpcLocalBridge, OutRpcLocalBridge)
	DECLARE_RPC("DeleteLocalBridge", RPC_LOCALBRIDGE, StDeleteLocalBridge, InRpcLocalBridge, OutRpcLocalBridge)
	DECLARE_RPC_EX("EnumLocalBridge", RPC_ENUM_LOCALBRIDGE, StEnumLocalBridge, InRpcEnumLocalBridge, OutRpcEnumLocalBridge, FreeRpcEnumLocalBridge)
	DECLARE_RPC("GetBridgeSupport", RPC_BRIDGE_SUPPORT, StGetBridgeSupport, InRpcBridgeSupport, OutRpcBridgeSupport)
	DECLARE_RPC("RebootServer", RPC_TEST, StRebootServer, InRpcTest, OutRpcTest)
	DECLARE_RPC_EX("GetCaps", CAPSLIST, StGetCaps, InRpcCapsList, OutRpcCapsList, FreeRpcCapsList)
	DECLARE_RPC_EX("GetConfig", RPC_CONFIG, StGetConfig, InRpcConfig, OutRpcConfig, FreeRpcConfig)
	DECLARE_RPC_EX("SetConfig", RPC_CONFIG, StSetConfig, InRpcConfig, OutRpcConfig, FreeRpcConfig)
	DECLARE_RPC_EX("GetDefaultHubAdminOptions", RPC_ADMIN_OPTION, StGetDefaultHubAdminOptions, InRpcAdminOption, OutRpcAdminOption, FreeRpcAdminOption)
	DECLARE_RPC_EX("GetHubAdminOptions", RPC_ADMIN_OPTION, StGetHubAdminOptions, InRpcAdminOption, OutRpcAdminOption, FreeRpcAdminOption)
	DECLARE_RPC_EX("SetHubAdminOptions", RPC_ADMIN_OPTION, StSetHubAdminOptions, InRpcAdminOption, OutRpcAdminOption, FreeRpcAdminOption)
	DECLARE_RPC_EX("GetHubExtOptions", RPC_ADMIN_OPTION, StGetHubExtOptions, InRpcAdminOption, OutRpcAdminOption, FreeRpcAdminOption)
	DECLARE_RPC_EX("SetHubExtOptions", RPC_ADMIN_OPTION, StSetHubExtOptions, InRpcAdminOption, OutRpcAdminOption, FreeRpcAdminOption)
	DECLARE_RPC_EX("EnumCrl", RPC_ENUM_CRL, StEnumCrl, InRpcEnumCrl, OutRpcEnumCrl, FreeRpcEnumCrl)
	DECLARE_RPC_EX("AddCrl", RPC_CRL, StAddCrl, InRpcCrl, OutRpcCrl, FreeRpcCrl)
	DECLARE_RPC_EX("DelCrl", RPC_CRL, StDelCrl, InRpcCrl, OutRpcCrl, FreeRpcCrl)
	DECLARE_RPC_EX("GetCrl", RPC_CRL, StGetCrl, InRpcCrl, OutRpcCrl, FreeRpcCrl)
	DECLARE_RPC_EX("SetCrl", RPC_CRL, StSetCrl, InRpcCrl, OutRpcCrl, FreeRpcCrl)
	DECLARE_RPC_EX("SetAcList", RPC_AC_LIST, StSetAcList, InRpcAcList, OutRpcAcList, FreeRpcAcList)
	DECLARE_RPC_EX("GetAcList", RPC_AC_LIST, StGetAcList, InRpcAcList, OutRpcAcList, FreeRpcAcList)
	DECLARE_RPC_EX("EnumLogFile", RPC_ENUM_LOG_FILE, StEnumLogFile, InRpcEnumLogFile, OutRpcEnumLogFile, FreeRpcEnumLogFile)
	DECLARE_RPC_EX("ReadLogFile", RPC_READ_LOG_FILE, StReadLogFile, InRpcReadLogFile, OutRpcReadLogFile, FreeRpcReadLogFile)
	DECLARE_RPC("AddLicenseKey", RPC_TEST, StAddLicenseKey, InRpcTest, OutRpcTest)
	DECLARE_RPC("DelLicenseKey", RPC_TEST, StAddLicenseKey, InRpcTest, OutRpcTest)
	DECLARE_RPC_EX("EnumLicenseKey", RPC_ENUM_LICENSE_KEY, StEnumLicenseKey, InRpcEnumLicenseKey, OutRpcEnumLicenseKey, FreeRpcEnumLicenseKey)
	DECLARE_RPC("GetLicenseStatus", RPC_LICENSE_STATUS, StGetLicenseStatus, InRpcLicenseStatus, OutRpcLicenseStatus)
	DECLARE_RPC("SetSysLog", SYSLOG_SETTING, StSetSysLog, InRpcSysLogSetting, OutRpcSysLogSetting)
	DECLARE_RPC("GetSysLog", SYSLOG_SETTING, StGetSysLog, InRpcSysLogSetting, OutRpcSysLogSetting)
	DECLARE_RPC_EX("EnumEthVLan", RPC_ENUM_ETH_VLAN, StEnumEthVLan, InRpcEnumEthVLan, OutRpcEnumEthVLan, FreeRpcEnumEthVLan)
	DECLARE_RPC("SetEnableEthVLan", RPC_TEST, StSetEnableEthVLan, InRpcTest, OutRpcTest)
	DECLARE_RPC_EX("SetHubMsg", RPC_MSG, StSetHubMsg, InRpcMsg, OutRpcMsg, FreeRpcMsg)
	DECLARE_RPC_EX("GetHubMsg", RPC_MSG, StGetHubMsg, InRpcMsg, OutRpcMsg, FreeRpcMsg)
	DECLARE_RPC("Crash", RPC_TEST, StCrash, InRpcTest, OutRpcTest)
	DECLARE_RPC_EX("GetAdminMsg", RPC_MSG, StGetAdminMsg, InRpcMsg, OutRpcMsg, FreeRpcMsg)
	DECLARE_RPC("Flush", RPC_TEST, StFlush, InRpcTest, OutRpcTest)
	DECLARE_RPC("Debug", RPC_TEST, StDebug, InRpcTest, OutRpcTest)
	DECLARE_RPC("RegenerateServerCert", RPC_TEST, StRegenerateServerCert, InRpcTest, OutRpcTest)

	if (ok == false)
	{
		err = ERR_NOT_SUPPORTED;
	}

	if (err != ERR_NO_ERROR)
	{
		PackAddInt(ret, "error", err);
	}

	if (true)
	{
		char tmp[MAX_PATH];
		char ip[MAX_PATH];
		UINT rpc_id = 0;

		StrCpy(ip, sizeof(ip), "Unknown");

		if (rpc->Sock != NULL)
		{
			IPToStr(ip, sizeof(ip), &rpc->Sock->RemoteIP);
			rpc_id = rpc->Sock->socket;
		}

		Format(tmp, sizeof(tmp), "RPC: RPC-%u (%s): Leaving RPC [%s] (Error: %u).",
			rpc_id, ip, name, err);

		SiDebugLog(a->Server, tmp);
	}

	Unlock(cedar->CedarSuperLock);

	return ret;
}

DECLARE_SC_EX("GetServerInfo", RPC_SERVER_INFO, ScGetServerInfo, InRpcServerInfo, OutRpcServerInfo, FreeRpcServerInfo)
DECLARE_SC("GetServerStatus", RPC_SERVER_STATUS, ScGetServerStatus, InRpcServerStatus, OutRpcServerStatus)
DECLARE_SC("CreateListener", RPC_LISTENER, ScCreateListener, InRpcListener, OutRpcListener)
DECLARE_SC_EX("EnumListener", RPC_LISTENER_LIST, ScEnumListener, InRpcListenerList, OutRpcListenerList, FreeRpcListenerList)
DECLARE_SC("DeleteListener", RPC_LISTENER, ScDeleteListener, InRpcListener, OutRpcListener)
DECLARE_SC("EnableListener", RPC_LISTENER, ScEnableListener, InRpcListener, OutRpcListener)
DECLARE_SC("SetServerPassword", RPC_SET_PASSWORD, ScSetServerPassword, InRpcSetPassword, OutRpcSetPassword)
DECLARE_SC_EX("SetServerCert", RPC_KEY_PAIR, ScSetServerCert, InRpcKeyPair, OutRpcKeyPair, FreeRpcKeyPair)
DECLARE_SC_EX("GetServerCert", RPC_KEY_PAIR, ScGetServerCert, InRpcKeyPair, OutRpcKeyPair, FreeRpcKeyPair)
DECLARE_SC_EX("GetServerCipherList", RPC_STR, ScGetServerCipherList, InRpcStr, OutRpcStr, FreeRpcStr)
DECLARE_SC_EX("GetServerCipher", RPC_STR, ScGetServerCipher, InRpcStr, OutRpcStr, FreeRpcStr)
DECLARE_SC_EX("SetServerCipher", RPC_STR, ScSetServerCipher, InRpcStr, OutRpcStr, FreeRpcStr)
DECLARE_SC("CreateHub", RPC_CREATE_HUB, ScCreateHub, InRpcCreateHub, OutRpcCreateHub)
DECLARE_SC("SetHub", RPC_CREATE_HUB, ScSetHub, InRpcCreateHub, OutRpcCreateHub)
DECLARE_SC("GetHub", RPC_CREATE_HUB, ScGetHub, InRpcCreateHub, OutRpcCreateHub)
DECLARE_SC_EX("EnumHub", RPC_ENUM_HUB, ScEnumHub, InRpcEnumHub, OutRpcEnumHub, FreeRpcEnumHub)
DECLARE_SC("DeleteHub", RPC_DELETE_HUB, ScDeleteHub, InRpcDeleteHub, OutRpcDeleteHub)
DECLARE_SC_EX("EnumConnection", RPC_ENUM_CONNECTION, ScEnumConnection, InRpcEnumConnection, OutRpcEnumConnection, FreeRpcEnumConnection)
DECLARE_SC("DisconnectConnection", RPC_DISCONNECT_CONNECTION, ScDisconnectConnection, InRpcDisconnectConnection, OutRpcDisconnectConnection)
DECLARE_SC("GetConnectionInfo", RPC_CONNECTION_INFO, ScGetConnectionInfo, InRpcConnectionInfo, OutRpcConnectionInfo)
DECLARE_SC("SetHubOnline", RPC_SET_HUB_ONLINE, ScSetHubOnline, InRpcSetHubOnline, OutRpcSetHubOnline)
DECLARE_SC("GetHubStatus", RPC_HUB_STATUS, ScGetHubStatus, InRpcHubStatus, OutRpcHubStatus)
DECLARE_SC("SetHubLog", RPC_HUB_LOG, ScSetHubLog, InRpcHubLog, OutRpcHubLog)
DECLARE_SC("GetHubLog", RPC_HUB_LOG, ScGetHubLog, InRpcHubLog, OutRpcHubLog)
DECLARE_SC_EX("AddCa", RPC_HUB_ADD_CA, ScAddCa, InRpcHubAddCa, OutRpcHubAddCa, FreeRpcHubAddCa)
DECLARE_SC_EX("EnumCa", RPC_HUB_ENUM_CA, ScEnumCa, InRpcHubEnumCa, OutRpcHubEnumCa, FreeRpcHubEnumCa)
DECLARE_SC_EX("GetCa", RPC_HUB_GET_CA, ScGetCa, InRpcHubGetCa, OutRpcHubGetCa, FreeRpcHubGetCa)
DECLARE_SC("DeleteCa", RPC_HUB_DELETE_CA, ScDeleteCa, InRpcHubDeleteCa, OutRpcHubDeleteCa)
DECLARE_SC_EX("CreateLink", RPC_CREATE_LINK, ScCreateLink, InRpcCreateLink, OutRpcCreateLink, FreeRpcCreateLink)
DECLARE_SC_EX("GetLink", RPC_CREATE_LINK, ScGetLink, InRpcCreateLink, OutRpcCreateLink, FreeRpcCreateLink)
DECLARE_SC_EX("SetLink", RPC_CREATE_LINK, ScSetLink, InRpcCreateLink, OutRpcCreateLink, FreeRpcCreateLink)
DECLARE_SC_EX("EnumLink", RPC_ENUM_LINK, ScEnumLink, InRpcEnumLink, OutRpcEnumLink, FreeRpcEnumLink)
DECLARE_SC_EX("GetLinkStatus", RPC_LINK_STATUS, ScGetLinkStatus, InRpcLinkStatus, OutRpcLinkStatus, FreeRpcLinkStatus)
DECLARE_SC("SetLinkOnline", RPC_LINK, ScSetLinkOnline, InRpcLink, OutRpcLink)
DECLARE_SC("SetLinkOffline", RPC_LINK, ScSetLinkOffline, InRpcLink, OutRpcLink)
DECLARE_SC("DeleteLink", RPC_LINK, ScDeleteLink, InRpcLink, OutRpcLink)
DECLARE_SC("RenameLink", RPC_RENAME_LINK, ScRenameLink, InRpcRenameLink, OutRpcRenameLink)
DECLARE_SC("AddAccess", RPC_ADD_ACCESS, ScAddAccess, InRpcAddAccess, OutRpcAddAccess)
DECLARE_SC("DeleteAccess", RPC_DELETE_ACCESS, ScDeleteAccess, InRpcDeleteAccess, OutRpcDeleteAccess)
DECLARE_SC_EX("EnumAccess", RPC_ENUM_ACCESS_LIST, ScEnumAccess, InRpcEnumAccessList, OutRpcEnumAccessList, FreeRpcEnumAccessList)
DECLARE_SC_EX("SetAccessList", RPC_ENUM_ACCESS_LIST, ScSetAccessList, InRpcEnumAccessList, OutRpcEnumAccessList, FreeRpcEnumAccessList)
DECLARE_SC_EX("CreateUser", RPC_SET_USER, ScCreateUser, InRpcSetUser, OutRpcSetUser, FreeRpcSetUser)
DECLARE_SC_EX("SetUser", RPC_SET_USER, ScSetUser, InRpcSetUser, OutRpcSetUser, FreeRpcSetUser)
DECLARE_SC_EX("GetUser", RPC_SET_USER, ScGetUser, InRpcSetUser, OutRpcSetUser, FreeRpcSetUser)
DECLARE_SC("DeleteUser", RPC_DELETE_USER, ScDeleteUser, InRpcDeleteUser, OutRpcDeleteUser)
DECLARE_SC_EX("EnumUser", RPC_ENUM_USER, ScEnumUser, InRpcEnumUser, OutRpcEnumUser, FreeRpcEnumUser)
DECLARE_SC_EX("CreateGroup", RPC_SET_GROUP, ScCreateGroup, InRpcSetGroup, OutRpcSetGroup, FreeRpcSetGroup)
DECLARE_SC_EX("SetGroup", RPC_SET_GROUP, ScSetGroup, InRpcSetGroup, OutRpcSetGroup, FreeRpcSetGroup)
DECLARE_SC_EX("GetGroup", RPC_SET_GROUP, ScGetGroup, InRpcSetGroup, OutRpcSetGroup, FreeRpcSetGroup)
DECLARE_SC("DeleteGroup", RPC_DELETE_USER, ScDeleteGroup, InRpcDeleteUser, OutRpcDeleteUser)
DECLARE_SC_EX("EnumGroup", RPC_ENUM_GROUP, ScEnumGroup, InRpcEnumGroup, OutRpcEnumGroup, FreeRpcEnumGroup)
DECLARE_SC_EX("EnumSession", RPC_ENUM_SESSION, ScEnumSession, InRpcEnumSession, OutRpcEnumSession, FreeRpcEnumSession)
DECLARE_SC_EX("GetSessionStatus", RPC_SESSION_STATUS, ScGetSessionStatus, InRpcSessionStatus, OutRpcSessionStatus, FreeRpcSessionStatus)
DECLARE_SC("DeleteSession", RPC_DELETE_SESSION, ScDeleteSession, InRpcDeleteSession, OutRpcDeleteSession)
DECLARE_SC_EX("EnumMacTable", RPC_ENUM_MAC_TABLE, ScEnumMacTable, InRpcEnumMacTable, OutRpcEnumMacTable, FreeRpcEnumMacTable)
DECLARE_SC("DeleteMacTable", RPC_DELETE_TABLE, ScDeleteMacTable, InRpcDeleteTable, OutRpcDeleteTable)
DECLARE_SC_EX("EnumIpTable", RPC_ENUM_IP_TABLE, ScEnumIpTable, InRpcEnumIpTable, OutRpcEnumIpTable, FreeRpcEnumIpTable)
DECLARE_SC("DeleteIpTable", RPC_DELETE_TABLE, ScDeleteIpTable, InRpcDeleteTable, OutRpcDeleteTable)
DECLARE_SC_EX("EnumEthernet", RPC_ENUM_ETH, ScEnumEthernet, InRpcEnumEth, OutRpcEnumEth, FreeRpcEnumEth)
DECLARE_SC("AddLocalBridge", RPC_LOCALBRIDGE, ScAddLocalBridge, InRpcLocalBridge, OutRpcLocalBridge)
DECLARE_SC("DeleteLocalBridge", RPC_LOCALBRIDGE, ScDeleteLocalBridge, InRpcLocalBridge, OutRpcLocalBridge)
DECLARE_SC_EX("EnumLocalBridge", RPC_ENUM_LOCALBRIDGE, ScEnumLocalBridge, InRpcEnumLocalBridge, OutRpcEnumLocalBridge, FreeRpcEnumLocalBridge)
DECLARE_SC("GetBridgeSupport", RPC_BRIDGE_SUPPORT, ScGetBridgeSupport, InRpcBridgeSupport, OutRpcBridgeSupport)
DECLARE_SC("RebootServer", RPC_TEST, ScRebootServer, InRpcTest, OutRpcTest)
DECLARE_SC_EX("GetCaps", CAPSLIST, ScGetCaps, InRpcCapsList, OutRpcCapsList, FreeRpcCapsList)
DECLARE_SC_EX("GetConfig", RPC_CONFIG, ScGetConfig, InRpcConfig, OutRpcConfig, FreeRpcConfig)
DECLARE_SC_EX("SetConfig", RPC_CONFIG, ScSetConfig, InRpcConfig, OutRpcConfig, FreeRpcConfig)
DECLARE_SC_EX("GetHubAdminOptions", RPC_ADMIN_OPTION, ScGetHubAdminOptions, InRpcAdminOption, OutRpcAdminOption, FreeRpcAdminOption)
DECLARE_SC_EX("SetHubAdminOptions", RPC_ADMIN_OPTION, ScSetHubAdminOptions, InRpcAdminOption, OutRpcAdminOption, FreeRpcAdminOption)
DECLARE_SC_EX("GetHubExtOptions", RPC_ADMIN_OPTION, ScGetHubExtOptions, InRpcAdminOption, OutRpcAdminOption, FreeRpcAdminOption)
DECLARE_SC_EX("SetHubExtOptions", RPC_ADMIN_OPTION, ScSetHubExtOptions, InRpcAdminOption, OutRpcAdminOption, FreeRpcAdminOption)
DECLARE_SC_EX("EnumCrl", RPC_ENUM_CRL, ScEnumCrl, InRpcEnumCrl, OutRpcEnumCrl, FreeRpcEnumCrl)
DECLARE_SC_EX("AddCrl", RPC_CRL, ScAddCrl, InRpcCrl, OutRpcCrl, FreeRpcCrl)
DECLARE_SC_EX("DelCrl", RPC_CRL, ScDelCrl, InRpcCrl, OutRpcCrl, FreeRpcCrl)
DECLARE_SC_EX("GetCrl", RPC_CRL, ScGetCrl, InRpcCrl, OutRpcCrl, FreeRpcCrl)
DECLARE_SC_EX("SetAcList", RPC_AC_LIST, ScSetAcList, InRpcAcList, OutRpcAcList, FreeRpcAcList)
DECLARE_SC_EX("GetAcList", RPC_AC_LIST, ScGetAcList, InRpcAcList, OutRpcAcList, FreeRpcAcList)
DECLARE_SC_EX("EnumLogFile", RPC_ENUM_LOG_FILE, ScEnumLogFile, InRpcEnumLogFile, OutRpcEnumLogFile, FreeRpcEnumLogFile)
DECLARE_SC_EX("ReadLogFile", RPC_READ_LOG_FILE, ScReadLogFile, InRpcReadLogFile, OutRpcReadLogFile, FreeRpcReadLogFile)
DECLARE_SC("AddLicenseKey", RPC_TEST, ScAddLicenseKey, InRpcTest, OutRpcTest)
DECLARE_SC("DelLicenseKey", RPC_TEST, ScDelLicenseKey, InRpcTest, OutRpcTest)
DECLARE_SC_EX("EnumLicenseKey", RPC_ENUM_LICENSE_KEY, ScEnumLicenseKey, InRpcEnumLicenseKey, OutRpcEnumLicenseKey, FreeRpcEnumLicenseKey)
DECLARE_SC("GetLicenseStatus", RPC_LICENSE_STATUS, ScGetLicenseStatus, InRpcLicenseStatus, OutRpcLicenseStatus)
DECLARE_SC("SetSysLog", SYSLOG_SETTING, ScSetSysLog, InRpcSysLogSetting, OutRpcSysLogSetting)
DECLARE_SC("GetSysLog", SYSLOG_SETTING, ScGetSysLog, InRpcSysLogSetting, OutRpcSysLogSetting)
DECLARE_SC("Crash", RPC_TEST, ScCrash, InRpcTest, OutRpcTest)
DECLARE_SC("Flush", RPC_TEST, ScFlush, InRpcTest, OutRpcTest)
DECLARE_SC("Debug", RPC_TEST, ScDebug, InRpcTest, OutRpcTest)
DECLARE_SC("RegenerateServerCert", RPC_TEST, ScRegenerateServerCert, InRpcTest, OutRpcTest)

BUF *DownloadFileFromServer(RPC *r, char *filepath, UINT total_size, DOWNLOAD_PROC *proc, void *param)
{
	UINT offset;
	BUF *buf;
	if (r == NULL || filepath == NULL)
	{
		return NULL;
	}

	offset = 0;

	buf = NewBuf();

	while (true)
	{
		DOWNLOAD_PROGRESS g;
		RPC_READ_LOG_FILE t;
		UINT ret;

		Zero(&t, sizeof(t));
		StrCpy(t.FilePath, sizeof(t.FilePath), filepath);
		t.Offset = offset;

		ret = ScReadLogFile(r, &t);

		if (ret != ERR_NO_ERROR)
		{
			FreeRpcReadLogFile(&t);
			FreeBuf(buf);
			return NULL;
		}

		if (t.Buffer == NULL)
		{
			break;
		}

		offset += t.Buffer->Size;
		Zero(&g, sizeof(g));
		g.Param = param;
		g.CurrentSize = offset;
		g.TotalSize = MAX(total_size, offset);
		g.ProgressPercent = (UINT)(MAKESURE((UINT64)g.CurrentSize * 100ULL / (UINT64)(MAX(g.TotalSize, 1)), 0, 100ULL));

		WriteBuf(buf, t.Buffer->Buf, t.Buffer->Size);

		FreeRpcReadLogFile(&t);

		if (proc != NULL)
		{
			if (proc(&g) == false)
			{
				FreeBuf(buf);
				return NULL;
			}
		}
	}

	if (buf->Size == 0)
	{
		FreeBuf(buf);
		return NULL;
	}

	return buf;
}


void InRpcWinVer(RPC_WINVER *t, PACK *p)
{
	if (t == NULL || p == NULL)
	{
		return;
	}

	Zero(t, sizeof(RPC_WINVER));

	t->IsWindows = PackGetBool(p, "V_IsWindows");
	t->IsNT = PackGetBool(p, "V_IsNT");
	t->IsServer = PackGetBool(p, "V_IsServer");
	t->IsBeta = PackGetBool(p, "V_IsBeta");
	t->VerMajor = PackGetInt(p, "V_VerMajor");
	t->VerMinor = PackGetInt(p, "V_VerMinor");
	t->Build = PackGetInt(p, "V_Build");
	t->ServicePack = PackGetInt(p, "V_ServicePack");
	PackGetStr(p, "V_Title", t->Title, sizeof(t->Title));
}
void OutRpcWinVer(PACK *p, RPC_WINVER *t)
{
	if (t == NULL || p == NULL)
	{
		return;
	}

	PackAddBool(p, "V_IsWindows", t->IsWindows);
	PackAddBool(p, "V_IsNT", t->IsNT);
	PackAddBool(p, "V_IsServer", t->IsServer);
	PackAddBool(p, "V_IsBeta", t->IsBeta);
	PackAddInt(p, "V_VerMajor", t->VerMajor);
	PackAddInt(p, "V_VerMinor", t->VerMinor);
	PackAddInt(p, "V_Build", t->Build);
	PackAddInt(p, "V_ServicePack", t->ServicePack);
	PackAddStr(p, "V_Title", t->Title);
}

void InRpcMsg(RPC_MSG *t, PACK *p)
{
	UINT size;
	char *utf8;
	if (t == NULL || p == NULL)
	{
		return;
	}

	Zero(t, sizeof(RPC_MSG));

	PackGetStr(p, "HubName", t->HubName, sizeof(t->HubName));
	size = PackGetDataSize(p, "Msg");
	utf8 = ZeroMalloc(size + 8);
	PackGetData(p, "Msg", utf8);
	t->Msg = CopyUtfToUni(utf8);
	Free(utf8);
}
void OutRpcMsg(PACK *p, RPC_MSG *t)
{
	UINT size;
	char *utf8;
	if (t == NULL || p == NULL)
	{
		return;
	}

	PackAddStr(p, "HubName", t->HubName);
	utf8 = CopyUniToUtf(t->Msg);
	size = StrLen(utf8);
	PackAddData(p, "Msg", utf8, size);
	Free(utf8);
}
void FreeRpcMsg(RPC_MSG *t)
{
	if (t == NULL)
	{
		return;
	}

	Free(t->Msg);
}

void InRpcEnumEthVLan(RPC_ENUM_ETH_VLAN *t, PACK *p)
{
	UINT i;
	if (t == NULL || p == NULL)
	{
		return;
	}

	Zero(t, sizeof(RPC_ENUM_ETH_VLAN));

	t->NumItem = PackGetIndexCount(p, "DeviceName");
	t->Items = ZeroMalloc(sizeof(RPC_ENUM_ETH_VLAN_ITEM) * t->NumItem);

	for (i = 0;i < t->NumItem;i++)
	{
		RPC_ENUM_ETH_VLAN_ITEM *e = &t->Items[i];

		PackGetStrEx(p, "DeviceName", e->DeviceName, sizeof(e->DeviceName), i);
		PackGetStrEx(p, "Guid", e->Guid, sizeof(e->Guid), i);
		PackGetStrEx(p, "DriverName", e->DriverName, sizeof(e->DriverName), i);
		PackGetStrEx(p, "DriverType", e->DriverType, sizeof(e->DriverType), i);
		e->Support = PackGetBoolEx(p, "Support", i);
		e->Enabled = PackGetBoolEx(p, "Enabled", i);
	}
}
void OutRpcEnumEthVLan(PACK *p, RPC_ENUM_ETH_VLAN *t)
{
	UINT i;
	if (t == NULL || p == NULL)
	{
		return;
	}

	for (i = 0;i < t->NumItem;i++)
	{
		RPC_ENUM_ETH_VLAN_ITEM *e = &t->Items[i];

		PackAddStrEx(p, "DeviceName", e->DeviceName, i, t->NumItem);
		PackAddStrEx(p, "Guid", e->Guid, i, t->NumItem);
		PackAddStrEx(p, "DeviceInstanceId", e->DeviceInstanceId, i, t->NumItem);
		PackAddStrEx(p, "DriverName", e->DriverName, i, t->NumItem);
		PackAddStrEx(p, "DriverType", e->DriverType, i, t->NumItem);
		PackAddBoolEx(p, "Support", e->Support, i, t->NumItem);
		PackAddBoolEx(p, "Enabled", e->Enabled, i, t->NumItem);
	}
}
void FreeRpcEnumEthVLan(RPC_ENUM_ETH_VLAN *t)
{
	if (t == NULL)
	{
		return;
	}

	Free(t->Items);
}

void InRpcEnumLogFile(RPC_ENUM_LOG_FILE *t, PACK *p)
{
	UINT i;
	if (t == NULL || p == NULL)
	{
		return;
	}

	Zero(t, sizeof(RPC_ENUM_LOG_FILE));
	t->NumItem = PackGetInt(p, "NumItem");
	t->Items = ZeroMalloc(sizeof(RPC_ENUM_LOG_FILE_ITEM) * t->NumItem);

	for (i = 0;i < t->NumItem;i++)
	{
		RPC_ENUM_LOG_FILE_ITEM *e = &t->Items[i];

		PackGetStrEx(p, "FilePath", e->FilePath, sizeof(e->FilePath), i);
		e->FileSize = PackGetIntEx(p, "FileSize", i);
		e->UpdatedTime = PackGetInt64Ex(p, "UpdatedTime", i);
	}
}
void OutRpcEnumLogFile(PACK *p, RPC_ENUM_LOG_FILE *t)
{
	UINT i;
	if (t == NULL || p == NULL)
	{
		return;
	}

	PackAddInt(p, "NumItem", t->NumItem);

	for (i = 0;i < t->NumItem;i++)
	{
		RPC_ENUM_LOG_FILE_ITEM *e = &t->Items[i];

		PackAddStrEx(p, "FilePath", e->FilePath, i, t->NumItem);
		PackAddIntEx(p, "FileSize", e->FileSize, i, t->NumItem);
		PackAddInt64Ex(p, "UpdatedTime", e->UpdatedTime, i, t->NumItem);
	}
}
void FreeRpcEnumLogFile(RPC_ENUM_LOG_FILE *t)
{
	if (t == NULL)
	{
		return;
	}

	Free(t->Items);
}
void InRpcReadLogFile(RPC_READ_LOG_FILE *t, PACK *p)
{
	if (t == NULL || p == NULL)
	{
		return;
	}

	Zero(t, sizeof(RPC_READ_LOG_FILE));
	PackGetStr(p, "FilePath", t->FilePath, sizeof(t->FilePath));
	t->Offset = PackGetInt(p, "Offset");

	t->Buffer = PackGetBuf(p, "Buffer");
}
void OutRpcReadLogFile(PACK *p, RPC_READ_LOG_FILE *t)
{
	if (p == NULL || t == NULL)
	{
		return;
	}

	PackAddStr(p, "FilePath", t->FilePath);
	PackAddInt(p, "Offset", t->Offset);

	if (t->Buffer != NULL)
	{
		PackAddBuf(p, "Buffer", t->Buffer);
	}
}
void FreeRpcReadLogFile(RPC_READ_LOG_FILE *t)
{
	if (t == NULL)
	{
		return;
	}

	if (t->Buffer != NULL)
	{
		FreeBuf(t->Buffer);
	}
}

void InRpcAcList(RPC_AC_LIST *t, PACK *p)
{
	UINT i;
	LIST *o;
	UINT num;
	if (t == NULL || p == NULL)
	{
		return;
	}

	Zero(t, sizeof(RPC_AC_LIST));
	o = NewList(CmpAc);

	PackGetStr(p, "HubName", t->HubName, sizeof(t->HubName));
	num = PackGetIndexCount(p, "IpAddress");

	for (i = 0;i < num;i++)
	{
		AC *ac = ZeroMalloc(sizeof(AC));

		ac->Id = PackGetIntEx(p, "Id", i);
		ac->Deny = PackGetBoolEx(p, "Deny", i);
		PackGetIpEx(p, "IpAddress", &ac->IpAddress, i);
		ac->Masked = PackGetBoolEx(p, "Masked", i);

		if (ac->Masked)
		{
			PackGetIpEx(p, "SubnetMask", &ac->SubnetMask, i);
		}

		ac->Priority = PackGetIntEx(p, "Priority", i);

		AddAc(o, ac);

		Free(ac);
	}

	t->o = o;
}
void OutRpcAcList(PACK *p, RPC_AC_LIST *t)
{
	UINT i, num;
	LIST *o;
	if (t == NULL || p == NULL)
	{
		return;
	}

	o = t->o;
	num = LIST_NUM(o);

	PackAddInt(p, "NumItem", num);

	PackAddStr(p, "HubName", t->HubName);

	for (i = 0;i < num;i++)
	{
		AC *ac = LIST_DATA(o, i);

		PackAddIntEx(p, "Id", ac->Id, i, num);
		PackAddBoolEx(p, "Deny", ac->Deny, i, num);
		PackAddIpEx(p, "IpAddress", &ac->IpAddress, i, num);
		PackAddBoolEx(p, "Masked", ac->Masked, i, num);

		PackAddIpEx(p, "SubnetMask", &ac->SubnetMask, i, num);

		PackAddIntEx(p, "Priority", ac->Priority, i, num);
	}
}
void FreeRpcAcList(RPC_AC_LIST *t)
{
	if (t == NULL)
	{
		return;
	}

	FreeAcList(t->o);
}

void InRpcEnumCrl(RPC_ENUM_CRL *t, PACK *p)
{
	UINT i;
	if (t == NULL || p == NULL)
	{
		return;
	}

	Zero(t, sizeof(RPC_ENUM_CRL));
	PackGetStr(p, "HubName", t->HubName, sizeof(t->HubName));
	t->NumItem = PackGetInt(p, "NumItem");

	t->Items = ZeroMalloc(sizeof(RPC_ENUM_CRL_ITEM) * t->NumItem);
	for (i = 0;i < t->NumItem;i++)
	{
		RPC_ENUM_CRL_ITEM *e = &t->Items[i];

		e->Key = PackGetIntEx(p, "Key", i);
		PackGetUniStrEx(p, "CrlInfo", e->CrlInfo, sizeof(e->CrlInfo), i);
	}
}
void OutRpcEnumCrl(PACK *p, RPC_ENUM_CRL *t)
{
	UINT i;
	if (t == NULL || p == NULL)
	{
		return;
	}

	PackAddStr(p, "HubName", t->HubName);
	PackAddInt(p, "NumItem", t->NumItem);

	for (i = 0;i < t->NumItem;i++)
	{
		RPC_ENUM_CRL_ITEM *e = &t->Items[i];

		PackAddIntEx(p, "Key", e->Key, i, t->NumItem);
		PackAddUniStrEx(p, "CrlInfo", e->CrlInfo, i, t->NumItem);
	}
}
void FreeRpcEnumCrl(RPC_ENUM_CRL *t)
{
	if (t == NULL)
	{
		return;
	}

	Free(t->Items);
}

void InRpcCrl(RPC_CRL *t, PACK *p)
{
	BUF *b;
	NAME *n;
	wchar_t tmp[MAX_SIZE];
	if (t == NULL || p == NULL)
	{
		return;
	}

	Zero(t, sizeof(RPC_CRL));
	PackGetStr(p, "HubName", t->HubName, sizeof(t->HubName));
	t->Key = PackGetInt(p, "Key");
	b = PackGetBuf(p, "Serial");
	t->Crl = ZeroMalloc(sizeof(CRL));
	if (b != NULL)
	{
		t->Crl->Serial = NewXSerial(b->Buf, b->Size);
		FreeBuf(b);
	}
	t->Crl->Name = ZeroMalloc(sizeof(NAME));
	n = t->Crl->Name;
	if (PackGetUniStr(p, "CommonName", tmp, sizeof(tmp)))
	{
		n->CommonName = CopyUniStr(tmp);
	}
	if (PackGetUniStr(p, "Organization", tmp, sizeof(tmp)))
	{
		n->Organization = CopyUniStr(tmp);
	}
	if (PackGetUniStr(p, "Unit", tmp, sizeof(tmp)))
	{
		n->Unit = CopyUniStr(tmp);
	}
	if (PackGetUniStr(p, "Country", tmp, sizeof(tmp)))
	{
		n->Country = CopyUniStr(tmp);
	}
	if (PackGetUniStr(p, "State", tmp, sizeof(tmp)))
	{
		n->State = CopyUniStr(tmp);
	}
	if (PackGetUniStr(p, "Local", tmp, sizeof(tmp)))
	{
		n->Local = CopyUniStr(tmp);
	}
	if (PackGetDataSize(p, "DigestMD5") == MD5_SIZE)
	{
		PackGetData(p, "DigestMD5", t->Crl->DigestMD5);
	}
	if (PackGetDataSize(p, "DigestSHA1") == SHA1_SIZE)
	{
		PackGetData(p, "DigestSHA1", t->Crl->DigestSHA1);
	}
}
void OutRpcCrl(PACK *p, RPC_CRL *t)
{
	NAME *n;
	if (p == NULL || t == NULL)
	{
		return;
	}

	PackAddStr(p, "HubName", t->HubName);
	PackAddInt(p, "Key", t->Key);

	if (t->Crl == NULL)
	{
		return;
	}

	if (t->Crl->Serial != NULL)
	{
		PackAddData(p, "Serial", t->Crl->Serial->data, t->Crl->Serial->size);
	}
	n = t->Crl->Name;
	if (n->CommonName != NULL)
	{
		PackAddUniStr(p, "CommonName", n->CommonName);
	}
	if (n->Organization != NULL)
	{
		PackAddUniStr(p, "Organization", n->Organization);
	}
	if (n->Unit != NULL)
	{
		PackAddUniStr(p, "Unit", n->Unit);
	}
	if (n->Country != NULL)
	{
		PackAddUniStr(p, "Country", n->Country);
	}
	if (n->State != NULL)
	{
		PackAddUniStr(p, "State", n->State);
	}
	if (n->Local != NULL)
	{
		PackAddUniStr(p, "Local", n->Local);
	}
	if (IsZero(t->Crl->DigestMD5, MD5_SIZE) == false)
	{
		PackAddData(p, "DigestMD5", t->Crl->DigestMD5, MD5_SIZE);
	}
	if (IsZero(t->Crl->DigestSHA1, SHA1_SIZE) == false)
	{
		PackAddData(p, "DigestSHA1", t->Crl->DigestSHA1, SHA1_SIZE);
	}
}
void FreeRpcCrl(RPC_CRL *t)
{
	if (t == NULL)
	{
		return;
	}

	FreeCrl(t->Crl);
}

void InRpcEnumEth(RPC_ENUM_ETH *t, PACK *p)
{
	UINT i;
	if (t == NULL || p == NULL)
	{
		return;
	}

	Zero(t, sizeof(RPC_ENUM_ETH));
	t->NumItem = PackGetInt(p, "NumItem");
	t->Items = ZeroMalloc(sizeof(RPC_ENUM_ETH_ITEM) * t->NumItem);

	for (i = 0;i < t->NumItem;i++)
	{
		RPC_ENUM_ETH_ITEM *e = &t->Items[i];
		PackGetStrEx(p, "DeviceName", e->DeviceName, sizeof(e->DeviceName), i);
	}
}
void OutRpcEnumEth(PACK *p, RPC_ENUM_ETH *t)
{
	UINT i;
	if (p == NULL || t == NULL)
	{
		return;
	}

	PackAddInt(p, "NumItem", t->NumItem);

	for (i = 0;i < t->NumItem;i++)
	{
		RPC_ENUM_ETH_ITEM *e = &t->Items[i];
		PackAddStrEx(p, "DeviceName", e->DeviceName, i, t->NumItem);
		PackAddUniStrEx(p, "NetworkConnectionName", e->NetworkConnectionName, i, t->NumItem);
	}
}
void FreeRpcEnumEth(RPC_ENUM_ETH *t)
{
	if (t == NULL)
	{
		return;
	}

	Free(t->Items);
}

void InRpcLocalBridge(RPC_LOCALBRIDGE *t, PACK *p)
{
	if (t == NULL || p == NULL)
	{
		return;
	}

	Zero(t, sizeof(RPC_LOCALBRIDGE));
	PackGetStr(p, "DeviceName", t->DeviceName, sizeof(t->DeviceName));
	PackGetStr(p, "HubNameLB", t->HubName, sizeof(t->HubName));
	t->TapMode = PackGetBool(p, "TapMode");
}
void OutRpcLocalBridge(PACK *p, RPC_LOCALBRIDGE *t)
{
	if (t == NULL || p == NULL)
	{
		return;
	}

	PackAddStr(p, "DeviceName", t->DeviceName);
	PackAddStr(p, "HubNameLB", t->HubName);
	PackAddBool(p, "TapMode", t->TapMode);
}

void InRpcEnumLocalBridge(RPC_ENUM_LOCALBRIDGE *t, PACK *p)
{
	UINT i;
	if (t == NULL || p == NULL)
	{
		return;
	}

	Zero(t, sizeof(RPC_ENUM_LOCALBRIDGE));
	t->NumItem = PackGetInt(p, "NumItem");
	t->Items = ZeroMalloc(sizeof(RPC_LOCALBRIDGE) * t->NumItem);

	for (i = 0;i < t->NumItem;i++)
	{
		RPC_LOCALBRIDGE *e = &t->Items[i];

		PackGetStrEx(p, "DeviceName", e->DeviceName, sizeof(e->DeviceName), i);
		PackGetStrEx(p, "HubNameLB", e->HubName, sizeof(e->HubName), i);
		e->Online = PackGetBoolEx(p, "Online", i);
		e->Active = PackGetBoolEx(p, "Active", i);
		e->TapMode = PackGetBoolEx(p, "TapMode", i);
	}
}
void OutRpcEnumLocalBridge(PACK *p, RPC_ENUM_LOCALBRIDGE *t)
{
	UINT i;
	if (t == NULL || p == NULL)
	{
		return;
	}

	PackAddInt(p, "NumItem", t->NumItem);

	for (i = 0;i < t->NumItem;i++)
	{
		RPC_LOCALBRIDGE *e = &t->Items[i];

		PackAddStrEx(p, "DeviceName", e->DeviceName, i, t->NumItem);
		PackAddStrEx(p, "HubNameLB", e->HubName, i, t->NumItem);
		PackAddBoolEx(p, "Online", e->Online, i, t->NumItem);
		PackAddBoolEx(p, "Active", e->Active, i, t->NumItem);
		PackAddBoolEx(p, "TapMode", e->TapMode, i, t->NumItem);
	}
}
void FreeRpcEnumLocalBridge(RPC_ENUM_LOCALBRIDGE *t)
{
	if (t == NULL)
	{
		return;
	}
	Free(t->Items);
}

void InRpcMemInfo(MEMINFO *t, PACK *p)
{
	if (t == NULL || p == NULL)
	{
		return;
	}

	Zero(t, sizeof(MEMINFO));
	t->TotalMemory = PackGetInt64(p, "TotalMemory");
	t->UsedMemory = PackGetInt64(p, "UsedMemory");
	t->FreeMemory = PackGetInt64(p, "FreeMemory");
	t->TotalPhys = PackGetInt64(p, "TotalPhys");
	t->UsedPhys = PackGetInt64(p, "UsedPhys");
	t->FreePhys = PackGetInt64(p, "FreePhys");
}
void OutRpcMemInfo(PACK *p, MEMINFO *t)
{
	if (t == NULL || p == NULL)
	{
		return;
	}

	PackAddInt64(p, "TotalMemory", t->TotalMemory);
	PackAddInt64(p, "UsedMemory", t->UsedMemory);
	PackAddInt64(p, "FreeMemory", t->FreeMemory);
	PackAddInt64(p, "TotalPhys", t->TotalPhys);
	PackAddInt64(p, "UsedPhys", t->UsedPhys);
	PackAddInt64(p, "FreePhys", t->FreePhys);
}

void InRpcOsInfo(OS_INFO *t, PACK *p)
{
	char tmp[MAX_SIZE];
	if (t == NULL || p == NULL)
	{
		return;
	}

	Zero(t, sizeof(OS_INFO));
	t->OsType = PackGetInt(p, "OsType");
	t->OsServicePack = PackGetInt(p, "OsServicePack");
	if (PackGetStr(p, "OsSystemName", tmp, sizeof(tmp)))
	{
		t->OsSystemName = CopyStr(tmp);
	}
	if (PackGetStr(p, "OsProductName", tmp, sizeof(tmp)))
	{
		t->OsProductName = CopyStr(tmp);
	}
	if (PackGetStr(p, "OsVendorName", tmp, sizeof(tmp)))
	{
		t->OsVendorName = CopyStr(tmp);
	}
	if (PackGetStr(p, "OsVersion", tmp, sizeof(tmp)))
	{
		t->OsVersion = CopyStr(tmp);
	}
	if (PackGetStr(p, "KernelName", tmp, sizeof(tmp)))
	{
		t->KernelName = CopyStr(tmp);
	}
	if (PackGetStr(p, "KernelVersion", tmp, sizeof(tmp)))
	{
		t->KernelVersion = CopyStr(tmp);
	}
}
void OutRpcOsInfo(PACK *p, OS_INFO *t)
{
	if (t == NULL || p == NULL)
	{
		return;
	}

	PackAddInt(p, "OsType", t->OsType);
	PackAddInt(p, "OsServicePack", t->OsServicePack);
	PackAddStr(p, "OsSystemName", t->OsSystemName);
	PackAddStr(p, "OsProductName", t->OsProductName);
	PackAddStr(p, "OsVendorName", t->OsVendorName);
	PackAddStr(p, "OsVersion", t->OsVersion);
	PackAddStr(p, "KernelName", t->KernelName);
	PackAddStr(p, "KernelVersion", t->KernelVersion);
}
void FreeRpcOsInfo(OS_INFO *t)
{
	if (t == NULL)
	{
		return;
	}

	Free(t->OsSystemName);
	Free(t->OsProductName);
	Free(t->OsVendorName);
	Free(t->OsVersion);
	Free(t->KernelName);
	Free(t->KernelVersion);
}

void InRpcEnumLicenseKey(RPC_ENUM_LICENSE_KEY *t, PACK *p)
{
	UINT i;
	if (t == NULL || p == NULL)
	{
		return;
	}

	Zero(t, sizeof(RPC_ENUM_LICENSE_KEY));
	t->NumItem = PackGetInt(p, "NumItem");
	t->Items = ZeroMalloc(sizeof(RPC_ENUM_LICENSE_KEY_ITEM) * t->NumItem);
	for (i = 0;i < t->NumItem;i++)
	{
		RPC_ENUM_LICENSE_KEY_ITEM *e = &t->Items[i];

		e->Id = PackGetIntEx(p, "Id", i);
		PackGetStrEx(p, "LicenseKey", e->LicenseKey, sizeof(e->LicenseKey), i);
		PackGetStrEx(p, "LicenseId", e->LicenseId, sizeof(e->LicenseId), i);
		PackGetStrEx(p, "LicenseName", e->LicenseName, sizeof(e->LicenseName), i);
		e->Expires = PackGetInt64Ex(p, "Expires", i);
		e->Status = PackGetIntEx(p, "Status", i);
		e->ProductId = PackGetIntEx(p, "ProductId", i);
		e->SystemId = PackGetInt64Ex(p, "SystemId", i);
		e->SerialId = PackGetIntEx(p, "SerialId", i);
	}
}
void OutRpcEnumLicenseKey(PACK *p, RPC_ENUM_LICENSE_KEY *t)
{
	UINT i;
	if (t == NULL || p == NULL)
	{
		return;
	}

	PackAddInt(p, "NumItem", t->NumItem);

	for (i = 0;i < t->NumItem;i++)
	{
		RPC_ENUM_LICENSE_KEY_ITEM *e = &t->Items[i];

		PackAddIntEx(p, "Id", e->Id, i, t->NumItem);
		PackAddStrEx(p, "LicenseKey", e->LicenseKey, i, t->NumItem);
		PackAddStrEx(p, "LicenseId", e->LicenseId, i, t->NumItem);
		PackAddStrEx(p, "LicenseName", e->LicenseName, i, t->NumItem);
		PackAddInt64Ex(p, "Expires", e->Expires, i, t->NumItem);
		PackAddIntEx(p, "Status", e->Status, i, t->NumItem);
		PackAddIntEx(p, "ProductId", e->ProductId, i, t->NumItem);
		PackAddInt64Ex(p, "SystemId", e->SystemId, i, t->NumItem);
		PackAddIntEx(p, "SerialId", e->SerialId, i, t->NumItem);
	}
}
void FreeRpcEnumLicenseKey(RPC_ENUM_LICENSE_KEY *t)
{
	if (t == NULL)
	{
		return;
	}

	Free(t->Items);
}

void InRpcLicenseStatus(RPC_LICENSE_STATUS *t, PACK *p)
{
	if (t == NULL || p == NULL)
	{
		return;
	}

	Zero(t, sizeof(RPC_LICENSE_STATUS));

	t->EditionId = PackGetInt(p, "EditionId");
	PackGetStr(p, "EditionStr", t->EditionStr, sizeof(t->EditionStr) );
	t->SystemId = PackGetInt64(p, "SystemId");
	t->SystemExpires = PackGetInt64(p, "SystemExpires");
	t->NumClientConnectLicense = PackGetInt(p, "NumClientConnectLicense");
	t->NumBridgeConnectLicense = PackGetInt(p, "NumBridgeConnectLicense");

	t->NeedSubscription = PackGetBool(p, "NeedSubscription");
	t->AllowEnterpriseFunction = PackGetBool(p, "AllowEnterpriseFunction");
	t->SubscriptionExpires = PackGetInt64(p, "SubscriptionExpires");
	t->IsSubscriptionExpired = PackGetBool(p, "IsSubscriptionExpired");
	t->ReleaseDate = PackGetInt64(p, "ReleaseDate");
}
void OutRpcLicenseStatus(PACK *p, RPC_LICENSE_STATUS *t)
{
	if (t == NULL || p == NULL)
	{
		return;
	}

	PackAddInt(p, "EditionId", t->EditionId);
	PackAddStr(p, "EditionStr", t->EditionStr);
	PackAddInt64(p, "SystemId", t->SystemId);
	PackAddInt64(p, "SystemExpires", t->SystemExpires);
	PackAddInt(p, "NumClientConnectLicense", t->NumClientConnectLicense);
	PackAddInt(p, "NumBridgeConnectLicense", t->NumBridgeConnectLicense);

	PackAddBool(p, "NeedSubscription", t->NeedSubscription);
	PackAddBool(p, "AllowEnterpriseFunction", t->AllowEnterpriseFunction);
	PackAddInt64(p, "SubscriptionExpires", t->SubscriptionExpires);
	PackAddBool(p, "IsSubscriptionExpired", t->IsSubscriptionExpired);
	PackAddInt(p, "NumUserCreationLicense", t->NumUserCreationLicense);
	PackAddInt64(p, "ReleaseDate", t->ReleaseDate);
}

void InRpcAdminOption(RPC_ADMIN_OPTION *t, PACK *p)
{
	UINT i;
	if (t == NULL || p == NULL)
	{
		return;
	}

	Zero(t, sizeof(RPC_ADMIN_OPTION));
	t->NumItem = PackGetIndexCount(p, "Name");
	t->Items = ZeroMalloc(sizeof(ADMIN_OPTION) * t->NumItem);

	PackGetStr(p, "HubName", t->HubName, sizeof(t->HubName));

	for (i = 0;i < t->NumItem;i++)
	{
		ADMIN_OPTION *o = &t->Items[i];

		PackGetStrEx(p, "Name", o->Name, sizeof(o->Name), i);
		o->Value = PackGetIntEx(p, "Value", i);
		PackGetUniStrEx(p, "Descrption", o->Descrption, sizeof(o->Descrption), i);
	}
}
void OutRpcAdminOption(PACK *p, RPC_ADMIN_OPTION *t)
{
	UINT i;
	if (t == NULL || p == NULL)
	{
		return;
	}

	PackAddInt(p, "NumItem", t->NumItem);

	PackAddStr(p, "HubName", t->HubName);

	for (i = 0;i < t->NumItem;i++)
	{
		ADMIN_OPTION *o = &t->Items[i];

		PackAddStrEx(p, "Name", o->Name, i, t->NumItem);
		PackAddIntEx(p, "Value", o->Value, i, t->NumItem);
		PackAddUniStrEx(p, "Descrption", o->Descrption, i, t->NumItem);
	}
}
void FreeRpcAdminOption(RPC_ADMIN_OPTION *t)
{
	if (t == NULL)
	{
		return;
	}

	Free(t->Items);
}

void InRpcConfig(RPC_CONFIG *t, PACK *p)
{
	UINT size;
	if (t == NULL || p == NULL)
	{
		return;
	}

	Zero(t, sizeof(RPC_CONFIG));
	PackGetStr(p, "FileName", t->FileName, sizeof(t->FileName));
	size = PackGetDataSize(p, "FileData");
	t->FileData = ZeroMalloc(size + 1);
	PackGetData(p, "FileData", t->FileData);
}
void OutRpcConfig(PACK *p, RPC_CONFIG *t)
{
	if (t == NULL || p == NULL)
	{
		return;
	}

	PackAddStr(p, "FileName", t->FileName);
	PackAddData(p, "FileData", t->FileData, StrLen(t->FileData));
}
void FreeRpcConfig(RPC_CONFIG *t)
{
	if (t == NULL)
	{
		return;
	}

	Free(t->FileData);
}

void InRpcBridgeSupport(RPC_BRIDGE_SUPPORT *t, PACK *p)
{
	if (t == NULL || p == NULL)
	{
		return;
	}

	Zero(t, sizeof(RPC_BRIDGE_SUPPORT));

	t->IsBridgeSupportedOs = PackGetBool(p, "IsBridgeSupportedOs");
}
void OutRpcBridgeSupport(PACK *p, RPC_BRIDGE_SUPPORT *t)
{
	if (p == NULL || t == NULL)
	{
		return;
	}

	PackAddBool(p, "IsBridgeSupportedOs", t->IsBridgeSupportedOs);
}

void InRpcAddAccess(RPC_ADD_ACCESS *t, PACK *p)
{
	if (t == NULL || p == NULL)
	{
		return;
	}

	Zero(t, sizeof(RPC_ADD_ACCESS));

	PackGetStr(p, "HubName", t->HubName, sizeof(t->HubName));
	InRpcAccess(&t->Access, p);
}
void OutRpcAddAccess(PACK *p, RPC_ADD_ACCESS *t)
{
	if (t == NULL || p == NULL)
	{
		return;
	}

	PackAddStr(p, "HubName", t->HubName);
	OutRpcAccess(p, &t->Access);
}

void InRpcDeleteAccess(RPC_DELETE_ACCESS *t, PACK *p)
{
	if (t == NULL || p == NULL)
	{
		return;
	}

	Zero(t, sizeof(RPC_DELETE_ACCESS));

	PackGetStr(p, "HubName", t->HubName, sizeof(t->HubName));
	t->Id = PackGetInt(p, "Id");
}
void OutRpcDeleteAccess(PACK *p, RPC_DELETE_ACCESS *t)
{
	if (t == NULL || p == NULL)
	{
		return;
	}

	PackAddStr(p, "HubName", t->HubName);
	PackAddInt(p, "Id", t->Id);
}


void InRpcServerInfo(RPC_SERVER_INFO *t, PACK *p)
{
	if (t == NULL || p == NULL)
	{
		return;
	}

	Zero(t, sizeof(RPC_SERVER_INFO));

	PackGetStr(p, "ServerProductName", t->ServerProductName, sizeof(t->ServerProductName));
	PackGetStr(p, "ServerVersionString", t->ServerVersionString, sizeof(t->ServerVersionString));
	PackGetStr(p, "ServerBuildInfoString", t->ServerBuildInfoString, sizeof(t->ServerBuildInfoString));
	t->ServerBuildInt = PackGetInt(p, "ServerBuildInt");
	PackGetStr(p, "ServerHostName", t->ServerHostName, sizeof(t->ServerHostName));
	InRpcOsInfo(&t->OsInfo, p);
}
void OutRpcServerInfo(PACK *p, RPC_SERVER_INFO *t)
{
	if (t == NULL || p == NULL)
	{
		return;
	}

	PackAddStr(p, "ServerProductName", t->ServerProductName);
	PackAddStr(p, "ServerVersionString", t->ServerVersionString);
	PackAddStr(p, "ServerBuildInfoString", t->ServerBuildInfoString);
	PackAddInt(p, "ServerVerInt", t->ServerVerInt);
	PackAddInt(p, "ServerBuildInt", t->ServerBuildInt);
	PackAddStr(p, "ServerHostName", t->ServerHostName);
	PackAddInt64(p, "ServerBuildDate", t->ServerBuildDate);
	OutRpcOsInfo(p, &t->OsInfo);
}
void FreeRpcServerInfo(RPC_SERVER_INFO *t)
{
	if (t == NULL)
	{
		return;
	}

	FreeRpcOsInfo(&t->OsInfo);
}

void InRpcServerStatus(RPC_SERVER_STATUS *t, PACK *p)
{
	if (t == NULL || p == NULL)
	{
		return;
	}

	Zero(t, sizeof(RPC_SERVER_STATUS));
	t->NumTcpConnections = PackGetInt(p, "NumTcpConnections");
	t->NumTcpConnectionsLocal = PackGetInt(p, "NumTcpConnectionsLocal");
	t->NumHubTotal = PackGetInt(p, "NumHubTotal");
	t->NumSessionsTotal = PackGetInt(p, "NumSessionsTotal");
	t->NumSessionsLocal = PackGetInt(p, "NumSessionsLocal");
	t->NumMacTables = PackGetInt(p, "NumMacTables");
	t->NumIpTables = PackGetInt(p, "NumIpTables");
	t->NumUsers = PackGetInt(p, "NumUsers");
	t->NumGroups = PackGetInt(p, "NumGroups");
	t->CurrentTime = PackGetInt64(p, "CurrentTime");
	t->CurrentTick = PackGetInt64(p, "CurrentTick");
	t->AssignedBridgeLicenses = PackGetInt(p, "AssignedBridgeLicenses");
	t->AssignedClientLicenses = PackGetInt(p, "AssignedClientLicenses");
	t->StartTime = PackGetInt64(p, "StartTime");

	InRpcTraffic(&t->Traffic, p);

	InRpcMemInfo(&t->MemInfo, p);
}
void OutRpcServerStatus(PACK *p, RPC_SERVER_STATUS *t)
{
	if (t == NULL || p == NULL)
	{
		return;
	}

	PackAddInt(p, "NumHubTotal", t->NumHubTotal);
	PackAddInt(p, "NumHubStandalone", t->NumHubStandalone);
	PackAddInt(p, "NumSessionsTotal", t->NumSessionsTotal);
	PackAddInt(p, "NumSessionsLocal", t->NumSessionsLocal);
	PackAddInt(p, "NumTcpConnections", t->NumTcpConnections);
	PackAddInt(p, "NumTcpConnectionsLocal", t->NumTcpConnectionsLocal);
	PackAddInt(p, "NumMacTables", t->NumMacTables);
	PackAddInt(p, "NumIpTables", t->NumIpTables);
	PackAddInt(p, "NumUsers", t->NumUsers);
	PackAddInt(p, "NumGroups", t->NumGroups);
	PackAddInt64(p, "CurrentTime", t->CurrentTime);
	PackAddInt64(p, "CurrentTick", t->CurrentTick);
	PackAddInt(p, "AssignedBridgeLicenses", t->AssignedBridgeLicenses);
	PackAddInt(p, "AssignedClientLicenses", t->AssignedClientLicenses);
	PackAddInt(p, "AssignedBridgeLicensesTotal", t->AssignedBridgeLicensesTotal);
	PackAddInt(p, "AssignedClientLicensesTotal", t->AssignedClientLicensesTotal);
	PackAddInt64(p, "StartTime", t->StartTime);

	OutRpcTraffic(p, &t->Traffic);

	OutRpcMemInfo(p, &t->MemInfo);
}

void InRpcListener(RPC_LISTENER *t, PACK *p)
{
	if (t == NULL || p == NULL)
	{
		return;
	}

	Zero(t, sizeof(RPC_LISTENER));
	t->Port = PackGetInt(p, "Port");
	t->Enable = PackGetBool(p, "Enable");
}
void OutRpcListener(PACK *p, RPC_LISTENER *t)
{
	if (t == NULL || p == NULL)
	{
		return;
	}

	PackAddInt(p, "Port", t->Port);
	PackAddBool(p, "Enable", t->Enable);
}

void InRpcListenerList(RPC_LISTENER_LIST *t, PACK *p)
{
	UINT i;
	if (t == NULL || p == NULL)
	{
		return;
	}

	Zero(t, sizeof(RPC_LISTENER_LIST));
	t->NumPort = PackGetIndexCount(p, "Ports");
	t->Ports = ZeroMalloc(sizeof(UINT) * t->NumPort);
	t->Enables = ZeroMalloc(sizeof(UINT) * t->NumPort);
	t->Errors = ZeroMalloc(sizeof(UINT) * t->NumPort);
	for (i = 0;i < t->NumPort;i++)
	{
		t->Ports[i] = PackGetIntEx(p, "Ports", i);
		t->Enables[i] = PackGetBoolEx(p, "Enables", i);
		t->Errors[i] = PackGetBoolEx(p, "Errors", i);
	}
}
void OutRpcListenerList(PACK *p, RPC_LISTENER_LIST *t)
{
	UINT i;
	if (t == NULL || p == NULL)
	{
		return;
	}

	for (i = 0;i < t->NumPort;i++)
	{
		PackAddIntEx(p, "Ports", t->Ports[i], i, t->NumPort);
		PackAddBoolEx(p, "Enables", t->Enables[i], i, t->NumPort);
		PackAddBoolEx(p, "Errors", t->Errors[i], i, t->NumPort);
	}
}
void FreeRpcListenerList(RPC_LISTENER_LIST *t)
{
	if (t == NULL)
	{
		return;
	}

	Free(t->Ports);
	Free(t->Enables);
	Free(t->Errors);
}

void InRpcStr(RPC_STR *t, PACK *p)
{
	UINT size = 65536;
	char *tmp = Malloc(size);
	if (t == NULL || p == NULL)
	{
		return;
	}

	Zero(t, sizeof(RPC_STR));
	if (PackGetStr(p, "String", tmp, size) == false)
	{
		t->String = CopyStr("");
	}
	else
	{
		t->String = CopyStr(tmp);
	}
	Free(tmp);
}
void OutRpcStr(PACK *p, RPC_STR *t)
{
	if (t == NULL || p == NULL)
	{
		return;
	}

	PackAddStr(p, "String", t->String);
}
void FreeRpcStr(RPC_STR *t)
{
	if (t == NULL )
	{
		return;
	}

	Free(t->String);
}

void InRpcSetPassword(RPC_SET_PASSWORD *t, PACK *p)
{
	if (t == NULL || p == NULL)
	{
		return;
	}

	Zero(t, sizeof(RPC_SET_PASSWORD));
	PackGetData2(p, "HashedPassword", t->HashedPassword, sizeof(t->HashedPassword));
	PackGetStr(p, "PlainTextPassword", t->PlainTextPassword, sizeof(t->PlainTextPassword));
}
void OutRpcSetPassword(PACK *p, RPC_SET_PASSWORD *t)
{
	if (t == NULL || p == NULL)
	{
		return;
	}

	PackAddData(p, "HashedPassword", t->HashedPassword, sizeof(t->HashedPassword));
	PackAddStr(p, "PlainTextPassword", t->PlainTextPassword);
}

void InRpcHubOption(RPC_HUB_OPTION *t, PACK *p)
{
	if (t == NULL || p == NULL)
	{
		return;
	}

	Zero(t, sizeof(RPC_HUB_OPTION));
	t->MaxSession = PackGetInt(p, "MaxSession");
	t->NoEnum = PackGetBool(p, "NoEnum");
}
void OutRpcHubOption(PACK *p, RPC_HUB_OPTION *t)
{
	if (t == NULL || p == NULL)
	{
		return;
	}

	PackAddInt(p, "MaxSession", t->MaxSession);
	PackAddBool(p, "NoEnum", t->NoEnum);
}

void InRpcCreateHub(RPC_CREATE_HUB *t, PACK *p)
{
	if (t == NULL || p == NULL)
	{
		return;
	}

	Zero(t, sizeof(RPC_CREATE_HUB));
	PackGetStr(p, "HubName", t->HubName, sizeof(t->HubName));
	PackGetData2(p, "HashedPassword", t->HashedPassword, sizeof(t->HashedPassword));
	PackGetData2(p, "SecurePassword", t->SecurePassword, sizeof(t->SecurePassword));
	PackGetStr(p, "AdminPasswordPlainText", t->AdminPasswordPlainText, sizeof(t->AdminPasswordPlainText));
	t->Online = PackGetBool(p, "Online");
	InRpcHubOption(&t->HubOption, p);
}
void OutRpcCreateHub(PACK *p, RPC_CREATE_HUB *t)
{
	if (t == NULL || p == NULL)
	{
		return;
	}

	PackAddStr(p, "HubName", t->HubName);
	PackAddData(p, "HashedPassword", t->HashedPassword, sizeof(t->HashedPassword));
	PackAddData(p, "SecurePassword", t->SecurePassword, sizeof(t->SecurePassword));
	PackAddBool(p, "Online", t->Online);
	PackAddStr(p, "AdminPasswordPlainText", t->AdminPasswordPlainText);
	OutRpcHubOption(p, &t->HubOption);
}

void InRpcEnumHub(RPC_ENUM_HUB *t, PACK *p)
{
	UINT i;
	if (t == NULL || p == NULL)
	{
		return;
	}

	Zero(t, sizeof(RPC_ENUM_HUB));
	t->NumHub = PackGetIndexCount(p, "HubName");
	t->Hubs = ZeroMalloc(sizeof(RPC_ENUM_HUB_ITEM) * t->NumHub);

	for (i = 0;i < t->NumHub;i++)
	{
		RPC_ENUM_HUB_ITEM *e = &t->Hubs[i];

		PackGetStrEx(p, "HubName", e->HubName, sizeof(e->HubName), i);
		e->Online = PackGetBoolEx(p, "Online", i);
		e->NumSessions = PackGetIntEx(p, "NumSessions", i);
		e->NumUsers = PackGetIntEx(p, "NumUsers", i);
		e->NumGroups = PackGetIntEx(p, "NumGroups", i);
		e->NumMacTables = PackGetIntEx(p, "NumMacTables", i);
		e->NumIpTables = PackGetIntEx(p, "NumIpTables", i);
		e->LastCommTime = PackGetInt64Ex(p, "LastCommTime", i);
		e->CreatedTime = PackGetInt64Ex(p, "CreatedTime", i);
		e->LastLoginTime = PackGetInt64Ex(p, "LastLoginTime", i);
		e->NumLogin = PackGetIntEx(p, "NumLogin", i);
		e->IsTrafficFilled = PackGetBoolEx(p, "IsTrafficFilled", i);

		InRpcTrafficEx(&e->Traffic, p, i);
	}
}
void OutRpcEnumHub(PACK *p, RPC_ENUM_HUB *t)
{
	UINT i;
	if (t == NULL || p == NULL)
	{
		return;
	}

	for (i = 0;i < t->NumHub;i++)
	{
		RPC_ENUM_HUB_ITEM *e = &t->Hubs[i];

		PackAddStrEx(p, "HubName", e->HubName, i, t->NumHub);
		PackAddBoolEx(p, "Online", e->Online, i, t->NumHub);
		PackAddIntEx(p, "NumSessions", e->NumSessions, i, t->NumHub);
		PackAddIntEx(p, "NumUsers", e->NumUsers, i, t->NumHub);
		PackAddIntEx(p, "NumGroups", e->NumGroups, i, t->NumHub);
		PackAddIntEx(p, "NumMacTables", e->NumMacTables, i, t->NumHub);
		PackAddIntEx(p, "NumIpTables", e->NumIpTables, i, t->NumHub);
		PackAddInt64Ex(p, "LastCommTime", e->LastCommTime, i, t->NumHub);
		PackAddInt64Ex(p, "CreatedTime", e->CreatedTime, i, t->NumHub);
		PackAddInt64Ex(p, "LastLoginTime", e->LastLoginTime, i, t->NumHub);
		PackAddIntEx(p, "NumLogin", e->NumLogin, i, t->NumHub);
		PackAddBoolEx(p, "IsTrafficFilled", e->IsTrafficFilled, i, t->NumHub);

		OutRpcTrafficEx(&e->Traffic, p, i, t->NumHub);
	}
}
void FreeRpcEnumHub(RPC_ENUM_HUB *t)
{
	if (t == NULL)
	{
		return;
	}

	Free(t->Hubs);
}

void InRpcDeleteHub(RPC_DELETE_HUB *t, PACK *p)
{
	if (t == NULL || p == NULL)
	{
		return;
	}

	Zero(t, sizeof(RPC_DELETE_HUB));
	PackGetStr(p, "HubName", t->HubName, sizeof(t->HubName));
}
void OutRpcDeleteHub(PACK *p, RPC_DELETE_HUB *t)
{
	if (t == NULL || p == NULL)
	{
		return;
	}

	PackAddStr(p, "HubName", t->HubName);
}

void InRpcEnumConnection(RPC_ENUM_CONNECTION *t, PACK *p)
{
	UINT i;
	if (t == NULL || p == NULL)
	{
		return;
	}

	Zero(t, sizeof(RPC_ENUM_CONNECTION));
	t->NumConnection = PackGetIndexCount(p, "Name");
	t->Connections = ZeroMalloc(sizeof(RPC_ENUM_CONNECTION_ITEM) * t->NumConnection);

	for (i = 0;i < t->NumConnection;i++)
	{
		RPC_ENUM_CONNECTION_ITEM *e = &t->Connections[i];

		e->Ip = PackGetIp32Ex(p, "Ip", i);
		e->Port = PackGetIntEx(p, "Port", i);
		PackGetStrEx(p, "Name", e->Name, sizeof(e->Name), i);
		PackGetStrEx(p, "Hostname", e->Hostname, sizeof(e->Hostname), i);
		e->ConnectedTime = PackGetInt64Ex(p, "ConnectedTime", i);
		e->Type = PackGetIntEx(p, "Type", i);
	}
}
void OutRpcEnumConnection(PACK *p, RPC_ENUM_CONNECTION *t)
{
	UINT i;
	if (t == NULL || p == NULL)
	{
		return;
	}

	for (i = 0;i < t->NumConnection;i++)
	{
		RPC_ENUM_CONNECTION_ITEM *e = &t->Connections[i];

		PackAddIp32Ex(p, "Ip", e->Ip, i, t->NumConnection);
		PackAddIntEx(p, "Port", e->Port, i, t->NumConnection);
		PackAddStrEx(p, "Name", e->Name, i, t->NumConnection);
		PackAddStrEx(p, "Hostname", e->Hostname, i, t->NumConnection);
		PackAddInt64Ex(p, "ConnectedTime", e->ConnectedTime, i, t->NumConnection);
		PackAddIntEx(p, "Type", e->Type, i, t->NumConnection);
	}
}
void FreeRpcEnumConnection(RPC_ENUM_CONNECTION *t)
{
	if (t == NULL)
	{
		return;
	}

	Free(t->Connections);
}

void InRpcDisconnectConnection(RPC_DISCONNECT_CONNECTION *t, PACK *p)
{
	if (t == NULL || p == NULL)
	{
		return;
	}

	Zero(t, sizeof(RPC_DISCONNECT_CONNECTION));
	PackGetStr(p, "Name", t->Name, sizeof(t->Name));
}
void OutRpcDisconnectConnection(PACK *p, RPC_DISCONNECT_CONNECTION *t)
{
	if (t == NULL || p == NULL)
	{
		return;
	}

	PackAddStr(p, "Name", t->Name);
}

void InRpcConnectionInfo(RPC_CONNECTION_INFO *t, PACK *p)
{
	if (t == NULL || p == NULL)
	{
		return;
	}

	Zero(t, sizeof(RPC_CONNECTION_INFO));
	PackGetStr(p, "Name", t->Name, sizeof(t->Name));
	t->Ip = PackGetIp32(p, "Ip");
	t->Port = PackGetInt(p, "Port");
	t->ConnectedTime = PackGetInt64(p, "ConnectedTime");
	PackGetStr(p, "Hostname", t->Hostname, sizeof(t->Hostname));
	PackGetStr(p, "ServerStr", t->ServerStr, sizeof(t->ServerStr));
	PackGetStr(p, "ClientStr", t->ClientStr, sizeof(t->ClientStr));
	t->ServerVer = PackGetInt(p, "ServerVer");
	t->ServerBuild = PackGetInt(p, "ServerBuild");
	t->ClientVer = PackGetInt(p, "ClientVer");
	t->ClientBuild = PackGetInt(p, "ClientBuild");
	t->Type = PackGetInt(p, "Type");
}
void OutRpcConnectionInfo(PACK *p, RPC_CONNECTION_INFO *t)
{
	if (t == NULL || p == NULL)
	{
		return;
	}

	PackAddStr(p, "Name", t->Name);
	PackAddIp32(p, "Ip", t->Ip);
	PackAddInt(p, "Port", t->Port);
	PackAddInt64(p, "ConnectedTime", t->ConnectedTime);
	PackAddStr(p, "Hostname", t->Hostname);
	PackAddStr(p, "ServerStr", t->ServerStr);
	PackAddStr(p, "ClientStr", t->ClientStr);
	PackAddInt(p, "ServerVer", t->ServerVer);
	PackAddInt(p, "ServerBuild", t->ServerBuild);
	PackAddInt(p, "ClientVer", t->ClientVer);
	PackAddInt(p, "ClientBuild", t->ClientBuild);
	PackAddInt(p, "Type", t->Type);
}

void InRpcSetHubOnline(RPC_SET_HUB_ONLINE *t, PACK *p)
{
	if (t == NULL || p == NULL)
	{
		return;
	}

	Zero(t, sizeof(RPC_SET_HUB_ONLINE));
	PackGetStr(p, "HubName", t->HubName, sizeof(t->HubName));
	t->Online = PackGetBool(p, "Online");
}
void OutRpcSetHubOnline(PACK *p, RPC_SET_HUB_ONLINE *t)
{
	if (t == NULL || p == NULL)
	{
		return;
	}

	PackAddStr(p, "HubName", t->HubName);
	PackAddBool(p, "Online", t->Online);
}

void InRpcHubStatus(RPC_HUB_STATUS *t, PACK *p)
{
	Zero(t, sizeof(RPC_HUB_STATUS));
	if (t == NULL || p == NULL)
	{
		return;
	}

	PackGetStr(p, "HubName", t->HubName, sizeof(t->HubName));
	t->Online = PackGetBool(p, "Online");
	t->NumSessions = PackGetInt(p, "NumSessions");
	t->NumSessionsClient = PackGetInt(p, "NumSessionsClient");
	t->NumSessionsBridge = PackGetInt(p, "NumSessionsBridge");
	t->NumAccessLists = PackGetInt(p, "NumAccessLists");
	t->NumUsers = PackGetInt(p, "NumUsers");
	t->NumGroups = PackGetInt(p, "NumGroups");
	t->NumMacTables = PackGetInt(p, "NumMacTables");
	t->NumIpTables = PackGetInt(p, "NumIpTables");
	InRpcTraffic(&t->Traffic, p);
	t->LastCommTime = PackGetInt64(p, "LastCommTime");
	t->CreatedTime = PackGetInt64(p, "CreatedTime");
	t->LastLoginTime = PackGetInt64(p, "LastLoginTime");
	t->NumLogin = PackGetInt(p, "NumLogin");
}
void OutRpcHubStatus(PACK *p, RPC_HUB_STATUS *t)
{
	if (t == NULL || p == NULL)
	{
		return;
	}

	PackAddStr(p, "HubName", t->HubName);
	PackAddBool(p, "Online", t->Online);
	PackAddInt(p, "NumSessions", t->NumSessions);
	PackAddInt(p, "NumSessionsClient", t->NumSessionsClient);
	PackAddInt(p, "NumSessionsBridge", t->NumSessionsBridge);
	PackAddInt(p, "NumAccessLists", t->NumAccessLists);
	PackAddInt(p, "NumUsers", t->NumUsers);
	PackAddInt(p, "NumGroups", t->NumGroups);
	PackAddInt(p, "NumMacTables", t->NumMacTables);
	PackAddInt(p, "NumIpTables", t->NumIpTables);
	OutRpcTraffic(p, &t->Traffic);
	PackAddInt64(p, "LastCommTime", t->LastCommTime);
	PackAddInt64(p, "CreatedTime", t->CreatedTime);
	PackAddInt64(p, "LastLoginTime", t->LastLoginTime);
	PackAddInt(p, "NumLogin", t->NumLogin);
}

void InRpcHubLog(RPC_HUB_LOG *t, PACK *p)
{
	UINT i;
	if (t == NULL || p == NULL)
	{
		return;
	}

	Zero(t, sizeof(RPC_HUB_LOG));
	PackGetStr(p, "HubName", t->HubName, sizeof(t->HubName));
	t->LogSetting.SaveSecurityLog = PackGetBool(p, "SaveSecurityLog");
	t->LogSetting.SecurityLogSwitchType = PackGetInt(p, "SecurityLogSwitchType");
	t->LogSetting.SavePacketLog = PackGetBool(p, "SavePacketLog");
	t->LogSetting.PacketLogSwitchType = PackGetInt(p, "PacketLogSwitchType");
	for (i = 0;i < NUM_PACKET_LOG;i++)
	{
		t->LogSetting.PacketLogConfig[i] = PackGetIntEx(p, "PacketLogConfig", i);
	}
}
void OutRpcHubLog(PACK *p, RPC_HUB_LOG *t)
{
	UINT i;
	if (t == NULL || p == NULL)
	{
		return;
	}

	PackAddStr(p, "HubName", t->HubName);
	PackAddBool(p, "SaveSecurityLog", t->LogSetting.SaveSecurityLog);
	PackAddInt(p, "SecurityLogSwitchType", t->LogSetting.SecurityLogSwitchType);
	PackAddBool(p, "SavePacketLog", t->LogSetting.SavePacketLog);
	PackAddInt(p, "PacketLogSwitchType", t->LogSetting.PacketLogSwitchType);
	for (i = 0;i < NUM_PACKET_LOG;i++)
	{
		PackAddIntEx(p, "PacketLogConfig", t->LogSetting.PacketLogConfig[i], i, NUM_PACKET_LOG);
	}
}

void InRpcHubAddCa(RPC_HUB_ADD_CA *t, PACK *p)
{
	if (t == NULL || p == NULL)
	{
		return;
	}

	Zero(t, sizeof(RPC_HUB_ADD_CA));
	PackGetStr(p, "HubName", t->HubName, sizeof(t->HubName));
	t->Cert = PackGetX(p, "Cert");
}
void OutRpcHubAddCa(PACK *p, RPC_HUB_ADD_CA *t)
{
	if (t == NULL || p == NULL)
	{
		return;
	}

	PackAddStr(p, "HubName", t->HubName);
	PackAddX(p, "Cert", t->Cert);
}
void FreeRpcHubAddCa(RPC_HUB_ADD_CA *t)
{
	if (t == NULL)
	{
		return;
	}

	FreeX(t->Cert);
}

void InRpcHubEnumCa(RPC_HUB_ENUM_CA *t, PACK *p)
{
	UINT i;
	if (t == NULL || p == NULL)
	{
		return;
	}

	Zero(t, sizeof(RPC_HUB_ENUM_CA));
	PackGetStr(p, "HubName", t->HubName, sizeof(t->HubName));
	t->NumCa = PackGetIndexCount(p, "Key");
	t->Ca = ZeroMalloc(sizeof(RPC_HUB_ENUM_CA_ITEM) * t->NumCa);

	for (i = 0;i < t->NumCa;i++)
	{
		RPC_HUB_ENUM_CA_ITEM *e = &t->Ca[i];

		e->Key = PackGetIntEx(p, "Key", i);
		PackGetUniStrEx(p, "SubjectName", e->SubjectName, sizeof(e->SubjectName), i);
		PackGetUniStrEx(p, "IssuerName", e->IssuerName, sizeof(e->IssuerName), i);
		e->Expires = PackGetInt64Ex(p, "Expires", i);
	}
}
void OutRpcHubEnumCa(PACK *p, RPC_HUB_ENUM_CA *t)
{
	UINT i;
	if (t == NULL || p == NULL)
	{
		return;
	}
	PackAddStr(p, "HubName", t->HubName);

	for (i = 0;i < t->NumCa;i++)
	{
		RPC_HUB_ENUM_CA_ITEM *e = &t->Ca[i];

		PackAddIntEx(p, "Key", e->Key, i, t->NumCa);
		PackAddUniStrEx(p, "SubjectName", e->SubjectName, i, t->NumCa);
		PackAddUniStrEx(p, "IssuerName", e->IssuerName, i, t->NumCa);
		PackAddInt64Ex(p, "Expires", e->Expires, i, t->NumCa);
	}
}
void FreeRpcHubEnumCa(RPC_HUB_ENUM_CA *t)
{
	if (t == NULL)
	{
		return;
	}

	Free(t->Ca);
}

void InRpcHubGetCa(RPC_HUB_GET_CA *t, PACK *p)
{
	if (t == NULL || p == NULL)
	{
		return;
	}

	Zero(t, sizeof(RPC_HUB_GET_CA));
	PackGetStr(p, "HubName", t->HubName, sizeof(t->HubName));
	t->Key = PackGetInt(p, "Key");
	t->Cert = PackGetX(p, "Cert");
}
void OutRpcHubGetCa(PACK *p, RPC_HUB_GET_CA *t)
{
	if (t == NULL || p == NULL)
	{
		return;
	}

	PackAddStr(p, "HubName", t->HubName);
	PackAddInt(p, "Key", t->Key);
	PackAddX(p, "Cert", t->Cert);
}
void FreeRpcHubGetCa(RPC_HUB_GET_CA *t)
{
	if (t == NULL)
	{
		return;
	}

	FreeX(t->Cert);
}

void InRpcHubDeleteCa(RPC_HUB_DELETE_CA *t, PACK *p)
{
	if (t == NULL || p == NULL)
	{
		return;
	}

	Zero(t, sizeof(RPC_HUB_DELETE_CA));
	PackGetStr(p, "HubName", t->HubName, sizeof(t->HubName));
	t->Key = PackGetInt(p, "Key");
}
void OutRpcHubDeleteCa(PACK *p, RPC_HUB_DELETE_CA *t)
{
	if (t == NULL || p == NULL)
	{
		return;
	}

	PackAddStr(p, "HubName", t->HubName);
	PackAddInt(p, "Key", t->Key);
}

void InRpcCreateLink(RPC_CREATE_LINK *t, PACK *p)
{
	BUF *b;
	if (t == NULL || p == NULL)
	{
		return;
	}

	Zero(t, sizeof(RPC_CREATE_LINK));
	PackGetStr(p, "HubName_Ex", t->HubName, sizeof(t->HubName));
	t->Online = PackGetBool(p, "Online");
	t->ClientOption = ZeroMalloc(sizeof(CLIENT_OPTION));
	InRpcClientOption(t->ClientOption, p);
	t->ClientAuth  = ZeroMalloc(sizeof(CLIENT_AUTH));
	InRpcClientAuth(t->ClientAuth, p);
	InRpcPolicy(&t->Policy, p);

	t->CheckServerCert = PackGetBool(p, "CheckServerCert");
	t->AddDefaultCA = PackGetBool(p, "AddDefaultCA");
	b = PackGetBuf(p, "ServerCert");
	if (b != NULL)
	{
		t->ServerCert = BufToX(b, false);
		FreeBuf(b);
	}
}
void OutRpcCreateLink(PACK *p, RPC_CREATE_LINK *t)
{
	if (t == NULL || p == NULL)
	{
		return;
	}

	PackAddStr(p, "HubName_Ex",t->HubName);
	PackAddBool(p, "Online", t->Online);
	OutRpcClientOption(p, t->ClientOption);
	OutRpcClientAuth(p, t->ClientAuth);
	OutRpcPolicy(p, &t->Policy);

	PackAddBool(p, "CheckServerCert", t->CheckServerCert);
	PackAddBool(p, "AddDefaultCA", t->AddDefaultCA);
	if (t->ServerCert != NULL)
	{
		BUF *b;
		b = XToBuf(t->ServerCert, false);
		PackAddBuf(p, "ServerCert", b);
		FreeBuf(b);
	}
}
void FreeRpcCreateLink(RPC_CREATE_LINK *t)
{
	if (t == NULL)
	{
		return;
	}

	if (t->ServerCert != NULL)
	{
		FreeX(t->ServerCert);
	}
	Free(t->ClientOption);
	CiFreeClientAuth(t->ClientAuth);
}

void InRpcEnumLink(RPC_ENUM_LINK *t, PACK *p)
{
	UINT i;
	if (t == NULL || p == NULL)
	{
		return;
	}

	Zero(t, sizeof(RPC_ENUM_LINK));
	PackGetStr(p, "HubName", t->HubName, sizeof(t->HubName));
	t->NumLink = PackGetIndexCount(p, "AccountName");
	t->Links = ZeroMalloc(sizeof(RPC_ENUM_LINK_ITEM) * t->NumLink);

	for (i = 0;i < t->NumLink;i++)
	{
		RPC_ENUM_LINK_ITEM *e = &t->Links[i];

		PackGetUniStrEx(p, "AccountName", e->AccountName, sizeof(e->AccountName), i);
		PackGetStrEx(p, "Hostname", e->Hostname, sizeof(e->Hostname), i);
		if (PackGetStrEx(p, "ConnectedHubName", e->HubName, sizeof(e->HubName), i) == false)
		{
			PackGetStrEx(p, "TargetHubName", e->HubName, sizeof(e->HubName), i);
		}
		e->Online = PackGetBoolEx(p, "Online", i);
		e->ConnectedTime = PackGetInt64Ex(p, "ConnectedTime", i);
		e->Connected = PackGetBoolEx(p, "Connected", i);
		e->LastError = PackGetIntEx(p, "LastError", i);
	}
}
void OutRpcEnumLink(PACK *p, RPC_ENUM_LINK *t)
{
	UINT i;
	if (t == NULL || p == NULL)
	{
		return;
	}

	PackAddStr(p, "HubName", t->HubName);

	for (i = 0;i < t->NumLink;i++)
	{
		RPC_ENUM_LINK_ITEM *e = &t->Links[i];

		PackAddUniStrEx(p, "AccountName", e->AccountName, i, t->NumLink);
		PackAddStrEx(p, "ConnectedHubName", e->HubName, i, t->NumLink);
		PackAddStrEx(p, "Hostname", e->Hostname, i, t->NumLink);
		PackAddBoolEx(p, "Online", e->Online, i, t->NumLink);
		PackAddInt64Ex(p, "ConnectedTime", e->ConnectedTime, i, t->NumLink);
		PackAddBoolEx(p, "Connected", e->Connected, i, t->NumLink);
		PackAddIntEx(p, "LastError", e->LastError, i, t->NumLink);
		PackAddStrEx(p, "TargetHubName", e->HubName, i, t->NumLink);
	}
}
void FreeRpcEnumLink(RPC_ENUM_LINK *t)
{
	if (t == NULL)
	{
		return;
	}

	Free(t->Links);
}

void InRpcLinkStatus(RPC_LINK_STATUS *t, PACK *p)
{
	if (t == NULL || p == NULL)
	{
		return;
	}

	Zero(t, sizeof(RPC_LINK_STATUS));
	PackGetStr(p, "HubName_Ex", t->HubName, sizeof(t->HubName));
	PackGetUniStr(p, "AccountName", t->AccountName, sizeof(t->AccountName));
	InRpcClientGetConnectionStatus(&t->Status, p);
}
void OutRpcLinkStatus(PACK *p, RPC_LINK_STATUS *t)
{
	if (t == NULL || p == NULL)
	{
		return;
	}

	PackAddStr(p, "HubName_Ex", t->HubName);
	PackAddUniStr(p, "AccountName", t->AccountName);
	OutRpcClientGetConnectionStatus(p, &t->Status);
}
void FreeRpcLinkStatus(RPC_LINK_STATUS *t)
{
	if (t == NULL)
	{
		return;
	}

	CiFreeClientGetConnectionStatus(&t->Status);
}

void InRpcLink(RPC_LINK *t, PACK *p)
{
	if (t == NULL || p == NULL)
	{
		return;
	}

	Zero(t, sizeof(RPC_LINK));
	PackGetStr(p, "HubName", t->HubName, sizeof(t->HubName));
	PackGetUniStr(p, "AccountName", t->AccountName, sizeof(t->AccountName));
}
void OutRpcLink(PACK *p, RPC_LINK *t)
{
	if (t == NULL)
	{
		return;
	}

	PackAddStr(p, "HubName", t->HubName);
	PackAddUniStr(p, "AccountName", t->AccountName);
}

void InRpcRenameLink(RPC_RENAME_LINK *t, PACK *p)
{
	if (t == NULL || p == NULL)
	{
		return;
	}

	Zero(t, sizeof(RPC_RENAME_LINK));
	PackGetStr(p, "HubName", t->HubName, sizeof(t->HubName));
	PackGetUniStr(p, "OldAccountName", t->OldAccountName, sizeof(t->OldAccountName));
	PackGetUniStr(p, "NewAccountName", t->NewAccountName, sizeof(t->NewAccountName));
}
void OutRpcRenameLink(PACK *p, RPC_RENAME_LINK *t)
{
	if (p == NULL || t == NULL)
	{
		return;
	}

	PackAddStr(p, "HubName", t->HubName);
	PackAddUniStr(p, "OldAccountName", t->OldAccountName);
	PackAddUniStr(p, "NewAccountName", t->NewAccountName);
}

void InRpcAccessEx(ACCESS *a, PACK *p, UINT index)
{
	if (a == NULL || p == NULL)
	{
		return;
	}

	Zero(a, sizeof(ACCESS));
	a->Id = PackGetIntEx(p, "Id", index);
	PackGetUniStrEx(p, "Note", a->Note, sizeof(a->Note), index);
	a->Active = PackGetBoolEx(p, "Active", index);
	a->Priority = PackGetIntEx(p, "Priority", index);
	a->Discard = PackGetBoolEx(p, "Discard", index);
	a->SrcIpAddress = PackGetIp32Ex(p, "SrcIpAddress", index);
	a->SrcSubnetMask = PackGetIp32Ex(p, "SrcSubnetMask", index);
	a->DestIpAddress = PackGetIp32Ex(p, "DestIpAddress", index);
	a->DestSubnetMask = PackGetIp32Ex(p, "DestSubnetMask", index);
	a->Protocol = PackGetIntEx(p, "Protocol", index);
	a->SrcPortStart = PackGetIntEx(p, "SrcPortStart", index);
	a->SrcPortEnd = PackGetIntEx(p, "SrcPortEnd", index);
	a->DestPortStart = PackGetIntEx(p, "DestPortStart", index);
	a->DestPortEnd = PackGetIntEx(p, "DestPortEnd", index);
	PackGetStrEx(p, "SrcUsername", a->SrcUsername, sizeof(a->SrcUsername), index);
	PackGetStrEx(p, "DestUsername", a->DestUsername, sizeof(a->DestUsername), index);
	a->CheckSrcMac = PackGetBoolEx(p, "CheckSrcMac", index);
	PackGetDataEx2(p, "SrcMacAddress", a->SrcMacAddress, sizeof(a->SrcMacAddress), index);
	PackGetDataEx2(p, "SrcMacMask", a->SrcMacMask, sizeof(a->SrcMacMask), index);
	a->CheckDstMac = PackGetBoolEx(p, "CheckDstMac", index);
	PackGetDataEx2(p, "DstMacAddress", a->DstMacAddress, sizeof(a->DstMacAddress), index);
	PackGetDataEx2(p, "DstMacMask", a->DstMacMask, sizeof(a->DstMacMask), index);
	a->CheckTcpState = PackGetBoolEx(p, "CheckTcpState", index);
	a->Established = PackGetBoolEx(p, "Established", index);
	a->Delay = PackGetIntEx(p, "Delay", index);
	a->Jitter = PackGetIntEx(p, "Jitter", index);
	a->Loss = PackGetIntEx(p, "Loss", index);
	a->IsIPv6 = PackGetBoolEx(p, "IsIPv6", index);
	a->UniqueId = PackGetIntEx(p, "UniqueId", index);
	PackGetStrEx(p, "RedirectUrl", a->RedirectUrl, sizeof(a->RedirectUrl), index);
	if (a->IsIPv6)
	{
		PackGetIp6AddrEx(p, "SrcIpAddress6", &a->SrcIpAddress6, index);
		PackGetIp6AddrEx(p, "SrcSubnetMask6", &a->SrcSubnetMask6, index);
		PackGetIp6AddrEx(p, "DestIpAddress6", &a->DestIpAddress6, index);
		PackGetIp6AddrEx(p, "DestSubnetMask6", &a->DestSubnetMask6, index);
	}
}
void InRpcAccess(ACCESS *a, PACK *p)
{
	if (a == NULL || p == NULL)
	{
		return;
	}

	InRpcAccessEx(a, p, 0);
}
void OutRpcAccessEx(PACK *p, ACCESS *a, UINT index, UINT total)
{
	if (a == NULL || p == NULL)
	{
		return;
	}

	PackAddIntEx(p, "Id", a->Id, index, total);
	PackAddUniStrEx(p, "Note", a->Note, index, total);
	PackAddBoolEx(p, "Active", a->Active, index, total);
	PackAddIntEx(p, "Priority", a->Priority, index, total);
	PackAddBoolEx(p, "Discard", a->Discard, index, total);
	if (a->IsIPv6)
	{
		PackAddIp32Ex(p, "SrcIpAddress", 0xFDFFFFDF, index, total);
		PackAddIp32Ex(p, "SrcSubnetMask", 0xFFFFFFFF, index, total);
		PackAddIp32Ex(p, "DestIpAddress", 0xFDFFFFDF, index, total);
		PackAddIp32Ex(p, "DestSubnetMask", 0xFFFFFFFF, index, total);
	}
	else
	{
		PackAddIp32Ex(p, "SrcIpAddress", a->SrcIpAddress, index, total);
		PackAddIp32Ex(p, "SrcSubnetMask", a->SrcSubnetMask, index, total);
		PackAddIp32Ex(p, "DestIpAddress", a->DestIpAddress, index, total);
		PackAddIp32Ex(p, "DestSubnetMask", a->DestSubnetMask, index, total);
	}
	PackAddIntEx(p, "Protocol", a->Protocol, index, total);
	PackAddIntEx(p, "SrcPortStart", a->SrcPortStart, index, total);
	PackAddIntEx(p, "SrcPortEnd", a->SrcPortEnd, index, total);
	PackAddIntEx(p, "DestPortStart", a->DestPortStart, index, total);
	PackAddIntEx(p, "DestPortEnd", a->DestPortEnd, index, total);
	PackAddStrEx(p, "SrcUsername", a->SrcUsername, index, total);
	PackAddStrEx(p, "DestUsername", a->DestUsername, index, total);
	PackAddBoolEx(p, "CheckSrcMac", a->CheckSrcMac, index, total);
	PackAddDataEx(p, "SrcMacAddress", a->SrcMacAddress, sizeof(a->SrcMacAddress), index, total);
	PackAddDataEx(p, "SrcMacMask", a->SrcMacMask, sizeof(a->SrcMacMask), index, total);
	PackAddBoolEx(p, "CheckDstMac", a->CheckDstMac, index, total);
	PackAddDataEx(p, "DstMacAddress", a->DstMacAddress, sizeof(a->DstMacAddress), index, total);
	PackAddDataEx(p, "DstMacMask", a->DstMacMask, sizeof(a->DstMacMask), index, total);
	PackAddBoolEx(p, "CheckTcpState", a->CheckTcpState, index, total);
	PackAddBoolEx(p, "Established", a->Established, index, total);
	PackAddIntEx(p, "Delay", a->Delay, index, total);
	PackAddIntEx(p, "Jitter", a->Jitter, index, total);
	PackAddIntEx(p, "Loss", a->Loss, index, total);
	PackAddBoolEx(p, "IsIPv6", a->IsIPv6, index, total);
	PackAddIntEx(p, "UniqueId", a->UniqueId, index, total);
	PackAddStrEx(p, "RedirectUrl", a->RedirectUrl, index, total);
	if (a->IsIPv6)
	{
		PackAddIp6AddrEx(p, "SrcIpAddress6", &a->SrcIpAddress6, index, total);
		PackAddIp6AddrEx(p, "SrcSubnetMask6", &a->SrcSubnetMask6, index, total);
		PackAddIp6AddrEx(p, "DestIpAddress6", &a->DestIpAddress6, index, total);
		PackAddIp6AddrEx(p, "DestSubnetMask6", &a->DestSubnetMask6, index, total);
	}
	else
	{
		IPV6_ADDR zero;

		Zero(&zero, sizeof(zero));

		PackAddIp6AddrEx(p, "SrcIpAddress6", &zero, index, total);
		PackAddIp6AddrEx(p, "SrcSubnetMask6", &zero, index, total);
		PackAddIp6AddrEx(p, "DestIpAddress6", &zero, index, total);
		PackAddIp6AddrEx(p, "DestSubnetMask6", &zero, index, total);
	}
}
void OutRpcAccess(PACK *p, ACCESS *a)
{
	if (a == NULL || p == NULL)
	{
		return;
	}

	OutRpcAccessEx(p, a, 0, 1);
}

void InRpcEnumAccessList(RPC_ENUM_ACCESS_LIST *a, PACK *p)
{
	UINT i;
	if (a == NULL || p == NULL)
	{
		return;
	}

	Zero(a, sizeof(RPC_ENUM_ACCESS_LIST));
	PackGetStr(p, "HubName", a->HubName, sizeof(a->HubName));
	a->NumAccess = PackGetIndexCount(p, "Protocol");
	a->Accesses = ZeroMalloc(sizeof(ACCESS) * a->NumAccess);

	for (i = 0;i < a->NumAccess;i++)
	{
		ACCESS *e = &a->Accesses[i];

		InRpcAccessEx(e, p, i);
	}
}
void OutRpcEnumAccessList(PACK *p, RPC_ENUM_ACCESS_LIST *a)
{
	UINT i;
	if (a == NULL || p == NULL)
	{
		return;
	}
	PackAddStr(p, "HubName", a->HubName);

	for (i = 0;i < a->NumAccess;i++)
	{
		ACCESS *e = &a->Accesses[i];

		OutRpcAccessEx(p, e, i, a->NumAccess);
	}
}
void FreeRpcEnumAccessList(RPC_ENUM_ACCESS_LIST *a)
{
	if (a == NULL)
	{
		return;
	}

	Free(a->Accesses);
}

void *InRpcAuthData(PACK *p, UINT *authtype, char *username)
{
	wchar_t tmp[MAX_SIZE];
	AUTHPASSWORD *pw;
	AUTHUSERCERT *usercert;
	AUTHROOTCERT *rootcert;
	AUTHNT *nt;
	BUF *b;
	char plain_pw[MAX_SIZE];
	if (p == NULL)
	{
		return NULL;
	}
	if (authtype == NULL)
	{
		return NULL;
	}

	*authtype = PackGetInt(p, "AuthType");

	switch (*authtype)
	{
	case AUTHTYPE_PASSWORD:
		pw = ZeroMalloc(sizeof(AUTHPASSWORD));
		PackGetData2(p, "HashedKey", pw->HashedKey, sizeof(pw->HashedKey));
		PackGetData2(p, "NtLmSecureHash", pw->NtLmSecureHash, sizeof(pw->NtLmSecureHash));

		if (PackGetStr(p, "Auth_Password", plain_pw, sizeof(plain_pw)))
		{
			if (IsZero(pw->HashedKey, sizeof(pw->HashedKey)))
			{
				HashPassword(pw->HashedKey, username, plain_pw);
				GenerateNtPasswordHash(pw->NtLmSecureHash, plain_pw);
			}
		}
		return pw;

	case AUTHTYPE_USERCERT:
		usercert = ZeroMalloc(sizeof(AUTHUSERCERT));
		usercert->UserX = PackGetX(p, "UserX");
		return usercert;

	case AUTHTYPE_ROOTCERT:
		rootcert = ZeroMalloc(sizeof(AUTHROOTCERT));
		b = PackGetBuf(p, "Serial");
		if (b != NULL)
		{
			rootcert->Serial = NewXSerial(b->Buf, b->Size);
			FreeBuf(b);
		}
		if (PackGetUniStr(p, "CommonName", tmp, sizeof(tmp)))
		{
			rootcert->CommonName = CopyUniStr(tmp);
		}
		return rootcert;

	case AUTHTYPE_NT:
		nt = ZeroMalloc(sizeof(AUTHNT));
		if (PackGetUniStr(p, "NtUsername", tmp, sizeof(tmp)))
		{
			nt->NtUsername = CopyUniStr(tmp);
		}
		else
		{
			nt->NtUsername = CopyUniStr(L"");
		}
		return nt;
	}

	return NULL;
}
void OutRpcAuthData(PACK *p, void *authdata, UINT authtype)
{
	AUTHPASSWORD *pw = authdata;
	AUTHUSERCERT *usercert = authdata;
	AUTHROOTCERT *rootcert = authdata;
	AUTHNT *nt = authdata;
	if (p == NULL)
	{
		return;
	}

	PackAddInt(p, "AuthType", authtype);

	switch (authtype)
	{
	case AUTHTYPE_PASSWORD:
		PackAddData(p, "HashedKey", pw->HashedKey, sizeof(pw->HashedKey));
		PackAddData(p, "NtLmSecureHash", pw->NtLmSecureHash, sizeof(pw->NtLmSecureHash));
		break;

	case AUTHTYPE_USERCERT:
		PackAddX(p, "UserX", usercert->UserX);
		break;

	case AUTHTYPE_ROOTCERT:
		if (rootcert->Serial != NULL)
		{
			PackAddData(p, "Serial", rootcert->Serial->data, rootcert->Serial->size);
		}
		if (rootcert->CommonName != NULL)
		{
			PackAddUniStr(p, "CommonName", rootcert->CommonName);
		}
		break;

	case AUTHTYPE_NT:
		PackAddUniStr(p, "NtUsername", nt->NtUsername);
		break;
	}
}

void InRpcSetUser(RPC_SET_USER *t, PACK *p)
{
	if (t == NULL || p == NULL)
	{
		return;
	}

	Zero(t, sizeof(RPC_SET_USER));
	PackGetStr(p, "HubName", t->HubName, sizeof(t->HubName));
	PackGetStr(p, "Name", t->Name, sizeof(t->Name));
	PackGetStr(p, "GroupName", t->GroupName, sizeof(t->GroupName));
	PackGetUniStr(p, "Realname", t->Realname, sizeof(t->Realname));
	PackGetUniStr(p, "Note", t->Note, sizeof(t->Note));
	t->CreatedTime = PackGetInt64(p, "CreatedTime");
	t->UpdatedTime = PackGetInt64(p, "UpdatedTime");
	t->ExpireTime = PackGetInt64(p, "ExpireTime");
	t->AuthData = InRpcAuthData(p, &t->AuthType, t->Name);
	t->NumLogin = PackGetInt(p, "NumLogin");
	InRpcTraffic(&t->Traffic, p);

	if (PackGetBool(p, "UsePolicy"))
	{
		t->Policy = ZeroMalloc(sizeof(POLICY));
		InRpcPolicy(t->Policy, p);
	}
}

void OutRpcSetUser(PACK *p, RPC_SET_USER *t)
{
	if (t == NULL || p == NULL)
	{
		return;
	}

	PackAddStr(p, "HubName", t->HubName);
	PackAddStr(p, "Name", t->Name);
	PackAddStr(p, "GroupName", t->GroupName);
	PackAddUniStr(p, "Realname", t->Realname);
	PackAddUniStr(p, "Note", t->Note);
	PackAddInt64(p, "CreatedTime", t->CreatedTime);
	PackAddInt64(p, "UpdatedTime", t->UpdatedTime);
	PackAddInt64(p, "ExpireTime", t->ExpireTime);
	OutRpcAuthData(p, t->AuthData, t->AuthType);
	PackAddInt(p, "NumLogin", t->NumLogin);
	OutRpcTraffic(p, &t->Traffic);

	if (t->Policy != NULL)
	{
		PackAddBool(p, "UsePolicy", true);
		OutRpcPolicy(p, t->Policy);
	}
}
void FreeRpcSetUser(RPC_SET_USER *t)
{
	if (t == NULL)
	{
		return;
	}

	FreeAuthData(t->AuthType, t->AuthData);
	if (t->Policy)
	{
		Free(t->Policy);
	}
}

void InRpcEnumUser(RPC_ENUM_USER *t, PACK *p)
{
	UINT i;
	if (t == NULL || p == NULL)
	{
		return;
	}

	Zero(t, sizeof(RPC_ENUM_USER));
	PackGetStr(p, "HubName", t->HubName, sizeof(t->HubName));
	t->NumUser = PackGetIndexCount(p, "Name");
	t->Users = ZeroMalloc(sizeof(RPC_ENUM_USER_ITEM) * t->NumUser);

	for (i = 0;i < t->NumUser;i++)
	{
		RPC_ENUM_USER_ITEM *e = &t->Users[i];

		PackGetStrEx(p, "Name", e->Name, sizeof(e->Name), i);
		PackGetStrEx(p, "GroupName", e->GroupName, sizeof(e->GroupName), i);
		PackGetUniStrEx(p, "Realname", e->Realname, sizeof(e->Realname), i);
		PackGetUniStrEx(p, "Note", e->Note, sizeof(e->Note), i);
		e->AuthType = PackGetIntEx(p, "AuthType", i);
		e->LastLoginTime = PackGetInt64Ex(p, "LastLoginTime", i);
		e->NumLogin = PackGetIntEx(p, "NumLogin", i);

		e->IsTrafficFilled = PackGetBoolEx(p, "IsTrafficFilled", i);
		InRpcTrafficEx(&e->Traffic, p, i);

		e->IsExpiresFilled = PackGetBoolEx(p, "IsExpiresFilled", i);
		e->Expires = PackGetInt64Ex(p, "Expires", i);
	}
}
void OutRpcEnumUser(PACK *p, RPC_ENUM_USER *t)
{
	UINT i;
	if (t == NULL || p == NULL)
	{
		return;
	}
	PackAddStr(p, "HubName", t->HubName);

	for (i = 0;i < t->NumUser;i++)
	{
		RPC_ENUM_USER_ITEM *e = &t->Users[i];

		PackAddStrEx(p, "Name", e->Name, i, t->NumUser);
		PackAddStrEx(p, "GroupName", e->GroupName, i, t->NumUser);
		PackAddUniStrEx(p, "Realname", e->Realname, i, t->NumUser);
		PackAddUniStrEx(p, "Note", e->Note, i, t->NumUser);
		PackAddIntEx(p, "AuthType", e->AuthType, i, t->NumUser);
		PackAddInt64Ex(p, "LastLoginTime", e->LastLoginTime, i, t->NumUser);
		PackAddIntEx(p, "NumLogin", e->NumLogin, i, t->NumUser);
		PackAddBoolEx(p, "DenyAccess", e->DenyAccess, i, t->NumUser);

		PackAddBoolEx(p, "IsTrafficFilled", e->IsTrafficFilled, i, t->NumUser);
		OutRpcTrafficEx(&e->Traffic, p, i, t->NumUser);

		PackAddBoolEx(p, "IsExpiresFilled", e->IsExpiresFilled, i, t->NumUser);
		PackAddInt64Ex(p, "Expires", e->Expires, i, t->NumUser);
	}
}
void FreeRpcEnumUser(RPC_ENUM_USER *t)
{
	if (t == NULL)
	{
		return;
	}

	Free(t->Users);
}

void InRpcSetGroup(RPC_SET_GROUP *t, PACK *p)
{
	if (t == NULL || p == NULL)
	{
		return;
	}

	Zero(t, sizeof(RPC_SET_GROUP));
	PackGetStr(p, "HubName", t->HubName, sizeof(t->HubName));
	PackGetStr(p, "Name", t->Name, sizeof(t->Name));
	PackGetUniStr(p, "Realname", t->Realname, sizeof(t->Realname));
	PackGetUniStr(p, "Note", t->Note, sizeof(t->Note));
	InRpcTraffic(&t->Traffic, p);

	if (PackGetBool(p, "UsePolicy"))
	{
		t->Policy = ZeroMalloc(sizeof(POLICY));
		InRpcPolicy(t->Policy, p);
	}
}
void OutRpcSetGroup(PACK *p, RPC_SET_GROUP *t)
{
	if (t == NULL || p == NULL)
	{
		return;
	}

	PackAddStr(p, "HubName", t->HubName);
	PackAddStr(p, "Name", t->Name);
	PackAddUniStr(p, "Realname", t->Realname);
	PackAddUniStr(p, "Note", t->Note);
	OutRpcTraffic(p, &t->Traffic);

	if (t->Policy != NULL)
	{
		PackAddBool(p, "UsePolicy", true);
		OutRpcPolicy(p, t->Policy);
	}
}
void FreeRpcSetGroup(RPC_SET_GROUP *t)
{
	Free(t->Policy);
}

void InRpcEnumGroup(RPC_ENUM_GROUP *t, PACK *p)
{
	UINT i;
	if (t == NULL || p == NULL)
	{
		return;
	}

	Zero(t, sizeof(RPC_ENUM_GROUP));
	PackGetStr(p, "HubName", t->HubName, sizeof(t->HubName));
	t->NumGroup = PackGetIndexCount(p, "Name");
	t->Groups = ZeroMalloc(sizeof(RPC_ENUM_GROUP_ITEM) * t->NumGroup);

	for (i = 0;i < t->NumGroup;i++)
	{
		RPC_ENUM_GROUP_ITEM *e = &t->Groups[i];

		PackGetStrEx(p, "Name", e->Name, sizeof(e->Name), i);
		PackGetUniStrEx(p, "Realname", e->Realname, sizeof(e->Realname), i);
		PackGetUniStrEx(p, "Note", e->Note, sizeof(e->Note), i);
		e->NumUsers = PackGetIntEx(p, "NumUsers", i);
	}
}
void OutRpcEnumGroup(PACK *p, RPC_ENUM_GROUP *t)
{
	UINT i;
	if (t == NULL || p == NULL)
	{
		return;
	}

	PackAddStr(p, "HubName", t->HubName);

	for (i = 0;i < t->NumGroup;i++)
	{
		RPC_ENUM_GROUP_ITEM *e = &t->Groups[i];

		PackAddStrEx(p, "Name", e->Name, i, t->NumGroup);
		PackAddUniStrEx(p, "Realname", e->Realname, i, t->NumGroup);
		PackAddUniStrEx(p, "Note", e->Note, i, t->NumGroup);
		PackAddIntEx(p, "NumUsers", e->NumUsers, i, t->NumGroup);
		PackAddBoolEx(p, "DenyAccess", e->DenyAccess, i, t->NumGroup);
	}
}
void FreeRpcEnumGroup(RPC_ENUM_GROUP *t)
{
	if (t == NULL)
	{
		return;
	}

	Free(t->Groups);
}

void InRpcDeleteUser(RPC_DELETE_USER *t, PACK *p)
{
	if (t == NULL || p == NULL)
	{
		return;
	}

	Zero(t, sizeof(RPC_DELETE_USER));
	PackGetStr(p, "HubName", t->HubName, sizeof(t->HubName));
	PackGetStr(p, "Name", t->Name, sizeof(t->Name));
}
void OutRpcDeleteUser(PACK *p, RPC_DELETE_USER *t)
{
	if (t == NULL || p == NULL)
	{
		return;
	}

	PackAddStr(p, "HubName", t->HubName);
	PackAddStr(p, "Name", t->Name);
}

void InRpcEnumSession(RPC_ENUM_SESSION *t, PACK *p)
{
	UINT i;
	if (t == NULL || p == NULL)
	{
		return;
	}

	Zero(t, sizeof(RPC_ENUM_SESSION));
	PackGetStr(p, "HubName", t->HubName, sizeof(t->HubName));
	t->NumSession = PackGetIndexCount(p, "Name");
	t->Sessions = ZeroMalloc(sizeof(RPC_ENUM_SESSION_ITEM) * t->NumSession);

	for (i = 0;i < t->NumSession;i++)
	{
		RPC_ENUM_SESSION_ITEM *e = &t->Sessions[i];

		PackGetStrEx(p, "Name", e->Name, sizeof(e->Name), i);
		PackGetStrEx(p, "Username", e->Username, sizeof(e->Username), i);
		e->Ip = PackGetIntEx(p, "Ip", i);
		PackGetIpEx(p, "ClientIP", &e->ClientIP, i);
		PackGetStrEx(p, "Hostname", e->Hostname, sizeof(e->Hostname), i);
		e->MaxNumTcp = PackGetIntEx(p, "MaxNumTcp", i);
		e->CurrentNumTcp = PackGetIntEx(p, "CurrentNumTcp", i);
		e->PacketSize = PackGetInt64Ex(p, "PacketSize", i);
		e->PacketNum = PackGetInt64Ex(p, "PacketNum", i);
		e->LinkMode = PackGetBoolEx(p, "LinkMode", i);
		e->BridgeMode = PackGetBoolEx(p, "BridgeMode", i);
		e->VLanId = PackGetIntEx(p, "VLanId", i);
		PackGetDataEx2(p, "UniqueId", e->UniqueId, sizeof(e->UniqueId), i);
		e->IsDormantEnabled = PackGetBoolEx(p, "IsDormantEnabled", i);
		e->CreatedTime = PackGetInt64Ex(p, "CreatedTime", i);
		e->LastCommTime = PackGetInt64Ex(p, "LastCommTime", i);
	}
}
void OutRpcEnumSession(PACK *p, RPC_ENUM_SESSION *t)
{
	UINT i;
	if (t == NULL || p == NULL)
	{
		return;
	}
	PackAddStr(p, "HubName", t->HubName);

	for (i = 0;i < t->NumSession;i++)
	{
		RPC_ENUM_SESSION_ITEM *e = &t->Sessions[i];

		PackAddStrEx(p, "Name", e->Name, i, t->NumSession);
		PackAddStrEx(p, "Username", e->Username, i, t->NumSession);
		PackAddIp32Ex(p, "Ip", e->Ip, i, t->NumSession);
		PackAddIpEx(p, "ClientIP", &e->ClientIP, i, t->NumSession);
		PackAddStrEx(p, "Hostname", e->Hostname, i, t->NumSession);
		PackAddIntEx(p, "MaxNumTcp", e->MaxNumTcp, i, t->NumSession);
		PackAddIntEx(p, "CurrentNumTcp", e->CurrentNumTcp, i, t->NumSession);
		PackAddInt64Ex(p, "PacketSize", e->PacketSize, i, t->NumSession);
		PackAddInt64Ex(p, "PacketNum", e->PacketNum, i, t->NumSession);
		PackAddBoolEx(p, "LinkMode", e->LinkMode, i, t->NumSession);
		PackAddBoolEx(p, "BridgeMode", e->BridgeMode, i, t->NumSession);
		PackAddBoolEx(p, "Client_BridgeMode", e->Client_BridgeMode, i, t->NumSession);
		PackAddBoolEx(p, "Client_MonitorMode", e->Client_MonitorMode, i, t->NumSession);
		PackAddIntEx(p, "VLanId", e->VLanId, i, t->NumSession);
		PackAddDataEx(p, "UniqueId", e->UniqueId, sizeof(e->UniqueId), i, t->NumSession);
		PackAddBoolEx(p, "IsDormantEnabled", e->IsDormantEnabled, i, t->NumSession);
		PackAddBoolEx(p, "IsDormant", e->IsDormant, i, t->NumSession);
		PackAddInt64Ex(p, "LastCommDormant", e->LastCommDormant, i, t->NumSession);
		PackAddInt64Ex(p, "CreatedTime", e->CreatedTime, i, t->NumSession);
		PackAddInt64Ex(p, "LastCommTime", e->LastCommTime, i, t->NumSession);
	}
}
void FreeRpcEnumSession(RPC_ENUM_SESSION *t)
{
	if (t == NULL)
	{
		return;
	}

	Free(t->Sessions);
}

void InRpcKeyPair(RPC_KEY_PAIR *t, PACK *p)
{
	if (t == NULL || p == NULL)
	{
		return;
	}

	t->Cert = PackGetX(p, "Cert");
	t->Chain = PackGetXList(p, "Chain");
	t->Key = PackGetK(p, "Key");
	t->Flag1 = PackGetInt(p, "Flag1");
}
void OutRpcKeyPair(PACK *p, RPC_KEY_PAIR *t)
{
	if (p == NULL || t == NULL)
	{
		return;
	}

	PackAddX(p, "Cert", t->Cert);
	PackAddXList(p, "Chain", t->Chain);
	PackAddK(p, "Key", t->Key);
	PackAddInt(p, "Flag1", t->Flag1);
}
void FreeRpcKeyPair(RPC_KEY_PAIR *t)
{
	FreeX(t->Cert);
	FreeXList(t->Chain);
	FreeK(t->Key);
}

void InRpcNodeInfo(NODE_INFO *t, PACK *p)
{
	if (t == NULL || p == NULL)
	{
		return;
	}

	Zero(t, sizeof(NODE_INFO));
	PackGetStr(p, "ClientProductName", t->ClientProductName, sizeof(t->ClientProductName));
	PackGetStr(p, "ServerProductName", t->ServerProductName, sizeof(t->ServerProductName));
	PackGetStr(p, "ClientOsName", t->ClientOsName, sizeof(t->ClientOsName));
	PackGetStr(p, "ClientOsVer", t->ClientOsVer, sizeof(t->ClientOsVer));
	PackGetStr(p, "ClientOsProductId", t->ClientOsProductId, sizeof(t->ClientOsProductId));
	PackGetStr(p, "ClientHostname", t->ClientHostname, sizeof(t->ClientHostname));
	PackGetStr(p, "ServerHostname", t->ServerHostname, sizeof(t->ServerHostname));
	PackGetStr(p, "ProxyHostname", t->ProxyHostname, sizeof(t->ProxyHostname));
	PackGetStr(p, "HubName", t->HubName, sizeof(t->HubName));
	PackGetData2(p, "UniqueId", t->UniqueId, sizeof(t->UniqueId));

	t->ClientProductVer = LittleEndian32(PackGetInt(p, "ClientProductVer"));
	t->ClientProductBuild = LittleEndian32(PackGetInt(p, "ClientProductBuild"));
	t->ServerProductVer = LittleEndian32(PackGetInt(p, "ServerProductVer"));
	t->ServerProductBuild = LittleEndian32(PackGetInt(p, "ServerProductBuild"));
	t->ClientIpAddress = PackGetIp32(p, "ClientIpAddress");
	PackGetData2(p, "ClientIpAddress6", t->ClientIpAddress6, sizeof(t->ClientIpAddress6));
	t->ClientPort = LittleEndian32(PackGetInt(p, "ClientPort"));
	t->ServerIpAddress = PackGetIp32(p, "ServerIpAddress");
	PackGetData2(p, "ServerIpAddress6", t->ServerIpAddress6, sizeof(t->ServerIpAddress6));
	t->ServerPort = LittleEndian32(PackGetInt(p, "ServerPort2"));
	t->ProxyIpAddress = PackGetIp32(p, "ProxyIpAddress");
	PackGetData2(p, "ProxyIpAddress6", t->ProxyIpAddress6, sizeof(t->ProxyIpAddress6));
	t->ProxyPort = LittleEndian32(PackGetInt(p, "ProxyPort"));
}
void OutRpcNodeInfo(PACK *p, NODE_INFO *t)
{
	if (t == NULL || p == NULL)
	{
		return;
	}

	PackAddStr(p, "ClientProductName", t->ClientProductName);
	PackAddStr(p, "ServerProductName", t->ServerProductName);
	PackAddStr(p, "ClientOsName", t->ClientOsName);
	PackAddStr(p, "ClientOsVer", t->ClientOsVer);
	PackAddStr(p, "ClientOsProductId", t->ClientOsProductId);
	PackAddStr(p, "ClientHostname", t->ClientHostname);
	PackAddStr(p, "ServerHostname", t->ServerHostname);
	PackAddStr(p, "ProxyHostname", t->ProxyHostname);
	PackAddStr(p, "HubName", t->HubName);
	PackAddData(p, "UniqueId", t->UniqueId, sizeof(t->UniqueId));

	PackAddInt(p, "ClientProductVer", LittleEndian32(t->ClientProductVer));
	PackAddInt(p, "ClientProductBuild", LittleEndian32(t->ClientProductBuild));
	PackAddInt(p, "ServerProductVer", LittleEndian32(t->ServerProductVer));
	PackAddInt(p, "ServerProductBuild", LittleEndian32(t->ServerProductBuild));
	PackAddIp32(p, "ClientIpAddress", t->ClientIpAddress);
	PackAddData(p, "ClientIpAddress6", t->ClientIpAddress6, sizeof(t->ClientIpAddress6));
	PackAddInt(p, "ClientPort", LittleEndian32(t->ClientPort));
	PackAddIp32(p, "ServerIpAddress", t->ServerIpAddress);
	PackAddData(p, "ServerIpAddress6", t->ServerIpAddress6, sizeof(t->ServerIpAddress6));
	PackAddInt(p, "ServerPort2", LittleEndian32(t->ServerPort));
	PackAddIp32(p, "ProxyIpAddress", t->ProxyIpAddress);
	PackAddData(p, "ProxyIpAddress6", t->ProxyIpAddress6, sizeof(t->ProxyIpAddress6));
	PackAddInt(p, "ProxyPort", LittleEndian32(t->ProxyPort));
}

void InRpcSessionStatus(RPC_SESSION_STATUS *t, PACK *p)
{
	if (t == NULL || p == NULL)
	{
		return;
	}

	Zero(t, sizeof(RPC_SESSION_STATUS));
	PackGetStr(p, "HubName", t->HubName, sizeof(t->HubName));
	PackGetStr(p, "Name", t->Name, sizeof(t->Name));
	PackGetStr(p, "Username", t->Username, sizeof(t->Username));
	PackGetStr(p, "GroupName", t->GroupName, sizeof(t->GroupName));
	PackGetStr(p, "RealUsername", t->RealUsername, sizeof(t->RealUsername));
	t->ClientIp = PackGetIp32(p, "SessionStatus_ClientIp");
	PackGetData2(p, "SessionStatus_ClientIp6", t->ClientIp6, sizeof(t->ClientIp6));
	PackGetStr(p, "SessionStatus_ClientHostName", t->ClientHostName, sizeof(t->ClientHostName));
	PackGetIp(p, "Client_Ip_Address", &t->ClientIpAddress);

	InRpcClientGetConnectionStatus(&t->Status, p);
	InRpcNodeInfo(&t->NodeInfo, p);
}
void OutRpcSessionStatus(PACK *p, RPC_SESSION_STATUS *t)
{
	if (t == NULL || p == NULL)
	{
		return;
	}

	PackAddStr(p, "HubName", t->HubName);
	PackAddStr(p, "Name", t->Name);
	PackAddStr(p, "Username", t->Username);
	PackAddStr(p, "GroupName", t->GroupName);
	PackAddStr(p, "RealUsername", t->RealUsername);
	PackAddIp32(p, "SessionStatus_ClientIp", t->ClientIp);
	PackAddData(p, "SessionStatus_ClientIp6", t->ClientIp6, sizeof(t->ClientIp6));
	PackAddStr(p, "SessionStatus_ClientHostName", t->ClientHostName);
	PackAddIp(p, "Client_Ip_Address", &t->ClientIpAddress);

	OutRpcClientGetConnectionStatus(p, &t->Status);
	OutRpcNodeInfo(p, &t->NodeInfo);
}
void FreeRpcSessionStatus(RPC_SESSION_STATUS *t)
{
	if (t == NULL)
	{
		return;
	}

	CiFreeClientGetConnectionStatus(&t->Status);
}

void InRpcDeleteSession(RPC_DELETE_SESSION *t, PACK *p)
{
	if (t == NULL || p == NULL)
	{
		return;
	}

	Zero(t, sizeof(RPC_DELETE_SESSION));
	PackGetStr(p, "HubName", t->HubName, sizeof(t->HubName));
	PackGetStr(p, "Name", t->Name, sizeof(t->Name));
}
void OutRpcDeleteSession(PACK *p, RPC_DELETE_SESSION *t)
{
	if (t == NULL || p == NULL)
	{
		return;
	}

	PackAddStr(p, "HubName", t->HubName);
	PackAddStr(p, "Name", t->Name);
}

void InRpcEnumMacTable(RPC_ENUM_MAC_TABLE *t, PACK *p)
{
	UINT i;
	if (t == NULL || p == NULL)
	{
		return;
	}

	Zero(t, sizeof(RPC_ENUM_MAC_TABLE));
	PackGetStr(p, "HubName", t->HubName, sizeof(t->HubName));
	t->NumMacTable = PackGetIndexCount(p, "SessionName");
	t->MacTables = ZeroMalloc(sizeof(RPC_ENUM_MAC_TABLE_ITEM) * t->NumMacTable);

	for (i = 0;i < t->NumMacTable;i++)
	{
		RPC_ENUM_MAC_TABLE_ITEM *e = &t->MacTables[i];

		e->Key = PackGetIntEx(p, "Key", i);
		PackGetStrEx(p, "SessionName", e->SessionName, sizeof(e->SessionName), i);
		PackGetDataEx2(p, "MacAddress", e->MacAddress, sizeof(e->MacAddress), i);
		e->VlanId = PackGetIntEx(p, "VlanId", i);
		e->CreatedTime = PackGetInt64Ex(p, "CreatedTime", i);
		e->UpdatedTime = PackGetInt64Ex(p, "UpdatedTime", i);
	}
}
void OutRpcEnumMacTable(PACK *p, RPC_ENUM_MAC_TABLE *t)
{
	UINT i;
	if (t == NULL || p == NULL)
	{
		return;
	}

	PackAddStr(p, "HubName", t->HubName);

	for (i = 0;i < t->NumMacTable;i++)
	{
		RPC_ENUM_MAC_TABLE_ITEM *e = &t->MacTables[i];

		PackAddIntEx(p, "Key", e->Key, i, t->NumMacTable);
		PackAddStrEx(p, "SessionName", e->SessionName, i, t->NumMacTable);
		PackAddDataEx(p, "MacAddress", e->MacAddress, sizeof(e->MacAddress), i, t->NumMacTable);
		PackAddIntEx(p, "VlanId", e->VlanId, i, t->NumMacTable);
		PackAddInt64Ex(p, "CreatedTime", e->CreatedTime, i, t->NumMacTable);
		PackAddInt64Ex(p, "UpdatedTime", e->UpdatedTime, i, t->NumMacTable);
	}
}
void FreeRpcEnumMacTable(RPC_ENUM_MAC_TABLE *t)
{
	if (t == NULL)
	{
		return;
	}

	Free(t->MacTables);
}

void InRpcEnumIpTable(RPC_ENUM_IP_TABLE *t, PACK *p)
{
	UINT i;
	if (t == NULL || p == NULL)
	{
		return;
	}

	Zero(t, sizeof(RPC_ENUM_IP_TABLE));
	PackGetStr(p, "HubName", t->HubName, sizeof(t->HubName));
	t->NumIpTable = PackGetIndexCount(p, "SessionName");
	t->IpTables = ZeroMalloc(sizeof(RPC_ENUM_IP_TABLE_ITEM) * t->NumIpTable);

	for (i = 0;i < t->NumIpTable;i++)
	{
		RPC_ENUM_IP_TABLE_ITEM *e = &t->IpTables[i];

		e->Key = PackGetIntEx(p, "Key", i);
		PackGetStrEx(p, "SessionName", e->SessionName, sizeof(e->SessionName), i);
		e->Ip = PackGetIp32Ex(p, "Ip", i);
		if (PackGetIpEx(p, "IpV6", &e->IpV6, i) == false)
		{
			UINTToIP(&e->IpV6, e->Ip);
		}
		PackGetIp(p, "IpAddress", &e->IpAddress);
		e->DhcpAllocated = PackGetBoolEx(p, "DhcpAllocated", i);
		e->CreatedTime = PackGetInt64Ex(p, "CreatedTime", i);
		e->UpdatedTime = PackGetInt64Ex(p, "UpdatedTime", i);
	}
}
void OutRpcEnumIpTable(PACK *p, RPC_ENUM_IP_TABLE *t)
{
	UINT i;
	if (t == NULL || p == NULL)
	{
		return;
	}

	PackAddStr(p, "HubName", t->HubName);

	for (i = 0;i < t->NumIpTable;i++)
	{
		RPC_ENUM_IP_TABLE_ITEM *e = &t->IpTables[i];

		PackAddIntEx(p, "Key", e->Key, i, t->NumIpTable);
		PackAddStrEx(p, "SessionName", e->SessionName, i, t->NumIpTable);
		PackAddIp32Ex(p, "Ip", e->Ip, i, t->NumIpTable);
		PackAddIpEx(p, "IpV6", &e->IpV6, i, t->NumIpTable);
		PackAddIpEx(p, "IpAddress", &e->IpAddress, i, t->NumIpTable);
		PackAddBoolEx(p, "DhcpAllocated", e->DhcpAllocated, i, t->NumIpTable);
		PackAddInt64Ex(p, "CreatedTime", e->CreatedTime, i, t->NumIpTable);
		PackAddInt64Ex(p, "UpdatedTime", e->UpdatedTime, i, t->NumIpTable);
	}
}
void FreeRpcEnumIpTable(RPC_ENUM_IP_TABLE *t)
{
	if (t == NULL)
	{
		return;
	}

	Free(t->IpTables);
}

void InRpcDeleteTable(RPC_DELETE_TABLE *t, PACK *p)
{
	if (t == NULL || p == NULL)
	{
		return;
	}

	Zero(t, sizeof(RPC_DELETE_TABLE));
	PackGetStr(p, "HubName", t->HubName, sizeof(t->HubName));
	t->Key = PackGetInt(p, "Key");
}
void OutRpcDeleteTable(PACK *p, RPC_DELETE_TABLE *t)
{
	if (t == NULL || p == NULL)
	{
		return;
	}

	PackAddStr(p, "HubName", t->HubName);
	PackAddInt(p, "Key", t->Key);
}

void InRpcTest(RPC_TEST *t, PACK *p)
{
	Zero(t, sizeof(RPC_TEST));
	t->IntValue = PackGetInt(p, "IntValue");
	t->Int64Value = PackGetInt64(p, "Int64Value");
	PackGetStr(p, "StrValue", t->StrValue, sizeof(t->StrValue));
	PackGetUniStr(p, "UniStrValue", t->UniStrValue, sizeof(t->UniStrValue));
}
void OutRpcTest(PACK *p, RPC_TEST *t)
{
	PackAddInt(p, "IntValue", t->IntValue);
	PackAddInt64(p, "Int64Value", t->Int64Value);
	PackAddStr(p, "StrValue", t->StrValue);
	PackAddUniStr(p, "UniStrValue", t->UniStrValue);
}
void FreeRpcTest(RPC_TEST *t)
{
}

PACK *AdminCall(RPC *rpc, char *function_name, PACK *p)
{
	if (rpc == NULL || function_name == NULL)
	{
		return NULL;
	}
	if (p == NULL)
	{
		p = NewPack();
	}


	return RpcCall(rpc, function_name, p);
}

bool CheckAdminSourceAddress(SOCK *sock, char *hubname)
{
	BUF *b;
	char *s;
	bool ok = false;
	if (sock == NULL)
	{
		return false;
	}

	b = ReadDump(ADMINIP_TXT);
	if (b == NULL)
	{
		return true;
	}

	while (true)
	{
		UINT i;
		TOKEN_LIST *t;
		IP ip;
		IP mask;
		IP ip1;
		IP ip2;
		s = CfgReadNextLine(b);

		if (s == NULL)
		{
			break;
		}

		Trim(s);

		i = SearchStrEx(s, "//", 0, false);
		if (i != INFINITE)
		{
			s[i] = 0;
		}

		i = SearchStrEx(s, "#", 0, false);
		if (i != INFINITE)
		{
			s[i] = 0;
		}

		Trim(s);

		t = ParseToken(s, " \t");
		if (t != NULL)
		{
			if (t->NumTokens >= 1)
			{
				if (t->NumTokens == 1 || StrCmpi(hubname, t->Token[1]) == 0)
				{
					if (ParseIpAndMask46(t->Token[0], &ip, &mask))
					{
						if (IsIP4(&sock->RemoteIP) && IsIP4(&ip))
						{
							IPAnd4(&ip1, &sock->RemoteIP, &mask);
							IPAnd4(&ip2, &ip, &mask);

							if (CmpIpAddr(&ip1, &ip2) == 0)
							{
								ok = true;
							}
						}
						else if (IsIP6(&sock->RemoteIP) && IsIP6(&ip))
						{
							IPAnd6(&ip1, &sock->RemoteIP, &mask);
							IPAnd6(&ip2, &ip, &mask);

							if (CmpIpAddr(&ip1, &ip2) == 0)
							{
								ok = true;
							}
						}
					}
					else if (StrToIP(&ip, t->Token[0]))
					{
						if (CmpIpAddr(&sock->RemoteIP, &ip) == 0)
						{
							ok = true;
						}
					}

					if (StrCmpi(t->Token[0], "*") == 0)
					{
						ok = true;
					}
				}
			}

			FreeToken(t);
		}

		Free(s);
	}

	FreeBuf(b);

	return ok;
}

UINT AdminAccept(CONNECTION *c, PACK *p)
{
	ADMIN *a;
	UCHAR secure_password[SHA1_SIZE];
	UCHAR null_password[SHA1_SIZE];
	UCHAR secure_null_password[SHA1_SIZE];
	char hubname[MAX_HUBNAME_LEN + 1];
	CEDAR *cedar;
	SOCK *sock;
	RPC *rpc;
	UINT err;
	SERVER *server = NULL;
	RPC_WINVER ver;
	bool accept_empty_password;
	bool is_empty_password = false;
	if (c == NULL || p == NULL)
	{
		return ERR_INTERNAL_ERROR;
	}

	cedar = c->Cedar;
	sock = c->FirstSock;

	if (cedar != NULL)
	{
		server = cedar->Server;
	}

	accept_empty_password = PackGetBool(p, "accept_empty_password");

	InRpcWinVer(&ver, p);

	if (PackGetStr(p, "hubname", hubname, sizeof(hubname)) == false)
	{
		StrCpy(hubname, sizeof(hubname), "");
	}

	if (CheckAdminSourceAddress(sock, hubname) == false)
	{
		SLog(c->Cedar, "LA_IP_DENIED", c->Name);
		return ERR_IP_ADDRESS_DENIED;
	}

	if (PackGetDataSize(p, "secure_password") != SHA1_SIZE)
	{
		return ERR_PROTOCOL_ERROR;
	}
	PackGetData(p, "secure_password", secure_password);

	if (StrLen(hubname) == 0)
	{
		SLog(c->Cedar, "LA_CONNECTED_1", c->Name);
	}
	else
	{
		SLog(c->Cedar, "LA_CONNECTED_2", c->Name, hubname);
	}

	err = AdminCheckPassword(cedar, c->Random, secure_password,
		StrLen(hubname) != 0 ? hubname : NULL, accept_empty_password, &is_empty_password);

	if (err != ERR_NO_ERROR)
	{
		SLog(c->Cedar, "LA_ERROR", c->Name, GetUniErrorStr(err), err);
		return err;
	}

	SLog(c->Cedar, "LA_OK", c->Name);

	HashAdminPassword(null_password, "");
	SecurePassword(secure_null_password, null_password, c->Random);

	if (Cmp(secure_null_password, secure_password, SHA1_SIZE) == 0)
	{
		if (IsLocalHostIP(&sock->RemoteIP) == false)
		{
			// Refuse a blank hub admin password from a remote client
			if (StrLen(hubname) != 0)
			{
				return ERR_NULL_PASSWORD_LOCAL_ONLY;
			}
		}
	}


	p = NewPack();
	if (accept_empty_password && is_empty_password)
	{
		PackAddBool(p, "empty_password", true);
	}
	HttpServerSend(sock, p);
	FreePack(p);

	a = ZeroMalloc(sizeof(ADMIN));
	a->ServerAdmin = ((StrLen(hubname) == 0) ? true : false);
	a->HubName = (StrLen(hubname) != 0 ? hubname : NULL);
	a->Server = c->Cedar->Server;
	a->ClientBuild = c->ClientBuild;

	Copy(&a->ClientWinVer, &ver, sizeof(RPC_WINVER));

	SetTimeout(sock, INFINITE);

	rpc = StartRpcServer(sock, AdminDispatch, a);

	a->Rpc = rpc;

	SLog(c->Cedar, "LA_RPC_START", c->Name, rpc->Name);

	RpcServer(rpc);
	RpcFree(rpc);

	if (a->LogFileList != NULL)
	{
		FreeEnumLogFile(a->LogFileList);
	}

	Free(a);

	return ERR_NO_ERROR;
}

UINT AdminCheckPassword(CEDAR *c, void *random, void *secure_password, char *hubname,
						bool accept_empty_password, bool *is_password_empty)
{
	UCHAR check[SHA1_SIZE];
	bool b_dummy;
	if (c == NULL || random == NULL || secure_password == NULL)
	{
		return ERR_INTERNAL_ERROR;
	}
	if (is_password_empty == NULL)
	{
		is_password_empty = &b_dummy;
	}

	*is_password_empty = false;

	if (hubname == NULL || StrLen(hubname) == 0)
	{
		Lock(c->lock);
		{
			if (accept_empty_password && SiIsEmptyPassword(c->Server->HashedPassword))
			{
				*is_password_empty = true;
			}

			SecurePassword(check, c->Server->HashedPassword, random);
		}
		Unlock(c->lock);

		if (Cmp(check, secure_password, SHA1_SIZE) != 0)
		{
			return ERR_ACCESS_DENIED;
		}
	}
	else
	{
		HUB *h;

		LockHubList(c);
		{
			h = GetHub(c, hubname);
		}
		UnlockHubList(c);

		if (h == NULL)
		{
			return ERR_HUB_NOT_FOUND;
		}

		Lock(h->lock);
		{
			if (accept_empty_password && SiIsEmptyPassword(h->HashedPassword))
			{
				*is_password_empty = true;
			}

			SecurePassword(check, h->HashedPassword, random);
		}
		Unlock(h->lock);

		ReleaseHub(h);

		if (Cmp(check, secure_password, SHA1_SIZE) != 0)
		{
			return ERR_ACCESS_DENIED;
		}
	}

	return ERR_NO_ERROR;
}

void HashAdminPassword(void *hash, char *password)
{
	if (hash == NULL || password == NULL)
	{
		return;
	}

	Sha0(hash, password, StrLen(password));
}

void AdminDisconnect(RPC *rpc)
{
	SESSION *s;
	SOCK *sock;
	if (rpc == NULL)
	{
		return;
	}

	s = (SESSION *)rpc->Param;
	sock = rpc->Sock;

	RpcFree(rpc);

	Disconnect(sock);
	ReleaseSession(s);
}

SESSION *AdminConnectMain(CEDAR *cedar, CLIENT_OPTION *o, char *hubname, void *hashed_password, UINT *err, char *client_name, void *hWnd, bool *empty_password)
{
	UCHAR secure_password[SHA1_SIZE];
	SESSION *s;
	SOCK *sock;
	PACK *p;
	RPC_WINVER ver;
	s = NewRpcSessionEx2(cedar, o, err, client_name, hWnd);
	if (s == NULL)
	{
		return NULL;
	}

	sock = s->Connection->FirstSock;

	p = NewPack();

	PackAddClientVersion(p, s->Connection);

	PackAddStr(p, "method", "admin");
	PackAddBool(p, "accept_empty_password", true);

	GetWinVer(&ver);
	OutRpcWinVer(p, &ver);

	SecurePassword(secure_password, hashed_password, s->Connection->Random);

	PackAddData(p, "secure_password", secure_password, sizeof(secure_password));

	if (hubname != NULL)
	{
		PackAddStr(p, "hubname", hubname);
	}

	if (HttpClientSend(sock, p) == false)
	{
		FreePack(p);
		ReleaseSession(s);
		*err = ERR_DISCONNECTED;
		return NULL;
	}

	FreePack(p);

	p = HttpClientRecv(sock);
	if (p == NULL)
	{
		ReleaseSession(s);
		*err = ERR_DISCONNECTED;
		return NULL;
	}

	if (GetErrorFromPack(p) != 0)
	{
		ReleaseSession(s);
		*err = GetErrorFromPack(p);
		FreePack(p);
		return NULL;
	}

	if (empty_password != NULL)
	{
		*empty_password = PackGetBool(p, "empty_password");
	}

	FreePack(p);

	return s;
}

RPC *AdminConnectEx(CEDAR *cedar, CLIENT_OPTION *o, char *hubname, void *hashed_password, UINT *err, char *client_name)
{
	return AdminConnectEx2(cedar, o, hubname, hashed_password, err, client_name, NULL);
}
RPC *AdminConnectEx2(CEDAR *cedar, CLIENT_OPTION *o, char *hubname, void *hashed_password, UINT *err, char *client_name, void *hWnd)
{
	SESSION *s;
	SOCK *sock;
	RPC *rpc;
	UCHAR hashed_password_2[SHA1_SIZE];
	bool empty_password = false;
	if (cedar == NULL || o == NULL || hashed_password == NULL || err == NULL)
	{
		return NULL;
	}

	if (client_name == NULL)
	{
		client_name = CEDAR_MANAGER_STR;
	}

	Copy(hashed_password_2, hashed_password, SHA1_SIZE);

	s = AdminConnectMain(cedar, o, hubname, hashed_password_2, err, client_name, hWnd, &empty_password);

	if (s == NULL)
	{
		return NULL;
	}

	sock = s->Connection->FirstSock;

	rpc = StartRpcClient(sock, s);

	rpc->IsVpnServer = true;
	Copy(&rpc->VpnServerClientOption, o, sizeof(CLIENT_OPTION));
	StrCpy(rpc->VpnServerHubName, sizeof(rpc->VpnServerHubName), hubname);
	StrCpy(rpc->VpnServerClientName, sizeof(rpc->VpnServerClientName), client_name);

	if (empty_password == false)
	{
		Copy(rpc->VpnServerHashedPassword, hashed_password_2, SHA1_SIZE);
	}
	else
	{
		HashAdminPassword(rpc->VpnServerHashedPassword, "");
	}

	SetTimeout(sock, INFINITE);

	return rpc;
}

UINT AdminReconnect(RPC *rpc)
{
	SESSION *s;
	SOCK *sock;
	CEDAR *cedar;
	UINT err;
	bool empty_password = false;
	if (rpc == NULL || rpc->IsVpnServer == false)
	{
		return ERR_INTERNAL_ERROR;
	}

	s = (SESSION *)rpc->Param;
	cedar = s->Cedar;
	AddRef(cedar->ref);

	sock = rpc->Sock;
	Disconnect(sock);
	ReleaseSock(sock);
	ReleaseSession(s);
	rpc->Param = NULL;

	rpc->Sock = NULL;

	s = AdminConnectMain(cedar, &rpc->VpnServerClientOption,
		rpc->VpnServerHubName,
		rpc->VpnServerHashedPassword,
		&err,
		rpc->VpnServerClientName, NULL, &empty_password);

	ReleaseCedar(cedar);

	if (s == NULL)
	{
		return err;
	}

	if (empty_password)
	{
		HashAdminPassword(rpc->VpnServerHashedPassword, "");
	}

	rpc->Param = s;
	rpc->Sock = s->Connection->FirstSock;
	AddRef(rpc->Sock->ref);

	return ERR_NO_ERROR;
}

bool SiIsEmptyPassword(void *hash_password)
{
	UCHAR hash[SHA1_SIZE];
	if (hash_password == NULL)
	{
		return false;
	}

	Sha0(hash, "", 0);

	if (Cmp(hash_password, hash, SHA1_SIZE) == 0)
	{
		return true;
	}

	return false;
}

