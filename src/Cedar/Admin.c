// Admin.c
// RPC Module for Management

#include "Admin.h"

#include "Account.h"
#include "BridgeWin32.h"
#include "BuildInfo.h"
#include "Connection.h"
#include "Link.h"
#include "Listener.h"
#include "Remote.h"
#include "RpcField.h"
#include "Protocol.h"
#include "Sam.h"
#include "Server.h"
#include "Session.h"

#include "Mayaqua/Cfg.h"
#include "Mayaqua/FileIO.h"
#include "Mayaqua/Internat.h"
#include "Mayaqua/HTTP.h"
#include "Mayaqua/Memory.h"
#include "Mayaqua/Microsoft.h"
#include "Mayaqua/Object.h"
#include "Mayaqua/Pack.h"
#include "Mayaqua/Platform.h"
#include "Mayaqua/Str.h"
#include "Mayaqua/Table.h"
#include "Mayaqua/Tick64.h"
#include "AdminInternal.h"

static void InRpcAccess(ACCESS *a, PACK *p);
static void OutRpcAccess(PACK *p, ACCESS *a);
static void InRpcAccessEx(ACCESS *a, PACK *p, UINT index);
static void OutRpcAccessEx(PACK *p, ACCESS *a, UINT index, UINT total);
static UINT AdminCheckPassword(CEDAR *c, void *random, void *secure_password, char *hubname, bool accept_empty_password, bool *is_password_empty);
static bool SiIsEmptyPassword(void *hash_password);

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

// Hub lookup for the admin handlers: the access check, the lookup and the hub
// admin option check, in that order. Returns a referenced HUB, or NULL with *err set.
HUB *AdminGetHub(ADMIN *a, char *hubname, char *denied_option, UINT *err)
{
	HUB *h;

	if (a->ServerAdmin == false && StrCmpi(a->HubName, hubname) != 0)
	{
		*err = ERR_NOT_ENOUGH_RIGHT;
		return NULL;
	}

	if (IsEmptyStr(hubname))
	{
		*err = ERR_INVALID_PARAMETER;
		return NULL;
	}

	h = GetHub(a->Server->Cedar, hubname);
	if (h == NULL)
	{
		*err = ERR_HUB_NOT_FOUND;
		return NULL;
	}

	if (denied_option != NULL && a->ServerAdmin == false && GetHubAdminOption(h, denied_option) != 0)
	{
		ReleaseHub(h);
		*err = ERR_NOT_ENOUGH_RIGHT;
		return NULL;
	}

	return h;
}

CAPSLIST *ScGetCapsEx(RPC *rpc)
{
	CAPSLIST *t;
	TOKEN_LIST *names;
	if (rpc == NULL)
	{
		return NULL;
	}

	t = ZeroMalloc(sizeof(CAPSLIST));

	if (ScGetCaps(rpc, t) != ERR_NO_ERROR)
	{
		Free(t);
		return NULL;
	}

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

	return t;
}

// Debug log line "RPC: RPC-n (ip): ..." of the session
static void AdminDispatchTrace(ADMIN *a, char *format, ...)
{
	char msg[MAX_PATH];
	char ip[MAX_PATH];
	char tmp[MAX_PATH * 2];
	va_list args;

	IPToStr(ip, sizeof(ip), &a->RemoteIP);

	va_start(args, format);
	FormatArgs(msg, sizeof(msg), format, args);
	va_end(args);

	Format(tmp, sizeof(tmp), "RPC: %s (%s): %s", a->Tag, ip, msg);

	SiDebugLog(a->Server, tmp);
}

// Run one admin RPC of the session: take the super lock, trace, dispatch, trace; the Pack of the answer
PACK *AdminInvoke(ADMIN *a, char *name, PACK *p)
{
	PACK *ret;
	UINT err;
	SERVER *server = NULL;
	CEDAR *cedar = NULL;
	bool ok = false;
	if (a == NULL || name == NULL || p == NULL)
	{
		return NULL;
	}

	server = a->Server;

	if (server == NULL)
	{
		return NULL;
	}

	ret = NewPack();
	err = ERR_NO_ERROR;

	cedar = server->Cedar;
	Lock(cedar->CedarSuperLock);

	AdminDispatchTrace(a, "Entering RPC [%s]...", name);

	if (0) {}

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
	DECLARE_RPC("SetSysLog", SYSLOG_SETTING, StSetSysLog, InRpcSysLogSetting, OutRpcSysLogSetting)
	DECLARE_RPC("GetSysLog", SYSLOG_SETTING, StGetSysLog, InRpcSysLogSetting, OutRpcSysLogSetting)
	DECLARE_RPC_EX("EnumEthVLan", RPC_ENUM_ETH_VLAN, StEnumEthVLan, InRpcEnumEthVLan, OutRpcEnumEthVLan, FreeRpcEnumEthVLan)
	DECLARE_RPC("SetEnableEthVLan", RPC_TEST, StSetEnableEthVLan, InRpcTest, OutRpcTest)
	DECLARE_RPC_EX("SetHubMsg", RPC_MSG, StSetHubMsg, InRpcMsg, OutRpcMsg, FreeRpcMsg)
	DECLARE_RPC_EX("GetHubMsg", RPC_MSG, StGetHubMsg, InRpcMsg, OutRpcMsg, FreeRpcMsg)
	DECLARE_RPC("Crash", RPC_TEST, StCrash, InRpcTest, OutRpcTest)
	DECLARE_RPC_EX("GetAdminMsg", RPC_MSG, StGetAdminMsg, InRpcMsg, OutRpcMsg, FreeRpcMsg)
	DECLARE_RPC("Flush", RPC_TEST, StFlush, InRpcTest, OutRpcTest)
	DECLARE_RPC("RegenerateServerCert", RPC_TEST, StRegenerateServerCert, InRpcTest, OutRpcTest)

	if (ok == false)
	{
		err = ERR_NOT_SUPPORTED;
	}

	if (err != ERR_NO_ERROR)
	{
		PackAddInt(ret, "error", err);
	}

	AdminDispatchTrace(a, "Leaving RPC [%s] (Error: %u).", name, err);

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
DECLARE_SC("SetSysLog", SYSLOG_SETTING, ScSetSysLog, InRpcSysLogSetting, OutRpcSysLogSetting)
DECLARE_SC("GetSysLog", SYSLOG_SETTING, ScGetSysLog, InRpcSysLogSetting, OutRpcSysLogSetting)
DECLARE_SC("Crash", RPC_TEST, ScCrash, InRpcTest, OutRpcTest)
DECLARE_SC("Flush", RPC_TEST, ScFlush, InRpcTest, OutRpcTest)
DECLARE_SC("RegenerateServerCert", RPC_TEST, ScRegenerateServerCert, InRpcTest, OutRpcTest)

UINT StRegenerateServerCert(ADMIN *a, RPC_TEST *t)
{
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;
	X *x;
	K *k;

	SERVER_ADMIN_ONLY;

	if (SiGenerateDefaultCertEx(&x, &k, t->StrValue) == false)
	{
		SLog(c, "LS_DEFAULT_CERT_FAILED");
		return ERR_INTERNAL_ERROR;
	}

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
	HUB *h;
	UINT err;

	CHECK_RIGHT;
	if (UniStrLen(t->Msg) > HUB_MAXMSG_LEN)
	{
		return ERR_MEMORY_NOT_ENOUGH;
	}

	h = AdminGetHub(a, t->HubName, "no_change_msg", &err);
	if (h == NULL)
	{
		return err;
	}

	SetHubMsg(h, t->Msg);

	IncrementServerConfigRevision(s);

	ReleaseHub(h);

	return ERR_NO_ERROR;
}

UINT StGetHubMsg(ADMIN *a, RPC_MSG *t)
{
	HUB *h;
	UINT err;

	CHECK_RIGHT;

	h = AdminGetHub(a, t->HubName, NULL, &err);
	if (h == NULL)
	{
		return err;
	}

	FreeRpcMsg(t);
	Zero(t, sizeof(RPC_MSG));

	t->Msg = GetHubMsg(h);

	ReleaseHub(h);

	return ERR_NO_ERROR;
}

UINT StFlush(ADMIN *a, RPC_TEST *t)
{
	SERVER *s = a->Server;
	UINT size;

	SERVER_ADMIN_ONLY;

	size = SiWriteConfigurationFile(s);

	t->IntValue = size;

	return ERR_NO_ERROR;
}

UINT StCrash(ADMIN *a, RPC_TEST *t)
{
	SERVER_ADMIN_ONLY;

	CrashNow();

	return ERR_NO_ERROR;
}

UINT StGetAdminMsg(ADMIN *a, RPC_MSG *t)
{
	wchar_t winver_msg_client[3800];
	UINT tmpsize;
	wchar_t *tmp;

	FreeRpcMsg(t);
	Zero(t, sizeof(RPC_MSG));

	FormatUnsupportedWinVerMsg(winver_msg_client, sizeof(winver_msg_client), &a->ClientWinVer);

	tmpsize = UniStrSize(winver_msg_client) + 10000;

	tmp = ZeroMalloc(tmpsize);

	UniStrCat(tmp, tmpsize, winver_msg_client);

	t->Msg = tmp;

	return ERR_NO_ERROR;
}

UINT StEnumEthVLan(ADMIN *a, RPC_ENUM_ETH_VLAN *t)
{
	UINT ret = ERR_NO_ERROR;

	SERVER_ADMIN_ONLY;

	FreeRpcEnumEthVLan(t);
	Zero(t, sizeof(RPC_ENUM_ETH_VLAN));

	if (EnumEthVLanWin32(t) == false)
	{
		ret = ERR_INTERNAL_ERROR;
	}

	return ret;
}

UINT StSetEnableEthVLan(ADMIN *a, RPC_TEST *t)
{
	UINT ret = ERR_NO_ERROR;

	SERVER_ADMIN_ONLY;

	if (MsIsAdmin() == false)
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


UINT StRebootServer(ADMIN *a, RPC_TEST *t)
{
	SERVER_ADMIN_ONLY;

	ALog(a, NULL, "LA_REBOOT_SERVER");

	SiRebootServerEx(t->IntValue);

	return ERR_NO_ERROR;
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

static const RPC_FIELD rpc_enum_eth_vlan_item_fields[] =
{
	RPC_ROW_STR(RPC_ENUM_ETH_VLAN_ITEM, DeviceName, "DeviceName"),
	RPC_ROW_STR(RPC_ENUM_ETH_VLAN_ITEM, Guid, "Guid"),
	RPC_ROW_STR(RPC_ENUM_ETH_VLAN_ITEM, DeviceInstanceId, "DeviceInstanceId"),
	RPC_ROW_STR(RPC_ENUM_ETH_VLAN_ITEM, DriverName, "DriverName"),
	RPC_ROW_STR(RPC_ENUM_ETH_VLAN_ITEM, DriverType, "DriverType"),
	RPC_ROW_BOOL(RPC_ENUM_ETH_VLAN_ITEM, Support, "Support"),
	RPC_ROW_BOOL(RPC_ENUM_ETH_VLAN_ITEM, Enabled, "Enabled"),
	RPC_ROW_END
};
RPC_TABLE_DEF(rpc_enum_eth_vlan_item_table, RPC_ENUM_ETH_VLAN_ITEM, rpc_enum_eth_vlan_item_fields);

static const RPC_FIELD rpc_enum_eth_vlan_fields[] =
{
	RPC_ROW_ARRAY(RPC_ENUM_ETH_VLAN, Items, NumItem, &rpc_enum_eth_vlan_item_table, "DeviceName", 0),
	RPC_ROW_END
};
RPC_TABLE_DEF(rpc_enum_eth_vlan_table, RPC_ENUM_ETH_VLAN, rpc_enum_eth_vlan_fields);

void InRpcEnumEthVLan(RPC_ENUM_ETH_VLAN *t, PACK *p)
{
	RpcFieldIn(&rpc_enum_eth_vlan_table, t, p);
}
void OutRpcEnumEthVLan(PACK *p, RPC_ENUM_ETH_VLAN *t)
{
	RpcFieldOut(&rpc_enum_eth_vlan_table, p, t);
}
void FreeRpcEnumEthVLan(RPC_ENUM_ETH_VLAN *t)
{
	RpcFieldFree(&rpc_enum_eth_vlan_table, t);
}

static const RPC_FIELD rpc_enum_log_file_item_fields[] =
{
	RPC_ROW_STR(RPC_ENUM_LOG_FILE_ITEM, FilePath, "FilePath"),
	RPC_ROW_INT(RPC_ENUM_LOG_FILE_ITEM, FileSize, "FileSize"),
	RPC_ROW_TIME64(RPC_ENUM_LOG_FILE_ITEM, UpdatedTime, "UpdatedTime"),
	RPC_ROW_END
};
RPC_TABLE_DEF(rpc_enum_log_file_item_table, RPC_ENUM_LOG_FILE_ITEM, rpc_enum_log_file_item_fields);

static const RPC_FIELD rpc_enum_log_file_fields[] =
{
	RPC_ROW_COUNT(RPC_ENUM_LOG_FILE, NumItem),
	RPC_ROW_ARRAY(RPC_ENUM_LOG_FILE, Items, NumItem, &rpc_enum_log_file_item_table, "FilePath", RPC_FF_READ_NUMITEM),
	RPC_ROW_END
};
RPC_TABLE_DEF(rpc_enum_log_file_table, RPC_ENUM_LOG_FILE, rpc_enum_log_file_fields);

void InRpcEnumLogFile(RPC_ENUM_LOG_FILE *t, PACK *p)
{
	RpcFieldIn(&rpc_enum_log_file_table, t, p);
}
void OutRpcEnumLogFile(PACK *p, RPC_ENUM_LOG_FILE *t)
{
	RpcFieldOut(&rpc_enum_log_file_table, p, t);
}
void FreeRpcEnumLogFile(RPC_ENUM_LOG_FILE *t)
{
	RpcFieldFree(&rpc_enum_log_file_table, t);
}
static void RpcReadLogFileBufferOut(const RPC_FIELD *f, PACK *p, void *base, UINT index, UINT total)
{
	BUF *b = *((BUF **)(((UCHAR *)base) + f->Offset));

	// Written only when there is a buffer
	if (b != NULL)
	{
		PackAddBuf(p, f->Key, b);
	}
}
static void RpcReadLogFileBufferIn(const RPC_FIELD *f, void *base, PACK *p, UINT index, UINT total)
{
	*((BUF **)(((UCHAR *)base) + f->Offset)) = PackGetBuf(p, f->Key);
}
static void RpcReadLogFileBufferFree(const RPC_FIELD *f, void *base)
{
	BUF *b = *((BUF **)(((UCHAR *)base) + f->Offset));

	if (b != NULL)
	{
		FreeBuf(b);
	}
}
static const RPC_HOOK rpc_read_log_file_buffer_hook = {RpcReadLogFileBufferOut, RpcReadLogFileBufferIn, RpcReadLogFileBufferFree};

static const RPC_FIELD rpc_read_log_file_fields[] =
{
	RPC_ROW_STR(RPC_READ_LOG_FILE, FilePath, "FilePath"),
	RPC_ROW_INT(RPC_READ_LOG_FILE, Offset, "Offset"),
	RPC_ROW_HOOK(RPC_FT_BUF, RPC_READ_LOG_FILE, Buffer, "Buffer", 0, &rpc_read_log_file_buffer_hook),
	RPC_ROW_END
};
RPC_TABLE_DEF(rpc_read_log_file_table, RPC_READ_LOG_FILE, rpc_read_log_file_fields);

void InRpcReadLogFile(RPC_READ_LOG_FILE *t, PACK *p)
{
	RpcFieldIn(&rpc_read_log_file_table, t, p);
}
void OutRpcReadLogFile(PACK *p, RPC_READ_LOG_FILE *t)
{
	RpcFieldOut(&rpc_read_log_file_table, p, t);
}
void FreeRpcReadLogFile(RPC_READ_LOG_FILE *t)
{
	RpcFieldFree(&rpc_read_log_file_table, t);
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

static const RPC_FIELD rpc_enum_crl_item_fields[] =
{
	RPC_ROW_INT(RPC_ENUM_CRL_ITEM, Key, "Key"),
	RPC_ROW_UNISTR(RPC_ENUM_CRL_ITEM, CrlInfo, "CrlInfo"),
	RPC_ROW_END
};
RPC_TABLE_DEF(rpc_enum_crl_item_table, RPC_ENUM_CRL_ITEM, rpc_enum_crl_item_fields);

static const RPC_FIELD rpc_enum_crl_fields[] =
{
	RPC_ROW_STR(RPC_ENUM_CRL, HubName, "HubName"),
	RPC_ROW_COUNT(RPC_ENUM_CRL, NumItem),
	RPC_ROW_ARRAY(RPC_ENUM_CRL, Items, NumItem, &rpc_enum_crl_item_table, "Key", RPC_FF_READ_NUMITEM),
	RPC_ROW_END
};
RPC_TABLE_DEF(rpc_enum_crl_table, RPC_ENUM_CRL, rpc_enum_crl_fields);

void InRpcEnumCrl(RPC_ENUM_CRL *t, PACK *p)
{
	RpcFieldIn(&rpc_enum_crl_table, t, p);
}
void OutRpcEnumCrl(PACK *p, RPC_ENUM_CRL *t)
{
	RpcFieldOut(&rpc_enum_crl_table, p, t);
}
void FreeRpcEnumCrl(RPC_ENUM_CRL *t)
{
	RpcFieldFree(&rpc_enum_crl_table, t);
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

static const RPC_FIELD rpc_enum_eth_item_fields[] =
{
	RPC_ROW_STR(RPC_ENUM_ETH_ITEM, DeviceName, "DeviceName"),
	RPC_ROW_UNISTR(RPC_ENUM_ETH_ITEM, NetworkConnectionName, "NetworkConnectionName"),
	RPC_ROW_END
};
RPC_TABLE_DEF(rpc_enum_eth_item_table, RPC_ENUM_ETH_ITEM, rpc_enum_eth_item_fields);

static const RPC_FIELD rpc_enum_eth_fields[] =
{
	RPC_ROW_COUNT(RPC_ENUM_ETH, NumItem),
	RPC_ROW_ARRAY(RPC_ENUM_ETH, Items, NumItem, &rpc_enum_eth_item_table, "DeviceName", RPC_FF_READ_NUMITEM),
	RPC_ROW_END
};
RPC_TABLE_DEF(rpc_enum_eth_table, RPC_ENUM_ETH, rpc_enum_eth_fields);

void InRpcEnumEth(RPC_ENUM_ETH *t, PACK *p)
{
	RpcFieldIn(&rpc_enum_eth_table, t, p);
}
void OutRpcEnumEth(PACK *p, RPC_ENUM_ETH *t)
{
	RpcFieldOut(&rpc_enum_eth_table, p, t);
}
void FreeRpcEnumEth(RPC_ENUM_ETH *t)
{
	RpcFieldFree(&rpc_enum_eth_table, t);
}

static const RPC_FIELD rpc_localbridge_fields[] =
{
	RPC_ROW_STR(RPC_LOCALBRIDGE, DeviceName, "DeviceName"),
	RPC_ROW_STR(RPC_LOCALBRIDGE, HubName, "HubNameLB"),
	RPC_ROW_BOOL(RPC_LOCALBRIDGE, TapMode, "TapMode"),
	RPC_ROW_END
};
RPC_TABLE_DEF(rpc_localbridge_table, RPC_LOCALBRIDGE, rpc_localbridge_fields);

void InRpcLocalBridge(RPC_LOCALBRIDGE *t, PACK *p)
{
	RpcFieldIn(&rpc_localbridge_table, t, p);
}
void OutRpcLocalBridge(PACK *p, RPC_LOCALBRIDGE *t)
{
	RpcFieldOut(&rpc_localbridge_table, p, t);
}

// The item is an RPC_LOCALBRIDGE with Online and Active, which the
// top-level RPC_LOCALBRIDGE table does not carry
static const RPC_FIELD rpc_enum_localbridge_item_fields[] =
{
	RPC_ROW_STR(RPC_LOCALBRIDGE, DeviceName, "DeviceName"),
	RPC_ROW_STR(RPC_LOCALBRIDGE, HubName, "HubNameLB"),
	RPC_ROW_BOOL(RPC_LOCALBRIDGE, Online, "Online"),
	RPC_ROW_BOOL(RPC_LOCALBRIDGE, Active, "Active"),
	RPC_ROW_BOOL(RPC_LOCALBRIDGE, TapMode, "TapMode"),
	RPC_ROW_END
};
RPC_TABLE_DEF(rpc_enum_localbridge_item_table, RPC_LOCALBRIDGE, rpc_enum_localbridge_item_fields);

static const RPC_FIELD rpc_enum_localbridge_fields[] =
{
	RPC_ROW_COUNT(RPC_ENUM_LOCALBRIDGE, NumItem),
	RPC_ROW_ARRAY(RPC_ENUM_LOCALBRIDGE, Items, NumItem, &rpc_enum_localbridge_item_table, "DeviceName", RPC_FF_READ_NUMITEM),
	RPC_ROW_END
};
RPC_TABLE_DEF(rpc_enum_localbridge_table, RPC_ENUM_LOCALBRIDGE, rpc_enum_localbridge_fields);

void InRpcEnumLocalBridge(RPC_ENUM_LOCALBRIDGE *t, PACK *p)
{
	RpcFieldIn(&rpc_enum_localbridge_table, t, p);
}
void OutRpcEnumLocalBridge(PACK *p, RPC_ENUM_LOCALBRIDGE *t)
{
	RpcFieldOut(&rpc_enum_localbridge_table, p, t);
}
void FreeRpcEnumLocalBridge(RPC_ENUM_LOCALBRIDGE *t)
{
	RpcFieldFree(&rpc_enum_localbridge_table, t);
}

static const RPC_FIELD rpc_meminfo_fields[] =
{
	RPC_ROW_INT64(MEMINFO, TotalMemory, "TotalMemory"),
	RPC_ROW_INT64(MEMINFO, UsedMemory, "UsedMemory"),
	RPC_ROW_INT64(MEMINFO, FreeMemory, "FreeMemory"),
	RPC_ROW_INT64(MEMINFO, TotalPhys, "TotalPhys"),
	RPC_ROW_INT64(MEMINFO, UsedPhys, "UsedPhys"),
	RPC_ROW_INT64(MEMINFO, FreePhys, "FreePhys"),
	RPC_ROW_END
};
RPC_TABLE_DEF(rpc_meminfo_table, MEMINFO, rpc_meminfo_fields);

void InRpcMemInfo(MEMINFO *t, PACK *p)
{
	RpcFieldIn(&rpc_meminfo_table, t, p);
}
static void OutRpcMemInfo(PACK *p, MEMINFO *t)
{
	RpcFieldOut(&rpc_meminfo_table, p, t);
}

static void InRpcOsInfo(OS_INFO *t, PACK *p)
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
static void OutRpcOsInfo(PACK *p, OS_INFO *t)
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
static void FreeRpcOsInfo(OS_INFO *t)
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

static const RPC_FIELD rpc_admin_option_item_fields[] =
{
	RPC_ROW_STR(ADMIN_OPTION, Name, "Name"),
	RPC_ROW_INT(ADMIN_OPTION, Value, "Value"),
	RPC_ROW_UNISTR(ADMIN_OPTION, Descrption, "Descrption"),
	RPC_ROW_END
};
RPC_TABLE_DEF(rpc_admin_option_item_table, ADMIN_OPTION, rpc_admin_option_item_fields);

// NumItem is written before HubName; the count is read from "Name"
static const RPC_FIELD rpc_admin_option_fields[] =
{
	RPC_ROW_COUNT(RPC_ADMIN_OPTION, NumItem),
	RPC_ROW_STR(RPC_ADMIN_OPTION, HubName, "HubName"),
	RPC_ROW_ARRAY(RPC_ADMIN_OPTION, Items, NumItem, &rpc_admin_option_item_table, "Name", 0),
	RPC_ROW_END
};
RPC_TABLE_DEF(rpc_admin_option_table, RPC_ADMIN_OPTION, rpc_admin_option_fields);

void InRpcAdminOption(RPC_ADMIN_OPTION *t, PACK *p)
{
	RpcFieldIn(&rpc_admin_option_table, t, p);
}
void OutRpcAdminOption(PACK *p, RPC_ADMIN_OPTION *t)
{
	RpcFieldOut(&rpc_admin_option_table, p, t);
}
void FreeRpcAdminOption(RPC_ADMIN_OPTION *t)
{
	RpcFieldFree(&rpc_admin_option_table, t);
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

static const RPC_FIELD rpc_bridge_support_fields[] =
{
	RPC_ROW_BOOL(RPC_BRIDGE_SUPPORT, IsBridgeSupportedOs, "IsBridgeSupportedOs"),
	RPC_ROW_END
};
RPC_TABLE_DEF(rpc_bridge_support_table, RPC_BRIDGE_SUPPORT, rpc_bridge_support_fields);

void InRpcBridgeSupport(RPC_BRIDGE_SUPPORT *t, PACK *p)
{
	RpcFieldIn(&rpc_bridge_support_table, t, p);
}
void OutRpcBridgeSupport(PACK *p, RPC_BRIDGE_SUPPORT *t)
{
	RpcFieldOut(&rpc_bridge_support_table, p, t);
}

// ACCESS entry, written and read by the hand-written ACCESS functions: as
// the single entry of a top-level row (index 0 of 1), or as an array item
static void RpcAccessOut(const RPC_FIELD *f, PACK *p, void *base, UINT index, UINT total)
{
	ACCESS *a = (ACCESS *)(((UCHAR *)base) + f->Offset);

	if (total == 0)
	{
		OutRpcAccess(p, a);
	}
	else
	{
		OutRpcAccessEx(p, a, index, total);
	}
}
static void RpcAccessIn(const RPC_FIELD *f, void *base, PACK *p, UINT index, UINT total)
{
	ACCESS *a = (ACCESS *)(((UCHAR *)base) + f->Offset);

	if (total == 0)
	{
		InRpcAccess(a, p);
	}
	else
	{
		InRpcAccessEx(a, p, index);
	}
}
static const RPC_HOOK rpc_access_hook = { RpcAccessOut, RpcAccessIn, NULL };

static const RPC_FIELD rpc_add_access_fields[] =
{
	RPC_ROW_STR(RPC_ADD_ACCESS, HubName, "HubName"),
	RPC_ROW_HOOK(RPC_FT_STRUCT, RPC_ADD_ACCESS, Access, NULL, 0, &rpc_access_hook),
	RPC_ROW_END
};
RPC_TABLE_DEF(rpc_add_access_table, RPC_ADD_ACCESS, rpc_add_access_fields);

void InRpcAddAccess(RPC_ADD_ACCESS *t, PACK *p)
{
	RpcFieldIn(&rpc_add_access_table, t, p);
}
void OutRpcAddAccess(PACK *p, RPC_ADD_ACCESS *t)
{
	RpcFieldOut(&rpc_add_access_table, p, t);
}

static const RPC_FIELD rpc_delete_access_fields[] =
{
	RPC_ROW_STR(RPC_DELETE_ACCESS, HubName, "HubName"),
	RPC_ROW_INT(RPC_DELETE_ACCESS, Id, "Id"),
	RPC_ROW_END
};
RPC_TABLE_DEF(rpc_delete_access_table, RPC_DELETE_ACCESS, rpc_delete_access_fields);

void InRpcDeleteAccess(RPC_DELETE_ACCESS *t, PACK *p)
{
	RpcFieldIn(&rpc_delete_access_table, t, p);
}
void OutRpcDeleteAccess(PACK *p, RPC_DELETE_ACCESS *t)
{
	RpcFieldOut(&rpc_delete_access_table, p, t);
}


static void RpcServerInfoOsInfoOut(const RPC_FIELD *f, PACK *p, void *base, UINT index, UINT total)
{
	OutRpcOsInfo(p, (OS_INFO *)(((UCHAR *)base) + f->Offset));
}
static void RpcServerInfoOsInfoIn(const RPC_FIELD *f, void *base, PACK *p, UINT index, UINT total)
{
	InRpcOsInfo((OS_INFO *)(((UCHAR *)base) + f->Offset), p);
}
static void RpcServerInfoOsInfoFree(const RPC_FIELD *f, void *base)
{
	FreeRpcOsInfo((OS_INFO *)(((UCHAR *)base) + f->Offset));
}
static const RPC_HOOK rpc_server_info_os_info_hook = {RpcServerInfoOsInfoOut, RpcServerInfoOsInfoIn, RpcServerInfoOsInfoFree};

static const RPC_FIELD rpc_server_info_fields[] =
{
	RPC_ROW_STR(RPC_SERVER_INFO, ServerProductName, "ServerProductName"),
	RPC_ROW_STR(RPC_SERVER_INFO, ServerVersionString, "ServerVersionString"),
	RPC_ROW_STR(RPC_SERVER_INFO, ServerBuildInfoString, "ServerBuildInfoString"),
	RPC_ROW_INT(RPC_SERVER_INFO, ServerVerInt, "ServerVerInt"),
	RPC_ROW_INT(RPC_SERVER_INFO, ServerBuildInt, "ServerBuildInt"),
	RPC_ROW_STR(RPC_SERVER_INFO, ServerHostName, "ServerHostName"),
	RPC_ROW_TIME64(RPC_SERVER_INFO, ServerBuildDate, "ServerBuildDate"),
	RPC_ROW_HOOK(RPC_FT_STRUCT, RPC_SERVER_INFO, OsInfo, NULL, 0, &rpc_server_info_os_info_hook),
	RPC_ROW_END
};
RPC_TABLE_DEF(rpc_server_info_table, RPC_SERVER_INFO, rpc_server_info_fields);

void InRpcServerInfo(RPC_SERVER_INFO *t, PACK *p)
{
	RpcFieldIn(&rpc_server_info_table, t, p);
}
void OutRpcServerInfo(PACK *p, RPC_SERVER_INFO *t)
{
	RpcFieldOut(&rpc_server_info_table, p, t);
}
void FreeRpcServerInfo(RPC_SERVER_INFO *t)
{
	RpcFieldFree(&rpc_server_info_table, t);
}

static void RpcServerStatusTrafficOut(const RPC_FIELD *f, PACK *p, void *base, UINT index, UINT total)
{
	OutRpcTraffic(p, (TRAFFIC *)(((UCHAR *)base) + f->Offset));
}
static void RpcServerStatusTrafficIn(const RPC_FIELD *f, void *base, PACK *p, UINT index, UINT total)
{
	InRpcTraffic((TRAFFIC *)(((UCHAR *)base) + f->Offset), p);
}
static const RPC_HOOK rpc_server_status_traffic_hook = {RpcServerStatusTrafficOut, RpcServerStatusTrafficIn, NULL};

static void RpcServerStatusMemInfoOut(const RPC_FIELD *f, PACK *p, void *base, UINT index, UINT total)
{
	OutRpcMemInfo(p, (MEMINFO *)(((UCHAR *)base) + f->Offset));
}
static void RpcServerStatusMemInfoIn(const RPC_FIELD *f, void *base, PACK *p, UINT index, UINT total)
{
	InRpcMemInfo((MEMINFO *)(((UCHAR *)base) + f->Offset), p);
}
static const RPC_HOOK rpc_server_status_mem_info_hook = {RpcServerStatusMemInfoOut, RpcServerStatusMemInfoIn, NULL};

static const RPC_FIELD rpc_server_status_fields[] =
{
	RPC_ROW_INT(RPC_SERVER_STATUS, NumHubTotal, "NumHubTotal"),
	RPC_ROW_INT(RPC_SERVER_STATUS, NumHubStandalone, "NumHubStandalone"),
	RPC_ROW_INT(RPC_SERVER_STATUS, NumSessionsTotal, "NumSessionsTotal"),
	RPC_ROW_INT(RPC_SERVER_STATUS, NumSessionsLocal, "NumSessionsLocal"),
	RPC_ROW_INT(RPC_SERVER_STATUS, NumTcpConnections, "NumTcpConnections"),
	RPC_ROW_INT(RPC_SERVER_STATUS, NumTcpConnectionsLocal, "NumTcpConnectionsLocal"),
	RPC_ROW_INT(RPC_SERVER_STATUS, NumMacTables, "NumMacTables"),
	RPC_ROW_INT(RPC_SERVER_STATUS, NumIpTables, "NumIpTables"),
	RPC_ROW_INT(RPC_SERVER_STATUS, NumUsers, "NumUsers"),
	RPC_ROW_INT(RPC_SERVER_STATUS, NumGroups, "NumGroups"),
	RPC_ROW_TIME64(RPC_SERVER_STATUS, CurrentTime, "CurrentTime"),
	RPC_ROW_INT64(RPC_SERVER_STATUS, CurrentTick, "CurrentTick"),
	RPC_ROW_INT(RPC_SERVER_STATUS, AssignedBridgeLicenses, "AssignedBridgeLicenses"),
	RPC_ROW_INT(RPC_SERVER_STATUS, AssignedClientLicenses, "AssignedClientLicenses"),
	RPC_ROW_INT(RPC_SERVER_STATUS, AssignedBridgeLicensesTotal, "AssignedBridgeLicensesTotal"),
	RPC_ROW_INT(RPC_SERVER_STATUS, AssignedClientLicensesTotal, "AssignedClientLicensesTotal"),
	RPC_ROW_TIME64(RPC_SERVER_STATUS, StartTime, "StartTime"),
	RPC_ROW_HOOK(RPC_FT_STRUCT, RPC_SERVER_STATUS, Traffic, NULL, 0, &rpc_server_status_traffic_hook),
	RPC_ROW_HOOK(RPC_FT_STRUCT, RPC_SERVER_STATUS, MemInfo, NULL, 0, &rpc_server_status_mem_info_hook),
	RPC_ROW_END
};
RPC_TABLE_DEF(rpc_server_status_table, RPC_SERVER_STATUS, rpc_server_status_fields);

void InRpcServerStatus(RPC_SERVER_STATUS *t, PACK *p)
{
	RpcFieldIn(&rpc_server_status_table, t, p);
}
void OutRpcServerStatus(PACK *p, RPC_SERVER_STATUS *t)
{
	RpcFieldOut(&rpc_server_status_table, p, t);
}

static const RPC_FIELD rpc_listener_fields[] =
{
	RPC_ROW_INT(RPC_LISTENER, Port, "Port"),
	RPC_ROW_BOOL(RPC_LISTENER, Enable, "Enable"),
	RPC_ROW_END
};
RPC_TABLE_DEF(rpc_listener_table, RPC_LISTENER, rpc_listener_fields);

void InRpcListener(RPC_LISTENER *t, PACK *p)
{
	RpcFieldIn(&rpc_listener_table, t, p);
}
void OutRpcListener(PACK *p, RPC_LISTENER *t)
{
	RpcFieldOut(&rpc_listener_table, p, t);
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

static const RPC_FIELD rpc_set_password_fields[] =
{
	RPC_ROW_DATA(RPC_SET_PASSWORD, HashedPassword, "HashedPassword"),
	RPC_ROW_STR(RPC_SET_PASSWORD, PlainTextPassword, "PlainTextPassword"),
	RPC_ROW_END
};
RPC_TABLE_DEF(rpc_set_password_table, RPC_SET_PASSWORD, rpc_set_password_fields);

void InRpcSetPassword(RPC_SET_PASSWORD *t, PACK *p)
{
	RpcFieldIn(&rpc_set_password_table, t, p);
}
void OutRpcSetPassword(PACK *p, RPC_SET_PASSWORD *t)
{
	RpcFieldOut(&rpc_set_password_table, p, t);
}

static const RPC_FIELD rpc_hub_option_fields[] =
{
	RPC_ROW_INT(RPC_HUB_OPTION, MaxSession, "MaxSession"),
	RPC_ROW_BOOL(RPC_HUB_OPTION, NoEnum, "NoEnum"),
	RPC_ROW_END
};
RPC_TABLE_DEF(rpc_hub_option_table, RPC_HUB_OPTION, rpc_hub_option_fields);

void InRpcHubOption(RPC_HUB_OPTION *t, PACK *p)
{
	RpcFieldIn(&rpc_hub_option_table, t, p);
}
static void OutRpcHubOption(PACK *p, RPC_HUB_OPTION *t)
{
	RpcFieldOut(&rpc_hub_option_table, p, t);
}

static void RpcCreateHubHubOptionOut(const RPC_FIELD *f, PACK *p, void *base, UINT index, UINT total)
{
	OutRpcHubOption(p, (RPC_HUB_OPTION *)(((UCHAR *)base) + f->Offset));
}
static void RpcCreateHubHubOptionIn(const RPC_FIELD *f, void *base, PACK *p, UINT index, UINT total)
{
	InRpcHubOption((RPC_HUB_OPTION *)(((UCHAR *)base) + f->Offset), p);
}
static const RPC_HOOK rpc_create_hub_hub_option_hook = {RpcCreateHubHubOptionOut, RpcCreateHubHubOptionIn, NULL};

static const RPC_FIELD rpc_create_hub_fields[] =
{
	RPC_ROW_STR(RPC_CREATE_HUB, HubName, "HubName"),
	RPC_ROW_DATA(RPC_CREATE_HUB, HashedPassword, "HashedPassword"),
	RPC_ROW_DATA(RPC_CREATE_HUB, SecurePassword, "SecurePassword"),
	RPC_ROW_BOOL(RPC_CREATE_HUB, Online, "Online"),
	RPC_ROW_STR(RPC_CREATE_HUB, AdminPasswordPlainText, "AdminPasswordPlainText"),
	RPC_ROW_HOOK(RPC_FT_STRUCT, RPC_CREATE_HUB, HubOption, NULL, 0, &rpc_create_hub_hub_option_hook),
	RPC_ROW_END
};
RPC_TABLE_DEF(rpc_create_hub_table, RPC_CREATE_HUB, rpc_create_hub_fields);

void InRpcCreateHub(RPC_CREATE_HUB *t, PACK *p)
{
	RpcFieldIn(&rpc_create_hub_table, t, p);
}
void OutRpcCreateHub(PACK *p, RPC_CREATE_HUB *t)
{
	RpcFieldOut(&rpc_create_hub_table, p, t);
}

static void RpcEnumHubTrafficOut(const RPC_FIELD *f, PACK *p, void *base, UINT index, UINT total)
{
	OutRpcTrafficEx((TRAFFIC *)(((UCHAR *)base) + f->Offset), p, index, total);
}
static void RpcEnumHubTrafficIn(const RPC_FIELD *f, void *base, PACK *p, UINT index, UINT total)
{
	InRpcTrafficEx((TRAFFIC *)(((UCHAR *)base) + f->Offset), p, index);
}
static const RPC_HOOK rpc_enum_hub_traffic_hook = {RpcEnumHubTrafficOut, RpcEnumHubTrafficIn, NULL};

static const RPC_FIELD rpc_enum_hub_item_fields[] =
{
	RPC_ROW_STR(RPC_ENUM_HUB_ITEM, HubName, "HubName"),
	RPC_ROW_BOOL(RPC_ENUM_HUB_ITEM, Online, "Online"),
	RPC_ROW_INT(RPC_ENUM_HUB_ITEM, NumSessions, "NumSessions"),
	RPC_ROW_INT(RPC_ENUM_HUB_ITEM, NumUsers, "NumUsers"),
	RPC_ROW_INT(RPC_ENUM_HUB_ITEM, NumGroups, "NumGroups"),
	RPC_ROW_INT(RPC_ENUM_HUB_ITEM, NumMacTables, "NumMacTables"),
	RPC_ROW_INT(RPC_ENUM_HUB_ITEM, NumIpTables, "NumIpTables"),
	RPC_ROW_TIME64(RPC_ENUM_HUB_ITEM, LastCommTime, "LastCommTime"),
	RPC_ROW_TIME64(RPC_ENUM_HUB_ITEM, CreatedTime, "CreatedTime"),
	RPC_ROW_TIME64(RPC_ENUM_HUB_ITEM, LastLoginTime, "LastLoginTime"),
	RPC_ROW_INT(RPC_ENUM_HUB_ITEM, NumLogin, "NumLogin"),
	RPC_ROW_BOOL(RPC_ENUM_HUB_ITEM, IsTrafficFilled, "IsTrafficFilled"),
	RPC_ROW_HOOK(RPC_FT_STRUCT, RPC_ENUM_HUB_ITEM, Traffic, NULL, 0, &rpc_enum_hub_traffic_hook),
	RPC_ROW_END
};
RPC_TABLE_DEF(rpc_enum_hub_item_table, RPC_ENUM_HUB_ITEM, rpc_enum_hub_item_fields);

static const RPC_FIELD rpc_enum_hub_fields[] =
{
	RPC_ROW_ARRAY(RPC_ENUM_HUB, Hubs, NumHub, &rpc_enum_hub_item_table, "HubName", 0),
	RPC_ROW_END
};
RPC_TABLE_DEF(rpc_enum_hub_table, RPC_ENUM_HUB, rpc_enum_hub_fields);

void InRpcEnumHub(RPC_ENUM_HUB *t, PACK *p)
{
	RpcFieldIn(&rpc_enum_hub_table, t, p);
}
void OutRpcEnumHub(PACK *p, RPC_ENUM_HUB *t)
{
	RpcFieldOut(&rpc_enum_hub_table, p, t);
}
void FreeRpcEnumHub(RPC_ENUM_HUB *t)
{
	RpcFieldFree(&rpc_enum_hub_table, t);
}

static const RPC_FIELD rpc_delete_hub_fields[] =
{
	RPC_ROW_STR(RPC_DELETE_HUB, HubName, "HubName"),
	RPC_ROW_END
};
RPC_TABLE_DEF(rpc_delete_hub_table, RPC_DELETE_HUB, rpc_delete_hub_fields);

void InRpcDeleteHub(RPC_DELETE_HUB *t, PACK *p)
{
	RpcFieldIn(&rpc_delete_hub_table, t, p);
}
void OutRpcDeleteHub(PACK *p, RPC_DELETE_HUB *t)
{
	RpcFieldOut(&rpc_delete_hub_table, p, t);
}

static const RPC_FIELD rpc_enum_connection_item_fields[] =
{
	RPC_ROW_IP32(RPC_ENUM_CONNECTION_ITEM, Ip, "Ip"),
	RPC_ROW_INT(RPC_ENUM_CONNECTION_ITEM, Port, "Port"),
	RPC_ROW_STR(RPC_ENUM_CONNECTION_ITEM, Name, "Name"),
	RPC_ROW_STR(RPC_ENUM_CONNECTION_ITEM, Hostname, "Hostname"),
	RPC_ROW_TIME64(RPC_ENUM_CONNECTION_ITEM, ConnectedTime, "ConnectedTime"),
	RPC_ROW_INT(RPC_ENUM_CONNECTION_ITEM, Type, "Type"),
	RPC_ROW_END
};
RPC_TABLE_DEF(rpc_enum_connection_item_table, RPC_ENUM_CONNECTION_ITEM, rpc_enum_connection_item_fields);

static const RPC_FIELD rpc_enum_connection_fields[] =
{
	RPC_ROW_ARRAY(RPC_ENUM_CONNECTION, Connections, NumConnection, &rpc_enum_connection_item_table, "Name", 0),
	RPC_ROW_END
};
RPC_TABLE_DEF(rpc_enum_connection_table, RPC_ENUM_CONNECTION, rpc_enum_connection_fields);

void InRpcEnumConnection(RPC_ENUM_CONNECTION *t, PACK *p)
{
	RpcFieldIn(&rpc_enum_connection_table, t, p);
}
void OutRpcEnumConnection(PACK *p, RPC_ENUM_CONNECTION *t)
{
	RpcFieldOut(&rpc_enum_connection_table, p, t);
}
void FreeRpcEnumConnection(RPC_ENUM_CONNECTION *t)
{
	RpcFieldFree(&rpc_enum_connection_table, t);
}

static const RPC_FIELD rpc_disconnect_connection_fields[] =
{
	RPC_ROW_STR(RPC_DISCONNECT_CONNECTION, Name, "Name"),
	RPC_ROW_END
};
RPC_TABLE_DEF(rpc_disconnect_connection_table, RPC_DISCONNECT_CONNECTION, rpc_disconnect_connection_fields);

void InRpcDisconnectConnection(RPC_DISCONNECT_CONNECTION *t, PACK *p)
{
	RpcFieldIn(&rpc_disconnect_connection_table, t, p);
}
void OutRpcDisconnectConnection(PACK *p, RPC_DISCONNECT_CONNECTION *t)
{
	RpcFieldOut(&rpc_disconnect_connection_table, p, t);
}

static const RPC_FIELD rpc_connection_info_fields[] =
{
	RPC_ROW_STR(RPC_CONNECTION_INFO, Name, "Name"),
	RPC_ROW_IP32(RPC_CONNECTION_INFO, Ip, "Ip"),
	RPC_ROW_INT(RPC_CONNECTION_INFO, Port, "Port"),
	RPC_ROW_TIME64(RPC_CONNECTION_INFO, ConnectedTime, "ConnectedTime"),
	RPC_ROW_STR(RPC_CONNECTION_INFO, Hostname, "Hostname"),
	RPC_ROW_STR(RPC_CONNECTION_INFO, ServerStr, "ServerStr"),
	RPC_ROW_STR(RPC_CONNECTION_INFO, ClientStr, "ClientStr"),
	RPC_ROW_INT(RPC_CONNECTION_INFO, ServerVer, "ServerVer"),
	RPC_ROW_INT(RPC_CONNECTION_INFO, ServerBuild, "ServerBuild"),
	RPC_ROW_INT(RPC_CONNECTION_INFO, ClientVer, "ClientVer"),
	RPC_ROW_INT(RPC_CONNECTION_INFO, ClientBuild, "ClientBuild"),
	RPC_ROW_INT(RPC_CONNECTION_INFO, Type, "Type"),
	RPC_ROW_END
};
RPC_TABLE_DEF(rpc_connection_info_table, RPC_CONNECTION_INFO, rpc_connection_info_fields);

void InRpcConnectionInfo(RPC_CONNECTION_INFO *t, PACK *p)
{
	RpcFieldIn(&rpc_connection_info_table, t, p);
}
void OutRpcConnectionInfo(PACK *p, RPC_CONNECTION_INFO *t)
{
	RpcFieldOut(&rpc_connection_info_table, p, t);
}

static const RPC_FIELD rpc_set_hub_online_fields[] =
{
	RPC_ROW_STR(RPC_SET_HUB_ONLINE, HubName, "HubName"),
	RPC_ROW_BOOL(RPC_SET_HUB_ONLINE, Online, "Online"),
	RPC_ROW_END
};
RPC_TABLE_DEF(rpc_set_hub_online_table, RPC_SET_HUB_ONLINE, rpc_set_hub_online_fields);

void InRpcSetHubOnline(RPC_SET_HUB_ONLINE *t, PACK *p)
{
	RpcFieldIn(&rpc_set_hub_online_table, t, p);
}
void OutRpcSetHubOnline(PACK *p, RPC_SET_HUB_ONLINE *t)
{
	RpcFieldOut(&rpc_set_hub_online_table, p, t);
}

static void RpcHubStatusTrafficOut(const RPC_FIELD *f, PACK *p, void *base, UINT index, UINT total)
{
	OutRpcTraffic(p, (TRAFFIC *)(((UCHAR *)base) + f->Offset));
}
static void RpcHubStatusTrafficIn(const RPC_FIELD *f, void *base, PACK *p, UINT index, UINT total)
{
	InRpcTraffic((TRAFFIC *)(((UCHAR *)base) + f->Offset), p);
}
static const RPC_HOOK rpc_hub_status_traffic_hook = {RpcHubStatusTrafficOut, RpcHubStatusTrafficIn, NULL};

static const RPC_FIELD rpc_hub_status_fields[] =
{
	RPC_ROW_STR(RPC_HUB_STATUS, HubName, "HubName"),
	RPC_ROW_BOOL(RPC_HUB_STATUS, Online, "Online"),
	RPC_ROW_INT(RPC_HUB_STATUS, NumSessions, "NumSessions"),
	RPC_ROW_INT(RPC_HUB_STATUS, NumSessionsClient, "NumSessionsClient"),
	RPC_ROW_INT(RPC_HUB_STATUS, NumSessionsBridge, "NumSessionsBridge"),
	RPC_ROW_INT(RPC_HUB_STATUS, NumAccessLists, "NumAccessLists"),
	RPC_ROW_INT(RPC_HUB_STATUS, NumUsers, "NumUsers"),
	RPC_ROW_INT(RPC_HUB_STATUS, NumGroups, "NumGroups"),
	RPC_ROW_INT(RPC_HUB_STATUS, NumMacTables, "NumMacTables"),
	RPC_ROW_INT(RPC_HUB_STATUS, NumIpTables, "NumIpTables"),
	RPC_ROW_HOOK(RPC_FT_STRUCT, RPC_HUB_STATUS, Traffic, NULL, 0, &rpc_hub_status_traffic_hook),
	RPC_ROW_TIME64(RPC_HUB_STATUS, LastCommTime, "LastCommTime"),
	RPC_ROW_TIME64(RPC_HUB_STATUS, CreatedTime, "CreatedTime"),
	RPC_ROW_TIME64(RPC_HUB_STATUS, LastLoginTime, "LastLoginTime"),
	RPC_ROW_INT(RPC_HUB_STATUS, NumLogin, "NumLogin"),
	RPC_ROW_END
};
RPC_TABLE_DEF(rpc_hub_status_table, RPC_HUB_STATUS, rpc_hub_status_fields);

void InRpcHubStatus(RPC_HUB_STATUS *t, PACK *p)
{
	RpcFieldIn(&rpc_hub_status_table, t, p);
}
void OutRpcHubStatus(PACK *p, RPC_HUB_STATUS *t)
{
	RpcFieldOut(&rpc_hub_status_table, p, t);
}

static void RpcHubLogPacketLogConfigOut(const RPC_FIELD *f, PACK *p, void *base, UINT index, UINT total)
{
	UINT *c = (UINT *)(((UCHAR *)base) + f->Offset);
	UINT i, num = f->Size / sizeof(UINT);

	for (i = 0;i < num;i++)
	{
		PackAddIntEx(p, f->Key, c[i], i, num);
	}
}
static void RpcHubLogPacketLogConfigIn(const RPC_FIELD *f, void *base, PACK *p, UINT index, UINT total)
{
	UINT *c = (UINT *)(((UCHAR *)base) + f->Offset);
	UINT i, num = f->Size / sizeof(UINT);

	for (i = 0;i < num;i++)
	{
		c[i] = PackGetIntEx(p, f->Key, i);
	}
}
static const RPC_HOOK rpc_hub_log_packet_log_config_hook = {RpcHubLogPacketLogConfigOut, RpcHubLogPacketLogConfigIn, NULL};

static const RPC_FIELD rpc_hub_log_fields[] =
{
	RPC_ROW_STR(RPC_HUB_LOG, HubName, "HubName"),
	RPC_ROW_BOOL(RPC_HUB_LOG, LogSetting.SaveSecurityLog, "SaveSecurityLog"),
	RPC_ROW_INT(RPC_HUB_LOG, LogSetting.SecurityLogSwitchType, "SecurityLogSwitchType"),
	RPC_ROW_BOOL(RPC_HUB_LOG, LogSetting.SavePacketLog, "SavePacketLog"),
	RPC_ROW_INT(RPC_HUB_LOG, LogSetting.PacketLogSwitchType, "PacketLogSwitchType"),
	RPC_ROW_HOOK(RPC_FT_INTARRAY, RPC_HUB_LOG, LogSetting.PacketLogConfig, "PacketLogConfig", 0, &rpc_hub_log_packet_log_config_hook),
	RPC_ROW_END
};
RPC_TABLE_DEF(rpc_hub_log_table, RPC_HUB_LOG, rpc_hub_log_fields);

void InRpcHubLog(RPC_HUB_LOG *t, PACK *p)
{
	RpcFieldIn(&rpc_hub_log_table, t, p);
}
void OutRpcHubLog(PACK *p, RPC_HUB_LOG *t)
{
	RpcFieldOut(&rpc_hub_log_table, p, t);
}

// Certificate of a CA row: PackAddX, PackGetX, FreeX
static void RpcHubCaCertOut(const RPC_FIELD *f, PACK *p, void *base, UINT index, UINT total)
{
	PackAddX(p, f->Key, *((X **)(((UCHAR *)base) + f->Offset)));
}
static void RpcHubCaCertIn(const RPC_FIELD *f, void *base, PACK *p, UINT index, UINT total)
{
	*((X **)(((UCHAR *)base) + f->Offset)) = PackGetX(p, f->Key);
}
static void RpcHubCaCertFree(const RPC_FIELD *f, void *base)
{
	FreeX(*((X **)(((UCHAR *)base) + f->Offset)));
}
static const RPC_HOOK rpc_hub_ca_cert_hook = { RpcHubCaCertOut, RpcHubCaCertIn, RpcHubCaCertFree };

static const RPC_FIELD rpc_hub_add_ca_fields[] =
{
	RPC_ROW_STR(RPC_HUB_ADD_CA, HubName, "HubName"),
	RPC_ROW_HOOK(RPC_FT_X, RPC_HUB_ADD_CA, Cert, "Cert", 0, &rpc_hub_ca_cert_hook),
	RPC_ROW_END
};
RPC_TABLE_DEF(rpc_hub_add_ca_table, RPC_HUB_ADD_CA, rpc_hub_add_ca_fields);

void InRpcHubAddCa(RPC_HUB_ADD_CA *t, PACK *p)
{
	RpcFieldIn(&rpc_hub_add_ca_table, t, p);
}
void OutRpcHubAddCa(PACK *p, RPC_HUB_ADD_CA *t)
{
	RpcFieldOut(&rpc_hub_add_ca_table, p, t);
}
void FreeRpcHubAddCa(RPC_HUB_ADD_CA *t)
{
	RpcFieldFree(&rpc_hub_add_ca_table, t);
}

static const RPC_FIELD rpc_hub_enum_ca_item_fields[] =
{
	RPC_ROW_INT(RPC_HUB_ENUM_CA_ITEM, Key, "Key"),
	RPC_ROW_UNISTR(RPC_HUB_ENUM_CA_ITEM, SubjectName, "SubjectName"),
	RPC_ROW_UNISTR(RPC_HUB_ENUM_CA_ITEM, IssuerName, "IssuerName"),
	RPC_ROW_TIME64(RPC_HUB_ENUM_CA_ITEM, Expires, "Expires"),
	RPC_ROW_END
};
RPC_TABLE_DEF(rpc_hub_enum_ca_item_table, RPC_HUB_ENUM_CA_ITEM, rpc_hub_enum_ca_item_fields);

static const RPC_FIELD rpc_hub_enum_ca_fields[] =
{
	RPC_ROW_STR(RPC_HUB_ENUM_CA, HubName, "HubName"),
	RPC_ROW_ARRAY(RPC_HUB_ENUM_CA, Ca, NumCa, &rpc_hub_enum_ca_item_table, "Key", 0),
	RPC_ROW_END
};
RPC_TABLE_DEF(rpc_hub_enum_ca_table, RPC_HUB_ENUM_CA, rpc_hub_enum_ca_fields);

void InRpcHubEnumCa(RPC_HUB_ENUM_CA *t, PACK *p)
{
	RpcFieldIn(&rpc_hub_enum_ca_table, t, p);
}
void OutRpcHubEnumCa(PACK *p, RPC_HUB_ENUM_CA *t)
{
	RpcFieldOut(&rpc_hub_enum_ca_table, p, t);
}
void FreeRpcHubEnumCa(RPC_HUB_ENUM_CA *t)
{
	RpcFieldFree(&rpc_hub_enum_ca_table, t);
}

static const RPC_FIELD rpc_hub_get_ca_fields[] =
{
	RPC_ROW_STR(RPC_HUB_GET_CA, HubName, "HubName"),
	RPC_ROW_INT(RPC_HUB_GET_CA, Key, "Key"),
	RPC_ROW_HOOK(RPC_FT_X, RPC_HUB_GET_CA, Cert, "Cert", 0, &rpc_hub_ca_cert_hook),
	RPC_ROW_END
};
RPC_TABLE_DEF(rpc_hub_get_ca_table, RPC_HUB_GET_CA, rpc_hub_get_ca_fields);

void InRpcHubGetCa(RPC_HUB_GET_CA *t, PACK *p)
{
	RpcFieldIn(&rpc_hub_get_ca_table, t, p);
}
void OutRpcHubGetCa(PACK *p, RPC_HUB_GET_CA *t)
{
	RpcFieldOut(&rpc_hub_get_ca_table, p, t);
}
void FreeRpcHubGetCa(RPC_HUB_GET_CA *t)
{
	RpcFieldFree(&rpc_hub_get_ca_table, t);
}

static const RPC_FIELD rpc_hub_delete_ca_fields[] =
{
	RPC_ROW_STR(RPC_HUB_DELETE_CA, HubName, "HubName"),
	RPC_ROW_INT(RPC_HUB_DELETE_CA, Key, "Key"),
	RPC_ROW_END
};
RPC_TABLE_DEF(rpc_hub_delete_ca_table, RPC_HUB_DELETE_CA, rpc_hub_delete_ca_fields);

void InRpcHubDeleteCa(RPC_HUB_DELETE_CA *t, PACK *p)
{
	RpcFieldIn(&rpc_hub_delete_ca_table, t, p);
}
void OutRpcHubDeleteCa(PACK *p, RPC_HUB_DELETE_CA *t)
{
	RpcFieldOut(&rpc_hub_delete_ca_table, p, t);
}

static void RpcCreateLinkClientOptionOut(const RPC_FIELD *f, PACK *p, void *base, UINT index, UINT total)
{
	OutRpcClientOption(p, *(CLIENT_OPTION **)((UCHAR *)base + f->Offset));
}
static void RpcCreateLinkClientOptionIn(const RPC_FIELD *f, void *base, PACK *p, UINT index, UINT total)
{
	CLIENT_OPTION **o = (CLIENT_OPTION **)((UCHAR *)base + f->Offset);

	*o = ZeroMalloc(sizeof(CLIENT_OPTION));
	InRpcClientOption(*o, p);
}
static void RpcCreateLinkClientOptionFree(const RPC_FIELD *f, void *base)
{
	Free(*(CLIENT_OPTION **)((UCHAR *)base + f->Offset));
}
static const RPC_HOOK rpc_create_link_client_option_hook = {RpcCreateLinkClientOptionOut, RpcCreateLinkClientOptionIn, RpcCreateLinkClientOptionFree};

static void RpcCreateLinkClientAuthOut(const RPC_FIELD *f, PACK *p, void *base, UINT index, UINT total)
{
	OutRpcClientAuth(p, *(CLIENT_AUTH **)((UCHAR *)base + f->Offset));
}
static void RpcCreateLinkClientAuthIn(const RPC_FIELD *f, void *base, PACK *p, UINT index, UINT total)
{
	CLIENT_AUTH **a = (CLIENT_AUTH **)((UCHAR *)base + f->Offset);

	*a = ZeroMalloc(sizeof(CLIENT_AUTH));
	InRpcClientAuth(*a, p);
}
static void RpcCreateLinkClientAuthFree(const RPC_FIELD *f, void *base)
{
	ClientAuthFree(*(CLIENT_AUTH **)((UCHAR *)base + f->Offset));
}
static const RPC_HOOK rpc_create_link_client_auth_hook = {RpcCreateLinkClientAuthOut, RpcCreateLinkClientAuthIn, RpcCreateLinkClientAuthFree};

static void RpcCreateLinkPolicyOut(const RPC_FIELD *f, PACK *p, void *base, UINT index, UINT total)
{
	OutRpcPolicy(p, (POLICY *)((UCHAR *)base + f->Offset));
}
static void RpcCreateLinkPolicyIn(const RPC_FIELD *f, void *base, PACK *p, UINT index, UINT total)
{
	InRpcPolicy((POLICY *)((UCHAR *)base + f->Offset), p);
}
static const RPC_HOOK rpc_create_link_policy_hook = {RpcCreateLinkPolicyOut, RpcCreateLinkPolicyIn, NULL};

// Server certificate as DER data (read without the PEM fallback of PackGetX)
static void RpcCreateLinkServerCertOut(const RPC_FIELD *f, PACK *p, void *base, UINT index, UINT total)
{
	X *x = *(X **)((UCHAR *)base + f->Offset);

	if (x != NULL)
	{
		BUF *b = XToBuf(x, false);
		PackAddBuf(p, f->Key, b);
		FreeBuf(b);
	}
}
static void RpcCreateLinkServerCertIn(const RPC_FIELD *f, void *base, PACK *p, UINT index, UINT total)
{
	BUF *b = PackGetBuf(p, f->Key);

	if (b != NULL)
	{
		*(X **)((UCHAR *)base + f->Offset) = BufToX(b, false);
		FreeBuf(b);
	}
}
static void RpcCreateLinkServerCertFree(const RPC_FIELD *f, void *base)
{
	X *x = *(X **)((UCHAR *)base + f->Offset);

	if (x != NULL)
	{
		FreeX(x);
	}
}
static const RPC_HOOK rpc_create_link_server_cert_hook = {RpcCreateLinkServerCertOut, RpcCreateLinkServerCertIn, RpcCreateLinkServerCertFree};

static const RPC_FIELD rpc_create_link_fields[] =
{
	RPC_ROW_STR(RPC_CREATE_LINK, HubName, "HubName_Ex"),
	RPC_ROW_BOOL(RPC_CREATE_LINK, Online, "Online"),
	RPC_ROW_HOOK(RPC_FT_STRUCTPTR, RPC_CREATE_LINK, ClientOption, NULL, 0, &rpc_create_link_client_option_hook),
	RPC_ROW_HOOK(RPC_FT_STRUCTPTR, RPC_CREATE_LINK, ClientAuth, NULL, 0, &rpc_create_link_client_auth_hook),
	RPC_ROW_HOOK(RPC_FT_STRUCT, RPC_CREATE_LINK, Policy, NULL, 0, &rpc_create_link_policy_hook),
	RPC_ROW_BOOL(RPC_CREATE_LINK, CheckServerCert, "CheckServerCert"),
	RPC_ROW_BOOL(RPC_CREATE_LINK, AddDefaultCA, "AddDefaultCA"),
	RPC_ROW_HOOK(RPC_FT_X, RPC_CREATE_LINK, ServerCert, "ServerCert", 0, &rpc_create_link_server_cert_hook),
	RPC_ROW_END
};
RPC_TABLE_DEF(rpc_create_link_table, RPC_CREATE_LINK, rpc_create_link_fields);

void InRpcCreateLink(RPC_CREATE_LINK *t, PACK *p)
{
	RpcFieldIn(&rpc_create_link_table, t, p);
}
void OutRpcCreateLink(PACK *p, RPC_CREATE_LINK *t)
{
	RpcFieldOut(&rpc_create_link_table, p, t);
}
void FreeRpcCreateLink(RPC_CREATE_LINK *t)
{
	RpcFieldFree(&rpc_create_link_table, t);
}

// Hub name: "ConnectedHubName", or "TargetHubName" when it is missing
static void RpcEnumLinkHubNameIn(const RPC_FIELD *f, void *base, PACK *p, UINT index, UINT total)
{
	char *s = (char *)((UCHAR *)base + f->Offset);

	if (PackGetStrEx(p, f->Key, s, f->Size, index) == false)
	{
		PackGetStrEx(p, "TargetHubName", s, f->Size, index);
	}
}
static const RPC_HOOK rpc_enum_link_hub_name_hook = {NULL, RpcEnumLinkHubNameIn, NULL};

// "TargetHubName" is written last and read only by the fallback above
static void RpcEnumLinkTargetHubNameIn(const RPC_FIELD *f, void *base, PACK *p, UINT index, UINT total)
{
}
static const RPC_HOOK rpc_enum_link_target_hub_name_hook = {NULL, RpcEnumLinkTargetHubNameIn, NULL};

static const RPC_FIELD rpc_enum_link_item_fields[] =
{
	RPC_ROW_UNISTR(RPC_ENUM_LINK_ITEM, AccountName, "AccountName"),
	RPC_ROW_HOOK(RPC_FT_STR, RPC_ENUM_LINK_ITEM, HubName, "ConnectedHubName", 0, &rpc_enum_link_hub_name_hook),
	RPC_ROW_STR(RPC_ENUM_LINK_ITEM, Hostname, "Hostname"),
	RPC_ROW_BOOL(RPC_ENUM_LINK_ITEM, Online, "Online"),
	RPC_ROW_TIME64(RPC_ENUM_LINK_ITEM, ConnectedTime, "ConnectedTime"),
	RPC_ROW_BOOL(RPC_ENUM_LINK_ITEM, Connected, "Connected"),
	RPC_ROW_INT(RPC_ENUM_LINK_ITEM, LastError, "LastError"),
	RPC_ROW_HOOK(RPC_FT_STR, RPC_ENUM_LINK_ITEM, HubName, "TargetHubName", RPC_FF_ALIAS, &rpc_enum_link_target_hub_name_hook),
	RPC_ROW_END
};
RPC_TABLE_DEF(rpc_enum_link_item_table, RPC_ENUM_LINK_ITEM, rpc_enum_link_item_fields);

static const RPC_FIELD rpc_enum_link_fields[] =
{
	RPC_ROW_STR(RPC_ENUM_LINK, HubName, "HubName"),
	RPC_ROW_ARRAY(RPC_ENUM_LINK, Links, NumLink, &rpc_enum_link_item_table, "AccountName", 0),
	RPC_ROW_END
};
RPC_TABLE_DEF(rpc_enum_link_table, RPC_ENUM_LINK, rpc_enum_link_fields);

void InRpcEnumLink(RPC_ENUM_LINK *t, PACK *p)
{
	RpcFieldIn(&rpc_enum_link_table, t, p);
}
void OutRpcEnumLink(PACK *p, RPC_ENUM_LINK *t)
{
	RpcFieldOut(&rpc_enum_link_table, p, t);
}
void FreeRpcEnumLink(RPC_ENUM_LINK *t)
{
	RpcFieldFree(&rpc_enum_link_table, t);
}

static void RpcLinkStatusStatusOut(const RPC_FIELD *f, PACK *p, void *base, UINT index, UINT total)
{
	OutRpcClientGetConnectionStatus(p, (RPC_CLIENT_GET_CONNECTION_STATUS *)((UCHAR *)base + f->Offset));
}
static void RpcLinkStatusStatusIn(const RPC_FIELD *f, void *base, PACK *p, UINT index, UINT total)
{
	InRpcClientGetConnectionStatus((RPC_CLIENT_GET_CONNECTION_STATUS *)((UCHAR *)base + f->Offset), p);
}
static void RpcLinkStatusStatusFree(const RPC_FIELD *f, void *base)
{
	CiFreeClientGetConnectionStatus((RPC_CLIENT_GET_CONNECTION_STATUS *)((UCHAR *)base + f->Offset));
}
static const RPC_HOOK rpc_link_status_status_hook = {RpcLinkStatusStatusOut, RpcLinkStatusStatusIn, RpcLinkStatusStatusFree};

static const RPC_FIELD rpc_link_status_fields[] =
{
	RPC_ROW_STR(RPC_LINK_STATUS, HubName, "HubName_Ex"),
	RPC_ROW_UNISTR(RPC_LINK_STATUS, AccountName, "AccountName"),
	// The connection status adds "AccountName" again: the row above is written first and wins
	RPC_ROW_HOOK(RPC_FT_STRUCT, RPC_LINK_STATUS, Status, NULL, 0, &rpc_link_status_status_hook),
	RPC_ROW_END
};
RPC_TABLE_DEF(rpc_link_status_table, RPC_LINK_STATUS, rpc_link_status_fields);

void InRpcLinkStatus(RPC_LINK_STATUS *t, PACK *p)
{
	RpcFieldIn(&rpc_link_status_table, t, p);
}
void OutRpcLinkStatus(PACK *p, RPC_LINK_STATUS *t)
{
	RpcFieldOut(&rpc_link_status_table, p, t);
}
void FreeRpcLinkStatus(RPC_LINK_STATUS *t)
{
	RpcFieldFree(&rpc_link_status_table, t);
}

static const RPC_FIELD rpc_link_fields[] =
{
	RPC_ROW_STR(RPC_LINK, HubName, "HubName"),
	RPC_ROW_UNISTR(RPC_LINK, AccountName, "AccountName"),
	RPC_ROW_END
};
RPC_TABLE_DEF(rpc_link_table, RPC_LINK, rpc_link_fields);

void InRpcLink(RPC_LINK *t, PACK *p)
{
	RpcFieldIn(&rpc_link_table, t, p);
}
void OutRpcLink(PACK *p, RPC_LINK *t)
{
	RpcFieldOut(&rpc_link_table, p, t);
}

static const RPC_FIELD rpc_rename_link_fields[] =
{
	RPC_ROW_STR(RPC_RENAME_LINK, HubName, "HubName"),
	RPC_ROW_UNISTR(RPC_RENAME_LINK, OldAccountName, "OldAccountName"),
	RPC_ROW_UNISTR(RPC_RENAME_LINK, NewAccountName, "NewAccountName"),
	RPC_ROW_END
};
RPC_TABLE_DEF(rpc_rename_link_table, RPC_RENAME_LINK, rpc_rename_link_fields);

void InRpcRenameLink(RPC_RENAME_LINK *t, PACK *p)
{
	RpcFieldIn(&rpc_rename_link_table, t, p);
}
void OutRpcRenameLink(PACK *p, RPC_RENAME_LINK *t)
{
	RpcFieldOut(&rpc_rename_link_table, p, t);
}

static void InRpcAccessEx(ACCESS *a, PACK *p, UINT index)
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
static void InRpcAccess(ACCESS *a, PACK *p)
{
	if (a == NULL || p == NULL)
	{
		return;
	}

	InRpcAccessEx(a, p, 0);
}
static void OutRpcAccessEx(PACK *p, ACCESS *a, UINT index, UINT total)
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
static void OutRpcAccess(PACK *p, ACCESS *a)
{
	if (a == NULL || p == NULL)
	{
		return;
	}

	OutRpcAccessEx(p, a, 0, 1);
}

static const RPC_FIELD rpc_enum_access_list_item_fields[] =
{
	RPC_ROW_WHOLE(ACCESS, NULL, 0, &rpc_access_hook),
	RPC_ROW_END
};
RPC_TABLE_DEF(rpc_enum_access_list_item_table, ACCESS, rpc_enum_access_list_item_fields);

static const RPC_FIELD rpc_enum_access_list_fields[] =
{
	RPC_ROW_STR(RPC_ENUM_ACCESS_LIST, HubName, "HubName"),
	RPC_ROW_ARRAY(RPC_ENUM_ACCESS_LIST, Accesses, NumAccess, &rpc_enum_access_list_item_table, "Protocol", 0),
	RPC_ROW_END
};
RPC_TABLE_DEF(rpc_enum_access_list_table, RPC_ENUM_ACCESS_LIST, rpc_enum_access_list_fields);

void InRpcEnumAccessList(RPC_ENUM_ACCESS_LIST *a, PACK *p)
{
	RpcFieldIn(&rpc_enum_access_list_table, a, p);
}
void OutRpcEnumAccessList(PACK *p, RPC_ENUM_ACCESS_LIST *a)
{
	RpcFieldOut(&rpc_enum_access_list_table, p, a);
}
void FreeRpcEnumAccessList(RPC_ENUM_ACCESS_LIST *a)
{
	RpcFieldFree(&rpc_enum_access_list_table, a);
}

static void *InRpcAuthData(PACK *p, UINT *authtype, char *username)
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
static void OutRpcAuthData(PACK *p, void *authdata, UINT authtype)
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

// Embedded TRAFFIC through the TRAFFIC entry points
static void RpcSetUserTrafficOut(const RPC_FIELD *f, PACK *p, void *base, UINT index, UINT total)
{
	OutRpcTraffic(p, (TRAFFIC *)(((UCHAR *)base) + f->Offset));
}
static void RpcSetUserTrafficIn(const RPC_FIELD *f, void *base, PACK *p, UINT index, UINT total)
{
	InRpcTraffic((TRAFFIC *)(((UCHAR *)base) + f->Offset), p);
}
static const RPC_HOOK rpc_set_user_traffic_hook = {RpcSetUserTrafficOut, RpcSetUserTrafficIn, NULL};

// Authentication data: "AuthType" and the data of that type. Read after
// Name, which hashes a plain-text password.
static void RpcSetUserAuthDataOut(const RPC_FIELD *f, PACK *p, void *base, UINT index, UINT total)
{
	RPC_SET_USER *t = base;

	OutRpcAuthData(p, t->AuthData, t->AuthType);
}
static void RpcSetUserAuthDataIn(const RPC_FIELD *f, void *base, PACK *p, UINT index, UINT total)
{
	RPC_SET_USER *t = base;

	t->AuthData = InRpcAuthData(p, &t->AuthType, t->Name);
}
static void RpcSetUserAuthDataFree(const RPC_FIELD *f, void *base)
{
	RPC_SET_USER *t = base;

	FreeAuthData(t->AuthType, t->AuthData);
}
static const RPC_HOOK rpc_set_user_auth_data_hook = {RpcSetUserAuthDataOut, RpcSetUserAuthDataIn, RpcSetUserAuthDataFree};

// Optional policy: "UsePolicy" and the policy, only when the POLICY pointer is set
static void RpcSetUserPolicyOut(const RPC_FIELD *f, PACK *p, void *base, UINT index, UINT total)
{
	POLICY *policy = *((POLICY **)(((UCHAR *)base) + f->Offset));

	if (policy != NULL)
	{
		PackAddBool(p, f->Key, true);
		OutRpcPolicy(p, policy);
	}
}
static void RpcSetUserPolicyIn(const RPC_FIELD *f, void *base, PACK *p, UINT index, UINT total)
{
	POLICY **policy = (POLICY **)(((UCHAR *)base) + f->Offset);

	if (PackGetBool(p, f->Key))
	{
		*policy = ZeroMalloc(sizeof(POLICY));
		InRpcPolicy(*policy, p);
	}
}
static void RpcSetUserPolicyFree(const RPC_FIELD *f, void *base)
{
	Free(*((POLICY **)(((UCHAR *)base) + f->Offset)));
}
static const RPC_HOOK rpc_set_user_policy_hook = {RpcSetUserPolicyOut, RpcSetUserPolicyIn, RpcSetUserPolicyFree};

static const RPC_FIELD rpc_set_user_fields[] =
{
	RPC_ROW_STR(RPC_SET_USER, HubName, "HubName"),
	RPC_ROW_STR(RPC_SET_USER, Name, "Name"),
	RPC_ROW_STR(RPC_SET_USER, GroupName, "GroupName"),
	RPC_ROW_UNISTR(RPC_SET_USER, Realname, "Realname"),
	RPC_ROW_UNISTR(RPC_SET_USER, Note, "Note"),
	RPC_ROW_TIME64(RPC_SET_USER, CreatedTime, "CreatedTime"),
	RPC_ROW_TIME64(RPC_SET_USER, UpdatedTime, "UpdatedTime"),
	RPC_ROW_TIME64(RPC_SET_USER, ExpireTime, "ExpireTime"),
	RPC_ROW_OPAQUE(RPC_SET_USER, AuthData, "AuthType", 0, &rpc_set_user_auth_data_hook),
	RPC_ROW_INT(RPC_SET_USER, NumLogin, "NumLogin"),
	RPC_ROW_HOOK(RPC_FT_STRUCT, RPC_SET_USER, Traffic, NULL, 0, &rpc_set_user_traffic_hook),
	RPC_ROW_OPAQUE(RPC_SET_USER, Policy, "UsePolicy", 0, &rpc_set_user_policy_hook),
	RPC_ROW_END
};
RPC_TABLE_DEF(rpc_set_user_table, RPC_SET_USER, rpc_set_user_fields);

void InRpcSetUser(RPC_SET_USER *t, PACK *p)
{
	RpcFieldIn(&rpc_set_user_table, t, p);
}

void OutRpcSetUser(PACK *p, RPC_SET_USER *t)
{
	RpcFieldOut(&rpc_set_user_table, p, t);
}
void FreeRpcSetUser(RPC_SET_USER *t)
{
	RpcFieldFree(&rpc_set_user_table, t);
}

// Embedded TRAFFIC of an item through the indexed TRAFFIC entry points
static void RpcEnumUserTrafficOut(const RPC_FIELD *f, PACK *p, void *base, UINT index, UINT total)
{
	OutRpcTrafficEx((TRAFFIC *)(((UCHAR *)base) + f->Offset), p, index, total);
}
static void RpcEnumUserTrafficIn(const RPC_FIELD *f, void *base, PACK *p, UINT index, UINT total)
{
	InRpcTrafficEx((TRAFFIC *)(((UCHAR *)base) + f->Offset), p, index);
}
static const RPC_HOOK rpc_enum_user_traffic_hook = {RpcEnumUserTrafficOut, RpcEnumUserTrafficIn, NULL};

static const RPC_FIELD rpc_enum_user_item_fields[] =
{
	RPC_ROW_STR(RPC_ENUM_USER_ITEM, Name, "Name"),
	RPC_ROW_STR(RPC_ENUM_USER_ITEM, GroupName, "GroupName"),
	RPC_ROW_UNISTR(RPC_ENUM_USER_ITEM, Realname, "Realname"),
	RPC_ROW_UNISTR(RPC_ENUM_USER_ITEM, Note, "Note"),
	RPC_ROW_INT(RPC_ENUM_USER_ITEM, AuthType, "AuthType"),
	RPC_ROW_TIME64(RPC_ENUM_USER_ITEM, LastLoginTime, "LastLoginTime"),
	RPC_ROW_INT(RPC_ENUM_USER_ITEM, NumLogin, "NumLogin"),
	RPC_ROW_BOOL(RPC_ENUM_USER_ITEM, DenyAccess, "DenyAccess"),
	RPC_ROW_BOOL(RPC_ENUM_USER_ITEM, IsTrafficFilled, "IsTrafficFilled"),
	RPC_ROW_HOOK(RPC_FT_STRUCT, RPC_ENUM_USER_ITEM, Traffic, NULL, 0, &rpc_enum_user_traffic_hook),
	RPC_ROW_BOOL(RPC_ENUM_USER_ITEM, IsExpiresFilled, "IsExpiresFilled"),
	RPC_ROW_TIME64(RPC_ENUM_USER_ITEM, Expires, "Expires"),
	RPC_ROW_END
};
RPC_TABLE_DEF(rpc_enum_user_item_table, RPC_ENUM_USER_ITEM, rpc_enum_user_item_fields);

static const RPC_FIELD rpc_enum_user_fields[] =
{
	RPC_ROW_STR(RPC_ENUM_USER, HubName, "HubName"),
	RPC_ROW_ARRAY(RPC_ENUM_USER, Users, NumUser, &rpc_enum_user_item_table, "Name", 0),
	RPC_ROW_END
};
RPC_TABLE_DEF(rpc_enum_user_table, RPC_ENUM_USER, rpc_enum_user_fields);

void InRpcEnumUser(RPC_ENUM_USER *t, PACK *p)
{
	RpcFieldIn(&rpc_enum_user_table, t, p);
}
void OutRpcEnumUser(PACK *p, RPC_ENUM_USER *t)
{
	RpcFieldOut(&rpc_enum_user_table, p, t);
}
void FreeRpcEnumUser(RPC_ENUM_USER *t)
{
	RpcFieldFree(&rpc_enum_user_table, t);
}

// TRAFFIC and the optional policy use the RPC_SET_USER hooks
static const RPC_FIELD rpc_set_group_fields[] =
{
	RPC_ROW_STR(RPC_SET_GROUP, HubName, "HubName"),
	RPC_ROW_STR(RPC_SET_GROUP, Name, "Name"),
	RPC_ROW_UNISTR(RPC_SET_GROUP, Realname, "Realname"),
	RPC_ROW_UNISTR(RPC_SET_GROUP, Note, "Note"),
	RPC_ROW_HOOK(RPC_FT_STRUCT, RPC_SET_GROUP, Traffic, NULL, 0, &rpc_set_user_traffic_hook),
	RPC_ROW_OPAQUE(RPC_SET_GROUP, Policy, "UsePolicy", 0, &rpc_set_user_policy_hook),
	RPC_ROW_END
};
RPC_TABLE_DEF(rpc_set_group_table, RPC_SET_GROUP, rpc_set_group_fields);

void InRpcSetGroup(RPC_SET_GROUP *t, PACK *p)
{
	RpcFieldIn(&rpc_set_group_table, t, p);
}
void OutRpcSetGroup(PACK *p, RPC_SET_GROUP *t)
{
	RpcFieldOut(&rpc_set_group_table, p, t);
}
void FreeRpcSetGroup(RPC_SET_GROUP *t)
{
	RpcFieldFree(&rpc_set_group_table, t);
}

static const RPC_FIELD rpc_enum_group_item_fields[] =
{
	RPC_ROW_STR(RPC_ENUM_GROUP_ITEM, Name, "Name"),
	RPC_ROW_UNISTR(RPC_ENUM_GROUP_ITEM, Realname, "Realname"),
	RPC_ROW_UNISTR(RPC_ENUM_GROUP_ITEM, Note, "Note"),
	RPC_ROW_INT(RPC_ENUM_GROUP_ITEM, NumUsers, "NumUsers"),
	RPC_ROW_BOOL(RPC_ENUM_GROUP_ITEM, DenyAccess, "DenyAccess"),
	RPC_ROW_END
};
RPC_TABLE_DEF(rpc_enum_group_item_table, RPC_ENUM_GROUP_ITEM, rpc_enum_group_item_fields);

static const RPC_FIELD rpc_enum_group_fields[] =
{
	RPC_ROW_STR(RPC_ENUM_GROUP, HubName, "HubName"),
	RPC_ROW_ARRAY(RPC_ENUM_GROUP, Groups, NumGroup, &rpc_enum_group_item_table, "Name", 0),
	RPC_ROW_END
};
RPC_TABLE_DEF(rpc_enum_group_table, RPC_ENUM_GROUP, rpc_enum_group_fields);

void InRpcEnumGroup(RPC_ENUM_GROUP *t, PACK *p)
{
	RpcFieldIn(&rpc_enum_group_table, t, p);
}
void OutRpcEnumGroup(PACK *p, RPC_ENUM_GROUP *t)
{
	RpcFieldOut(&rpc_enum_group_table, p, t);
}
void FreeRpcEnumGroup(RPC_ENUM_GROUP *t)
{
	RpcFieldFree(&rpc_enum_group_table, t);
}

static const RPC_FIELD rpc_delete_user_fields[] =
{
	RPC_ROW_STR(RPC_DELETE_USER, HubName, "HubName"),
	RPC_ROW_STR(RPC_DELETE_USER, Name, "Name"),
	RPC_ROW_END
};
RPC_TABLE_DEF(rpc_delete_user_table, RPC_DELETE_USER, rpc_delete_user_fields);

void InRpcDeleteUser(RPC_DELETE_USER *t, PACK *p)
{
	RpcFieldIn(&rpc_delete_user_table, t, p);
}
void OutRpcDeleteUser(PACK *p, RPC_DELETE_USER *t)
{
	RpcFieldOut(&rpc_delete_user_table, p, t);
}

// Ip is read as a plain integer; the write side uses the IPv4 helper
static void RpcEnumSessionIpIn(const RPC_FIELD *f, void *base, PACK *p, UINT index, UINT total)
{
	*((UINT *)(((UCHAR *)base) + f->Offset)) = PackGetIntEx(p, f->Key, index);
}
static const RPC_HOOK rpc_enum_session_ip_hook = {NULL, RpcEnumSessionIpIn, NULL};

static const RPC_FIELD rpc_enum_session_item_fields[] =
{
	RPC_ROW_STR(RPC_ENUM_SESSION_ITEM, Name, "Name"),
	RPC_ROW_STR(RPC_ENUM_SESSION_ITEM, Username, "Username"),
	RPC_ROW_HOOK(RPC_FT_IP32, RPC_ENUM_SESSION_ITEM, Ip, "Ip", 0, &rpc_enum_session_ip_hook),
	RPC_ROW_IP(RPC_ENUM_SESSION_ITEM, ClientIP, "ClientIP"),
	RPC_ROW_STR(RPC_ENUM_SESSION_ITEM, Hostname, "Hostname"),
	RPC_ROW_INT(RPC_ENUM_SESSION_ITEM, MaxNumTcp, "MaxNumTcp"),
	RPC_ROW_INT(RPC_ENUM_SESSION_ITEM, CurrentNumTcp, "CurrentNumTcp"),
	RPC_ROW_INT64(RPC_ENUM_SESSION_ITEM, PacketSize, "PacketSize"),
	RPC_ROW_INT64(RPC_ENUM_SESSION_ITEM, PacketNum, "PacketNum"),
	RPC_ROW_BOOL(RPC_ENUM_SESSION_ITEM, LinkMode, "LinkMode"),
	RPC_ROW_BOOL(RPC_ENUM_SESSION_ITEM, BridgeMode, "BridgeMode"),
	RPC_ROW_BOOL(RPC_ENUM_SESSION_ITEM, Client_BridgeMode, "Client_BridgeMode"),
	RPC_ROW_BOOL(RPC_ENUM_SESSION_ITEM, Client_MonitorMode, "Client_MonitorMode"),
	RPC_ROW_INT(RPC_ENUM_SESSION_ITEM, VLanId, "VLanId"),
	RPC_ROW_DATA(RPC_ENUM_SESSION_ITEM, UniqueId, "UniqueId"),
	RPC_ROW_BOOL(RPC_ENUM_SESSION_ITEM, IsDormantEnabled, "IsDormantEnabled"),
	RPC_ROW_BOOL(RPC_ENUM_SESSION_ITEM, IsDormant, "IsDormant"),
	RPC_ROW_TIME64(RPC_ENUM_SESSION_ITEM, LastCommDormant, "LastCommDormant"),
	RPC_ROW_TIME64(RPC_ENUM_SESSION_ITEM, CreatedTime, "CreatedTime"),
	RPC_ROW_TIME64(RPC_ENUM_SESSION_ITEM, LastCommTime, "LastCommTime"),
	RPC_ROW_END
};
RPC_TABLE_DEF(rpc_enum_session_item_table, RPC_ENUM_SESSION_ITEM, rpc_enum_session_item_fields);

static const RPC_FIELD rpc_enum_session_fields[] =
{
	RPC_ROW_STR(RPC_ENUM_SESSION, HubName, "HubName"),
	RPC_ROW_ARRAY(RPC_ENUM_SESSION, Sessions, NumSession, &rpc_enum_session_item_table, "Name", 0),
	RPC_ROW_END
};
RPC_TABLE_DEF(rpc_enum_session_table, RPC_ENUM_SESSION, rpc_enum_session_fields);

void InRpcEnumSession(RPC_ENUM_SESSION *t, PACK *p)
{
	RpcFieldIn(&rpc_enum_session_table, t, p);
}
void OutRpcEnumSession(PACK *p, RPC_ENUM_SESSION *t)
{
	RpcFieldOut(&rpc_enum_session_table, p, t);
}
void FreeRpcEnumSession(RPC_ENUM_SESSION *t)
{
	RpcFieldFree(&rpc_enum_session_table, t);
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

	t->ClientProductVer = PackGetInt(p, "ClientProductVer");
	t->ClientProductBuild = PackGetInt(p, "ClientProductBuild");
	t->ServerProductVer = PackGetInt(p, "ServerProductVer");
	t->ServerProductBuild = PackGetInt(p, "ServerProductBuild");
	t->ClientIpAddress = PackGetIp32(p, "ClientIpAddress");
	PackGetData2(p, "ClientIpAddress6", t->ClientIpAddress6, sizeof(t->ClientIpAddress6));
	t->ClientPort = PackGetInt(p, "ClientPort");
	t->ServerIpAddress = PackGetIp32(p, "ServerIpAddress");
	PackGetData2(p, "ServerIpAddress6", t->ServerIpAddress6, sizeof(t->ServerIpAddress6));
	t->ServerPort = PackGetInt(p, "ServerPort2");
	t->ProxyIpAddress = PackGetIp32(p, "ProxyIpAddress");
	PackGetData2(p, "ProxyIpAddress6", t->ProxyIpAddress6, sizeof(t->ProxyIpAddress6));
	t->ProxyPort = PackGetInt(p, "ProxyPort");
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

	PackAddInt(p, "ClientProductVer", t->ClientProductVer);
	PackAddInt(p, "ClientProductBuild", t->ClientProductBuild);
	PackAddInt(p, "ServerProductVer", t->ServerProductVer);
	PackAddInt(p, "ServerProductBuild", t->ServerProductBuild);
	PackAddIp32(p, "ClientIpAddress", t->ClientIpAddress);
	PackAddData(p, "ClientIpAddress6", t->ClientIpAddress6, sizeof(t->ClientIpAddress6));
	PackAddInt(p, "ClientPort", t->ClientPort);
	PackAddIp32(p, "ServerIpAddress", t->ServerIpAddress);
	PackAddData(p, "ServerIpAddress6", t->ServerIpAddress6, sizeof(t->ServerIpAddress6));
	PackAddInt(p, "ServerPort2", t->ServerPort);
	PackAddIp32(p, "ProxyIpAddress", t->ProxyIpAddress);
	PackAddData(p, "ProxyIpAddress6", t->ProxyIpAddress6, sizeof(t->ProxyIpAddress6));
	PackAddInt(p, "ProxyPort", t->ProxyPort);
}

// Embedded connection status, through its own entry points (Free releases its certificates)
static void RpcSessionStatusStatusOut(const RPC_FIELD *f, PACK *p, void *base, UINT index, UINT total)
{
	OutRpcClientGetConnectionStatus(p, (RPC_CLIENT_GET_CONNECTION_STATUS *)(((UCHAR *)base) + f->Offset));
}
static void RpcSessionStatusStatusIn(const RPC_FIELD *f, void *base, PACK *p, UINT index, UINT total)
{
	InRpcClientGetConnectionStatus((RPC_CLIENT_GET_CONNECTION_STATUS *)(((UCHAR *)base) + f->Offset), p);
}
static void RpcSessionStatusStatusFree(const RPC_FIELD *f, void *base)
{
	CiFreeClientGetConnectionStatus((RPC_CLIENT_GET_CONNECTION_STATUS *)(((UCHAR *)base) + f->Offset));
}
static const RPC_HOOK rpc_session_status_status_hook =
{
	RpcSessionStatusStatusOut, RpcSessionStatusStatusIn, RpcSessionStatusStatusFree
};

// Embedded node information, through its own entry points
static void RpcSessionStatusNodeInfoOut(const RPC_FIELD *f, PACK *p, void *base, UINT index, UINT total)
{
	OutRpcNodeInfo(p, (NODE_INFO *)(((UCHAR *)base) + f->Offset));
}
static void RpcSessionStatusNodeInfoIn(const RPC_FIELD *f, void *base, PACK *p, UINT index, UINT total)
{
	InRpcNodeInfo((NODE_INFO *)(((UCHAR *)base) + f->Offset), p);
}
static const RPC_HOOK rpc_session_status_node_info_hook =
{
	RpcSessionStatusNodeInfoOut, RpcSessionStatusNodeInfoIn, NULL
};

// The direct rows come first, then the connection status, then the node
// information: on a colliding key the first writer wins
static const RPC_FIELD rpc_session_status_fields[] =
{
	RPC_ROW_STR(RPC_SESSION_STATUS, HubName, "HubName"),
	RPC_ROW_STR(RPC_SESSION_STATUS, Name, "Name"),
	RPC_ROW_STR(RPC_SESSION_STATUS, Username, "Username"),
	RPC_ROW_STR(RPC_SESSION_STATUS, GroupName, "GroupName"),
	RPC_ROW_STR(RPC_SESSION_STATUS, RealUsername, "RealUsername"),
	RPC_ROW_IP32(RPC_SESSION_STATUS, ClientIp, "SessionStatus_ClientIp"),
	RPC_ROW_DATA(RPC_SESSION_STATUS, ClientIp6, "SessionStatus_ClientIp6"),
	RPC_ROW_STR(RPC_SESSION_STATUS, ClientHostName, "SessionStatus_ClientHostName"),
	RPC_ROW_IP(RPC_SESSION_STATUS, ClientIpAddress, "Client_Ip_Address"),
	RPC_ROW_HOOK(RPC_FT_STRUCT, RPC_SESSION_STATUS, Status, NULL, 0, &rpc_session_status_status_hook),
	RPC_ROW_HOOK(RPC_FT_STRUCT, RPC_SESSION_STATUS, NodeInfo, NULL, 0, &rpc_session_status_node_info_hook),
	RPC_ROW_END
};
RPC_TABLE_DEF(rpc_session_status_table, RPC_SESSION_STATUS, rpc_session_status_fields);

void InRpcSessionStatus(RPC_SESSION_STATUS *t, PACK *p)
{
	RpcFieldIn(&rpc_session_status_table, t, p);
}
void OutRpcSessionStatus(PACK *p, RPC_SESSION_STATUS *t)
{
	RpcFieldOut(&rpc_session_status_table, p, t);
}
void FreeRpcSessionStatus(RPC_SESSION_STATUS *t)
{
	RpcFieldFree(&rpc_session_status_table, t);
}

static const RPC_FIELD rpc_delete_session_fields[] =
{
	RPC_ROW_STR(RPC_DELETE_SESSION, HubName, "HubName"),
	RPC_ROW_STR(RPC_DELETE_SESSION, Name, "Name"),
	RPC_ROW_END
};
RPC_TABLE_DEF(rpc_delete_session_table, RPC_DELETE_SESSION, rpc_delete_session_fields);

void InRpcDeleteSession(RPC_DELETE_SESSION *t, PACK *p)
{
	RpcFieldIn(&rpc_delete_session_table, t, p);
}
void OutRpcDeleteSession(PACK *p, RPC_DELETE_SESSION *t)
{
	RpcFieldOut(&rpc_delete_session_table, p, t);
}

static const RPC_FIELD rpc_enum_mac_table_item_fields[] =
{
	RPC_ROW_INT(RPC_ENUM_MAC_TABLE_ITEM, Key, "Key"),
	RPC_ROW_STR(RPC_ENUM_MAC_TABLE_ITEM, SessionName, "SessionName"),
	RPC_ROW_DATA(RPC_ENUM_MAC_TABLE_ITEM, MacAddress, "MacAddress"),
	RPC_ROW_INT(RPC_ENUM_MAC_TABLE_ITEM, VlanId, "VlanId"),
	RPC_ROW_TIME64(RPC_ENUM_MAC_TABLE_ITEM, CreatedTime, "CreatedTime"),
	RPC_ROW_TIME64(RPC_ENUM_MAC_TABLE_ITEM, UpdatedTime, "UpdatedTime"),
	RPC_ROW_END
};
RPC_TABLE_DEF(rpc_enum_mac_table_item_table, RPC_ENUM_MAC_TABLE_ITEM, rpc_enum_mac_table_item_fields);

static const RPC_FIELD rpc_enum_mac_table_fields[] =
{
	RPC_ROW_STR(RPC_ENUM_MAC_TABLE, HubName, "HubName"),
	RPC_ROW_ARRAY(RPC_ENUM_MAC_TABLE, MacTables, NumMacTable, &rpc_enum_mac_table_item_table, "SessionName", 0),
	RPC_ROW_END
};
RPC_TABLE_DEF(rpc_enum_mac_table_table, RPC_ENUM_MAC_TABLE, rpc_enum_mac_table_fields);

void InRpcEnumMacTable(RPC_ENUM_MAC_TABLE *t, PACK *p)
{
	RpcFieldIn(&rpc_enum_mac_table_table, t, p);
}
void OutRpcEnumMacTable(PACK *p, RPC_ENUM_MAC_TABLE *t)
{
	RpcFieldOut(&rpc_enum_mac_table_table, p, t);
}
void FreeRpcEnumMacTable(RPC_ENUM_MAC_TABLE *t)
{
	RpcFieldFree(&rpc_enum_mac_table_table, t);
}

// IpV6: when the peer sent none, it comes from Ip (the row before)
static void RpcEnumIpTableIpV6In(const RPC_FIELD *f, void *base, PACK *p, UINT index, UINT total)
{
	RPC_ENUM_IP_TABLE_ITEM *e = (RPC_ENUM_IP_TABLE_ITEM *)base;
	IP *ip = (IP *)(((UCHAR *)base) + f->Offset);

	if (PackGetIpEx(p, f->Key, ip, index) == false)
	{
		UINTToIP(ip, e->Ip);
	}
}
static const RPC_HOOK rpc_enum_ip_table_ipv6_hook = {NULL, RpcEnumIpTableIpV6In, NULL};

// IpAddress is read without the index, as before: every item gets the first address
static void RpcEnumIpTableIpAddressIn(const RPC_FIELD *f, void *base, PACK *p, UINT index, UINT total)
{
	PackGetIp(p, f->Key, (IP *)(((UCHAR *)base) + f->Offset));
}
static const RPC_HOOK rpc_enum_ip_table_ip_address_hook = {NULL, RpcEnumIpTableIpAddressIn, NULL};

static const RPC_FIELD rpc_enum_ip_table_item_fields[] =
{
	RPC_ROW_INT(RPC_ENUM_IP_TABLE_ITEM, Key, "Key"),
	RPC_ROW_STR(RPC_ENUM_IP_TABLE_ITEM, SessionName, "SessionName"),
	RPC_ROW_IP32(RPC_ENUM_IP_TABLE_ITEM, Ip, "Ip"),
	RPC_ROW_HOOK(RPC_FT_IP, RPC_ENUM_IP_TABLE_ITEM, IpV6, "IpV6", 0, &rpc_enum_ip_table_ipv6_hook),
	RPC_ROW_HOOK(RPC_FT_IP, RPC_ENUM_IP_TABLE_ITEM, IpAddress, "IpAddress", 0, &rpc_enum_ip_table_ip_address_hook),
	RPC_ROW_BOOL(RPC_ENUM_IP_TABLE_ITEM, DhcpAllocated, "DhcpAllocated"),
	RPC_ROW_TIME64(RPC_ENUM_IP_TABLE_ITEM, CreatedTime, "CreatedTime"),
	RPC_ROW_TIME64(RPC_ENUM_IP_TABLE_ITEM, UpdatedTime, "UpdatedTime"),
	RPC_ROW_END
};
RPC_TABLE_DEF(rpc_enum_ip_table_item_table, RPC_ENUM_IP_TABLE_ITEM, rpc_enum_ip_table_item_fields);

static const RPC_FIELD rpc_enum_ip_table_fields[] =
{
	RPC_ROW_STR(RPC_ENUM_IP_TABLE, HubName, "HubName"),
	RPC_ROW_ARRAY(RPC_ENUM_IP_TABLE, IpTables, NumIpTable, &rpc_enum_ip_table_item_table, "SessionName", 0),
	RPC_ROW_END
};
RPC_TABLE_DEF(rpc_enum_ip_table_table, RPC_ENUM_IP_TABLE, rpc_enum_ip_table_fields);

void InRpcEnumIpTable(RPC_ENUM_IP_TABLE *t, PACK *p)
{
	RpcFieldIn(&rpc_enum_ip_table_table, t, p);
}
void OutRpcEnumIpTable(PACK *p, RPC_ENUM_IP_TABLE *t)
{
	RpcFieldOut(&rpc_enum_ip_table_table, p, t);
}
void FreeRpcEnumIpTable(RPC_ENUM_IP_TABLE *t)
{
	RpcFieldFree(&rpc_enum_ip_table_table, t);
}

static const RPC_FIELD rpc_delete_table_fields[] =
{
	RPC_ROW_STR(RPC_DELETE_TABLE, HubName, "HubName"),
	RPC_ROW_INT(RPC_DELETE_TABLE, Key, "Key"),
	RPC_ROW_END
};
RPC_TABLE_DEF(rpc_delete_table_table, RPC_DELETE_TABLE, rpc_delete_table_fields);

void InRpcDeleteTable(RPC_DELETE_TABLE *t, PACK *p)
{
	RpcFieldIn(&rpc_delete_table_table, t, p);
}
void OutRpcDeleteTable(PACK *p, RPC_DELETE_TABLE *t)
{
	RpcFieldOut(&rpc_delete_table_table, p, t);
}

static const RPC_FIELD rpc_test_fields[] =
{
	RPC_ROW_INT(RPC_TEST, IntValue, "IntValue"),
	RPC_ROW_INT64(RPC_TEST, Int64Value, "Int64Value"),
	RPC_ROW_STR(RPC_TEST, StrValue, "StrValue"),
	RPC_ROW_UNISTR(RPC_TEST, UniStrValue, "UniStrValue"),
	RPC_ROW_END
};
RPC_TABLE_DEF(rpc_test_table, RPC_TEST, rpc_test_fields);

void InRpcTest(RPC_TEST *t, PACK *p)
{
	RpcFieldIn(&rpc_test_table, t, p);
}
void OutRpcTest(PACK *p, RPC_TEST *t)
{
	RpcFieldOut(&rpc_test_table, p, t);
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

static bool CheckAdminSourceAddress(IP *remote_ip, char *hubname)
{
	BUF *b;
	char *s;
	bool ok = false;
	if (remote_ip == NULL)
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
						if (IsIP4(remote_ip) && IsIP4(&ip))
						{
							IPAnd4(&ip1, remote_ip, &mask);
							IPAnd4(&ip2, &ip, &mask);

							if (CmpIpAddr(&ip1, &ip2) == 0)
							{
								ok = true;
							}
						}
						else if (IsIP6(remote_ip) && IsIP6(&ip))
						{
							IPAnd6(&ip1, remote_ip, &mask);
							IPAnd6(&ip2, &ip, &mask);

							if (CmpIpAddr(&ip1, &ip2) == 0)
							{
								ok = true;
							}
						}
					}
					else if (StrToIP(&ip, t->Token[0]))
					{
						if (CmpIpAddr(remote_ip, &ip) == 0)
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

// Open an admin session: the source address list, the password and the empty-password policy, with the LA_* log lines
ADMIN *AdminOpen(SERVER *server, ADMIN_LOGIN *login, UINT *err)
{
	ADMIN *a;
	CEDAR *cedar;
	UINT e;
	bool is_empty_password = false;
	bool hub_scope;
	UCHAR null_password[SHA1_SIZE];
	UCHAR secure_null_password[SHA1_SIZE];
	UINT dummy;
	if (err == NULL)
	{
		err = &dummy;
	}
	if (server == NULL || login == NULL)
	{
		*err = ERR_INTERNAL_ERROR;
		return NULL;
	}

	cedar = server->Cedar;
	hub_scope = (StrLen(login->HubName) != 0);

	if (CheckAdminSourceAddress(&login->RemoteIP, login->HubName) == false)
	{
		SLog(cedar, "LA_IP_DENIED", login->ConnName);
		*err = ERR_IP_ADDRESS_DENIED;
		return NULL;
	}

	if (login->HasSecurePassword == false)
	{
		*err = ERR_PROTOCOL_ERROR;
		return NULL;
	}

	if (hub_scope == false)
	{
		SLog(cedar, "LA_CONNECTED_1", login->ConnName);
	}
	else
	{
		SLog(cedar, "LA_CONNECTED_2", login->ConnName, login->HubName);
	}

	e = AdminCheckPassword(cedar, login->Random, login->SecurePassword,
		hub_scope ? login->HubName : NULL, login->AcceptEmptyPassword, &is_empty_password);

	if (e != ERR_NO_ERROR)
	{
		SLog(cedar, "LA_ERROR", login->ConnName, GetUniErrorStr(e), e);
		*err = e;
		return NULL;
	}

	SLog(cedar, "LA_OK", login->ConnName);

	HashAdminPassword(null_password, "");
	SecurePassword(secure_null_password, null_password, login->Random);

	if (Cmp(secure_null_password, login->SecurePassword, SHA1_SIZE) == 0)
	{
		if (IsLocalHostIP(&login->RemoteIP) == false)
		{
			// Refuse a blank hub admin password from a remote client
			if (hub_scope)
			{
				*err = ERR_NULL_PASSWORD_LOCAL_ONLY;
				return NULL;
			}
		}
	}

	a = ZeroMalloc(sizeof(ADMIN));
	a->Server = server;
	a->ServerAdmin = (hub_scope ? false : true);
	a->HubName = (hub_scope ? CopyStr(login->HubName) : NULL);
	Copy(&a->RemoteIP, &login->RemoteIP, sizeof(IP));
	Format(a->Tag, sizeof(a->Tag), "RPC-%u", login->Id);
	a->EmptyPassword = (login->AcceptEmptyPassword && is_empty_password);
	Copy(&a->ClientWinVer, &login->ClientWinVer, sizeof(RPC_WINVER));

	*err = ERR_NO_ERROR;

	return a;
}

// Free an admin session
void AdminClose(ADMIN *a)
{
	if (a == NULL)
	{
		return;
	}

	if (a->LogFileList != NULL)
	{
		FreeEnumLogFile(a->LogFileList);
	}

	Free(a->HubName);
	Free(a);
}

// RPC server dispatcher of the admin connection: the session is the RPC parameter
static PACK *AdminDispatch(RPC *rpc, char *name, PACK *p)
{
	if (rpc == NULL)
	{
		return NULL;
	}

	return AdminInvoke((ADMIN *)rpc->Param, name, p);
}

UINT AdminAccept(CONNECTION *c, PACK *p)
{
	ADMIN_LOGIN login;
	ADMIN *a;
	SOCK *sock;
	RPC *rpc;
	UINT err;
	if (c == NULL || p == NULL || c->FirstSock == NULL || c->Cedar == NULL || c->Cedar->Server == NULL)
	{
		return ERR_INTERNAL_ERROR;
	}

	sock = c->FirstSock;

	Zero(&login, sizeof(login));
	StrCpy(login.ConnName, sizeof(login.ConnName), c->Name);
	Copy(&login.RemoteIP, &sock->RemoteIP, sizeof(IP));
	login.Id = sock->socket;
	Copy(login.Random, c->Random, SHA1_SIZE);
	login.AcceptEmptyPassword = PackGetBool(p, "accept_empty_password");
	InRpcWinVer(&login.ClientWinVer, p);
	PackGetStr(p, "hubname", login.HubName, sizeof(login.HubName));
	if (PackGetDataSize(p, "secure_password") == SHA1_SIZE)
	{
		PackGetData(p, "secure_password", login.SecurePassword);
		login.HasSecurePassword = true;
	}

	a = AdminOpen(c->Cedar->Server, &login, &err);
	if (a == NULL)
	{
		return err;
	}

	p = NewPack();
	if (a->EmptyPassword)
	{
		PackAddBool(p, "empty_password", true);
	}
	HttpServerSend(sock, p);
	FreePack(p);

	SetTimeout(sock, INFINITE);

	rpc = NewRpc(sock, AdminDispatch, a);

	SLog(c->Cedar, "LA_RPC_START", c->Name, a->Tag);

	RpcServer(rpc);
	RpcFree(rpc);

	AdminClose(a);

	return ERR_NO_ERROR;
}

static UINT AdminCheckPassword(CEDAR *c, void *random, void *secure_password, char *hubname,
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
		HUB *h = GetHub(c, hubname);

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

static SESSION *AdminConnectMain(CEDAR *cedar, CLIENT_OPTION *o, char *hubname, void *hashed_password, UINT *err, char *client_name, bool *empty_password)
{
	UCHAR secure_password[SHA1_SIZE];
	SESSION *s;
	CONNECTION *c;
	SOCK *sock;
	PACK *p;
	RPC_WINVER ver;
	s = NewRpcSession(cedar, o, err, client_name);
	if (s == NULL)
	{
		return NULL;
	}

	// The connection NewRpcSession opened and logged in: the admin RPC runs on its first socket
	c = s->Connection;
	sock = c->FirstSock;

	p = NewPack();

	PackAddClientVersion(p, c);

	PackAddStr(p, "method", "admin");
	PackAddBool(p, "accept_empty_password", true);

	GetWinVer(&ver);
	OutRpcWinVer(p, &ver);

	SecurePassword(secure_password, hashed_password, c->Random);

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

// The socket an admin RPC uses after the login of its session (AdminConnectMain), at the first connect and at every
// reconnect: no timeout, because the server can take long to answer an RPC (SetConfig, a large EnumSession or
// EnumLogFile) and the connect left CONNECTING_TIMEOUT on the socket. The caller takes its own reference
static SOCK *AdminRpcSock(SESSION *s)
{
	CONNECTION *c = s->Connection;
	SOCK *sock = c->FirstSock;

	SetTimeout(sock, INFINITE);

	return sock;
}

RPC *AdminConnectEx(CEDAR *cedar, CLIENT_OPTION *o, char *hubname, void *hashed_password, UINT *err, char *client_name)
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

	s = AdminConnectMain(cedar, o, hubname, hashed_password_2, err, client_name, &empty_password);

	if (s == NULL)
	{
		return NULL;
	}

	sock = AdminRpcSock(s);

	rpc = NewRpc(sock, NULL, s);

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

	return rpc;
}

UINT AdminReconnect(RPC *rpc)
{
	SESSION *s;
	SOCK *sock;
	CEDAR *cedar;
	UINT err;
	bool empty_password = false;
	if (rpc == NULL)
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
		rpc->VpnServerClientName, &empty_password);

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
	rpc->Sock = AdminRpcSock(s);
	AddRef(rpc->Sock->ref);

	return ERR_NO_ERROR;
}

static bool SiIsEmptyPassword(void *hash_password)
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

