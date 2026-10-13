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

static UINT StRegenerateServerCert(ADMIN *a, RPC_TEST *t);
static UINT StSetHubMsg(ADMIN *a, RPC_MSG *t);
static UINT StGetHubMsg(ADMIN *a, RPC_MSG *t);
static UINT StDebug(ADMIN *a, RPC_TEST *t);
static UINT StFlush(ADMIN *a, RPC_TEST *t);
static UINT StCrash(ADMIN *a, RPC_TEST *t);
static UINT StGetAdminMsg(ADMIN *a, RPC_MSG *t);
static UINT StEnumEthVLan(ADMIN *a, RPC_ENUM_ETH_VLAN *t);
static UINT StSetEnableEthVLan(ADMIN *a, RPC_TEST *t);
static UINT StGetLicenseStatus(ADMIN *a, RPC_LICENSE_STATUS *t);
static UINT StEnumLicenseKey(ADMIN *a, RPC_ENUM_LICENSE_KEY *t);
static UINT StAddLicenseKey(ADMIN *a, RPC_TEST *t);
static UINT StReadLogFile(ADMIN *a, RPC_READ_LOG_FILE *t);
static UINT StEnumLogFile(ADMIN *a, RPC_ENUM_LOG_FILE *t);
static UINT StGetAcList(ADMIN *a, RPC_AC_LIST *t);
static UINT StSetAcList(ADMIN *a, RPC_AC_LIST *t);
static UINT StSetCrl(ADMIN *a, RPC_CRL *t);
static UINT StGetCrl(ADMIN *a, RPC_CRL *t);
static UINT StDelCrl(ADMIN *a, RPC_CRL *t);
static UINT StAddCrl(ADMIN *a, RPC_CRL *t);
static UINT StEnumCrl(ADMIN *a, RPC_ENUM_CRL *t);
static UINT StSetHubExtOptions(ADMIN *a, RPC_ADMIN_OPTION *t);
static UINT StGetHubExtOptions(ADMIN *a, RPC_ADMIN_OPTION *t);
static UINT StSetHubAdminOptions(ADMIN *a, RPC_ADMIN_OPTION *t);
static UINT StGetHubAdminOptions(ADMIN *a, RPC_ADMIN_OPTION *t);
static UINT StGetDefaultHubAdminOptions(ADMIN *a, RPC_ADMIN_OPTION *t);
static UINT StGetConfig(ADMIN *a, RPC_CONFIG *t);
static UINT StSetConfig(ADMIN *a, RPC_CONFIG *t);
static UINT StGetCaps(ADMIN *a, CAPSLIST *t);
static UINT StRebootServer(ADMIN *a, RPC_TEST *t);
static UINT StGetBridgeSupport(ADMIN *a, RPC_BRIDGE_SUPPORT *t);
static UINT StEnumEthernet(ADMIN *a, RPC_ENUM_ETH *t);
static UINT StAddLocalBridge(ADMIN *a, RPC_LOCALBRIDGE *t);
static UINT StDeleteLocalBridge(ADMIN *a, RPC_LOCALBRIDGE *t);
static UINT StEnumLocalBridge(ADMIN *a, RPC_ENUM_LOCALBRIDGE *t);
static UINT StSetSysLog(ADMIN *a, SYSLOG_SETTING *t);
static UINT StGetSysLog(ADMIN *a, SYSLOG_SETTING *t);
static UINT StDeleteIpTable(ADMIN *a, RPC_DELETE_TABLE *t);
static UINT StEnumIpTable(ADMIN *a, RPC_ENUM_IP_TABLE *t);
static UINT StDeleteMacTable(ADMIN *a, RPC_DELETE_TABLE *t);
static UINT StEnumMacTable(ADMIN *a, RPC_ENUM_MAC_TABLE *t);
static UINT StDeleteSession(ADMIN *a, RPC_DELETE_SESSION *t);
static UINT StGetSessionStatus(ADMIN *a, RPC_SESSION_STATUS *t);
static UINT StEnumSession(ADMIN *a, RPC_ENUM_SESSION *t);
static UINT StEnumGroup(ADMIN *a, RPC_ENUM_GROUP *t);
static UINT StDeleteGroup(ADMIN *a, RPC_DELETE_USER *t);
static UINT StGetGroup(ADMIN *a, RPC_SET_GROUP *t);
static UINT StSetGroup(ADMIN *a, RPC_SET_GROUP *t);
static UINT StCreateGroup(ADMIN *a, RPC_SET_GROUP *t);
static UINT StEnumUser(ADMIN *a, RPC_ENUM_USER *t);
static UINT StDeleteUser(ADMIN *a, RPC_DELETE_USER *t);
static UINT StGetUser(ADMIN *a, RPC_SET_USER *t);
static UINT StSetUser(ADMIN *a, RPC_SET_USER *t);
static UINT StCreateUser(ADMIN *a, RPC_SET_USER *t);
static UINT StEnumAccess(ADMIN *a, RPC_ENUM_ACCESS_LIST *t);
static UINT StDeleteAccess(ADMIN *a, RPC_DELETE_ACCESS *t);
static UINT StSetAccessList(ADMIN *a, RPC_ENUM_ACCESS_LIST *t);
static UINT StAddAccess(ADMIN *a, RPC_ADD_ACCESS *t);
static UINT StRenameLink(ADMIN *a, RPC_RENAME_LINK *t);
static UINT StDeleteLink(ADMIN *a, RPC_LINK *t);
static UINT StSetLinkOffline(ADMIN *a, RPC_LINK *t);
static UINT StSetLinkOnline(ADMIN *a, RPC_LINK *t);
static UINT StGetLinkStatus(ADMIN *a, RPC_LINK_STATUS *t);
static UINT StEnumLink(ADMIN *a, RPC_ENUM_LINK *t);
static UINT StGetLink(ADMIN *a, RPC_CREATE_LINK *t);
static UINT StSetLink(ADMIN *a, RPC_CREATE_LINK *t);
static UINT StCreateLink(ADMIN *a, RPC_CREATE_LINK *t);
static UINT StDeleteCa(ADMIN *a, RPC_HUB_DELETE_CA *t);
static UINT StGetCa(ADMIN *a, RPC_HUB_GET_CA *t);
static UINT StEnumCa(ADMIN *a, RPC_HUB_ENUM_CA *t);
static UINT StAddCa(ADMIN *a, RPC_HUB_ADD_CA *t);
static UINT StGetHubLog(ADMIN *a, RPC_HUB_LOG *t);
static UINT StSetHubLog(ADMIN *a, RPC_HUB_LOG *t);
static UINT StGetHubStatus(ADMIN *a, RPC_HUB_STATUS *t);
static UINT StSetHubOnline(ADMIN *a, RPC_SET_HUB_ONLINE *t);
static UINT StGetConnectionInfo(ADMIN *a, RPC_CONNECTION_INFO *t);
static UINT StDisconnectConnection(ADMIN *a, RPC_DISCONNECT_CONNECTION *t);
static UINT StEnumConnection(ADMIN *a, RPC_ENUM_CONNECTION *t);
static UINT StDeleteHub(ADMIN *a, RPC_DELETE_HUB *t);
static UINT StEnumHub(ADMIN *a, RPC_ENUM_HUB *t);
static UINT StGetHub(ADMIN *a, RPC_CREATE_HUB *t);
static UINT StSetHub(ADMIN *a, RPC_CREATE_HUB *t);
static UINT StCreateHub(ADMIN *a, RPC_CREATE_HUB *t);
static UINT StSetServerCipher(ADMIN *a, RPC_STR *t);
static UINT StGetServerCipher(ADMIN *a, RPC_STR *t);
static UINT StGetServerCipherList(ADMIN *a, RPC_STR *t);
static UINT StGetServerCert(ADMIN *a, RPC_KEY_PAIR *t);
static UINT StSetServerCert(ADMIN *a, RPC_KEY_PAIR *t);
static UINT StSetServerPassword(ADMIN *a, RPC_SET_PASSWORD *t);
static UINT StEnableListener(ADMIN *a, RPC_LISTENER *t);
static UINT StDeleteListener(ADMIN *a, RPC_LISTENER *t);
static UINT StEnumListener(ADMIN *a, RPC_LISTENER_LIST *t);
static UINT StCreateListener(ADMIN *a, RPC_LISTENER *t);
static UINT StGetServerStatus(ADMIN *a, RPC_SERVER_STATUS *t);
static UINT StGetServerInfo(ADMIN *a, RPC_SERVER_INFO *t);
static void CopyOsInfo(OS_INFO *dst, OS_INFO *info);
static void InRpcMsg(RPC_MSG *t, PACK *p);
static void OutRpcMsg(PACK *p, RPC_MSG *t);
static void FreeRpcMsg(RPC_MSG *t);
static void InRpcEnumEthVLan(RPC_ENUM_ETH_VLAN *t, PACK *p);
static void OutRpcEnumEthVLan(PACK *p, RPC_ENUM_ETH_VLAN *t);
static void InRpcEnumLogFile(RPC_ENUM_LOG_FILE *t, PACK *p);
static void OutRpcEnumLogFile(PACK *p, RPC_ENUM_LOG_FILE *t);
static void InRpcReadLogFile(RPC_READ_LOG_FILE *t, PACK *p);
static void OutRpcReadLogFile(PACK *p, RPC_READ_LOG_FILE *t);
static void FreeRpcReadLogFile(RPC_READ_LOG_FILE *t);
static void InRpcAcList(RPC_AC_LIST *t, PACK *p);
static void OutRpcAcList(PACK *p, RPC_AC_LIST *t);
static void InRpcEnumCrl(RPC_ENUM_CRL *t, PACK *p);
static void OutRpcEnumCrl(PACK *p, RPC_ENUM_CRL *t);
static void InRpcCrl(RPC_CRL *t, PACK *p);
static void OutRpcCrl(PACK *p, RPC_CRL *t);
static void InRpcEnumEth(RPC_ENUM_ETH *t, PACK *p);
static void OutRpcEnumEth(PACK *p, RPC_ENUM_ETH *t);
static void InRpcLocalBridge(RPC_LOCALBRIDGE *t, PACK *p);
static void OutRpcLocalBridge(PACK *p, RPC_LOCALBRIDGE *t);
static void InRpcEnumLocalBridge(RPC_ENUM_LOCALBRIDGE *t, PACK *p);
static void OutRpcEnumLocalBridge(PACK *p, RPC_ENUM_LOCALBRIDGE *t);
static void SiReadLocalLogFile(SERVER *s, char *filepath, UINT offset, RPC_READ_LOG_FILE *t);
static void SiEnumLocalLogFileList(SERVER *s, char *hubname, RPC_ENUM_LOG_FILE *t);
static void SiEnumLocalSession(SERVER *s, char *hubname, RPC_ENUM_SESSION *t);
static void InRpcEnumLicenseKey(RPC_ENUM_LICENSE_KEY *t, PACK *p);
static void OutRpcEnumLicenseKey(PACK *p, RPC_ENUM_LICENSE_KEY *t);
static void InRpcLicenseStatus(RPC_LICENSE_STATUS *t, PACK *p);
static void OutRpcLicenseStatus(PACK *p, RPC_LICENSE_STATUS *t);
static void InRpcAdminOption(RPC_ADMIN_OPTION *t, PACK *p);
static void OutRpcAdminOption(PACK *p, RPC_ADMIN_OPTION *t);
static void InRpcConfig(RPC_CONFIG *t, PACK *p);
static void OutRpcConfig(PACK *p, RPC_CONFIG *t);
static void InRpcBridgeSupport(RPC_BRIDGE_SUPPORT *t, PACK *p);
static void OutRpcBridgeSupport(PACK *p, RPC_BRIDGE_SUPPORT *t);
static void InRpcAddAccess(RPC_ADD_ACCESS *t, PACK *p);
static void OutRpcAddAccess(PACK *p, RPC_ADD_ACCESS *t);
static void InRpcDeleteAccess(RPC_DELETE_ACCESS *t, PACK *p);
static void OutRpcDeleteAccess(PACK *p, RPC_DELETE_ACCESS *t);
static void InRpcServerInfo(RPC_SERVER_INFO *t, PACK *p);
static void OutRpcServerInfo(PACK *p, RPC_SERVER_INFO *t);
static void InRpcServerStatus(RPC_SERVER_STATUS *t, PACK *p);
static void OutRpcServerStatus(PACK *p, RPC_SERVER_STATUS *t);
static void InRpcListener(RPC_LISTENER *t, PACK *p);
static void OutRpcListener(PACK *p, RPC_LISTENER *t);
static void InRpcListenerList(RPC_LISTENER_LIST *t, PACK *p);
static void OutRpcListenerList(PACK *p, RPC_LISTENER_LIST *t);
static void InRpcStr(RPC_STR *t, PACK *p);
static void OutRpcStr(PACK *p, RPC_STR *t);
static void InRpcSetPassword(RPC_SET_PASSWORD *t, PACK *p);
static void OutRpcSetPassword(PACK *p, RPC_SET_PASSWORD *t);
static void InRpcCreateHub(RPC_CREATE_HUB *t, PACK *p);
static void OutRpcCreateHub(PACK *p, RPC_CREATE_HUB *t);
static void InRpcEnumHub(RPC_ENUM_HUB *t, PACK *p);
static void OutRpcEnumHub(PACK *p, RPC_ENUM_HUB *t);
static void InRpcDeleteHub(RPC_DELETE_HUB *t, PACK *p);
static void OutRpcDeleteHub(PACK *p, RPC_DELETE_HUB *t);
static void InRpcEnumConnection(RPC_ENUM_CONNECTION *t, PACK *p);
static void OutRpcEnumConnection(PACK *p, RPC_ENUM_CONNECTION *t);
static void InRpcDisconnectConnection(RPC_DISCONNECT_CONNECTION *t, PACK *p);
static void OutRpcDisconnectConnection(PACK *p, RPC_DISCONNECT_CONNECTION *t);
static void InRpcConnectionInfo(RPC_CONNECTION_INFO *t, PACK *p);
static void OutRpcConnectionInfo(PACK *p, RPC_CONNECTION_INFO *t);
static void InRpcSetHubOnline(RPC_SET_HUB_ONLINE *t, PACK *p);
static void OutRpcSetHubOnline(PACK *p, RPC_SET_HUB_ONLINE *t);
static void InRpcHubStatus(RPC_HUB_STATUS *t, PACK *p);
static void OutRpcHubStatus(PACK *p, RPC_HUB_STATUS *t);
static void InRpcHubLog(RPC_HUB_LOG *t, PACK *p);
static void OutRpcHubLog(PACK *p, RPC_HUB_LOG *t);
static void InRpcHubAddCa(RPC_HUB_ADD_CA *t, PACK *p);
static void OutRpcHubAddCa(PACK *p, RPC_HUB_ADD_CA *t);
static void InRpcHubEnumCa(RPC_HUB_ENUM_CA *t, PACK *p);
static void OutRpcHubEnumCa(PACK *p, RPC_HUB_ENUM_CA *t);
static void InRpcHubGetCa(RPC_HUB_GET_CA *t, PACK *p);
static void OutRpcHubGetCa(PACK *p, RPC_HUB_GET_CA *t);
static void InRpcHubDeleteCa(RPC_HUB_DELETE_CA *t, PACK *p);
static void OutRpcHubDeleteCa(PACK *p, RPC_HUB_DELETE_CA *t);
static void InRpcCreateLink(RPC_CREATE_LINK *t, PACK *p);
static void OutRpcCreateLink(PACK *p, RPC_CREATE_LINK *t);
static void InRpcEnumLink(RPC_ENUM_LINK *t, PACK *p);
static void OutRpcEnumLink(PACK *p, RPC_ENUM_LINK *t);
static void InRpcLinkStatus(RPC_LINK_STATUS *t, PACK *p);
static void OutRpcLinkStatus(PACK *p, RPC_LINK_STATUS *t);
static void InRpcLink(RPC_LINK *t, PACK *p);
static void OutRpcLink(PACK *p, RPC_LINK *t);
static void InRpcRenameLink(RPC_RENAME_LINK *t, PACK *p);
static void OutRpcRenameLink(PACK *p, RPC_RENAME_LINK *t);
static void InRpcAccess(ACCESS *a, PACK *p);
static void OutRpcAccess(PACK *p, ACCESS *a);
static void InRpcEnumAccessList(RPC_ENUM_ACCESS_LIST *a, PACK *p);
static void OutRpcEnumAccessList(PACK *p, RPC_ENUM_ACCESS_LIST *a);
static void InRpcSetUser(RPC_SET_USER *t, PACK *p);
static void OutRpcSetUser(PACK *p, RPC_SET_USER *t);
static void InRpcEnumUser(RPC_ENUM_USER *t, PACK *p);
static void OutRpcEnumUser(PACK *p, RPC_ENUM_USER *t);
static void InRpcSetGroup(RPC_SET_GROUP *t, PACK *p);
static void OutRpcSetGroup(PACK *p, RPC_SET_GROUP *t);
static void InRpcEnumGroup(RPC_ENUM_GROUP *t, PACK *p);
static void OutRpcEnumGroup(PACK *p, RPC_ENUM_GROUP *t);
static void InRpcDeleteUser(RPC_DELETE_USER *t, PACK *p);
static void OutRpcDeleteUser(PACK *p, RPC_DELETE_USER *t);
static void InRpcKeyPair(RPC_KEY_PAIR *t, PACK *p);
static void OutRpcKeyPair(PACK *p, RPC_KEY_PAIR *t);
static void InRpcSessionStatus(RPC_SESSION_STATUS *t, PACK *p);
static void OutRpcSessionStatus(PACK *p, RPC_SESSION_STATUS *t);
static void InRpcDeleteSession(RPC_DELETE_SESSION *t, PACK *p);
static void OutRpcDeleteSession(PACK *p, RPC_DELETE_SESSION *t);
static void InRpcEnumMacTable(RPC_ENUM_MAC_TABLE *t, PACK *p);
static void OutRpcEnumMacTable(PACK *p, RPC_ENUM_MAC_TABLE *t);
static void InRpcEnumIpTable(RPC_ENUM_IP_TABLE *t, PACK *p);
static void OutRpcEnumIpTable(PACK *p, RPC_ENUM_IP_TABLE *t);
static void InRpcDeleteTable(RPC_DELETE_TABLE *t, PACK *p);
static void OutRpcDeleteTable(PACK *p, RPC_DELETE_TABLE *t);
static UINT StTest(ADMIN *a, RPC_TEST *t);
static void InRpcTest(RPC_TEST *t, PACK *p);
static void OutRpcTest(PACK *p, RPC_TEST *t);
static PACK *AdminCall(RPC *rpc, char *function_name, PACK *p);
static UINT AdminCheckPassword(CEDAR *c, void *random, void *secure_password, char *hubname, bool accept_empty_password, bool *is_password_empty);
static void HashAdminPassword(void *hash, char *password);
static RPC *AdminConnectEx2(CEDAR *cedar, CLIENT_OPTION *o, char *hubname, void *hashed_password, UINT *err, char *client_name, void *hWnd);
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
#define	CHECK_RIGHT														\
	if (a->ServerAdmin == false && (StrCmpi(a->HubName, t->HubName) != 0))	\
		return ERR_NOT_ENOUGH_RIGHT;	\
	if (IsEmptyStr(t->HubName))			\
		return ERR_INVALID_PARAMETER;
#define	SERVER_ADMIN_ONLY												\
	if (a->ServerAdmin == false)										\
		return ERR_NOT_ENOUGH_RIGHT;
#define	NO_SUPPORT_FOR_BRIDGE											\
	if (a->Server->Cedar->Bridge)										\
		return ERR_NOT_SUPPORTED;

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

static PACK *AdminDispatch(RPC *rpc, char *name, PACK *p)
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

static UINT StRegenerateServerCert(ADMIN *a, RPC_TEST *t)
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

static UINT StSetHubMsg(ADMIN *a, RPC_MSG *t)
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

static UINT StGetHubMsg(ADMIN *a, RPC_MSG *t)
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

static UINT StDebug(ADMIN *a, RPC_TEST *t)
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

static UINT StFlush(ADMIN *a, RPC_TEST *t)
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

static UINT StCrash(ADMIN *a, RPC_TEST *t)
{
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;
	UINT ret = ERR_NO_ERROR;

	SERVER_ADMIN_ONLY;

	MsSetEnableMinidump(false);

	CrashNow();

	return ERR_NO_ERROR;
}

static UINT StGetAdminMsg(ADMIN *a, RPC_MSG *t)
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

static UINT StEnumEthVLan(ADMIN *a, RPC_ENUM_ETH_VLAN *t)
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

static UINT StSetEnableEthVLan(ADMIN *a, RPC_TEST *t)
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

static UINT StGetLicenseStatus(ADMIN *a, RPC_LICENSE_STATUS *t)
{
	return ERR_NOT_SUPPORTED;
}

static UINT StEnumLicenseKey(ADMIN *a, RPC_ENUM_LICENSE_KEY *t)
{
	return ERR_NOT_SUPPORTED;
}

static UINT StAddLicenseKey(ADMIN *a, RPC_TEST *t)
{
	return ERR_NOT_SUPPORTED;
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

static UINT StReadLogFile(ADMIN *a, RPC_READ_LOG_FILE *t)
{
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;
	char logfilename[MAX_PATH];
	char servername[MAX_HOST_NAME_LEN + 1];
	UINT offset;

	if (IsEmptyStr(t->FilePath))
	{
		return ERR_INVALID_PARAMETER;
	}

	StrCpy(logfilename, sizeof(logfilename), t->FilePath);
	offset = t->Offset;

	GetMachineName(servername, sizeof(servername));

	// Check the permission to read the log file
	if (a->LogFileList == NULL)
	{
		RPC_ENUM_LOG_FILE elf;
		UINT elf_ret;

		Zero(&elf, sizeof(elf));

		elf_ret = StEnumLogFile(a, &elf);

		FreeRpcEnumLogFile(&elf);

		if (elf_ret != ERR_NO_ERROR)
		{
			return elf_ret;
		}
	}
	if (CheckLogFileNameFromEnumList(a->LogFileList, logfilename) == false)
	{
		return ERR_OBJECT_NOT_FOUND;
	}

	FreeRpcReadLogFile(t);
	Zero(t, sizeof(RPC_READ_LOG_FILE));

	SiReadLocalLogFile(s, logfilename, offset, t);

	if (offset == 0)
	{
		ALog(a, NULL, "LA_READ_LOG_FILE", servername, logfilename);
	}

	StrCpy(t->FilePath, sizeof(t->FilePath), logfilename);
	t->Offset = offset;

	return ERR_NO_ERROR;
}

static UINT StEnumLogFile(ADMIN *a, RPC_ENUM_LOG_FILE *t)
{
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;
	UINT i;
	bool no_access = false;

	HUB *h;

	if (a->ServerAdmin == false)
	{
		h = GetHub(c, a->HubName);

		if (a->ServerAdmin == false && GetHubAdminOption(h, "no_read_log_file") != 0)
		{
			no_access = true;
		}

		ReleaseHub(h);
	}

	if (no_access)
	{
		return ERR_NOT_ENOUGH_RIGHT;
	}

	FreeRpcEnumLogFile(t);
	Zero(t, sizeof(RPC_ENUM_LOG_FILE));

	SiEnumLocalLogFileList(s, a->ServerAdmin ? NULL : a->HubName, t);

	// Cache the log file list on the RPC session
	if (a->LogFileList != NULL)
	{
		FreeEnumLogFile(a->LogFileList);
	}

	a->LogFileList = NewListFast(CmpLogFile);

	for (i = 0;i < t->NumItem;i++)
	{
		RPC_ENUM_LOG_FILE_ITEM *e = &t->Items[i];
		LOG_FILE *f = ZeroMalloc(sizeof(LOG_FILE));

		f->FileSize = e->FileSize;
		f->UpdatedTime = e->UpdatedTime;
		StrCpy(f->Path, sizeof(f->Path), e->FilePath);

		Insert(a->LogFileList, f);
	}

	return ERR_NO_ERROR;
}


static UINT StGetAcList(ADMIN *a, RPC_AC_LIST *t)
{
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;
	HUB *h;
	UINT ret = ERR_NO_ERROR;
	char hubname[MAX_HUBNAME_LEN + 1];

	CHECK_RIGHT;
	NO_SUPPORT_FOR_BRIDGE;

	StrCpy(hubname, sizeof(hubname), t->HubName);

	FreeRpcAcList(t);
	Zero(t, sizeof(RPC_AC_LIST));
	StrCpy(t->HubName, sizeof(t->HubName), hubname);

	h = GetHub(c, hubname);

	if (h == NULL)
	{
		ret = ERR_HUB_NOT_FOUND;
	}
	else
	{
		if (h->HubDb == NULL)
		{
			ret = ERR_NOT_SUPPORTED;
		}
		else
		{
			HUBDB *db = h->HubDb;

			LockList(db->AcList);
			{
				t->o = NewList(CmpAc);

				SetAcList(t->o, db->AcList);
			}
			UnlockList(db->AcList);
		}
		ReleaseHub(h);
	}

	return ret;
}

static UINT StSetAcList(ADMIN *a, RPC_AC_LIST *t)
{
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;
	HUB *h;
	UINT ret = ERR_NO_ERROR;
	char hubname[MAX_HUBNAME_LEN + 1];


	if (c->Bridge)
	{
		return ERR_NOT_SUPPORTED;
	}

	if (GetGlobalServerFlag(GSF_DISABLE_AC) != 0 && LIST_NUM(t->o) >= 1)
	{
		return ERR_NOT_SUPPORTED_FUNCTION_ON_OPENSOURCE;
	}

	CHECK_RIGHT;
	NO_SUPPORT_FOR_BRIDGE;
	StrCpy(hubname, sizeof(hubname), t->HubName);

	h = GetHub(c, hubname);

	if (h == NULL)
	{
		ret = ERR_HUB_NOT_FOUND;
	}
	else
	{
		if (a->ServerAdmin == false && GetHubAdminOption(h, "no_change_access_control_list") != 0)
		{
			ret = ERR_NOT_ENOUGH_RIGHT;
		}
		else
		{
			if (h->HubDb == NULL)
			{
				ret = ERR_NOT_SUPPORTED;
			}
			else
			{
				HUBDB *db = h->HubDb;

				LockList(db->AcList);
				{
					SetAcList(db->AcList, t->o);

					{
						ALog(a, h, "LA_SET_AC_LIST", LIST_NUM(t->o));

						IncrementServerConfigRevision(s);
					}
				}
				UnlockList(db->AcList);
			}
		}
		ReleaseHub(h);
	}

	return ret;
}

static UINT StSetCrl(ADMIN *a, RPC_CRL *t)
{
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;
	HUB *h;
	UINT ret = ERR_NO_ERROR;
	UINT key;
	char hubname[MAX_HUBNAME_LEN + 1];

	CHECK_RIGHT;
	NO_SUPPORT_FOR_BRIDGE;
	StrCpy(hubname, sizeof(hubname), t->HubName);
	key = t->Key;

	h = GetHub(c, hubname);

	if (h == NULL)
	{
		ret = ERR_HUB_NOT_FOUND;
	}
	else
	{
		if (a->ServerAdmin == false && GetHubAdminOption(h, "no_change_crl_list") != 0)
		{
			ret = ERR_NOT_ENOUGH_RIGHT;
		}
		else
		{
			if (h->HubDb == NULL)
			{
				ret = ERR_NOT_SUPPORTED;
			}
			else
			{
				LockList(h->HubDb->CrlList);
				{
					CRL *crl = ListKeyToPointer(h->HubDb->CrlList, t->Key);

					if (crl == NULL)
					{
						ret = ERR_OBJECT_NOT_FOUND;
					}
					else
					{
						CRL *new_crl = CopyCrl(t->Crl);
						if (ReplaceListPointer(h->HubDb->CrlList, crl, new_crl))
						{
							ALog(a, h, "LA_ADD_CRL");
							FreeCrl(crl);

							IncrementServerConfigRevision(s);
						}
					}
				}
				UnlockList(h->HubDb->CrlList);
			}
		}

		ReleaseHub(h);
	}

	return ret;
}

static UINT StGetCrl(ADMIN *a, RPC_CRL *t)
{
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;
	HUB *h;
	UINT ret = ERR_NO_ERROR;
	UINT key;
	char hubname[MAX_HUBNAME_LEN + 1];

	CHECK_RIGHT;
	NO_SUPPORT_FOR_BRIDGE;
	StrCpy(hubname, sizeof(hubname), t->HubName);
	key = t->Key;

	FreeRpcCrl(t);
	Zero(t, sizeof(RPC_CRL));
	StrCpy(t->HubName, sizeof(t->HubName), hubname);
	t->Key = key;

	h = GetHub(c, hubname);

	if (h == NULL)
	{
		ret = ERR_HUB_NOT_FOUND;
	}
	else
	{
		if (h->HubDb == NULL)
		{
			ret = ERR_NOT_SUPPORTED;
		}
		else
		{
			LockList(h->HubDb->CrlList);
			{
				CRL *crl = ListKeyToPointer(h->HubDb->CrlList, t->Key);

				if (crl == NULL)
				{
					ret = ERR_OBJECT_NOT_FOUND;
				}
				else
				{
					t->Crl = CopyCrl(crl);
				}
			}
			UnlockList(h->HubDb->CrlList);
		}

		ReleaseHub(h);
	}

	return ret;
}

static UINT StDelCrl(ADMIN *a, RPC_CRL *t)
{
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;
	HUB *h;
	UINT ret = ERR_NO_ERROR;
	char hubname[MAX_HUBNAME_LEN + 1];

	CHECK_RIGHT;
	NO_SUPPORT_FOR_BRIDGE;
	StrCpy(hubname, sizeof(hubname), t->HubName);

	h = GetHub(c, hubname);

	if (h == NULL)
	{
		ret = ERR_HUB_NOT_FOUND;
	}
	else
	{
		if (a->ServerAdmin == false && GetHubAdminOption(h, "no_change_crl_list") != 0)
		{
			ret = ERR_NOT_ENOUGH_RIGHT;
		}
		else
		{
			if (h->HubDb == NULL)
			{
				ret = ERR_NOT_SUPPORTED;
			}
			else
			{
				LockList(h->HubDb->CrlList);
				{
					CRL *crl = ListKeyToPointer(h->HubDb->CrlList, t->Key);

					if (crl == NULL)
					{
						ret = ERR_OBJECT_NOT_FOUND;
					}
					else
					{
						ALog(a, h, "LA_DEL_CRL");
						FreeCrl(crl);
						Delete(h->HubDb->CrlList, crl);
					}
				}
				UnlockList(h->HubDb->CrlList);
			}
		}

		ReleaseHub(h);
	}

	return ret;
}

static UINT StAddCrl(ADMIN *a, RPC_CRL *t)
{
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;
	HUB *h;
	UINT ret = ERR_NO_ERROR;
	char hubname[MAX_HUBNAME_LEN + 1];

	if (c->Bridge)
	{
		return ERR_NOT_SUPPORTED;
	}

	CHECK_RIGHT;
	NO_SUPPORT_FOR_BRIDGE;
	StrCpy(hubname, sizeof(hubname), t->HubName);

	h = GetHub(c, hubname);

	if (h == NULL)
	{
		ret = ERR_HUB_NOT_FOUND;
	}
	else
	{
		if (a->ServerAdmin == false && GetHubAdminOption(h, "no_change_crl_list") != 0)
		{
			ret = ERR_NOT_ENOUGH_RIGHT;
		}
		else
		{
			if (h->HubDb == NULL)
			{
				ret = ERR_NOT_SUPPORTED;
			}
			else
			{
				LockList(h->HubDb->CrlList);
				{
					if (LIST_NUM(h->HubDb->CrlList) < MAX_HUB_CRLS)
					{
						CRL *crl = CopyCrl(t->Crl);

						Insert(h->HubDb->CrlList, crl);

						ALog(a, h, "LA_SET_CRL");

						IncrementServerConfigRevision(s);
					}
				}
				UnlockList(h->HubDb->CrlList);
			}
		}

		ReleaseHub(h);
	}

	return ret;
}

static UINT StEnumCrl(ADMIN *a, RPC_ENUM_CRL *t)
{
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;
	HUB *h;
	UINT ret = ERR_NO_ERROR;
	char hubname[MAX_HUBNAME_LEN + 1];

	CHECK_RIGHT;
	NO_SUPPORT_FOR_BRIDGE;
	StrCpy(hubname, sizeof(hubname), t->HubName);
	FreeRpcEnumCrl(t);
	Zero(t, sizeof(RPC_ENUM_CRL));

	StrCpy(t->HubName, sizeof(t->HubName), hubname);

	h = GetHub(c, hubname);

	if (h == NULL)
	{
		ret = ERR_HUB_NOT_FOUND;
	}
	else
	{
		if (h->HubDb == NULL)
		{
			ret = ERR_NOT_SUPPORTED;
		}
		else
		{
			LockList(h->HubDb->CrlList);
			{
				UINT i;

				t->NumItem = LIST_NUM(h->HubDb->CrlList);
				t->Items = ZeroMalloc(sizeof(RPC_ENUM_CRL_ITEM) * t->NumItem);

				for (i = 0;i < LIST_NUM(h->HubDb->CrlList);i++)
				{
					CRL *crl = LIST_DATA(h->HubDb->CrlList, i);
					wchar_t *info = GenerateCrlStr(crl);

					UniStrCpy(t->Items[i].CrlInfo, sizeof(t->Items[i].CrlInfo), info);
					Free(info);

					t->Items[i].Key = POINTER_TO_KEY(crl);
				}
			}
			UnlockList(h->HubDb->CrlList);
		}

		ReleaseHub(h);
	}

	return ret;
}

static UINT StSetHubExtOptions(ADMIN *a, RPC_ADMIN_OPTION *t)
{
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;
	HUB *h;

	bool not_server_admin = false;

	if (t->NumItem > MAX_HUB_ADMIN_OPTIONS)
	{
		return ERR_TOO_MANT_ITEMS;
	}


	CHECK_RIGHT;

	if (a->ServerAdmin == false)
	{
		not_server_admin = true;
	}

	LockHubList(c);
	{
		h = GetHub(c, t->HubName);
	}
	UnlockHubList(c);

	if (h == NULL)
	{
		return ERR_HUB_NOT_FOUND;
	}

	if (GetHubAdminOption(h, "deny_hub_admin_change_ext_option") && not_server_admin)
	{
		ReleaseHub(h);

		return ERR_NOT_ENOUGH_RIGHT;
	}

	Lock(h->lock);
	{
		DataToHubOptionStruct(h->Option, t);
	}
	Unlock(h->lock);

	ALog(a, NULL, "LA_SET_HUB_EXT_OPTION", h->Name);

	ReleaseHub(h);

	IncrementServerConfigRevision(s);

	return ERR_NO_ERROR;
}

static UINT StGetHubExtOptions(ADMIN *a, RPC_ADMIN_OPTION *t)
{
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;
	HUB *h;

	CHECK_RIGHT;

	LockHubList(c);
	{
		h = GetHub(c, t->HubName);
	}
	UnlockHubList(c);

	if (h == NULL)
	{
		return ERR_HUB_NOT_FOUND;
	}

	FreeRpcAdminOption(t);
	Zero(t, sizeof(RPC_ADMIN_OPTION));

	StrCpy(t->HubName, sizeof(t->HubName), h->Name);

	Lock(h->lock);
	{
		HubOptionStructToData(t, h->Option, h->Name);
	}
	Unlock(h->lock);

	ReleaseHub(h);

	return ERR_NO_ERROR;
}

static UINT StSetHubAdminOptions(ADMIN *a, RPC_ADMIN_OPTION *t)
{
	UINT i;
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;
	HUB *h;

	bool not_server_admin = false;


	if (t->NumItem > MAX_HUB_ADMIN_OPTIONS)
	{
		return ERR_TOO_MANT_ITEMS;
	}

	NO_SUPPORT_FOR_BRIDGE;
	CHECK_RIGHT;

	if (a->ServerAdmin == false)
	{
		not_server_admin = true;
	}

	LockHubList(c);
	{
		h = GetHub(c, t->HubName);
	}
	UnlockHubList(c);

	if (h == NULL)
	{
		return ERR_HUB_NOT_FOUND;
	}

	if (GetHubAdminOption(h, "allow_hub_admin_change_option") == false
		&& not_server_admin)
	{
		ReleaseHub(h);

		return ERR_NOT_ENOUGH_RIGHT;
	}

	LockList(h->AdminOptionList);
	{
		DeleteAllHubAdminOption(h, false);

		for (i = 0;i < t->NumItem;i++)
		{
			ADMIN_OPTION *e = &t->Items[i];
			ADMIN_OPTION *a = ZeroMalloc(sizeof(ADMIN_OPTION));

			StrCpy(a->Name, sizeof(a->Name), e->Name);
			a->Value = e->Value;

			Insert(h->AdminOptionList, a);
		}

		AddHubAdminOptionsDefaults(h, false);
	}
	UnlockList(h->AdminOptionList);

	ALog(a, NULL, "LA_SET_HUB_ADMIN_OPTION", h->Name);

	ReleaseHub(h);

	IncrementServerConfigRevision(s);

	return ERR_NO_ERROR;
}

static UINT StGetHubAdminOptions(ADMIN *a, RPC_ADMIN_OPTION *t)
{
	UINT i;
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;
	HUB *h;

	CHECK_RIGHT;

	NO_SUPPORT_FOR_BRIDGE;
	LockHubList(c);
	{
		h = GetHub(c, t->HubName);
	}
	UnlockHubList(c);

	if (h == NULL)
	{
		return ERR_HUB_NOT_FOUND;
	}

	FreeRpcAdminOption(t);
	Zero(t, sizeof(RPC_ADMIN_OPTION));

	StrCpy(t->HubName, sizeof(t->HubName), h->Name);

	LockList(h->AdminOptionList);
	{
		t->NumItem = LIST_NUM(h->AdminOptionList);
		t->Items = ZeroMalloc(sizeof(ADMIN_OPTION) * t->NumItem);

		for (i = 0;i < t->NumItem;i++)
		{
			ADMIN_OPTION *a = LIST_DATA(h->AdminOptionList, i);
			ADMIN_OPTION *e = &t->Items[i];

			StrCpy(e->Name, sizeof(e->Name), a->Name);
			e->Value = a->Value;
			UniStrCpy(e->Descrption, sizeof(e->Descrption), GetHubAdminOptionHelpString(e->Name));
		}
	}
	UnlockList(h->AdminOptionList);

	ReleaseHub(h);

	return ERR_NO_ERROR;
}

static UINT StGetDefaultHubAdminOptions(ADMIN *a, RPC_ADMIN_OPTION *t)
{
	UINT i;

	NO_SUPPORT_FOR_BRIDGE;
	FreeRpcAdminOption(t);
	Zero(t, sizeof(RPC_ADMIN_OPTION));

	t->NumItem = num_admin_options;
	t->Items = ZeroMalloc(sizeof(ADMIN_OPTION) * t->NumItem);

	for (i = 0;i < t->NumItem;i++)
	{
		ADMIN_OPTION *a = &t->Items[i];

		StrCpy(a->Name, sizeof(a->Name), admin_options[i].Name);
		a->Value = admin_options[i].Value;
		UniStrCpy(a->Descrption, sizeof(a->Descrption), GetHubAdminOptionHelpString(a->Name));
	}

	return ERR_NO_ERROR;
}

static UINT StGetConfig(ADMIN *a, RPC_CONFIG *t)
{
	SERVER *s;

	SERVER_ADMIN_ONLY;

	FreeRpcConfig(t);
	Zero(t, sizeof(RPC_CONFIG));

	s = a->Server;

	ALog(a, NULL, "LA_GET_CONFIG");

	if (s->CfgRw != NULL)
	{
		FOLDER *f = SiWriteConfigurationToCfg(s);
		BUF *b = CfgFolderToBuf(f, true);

		StrCpy(t->FileName, sizeof(t->FileName), s->CfgRw->FileName + (s->CfgRw->FileName[0] == '@' ? 1 : 0));

		t->FileData = ZeroMalloc(b->Size + 1);
		Copy(t->FileData, b->Buf, b->Size);

		CfgDeleteFolder(f);
		FreeBuf(b);

		return ERR_NO_ERROR;
	}
	else
	{
		return ERR_INTERNAL_ERROR;
	}
}

static UINT StSetConfig(ADMIN *a, RPC_CONFIG *t)
{
	SERVER *s;
	IO *o;
	char filename[MAX_PATH];

	SERVER_ADMIN_ONLY;

	s = a->Server;
	if (s->CfgRw == NULL)
	{
		return ERR_INTERNAL_ERROR;
	}

	Format(filename, sizeof(filename), "%s.new", s->CfgRw->FileName);

	o = FileCreate(filename);

	FileWrite(o, t->FileData, StrLen(t->FileData));

	FileClose(o);

	IncrementServerConfigRevision(s);

	ALog(a, NULL, "LA_SET_CONFIG");

	SiRebootServerEx(s->Cedar->Bridge, false);

	return ERR_NO_ERROR;
}

static UINT StGetCaps(ADMIN *a, CAPSLIST *t)
{
	FreeRpcCapsList(t);
	Zero(t, sizeof(CAPSLIST));

	GetServerCapsMain(a->Server, t);

	return ERR_NO_ERROR;
}

static UINT StRebootServer(ADMIN *a, RPC_TEST *t)
{
	SERVER_ADMIN_ONLY;

	ALog(a, NULL, "LA_REBOOT_SERVER");

	SiRebootServerEx(a->Server->Cedar->Bridge, t->IntValue);

	return ERR_NO_ERROR;
}

static UINT StGetBridgeSupport(ADMIN *a, RPC_BRIDGE_SUPPORT *t)
{
	Zero(t, sizeof(RPC_BRIDGE_SUPPORT));

	t->IsBridgeSupportedOs = IsBridgeSupported();

	return ERR_NO_ERROR;
}

static UINT StEnumEthernet(ADMIN *a, RPC_ENUM_ETH *t)
{
	TOKEN_LIST *o;
	UINT i;
	char tmp[MAX_SIZE];

	SERVER_ADMIN_ONLY;

	o = GetEthList();
	if (o == NULL)
	{
		return ERR_NOT_SUPPORTED;
	}

	FreeRpcEnumEth(t);
	Zero(t, sizeof(RPC_ENUM_ETH));

	t->NumItem = o->NumTokens;
	t->Items = ZeroMalloc(sizeof(RPC_ENUM_ETH_ITEM) * t->NumItem);

	for (i = 0;i < t->NumItem;i++)
	{
		RPC_ENUM_ETH_ITEM *e = &t->Items[i];

		StrCpy(e->DeviceName, sizeof(e->DeviceName), o->Token[i]);

		StrCpy(tmp, sizeof(tmp), e->DeviceName);

		GetEthNetworkConnectionName(e->NetworkConnectionName, sizeof(e->NetworkConnectionName), e->DeviceName);
	}

	FreeToken(o);

	return ERR_NO_ERROR;
}

static UINT StAddLocalBridge(ADMIN *a, RPC_LOCALBRIDGE *t)
{
	if (IsEmptyStr(t->DeviceName) || IsEmptyStr(t->HubName))
	{
		return ERR_INVALID_PARAMETER;
	}

	SERVER_ADMIN_ONLY;


	if (Win32EthIsSuSupported() == false)
	{
		return ERR_LOCAL_BRIDGE_UNSUPPORTED;
	}

	if (true)
	{
		char tmp[MAX_SIZE];
		UINT id = Win32EthGetNameAndIdFromCombinedName(tmp, sizeof(tmp), t->DeviceName);

		if (id == 0)
		{
			// On Win32, adding fails when no device ID is given
			return ERR_OBJECT_NOT_FOUND;
		}
	}

	ALog(a, NULL, "LA_ADD_BRIDGE", t->HubName, t->DeviceName);

	AddLocalBridge(a->Server->Cedar, t->HubName, t->DeviceName, false, false, t->TapMode, NULL, false);

	IncrementServerConfigRevision(a->Server);

	return ERR_NO_ERROR;
}

static UINT StDeleteLocalBridge(ADMIN *a, RPC_LOCALBRIDGE *t)
{
	if (IsEmptyStr(t->DeviceName) || IsEmptyStr(t->HubName))
	{
		return ERR_INVALID_PARAMETER;
	}

	SERVER_ADMIN_ONLY;

	ALog(a, NULL, "LA_DELETE_BRIDGE", t->HubName, t->DeviceName);

	if (DeleteLocalBridge(a->Server->Cedar, t->HubName, t->DeviceName) == false)
	{
		return ERR_OBJECT_NOT_FOUND;
	}

	IncrementServerConfigRevision(a->Server);

	return ERR_NO_ERROR;
}

static UINT StEnumLocalBridge(ADMIN *a, RPC_ENUM_LOCALBRIDGE *t)
{
	UINT i;
	CEDAR *c;

	if (Win32EthIsSuSupported() == false)
	{
		return ERR_LOCAL_BRIDGE_UNSUPPORTED;
	}

	FreeRpcEnumLocalBridge(t);
	Zero(t, sizeof(RPC_ENUM_LOCALBRIDGE));

	c = a->Server->Cedar;

	LockList(c->LocalBridgeList);
	{
		t->NumItem = LIST_NUM(c->LocalBridgeList);
		t->Items = ZeroMalloc(sizeof(RPC_LOCALBRIDGE) * t->NumItem);

		for (i = 0;i < t->NumItem;i++)
		{
			RPC_LOCALBRIDGE *e = &t->Items[i];
			LOCALBRIDGE *br = LIST_DATA(c->LocalBridgeList, i);

			if (br->Bridge == false)
			{
				e->Online = e->Active = false;
			}
			else
			{
				e->Online = true;
				if (br->Bridge->Active)
				{
					e->Active = true;
				}
				else
				{
					e->Active = false;
				}
			}
			StrCpy(e->DeviceName, sizeof(e->DeviceName), br->DeviceName);
			StrCpy(e->HubName, sizeof(e->HubName), br->HubName);

			e->TapMode = br->TapMode;
		}
	}
	UnlockList(c->LocalBridgeList);

	return ERR_NO_ERROR;
}

static UINT StSetSysLog(ADMIN *a, SYSLOG_SETTING *t)
{
	SERVER *s = a->Server;

	SERVER_ADMIN_ONLY;

	if (GetGlobalServerFlag(GSF_DISABLE_SYSLOG) != 0 && t->SaveType != SYSLOG_NONE)
	{
		return ERR_NOT_SUPPORTED_FUNCTION_ON_OPENSOURCE;
	}

	if (GetServerCapsBool(s, "b_support_syslog") == false)
	{
		return ERR_NOT_SUPPORTED;
	}

	SiSetSysLogSetting(s, t);

	IncrementServerConfigRevision(s);
	ALog(a, NULL, "LA_SET_SYSLOG");

	return ERR_NO_ERROR;
}

static UINT StGetSysLog(ADMIN *a, SYSLOG_SETTING *t)
{
	SERVER *s = a->Server;

	SiGetSysLogSetting(s, t);

	if (a->ServerAdmin == false)
	{
		// Hide the server name from non-administrators
		if (t->SaveType == SYSLOG_NONE)
		{
			StrCpy(t->Hostname, sizeof(t->Hostname), "");
			t->Port = 0;
		}
		else
		{
			StrCpy(t->Hostname, sizeof(t->Hostname), "Secret");
			t->Port = 0;
		}
	}

	return ERR_NO_ERROR;
}

static UINT StDeleteIpTable(ADMIN *a, RPC_DELETE_TABLE *t)
{
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;
	HUB *h = NULL;
	UINT ret = ERR_NO_ERROR;

	CHECK_RIGHT;

	LockHubList(c);
	{
		h = GetHub(c, t->HubName);
	}
	UnlockHubList(c);

	if (h == NULL)
	{
		return ERR_HUB_NOT_FOUND;
	}

	if (a->ServerAdmin == false && GetHubAdminOption(h, "no_delete_iptable") != 0)
	{
		ReleaseHub(h);
		return ERR_NOT_ENOUGH_RIGHT;
	}

	LockList(h->IpTable);
	{
		if (IsInListKey(h->IpTable, t->Key))
		{
			IP_TABLE_ENTRY *e = ListKeyToPointer(h->IpTable, t->Key);
			Free(e);
			Delete(h->IpTable, e);
		}
		else
		{
			ret = ERR_OBJECT_NOT_FOUND;
		}
	}
	UnlockList(h->IpTable);

	ReleaseHub(h);

	return ret;
}

static UINT SiEnumIpTable(SERVER *s, char *hubname, RPC_ENUM_IP_TABLE *t)
{
	CEDAR *c;
	UINT i;
	HUB *h = NULL;
	if (s == NULL || hubname == NULL || t == NULL)
	{
		return ERR_INTERNAL_ERROR;
	}

	c = s->Cedar;

	LockHubList(c);
	{
		h = GetHub(c, hubname);
	}
	UnlockHubList(c);

	if (h == NULL)
	{
		return ERR_HUB_NOT_FOUND;
	}

	StrCpy(t->HubName, sizeof(t->HubName), hubname);

	LockList(h->IpTable);
	{
		t->NumIpTable = LIST_NUM(h->IpTable);
		t->IpTables = ZeroMalloc(sizeof(RPC_ENUM_IP_TABLE_ITEM) * t->NumIpTable);

		for (i = 0;i < t->NumIpTable;i++)
		{
			RPC_ENUM_IP_TABLE_ITEM *e = &t->IpTables[i];
			IP_TABLE_ENTRY *table = LIST_DATA(h->IpTable, i);

			e->Key = POINTER_TO_KEY(table);
			StrCpy(e->SessionName, sizeof(e->SessionName), table->Session->Name);
			e->Ip = IPToUINT(&table->Ip);
			Copy(&e->IpV6, &table->Ip, sizeof(IP));
			Copy(&e->IpAddress, &table->Ip, sizeof(IP));
			e->DhcpAllocated = table->DhcpAllocated;
			e->CreatedTime = Tick64ToTime64(table->CreatedTime);
			e->UpdatedTime = Tick64ToTime64(table->UpdatedTime);
		}
	}
	UnlockList(h->IpTable);

	ReleaseHub(h);

	return ERR_NO_ERROR;
}

static UINT StEnumIpTable(ADMIN *a, RPC_ENUM_IP_TABLE *t)
{
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;
	UINT ret = ERR_NO_ERROR;
	char hubname[MAX_HUBNAME_LEN + 1];

	CHECK_RIGHT;

	StrCpy(hubname, sizeof(hubname), t->HubName);
	FreeRpcEnumIpTable(t);
	Zero(t, sizeof(RPC_ENUM_IP_TABLE));
	StrCpy(t->HubName, sizeof(t->HubName), hubname);

	ret = SiEnumIpTable(s, hubname, t);
	if (ret != ERR_NO_ERROR)
	{
		return ret;
	}

	return ret;
}

static UINT StDeleteMacTable(ADMIN *a, RPC_DELETE_TABLE *t)
{
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;
	HUB *h = NULL;
	UINT ret = ERR_NO_ERROR;

	CHECK_RIGHT;

	LockHubList(c);
	{
		h = GetHub(c, t->HubName);
	}
	UnlockHubList(c);

	if (h == NULL)
	{
		return ERR_HUB_NOT_FOUND;
	}

	if (a->ServerAdmin == false && GetHubAdminOption(h, "no_delete_mactable") != 0)
	{
		ReleaseHub(h);
		return ERR_NOT_ENOUGH_RIGHT;
	}

	LockHashList(h->MacHashTable);
	{
		if (IsInHashListKey(h->MacHashTable, t->Key))
		{
			MAC_TABLE_ENTRY *e = HashListKeyToPointer(h->MacHashTable, t->Key);
			DeleteHash(h->MacHashTable, e);
			Free(e);
		}
		else
		{
			ret = ERR_OBJECT_NOT_FOUND;
		}
	}
	UnlockHashList(h->MacHashTable);

	ReleaseHub(h);

	return ret;
}

static UINT SiEnumMacTable(SERVER *s, char *hubname, RPC_ENUM_MAC_TABLE *t)
{
	CEDAR *c;
	UINT i;
	HUB *h = NULL;
	if (s == NULL || hubname == NULL || t == NULL)
	{
		return ERR_INTERNAL_ERROR;
	}

	c = s->Cedar;

	LockHubList(c);
	{
		h = GetHub(c, hubname);
	}
	UnlockHubList(c);

	if (h == NULL)
	{
		return ERR_HUB_NOT_FOUND;
	}

	StrCpy(t->HubName, sizeof(t->HubName), hubname);

	LockHashList(h->MacHashTable);
	{
		MAC_TABLE_ENTRY **pp = (MAC_TABLE_ENTRY **)HashListToArray(h->MacHashTable, &t->NumMacTable);
		t->MacTables = ZeroMalloc(sizeof(RPC_ENUM_MAC_TABLE_ITEM) * t->NumMacTable);

		for (i = 0;i < t->NumMacTable;i++)
		{
			RPC_ENUM_MAC_TABLE_ITEM *e = &t->MacTables[i];
			MAC_TABLE_ENTRY *mac = pp[i];

			e->Key = POINTER_TO_KEY(mac);
			StrCpy(e->SessionName, sizeof(e->SessionName), mac->Session->Name);
			Copy(e->MacAddress, mac->MacAddress, sizeof(e->MacAddress));
			e->CreatedTime = Tick64ToTime64(mac->CreatedTime);
			e->UpdatedTime = Tick64ToTime64(mac->UpdatedTime);
			e->VlanId = mac->VlanId;
		}

		Free(pp);
	}
	UnlockHashList(h->MacHashTable);

	ReleaseHub(h);

	return ERR_NO_ERROR;
}

static UINT StEnumMacTable(ADMIN *a, RPC_ENUM_MAC_TABLE *t)
{
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;
	HUB *h = NULL;
	UINT ret = ERR_NO_ERROR;
	char hubname[MAX_HUBNAME_LEN + 1];

	CHECK_RIGHT;

	StrCpy(hubname, sizeof(hubname), t->HubName);
	FreeRpcEnumMacTable(t);
	Zero(t, sizeof(RPC_ENUM_MAC_TABLE));

	ret = SiEnumMacTable(s, hubname, t);
	if (ret != ERR_NO_ERROR)
	{
		return ret;
	}

	return ret;
}

static UINT StDeleteSession(ADMIN *a, RPC_DELETE_SESSION *t)
{
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;
	HUB *h = NULL;
	UINT ret = ERR_NO_ERROR;
	char hubname[MAX_HUBNAME_LEN + 1];
	char name[MAX_SESSION_NAME_LEN + 1];
	SESSION *sess;

	if (IsEmptyStr(t->Name))
	{
		return ERR_INVALID_PARAMETER;
	}

	StrCpy(hubname, sizeof(hubname), t->HubName);
	StrCpy(name, sizeof(name), t->Name);

	CHECK_RIGHT;

	LockHubList(c);
	{
		h = GetHub(c, t->HubName);
	}
	UnlockHubList(c);

	if (h == NULL)
	{
		return ERR_HUB_NOT_FOUND;
	}

	if (a->ServerAdmin == false && GetHubAdminOption(h, "no_disconnect_session") != 0)
	{
		ReleaseHub(h);
		return ERR_NOT_ENOUGH_RIGHT;
	}

	sess = GetSessionByName(h, name);

	if (sess == NULL)
	{
		ret = ERR_OBJECT_NOT_FOUND;
	}
	else
	{
		if (sess->LinkModeServer)
		{
			ret = ERR_LINK_CANT_DISCONNECT;
		}
		else if (sess->BridgeMode)
		{
			ret = ERR_BRIDGE_CANT_DISCONNECT;
		}
		else
		{
			StopSession(sess);
		}
		ReleaseSession(sess);
	}

	if (ret != ERR_NO_ERROR)
	{
		ALog(a, h, "LA_DELETE_SESSION", t->Name);
	}

	ReleaseHub(h);

	return ret;
}

static UINT StGetSessionStatus(ADMIN *a, RPC_SESSION_STATUS *t)
{
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;
	HUB *h = NULL;
	UINT ret = ERR_NO_ERROR;
	char hubname[MAX_HUBNAME_LEN + 1];
	char name[MAX_SESSION_NAME_LEN + 1];
	SESSION *sess;

	StrCpy(hubname, sizeof(hubname), t->HubName);
	StrCpy(name, sizeof(name), t->Name);

	if (IsEmptyStr(t->Name))
	{
		return ERR_INVALID_PARAMETER;
	}

	CHECK_RIGHT;

	LockHubList(c);
	{
		h = GetHub(c, t->HubName);
	}
	UnlockHubList(c);

	if (h == NULL)
	{
		return ERR_HUB_NOT_FOUND;
	}

	if (a->ServerAdmin == false && GetHubAdminOption(h, "no_query_session") != 0)
	{
		ReleaseHub(h);
		return ERR_NOT_ENOUGH_RIGHT;
	}

	FreeRpcSessionStatus(t);
	Zero(t, sizeof(RPC_SESSION_STATUS));
	StrCpy(t->HubName, sizeof(t->HubName), hubname);
	StrCpy(t->Name, sizeof(t->Name), name);

	sess = GetSessionByName(h, t->Name);

	if (sess == NULL)
	{
		ret = ERR_OBJECT_NOT_FOUND;
	}
	else
	{
		SESSION *s = sess;

		Lock(s->lock);
		{
			StrCpy(t->Username, sizeof(t->Username), s->Username);
			StrCpy(t->RealUsername, sizeof(t->RealUsername), s->UserNameReal);
			StrCpy(t->GroupName, sizeof(t->GroupName), s->GroupName);
			Copy(&t->NodeInfo, &s->NodeInfo, sizeof(NODE_INFO));

			if (s->Connection != NULL)
			{
				t->ClientIp = IPToUINT(&s->Connection->ClientIp);
				if (IsIP6(&s->Connection->ClientIp))
				{
					Copy(&t->ClientIp6, &s->Connection->ClientIp.address, sizeof(t->ClientIp6));
				}

				CopyIP(&t->ClientIpAddress, &s->Connection->ClientIp);

				StrCpy(t->ClientHostName, sizeof(t->ClientHostName), s->Connection->ClientHostname);
			}
		}
		Unlock(s->lock);

		CiGetSessionStatus(&t->Status, s);

		ReleaseSession(s);
	}

	ReleaseHub(h);

	return ret;
}

void SiEnumSessionMain(SERVER *s, RPC_ENUM_SESSION *t)
{
	char hubname[MAX_HUBNAME_LEN + 1];
	UINT ret = ERR_NO_ERROR;
	UINT num;
	if (s == NULL || t == NULL)
	{
		return;
	}

	StrCpy(hubname, sizeof(hubname), t->HubName);

	FreeRpcEnumSession(t);
	Zero(t, sizeof(RPC_ENUM_SESSION));
	StrCpy(t->HubName, sizeof(t->HubName), hubname);

	num = 0;
	SiEnumLocalSession(s, hubname, t);

}

static UINT StEnumSession(ADMIN *a, RPC_ENUM_SESSION *t)
{
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;
	HUB *h = NULL;
	UINT ret = ERR_NO_ERROR;

	CHECK_RIGHT;

	LockHubList(c);
	{
		h = GetHub(c, t->HubName);
	}
	UnlockHubList(c);

	if (h == NULL)
	{
		return ERR_HUB_NOT_FOUND;
	}

	if (a->ServerAdmin == false && GetHubAdminOption(h, "no_enum_session") != 0)
	{
		ReleaseHub(h);
		return ERR_NOT_ENOUGH_RIGHT;
	}

	SiEnumSessionMain(s, t);

	ReleaseHub(h);

	return ret;
}

static UINT StEnumGroup(ADMIN *a, RPC_ENUM_GROUP *t)
{
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;
	HUB *h = NULL;
	UINT ret = ERR_NO_ERROR;
	char hubname[MAX_HUBNAME_LEN + 1];

	StrCpy(hubname, sizeof(hubname), t->HubName);

	CHECK_RIGHT;

	NO_SUPPORT_FOR_BRIDGE;

	LockHubList(c);
	{
		h = GetHub(c, t->HubName);
	}
	UnlockHubList(c);

	if (h == NULL)
	{
		return ERR_HUB_NOT_FOUND;
	}

	AcLock(h);
	{
		UINT i, j;

		FreeRpcEnumGroup(t);
		Zero(t, sizeof(RPC_ENUM_GROUP));
		StrCpy(t->HubName, sizeof(t->HubName), hubname);

		t->NumGroup = LIST_NUM(h->HubDb->GroupList);
		t->Groups = ZeroMalloc(sizeof(RPC_ENUM_GROUP_ITEM) * t->NumGroup);

		for (i = 0;i < t->NumGroup;i++)
		{
			RPC_ENUM_GROUP_ITEM *e = &t->Groups[i];
			USERGROUP *g = LIST_DATA(h->HubDb->GroupList, i);

			Lock(g->lock);
			{
				StrCpy(e->Name, sizeof(e->Name), g->Name);
				UniStrCpy(e->Realname, sizeof(e->Realname), g->RealName);
				UniStrCpy(e->Note, sizeof(e->Note), g->Note);
				if (g->Policy != NULL)
				{
					if (g->Policy->Access == false)
					{
						e->DenyAccess = true;
					}
				}
			}
			Unlock(g->lock);

			e->NumUsers = 0;


			LockList(h->HubDb->UserList);
			{
				for (j = 0;j < LIST_NUM(h->HubDb->UserList);j++)
				{
					USER *u = LIST_DATA(h->HubDb->UserList, j);

					Lock(u->lock);
					{
						if (u->Group == g)
						{
							e->NumUsers++;
						}
					}
					Unlock(u->lock);
				}
			}
			UnlockList(h->HubDb->UserList);
		}
	}
	AcUnlock(h);

	ReleaseHub(h);

	return ERR_NO_ERROR;
}

static UINT StDeleteGroup(ADMIN *a, RPC_DELETE_USER *t)
{
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;
	HUB *h = NULL;
	UINT ret = ERR_NO_ERROR;

	if (IsEmptyStr(t->Name) || IsSafeStr(t->Name) == false)
	{
		return ERR_INVALID_PARAMETER;
	}

	CHECK_RIGHT;

	NO_SUPPORT_FOR_BRIDGE;
	LockHubList(c);
	{
		h = GetHub(c, t->HubName);
	}
	UnlockHubList(c);

	if (h == NULL)
	{
		return ERR_HUB_NOT_FOUND;
	}

	if (a->ServerAdmin == false && GetHubAdminOption(h, "no_change_groups") != 0)
	{
		ReleaseHub(h);
		return ERR_NOT_ENOUGH_RIGHT;
	}

	AcLock(h);
	{
		if (AcDeleteGroup(h, t->Name) == false)
		{
			ret = ERR_OBJECT_NOT_FOUND;
		}
	}
	AcUnlock(h);

	if (ret == ERR_NO_ERROR)
	{
		ALog(a, h, "LA_DELETE_GROUP", t->Name);
	}

	ReleaseHub(h);

	IncrementServerConfigRevision(s);

	return ret;
}

static UINT StGetGroup(ADMIN *a, RPC_SET_GROUP *t)
{
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;
	HUB *h = NULL;
	UINT ret = ERR_NO_ERROR;
	char hubname[MAX_HUBNAME_LEN + 1];

	if (IsEmptyStr(t->Name) || IsSafeStr(t->Name) == false)
	{
		return ERR_INVALID_PARAMETER;
	}

	CHECK_RIGHT;
	NO_SUPPORT_FOR_BRIDGE;
	StrCpy(hubname, sizeof(hubname), t->HubName);

	LockHubList(c);
	{
		h = GetHub(c, t->HubName);
	}
	UnlockHubList(c);

	if (h == NULL)
	{
		return ERR_HUB_NOT_FOUND;
	}

	AcLock(h);
	{
		USERGROUP *g = AcGetGroup(h, t->Name);

		if (g == NULL)
		{
			ret = ERR_OBJECT_NOT_FOUND;
		}
		else
		{
			FreeRpcSetGroup(t);
			Zero(t, sizeof(RPC_SET_GROUP));

			StrCpy(t->HubName, sizeof(t->HubName), hubname);

			Lock(g->lock);
			{
				StrCpy(t->Name, sizeof(t->Name), g->Name);
				UniStrCpy(t->Realname, sizeof(t->Realname), g->RealName);
				UniStrCpy(t->Note, sizeof(t->Note), g->Note);
				Copy(&t->Traffic, g->Traffic, sizeof(TRAFFIC));
			}
			Unlock(g->lock);

			t->Policy = GetGroupPolicy(g);

			ReleaseGroup(g);
		}
	}
	AcUnlock(h);

	ReleaseHub(h);

	return ret;
}

static UINT StSetGroup(ADMIN *a, RPC_SET_GROUP *t)
{
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;
	HUB *h = NULL;
	UINT ret = ERR_NO_ERROR;

	if (IsEmptyStr(t->Name) || IsSafeStr(t->Name) == false)
	{
		return ERR_INVALID_PARAMETER;
	}

	CHECK_RIGHT;
	NO_SUPPORT_FOR_BRIDGE;
	LockHubList(c);
	{
		h = GetHub(c, t->HubName);
	}
	UnlockHubList(c);

	if (h == NULL)
	{
		return ERR_HUB_NOT_FOUND;
	}

	if (a->ServerAdmin == false && GetHubAdminOption(h, "no_change_groups") != 0)
	{
		ReleaseHub(h);
		return ERR_NOT_ENOUGH_RIGHT;
	}

	AcLock(h);
	{
		USERGROUP *g = AcGetGroup(h, t->Name);
		if (g == NULL)
		{
			ret = ERR_OBJECT_NOT_FOUND;
		}
		else
		{
			Lock(g->lock);
			{
				Free(g->RealName);
				Free(g->Note);
				g->RealName = UniCopyStr(t->Realname);
				g->Note = UniCopyStr(t->Note);
			}
			Unlock(g->lock);

			SetGroupPolicy(g, t->Policy);

			ReleaseGroup(g);

			ALog(a, h, "LA_SET_GROUP", t->Name);
		}
	}
	AcUnlock(h);

	ReleaseHub(h);

	IncrementServerConfigRevision(s);

	return ret;
}

static UINT StCreateGroup(ADMIN *a, RPC_SET_GROUP *t)
{
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;
	HUB *h = NULL;
	UINT ret = ERR_NO_ERROR;

	if (IsEmptyStr(t->Name) || IsSafeStr(t->Name) == false)
	{
		return ERR_INVALID_PARAMETER;
	}

	CHECK_RIGHT;

	NO_SUPPORT_FOR_BRIDGE;
	LockHubList(c);
	{
		h = GetHub(c, t->HubName);
	}
	UnlockHubList(c);

	if (h == NULL)
	{
		return ERR_HUB_NOT_FOUND;
	}

	if (a->ServerAdmin == false && GetHubAdminOption(h, "no_change_groups") != 0)
	{
		ReleaseHub(h);
		return ERR_NOT_ENOUGH_RIGHT;
	}

	AcLock(h);
	{
		if (AcIsGroup(h, t->Name))
		{
			ret = ERR_GROUP_ALREADY_EXISTS;
		}
		else
		{
			USERGROUP *g = NewGroup(t->Name, t->Realname, t->Note);
			SetGroupPolicy(g, t->Policy);

			if ((LIST_NUM(h->HubDb->GroupList) >= GetServerCapsInt(a->Server, "i_max_users_per_hub")) ||
				((GetHubAdminOption(h, "max_groups") != 0) && (LIST_NUM(h->HubDb->GroupList) >= GetHubAdminOption(h, "max_groups"))))
			{
				ret = ERR_TOO_MANY_GROUP;
			}
			else
			{
				AcAddGroup(h, g);
			}

			ReleaseGroup(g);

			ALog(a, h, "LA_CREATE_GROUP", t->Name);
		}
	}
	AcUnlock(h);

	ReleaseHub(h);

	IncrementServerConfigRevision(s);

	return ret;
}

static UINT StEnumUser(ADMIN *a, RPC_ENUM_USER *t)
{
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;
	HUB *h = NULL;
	UINT ret = ERR_NO_ERROR;
	char hubname[MAX_HUBNAME_LEN + 1];
	UINT i, num;

	CHECK_RIGHT;
	NO_SUPPORT_FOR_BRIDGE;
	LockHubList(c);
	{
		h = GetHub(c, t->HubName);
	}
	UnlockHubList(c);

	if (h == NULL)
	{
		return ERR_HUB_NOT_FOUND;
	}

	FreeRpcEnumUser(t);

	StrCpy(hubname, sizeof(hubname), t->HubName);

	Zero(t, sizeof(RPC_ENUM_USER));
	StrCpy(t->HubName, sizeof(t->HubName), hubname);

	LockList(h->HubDb->UserList);
	{
		num = LIST_NUM(h->HubDb->UserList);

		t->NumUser = num;
		t->Users = ZeroMalloc(sizeof(RPC_ENUM_USER_ITEM) * num);

		for (i = 0;i < num;i++)
		{
			USER *u = LIST_DATA(h->HubDb->UserList, i);

			Lock(u->lock);
			{
				RPC_ENUM_USER_ITEM *e = &t->Users[i];

				StrCpy(e->Name, sizeof(e->Name), u->Name);
				StrCpy(e->GroupName, sizeof(e->GroupName), u->GroupName);
				UniStrCpy(e->Realname, sizeof(e->Realname), u->RealName);
				UniStrCpy(e->Note, sizeof(e->Note), u->Note);
				e->AuthType = u->AuthType;
				e->LastLoginTime = u->LastLoginTime;
				e->NumLogin = u->NumLogin;

				if (u->Policy != NULL)
				{
					e->DenyAccess = u->Policy->Access ? false : true;
				}

				Copy(&e->Traffic, u->Traffic, sizeof(TRAFFIC));
				e->IsTrafficFilled = true;

				e->Expires = u->ExpireTime;
				e->IsExpiresFilled = true;
			}
			Unlock(u->lock);
		}
	}
	UnlockList(h->HubDb->UserList);

	ReleaseHub(h);

	IncrementServerConfigRevision(s);

	return ERR_NO_ERROR;
}

static UINT StDeleteUser(ADMIN *a, RPC_DELETE_USER *t)
{
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;
	HUB *h = NULL;
	UINT ret = ERR_NO_ERROR;


	if (IsEmptyStr(t->Name) || IsUserName(t->Name) == false)
	{
		return ERR_INVALID_PARAMETER;
	}

	CHECK_RIGHT;
	NO_SUPPORT_FOR_BRIDGE;
	LockHubList(c);
	{
		h = GetHub(c, t->HubName);
	}
	UnlockHubList(c);

	if (h == NULL)
	{
		return ERR_HUB_NOT_FOUND;
	}

	if (a->ServerAdmin == false && GetHubAdminOption(h, "no_change_users") != 0)
	{
		ReleaseHub(h);
		return ERR_NOT_ENOUGH_RIGHT;
	}

	ALog(a, h, "LA_DELETE_USER", t->Name);

	AcLock(h);
	{
		if (AcDeleteUser(h, t->Name) == false)
		{
			ret = ERR_OBJECT_NOT_FOUND;
		}
	}
	AcUnlock(h);

	ReleaseHub(h);

	IncrementServerConfigRevision(s);

	return ret;
}

static UINT StGetUser(ADMIN *a, RPC_SET_USER *t)
{
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;
	HUB *h = NULL;
	UINT ret = ERR_NO_ERROR;
	USER *u = NULL;
	USERGROUP *g = NULL;
	char name[MAX_USERNAME_LEN + 1];
	char hubname[MAX_HUBNAME_LEN + 1];
	StrCpy(name, sizeof(name), t->Name);
	StrCpy(hubname, sizeof(hubname), t->HubName);

	if (IsEmptyStr(t->Name) || IsUserName(t->Name) == false)
	{
		return ERR_INVALID_PARAMETER;
	}

	CHECK_RIGHT;
	NO_SUPPORT_FOR_BRIDGE;
	FreeRpcSetUser(t);
	Zero(t, sizeof(RPC_SET_USER));
	StrCpy(t->HubName, sizeof(t->HubName), hubname);
	StrCpy(t->Name, sizeof(t->Name), name);

	LockHubList(c);
	{
		h = GetHub(c, hubname);
	}
	UnlockHubList(c);

	if (h == NULL)
	{
		return ERR_HUB_NOT_FOUND;
	}

	AcLock(h);
	{
		u = AcGetUser(h, name);
		if (u == NULL)
		{
			ret = ERR_OBJECT_NOT_FOUND;
		}
		else
		{
			Lock(u->lock);
			{
				StrCpy(t->GroupName, sizeof(t->GroupName), u->GroupName);
				UniStrCpy(t->Realname, sizeof(t->Realname), u->RealName);
				UniStrCpy(t->Note, sizeof(t->Note), u->Note);
				t->CreatedTime = u->CreatedTime;
				t->UpdatedTime = u->UpdatedTime;
				t->ExpireTime = u->ExpireTime;

				t->AuthType = u->AuthType;
				t->AuthData = CopyAuthData(u->AuthData, t->AuthType);
				t->NumLogin = u->NumLogin;
				Copy(&t->Traffic, u->Traffic, sizeof(TRAFFIC));
				if (u->Policy != NULL)
				{
					t->Policy = ClonePolicy(u->Policy);
				}
			}
			Unlock(u->lock);

			ReleaseUser(u);
		}
	}
	AcUnlock(h);

	ReleaseHub(h);

	return ret;
}

static UINT StSetUser(ADMIN *a, RPC_SET_USER *t)
{
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;
	HUB *h = NULL;
	UINT ret = ERR_NO_ERROR;
	USER *u = NULL;
	USERGROUP *g = NULL;


	if (IsEmptyStr(t->Name) || IsUserName(t->Name) == false)
	{
		return ERR_INVALID_PARAMETER;
	}

	NO_SUPPORT_FOR_BRIDGE;
	CHECK_RIGHT;

	if (GetGlobalServerFlag(GSF_DISABLE_RADIUS_AUTH) != 0)
	{
		if (t->AuthType == AUTHTYPE_USERCERT || t->AuthType == AUTHTYPE_ROOTCERT || t->AuthType == AUTHTYPE_NT)
		{
			return ERR_NOT_SUPPORTED_AUTH_ON_OPENSOURCE;
		}
	}

	if (StrCmpi(t->Name, "*") == 0)
	{
		if (t->AuthType != AUTHTYPE_NT)
		{
			return ERR_INVALID_PARAMETER;
		}
	}

	if (t->AuthType == AUTHTYPE_USERCERT)
	{
		AUTHUSERCERT *c = t->AuthData;
		if (c != NULL && c->UserX != NULL &&
			c->UserX->is_compatible_bit == false)
		{
			return ERR_NOT_RSA_1024;
		}
		if (c == NULL || c->UserX == NULL)
		{
			return ERR_INVALID_PARAMETER;
		}
	}

	LockHubList(c);
	{
		h = GetHub(c, t->HubName);
	}
	UnlockHubList(c);

	if (h == NULL)
	{
		return ERR_HUB_NOT_FOUND;
	}

	if (a->ServerAdmin == false && GetHubAdminOption(h, "no_change_users") != 0)
	{
		ReleaseHub(h);
		return ERR_NOT_ENOUGH_RIGHT;
	}

	AcLock(h);
	{
		u = AcGetUser(h, t->Name);
		if (u == NULL)
		{
			ret = ERR_OBJECT_NOT_FOUND;
		}
		else
		{
			Lock(u->lock);
			{
				if (StrLen(t->GroupName) != 0)
				{
					g = AcGetGroup(h, t->GroupName);

					if (g != NULL)
					{
						JoinUserToGroup(u, g);
						ReleaseGroup(g);
					}
					else
					{
						ret = ERR_GROUP_NOT_FOUND;
					}
				}
				else
				{
					JoinUserToGroup(u, NULL);
				}

				if (ret != ERR_GROUP_NOT_FOUND)
				{
					Free(u->RealName);
					Free(u->Note);
					u->RealName = UniCopyStr(t->Realname);
					u->Note = UniCopyStr(t->Note);
					SetUserAuthData(u, t->AuthType, CopyAuthData(t->AuthData, t->AuthType));
					u->ExpireTime = t->ExpireTime;
					u->UpdatedTime = SystemTime64();

					SetUserPolicy(u, t->Policy);
				}
			}
			Unlock(u->lock);

			IncrementServerConfigRevision(s);

			ReleaseUser(u);
		}
	}
	AcUnlock(h);

	if (ret == ERR_NO_ERROR)
	{
		ALog(a, h, "LA_SET_USER", t->Name);
	}

	ReleaseHub(h);

	return ret;
}

static UINT StCreateUser(ADMIN *a, RPC_SET_USER *t)
{
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;
	HUB *h = NULL;
	UINT ret = ERR_NO_ERROR;
	USER *u;
	USERGROUP *g = NULL;


	if (IsEmptyStr(t->Name) || IsUserName(t->Name) == false)
	{
		return ERR_INVALID_PARAMETER;
	}

	NO_SUPPORT_FOR_BRIDGE;
	CHECK_RIGHT;

	if (GetGlobalServerFlag(GSF_DISABLE_RADIUS_AUTH) != 0)
	{
		if (t->AuthType == AUTHTYPE_USERCERT || t->AuthType == AUTHTYPE_ROOTCERT || t->AuthType == AUTHTYPE_NT)
		{
			return ERR_NOT_SUPPORTED_AUTH_ON_OPENSOURCE;
		}
	}

	if (t->AuthType == AUTHTYPE_USERCERT)
	{
		AUTHUSERCERT *c = t->AuthData;
		if (c != NULL && c->UserX != NULL &&
			c->UserX->is_compatible_bit == false)
		{
			return ERR_NOT_RSA_1024;
		}
		if (c == NULL || c->UserX == NULL)
		{
			return ERR_INVALID_PARAMETER;
		}
	}

	if (IsUserName(t->Name) == false)
	{
		return ERR_INVALID_PARAMETER;
	}

	if (StrCmpi(t->Name, "*") == 0)
	{
		if (t->AuthType != AUTHTYPE_NT)
		{
			return ERR_INVALID_PARAMETER;
		}
	}

	LockHubList(c);
	{
		h = GetHub(c, t->HubName);
	}
	UnlockHubList(c);

	if (h == NULL)
	{
		return ERR_HUB_NOT_FOUND;
	}

	if (a->ServerAdmin == false && GetHubAdminOption(h, "no_change_users") != 0)
	{
		ReleaseHub(h);
		return ERR_NOT_ENOUGH_RIGHT;
	}

	u = NewUser(t->Name, t->Realname, t->Note, t->AuthType, CopyAuthData(t->AuthData, t->AuthType));
	if (u == NULL)
	{
		ReleaseHub(h);
		return ERR_INTERNAL_ERROR;
	}

	u->ExpireTime = t->ExpireTime;

	SetUserPolicy(u, t->Policy);

	AcLock(h);
	{
		if ((LIST_NUM(h->HubDb->UserList) >= GetServerCapsInt(a->Server, "i_max_users_per_hub")) ||
			((GetHubAdminOption(h, "max_users") != 0) && (LIST_NUM(h->HubDb->UserList) >= GetHubAdminOption(h, "max_users"))))
		{
			ret = ERR_TOO_MANY_USER;
		}
		else if (SiTooManyUserObjectsInServer(s, false))
		{
			ret = ERR_TOO_MANY_USERS_CREATED;
			ALog(a, h, "ERR_128");
		}
		else if (AcIsUser(h, t->Name))
		{
			ret = ERR_USER_ALREADY_EXISTS;
		}
		else
		{
			if (StrLen(t->GroupName) != 0)
			{
				g = AcGetGroup(h, t->GroupName);
				if (g == NULL)
				{
					ret = ERR_GROUP_NOT_FOUND;
				}
			}

			if (ret != ERR_GROUP_NOT_FOUND)
			{
				if (g != NULL)
				{
					JoinUserToGroup(u, g);
					ReleaseGroup(g);
				}

				AcAddUser(h, u);
				ALog(a, h, "LA_CREATE_USER", t->Name);

				IncrementServerConfigRevision(s);
			}
		}
	}
	AcUnlock(h);

	ReleaseUser(u);

	ReleaseHub(h);

	return ret;
}

static UINT StEnumAccess(ADMIN *a, RPC_ENUM_ACCESS_LIST *t)
{
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;
	HUB *h;
	UINT i;
	char hubname[MAX_HUBNAME_LEN + 1];

	CHECK_RIGHT;
	NO_SUPPORT_FOR_BRIDGE;
	LockHubList(c);
	{
		h = GetHub(c, t->HubName);
	}
	UnlockHubList(c);

	if (h == NULL)
	{
		return ERR_HUB_NOT_FOUND;
	}

	StrCpy(hubname, sizeof(hubname), t->HubName);
	FreeRpcEnumAccessList(t);
	Zero(t, sizeof(RPC_ENUM_ACCESS_LIST));
	StrCpy(t->HubName, sizeof(t->HubName), hubname);

	LockList(h->AccessList);
	{
		t->NumAccess = LIST_NUM(h->AccessList);
		t->Accesses = ZeroMalloc(sizeof(ACCESS) * t->NumAccess);

		for (i = 0;i < LIST_NUM(h->AccessList);i++)
		{
			ACCESS *a = &t->Accesses[i];
			Copy(a, LIST_DATA(h->AccessList, i), sizeof(ACCESS));
			a->UniqueId = HashPtrToUINT(LIST_DATA(h->AccessList, i));
		}
	}
	UnlockList(h->AccessList);

	ReleaseHub(h);

	return ERR_NO_ERROR;
}

static UINT StDeleteAccess(ADMIN *a, RPC_DELETE_ACCESS *t)
{
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;
	HUB *h;
	UINT i;
	bool exists;


	CHECK_RIGHT;
	NO_SUPPORT_FOR_BRIDGE;

	LockHubList(c);
	{
		h = GetHub(c, t->HubName);
	}
	UnlockHubList(c);

	if (h == NULL)
	{
		return ERR_HUB_NOT_FOUND;
	}

	if (a->ServerAdmin == false && GetHubAdminOption(h, "no_change_access_list") != 0)
	{
		ReleaseHub(h);
		return ERR_NOT_ENOUGH_RIGHT;
	}

	exists = false;

	LockList(h->AccessList);
	{
		for (i = 0;i < LIST_NUM(h->AccessList);i++)
		{
			ACCESS *access = LIST_DATA(h->AccessList, i);

			if ((t->Id < MAX_ACCESSLISTS && access->Id == t->Id) ||
				(t->Id >= MAX_ACCESSLISTS && HashPtrToUINT(access) == t->Id))
			{
				Free(access);
				Delete(h->AccessList, access);
				exists = true;

				break;
			}
		}
	}
	UnlockList(h->AccessList);

	if (exists == false)
	{
		ReleaseHub(h);
		return ERR_OBJECT_NOT_FOUND;
	}

	ALog(a, h, "LA_DELETE_ACCESS");

	IncrementServerConfigRevision(s);

	ReleaseHub(h);

	return ERR_NO_ERROR;
}

static UINT StSetAccessList(ADMIN *a, RPC_ENUM_ACCESS_LIST *t)
{
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;
	HUB *h;
	UINT i;
	bool no_jitter = false;
	bool no_include = false;

	NO_SUPPORT_FOR_BRIDGE;
	CHECK_RIGHT;

	if (t->NumAccess > GetServerCapsInt(a->Server, "i_max_access_lists"))
	{
		return ERR_TOO_MANY_ACCESS_LIST;
	}

	LockHubList(c);
	{
		h = GetHub(c, t->HubName);
	}
	UnlockHubList(c);

	if (h == NULL)
	{
		return ERR_HUB_NOT_FOUND;
	}

	no_jitter = GetHubAdminOption(h, "no_delay_jitter_packet_loss");
	no_include = GetHubAdminOption(h, "no_access_list_include_file");

	if (a->ServerAdmin == false && GetHubAdminOption(h, "no_change_access_list") != 0)
	{
		ReleaseHub(h);
		return ERR_NOT_ENOUGH_RIGHT;
	}

	if (a->ServerAdmin == false && GetHubAdminOption(h, "max_accesslists") != 0 &&
		t->NumAccess > GetHubAdminOption(h, "max_accesslists"))
	{
		ReleaseHub(h);
		return ERR_TOO_MANY_ACCESS_LIST;
	}

	LockList(h->AccessList);
	{
		for (i = 0; i < LIST_NUM(h->AccessList); ++i)
		{
			ACCESS *access = LIST_DATA(h->AccessList, i);
			Free(access);
		}

		DeleteAll(h->AccessList);

		ALog(a, h, "LA_SET_ACCESS_LIST", t->NumAccess);

		for (i = 0; i < t->NumAccess; ++i)
		{
			ACCESS *a = &t->Accesses[i];

			if (no_jitter)
			{
				a->Jitter = a->Loss = a->Delay = 0;
			}

			if (no_include)
			{
				if (StartWith(a->SrcUsername, ACCESS_LIST_INCLUDED_PREFIX) ||
					StartWith(a->SrcUsername, ACCESS_LIST_EXCLUDED_PREFIX))
				{
					ClearStr(a->SrcUsername, sizeof(a->SrcUsername));
				}

				if (StartWith(a->DestUsername, ACCESS_LIST_INCLUDED_PREFIX) ||
					StartWith(a->DestUsername, ACCESS_LIST_EXCLUDED_PREFIX))
				{
					ClearStr(a->DestUsername, sizeof(a->DestUsername));
				}
			}

			if (i == (t->NumAccess - 1))
			{
				Sort(h->AccessList);
			}

			AddAccessListEx(h, a, ((i != (t->NumAccess - 1)) ? true : false), ((i != (t->NumAccess - 1)) ? true : false));
		}

		UnlockList(h->AccessList);

		IncrementServerConfigRevision(s);

	}

	ReleaseHub(h);

	return ERR_NO_ERROR;
}

static UINT StAddAccess(ADMIN *a, RPC_ADD_ACCESS *t)
{
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;
	HUB *h;
	bool no_jitter = false;
	bool no_include = false;


	NO_SUPPORT_FOR_BRIDGE;
	CHECK_RIGHT;

	LockHubList(c);
	{
		h = GetHub(c, t->HubName);
	}
	UnlockHubList(c);

	if (h == NULL)
	{
		return ERR_HUB_NOT_FOUND;
	}

	no_jitter = GetHubAdminOption(h, "no_delay_jitter_packet_loss");
	no_include = GetHubAdminOption(h, "no_access_list_include_file");

	if (a->ServerAdmin == false && GetHubAdminOption(h, "no_change_access_list") != 0)
	{
		ReleaseHub(h);
		return ERR_NOT_ENOUGH_RIGHT;
	}

	if ((LIST_NUM(h->AccessList) >= GetServerCapsInt(a->Server, "i_max_access_lists") ||
		(GetHubAdminOption(h, "max_accesslists") != 0) && (LIST_NUM(h->AccessList) >= GetHubAdminOption(h, "max_accesslists"))))
	{
		ReleaseHub(h);
		return ERR_TOO_MANY_ACCESS_LIST;
	}

	ALog(a, h, "LA_ADD_ACCESS");

	if (no_jitter)
	{
		t->Access.Jitter = t->Access.Delay = t->Access.Loss = 0;
	}

	if (no_include)
	{
		if (StartWith(t->Access.SrcUsername, ACCESS_LIST_INCLUDED_PREFIX) ||
			StartWith(t->Access.SrcUsername, ACCESS_LIST_EXCLUDED_PREFIX))
		{
			ClearStr(t->Access.SrcUsername, sizeof(t->Access.SrcUsername));
		}

		if (StartWith(t->Access.DestUsername, ACCESS_LIST_INCLUDED_PREFIX) ||
			StartWith(t->Access.DestUsername, ACCESS_LIST_EXCLUDED_PREFIX))
		{
			ClearStr(t->Access.DestUsername, sizeof(t->Access.DestUsername));
		}
	}

	AddAccessListEx(h, &t->Access, false, false);

	ReleaseHub(h);

	IncrementServerConfigRevision(s);

	return ERR_NO_ERROR;
}

static UINT StRenameLink(ADMIN *a, RPC_RENAME_LINK *t)
{
	UINT i;
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;
	HUB *h;
	UINT ret = ERR_NO_ERROR;
	LINK *k;
	bool exists = false;

	if (UniIsEmptyStr(t->OldAccountName) || UniIsEmptyStr(t->NewAccountName))
	{
		return ERR_INVALID_PARAMETER;
	}

	CHECK_RIGHT;

	if (UniStrCmpi(t->NewAccountName, t->OldAccountName) == 0)
	{
		return ERR_NO_ERROR;
	}

	h = GetHub(c, t->HubName);

	if (h == NULL)
	{
		return ERR_HUB_NOT_FOUND;
	}

	if (a->ServerAdmin == false && GetHubAdminOption(h, "no_cascade") != 0)
	{
		ReleaseHub(h);
		return ERR_NOT_ENOUGH_RIGHT;
	}

	k = NULL;

	LockList(h->LinkList);
	{
		for (i = 0;i < LIST_NUM(h->LinkList);i++)
		{
			LINK *kk = LIST_DATA(h->LinkList, i);
			Lock(kk->lock);
			{
				if (UniStrCmpi(kk->Option->AccountName, t->OldAccountName) == 0)
				{
					k = kk;
					AddRef(kk->ref);
				}
			}
			Unlock(kk->lock);

			if (k != NULL)
			{
				break;
			}
		}

		exists = false;

		if (k != NULL)
		{
			for (i = 0;i < LIST_NUM(h->LinkList);i++)
			{
				LINK *kk = LIST_DATA(h->LinkList, i);
				Lock(kk->lock);
				{
					if (UniStrCmpi(kk->Option->AccountName, t->NewAccountName) == 0)
					{
						exists = true;
					}
				}
				Unlock(kk->lock);
			}

			if (exists)
			{
				ret = ERR_LINK_ALREADY_EXISTS;
			}
			else
			{
				UniStrCpy(k->Option->AccountName, sizeof(k->Option->AccountName), t->NewAccountName);

				ALog(a, h, "LA_RENAME_LINK", t->OldAccountName, t->NewAccountName);

				IncrementServerConfigRevision(s);
			}
		}
	}
	UnlockList(h->LinkList);

	if (k == NULL)
	{
		ReleaseHub(h);
		return ERR_OBJECT_NOT_FOUND;
	}

	ReleaseLink(k);

	ReleaseHub(h);

	return ret;
}

static UINT StDeleteLink(ADMIN *a, RPC_LINK *t)
{
	UINT i;
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;
	HUB *h;
	UINT ret = ERR_NO_ERROR;
	char hubname[MAX_HUBNAME_LEN + 1];
	wchar_t accountname[MAX_ACCOUNT_NAME_LEN + 1];
	LINK *k;

	if (UniIsEmptyStr(t->AccountName))
	{
		return ERR_INVALID_PARAMETER;
	}

	CHECK_RIGHT;

	LockHubList(c);
	{
		h = GetHub(c, t->HubName);
	}
	UnlockHubList(c);

	if (h == NULL)
	{
		return ERR_HUB_NOT_FOUND;
	}

	if (a->ServerAdmin == false && GetHubAdminOption(h, "no_cascade") != 0)
	{
		ReleaseHub(h);
		return ERR_NOT_ENOUGH_RIGHT;
	}

	StrCpy(hubname, sizeof(hubname), t->HubName);
	UniStrCpy(accountname, sizeof(accountname), t->AccountName);
	k = NULL;

	LockList(h->LinkList);
	{
		for (i = 0;i < LIST_NUM(h->LinkList);i++)
		{
			LINK *kk = LIST_DATA(h->LinkList, i);
			Lock(kk->lock);
			{
				if (UniStrCmpi(kk->Option->AccountName, accountname) == 0)
				{
					k = kk;
					AddRef(kk->ref);
				}
			}
			Unlock(kk->lock);

			if (k != NULL)
			{
				break;
			}
		}
	}
	UnlockList(h->LinkList);

	if (k == NULL)
	{
		ReleaseHub(h);

		return ERR_OBJECT_NOT_FOUND;
	}

	k->NoOnline = true;

	ALog(a, h, "LA_DELETE_LINK", t->AccountName);

	SetLinkOffline(k);

	IncrementServerConfigRevision(s);

	DelLink(h, k);

	ReleaseLink(k);
	ReleaseHub(h);

	return ret;
}

static UINT StSetLinkOffline(ADMIN *a, RPC_LINK *t)
{
	UINT i;
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;
	HUB *h;
	UINT ret = ERR_NO_ERROR;
	char hubname[MAX_HUBNAME_LEN + 1];
	wchar_t accountname[MAX_ACCOUNT_NAME_LEN + 1];
	LINK *k;


	if (UniIsEmptyStr(t->AccountName))
	{
		return ERR_INVALID_PARAMETER;
	}

	CHECK_RIGHT;

	LockHubList(c);
	{
		h = GetHub(c, t->HubName);
	}
	UnlockHubList(c);

	if (h == NULL)
	{
		return ERR_HUB_NOT_FOUND;
	}

	if (a->ServerAdmin == false && GetHubAdminOption(h, "no_cascade") != 0)
	{
		ReleaseHub(h);
		return ERR_NOT_ENOUGH_RIGHT;
	}

	StrCpy(hubname, sizeof(hubname), t->HubName);
	UniStrCpy(accountname, sizeof(accountname), t->AccountName);
	k = NULL;

	LockList(h->LinkList);
	{
		for (i = 0;i < LIST_NUM(h->LinkList);i++)
		{
			LINK *kk = LIST_DATA(h->LinkList, i);
			Lock(kk->lock);
			{
				if (UniStrCmpi(kk->Option->AccountName, accountname) == 0)
				{
					k = kk;
					AddRef(kk->ref);
				}
			}
			Unlock(kk->lock);

			if (k != NULL)
			{
				break;
			}
		}
	}
	UnlockList(h->LinkList);

	if (k == NULL)
	{
		ReleaseHub(h);

		return ERR_OBJECT_NOT_FOUND;
	}

	ALog(a, h, "LA_SET_LINK_OFFLINE", t->AccountName);

	SetLinkOffline(k);

	IncrementServerConfigRevision(s);

	ReleaseLink(k);
	ReleaseHub(h);

	return ret;
}

static UINT StSetLinkOnline(ADMIN *a, RPC_LINK *t)
{
	UINT i;
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;
	HUB *h;
	UINT ret = ERR_NO_ERROR;
	char hubname[MAX_HUBNAME_LEN + 1];
	wchar_t accountname[MAX_ACCOUNT_NAME_LEN + 1];
	LINK *k;


	if (UniIsEmptyStr(t->AccountName))
	{
		return ERR_INVALID_PARAMETER;
	}

	CHECK_RIGHT;

	LockHubList(c);
	{
		h = GetHub(c, t->HubName);
	}
	UnlockHubList(c);

	if (h == NULL)
	{
		return ERR_HUB_NOT_FOUND;
	}

	if (a->ServerAdmin == false && GetHubAdminOption(h, "no_cascade") != 0)
	{
		ReleaseHub(h);
		return ERR_NOT_ENOUGH_RIGHT;
	}

	StrCpy(hubname, sizeof(hubname), t->HubName);
	UniStrCpy(accountname, sizeof(accountname), t->AccountName);
	k = NULL;

	LockList(h->LinkList);
	{
		for (i = 0;i < LIST_NUM(h->LinkList);i++)
		{
			LINK *kk = LIST_DATA(h->LinkList, i);
			Lock(kk->lock);
			{
				if (UniStrCmpi(kk->Option->AccountName, accountname) == 0)
				{
					k = kk;
					AddRef(kk->ref);
				}
			}
			Unlock(kk->lock);

			if (k != NULL)
			{
				break;
			}
		}
	}
	UnlockList(h->LinkList);

	if (k == NULL)
	{
		ReleaseHub(h);

		return ERR_OBJECT_NOT_FOUND;
	}

	ALog(a, h, "LA_SET_LINK_ONLINE", t->AccountName);

	SetLinkOnline(k);

	ReleaseLink(k);
	ReleaseHub(h);

	IncrementServerConfigRevision(s);

	return ret;
}

static UINT StGetLinkStatus(ADMIN *a, RPC_LINK_STATUS *t)
{
	UINT i;
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;
	HUB *h;
	UINT ret = ERR_NO_ERROR;
	char hubname[MAX_HUBNAME_LEN + 1];
	wchar_t accountname[MAX_ACCOUNT_NAME_LEN + 1];
	LINK *k;
	SESSION *sess;

	if (UniIsEmptyStr(t->AccountName))
	{
		return ERR_INVALID_PARAMETER;
	}

	CHECK_RIGHT;

	LockHubList(c);
	{
		h = GetHub(c, t->HubName);
	}
	UnlockHubList(c);

	if (h == NULL)
	{
		return ERR_HUB_NOT_FOUND;
	}

	StrCpy(hubname, sizeof(hubname), t->HubName);
	UniStrCpy(accountname, sizeof(accountname), t->AccountName);
	FreeRpcLinkStatus(t);
	Zero(t, sizeof(RPC_LINK_STATUS));
	StrCpy(t->HubName, sizeof(t->HubName), hubname);
	UniStrCpy(t->AccountName, sizeof(t->AccountName), accountname);

	k = NULL;

	LockList(h->LinkList);
	{
		for (i = 0;i < LIST_NUM(h->LinkList);i++)
		{
			LINK *kk = LIST_DATA(h->LinkList, i);
			Lock(kk->lock);
			{
				if (UniStrCmpi(kk->Option->AccountName, accountname) == 0)
				{
					k = kk;
					AddRef(kk->ref);
				}
			}
			Unlock(kk->lock);

			if (k != NULL)
			{
				break;
			}
		}
	}
	UnlockList(h->LinkList);

	if (k == NULL)
	{
		ReleaseHub(h);

		return ERR_OBJECT_NOT_FOUND;
	}

	Lock(k->lock);
	{
		sess = k->ClientSession;
		if (sess != NULL)
		{
			AddRef(sess->ref);
		}
	}
	Unlock(k->lock);

	if (sess != NULL && k->Offline == false)
	{
		CiGetSessionStatus(&t->Status, sess);
	}
	else
	{
		ret = ERR_LINK_IS_OFFLINE;
	}
	ReleaseSession(sess);

	ReleaseLink(k);
	ReleaseHub(h);

	return ret;
}

static UINT StEnumLink(ADMIN *a, RPC_ENUM_LINK *t)
{
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;
	HUB *h;
	char hubname[MAX_HUBNAME_LEN + 1];
	UINT i;

	CHECK_RIGHT;

	LockHubList(c);
	{
		h = GetHub(c, t->HubName);
	}
	UnlockHubList(c);

	if (h == NULL)
	{
		return ERR_HUB_NOT_FOUND;
	}

	StrCpy(hubname, sizeof(hubname), t->HubName);
	FreeRpcEnumLink(t);
	Zero(t, sizeof(RPC_ENUM_LINK));
	StrCpy(t->HubName, sizeof(t->HubName), hubname);

	LockList(h->LinkList);
	{
		t->NumLink = LIST_NUM(h->LinkList);
		t->Links = ZeroMalloc(sizeof(RPC_ENUM_LINK_ITEM) * t->NumLink);

		for (i = 0;i < LIST_NUM(h->LinkList);i++)
		{
			LINK *k = LIST_DATA(h->LinkList, i);
			RPC_ENUM_LINK_ITEM *e = &t->Links[i];

			Lock(k->lock);
			{
				UniStrCpy(e->AccountName, sizeof(e->AccountName), k->Option->AccountName);
				StrCpy(e->Hostname, sizeof(e->Hostname), k->Option->Hostname);
				StrCpy(e->HubName, sizeof(e->HubName), k->Option->HubName);
				e->Online = k->Offline ? false : true;

				if (e->Online)
				{
					if (k->ClientSession != NULL)
					{
						e->ConnectedTime = Tick64ToTime64(k->ClientSession->CurrentConnectionEstablishTime);
						e->Connected = (k->ClientSession->ClientStatus == CLIENT_STATUS_ESTABLISHED);
						e->LastError = k->ClientSession->Err;
					}
				}
			}
			Unlock(k->lock);
		}
	}
	UnlockList(h->LinkList);

	ReleaseHub(h);

	return ERR_NO_ERROR;
}

static UINT StGetLink(ADMIN *a, RPC_CREATE_LINK *t)
{
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;
	HUB *h;
	UINT ret = ERR_NO_ERROR;
	UINT i;
	char hubname[MAX_SIZE];
	LINK *k;

	CHECK_RIGHT;

	LockHubList(c);
	{
		h = GetHub(c, t->HubName);
	}
	UnlockHubList(c);

	if (h == NULL)
	{
		return ERR_HUB_NOT_FOUND;
	}

	k = NULL;

	LockList(h->LinkList);
	{
		for (i = 0;i < LIST_NUM(h->LinkList);i++)
		{
			LINK *kk = LIST_DATA(h->LinkList, i);
			Lock(kk->lock);
			{
				if (UniStrCmpi(kk->Option->AccountName, t->ClientOption->AccountName) == 0)
				{
					k = kk;
					AddRef(kk->ref);
				}
			}
			Unlock(kk->lock);

			if (k != NULL)
			{
				break;
			}
		}
	}
	UnlockList(h->LinkList);

	if (k == NULL)
	{
		ReleaseHub(h);
		return ERR_OBJECT_NOT_FOUND;
	}

	StrCpy(hubname, sizeof(hubname), t->HubName);
	FreeRpcCreateLink(t);
	Zero(t, sizeof(RPC_CREATE_LINK));
	StrCpy(t->HubName, sizeof(t->HubName), hubname);

	Lock(k->lock);
	{
		t->Online = k->Offline ? false : true;
		t->ClientOption = ZeroMalloc(sizeof(CLIENT_OPTION));
		Copy(t->ClientOption, k->Option, sizeof(CLIENT_OPTION));
		t->ClientAuth = CopyClientAuth(k->Auth);
		Copy(&t->Policy, k->Policy, sizeof(POLICY));

		t->CheckServerCert = k->CheckServerCert;
		t->AddDefaultCA = k->AddDefaultCA;
		t->ServerCert = CloneX(k->ServerCert);
	}
	Unlock(k->lock);

	ReleaseLink(k);
	ReleaseHub(h);

	return ret;
}

static UINT StSetLink(ADMIN *a, RPC_CREATE_LINK *t)
{
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;
	HUB *h;
	UINT ret = ERR_NO_ERROR;
	UINT i;
	LINK *k;


	CHECK_RIGHT;

	LockHubList(c);
	{
		h = GetHub(c, t->HubName);
	}
	UnlockHubList(c);

	if (h == NULL)
	{
		return ERR_HUB_NOT_FOUND;
	}

	if (a->ServerAdmin == false && GetHubAdminOption(h, "no_cascade") != 0)
	{
		ReleaseHub(h);
		return ERR_NOT_ENOUGH_RIGHT;
	}

	k = NULL;

	LockList(h->LinkList);
	{
		for (i = 0;i < LIST_NUM(h->LinkList);i++)
		{
			LINK *kk = LIST_DATA(h->LinkList, i);
			Lock(kk->lock);
			{
				if (UniStrCmpi(kk->Option->AccountName, t->ClientOption->AccountName) == 0)
				{
					k = kk;
					AddRef(kk->ref);
				}
			}
			Unlock(kk->lock);

			if (k != NULL)
			{
				break;
			}
		}
	}
	UnlockList(h->LinkList);

	if (k == NULL)
	{
		ReleaseHub(h);
		return ERR_OBJECT_NOT_FOUND;
	}

	ALog(a, h, "LA_SET_LINK", t->ClientOption->AccountName);

	Lock(k->lock);
	{
		if (k->ServerCert != NULL)
		{
			FreeX(k->ServerCert);
			k->ServerCert = NULL;
		}

		Copy(k->Option, t->ClientOption, sizeof(CLIENT_OPTION));
		StrCpy(k->Option->DeviceName, sizeof(k->Option->DeviceName), LINK_DEVICE_NAME);
		k->Option->NumRetry = INFINITE;
		k->Option->RetryInterval = 10;
		k->Option->NoRoutingTracking = true;
		CiFreeClientAuth(k->Auth);
		k->Auth = CopyClientAuth(t->ClientAuth);

		if (t->Policy.Ver3 == false)
		{
			Copy(k->Policy, &t->Policy, policy_item[NUM_POLICY_ITEM_FOR_VER2].Offset);
		}
		else
		{
			Copy(k->Policy, &t->Policy, sizeof(POLICY));
		}

		k->Option->RequireBridgeRoutingMode = true;
		k->Option->RequireMonitorMode = false;

		k->CheckServerCert = t->CheckServerCert;
		k->AddDefaultCA = t->AddDefaultCA;
		k->ServerCert = CloneX(t->ServerCert);
	}
	Unlock(k->lock);

	IncrementServerConfigRevision(s);

	ReleaseLink(k);
	ReleaseHub(h);

	return ret;
}

static UINT StCreateLink(ADMIN *a, RPC_CREATE_LINK *t)
{
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;
	HUB *h;
	UINT ret = ERR_NO_ERROR;
	UINT i;
	LINK *k;

	CHECK_RIGHT;


	LockHubList(c);
	{
		h = GetHub(c, t->HubName);
	}
	UnlockHubList(c);

	if (h == NULL)
	{
		return ERR_HUB_NOT_FOUND;
	}

	if (a->ServerAdmin == false && GetHubAdminOption(h, "no_cascade") != 0)
	{
		ReleaseHub(h);
		return ERR_NOT_ENOUGH_RIGHT;
	}

	k = NULL;

	LockList(h->LinkList);
	{
		for (i = 0;i < LIST_NUM(h->LinkList);i++)
		{
			LINK *kk = LIST_DATA(h->LinkList, i);
			Lock(kk->lock);
			{
				if (UniStrCmpi(kk->Option->AccountName, t->ClientOption->AccountName) == 0)
				{
					k = kk;
					AddRef(kk->ref);
				}
			}
			Unlock(kk->lock);

			if (k != NULL)
			{
				break;
			}
		}
	}
	UnlockList(h->LinkList);

	if (k != NULL)
	{
		ReleaseLink(k);
		ReleaseHub(h);
		return ERR_LINK_ALREADY_EXISTS;
	}

	ALog(a, h, "LA_CREATE_LINK", t->ClientOption->AccountName);

	k = NewLink(c, h, t->ClientOption, t->ClientAuth, &t->Policy);

	if (k == NULL)
	{
		ret = ERR_INTERNAL_ERROR;
	}
	else
	{
		k->CheckServerCert = t->CheckServerCert;
		k->AddDefaultCA = t->AddDefaultCA;
		k->ServerCert = CloneX(t->ServerCert);

		k->Offline = false;
		SetLinkOffline(k);
		ReleaseLink(k);

		IncrementServerConfigRevision(s);
	}

	ReleaseHub(h);

	return ret;
}

static UINT StDeleteCa(ADMIN *a, RPC_HUB_DELETE_CA *t)
{
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;
	HUB *h;
	UINT ret = ERR_NO_ERROR;

	NO_SUPPORT_FOR_BRIDGE;
	CHECK_RIGHT;

	LockHubList(c);
	{
		h = GetHub(c, t->HubName);
	}
	UnlockHubList(c);

	if (h == NULL)
	{
		return ERR_HUB_NOT_FOUND;
	}

	if (a->ServerAdmin == false && GetHubAdminOption(h, "no_change_cert_list") != 0)
	{
		ReleaseHub(h);
		return ERR_NOT_ENOUGH_RIGHT;
	}

	LockList(h->HubDb->RootCertList);
	{
		if (IsInListKey(h->HubDb->RootCertList, t->Key))
		{
			X *x = ListKeyToPointer(h->HubDb->RootCertList, t->Key);
			Delete(h->HubDb->RootCertList, x);
			FreeX(x);

			ALog(a, h, "LA_DELETE_CA");

			IncrementServerConfigRevision(s);
		}
		else
		{
			ret = ERR_OBJECT_NOT_FOUND;
		}
	}
	UnlockList(h->HubDb->RootCertList);

	ReleaseHub(h);

	return ret;
}

static UINT StGetCa(ADMIN *a, RPC_HUB_GET_CA *t)
{
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;
	HUB *h;
	UINT ret = ERR_NO_ERROR;
	char hubname[MAX_HUBNAME_LEN + 1];
	UINT key;

	NO_SUPPORT_FOR_BRIDGE;

	StrCpy(hubname, sizeof(hubname), t->HubName);
	key = t->Key;

	FreeRpcHubGetCa(t);
	Zero(t, sizeof(RPC_HUB_GET_CA));
	t->Key = key;
	StrCpy(t->HubName, sizeof(t->HubName), hubname);

	CHECK_RIGHT;

	LockHubList(c);
	{
		h = GetHub(c, t->HubName);
	}
	UnlockHubList(c);

	if (h == NULL)
	{
		return ERR_HUB_NOT_FOUND;
	}

	LockList(h->HubDb->RootCertList);
	{
		if (IsInListKey(h->HubDb->RootCertList, key))
		{
			X *x = ListKeyToPointer(h->HubDb->RootCertList, key);

			t->Cert = CloneX(x);
		}
		else
		{
			ret = ERR_OBJECT_NOT_FOUND;
		}
	}
	UnlockList(h->HubDb->RootCertList);

	ReleaseHub(h);

	return ret;
}

static UINT StEnumCa(ADMIN *a, RPC_HUB_ENUM_CA *t)
{
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;
	HUB *h;
	char hubname[MAX_HUBNAME_LEN + 1];
	UINT i;

	NO_SUPPORT_FOR_BRIDGE;

	StrCpy(hubname, sizeof(hubname), t->HubName);

	FreeRpcHubEnumCa(t);
	Zero(t, sizeof(RPC_HUB_ENUM_CA));

	StrCpy(t->HubName, sizeof(t->HubName), hubname);
	CHECK_RIGHT;

	LockHubList(c);
	{
		h = GetHub(c, hubname);
	}
	UnlockHubList(c);

	if (h == NULL)
	{
		return ERR_HUB_NOT_FOUND;
	}

	Zero(t, sizeof(RPC_HUB_ENUM_CA));
	StrCpy(t->HubName, sizeof(t->HubName), hubname);

	if (h->HubDb->RootCertList != NULL)
	{
		LockList(h->HubDb->RootCertList);
		{
			t->NumCa = LIST_NUM(h->HubDb->RootCertList);
			t->Ca = ZeroMalloc(sizeof(RPC_HUB_ENUM_CA_ITEM) * t->NumCa);

			for (i = 0;i < t->NumCa;i++)
			{
				RPC_HUB_ENUM_CA_ITEM *e = &t->Ca[i];
				X *x = LIST_DATA(h->HubDb->RootCertList, i);

				e->Key = POINTER_TO_KEY(x);
				GetAllNameFromNameEx(e->SubjectName, sizeof(e->SubjectName), x->subject_name);
				GetAllNameFromNameEx(e->IssuerName, sizeof(e->IssuerName), x->issuer_name);
				e->Expires = x->notAfter;
			}
		}
		UnlockList(h->HubDb->RootCertList);
	}

	ReleaseHub(h);

	return ERR_NO_ERROR;
}

static UINT StAddCa(ADMIN *a, RPC_HUB_ADD_CA *t)
{
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;
	HUB *h;

	if (c->Bridge)
	{
		return ERR_NOT_SUPPORTED;
	}

	if (t->Cert == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	CHECK_RIGHT;

	LockHubList(c);
	{
		h = GetHub(c, t->HubName);
	}
	UnlockHubList(c);

	if (h == NULL)
	{
		return ERR_HUB_NOT_FOUND;
	}

	if (a->ServerAdmin == false && GetHubAdminOption(h, "no_change_cert_list") != 0)
	{
		ReleaseHub(h);
		return ERR_NOT_ENOUGH_RIGHT;
	}

	IncrementServerConfigRevision(s);

	ALog(a, h, "LA_ADD_CA");

	AddRootCert(h, t->Cert);

	ReleaseHub(h);

	return ERR_NO_ERROR;
}

static UINT StGetHubLog(ADMIN *a, RPC_HUB_LOG *t)
{
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;
	HUB *h;

	CHECK_RIGHT;

	LockHubList(c);
	{
		h = GetHub(c, t->HubName);
	}
	UnlockHubList(c);

	if (h == NULL)
	{
		return ERR_HUB_NOT_FOUND;
	}

	GetHubLogSetting(h, &t->LogSetting);

	ReleaseHub(h);

	return ERR_NO_ERROR;
}

static UINT StSetHubLog(ADMIN *a, RPC_HUB_LOG *t)
{
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;
	HUB *h;

	CHECK_RIGHT;


	LockHubList(c);
	{
		h = GetHub(c, t->HubName);
	}
	UnlockHubList(c);

	if (h == NULL)
	{
		return ERR_HUB_NOT_FOUND;
	}

	if (a->ServerAdmin == false && GetHubAdminOption(h, "no_change_log_config") != 0)
	{
		ReleaseHub(h);
		return ERR_NOT_ENOUGH_RIGHT;
	}

	ALog(a, h, "LA_SET_HUB_LOG");

	SetHubLogSettingEx(h, &t->LogSetting,
		(a->ServerAdmin == false && GetHubAdminOption(h, "no_change_log_switch_type") != 0));

	ReleaseHub(h);

	IncrementServerConfigRevision(s);

	return ERR_NO_ERROR;
}

static UINT StGetHubStatus(ADMIN *a, RPC_HUB_STATUS *t)
{
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;
	HUB *h;

	CHECK_RIGHT;

	LockHubList(c);
	{
		h = GetHub(c, t->HubName);
	}
	UnlockHubList(c);

	if (h == NULL)
	{
		return ERR_HUB_NOT_FOUND;
	}

	Zero(t, sizeof(RPC_HUB_STATUS));

	Lock(h->lock);
	{
		StrCpy(t->HubName, sizeof(t->HubName), h->Name);
		t->Online = h->Offline ? false : true;
		t->NumSessions = LIST_NUM(h->SessionList);
		t->NumSessionsClient = Count(h->NumSessionsClient);
		t->NumSessionsBridge = Count(h->NumSessionsBridge);
		t->NumAccessLists = LIST_NUM(h->AccessList);

		if (h->HubDb != NULL)
		{
			t->NumUsers = LIST_NUM(h->HubDb->UserList);
			t->NumGroups = LIST_NUM(h->HubDb->GroupList);
		}

		t->NumMacTables = HASH_LIST_NUM(h->MacHashTable);
		t->NumIpTables = LIST_NUM(h->IpTable);

		Lock(h->TrafficLock);
		{
			Copy(&t->Traffic, h->Traffic, sizeof(TRAFFIC));
		}
		Unlock(h->TrafficLock);

		t->NumLogin = h->NumLogin;
		t->LastCommTime = h->LastCommTime;
		t->LastLoginTime = h->LastLoginTime;
		t->CreatedTime = h->CreatedTime;
	}
	Unlock(h->lock);

	ReleaseHub(h);

	return ERR_NO_ERROR;
}

static UINT StSetHubOnline(ADMIN *a, RPC_SET_HUB_ONLINE *t)
{
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;
	HUB *h;


	NO_SUPPORT_FOR_BRIDGE;

	CHECK_RIGHT;

	LockHubList(c);
	{
		h = GetHub(c, t->HubName);
	}
	UnlockHubList(c);

	if (h == NULL)
	{
		return ERR_HUB_NOT_FOUND;
	}

	if (a->ServerAdmin == false && t->Online && GetHubAdminOption(h, "no_online") != 0)
	{
		ReleaseHub(h);
		return ERR_NOT_ENOUGH_RIGHT;
	}

	if (a->ServerAdmin == false && t->Online == false && GetHubAdminOption(h, "no_offline") != 0)
	{
		ReleaseHub(h);
		return ERR_NOT_ENOUGH_RIGHT;
	}

	if (t->Online)
	{
		ALog(a, h, "LA_SET_HUB_ONLINE");
		SetHubOnline(h);
	}
	else
	{
		ALog(a, h, "LA_SET_HUB_OFFLINE");
		SetHubOffline(h);
	}

	IncrementServerConfigRevision(s);

	ReleaseHub(h);

	return ERR_NO_ERROR;
}

static UINT StGetConnectionInfo(ADMIN *a, RPC_CONNECTION_INFO *t)
{
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;
	CONNECTION *connection;
	char name[MAX_CONNECTION_NAME_LEN + 1];

	if (IsEmptyStr(t->Name))
	{
		return ERR_INVALID_PARAMETER;
	}

	SERVER_ADMIN_ONLY;

	LockList(c->ConnectionList);
	{
		CONNECTION tt;
		Zero(&tt, sizeof(tt));
		tt.Name = t->Name;
		StrCpy(name, sizeof(name), t->Name);

		connection = Search(c->ConnectionList, &tt);

		if (connection != NULL)
		{
			AddRef(connection->ref);
		}
	}
	UnlockList(c->ConnectionList);

	if (connection == NULL)
	{
		return ERR_OBJECT_NOT_FOUND;
	}

	Zero(t, sizeof(RPC_CONNECTION_INFO));
	StrCpy(t->Name, sizeof(t->Name), name);

	Lock(connection->lock);
	{
		SOCK *s = connection->FirstSock;

		if (s != NULL)
		{
			t->Ip = IPToUINT(&s->RemoteIP);
			t->Port = s->RemotePort;
			StrCpy(t->Hostname, sizeof(t->Hostname), s->RemoteHostname);
		}

		StrCpy(t->Name, sizeof(t->Name), connection->Name);
		t->ConnectedTime = Tick64ToTime64(connection->ConnectedTick);
		t->Type = connection->Type;

		StrCpy(t->ServerStr, sizeof(t->ServerStr), connection->ServerStr);
		StrCpy(t->ClientStr, sizeof(t->ClientStr), connection->ClientStr);
		t->ServerVer = connection->ServerVer;
		t->ServerBuild = connection->ServerBuild;
		t->ClientVer = connection->ClientVer;
		t->ClientBuild = connection->ClientBuild;
	}
	Unlock(connection->lock);

	ReleaseConnection(connection);

	return ERR_NO_ERROR;
}

static UINT StDisconnectConnection(ADMIN *a, RPC_DISCONNECT_CONNECTION *t)
{
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;
	CONNECTION *connection;

	if (IsEmptyStr(t->Name))
	{
		return ERR_INVALID_PARAMETER;
	}

	SERVER_ADMIN_ONLY;

	LockList(c->ConnectionList);
	{
		CONNECTION tt;
		Zero(&tt, sizeof(tt));
		tt.Name = t->Name;

		connection = Search(c->ConnectionList, &tt);
		if (connection != NULL)
		{
			AddRef(connection->ref);
		}
	}
	UnlockList(c->ConnectionList);

	if (connection == NULL)
	{
		return ERR_OBJECT_NOT_FOUND;
	}

	StopConnection(connection, true);

	ReleaseConnection(connection);

	ALog(a, NULL, "LA_DISCONNECT_CONN", t->Name);

	return ERR_NO_ERROR;
}

static UINT StEnumConnection(ADMIN *a, RPC_ENUM_CONNECTION *t)
{
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;

	SERVER_ADMIN_ONLY;

	FreeRpcEnumConnection(t);
	Zero(t, sizeof(RPC_ENUM_CONNECTION));

	LockList(c->ConnectionList);
	{
		UINT i;
		t->NumConnection = LIST_NUM(c->ConnectionList);
		t->Connections = ZeroMalloc(sizeof(RPC_ENUM_CONNECTION_ITEM) * t->NumConnection);
		
		for (i = 0;i < t->NumConnection;i++)
		{
			RPC_ENUM_CONNECTION_ITEM *e = &t->Connections[i];
			CONNECTION *connection = LIST_DATA(c->ConnectionList, i);

			Lock(connection->lock);
			{
				SOCK *s = connection->FirstSock;

				if (s != NULL)
				{
					e->Ip = IPToUINT(&s->RemoteIP);
					e->Port = s->RemotePort;
					StrCpy(e->Hostname, sizeof(e->Hostname), s->RemoteHostname);
				}

				StrCpy(e->Name, sizeof(e->Name), connection->Name);
				e->ConnectedTime = Tick64ToTime64(connection->ConnectedTick);
				e->Type = connection->Type;
			}
			Unlock(connection->lock);
		}
	}
	UnlockList(c->ConnectionList);

	return ERR_NO_ERROR;
}

static UINT StDeleteHub(ADMIN *a, RPC_DELETE_HUB *t)
{
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;
	HUB *h = NULL;


	if (IsEmptyStr(t->HubName) || IsSafeStr(t->HubName) == false)
	{
		return ERR_INVALID_PARAMETER;
	}

	NO_SUPPORT_FOR_BRIDGE;

	SERVER_ADMIN_ONLY;

	LockHubList(c);
	{
		h = GetHub(c, t->HubName);
	}
	UnlockHubList(c);

	if (h == NULL)
	{
		return ERR_HUB_NOT_FOUND;
	}

	StopHub(h);

	IncrementServerConfigRevision(s);

	DelHub(c, h);
	ReleaseHub(h);

	ALog(a, NULL, "LA_DELETE_HUB", t->HubName);

	return ERR_NO_ERROR;
}

static UINT StEnumHub(ADMIN *a, RPC_ENUM_HUB *t)
{
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;
	HUB *h = NULL;

	FreeRpcEnumHub(t);

	Zero(t, sizeof(RPC_ENUM_HUB));

	LockHubList(c);
	{
		UINT i, num, j;

		num = 0;

		for (i = 0;i < LIST_NUM(c->HubList);i++)
		{
			HUB *h = LIST_DATA(c->HubList, i);

			Lock(h->lock);

			if (a->ServerAdmin == false &&
				h->Option != NULL &&
				StrCmpi(h->Name, a->HubName) != 0)
			{
			}
			else
			{
				num++;
			}
		}

		t->NumHub = num;

		t->Hubs = ZeroMalloc(sizeof(RPC_ENUM_HUB_ITEM) * num);

		i = 0;
		for (j = 0;j < LIST_NUM(c->HubList);j++)
		{
			HUB *h = LIST_DATA(c->HubList, j);

			if (a->ServerAdmin == false &&
				h->Option != NULL &&
				StrCmpi(h->Name, a->HubName) != 0)
			{
			}
			else
			{
				RPC_ENUM_HUB_ITEM *e = &t->Hubs[i++];

				StrCpy(e->HubName, sizeof(e->HubName), h->Name);
				e->Online = h->Offline ? false : true;

				e->NumSessions = LIST_NUM(h->SessionList);

				LockHashList(h->MacHashTable);
				{
					e->NumMacTables = HASH_LIST_NUM(h->MacHashTable);
				}
				UnlockHashList(h->MacHashTable);

				LockList(h->IpTable);
				{
					e->NumIpTables = LIST_NUM(h->IpTable);
				}
				UnlockList(h->IpTable);

				if (h->HubDb != NULL)
				{
					LockList(h->HubDb->UserList);
					{
						e->NumUsers = LIST_NUM(h->HubDb->UserList);
					}
					UnlockList(h->HubDb->UserList);

					LockList(h->HubDb->GroupList);
					{
						e->NumGroups = LIST_NUM(h->HubDb->GroupList);
					}
					UnlockList(h->HubDb->GroupList);
				}

				e->LastCommTime = h->LastCommTime;
				e->LastLoginTime = h->LastLoginTime;
				e->NumLogin = h->NumLogin;
				e->CreatedTime = h->CreatedTime;

				Lock(h->TrafficLock);
				{
					Copy(&e->Traffic, h->Traffic, sizeof(TRAFFIC));
				}
				Unlock(h->TrafficLock);

				e->IsTrafficFilled = true;
			}

			Unlock(h->lock);
		}
	}
	UnlockHubList(c);

	return ERR_NO_ERROR;
}

static UINT StGetHub(ADMIN *a, RPC_CREATE_HUB *t)
{
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;
	UINT ret = ERR_NO_ERROR;
	HUB *h;

	if (IsEmptyStr(t->HubName) || IsSafeStr(t->HubName) == false)
	{
		return ERR_INVALID_PARAMETER;
	}

	NO_SUPPORT_FOR_BRIDGE;
	CHECK_RIGHT;

	LockHubList(c);
	{
		h = GetHub(c, t->HubName);
	}
	UnlockHubList(c);

	Zero(t, sizeof(RPC_CREATE_HUB));

	if (h == NULL)
	{
		return ERR_HUB_NOT_FOUND;
	}

	Lock(h->lock);
	{
		StrCpy(t->HubName, sizeof(t->HubName), h->Name);
		t->Online = h->Offline ? false : true;
		t->HubOption.MaxSession = h->Option->MaxSession;
		t->HubOption.NoEnum = h->Option->NoEnum;
	}
	Unlock(h->lock);

	ReleaseHub(h);

	return ret;
}

static UINT StSetHub(ADMIN *a, RPC_CREATE_HUB *t)
{
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;
	HUB *h;
	UINT ret = ERR_NO_ERROR;

	if (IsEmptyStr(t->HubName) || IsSafeStr(t->HubName) == false)
	{
		return ERR_INVALID_PARAMETER;
	}

	CHECK_RIGHT;
	NO_SUPPORT_FOR_BRIDGE;

	LockHubList(c);
	{
		h = GetHub(c, t->HubName);
	}
	UnlockHubList(c);

	if (h == NULL)
	{
		return ERR_HUB_NOT_FOUND;
	}

	// For JSON-RPC
	if (StrLen(t->AdminPasswordPlainText) != 0)
	{
		Sha0(t->HashedPassword, t->AdminPasswordPlainText, StrLen(t->AdminPasswordPlainText));
		HashPassword(t->SecurePassword, ADMINISTRATOR_USERNAME, t->AdminPasswordPlainText);
	}

	if (IsZero(t->HashedPassword, sizeof(t->HashedPassword)) == false &&
		IsZero(t->SecurePassword, sizeof(t->SecurePassword)) == false)
	{
		if (a->ServerAdmin == false && GetHubAdminOption(h, "no_change_admin_password") != 0)
		{
			ReleaseHub(h);
			return ERR_NOT_ENOUGH_RIGHT;
		}
	}

	{
		UCHAR hash1[SHA1_SIZE], hash2[SHA1_SIZE];
		HashPassword(hash1, ADMINISTRATOR_USERNAME, "");
		Sha0(hash2, "", 0);

		if (Cmp(t->HashedPassword, hash2, SHA1_SIZE) == 0 || Cmp(t->SecurePassword, hash1, SHA1_SIZE) == 0)
		{
			if (a->ServerAdmin == false && IsLocalHostIP(&a->Rpc->Sock->RemoteIP) == false)
			{
				// Refuse a blank hub admin password set from a remote host
				ReleaseHub(h);
				return ERR_INVALID_PARAMETER;
			}
		}
	}

	Lock(h->lock);
	{
		h->Option->MaxSession = t->HubOption.MaxSession;
		h->Option->NoEnum = t->HubOption.NoEnum;

		if (IsZero(t->HashedPassword, sizeof(t->HashedPassword)) == false &&
			IsZero(t->SecurePassword, sizeof(t->SecurePassword)) == false)
		{
			Copy(h->HashedPassword, t->HashedPassword, SHA1_SIZE);
			Copy(h->SecurePassword, t->SecurePassword, SHA1_SIZE);
		}
	}
	Unlock(h->lock);

	if (t->Online)
	{
		if (a->ServerAdmin || GetHubAdminOption(h, "no_online") == 0)
		{
			SetHubOnline(h);
		}
	}
	else
	{
		if (a->ServerAdmin || GetHubAdminOption(h, "no_offline") == 0)
		{
			SetHubOffline(h);
		}
	}

	IncrementServerConfigRevision(s);

	ALog(a, h, "LA_SET_HUB");

	ReleaseHub(h);

	return ret;
}

static UINT StCreateHub(ADMIN *a, RPC_CREATE_HUB *t)
{
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;
	HUB *h;
	HUB_OPTION o;
	UINT current_hub_num;
	bool b;

	if (IsEmptyStr(t->HubName) || IsSafeStr(t->HubName) == false)
	{
		return ERR_INVALID_PARAMETER;
	}

	NO_SUPPORT_FOR_BRIDGE;

	SERVER_ADMIN_ONLY;

	Trim(t->HubName);
	if (StrLen(t->HubName) == 0)
	{
		return ERR_INVALID_PARAMETER;
	}
	if (StartWith(t->HubName, ".") || EndWith(t->HubName, "."))
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&o, sizeof(o));
	o.MaxSession = t->HubOption.MaxSession;
	o.NoEnum = t->HubOption.NoEnum;

	SiSetDefaultHubOption(&o);

	LockList(c->HubList);
	{
		current_hub_num = LIST_NUM(c->HubList);
	}
	UnlockList(c->HubList);

	if (current_hub_num > GetServerCapsInt(a->Server, "i_max_hubs"))
	{
		return ERR_TOO_MANY_HUBS;
	}

	LockList(c->HubList);
	{
		b = IsHub(c, t->HubName);
	}
	UnlockList(c->HubList);

	if (b)
	{
		return ERR_HUB_ALREADY_EXISTS;
	}

	ALog(a, NULL, "LA_CREATE_HUB", t->HubName);

	// For JSON-RPC
	if ((IsZero(t->HashedPassword, sizeof(t->HashedPassword)) &&
		IsZero(t->SecurePassword, sizeof(t->SecurePassword))) ||
		StrLen(t->AdminPasswordPlainText) != 0)
	{
		Sha0(t->HashedPassword, t->AdminPasswordPlainText, StrLen(t->AdminPasswordPlainText));
		HashPassword(t->SecurePassword, ADMINISTRATOR_USERNAME, t->AdminPasswordPlainText);
	}

	h = NewHub(c, t->HubName, &o);
	Copy(h->HashedPassword, t->HashedPassword, SHA1_SIZE);
	Copy(h->SecurePassword, t->SecurePassword, SHA1_SIZE);

	AddHub(c, h);

	if (t->Online)
	{
		h->Offline = true;
		SetHubOnline(h);
	}
	else
	{
		h->Offline = false;
		SetHubOffline(h);
	}

	h->CreatedTime = SystemTime64();

	ReleaseHub(h);

	IncrementServerConfigRevision(s);

	return ERR_NO_ERROR;
}

static UINT StSetServerCipher(ADMIN *a, RPC_STR *t)
{
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;

	if (IsEmptyStr(t->String))
	{
		return ERR_INVALID_PARAMETER;
	}

	SERVER_ADMIN_ONLY;

	StrUpper(t->String);

	ALog(a, NULL, "LA_SET_SERVER_CIPHER", t->String);

	Lock(c->lock);
	{
		SetCedarCipherList(c, t->String);
	}
	Unlock(c->lock);

	IncrementServerConfigRevision(s);

	return ERR_NO_ERROR;
}

static UINT StGetServerCipher(ADMIN *a, RPC_STR *t)
{
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;

	FreeRpcStr(t);
	Zero(t, sizeof(RPC_STR));

	Lock(c->lock);
	{
		t->String = CopyStr(c->CipherList);
	}
	Unlock(c->lock);

	return ERR_NO_ERROR;
}

static UINT StGetServerCipherList(ADMIN *a, RPC_STR *t)
{
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;

	FreeRpcStr(t);
	Zero(t, sizeof(RPC_STR));

	Lock(c->lock);
	{
		UINT i;
		TOKEN_LIST *ciphers = GetCipherList();
		if (ciphers->NumTokens > 0)
		{
			UINT size = StrSize(ciphers->Token[0]);
			t->String = Malloc(size);
			StrCpy(t->String, size, ciphers->Token[0]);
			i = 1;

			for (; i < ciphers->NumTokens; i++)
			{
				// We use StrSize() because we need the extra space for ';'
				size += StrSize(ciphers->Token[i]);
				t->String = ReAlloc(t->String, size);
				StrCat(t->String, size, ";");
				StrCat(t->String, size, ciphers->Token[i]);
			}
		}

		FreeToken(ciphers);
	}
	Unlock(c->lock);

	return ERR_NO_ERROR;
}

static UINT StGetServerCert(ADMIN *a, RPC_KEY_PAIR *t)
{
	bool admin;
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;

	admin = a->ServerAdmin;

	FreeRpcKeyPair(t);
	Zero(t, sizeof(RPC_KEY_PAIR));

	Lock(c->lock);
	{

		t->Cert = CloneX(c->ServerX);
		if (admin)
		{
			t->Key = CloneK(c->ServerK);
		}
	}
	Unlock(c->lock);

	return ERR_NO_ERROR;
}

static UINT StSetServerCert(ADMIN *a, RPC_KEY_PAIR *t)
{
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;

	SERVER_ADMIN_ONLY;

	if (t->Cert == NULL || t->Key == NULL)
	{
		return ERR_PROTOCOL_ERROR;
	}

	if (CheckXandK(t->Cert, t->Key) == false)
	{
		return ERR_PROTOCOL_ERROR;
	}

	t->Flag1 = 1;
	if (t->Cert->root_cert == false)
	{
		if (DownloadAndSaveIntermediateCertificatesIfNecessary(t->Cert) == false)
		{
			t->Flag1 = 0;
		}
	}

	SetCedarCertAndChain(c, t->Cert, t->Key, t->Chain);

	ALog(a, NULL, "LA_SET_SERVER_CERT");

	IncrementServerConfigRevision(s);

	return ERR_NO_ERROR;
}

static UINT StSetServerPassword(ADMIN *a, RPC_SET_PASSWORD *t)
{
	SERVER_ADMIN_ONLY;

	if (IsZero(t->HashedPassword, sizeof(t->HashedPassword)))
	{
		// For JSON-RPC
		HashAdminPassword(t->HashedPassword, t->PlainTextPassword);
	}

	Copy(a->Server->HashedPassword, t->HashedPassword, SHA1_SIZE);

	ALog(a, NULL, "LA_SET_SERVER_PASSWORD");

	IncrementServerConfigRevision(a->Server);

	return ERR_NO_ERROR;
}

static UINT StEnableListener(ADMIN *a, RPC_LISTENER *t)
{
	UINT ret = ERR_NO_ERROR;

	SERVER_ADMIN_ONLY;


	LockList(a->Server->ServerListenerList);
	{
		if (t->Enable)
		{
			if (SiEnableListener(a->Server, t->Port) == false)
			{
				ret = ERR_LISTENER_NOT_FOUND;
			}
			else
			{
				ALog(a, NULL, "LA_ENABLE_LISTENER", t->Port);
			}
		}
		else
		{
			if (SiDisableListener(a->Server, t->Port) == false)
			{
				ret = ERR_LISTENER_NOT_FOUND;
			}
			else
			{
				ALog(a, NULL, "LA_DISABLE_LISTENER", t->Port);
			}
		}
	}
	UnlockList(a->Server->ServerListenerList);

	IncrementServerConfigRevision(a->Server);

	SleepThread(250);

	return ret;
}

static UINT StDeleteListener(ADMIN *a, RPC_LISTENER *t)
{
	UINT ret = ERR_NO_ERROR;

	SERVER_ADMIN_ONLY;


	LockList(a->Server->ServerListenerList);
	{
		if (SiDeleteListener(a->Server, t->Port) == false)
		{
			ret = ERR_LISTENER_NOT_FOUND;
		}
		else
		{
			ALog(a, NULL, "LA_DELETE_LISTENER", t->Port);

			IncrementServerConfigRevision(a->Server);
		}
	}
	UnlockList(a->Server->ServerListenerList);

	return ret;
}

static UINT StEnumListener(ADMIN *a, RPC_LISTENER_LIST *t)
{
	CEDAR *c = a->Server->Cedar;
	UINT i;

	FreeRpcListenerList(t);
	Zero(t, sizeof(RPC_LISTENER_LIST));

	LockList(a->Server->ServerListenerList);
	{
		t->NumPort = LIST_NUM(a->Server->ServerListenerList);
		t->Ports = ZeroMalloc(sizeof(UINT) * t->NumPort);
		t->Enables = ZeroMalloc(sizeof(bool) * t->NumPort);
		t->Errors = ZeroMalloc(sizeof(bool) * t->NumPort);

		for (i = 0;i < t->NumPort;i++)
		{
			SERVER_LISTENER *o = LIST_DATA(a->Server->ServerListenerList, i);

			t->Ports[i] = o->Port;
			t->Enables[i] = o->Enabled;
			if (t->Enables[i])
			{
				if (o->Listener->Status == LISTENER_STATUS_TRYING)
				{
					t->Errors[i] = true;
				}
			}
		}
	}
	UnlockList(a->Server->ServerListenerList);

	return ERR_NO_ERROR;
}

static UINT StCreateListener(ADMIN *a, RPC_LISTENER *t)
{
	UINT ret = ERR_NO_ERROR;
	CEDAR *c = a->Server->Cedar;

	if (t->Port == 0 || t->Port > 65535)
	{
		return ERR_INVALID_PARAMETER;
	}

	SERVER_ADMIN_ONLY;

	LockList(a->Server->ServerListenerList);
	{
		if (SiAddListenerEx(a->Server, t->Port, t->Enable, false) == false)
		{
			ret = ERR_LISTENER_ALREADY_EXISTS;
		}
		else
		{
			ALog(a, NULL, "LA_CREATE_LISTENER", t->Port);

			IncrementServerConfigRevision(a->Server);
		}
	}
	UnlockList(a->Server->ServerListenerList);

	SleepThread(250);

	return ret;
}

static UINT StGetServerStatus(ADMIN *a, RPC_SERVER_STATUS *t)
{
	CEDAR *c;
	UINT i;

	c = a->Server->Cedar;

	Zero(t, sizeof(RPC_SERVER_STATUS));

	Lock(c->TrafficLock);
	{
		Copy(&t->Traffic, c->Traffic, sizeof(TRAFFIC));
	}
	Unlock(c->TrafficLock);

	GetMemInfo(&t->MemInfo);

	t->NumTcpConnections = t->NumTcpConnectionsLocal = 0;
	t->NumSessionsTotal = t->NumSessionsLocal = 0;

	t->NumTcpConnectionsLocal = Count(c->CurrentTcpConnections);

	t->NumMacTables = t->NumIpTables = t->NumUsers = t->NumGroups = 0;

	LockList(c->HubList);
	{
		t->NumHubTotal = LIST_NUM(c->HubList);

		t->NumHubStandalone = 0;

		for (i = 0;i < LIST_NUM(c->HubList);i++)
		{
			HUB *h = LIST_DATA(c->HubList, i);
			Lock(h->lock);
			{
				t->NumHubStandalone++;
			}

			t->NumMacTables += HASH_LIST_NUM(h->MacHashTable);
			t->NumIpTables += LIST_NUM(h->IpTable);

			if (h->HubDb != NULL)
			{
				t->NumUsers += LIST_NUM(h->HubDb->UserList);
				t->NumGroups += LIST_NUM(h->HubDb->GroupList);
			}

			Unlock(h->lock);
		}
	}
	UnlockList(c->HubList);

	t->NumSessionsLocal = Count(c->CurrentSessions);
	t->NumSessionsTotal = t->NumSessionsLocal;
	t->NumTcpConnections = t->NumTcpConnectionsLocal;

	t->AssignedBridgeLicenses = Count(c->AssignedBridgeLicense);
	t->AssignedClientLicenses = Count(c->AssignedClientLicense);

	t->AssignedBridgeLicensesTotal = a->Server->CurrentAssignedBridgeLicense;
	t->AssignedClientLicensesTotal = a->Server->CurrentAssignedClientLicense;

	t->CurrentTick = Tick64();
	t->CurrentTime = SystemTime64();

	t->StartTime = a->Server->StartTime;

	return ERR_NO_ERROR;
}

static UINT StGetServerInfo(ADMIN *a, RPC_SERVER_INFO *t)
{
	CEDAR *c;
	OS_INFO *info;
	SYSTEMTIME st;
	if (a == NULL || t == NULL)
	{
		return ERR_INTERNAL_ERROR;
	}

	FreeRpcServerInfo(t);
	Zero(t, sizeof(RPC_SERVER_INFO));

	c = a->Server->Cedar;

	GetServerProductName(a->Server, t->ServerProductName, sizeof(t->ServerProductName));

	StrCpy(t->ServerVersionString, sizeof(t->ServerVersionString), c->VerString);
	StrCpy(t->ServerBuildInfoString, sizeof(t->ServerBuildInfoString), c->BuildInfo);
	t->ServerVerInt = c->Version;
	t->ServerBuildInt = c->Build;
	GetMachineName(t->ServerHostName, sizeof(t->ServerHostName));

	Zero(&st, sizeof(st));
	st.wYear = BUILD_DATE_Y;
	st.wMonth = BUILD_DATE_M;
	st.wDay = BUILD_DATE_D;
	st.wHour = BUILD_DATE_HO;
	st.wMinute = BUILD_DATE_MI;
	st.wSecond = BUILD_DATE_SE;

	t->ServerBuildDate = SystemToUINT64(&st);

	info = GetOsInfo();
	if (info != NULL)
	{
		CopyOsInfo(&t->OsInfo, info);
	}

	return ERR_NO_ERROR;
}

static void CopyOsInfo(OS_INFO *dst, OS_INFO *info)
{
	if (info == NULL || dst == NULL)
	{
		return;
	}

	dst->OsType = info->OsType;
	dst->OsServicePack = info->OsServicePack;
	dst->OsSystemName = CopyStr(info->OsSystemName);
	dst->OsProductName = CopyStr(info->OsProductName);
	dst->OsVendorName = CopyStr(info->OsVendorName);
	dst->OsVersion = CopyStr(info->OsVersion);
	dst->KernelName = CopyStr(info->KernelName);
	dst->KernelVersion = CopyStr(info->KernelVersion);
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

static void InRpcMsg(RPC_MSG *t, PACK *p)
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
static void OutRpcMsg(PACK *p, RPC_MSG *t)
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
static void FreeRpcMsg(RPC_MSG *t)
{
	if (t == NULL)
	{
		return;
	}

	Free(t->Msg);
}

static void InRpcEnumEthVLan(RPC_ENUM_ETH_VLAN *t, PACK *p)
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
static void OutRpcEnumEthVLan(PACK *p, RPC_ENUM_ETH_VLAN *t)
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

static void InRpcEnumLogFile(RPC_ENUM_LOG_FILE *t, PACK *p)
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
static void OutRpcEnumLogFile(PACK *p, RPC_ENUM_LOG_FILE *t)
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
static void InRpcReadLogFile(RPC_READ_LOG_FILE *t, PACK *p)
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
static void OutRpcReadLogFile(PACK *p, RPC_READ_LOG_FILE *t)
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
static void FreeRpcReadLogFile(RPC_READ_LOG_FILE *t)
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

static void InRpcAcList(RPC_AC_LIST *t, PACK *p)
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
static void OutRpcAcList(PACK *p, RPC_AC_LIST *t)
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

static void InRpcEnumCrl(RPC_ENUM_CRL *t, PACK *p)
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
static void OutRpcEnumCrl(PACK *p, RPC_ENUM_CRL *t)
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

static void InRpcCrl(RPC_CRL *t, PACK *p)
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
static void OutRpcCrl(PACK *p, RPC_CRL *t)
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

static void InRpcEnumEth(RPC_ENUM_ETH *t, PACK *p)
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
static void OutRpcEnumEth(PACK *p, RPC_ENUM_ETH *t)
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

static void InRpcLocalBridge(RPC_LOCALBRIDGE *t, PACK *p)
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
static void OutRpcLocalBridge(PACK *p, RPC_LOCALBRIDGE *t)
{
	if (t == NULL || p == NULL)
	{
		return;
	}

	PackAddStr(p, "DeviceName", t->DeviceName);
	PackAddStr(p, "HubNameLB", t->HubName);
	PackAddBool(p, "TapMode", t->TapMode);
}

static void InRpcEnumLocalBridge(RPC_ENUM_LOCALBRIDGE *t, PACK *p)
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
static void OutRpcEnumLocalBridge(PACK *p, RPC_ENUM_LOCALBRIDGE *t)
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

static void InRpcMemInfo(MEMINFO *t, PACK *p)
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
static void OutRpcMemInfo(PACK *p, MEMINFO *t)
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

static void SiReadLocalLogFile(SERVER *s, char *filepath, UINT offset, RPC_READ_LOG_FILE *t)
{
	char exe_dir[MAX_PATH], full_path[MAX_PATH];
	IO *o;
	if (s == NULL || t == NULL || filepath == NULL)
	{
		return;
	}

	Zero(t, sizeof(RPC_READ_LOG_FILE));

	GetExeDir(exe_dir, sizeof(exe_dir));
	Format(full_path, sizeof(full_path), "%s/%s", exe_dir, filepath);

	o = FileOpenEx(full_path, false, false);
	if (o != NULL)
	{
		UINT filesize = FileSize(o);

		if (offset < filesize)
		{
			UINT readsize = MIN(filesize - offset, FTP_BLOCK_SIZE);
			void *buf = ZeroMalloc(readsize);

			FileSeek(o, FILE_BEGIN, offset);
			FileRead(o, buf, readsize);

			t->Buffer = NewBuf();
			WriteBuf(t->Buffer, buf, readsize);
			Free(buf);
		}

		FileClose(o);
	}
}

static void SiEnumLocalLogFileList(SERVER *s, char *hubname, RPC_ENUM_LOG_FILE *t)
{
	LIST *o;
	UINT i;
	if (s == NULL || t == NULL)
	{
		return;
	}

	Zero(t, sizeof(RPC_ENUM_LOG_FILE));

	o = EnumLogFile(hubname);

	t->NumItem = LIST_NUM(o);
	t->Items = ZeroMalloc(sizeof(RPC_ENUM_LOG_FILE_ITEM) * t->NumItem);

	for (i = 0;i < LIST_NUM(o);i++)
	{
		LOG_FILE *f = LIST_DATA(o, i);
		RPC_ENUM_LOG_FILE_ITEM *e = &t->Items[i];

		StrCpy(e->FilePath, sizeof(e->FilePath), f->Path);
		e->FileSize = f->FileSize;
		e->UpdatedTime = f->UpdatedTime;
	}

	FreeEnumLogFile(o);
}

static void SiEnumLocalSession(SERVER *s, char *hubname, RPC_ENUM_SESSION *t)
{
	HUB *h;
	UINT64 now = Tick64();
	UINT64 dormant_interval = 0;
	if (s == NULL || hubname == NULL || t == NULL)
	{
		return;
	}

	LockHubList(s->Cedar);
	h = GetHub(s->Cedar, hubname);
	UnlockHubList(s->Cedar);

	if (h == NULL)
	{
		t->NumSession = 0;
		t->Sessions = ZeroMalloc(0);
		return;
	}

	if (h->Option != NULL)
	{
		dormant_interval = h->Option->DetectDormantSessionInterval * (UINT64)1000;
	}

	LockList(h->SessionList);
	{
		UINT i;
		t->NumSession = LIST_NUM(h->SessionList);
		t->Sessions = ZeroMalloc(sizeof(RPC_ENUM_SESSION_ITEM) * t->NumSession);

		for (i = 0;i < t->NumSession;i++)
		{
			SESSION *s = LIST_DATA(h->SessionList, i);
			RPC_ENUM_SESSION_ITEM *e = &t->Sessions[i];
			Lock(s->lock);
			{
				StrCpy(e->Name, sizeof(e->Name), s->Name);
				StrCpy(e->Username, sizeof(e->Username), s->Username);
				e->Ip = IPToUINT(&s->Connection->ClientIp);
				CopyIP(&e->ClientIP, &s->Connection->ClientIp);
				StrCpy(e->Hostname, sizeof(e->Hostname), s->Connection->ClientHostname);
				e->MaxNumTcp = s->MaxConnection;
				e->CreatedTime = Tick64ToTime64(s->CreatedTime);
				e->LastCommTime = Tick64ToTime64(s->LastCommTime);
				e->LinkMode = s->LinkModeServer;
				e->BridgeMode = s->BridgeMode;
				e->VLanId = s->VLanId;
				LockList(s->Connection->Tcp->TcpSockList);
				{
					e->CurrentNumTcp = s->Connection->Tcp->TcpSockList->num_item;
				}
				UnlockList(s->Connection->Tcp->TcpSockList);
				Lock(s->TrafficLock);
				{
					e->PacketSize = GetTrafficPacketSize(s->Traffic);
					e->PacketNum = GetTrafficPacketNum(s->Traffic);
				}
				Unlock(s->TrafficLock);
				e->Client_BridgeMode = s->IsBridgeMode;
				e->Client_MonitorMode = s->IsMonitorMode;
				Copy(e->UniqueId, s->NodeInfo.UniqueId, 16);

				if (s->NormalClient)
				{
					e->IsDormantEnabled = (dormant_interval == 0 ? false : true);
					if (e->IsDormantEnabled)
					{
						if (s->LastCommTimeForDormant == 0)
						{
							e->LastCommDormant = (UINT64)0x7FFFFFFF;
						}
						else
						{
							e->LastCommDormant = now - s->LastCommTimeForDormant;
						}
						if (s->LastCommTimeForDormant == 0)
						{
							e->IsDormant = true;
						}
						else
						{
							if ((s->LastCommTimeForDormant + dormant_interval) < now)
							{
								e->IsDormant = true;
							}
						}
					}
				}
			}
			Unlock(s->lock);
		}
	}
	UnlockList(h->SessionList);

	ReleaseHub(h);
}

static void InRpcEnumLicenseKey(RPC_ENUM_LICENSE_KEY *t, PACK *p)
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
static void OutRpcEnumLicenseKey(PACK *p, RPC_ENUM_LICENSE_KEY *t)
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

static void InRpcLicenseStatus(RPC_LICENSE_STATUS *t, PACK *p)
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
static void OutRpcLicenseStatus(PACK *p, RPC_LICENSE_STATUS *t)
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

static void InRpcAdminOption(RPC_ADMIN_OPTION *t, PACK *p)
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
static void OutRpcAdminOption(PACK *p, RPC_ADMIN_OPTION *t)
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

static void InRpcConfig(RPC_CONFIG *t, PACK *p)
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
static void OutRpcConfig(PACK *p, RPC_CONFIG *t)
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

static void InRpcBridgeSupport(RPC_BRIDGE_SUPPORT *t, PACK *p)
{
	if (t == NULL || p == NULL)
	{
		return;
	}

	Zero(t, sizeof(RPC_BRIDGE_SUPPORT));

	t->IsBridgeSupportedOs = PackGetBool(p, "IsBridgeSupportedOs");
}
static void OutRpcBridgeSupport(PACK *p, RPC_BRIDGE_SUPPORT *t)
{
	if (p == NULL || t == NULL)
	{
		return;
	}

	PackAddBool(p, "IsBridgeSupportedOs", t->IsBridgeSupportedOs);
}

static void InRpcAddAccess(RPC_ADD_ACCESS *t, PACK *p)
{
	if (t == NULL || p == NULL)
	{
		return;
	}

	Zero(t, sizeof(RPC_ADD_ACCESS));

	PackGetStr(p, "HubName", t->HubName, sizeof(t->HubName));
	InRpcAccess(&t->Access, p);
}
static void OutRpcAddAccess(PACK *p, RPC_ADD_ACCESS *t)
{
	if (t == NULL || p == NULL)
	{
		return;
	}

	PackAddStr(p, "HubName", t->HubName);
	OutRpcAccess(p, &t->Access);
}

static void InRpcDeleteAccess(RPC_DELETE_ACCESS *t, PACK *p)
{
	if (t == NULL || p == NULL)
	{
		return;
	}

	Zero(t, sizeof(RPC_DELETE_ACCESS));

	PackGetStr(p, "HubName", t->HubName, sizeof(t->HubName));
	t->Id = PackGetInt(p, "Id");
}
static void OutRpcDeleteAccess(PACK *p, RPC_DELETE_ACCESS *t)
{
	if (t == NULL || p == NULL)
	{
		return;
	}

	PackAddStr(p, "HubName", t->HubName);
	PackAddInt(p, "Id", t->Id);
}


static void InRpcServerInfo(RPC_SERVER_INFO *t, PACK *p)
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
static void OutRpcServerInfo(PACK *p, RPC_SERVER_INFO *t)
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

static void InRpcServerStatus(RPC_SERVER_STATUS *t, PACK *p)
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
static void OutRpcServerStatus(PACK *p, RPC_SERVER_STATUS *t)
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

static void InRpcListener(RPC_LISTENER *t, PACK *p)
{
	if (t == NULL || p == NULL)
	{
		return;
	}

	Zero(t, sizeof(RPC_LISTENER));
	t->Port = PackGetInt(p, "Port");
	t->Enable = PackGetBool(p, "Enable");
}
static void OutRpcListener(PACK *p, RPC_LISTENER *t)
{
	if (t == NULL || p == NULL)
	{
		return;
	}

	PackAddInt(p, "Port", t->Port);
	PackAddBool(p, "Enable", t->Enable);
}

static void InRpcListenerList(RPC_LISTENER_LIST *t, PACK *p)
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
static void OutRpcListenerList(PACK *p, RPC_LISTENER_LIST *t)
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

static void InRpcStr(RPC_STR *t, PACK *p)
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
static void OutRpcStr(PACK *p, RPC_STR *t)
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

static void InRpcSetPassword(RPC_SET_PASSWORD *t, PACK *p)
{
	if (t == NULL || p == NULL)
	{
		return;
	}

	Zero(t, sizeof(RPC_SET_PASSWORD));
	PackGetData2(p, "HashedPassword", t->HashedPassword, sizeof(t->HashedPassword));
	PackGetStr(p, "PlainTextPassword", t->PlainTextPassword, sizeof(t->PlainTextPassword));
}
static void OutRpcSetPassword(PACK *p, RPC_SET_PASSWORD *t)
{
	if (t == NULL || p == NULL)
	{
		return;
	}

	PackAddData(p, "HashedPassword", t->HashedPassword, sizeof(t->HashedPassword));
	PackAddStr(p, "PlainTextPassword", t->PlainTextPassword);
}

static void InRpcHubOption(RPC_HUB_OPTION *t, PACK *p)
{
	if (t == NULL || p == NULL)
	{
		return;
	}

	Zero(t, sizeof(RPC_HUB_OPTION));
	t->MaxSession = PackGetInt(p, "MaxSession");
	t->NoEnum = PackGetBool(p, "NoEnum");
}
static void OutRpcHubOption(PACK *p, RPC_HUB_OPTION *t)
{
	if (t == NULL || p == NULL)
	{
		return;
	}

	PackAddInt(p, "MaxSession", t->MaxSession);
	PackAddBool(p, "NoEnum", t->NoEnum);
}

static void InRpcCreateHub(RPC_CREATE_HUB *t, PACK *p)
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
static void OutRpcCreateHub(PACK *p, RPC_CREATE_HUB *t)
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

static void InRpcEnumHub(RPC_ENUM_HUB *t, PACK *p)
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
static void OutRpcEnumHub(PACK *p, RPC_ENUM_HUB *t)
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

static void InRpcDeleteHub(RPC_DELETE_HUB *t, PACK *p)
{
	if (t == NULL || p == NULL)
	{
		return;
	}

	Zero(t, sizeof(RPC_DELETE_HUB));
	PackGetStr(p, "HubName", t->HubName, sizeof(t->HubName));
}
static void OutRpcDeleteHub(PACK *p, RPC_DELETE_HUB *t)
{
	if (t == NULL || p == NULL)
	{
		return;
	}

	PackAddStr(p, "HubName", t->HubName);
}

static void InRpcEnumConnection(RPC_ENUM_CONNECTION *t, PACK *p)
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
static void OutRpcEnumConnection(PACK *p, RPC_ENUM_CONNECTION *t)
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

static void InRpcDisconnectConnection(RPC_DISCONNECT_CONNECTION *t, PACK *p)
{
	if (t == NULL || p == NULL)
	{
		return;
	}

	Zero(t, sizeof(RPC_DISCONNECT_CONNECTION));
	PackGetStr(p, "Name", t->Name, sizeof(t->Name));
}
static void OutRpcDisconnectConnection(PACK *p, RPC_DISCONNECT_CONNECTION *t)
{
	if (t == NULL || p == NULL)
	{
		return;
	}

	PackAddStr(p, "Name", t->Name);
}

static void InRpcConnectionInfo(RPC_CONNECTION_INFO *t, PACK *p)
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
static void OutRpcConnectionInfo(PACK *p, RPC_CONNECTION_INFO *t)
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

static void InRpcSetHubOnline(RPC_SET_HUB_ONLINE *t, PACK *p)
{
	if (t == NULL || p == NULL)
	{
		return;
	}

	Zero(t, sizeof(RPC_SET_HUB_ONLINE));
	PackGetStr(p, "HubName", t->HubName, sizeof(t->HubName));
	t->Online = PackGetBool(p, "Online");
}
static void OutRpcSetHubOnline(PACK *p, RPC_SET_HUB_ONLINE *t)
{
	if (t == NULL || p == NULL)
	{
		return;
	}

	PackAddStr(p, "HubName", t->HubName);
	PackAddBool(p, "Online", t->Online);
}

static void InRpcHubStatus(RPC_HUB_STATUS *t, PACK *p)
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
static void OutRpcHubStatus(PACK *p, RPC_HUB_STATUS *t)
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

static void InRpcHubLog(RPC_HUB_LOG *t, PACK *p)
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
static void OutRpcHubLog(PACK *p, RPC_HUB_LOG *t)
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

static void InRpcHubAddCa(RPC_HUB_ADD_CA *t, PACK *p)
{
	if (t == NULL || p == NULL)
	{
		return;
	}

	Zero(t, sizeof(RPC_HUB_ADD_CA));
	PackGetStr(p, "HubName", t->HubName, sizeof(t->HubName));
	t->Cert = PackGetX(p, "Cert");
}
static void OutRpcHubAddCa(PACK *p, RPC_HUB_ADD_CA *t)
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

static void InRpcHubEnumCa(RPC_HUB_ENUM_CA *t, PACK *p)
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
static void OutRpcHubEnumCa(PACK *p, RPC_HUB_ENUM_CA *t)
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

static void InRpcHubGetCa(RPC_HUB_GET_CA *t, PACK *p)
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
static void OutRpcHubGetCa(PACK *p, RPC_HUB_GET_CA *t)
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

static void InRpcHubDeleteCa(RPC_HUB_DELETE_CA *t, PACK *p)
{
	if (t == NULL || p == NULL)
	{
		return;
	}

	Zero(t, sizeof(RPC_HUB_DELETE_CA));
	PackGetStr(p, "HubName", t->HubName, sizeof(t->HubName));
	t->Key = PackGetInt(p, "Key");
}
static void OutRpcHubDeleteCa(PACK *p, RPC_HUB_DELETE_CA *t)
{
	if (t == NULL || p == NULL)
	{
		return;
	}

	PackAddStr(p, "HubName", t->HubName);
	PackAddInt(p, "Key", t->Key);
}

static void InRpcCreateLink(RPC_CREATE_LINK *t, PACK *p)
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
static void OutRpcCreateLink(PACK *p, RPC_CREATE_LINK *t)
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

static void InRpcEnumLink(RPC_ENUM_LINK *t, PACK *p)
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
static void OutRpcEnumLink(PACK *p, RPC_ENUM_LINK *t)
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

static void InRpcLinkStatus(RPC_LINK_STATUS *t, PACK *p)
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
static void OutRpcLinkStatus(PACK *p, RPC_LINK_STATUS *t)
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

static void InRpcLink(RPC_LINK *t, PACK *p)
{
	if (t == NULL || p == NULL)
	{
		return;
	}

	Zero(t, sizeof(RPC_LINK));
	PackGetStr(p, "HubName", t->HubName, sizeof(t->HubName));
	PackGetUniStr(p, "AccountName", t->AccountName, sizeof(t->AccountName));
}
static void OutRpcLink(PACK *p, RPC_LINK *t)
{
	if (t == NULL)
	{
		return;
	}

	PackAddStr(p, "HubName", t->HubName);
	PackAddUniStr(p, "AccountName", t->AccountName);
}

static void InRpcRenameLink(RPC_RENAME_LINK *t, PACK *p)
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
static void OutRpcRenameLink(PACK *p, RPC_RENAME_LINK *t)
{
	if (p == NULL || t == NULL)
	{
		return;
	}

	PackAddStr(p, "HubName", t->HubName);
	PackAddUniStr(p, "OldAccountName", t->OldAccountName);
	PackAddUniStr(p, "NewAccountName", t->NewAccountName);
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

static void InRpcEnumAccessList(RPC_ENUM_ACCESS_LIST *a, PACK *p)
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
static void OutRpcEnumAccessList(PACK *p, RPC_ENUM_ACCESS_LIST *a)
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

static void InRpcSetUser(RPC_SET_USER *t, PACK *p)
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

static void OutRpcSetUser(PACK *p, RPC_SET_USER *t)
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

static void InRpcEnumUser(RPC_ENUM_USER *t, PACK *p)
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
static void OutRpcEnumUser(PACK *p, RPC_ENUM_USER *t)
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

static void InRpcSetGroup(RPC_SET_GROUP *t, PACK *p)
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
static void OutRpcSetGroup(PACK *p, RPC_SET_GROUP *t)
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

static void InRpcEnumGroup(RPC_ENUM_GROUP *t, PACK *p)
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
static void OutRpcEnumGroup(PACK *p, RPC_ENUM_GROUP *t)
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

static void InRpcDeleteUser(RPC_DELETE_USER *t, PACK *p)
{
	if (t == NULL || p == NULL)
	{
		return;
	}

	Zero(t, sizeof(RPC_DELETE_USER));
	PackGetStr(p, "HubName", t->HubName, sizeof(t->HubName));
	PackGetStr(p, "Name", t->Name, sizeof(t->Name));
}
static void OutRpcDeleteUser(PACK *p, RPC_DELETE_USER *t)
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

static void InRpcKeyPair(RPC_KEY_PAIR *t, PACK *p)
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
static void OutRpcKeyPair(PACK *p, RPC_KEY_PAIR *t)
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

static void InRpcSessionStatus(RPC_SESSION_STATUS *t, PACK *p)
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
static void OutRpcSessionStatus(PACK *p, RPC_SESSION_STATUS *t)
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

static void InRpcDeleteSession(RPC_DELETE_SESSION *t, PACK *p)
{
	if (t == NULL || p == NULL)
	{
		return;
	}

	Zero(t, sizeof(RPC_DELETE_SESSION));
	PackGetStr(p, "HubName", t->HubName, sizeof(t->HubName));
	PackGetStr(p, "Name", t->Name, sizeof(t->Name));
}
static void OutRpcDeleteSession(PACK *p, RPC_DELETE_SESSION *t)
{
	if (t == NULL || p == NULL)
	{
		return;
	}

	PackAddStr(p, "HubName", t->HubName);
	PackAddStr(p, "Name", t->Name);
}

static void InRpcEnumMacTable(RPC_ENUM_MAC_TABLE *t, PACK *p)
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
static void OutRpcEnumMacTable(PACK *p, RPC_ENUM_MAC_TABLE *t)
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

static void InRpcEnumIpTable(RPC_ENUM_IP_TABLE *t, PACK *p)
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
static void OutRpcEnumIpTable(PACK *p, RPC_ENUM_IP_TABLE *t)
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

static void InRpcDeleteTable(RPC_DELETE_TABLE *t, PACK *p)
{
	if (t == NULL || p == NULL)
	{
		return;
	}

	Zero(t, sizeof(RPC_DELETE_TABLE));
	PackGetStr(p, "HubName", t->HubName, sizeof(t->HubName));
	t->Key = PackGetInt(p, "Key");
}
static void OutRpcDeleteTable(PACK *p, RPC_DELETE_TABLE *t)
{
	if (t == NULL || p == NULL)
	{
		return;
	}

	PackAddStr(p, "HubName", t->HubName);
	PackAddInt(p, "Key", t->Key);
}

static UINT StTest(ADMIN *a, RPC_TEST *t)
{
	Format(t->StrValue, sizeof(t->StrValue), "%u", t->IntValue);

	return ERR_NO_ERROR;
}

static void InRpcTest(RPC_TEST *t, PACK *p)
{
	Zero(t, sizeof(RPC_TEST));
	t->IntValue = PackGetInt(p, "IntValue");
	t->Int64Value = PackGetInt64(p, "Int64Value");
	PackGetStr(p, "StrValue", t->StrValue, sizeof(t->StrValue));
	PackGetUniStr(p, "UniStrValue", t->UniStrValue, sizeof(t->UniStrValue));
}
static void OutRpcTest(PACK *p, RPC_TEST *t)
{
	PackAddInt(p, "IntValue", t->IntValue);
	PackAddInt64(p, "Int64Value", t->Int64Value);
	PackAddStr(p, "StrValue", t->StrValue);
	PackAddUniStr(p, "UniStrValue", t->UniStrValue);
}
void FreeRpcTest(RPC_TEST *t)
{
}

static PACK *AdminCall(RPC *rpc, char *function_name, PACK *p)
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

static bool CheckAdminSourceAddress(SOCK *sock, char *hubname)
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

static void HashAdminPassword(void *hash, char *password)
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

static SESSION *AdminConnectMain(CEDAR *cedar, CLIENT_OPTION *o, char *hubname, void *hashed_password, UINT *err, char *client_name, void *hWnd, bool *empty_password)
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
static RPC *AdminConnectEx2(CEDAR *cedar, CLIENT_OPTION *o, char *hubname, void *hashed_password, UINT *err, char *client_name, void *hWnd)
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

