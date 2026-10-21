// AdminInternal.h
// Module-internal declarations of the Admin module: only its own files include this header

#ifndef	ADMIN_INTERNAL_H
#define	ADMIN_INTERNAL_H

#define	CHECK_RIGHT														\
	if (a->ServerAdmin == false && (StrCmpi(a->HubName, t->HubName) != 0))	\
		return ERR_NOT_ENOUGH_RIGHT;	\
	if (IsEmptyStr(t->HubName))			\
		return ERR_INVALID_PARAMETER;
#define	SERVER_ADMIN_ONLY												\
	if (a->ServerAdmin == false)										\
		return ERR_NOT_ENOUGH_RIGHT;

UINT ScGetCaps(RPC *r, CAPSLIST *t);
UINT ScReadLogFile(RPC *r, RPC_READ_LOG_FILE *t);

UINT StRegenerateServerCert(ADMIN *a, RPC_TEST *t);
UINT StFlush(ADMIN *a, RPC_TEST *t);
UINT StCrash(ADMIN *a, RPC_TEST *t);
UINT StReadLogFile(ADMIN *a, RPC_READ_LOG_FILE *t);
UINT StEnumLogFile(ADMIN *a, RPC_ENUM_LOG_FILE *t);
UINT StGetAcList(ADMIN *a, RPC_AC_LIST *t);
UINT StSetAcList(ADMIN *a, RPC_AC_LIST *t);
UINT StGetCrl(ADMIN *a, RPC_CRL *t);
UINT StDelCrl(ADMIN *a, RPC_CRL *t);
UINT StAddCrl(ADMIN *a, RPC_CRL *t);
UINT StEnumCrl(ADMIN *a, RPC_ENUM_CRL *t);
UINT StSetHubExtOptions(ADMIN *a, RPC_ADMIN_OPTION *t);
UINT StGetHubExtOptions(ADMIN *a, RPC_ADMIN_OPTION *t);
UINT StSetHubAdminOptions(ADMIN *a, RPC_ADMIN_OPTION *t);
UINT StGetHubAdminOptions(ADMIN *a, RPC_ADMIN_OPTION *t);
UINT StGetConfig(ADMIN *a, RPC_CONFIG *t);
UINT StSetConfig(ADMIN *a, RPC_CONFIG *t);
UINT StGetCaps(ADMIN *a, CAPSLIST *t);
UINT StRebootServer(ADMIN *a, RPC_TEST *t);
UINT StEnumEthernet(ADMIN *a, RPC_ENUM_ETH *t);
UINT StAddLocalBridge(ADMIN *a, RPC_LOCALBRIDGE *t);
UINT StDeleteLocalBridge(ADMIN *a, RPC_LOCALBRIDGE *t);
UINT StEnumLocalBridge(ADMIN *a, RPC_ENUM_LOCALBRIDGE *t);
UINT StSetSysLog(ADMIN *a, SYSLOG_SETTING *t);
UINT StGetSysLog(ADMIN *a, SYSLOG_SETTING *t);
UINT StDeleteIpTable(ADMIN *a, RPC_DELETE_TABLE *t);
UINT StEnumIpTable(ADMIN *a, RPC_ENUM_IP_TABLE *t);
UINT StDeleteMacTable(ADMIN *a, RPC_DELETE_TABLE *t);
UINT StEnumMacTable(ADMIN *a, RPC_ENUM_MAC_TABLE *t);
UINT StDeleteSession(ADMIN *a, RPC_DELETE_SESSION *t);
UINT StGetSessionStatus(ADMIN *a, RPC_SESSION_STATUS *t);
UINT StEnumSession(ADMIN *a, RPC_ENUM_SESSION *t);
UINT StEnumGroup(ADMIN *a, RPC_ENUM_GROUP *t);
UINT StDeleteGroup(ADMIN *a, RPC_DELETE_USER *t);
UINT StGetGroup(ADMIN *a, RPC_SET_GROUP *t);
UINT StSetGroup(ADMIN *a, RPC_SET_GROUP *t);
UINT StCreateGroup(ADMIN *a, RPC_SET_GROUP *t);
UINT StEnumUser(ADMIN *a, RPC_ENUM_USER *t);
UINT StDeleteUser(ADMIN *a, RPC_DELETE_USER *t);
UINT StGetUser(ADMIN *a, RPC_SET_USER *t);
UINT StSetUser(ADMIN *a, RPC_SET_USER *t);
UINT StCreateUser(ADMIN *a, RPC_SET_USER *t);
UINT StEnumAccess(ADMIN *a, RPC_ENUM_ACCESS_LIST *t);
UINT StDeleteAccess(ADMIN *a, RPC_DELETE_ACCESS *t);
UINT StSetAccessList(ADMIN *a, RPC_ENUM_ACCESS_LIST *t);
UINT StAddAccess(ADMIN *a, RPC_ADD_ACCESS *t);
UINT StRenameLink(ADMIN *a, RPC_RENAME_LINK *t);
UINT StDeleteLink(ADMIN *a, RPC_LINK *t);
UINT StSetLinkOffline(ADMIN *a, RPC_LINK *t);
UINT StSetLinkOnline(ADMIN *a, RPC_LINK *t);
UINT StGetLinkStatus(ADMIN *a, RPC_LINK_STATUS *t);
UINT StEnumLink(ADMIN *a, RPC_ENUM_LINK *t);
UINT StGetLink(ADMIN *a, RPC_CREATE_LINK *t);
UINT StSetLink(ADMIN *a, RPC_CREATE_LINK *t);
UINT StCreateLink(ADMIN *a, RPC_CREATE_LINK *t);
UINT StDeleteCa(ADMIN *a, RPC_HUB_DELETE_CA *t);
UINT StGetCa(ADMIN *a, RPC_HUB_GET_CA *t);
UINT StEnumCa(ADMIN *a, RPC_HUB_ENUM_CA *t);
UINT StAddCa(ADMIN *a, RPC_HUB_ADD_CA *t);
UINT StGetHubLog(ADMIN *a, RPC_HUB_LOG *t);
UINT StSetHubLog(ADMIN *a, RPC_HUB_LOG *t);
UINT StGetHubStatus(ADMIN *a, RPC_HUB_STATUS *t);
UINT StSetHubOnline(ADMIN *a, RPC_SET_HUB_ONLINE *t);
UINT StGetConnectionInfo(ADMIN *a, RPC_CONNECTION_INFO *t);
UINT StDisconnectConnection(ADMIN *a, RPC_DISCONNECT_CONNECTION *t);
UINT StEnumConnection(ADMIN *a, RPC_ENUM_CONNECTION *t);
UINT StDeleteHub(ADMIN *a, RPC_DELETE_HUB *t);
UINT StEnumHub(ADMIN *a, RPC_ENUM_HUB *t);
UINT StGetHub(ADMIN *a, RPC_CREATE_HUB *t);
UINT StSetHub(ADMIN *a, RPC_CREATE_HUB *t);
UINT StCreateHub(ADMIN *a, RPC_CREATE_HUB *t);
UINT StSetServerCipher(ADMIN *a, RPC_STR *t);
UINT StGetServerCipher(ADMIN *a, RPC_STR *t);
UINT StGetServerCipherList(ADMIN *a, RPC_STR *t);
UINT StGetServerCert(ADMIN *a, RPC_KEY_PAIR *t);
UINT StSetServerCert(ADMIN *a, RPC_KEY_PAIR *t);
UINT StSetServerPassword(ADMIN *a, RPC_SET_PASSWORD *t);
UINT StEnableListener(ADMIN *a, RPC_LISTENER *t);
UINT StDeleteListener(ADMIN *a, RPC_LISTENER *t);
UINT StEnumListener(ADMIN *a, RPC_LISTENER_LIST *t);
UINT StCreateListener(ADMIN *a, RPC_LISTENER *t);
UINT StGetServerStatus(ADMIN *a, RPC_SERVER_STATUS *t);
UINT StGetServerInfo(ADMIN *a, RPC_SERVER_INFO *t);
void HashAdminPassword(void *hash, char *password);
HUB *AdminGetHub(ADMIN *a, char *hubname, char *denied_option, UINT *err);

#endif	// ADMIN_INTERNAL_H
