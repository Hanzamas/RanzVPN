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

static UINT AdminCheckPassword(CEDAR *c, void *random, const void *secure_password, char *hubname, bool accept_empty_password, bool *is_password_empty);
static bool SiIsEmptyPassword(const void *hash_password);

#define DECLARE_RPC_EX(rpc_name, data_type, function, in_rpc, out_rpc, free_rpc) \
	else if (StrCmpi(name, rpc_name) == 0) {                                     \
		data_type *t;                                                            \
		t = ZeroMalloc(sizeof(data_type));                                       \
		in_rpc(t, p);                                                            \
		err = function(a, t);                                                    \
		if (err == ERR_NO_ERROR) {                                               \
			out_rpc(ret, t);                                                     \
		}                                                                        \
		free_rpc(t);                                                             \
		Free(t);                                                                 \
		ok = true;                                                               \
	}
#define DECLARE_RPC(rpc_name, data_type, function, in_rpc, out_rpc) \
	else if (StrCmpi(name, rpc_name) == 0) {                        \
		data_type *t;                                               \
		t = ZeroMalloc(sizeof(data_type));                          \
		in_rpc(t, p);                                               \
		err = function(a, t);                                       \
		if (err == ERR_NO_ERROR) {                                  \
			out_rpc(ret, t);                                        \
		}                                                           \
		Free(t);                                                    \
		ok = true;                                                  \
	}

// Hub lookup for the admin handlers: the access check, the lookup and the hub
// admin option check, in that order. Returns a referenced HUB, or NULL with *err set.
HUB *AdminGetHub(ADMIN *a, char *hubname, char *denied_option, UINT *err) {
	if (a->ServerAdmin == false && StrCmpi(a->HubName, hubname) != 0) {
		*err = ERR_NOT_ENOUGH_RIGHT;
		return NULL;
	}

	if (IsEmptyStr(hubname)) {
		*err = ERR_INVALID_PARAMETER;
		return NULL;
	}

	HUB *h = GetHub(a->Server->Cedar, hubname);
	if (h == NULL) {
		*err = ERR_HUB_NOT_FOUND;
		return NULL;
	}

	if (denied_option != NULL && a->ServerAdmin == false && GetHubAdminOption(h, denied_option) != 0) {
		ReleaseHub(h);
		*err = ERR_NOT_ENOUGH_RIGHT;
		return NULL;
	}

	return h;
}

// Debug log line "RPC: RPC-n (ip): ..." of the session
static void AdminDispatchTrace(ADMIN *a, char *format, ...) {
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
PACK *AdminInvoke(ADMIN *a, char *name, PACK *p) {
	SERVER *server = NULL;
	CEDAR *cedar = NULL;
	bool ok = false;
	if (a == NULL || name == NULL || p == NULL)
		return NULL;

	server = a->Server;

	if (server == NULL)
		return NULL;

	PACK *ret = NewPack();
	UINT err = ERR_NO_ERROR;

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
	DECLARE_RPC("RebootServer", RPC_TEST, StRebootServer, InRpcTest, OutRpcTest)
	DECLARE_RPC_EX("GetCaps", CAPSLIST, StGetCaps, InRpcCapsList, OutRpcCapsList, FreeRpcCapsList)
	DECLARE_RPC_EX("GetConfig", RPC_CONFIG, StGetConfig, InRpcConfig, OutRpcConfig, FreeRpcConfig)
	DECLARE_RPC_EX("SetConfig", RPC_CONFIG, StSetConfig, InRpcConfig, OutRpcConfig, FreeRpcConfig)
	DECLARE_RPC_EX("GetHubAdminOptions", RPC_ADMIN_OPTION, StGetHubAdminOptions, InRpcAdminOption, OutRpcAdminOption, FreeRpcAdminOption)
	DECLARE_RPC_EX("SetHubAdminOptions", RPC_ADMIN_OPTION, StSetHubAdminOptions, InRpcAdminOption, OutRpcAdminOption, FreeRpcAdminOption)
	DECLARE_RPC_EX("GetHubExtOptions", RPC_ADMIN_OPTION, StGetHubExtOptions, InRpcAdminOption, OutRpcAdminOption, FreeRpcAdminOption)
	DECLARE_RPC_EX("SetHubExtOptions", RPC_ADMIN_OPTION, StSetHubExtOptions, InRpcAdminOption, OutRpcAdminOption, FreeRpcAdminOption)
	DECLARE_RPC_EX("EnumCrl", RPC_ENUM_CRL, StEnumCrl, InRpcEnumCrl, OutRpcEnumCrl, FreeRpcEnumCrl)
	DECLARE_RPC_EX("AddCrl", RPC_CRL, StAddCrl, InRpcCrl, OutRpcCrl, FreeRpcCrl)
	DECLARE_RPC_EX("DelCrl", RPC_CRL, StDelCrl, InRpcCrl, OutRpcCrl, FreeRpcCrl)
	DECLARE_RPC_EX("GetCrl", RPC_CRL, StGetCrl, InRpcCrl, OutRpcCrl, FreeRpcCrl)
	DECLARE_RPC_EX("SetAcList", RPC_AC_LIST, StSetAcList, InRpcAcList, OutRpcAcList, FreeRpcAcList)
	DECLARE_RPC_EX("GetAcList", RPC_AC_LIST, StGetAcList, InRpcAcList, OutRpcAcList, FreeRpcAcList)
	DECLARE_RPC_EX("EnumLogFile", RPC_ENUM_LOG_FILE, StEnumLogFile, InRpcEnumLogFile, OutRpcEnumLogFile, FreeRpcEnumLogFile)
	DECLARE_RPC_EX("ReadLogFile", RPC_READ_LOG_FILE, StReadLogFile, InRpcReadLogFile, OutRpcReadLogFile, FreeRpcReadLogFile)
	DECLARE_RPC("SetSysLog", SYSLOG_SETTING, StSetSysLog, InRpcSysLogSetting, OutRpcSysLogSetting)
	DECLARE_RPC("GetSysLog", SYSLOG_SETTING, StGetSysLog, InRpcSysLogSetting, OutRpcSysLogSetting)
	DECLARE_RPC("Crash", RPC_TEST, StCrash, InRpcTest, OutRpcTest)
	DECLARE_RPC("Flush", RPC_TEST, StFlush, InRpcTest, OutRpcTest)
	DECLARE_RPC("RegenerateServerCert", RPC_TEST, StRegenerateServerCert, InRpcTest, OutRpcTest)

	if (ok == false)
		err = ERR_NOT_SUPPORTED;

	if (err != ERR_NO_ERROR)
		PackAddInt(ret, "error", err);

	AdminDispatchTrace(a, "Leaving RPC [%s] (Error: %u).", name, err);

	Unlock(cedar->CedarSuperLock);

	return ret;
}



static bool CheckAdminSourceAddress(IP *remote_ip, const char *hubname) {
	char *s;
	bool ok = false;
	if (remote_ip == NULL)
		return false;

	BUF *b = ReadDump(ADMINIP_TXT);
	if (b == NULL)
		return true;

	while (true) {
		IP ip;
		IP mask;
		IP ip1;
		IP ip2;
		s = CfgReadNextLine(b);

		if (s == NULL)
			break;

		Trim(s);

		UINT i = SearchStrEx(s, "//", 0, false);
		if (i != INFINITE)
			s[i] = 0;

		i = SearchStrEx(s, "#", 0, false);
		if (i != INFINITE)
			s[i] = 0;

		Trim(s);

		TOKEN_LIST *t = ParseToken(s, " \t");
		if (t != NULL) {
			if (t->NumTokens >= 1) {
				if (t->NumTokens == 1 || StrCmpi(hubname, t->Token[1]) == 0) {
					if (ParseIpAndMask46(t->Token[0], &ip, &mask)) {
						if (IsIP4(remote_ip) && IsIP4(&ip)) {
							IPAnd4(&ip1, remote_ip, &mask);
							IPAnd4(&ip2, &ip, &mask);

							if (CmpIpAddr(&ip1, &ip2) == 0)
								ok = true;
						} else if (IsIP6(remote_ip) && IsIP6(&ip)) {
							IPAnd6(&ip1, remote_ip, &mask);
							IPAnd6(&ip2, &ip, &mask);

							if (CmpIpAddr(&ip1, &ip2) == 0)
								ok = true;
						}
					} else if (StrToIP(&ip, t->Token[0])) {
						if (CmpIpAddr(remote_ip, &ip) == 0)
							ok = true;
					}

					if (StrCmpi(t->Token[0], "*") == 0)
						ok = true;
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
ADMIN *AdminOpen(SERVER *server, ADMIN_LOGIN *login, UINT *err) {
	bool is_empty_password = false;
	UCHAR null_password[SHA1_SIZE];
	UCHAR secure_null_password[SHA1_SIZE];
	UINT dummy;
	if (err == NULL)
		err = &dummy;
	if (server == NULL || login == NULL) {
		*err = ERR_INTERNAL_ERROR;
		return NULL;
	}

	CEDAR *cedar = server->Cedar;
	bool hub_scope = (StrLen(login->HubName) != 0);

	if (CheckAdminSourceAddress(&login->RemoteIP, login->HubName) == false) {
		SLog(cedar, "LA_IP_DENIED", login->ConnName);
		*err = ERR_IP_ADDRESS_DENIED;
		return NULL;
	}

	if (login->HasSecurePassword == false) {
		*err = ERR_PROTOCOL_ERROR;
		return NULL;
	}

	if (hub_scope == false)
		SLog(cedar, "LA_CONNECTED_1", login->ConnName);
	else
		SLog(cedar, "LA_CONNECTED_2", login->ConnName, login->HubName);

	UINT e = AdminCheckPassword(cedar, login->Random, login->SecurePassword,
	                            hub_scope ? login->HubName : NULL, login->AcceptEmptyPassword, &is_empty_password);

	if (e != ERR_NO_ERROR) {
		SLog(cedar, "LA_ERROR", login->ConnName, GetUniErrorStr(e), e);
		*err = e;
		return NULL;
	}

	SLog(cedar, "LA_OK", login->ConnName);

	HashAdminPassword(null_password, "");
	SecurePassword(secure_null_password, null_password, login->Random);

	if (Cmp(secure_null_password, login->SecurePassword, SHA1_SIZE) == 0) {
		// Refuse a blank server admin or Hub admin password from any address but loopback (127.0.0.0/8, ::1)
		if (IsLocalHostIP(&login->RemoteIP) == false) {
			*err = ERR_NULL_PASSWORD_LOCAL_ONLY;
			return NULL;
		}
	}

	ADMIN *a = ZeroMalloc(sizeof(ADMIN));
	a->Server = server;
	a->ServerAdmin = (hub_scope ? false : true);
	a->HubName = (hub_scope ? CopyStr(login->HubName) : NULL);
	Copy(&a->RemoteIP, &login->RemoteIP, sizeof(IP));
	Format(a->Tag, sizeof(a->Tag), "RPC-%u", login->Id);
	a->EmptyPassword = (login->AcceptEmptyPassword && is_empty_password);

	*err = ERR_NO_ERROR;

	return a;
}

// Free an admin session
void AdminClose(ADMIN *a) {
	if (a == NULL)
		return;

	if (a->LogFileList != NULL)
		FreeEnumLogFile(a->LogFileList);

	Free(a->HubName);
	Free(a);
}

// RPC server dispatcher of the admin connection: the session is the RPC parameter
static PACK *AdminDispatch(RPC *rpc, char *name, PACK *p) {
	if (rpc == NULL)
		return NULL;

	return AdminInvoke((ADMIN *)rpc->Param, name, p);
}

UINT AdminAccept(CONNECTION *c, PACK *p) {
	ADMIN_LOGIN login;
	UINT err;
	if (c == NULL || p == NULL || c->FirstSock == NULL || c->Cedar == NULL || c->Cedar->Server == NULL)
		return ERR_INTERNAL_ERROR;

	SOCK *sock = c->FirstSock;

	Zero(&login, sizeof(login));
	StrCpy(login.ConnName, sizeof(login.ConnName), c->Name);
	Copy(&login.RemoteIP, &sock->RemoteIP, sizeof(IP));
	login.Id = sock->socket;
	Copy(login.Random, c->Random, SHA1_SIZE);
	login.AcceptEmptyPassword = PackGetBool(p, "accept_empty_password");
	PackGetStr(p, "hubname", login.HubName, sizeof(login.HubName));
	if (PackGetDataSize(p, "secure_password") == SHA1_SIZE) {
		PackGetData(p, "secure_password", login.SecurePassword);
		login.HasSecurePassword = true;
	}

	ADMIN *a = AdminOpen(c->Cedar->Server, &login, &err);
	if (a == NULL)
		return err;

	p = NewPack();
	if (a->EmptyPassword)
		PackAddBool(p, "empty_password", true);
	HttpServerSend(sock, p);
	FreePack(p);

	SetTimeout(sock, INFINITE);

	RPC *rpc = NewRpc(sock, AdminDispatch, a);

	SLog(c->Cedar, "LA_RPC_START", c->Name, a->Tag);

	RpcServer(rpc);
	RpcFree(rpc);

	AdminClose(a);

	return ERR_NO_ERROR;
}

static UINT AdminCheckPassword(CEDAR *c, void *random, const void *secure_password, char *hubname,
                               bool accept_empty_password, bool *is_password_empty) {
	UCHAR check[SHA1_SIZE];
	bool b_dummy;
	if (c == NULL || random == NULL || secure_password == NULL)
		return ERR_INTERNAL_ERROR;
	if (is_password_empty == NULL)
		is_password_empty = &b_dummy;

	*is_password_empty = false;

	if (hubname == NULL || StrLen(hubname) == 0) {
		Lock(c->lock);
		{
			if (accept_empty_password && SiIsEmptyPassword(c->Server->HashedPassword))
				*is_password_empty = true;

			SecurePassword(check, c->Server->HashedPassword, random);
		}
		Unlock(c->lock);

		if (Cmp(check, secure_password, SHA1_SIZE) != 0)
			return ERR_ACCESS_DENIED;
	} else {
		HUB *h = GetHub(c, hubname);

		if (h == NULL)
			return ERR_HUB_NOT_FOUND;

		Lock(h->lock);
		{
			if (accept_empty_password && SiIsEmptyPassword(h->HashedPassword))
				*is_password_empty = true;

			SecurePassword(check, h->HashedPassword, random);
		}
		Unlock(h->lock);

		ReleaseHub(h);

		if (Cmp(check, secure_password, SHA1_SIZE) != 0)
			return ERR_ACCESS_DENIED;
	}

	return ERR_NO_ERROR;
}

void HashAdminPassword(void *hash, char *password) {
	if (hash == NULL || password == NULL)
		return;

	Sha0(hash, password, StrLen(password));
}

static SESSION *AdminConnectMain(CEDAR *cedar, CLIENT_OPTION *o, char *hubname, void *hashed_password, UINT *err, char *client_name, bool *empty_password) {
	UCHAR secure_password[SHA1_SIZE];
	RPC_WINVER ver;
	SESSION *s = NewRpcSession(cedar, o, err, client_name);
	if (s == NULL)
		return NULL;

	// The connection NewRpcSession opened and logged in: the admin RPC runs on its first socket
	CONNECTION *c = s->Connection;
	SOCK *sock = c->FirstSock;

	PACK *p = NewPack();

	PackAddClientVersion(p, c);

	PackAddStr(p, "method", "admin");
	PackAddBool(p, "accept_empty_password", true);

	GetWinVer(&ver);
	OutRpcWinVer(p, &ver);

	SecurePassword(secure_password, hashed_password, c->Random);

	PackAddData(p, "secure_password", secure_password, sizeof(secure_password));

	if (hubname != NULL)
		PackAddStr(p, "hubname", hubname);

	if (HttpClientSend(sock, p) == false) {
		FreePack(p);
		ReleaseSession(s);
		*err = ERR_DISCONNECTED;
		return NULL;
	}

	FreePack(p);

	p = HttpClientRecv(sock);
	if (p == NULL) {
		ReleaseSession(s);
		*err = ERR_DISCONNECTED;
		return NULL;
	}

	if (GetErrorFromPack(p) != 0) {
		ReleaseSession(s);
		*err = GetErrorFromPack(p);
		FreePack(p);
		return NULL;
	}

	if (empty_password != NULL)
		*empty_password = PackGetBool(p, "empty_password");

	FreePack(p);

	return s;
}

// The socket an admin RPC uses after the login of its session (AdminConnectMain), at the first connect and at every
// reconnect: no timeout, because the server can take long to answer an RPC (SetConfig, a large EnumSession or
// EnumLogFile) and the connect left CONNECTING_TIMEOUT on the socket. The caller takes its own reference
static SOCK *AdminRpcSock(const SESSION *s) {
	CONNECTION *c = s->Connection;
	SOCK *sock = c->FirstSock;

	SetTimeout(sock, INFINITE);

	return sock;
}

RPC *AdminConnectEx(CEDAR *cedar, CLIENT_OPTION *o, char *hubname, void *hashed_password, UINT *err, char *client_name) {
	UCHAR hashed_password_2[SHA1_SIZE];
	bool empty_password = false;
	if (cedar == NULL || o == NULL || hashed_password == NULL || err == NULL)
		return NULL;

	if (client_name == NULL)
		client_name = CEDAR_MANAGER_STR;

	Copy(hashed_password_2, hashed_password, SHA1_SIZE);

	SESSION *s = AdminConnectMain(cedar, o, hubname, hashed_password_2, err, client_name, &empty_password);

	if (s == NULL)
		return NULL;

	SOCK *sock = AdminRpcSock(s);

	RPC *rpc = NewRpc(sock, NULL, s);

	Copy(&rpc->VpnServerClientOption, o, sizeof(CLIENT_OPTION));
	StrCpy(rpc->VpnServerHubName, sizeof(rpc->VpnServerHubName), hubname);
	StrCpy(rpc->VpnServerClientName, sizeof(rpc->VpnServerClientName), client_name);

	if (empty_password == false)
		Copy(rpc->VpnServerHashedPassword, hashed_password_2, SHA1_SIZE);
	else
		HashAdminPassword(rpc->VpnServerHashedPassword, "");

	return rpc;
}

UINT AdminReconnect(RPC *rpc) {
	UINT err;
	bool empty_password = false;
	if (rpc == NULL)
		return ERR_INTERNAL_ERROR;

	SESSION *s = (SESSION *)rpc->Param;
	CEDAR *cedar = s->Cedar;
	AddRef(cedar->ref);

	SOCK *sock = rpc->Sock;
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
		return err;

	if (empty_password)
		HashAdminPassword(rpc->VpnServerHashedPassword, "");

	rpc->Param = s;
	rpc->Sock = AdminRpcSock(s);
	AddRef(rpc->Sock->ref);

	return ERR_NO_ERROR;
}

static bool SiIsEmptyPassword(const void *hash_password) {
	UCHAR hash[SHA1_SIZE];
	if (hash_password == NULL)
		return false;

	Sha0(hash, "", 0);

	if (Cmp(hash_password, hash, SHA1_SIZE) == 0)
		return true;

	return false;
}

