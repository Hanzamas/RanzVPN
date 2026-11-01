// Admin.h
// Header of Admin.c

#ifndef ADMIN_H
#define ADMIN_H

#include "Account.h"
#include "Cedar.h"
#include "Hub.h"
#include "HubLog.h"

#include "Mayaqua/Kernel.h"

struct RPC_WINVER {
	bool IsWindows;
	bool IsNT;
	bool IsServer;
	bool IsBeta;
	UINT VerMajor;
	UINT VerMinor;
	UINT Build;
	UINT ServicePack;
	char Title[128];
};

// An admin session that owns everything its RPCs and log lines need: no socket, no RPC object
struct ADMIN {
	SERVER *Server;
	bool ServerAdmin; // Server scope; otherwise the scope is the hub HubName
	char *HubName;    // Copy owned by the session, NULL in the server scope
	IP RemoteIP;
	char Tag[32];       // "RPC-n", the name of the session in the log lines
	bool EmptyPassword; // Logged in with the empty password and the client accepts that
	LIST *LogFileList;
};

// What a client sends to open an admin session, with the facts of its connection
struct ADMIN_LOGIN {
	char ConnName[MAX_SIZE]; // Connection name in the LA_* log lines
	IP RemoteIP;
	UINT Id;                           // Number n of the session tag "RPC-n"
	UCHAR Random[SHA1_SIZE];           // Challenge the connection sent
	char HubName[MAX_HUBNAME_LEN + 1]; // Empty: server scope
	bool AcceptEmptyPassword;
	bool HasSecurePassword; // A secure_password of SHA1_SIZE bytes came with the request
	UCHAR SecurePassword[SHA1_SIZE];
};

struct RPC_TEST {
	UINT IntValue;
	UINT64 Int64Value;
	char StrValue[1024];
	wchar_t UniStrValue[1024];
};

struct RPC_SERVER_INFO {
	char ServerProductName[128];
	char ServerVersionString[128];
	char ServerBuildInfoString[128];
	UINT ServerVerInt;
	UINT ServerBuildInt;
	char ServerHostName[MAX_HOST_NAME_LEN + 1];
	UINT64 ServerBuildDate;
	OS_INFO OsInfo;
};

struct RPC_SERVER_STATUS {
	UINT NumTcpConnections;
	UINT NumTcpConnectionsLocal;
	UINT NumHubTotal;
	UINT NumHubStandalone;
	UINT NumSessionsTotal;
	UINT NumSessionsLocal;
	UINT NumMacTables;
	UINT NumIpTables;
	UINT NumUsers;
	UINT NumGroups;
	UINT AssignedBridgeLicenses;
	UINT AssignedClientLicenses;
	UINT AssignedBridgeLicensesTotal;
	UINT AssignedClientLicensesTotal;
	TRAFFIC Traffic;
	UINT64 CurrentTime;
	UINT64 CurrentTick;
	UINT64 StartTime;
	MEMINFO MemInfo;
};

struct RPC_LISTENER {
	UINT Port;
	bool Enable;
};

struct RPC_LISTENER_LIST {
	UINT NumPort;
	UINT *Ports;
	bool *Enables;
	bool *Errors;
};

// The HTTP listener setting (GetHttpListener, SetHttpListener). For SetHttpListener, Port 0 keeps the saved port
struct RPC_HTTP_LISTENER {
	bool Enabled;
	UINT Port;
	bool Listening; // Get only: the port is bound now
};

struct RPC_STR {
	char *String;
};

struct RPC_SET_PASSWORD {
	UCHAR HashedPassword[SHA1_SIZE];
	char PlainTextPassword[MAX_SIZE];
};

struct RPC_KEY_PAIR {
	X *Cert;
	LIST *Chain;
	K *Key;
	UINT Flag1;
};

struct RPC_HUB_OPTION {
	UINT MaxSession;
	bool NoEnum;
};

struct RPC_CREATE_HUB {
	char HubName[MAX_HUBNAME_LEN + 1];
	UCHAR HashedPassword[SHA1_SIZE];
	UCHAR SecurePassword[SHA1_SIZE];
	char AdminPasswordPlainText[MAX_SIZE];
	bool Online;
	RPC_HUB_OPTION HubOption;
};

struct RPC_ENUM_HUB_ITEM {
	char HubName[MAX_HUBNAME_LEN + 1];
	bool Online;
	UINT NumUsers;
	UINT NumGroups;
	UINT NumSessions;
	UINT NumMacTables;
	UINT NumIpTables;
	UINT64 LastCommTime;
	UINT64 LastLoginTime;
	UINT64 CreatedTime;
	UINT NumLogin;
	bool IsTrafficFilled;
	TRAFFIC Traffic;
};

struct RPC_ENUM_HUB {
	UINT NumHub;
	RPC_ENUM_HUB_ITEM *Hubs;
};

struct RPC_DELETE_HUB {
	char HubName[MAX_HUBNAME_LEN + 1];
};

struct RPC_ENUM_CONNECTION_ITEM {
	char Name[MAX_SIZE];
	char Hostname[MAX_SIZE];
	UINT Ip;
	UINT Port;
	UINT64 ConnectedTime;
	UINT Type;
};

struct RPC_ENUM_CONNECTION {
	UINT NumConnection;
	RPC_ENUM_CONNECTION_ITEM *Connections;
};

struct RPC_DISCONNECT_CONNECTION {
	char Name[MAX_SIZE];
};

struct RPC_CONNECTION_INFO {
	char Name[MAX_SIZE];
	UINT Type;
	char Hostname[MAX_SIZE];
	UINT Ip;
	UINT Port;
	UINT64 ConnectedTime;
	char ServerStr[MAX_SERVER_STR_LEN + 1];
	UINT ServerVer;
	UINT ServerBuild;
	char ClientStr[MAX_CLIENT_STR_LEN + 1];
	UINT ClientVer;
	UINT ClientBuild;
};

struct RPC_SET_HUB_ONLINE {
	char HubName[MAX_HUBNAME_LEN + 1];
	bool Online;
};

struct RPC_HUB_STATUS {
	char HubName[MAX_HUBNAME_LEN + 1];
	bool Online;
	UINT NumSessions;
	UINT NumSessionsClient;
	UINT NumSessionsBridge;
	UINT NumAccessLists;
	UINT NumUsers;
	UINT NumGroups;
	UINT NumMacTables;
	UINT NumIpTables;
	TRAFFIC Traffic;
	UINT64 LastCommTime;
	UINT64 LastLoginTime;
	UINT64 CreatedTime;
	UINT NumLogin;
};

struct RPC_HUB_LOG {
	char HubName[MAX_HUBNAME_LEN + 1];
	HUB_LOG LogSetting;
};

struct RPC_HUB_ADD_CA {
	char HubName[MAX_HUBNAME_LEN + 1];
	X *Cert;
};

struct RPC_HUB_ENUM_CA_ITEM {
	UINT Key;
	wchar_t SubjectName[MAX_SIZE];
	wchar_t IssuerName[MAX_SIZE];
	UINT64 Expires;
};

struct RPC_HUB_ENUM_CA {
	char HubName[MAX_HUBNAME_LEN + 1];
	UINT NumCa;
	RPC_HUB_ENUM_CA_ITEM *Ca;
};

struct RPC_HUB_GET_CA {
	char HubName[MAX_HUBNAME_LEN + 1];
	UINT Key;
	X *Cert;
};

struct RPC_HUB_DELETE_CA {
	char HubName[MAX_HUBNAME_LEN + 1];
	UINT Key;
};

struct RPC_CREATE_LINK {
	char HubName[MAX_HUBNAME_LEN + 1];
	bool Online;
	CLIENT_OPTION *ClientOption;
	CLIENT_AUTH *ClientAuth;
	POLICY Policy;
	bool CheckServerCert;
	bool AddDefaultCA;
	X *ServerCert;
};

struct RPC_ENUM_LINK_ITEM {
	wchar_t AccountName[MAX_ACCOUNT_NAME_LEN + 1];
	bool Online;
	bool Connected;
	UINT LastError;
	UINT64 ConnectedTime;
	char Hostname[MAX_HOST_NAME_LEN + 1];
	char HubName[MAX_HUBNAME_LEN + 1];
};

struct RPC_ENUM_LINK {
	char HubName[MAX_HUBNAME_LEN + 1];
	UINT NumLink;
	RPC_ENUM_LINK_ITEM *Links;
};

struct RPC_LINK_STATUS {
	char HubName[MAX_HUBNAME_LEN + 1];
	wchar_t AccountName[MAX_ACCOUNT_NAME_LEN + 1];
	RPC_CLIENT_GET_CONNECTION_STATUS Status;
};

struct RPC_LINK {
	char HubName[MAX_HUBNAME_LEN + 1];
	wchar_t AccountName[MAX_ACCOUNT_NAME_LEN + 1];
};

struct RPC_RENAME_LINK {
	char HubName[MAX_HUBNAME_LEN + 1];
	wchar_t OldAccountName[MAX_ACCOUNT_NAME_LEN + 1];
	wchar_t NewAccountName[MAX_ACCOUNT_NAME_LEN + 1];
};

struct RPC_ENUM_ACCESS_LIST {
	char HubName[MAX_HUBNAME_LEN + 1];
	UINT NumAccess;
	ACCESS *Accesses;
};

struct RPC_ADD_ACCESS {
	char HubName[MAX_HUBNAME_LEN + 1];
	ACCESS Access;
};

struct RPC_DELETE_ACCESS {
	char HubName[MAX_HUBNAME_LEN + 1];
	UINT Id;
};

struct RPC_SET_USER {
	char HubName[MAX_HUBNAME_LEN + 1];
	char Name[MAX_USERNAME_LEN + 1];
	char GroupName[MAX_USERNAME_LEN + 1];
	wchar_t Realname[MAX_SIZE];
	wchar_t Note[MAX_SIZE];
	UINT64 CreatedTime;
	UINT64 UpdatedTime;
	UINT64 ExpireTime;
	UINT AuthType;
	void *AuthData;
	UINT NumLogin;
	TRAFFIC Traffic;
	POLICY *Policy;
};

struct RPC_ENUM_USER_ITEM {
	char Name[MAX_USERNAME_LEN + 1];
	char GroupName[MAX_USERNAME_LEN + 1];
	wchar_t Realname[MAX_SIZE];
	wchar_t Note[MAX_SIZE];
	UINT AuthType;
	UINT NumLogin;
	UINT64 LastLoginTime;
	bool DenyAccess;
	bool IsTrafficFilled;
	TRAFFIC Traffic;
	bool IsExpiresFilled;
	UINT64 Expires;
};

struct RPC_ENUM_USER {
	char HubName[MAX_HUBNAME_LEN + 1];
	UINT NumUser;
	RPC_ENUM_USER_ITEM *Users;
};

struct RPC_SET_GROUP {
	char HubName[MAX_HUBNAME_LEN + 1];
	char Name[MAX_USERNAME_LEN + 1];
	wchar_t Realname[MAX_SIZE];
	wchar_t Note[MAX_SIZE];
	TRAFFIC Traffic;
	POLICY *Policy;
};

struct RPC_ENUM_GROUP_ITEM {
	char Name[MAX_USERNAME_LEN + 1];
	wchar_t Realname[MAX_SIZE];
	wchar_t Note[MAX_SIZE];
	UINT NumUsers;
	bool DenyAccess;
};

struct RPC_ENUM_GROUP {
	char HubName[MAX_HUBNAME_LEN + 1];
	UINT NumGroup;
	RPC_ENUM_GROUP_ITEM *Groups;
};

struct RPC_DELETE_USER {
	char HubName[MAX_HUBNAME_LEN + 1];
	char Name[MAX_USERNAME_LEN + 1];
};

struct RPC_ENUM_SESSION_ITEM {
	char Name[MAX_SESSION_NAME_LEN + 1];
	char Username[MAX_USERNAME_LEN + 1];
	UINT Ip;
	IP ClientIP;
	char Hostname[MAX_HOST_NAME_LEN + 1];
	UINT MaxNumTcp;
	UINT CurrentNumTcp;
	UINT64 PacketSize;
	UINT64 PacketNum;
	bool LinkMode;
	bool BridgeMode;
	bool Client_BridgeMode;
	bool Client_MonitorMode;
	UINT VLanId;
	UCHAR UniqueId[16];
	bool IsDormantEnabled;
	bool IsDormant;
	UINT64 LastCommDormant;
	UINT64 CreatedTime;
	UINT64 LastCommTime;
};

struct RPC_DELETE_SESSION {
	char HubName[MAX_HUBNAME_LEN + 1];
	char Name[MAX_SESSION_NAME_LEN + 1];
};

struct RPC_ENUM_MAC_TABLE_ITEM {
	UINT Key;
	char SessionName[MAX_SESSION_NAME_LEN + 1];
	UCHAR MacAddress[6];
	UINT64 CreatedTime;
	UINT64 UpdatedTime;
	UINT VlanId;
};

struct RPC_ENUM_MAC_TABLE {
	char HubName[MAX_HUBNAME_LEN + 1];
	UINT NumMacTable;
	RPC_ENUM_MAC_TABLE_ITEM *MacTables;
};

struct RPC_ENUM_IP_TABLE_ITEM {
	UINT Key;
	char SessionName[MAX_SESSION_NAME_LEN + 1];
	UINT Ip;
	IP IpV6;
	IP IpAddress;
	bool DhcpAllocated;
	UINT64 CreatedTime;
	UINT64 UpdatedTime;
};

struct RPC_ENUM_IP_TABLE {
	char HubName[MAX_HUBNAME_LEN + 1];
	UINT NumIpTable;
	RPC_ENUM_IP_TABLE_ITEM *IpTables;
};

struct RPC_DELETE_TABLE {
	char HubName[MAX_HUBNAME_LEN + 1];
	UINT Key;
};

struct RPC_ENUM_ETH_ITEM {
	char DeviceName[MAX_SIZE];
	wchar_t NetworkConnectionName[MAX_SIZE];
};

struct RPC_ENUM_ETH {
	UINT NumItem;
	RPC_ENUM_ETH_ITEM *Items;
};

struct RPC_LOCALBRIDGE {
	char DeviceName[MAX_SIZE];
	char HubName[MAX_HUBNAME_LEN + 1];
	bool Online;
	bool Active;
	bool TapMode;
};

struct RPC_ENUM_LOCALBRIDGE {
	UINT NumItem;
	RPC_LOCALBRIDGE *Items;
};

struct RPC_CONFIG {
	char FileName[MAX_PATH];
	char *FileData;
};

struct RPC_ADMIN_OPTION {
	char HubName[MAX_HUBNAME_LEN + 1];
	UINT NumItem;
	ADMIN_OPTION *Items;
};

struct RPC_CRL {
	char HubName[MAX_HUBNAME_LEN + 1];
	UINT Key;
	CRL *Crl;
};

struct RPC_ENUM_CRL_ITEM {
	UINT Key;
	wchar_t CrlInfo[MAX_SIZE];
};
struct RPC_ENUM_CRL {
	char HubName[MAX_HUBNAME_LEN + 1];
	UINT NumItem;
	RPC_ENUM_CRL_ITEM *Items;
};

struct RPC_AC_LIST {
	char HubName[MAX_HUBNAME_LEN + 1];
	LIST *o;
};

struct RPC_ENUM_LOG_FILE_ITEM {
	char FilePath[MAX_PATH];
	UINT FileSize;
	UINT64 UpdatedTime;
};
struct RPC_ENUM_LOG_FILE {
	UINT NumItem;
	RPC_ENUM_LOG_FILE_ITEM *Items;
};

struct RPC_READ_LOG_FILE {
	char FilePath[MAX_PATH];
	UINT Offset;
	BUF *Buffer;
};

struct DOWNLOAD_PROGRESS {
	UINT TotalSize;
	UINT CurrentSize;
	UINT ProgressPercent;
};


UINT AdminAccept(CONNECTION *c, PACK *p);
ADMIN *AdminOpen(SERVER *server, ADMIN_LOGIN *login, UINT *err);
PACK *AdminInvoke(ADMIN *a, char *name, PACK *p);
void AdminClose(ADMIN *a);
RPC *AdminConnectEx(CEDAR *cedar, CLIENT_OPTION *o, char *hubname, void *hashed_password, UINT *err, char *client_name);
void AdminDisconnect(RPC *rpc);
UINT AdminReconnect(RPC *rpc);
CAPSLIST *ScGetCapsEx(RPC *rpc);
typedef bool(DOWNLOAD_PROC)(DOWNLOAD_PROGRESS *progress);
BUF *DownloadFileFromServer(RPC *r, char *filepath, UINT total_size, DOWNLOAD_PROC *proc, void *param);

UINT ScGetServerInfo(RPC *r, RPC_SERVER_INFO *t);
UINT ScGetServerStatus(RPC *r, RPC_SERVER_STATUS *t);
UINT ScCreateListener(RPC *r, RPC_LISTENER *t);
UINT ScEnumListener(RPC *r, RPC_LISTENER_LIST *t);
UINT ScDeleteListener(RPC *r, RPC_LISTENER *t);
UINT ScEnableListener(RPC *r, RPC_LISTENER *t);
UINT ScGetHttpListener(RPC *r, RPC_HTTP_LISTENER *t);
UINT ScSetHttpListener(RPC *r, RPC_HTTP_LISTENER *t);
UINT ScSetServerPassword(RPC *r, RPC_SET_PASSWORD *t);
UINT ScSetServerCert(RPC *r, RPC_KEY_PAIR *t);
UINT ScGetServerCert(RPC *r, RPC_KEY_PAIR *t);
UINT ScGetServerCipherList(RPC *r, RPC_STR *t);
UINT ScGetServerCipher(RPC *r, RPC_STR *t);
UINT ScSetServerCipher(RPC *r, RPC_STR *t);
UINT ScCreateHub(RPC *r, RPC_CREATE_HUB *t);
UINT ScSetHub(RPC *r, RPC_CREATE_HUB *t);
UINT ScGetHub(RPC *r, RPC_CREATE_HUB *t);
UINT ScEnumHub(RPC *r, RPC_ENUM_HUB *t);
UINT ScDeleteHub(RPC *r, RPC_DELETE_HUB *t);
UINT ScEnumConnection(RPC *r, RPC_ENUM_CONNECTION *t);
UINT ScDisconnectConnection(RPC *r, RPC_DISCONNECT_CONNECTION *t);
UINT ScGetConnectionInfo(RPC *r, RPC_CONNECTION_INFO *t);
UINT ScSetHubOnline(RPC *r, RPC_SET_HUB_ONLINE *t);
UINT ScGetHubStatus(RPC *r, RPC_HUB_STATUS *t);
UINT ScSetHubLog(RPC *r, RPC_HUB_LOG *t);
UINT ScGetHubLog(RPC *r, RPC_HUB_LOG *t);
UINT ScAddCa(RPC *r, RPC_HUB_ADD_CA *t);
UINT ScEnumCa(RPC *r, RPC_HUB_ENUM_CA *t);
UINT ScGetCa(RPC *r, RPC_HUB_GET_CA *t);
UINT ScDeleteCa(RPC *r, RPC_HUB_DELETE_CA *t);
UINT ScCreateLink(RPC *r, RPC_CREATE_LINK *t);
UINT ScEnumLink(RPC *r, RPC_ENUM_LINK *t);
UINT ScGetLinkStatus(RPC *r, RPC_LINK_STATUS *t);
UINT ScSetLinkOnline(RPC *r, RPC_LINK *t);
UINT ScSetLinkOffline(RPC *r, RPC_LINK *t);
UINT ScDeleteLink(RPC *r, RPC_LINK *t);
UINT ScRenameLink(RPC *r, RPC_RENAME_LINK *t);
UINT ScAddAccess(RPC *r, RPC_ADD_ACCESS *t);
UINT ScDeleteAccess(RPC *r, RPC_DELETE_ACCESS *t);
UINT ScEnumAccess(RPC *r, RPC_ENUM_ACCESS_LIST *t);
UINT ScCreateUser(RPC *r, RPC_SET_USER *t);
UINT ScSetUser(RPC *r, RPC_SET_USER *t);
UINT ScGetUser(RPC *r, RPC_SET_USER *t);
UINT ScDeleteUser(RPC *r, RPC_DELETE_USER *t);
UINT ScEnumUser(RPC *r, RPC_ENUM_USER *t);
UINT ScCreateGroup(RPC *r, RPC_SET_GROUP *t);
UINT ScSetGroup(RPC *r, RPC_SET_GROUP *t);
UINT ScGetGroup(RPC *r, RPC_SET_GROUP *t);
UINT ScDeleteGroup(RPC *r, RPC_DELETE_USER *t);
UINT ScEnumGroup(RPC *r, RPC_ENUM_GROUP *t);
UINT ScEnumSession(RPC *r, RPC_ENUM_SESSION *t);
UINT ScGetSessionStatus(RPC *r, RPC_SESSION_STATUS *t);
UINT ScDeleteSession(RPC *r, RPC_DELETE_SESSION *t);
UINT ScEnumMacTable(RPC *r, RPC_ENUM_MAC_TABLE *t);
UINT ScDeleteMacTable(RPC *r, RPC_DELETE_TABLE *t);
UINT ScEnumIpTable(RPC *r, RPC_ENUM_IP_TABLE *t);
UINT ScDeleteIpTable(RPC *r, RPC_DELETE_TABLE *t);
UINT ScGetLink(RPC *a, RPC_CREATE_LINK *t);
UINT ScSetLink(RPC *a, RPC_CREATE_LINK *t);
UINT ScSetAccessList(RPC *r, RPC_ENUM_ACCESS_LIST *t);
UINT ScEnumEthernet(RPC *r, RPC_ENUM_ETH *t);
UINT ScAddLocalBridge(RPC *r, RPC_LOCALBRIDGE *t);
UINT ScDeleteLocalBridge(RPC *r, RPC_LOCALBRIDGE *t);
UINT ScEnumLocalBridge(RPC *r, RPC_ENUM_LOCALBRIDGE *t);
UINT ScRebootServer(RPC *r, RPC_TEST *t);
UINT ScGetConfig(RPC *r, RPC_CONFIG *t);
UINT ScSetConfig(RPC *r, RPC_CONFIG *t);
UINT ScGetHubAdminOptions(RPC *r, RPC_ADMIN_OPTION *t);
UINT ScSetHubAdminOptions(RPC *r, RPC_ADMIN_OPTION *t);
UINT ScGetHubExtOptions(RPC *r, RPC_ADMIN_OPTION *t);
UINT ScSetHubExtOptions(RPC *r, RPC_ADMIN_OPTION *t);
UINT ScEnumCrl(RPC *r, RPC_ENUM_CRL *t);
UINT ScAddCrl(RPC *r, RPC_CRL *t);
UINT ScDelCrl(RPC *r, RPC_CRL *t);
UINT ScGetCrl(RPC *r, RPC_CRL *t);
UINT ScSetAcList(RPC *r, RPC_AC_LIST *t);
UINT ScGetAcList(RPC *r, RPC_AC_LIST *t);
UINT ScEnumLogFile(RPC *r, RPC_ENUM_LOG_FILE *t);
UINT ScSetSysLog(RPC *r, SYSLOG_SETTING *t);
UINT ScGetSysLog(RPC *r, SYSLOG_SETTING *t);
UINT ScCrash(RPC *r, RPC_TEST *t);
UINT ScFlush(RPC *r, RPC_TEST *t);
UINT ScRegenerateServerCert(RPC *r, RPC_TEST *t);

void FreeRpcTest(RPC_TEST *t);
void FreeRpcServerInfo(RPC_SERVER_INFO *t);
void FreeRpcListenerList(RPC_LISTENER_LIST *t);
void FreeRpcStr(RPC_STR *t);
void FreeRpcEnumHub(RPC_ENUM_HUB *t);
void FreeRpcEnumConnection(RPC_ENUM_CONNECTION *t);
void FreeRpcHubAddCa(RPC_HUB_ADD_CA *t);
void FreeRpcHubEnumCa(RPC_HUB_ENUM_CA *t);
void FreeRpcHubGetCa(RPC_HUB_GET_CA *t);
void FreeRpcCreateLink(RPC_CREATE_LINK *t);
void FreeRpcEnumLink(RPC_ENUM_LINK *t);
void FreeRpcLinkStatus(RPC_LINK_STATUS *t);
void FreeRpcEnumAccessList(RPC_ENUM_ACCESS_LIST *a);
void FreeRpcSetUser(RPC_SET_USER *t);
void FreeRpcEnumUser(RPC_ENUM_USER *t);
void FreeRpcEnumGroup(RPC_ENUM_GROUP *t);
void InRpcEnumSession(RPC_ENUM_SESSION *t, PACK *p);
void OutRpcEnumSession(PACK *p, RPC_ENUM_SESSION *t);
void FreeRpcEnumSession(RPC_ENUM_SESSION *t);
void InRpcNodeInfo(NODE_INFO *t, PACK *p);
void OutRpcNodeInfo(PACK *p, NODE_INFO *t);
void FreeRpcSessionStatus(RPC_SESSION_STATUS *t);
void FreeRpcEnumMacTable(RPC_ENUM_MAC_TABLE *t);
void FreeRpcEnumIpTable(RPC_ENUM_IP_TABLE *t);
void FreeRpcKeyPair(RPC_KEY_PAIR *t);
void FreeRpcSetGroup(RPC_SET_GROUP *t);
void FreeRpcEnumEth(RPC_ENUM_ETH *t);
void FreeRpcEnumLocalBridge(RPC_ENUM_LOCALBRIDGE *t);
void FreeRpcConfig(RPC_CONFIG *t);
void FreeRpcAdminOption(RPC_ADMIN_OPTION *t);
void FreeRpcCrl(RPC_CRL *t);
void FreeRpcEnumCrl(RPC_ENUM_CRL *t);
void FreeRpcAcList(RPC_AC_LIST *t);
void FreeRpcEnumLogFile(RPC_ENUM_LOG_FILE *t);
void InRpcWinVer(RPC_WINVER *t, PACK *p);
void OutRpcWinVer(PACK *p, RPC_WINVER *t);
void InRpcEnumLogFile(RPC_ENUM_LOG_FILE *t, PACK *p);
void OutRpcEnumLogFile(PACK *p, RPC_ENUM_LOG_FILE *t);
void InRpcReadLogFile(RPC_READ_LOG_FILE *t, PACK *p);
void OutRpcReadLogFile(PACK *p, RPC_READ_LOG_FILE *t);
void FreeRpcReadLogFile(RPC_READ_LOG_FILE *t);
void InRpcAcList(RPC_AC_LIST *t, PACK *p);
void OutRpcAcList(PACK *p, RPC_AC_LIST *t);
void InRpcEnumCrl(RPC_ENUM_CRL *t, PACK *p);
void OutRpcEnumCrl(PACK *p, RPC_ENUM_CRL *t);
void InRpcCrl(RPC_CRL *t, PACK *p);
void OutRpcCrl(PACK *p, RPC_CRL *t);
void InRpcEnumEth(RPC_ENUM_ETH *t, PACK *p);
void OutRpcEnumEth(PACK *p, RPC_ENUM_ETH *t);
void InRpcLocalBridge(RPC_LOCALBRIDGE *t, PACK *p);
void OutRpcLocalBridge(PACK *p, RPC_LOCALBRIDGE *t);
void InRpcEnumLocalBridge(RPC_ENUM_LOCALBRIDGE *t, PACK *p);
void OutRpcEnumLocalBridge(PACK *p, RPC_ENUM_LOCALBRIDGE *t);
void InRpcAdminOption(RPC_ADMIN_OPTION *t, PACK *p);
void OutRpcAdminOption(PACK *p, RPC_ADMIN_OPTION *t);
void InRpcConfig(RPC_CONFIG *t, PACK *p);
void OutRpcConfig(PACK *p, RPC_CONFIG *t);
void InRpcAddAccess(RPC_ADD_ACCESS *t, PACK *p);
void OutRpcAddAccess(PACK *p, RPC_ADD_ACCESS *t);
void InRpcDeleteAccess(RPC_DELETE_ACCESS *t, PACK *p);
void OutRpcDeleteAccess(PACK *p, RPC_DELETE_ACCESS *t);
void InRpcServerInfo(RPC_SERVER_INFO *t, PACK *p);
void OutRpcServerInfo(PACK *p, RPC_SERVER_INFO *t);
void InRpcServerStatus(RPC_SERVER_STATUS *t, PACK *p);
void OutRpcServerStatus(PACK *p, RPC_SERVER_STATUS *t);
void InRpcListener(RPC_LISTENER *t, PACK *p);
void OutRpcListener(PACK *p, RPC_LISTENER *t);
void InRpcListenerList(RPC_LISTENER_LIST *t, PACK *p);
void OutRpcListenerList(PACK *p, RPC_LISTENER_LIST *t);
void InRpcHttpListener(RPC_HTTP_LISTENER *t, PACK *p);
void OutRpcHttpListener(PACK *p, RPC_HTTP_LISTENER *t);
void InRpcStr(RPC_STR *t, PACK *p);
void OutRpcStr(PACK *p, RPC_STR *t);
void InRpcSetPassword(RPC_SET_PASSWORD *t, PACK *p);
void OutRpcSetPassword(PACK *p, RPC_SET_PASSWORD *t);
void InRpcCreateHub(RPC_CREATE_HUB *t, PACK *p);
void OutRpcCreateHub(PACK *p, RPC_CREATE_HUB *t);
void InRpcEnumHub(RPC_ENUM_HUB *t, PACK *p);
void OutRpcEnumHub(PACK *p, RPC_ENUM_HUB *t);
void InRpcDeleteHub(RPC_DELETE_HUB *t, PACK *p);
void OutRpcDeleteHub(PACK *p, RPC_DELETE_HUB *t);
void InRpcEnumConnection(RPC_ENUM_CONNECTION *t, PACK *p);
void OutRpcEnumConnection(PACK *p, RPC_ENUM_CONNECTION *t);
void InRpcDisconnectConnection(RPC_DISCONNECT_CONNECTION *t, PACK *p);
void OutRpcDisconnectConnection(PACK *p, RPC_DISCONNECT_CONNECTION *t);
void InRpcConnectionInfo(RPC_CONNECTION_INFO *t, PACK *p);
void OutRpcConnectionInfo(PACK *p, RPC_CONNECTION_INFO *t);
void InRpcSetHubOnline(RPC_SET_HUB_ONLINE *t, PACK *p);
void OutRpcSetHubOnline(PACK *p, RPC_SET_HUB_ONLINE *t);
void InRpcHubStatus(RPC_HUB_STATUS *t, PACK *p);
void OutRpcHubStatus(PACK *p, RPC_HUB_STATUS *t);
void InRpcHubLog(RPC_HUB_LOG *t, PACK *p);
void OutRpcHubLog(PACK *p, RPC_HUB_LOG *t);
void InRpcHubAddCa(RPC_HUB_ADD_CA *t, PACK *p);
void OutRpcHubAddCa(PACK *p, RPC_HUB_ADD_CA *t);
void InRpcHubEnumCa(RPC_HUB_ENUM_CA *t, PACK *p);
void OutRpcHubEnumCa(PACK *p, RPC_HUB_ENUM_CA *t);
void InRpcHubGetCa(RPC_HUB_GET_CA *t, PACK *p);
void OutRpcHubGetCa(PACK *p, RPC_HUB_GET_CA *t);
void InRpcHubDeleteCa(RPC_HUB_DELETE_CA *t, PACK *p);
void OutRpcHubDeleteCa(PACK *p, RPC_HUB_DELETE_CA *t);
void InRpcCreateLink(RPC_CREATE_LINK *t, PACK *p);
void OutRpcCreateLink(PACK *p, RPC_CREATE_LINK *t);
void InRpcEnumLink(RPC_ENUM_LINK *t, PACK *p);
void OutRpcEnumLink(PACK *p, RPC_ENUM_LINK *t);
void InRpcLinkStatus(RPC_LINK_STATUS *t, PACK *p);
void OutRpcLinkStatus(PACK *p, RPC_LINK_STATUS *t);
void InRpcLink(RPC_LINK *t, PACK *p);
void OutRpcLink(PACK *p, RPC_LINK *t);
void InRpcRenameLink(RPC_RENAME_LINK *t, PACK *p);
void OutRpcRenameLink(PACK *p, RPC_RENAME_LINK *t);
void InRpcEnumAccessList(RPC_ENUM_ACCESS_LIST *a, PACK *p);
void OutRpcEnumAccessList(PACK *p, RPC_ENUM_ACCESS_LIST *a);
void InRpcSetUser(RPC_SET_USER *t, PACK *p);
void OutRpcSetUser(PACK *p, RPC_SET_USER *t);
void InRpcEnumUser(RPC_ENUM_USER *t, PACK *p);
void OutRpcEnumUser(PACK *p, RPC_ENUM_USER *t);
void InRpcSetGroup(RPC_SET_GROUP *t, PACK *p);
void OutRpcSetGroup(PACK *p, RPC_SET_GROUP *t);
void InRpcEnumGroup(RPC_ENUM_GROUP *t, PACK *p);
void OutRpcEnumGroup(PACK *p, RPC_ENUM_GROUP *t);
void InRpcDeleteUser(RPC_DELETE_USER *t, PACK *p);
void OutRpcDeleteUser(PACK *p, RPC_DELETE_USER *t);
void InRpcKeyPair(RPC_KEY_PAIR *t, PACK *p);
void OutRpcKeyPair(PACK *p, RPC_KEY_PAIR *t);
void InRpcSessionStatus(RPC_SESSION_STATUS *t, PACK *p);
void OutRpcSessionStatus(PACK *p, RPC_SESSION_STATUS *t);
void InRpcDeleteSession(RPC_DELETE_SESSION *t, PACK *p);
void OutRpcDeleteSession(PACK *p, RPC_DELETE_SESSION *t);
void InRpcEnumMacTable(RPC_ENUM_MAC_TABLE *t, PACK *p);
void OutRpcEnumMacTable(PACK *p, RPC_ENUM_MAC_TABLE *t);
void InRpcEnumIpTable(RPC_ENUM_IP_TABLE *t, PACK *p);
void OutRpcEnumIpTable(PACK *p, RPC_ENUM_IP_TABLE *t);
void InRpcDeleteTable(RPC_DELETE_TABLE *t, PACK *p);
void OutRpcDeleteTable(PACK *p, RPC_DELETE_TABLE *t);
void InRpcTest(RPC_TEST *t, PACK *p);
void OutRpcTest(PACK *p, RPC_TEST *t);
void InRpcClientOption(CLIENT_OPTION *c, PACK *p);
void OutRpcClientOption(PACK *p, CLIENT_OPTION *c);
void InRpcClientAuth(CLIENT_AUTH *c, PACK *p);
void OutRpcClientAuth(PACK *p, CLIENT_AUTH *c);
void InRpcPolicy(POLICY *o, PACK *p);
void OutRpcPolicy(PACK *p, POLICY *o);
void InRpcClientGetConnectionStatus(RPC_CLIENT_GET_CONNECTION_STATUS *s, PACK *p);
void OutRpcClientGetConnectionStatus(PACK *p, RPC_CLIENT_GET_CONNECTION_STATUS *c);
void InRpcTraffic(TRAFFIC *t, PACK *p);
void OutRpcTraffic(PACK *p, TRAFFIC *t);
void InRpcTrafficEx(TRAFFIC *t, PACK *p, UINT i);
void OutRpcTrafficEx(TRAFFIC *t, PACK *p, UINT i, UINT num);
PACK *AdminCall(RPC *rpc, char *function_name, PACK *p);

#endif


