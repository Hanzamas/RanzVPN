// SoftEther VPN Source Code - Developer Edition Master Branch
// Cedar Communication Module


// Server.h
// Header of Server.c

#ifndef	SERVER_H
#define	SERVER_H

#include "Account.h"
#include "Wpc.h"

// Default ports
#define	SERVER_DEF_PORTS_1				443
#define	SERVER_DEF_PORTS_4				GC_DEFAULT_PORT

extern char *SERVER_CONFIG_FILE_NAME;
// This is set to an invalid OpenSSL cipher specification by default.
// The server will default to a list of sane and secure modern ciphers.
#define	SERVER_DEFAULT_CIPHER_NAME		"~DEFAULT~"
#define	SERVER_DEFAULT_HUB_NAME			"DEFAULT"
#define	SERVER_DEFAULT_BRIDGE_NAME		"BRIDGE"

#define	SERVER_FILE_SAVE_INTERVAL_DEFAULT	(5 * 60 * 1000)
#define	SERVER_FILE_SAVE_INTERVAL_MIN		(5 * 1000)
#define	SERVER_FILE_SAVE_INTERVAL_MAX		(3600 * 1000)
#define	SERVER_FILE_SAVE_INTERVAL_USERMODE	(1 * 60 * 1000)

#define SERVER_DEADLOCK_CHECK_SPAN		(2 * 60 * 1000)
#define SERVER_DEADLOCK_CHECK_TIMEOUT	(10 * 60 * 1000)


// Server listener
struct SERVER_LISTENER
{
	UINT Port;							// Port number
	bool Enabled;						// Active flag
	LISTENER *Listener;					// Listener object
	bool DisableDos;					// Disable the DoS detection
};

// Syslog configuration
struct SYSLOG_SETTING
{
	UINT SaveType;							// Save type
	char Hostname[MAX_HOST_NAME_LEN + 1];	// Host name
	UINT Port;								// Port number
};

// Server object
struct SERVER
{
	LIST *ServerListenerList;			// Server listener list
	UCHAR HashedPassword[SHA1_SIZE];	// Password
	UINT64 StartTime;					// Start-up time
	UINT AutoSaveConfigSpan;			// Auto save interval
	UINT AutoSaveConfigSpanSaved;		// Auto save interval (stored value)
	bool DontBackupConfig;				// Do not save a backup of the configuration automatically
	bool BackupConfigOnlyWhenModified;	// Save a backup of the configuration only if there is a modification
	UINT ConfigRevision;				// Configuration file revision
	bool DisableDosProtection;			// Disable the DoS attack protection
	UCHAR MyRandomKey[SHA1_SIZE];		// Their own random key
	bool DisableDeadLockCheck;			// Disable the deadlock check
	bool SaveDebugLog;					// Save the debug log
	bool NoSendSignature;				// Let the client not to send a signature
	bool UseWebTimePage;				// Use WebTimePage
	bool NoLinuxArpFilter;				// Not to set arp_filter in Linux
	bool NoHighPriorityProcess;			// Not to raise the priority of the process
	bool NoDebugDump;					// Not to output the debug dump
	bool NoMoreSave;					// Do not save any more
	bool EnableConditionalAccept;		// Apply the Conditional Accept the Listener

	volatile bool Halt;					// Halting flag
	LOCK *lock;							// Lock
	REF *ref;							// Reference counter
	CEDAR *Cedar;						// Cedar
	CFG_RW *CfgRw;						// Configuration file R/W
	LOCK *SaveCfgLock;					// Settings saving lock
	EVENT *SaveHaltEvent;				// Saving thread halting event
	THREAD *SaveThread;					// Settings saving thread
	LIST *HubCreateHistoryList;			// Virtual HUB creation history list

	LOG *Logger;						// Server logger
	ERASER *Eraser;						// Eraser

	bool Led;							// Use the LED display board
	bool LedSpecial;					// LED Special

	UINT CurrentAssignedClientLicense;	// Current number of assigned client licenses
	UINT CurrentAssignedBridgeLicense;	// Current number of assigned bridge license


	LOCK *SyslogLock;					// The lock of the syslog configuration
	SYSLOG_SETTING SyslogSetting;		// Syslog configuration
	SLOG *Syslog;						// Syslog object

	LOCK *CapsCacheLock;				// Lock for Caps cache
	CAPSLIST *CapsListCache;			// Caps cache

	THREAD *DeadLockCheckThread;		// Deadlock check thread
	volatile bool HaltDeadLockThread;	// Halting flag
	EVENT *DeadLockWaitEvent;			// Waiting Event

	bool DisableGetHostNameWhenAcceptTcp;	// Disable GetHostName when accepting TCP
	bool DisableCoreDumpOnUnix;			// Disable core dump on UNIX

	TINY_LOG *DebugLog;					// Debug log

	bool IsInVm;						// Whether I'm within the VM



	IP ListenIP;						// Listen IP
	bool StrictSyslogDatetimeFormat;	// Make syslog datetime format strict RFC3164
};


// Enumerate sessions *
struct RPC_ENUM_SESSION
{
	char HubName[MAX_HUBNAME_LEN + 1];				// HUB Name
	UINT NumSession;								// Number of sessions
	struct RPC_ENUM_SESSION_ITEM *Sessions;			// Session list
};

// Session status *
struct RPC_SESSION_STATUS
{
	char HubName[MAX_HUBNAME_LEN + 1];				// HUB Name
	char Name[MAX_SESSION_NAME_LEN + 1];			// Session name
	char Username[MAX_USERNAME_LEN + 1];			// User name
	char RealUsername[MAX_USERNAME_LEN + 1];		// Real user name
	char GroupName[MAX_USERNAME_LEN + 1];			// Group name
	bool LinkMode;									// Link mode
	RPC_CLIENT_GET_CONNECTION_STATUS Status;		// Status
	UINT ClientIp;									// Client IP address
	UCHAR ClientIp6[16];							// Client IPv6 address
	IP ClientIpAddress;								// Client IP address (IPv4/IPv6)
	char ClientHostName[MAX_HOST_NAME_LEN + 1];		// Client host name
	NODE_INFO NodeInfo;								// Node information
};


// Caps related
struct CAPS
{
	char *Name;							// Name
	UINT Value;							// Value
};
struct CAPSLIST
{
	LIST *CapsList;						// Caps list
};

// Log file
struct LOG_FILE
{
	char Path[MAX_PATH];				// Path name
	UINT FileSize;						// File size
	UINT64 UpdatedTime;					// Updating date
};


// Global server flags
#define	NUM_GLOBAL_SERVER_FLAGS			128
#define	GSF_DISABLE_RADIUS_AUTH			2
#define	GSF_DISABLE_CERT_AUTH			3
#define	GSF_DISABLE_DEEP_LOGGING		4
#define	GSF_DISABLE_AC					5
#define	GSF_DISABLE_SYSLOG				6
#define	GSF_SHOW_OSS_MSG				7
#define	GSF_DISABLE_SESSION_RECONNECT	9

// Global parameters
#define	NUM_GLOBAL_PARAMS					128
#define	GP_MAX_SEND_SOCKET_QUEUE_SIZE		1
#define	GP_MIN_SEND_SOCKET_QUEUE_SIZE		2
#define	GP_MAX_SEND_SOCKET_QUEUE_NUM		3
#define	GP_SELECT_TIME						4
#define	GP_SELECT_TIME_FOR_NAT				5
#define	GP_MAX_STORED_QUEUE_NUM				6
#define	GP_MAX_BUFFERING_PACKET_SIZE		7
#define	GP_HUB_ARP_SEND_INTERVAL			8
#define	GP_MAC_TABLE_EXPIRE_TIME			9
#define	GP_IP_TABLE_EXPIRE_TIME				10
#define	GP_IP_TABLE_EXPIRE_TIME_DHCP		11
#define	GP_STORM_CHECK_SPAN					12
#define	GP_STORM_DISCARD_VALUE_START		13
#define	GP_STORM_DISCARD_VALUE_END			14
#define	GP_MAX_MAC_TABLES					15
#define	GP_MAX_IP_TABLES					16
#define	GP_MAX_HUB_LINKS					17
#define	GP_MEM_FIFO_REALLOC_MEM_SIZE		18
#define	GP_QUEUE_BUDGET						19
#define	GP_FIFO_BUDGET						20

extern UINT vpn_global_parameters[NUM_GLOBAL_PARAMS];

#define	VPN_GP(id, default_value)	((UINT)(vpn_global_parameters[(id)] != 0 ? vpn_global_parameters[(id)] : (default_value)))



// Virtual HUB creation history
struct SERVER_HUB_CREATE_HISTORY
{
	char HubName[MAX_HUBNAME_LEN + 1];
	UINT64 CreatedTime;
};

// Function prototype declaration
SERVER *SiNewServer(bool bridge);
SERVER *SiNewServerEx(bool bridge, bool in_client_inner_server, bool relay_server);
void SiReleaseServer(SERVER *s);
void SiCleanupServer(SERVER *s);
void StStartServer(bool bridge);
void StStopServer();
void SiInitConfiguration(SERVER *s);
void SiFreeConfiguration(SERVER *s);
UINT SiWriteConfigurationFile(SERVER *s);
void SiLoadInitialConfiguration(SERVER *s);
bool SiLoadConfigurationFile(SERVER *s);
bool SiLoadConfigurationFileMain(SERVER *s, FOLDER *root);
void SiInitDefaultServerCert(SERVER *s);
void SiInitCipherName(SERVER *s);
void SiGenerateDefaultCertEx(X **server_x, K **server_k, char *common_name);
void SiInitListenerList(SERVER *s);
void SiLockListenerList(SERVER *s);
void SiUnlockListenerList(SERVER *s);
bool SiAddListener(SERVER *s, UINT port, bool enabled);
bool SiAddListenerEx(SERVER *s, UINT port, bool enabled, bool disable_dos);
bool SiEnableListener(SERVER *s, UINT port);
bool SiDisableListener(SERVER *s, UINT port);
bool SiDeleteListener(SERVER *s, UINT port);
SERVER_LISTENER *SiGetListener(SERVER *s, UINT port);
int CompareServerListener(void *p1, void *p2);
void SiStopAllListener(SERVER *s);
void SiInitDefaultHubList(SERVER *s);
void SiSetDefaultHubOption(HUB_OPTION *o);
FOLDER *SiWriteConfigurationToCfg(SERVER *s);
bool SiLoadConfigurationCfg(SERVER *s, FOLDER *root);
void SiWriteLocalBridges(FOLDER *f, SERVER *s);
void SiLoadLocalBridges(SERVER *s, FOLDER *f);
void SiWriteLocalBridgeCfg(FOLDER *f, LOCALBRIDGE *br);
void SiLoadLocalBridgeCfg(SERVER *s, FOLDER *f);
void SiWriteListeners(FOLDER *f, SERVER *s);
void SiLoadListeners(SERVER *s, FOLDER *f);
void SiWriteListenerCfg(FOLDER *f, SERVER_LISTENER *r);
void SiLoadListenerCfg(SERVER *s, FOLDER *f);
void SiWriteServerCfg(FOLDER *f, SERVER *s);
void SiLoadServerCfg(SERVER *s, FOLDER *f);
void SiWriteGlobalParamsCfg(FOLDER *f);
void SiLoadGlobalParamsCfg(FOLDER *f);
void SiLoadGlobalParamItem(UINT id, UINT value);
void SiWriteTraffic(FOLDER *parent, char *name, TRAFFIC *t);
void SiWriteTrafficInner(FOLDER *parent, char *name, TRAFFIC_ENTRY *e);
void SiLoadTrafficInner(FOLDER *parent, char *name, TRAFFIC_ENTRY *e);
void SiLoadTraffic(FOLDER *parent, char *name, TRAFFIC *t);
void SiSaverThread(THREAD *thread, void *param);
void SiLoadLicenseManager(SERVER *s, FOLDER *f);
void SiWriteLicenseManager(FOLDER *f, SERVER *s);
void SiWriteHubs(FOLDER *f, SERVER *s);
void SiLoadHubs(SERVER *s, FOLDER *f);
void SiWriteHubCfg(FOLDER *f, HUB *h);
void SiLoadHubCfg(SERVER *s, FOLDER *f, char *name);
void SiLoadHubLogCfg(HUB_LOG *g, FOLDER *f);
void SiWriteHubOptionCfg(FOLDER *f, HUB_OPTION *o);
void SiWriteHubLogCfgEx(FOLDER *f, HUB_LOG *g, bool el_mode);
void SiLoadHubOptionCfg(FOLDER *f, HUB_OPTION *o);
void SiWriteHubLinks(FOLDER *f, HUB *h);
void SiLoadHubLinks(HUB *h, FOLDER *f);
void SiWriteHubAdminOptions(FOLDER *f, HUB *h);
void SiLoadHubAdminOptions(HUB *h, FOLDER *f);
void SiWriteHubLinkCfg(FOLDER *f, LINK *k);
void SiLoadHubLinkCfg(FOLDER *f, HUB *h);
void SiWriteHubAccessLists(FOLDER *f, HUB *h);
void SiLoadHubAccessLists(HUB *h, FOLDER *f);
void SiWriteHubAccessCfg(FOLDER *f, ACCESS *a);
void SiLoadHubAccessCfg(HUB *h, FOLDER *f);
void SiWriteHubDb(FOLDER *f, HUBDB *db, bool no_save_ac_list);
void SiLoadHubDb(HUB *h, FOLDER *f);
void SiWriteUserList(FOLDER *f, LIST *o);
void SiLoadUserList(HUB *h, FOLDER *f);
void SiWriteUserCfg(FOLDER *f, USER *u);
void SiLoadUserCfg(HUB *h, FOLDER *f);
void SiWriteGroupList(FOLDER *f, LIST *o);
void SiLoadGroupList(HUB *h, FOLDER *f);
void SiWriteGroupCfg(FOLDER *f, USERGROUP *g);
void SiLoadGroupCfg(HUB *h, FOLDER *f);
void SiWriteCertList(FOLDER *f, LIST *o);
void SiLoadCertList(LIST *o, FOLDER *f);
void SiWriteCrlList(FOLDER *f, LIST *o);
void SiLoadCrlList(LIST *o, FOLDER *f);
void SiWriteAcList(FOLDER *f, LIST *o);
void SiLoadAcList(LIST *o, FOLDER *f);
void SiWritePolicyCfg(FOLDER *f, POLICY *p, bool cascade_mode);
void SiLoadPolicyCfg(POLICY *p, FOLDER *f);
void SiRebootServerEx(bool bridge, bool reset_setting);
void SiRebootServer(bool bridge);
void SiRebootServerThread(THREAD *thread, void *param);
void StInit();
void StFree();
int CmpLogFile(void *p1, void *p2);
LIST *EnumLogFile(char *hubname);
void EnumLogFileDir(LIST *o, char *dirname);
void FreeEnumLogFile(LIST *o);
bool CheckLogFileNameFromEnumList(LIST *o, char *name);
void IncrementServerConfigRevision(SERVER *s);
void GetServerProductName(SERVER *s, char *name, UINT size);
void GetServerProductNameInternal(SERVER *s, char *name, UINT size);


void SiSetSysLogSetting(SERVER *s, SYSLOG_SETTING *setting);
void SiGetSysLogSetting(SERVER *s, SYSLOG_SETTING *setting);
void SiWriteSysLog(SERVER *s, char *typestr, char *hubname, wchar_t *message);
UINT SiGetSysLogSaveStatus(SERVER *s);
void SiInitDeadLockCheck(SERVER *s);
void SiFreeDeadLockCheck(SERVER *s);
void SiDeadLockCheckThread(THREAD *t, void *param);
void SiCheckDeadLockMain(SERVER *s, UINT timeout);
void SiDebugLog(SERVER *s, char *msg);
UINT SiDebug(SERVER *s, RPC_TEST *ret, UINT i, char *str);
UINT SiDebugProcHelloWorld(SERVER *s, char *in_str, char *ret_str, UINT ret_str_size);
UINT SiDebugProcExit(SERVER *s, char *in_str, char *ret_str, UINT ret_str_size);
UINT SiDebugProcDump(SERVER *s, char *in_str, char *ret_str, UINT ret_str_size);
UINT SiDebugProcRestorePriority(SERVER *s, char *in_str, char *ret_str, UINT ret_str_size);
UINT SiDebugProcSetHighPriority(SERVER *s, char *in_str, char *ret_str, UINT ret_str_size);
UINT SiDebugProcGetExeFileName(SERVER *s, char *in_str, char *ret_str, UINT ret_str_size);
UINT SiDebugProcCrash(SERVER *s, char *in_str, char *ret_str, UINT ret_str_size);
UINT SiDebugProcGetCurrentTcpSendQueueLength(SERVER *s, char *in_str, char *ret_str, UINT ret_str_size);
UINT SiDebugProcGetCurrentGetIPThreadCount(SERVER *s, char *in_str, char *ret_str, UINT ret_str_size);

typedef UINT (SI_DEBUG_PROC)(SERVER *s, char *in_str, char *ret_str, UINT ret_str_size);

CAPS *NewCaps(char *name, UINT value);
void FreeCaps(CAPS *c);
CAPSLIST *NewCapsList();
int CompareCaps(void *p1, void *p2);
void AddCaps(CAPSLIST *caps, CAPS *c);
CAPS *GetCaps(CAPSLIST *caps, char *name);
void FreeCapsList(CAPSLIST *caps);
bool GetCapsBool(CAPSLIST *caps, char *name);
UINT GetCapsInt(CAPSLIST *caps, char *name);
void AddCapsBool(CAPSLIST *caps, char *name, bool b);
void AddCapsInt(CAPSLIST *caps, char *name, UINT i);
void InRpcCapsList(CAPSLIST *t, PACK *p);
void OutRpcCapsList(PACK *p, CAPSLIST *t);
void FreeRpcCapsList(CAPSLIST *t);
void InitCapsList(CAPSLIST *t);
void InRpcSysLogSetting(SYSLOG_SETTING *t, PACK *p);
void OutRpcSysLogSetting(PACK *p, SYSLOG_SETTING *t);

void GetServerCaps(SERVER *s, CAPSLIST *t);
void FlushServerCaps(SERVER *s);
bool GetServerCapsBool(SERVER *s, char *name);
UINT GetServerCapsInt(SERVER *s, char *name);
void GetServerCapsMain(SERVER *s, CAPSLIST *t);
void InitServerCapsCache(SERVER *s);
void FreeServerCapsCache(SERVER *s);
void DestroyServerCapsCache(SERVER *s);

void SetGlobalServerFlag(UINT index, UINT value);
UINT GetGlobalServerFlag(UINT index);
void UpdateGlobalServerFlags(SERVER *s, CAPSLIST *t);


bool IsAdminPackSupportedServerProduct(char *name);

void SiInitHubCreateHistory(SERVER *s);
void SiFreeHubCreateHistory(SERVER *s);

bool SiTooManyUserObjectsInServer(SERVER *s, bool oneMore);

void SiUpdateCurrentRegion(CEDAR *c, char *region, bool force_update);
void SiGetCurrentRegion(CEDAR *c, char *region, UINT region_size);
bool SiIsEnterpriseFunctionsRestrictedOnOpenSource(CEDAR *c);

#endif	// SERVER_H



