// Server.h
// Header of Server.c

#ifndef	SERVER_H
#define	SERVER_H

#include "Account.h"

#define	SERVER_DEF_PORTS_1				443
#define	SERVER_DEF_PORTS_4				GC_DEFAULT_PORT

extern char *SERVER_CONFIG_FILE_NAME;
// An invalid cipher spec makes the server fall back to its built-in list of modern ciphers.
#define	SERVER_DEFAULT_CIPHER_NAME		"~DEFAULT~"
#define	SERVER_DEFAULT_HUB_NAME			"DEFAULT"

#define	SERVER_FILE_SAVE_INTERVAL_DEFAULT	(5 * 60 * 1000)
#define	SERVER_FILE_SAVE_INTERVAL_MIN		(5 * 1000)
#define	SERVER_FILE_SAVE_INTERVAL_MAX		(3600 * 1000)
#define	SERVER_FILE_SAVE_INTERVAL_USERMODE	(1 * 60 * 1000)

// A failed configuration save is retried after this span, doubled per failure up to the autosave span
#define	SERVER_FILE_SAVE_RETRY_MIN			(1 * 1000)
// Tries of the last save when the server stops
#define	SERVER_FILE_SAVE_FINAL_TRIES		3

#define SERVER_DEADLOCK_CHECK_SPAN		(2 * 60 * 1000)
#define SERVER_DEADLOCK_CHECK_TIMEOUT	(10 * 60 * 1000)


struct SERVER_LISTENER
{
	UINT Port;
	bool Enabled;
	LISTENER *Listener;
	bool DisableDos;
};

struct SYSLOG_SETTING
{
	UINT SaveType;
	char Hostname[MAX_HOST_NAME_LEN + 1];
	UINT Port;
};

struct SERVER
{
	LIST *ServerListenerList;
	UCHAR HashedPassword[SHA1_SIZE];
	UINT64 StartTime;
	UINT AutoSaveConfigSpan;
	UINT AutoSaveConfigSpanSaved;
	bool DontBackupConfig;
	bool BackupConfigOnlyWhenModified;
	UINT ConfigRevision;
	bool DisableDosProtection;
	UCHAR MyRandomKey[SHA1_SIZE];
	bool DisableDeadLockCheck;
	bool SaveDebugLog;
	bool NoSendSignature;
	bool UseWebTimePage;
	bool NoHighPriorityProcess;
	bool NoDebugDump;
	bool NoMoreSave;

	volatile bool Halt;
	LOCK *lock;
	REF *ref;
	CEDAR *Cedar;
	CFG_RW *CfgRw;
	LOCK *SaveCfgLock;
	bool ConfigSaveFailing;		// The last configuration save failed (under SaveCfgLock)
	EVENT *SaveHaltEvent;
	THREAD *SaveThread;
	LIST *HubCreateHistoryList;

	LOG *Logger;
	ERASER *Eraser;

	bool Led;
	bool LedSpecial;


	LOCK *SyslogLock;
	SYSLOG_SETTING SyslogSetting;
	SLOG *Syslog;

	THREAD *DeadLockCheckThread;
	volatile bool HaltDeadLockThread;
	EVENT *DeadLockWaitEvent;

	bool DisableGetHostNameWhenAcceptTcp;
	bool DisableCoreDumpOnUnix;

	TINY_LOG *DebugLog;

	bool IsInVm;



	IP ListenIP;
	bool StrictSyslogDatetimeFormat;
};


struct RPC_ENUM_SESSION
{
	char HubName[MAX_HUBNAME_LEN + 1];
	UINT NumSession;
	struct RPC_ENUM_SESSION_ITEM *Sessions;
};

struct RPC_SESSION_STATUS
{
	char HubName[MAX_HUBNAME_LEN + 1];
	char Name[MAX_SESSION_NAME_LEN + 1];
	char Username[MAX_USERNAME_LEN + 1];
	char RealUsername[MAX_USERNAME_LEN + 1];
	char GroupName[MAX_USERNAME_LEN + 1];
	RPC_CLIENT_GET_CONNECTION_STATUS Status;
	UINT ClientIp;
	UCHAR ClientIp6[16];
	IP ClientIpAddress;
	char ClientHostName[MAX_HOST_NAME_LEN + 1];
	NODE_INFO NodeInfo;
};


struct CAPS
{
	char *Name;
	UINT Value;
};
struct CAPSLIST
{
	LIST *CapsList;
};

struct LOG_FILE
{
	char Path[MAX_PATH];
	UINT FileSize;
	UINT64 UpdatedTime;
};


#define	NUM_GLOBAL_SERVER_FLAGS			128
#define	GSF_DISABLE_SESSION_RECONNECT	9

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



struct SERVER_HUB_CREATE_HISTORY
{
	char HubName[MAX_HUBNAME_LEN + 1];
	UINT64 CreatedTime;
};

SERVER *SiNewServer(void);
void SiReleaseServer(SERVER *s);
void StStartServer(void);
void StStopServer();
UINT SiWriteConfigurationFile(SERVER *s);
void SiGenerateDefaultCertEx(X **server_x, K **server_k, char *common_name);
void SiLockListenerList(SERVER *s);
void SiUnlockListenerList(SERVER *s);
bool SiAddListenerEx(SERVER *s, UINT port, bool enabled, bool disable_dos);
bool SiEnableListener(SERVER *s, UINT port);
bool SiDisableListener(SERVER *s, UINT port);
bool SiDeleteListener(SERVER *s, UINT port);
SERVER_LISTENER *SiGetListener(SERVER *s, UINT port);
void SiSetDefaultHubOption(HUB_OPTION *o);
FOLDER *SiWriteConfigurationToCfg(SERVER *s);
bool SiLoadConfigurationCfg(SERVER *s, FOLDER *root);
void SiLoadLocalBridges(SERVER *s, FOLDER *f);
void SiLoadListeners(SERVER *s, FOLDER *f);
void SiWriteServerCfg(FOLDER *f, SERVER *s);
void SiLoadServerCfg(SERVER *s, FOLDER *f);
void SiWriteMachineIdCfg(FOLDER *f, CEDAR *c);
void SiLoadMachineIdCfg(CEDAR *c, FOLDER *f);
void SiLoadGlobalParamsCfg(FOLDER *f);
void SiLoadGlobalParamItem(UINT id, UINT value);
void SiWriteTraffic(FOLDER *parent, char *name, TRAFFIC *t);
void SiWriteTrafficInner(FOLDER *parent, char *name, TRAFFIC_ENTRY *e);
void SiLoadTrafficInner(FOLDER *parent, char *name, TRAFFIC_ENTRY *e);
void SiLoadTraffic(FOLDER *parent, char *name, TRAFFIC *t);
void SiSaverThread(THREAD *thread, void *param);
void SiWriteHubs(FOLDER *f, SERVER *s);
void SiLoadHubs(SERVER *s, FOLDER *f);
void SiWriteHubLogCfgEx(FOLDER *f, HUB_LOG *g, bool el_mode);
void SiRebootServerEx(bool reset_setting);
void StInit();
void StFree();
int CmpLogFile(void *p1, void *p2);
LIST *EnumLogFile(char *hubname);
void EnumLogFileDir(LIST *o, char *dirname);
void FreeEnumLogFile(LIST *o);
bool CheckLogFileNameFromEnumList(LIST *o, char *name);
void IncrementServerConfigRevision(SERVER *s);
UINT SiStageConfiguration(SERVER *s, char *data, UINT size);
void GetServerProductName(SERVER *s, char *name, UINT size);


void SiSetSysLogSetting(SERVER *s, SYSLOG_SETTING *setting);
void SiGetSysLogSetting(SERVER *s, SYSLOG_SETTING *setting);
void SiWriteSysLog(SERVER *s, char *typestr, char *hubname, wchar_t *message);
UINT SiGetSysLogSaveStatus(SERVER *s);
void SiDebugLog(SERVER *s, char *msg);

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

void GetServerCapsMain(SERVER *s, CAPSLIST *t);

void SetGlobalServerFlag(UINT index, UINT value);
UINT GetGlobalServerFlag(UINT index);

#endif



