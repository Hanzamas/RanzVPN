// Server.h
// Header of Server.c

#ifndef SERVER_H
#define SERVER_H

#include "Account.h"
#include "Eraser.h"
#include "LogWriter.h"
#include "Syslog.h"

#define SERVER_DEF_PORTS_1 443
#define SERVER_DEF_PORTS_4 GC_DEFAULT_PORT

extern char *SERVER_CONFIG_FILE_NAME;

#define SERVER_FILE_SAVE_INTERVAL_DEFAULT  (5 * 60 * 1000)
#define SERVER_FILE_SAVE_INTERVAL_MIN      (5 * 1000)
#define SERVER_FILE_SAVE_INTERVAL_MAX      (3600 * 1000)
#define SERVER_FILE_SAVE_INTERVAL_USERMODE (1 * 60 * 1000)

// A failed configuration save is retried after this span, doubled per failure up to the autosave span
#define SERVER_FILE_SAVE_RETRY_MIN (1 * 1000)
// Tries of the last save when the server stops
#define SERVER_FILE_SAVE_FINAL_TRIES 3

#define SERVER_DEADLOCK_CHECK_SPAN    (2 * 60 * 1000)
#define SERVER_DEADLOCK_CHECK_TIMEOUT (10 * 60 * 1000)


struct SERVER_LISTENER {
	UINT Port;
	bool Enabled;
	LISTENER *Listener;
	bool DisableDos;
};

// One listener as the admin RPCs report it, copied by SiEnumListeners under the listener list lock
struct SERVER_LISTENER_INFO {
	UINT Port;
	bool Enabled;
	bool Trying; // Enabled, and the port is not bound yet
};

struct SYSLOG_SETTING {
	UINT SaveType;
	char Hostname[MAX_HOST_NAME_LEN + 1];
	UINT Port;
};

struct SERVER {
	LIST *ServerListenerList;
	bool HttpListenerEnabled; // The HTTP listener setting (ServerHttpListener.c), under the listener list lock
	UINT HttpListenerPort;
	LISTENER *HttpListener; // NULL while it is off
	UCHAR HashedPassword[SHA1_SIZE];
	UINT64 StartTime;
	UINT AutoSaveConfigSpan;
	UINT AutoSaveConfigSpanSaved;
	bool DontBackupConfig;
	bool BackupConfigOnlyWhenModified;
	UINT ConfigRevision;
	bool DisableDosProtection;
	bool DisableDeadLockCheck;
	bool SaveDebugLog;
	bool NoSendSignature;
	bool NoHighPriorityProcess;
	bool NoMoreSave;

	volatile bool Halt;
	LOCK *lock;
	CEDAR *Cedar;
	CFG_RW *CfgRw;
	LOCK *SaveCfgLock;
	bool ConfigSaveFailing; // The last configuration save failed (under SaveCfgLock)
	EVENT *SaveHaltEvent;
	THREAD *SaveThread;

	LOG *Logger;
	ERASER *Eraser;

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


struct RPC_ENUM_SESSION {
	char HubName[MAX_HUBNAME_LEN + 1];
	UINT NumSession;
	struct RPC_ENUM_SESSION_ITEM *Sessions;
};

struct RPC_SESSION_STATUS {
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


struct CAPS {
	char *Name;
	UINT Value;
};
struct CAPSLIST {
	LIST *CapsList;
};


SERVER *SiNewServer(void);
void SiReleaseServer(SERVER *s);
void StStartServer(void);
void StStopServer();
UINT SiWriteConfigurationFile(SERVER *s);
bool SiGenerateDefaultCertEx(X **server_x, K **server_k, char *common_name);
void SiLockListenerList(SERVER *s);
void SiUnlockListenerList(SERVER *s);
bool SiAddListenerEx(SERVER *s, UINT port, bool enabled, bool disable_dos);
bool SiEnableListener(SERVER *s, UINT port);
bool SiDisableListener(SERVER *s, UINT port);
bool SiDeleteListener(SERVER *s, UINT port);
SERVER_LISTENER *SiGetListener(SERVER *s, UINT port);
SERVER_LISTENER_INFO *SiEnumListeners(SERVER *s, UINT *num);
UINT SiSetHttpListener(SERVER *s, bool enabled, UINT port);
void SiGetHttpListener(SERVER *s, bool *enabled, UINT *port, bool *listening);
FOLDER *SiWriteConfigurationToCfg(SERVER *s);
void SiWriteMachineIdCfg(FOLDER *f, CEDAR *c);
void SiLoadMachineIdCfg(CEDAR *c, FOLDER *f);
void SiRebootServerEx(bool reset_setting);
void StInit();
void StFree();
void IncrementServerConfigRevision(SERVER *s);
UINT SiStageConfiguration(SERVER *s, char *data, UINT size);


bool SiIsSysLogSaveType(UINT save_type);
void SiSetSysLogSetting(SERVER *s, SYSLOG_SETTING *setting);
void SiDebugLog(SERVER *s, char *msg);

CAPS *GetCaps(CAPSLIST *caps, char *name);
void FreeCapsList(CAPSLIST *caps);
bool GetCapsBool(CAPSLIST *caps, char *name);
void AddCapsBool(CAPSLIST *caps, char *name, bool b);
void AddCapsInt(CAPSLIST *caps, char *name, UINT i);
void InRpcCapsList(CAPSLIST *t, PACK *p);
void OutRpcCapsList(PACK *p, CAPSLIST *t);
void FreeRpcCapsList(CAPSLIST *t);
void InitCapsList(CAPSLIST *t);
void InRpcSysLogSetting(SYSLOG_SETTING *t, PACK *p);
void OutRpcSysLogSetting(PACK *p, SYSLOG_SETTING *t);

void GetServerCapsMain(SERVER *s, CAPSLIST *t);

#endif



