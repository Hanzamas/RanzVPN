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

#define	SERVER_DEF_PORTS_INCLIENT_1		995
#define	SERVER_DEF_PORTS_INCLIENT_2		465
#define	SERVER_DEF_PORTS_INCLIENT_3		9008	// for admin (in client)
#define	SERVER_DEF_PORTS_INCLIENT_4		1195

#define	SERVER_DEF_PORTS_INCLIENT_DYN_MIN	1201
#define	SERVER_DEF_PORTS_INCLIENT_DYN_MAX	1999

extern char *SERVER_CONFIG_FILE_NAME;
// This is set to an invalid OpenSSL cipher specification by default.
// The server will default to a list of sane and secure modern ciphers.
#define	SERVER_DEFAULT_CIPHER_NAME		"~DEFAULT~"
#define	SERVER_DEFAULT_CERT_DAYS		(365 * 10)
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
	bool EnableLegacySSL;				// Enable Legacy SSL

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
	UINT LicenseHash;					// Hash value of the license list

	bool SnapshotInited;
	EVENT *SnapshotHaltEvent;			// Snapshot halting event
	volatile bool HaltSnapshot;			// Snapshot halting flag
	THREAD *SnapshotThread;				// Snapshot thread
	LOG *SnapshotLogger;				// Snapshot logger
	UINT64 LastSnapshotTime;			// Time that the last snapshot created

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
void SiReleaseServer(SERVER *s);
void StStartServer(bool bridge);
void StStopServer();
UINT SiWriteConfigurationFile(SERVER *s);
void SiGenerateDefaultCertEx(X **server_x, K **server_k, char *common_name);
void SiLockListenerList(SERVER *s);
void SiUnlockListenerList(SERVER *s);
bool SiAddListener(SERVER *s, UINT port, bool enabled);
bool SiAddListenerEx(SERVER *s, UINT port, bool enabled, bool disable_dos);
bool SiEnableListener(SERVER *s, UINT port);
bool SiDisableListener(SERVER *s, UINT port);
bool SiDeleteListener(SERVER *s, UINT port);
void SiSetDefaultHubOption(HUB_OPTION *o);
FOLDER *SiWriteConfigurationToCfg(SERVER *s);
void SiRebootServerEx(bool bridge, bool reset_setting);
void SiRebootServer(bool bridge);
void StInit();
void StFree();
int CmpLogFile(void *p1, void *p2);
LIST *EnumLogFile(char *hubname);
void FreeEnumLogFile(LIST *o);
bool CheckLogFileNameFromEnumList(LIST *o, char *name);
void IncrementServerConfigRevision(SERVER *s);
void GetServerProductName(SERVER *s, char *name, UINT size);


void SiSetSysLogSetting(SERVER *s, SYSLOG_SETTING *setting);
void SiGetSysLogSetting(SERVER *s, SYSLOG_SETTING *setting);
void SiWriteSysLog(SERVER *s, char *typestr, char *hubname, wchar_t *message);
UINT SiGetSysLogSaveStatus(SERVER *s);
void SiDebugLog(SERVER *s, char *msg);
UINT SiDebug(SERVER *s, RPC_TEST *ret, UINT i, char *str);

typedef UINT (SI_DEBUG_PROC)(SERVER *s, char *in_str, char *ret_str, UINT ret_str_size);

CAPSLIST *NewCapsList();
CAPS *GetCaps(CAPSLIST *caps, char *name);
void FreeCapsList(CAPSLIST *caps);
bool GetCapsBool(CAPSLIST *caps, char *name);
void AddCapsBool(CAPSLIST *caps, char *name, bool b);
void AddCapsInt(CAPSLIST *caps, char *name, UINT i);
void InRpcCapsList(CAPSLIST *t, PACK *p);
void OutRpcCapsList(PACK *p, CAPSLIST *t);
void FreeRpcCapsList(CAPSLIST *t);
void InRpcSysLogSetting(SYSLOG_SETTING *t, PACK *p);
void OutRpcSysLogSetting(PACK *p, SYSLOG_SETTING *t);

bool GetServerCapsBool(SERVER *s, char *name);
UINT GetServerCapsInt(SERVER *s, char *name);
void GetServerCapsMain(SERVER *s, CAPSLIST *t);

UINT GetGlobalServerFlag(UINT index);


bool IsAdminPackSupportedServerProduct(char *name);

bool SiTooManyUserObjectsInServer(SERVER *s, bool oneMore);

#endif	// SERVER_H



