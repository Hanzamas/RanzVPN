// Microsoft.h
// Header of Microsoft.c

#ifndef	MICROSOFT_H
#define	MICROSOFT_H

#include "Network.h"

#define	SVC_ARG_INSTALL				"/install"
#define	SVC_ARG_UNINSTALL			"/uninstall"
#define	SVC_ARG_START				"/start"
#define	SVC_ARG_STOP				"/stop"
#define	SVC_ARG_TEST				"/test"
#define	SVC_ARG_USERMODE			"/usermode"
#define	SVC_ARG_USERMODE_SHOWTRAY	"/usermode_showtray"
#define	SVC_ARG_USERMODE_HIDETRAY	"/usermode_hidetray"
#define	SVC_ARG_SERVICE				"/service"
#define	SVC_ARG_SETUP_INSTALL		"/setup_install"
#define	SVC_ARG_SETUP_UNINSTALL		"/setup_uninstall"
#define SVC_ARG_SILENT				"/silent"

// Self-kill timeout if the service freezes
#define	SVC_SELFKILL_TIMEOUT		(5 * 60 * 1000)

// Event IDs of the service entries in the Application event log, under the service name as source
#define	MS_EVENT_SERVICE_STARTED	1
#define	MS_EVENT_SERVICE_STOPPED	2
#define	MS_EVENT_SERVICE_FAILED		3

#define	SVC_RUN_COMMANDLINE			L"\"%s\" /service"

#define	SVC_MODE_NONE				0
#define	SVC_MODE_INSTALL			1
#define	SVC_MODE_UNINSTALL			2
#define	SVC_MODE_START				3
#define	SVC_MODE_STOP				4
#define	SVC_MODE_TEST				5
#define	SVC_MODE_USERMODE			6
#define	SVC_MODE_SERVICE			7
#define	SVC_MODE_SETUP_INSTALL		8
#define	SVC_MODE_SETUP_UNINSTALL	9

#define	SVC_NAME					"SVC_%s_NAME"
#define	SVC_TITLE					"SVC_%s_TITLE"
#define	SVC_DESCRIPT				"SVC_%s_DESCRIPT"

#define	SVC_CALLING_SM_PROCESS_ID_KEY	"Software\\" GC_REG_COMPANY_NAME "\\PacketiX VPN\\Service Control\\%s"
#define SVC_CALLING_SM_PROCESS_ID_VALUE	"ProcessId"

#define	SOFTETHER_FW_SCRIPT_HASH	"Software\\" GC_REG_COMPANY_NAME "\\PacketiX VPN\\FW ScriptHash"

#define	MS_REG_TCP_SETTING_KEY		"Software\\" GC_REG_COMPANY_NAME "\\Network Settings"


#ifdef	MICROSOFT_C
typedef struct MS
{
	HINSTANCE hInst;
	bool IsAdmin;
	HANDLE hCurrentProcess;
	UINT CurrentProcessId;
	bool MiniDumpEnabled;
	char *ExeFileDir;
	char *System32Dir;
	char *TempDir;
	char *MyTempDir;
	wchar_t *ExeFileNameW;
	wchar_t *ExeFileDirW;
	wchar_t *WindowsDirW;
	wchar_t *System32DirW;
	wchar_t *TempDirW;
	wchar_t *MyTempDirW;
	wchar_t *UserNameW;
	wchar_t *MinidumpBaseFileNameW;
	IO *LockFile;
} MS;

typedef struct MS_USERMODE_SVC_PULSE_THREAD_PARAM
{
	void *hWnd;
	void *GlobalPulse;
	volatile bool Halt;
} MS_USERMODE_SVC_PULSE_THREAD_PARAM;

#endif	// MICROSOFT_C

typedef struct NO_WARNING
{
	UINT ThreadId;
	THREAD *NoWarningThread;
	EVENT *HaltEvent;
	volatile bool Halt;
	UINT64 StartTimer;
	UINT64 StartTick;
} NO_WARNING;

#define	REG_CLASSES_ROOT		0
#define	REG_LOCAL_MACHINE		1
#define	REG_CURRENT_USER		2
#define	REG_USERS				3

typedef void (SERVICE_FUNCTION)();

typedef struct MS_PROCESS
{
	char ExeFilename[MAX_PATH];
	wchar_t ExeFilenameW[MAX_PATH];
	UINT ProcessId;
} MS_PROCESS;

#define	MAX_MS_ADAPTER_IP_ADDRESS	64

typedef struct MS_ADAPTER
{
	char Title[MAX_PATH];
	wchar_t TitleW[MAX_PATH];
	UINT Index;
	UINT MediaConnectState;
	UINT Type;
	UINT Status;
	UINT Mtu;
	UINT Speed;
	UINT AddressSize;
	UCHAR Address[8];
	UINT64 RecvBytes;
	UINT64 RecvPacketsBroadcast;
	UINT64 RecvPacketsUnicast;
	UINT64 SendBytes;
	UINT64 SendPacketsBroadcast;
	UINT64 SendPacketsUnicast;
	char Guid[MAX_SIZE];
	UINT NumIpAddress;
	IP IpAddresses[MAX_MS_ADAPTER_IP_ADDRESS];
	IP SubnetMasks[MAX_MS_ADAPTER_IP_ADDRESS];
	UINT NumGateway;
	IP Gateways[MAX_MS_ADAPTER_IP_ADDRESS];
	bool UseDhcp;
	IP DhcpServer;
	UINT64 DhcpLeaseStart;
	UINT64 DhcpLeaseExpires;
	bool UseWins;
	IP PrimaryWinsServer;
	IP SecondaryWinsServer;
	bool IsWireless;
	bool IsNotEthernetLan;
} MS_ADAPTER;

typedef struct MS_ADAPTER_LIST
{
	UINT Num;
	MS_ADAPTER **Adapters;
} MS_ADAPTER_LIST;

typedef struct MS_TCP
{
	UINT RecvWindowSize;
	UINT SendWindowSize;
} MS_TCP;

typedef struct ENUM_CHILD_WINDOW_PARAM
{
	LIST *o;
	bool no_recursion;
	bool include_ipcontrol;
} ENUM_CHILD_WINDOW_PARAM;


void MsInit();
void MsFree();

bool MsRegIsKeyEx2(UINT root, char *name, bool force32bit);

bool MsRegIsValue(UINT root, char *keyname, char *valuename);
bool MsRegIsValueEx2(UINT root, char *keyname, char *valuename, bool force32bit);

char *MsRegReadStr(UINT root, char *keyname, char *valuename);
char *MsRegReadStrEx2(UINT root, char *keyname, char *valuename, bool force32bit);
wchar_t *MsRegReadStrEx2W(UINT root, char *keyname, char *valuename, bool force32bit);

UINT MsRegReadInt(UINT root, char *keyname, char *valuename);
UINT MsRegReadIntEx2(UINT root, char *keyname, char *valuename, bool force32bit);

bool MsRegNewKeyEx2(UINT root, char *keyname, bool force32bit);

bool MsRegWriteValueEx2(UINT root, char *keyname, char *valuename, UINT type, void *data, UINT size, bool force32bit);

bool MsRegWriteStr(UINT root, char *keyname, char *valuename, char *str);
bool MsRegWriteStrEx2(UINT root, char *keyname, char *valuename, char *str, bool force32bit);

bool MsRegWriteInt(UINT root, char *keyname, char *valuename, UINT value);
bool MsRegWriteIntEx2(UINT root, char *keyname, char *valuename, UINT value, bool force32bit);

TOKEN_LIST *MsRegEnumKey(UINT root, char *keyname);
TOKEN_LIST *MsRegEnumKeyEx2(UINT root, char *keyname, bool force32bit);

bool MsRegDeleteKeyEx2(UINT root, char *keyname, bool force32bit);
bool MsRegDeleteValue(UINT root, char *keyname, char *valuename);
bool MsRegDeleteValueEx2(UINT root, char *keyname, char *valuename, bool force32bit);

bool MsRegLoadHive(UINT root, wchar_t *keyname, wchar_t *filename);

bool MsIsAdmin();
bool MsEnablePrivilege(char *name, bool enable);
UINT MsGetCurrentProcessId();
char *MsGetExeDirName();
wchar_t *MsCopyProcessArgsW();

bool MsCheckLogon(wchar_t *username, char *password);
wchar_t *MsGetNetworkConnectionName(char *guid);

void MsGenLockFile(wchar_t *name, UINT size, wchar_t *temp_dir);
void MsDeleteAllFileW(wchar_t *dir);

void MsInitGlobalNetworkConfig();
void MsSetThreadPriorityIdle();
void MsSetThreadPriorityRealtime();
void MsRestoreThreadPriority();
char *MsGetSystem32Dir();
char *MsGetTempDir();
char *MsGetMyTempDir();
wchar_t *MsGetWindowsDirW();
wchar_t *MsGetExeFileNameW();
wchar_t *MsGetSystem32DirW();
wchar_t *MsGetMyTempDirW();
wchar_t *MsGetUserNameW();
bool MsIsServiceInstalled(char *name);
bool MsInstallServiceExW(char *name, wchar_t *title, wchar_t *description, wchar_t *path);
bool MsUpdateServiceConfig(char *name);
bool MsUninstallService(char *name);
bool MsStartService(char *name);
bool MsStopService(char *name);
bool MsIsServiceRunning(char *name);
UINT MsService(char *name, SERVICE_FUNCTION *start, SERVICE_FUNCTION *stop, char *cmd_line);
bool MsWriteEventLog(char *source, UINT type, UINT event_id, char *message);
bool MsIsUserMode();
LIST *MsGetProcessList();
void MsFreeProcessList(LIST *o);

void MsGenerateUserModeSvcGlobalPulseName(char *name, UINT size, char *svc_name);
void MsUserModeGlobalPulseRecvThread(THREAD *thread, void *param);

MS_ADAPTER_LIST *MsCreateAdapterListInnerExVista(bool no_info);
void MsFreeAdapter(MS_ADAPTER *a);
void MsFreeAdapterList(MS_ADAPTER_LIST *o);
MS_ADAPTER *MsCloneAdapter(MS_ADAPTER *a);
MS_ADAPTER_LIST *MsCloneAdapterList(MS_ADAPTER_LIST *o);
MS_ADAPTER_LIST *MsCreateAdapterList();
MS_ADAPTER_LIST *MsCreateAdapterListEx(bool no_info);
MS_ADAPTER *MsGetAdapterByGuid(char *guid);
MS_ADAPTER *MsGetAdapterByGuidFromList(MS_ADAPTER_LIST *o, char *guid);
UINT ConvertMidStatusVistaToXp(UINT st);

void MsSetTcpConfig(MS_TCP *tcp);
bool MsLoadTcpConfigReg(MS_TCP *tcp);

UINT MsGetConsoleWidth();
UINT MsSetConsoleWidth(UINT size);
NO_WARNING *MsInitNoWarningEx(UINT start_timer);
void MsFreeNoWarning(NO_WARNING *nw);
int CmpWindowList(void *p1, void *p2);
void AddWindow(LIST *o, HWND hWnd);

void MsRegistWindowsFirewallEx(char *title, char *exe);
void MsRegistWindowsFirewallEx2(char *title, char *exe, char *dir);
bool MsIsX64();
void *MsDisableWow64FileSystemRedirection();
void MsRestoreWow64FileSystemRedirection(void *p);

bool MsGetProcessExeName(char *path, UINT size, UINT id);

void MsGetComputerName(char *name, UINT size);
void MsGetComputerNameFullEx(wchar_t *name, UINT size, bool with_cache);

UINT64 MsGetHiResCounter();
double MsGetHiResTimeSpan(UINT64 diff);
bool MsGetFileInformation(void *h, void *info);
void MsSetEnableMinidump(bool enabled);
void MsWriteMinidump(wchar_t *filename, void *ex);


UINT MsGetUserLocaleId();

bool MsIsInVm();

void MsInitProcessCallOnce();

#ifdef MICROSOFT_C
LONG CALLBACK MsExceptionHandler(struct _EXCEPTION_POINTERS *ExceptionInfo);
HKEY MsGetRootKeyFromInt(UINT root);
#endif // MICROSOFT_C

#endif // MICROSOFT_H
