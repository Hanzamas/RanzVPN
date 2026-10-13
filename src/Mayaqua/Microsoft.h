// SoftEther VPN Source Code - Developer Edition Master Branch
// Mayaqua Kernel


// Microsoft.h
// Header of Microsoft.c

#ifdef OS_WIN32

#ifndef	MICROSOFT_H
#define	MICROSOFT_H

#include "Network.h"

// Constant for Event log
#define	MS_EVENTLOG_TYPE_INFORMATION		0
#define	MS_EVENTLOG_TYPE_WARNING			1
#define	MS_EVENTLOG_TYPE_ERROR				2

#define	MS_RC_EVENTLOG_TYPE_INFORMATION		0x40000001L
#define	MS_RC_EVENTLOG_TYPE_WARNING			0x80000002L
#define	MS_RC_EVENTLOG_TYPE_ERROR			0xC0000003L


// TCP/IP registry value
#define	TCP_MAX_NUM_CONNECTIONS				16777214

#define	DEFAULT_TCP_MAX_WINDOW_SIZE_RECV	5955584
#define	DEFAULT_TCP_MAX_WINDOW_SIZE_SEND	131072
#define	DEFAULT_TCP_MAX_NUM_CONNECTIONS		16777214

// Constant
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

// Time to suicide, if the service freezed
#define	SVC_SELFKILL_TIMEOUT		(5 * 60 * 1000)

// Command line format in the service mode
#define	SVC_RUN_COMMANDLINE			L"\"%s\" /service"

// Mode value
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

#define	VISTA_MMCSS_KEYNAME			"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Multimedia\\SystemProfile\\Tasks"
#define	VISTA_MMCSS_FILENAME		"mmcss_backup.dat"

#define	SVC_NAME					"SVC_%s_NAME"
#define	SVC_TITLE					"SVC_%s_TITLE"
#define	SVC_DESCRIPT				"SVC_%s_DESCRIPT"

#define	SVC_CALLING_SM_PROCESS_ID_KEY	"Software\\" GC_REG_COMPANY_NAME "\\PacketiX VPN\\Service Control\\%s"
#define SVC_CALLING_SM_PROCESS_ID_VALUE	"ProcessId"

#define	SOFTETHER_FW_SCRIPT_HASH	"Software\\" GC_REG_COMPANY_NAME "\\PacketiX VPN\\FW ScriptHash"

#define	MMCSS_PROFILE_KEYNAME		"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Multimedia\\SystemProfile"

// Other constants
#define	MS_REG_TCP_SETTING_KEY		"Software\\" GC_REG_COMPANY_NAME "\\Network Settings"



#ifdef	MICROSOFT_C
// Internal structure
typedef struct MS
{
	HINSTANCE hInst;
	HINSTANCE hKernel32;
	bool IsAdmin;
	HANDLE hCurrentProcess;
	UINT CurrentProcessId;
	bool MiniDumpEnabled;
	char *ExeFileName;
	char *ExeFileDir;
	char *WindowsDir;
	char *System32Dir;
	char *TempDir;
	char *WinTempDir;
	char *WindowsDrive;
	char *ProgramFilesDir;
	char *ProgramFilesDirX86;
	char *ProgramFilesDirX64;
	char *CommonStartMenuDir;
	char *CommonProgramsDir;
	char *CommonStartupDir;
	char *CommonAppDataDir;
	char *CommonDesktopDir;
	char *PersonalStartMenuDir;
	char *PersonalProgramsDir;
	char *PersonalStartupDir;
	char *PersonalAppDataDir;
	char *PersonalDesktopDir;
	char *MyDocumentsDir;
	char *LocalAppDataDir;
	char *MyTempDir;
	char *UserName;
	char *UserNameEx;
	wchar_t *ExeFileNameW;
	wchar_t *ExeFileDirW;
	wchar_t *WindowsDirW;
	wchar_t *System32DirW;
	wchar_t *TempDirW;
	wchar_t *WinTempDirW;
	wchar_t *WindowsDriveW;
	wchar_t *ProgramFilesDirW;
	wchar_t *ProgramFilesDirX86W;
	wchar_t *ProgramFilesDirX64W;
	wchar_t *CommonStartMenuDirW;
	wchar_t *CommonProgramsDirW;
	wchar_t *CommonStartupDirW;
	wchar_t *CommonAppDataDirW;
	wchar_t *CommonDesktopDirW;
	wchar_t *PersonalStartMenuDirW;
	wchar_t *PersonalProgramsDirW;
	wchar_t *PersonalStartupDirW;
	wchar_t *PersonalAppDataDirW;
	wchar_t *PersonalDesktopDirW;
	wchar_t *MyDocumentsDirW;
	wchar_t *LocalAppDataDirW;
	wchar_t *MyTempDirW;
	wchar_t *UserNameW;
	wchar_t *UserNameExW;
	wchar_t *MinidumpBaseFileNameW;
	IO *LockFile;
} MS;

typedef struct MS_EVENTLOG
{
	HANDLE hEventLog;
} MS_EVENTLOG;

typedef struct MS_USERMODE_SVC_PULSE_THREAD_PARAM
{
	void *hWnd;
	void *GlobalPulse;
	volatile bool Halt;
} MS_USERMODE_SVC_PULSE_THREAD_PARAM;

#endif	// MICROSOFT_C

// Structure to suppress the warning message
typedef struct NO_WARNING
{
	UINT ThreadId;
	THREAD *NoWarningThread;
	EVENT *HaltEvent;
	volatile bool Halt;
	wchar_t *SoundFileName;
	UINT64 StartTimer;
	UINT64 StartTick;
} NO_WARNING;

// ID of the root key
#define	REG_CLASSES_ROOT		0	// HKEY_CLASSES_ROOT
#define	REG_LOCAL_MACHINE		1	// HKEY_LOCAL_MACHINE
#define	REG_CURRENT_USER		2	// HKEY_CURRENT_USER
#define	REG_USERS				3	// HKEY_USERS

// Service Functions
typedef void (SERVICE_FUNCTION)();

// Process list item
typedef struct MS_PROCESS
{
	char ExeFilename[MAX_PATH];		// EXE file name
	wchar_t ExeFilenameW[MAX_PATH];	// EXE file name (Unicode)
	UINT ProcessId;					// Process ID
} MS_PROCESS;

#define	MAX_MS_ADAPTER_IP_ADDRESS	64

// Network adapter
typedef struct MS_ADAPTER
{
	char Title[MAX_PATH];			// Display name
	wchar_t TitleW[MAX_PATH];		// Display Name (Unicode)
	UINT Index;						// Index
	UINT MediaConnectState;			// Media Connect State
	UINT Type;						// Type
	UINT Status;					// Status
	UINT Mtu;						// MTU
	UINT Speed;						// Speed
	UINT AddressSize;				// Address size
	UCHAR Address[8];				// Address
	UINT64 RecvBytes;				// Number of received bytes
	UINT64 RecvPacketsBroadcast;	// Number of broadcast packets received
	UINT64 RecvPacketsUnicast;		// Number of unicast packets received
	UINT64 SendBytes;				// Number of bytes sent
	UINT64 SendPacketsBroadcast;	// Number of sent broadcast packets
	UINT64 SendPacketsUnicast;		// Number of sent unicast packets
	bool Info;						// Whether there is detailed information
	char Guid[MAX_SIZE];			// GUID
	UINT NumIpAddress;				// The number of IP addresses
	IP IpAddresses[MAX_MS_ADAPTER_IP_ADDRESS];	// IP address
	IP SubnetMasks[MAX_MS_ADAPTER_IP_ADDRESS];	// Subnet mask
	UINT NumGateway;				// The number of the gateway
	IP Gateways[MAX_MS_ADAPTER_IP_ADDRESS];	// Gateway
	bool UseDhcp;					// Using DHCP flag
	IP DhcpServer;					// DHCP Server
	UINT64 DhcpLeaseStart;			// DHCP lease start date and time
	UINT64 DhcpLeaseExpires;		// DHCP lease expiration date and time
	bool UseWins;					// WINS use flag
	IP PrimaryWinsServer;			// Primary WINS server
	IP SecondaryWinsServer;			// Secondary WINS server
	bool IsWireless;				// Whether wireless
	bool IsNotEthernetLan;			// Whether It isn't a Ethernet LAN
} MS_ADAPTER;

// Network adapter list
typedef struct MS_ADAPTER_LIST
{
	UINT Num;						// Count
	MS_ADAPTER **Adapters;			// Content
} MS_ADAPTER_LIST;

typedef struct MS_ISLOCKED
{
	HWND hWnd;
	THREAD *Thread;
	volatile bool IsLockedFlag;
} MS_ISLOCKED;

// TCP setting
typedef struct MS_TCP
{
	UINT RecvWindowSize;			// Receive window size
	UINT SendWindowSize;			// Send window size
} MS_TCP;

// Sleep prevention
typedef struct MS_NOSLEEP
{
	THREAD *Thread;					// Thread
	EVENT *HaltEvent;				// Halting event
	volatile bool Halt;				// Halting flag
	bool NoScreenSaver;				// Prevent Screensaver

	// Following is for Windows Vista
	wchar_t ScreenSaveActive[MAX_PATH];
	wchar_t SCRNSAVE_EXE[MAX_PATH];
} MS_NOSLEEP;

// Child window enumeration
typedef struct ENUM_CHILD_WINDOW_PARAM
{
	LIST *o;
	bool no_recursion;
	bool include_ipcontrol;
} ENUM_CHILD_WINDOW_PARAM;


// Function prototype
void MsInit();
void MsFree();
char *MsCutExeNameFromCommandLine(char *str);
wchar_t *MsCutExeNameFromUniCommandLine(wchar_t *str);

UINT MsRegAccessMaskFor64BitEx(bool force32bit, bool force64bit);

bool MsRegIsKeyEx2(UINT root, char *name, bool force32bit, bool force64bit);

bool MsRegIsValue(UINT root, char *keyname, char *valuename);
bool MsRegIsValueEx(UINT root, char *keyname, char *valuename, bool force32bit);
bool MsRegIsValueEx2(UINT root, char *keyname, char *valuename, bool force32bit, bool force64bit);

bool MsRegReadValueEx2(UINT root, char *keyname, char *valuename, void **data, DWORD *type, DWORD *size, bool force32bit, bool force64bit);
bool MsRegReadValueEx2W(UINT root, char *keyname, char *valuename, void **data, DWORD *type, DWORD *size, bool force32bit, bool force64bit);

char *MsRegReadStr(UINT root, char *keyname, char *valuename);
char *MsRegReadStrEx(UINT root, char *keyname, char *valuename, bool force32bit);
char *MsRegReadStrEx2(UINT root, char *keyname, char *valuename, bool force32bit, bool force64bit);
wchar_t *MsRegReadStrW(UINT root, char *keyname, char *valuename);
wchar_t *MsRegReadStrExW(UINT root, char *keyname, char *valuename, bool force32bit);
wchar_t *MsRegReadStrEx2W(UINT root, char *keyname, char *valuename, bool force32bit, bool force64bit);

UINT MsRegReadInt(UINT root, char *keyname, char *valuename);
UINT MsRegReadIntEx(UINT root, char *keyname, char *valuename, bool force32bit);
UINT MsRegReadIntEx2(UINT root, char *keyname, char *valuename, bool force32bit, bool force64bit);
LIST *MsRegReadStrList(UINT root, char *keyname, char *valuename);
LIST *MsRegReadStrListEx(UINT root, char *keyname, char *valuename, bool force32bit);
LIST *MsRegReadStrListEx2(UINT root, char *keyname, char *valuename, bool force32bit, bool force64bit);

bool MsRegNewKeyEx2(UINT root, char *keyname, bool force32bit, bool force64bit);

bool MsRegWriteValueEx2(UINT root, char *keyname, char *valuename, UINT type, void *data, UINT size, bool force32bit, bool force64bit);
bool MsRegWriteValueEx2W(UINT root, char *keyname, char *valuename, UINT type, void *data, UINT size, bool force32bit, bool force64bit);

bool MsRegWriteStr(UINT root, char *keyname, char *valuename, char *str);
bool MsRegWriteStrEx(UINT root, char *keyname, char *valuename, char *str, bool force32bit);
bool MsRegWriteStrEx2(UINT root, char *keyname, char *valuename, char *str, bool force32bit, bool force64bit);

bool MsRegWriteInt(UINT root, char *keyname, char *valuename, UINT value);
bool MsRegWriteIntEx(UINT root, char *keyname, char *valuename, UINT value, bool force32bit);
bool MsRegWriteIntEx2(UINT root, char *keyname, char *valuename, UINT value, bool force32bit, bool force64bit);

TOKEN_LIST *MsRegEnumKey(UINT root, char *keyname);
TOKEN_LIST *MsRegEnumKeyEx(UINT root, char *keyname, bool force32bit);
TOKEN_LIST *MsRegEnumKeyEx2(UINT root, char *keyname, bool force32bit, bool force64bit);

bool MsRegDeleteKey(UINT root, char *keyname);
bool MsRegDeleteKeyEx(UINT root, char *keyname, bool force32bit);
bool MsRegDeleteKeyEx2(UINT root, char *keyname, bool force32bit, bool force64bit);
bool MsRegDeleteValue(UINT root, char *keyname, char *valuename);
bool MsRegDeleteValueEx(UINT root, char *keyname, char *valuename, bool force32bit);
bool MsRegDeleteValueEx2(UINT root, char *keyname, char *valuename, bool force32bit, bool force64bit);

bool MsRegLoadHive(UINT root, wchar_t *keyname, wchar_t *filename);

bool MsIsAdmin();
bool MsEnablePrivilege(char *name, bool enable);
UINT MsGetCurrentProcessId();
char *MsGetExeDirName();

void MsStartIsLockedThread();
void MsStopIsLockedThread();

bool MsCheckLogon(wchar_t *username, char *password);
wchar_t *MsGetNetworkConnectionName(char *guid);

char *MsGetSpecialDir(int id);
wchar_t *MsGetSpecialDirW(int id);
void MsGetSpecialDirs();
bool MsCheckIsAdmin();
void MsInitTempDir();
void MsFreeTempDir();
void MsGenLockFile(wchar_t *name, UINT size, wchar_t *temp_dir);
void MsDeleteTempDir();
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
struct SAFE_TABLE *MsGetSafeTable();
bool MsIsServiceInstalled(char *name);
bool MsInstallServiceExW(char *name, wchar_t *title, wchar_t *description, wchar_t *path, UINT *error_code);
bool MsInstallServiceW(char *name, wchar_t *title, wchar_t *description, wchar_t *path);
bool MsUpdateServiceConfig(char *name);
bool MsUninstallService(char *name);
bool MsStartService(char *name);
bool MsStartServiceEx(char *name, UINT *error_code);
bool MsStopService(char *name);
bool MsIsServiceRunning(char *name);
UINT MsService(char *name, SERVICE_FUNCTION *start, SERVICE_FUNCTION *stop, UINT icon, char *cmd_line);
void MsTestModeW(wchar_t *title, SERVICE_FUNCTION *start, SERVICE_FUNCTION *stop);
void MsServiceMode(SERVICE_FUNCTION *start, SERVICE_FUNCTION *stop);
void MsUserModeW(wchar_t *title, SERVICE_FUNCTION *start, SERVICE_FUNCTION *stop, UINT icon);
bool MsIsUserMode();
LIST *MsGetProcessList();
LIST *MsGetProcessList9x();
LIST *MsGetProcessListNt();
void MsFreeProcessList(LIST *o);
int MsCompareProcessList(void *p1, void *p2);
MS_PROCESS *MsSearchProcessById(LIST *o, UINT id);
void MsWriteCallingServiceManagerProcessId(char *svcname, UINT pid);

void MsGenerateUserModeSvcGlobalPulseName(char *name, UINT size, char *svc_name);
void *MsCreateUserModeSvcGlocalPulse(char *svc_name);
void MsUserModeGlobalPulseRecvThread(THREAD *thread, void *param);

MS_ADAPTER_LIST *MsCreateAdapterListInner();
MS_ADAPTER_LIST *MsCreateAdapterListInnerEx(bool no_info);
MS_ADAPTER_LIST *MsCreateAdapterListInnerExVista(bool no_info);
void MsFreeAdapter(MS_ADAPTER *a);
void MsFreeAdapterList(MS_ADAPTER_LIST *o);
MS_ADAPTER *MsCloneAdapter(MS_ADAPTER *a);
MS_ADAPTER_LIST *MsCloneAdapterList(MS_ADAPTER_LIST *o);
void MsInitAdapterListModule();
void MsFreeAdapterListModule();
MS_ADAPTER_LIST *MsCreateAdapterList();
MS_ADAPTER_LIST *MsCreateAdapterListEx(bool no_info);
void MsGetAdapterTcpIpInformation(MS_ADAPTER *a);
MS_ADAPTER *MsGetAdapterByGuid(char *guid);
MS_ADAPTER *MsGetAdapterByGuidFromList(MS_ADAPTER_LIST *o, char *guid);
UINT ConvertMidStatusVistaToXp(UINT st);

void *MsLoadLibrary(char *name);
void *MsLoadLibraryW(wchar_t *name);

void MsPrintTick();
bool MsDisableIme();

void MsSetTcpConfig(MS_TCP *tcp);
bool MsLoadTcpConfigReg(MS_TCP *tcp);
bool MsIsTcpConfigSupported();
void MsApplyTcpConfig();

UINT MsGetConsoleWidth();
UINT MsSetConsoleWidth(UINT size);
NO_WARNING *MsInitNoWarningEx(UINT start_timer);
void MsFreeNoWarning(NO_WARNING *nw);
void MsNoWarningThreadProc(THREAD *thread, void *param);
bool MsCloseWarningWindow(NO_WARNING *nw, UINT thread_id);
LIST *MsEnumChildWindows(LIST *o, HWND hWnd);
void MsAddWindowToList(LIST *o, HWND hWnd);
UINT MsGetThreadLocale();
LIST *NewWindowList();
int CmpWindowList(void *p1, void *p2);
void AddWindow(LIST *o, HWND hWnd);
void FreeWindowList(LIST *o);
LIST *EnumAllChildWindow(HWND hWnd);
LIST *EnumAllChildWindowEx(HWND hWnd, bool no_recursion, bool include_ipcontrol, bool no_self);
LIST *EnumAllTopWindow();

void MsRegistWindowsFirewallEx(char *title, char *exe);
void MsRegistWindowsFirewallEx2(char *title, char *exe, char *dir);
bool MsIs64BitWindows();
bool MsIsX64();
void *MsDisableWow64FileSystemRedirection();
void MsRestoreWow64FileSystemRedirection(void *p);

bool MsGetProcessExeName(char *path, UINT size, UINT id);
bool MsGetWindowOwnerProcessExeName(char *path, UINT size, HWND hWnd);

void MsGetComputerName(char *name, UINT size);
void MsGetComputerNameFullEx(wchar_t *name, UINT size, bool with_cache);
UINT64 MsGetScreenSaverTimeout();

bool MsUniMakeDir(wchar_t *name);
void MsUniMakeDirEx(wchar_t *name);
UINT64 MsGetHiResCounter();
double MsGetHiResTimeSpan(UINT64 diff);
UINT64 MsGetHiResTimeSpanUSec(UINT64 diff);
bool MsGetFileInformation(void *h, void *info);
void MsSetErrorModeToSilent();
void MsSetEnableMinidump(bool enabled);
void MsWriteMinidump(wchar_t *filename, void *ex);


void *MsOpenOrCreateGlobalPulse(char *name);
bool MsWaitForGlobalPulse(void *p, UINT timeout);
void MsCloseGlobalPulse(void *p);
void MsSendGlobalPulse(void *p);

UINT MsGetUserLocaleId();

bool MsIsInVmMain();
bool MsIsInVm();

void MsInitProcessCallOnce();

// Inner functions
#ifdef MICROSOFT_C
LONG CALLBACK MsExceptionHandler(struct _EXCEPTION_POINTERS *ExceptionInfo);
HKEY MsGetRootKeyFromInt(UINT root);
void CALLBACK MsServiceDispatcher(DWORD argc, LPTSTR *argv);
void CALLBACK MsServiceHandler(DWORD opcode);
bool MsServiceStopProc();
void MsServiceStoperMainThread(THREAD *t, void *p);
void MsServiceStarterMainThread(THREAD *t, void *p);
LRESULT CALLBACK MsUserModeWindowProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);
BOOL CALLBACK MsEnumChildWindowProc(HWND hWnd, LPARAM lParam);
BOOL CALLBACK EnumTopWindowProc(HWND hWnd, LPARAM lParam);
#endif // MICROSOFT_C

#endif // MICROSOFT_H

#endif // OS_WIN32
