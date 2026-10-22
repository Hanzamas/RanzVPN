// Microsoft.h
// Header of Microsoft.c

#ifndef MICROSOFT_H
#define MICROSOFT_H

#include "MayaType.h"

#define SVC_ARG_INSTALL         "/install"
#define SVC_ARG_UNINSTALL       "/uninstall"
#define SVC_ARG_START           "/start"
#define SVC_ARG_STOP            "/stop"
#define SVC_ARG_TEST            "/test"
#define SVC_ARG_USERMODE        "/usermode"
#define SVC_ARG_SERVICE         "/service"
#define SVC_ARG_SETUP_INSTALL   "/setup_install"
#define SVC_ARG_SETUP_UNINSTALL "/setup_uninstall"
#define SVC_ARG_SILENT          "/silent"

// Self-kill timeout if the service freezes
#define SVC_SELFKILL_TIMEOUT (5 * 60 * 1000)

// Event IDs of the service entries in the Application event log, under the service name as source
#define MS_EVENT_SERVICE_STARTED 1
#define MS_EVENT_SERVICE_STOPPED 2
#define MS_EVENT_SERVICE_FAILED  3
// MayaFatalExit() (Mayaqua.c), under the source "Ranz VPN"
#define MS_EVENT_FATAL_ERROR 4

#define SVC_RUN_COMMANDLINE L"\"%s\" /service"

// The account of a service that MsServiceEx installs with its virtual account: this and the service name
#define SVC_VIRTUAL_ACCOUNT_PREFIX L"NT SERVICE\\"

#define SVC_MODE_NONE            0
#define SVC_MODE_INSTALL         1
#define SVC_MODE_UNINSTALL       2
#define SVC_MODE_START           3
#define SVC_MODE_STOP            4
#define SVC_MODE_TEST            5
#define SVC_MODE_USERMODE        6
#define SVC_MODE_SERVICE         7
#define SVC_MODE_SETUP_INSTALL   8
#define SVC_MODE_SETUP_UNINSTALL 9

#define SVC_NAME     "SVC_%s_NAME"
#define SVC_TITLE    "SVC_%s_TITLE"
#define SVC_DESCRIPT "SVC_%s_DESCRIPT"

#define SVC_CALLING_SM_PROCESS_ID_KEY   "Software\\" GC_REG_COMPANY_NAME "\\PacketiX VPN\\Service Control\\%s"
#define SVC_CALLING_SM_PROCESS_ID_VALUE "ProcessId"

#ifdef MICROSOFT_C
typedef struct MS {
	HINSTANCE hInst;
	bool IsAdmin;
	HANDLE hCurrentProcess;
	UINT CurrentProcessId;
	char *ExeFileDir;
	char *System32Dir;
	char *TempDir;
	char *MyTempDir;
	wchar_t *ExeFileNameW;
	wchar_t *WindowsDirW;
	wchar_t *System32DirW;
	wchar_t *TempDirW;
	wchar_t *MyTempDirW;
	wchar_t *UserNameW;
	IO *LockFile;
} MS;

#endif // MICROSOFT_C

#define REG_CLASSES_ROOT  0
#define REG_LOCAL_MACHINE 1
#define REG_CURRENT_USER  2
#define REG_USERS         3

typedef void(SERVICE_FUNCTION)();

// One command line argument of MsService and the mode it selects; SVC_HELP lists exactly these
typedef struct MS_SVC_ARG {
	char *Arg; // Argument, compared without case
	UINT Mode; // SVC_MODE_* that the argument selects
} MS_SVC_ARG;

typedef struct MS_ADAPTER {
	char Title[MAX_PATH];
	wchar_t TitleW[MAX_PATH];
	UINT Index;
	UINT MediaConnectState;
	UINT Type;
	UINT AddressSize;
	UCHAR Address[8];
	char Guid[MAX_SIZE];     // MIB_IF_ROW2.InterfaceGuid as "{XXXXXXXX-...}"
	bool IsBridgeable;       // MsIsBridgeableIf of the interface type data
	wchar_t Alias[MAX_PATH]; // MIB_IF_ROW2.Alias: the network connection name, such as "Ethernet 2"
} MS_ADAPTER;

// One present device of the network adapter setup class, from MsNetClassEnum
typedef struct MS_NETCLASS_DEVICE {
	char Guid[MAX_SIZE];             // NetCfgInstanceId, "{XXXXXXXX-...}": the key of the table
	char ShortKey[MAX_SIZE];         // Driver key below the Class key, "{4D36E972-E325-11CE-BFC1-08002BE10318}\0007"
	char ClassKey[MAX_SIZE];         // "SYSTEM\CurrentControlSet\Control\Class\" and ShortKey
	char DeviceInstanceId[MAX_SIZE]; // Such as "PCI\VEN_8086&DEV_15B8&...\3&11583659&0&FE"
} MS_NETCLASS_DEVICE;

typedef struct MS_ADAPTER_LIST {
	UINT Num;
	MS_ADAPTER **Adapters;
} MS_ADAPTER_LIST;


void MsInit();
void MsFree();

bool MsRegIsKeyEx2(UINT root, char *name, bool force32bit);

bool MsRegIsValue(UINT root, char *keyname, char *valuename);

char *MsRegReadStr(UINT root, char *keyname, char *valuename);
char *MsRegReadStrEx2(UINT root, char *keyname, char *valuename, bool force32bit);
wchar_t *MsRegReadStrEx2W(UINT root, char *keyname, char *valuename, bool force32bit);

UINT MsRegReadInt(UINT root, char *keyname, char *valuename);
UINT MsRegReadIntEx2(UINT root, char *keyname, char *valuename, bool force32bit);

bool MsRegWriteStr(UINT root, char *keyname, char *valuename, char *str);

bool MsRegWriteInt(UINT root, char *keyname, char *valuename, UINT value);
bool MsRegWriteIntEx2(UINT root, char *keyname, char *valuename, UINT value, bool force32bit);

bool MsRegDeleteValue(UINT root, char *keyname, char *valuename);

bool MsIsAdmin();
bool MsEnablePrivilege(char *name, bool enable);
UINT MsGetCurrentProcessId();
wchar_t *MsCopyProcessArgsW();

bool MsCheckLogon(wchar_t *username, char *password);

LIST *MsNetClassEnum();
MS_NETCLASS_DEVICE *MsNetClassFind(LIST *o, char *guid);
void MsNetClassFree(LIST *o);

void MsDeleteAllFileW(wchar_t *dir);

void MsSetThreadPriorityIdle();
void MsSetThreadPriorityRealtime();
void MsRestoreThreadPriority();
char *MsGetSystem32Dir();
char *MsGetTempDir();
char *MsGetMyTempDir();
wchar_t *MsGetWindowsDirW();
wchar_t *MsGetSystem32DirW();
wchar_t *MsGetMyTempDirW();
bool MsIsServiceInstalled(char *name);
bool MsStartService(char *name);
bool MsIsServiceRunning(char *name);
UINT MsService(char *name, SERVICE_FUNCTION *start, SERVICE_FUNCTION *stop, char *cmd_line, wchar_t *firewall_rule);
UINT MsServiceEx(char *name, SERVICE_FUNCTION *start, SERVICE_FUNCTION *stop, char *cmd_line, wchar_t *firewall_rule, bool virtual_account);
const MS_SVC_ARG *MsSvcArgs(UINT *num);
UINT MsSvcArgToMode(char *arg);
bool MsWriteEventLog(char *source, UINT type, UINT event_id, char *message);
bool MsIsUserMode();

void MsFreeAdapter(MS_ADAPTER *a);
void MsFreeAdapterList(MS_ADAPTER_LIST *o);
MS_ADAPTER_LIST *MsCreateAdapterList();
MS_ADAPTER *MsGetAdapterByGuidFromList(MS_ADAPTER_LIST *o, char *guid);
bool MsIsBridgeableIf(UINT type, UINT media_type, UINT physical_medium_type, bool hardware_interface);

UINT MsGetConsoleWidth();

void MsGetComputerNameFullEx(wchar_t *name, UINT size, bool with_cache);

UINT MsGetUserLocaleId();

bool MsIsInVm();

void MsInitProcessCallOnce();

#ifdef MICROSOFT_C
HKEY MsGetRootKeyFromInt(UINT root);
#endif // MICROSOFT_C

#endif // MICROSOFT_H
