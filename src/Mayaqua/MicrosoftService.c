// MicrosoftService.c
// Windows service control: service arguments, SCM install, update, uninstall, start, stop and query, event log

#define MICROSOFT_C

#include "Microsoft.h"

#include "Cfg.h"
#include "FileIO.h"
#include "GlobalConst.h"
#include "Internat.h"
#include "Memory.h"
#include "Str.h"
#include "Table.h"
#include "Tick64.h"

#define SECURITY_WIN32

#define NO_SHLWAPI_STRFCNS
#define NO_SHLWAPI_REG
#define NO_SHLWAPI_STREAM
#define NO_SHLWAPI_HTTP
#define NO_SHLWAPI_ISOS
#define NO_SHLWAPI_GDI

#include <AclAPI.h>
#include <iphlpapi.h>
#include <mmsystem.h>
#include <nb30.h>
#include <sddl.h>
#include <security.h>
#include <SetupAPI.h>
#include <shellapi.h>
#include <ShlObj.h>
#include <Shlwapi.h> // PathGetArgsW() of MsCopyProcessArgsW
#include <SoftPub.h>

#if defined(_M_X64) || defined(_M_IX86)
#include <intrin.h> // __cpuid() of the VM detection
#endif              // defined(_M_X64) || defined(_M_IX86)
#include "MicrosoftInternal.h"

// Write one entry to the Application event log, with the message as its only insertion string;
// type is an EVENTLOG_*_TYPE value. Plain Win32 calls only, so that the service code can write
// entries before InitMayaqua().
bool MsWriteEventLog(char *source, UINT type, UINT event_id, char *message) {
	LPCSTR strings[1];
	if (source == NULL || message == NULL)
		return false;

	HANDLE h = RegisterEventSourceA(NULL, source);
	if (h == NULL)
		return false;

	strings[0] = message;
	BOOL ret = ReportEventA(h, (WORD)type, 0, event_id, NULL, 1, 0, strings, NULL);

	DeregisterEventSource(h);

	return ret ? true : false;
}

// The command line arguments of MsService and the mode each one selects. SVC_HELP lists exactly
// these; any other argument selects SVC_MODE_NONE, which prints SVC_HELP.
static const MS_SVC_ARG ms_svc_args[] =
    {
        {SVC_ARG_INSTALL, SVC_MODE_INSTALL},
        {SVC_ARG_UNINSTALL, SVC_MODE_UNINSTALL},
        {SVC_ARG_START, SVC_MODE_START},
        {SVC_ARG_STOP, SVC_MODE_STOP},
        {SVC_ARG_TEST, SVC_MODE_TEST},
        {SVC_ARG_USERMODE, SVC_MODE_USERMODE},
        {SVC_ARG_SETUP_INSTALL, SVC_MODE_SETUP_INSTALL},
        {SVC_ARG_SETUP_UNINSTALL, SVC_MODE_SETUP_UNINSTALL},
        {SVC_ARG_SERVICE, SVC_MODE_SERVICE},
};

// The argument table of MsService; num receives the number of its entries
const MS_SVC_ARG *MsSvcArgs(UINT *num) {
	if (num != NULL)
		*num = sizeof(ms_svc_args) / sizeof(ms_svc_args[0]);

	return ms_svc_args;
}

// The mode that the command line argument arg selects, compared without case; SVC_MODE_NONE for an
// argument that is not in the table, and for NULL
UINT MsSvcArgToMode(char *arg) {
	if (arg == NULL)
		return SVC_MODE_NONE;

	for (UINT i = 0; i < sizeof(ms_svc_args) / sizeof(ms_svc_args[0]); i++)
		if (StrCmpi(arg, ms_svc_args[i].Arg) == 0)
			return ms_svc_args[i].Mode;

	return SVC_MODE_NONE;
}

// Wait up to 10 s, polling every 250 ms, until the service is running (running == true) or no longer
// running (running == false)
static void MsWaitServiceState(char *name, bool running) {
	UINT64 end = Tick64() + 10000ULL;

	while (Tick64() < end) {
		if (MsIsServiceRunning(name) == running)
			break;

		SleepThread(250);
	}
}

bool MsStopService(char *name) {
	bool ret = false;
	if (name == NULL)
		return false;

	SC_HANDLE sc = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
	if (sc == NULL)
		return false;

	SC_HANDLE service = OpenService(sc, name, SERVICE_ALL_ACCESS);
	if (service != NULL) {
		SERVICE_STATUS st;
		ret = ControlService(service, SERVICE_CONTROL_STOP, &st);

		CloseServiceHandle(service);
	}

	if (ret)
		MsWaitServiceState(name, false);

	CloseServiceHandle(sc);
	return ret;
}

bool MsStartService(char *name) {
	bool ret = false;
	if (name == NULL)
		return false;

	SC_HANDLE sc = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
	if (sc == NULL)
		return false;

	SC_HANDLE service = OpenService(sc, name, SERVICE_ALL_ACCESS);
	if (service != NULL) {
		ret = StartService(service, 0, NULL);

		CloseServiceHandle(service);
	}

	if (ret)
		MsWaitServiceState(name, true);

	CloseServiceHandle(sc);
	return ret;
}

bool MsIsServiceRunning(char *name) {
	bool ret = false;
	if (name == NULL || IsEmptyStr(name))
		return false;

	SC_HANDLE sc = OpenSCManager(NULL, NULL, GENERIC_READ);
	if (sc == NULL)
		return false;

	SC_HANDLE service = OpenService(sc, name, GENERIC_READ);
	if (service != NULL) {
		SERVICE_STATUS st;
		Zero(&st, sizeof(st));
		if (QueryServiceStatus(service, &st)) {
			switch (st.dwCurrentState) {
			case SERVICE_CONTINUE_PENDING:
			case SERVICE_PAUSE_PENDING:
			case SERVICE_PAUSED:
			case SERVICE_RUNNING:
			case SERVICE_START_PENDING:
			case SERVICE_STOP_PENDING:
				ret = true;
				break;
			}
		}

		CloseServiceHandle(service);
	}

	CloseServiceHandle(sc);
	return ret;
}

bool MsUninstallService(char *name) {
	bool ret = false;
	if (name == NULL)
		return false;

	MsStopService(name);

	SC_HANDLE sc = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
	if (sc == NULL)
		return false;

	SC_HANDLE service = OpenService(sc, name, SERVICE_ALL_ACCESS);
	if (service != NULL) {
		if (DeleteService(service))
			ret = true;
		CloseServiceHandle(service);
	}

	CloseServiceHandle(sc);

	if (ret)
		SleepThread(2000);

	return ret;
}

// Recovery of the service: restart it 10 s after each of its first three failures, and count the
// failures from zero again after a day without one. The handle needs SERVICE_CHANGE_CONFIG, and
// SERVICE_START for the restart actions.
static void MsSetServiceRecovery(SC_HANDLE service) {
	SERVICE_FAILURE_ACTIONS action;
	SC_ACTION e[3];

	Zero(&action, sizeof(action));
	action.dwResetPeriod = 1 * 60 * 60 * 24;
	action.cActions = (DWORD)(sizeof(e) / sizeof(e[0]));
	action.lpsaActions = e;

	for (UINT i = 0; i < action.cActions; i++) {
		e[i].Type = SC_ACTION_RESTART;
		e[i].Delay = 10000;
	}

	ChangeServiceConfig2(service, SERVICE_CONFIG_FAILURE_ACTIONS, &action);
}

bool MsUpdateServiceConfig(char *name) {
	if (name == NULL)
		return false;

	// Shortly after Windows startup (prevents a deadlock)
	if (timeGetTime() <= (60 * 30 * 1000)) {
		if (MsRegReadInt(REG_LOCAL_MACHINE, "Software\\" GC_REG_COMPANY_NAME "\\Update Service Config", name) != 0)
			return false;
	}

	SC_HANDLE sc = OpenSCManager(NULL, NULL, SC_MANAGER_CONNECT);
	if (sc == NULL)
		return false;

	// ChangeServiceConfig2 needs SERVICE_CHANGE_CONFIG, and SERVICE_START for the restart actions
	SC_HANDLE service = OpenService(sc, name, SERVICE_CHANGE_CONFIG | SERVICE_START);
	if (service != NULL) {
		SERVICE_DESCRIPTIONW d;
		char dname[MAX_SIZE];

		MsSetServiceRecovery(service);

		MsRegWriteInt(REG_LOCAL_MACHINE, "Software\\" GC_REG_COMPANY_NAME "\\Update Service Config", name, 1);

		Format(dname, sizeof(dname), "SVC_%s_DESCRIPT", name);

		wchar_t *description = _UU(dname);

		if (UniIsEmptyStr(description) == false) {
			Zero(&d, sizeof(d));
			d.lpDescription = description;
			ChangeServiceConfig2(service, SERVICE_CONFIG_DESCRIPTION, &d);
		}

		CloseServiceHandle(service);
	}

	CloseServiceHandle(sc);

	return true;
}

// Install the service, as LocalSystem, or with virtual_account as its virtual account NT SERVICE\<name>, which
// needs no password and whose SID is the service SID (an unrestricted service SID type)
bool MsInstallServiceExW(char *name, wchar_t *title, wchar_t *description, wchar_t *path, bool virtual_account) {
	bool ret = false;
	wchar_t name_w[MAX_SIZE];
	wchar_t account[MAX_SIZE];
	if (name == NULL || title == NULL || path == NULL)
		return false;

	StrToUni(name_w, sizeof(name_w), name);
	UniFormat(account, sizeof(account), SVC_VIRTUAL_ACCOUNT_PREFIX L"%s", name_w);

	SC_HANDLE sc = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
	if (sc == NULL)
		return false;

	SC_HANDLE service = CreateServiceW(sc, name_w, title, SERVICE_ALL_ACCESS,
	                                   SERVICE_WIN32_OWN_PROCESS, SERVICE_AUTO_START,
	                                   SERVICE_ERROR_NORMAL, path, NULL, NULL, NULL, virtual_account ? account : NULL, NULL);

	if (service != NULL) {
		SERVICE_DESCRIPTIONW d;

		ret = true;

		Zero(&d, sizeof(d));
		d.lpDescription = description;
		ChangeServiceConfig2(service, SERVICE_CONFIG_DESCRIPTION, &d);

		if (virtual_account) {
			SERVICE_SID_INFO sid_info;

			Zero(&sid_info, sizeof(sid_info));
			sid_info.dwServiceSidType = SERVICE_SID_TYPE_UNRESTRICTED;
			ChangeServiceConfig2W(service, SERVICE_CONFIG_SERVICE_SID_INFO, &sid_info);
		}

		MsSetServiceRecovery(service);

		CloseServiceHandle(service);
	}

	CloseServiceHandle(sc);

	if (ret)
		SleepThread(2000);

	return ret;
}

bool MsIsServiceInstalled(char *name) {
	bool ret = false;
	if (name == NULL)
		return false;

	SC_HANDLE sc = OpenSCManager(NULL, NULL, GENERIC_READ);
	if (sc == NULL)
		return false;

	SC_HANDLE service = OpenService(sc, name, GENERIC_READ);
	if (service != NULL)
		ret = true;

	CloseServiceHandle(service);
	CloseServiceHandle(sc);

	return ret;
}
