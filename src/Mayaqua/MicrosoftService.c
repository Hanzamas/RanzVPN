// MicrosoftService.c
// Windows services: service host, user mode, SCM install, start and stop, global pulse

#ifdef OS_WIN32

#define	MICROSOFT_C

#include "Microsoft.h"

#include "Cfg.h"
#include "FileIO.h"
#include "GlobalConst.h"
#include "Internat.h"
#include "Memory.h"
#include "Object.h"
#include "Str.h"
#include "Table.h"
#include "Tick64.h"
#include "Win32.h"

#define SECURITY_WIN32

#include <AclAPI.h>
#include <DbgHelp.h>
#include <dwmapi.h>
#include <iphlpapi.h>
#include <mmsystem.h>
#include <Msi.h>
#include <nb30.h>
#include <NTSecAPI.h>
#include <Psapi.h>
#include <sddl.h>
#include <security.h>
#include <shellapi.h>
#include <ShlObj.h>
#include <SoftPub.h>
#include <WtsApi32.h>

void MsSendGlobalPulse(void *p)
{
	HANDLE h;
	if (p == NULL)
	{
		return;
	}

	h = (HANDLE)p;

	PulseEvent(h);
}

void MsCloseGlobalPulse(void *p)
{
	HANDLE h;
	if (p == NULL)
	{
		return;
	}

	h = (HANDLE)p;

	CloseHandle(h);
}

bool MsWaitForGlobalPulse(void *p, UINT timeout)
{
	HANDLE h;
	UINT ret;
	if (p == NULL)
	{
		return false;
	}
	if (timeout == TIMEOUT_INFINITE)
	{
		timeout = INFINITE;
	}

	h = (HANDLE)p;

	ret = WaitForSingleObject(h, timeout);

	if (ret == WAIT_OBJECT_0)
	{
		return true;
	}

	return false;
}

void *MsOpenOrCreateGlobalPulse(char *name)
{
	UCHAR hash[20];
	char tmp[MAX_SIZE];
	char tmp2[MAX_SIZE];
	HANDLE h;
	if (name == NULL)
	{
		return NULL;
	}

	StrCpy(tmp, sizeof(tmp), name);
	Trim(tmp);
	StrUpper(tmp);

	Sha1(hash, name, StrLen(name));

	BinToStr(tmp, sizeof(tmp), hash, sizeof(hash));
	Format(tmp2, sizeof(tmp2), "Global\\GlobalPulse_%s", tmp);

	h = CreateEvent(NULL, true, false, tmp2);

	return (void *)h;
}

void *MsCreateUserModeSvcGlocalPulse(char *svc_name)
{
	char name[MAX_SIZE];
	if (svc_name == NULL)
	{
		return NULL;
	}

	MsGenerateUserModeSvcGlobalPulseName(name, sizeof(name), svc_name);

	return MsOpenOrCreateGlobalPulse(name);
}

void MsGenerateUserModeSvcGlobalPulseName(char *name, UINT size, char *svc_name)
{
	wchar_t tmp[MAX_SIZE];
	UCHAR hash[SHA1_SIZE];
	if (name == NULL || svc_name == NULL)
	{
		return;
	}

	UniFormat(tmp, sizeof(tmp), L"usersvc_%S_@_%s", svc_name, MsGetUserNameW());

	UniTrim(tmp);
	UniStrUpper(tmp);

	Sha1(hash, tmp, UniStrLen(tmp) * sizeof(wchar_t));

	BinToStr(name, size, hash, sizeof(hash));
}

void MsUserModeGlobalPulseRecvThread(THREAD *thread, void *param)
{
	MS_USERMODE_SVC_PULSE_THREAD_PARAM *p = (MS_USERMODE_SVC_PULSE_THREAD_PARAM *)param;
	if (thread == NULL || p == NULL)
	{
		return;
	}

	while (p->Halt == false)
	{
		if (MsWaitForGlobalPulse(p->GlobalPulse, INFINITE))
		{
			break;
		}
	}

	if (p->hWnd != NULL)
	{
		PostMessageA(p->hWnd, WM_CLOSE, 0, 0);
	}
}

void MsWriteCallingServiceManagerProcessId(char *svcname, UINT pid)
{
	char tmp[MAX_PATH];

	Format(tmp, sizeof(tmp), SVC_CALLING_SM_PROCESS_ID_KEY, svcname);

	if (pid != 0)
	{
		MsRegWriteInt(REG_LOCAL_MACHINE, tmp, SVC_CALLING_SM_PROCESS_ID_VALUE, pid);
		MsRegWriteInt(REG_CURRENT_USER, tmp, SVC_CALLING_SM_PROCESS_ID_VALUE, pid);
	}
	else
	{
		MsRegDeleteValue(REG_LOCAL_MACHINE, tmp, SVC_CALLING_SM_PROCESS_ID_VALUE);
		MsRegDeleteKeyEx2(REG_LOCAL_MACHINE, tmp, false, false);

		MsRegDeleteValue(REG_CURRENT_USER, tmp, SVC_CALLING_SM_PROCESS_ID_VALUE);
		MsRegDeleteKeyEx2(REG_CURRENT_USER, tmp, false, false);
	}
}

bool MsStopService(char *name)
{
	SC_HANDLE sc, service;
	bool ret = false;
	if (name == NULL)
	{
		return false;
	}

	sc = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
	if (sc == NULL)
	{
		return false;
	}

	service = OpenService(sc, name, SERVICE_ALL_ACCESS);
	if (service != NULL)
	{
		SERVICE_STATUS st;
		ret = ControlService(service, SERVICE_CONTROL_STOP, &st);

		CloseServiceHandle(service);
	}

	if (ret)
	{
		UINT64 end = Tick64() + 10000ULL;
		while (Tick64() < end)
		{
			if (MsIsServiceRunning(name) == false)
			{
				break;
			}

			SleepThread(250);
		}
	}

	CloseServiceHandle(sc);
	return ret;
}

bool MsStartService(char *name)
{
	return MsStartServiceEx(name, NULL);
}

bool MsStartServiceEx(char *name, UINT *error_code)
{
	SC_HANDLE sc, service;
	bool ret = false;
	static UINT dummy = 0;
	if (name == NULL)
	{
		return false;
	}

	if (error_code == NULL)
	{
		error_code = &dummy;
	}

	*error_code = 0;

	sc = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
	if (sc == NULL)
	{
		*error_code = GetLastError();
		return false;
	}

	service = OpenService(sc, name, SERVICE_ALL_ACCESS);
	if (service != NULL)
	{
		ret = StartService(service, 0, NULL);

		CloseServiceHandle(service);
	}
	else
	{
		*error_code = GetLastError();
	}

	if (ret)
	{
		UINT64 end = Tick64() + 10000ULL;
		while (Tick64() < end)
		{
			if (MsIsServiceRunning(name))
			{
				break;
			}

			SleepThread(250);
		}
	}

	CloseServiceHandle(sc);
	return ret;
}

bool MsIsServiceRunning(char *name)
{
	SC_HANDLE sc, service;
	bool ret = false;
	if (name == NULL || IsEmptyStr(name))
	{
		return false;
	}

	sc = OpenSCManager(NULL, NULL, GENERIC_READ);
	if (sc == NULL)
	{
		return false;
	}

	service = OpenService(sc, name, GENERIC_READ);
	if (service != NULL)
	{
		SERVICE_STATUS st;
		Zero(&st, sizeof(st));
		if (QueryServiceStatus(service, &st))
		{
			switch (st.dwCurrentState)
			{
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

bool MsUninstallService(char *name)
{
	SC_HANDLE sc, service;
	bool ret = false;
	if (name == NULL)
	{
		return false;
	}

	MsStopService(name);

	sc = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
	if (sc == NULL)
	{
		return false;
	}

	service = OpenService(sc, name, SERVICE_ALL_ACCESS);
	if (service != NULL)
	{
		if (DeleteService(service))
		{
			ret = true;
		}
		CloseServiceHandle(service);
	}

	CloseServiceHandle(sc);

	if (ret)
	{
		SleepThread(2000);
	}

	return ret;
}

bool MsUpdateServiceConfig(char *name)
{
	SC_HANDLE sc, service;
	if (name == NULL)
	{
		return false;
	}

	// Shortly after Windows startup (prevents a deadlock)
	if (timeGetTime() <= (60 * 30 * 1000))
	{
		if (MsRegReadInt(REG_LOCAL_MACHINE, "Software\\" GC_REG_COMPANY_NAME "\\Update Service Config", name) != 0)
		{
			return false;
		}
	}

	sc = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
	if (sc == NULL)
	{
		return false;
	}

	service = OpenService(sc, name, SERVICE_ALL_ACCESS);
	if (service != NULL)
	{
		if (GET_KETA(GetOsInfo()->OsType, 100) >= 2)
		{
			SERVICE_FAILURE_ACTIONS action;
			SC_ACTION *e;
			Zero(&action, sizeof(action));
			e = ZeroMalloc(sizeof(SC_ACTION) * 3);
			e[0].Delay = 10000; e[0].Type = SC_ACTION_RESTART;
			e[1].Delay = 10000; e[1].Type = SC_ACTION_RESTART;
			e[2].Delay = 10000; e[2].Type = SC_ACTION_RESTART;
			action.cActions = 3;
			action.lpsaActions = e;
			action.dwResetPeriod = 1 * 60 * 60 * 24;
			ChangeServiceConfig2(service, SERVICE_CONFIG_FAILURE_ACTIONS, &action);

			MsRegWriteInt(REG_LOCAL_MACHINE, "Software\\" GC_REG_COMPANY_NAME "\\Update Service Config", name, 1);
		}

		
		if (GET_KETA(GetOsInfo()->OsType, 100) >= 2)
		{
			SERVICE_DESCRIPTIONW d;
			wchar_t *description;
			char dname[MAX_SIZE];

			Format(dname, sizeof(dname), "SVC_%s_DESCRIPT", name);

			description = _UU(dname);

			if (UniIsEmptyStr(description) == false)
			{
				Zero(&d, sizeof(d));
				d.lpDescription = description;
				ChangeServiceConfig2(service, SERVICE_CONFIG_DESCRIPTION, &d);
			}
		}

		CloseServiceHandle(service);
	}

	CloseServiceHandle(sc);

	return true;
}

bool MsInstallServiceExW(char *name, wchar_t *title, wchar_t *description, wchar_t *path, UINT *error_code)
{
	SC_HANDLE sc, service;
	bool ret = false;
	wchar_t name_w[MAX_SIZE];
	static UINT temp_int = 0;
	if (name == NULL || title == NULL || path == NULL)
	{
		return false;
	}

	if (error_code == NULL)
	{
		error_code = &temp_int;
	}

	*error_code = 0;

	StrToUni(name_w, sizeof(name_w), name);

	sc = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
	if (sc == NULL)
	{
		*error_code = GetLastError();
		return false;
	}

	service = CreateServiceW(sc, name_w, title, SERVICE_ALL_ACCESS,
		SERVICE_WIN32_OWN_PROCESS, SERVICE_AUTO_START,
		SERVICE_ERROR_NORMAL, path, NULL, NULL, NULL, NULL, NULL);

	if (service != NULL)
	{
		ret = true;

		if (GET_KETA(GetOsInfo()->OsType, 100) >= 2)
		{
			SERVICE_DESCRIPTIONW d;
			SERVICE_FAILURE_ACTIONS action;
			SC_ACTION *e;
			Zero(&d, sizeof(d));
			d.lpDescription = description;
			ChangeServiceConfig2(service, SERVICE_CONFIG_DESCRIPTION, &d);
			Zero(&action, sizeof(action));
			e = ZeroMalloc(sizeof(SC_ACTION) * 3);
			e[0].Delay = 10000; e[0].Type = SC_ACTION_RESTART;
			e[1].Delay = 10000; e[1].Type = SC_ACTION_RESTART;
			e[2].Delay = 10000; e[2].Type = SC_ACTION_RESTART;
			action.cActions = 3;
			action.lpsaActions = e;
			action.dwResetPeriod = 1 * 60 * 60 * 24;
			ChangeServiceConfig2(service, SERVICE_CONFIG_FAILURE_ACTIONS, &action);

			Free(e);
		}

		CloseServiceHandle(service);
	}
	else
	{
		*error_code = GetLastError();
	}

	CloseServiceHandle(sc);

	if (ret)
	{
		SleepThread(2000);
	}

	return ret;
}

bool MsIsServiceInstalled(char *name)
{
	SC_HANDLE sc;
	SC_HANDLE service;
	bool ret = false;
	if (name == NULL)
	{
		return false;
	}

	sc = OpenSCManager(NULL, NULL, GENERIC_READ);
	if (sc == NULL)
	{
		return false;
	}

	service = OpenService(sc, name, GENERIC_READ);
	if (service != NULL)
	{
		ret = true;
	}

	CloseServiceHandle(service);
	CloseServiceHandle(sc);

	return ret;
}

#endif	// WIN32

