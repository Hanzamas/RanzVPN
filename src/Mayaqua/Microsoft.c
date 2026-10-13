// Microsoft.c
// For Microsoft Windows code
// (not compiled on non-Windows environments)

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

static MS *ms = NULL;

static SERVICE_STATUS_HANDLE ssh = NULL;
static SERVICE_STATUS status = { 0 };
static HANDLE service_stop_event = NULL;
static BOOL (WINAPI *_StartServiceCtrlDispatcher)(CONST LPSERVICE_TABLE_ENTRY) = NULL;
static SERVICE_STATUS_HANDLE (WINAPI *_RegisterServiceCtrlHandler)(LPCTSTR, LPHANDLER_FUNCTION) = NULL;
static BOOL (WINAPI *_SetServiceStatus)(SERVICE_STATUS_HANDLE, LPSERVICE_STATUS) = NULL;
static char g_service_name[MAX_SIZE];
static SERVICE_FUNCTION *g_start, *g_stop;
static bool exiting = false;
static bool wnd_end;
static bool is_usermode = false;
static HWND hWndUsermode = NULL;
static HANDLE hLsa = NULL;
static ULONG lsa_package_id = 0;
static TOKEN_SOURCE lsa_token_source;

static HINSTANCE hMsi = NULL;
static UINT (WINAPI *_MsiGetProductInfoW)(LPCWSTR, LPCWSTR, LPWSTR, LPDWORD) = NULL;
static UINT (WINAPI *_MsiConfigureProductW)(LPCWSTR, int, INSTALLSTATE) = NULL;
static INSTALLUILEVEL (WINAPI *_MsiSetInternalUI)(INSTALLUILEVEL, HWND *) = NULL;
static INSTALLSTATE (WINAPI *_MsiLocateComponentW)(LPCWSTR, LPWSTR, LPDWORD) = NULL;

void MsInitProcessCallOnce()
{
	// Mitigate DLL injection attacks
	char system_dir[MAX_PATH];
	char kernel32_path[MAX_PATH];
	UINT len;
	HINSTANCE hKernel32;

	memset(system_dir, 0, sizeof(system_dir));
	GetSystemDirectory(system_dir, sizeof(system_dir));
	len = lstrlenA(system_dir);
	if (system_dir[len] == '\\')
	{
		system_dir[len] = 0;
	}
	wsprintfA(kernel32_path, "%s\\kernel32.dll", system_dir);

	hKernel32 = LoadLibraryA(kernel32_path);
	if (hKernel32 != NULL)
	{
		BOOL (WINAPI *_SetDllDirectoryA)(LPCTSTR);

		_SetDllDirectoryA = (BOOL (WINAPI *)(LPCTSTR))
			GetProcAddress(hKernel32, "SetDllDirectoryA");

		if (_SetDllDirectoryA != NULL)
		{
			_SetDllDirectoryA("");
		}

		FreeLibrary(hKernel32);
	}
}


LRESULT CALLBACK MsUserModeWindowProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
	if (hWnd == NULL)
	{
		return 0;
	}

	switch (msg)
	{
	case WM_ENDSESSION:
		if (wParam == false)
		{
			break;
		}
	case WM_CREATE:
		exiting = false;
		g_start();
		break;
	case WM_QUERYENDSESSION:
		if (exiting == false)
		{
			exiting = true;
			g_stop();
			DestroyWindow(hWnd);
		}
		return TRUE;
	case WM_CLOSE:
		if (exiting == false)
		{
			exiting = true;
			g_stop();
			DestroyWindow(hWnd);
		}
		break;
	case WM_DESTROY:
		wnd_end = true;
		break;
	}
	return DefWindowProc(hWnd, msg, wParam, lParam);
}

bool MsIsUserMode()
{
	return is_usermode;
}

void MsUserModeW(wchar_t *title, SERVICE_FUNCTION *start, SERVICE_FUNCTION *stop, UINT icon)
{
	WNDCLASS wc;
	HWND hWnd;
	MSG msg;
	INSTANCE *inst;
	char title_a[MAX_PATH];
	wchar_t msg_str[MAX_SIZE];
	MS_USERMODE_SVC_PULSE_THREAD_PARAM p;
	THREAD *recv_thread = NULL;
	if (title == NULL || start == NULL || stop == NULL)
	{
		return;
	}

	UniToStr(title_a, sizeof(title_a), title);

	is_usermode = true;
	g_start = start;
	g_stop = stop;

	inst = NewSingleInstance(NULL);
	if (inst == NULL)
	{
		UniFormat(msg_str, sizeof(msg_str), _UU("SVC_USERMODE_MUTEX"), ms->ExeFileNameW);
		UniPrint(L"%s\n", msg_str);
		return;
	}

	Zero(&wc, sizeof(wc));
	wc.hbrBackground = (HBRUSH)GetStockObject(WHITE_BRUSH);
	wc.hCursor = LoadCursor(NULL,IDC_ARROW);
	wc.hInstance = ms->hInst;
	wc.lpfnWndProc = MsUserModeWindowProc;
	wc.lpszClassName = title_a;
	if (RegisterClass(&wc) == 0)
	{
		return;
	}

	hWnd = CreateWindow(title_a, title_a, WS_OVERLAPPEDWINDOW,
		CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT,
		NULL, NULL, ms->hInst, NULL);

	if (hWnd == NULL)
	{
		return;
	}

	Zero(&p, sizeof(p));
	p.hWnd = hWnd;
	p.GlobalPulse = MsCreateUserModeSvcGlocalPulse(g_service_name);

	if (p.GlobalPulse != NULL)
	{
		p.Halt = false;

		recv_thread = NewThread(MsUserModeGlobalPulseRecvThread, &p);
	}

	hWndUsermode = hWnd;

	wnd_end = false;
	while (wnd_end == false)
	{
		GetMessage(&msg, NULL, 0, 0);
		TranslateMessage(&msg);
		DispatchMessage(&msg);
	}

	FreeSingleInstance(inst);

	p.hWnd = NULL;

	hWndUsermode = NULL;

	if (p.GlobalPulse != NULL)
	{
		p.Halt = true;
		MsSendGlobalPulse(p.GlobalPulse);

		WaitThread(recv_thread, INFINITE);
		ReleaseThread(recv_thread);

		MsCloseGlobalPulse(p.GlobalPulse);
	}

	_exit(0);
}

void MsServiceStoperMainThread(THREAD *t, void *p)
{
	g_stop();
}

bool MsServiceStopProc()
{
	THREAD *thread;
	bool ret = true;
	UINT64 selfkill_timeout = Tick64() + SVC_SELFKILL_TIMEOUT;

	thread = NewThread(MsServiceStoperMainThread, NULL);

	while (WaitThread(thread, 250) == false)
	{
		if (Tick64() >= selfkill_timeout)
		{
			ret = false;
			break;
		}
		status.dwWin32ExitCode = 0;
		status.dwWaitHint = 100000;
		status.dwCheckPoint++;
		status.dwCurrentState = SERVICE_STOP_PENDING;
		_SetServiceStatus(ssh, &status);
	}

	status.dwWin32ExitCode = 0;
	status.dwWaitHint = 0;
	status.dwCheckPoint = 0;
	status.dwCurrentState = SERVICE_STOPPED;
	_SetServiceStatus(ssh, &status);

	if (ret == false)
	{
		// The self-kill timeout fired: force an exit
		_exit(-1);
	}
	else
	{
		ReleaseThread(thread);
	}

	return ret;
}

void CALLBACK MsServiceHandler(DWORD opcode)
{
	switch (opcode)
	{
	case SERVICE_CONTROL_SHUTDOWN:
	case SERVICE_CONTROL_STOP:
		status.dwWin32ExitCode = 0;
		status.dwWaitHint = 100000;
		status.dwCheckPoint = 0;
		status.dwCurrentState = SERVICE_STOP_PENDING;

		if (service_stop_event != NULL)
		{
			SetEvent(service_stop_event);
		}
		break;
	}

	_SetServiceStatus(ssh, &status);
}

void CALLBACK MsServiceDispatcher(DWORD argc, LPTSTR *argv)
{
	service_stop_event = CreateEventA(NULL, true, false, NULL);

	Zero(&status, sizeof(status));
	status.dwServiceType = SERVICE_WIN32;
	status.dwCurrentState = SERVICE_START_PENDING;
	status.dwControlsAccepted = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN;

	ssh = _RegisterServiceCtrlHandler(g_service_name, MsServiceHandler);

	if (ssh == NULL)
	{
		MessageBox(NULL, "RegisterServiceCtrlHandler() Failed.", "MsServiceDispatcher()", MB_SETFOREGROUND | MB_TOPMOST | MB_SERVICE_NOTIFICATION | MB_OK | MB_ICONEXCLAMATION);
		return;
	}

	status.dwWaitHint = 300000;
	status.dwCheckPoint = 0;
	status.dwCheckPoint++;
	status.dwCurrentState = SERVICE_START_PENDING;
	_SetServiceStatus(ssh, &status);

	status.dwWaitHint = 0;
	status.dwCheckPoint = 0;
	status.dwCurrentState = SERVICE_RUNNING;
	_SetServiceStatus(ssh, &status);

#if defined(_DEBUG) || defined(DEBUG)	// In VC++ compilers, the macro is "_DEBUG", not "DEBUG".
	// memcheck = true logs every malloc/realloc/free to find leaks, but is very slow.
	InitMayaqua(false, true, 0, NULL);
#else
	InitMayaqua(false, false, 0, NULL);
#endif

	MsDisableIme();

	g_start();
	MsUpdateServiceConfig(g_service_name);

	WaitForSingleObject(service_stop_event, INFINITE);

	MsServiceStopProc();
}

void MsTestModeW(wchar_t *title, SERVICE_FUNCTION *start, SERVICE_FUNCTION *stop)
{
	INSTANCE *inst;
	wchar_t msg[MAX_SIZE];
	if (title == NULL || start == NULL || stop == NULL)
	{
		return;
	}

	is_usermode = true;

	inst = NewSingleInstance(NULL);
	if (inst == NULL)
	{
		UniFormat(msg, sizeof(msg), _UU("SVC_TEST_MUTEX"), ms->ExeFileNameW);
		UniPrint(L"%s\n", msg);
		return;
	}

	start();

	UniFormat(msg, sizeof(msg), _UU("SVC_TEST_MSG"), title);
	UniPrint(L"%s\n", msg);
	GetLine(NULL, 0);

	stop();

	FreeSingleInstance(inst);
}

UINT MsService(char *name, SERVICE_FUNCTION *start, SERVICE_FUNCTION *stop, UINT icon, char *cmd_line)
{
	UINT mode;
	UINT ret = 0;
	char *arg;
	TOKEN_LIST *t = NULL;
	char *service_name;
	wchar_t *service_title;
	wchar_t *service_description;
	char tmp[MAX_SIZE];
	wchar_t msg[MAX_SIZE * 4];
	bool restoreReg = false;
	bool silent = false;
	bool is_win32_service_mode = false;
	if (name == NULL || start == NULL || stop == NULL)
	{
		return ret;
	}

	g_start = start;
	g_stop = stop;
	StrCpy(g_service_name, sizeof(g_service_name), name);
	StrLower(g_service_name);

	if (cmd_line != NULL && lstrcmpiA(cmd_line, SVC_ARG_SERVICE) == 0)
	{
		HINSTANCE h_advapi32 = LoadLibraryA("advapi32.dll");

		if (h_advapi32 != NULL)
		{
			_StartServiceCtrlDispatcher =
				(BOOL (__stdcall *)(const LPSERVICE_TABLE_ENTRY))
				GetProcAddress(h_advapi32, "StartServiceCtrlDispatcherW");

			_RegisterServiceCtrlHandler =
				(SERVICE_STATUS_HANDLE (__stdcall *)(LPCTSTR,LPHANDLER_FUNCTION))
				GetProcAddress(h_advapi32, "RegisterServiceCtrlHandlerW");

			_SetServiceStatus =
				(BOOL (__stdcall *)(SERVICE_STATUS_HANDLE,LPSERVICE_STATUS))
				GetProcAddress(h_advapi32, "SetServiceStatus");

			if (_StartServiceCtrlDispatcher != NULL &&
				_RegisterServiceCtrlHandler != NULL && 
				_SetServiceStatus != NULL)
			{
				is_win32_service_mode = true;
			}
		}
	}

	if (is_win32_service_mode)
	{
		SERVICE_TABLE_ENTRY dispatch_table[] =
		{
			{"", MsServiceDispatcher},
			{NULL, NULL},
		};

		SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX | SEM_NOOPENFILEERRORBOX);

		if (_StartServiceCtrlDispatcher(dispatch_table) == false)
		{
			MessageBox(NULL, "StartServiceCtrlDispatcher() Failed.", "MsServiceMode()", MB_SETFOREGROUND | MB_TOPMOST | MB_SERVICE_NOTIFICATION | MB_OK | MB_ICONEXCLAMATION);
		}
		else
		{
			MsUpdateServiceConfig(g_service_name);
		}

		_exit(0);
		return 0;
	}

#if defined(_DEBUG) || defined(DEBUG)	// In VC++ compilers, the macro is "_DEBUG", not "DEBUG".
	// memcheck = true logs every malloc/realloc/free to find leaks, but is very slow.
	InitMayaqua(false, true, 0, NULL);
#else
	InitMayaqua(false, false, 0, NULL);
#endif

	MsDisableIme();

	Format(tmp, sizeof(tmp), SVC_NAME, name);
	service_name = _SS(tmp);
	Format(tmp, sizeof(tmp), SVC_TITLE, name);
	service_title = _UU(tmp);
	Format(tmp, sizeof(tmp), SVC_DESCRIPT, name);
	service_description = _UU(tmp);

	if (StrLen(service_name) == 0 || UniStrLen(service_title) == 0)
	{
		UniFormat(msg, sizeof(msg), _UU("SVC_NOT_FOUND"), name);
		UniPrint(L"%s\n", msg);
	}
	else
	{
		wchar_t path[MAX_SIZE];
		mode = SVC_MODE_NONE;

		t = GetCommandLineToken();
		arg = NULL;

		if (t->NumTokens >= 1)
		{
			arg = t->Token[0];
		}
		if(t->NumTokens >= 2)
		{
			if(StrCmpi(t->Token[1], SVC_ARG_SILENT) == 0)
			{
				silent = true;
			}
		}

		if (arg != NULL)
		{
			if (StrCmpi(arg, SVC_ARG_INSTALL) == 0)
			{
				mode = SVC_MODE_INSTALL;
			}
			if (StrCmpi(arg, SVC_ARG_UNINSTALL) == 0)
			{
				mode = SVC_MODE_UNINSTALL;
			}
			if (StrCmpi(arg, SVC_ARG_START) == 0)
			{
				mode = SVC_MODE_START;
			}
			if (StrCmpi(arg, SVC_ARG_STOP) == 0)
			{
				mode = SVC_MODE_STOP;
			}
			if (StrCmpi(arg, SVC_ARG_TEST) == 0)
			{
				mode = SVC_MODE_TEST;
			}
			if (StrCmpi(arg, SVC_ARG_USERMODE) == 0)
			{
				mode = SVC_MODE_USERMODE;
			}
			if (StrCmpi(arg, SVC_ARG_SETUP_INSTALL) == 0)
			{
				mode = SVC_MODE_SETUP_INSTALL;
			}
			if (StrCmpi(arg, SVC_ARG_SETUP_UNINSTALL) == 0)
			{
				mode = SVC_MODE_SETUP_UNINSTALL;
			}
			if (StrCmpi(arg, SVC_ARG_USERMODE_SHOWTRAY) == 0 || StrCmpi(arg, SVC_ARG_USERMODE_HIDETRAY) == 0)
			{
				// Legacy arguments: there is no task tray icon any more, so these are the same as /usermode
				mode = SVC_MODE_USERMODE;
			}
			if (StrCmpi(arg, SVC_ARG_SERVICE) == 0)
			{
				mode = SVC_MODE_SERVICE;
			}

			if (mode != SVC_MODE_NONE)
			{
				MsInitGlobalNetworkConfig();
			}
		}

		UniFormat(path, sizeof(path), SVC_RUN_COMMANDLINE, ms->ExeFileNameW);

		if ((mode == SVC_MODE_INSTALL || mode == SVC_MODE_UNINSTALL || mode == SVC_MODE_START ||
			mode == SVC_MODE_STOP || mode == SVC_MODE_SERVICE) &&
			(ms->IsAdmin == false))
		{
			UniPrint(L"%s\n", _UU("SVC_NOT_ADMIN"));
		}
		else
		{
			switch (mode)
			{
			case SVC_MODE_NONE:
				UniFormat(msg, sizeof(msg), _UU("SVC_HELP"),
					service_title, service_name, service_title, service_title, service_name, service_title, service_name, service_title, service_name, service_title, service_name, service_title, service_title);
				UniPrint(L"%s\n", msg);
				break;

			case SVC_MODE_SETUP_INSTALL:
				MsWriteCallingServiceManagerProcessId(service_name, MsGetCurrentProcessId());
				restoreReg = true;

				if (MsIsServiceInstalled(service_name))
				{
					if (MsIsServiceRunning(service_name))
					{
						MsStopService(service_name);
					}
					MsUninstallService(service_name);
				}
				if (MsInstallServiceExW(service_name, service_title, service_description, path, NULL) == false)
				{
					ret = 1;
				}
				MsStartService(service_name);
				MsWriteCallingServiceManagerProcessId(service_name, 0);
				break;

			case SVC_MODE_SETUP_UNINSTALL:
				MsWriteCallingServiceManagerProcessId(service_name, MsGetCurrentProcessId());
				restoreReg = true;

				if (MsIsServiceInstalled(service_name))
				{
					if (MsIsServiceRunning(service_name))
					{
						MsStopService(service_name);
					}
					if (MsUninstallService(service_name) == false)
					{
						ret = 1;
					}
				}
				break;

			case SVC_MODE_INSTALL:
				MsWriteCallingServiceManagerProcessId(service_name, MsGetCurrentProcessId());
				restoreReg = true;

				if (MsIsServiceInstalled(service_name))
				{
					if(silent == true)
					{
						break;
					}
					// The operator explicitly requested /install, so uninstall and then re-install
					UniFormat(msg, sizeof(msg), _UU("SVC_ALREADY_INSTALLED"),
						service_title, service_name);
					UniPrint(L"%s\n", msg);

					if (MsIsServiceRunning(service_name))
					{
						if (MsStopService(service_name) == false)
						{
							if(silent == false)
							{
								UniFormat(msg, sizeof(msg), _UU("SVC_STOP_FAILED"),
									service_title, service_name);
								UniPrint(L"%s\n", msg);
							}
							break;
						}
					}
					if (MsUninstallService(service_name) == false)
					{
						if(silent == false)
						{
							UniFormat(msg, sizeof(msg), _UU("SVC_UNINSTALL_FAILED"),
								service_title, service_name);
							UniPrint(L"%s\n", msg);
						}
						break;
					}
				}

				if (MsInstallServiceExW(service_name, service_title, service_description, path, NULL) == false)
				{
					if(silent == false)
					{
						UniFormat(msg, sizeof(msg), _UU("SVC_INSTALL_FAILED"),
							service_title, service_name);
						UniPrint(L"%s\n", msg);
					}
					break;
				}

				if (MsStartService(service_name) == false)
				{
					if(silent == false)
					{
						UniFormat(msg, sizeof(msg), _UU("SVC_INSTALL_FAILED_2"),
							service_title, service_name, path);
						UniPrint(L"%s\n", msg);
					}
					break;
				}

				if(silent == false)
				{
					UniFormat(msg, sizeof(msg), _UU("SVC_INSTALL_OK"),
						service_title, service_name, path);
					UniPrint(L"%s\n", msg);
				}
				break;

			case SVC_MODE_UNINSTALL:
				MsWriteCallingServiceManagerProcessId(service_name, MsGetCurrentProcessId());
				restoreReg = true;

				if (MsIsServiceInstalled(service_name) == false)
				{
					if(silent == false)
					{
						UniFormat(msg, sizeof(msg), _UU("SVC_NOT_INSTALLED"),
							service_title, service_name, path);
						UniPrint(L"%s\n", msg);
					}
					break;
				}

				if (MsIsServiceRunning(service_name))
				{
					if (MsStopService(service_name) == false)
					{
						if(silent == false)
						{
							UniFormat(msg, sizeof(msg), _UU("SVC_STOP_FAILED"),
								service_title, service_name);
							UniPrint(L"%s\n", msg);
						}
						break;
					}
				}

				if (MsUninstallService(service_name) == false)
				{
					if(silent == false)
					{
						UniFormat(msg, sizeof(msg), _UU("SVC_UNINSTALL_FAILED"),
							service_title, service_name);
						UniPrint(L"%s\n", msg);
					}
					break;
				}

				if(silent == false)
				{
					UniFormat(msg, sizeof(msg), _UU("SVC_UNINSTALL_OK"),
						service_title, service_name);
					UniPrint(L"%s\n", msg);
				}
				break;

			case SVC_MODE_START:
				MsWriteCallingServiceManagerProcessId(service_name, MsGetCurrentProcessId());
				restoreReg = true;

				if (MsIsServiceInstalled(service_name) == false)
				{
					if(silent == false)
					{
						UniFormat(msg, sizeof(msg), _UU("SVC_NOT_INSTALLED"),
							service_title, service_name);
						UniPrint(L"%s\n", msg);
					}
					break;
				}

				if (MsIsServiceRunning(service_name))
				{
					if(silent == false)
					{
						UniFormat(msg, sizeof(msg), _UU("SVR_ALREADY_START"),
							service_title, service_name);
						UniPrint(L"%s\n", msg);
					}
					break;
				}

				if (MsStartService(service_name) == false)
				{
					if(silent == false)
					{
						UniFormat(msg, sizeof(msg), _UU("SVC_START_FAILED"),
							service_title, service_name);
						UniPrint(L"%s\n", msg);
					}
					break;
				}

				if(silent == false)
				{
					UniFormat(msg, sizeof(msg), _UU("SVC_START_OK"),
						service_title, service_name);
					UniPrint(L"%s\n", msg);
				}
				break;

			case SVC_MODE_STOP:
				MsWriteCallingServiceManagerProcessId(service_name, MsGetCurrentProcessId());
				restoreReg = true;

				if (MsIsServiceInstalled(service_name) == false)
				{
					if(silent == false)
					{
						UniFormat(msg, sizeof(msg), _UU("SVC_NOT_INSTALLED"),
							service_title, service_name);
						UniPrint(L"%s\n", msg);
					}
					break;
				}

				if (MsIsServiceRunning(service_name) == false)
				{
					if(silent == false)
					{
					UniFormat(msg, sizeof(msg), _UU("SVC_ALREADY_STOP"),
						service_title, service_name);
					UniPrint(L"%s\n", msg);
					}
					break;
				}
				if (MsStopService(service_name) == false)
				{
					if(silent == false)
					{
						UniFormat(msg, sizeof(msg), _UU("SVC_STOP_FAILED"),
							service_title, service_name);
						UniPrint(L"%s\n", msg);
					}
					break;
				}

				if(silent == false)
				{
					UniFormat(msg, sizeof(msg), _UU("SVC_STOP_OK"),
						service_title, service_name);
					UniPrint(L"%s\n", msg);
				}
				break;

			case SVC_MODE_TEST:
				MsTestModeW(service_title, start, stop);
				break;
			case SVC_MODE_USERMODE:
				MsUserModeW(service_title, start, stop, icon);
				break;
			case SVC_MODE_SERVICE:
				break;
			}

		}
		FreeToken(t);

		if (restoreReg)
		{
			MsWriteCallingServiceManagerProcessId(service_name, 0);
		}
	}

	FreeMayaqua();

	return 0;
}

void MsDeleteTempDir()
{
	HANDLE h;
	wchar_t dir_mask[MAX_PATH];
	WIN32_FIND_DATAW data_w;

	Zero(&data_w, sizeof(data_w));

	UniFormat(dir_mask, sizeof(dir_mask), L"%s\\*", ms->TempDirW);

	h = FindFirstFileW(dir_mask, &data_w);

	if (h != INVALID_HANDLE_VALUE)
	{
		bool b = true;

		do
		{
			if (UniStrCmpi(data_w.cFileName, L".") != 0 &&
				UniStrCmpi(data_w.cFileName, L"..") != 0)
			{
				if (data_w.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
				{
					if (UniStartWith(data_w.cFileName, L"VPN_") && UniStrLen(data_w.cFileName) == 8)
					{
						wchar_t lock_file_name[MAX_PATH];
						wchar_t dir_name[MAX_PATH];
						bool delete_now = false;
						IO *io;

						UniFormat(dir_name, sizeof(dir_name), L"%s\\%s",
							ms->TempDirW, data_w.cFileName);
						MsGenLockFile(lock_file_name, sizeof(lock_file_name), dir_name);

						io = FileOpenExW(lock_file_name, false, false);
						if (io != NULL)
						{
							FileClose(io);
							io = FileOpenW(lock_file_name, true);
							if (io != NULL)
							{
								delete_now = true;
								FileClose(io);
							}
						}
						else
						{
							DIRLIST *d;

							delete_now = true;

							d = EnumDirW(dir_name);
							if (d != NULL)
							{
								UINT i;

								for (i = 0;i < d->NumFiles;i++)
								{
									wchar_t full_path[MAX_PATH];

									UniFormat(full_path, sizeof(full_path), L"%s\\%s", dir_name, d->File[i]->FileNameW);

									io = FileOpenW(full_path, true);
									if (io != NULL)
									{
										delete_now = true;
										FileClose(io);
									}
								}
								FreeDir(d);
							}
						}
						if (delete_now)
						{
							MsDeleteAllFileW(dir_name);

							Win32DeleteDirW(dir_name);
						}
					}
				}
			}


			Zero(&data_w, sizeof(data_w));

			b = FindNextFileW(h, &data_w);
		}
		while (b);

		FindClose(h);
	}
}

void MsInitTempDir()
{
	wchar_t tmp[MAX_PATH];
	wchar_t tmp2[16];
	UCHAR random[2];
	wchar_t lockfilename[MAX_PATH];
	UINT num = 0;

	MsDeleteTempDir();

	while (true)
	{
		random[0] = rand() % 256;
		random[1] = rand() % 256;
		BinToStrW(tmp2, sizeof(tmp2), random, sizeof(random));

		UniFormat(tmp, sizeof(tmp), L"%s\\VPN_%s", ms->TempDirW, tmp2);

		if (MakeDirW(tmp))
		{
			break;
		}

		if ((num++) >= 100)
		{
			char msg[MAX_SIZE];
			Format(msg, sizeof(msg),
				"Couldn't create Temporary Directory: %s\r\n\r\n"
				"Please contact your system administrator.",
				tmp);
			exit(0);
		}
	}

	ms->MyTempDirW = CopyUniStr(tmp);
	ms->MyTempDir = CopyUniToStr(tmp);

	MsGenLockFile(lockfilename, sizeof(lockfilename), ms->MyTempDirW);
	ms->LockFile = FileCreateW(lockfilename);
}

void MsFreeTempDir()
{
	wchar_t lock_file_name[MAX_SIZE];

	MsGenLockFile(lock_file_name, sizeof(lock_file_name), ms->MyTempDirW);
	FileClose(ms->LockFile);

	Free(ms->MyTempDir);
	Free(ms->MyTempDirW);
	ms->MyTempDir = NULL;
	ms->MyTempDirW = NULL;

	MsDeleteTempDir();
}

bool MsEnablePrivilege(char *name, bool enable)
{
	HANDLE hToken;
	LUID luid;
	TOKEN_PRIVILEGES *tp;
	bool ret;
	if (name == NULL)
	{
		return false;
	}

	if (OpenProcessToken(ms->hCurrentProcess, TOKEN_ADJUST_PRIVILEGES, &hToken) == false)
	{
		return false;
	}

	if (LookupPrivilegeValue(NULL, name, &luid) == FALSE)
	{
		CloseHandle(hToken);
		return false;
	}

	tp = ZeroMalloc(sizeof(TOKEN_PRIVILEGES));
	tp->PrivilegeCount = 1;
	tp->Privileges[0].Attributes = enable ? SE_PRIVILEGE_ENABLED : 0;
	Copy(&tp->Privileges[0].Luid, &luid, sizeof(LUID));

	ret = AdjustTokenPrivileges(hToken, false, tp, sizeof(TOKEN_PRIVILEGES), 0, 0);

	Free(tp);
	CloseHandle(hToken);

	return ret;
}

bool MsIsAdmin()
{
	return ms->IsAdmin;
}

UINT MsGetCurrentProcessId()
{
	return ms->CurrentProcessId;
}

char *MsGetExeDirName()
{
	return ms->ExeFileDir;
}

char *MsGetSpecialDir(int id)
{
	LPITEMIDLIST t = NULL;
	char tmp[MAX_PATH];

	if (SHGetSpecialFolderLocation(NULL, id, &t) != S_OK)
	{
		return CopyStr(ms->ExeFileDir);
	}

	if (SHGetPathFromIDList(t, tmp) == false)
	{
		return CopyStr(ms->ExeFileDir);
	}

	Win32NukuEn(tmp, sizeof(tmp), tmp);

	return CopyStr(tmp);
}
wchar_t *MsGetSpecialDirW(int id)
{
	LPITEMIDLIST t = NULL;
	wchar_t tmp[MAX_PATH];

	if (SHGetSpecialFolderLocation(NULL, id, &t) != S_OK)
	{
		return UniCopyStr(ms->ExeFileDirW);
	}

	if (SHGetPathFromIDListW(t, tmp) == false)
	{
		return UniCopyStr(ms->ExeFileDirW);
	}

	Win32NukuEnW(tmp, sizeof(tmp), tmp);

	return UniCopyStr(tmp);
}

void MsGetSpecialDirs()
{
	char tmp[MAX_PATH];

	GetSystemDirectory(tmp, sizeof(tmp));
	Win32NukuEn(tmp, sizeof(tmp), tmp);
	ms->System32Dir = CopyStr(tmp);
	ms->System32DirW = CopyStrToUni(tmp);

	// The Windows directory is parent of the System32 directory
	Win32GetDirFromPath(tmp, sizeof(tmp), tmp);
	Win32NukuEn(tmp, sizeof(tmp), tmp);
	ms->WindowsDir = CopyStr(tmp);
	ms->WindowsDirW = CopyStrToUni(tmp);

	Format(tmp, sizeof(tmp), "%s\\Temp", ms->WindowsDir);
	ms->WinTempDir = CopyStr(tmp);
	ms->WinTempDirW = CopyStrToUni(tmp);
	MsUniMakeDirEx(ms->WinTempDirW);

	tmp[2] = 0;
	ms->WindowsDrive = CopyStr(tmp);
	ms->WindowsDriveW = CopyStrToUni(tmp);

	GetTempPath(MAX_PATH, tmp);
	Win32NukuEn(tmp, sizeof(tmp), tmp);
	ms->TempDir = CopyStr(tmp);

	{
		wchar_t tmp_w[MAX_PATH];

		GetTempPathW(MAX_PATH, tmp_w);
		Win32NukuEnW(tmp_w, sizeof(tmp_w), tmp_w);

		ms->TempDirW = CopyUniStr(tmp_w);
	}
	MakeDirExW(ms->TempDirW);
	MakeDirEx(ms->TempDir);

	ms->ProgramFilesDir = MsGetSpecialDir(CSIDL_PROGRAM_FILES);
	if (StrCmpi(ms->ProgramFilesDir, ms->ExeFileDir) == 0)
	{
		char tmp[MAX_PATH];
		Format(tmp, sizeof(tmp), "%s\\Program Files", ms->WindowsDrive);

		Free(ms->ProgramFilesDir);
		ms->ProgramFilesDir = CopyStr(tmp);
	}

	ms->ProgramFilesDirW = MsGetSpecialDirW(CSIDL_PROGRAM_FILES);
	if (UniStrCmpi(ms->ProgramFilesDirW, ms->ExeFileDirW) == 0)
	{
		wchar_t tmp[MAX_PATH];
		UniFormat(tmp, sizeof(tmp), L"%s\\Program Files", ms->WindowsDriveW);

		Free(ms->ProgramFilesDirW);
		ms->ProgramFilesDirW = UniCopyStr(tmp);
	}

	ms->ProgramFilesDirX86 = MsGetSpecialDir(CSIDL_PROGRAM_FILESX86);
	if (StrCmpi(ms->ProgramFilesDirX86, ms->ExeFileDir) == 0)
	{
		char tmp[MAX_PATH];
		Format(tmp, sizeof(tmp), "%s\\Program Files (x86)", ms->WindowsDrive);

		Free(ms->ProgramFilesDirX86);
		ms->ProgramFilesDirX86 = CopyStr(tmp);
	}

	ms->ProgramFilesDirX86W = MsGetSpecialDirW(CSIDL_PROGRAM_FILESX86);
	if (UniStrCmpi(ms->ProgramFilesDirX86W, ms->ExeFileDirW) == 0)
	{
		wchar_t tmp[MAX_PATH];
		UniFormat(tmp, sizeof(tmp), L"%s\\Program Files (x86)", ms->WindowsDriveW);

		Free(ms->ProgramFilesDirX86W);
		ms->ProgramFilesDirX86W = UniCopyStr(tmp);
	}

	ms->ProgramFilesDirX64 = CopyStr(ms->ProgramFilesDir);
	ms->ProgramFilesDirX64W = CopyUniStr(ms->ProgramFilesDirW);

	ms->CommonStartMenuDir = MsGetSpecialDir(CSIDL_COMMON_STARTMENU);
	ms->CommonStartMenuDirW = MsGetSpecialDirW(CSIDL_COMMON_STARTMENU);

	ms->CommonProgramsDir = MsGetSpecialDir(CSIDL_COMMON_PROGRAMS);
	ms->CommonProgramsDirW = MsGetSpecialDirW(CSIDL_COMMON_PROGRAMS);

	ms->CommonStartupDir = MsGetSpecialDir(CSIDL_COMMON_STARTUP);
	ms->CommonStartupDirW = MsGetSpecialDirW(CSIDL_COMMON_STARTUP);

	ms->CommonAppDataDir = MsGetSpecialDir(CSIDL_COMMON_APPDATA);
	ms->CommonAppDataDirW = MsGetSpecialDirW(CSIDL_COMMON_APPDATA);

	ms->CommonDesktopDir = MsGetSpecialDir(CSIDL_COMMON_DESKTOPDIRECTORY);
	ms->CommonDesktopDirW = MsGetSpecialDirW(CSIDL_COMMON_DESKTOPDIRECTORY);

	ms->LocalAppDataDir = MsGetSpecialDir(CSIDL_LOCAL_APPDATA);
	ms->LocalAppDataDirW = MsGetSpecialDirW(CSIDL_LOCAL_APPDATA);
}

void MsInit()
{
	char *str_ansi;
	wchar_t *str_unicode;
	char tmp[MAX_SIZE];
	DWORD size;
	if (ms != NULL)
	{
		return;
	}

	ms = ZeroMalloc(sizeof(MS));

	ms->hInst = GetModuleHandle(NULL);

	ms->hKernel32 = LoadLibrary("kernel32.dll");

	str_ansi = CopyStr(GetCommandLineA());
	Trim(str_ansi);
	str_unicode = UniCopyStr(GetCommandLineW());
	UniTrim(str_unicode);

	SetCommandLineStr(MsCutExeNameFromCommandLine(str_ansi));
	SetCommandLineUniStr(MsCutExeNameFromUniCommandLine(str_unicode));

	Free(str_unicode);
	Free(str_ansi);

	ms->IsAdmin = MsCheckIsAdmin();

	ms->hCurrentProcess = GetCurrentProcess();
	ms->CurrentProcessId = GetCurrentProcessId();

	GetModuleFileName(NULL, tmp, sizeof(tmp));
	ms->ExeFileName = CopyStr(tmp);
	Win32GetDirFromPath(tmp, sizeof(tmp), tmp);
	ms->ExeFileDir = CopyStr(tmp);

	{
		wchar_t tmp_w[MAX_PATH];

		GetModuleFileNameW(NULL, tmp_w, sizeof(tmp_w));
		ms->ExeFileNameW = CopyUniStr(tmp_w);

		Win32GetDirFromPathW(tmp_w, sizeof(tmp_w), tmp_w);
		ms->ExeFileDirW = CopyUniStr(tmp_w);
	}

	MsGetSpecialDirs();

	MsInitTempDir();

	size = sizeof(tmp);
	GetUserName(tmp, &size);
	ms->UserName = CopyStr(tmp);

	wchar_t tmp_w[MAX_PATH];

	size = sizeof(tmp_w);

	GetUserNameW(tmp_w, &size);
	ms->UserNameW = CopyUniStr(tmp_w);

	size = sizeof(tmp);
	if (GetUserNameExA(NameSamCompatible, tmp, &size))
	{
		ms->UserNameEx = CopyStr(tmp);
	}

	size = sizeof(tmp_w);
	if (GetUserNameExW(NameSamCompatible, tmp_w, &size))
	{
		ms->UserNameExW = CopyUniStr(tmp_w);
	}

	if (ms->UserNameEx == NULL)
	{
		ms->UserNameEx = CopyStr(ms->UserName);
	}
	if (ms->UserNameExW == NULL)
	{
		ms->UserNameExW = CopyUniStr(ms->UserNameW);
	}

	MsInitAdapterListModule();

	if (true)
	{
		wchar_t tmp[MAX_PATH];
		if (MsIsAdmin())
		{
			CombinePathW(tmp, sizeof(tmp), ms->ExeFileDirW, L"vpn_debug\\dump");
		}
		else
		{
			CombinePathW(tmp, sizeof(tmp), ms->TempDirW, L"vpn_debug\\dump");
		}
		ms->MinidumpBaseFileNameW = CopyUniStr(tmp);
	}

	MsSetEnableMinidump(true);
	SetUnhandledExceptionFilter(MsExceptionHandler);

	hLsa = NULL;
	lsa_package_id = 0;

	MsEnablePrivilege(SE_TCB_NAME, true);

	HANDLE h = NULL;
	NTSTATUS ret = LsaConnectUntrusted(&h);

	if (ret == 0)
	{
		LSA_STRING pkg_name;
		ULONG ul = 0;

		Zero(&pkg_name, sizeof(pkg_name));
		pkg_name.Buffer = MSV1_0_PACKAGE_NAME;
		pkg_name.Length = pkg_name.MaximumLength = StrLen(MSV1_0_PACKAGE_NAME);

		ret = LsaLookupAuthenticationPackage(h, &pkg_name, &ul);

		if (ret == 0)
		{
			Zero(&lsa_token_source, sizeof(lsa_token_source));

			AllocateLocallyUniqueId(&lsa_token_source.SourceIdentifier);
			Copy(lsa_token_source.SourceName, "SE-VPN  ", 8);

			lsa_package_id = ul;
			hLsa = h;
		}
		else
		{
			LsaDeregisterLogonProcess(h);
		}
	}

	if (hMsi == NULL)
	{
		hMsi = LoadLibrary("msi.dll");

		if (hMsi != NULL)
		{
			_MsiConfigureProductW =
				(UINT (__stdcall *)(LPCWSTR,int,INSTALLSTATE)) GetProcAddress(hMsi, "MsiConfigureProductW");
			_MsiGetProductInfoW =
				(UINT (__stdcall *)(LPCWSTR,LPCWSTR,LPWSTR,LPDWORD)) GetProcAddress(hMsi, "MsiGetProductInfoW");
			_MsiSetInternalUI =
				(INSTALLUILEVEL (__stdcall *)(INSTALLUILEVEL,HWND *)) GetProcAddress(hMsi, "MsiSetInternalUI");
			_MsiLocateComponentW =
				(INSTALLSTATE (__stdcall *)(LPCWSTR,LPWSTR,LPDWORD)) GetProcAddress(hMsi, "MsiLocateComponentW");
		}
	}
}

void MsSetEnableMinidump(bool enabled)
{
	ms->MiniDumpEnabled = enabled;
}

void MsWriteMinidump(wchar_t *filename, void *ex)
{
	wchar_t tmp[MAX_PATH];
	wchar_t dir[MAX_PATH];
	HANDLE h;
	MINIDUMP_EXCEPTION_INFORMATION info;
	struct _EXCEPTION_POINTERS *exp = (struct _EXCEPTION_POINTERS *)ex;

	if (filename != NULL)
	{
		UniStrCpy(tmp, sizeof(tmp), filename);
	}
	else
	{
		SYSTEMTIME tm;

		Zero(&tm, sizeof(tm));
		GetLocalTime(&tm);

		UniFormat(tmp, sizeof(tmp), L"%s_%04u%02u%02u_%02u%02u%02u.dmp",
			ms->MinidumpBaseFileNameW,
			tm.wYear, tm.wMonth, tm.wDay, tm.wHour, tm.wMinute, tm.wSecond);
	}

	GetDirNameFromFilePathW(dir, sizeof(dir), tmp);

	CreateDirectoryW(dir, NULL);

	Zero(&info, sizeof(info));

	if (exp != NULL)
	{
		info.ThreadId = GetCurrentThreadId();
		info.ExceptionPointers = exp;
		info.ClientPointers = true;
	}

	h = CreateFileW(tmp, GENERIC_READ | GENERIC_WRITE,
		FILE_SHARE_READ, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL,
		NULL);
	if (h != INVALID_HANDLE_VALUE)
	{
		MiniDumpWriteDump(ms->hCurrentProcess, ms->CurrentProcessId,
			h,
			MiniDumpNormal | MiniDumpWithFullMemory | MiniDumpWithDataSegs |
			MiniDumpWithHandleData
			,
			info.ThreadId == 0 ? NULL : &info, NULL, NULL);

		FlushFileBuffers(h);
		CloseHandle(h);
	}
}

LONG CALLBACK MsExceptionHandler(struct _EXCEPTION_POINTERS *ExceptionInfo)
{
	if (ms->MiniDumpEnabled)
	{
		MsWriteMinidump(NULL, ExceptionInfo);
	}

	return EXCEPTION_CONTINUE_SEARCH;
}

void MsFree()
{
	if (ms == NULL)
	{
		return;
	}

	if (hLsa != NULL)
	{
		LsaDeregisterLogonProcess(hLsa);

		hLsa = NULL;
	}

	MsFreeAdapterListModule();

	MsFreeTempDir();

	Free(ms->WindowsDir);
	Free(ms->System32Dir);
	Free(ms->TempDir);
	Free(ms->WinTempDir);
	Free(ms->WindowsDrive);
	Free(ms->ProgramFilesDir);
	Free(ms->CommonStartMenuDir);
	Free(ms->CommonProgramsDir);
	Free(ms->CommonStartupDir);
	Free(ms->CommonAppDataDir);
	Free(ms->CommonDesktopDir);
	Free(ms->PersonalStartMenuDir);
	Free(ms->PersonalProgramsDir);
	Free(ms->PersonalStartupDir);
	Free(ms->PersonalAppDataDir);
	Free(ms->PersonalDesktopDir);
	Free(ms->MyDocumentsDir);
	Free(ms->ExeFileDir);
	Free(ms->ExeFileName);
	Free(ms->UserName);
	Free(ms->UserNameEx);
	Free(ms->LocalAppDataDir);
	Free(ms->ProgramFilesDirX86);
	Free(ms->ProgramFilesDirX64);
	Free(ms->WindowsDirW);
	Free(ms->System32DirW);
	Free(ms->TempDirW);
	Free(ms->WinTempDirW);
	Free(ms->WindowsDriveW);
	Free(ms->ProgramFilesDirW);
	Free(ms->CommonStartMenuDirW);
	Free(ms->CommonProgramsDirW);
	Free(ms->CommonStartupDirW);
	Free(ms->CommonAppDataDirW);
	Free(ms->CommonDesktopDirW);
	Free(ms->PersonalStartMenuDirW);
	Free(ms->PersonalProgramsDirW);
	Free(ms->PersonalStartupDirW);
	Free(ms->PersonalAppDataDirW);
	Free(ms->PersonalDesktopDirW);
	Free(ms->MyDocumentsDirW);
	Free(ms->ExeFileDirW);
	Free(ms->ExeFileNameW);
	Free(ms->UserNameW);
	Free(ms->UserNameExW);
	Free(ms->LocalAppDataDirW);
	Free(ms->MinidumpBaseFileNameW);
	Free(ms->ProgramFilesDirX86W);
	Free(ms->ProgramFilesDirX64W);

	Free(ms);
	ms = NULL;
}

wchar_t *MsGetWindowsDirW()
{
	return ms->WindowsDirW;
}
char *MsGetSystem32Dir()
{
	return ms->System32Dir;
}
char *MsGetTempDir()
{
	return ms->TempDir;
}
char *MsGetMyTempDir()
{
	return ms->MyTempDir;
}

wchar_t *MsGetExeFileNameW()
{
	return ms == NULL ? L"Unknown" : ms->ExeFileNameW;
}
wchar_t *MsGetSystem32DirW()
{
	return ms->System32DirW;
}
wchar_t *MsGetMyTempDirW()
{
	return ms->MyTempDirW;
}
wchar_t *MsGetUserNameW()
{
	return ms->UserNameW;
}

#endif	// WIN32

