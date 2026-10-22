// Microsoft.c
// For Microsoft Windows code

#define MICROSOFT_C

#include "Microsoft.h"

#include "Cfg.h"
#include "Encrypt.h"
#include "FileIO.h"
#include "GlobalConst.h"
#include "Internat.h"
#include "Kernel.h"
#include "Mayaqua.h"
#include "Memory.h"
#include "Object.h"
#include "Str.h"
#include "Table.h"
#include "Tick64.h"
#include "Win32.h"

#define SECURITY_WIN32

// Shlwapi.h only for its path functions: its string macros (StrCpy, StrCat, ...) would replace ours
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

static MS *ms = NULL;

static SERVICE_STATUS_HANDLE ssh = NULL;
static SERVICE_STATUS status = {0};
// The control handler and the service thread both report the status: status_lock guards status
static CRITICAL_SECTION status_lock;
static HANDLE service_stop_event = NULL;
static char g_service_name[MAX_SIZE];
static SERVICE_FUNCTION *g_start, *g_stop;
static bool exiting = false;
static bool wnd_end;
static bool is_usermode = false;

void MsInitProcessCallOnce() {
	// Mitigate DLL injection attacks
	// A dynamic load of a DLL named without a path searches the directory of the executable, the
	// directories added with AddDllDirectory and System32: never the current directory, the Windows
	// directory or PATH. LOAD_LIBRARY_SEARCH_SYSTEM32 alone would drop the directory of the
	// executable. Statically imported DLLs (the ASan runtime) were loaded before this runs.
	SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_DEFAULT_DIRS);
	// SetDllDirectory("") also keeps the current directory out of the orders the default directories do not
	// govern: the standard order of child processes and the alternate order of
	// LoadLibraryEx with LOAD_WITH_ALTERED_SEARCH_PATH. Empty, it adds no directory to the default ones.
	SetDllDirectoryW(L"");
}

static LRESULT CALLBACK MsUserModeWindowProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam) {
	if (hWnd == NULL)
		return 0;

	switch (msg) {
	case WM_ENDSESSION:
		if (wParam == false)
			break;
	case WM_CREATE:
		exiting = false;
		g_start();
		break;
	case WM_QUERYENDSESSION:
		if (exiting == false) {
			exiting = true;
			g_stop();
			DestroyWindow(hWnd);
		}
		return TRUE;
	case WM_CLOSE:
		if (exiting == false) {
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

bool MsIsUserMode() {
	return is_usermode;
}

static void MsUserModeW(const wchar_t *title, SERVICE_FUNCTION *start, SERVICE_FUNCTION *stop) {
	WNDCLASS wc;
	MSG msg;
	char title_a[MAX_PATH];
	wchar_t msg_str[MAX_SIZE];
	if (title == NULL || start == NULL || stop == NULL)
		return;

	UniToStr(title_a, sizeof(title_a), title);

	is_usermode = true;
	g_start = start;
	g_stop = stop;

	INSTANCE *inst = NewSingleInstance(NULL);
	if (inst == NULL) {
		UniFormat(msg_str, sizeof(msg_str), _UU("SVC_USERMODE_MUTEX"), ms->ExeFileNameW);
		UniPrint(L"%s\n", msg_str);
		return;
	}

	Zero(&wc, sizeof(wc));
	wc.hbrBackground = (HBRUSH)GetStockObject(WHITE_BRUSH);
	wc.hCursor = LoadCursor(NULL, IDC_ARROW);
	wc.hInstance = ms->hInst;
	wc.lpfnWndProc = MsUserModeWindowProc;
	wc.lpszClassName = title_a;
	if (RegisterClass(&wc) == 0)
		return;

	HWND hWnd = CreateWindow(title_a, title_a, WS_OVERLAPPEDWINDOW,
	                         CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT,
	                         NULL, NULL, ms->hInst, NULL);

	if (hWnd == NULL)
		return;

	wnd_end = false;
	while (wnd_end == false) {
		GetMessage(&msg, NULL, 0, 0);
		TranslateMessage(&msg);
		DispatchMessage(&msg);
	}

	FreeSingleInstance(inst);

	_exit(0);
}

// Write a service entry (MS_EVENT_SERVICE_*) under the service name: "Service <name> <what>.",
// with the Win32 error code when it is not 0
static void MsWriteServiceEvent(UINT type, UINT event_id, char *what, UINT error) {
	char msg[MAX_SIZE];

	if (error == 0)
		snprintf(msg, sizeof(msg), "Service %s %s.", g_service_name, what);
	else
		snprintf(msg, sizeof(msg), "Service %s %s (error %u).", g_service_name, what, error);

	MsWriteEventLog(g_service_name, type, event_id, msg);
}

// Report the state to the SCM under status_lock. A pending state advances the checkpoint and accepts
// no control; the running service accepts STOP and PRESHUTDOWN.
static void MsSetServiceState(DWORD state, DWORD wait_hint, DWORD exit_code) {
	EnterCriticalSection(&status_lock);

	status.dwCurrentState = state;
	status.dwWin32ExitCode = exit_code;
	status.dwWaitHint = wait_hint;

	if (state == SERVICE_START_PENDING || state == SERVICE_STOP_PENDING) {
		status.dwCheckPoint++;
		status.dwControlsAccepted = 0;
	} else {
		status.dwCheckPoint = 0;
		status.dwControlsAccepted = (state == SERVICE_RUNNING ? SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_PRESHUTDOWN : 0);
	}

	SetServiceStatus(ssh, &status);

	LeaveCriticalSection(&status_lock);
}

static void MsServiceStoperMainThread(THREAD *t, void *p) {
	g_stop();
}

static bool MsServiceStopProc() {
	bool ret = true;
	UINT64 selfkill_timeout = Tick64() + SVC_SELFKILL_TIMEOUT;

	THREAD *thread = NewThread(MsServiceStoperMainThread, NULL);

	while (WaitThread(thread, 250) == false) {
		if (Tick64() >= selfkill_timeout) {
			ret = false;
			break;
		}
		MsSetServiceState(SERVICE_STOP_PENDING, 100000, NO_ERROR);
	}

	// The entry goes out before SERVICE_STOPPED: once that is reported, the process may end at any time
	if (ret)
		MsWriteServiceEvent(EVENTLOG_INFORMATION_TYPE, MS_EVENT_SERVICE_STOPPED, "stopped", 0);
	else
		MsWriteServiceEvent(EVENTLOG_ERROR_TYPE, MS_EVENT_SERVICE_FAILED,
		                    "did not stop within the self-kill timeout and is terminated", 0);

	MsSetServiceState(SERVICE_STOPPED, 0, ret ? NO_ERROR : ERROR_TIMEOUT);

	if (ret == false) {
		// The self-kill timeout fired: force an exit
		_exit(-1);
	} else {
		ReleaseThread(thread);
	}

	return ret;
}

// Control handler (HandlerEx), run on the thread of StartServiceCtrlDispatcherW. STOP and PRESHUTDOWN
// both stop the server, and g_stop() saves the configuration: PRESHUTDOWN gives that the pre-shutdown
// window of an OS shutdown instead of the short SHUTDOWN one.
static DWORD WINAPI MsServiceHandler(DWORD control, DWORD event_type, LPVOID event_data, LPVOID context) {
	switch (control) {
	case SERVICE_CONTROL_STOP:
	case SERVICE_CONTROL_PRESHUTDOWN:
		MsSetServiceState(SERVICE_STOP_PENDING, 100000, NO_ERROR);
		SetEvent(service_stop_event);
		return NO_ERROR;

	case SERVICE_CONTROL_INTERROGATE:
		return NO_ERROR;
	}

	return ERROR_CALL_NOT_IMPLEMENTED;
}

// Service main, run on its own thread by StartServiceCtrlDispatcherW. The service is START_PENDING
// while Mayaqua and the server start and RUNNING once g_start() has returned; no control is accepted
// before that, so the handler never sees a NULL service_stop_event.
static void WINAPI MsServiceDispatcher(DWORD argc, LPWSTR *argv) {
	// An own-process service may register under any name; argv[0] is the one the SCM started
	ssh = RegisterServiceCtrlHandlerExW(argc >= 1 ? argv[0] : L"", MsServiceHandler, NULL);

	if (ssh == NULL) {
		MsWriteServiceEvent(EVENTLOG_ERROR_TYPE, MS_EVENT_SERVICE_FAILED,
		                    "could not start: RegisterServiceCtrlHandlerExW() failed", GetLastError());
		return;
	}

	status.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
	MsSetServiceState(SERVICE_START_PENDING, 300000, NO_ERROR);

	service_stop_event = CreateEventW(NULL, true, false, NULL);
	if (service_stop_event == NULL) {
		DWORD error = GetLastError();

		MsWriteServiceEvent(EVENTLOG_ERROR_TYPE, MS_EVENT_SERVICE_FAILED,
		                    "could not start: CreateEventW() failed", error);
		MsSetServiceState(SERVICE_STOPPED, 0, error);
		return;
	}

#ifdef _DEBUG // Debug configuration: the debug CRT (/MTd) defines _DEBUG
	// memcheck = true logs every malloc/realloc/free to find leaks, but is very slow.
	InitMayaqua(false, true);
#else
	InitMayaqua(false, false);
#endif

	MsSetServiceState(SERVICE_START_PENDING, 300000, NO_ERROR);

	g_start();

	// RUNNING goes out before the entry: whoever waits for "started" can stop the service at once
	MsSetServiceState(SERVICE_RUNNING, 0, NO_ERROR);
	MsWriteServiceEvent(EVENTLOG_INFORMATION_TYPE, MS_EVENT_SERVICE_STARTED, "started", 0);
	MsUpdateServiceConfig(g_service_name);

	WaitForSingleObject(service_stop_event, INFINITE);

	MsServiceStopProc();
}

static void MsTestModeW(wchar_t *title, SERVICE_FUNCTION *start, SERVICE_FUNCTION *stop) {
	wchar_t msg[MAX_SIZE];
	if (title == NULL || start == NULL || stop == NULL)
		return;

	is_usermode = true;

	INSTANCE *inst = NewSingleInstance(NULL);
	if (inst == NULL) {
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

static void MsWriteCallingServiceManagerProcessId(char *svcname, UINT pid) {
	char tmp[MAX_PATH];

	Format(tmp, sizeof(tmp), SVC_CALLING_SM_PROCESS_ID_KEY, svcname);

	if (pid != 0) {
		MsRegWriteInt(REG_LOCAL_MACHINE, tmp, SVC_CALLING_SM_PROCESS_ID_VALUE, pid);
		MsRegWriteInt(REG_CURRENT_USER, tmp, SVC_CALLING_SM_PROCESS_ID_VALUE, pid);
	} else {
		MsRegDeleteValue(REG_LOCAL_MACHINE, tmp, SVC_CALLING_SM_PROCESS_ID_VALUE);
		MsRegDeleteKeyEx2(REG_LOCAL_MACHINE, tmp, false);

		MsRegDeleteValue(REG_CURRENT_USER, tmp, SVC_CALLING_SM_PROCESS_ID_VALUE);
		MsRegDeleteKeyEx2(REG_CURRENT_USER, tmp, false);
	}
}

// Print the string table message id, formatted with the arguments, on a line of its own; nothing
// when silent
static void MsSvcMsg(bool silent, char *id, ...) {
	wchar_t msg[MAX_SIZE * 4];
	va_list args;

	if (silent)
		return;

	va_start(args, id);
	UniFormatArgs(msg, sizeof(msg), _UU(id), args);
	va_end(args);

	UniPrint(L"%s\n", msg);
}

// The service program: the command line argument selects the mode (MsSvcArgToMode). firewall_rule
// names the inbound rule of Windows Firewall for this program, which /install and /setup_install add
// before the service starts, and /uninstall and /setup_uninstall delete; NULL for none. The service
// itself adds no rule when it starts.
UINT MsService(char *name, SERVICE_FUNCTION *start, SERVICE_FUNCTION *stop, char *cmd_line, wchar_t *firewall_rule) {
	return MsServiceEx(name, start, stop, cmd_line, firewall_rule, false);
}

// MsService, which with virtual_account installs the service to run as its virtual account, NT SERVICE\<service
// name>, instead of LocalSystem: the least privilege of ADR-0039 decision 3, for the services of the new core
UINT MsServiceEx(char *name, SERVICE_FUNCTION *start, SERVICE_FUNCTION *stop, char *cmd_line, wchar_t *firewall_rule, bool virtual_account) {
	UINT mode;
	UINT ret = 0;
	char *arg;
	TOKEN_LIST *t = NULL;
	char *service_name;
	wchar_t *service_title;
	wchar_t *service_description;
	char tmp[MAX_SIZE];
	bool restoreReg = false;
	bool silent = false;
	if (name == NULL || start == NULL || stop == NULL)
		return ret;

	g_start = start;
	g_stop = stop;
	StrCpy(g_service_name, sizeof(g_service_name), name);
	StrLower(g_service_name);

	if (cmd_line != NULL && lstrcmpiA(cmd_line, SVC_ARG_SERVICE) == 0) {
		// An own-process service: the name in the table is ignored, but must not be NULL
		SERVICE_TABLE_ENTRYW dispatch_table[] =
		    {
		        {L"", MsServiceDispatcher},
		        {NULL, NULL},
		    };

		// No SEM_NOGPFAULTERRORBOX: it bypasses Windows Error Reporting, and the WER LocalDumps key writes
		// the crash dumps of the service
		SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOOPENFILEERRORBOX);
		InitializeCriticalSection(&status_lock);

		if (StartServiceCtrlDispatcherW(dispatch_table) == false) {
			// Not started by the SCM (for example /service from a console): nothing ran, so exit 1
			MsWriteServiceEvent(EVENTLOG_ERROR_TYPE, MS_EVENT_SERVICE_FAILED,
			                    "could not start: StartServiceCtrlDispatcherW() failed", GetLastError());
			// The entry above is the event log record: standard error and a non-zero exit only
			fputs("StartServiceCtrlDispatcherW() failed: start this program as a service.\n", stderr);
			fflush(stderr);
			_exit(1);
		}

		MsUpdateServiceConfig(g_service_name);

		_exit(0);
	}

#ifdef _DEBUG // Debug configuration: the debug CRT (/MTd) defines _DEBUG
	// memcheck = true logs every malloc/realloc/free to find leaks, but is very slow.
	InitMayaqua(false, true);
#else
	InitMayaqua(false, false);
#endif

	Format(tmp, sizeof(tmp), SVC_NAME, name);
	service_name = _SS(tmp);
	Format(tmp, sizeof(tmp), SVC_TITLE, name);
	service_title = _UU(tmp);
	Format(tmp, sizeof(tmp), SVC_DESCRIPT, name);
	service_description = _UU(tmp);

	if (StrLen(service_name) == 0 || UniStrLen(service_title) == 0) {
		MsSvcMsg(false, "SVC_NOT_FOUND", name);
	} else {
		wchar_t path[MAX_SIZE];
		wchar_t *args_w = MsCopyProcessArgsW();
		char *args = CopyUniToStr(args_w);

		t = ParseCmdLine(args);
		Free(args);
		Free(args_w);
		arg = NULL;

		if (t->NumTokens >= 1)
			arg = t->Token[0];
		if (t->NumTokens >= 2) {
			if (StrCmpi(t->Token[1], SVC_ARG_SILENT) == 0)
				silent = true;
		}

		mode = MsSvcArgToMode(arg);

		UniFormat(path, sizeof(path), SVC_RUN_COMMANDLINE, ms->ExeFileNameW);

		if ((mode == SVC_MODE_INSTALL || mode == SVC_MODE_UNINSTALL || mode == SVC_MODE_START ||
		     mode == SVC_MODE_STOP || mode == SVC_MODE_SERVICE) &&
		    (ms->IsAdmin == false)) {
			UniPrint(L"%s\n", _UU("SVC_NOT_ADMIN"));
		} else {
			switch (mode) {
			case SVC_MODE_NONE:
				// Title and name: the heading, the program, /install, /uninstall, /start, /stop,
				// /test, /usermode, /setup_install, /setup_uninstall, /service
				MsSvcMsg(false, "SVC_HELP",
				         service_title, service_name, service_title,
				         service_title, service_name, service_title, service_name, service_title, service_name, service_title, service_name,
				         service_title, service_title,
				         service_title, service_name, service_title, service_name,
				         service_title);
				break;

			case SVC_MODE_SETUP_INSTALL:
				MsWriteCallingServiceManagerProcessId(service_name, MsGetCurrentProcessId());
				restoreReg = true;

				if (MsIsServiceInstalled(service_name)) {
					if (MsIsServiceRunning(service_name))
						MsStopService(service_name);
					MsUninstallService(service_name);
				}
				if (MsInstallServiceExW(service_name, service_title, service_description, path, virtual_account) == false)
					ret = 1;
				if (firewall_rule != NULL)
					MsAddFirewallRule(firewall_rule, ms->ExeFileNameW);
				MsStartService(service_name);
				MsWriteCallingServiceManagerProcessId(service_name, 0);
				break;

			case SVC_MODE_SETUP_UNINSTALL:
				MsWriteCallingServiceManagerProcessId(service_name, MsGetCurrentProcessId());
				restoreReg = true;

				if (MsIsServiceInstalled(service_name)) {
					if (MsIsServiceRunning(service_name))
						MsStopService(service_name);
					if (MsUninstallService(service_name) == false)
						ret = 1;
				}
				if (firewall_rule != NULL)
					MsDeleteFirewallRule(firewall_rule);
				break;

			case SVC_MODE_INSTALL:
				MsWriteCallingServiceManagerProcessId(service_name, MsGetCurrentProcessId());
				restoreReg = true;

				if (MsIsServiceInstalled(service_name)) {
					if (silent == true)
						break;
					// The operator explicitly requested /install, so uninstall and then re-install
					MsSvcMsg(silent, "SVC_ALREADY_INSTALLED", service_title, service_name);

					if (MsIsServiceRunning(service_name)) {
						if (MsStopService(service_name) == false) {
							MsSvcMsg(silent, "SVC_STOP_FAILED", service_title, service_name);
							break;
						}
					}
					if (MsUninstallService(service_name) == false) {
						MsSvcMsg(silent, "SVC_UNINSTALL_FAILED", service_title, service_name);
						break;
					}
				}

				if (MsInstallServiceExW(service_name, service_title, service_description, path, virtual_account) == false) {
					MsSvcMsg(silent, "SVC_INSTALL_FAILED", service_title, service_name);
					break;
				}

				// The rule is there before the server listens; the service still starts without it
				if (firewall_rule != NULL && MsAddFirewallRule(firewall_rule, ms->ExeFileNameW) == false)
					MsSvcMsg(silent, "SVC_FIREWALL_ADD_FAILED", firewall_rule, ms->ExeFileNameW);

				if (MsStartService(service_name) == false) {
					MsSvcMsg(silent, "SVC_INSTALL_FAILED_2", service_title, service_name, path);
					break;
				}

				MsSvcMsg(silent, "SVC_INSTALL_OK", service_title, service_name, path);
				break;

			case SVC_MODE_UNINSTALL:
				MsWriteCallingServiceManagerProcessId(service_name, MsGetCurrentProcessId());
				restoreReg = true;

				if (MsIsServiceInstalled(service_name) == false) {
					MsSvcMsg(silent, "SVC_NOT_INSTALLED", service_title, service_name, path);
					break;
				}

				if (MsIsServiceRunning(service_name)) {
					if (MsStopService(service_name) == false) {
						MsSvcMsg(silent, "SVC_STOP_FAILED", service_title, service_name);
						break;
					}
				}

				if (MsUninstallService(service_name) == false) {
					MsSvcMsg(silent, "SVC_UNINSTALL_FAILED", service_title, service_name);
					break;
				}

				if (firewall_rule != NULL && MsDeleteFirewallRule(firewall_rule) == false)
					MsSvcMsg(silent, "SVC_FIREWALL_DELETE_FAILED", firewall_rule);

				MsSvcMsg(silent, "SVC_UNINSTALL_OK", service_title, service_name);
				break;

			case SVC_MODE_START:
				MsWriteCallingServiceManagerProcessId(service_name, MsGetCurrentProcessId());
				restoreReg = true;

				if (MsIsServiceInstalled(service_name) == false) {
					MsSvcMsg(silent, "SVC_NOT_INSTALLED", service_title, service_name);
					break;
				}

				if (MsIsServiceRunning(service_name)) {
					MsSvcMsg(silent, "SVR_ALREADY_START", service_title, service_name);
					break;
				}

				if (MsStartService(service_name) == false) {
					MsSvcMsg(silent, "SVC_START_FAILED", service_title, service_name);
					break;
				}

				MsSvcMsg(silent, "SVC_START_OK", service_title, service_name);
				break;

			case SVC_MODE_STOP:
				MsWriteCallingServiceManagerProcessId(service_name, MsGetCurrentProcessId());
				restoreReg = true;

				if (MsIsServiceInstalled(service_name) == false) {
					MsSvcMsg(silent, "SVC_NOT_INSTALLED", service_title, service_name);
					break;
				}

				if (MsIsServiceRunning(service_name) == false) {
					MsSvcMsg(silent, "SVC_ALREADY_STOP", service_title, service_name);
					break;
				}
				if (MsStopService(service_name) == false) {
					MsSvcMsg(silent, "SVC_STOP_FAILED", service_title, service_name);
					break;
				}

				MsSvcMsg(silent, "SVC_STOP_OK", service_title, service_name);
				break;

			case SVC_MODE_TEST:
				MsTestModeW(service_title, start, stop);
				break;
			case SVC_MODE_USERMODE:
				MsUserModeW(service_title, start, stop);
				break;
			case SVC_MODE_SERVICE:
				break;
			}
		}
		FreeToken(t);

		if (restoreReg)
			MsWriteCallingServiceManagerProcessId(service_name, 0);
	}

	FreeMayaqua();

	return ret;
}

// Temp directory of the process: %TEMP%\VPN_ and 16 hex digits of the CNG generator (64 bits),
// so the name cannot be guessed and created first. The protected DACL inherits nothing from
// %TEMP% (C:\Windows\Temp for the service, where every user can add files and folders): full
// access for SYSTEM, Administrators and the owner of the directory (the user who runs the
// process), nothing for anyone else.
#define MS_TEMP_DIR_RANDOM_SIZE 8
#define MS_TEMP_DIR_NAME_LEN    (4 + MS_TEMP_DIR_RANDOM_SIZE * 2) // "VPN_" and the hex digits
#define MS_TEMP_DIR_SDDL        L"D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;OW)"

// Delete the temp directories that earlier processes left in %TEMP% (no lock file, or one no process
// holds). A reparse point named like one (a junction or a symbolic link, which anyone who can write
// to %TEMP% can make) is no temp directory of this program: it is left alone and never followed.
static void MsDeleteTempDir() {
	wchar_t dir_mask[MAX_PATH];
	WIN32_FIND_DATAW data_w;

	Zero(&data_w, sizeof(data_w));

	UniFormat(dir_mask, sizeof(dir_mask), L"%s\\*", ms->TempDirW);

	HANDLE h = FindFirstFileW(dir_mask, &data_w);

	if (h != INVALID_HANDLE_VALUE) {
		bool b = true;

		do {
			if (UniStrCmpi(data_w.cFileName, L".") != 0 &&
			    UniStrCmpi(data_w.cFileName, L"..") != 0) {
				if ((data_w.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) &&
				    (data_w.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) == 0) {
					if (UniStartWith(data_w.cFileName, L"VPN_") && UniStrLen(data_w.cFileName) == MS_TEMP_DIR_NAME_LEN) {
						wchar_t lock_file_name[MAX_PATH];
						wchar_t dir_name[MAX_PATH];
						bool delete_now = false;

						UniFormat(dir_name, sizeof(dir_name), L"%s\\%s",
						          ms->TempDirW, data_w.cFileName);
						MsGenLockFile(lock_file_name, sizeof(lock_file_name), dir_name);

						IO *io = FileOpenExW(lock_file_name, false, false);
						if (io != NULL) {
							FileClose(io);
							io = FileOpenW(lock_file_name, true);
							if (io != NULL) {
								delete_now = true;
								FileClose(io);
							}
						} else {
							delete_now = true;

							DIRLIST *d = EnumDirW(dir_name);
							if (d != NULL) {
								for (UINT i = 0; i < d->NumFiles; i++) {
									wchar_t full_path[MAX_PATH];

									UniFormat(full_path, sizeof(full_path), L"%s\\%s", dir_name, d->File[i]->FileNameW);

									io = FileOpenW(full_path, true);
									if (io != NULL) {
										delete_now = true;
										FileClose(io);
									}
								}
								FreeDir(d);
							}
						}
						if (delete_now) {
							MsDeleteAllFileW(dir_name);

							Win32DeleteDirW(dir_name);
						}
					}
				}
			}


			Zero(&data_w, sizeof(data_w));

			b = FindNextFileW(h, &data_w);
		} while (b);

		FindClose(h);
	}
}

// Delete the files and subdirectories of dir, never through a reparse point. dir is opened without
// following a reparse point and left alone when it is one. A junction or a symbolic link in it goes
// as a link: RemoveDirectoryW and DeleteFileW remove the link, not its target. dir stays open
// without delete or write sharing while its entries go, so that it cannot be renamed or replaced
// in the meantime.
void MsDeleteAllFileW(wchar_t *dir) {
	BY_HANDLE_FILE_INFORMATION info;
	wchar_t file_mask[MAX_PATH];
	WIN32_FIND_DATAW data;
	if (dir == NULL || UniIsEmptyStr(dir))
		return;

	HANDLE dir_handle = CreateFileW(dir, FILE_LIST_DIRECTORY, FILE_SHARE_READ, NULL, OPEN_EXISTING,
	                                FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, NULL);
	if (dir_handle == INVALID_HANDLE_VALUE)
		return;

	Zero(&info, sizeof(info));
	if (GetFileInformationByHandle(dir_handle, &info) == FALSE ||
	    (info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0 ||
	    (info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0) {
		CloseHandle(dir_handle);
		return;
	}

	UniFormat(file_mask, sizeof(file_mask), L"%s\\*.*", dir);

	HANDLE h = FindFirstFileW(file_mask, &data);
	if (h != INVALID_HANDLE_VALUE) {
		do {
			if (UniStrCmpi(data.cFileName, L".") != 0 &&
			    UniStrCmpi(data.cFileName, L"..") != 0) {
				wchar_t fullpath[MAX_PATH];

				UniFormat(fullpath, sizeof(fullpath), L"%s\\%s", dir, data.cFileName);

				if ((data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0) {
					DeleteFileW(fullpath);
				} else {
					if ((data.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) == 0)
						MsDeleteAllFileW(fullpath);

					RemoveDirectoryW(fullpath);
				}
			}
		} while (FindNextFileW(h, &data));

		FindClose(h);
	}

	CloseHandle(dir_handle);
}

static void MsInitTempDir() {
	wchar_t tmp[MAX_PATH];
	wchar_t tmp2[MS_TEMP_DIR_RANDOM_SIZE * 2 + 1];
	UCHAR random[MS_TEMP_DIR_RANDOM_SIZE];
	wchar_t lockfilename[MAX_PATH];
	SECURITY_ATTRIBUTES sa;
	PSECURITY_DESCRIPTOR sd = NULL;
	UINT num = 0;

	MsDeleteTempDir();

	if (ConvertStringSecurityDescriptorToSecurityDescriptorW(MS_TEMP_DIR_SDDL, SDDL_REVISION_1, &sd, NULL) == FALSE)
		AbortExitEx("MsInitTempDir(): ConvertStringSecurityDescriptorToSecurityDescriptorW() failed");

	Zero(&sa, sizeof(sa));
	sa.nLength = sizeof(sa);
	sa.lpSecurityDescriptor = sd;
	sa.bInheritHandle = FALSE;

	while (true) {
		Rand(random, sizeof(random));
		BinToStrW(tmp2, sizeof(tmp2), random, sizeof(random));

		UniFormat(tmp, sizeof(tmp), L"%s\\VPN_%s", ms->TempDirW, tmp2);

		// Fails when the name exists, so the directory is always a new one made here
		if (CreateDirectoryW(tmp, &sa))
			break;

		if ((num++) >= 100) {
			char msg[MAX_SIZE];
			Format(msg, sizeof(msg),
			       "Couldn't create Temporary Directory: %S\r\n\r\n"
			       "Please contact your system administrator.",
			       tmp);
			MayaFatalExit(1, msg);
		}
	}

	LocalFree(sd);

	ms->MyTempDirW = CopyUniStr(tmp);
	ms->MyTempDir = CopyUniToStr(tmp);

	MsGenLockFile(lockfilename, sizeof(lockfilename), ms->MyTempDirW);
	ms->LockFile = FileCreateW(lockfilename);
}

static void MsFreeTempDir() {
	wchar_t lock_file_name[MAX_SIZE];

	MsGenLockFile(lock_file_name, sizeof(lock_file_name), ms->MyTempDirW);
	FileClose(ms->LockFile);

	Free(ms->MyTempDir);
	Free(ms->MyTempDirW);
	ms->MyTempDir = NULL;
	ms->MyTempDirW = NULL;

	MsDeleteTempDir();
}

void MsGenLockFile(wchar_t *name, UINT size, wchar_t *temp_dir) {
	if (name == NULL || temp_dir == NULL)
		return;

	UniFormat(name, size, L"%s\\VPN_Lock.dat", temp_dir);
}

bool MsEnablePrivilege(char *name, bool enable) {
	HANDLE hToken;
	LUID luid;
	TOKEN_PRIVILEGES *tp;
	bool ret;
	if (name == NULL)
		return false;

	if (OpenProcessToken(ms->hCurrentProcess, TOKEN_ADJUST_PRIVILEGES, &hToken) == false)
		return false;

	if (LookupPrivilegeValue(NULL, name, &luid) == FALSE) {
		CloseHandle(hToken);
		return false;
	}

	tp = ZeroMalloc(sizeof(TOKEN_PRIVILEGES));
	tp->PrivilegeCount = 1;
	tp->Privileges[0].Attributes = enable ? SE_PRIVILEGE_ENABLED : 0;
	Copy(&tp->Privileges[0].Luid, &luid, sizeof(LUID));

	// AdjustTokenPrivileges also succeeds when the token does not hold the privilege; it then sets
	// ERROR_NOT_ALL_ASSIGNED
	ret = AdjustTokenPrivileges(hToken, false, tp, sizeof(TOKEN_PRIVILEGES), 0, 0) && GetLastError() == ERROR_SUCCESS;

	Free(tp);
	CloseHandle(hToken);

	return ret;
}

bool MsIsAdmin() {
	return ms->IsAdmin;
}

UINT MsGetCurrentProcessId() {
	return ms->CurrentProcessId;
}

static void MsGetSpecialDirs() {
	char tmp[MAX_PATH];

	GetSystemDirectory(tmp, sizeof(tmp));
	Win32NukuEn(tmp, sizeof(tmp), tmp);
	ms->System32Dir = CopyStr(tmp);
	ms->System32DirW = CopyStrToUni(tmp);

	// The Windows directory is parent of the System32 directory
	Win32GetDirFromPath(tmp, sizeof(tmp), tmp);
	Win32NukuEn(tmp, sizeof(tmp), tmp);
	ms->WindowsDirW = CopyStrToUni(tmp);

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
}

// True when the process token is elevated: an elevated administrator or LocalSystem, not a standard
// user or an administrator filtered by UAC. Reads the token only; writes nothing.
static bool MsCheckIsAdmin() {
	HANDLE token;
	TOKEN_ELEVATION elevation;
	DWORD size = 0;
	bool ret = false;

	if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token) == false)
		return false;

	Zero(&elevation, sizeof(elevation));
	if (GetTokenInformation(token, TokenElevation, &elevation, sizeof(elevation), &size))
		ret = (elevation.TokenIsElevated != 0);

	CloseHandle(token);

	return ret;
}

void MsInit() {
	char tmp[MAX_SIZE];
	if (ms != NULL)
		return;

	ms = ZeroMalloc(sizeof(MS));

	ms->hInst = GetModuleHandle(NULL);

	ms->IsAdmin = MsCheckIsAdmin();

	ms->hCurrentProcess = GetCurrentProcess();
	ms->CurrentProcessId = GetCurrentProcessId();

	GetModuleFileName(NULL, tmp, sizeof(tmp));
	Win32GetDirFromPath(tmp, sizeof(tmp), tmp);
	ms->ExeFileDir = CopyStr(tmp);

	{
		wchar_t tmp_w[MAX_SIZE];

		// The wide APIs below count wide characters, not bytes
		Win32GetExeNameW(tmp_w, ARRAYSIZE(tmp_w));
		ms->ExeFileNameW = CopyUniStr(tmp_w);
	}

	MsGetSpecialDirs();

	MsInitTempDir();

	wchar_t tmp_w[MAX_SIZE];

	DWORD size = ARRAYSIZE(tmp_w);
	if (GetUserNameW(tmp_w, &size) == false)
		tmp_w[0] = 0;
	ms->UserNameW = CopyUniStr(tmp_w);
}

void MsFree() {
	if (ms == NULL)
		return;

	MsFreeTempDir();

	Free(ms->System32Dir);
	Free(ms->TempDir);
	Free(ms->ExeFileDir);
	Free(ms->WindowsDirW);
	Free(ms->System32DirW);
	Free(ms->TempDirW);
	Free(ms->ExeFileNameW);
	Free(ms->UserNameW);

	Free(ms);
	ms = NULL;
}

wchar_t *MsGetWindowsDirW() {
	return ms->WindowsDirW;
}
char *MsGetSystem32Dir() {
	return ms->System32Dir;
}
char *MsGetTempDir() {
	return ms->TempDir;
}
char *MsGetMyTempDir() {
	return ms->MyTempDir;
}

wchar_t *MsGetExeFileNameW() {
	return ms == NULL ? L"Unknown" : ms->ExeFileNameW;
}
wchar_t *MsGetSystem32DirW() {
	return ms->System32DirW;
}
wchar_t *MsGetMyTempDirW() {
	return ms->MyTempDirW;
}
wchar_t *MsGetUserNameW() {
	return ms->UserNameW;
}

