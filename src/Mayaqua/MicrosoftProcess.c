// SoftEther VPN Source Code - Developer Edition Master Branch
// Mayaqua Kernel


// MicrosoftProcess.c
// Windows processes, windows, tokens and privileges

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

// Search the process by the process ID
MS_PROCESS *MsSearchProcessById(LIST *o, UINT id)
{
	MS_PROCESS *p, t;
	// Validate arguments
	if (o == NULL)
	{
		return NULL;
	}

	Zero(&t, sizeof(t));
	t.ProcessId = id;

	p = Search(o, &t);

	return p;
}

// Compare the Process List items
int MsCompareProcessList(void *p1, void *p2)
{
	MS_PROCESS *e1, *e2;
	if (p1 == NULL || p2 == NULL)
	{
		return 0;
	}
	e1 = *(MS_PROCESS **)p1;
	e2 = *(MS_PROCESS **)p2;
	if (e1 == NULL || e2 == NULL)
	{
		return 0;
	}

	if (e1->ProcessId > e2->ProcessId)
	{
		return 1;
	}
	else if (e1->ProcessId < e2->ProcessId)
	{
		return -1;
	}
	else
	{
		return 0;
	}
}

// Release of the process list
void MsFreeProcessList(LIST *o)
{
	UINT i;
	// Validate arguments
	if (o == NULL)
	{
		return;
	}

	for (i = 0;i < LIST_NUM(o);i++)
	{
		MS_PROCESS *p = LIST_DATA(o, i);
		Free(p);
	}

	ReleaseList(o);
}

// Get the Process List (for WinNT)
LIST *MsGetProcessListNt()
{
	LIST *o;
	UINT max = 16384;
	DWORD *processes;
	DWORD needed;
	UINT num;
	UINT i;

	o = NewListFast(MsCompareProcessList);

	processes = ZeroMalloc(sizeof(DWORD) * max);

	if (EnumProcesses(processes, sizeof(DWORD) * max, &needed) == FALSE)
	{
		Free(processes);
		return NULL;
	}

	num = needed / sizeof(DWORD);

	for (i = 0;i < num;i++)
	{
		UINT id = processes[i];
		HANDLE h = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
			false, id);

		if (h != NULL)
		{
			HINSTANCE hInst = NULL;
			DWORD needed;
			char exe[MAX_SIZE];
			wchar_t exe_w[MAX_SIZE];
			bool ok = false;
			DWORD sz1, sz2;

			sz1 = sizeof(exe) - 1;
			sz2 = sizeof(exe_w) / sizeof(wchar_t) - 1;

			if (EnumProcessModules(h, &hInst, sizeof(hInst), &needed) == false)
			{
				hInst = NULL;
			}

			if (GetModuleFileNameExA(h, hInst, exe, sizeof(exe) - 1) &&
				GetModuleFileNameExW(h, hInst, exe_w, sizeof(exe_w) / sizeof(wchar_t) - 1))
			{
				ok = true;
			}
			else if (QueryFullProcessImageNameA(h, 0, exe, &sz1) &&
				QueryFullProcessImageNameW(h, 0, exe_w, &sz2))
			{
				ok = true;
			}

			if (ok)
			{
				MS_PROCESS *p = ZeroMalloc(sizeof(MS_PROCESS));

				StrCpy(p->ExeFilename, sizeof(p->ExeFilename), exe);
				UniStrCpy(p->ExeFilenameW, sizeof(p->ExeFilenameW), exe_w);
				p->ProcessId = id;

				Add(o, p);
			}

			CloseHandle(h);
		}
	}

	Sort(o);

	Free(processes);

	return o;
}

// Get the Process List
LIST *MsGetProcessList()
{
	return MsGetProcessListNt();
}

// Lower the priority of the thread to lowest
void MsSetThreadPriorityIdle()
{
	SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_IDLE);
}

// Raise the priority of the thread to highest
void MsSetThreadPriorityRealtime()
{
	SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_ABOVE_NORMAL);
	SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_HIGHEST);
	SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_TIME_CRITICAL);
}

// Restore the priority of the thread
void MsRestoreThreadPriority()
{
	SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_NORMAL);
}

// Child window enumeration procedure
BOOL CALLBACK MsEnumChildWindowProc(HWND hWnd, LPARAM lParam)
{
	LIST *o = (LIST *)lParam;

	if (o != NULL)
	{
		MsEnumChildWindows(o, hWnd);
	}

	return true;
}

// Enumerate specified window and all the its child windows
LIST *MsEnumChildWindows(LIST *o, HWND hWnd)
{
	// Validate arguments
	if (hWnd == NULL)
	{
		return NULL;
	}

	if (o == NULL)
	{
		o = NewListFast(NULL);
	}

	MsAddWindowToList(o, hWnd);

	EnumChildWindows(hWnd, MsEnumChildWindowProc, (LPARAM)o);

	return o;
}

// Add a window to the list
void MsAddWindowToList(LIST *o, HWND hWnd)
{
	// Validate arguments
	if (o == NULL || hWnd == NULL)
	{
		return;
	}

	if (IsInList(o, hWnd) == false)
	{
		Add(o, hWnd);
	}
}

// Window enumeration procedure
BOOL CALLBACK EnumTopWindowProc(HWND hWnd, LPARAM lParam)
{
	LIST *o = (LIST *)lParam;
	HWND hParent;
	char c1[MAX_SIZE], c2[MAX_SIZE];
	// Validate arguments
	if (hWnd == NULL || o == NULL)
	{
		return TRUE;
	}

	Zero(c1, sizeof(c1));
	Zero(c2, sizeof(c2));

	hParent = GetParent(hWnd);

	GetClassName(hWnd, c1, sizeof(c1));

	if (hParent != NULL)
	{
		GetClassName(hParent, c2, sizeof(c2));
	}

	if (StrCmpi(c1, "SysIPAddress32") != 0 && (IsEmptyStr(c2) || StrCmpi(c2, "SysIPAddress32") != 0))
	{
		AddWindow(o, hWnd);
	}

	return TRUE;
}

// Child window enumeration procedure
BOOL CALLBACK EnumChildWindowProc(HWND hWnd, LPARAM lParam)
{
	ENUM_CHILD_WINDOW_PARAM *p = (ENUM_CHILD_WINDOW_PARAM *)lParam;
	LIST *o;
	HWND hParent;
	char c1[MAX_SIZE], c2[MAX_SIZE];
	bool ok = false;
	// Validate arguments
	if (hWnd == NULL || p == NULL)
	{
		return TRUE;
	}

	o = p->o;

	Zero(c1, sizeof(c1));
	Zero(c2, sizeof(c2));

	hParent = GetParent(hWnd);

	GetClassName(hWnd, c1, sizeof(c1));

	if (hParent != NULL)
	{
		GetClassName(hParent, c2, sizeof(c2));
	}

	if (p->include_ipcontrol || (StrCmpi(c1, "SysIPAddress32") != 0 && (IsEmptyStr(c2) || StrCmpi(c2, "SysIPAddress32") != 0)))
	{
		ok = true;
	}

	if (ok)
	{
		AddWindow(o, hWnd);

		if (p->no_recursion == false)
		{
			EnumChildWindows(hWnd, EnumChildWindowProc, (LPARAM)p);
		}
	}

	return TRUE;
}

LIST *EnumAllTopWindow()
{
	LIST *o = NewWindowList();

	EnumWindows(EnumTopWindowProc, (LPARAM)o);

	return o;
}

// Enumerate the child windows of all that is in the specified window
LIST *EnumAllChildWindow(HWND hWnd)
{
	return EnumAllChildWindowEx(hWnd, false, false, false);
}

LIST *EnumAllChildWindowEx(HWND hWnd, bool no_recursion, bool include_ipcontrol, bool no_self)
{
	ENUM_CHILD_WINDOW_PARAM p;
	LIST *o = NewWindowList();

	Zero(&p, sizeof(p));
	p.include_ipcontrol = include_ipcontrol;
	p.no_recursion = no_recursion;
	p.o = o;

	if (no_self == false)
	{
		AddWindow(o, hWnd);
	}

	EnumChildWindows(hWnd, EnumChildWindowProc, (LPARAM)&p);

	return o;
}

// Release of the window list
void FreeWindowList(LIST *o)
{
	UINT i;
	// Validate arguments
	if (o == NULL)
	{
		return;
	}

	for (i = 0;i < LIST_NUM(o);i++)
	{
		HWND *e = LIST_DATA(o, i);

		Free(e);
	}

	ReleaseList(o);
}

// Add a window to the window list
void AddWindow(LIST *o, HWND hWnd)
{
	HWND t, *e;
	// Validate arguments
	if (o == NULL || hWnd == NULL)
	{
		return;
	}

	t = hWnd;

	if (Search(o, &t) != NULL)
	{
		return;
	}

	e = ZeroMalloc(sizeof(HWND));
	*e = hWnd;

	Insert(o, e);
}

// Comparison of the window list items
int CmpWindowList(void *p1, void *p2)
{
	HWND *h1, *h2;
	if (p1 == NULL || p2 == NULL)
	{
		return 0;
	}
	h1 = *(HWND **)p1;
	h2 = *(HWND **)p2;
	if (h1 == NULL || h2 == NULL)
	{
		return 0;
	}

	return Cmp(h1, h2, sizeof(HWND));
}

// Creating a new window list
LIST *NewWindowList()
{
	return NewListFast(CmpWindowList);
}

// Get the process path of the owner of the window
bool MsGetWindowOwnerProcessExeName(char *path, UINT size, HWND hWnd)
{
	DWORD procId = 0;
	// Validate arguments
	if (path == NULL || hWnd == NULL)
	{
		return false;
	}

	GetWindowThreadProcessId(hWnd, &procId);
	if (procId == 0)
	{
		return false;
	}

	if (MsGetProcessExeName(path, size, procId) == false)
	{
		return false;
	}

	return true;
}

// Get the process path from process ID
bool MsGetProcessExeName(char *path, UINT size, UINT id)
{
	LIST *o;
	MS_PROCESS *proc;
	bool ret = false;
	// Validate arguments
	if (path == NULL)
	{
		return false;
	}

	o = MsGetProcessList();
	proc = MsSearchProcessById(o, id);

	if (proc != NULL)
	{
		ret = true;
		StrCpy(path, size, proc->ExeFilename);
	}

	MsFreeProcessList(o);

	return ret;
}

// Close the alert dialog
bool MsCloseWarningWindow(NO_WARNING *nw, UINT thread_id)
{
	UINT i;
	LIST *o;
	bool ret = false;
	bool press = false;

	if (nw->StartTimer == 0)
	{
		press = true;
	}

	if (nw->StartTick != 0 && nw->StartTick <= Tick64())
	{
		press = true;
	}

	o = EnumAllTopWindow();

	for (i = 0;i < LIST_NUM(o);i++)
	{
		HWND hWnd;

		if (nw->Halt)
		{
			break;
		}
		
		hWnd = *((HWND *)LIST_DATA(o, i));

		if (hWnd != NULL)
		{
			if (true)
			{
				// Get whether this window is a warning screen of driver
				if (true)
				{
					// Windows Vista
					char exe[MAX_PATH];

					if (MsGetWindowOwnerProcessExeName(exe, sizeof(exe), hWnd))
					{
						if (EndWith(exe, "rundll32.exe"))
						{
							LIST *o;
							HWND h;
							UINT i;

							o = EnumAllChildWindow(hWnd);

							if (o != NULL)
							{
								for (i = 0;i < LIST_NUM(o);i++)
								{
									char tmp[MAX_SIZE];

									h = *((HWND *)LIST_DATA(o, i));

									Zero(tmp, sizeof(tmp));
									GetClassNameA(h, tmp, sizeof(tmp));

									if (StrCmpi(tmp, "DirectUIHWND") == 0)
									{
										LIST *o = EnumAllChildWindow(h);

										if (o != NULL)
										{
											UINT j;
											UINT numDirectUIHWND = 0;
											UINT numButton = 0;
											HWND hButton1 = NULL;
											HWND hButton2 = NULL;

											for (j = 0;j < LIST_NUM(o);j++)
											{
												HWND hh;
												char tmp[MAX_SIZE];

												hh = *((HWND *)LIST_DATA(o, j));

												Zero(tmp, sizeof(tmp));
												GetClassNameA(hh, tmp, sizeof(tmp));

												if (StrCmpi(tmp, "DirectUIHWND") == 0)
												{
													numDirectUIHWND++;
												}

												if (StrCmpi(tmp, "button") == 0)
												{
													numButton++;
													if (hButton1 == NULL)
													{
														hButton1 = hh;
													}
													else
													{
														hButton2 = hh;
													}
												}
											}

											if ((numDirectUIHWND == 1 || numDirectUIHWND == 2) && numButton == 2)
											{
												if (hButton1 != NULL && hButton2 != NULL)
												{
													HWND hButton;
													HWND hParent;
													RECT r1, r2;

													GetWindowRect(hButton1, &r1);
													GetWindowRect(hButton2, &r2);

													hButton = hButton1;

													if (numDirectUIHWND == 1)
													{
														// Warning that there is no signature
														if (r1.top < r2.top)
														{
															hButton = hButton2;
														}
													}
													else
													{
														// Notification that there is signature
														if (r1.left >= r2.left)
														{
															hButton = hButton2;
														}
													}

													hParent = GetParent(hButton);

													// Press the OK button since it was found
													if (press)
													{
														PostMessage(hParent, WM_COMMAND, 1, 0);
													}

													ret = true;
												}
											}

											FreeWindowList(o);
										}
									}
								}

								FreeWindowList(o);
							}
						}
					}
				}
			}
		}
	}

	FreeWindowList(o);

	if (press == false)
	{
		if (ret)
		{
			ret = false;

			if (nw->StartTick == 0)
			{
				nw->StartTick = Tick64() + nw->StartTimer;
			}
		}
	}

	return ret;
}

// Thread to suppress a warning message
void MsNoWarningThreadProc(THREAD *thread, void *param)
{
	NO_WARNING *nw;
	UINT interval;
	UINT i;
	bool found0 = false;
	// Validate arguments
	if (thread == NULL)
	{
		return;
	}

	nw = (NO_WARNING *)param;

	nw->NoWarningThread = thread;
	AddRef(thread->ref);

	NoticeThreadInit(thread);

	interval = 1000;

	i = 0;

	while (nw->Halt == false)
	{
		bool found = false;

		// Close the alert dialog
		found = MsCloseWarningWindow(nw, nw->ThreadId);
		if (i == 0)
		{
			found0 = found;
		}
		else
		{
			if (found0 == false && found)
			{
				break;
			}
		}
		i++;

		// Loop until the command incomes from parent thread
		Wait(nw->HaltEvent, interval);
	}
}

// The start of the procedure to suppress the warning
NO_WARNING *MsInitNoWarningEx(UINT start_timer)
{
	THREAD *thread;
	NO_WARNING *nw = ZeroMalloc(sizeof(NO_WARNING));

	nw->StartTimer = (UINT64)start_timer;
	nw->ThreadId = GetCurrentThreadId();
	nw->HaltEvent = NewEvent();

	thread = NewThread(MsNoWarningThreadProc, nw);
	WaitThreadInit(thread);

	ReleaseThread(thread);

	return nw;
}

// End of the procedure to suppress the warning
void MsFreeNoWarning(NO_WARNING *nw)
{
	// Validate arguments
	if (nw == NULL)
	{
		return;
	}

	nw->Halt = true;
	Set(nw->HaltEvent);

	WaitThread(nw->NoWarningThread, INFINITE);

	ReleaseThread(nw->NoWarningThread);
	ReleaseEvent(nw->HaltEvent);
	Free(nw);
}

// Attempt to logon to the domain
bool MsCheckLogon(wchar_t *username, char *password)
{
	wchar_t password_unicode[MAX_SIZE];
	HANDLE h;
	// Validate arguments
	if (username == NULL || password == NULL)
	{
		return false;
	}

	StrToUni(password_unicode, sizeof(password_unicode), password);

	if (GET_KETA(GetOsInfo()->OsType, 100) >= 2)
	{
		if (LogonUserW(username, NULL, password_unicode, LOGON32_LOGON_NETWORK, LOGON32_PROVIDER_DEFAULT, &h) == false)
		{
			// Logon failure
			return false;
		}
	}
	else
	{
		char username_ansi[MAX_SIZE];
		UniToStr(username_ansi, sizeof(username_ansi), username);

		if (LogonUserA(username_ansi, NULL, password, LOGON32_LOGON_NETWORK, LOGON32_PROVIDER_DEFAULT, &h) == false)
		{
			// Logon failure
			return false;
		}
	}

	CloseHandle(h);

	return true;
}

// Check whether the current user is a Administrators
bool MsCheckIsAdmin()
{
	UCHAR test_bit[32];
	UCHAR tmp[32];
	UCHAR exe_hash[SHA1_SIZE];
	char *name_tag = "Vpn_Check_Admin_Key_%u";
	DWORD type;
	DWORD size;
	char name[MAX_SIZE];

	Sha1(exe_hash, MsGetExeFileNameW(), UniStrLen(MsGetExeFileNameW()));

	Format(name, sizeof(name), name_tag, *((UINT *)exe_hash));

	Rand(test_bit, sizeof(test_bit));

	if (RegSetValueEx(HKEY_LOCAL_MACHINE, name, 0, REG_BINARY, test_bit, sizeof(test_bit)) != ERROR_SUCCESS)
	{
		return false;
	}

	size = sizeof(tmp);
	if (RegQueryValueEx(HKEY_LOCAL_MACHINE, name, 0, &type, tmp, &size) != ERROR_SUCCESS)
	{
		RegDeleteValue(HKEY_LOCAL_MACHINE, name);
		return false;
	}

	RegDeleteValue(HKEY_LOCAL_MACHINE, name);

	if (Cmp(test_bit, tmp, 32) != 0)
	{
		return false;
	}

	return true;
}

#endif	// WIN32

