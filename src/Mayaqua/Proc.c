// Proc.c
// Process launch and wait of the Win32 layer (declared in Win32.h)

#include "Win32.h"

#include "Internat.h"
#include "Memory.h"

void Win32CloseProcess(void *handle)
{
	if (handle == NULL)
	{
		return;
	}

	CloseHandle((HANDLE)handle);
}

bool Win32WaitProcess(void *h, UINT timeout)
{
	if (h == NULL)
	{
		return false;
	}
	if (timeout == 0)
	{
		timeout = INFINITE;
	}

	if (WaitForSingleObject((HANDLE)h, timeout) == WAIT_TIMEOUT)
	{
		return false;
	}

	return true;
}

bool Win32Run(char *filename, char *arg, bool hide, bool wait)
{
	STARTUPINFOW info;
	PROCESS_INFORMATION ret;
	wchar_t cmdline[MAX_SIZE];
	wchar_t name[MAX_PATH];
	wchar_t arg_w[MAX_SIZE];
	if (filename == NULL)
	{
		return false;
	}

	StrToUni(name, sizeof(name), filename);
	UniTrim(name);

	if (arg != NULL)
	{
		StrToUni(arg_w, sizeof(arg_w), arg);
	}

	// Quote a bare path so CreateProcess does not probe "C:\Program" first; a name that already has quotes goes as is
	if (UniSearchStr(name, L"\"", 0) == INFINITE)
	{
		if (arg == NULL)
		{
			UniFormat(cmdline, sizeof(cmdline), L"\"%s\"", name);
		}
		else
		{
			UniFormat(cmdline, sizeof(cmdline), L"\"%s\" %s", name, arg_w);
		}
	}
	else
	{
		if (arg == NULL)
		{
			UniFormat(cmdline, sizeof(cmdline), L"%s", name);
		}
		else
		{
			UniFormat(cmdline, sizeof(cmdline), L"%s %s", name, arg_w);
		}
	}

	Zero(&info, sizeof(info));
	Zero(&ret, sizeof(ret));
	info.cb = sizeof(info);
	info.dwFlags = STARTF_USESHOWWINDOW;
	info.wShowWindow = (hide == false ? SW_SHOWDEFAULT : SW_HIDE);

	UniTrim(cmdline);

	// CREATE_NO_WINDOW is ignored together with CREATE_NEW_CONSOLE, so a hidden launch sets it alone
	if (CreateProcessW(NULL, cmdline, NULL, NULL, FALSE,
		(hide == false ? CREATE_NEW_CONSOLE : CREATE_NO_WINDOW) | NORMAL_PRIORITY_CLASS,
		NULL, NULL, &info, &ret) == FALSE)
	{
		return false;
	}

	if (wait)
	{
		WaitForSingleObject(ret.hProcess, INFINITE);
	}

	CloseHandle(ret.hThread);
	CloseHandle(ret.hProcess);

	return true;
}
