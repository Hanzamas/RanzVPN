// vpncmd.c
// VPN Command Line Management Utility

#include "Cedar/Cedar.h"
#include "Cedar/Command.h"

#include "Mayaqua/Internat.h"
#include "Mayaqua/Memory.h"
#include "Mayaqua/Microsoft.h"
#include "Mayaqua/Str.h"

#include <TlHelp32.h>

// A command shell (cmd.exe, command.com) runs on this computer: Toolhelp32 snapshot of the processes
static bool VpncmdIsShellRunning()
{
	HANDLE h;
	PROCESSENTRY32W e;
	bool ret = false;

	h = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (h == INVALID_HANDLE_VALUE)
	{
		return false;
	}

	Zero(&e, sizeof(e));
	e.dwSize = sizeof(e);

	if (Process32FirstW(h, &e))
	{
		do
		{
			if (UniStrCmpi(e.szExeFile, L"cmd.exe") == 0 || UniStrCmpi(e.szExeFile, L"command.com") == 0)
			{
				ret = true;
				break;
			}
		}
		while (Process32NextW(h, &e));
	}

	CloseHandle(h);

	return ret;
}

int main(int argc, char *argv[])
{
	wchar_t *s;
	UINT ret = 0;

	InitProcessCallOnce();

	SetConsoleTitleA(CEDAR_PRODUCT_STR " VPN Command Line Utility");

#ifdef	_DEBUG	// Debug configuration: the debug CRT (/MTd) defines _DEBUG
	// memcheck = true logs every malloc/realloc/free to find leaks; it is very slow.
	InitMayaqua(false, true, argc, argv);
#else
	InitMayaqua(false, false, argc, argv);
#endif
	InitCedar();

	s = GetCommandLineUniStr();

	if (s == NULL)
	{
		s = CopyUniStr(L"");
	}

	if (UniStrCmpi(s, L"exit") != 0)
	{
		UINT size = UniStrSize(s) + 64;
		wchar_t *tmp;

		tmp = Malloc(size);
		UniFormat(tmp, size, L"vpncmd %s", s);
		ret = CommandMain(tmp);

		Free(tmp);
	}

	if (VpncmdIsShellRunning() == false)
	{
		if (ret != ERR_NO_ERROR)
		{
			SleepThread(1000);
		}
	}

	Free(s);

	FreeCedar();
	FreeMayaqua();
	return ret;
}


