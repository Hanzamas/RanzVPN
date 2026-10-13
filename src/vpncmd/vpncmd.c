// SoftEther VPN Source Code - Developer Edition Master Branch
// Cedar Communication Module


// vpncmd.c
// VPN Command Line Management Utility

#include "Cedar/Cedar.h"
#include "Cedar/Command.h"

#include "Mayaqua/Internat.h"
#include "Mayaqua/Memory.h"
#include "Mayaqua/Microsoft.h"
#include "Mayaqua/Str.h"

int main(int argc, char *argv[])
{
	wchar_t *s;
	UINT ret = 0;

	InitProcessCallOnce();

	SetConsoleTitleA(CEDAR_PRODUCT_STR " VPN Command Line Utility");

#if defined(_DEBUG) || defined(DEBUG)	// MSVC defines _DEBUG, not DEBUG
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

	{
		UINT i;
		LIST *o = MsGetProcessList();
		bool b = false;

		for (i = 0;i < LIST_NUM(o);i++)
		{
			MS_PROCESS *p = LIST_DATA(o, i);

			if (EndWith(p->ExeFilename, "\\cmd.exe") || EndWith(p->ExeFilename, "\\command.com"))
			{
				b = true;
				break;
			}
		}

		MsFreeProcessList(o);

		if (b == false)
		{
			if (ret != ERR_NO_ERROR)
			{
				SleepThread(1000);
			}
		}
	}

	Free(s);

	FreeCedar();
	FreeMayaqua();
	return ret;
}


