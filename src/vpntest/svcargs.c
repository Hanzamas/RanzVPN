// svcargs.c
// Named service argument test of vpntest ("svcargs" command, FND-205 #167)
//
// MsService picks its mode from the first command line argument through one static table
// (MsSvcArgs, MsSvcArgToMode), and SVC_HELP lists exactly the arguments of that table. The old code
// also took /usermode_showtray and /usermode_hidetray as aliases of /usermode, and SVC_HELP listed
// them with a note on Windows NT / XP / Server 2003 / Vista / Server 2008. The test checks that each
// documented argument maps to its mode, also in upper case, that the table holds no other argument,
// that SVC_HELP lists each one as "<argument> :" and no other, and that the tray arguments, /silent,
// an empty string and NULL map to no mode (the tray checks fail on the old code). Prints
// "SVCARGS TEST OK" only when every check passes, and frees everything it allocates.

#include "Mayaqua/Internat.h"
#include "Mayaqua/Memory.h"
#include "Mayaqua/Microsoft.h"
#include "Mayaqua/Str.h"
#include "Mayaqua/Table.h"

#include <stdarg.h>

// Run state of the test
typedef struct SVCARGS_TEST
{
	UINT NumChecks;						// Checks run so far
	UINT NumFailed;						// Checks failed so far
} SVCARGS_TEST;

// The documented arguments and their modes, written out here apart from the table of Microsoft.c
static const MS_SVC_ARG svcargs_expect[] =
{
	{"/install", SVC_MODE_INSTALL},
	{"/uninstall", SVC_MODE_UNINSTALL},
	{"/start", SVC_MODE_START},
	{"/stop", SVC_MODE_STOP},
	{"/test", SVC_MODE_TEST},
	{"/usermode", SVC_MODE_USERMODE},
	{"/setup_install", SVC_MODE_SETUP_INSTALL},
	{"/setup_uninstall", SVC_MODE_SETUP_UNINSTALL},
	{"/service", SVC_MODE_SERVICE},
};

// Arguments that select no mode: the former tray aliases, the /silent modifier and other strings
static char *svcargs_none[] =
{
	"/usermode_showtray",
	"/usermode_hidetray",
	"/silent",
	"",
	"/",
	"install",
	"/install ",
	"/usermode_",
};

// Record one check: print [PASS], or [FAIL] with the formatted detail
static void SvcArgsTestCheck(SVCARGS_TEST *t, bool ok, char *what, char *detail_fmt, ...)
{
	char detail[MAX_SIZE];
	va_list args;

	t->NumChecks++;

	if (ok)
	{
		Print("  [PASS] %s\n", what);
		return;
	}

	va_start(args, detail_fmt);
	FormatArgs(detail, sizeof(detail), detail_fmt, args);
	va_end(args);

	Print("  [FAIL] %s (%s)\n", what, detail);

	t->NumFailed++;
}

// The number of times keyword occurs in str
static UINT SvcArgsTestCount(wchar_t *str, wchar_t *keyword)
{
	UINT num = 0;
	UINT pos = 0;
	UINT len = UniStrLen(keyword);

	while (true)
	{
		UINT found = UniSearchStr(str, keyword, pos);

		if (found == INFINITE)
		{
			break;
		}

		num++;
		pos = found + len;
	}

	return num;
}

// svcargs: the argument table of MsService, its modes and SVC_HELP
void svcargs_test(UINT num, char **arg)
{
	SVCARGS_TEST t;
	UINT table_num = 0;

	Zero(&t, sizeof(t));

	Print("Service argument test (MsSvcArgs, MsSvcArgToMode, SVC_HELP)\n");

	// Each documented argument selects its mode, also in upper case
	for (UINT i = 0;i < sizeof(svcargs_expect) / sizeof(svcargs_expect[0]);i++)
	{
		char what[MAX_SIZE];
		char upper[MAX_SIZE];
		UINT mode = MsSvcArgToMode(svcargs_expect[i].Arg);

		Format(what, sizeof(what), "%s selects mode %u", svcargs_expect[i].Arg, svcargs_expect[i].Mode);
		SvcArgsTestCheck(&t, mode == svcargs_expect[i].Mode, what, "mode %u", mode);

		StrCpy(upper, sizeof(upper), svcargs_expect[i].Arg);
		StrUpper(upper);
		mode = MsSvcArgToMode(upper);
		Format(what, sizeof(what), "%s selects mode %u", upper, svcargs_expect[i].Mode);
		SvcArgsTestCheck(&t, mode == svcargs_expect[i].Mode, what, "mode %u", mode);
	}

	// The table holds the documented arguments and no other
	const MS_SVC_ARG *table = MsSvcArgs(&table_num);
	SvcArgsTestCheck(&t, table != NULL && table_num == sizeof(svcargs_expect) / sizeof(svcargs_expect[0]),
		"the table holds exactly the documented arguments", "%u entries", table_num);

	// The former tray aliases and other strings select no mode
	for (UINT i = 0;i < sizeof(svcargs_none) / sizeof(svcargs_none[0]);i++)
	{
		char what[MAX_SIZE];
		UINT mode = MsSvcArgToMode(svcargs_none[i]);

		Format(what, sizeof(what), "\"%s\" selects no mode", svcargs_none[i]);
		SvcArgsTestCheck(&t, mode == SVC_MODE_NONE, what, "mode %u", mode);
	}
	SvcArgsTestCheck(&t, MsSvcArgToMode(NULL) == SVC_MODE_NONE, "NULL selects no mode", "mode %u", MsSvcArgToMode(NULL));

	// SVC_HELP lists each argument of the table as "<argument> :", and no other argument
	wchar_t *help = _UU("SVC_HELP");
	SvcArgsTestCheck(&t, UniStrLen(help) != 0, "SVC_HELP is in the string table", "empty");

	for (UINT i = 0;table != NULL && i < table_num;i++)
	{
		char what[MAX_SIZE];
		char line[MAX_SIZE];
		wchar_t line_w[MAX_SIZE];

		// "/install : " is not inside "/setup_install : ": the slash comes right before the name
		Format(line, sizeof(line), "%s : ", table[i].Arg);
		StrToUni(line_w, sizeof(line_w), line);
		UINT count = SvcArgsTestCount(help, line_w);

		Format(what, sizeof(what), "SVC_HELP lists %s once", table[i].Arg);
		SvcArgsTestCheck(&t, count == 1, what, "%u times", count);
	}

	{
		UINT count = SvcArgsTestCount(help, L" : ");

		SvcArgsTestCheck(&t, count == table_num, "SVC_HELP lists no argument outside the table",
			"%u argument lines, %u table entries", count, table_num);
	}

	SvcArgsTestCheck(&t, SvcArgsTestCount(help, L"tray") == 0, "SVC_HELP names no tray argument", "found");
	SvcArgsTestCheck(&t, SvcArgsTestCount(help, L"Windows NT") == 0 && SvcArgsTestCount(help, L"2003") == 0 &&
		SvcArgsTestCount(help, L"Vista") == 0 && SvcArgsTestCount(help, L"2008") == 0,
		"SVC_HELP names no legacy Windows version", "found");

	if (t.NumFailed == 0)
	{
		Print("SVCARGS TEST OK\n");
	}
	else
	{
		Print("SVCARGS TEST FAILED (%u of %u checks failed)\n", t.NumFailed, t.NumChecks);
	}
}
