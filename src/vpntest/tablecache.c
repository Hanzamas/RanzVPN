// tablecache.c
// Named string table loader test of vpntest ("tablecache" command, FND-43 #114)
//
// LoadTableW() read '@table_name.txt' beside the exe: when it named another file, that file was
// loaded instead of the string table asked for, so anyone who can write the exe directory replaced
// every string of the program. The parsed table was also cached in %TEMP% and trusted at the next
// start; SEC-8 removed that cache and the tempdir test pins it. This test plants a table_name.txt
// that names a crafted string table beside the exe, loads the current string table, and checks that
// the strings come from the resource and that the load writes no file beside the exe or in the temp
// directory of the process. It also checks that languages.txt still yields the language list and
// the LCIDs. Prints "TABLECACHE TEST OK" only when every check passes, removes the planted files and
// frees everything it allocates.

#include "Mayaqua/FileIO.h"
#include "Mayaqua/Internat.h"
#include "Mayaqua/Mayaqua.h"
#include "Mayaqua/Memory.h"
#include "Mayaqua/Microsoft.h"
#include "Mayaqua/Str.h"
#include "Mayaqua/Table.h"

#include <stdarg.h>

#define	TABLECACHE_OVERRIDE_FILE	L"table_name.txt"			// The former override, '@table_name.txt'
#define	TABLECACHE_PLANTED_FILE		L"tablecache_planted.stb"	// Crafted string table it names
#define	TABLECACHE_PLANTED_NAME		"TABLECACHE_PLANTED"		// Key only the crafted table holds
#define	TABLECACHE_RESOURCE_NAME	"COMMON_UNKNOWN"			// Key every resource table holds

// Run state of the test
typedef struct TABLECACHE_CTX
{
	UINT NumChecks;						// Checks run so far
	UINT NumFailed;						// Checks failed so far
} TABLECACHE_CTX;

// Record one check: print [PASS], or [FAIL] with the formatted detail
static void TableCacheCheck(TABLECACHE_CTX *ctx, bool ok, char *what, char *detail_fmt, ...)
{
	char detail[MAX_SIZE];
	va_list args;

	ctx->NumChecks++;

	if (ok)
	{
		Print("  [PASS] %s\n", what);
		return;
	}

	va_start(args, detail_fmt);
	FormatArgs(detail, sizeof(detail), detail_fmt, args);
	va_end(args);

	Print("  [FAIL] %s (%s)\n", what, detail);

	ctx->NumFailed++;
}

// The language of the list with this name, or NULL
static LANGLIST *TableCacheFindLang(LIST *o, const char *name)
{
	for (UINT i = 0;i < LIST_NUM(o);i++)
	{
		LANGLIST *e = LIST_DATA(o, i);

		if (StrCmpi(e->Name, name) == 0)
		{
			return e;
		}
	}

	return NULL;
}

// True when the language has the name and the Windows locale ID
static bool TableCacheLangOk(LANGLIST *e, const char *name, UINT lcid)
{
	return e != NULL && StrCmpi(e->Name, name) == 0 && IsIntInList(e->LcidList, lcid);
}

// Name of the string table of the language, or false when the list has no such language
static bool TableCacheTableName(LIST *o, UINT id, char *name, UINT size)
{
	for (UINT i = 0;i < LIST_NUM(o);i++)
	{
		LANGLIST *e = LIST_DATA(o, i);

		if (e->Id == id)
		{
			Format(name, size, "|strtable_%s.stb", e->Name);
			return true;
		}
	}

	return false;
}

// Number of files in the directory that the list taken before does not hold; prints their names
static UINT TableCacheNewFiles(const DIRLIST *before, wchar_t *dir)
{
	UINT num = 0;

	DIRLIST *d = EnumDirW(dir);
	if (d == NULL)
	{
		return 0;
	}

	for (UINT i = 0;i < d->NumFiles;i++)
	{
		struct DIRENT *e = d->File[i];
		bool found = false;

		if (e->Folder)
		{
			continue;
		}

		for (UINT j = 0;before != NULL && j < before->NumFiles;j++)
		{
			if (UniStrCmpi(before->File[j]->FileNameW, e->FileNameW) == 0)
			{
				found = true;
				break;
			}
		}

		if (found == false)
		{
			Print("  new file: %S\\%S\n", dir, e->FileNameW);
			num++;
		}
	}

	FreeDir(d);

	return num;
}

// True when the current string table is the resource table of the language
static bool TableCacheResourceInUse(UINT lang_id)
{
	return FindTable(TABLECACHE_PLANTED_NAME) == NULL &&
		StrCmpi(_SS("STRTABLE_ID"), STRTABLE_ID) == 0 &&
		_II("LANG") == lang_id &&
		UniIsEmptyStr(_UU(TABLECACHE_RESOURCE_NAME)) == false;
}

// tablecache: the string table comes from the resource only: a table_name.txt beside the exe that
// names a crafted table is ignored, and loading a table writes no cache file
void tablecache_test(UINT num, char **arg)
{
	TABLECACHE_CTX ctx;
	wchar_t exe_dir[MAX_PATH];
	wchar_t override_path[MAX_PATH];
	wchar_t planted_path[MAX_PATH];
	char override_text[MAX_SIZE];
	char planted_text[MAX_SIZE];
	char cur_table[MAX_SIZE];

	Zero(&ctx, sizeof(ctx));

	Print("String table loader test (LoadTable, LoadLangList)\n");

	// (1) languages.txt still yields the language list and the LCIDs
	UINT lang_id = GetCurrentLangId();
	LIST *langs = LoadLangList();

	TableCacheCheck(&ctx, langs != NULL && LIST_NUM(langs) >= 2, "languages.txt yields two languages or more",
		"%u languages", langs == NULL ? 0 : LIST_NUM(langs));

	LANGLIST *en = langs == NULL ? NULL : TableCacheFindLang(langs, "en");
	LANGLIST *id = langs == NULL ? NULL : TableCacheFindLang(langs, "id");

	TableCacheCheck(&ctx, TableCacheLangOk(en, "en", 1033) && en->Id == 1, "English is language 1 with LCID 1033",
		"en %s", en == NULL ? "missing" : "has another ID or no LCID 1033");

	TableCacheCheck(&ctx, TableCacheLangOk(id, "id", 1057) && id->Id == 7, "Indonesian is language 7 with LCID 1057",
		"id %s", id == NULL ? "missing" : "has another ID or no LCID 1057");

	TableCacheCheck(&ctx, langs != NULL && GetBestLangByLcid(langs, 1057) == id && id != NULL,
		"LCID 1057 selects Indonesian", "another language");

	TableCacheCheck(&ctx, langs != NULL && GetBestLangByLcid(langs, 0xFFFF) == en && en != NULL,
		"An unknown LCID falls back to English", "another language");

	bool has_table = langs != NULL && TableCacheTableName(langs, lang_id, cur_table, sizeof(cur_table));

	TableCacheCheck(&ctx, has_table, "The current language has a string table", "language %u not in the list", lang_id);

	FreeLangList(langs);

	// (2) Plant table_name.txt beside the exe, naming a crafted table with the right STRTABLE_ID
	GetExeDirW(exe_dir, sizeof(exe_dir));
	wchar_t *my_temp = MsGetMyTempDirW();

	CombinePathW(override_path, sizeof(override_path), exe_dir, TABLECACHE_OVERRIDE_FILE);
	CombinePathW(planted_path, sizeof(planted_path), exe_dir, TABLECACHE_PLANTED_FILE);

	StrCpy(override_text, sizeof(override_text), "@tablecache_planted.stb\r\n");
	Format(planted_text, sizeof(planted_text),
		"DEFAULT_LOCALE\t\t\t- - $ : : $ Sun Mon Tue Wed Thu Fri Sat : : : $ (None)\r\n"
		"LANG\t\t\t\t\t%u\r\n"
		"STRTABLE_ID\t\t\t\t%s\r\n"
		"%s\t\tplanted\r\n",
		lang_id, STRTABLE_ID, TABLECACHE_PLANTED_NAME);

	bool planted = DumpDataW(planted_text, StrLen(planted_text), planted_path) &&
		DumpDataW(override_text, StrLen(override_text), override_path);

	TableCacheCheck(&ctx, planted, "table_name.txt and a crafted table are planted beside the exe", "cannot write to %S", exe_dir);

	DIRLIST *exe_before = EnumDirW(exe_dir);
	DIRLIST *temp_before = my_temp == NULL ? NULL : EnumDirW(my_temp);

	// (3) Load the current table: the override is ignored and the strings come from the resource
	bool loaded = has_table && planted && LoadTable(cur_table);

	TableCacheCheck(&ctx, loaded, "The current string table loads with the planted files present", "LoadTable failed");

	TableCacheCheck(&ctx, FindTable(TABLECACHE_PLANTED_NAME) == NULL, "The crafted table named by table_name.txt is not read",
		"%s is \"%s\"", TABLECACHE_PLANTED_NAME, _SS(TABLECACHE_PLANTED_NAME));

	TableCacheCheck(&ctx, TableCacheResourceInUse(lang_id), "The strings come from the resource table",
		"STRTABLE_ID \"%s\", LANG %u, expected %u, %s \"%S\"", _SS("STRTABLE_ID"), _II("LANG"), lang_id,
		TABLECACHE_RESOURCE_NAME, _UU(TABLECACHE_RESOURCE_NAME));

	// (4) The load wrote no file beside the exe or in the temp directory of the process
	UINT new_exe = TableCacheNewFiles(exe_before, exe_dir);
	UINT new_temp = my_temp == NULL ? 0 : TableCacheNewFiles(temp_before, my_temp);

	FreeDir(exe_before);
	FreeDir(temp_before);

	TableCacheCheck(&ctx, new_exe == 0 && new_temp == 0, "Loading the table writes no file beside the exe or in the temp directory",
		"%u new files beside the exe, %u in the temp directory", new_exe, new_temp);

	// (5) Remove the planted files and load the resource table again
	FileDeleteW(override_path);
	FileDeleteW(planted_path);

	TableCacheCheck(&ctx, IsFileExistsW(override_path) == false && IsFileExistsW(planted_path) == false,
		"The planted files are removed", "a planted file is still there");

	loaded = has_table && LoadTable(cur_table);

	TableCacheCheck(&ctx, loaded && TableCacheResourceInUse(lang_id), "The resource table is in use again",
		"STRTABLE_ID \"%s\", LANG %u, expected %u", _SS("STRTABLE_ID"), _II("LANG"), lang_id);

	if (ctx.NumFailed == 0)
	{
		Print("TABLECACHE TEST OK\n");
	}
	else
	{
		Print("TABLECACHE TEST FAILED (%u of %u checks failed)\n", ctx.NumFailed, ctx.NumChecks);
	}
}
