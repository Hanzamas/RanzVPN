// Table.c
// Read and management routines for string table

#include "Table.h"

#include "Cfg.h"
#include "FileIO.h"
#include "Internat.h"
#include "Mayaqua.h"
#include "Memory.h"
#include "Microsoft.h"
#include "Str.h"

#include <stdlib.h>

static LIST *TableList = NULL;
static LANGLIST current_lang = {0};

void InitTable()
{
	LIST *o;
	char tmp[MAX_SIZE];
	LANGLIST *e = NULL;
	char table_name[MAX_SIZE];
	if (MayaquaIsMinimalMode())
	{
		return;
	}

	o = LoadLangList();
	if (o == NULL)
	{
LABEL_FATAL_ERROR:
		MayaFatalExit(1, "Fatal Error: The hamcore files are missing or broken.\r\nPlease check the hamcore files: the resources of the executable, and a hamcore folder next to it.\r\n\r\n(First, reboot the computer. If this problem occurs again, please reinstall VPN software files.)");
	}

	if (LoadLangConfig(LANG_CONFIG_FILENAME, tmp, sizeof(tmp)))
	{
		e = GetBestLangByName(o, tmp);
	}

	if (e == NULL)
	{
		e = GetBestLangForCurrentEnvironment(o);
	}

	if (e == NULL)
	{
		goto LABEL_FATAL_ERROR;
	}

	SaveLangConfig(LANG_CONFIG_FILENAME, e->Name);

	Copy(&current_lang, e, sizeof(LANGLIST));

	current_lang.LcidList = NULL;

	Format(table_name, sizeof(table_name), "|strtable_%s.stb", current_lang.Name);
	if (LoadTable(table_name) == false)
	{
		goto LABEL_FATAL_ERROR;
	}

	FreeLangList(o);
}

static void GetCurrentLang(LANGLIST *e)
{
	if (e == NULL)
	{
		return;
	}

	Copy(e, &current_lang, sizeof(LANGLIST));
}

UINT GetCurrentLangId()
{
	LANGLIST e;

	Zero(&e, sizeof(e));

	GetCurrentLang(&e);

	return e.Id;
}

bool SaveLangConfig(wchar_t *filename, char *str)
{
	BUF *b;
	LIST *o;
	UINT i;
	bool ret;
	if (filename == NULL)
	{
		return false;
	}

	b = ReadDump(LANG_CONFIG_TEMPLETE);
	if (b == NULL)
	{
		return false;
	}

	SeekBuf(b, b->Size, 0);

	o = LoadLangList();
	if (o != NULL)
	{
		wchar_t tmp[MAX_SIZE];

		AppendBufStr(b, "# Available Language IDs are:\r\n");

		for (i = 0;i < LIST_NUM(o);i++)
		{
			LANGLIST *e = LIST_DATA(o, i);

			UniFormat(tmp, sizeof(tmp), L"#  %S: %s (%s)\r\n",
				e->Name, e->TitleEnglish, e->TitleLocal);

			AppendBufUtf8(b, tmp);
		}

		AppendBufStr(b, "\r\n\r\n# Specify a Language ID here.\r\n");
		AppendBufStr(b, str);
		AppendBufStr(b, "\r\n\r\n");

		FreeLangList(o);
	}

	ret = DumpBufWIfNecessary(b, filename);

	FreeBuf(b);

	return ret;
}

bool LoadLangConfig(wchar_t *filename, char *str, UINT str_size)
{
	BUF *b;
	bool ret = false;
	if (filename == NULL || str == NULL)
	{
		return false;
	}

	b = ReadDumpW(filename);
	if (b == NULL)
	{
		return false;
	}

	while (true)
	{
		char *line = CfgReadNextLine(b);

		if (line == NULL)
		{
			break;
		}

		Trim(line);

		if (IsEmptyStr(line) == false)
		{
			if (StartWith(line, "#") == false && StartWith(line, "//") == false && StartWith(line, ";") == false &&
				InStr(line, "#") == false)
			{
				StrCpy(str, str_size, line);
				ret = true;
			}
		}

		Free(line);
	}

	FreeBuf(b);

	return ret;
}

LANGLIST *GetBestLangForCurrentEnvironment(LIST *o)
{
	LANGLIST *ret = NULL;
	if (o == NULL)
	{
		return NULL;
	}

	ret = GetBestLangByLcid(o, MsGetUserLocaleId());

	return ret;
}

LANGLIST *GetBestLangByLcid(LIST *o, UINT lcid)
{
	LANGLIST *ret;
	UINT i;
	if (o == NULL)
	{
		return NULL;
	}

	for (i = 0;i < LIST_NUM(o);i++)
	{
		LANGLIST *e = LIST_DATA(o, i);

		if (IsIntInList(e->LcidList, lcid))
		{
			return e;
		}
	}

	ret = GetBestLangByName(o, "en");

	return ret;
}

LANGLIST *GetBestLangByName(LIST *o, char *name)
{
	UINT i;
	LANGLIST *ret = NULL;
	if (o == NULL)
	{
		return NULL;
	}

	for (i = 0;i < LIST_NUM(o);i++)
	{
		LANGLIST *e = LIST_DATA(o, i);

		if (StrCmpi(e->Name, name) == 0)
		{
			ret = e;
			break;
		}
	}

	if (ret != NULL)
	{
		return ret;
	}

	for (i = 0;i < LIST_NUM(o);i++)
	{
		LANGLIST *e = LIST_DATA(o, i);

		if (StartWith(e->Name, name) || StartWith(name, e->Name))
		{
			ret = e;
			break;
		}
	}

	if (ret != NULL)
	{
		return ret;
	}

	return ret;
}

void FreeLangList(LIST *o)
{
	UINT i;
	if (o == NULL)
	{
		return;
	}

	for (i = 0;i < LIST_NUM(o);i++)
	{
		LANGLIST *e = LIST_DATA(o, i);

		ReleaseIntList(e->LcidList);

		Free(e);
	}

	ReleaseList(o);
}

LIST *LoadLangList()
{
	LIST *o = NewListFast(NULL);
	char *filename = LANGLIST_FILENAME;
	BUF *b;

	b = ReadDump(filename);
	if (b == NULL)
	{
		FreeLangList(o);
		return NULL;
	}

	while (true)
	{
		char *line = CfgReadNextLine(b);

		if (line == NULL)
		{
			break;
		}

		Trim(line);

		if (IsEmptyStr(line) == false && StartWith(line, "#") == false)
		{
			TOKEN_LIST *t = ParseToken(line, "\t ");
			if (t != NULL)
			{
				if (t->NumTokens == 6)
				{
					LANGLIST *e = ZeroMalloc(sizeof(LANGLIST));
					TOKEN_LIST *t2;

					e->Id = ToInt(t->Token[0]);
					StrCpy(e->Name, sizeof(e->Name), t->Token[1]);
					Utf8ToUni(e->TitleEnglish, sizeof(e->TitleEnglish), t->Token[2], StrLen(t->Token[2]));
					Utf8ToUni(e->TitleLocal, sizeof(e->TitleLocal), t->Token[3], StrLen(t->Token[3]));

					UniReplaceStrEx(e->TitleEnglish, sizeof(e->TitleEnglish), e->TitleEnglish,
						L"_", L" ", true);

					UniReplaceStrEx(e->TitleLocal, sizeof(e->TitleLocal), e->TitleLocal,
						L"_", L" ", true);

					e->LcidList = NewIntList(false);

					t2 = ParseToken(t->Token[4], ",");
					if (t2 != NULL)
					{
						UINT i;

						for (i = 0;i < t2->NumTokens;i++)
						{
							UINT id = ToInt(t2->Token[i]);

							AddIntDistinct(e->LcidList, id);
						}

						FreeToken(t2);
					}

					Add(o, e);
				}

				FreeToken(t);
			}
		}

		Free(line);
	}

	FreeBuf(b);

	return o;
}

wchar_t *GetUniErrorStr(UINT err)
{
	wchar_t *ret;
	char name[MAX_SIZE];
	Format(name, sizeof(name), "ERR_%u", err);

	ret = GetTableUniStr(name);
	if (UniStrLen(ret) != 0)
	{
		return ret;
	}
	else
	{
		return _UU("ERR_UNKNOWN");
	}
}

UINT GetTableInt(char *name)
{
	char *str;
	if (name == NULL)
	{
		return 0;
	}

	str = GetTableStr(name);
	return ToInt(str);
}

wchar_t *GetTableUniStr(char *name)
{
	TABLE *t;
	if (name == NULL)
	{
		return L"";
	}

	t = FindTable(name);
	if (t == NULL)
	{
		return L"";
	}

	return t->unistr;
}

char *GetTableStr(char *name)
{
	TABLE *t;
	if (name == NULL)
	{
		return "";
	}

	t = FindTable(name);
	if (t == NULL)
	{
		return "";
	}

	return t->str;
}

TOKEN_LIST *GetTableNameStartWith(char *str)
{
	UINT i;
	UINT len;
	LIST *o;
	TOKEN_LIST *t;
	char tmp[MAX_SIZE];
	if (str == NULL)
	{
		return NullToken();
	}

	StrCpy(tmp, sizeof(tmp), str);
	StrUpper(tmp);

	len = StrLen(tmp);

	o = NewListFast(NULL);

	for (i = 0;i < LIST_NUM(TableList);i++)
	{
		TABLE *t = LIST_DATA(TableList, i);
		UINT len2 = StrLen(t->name);

		if (len2 >= len)
		{
			if (Cmp(t->name, tmp, len) == 0)
			{
				Insert(o, CopyStr(t->name));
			}
		}
	}

	t = ZeroMalloc(sizeof(TOKEN_LIST));
	t->NumTokens = LIST_NUM(o);
	t->Token = ZeroMalloc(sizeof(char *) * t->NumTokens);

	for (i = 0;i < t->NumTokens;i++)
	{
		t->Token[i] = LIST_DATA(o, i);
	}

	ReleaseList(o);

	return t;
}

TABLE *FindTable(char *name)
{
	TABLE *t, tt;
	if (name == NULL || TableList == NULL)
	{
		return NULL;
	}

	tt.name = CopyStr(name);
	t = Search(TableList, &tt);
	Free(tt.name);

	return t;
}

static int CmpTableName(void *p1, void *p2)
{
	TABLE *t1, *t2;
	if (p1 == NULL || p2 == NULL)
	{
		return 0;
	}
	t1 = *(TABLE **)p1;
	t2 = *(TABLE **)p2;
	if (t1 == NULL || t2 == NULL)
	{
		return 0;
	}

	return StrCmpi(t1->name, t2->name);
}

static TABLE *ParseTableLine(char *line, char *prefix, UINT prefix_size, LIST *replace_list)
{
	UINT i, len;
	UINT len_name;
	UINT string_start;
	char *name;
	char *name2;
	UINT name2_size;
	wchar_t *unistr;
	char *str;
	UINT unistr_size, str_size;
	TABLE *t;
	if (line == NULL || prefix == NULL)
	{
		return NULL;
	}
	TrimLeft(line);

	len = StrLen(line);
	if (len == 0)
	{
		return NULL;
	}

	if (line[0] == '#' || (line[0] == '/' && line[1] == '/'))
	{
		return NULL;
	}

	len_name = 0;
	for (i = 0;;i++)
	{
		if (line[i] == 0)
		{
			return NULL;
		}
		if (line[i] == ' ' || line[i] == '\t')
		{
			break;
		}
		len_name++;
	}

	name = Malloc(len_name + 1);
	StrCpy(name, len_name + 1, line);

	string_start = len_name;
	for (i = len_name;i < len;i++)
	{
		if (line[i] != ' ' && line[i] != '\t')
		{
			break;
		}
		string_start++;
	}
	if (i == len)
	{
		Free(name);
		return NULL;
	}

	UnescapeStr(&line[string_start]);

	unistr_size = CalcUtf8ToUni(&line[string_start], StrLen(&line[string_start]));
	if (unistr_size == 0)
	{
		Free(name);
		return NULL;
	}
	unistr = Malloc(unistr_size);
	Utf8ToUni(unistr, unistr_size, &line[string_start], StrLen(&line[string_start]));

	if (UniInChar(unistr, L'$'))
	{
		wchar_t *tmp;
		UINT tmp_size = (UniStrSize(unistr) + 1024) * 2;
		UINT i;

		tmp = Malloc(tmp_size);

		UniStrCpy(tmp, tmp_size, unistr);

		for (i = 0; i < LIST_NUM(replace_list);i++)
		{
			TABLE *r = LIST_DATA(replace_list, i);

			UniReplaceStrEx(tmp, tmp_size, tmp, (wchar_t *)r->name, r->unistr, false);
		}

		Free(unistr);

		unistr = CopyUniStr(tmp);

		Free(tmp);
	}

	str_size = CalcUniToStr(unistr);
	if (str_size == 0)
	{
		str_size = 1;
		str = Malloc(1);
		str[0] = 0;
	}
	else
	{
		str = Malloc(str_size);
		UniToStr(str, str_size, unistr);
	}

	if (StrCmpi(name, "PREFIX") == 0)
	{
		StrCpy(prefix, prefix_size, str);
		Trim(prefix);

		if (StrCmpi(prefix, "$") == 0 || StrCmpi(prefix, "NULL") == 0)
		{
			prefix[0] = 0;
		}

		Free(name);
		Free(str);
		Free(unistr);

		return NULL;
	}

	name2_size = StrLen(name) + StrLen(prefix) + 2;
	name2 = ZeroMalloc(name2_size);

	if (prefix[0] != 0)
	{
		StrCat(name2, name2_size, prefix);
		StrCat(name2, name2_size, "@");
	}

	StrCat(name2, name2_size, name);

	Free(name);

	t = Malloc(sizeof(TABLE));
	StrUpper(name2);
	t->name = name2;
	t->str = str;
	t->unistr = unistr;

	return t;
}

void UnescapeStr(char *src)
{
	UINT i, len, wp;
	char *tmp;
	if (src == NULL)
	{
		return;
	}
	
	len = StrLen(src);
	tmp = Malloc(len + 1);
	wp = 0;
	for (i = 0;i < len;i++)
	{
		if (src[i] == '\\')
		{
			i++;
			switch (src[i])
			{
			case 0:
				goto FINISH;
			case '\\':
				tmp[wp++] = '\\';
				break;
			case ' ':
				tmp[wp++] = ' ';
				break;
			case 'n':
			case 'N':
				tmp[wp++] = '\n';
				break;
			case 'r':
			case 'R':
				tmp[wp++] = '\r';
				break;
			case 't':
			case 'T':
				tmp[wp++] = '\t';
				break;
			}
		}
		else
		{
			tmp[wp++] = src[i];
		}
	}
FINISH:
	tmp[wp++] = 0;
	StrCpy(src, 0, tmp);
	Free(tmp);
}

void FreeTable()
{
	UINT i, num;
	TABLE **tables;
	if (TableList == NULL)
	{
		return;
	}

	num = LIST_NUM(TableList);
	tables = ToArray(TableList);
	for (i = 0;i < num;i++)
	{
		TABLE *t = tables[i];
		Free(t->name);
		Free(t->str);
		Free(t->unistr);
		Free(t);
	}
	ReleaseList(TableList);
	TableList = NULL;
	Free(tables);
}

static bool LoadTableFromBuf(BUF *b)
{
	char *tmp;
	char prefix[MAX_SIZE];
	LIST *replace_list = NULL;
	UINT i;
	if (b == NULL)
	{
		return false;
	}

	FreeTable();

	TableList = NewList(CmpTableName);

	Zero(prefix, sizeof(prefix));

	replace_list = NewListFast(NULL);

	while (true)
	{
		TABLE *t;
		bool ok = true;

		tmp = CfgReadNextLine(b);
		if (tmp == NULL)
		{
			break;
		}

		if (tmp[0] == '$')
		{
			char key[128];
			char value[MAX_SIZE];
			if (GetKeyAndValue(tmp, key, sizeof(key), value, sizeof(value), " \t"))
			{
				if (StartWith(key, "$") && EndWith(key, "$") && StrLen(key) >= 3)
				{
					TABLE *t;
					wchar_t univalue[MAX_SIZE];
					wchar_t uniname[MAX_SIZE];

					t = ZeroMalloc(sizeof(TABLE));

					Zero(univalue, sizeof(univalue));
					Utf8ToUni(univalue, sizeof(univalue), value, StrLen(value));

					StrToUni(uniname, sizeof(uniname), key);

					t->name = (char *)CopyUniStr(uniname);
					t->unistr = CopyUniStr(univalue);

					Add(replace_list, t);

					ok = false;
				}
			}
		}

		if (ok)
		{
			t = ParseTableLine(tmp, prefix, sizeof(prefix), replace_list);
			if (t != NULL)
			{
				Insert(TableList, t);
			}
		}

		Free(tmp);
	}

	for (i = 0;i < LIST_NUM(replace_list);i++)
	{
		TABLE *t = LIST_DATA(replace_list, i);

		Free(t->name);
		Free(t->str);
		Free(t->unistr);

		Free(t);
	}

	ReleaseList(replace_list);

	return true;
}

// Load the string table from the file, '|' names a resource. Parsed at every load: no cache file in %TEMP%,
// which other users can write (SEC-8), and no override file beside the exe naming another table (FND-43)
bool LoadTable(char *filename)
{
	BUF *b;
	if (filename == NULL)
	{
		return false;
	}

	if (MayaquaIsMinimalMode())
	{
		return true;
	}

	b = ReadDump(filename);
	if (b == NULL)
	{
		MayaFatalExit(1, "Error: Can't read string tables (file not found).\r\nPlease check the hamcore files: the resources of the executable, and a hamcore folder next to it.\r\n\r\n(First, reboot the computer. If this problem occurs again, please reinstall VPN software files.)");
	}

	if (LoadTableFromBuf(b) == false)
	{
		FreeBuf(b);
		return false;
	}

	FreeBuf(b);

	SetLocale(_UU("DEFAULT_LOCALE"));

	if (StrCmpi(_SS("STRTABLE_ID"), STRTABLE_ID) != 0)
	{
		char tmp[MAX_SIZE];
		Format(tmp, sizeof(tmp), "Error: Can't read string tables (invalid version: '%s'!='%s').\r\nPlease check the hamcore files: the resources of the executable, and a hamcore folder next to it.\r\n\r\n(First, reboot the computer. If this problem occurs again, please reinstall VPN software files.)",
			_SS("STRTABLE_ID"), STRTABLE_ID);
		MayaFatalExit(1, tmp);
	}

	return true;
}
