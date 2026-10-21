// Table.h
// Header of Table.c

#ifndef TABLE_H
#define TABLE_H

#include "Encrypt.h"

#define LANGLIST_FILENAME "|languages.txt"

#define LANG_CONFIG_FILENAME L"$lang.config"
#define LANG_CONFIG_TEMPLETE "|lang.config"

#define SE_LANG_JAPANESE   0
#define SE_LANG_CHINESE_ZH 2

struct TABLE {
	char *name;
	char *str;
	wchar_t *unistr;
};

#define _SS(name)  (GetTableStr((const char *)(name)))
#define _UU(name)  (GetTableUniStr((const char *)(name)))
#define _II(name)  (GetTableInt((const char *)(name)))
#define _GETLANG() (_II("LANG"))

struct LANGLIST {
	UINT Id;
	char Name[32];
	wchar_t TitleEnglish[128];
	wchar_t TitleLocal[128];
	LIST *LcidList;
};

bool LoadTable(const char *filename);
void FreeTable();
void UnescapeStr(char *src);
TABLE *FindTable(const char *name);
TOKEN_LIST *GetTableNameStartWith(const char *str);
char *GetTableStr(const char *name);
wchar_t *GetTableUniStr(const char *name);
wchar_t *GetUniErrorStr(UINT err);
static inline wchar_t *_E(UINT name) {
	return (GetUniErrorStr((UINT)(name)));
}
UINT GetTableInt(const char *name);
void InitTable();

LIST *LoadLangList();
void FreeLangList(LIST *o);

LANGLIST *GetBestLangByName(LIST *o, const char *name);
LANGLIST *GetBestLangByLcid(LIST *o, UINT lcid);
LANGLIST *GetBestLangForCurrentEnvironment(LIST *o);

bool LoadLangConfig(wchar_t *filename, char *str, UINT str_size);
bool SaveLangConfig(wchar_t *filename, const char *str);

UINT GetCurrentLangId();

#endif // TABLE_H

