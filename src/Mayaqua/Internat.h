// Internat.h
// Header of Internat.c

#ifndef INTERNAT_H
#define INTERNAT_H

#include "MayaType.h"

#include <stdarg.h>

struct UNI_TOKEN_LIST {
	UINT NumTokens;
	wchar_t **Token;
};

UINT UniStrLen(const wchar_t *str);
UINT UniStrSize(const wchar_t *str);
UINT UniStrCpy(wchar_t *dst, UINT size, const wchar_t *src);
UINT UniStrCat(wchar_t *dst, UINT size, const wchar_t *src);
wchar_t UniToLower(wchar_t c);
wchar_t UniToUpper(wchar_t c);
void UniStrLower(wchar_t *str);
void UniStrUpper(wchar_t *str);
int UniStrCmp(const wchar_t *str1, const wchar_t *str2);
int UniStrCmpi(const wchar_t *str1, const wchar_t *str2);
int UniSoftStrCmp(const wchar_t *str1, const wchar_t *str2);
void UniFormat(wchar_t *buf, UINT size, const wchar_t *fmt, ...);
void UniFormatArgs(wchar_t *buf, UINT size, const wchar_t *fmt, va_list args);
void UniPrint(const wchar_t *fmt, ...);
void UniPrintStr(wchar_t *string);
void UniToStru(wchar_t *str, UINT i);
void UniTrim(wchar_t *str);
void UniTrimLeft(wchar_t *str);
void UniTrimRight(wchar_t *str);
void UniTrimCrlf(wchar_t *str);
bool UniGetLineWin32(wchar_t *str, UINT size);
void UniFreeToken(UNI_TOKEN_LIST *tokens);
UNI_TOKEN_LIST *UniParseToken(const wchar_t *src, const wchar_t *separator);
UINT UniSearchStrEx(const wchar_t *string, const wchar_t *keyword, UINT start, bool case_sensitive);
UINT UniSearchStr(const wchar_t *string, const wchar_t *keyword, UINT start);
UINT UniCalcReplaceStrEx(const wchar_t *string, const wchar_t *old_keyword, const wchar_t *new_keyword, bool case_sensitive);
UINT UniReplaceStrEx(wchar_t *dst, UINT size, const wchar_t *string, const wchar_t *old_keyword, const wchar_t *new_keyword, bool case_sensitive);
UINT GetUniType(wchar_t c);
UINT GetUtf8Type(const BYTE *s, UINT size, UINT offset);
UINT CalcUniToUtf8(const wchar_t *s);
UINT UniToUtf8(void *u, UINT size, const wchar_t *s);
UINT Utf8Len(const BYTE *u, UINT size);
UINT CalcUtf8ToUni(const void *u, UINT u_size);
UINT Utf8ToUni(wchar_t *s, UINT size, const void *u, UINT u_size);
UINT CalcStrToUni(const char *str);
UINT StrToUni(wchar_t *s, UINT size, const char *str);
UINT CalcUniToStr(const wchar_t *s);
UINT UniToStr(char *str, UINT size, const wchar_t *s);
bool IsSafeUniStr(const wchar_t *str);
bool IsSafeUniChar(wchar_t c);
wchar_t *CopyUniStr(const wchar_t *str);
wchar_t *CopyStrToUni(const char *str);
UINT UtfToUni(wchar_t *unistr, UINT size, const char *utfstr);
char *CopyUniToUtf(const wchar_t *unistr);
char *CopyUniToStr(const wchar_t *unistr);
wchar_t *CopyUtfToUni(const char *utfstr);
UNI_TOKEN_LIST *UniParseCmdLine(const wchar_t *str);
UNI_TOKEN_LIST *UniNullToken();
bool UniIsEmptyStr(const wchar_t *str);
UINT UniStrWidth(const wchar_t *str);
void UniToStr3(wchar_t *str, UINT size, UINT64 value);
bool UniEndWith(const wchar_t *str, const wchar_t *key);
bool UniStartWith(const wchar_t *str, const wchar_t *key);
wchar_t *UniNormalizeCrlf(const wchar_t *str);
void UniFreeStrList(LIST *o);
bool UniIsCharInStr(const wchar_t *str, wchar_t c);
UNI_TOKEN_LIST *UniGetLines(const wchar_t *str);

#endif

