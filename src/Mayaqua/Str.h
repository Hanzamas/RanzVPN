// Str.h
// Header of Str.c

#ifndef STR_H
#define STR_H

#include "MayaType.h"

#include <stdarg.h>

struct TOKEN_LIST {
	UINT NumTokens;
	char **Token;
};

UINT StrLen(const char *str);
UINT StrSize(const char *str);
bool StrCheckLen(const char *str, UINT len);
UINT StrCpy(char *dst, UINT size, const char *src);
UINT StrCat(char *dst, UINT size, const char *src);
UINT StrCatLeft(char *dst, UINT size, const char *src);
char ToLower(char c);
char ToUpper(char c);
void StrUpper(char *str);
void StrLower(char *str);
int StrCmp(const char *str1, const char *str2);
int StrCmpi(const char *str1, const char *str2);
void FormatArgs(char *buf, UINT size, const char *fmt, va_list args) RANZ_PRINTF_FORMAT(3, 0);
wchar_t *CopyFormatArgsToUni(const char *fmt, va_list args);
void Format(char *buf, UINT size, const char *fmt, ...) RANZ_PRINTF_FORMAT(3, 4);
void Print(const char *fmt, ...) RANZ_PRINTF_FORMAT(1, 2);
void Debug(const char *fmt, ...) RANZ_PRINTF_FORMAT(1, 2);
UINT ToInt(const char *str);
void ToStr(char *str, UINT i);
void TrimCrlf(char *str);
void Trim(char *str);
void TrimRight(char *str);
void TrimLeft(char *str);
bool GetLine(char *str, UINT size);
void FreeToken(TOKEN_LIST *tokens);
TOKEN_LIST *ParseToken(const char *src, const char *separator);
void InitStringLibrary();
UINT SearchStrEx(const char *string, const char *keyword, UINT start, bool case_sensitive);
UINT SearchStr(const char *string, const char *keyword, UINT start);
UINT CalcReplaceStrEx(const char *string, const char *old_keyword, const char *new_keyword, bool case_sensitive);
UINT ReplaceStrEx(char *dst, UINT size, const char *string, const char *old_keyword, const char *new_keyword, bool case_sensitive);
UINT ReplaceStr(char *dst, UINT size, const char *string, const char *old_keyword, const char *new_keyword);
UINT ReplaceStri(char *dst, UINT size, const char *string, const char *old_keyword, const char *new_keyword);
bool IsPrintableAsciiChar(char c);
void EnPrintableAsciiStr(char *str, char replace);
bool IsSafeChar(char c);
bool IsSafeStr(const char *str);
void EnSafeHttpHeaderValueStr(char *str, char replace);
char *CopyStr(const char *str);
void BinToStr(char *str, UINT str_size, const void *data, UINT data_size);
void BinToStrW(wchar_t *str, UINT str_size, const void *data, UINT data_size);
bool StartWith(const char *str, const char *key);
bool EndWith(const char *str, const char *key);
UINT64 ToInt64(const char *str);
void ToStr64(char *str, UINT64 value);
TOKEN_LIST *ParseCmdLine(const char *str);
TOKEN_LIST *NullToken();
bool IsNum(const char *str);
void FreeStrList(LIST *o);
TOKEN_LIST *ListToTokenList(const LIST *o);
bool IsEmptyStr(const char *str);
void BinToStrEx(char *str, UINT str_size, const void *data, UINT data_size);
BUF *StrToBin(const char *str);
void MacToStr(char *str, UINT size, const UCHAR *mac_address);
void ToStr3(char *str, UINT size, UINT64 v);
void ToStrByte(char *str, UINT size, UINT64 v);
void ToStrByte1000(char *str, UINT size, UINT64 v);
bool IsAllUpperStr(const char *str);
UINT StrWidth(const char *str);
char *MakeCharArray(char c, UINT count);
bool StrToMac(UCHAR *mac_address, const char *str);
bool GetKeyAndValue(const char *str, char *key, UINT key_size, char *value, UINT value_size, const char *split_str);
bool InStr(const char *str, const char *keyword);
bool InStrEx(const char *str, const char *keyword, bool case_sensitive);
TOKEN_LIST *ParseTokenWithoutNullStr(const char *str, const char *split_chars);
TOKEN_LIST *ParseTokenWithNullStr(const char *str, const char *split_chars);
UINT HexTo4Bit(char c);
char FourBitToHex(UINT value);
void ToHex(char *str, UINT value);
UINT HexToInt(const char *str);
UINT SearchAsciiInBinary(const void *data, UINT size, const char *str, bool case_sensitive);
void ClearStr(char *str, UINT str_size);

#endif

