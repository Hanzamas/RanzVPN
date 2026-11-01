// Str.c
// String processing routine

#include "Str.h"

#include "Cfg.h"
#include "Internat.h"
#include "Mayaqua.h"
#include "Memory.h"
#include "Object.h"
#include "Trace.h"
#include "Tracking.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Without STRSAFE_NO_DEPRECATE, strsafe.h redefines the unsafe copy and print names, among them
// StrCpy and StrCat, which Mayaqua defines itself
#define STRSAFE_NO_DEPRECATE
#include <strsafe.h>

// Room for the longest result of ToStr, ToStr64 and ToHex, terminator included
#define TOSTR_SIZE   sizeof("4294967295")
#define TOSTR64_SIZE sizeof("18446744073709551615")
#define TOHEX_SIZE   sizeof("ffffffff")

// The separators of ParseToken and its two variants when none are given
#define DEFAULT_TOKEN_SPLIT_CHARS " ,\t\r\n"

typedef struct BYTESTR {
	UINT64 base_value;
	char *string;
} BYTESTR;

static BYTESTR bytestr[] =
    {
        {0, "PBytes"},
        {0, "TBytes"},
        {0, "GBytes"},
        {0, "MBytes"},
        {0, "KBytes"},
        {0, "Bytes"},
};

void ClearStr(char *str, UINT str_size) {
	StrCpy(str, str_size, "");
}

UINT SearchAsciiInBinary(const void *data, UINT size, const char *str, bool case_sensitive) {
	UINT ret = INFINITE;
	if (data == NULL || size == 0 || str == NULL)
		return INFINITE;

	char *tmp = ZeroMalloc(size + 1);
	Copy(tmp, data, size);

	ret = SearchStrEx(tmp, str, 0, case_sensitive);

	Free(tmp);

	return ret;
}

UINT HexToInt(const char *str) {
	UINT ret = 0;
	if (str == NULL)
		return 0;

	if (str[0] == '0' && (str[1] == 'x' || str[1] == 'X'))
		str += 2;

	UINT len = StrLen(str);
	for (UINT i = 0; i < len; i++) {
		char c = str[i];

		if ((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'))
			ret = ret * 16 + (UINT)HexTo4Bit(c);
		else
			break;
	}

	return ret;
}

void ToHex(char *str, UINT value) {
	if (str == NULL)
		return;

	// Lower case digits without leading zeros
	StringCchPrintfA(str, TOHEX_SIZE, "%x", value);
}

char FourBitToHex(UINT value) {
	value = value % 16;

	if (value <= 9)
		return '0' + value;
	else
		return 'a' + (value - 10);
}

UINT HexTo4Bit(char c) {
	if ('0' <= c && c <= '9')
		return c - '0';
	else if ('a' <= c && c <= 'f')
		return c - 'a' + 10;
	else if ('A' <= c && c <= 'F')
		return c - 'A' + 10;
	else
		return 0;
}

// A heap copy of the first len characters of str
static char *CopyStrPrefix(const char *str, UINT len) {
	char *ret = Malloc(len + 1);

	StringCchCopyNA(ret, (size_t)len + 1, str, len);

	return ret;
}

// The tokenizer of both variants. With keep_empty, each separator and the terminator end a token,
// also an empty one; without it, a run of separators splits once and no token is empty.
static TOKEN_LIST *ParseTokenCore(const char *str, const char *split_chars, bool keep_empty) {
	if (str == NULL)
		return NullToken();
	if (split_chars == NULL)
		split_chars = DEFAULT_TOKEN_SPLIT_CHARS;

	LIST *o = NewListFast(NULL);

	while (true) {
		if (keep_empty == false) {
			str += strspn(str, split_chars);
			if (str[0] == '\0')
				break;
		}

		UINT len = (UINT)strcspn(str, split_chars);

		Insert(o, CopyStrPrefix(str, len));

		if (str[len] == '\0')
			break;

		str += len + 1;
	}

	TOKEN_LIST *t = ZeroMalloc(sizeof(TOKEN_LIST));
	t->NumTokens = LIST_NUM(o);
	t->Token = ZeroMalloc(sizeof(char *) * t->NumTokens);

	for (UINT i = 0; i < t->NumTokens; i++)
		t->Token[i] = LIST_DATA(o, i);

	ReleaseList(o);

	return t;
}

TOKEN_LIST *ParseTokenWithNullStr(const char *str, const char *split_chars) {
	return ParseTokenCore(str, split_chars, true);
}

TOKEN_LIST *ParseTokenWithoutNullStr(const char *str, const char *split_chars) {
	return ParseTokenCore(str, split_chars, false);
}

bool InStr(const char *str, const char *keyword) {
	return InStrEx(str, keyword, false);
}
bool InStrEx(const char *str, const char *keyword, bool case_sensitive) {
	if (IsEmptyStr(str) || IsEmptyStr(keyword))
		return false;

	if (SearchStrEx(str, keyword, 0, case_sensitive) == INFINITE)
		return false;

	return true;
}

static bool IsSplitChar(char c, const char *split_str) {
	char c_upper = ToUpper(c);

	UINT len = StrLen(split_str);

	for (UINT i = 0; i < len; i++)
		if (ToUpper(split_str[i]) == c_upper)
			return true;

	return false;
}

bool GetKeyAndValue(const char *str, char *key, UINT key_size, char *value, UINT value_size, const char *split_str) {
	UINT mode = 0;
	UINT wp1 = 0, wp2 = 0;
	bool ret = false;

	UINT len = StrLen(str);

	char *key_tmp = ZeroMalloc(len + 1);
	char *value_tmp = ZeroMalloc(len + 1);

	for (UINT i = 0; i < len; i++) {
		char c = str[i];

		switch (mode) {
		case 0:
			if (IsSplitChar(c, split_str) == false) {
				mode = 1;
				key_tmp[wp1] = c;
				wp1++;
			}
			break;

		case 1:
			if (IsSplitChar(c, split_str) == false) {
				key_tmp[wp1] = c;
				wp1++;
			} else {
				mode = 2;
			}
			break;

		case 2:
			if (IsSplitChar(c, split_str) == false) {
				mode = 3;
				value_tmp[wp2] = c;
				wp2++;
			}
			break;

		case 3:
			value_tmp[wp2] = c;
			wp2++;
			break;
		}
	}

	if (mode != 0) {
		ret = true;
		StrCpy(key, key_size, key_tmp);
		StrCpy(value, value_size, value_tmp);
	}

	Free(key_tmp);
	Free(value_tmp);

	return ret;
}

char *MakeCharArray(char c, UINT count) {
	char *ret = Malloc(count + 1);

	memset(ret, c, count);

	ret[count] = 0;

	return ret;
}

UINT StrWidth(const char *str) {
	if (str == NULL)
		return 0;

	wchar_t *s = CopyStrToUni(str);
	UINT ret = UniStrWidth(s);
	Free(s);

	return ret;
}

bool IsAllUpperStr(const char *str) {
	if (str == NULL)
		return false;

	UINT len = StrLen(str);

	for (UINT i = 0; i < len; i++) {
		char c = str[i];

		if ((c >= '0' && c <= '9') ||
		    (c >= 'A' && c <= 'Z')) {
		} else {
			return false;
		}
	}

	return true;
}

void ToStrByte1000(char *str, UINT size, UINT64 v) {
	if (str == NULL)
		return;

	// Built by multiplication to avoid a gcc overflow warning
	bytestr[0].base_value = 1000000000UL;
	bytestr[0].base_value *= 1000UL;
	bytestr[0].base_value *= 1000UL;
	bytestr[1].base_value = 1000000000UL;
	bytestr[1].base_value *= 1000UL;
	bytestr[2].base_value = 1000000000UL;
	bytestr[3].base_value = 1000000UL;
	bytestr[4].base_value = 1000UL;
	bytestr[5].base_value = 0UL;

	for (UINT i = 0; i < _countof(bytestr); i++) {
		BYTESTR *b = &bytestr[i];

		if ((v * 11UL) / 10UL >= b->base_value) {
			if (b->base_value != 0) {
				double d = (double)v / (double)b->base_value;
				Format(str, size, "%.2f %s", d, b->string);
			} else {
				Format(str, size, "%I64u %s", v, b->string);
			}

			break;
		}
	}
}

void ToStrByte(char *str, UINT size, UINT64 v) {
	if (str == NULL)
		return;

	// Built by multiplication to avoid a gcc overflow warning
	bytestr[0].base_value = 1073741824UL;
	bytestr[0].base_value *= 1024UL;
	bytestr[0].base_value *= 1024UL;
	bytestr[1].base_value = 1073741824UL;
	bytestr[1].base_value *= 1024UL;
	bytestr[2].base_value = 1073741824UL;
	bytestr[3].base_value = 1048576UL;
	bytestr[4].base_value = 1024UL;
	bytestr[5].base_value = 0UL;

	for (UINT i = 0; i < _countof(bytestr); i++) {
		BYTESTR *b = &bytestr[i];

		if ((v * 11UL) / 10UL >= b->base_value) {
			if (b->base_value != 0) {
				double d = (double)v / (double)b->base_value;
				Format(str, size, "%.2f %s", d, b->string);
			} else {
				Format(str, size, "%I64u %s", v, b->string);
			}

			break;
		}
	}
}

void ToStr3(char *str, UINT size, UINT64 v) {
	char tmp[128];
	char tmp2[128];
	if (str == NULL)
		return;

	ToStr64(tmp, v);

	UINT wp = 0;
	UINT len = StrLen(tmp);

	for (UINT i = len - 1; ((int)i) >= 0; i--)
		tmp2[wp++] = tmp[i];
	tmp2[wp++] = 0;

	wp = 0;

	for (UINT i = 0; i < len; i++) {
		if (i != 0 && (i % 3) == 0)
			tmp[wp++] = ',';
		tmp[wp++] = tmp2[i];
	}
	tmp[wp++] = 0;
	wp = 0;
	len = StrLen(tmp);

	for (UINT i = len - 1; ((int)i) >= 0; i--)
		tmp2[wp++] = tmp[i];
	tmp2[wp++] = 0;

	StrCpy(str, size, tmp2);
}

// The digits of "%02X-%02X-%02X-%02X-%02X-%02X" by hand into a local string, copied with StrCpy,
// which cuts it as Format did: at most size - 1 characters (no limit for size 0) and the terminator
void MacToStr(char *str, UINT size, const UCHAR *mac_address) {
	static const char hex[] = "0123456789ABCDEF";
	char tmp[6 * 3];
	if (str == NULL || mac_address == NULL)
		return;

	for (UINT i = 0; i < 6; i++) {
		tmp[i * 3] = hex[mac_address[i] >> 4];
		tmp[i * 3 + 1] = hex[mac_address[i] & 0x0F];
		tmp[i * 3 + 2] = (i == 5) ? '\0' : '-';
	}

	StrCpy(str, size, tmp);
}

bool IsEmptyStr(const char *str) {
	if (str == NULL)
		return true;

	// Empty when nothing but blanks (the characters Trim removes) precedes the terminator
	return str[strspn(str, " \t")] == '\0';
}

TOKEN_LIST *ListToTokenList(const LIST *o) {
	if (o == NULL)
		return NULL;

	TOKEN_LIST *t = ZeroMalloc(sizeof(TOKEN_LIST));
	t->NumTokens = LIST_NUM(o);
	t->Token = ZeroMalloc(sizeof(char *) * t->NumTokens);
	for (UINT i = 0; i < LIST_NUM(o); i++)
		t->Token[i] = CopyStr(LIST_DATA(o, i));

	return t;
}

void FreeStrList(LIST *o) {
	FreeListItems(o);
}

bool IsNum(const char *str) {
	char c;
	UINT n = 0;
	char tmp[MAX_SIZE];
	if (str == NULL)
		return false;

	StrCpy(tmp, sizeof(tmp), str);
	Trim(tmp);

	if (StrLen(tmp) == 0)
		return false;

	TOKEN_LIST *t = ParseToken(tmp, " ");

	if (t->NumTokens >= 1)
		StrCpy(tmp, sizeof(tmp), t->Token[0]);

	FreeToken(t);

	UINT len = StrLen(tmp);
	for (UINT i = 0; i < len; i++) {
		bool b = false;
		c = tmp[i];
		if (('0' <= c && c <= '9') || (c == '+') || (c == '-') || (c == ','))
			b = true;

		if (b == false)
			return false;
	}

	for (UINT i = 0; i < len; i++) {
		c = tmp[i];
		if (c == '-')
			n++;
	}
	if (n >= 2)
		return false;

	return true;
}

TOKEN_LIST *NullToken() {
	TOKEN_LIST *ret = ZeroMalloc(sizeof(TOKEN_LIST));
	ret->Token = ZeroMalloc(0);

	return ret;
}

TOKEN_LIST *ParseCmdLine(const char *str) {
	char c;
	bool ignore_space = false;
	if (str == NULL)
		return NullToken();

	LIST *o = NewListFast(NULL);
	char *tmp = Malloc(StrSize(str) + 32);

	UINT wp = 0;
	UINT mode = 0;

	UINT len = StrLen(str);
	for (UINT i = 0; i < len; i++) {
		c = str[i];

		switch (mode) {
		case 0:
			if (c == ' ' || c == '\t') {
			} else {
				if (c == '\"') {
					if (str[i + 1] == '\"') {
						// "" is an escaped quote
						tmp[wp++] = '\"';
						i++;
					} else {
						// A lone " toggles quoted mode (spaces are kept)
						ignore_space = true;
					}
				} else {
					tmp[wp++] = c;
				}

				mode = 1;
			}
			break;

		case 1:
			if (ignore_space == false && (c == ' ' || c == '\t')) {
				tmp[wp++] = 0;
				wp = 0;

				Insert(o, CopyStr(tmp));
				mode = 0;
			} else if (c == '\"') {
				if (str[i + 1] == '\"') {
					// "" is an escaped quote
					tmp[wp++] = L'\"';
					i++;
				} else if (ignore_space == false) {
					// A lone " toggles quoted mode (spaces are kept)
					ignore_space = true;
				} else {
					ignore_space = false;
				}
			} else {
				tmp[wp++] = c;
			}
			break;
		}
	}

	if (wp != 0) {
		tmp[wp++] = 0;
		Insert(o, CopyStr(tmp));
	}

	Free(tmp);

	TOKEN_LIST *t = ZeroMalloc(sizeof(TOKEN_LIST));
	t->NumTokens = LIST_NUM(o);
	t->Token = ZeroMalloc(sizeof(char *) * t->NumTokens);
	for (UINT i = 0; i < t->NumTokens; i++)
		t->Token[i] = LIST_DATA(o, i);

	ReleaseList(o);

	return t;
}

void ToStr64(char *str, UINT64 value) {
	if (str == NULL)
		return;

	StringCchPrintfA(str, TOSTR64_SIZE, "%I64u", value);
}

UINT64 ToInt64(const char *str) {
	UINT64 ret = 0;
	if (str == NULL)
		return 0;

	UINT len = StrLen(str);
	for (UINT i = 0; i < len; i++) {
		char c = str[i];
		if (c != ',') {
			if ('0' <= c && c <= '9')
				ret = ret * (UINT64)10 + (UINT64)(c - '0');
			else
				break;
		}
	}

	return ret;
}


bool EndWith(const char *str, const char *key) {
	if (str == NULL || key == NULL)
		return false;

	UINT str_len = StrLen(str);
	UINT key_len = StrLen(key);
	if (str_len < key_len)
		return false;

	if (StrCmpi(str + (str_len - key_len), key) == 0)
		return true;
	else
		return false;
}

bool StartWith(const char *str, const char *key) {
	if (str == NULL || key == NULL)
		return false;

	// An empty str or key never matches
	if (key[0] == '\0')
		return false;

	// Compares in place with the ASCII-only fold of StrCmpi, and stops at the end of str
	for (UINT i = 0; key[i] != '\0'; i++)
		if (str[i] == '\0' || ToUpper(str[i]) != ToUpper(key[i]))
			return false;

	return true;
}

bool StrToMac(UCHAR *mac_address, const char *str) {
	if (mac_address == NULL || str == NULL)
		return false;

	BUF *b = StrToBin(str);
	if (b == NULL)
		return false;

	if (b->Size != 6) {
		FreeBuf(b);
		return false;
	}

	Copy(mac_address, b->Buf, 6);

	FreeBuf(b);

	return true;
}

BUF *StrToBin(const char *str) {
	char tmp[3];
	if (str == NULL)
		return NULL;

	UINT len = StrLen(str);
	tmp[0] = 0;
	BUF *b = NewBuf();
	for (UINT i = 0; i < len; i++) {
		char c = str[i];
		c = ToUpper(c);
		if (('0' <= c && c <= '9') || ('A' <= c && c <= 'F')) {
			if (tmp[0] == 0) {
				tmp[0] = c;
				tmp[1] = 0;
			} else if (tmp[1] == 0) {
				char tmp2[64];
				tmp[1] = c;
				tmp[2] = 0;
				StrCpy(tmp2, sizeof(tmp2), "0x");
				StrCat(tmp2, sizeof(tmp2), tmp);
				UCHAR data = (UCHAR)strtoul(tmp2, NULL, 0);
				WriteBuf(b, &data, 1);
				Zero(tmp, sizeof(tmp));
			}
		} else if (c == ' ' || c == ',' || c == '-' || c == ':') {
		} else {
			break;
		}
	}

	return b;
}

// Upper case hex of data straight into str, with one space between the bytes when spaced. Like
// StrCpy, it writes at most str_size - 1 characters (no limit for str_size 0) and the terminator.
static void BinToHexStr(char *str, UINT str_size, const UCHAR *data, UINT data_size, bool spaced) {
	static const char hex[] = "0123456789ABCDEF";
	UINT room = (str_size == 0) ? INFINITE : str_size - 1;
	UINT wp = 0;

	for (UINT i = 0; i < data_size && wp < room; i++) {
		if (spaced && i != 0) {
			str[wp++] = ' ';
			if (wp >= room)
				break;
		}

		str[wp++] = hex[data[i] >> 4];
		if (wp >= room)
			break;

		str[wp++] = hex[data[i] & 0x0F];
	}

	str[wp] = '\0';
}

void BinToStrEx(char *str, UINT str_size, const void *data, UINT data_size) {
	if (str == NULL || data == NULL)
		return;

	BinToHexStr(str, str_size, (const UCHAR *)data, data_size, true);
}

void BinToStr(char *str, UINT str_size, const void *data, UINT data_size) {
	if (str == NULL || data == NULL) {
		if (str != NULL)
			str[0] = 0;
		return;
	}

	BinToHexStr(str, str_size, (const UCHAR *)data, data_size, false);
}
void BinToStrW(wchar_t *str, UINT str_size, const void *data, UINT data_size) {
	if (str == NULL || data == NULL) {
		if (str != NULL)
			str[0] = 0;
		return;
	}

	UINT tmp_size = (data_size * 2 + 4) * sizeof(wchar_t);
	char *tmp = ZeroMalloc(tmp_size);

	BinToStr(tmp, tmp_size, data, data_size);

	StrToUni(str, str_size, tmp);

	Free(tmp);
}

char *CopyStr(const char *str) {
	if (str == NULL)
		return NULL;

	UINT len = StrLen(str);
	char *dst = Malloc(len + 1);
	StrCpy(dst, len + 1, str);
	return dst;
}

bool IsSafeStr(const char *str) {
	if (str == NULL)
		return false;

	UINT len = StrLen(str);
	for (UINT i = 0; i < len; i++)
		if (IsSafeChar(str[i]) == false)
			return false;
	if (str[0] == ' ')
		return false;
	if (len != 0) {
		if (str[len - 1] == ' ')
			return false;
	}
	return true;
}

bool IsPrintableAsciiChar(char c) {
	UCHAR uc = (UCHAR)c;
	if (uc <= 31)
		return false;
	if (uc >= 127)
		return false;
	return true;
}

void EnPrintableAsciiStr(char *str, char replace) {
	if (str == NULL)
		return;

	UINT len = StrLen(str);

	for (UINT i = 0; i < len; i++) {
		char c = str[i];

		if (IsPrintableAsciiChar(c) == false)
			str[i] = replace;
	}
}

bool IsSafeChar(char c) {
	char *check_str =
	    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	    "abcdefghijklmnopqrstuvwxyz"
	    "0123456789"
	    " ()-_#%&.";

	// strchr also finds the terminator, which is not a safe character
	return c != '\0' && strchr(check_str, c) != NULL;
}

// If the replacement is a space, line breaks are removed instead
void EnSafeHttpHeaderValueStr(char *str, char replace) {
	UINT length = 0;
	UINT index = 0;

	if (str == NULL)
		return;

	length = StrLen(str);
	while (index < length) {
		if ((str[index] == '\r' || str[index] == '\n') && length - index > 1) {
			if (replace == ' ')
				Move(&str[index], &str[index + 1], length - index - 1);
			else
				str[index] = replace;
		} else if (str[index] == '\\') {
			if ((str[index + 1] == 'r' || str[index + 1] == 'n') && length - index > 2) {
				if (replace == ' ') {
					Move(&str[index], &str[index + 2], length - index - 2);
					index++;
				} else {
					str[index] = str[index + 1] = replace;
					index++;
				}
			}
		}
		index++;
	}
}

static bool CheckStringLibrary() {
	wchar_t *compare_str = L"TEST_TEST_123_123456789012345";
	char *teststr = "TEST";
	wchar_t *testunistr = L"TEST";
	wchar_t tmp[64];
	UINT i1 = 123;
	UINT64 i2 = 123456789012345ULL;

	UniFormat(tmp, sizeof(tmp), L"%S_%s_%u_%I64u", teststr, testunistr,
	          i1, i2);

	if (UniStrCmpi(tmp, compare_str) != 0)
		return false;

	return true;
}

void InitStringLibrary() {
	if (CheckStringLibrary() == false)
		MayaFatalExit(1, "String Library Init Failed.\r\nPlease check your locale settings.");
}

UINT ReplaceStri(char *dst, UINT size, const char *string, const char *old_keyword, const char *new_keyword) {
	return ReplaceStrEx(dst, size, string, old_keyword, new_keyword, false);
}

UINT ReplaceStr(char *dst, UINT size, const char *string, const char *old_keyword, const char *new_keyword) {
	return ReplaceStrEx(dst, size, string, old_keyword, new_keyword, true);
}

UINT ReplaceStrEx(char *dst, UINT size, const char *string, const char *old_keyword, const char *new_keyword, bool case_sensitive) {
	if (string == NULL || old_keyword == NULL || new_keyword == NULL)
		return 0;

	UINT len_string = StrLen(string);
	UINT len_old = StrLen(old_keyword);
	UINT len_new = StrLen(new_keyword);

	UINT len_ret = CalcReplaceStrEx(string, old_keyword, new_keyword, case_sensitive);
	char *ret = Malloc(len_ret + 1);
	ret[len_ret] = '\0';

	UINT i = 0;
	UINT j = 0;
	UINT num = 0;
	UINT wp = 0;
	while (true) {
		i = SearchStrEx(string, old_keyword, i, case_sensitive);
		if (i == INFINITE) {
			Copy(ret + wp, string + j, len_string - j);
			wp += len_string - j;
			break;
		}
		num++;
		Copy(ret + wp, string + j, i - j);
		wp += i - j;
		Copy(ret + wp, new_keyword, len_new);
		wp += len_new;
		i += len_old;
		j = i;
	}

	StrCpy(dst, size, ret);

	Free(ret);

	return num;
}

UINT CalcReplaceStrEx(const char *string, const char *old_keyword, const char *new_keyword, bool case_sensitive) {
	if (string == NULL || old_keyword == NULL || new_keyword == NULL)
		return 0;

	UINT len_string = StrLen(string);
	UINT len_old = StrLen(old_keyword);
	UINT len_new = StrLen(new_keyword);

	if (len_old == len_new)
		return len_string;

	UINT num = 0;
	UINT i = 0;
	while (true) {
		i = SearchStrEx(string, old_keyword, i, case_sensitive);
		if (i == INFINITE)
			break;
		i += len_old;
		num++;
	}

	return len_string + len_new * num - len_old * num;
}

UINT SearchStr(const char *string, const char *keyword, UINT start) {
	return SearchStrEx(string, keyword, start, true);
}

// Returns INFINITE if not found
UINT SearchStrEx(const char *string, const char *keyword, UINT start, bool case_sensitive) {
	const char *cmp_string, *cmp_keyword;
	char *upper_string = NULL, *upper_keyword = NULL;
	if (string == NULL || keyword == NULL)
		return INFINITE;

	UINT len_string = StrLen(string);
	if (len_string <= start)
		return INFINITE;

	UINT len_keyword = StrLen(keyword);
	if (len_keyword == 0)
		return INFINITE;

	if ((len_string - start) < len_keyword)
		return INFINITE;

	if (case_sensitive) {
		cmp_string = string;
		cmp_keyword = keyword;
	} else {
		upper_string = CopyStr(string);
		upper_keyword = CopyStr(keyword);
		StrUpper(upper_string);
		StrUpper(upper_keyword);
		cmp_string = upper_string;
		cmp_keyword = upper_keyword;
	}

	// The first match at or after start
	char *found = strstr(cmp_string + start, cmp_keyword);
	UINT ret = (found == NULL) ? INFINITE : (UINT)(found - cmp_string);

	if (case_sensitive == false) {
		Free(upper_keyword);
		Free(upper_string);
	}

	return ret;
}

void FreeToken(TOKEN_LIST *tokens) {
	if (tokens == NULL)
		return;
	for (UINT i = 0; i < tokens->NumTokens; i++)
		if (tokens->Token[i] != 0)
			Free(tokens->Token[i]);
	Free(tokens->Token);
	Free(tokens);
}

TOKEN_LIST *ParseToken(const char *src, const char *separator) {
	return ParseTokenWithoutNullStr(src, separator);
}

bool GetLine(char *str, UINT size) {
	UINT unistr_size = (size + 1) * sizeof(wchar_t);

	wchar_t *unistr = Malloc(unistr_size);

	bool ret = UniGetLineWin32(unistr, unistr_size);

	UniToStr(str, size, unistr);

	Free(unistr);

	return ret;
}

void TrimCrlf(char *str) {
	if (str == NULL)
		return;
	UINT len = StrLen(str);
	if (len == 0)
		return;

	if (str[len - 1] == '\n') {
		if (len >= 2 && str[len - 2] == '\r')
			str[len - 2] = 0;
		str[len - 1] = 0;
	} else if (str[len - 1] == '\r') {
		str[len - 1] = 0;
	}
}

void Trim(char *str) {
	if (str == NULL)
		return;

	TrimLeft(str);

	TrimRight(str);
}

void TrimRight(char *str) {
	if (str == NULL)
		return;

	UINT len = StrLen(str);
	UINT end = len;
	while (end != 0 && (str[end - 1] == ' ' || str[end - 1] == '\t'))
		end--;

	// Writes only when there is something to remove
	if (end != len)
		str[end] = '\0';
}

void TrimLeft(char *str) {
	if (str == NULL)
		return;

	// Writes only when there is something to remove
	UINT skip = (UINT)strspn(str, " \t");
	if (skip != 0)
		StrCpy(str, 0, str + skip);
}

void ToStr(char *str, UINT i) {
	StringCchPrintfA(str, TOSTR_SIZE, "%u", i);
}

UINT ToInt(const char *str) {
	if (str == NULL)
		return 0;

	// Ignore the octal literal
	while (true) {
		if (*str != '0')
			break;
		if ((*(str + 1) == 'x') || (*(str + 1) == 'X'))
			break;
		str++;
	}

	return (UINT)strtoul(str, NULL, 0);
}

// Format a narrow format string into a new wide heap string (Free) with the CRT. The conversions
// mean what they mean in Format (%s is a char string, %S a wchar_t string): the wide formatter
// runs without the legacy wide specifiers, so a wchar_t argument keeps every character instead
// of a round trip through the ANSI code page. NULL when the CRT cannot format the arguments
wchar_t *CopyFormatArgsToUni(const char *fmt, va_list args) {
	unsigned __int64 options = _CRT_INTERNAL_LOCAL_PRINTF_OPTIONS & ~(unsigned __int64)_CRT_INTERNAL_PRINTF_LEGACY_WIDE_SPECIFIERS;
	va_list count_args;
	wchar_t *fmt_w;
	wchar_t *ret;
	int len;
	if (fmt == NULL)
		return NULL;

	fmt_w = CopyStrToUni(fmt);

	va_copy(count_args, args);
	len = __stdio_common_vswprintf(options | _CRT_INTERNAL_PRINTF_STANDARD_SNPRINTF_BEHAVIOR, NULL, 0, fmt_w, NULL, count_args);
	va_end(count_args);
	if (len < 0) {
		Free(fmt_w);
		return NULL;
	}

	ret = Malloc(((UINT)len + 1) * (UINT)sizeof(wchar_t));
	__stdio_common_vswprintf(options | _CRT_INTERNAL_PRINTF_STANDARD_SNPRINTF_BEHAVIOR, ret, (size_t)len + 1, fmt_w, NULL, args);
	Free(fmt_w);

	return ret;
}

// The message goes to the console as a wide string, without a hop through the ANSI code page
static void PrintArgs(const char *fmt, va_list args) {
	if (fmt == NULL)
		return;

	wchar_t *str = CopyFormatArgsToUni(fmt, args);
	if (str == NULL)
		return;

	UniPrintStr(str);
	Free(str);
}

void Print(const char *fmt, ...) {
	va_list args;
	if (fmt == NULL)
		return;

	va_start(args, fmt);
	PrintArgs(fmt, args);
	va_end(args);
}

static void DebugArgs(const char *fmt, va_list args) {
	if (fmt == NULL)
		return;
	if (IsTraceEnabled()) {
		// An ETW trace session listens (Trace.c): it gets the message also with debug output off
		va_list trace_args;

		va_copy(trace_args, args);
		TraceDebugArgs(fmt, trace_args);
		va_end(trace_args);
	}
	if (g_debug == false)
		return;

	PrintArgs(fmt, args);
}

void Debug(const char *fmt, ...) {
	va_list args;
	if (fmt == NULL)
		return;
	if (g_debug == false && IsTraceEnabled() == false)
		return;

	va_start(args, fmt);

	DebugArgs(fmt, args);

	va_end(args);
}

void Format(char *buf, UINT size, const char *fmt, ...) {
	va_list args;
	if (buf == NULL || fmt == NULL)
		return;

	va_start(args, fmt);
	FormatArgs(buf, size, fmt, args);
	va_end(args);
}

// The CRT formatter (narrow: %s is a char string, %S a wchar_t string). size 0 means the buffer
// holds the whole result; otherwise a longer result keeps size - 1 characters and the
// terminator. buf must not be an argument or fmt
void FormatArgs(char *buf, UINT size, const char *fmt, va_list args) {
	size_t count = size;
	if (buf == NULL || fmt == NULL)
		return;

	if (size == 0) {
		va_list count_args;

		va_copy(count_args, args);
		int len = _vscprintf(fmt, count_args);
		va_end(count_args);
		if (len < 0) {
			buf[0] = 0;
			return;
		}
		count = (size_t)len + 1;
	}

	_vsnprintf_s(buf, count, _TRUNCATE, fmt, args);
}

int StrCmpi(const char *str1, const char *str2) {
	if (str1 == NULL && str2 == NULL)
		return 0;
	if (str1 == NULL)
		return 1;
	if (str2 == NULL)
		return -1;

	UINT i = 0;
	while (true) {
		char c1 = ToUpper(str1[i]);
		char c2 = ToUpper(str2[i]);
		if (c1 > c2)
			return 1;
		else if (c1 < c2)
			return -1;
		if (str1[i] == 0 || str2[i] == 0)
			return 0;
		i++;
	}
}

int StrCmp(const char *str1, const char *str2) {
	if (str1 == NULL && str2 == NULL)
		return 0;
	if (str1 == NULL)
		return 1;
	if (str2 == NULL)
		return -1;

	return strcmp(str1, str2);
}

void StrLower(char *str) {
	if (str == NULL)
		return;

	UINT len = StrLen(str);
	for (UINT i = 0; i < len; i++)
		str[i] = ToLower(str[i]);
}

void StrUpper(char *str) {
	if (str == NULL)
		return;

	UINT len = StrLen(str);
	for (UINT i = 0; i < len; i++)
		str[i] = ToUpper(str[i]);
}

char ToLower(char c) {
	if ('A' <= c && c <= 'Z')
		c += 'z' - 'Z';
	return c;
}

char ToUpper(char c) {
	if ('a' <= c && c <= 'z')
		c += 'Z' - 'z';
	return c;
}

// The cch that strsafe takes for the size argument of a string function: size 0 means no limit,
// and strsafe accepts at most STRSAFE_MAX_CCH characters
static size_t StrSafeCch(UINT size) {
	if (size == 0 || size > STRSAFE_MAX_CCH)
		return STRSAFE_MAX_CCH;

	return size;
}

UINT StrCat(char *dst, UINT size, const char *src) {
	size_t len1;
	if (dst == NULL || src == NULL)
		return 0;

	KS_INC(KS_STRCAT_COUNT);

	size_t cch = StrSafeCch(size);

	// A destination without room for one more character takes nothing and gives 0, except that
	// an empty src gives the length of a destination that fits
	if (FAILED(StringCchLengthA(dst, cch, &len1)) || (len1 == cch - 1 && src[0] != '\0'))
		return 0;

	// Appends at most cch - 1 - len1 characters and always writes the terminator
	char *end = dst + len1;
	StringCchCopyExA(dst + len1, cch - len1, src, &end, NULL, 0);

	return (UINT)(end - dst);
}
UINT StrCatLeft(char *dst, UINT size, const char *src) {
	if (dst == NULL || src == NULL)
		return 0;

	char *s = CopyStr(dst);
	StrCpy(dst, size, src);
	StrCat(dst, size, s);

	Free(s);

	return StrLen(dst);
}

UINT StrCpy(char *dst, UINT size, const char *src) {
	size_t len;
	if (dst == src)
		return StrLen(src);
	if (dst == NULL || src == NULL) {
		if (src == NULL && dst != NULL) {
			if (size >= 1)
				dst[0] = '\0';
		}
		return 0;
	}

	// Copies at most size - 1 characters and always writes the terminator: a longer src is cut,
	// and size 1 writes only the terminator. src and dst may overlap: strsafe copies forward only,
	// so Move copies; strsafe bounds the length, which is size - 1 for a src of size characters
	// or more
	size_t cch = StrSafeCch(size);
	if (FAILED(StringCchLengthA(src, cch, &len)))
		len = cch - 1;
	Move(dst, src, (UINT)len);
	dst[len] = '\0';

	KS_INC(KS_STRCPY_COUNT);

	return (UINT)len;
}

bool StrCheckLen(const char *str, UINT len) {
	if (str == NULL)
		return false;

	KS_INC(KS_STRCHECK_COUNT);

	// True when a terminator is among the first len + 1 characters; reads no further
	return SUCCEEDED(StringCchLengthA(str, (len >= STRSAFE_MAX_CCH) ? STRSAFE_MAX_CCH : (size_t)len + 1, NULL));
}

UINT StrSize(const char *str) {
	if (str == NULL)
		return 0;

	return StrLen(str) + 1;
}

UINT StrLen(const char *str) {
	if (str == NULL)
		return 0;

	KS_INC(KS_STRLEN_COUNT);

	return (UINT)strlen(str);
}

