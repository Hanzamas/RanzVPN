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
#define	STRSAFE_NO_DEPRECATE
#include <strsafe.h>

// Room for the longest result of ToStr, ToStr64 and ToHex, terminator included
#define	TOSTR_SIZE			sizeof("4294967295")
#define	TOSTR64_SIZE		sizeof("18446744073709551615")
#define	TOHEX_SIZE			sizeof("ffffffff")

static LOCK *token_lock = NULL;
static char *default_spliter = " ,\t\r\n";

typedef struct BYTESTR
{
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

void ClearStr(char *str, UINT str_size)
{
	StrCpy(str, str_size, "");
}

UINT SearchAsciiInBinary(void *data, UINT size, char *str, bool case_sensitive)
{
	UINT ret = INFINITE;
	char *tmp;
	if (data == NULL || size == 0 || str == NULL)
	{
		return INFINITE;
	}

	tmp = ZeroMalloc(size + 1);
	Copy(tmp, data, size);

	ret = SearchStrEx(tmp, str, 0, case_sensitive);

	Free(tmp);

	return ret;
}

UINT HexToInt(char *str)
{
	UINT len, i;
	UINT ret = 0;
	if (str == NULL)
	{
		return 0;
	}

	if (str[0] == '0' && (str[1] == 'x' || str[1] == 'X'))
	{
		str += 2;
	}

	len = StrLen(str);
	for (i = 0;i < len;i++)
	{
		char c = str[i];

		if ((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'))
		{
			ret = ret * 16 + (UINT)HexTo4Bit(c);
		}
		else
		{
			break;
		}
	}

	return ret;
}

void ToHex(char *str, UINT value)
{
	if (str == NULL)
	{
		return;
	}

	// Lower case digits without leading zeros
	StringCchPrintfA(str, TOHEX_SIZE, "%x", value);
}

char FourBitToHex(UINT value)
{
	value = value % 16;

	if (value <= 9)
	{
		return '0' + value;
	}
	else
	{
		return 'a' + (value - 10);
	}
}

UINT HexTo4Bit(char c)
{
	if ('0' <= c && c <= '9')
	{
		return c - '0';
	}
	else if ('a' <= c && c <= 'f')
	{
		return c - 'a' + 10;
	}
	else if ('A' <= c && c <= 'F')
	{
		return c - 'A' + 10;
	}
	else
	{
		return 0;
	}
}

static char *DefaultTokenSplitChars()
{
	return " ,\t\r\n";
}

// A heap copy of the first len characters of str
static char *CopyStrPrefix(char *str, UINT len)
{
	char *ret = Malloc(len + 1);

	StringCchCopyNA(ret, (size_t)len + 1, str, len);

	return ret;
}

TOKEN_LIST *ParseTokenWithNullStr(char *str, char *split_chars)
{
	LIST *o;
	UINT i;
	TOKEN_LIST *t;
	if (str == NULL)
	{
		return NullToken();
	}
	if (split_chars == NULL)
	{
		split_chars = DefaultTokenSplitChars();
	}

	o = NewListFast(NULL);

	// Each separator and the terminator end a token, also an empty one
	while (true)
	{
		UINT len = (UINT)strcspn(str, split_chars);

		Insert(o, CopyStrPrefix(str, len));

		if (str[len] == '\0')
		{
			break;
		}

		str += len + 1;
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

TOKEN_LIST *ParseTokenWithoutNullStr(char *str, char *split_chars)
{
	LIST *o;
	UINT i;
	TOKEN_LIST *t;
	if (str == NULL)
	{
		return NullToken();
	}
	if (split_chars == NULL)
	{
		split_chars = DefaultTokenSplitChars();
	}

	o = NewListFast(NULL);

	// A run of separators splits once, and no token is empty
	while (true)
	{
		UINT len;

		str += strspn(str, split_chars);
		if (str[0] == '\0')
		{
			break;
		}

		len = (UINT)strcspn(str, split_chars);

		Insert(o, CopyStrPrefix(str, len));

		str += len;
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

bool InStr(char *str, char *keyword)
{
	return InStrEx(str, keyword, false);
}
bool InStrEx(char *str, char *keyword, bool case_sensitive)
{
	if (IsEmptyStr(str) || IsEmptyStr(keyword))
	{
		return false;
	}

	if (SearchStrEx(str, keyword, 0, case_sensitive) == INFINITE)
	{
		return false;
	}

	return true;
}

static bool IsSplitChar(char c, char *split_str)
{
	UINT i, len;
	char c_upper = ToUpper(c);
	if (split_str == NULL)
	{
		split_str = default_spliter;
	}

	len = StrLen(split_str);

	for (i = 0;i < len;i++)
	{
		if (ToUpper(split_str[i]) == c_upper)
		{
			return true;
		}
	}

	return false;
}

bool GetKeyAndValue(char *str, char *key, UINT key_size, char *value, UINT value_size, char *split_str)
{
	UINT mode = 0;
	UINT wp1 = 0, wp2 = 0;
	UINT i, len;
	char *key_tmp, *value_tmp;
	bool ret = false;
	if (split_str == NULL)
	{
		split_str = default_spliter;
	}

	len = StrLen(str);

	key_tmp = ZeroMalloc(len + 1);
	value_tmp = ZeroMalloc(len + 1);

	for (i = 0;i < len;i++)
	{
		char c = str[i];

		switch (mode)
		{
		case 0:
			if (IsSplitChar(c, split_str) == false)
			{
				mode = 1;
				key_tmp[wp1] = c;
				wp1++;
			}
			break;

		case 1:
			if (IsSplitChar(c, split_str) == false)
			{
				key_tmp[wp1] = c;
				wp1++;
			}
			else
			{
				mode = 2;
			}
			break;

		case 2:
			if (IsSplitChar(c, split_str) == false)
			{
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

	if (mode != 0)
	{
		ret = true;
		StrCpy(key, key_size, key_tmp);
		StrCpy(value, value_size, value_tmp);
	}

	Free(key_tmp);
	Free(value_tmp);

	return ret;
}

char *MakeCharArray(char c, UINT count)
{
	char *ret = Malloc(count + 1);

	memset(ret, c, count);

	ret[count] = 0;

	return ret;
}

UINT StrWidth(char *str)
{
	wchar_t *s;
	UINT ret;
	if (str == NULL)
	{
		return 0;
	}

	s = CopyStrToUni(str);
	ret = UniStrWidth(s);
	Free(s);

	return ret;
}

bool IsAllUpperStr(char *str)
{
	UINT i, len;
	if (str == NULL)
	{
		return false;
	}

	len = StrLen(str);

	for (i = 0;i < len;i++)
	{
		char c = str[i];

		if ((c >= '0' && c <= '9') ||
			(c >= 'A' && c <= 'Z'))
		{
		}
		else
		{
			return false;
		}
	}

	return true;
}

TOKEN_LIST *UniqueToken(TOKEN_LIST *t)
{
	UINT i, num, j, n;
	TOKEN_LIST *ret;
	if (t == NULL)
	{
		return NULL;
	}

	num = 0;
	for (i = 0;i < t->NumTokens;i++)
	{
		bool exists = false;

		for (j = 0;j < i;j++)
		{
			if (StrCmpi(t->Token[j], t->Token[i]) == 0)
			{
				exists = true;
				break;
			}
		}

		if (exists == false)
		{
			num++;
		}
	}

	ret = ZeroMalloc(sizeof(TOKEN_LIST));
	ret->Token = ZeroMalloc(sizeof(char *) * num);
	ret->NumTokens = num;

	n = 0;

	for (i = 0;i < t->NumTokens;i++)
	{
		bool exists = false;

		for (j = 0;j < i;j++)
		{
			if (StrCmpi(t->Token[j], t->Token[i]) == 0)
			{
				exists = true;
				break;
			}
		}

		if (exists == false)
		{
			ret->Token[n++] = CopyStr(t->Token[i]);
		}
	}

	return ret;
}

void ToStrByte1000(char *str, UINT size, UINT64 v)
{
	UINT i;
	if (str == NULL)
	{
		return;
	}

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

	for (i = 0;i < sizeof(bytestr) / sizeof(bytestr[0]);i++)
	{
		BYTESTR *b = &bytestr[i];

		if ((v * 11UL) / 10UL >= b->base_value)
		{
			if (b->base_value != 0)
			{
				double d = (double)v / (double)b->base_value;
				Format(str, size, "%.2f %s", d, b->string);
			}
			else
			{
				Format(str, size, "%I64u %s", v, b->string);
			}

			break;
		}
	}
}

void ToStrByte(char *str, UINT size, UINT64 v)
{
	UINT i;
	if (str == NULL)
	{
		return;
	}

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

	for (i = 0;i < sizeof(bytestr) / sizeof(bytestr[0]);i++)
	{
		BYTESTR *b = &bytestr[i];

		if ((v * 11UL) / 10UL >= b->base_value)
		{
			if (b->base_value != 0)
			{
				double d = (double)v / (double)b->base_value;
				Format(str, size, "%.2f %s", d, b->string);
			}
			else
			{
				Format(str, size, "%I64u %s", v, b->string);
			}

			break;
		}
	}
}

void ToStr3(char *str, UINT size, UINT64 v)
{
	char tmp[128];
	char tmp2[128];
	UINT i, len, wp;
	if (str == NULL)
	{
		return;
	}

	ToStr64(tmp, v);

	wp = 0;
	len = StrLen(tmp);

	for (i = len - 1;((int)i) >= 0;i--)
	{
		tmp2[wp++] = tmp[i];
	}
	tmp2[wp++] = 0;

	wp = 0;

	for (i = 0;i < len;i++)
	{
		if (i != 0 && (i % 3) == 0)
		{
			tmp[wp++] = ',';
		}
		tmp[wp++] = tmp2[i];
	}
	tmp[wp++] = 0;
	wp = 0;
	len = StrLen(tmp);

	for (i = len - 1;((int)i) >= 0;i--)
	{
		tmp2[wp++] = tmp[i];
	}
	tmp2[wp++] = 0;

	StrCpy(str, size, tmp2);
}

void MacToStr(char *str, UINT size, UCHAR *mac_address)
{
	if (str == NULL || mac_address == NULL)
	{
		return;
	}

	Format(str, size, "%02X-%02X-%02X-%02X-%02X-%02X",
		mac_address[0],
		mac_address[1],
		mac_address[2],
		mac_address[3],
		mac_address[4],
		mac_address[5]);
}

bool IsEmptyStr(char *str)
{
	char *s;
	if (str == NULL)
	{
		return true;
	}

	s = CopyStr(str);
	Trim(s);

	if (StrLen(s) == 0)
	{
		Free(s);
		return true;
	}
	else
	{
		Free(s);
		return false;
	}
}

TOKEN_LIST *ListToTokenList(LIST *o)
{
	UINT i;
	TOKEN_LIST *t;
	if (o == NULL)
	{
		return NULL;
	}

	t = ZeroMalloc(sizeof(TOKEN_LIST));
	t->NumTokens = LIST_NUM(o);
	t->Token = ZeroMalloc(sizeof(char *) * t->NumTokens);
	for (i = 0;i < LIST_NUM(o);i++)
	{
		t->Token[i] = CopyStr(LIST_DATA(o, i));
	}

	return t;
}

void FreeStrList(LIST *o)
{
	UINT i;
	if (o == NULL)
	{
		return;
	}

	for (i = 0;i < LIST_NUM(o);i++)
	{
		char *s = LIST_DATA(o, i);
		Free(s);
	}

	ReleaseList(o);
}

LIST *StrToStrList(char *str, UINT size)
{
	LIST *o;
	char *tmp;
	UINT tmp_size;
	UINT i;
	if (str == NULL)
	{
		return NULL;
	}

	o = NewListFast(NULL);

	i = 0;
	while (true)
	{
		if (i >= size)
		{
			break;
		}
		if (*str == 0)
		{
			break;
		}

		tmp_size = StrSize(str);
		tmp = ZeroMalloc(tmp_size);
		StrCpy(tmp, tmp_size, str);
		Add(o, tmp);
		str += StrLen(str) + 1;
		i++;
	}

	return o;
}

bool IsNum(char *str)
{
	char c;
	UINT i, len;
	UINT n = 0;
	char tmp[MAX_SIZE];
	TOKEN_LIST *t;
	if (str == NULL)
	{
		return false;
	}

	StrCpy(tmp, sizeof(tmp), str);
	Trim(tmp);

	if (StrLen(tmp) == 0)
	{
		return false;
	}

	t = ParseToken(tmp, " ");

	if (t->NumTokens >= 1)
	{
		StrCpy(tmp, sizeof(tmp), t->Token[0]);
	}

	FreeToken(t);

	len = StrLen(tmp);
	for (i = 0;i < len;i++)
	{
		bool b = false;
		c = tmp[i];
		if (('0' <= c && c <= '9') || (c == '+') || (c == '-') || (c == ','))
		{
			b = true;
		}

		if (b == false)
		{
			return false;
		}
	}

	for (i = 0;i < len;i++)
	{
		c = tmp[i];
		if (c == '-')
		{
			n++;
		}
	}
	if (n >= 2)
	{
		return false;
	}

	return true;
}

TOKEN_LIST *NullToken()
{
	TOKEN_LIST *ret = ZeroMalloc(sizeof(TOKEN_LIST));
	ret->Token = ZeroMalloc(0);

	return ret;
}

TOKEN_LIST *CopyToken(TOKEN_LIST *src)
{
	TOKEN_LIST *ret;
	UINT i;
	if (src == NULL)
	{
		return NULL;
	}

	ret = ZeroMalloc(sizeof(TOKEN_LIST));
	ret->NumTokens = src->NumTokens;
	ret->Token = ZeroMalloc(sizeof(char *) * ret->NumTokens);
	for (i = 0;i < ret->NumTokens;i++)
	{
		ret->Token[i] = CopyStr(src->Token[i]);
	}

	return ret;
}

TOKEN_LIST *ParseCmdLine(char *str)
{
	TOKEN_LIST *t;
	LIST *o;
	UINT i, len, wp, mode;
	char c;
	char *tmp;
	bool ignore_space = false;
	if (str == NULL)
	{
		return NullToken();
	}

	o = NewListFast(NULL);
	tmp = Malloc(StrSize(str) + 32);

	wp = 0;
	mode = 0;

	len = StrLen(str);
	for (i = 0;i < len;i++)
	{
		c = str[i];

		switch (mode)
		{
		case 0:
			if (c == ' ' || c == '\t')
			{
			}
			else
			{
				if (c == '\"')
				{
					if (str[i + 1] == '\"')
					{
						// "" is an escaped quote
						tmp[wp++] = '\"';
						i++;
					}
					else
					{
						// A lone " toggles quoted mode (spaces are kept)
						ignore_space = true;
					}
				}
				else
				{
					tmp[wp++] = c;
				}

				mode = 1;
			}
			break;

		case 1:
			if (ignore_space == false && (c == ' ' || c == '\t'))
			{
				tmp[wp++] = 0;
				wp = 0;

				Insert(o, CopyStr(tmp));
				mode = 0;
			}
			else
			{
				if (c == '\"')
				{
					if (str[i + 1] == '\"')
					{
						// "" is an escaped quote
						tmp[wp++] = L'\"';
						i++;
					}
					else
					{
						if (ignore_space == false)
						{
							// A lone " toggles quoted mode (spaces are kept)
							ignore_space = true;
						}
						else
						{
							ignore_space = false;
						}
					}
				}
				else
				{
					tmp[wp++] = c;
				}
			}
			break;
		}
	}

	if (wp != 0)
	{
		tmp[wp++] = 0;
		Insert(o, CopyStr(tmp));
	}

	Free(tmp);

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

void ToStr64(char *str, UINT64 value)
{
	if (str == NULL)
	{
		return;
	}

	StringCchPrintfA(str, TOSTR64_SIZE, "%I64u", value);
}

UINT64 ToInt64(char *str)
{
	UINT len, i;
	UINT64 ret = 0;
	if (str == NULL)
	{
		return 0;
	}

	len = StrLen(str);
	for (i = 0;i < len;i++)
	{
		char c = str[i];
		if (c != ',')
		{
			if ('0' <= c && c <= '9')
			{
				ret = ret * (UINT64)10 + (UINT64)(c - '0');
			}
			else
			{
				break;
			}
		}
	}

	return ret;
}


bool EndWith(char *str, char *key)
{
	UINT str_len;
	UINT key_len;
	if (str == NULL || key == NULL)
	{
		return false;
	}

	str_len = StrLen(str);
	key_len = StrLen(key);
	if (str_len < key_len)
	{
		return false;
	}

	if (StrCmpi(str + (str_len - key_len), key) == 0)
	{
		return true;
	}
	else
	{
		return false;
	}
}

bool StartWith(char *str, char *key)
{
	UINT str_len;
	UINT key_len;
	char *tmp;
	bool ret;
	if (str == NULL || key == NULL)
	{
		return false;
	}

	str_len = StrLen(str);
	key_len = StrLen(key);
	if (str_len < key_len)
	{
		return false;
	}
	if (str_len == 0 || key_len == 0)
	{
		return false;
	}
	tmp = CopyStr(str);
	tmp[key_len] = 0;

	if (StrCmpi(tmp, key) == 0)
	{
		ret = true;
	}
	else
	{
		ret = false;
	}

	Free(tmp);

	return ret;
}

bool StrToMac(UCHAR *mac_address, char *str)
{
	BUF *b;
	if (mac_address == NULL || str == NULL)
	{
		return false;
	}

	b = StrToBin(str);
	if (b == NULL)
	{
		return false;
	}

	if (b->Size != 6)
	{
		FreeBuf(b);
		return false;
	}

	Copy(mac_address, b->Buf, 6);

	FreeBuf(b);

	return true;
}

BUF *StrToBin(char *str)
{
	BUF *b;
	UINT len, i;
	char tmp[3];
	if (str == NULL)
	{
		return NULL;
	}

	len = StrLen(str);
	tmp[0] = 0;
	b = NewBuf();
	for (i = 0;i < len;i++)
	{
		char c = str[i];
		c = ToUpper(c);
		if (('0' <= c && c <= '9') || ('A' <= c && c <= 'F'))
		{
			if (tmp[0] == 0)
			{
				tmp[0] = c;
				tmp[1] = 0;
			}
			else if (tmp[1] == 0)
			{
				UCHAR data;
				char tmp2[64];
				tmp[1] = c;
				tmp[2] = 0;
				StrCpy(tmp2, sizeof(tmp2), "0x");
				StrCat(tmp2, sizeof(tmp2), tmp);
				data = (UCHAR)strtoul(tmp2, NULL, 0);
				WriteBuf(b, &data, 1);
				Zero(tmp, sizeof(tmp));	
			}
		}
		else if (c == ' ' || c == ',' || c == '-' || c == ':')
		{
		}
		else
		{
			break;
		}
	}

	return b;
}

void BinToStrEx(char *str, UINT str_size, void *data, UINT data_size)
{
	char *tmp;
	UCHAR *buf = (UCHAR *)data;
	UINT size;
	UINT i;
	if (str == NULL || data == NULL)
	{
		return;
	}

	size = data_size * 3 + 1;
	tmp = ZeroMalloc(size);
	for (i = 0;i < data_size;i++)
	{
		StringCchPrintfA(&tmp[i * 3], size - i * 3, "%02X ", buf[i]);
	}
	Trim(tmp);
	StrCpy(str, str_size, tmp);
	Free(tmp);
}

void BinToStr(char *str, UINT str_size, void *data, UINT data_size)
{
	char *tmp;
	UCHAR *buf = (UCHAR *)data;
	UINT size;
	UINT i;
	if (str == NULL || data == NULL)
	{
		if (str != NULL)
		{
			str[0] = 0;
		}
		return;
	}

	size = data_size * 2 + 1;
	tmp = ZeroMalloc(size);
	for (i = 0;i < data_size;i++)
	{
		StringCchPrintfA(&tmp[i * 2], size - i * 2, "%02X", buf[i]);
	}
	StrCpy(str, str_size, tmp);
	Free(tmp);
}
void BinToStrW(wchar_t *str, UINT str_size, void *data, UINT data_size)
{
	char *tmp;
	UINT tmp_size;
	if (str == NULL || data == NULL)
	{
		if (str != NULL)
		{
			str[0] = 0;
		}
		return;
	}

	tmp_size = (data_size * 2 + 4) * sizeof(wchar_t);
	tmp = ZeroMalloc(tmp_size);

	BinToStr(tmp, tmp_size, data, data_size);

	StrToUni(str, str_size, tmp);

	Free(tmp);
}

char *CopyStr(char *str)
{
	UINT len;
	char *dst;
	if (str == NULL)
	{
		return NULL;
	}

	len = StrLen(str);
	dst = Malloc(len + 1);
	StrCpy(dst, len + 1, str);
	return dst;
}

bool IsSafeStr(char *str)
{
	UINT i, len;
	if (str == NULL)
	{
		return false;
	}

	len = StrLen(str);
	for (i = 0;i < len;i++)
	{
		if (IsSafeChar(str[i]) == false)
		{
			return false;
		}
	}
	if (str[0] == ' ')
	{
		return false;
	}
	if (len != 0)
	{
		if (str[len - 1] == ' ')
		{
			return false;
		}
	}
	return true;
}

bool IsPrintableAsciiChar(char c)
{
	UCHAR uc = (UCHAR)c;
	if (uc <= 31)
	{
		return false;
	}
	if (uc >= 127)
	{
		return false;
	}
	return true;
}

void EnPrintableAsciiStr(char *str, char replace)
{
	UINT i, len;
	if (str == NULL)
	{
		return;
	}

	len = StrLen(str);

	for (i = 0;i < len;i++)
	{
		char c = str[i];

		if (IsPrintableAsciiChar(c) == false)
		{
			str[i] = replace;
		}
	}
}

bool IsSafeChar(char c)
{
	char *check_str =
		"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
		"abcdefghijklmnopqrstuvwxyz"
		"0123456789"
		" ()-_#%&.";

	// strchr also finds the terminator, which is not a safe character
	return c != '\0' && strchr(check_str, c) != NULL;
}

// If the replacement is a space, line breaks are removed instead
void EnSafeHttpHeaderValueStr(char *str, char replace)
{
	UINT length = 0;
	UINT index = 0;

	if (str == NULL)
	{
		return;
	}

	length = StrLen(str);
	while (index < length)
	{
		if ((str[index] == '\r' || str[index] == '\n') &&  length - index > 1)
		{
			if (replace == ' ')
			{
				Move(&str[index], &str[index + 1], length - index - 1);
			}
			else
			{
				str[index] = replace;
			}
		}
		else if (str[index] == '\\')
		{
			if ((str[index + 1] == 'r' || str[index + 1] == 'n') && length - index > 2)
			{
				if (replace == ' ')
				{
					Move(&str[index], &str[index + 2], length - index - 2);
					index++;
				}
				else
				{
					str[index] = str[index + 1] = replace;
					index++;
				}
			}
		}
		index++;
	}
}

static bool CheckStringLibrary()
{
	wchar_t *compare_str = L"TEST_TEST_123_123456789012345";
	char *teststr = "TEST";
	wchar_t *testunistr = L"TEST";
	wchar_t tmp[64];
	UINT i1 = 123;
	UINT64 i2 = 123456789012345ULL;

	UniFormat(tmp, sizeof(tmp), L"%S_%s_%u_%I64u", teststr, testunistr,
		i1, i2);

	if (UniStrCmpi(tmp, compare_str) != 0)
	{
		return false;
	}

	return true;
}

void InitStringLibrary()
{
	token_lock = NewLock();

	if (CheckStringLibrary() == false)
	{
		Alert("String Library Init Failed.\r\nPlease check your locale settings.", NULL);
		exit(0);
	}
}

void FreeStringLibrary()
{
	DeleteLock(token_lock);
	token_lock = NULL;
}

UINT ReplaceStri(char *dst, UINT size, char *string, char *old_keyword, char *new_keyword)
{
	return ReplaceStrEx(dst, size, string, old_keyword, new_keyword, false);
}

UINT ReplaceStr(char *dst, UINT size, char *string, char *old_keyword, char *new_keyword)
{
	return ReplaceStrEx(dst, size, string, old_keyword, new_keyword, true);
}

UINT ReplaceStrEx(char *dst, UINT size, char *string, char *old_keyword, char *new_keyword, bool case_sensitive)
{
	UINT i, j, num;
	UINT len_string, len_old, len_new;
	UINT len_ret;
	UINT wp;
	char *ret;
	if (string == NULL || old_keyword == NULL || new_keyword == NULL)
	{
		return 0;
	}

	len_string = StrLen(string);
	len_old = StrLen(old_keyword);
	len_new = StrLen(new_keyword);

	len_ret = CalcReplaceStrEx(string, old_keyword, new_keyword, case_sensitive);
	ret = Malloc(len_ret + 1);
	ret[len_ret] = '\0';

	i = 0;
	j = 0;
	num = 0;
	wp = 0;
	while (true)
	{
		i = SearchStrEx(string, old_keyword, i, case_sensitive);
		if (i == INFINITE)
		{
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

UINT CalcReplaceStrEx(char *string, char *old_keyword, char *new_keyword, bool case_sensitive)
{
	UINT i, num;
	UINT len_string, len_old, len_new;
	if (string == NULL || old_keyword == NULL || new_keyword == NULL)
	{
		return 0;
	}

	len_string = StrLen(string);
	len_old = StrLen(old_keyword);
	len_new = StrLen(new_keyword);

	if (len_old == len_new)
	{
		return len_string;
	}

	num = 0;
	i = 0;
	while (true)
	{
		i = SearchStrEx(string, old_keyword, i, case_sensitive);
		if (i == INFINITE)
		{
			break;
		}
		i += len_old;
		num++;
	}

	return len_string + len_new * num - len_old * num;
}

UINT SearchStr(char *string, char *keyword, UINT start)
{
	return SearchStrEx(string, keyword, start, true);
}

// Returns INFINITE if not found
UINT SearchStrEx(char *string, char *keyword, UINT start, bool case_sensitive)
{
	UINT len_string, len_keyword;
	UINT ret;
	char *cmp_string, *cmp_keyword;
	char *found;
	if (string == NULL || keyword == NULL)
	{
		return INFINITE;
	}

	len_string = StrLen(string);
	if (len_string <= start)
	{
		return INFINITE;
	}

	len_keyword = StrLen(keyword);
	if (len_keyword == 0)
	{
		return INFINITE;
	}

	if ((len_string - start) < len_keyword)
	{
		return INFINITE;
	}

	if (case_sensitive)
	{
		cmp_string = string;
		cmp_keyword = keyword;
	}
	else
	{
		cmp_string = CopyStr(string);
		cmp_keyword = CopyStr(keyword);
		StrUpper(cmp_string);
		StrUpper(cmp_keyword);
	}

	// The first match at or after start
	found = strstr(cmp_string + start, cmp_keyword);
	ret = (found == NULL) ? INFINITE : (UINT)(found - cmp_string);

	if (case_sensitive == false)
	{
		Free(cmp_keyword);
		Free(cmp_string);
	}

	return ret;
}

void FreeToken(TOKEN_LIST *tokens)
{
	UINT i;
	if (tokens == NULL)
	{
		return;
	}
	for (i = 0;i < tokens->NumTokens;i++)
	{
		if (tokens->Token[i] != 0)
		{
			Free(tokens->Token[i]);
		}
	}
	Free(tokens->Token);
	Free(tokens);
}

TOKEN_LIST *ParseToken(char *src, char *separator)
{
	return ParseTokenWithoutNullStr(src, separator);
}

bool GetLine(char *str, UINT size)
{
	bool ret;
	wchar_t *unistr;
	UINT unistr_size = (size + 1) * sizeof(wchar_t);

	unistr = Malloc(unistr_size);

	ret = UniGetLineWin32(unistr, unistr_size);

	UniToStr(str, size, unistr);

	Free(unistr);

	return ret;
}

void TrimCrlf(char *str)
{
	UINT len;
	if (str == NULL)
	{
		return;
	}
	len = StrLen(str);
	if (len == 0)
	{
		return;
	}

	if (str[len - 1] == '\n')
	{
		if (len >= 2 && str[len - 2] == '\r')
		{
			str[len - 2] = 0;
		}
		str[len - 1] = 0;
	}
	else if (str[len - 1] == '\r')
	{
		str[len - 1] = 0;
	}
}

void Trim(char *str)
{
	if (str == NULL)
	{
		return;
	}

	TrimLeft(str);

	TrimRight(str);
}

void TrimRight(char *str)
{
	UINT len, end;
	if (str == NULL)
	{
		return;
	}

	len = StrLen(str);
	end = len;
	while (end != 0 && (str[end - 1] == ' ' || str[end - 1] == '\t'))
	{
		end--;
	}

	// Writes only when there is something to remove
	if (end != len)
	{
		str[end] = '\0';
	}
}

void TrimLeft(char *str)
{
	UINT skip;
	if (str == NULL)
	{
		return;
	}

	// Writes only when there is something to remove
	skip = (UINT)strspn(str, " \t");
	if (skip != 0)
	{
		StrCpyAllowOverlap(str, 0, str + skip);
	}
}

void ToStr(char *str, UINT i)
{
	StringCchPrintfA(str, TOSTR_SIZE, "%u", i);
}

int ToInti(char *str)
{
	if (str == NULL)
	{
		return 0;
	}

	return (int)ToInt(str);
}

UINT ToInt(char *str)
{
	if (str == NULL)
	{
		return 0;
	}

	// Ignore the octal literal
	while (true)
	{
		if (*str != '0')
		{
			break;
		}
		if ((*(str + 1) == 'x') || (*(str + 1) == 'X'))
		{
			break;
		}
		str++;
	}

	return (UINT)strtoul(str, NULL, 0);
}

static void PrintStr(char *str)
{
	wchar_t *unistr = NULL;
	if (str == NULL)
	{
		return;
	}

	unistr = CopyStrToUni(str);
	UniPrintStr(unistr);
	Free(unistr);
}

static void PrintArgs(char *fmt, va_list args)
{
	wchar_t *ret;
	wchar_t *fmt_wchar;
	char *tmp;
	if (fmt == NULL)
	{
		return;
	}

	fmt_wchar = CopyStrToUni(fmt);
	ret = InternalFormatArgs(fmt_wchar, args, true);

	tmp = CopyUniToStr(ret);
	PrintStr(tmp);
	Free(tmp);

	Free(ret);
	Free(fmt_wchar);
}

void Print(char *fmt, ...)
{
	va_list args;
	if (fmt == NULL)
	{
		return;
	}

	va_start(args, fmt);
	PrintArgs(fmt, args);
	va_end(args);
}

static void DebugArgs(char *fmt, va_list args)
{
	if (fmt == NULL)
	{
		return;
	}
	if (IsTraceEnabled())
	{
		// An ETW trace session listens (Trace.c): it gets the message also with debug output off
		va_list trace_args;

		va_copy(trace_args, args);
		TraceDebugArgs(fmt, trace_args);
		va_end(trace_args);
	}
	if (g_debug == false)
	{
		return;
	}

	PrintArgs(fmt, args);
}

void Debug(char *fmt, ...)
{
	va_list args;
	if (fmt == NULL)
	{
		return;
	}
	if (g_debug == false && IsTraceEnabled() == false)
	{
		return;
	}

	va_start(args, fmt);

	DebugArgs(fmt, args);

	va_end(args);
}

void Format(char *buf, UINT size, char *fmt, ...)
{
	va_list args;
	if (buf == NULL || fmt == NULL)
	{
		return;
	}

	va_start(args, fmt);
	FormatArgs(buf, size, fmt, args);
	va_end(args);
}

void FormatArgs(char *buf, UINT size, char *fmt, va_list args)
{
	wchar_t *tag;
	wchar_t *ret;
	if (buf == NULL || fmt == NULL)
	{
		return;
	}

	tag = CopyStrToUni(fmt);
	ret = InternalFormatArgs(tag, args, true);

	UniToStr(buf, size, ret);
	Free(ret);
	Free(tag);
}

int StrCmpi(char *str1, char *str2)
{
	UINT i;
	if (str1 == NULL && str2 == NULL)
	{
		return 0;
	}
	if (str1 == NULL)
	{
		return 1;
	}
	if (str2 == NULL)
	{
		return -1;
	}

	i = 0;
	while (true)
	{
		char c1, c2;
		c1 = ToUpper(str1[i]);
		c2 = ToUpper(str2[i]);
		if (c1 > c2)
		{
			return 1;
		}
		else if (c1 < c2)
		{
			return -1;
		}
		if (str1[i] == 0 || str2[i] == 0)
		{
			return 0;
		}
		i++;
	}
}

int StrCmp(char *str1, char *str2)
{
	if (str1 == NULL && str2 == NULL)
	{
		return 0;
	}
	if (str1 == NULL)
	{
		return 1;
	}
	if (str2 == NULL)
	{
		return -1;
	}

	return strcmp(str1, str2);
}

void StrLower(char *str)
{
	UINT len, i;
	if (str == NULL)
	{
		return;
	}

	len = StrLen(str);
	for (i = 0;i < len;i++)
	{
		str[i] = ToLower(str[i]);
	}
}

void StrUpper(char *str)
{
	UINT len, i;
	if (str == NULL)
	{
		return;
	}

	len = StrLen(str);
	for (i = 0;i < len;i++)
	{
		str[i] = ToUpper(str[i]);
	}
}

char ToLower(char c)
{
	if ('A' <= c && c <= 'Z')
	{
		c += 'z' - 'Z';
	}
	return c;
}

char ToUpper(char c)
{
	if ('a' <= c && c <= 'z')
	{
		c += 'Z' - 'z';
	}
	return c;
}

// The cch that strsafe takes for the size argument of a string function: size 0 means no limit,
// and strsafe accepts at most STRSAFE_MAX_CCH characters
static size_t StrSafeCch(UINT size)
{
	if (size == 0 || size > STRSAFE_MAX_CCH)
	{
		return STRSAFE_MAX_CCH;
	}

	return size;
}

UINT StrCat(char *dst, UINT size, char *src)
{
	size_t cch, len1;
	char *end;
	if (dst == NULL || src == NULL)
	{
		return 0;
	}

	KS_INC(KS_STRCAT_COUNT);

	cch = StrSafeCch(size);

	// A destination without room for one more character takes nothing and gives 0, except that
	// an empty src gives the length of a destination that fits
	if (FAILED(StringCchLengthA(dst, cch, &len1)) || (len1 == cch - 1 && src[0] != '\0'))
	{
		return 0;
	}

	// Appends at most cch - 1 - len1 characters and always writes the terminator
	end = dst + len1;
	StringCchCopyExA(dst + len1, cch - len1, src, &end, NULL, 0);

	return (UINT)(end - dst);
}
UINT StrCatLeft(char *dst, UINT size, char *src)
{
	char *s;
	if (dst == NULL || src == NULL)
	{
		return 0;
	}

	s = CopyStr(dst);
	StrCpy(dst, size, src);
	StrCat(dst, size, s);

	Free(s);

	return StrLen(dst);
}

UINT StrCpy(char *dst, UINT size, char *src)
{
	char *end;
	if (dst == src)
	{
		return StrLen(src);
	}
	if (dst == NULL || src == NULL)
	{
		if (src == NULL && dst != NULL)
		{
			if (size >= 1)
			{
				dst[0] = '\0';
			}
		}
		return 0;
	}

	// Copies at most size - 1 characters and always writes the terminator: a longer src is cut,
	// and size 1 writes only the terminator
	end = dst;
	StringCchCopyExA(dst, StrSafeCch(size), src, &end, NULL, 0);

	KS_INC(KS_STRCPY_COUNT);

	return (UINT)(end - dst);
}
UINT StrCpyAllowOverlap(char *dst, UINT size, char *src)
{
	size_t cch, len;
	if (dst == src)
	{
		return StrLen(src);
	}
	if (dst == NULL || src == NULL)
	{
		if (src == NULL && dst != NULL)
		{
			if (size >= 1)
			{
				dst[0] = '\0';
			}
		}
		return 0;
	}

	// strsafe copies forward only, so Move copies; strsafe bounds the length, which is size - 1
	// for a src of size characters or more
	cch = StrSafeCch(size);
	if (FAILED(StringCchLengthA(src, cch, &len)))
	{
		len = cch - 1;
	}
	Move(dst, src, (UINT)len);
	dst[len] = '\0';

	KS_INC(KS_STRCPY_COUNT);

	return (UINT)len;
}

bool StrCheckLen(char *str, UINT len)
{
	if (str == NULL)
	{
		return false;
	}

	KS_INC(KS_STRCHECK_COUNT);

	// True when a terminator is among the first len + 1 characters; reads no further
	return SUCCEEDED(StringCchLengthA(str, (len >= STRSAFE_MAX_CCH) ? STRSAFE_MAX_CCH : (size_t)len + 1, NULL));
}

UINT StrSize(char *str)
{
	if (str == NULL)
	{
		return 0;
	}

	return StrLen(str) + 1;
}

UINT StrLen(char *str)
{
	if (str == NULL)
	{
		return 0;
	}

	KS_INC(KS_STRLEN_COUNT);

	return (UINT)strlen(str);
}

