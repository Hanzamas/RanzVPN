// Internat.c
// String conversion library for internationalization

#include "Internat.h"

#include "Mayaqua.h"
#include "Memory.h"
#include "Network.h"
#include "Object.h"
#include "Str.h"
#include "Tracking.h"
#include "Win32.h"

#include <locale.h>
#include <wchar.h>

bool UniInChar(wchar_t *string, wchar_t c)
{
	UINT i, len;
	if (string == NULL)
	{
		return false;
	}

	len = UniStrLen(string);

	for (i = 0;i < len;i++)
	{
		if (string[i] == c)
		{
			return true;
		}
	}

	return false;
}

static UNI_TOKEN_LIST *UniListToTokenList(LIST *o)
{
	UINT i;
	UNI_TOKEN_LIST *t;
	if (o == NULL)
	{
		return NULL;
	}

	t = ZeroMalloc(sizeof(UNI_TOKEN_LIST));
	t->NumTokens = LIST_NUM(o);
	t->Token = ZeroMalloc(sizeof(wchar_t *) * t->NumTokens);
	for (i = 0;i < LIST_NUM(o);i++)
	{
		t->Token[i] = UniCopyStr(LIST_DATA(o, i));
	}

	return t;
}

void UniFreeStrList(LIST *o)
{
	UINT i;
	if (o == NULL)
	{
		return;
	}

	for (i = 0;i < LIST_NUM(o);i++)
	{
		wchar_t *s = LIST_DATA(o, i);
		Free(s);
	}

	ReleaseList(o);
}

wchar_t *UniNormalizeCrlf(wchar_t *str)
{
	wchar_t *ret;
	UINT ret_size, i, len, wp;
	if (str == NULL)
	{
		return NULL;
	}

	len = UniStrLen(str);
	ret_size = sizeof(wchar_t) * (len + 32) * 2;
	ret = Malloc(ret_size);

	wp = 0;

	for (i = 0;i < len;i++)
	{
		wchar_t c = str[i];

		switch (c)
		{
		case L'\r':
			if (str[i + 1] == L'\n')
			{
				i++;
			}
			ret[wp++] = L'\r';
			ret[wp++] = L'\n';
			break;

		case L'\n':
			ret[wp++] = L'\r';
			ret[wp++] = L'\n';
			break;

		default:
			ret[wp++] = c;
			break;
		}
	}

	ret[wp++] = 0;

	return ret;
}

bool UniEndWith(wchar_t *str, wchar_t *key)
{
	UINT str_len;
	UINT key_len;
	if (str == NULL || key == NULL)
	{
		return false;
	}

	str_len = UniStrLen(str);
	key_len = UniStrLen(key);
	if (str_len < key_len)
	{
		return false;
	}

	if (UniStrCmpi(str + (str_len - key_len), key) == 0)
	{
		return true;
	}
	else
	{
		return false;
	}
}

bool UniStartWith(wchar_t *str, wchar_t *key)
{
	UINT str_len;
	UINT key_len;
	wchar_t *tmp;
	bool ret;
	if (str == NULL || key == NULL)
	{
		return false;
	}

	str_len = UniStrLen(str);
	key_len = UniStrLen(key);
	if (str_len < key_len)
	{
		return false;
	}
	if (str_len == 0 || key_len == 0)
	{
		return false;
	}
	tmp = CopyUniStr(str);
	tmp[key_len] = 0;

	if (UniStrCmpi(tmp, key) == 0)
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

void UniToStr3(wchar_t *str, UINT size, UINT64 value)
{
	char tmp[MAX_SIZE];
	if (str == NULL)
	{
		return;
	}

	ToStr3(tmp, sizeof(tmp), value);

	StrToUni(str, size, tmp);
}

wchar_t *InternalFormatArgs(wchar_t *fmt, va_list args, bool ansi_mode)
{
	UINT i, len;
	wchar_t *tmp;
	UINT tmp_size;
	LIST *o;
	UINT mode = 0;
	UINT wp;
	UINT total_size;
	wchar_t *ret;
	if (fmt == NULL)
	{
		return NULL;
	}

	len = UniStrLen(fmt);
	tmp_size = UniStrSize(fmt);
	tmp = Malloc(tmp_size);

	o = NewListFast(NULL);

	mode = 0;

	wp = 0;

	for (i = 0;i < len;i++)
	{
		wchar_t c = fmt[i];

		if (mode == 0)
		{
			switch (c)
			{
			case L'%':
				if (fmt[i + 1] == L'%')
				{
					// %% outputs a literal %
					i++;
					tmp[wp++] = c;
				}
				else
				{
					mode = 1;
					tmp[wp++] = 0;
					wp = 0;
					Add(o, CopyUniStr(tmp));
					tmp[wp++] = c;
				}
				break;
			default:
				tmp[wp++] = c;
				break;
			}
		}
		else
		{
			char *tag;
			char dst[MAX_SIZE];
			wchar_t *target_str;
			wchar_t *padding_str;
			bool left_padding;
			UINT target_str_len;
			UINT total_len;
			wchar_t *output_str;
			UINT padding;
			switch (c)
			{
			case L'c':
			case L'C':
			case L'd':
			case L'i':
			case L'o':
			case L'u':
			case L'x':
			case L'X':
				tmp[wp++] = c;
				tmp[wp++] = 0;
				tag = CopyUniToStr(tmp);

					ReplaceStrEx(tag, 0, tag, "ll", "I64", false);

				if ((UniStrLen(tmp) >= 5 && tmp[UniStrLen(tmp) - 4] == L'I' &&
					tmp[UniStrLen(tmp) - 3] == L'6' &&
					tmp[UniStrLen(tmp) - 2] == L'4') ||
					(
					UniStrLen(tmp) >= 4 && tmp[UniStrLen(tmp) - 3] == L'l' &&
					tmp[UniStrLen(tmp) - 2] == L'l'))
				{
						snprintf(dst, sizeof(dst), tag, va_arg(args, UINT64));
				}
				else
				{
						snprintf(dst, sizeof(dst), tag, va_arg(args, int));
				}

				Free(tag);
				Add(o, CopyStrToUni(dst));

				wp = 0;
				mode = 0;
				break;
			case L'e':
			case L'E':
			case L'f':
			case L'g':
			case L'G':
				tmp[wp++] = c;
				tmp[wp++] = 0;
				tag = CopyUniToStr(tmp);

					snprintf(dst, sizeof(dst), tag, va_arg(args, double));

				Free(tag);
				Add(o, CopyStrToUni(dst));

				wp = 0;
				mode = 0;
				break;
			case L'n':
			case L'p':
				tmp[wp++] = c;
				tmp[wp++] = 0;
				tag = ZeroMalloc(UniStrSize(tmp) + 32);
				UniToStr(tag, 0, tmp);

					snprintf(dst, sizeof(dst), tag, va_arg(args, void *));

				Free(tag);
				Add(o, CopyStrToUni(dst));

				wp = 0;
				mode = 0;
				break;
			case L'r':
			case L'R':
				tmp[wp++] = c;
				tmp[wp++] = 0;

				Zero(dst, sizeof(dst));
				IPToStr(dst, sizeof(dst), va_arg(args, void *));

				Add(o, CopyStrToUni(dst));

				wp = 0;
				mode = 0;
				break;

			case L's':
			case L'S':
				tmp[wp++] = c;
				tmp[wp++] = 0;

				if (ansi_mode == false)
				{
					if (c == L'S')
					{
						c = L's';
					}
					else
					{
						c = L'S';
					}
				}

				if (c == L's')
				{
					target_str = CopyStrToUni(va_arg(args, char *));
				}
				else
				{
					target_str = CopyUniStr(va_arg(args, wchar_t *));
				}

				if (target_str == NULL)
				{
					target_str = CopyUniStr(L"(null)");
				}

				padding = 0;
				left_padding = false;
				if (tmp[1] == L'-')
				{
					if (UniStrLen(tmp) >= 3)
					{
						padding = UniToInt(&tmp[2]);
					}
					left_padding = true;
				}
				else
				{
					if (UniStrLen(tmp) >= 2)
					{
						padding = UniToInt(&tmp[1]);
					}
				}

				target_str_len = UniStrWidth(target_str);

				if (padding > target_str_len)
				{
					UINT len = padding - target_str_len;
					UINT i;
					padding_str = ZeroMalloc(sizeof(wchar_t) * (len + 1));
					for (i = 0;i < len;i++)
					{
						padding_str[i] = L' ';
					}
				}
				else
				{
					padding_str = ZeroMalloc(sizeof(wchar_t));
				}

				total_len = sizeof(wchar_t) * (UniStrLen(padding_str) + UniStrLen(target_str) + 1);
				output_str = ZeroMalloc(total_len);
				output_str[0] = 0;

				if (left_padding == false)
				{
					UniStrCat(output_str, total_len, padding_str);
				}
				UniStrCat(output_str, total_len, target_str);
				if (left_padding)
				{
					UniStrCat(output_str, total_len, padding_str);
				}

				Add(o, output_str);

				Free(target_str);
				Free(padding_str);

				wp = 0;
				mode = 0;
				break;
			default:
				tmp[wp++] = c;
				break;
			}
		}
	}
	tmp[wp++] = 0;
	wp = 0;

	if (UniStrLen(tmp) >= 1)
	{
		Add(o, CopyUniStr(tmp));
	}

	total_size = sizeof(wchar_t);
	for (i = 0;i < LIST_NUM(o);i++)
	{
		wchar_t *s = LIST_DATA(o, i);
		total_size += UniStrLen(s) * sizeof(wchar_t);
	}

	ret = ZeroMalloc(total_size);
	for (i = 0;i < LIST_NUM(o);i++)
	{
		wchar_t *s = LIST_DATA(o, i);
		UniStrCat(ret, total_size, s);
		Free(s);
	}

	ReleaseList(o);

	Free(tmp);

	return ret;
}

UINT UniStrWidth(wchar_t *str)
{
	UINT i, len, ret;
	if (str == NULL)
	{
		return 0;
	}

	ret = 0;
	len = UniStrLen(str);
	for (i = 0;i < len;i++)
	{
		if (str[i] <= 255)
		{
			ret++;
		}
		else
		{
			ret += 2;
		}
	}
	return ret;
}

bool UniIsEmptyStr(wchar_t *str)
{
	return IsEmptyUniStr(str);
}
bool IsEmptyUniStr(wchar_t *str)
{
	bool ret;
	wchar_t *s;
	if (str == NULL)
	{
		return true;
	}

	s = UniCopyStr(str);

	UniTrim(s);
	if (UniStrLen(s) == 0)
	{
		ret = true;
	}
	else
	{
		ret = false;
	}

	Free(s);

	return ret;
}


UNI_TOKEN_LIST *UniNullToken()
{
	UNI_TOKEN_LIST *ret = ZeroMalloc(sizeof(UNI_TOKEN_LIST));
	ret->Token = ZeroMalloc(0);

	return ret;
}

wchar_t *UniCopyStr(wchar_t *str)
{
	return CopyUniStr(str);
}

UNI_TOKEN_LIST *UniParseCmdLine(wchar_t *str)
{
	UNI_TOKEN_LIST *t;
	LIST *o;
	UINT i, len, wp, mode;
	wchar_t c;
	wchar_t *tmp;
	bool ignore_space = false;
	if (str == NULL)
	{
		return UniNullToken();
	}

	o = NewListFast(NULL);
	tmp = Malloc(UniStrSize(str) + 32);

	wp = 0;
	mode = 0;

	len = UniStrLen(str);
	for (i = 0;i < len;i++)
	{
		c = str[i];

		switch (mode)
		{
		case 0:
			if (c == L' ' || c == L'\t')
			{
			}
			else
			{
				if (c == L'\"')
				{
					if (str[i + 1] == L'\"')
					{
						// "" is an escaped quote
						tmp[wp++] = L'\"';
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
			if (ignore_space == false && (c == L' ' || c == L'\t'))
			{
				tmp[wp++] = 0;
				wp = 0;

				Insert(o, UniCopyStr(tmp));
				mode = 0;
			}
			else
			{
				if (c == L'\"')
				{
					if (str[i + 1] == L'\"')
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
		Insert(o, UniCopyStr(tmp));
	}

	Free(tmp);

	t = ZeroMalloc(sizeof(UNI_TOKEN_LIST));
	t->NumTokens = LIST_NUM(o);
	t->Token = ZeroMalloc(sizeof(wchar_t *) * t->NumTokens);
	for (i = 0;i < t->NumTokens;i++)
	{
		t->Token[i] = LIST_DATA(o, i);
	}

	ReleaseList(o);

	return t;
}

UINT UtfToUni(wchar_t *unistr, UINT size, char *utfstr)
{
	wchar_t *tmp;
	if (unistr == NULL || utfstr == NULL)
	{
		UniStrCpy(unistr, size, L"");
		return 0;
	}

	tmp = CopyUtfToUni(utfstr);

	UniStrCpy(unistr, size, tmp);

	Free(tmp);

	return UniStrLen(unistr);
}

wchar_t *CopyUtfToUni(char *utfstr)
{
	UINT size;
	wchar_t *ret;
	UINT utfstr_len;
	if (utfstr == NULL)
	{
		return NULL;
	}

	utfstr_len = StrLen(utfstr);

	size = CalcUtf8ToUni((BYTE *)utfstr, utfstr_len);
	ret = ZeroMalloc(size + sizeof(wchar_t));
	Utf8ToUni(ret, size, (BYTE *)utfstr, utfstr_len);

	return ret;
}

char *CopyUniToStr(wchar_t *unistr)
{
	char *str;
	UINT str_size;
	if (unistr == NULL)
	{
		return NULL;
	}

	str_size = CalcUniToStr(unistr);
	if (str_size == 0)
	{
		return CopyStr("");
	}
	str = Malloc(str_size);
	UniToStr(str, str_size, unistr);

	return str;
}

wchar_t *CopyStrToUni(char *str)
{
	wchar_t *uni;
	UINT uni_size;
	if (str == NULL)
	{
		return NULL;
	}

	uni_size = CalcStrToUni(str);
	if (uni_size == 0)
	{
		return CopyUniStr(L"");
	}
	uni = Malloc(uni_size);
	StrToUni(uni, uni_size, str);

	return uni;
}

char *CopyUniToUtf(wchar_t *unistr)
{
	UINT size;
	char *ret;
	if (unistr == NULL)
	{
		return NULL;
	}

	size = CalcUniToUtf8(unistr);
	ret = ZeroMalloc(size + sizeof(char));

	UniToUtf8((char *)ret, size, unistr);

	return ret;
}

wchar_t *CopyUniStr(wchar_t *str)
{
	UINT len;
	wchar_t *dst;
	if (str == NULL)
	{
		return NULL;
	}

	len = UniStrLen(str);
	dst = Malloc((len + 1) * sizeof(wchar_t));
	UniStrCpy(dst, 0, str);

	return dst;
}

bool IsSafeUniStr(wchar_t *str)
{
	UINT i, len;
	if (str == NULL)
	{
		return false;
	}

	len = UniStrLen(str);
	for (i = 0;i < len;i++)
	{
		if (IsSafeUniChar(str[i]) == false)
		{
			return false;
		}
	}
	if (str[0] == L' ')
	{
		return false;
	}
	if (len != 0)
	{
		if (str[len - 1] == L' ')
		{
			return false;
		}
	}
	return true;
}

bool IsSafeUniChar(wchar_t c)
{
	UINT i, len;
	wchar_t *check_str =
		L"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
		L"abcdefghijklmnopqrstuvwxyz"
		L"0123456789"
		L" ()-_#%&.";

	len = UniStrLen(check_str);
	for (i = 0;i < len;i++)
	{
		if (c == check_str[i])
		{
			return true;
		}
	}
	return false;
}

// The ANSI conversions run on MultiByteToWideChar and WideCharToMultiByte in the code page of
// the C runtime's LC_CTYPE locale (InitMayaqua sets it with setlocale(LC_ALL, "")), with the
// flags the UCRT's mbstowcs() and wcstombs() use, so they convert as those did: a string that
// does not convert exactly gives an empty string (a byte sequence that is invalid in the code
// page; a character without an equivalent, where a best-fit mapping counts as one).

// Code page standing for the C locale, in which the CRT maps the bytes 1:1 to U+0000-U+00FF and
// has no best fit: ISO 8859-1 with WC_NO_BEST_FIT_CHARS. No locale that setlocale(LC_ALL, "")
// selects uses this code page.
#define	ANSI_C_LOCALE_CODE_PAGE		28591

// Code page of the ANSI conversions. *c_locale (optional) receives whether the C locale is
// active, the same test the UCRT's own mbstowcs() and wcstombs() make: only that locale has no
// best fit, while a real ".28591" locale has the best fit of code page 28591.
static UINT AnsiCodePage(bool *c_locale)
{
	bool c = (___lc_locale_name_func()[LC_CTYPE] == NULL);

	if (c_locale != NULL)
	{
		*c_locale = c;
	}

	if (c)
	{
		return ANSI_C_LOCALE_CODE_PAGE;
	}

	return ___lc_codepage_func();
}

// Convert the ANSI string str into dst (NULL: only count), dst_len wchar_t at most. Returns the
// number of wchar_t with the terminating NUL, or 0 when str does not convert
static UINT ConvertAnsiToUni(wchar_t *dst, UINT dst_len, char *str)
{
	UINT cp = AnsiCodePage(NULL);
	// UTF-8 takes no flag but MB_ERR_INVALID_CHARS
	DWORD flags = (cp == CP_UTF8) ? MB_ERR_INVALID_CHARS : (MB_PRECOMPOSED | MB_ERR_INVALID_CHARS);
	int ret = MultiByteToWideChar(cp, flags, str, -1, dst, (int)dst_len);

	return (ret > 0) ? (UINT)ret : 0;
}

// Convert the wide string s into dst (NULL: only count), dst_size bytes at most. Returns the
// number of bytes with the terminating NUL, or 0 when s does not convert
static UINT ConvertUniToAnsi(char *dst, UINT dst_size, wchar_t *s)
{
	bool c_locale;
	UINT cp = AnsiCodePage(&c_locale);
	BOOL used_default = FALSE;
	int ret;

	if (cp == CP_UTF8)
	{
		// UTF-8 has no default character; an unpaired surrogate does not convert
		ret = WideCharToMultiByte(cp, WC_ERR_INVALID_CHARS, s, -1, dst, (int)dst_size, NULL, NULL);
	}
	else
	{
		ret = WideCharToMultiByte(cp, c_locale ? WC_NO_BEST_FIT_CHARS : 0, s, -1, dst, (int)dst_size, NULL, &used_default);
	}

	return (ret > 0 && used_default == FALSE) ? (UINT)ret : 0;
}

UINT UniToStr(char *str, UINT size, wchar_t *s)
{
	UINT ret;
	char *tmp;
	UINT new_size;
	if (s == NULL || str == NULL)
	{
		return 0;
	}

	new_size = CalcUniToStr(s);
	if (new_size == 0)
	{
		if (size >= 1)
		{
			StrCpy(str, 0, "");
		}
		return 0;
	}
	tmp = Malloc(new_size);
	tmp[0] = 0;
	ConvertUniToAnsi(tmp, new_size, s);
	tmp[new_size - 1] = 0;
	ret = StrCpy(str, size, tmp);
	Free(tmp);

	return ret;
}

UINT CalcUniToStr(wchar_t *s)
{
	if (s == NULL)
	{
		return 0;
	}

	return ConvertUniToAnsi(NULL, 0, s);
}

UINT StrToUni(wchar_t *s, UINT size, char *str)
{
	UINT ret;
	wchar_t *tmp;
	UINT new_size;
	if (s == NULL || str == NULL)
	{
		return 0;
	}

	new_size = CalcStrToUni(str);
	if (new_size == 0)
	{
		if (size >= 2)
		{
			UniStrCpy(s, 0, L"");
		}
		return 0;
	}
	tmp = Malloc(new_size);
	tmp[0] = 0;
	ConvertAnsiToUni(tmp, new_size / (UINT)sizeof(wchar_t), str);
	tmp[(new_size - 1) / sizeof(wchar_t)] = 0;
	ret = UniStrCpy(s, size, tmp);
	Free(tmp);

	return ret;
}

UINT CalcStrToUni(char *str)
{
	if (str == NULL)
	{
		return 0;
	}

	return ConvertAnsiToUni(NULL, 0, str) * (UINT)sizeof(wchar_t);
}

// Mayaqua's UTF-8 differs from the standard in two ways, which stay. The encoder writes every
// UTF-16 code unit on its own, so a surrogate becomes a 3-byte sequence (CESU-8). The decoder
// takes sequences of at most 3 bytes without validation: GetUtf8Type gives the length from the
// lead byte alone, a sequence cut off by the end of the input ends the decoding, and the payload
// bits are used as they are. Everything else is plain UTF-8 and runs on WideCharToMultiByte and
// MultiByteToWideChar (CP_UTF8). Only surrogates, input that is not well-formed, and 4-byte
// sequences (which MultiByteToWideChar decodes to surrogate pairs) take the bit-level path, so
// the results do not change.

// Longest input of one WideCharToMultiByte or MultiByteToWideChar call: they count in int
#define	UTF8_NATIVE_MAX		((UINT)0x7fffffff)

static bool IsSurrogateUnit(wchar_t c)
{
	return (c >= 0xd800 && c <= 0xdfff);
}

// Encode the len code units of s into u (NULL: only count), which has room for u_size bytes,
// all of the encoding. Returns the number of bytes
static UINT UniToUtf8Units(BYTE *u, UINT u_size, wchar_t *s, UINT len)
{
	UINT i = 0, wp = 0;

	while (i < len)
	{
		wchar_t c = s[i];
		UINT run;

		if (IsSurrogateUnit(c))
		{
			if (u != NULL)
			{
				u[wp] = (BYTE)(0xe0 | (c >> 12));
				u[wp + 1] = (BYTE)(0x80 | ((c >> 6) & 0x3f));
				u[wp + 2] = (BYTE)(0x80 | (c & 0x3f));
			}
			wp += 3;
			i++;
			continue;
		}

		// A run without surrogates: WideCharToMultiByte writes the same bytes as one code unit
		// at a time
		run = 1;
		while (i + run < len && run < UTF8_NATIVE_MAX && IsSurrogateUnit(s[i + run]) == false)
		{
			run++;
		}

		if (u != NULL)
		{
			wp += (UINT)WideCharToMultiByte(CP_UTF8, 0, &s[i], (int)run, (char *)&u[wp], (int)MIN(u_size - wp, UTF8_NATIVE_MAX), NULL, NULL);
		}
		else
		{
			wp += (UINT)WideCharToMultiByte(CP_UTF8, 0, &s[i], (int)run, NULL, 0, NULL, NULL);
		}
		i += run;
	}

	return wp;
}

// Number of code units MultiByteToWideChar decodes the size bytes of u to, or 0 when they take
// the bit-level decoder: they are not well-formed UTF-8, or hold a 4-byte sequence (a byte of
// 0xF0 or above)
static UINT Utf8NativeLen(BYTE *u, UINT size)
{
	UINT i;
	int ret;

	if (size == 0 || size > UTF8_NATIVE_MAX)
	{
		return 0;
	}

	for (i = 0;i < size;i++)
	{
		if (u[i] >= 0xf0)
		{
			return 0;
		}
	}

	ret = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, (char *)u, (int)size, NULL, 0);

	return (ret > 0) ? (UINT)ret : 0;
}

// The bit-level decoder: decode the size bytes of u into s (NULL: only count), at most room code
// units. Returns the number of code units
static UINT Utf8ToUniBits(wchar_t *s, UINT room, BYTE *u, UINT size)
{
	UINT i = 0, num = 0;

	while (num < room)
	{
		UINT type = GetUtf8Type(u, size, i);
		if (type == 0)
		{
			break;
		}

		if (s != NULL)
		{
			switch (type)
			{
			case 1:
				s[num] = (wchar_t)u[i];
				break;
			case 2:
				s[num] = (wchar_t)(((u[i] & 0x1f) << 6) | (u[i + 1] & 0x3f));
				break;
			default:
				s[num] = (wchar_t)(((u[i] & 0x0f) << 12) | ((u[i + 1] & 0x3f) << 6) | (u[i + 2] & 0x3f));
				break;
			}
		}

		i += type;
		num++;
	}

	return num;
}

UINT Utf8ToUni(wchar_t *s, UINT size, BYTE *u, UINT u_size)
{
	UINT room, len, num;
	if (s == NULL || u == NULL)
	{
		return 0;
	}
	if (size == 0)
	{
		size = 0x3fffffff;
	}
	if (u_size == 0)
	{
		u_size = StrLen((char *)u);
	}

	// Code units that fit before the terminating NUL
	room = (UINT)(size / sizeof(wchar_t) - 1);

	len = Utf8NativeLen(u, u_size);
	if (len == 0)
	{
		num = Utf8ToUniBits(s, room, u, u_size);
	}
	else if (len <= room)
	{
		num = (UINT)MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, (char *)u, (int)u_size, s, (int)len);
	}
	else
	{
		// Too small: the first room code units
		wchar_t *tmp = Malloc(len * sizeof(wchar_t));
		MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, (char *)u, (int)u_size, tmp, (int)len);
		Copy(s, tmp, room * sizeof(wchar_t));
		Free(tmp);
		num = room;
	}

	if (num < (size / sizeof(wchar_t)))
	{
		s[num] = 0;
	}

	return num;
}

UINT CalcUtf8ToUni(BYTE *u, UINT u_size)
{
	if (u == NULL)
	{
		return 0;
	}
	if (u_size == 0)
	{
		u_size = StrLen((char *)u);
	}

	return (Utf8Len(u, u_size) + 1) * sizeof(wchar_t);
}

UINT Utf8Len(BYTE *u, UINT size)
{
	UINT num;
	if (u == NULL)
	{
		return 0;
	}
	if (size == 0)
	{
		size = StrLen((char *)u);
	}

	num = Utf8NativeLen(u, size);
	if (num == 0)
	{
		num = Utf8ToUniBits(NULL, INFINITE, u, size);
	}

	return num;
}

UINT UniToUtf8(BYTE *u, UINT size, wchar_t *s)
{
	UINT len, need, wp;
	if (u == NULL || s == NULL)
	{
		return 0;
	}
	if (size == 0)
	{
		size = 0x3fffffff;
	}

	len = UniStrLen(s);
	need = UniToUtf8Units(NULL, 0, s, len);
	if (need <= size)
	{
		wp = UniToUtf8Units(u, need, s, len);
	}
	else
	{
		// Too small: the first size bytes, which can end inside a sequence
		BYTE *tmp = Malloc(need);
		UniToUtf8Units(tmp, need, s, len);
		Copy(u, tmp, size);
		Free(tmp);
		wp = size;
	}

	if (wp < size)
	{
		u[wp] = 0;
	}

	return wp;
}

UINT CalcUniToUtf8(wchar_t *s)
{
	if (s == NULL)
	{
		return 0;
	}

	return UniToUtf8Units(NULL, 0, s, UniStrLen(s));
}

UINT GetUtf8Type(BYTE *s, UINT size, UINT offset)
{
	if (s == NULL)
	{
		return 0;
	}
	if ((offset + 1) > size)
	{
		return 0;
	}
	if ((s[offset] & 0x80) == 0)
	{
		return 1;
	}
	if ((s[offset] & 0x20) == 0)
	{
		if ((offset + 2) > size)
		{
			return 0;
		}
		return 2;
	}
	if ((offset + 3) > size)
	{
		return 0;
	}
	return 3;
}

UINT GetUniType(wchar_t c)
{
	BYTE c1, c2;

	if (IsBigEndian())
	{
		if (sizeof(wchar_t) == 2)
		{
			c1 = ((BYTE *)&c)[0];
			c2 = ((BYTE *)&c)[1];
		}
		else
		{
			c1 = ((BYTE *)&c)[2];
			c2 = ((BYTE *)&c)[3];
		}
	}
	else
	{
		c1 = ((BYTE *)&c)[1];
		c2 = ((BYTE *)&c)[0];
	}

	if (c1 == 0)
	{
		if (c2 <= 0x7f)
		{
			return 1;
		}
		else
		{
			return 2;
		}
	}
	if ((c1 & 0xf8) == 0)
	{
		return 2;
	}
	return 3;
}

UINT UniReplaceStrEx(wchar_t *dst, UINT size, wchar_t *string, wchar_t *old_keyword, wchar_t *new_keyword, bool case_sensitive)
{
	UINT i, j, num, len_string, len_old, len_new, len_ret, wp;
	wchar_t *ret;
	if (string == NULL || old_keyword == NULL || new_keyword == NULL)
	{
		return 0;
	}

	len_string = UniStrLen(string);
	len_old = UniStrLen(old_keyword);
	len_new = UniStrLen(new_keyword);

	len_ret = UniCalcReplaceStrEx(string, old_keyword, new_keyword, case_sensitive);
	ret = Malloc((len_ret + 1) * sizeof(wchar_t));
	ret[len_ret] = 0;

	i = j = num = wp = 0;
	while (true)
	{
		i = UniSearchStrEx(string, old_keyword, i, case_sensitive);
		if (i == INFINITE)
		{
			Copy(&ret[wp], &string[j], (len_string - j) * sizeof(wchar_t));
			wp += len_string - j;
			break;
		}
		num++;
		Copy(&ret[wp], &string[j], (i - j) * sizeof(wchar_t));
		wp += i - j;
		Copy(&ret[wp], new_keyword, len_new * sizeof(wchar_t));
		wp += len_new;
		i += len_old;
		j = i;
	}

	UniStrCpy(dst, size, ret);

	Free(ret);

	return num;
}

UINT UniCalcReplaceStrEx(wchar_t *string, wchar_t *old_keyword, wchar_t *new_keyword, bool case_sensitive)
{
	UINT i, num;
	UINT len_string, len_old, len_new;
	if (string == NULL || old_keyword == NULL || new_keyword == NULL)
	{
		return 0;
	}

	len_string = UniStrLen(string);
	len_old = UniStrLen(old_keyword);
	len_new = UniStrLen(new_keyword);

	if (len_old == len_new)
	{
		return len_string;
	}

	num = 0;
	i = 0;
	while (true)
	{
		i = UniSearchStrEx(string, old_keyword, i, case_sensitive);
		if (i == INFINITE)
		{
			break;
		}
		i += len_old;
		num++;
	}

	return len_string + len_new * num - len_old * num;
}

UINT UniSearchStr(wchar_t *string, wchar_t *keyword, UINT start)
{
	return UniSearchStrEx(string, keyword, start, true);
}

// Returns INFINITE if not found
UINT UniSearchStrEx(wchar_t *string, wchar_t *keyword, UINT start, bool case_sensitive)
{
	UINT len_string, len_keyword;
	UINT i;
	wchar_t *cmp_string, *cmp_keyword;
	bool found;
	if (string == NULL || keyword == NULL)
	{
		return INFINITE;
	}

	len_string = UniStrLen(string);
	if (len_string <= start)
	{
		return INFINITE;
	}

	len_keyword = UniStrLen(keyword);
	if (len_keyword == 0)
	{
		return INFINITE;
	}

	if (len_string < len_keyword)
	{
		return INFINITE;
	}

	if (len_string == len_keyword)
	{
		if (case_sensitive)
		{
			if (UniStrCmp(string, keyword) == 0)
			{
				return 0;
			}
			else
			{
				return INFINITE;
			}
		}
		else
		{
			if (UniStrCmpi(string, keyword) == 0)
			{
				return 0;
			}
			else
			{
				return INFINITE;
			}
		}
	}

	if (case_sensitive)
	{
		cmp_string = string;
		cmp_keyword = keyword;
	}
	else
	{
		cmp_string = Malloc((len_string + 1) * sizeof(wchar_t));
		UniStrCpy(cmp_string, (len_string + 1) * sizeof(wchar_t), string);
		cmp_keyword = Malloc((len_keyword + 1) * sizeof(wchar_t));
		UniStrCpy(cmp_keyword, (len_keyword + 1) * sizeof(wchar_t), keyword);
		UniStrUpper(cmp_string);
		UniStrUpper(cmp_keyword);
	}

	found = false;
	for (i = start;i < (len_string - len_keyword + 1);i++)
	{
		if (!wcsncmp(&cmp_string[i], cmp_keyword, len_keyword))
		{
			found = true;
			break;
		}
	}

	if (case_sensitive == false)
	{
		Free(cmp_keyword);
		Free(cmp_string);
	}

	if (found == false)
	{
		return INFINITE;
	}
	return i;
}

void UniFreeToken(UNI_TOKEN_LIST *tokens)
{
	UINT i;
	if (tokens == NULL)
	{
		return;
	}
	for (i = 0;i < tokens->NumTokens;i++)
	{
		Free(tokens->Token[i]);
	}
	Free(tokens->Token);
	Free(tokens);
}

static wchar_t *UniDefaultTokenSplitChars()
{
	return L" ,\t\r\n";
}

static bool UniIsCharInStr(wchar_t *str, wchar_t c)
{
	UINT i, len;
	if (str == NULL)
	{
		return false;
	}

	len = UniStrLen(str);
	for (i = 0;i < len;i++)
	{
		if (str[i] == c)
		{
			return true;
		}
	}

	return false;
}

static UNI_TOKEN_LIST *UniParseTokenWithoutNullStr(wchar_t *str, wchar_t *split_chars)
{
	LIST *o;
	UINT i, len;
	bool last_flag;
	BUF *b;
	wchar_t zero = 0;
	UNI_TOKEN_LIST *t;
	if (str == NULL)
	{
		return UniNullToken();
	}
	if (split_chars == NULL)
	{
		split_chars = UniDefaultTokenSplitChars();
	}

	b = NewBuf();
	o = NewListFast(NULL);

	len = UniStrLen(str);
	last_flag = false;

	for (i = 0;i < (len + 1);i++)
	{
		wchar_t c = str[i];
		bool flag = UniIsCharInStr(split_chars, c);

		if (c == L'\0')
		{
			flag = true;
		}

		if (flag == false)
		{
			WriteBuf(b, &c, sizeof(wchar_t));
		}
		else
		{
			if (last_flag == false)
			{
				WriteBuf(b, &zero, sizeof(wchar_t));

				if ((UniStrLen((wchar_t *)b->Buf)) != 0)
				{
					Insert(o, UniCopyStr((wchar_t *)b->Buf));
				}
				ClearBuf(b);
			}
		}

		last_flag = flag;
	}

	t = ZeroMalloc(sizeof(UNI_TOKEN_LIST));
	t->NumTokens = LIST_NUM(o);
	t->Token = ZeroMalloc(sizeof(wchar_t *) * t->NumTokens);

	for (i = 0;i < t->NumTokens;i++)
	{
		t->Token[i] = LIST_DATA(o, i);
	}

	ReleaseList(o);
	FreeBuf(b);

	return t;
}

UNI_TOKEN_LIST *UniParseToken(wchar_t *src, wchar_t *separator)
{
	return UniParseTokenWithoutNullStr(src, separator);
}

bool UniGetLineWin32(wchar_t *str, UINT size)
{
	bool ret = false;

	ret = Win32InputW(str, size);

	return ret;
}

void UniTrimCrlf(wchar_t *str)
{
	UINT len;
	if (str == NULL)
	{
		return;
	}
	len = UniStrLen(str);
	if (len == 0)
	{
		return;
	}

	if (str[len - 1] == L'\n')
	{
		if (len >= 2 && str[len - 2] == L'\r')
		{
			str[len - 2] = 0;
		}
		str[len - 1] = 0;
	}
	else if(str[len - 1] == L'\r')
	{
		str[len - 1] = 0;
	}
}

void UniTrim(wchar_t *str)
{
	if (str == NULL)
	{
		return;
	}

	UniTrimLeft(str);
	UniTrimRight(str);
}

void UniTrimRight(wchar_t *str)
{
	wchar_t *buf, *tmp;
	UINT len, i, wp, wp2;
	bool flag;
	if (str == NULL)
	{
		return;
	}
	len = UniStrLen(str);
	if (len == 0)
	{
		return;
	}
	if (str[len - 1] != L' ' && str[len - 1] != L'\t')
	{
		return;
	}

	buf = Malloc((len + 1) * sizeof(wchar_t));
	tmp = Malloc((len + 1) * sizeof(wchar_t));
	flag = false;
	wp = wp2 = 0;
	for (i = 0;i < len;i++)
	{
		if (str[i] != L' ' && str[i] != L'\t')
		{
			Copy(&buf[wp], tmp, wp2 * sizeof(wchar_t));
			wp += wp2;
			wp2 = 0;
			buf[wp++] = str[i];
		}
		else
		{
			tmp[wp2++] = str[i];
		}
	}
	buf[wp] = 0;
	UniStrCpy(str, 0, buf);
	Free(buf);
	Free(tmp);
}

void UniTrimLeft(wchar_t *str)
{
	wchar_t *buf;
	UINT len, i, wp;
	bool flag;
	if (str == NULL)
	{
		return;
	}
	len = UniStrLen(str);
	if (len == 0)
	{
		return;
	}
	if (str[0] != L' ' && str[0] != L'\t')
	{
		return;
	}

	buf = Malloc((len + 1) * sizeof(wchar_t));
	flag = false;
	wp = 0;
	for (i = 0;i < len;i++)
	{
		if (str[i] != L' ' && str[i] != L'\t')
		{
			flag = true;
		}
		if (flag)
		{
			buf[wp++] = str[i];
		}
	}
	buf[wp] = 0;
	UniStrCpy(str, 0, buf);
	Free(buf);
}

void UniToStru(wchar_t *str, UINT i)
{
	UniFormat(str, 0, L"%u", i);
}

UINT UniToInt(wchar_t *str)
{
	char tmp[128];
	if (str == NULL)
	{
		return 0;
	}

	// A longer string is read up to its first sizeof(tmp) - 1 characters
	UniToStrForSingleChars(tmp, sizeof(tmp), str);

	return ToInti(tmp);
}

void UniToStrForSingleChars(char *dst, UINT dst_size, wchar_t *src)
{
	UINT i, len;
	if (dst == NULL || src == NULL || dst_size == 0)
	{
		return;
	}

	// At most dst_size - 1 characters and the terminator
	len = UniStrLen(src);
	if (len > dst_size - 1)
	{
		len = dst_size - 1;
	}

	for (i = 0;i < len;i++)
	{
		wchar_t s = src[i];

		if (s <= 0xff)
		{
			dst[i] = (char)s;
		}
		else
		{
			dst[i] = ' ';
		}
	}

	dst[len] = 0;
}

UNI_TOKEN_LIST *UniGetLines(wchar_t *str)
{
	UINT i, len;
	BUF *b = NULL;
	LIST *o;
	UNI_TOKEN_LIST *ret;
	if (str == NULL)
	{
		return UniNullToken();
	}

	o = NewListFast(NULL);

	len = UniStrLen(str);

	b = NewBuf();

	for (i = 0;i < len;i++)
	{
		wchar_t c = str[i];
		bool f = false;

		if (c == L'\r')
		{
			if (str[i + 1] == L'\n')
			{
				i++;
			}
			f = true;
		}
		else if (c == L'\n')
		{
			f = true;
		}

		if (f)
		{
			wchar_t zero = 0;
			wchar_t *s;
			WriteBuf(b, &zero, sizeof(wchar_t));

			s = (wchar_t *)b->Buf;

			Add(o, UniCopyStr(s));

			ClearBuf(b);
		}
		else
		{
			WriteBuf(b, &c, sizeof(wchar_t));
		}
	}

	if (true)
	{
		wchar_t zero = 0;
		wchar_t *s;
		WriteBuf(b, &zero, sizeof(wchar_t));

		s = (wchar_t *)b->Buf;

		Add(o, UniCopyStr(s));

		ClearBuf(b);
	}

	FreeBuf(b);

	ret = UniListToTokenList(o);

	UniFreeStrList(o);

	return ret;
}

void UniPrintStr(wchar_t *string)
{
	if (string == NULL)
	{
		return;
	}

	Win32PrintW(string);
}

static void UniPrintArgs(wchar_t *fmt, va_list args)
{
	wchar_t *str;
	if (fmt == NULL)
	{
		return;
	}

	str = InternalFormatArgs(fmt, args, false);

	UniPrintStr(str);

	Free(str);
}

void UniPrint(wchar_t *fmt, ...)
{
	va_list args;
	if (fmt == NULL)
	{
		return;
	}

	va_start(args, fmt);
	UniPrintArgs(fmt, args);
	va_end(args);
}

void UniFormatArgs(wchar_t *buf, UINT size, wchar_t *fmt, va_list args)
{
	wchar_t *ret;
	if (buf == NULL || fmt == NULL)
	{
		return;
	}
	if (size == 1)
	{
		return;
	}

	KS_INC(KS_FORMAT_COUNT);

	ret = InternalFormatArgs(fmt, args, false);

	UniStrCpy(buf, size, ret);

	Free(ret);
}

void UniFormat(wchar_t *buf, UINT size, wchar_t *fmt, ...)
{
	va_list args;
	if (buf == NULL || fmt == NULL)
	{
		return;
	}

	va_start(args, fmt);
	UniFormatArgs(buf, size, fmt, args);
	va_end(args);
}

int UniSoftStrCmp(wchar_t *str1, wchar_t *str2)
{
	UINT ret;
	wchar_t *tmp1, *tmp2;
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

	tmp1 = CopyUniStr(str1);
	tmp2 = CopyUniStr(str2);

	UniTrim(tmp1);
	UniTrim(tmp2);

	ret = UniStrCmpi(tmp1, tmp2);

	Free(tmp1);
	Free(tmp2);

	return ret;
}

int UniStrCmpi(wchar_t *str1, wchar_t *str2)
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
		wchar_t c1, c2;
		c1 = UniToUpper(str1[i]);
		c2 = UniToUpper(str2[i]);
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

int UniStrCmp(wchar_t *str1, wchar_t *str2)
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

	return wcscmp(str1, str2);
}

void UniStrLower(wchar_t *str)
{
	UINT i, len;
	if (str == NULL)
	{
		return;
	}

	len = UniStrLen(str);
	for (i = 0;i < len;i++)
	{
		str[i] = UniToLower(str[i]);
	}
}

void UniStrUpper(wchar_t *str)
{
	UINT i, len;
	if (str == NULL)
	{
		return;
	}

	len = UniStrLen(str);
	for (i = 0;i < len;i++)
	{
		str[i] = UniToUpper(str[i]);
	}
}

wchar_t UniToLower(wchar_t c)
{
	if (c >= L'A' && c <= L'Z')
	{
		c += L'a' - L'A';
	}

	return c;
}

wchar_t UniToUpper(wchar_t c)
{
	if (c >= L'a' && c <= L'z')
	{
		c -= L'a' - L'A';
	}

	return c;
}

UINT UniStrCat(wchar_t *dst, UINT size, wchar_t *src)
{
	UINT len1, len2, len_test;
	if (dst == NULL || src == NULL)
	{
		return 0;
	}
	if (size != 0 && size < sizeof(wchar_t))
	{
		return 0;
	}
	if (size == sizeof(wchar_t))
	{
		wcscpy(dst, L"");
		return 0;
	}
	if (size == 0)
	{
		size = 0x3fffffff;
	}

	len1 = UniStrLen(dst);
	len2 = UniStrLen(src);
	len_test = len1 + len2 + 1;
	if (len_test > (size / sizeof(wchar_t)))
	{
		if (len2 <= (len_test - (size / sizeof(wchar_t))))
		{
			return 0;
		}
		len2 -= len_test - (size / sizeof(wchar_t));
	}
	Copy(&dst[len1], src, len2 * sizeof(wchar_t));
	dst[len1 + len2] = 0;

	return len1 + len2;
}

UINT UniStrCpy(wchar_t *dst, UINT size, wchar_t *src)
{
	UINT len;
	if (dst == NULL || src == NULL)
	{
		if (src == NULL && dst != NULL)
		{
			if (size >= sizeof(wchar_t))
			{
				dst[0] = L'\0';
			}
		}
		return 0;
	}
	if (dst == src)
	{
		return UniStrLen(src);
	}
	if (size != 0 && size < sizeof(wchar_t))
	{
		return 0;
	}
	if (size == sizeof(wchar_t))
	{
		wcscpy(dst, L"");
		return 0;
	}
	if (size == 0)
	{
		size = 0x3fffffff;
	}

	len = UniStrLen(src);
	if (len <= (size / sizeof(wchar_t) - 1))
	{
		Copy(dst, src, (len + 1) * sizeof(wchar_t));
	}
	else
	{
		len = size / sizeof(wchar_t) - 1;
		Copy(dst, src, len * sizeof(wchar_t));
		dst[len] = 0;
	}

	return len;
}

UINT UniStrSize(wchar_t *str)
{
	if (str == NULL)
	{
		return 0;
	}

	return (UniStrLen(str) + 1) * sizeof(wchar_t);
}

UINT UniStrLen(wchar_t *str)
{
	UINT i;
	if (str == NULL)
	{
		return 0;
	}

	i = 0;
	while (true)
	{
		if (str[i] == 0)
		{
			break;
		}
		i++;
	}

	return i;
}

