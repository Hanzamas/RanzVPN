// Internat.c
// String conversion library for internationalization

#include "Internat.h"

#include "Mayaqua.h"
#include "Memory.h"
#include "Object.h"
#include "Str.h"
#include "Tracking.h"
#include "Win32.h"

#include <locale.h>
#include <wchar.h>

bool UniIsCharInStr(const wchar_t *str, wchar_t c) {
	if (str == NULL)
		return false;

	// wcschr also finds the terminator, which is not a character of the string
	return c != L'\0' && wcschr(str, c) != NULL;
}

static UNI_TOKEN_LIST *UniListToTokenList(LIST *o) {
	if (o == NULL)
		return NULL;

	UNI_TOKEN_LIST *t = ZeroMalloc(sizeof(UNI_TOKEN_LIST));
	t->NumTokens = LIST_NUM(o);
	t->Token = ZeroMalloc(sizeof(wchar_t *) * t->NumTokens);
	for (UINT i = 0; i < LIST_NUM(o); i++)
		t->Token[i] = CopyUniStr(LIST_DATA(o, i));

	return t;
}

void UniFreeStrList(LIST *o) {
	FreeListItems(o);
}

wchar_t *UniNormalizeCrlf(const wchar_t *str) {
	if (str == NULL)
		return NULL;

	UINT len = UniStrLen(str);
	UINT ret_size = sizeof(wchar_t) * (len + 32) * 2;
	wchar_t *ret = Malloc(ret_size);

	UINT wp = 0;

	for (UINT i = 0; i < len; i++) {
		wchar_t c = str[i];

		switch (c) {
		case L'\r':
			if (str[i + 1] == L'\n')
				i++;
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

bool UniEndWith(const wchar_t *str, const wchar_t *key) {
	if (str == NULL || key == NULL)
		return false;

	UINT str_len = UniStrLen(str);
	UINT key_len = UniStrLen(key);
	if (str_len < key_len)
		return false;

	if (UniStrCmpi(str + (str_len - key_len), key) == 0)
		return true;
	else
		return false;
}

bool UniStartWith(const wchar_t *str, const wchar_t *key) {
	if (str == NULL || key == NULL)
		return false;

	// An empty str or key never matches
	if (key[0] == L'\0')
		return false;

	// Compares in place with the ASCII-only fold of UniStrCmpi, and stops at the end of str
	for (UINT i = 0; key[i] != L'\0'; i++)
		if (str[i] == L'\0' || UniToUpper(str[i]) != UniToUpper(key[i]))
			return false;

	return true;
}

void UniToStr3(wchar_t *str, UINT size, UINT64 value) {
	char tmp[MAX_SIZE];
	if (str == NULL)
		return;

	ToStr3(tmp, sizeof(tmp), value);

	StrToUni(str, size, tmp);
}

UINT UniStrWidth(const wchar_t *str) {
	if (str == NULL)
		return 0;

	UINT ret = 0;
	UINT len = UniStrLen(str);
	for (UINT i = 0; i < len; i++)
		if (str[i] <= 255)
			ret++;
		else
			ret += 2;
	return ret;
}

bool UniIsEmptyStr(const wchar_t *str) {
	if (str == NULL)
		return true;

	// Empty when nothing but blanks (the characters UniTrim removes) precedes the terminator
	UINT i = 0;
	while (str[i] == L' ' || str[i] == L'\t')
		i++;

	return str[i] == L'\0';
}


UNI_TOKEN_LIST *UniNullToken() {
	UNI_TOKEN_LIST *ret = ZeroMalloc(sizeof(UNI_TOKEN_LIST));
	ret->Token = ZeroMalloc(0);

	return ret;
}

UNI_TOKEN_LIST *UniParseCmdLine(const wchar_t *str) {
	wchar_t c;
	bool ignore_space = false;
	if (str == NULL)
		return UniNullToken();

	LIST *o = NewListFast(NULL);
	wchar_t *tmp = Malloc(UniStrSize(str) + 32);

	UINT wp = 0;
	UINT mode = 0;

	UINT len = UniStrLen(str);
	for (UINT i = 0; i < len; i++) {
		c = str[i];

		switch (mode) {
		case 0:
			if (c == L' ' || c == L'\t') {
			} else {
				if (c == L'\"') {
					if (str[i + 1] == L'\"') {
						// "" is an escaped quote
						tmp[wp++] = L'\"';
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
			if (ignore_space == false && (c == L' ' || c == L'\t')) {
				tmp[wp++] = 0;
				wp = 0;

				Insert(o, CopyUniStr(tmp));
				mode = 0;
			} else if (c == L'\"') {
				if (str[i + 1] == L'\"') {
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
		Insert(o, CopyUniStr(tmp));
	}

	Free(tmp);

	UNI_TOKEN_LIST *t = ZeroMalloc(sizeof(UNI_TOKEN_LIST));
	t->NumTokens = LIST_NUM(o);
	t->Token = ZeroMalloc(sizeof(wchar_t *) * t->NumTokens);
	for (UINT i = 0; i < t->NumTokens; i++)
		t->Token[i] = LIST_DATA(o, i);

	ReleaseList(o);

	return t;
}

UINT UtfToUni(wchar_t *unistr, UINT size, const char *utfstr) {
	if (unistr == NULL || utfstr == NULL) {
		UniStrCpy(unistr, size, L"");
		return 0;
	}

	wchar_t *tmp = CopyUtfToUni(utfstr);

	UniStrCpy(unistr, size, tmp);

	Free(tmp);

	return UniStrLen(unistr);
}

wchar_t *CopyUtfToUni(const char *utfstr) {
	if (utfstr == NULL)
		return NULL;

	UINT utfstr_len = StrLen(utfstr);

	UINT size = CalcUtf8ToUni((const BYTE *)utfstr, utfstr_len);
	wchar_t *ret = ZeroMalloc(size + sizeof(wchar_t));
	Utf8ToUni(ret, size, (const BYTE *)utfstr, utfstr_len);

	return ret;
}

char *CopyUniToUtf(const wchar_t *unistr) {
	if (unistr == NULL)
		return NULL;

	UINT size = CalcUniToUtf8(unistr);
	char *ret = ZeroMalloc(size + sizeof(char));

	UniToUtf8((char *)ret, size, unistr);

	return ret;
}

wchar_t *CopyUniStr(const wchar_t *str) {
	if (str == NULL)
		return NULL;

	UINT len = UniStrLen(str);
	wchar_t *dst = Malloc((len + 1) * sizeof(wchar_t));
	UniStrCpy(dst, 0, str);

	return dst;
}

bool IsSafeUniStr(const wchar_t *str) {
	if (str == NULL)
		return false;

	UINT len = UniStrLen(str);
	for (UINT i = 0; i < len; i++)
		if (IsSafeUniChar(str[i]) == false)
			return false;
	if (str[0] == L' ')
		return false;
	if (len != 0) {
		if (str[len - 1] == L' ')
			return false;
	}
	return true;
}

bool IsSafeUniChar(wchar_t c) {
	wchar_t *check_str =
	    L"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	    L"abcdefghijklmnopqrstuvwxyz"
	    L"0123456789"
	    L" ()-_#%&.";

	UINT len = UniStrLen(check_str);
	for (UINT i = 0; i < len; i++)
		if (c == check_str[i])
			return true;
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
#define ANSI_C_LOCALE_CODE_PAGE 28591

// Code page of the ANSI conversions. *c_locale (optional) receives whether the C locale is
// active, the same test the UCRT's own mbstowcs() and wcstombs() make: only that locale has no
// best fit, while a real ".28591" locale has the best fit of code page 28591.
static UINT AnsiCodePage(bool *c_locale) {
	bool c = (___lc_locale_name_func()[LC_CTYPE] == NULL);

	if (c_locale != NULL)
		*c_locale = c;

	if (c)
		return ANSI_C_LOCALE_CODE_PAGE;

	return ___lc_codepage_func();
}

// Convert the ANSI string str into dst (NULL: only count), dst_len wchar_t at most. Returns the
// number of wchar_t with the terminating NUL, or 0 when str does not convert
static UINT ConvertAnsiToUni(wchar_t *dst, UINT dst_len, const char *str) {
	UINT cp = AnsiCodePage(NULL);
	// UTF-8 takes no flag but MB_ERR_INVALID_CHARS
	DWORD flags = (cp == CP_UTF8) ? MB_ERR_INVALID_CHARS : (MB_PRECOMPOSED | MB_ERR_INVALID_CHARS);
	int ret = MultiByteToWideChar(cp, flags, str, -1, dst, (int)dst_len);

	return (ret > 0) ? (UINT)ret : 0;
}

// Convert the wide string s into dst (NULL: only count), dst_size bytes at most. Returns the
// number of bytes with the terminating NUL, or 0 when s does not convert
static UINT ConvertUniToAnsi(char *dst, UINT dst_size, const wchar_t *s) {
	bool c_locale;
	UINT cp = AnsiCodePage(&c_locale);
	BOOL used_default = FALSE;
	int ret;

	if (cp == CP_UTF8) {
		// UTF-8 has no default character; an unpaired surrogate does not convert
		ret = WideCharToMultiByte(cp, WC_ERR_INVALID_CHARS, s, -1, dst, (int)dst_size, NULL, NULL);
	} else {
		ret = WideCharToMultiByte(cp, c_locale ? WC_NO_BEST_FIT_CHARS : 0, s, -1, dst, (int)dst_size, NULL, &used_default);
	}

	return (ret > 0 && used_default == FALSE) ? (UINT)ret : 0;
}

// ASCII fast path: in the code page of the C locale and in the ANSI code pages of the Windows
// locales, the only ones setlocale(LC_ALL, "") selects, the characters U+0001-U+007F and the
// bytes 0x01-0x7F map to each other one to one, so a string of them alone converts by widening
// or narrowing each unit, without MultiByteToWideChar or WideCharToMultiByte. Any other code
// page takes the conversion functions.
static bool AnsiKeepsAscii(void) {
	switch (AnsiCodePage(NULL)) {
	case ANSI_C_LOCALE_CODE_PAGE:
	case CP_UTF8:
	case 874:
	case 932:
	case 936:
	case 949:
	case 950:
	case 1250:
	case 1251:
	case 1252:
	case 1253:
	case 1254:
	case 1255:
	case 1256:
	case 1257:
	case 1258:
		return true;
	}

	return false;
}

// Length of str when the ASCII fast path converts it, else INFINITE
static UINT AnsiAsciiLen(const char *str) {
	UINT i;

	for (i = 0; str[i] != 0; i++)
		if ((UCHAR)str[i] >= 0x80)
			return INFINITE;

	return AnsiKeepsAscii() ? i : INFINITE;
}

// Length of s when the ASCII fast path converts it, else INFINITE
static UINT UniAsciiLen(const wchar_t *s) {
	UINT i;

	for (i = 0; s[i] != 0; i++)
		if (s[i] >= 0x80)
			return INFINITE;

	return AnsiKeepsAscii() ? i : INFINITE;
}

// Widen the first len characters of the ASCII string str into s and terminate s
static void WidenAscii(wchar_t *s, const char *str, UINT len) {
	for (UINT i = 0; i < len; i++)
		s[i] = (wchar_t)str[i];
	s[len] = 0;
}

// Narrow the first len characters of the ASCII string s into str and terminate str
static void NarrowAscii(char *str, const wchar_t *s, UINT len) {
	for (UINT i = 0; i < len; i++)
		str[i] = (char)s[i];
	str[len] = 0;
}

// UniToStr and StrToUni give what the copy of the whole converted string into the destination
// gives (StrCpy, UniStrCpy). A result that fits is converted straight into the destination;
// only a result that the copy cuts still goes through a temporary string.

UINT UniToStr(char *str, UINT size, const wchar_t *s) {
	if (s == NULL || str == NULL)
		return 0;

	// StrCpy copies at most room - 1 bytes and the terminator: room is size, or STRSAFE_MAX_CCH
	// for size 0 and for a larger size
	UINT room = (size == 0 || size > 0x7fffffff) ? 0x7fffffff : size;

	UINT len = UniAsciiLen(s);
	if (len != INFINITE) {
		len = MIN(len, room - 1);
		NarrowAscii(str, s, len);
		return len;
	}

	UINT new_size = ConvertUniToAnsi(NULL, 0, s);
	if (new_size == 0) {
		if (size >= 1)
			StrCpy(str, 0, "");
		return 0;
	}
	if (new_size <= room) {
		if (ConvertUniToAnsi(str, new_size, s) == 0) {
			str[0] = 0;
			return 0;
		}
		return new_size - 1;
	}
	char *tmp = Malloc(new_size);
	tmp[0] = 0;
	ConvertUniToAnsi(tmp, new_size, s);
	tmp[new_size - 1] = 0;
	UINT ret = StrCpy(str, size, tmp);
	Free(tmp);

	return ret;
}

UINT CalcUniToStr(const wchar_t *s) {
	if (s == NULL)
		return 0;

	UINT len = UniAsciiLen(s);
	if (len != INFINITE)
		return len + 1;

	return ConvertUniToAnsi(NULL, 0, s);
}

UINT StrToUni(wchar_t *s, UINT size, const char *str) {
	if (s == NULL || str == NULL)
		return 0;

	// UniStrCpy writes nothing into a destination without room for the terminator, and no
	// result here writes one
	if (size == 1)
		return 0;

	// UniStrCpy copies at most room / sizeof(wchar_t) - 1 characters and the terminator: room
	// is size, or 0x3fffffff bytes for size 0
	UINT room = (size == 0) ? 0x3fffffff : size;

	UINT len = AnsiAsciiLen(str);
	if (len != INFINITE) {
		len = MIN(len, room / (UINT)sizeof(wchar_t) - 1);
		WidenAscii(s, str, len);
		return len;
	}

	UINT new_size = ConvertAnsiToUni(NULL, 0, str) * (UINT)sizeof(wchar_t);
	if (new_size == 0) {
		if (size >= 2)
			UniStrCpy(s, 0, L"");
		return 0;
	}
	if (new_size <= room) {
		if (ConvertAnsiToUni(s, new_size / (UINT)sizeof(wchar_t), str) == 0) {
			s[0] = 0;
			return 0;
		}
		return new_size / (UINT)sizeof(wchar_t) - 1;
	}
	wchar_t *tmp = Malloc(new_size);
	tmp[0] = 0;
	ConvertAnsiToUni(tmp, new_size / (UINT)sizeof(wchar_t), str);
	tmp[(new_size - 1) / sizeof(wchar_t)] = 0;
	UINT ret = UniStrCpy(s, size, tmp);
	Free(tmp);

	return ret;
}

UINT CalcStrToUni(const char *str) {
	if (str == NULL)
		return 0;

	UINT len = AnsiAsciiLen(str);
	if (len != INFINITE)
		return (len + 1) * (UINT)sizeof(wchar_t);

	return ConvertAnsiToUni(NULL, 0, str) * (UINT)sizeof(wchar_t);
}

// The converted string in one allocation of its exact size, without a temporary string
char *CopyUniToStr(const wchar_t *unistr) {
	char *str;
	if (unistr == NULL)
		return NULL;

	UINT len = UniAsciiLen(unistr);
	if (len != INFINITE) {
		str = Malloc(len + 1);
		NarrowAscii(str, unistr, len);
		return str;
	}

	UINT str_size = ConvertUniToAnsi(NULL, 0, unistr);
	if (str_size == 0)
		return CopyStr("");
	str = Malloc(str_size);
	if (ConvertUniToAnsi(str, str_size, unistr) == 0)
		str[0] = 0;

	return str;
}

// The converted string in one allocation of its exact size, without a temporary string
wchar_t *CopyStrToUni(const char *str) {
	wchar_t *uni;
	if (str == NULL)
		return NULL;

	UINT len = AnsiAsciiLen(str);
	if (len != INFINITE) {
		uni = Malloc((len + 1) * (UINT)sizeof(wchar_t));
		WidenAscii(uni, str, len);
		return uni;
	}

	UINT uni_len = ConvertAnsiToUni(NULL, 0, str);
	if (uni_len == 0)
		return CopyUniStr(L"");
	uni = Malloc(uni_len * (UINT)sizeof(wchar_t));
	if (ConvertAnsiToUni(uni, uni_len, str) == 0)
		uni[0] = 0;

	return uni;
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
#define UTF8_NATIVE_MAX ((UINT)0x7fffffff)

static bool IsSurrogateUnit(wchar_t c) {
	return (c >= 0xd800 && c <= 0xdfff);
}

// Encode the len code units of s into u (NULL: only count), which has room for u_size bytes,
// all of the encoding. Returns the number of bytes
static UINT UniToUtf8Units(BYTE *u, UINT u_size, const wchar_t *s, UINT len) {
	UINT i = 0, wp = 0;

	while (i < len) {
		wchar_t c = s[i];

		if (IsSurrogateUnit(c)) {
			if (u != NULL) {
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
		UINT run = 1;
		while (i + run < len && run < UTF8_NATIVE_MAX && IsSurrogateUnit(s[i + run]) == false)
			run++;

		if (u != NULL)
			wp += (UINT)WideCharToMultiByte(CP_UTF8, 0, &s[i], (int)run, (char *)&u[wp], (int)MIN(u_size - wp, UTF8_NATIVE_MAX), NULL, NULL);
		else
			wp += (UINT)WideCharToMultiByte(CP_UTF8, 0, &s[i], (int)run, NULL, 0, NULL, NULL);
		i += run;
	}

	return wp;
}

// Number of code units MultiByteToWideChar decodes the size bytes of u to, or 0 when they take
// the bit-level decoder: they are not well-formed UTF-8, or hold a 4-byte sequence (a byte of
// 0xF0 or above)
static UINT Utf8NativeLen(const BYTE *u, UINT size) {
	if (size == 0 || size > UTF8_NATIVE_MAX)
		return 0;

	for (UINT i = 0; i < size; i++)
		if (u[i] >= 0xf0)
			return 0;

	int ret = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, (char *)u, (int)size, NULL, 0);

	return (ret > 0) ? (UINT)ret : 0;
}

// The bit-level decoder: decode the size bytes of u into s (NULL: only count), at most room code
// units. Returns the number of code units
static UINT Utf8ToUniBits(wchar_t *s, UINT room, const BYTE *u, UINT size) {
	UINT i = 0, num = 0;

	while (num < room) {
		UINT type = GetUtf8Type(u, size, i);
		if (type == 0)
			break;

		if (s != NULL) {
			switch (type) {
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

UINT Utf8ToUni(wchar_t *s, UINT size, const void *u, UINT u_size) {
	UINT num;
	if (s == NULL || u == NULL)
		return 0;
	if (size == 0)
		size = 0x3fffffff;
	if (u_size == 0)
		u_size = StrLen(u);

	// Code units that fit before the terminating NUL
	UINT room = (UINT)(size / sizeof(wchar_t) - 1);

	UINT len = Utf8NativeLen(u, u_size);
	if (len == 0) {
		num = Utf8ToUniBits(s, room, u, u_size);
	} else if (len <= room) {
		num = (UINT)MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, (char *)u, (int)u_size, s, (int)len);
	} else {
		// Too small: the first room code units
		wchar_t *tmp = Malloc(len * sizeof(wchar_t));
		MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, (char *)u, (int)u_size, tmp, (int)len);
		Copy(s, tmp, room * sizeof(wchar_t));
		Free(tmp);
		num = room;
	}

	if (num < (size / sizeof(wchar_t)))
		s[num] = 0;

	return num;
}

UINT CalcUtf8ToUni(const void *u, UINT u_size) {
	if (u == NULL)
		return 0;
	if (u_size == 0)
		u_size = StrLen(u);

	return (Utf8Len(u, u_size) + 1) * sizeof(wchar_t);
}

UINT Utf8Len(const BYTE *u, UINT size) {
	if (u == NULL)
		return 0;
	if (size == 0)
		size = StrLen((char *)u);

	UINT num = Utf8NativeLen(u, size);
	if (num == 0)
		num = Utf8ToUniBits(NULL, INFINITE, u, size);

	return num;
}

UINT UniToUtf8(void *u, UINT size, const wchar_t *s) {
	UINT wp;
	if (u == NULL || s == NULL)
		return 0;
	if (size == 0)
		size = 0x3fffffff;

	UINT len = UniStrLen(s);
	UINT need = UniToUtf8Units(NULL, 0, s, len);
	if (need <= size) {
		wp = UniToUtf8Units(u, need, s, len);
	} else {
		// Too small: the first size bytes, which can end inside a sequence
		BYTE *tmp = Malloc(need);
		UniToUtf8Units(tmp, need, s, len);
		Copy(u, tmp, size);
		Free(tmp);
		wp = size;
	}

	if (wp < size)
		((BYTE *)u)[wp] = 0;

	return wp;
}

UINT CalcUniToUtf8(const wchar_t *s) {
	if (s == NULL)
		return 0;

	return UniToUtf8Units(NULL, 0, s, UniStrLen(s));
}

UINT GetUtf8Type(const BYTE *s, UINT size, UINT offset) {
	if (s == NULL)
		return 0;
	if ((offset + 1) > size)
		return 0;
	if ((s[offset] & 0x80) == 0)
		return 1;
	if ((s[offset] & 0x20) == 0) {
		if ((offset + 2) > size)
			return 0;
		return 2;
	}
	if ((offset + 3) > size)
		return 0;
	return 3;
}

UINT GetUniType(wchar_t c) {
	BYTE c1 = (BYTE)((c >> 8) & 0xFF);
	BYTE c2 = (BYTE)(c & 0xFF);

	if (c1 == 0) {
		if (c2 <= 0x7f)
			return 1;
		else
			return 2;
	}
	if ((c1 & 0xf8) == 0)
		return 2;
	return 3;
}

UINT UniReplaceStrEx(wchar_t *dst, UINT size, const wchar_t *string, const wchar_t *old_keyword, const wchar_t *new_keyword, bool case_sensitive) {
	UINT j, num, wp;
	if (string == NULL || old_keyword == NULL || new_keyword == NULL)
		return 0;

	UINT len_string = UniStrLen(string);
	UINT len_old = UniStrLen(old_keyword);
	UINT len_new = UniStrLen(new_keyword);

	UINT len_ret = UniCalcReplaceStrEx(string, old_keyword, new_keyword, case_sensitive);
	wchar_t *ret = Malloc((len_ret + 1) * sizeof(wchar_t));
	ret[len_ret] = 0;

	UINT i = j = num = wp = 0;
	while (true) {
		i = UniSearchStrEx(string, old_keyword, i, case_sensitive);
		if (i == INFINITE) {
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

UINT UniCalcReplaceStrEx(const wchar_t *string, const wchar_t *old_keyword, const wchar_t *new_keyword, bool case_sensitive) {
	if (string == NULL || old_keyword == NULL || new_keyword == NULL)
		return 0;

	UINT len_string = UniStrLen(string);
	UINT len_old = UniStrLen(old_keyword);
	UINT len_new = UniStrLen(new_keyword);

	if (len_old == len_new)
		return len_string;

	UINT num = 0;
	UINT i = 0;
	while (true) {
		i = UniSearchStrEx(string, old_keyword, i, case_sensitive);
		if (i == INFINITE)
			break;
		i += len_old;
		num++;
	}

	return len_string + len_new * num - len_old * num;
}

UINT UniSearchStr(const wchar_t *string, const wchar_t *keyword, UINT start) {
	return UniSearchStrEx(string, keyword, start, true);
}

// Returns INFINITE if not found
UINT UniSearchStrEx(const wchar_t *string, const wchar_t *keyword, UINT start, bool case_sensitive) {
	UINT i;
	const wchar_t *cmp_string, *cmp_keyword;
	wchar_t *upper_string = NULL, *upper_keyword = NULL;
	if (string == NULL || keyword == NULL)
		return INFINITE;

	UINT len_string = UniStrLen(string);
	if (len_string <= start)
		return INFINITE;

	UINT len_keyword = UniStrLen(keyword);
	if (len_keyword == 0)
		return INFINITE;

	if (len_string < len_keyword)
		return INFINITE;

	if (case_sensitive) {
		cmp_string = string;
		cmp_keyword = keyword;
	} else {
		upper_string = Malloc((len_string + 1) * sizeof(wchar_t));
		UniStrCpy(upper_string, (len_string + 1) * sizeof(wchar_t), string);
		upper_keyword = Malloc((len_keyword + 1) * sizeof(wchar_t));
		UniStrCpy(upper_keyword, (len_keyword + 1) * sizeof(wchar_t), keyword);
		UniStrUpper(upper_string);
		UniStrUpper(upper_keyword);
		cmp_string = upper_string;
		cmp_keyword = upper_keyword;
	}

	bool found = false;
	for (i = start; i < (len_string - len_keyword + 1); i++) {
		if (!wcsncmp(&cmp_string[i], cmp_keyword, len_keyword)) {
			found = true;
			break;
		}
	}

	if (case_sensitive == false) {
		Free(upper_keyword);
		Free(upper_string);
	}

	if (found == false)
		return INFINITE;
	return i;
}

void UniFreeToken(UNI_TOKEN_LIST *tokens) {
	if (tokens == NULL)
		return;
	for (UINT i = 0; i < tokens->NumTokens; i++)
		Free(tokens->Token[i]);
	Free(tokens->Token);
	Free(tokens);
}

static wchar_t *UniDefaultTokenSplitChars() {
	return L" ,\t\r\n";
}

static UNI_TOKEN_LIST *UniParseTokenWithoutNullStr(const wchar_t *str, const wchar_t *split_chars) {
	wchar_t zero = 0;
	if (str == NULL)
		return UniNullToken();
	if (split_chars == NULL)
		split_chars = UniDefaultTokenSplitChars();

	BUF *b = NewBuf();
	LIST *o = NewListFast(NULL);

	UINT len = UniStrLen(str);
	bool last_flag = false;

	for (UINT i = 0; i < (len + 1); i++) {
		wchar_t c = str[i];
		bool flag = UniIsCharInStr(split_chars, c);

		if (c == L'\0')
			flag = true;

		if (flag == false) {
			WriteBuf(b, &c, sizeof(wchar_t));
		} else if (last_flag == false) {
			WriteBuf(b, &zero, sizeof(wchar_t));

			if ((UniStrLen((wchar_t *)b->Buf)) != 0)
				Insert(o, CopyUniStr((wchar_t *)b->Buf));
			ClearBuf(b);
		}

		last_flag = flag;
	}

	UNI_TOKEN_LIST *t = ZeroMalloc(sizeof(UNI_TOKEN_LIST));
	t->NumTokens = LIST_NUM(o);
	t->Token = ZeroMalloc(sizeof(wchar_t *) * t->NumTokens);

	for (UINT i = 0; i < t->NumTokens; i++)
		t->Token[i] = LIST_DATA(o, i);

	ReleaseList(o);
	FreeBuf(b);

	return t;
}

UNI_TOKEN_LIST *UniParseToken(const wchar_t *src, const wchar_t *separator) {
	return UniParseTokenWithoutNullStr(src, separator);
}

bool UniGetLineWin32(wchar_t *str, UINT size) {
	bool ret = false;

	ret = Win32InputW(str, size);

	return ret;
}

void UniTrimCrlf(wchar_t *str) {
	if (str == NULL)
		return;
	UINT len = UniStrLen(str);
	if (len == 0)
		return;

	if (str[len - 1] == L'\n') {
		if (len >= 2 && str[len - 2] == L'\r')
			str[len - 2] = 0;
		str[len - 1] = 0;
	} else if (str[len - 1] == L'\r') {
		str[len - 1] = 0;
	}
}

void UniTrim(wchar_t *str) {
	if (str == NULL)
		return;

	UniTrimLeft(str);
	UniTrimRight(str);
}

void UniTrimRight(wchar_t *str) {
	if (str == NULL)
		return;

	UINT len = UniStrLen(str);
	UINT end = len;
	while (end != 0 && (str[end - 1] == L' ' || str[end - 1] == L'\t'))
		end--;

	// Writes only when there is something to remove
	if (end != len)
		str[end] = L'\0';
}

void UniTrimLeft(wchar_t *str) {
	UINT len;
	if (str == NULL)
		return;

	UINT skip = 0;
	while (str[skip] == L' ' || str[skip] == L'\t')
		skip++;

	// Writes only when there is something to remove; the terminator moves along
	if (skip != 0) {
		len = UniStrLen(str + skip);
		Move(str, str + skip, (len + 1) * sizeof(wchar_t));
	}
}

void UniToStru(wchar_t *str, UINT i) {
	UniFormat(str, 0, L"%u", i);
}

UNI_TOKEN_LIST *UniGetLines(const wchar_t *str) {
	BUF *b = NULL;
	wchar_t zero = 0;
	wchar_t *s;
	if (str == NULL)
		return UniNullToken();

	LIST *o = NewListFast(NULL);

	UINT len = UniStrLen(str);

	b = NewBuf();

	for (UINT i = 0; i < len; i++) {
		wchar_t c = str[i];
		bool f = false;

		if (c == L'\r') {
			if (str[i + 1] == L'\n')
				i++;
			f = true;
		} else if (c == L'\n') {
			f = true;
		}

		if (f) {
			WriteBuf(b, &zero, sizeof(wchar_t));

			s = (wchar_t *)b->Buf;

			Add(o, CopyUniStr(s));

			ClearBuf(b);
		} else {
			WriteBuf(b, &c, sizeof(wchar_t));
		}
	}

	WriteBuf(b, &zero, sizeof(wchar_t));

	s = (wchar_t *)b->Buf;

	Add(o, CopyUniStr(s));

	ClearBuf(b);

	FreeBuf(b);

	UNI_TOKEN_LIST *ret = UniListToTokenList(o);

	UniFreeStrList(o);

	return ret;
}

void UniPrintStr(wchar_t *string) {
	if (string == NULL)
		return;

	Win32PrintW(string);
}

// The CRT formats the whole message into a heap buffer, which goes to the console as it is
static void UniPrintArgs(const wchar_t *fmt, va_list args) {
	va_list count_args;
	if (fmt == NULL)
		return;

	va_copy(count_args, args);
	int len = _vscwprintf(fmt, count_args);
	va_end(count_args);
	if (len < 0)
		return;

	wchar_t *str = Malloc(((UINT)len + 1) * (UINT)sizeof(wchar_t));
	_vsnwprintf_s(str, (size_t)len + 1, _TRUNCATE, fmt, args);

	UniPrintStr(str);

	Free(str);
}

void UniPrint(const wchar_t *fmt, ...) {
	va_list args;
	if (fmt == NULL)
		return;

	va_start(args, fmt);
	UniPrintArgs(fmt, args);
	va_end(args);
}

// The CRT formatter (wide: %s is a wchar_t string, %S a char string). size is in bytes: 0 means
// the buffer holds the whole result, 1 leaves buf as it is, and a longer result keeps
// size / sizeof(wchar_t) - 1 characters and the terminator. buf must not be an argument or fmt
void UniFormatArgs(wchar_t *buf, UINT size, const wchar_t *fmt, va_list args) {
	size_t count = size / sizeof(wchar_t);
	if (buf == NULL || fmt == NULL)
		return;
	if (size == 1)
		return;

	KS_INC(KS_FORMAT_COUNT);

	if (size == 0) {
		va_list count_args;

		va_copy(count_args, args);
		int len = _vscwprintf(fmt, count_args);
		va_end(count_args);
		if (len < 0) {
			buf[0] = 0;
			return;
		}
		count = (size_t)len + 1;
	}

	_vsnwprintf_s(buf, count, _TRUNCATE, fmt, args);
}

void UniFormat(wchar_t *buf, UINT size, const wchar_t *fmt, ...) {
	va_list args;
	if (buf == NULL || fmt == NULL)
		return;

	va_start(args, fmt);
	UniFormatArgs(buf, size, fmt, args);
	va_end(args);
}

int UniSoftStrCmp(const wchar_t *str1, const wchar_t *str2) {
	if (str1 == NULL && str2 == NULL)
		return 0;
	if (str1 == NULL)
		return 1;
	if (str2 == NULL)
		return -1;

	// Compares the ranges left after UniTrim in place, with the fold of UniStrCmpi
	while (*str1 == L' ' || *str1 == L'\t')
		str1++;
	while (*str2 == L' ' || *str2 == L'\t')
		str2++;

	UINT len1 = UniStrLen(str1);
	while (len1 != 0 && (str1[len1 - 1] == L' ' || str1[len1 - 1] == L'\t'))
		len1--;
	UINT len2 = UniStrLen(str2);
	while (len2 != 0 && (str2[len2 - 1] == L' ' || str2[len2 - 1] == L'\t'))
		len2--;

	for (UINT i = 0; i < len1 || i < len2; i++) {
		// A range that has ended reads as the terminator
		wchar_t c1 = (i < len1) ? UniToUpper(str1[i]) : L'\0';
		wchar_t c2 = (i < len2) ? UniToUpper(str2[i]) : L'\0';
		if (c1 > c2)
			return 1;
		else if (c1 < c2)
			return -1;
	}

	return 0;
}

int UniStrCmpi(const wchar_t *str1, const wchar_t *str2) {
	if (str1 == NULL && str2 == NULL)
		return 0;
	if (str1 == NULL)
		return 1;
	if (str2 == NULL)
		return -1;

	UINT i = 0;
	while (true) {
		wchar_t c1 = UniToUpper(str1[i]);
		wchar_t c2 = UniToUpper(str2[i]);
		if (c1 > c2)
			return 1;
		else if (c1 < c2)
			return -1;
		if (str1[i] == 0 || str2[i] == 0)
			return 0;
		i++;
	}
}

int UniStrCmp(const wchar_t *str1, const wchar_t *str2) {
	if (str1 == NULL && str2 == NULL)
		return 0;
	if (str1 == NULL)
		return 1;
	if (str2 == NULL)
		return -1;

	return wcscmp(str1, str2);
}

void UniStrLower(wchar_t *str) {
	if (str == NULL)
		return;

	UINT len = UniStrLen(str);
	for (UINT i = 0; i < len; i++)
		str[i] = UniToLower(str[i]);
}

void UniStrUpper(wchar_t *str) {
	if (str == NULL)
		return;

	UINT len = UniStrLen(str);
	for (UINT i = 0; i < len; i++)
		str[i] = UniToUpper(str[i]);
}

wchar_t UniToLower(wchar_t c) {
	if (c >= L'A' && c <= L'Z')
		c += L'a' - L'A';

	return c;
}

wchar_t UniToUpper(wchar_t c) {
	if (c >= L'a' && c <= L'z')
		c -= L'a' - L'A';

	return c;
}

UINT UniStrCat(wchar_t *dst, UINT size, const wchar_t *src) {
	if (dst == NULL || src == NULL)
		return 0;
	if (size != 0 && size < sizeof(wchar_t))
		return 0;
	if (size == sizeof(wchar_t)) {
		wcscpy(dst, L"");
		return 0;
	}
	if (size == 0)
		size = 0x3fffffff;

	UINT len1 = UniStrLen(dst);
	UINT len2 = UniStrLen(src);
	UINT len_test = len1 + len2 + 1;
	if (len_test > (size / sizeof(wchar_t))) {
		if (len2 <= (len_test - (size / sizeof(wchar_t))))
			return 0;
		len2 -= len_test - (size / sizeof(wchar_t));
	}
	Copy(&dst[len1], src, len2 * sizeof(wchar_t));
	dst[len1 + len2] = 0;

	return len1 + len2;
}

UINT UniStrCpy(wchar_t *dst, UINT size, const wchar_t *src) {
	if (dst == NULL || src == NULL) {
		if (src == NULL && dst != NULL) {
			if (size >= sizeof(wchar_t))
				dst[0] = L'\0';
		}
		return 0;
	}
	if (dst == src)
		return UniStrLen(src);
	if (size != 0 && size < sizeof(wchar_t))
		return 0;
	if (size == sizeof(wchar_t)) {
		wcscpy(dst, L"");
		return 0;
	}
	if (size == 0)
		size = 0x3fffffff;

	UINT len = UniStrLen(src);
	if (len <= (size / sizeof(wchar_t) - 1)) {
		Copy(dst, src, (len + 1) * sizeof(wchar_t));
	} else {
		len = size / sizeof(wchar_t) - 1;
		Copy(dst, src, len * sizeof(wchar_t));
		dst[len] = 0;
	}

	return len;
}

UINT UniStrSize(const wchar_t *str) {
	if (str == NULL)
		return 0;

	return (UniStrLen(str) + 1) * sizeof(wchar_t);
}

UINT UniStrLen(const wchar_t *str) {
	if (str == NULL)
		return 0;

	return (UINT)wcslen(str);
}

