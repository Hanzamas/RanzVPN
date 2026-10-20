// strtest.c
// Named string test of vpntest ("str" command, NAT-4 #90)
//
// Pins the truncation and return-value semantics of the Mayaqua string functions that NAT-4
// implements on strsafe and the CRT: copy, concatenate, length check, fill, number and hex
// formatting, search, tokens, trim and the ordering of the compare functions. It is written
// against the old implementation and must pass on the old and on the new one. Each destination
// is a buffer filled with STRTEST_FILL before the call, so a check also sees every byte written
// behind the result. Prints "STR TEST OK" only when every check passes, and frees everything it
// allocates. The [PASS] lines carry no values; the [FAIL] details do.
// It also pins snprintf as a unit that includes Mayaqua.h sees it: the C99 snprintf of the CRT,
// which ends a truncated result in NUL (FND-2, #105).

#include "Mayaqua/Internat.h"
#include "Mayaqua/Mayaqua.h"
#include "Mayaqua/Memory.h"
#include "Mayaqua/Str.h"

#include <stdarg.h>
#include <stdio.h>
#include <string.h>

// Destination buffer
#define	STRTEST_BUF_SIZE	32		// Bytes of the destination that a call may see
#define	STRTEST_FILL		'#'		// Byte that fills the destination before each call
#define	STRTEST_GUARD_END	0		// Guard of StrTestIs: starts right after the terminator of the expected string

// Run state of the test
typedef struct STRTEST_CTX
{
	UINT NumChecks;						// Checks run so far
	UINT NumFailed;						// Checks failed so far
	char Buf[STRTEST_BUF_SIZE + 1];		// Destination; the last byte stays 0 so that a [FAIL] line can print it
} STRTEST_CTX;

// Record one check: print [PASS], or [FAIL] with the formatted detail
static bool StrTestCheck(STRTEST_CTX *ctx, bool ok, char *what, char *detail_fmt, ...)
{
	char detail[MAX_SIZE];
	va_list args;

	ctx->NumChecks++;

	if (ok)
	{
		Print("  [PASS] %s\n", what);
		return true;
	}

	va_start(args, detail_fmt);
	FormatArgs(detail, sizeof(detail), detail_fmt, args);
	va_end(args);

	Print("  [FAIL] %s (%s)\n", what, detail);

	ctx->NumFailed++;

	return false;
}

// Fill the destination with STRTEST_FILL, put init (with its terminator) at its start when it
// is not NULL, and return the destination
static char *StrTestReset(STRTEST_CTX *ctx, char *init)
{
	memset(ctx->Buf, STRTEST_FILL, STRTEST_BUF_SIZE);
	ctx->Buf[STRTEST_BUF_SIZE] = 0;

	if (init != NULL)
	{
		Copy(ctx->Buf, init, StrSize(init));
	}

	return ctx->Buf;
}

// True when the destination holds the string expect and every byte from guard to its end is
// still STRTEST_FILL
static bool StrTestIs(STRTEST_CTX *ctx, char *expect, UINT guard)
{
	UINT size = StrSize(expect);
	UINT i;

	if (Cmp(ctx->Buf, expect, size) != 0)
	{
		return false;
	}

	if (guard == STRTEST_GUARD_END)
	{
		guard = size;
	}

	for (i = guard;i < STRTEST_BUF_SIZE;i++)
	{
		if (ctx->Buf[i] != STRTEST_FILL)
		{
			return false;
		}
	}

	return true;
}

// One check of a call that wrote the destination and returned a UINT
static void StrTestDst(STRTEST_CTX *ctx, char *what, UINT ret, UINT expect_ret, char *expect, UINT guard)
{
	StrTestCheck(ctx, ret == expect_ret && StrTestIs(ctx, expect, guard), what,
		"returned %u, buffer \"%s\"; expected %u, \"%s\"", ret, ctx->Buf, expect_ret, expect);
}

// One check of a call that wrote the destination and returns nothing
static void StrTestOut(STRTEST_CTX *ctx, char *what, char *expect, UINT guard)
{
	StrTestCheck(ctx, StrTestIs(ctx, expect, guard), what, "buffer \"%s\"; expected \"%s\"", ctx->Buf, expect);
}

// One check of a UINT result
static void StrTestUint(STRTEST_CTX *ctx, char *what, UINT ret, UINT expect_ret)
{
	StrTestCheck(ctx, ret == expect_ret, what, "returned %u; expected %u", ret, expect_ret);
}

// One check of an int result
static void StrTestInt(STRTEST_CTX *ctx, char *what, int ret, int expect_ret)
{
	StrTestCheck(ctx, ret == expect_ret, what, "returned %d; expected %d", ret, expect_ret);
}

// One check of a heap string; frees it
static void StrTestHeap(STRTEST_CTX *ctx, char *what, char *s, char *expect)
{
	StrTestCheck(ctx, s != NULL && StrCmp(s, expect) == 0, what, "got \"%s\"; expected \"%s\"", s == NULL ? "(null)" : s, expect);

	Free(s);
}

// One check of a token list, given as its number of tokens and its tokens joined by '|'; frees
// the list
static void StrTestTokens(STRTEST_CTX *ctx, char *what, TOKEN_LIST *t, UINT expect_num, char *expect)
{
	char joined[MAX_SIZE];
	UINT i;

	joined[0] = 0;
	for (i = 0;i < t->NumTokens;i++)
	{
		if (i != 0)
		{
			StrCat(joined, sizeof(joined), "|");
		}
		StrCat(joined, sizeof(joined), t->Token[i]);
	}

	StrTestCheck(ctx, t->NumTokens == expect_num && StrCmp(joined, expect) == 0, what,
		"%u tokens \"%s\"; expected %u, \"%s\"", t->NumTokens, joined, expect_num, expect);

	FreeToken(t);
}

// StrCpy, StrCpyAllowOverlap, CopyStr, ClearStr and MakeCharArray
static void StrTestCopy(STRTEST_CTX *ctx)
{
	char *b;
	char *p;
	UINT ret;

	b = StrTestReset(ctx, NULL);
	StrTestDst(ctx, "StrCpy copies a string that fits and writes nothing behind its terminator", StrCpy(b, 8, "abc"), 3, "abc", STRTEST_GUARD_END);
	b = StrTestReset(ctx, NULL);
	StrTestDst(ctx, "StrCpy fills size exactly with a string of size - 1 characters", StrCpy(b, 4, "abc"), 3, "abc", STRTEST_GUARD_END);
	b = StrTestReset(ctx, NULL);
	StrTestDst(ctx, "StrCpy truncates to size - 1 characters and returns that length", StrCpy(b, 4, "abcdef"), 3, "abc", STRTEST_GUARD_END);
	b = StrTestReset(ctx, NULL);
	StrTestDst(ctx, "StrCpy with size 1 writes only the terminator and returns 0", StrCpy(b, 1, "abc"), 0, "", STRTEST_GUARD_END);
	b = StrTestReset(ctx, NULL);
	StrTestDst(ctx, "StrCpy with size 0 copies without a limit", StrCpy(b, 0, "abcdefghij"), 10, "abcdefghij", STRTEST_GUARD_END);
	b = StrTestReset(ctx, NULL);
	StrTestDst(ctx, "StrCpy with size 0xFFFFFFFF copies without a limit, like size 0", StrCpy(b, 0xFFFFFFFF, "abcdefghij"), 10, "abcdefghij", STRTEST_GUARD_END);
	b = StrTestReset(ctx, NULL);
	StrTestDst(ctx, "StrCpy of an empty string writes the terminator and returns 0", StrCpy(b, 8, ""), 0, "", STRTEST_GUARD_END);
	b = StrTestReset(ctx, "xy");
	StrTestDst(ctx, "StrCpy of NULL writes the terminator and returns 0", StrCpy(b, 8, NULL), 0, "", sizeof("xy"));
	b = StrTestReset(ctx, "xy");
	StrTestDst(ctx, "StrCpy of NULL with size 0 leaves the destination as it is", StrCpy(b, 0, NULL), 0, "xy", STRTEST_GUARD_END);
	b = StrTestReset(ctx, "hello");
	StrTestDst(ctx, "StrCpy onto itself copies nothing and returns the length, whatever the size", StrCpy(b, 2, b), 5, "hello", STRTEST_GUARD_END);
	ret = StrCpy(NULL, 8, "abc");
	StrTestUint(ctx, "StrCpy to NULL returns 0", ret, 0);

	// A heap block of exactly size bytes (AddressSanitizer sees a write past it)
	p = Malloc(4);
	ret = StrCpy(p, 4, "abcdefgh");
	StrTestCheck(ctx, ret == 3 && StrCmp(p, "abc") == 0, "StrCpy into a heap block of size bytes truncates inside it",
		"returned %u, \"%s\"", ret, p);
	Free(p);

	StrTestHeap(ctx, "CopyStr copies the string", CopyStr("abc"), "abc");
	StrTestHeap(ctx, "CopyStr copies an empty string", CopyStr(""), "");
	p = CopyStr(NULL);
	StrTestCheck(ctx, p == NULL, "CopyStr(NULL) is NULL", "not NULL");

	b = StrTestReset(ctx, "abcdef");
	StrTestDst(ctx, "StrCpyAllowOverlap copies right over its own source", StrCpyAllowOverlap(b + 2, STRTEST_BUF_SIZE - 2, b), 6, "ababcdef", STRTEST_GUARD_END);
	b = StrTestReset(ctx, "abcdef");
	StrTestDst(ctx, "StrCpyAllowOverlap copies left over its own source", StrCpyAllowOverlap(b, STRTEST_BUF_SIZE, b + 2), 4, "cdef", sizeof("abcdef"));
	b = StrTestReset(ctx, "abcdef");
	StrTestDst(ctx, "StrCpyAllowOverlap truncates to size - 1 characters", StrCpyAllowOverlap(b + 1, 4, b), 3, "aabc", sizeof("abcdef"));
	b = StrTestReset(ctx, NULL);
	StrTestDst(ctx, "StrCpyAllowOverlap with size 0 copies without a limit", StrCpyAllowOverlap(b, 0, "abcdefghij"), 10, "abcdefghij", STRTEST_GUARD_END);
	b = StrTestReset(ctx, NULL);
	StrTestDst(ctx, "StrCpyAllowOverlap with size 0xFFFFFFFF copies without a limit, like size 0", StrCpyAllowOverlap(b, 0xFFFFFFFF, "abcdefghij"), 10, "abcdefghij", STRTEST_GUARD_END);
	b = StrTestReset(ctx, "abc");
	StrTestDst(ctx, "StrCpyAllowOverlap with size 1 writes only the terminator and returns 0", StrCpyAllowOverlap(b, 1, "xyz"), 0, "", sizeof("abc"));
	b = StrTestReset(ctx, "xy");
	StrTestDst(ctx, "StrCpyAllowOverlap of NULL writes the terminator and returns 0", StrCpyAllowOverlap(b, 8, NULL), 0, "", sizeof("xy"));
	b = StrTestReset(ctx, "hello");
	StrTestDst(ctx, "StrCpyAllowOverlap onto itself returns the length", StrCpyAllowOverlap(b, 2, b), 5, "hello", STRTEST_GUARD_END);

	b = StrTestReset(ctx, "abc");
	ClearStr(b, 8);
	StrTestOut(ctx, "ClearStr writes only the terminator", "", sizeof("abc"));

	StrTestHeap(ctx, "MakeCharArray repeats the character count times", MakeCharArray('x', 3), "xxx");
	StrTestHeap(ctx, "MakeCharArray with count 0 is an empty string", MakeCharArray('x', 0), "");
}

// StrCat and StrCatLeft
static void StrTestCat(STRTEST_CTX *ctx)
{
	char *b;
	UINT ret;

	b = StrTestReset(ctx, "ab");
	StrTestDst(ctx, "StrCat appends a string that fits and returns the new length", StrCat(b, 8, "cd"), 4, "abcd", STRTEST_GUARD_END);
	b = StrTestReset(ctx, "ab");
	StrTestDst(ctx, "StrCat fills size exactly with a result of size - 1 characters", StrCat(b, 5, "cd"), 4, "abcd", STRTEST_GUARD_END);
	b = StrTestReset(ctx, "ab");
	StrTestDst(ctx, "StrCat truncates to size - 1 characters and returns that length", StrCat(b, 5, "cdef"), 4, "abcd", STRTEST_GUARD_END);
	b = StrTestReset(ctx, "ab");
	StrTestDst(ctx, "StrCat with size 0 appends without a limit", StrCat(b, 0, "cdefghij"), 10, "abcdefghij", STRTEST_GUARD_END);
	b = StrTestReset(ctx, "ab");
	StrTestDst(ctx, "StrCat with size 0xFFFFFFFF appends without a limit, like size 0", StrCat(b, 0xFFFFFFFF, "cdefghij"), 10, "abcdefghij", STRTEST_GUARD_END);
	b = StrTestReset(ctx, "ab");
	StrTestDst(ctx, "StrCat of an empty string returns the length of the destination", StrCat(b, 8, ""), 2, "ab", STRTEST_GUARD_END);
	b = StrTestReset(ctx, "abcd");
	StrTestDst(ctx, "StrCat to a full destination changes nothing and returns 0", StrCat(b, 5, "e"), 0, "abcd", STRTEST_GUARD_END);
	b = StrTestReset(ctx, "abcd");
	StrTestDst(ctx, "StrCat of an empty string to a full destination returns its length", StrCat(b, 5, ""), 4, "abcd", STRTEST_GUARD_END);
	b = StrTestReset(ctx, "abcdef");
	StrTestDst(ctx, "StrCat to a destination longer than size changes nothing and returns 0", StrCat(b, 3, "x"), 0, "abcdef", STRTEST_GUARD_END);
	b = StrTestReset(ctx, "abcdef");
	StrTestDst(ctx, "StrCat of an empty string to a destination longer than size returns 0", StrCat(b, 3, ""), 0, "abcdef", STRTEST_GUARD_END);
	b = StrTestReset(ctx, "");
	StrTestDst(ctx, "StrCat with size 1 changes nothing and returns 0", StrCat(b, 1, "a"), 0, "", STRTEST_GUARD_END);
	b = StrTestReset(ctx, "");
	StrTestDst(ctx, "StrCat to an empty destination copies the string", StrCat(b, 8, "abc"), 3, "abc", STRTEST_GUARD_END);
	b = StrTestReset(ctx, "ab");
	StrTestDst(ctx, "StrCat of NULL changes nothing and returns 0", StrCat(b, 8, NULL), 0, "ab", STRTEST_GUARD_END);
	ret = StrCat(NULL, 8, "ab");
	StrTestUint(ctx, "StrCat to NULL returns 0", ret, 0);

	b = StrTestReset(ctx, "cd");
	StrTestDst(ctx, "StrCatLeft puts the string in front and returns the new length", StrCatLeft(b, 8, "ab"), 4, "abcd", STRTEST_GUARD_END);
	b = StrTestReset(ctx, "cd");
	StrTestDst(ctx, "StrCatLeft truncates to size - 1 characters", StrCatLeft(b, 4, "ab"), 3, "abc", STRTEST_GUARD_END);
}

// StrCheckLen
static void StrTestCheckLen(STRTEST_CTX *ctx)
{
	char raw[4] = {'a', 'a', 'a', 'a'};		// No terminator

	StrTestCheck(ctx, StrCheckLen("abc", 3), "StrCheckLen accepts a string of len characters", "returned false");
	StrTestCheck(ctx, StrCheckLen("abc", 2) == false, "StrCheckLen rejects a string of more than len characters", "returned true");
	StrTestCheck(ctx, StrCheckLen("", 0), "StrCheckLen accepts an empty string with len 0", "returned false");
	StrTestCheck(ctx, StrCheckLen("a", 0) == false, "StrCheckLen rejects a character with len 0", "returned true");
	StrTestCheck(ctx, StrCheckLen("abc", INFINITE), "StrCheckLen accepts a string with len INFINITE", "returned false");
	StrTestCheck(ctx, StrCheckLen("abc", INFINITE - 1), "StrCheckLen accepts a string with len INFINITE - 1", "returned false");
	StrTestCheck(ctx, StrCheckLen(NULL, 8) == false, "StrCheckLen(NULL) is false", "returned true");
	// AddressSanitizer sees a read past the array
	StrTestCheck(ctx, StrCheckLen(raw, sizeof(raw) - 1) == false, "StrCheckLen reads at most len + 1 characters", "returned true");
}

// ToStr, ToStr64, ToHex, BinToStr and BinToStrEx
static void StrTestFormat(STRTEST_CTX *ctx)
{
	UCHAR data[3] = {0x00, 0xAB, 0x7F};
	char *b;

	b = StrTestReset(ctx, NULL);
	ToStr(b, 0);
	StrTestOut(ctx, "ToStr(0) is \"0\"", "0", STRTEST_GUARD_END);
	b = StrTestReset(ctx, NULL);
	ToStr(b, 4294967295U);
	StrTestOut(ctx, "ToStr of the largest UINT has 10 digits", "4294967295", STRTEST_GUARD_END);
	b = StrTestReset(ctx, NULL);
	ToStr64(b, 0);
	StrTestOut(ctx, "ToStr64(0) is \"0\"", "0", STRTEST_GUARD_END);
	b = StrTestReset(ctx, NULL);
	ToStr64(b, 1234567890123ULL);
	StrTestOut(ctx, "ToStr64 writes the decimal digits", "1234567890123", STRTEST_GUARD_END);
	b = StrTestReset(ctx, NULL);
	ToStr64(b, 18446744073709551615ULL);
	StrTestOut(ctx, "ToStr64 of the largest UINT64 has 20 digits", "18446744073709551615", STRTEST_GUARD_END);
	b = StrTestReset(ctx, NULL);
	ToHex(b, 0);
	StrTestOut(ctx, "ToHex(0) is \"0\"", "0", STRTEST_GUARD_END);
	b = StrTestReset(ctx, NULL);
	ToHex(b, 0x1A);
	StrTestOut(ctx, "ToHex writes lower case digits without leading zeros", "1a", STRTEST_GUARD_END);
	b = StrTestReset(ctx, NULL);
	ToHex(b, 0xFFFFFFFF);
	StrTestOut(ctx, "ToHex of the largest UINT has 8 digits", "ffffffff", STRTEST_GUARD_END);

	b = StrTestReset(ctx, NULL);
	BinToStr(b, STRTEST_BUF_SIZE, data, sizeof(data));
	StrTestOut(ctx, "BinToStr writes two upper case digits per byte", "00AB7F", STRTEST_GUARD_END);
	b = StrTestReset(ctx, NULL);
	BinToStr(b, 4, data, sizeof(data));
	StrTestOut(ctx, "BinToStr truncates to str_size - 1 characters", "00A", STRTEST_GUARD_END);
	b = StrTestReset(ctx, NULL);
	BinToStr(b, STRTEST_BUF_SIZE, data, 0);
	StrTestOut(ctx, "BinToStr of no bytes writes an empty string", "", STRTEST_GUARD_END);
	b = StrTestReset(ctx, "xy");
	BinToStr(b, STRTEST_BUF_SIZE, NULL, sizeof(data));
	StrTestOut(ctx, "BinToStr of NULL writes an empty string", "", sizeof("xy"));

	b = StrTestReset(ctx, NULL);
	BinToStrEx(b, STRTEST_BUF_SIZE, data, sizeof(data));
	StrTestOut(ctx, "BinToStrEx separates the bytes with spaces", "00 AB 7F", STRTEST_GUARD_END);
	b = StrTestReset(ctx, NULL);
	BinToStrEx(b, 5, data, sizeof(data));
	StrTestOut(ctx, "BinToStrEx truncates to str_size - 1 characters", "00 A", STRTEST_GUARD_END);
	b = StrTestReset(ctx, NULL);
	BinToStrEx(b, STRTEST_BUF_SIZE, data, 0);
	StrTestOut(ctx, "BinToStrEx of no bytes writes an empty string", "", STRTEST_GUARD_END);
	b = StrTestReset(ctx, "xy");
	BinToStrEx(b, STRTEST_BUF_SIZE, NULL, sizeof(data));
	StrTestOut(ctx, "BinToStrEx of NULL leaves the destination as it is", "xy", STRTEST_GUARD_END);
}

// snprintf after the Mayaqua headers, and Format and UniFormat on the CRT formatter. Mayaqua.h once
// mapped snprintf to the legacy Microsoft variant, which leaves a truncated result without its
// terminator and returns -1.
static void StrTestSnprintf(STRTEST_CTX *ctx)
{
	char *b;
	char *six = "abcdef";		// Arguments, not literals, so the compiler does not report the truncation
	char *three = "abc";
	char wide[MAX_SIZE * 2];
	wchar_t uni[MAX_SIZE];
	UINT len, spaces;
	int ret;

	b = StrTestReset(ctx, NULL);
	ret = snprintf(b, 4, "%s", six);
	StrTestCheck(ctx, ret == 6 && b[3] == 0 && StrTestIs(ctx, "abc", STRTEST_GUARD_END),
		"snprintf truncates to size - 1 characters, ends them in NUL and returns the full length",
		"returned %d, buffer \"%s\"", ret, b);
	b = StrTestReset(ctx, NULL);
	ret = snprintf(b, 3, "%s", three);
	StrTestCheck(ctx, ret == 3 && b[2] == 0 && StrTestIs(ctx, "ab", STRTEST_GUARD_END),
		"snprintf of exactly size characters keeps size - 1 of them and the NUL",
		"returned %d, buffer \"%s\"", ret, b);

	// A field of 600 characters comes out whole: 599 spaces and the number
	Format(wide, sizeof(wide), "%600u", 7);
	len = StrLen(wide);
	spaces = 0;
	while (spaces < len && wide[spaces] == ' ')
	{
		spaces++;
	}
	StrTestCheck(ctx, len == 600 && spaces == 599 && wide[spaces] == '7',
		"Format of a numeric field of 600 characters gives the whole padded number",
		"%u characters, %u leading spaces", len, spaces);

	// The CRT pads %s by characters: a CJK character is one, not two (UniStrWidth)
	UniFormat(uni, sizeof(uni), L"%-6s|", L"\x4e2d");
	StrTestCheck(ctx, UniStrCmp(uni, L"\x4e2d     |") == 0,
		"UniFormat pads %-6s of one CJK character with 5 spaces", "got %u characters", UniStrLen(uni));

	// Size rules: a cut result keeps size - 1 characters and the terminator, size 1 leaves a wide
	// buffer as it is, and %S and %s swap between Format and UniFormat
	b = StrTestReset(ctx, NULL);
	Format(b, 4, "%s%S", "ab", L"cd");
	StrTestCheck(ctx, StrTestIs(ctx, "abc", STRTEST_GUARD_END), "Format cuts to size - 1 characters", "buffer \"%s\"", b);
	UniStrCpy(uni, sizeof(uni), L"xy");
	UniFormat(uni, 1, L"%u", 5);
	StrTestCheck(ctx, UniStrCmp(uni, L"xy") == 0, "UniFormat of size 1 leaves the buffer as it is", "changed");
	UniFormat(uni, sizeof(uni), L"%s|%S|%I64u|%llu|%s", L"w", "n", (UINT64)1 << 40, (UINT64)7, (wchar_t *)NULL);
	StrTestCheck(ctx, UniStrCmp(uni, L"w|n|1099511627776|7|(null)") == 0,
		"UniFormat formats %s, %S, %I64u, %llu and a NULL string", "got %u characters", UniStrLen(uni));
}

// SearchStr, SearchStrEx, InStr, InStrEx, ReplaceStr and ReplaceStri
static void StrTestSearch(STRTEST_CTX *ctx)
{
	char *b;

	StrTestUint(ctx, "SearchStr finds the first match", SearchStr("abcabc", "bc", 0), 1);
	StrTestUint(ctx, "SearchStr finds a match at the start", SearchStr("abcabc", "ab", 0), 0);
	StrTestUint(ctx, "SearchStr finds the first match at or after start", SearchStr("abcabc", "bc", 2), 4);
	StrTestUint(ctx, "SearchStr finds a match that ends the string", SearchStr("abcabc", "abc", 3), 3);
	StrTestUint(ctx, "SearchStr gives INFINITE when nothing matches", SearchStr("abcabc", "cb", 0), INFINITE);
	StrTestUint(ctx, "SearchStr gives INFINITE when the rest after start is too short", SearchStr("abcabc", "bc", 5), INFINITE);
	StrTestUint(ctx, "SearchStr gives INFINITE when start is at the end", SearchStr("abcabc", "bc", 6), INFINITE);
	StrTestUint(ctx, "SearchStr gives INFINITE when start is past the end", SearchStr("abcabc", "bc", 100), INFINITE);
	StrTestUint(ctx, "SearchStr gives INFINITE for a keyword longer than the string", SearchStr("abc", "abcd", 0), INFINITE);
	StrTestUint(ctx, "SearchStr gives INFINITE for an empty keyword", SearchStr("abc", "", 0), INFINITE);
	StrTestUint(ctx, "SearchStr gives INFINITE for a NULL string", SearchStr(NULL, "a", 0), INFINITE);
	StrTestUint(ctx, "SearchStr gives INFINITE for a NULL keyword", SearchStr("a", NULL, 0), INFINITE);
	StrTestUint(ctx, "SearchStrEx ignores the case when asked", SearchStrEx("aBcAbC", "abc", 1, false), 3);
	StrTestUint(ctx, "SearchStrEx keeps the case when asked", SearchStrEx("aBcAbC", "abc", 0, true), INFINITE);
	StrTestUint(ctx, "SearchStrEx folds only letters", SearchStrEx("x_Y", "_y", 0, false), 1);
	StrTestUint(ctx, "SearchStrEx folds only ASCII letters, not bytes above 127", SearchStrEx("\xe9X", "\xc9x", 0, false), INFINITE);

	// search_str_parity: UniSearchStrEx gives what SearchStrEx gives (FND-124)
	{
		static char *cases[][2] = {{"abc", "abc"}, {"abc", "ABC"}, {"abc", "abcd"}, {"abc", ""}, {"abcabc", "bc"}};
		UINT i, start, cs;

		for (i = 0;i < sizeof(cases) / sizeof(cases[0]);i++)
		{
			for (start = 0;start <= 1;start++)
			{
				for (cs = 0;cs <= 1;cs++)
				{
					wchar_t ws[16], wk[16];
					UINT a, w;

					StrToUni(ws, sizeof(ws), cases[i][0]);
					StrToUni(wk, sizeof(wk), cases[i][1]);
					a = SearchStrEx(cases[i][0], cases[i][1], start, cs != 0);
					w = UniSearchStrEx(ws, wk, start, cs != 0);
					StrTestCheck(ctx, a == w, "search_str_parity: UniSearchStrEx agrees with SearchStrEx",
						"\"%s\" in \"%s\" from %u, case %u: %u and %u", cases[i][1], cases[i][0], start, cs, a, w);
				}
			}
		}
	}

	StrTestCheck(ctx, InStr("Hello World", "WORLD"), "InStr ignores the case", "returned false");
	StrTestCheck(ctx, InStrEx("Hello World", "WORLD", true) == false, "InStrEx keeps the case when asked", "returned true");
	StrTestCheck(ctx, InStr("abc", "") == false, "InStr of an empty keyword is false", "returned true");

	b = StrTestReset(ctx, NULL);
	StrTestDst(ctx, "ReplaceStri replaces every match whatever its case", ReplaceStri(b, STRTEST_BUF_SIZE, "aXbxc", "x", "--"), 2, "a--b--c", STRTEST_GUARD_END);
	b = StrTestReset(ctx, NULL);
	StrTestDst(ctx, "ReplaceStr replaces only the matches of the same case", ReplaceStr(b, STRTEST_BUF_SIZE, "aXbxc", "x", "--"), 1, "aXb--c", STRTEST_GUARD_END);
	b = StrTestReset(ctx, NULL);
	StrTestDst(ctx, "ReplaceStr resumes the search after each match", ReplaceStr(b, STRTEST_BUF_SIZE, "aaa", "aa", "b"), 1, "ba", STRTEST_GUARD_END);
	b = StrTestReset(ctx, NULL);
	StrTestDst(ctx, "ReplaceStr truncates to size - 1 characters and returns the number of matches", ReplaceStr(b, 5, "abcabc", "b", "BB"), 2, "aBBc", STRTEST_GUARD_END);
}

// ParseToken, ParseTokenWithNullStr, IsSafeChar and IsSafeStr
static void StrTestChars(STRTEST_CTX *ctx)
{
	StrTestTokens(ctx, "ParseToken splits at any separator and drops empty tokens", ParseToken("a, b,,c", ", "), 3, "a|b|c");
	StrTestTokens(ctx, "ParseToken drops leading and trailing separators", ParseToken(", a ,b, ", ", "), 2, "a|b");
	StrTestTokens(ctx, "ParseToken with NULL separators splits at spaces, commas, tabs and line breaks", ParseToken("a\tb c,d\r\ne", NULL), 5, "a|b|c|d|e");
	StrTestTokens(ctx, "ParseToken with no separators gives the whole string", ParseToken("a b", ""), 1, "a b");
	StrTestTokens(ctx, "ParseToken of only separators gives no token", ParseToken(" ,, ", ", "), 0, "");
	StrTestTokens(ctx, "ParseToken of an empty string gives no token", ParseToken("", ","), 0, "");
	StrTestTokens(ctx, "ParseToken of NULL gives no token", ParseToken(NULL, ","), 0, "");
	StrTestTokens(ctx, "ParseToken splits at a separator byte above 127", ParseToken("a\xe9z", "\xe9"), 2, "a|z");
	StrTestTokens(ctx, "ParseTokenWithNullStr splits at a separator byte above 127", ParseTokenWithNullStr("a\xe9z", "\xe9"), 2, "a|z");
	StrTestTokens(ctx, "ParseTokenWithNullStr keeps empty tokens", ParseTokenWithNullStr("a,,b", ","), 3, "a||b");
	StrTestTokens(ctx, "ParseTokenWithNullStr keeps a leading and a trailing empty token", ParseTokenWithNullStr(",a;", ",;"), 3, "|a|");
	StrTestTokens(ctx, "ParseTokenWithNullStr of an empty string gives one empty token", ParseTokenWithNullStr("", ","), 1, "");
	StrTestTokens(ctx, "ParseTokenWithNullStr of NULL gives no token", ParseTokenWithNullStr(NULL, ","), 0, "");

	StrTestCheck(ctx, IsSafeChar('a') && IsSafeChar('&'), "IsSafeChar accepts a letter and '&'", "returned false");
	StrTestCheck(ctx, IsSafeChar('/') == false, "IsSafeChar rejects '/'", "returned true");
	StrTestCheck(ctx, IsSafeChar((char)0xE9) == false, "IsSafeChar rejects a byte of 0x80 and above", "returned true");
	StrTestCheck(ctx, IsSafeChar('\0') == false, "IsSafeChar rejects the terminator", "returned true");
	StrTestCheck(ctx, IsSafeStr("Ab-1_2"), "IsSafeStr accepts safe characters", "returned false");
	StrTestCheck(ctx, IsSafeStr(" ab") == false && IsSafeStr("ab ") == false, "IsSafeStr rejects a leading or trailing space", "returned true");
	StrTestCheck(ctx, IsSafeStr(""), "IsSafeStr accepts an empty string", "returned false");
	StrTestCheck(ctx, IsSafeStr(NULL) == false, "IsSafeStr(NULL) is false", "returned true");
}

// Trim, TrimLeft and TrimRight
static void StrTestTrim(STRTEST_CTX *ctx)
{
	char *b;

	b = StrTestReset(ctx, " \t a b \t ");
	Trim(b);
	StrTestOut(ctx, "Trim removes the leading and trailing spaces and tabs", "a b", sizeof(" \t a b \t "));
	b = StrTestReset(ctx, "\t a ");
	TrimLeft(b);
	StrTestOut(ctx, "TrimLeft removes only the leading spaces and tabs", "a ", sizeof("\t a "));
	b = StrTestReset(ctx, " a \t");
	TrimRight(b);
	StrTestOut(ctx, "TrimRight removes only the trailing spaces and tabs", " a", sizeof(" a \t"));
	b = StrTestReset(ctx, "a\r\n ");
	TrimRight(b);
	StrTestOut(ctx, "TrimRight keeps line breaks", "a\r\n", sizeof("a\r\n "));
	b = StrTestReset(ctx, "\r\n a");
	TrimLeft(b);
	StrTestOut(ctx, "TrimLeft keeps line breaks", "\r\n a", STRTEST_GUARD_END);
	b = StrTestReset(ctx, " \t ");
	Trim(b);
	StrTestOut(ctx, "Trim of only spaces and tabs gives an empty string", "", sizeof(" \t "));
	b = StrTestReset(ctx, "ab");
	Trim(b);
	StrTestOut(ctx, "Trim leaves a string without spaces as it is", "ab", STRTEST_GUARD_END);
	b = StrTestReset(ctx, "");
	Trim(b);
	StrTestOut(ctx, "Trim leaves an empty string as it is", "", STRTEST_GUARD_END);

	// A string literal is read-only: these calls fault if they write to a string they leave as it
	// is, even a write of the same value, which the fill-byte guard cannot see
	Trim("abc");
	TrimLeft("abc");
	TrimRight("abc");
	Trim("");
	TrimLeft("");
	TrimRight("");
	StrTestCheck(ctx, true, "Trim, TrimLeft and TrimRight do not write to a string they leave as it is", "");
}

// IsEmptyStr, UniIsEmptyStr, StartWith, UniStartWith, EndWith, UniEndWith, UniTrimLeft, UniTrimRight
// and UniSoftStrCmp (FND-167: they work in place)
static void StrTestEdge(STRTEST_CTX *ctx)
{
	wchar_t ub[STRTEST_BUF_SIZE];

	StrTestCheck(ctx, IsEmptyStr(NULL) && IsEmptyStr("") && IsEmptyStr(" \t") && IsEmptyStr(" a") == false,
		"IsEmptyStr is true for NULL, an empty string and blanks, false for a letter", "wrong result");
	StrTestCheck(ctx, UniIsEmptyStr(NULL) && UniIsEmptyStr(L"") && UniIsEmptyStr(L" \t") && UniIsEmptyStr(L" a") == false,
		"UniIsEmptyStr is true for NULL, an empty string and blanks, false for a letter", "wrong result");

	StrTestCheck(ctx, StartWith("Abc", "aB") && StartWith("abc", "abc") && StartWith("ab", "abc") == false,
		"StartWith ignores the case and needs the whole key", "wrong result");
	StrTestCheck(ctx, StartWith("", "") == false && StartWith("a", "") == false && StartWith("", "a") == false &&
		StartWith(NULL, "a") == false && StartWith("a", NULL) == false,
		"StartWith is false for an empty or NULL string or key", "wrong result");
	StrTestCheck(ctx, StartWith("\xe9", "\xc9") == false, "StartWith folds only ASCII letters", "returned true");
	StrTestCheck(ctx, UniStartWith(L"Abc", L"aB") && UniStartWith(L"abc", L"abc") && UniStartWith(L"ab", L"abc") == false,
		"UniStartWith ignores the case and needs the whole key", "wrong result");
	StrTestCheck(ctx, UniStartWith(L"", L"") == false && UniStartWith(L"a", L"") == false && UniStartWith(L"", L"a") == false &&
		UniStartWith(NULL, L"a") == false && UniStartWith(L"a", NULL) == false,
		"UniStartWith is false for an empty or NULL string or key", "wrong result");
	StrTestCheck(ctx, UniStartWith(L"\xe9", L"\xc9") == false, "UniStartWith folds only ASCII letters", "returned true");

	StrTestCheck(ctx, EndWith("abC", "Bc") && EndWith("abc", "") && EndWith("", "") && EndWith("c", "bc") == false && EndWith("\xe9", "\xc9") == false,
		"EndWith ignores the case of ASCII letters, and an empty key always matches", "wrong result");
	StrTestCheck(ctx, UniEndWith(L"abC", L"Bc") && UniEndWith(L"abc", L"") && UniEndWith(L"", L"") && UniEndWith(L"c", L"bc") == false && UniEndWith(L"\xe9", L"\xc9") == false,
		"UniEndWith ignores the case of ASCII letters, and an empty key always matches", "wrong result");

	UniStrCpy(ub, sizeof(ub), L" \t a b \t ");
	UniTrimLeft(ub);
	StrTestCheck(ctx, UniStrCmp(ub, L"a b \t ") == 0, "UniTrimLeft removes only the leading blanks", "wrong result");
	UniStrCpy(ub, sizeof(ub), L" \t a b \t ");
	UniTrimRight(ub);
	StrTestCheck(ctx, UniStrCmp(ub, L" \t a b") == 0, "UniTrimRight removes only the trailing blanks", "wrong result");
	UniStrCpy(ub, sizeof(ub), L" \t ");
	UniTrimLeft(ub);
	StrTestCheck(ctx, UniStrLen(ub) == 0, "UniTrimLeft of only blanks gives an empty string", "wrong result");
	UniStrCpy(ub, sizeof(ub), L" \t ");
	UniTrimRight(ub);
	StrTestCheck(ctx, UniStrLen(ub) == 0, "UniTrimRight of only blanks gives an empty string", "wrong result");

	StrTestInt(ctx, "UniSoftStrCmp ignores the outer blanks and the case", UniSoftStrCmp(L" \tAbc ", L"aBC\t"), 0);
	StrTestInt(ctx, "UniSoftStrCmp keeps the inner blanks", UniSoftStrCmp(L"a b", L"ab"), -1);
	StrTestInt(ctx, "UniSoftStrCmp sorts a prefix first", UniSoftStrCmp(L" ab ", L"abc"), -1);
	StrTestInt(ctx, "UniSoftStrCmp of blanks and an empty string is 0", UniSoftStrCmp(L"  ", L""), 0);
	StrTestInt(ctx, "UniSoftStrCmp(NULL, string) is 1", UniSoftStrCmp(NULL, L"a"), 1);
	StrTestInt(ctx, "UniSoftStrCmp(string, NULL) is -1", UniSoftStrCmp(L"a", NULL), -1);
}

// StrCmp and StrCmpi
static void StrTestCompare(STRTEST_CTX *ctx)
{
	// StrCmpi compares char values, so the sign for a byte of 0x80 and above follows the char type
	char high = (char)0x80;
	int high_vs_letter = (high < 'A') ? -1 : 1;

	StrTestInt(ctx, "StrCmpi ignores the case of letters", StrCmpi("abc", "ABC"), 0);
	StrTestInt(ctx, "StrCmpi gives -1 for a smaller string", StrCmpi("abc", "ABD"), -1);
	StrTestInt(ctx, "StrCmpi gives 1 for a larger string", StrCmpi("abd", "ABC"), 1);
	StrTestInt(ctx, "StrCmpi sorts a prefix first", StrCmpi("ab", "abc"), -1);
	StrTestInt(ctx, "StrCmpi sorts a longer string last", StrCmpi("abc", "ab"), 1);
	StrTestInt(ctx, "StrCmpi folds to upper case, so '_' sorts after the letters", StrCmpi("_", "a"), 1);
	StrTestInt(ctx, "StrCmpi folds to upper case, so the letters sort before '_'", StrCmpi("a", "_"), -1);
	StrTestInt(ctx, "StrCmpi compares bytes as char values", StrCmpi("\x80", "a"), high_vs_letter);
	StrTestInt(ctx, "StrCmpi(NULL, NULL) is 0", StrCmpi(NULL, NULL), 0);
	StrTestInt(ctx, "StrCmpi(NULL, string) is 1", StrCmpi(NULL, "a"), 1);
	StrTestInt(ctx, "StrCmpi(string, NULL) is -1", StrCmpi("a", NULL), -1);

	StrTestCheck(ctx, StrCmp("a", "b") < 0 && StrCmp("b", "a") > 0 && StrCmp("a", "a") == 0, "StrCmp orders like strcmp", "wrong sign");
	StrTestCheck(ctx, StrCmp("a", "A") != 0, "StrCmp keeps the case", "returned 0");
	StrTestInt(ctx, "StrCmp(NULL, NULL) is 0", StrCmp(NULL, NULL), 0);
	StrTestInt(ctx, "StrCmp(NULL, string) is 1", StrCmp(NULL, "a"), 1);
	StrTestInt(ctx, "StrCmp(string, NULL) is -1", StrCmp("a", NULL), -1);
}

// str: truncation and return values of the string functions
void str_test(UINT num, char **arg)
{
	STRTEST_CTX ctx;

	Zero(&ctx, sizeof(ctx));

	Print("String functions test\n");

	StrTestCopy(&ctx);
	StrTestCat(&ctx);
	StrTestCheckLen(&ctx);
	StrTestFormat(&ctx);
	StrTestSnprintf(&ctx);
	StrTestSearch(&ctx);
	StrTestChars(&ctx);
	StrTestTrim(&ctx);
	StrTestEdge(&ctx);
	StrTestCompare(&ctx);

	if (ctx.NumFailed == 0)
	{
		Print("STR TEST OK\n");
	}
	else
	{
		Print("STR TEST FAILED (%u of %u checks failed)\n", ctx.NumFailed, ctx.NumChecks);
	}
}
