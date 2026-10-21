// packdecode.c
// Named PACK decoder bounds test of vpntest ("pack_decode_bounds" command, FND-42 #114)
//
// BufToPack() decodes every PACK a peer sends, also before the authentication (HttpServerRecv,
// at most HTTP_PACK_MAX_SIZE bytes). ReadElement() and ReadValue() allocated from the counts and
// sizes the peer claimed before they checked that the bytes were there:
// - an element of 13 bytes that claims 262144 INT values made 262144 values of 0 (ReadBufInt reads
//   0 past the end), about 20 MB;
// - a VALUE_DATA size of 0x10000000 allocated 256 MiB before the read of the 4 bytes present;
// - a value that could not be read (an unknown type, a size past the end) stayed in the element as
//   a NULL value, and the PACK was accepted.
//
// The test feeds BufToPack() malformed PACKs that must each be rejected, measures the bytes the
// first three allocate (KS_TOTAL_MEM_SIZE, counted while memory tracking is on, as in vpntest), and
// checks that a valid PACK with every value type, multi-value elements and empty values still
// decodes and encodes to the same bytes. Prints "PACK_DECODE_BOUNDS TEST OK" only when every check
// passes, and frees everything it allocates.

#include "Mayaqua/Internat.h"
#include "Mayaqua/Mayaqua.h"
#include "Mayaqua/Memory.h"
#include "Mayaqua/Pack.h"
#include "Mayaqua/Str.h"
#include "Mayaqua/Tracking.h"

#include <stdarg.h>

#define	PACKDECODE_ALLOC_MAX		(64 * 1024)		// Bytes a rejected PACK of the first vectors may allocate

// Run state of the test
typedef struct PACKDECODE_CTX
{
	UINT NumChecks;						// Checks run so far
	UINT NumFailed;						// Checks failed so far
} PACKDECODE_CTX;

// Record one check: print [PASS], or [FAIL] with the formatted detail
static void PackDecodeCheck(PACKDECODE_CTX *ctx, bool ok, char *what, char *detail_fmt, ...)
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

// A PACK of one element: the element count, then the name, type and value count of the element.
// The caller writes the values.
static BUF *PackDecodeOneElement(UINT type, UINT num_value)
{
	BUF *b = NewBuf();

	WriteBufInt(b, 1);
	WriteBufStr(b, "a");
	WriteBufInt(b, type);
	WriteBufInt(b, num_value);

	return b;
}

// Decodes b from its beginning and frees it. True when BufToPack() rejects it; *alloc gets the
// bytes allocated meanwhile.
static bool PackDecodeRejects(BUF *b, UINT64 *alloc)
{
	PACK *p;
	UINT64 before;

	SeekBufToBegin(b);

	before = KS_GET64(KS_TOTAL_MEM_SIZE);
	p = BufToPack(b);
	*alloc = KS_GET64(KS_TOTAL_MEM_SIZE) - before;

	FreeBuf(b);

	if (p != NULL)
	{
		FreePack(p);
		return false;
	}

	return true;
}

// One malformed PACK: it must be rejected, and with bounded set, allocate under PACKDECODE_ALLOC_MAX
static void PackDecodeTestReject(PACKDECODE_CTX *ctx, BUF *b, bool bounded, char *what)
{
	UINT64 alloc = 0;
	char tmp[MAX_SIZE];

	PackDecodeCheck(ctx, PackDecodeRejects(b, &alloc), what, "BufToPack returned a PACK");

	if (bounded)
	{
		Format(tmp, sizeof(tmp), "  ... and allocates under %u bytes", PACKDECODE_ALLOC_MAX);
		PackDecodeCheck(ctx, IsTrackingEnabled() && alloc < PACKDECODE_ALLOC_MAX, tmp,
			"%I64u bytes allocated, memory tracking %s", alloc, IsTrackingEnabled() ? "on" : "off");
	}
}

// Malformed PACKs: counts and sizes past the bytes present, an unknown type, values cut short
static void PackDecodeTestMalformed(PACKDECODE_CTX *ctx)
{
	BUF *b;

	// 13 bytes after the element count, no values
	b = PackDecodeOneElement(VALUE_INT, MAX_VALUE_NUM);
	PackDecodeTestReject(ctx, b, true,
		"VALUE_INT with 262144 values and no payload is rejected (the old decoder made 262144 values of 0)");

	b = PackDecodeOneElement(7, 1);
	WriteBufInt(b, 0);
	PackDecodeTestReject(ctx, b, true,
		"an unknown value type 7 is rejected (the old decoder kept a NULL value)");

	b = PackDecodeOneElement(VALUE_DATA, 1);
	WriteBufInt(b, 0x10000000);
	WriteBuf(b, "abcd", 4);
	PackDecodeTestReject(ctx, b, true,
		"VALUE_DATA of size 0x10000000 with 4 bytes present is rejected before it allocates (the old decoder allocated 256 MiB)");

	b = PackDecodeOneElement(VALUE_STR, 2);
	WriteBufInt(b, 3);
	WriteBuf(b, "abc", 3);
	WriteBufInt(b, 10);
	WriteBuf(b, "abc", 3);
	PackDecodeTestReject(ctx, b, false,
		"two VALUE_STR values with the second cut short are rejected (the old decoder kept a NULL value)");

	b = PackDecodeOneElement(VALUE_INT64, 2);
	WriteBufInt64(b, 1);
	WriteBufInt(b, 2);
	PackDecodeTestReject(ctx, b, false,
		"two VALUE_INT64 values in 12 bytes are rejected (the old decoder read the second as 0)");

	b = PackDecodeOneElement(VALUE_DATA, 2);
	WriteBufInt(b, 4);
	WriteBuf(b, "abcd", 4);
	PackDecodeTestReject(ctx, b, false,
		"a second VALUE_DATA value without its size is rejected (the old decoder read an empty value)");

	b = PackDecodeOneElement(VALUE_UNISTR, 1);
	WriteBufInt(b, 0x7FFFFFFF);
	WriteBuf(b, "abcd", 4);
	PackDecodeTestReject(ctx, b, false,
		"VALUE_UNISTR of size 0x7FFFFFFF with 4 bytes present is rejected");

	b = NewBuf();
	WriteBufInt(b, 1000);
	WriteBufStr(b, "a");
	WriteBufInt(b, VALUE_INT);
	WriteBufInt(b, 1);
	WriteBufInt(b, 5);
	PackDecodeTestReject(ctx, b, false, "an element count of 1000 with one element present is rejected");
}

// A valid PACK with every value type, multi-value elements and empty values decodes, and encodes
// to the same bytes again
static void PackDecodeTestValid(PACKDECODE_CTX *ctx)
{
	PACK *p = NewPack();
	PACK *p2;
	BUF *b1, *b2 = NULL;
	UCHAR data[20];
	wchar_t uni[64];
	char str[64];

	for (UINT i = 0;i < sizeof(data);i++)
	{
		data[i] = (UCHAR)i;
	}

	PackAddInt(p, "int", 0x12345678);
	PackAddInt64(p, "int64", 0x0000019A2B3C4D5EULL);
	PackAddData(p, "data", data, sizeof(data));
	PackAddData(p, "data_empty", data, 0);
	PackAddStr(p, "str", "Ranz VPN");
	PackAddStr(p, "str_empty", "");
	PackAddUniStr(p, "unistr", L"Ranz \x00e9\x65e5");
	PackAddUniStr(p, "unistr_empty", L"");
	for (UINT i = 0;i < 3;i++)
	{
		PackAddIntEx(p, "ints", 443 + i, i, 3);
		PackAddStrEx(p, "strs", (i == 1 ? "" : "x"), i, 3);
		PackAddDataEx(p, "datas", data, i * 4, i, 3);
	}

	b1 = PackToBuf(p);
	SeekBufToBegin(b1);
	p2 = BufToPack(b1);
	if (p2 != NULL)
	{
		b2 = PackToBuf(p2);
	}

	PackDecodeCheck(ctx, p2 != NULL && CompareBuf(b1, b2),
		"a valid PACK with every value type, multi-value elements and empty values decodes and encodes to the same bytes",
		"%s", p2 == NULL ? "BufToPack returned NULL" : "the bytes differ");

	if (p2 != NULL)
	{
		PackGetUniStr(p2, "unistr", uni, sizeof(uni));
		PackGetStrEx(p2, "strs", str, sizeof(str), 2);

		PackDecodeCheck(ctx, PackGetInt(p2, "int") == 0x12345678 && PackGetInt64(p2, "int64") == 0x0000019A2B3C4D5EULL &&
			PackGetDataSize(p2, "data") == sizeof(data) && PackGetIntEx(p2, "ints", 2) == 445 &&
			PackGetDataSizeEx(p2, "datas", 2) == 8 && StrCmp(str, "x") == 0 && UniStrCmp(uni, L"Ranz \x00e9\x65e5") == 0,
			"the decoded values are the encoded ones", "a value differs");
	}

	FreeBuf(b1);
	FreeBuf(b2);
	FreePack(p2);
	FreePack(p);
}

// pack_decode_bounds: the PACK decoder against counts and sizes past the bytes present
void pack_decode_bounds_test(UINT num, char **arg)
{
	PACKDECODE_CTX ctx;

	Zero(&ctx, sizeof(ctx));

	Print("PACK decoder bounds test (BufToPack)\n");

	PackDecodeTestValid(&ctx);
	PackDecodeTestMalformed(&ctx);

	if (ctx.NumFailed == 0)
	{
		Print("PACK_DECODE_BOUNDS TEST OK\n");
	}
	else
	{
		Print("PACK_DECODE_BOUNDS TEST FAILED (%u of %u checks failed)\n", ctx.NumFailed, ctx.NumChecks);
	}
}
