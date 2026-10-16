// crypto.c
// Known-answer tests of the Mayaqua hash, cipher and random primitives ("crypto" command of vpntest)
//
// Pins the outputs that ticket #87 must keep when MD4, MD5, SHA-1, RC4, DES and the random
// generator move from OpenSSL to CNG, plus SHA-0 (own code: CNG has no SHA-0) and SHA-256
// (stays on OpenSSL). The hash vectors are the RFC 1320 and RFC 1321 test suites and the FIPS 180
// messages, the RC4 vectors come from RFC 6229 and the DES vectors from FIPS 81 and the DES
// literature; a value marked "computed" was made with two independent implementations. All of
// them hold for the OpenSSL code and for CNG alike, so the test runs against both. The one
// exception is the 65-byte RC4 key, which pins the CNG code: Encrypt() writes zeros for it.
// The test prints "CRYPTO TEST OK" only when every check passes, and frees everything it
// allocates, so that the run still ends with "NO MEMORY LEAKS". The [PASS] lines carry only
// fixed values; the [FAIL] details show what was computed.

#include "Cedar/Account.h"

#include "Mayaqua/Encrypt.h"
#include "Mayaqua/Memory.h"
#include "Mayaqua/Str.h"

#include <stdarg.h>
#include <string.h>

// Sizes and limits
#define	KAT_MD4_SIZE			16			// MD4 digest (bytes)
#define	KAT_MAX_DIGEST			SHA256_SIZE	// Largest digest under test (bytes)
#define	KAT_MILLION				1000000		// Length of the one-million 'a' message
#define	KAT_NUM_MESSAGES		9			// Messages of the hash suite
#define	KAT_RC4_BLOCK			16			// Keystream bytes compared per RC4 vector
#define	KAT_RC4_LONG			4096		// Offset of the RFC 6229 vector at 4096
#define	KAT_RC4_LONG_KEY		65			// RC4 key one byte longer than CNG makes into real RC4
#define	KAT_RAND_BULK			65536		// Bytes drawn for the random generator statistics
#define	KAT_RAND_MAX_SKEW		2200		// Allowed distance of the 1-bit count from its mean (about 6 sigma)
#define	KAT_RAND_DRAWS			64			// Draws of each RandN function
#define	KAT_GUARD				16			// Guard bytes after an output buffer
#define	KAT_GUARD_BYTE			0xA5		// Value of the guard bytes

// Run state of the test
typedef struct KAT_CTX
{
	UINT NumChecks;					// Checks run so far
	UINT NumFailed;					// Checks failed so far
} KAT_CTX;

// Hash function under test: every Mayaqua hash has this signature
typedef void (KAT_HASH_PROC)(void *dst, void *src, UINT size);

// Messages of the hash suite: RFC 1320 / RFC 1321 section A.5, then the two FIPS 180 messages.
// NULL stands for one million times 'a'.
static char *kat_messages[KAT_NUM_MESSAGES] =
{
	"",
	"a",
	"abc",
	"message digest",
	"abcdefghijklmnopqrstuvwxyz",
	"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
	"12345678901234567890123456789012345678901234567890123456789012345678901234567890",
	"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
	NULL,
};

// Labels of the messages in the [PASS] and [FAIL] lines
static char *kat_labels[KAT_NUM_MESSAGES] =
{
	"empty",
	"\"a\"",
	"\"abc\"",
	"\"message digest\"",
	"a to z",
	"A to Z, a to z, 0 to 9",
	"8 times 1234567890",
	"448-bit FIPS 180 message",
	"one million 'a'",
};

// MD4: RFC 1320 section A.5 for the first seven, computed for the last two
static char *kat_md4[KAT_NUM_MESSAGES] =
{
	"31D6CFE0D16AE931B73C59D7E0C089C0",
	"BDE52CB31DE33E46245E05FBDBD6FB24",
	"A448017AAF21D8525FC10AE87AA6729D",
	"D9130A8164549FE818874806E1C7014B",
	"D79E1C308AA5BBCDEEA8ED63DF412DA9",
	"043F8582F241DB351CE627E153E7F0E4",
	"E33B4DDC9C38F2199C3E7B164FCC0536",
	"4691A9EC81B1A6BD1AB8557240B245C5",
	"BBCE80CC6BB65E5C6745E30D4EECA9A4",
};

// MD5: RFC 1321 section A.5 for the first seven, computed for the last two
static char *kat_md5[KAT_NUM_MESSAGES] =
{
	"D41D8CD98F00B204E9800998ECF8427E",
	"0CC175B9C0F1B6A831C399E269772661",
	"900150983CD24FB0D6963F7D28E17F72",
	"F96B697D7CB7938D525A2F31AAF161D0",
	"C3FCD3D76192E4007DFB496CCA67E13B",
	"D174AB98D277D9F5A5611C2C9F419D9F",
	"57EDF4A22BE3C955AC49DA2E2107B67A",
	"8215EF0796A20BCAAAE116D3876C664A",
	"7707D6AE4E027C70EEA2A935C2296F21",
};

// SHA-0: FIPS 180 (1993) appendix A and B for "abc" and the 448-bit message, computed for the others
static char *kat_sha0[KAT_NUM_MESSAGES] =
{
	"F96CEA198AD1DD5617AC084A3D92C6107708C0EF",
	"37F297772FAE4CB1BA39B6CF9CF0381180BD62F2",
	"0164B8A914CD2A5E74C4F7FF082C4D97F1EDF880",
	"C1B0F222D150EBB9AA36A40CAFDC8BCBED830B14",
	"B40CE07A430CFD3C033039B9FE9AFEC95DC1BDCD",
	"79E966F7A3A990DF33E40E3D7F8F18D2CAEBADFA",
	"4AA29D14D171522ECE47BEE8957E35A41F3E9CFF",
	"D2516EE1ACFA5BAF33DFC1C471E438449EF134C8",
	"3232AFFA48628A26653B5AAA44541FD90D690603",
};

// SHA-1: FIPS 180-2 appendix A and RFC 3174 for "abc", the 448-bit message and one million 'a'
static char *kat_sha1[KAT_NUM_MESSAGES] =
{
	"DA39A3EE5E6B4B0D3255BFEF95601890AFD80709",
	"86F7E437FAA5A7FCE15D1DDCB9EAEAEA377667B8",
	"A9993E364706816ABA3E25717850C26C9CD0D89D",
	"C12252CEDA8BE8994D5FA0290A47231C1D16AAE3",
	"32D10C7B8CF96570CA04CE37F2A19D84240D3A89",
	"761C457BF73B14D27E9E9265C46F4B4DDA11F940",
	"50ABF5706A150990A08B2C5EA40FA0E585554732",
	"84983E441C3BD26EBAAE4AA1F95129E5E54670F1",
	"34AA973CD4C4DAA4F61EEB2BDBAD27316534016F",
};

// SHA-256: FIPS 180-2 appendix B for "abc", the 448-bit message and one million 'a'
static char *kat_sha256[KAT_NUM_MESSAGES] =
{
	"E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855",
	"CA978112CA1BBDCAFAC231B39A23DC4DA786EFF8147C4E72B9807785AFEE48BB",
	"BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD",
	"F7846F55CF23E14EEBEAB5B4E1550CAD5B509E3348FBC4EFA3A1413D393CB650",
	"71C480DF93D6AE2F1EFAD1447C66C9525E316218CF51FC8D9ED832F2DAF18B73",
	"DB4BFCBD4DA0CD85A60C3C37D3FBD8805C77F15FC6B1FDFE614EE0A7C8FDB4C0",
	"F371BC4A311F2B009EEF952DD83CA80E2B60026C8E935592D0F9C308453C813E",
	"248D6A61D20638B8E5C026930C3E6039A33CE45964FF2167F6ECEDD419DB06C1",
	"CDC76E5C9914FB9281A1C7E284D73E67F1809A48A497200E046D39CCC7112CD0",
};

// Record one check: print [PASS], or [FAIL] with the formatted detail
static bool KatCheck(KAT_CTX *ctx, bool ok, char *what, char *detail_fmt, ...)
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

// Compare bytes with a hex string; got receives the hex of the bytes
static bool KatHexEq(void *data, UINT size, char *expect_hex, char *got, UINT got_size)
{
	BinToStr(got, got_size, data, size);

	return StrCmpi(got, expect_hex) == 0;
}

// Whether every byte of the buffer has the value
static bool KatAllBytes(UCHAR *buf, UINT size, UCHAR value)
{
	UINT i;

	for (i = 0;i < size;i++)
	{
		if (buf[i] != value)
		{
			return false;
		}
	}

	return true;
}

// Run the hash suite on one hash function, then its edge cases
static void KatHashSuite(KAT_CTX *ctx, char *name, KAT_HASH_PROC *proc, UINT digest_size, char **expect, UCHAR *million)
{
	UCHAR digest[KAT_MAX_DIGEST + KAT_GUARD];
	UCHAR buf[KAT_MAX_DIGEST];
	char got[KAT_MAX_DIGEST * 2 + 1];
	char what[MAX_SIZE];
	UINT i;

	for (i = 0;i < KAT_NUM_MESSAGES;i++)
	{
		void *msg = kat_messages[i];
		UINT msg_size = (kat_messages[i] == NULL ? KAT_MILLION : StrLen(kat_messages[i]));

		if (kat_messages[i] == NULL)
		{
			msg = million;
		}

		// The digest must not run past its size
		Zero(digest, sizeof(digest));
		memset(digest + digest_size, KAT_GUARD_BYTE, KAT_GUARD);

		proc(digest, msg, msg_size);

		Format(what, sizeof(what), "%s(%s) = %s", name, kat_labels[i], expect[i]);
		KatCheck(ctx, KatHexEq(digest, digest_size, expect[i], got, sizeof(got)) &&
			KatAllBytes(digest + digest_size, KAT_GUARD, KAT_GUARD_BYTE), what, "got %s", got);
	}

	// No source and size 0 is the empty message
	Zero(digest, sizeof(digest));
	proc(digest, NULL, 0);
	Format(what, sizeof(what), "%s(NULL, 0) is the digest of the empty message", name);
	KatCheck(ctx, KatHexEq(digest, digest_size, expect[0], got, sizeof(got)), what, "got %s", got);

	// No source and a size leaves the destination as it was
	memset(digest, KAT_GUARD_BYTE, sizeof(digest));
	proc(digest, NULL, 3);
	Format(what, sizeof(what), "%s(NULL, 3) leaves the destination unchanged", name);
	KatCheck(ctx, KatAllBytes(digest, sizeof(digest), KAT_GUARD_BYTE), what, "destination was written");

	// No destination is ignored
	proc(NULL, "abc", 3);
	Format(what, sizeof(what), "%s with no destination returns", name);
	KatCheck(ctx, true, what, "");

	// Destination and source in the same buffer
	Zero(buf, sizeof(buf));
	Copy(buf, "abc", 3);
	proc(buf, buf, 3);
	Format(what, sizeof(what), "%s in place (destination is the source \"abc\")", name);
	KatCheck(ctx, KatHexEq(buf, digest_size, expect[2], got, sizeof(got)), what, "got %s", got);
}

// HashPassword() of Account.c: SHA-0 of the password followed by the upper case user name
static void KatHashPassword(KAT_CTX *ctx, char *username, char *password, char *expect_hex)
{
	UCHAR hash[SHA1_SIZE];
	char got[SHA1_SIZE * 2 + 1];
	char what[MAX_SIZE];

	Zero(hash, sizeof(hash));
	HashPassword(hash, username, password);

	Format(what, sizeof(what), "HashPassword(\"%s\", \"%s\") = %s (computed)", username, password, expect_hex);
	KatCheck(ctx, KatHexEq(hash, sizeof(hash), expect_hex, got, sizeof(got)), what, "got %s", got);
}

// RC4 keystream: bytes [offset, offset + 16) of the key, by encrypting zeros. With split set, the
// bytes before the offset are encrypted by a first Encrypt() call and the 16 bytes by a second,
// so the key must carry its keystream position from one call to the next.
static void KatRc4Stream(KAT_CTX *ctx, char *key_hex, UINT offset, bool split, char *expect_hex, char *source)
{
	BUF *key = StrToBin(key_hex);
	UINT size = offset + KAT_RC4_BLOCK;
	UCHAR *zero = ZeroMalloc(size);
	UCHAR *out = ZeroMalloc(size + KAT_GUARD);
	char got[KAT_RC4_BLOCK * 2 + 1];
	char what[MAX_SIZE];
	CRYPT *c;

	memset(out + size, KAT_GUARD_BYTE, KAT_GUARD);

	c = NewCrypt(key->Buf, key->Size);
	if (split && offset != 0)
	{
		Encrypt(c, out, zero, offset);
		Encrypt(c, out + offset, zero + offset, KAT_RC4_BLOCK);
	}
	else
	{
		Encrypt(c, out, zero, size);
	}
	FreeCrypt(c);

	Format(what, sizeof(what), "RC4 key %s, keystream at %u%s = %s (%s)", key_hex, offset,
		(split && offset != 0) ? " after a separate call" : "", expect_hex, source);
	KatCheck(ctx, KatHexEq(out + offset, KAT_RC4_BLOCK, expect_hex, got, sizeof(got)) &&
		KatAllBytes(out + size, KAT_GUARD, KAT_GUARD_BYTE), what, "got %s", got);

	Free(out);
	Free(zero);
	FreeBuf(key);
}

// RC4 of a text with a text key; in_place encrypts the text in its own buffer
static void KatRc4Text(KAT_CTX *ctx, char *key, char *text, bool in_place, char *expect_hex, char *source)
{
	UINT size = StrLen(text);
	UCHAR buf[MAX_SIZE];
	UCHAR out[MAX_SIZE];
	char got[MAX_SIZE];
	char what[MAX_SIZE];
	UCHAR *dst = (in_place ? buf : out);
	CRYPT *c;

	Zero(buf, sizeof(buf));
	Zero(out, sizeof(out));
	Copy(buf, text, size);

	c = NewCrypt(key, StrLen(key));
	Encrypt(c, dst, buf, size);
	FreeCrypt(c);

	Format(what, sizeof(what), "RC4 key \"%s\", \"%s\"%s = %s (%s)", key, text, in_place ? " in place" : "", expect_hex, source);
	KatCheck(ctx, KatHexEq(dst, size, expect_hex, got, sizeof(got)), what, "got %s", got);
}

// The RC4 checks
static void KatRc4(KAT_CTX *ctx)
{
	UCHAR key[8];
	UCHAR in[8];
	UCHAR out[8];
	UCHAR back[8];
	UCHAR long_key[KAT_RC4_LONG_KEY];
	char got[sizeof(out) * 2 + 1];
	CRYPT *c;

	// RFC 6229 section 2: 40, 64 and 128-bit keys
	KatRc4Stream(ctx, "0102030405", 0, false, "B2396305F03DC027CCC3524A0A1118A8", "RFC 6229");
	KatRc4Stream(ctx, "0102030405", 16, false, "6982944F18FC82D589C403A47A0D0919", "RFC 6229");
	KatRc4Stream(ctx, "0102030405", KAT_RC4_LONG, false, "FF25B58995996707E51FBDF08B34D875", "RFC 6229");
	KatRc4Stream(ctx, "0102030405060708", 0, false, "97AB8A1BF0AFB96132F2F67258DA15A8", "RFC 6229");
	KatRc4Stream(ctx, "0102030405060708", 16, false, "8263EFDB45C4A18684EF87E6B19E5B09", "RFC 6229");
	KatRc4Stream(ctx, "0102030405060708090A0B0C0D0E0F10", 0, false, "9AC7CC9A609D1EF7B2932899CDE41B97", "RFC 6229");
	KatRc4Stream(ctx, "0102030405060708090A0B0C0D0E0F10", KAT_RC4_LONG, false, "A36A4C301AE8AC13610CCBC12256CACC", "RFC 6229");

	// The 20-byte key size of UDP acceleration V1
	KatRc4Stream(ctx, "0102030405060708090A0B0C0D0E0F1011121314", 0, false, "F644D3AA1F242C35F51B71D4FAF55383", "computed");

	// The keystream continues from one Encrypt() call to the next
	KatRc4Stream(ctx, "0102030405", 16, true, "6982944F18FC82D589C403A47A0D0919", "RFC 6229");
	KatRc4Stream(ctx, "0102030405", KAT_RC4_LONG, true, "FF25B58995996707E51FBDF08B34D875", "RFC 6229");
	KatRc4Stream(ctx, "0102030405060708090A0B0C0D0E0F10", 7, true, "F7B2932899CDE41B975248C495901412", "RFC 6229, offset 7");

	// Short text keys, and the 8-byte key of EncryptPassword() in Account.c ("EncryptP")
	KatRc4Text(ctx, "Key", "Plaintext", false, "BBF316E8D940AF0AD3", "published");
	KatRc4Text(ctx, "Wiki", "pedia", false, "1021BF0420", "published");
	KatRc4Text(ctx, "Secret", "Attack at dawn", false, "45A01F645FC35B383552544B9BF5", "published");
	KatRc4Text(ctx, "Key", "Plaintext", true, "BBF316E8D940AF0AD3", "published");
	KatRc4Text(ctx, "EncryptP", "password", false, "1EFE179107421E3F", "computed");

	// A second key with the same bytes decrypts, and a size of 0 writes nothing
	Copy(key, "EncryptP", sizeof(key));
	Copy(in, "password", sizeof(in));
	Zero(out, sizeof(out));
	memset(back, KAT_GUARD_BYTE, sizeof(back));

	c = NewCrypt(key, sizeof(key));
	Encrypt(c, out, in, sizeof(in));
	FreeCrypt(c);

	c = NewCrypt(key, sizeof(key));
	Encrypt(c, back, out, 0);
	KatCheck(ctx, KatAllBytes(back, sizeof(back), KAT_GUARD_BYTE), "RC4 Encrypt() of 0 bytes writes nothing", "destination was written");
	Encrypt(c, back, out, sizeof(out));
	FreeCrypt(c);

	BinToStr(got, sizeof(got), back, sizeof(back));
	KatCheck(ctx, Cmp(back, in, sizeof(in)) == 0, "RC4 round trip with a fresh key restores the text", "got %s", got);

	// A key longer than 64 bytes gets no CNG key object (CNG would make a keystream that is not RC4),
	// so Encrypt() writes zeros
	memset(long_key, 0x01, sizeof(long_key));
	memset(out, KAT_GUARD_BYTE, sizeof(out));
	c = NewCrypt(long_key, sizeof(long_key));
	Encrypt(c, out, in, sizeof(in));
	FreeCrypt(c);

	BinToStr(got, sizeof(got), out, sizeof(out));
	KatCheck(ctx, KatAllBytes(out, sizeof(out), 0), "RC4 with a 65-byte key writes zeros", "got %s", got);
}

// One DES vector: DesEcbEncrypt() takes the 56 key bits without the parity bits, 7 bytes
static void KatDes(KAT_CTX *ctx, char *key56_hex, char *key64_hex, char *plain_hex, char *expect_hex, char *source)
{
	BUF *key = StrToBin(key56_hex);
	BUF *plain = StrToBin(plain_hex);
	UCHAR out[8 + KAT_GUARD];
	char got[8 * 2 + 1];
	char what[MAX_SIZE];

	Zero(out, sizeof(out));
	memset(out + 8, KAT_GUARD_BYTE, KAT_GUARD);

	DesEcbEncrypt(out, plain->Buf, key->Buf);

	Format(what, sizeof(what), "DES-ECB key %s (%s), block %s = %s (%s)", key56_hex, key64_hex, plain_hex, expect_hex, source);
	KatCheck(ctx, KatHexEq(out, 8, expect_hex, got, sizeof(got)) && KatAllBytes(out + 8, KAT_GUARD, KAT_GUARD_BYTE),
		what, "got %s", got);

	FreeBuf(plain);
	FreeBuf(key);
}

// The DES checks
static void KatDesSuite(KAT_CTX *ctx)
{
	BUF *key = StrToBin("12695BC9B7B7F8");
	BUF *plain = StrToBin("0123456789ABCDEF");
	UCHAR buf[8];
	UCHAR before[8];
	char got[sizeof(buf) * 2 + 1];

	KatDes(ctx, "00451338957377", "0123456789ABCDEF", "4E6F772069732074", "3FA40E8A984D4815", "FIPS 81, \"Now is t\"");
	KatDes(ctx, "12695BC9B7B7F8", "133457799BBCDFF1", "0123456789ABCDEF", "85E813540F0AB405", "published worked example");
	KatDes(ctx, "0E66499EAD8339", "0E329232EA6D0D73", "8787878787878787", "0000000000000000", "published");

	// The weak key 0101010101010101: the third MS-CHAPv2 key when the NT hash ends in 00 00
	KatDes(ctx, "00000000000000", "0101010101010101", "0000000000000000", "8CA64DE9C1B123A7", "published, weak key");

	// Destination and source in the same buffer
	Copy(buf, plain->Buf, sizeof(buf));
	DesEcbEncrypt(buf, buf, key->Buf);
	KatCheck(ctx, KatHexEq(buf, sizeof(buf), "85E813540F0AB405", got, sizeof(got)), "DES-ECB in place", "got %s", got);

	// Missing arguments are ignored
	Copy(before, buf, sizeof(buf));
	DesEcbEncrypt(NULL, plain->Buf, key->Buf);
	DesEcbEncrypt(buf, NULL, key->Buf);
	DesEcbEncrypt(buf, plain->Buf, NULL);
	KatCheck(ctx, Cmp(buf, before, sizeof(buf)) == 0, "DES-ECB with a missing argument writes nothing", "destination was written");

	FreeBuf(plain);
	FreeBuf(key);
}

// Number of 1 bits in a byte
static UINT KatBits(UCHAR b)
{
	UINT n = 0;

	while (b != 0)
	{
		n += (b & 1);
		b >>= 1;
	}

	return n;
}

// The random generator checks: no known answer exists, so they check the shape of the output
static void KatRand(KAT_CTX *ctx)
{
	UCHAR a[32 + KAT_GUARD];
	UCHAR b[32];
	UCHAR *bulk = ZeroMalloc(KAT_RAND_BULK);
	bool seen[256];
	UINT64 ones = 0;
	UINT64 expect_ones = (UINT64)KAT_RAND_BULK * 8 / 2;
	UINT64 skew;
	UINT num_seen = 0;
	UINT i;
	bool rand1_true = false, rand1_false = false;
	bool r8 = false, r16 = false, r32 = false, r64 = false;
	UCHAR first8;
	USHORT first16;
	UINT first32;
	UINT64 first64;

	// Missing buffer and size 0
	memset(a, KAT_GUARD_BYTE, sizeof(a));
	Rand(NULL, 16);
	Rand(a, 0);
	KatCheck(ctx, KatAllBytes(a, sizeof(a), KAT_GUARD_BYTE), "Rand() with no buffer or size 0 writes nothing", "buffer was written");

	// Exactly the requested bytes are written, and two draws differ
	Zero(a, sizeof(a));
	memset(a + 32, KAT_GUARD_BYTE, KAT_GUARD);
	Zero(b, sizeof(b));
	Rand(a, 32);
	Rand(b, 32);
	KatCheck(ctx, KatAllBytes(a + 32, KAT_GUARD, KAT_GUARD_BYTE), "Rand() writes no byte past the requested size", "guard bytes were written");
	KatCheck(ctx, KatAllBytes(a, 32, 0) == false && KatAllBytes(b, 32, 0) == false && Cmp(a, b, sizeof(b)) != 0,
		"Rand(): two 32-byte draws are not zero and differ", "draws are zero or equal");

	// Statistics of a large draw: the 1-bit count near half, every byte value present
	Zero(seen, sizeof(seen));
	Rand(bulk, KAT_RAND_BULK);
	for (i = 0;i < KAT_RAND_BULK;i++)
	{
		ones += KatBits(bulk[i]);
		if (seen[bulk[i]] == false)
		{
			seen[bulk[i]] = true;
			num_seen++;
		}
	}
	skew = (ones >= expect_ones ? ones - expect_ones : expect_ones - ones);
	KatCheck(ctx, skew <= KAT_RAND_MAX_SKEW, "Rand(): 1-bit count of 64 KiB within 6 sigma of half",
		"%I64u ones, expected %I64u", ones, expect_ones);
	KatCheck(ctx, num_seen == 256, "Rand(): every byte value appears in 64 KiB", "%u of 256 values", num_seen);

	// The fixed-size helpers vary
	first8 = Rand8();
	first16 = Rand16();
	first32 = Rand32();
	first64 = Rand64();
	for (i = 0;i < KAT_RAND_DRAWS;i++)
	{
		if (Rand1())
		{
			rand1_true = true;
		}
		else
		{
			rand1_false = true;
		}
		r8 = r8 || (Rand8() != first8);
		r16 = r16 || (Rand16() != first16);
		r32 = r32 || (Rand32() != first32);
		r64 = r64 || (Rand64() != first64);
	}
	KatCheck(ctx, rand1_true && rand1_false, "Rand1() returns both values in 64 draws", "only one value");
	KatCheck(ctx, r8 && r16 && r32 && r64, "Rand8(), Rand16(), Rand32() and Rand64() vary in 64 draws",
		"Rand8 %u, Rand16 %u, Rand32 %u, Rand64 %u (1 = varied)", r8, r16, r32, r64);

	Free(bulk);
}

// Crypto known-answer test
void crypto_test(UINT num, char **arg)
{
	KAT_CTX ctx;
	UCHAR *million = Malloc(KAT_MILLION);

	Zero(&ctx, sizeof(ctx));
	memset(million, 'a', KAT_MILLION);

	Print("Crypto known-answer test (MD4, MD5, SHA-0, SHA-1, SHA-256, RC4, DES, random generator)\n");

	KatHashSuite(&ctx, "HashMd4", HashMd4, KAT_MD4_SIZE, kat_md4, million);
	KatHashSuite(&ctx, "Md5", Md5, MD5_SIZE, kat_md5, million);
	KatHashSuite(&ctx, "Sha0", Sha0, SHA1_SIZE, kat_sha0, million);
	KatHashSuite(&ctx, "Sha1", Sha1, SHA1_SIZE, kat_sha1, million);
	KatHashSuite(&ctx, "Sha2_256", Sha2_256, SHA256_SIZE, kat_sha256, million);

	// SHA-0 password hashing stays own code
	KatHashPassword(&ctx, "user", "password", "FD7FD6A0D78CF029BDA789D5F5919C68EB7E8E5C");
	KatHashPassword(&ctx, "Admin", "secret", "E42FD00C3851B20799272935805AF344FFAB5D59");

	KatRc4(&ctx);
	KatDesSuite(&ctx);
	KatRand(&ctx);

	Free(million);

	if (ctx.NumFailed == 0)
	{
		Print("CRYPTO TEST OK\n");
	}
	else
	{
		Print("CRYPTO TEST FAILED (%u of %u checks failed)\n", ctx.NumFailed, ctx.NumChecks);
	}
}
