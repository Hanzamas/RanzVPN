// x509test.c
// Named X.509 and certificate signature test of vpntest ("x509" command, SEC-2 #96)
//
// Pins four fixes in Mayaqua/Encrypt.c on data that a peer certificate or signature controls:
// - GetUniStrFromX509Name scanned UniStrLen() * 4 + 8 bytes of its 1024-byte stack buffer for
//   high bytes, so a name field of about 508 bytes or more was read past the buffer
//   (AddressSanitizer: stack-buffer-overflow), and the stray bytes could switch the decoding.
//   Long PrintableString, UTF8String and BMPString fields must come back exactly, a field longer
//   than the buffer as its first X509T_NAME_KEPT bytes, as before.
// - Asn1TimeToSystem moved a GeneralizedTime by the local UTC offset. Both certificate time forms
//   are UTC (RFC 5280 section 4.1.2.5): with the process time zone set to UTC+9, a GeneralizedTime
//   must read as written and as the same instant as the equal UTCTime.
// - BioToXList freed a certificate twice when X509ToX failed on it (here: an unknown public key
//   algorithm): X509ToX freed it, then X509_INFO_free. A PEM bundle of such a certificate and a
//   valid one must give a list of the valid one, each certificate freed once.
// - RsaVerifyEx accepted any RSA_public_decrypt() length and compared the first 35 bytes, so a
//   PKCS#1 v1.5 block of the DigestInfo and hash followed by more bytes verified. The block must be
//   exactly the 35 bytes, and the signature exactly one modulus long.
// On the old code the name and bundle checks end in an AddressSanitizer report (fuzz-asan smoke
// run), the time and signature checks fail. Prints "X509 TEST OK" only when every check passes,
// and frees everything it allocates.

#include "Mayaqua/Encrypt.h"
#include "Mayaqua/Internat.h"
#include "Mayaqua/Kernel.h"
#include "Mayaqua/Memory.h"
#include "Mayaqua/Str.h"

#include <stdlib.h>
#include <time.h>

#include <openssl/asn1.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>

// Sizes and limits
#define	X509T_NAME_KEPT			1021		// Bytes of a name field GetUniStrFromX509Name keeps (its buffer less the terminator room)
#define	X509T_LONG_ASCII		600			// Characters of the long PrintableString and UTF8String fields
#define	X509T_LONG_UTF8			300			// Two-byte characters of the long non-ASCII UTF8String field
#define	X509T_LONG_BMP			500			// Characters of the long BMPString field (1000 bytes)
#define	X509T_OVERLONG			1500		// Characters of the field longer than the buffer
#define	X509T_TRAILING			8			// Bytes after the DigestInfo and hash in the forged signature block
#define	X509T_MAX_SIGN			(4096 / 8)	// Largest signature (bytes): the buffer Protocol.c receives it into
#define	X509T_TIME_ZONE			"JST-9"		// CRT time zone of the time checks: UTC+9, no daylight saving time

// Certificate whose public key algorithm is 1.3.6.1.4.1.32473.1 (under the RFC 5612 documentation
// enterprise number), which OpenSSL parses but cannot turn into a key; signed by a throwaway
// RSA-2048 key. Also the first certificate of the fuzz_x509 seed unknown_key_bundle.pem.
static char x509t_unknown_key_pem[] =
	"-----BEGIN CERTIFICATE-----\n"
	"MIIB2TCBwqADAgECAgRewgACMA0GCSqGSIb3DQEBCwUAMCkxJzAlBgNVBAMMHlJh\n"
	"bnogVlBOIHVua25vd24ga2V5IGFsZ29yaXRobTAeFw0yNjAxMDEwMDAwMDBaFw0z\n"
	"NjAxMDEwMDAwMDBaMCkxJzAlBgNVBAMMHlJhbnogVlBOIHVua25vd24ga2V5IGFs\n"
	"Z29yaXRobTAwMAsGCSsGAQQBgf1ZAQMhAAABAgMEBQYHCAkKCwwNDg8QERITFBUW\n"
	"FxgZGhscHR4fMA0GCSqGSIb3DQEBCwUAA4IBAQBf0ga3drqFy749cIin4VnLQb88\n"
	"rz7kJiyJH5ke9WBhah9nn1x3fZvmGbUKkArLDr/IrK3IzZaPjvjE9GE4GjJzcy2d\n"
	"AkVSsDuBQ7PDdhE/r0j++Nnl4/DJEo0zTqjPSHJa9TqoM9txCImZUYKws2sqFzWS\n"
	"toNsloeRO2ujSHDKiVrgvDLTC8ukzj87PWxsBCUFZzSFdKXqThlQwW2ym8gH4Pol\n"
	"e2gm1puAd/X/mYZSlNcksvTc3djTzFhuo0w4ViPnmtWs00WZMhMWg4Tm3uevzlxO\n"
	"rGKGSfqPIuhDI2GU1BzbI+CsciPUPh7wuRtJpgE6P0W0It5dpF6Bo0VmH89A\n"
	"-----END CERTIFICATE-----\n";

// Run state of the test
typedef struct X509T_CTX
{
	UINT NumChecks;					// Checks run so far
	UINT NumFailed;					// Checks failed so far
} X509T_CTX;

// Record one check: print [PASS] or [FAIL]
static bool X509TestCheck(X509T_CTX *ctx, bool ok, char *what)
{
	ctx->NumChecks++;

	if (ok)
	{
		Print("  [PASS] %s\n", what);
		return true;
	}

	Print("  [FAIL] %s\n", what);

	ctx->NumFailed++;

	return false;
}

// Character i of the test text: A to Z and 0 to 9, repeated
static char X509TestChar(UINT i)
{
	static char alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

	return alphabet[i % (sizeof(alphabet) - 1)];
}

// GetUniStrFromX509Name on a name whose common name holds the raw bytes as the ASN.1 string type;
// true when it returns expect
static bool X509TestName(int type, UCHAR *bytes, UINT size, wchar_t *expect)
{
	X509_NAME *xn = X509_NAME_new();
	wchar_t *got;
	bool ok;

	if (xn == NULL)
	{
		return false;
	}

	// A V_ASN1_* type stores the bytes as they are, with no length limit (an MBSTRING_* type would
	// apply the 64-character upper bound of commonName)
	if (X509_NAME_add_entry_by_NID(xn, NID_commonName, type, bytes, (int)size, -1, 0) == 0)
	{
		X509_NAME_free(xn);
		return false;
	}

	got = GetUniStrFromX509Name(xn, NID_commonName);
	ok = (got != NULL && UniStrCmp(got, expect) == 0);

	Free(got);
	X509_NAME_free(xn);

	return ok;
}

// Long name fields: decoded exactly, and no read past the stack buffer
static void X509TestNames(X509T_CTX *ctx)
{
	UCHAR *bytes = ZeroMalloc(X509T_OVERLONG * 2);
	wchar_t *expect = ZeroMalloc((X509T_OVERLONG + 1) * sizeof(wchar_t));
	UINT i;

	// 600 ASCII characters as PrintableString and as UTF8String
	for (i = 0;i < X509T_LONG_ASCII;i++)
	{
		bytes[i] = (UCHAR)X509TestChar(i);
		expect[i] = (wchar_t)X509TestChar(i);
	}
	expect[X509T_LONG_ASCII] = 0;
	X509TestCheck(ctx, X509TestName(V_ASN1_PRINTABLESTRING, bytes, X509T_LONG_ASCII, expect),
		"600-character PrintableString common name comes back exactly");
	X509TestCheck(ctx, X509TestName(V_ASN1_UTF8STRING, bytes, X509T_LONG_ASCII, expect),
		"600-character UTF8String common name comes back exactly");

	// 300 times U+00E9 as UTF-8 (C3 A9), 600 bytes
	for (i = 0;i < X509T_LONG_UTF8;i++)
	{
		bytes[i * 2] = 0xC3;
		bytes[i * 2 + 1] = 0xA9;
		expect[i] = 0x00E9;
	}
	expect[X509T_LONG_UTF8] = 0;
	X509TestCheck(ctx, X509TestName(V_ASN1_UTF8STRING, bytes, X509T_LONG_UTF8 * 2, expect),
		"UTF8String common name of 300 times U+00E9 comes back exactly");

	// 500 characters as BMPString (UTF-16 big endian), 1000 bytes
	for (i = 0;i < X509T_LONG_BMP;i++)
	{
		bytes[i * 2] = 0;
		bytes[i * 2 + 1] = (UCHAR)X509TestChar(i);
		expect[i] = (wchar_t)X509TestChar(i);
	}
	expect[X509T_LONG_BMP] = 0;
	X509TestCheck(ctx, X509TestName(V_ASN1_BMPSTRING, bytes, X509T_LONG_BMP * 2, expect),
		"500-character BMPString common name comes back exactly");

	// Longer than the buffer: its first X509T_NAME_KEPT bytes, as before
	for (i = 0;i < X509T_OVERLONG;i++)
	{
		bytes[i] = (UCHAR)X509TestChar(i);
		expect[i] = (wchar_t)X509TestChar(i);
	}
	expect[X509T_NAME_KEPT] = 0;
	X509TestCheck(ctx, X509TestName(V_ASN1_PRINTABLESTRING, bytes, X509T_OVERLONG, expect),
		"1500-character PrintableString common name comes back as its first 1021 characters");

	Free(expect);
	Free(bytes);
}

// Whether a SYSTEMTIME holds the date and time
static bool X509TestIsTime(SYSTEMTIME *st, UINT year, UINT month, UINT day, UINT hour, UINT minute, UINT second)
{
	return st->wYear == year && st->wMonth == month && st->wDay == day &&
		st->wHour == hour && st->wMinute == minute && st->wSecond == second;
}

// Certificate times are UTC in both ASN.1 forms, whatever the local time zone
static void X509TestTimes(X509T_CTX *ctx)
{
	char old_tz[MAX_SIZE];
	bool had_tz = GetEnv("TZ", old_tz, sizeof(old_tz));
	ASN1_GENERALIZEDTIME *gen2060 = ASN1_GENERALIZEDTIME_new();
	ASN1_GENERALIZEDTIME *gen2049 = ASN1_GENERALIZEDTIME_new();
	ASN1_UTCTIME *utc2049 = ASN1_UTCTIME_new();
	SYSTEMTIME local, st;
	bool made;

	// The CRT time functions behind LocalToSystem (mktime, localtime) follow TZ once _tzset reads it
	_putenv_s("TZ", X509T_TIME_ZONE);
	_tzset();

	// The zone is in effect: 2060-01-01 00:00 local time is 2059-12-31 15:00 UTC
	Zero(&local, sizeof(local));
	local.wYear = 2060;
	local.wMonth = 1;
	local.wDay = 1;
	LocalToSystem(&st, &local);
	X509TestCheck(ctx, X509TestIsTime(&st, 2059, 12, 31, 15, 0, 0), "Process time zone is UTC+9 for the time checks");

	made = gen2060 != NULL && gen2049 != NULL && utc2049 != NULL &&
		ASN1_GENERALIZEDTIME_set_string(gen2060, "20600101000000Z") == 1 &&
		ASN1_GENERALIZEDTIME_set_string(gen2049, "20491230000000Z") == 1 &&
		ASN1_UTCTIME_set_string(utc2049, "491230000000Z") == 1;
	X509TestCheck(ctx, made, "GeneralizedTime 20600101000000Z and 20491230000000Z, UTCTime 491230000000Z are made");

	if (made)
	{
		Zero(&st, sizeof(st));
		X509TestCheck(ctx, Asn1TimeToSystem(&st, gen2060) && X509TestIsTime(&st, 2060, 1, 1, 0, 0, 0),
			"GeneralizedTime 20600101000000Z reads as 2060-01-01 00:00:00 UTC");

		Zero(&st, sizeof(st));
		X509TestCheck(ctx, Asn1TimeToSystem(&st, utc2049) && X509TestIsTime(&st, 2049, 12, 30, 0, 0, 0),
			"UTCTime 491230000000Z reads as 2049-12-30 00:00:00 UTC");

		X509TestCheck(ctx, Asn1TimeToUINT64(gen2049) != 0 && Asn1TimeToUINT64(gen2049) == Asn1TimeToUINT64(utc2049),
			"GeneralizedTime 20491230000000Z and UTCTime 491230000000Z are the same instant");
	}

	ASN1_UTCTIME_free(utc2049);
	ASN1_GENERALIZEDTIME_free(gen2049);
	ASN1_GENERALIZEDTIME_free(gen2060);

	// Back to the time zone of the process: an empty value removes TZ
	_putenv_s("TZ", had_tz ? old_tz : "");
	_tzset();
}

// RsaVerifyEx: a valid signature verifies, a block with bytes after the hash does not
static void X509TestRsa(X509T_CTX *ctx, K *priv, K *pub, UINT bits)
{
	UCHAR data[SHA1_SIZE];
	UCHAR other[SHA1_SIZE];
	UCHAR sign[X509T_MAX_SIGN];
	UCHAR block[SIGN_HASH_SIZE + X509T_TRAILING];
	UCHAR forged[X509T_MAX_SIGN];
	size_t forged_size = sizeof(forged);
	EVP_PKEY_CTX *pctx;
	bool forged_ok = false;
	char what[MAX_SIZE];
	UINT i;

	// The client signs the 20 random bytes of the server (c->Random in Protocol.c)
	Rand(data, sizeof(data));
	Copy(other, data, sizeof(other));
	other[0] ^= 0x01;

	Zero(sign, sizeof(sign));
	Format(what, sizeof(what), "RSA-%u: a RsaSignEx signature verifies", bits);
	X509TestCheck(ctx, RsaSignEx(sign, data, sizeof(data), priv, bits) && RsaVerifyEx(data, sizeof(data), sign, pub, bits), what);

	Format(what, sizeof(what), "RSA-%u: the signature does not verify other data", bits);
	X509TestCheck(ctx, RsaVerifyEx(other, sizeof(other), sign, pub, bits) == false, what);

	Format(what, sizeof(what), "RSA-%u: a signature length other than the key size is rejected", bits);
	X509TestCheck(ctx, RsaVerifyEx(data, sizeof(data), sign, pub, bits / 2) == false, what);

	// The DigestInfo and SHA-1 of the data, then trailing bytes, PKCS#1 v1.5 type 1 padded and
	// signed with the private key (EVP_PKEY_sign with no digest signs the bytes as they are)
	HashForSign(block, sizeof(block), data, sizeof(data));
	for (i = SIGN_HASH_SIZE;i < sizeof(block);i++)
	{
		block[i] = 'X';
	}

	pctx = EVP_PKEY_CTX_new(priv->pkey, NULL);
	if (pctx != NULL)
	{
		forged_ok = EVP_PKEY_sign_init(pctx) == 1 &&
			EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PADDING) == 1 &&
			EVP_PKEY_sign(pctx, forged, &forged_size, block, sizeof(block)) == 1 &&
			forged_size == bits / 8;
		EVP_PKEY_CTX_free(pctx);
	}

	Format(what, sizeof(what), "RSA-%u: a block of DigestInfo, hash and %u more bytes is signed", bits, X509T_TRAILING);
	X509TestCheck(ctx, forged_ok, what);

	Format(what, sizeof(what), "RSA-%u: that signature, with bytes after the hash, is rejected", bits);
	X509TestCheck(ctx, forged_ok && RsaVerifyEx(data, sizeof(data), forged, pub, bits) == false, what);
}

// A PEM bundle whose first certificate X509ToX refuses: each certificate freed once
static void X509TestBundle(X509T_CTX *ctx, K *priv, K *pub)
{
	NAME *name = NewName(L"Ranz VPN x509 test", NULL, NULL, NULL, NULL, NULL);
	X *valid = NewRootX(pub, priv, name, 365, NULL);
	BUF *valid_pem = XToBuf(valid, true);
	BUF *one = NewBuf();
	BUF *bundle = NewBuf();
	LIST *chain;
	X *x;

	X509TestCheck(ctx, valid != NULL && valid_pem != NULL, "Valid self-signed RSA-2048 certificate is made");

	// Alone: X509ToX gets no public key from it
	WriteBuf(one, x509t_unknown_key_pem, StrLen(x509t_unknown_key_pem));
	x = BufToX(one, true);
	X509TestCheck(ctx, x == NULL, "BufToX refuses the certificate with the unknown public key algorithm");
	FreeX(x);

	// First in a bundle, the valid certificate after it
	WriteBuf(bundle, x509t_unknown_key_pem, StrLen(x509t_unknown_key_pem));
	WriteBufBuf(bundle, valid_pem);
	chain = BufToXList(bundle, true);
	X509TestCheck(ctx, chain != NULL && LIST_NUM(chain) == 1 && CompareX(LIST_DATA(chain, 0), valid),
		"BufToXList of the bundle frees the refused certificate once and lists the valid one");
	FreeXList(chain);

	FreeBuf(bundle);
	FreeBuf(one);
	FreeBuf(valid_pem);
	FreeX(valid);
	FreeName(name);
}

// X.509 and certificate signature test
void x509_test(UINT num, char **arg)
{
	X509T_CTX ctx;
	K *priv1024 = NULL, *pub1024 = NULL;
	K *priv2048 = NULL, *pub2048 = NULL;

	Zero(&ctx, sizeof(ctx));

	Print("X.509 and certificate signature test (name fields, certificate times, PKCS#1 v1.5 length, PEM bundles)\n");

	X509TestNames(&ctx);
	X509TestTimes(&ctx);

	if (X509TestCheck(&ctx, RsaGen(&priv1024, &pub1024, 1024) && RsaGen(&priv2048, &pub2048, 2048),
		"RSA-1024 and RSA-2048 test keys are generated"))
	{
		X509TestRsa(&ctx, priv1024, pub1024, 1024);
		X509TestRsa(&ctx, priv2048, pub2048, 2048);
		X509TestBundle(&ctx, priv2048, pub2048);
	}

	FreeK(pub2048);
	FreeK(priv2048);
	FreeK(pub1024);
	FreeK(priv1024);

	if (ctx.NumFailed == 0)
	{
		Print("X509 TEST OK\n");
	}
	else
	{
		Print("X509 TEST FAILED (%u of %u checks failed)\n", ctx.NumFailed, ctx.NumChecks);
	}
}
