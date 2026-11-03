// x509test.c
// Named X.509 and certificate signature test of vpntest ("x509" command, SEC-2 #96)
//
// Pins four fixes in Mayaqua/Crypto/ (X509.c, Pem.c, Rsa.c) on data that a peer certificate or
// signature controls:
// - GetUniStrFromX509Name scanned UniStrLen() * 4 + 8 bytes of its 1024-byte stack buffer for
//   high bytes, so a name field of about 508 bytes or more was read past the buffer
//   (AddressSanitizer: stack-buffer-overflow), and the stray bytes could switch the decoding.
//   Long PrintableString, UTF8String and BMPString fields must come back exactly, a field longer
//   than the buffer as its first X509T_NAME_KEPT bytes, as before.
// - Asn1TimeToSystem moved a GeneralizedTime by the local UTC offset. Both certificate time forms
//   are UTC (RFC 5280 section 4.1.2.5): whatever the OS time zone, a GeneralizedTime must read as
//   written and as the same instant as the equal UTCTime. The old check set the CRT zone with TZ to
//   UTC+9; the local time conversions follow the OS zone since FND-132 and ignore TZ, so a runner in
//   UTC no longer exercises a zone with an offset.
// - BioToXList freed a certificate twice when X509ToX failed on it (here: an unknown public key
//   algorithm): X509ToX freed it, then X509_INFO_free. A PEM bundle of such a certificate and a
//   valid one must give a list of the valid one, each certificate freed once.
// - RsaVerifyEx accepted any RSA_public_decrypt() length and compared the first 35 bytes, so a
//   PKCS#1 v1.5 block of the DigestInfo and hash followed by more bytes verified. The block must be
//   exactly the 35 bytes, and the signature exactly one modulus long.
// On the old code the name and bundle checks end in an AddressSanitizer report (fuzz-asan smoke
// run), the time and signature checks fail. Prints "X509 TEST OK" only when every check passes,
// and frees everything it allocates.
//
// "certsig" command (FND-80, #127): X509_verify() returns 1 for a valid signature, 0 for a bad one
// and a negative value when it cannot check it (unknown signature algorithm, bad BIT STRING).
// CheckSignature took every value but 0 for valid, so a certificate that names a hub's root CA as
// its issuer and carries an unknown signature algorithm passed CheckSignature, CheckXEx and
// GetIssuerFromList (the AUTHTYPE_ROOTCERT login of Sam.c). Against a committed test CA: the
// forged certificate must fail all three, a certificate the CA really signed must pass them, and
// a certificate checked against the wrong key must fail. Prints "CERTSIG TEST OK".
//
// "x509root" command (FND-81, #127): X509ToX set root_cert when the issuer and subject names were
// equal and X509_check_private_key() matched the certificate against its own public key, which
// always holds, so the self-signature was never checked: a certificate with equal names and a bad
// self-signature ended chain building as a root. It must not be a root; the really self-signed test
// CA must be one. X509ToX must leave a certificate it refuses to its caller, who frees it once; the
// old X509ToX freed it itself, so the X509_free of the test is a double free there (AddressSanitizer
// report in the fuzz-asan smoke run). Prints "X509ROOT TEST OK".
//
// "rsasig" command (FND-83, #127): the client certificate signature (RSASSA-PKCS1-v1_5 with SHA-1
// over the server's random bytes) with explicit sizes. RsaSignEx wrote RSA_size() bytes wherever
// the caller's bits said the destination ended, so a key larger than the certificate's bits wrote
// past it: a destination smaller than the key's signature must be refused with nothing written past
// it. A signature verifies, other data and a block with bytes after the hash do not, and a received
// signature of another length than the key's is rejected. Prints "RSASIG TEST OK".

#include "testlist.h"

#include "Mayaqua/Encrypt.h"
#include "Mayaqua/Internat.h"
#include "Mayaqua/Kernel.h"
#include "Mayaqua/Memory.h"
#include "Mayaqua/Str.h"

#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <openssl/asn1.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>

// Sizes and limits
#define	X509T_NAME_KEPT			1021		// Bytes of a name field GetUniStrFromX509Name keeps (its buffer less the terminator room)
#define	X509T_LONG_ASCII		600			// Characters of the long PrintableString and UTF8String fields
#define	X509T_LONG_UTF8			300			// Two-byte characters of the long non-ASCII UTF8String field
#define	X509T_LONG_BMP			500			// Characters of the long BMPString field (1000 bytes)
#define	X509T_OVERLONG			1500		// Characters of the field longer than the buffer
#define	X509T_DIGEST_INFO		(15 + SHA1_SIZE)	// Bytes of the SHA-1 DigestInfo and hash in a PKCS#1 v1.5 block
#define	X509T_TRAILING			8			// Bytes after the DigestInfo and hash in the forged signature block
#define	X509T_MAX_SIGN			(4096 / 8)	// Largest signature (bytes): the buffer that the SE-VPN login received it into
#define	X509T_GUARD				16			// Guard bytes after a signature destination
#define	X509T_GUARD_BYTE		0xA5		// Value of the guard bytes

// DER prefix of the SHA-1 DigestInfo (RFC 8017 section 9.2, note 1); the 20-byte hash follows it
static UCHAR x509t_sha1_digest_info[] =
{
	0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2B, 0x0E,
	0x03, 0x02, 0x1A, 0x05, 0x00, 0x04, 0x14,
};

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

// Fixtures of "certsig", built as DER with Python, signed with sha256WithRSAEncryption and checked
// through libcrypto 3.2 X509_verify(); all valid from 2026-01-01 to 2049-12-31.
// Test CA "Ranz VPN certsig CA": RSA-2048, self-signed, basicConstraints CA:TRUE.
static char x509t_certsig_ca_pem[] =
	"-----BEGIN CERTIFICATE-----\n"
	"MIIDFjCCAf6gAwIBAgIDXsChMA0GCSqGSIb3DQEBCwUAMEMxCzAJBgNVBAYTAklE\n"
	"MRYwFAYDVQQKDA1SYW56IFZQTiB0ZXN0MRwwGgYDVQQDDBNSYW56IFZQTiBjZXJ0\n"
	"c2lnIENBMB4XDTI2MDEwMTAwMDAwMFoXDTQ5MTIzMTIzNTk1OVowQzELMAkGA1UE\n"
	"BhMCSUQxFjAUBgNVBAoMDVJhbnogVlBOIHRlc3QxHDAaBgNVBAMME1JhbnogVlBO\n"
	"IGNlcnRzaWcgQ0EwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC8C+Ft\n"
	"K1RPcoRNxI/hKeW/ipIq/XYAD1s9sN5Ntsfa2pLTuNM3E5fPl0uAAMGtO8LhyQte\n"
	"ah+KjjOd/TNSNTyd1Mx5LYRvCp1IztQw/yoaUhAnNBd8ejgTM89mk+ppcaiazq6D\n"
	"/sNAGbIpQ7mzR4UOObSYIAv1RU6kaxq4RkYtiolcgEoaZzSu4gQPbn/qMy9qTXKQ\n"
	"nwPoVfk0ty0fRuS3K6xxbA4KlGBpVXjXbSGIIn11742wgXyCz1ovaRgKpQR5EzOP\n"
	"qXIHmgyZXkApqNlDnn18GnumVVwXZplRsWGpln2zgvMe0BXspKCKhYOu1X19/Yuv\n"
	"v837nAliW107JAKLAgMBAAGjEzARMA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcN\n"
	"AQELBQADggEBAKuHXc+PEcnn7GlLicEhcvXiStkHSNRRx5Yucv2yibWWIO4o1lRr\n"
	"nmJI0CdU9wPF7bxyG63lwdHfSV+ryyTSBxoBIeK9bANprsExKrFXb3mCcOVJUglT\n"
	"1Yvknsdh3P3PYXuOUeQdFJjQCQxebQ8MFddB0okdXAwuhxD/fZMKscZdYPQXiJfQ\n"
	"cXpkFKKl5yrUCxSa1Rn1bAiFbWJKREhKT598b/ayybOgse/NYMl/gwrj4kp4zzcD\n"
	"5O6BPIlawGByqXAYVanCGWLk2WiH77UFynYHg3OrYdrVIETla5e/EEiQKjZ1+E8K\n"
	"oHHWfl6LD8WopfaDtIsODgSJpPmcTaKf41U=\n"
	"-----END CERTIFICATE-----\n";

// "Ranz VPN certsig leaf": RSA-2048, signed by the test CA
static char x509t_certsig_leaf_pem[] =
	"-----BEGIN CERTIFICATE-----\n"
	"MIIDAzCCAeugAwIBAgIDXsCiMA0GCSqGSIb3DQEBCwUAMEMxCzAJBgNVBAYTAklE\n"
	"MRYwFAYDVQQKDA1SYW56IFZQTiB0ZXN0MRwwGgYDVQQDDBNSYW56IFZQTiBjZXJ0\n"
	"c2lnIENBMB4XDTI2MDEwMTAwMDAwMFoXDTQ5MTIzMTIzNTk1OVowRTELMAkGA1UE\n"
	"BhMCSUQxFjAUBgNVBAoMDVJhbnogVlBOIHRlc3QxHjAcBgNVBAMMFVJhbnogVlBO\n"
	"IGNlcnRzaWcgbGVhZjCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAK8w\n"
	"w2+QJ2N9eRZr8Zupv7T3bWNoSJlYZSwQrjJCHTy4f8rI/wYOVwRliq4j9XXQT5ub\n"
	"T5OQBJFu9oAEv+wApvkwW+A+4WQrQAYG/d9ixin7qU+Ew5XgYl7HdJXwW6yr6A7A\n"
	"vCkLQcxuYRj46nCP+QDaYh8VycAse9tMLKEJBjDf7N4+0ltHhqtmyrWEm1f+RS3L\n"
	"n+T1NfBkqKiyRG3qGiOdrM+NTPdTDbjnDRmsECPRD6NUN0zpqjzhf0AyrDpBT/zC\n"
	"BhX6KxK2JkmYN1rXwq8nn1qrA7J6FXwjAss2xClvi5GhtuS5sixUIG3f/Kty7VFY\n"
	"VaYEGHAJjkBmRou4EacCAwEAATANBgkqhkiG9w0BAQsFAAOCAQEAninpsOCHQuIy\n"
	"5htDyuMEtdndwuvyJOJVrllPzBgbkQzRDVodhYA8WBC/ls7aJKBpoRExI6uBv7fD\n"
	"V5QVwW/HnUrtpBiacQBlRXDVg/87Tvw9efQidJJcCOoVpp5xRou1XY4UXY28LoX+\n"
	"jGi4+xIedZcWF/72ublcdshJE7qlQciBHbB5Gu8jxCBt3LCnsdidhwrpMOwhVVK8\n"
	"he7PAadC2G4iF9Zy629cSR0fIRTYMy7nZs8AaFwBbSEwSREvh0n+kXuDoKD703jX\n"
	"92i8G8yOuRYAwK5djMHLZK8jfLfR6kxjHkn3wRin1uxs0iLf8ddJ7C56IuShvfYJ\n"
	"9EZb7TtUpA==\n"
	"-----END CERTIFICATE-----\n";

// "Ranz VPN certsig forged": names the test CA as its issuer and carries the key of the leaf, the
// signature algorithm 1.3.6.1.4.1.32473.2 (RFC 5612 documentation enterprise number, unknown to
// OpenSSL) in the TBS signature field and in signatureAlgorithm, and 256 arbitrary signature bytes.
// X509_verify() with the CA key returns -1. Also the fuzz_x509 seed certsig_unknown_sigalg.der.
static char x509t_certsig_forged_pem[] =
	"-----BEGIN CERTIFICATE-----\n"
	"MIIDATCCAeugAwIBAgIDXsCjMAsGCSsGAQQBgf1ZAjBDMQswCQYDVQQGEwJJRDEW\n"
	"MBQGA1UECgwNUmFueiBWUE4gdGVzdDEcMBoGA1UEAwwTUmFueiBWUE4gY2VydHNp\n"
	"ZyBDQTAeFw0yNjAxMDEwMDAwMDBaFw00OTEyMzEyMzU5NTlaMEcxCzAJBgNVBAYT\n"
	"AklEMRYwFAYDVQQKDA1SYW56IFZQTiB0ZXN0MSAwHgYDVQQDDBdSYW56IFZQTiBj\n"
	"ZXJ0c2lnIGZvcmdlZDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAK8w\n"
	"w2+QJ2N9eRZr8Zupv7T3bWNoSJlYZSwQrjJCHTy4f8rI/wYOVwRliq4j9XXQT5ub\n"
	"T5OQBJFu9oAEv+wApvkwW+A+4WQrQAYG/d9ixin7qU+Ew5XgYl7HdJXwW6yr6A7A\n"
	"vCkLQcxuYRj46nCP+QDaYh8VycAse9tMLKEJBjDf7N4+0ltHhqtmyrWEm1f+RS3L\n"
	"n+T1NfBkqKiyRG3qGiOdrM+NTPdTDbjnDRmsECPRD6NUN0zpqjzhf0AyrDpBT/zC\n"
	"BhX6KxK2JkmYN1rXwq8nn1qrA7J6FXwjAss2xClvi5GhtuS5sixUIG3f/Kty7VFY\n"
	"VaYEGHAJjkBmRou4EacCAwEAATALBgkrBgEEAYH9WQIDggEBAKwpdPtyK7/emvyb\n"
	"H1RQ3g9GI7AXp0Pa2StAd3uyvLcUrCl0+3Irv96a/JsfVFDeD0YjsBenQ9rZK0B3\n"
	"e7K8txSsKXT7ciu/3pr8mx9UUN4PRiOwF6dD2tkrQHd7sry3FKwpdPtyK7/emvyb\n"
	"H1RQ3g9GI7AXp0Pa2StAd3uyvLcUrCl0+3Irv96a/JsfVFDeD0YjsBenQ9rZK0B3\n"
	"e7K8txSsKXT7ciu/3pr8mx9UUN4PRiOwF6dD2tkrQHd7sry3FKwpdPtyK7/emvyb\n"
	"H1RQ3g9GI7AXp0Pa2StAd3uyvLcUrCl0+3Irv96a/JsfVFDeD0YjsBenQ9rZK0B3\n"
	"e7K8txQ=\n"
	"-----END CERTIFICATE-----\n";

// Fixture of "x509root", made like the certsig ones: "Ranz VPN x509root bad self-signature", issuer
// and subject equal, the key of the certsig leaf, signed by another RSA-2048 key. X509_verify() with
// its own key returns 0, X509_check_private_key() with its own key returns 1.
static char x509t_x509root_bad_pem[] =
	"-----BEGIN CERTIFICATE-----\n"
	"MIIDIzCCAgugAwIBAgIDXsCkMA0GCSqGSIb3DQEBCwUAMFQxCzAJBgNVBAYTAklE\n"
	"MRYwFAYDVQQKDA1SYW56IFZQTiB0ZXN0MS0wKwYDVQQDDCRSYW56IFZQTiB4NTA5\n"
	"cm9vdCBiYWQgc2VsZi1zaWduYXR1cmUwHhcNMjYwMTAxMDAwMDAwWhcNNDkxMjMx\n"
	"MjM1OTU5WjBUMQswCQYDVQQGEwJJRDEWMBQGA1UECgwNUmFueiBWUE4gdGVzdDEt\n"
	"MCsGA1UEAwwkUmFueiBWUE4geDUwOXJvb3QgYmFkIHNlbGYtc2lnbmF0dXJlMIIB\n"
	"IjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEArzDDb5AnY315Fmvxm6m/tPdt\n"
	"Y2hImVhlLBCuMkIdPLh/ysj/Bg5XBGWKriP1ddBPm5tPk5AEkW72gAS/7ACm+TBb\n"
	"4D7hZCtABgb932LGKfupT4TDleBiXsd0lfBbrKvoDsC8KQtBzG5hGPjqcI/5ANpi\n"
	"HxXJwCx720wsoQkGMN/s3j7SW0eGq2bKtYSbV/5FLcuf5PU18GSoqLJEbeoaI52s\n"
	"z41M91MNuOcNGawQI9EPo1Q3TOmqPOF/QDKsOkFP/MIGFforErYmSZg3WtfCryef\n"
	"WqsDsnoVfCMCyzbEKW+LkaG25LmyLFQgbd/8q3LtUVhVpgQYcAmOQGZGi7gRpwID\n"
	"AQABMA0GCSqGSIb3DQEBCwUAA4IBAQBFg38OFmKhFGs1Rw3evX7XmIdf15ypLdz6\n"
	"nNhTBR/ZqE9K/Dkvh/X0g4YsGZlSUBJDYmFxJ+HYSZ7lKgMhZnv7ZMNVzqoRob6x\n"
	"1eehP6E6fi/yvYsyWw1h3Vb+aAoFskegivf8Vh4y6qqXx3RYCo6XKmua48E4fPzX\n"
	"k1oaIAt1/lfiBWEjo5q6qNpYGOwi31egfvAZU2y53zvddR+icNSw5rEfWLRgU6YJ\n"
	"JRMv/KECgh1JWlJTmut7LIRgqfhO51EPcfrXSFtXtwOV3K1FDFSsI3DSWqV4SyPJ\n"
	"bEH4TgptUoJbKPEDf/3xYLnuJm7TFIGdEpMQ1N1MQ3BjByrxqQwR\n"
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
static bool X509TestName(int type, UCHAR *bytes, UINT size, const wchar_t *expect)
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

	// 600 ASCII characters as PrintableString and as UTF8String
	for (UINT i = 0;i < X509T_LONG_ASCII;i++)
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
	for (UINT i = 0;i < X509T_LONG_UTF8;i++)
	{
		bytes[i * 2] = 0xC3;
		bytes[i * 2 + 1] = 0xA9;
		expect[i] = 0x00E9;
	}
	expect[X509T_LONG_UTF8] = 0;
	X509TestCheck(ctx, X509TestName(V_ASN1_UTF8STRING, bytes, X509T_LONG_UTF8 * 2, expect),
		"UTF8String common name of 300 times U+00E9 comes back exactly");

	// 500 characters as BMPString (UTF-16 big endian), 1000 bytes
	for (UINT i = 0;i < X509T_LONG_BMP;i++)
	{
		bytes[i * 2] = 0;
		bytes[i * 2 + 1] = (UCHAR)X509TestChar(i);
		expect[i] = (wchar_t)X509TestChar(i);
	}
	expect[X509T_LONG_BMP] = 0;
	X509TestCheck(ctx, X509TestName(V_ASN1_BMPSTRING, bytes, X509T_LONG_BMP * 2, expect),
		"500-character BMPString common name comes back exactly");

	// Longer than the buffer: its first X509T_NAME_KEPT bytes, as before
	for (UINT i = 0;i < X509T_OVERLONG;i++)
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
static bool X509TestIsTime(const SYSTEMTIME *st, UINT year, UINT month, UINT day, UINT hour, UINT minute, UINT second)
{
	return st->wYear == year && st->wMonth == month && st->wDay == day &&
		st->wHour == hour && st->wMinute == minute && st->wSecond == second;
}

// Certificate times are UTC in both ASN.1 forms, whatever the local time zone. The zone is the one
// of the OS: LocalToSystem follows it through the Windows time zone functions, not the TZ variable
static void X509TestTimes(X509T_CTX *ctx)
{
	ASN1_GENERALIZEDTIME *gen2060 = ASN1_GENERALIZEDTIME_new();
	ASN1_GENERALIZEDTIME *gen2049 = ASN1_GENERALIZEDTIME_new();
	ASN1_UTCTIME *utc2049 = ASN1_UTCTIME_new();
	SYSTEMTIME st;
	bool made;

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
}

// RsaVerifyEx: a valid signature verifies, a block with bytes after the hash does not
static void X509TestRsa(X509T_CTX *ctx, K *priv, K *pub, UINT bits)
{
	UCHAR data[SHA1_SIZE];
	UCHAR other[SHA1_SIZE];
	UCHAR sign[X509T_MAX_SIGN];
	UCHAR block[X509T_DIGEST_INFO + X509T_TRAILING];
	UCHAR forged[X509T_MAX_SIGN];
	size_t forged_size = sizeof(forged);
	EVP_PKEY_CTX *pctx;
	bool forged_ok = false;
	char what[MAX_SIZE];
	UINT sign_size = bits / 8;

	// The client signs the 20 random bytes of the server (c->Random of the SE-VPN login)
	Rand(data, sizeof(data));
	Copy(other, data, sizeof(other));
	other[0] ^= 0x01;

	Zero(sign, sizeof(sign));
	Format(what, sizeof(what), "RSA-%u: a RsaSignEx signature verifies", bits);
	X509TestCheck(ctx, RsaSignEx(sign, sizeof(sign), data, sizeof(data), priv) &&
		RsaVerifyEx(data, sizeof(data), sign, sign_size, pub), what);

	Format(what, sizeof(what), "RSA-%u: the signature does not verify other data", bits);
	X509TestCheck(ctx, RsaVerifyEx(other, sizeof(other), sign, sign_size, pub) == false, what);

	Format(what, sizeof(what), "RSA-%u: a signature length other than the key size is rejected", bits);
	X509TestCheck(ctx, RsaVerifyEx(data, sizeof(data), sign, sign_size / 2, pub) == false, what);

	// The DigestInfo and SHA-1 of the data, then trailing bytes, PKCS#1 v1.5 type 1 padded and
	// signed with the private key (EVP_PKEY_sign with no digest signs the bytes as they are)
	Copy(block, x509t_sha1_digest_info, sizeof(x509t_sha1_digest_info));
	Sha1(block + sizeof(x509t_sha1_digest_info), data, sizeof(data));
	for (UINT i = X509T_DIGEST_INFO;i < sizeof(block);i++)
	{
		block[i] = 'X';
	}

	pctx = EVP_PKEY_CTX_new(priv->pkey, NULL);
	if (pctx != NULL)
	{
		forged_ok = EVP_PKEY_sign_init(pctx) == 1 &&
			EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PADDING) == 1 &&
			EVP_PKEY_sign(pctx, forged, &forged_size, block, sizeof(block)) == 1 &&
			forged_size == sign_size;
		EVP_PKEY_CTX_free(pctx);
	}

	Format(what, sizeof(what), "RSA-%u: a block of DigestInfo, hash and %u more bytes is signed", bits, X509T_TRAILING);
	X509TestCheck(ctx, forged_ok, what);

	Format(what, sizeof(what), "RSA-%u: that signature, with bytes after the hash, is rejected", bits);
	X509TestCheck(ctx, forged_ok && RsaVerifyEx(data, sizeof(data), forged, sign_size, pub) == false, what);
}

// A PEM bundle whose first certificate X509ToX refuses: each certificate freed once
static void X509TestBundle(X509T_CTX *ctx, K *priv, K *pub)
{
	NAME *name = NewName(L"Ranz VPN x509 test", NULL, NULL, NULL, NULL, NULL);
	X *valid = NewRootX(pub, priv, name, 365, NULL);
	BUF *valid_pem = XToBuf(valid, true);
	BUF *one = NewBuf();
	BUF *bundle = NewBuf();

	X509TestCheck(ctx, valid != NULL && valid_pem != NULL, "Valid self-signed RSA-2048 certificate is made");

	// Alone: X509ToX gets no public key from it
	WriteBuf(one, x509t_unknown_key_pem, StrLen(x509t_unknown_key_pem));
	X *x = BufToX(one, true);
	X509TestCheck(ctx, x == NULL, "BufToX refuses the certificate with the unknown public key algorithm");
	FreeX(x);

	// First in a bundle, the valid certificate after it
	WriteBuf(bundle, x509t_unknown_key_pem, StrLen(x509t_unknown_key_pem));
	WriteBufBuf(bundle, valid_pem);
	LIST *chain = BufToXList(bundle, true);
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
RANZ_TEST("x509", x509_test, "X.509: long name fields, certificate times in UTC, PKCS#1 v1.5 signature length, PEM bundle with an unknown key.");
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

// Load a PEM certificate of the test
static X *X509TestPemToX(const char *pem)
{
	BUF *b = NewBuf();

	WriteBuf(b, pem, StrLen(pem));
	SeekBuf(b, 0, 0);
	X *x = BufToX(b, true);
	FreeBuf(b);

	return x;
}

// Certificate signature test: a certificate with an unknown signature algorithm that names the test
// CA as its issuer is not signed by it
RANZ_TEST("certsig", certsig_test, "Certificate signatures: only X509_verify() == 1 is valid; an unknown signature algorithm fails CheckXEx and GetIssuerFromList.");
void certsig_test(UINT num, char **arg)
{
	X509T_CTX ctx;
	X *ca = X509TestPemToX(x509t_certsig_ca_pem);
	X *leaf = X509TestPemToX(x509t_certsig_leaf_pem);
	X *forged = X509TestPemToX(x509t_certsig_forged_pem);
	K *ca_k = NULL;
	K *leaf_k = NULL;
	LIST *roots = NewList(NULL);

	Zero(&ctx, sizeof(ctx));

	Print("Certificate signature test (CheckSignature, CheckXEx, GetIssuerFromList; only X509_verify() == 1 is valid)\n");

	if (X509TestCheck(&ctx, ca != NULL && leaf != NULL && forged != NULL, "Test CA, leaf and forged certificates load"))
	{
		ca_k = GetKFromX(ca);
		leaf_k = GetKFromX(leaf);
		X509TestCheck(&ctx, ca_k != NULL && leaf_k != NULL, "Public keys of the test CA and the leaf load");

		// The list of root certificates of a hub (AUTHTYPE_ROOTCERT)
		Add(roots, ca);

		// A certificate the CA really signed
		X509TestCheck(&ctx, CheckSignature(leaf, ca_k), "CheckSignature: the leaf verifies with the CA key");
		X509TestCheck(&ctx, CheckXEx(leaf, ca, true, true), "CheckXEx: the leaf verifies against the CA, name and dates checked");
		X509TestCheck(&ctx, GetIssuerFromList(roots, leaf) == ca, "GetIssuerFromList: the CA is the issuer of the leaf");

		// The wrong key
		X509TestCheck(&ctx, CheckSignature(leaf, leaf_k) == false, "CheckSignature: the leaf does not verify with its own key");
		X509TestCheck(&ctx, CheckXEx(leaf, leaf, false, false) == false, "CheckXEx: the leaf does not verify against itself");

		// Unknown signature algorithm: X509_verify() returns -1, not 1
		X509TestCheck(&ctx, CheckSignature(forged, ca_k) == false,
			"CheckSignature: the certificate with an unknown signature algorithm does not verify with the CA key");
		X509TestCheck(&ctx, CheckXEx(forged, ca, true, true) == false,
			"CheckXEx: the certificate with an unknown signature algorithm does not verify against the CA");
		X509TestCheck(&ctx, CheckXEx(forged, ca, false, false) == false,
			"CheckXEx without the name and date checks: it does not verify either");
		X509TestCheck(&ctx, GetIssuerFromList(roots, forged) == NULL,
			"GetIssuerFromList: no issuer for the certificate with an unknown signature algorithm");
	}

	ReleaseList(roots);
	FreeK(leaf_k);
	FreeK(ca_k);
	FreeX(forged);
	FreeX(leaf);
	FreeX(ca);

	if (ctx.NumFailed == 0)
	{
		Print("CERTSIG TEST OK\n");
	}
	else
	{
		Print("CERTSIG TEST FAILED (%u of %u checks failed)\n", ctx.NumFailed, ctx.NumChecks);
	}
}

// Read a PEM certificate of the test as an OpenSSL X509, which the caller frees
static X509 *X509TestPemToX509(char *pem)
{
	BIO *bio = BIO_new_mem_buf(pem, -1);
	X509 *x509 = NULL;

	if (bio != NULL)
	{
		x509 = PEM_read_bio_X509(bio, NULL, NULL, NULL);
		BIO_free(bio);
	}

	return x509;
}

// Root certificate and X509ToX ownership test
RANZ_TEST("x509root", x509root_test, "Root certificates: root_cert only for a verified self-signature; X509ToX leaves a certificate it refuses to its caller.");
void x509root_test(UINT num, char **arg)
{
	X509T_CTX ctx;
	X *ca = X509TestPemToX(x509t_certsig_ca_pem);
	X *bad = X509TestPemToX(x509t_x509root_bad_pem);
	X509 *unknown = X509TestPemToX509(x509t_unknown_key_pem);
	X *x;

	Zero(&ctx, sizeof(ctx));

	Print("Root certificate and X509ToX ownership test (root_cert only for a verified self-signature)\n");

	X509TestCheck(&ctx, ca != NULL && ca->root_cert, "The certsig test CA, really self-signed, is a root certificate");
	X509TestCheck(&ctx, bad != NULL && CompareName(bad->issuer_name, bad->subject_name),
		"The certificate with a bad self-signature loads, its issuer and subject names are equal");
	X509TestCheck(&ctx, bad != NULL && bad->root_cert == false,
		"The certificate with a bad self-signature is not a root certificate");

	// X509ToX leaves a certificate it refuses to the caller
	if (X509TestCheck(&ctx, unknown != NULL, "The certificate with the unknown public key algorithm parses"))
	{
		x = X509ToX(unknown);
		if (X509TestCheck(&ctx, x == NULL, "X509ToX refuses the certificate with the unknown public key algorithm"))
		{
			// Still owned here, freed once (the old X509ToX had freed it already)
			X509_free(unknown);
		}
		else
		{
			FreeX(x);
		}
	}

	FreeX(bad);
	FreeX(ca);

	if (ctx.NumFailed == 0)
	{
		Print("X509ROOT TEST OK\n");
	}
	else
	{
		Print("X509ROOT TEST FAILED (%u of %u checks failed)\n", ctx.NumFailed, ctx.NumChecks);
	}
}

// Whether every byte of the buffer has the value
static bool X509TestAllBytes(const UCHAR *buf, UINT size, UCHAR value)
{
	for (UINT i = 0;i < size;i++)
	{
		if (buf[i] != value)
		{
			return false;
		}
	}

	return true;
}

// Explicit sizes: a destination smaller than the signature of the key is refused and nothing is
// written past it; a received signature one byte shorter or longer than the key's is rejected
static void X509TestRsaSizes(X509T_CTX *ctx, K *priv, K *pub, UINT bits)
{
	UCHAR data[SHA1_SIZE];
	UCHAR sign[X509T_MAX_SIGN];
	UCHAR dst[X509T_MAX_SIGN + X509T_GUARD];
	UINT sign_size = bits / 8;
	UINT small = sign_size / 2;
	char what[MAX_SIZE];

	Rand(data, sizeof(data));

	Zero(sign, sizeof(sign));
	bool signed_ok = RsaSignEx(sign, sign_size, data, sizeof(data), priv);
	Format(what, sizeof(what), "RSA-%u: a signature into a destination of exactly %u bytes verifies", bits, sign_size);
	X509TestCheck(ctx, signed_ok && RsaVerifyEx(data, sizeof(data), sign, sign_size, pub), what);

	// Half the size the key signs into
	memset(dst, X509T_GUARD_BYTE, sizeof(dst));
	Format(what, sizeof(what), "RSA-%u: a destination of %u bytes is refused, nothing written past it", bits, small);
	X509TestCheck(ctx, RsaSignEx(dst, small, data, sizeof(data), priv) == false &&
		X509TestAllBytes(dst + small, sizeof(dst) - small, X509T_GUARD_BYTE), what);

	// The signature with one byte less, then with one byte more (a zero) than the key's
	Format(what, sizeof(what), "RSA-%u: the signature received as %u or %u bytes is rejected", bits, sign_size - 1, sign_size + 1);
	X509TestCheck(ctx, signed_ok && RsaVerifyEx(data, sizeof(data), sign, sign_size - 1, pub) == false &&
		RsaVerifyEx(data, sizeof(data), sign, sign_size + 1, pub) == false, what);
}

// RSA client certificate signature test
RANZ_TEST("rsasig", rsasig_test, "RSA client certificate signatures: PKCS#1 v1.5 SHA-1, a destination smaller than the key refused, a signature of another length rejected.");
void rsasig_test(UINT num, char **arg)
{
	X509T_CTX ctx;
	K *priv1024 = NULL, *pub1024 = NULL;
	K *priv2048 = NULL, *pub2048 = NULL;

	Zero(&ctx, sizeof(ctx));

	Print("RSA client certificate signature test (PKCS#1 v1.5 with SHA-1, explicit signature and destination sizes)\n");

	if (X509TestCheck(&ctx, RsaGen(&priv1024, &pub1024, 1024) && RsaGen(&priv2048, &pub2048, 2048),
		"RSA-1024 and RSA-2048 test keys are generated"))
	{
		X509TestRsa(&ctx, priv1024, pub1024, 1024);
		X509TestRsa(&ctx, priv2048, pub2048, 2048);
		X509TestRsaSizes(&ctx, priv2048, pub2048, 2048);
	}

	FreeK(pub2048);
	FreeK(priv2048);
	FreeK(pub1024);
	FreeK(priv1024);

	if (ctx.NumFailed == 0)
	{
		Print("RSASIG TEST OK\n");
	}
	else
	{
		Print("RSASIG TEST FAILED (%u of %u checks failed)\n", ctx.NumFailed, ctx.NumChecks);
	}
}
