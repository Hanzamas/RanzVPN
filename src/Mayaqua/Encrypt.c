// Encrypt.c
// Encryption and digital certification routine

#include "Mayaqua/Encrypt.h"

#include "Mayaqua/Crypto/Cng.h"
#include "Mayaqua/FileIO.h"
#include "Mayaqua/Internat.h"
#include "Mayaqua/Kernel.h"
#include "Mayaqua/Mayaqua.h"
#include "Mayaqua/Memory.h"
#include "Mayaqua/Object.h"
#include "Mayaqua/Str.h"
#include "Mayaqua/Trace.h"

#include <string.h>

#include <bcrypt.h>

#include <openssl/crypto.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#ifndef OPENSSL_NO_ENGINE
#include <openssl/engine.h>
#endif
#include <openssl/bio.h>
#include <openssl/x509.h>
#include <openssl/pkcs7.h>
#include <openssl/pkcs12.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <openssl/aes.h>
#include <openssl/rsa.h>
#include <openssl/dh.h>
#include <openssl/bn.h>
#include <openssl/pem.h>
#include <openssl/conf.h>
#include <openssl/x509v3.h>
#include <openssl/provider.h>
#ifndef SKIP_OQS_PROVIDER
	extern OSSL_provider_init_fn oqs_provider_init;
#endif

	#include <intrin.h> // For __cpuid()

static OSSL_PROVIDER *ossl_provider_legacy = NULL;
static OSSL_PROVIDER *ossl_provider_default = NULL;
static OSSL_PROVIDER *ossl_provider_oqsprovider = NULL;

typedef struct CB_PARAM
{
	char *password;
} CB_PARAM;

// A FILETIME counts 100 ns ticks since 1601-01-01 UTC
#define	FILETIME_TICKS_PER_SEC		10000000ULL				// FILETIME ticks in a second
#define	FILETIME_UNIX_EPOCH_TICKS	116444736000000000ULL	// 1970-01-01 00:00:00 UTC as a FILETIME

// CNG algorithm providers of MD4, MD5, SHA-1 and RC4, which run on CNG instead of OpenSSL.
// They are opened once, on first use, and kept for the life of the process, as the CNG
// pseudo-handles are (MayaType.h selects the Vista SDK level, which does not declare those).
// A provider that failed to open stays NULL.
static INIT_ONCE cng_init_once = INIT_ONCE_STATIC_INIT;
BCRYPT_ALG_HANDLE cng_md4 = NULL;
BCRYPT_ALG_HANDLE cng_md5 = NULL;
BCRYPT_ALG_HANDLE cng_sha1 = NULL;
BCRYPT_ALG_HANDLE cng_rc4 = NULL;

// Open one CNG algorithm provider; NULL on failure
static BCRYPT_ALG_HANDLE CngOpenAlg(LPCWSTR alg_id)
{
	BCRYPT_ALG_HANDLE h = NULL;

	if (CNG_SUCCESS(BCryptOpenAlgorithmProvider(&h, alg_id, NULL, 0)) == false)
	{
		return NULL;
	}

	return h;
}

// INIT_ONCE callback of CngInit(): open every provider
static BOOL CALLBACK CngOpenAll(PINIT_ONCE once, PVOID param, PVOID *context)
{
	cng_md4 = CngOpenAlg(BCRYPT_MD4_ALGORITHM);
	cng_md5 = CngOpenAlg(BCRYPT_MD5_ALGORITHM);
	cng_sha1 = CngOpenAlg(BCRYPT_SHA1_ALGORITHM);
	cng_rc4 = CngOpenAlg(BCRYPT_RC4_ALGORITHM);

	return TRUE;
}

// Open the CNG providers, once per process; any thread, any time, also before InitCryptLibrary()
void CngInit()
{
	InitOnceExecuteOnce(&cng_init_once, CngOpenAll, NULL, NULL);
}

// Empties the OpenSSL error queue of this thread. The messages are formatted only while Debug() shows them
void DrainCryptErrors(char *what)
{
	UINT err;

	if (IsDebug() == false && IsTraceEnabled() == false)
	{
		ERR_clear_error();
		return;
	}

	while ((err = ERR_get_error()) != 0)
	{
		char tmp[256];

		ERR_error_string_n(err, tmp, sizeof(tmp));
		Debug("%s: %s\n", what, tmp);
	}
}

UINT HashPtrToUINT(void *p)
{
	UCHAR hash_data[SHA256_SIZE];
	UCHAR hash_src[CANARY_RAND_SIZE + sizeof(void *)];
	UINT ret;
	if (p == NULL)
	{
		return 0;
	}

	// The key names the block by its address: the pointer value, never the bytes it points to (blocks
	// with equal content must get different keys, and a key must not change with the content)
	Zero(hash_src, sizeof(hash_src));
	Copy(hash_src + 0, GetCanaryRand(CANARY_RAND_ID_PTR_KEY_HASH), CANARY_RAND_SIZE);
	Copy(hash_src + CANARY_RAND_SIZE, &p, sizeof(void *));

	Sha2_256(hash_data, hash_src, sizeof(hash_src));

	Copy(&ret, hash_data, sizeof(ret));

	return ret;
}

NAME *CopyName(NAME *n)
{
	if (n == NULL)
	{
		return NULL;
	}

	return NewName(n->CommonName, n->Organization, n->Unit,
		n->Country, n->State, n->Local);
}

void GetPrintNameFromX(wchar_t *str, UINT size, X *x)
{
	if (x == NULL || str == NULL)
	{
		return;
	}

	GetPrintNameFromName(str, size, x->subject_name);
}

void GetPrintNameFromName(wchar_t *str, UINT size, NAME *name)
{
	if (str == NULL || name == NULL)
	{
		return;
	}

	if (name->CommonName != NULL)
	{
		UniStrCpy(str, size, name->CommonName);
	}
	else if (name->Organization != NULL)
	{
		UniStrCpy(str, size, name->Organization);
	}
	else if (name->Unit != NULL)
	{
		UniStrCpy(str, size, name->Unit);
	}
	else if (name->State != NULL)
	{
		UniStrCpy(str, size, name->State);
	}
	else if (name->Local != NULL)
	{
		UniStrCpy(str, size, name->Local);
	}
	else if (name->Country != NULL)
	{
		UniStrCpy(str, size, name->Country);
	}
	else
	{
		UniStrCpy(str, size, L"untitled");
	}
}

void GetAllNameFromX(wchar_t *str, UINT size, X *x)
{
	UCHAR md5[MD5_SIZE], sha1[SHA1_SIZE];
	char tmp1[MD5_SIZE * 3 + 8], tmp2[SHA1_SIZE * 3 + 8];
	wchar_t tmp3[sizeof(tmp1) + sizeof(tmp2) + 64];
	if (str == NULL || x == NULL)
	{
		return;
	}

	GetAllNameFromName(str, size, x->subject_name);

	if (x->serial != NULL && x->serial->size >= 1)
	{
		char tmp[128];
		wchar_t tmp2[128];

		BinToStr(tmp, sizeof(tmp), x->serial->data, x->serial->size);
		UniFormat(tmp2, sizeof(tmp2), L", SERIAL=\"%S\"", tmp);

		UniStrCat(str, size, tmp2);
	}

	GetXDigest(x, md5, false);
	GetXDigest(x, sha1, true);

	BinToStr(tmp1, sizeof(tmp1), md5, MD5_SIZE);
	BinToStr(tmp2, sizeof(tmp2), sha1, SHA1_SIZE);

	UniFormat(tmp3, sizeof(tmp3), L" (Digest: MD5=\"%S\", SHA1=\"%S\")", tmp1, tmp2);
	UniStrCat(str, size, tmp3);
}

// Append key, value and ", " to str, cut at size like the rest of the name list
static void AppendNamePart(wchar_t *str, UINT size, wchar_t *key, wchar_t *value)
{
	UniStrCat(str, size, key);
	UniStrCat(str, size, value);
	UniStrCat(str, size, L", ");
}

// Appends the set fields of the name to str, each as "value, " (with_labels: "CN=value, "), and cuts the last ", ".
// str holds the empty string.
static void BuildAllName(wchar_t *str, UINT size, NAME *name, bool with_labels)
{
	wchar_t *labels[] = { L"CN=", L"O=", L"OU=", L"S=", L"L=", L"C=" };
	wchar_t *values[] = { name->CommonName, name->Organization, name->Unit, name->State, name->Local, name->Country };
	UINT i;

	for (i = 0;i < sizeof(values) / sizeof(values[0]);i++)
	{
		if (values[i] != NULL)
		{
			AppendNamePart(str, size, with_labels ? labels[i] : L"", values[i]);
		}
	}

	if (UniStrLen(str) >= 3)
	{
		UINT len = UniStrLen(str);
		if (str[len - 2] == L',' &&
			str[len - 1] == L' ')
		{
			str[len - 2] = 0;
		}
	}
}

void GetAllNameFromName(wchar_t *str, UINT size, NAME *name)
{
	UniStrCpy(str, size, L"");
	if (str == NULL || name == NULL)
	{
		return;
	}

	BuildAllName(str, size, name, true);
}

void GetAllNameFromNameEx(wchar_t *str, UINT size, NAME *name)
{
	if (str == NULL || name == NULL)
	{
		return;
	}

	UniStrCpy(str, size, L"");
	BuildAllName(str, size, name, false);
}

static NAME *CloneName(NAME *n)
{
	NAME *ret;
	if (n == NULL)
	{
		return NULL;
	}

	ret = ZeroMalloc(sizeof(NAME));
	ret->CommonName = CopyUniStr(n->CommonName);
	ret->Organization = CopyUniStr(n->Organization);
	ret->Unit = CopyUniStr(n->Unit);
	ret->Country = CopyUniStr(n->Country);
	ret->State = CopyUniStr(n->State);
	ret->Local = CopyUniStr(n->Local);

	return ret;
}

// The clone holds its own reference to the certificate, FreeX releases exactly one. The parsed
// fields are copied. NewX/NewRootX change an X509 only before they wrap it, so a shared X509 is
// read only.
X *CloneX(X *x)
{
	X *ret;
	if (x == NULL || x->x509 == NULL)
	{
		return NULL;
	}

	if (X509_up_ref(x->x509) != 1)
	{
		return NULL;
	}

	ret = ZeroMalloc(sizeof(X));
	*ret = *x;
	ret->issuer_name = CloneName(x->issuer_name);
	ret->subject_name = CloneName(x->subject_name);
	ret->serial = CloneXSerial(x->serial);
	// The reference above is the clone's own, also when the original does not free its certificate
	ret->do_not_free = false;

	return ret;
}

LIST *CloneXList(LIST *chain)
{
	X *x;
	LIST *ret;
	if (chain == NULL)
	{
		return NULL;
	}

	ret = NewList(NULL);
	LockList(chain);
	{
		UINT i;
		for (i = 0;i < LIST_NUM(chain);i++)
		{
			x = CloneX(LIST_DATA(chain, i));
			if (x != NULL)
			{
				Add(ret, x);
			}
		}
	}
	UnlockList(chain);

	return ret;
}

void FreeXSerial(X_SERIAL *serial)
{
	if (serial == NULL)
	{
		return;
	}

	Free(serial->data);
	Free(serial);
}

bool CompareXSerial(X_SERIAL *s1, X_SERIAL *s2)
{
	if (s1 == NULL || s2 == NULL)
	{
		return false;
	}

	if (s1->size != s2->size)
	{
		return false;
	}

	if (Cmp(s1->data, s2->data, s1->size) != 0)
	{
		return false;
	}

	return true;
}

X_SERIAL *CloneXSerial(X_SERIAL *src)
{
	X_SERIAL *s;
	if (src == NULL)
	{
		return NULL;
	}

	s = ZeroMalloc(sizeof(X_SERIAL));
	s->data = ZeroMalloc(src->size);
	Copy(s->data, src->data, src->size);
	s->size = src->size;

	return s;
}

X_SERIAL *NewXSerial(void *data, UINT size)
{
	X_SERIAL *serial;
	UCHAR *buf = (UCHAR *)data;
	UINT i;
	if (data == NULL || size == 0)
	{
		return NULL;
	}

	for (i = 0;i < size;i++)
	{
		if (buf[i] != 0)
		{
			break;
		}
	}
	if (i == size)
	{
		i = size - 1;
	}
	buf += i;

	serial = Malloc(sizeof(X_SERIAL));
	serial->size = size - i;
	serial->data = ZeroMalloc(size + 16);
	Copy(serial->data, buf, size - i);

	return serial;
}

X *NewX(K *pub, K *priv, X *ca, NAME *name, UINT days, X_SERIAL *serial)
{
	X509 *x509;
	X *x;
	if (pub == NULL || priv == NULL || name == NULL || ca == NULL)
	{
		return NULL;
	}

	x509 = NewX509(pub, priv, ca, name, days, serial);
	if (x509 == NULL)
	{
		return NULL;
	}

	x = X509ToX(x509);

	if (x == NULL)
	{
		FreeX509(x509);
		return NULL;
	}

	return x;
}

X *NewRootX(K *pub, K *priv, NAME *name, UINT days, X_SERIAL *serial)
{
	X509 *x509;
	X *x;
	if (pub == NULL || priv == NULL || name == NULL)
	{
		return NULL;
	}

	x509 = NewRootX509(pub, priv, name, days, serial);
	if (x509 == NULL)
	{
		return NULL;
	}

	x = X509ToX(x509);
	if (x == NULL)
	{
		FreeX509(x509);
		return NULL;
	}

	return x;
}

static void AddKeyUsageX509(EXTENDED_KEY_USAGE *ex, int nid)
{
	ASN1_OBJECT *obj;
	if (ex == NULL)
	{
		return;
	}

	obj = OBJ_nid2obj(nid);
	if (obj != NULL)
	{
		sk_ASN1_OBJECT_push(ex, obj);
	}
}
// Extended key usage of a generated certificate: TLS server and TLS client only
static X509_EXTENSION *NewExtendedKeyUsageForX509()
{
	EXTENDED_KEY_USAGE *ex = sk_ASN1_OBJECT_new_null();
	X509_EXTENSION *ret;

	if (ex == NULL)
	{
		return NULL;
	}

	AddKeyUsageX509(ex, NID_server_auth);
	AddKeyUsageX509(ex, NID_client_auth);

	ret = X509V3_EXT_i2d(NID_ext_key_usage, 0, ex);

	sk_ASN1_OBJECT_pop_free(ex, ASN1_OBJECT_free);

	return ret;
}
static void BitStringSetBit(ASN1_BIT_STRING *str, int bit)
{
	if (str == NULL)
	{
		return;
	}

	ASN1_BIT_STRING_set_bit(str, bit, 1);
}
// Key usage of a generated certificate. Only a CA certificate may sign certificates and CRLs
// (RFC 5280 4.2.1.3: keyCertSign needs CA:TRUE).
static X509_EXTENSION *NewBasicKeyUsageForX509(bool ca)
{
	X509_EXTENSION *ret = NULL;
	ASN1_BIT_STRING *str;

	str = ASN1_BIT_STRING_new();
	if (str != NULL)
	{
		BitStringSetBit(str, 0);	// KU_DIGITAL_SIGNATURE
		BitStringSetBit(str, 1);	// KU_NON_REPUDIATION
		BitStringSetBit(str, 2);	// KU_KEY_ENCIPHERMENT
		BitStringSetBit(str, 3);	// KU_DATA_ENCIPHERMENT
		if (ca)
		{
			BitStringSetBit(str, 5);	// KU_KEY_CERT_SIGN
			BitStringSetBit(str, 6);	// KU_CRL_SIGN
		}

		ret = X509V3_EXT_i2d(NID_key_usage, 0, str);

		ASN1_BIT_STRING_free(str);
	}

	return ret;
}

// Adds an extension made for a new certificate and frees it. False when it is NULL or cannot be added.
static bool AddNewExtToX509(X509 *x509, X509_EXTENSION *ex)
{
	bool ret;

	if (ex == NULL)
	{
		return false;
	}

	ret = (X509_add_ext(x509, ex, -1) == 1);
	X509_EXTENSION_free(ex);

	return ret;
}

// Serial number of a new certificate: the given one, or a random positive 127-bit number. RFC 5280
// 4.1.2.2 asks for a positive serial that is unique per issuer, so a fixed 0 is not used.
static bool SetSerialForNewX509(X509 *x509, X_SERIAL *serial)
{
	ASN1_INTEGER *s = X509_get_serialNumber(x509);
	BIGNUM *bn;
	bool ret;

	if (s == NULL)
	{
		return false;
	}

	if (serial != NULL)
	{
		bn = BN_bin2bn(serial->data, serial->size, NULL);
	}
	else
	{
		UCHAR random_serial[16];

		// Top bit clear (no sign octet in DER), next bit set (never zero, always 16 octets)
		Rand(random_serial, sizeof(random_serial));
		random_serial[0] = (random_serial[0] & 0x7f) | 0x40;

		bn = BN_bin2bn(random_serial, sizeof(random_serial), NULL);
	}

	if (bn == NULL)
	{
		return false;
	}

	ret = (BN_to_ASN1_INTEGER(bn, s) != NULL);
	BN_free(bn);

	return ret;
}

// Subject alternative name of a new certificate: the common name as one DNS name. The name is built as a
// single GENERAL_NAME, so a ',' or "DNS:" in the common name cannot add further entries. A common name
// that is not printable ASCII without spaces gets no SAN; that is not an error.
static bool AddDnsAltNameToX509(X509 *x509, wchar_t *common_name)
{
	char dns[MAX_PATH];
	UINT i, len;
	GENERAL_NAMES *names;
	GENERAL_NAME *gn;
	ASN1_IA5STRING *ia5;
	bool ret = false;

	if (UniIsEmptyStr(common_name))
	{
		return true;
	}

	UniToStr(dns, sizeof(dns), common_name);
	len = StrLen(dns);
	if (len == 0 || len != UniStrLen(common_name))
	{
		return true;
	}
	for (i = 0;i < len;i++)
	{
		if (dns[i] <= ' ' || dns[i] > '~')
		{
			return true;
		}
	}

	names = GENERAL_NAMES_new();
	gn = GENERAL_NAME_new();
	ia5 = ASN1_IA5STRING_new();
	if (names != NULL && gn != NULL && ia5 != NULL && ASN1_STRING_set(ia5, dns, (int)len) == 1)
	{
		GENERAL_NAME_set0_value(gn, GEN_DNS, ia5);
		ia5 = NULL;

		if (sk_GENERAL_NAME_push(names, gn) > 0)
		{
			gn = NULL;
			ret = (X509_add1_ext_i2d(x509, NID_subject_alt_name, names, 0, X509V3_ADD_DEFAULT) == 1);
		}
	}

	ASN1_IA5STRING_free(ia5);
	GENERAL_NAME_free(gn);
	GENERAL_NAMES_free(names);

	return ret;
}

// Sets the public key and signs a new certificate with SHA-256. False when either step fails.
static bool SignNewX509(X509 *x509, K *pub, K *priv)
{
	bool ret = false;

	if (X509_set_pubkey(x509, pub->pkey) == 1 && X509_sign(x509, priv->pkey, EVP_sha256()) > 0)
	{
		ret = true;
	}

	return ret;
}

X509 *NewX509(K *pub, K *priv, X *ca, NAME *name, UINT days, X_SERIAL *serial)
{
	X509 *x509;
	UINT64 notBefore, notAfter;
	const ASN1_TIME *t1, *t2;
	X509_NAME *subject_name, *issuer_name;
	if (pub == NULL || priv == NULL || name == NULL || ca == NULL)
	{
		return NULL;
	}
	if (pub->private_key != false)
	{
		return NULL;
	}
	if (priv->private_key == false)
	{
		return NULL;
	}

	notBefore = SystemTime64();
	notAfter = notBefore + (UINT64)days * (UINT64)3600 * (UINT64)24 * (UINT64)1000;

	x509 = X509_new();
	if (x509 == NULL)
	{
		return NULL;
	}

	X509_set_version(x509, 2L);

	t1 = X509_get0_notBefore(x509);
	t2 = X509_get0_notAfter(x509);
	if (!UINT64ToAsn1Time((void *)t1, notBefore))
	{
		FreeX509(x509);
		return NULL;
	}
	if (!UINT64ToAsn1Time((void *)t2, notAfter))
	{
		FreeX509(x509);
		return NULL;
	}

	subject_name = NameToX509Name(name);
	if (subject_name == NULL)
	{
		FreeX509(x509);
		return NULL;
	}
	issuer_name = X509_get_subject_name(ca->x509);
	if (issuer_name == NULL)
	{
		FreeX509Name(subject_name);
		FreeX509(x509);
		return NULL;
	}

	X509_set_issuer_name(x509, issuer_name);
	X509_set_subject_name(x509, subject_name);

	FreeX509Name(subject_name);

	if (SetSerialForNewX509(x509, serial) == false ||
		AddNewExtToX509(x509, X509V3_EXT_conf_nid(NULL, NULL, NID_basic_constraints, "critical,CA:FALSE")) == false ||
		AddNewExtToX509(x509, NewBasicKeyUsageForX509(false)) == false ||
		AddNewExtToX509(x509, NewExtendedKeyUsageForX509()) == false ||
		AddDnsAltNameToX509(x509, name->CommonName) == false ||
		SignNewX509(x509, pub, priv) == false)
	{
		FreeX509(x509);
		return NULL;
	}

	return x509;
}

X509 *NewRootX509(K *pub, K *priv, NAME *name, UINT days, X_SERIAL *serial)
{
	X509 *x509;
	UINT64 notBefore, notAfter;
	const ASN1_TIME *t1, *t2;
	X509_NAME *subject_name, *issuer_name;
	if (pub == NULL || name == NULL || priv == NULL)
	{
		return NULL;
	}
	if (days == 0)
	{
		days = 365;
	}
	if (priv->private_key == false)
	{
		return NULL;
	}
	if (pub->private_key != false)
	{
		return NULL;
	}

	notBefore = SystemTime64();
	notAfter = notBefore + (UINT64)days * (UINT64)3600 * (UINT64)24 * (UINT64)1000;

	x509 = X509_new();
	if (x509 == NULL)
	{
		return NULL;
	}

	X509_set_version(x509, 2L);

	t1 = X509_get0_notBefore(x509);
	t2 = X509_get0_notAfter(x509);
	if (!UINT64ToAsn1Time((void *)t1, notBefore))
	{
		FreeX509(x509);
		return NULL;
	}
	if (!UINT64ToAsn1Time((void *)t2, notAfter))
	{
		FreeX509(x509);
		return NULL;
	}

	subject_name = NameToX509Name(name);
	if (subject_name == NULL)
	{
		FreeX509(x509);
		return NULL;
	}
	issuer_name = NameToX509Name(name);
	if (issuer_name == NULL)
	{
		FreeX509Name(subject_name);
		FreeX509(x509);
		return NULL;
	}

	X509_set_issuer_name(x509, issuer_name);
	X509_set_subject_name(x509, subject_name);

	FreeX509Name(subject_name);
	FreeX509Name(issuer_name);

	if (SetSerialForNewX509(x509, serial) == false ||
		AddNewExtToX509(x509, X509V3_EXT_conf_nid(NULL, NULL, NID_basic_constraints, "critical,CA:TRUE")) == false ||
		AddNewExtToX509(x509, NewBasicKeyUsageForX509(true)) == false ||
		AddNewExtToX509(x509, NewExtendedKeyUsageForX509()) == false ||
		SignNewX509(x509, pub, priv) == false)
	{
		FreeX509(x509);
		return NULL;
	}

	return x509;
}

void *NameToX509Name(NAME *nm)
{
	X509_NAME *xn;
	if (nm == NULL)
	{
		return NULL;
	}

	xn = X509_NAME_new();
	if (xn == NULL)
	{
		return NULL;
	}

	AddX509Name(xn, NID_commonName, nm->CommonName);
	AddX509Name(xn, NID_organizationName, nm->Organization);
	AddX509Name(xn, NID_organizationalUnitName, nm->Unit);
	AddX509Name(xn, NID_countryName, nm->Country);
	AddX509Name(xn, NID_stateOrProvinceName, nm->State);
	AddX509Name(xn, NID_localityName, nm->Local);

	return xn;
}

bool AddX509Name(void *xn, int nid, wchar_t *str)
{
	X509_NAME *x509_name;
	UINT utf8_size;
	BYTE *utf8;
	int encoding_type = MBSTRING_ASC;
	if (xn == NULL || str == NULL)
	{
		return false;
	}

	utf8_size = CalcUniToUtf8(str);
	if (utf8_size == 0)
	{
		return false;
	}
	utf8 = ZeroMalloc(utf8_size + 1);
	UniToUtf8(utf8, utf8_size, str);
	utf8[utf8_size] = 0;

	if (utf8_size != UniStrLen(str))
	{
		encoding_type = MBSTRING_UTF8;
	}

	x509_name = (X509_NAME *)xn;
	X509_NAME_add_entry_by_NID(x509_name, nid, encoding_type, utf8, utf8_size, -1, 0);
	Free(utf8);

	return true;
}

void FreeX509Name(void *xn)
{
	X509_NAME *x509_name;
	if (xn == NULL)
	{
		return;
	}

	x509_name = (X509_NAME *)xn;
	X509_NAME_free(x509_name);
}

NAME *NewName(wchar_t *common_name, wchar_t *organization, wchar_t *unit,
			  wchar_t *country, wchar_t *state, wchar_t *local)
{
	NAME *nm = ZeroMalloc(sizeof(NAME));

	if (UniIsEmptyStr(common_name) == false)
	{
		nm->CommonName = CopyUniStr(common_name);
	}

	if (UniIsEmptyStr(organization) == false)
	{
		nm->Organization = CopyUniStr(organization);
	}

	if (UniIsEmptyStr(unit) == false)
	{
		nm->Unit = CopyUniStr(unit);
	}

	if (UniIsEmptyStr(country) == false)
	{
		nm->Country = CopyUniStr(country);
	}

	if (UniIsEmptyStr(state) == false)
	{
		nm->State = CopyUniStr(state);
	}

	if (UniIsEmptyStr(local) == false)
	{
		nm->Local = CopyUniStr(local);
	}

	return nm;
}

bool CheckXDateNow(X *x)
{
	if (x == NULL)
	{
		return false;
	}

	return CheckXDate(x, SystemTime64());
}

bool CheckXDate(X *x, UINT64 current_system_time)
{
	if (x == NULL)
	{
		return false;
	}

	if (x->notBefore >= current_system_time || x->notAfter <= current_system_time)
	{
		return false;
	}
	return true;
}

static void LoadXDates(X *x)
{
	if (x == NULL)
	{
		return;
	}

	x->notBefore = Asn1TimeToUINT64((ASN1_TIME *)X509_get0_notBefore(x->x509));
	x->notAfter = Asn1TimeToUINT64((ASN1_TIME *)X509_get0_notAfter(x->x509));
}

// Writes the system time t into asn1_time. OpenSSL picks the form RFC 5280 section 4.1.2.5 asks for:
// UTCTime for 1950 to 2049, GeneralizedTime (4-digit year) from 2050, so a later time does not wrap
bool UINT64ToAsn1Time(void *asn1_time, UINT64 t)
{
	FILETIME ft;
	UINT64 ticks;
	if (asn1_time == NULL)
	{
		return false;
	}

	// The UTC time as FILETIME ticks; whole seconds after 1970 are the time_t OpenSSL takes
	UINT64ToFileTime(&ft, t);
	ticks = ((UINT64)ft.dwHighDateTime << 32) | (UINT64)ft.dwLowDateTime;
	if (ticks < FILETIME_UNIX_EPOCH_TICKS + FILETIME_TICKS_PER_SEC)
	{
		return false;
	}

	return ASN1_TIME_set((ASN1_TIME *)asn1_time, (time_t)((ticks - FILETIME_UNIX_EPOCH_TICKS) / FILETIME_TICKS_PER_SEC)) != NULL;
}

UINT64 Asn1TimeToUINT64(void *asn1_time)
{
	SYSTEMTIME st;
	if (asn1_time == NULL)
	{
		return 0;
	}

	if (Asn1TimeToSystem(&st, asn1_time) == false)
	{
		return 0;
	}
	return SystemToUINT64(&st);
}

bool Asn1TimeToSystem(SYSTEMTIME *s, void *asn1_time)
{
	struct tm tm;
	if (s == NULL || asn1_time == NULL)
	{
		return false;
	}

	// UTCTime and GeneralizedTime in a certificate are both UTC ("Z", RFC 5280 section 4.1.2.5):
	// ASN1_TIME_to_tm reads either form as UTC, so neither is moved by the local time zone
	Zero(&tm, sizeof(tm));
	if (ASN1_TIME_to_tm((const ASN1_TIME *)asn1_time, &tm) != 1)
	{
		return false;
	}

	Zero(s, sizeof(SYSTEMTIME));
	s->wYear = (USHORT)(tm.tm_year + 1900);
	s->wMonth = (USHORT)(tm.tm_mon + 1);
	s->wDay = (USHORT)tm.tm_mday;
	s->wHour = (USHORT)tm.tm_hour;
	s->wMinute = (USHORT)tm.tm_min;
	s->wSecond = (USHORT)tm.tm_sec;
	NormalizeSystem(s);

	return true;
}

bool CheckXEx(X *x, X *x_issuer, bool check_name, bool check_date)
{
	K *k;
	bool ret;
	if (x == NULL || x_issuer == NULL)
	{
		return false;
	}

	k = GetKFromX(x_issuer);
	if (k == NULL)
	{
		return false;
	}

	ret = CheckSignature(x, k);

	if (ret)
	{
		if (check_name)
		{
			if (CompareName(x->issuer_name, x_issuer->subject_name) == false)
			{
				ret = false;
			}
		}

		if (check_date)
		{
			if (CheckXDateNow(x_issuer) == false)
			{
				ret = false;
			}
		}
	}

	FreeK(k);

	return ret;
}

bool CheckSignature(X *x, K *k)
{
	bool ret;
	if (x == NULL || k == NULL)
	{
		return false;
	}

	// X509_verify() returns 1 for a valid signature, 0 for a bad one and a negative value when it
	// cannot check it (unknown signature algorithm, bad BIT STRING): only 1 is a valid signature
	ret = (X509_verify(x->x509, k->pkey) == 1);

	return ret;
}

K *GetKFromX(X *x)
{
	EVP_PKEY *pkey;
	K *k;
	if (x == NULL)
	{
		return NULL;
	}

	pkey = X509_get_pubkey(x->x509);
	if (pkey == NULL)
	{
		return NULL;
	}

	k = ZeroMalloc(sizeof(K));
	k->pkey = pkey;

	return k;
}

bool CompareName(NAME *n1, NAME *n2)
{
	if (n1 == NULL || n2 == NULL)
	{
		return false;
	}

	if (UniStrCmpi(n1->CommonName, n2->CommonName) == 0 &&
		UniStrCmpi(n1->Organization, n2->Organization) == 0 &&
		UniStrCmpi(n1->Unit, n2->Unit) == 0 &&
		UniStrCmpi(n1->Country, n2->Country) == 0 &&
		UniStrCmpi(n1->State, n2->State) == 0 &&
		UniStrCmpi(n1->Local, n2->Local) == 0)
	{
		return true;
	}

	return false;
}

static void FreeXNames(X *x)
{
	if (x == NULL)
	{
		return;
	}

	FreeName(x->issuer_name);
	x->issuer_name = NULL;

	FreeName(x->subject_name);
	x->subject_name = NULL;
}

void FreeName(NAME *n)
{
	if (n == NULL)
	{
		return;
	}

	Free(n->CommonName);
	Free(n->Organization);
	Free(n->Unit);
	Free(n->Country);
	Free(n->State);
	Free(n->Local);

	Free(n);

	return;
}

static void LoadXNames(X *x)
{
	X509 *x509;
	if (x == NULL)
	{
		return;
	}

	x509 = x->x509;
	x->issuer_name = X509NameToName(X509_get_issuer_name(x509));
	x->subject_name = X509NameToName(X509_get_subject_name(x509));
}

NAME *X509NameToName(void *xn)
{
	NAME *n;
	if (xn == NULL)
	{
		return NULL;
	}

	n = ZeroMalloc(sizeof(NAME));

	n->CommonName = GetUniStrFromX509Name(xn, NID_commonName);
	n->Organization = GetUniStrFromX509Name(xn, NID_organizationName);
	n->Unit = GetUniStrFromX509Name(xn, NID_organizationalUnitName);
	n->Country = GetUniStrFromX509Name(xn, NID_countryName);
	n->State = GetUniStrFromX509Name(xn, NID_stateOrProvinceName);
	n->Local = GetUniStrFromX509Name(xn, NID_localityName);

	return n;
}

wchar_t *GetUniStrFromX509Name(void *xn, int nid)
{
	char txt[1024];
	UINT i, size;
	int index, len;
	bool unicode = false;
	bool is_utf_8 = false;
	ASN1_OBJECT *obj;
	const ASN1_STRING *data;
	if (xn == NULL || nid == 0)
	{
		return NULL;
	}

	Zero(txt, sizeof(txt));
	len = X509_NAME_get_text_by_NID(xn, nid, txt, sizeof(txt) - 2);
	if (len <= 0)
	{
		return NULL;
	}

	obj = OBJ_nid2obj(nid);
	if (obj == NULL)
	{
		return NULL;
	}
	index = X509_NAME_get_index_by_OBJ(xn, obj, -1);
	if (index < 0)
	{
		return NULL;
	}
	data = X509_NAME_ENTRY_get_data(X509_NAME_get_entry(xn, index));
	if (data == NULL)
	{
		return NULL;
	}
	if (ASN1_STRING_type(data) == V_ASN1_BMPSTRING)
	{
		unicode = true;
	}
	if (ASN1_STRING_type(data) == V_ASN1_UTF8STRING || ASN1_STRING_type(data) == V_ASN1_T61STRING)
	{
		is_utf_8 = true;
	}

	// Scan only the bytes X509_NAME_get_text_by_NID copied (at most sizeof(txt) - 3): the field
	// comes from the peer's certificate, and a scan sized from it ran past txt
	size = (UINT)len;
	for (i = 0;i < size;i++)
	{
		if ((UCHAR)txt[i] >= 0x80)
		{
			unicode = true;
			break;
		}
	}

	if (is_utf_8)
	{
		wchar_t *ret;
		UINT ret_size;

		ret_size = CalcUtf8ToUni(txt, StrLen(txt));
		ret = ZeroMalloc(ret_size + 8);
		Utf8ToUni(ret, ret_size, txt, StrLen(txt));

		return ret;
	}
	else if (unicode == false)
	{
		wchar_t tmp[1024];
		StrToUni(tmp, sizeof(tmp), txt);
		return CopyUniStr(tmp);
	}
	else
	{
		EndianUnicode((wchar_t *)txt);
		return CopyUniStr((wchar_t *)txt);
	}
}

bool CompareX(X *x1, X *x2)
{
	if (x1 == NULL || x2 == NULL)
	{
		return false;
	}

	return (X509_cmp(x1->x509, x2->x509) == 0);
}

bool CheckXandK(X *x, K *k)
{
	if (x == NULL || k == NULL)
	{
		return false;
	}

	if (X509_check_private_key(x->x509, k->pkey) != 0)
	{
		return true;
	}
	else
	{
		return false;
	}
}

X *FileToXW(wchar_t *filename)
{
	bool text;
	BUF *b;
	X *x;
	if (filename == NULL)
	{
		return NULL;
	}

	b = ReadDumpW(filename);
	text = IsBase64(b);

	x = BufToX(b, text);
	FreeBuf(b);

	return x;
}

bool XToFileW(X *x, wchar_t *filename, bool text)
{
	BUF *b;
	bool ret;
	if (x == NULL || filename == NULL)
	{
		return false;
	}

	b = XToBuf(x, text);
	if (b == NULL)
	{
		return false;
	}

	ret = DumpBufW(b, filename);
	FreeBuf(b);

	return ret;
}

K *FileToKW(wchar_t *filename, bool private_key, char *password)
{
	bool text;
	BUF *b;
	K *k;
	if (filename == NULL)
	{
		return NULL;
	}

	b = ReadDumpW(filename);
	if (b == NULL)
	{
		return NULL;
	}

	text = IsBase64(b);
	if (text == false)
	{
		k = BufToK(b, private_key, false, NULL);
	}
	else
	{
		k = BufToK(b, private_key, true, NULL);
		if (k == NULL)
		{
			k = BufToK(b, private_key, true, password);
		}
	}

	FreeBuf(b);

	return k;
}

bool KToFileW(K *k, wchar_t *filename, bool text, char *password)
{
	BUF *b;
	bool ret;
	if (k == NULL || filename == NULL)
	{
		return false;
	}

	b = KToBuf(k, text, password);
	if (b == NULL)
	{
		return false;
	}

	ret = DumpBufW(b, filename);
	FreeBuf(b);

	return ret;
}

BUF *KToBuf(K *k, bool text, char *password)
{
	BUF *buf;
	BIO *bio;
	if (k == NULL)
	{
		return NULL;
	}

	bio = KToBio(k, text, password);
	if (bio == NULL)
	{
		return NULL;
	}

	buf = BioToBuf(bio);
	FreeBio(bio);

	SeekBuf(buf, 0, 0);

	return buf;
}

BIO *KToBio(K *k, bool text, char *password)
{
	BIO *bio;
	if (k == NULL)
	{
		return NULL;
	}

	bio = BIO_new(BIO_s_mem());

	if (k->private_key)
	{
		if (text == false)
		{
			i2d_PrivateKey_bio(bio, k->pkey);
		}
		else
		{
			if (password == 0 || StrLen(password) == 0)
			{
				PEM_write_bio_PrivateKey(bio, k->pkey, NULL, NULL, 0, NULL, NULL);
			}
			else
			{
				CB_PARAM cb;
				cb.password = password;
				PEM_write_bio_PrivateKey(bio, k->pkey, EVP_des_ede3_cbc(),
					NULL, 0, (pem_password_cb *)PKeyPasswordCallbackFunction, &cb);
			}
		}
	}
	else
	{
		if (text == false)
		{
			i2d_PUBKEY_bio(bio, k->pkey);
		}
		else
		{
			PEM_write_bio_PUBKEY(bio, k->pkey);
		}
	}

	return bio;
}

bool IsBase64(BUF *b)
{
	UINT i;
	if (b == NULL)
	{
		return false;
	}

	if (SearchAsciiInBinary(b->Buf, b->Size, "-----BEGIN", false) != INFINITE)
	{
		return true;
	}

	for (i = 0;i < b->Size;i++)
	{
		char c = ((char *)b->Buf)[i];
		bool b = false;
		if ('a' <= c && c <= 'z')
		{
			b = true;
		}
		else if ('A' <= c && c <= 'Z')
		{
			b = true;
		}
		else if ('0' <= c && c <= '9')
		{
			b = true;
		}
		else if (c == ':' || c == '.' || c == ';' || c == ',')
		{
			b = true;
		}
		else if (c == '!' || c == '&' || c == '#' || c == '(' || c == ')')
		{
			b = true;
		}
		else if (c == '-' || c == ' ')
		{
			b = true;
		}
		else if (c == 13 || c == 10 || c == EOF)
		{
			b = true;
		}
		else if (c == '\t' || c == '=' || c == '+' || c == '/')
		{
			b = true;
		}
		if (b == false)
		{
			return false;
		}
	}
	return true;
}

bool IsEncryptedK(BUF *b, bool private_key)
{
	K *k;
	if (b == NULL)
	{
		return false;
	}
	if (IsBase64(b) == false)
	{
		return false;
	}

	k = BufToK(b, private_key, true, NULL);
	if (k != NULL)
	{
		FreeK(k);
		return false;
	}

	return true;
}

K *OpensslEngineToK(char *key_file_name, char *engine_name)
{
#ifndef OPENSSL_NO_ENGINE
    K *k;
    ENGINE *engine = ENGINE_by_id(engine_name);
    ENGINE_init(engine);
    EVP_PKEY *pkey;
    pkey = ENGINE_load_private_key(engine, key_file_name, NULL, NULL);
   	k = ZeroMalloc(sizeof(K));
    k->pkey = pkey;
    k->private_key = true;
    return k;
#else
    return NULL;
#endif
}

K *BufToK(BUF *b, bool private_key, bool text, char *password)
{
	BIO *bio;
	K *k;
	if (b == NULL)
	{
		return NULL;
	}

	bio = BufToBio(b);
	k = BioToK(bio, private_key, text, password);
	FreeBio(bio);

	return k;
}

K *BioToK(BIO *bio, bool private_key, bool text, char *password)
{
	EVP_PKEY *pkey;
	K *k;
	if (bio == NULL)
	{
		return NULL;
	}

	if (password != NULL && StrLen(password) == 0)
	{
		password = NULL;
	}

	if (private_key == false)
	{
		if (text == false)
		{
			pkey = d2i_PUBKEY_bio(bio, NULL);
			if (pkey == NULL)
			{
				return NULL;
			}
		}
		else
		{
			CB_PARAM cb;
			cb.password = password;
			pkey = PEM_read_bio_PUBKEY(bio, NULL, (pem_password_cb *)PKeyPasswordCallbackFunction, &cb);
			if (pkey == NULL)
			{
				return NULL;
			}
		}
	}
	else
	{
		if (text == false)
		{
			pkey = d2i_PrivateKey_bio(bio, NULL);
			if (pkey == NULL)
			{
				return NULL;
			}
		}
		else
		{
			CB_PARAM cb;
			cb.password = password;
			pkey = PEM_read_bio_PrivateKey(bio, NULL, (pem_password_cb *)PKeyPasswordCallbackFunction, &cb);
			if (pkey == NULL)
			{
				return NULL;
			}
		}
	}

	k = ZeroMalloc(sizeof(K));
	k->pkey = pkey;
	k->private_key = private_key;

	return k;
}

int PKeyPasswordCallbackFunction(char *buf, int bufsize, int verify, void *param)
{
	CB_PARAM *cb;
	if (buf == NULL || param == NULL || bufsize == 0)
	{
		return 0;
	}

	cb = (CB_PARAM *)param;
	if (cb->password == NULL)
	{
		return 0;
	}

	return StrCpy(buf, bufsize, cb->password);
}

BUF *XToBuf(X *x, bool text)
{
	BIO *bio;
	BUF *b;
	if (x == NULL)
	{
		return NULL;
	}

	bio = XToBio(x, text);
	if (bio == NULL)
	{
		return NULL;
	}

	b = BioToBuf(bio);
	FreeBio(bio);

	SeekBuf(b, 0, 0);

	return b;
}

BIO *XToBio(X *x, bool text)
{
	BIO *bio;
	if (x == NULL)
	{
		return NULL;
	}

	bio = BIO_new(BIO_s_mem());

	if (text == false)
	{
		i2d_X509_bio(bio, x->x509);
	}
	else
	{
		PEM_write_bio_X509(bio, x->x509);
	}

	return bio;
}

void FreeX(X *x)
{
	if (x == NULL)
	{
		return;
	}

	FreeXNames(x);


	FreeXSerial(x->serial);

	if (x->do_not_free == false)
	{
		FreeX509(x->x509);
	}
	Free(x);
}

void FreeXList(LIST *chain)
{
	if (chain == NULL)
	{
		return;
	}

	LockList(chain);
	{
		UINT i;
		for (i = 0; i < LIST_NUM(chain); i++)
		{
			X *x = LIST_DATA(chain, i);
			FreeX(x);
		}
	}
	UnlockList(chain);

	ReleaseList(chain);
}

void FreeX509(X509 *x509)
{
	if (x509 == NULL)
	{
		return;
	}

	X509_free(x509);
}

// The caller keeps b and frees it, also when this fails
X *BufToX(BUF *b, bool text)
{
	X *x;
	BIO *bio;
	if (b == NULL)
	{
		return NULL;
	}

	bio = BufToBio(b);
	if (bio == NULL)
	{
		return NULL;
	}

	x = BioToX(bio, text);

	FreeBio(bio);

	return x;
}

// The caller keeps b and frees it, also when this fails
LIST *BufToXList(BUF *b, bool text)
{
	LIST *chain;
	BIO *bio;
	if (b == NULL)
	{
		return NULL;
	}

	bio = BufToBio(b);
	if (bio == NULL)
	{
		return NULL;
	}

	chain = BioToXList(bio, text);

	FreeBio(bio);

	return chain;
}

void GetXDigest(X *x, UCHAR *buf, bool sha1)
{
	if (x == NULL)
	{
		return;
	}

	if (sha1 == false)
	{
		UINT size = MD5_SIZE;
		X509_digest(x->x509, EVP_md5(), buf, (unsigned int *)&size);
	}
	else
	{
		UINT size = SHA1_SIZE;
		X509_digest(x->x509, EVP_sha1(), buf, (unsigned int *)&size);
	}
}

X *BioToX(BIO *bio, bool text)
{
	X *x;
	X509 *x509;
	if (bio == NULL)
	{
		return NULL;
	}

	if (text == false)
	{
		x509 = d2i_X509_bio(bio, NULL);
	}
	else
	{
		x509 = PEM_read_bio_X509(bio, NULL, NULL, NULL);
	}

	if (x509 == NULL)
	{
		return NULL;
	}

	x = X509ToX(x509);

	if (x == NULL)
	{
		FreeX509(x509);
		return NULL;
	}

	return x;
}

LIST *BioToXList(BIO *bio, bool text)
{
	X *x;
	STACK_OF(X509_INFO) *sk = NULL;
	X509_INFO *xi;
	LIST *chain;

	if (bio == NULL || text == false)
	{
		return NULL;
	}

	sk = PEM_X509_INFO_read_bio(bio, NULL, NULL, NULL);
	if (sk == NULL)
	{
		return NULL;
	}

	chain = NewList(NULL);

	while (sk_X509_INFO_num(sk))
	{
		xi = sk_X509_INFO_shift(sk);
		x = X509ToX(xi->x509);
		if (x != NULL)
		{
			// The X owns the certificate now
			xi->x509 = NULL;
			Add(chain, x);
		}
		// Also frees a certificate X509ToX refused, once
		X509_INFO_free(xi);
	}

	sk_X509_INFO_free(sk);

	return chain;
}

// Takes ownership of x509 only when it succeeds: the certificate is then freed with the returned X.
// A certificate it refuses (NULL) stays the caller's, who frees it or leaves it to its owner.
X *X509ToX(X509 *x509)
{
	X *x;
	K *k;
	UINT type;
	ASN1_INTEGER *s;
	if (x509 == NULL)
	{
		return NULL;
	}

	x = ZeroMalloc(sizeof(X));
	x->x509 = x509;

	LoadXNames(x);

	LoadXDates(x);

	// A root certificate is self-issued and verifies with its own key: equal names alone (with the
	// key matching itself, which always holds) let a certificate with a bad self-signature end a chain
	if (CompareName(x->issuer_name, x->subject_name))
	{
		K *pubkey = GetKFromX(x);
		if (pubkey != NULL)
		{
			if (CheckSignature(x, pubkey))
			{
				x->root_cert = true;
			}
			FreeK(pubkey);
		}
	}

	if (X509_get_ext_by_NID(x509, NID_basic_constraints, -1) != -1)
	{
		x->has_basic_constraints = true;
	}

	// Get the "Certification Authority Issuer" (1.3.6.1.5.5.7.48.2) field value
	if (x->root_cert == false)
	{
		AUTHORITY_INFO_ACCESS *ads = (AUTHORITY_INFO_ACCESS *)X509_get_ext_d2i(x509, NID_info_access, NULL, NULL);

		if (ads != NULL)
		{
			int i;

			for (i = 0; i < sk_ACCESS_DESCRIPTION_num(ads); i++)
			{
				ACCESS_DESCRIPTION *ad = sk_ACCESS_DESCRIPTION_value(ads, i);
				if (ad != NULL)
				{
					if (OBJ_obj2nid(ad->method) == NID_ad_ca_issuers && ad->location->type == GEN_URI)
					{
						char *uri = (char *)ASN1_STRING_get0_data(ad->location->d.uniformResourceIdentifier);
						if (IsEmptyStr(uri) == false)
						{
							StrCpy(x->issuer_url, sizeof(x->issuer_url), uri);
							break;
						}
					}
				}
			}

			AUTHORITY_INFO_ACCESS_free(ads);
		}
	}

	s = X509_get_serialNumber(x509);
	x->serial = (s != NULL) ? NewXSerial((void *)ASN1_STRING_get0_data((const ASN1_STRING *)s), ASN1_STRING_length((const ASN1_STRING *)s)) : NULL;
	if (x->serial == NULL)
	{
		char zero = 0;
		x->serial = NewXSerial(&zero, sizeof(char));
	}

	k = GetKFromX(x);
	if (k == NULL)
	{
		// The certificate stays the caller's
		x->x509 = NULL;
		FreeX(x);
		return NULL;
	}

	type = EVP_PKEY_base_id(k->pkey);

	x->bits = EVP_PKEY_bits(k->pkey);
	
	FreeK(k);

	if (type == EVP_PKEY_RSA)
	{
		x->is_compatible_bit = (x->bits == 1024 || x->bits == 1536 || x->bits == 2048 || x->bits == 3072 || x->bits == 4096);
	}

	return x;
}

void FreeBio(BIO *bio)
{
	if (bio == NULL)
	{
		return;
	}

	BIO_free(bio);
}

BUF *BioToBuf(BIO *bio)
{
	BUF *b;
	UINT size;
	void *tmp;
	if (bio == NULL)
	{
		return NULL;
	}

	BIO_seek(bio, 0);
	size = (UINT)BIO_number_written(bio);
	tmp = Malloc(size);
	BIO_read(bio, tmp, size);

	b = NewBuf();
	WriteBuf(b, tmp, size);
	Free(tmp);

	return b;
}

BIO *BufToBio(BUF *b)
{
	BIO *bio;
	if (b == NULL)
	{
		return NULL;
	}

	bio = BIO_new(BIO_s_mem());
	if (bio == NULL)
	{
		return NULL;
	}
	BIO_write(bio, b->Buf, b->Size);
	BIO_seek(bio, 0);

	return bio;
}

void FreeOpenSSLThreadState()
{
	OPENSSL_thread_stop();
}

void FreeCryptLibrary()
{
	if (ossl_provider_default != NULL)
	{
		OSSL_PROVIDER_unload(ossl_provider_default);
		ossl_provider_default = NULL;
	}

	if (ossl_provider_legacy != NULL)
	{
		OSSL_PROVIDER_unload(ossl_provider_legacy);
		ossl_provider_legacy = NULL;
	}

	if (ossl_provider_oqsprovider != NULL)
	{
		OSSL_PROVIDER_unload(ossl_provider_oqsprovider);
		ossl_provider_oqsprovider = NULL;
	}
}

void InitCryptLibrary()
{
	ossl_provider_legacy = OSSL_PROVIDER_load(NULL, "legacy");
	ossl_provider_default = OSSL_PROVIDER_load(NULL, "default");

	char *oqs_provider_name = "oqsprovider";
	#ifndef SKIP_OQS_PROVIDER
		// oqsprovider is linked in, so register it as a built-in provider
		OSSL_PROVIDER_add_builtin(NULL, oqs_provider_name, oqs_provider_init); 
	#endif
	ossl_provider_oqsprovider = OSSL_PROVIDER_load(NULL, oqs_provider_name);

	// Seeds OpenSSL's own generator, which TLS, RSA and DH still use; Rand() runs on CNG
	RAND_poll();

	// The CNG providers are opened here rather than on the first hash
	CngInit();

}

bool IsAesNiSupported()
{
	bool supported = false;

	// OpenSSL has no API to detect AES-NI
  #if defined(_M_X64)
    int regs[4]; // EAX, EBX, ECX, EDX
    __cpuid(regs, 1);
    supported = (regs[2] >> 25) & 1;
  #elif defined(_M_ARM64)
	return IsProcessorFeaturePresent(PF_ARM_V8_CRYPTO_INSTRUCTIONS_AVAILABLE);
  #endif

	return supported;
}
