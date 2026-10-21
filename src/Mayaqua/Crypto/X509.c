// X509.c
// X.509 on OpenSSL: X, NAME and X_SERIAL, the certificate builders, the checks and the ASN.1 time conversion

#include "Mayaqua/Encrypt.h"

#include "Mayaqua/Internat.h"
#include "Mayaqua/Kernel.h"
#include "Mayaqua/Memory.h"
#include "Mayaqua/Object.h"
#include "Mayaqua/Str.h"

#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/bn.h>
#include <openssl/x509v3.h>

// A FILETIME counts 100 ns ticks since 1601-01-01 UTC
#define	FILETIME_TICKS_PER_SEC		10000000ULL				// FILETIME ticks in a second
#define	FILETIME_UNIX_EPOCH_TICKS	116444736000000000ULL	// 1970-01-01 00:00:00 UTC as a FILETIME

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

	for (UINT i = 0;i < sizeof(values) / sizeof(values[0]);i++)
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
		for (UINT i = 0;i < LIST_NUM(chain);i++)
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
	UINT len;
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
	for (UINT i = 0;i < len;i++)
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
	UINT size;
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
	for (UINT i = 0;i < size;i++)
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
		for (UINT i = 0; i < LIST_NUM(chain); i++)
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
			for (int i = 0; i < sk_ACCESS_DESCRIPTION_num(ads); i++)
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

X *GetIssuerFromList(LIST *cert_list, X *cert)
{
	X *ret = NULL;
	if (cert_list == NULL || cert == NULL)
	{
		return NULL;
	}

	for (UINT i = 0;i < LIST_NUM(cert_list);i++)
	{
		X *x = LIST_DATA(cert_list, i);
		if (CheckXDateNow(x))
		{
			if (CompareName(x->subject_name, cert->issuer_name))
			{
				K *k = GetKFromX(x);

				if (k != NULL)
				{
					if (CheckSignature(cert, k))
					{
						ret = x;
					}
					FreeK(k);
				}
			}
		}
		if (CompareX(x, cert))
		{
			ret = x;
		}
	}

	return ret;
}
