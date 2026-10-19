// Encrypt.c
// Encryption and digital certification routine

#include "Encrypt.h"

#include "FileIO.h"
#include "Internat.h"
#include "Kernel.h"
#include "Memory.h"
#include "Object.h"
#include "Str.h"

#include <string.h>

#include <bcrypt.h>

#include <openssl/crypto.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
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

LOCK *openssl_lock = NULL;

static int ssl_clientcert_index = 0;

static OSSL_PROVIDER *ossl_provider_legacy = NULL;
static OSSL_PROVIDER *ossl_provider_default = NULL;
static OSSL_PROVIDER *ossl_provider_oqsprovider = NULL;

static void Internal_Sha0(unsigned char *dest, const unsigned char *src, const UINT size);

typedef struct CB_PARAM
{
	char *password;
} CB_PARAM;

// Whether a CNG call succeeded: an NTSTATUS of 0 or more (success or information)
#define	CNG_SUCCESS(status)		(((NTSTATUS)(status)) >= 0)

// BCryptGenRandom() flag of Windows 7 and later, in case the Vista SDK level of MayaType.h hides it
#ifndef	BCRYPT_USE_SYSTEM_PREFERRED_RNG
#define	BCRYPT_USE_SYSTEM_PREFERRED_RNG	0x00000002
#endif	// BCRYPT_USE_SYSTEM_PREFERRED_RNG

// Longest RC4 key (bytes) that CNG turns into real RC4. CNG accepts longer keys without an error
// but then produces a keystream that is not RC4, so NewCrypt() does not give it those.
#define	RC4_MAX_KEY_SIZE	64

// CNG algorithm providers of MD4, MD5, SHA-1, RC4 and DES, which run on CNG instead of OpenSSL.
// They are opened once, on first use, and kept for the life of the process, as the CNG
// pseudo-handles are (MayaType.h selects the Vista SDK level, which does not declare those).
// A provider that failed to open stays NULL.
static INIT_ONCE cng_init_once = INIT_ONCE_STATIC_INIT;
static BCRYPT_ALG_HANDLE cng_md4 = NULL;
static BCRYPT_ALG_HANDLE cng_md5 = NULL;
static BCRYPT_ALG_HANDLE cng_sha1 = NULL;
static BCRYPT_ALG_HANDLE cng_rc4 = NULL;
static BCRYPT_ALG_HANDLE cng_des_ecb = NULL;

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
	BCRYPT_ALG_HANDLE des = CngOpenAlg(BCRYPT_DES_ALGORITHM);

	cng_md4 = CngOpenAlg(BCRYPT_MD4_ALGORITHM);
	cng_md5 = CngOpenAlg(BCRYPT_MD5_ALGORITHM);
	cng_sha1 = CngOpenAlg(BCRYPT_SHA1_ALGORITHM);
	cng_rc4 = CngOpenAlg(BCRYPT_RC4_ALGORITHM);

	// DesEcbEncrypt() encrypts single blocks, without chaining
	if (des != NULL)
	{
		if (CNG_SUCCESS(BCryptSetProperty(des, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_ECB, sizeof(BCRYPT_CHAIN_MODE_ECB), 0)))
		{
			cng_des_ecb = des;
		}
		else
		{
			BCryptCloseAlgorithmProvider(des, 0);
		}
	}

	return TRUE;
}

// Open the CNG providers, once per process; any thread, any time, also before InitCryptLibrary()
static void CngInit()
{
	InitOnceExecuteOnce(&cng_init_once, CngOpenAll, NULL, NULL);
}

// Hash with a CNG provider. digest_size is the digest size of the algorithm; the source may be the
// destination. Should CNG fail, the digest is all zero.
static void CngHash(BCRYPT_ALG_HANDLE *alg, void *dst, UINT digest_size, void *src, UINT size)
{
	BCRYPT_HASH_HANDLE h = NULL;
	bool ok = false;

	CngInit();

	if (*alg != NULL && CNG_SUCCESS(BCryptCreateHash(*alg, &h, NULL, 0, NULL, 0, 0)))
	{
		if ((size == 0 || CNG_SUCCESS(BCryptHashData(h, (PUCHAR)src, size, 0))) &&
			CNG_SUCCESS(BCryptFinishHash(h, (PUCHAR)dst, digest_size, 0)))
		{
			ok = true;
		}

		BCryptDestroyHash(h);
	}

	if (ok == false)
	{
		Zero(dst, digest_size);
	}
}

void HashMd4(void *dst, void *src, UINT size)
{
	if (dst == NULL || (src == NULL && size != 0))
	{
		return;
	}

	CngHash(&cng_md4, dst, MD4_SIZE, src, size);
}

void Md5(void *dst, void *src, UINT size)
{
	if (dst == NULL || (src == NULL && size != 0))
	{
		return;
	}

	CngHash(&cng_md5, dst, MD5_SIZE, src, size);
}

void Sha0(void *dst, void *src, UINT size)
{
	if (dst == NULL || (src == NULL && size != 0))
	{
		return;
	}

	Internal_Sha0(dst, src, size);
}

void Sha1(void *dst, void *src, UINT size)
{
	if (dst == NULL || (src == NULL && size != 0))
	{
		return;
	}

	CngHash(&cng_sha1, dst, SHA1_SIZE, src, size);
}

void Sha2_256(void *dst, void *src, UINT size)
{
	if (dst == NULL || (src == NULL && size != 0))
	{
		return;
	}

	SHA256(src, size, dst);
}

CIPHER *NewCipher(char *name)
{
	CIPHER *c;
	if (name == NULL)
	{
		return NULL;
	}

	c = ZeroMalloc(sizeof(CIPHER));

	StrCpy(c->Name, sizeof(c->Name), name);

	if (StrCmpi(name, "[null-cipher]") == 0 ||
		StrCmpi(name, "NULL") == 0 ||
		IsEmptyStr(name))
	{
		c->IsNullCipher = true;
		return c;
	}

	c->Cipher = EVP_get_cipherbyname(c->Name);
	if (c->Cipher == NULL)
	{
		FreeCipher(c);
		return NULL;
	}

	c->Ctx = EVP_CIPHER_CTX_new();

	c->IsAeadCipher = EVP_CIPHER_flags(c->Cipher) & EVP_CIPH_FLAG_AEAD_CIPHER;
	c->BlockSize = EVP_CIPHER_block_size(c->Cipher);
	c->KeySize = EVP_CIPHER_key_length(c->Cipher);
	c->IvSize = EVP_CIPHER_iv_length(c->Cipher);

	return c;
}

void SetCipherKey(CIPHER *c, void *key, bool enc)
{
	if (c == NULL || key == NULL)
	{
		return;
	}

	if (c->IsNullCipher == false)
	{
		if (c->Ctx != NULL)
		{
			EVP_CipherInit(c->Ctx, c->Cipher, key, NULL, enc);
		}
	}

	c->Encrypt = enc;
}

UINT CipherProcessAead(CIPHER *c, void *iv, void *tag, UINT tag_size, void *dest, void *src, UINT src_size, void *aad, UINT aad_size)
{
	int r = src_size;
	int r2 = 0;
	if (c == NULL)
	{
		return 0;
	}
	else if (c->IsNullCipher)
	{
		Copy(dest, src, src_size);
		return src_size;
	}
	else if (c->IsAeadCipher == false || iv == NULL || tag == NULL || tag_size == 0 || dest == NULL || src == NULL || src_size == 0)
	{
		return 0;
	}

	if (EVP_CipherInit_ex(c->Ctx, NULL, NULL, NULL, iv, c->Encrypt) == false)
	{
		Debug("CipherProcessAead(): EVP_CipherInit_ex() failed with error: %s\n", ERR_error_string(ERR_get_error(), NULL));
		return 0;
	}

	if (c->Encrypt == false)
	{
		if (EVP_CIPHER_CTX_ctrl(c->Ctx, EVP_CTRL_AEAD_SET_TAG, tag_size, tag) == false)
		{
			return 0;
		}
	}

	if (aad != NULL && aad_size != 0)
	{
		if (EVP_CipherUpdate(c->Ctx, NULL, &r, aad, aad_size) == false)
		{
			Debug("CipherProcessAead(): EVP_CipherUpdate() failed with error: %s\n", ERR_error_string(ERR_get_error(), NULL));
			return 0;
		}
	}

	if (EVP_CipherUpdate(c->Ctx, dest, &r, src, src_size) == false)
	{
		Debug("CipherProcessAead(): EVP_CipherUpdate() failed with error: %s\n", ERR_error_string(ERR_get_error(), NULL));
		return 0;
	}

	if (EVP_CipherFinal_ex(c->Ctx, ((UCHAR *)dest) + (UINT)r, &r2) == false)
	{
		Debug("CipherProcessAead(): EVP_CipherFinal_ex() failed with error: %s\n", ERR_error_string(ERR_get_error(), NULL));
		return 0;
	}

	if (c->Encrypt)
	{
		if (EVP_CIPHER_CTX_ctrl(c->Ctx, EVP_CTRL_AEAD_GET_TAG, tag_size, tag) == false)
		{
			return 0;
		}
	}

	return r + r2;
}

void FreeCipher(CIPHER *c)
{
	if (c == NULL)
	{
		return;
	}

	if (c->Ctx != NULL)
	{
		EVP_CIPHER_CTX_free(c->Ctx);
	}

	Free(c);
}

static BUF *RsaPublicToBuf(K *k)
{
	BUF *b;
	RSA *rsa;
	const BIGNUM *n;
	if (k == NULL || k->pkey == NULL)
	{
		return NULL;
	}

	rsa = EVP_PKEY_get0_RSA(k->pkey);
	if (rsa == NULL)
	{
		return NULL;
	}

	RSA_get0_key(rsa, &n, NULL, NULL);
	if (n == NULL)
	{
		return NULL;
	}

	b = BigNumToBuf(n);

	if (b == NULL)
	{
		return NULL;
	}

	return b;
}

static UINT RsaPublicSize(K *k)
{
	BUF *b;
	UINT ret;

	b = RsaPublicToBuf(k);
	if (b == NULL)
	{
		return 0;
	}

	ret = b->Size;

	FreeBuf(b);

	return ret;
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

static BIGNUM *BinToBigNum(void *data, UINT size)
{
	BIGNUM *bn;
	if (data == NULL)
	{
		return NULL;
	}

	bn = BN_new();
	BN_bin2bn(data, size, bn);

	return bn;
}

BUF *BigNumToBuf(const BIGNUM *bn)
{
	UINT size;
	UCHAR *tmp;
	BUF *b;
	if (bn == NULL)
	{
		return NULL;
	}

	size = BN_num_bytes(bn);
	tmp = ZeroMalloc(size);
	BN_bn2bin(bn, tmp);

	b = NewBuf();
	WriteBuf(b, tmp, size);
	Free(tmp);

	SeekBuf(b, 0, 0);

	return b;
}

static void OpenSSL_InitLock()
{
}

static void OpenSSL_FreeLock()
{
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

void GetAllNameFromName(wchar_t *str, UINT size, NAME *name)
{
	UniStrCpy(str, size, L"");
	if (str == NULL || name == NULL)
	{
		return;
	}

	if (name->CommonName != NULL)
	{
		UniFormat(str, size, L"%sCN=%s, ", str, name->CommonName);
	}
	if (name->Organization != NULL)
	{
		UniFormat(str, size, L"%sO=%s, ", str, name->Organization);
	}
	if (name->Unit != NULL)
	{
		UniFormat(str, size, L"%sOU=%s, ", str, name->Unit);
	}
	if (name->State != NULL)
	{
		UniFormat(str, size, L"%sS=%s, ", str, name->State);
	}
	if (name->Local != NULL)
	{
		UniFormat(str, size, L"%sL=%s, ", str, name->Local);
	}
	if (name->Country != NULL)
	{
		UniFormat(str, size, L"%sC=%s, ", str, name->Country);
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
void GetAllNameFromNameEx(wchar_t *str, UINT size, NAME *name)
{
	if (str == NULL || name == NULL)
	{
		return;
	}

	UniStrCpy(str, size, L"");
	if (name->CommonName != NULL)
	{
		UniFormat(str, size, L"%s%s, ", str, name->CommonName);
	}
	if (name->Organization != NULL)
	{
		UniFormat(str, size, L"%s%s, ", str, name->Organization);
	}
	if (name->Unit != NULL)
	{
		UniFormat(str, size, L"%s%s, ", str, name->Unit);
	}
	if (name->State != NULL)
	{
		UniFormat(str, size, L"%s%s, ", str, name->State);
	}
	if (name->Local != NULL)
	{
		UniFormat(str, size, L"%s%s, ", str, name->Local);
	}
	if (name->Country != NULL)
	{
		UniFormat(str, size, L"%s%s, ", str, name->Country);
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

K *CloneK(K *k)
{
	BUF *b;
	K *ret;
	if (k == NULL)
	{
		return NULL;
	}

	b = KToBuf(k, false, NULL);
	if (b == NULL)
	{
		return NULL;
	}

	ret = BufToK(b, k->private_key, false, NULL);
	FreeBuf(b);

	return ret;
}

X *CloneX(X *x)
{
	BUF *b;
	X *ret;
	if (x == NULL)
	{
		return NULL;
	}

	b = XToBuf(x, false);
	if (b == NULL)
	{
		return NULL;
	}

	ret = BufToX(b, false);
	FreeBuf(b);

	return ret;
}

LIST *CloneXList(LIST *chain)
{
	BUF *b;
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
			x = LIST_DATA(chain, i);
			b = XToBuf(x, false);
			if (b == NULL)
			{
				continue;
			}

			x = BufToX(b, false);
			Add(ret, x);
			FreeBuf(b);
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

static UINT GetDaysUntil2038()
{
	UINT64 now = SystemTime64();
	UINT64 target;
	SYSTEMTIME st;

	Zero(&st, sizeof(st));
	st.wYear = 2038;
	st.wMonth = 1;
	st.wDay = 1;

	target = SystemToUINT64(&st);

	if (now >= target)
	{
		return 0;
	}
	else
	{
		return (UINT)((target - now) / (UINT64)(1000 * 60 * 60 * 24));
	}
}
UINT GetDaysUntil2038Ex()
{
	SYSTEMTIME now;

	Zero(&now, sizeof(now));
	SystemTime(&now);

	if (now.wYear >= 2030)
	{
		UINT64 now = SystemTime64();
		UINT64 target;
		SYSTEMTIME st;

		Zero(&st, sizeof(st));
		st.wYear = 2049;
		st.wMonth = 12;
		st.wDay = 30;

		target = SystemToUINT64(&st);

		if (now >= target)
		{
			return 0;
		}
		else
		{
			return (UINT)((target - now) / (UINT64)(1000 * 60 * 60 * 24));
		}
	}
	else
	{
		return GetDaysUntil2038();
	}
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
	X *x, *x2;
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

	x2 = CloneX(x);
	FreeX(x);

	return x2;
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

	Lock(openssl_lock);
	{
		if (X509_set_pubkey(x509, pub->pkey) == 1 && X509_sign(x509, priv->pkey, EVP_sha256()) > 0)
		{
			ret = true;
		}
	}
	Unlock(openssl_lock);

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

	if (StrLen(utf8) != UniStrLen(str))
	{
		encoding_type = MBSTRING_UTF8;
	}

	x509_name = (X509_NAME *)xn;
	Lock(openssl_lock);
	{
		X509_NAME_add_entry_by_NID(x509_name, nid, encoding_type, utf8, utf8_size, -1, 0);
	}
	Unlock(openssl_lock);
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

bool UINT64ToAsn1Time(void *asn1_time, UINT64 t)
{
	SYSTEMTIME st;
	if (asn1_time == NULL)
	{
		return false;
	}

	UINT64ToSystem(&st, t);
	return SystemToAsn1Time(asn1_time, &st);
}

bool SystemToAsn1Time(void *asn1_time, SYSTEMTIME *s)
{
	char tmp[20];
	ASN1_TIME *t;
	if (asn1_time == NULL || s == NULL)
	{
		return false;
	}

	if (SystemToStr(tmp, sizeof(tmp), s) == false)
	{
		return false;
	}
	t = (ASN1_TIME *)asn1_time;
	return ASN1_TIME_set_string(t, tmp) != 0;
}

bool SystemToStr(char *str, UINT size, SYSTEMTIME *s)
{
	if (str == NULL || s == NULL)
	{
		return false;
	}

	Format(str, size, "%02u%02u%02u%02u%02u%02uZ",
		s->wYear % 100, s->wMonth, s->wDay,
		s->wHour, s->wMinute, s->wSecond);

	return true;
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
	ASN1_TIME *t;
	char tmp[32];
	int len;
	const char *src;
	if (s == NULL || asn1_time == NULL)
	{
		return false;
	}

	t = (ASN1_TIME *)asn1_time;
	len = ASN1_STRING_length((const ASN1_STRING *)t);
	src = (const char *)ASN1_STRING_get0_data((const ASN1_STRING *)t);

	if (src == NULL || len <= 0 || len >= (int)sizeof(tmp))
	{
		return false;
	}

	Copy(tmp, src, len);
	tmp[len] = '\0';

	// UTCTime and GeneralizedTime in a certificate are both UTC ("Z", RFC 5280 section 4.1.2.5),
	// so neither form is moved by the local time zone
	return StrToSystem(s, tmp);
}

bool StrToSystem(SYSTEMTIME *s, char *str)
{
	char century[3] = {0, 0, 0};
	bool fourdigityear = false;

	if (s == NULL || str == NULL)
	{
		return false;
	}
	if (StrLen(str) != 13)
	{
		if (StrLen(str) != 15)
		{
			return false;
		}

		// A 4-digit year: keep the first two digits and parse the rest as a 2-digit year
		fourdigityear = true;
		century[0] = str[0];
		century[1] = str[1];
		str += 2;
	}
	if (str[12] != 'Z')
	{
		return false;
	}

	{
		char year[3] = {str[0], str[1], 0},
			month[3] = {str[2], str[3], 0},
			day[3] = {str[4], str[5], 0},
			hour[3] = {str[6], str[7], 0},
			minute[3] = {str[8], str[9], 0},
			second[3] = {str[10], str[11], 0};
		Zero(s, sizeof(SYSTEMTIME));
		s->wYear = ToInt(year);
		if (fourdigityear)
		{
			s->wYear += ToInt(century) * 100;
		}
		else if (s->wYear >= 60)
		{
			s->wYear += 1900;
		}
		else
		{
			s->wYear += 2000;
		}
		s->wMonth = ToInt(month);
		s->wDay = ToInt(day);
		s->wHour = ToInt(hour);
		s->wMinute = ToInt(minute);
		s->wSecond = ToInt(second);
		NormalizeSystem(s);
	}

	return true;
}

// Verifies the RSASSA-PKCS1-v1_5 signature with SHA-1 of a client certificate (over the server's
// random bytes). sign_size is the size received: a signature is exactly one modulus long, and
// OpenSSL accepts only the padding, the SHA-1 DigestInfo and the hash in the block, nothing after it.
bool RsaVerifyEx(void *data, UINT data_size, void *sign, UINT sign_size, K *k)
{
	EVP_MD_CTX *md_ctx;
	EVP_PKEY_CTX *pkey_ctx = NULL;
	int key_size;
	bool ret = false;
	if (data == NULL || data_size == 0 || sign == NULL || k == NULL || k->pkey == NULL || k->private_key != false ||
		EVP_PKEY_base_id(k->pkey) != EVP_PKEY_RSA)
	{
		return false;
	}

	key_size = EVP_PKEY_size(k->pkey);
	if (key_size <= 0 || sign_size != (UINT)key_size)
	{
		return false;
	}

	md_ctx = EVP_MD_CTX_new();
	if (md_ctx == NULL)
	{
		return false;
	}

	if (EVP_DigestVerifyInit(md_ctx, &pkey_ctx, EVP_sha1(), NULL, k->pkey) == 1 &&
		EVP_PKEY_CTX_set_rsa_padding(pkey_ctx, RSA_PKCS1_PADDING) == 1 &&
		EVP_DigestVerify(md_ctx, sign, sign_size, data, data_size) == 1)
	{
		ret = true;
	}

	EVP_MD_CTX_free(md_ctx);

	return ret;
}

// Makes the RSASSA-PKCS1-v1_5 signature with SHA-1 of src (the client certificate signature). The
// signature is EVP_PKEY_size() bytes long; a dst_size smaller than that is refused before anything
// is written.
bool RsaSignEx(void *dst, UINT dst_size, void *src, UINT src_size, K *k)
{
	EVP_MD_CTX *md_ctx;
	EVP_PKEY_CTX *pkey_ctx = NULL;
	size_t sign_size;
	int key_size;
	bool ret = false;
	if (dst == NULL || src == NULL || src_size == 0 || k == NULL || k->pkey == NULL ||
		EVP_PKEY_base_id(k->pkey) != EVP_PKEY_RSA)
	{
		return false;
	}

	key_size = EVP_PKEY_size(k->pkey);
	if (key_size <= 0 || (UINT)key_size > dst_size)
	{
		return false;
	}

	md_ctx = EVP_MD_CTX_new();
	if (md_ctx == NULL)
	{
		return false;
	}

	sign_size = (size_t)key_size;
	if (EVP_DigestSignInit(md_ctx, &pkey_ctx, EVP_sha1(), NULL, k->pkey) == 1 &&
		EVP_PKEY_CTX_set_rsa_padding(pkey_ctx, RSA_PKCS1_PADDING) == 1 &&
		EVP_DigestSign(md_ctx, dst, &sign_size, src, src_size) == 1 &&
		sign_size == (size_t)key_size)
	{
		ret = true;
	}

	EVP_MD_CTX_free(md_ctx);

	return ret;
}

bool RsaCheckEx()
{
	UINT num = 20;
	UINT i;

	for (i = 0;i < num;i++)
	{
		if (RsaCheck())
		{
			return true;
		}

		SleepThread(100);
	}

	return false;
}
bool RsaCheck()
{
	int ret = 0;
	RSA *rsa = NULL;
	BIGNUM *e = NULL;
	K *priv_key, *pub_key;
	BIO *bio;
	char errbuf[MAX_SIZE];
	UINT size = 0;
	UINT bit = RSA_KEY_SIZE;

	e = BN_new();
	ret = BN_set_word(e, RSA_F4);
	if (ret == 0)
	{
		BN_free(e);
		Debug("BN_set_word: err=%s\n", ERR_error_string(ERR_get_error(), errbuf));
		return false;
	}

	Lock(openssl_lock);
	{
		rsa = RSA_new();
		ret = RSA_generate_key_ex(rsa, bit, e, NULL);
		BN_free(e);
	}
	Unlock(openssl_lock);
	if (ret == 0)
	{
		Debug("RSA_generate_key_ex: err=%s\n", ERR_error_string(ERR_get_error(), errbuf));
		return false;
	}

	bio = BIO_new(BIO_s_mem());
	Lock(openssl_lock);
	{
		i2d_RSAPrivateKey_bio(bio, rsa);
	}
	Unlock(openssl_lock);
	BIO_seek(bio, 0);
	priv_key = BioToK(bio, true, false, NULL);
	FreeBio(bio);

	bio = BIO_new(BIO_s_mem());
	Lock(openssl_lock);
	{
		i2d_RSA_PUBKEY_bio(bio, rsa);
	}
	Unlock(openssl_lock);
	BIO_seek(bio, 0);
	pub_key = BioToK(bio, false, false, NULL);
	FreeBio(bio);

	RSA_free(rsa);

	size = RsaPublicSize(pub_key);

	if (size != ((bit + 7) / 8))
	{
		FreeK(priv_key);
		FreeK(pub_key);

		return false;
	}

	FreeK(priv_key);
	FreeK(pub_key);

	return true;
}

bool RsaGen(K **priv, K **pub, UINT bit)
{
	int ret = 0;
	RSA *rsa = NULL;
	BIGNUM *e = NULL;
	K *priv_key, *pub_key;
	BIO *bio;
	char errbuf[MAX_SIZE];
	UINT size = 0;
	if (priv == NULL || pub == NULL)
	{
		return false;
	}
	if (bit == 0)
	{
		bit = RSA_KEY_SIZE;
	}

	e = BN_new();
	ret = BN_set_word(e, RSA_F4);
	if (ret == 0)
	{
		BN_free(e);
		Debug("BN_set_word: err=%s\n", ERR_error_string(ERR_get_error(), errbuf));
		return false;
	}

	Lock(openssl_lock);
	{
		rsa = RSA_new();
		ret = RSA_generate_key_ex(rsa, bit, e, NULL);
		BN_free(e);
	}
	Unlock(openssl_lock);
	if (ret == 0)
	{
		Debug("RSA_generate_key_ex: err=%s\n", ERR_error_string(ERR_get_error(), errbuf));
		return false;
	}

	bio = BIO_new(BIO_s_mem());
	Lock(openssl_lock);
	{
		i2d_RSAPrivateKey_bio(bio, rsa);
	}
	Unlock(openssl_lock);
	BIO_seek(bio, 0);
	priv_key = BioToK(bio, true, false, NULL);
	FreeBio(bio);

	bio = BIO_new(BIO_s_mem());
	Lock(openssl_lock);
	{
		i2d_RSA_PUBKEY_bio(bio, rsa);
	}
	Unlock(openssl_lock);
	BIO_seek(bio, 0);
	pub_key = BioToK(bio, false, false, NULL);
	FreeBio(bio);

	*priv = priv_key;
	*pub = pub_key;

	RSA_free(rsa);

	size = RsaPublicSize(*pub);

	if (size != ((bit + 7) / 8))
	{
		FreeK(*priv);
		FreeK(*pub);

		return RsaGen(priv, pub, bit);
	}

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
	Lock(openssl_lock);
	{
		ret = (X509_verify(x->x509, k->pkey) == 1);
	}
	Unlock(openssl_lock);

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

	Lock(openssl_lock);
	{
		pkey = X509_get_pubkey(x->x509);
	}
	Unlock(openssl_lock);
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
	UCHAR txt[1024];
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
	len = X509_NAME_get_text_by_NID(xn, nid, (char *)txt, sizeof(txt) - 2);
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
		if (txt[i] >= 0x80)
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
		StrToUni(tmp, sizeof(tmp), (char *)txt);
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

	Lock(openssl_lock);
	if (X509_cmp(x1->x509, x2->x509) == 0)
	{
		Unlock(openssl_lock);
		return true;
	}
	else
	{
		Unlock(openssl_lock);
		return false;
	}
}

bool CheckXandK(X *x, K *k)
{
	if (x == NULL || k == NULL)
	{
		return false;
	}

	Lock(openssl_lock);
	if (X509_check_private_key(x->x509, k->pkey) != 0)
	{
		Unlock(openssl_lock);
		return true;
	}
	else
	{
		Unlock(openssl_lock);
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
			Lock(openssl_lock);
			{
				i2d_PrivateKey_bio(bio, k->pkey);
			}
			Unlock(openssl_lock);
		}
		else
		{
			if (password == 0 || StrLen(password) == 0)
			{
				Lock(openssl_lock);
				{
					PEM_write_bio_PrivateKey(bio, k->pkey, NULL, NULL, 0, NULL, NULL);
				}
				Unlock(openssl_lock);
			}
			else
			{
				CB_PARAM cb;
				cb.password = password;
				Lock(openssl_lock);
				{
					PEM_write_bio_PrivateKey(bio, k->pkey, EVP_des_ede3_cbc(),
						NULL, 0, (pem_password_cb *)PKeyPasswordCallbackFunction, &cb);
				}
				Unlock(openssl_lock);
			}
		}
	}
	else
	{
		if (text == false)
		{
			Lock(openssl_lock);
			{
				i2d_PUBKEY_bio(bio, k->pkey);
			}
			Unlock(openssl_lock);
		}
		else
		{
			Lock(openssl_lock);
			{
				PEM_write_bio_PUBKEY(bio, k->pkey);
			}
			Unlock(openssl_lock);
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
#if OPENSSL_API_COMPAT < 0x10100000L
    ENGINE_load_dynamic();
#endif
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

void FreeK(K *k)
{
	if (k == NULL)
	{
		return;
	}

	FreePKey(k->pkey);
	Free(k);
}

void FreePKey(EVP_PKEY *pkey)
{
	if (pkey == NULL)
	{
		return;
	}

	EVP_PKEY_free(pkey);
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
			Lock(openssl_lock);
			{
				pkey = PEM_read_bio_PUBKEY(bio, NULL, (pem_password_cb *)PKeyPasswordCallbackFunction, &cb);
			}
			Unlock(openssl_lock);
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
			Lock(openssl_lock);
			{
				pkey = d2i_PrivateKey_bio(bio, NULL);
			}
			Unlock(openssl_lock);
			if (pkey == NULL)
			{
				return NULL;
			}
		}
		else
		{
			CB_PARAM cb;
			cb.password = password;
			Lock(openssl_lock);
			{
				pkey = PEM_read_bio_PrivateKey(bio, NULL, (pem_password_cb *)PKeyPasswordCallbackFunction, &cb);
			}
			Unlock(openssl_lock);
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

	Lock(openssl_lock);
	{
		if (text == false)
		{
			i2d_X509_bio(bio, x->x509);
		}
		else
		{
			PEM_write_bio_X509(bio, x->x509);
		}
	}
	Unlock(openssl_lock);

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

	Lock(openssl_lock);
	{
		X509_free(x509);
	}
	Unlock(openssl_lock);
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

	Lock(openssl_lock);
	{
		if (text == false)
		{
			x509 = d2i_X509_bio(bio, NULL);
		}
		else
		{
			x509 = PEM_read_bio_X509(bio, NULL, NULL, NULL);
		}
	}
	Unlock(openssl_lock);

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

	Lock(openssl_lock);
	{
		sk = PEM_X509_INFO_read_bio(bio, NULL, NULL, NULL);
		if (sk == NULL)
		{
			Unlock(openssl_lock);
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
	}
	Unlock(openssl_lock);

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
		x->is_compatible_bit = true;

		if(x->bits != 1024 && x->bits != 1536 && x->bits != 2048 && x->bits != 3072 && x->bits != 4096)
		{
			x->is_compatible_bit = false;
		}
		else
		{
			x->is_compatible_bit = true;
		}
		
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

	Lock(openssl_lock);
	{
		bio = BIO_new(BIO_s_mem());
		if (bio == NULL)
		{
			Unlock(openssl_lock);
			return NULL;
		}
		BIO_write(bio, b->Buf, b->Size);
		BIO_seek(bio, 0);
	}
	Unlock(openssl_lock);

	return bio;
}

UINT64 Rand64()
{
	UINT64 i;
	Rand(&i, sizeof(i));
	return i;
}

UINT Rand32()
{
	UINT i;
	Rand(&i, sizeof(i));
	return i;
}

USHORT Rand16()
{
	USHORT i;
	Rand(&i, sizeof(i));
	return i;
}

UCHAR Rand8()
{
	UCHAR i;
	Rand(&i, sizeof(i));
	return i;
}

bool Rand1()
{
	return (Rand32() % 2) == 0 ? false : true;
}

void Rand(void *buf, UINT size)
{
	if (buf == NULL || size == 0)
	{
		return;
	}

	// The system-preferred generator needs no provider handle; it fails only on bad arguments.
	// Bytes that may not be random are never returned: the process stops instead.
	if (CNG_SUCCESS(BCryptGenRandom(NULL, (PUCHAR)buf, size, BCRYPT_USE_SYSTEM_PREFERRED_RNG)) == false)
	{
		AbortExitEx("Rand(): BCryptGenRandom() failed");
	}
}

void FreeOpenSSLThreadState()
{
	OPENSSL_thread_stop();
}

void FreeCryptLibrary()
{
	DeleteLock(openssl_lock);
	openssl_lock = NULL;
	OpenSSL_FreeLock();
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
	char tmp[16];

	ossl_provider_default = OSSL_PROVIDER_load(NULL, "legacy");
	ossl_provider_legacy = OSSL_PROVIDER_load(NULL, "default");

	char *oqs_provider_name = "oqsprovider";
	#ifndef SKIP_OQS_PROVIDER
		// oqsprovider is linked in, so register it as a built-in provider
		OSSL_PROVIDER_add_builtin(NULL, oqs_provider_name, oqs_provider_init); 
	#endif
	ossl_provider_oqsprovider = OSSL_PROVIDER_load(NULL, oqs_provider_name);

	ssl_clientcert_index = SSL_get_ex_new_index(0, "struct SslClientCertInfo *", NULL, NULL, NULL);

	// Seeds OpenSSL's own generator, which TLS, RSA and DH still use; Rand() runs on CNG
	RAND_poll();

	// The CNG providers are opened here rather than on the first hash
	CngInit();

	Rand(tmp, sizeof(tmp));
	OpenSSL_InitLock();
}

// RC4 key: a CNG key object, which keeps the keystream position from one Encrypt() call to the next.
// Only keys of 1 to RC4_MAX_KEY_SIZE bytes get a key object: CNG refuses a 0-byte key, and it accepts
// a longer one without an error but then produces a keystream that is not RC4. With any other key,
// Rc4Key stays NULL and Encrypt() writes zeros.
CRYPT *NewCrypt(void *key, UINT size)
{
	CRYPT *c = ZeroMalloc(sizeof(CRYPT));
	BCRYPT_KEY_HANDLE k = NULL;

	CngInit();

	if (cng_rc4 != NULL && key != NULL && size >= 1 && size <= RC4_MAX_KEY_SIZE &&
		CNG_SUCCESS(BCryptGenerateSymmetricKey(cng_rc4, &k, NULL, 0, (PUCHAR)key, size, 0)))
	{
		c->Rc4Key = k;
	}

	return c;
}

void FreeCrypt(CRYPT *c)
{
	if (c == NULL)
	{
		return;
	}

	if (c->Rc4Key != NULL)
	{
		BCryptDestroyKey(c->Rc4Key);
	}

	Free(c);
}

// RC4 of size bytes; dst may be src. Should CNG fail, dst is all zero rather than left as it was,
// so that an in-place call never leaves the plain text in place.
void Encrypt(CRYPT *c, void *dst, void *src, UINT size)
{
	ULONG done = 0;
	if (c == NULL || dst == NULL || src == NULL || size == 0)
	{
		return;
	}

	if (c->Rc4Key == NULL ||
		CNG_SUCCESS(BCryptEncrypt(c->Rc4Key, (PUCHAR)src, size, NULL, NULL, 0, (PUCHAR)dst, size, &done, 0)) == false ||
		done != size)
	{
		Zero(dst, size);
	}
}

// DES-ECB of one 8-byte block with a 56-bit key given as 7 bytes; dst may be src.
// Should CNG fail, the output block is all zero.
void DesEcbEncrypt(void *dst, void *src, void *key_7bytes)
{
	UCHAR *key_56;
	UCHAR key[8];
	UCHAR block[8];
	BCRYPT_KEY_HANDLE k = NULL;
	ULONG done = 0;
	bool ok = false;
	UINT i, j, ones;
	if (dst == NULL || src == NULL || key_7bytes == NULL)
	{
		return;
	}

	key_56 = (UCHAR *)key_7bytes;

	Zero(key, sizeof(key));
	Copy(block, src, sizeof(block));

	key[0] = key_56[0];
	key[1] = (unsigned char)(((key_56[0] << 7) & 0xFF) | (key_56[1] >> 1));
	key[2] = (unsigned char)(((key_56[1] << 6) & 0xFF) | (key_56[2] >> 2));
	key[3] = (unsigned char)(((key_56[2] << 5) & 0xFF) | (key_56[3] >> 3));
	key[4] = (unsigned char)(((key_56[3] << 4) & 0xFF) | (key_56[4] >> 4));
	key[5] = (unsigned char)(((key_56[4] << 3) & 0xFF) | (key_56[5] >> 5));
	key[6] = (unsigned char)(((key_56[5] << 2) & 0xFF) | (key_56[6] >> 6));
	key[7] = (unsigned char) ((key_56[6] << 1) & 0xFF);

	// Odd parity in the low bit of each key byte (DES itself ignores the parity bits)
	for (i = 0;i < sizeof(key);i++)
	{
		ones = 0;
		for (j = 1;j < 8;j++)
		{
			ones += (key[i] >> j) & 1;
		}
		key[i] = (UCHAR)((key[i] & 0xFE) | ((ones % 2) == 0 ? 1 : 0));
	}

	CngInit();

	// Weak keys go to CNG as they are: the third MS-CHAPv2 key can be 0101010101010101 (crypto test)
	if (cng_des_ecb != NULL &&
		CNG_SUCCESS(BCryptGenerateSymmetricKey(cng_des_ecb, &k, NULL, 0, key, sizeof(key), 0)))
	{
		ok = (CNG_SUCCESS(BCryptEncrypt(k, block, sizeof(block), NULL, NULL, 0, (PUCHAR)dst, sizeof(block), &done, 0)) &&
			done == sizeof(block));

		BCryptDestroyKey(k);
	}

	if (ok == false)
	{
		Zero(dst, sizeof(block));
	}

	Zero(key, sizeof(key));
	Zero(block, sizeof(block));
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

DH_CTX *DhNewFromBits(UINT bits)
{
	switch (bits)
	{
	case 160:
		return DhNew(DH_SIMPLE_160, 2);
	case 768:
		return DhNew(DH_GROUP1_PRIME_768, 2);
	case 1024:
		return DhNew(DH_GROUP2_PRIME_1024, 2);
	case 1536:
		return DhNew(DH_GROUP5_PRIME_1536, 2);
	case 2048:
		return DhNew(DH_SET_2048, 2);
	case 3072:
		return DhNew(DH_SET_3072, 2);
	case 4096:
		return DhNew(DH_SET_4096, 2);
	default:
		return DhNew(DH_SET_2048, 2);
	}
}

DH_CTX *DhNew(char *prime, UINT g)
{
	DH_CTX *dh;
	BUF *buf;
	BIGNUM *dhp, *dhg;
	const BIGNUM *pub, *priv;
	if (prime == NULL || g == 0)
	{
		return NULL;
	}

	buf = StrToBin(prime);

	dh = ZeroMalloc(sizeof(DH_CTX));

	dh->dh = DH_new();
	if (dh->dh == NULL)
	{
		return NULL;
	}
	
	dhp = BinToBigNum(buf->Buf, buf->Size);
	dhg = BN_new();
	BN_set_word(dhg, g);
	DH_set0_pqg(dh->dh, dhp, NULL, dhg);

	DH_generate_key(dh->dh);

	DH_get0_key(dh->dh, &pub, &priv);
	dh->MyPublicKey = BigNumToBuf(pub);
	dh->MyPrivateKey = BigNumToBuf(priv);

	dh->Size = buf->Size;

	FreeBuf(buf);

	return dh;
}

void DhFree(DH_CTX *dh)
{
	if (dh == NULL)
	{
		return;
	}

	DH_free(dh->dh);

	FreeBuf(dh->MyPrivateKey);
	FreeBuf(dh->MyPublicKey);

	Free(dh);
}

// SHA0 implementation

// Source codes from:
//  https://android.googlesource.com/platform/system/core/+/81df1cc77722000f8d0025c1ab00ced123aa573c/libmincrypt/sha.c
//  https://android.googlesource.com/platform/system/core/+/81df1cc77722000f8d0025c1ab00ced123aa573c/include/mincrypt/hash-internal.h
//  https://android.googlesource.com/platform/system/core/+/81df1cc77722000f8d0025c1ab00ced123aa573c/include/mincrypt/sha.h

/*
 * Copyright 2013 The Android Open Source Project
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *     * Neither the name of Google Inc. nor the names of its contributors may
 *       be used to endorse or promote products derived from this software
 *       without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY Google Inc. ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO
 * EVENT SHALL Google Inc. BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
 * OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
 * ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */


#define rol(bits, value) (((value) << (bits)) | ((value) >> (32 - (bits))))

typedef struct MY_SHA0_CTX {
	UINT64 count;
	UCHAR buf[64];
	UINT state[8];
} MY_SHA0_CTX;

#define MY_SHA0_DIGEST_SIZE 20

static void MY_SHA0_Transform(MY_SHA0_CTX* ctx) {
	UINT W[80];
	UINT A, B, C, D, E;
	UCHAR* p = ctx->buf;
	int t;
	for(t = 0; t < 16; ++t) {
		UINT tmp =  (UINT)*p++ << 24;
		tmp |= *p++ << 16;
		tmp |= *p++ << 8;
		tmp |= *p++;
		W[t] = tmp;
	}
	for(; t < 80; t++) {
		W[t] = (1,W[t-3] ^ W[t-8] ^ W[t-14] ^ W[t-16]);
	}
	A = ctx->state[0];
	B = ctx->state[1];
	C = ctx->state[2];
	D = ctx->state[3];
	E = ctx->state[4];
	for(t = 0; t < 80; t++) {
		UINT tmp = rol(5,A) + E + W[t];
		if (t < 20)
			tmp += (D^(B&(C^D))) + 0x5A827999;
		else if ( t < 40)
			tmp += (B^C^D) + 0x6ED9EBA1;
		else if ( t < 60)
			tmp += ((B&C)|(D&(B|C))) + 0x8F1BBCDC;
		else
			tmp += (B^C^D) + 0xCA62C1D6;
		E = D;
		D = C;
		C = rol(30,B);
		B = A;
		A = tmp;
	}
	ctx->state[0] += A;
	ctx->state[1] += B;
	ctx->state[2] += C;
	ctx->state[3] += D;
	ctx->state[4] += E;
}
static void MY_SHA0_init(MY_SHA0_CTX* ctx) {
	ctx->state[0] = 0x67452301;
	ctx->state[1] = 0xEFCDAB89;
	ctx->state[2] = 0x98BADCFE;
	ctx->state[3] = 0x10325476;
	ctx->state[4] = 0xC3D2E1F0;
	ctx->count = 0;
}
static void MY_SHA0_update(MY_SHA0_CTX* ctx, const void* data, int len) {
	int i = (int) (ctx->count & 63);
	const UCHAR* p = (const UCHAR*)data;
	ctx->count += len;
	while (len--) {
		ctx->buf[i++] = *p++;
		if (i == 64) {
			MY_SHA0_Transform(ctx);
			i = 0;
		}
	}
}
static const UCHAR* MY_SHA0_final(MY_SHA0_CTX* ctx) {
	UCHAR *p = ctx->buf;
	UINT64 cnt = ctx->count * 8;
	int i;
	MY_SHA0_update(ctx, (UCHAR*)"\x80", 1);
	while ((ctx->count & 63) != 56) {
		MY_SHA0_update(ctx, (UCHAR*)"\0", 1);
	}
	for (i = 0; i < 8; ++i) {
		UCHAR tmp = (UCHAR) (cnt >> ((7 - i) * 8));
		MY_SHA0_update(ctx, &tmp, 1);
	}
	for (i = 0; i < 5; i++) {
		UINT tmp = ctx->state[i];
		*p++ = tmp >> 24;
		*p++ = tmp >> 16;
		*p++ = tmp >> 8;
		*p++ = tmp >> 0;
	}
	return ctx->buf;
}
static const UCHAR* MY_SHA0_hash(const void* data, int len, UCHAR* digest) {
	MY_SHA0_CTX ctx;
	MY_SHA0_init(&ctx);
	MY_SHA0_update(&ctx, data, len);
	memcpy(digest, MY_SHA0_final(&ctx), MY_SHA0_DIGEST_SIZE);
	return digest;
}
static void Internal_Sha0(unsigned char *dest, const unsigned char *src, const UINT size)
{
	MY_SHA0_hash(src, (int)size, dest);
}
