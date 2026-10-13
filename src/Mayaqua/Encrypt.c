// SoftEther VPN Source Code - Developer Edition Master Branch
// Mayaqua Kernel
// © 2020 Nokia

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
#include <openssl/rc4.h>
#include <openssl/md5.h>
#include <openssl/md4.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <openssl/des.h>
#include <openssl/aes.h>
#include <openssl/rsa.h>
#include <openssl/dh.h>
#include <openssl/bn.h>
#include <openssl/pem.h>
#include <openssl/conf.h>
#include <openssl/x509v3.h>
#include <openssl/provider.h>
// Static oqsprovider initialization function
#ifndef SKIP_OQS_PROVIDER
	extern OSSL_provider_init_fn oqs_provider_init;
#endif

	#include <intrin.h> // For __cpuid()

LOCK *openssl_lock = NULL;

int ssl_clientcert_index = 0;

static OSSL_PROVIDER *ossl_provider_legacy = NULL;
static OSSL_PROVIDER *ossl_provider_default = NULL;
static OSSL_PROVIDER *ossl_provider_oqsprovider = NULL;

LOCK **ssl_lock_obj = NULL;
UINT ssl_lock_num;
static bool openssl_inited = false;

static void Internal_Sha0(unsigned char *dest, const unsigned char *src, const UINT size);

// For the callback function
typedef struct CB_PARAM
{
	char *password;
} CB_PARAM;

// MD4 specific hash function
void HashMd4(void *dst, void *src, UINT size)
{
	// Validate arguments
	if (dst == NULL || (src == NULL && size != 0))
	{
		return;
	}

	MD4(src, size, dst);
}

// MD5 hash
void Md5(void *dst, void *src, UINT size)
{
	// Validate arguments
	if (dst == NULL || (src == NULL && size != 0))
	{
		return;
	}

	MD5(src, size, dst);
}

// SHA hash
void Sha(UINT sha_type, void *dst, void *src, UINT size)
{
	// Validate arguments
	if (dst == NULL || (src == NULL && size != 0))
	{
		return;
	}

	switch(sha_type) {
	case SHA1_160:
		SHA1(src, size, dst);
		break;
	case SHA2_256:
		SHA256(src, size, dst);
		break;
	case SHA2_384:
		SHA384(src, size, dst);
		break;
	case SHA2_512:
		SHA512(src, size, dst);
		break;
	}
}

void Sha0(void *dst, void *src, UINT size)
{
	// Validate arguments
	if (dst == NULL || (src == NULL && size != 0))
	{
		return;
	}

	Internal_Sha0(dst, src, size);
}

void Sha1(void *dst, void *src, UINT size)
{
	Sha(SHA1_160, dst, src, size);
}

void Sha2_256(void *dst, void *src, UINT size)
{
	Sha(SHA2_256, dst, src, size);
}

// Creating a cipher object
CIPHER *NewCipher(char *name)
{
	CIPHER *c;
	// Validate arguments
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

// Set the key to the cipher object
void SetCipherKey(CIPHER *c, void *key, bool enc)
{
	// Validate arguments
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

// Process encryption / decryption (AEAD)
UINT CipherProcessAead(CIPHER *c, void *iv, void *tag, UINT tag_size, void *dest, void *src, UINT src_size, void *aad, UINT aad_size)
{
	int r = src_size;
	int r2 = 0;
	// Validate arguments
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
		Debug("CipherProcessAead(): EVP_CipherInit_ex() failed with error: %s\n", OpenSSL_Error());
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
			Debug("CipherProcessAead(): EVP_CipherUpdate() failed with error: %s\n", OpenSSL_Error());
			return 0;
		}
	}

	if (EVP_CipherUpdate(c->Ctx, dest, &r, src, src_size) == false)
	{
		Debug("CipherProcessAead(): EVP_CipherUpdate() failed with error: %s\n", OpenSSL_Error());
		return 0;
	}

	if (EVP_CipherFinal_ex(c->Ctx, ((UCHAR *)dest) + (UINT)r, &r2) == false)
	{
		Debug("CipherProcessAead(): EVP_CipherFinal_ex() failed with error: %s\n", OpenSSL_Error());
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

// Release of the cipher object
void FreeCipher(CIPHER *c)
{
	// Validate arguments
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

// Convert the public key to a buffer
BUF *RsaPublicToBuf(K *k)
{
	BUF *b;
	RSA *rsa;
	const BIGNUM *n;
	// Validate arguments
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

// Get public key size
UINT RsaPublicSize(K *k)
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

// Hash a pointer to a 32-bit
UINT HashPtrToUINT(void *p)
{
	UCHAR hash_data[SHA256_SIZE];
	UCHAR hash_src[CANARY_RAND_SIZE + sizeof(void *)];
	UINT ret;
	// Validate arguments
	if (p == NULL)
	{
		return 0;
	}

	Zero(hash_src, sizeof(hash_src));
	Copy(hash_src + 0, GetCanaryRand(CANARY_RAND_ID_PTR_KEY_HASH), CANARY_RAND_SIZE);
	Copy(hash_src + CANARY_RAND_SIZE, p, sizeof(void *));

	Sha2_256(hash_data, hash_src, sizeof(hash_src));

	Copy(&ret, hash_data, sizeof(ret));

	return ret;
}

// Copy of the NAME
NAME *CopyName(NAME *n)
{
	// Validate arguments
	if (n == NULL)
	{
		return NULL;
	}

	return NewName(n->CommonName, n->Organization, n->Unit,
		n->Country, n->State, n->Local);
}

// Convert the binary to the BIGNUM
BIGNUM *BinToBigNum(void *data, UINT size)
{
	BIGNUM *bn;
	// Validate arguments
	if (data == NULL)
	{
		return NULL;
	}

	bn = BN_new();
	BN_bin2bn(data, size, bn);

	return bn;
}

// Convert a BIGNUM to a buffer
BUF *BigNumToBuf(const BIGNUM *bn)
{
	UINT size;
	UCHAR *tmp;
	BUF *b;
	// Validate arguments
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

// Initialization of the lock of OpenSSL
void OpenSSL_InitLock()
{
}

// Release of the lock of OpenSSL
void OpenSSL_FreeLock()
{
}

// Lock function for OpenSSL
void OpenSSL_Lock(int mode, int n, const char *file, int line)
{
}

char *OpenSSL_Error()
{
	return ERR_error_string(ERR_get_error(), NULL);
}

// Get the display name of the certificate
void GetPrintNameFromX(wchar_t *str, UINT size, X *x)
{
	// Validate arguments
	if (x == NULL || str == NULL)
	{
		return;
	}

	GetPrintNameFromName(str, size, x->subject_name);
}

// Get the display name from NAME
void GetPrintNameFromName(wchar_t *str, UINT size, NAME *name)
{
	// Validate arguments
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

// Get all the name strings from the certificate
void GetAllNameFromX(wchar_t *str, UINT size, X *x)
{
	UCHAR md5[MD5_SIZE], sha1[SHA1_SIZE];
	char tmp1[MD5_SIZE * 3 + 8], tmp2[SHA1_SIZE * 3 + 8];
	wchar_t tmp3[sizeof(tmp1) + sizeof(tmp2) + 64];
	// Validate arguments
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

	// Digest value
	GetXDigest(x, md5, false);
	GetXDigest(x, sha1, true);

	BinToStr(tmp1, sizeof(tmp1), md5, MD5_SIZE);
	BinToStr(tmp2, sizeof(tmp2), sha1, SHA1_SIZE);

	UniFormat(tmp3, sizeof(tmp3), L" (Digest: MD5=\"%S\", SHA1=\"%S\")", tmp1, tmp2);
	UniStrCat(str, size, tmp3);
}

// Get the all name strings from NAME
void GetAllNameFromName(wchar_t *str, UINT size, NAME *name)
{
	UniStrCpy(str, size, L"");
	// Validate arguments
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
	// Validate arguments
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

// Clone of the key
K *CloneK(K *k)
{
	BUF *b;
	K *ret;
	// Validate arguments
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

// Clone of certificate
X *CloneX(X *x)
{
	BUF *b;
	X *ret;
	// Validate arguments
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

// Clone of certificate chain
LIST *CloneXList(LIST *chain)
{
	BUF *b;
	X *x;
	LIST *ret;
	// Validate arguments
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

// Release of X_SERIAL
void FreeXSerial(X_SERIAL *serial)
{
	// Validate arguments
	if (serial == NULL)
	{
		return;
	}

	Free(serial->data);
	Free(serial);
}

// Comparison of X_SERIAL
bool CompareXSerial(X_SERIAL *s1, X_SERIAL *s2)
{
	// Validate arguments
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

// Copy of X_SERIAL
X_SERIAL *CloneXSerial(X_SERIAL *src)
{
	X_SERIAL *s;
	// Validate arguments
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

// Initialization of X_SERIAL
X_SERIAL *NewXSerial(void *data, UINT size)
{
	X_SERIAL *serial;
	UCHAR *buf = (UCHAR *)data;
	UINT i;
	// Validate arguments
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

// Get the number of days till January 1, 2038
UINT GetDaysUntil2038()
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

// Issue an X509 certificate
X *NewX(K *pub, K *priv, X *ca, NAME *name, UINT days, X_SERIAL *serial)
{
	X509 *x509;
	X *x;
	// Validate arguments
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
		return NULL;
	}

	return x;
}

// Create a root certificate
X *NewRootX(K *pub, K *priv, NAME *name, UINT days, X_SERIAL *serial)
{
	X509 *x509;
	X *x, *x2;
	// Validate arguments
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
		return NULL;
	}

	x2 = CloneX(x);
	FreeX(x);

	return x2;
}

// Create new X509 basic & extended key usage
void AddKeyUsageX509(EXTENDED_KEY_USAGE *ex, int nid)
{
	ASN1_OBJECT *obj;
	// Validate arguments
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
X509_EXTENSION *NewExtendedKeyUsageForX509()
{
	EXTENDED_KEY_USAGE *ex = sk_ASN1_OBJECT_new_null();
	X509_EXTENSION *ret;

	AddKeyUsageX509(ex, NID_server_auth);
	AddKeyUsageX509(ex, NID_client_auth);
	AddKeyUsageX509(ex, NID_code_sign);
	AddKeyUsageX509(ex, NID_email_protect);
	AddKeyUsageX509(ex, NID_ipsecEndSystem);
	AddKeyUsageX509(ex, NID_ipsecTunnel);
	AddKeyUsageX509(ex, NID_ipsecUser);
	AddKeyUsageX509(ex, NID_time_stamp);
	AddKeyUsageX509(ex, NID_OCSP_sign);

	ret = X509V3_EXT_i2d(NID_ext_key_usage, 0, ex);

	sk_ASN1_OBJECT_pop_free(ex, ASN1_OBJECT_free);

	return ret;
}
void BitStringSetBit(ASN1_BIT_STRING *str, int bit)
{
	// Validate arguments
	if (str == NULL)
	{
		return;
	}

	ASN1_BIT_STRING_set_bit(str, bit, 1);
}
X509_EXTENSION *NewBasicKeyUsageForX509()
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
		//BitStringSetBit(str, 4);	// KU_KEY_AGREEMENT
		BitStringSetBit(str, 5);	// KU_KEY_CERT_SIGN
		BitStringSetBit(str, 6);	// KU_CRL_SIGN

		ret = X509V3_EXT_i2d(NID_key_usage, 0, str);

		ASN1_BIT_STRING_free(str);
	}

	return ret;
}

// Issue an X509 certificate
X509 *NewX509(K *pub, K *priv, X *ca, NAME *name, UINT days, X_SERIAL *serial)
{
	X509 *x509;
	UINT64 notBefore, notAfter;
	const ASN1_TIME *t1, *t2;
	X509_NAME *subject_name, *issuer_name;
	X509_EXTENSION *ex = NULL;
	X509_EXTENSION *eku = NULL;
	X509_EXTENSION *busage = NULL;
	ASN1_INTEGER *s;
	// Validate arguments
	if (pub == NULL || name == NULL || ca == NULL)
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

	// Creating a X509
	x509 = X509_new();
	if (x509 == NULL)
	{
		return NULL;
	}

	// Make it a v3 certificate
	X509_set_version(x509, 2L);

	// Set the Expiration
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

	// Set the name
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

	// Set the Serial Number
	s = X509_get_serialNumber(x509);
	if (serial == NULL)
	{
		ASN1_INTEGER_set(s, 0);
	}
	else
	{
		BIGNUM *bn = BN_bin2bn(serial->data, serial->size, NULL);
		if (bn != NULL)
		{
			BN_to_ASN1_INTEGER(bn, s);
			BN_free(bn);
		}
	}

	// Basic usage
	busage = NewBasicKeyUsageForX509();
	if (busage != NULL)
	{
		X509_add_ext(x509, busage, -1);
		X509_EXTENSION_free(busage);
	}

	// EKU
	eku = NewExtendedKeyUsageForX509();
	if (eku != NULL)
	{
		X509_add_ext(x509, eku, -1);
		X509_EXTENSION_free(eku);
	}

	// Alternative subject name
	if (UniIsEmptyStr(name->CommonName) == false)
	{
		char alt_dns[MAX_PATH];

		Format(alt_dns, sizeof(alt_dns), "DNS.1:%S", name->CommonName);

		ex = X509V3_EXT_conf_nid(NULL, NULL, NID_subject_alt_name,	alt_dns);
		X509_add_ext(x509, ex, -1);
		X509_EXTENSION_free(ex);
	}

	Lock(openssl_lock);
	{
		// Set the public key
		X509_set_pubkey(x509, pub->pkey);

		// Signature
		// 2014.3.19 set the initial digest algorithm to SHA-256
		X509_sign(x509, priv->pkey, EVP_sha256());
	}
	Unlock(openssl_lock);

	return x509;
}

// Create an X509 root certificate
X509 *NewRootX509(K *pub, K *priv, NAME *name, UINT days, X_SERIAL *serial)
{
	X509 *x509;
	UINT64 notBefore, notAfter;
	const ASN1_TIME *t1, *t2;
	X509_NAME *subject_name, *issuer_name;
	X509_EXTENSION *ex = NULL;
	X509_EXTENSION *eku = NULL;
	X509_EXTENSION *busage = NULL;
	ASN1_INTEGER *s;
	// Validate arguments
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

	// Creating a X509
	x509 = X509_new();
	if (x509 == NULL)
	{
		return NULL;
	}

	// Make it a v3 certificate
	X509_set_version(x509, 2L);

	// Set the Expiration
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

	// Set the name
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

	// Set a Serial Number
	s = X509_get_serialNumber(x509);
	if (serial == NULL)
	{
		ASN1_INTEGER_set(s, 0);
	}
	else
	{
		BIGNUM *bn = BN_bin2bn(serial->data, serial->size, NULL);
		if (bn != NULL)
		{
			BN_to_ASN1_INTEGER(bn, s);
			BN_free(bn);
		}
	}

	// Extensions
	ex = X509V3_EXT_conf_nid(NULL, NULL, NID_basic_constraints,	"critical,CA:TRUE");
	X509_add_ext(x509, ex, -1);
	X509_EXTENSION_free(ex);

	// Basic usage
	busage = NewBasicKeyUsageForX509();
	if (busage != NULL)
	{
		X509_add_ext(x509, busage, -1);
		X509_EXTENSION_free(busage);
	}

	// EKU
	eku = NewExtendedKeyUsageForX509();
	if (eku != NULL)
	{
		X509_add_ext(x509, eku, -1);
		X509_EXTENSION_free(eku);
	}

	Lock(openssl_lock);
	{
		// Set the public key
		X509_set_pubkey(x509, pub->pkey);

		// Signature
		// 2014.3.19 set the initial digest algorithm to SHA-256
		X509_sign(x509, priv->pkey, EVP_sha256());
	}
	Unlock(openssl_lock);

	return x509;
}

// Convert the NAMEto a X509_NAME
void *NameToX509Name(NAME *nm)
{
	X509_NAME *xn;
	// Validate arguments
	if (nm == NULL)
	{
		return NULL;
	}

	xn = X509_NAME_new();
	if (xn == NULL)
	{
		return NULL;
	}

	// Add the entries
	AddX509Name(xn, NID_commonName, nm->CommonName);
	AddX509Name(xn, NID_organizationName, nm->Organization);
	AddX509Name(xn, NID_organizationalUnitName, nm->Unit);
	AddX509Name(xn, NID_countryName, nm->Country);
	AddX509Name(xn, NID_stateOrProvinceName, nm->State);
	AddX509Name(xn, NID_localityName, nm->Local);

	return xn;
}

// Add an entry to the X509_NAME
bool AddX509Name(void *xn, int nid, wchar_t *str)
{
	X509_NAME *x509_name;
	UINT utf8_size;
	BYTE *utf8;
	int encoding_type = MBSTRING_ASC;
	// Validate arguments
	if (xn == NULL || str == NULL)
	{
		return false;
	}

	// Convert to UTF-8
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

	// Adding
	x509_name = (X509_NAME *)xn;
	Lock(openssl_lock);
	{
		X509_NAME_add_entry_by_NID(x509_name, nid, encoding_type, utf8, utf8_size, -1, 0);
	}
	Unlock(openssl_lock);
	Free(utf8);

	return true;
}

// Release the X509_NAME
void FreeX509Name(void *xn)
{
	X509_NAME *x509_name;
	// Validate arguments
	if (xn == NULL)
	{
		return;
	}

	x509_name = (X509_NAME *)xn;
	X509_NAME_free(x509_name);
}

// Creating the NAME
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

// Check the expiration date of the certificate by the current time
bool CheckXDateNow(X *x)
{
	// Validate arguments
	if (x == NULL)
	{
		return false;
	}

	return CheckXDate(x, SystemTime64());
}

// Check the expiration date of the certificate
bool CheckXDate(X *x, UINT64 current_system_time)
{
	// Validate arguments
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

// Read the expiration date of the certificate
void LoadXDates(X *x)
{
	// Validate arguments
	if (x == NULL)
	{
		return;
	}

	x->notBefore = Asn1TimeToUINT64((ASN1_TIME *)X509_get0_notBefore(x->x509));
	x->notAfter = Asn1TimeToUINT64((ASN1_TIME *)X509_get0_notAfter(x->x509));
}

// Convert the 64bit system time to ASN1 time
bool UINT64ToAsn1Time(void *asn1_time, UINT64 t)
{
	SYSTEMTIME st;
	// Validate arguments
	if (asn1_time == NULL)
	{
		return false;
	}

	UINT64ToSystem(&st, t);
	return SystemToAsn1Time(asn1_time, &st);
}

// Convert the system time to the ASN1 time
bool SystemToAsn1Time(void *asn1_time, SYSTEMTIME *s)
{
	char tmp[20];
	ASN1_TIME *t;
	// Validate arguments
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

// Convert the system time to a string
bool SystemToStr(char *str, UINT size, SYSTEMTIME *s)
{
	// Validate arguments
	if (str == NULL || s == NULL)
	{
		return false;
	}

	Format(str, size, "%02u%02u%02u%02u%02u%02uZ",
		s->wYear % 100, s->wMonth, s->wDay,
		s->wHour, s->wMinute, s->wSecond);

	return true;
}

// Convert an ASN1 time to an UINT64 time
UINT64 Asn1TimeToUINT64(void *asn1_time)
{
	SYSTEMTIME st;
	// Validate arguments
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

// Converted an ASN1 time to a system time
bool Asn1TimeToSystem(SYSTEMTIME *s, void *asn1_time)
{
	ASN1_TIME *t;
	char tmp[32];
	int len;
	const char *src;
	int type;
	// Validate arguments
	if (s == NULL || asn1_time == NULL)
	{
		return false;
	}

	t = (ASN1_TIME *)asn1_time;
	len = ASN1_STRING_length((const ASN1_STRING *)t);
	src = (const char *)ASN1_STRING_get0_data((const ASN1_STRING *)t);
	type = ASN1_STRING_type((const ASN1_STRING *)t);

	if (src == NULL || len <= 0 || len >= (int)sizeof(tmp))
	{
		return false;
	}

	Copy(tmp, src, len);
	tmp[len] = '\0';

	if (StrToSystem(s, tmp) == false)
	{
		return false;
	}

	if (type == V_ASN1_GENERALIZEDTIME)
	{
		LocalToSystem(s, s);
	}

	return true;
}

// Convert the string to the system time
bool StrToSystem(SYSTEMTIME *s, char *str)
{
	char century[3] = {0, 0, 0};
	bool fourdigityear = false;

	// Validate arguments
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

		// Year has 4 digits - save first two and use the rest
		// as if it had two digits
		fourdigityear = true;
		century[0] = str[0];
		century[1] = str[1];
		str += 2;
	}
	if (str[12] != 'Z')
	{
		return false;
	}

	// Conversion
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

bool RsaVerifyEx(void *data, UINT data_size, void *sign, K *k, UINT bits)
{
	UCHAR hash_data[SIGN_HASH_SIZE];
	UCHAR *decrypt_data;
	RSA *rsa;
	UINT rsa_size;
	// Validate arguments
	if (data == NULL || sign == NULL || k == NULL || k->private_key != false)
	{
		return false;
	}
	if (bits == 0)
	{
		bits = RSA_KEY_SIZE;
	}

	rsa = EVP_PKEY_get0_RSA(k->pkey);
	if (rsa == NULL)
	{
		return false;
	}

	// Hash the data
	if (HashForSign(hash_data, sizeof(hash_data), data, data_size) == false)
	{
		return false;
	}

	rsa_size = RSA_size(rsa);
	rsa_size = MAX(rsa_size, 1024); // For just in case
	decrypt_data = ZeroMalloc(rsa_size);

	// Decode the signature
	if (RSA_public_decrypt(bits / 8, sign, decrypt_data, rsa, RSA_PKCS1_PADDING) <= 0)
	{
		Free(decrypt_data);
		return false;
	}

	// Comparison
	if (Cmp(decrypt_data, hash_data, SIGN_HASH_SIZE) != 0)
	{
		Free(decrypt_data);
		return false;
	}

	Free(decrypt_data);

	return true;
}

// RSA signature
bool RsaSignEx(void *dst, void *src, UINT size, K *k, UINT bits)
{
	UCHAR hash[SIGN_HASH_SIZE];
	// Validate arguments
	if (dst == NULL || src == NULL || k == NULL || EVP_PKEY_base_id(k->pkey) != EVP_PKEY_RSA)
	{
		return false;
	}
	if (bits == 0)
	{
		bits = RSA_KEY_SIZE;
	}

	Zero(dst, bits / 8);

	// Hash
	if (HashForSign(hash, sizeof(hash), src, size) == false)
	{
		return false;
	}

	// Signature
	if (RSA_private_encrypt(sizeof(hash), hash, dst, EVP_PKEY_get0_RSA(k->pkey), RSA_PKCS1_PADDING) <= 0)
	{
		return false;
	}

	return true;
}

// Generation of signature data by SHA-1
bool HashForSign(void *dst, UINT dst_size, void *src, UINT src_size)
{
	UCHAR *buf = (UCHAR *)dst;
	UCHAR sign_data[] =
	{
		0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2B, 0x0E,
		0x03, 0x02, 0x1A, 0x05, 0x00, 0x04, 0x14,
	};
	// Validate arguments
	if (dst == NULL || src == NULL || src_size == 0 || MIN_SIGN_HASH_SIZE > dst_size)
	{
		return false;
	}

	// Header part
	Copy(buf, sign_data, sizeof(sign_data));

	// Hash
	Sha1(HASHED_DATA(buf), src, src_size);

	return true;
}

// RSA operating environment check
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

	// Key generation
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

	// Secret key
	bio = NewBio();
	Lock(openssl_lock);
	{
		i2d_RSAPrivateKey_bio(bio, rsa);
	}
	Unlock(openssl_lock);
	BIO_seek(bio, 0);
	priv_key = BioToK(bio, true, false, NULL);
	FreeBio(bio);

	// Public key
	bio = NewBio();
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

// Generation of RSA key
bool RsaGen(K **priv, K **pub, UINT bit)
{
	int ret = 0;
	RSA *rsa = NULL;
	BIGNUM *e = NULL;
	K *priv_key, *pub_key;
	BIO *bio;
	char errbuf[MAX_SIZE];
	UINT size = 0;
	// Validate arguments
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

	// Key generation
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

	// Secret key
	bio = NewBio();
	Lock(openssl_lock);
	{
		i2d_RSAPrivateKey_bio(bio, rsa);
	}
	Unlock(openssl_lock);
	BIO_seek(bio, 0);
	priv_key = BioToK(bio, true, false, NULL);
	FreeBio(bio);

	// Public key
	bio = NewBio();
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

// Confirm whether the certificate X is signed by the issuer of the certificate x_issuer
bool CheckXEx(X *x, X *x_issuer, bool check_name, bool check_date)
{
	K *k;
	bool ret;
	// Validate arguments
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

// Confirm the signature of the certificate X with the public key K
bool CheckSignature(X *x, K *k)
{
	// Validate arguments
	if (x == NULL || k == NULL)
	{
		return false;
	}

	Lock(openssl_lock);
	{
		if (X509_verify(x->x509, k->pkey) == 0)
		{
			Unlock(openssl_lock);
			return false;
		}
	}
	Unlock(openssl_lock);
	return true;
}

// Get the public key from the certificate
K *GetKFromX(X *x)
{
	EVP_PKEY *pkey;
	K *k;
	// Validate arguments
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

// The name comparison
bool CompareName(NAME *n1, NAME *n2)
{
	// Validate arguments
	if (n1 == NULL || n2 == NULL)
	{
		return false;
	}

	// Name comparison
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

// Release the name of the X
void FreeXNames(X *x)
{
	// Validate arguments
	if (x == NULL)
	{
		return;
	}

	FreeName(x->issuer_name);
	x->issuer_name = NULL;

	FreeName(x->subject_name);
	x->subject_name = NULL;
}

// Release the name
void FreeName(NAME *n)
{
	// Validate arguments
	if (n == NULL)
	{
		return;
	}

	// Release the string
	Free(n->CommonName);
	Free(n->Organization);
	Free(n->Unit);
	Free(n->Country);
	Free(n->State);
	Free(n->Local);

	// Release the object
	Free(n);

	return;
}

// Get the name of the certificate
void LoadXNames(X *x)
{
	X509 *x509;
	// Validate arguments
	if (x == NULL)
	{
		return;
	}

	x509 = x->x509;
	x->issuer_name = X509NameToName(X509_get_issuer_name(x509));
	x->subject_name = X509NameToName(X509_get_subject_name(x509));
}

// Convert the X509_NAME structure to the NAME structure
NAME *X509NameToName(void *xn)
{
	NAME *n;
	// Validate arguments
	if (xn == NULL)
	{
		return NULL;
	}

	n = ZeroMalloc(sizeof(NAME));

	// Get the strings one by one
	n->CommonName = GetUniStrFromX509Name(xn, NID_commonName);
	n->Organization = GetUniStrFromX509Name(xn, NID_organizationName);
	n->Unit = GetUniStrFromX509Name(xn, NID_organizationalUnitName);
	n->Country = GetUniStrFromX509Name(xn, NID_countryName);
	n->State = GetUniStrFromX509Name(xn, NID_stateOrProvinceName);
	n->Local = GetUniStrFromX509Name(xn, NID_localityName);

	return n;
}

// Read a Unicode string from the X509_NAME structure
wchar_t *GetUniStrFromX509Name(void *xn, int nid)
{
	UCHAR txt[1024];
	bool b = false;
	UINT i, size;
	int index;
	bool unicode = false;
	bool is_utf_8 = false;
	ASN1_OBJECT *obj;
	const ASN1_STRING *data;
	// Validate arguments
	if (xn == NULL || nid == 0)
	{
		return NULL;
	}

	Zero(txt, sizeof(txt));
	if (X509_NAME_get_text_by_NID(xn, nid, (char *)txt, sizeof(txt) - 2) <= 0)
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

	size = UniStrLen((wchar_t *)txt) * 4 + 8;
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

// Check whether the certificate x1 equal to x2
bool CompareX(X *x1, X *x2)
{
	// Validate arguments
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

// Check whether K is private key of X
bool CheckXandK(X *x, K *k)
{
	// Validate arguments
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

// Read a X from the file
X *FileToXW(wchar_t *filename)
{
	bool text;
	BUF *b;
	X *x;
	// Validate arguments
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

// Write the X to a file
bool XToFileW(X *x, wchar_t *filename, bool text)
{
	BUF *b;
	bool ret;
	// Validate arguments
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

// Read a K from the file
K *FileToKW(wchar_t *filename, bool private_key, char *password)
{
	bool text;
	BUF *b;
	K *k;
	// Validate arguments
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

// Save the K to a file
bool KToFileW(K *k, wchar_t *filename, bool text, char *password)
{
	BUF *b;
	bool ret;
	// Validate arguments
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

// Convert the K to the BUF
BUF *KToBuf(K *k, bool text, char *password)
{
	BUF *buf;
	BIO *bio;
	// Validate arguments
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

// Convert the K to the BIO
BIO *KToBio(K *k, bool text, char *password)
{
	BIO *bio;
	// Validate arguments
	if (k == NULL)
	{
		return NULL;
	}

	bio = NewBio();

	if (k->private_key)
	{
		// Secret key
		if (text == false)
		{
			// Binary format
			Lock(openssl_lock);
			{
				i2d_PrivateKey_bio(bio, k->pkey);
			}
			Unlock(openssl_lock);
		}
		else
		{
			// Text format
			if (password == 0 || StrLen(password) == 0)
			{
				// No encryption
				Lock(openssl_lock);
				{
					PEM_write_bio_PrivateKey(bio, k->pkey, NULL, NULL, 0, NULL, NULL);
				}
				Unlock(openssl_lock);
			}
			else
			{
				// Encrypt
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
		// Public key
		if (text == false)
		{
			// Binary format
			Lock(openssl_lock);
			{
				i2d_PUBKEY_bio(bio, k->pkey);
			}
			Unlock(openssl_lock);
		}
		else
		{
			// Text format
			Lock(openssl_lock);
			{
				PEM_write_bio_PUBKEY(bio, k->pkey);
			}
			Unlock(openssl_lock);
		}
	}

	return bio;
}

// Check whether the BUF is encoded as the Base64
bool IsBase64(BUF *b)
{
	UINT i;
	// Validate arguments
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

// Check whether the K in the BUF is encrypted
bool IsEncryptedK(BUF *b, bool private_key)
{
	K *k;
	// Validate arguments
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
#endif	// OPENSSL_API_COMPAT < 0x10100000L
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

// Convert the BUF to a K
K *BufToK(BUF *b, bool private_key, bool text, char *password)
{
	BIO *bio;
	K *k;
	// Validate arguments
	if (b == NULL)
	{
		return NULL;
	}

	bio = BufToBio(b);
	k = BioToK(bio, private_key, text, password);
	FreeBio(bio);

	return k;
}

// Release of K
void FreeK(K *k)
{
	// Validate arguments
	if (k == NULL)
	{
		return;
	}

	FreePKey(k->pkey);
	Free(k);
}

// Release the secret key
void FreePKey(EVP_PKEY *pkey)
{
	// Validate arguments
	if (pkey == NULL)
	{
		return;
	}

	EVP_PKEY_free(pkey);
}

// Convert the BIO to the K
K *BioToK(BIO *bio, bool private_key, bool text, char *password)
{
	EVP_PKEY *pkey;
	K *k;
	// Validate arguments
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
		// Public key
		if (text == false)
		{
			// Binary format
			pkey = d2i_PUBKEY_bio(bio, NULL);
			if (pkey == NULL)
			{
				return NULL;
			}
		}
		else
		{
			// Text format
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
			// Binary format
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
			// Text format
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

// Password callback function
int PKeyPasswordCallbackFunction(char *buf, int bufsize, int verify, void *param)
{
	CB_PARAM *cb;
	// Validate arguments
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

// Convert the X to a BUF
BUF *XToBuf(X *x, bool text)
{
	BIO *bio;
	BUF *b;
	// Validate arguments
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

// Convert the X to a BIO
BIO *XToBio(X *x, bool text)
{
	BIO *bio;
	// Validate arguments
	if (x == NULL)
	{
		return NULL;
	}

	bio = NewBio();

	Lock(openssl_lock);
	{
		if (text == false)
		{
			// Binary format
			i2d_X509_bio(bio, x->x509);
		}
		else
		{
			// Text format
			PEM_write_bio_X509(bio, x->x509);
		}
	}
	Unlock(openssl_lock);

	return bio;
}

// Release of the X
void FreeX(X *x)
{
	// Validate arguments
	if (x == NULL)
	{
		return;
	}

	// Release the name
	FreeXNames(x);


	// Release the Serial
	FreeXSerial(x->serial);

	if (x->do_not_free == false)
	{
		FreeX509(x->x509);
	}
	Free(x);
}

// Release of an X chain
void FreeXList(LIST *chain)
{
	// Validate arguments
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

// Release of the X509
void FreeX509(X509 *x509)
{
	// Validate arguments
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

// Convert the BUF to a X
X *BufToX(BUF *b, bool text)
{
	X *x;
	BIO *bio;
	// Validate arguments
	if (b == NULL)
	{
		return NULL;
	}

	bio = BufToBio(b);
	if (bio == NULL)
	{
		FreeBuf(b);
		return NULL;
	}

	x = BioToX(bio, text);

	FreeBio(bio);

	return x;
}

// Convert the BUF to X chain
LIST *BufToXList(BUF *b, bool text)
{
	LIST *chain;
	BIO *bio;
	// Validate arguments
	if (b == NULL)
	{
		return NULL;
	}

	bio = BufToBio(b);
	if (bio == NULL)
	{
		FreeBuf(b);
		return NULL;
	}

	chain = BioToXList(bio, text);

	FreeBio(bio);

	return chain;
}

// Get a digest of the X
void GetXDigest(X *x, UCHAR *buf, bool sha1)
{
	// Validate arguments
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

// Convert BIO to X
X *BioToX(BIO *bio, bool text)
{
	X *x;
	X509 *x509;
	// Validate arguments
	if (bio == NULL)
	{
		return NULL;
	}

	Lock(openssl_lock);
	{
		// Reading x509
		if (text == false)
		{
			// Binary mode
			x509 = d2i_X509_bio(bio, NULL);
		}
		else
		{
			// Text mode
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
		return NULL;
	}

	return x;
}

// Convert BIO to X chain
LIST *BioToXList(BIO *bio, bool text)
{
	X *x;
	STACK_OF(X509_INFO) *sk = NULL;
	X509_INFO *xi;
	LIST *chain;

	// Validate arguments
	if (bio == NULL || text == false)
	{
		return NULL;
	}

	Lock(openssl_lock);
	{
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
				Add(chain, x);
				xi->x509 = NULL;
			}
			X509_INFO_free(xi);
		}

		sk_X509_INFO_free(sk);
	}
	Unlock(openssl_lock);

	return chain;
}

// Convert the X509 to X
X *X509ToX(X509 *x509)
{
	X *x;
	K *k;
	BUF *b;
	UINT size;
	UINT type;
	ASN1_INTEGER *s;
	// Validate arguments
	if (x509 == NULL)
	{
		return NULL;
	}

	x = ZeroMalloc(sizeof(X));
	x->x509 = x509;

	// Name
	LoadXNames(x);

	// Expiration date
	LoadXDates(x);

	// Check whether it is a root certificate
	if (CompareName(x->issuer_name, x->subject_name))
	{
		K *pubkey = GetKFromX(x);
		if (pubkey != NULL)
		{
			if (CheckXandK(x, pubkey))
			{
				x->root_cert = true;
			}
			FreeK(pubkey);
		}
	}

	// Check whether there is basic constraints
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

	// Get the Serial Number
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
		FreeX(x);
		return NULL;
	}

	b = KToBuf(k, false, NULL);

	size = b->Size;
	type = EVP_PKEY_base_id(k->pkey);

	FreeBuf(b);
	
	//Fixed to get actual RSA key bits
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
		
		/*switch (size)
		{
		case 162:
			x->bits = 1024;
			break;

		case 226:
			x->bits = 1536;
			break;

		case 294:
			x->bits = 2048;
			break;

		case 442:
			x->bits = 3072;
			break;

		case 550:
			x->bits = 4096;
			break;

		default:
			x->is_compatible_bit = false;
			break;
		}*/
	}

	return x;
}

// Create a BIO
BIO *NewBio()
{
	return BIO_new(BIO_s_mem());
}

// Release the BIO
void FreeBio(BIO *bio)
{
	// Validate arguments
	if (bio == NULL)
	{
		return;
	}

	BIO_free(bio);
}

// Convert the BIO to the BUF
BUF *BioToBuf(BIO *bio)
{
	BUF *b;
	UINT size;
	void *tmp;
	// Validate arguments
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

// Convert the BUF to a BIO
BIO *BufToBio(BUF *b)
{
	BIO *bio;
	// Validate arguments
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

// 64-bit random number generation
UINT64 Rand64()
{
	UINT64 i;
	Rand(&i, sizeof(i));
	return i;
}

// 32-bit random number generation
UINT Rand32()
{
	UINT i;
	Rand(&i, sizeof(i));
	return i;
}

// 16-bit random number generation
USHORT Rand16()
{
	USHORT i;
	Rand(&i, sizeof(i));
	return i;
}

// 8-bit random number generation
UCHAR Rand8()
{
	UCHAR i;
	Rand(&i, sizeof(i));
	return i;
}

// 1-bit random number generation
bool Rand1()
{
	return (Rand32() % 2) == 0 ? false : true;
}

// Random number generation
void Rand(void *buf, UINT size)
{
	// Validate arguments
	if (buf == NULL || size == 0)
	{
		return;
	}
	RAND_bytes(buf, size);
}

// Delete a thread-specific information that OpenSSL has holded
void FreeOpenSSLThreadState()
{
	OPENSSL_thread_stop();
}

// Release the Crypt library
void FreeCryptLibrary()
{
	openssl_inited = false;

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

// Initialize the Crypt library
void InitCryptLibrary()
{
	char tmp[16];

	ossl_provider_default = OSSL_PROVIDER_load(NULL, "legacy");
	ossl_provider_legacy = OSSL_PROVIDER_load(NULL, "default");

	char *oqs_provider_name = "oqsprovider";
	#ifndef SKIP_OQS_PROVIDER
		// Registers "oqsprovider" as a provider -- necessary because oqsprovider is built in now.
		OSSL_PROVIDER_add_builtin(NULL, oqs_provider_name, oqs_provider_init); 
	#endif
	ossl_provider_oqsprovider = OSSL_PROVIDER_load(NULL, oqs_provider_name);

	ssl_clientcert_index = SSL_get_ex_new_index(0, "struct SslClientCertInfo *", NULL, NULL, NULL);

	RAND_poll();

	Rand(tmp, sizeof(tmp));
	OpenSSL_InitLock();

	openssl_inited = true;
}

// Creating a new CRYPT object
CRYPT *NewCrypt(void *key, UINT size)
{
	CRYPT *c = ZeroMalloc(sizeof(CRYPT));

	c->Rc4Key = Malloc(sizeof(RC4_KEY));

	RC4_set_key(c->Rc4Key, size, (UCHAR *)key);

	return c;
}

// Release the CRYPT object
void FreeCrypt(CRYPT *c)
{
	// Validate arguments
	if (c == NULL)
	{
		return;
	}

	// Memory release
	Free(c->Rc4Key);
	Free(c);
}

// Encryption and decryption
void Encrypt(CRYPT *c, void *dst, void *src, UINT size)
{
	RC4(c->Rc4Key, size, src, dst);
}

// DES-ECB encryption
void DesEcbEncrypt(void *dst, void *src, void *key_7bytes)
{
	UCHAR *key_56;
	DES_cblock key;
	DES_key_schedule ks;
	// Validate arguments
	if (dst == NULL || src == NULL || key_7bytes == NULL)
	{
		return;
	}

	key_56 = (UCHAR *)key_7bytes;

	Zero(&key, sizeof(key));
	Zero(&ks, sizeof(ks));

	key[0] = key_56[0];
	key[1] = (unsigned char)(((key_56[0] << 7) & 0xFF) | (key_56[1] >> 1));
	key[2] = (unsigned char)(((key_56[1] << 6) & 0xFF) | (key_56[2] >> 2));
	key[3] = (unsigned char)(((key_56[2] << 5) & 0xFF) | (key_56[3] >> 3));
	key[4] = (unsigned char)(((key_56[3] << 4) & 0xFF) | (key_56[4] >> 4));
	key[5] = (unsigned char)(((key_56[4] << 3) & 0xFF) | (key_56[5] >> 5));
	key[6] = (unsigned char)(((key_56[5] << 2) & 0xFF) | (key_56[6] >> 6));
	key[7] = (unsigned char) ((key_56[6] << 1) & 0xFF);

	DES_set_odd_parity(&key);
	DES_set_key_unchecked(&key, &ks);

	DES_ecb_encrypt(src, dst, &ks, 1);
}

// Determine whether the AES-NI instruction set is supported by the CPU
bool IsAesNiSupported()
{
	bool supported = false;

	// Unfortunately OpenSSL doesn't provide a function to do it
  #if defined(_M_X64) || defined(_M_IX86)
    int regs[4]; // EAX, EBX, ECX, EDX
    __cpuid(regs, 1);
    supported = (regs[2] >> 25) & 1;
  #elif defined(_M_ARM64)
	return IsProcessorFeaturePresent(PF_ARM_V8_CRYPTO_INSTRUCTIONS_AVAILABLE);
  #endif

	return supported;
}

// Creating a DH 2048bit
DH_CTX *DhNew2048()
{
	return DhNew(DH_SET_2048, 2);
}
// Creating a DH 3072bit
DH_CTX *DhNew3072()
{
	return DhNew(DH_SET_3072, 2);
}
// Creating a DH 4096bit
DH_CTX *DhNew4096()
{
	return DhNew(DH_SET_4096, 2);
}

// Creating a DH GROUP1
DH_CTX *DhNewGroup1()
{
	return DhNew(DH_GROUP1_PRIME_768, 2);
}

// Creating a DH GROUP2
DH_CTX *DhNewGroup2()
{
	return DhNew(DH_GROUP2_PRIME_1024, 2);
}

// Creating a DH GROUP5
DH_CTX *DhNewGroup5()
{
	return DhNew(DH_GROUP5_PRIME_1536, 2);
}


// Creating a DH SIMPLE 160bits
DH_CTX *DhNewSimple160()
{
	return DhNew(DH_SIMPLE_160, 2);
}

DH_CTX *DhNewFromBits(UINT bits)
{
	switch (bits)
	{
	case 160:
		return DhNewSimple160();
	case 768:
		return DhNewGroup1();
	case 1024:
		return DhNewGroup2();
	case 1536:
		return DhNewGroup5();
	case 2048:
		return DhNew2048();
	case 3072:
		return DhNew3072();
	case 4096:
		return DhNew4096();
	default:
		return DhNew2048();
	}
}

// Creating a new DH
DH_CTX *DhNew(char *prime, UINT g)
{
	DH_CTX *dh;
	BUF *buf;
	BIGNUM *dhp, *dhg;
	const BIGNUM *pub, *priv;
	// Validate arguments
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

// Release of DH
void DhFree(DH_CTX *dh)
{
	// Validate arguments
	if (dh == NULL)
	{
		return;
	}

	DH_free(dh->dh);

	FreeBuf(dh->MyPrivateKey);
	FreeBuf(dh->MyPublicKey);

	Free(dh);
}

int GetSslClientCertIndex()
{
	return ssl_clientcert_index;
}

/////////////////////////
// SHA0 implementation //
/////////////////////////

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
	UINT state[8];  // upto SHA2
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
		//W[t] = rol(1,W[t-3] ^ W[t-8] ^ W[t-14] ^ W[t-16]);
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
void MY_SHA0_init(MY_SHA0_CTX* ctx) {
	ctx->state[0] = 0x67452301;
	ctx->state[1] = 0xEFCDAB89;
	ctx->state[2] = 0x98BADCFE;
	ctx->state[3] = 0x10325476;
	ctx->state[4] = 0xC3D2E1F0;
	ctx->count = 0;
}
void MY_SHA0_update(MY_SHA0_CTX* ctx, const void* data, int len) {
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
const UCHAR* MY_SHA0_final(MY_SHA0_CTX* ctx) {
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
/* Convenience function */
const UCHAR* MY_SHA0_hash(const void* data, int len, UCHAR* digest) {
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
