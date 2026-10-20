// Encrypt.h
// Header of Encrypt.c

#ifndef	ENCRYPT_H
#define	ENCRYPT_H

#include "MayaType.h"

#include <openssl/opensslv.h>

#define RSA_KEY_SIZE				1024

// IANA definitions taken from IKEv1 Phase 1
#define SHA1_160						2
#define SHA2_256						4
#define SHA2_384						5
#define SHA2_512						6

#define	DH_SIMPLE_160	"AEE7561459353C95DDA966AE1FD25D95CD46E935"

typedef struct bignum_st BIGNUM;
typedef struct bio_st BIO;
typedef struct dh_st DH;
typedef struct evp_cipher_st EVP_CIPHER;
typedef struct evp_cipher_ctx_st EVP_CIPHER_CTX;
typedef struct evp_pkey_st EVP_PKEY;
typedef struct ssl_st SSL;
typedef struct x509_st X509;

struct CRYPT
{
	void *Rc4Key;					// CNG key object (BCRYPT_KEY_HANDLE) of the RC4 key, NULL if CNG refused the key
};

struct NAME
{
	wchar_t *CommonName;
	wchar_t *Organization;
	wchar_t *Unit;
	wchar_t *Country;
	wchar_t *State;
	wchar_t *Local;
};

struct X_SERIAL
{
	UINT size;
	UCHAR *data;
};

struct X
{
	X509 *x509;
	NAME *issuer_name;
	NAME *subject_name;
	bool root_cert;
	UINT64 notBefore;
	UINT64 notAfter;
	X_SERIAL *serial;
	bool do_not_free;
	bool is_compatible_bit;
	UINT bits;
	bool has_basic_constraints;
	char issuer_url[256];
};

struct K
{
	EVP_PKEY *pkey;
	bool private_key;
};

#define	MD4_SIZE	16
#define	MD5_SIZE	16
#define	SHA1_SIZE	20
#define	SHA256_SIZE	32

struct DH_CTX
{
	DH *dh;
};

struct CIPHER
{
	char Name[MAX_PATH];
	const EVP_CIPHER *Cipher;
	EVP_CIPHER_CTX *Ctx;
	bool Encrypt;
};


CRYPT *NewCrypt(void *key, UINT size);
void FreeCrypt(CRYPT *c);
void Encrypt(CRYPT *c, void *dst, void *src, UINT size);
void InitCryptLibrary();
void DrainCryptErrors(char *what);
void Rand(void *buf, UINT size);
UINT64 Rand64();
UINT Rand32();
USHORT Rand16();
UCHAR Rand8();
bool Rand1();
UINT HashPtrToUINT(void *p);

BIO *BufToBio(BUF *b);
BUF *BioToBuf(BIO *bio);
void FreeBio(BIO *bio);
X *BioToX(BIO *bio, bool text);
LIST *BioToXList(BIO *bio, bool text);
X *BufToX(BUF *b, bool text);
LIST *BufToXList(BUF *b, bool text);
void FreeX509(X509 *x509);
void FreeX(X *x);
void FreeXList(LIST *chain);
BIO *XToBio(X *x, bool text);
BUF *XToBuf(X *x, bool text);
K *BioToK(BIO *bio, bool private_key, bool text, char *password);
int PKeyPasswordCallbackFunction(char *buf, int bufsize, int verify, void *param);
void FreePKey(EVP_PKEY *pkey);
void FreeK(K *k);
K *OpensslEngineToK(char *key_file_name, char *engine_name);
K *BufToK(BUF *b, bool private_key, bool text, char *password);
bool IsEncryptedK(BUF *b, bool private_key);
bool IsBase64(BUF *b);
BIO *KToBio(K *k, bool text, char *password);
BUF *KToBuf(K *k, bool text, char *password);
X *FileToXW(wchar_t *filename);
bool XToFileW(X *x, wchar_t *filename, bool text);
K *FileToKW(wchar_t *filename, bool private_key, char *password);
bool KToFileW(K *k, wchar_t *filename, bool text, char *password);
bool CheckXandK(X *x, K *k);
bool CompareX(X *x1, X *x2);
NAME *X509NameToName(void *xn);
wchar_t *GetUniStrFromX509Name(void *xn, int nid);
void FreeName(NAME *n);
bool CompareName(NAME *n1, NAME *n2);
K *GetKFromX(X *x);
bool CheckSignature(X *x, K *k);
X *X509ToX(X509 *x509);
bool CheckXEx(X *x, X *x_issuer, bool check_name, bool check_date);
bool Asn1TimeToSystem(SYSTEMTIME *s, void *asn1_time);
UINT64 Asn1TimeToUINT64(void *asn1_time);
bool UINT64ToAsn1Time(void *asn1_time, UINT64 t);
bool CheckXDate(X *x, UINT64 current_system_time);
bool CheckXDateNow(X *x);
NAME *NewName(wchar_t *common_name, wchar_t *organization, wchar_t *unit,
			  wchar_t *country, wchar_t *state, wchar_t *local);
void *NameToX509Name(NAME *nm);
void FreeX509Name(void *xn);
bool AddX509Name(void *xn, int nid, wchar_t *str);
X509 *NewRootX509(K *pub, K *priv, NAME *name, UINT days, X_SERIAL *serial);
X *NewRootX(K *pub, K *priv, NAME *name, UINT days, X_SERIAL *serial);
X509 *NewX509(K *pub, K *priv, X *ca, NAME *name, UINT days, X_SERIAL *serial);
X *NewX(K *pub, K *priv, X *ca, NAME *name, UINT days, X_SERIAL *serial);
X_SERIAL *NewXSerial(void *data, UINT size);
void FreeXSerial(X_SERIAL *serial);
X *CloneX(X *x);
LIST *CloneXList(LIST *chain);
K *CloneK(K *k);
void FreeCryptLibrary();
void GetPrintNameFromX(wchar_t *str, UINT size, X *x);
void GetPrintNameFromName(wchar_t *str, UINT size, NAME *name);
void GetAllNameFromX(wchar_t *str, UINT size, X *x);
void GetAllNameFromName(wchar_t *str, UINT size, NAME *name);
void GetAllNameFromNameEx(wchar_t *str, UINT size, NAME *name);
BUF *BigNumToBuf(const BIGNUM *bn);
X_SERIAL *CloneXSerial(X_SERIAL *src);
bool CompareXSerial(X_SERIAL *s1, X_SERIAL *s2);
void GetXDigest(X *x, UCHAR *buf, bool sha1);
NAME *CopyName(NAME *n);


bool RsaGen(K **priv, K **pub, UINT bit);
bool RsaSignEx(void *dst, UINT dst_size, void *src, UINT src_size, K *k);
bool RsaVerifyEx(void *data, UINT data_size, void *sign, UINT sign_size, K *k);

DH_CTX *DhNewFromBits(UINT bits);
DH_CTX *DhNew(char *prime, UINT g);
void DhFree(DH_CTX *dh);

bool IsAesNiSupported();

void FreeOpenSSLThreadState();

CIPHER *NewCipher(char *name);
void FreeCipher(CIPHER *c);
void SetCipherKey(CIPHER *c, void *key, bool enc);
UINT CipherProcessAead(CIPHER *c, void *iv, void *tag, UINT tag_size, void *dest, void *src, UINT src_size, void *aad, UINT aad_size);

void HashMd4(void *dst, void *src, UINT size);
void Md5(void *dst, void *src, UINT size);
void Sha0(void *dst, void *src, UINT size);
void Sha1(void *dst, void *src, UINT size);
void Sha2_256(void *dst, void *src, UINT size);

#endif
