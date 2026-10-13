// SoftEther VPN Source Code - Developer Edition Master Branch
// Mayaqua Kernel
// © 2020 Nokia

// Encrypt.h
// Header of Encrypt.c

#ifndef	ENCRYPT_H
#define	ENCRYPT_H

#include "MayaType.h"

#include <openssl/opensslv.h>

// Constant
#define	MIN_SIGN_HASH_SIZE		(15 + SHA1_SIZE)
#define	SIGN_HASH_SIZE			(MIN_SIGN_HASH_SIZE)

#define RSA_KEY_SIZE				1024		// RSA key size

// IANA definitions taken from IKEv1 Phase 1
#define SHA1_160						2
#define SHA2_256						4
#define SHA2_384						5
#define SHA2_512						6

#define DH_GROUP1_PRIME_768 \
	"FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1" \
	"29024E088A67CC74020BBEA63B139B22514A08798E3404DD" \
	"EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245" \
	"E485B576625E7EC6F44C42E9A63A3620FFFFFFFFFFFFFFFF"

#define DH_GROUP2_PRIME_1024 \
	"FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1" \
	"29024E088A67CC74020BBEA63B139B22514A08798E3404DD" \
	"EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245" \
	"E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED" \
	"EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381" \
	"FFFFFFFFFFFFFFFF"

#define DH_GROUP5_PRIME_1536 \
	"FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1" \
	"29024E088A67CC74020BBEA63B139B22514A08798E3404DD" \
	"EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245" \
	"E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED" \
	"EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D" \
	"C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F" \
	"83655D23DCA3AD961C62F356208552BB9ED529077096966D" \
	"670C354E4ABC9804F1746C08CA237327FFFFFFFFFFFFFFFF"

#define	DH_SIMPLE_160	"AEE7561459353C95DDA966AE1FD25D95CD46E935"

#define	DH_SET_2048 \
	"FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1" \
	"29024E088A67CC74020BBEA63B139B22514A08798E3404DD" \
	"EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245" \
	"E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED" \
	"EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D" \
	"C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F" \
	"83655D23DCA3AD961C62F356208552BB9ED529077096966D" \
	"670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B" \
	"E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9" \
	"DE2BCBF6955817183995497CEA956AE515D2261898FA0510" \
	"15728E5A8AACAA68FFFFFFFFFFFFFFFF"

#define	DH_SET_3072	\
	"FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"\
	"29024E088A67CC74020BBEA63B139B22514A08798E3404DD"\
	"EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"\
	"E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"\
	"EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"\
	"C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"\
	"83655D23DCA3AD961C62F356208552BB9ED529077096966D"\
	"670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"\
	"E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"\
	"DE2BCBF6955817183995497CEA956AE515D2261898FA0510"\
	"15728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64"\
	"ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7"\
	"ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6B"\
	"F12FFA06D98A0864D87602733EC86A64521F2B18177B200C"\
	"BBE117577A615D6C770988C0BAD946E208E24FA074E5AB31"\
	"43DB5BFCE0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF"

#define	DH_SET_4096 \
	"FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1" \
	"29024E088A67CC74020BBEA63B139B22514A08798E3404DD" \
	"EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245" \
	"E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED" \
	"EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D" \
	"C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F" \
	"83655D23DCA3AD961C62F356208552BB9ED529077096966D" \
	"670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B" \
	"E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9" \
	"DE2BCBF6955817183995497CEA956AE515D2261898FA0510" \
	"15728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64" \
	"ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7" \
	"ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6B" \
	"F12FFA06D98A0864D87602733EC86A64521F2B18177B200C" \
	"BBE117577A615D6C770988C0BAD946E208E24FA074E5AB31" \
	"43DB5BFCE0FD108E4B82D120A92108011A723C12A787E6D7" \
	"88719A10BDBA5B2699C327186AF4E23C1A946834B6150BDA" \
	"2583E9CA2AD44CE8DBBBC2DB04DE8EF92E8EFC141FBECAA6" \
	"287C59474E6BC05D99B2964FA090C3A2233BA186515BE7ED" \
	"1F612970CEE2D7AFB81BDD762170481CD0069127D5B05AA9" \
	"93B4EA988D8FDDC186FFB7DC90A6C08F4DF435C934063199" \
	"FFFFFFFFFFFFFFFF"

// Macro
#define	HASHED_DATA(p)			(((UCHAR *)p) + 15)

typedef struct bignum_st BIGNUM;
typedef struct bio_st BIO;
typedef struct DES_ks DES_key_schedule;
typedef struct dh_st DH;
typedef struct evp_cipher_st EVP_CIPHER;
typedef struct evp_cipher_ctx_st EVP_CIPHER_CTX;
typedef struct evp_pkey_st EVP_PKEY;
typedef struct rc4_key_st RC4_KEY;
typedef struct ssl_st SSL;
typedef struct x509_st X509;

// Crypt context
struct CRYPT
{
	RC4_KEY *Rc4Key;
};

// Name in the certificate
struct NAME
{
	wchar_t *CommonName;		// CN
	wchar_t *Organization;		// O
	wchar_t *Unit;				// OU
	wchar_t *Country;			// C
	wchar_t *State;				// ST
	wchar_t *Local;				// L
};

// Serial number
struct X_SERIAL
{
	UINT size;
	UCHAR *data;
};

// Certificate
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

// Key
struct K
{
	EVP_PKEY *pkey;
	bool private_key;
};

// Constant
#define	MD5_SIZE	16
#define	SHA1_SIZE	20
#define	SHA256_SIZE	32

// DH
struct DH_CTX
{
	DH *dh;
	BUF *MyPublicKey;
	BUF *MyPrivateKey;
	UINT Size;
};

// Cipher object
struct CIPHER
{
	char Name[MAX_PATH];
	bool IsNullCipher, IsAeadCipher;
	const EVP_CIPHER *Cipher;
	EVP_CIPHER_CTX *Ctx;
	bool Encrypt;
	UINT BlockSize, IvSize, KeySize;
};


// Lock of the OpenSSL
extern LOCK **ssl_lock_obj;

// Function prototype
CRYPT *NewCrypt(void *key, UINT size);
void FreeCrypt(CRYPT *c);
void Encrypt(CRYPT *c, void *dst, void *src, UINT size);
void InitCryptLibrary();
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
void LoadXNames(X *x);
void FreeXNames(X *x);
void FreeName(NAME *n);
bool CompareName(NAME *n1, NAME *n2);
K *GetKFromX(X *x);
bool CheckSignature(X *x, K *k);
X *X509ToX(X509 *x509);
bool CheckXEx(X *x, X *x_issuer, bool check_name, bool check_date);
bool Asn1TimeToSystem(SYSTEMTIME *s, void *asn1_time);
bool StrToSystem(SYSTEMTIME *s, char *str);
UINT64 Asn1TimeToUINT64(void *asn1_time);
bool SystemToAsn1Time(void *asn1_time, SYSTEMTIME *s);
bool UINT64ToAsn1Time(void *asn1_time, UINT64 t);
bool SystemToStr(char *str, UINT size, SYSTEMTIME *s);
void LoadXDates(X *x);
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
UINT GetDaysUntil2038();
UINT GetDaysUntil2038Ex();
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
BIGNUM *BinToBigNum(void *data, UINT size);
X_SERIAL *CloneXSerial(X_SERIAL *src);
bool CompareXSerial(X_SERIAL *s1, X_SERIAL *s2);
void GetXDigest(X *x, UCHAR *buf, bool sha1);
NAME *CopyName(NAME *n);


bool RsaGen(K **priv, K **pub, UINT bit);
bool RsaCheck();
bool RsaCheckEx();
bool RsaSignEx(void *dst, void *src, UINT size, K *k, UINT bits);
bool HashForSign(void *dst, UINT dst_size, void *src, UINT src_size);
bool RsaVerifyEx(void *data, UINT data_size, void *sign, K *k, UINT bits);
UINT RsaPublicSize(K *k);
BUF *RsaPublicToBuf(K *k);

void Sha(UINT sha_type, void *dst, void *src, UINT size);

void DesEcbEncrypt(void *dst, void *src, void *key_7bytes);

DH_CTX *DhNewFromBits(UINT bits);
DH_CTX *DhNew(char *prime, UINT g);
void DhFree(DH_CTX *dh);

bool IsAesNiSupported();

void OpenSSL_InitLock();
void OpenSSL_FreeLock();
void OpenSSL_Lock(int mode, int n, const char *file, int line);
void FreeOpenSSLThreadState();

// Encryption/Decryption
CIPHER *NewCipher(char *name);
void FreeCipher(CIPHER *c);
void SetCipherKey(CIPHER *c, void *key, bool enc);
UINT CipherProcessAead(CIPHER *c, void *iv, void *tag, UINT tag_size, void *dest, void *src, UINT src_size, void *aad, UINT aad_size);

// Hashing
void HashMd4(void *dst, void *src, UINT size);
void Md5(void *dst, void *src, UINT size);
void Sha(UINT sha_type, void *dst, void *src, UINT size);
void Sha0(void *dst, void *src, UINT size);
void Sha1(void *dst, void *src, UINT size);
void Sha2_256(void *dst, void *src, UINT size);

int GetSslClientCertIndex();

#endif	// ENCRYPT_H
