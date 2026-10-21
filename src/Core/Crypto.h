// Crypto.h
// The crypto module of the new core (ADR-0022, Crypto and TLS): X25519, AES-GCM, SHA-256,
// HMAC-SHA256, HKDF and the system random generator on CNG; the X25519MLKEM768 hybrid where the
// OS has ML-KEM; the node identity key in a CNG key storage provider; ECDSA P-256 certificates,
// PFX import and the certificate stores through CryptoAPI. The module links bcrypt, ncrypt and
// crypt32 only: no OpenSSL, no liboqs and nothing of the slim fork (Mayaqua, Cedar).
//
// Byte order: X25519 scalars, u-coordinates and shared secrets are in the RFC 7748 order
// (little-endian); the module converts them to and from the CNG blobs. A function that fails
// returns false (or NULL) and leaves its secret outputs zeroed.

#ifndef CORE_CRYPTO_H
#define CORE_CRYPTO_H

#include <windows.h>
#include <wincrypt.h>

#include <stdbool.h>

#define CRYPTO_SHA256_SIZE        32
#define CRYPTO_X25519_SIZE        32 // Scalar, u-coordinate and shared secret
#define CRYPTO_AES_GCM_NONCE_SIZE 12
#define CRYPTO_AES_GCM_TAG_SIZE   16
#define CRYPTO_HKDF_MAX_SIZE      (255 * CRYPTO_SHA256_SIZE) // RFC 5869: at most 255 blocks of output
#define CRYPTO_THUMBPRINT_SIZE    20                         // SHA-1 of the encoded certificate
#define CRYPTO_END_POINT_MAX_SIZE 64                         // tls-server-end-point of a certificate signed with SHA-512

// ML-KEM-768 (FIPS 203) and the X25519MLKEM768 hybrid of draft-ietf-tls-ecdhe-mlkem: the client
// share is the encapsulation key followed by an X25519 public key, the server share the
// ciphertext followed by an X25519 public key, and the secret the ML-KEM shared secret followed
// by the X25519 shared secret
#define CRYPTO_MLKEM768_ENCAPS_KEY_SIZE 1184
#define CRYPTO_MLKEM768_CIPHERTEXT_SIZE 1088
#define CRYPTO_MLKEM_SECRET_SIZE        32
#define CRYPTO_HYBRID_CLIENT_SHARE_SIZE (CRYPTO_MLKEM768_ENCAPS_KEY_SIZE + CRYPTO_X25519_SIZE)
#define CRYPTO_HYBRID_SERVER_SHARE_SIZE (CRYPTO_MLKEM768_CIPHERTEXT_SIZE + CRYPTO_X25519_SIZE)
#define CRYPTO_HYBRID_SECRET_SIZE       (CRYPTO_MLKEM_SECRET_SIZE + CRYPTO_X25519_SIZE)

// TLS NamedGroup code points of the key exchange groups (RFC 8446 section 4.2.7, draft-ietf-tls-ecdhe-mlkem)
#define CRYPTO_GROUP_X25519         0x001D
#define CRYPTO_GROUP_X25519MLKEM768 0x11EC

// Key and store scope of the identity, certificate and store functions
#define CRYPTO_MACHINE 0x00000001 // The machine key set and LocalMachine store (the service); else the current user's

// SHA-256 over several parts
typedef struct CRYPTO_SHA256 {
	void *Hash; // BCRYPT_HASH_HANDLE
} CRYPTO_SHA256;

// An AES-GCM key: 16 or 32 bytes, 12-byte nonce, 16-byte tag
typedef struct CRYPTO_AEAD {
	void *Key; // BCRYPT_KEY_HANDLE
} CRYPTO_AEAD;

// A node identity key: a persisted X25519 key in the Microsoft Software Key Storage Provider,
// never exported. The TPM provider (Microsoft Platform Crypto Provider) has no curve25519.
typedef struct CRYPTO_IDENTITY {
	ULONG_PTR Provider; // NCRYPT_PROV_HANDLE
	ULONG_PTR Key;      // NCRYPT_KEY_HANDLE
} CRYPTO_IDENTITY;

// The decapsulating side of one ML-KEM-768 exchange, between CryptoMlKemGenerate and CryptoMlKemDecapsulate
typedef struct CRYPTO_MLKEM {
	void *Key; // BCRYPT_KEY_HANDLE of the ML-KEM-768 key pair
} CRYPTO_MLKEM;

// The initiator side of one X25519MLKEM768 exchange, between CryptoHybridBegin and CryptoHybridFinish
typedef struct CRYPTO_HYBRID {
	void *MlKemKey;                      // BCRYPT_KEY_HANDLE of the ML-KEM-768 key pair
	UCHAR X25519Key[CRYPTO_X25519_SIZE]; // Ephemeral X25519 scalar
} CRYPTO_HYBRID;

// Start-up (Crypto.c): opens the CNG providers once per process, from any thread. false when a
// provider the module needs is missing; ML-KEM is optional and does not count
bool CryptoInit();

// Random bytes from the system-preferred generator
bool CryptoRandom(void *buf, UINT size);

// SHA-256, in one call or over several parts. CryptoSha256End must follow every successful
// CryptoSha256Begin, also after a failed CryptoSha256Update: it releases the hash
bool CryptoSha256(UCHAR *dst, const void *src, UINT size);
bool CryptoSha256Begin(CRYPTO_SHA256 *s);
bool CryptoSha256Update(CRYPTO_SHA256 *s, const void *src, UINT size);
bool CryptoSha256End(CRYPTO_SHA256 *s, UCHAR *dst);

// HMAC-SHA256 (RFC 2104)
bool CryptoHmacSha256(UCHAR *dst, const void *key, UINT key_size, const void *src, UINT size);

// HKDF-SHA256 (RFC 5869). Extract writes the 32-byte PRK; Expand writes okm_size bytes, at most
// CRYPTO_HKDF_MAX_SIZE; CryptoHkdf is both. An empty salt is the salt of 32 zero bytes
bool CryptoHkdfExtract(UCHAR *prk, const void *salt, UINT salt_size, const void *ikm, UINT ikm_size);
bool CryptoHkdfExpand(void *okm, UINT okm_size, const UCHAR *prk, const void *info, UINT info_size);
bool CryptoHkdf(void *okm, UINT okm_size, const void *salt, UINT salt_size, const void *ikm, UINT ikm_size, const void *info, UINT info_size);

// AES-GCM. Seal writes size bytes of ciphertext and the tag; Open checks the tag and writes the
// plaintext, or zeroes dst and returns false. dst may be src
bool CryptoAeadInit(CRYPTO_AEAD *a, const void *key, UINT key_size);
void CryptoAeadFree(CRYPTO_AEAD *a);
bool CryptoAeadSeal(CRYPTO_AEAD *a, const UCHAR *nonce, const void *aad, UINT aad_size, const void *src, UINT size, void *dst, UCHAR *tag);
bool CryptoAeadOpen(CRYPTO_AEAD *a, const UCHAR *nonce, const void *aad, UINT aad_size, const void *src, UINT size, const UCHAR *tag, void *dst);

// X25519 (RFC 7748) on CNG (CryptoX25519.c). The scalar is clamped and the peer's u-coordinate
// is masked to 255 bits and reduced modulo 2^255 - 19, as the RFC requires; a peer key of low
// order (an all-zero shared secret) fails
bool CryptoX25519PublicKey(UCHAR *pub, const UCHAR *priv);
bool CryptoX25519GenerateKey(UCHAR *priv, UCHAR *pub);
bool CryptoX25519(UCHAR *shared, const UCHAR *priv, const UCHAR *peer_pub);

// The node identity key (CryptoX25519.c), named in the key storage provider. Create fails when
// the name exists; Import stores a known scalar under a new name (restore, tests); Delete removes
// the key from the provider and closes it
bool CryptoIdentityCreate(CRYPTO_IDENTITY *id, const wchar_t *name, UINT flags);
bool CryptoIdentityImport(CRYPTO_IDENTITY *id, const wchar_t *name, const UCHAR *priv, UINT flags);
bool CryptoIdentityOpen(CRYPTO_IDENTITY *id, const wchar_t *name, UINT flags);
bool CryptoIdentityPublicKey(CRYPTO_IDENTITY *id, UCHAR *pub);
bool CryptoIdentityDh(CRYPTO_IDENTITY *id, UCHAR *shared, const UCHAR *peer_pub);
void CryptoIdentityClose(CRYPTO_IDENTITY *id);
bool CryptoIdentityDelete(CRYPTO_IDENTITY *id);

// ML-KEM-768 and the X25519MLKEM768 hybrid (CryptoMlKem.c). CryptoMlKemAvailable is true where
// CNG has ML-KEM (Windows 11 24H2, Windows Server 2025 and later). CryptoKeyExchangeGroups lists
// the groups to offer in order of preference: X25519MLKEM768 only where ML-KEM is available,
// then X25519. Begin and Finish are the initiator, Respond the responder; Finish and Free
// release the initiator state
bool CryptoMlKemAvailable();
UINT CryptoKeyExchangeGroups(USHORT *groups, UINT max);
bool CryptoHybridBegin(CRYPTO_HYBRID *h, UCHAR *client_share);
bool CryptoHybridRespond(UCHAR *server_share, UCHAR *secret, const UCHAR *client_share);
bool CryptoHybridFinish(CRYPTO_HYBRID *h, UCHAR *secret, const UCHAR *server_share);
void CryptoHybridFree(CRYPTO_HYBRID *h);

// ML-KEM-768 alone (CryptoMlKem.c), the KEM of the Noise hfs handshake (Core/Noise.h). Generate
// makes a key pair and writes its encapsulation key; Encapsulate writes the ciphertext and the
// secret for a peer's encapsulation key; Decapsulate writes the secret of a ciphertext. Decapsulate
// and Free release the key pair. Where CNG has no ML-KEM, each fails without side effects.
bool CryptoMlKemGenerate(CRYPTO_MLKEM *k, UCHAR *encaps_key);
bool CryptoMlKemEncapsulate(UCHAR *ciphertext, UCHAR *secret, const UCHAR *encaps_key);
bool CryptoMlKemDecapsulate(CRYPTO_MLKEM *k, UCHAR *secret, const UCHAR *ciphertext);
void CryptoMlKemFree(CRYPTO_MLKEM *k);

// Certificates through CryptoAPI (CryptoCert.c); free each returned context with CryptoCertFree.
// CreateSelfSigned: a self-signed ECDSA P-256 certificate (ecdsa-with-SHA256, server and client
// authentication) whose key is a new persisted key of the software KSP, named key_name or, for
// NULL, a random name; subject is an X.500 string such as L"CN=node.example.com", dns_name the
// optional subject alternative name. ImportPfx: the first certificate of a PKCS #12 file that has
// a private key, the key persisted in the software KSP (PKCS12_ALWAYS_CNG_KSP). The store
// functions take a system store name (NULL: L"My") and CRYPTO_MACHINE for LocalMachine; the
// thumbprint is 40 hex digits, spaces and colons ignored. EndPoint: the tls-server-end-point
// channel binding of the certificate (RFC 5929 section 4.1), the hash of its encoding by the hash
// of its signature algorithm, SHA-256 for MD5 and SHA-1, into CRYPTO_END_POINT_MAX_SIZE bytes of
// hash; size receives 32, 48 or 64. It fails for a signature algorithm whose hash is in its
// parameters (RSA-PSS) or is none of these.
PCCERT_CONTEXT CryptoCertCreateSelfSigned(const wchar_t *subject, const wchar_t *dns_name, const wchar_t *key_name, UINT days, UINT flags);
PCCERT_CONTEXT CryptoCertImportPfx(const void *pfx, UINT size, const wchar_t *password, UINT flags);
bool CryptoCertVerifySelfSigned(PCCERT_CONTEXT cert);
bool CryptoCertHasKspKey(PCCERT_CONTEXT cert);
bool CryptoCertThumbprint(PCCERT_CONTEXT cert, UCHAR *thumbprint);
bool CryptoCertThumbprintStr(PCCERT_CONTEXT cert, char *str, UINT size);
bool CryptoCertEndPoint(PCCERT_CONTEXT cert, UCHAR *hash, UINT *size);
bool CryptoCertAddToStore(PCCERT_CONTEXT cert, const wchar_t *store_name, UINT flags);
PCCERT_CONTEXT CryptoCertFindByThumbprint(const char *thumbprint, const wchar_t *store_name, UINT flags);
bool CryptoCertRemoveFromStore(const char *thumbprint, const wchar_t *store_name, UINT flags);
bool CryptoCertDeleteKey(PCCERT_CONTEXT cert);
void CryptoCertFree(PCCERT_CONTEXT cert);

#endif // CORE_CRYPTO_H
