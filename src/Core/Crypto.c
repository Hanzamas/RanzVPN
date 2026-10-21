// Crypto.c
// Start-up of the crypto module, and the symmetric primitives on CNG: the system random
// generator, SHA-256, HMAC-SHA256, HKDF-SHA256 and AES-GCM

#include "Core/CryptoInternal.h"

// The hash, HMAC, HKDF and AES-GCM primitives use the CNG pseudo-handles of Windows 10, which
// need no opening. X25519 needs a provider with its curve set, and ML-KEM is looked up by name.
static INIT_ONCE crypto_init_once = INIT_ONCE_STATIC_INIT;
BCRYPT_ALG_HANDLE crypto_x25519 = NULL;
BCRYPT_ALG_HANDLE crypto_mlkem = NULL;
CRYPTO_ENCAPSULATE_PROC crypto_encapsulate = NULL;
CRYPTO_DECAPSULATE_PROC crypto_decapsulate = NULL;

// INIT_ONCE callback of CryptoInit(): open the providers
static BOOL CALLBACK CryptoOpenAll(PINIT_ONCE once, PVOID param, PVOID *context) {
	BCRYPT_ALG_HANDLE h = NULL;

	if (CNG_SUCCESS(BCryptOpenAlgorithmProvider(&h, BCRYPT_ECDH_ALGORITHM, NULL, 0))) {
		if (CNG_SUCCESS(BCryptSetProperty(h, BCRYPT_ECC_CURVE_NAME, (PUCHAR)BCRYPT_ECC_CURVE_25519, sizeof(BCRYPT_ECC_CURVE_25519), 0)))
			crypto_x25519 = h;
		else
			BCryptCloseAlgorithmProvider(h, 0);
	}

	// ML-KEM: the provider and both entry points, or nothing. bcrypt.dll is loaded, the module links it
	HMODULE bcrypt = GetModuleHandleW(L"bcrypt.dll");
	if (bcrypt != NULL) {
		CRYPTO_ENCAPSULATE_PROC encapsulate = (CRYPTO_ENCAPSULATE_PROC)(void *)GetProcAddress(bcrypt, "BCryptEncapsulate");
		CRYPTO_DECAPSULATE_PROC decapsulate = (CRYPTO_DECAPSULATE_PROC)(void *)GetProcAddress(bcrypt, "BCryptDecapsulate");

		h = NULL;
		if (encapsulate != NULL && decapsulate != NULL && CNG_SUCCESS(BCryptOpenAlgorithmProvider(&h, CRYPTO_MLKEM_ALGORITHM, NULL, 0))) {
			// ML-KEM-768 for the keys of this provider, where CNG takes the parameter set on the
			// provider; CryptoMlKemGenerate() also sets it on each key
			BCryptSetProperty(h, CRYPTO_MLKEM_PARAMETER_SET, (PUCHAR)CRYPTO_MLKEM_PARAMETER_SET_768, sizeof(CRYPTO_MLKEM_PARAMETER_SET_768), 0);
			crypto_mlkem = h;
			crypto_encapsulate = encapsulate;
			crypto_decapsulate = decapsulate;
		}
	}

	return TRUE;
}

bool CryptoInit() {
	InitOnceExecuteOnce(&crypto_init_once, CryptoOpenAll, NULL, NULL);

	return crypto_x25519 != NULL;
}

bool CryptoRandom(void *buf, UINT size) {
	if (buf == NULL)
		return false;
	if (size == 0)
		return true;

	if (CNG_SUCCESS(BCryptGenRandom(NULL, (PUCHAR)buf, size, BCRYPT_USE_SYSTEM_PREFERRED_RNG)) == false) {
		SecureZeroMemory(buf, size);
		return false;
	}

	return true;
}

bool CryptoSha256(UCHAR *dst, const void *src, UINT size) {
	if (dst == NULL || (src == NULL && size != 0))
		return false;

	if (CNG_SUCCESS(BCryptHash(BCRYPT_SHA256_ALG_HANDLE, NULL, 0, (PUCHAR)src, size, dst, CRYPTO_SHA256_SIZE)) == false) {
		SecureZeroMemory(dst, CRYPTO_SHA256_SIZE);
		return false;
	}

	return true;
}

bool CryptoSha256Begin(CRYPTO_SHA256 *s) {
	BCRYPT_HASH_HANDLE h = NULL;

	if (s == NULL)
		return false;

	s->Hash = NULL;
	if (CNG_SUCCESS(BCryptCreateHash(BCRYPT_SHA256_ALG_HANDLE, &h, NULL, 0, NULL, 0, 0)) == false)
		return false;

	s->Hash = h;
	return true;
}

bool CryptoSha256Update(CRYPTO_SHA256 *s, const void *src, UINT size) {
	if (s == NULL || s->Hash == NULL || (src == NULL && size != 0))
		return false;
	if (size == 0)
		return true;

	return CNG_SUCCESS(BCryptHashData(s->Hash, (PUCHAR)src, size, 0));
}

bool CryptoSha256End(CRYPTO_SHA256 *s, UCHAR *dst) {
	bool ok = false;

	if (s == NULL || s->Hash == NULL) {
		if (dst != NULL)
			SecureZeroMemory(dst, CRYPTO_SHA256_SIZE);
		return false;
	}

	if (dst != NULL) {
		ok = CNG_SUCCESS(BCryptFinishHash(s->Hash, dst, CRYPTO_SHA256_SIZE, 0));
		if (ok == false)
			SecureZeroMemory(dst, CRYPTO_SHA256_SIZE);
	}

	BCryptDestroyHash(s->Hash);
	s->Hash = NULL;

	return ok;
}

bool CryptoHmacSha256(UCHAR *dst, const void *key, UINT key_size, const void *src, UINT size) {
	if (dst == NULL || (key == NULL && key_size != 0) || (src == NULL && size != 0))
		return false;

	if (CNG_SUCCESS(BCryptHash(BCRYPT_HMAC_SHA256_ALG_HANDLE, (PUCHAR)key, key_size, (PUCHAR)src, size, dst, CRYPTO_SHA256_SIZE)) == false) {
		SecureZeroMemory(dst, CRYPTO_SHA256_SIZE);
		return false;
	}

	return true;
}

// HKDF-Extract is HMAC(salt, IKM) (RFC 5869 section 2.2). It runs on the HMAC provider, not the
// HKDF one, because CNG refuses an HKDF key made from an empty IKM, which Noise uses (Split()).
// An empty salt is HashLen zero bytes, and the HMAC of an empty key pads it to those zeros.
bool CryptoHkdfExtract(UCHAR *prk, const void *salt, UINT salt_size, const void *ikm, UINT ikm_size) {
	return CryptoHmacSha256(prk, salt, salt_size, ikm, ikm_size);
}

// HKDF-Expand (RFC 5869 section 2.3) by BCryptKeyDerivation: the PRK goes in as the key, marked
// as already extracted (BCRYPT_HKDF_PRK_AND_FINALIZE), and info as the KDF_HKDF_INFO parameter
bool CryptoHkdfExpand(void *okm, UINT okm_size, const UCHAR *prk, const void *info, UINT info_size) {
	BCRYPT_KEY_HANDLE key = NULL;
	ULONG result = 0;
	bool ok = false;

	if (okm == NULL || prk == NULL || (info == NULL && info_size != 0))
		return false;
	if (okm_size == 0 || okm_size > CRYPTO_HKDF_MAX_SIZE) {
		if (okm_size != 0)
			SecureZeroMemory(okm, okm_size);
		return false;
	}

	if (CNG_SUCCESS(BCryptGenerateSymmetricKey(BCRYPT_HKDF_ALG_HANDLE, &key, NULL, 0, (PUCHAR)prk, CRYPTO_SHA256_SIZE, 0))) {
		BCryptBuffer param;
		BCryptBufferDesc params;

		param.cbBuffer = info_size;
		param.BufferType = KDF_HKDF_INFO;
		param.pvBuffer = (PVOID)info;
		params.ulVersion = BCRYPTBUFFER_VERSION;
		params.cBuffers = 1;
		params.pBuffers = &param;

		if (CNG_SUCCESS(BCryptSetProperty(key, BCRYPT_HKDF_HASH_ALGORITHM, (PUCHAR)BCRYPT_SHA256_ALGORITHM, sizeof(BCRYPT_SHA256_ALGORITHM), 0)) &&
		    CNG_SUCCESS(BCryptSetProperty(key, BCRYPT_HKDF_PRK_AND_FINALIZE, NULL, 0, 0)) &&
		    CNG_SUCCESS(BCryptKeyDerivation(key, &params, (PUCHAR)okm, okm_size, &result, 0)) &&
		    result == okm_size)
			ok = true;

		BCryptDestroyKey(key);
	}

	if (ok == false)
		SecureZeroMemory(okm, okm_size);

	return ok;
}

bool CryptoHkdf(void *okm, UINT okm_size, const void *salt, UINT salt_size, const void *ikm, UINT ikm_size, const void *info, UINT info_size) {
	UCHAR prk[CRYPTO_SHA256_SIZE];
	bool ok = false;

	if (okm == NULL)
		return false;

	if (CryptoHkdfExtract(prk, salt, salt_size, ikm, ikm_size))
		ok = CryptoHkdfExpand(okm, okm_size, prk, info, info_size);
	else if (okm_size != 0 && okm_size <= CRYPTO_HKDF_MAX_SIZE)
		SecureZeroMemory(okm, okm_size);

	SecureZeroMemory(prk, sizeof(prk));

	return ok;
}

bool CryptoAeadInit(CRYPTO_AEAD *a, const void *key, UINT key_size) {
	BCRYPT_KEY_HANDLE k = NULL;

	if (a == NULL)
		return false;

	a->Key = NULL;
	if (key == NULL || (key_size != 16 && key_size != 32))
		return false;

	// The AES-GCM pseudo-handle has its chaining mode set already
	if (CNG_SUCCESS(BCryptGenerateSymmetricKey(BCRYPT_AES_GCM_ALG_HANDLE, &k, NULL, 0, (PUCHAR)key, key_size, 0)) == false)
		return false;

	a->Key = k;
	return true;
}

void CryptoAeadFree(CRYPTO_AEAD *a) {
	if (a == NULL || a->Key == NULL)
		return;

	BCryptDestroyKey(a->Key);
	a->Key = NULL;
}

// The authenticated-cipher parameters of one message: nonce, AAD and tag
static void CryptoAeadInfo(BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO *info, const UCHAR *nonce, const void *aad, UINT aad_size, UCHAR *tag) {
	BCRYPT_INIT_AUTH_MODE_INFO(*info);
	info->pbNonce = (PUCHAR)nonce;
	info->cbNonce = CRYPTO_AES_GCM_NONCE_SIZE;
	info->pbAuthData = (PUCHAR)aad;
	info->cbAuthData = aad_size;
	info->pbTag = tag;
	info->cbTag = CRYPTO_AES_GCM_TAG_SIZE;
}

bool CryptoAeadSeal(CRYPTO_AEAD *a, const UCHAR *nonce, const void *aad, UINT aad_size, const void *src, UINT size, void *dst, UCHAR *tag) {
	BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO info;
	ULONG result = 0;

	if (a == NULL || a->Key == NULL || nonce == NULL || tag == NULL || (aad == NULL && aad_size != 0) ||
	    ((src == NULL || dst == NULL) && size != 0))
		return false;

	CryptoAeadInfo(&info, nonce, aad, aad_size, tag);

	if (CNG_SUCCESS(BCryptEncrypt(a->Key, (PUCHAR)src, size, &info, NULL, 0, (PUCHAR)dst, size, &result, 0)) == false || result != size) {
		if (size != 0)
			SecureZeroMemory(dst, size);
		SecureZeroMemory(tag, CRYPTO_AES_GCM_TAG_SIZE);
		return false;
	}

	return true;
}

bool CryptoAeadOpen(CRYPTO_AEAD *a, const UCHAR *nonce, const void *aad, UINT aad_size, const void *src, UINT size, const UCHAR *tag, void *dst) {
	BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO info;
	ULONG result = 0;

	if (a == NULL || a->Key == NULL || nonce == NULL || tag == NULL || (aad == NULL && aad_size != 0) ||
	    ((src == NULL || dst == NULL) && size != 0))
		return false;

	// CNG reads the expected tag through pbTag and does not write it on decryption
	CryptoAeadInfo(&info, nonce, aad, aad_size, (UCHAR *)tag);

	// A wrong tag is STATUS_AUTH_TAG_MISMATCH; the plaintext is never handed out then
	if (CNG_SUCCESS(BCryptDecrypt(a->Key, (PUCHAR)src, size, &info, NULL, 0, (PUCHAR)dst, size, &result, 0)) == false || result != size) {
		if (size != 0)
			SecureZeroMemory(dst, size);
		return false;
	}

	return true;
}
