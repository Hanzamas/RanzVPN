// CryptoMlKem.c
// ML-KEM-768 on CNG where the OS has it (Windows 11 24H2, Windows Server 2025 and later), and the
// X25519MLKEM768 hybrid of draft-ietf-tls-ecdhe-mlkem on top of it. Where CNG has no ML-KEM the
// hybrid is not offered (CryptoKeyExchangeGroups) and its functions fail without side effects.

#include "Core/CryptoInternal.h"

#include <string.h>

// The CNG blob of an ML-KEM-768 encapsulation key: BCRYPT_MLKEM_KEY_BLOB (magic, size of the
// parameter set name, size of the key), the name L"768" with its terminator, then the key in the
// FIPS 203 encoding that TLS and Noise carry
typedef struct CRYPTO_MLKEM_BLOB {
	ULONG Magic;
	ULONG ParameterSetSize;
	ULONG KeySize;
} CRYPTO_MLKEM_BLOB;

#define CRYPTO_MLKEM_PUBLIC_BLOB_SIZE (sizeof(CRYPTO_MLKEM_BLOB) + sizeof(CRYPTO_MLKEM_PARAMETER_SET_768) + CRYPTO_MLKEM768_ENCAPS_KEY_SIZE)

bool CryptoMlKemAvailable() {
	CryptoInit();

	return crypto_mlkem != NULL;
}

UINT CryptoKeyExchangeGroups(USHORT *groups, UINT max) {
	USHORT list[2];
	UINT num = 0;

	if (CryptoMlKemAvailable())
		list[num++] = CRYPTO_GROUP_X25519MLKEM768;
	list[num++] = CRYPTO_GROUP_X25519;

	if (groups == NULL)
		return num;
	if (num > max)
		num = max;
	for (UINT i = 0; i < num; i++)
		groups[i] = list[i];

	return num;
}

// The raw encapsulation key in an exported CNG blob; false unless it is an ML-KEM-768 public blob
static bool CryptoMlKemKeyFromBlob(UCHAR *encaps_key, const UCHAR *blob, ULONG size) {
	const CRYPTO_MLKEM_BLOB *head = (const CRYPTO_MLKEM_BLOB *)blob;

	if (size != CRYPTO_MLKEM_PUBLIC_BLOB_SIZE || head->Magic != CRYPTO_MLKEM_PUBLIC_MAGIC ||
	    head->ParameterSetSize != sizeof(CRYPTO_MLKEM_PARAMETER_SET_768) || head->KeySize != CRYPTO_MLKEM768_ENCAPS_KEY_SIZE ||
	    memcmp(blob + sizeof(CRYPTO_MLKEM_BLOB), CRYPTO_MLKEM_PARAMETER_SET_768, sizeof(CRYPTO_MLKEM_PARAMETER_SET_768)) != 0)
		return false;

	CopyMemory(encaps_key, blob + sizeof(CRYPTO_MLKEM_BLOB) + sizeof(CRYPTO_MLKEM_PARAMETER_SET_768), CRYPTO_MLKEM768_ENCAPS_KEY_SIZE);
	return true;
}

static void CryptoMlKemBlobFromKey(UCHAR *blob, const UCHAR *encaps_key) {
	CRYPTO_MLKEM_BLOB *head = (CRYPTO_MLKEM_BLOB *)blob;

	head->Magic = CRYPTO_MLKEM_PUBLIC_MAGIC;
	head->ParameterSetSize = sizeof(CRYPTO_MLKEM_PARAMETER_SET_768);
	head->KeySize = CRYPTO_MLKEM768_ENCAPS_KEY_SIZE;
	CopyMemory(blob + sizeof(CRYPTO_MLKEM_BLOB), CRYPTO_MLKEM_PARAMETER_SET_768, sizeof(CRYPTO_MLKEM_PARAMETER_SET_768));
	CopyMemory(blob + sizeof(CRYPTO_MLKEM_BLOB) + sizeof(CRYPTO_MLKEM_PARAMETER_SET_768), encaps_key, CRYPTO_MLKEM768_ENCAPS_KEY_SIZE);
}

// A new ML-KEM-768 key pair and its raw encapsulation key. The parameter set is set on the key
// and, by CryptoInit(), on the provider; the exported blob must name 768 either way.
static BCRYPT_KEY_HANDLE CryptoMlKemGenerate(UCHAR *encaps_key) {
	UCHAR blob[CRYPTO_MLKEM_PUBLIC_BLOB_SIZE];
	BCRYPT_KEY_HANDLE key = NULL;
	ULONG size = 0;

	if (CNG_SUCCESS(BCryptGenerateKeyPair(crypto_mlkem, &key, 0, 0)) == false)
		return NULL;

	BCryptSetProperty(key, CRYPTO_MLKEM_PARAMETER_SET, (PUCHAR)CRYPTO_MLKEM_PARAMETER_SET_768, sizeof(CRYPTO_MLKEM_PARAMETER_SET_768), 0);
	if (CNG_SUCCESS(BCryptFinalizeKeyPair(key, 0)) &&
	    CNG_SUCCESS(BCryptExportKey(key, NULL, CRYPTO_MLKEM_PUBLIC_BLOB, blob, sizeof(blob), &size, 0)) &&
	    CryptoMlKemKeyFromBlob(encaps_key, blob, size))
		return key;

	BCryptDestroyKey(key);
	return NULL;
}

bool CryptoHybridBegin(CRYPTO_HYBRID *h, UCHAR *client_share) {
	UCHAR x25519_pub[CRYPTO_X25519_SIZE];

	if (h == NULL)
		return false;

	h->MlKemKey = NULL;
	SecureZeroMemory(h->X25519Key, sizeof(h->X25519Key));
	if (client_share == NULL || CryptoMlKemAvailable() == false)
		return false;

	BCRYPT_KEY_HANDLE key = CryptoMlKemGenerate(client_share);
	if (key == NULL)
		return false;

	if (CryptoX25519GenerateKey(h->X25519Key, x25519_pub) == false) {
		BCryptDestroyKey(key);
		ZeroMemory(client_share, CRYPTO_HYBRID_CLIENT_SHARE_SIZE);
		return false;
	}

	CopyMemory(client_share + CRYPTO_MLKEM768_ENCAPS_KEY_SIZE, x25519_pub, CRYPTO_X25519_SIZE);
	h->MlKemKey = key;

	return true;
}

bool CryptoHybridRespond(UCHAR *server_share, UCHAR *secret, const UCHAR *client_share) {
	UCHAR blob[CRYPTO_MLKEM_PUBLIC_BLOB_SIZE];
	UCHAR x25519_key[CRYPTO_X25519_SIZE];
	BCRYPT_KEY_HANDLE encaps_key = NULL;
	ULONG secret_size = 0;
	ULONG ciphertext_size = 0;
	bool ok = false;

	if (server_share == NULL || secret == NULL)
		return false;

	if (client_share != NULL && CryptoMlKemAvailable()) {
		CryptoMlKemBlobFromKey(blob, client_share);
		if (CNG_SUCCESS(BCryptImportKeyPair(crypto_mlkem, NULL, CRYPTO_MLKEM_PUBLIC_BLOB, &encaps_key, blob, sizeof(blob), 0))) {
			if (CNG_SUCCESS(crypto_encapsulate(encaps_key, secret, CRYPTO_MLKEM_SECRET_SIZE, &secret_size,
			                                   server_share, CRYPTO_MLKEM768_CIPHERTEXT_SIZE, &ciphertext_size, 0)) &&
			    secret_size == CRYPTO_MLKEM_SECRET_SIZE && ciphertext_size == CRYPTO_MLKEM768_CIPHERTEXT_SIZE &&
			    CryptoX25519GenerateKey(x25519_key, server_share + CRYPTO_MLKEM768_CIPHERTEXT_SIZE) &&
			    CryptoX25519(secret + CRYPTO_MLKEM_SECRET_SIZE, x25519_key, client_share + CRYPTO_MLKEM768_ENCAPS_KEY_SIZE))
				ok = true;
			BCryptDestroyKey(encaps_key);
		}
	}

	SecureZeroMemory(x25519_key, sizeof(x25519_key));
	if (ok == false) {
		SecureZeroMemory(secret, CRYPTO_HYBRID_SECRET_SIZE);
		ZeroMemory(server_share, CRYPTO_HYBRID_SERVER_SHARE_SIZE);
	}

	return ok;
}

bool CryptoHybridFinish(CRYPTO_HYBRID *h, UCHAR *secret, const UCHAR *server_share) {
	ULONG secret_size = 0;
	bool ok = false;

	if (secret == NULL) {
		CryptoHybridFree(h);
		return false;
	}

	// A ciphertext that was tampered with decapsulates to an unrelated secret (FIPS 203 implicit
	// rejection), so the exchange fails later, at the first message under the secret
	if (h != NULL && h->MlKemKey != NULL && server_share != NULL && crypto_decapsulate != NULL &&
	    CNG_SUCCESS(crypto_decapsulate(h->MlKemKey, (PUCHAR)server_share, CRYPTO_MLKEM768_CIPHERTEXT_SIZE,
	                                   secret, CRYPTO_MLKEM_SECRET_SIZE, &secret_size, 0)) &&
	    secret_size == CRYPTO_MLKEM_SECRET_SIZE &&
	    CryptoX25519(secret + CRYPTO_MLKEM_SECRET_SIZE, h->X25519Key, server_share + CRYPTO_MLKEM768_CIPHERTEXT_SIZE))
		ok = true;

	CryptoHybridFree(h);
	if (ok == false)
		SecureZeroMemory(secret, CRYPTO_HYBRID_SECRET_SIZE);

	return ok;
}

void CryptoHybridFree(CRYPTO_HYBRID *h) {
	if (h == NULL)
		return;

	if (h->MlKemKey != NULL)
		BCryptDestroyKey(h->MlKemKey);
	h->MlKemKey = NULL;
	SecureZeroMemory(h->X25519Key, sizeof(h->X25519Key));
}
