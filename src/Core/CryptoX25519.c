// CryptoX25519.c
// X25519 (RFC 7748) on the CNG curve25519 provider, and the node identity key: a persisted
// X25519 key in the Microsoft Software Key Storage Provider
//
// CNG's curve25519 blobs and secrets are undocumented. What the module relies on, measured on
// Windows 11 and checked by the coretest known-answer tests on x64 and arm64:
// - The scalar d and the u-coordinate X of a BCRYPT_ECCKEY_BLOB are little-endian, as in the RFC;
//   Y is unused and zero. A private blob may leave X zero.
// - CNG does not clamp: a scalar that is not clamped is refused (STATUS_INVALID_PARAMETER).
// - A u-coordinate with bit 255 set, or not below 2^255 - 19, is refused, where the RFC asks to
//   mask the bit and reduce the value; a u of zero is refused at import, a point of low order at
//   the secret agreement.
// - Windows 11 24H2 and Server 2025 (build 26100) also refuse, at import, a public key outside the
//   prime-order subgroup, such as the u of the first RFC 7748 5.2 vector. X25519 takes any u: the
//   clamped scalar is a multiple of the cofactor 8, which removes the small-order part. So a peer
//   key is imported with BCRYPT_NO_KEY_VALIDATION; a point of low order still gives no secret.
// - BCRYPT_KDF_RAW_SECRET returns the shared secret byte-reversed (big-endian).
// The NCrypt key storage provider behaves the same; it also needs the curve name to import a
// curve25519 blob (NCRYPTBUFFER_ECC_CURVE_NAME).

#include "Core/CryptoInternal.h"

// RFC 7748 section 5: decodeScalar25519 without the decoding
static void CryptoX25519Clamp(UCHAR *k) {
	k[0] &= 248;
	k[31] &= 127;
	k[31] |= 64;
}

// RFC 7748 section 5: decodeUCoordinate. Bit 255 is masked; a value in [p, 2^255) is reduced by
// p = 2^255 - 19. Those are p + 0 to p + 18: low byte 0xED to 0xFF, bytes 1 to 30 0xFF, top byte
// 0x7F, and the reduced value is the low byte minus 0xED.
static void CryptoX25519NormalizeU(UCHAR *u) {
	u[31] &= 0x7F;

	if (u[31] != 0x7F || u[0] < 0xED)
		return;
	for (UINT i = 1; i < 31; i++)
		if (u[i] != 0xFF)
			return;

	u[0] = (UCHAR)(u[0] - 0xED);
	for (UINT i = 1; i < 32; i++)
		u[i] = 0;
}

void CryptoX25519PrivateBlob(UCHAR *blob, const UCHAR *priv) {
	BCRYPT_ECCKEY_BLOB *head = (BCRYPT_ECCKEY_BLOB *)blob;
	UCHAR *d = blob + sizeof(BCRYPT_ECCKEY_BLOB) + 2 * CRYPTO_X25519_SIZE;

	SecureZeroMemory(blob, CRYPTO_X25519_PRIVATE_BLOB_SIZE);
	head->dwMagic = BCRYPT_ECDH_PRIVATE_GENERIC_MAGIC;
	head->cbKey = CRYPTO_X25519_SIZE;
	CopyMemory(d, priv, CRYPTO_X25519_SIZE);
	CryptoX25519Clamp(d);
}

void CryptoX25519PublicBlob(UCHAR *blob, const UCHAR *pub) {
	BCRYPT_ECCKEY_BLOB *head = (BCRYPT_ECCKEY_BLOB *)blob;
	UCHAR *x = blob + sizeof(BCRYPT_ECCKEY_BLOB);

	ZeroMemory(blob, CRYPTO_X25519_PUBLIC_BLOB_SIZE);
	head->dwMagic = BCRYPT_ECDH_PUBLIC_GENERIC_MAGIC;
	head->cbKey = CRYPTO_X25519_SIZE;
	CopyMemory(x, pub, CRYPTO_X25519_SIZE);
	CryptoX25519NormalizeU(x);
}

// The RFC byte order of a raw secret from CNG or NCrypt; false for the all-zero secret of a peer
// key of low order (RFC 7748 section 6.1), which the caller must not use
bool CryptoX25519FromRawSecret(UCHAR *shared, const UCHAR *raw) {
	UCHAR any = 0;

	for (UINT i = 0; i < CRYPTO_X25519_SIZE; i++) {
		shared[i] = raw[CRYPTO_X25519_SIZE - 1 - i];
		any |= shared[i];
	}

	if (any == 0)
		return false;

	return true;
}

// The X25519 public key in a CNG or NCrypt BCRYPT_ECCPUBLIC_BLOB
static bool CryptoX25519PublicFromBlob(UCHAR *pub, const UCHAR *blob, ULONG size) {
	const BCRYPT_ECCKEY_BLOB *head = (const BCRYPT_ECCKEY_BLOB *)blob;

	if (size < CRYPTO_X25519_PUBLIC_BLOB_SIZE || head->dwMagic != BCRYPT_ECDH_PUBLIC_GENERIC_MAGIC || head->cbKey != CRYPTO_X25519_SIZE)
		return false;

	CopyMemory(pub, blob + sizeof(BCRYPT_ECCKEY_BLOB), CRYPTO_X25519_SIZE);
	return true;
}

// A CNG key of the curve25519 provider from a private scalar
static BCRYPT_KEY_HANDLE CryptoX25519ImportPrivate(const UCHAR *priv) {
	UCHAR blob[CRYPTO_X25519_PRIVATE_BLOB_SIZE];
	BCRYPT_KEY_HANDLE key = NULL;

	if (CryptoInit() == false)
		return NULL;

	CryptoX25519PrivateBlob(blob, priv);
	if (CNG_SUCCESS(BCryptImportKeyPair(crypto_x25519, NULL, BCRYPT_ECCPRIVATE_BLOB, &key, blob, sizeof(blob), 0)) == false)
		key = NULL;

	SecureZeroMemory(blob, sizeof(blob));
	return key;
}

bool CryptoX25519PublicKey(UCHAR *pub, const UCHAR *priv) {
	UCHAR blob[CRYPTO_X25519_PUBLIC_BLOB_SIZE];
	ULONG size = 0;
	bool ok = false;

	if (pub == NULL || priv == NULL)
		return false;

	BCRYPT_KEY_HANDLE key = CryptoX25519ImportPrivate(priv);
	if (key != NULL) {
		if (CNG_SUCCESS(BCryptExportKey(key, NULL, BCRYPT_ECCPUBLIC_BLOB, blob, sizeof(blob), &size, 0)))
			ok = CryptoX25519PublicFromBlob(pub, blob, size);
		BCryptDestroyKey(key);
	}

	if (ok == false)
		ZeroMemory(pub, CRYPTO_X25519_SIZE);

	return ok;
}

bool CryptoX25519GenerateKey(UCHAR *priv, UCHAR *pub) {
	if (priv == NULL || pub == NULL)
		return false;

	if (CryptoRandom(priv, CRYPTO_X25519_SIZE)) {
		CryptoX25519Clamp(priv);
		if (CryptoX25519PublicKey(pub, priv))
			return true;
	}

	SecureZeroMemory(priv, CRYPTO_X25519_SIZE);
	ZeroMemory(pub, CRYPTO_X25519_SIZE);
	return false;
}

bool CryptoX25519(UCHAR *shared, const UCHAR *priv, const UCHAR *peer_pub) {
	UCHAR blob[CRYPTO_X25519_PUBLIC_BLOB_SIZE];
	UCHAR raw[CRYPTO_X25519_SIZE];
	BCRYPT_KEY_HANDLE peer = NULL;
	BCRYPT_SECRET_HANDLE secret = NULL;
	ULONG size = 0;
	bool ok = false;

	if (shared == NULL || priv == NULL || peer_pub == NULL)
		return false;

	BCRYPT_KEY_HANDLE key = CryptoX25519ImportPrivate(priv);
	if (key != NULL) {
		CryptoX25519PublicBlob(blob, peer_pub);
		if (CNG_SUCCESS(BCryptImportKeyPair(crypto_x25519, NULL, BCRYPT_ECCPUBLIC_BLOB, &peer, blob, sizeof(blob), BCRYPT_NO_KEY_VALIDATION))) {
			if (CNG_SUCCESS(BCryptSecretAgreement(key, peer, &secret, 0))) {
				if (CNG_SUCCESS(BCryptDeriveKey(secret, BCRYPT_KDF_RAW_SECRET, NULL, raw, sizeof(raw), &size, 0)) && size == sizeof(raw))
					ok = CryptoX25519FromRawSecret(shared, raw);
				BCryptDestroySecret(secret);
			}
			BCryptDestroyKey(peer);
		}
		BCryptDestroyKey(key);
	}

	SecureZeroMemory(raw, sizeof(raw));
	if (ok == false)
		SecureZeroMemory(shared, CRYPTO_X25519_SIZE);

	return ok;
}

// The node identity key

// NCrypt flags of the key scope
static DWORD CryptoIdentityKeyFlags(UINT flags) {
	return NCRYPT_SILENT_FLAG | ((flags & CRYPTO_MACHINE) ? NCRYPT_MACHINE_KEY_FLAG : 0);
}

static bool CryptoIdentityOpenProvider(CRYPTO_IDENTITY *id, const wchar_t *name) {
	NCRYPT_PROV_HANDLE prov = 0;

	if (id == NULL)
		return false;

	id->Provider = 0;
	id->Key = 0;
	if (name == NULL || name[0] == 0)
		return false;

	if (NCryptOpenStorageProvider(&prov, MS_KEY_STORAGE_PROVIDER, 0) != ERROR_SUCCESS)
		return false;

	id->Provider = prov;
	return true;
}

// Whether an NCrypt key is an X25519 key (ECDH on curve25519)
static bool CryptoIdentityIsX25519(NCRYPT_KEY_HANDLE key) {
	wchar_t curve[64];
	DWORD size = 0;

	if (NCryptGetProperty(key, NCRYPT_ECC_CURVE_NAME_PROPERTY, (PBYTE)curve, sizeof(curve) - sizeof(wchar_t), &size, 0) != ERROR_SUCCESS)
		return false;

	curve[size / sizeof(wchar_t)] = 0;
	return CompareStringOrdinal(curve, -1, BCRYPT_ECC_CURVE_25519, -1, TRUE) == CSTR_EQUAL;
}

bool CryptoIdentityCreate(CRYPTO_IDENTITY *id, const wchar_t *name, UINT flags) {
	NCRYPT_KEY_HANDLE key = 0;

	if (CryptoIdentityOpenProvider(id, name) == false)
		return false;

	// Without NCRYPT_OVERWRITE_KEY_FLAG an existing key of that name is an error (NTE_EXISTS). The
	// export policy stays the default: the private key cannot be exported.
	if (NCryptCreatePersistedKey(id->Provider, &key, NCRYPT_ECDH_ALGORITHM, name, 0, (flags & CRYPTO_MACHINE) ? NCRYPT_MACHINE_KEY_FLAG : 0) == ERROR_SUCCESS) {
		if (NCryptSetProperty(key, NCRYPT_ECC_CURVE_NAME_PROPERTY, (PBYTE)BCRYPT_ECC_CURVE_25519, sizeof(BCRYPT_ECC_CURVE_25519), 0) == ERROR_SUCCESS &&
		    NCryptFinalizeKey(key, NCRYPT_SILENT_FLAG) == ERROR_SUCCESS) {
			id->Key = key;
			return true;
		}

		// A key that was not finalized was never stored
		NCryptFreeObject(key);
	}

	CryptoIdentityClose(id);
	return false;
}

bool CryptoIdentityImport(CRYPTO_IDENTITY *id, const wchar_t *name, const UCHAR *priv, UINT flags) {
	UCHAR blob[CRYPTO_X25519_PRIVATE_BLOB_SIZE];
	NCryptBuffer param[2];
	NCryptBufferDesc params;
	NCRYPT_KEY_HANDLE key = 0;

	if (id == NULL)
		return false;

	id->Provider = 0;
	id->Key = 0;
	if (priv == NULL || CryptoIdentityOpenProvider(id, name) == false)
		return false;

	// The name makes the imported key persisted; the curve name makes the generic ECDH blob a curve25519 one
	param[0].cbBuffer = (ULONG)((lstrlenW(name) + 1) * sizeof(wchar_t));
	param[0].BufferType = NCRYPTBUFFER_PKCS_KEY_NAME;
	param[0].pvBuffer = (PVOID)name;
	param[1].cbBuffer = sizeof(BCRYPT_ECC_CURVE_25519);
	param[1].BufferType = NCRYPTBUFFER_ECC_CURVE_NAME;
	param[1].pvBuffer = (PVOID)BCRYPT_ECC_CURVE_25519;
	params.ulVersion = NCRYPTBUFFER_VERSION;
	params.cBuffers = 2;
	params.pBuffers = param;

	CryptoX25519PrivateBlob(blob, priv);
	if (NCryptImportKey(id->Provider, 0, BCRYPT_ECCPRIVATE_BLOB, &params, &key, blob, sizeof(blob), CryptoIdentityKeyFlags(flags)) == ERROR_SUCCESS)
		id->Key = key;
	SecureZeroMemory(blob, sizeof(blob));

	if (id->Key == 0) {
		CryptoIdentityClose(id);
		return false;
	}

	return true;
}

bool CryptoIdentityOpen(CRYPTO_IDENTITY *id, const wchar_t *name, UINT flags) {
	NCRYPT_KEY_HANDLE key = 0;

	if (CryptoIdentityOpenProvider(id, name) == false)
		return false;

	if (NCryptOpenKey(id->Provider, &key, name, 0, CryptoIdentityKeyFlags(flags)) == ERROR_SUCCESS) {
		if (CryptoIdentityIsX25519(key)) {
			id->Key = key;
			return true;
		}
		NCryptFreeObject(key);
	}

	CryptoIdentityClose(id);
	return false;
}

bool CryptoIdentityPublicKey(CRYPTO_IDENTITY *id, UCHAR *pub) {
	UCHAR blob[CRYPTO_X25519_PUBLIC_BLOB_SIZE];
	DWORD size = 0;

	if (pub == NULL)
		return false;

	if (id != NULL && id->Key != 0 &&
	    NCryptExportKey(id->Key, 0, BCRYPT_ECCPUBLIC_BLOB, NULL, blob, sizeof(blob), &size, 0) == ERROR_SUCCESS &&
	    CryptoX25519PublicFromBlob(pub, blob, size))
		return true;

	ZeroMemory(pub, CRYPTO_X25519_SIZE);
	return false;
}

bool CryptoIdentityDh(CRYPTO_IDENTITY *id, UCHAR *shared, const UCHAR *peer_pub) {
	UCHAR blob[CRYPTO_X25519_PUBLIC_BLOB_SIZE];
	UCHAR raw[CRYPTO_X25519_SIZE];
	NCryptBuffer param;
	NCryptBufferDesc params;
	NCRYPT_KEY_HANDLE peer = 0;
	NCRYPT_SECRET_HANDLE secret = 0;
	DWORD size = 0;
	bool ok = false;

	if (shared == NULL)
		return false;
	if (id == NULL || id->Key == 0 || peer_pub == NULL) {
		SecureZeroMemory(shared, CRYPTO_X25519_SIZE);
		return false;
	}

	// The peer key is an ephemeral key of the same provider, as NCryptSecretAgreement requires,
	// imported without the subgroup check, as in CryptoX25519()
	param.cbBuffer = sizeof(BCRYPT_ECC_CURVE_25519);
	param.BufferType = NCRYPTBUFFER_ECC_CURVE_NAME;
	param.pvBuffer = (PVOID)BCRYPT_ECC_CURVE_25519;
	params.ulVersion = NCRYPTBUFFER_VERSION;
	params.cBuffers = 1;
	params.pBuffers = &param;

	CryptoX25519PublicBlob(blob, peer_pub);
	if (NCryptImportKey(id->Provider, 0, BCRYPT_ECCPUBLIC_BLOB, &params, &peer, blob, sizeof(blob), NCRYPT_NO_KEY_VALIDATION | NCRYPT_SILENT_FLAG) == ERROR_SUCCESS) {
		if (NCryptSecretAgreement(id->Key, peer, &secret, NCRYPT_SILENT_FLAG) == ERROR_SUCCESS) {
			if (NCryptDeriveKey(secret, BCRYPT_KDF_RAW_SECRET, NULL, raw, sizeof(raw), &size, 0) == ERROR_SUCCESS && size == sizeof(raw))
				ok = CryptoX25519FromRawSecret(shared, raw);
			NCryptFreeObject(secret);
		}
		NCryptFreeObject(peer);
	}

	SecureZeroMemory(raw, sizeof(raw));
	if (ok == false)
		SecureZeroMemory(shared, CRYPTO_X25519_SIZE);

	return ok;
}

void CryptoIdentityClose(CRYPTO_IDENTITY *id) {
	if (id == NULL)
		return;

	if (id->Key != 0)
		NCryptFreeObject(id->Key);
	if (id->Provider != 0)
		NCryptFreeObject(id->Provider);

	id->Key = 0;
	id->Provider = 0;
}

bool CryptoIdentityDelete(CRYPTO_IDENTITY *id) {
	bool ok = false;

	if (id == NULL)
		return false;

	// NCryptDeleteKey frees the key handle when it succeeds; CryptoIdentityClose frees it otherwise
	if (id->Key != 0 && NCryptDeleteKey(id->Key, NCRYPT_SILENT_FLAG) == ERROR_SUCCESS) {
		ok = true;
		id->Key = 0;
	}

	CryptoIdentityClose(id);
	return ok;
}
