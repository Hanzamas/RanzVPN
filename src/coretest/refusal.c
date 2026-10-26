// refusal.c
// The refusals of the crypto module (FIX-10, #435): every function of src/Core/Crypto*.c that is
// handed a missing argument, a state it cannot use or a key it must not take fails without side
// effects, zeroes the output it was given and releases the key it owned. The known-answer tests
// of kat.c and hybrid.c show what the functions compute; this test shows what they refuse.

#include "coretest.h"

#include <string.h>

#include <ncrypt.h>

// Whether size bytes are all zero
static bool refusal_zero(const UCHAR *p, UINT size) {
	for (UINT i = 0; i < size; i++) {
		if (p[i] != 0)
			return false;
	}

	return true;
}

// SHA-256 in parts, HMAC-SHA256 and HKDF-SHA256
static void refusal_hash() {
	UCHAR d[CRYPTO_SHA256_SIZE], okm[64], prk[CRYPTO_SHA256_SIZE];
	CRYPTO_SHA256 s;

	coretest_check(CryptoSha256Begin(NULL) == false, "SHA-256: no state is refused");

	ZeroMemory(&s, sizeof(s));
	FillMemory(d, sizeof(d), 0x55);
	coretest_check(CryptoSha256Update(&s, "abc", 3) == false && CryptoSha256Update(NULL, "abc", 3) == false,
	               "SHA-256: data into a state that was never begun is refused");
	coretest_check(CryptoSha256End(&s, d) == false && refusal_zero(d, sizeof(d)), "SHA-256: ending a state that was never begun zeroes the digest");
	coretest_check(CryptoSha256End(NULL, NULL) == false, "SHA-256: ending no state with no digest is refused");

	if (coretest_check(CryptoSha256Begin(&s) && s.Hash != NULL, "SHA-256: a state begun")) {
		coretest_check(CryptoSha256Update(&s, NULL, 3) == false, "SHA-256: a NULL source of 3 bytes is refused");
		coretest_check(CryptoSha256End(&s, NULL) == false && s.Hash == NULL, "SHA-256: ending without a digest releases the state");
		FillMemory(d, sizeof(d), 0x55);
		coretest_check(CryptoSha256End(&s, d) == false && refusal_zero(d, sizeof(d)), "SHA-256: a released state is not ended twice");
	}

	coretest_check(CryptoHmacSha256(NULL, "k", 1, "m", 1) == false && CryptoHmacSha256(d, NULL, 1, "m", 1) == false &&
	                   CryptoHmacSha256(d, "k", 1, NULL, 1) == false,
	               "HMAC-SHA256: a NULL output, key or message is refused");

	CryptoSha256(prk, "ikm", 3);
	coretest_check(CryptoHkdfExpand(NULL, sizeof(okm), prk, NULL, 0) == false && CryptoHkdfExpand(okm, sizeof(okm), NULL, NULL, 0) == false &&
	                   CryptoHkdfExpand(okm, sizeof(okm), prk, NULL, 4) == false,
	               "HKDF-Expand: a NULL output, PRK or info of 4 bytes is refused");
	FillMemory(okm, sizeof(okm), 0x55);
	coretest_check(CryptoHkdfExpand(okm, 0, prk, NULL, 0) == false && okm[0] == 0x55, "HKDF-Expand: L = 0 is refused and nothing written");
	coretest_check(CryptoHkdf(NULL, sizeof(okm), "s", 1, "ikm", 3, NULL, 0) == false, "HKDF: a NULL output is refused");
	coretest_check(CryptoHkdf(okm, sizeof(okm), NULL, 1, "ikm", 3, NULL, 0) == false && refusal_zero(okm, sizeof(okm)),
	               "HKDF: a NULL salt of 1 byte fails the Extract and zeroes the output");
	FillMemory(okm, sizeof(okm), 0x55);
	coretest_check(CryptoHkdf(okm, 0, NULL, 1, "ikm", 3, NULL, 0) == false && okm[0] == 0x55, "HKDF: a failed Extract with L = 0 writes nothing");
}

// AES-GCM without a key, with a key released, and with missing buffers
static void refusal_aead() {
	static const UCHAR key[32] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32};
	UCHAR nonce[CRYPTO_AES_GCM_NONCE_SIZE], tag[CRYPTO_AES_GCM_TAG_SIZE], pt[16], ct[16];
	CRYPTO_AEAD a;

	ZeroMemory(nonce, sizeof(nonce));
	FillMemory(pt, sizeof(pt), 0x11);
	coretest_check(CryptoAeadInit(NULL, key, 32) == false, "AES-GCM: no state is refused");
	CryptoAeadFree(NULL);

	if (coretest_check(CryptoAeadInit(&a, key, 32), "AES-GCM: a 256-bit key")) {
		coretest_check(CryptoAeadSeal(&a, NULL, NULL, 0, pt, sizeof(pt), ct, tag) == false && CryptoAeadSeal(&a, nonce, NULL, 0, pt, sizeof(pt), ct, NULL) == false &&
		                   CryptoAeadSeal(&a, nonce, NULL, 4, pt, sizeof(pt), ct, tag) == false && CryptoAeadSeal(&a, nonce, NULL, 0, NULL, sizeof(pt), ct, tag) == false &&
		                   CryptoAeadSeal(&a, nonce, NULL, 0, pt, sizeof(pt), NULL, tag) == false,
		               "AES-GCM: sealing without a nonce, tag, AAD of 4 bytes, source or destination is refused");
		coretest_check(CryptoAeadSeal(&a, nonce, NULL, 0, pt, sizeof(pt), ct, tag), "AES-GCM: a message sealed");
		tag[0] ^= 0x01;
		FillMemory(pt, sizeof(pt), 0x55);
		coretest_check(CryptoAeadOpen(&a, nonce, NULL, 0, ct, sizeof(ct), tag, pt) == false && refusal_zero(pt, sizeof(pt)),
		               "AES-GCM: a changed tag is refused, the plaintext zeroed");
		tag[0] ^= 0x01;
		coretest_check(CryptoAeadOpen(&a, NULL, NULL, 0, ct, sizeof(ct), tag, pt) == false && CryptoAeadOpen(&a, nonce, NULL, 0, ct, sizeof(ct), NULL, pt) == false &&
		                   CryptoAeadOpen(&a, nonce, NULL, 4, ct, sizeof(ct), tag, pt) == false && CryptoAeadOpen(&a, nonce, NULL, 0, NULL, sizeof(ct), tag, pt) == false &&
		                   CryptoAeadOpen(&a, nonce, NULL, 0, ct, sizeof(ct), tag, NULL) == false,
		               "AES-GCM: opening without a nonce, tag, AAD of 4 bytes, source or destination is refused");

		CryptoAeadFree(&a);
		coretest_check(a.Key == NULL, "AES-GCM: the key released");
		CryptoAeadFree(&a);
		coretest_check(CryptoAeadSeal(&a, nonce, NULL, 0, pt, sizeof(pt), ct, tag) == false && CryptoAeadOpen(&a, nonce, NULL, 0, ct, sizeof(ct), tag, pt) == false,
		               "AES-GCM: a released key neither seals nor opens");
	}

	coretest_check(CryptoAeadSeal(NULL, nonce, NULL, 0, pt, sizeof(pt), ct, tag) == false && CryptoAeadOpen(NULL, nonce, NULL, 0, ct, sizeof(ct), tag, pt) == false,
	               "AES-GCM: no state neither seals nor opens");
}

// X25519 and the node identity key
static void refusal_x25519() {
	UCHAR priv[CRYPTO_X25519_SIZE], pub[CRYPTO_X25519_SIZE], s[CRYPTO_X25519_SIZE];
	CRYPTO_IDENTITY id;
	UINT scope = coretest_scope();
	wchar_t name[64];

	coretest_check(CryptoX25519PublicKey(NULL, priv) == false && CryptoX25519PublicKey(pub, NULL) == false, "X25519: a public key needs both buffers");
	coretest_check(CryptoX25519GenerateKey(NULL, pub) == false && CryptoX25519GenerateKey(priv, NULL) == false, "X25519: a key pair needs both buffers");
	if (coretest_check(CryptoX25519GenerateKey(priv, pub), "X25519: a key pair")) {
		coretest_check(CryptoX25519(NULL, priv, pub) == false && CryptoX25519(s, NULL, pub) == false && CryptoX25519(s, priv, NULL) == false,
		               "X25519: a NULL secret, scalar or peer key is refused");
	}

	FillMemory(pub, sizeof(pub), 0x55);
	coretest_check(CryptoIdentityPublicKey(NULL, pub) == false && refusal_zero(pub, sizeof(pub)), "identity: no identity has no public key, the buffer zeroed");
	ZeroMemory(&id, sizeof(id));
	FillMemory(pub, sizeof(pub), 0x55);
	coretest_check(CryptoIdentityPublicKey(&id, pub) == false && refusal_zero(pub, sizeof(pub)) && CryptoIdentityPublicKey(&id, NULL) == false,
	               "identity: a closed identity has no public key");
	FillMemory(s, sizeof(s), 0x55);
	coretest_check(CryptoIdentityDh(&id, s, pub) == false && refusal_zero(s, sizeof(s)) && CryptoIdentityDh(&id, NULL, pub) == false,
	               "identity: a closed identity agrees on no secret, the secret zeroed");
	coretest_check(CryptoIdentityImport(NULL, L"Ranz-coretest-refusal", priv, scope) == false, "identity: importing into no identity is refused");
	coretest_check(CryptoIdentityImport(&id, L"Ranz-coretest-refusal", NULL, scope) == false && id.Key == 0 && id.Provider == 0,
	               "identity: importing no scalar is refused");
	coretest_check(CryptoIdentityCreate(&id, NULL, scope) == false && id.Key == 0, "identity: a key without a name is refused");
	coretest_check(CryptoIdentityDelete(NULL) == false, "identity: deleting no identity is refused");
	CryptoIdentityClose(NULL);
	SecureZeroMemory(priv, sizeof(priv));

	// A key of the same name that is not an X25519 key (an ECDSA P-256 key, as a certificate's) is
	// never taken as the node identity
	NCRYPT_PROV_HANDLE prov = 0;
	NCRYPT_KEY_HANDLE key = 0;
	DWORD flags = (scope & CRYPTO_MACHINE) ? NCRYPT_MACHINE_KEY_FLAG : 0;

	_snwprintf_s(name, sizeof(name) / sizeof(wchar_t), _TRUNCATE, L"Ranz-coretest-refusal-p256-%lu", GetCurrentProcessId());
	if (coretest_check(NCryptOpenStorageProvider(&prov, MS_KEY_STORAGE_PROVIDER, 0) == ERROR_SUCCESS, "identity: the software KSP opened") == false)
		return;
	if (coretest_check(NCryptCreatePersistedKey(prov, &key, NCRYPT_ECDSA_P256_ALGORITHM, name, 0, flags) == ERROR_SUCCESS &&
	                       NCryptFinalizeKey(key, NCRYPT_SILENT_FLAG) == ERROR_SUCCESS,
	                   "identity: an ECDSA P-256 key stored under the name")) {
		coretest_check(CryptoIdentityOpen(&id, name, scope) == false && id.Key == 0 && id.Provider == 0, "identity: a key of another curve is not opened as the identity");
		coretest_check(CryptoIdentityCreate(&id, name, scope) == false && id.Key == 0, "identity: and the name is not taken over");
		coretest_check(NCryptDeleteKey(key, NCRYPT_SILENT_FLAG) == ERROR_SUCCESS, "identity: the P-256 key deleted");
	} else if (key != 0) {
		NCryptFreeObject(key);
	}
	NCryptFreeObject(prov);
}

// ML-KEM-768 and the X25519MLKEM768 hybrid, where the OS has ML-KEM (hybrid.c tests the system without it)
static void refusal_mlkem() {
	UCHAR client_share[CRYPTO_HYBRID_CLIENT_SHARE_SIZE], server_share[CRYPTO_HYBRID_SERVER_SHARE_SIZE];
	UCHAR secret[CRYPTO_HYBRID_SECRET_SIZE];
	CRYPTO_MLKEM k;
	CRYPTO_HYBRID h;

	CryptoMlKemFree(NULL);
	CryptoHybridFree(NULL);
	coretest_check(CryptoMlKemGenerate(NULL, client_share) == false && CryptoHybridBegin(NULL, client_share) == false, "ML-KEM: no state is refused");

	if (CryptoMlKemAvailable() == false) {
		coretest_info("ML-KEM is not provided by this OS: only the refusals that need no key pair");
		return;
	}

	FillMemory(&k, sizeof(k), 0x55);
	coretest_check(CryptoMlKemGenerate(&k, NULL) == false && k.Key == NULL, "ML-KEM: no encapsulation key buffer is refused, the state cleared");
	FillMemory(&h, sizeof(h), 0x55);
	coretest_check(CryptoHybridBegin(&h, NULL) == false && h.MlKemKey == NULL && h.X25519Key[0] == 0, "hybrid: no share buffer is refused, the state cleared");

	coretest_check(CryptoMlKemEncapsulate(NULL, secret, client_share) == false && CryptoMlKemEncapsulate(server_share, NULL, client_share) == false,
	               "ML-KEM: encapsulation without a ciphertext or secret buffer is refused");
	FillMemory(secret, sizeof(secret), 0x55);
	FillMemory(server_share, sizeof(server_share), 0x55);
	coretest_check(CryptoMlKemEncapsulate(server_share, secret, NULL) == false && refusal_zero(secret, CRYPTO_MLKEM_SECRET_SIZE) &&
	                   refusal_zero(server_share, CRYPTO_MLKEM768_CIPHERTEXT_SIZE),
	               "ML-KEM: encapsulation to no key fails, the secret and ciphertext zeroed");

	// FIPS 203 7.2: an encapsulation key whose coefficients are not reduced modulo q = 3329 (here
	// every 12-bit coefficient is 0xFFF) fails its modulus check; no secret may come out of it
	FillMemory(client_share, CRYPTO_MLKEM768_ENCAPS_KEY_SIZE, 0xFF);
	FillMemory(secret, sizeof(secret), 0x55);
	bool taken = CryptoMlKemEncapsulate(server_share, secret, client_share);
	coretest_info("an encapsulation key out of range: %s", taken ? "accepted by CNG" : "refused by CNG");
	coretest_check(taken == false && refusal_zero(secret, CRYPTO_MLKEM_SECRET_SIZE) && refusal_zero(server_share, CRYPTO_MLKEM768_CIPHERTEXT_SIZE),
	               "ML-KEM: an encapsulation key that fails the modulus check is refused, the outputs zeroed");
	FillMemory(secret, sizeof(secret), 0x55);
	coretest_check(CryptoHybridRespond(server_share, secret, client_share) == false && refusal_zero(secret, sizeof(secret)) &&
	                   refusal_zero(server_share, sizeof(server_share)),
	               "hybrid: a client share with that key is refused, the outputs zeroed");
	coretest_check(CryptoHybridRespond(NULL, secret, client_share) == false && CryptoHybridRespond(server_share, NULL, client_share) == false,
	               "hybrid: responding without a share or secret buffer is refused");

	// A decapsulation that is refused still releases the key pair, so that no caller leaks it on an error path
	if (coretest_check(CryptoMlKemGenerate(&k, client_share) && k.Key != NULL, "ML-KEM: a key pair")) {
		coretest_check(CryptoMlKemDecapsulate(&k, NULL, server_share) == false && k.Key == NULL, "ML-KEM: no secret buffer fails, the key pair released");
	}
	if (coretest_check(CryptoMlKemGenerate(&k, client_share), "ML-KEM: another key pair")) {
		FillMemory(secret, sizeof(secret), 0x55);
		coretest_check(CryptoMlKemDecapsulate(&k, secret, NULL) == false && k.Key == NULL && refusal_zero(secret, CRYPTO_MLKEM_SECRET_SIZE),
		               "ML-KEM: no ciphertext fails, the key pair released and the secret zeroed");
	}
	FillMemory(secret, sizeof(secret), 0x55);
	coretest_check(CryptoMlKemDecapsulate(NULL, secret, server_share) == false && refusal_zero(secret, CRYPTO_MLKEM_SECRET_SIZE), "ML-KEM: no state fails, the secret zeroed");

	if (coretest_check(CryptoHybridBegin(&h, client_share) && h.MlKemKey != NULL, "hybrid: a client share")) {
		coretest_check(CryptoHybridFinish(&h, NULL, server_share) == false && h.MlKemKey == NULL && refusal_zero(h.X25519Key, sizeof(h.X25519Key)),
		               "hybrid: no secret buffer fails, the ML-KEM key released and the X25519 scalar zeroed");
	}
	if (coretest_check(CryptoHybridBegin(&h, client_share), "hybrid: another client share")) {
		FillMemory(secret, sizeof(secret), 0x55);
		coretest_check(CryptoHybridFinish(&h, secret, NULL) == false && h.MlKemKey == NULL && refusal_zero(secret, sizeof(secret)),
		               "hybrid: no server share fails, the state released and the secret zeroed");
	}
	FillMemory(secret, sizeof(secret), 0x55);
	coretest_check(CryptoHybridFinish(NULL, secret, server_share) == false && refusal_zero(secret, sizeof(secret)), "hybrid: no state fails, the secret zeroed");
}

void cryptorefusal_test() {
	refusal_hash();
	refusal_aead();
	refusal_x25519();
	refusal_mlkem();
}
