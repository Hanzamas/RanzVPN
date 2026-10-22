// hybrid.c
// ML-KEM-768 and the X25519MLKEM768 hybrid: used where the OS provides ML-KEM, omitted without
// failing where it does not (CORE-F1 acceptance criterion 4). The test passes on both kinds of
// system and says which one it ran on.

#include "coretest.h"

#include <string.h>

#include <bcrypt.h>

// What CNG answers at each step of an ML-KEM-768 key generation and export, printed when the
// hybrid fails on a system that has ML-KEM, so that the job log shows where
static void mlkem_diagnose() {
	BCRYPT_ALG_HANDLE alg = NULL;
	BCRYPT_KEY_HANDLE key = NULL;
	UCHAR blob[2048];
	ULONG size = 0;

	NTSTATUS r = BCryptOpenAlgorithmProvider(&alg, L"ML-KEM", NULL, 0);
	coretest_info("BCryptOpenAlgorithmProvider(ML-KEM): 0x%08lX", (unsigned long)r);
	if (r < 0)
		return;

	r = BCryptGenerateKeyPair(alg, &key, 0, 0);
	coretest_info("BCryptGenerateKeyPair: 0x%08lX", (unsigned long)r);
	if (r >= 0) {
		r = BCryptSetProperty(key, L"ParameterSetName", (PUCHAR)L"768", sizeof(L"768"), 0);
		coretest_info("BCryptSetProperty(ParameterSetName, 768) on the key: 0x%08lX", (unsigned long)r);
		r = BCryptFinalizeKeyPair(key, 0);
		coretest_info("BCryptFinalizeKeyPair: 0x%08lX", (unsigned long)r);
		r = BCryptExportKey(key, NULL, L"MLKEMPUBLICBLOB", blob, sizeof(blob), &size, 0);
		coretest_info("BCryptExportKey(MLKEMPUBLICBLOB): 0x%08lX, %lu bytes", (unsigned long)r, (unsigned long)size);
		if (r >= 0 && size >= 12)
			coretest_info("blob header: magic 0x%08lX, parameter set %lu bytes, key %lu bytes", (unsigned long)((ULONG *)blob)[0],
			              (unsigned long)((ULONG *)blob)[1], (unsigned long)((ULONG *)blob)[2]);
		BCryptDestroyKey(key);
	}

	BCryptCloseAlgorithmProvider(alg, 0);
}

void mlkem_test() {
	USHORT groups[4];
	UCHAR client_share[CRYPTO_HYBRID_CLIENT_SHARE_SIZE];
	UCHAR server_share[CRYPTO_HYBRID_SERVER_SHARE_SIZE];
	UCHAR secret1[CRYPTO_HYBRID_SECRET_SIZE], secret2[CRYPTO_HYBRID_SECRET_SIZE], first[CRYPTO_HYBRID_SECRET_SIZE];
	UCHAR x25519[CRYPTO_X25519_SIZE], zero[CRYPTO_HYBRID_SECRET_SIZE];
	CRYPTO_HYBRID h;
	bool available = CryptoMlKemAvailable();

	ZeroMemory(zero, sizeof(zero));
	UINT num = CryptoKeyExchangeGroups(groups, 4);

	if (available == false) {
		coretest_info("ML-KEM is not provided by this OS: X25519MLKEM768 is omitted, X25519 is offered alone");
		coretest_check(num == 1 && groups[0] == CRYPTO_GROUP_X25519, "the groups are X25519 only");

		FillMemory(&h, sizeof(h), 0x55);
		coretest_check(CryptoHybridBegin(&h, client_share) == false && h.MlKemKey == NULL && h.X25519Key[0] == 0, "Begin fails cleanly");
		FillMemory(client_share, sizeof(client_share), 0x01);
		FillMemory(secret1, sizeof(secret1), 0x55);
		coretest_check(CryptoHybridRespond(server_share, secret1, client_share) == false && memcmp(secret1, zero, sizeof(secret1)) == 0,
		               "Respond fails cleanly, the secret zeroed");
		coretest_check(CryptoHybridFinish(&h, secret1, server_share) == false, "Finish fails cleanly");

		CRYPTO_MLKEM k;
		FillMemory(&k, sizeof(k), 0x55);
		coretest_check(CryptoMlKemGenerate(&k, client_share) == false && k.Key == NULL &&
		                   CryptoMlKemEncapsulate(server_share, secret1, client_share) == false && memcmp(secret1, zero, CRYPTO_MLKEM_SECRET_SIZE) == 0,
		               "ML-KEM alone fails cleanly");
		return;
	}

	coretest_info("ML-KEM is provided by this OS: X25519MLKEM768 (0x11EC) is offered first");
	coretest_check(num == 2 && groups[0] == CRYPTO_GROUP_X25519MLKEM768 && groups[1] == CRYPTO_GROUP_X25519, "the groups are X25519MLKEM768, then X25519");
	coretest_check(CryptoKeyExchangeGroups(groups, 1) == 1 && groups[0] == CRYPTO_GROUP_X25519MLKEM768 && CryptoKeyExchangeGroups(NULL, 0) == 2,
	               "the group list is cut at max; NULL counts it");

	for (UINT round = 0; round < 2; round++) {
		if (coretest_check(CryptoHybridBegin(&h, client_share), "initiator: ML-KEM-768 key pair and X25519 key, 1216-byte share") == false) {
			mlkem_diagnose();
			return;
		}
		if (coretest_check(CryptoHybridRespond(server_share, secret1, client_share), "responder: encapsulation and X25519, 1120-byte share") == false) {
			CryptoHybridFree(&h);
			return;
		}

		// The X25519 half by itself, from the initiator's scalar and the responder's public key
		coretest_check(CryptoX25519(x25519, h.X25519Key, server_share + CRYPTO_MLKEM768_CIPHERTEXT_SIZE), "X25519 half computed alone");
		coretest_check(CryptoHybridFinish(&h, secret2, server_share) && h.MlKemKey == NULL, "initiator: decapsulation, state released");
		coretest_check(memcmp(secret1, secret2, sizeof(secret1)) == 0, "both sides hold the same 64-byte secret");
		coretest_check(memcmp(secret1 + CRYPTO_MLKEM_SECRET_SIZE, x25519, sizeof(x25519)) == 0, "the secret is the ML-KEM secret, then the X25519 secret");
		coretest_check(memcmp(secret1, zero, CRYPTO_MLKEM_SECRET_SIZE) != 0, "the ML-KEM secret is not zero");

		if (round == 0)
			CopyMemory(first, secret1, sizeof(first));
		else
			coretest_check(memcmp(first, secret1, sizeof(first)) != 0, "a second exchange gives another secret");
	}

	// A ciphertext that was changed never gives the responder's secret: FIPS 203 decapsulates it to
	// an unrelated one (implicit rejection)
	if (CryptoHybridBegin(&h, client_share) && CryptoHybridRespond(server_share, secret1, client_share)) {
		server_share[0] ^= 0x01;
		bool finished = CryptoHybridFinish(&h, secret2, server_share);
		coretest_info("changed ciphertext: %s", finished ? "decapsulated to another secret (implicit rejection)" : "refused by CNG");
		coretest_check(memcmp(secret1, secret2, sizeof(secret1)) != 0, "a changed ciphertext does not give the responder's secret");
	} else {
		CryptoHybridFree(&h);
		coretest_check(false, "third exchange");
	}

	coretest_check(CryptoHybridRespond(server_share, secret1, NULL) == false && memcmp(secret1, zero, sizeof(secret1)) == 0, "no client share is refused");

	// ML-KEM-768 alone, the KEM of the Noise hfs handshake: the two sides agree, and the key pair is
	// released by the decapsulation
	CRYPTO_MLKEM k;
	if (coretest_check(CryptoMlKemGenerate(&k, client_share) && k.Key != NULL, "ML-KEM alone: key pair and 1184-byte encapsulation key")) {
		coretest_check(CryptoMlKemEncapsulate(server_share, secret1, client_share), "encapsulation: 1088-byte ciphertext and a 32-byte secret");
		coretest_check(CryptoMlKemDecapsulate(&k, secret2, server_share) && k.Key == NULL && memcmp(secret1, secret2, CRYPTO_MLKEM_SECRET_SIZE) == 0 &&
		                   memcmp(secret1, zero, CRYPTO_MLKEM_SECRET_SIZE) != 0,
		               "decapsulation gives the same secret, and releases the key pair");
	}
	CryptoMlKemFree(&k);
	coretest_check(CryptoMlKemDecapsulate(&k, secret2, server_share) == false && memcmp(secret2, zero, CRYPTO_MLKEM_SECRET_SIZE) == 0, "no key pair: decapsulation fails");
}
