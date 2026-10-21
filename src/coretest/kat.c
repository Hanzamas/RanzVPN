// kat.c
// Known-answer tests of the symmetric primitives, X25519 and the node identity key of the crypto
// module (seam 4 of spec #45). Every vector is from the RFC or specification named at it.

#include "coretest.h"

#include <string.h>

// The system random generator: no known answer exists, so sizes, distinct outputs and the share
// of zero bytes (1/256: 4096 of 1 MiB, standard deviation 64; the bounds are about 9 of them)
void rand_test() {
	UCHAR a[32], b[32], zero[32];
	UINT size = 1024 * 1024;
	UINT zeros = 0;

	ZeroMemory(zero, sizeof(zero));
	coretest_check(CryptoRandom(a, 0) && CryptoRandom(NULL, 16) == false, "size 0 succeeds, a NULL buffer is refused");
	coretest_check(CryptoRandom(a, sizeof(a)) && CryptoRandom(b, sizeof(b)) && memcmp(a, b, sizeof(a)) != 0 && memcmp(a, zero, sizeof(a)) != 0,
	               "two 32-byte outputs differ and are not zero");

	UCHAR *big = (UCHAR *)HeapAlloc(GetProcessHeap(), 0, size);
	if (coretest_check(big != NULL && CryptoRandom(big, size), "1 MiB in one call")) {
		for (UINT i = 0; i < size; i++)
			zeros += big[i] == 0;
		coretest_info("zero bytes in 1 MiB: %u (expected about 4096)", zeros);
		coretest_check(zeros > 3500 && zeros < 4700, "the share of zero bytes in 1 MiB is about 1/256");
	}
	if (big != NULL)
		HeapFree(GetProcessHeap(), 0, big);
}

// FIPS 180-2 appendix B and the NIST example values: "abc", the 448-bit and 896-bit messages and
// one million 'a'
void sha256_test() {
	static const char m448[] = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
	static const char m896[] = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";
	UCHAR d[CRYPTO_SHA256_SIZE];
	CRYPTO_SHA256 s;
	UINT size = 1000000;

	coretest_check(CryptoSha256(d, NULL, 0), "the empty message is hashed");
	coretest_check_hex(d, sizeof(d), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "SHA-256(\"\")");
	CryptoSha256(d, "abc", 3);
	coretest_check_hex(d, sizeof(d), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", "SHA-256(\"abc\")");
	CryptoSha256(d, m448, sizeof(m448) - 1);
	coretest_check_hex(d, sizeof(d), "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1", "SHA-256 of the 448-bit message");
	CryptoSha256(d, m896, sizeof(m896) - 1);
	coretest_check_hex(d, sizeof(d), "cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1", "SHA-256 of the 896-bit message");

	UCHAR *a = (UCHAR *)HeapAlloc(GetProcessHeap(), 0, size);
	if (coretest_check(a != NULL, "1,000,000 bytes allocated")) {
		FillMemory(a, size, 'a');
		CryptoSha256(d, a, size);
		coretest_check_hex(d, sizeof(d), "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0", "SHA-256 of one million 'a' in one call");

		// The same over 1000 parts of 1000 bytes, with an empty part between them
		bool ok = CryptoSha256Begin(&s);
		for (UINT i = 0; ok && i < 1000; i++)
			ok = CryptoSha256Update(&s, a + i * 1000, 1000) && CryptoSha256Update(&s, NULL, 0);
		ok = CryptoSha256End(&s, d) && ok;
		coretest_check(ok && s.Hash == NULL, "1000 parts hashed, the hash released");
		coretest_check_hex(d, sizeof(d), "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0", "SHA-256 of one million 'a' over 1000 parts");
		HeapFree(GetProcessHeap(), 0, a);
	}

	coretest_check(CryptoSha256(NULL, "abc", 3) == false && CryptoSha256(d, NULL, 3) == false, "a NULL destination or source is refused");
}

// RFC 4231 section 4, HMAC-SHA-256 of test cases 1 to 4, 6 and 7 (5 truncates the output)
void hmac_test() {
	static const char tc6_data[] = "Test Using Larger Than Block-Size Key - Hash Key First";
	static const char tc7_data[] = "This is a test using a larger than block-size key and a larger than block-size data. The key needs to be hashed before being used by the HMAC algorithm.";
	UCHAR key[131], data[50], d[CRYPTO_SHA256_SIZE];

	FillMemory(key, 20, 0x0b);
	CryptoHmacSha256(d, key, 20, "Hi There", 8);
	coretest_check_hex(d, sizeof(d), "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7", "RFC 4231 test case 1");

	CryptoHmacSha256(d, "Jefe", 4, "what do ya want for nothing?", 28);
	coretest_check_hex(d, sizeof(d), "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843", "RFC 4231 test case 2 (key shorter than the hash)");

	FillMemory(key, 20, 0xaa);
	FillMemory(data, 50, 0xdd);
	CryptoHmacSha256(d, key, 20, data, 50);
	coretest_check_hex(d, sizeof(d), "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe", "RFC 4231 test case 3");

	for (UINT i = 0; i < 25; i++)
		key[i] = (UCHAR)(i + 1);
	FillMemory(data, 50, 0xcd);
	CryptoHmacSha256(d, key, 25, data, 50);
	coretest_check_hex(d, sizeof(d), "82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b", "RFC 4231 test case 4");

	FillMemory(key, 131, 0xaa);
	CryptoHmacSha256(d, key, 131, tc6_data, sizeof(tc6_data) - 1);
	coretest_check_hex(d, sizeof(d), "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54", "RFC 4231 test case 6 (key longer than a block)");

	CryptoHmacSha256(d, key, 131, tc7_data, sizeof(tc7_data) - 1);
	coretest_check_hex(d, sizeof(d), "9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2", "RFC 4231 test case 7 (key and data longer than a block)");
}

// RFC 5869 appendix A.1 to A.3 (the SHA-256 cases), Expand from the PRK alone (TLS 1.3 and Noise
// use it), an empty IKM (Noise Split(): HKDF(ck, zerolen)) and the RFC limit of 255 blocks
void hkdf_test() {
	UCHAR ikm[80], salt[80], info[80], prk[CRYPTO_SHA256_SIZE], okm[82], ck[32];
	UCHAR *big;

	// A.1: 22-byte IKM, 13-byte salt, 10-byte info, L = 42
	FillMemory(ikm, 22, 0x0b);
	for (UINT i = 0; i < 13; i++)
		salt[i] = (UCHAR)i;
	for (UINT i = 0; i < 10; i++)
		info[i] = (UCHAR)(0xf0 + i);
	CryptoHkdfExtract(prk, salt, 13, ikm, 22);
	coretest_check_hex(prk, sizeof(prk), "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5", "A.1 PRK");
	CryptoHkdf(okm, 42, salt, 13, ikm, 22, info, 10);
	coretest_check_hex(okm, 42, "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865", "A.1 OKM");
	CryptoHkdfExpand(okm, 42, prk, info, 10);
	coretest_check_hex(okm, 42, "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865", "A.1 OKM by Expand from the PRK");

	// A.2: 80-byte IKM, salt and info, L = 82
	for (UINT i = 0; i < 80; i++) {
		ikm[i] = (UCHAR)i;
		salt[i] = (UCHAR)(0x60 + i);
		info[i] = (UCHAR)(0xb0 + i);
	}
	CryptoHkdfExtract(prk, salt, 80, ikm, 80);
	coretest_check_hex(prk, sizeof(prk), "06a6b88c5853361a06104c9ceb35b45cef760014904671014a193f40c15fc244", "A.2 PRK");
	CryptoHkdf(okm, 82, salt, 80, ikm, 80, info, 80);
	coretest_check_hex(okm, 82,
	                   "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71cc30c58179ec3e87c14c01d5c1f3434f1d87",
	                   "A.2 OKM");

	// A.3: empty salt and info, L = 42
	FillMemory(ikm, 22, 0x0b);
	CryptoHkdfExtract(prk, NULL, 0, ikm, 22);
	coretest_check_hex(prk, sizeof(prk), "19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04", "A.3 PRK (empty salt)");
	CryptoHkdf(okm, 42, NULL, 0, ikm, 22, NULL, 0);
	coretest_check_hex(okm, 42, "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8", "A.3 OKM (empty salt and info)");

	// Noise Split(): HKDF(ck, zerolen, 2) with ck = 01 02 ... 20, two 32-byte outputs (RFC 5869 by HMAC)
	for (UINT i = 0; i < 32; i++)
		ck[i] = (UCHAR)(i + 1);
	coretest_check(CryptoHkdf(okm, 64, ck, sizeof(ck), NULL, 0, NULL, 0), "an empty IKM is accepted");
	coretest_check_hex(okm, 64, "fc5eccc8a17f5575645b191c4123bcec6defa32c721a6c5009f4c251bc39c30946685175eb3b43cc7858098eaed45a5c9b6c967cca8c26dbf23f98bbeab77538",
	                   "HKDF with an empty IKM, as Noise Split() calls it");

	// The output limit: 255 blocks are written, 255 blocks and one byte are refused
	big = (UCHAR *)HeapAlloc(GetProcessHeap(), 0, CRYPTO_HKDF_MAX_SIZE + 1);
	if (coretest_check(big != NULL, "8161 bytes allocated")) {
		FillMemory(ikm, 22, 0x0b);
		for (UINT i = 0; i < 13; i++)
			salt[i] = (UCHAR)i;
		coretest_check(CryptoHkdf(big, CRYPTO_HKDF_MAX_SIZE, salt, 13, ikm, 22, NULL, 0), "L = 255 * 32 is written");
		CryptoSha256(prk, big, CRYPTO_HKDF_MAX_SIZE);
		coretest_check_hex(prk, sizeof(prk), "23add0c364ae395dc1fe8261a36329d5d6d84dc457b8cf60e9536ea46feacf57", "SHA-256 of the 8160-byte OKM (IKM and salt of A.1)");
		coretest_check(CryptoHkdf(big, CRYPTO_HKDF_MAX_SIZE + 1, salt, 13, ikm, 22, NULL, 0) == false && big[0] == 0, "L = 255 * 32 + 1 is refused and the output zeroed");
		HeapFree(GetProcessHeap(), 0, big);
	}
}

// One GCM test case: seal, open, and open with the tag, the AAD and the nonce tampered with
static void aesgcm_case(const char *name, const char *key_hex, const char *nonce_hex, const char *pt_hex, const char *aad_hex, const char *ct_hex, const char *tag_hex) {
	UCHAR key[32], nonce[CRYPTO_AES_GCM_NONCE_SIZE], pt[64], aad[20], ct[64], tag[CRYPTO_AES_GCM_TAG_SIZE], out[64];
	CRYPTO_AEAD a;
	char what[128];

	UINT key_size = coretest_unhex(key, sizeof(key), key_hex);
	coretest_unhex(nonce, sizeof(nonce), nonce_hex);
	UINT size = coretest_unhex(pt, sizeof(pt), pt_hex);
	UINT aad_size = coretest_unhex(aad, sizeof(aad), aad_hex);

	_snprintf_s(what, sizeof(what), _TRUNCATE, "%s: key accepted (%u bits)", name, key_size * 8);
	if (coretest_check(CryptoAeadInit(&a, key, key_size), what) == false)
		return;

	CryptoAeadSeal(&a, nonce, aad, aad_size, pt, size, ct, tag);
	_snprintf_s(what, sizeof(what), _TRUNCATE, "%s: ciphertext", name);
	if (size != 0)
		coretest_check_hex(ct, size, ct_hex, what);
	_snprintf_s(what, sizeof(what), _TRUNCATE, "%s: tag", name);
	coretest_check_hex(tag, sizeof(tag), tag_hex, what);

	_snprintf_s(what, sizeof(what), _TRUNCATE, "%s: opens to the plaintext", name);
	coretest_check(CryptoAeadOpen(&a, nonce, aad, aad_size, ct, size, tag, out) && memcmp(out, pt, size) == 0, what);

	tag[15] ^= 0x01;
	FillMemory(out, sizeof(out), 0x55);
	_snprintf_s(what, sizeof(what), _TRUNCATE, "%s: a changed tag is refused, the output zeroed", name);
	coretest_check(CryptoAeadOpen(&a, nonce, aad, aad_size, ct, size, tag, out) == false && (size == 0 || out[0] == 0), what);
	tag[15] ^= 0x01;

	nonce[0] ^= 0x01;
	_snprintf_s(what, sizeof(what), _TRUNCATE, "%s: a changed nonce is refused", name);
	coretest_check(CryptoAeadOpen(&a, nonce, aad, aad_size, ct, size, tag, out) == false, what);
	nonce[0] ^= 0x01;

	if (aad_size != 0) {
		aad[0] ^= 0x01;
		_snprintf_s(what, sizeof(what), _TRUNCATE, "%s: a changed AAD is refused", name);
		coretest_check(CryptoAeadOpen(&a, nonce, aad, aad_size, ct, size, tag, out) == false, what);
		aad[0] ^= 0x01;
	}

	// In place: dst is src
	if (size != 0) {
		CopyMemory(out, pt, size);
		_snprintf_s(what, sizeof(what), _TRUNCATE, "%s: sealed and opened in place", name);
		coretest_check(CryptoAeadSeal(&a, nonce, aad, aad_size, out, size, out, tag) && memcmp(out, ct, size) == 0 &&
		                   CryptoAeadOpen(&a, nonce, aad, aad_size, out, size, tag, out) && memcmp(out, pt, size) == 0,
		               what);
	}

	CryptoAeadFree(&a);
}

// The test cases of "The Galois/Counter Mode of Operation (GCM)", McGrew and Viega, appendix B:
// 1 to 4 (AES-128) and 13 to 16 (AES-256)
void aesgcm_test() {
	static const char k3[] = "feffe9928665731c6d6a8f9467308308";
	static const char k15[] = "feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308";
	static const char iv3[] = "cafebabefacedbaddecaf888";
	static const char p3[] = "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255";
	static const char p4[] = "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39";
	static const char a4[] = "feedfacedeadbeeffeedfacedeadbeefabaddad2";
	static const char zero16[] = "00000000000000000000000000000000";
	static const char zero32[] = "0000000000000000000000000000000000000000000000000000000000000000";
	static const char zero12[] = "000000000000000000000000";
	UCHAR key[24];
	CRYPTO_AEAD a;

	aesgcm_case("test case 1", zero16, zero12, "", "", "", "58e2fccefa7e3061367f1d57a4e7455a");
	aesgcm_case("test case 2", zero16, zero12, zero16, "", "0388dace60b6a392f328c2b971b2fe78", "ab6e47d42cec13bdf53a67b21257bddf");
	aesgcm_case("test case 3", k3, iv3, p3, "",
	            "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091473f5985",
	            "4d5c2af327cd64a62cf35abd2ba6fab4");
	aesgcm_case("test case 4", k3, iv3, p4, a4,
	            "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091",
	            "5bc94fbc3221a5db94fae95ae7121a47");
	aesgcm_case("test case 13", zero32, zero12, "", "", "", "530f8afbc74536b9a963b4f1c4cb738b");
	aesgcm_case("test case 14", zero32, zero12, zero16, "", "cea7403d4d606b6e074ec5d3baf39d18", "d0d1c8a799996bf0265b98b5d48ab919");
	aesgcm_case("test case 15", k15, iv3, p3, "",
	            "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662898015ad",
	            "b094dac5d93471bdec1a502270e3cc6c");
	aesgcm_case("test case 16", k15, iv3, p4, a4,
	            "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662",
	            "76fc6ece0f4e1768cddf8853bb2d551b");

	// AES-GCM keys are 128 or 256 bits: AES-192 is not offered (ADR-0022: AES-GCM 128/256)
	ZeroMemory(key, sizeof(key));
	coretest_check(CryptoAeadInit(&a, key, 24) == false && a.Key == NULL && CryptoAeadInit(&a, NULL, 16) == false, "a 192-bit or missing key is refused");
}

// One X25519 known answer
static void x25519_case(const char *what, const char *k_hex, const char *u_hex, const char *expect_hex) {
	UCHAR k[CRYPTO_X25519_SIZE], u[CRYPTO_X25519_SIZE], out[CRYPTO_X25519_SIZE];

	coretest_unhex(k, sizeof(k), k_hex);
	coretest_unhex(u, sizeof(u), u_hex);
	if (coretest_check(CryptoX25519(out, k, u), what))
		coretest_check_hex(out, sizeof(out), expect_hex, what);
}

// RFC 7748: section 5.2 (the first vector, whose scalar is not clamped, and the iterated test
// after 1 and 1000 rounds) and section 6.1 (the Diffie-Hellman example). Then the decoding rules
// of section 5 that CNG does not apply itself: bit 255 of u is masked, a u not below p is reduced
// (p + 9 is 9, the base point), and points of low order give no secret.
void x25519_test() {
	static const char alice[] = "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a";
	static const char alice_pub[] = "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a";
	static const char bob[] = "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb";
	static const char bob_pub[] = "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f";
	static const char shared[] = "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742";
	static const char v1_k[] = "a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4";
	static const char v1_u[] = "e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c";
	static const char v1_out[] = "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552";
	UCHAR k[CRYPTO_X25519_SIZE], u[CRYPTO_X25519_SIZE], r[CRYPTO_X25519_SIZE], pub[CRYPTO_X25519_SIZE], priv[CRYPTO_X25519_SIZE];

	x25519_case("RFC 7748 5.2 first vector (scalar not clamped)", v1_k, v1_u, v1_out);

	// Iterated: k = u = 9, then k, u = X25519(k, u), k
	ZeroMemory(k, sizeof(k));
	k[0] = 9;
	CopyMemory(u, k, sizeof(u));
	bool ok = true;
	for (UINT i = 1; ok && i <= 1000; i++) {
		ok = CryptoX25519(r, k, u);
		CopyMemory(u, k, sizeof(u));
		CopyMemory(k, r, sizeof(k));
		if (i == 1)
			coretest_check_hex(k, sizeof(k), "422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079", "RFC 7748 5.2 iterated, 1 round");
	}
	coretest_check(ok, "1000 rounds computed");
	coretest_check_hex(k, sizeof(k), "684cf59ba83309552800ef566f2f4d3c1c3887c49360e3875f2eb94d99532c51", "RFC 7748 5.2 iterated, 1000 rounds");

	// 6.1: both public keys and the shared secret from both sides
	coretest_unhex(priv, sizeof(priv), alice);
	coretest_check(CryptoX25519PublicKey(pub, priv), "Alice's public key computed");
	coretest_check_hex(pub, sizeof(pub), alice_pub, "RFC 7748 6.1 Alice's public key X25519(a, 9)");
	coretest_unhex(priv, sizeof(priv), bob);
	CryptoX25519PublicKey(pub, priv);
	coretest_check_hex(pub, sizeof(pub), bob_pub, "RFC 7748 6.1 Bob's public key X25519(b, 9)");
	x25519_case("RFC 7748 6.1 shared secret, Alice's side", alice, bob_pub, shared);
	x25519_case("RFC 7748 6.1 shared secret, Bob's side", bob, alice_pub, shared);

	// Section 5: bit 255 of u is masked
	coretest_unhex(k, sizeof(k), v1_k);
	coretest_unhex(u, sizeof(u), v1_u);
	u[31] |= 0x80;
	coretest_check(CryptoX25519(r, k, u), "u with bit 255 set is accepted");
	coretest_check_hex(r, sizeof(r), v1_out, "u with bit 255 set gives the result of the masked u");

	// Section 5: u = p + 9 = 2^255 - 10 is reduced to 9, so the result is the public key of k
	FillMemory(u, sizeof(u), 0xff);
	u[0] = 0xf6;
	u[31] = 0x7f;
	CryptoX25519PublicKey(pub, k);
	coretest_check(CryptoX25519(r, k, u) && memcmp(r, pub, sizeof(r)) == 0, "u = p + 9 (not canonical) is reduced to 9");
	u[31] = 0xff;
	coretest_check(CryptoX25519(r, k, u) && memcmp(r, pub, sizeof(r)) == 0, "u = 2^256 - 10 is masked and reduced to 9");

	// Low order: u = 0 and u = 1 give the all-zero secret, which is refused and never written
	ZeroMemory(u, sizeof(u));
	FillMemory(r, sizeof(r), 0x55);
	coretest_check(CryptoX25519(r, k, u) == false && r[0] == 0, "u = 0 (low order) gives no secret");
	u[0] = 1;
	FillMemory(r, sizeof(r), 0x55);
	coretest_check(CryptoX25519(r, k, u) == false && r[0] == 0, "u = 1 (low order) gives no secret");

	// A generated key is clamped and agrees with a peer
	UCHAR peer_priv[CRYPTO_X25519_SIZE], peer_pub[CRYPTO_X25519_SIZE], s1[CRYPTO_X25519_SIZE], s2[CRYPTO_X25519_SIZE];
	coretest_check(CryptoX25519GenerateKey(priv, pub) && CryptoX25519GenerateKey(peer_priv, peer_pub), "two key pairs generated");
	coretest_check((priv[0] & 7) == 0 && (priv[31] & 0xc0) == 0x40, "a generated scalar is clamped");
	coretest_check(CryptoX25519(s1, priv, peer_pub) && CryptoX25519(s2, peer_priv, pub) && memcmp(s1, s2, sizeof(s1)) == 0, "both sides of a generated pair agree");
}

// The node identity key through NCrypt: the RFC 7748 6.1 example with Alice's scalar stored in
// the key storage provider, then a key generated in the provider against a CNG key
void identity_test() {
	static const char alice[] = "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a";
	static const char alice_pub[] = "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a";
	static const char bob_pub[] = "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f";
	static const char shared[] = "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742";
	UCHAR priv[CRYPTO_X25519_SIZE], pub[CRYPTO_X25519_SIZE], peer[CRYPTO_X25519_SIZE], s1[CRYPTO_X25519_SIZE], s2[CRYPTO_X25519_SIZE];
	CRYPTO_IDENTITY id, id2;
	wchar_t name[64], name2[64];
	UINT scope = coretest_scope();

	coretest_info("scope: %s", coretest_scope_name());
	_snwprintf_s(name, sizeof(name) / sizeof(wchar_t), _TRUNCATE, L"Ranz-coretest-identity-%lu", GetCurrentProcessId());
	_snwprintf_s(name2, sizeof(name2) / sizeof(wchar_t), _TRUNCATE, L"Ranz-coretest-identity-new-%lu", GetCurrentProcessId());

	coretest_unhex(priv, sizeof(priv), alice);
	if (coretest_check(CryptoIdentityImport(&id, name, priv, scope), "Alice's scalar stored as a named key")) {
		CryptoIdentityPublicKey(&id, pub);
		coretest_check_hex(pub, sizeof(pub), alice_pub, "public key of the stored key");
		coretest_unhex(peer, sizeof(peer), bob_pub);
		coretest_check(CryptoIdentityDh(&id, s1, peer), "secret agreement in the provider");
		coretest_check_hex(s1, sizeof(s1), shared, "RFC 7748 6.1 shared secret through the key storage provider");

		ZeroMemory(peer, sizeof(peer));
		FillMemory(s1, sizeof(s1), 0x55);
		coretest_check(CryptoIdentityDh(&id, s1, peer) == false && s1[0] == 0, "u = 0 (low order) gives no secret");
		coretest_check(CryptoIdentityImport(&id2, name, priv, scope) == false && CryptoIdentityCreate(&id2, name, scope) == false,
		               "a second key of the same name is refused");
		CryptoIdentityClose(&id);

		coretest_check(CryptoIdentityOpen(&id, name, scope) && CryptoIdentityPublicKey(&id, pub), "opened again by name");
		coretest_check_hex(pub, sizeof(pub), alice_pub, "public key of the opened key");
		coretest_check(CryptoIdentityDelete(&id) && id.Key == 0 && id.Provider == 0, "deleted");
		coretest_check(CryptoIdentityOpen(&id, name, scope) == false && id.Key == 0, "gone after the delete");
	}
	SecureZeroMemory(priv, sizeof(priv));

	// A key made in the provider: its scalar never leaves it
	if (coretest_check(CryptoIdentityCreate(&id, name2, scope), "a new identity key created in the provider")) {
		UCHAR eph_priv[CRYPTO_X25519_SIZE], eph_pub[CRYPTO_X25519_SIZE];

		coretest_check(CryptoIdentityPublicKey(&id, pub), "its public key");
		coretest_check(CryptoX25519GenerateKey(eph_priv, eph_pub) && CryptoIdentityDh(&id, s1, eph_pub) && CryptoX25519(s2, eph_priv, pub) &&
		                   memcmp(s1, s2, sizeof(s1)) == 0,
		               "the provider key and a CNG key agree on the secret");
		coretest_check(CryptoIdentityDelete(&id), "deleted");
	}

	coretest_check(CryptoIdentityOpen(&id, L"", scope) == false && CryptoIdentityOpen(NULL, name, scope) == false, "an empty name or no identity is refused");
}
