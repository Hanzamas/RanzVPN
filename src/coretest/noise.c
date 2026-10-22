// noise.c
// Tests of the session module (src/Core/Noise.h; CORE-F2, #62; seam 4 of spec #45): the Noise_IK
// handshake against the Noise_IK_25519_AESGCM_SHA256 vector of the cacophony test vectors (the
// vectors that the Noise specification's wiki lists, also run by noise-c and snow), with the static
// keys as scalars and in the key storage provider; the rules of the cipher and handshake states;
// the IKhfs handshake on ML-KEM-768; the session against a fixed golden transcript, the channel
// binding, the Login, keepalive, the dead-peer timeout and rekey on a schedule, on a simulated
// clock; and the tunnel. The goldens of the session were computed from the same scenario by an
// independent model of the records on the Python cryptography package (OpenSSL), whose IK
// handshake reproduces the cacophony vector too.

#include "coretest.h"

#include "Core/Noise.h"

#include <string.h>

// Noise_IK_25519_AESGCM_SHA256 of cacophony (vectors/cacophony.txt at commit 18b7348c of
// haskell-cryptography/cacophony): prologue "John Galt", the static and ephemeral scalars of both
// sides, two handshake messages and four transport messages, each a payload and its ciphertext
static const char cac_prologue[] = "4a6f686e2047616c74";
static const char cac_init_static[] = "e61ef9919cde45dd5f82166404bd08e38bceb5dfdfded0a34c8df7ed542214d1";
static const char cac_init_ephemeral[] = "893e28b9dc6ca8d611ab664754b8ceb7bac5117349a4439a6b0569da977c464a";
static const char cac_resp_static[] = "4a3acbfdb163dec651dfa3194dece676d437029c62a408b4c5ea9114246e4893";
static const char cac_resp_ephemeral[] = "bbdb4cdbd309f1a1f2e1456967fe288cadd6f712d65dc7b7793d5e63da6b375b";
static const char cac_resp_public[] = "31e0303fd6418d2f8c0e78b91f22e8caed0fbe48656dcf4767e4834f701b8f62";
static const char cac_init_public[] = "6bc3822a2aa7f4e6981d6538692b3cdf3e6df9eea6ed269eb41d93c22757b75a";
static const char cac_hash[] = "669c8640d9e42a3cda2f232f78597ceefb01daa6e3df81181ccce6fc6b5026bf";

typedef struct NOISE_VECTOR_MESSAGE {
	const char *Payload;
	const char *Ciphertext;
} NOISE_VECTOR_MESSAGE;

static const NOISE_VECTOR_MESSAGE cac_messages[] = {
    {"4c756477696720766f6e204d69736573", "ca35def5ae56cec33dc2036731ab14896bc4c75dbb07a61f879f8e3afa4c79444e417bc55c7a8166c993356c1be41ef67818a292426f301556c7f26b21d25ddb097153891a9a956cff47b83e63ad8d701c1342c209cff1ca5ecd43402762ac249e3bd3a4c0a145fe07cb5dae28ea13a3"},
    {"4d757272617920526f746862617264", "95ebc60d2b1fa672c1f46a8aa265ef51bfe38e7ccb39ec5be34069f144808843af2ccf9972e22afc67aeafcd25162f7f98c363b7762e3e4cb7d272e39f27a5"},
    {"462e20412e20486179656b", "66acfc92e3197de166809e6d4d5d003dcc819a84bc3522ca53c9d9"},
    {"4361726c204d656e676572", "71f89aa6533a6de70b0826864dd75f60806ee40170c16290189eb3"},
    {"4a65616e2d426170746973746520536179", "4795a3423550c8bf00386bd496a3e2c76c10669d2a75ab8f79b5094c5412a25705"},
    {"457567656e2042f6686d20766f6e2042617765726b", "aa0bb39097555c918e40be82abc2b909eb79d9eb87adb07e268fc37323a6cf904fd01fb391"},
};

// After the vector's transport messages, both sides rekey both cipher states (Noise section 11.3)
// and send one message each: the ciphertexts of the reference model
static const char cac_rekey_initiator[] = "828bf1ef04654ae74ec8a5028369313d09332a11b74d785c7a17cd9ba7b330f106";
static const char cac_rekey_responder[] = "836af35d595281585da9b833b6e911549b1ca6196bec6549216cf4f6ff75245f82";

#define NOISE_TEST_BUF 2048

// Bytes from hex into a buffer of NOISE_TEST_BUF; the size
static UINT noise_unhex(UCHAR *dst, const char *hex) {
	return coretest_unhex(dst, NOISE_TEST_BUF, hex);
}

// The two sides of the cacophony vector: the responder's static key as a scalar or, with id, in
// the key storage provider; the initiator's static key likewise with init_id
static bool noise_vector_init(NOISE_HANDSHAKE *init, NOISE_HANDSHAKE *resp, CRYPTO_IDENTITY *init_id, CRYPTO_IDENTITY *resp_id) {
	UCHAR prologue[16], is[NOISE_KEY_SIZE], ie[NOISE_KEY_SIZE], rs[NOISE_KEY_SIZE], re[NOISE_KEY_SIZE], rpub[NOISE_KEY_SIZE];
	UINT prologue_size = coretest_unhex(prologue, sizeof(prologue), cac_prologue);

	coretest_unhex(is, sizeof(is), cac_init_static);
	coretest_unhex(ie, sizeof(ie), cac_init_ephemeral);
	coretest_unhex(rs, sizeof(rs), cac_resp_static);
	coretest_unhex(re, sizeof(re), cac_resp_ephemeral);
	coretest_unhex(rpub, sizeof(rpub), cac_resp_public);

	bool ok = NoiseHandshakeInit(init, NOISE_SUITE_IK, true, prologue, prologue_size, init_id != NULL ? NULL : is, init_id, rpub) &&
	          NoiseHandshakeInit(resp, NOISE_SUITE_IK, false, prologue, prologue_size, resp_id != NULL ? NULL : rs, resp_id, NULL);
	NoiseHandshakeSetEphemeral(init, ie);
	NoiseHandshakeSetEphemeral(resp, re);

	SecureZeroMemory(is, sizeof(is));
	SecureZeroMemory(rs, sizeof(rs));
	return ok && init->FixedEphemeral && resp->FixedEphemeral;
}

// The whole vector on two handshakes from noise_vector_init: both messages, the hash and the four
// transport messages; the cipher states stay with the caller for more
static void noise_vector_run(NOISE_HANDSHAKE *init, NOISE_HANDSHAKE *resp, NOISE_CIPHER *c[4], const char *label) {
	UCHAR *payload = (UCHAR *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 3 * NOISE_TEST_BUF);
	UCHAR *msg = payload + NOISE_TEST_BUF;
	UCHAR *out = msg + NOISE_TEST_BUF;
	UINT msg_size = 0, out_size = 0;
	char what[160];

	if (coretest_check(payload != NULL, "buffers") == false)
		return;

	// -> e, es, s, ss
	UINT payload_size = noise_unhex(payload, cac_messages[0].Payload);
	_snprintf_s(what, sizeof(what), _TRUNCATE, "%s: message 1 (-> e, es, s, ss) is the vector's", label);
	coretest_check(NoiseHandshakeWrite(init, payload, payload_size, msg, NOISE_TEST_BUF, &msg_size), "initiator writes message 1");
	coretest_check_hex(msg, msg_size, cac_messages[0].Ciphertext, what);
	coretest_check(NoiseHandshakeRead(resp, msg, msg_size, out, NOISE_TEST_BUF, &out_size) && out_size == payload_size && memcmp(out, payload, out_size) == 0,
	               "responder reads message 1 and its payload");

	// <- e, ee, se
	payload_size = noise_unhex(payload, cac_messages[1].Payload);
	_snprintf_s(what, sizeof(what), _TRUNCATE, "%s: message 2 (<- e, ee, se) is the vector's", label);
	coretest_check(NoiseHandshakeWrite(resp, payload, payload_size, msg, NOISE_TEST_BUF, &msg_size), "responder writes message 2");
	coretest_check_hex(msg, msg_size, cac_messages[1].Ciphertext, what);
	coretest_check(NoiseHandshakeRead(init, msg, msg_size, out, NOISE_TEST_BUF, &out_size) && out_size == payload_size && memcmp(out, payload, out_size) == 0,
	               "initiator reads message 2 and its payload");

	coretest_check_hex(init->H, NOISE_KEY_SIZE, cac_hash, "initiator: the handshake hash is the vector's");
	coretest_check_hex(resp->H, NOISE_KEY_SIZE, cac_hash, "responder: the handshake hash is the vector's");
	coretest_check_hex(resp->RemoteStatic, NOISE_KEY_SIZE, cac_init_public, "responder: learnt the initiator's static key");

	// c[0], c[1]: the initiator's send and receive states; c[2], c[3] the responder's
	coretest_check(NoiseHandshakeSplit(init, c[0], c[1]) && NoiseHandshakeSplit(resp, c[2], c[3]), "Split on both sides");
	for (UINT i = 2; i < 6; i++) {
		bool from_init = (i % 2) == 0;
		NOISE_CIPHER *send = from_init ? c[0] : c[2];
		NOISE_CIPHER *recv = from_init ? c[3] : c[1];

		payload_size = noise_unhex(payload, cac_messages[i].Payload);
		_snprintf_s(what, sizeof(what), _TRUNCATE, "%s: transport message %u (%s) is the vector's", label, i + 1, from_init ? "initiator" : "responder");
		coretest_check(NoiseCipherEncrypt(send, NULL, 0, payload, payload_size, msg), "encrypted");
		coretest_check_hex(msg, payload_size + NOISE_TAG_SIZE, cac_messages[i].Ciphertext, what);
		coretest_check(NoiseCipherDecrypt(recv, NULL, 0, msg, payload_size + NOISE_TAG_SIZE, out) && memcmp(out, payload, payload_size) == 0, "decrypted by the peer");
	}

	HeapFree(GetProcessHeap(), 0, payload);
}

static void noise_free_ciphers(NOISE_CIPHER *c) {
	for (UINT i = 0; i < 4; i++)
		NoiseCipherFree(&c[i]);
}

// The cacophony vector, the rekey after it and the static keys in the key storage provider
static void noise_vector_tests() {
	NOISE_HANDSHAKE init, resp;
	NOISE_CIPHER c[4];
	NOISE_CIPHER *cp[4] = {&c[0], &c[1], &c[2], &c[3]};
	UCHAR msg[64], out[64];
	CRYPTO_IDENTITY init_id, resp_id;
	UCHAR key[NOISE_KEY_SIZE];
	wchar_t name[64], name2[64];
	UINT scope = coretest_scope();

	ZeroMemory(c, sizeof(c));
	coretest_check(strcmp(NoiseSuiteName(NOISE_SUITE_IK), "Noise_IK_25519_AESGCM_SHA256") == 0 && NoiseSuiteAvailable(NOISE_SUITE_IK),
	               "the suite is Noise_IK_25519_AESGCM_SHA256");
	coretest_check(NOISE_IK_MESSAGE1_SIZE == 96 && NOISE_IK_MESSAGE2_SIZE == 48, "IK messages with empty payloads: 96 and 48 bytes");

	if (coretest_check(noise_vector_init(&init, &resp, NULL, NULL), "both sides with the vector's keys")) {
		noise_vector_run(&init, &resp, cp, "scalars");

		// REKEY(k) on all four states, then one message each way (reference model)
		coretest_check(NoiseCipherRekey(&c[0]) && NoiseCipherRekey(&c[1]) && NoiseCipherRekey(&c[2]) && NoiseCipherRekey(&c[3]), "Rekey of the four cipher states");
		coretest_check(c[0].Nonce == 2 && c[3].Nonce == 2, "Rekey keeps the nonce");
		coretest_check(NoiseCipherEncrypt(&c[0], NULL, 0, "rekeyed initiator", 17, msg), "the initiator encrypts under its next key");
		coretest_check_hex(msg, 17 + NOISE_TAG_SIZE, cac_rekey_initiator, "after Rekey: the initiator's message is the reference's");
		coretest_check(NoiseCipherDecrypt(&c[3], NULL, 0, msg, 17 + NOISE_TAG_SIZE, out) && memcmp(out, "rekeyed initiator", 17) == 0, "the responder decrypts it under its next key");
		coretest_check(NoiseCipherEncrypt(&c[2], NULL, 0, "rekeyed responder", 17, msg), "the responder encrypts under its next key");
		coretest_check_hex(msg, 17 + NOISE_TAG_SIZE, cac_rekey_responder, "after Rekey: the responder's message is the reference's");
		coretest_check(NoiseCipherDecrypt(&c[1], NULL, 0, msg, 17 + NOISE_TAG_SIZE, out) && memcmp(out, "rekeyed responder", 17) == 0, "the initiator decrypts it under its next key");
	}
	NoiseHandshakeFree(&init);
	NoiseHandshakeFree(&resp);
	noise_free_ciphers(c);

	// The same vector with both static keys in the key storage provider, as a node holds its identity
	coretest_info("static keys in the key storage provider: %s", coretest_scope_name());
	_snwprintf_s(name, sizeof(name) / sizeof(wchar_t), _TRUNCATE, L"Ranz-coretest-noise-init-%lu", GetCurrentProcessId());
	_snwprintf_s(name2, sizeof(name2) / sizeof(wchar_t), _TRUNCATE, L"Ranz-coretest-noise-resp-%lu", GetCurrentProcessId());
	coretest_unhex(key, sizeof(key), cac_init_static);
	bool have_init = CryptoIdentityImport(&init_id, name, key, scope);
	coretest_unhex(key, sizeof(key), cac_resp_static);
	bool have_resp = CryptoIdentityImport(&resp_id, name2, key, scope);
	SecureZeroMemory(key, sizeof(key));
	if (coretest_check(have_init && have_resp, "the vector's static keys stored in the key storage provider") &&
	    coretest_check(noise_vector_init(&init, &resp, &init_id, &resp_id), "both sides with their static keys in the provider"))
		noise_vector_run(&init, &resp, cp, "key storage provider");
	NoiseHandshakeFree(&init);
	NoiseHandshakeFree(&resp);
	noise_free_ciphers(c);
	if (have_init)
		CryptoIdentityDelete(&init_id);
	if (have_resp)
		CryptoIdentityDelete(&resp_id);
}

// The rules of the handshake: what fails, and that it stays failed
static void noise_rule_tests() {
	NOISE_HANDSHAKE init, resp;
	NOISE_CIPHER c[2];
	UCHAR msg[256], msg2[256], out[64];
	UINT size = 0, size2 = 0, out_size = 0;

	ZeroMemory(c, sizeof(c));
	ZeroMemory(msg, sizeof(msg));

	// Out of turn
	if (noise_vector_init(&init, &resp, NULL, NULL)) {
		coretest_check(NoiseHandshakeRead(&init, msg, NOISE_IK_MESSAGE2_SIZE, out, sizeof(out), &out_size) == false, "the initiator cannot read before it wrote");
		coretest_check(NoiseHandshakeWrite(&resp, NULL, 0, msg, sizeof(msg), &size) == false, "the responder cannot write first");
		coretest_check(NoiseHandshakeSplit(&init, &c[0], &c[1]) == false && c[0].Aead.Key == NULL, "no Split before the handshake is complete");
	}
	NoiseHandshakeFree(&init);
	NoiseHandshakeFree(&resp);

	// Every byte of message 1 matters: a change in e, in the encrypted s or in the payload tag fails
	// the responder, which then refuses to go on
	UINT positions[] = {0, 40, NOISE_IK_MESSAGE1_SIZE - 1};
	const char *changed[] = {"a changed e fails message 1, and the responder stops", "a changed s fails message 1", "a changed payload tag fails message 1"};
	for (UINT i = 0; i < sizeof(positions) / sizeof(positions[0]); i++) {
		if (noise_vector_init(&init, &resp, NULL, NULL) && NoiseHandshakeWrite(&init, NULL, 0, msg, sizeof(msg), &size)) {
			msg[positions[i]] ^= 0x01;
			bool read = NoiseHandshakeRead(&resp, msg, size, out, sizeof(out), &out_size);
			coretest_check(read == false && resp.Failed && NoiseHandshakeWrite(&resp, NULL, 0, msg2, sizeof(msg2), &size2) == false,
			               changed[i]);
		}
		NoiseHandshakeFree(&init);
		NoiseHandshakeFree(&resp);
	}

	// Truncated and empty messages
	if (noise_vector_init(&init, &resp, NULL, NULL) && NoiseHandshakeWrite(&init, NULL, 0, msg, sizeof(msg), &size))
		coretest_check(size == NOISE_IK_MESSAGE1_SIZE && NoiseHandshakeRead(&resp, msg, size - 1, out, sizeof(out), &out_size) == false, "message 1 one byte short fails");
	NoiseHandshakeFree(&init);
	NoiseHandshakeFree(&resp);
	if (noise_vector_init(&init, &resp, NULL, NULL))
		coretest_check(NoiseHandshakeRead(&resp, msg, 0, out, sizeof(out), &out_size) == false, "an empty message 1 fails");
	NoiseHandshakeFree(&init);
	NoiseHandshakeFree(&resp);

	// A payload larger than the buffer fails
	if (noise_vector_init(&init, &resp, NULL, NULL) && NoiseHandshakeWrite(&init, "0123456789abcdef", 16, msg, sizeof(msg), &size))
		coretest_check(NoiseHandshakeRead(&resp, msg, size, out, 15, &out_size) == false, "a payload larger than the buffer fails");
	NoiseHandshakeFree(&init);
	NoiseHandshakeFree(&resp);

	// A change in message 2 fails the initiator
	if (noise_vector_init(&init, &resp, NULL, NULL) && NoiseHandshakeWrite(&init, NULL, 0, msg, sizeof(msg), &size) &&
	    NoiseHandshakeRead(&resp, msg, size, out, sizeof(out), &out_size) && NoiseHandshakeWrite(&resp, NULL, 0, msg2, sizeof(msg2), &size2)) {
		msg2[size2 - 1] ^= 0x80;
		coretest_check(size2 == NOISE_IK_MESSAGE2_SIZE && NoiseHandshakeRead(&init, msg2, size2, out, sizeof(out), &out_size) == false && init.Failed,
		               "a changed message 2 fails the initiator");
	}
	NoiseHandshakeFree(&init);
	NoiseHandshakeFree(&resp);

	// The prologue and the responder's key: the initiator's knowledge of both is checked
	UCHAR prologue[8], rs[NOISE_KEY_SIZE], is[NOISE_KEY_SIZE], rpub[NOISE_KEY_SIZE], other[NOISE_KEY_SIZE], other_pub[NOISE_KEY_SIZE];
	coretest_unhex(rs, sizeof(rs), cac_resp_static);
	coretest_unhex(is, sizeof(is), cac_init_static);
	coretest_unhex(rpub, sizeof(rpub), cac_resp_public);
	CryptoX25519GenerateKey(other, other_pub);
	CopyMemory(prologue, "binding1", 8);
	if (NoiseHandshakeInit(&init, NOISE_SUITE_IK, true, prologue, 8, is, NULL, rpub) && NoiseHandshakeWrite(&init, NULL, 0, msg, sizeof(msg), &size)) {
		prologue[7] = '2';
		coretest_check(NoiseHandshakeInit(&resp, NOISE_SUITE_IK, false, prologue, 8, rs, NULL, NULL) && NoiseHandshakeRead(&resp, msg, size, out, sizeof(out), &out_size) == false,
		               "a prologue that differs (another channel binding) fails message 1");
		NoiseHandshakeFree(&resp);
		prologue[7] = '1';
		coretest_check(NoiseHandshakeInit(&resp, NOISE_SUITE_IK, false, prologue, 8, other, NULL, NULL) && NoiseHandshakeRead(&resp, msg, size, out, sizeof(out), &out_size) == false,
		               "a responder without the pinned static key fails message 1");
	}
	NoiseHandshakeFree(&init);
	NoiseHandshakeFree(&resp);

	// A low-order ephemeral key gives no DH secret, which fails the handshake (Noise section 12.1)
	if (NoiseHandshakeInit(&init, NOISE_SUITE_IK, true, prologue, 8, is, NULL, rpub) && NoiseHandshakeWrite(&init, NULL, 0, msg, sizeof(msg), &size) &&
	    NoiseHandshakeInit(&resp, NOISE_SUITE_IK, false, prologue, 8, rs, NULL, NULL)) {
		ZeroMemory(msg, NOISE_KEY_SIZE);
		coretest_check(NoiseHandshakeRead(&resp, msg, size, out, sizeof(out), &out_size) == false, "an ephemeral key of low order (u = 0) fails message 1");
	}
	NoiseHandshakeFree(&init);
	NoiseHandshakeFree(&resp);

	coretest_check(NoiseHandshakeInit(&init, NOISE_SUITE_IK, true, NULL, 0, is, NULL, NULL) == false, "an initiator without the responder's key is refused");
	coretest_check(NoiseHandshakeInit(&init, NOISE_SUITE_IK, true, NULL, 0, NULL, NULL, rpub) == false, "a side without a static key is refused");
	coretest_check(NoiseHandshakeInit(&init, 9, true, NULL, 0, is, NULL, rpub) == false && NoiseSuiteName(9) == NULL, "an unknown suite is refused");
	SecureZeroMemory(rs, sizeof(rs));
	SecureZeroMemory(is, sizeof(is));
	SecureZeroMemory(other, sizeof(other));

	// The cipher state: an empty plaintext still has its tag checked; a failed decrypt keeps the
	// nonce; the nonce 2^64 - 1 is never used
	UCHAR k[NOISE_KEY_SIZE];
	FillMemory(k, sizeof(k), 0x42);
	if (coretest_check(NoiseCipherInit(&c[0], k) && NoiseCipherInit(&c[1], k), "two cipher states under one key")) {
		coretest_check(NoiseCipherEncrypt(&c[0], "ad", 2, NULL, 0, msg) && c[0].Nonce == 1, "an empty plaintext: the tag alone");
		msg[3] ^= 0x10;
		coretest_check(NoiseCipherDecrypt(&c[1], "ad", 2, msg, NOISE_TAG_SIZE, NULL) == false && c[1].Nonce == 0, "a changed tag of an empty plaintext fails, the nonce stays");
		msg[3] ^= 0x10;
		coretest_check(NoiseCipherDecrypt(&c[1], "ad", 1, msg, NOISE_TAG_SIZE, NULL) == false && c[1].Nonce == 0, "other associated data fails");
		coretest_check(NoiseCipherDecrypt(&c[1], "ad", 2, msg, NOISE_TAG_SIZE, NULL) && c[1].Nonce == 1, "the right one passes and counts");
		coretest_check(NoiseCipherDecrypt(&c[1], "ad", 2, msg, NOISE_TAG_SIZE, NULL) == false, "a replayed message fails (its nonce is gone)");
		coretest_check(NoiseCipherDecrypt(&c[1], NULL, 0, msg, NOISE_TAG_SIZE - 1, NULL) == false, "a message shorter than a tag fails");
		c[0].Nonce = 0xFFFFFFFFFFFFFFFEULL;
		coretest_check(NoiseCipherEncrypt(&c[0], NULL, 0, "x", 1, msg), "n = 2^64 - 2 is the last nonce");
		coretest_check(c[0].Nonce == 0xFFFFFFFFFFFFFFFFULL && NoiseCipherEncrypt(&c[0], NULL, 0, "x", 1, msg) == false, "then the cipher state is used up");
	}
	NoiseCipherFree(&c[0]);
	NoiseCipherFree(&c[1]);
	coretest_check(NoiseCipherEncrypt(&c[0], NULL, 0, "x", 1, msg) == false && NoiseCipherRekey(&c[0]) == false, "a freed cipher state does nothing");
}

void noise_test() {
	noise_vector_tests();
	noise_rule_tests();
}

// The IKhfs handshake on ML-KEM-768: no known answer exists (ML-KEM encapsulation is randomised),
// so both sides of this module, the message sizes and what a change to e1 or ekem1 does
void noisehfs_test() {
	NOISE_HANDSHAKE init, resp;
	NOISE_CIPHER c[4];
	UCHAR *buf = (UCHAR *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 4 * NOISE_TEST_BUF);
	UCHAR rs[NOISE_KEY_SIZE], rpub[NOISE_KEY_SIZE], is[NOISE_KEY_SIZE], ipub[NOISE_KEY_SIZE], first_hash[NOISE_KEY_SIZE];
	UINT size = 0, size2 = 0, out_size = 0;

	if (coretest_check(buf != NULL, "buffers") == false)
		return;
	UCHAR *msg = buf, *msg2 = buf + NOISE_TEST_BUF, *out = buf + 2 * NOISE_TEST_BUF;

	ZeroMemory(c, sizeof(c));
	CryptoX25519GenerateKey(rs, rpub);
	CryptoX25519GenerateKey(is, ipub);
	coretest_check(strcmp(NoiseSuiteName(NOISE_SUITE_IKHFS), "Noise_IKhfs_25519+MLKEM768_AESGCM_SHA256") == 0, "the suite is Noise_IKhfs_25519+MLKEM768_AESGCM_SHA256");

	if (CryptoMlKemAvailable() == false) {
		coretest_info("ML-KEM is not provided by this OS: IKhfs is not offered");
		coretest_check(NoiseSuiteAvailable(NOISE_SUITE_IKHFS) == false && NoiseHandshakeInit(&init, NOISE_SUITE_IKHFS, true, NULL, 0, is, NULL, rpub) == false && init.Failed,
		               "an IKhfs handshake is refused cleanly");
		HeapFree(GetProcessHeap(), 0, buf);
		return;
	}

	coretest_info("ML-KEM is provided by this OS: IKhfs runs");
	coretest_check(NOISE_IKHFS_MESSAGE1_SIZE == 1296 && NOISE_IKHFS_MESSAGE2_SIZE == 1152, "IKhfs messages with empty payloads: 1296 and 1152 bytes");
	for (UINT round = 0; round < 2; round++) {
		bool ok = NoiseHandshakeInit(&init, NOISE_SUITE_IKHFS, true, "hfs", 3, is, NULL, rpub) && NoiseHandshakeInit(&resp, NOISE_SUITE_IKHFS, false, "hfs", 3, rs, NULL, NULL) &&
		          NoiseHandshakeWrite(&init, "one", 3, msg, NOISE_TEST_BUF, &size) && NoiseHandshakeRead(&resp, msg, size, out, NOISE_TEST_BUF, &out_size) &&
		          out_size == 3 && memcmp(out, "one", 3) == 0 && NoiseHandshakeWrite(&resp, "two", 3, msg2, NOISE_TEST_BUF, &size2) &&
		          NoiseHandshakeRead(&init, msg2, size2, out, NOISE_TEST_BUF, &out_size) && out_size == 3 && memcmp(out, "two", 3) == 0;
		coretest_check(ok, "-> e, es, e1, s, ss and <- e, ee, ekem1, se with their payloads");
		coretest_check(size == NOISE_IKHFS_MESSAGE1_SIZE + 3 && size2 == NOISE_IKHFS_MESSAGE2_SIZE + 3, "message sizes: e1 the 1184-byte encapsulation key, ekem1 the 1088-byte ciphertext, each with its tag");
		coretest_check(memcmp(init.H, resp.H, NOISE_KEY_SIZE) == 0 && memcmp(resp.RemoteStatic, ipub, NOISE_KEY_SIZE) == 0 && init.Kem.Key == NULL,
		               "same handshake hash; the responder learnt the initiator's key; the ML-KEM key pair is released");
		if (round == 0)
			CopyMemory(first_hash, init.H, NOISE_KEY_SIZE);
		else
			coretest_check(memcmp(first_hash, init.H, NOISE_KEY_SIZE) != 0, "a second handshake has another hash");

		if (NoiseHandshakeSplit(&init, &c[0], &c[1]) && NoiseHandshakeSplit(&resp, &c[2], &c[3]))
			coretest_check(NoiseCipherEncrypt(&c[0], NULL, 0, "data", 4, msg) && NoiseCipherDecrypt(&c[3], NULL, 0, msg, 4 + NOISE_TAG_SIZE, out) &&
			                   NoiseCipherEncrypt(&c[2], NULL, 0, "back", 4, msg) && NoiseCipherDecrypt(&c[1], NULL, 0, msg, 4 + NOISE_TAG_SIZE, out),
			               "transport both ways after Split");
		NoiseHandshakeFree(&init);
		NoiseHandshakeFree(&resp);
		noise_free_ciphers(c);
	}

	// A changed e1 fails its tag at the responder; a changed ekem1 decapsulates to another secret
	// (FIPS 203 implicit rejection), so the initiator's keys differ and the payload fails
	if (NoiseHandshakeInit(&init, NOISE_SUITE_IKHFS, true, NULL, 0, is, NULL, rpub) && NoiseHandshakeInit(&resp, NOISE_SUITE_IKHFS, false, NULL, 0, rs, NULL, NULL) &&
	    NoiseHandshakeWrite(&init, NULL, 0, msg, NOISE_TEST_BUF, &size)) {
		msg[NOISE_KEY_SIZE + 100] ^= 0x01;
		coretest_check(NoiseHandshakeRead(&resp, msg, size, out, NOISE_TEST_BUF, &out_size) == false, "a changed e1 fails message 1");
	}
	NoiseHandshakeFree(&init);
	NoiseHandshakeFree(&resp);
	if (NoiseHandshakeInit(&init, NOISE_SUITE_IKHFS, true, NULL, 0, is, NULL, rpub) && NoiseHandshakeInit(&resp, NOISE_SUITE_IKHFS, false, NULL, 0, rs, NULL, NULL) &&
	    NoiseHandshakeWrite(&init, NULL, 0, msg, NOISE_TEST_BUF, &size) && NoiseHandshakeRead(&resp, msg, size, out, NOISE_TEST_BUF, &out_size) &&
	    NoiseHandshakeWrite(&resp, NULL, 0, msg2, NOISE_TEST_BUF, &size2)) {
		msg2[NOISE_KEY_SIZE + 500] ^= 0x01;
		coretest_check(NoiseHandshakeRead(&init, msg2, size2, out, NOISE_TEST_BUF, &out_size) == false && init.Kem.Key == NULL, "a changed ekem1 fails message 2");
	}
	NoiseHandshakeFree(&init);
	NoiseHandshakeFree(&resp);

	// The protocol name is in the hash: IK and IKhfs never complete with each other
	if (NoiseHandshakeInit(&init, NOISE_SUITE_IK, true, NULL, 0, is, NULL, rpub) && NoiseHandshakeInit(&resp, NOISE_SUITE_IKHFS, false, NULL, 0, rs, NULL, NULL) &&
	    NoiseHandshakeWrite(&init, NULL, 0, msg, NOISE_TEST_BUF, &size))
		coretest_check(NoiseHandshakeRead(&resp, msg, size, out, NOISE_TEST_BUF, &out_size) == false, "an IK message 1 fails an IKhfs responder");
	NoiseHandshakeFree(&init);
	NoiseHandshakeFree(&resp);
	if (NoiseHandshakeInit(&init, NOISE_SUITE_IKHFS, true, NULL, 0, is, NULL, rpub) && NoiseHandshakeInit(&resp, NOISE_SUITE_IK, false, NULL, 0, rs, NULL, NULL) &&
	    NoiseHandshakeWrite(&init, NULL, 0, msg, NOISE_TEST_BUF, &size))
		coretest_check(NoiseHandshakeRead(&resp, msg, size, out, NOISE_TEST_BUF, &out_size) == false, "an IKhfs message 1 fails an IK responder");
	NoiseHandshakeFree(&init);
	NoiseHandshakeFree(&resp);

	SecureZeroMemory(rs, sizeof(rs));
	SecureZeroMemory(is, sizeof(is));
	HeapFree(GetProcessHeap(), 0, buf);
}
